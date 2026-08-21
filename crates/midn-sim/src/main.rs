// crates/midn-sim/src/main.rs
//! First real end-to-end proof for the "no physical hardware, $0 Linux box"
//! goal: an AMF and a mock UE/gNB, in two independent Tokio tasks talking
//! ONLY through a real `midn_transport::SctpLink` (real `UdpSocket`, real
//! SCTP handshake via `rtc_sctp`) — not the in-process `Amf::process_ngap`
//! calls every existing test uses. Drives the full Phase A Registration
//! procedure: RegistrationRequest -> IdentityRequest/Response ->
//! AuthenticationRequest/Response (real 5G-AKA) -> SecurityModeCommand/
//! Complete -> (protected) RegistrationAccept -> RegistrationComplete.
//!
//! Phase A only, deliberately — Phase B's `InitialContextSetupRequest`/
//! `Response` have no `ngap::codec` wire support yet (struct-only, see
//! that module's doc), and this binary only speaks real bytes on a real
//! socket. Extending to Phase B is the natural next increment once that
//! codec gap closes.
//!
//! Run: `cargo run -p midn-sim`
//!
//! The AMF and UE sides share this process only for convenience (one
//! `cargo run`, one log to read) — they do not share any Rust state.
//! Everything either side knows about the other comes from bytes on the
//! loopback socket, exactly as it would across two real processes or two
//! network-namespace-separated hosts.

use std::net::SocketAddr;
use std::time::Duration;

use bytes::Bytes;
use midn_proto::nas5gs::{
    decode_nas5gs, decode_protected_downlink, encode_auth_response, encode_identity_response_suci,
    encode_registration_complete, encode_registration_request, encode_sec_mode_complete, Nas5gsPdu,
    Nas5gsSecurityContext, Suci, NAS5GS_SHT_PLAIN,
};
use midn_proto::ngap::{
    decode_ngap_pdu, encode_ngap_pdu, NgapInitialUeMessage, NgapMessage, NgapUplinkNasTransport,
};
use midn_transport::{LinkEvent, SctpLink};

// ── Shared test-subscriber material ─────────────────────────────────────────
// Same values `amf::state_machine`'s own test suite uses — not because this
// binary shares any code with those tests, but because they're already a
// known-good (CI-green) Milenage K/OPC pair and an IMSI that round-trips
// through the 5-byte MSIN SUCI scheme (< 2^40 — see
// `amf::registration::resolve_suci_to_imsi`'s doc).
const TEST_IMSI: u64 = 901_700_000_001;
const TEST_K: &str = "465b5ce8b199b49faa5f0a2ee238a6bc";
const TEST_OPC: &str = "cd63cb71954a9f4e48a5994e37a02baf";
const TEST_PLMN: [u8; 3] = [0x00, 0x11, 0x22];
const TEST_TAI: [u8; 6] = [0x00, 0x11, 0x22, 0x00, 0x00, 0x01];
const RAN_UE_NGAP_ID: u32 = 7;

/// 38412 is the real, standardized NGAP-over-SCTP port (TS 38.412) —
/// authenticity touch, not load-bearing: this binary's two sides only ever
/// talk to each other on loopback, so any free, unprivileged port (>1024,
/// no root needed) would work identically.
const AMF_BIND_ADDR: &str = "127.0.0.1:38412";

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::WARN)
        .init();

    let amf_addr: SocketAddr = AMF_BIND_ADDR.parse().unwrap();
    // Port 0 = OS picks a free ephemeral port for the UE side.
    let ue_bind_addr: SocketAddr = "127.0.0.1:0".parse().unwrap();

    println!("midn-sim — AMF + mock UE/gNB over a real SCTP-over-UDP socket\n");

    let amf_task = tokio::spawn(run_amf(amf_addr));

    // Reduces (doesn't eliminate — SCTP's own T1-init retransmission would
    // recover regardless) the chance the UE's first INIT arrives before the
    // AMF task's UdpSocket::bind has actually happened. `tokio::spawn`
    // schedules, it doesn't guarantee the task has started running yet.
    tokio::time::sleep(Duration::from_millis(50)).await;

    let ue_result = run_ue(ue_bind_addr, amf_addr).await;

    match &ue_result {
        Ok(()) => println!(
            "\n✅ Full Registration procedure completed over a real SCTP-over-UDP socket."
        ),
        Err(e) => println!("\n❌ Simulation failed: {e}"),
    }

    amf_task.abort();
    ue_result
}

// ── AMF side ─────────────────────────────────────────────────────────────────

async fn run_amf(bind_addr: SocketAddr) -> Result<(), Box<dyn std::error::Error>> {
    let mut amf = midn_core::amf::Amf::new();
    amf.hss_mut().provision_hex(TEST_IMSI, TEST_K, TEST_OPC)?;

    println!("[AMF] binding {bind_addr}, waiting for an association...");
    let mut link = SctpLink::accept(bind_addr).await?;

    loop {
        match link.recv().await {
            Some(LinkEvent::Connected) => {
                println!("[AMF] SCTP association established");
            }
            Some(LinkEvent::Message(bytes)) => {
                let msg = match decode_ngap_pdu(&bytes) {
                    Ok(m) => m,
                    Err(e) => {
                        eprintln!("[AMF] failed to decode inbound NGAP PDU: {e}");
                        continue;
                    }
                };
                println!("[AMF] <- {}", ngap_summary(&msg));

                let (responses, events) = amf.process_ngap(msg).await;
                for evt in &events {
                    println!("[AMF]    (N3Event: {evt:?})");
                }
                for resp in responses {
                    println!("[AMF] -> {}", ngap_summary(&resp));
                    let out = encode_ngap_pdu(&resp)?;
                    link.send(out).await?;
                }
            }
            Some(LinkEvent::Lost { reason }) => {
                println!("[AMF] link lost: {reason}");
                return Ok(());
            }
            None => return Ok(()),
        }
    }
}

// ── UE / gNB side ────────────────────────────────────────────────────────────

async fn run_ue(bind_addr: SocketAddr, amf_addr: SocketAddr) -> Result<(), Box<dyn std::error::Error>> {
    println!("[UE ] connecting to AMF at {amf_addr}");
    let mut link = SctpLink::connect(bind_addr, amf_addr).await?;

    match link.recv().await {
        Some(LinkEvent::Connected) => println!("[UE ] SCTP association established"),
        Some(LinkEvent::Lost { reason }) => return Err(format!("link lost before connecting: {reason}").into()),
        Some(_) => return Err("unexpected event before Connected".into()),
        None => return Err("link closed before connecting".into()),
    }

    // Step 1: RegistrationRequest. registration_type=1 (initial), ngKSI=0,
    // no GUTI (SUCI-based first registration), ue_security_cap=0x00C0 —
    // same values `amf::state_machine`'s test suite already exercises.
    let reg_req = encode_registration_request(1, 0, None, 0x00C0);
    send_initial(&mut link, reg_req).await?;
    println!("[UE ] -> RegistrationRequest");

    let mut amf_ue_ngap_id: Option<u32> = None;
    // First vector for a freshly provisioned subscriber — SQN starts at 0.
    // See Hss's own doc/tests for why this is a safe assumption here.
    let sqn_used = [0u8; 6];
    let mut kamf: Option<[u8; 32]> = None;

    loop {
        let bytes = match link.recv().await {
            Some(LinkEvent::Message(b)) => b,
            Some(LinkEvent::Lost { reason }) => return Err(format!("link lost: {reason}").into()),
            Some(_) => continue,
            None => return Err("link closed unexpectedly".into()),
        };

        let ngap_msg = decode_ngap_pdu(&bytes)?;
        let (aid, nas_pdu) = match ngap_msg {
            NgapMessage::DownlinkNasTransport(dl) => (dl.amf_ue_ngap_id, dl.nas_pdu),
            other => return Err(format!("unexpected NGAP message from AMF: {other:?}").into()),
        };
        let amf_ue_ngap_id = *amf_ue_ngap_id.get_or_insert(aid);

        // Auto-detect plain vs protected exactly like `amf::state_machine::
        // handle_uplink_nas` does on the other side — 5G's security header
        // type lives in byte[1]'s low nibble (see nas5gs::codec module doc).
        let sht = nas_pdu.get(1).map(|b| b & 0x0F).unwrap_or(0);

        if sht != NAS5GS_SHT_PLAIN {
            // The only protected downlink message Phase A ever sends is
            // RegistrationAccept.
            let kamf = kamf.ok_or("received a protected PDU before KAMF was derived")?;
            let mut nas_ctx = Nas5gsSecurityContext::new(&kamf, 2, 2);
            let plain = decode_protected_downlink(&mut nas_ctx, &nas_pdu)
                .ok_or("failed to decrypt/verify RegistrationAccept")?;

            match decode_nas5gs(&plain)? {
                Nas5gsPdu::RegistrationAccept(acc) => {
                    println!("[UE ] <- RegistrationAccept (result={})", acc.registration_result);
                    let complete = encode_registration_complete();
                    send_uplink(&mut link, amf_ue_ngap_id, complete).await?;
                    println!("[UE ] -> RegistrationComplete");
                    println!("[UE ] registration complete — subscriber is online.");
                    return Ok(());
                }
                other => return Err(format!("expected RegistrationAccept, got {other:?}").into()),
            }
        }

        match decode_nas5gs(&nas_pdu)? {
            Nas5gsPdu::IdentityRequest { .. } => {
                println!("[UE ] <- IdentityRequest");
                let suci = suci_for_imsi(TEST_IMSI);
                let resp = encode_identity_response_suci(&suci);
                send_uplink(&mut link, amf_ue_ngap_id, resp).await?;
                println!("[UE ] -> IdentityResponse(SUCI)");
            }
            Nas5gsPdu::AuthenticationRequest(req) => {
                println!("[UE ] <- AuthenticationRequest");

                let ki = midn_auth::AuthKey::from_hex(TEST_K)?;
                let opc = midn_auth::OpCode::from_hex(TEST_OPC)?;
                let ctx = midn_auth::MilenageContext::new(ki, opc);
                let milenage_amf = midn_auth::keys::Amf([0x80, 0x00]);
                let vector = ctx.generate_vector_with_rand(
                    midn_auth::keys::Sqn::from_bytes(&sqn_used),
                    milenage_amf,
                    midn_auth::keys::Rand(req.rand),
                );

                let snn = midn_core::kdf::serving_network_name(&TEST_PLMN);
                let res_star =
                    midn_core::kdf::derive_res_star(&vector.ck, &vector.ik, &snn, &req.rand, &vector.res);

                // Independently re-derive the SAME KAUSF -> KSEAF -> KAMF
                // chain the AMF is deriving on its own side right now —
                // proving the whole loop actually closes once
                // RegistrationAccept needs decrypting, same principle the
                // in-process tests already establish, just over real bytes
                // this time.
                let sqn_xor_ak: [u8; 6] = core::array::from_fn(|i| sqn_used[i] ^ vector.ak[i]);
                let kausf = midn_core::kdf::derive_kausf(&vector.ck, &vector.ik, &snn, &sqn_xor_ak);
                let kseaf = midn_core::kdf::derive_kseaf(&kausf, &snn);
                let supi = TEST_IMSI.to_string().into_bytes();
                kamf = Some(midn_core::kdf::derive_kamf(&kseaf, &supi, &[0x00, 0x00]));

                let resp = encode_auth_response(&res_star);
                send_uplink(&mut link, amf_ue_ngap_id, resp).await?;
                println!("[UE ] -> AuthenticationResponse(RES*)");
            }
            Nas5gsPdu::SecurityModeCommand(_) => {
                println!("[UE ] <- SecurityModeCommand");
                let resp = encode_sec_mode_complete();
                send_uplink(&mut link, amf_ue_ngap_id, resp).await?;
                println!("[UE ] -> SecurityModeComplete");
            }
            other => return Err(format!("unexpected plain NAS PDU: {other:?}").into()),
        }
    }
}

/// Encode a null-scheme SUCI carrying `imsi` — the exact inverse of
/// `amf::registration::resolve_suci_to_imsi`.
fn suci_for_imsi(imsi: u64) -> Suci {
    let bytes = imsi.to_be_bytes();
    let mut msin = [0u8; 5];
    msin.copy_from_slice(&bytes[3..8]);
    Suci { mcc: [0, 0, 0], mnc: [0, 0, 0], routing_indicator: 0, protection_scheme: 0, home_network_pki: 0, msin }
}

async fn send_initial(link: &mut SctpLink, nas_pdu: Bytes) -> Result<(), Box<dyn std::error::Error>> {
    let msg = NgapMessage::InitialUeMessage(NgapInitialUeMessage {
        ran_ue_ngap_id: RAN_UE_NGAP_ID,
        nas_pdu,
        tai: TEST_TAI,
        nr_cgi: [0u8; 9],
        rrc_establishment_cause: 0,
    });
    link.send(encode_ngap_pdu(&msg)?).await?;
    Ok(())
}

async fn send_uplink(
    link: &mut SctpLink,
    amf_ue_ngap_id: u32,
    nas_pdu: Bytes,
) -> Result<(), Box<dyn std::error::Error>> {
    let msg = NgapMessage::UplinkNasTransport(NgapUplinkNasTransport {
        amf_ue_ngap_id,
        ran_ue_ngap_id: RAN_UE_NGAP_ID,
        nas_pdu,
        tai: TEST_TAI,
        nr_cgi: [0u8; 9],
    });
    link.send(encode_ngap_pdu(&msg)?).await?;
    Ok(())
}

/// Short, human-readable label for the log lines — `NgapMessage`'s
/// `Debug` impl includes full NAS PDU bytes, which floods the console.
fn ngap_summary(msg: &NgapMessage) -> &'static str {
    match msg {
        NgapMessage::InitialUeMessage(_) => "InitialUeMessage",
        NgapMessage::UplinkNasTransport(_) => "UplinkNasTransport",
        NgapMessage::DownlinkNasTransport(_) => "DownlinkNasTransport",
        NgapMessage::InitialContextSetupRequest(_) => "InitialContextSetupRequest",
        NgapMessage::InitialContextSetupResponse(_) => "InitialContextSetupResponse",
        _ => "(other NGAP message)",
    }
}
