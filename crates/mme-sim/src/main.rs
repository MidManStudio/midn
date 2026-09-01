// crates/mme-sim/src/main.rs
//! LTE twin of `midn-sim`: an MME and a mock UE/eNodeB, in two independent
//! Tokio tasks talking ONLY through a real `midn_transport::SctpLink` (real
//! `UdpSocket`, real SCTP handshake via `rtc_sctp`) — not the in-process
//! `Mme::process_s1ap` calls every existing test uses. Drives the full
//! Attach procedure: AttachRequest -> AuthenticationRequest/Response (real
//! Milenage, not 5G-AKA — LTE's AttachRequest already carries the IMSI, so
//! there's no separate Identity step the way NAS-5GS needs one for its
//! SUCI-based first registration) -> SecurityModeCommand/Complete ->
//! AttachAccept -> AttachComplete -> a real GTP-U user-plane G-PDU round
//! trip. Same shape `midn-sim` already proved for 5G, now for the protocol
//! stack this project actually started with.
//!
//! This binary is also the first real caller of `s1ap::codec`'s
//! InitialContextSetupRequest/Response support — that codec had no caller
//! anywhere in the project until now, same as `ngap::codec`'s equivalent
//! before `midn-sim` existed.
//!
//! Phase 3: AttachAccept + a bundled default EPS bearer arrive together via
//! `InitialContextSetupRequest` instead of `DownlinkNasTransport`. The mock
//! UE/eNodeB decrypts+verifies AttachAccept, then additionally plays the
//! eNodeB side of context setup: replies with `InitialContextSetupResponse`
//! carrying a real DL TEID + its own real S1-U address — the same exchange
//! `mme::attach`/`mme::state_machine` already prove correct in-process.
//!
//! Building this binary surfaced one real, necessary fix, not just a wiring
//! exercise: `nas::security::NasSecurityContext` only had the MME-role
//! `protect_downlink`/`unprotect_uplink` pair — no UE-role
//! `protect_uplink`/`unprotect_downlink` existed, so nothing could actually
//! decrypt AttachAccept or encrypt an uplink-protected message from the UE
//! side. Same gap `nas5gs::security::Nas5gsSecurityContext` had before
//! `midn-sim` needed it, closed the same way, one level down the protocol
//! stack. See that module's doc for the fuller DIRECTION-mismatch
//! rationale.
//!
//! User plane: the MME process also plays the S-GW/UPF role, using
//! `midn_userplane`'s `SessionManager`/`GtpForwarder` — the crate whose own
//! doc comments already talk in native `UpfEvent`/E-RAB/eNodeB terms
//! (`SessionManager::create_session_with_teid`'s doc literally says "MME
//! embeds the TEID in InitialContextSetupRequest.e_rabs[*].gtp_teid"), so
//! this is if anything a more direct fit than the 5G side's N3Event
//! adaptation was. Same "no simulated internet, echo every uplink G-PDU
//! straight back downlink" proof strategy as `midn-sim`.
//!
//! One real simplification, stated plainly, same as `midn-sim`'s own: real
//! 3GPP keeps MME and S-GW/UPF as separate network functions, and eNodeB
//! separate from the UE. This binary collapses each pair into one process
//! for the same reason `midn-sim` already does — a convenience of this
//! simulation, not a protocol requirement. Neither pairing shares any Rust
//! state; everything either side knows about the other comes from real
//! bytes on a real socket.
//!
//! Run (single process, both roles — the default):
//! `cargo run -p mme-sim`
//!
//! Run as two independent OS processes — the shape `netns`+`veth`
//! namespace-isolated testing needs:
//! `cargo run -p mme-sim -- --role mme --bind 10.98.0.1:36412`
//! `cargo run -p mme-sim -- --role ue  --bind 10.98.0.2:0 --mme 10.98.0.1:36412`

use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

use bytes::Bytes;
use midn_proto::gtp::header::GtpuHeader;
use midn_proto::nas::{
    decode_nas, decode_protected_downlink, encode_attach_complete, encode_attach_request,
    encode_auth_response, encode_detach_request, encode_sec_mode_complete, NasEeaAlgorithm,
    NasEiaAlgorithm, NasPdu, NasSecurityContext, NAS_BEARER, SHT_PLAIN,
};
use midn_proto::s1ap::{
    decode_s1ap_pdu, encode_s1ap_pdu, ErabSetupItem, InitialContextSetupResponse, InitialUeMessage,
    S1apMessage, UeContextReleaseComplete, UplinkNasTransport,
};
use midn_transport::{LinkEvent, SctpLink};
use midn_userplane::{DlPacket, GtpForwarder, SessionManager, GTP_PORT};

// ── Shared test-subscriber material ─────────────────────────────────────────
// Same values/shape `midn-sim` uses on the 5G side — a known-good Milenage
// K/OPC pair, an arbitrary but internally-consistent IMSI/PLMN/TAI. LTE's
// AttachRequest carries the IMSI directly (no SUCI-style concealment step
// this simulation models), so there's no equivalent constraint here to the
// 5G side's "< 2^40, round-trips through the 5-byte MSIN SUCI scheme" note.
const TEST_IMSI: u64 = 901_700_000_002;
const TEST_K: &str = "465b5ce8b199b49faa5f0a2ee238a6bc";
const TEST_OPC: &str = "cd63cb71954a9f4e48a5994e37a02baf";
const TEST_PLMN: [u8; 3] = [0x00, 0x11, 0x22];
// TAI = PLMN(3) ‖ TAC(2) — 5 bytes total, NOT NGAP's 6-byte 5G TAI
// (PLMN(3)+TAC(3)) — see s1ap::messages::InitialUeMessage's own field type.
const TEST_TAI: [u8; 5] = [0x00, 0x11, 0x22, 0x00, 0x01];
const TEST_EUTRAN_CGI: [u8; 7] = [0u8; 7];
const ENB_UE_S1AP_ID: u32 = 7;

/// Algorithm pair `mme::attach`'s own `SELECTED_EEA`/`SELECTED_EIA`
/// constants always select — the mock UE has to match, same as
/// `midn-sim`'s mock UE hardcoding the 5G side's always-selected pair
/// rather than actually parsing SecurityModeCommand's proposed algorithms.
const SELECTED_EEA: NasEeaAlgorithm = NasEeaAlgorithm::Eea2;
const SELECTED_EIA: NasEiaAlgorithm = NasEiaAlgorithm::Eia2;

/// DL TEID the mock eNodeB tells the MME/S-GW to use — fixed, same
/// reasoning as `midn-sim`'s `MOCK_DL_TEID` (single subscriber, single
/// bearer per run, nothing to collide with).
const MOCK_DL_TEID: u32 = 0xAABB_CCDD;

/// 36412 is the real, standardized S1AP-over-SCTP port (TS 36.412) —
/// authenticity touch, not load-bearing, same spirit as `midn-sim`'s 38412.
const MME_BIND_ADDR: &str = "127.0.0.1:36412";

/// Extract the IPv4 octets from a `SocketAddr` — identical to `midn-sim`'s
/// helper of the same name; every address this binary ever binds or is
/// told about is IPv4.
fn ipv4_octets(addr: SocketAddr) -> [u8; 4] {
    match addr.ip() {
        IpAddr::V4(v4) => v4.octets(),
        IpAddr::V6(v6) => panic!("expected an IPv4 address, got IPv6: {v6}"),
    }
}

#[derive(Debug)]
enum Role {
    /// Original mode: both sides in this one process, on loopback.
    Both,
    Mme { bind: SocketAddr },
    Ue { bind: SocketAddr, mme: SocketAddr },
}

const USAGE: &str = "\
Usage:
  mme-sim                                              (default: both roles, one process, loopback)
  mme-sim --role mme --bind ADDR:PORT
  mme-sim --role ue  --bind ADDR:PORT --mme ADDR:PORT   (--bind may use :0 for an OS-picked ephemeral port)";

fn parse_args(args: &[String]) -> Result<Role, String> {
    let mut role: Option<&str> = None;
    let mut bind: Option<&str> = None;
    let mut mme: Option<&str> = None;

    let mut i = 0;
    while i < args.len() {
        let (flag, value) = (args[i].as_str(), args.get(i + 1).map(String::as_str));
        match flag {
            "--role" => role = value,
            "--bind" => bind = value,
            "--mme" => mme = value,
            other => return Err(format!("unrecognized argument {other:?}\n\n{USAGE}")),
        }
        if value.is_none() {
            return Err(format!("{flag} needs a value\n\n{USAGE}"));
        }
        i += 2;
    }

    match role {
        None | Some("both") => Ok(Role::Both),
        Some("mme") => Ok(Role::Mme {
            bind: bind
                .unwrap_or(MME_BIND_ADDR)
                .parse()
                .map_err(|e| format!("--bind: {e}\n\n{USAGE}"))?,
        }),
        Some("ue") => Ok(Role::Ue {
            bind: bind
                .ok_or_else(|| format!("--role ue requires --bind ADDR:PORT\n\n{USAGE}"))?
                .parse()
                .map_err(|e| format!("--bind: {e}\n\n{USAGE}"))?,
            mme: mme
                .ok_or_else(|| format!("--role ue requires --mme ADDR:PORT\n\n{USAGE}"))?
                .parse()
                .map_err(|e| format!("--mme: {e}\n\n{USAGE}"))?,
        }),
        Some(other) => Err(format!("unknown --role {other:?} (expected mme, ue, or both)\n\n{USAGE}")),
    }
}

#[cfg(test)]
mod arg_tests {
    use super::*;

    fn args(v: &[&str]) -> Vec<String> {
        v.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn no_args_means_both() {
        assert!(matches!(parse_args(&args(&[])), Ok(Role::Both)));
    }

    #[test]
    fn explicit_role_both() {
        assert!(matches!(parse_args(&args(&["--role", "both"])), Ok(Role::Both)));
    }

    #[test]
    fn mme_role_defaults_bind_addr() {
        match parse_args(&args(&["--role", "mme"])) {
            Ok(Role::Mme { bind }) => assert_eq!(bind, MME_BIND_ADDR.parse().unwrap()),
            other => panic!("expected Role::Mme with the default bind addr, got {other:?}"),
        }
    }

    #[test]
    fn mme_role_with_explicit_bind() {
        match parse_args(&args(&["--role", "mme", "--bind", "10.98.0.1:36412"])) {
            Ok(Role::Mme { bind }) => assert_eq!(bind, "10.98.0.1:36412".parse().unwrap()),
            other => panic!("expected Role::Mme with the given bind addr, got {other:?}"),
        }
    }

    #[test]
    fn ue_role_requires_bind_and_mme() {
        match parse_args(&args(&["--role", "ue", "--bind", "10.98.0.2:0", "--mme", "10.98.0.1:36412"])) {
            Ok(Role::Ue { bind, mme }) => {
                assert_eq!(bind, "10.98.0.2:0".parse().unwrap());
                assert_eq!(mme, "10.98.0.1:36412".parse().unwrap());
            }
            other => panic!("expected Role::Ue with both addrs, got {other:?}"),
        }
    }

    #[test]
    fn ue_role_without_bind_is_an_error() {
        assert!(parse_args(&args(&["--role", "ue", "--mme", "10.98.0.1:36412"])).is_err());
    }

    #[test]
    fn ue_role_without_mme_is_an_error() {
        assert!(parse_args(&args(&["--role", "ue", "--bind", "10.98.0.2:0"])).is_err());
    }

    #[test]
    fn unknown_role_is_an_error() {
        assert!(parse_args(&args(&["--role", "upf"])).is_err());
    }

    #[test]
    fn unrecognized_flag_is_an_error() {
        assert!(parse_args(&args(&["--wat", "huh"])).is_err());
    }

    #[test]
    fn bad_addr_is_an_error() {
        assert!(parse_args(&args(&["--role", "mme", "--bind", "not-an-addr"])).is_err());
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::WARN)
        .init();

    let args: Vec<String> = std::env::args().skip(1).collect();
    let role = parse_args(&args).map_err(|e| -> Box<dyn std::error::Error + Send + Sync> { e.into() })?;

    match role {
        Role::Both => run_both().await,

        Role::Mme { bind } => {
            println!("mme-sim — MME only\n");
            // No matching drain-sleep-then-exit here on purpose — same
            // reasoning as midn-sim's Role::Amf arm: a single-role MME
            // process has no natural end, it's meant to keep serving until
            // whatever started it explicitly stops it.
            run_mme(bind).await
        }

        Role::Ue { bind, mme } => {
            println!("mme-sim — UE/eNodeB only, {bind} -> MME {mme}\n");
            tokio::time::sleep(Duration::from_millis(50)).await;

            let result = run_ue(bind, mme).await;
            match &result {
                Ok(()) => println!(
                    "\n✅ Full Attach procedure, user-plane G-PDU round trip, and Detach all confirmed, over a real SCTP-over-UDP socket."
                ),
                Err(e) => println!("\n❌ Simulation failed: {e}"),
            }
            result
        }
    }
}

/// Original combined mode: both sides as Tokio tasks in this one process,
/// on loopback. Still the default (`mme-sim` with no args).
async fn run_both() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let mme_addr: SocketAddr = MME_BIND_ADDR.parse().unwrap();
    // 127.0.0.2, not 127.0.0.1 — same collision-avoidance reasoning as
    // midn-sim's run_both: both sides also bind a GTP-U socket on the fixed
    // port 2152 once the MME side stands up its UPF role.
    let ue_bind_addr: SocketAddr = "127.0.0.2:0".parse().unwrap();

    println!("mme-sim — MME + mock UE/eNodeB over a real SCTP-over-UDP socket\n");

    let mme_task = tokio::spawn(run_mme(mme_addr));

    tokio::time::sleep(Duration::from_millis(50)).await;

    let ue_result = run_ue(ue_bind_addr, mme_addr).await;

    match &ue_result {
        Ok(()) => println!(
            "\n✅ Full Attach procedure, user-plane G-PDU round trip, and Detach all confirmed, over a real SCTP-over-UDP socket."
        ),
        Err(e) => println!("\n❌ Simulation failed: {e}"),
    }

    // Same shutdown-race reasoning midn-sim's run_both documents in detail
    // (and hit for real on build #3 of its own smoke-test workflow): the UE
    // task returning Ok only proves its last sends completed locally, not
    // that the MME task has processed them yet.
    tokio::time::sleep(Duration::from_millis(200)).await;

    mme_task.abort();
    ue_result
}

// ── MME side ─────────────────────────────────────────────────────────────────

async fn run_mme(bind_addr: SocketAddr) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    // This process plays S-GW/UPF too — see module doc. Real address, not a
    // fixed placeholder: the bundled EPS bearer tells the UE to actually
    // send uplink traffic here.
    let upf_ip = ipv4_octets(bind_addr);
    let mut mme = midn_core::mme::Mme::new().with_phase3(upf_ip);
    mme.hss_mut().provision_hex(TEST_IMSI, TEST_K, TEST_OPC)?;

    let mut session_mgr = SessionManager::new();
    let routing = session_mgr.routing_arc();
    let (ul_tx, mut ul_rx) = tokio::sync::mpsc::channel(64);
    let gtp_bind_addr = SocketAddr::from((upf_ip, GTP_PORT));
    let (fwd, dl_tx) = GtpForwarder::bind_addr(&gtp_bind_addr.to_string(), routing, ul_tx).await?;
    println!("[UPF] GTP-U forwarder listening on {gtp_bind_addr}");
    tokio::spawn(fwd.run());

    // Same "no simulated internet, echo uplink straight back downlink"
    // proof strategy as midn-sim's run_amf.
    tokio::spawn(async move {
        while let Some(pkt) = ul_rx.recv().await {
            println!(
                "[UPF] <- G-PDU UL ({} bytes) — routing to UE {:?}",
                pkt.inner_ip.len(), pkt.route.ue_ip
            );
            let echo = DlPacket { inner_ip: pkt.inner_ip.clone(), ue_ip: pkt.route.ue_ip };
            if dl_tx.send(echo).await.is_err() {
                println!("[UPF] DL channel closed — stopping echo task");
                break;
            }
            println!("[UPF] -> G-PDU DL ({} bytes, echoed back)", pkt.inner_ip.len());
        }
    });

    println!("[MME] binding {bind_addr}, waiting for an association...");
    let mut link = SctpLink::accept(bind_addr).await?;

    loop {
        match link.recv().await {
            Some(LinkEvent::Connected) => {
                println!("[MME] SCTP association established");
            }
            Some(LinkEvent::Message(bytes)) => {
                let msg = match decode_s1ap_pdu(&bytes) {
                    Ok(m) => m,
                    Err(e) => {
                        eprintln!("[MME] failed to decode inbound S1AP PDU: {e}");
                        continue;
                    }
                };
                println!("[MME] <- {}", s1ap_summary(&msg));

                let (responses, events) = mme.process_s1ap(msg).await;
                for evt in &events {
                    println!("[MME]    (UpfEvent: {evt:?})");
                    apply_upf_event(&mut session_mgr, evt);
                }
                for resp in responses {
                    println!("[MME] -> {}", s1ap_summary(&resp));
                    let out = encode_s1ap_pdu(&resp)?;
                    link.send(out).await?;
                }
            }
            Some(LinkEvent::Lost { reason }) => {
                println!("[MME] link lost: {reason}");
                return Ok(());
            }
            None => return Ok(()),
        }
    }
}

/// Apply one `UpfEvent` to the UPF's session state. Unlike midn-sim's 5G
/// side, this needs no field-name translation at all — `UpfEvent`'s own
/// field names (`enb_addr`, `qci`) already match `SessionManager`'s
/// parameter names exactly, since that crate's doc comments were written
/// with this exact LTE vocabulary in mind.
fn apply_upf_event(session_mgr: &mut SessionManager, evt: &midn_core::UpfEvent) {
    use midn_core::UpfEvent;
    match *evt {
        UpfEvent::CreateSession { ul_teid, entity_id, imsi, qci, ue_ip, enb_addr } => {
            session_mgr.create_session_with_teid(ul_teid, entity_id, imsi, ue_ip, enb_addr, qci);
        }
        UpfEvent::UpdateBearer { ul_teid, dl_teid, enb_addr } => {
            if !session_mgr.update_bearer_info(ul_teid, dl_teid, enb_addr) {
                eprintln!("[UPF] update_bearer_info: no session found for ul_teid={ul_teid:08x} (CreateSession missing or already removed)");
            }
        }
        UpfEvent::RemoveSession { ul_teid } => {
            session_mgr.remove_session(ul_teid);
        }
    }
}

// ── UE / eNodeB side ─────────────────────────────────────────────────────────

async fn run_ue(bind_addr: SocketAddr, mme_addr: SocketAddr) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let my_ip = ipv4_octets(bind_addr);

    // Bound early — ready to receive the DL G-PDU echo whenever the UPF
    // gets around to sending it.
    let gtp_sock = tokio::net::UdpSocket::bind(SocketAddr::from((my_ip, GTP_PORT))).await?;

    println!("[UE ] connecting to MME at {mme_addr}");
    let mut link = SctpLink::connect(bind_addr, mme_addr).await?;

    match link.recv().await {
        Some(LinkEvent::Connected) => println!("[UE ] SCTP association established"),
        Some(LinkEvent::Lost { reason }) => return Err(format!("link lost before connecting: {reason}").into()),
        Some(_) => return Err("unexpected event before Connected".into()),
        None => return Err("link closed before connecting".into()),
    }

    // Step 1: AttachRequest, carrying the IMSI directly — LTE has no
    // SUCI-style concealment step, so unlike midn-sim there's no separate
    // Identity Request/Response round trip before this. eps_attach_type=1
    // ("EPS attach", TS 24.301 Table 9.9.3.11.1), nas_ksi=0.
    let attach_req = encode_attach_request(TEST_IMSI, 1, 0);
    send_initial(&mut link, attach_req).await?;
    println!("[UE ] -> AttachRequest");

    let mut mme_ue_s1ap_id: Option<u32> = None;
    // First vector for a freshly provisioned subscriber — SQN starts at 0.
    // Same assumption midn-sim's mock UE makes on the 5G side, see Hss's
    // own doc/tests for why it's safe here.
    let sqn_used = [0u8; 6];
    let mut kasme: Option<[u8; 32]> = None;

    loop {
        let bytes = match link.recv().await {
            Some(LinkEvent::Message(b)) => b,
            Some(LinkEvent::Lost { reason }) => return Err(format!("link lost: {reason}").into()),
            Some(LinkEvent::Connected) => continue, // already handled above
            None => return Err("link closed unexpectedly".into()),
        };

        let s1ap_msg = decode_s1ap_pdu(&bytes)?;

        match s1ap_msg {
            S1apMessage::DownlinkNasTransport(dl) => {
                let mme_ue_s1ap_id = *mme_ue_s1ap_id.get_or_insert(dl.mme_ue_s1ap_id);
                let nas_pdu = dl.nas_pdu;

                // LTE's NAS header combines PD and SHT in ONE byte (high
                // nibble = SHT), unlike NAS-5GS which splits them across
                // two bytes — see decode_protected_downlink's own check for
                // the same byte/nibble position this mirrors.
                let sht = nas_pdu.first().map(|b| (*b >> 4) & 0x0F).unwrap_or(0);

                if sht != SHT_PLAIN {
                    // The only protected downlink message this arm actually
                    // sees in this binary's real flow is DetachAccept —
                    // Phase 3's AttachAccept always arrives via
                    // InitialContextSetupRequest instead (below), never
                    // here, since Mme::with_phase3 is always on.
                    let kasme = kasme.ok_or("received a protected PDU before Kasme was derived")?;
                    let mut nas_ctx = NasSecurityContext::new(&kasme, SELECTED_EEA, SELECTED_EIA);
                    let plain = decode_protected_downlink(&mut nas_ctx, &nas_pdu, NAS_BEARER)
                        .ok_or("failed to decrypt/verify DetachAccept")?;

                    match decode_nas(&plain)? {
                        NasPdu::DetachAccept => {
                            println!("[UE ] <- DetachAccept");
                            // UeContextReleaseCommand follows as its own
                            // separate S1AP message — handled by that match
                            // arm below, once this loop continues.
                        }
                        other => return Err(format!("expected DetachAccept, got {other:?}").into()),
                    }
                    continue;
                }

                match decode_nas(&nas_pdu)? {
                    NasPdu::AuthenticationRequest(req) => {
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

                        // LTE's key hierarchy stops one level short of 5G's:
                        // straight from CK/IK to Kasme, no KAUSF/KSEAF/RES*
                        // chain — Milenage's RES is used directly as the
                        // AuthenticationResponse, not re-derived into RES*.
                        let sqn_xor_ak: [u8; 6] = core::array::from_fn(|i| sqn_used[i] ^ vector.ak[i]);
                        kasme = Some(midn_core::kdf::derive_kasme(&vector.ck, &vector.ik, &TEST_PLMN, &sqn_xor_ak));

                        let resp = encode_auth_response(&vector.res);
                        send_uplink(&mut link, mme_ue_s1ap_id, resp).await?;
                        println!("[UE ] -> AuthenticationResponse(RES)");
                    }
                    NasPdu::SecurityModeCommand(_) => {
                        println!("[UE ] <- SecurityModeCommand");
                        let resp = encode_sec_mode_complete();
                        send_uplink(&mut link, mme_ue_s1ap_id, resp).await?;
                        println!("[UE ] -> SecurityModeComplete");
                    }
                    other => return Err(format!("unexpected plain NAS PDU: {other:?}").into()),
                }
            }

            S1apMessage::InitialContextSetupRequest(icsr) => {
                // Phase 3: AttachAccept + the bundled default EPS bearer
                // arrive together here instead of via DownlinkNasTransport.
                let mme_ue_s1ap_id = *mme_ue_s1ap_id.get_or_insert(icsr.mme_ue_s1ap_id);
                let enb_ue_s1ap_id = icsr.enb_ue_s1ap_id;

                let kasme = kasme.ok_or("received InitialContextSetupRequest before Kasme was derived")?;
                let nas_pdu = icsr
                    .nas_pdu
                    .ok_or("InitialContextSetupRequest with no piggybacked NAS PDU")?;
                let mut nas_ctx = NasSecurityContext::new(&kasme, SELECTED_EEA, SELECTED_EIA);
                let plain = decode_protected_downlink(&mut nas_ctx, &nas_pdu, NAS_BEARER)
                    .ok_or("failed to decrypt/verify AttachAccept")?;
                let acc = match decode_nas(&plain)? {
                    NasPdu::AttachAccept(acc) => acc,
                    other => return Err(format!("expected AttachAccept, got {other:?}").into()),
                };
                println!("[UE ] <- AttachAccept (result={}, ip={:?})", acc.attach_result, acc.ip_address);

                let erab = icsr
                    .e_rabs
                    .first()
                    .ok_or("InitialContextSetupRequest with no E-RAB to set up")?;
                let erab_id = erab.erab_id;
                let qci = erab.qci;
                let ul_teid = u32::from_be_bytes(erab.gtp_teid);
                let upf_addr = erab.transport_layer_addr;
                println!(
                    "[UE ] <- bundled E-RAB {erab_id} (qci={qci}, UL TEID={ul_teid:08x}, UPF={upf_addr:?})"
                );

                // eNodeB confirms the security context + bearer: real DL
                // TEID + this process's own real S1-U address — not a fixed
                // placeholder, since the UPF needs to actually reach it for
                // the G-PDU echo below to land anywhere.
                let icrsp = S1apMessage::InitialContextSetupResponse(InitialContextSetupResponse {
                    mme_ue_s1ap_id,
                    enb_ue_s1ap_id,
                    e_rabs_setup: vec![ErabSetupItem {
                        e_rab_id: erab_id,
                        transport_layer_addr: my_ip,
                        gtp_teid: MOCK_DL_TEID.to_be_bytes(),
                    }],
                    e_rabs_failed: vec![],
                });
                link.send(encode_s1ap_pdu(&icrsp)?).await?;
                println!("[UE ] -> InitialContextSetupResponse");

                // AttachComplete stays plain, same simplification the NAS
                // codec doc already states — SecurityModeCommand/Complete
                // and this final Complete message aren't protected in this
                // simulation, only AttachAccept is.
                let complete = encode_attach_complete();
                send_uplink(&mut link, mme_ue_s1ap_id, complete).await?;
                println!("[UE ] -> AttachComplete");
                println!("[UE ] attach complete — subscriber is online, E-RAB {erab_id} up.");

                user_plane_round_trip(&gtp_sock, upf_addr, ul_teid).await?;

                // UeContextReleaseCommand/Complete gained real wire codec
                // support this session — drive a full Detach to completion
                // too, over the real socket. DetachAccept (protected)
                // arrives via a separate DownlinkNasTransport, handled
                // above; the loop continues rather than returning here.
                // detach_type=1 ("normal detach", TS 24.301 Table
                // 9.9.3.7.1), switch_off=false. No real GUTI was ever
                // assigned (mme::attach never populates AttachAccept's
                // optional guti field in this codebase), so this is a
                // fixed placeholder — matches the "no real allocator, fixed
                // placeholder" simplification already used elsewhere in
                // both sim binaries.
                let detach = encode_detach_request(1, false, 0, &[0u8; 10]);
                send_uplink(&mut link, mme_ue_s1ap_id, detach).await?;
                println!("[UE ] -> DetachRequest");
            }

            S1apMessage::UeContextReleaseCommand { cause } => {
                println!("[UE ] <- UeContextReleaseCommand (cause={cause:?})");
                // No UE-ID IE on this message in this codebase's simplified
                // encoding (see s1ap::codec's own doc) — this simulation
                // only ever has one UE per socket, so the MME-UE-S1AP-ID
                // learned earlier in this same run is unambiguous.
                let mme_ue_s1ap_id = mme_ue_s1ap_id
                    .ok_or("received UeContextReleaseCommand before MME-UE-S1AP-ID was known")?;
                let complete = S1apMessage::UeContextReleaseComplete(UeContextReleaseComplete {
                    mme_ue_s1ap_id, enb_ue_s1ap_id: ENB_UE_S1AP_ID,
                });
                link.send(encode_s1ap_pdu(&complete)?).await?;
                println!("[UE ] -> UeContextReleaseComplete");
                println!("[UE ] detach complete — subscriber is offline.");
                return Ok(());
            }

            other => return Err(format!("unexpected S1AP message from MME: {other:?}").into()),
        }
    }
}

/// Send one real GTP-U G-PDU uplink and confirm it comes back down.
/// Byte-for-byte identical logic to `midn-sim`'s function of the same name
/// — GTP-U itself has no LTE/5G distinction at this layer, and the retry
/// loop's rationale (a genuine race between the MME processing this UE's
/// InitialContextSetupResponse and this first uplink packet arriving) is
/// the same race in the same shape.
async fn user_plane_round_trip(
    gtp_sock: &tokio::net::UdpSocket,
    upf_addr: [u8; 4],
    ul_teid: u32,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    const PAYLOAD: &[u8] = b"real user data over a real GTP-U tunnel";
    let hdr = GtpuHeader::new_gpdu(ul_teid, PAYLOAD.len() as u16);
    let mut gpdu = Vec::with_capacity(GtpuHeader::SIZE + PAYLOAD.len());
    gpdu.extend_from_slice(&hdr.to_bytes());
    gpdu.extend_from_slice(PAYLOAD);
    let upf_gtp_addr = SocketAddr::from((upf_addr, GTP_PORT));

    let mut buf = vec![0u8; 512];
    for attempt in 1..=5 {
        gtp_sock.send_to(&gpdu, upf_gtp_addr).await?;
        println!(
            "[UE ] -> G-PDU UL (ul_teid={ul_teid:08x}, {} bytes) -> UPF {upf_gtp_addr} (attempt {attempt}/5)",
            PAYLOAD.len()
        );

        let recv = tokio::time::timeout(Duration::from_millis(500), gtp_sock.recv_from(&mut buf)).await;
        let Ok(Ok((len, _))) = recv else { continue };
        let Some((dl_hdr, dl_payload)) = GtpuHeader::parse(&buf[..len]) else { continue };

        println!("[UE ] <- G-PDU DL (dl_teid={:08x}, {} bytes)", dl_hdr.teid, dl_payload.len());
        if dl_payload != PAYLOAD {
            return Err(format!(
                "DL G-PDU payload mismatch: sent {PAYLOAD:?}, got back {dl_payload:?}"
            ).into());
        }
        println!("[UE ] user-plane G-PDU round trip confirmed — payload matches what was sent.");
        return Ok(());
    }

    Err("no DL G-PDU echo received after 5 attempts".into())
}

async fn send_initial(link: &mut SctpLink, nas_pdu: Bytes) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let msg = S1apMessage::InitialUeMessage(InitialUeMessage {
        enb_ue_s1ap_id: ENB_UE_S1AP_ID,
        nas_pdu,
        tai: TEST_TAI,
        eutran_cgi: TEST_EUTRAN_CGI,
        rrc_cause: 0,
    });
    link.send(encode_s1ap_pdu(&msg)?).await?;
    Ok(())
}

async fn send_uplink(
    link: &mut SctpLink,
    mme_ue_s1ap_id: u32,
    nas_pdu: Bytes,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let msg = S1apMessage::UplinkNasTransport(UplinkNasTransport {
        mme_ue_s1ap_id,
        enb_ue_s1ap_id: ENB_UE_S1AP_ID,
        nas_pdu,
        tai: TEST_TAI,
        eutran_cgi: TEST_EUTRAN_CGI,
    });
    link.send(encode_s1ap_pdu(&msg)?).await?;
    Ok(())
}

/// Short, human-readable label for the log lines — `S1apMessage`'s `Debug`
/// impl includes full NAS PDU bytes, which floods the console.
fn s1ap_summary(msg: &S1apMessage) -> &'static str {
    match msg {
        S1apMessage::InitialUeMessage(_) => "InitialUeMessage",
        S1apMessage::UplinkNasTransport(_) => "UplinkNasTransport",
        S1apMessage::DownlinkNasTransport(_) => "DownlinkNasTransport",
        S1apMessage::InitialContextSetupRequest(_) => "InitialContextSetupRequest",
        S1apMessage::InitialContextSetupResponse(_) => "InitialContextSetupResponse",
        S1apMessage::UeContextReleaseCommand { .. } => "UeContextReleaseCommand",
        S1apMessage::UeContextReleaseComplete(_) => "UeContextReleaseComplete",
        _ => "(other S1AP message)",
    }
}
