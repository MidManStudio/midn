// crates/midn-sim/src/main.rs
//! First real end-to-end proof for the "no physical hardware, $0 Linux box"
//! goal: an AMF and a mock UE/gNB, in two independent Tokio tasks talking
//! ONLY through a real `midn_transport::SctpLink` (real `UdpSocket`, real
//! SCTP handshake via `rtc_sctp`) — not the in-process `Amf::process_ngap`
//! calls every existing test uses. Drives the full Registration procedure:
//! RegistrationRequest -> IdentityRequest/Response -> AuthenticationRequest/
//! Response (real 5G-AKA) -> SecurityModeCommand/Complete -> RegistrationAccept
//! -> RegistrationComplete -> a real GTP-U user-plane G-PDU round trip.
//!
//! Phase B: RegistrationAccept + a bundled default PDU session arrive
//! together via `InitialContextSetupRequest` instead of
//! `DownlinkNasTransport`. The mock UE/gNB decrypts+verifies RegistrationAccept
//! exactly as before, then additionally plays the gNB side of context setup:
//! replies with `InitialContextSetupResponse` carrying a real DL TEID + its
//! own real N3 address — the same exchange `amf::state_machine`'s own
//! `full_registration_flow_phase_b_bundles_pdu_session_and_completes_ics`
//! test already proves the AMF side handles correctly in-process.
//!
//! User plane: the AMF process also plays the UPF role — `midn_userplane`'s
//! `SessionManager`/`GtpForwarder` were already built and already had their
//! own real-socket integration tests, just never driven by a real AMF's
//! `N3Event`s before. Each event `Amf::process_ngap` emits gets applied to
//! the SessionManager exactly the way that crate's own doc says an MME/AMF
//! should (`CreateSession`/`UpdateBearer`/`RemoveSession` map 1:1 onto
//! `create_session_with_teid`/`update_bearer_info`/`remove_session`). No
//! simulated internet exists on the other side of the UPF, so uplink G-PDUs
//! are simply echoed straight back downlink — proof the UL decap+route and
//! DL route+encap paths both work, without needing a third simulated node.
//!
//! One real simplification, stated plainly: real 3GPP keeps AMF and UPF as
//! separate network functions. This binary collapses them into the same
//! process/address for the same reason the UE and gNB are already
//! collapsed — it's a convenience of this simulation, not a protocol
//! requirement, and neither pairing shares any Rust state either way.
//! Everything either side knows about the other still comes from real bytes
//! on a real socket.
//!
//! Run (single process, both roles — the original mode, still the default):
//! `cargo run -p midn-sim`
//!
//! Run as two independent OS processes instead — the shape `netns`+`veth`
//! namespace-isolated testing needs, since two Tokio tasks in one process
//! can't be placed in separate namespaces:
//! `cargo run -p midn-sim -- --role amf --bind 10.99.0.1:38412`
//! `cargo run -p midn-sim -- --role ue  --bind 10.99.0.2:0 --amf 10.99.0.1:38412`

use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

use bytes::Bytes;
use midn_proto::gtp::header::GtpuHeader;
use midn_proto::nas5gs::{
    decode_nas5gs, decode_protected_downlink, encode_auth_response, encode_identity_response_suci,
    encode_registration_complete, encode_registration_request, encode_sec_mode_complete, Nas5gsPdu,
    Nas5gsSecurityContext, Suci, NAS5GS_SHT_PLAIN,
};
use midn_proto::ngap::{
    decode_ngap_pdu, encode_ngap_pdu, NgapInitialContextSetupResponse, NgapInitialUeMessage,
    NgapMessage, NgapUplinkNasTransport, PduSessionSetupItem,
};
use midn_transport::{LinkEvent, SctpLink};
use midn_userplane::{DlPacket, GtpForwarder, SessionManager, GTP_PORT};

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

/// DL TEID the mock gNB tells the AMF/UPF to use — a real gNB would
/// allocate this itself; fixed here since nothing in this simulation reuses
/// or collides with it (single subscriber, single PDU session per run).
const MOCK_DL_TEID: u32 = 0xAABB_CCDD;

/// 38412 is the real, standardized NGAP-over-SCTP port (TS 38.412) —
/// authenticity touch, not load-bearing: whichever addresses the two sides
/// actually get told to use (loopback in the default mode, real veth-pair
/// IPs under `--role`) is what matters; any free, unprivileged port
/// (>1024, no root needed) would work identically.
const AMF_BIND_ADDR: &str = "127.0.0.1:38412";

/// Extract the IPv4 octets from a `SocketAddr` — every address this binary
/// ever binds or is told about is IPv4 (see `parse_args`'s `USAGE` string
/// and `run_both`'s hardcoded addresses), so this is a real, checked
/// assumption, not a silent narrowing.
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
    Amf { bind: SocketAddr },
    Ue { bind: SocketAddr, amf: SocketAddr },
}

const USAGE: &str = "\
Usage:
  midn-sim                                              (default: both roles, one process, loopback)
  midn-sim --role amf --bind ADDR:PORT
  midn-sim --role ue  --bind ADDR:PORT --amf ADDR:PORT   (--bind may use :0 for an OS-picked ephemeral port)";

fn parse_args(args: &[String]) -> Result<Role, String> {
    let mut role: Option<&str> = None;
    let mut bind: Option<&str> = None;
    let mut amf: Option<&str> = None;

    let mut i = 0;
    while i < args.len() {
        let (flag, value) = (args[i].as_str(), args.get(i + 1).map(String::as_str));
        match flag {
            "--role" => role = value,
            "--bind" => bind = value,
            "--amf" => amf = value,
            other => return Err(format!("unrecognized argument {other:?}\n\n{USAGE}")),
        }
        if value.is_none() {
            return Err(format!("{flag} needs a value\n\n{USAGE}"));
        }
        i += 2;
    }

    match role {
        None | Some("both") => Ok(Role::Both),
        Some("amf") => Ok(Role::Amf {
            bind: bind
                .unwrap_or(AMF_BIND_ADDR)
                .parse()
                .map_err(|e| format!("--bind: {e}\n\n{USAGE}"))?,
        }),
        Some("ue") => Ok(Role::Ue {
            bind: bind
                .ok_or_else(|| format!("--role ue requires --bind ADDR:PORT\n\n{USAGE}"))?
                .parse()
                .map_err(|e| format!("--bind: {e}\n\n{USAGE}"))?,
            amf: amf
                .ok_or_else(|| format!("--role ue requires --amf ADDR:PORT\n\n{USAGE}"))?
                .parse()
                .map_err(|e| format!("--amf: {e}\n\n{USAGE}"))?,
        }),
        Some(other) => Err(format!("unknown --role {other:?} (expected amf, ue, or both)\n\n{USAGE}")),
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
    fn amf_role_defaults_bind_addr() {
        match parse_args(&args(&["--role", "amf"])) {
            Ok(Role::Amf { bind }) => assert_eq!(bind, AMF_BIND_ADDR.parse().unwrap()),
            other => panic!("expected Role::Amf with the default bind addr, got {other:?}"),
        }
    }

    #[test]
    fn amf_role_with_explicit_bind() {
        match parse_args(&args(&["--role", "amf", "--bind", "10.99.0.1:38412"])) {
            Ok(Role::Amf { bind }) => assert_eq!(bind, "10.99.0.1:38412".parse().unwrap()),
            other => panic!("expected Role::Amf with the given bind addr, got {other:?}"),
        }
    }

    #[test]
    fn ue_role_requires_bind_and_amf() {
        match parse_args(&args(&["--role", "ue", "--bind", "10.99.0.2:0", "--amf", "10.99.0.1:38412"])) {
            Ok(Role::Ue { bind, amf }) => {
                assert_eq!(bind, "10.99.0.2:0".parse().unwrap());
                assert_eq!(amf, "10.99.0.1:38412".parse().unwrap());
            }
            other => panic!("expected Role::Ue with both addrs, got {other:?}"),
        }
    }

    #[test]
    fn ue_role_without_bind_is_an_error() {
        assert!(parse_args(&args(&["--role", "ue", "--amf", "10.99.0.1:38412"])).is_err());
    }

    #[test]
    fn ue_role_without_amf_is_an_error() {
        assert!(parse_args(&args(&["--role", "ue", "--bind", "10.99.0.2:0"])).is_err());
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
        assert!(parse_args(&args(&["--role", "amf", "--bind", "not-an-addr"])).is_err());
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

        Role::Amf { bind } => {
            println!("midn-sim — AMF only\n");
            // No matching drain-sleep-then-exit here on purpose: a
            // single-role AMF process has no natural end (`run_amf` only
            // returns on a lost/closed link) — it's meant to keep serving
            // until whatever started it (a netns/veth test script, most
            // likely) explicitly stops it. See `run_both`'s doc comment
            // for why that orchestrator needs its own drain delay before
            // doing so, same reasoning as the single-process shutdown race
            // this file already hit once.
            run_amf(bind).await
        }

        Role::Ue { bind, amf } => {
            println!("midn-sim — UE/gNB only, {bind} -> AMF {amf}\n");
            // Same reasoning as `run_both`'s startup sleep: gives the peer
            // process a head start on binding before the first INIT is
            // sent. Cheaper than polling for it, SCTP's own retransmission
            // covers the rest if this isn't enough.
            tokio::time::sleep(Duration::from_millis(50)).await;

            let result = run_ue(bind, amf).await;
            match &result {
                Ok(()) => println!(
                    "\n✅ Full Registration procedure completed and user-plane G-PDU round trip confirmed, over a real SCTP-over-UDP socket."
                ),
                Err(e) => println!("\n❌ Simulation failed: {e}"),
            }
            result
        }
    }
}

/// Original combined mode: both sides as Tokio tasks in this one process,
/// on loopback. Still the default (`midn-sim` with no args) — the existing
/// `midn-sim-smoke-test.yml` workflow calls it exactly this way and needs
/// no changes.
async fn run_both() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let amf_addr: SocketAddr = AMF_BIND_ADDR.parse().unwrap();
    // 127.0.0.2, not 127.0.0.1 — needs to be a genuinely different address
    // from the AMF side now that both sides also bind a GTP-U socket on the
    // fixed port 2152 (`GTP_PORT`): same IP for both would collide on that
    // bind. The whole 127.0.0.0/8 block routes to loopback on Linux with no
    // extra interface config needed, so this "just works" the same way
    // 127.0.0.1 always has. Port 0 still means "OS picks a free ephemeral
    // port" for the control-plane (SCTP-over-UDP) socket specifically.
    let ue_bind_addr: SocketAddr = "127.0.0.2:0".parse().unwrap();

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
            "\n✅ Full Registration procedure completed and user-plane G-PDU round trip confirmed, over a real SCTP-over-UDP socket."
        ),
        Err(e) => println!("\n❌ Simulation failed: {e}"),
    }

    // `run_ue` returning Ok only means the UE's last two sends
    // (InitialContextSetupResponse, RegistrationComplete) completed
    // locally — UDP is fire-and-forget, so that's the send-side syscall
    // finishing, not proof the AMF task has received, let alone processed,
    // either one yet. Without this drain window, `amf_task.abort()` below
    // can (and on build #3 of this workflow, did) kill the AMF task before
    // it ever gets scheduled to consume those last two datagrams — the
    // run still printed "success" because that line only reflects the UE
    // side, while AMF-side confirmation (N3Event::UpdateBearer, the
    // RegistrationComplete log line) silently never happened. Same
    // approximate-not-exact tradeoff as the startup sleep above, just on
    // the other end of the run; 200ms is generous relative to a couple of
    // loopback UDP round trips + task wakeups, cheap against the
    // workflow's 30s budget.
    //
    // A `--role amf` / `--role ue` two-process run has the exact same
    // shape of race — whatever starts both processes for a netns/veth test
    // needs its own equivalent drain delay between the UE process exiting
    // and killing the AMF process, or it'll hit the same silently-missing
    // AMF-side confirmation build #3 of the smoke-test workflow did.
    tokio::time::sleep(Duration::from_millis(200)).await;

    amf_task.abort();
    ue_result
}

// ── AMF side ─────────────────────────────────────────────────────────────────

async fn run_amf(bind_addr: SocketAddr) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    // This process plays UPF too — see module doc for why that's an honest
    // simplification, not silently glossed over. The UPF's N3 address is
    // this same process's real address (same IP the control plane is
    // bound to, GTP-U's own standard port instead of NGAP's) — NOT a fixed
    // placeholder, since the bundled PDU session tells the UE to actually
    // send uplink traffic there.
    let upf_ip = ipv4_octets(bind_addr);
    let mut amf = midn_core::amf::Amf::new().with_phase_b(upf_ip);
    amf.hss_mut().provision_hex(TEST_IMSI, TEST_K, TEST_OPC)?;

    let mut session_mgr = SessionManager::new();
    let routing = session_mgr.routing_arc();
    let (ul_tx, mut ul_rx) = tokio::sync::mpsc::channel(64);
    let gtp_bind_addr = SocketAddr::from((upf_ip, GTP_PORT));
    let (fwd, dl_tx) = GtpForwarder::bind_addr(&gtp_bind_addr.to_string(), routing, ul_tx).await?;
    println!("[UPF] GTP-U forwarder listening on {gtp_bind_addr}");
    tokio::spawn(fwd.run());

    // No simulated internet exists on the other side of this UPF — echo
    // every uplink G-PDU straight back downlink. That alone exercises both
    // directions for real: UL decap + routing.lookup_ul, then DL
    // routing.lookup_dl + re-encap, over the exact same `GtpForwarder` that
    // crate's own tests already proved works over a real socket — this is
    // the first time anything actually drives it from a real AMF's events
    // instead of a hand-built RoutingTable.
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
                    apply_n3_event(&mut session_mgr, evt);
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

/// Apply one `N3Event` to the UPF's session state — the 1:1 mapping
/// `midn_userplane::SessionManager`'s own module doc already documents for
/// `UpfEvent` (same shape, `midn_core::amf::N3Event` is the 5G-side name for
/// it). `qfi` stands in for `SessionManager`'s LTE-shaped `qci: u8`
/// parameter — same spirit as reusing `TeidAllocator` across mme/amf, a
/// generic "QoS class byte" the forwarder only uses for logging/metrics,
/// not literally the same 3GPP field.
fn apply_n3_event(session_mgr: &mut SessionManager, evt: &midn_core::amf::N3Event) {
    use midn_core::amf::N3Event;
    match *evt {
        N3Event::CreateSession { ul_teid, entity_id, imsi, qfi, ue_ip, gnb_addr, .. } => {
            session_mgr.create_session_with_teid(ul_teid, entity_id, imsi, ue_ip, gnb_addr, qfi);
        }
        N3Event::UpdateBearer { ul_teid, dl_teid, gnb_addr } => {
            if !session_mgr.update_bearer_info(ul_teid, dl_teid, gnb_addr) {
                eprintln!("[UPF] update_bearer_info: no session found for ul_teid={ul_teid:08x} (CreateSession missing or already removed)");
            }
        }
        N3Event::RemoveSession { ul_teid } => {
            session_mgr.remove_session(ul_teid);
        }
    }
}

// ── UE / gNB side ────────────────────────────────────────────────────────────

async fn run_ue(bind_addr: SocketAddr, amf_addr: SocketAddr) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let my_ip = ipv4_octets(bind_addr);

    // Bound early — ready to receive the DL G-PDU echo whenever the UPF
    // gets around to sending it (well before this UE side actually sends
    // anything uplink), not just right before it's needed.
    let gtp_sock = tokio::net::UdpSocket::bind(SocketAddr::from((my_ip, GTP_PORT))).await?;

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

        match ngap_msg {
            NgapMessage::DownlinkNasTransport(dl) => {
                let amf_ue_ngap_id = *amf_ue_ngap_id.get_or_insert(dl.amf_ue_ngap_id);
                let nas_pdu = dl.nas_pdu;

                // Auto-detect plain vs protected exactly like `amf::state_machine::
                // handle_uplink_nas` does on the other side — 5G's security header
                // type lives in byte[1]'s low nibble (see nas5gs::codec module doc).
                let sht = nas_pdu.get(1).map(|b| b & 0x0F).unwrap_or(0);

                if sht != NAS5GS_SHT_PLAIN {
                    // The only protected downlink message this arm ever sees is
                    // Phase A's RegistrationAccept — Phase B's RegistrationAccept
                    // arrives via InitialContextSetupRequest instead (below).
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
                        let res_star = midn_core::kdf::derive_res_star(
                            &vector.ck, &vector.ik, &snn, &req.rand, &vector.res,
                        );

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

            NgapMessage::InitialContextSetupRequest(icsr) => {
                // Phase B: RegistrationAccept + the bundled default PDU
                // session arrive together here instead of via
                // DownlinkNasTransport. Mirrors `amf::state_machine`'s own
                // `full_registration_flow_phase_b_bundles_pdu_session_and_completes_ics`
                // test, over a real socket instead of in-process.
                let amf_ue_ngap_id = *amf_ue_ngap_id.get_or_insert(icsr.amf_ue_ngap_id);
                let ran_ue_ngap_id = icsr.ran_ue_ngap_id;

                let kamf = kamf.ok_or("received InitialContextSetupRequest before KAMF was derived")?;
                let nas_pdu = icsr
                    .nas_pdu
                    .ok_or("InitialContextSetupRequest with no piggybacked NAS PDU")?;
                let mut nas_ctx = Nas5gsSecurityContext::new(&kamf, 2, 2);
                let plain = decode_protected_downlink(&mut nas_ctx, &nas_pdu)
                    .ok_or("failed to decrypt/verify RegistrationAccept")?;
                let acc = match decode_nas5gs(&plain)? {
                    Nas5gsPdu::RegistrationAccept(acc) => acc,
                    other => return Err(format!("expected RegistrationAccept, got {other:?}").into()),
                };
                println!("[UE ] <- RegistrationAccept (result={})", acc.registration_result);

                let session = icsr
                    .pdu_sessions
                    .first()
                    .ok_or("InitialContextSetupRequest with no PDU session to set up")?;
                let pdu_session_id = session.pdu_session_id;
                let qfi = session.qfi;
                let ul_teid = u32::from_be_bytes(session.gtp_teid);
                let upf_addr = session.transport_layer_addr;
                println!(
                    "[UE ] <- bundled PDU session {pdu_session_id} (qfi={qfi}, UL TEID={ul_teid:08x}, UPF={upf_addr:?})"
                );

                // gNodeB confirms the security context + PDU session: real
                // DL TEID + this process's own real N3 address — NOT a
                // fixed placeholder, since the UPF needs to actually be
                // able to reach this address for the G-PDU echo below to
                // land anywhere.
                let icrsp = NgapMessage::InitialContextSetupResponse(NgapInitialContextSetupResponse {
                    amf_ue_ngap_id,
                    ran_ue_ngap_id,
                    pdu_sessions_setup: vec![PduSessionSetupItem {
                        pdu_session_id,
                        transport_layer_addr: my_ip,
                        gtp_teid: MOCK_DL_TEID.to_be_bytes(),
                    }],
                    pdu_sessions_failed: vec![],
                });
                link.send(encode_ngap_pdu(&icrsp)?).await?;
                println!("[UE ] -> InitialContextSetupResponse");

                let complete = encode_registration_complete();
                send_uplink(&mut link, amf_ue_ngap_id, complete).await?;
                println!("[UE ] -> RegistrationComplete");
                println!(
                    "[UE ] registration complete — subscriber is online, PDU session {pdu_session_id} up."
                );

                user_plane_round_trip(&gtp_sock, upf_addr, ul_teid).await?;
                return Ok(());
            }

            other => return Err(format!("unexpected NGAP message from AMF: {other:?}").into()),
        }
    }
}

/// Send one real GTP-U G-PDU uplink and confirm it comes back down —
/// `run_amf`'s echo task is the other half of this. Real GTP-U is plain
/// UDP with no delivery guarantee, and there's a genuine race underneath
/// that on top of it: the UPF only routes correctly once it's processed
/// this UE's `InitialContextSetupResponse` (fire-and-forget, sent moments
/// ago) and called `update_bearer_info` — same shutdown-race *class* of
/// issue `run_both` already hit once (see its own doc comment), just
/// earlier in the flow and about a dropped packet instead of a missing log
/// line. A short retry loop absorbs it more honestly than guessing a fixed
/// sleep would: if the UPF's route isn't installed yet, the datagram is
/// simply dropped (logged `UnknownSession` on the UPF side) and the next
/// attempt succeeds once it is.
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

/// Encode a null-scheme SUCI carrying `imsi` — the exact inverse of
/// `amf::registration::resolve_suci_to_imsi`.
fn suci_for_imsi(imsi: u64) -> Suci {
    let bytes = imsi.to_be_bytes();
    let mut msin = [0u8; 5];
    msin.copy_from_slice(&bytes[3..8]);
    Suci { mcc: [0, 0, 0], mnc: [0, 0, 0], routing_indicator: 0, protection_scheme: 0, home_network_pki: 0, msin }
}

async fn send_initial(link: &mut SctpLink, nas_pdu: Bytes) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
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
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
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
