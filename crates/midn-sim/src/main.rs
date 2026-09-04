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
//! Multi-UE (`--n-ues N`, `--role ue`/`--role both` only): `N` concurrent
//! logical UEs sharing ONE `SctpLink` (one N2 association) and ONE GTP-U
//! socket to the same AMF — the way one real gNB really does carry every UE
//! it currently serves, not one connection per UE. `run_gnb` owns the link
//! and demuxes inbound NGAP messages to the right logical UE's task by
//! RAN-UE-NGAP-ID (assigned upfront, unlike AMF-UE-NGAP-ID which is only
//! learned mid-exchange); `gtp_demux_task` does the same for DL G-PDUs by
//! DL TEID. `N=1` (the default, and every existing workflow's usage) takes
//! this exact same multiplexed code path with a single logical UE — proof
//! the multiplexer itself is not a regression, not a special-cased bypass.
//! `run_amf` needs no change for this at all beyond provisioning `N`
//! subscribers instead of one: `Amf::process_ngap`'s dispatch already
//! demuxes by UE-ID for every message type, and `SctpLink` is fully
//! UE-agnostic (opaque bytes) — the only real gap was
//! `UeContextReleaseCommand` carrying no UE-ID IE at all, closed
//! separately (see `ngap::codec`'s doc).
//!
//! Run (single process, both roles — the original mode, still the default):
//! `cargo run -p midn-sim`
//!
//! Run as two independent OS processes instead — the shape `netns`+`veth`
//! namespace-isolated testing needs, since two Tokio tasks in one process
//! can't be placed in separate namespaces:
//! `cargo run -p midn-sim -- --role amf --bind 10.99.0.1:38412`
//! `cargo run -p midn-sim -- --role ue  --bind 10.99.0.2:0 --amf 10.99.0.1:38412`
//!
//! Multi-UE, same two-process shape, 3 logical UEs sharing each side's one
//! real connection:
//! `cargo run -p midn-sim -- --role amf --bind 10.99.0.1:38412 --n-ues 3`
//! `cargo run -p midn-sim -- --role ue  --bind 10.99.0.2:0 --amf 10.99.0.1:38412 --n-ues 3`

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use midn_proto::gtp::header::GtpuHeader;
use midn_proto::nas5gs::{
    decode_nas5gs, decode_protected_downlink, encode_auth_response, encode_deregistration_request,
    encode_identity_response_suci, encode_registration_complete, encode_registration_request,
    encode_sec_mode_complete, Nas5gsPdu, Nas5gsSecurityContext, Suci, NAS5GS_SHT_PLAIN,
};
use midn_proto::ngap::{
    decode_ngap_pdu, encode_ngap_pdu, NgapInitialContextSetupResponse, NgapInitialUeMessage,
    NgapMessage, NgapUeContextReleaseComplete, NgapUplinkNasTransport, PduSessionSetupItem,
};
use midn_transport::{LinkEvent, SctpLink};
use midn_userplane::{DlPacket, GtpForwarder, SessionManager, GTP_PORT};
use tokio::sync::mpsc;

// ── Shared test-subscriber material ─────────────────────────────────────────
// Same values `amf::state_machine`'s own test suite uses — not because this
// binary shares any code with those tests, but because they're already a
// known-good (CI-green) Milenage K/OPC pair and an IMSI that round-trips
// through the 5-byte MSIN SUCI scheme (< 2^40 — see
// `amf::registration::resolve_suci_to_imsi`'s doc). Every logical UE in an
// `--n-ues N` run reuses this same K/OPC test vector under its own IMSI
// (`TEST_IMSI + i`) — real subscribers each have distinct key material, but
// reusing one known-good test vector under N fake IMSIs is a harmless
// simplification for what this binary proves (routing/demux correctness,
// not key-material provisioning at scale).
const TEST_IMSI: u64 = 901_700_000_001;
const TEST_K: &str = "465b5ce8b199b49faa5f0a2ee238a6bc";
const TEST_OPC: &str = "cd63cb71954a9f4e48a5994e37a02baf";
const TEST_PLMN: [u8; 3] = [0x00, 0x11, 0x22];
const TEST_TAI: [u8; 6] = [0x00, 0x11, 0x22, 0x00, 0x00, 0x01];

/// Base RAN-UE-NGAP-ID — logical UE `i` (0-indexed) in an `--n-ues N` run
/// gets `RAN_UE_NGAP_ID_BASE + i`. `N=1`'s single UE gets exactly `7`, the
/// same fixed value this was before multi-UE support existed.
const RAN_UE_NGAP_ID_BASE: u32 = 7;

/// DL TEID the mock gNB tells the AMF/UPF to use for logical UE `i` —
/// `MOCK_DL_TEID_BASE + i`. A real gNB would allocate these itself; fixed
/// here since every value across an `--n-ues N` run is still unique by
/// construction, same reasoning the original single-UE constant already
/// had (`N=1` gets exactly the old fixed value back).
const MOCK_DL_TEID_BASE: u32 = 0xAABB_CCDD;

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
    Both { n_ues: u32 },
    Amf { bind: SocketAddr, n_ues: u32 },
    Ue { bind: SocketAddr, amf: SocketAddr, n_ues: u32 },
}

const USAGE: &str = "\
Usage:
  midn-sim                                              (default: both roles, one process, loopback)
  midn-sim --role amf --bind ADDR:PORT [--n-ues N]
  midn-sim --role ue  --bind ADDR:PORT --amf ADDR:PORT [--n-ues N]   (--bind may use :0 for an OS-picked ephemeral port)

  --n-ues N   how many logical UEs share one connection (default 1, must be >= 1).
              Give the SAME N to both --role amf and --role ue.";

fn parse_args(args: &[String]) -> Result<Role, String> {
    let mut role: Option<&str> = None;
    let mut bind: Option<&str> = None;
    let mut amf: Option<&str> = None;
    let mut n_ues_arg: Option<&str> = None;

    let mut i = 0;
    while i < args.len() {
        let (flag, value) = (args[i].as_str(), args.get(i + 1).map(String::as_str));
        match flag {
            "--role" => role = value,
            "--bind" => bind = value,
            "--amf" => amf = value,
            "--n-ues" => n_ues_arg = value,
            other => return Err(format!("unrecognized argument {other:?}\n\n{USAGE}")),
        }
        if value.is_none() {
            return Err(format!("{flag} needs a value\n\n{USAGE}"));
        }
        i += 2;
    }

    let n_ues: u32 = match n_ues_arg {
        None => 1,
        Some(s) => {
            let n: u32 = s.parse().map_err(|e| format!("--n-ues: {e}\n\n{USAGE}"))?;
            if n == 0 {
                return Err(format!("--n-ues must be at least 1\n\n{USAGE}"));
            }
            n
        }
    };

    match role {
        None | Some("both") => Ok(Role::Both { n_ues }),
        Some("amf") => Ok(Role::Amf {
            bind: bind
                .unwrap_or(AMF_BIND_ADDR)
                .parse()
                .map_err(|e| format!("--bind: {e}\n\n{USAGE}"))?,
            n_ues,
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
            n_ues,
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
        assert!(matches!(parse_args(&args(&[])), Ok(Role::Both { n_ues: 1 })));
    }

    #[test]
    fn explicit_role_both() {
        assert!(matches!(parse_args(&args(&["--role", "both"])), Ok(Role::Both { n_ues: 1 })));
    }

    #[test]
    fn amf_role_defaults_bind_addr() {
        match parse_args(&args(&["--role", "amf"])) {
            Ok(Role::Amf { bind, n_ues: 1 }) => assert_eq!(bind, AMF_BIND_ADDR.parse().unwrap()),
            other => panic!("expected Role::Amf with the default bind addr, got {other:?}"),
        }
    }

    #[test]
    fn amf_role_with_explicit_bind() {
        match parse_args(&args(&["--role", "amf", "--bind", "10.99.0.1:38412"])) {
            Ok(Role::Amf { bind, n_ues: 1 }) => assert_eq!(bind, "10.99.0.1:38412".parse().unwrap()),
            other => panic!("expected Role::Amf with the given bind addr, got {other:?}"),
        }
    }

    #[test]
    fn ue_role_requires_bind_and_amf() {
        match parse_args(&args(&["--role", "ue", "--bind", "10.99.0.2:0", "--amf", "10.99.0.1:38412"])) {
            Ok(Role::Ue { bind, amf, n_ues: 1 }) => {
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

    #[test]
    fn n_ues_explicit_value_is_parsed() {
        match parse_args(&args(&[
            "--role", "ue", "--bind", "10.99.0.2:0", "--amf", "10.99.0.1:38412", "--n-ues", "3",
        ])) {
            Ok(Role::Ue { n_ues: 3, .. }) => {}
            other => panic!("expected Role::Ue with n_ues=3, got {other:?}"),
        }
    }

    #[test]
    fn n_ues_zero_is_an_error() {
        assert!(parse_args(&args(&[
            "--role", "ue", "--bind", "10.99.0.2:0", "--amf", "10.99.0.1:38412", "--n-ues", "0",
        ]))
        .is_err());
    }

    #[test]
    fn n_ues_non_numeric_is_an_error() {
        assert!(parse_args(&args(&["--role", "amf", "--n-ues", "many"])).is_err());
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
        Role::Both { n_ues } => run_both(n_ues).await,

        Role::Amf { bind, n_ues } => {
            println!("midn-sim — AMF only\n");
            // No matching drain-sleep-then-exit here on purpose: a
            // single-role AMF process has no natural end (`run_amf` only
            // returns on a lost/closed link) — it's meant to keep serving
            // until whatever started it (a netns/veth test script, most
            // likely) explicitly stops it. See `run_both`'s doc comment
            // for why that orchestrator needs its own drain delay before
            // doing so, same reasoning as the single-process shutdown race
            // this file already hit once.
            run_amf(bind, n_ues).await
        }

        Role::Ue { bind, amf, n_ues } => {
            println!("midn-sim — UE/gNB only, {bind} -> AMF {amf}\n");
            // Same reasoning as `run_both`'s startup sleep: gives the peer
            // process a head start on binding before the first INIT is
            // sent. Cheaper than polling for it, SCTP's own retransmission
            // covers the rest if this isn't enough.
            tokio::time::sleep(Duration::from_millis(50)).await;

            let result = run_gnb(bind, amf, n_ues).await;
            match &result {
                Ok(()) => println!(
                    "\n✅ Full Registration procedure, user-plane G-PDU round trip, and Deregistration all confirmed, over a real SCTP-over-UDP socket."
                ),
                Err(e) => println!("\n❌ Simulation failed: {e}"),
            }
            result
        }
    }
}

/// Original combined mode: both sides as Tokio tasks in this one process,
/// on loopback. Still the default (`midn-sim` with no args) — the existing
/// `midn-sim-smoke-test.yml` workflow doesn't call this mode (it uses
/// `--role amf`/`--role ue` directly), so nothing here needs to stay
/// byte-for-byte compatible the way `run_gnb`'s `n_ues == 1` path does.
async fn run_both(n_ues: u32) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
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

    let amf_task = tokio::spawn(run_amf(amf_addr, n_ues));

    // Reduces (doesn't eliminate — SCTP's own T1-init retransmission would
    // recover regardless) the chance the UE's first INIT arrives before the
    // AMF task's UdpSocket::bind has actually happened. `tokio::spawn`
    // schedules, it doesn't guarantee the task has started running yet.
    tokio::time::sleep(Duration::from_millis(50)).await;

    let ue_result = run_gnb(ue_bind_addr, amf_addr, n_ues).await;

    match &ue_result {
        Ok(()) => println!(
            "\n✅ Full Registration procedure, user-plane G-PDU round trip, and Deregistration all confirmed, over a real SCTP-over-UDP socket."
        ),
        Err(e) => println!("\n❌ Simulation failed: {e}"),
    }

    // `run_gnb` returning Ok only means every logical UE's last sends
    // completed locally — UDP is fire-and-forget, so that's the send-side
    // syscall finishing, not proof the AMF task has received, let alone
    // processed, the last of them yet. Without this drain window,
    // `amf_task.abort()` below can (and on build #3 of this workflow,
    // did) kill the AMF task before it ever gets scheduled to consume the
    // last datagrams — the run still printed "success" because that line
    // only reflects the UE side, while AMF-side confirmation
    // (N3Event::UpdateBearer, the RegistrationComplete log line) silently
    // never happened. Same approximate-not-exact tradeoff as the startup
    // sleep above, just on the other end of the run; 200ms is generous
    // relative to a couple of loopback UDP round trips + task wakeups,
    // cheap against the workflow's 30s budget.
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

async fn run_amf(bind_addr: SocketAddr, n_ues: u32) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    // This process plays UPF too — see module doc for why that's an honest
    // simplification, not silently glossed over. The UPF's N3 address is
    // this same process's real address (same IP the control plane is
    // bound to, GTP-U's own standard port instead of NGAP's) — NOT a fixed
    // placeholder, since the bundled PDU session tells the UE to actually
    // send uplink traffic there.
    let upf_ip = ipv4_octets(bind_addr);
    let mut amf = midn_core::amf::Amf::new().with_phase_b(upf_ip);
    // One provisioned subscriber per logical UE the peer `--role ue`
    // process will drive — `TEST_IMSI + i`, same IMSI numbering
    // `run_gnb`/`run_one_ue` use on the other side (see their own doc).
    for i in 0..n_ues {
        amf.hss_mut().provision_hex(TEST_IMSI + i as u64, TEST_K, TEST_OPC)?;
    }

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
    // crate's own tests already proved works over a real socket. Works
    // identically for however many logical UEs are sharing this UPF's one
    // socket — `RoutingTable` was already keyed by TEID, one entry per UE,
    // long before multi-UE support existed on the gNB side.
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

/// Short, per-connection label for setup-phase log lines (`connecting to
/// AMF`, `SCTP association established`) that aren't about any one logical
/// UE. `--n-ues 1` keeps the exact `"[UE ]"` text every existing check
/// (`midn-sim-smoke-test.yml`) already greps for; `N > 1` says `"[gNB]"`
/// instead, since at that point the association really is gNB-level, not
/// UE-level.
fn gnb_label(n_ues: u32) -> &'static str {
    if n_ues == 1 { "[UE ]" } else { "[gNB]" }
}

/// Per-logical-UE log label. `--n-ues 1`'s single UE keeps the exact
/// `"[UE ]"` text every existing check already greps for; `N > 1` numbers
/// them `"[UE1]"`, `"[UE2]"`, ... instead.
fn ue_label(n_ues: u32, index: u32) -> String {
    if n_ues == 1 { "[UE ]".to_string() } else { format!("[UE{}]", index + 1) }
}

/// The RAN-UE-NGAP-ID an inbound NGAP message carries — every message this
/// binary's gNB role can ever receive from the AMF carries one (see
/// `ngap::messages`), which is exactly why it's the demux key `run_gnb`
/// uses to route to the right logical UE task: unlike AMF-UE-NGAP-ID, it's
/// known upfront (the gNB itself assigns it), not learned mid-exchange.
fn ran_ue_ngap_id_of(msg: &NgapMessage) -> Option<u32> {
    match msg {
        NgapMessage::DownlinkNasTransport(dl) => Some(dl.ran_ue_ngap_id),
        NgapMessage::InitialContextSetupRequest(icsr) => Some(icsr.ran_ue_ngap_id),
        NgapMessage::UeContextReleaseCommand { ran_ue_ngap_id, .. } => Some(*ran_ue_ngap_id),
        _ => None,
    }
}

/// The gNB role: one real `SctpLink` (one N2 association) and one real
/// GTP-U socket, shared by `n_ues` concurrent logical UEs exactly the way a
/// real gNB's do — multiplexed, disambiguated by ID, not one connection
/// per UE. `n_ues == 1` (the default, and every existing workflow's usage)
/// takes this exact same code path with a single logical UE — proof the
/// multiplexer itself introduces no regression, not a special-cased
/// bypass. Replaces the old single-UE `run_ue`.
async fn run_gnb(
    bind_addr: SocketAddr, amf_addr: SocketAddr, n_ues: u32,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let my_ip = ipv4_octets(bind_addr);
    let conn_label = gnb_label(n_ues);

    // Bound early — ready to receive DL G-PDU echoes whenever the UPF gets
    // around to sending them, well before any logical UE actually sends
    // anything uplink. Shared by every logical UE (see `gtp_demux_task`'s
    // doc) — real GTP-U doesn't get one socket per UE either.
    let gtp_sock = Arc::new(tokio::net::UdpSocket::bind(SocketAddr::from((my_ip, GTP_PORT))).await?);

    println!("{conn_label} connecting to AMF at {amf_addr}");
    let mut link = SctpLink::connect(bind_addr, amf_addr).await?;

    match link.recv().await {
        Some(LinkEvent::Connected) => println!("{conn_label} SCTP association established"),
        Some(LinkEvent::Lost { reason }) => return Err(format!("link lost before connecting: {reason}").into()),
        Some(_) => return Err("unexpected event before Connected".into()),
        None => return Err("link closed before connecting".into()),
    }

    // Per-logical-UE routing, fully populated before the dispatcher or any
    // UE task starts running — nothing can race a lookup against a
    // not-yet-inserted entry.
    let (out_tx, mut out_rx) = mpsc::unbounded_channel::<Bytes>();
    let mut ngap_routes: HashMap<u32, mpsc::UnboundedSender<NgapMessage>> = HashMap::new();
    let mut dl_routes: HashMap<u32, mpsc::UnboundedSender<Vec<u8>>> = HashMap::new();
    let mut ue_tasks = Vec::with_capacity(n_ues as usize);

    for i in 0..n_ues {
        let ran_ue_ngap_id = RAN_UE_NGAP_ID_BASE + i;
        let dl_teid = MOCK_DL_TEID_BASE + i;
        let imsi = TEST_IMSI + i as u64;
        let label = ue_label(n_ues, i);

        let (ngap_tx, ngap_rx) = mpsc::unbounded_channel();
        ngap_routes.insert(ran_ue_ngap_id, ngap_tx);
        let (gtp_tx, gtp_rx) = mpsc::unbounded_channel();
        dl_routes.insert(dl_teid, gtp_tx);

        ue_tasks.push(tokio::spawn(run_one_ue(
            label, ran_ue_ngap_id, dl_teid, imsi, my_ip,
            ngap_rx, out_tx.clone(), Arc::clone(&gtp_sock), gtp_rx,
        )));
    }

    tokio::spawn(gtp_demux_task(Arc::clone(&gtp_sock), dl_routes));

    // Owns `link` exclusively from here on — every logical UE task talks
    // to it only through `ngap_routes`/`out_tx`, never directly.
    let dispatch = tokio::spawn(async move {
        loop {
            tokio::select! {
                ev = link.recv() => match ev {
                    Some(LinkEvent::Message(bytes)) => {
                        let msg = match decode_ngap_pdu(&bytes) {
                            Ok(m) => m,
                            Err(e) => { eprintln!("{conn_label} failed to decode inbound NGAP PDU: {e}"); continue; }
                        };
                        match ran_ue_ngap_id_of(&msg) {
                            Some(id) => match ngap_routes.get(&id) {
                                Some(tx) => { let _ = tx.send(msg); }
                                None => eprintln!("{conn_label} NGAP message for unknown ran_ue_ngap_id={id}: {msg:?}"),
                            },
                            None => eprintln!("{conn_label} unexpected NGAP message with no UE-ID: {msg:?}"),
                        }
                    }
                    Some(LinkEvent::Lost { reason }) => { eprintln!("{conn_label} link lost: {reason}"); return; }
                    Some(LinkEvent::Connected) => {} // already handled above; ignore any stray repeats
                    None => { eprintln!("{conn_label} link closed unexpectedly"); return; }
                },
                Some(bytes) = out_rx.recv() => {
                    if let Err(e) = link.send(bytes).await {
                        eprintln!("{conn_label} send failed: {e}");
                    }
                }
            }
        }
    });

    let mut first_err: Option<Box<dyn std::error::Error + Send + Sync>> = None;
    for (i, task) in ue_tasks.into_iter().enumerate() {
        match task.await {
            Ok(Ok(())) => {}
            Ok(Err(e)) => {
                eprintln!("UE{} failed: {e}", i + 1);
                first_err.get_or_insert(e);
            }
            Err(join_err) => {
                eprintln!("UE{} task panicked: {join_err}", i + 1);
                first_err.get_or_insert(format!("UE{} task panicked: {join_err}", i + 1).into());
            }
        }
    }

    dispatch.abort();

    match first_err {
        Some(e) => Err(e),
        None => Ok(()),
    }
}

/// Owns the actual `recv_from` on the shared GTP-U socket every logical
/// UE's uplink traffic also flows through (`gtp_sock.send_to` is safe to
/// call concurrently from multiple tasks — `tokio::net::UdpSocket`
/// supports that directly through a shared `Arc`, no wrapping needed — but
/// only one task may ever poll `recv_from`, hence this dedicated task).
/// Real GTP-U carries every bearer for every UE a gNB serves over this one
/// socket, differentiated purely by TEID in each packet — this task is
/// that demux, keyed by the DL TEID each logical UE's own
/// `InitialContextSetupResponse` told the UPF to use.
async fn gtp_demux_task(
    gtp_sock: Arc<tokio::net::UdpSocket>,
    dl_routes: HashMap<u32, mpsc::UnboundedSender<Vec<u8>>>,
) {
    let mut buf = vec![0u8; 512];
    loop {
        let (len, _) = match gtp_sock.recv_from(&mut buf).await {
            Ok(v) => v,
            Err(e) => {
                eprintln!("[GTP] recv_from error: {e}");
                continue;
            }
        };
        let Some((dl_hdr, dl_payload)) = GtpuHeader::parse(&buf[..len]) else { continue };
        match dl_routes.get(&dl_hdr.teid) {
            Some(tx) => {
                let _ = tx.send(dl_payload.to_vec());
            }
            None => println!("[GTP] DL G-PDU for unknown dl_teid={:08x} — dropped", dl_hdr.teid),
        }
    }
}

/// One logical UE/gNB combined role's full lifecycle — the exact procedure
/// the old single-UE `run_ue` drove alone, now parameterized so `N` of
/// these can run concurrently under `run_gnb`, sharing one `SctpLink` and
/// one GTP-U socket exactly the way one real gNB's N2 association and N3
/// GTP-U socket really do carry every UE it currently serves.
async fn run_one_ue(
    label: String,
    ran_ue_ngap_id: u32,
    dl_teid: u32,
    imsi: u64,
    my_ip: [u8; 4],
    mut ngap_rx: mpsc::UnboundedReceiver<NgapMessage>,
    out_tx: mpsc::UnboundedSender<Bytes>,
    gtp_sock: Arc<tokio::net::UdpSocket>,
    mut gtp_rx: mpsc::UnboundedReceiver<Vec<u8>>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    // Step 1: RegistrationRequest. registration_type=1 (initial), ngKSI=0,
    // no GUTI (SUCI-based first registration), ue_security_cap=0x00C0 —
    // same values `amf::state_machine`'s test suite already exercises.
    let reg_req = encode_registration_request(1, 0, None, 0x00C0);
    send_initial(&out_tx, ran_ue_ngap_id, reg_req)?;
    println!("{label} -> RegistrationRequest");

    let mut amf_ue_ngap_id: Option<u32> = None;
    // First vector for a freshly provisioned subscriber — SQN starts at 0.
    // See Hss's own doc/tests for why this is a safe assumption here.
    let sqn_used = [0u8; 6];
    let mut kamf: Option<[u8; 32]> = None;

    loop {
        let ngap_msg = match ngap_rx.recv().await {
            Some(m) => m,
            None => return Err("gNB dispatcher channel closed unexpectedly".into()),
        };

        // Regression check for the multi-UE demux itself: every message
        // reaching this task must be one `run_gnb` actually routed here.
        // A mismatch means the dispatcher's `ngap_routes` lookup is wrong
        // — exactly the class of bug this whole feature exists to rule
        // out, so it's a hard error, not a debug-only assertion.
        if let Some(got) = ran_ue_ngap_id_of(&ngap_msg) {
            if got != ran_ue_ngap_id {
                return Err(format!(
                    "dispatcher routed {} for ran_ue_ngap_id={got} to the wrong UE task (expected {ran_ue_ngap_id})",
                    ngap_summary(&ngap_msg)
                ).into());
            }
        }

        match ngap_msg {
            NgapMessage::DownlinkNasTransport(dl) => {
                let amf_ue_ngap_id = *amf_ue_ngap_id.get_or_insert(dl.amf_ue_ngap_id);
                let nas_pdu = dl.nas_pdu;

                // Auto-detect plain vs protected exactly like `amf::state_machine::
                // handle_uplink_nas` does on the other side — 5G's security header
                // type lives in byte[1]'s low nibble (see nas5gs::codec module doc).
                let sht = nas_pdu.get(1).map(|b| b & 0x0F).unwrap_or(0);

                if sht != NAS5GS_SHT_PLAIN {
                    // The only protected downlink message this arm actually
                    // sees in this binary's real flow is DeregistrationAccept
                    // — Phase B's RegistrationAccept always arrives via
                    // InitialContextSetupRequest instead (below), never
                    // here, since Amf::with_phase_b is always on.
                    let kamf = kamf.ok_or("received a protected PDU before KAMF was derived")?;
                    let mut nas_ctx = Nas5gsSecurityContext::new(&kamf, 2, 2);
                    let plain = decode_protected_downlink(&mut nas_ctx, &nas_pdu)
                        .ok_or("failed to decrypt/verify DeregistrationAccept")?;

                    match decode_nas5gs(&plain)? {
                        Nas5gsPdu::DeregistrationAccept => {
                            println!("{label} <- DeregistrationAccept");
                            // UeContextReleaseCommand follows as its own
                            // separate NGAP message — handled by that
                            // match arm below, once this loop continues.
                        }
                        other => return Err(format!("expected DeregistrationAccept, got {other:?}").into()),
                    }
                    continue;
                }

                match decode_nas5gs(&nas_pdu)? {
                    Nas5gsPdu::IdentityRequest { .. } => {
                        println!("{label} <- IdentityRequest");
                        let suci = suci_for_imsi(imsi);
                        let resp = encode_identity_response_suci(&suci);
                        send_uplink(&out_tx, amf_ue_ngap_id, ran_ue_ngap_id, resp)?;
                        println!("{label} -> IdentityResponse(SUCI)");
                    }
                    Nas5gsPdu::AuthenticationRequest(req) => {
                        println!("{label} <- AuthenticationRequest");

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
                        let supi = imsi.to_string().into_bytes();
                        kamf = Some(midn_core::kdf::derive_kamf(&kseaf, &supi, &[0x00, 0x00]));

                        let resp = encode_auth_response(&res_star);
                        send_uplink(&out_tx, amf_ue_ngap_id, ran_ue_ngap_id, resp)?;
                        println!("{label} -> AuthenticationResponse(RES*)");
                    }
                    Nas5gsPdu::SecurityModeCommand(_) => {
                        println!("{label} <- SecurityModeCommand");
                        let resp = encode_sec_mode_complete();
                        send_uplink(&out_tx, amf_ue_ngap_id, ran_ue_ngap_id, resp)?;
                        println!("{label} -> SecurityModeComplete");
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
                println!("{label} <- RegistrationAccept (result={})", acc.registration_result);

                let session = icsr
                    .pdu_sessions
                    .first()
                    .ok_or("InitialContextSetupRequest with no PDU session to set up")?;
                let pdu_session_id = session.pdu_session_id;
                let qfi = session.qfi;
                let ul_teid = u32::from_be_bytes(session.gtp_teid);
                let upf_addr = session.transport_layer_addr;
                println!(
                    "{label} <- bundled PDU session {pdu_session_id} (qfi={qfi}, UL TEID={ul_teid:08x}, UPF={upf_addr:?})"
                );

                // gNodeB confirms the security context + PDU session: real
                // DL TEID + this process's own real N3 address — NOT a
                // fixed placeholder, since the UPF needs to actually be
                // able to reach this address for the G-PDU echo below to
                // land anywhere. `dl_teid` is this logical UE's own slot
                // (see `RAN_UE_NGAP_ID_BASE`'s doc) — the UPF sends DL
                // G-PDUs back using this value, and `gtp_demux_task`
                // routes them right back to this task by the same value.
                let icrsp = NgapMessage::InitialContextSetupResponse(NgapInitialContextSetupResponse {
                    amf_ue_ngap_id,
                    ran_ue_ngap_id,
                    pdu_sessions_setup: vec![PduSessionSetupItem {
                        pdu_session_id,
                        transport_layer_addr: my_ip,
                        gtp_teid: dl_teid.to_be_bytes(),
                    }],
                    pdu_sessions_failed: vec![],
                });
                out_tx.send(encode_ngap_pdu(&icrsp)?).map_err(|_| "gNB dispatcher gone")?;
                println!("{label} -> InitialContextSetupResponse");

                let complete = encode_registration_complete();
                send_uplink(&out_tx, amf_ue_ngap_id, ran_ue_ngap_id, complete)?;
                println!("{label} -> RegistrationComplete");
                println!(
                    "{label} registration complete — subscriber is online, PDU session {pdu_session_id} up."
                );

                user_plane_round_trip(&label, &gtp_sock, &mut gtp_rx, upf_addr, ul_teid).await?;

                // UeContextReleaseCommand/Complete gained real wire codec
                // support this session — drive a full Deregistration to
                // completion too, over the real socket, not just the
                // in-process proof amf::deregistration's own tests already
                // gave. DeregistrationAccept (protected) arrives via a
                // separate DownlinkNasTransport, handled above; the loop
                // continues rather than returning here.
                let dereg = encode_deregistration_request(false);
                send_uplink(&out_tx, amf_ue_ngap_id, ran_ue_ngap_id, dereg)?;
                println!("{label} -> DeregistrationRequest");
            }

            NgapMessage::UeContextReleaseCommand { amf_ue_ngap_id: cmd_amf_id, ran_ue_ngap_id: cmd_ran_id, cause } => {
                println!(
                    "{label} <- UeContextReleaseCommand (amf_ue_ngap_id={cmd_amf_id}, ran_ue_ngap_id={cmd_ran_id}, cause={cause:?})"
                );
                // UeContextReleaseCommand now carries real AMF-UE-NGAP-ID/
                // RAN-UE-NGAP-ID (multi-UE support) — echo exactly what the
                // AMF sent rather than the locally-tracked ID, which also
                // verifies the AMF targeted the right UE.
                let complete = NgapMessage::UeContextReleaseComplete(NgapUeContextReleaseComplete {
                    amf_ue_ngap_id: cmd_amf_id, ran_ue_ngap_id: cmd_ran_id,
                });
                out_tx.send(encode_ngap_pdu(&complete)?).map_err(|_| "gNB dispatcher gone")?;
                println!("{label} -> UeContextReleaseComplete");
                println!("{label} deregistration complete — subscriber is offline.");
                return Ok(());
            }

            other => return Err(format!("unexpected NGAP message from AMF: {other:?}").into()),
        }
    }
}

/// Send one real GTP-U G-PDU uplink and confirm it comes back down —
/// `gtp_demux_task` is the other half of this: it owns the actual
/// `recv_from` on the shared GTP-U socket and routes each DL G-PDU here by
/// `dl_teid`, so this function only ever sees payloads meant for THIS
/// logical UE. Real GTP-U is plain UDP with no delivery guarantee, and
/// there's a genuine race underneath that on top of it: the UPF only
/// routes correctly once it's processed this UE's
/// `InitialContextSetupResponse` (fire-and-forget, sent moments ago) and
/// called `update_bearer_info` — same shutdown-race *class* of issue
/// `run_both` already hit once (see its own doc comment), just earlier in
/// the flow and about a dropped packet instead of a missing log line. A
/// short retry loop absorbs it more honestly than guessing a fixed sleep
/// would: if the UPF's route isn't installed yet, the datagram is simply
/// dropped (logged `UnknownSession` on the UPF side) and the next attempt
/// succeeds once it is.
async fn user_plane_round_trip(
    label: &str,
    gtp_sock: &tokio::net::UdpSocket,
    gtp_rx: &mut mpsc::UnboundedReceiver<Vec<u8>>,
    upf_addr: [u8; 4],
    ul_teid: u32,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    const PAYLOAD: &[u8] = b"real user data over a real GTP-U tunnel";
    let hdr = GtpuHeader::new_gpdu(ul_teid, PAYLOAD.len() as u16);
    let mut gpdu = Vec::with_capacity(GtpuHeader::SIZE + PAYLOAD.len());
    gpdu.extend_from_slice(&hdr.to_bytes());
    gpdu.extend_from_slice(PAYLOAD);
    let upf_gtp_addr = SocketAddr::from((upf_addr, GTP_PORT));

    for attempt in 1..=5 {
        gtp_sock.send_to(&gpdu, upf_gtp_addr).await?;
        println!(
            "{label} -> G-PDU UL (ul_teid={ul_teid:08x}, {} bytes) -> UPF {upf_gtp_addr} (attempt {attempt}/5)",
            PAYLOAD.len()
        );

        let recv = tokio::time::timeout(Duration::from_millis(500), gtp_rx.recv()).await;
        let Ok(Some(dl_payload)) = recv else { continue };

        println!("{label} <- G-PDU DL ({} bytes)", dl_payload.len());
        if dl_payload != PAYLOAD {
            return Err(format!(
                "DL G-PDU payload mismatch: sent {PAYLOAD:?}, got back {dl_payload:?}"
            ).into());
        }
        println!("{label} user-plane G-PDU round trip confirmed — payload matches what was sent.");
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

fn send_initial(
    out_tx: &mpsc::UnboundedSender<Bytes>, ran_ue_ngap_id: u32, nas_pdu: Bytes,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let msg = NgapMessage::InitialUeMessage(NgapInitialUeMessage {
        ran_ue_ngap_id,
        nas_pdu,
        tai: TEST_TAI,
        nr_cgi: [0u8; 9],
        rrc_establishment_cause: 0,
    });
    out_tx.send(encode_ngap_pdu(&msg)?).map_err(|_| "gNB dispatcher gone")?;
    Ok(())
}

fn send_uplink(
    out_tx: &mpsc::UnboundedSender<Bytes>, amf_ue_ngap_id: u32, ran_ue_ngap_id: u32, nas_pdu: Bytes,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let msg = NgapMessage::UplinkNasTransport(NgapUplinkNasTransport {
        amf_ue_ngap_id,
        ran_ue_ngap_id,
        nas_pdu,
        tai: TEST_TAI,
        nr_cgi: [0u8; 9],
    });
    out_tx.send(encode_ngap_pdu(&msg)?).map_err(|_| "gNB dispatcher gone")?;
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
        NgapMessage::UeContextReleaseCommand { .. } => "UeContextReleaseCommand",
        NgapMessage::UeContextReleaseComplete(_) => "UeContextReleaseComplete",
        _ => "(other NGAP message)",
    }
}
