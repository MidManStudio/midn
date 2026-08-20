// crates/midn-transport/src/lib.rs
//! Generic SCTP transport, for S1AP/NGAP (or any other SCTP-carried
//! protocol midn adds later). Protocol-agnostic on purpose — this crate
//! knows nothing about S1AP/NGAP/NAS; it moves whole SCTP user messages
//! (`Bytes` in, `Bytes` out) between two endpoints over one association.
//! `midn-core`'s MME/AMF wiring (not yet done — the eNodeB/gNodeB simulator
//! binary on the project roadmap is the actual consumer) is responsible for
//! handing this crate already-encoded PDU bytes
//! (`s1ap::codec::encode_s1ap_pdu` / `ngap::codec::encode_ngap_pdu`) and
//! decoding whatever comes back through [`LinkEvent::Message`].
//!
//! Built on [`rtc_sctp`] (crate `rtc-sctp`), a Sans-IO RFC 4960 SCTP
//! implementation — see that crate's own doc: "contains no networking
//! code... you feed it datagrams and time, and poll it for the datagrams
//! and events it produces." This crate is the actual I/O: a Tokio
//! `UdpSocket` plus the event-pump loop `rtc_sctp`'s doc describes,
//! wrapped in a small async API ([`SctpLink::connect`]/[`SctpLink::accept`]
//! /[`SctpLink::send`]/[`SctpLink::recv`]).
//!
//! ## Why SCTP-over-UDP, not real IP-layer SCTP
//!
//! Real NGAP/S1AP run SCTP directly over IP (`IPPROTO_SCTP`). Two ways to
//! get that from Rust: the Linux kernel's own `net.sctp` module via a raw
//! `AF_INET`/`IPPROTO_SCTP` socket, or a userspace SCTP implementation like
//! this one. The kernel route needs `net.sctp` loaded — not guaranteed on
//! a stock GitHub Actions runner or every dev machine, and not something
//! this project's $0/one-Linux-box philosophy wants to depend on. The
//! userspace route needs *some* real transport underneath the Sans-IO
//! protocol logic to actually move bytes — SCTP-over-UDP (plain
//! `UdpSocket`, unprivileged, works identically in CI, this sandbox, and
//! on real hardware) is that transport. This is a deliberate, documented
//! simplification, same tier as the project's other flagged simplifications
//! (flat opaque IMSI, no BCD PLMN decoding, etc.) — not a bug, but a real
//! deviation from wire-exact 3GPP SCTP that would need addressing before
//! genuine interop with a real gNB/AMF.
//!
//! ## Two compatibility gaps in `rtc_sctp` itself — read before using
//!
//! `rtc_sctp` is built for WebRTC data channels, not 3GPP signaling
//! transport. Two consequences, discovered reading its actual source
//! (`association/mod.rs`, `chunk/chunk_payload_data.rs`) during this
//! session, not assumed from the docs:
//!
//! 1. **Payload Protocol Identifier is a closed 6-value enum**
//!    (`PayloadProtocolIdentifier::{Dcep,String,Binary,StringEmpty,
//!    BinaryEmpty,Unknown}` = `{50,51,53,56,57,58}`), all WebRTC data-
//!    channel PPIDs. Real NGAP's PPID is 60, S1AP's is 18 — neither exists
//!    in this enum, and there is no raw-`u32` write path on `Stream` that
//!    bypasses it. Every message this crate sends goes out with
//!    `PayloadProtocolIdentifier::Unknown` (58) on the wire, not the real
//!    3GPP value. Fine for midn talking to midn (both ends know from
//!    context, same way a TCP port number alone implies its protocol) —
//!    a genuine interop blocker against real 3GPP equipment that filters
//!    or routes on PPID. Flagging, not silently working around.
//! 2. **`Stream` open/accept is local bookkeeping only, not a DCEP
//!    handshake** — verified by reading `Association::open_stream`
//!    (`association/mod.rs`): it just checks `self.streams.contains_key`
//!    and inserts local state; no packet goes out. `accept_stream` drains
//!    a queue that `get_or_create_stream` fills when inbound DATA arrives
//!    for a stream id this side hasn't created yet. So both peers calling
//!    `open_stream` with the *same* id right after `Event::Connected` (see
//!    [`DEFAULT_STREAM_ID`] below) needs no coordination — this was the
//!    one design risk that could have forced a WebRTC-specific DCEP
//!    control message onto the wire, and it doesn't.
//!
//! ## What this crate does NOT do yet
//!
//! - Multiple associations per socket (one `SctpLink` = one association;
//!   a real AMF serving many gNBs needs a listener that fans out to many
//!   links — mechanical extension, not built).
//! - Multiple SCTP streams per association (`DEFAULT_STREAM_ID` only —
//!   real NGAP/S1AP deployments spread UEs across streams for load
//!   balancing; single-UE test scenarios don't need that).
//! - Graceful shutdown wiring (`Association::shutdown`/`close` exist and
//!   are reachable but nothing calls them yet).

pub mod link;

pub use link::{LinkEvent, SctpLink, TransportError, DEFAULT_STREAM_ID};
