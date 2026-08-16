// crates/midn-proto/src/ngap/mod.rs
//! NGAP — NG Application Protocol (3GPP TS 38.413)
//!
//! 5G NR equivalent of S1AP. The gNodeB communicates with the AMF via NGAP
//! instead of S1AP. Key differences:
//!   - UE context setup still uses the same message *name*
//!     (InitialContextSetupRequest/Response) as S1AP — 3GPP kept the two
//!     protocols structurally symmetric on purpose — but PDU Sessions
//!     replace EPS Bearers as the thing being set up.
//!   - AMF replaces MME; UPF replaces P-GW/S-GW split.
//!
//! `messages` defines the in-process message structs. `ie_ids` + `codec`
//! add a real ASN.1 ALIGNED PER wire encoder/decoder on top of those
//! structs, built on the shared bit-packing engine at `crate::per` (the
//! same engine `s1ap::codec` uses — S1AP and NGAP share identical ALIGNED
//! PER transport conventions). See `codec` module docs for current scope
//! (InitialUEMessage/Uplink/DownlinkNASTransport only, mirroring exactly
//! where S1AP's codec started) and the spec-fidelity disclaimer in
//! `ie_ids` before relying on this for actual gNB hardware — confidence
//! here is explicitly LOWER than the S1AP constants, see that file.
//!
//! Wired into the AMF state machine (`midn_core::amf`) — `InitialUeMessage`/
//! `Uplink`/`DownlinkNasTransport` and now `InitialContextSetupRequest`/
//! `Response` too, via the `NgapMessage` enum directly (`Amf::process_ngap`
//! dispatches on the enum, not through this file's PER codec — see
//! `amf::registration` module doc "Phase A vs Phase B" for why that's
//! enough for now). This file's PER encode/decode (`codec` module, scope
//! noted above) is a separate concern, only exercised once a real SCTP wire
//! boundary exists — not built yet.

pub mod codec;
pub mod ie_ids;
pub mod messages;

pub use codec::{decode_ngap_pdu, encode_ngap_pdu};
pub use messages::{
    NgapCause,
    NgapDownlinkNasTransport,
    NgapInitialContextSetupRequest,
    NgapInitialContextSetupResponse,
    NgapInitialUeMessage,
    NgapMessage,
    NgapUeContextReleaseComplete,
    NgapUplinkNasTransport,
    PduSessionSetupItem,
    PduSessionToSetup,
};
