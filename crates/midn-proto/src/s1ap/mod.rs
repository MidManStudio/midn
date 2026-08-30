// crates/midn-proto/src/s1ap/mod.rs
//! S1AP — S1 Application Protocol (3GPP TS 36.413)
//!
//! `messages` defines the in-process message structs the MME state machine
//! already operates on (in-process mock eNodeB, no real transport yet).
//!
//! `ie_ids` + `codec` add a real ASN.1 ALIGNED PER wire encoder/decoder on
//! top of those structs, built on the shared bit-packing engine at
//! `crate::per` (moved there since NGAP uses the identical ALIGNED PER
//! rules — see `crate::per` module docs). Scope now covers
//! InitialUEMessage/Uplink/DownlinkNASTransport plus
//! InitialContextSetupRequest/Response (added for `mme-sim`, the LTE
//! counterpart of `midn-sim`'s already-proven real-socket setup) — see
//! `codec` module docs for the exact current scope and the spec-fidelity
//! disclaimer in `ie_ids` before relying on this for actual eNodeB
//! hardware. Not yet wired into `Mme::process_s1ap` — that still takes
//! in-process structs; `mme-sim` bridges real bytes to those structs at the
//! transport boundary itself, the same pattern `midn-sim` already
//! established for `Amf::process_ngap`/`ngap::codec`.

pub mod codec;
pub mod ie_ids;
pub mod messages;

/// Re-export for source compatibility — the PER engine used to live here.
/// New code should use `crate::per` directly; this module now just points
/// at it so `midn_proto::s1ap::per::PerWriter` (if anything external still
/// imports that path) keeps working unchanged.
pub mod per {
    pub use crate::per::*;
}

pub use codec::{decode_s1ap_pdu, encode_s1ap_pdu};
pub use messages::{
    DownlinkNasTransport,
    ErabSetupItem,
    ErabToSetup,
    Gummei,
    InitialContextSetupRequest,
    InitialContextSetupResponse,
    InitialUeMessage,
    S1SetupRequest,
    S1SetupResponse,
    S1apCause,
    S1apMessage,
    SupportedTa,
    UeContextReleaseComplete,
    UplinkNasTransport,
};
