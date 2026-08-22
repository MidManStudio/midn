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
//! (`InitialUeMessage`/`Uplink`/`DownlinkNasTransport`/
//! `InitialContextSetupRequest`/`Response`) and `ie_ids`'s "Confidence
//! upgrade" note — every ProcedureCode/ProtocolIE-ID this file uses was
//! checked against Wireshark's real NGAP-Constants.asn this session, not
//! left at "best recollection."
//!
//! Wired into the AMF state machine (`midn_core::amf`) via the `NgapMessage`
//! enum directly (`Amf::process_ngap` dispatches on the enum, not through
//! this file's PER codec — see `amf::registration` module doc "Phase A vs
//! Phase B"). This file's PER encode/decode is the SEPARATE layer that
//! matters once bytes actually need to go on a wire — and now they do:
//! `midn-transport`/`midn-sim` drive real `InitialUeMessage`/`Uplink`/
//! `DownlinkNasTransport` PDUs over a real SCTP-over-UDP socket for Phase A.
//! `InitialContextSetupRequest`/`Response` codec support (this session)
//! extends that same real-wire path to Phase B — `midn-sim` doesn't call it
//! yet (still Phase-A-only), but the codec itself is no longer the blocker.

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
