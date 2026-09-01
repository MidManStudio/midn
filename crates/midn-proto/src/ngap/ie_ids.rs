// crates/midn-proto/src/ngap/ie_ids.rs
//! ProcedureCode / ProtocolIE-ID / Criticality constants — 3GPP TS 38.413.
//!
//! ## Confidence upgrade (this session)
//!
//! Every constant that was already in this file — the 3 ProcedureCodes and
//! 5 ProtocolIE-IDs from the original increment — was checked this session
//! against `wireshark/epan/dissectors/asn1/ngap/NGAP-Constants.asn`
//! (fetched directly from Wireshark's repo, itself generated from 3GPP
//! TS 38.413's real ASN.1 module) rather than trusted from memory. All 8
//! matched exactly: `id-InitialUEMessage=15`, `id-DownlinkNASTransport=4`,
//! `id-UplinkNASTransport=46`, `id-AMF-UE-NGAP-ID=10`, `id-RAN-UE-NGAP-ID=85`,
//! `id-NAS-PDU=38`, `id-UserLocationInformation=121`,
//! `id-RRCEstablishmentCause=90`. The 6 new constants added this session
//! (`PROC_INITIAL_CONTEXT_SETUP` and the 5 new `ID_*` below) come from the
//! same fetched source, not recollection — genuinely verified, not just a
//! confidence upgrade on old guesses. The warning below now applies only to
//! anything added in a FUTURE increment without doing the same fetch.
//!
//! Before connecting to real gNB equipment: still worth a real capture diff
//! regardless — this covers ProcedureCode/ProtocolIE-ID *values* only, not
//! the full ASN.1 structure of every IE's contents (see e.g. the PDU-session
//! list helpers in `codec.rs`, which are a deliberate structural
//! simplification, not a byte-exact rendering of the real nested transfer-IE
//! shape — flagged there, not here).
//!
//! ## Known structural simplification: bundled UserLocationInformation
//!
//! Real NGAP conveys TAI + NR-CGI together inside a single
//! `UserLocationInformation` IE (a CHOICE, with the NR branch being
//! `UserLocationInformationNR { nrCGI, tai, ... }`) — NOT as two independent
//! top-level ProtocolIE-Field entries the way S1AP keeps TAI and E-UTRAN-CGI
//! separate. This codec models that bundling: `ID_USER_LOCATION_INFO` covers
//! one IE whose value is `nr_cgi (9 bytes) || tai (6 bytes)` concatenated,
//! written/read together in `codec.rs`. This is closer to the real wire
//! shape than pretending they're separate IEs, but the exact field order and
//! any CHOICE-tag framing inside `UserLocationInformationNR` itself is not
//! modeled — this is still a simplification, not a byte-exact rendering of
//! that IE. Flag if diffing against a real capture.

// ── Criticality (NGAP-CommonDataTypes) ───────────────────────────────────────
// Criticality ::= ENUMERATED { reject, ignore, notify } — same generic ASN.1
// pattern as S1AP (and X2AP); confident this 3-value order is consistent
// across the sibling protocols.
pub const CRITICALITY_REJECT: u8 = 0;
pub const CRITICALITY_IGNORE: u8 = 1;
pub const CRITICALITY_NOTIFY: u8 = 2;

// ── ProcedureCode (NGAP-Constants) ────────────────────────────────────────────
// VERIFIED against Wireshark's NGAP-Constants.asn this session — see module
// doc "Confidence upgrade".
pub const PROC_DOWNLINK_NAS_TRANSPORT: u32 = 4;
pub const PROC_INITIAL_UE_MESSAGE: u32 = 15;
pub const PROC_UPLINK_NAS_TRANSPORT: u32 = 46;
/// Shared by InitialContextSetupRequest (initiatingMessage),
/// InitialContextSetupResponse (successfulOutcome), and
/// InitialContextSetupFailure (unsuccessfulOutcome, not implemented here) —
/// NGAP Class-1 procedures use ONE ProcedureCode across all three PDU-choice
/// outcomes, unlike the three Class-2 (request-only) procedures above. See
/// `codec.rs`'s `PDU_CHOICE_*` constants for how the choice value
/// disambiguates Request from Response at decode time.
pub const PROC_INITIAL_CONTEXT_SETUP: u32 = 14;

/// Verified against Wireshark's real NGAP-Constants.asn, fetched fresh this
/// session (not recollected) — same verification standard as the
/// InitialContextSetup block above.
pub const PROC_UE_CONTEXT_RELEASE: u32 = 41;

// ── ProtocolIE-ID (NGAP-Constants) ────────────────────────────────────────────
// VERIFIED against Wireshark's NGAP-Constants.asn this session — see module
// doc "Confidence upgrade".
pub const ID_AMF_UE_NGAP_ID: u32 = 10;
pub const ID_RAN_UE_NGAP_ID: u32 = 85;
pub const ID_NAS_PDU: u32 = 38;
/// Bundled TAI+NR-CGI — see module doc "Known structural simplification".
pub const ID_USER_LOCATION_INFO: u32 = 121;
pub const ID_RRC_ESTABLISHMENT_CAUSE: u32 = 90;
pub const ID_SECURITY_KEY: u32 = 94;
pub const ID_UE_AGGREGATE_MAX_BIT_RATE: u32 = 110;
/// PDU sessions to set up, carried inside InitialContextSetupRequest.
pub const ID_PDU_SESSION_RESOURCE_SETUP_LIST_CTXT_REQ: u32 = 71;
/// PDU sessions successfully set up, carried inside
/// InitialContextSetupResponse.
pub const ID_PDU_SESSION_RESOURCE_SETUP_LIST_CTXT_RES: u32 = 72;
/// PDU sessions that failed to set up, carried inside
/// InitialContextSetupResponse.
pub const ID_PDU_SESSION_RESOURCE_FAILED_TO_SETUP_LIST_CTXT_RES: u32 = 55;
/// Verified against Wireshark's real NGAP-Constants.asn, fetched fresh this
/// session — carried inside UeContextReleaseCommand.
pub const ID_CAUSE: u32 = 15;

// ── Field range constants ─────────────────────────────────────────────────────
// Real spec types, ranges as commonly documented:
//   RAN-UE-NGAP-ID  INTEGER (0..4294967295) — full 32-bit (NGAP widened this
//                    relative to S1AP's 24-bit ENB-UE-S1AP-ID — moderate
//                    confidence this widening is real, it's a commonly-cited
//                    4G→5G NGAP delta, but unverified against spec text here)
//   AMF-UE-NGAP-ID  INTEGER (0..4294967295) — full 32-bit, same as S1AP's
//                    MME-UE-S1AP-ID range.
pub const RAN_UE_NGAP_ID_MAX: u64 = 4_294_967_295;
pub const AMF_UE_NGAP_ID_MAX: u64 = 4_294_967_295;

// RRCEstablishmentCause modeled the same simplified way as S1AP's
// RRC-EstablishmentCause: a plain constrained range rather than a typed
// enum of the ~10-12 named cause values in the real spec.
pub const RRC_ESTABLISHMENT_CAUSE_MAX: u64 = 15;

// PDUSessionID: TS 24.501 §9.11.3.41 defines this as a 1-octet field —
// confident in the octet width; using the full 0..255 range rather than the
// narrower 1..15 practical value space real UEs use, since the IE itself
// isn't spec-constrained any tighter than "1 octet" at the NGAP layer.
pub const PDU_SESSION_ID_MAX: u64 = 255;
// QosFlowIdentifier: commonly documented as a 6-bit value (0..63) in
// TS 23.501/38.413 — same "commonly cited, not checked against fetched spec
// text this session" confidence tier as RRC_ESTABLISHMENT_CAUSE_MAX above.
pub const QFI_MAX: u64 = 63;
// BitRate (used by UE-AMBR's two DL/UL fields): commonly cited NGAP/S1AP
// ceiling (4 Tbps) — same confidence tier as QFI_MAX.
pub const BIT_RATE_MAX: u64 = 4_000_000_000_000;

// ProtocolIE-ID itself is INTEGER (0..65535) in the real spec — same generic
// range as S1AP, this part isn't NGAP-specific.
pub const PROTOCOL_IE_ID_MAX: u64 = 65_535;
// ProcedureCode is INTEGER (0..255) — same generic range as S1AP.
pub const PROCEDURE_CODE_MAX: u64 = 255;

// Cause: real NGAP models this as a CHOICE { radioNetwork, transport, nas,
// protocol, misc }, each arm its own ENUMERATED — this codebase's
// `NgapCause` flattens all of that into one 7-variant Rust enum (matching
// `s1ap::S1apCause`'s identical simplification), so the wire encoding here
// is a flat constrained int over the enum's discriminant, not a real
// nested CHOICE-of-ENUMERATED. Documented simplification, same spirit as
// the PDU-session list's own flat/simplified structure — a real decoder
// expecting the actual CHOICE shape would not parse this correctly.
pub const CAUSE_MAX: u64 = 6;
