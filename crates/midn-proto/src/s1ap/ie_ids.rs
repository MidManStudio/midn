// crates/midn-proto/src/s1ap/ie_ids.rs
//! ProcedureCode / ProtocolIE-ID / Criticality constants — 3GPP TS 36.413.
//!
//! ⚠️ CONFIDENCE LEVELS — read before trusting these against real hardware.
//!
//! The original 8 constants below (Criticality, the 3 Class-2 ProcedureCodes,
//! MME-UE-S1AP-ID/eNB-UE-S1AP-ID/NAS-PDU, plus the 3 UNVERIFIED entries) came
//! from memory of the public S1AP ASN.1 module, not a fetched copy of
//! TS 36.413 — see the per-entry confidence notes below, unchanged from
//! then.
//!
//! The InitialContextSetup block (added when that message got PER codec
//! support) was checked directly against Wireshark's real
//! `S1AP-Constants.asn`/`S1AP-IEs.asn` (fetched from Wireshark's GitHub
//! mirror, itself generated from 3GPP TS 36.413's actual ASN.1 — same
//! verification approach `ngap::ie_ids` already used and whose track record
//! held up exactly: every existing NGAP constant checked out correct). All
//! of `PROC_INITIAL_CONTEXT_SETUP`, `ID_E_RAB_TO_BE_SETUP_LIST_CTXT_SU_REQ`,
//! `ID_E_RAB_SETUP_LIST_CTXT_SU_RES`, `ID_E_RAB_FAILED_TO_SETUP_LIST_CTXT_SU_RES`,
//! `ID_UE_AGGREGATE_MAXIMUM_BITRATE`, `ID_SECURITY_KEY`, `ERAB_ID_MAX`,
//! `QCI_MAX`, and `BIT_RATE_MAX` are from that source, not recollection —
//! confidently correct, not "best guess" like the UNVERIFIED block still is.
//!
//! Before connecting to real RAN equipment: capture a real S1AP exchange
//! (Wireshark dissects it natively) and diff against what this codec
//! produces/expects, starting with the `// UNVERIFIED` entries — those are
//! still the ones that haven't had this treatment.

// ── Criticality (S1AP-CommonDataTypes) ───────────────────────────────────────
// Criticality ::= ENUMERATED { reject, ignore, notify } — confident, this
// 3-value enum order is widely and consistently referenced.
pub const CRITICALITY_REJECT: u8 = 0;
pub const CRITICALITY_IGNORE: u8 = 1;
pub const CRITICALITY_NOTIFY: u8 = 2;

// ── ProcedureCode (S1AP-Constants) ────────────────────────────────────────────
// Reasonably confident — these four show up constantly in S1AP material.
pub const PROC_DOWNLINK_NAS_TRANSPORT: u32 = 11;
pub const PROC_INITIAL_UE_MESSAGE: u32 = 12;
pub const PROC_UPLINK_NAS_TRANSPORT: u32 = 13;

// Verified against Wireshark's real S1AP-Constants.asn — see module doc.
pub const PROC_INITIAL_CONTEXT_SETUP: u32 = 9;
// Verified against Wireshark's real S1AP-Constants.asn, fetched fresh this
// session (not recollected).
pub const PROC_UE_CONTEXT_RELEASE: u32 = 23;

// ── ProtocolIE-ID (S1AP-Constants) ────────────────────────────────────────────
// High confidence — MME-UE-S1AP-ID=0 and eNB-UE-S1AP-ID=8 are near-universal
// reference points; NAS-PDU=26 likewise.
pub const ID_MME_UE_S1AP_ID: u32 = 0;
pub const ID_ENB_UE_S1AP_ID: u32 = 8;
pub const ID_NAS_PDU: u32 = 26;

// UNVERIFIED — lower confidence, prioritize checking these against a real
// capture or the actual ASN.1 module before relying on them for interop.
pub const ID_TAI: u32 = 67;
pub const ID_EUTRAN_CGI: u32 = 100;
pub const ID_RRC_ESTABLISHMENT_CAUSE: u32 = 134;

// Verified against Wireshark's real S1AP-Constants.asn — see module doc.
// InitialContextSetupRequest IEs:
pub const ID_E_RAB_TO_BE_SETUP_LIST_CTXT_SU_REQ: u32 = 24;
pub const ID_UE_AGGREGATE_MAXIMUM_BITRATE: u32 = 66;
pub const ID_SECURITY_KEY: u32 = 73;
// InitialContextSetupResponse IEs:
pub const ID_E_RAB_SETUP_LIST_CTXT_SU_RES: u32 = 51;
pub const ID_E_RAB_FAILED_TO_SETUP_LIST_CTXT_SU_RES: u32 = 48;
// Carried inside UeContextReleaseCommand — verified against Wireshark's
// real S1AP-Constants.asn, fetched fresh this session. Notably a LOW value
// (2) here vs NGAP's id-Cause=15 — genuinely different numbering between
// the two specs' ProtocolIE-ID tables, not a typo.
pub const ID_CAUSE: u32 = 2;

// ── Field range constants ─────────────────────────────────────────────────────
// Real spec types, ranges as commonly documented:
//   ENB-UE-S1AP-ID  INTEGER (0..16777215)   — 24-bit
//   MME-UE-S1AP-ID  INTEGER (0..4294967295) — 32-bit
pub const ENB_UE_S1AP_ID_MAX: u64 = 16_777_215;
pub const MME_UE_S1AP_ID_MAX: u64 = 4_294_967_295;

// RRC-EstablishmentCause is a real ENUMERATED with ~10-12 named values in the
// spec; this codebase models it as a plain `u8` rather than a typed enum, so
// we just give it a generously-sized constrained range (4 bits) rather than
// pretending to enumerate exact cause values we haven't modeled in Rust yet.
pub const RRC_ESTABLISHMENT_CAUSE_MAX: u64 = 15;

// Verified against Wireshark's real S1AP-IEs.asn — see module doc.
//   E-RAB-ID ::= INTEGER (0..15, ...)          — base range before the "..."
//                                                 extension marker, which this
//                                                 codebase doesn't model (same
//                                                 simplification as everywhere
//                                                 else here that touches an
//                                                 extensible INTEGER type).
//   QCI      ::= INTEGER (0..255)
//   BitRate  ::= INTEGER (0..10000000000)      — 10 Gbps; NOT the same range
//                                                 as NGAP's 5G BitRate
//                                                 (0..4000000000000, 4 Tbps)
//                                                 — different spec, genuinely
//                                                 different max, don't reuse
//                                                 ngap::ie_ids::BIT_RATE_MAX
//                                                 here.
pub const ERAB_ID_MAX: u64 = 15;
pub const QCI_MAX: u64 = 255;
pub const BIT_RATE_MAX: u64 = 10_000_000_000;

// ProtocolIE-ID itself is INTEGER (0..65535) in the real spec.
pub const PROTOCOL_IE_ID_MAX: u64 = 65_535;
// ProcedureCode is INTEGER (0..255).
pub const PROCEDURE_CODE_MAX: u64 = 255;

// Cause: real S1AP models this as a CHOICE { radioNetwork, transport, nas,
// misc } (S1AP's Cause CHOICE has 4 arms, one fewer than NGAP's 5 —
// S1AP has no separate `protocol` arm at the top level), each its own
// ENUMERATED — this codebase's `S1apCause` flattens all of that into one
// 7-variant Rust enum, matching `ngap::NgapCause`'s identical
// simplification for symmetry between the two protocols' Rust types even
// though the real CHOICE shapes aren't identical. Wire
// encoding here is a flat constrained int over the enum discriminant, not
// a real nested CHOICE-of-ENUMERATED — same documented simplification as
// ngap::ie_ids::CAUSE_MAX.
pub const CAUSE_MAX: u64 = 6;
