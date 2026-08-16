// crates/midn-proto/src/ngap/messages.rs
//! NGAP message definitions — 3GPP TS 38.413.
//!
//! Mirrors `s1ap::messages` structurally — same shape, 5G NR terminology —
//! since NGAP is deliberately designed by 3GPP as S1AP's structural sibling.
//! Differences from the S1AP stub this replaces:
//!
//!   - `RanUeNgapId`/`AmfUeNgapId` replace `EnbUeS1apId`/`MmeUeS1apId`.
//!   - `amf_ue_ngap_id` added to `DownlinkNasTransport`/`UplinkNasTransport`
//!     — the original stub only carried `ran_ue_ngap_id`, which can't
//!     actually address a specific AMF-side UE context on its own.
//!   - `tai` added to `InitialUeMessage`/`UplinkNasTransport` (6 bytes:
//!     PLMN(3) + 5GS-TAC(3) — moderate confidence: the 4G→5G TAC width
//!     change from 2 to 3 octets is one of the more widely and consistently
//!     documented differences between the two specs, but this hasn't been
//!     checked against a fetched copy of TS 23.003/38.413 in this session.
//!     Same caution tier as `ngap::ie_ids`; verify before relying on this
//!     for real gNB interop).
//!   - `nr_cgi: [u8; 9]` kept exactly as it was in the original stub —
//!     inherited, not re-derived by me. If you sized this from a real
//!     source originally, trust that over anything above.
//!   - `InitialContextSetupRequest`/`InitialContextSetupResponse` added.
//!     TS 38.413 uses this exact message name in NGAP (3GPP kept S1AP/NGAP
//!     naming symmetric on purpose) — the original stub jumped straight to
//!     `PduSessionResourceSetup*` and had no message carrying the AS
//!     security anchor key or a piggybacked NAS Registration Accept, which
//!     the AMF registration procedure needs in Phase B mode. `PduSessionResourceSetup*`
//!     is left untouched — TS 38.413 really does have both as separate
//!     procedures (initial PDU session(s) can ride inside
//!     InitialContextSetupRequest OR arrive later via a standalone
//!     PDUSessionResourceSetupRequest; this project models the former,
//!     matching how `s1ap`'s ICSR carries the initial E-RAB(s)).
//!
//! PER wire encoding for `InitialUeMessage`/`Uplink`/`DownlinkNasTransport`
//! is implemented in `ngap::codec` (mirrors `s1ap::codec`'s scope exactly).
//! `InitialContextSetupRequest/Response` and everything else here is struct-
//! only for now — no codec yet. `s1ap`'s own ICSR is in the identical
//! position (see that module's codec doc) despite LTE's Phase 3 having
//! shipped and passed CI for a while — `Mme`/`Amf` dispatch on the
//! `S1apMessage`/`NgapMessage` enum directly and never go through
//! `encode_*_pdu`/`decode_*_pdu` internally, so struct-only is enough until
//! a real SCTP wire boundary exists (not built yet, either RAT).

use bytes::Bytes;

/// NGAP message discriminant.
#[derive(Debug, Clone)]
pub enum NgapMessage {
    // ── Connection management ─────────────────────────────────────────────
    /// gNodeB → AMF: register gNodeB on startup.
    NgSetupRequest,
    /// AMF → gNodeB: accept registration.
    NgSetupResponse,

    // ── UE context management ─────────────────────────────────────────────
    /// gNodeB → AMF: first NAS message from a new UE.
    InitialUeMessage(NgapInitialUeMessage),
    /// AMF → gNodeB: send NAS PDU down to UE.
    DownlinkNasTransport(NgapDownlinkNasTransport),
    /// gNodeB → AMF: send NAS PDU up to AMF.
    UplinkNasTransport(NgapUplinkNasTransport),

    // ── Security / context establishment ──────────────────────────────────
    /// AMF → gNodeB: establish UE security context, optionally piggyback
    /// initial PDU session(s) and a NAS PDU (RegistrationAccept).
    InitialContextSetupRequest(NgapInitialContextSetupRequest),
    /// gNodeB → AMF: security context (+ any requested PDU sessions) established.
    InitialContextSetupResponse(NgapInitialContextSetupResponse),
    /// gNodeB → AMF: context setup failed.
    InitialContextSetupFailure { cause: NgapCause },

    // ── PDU Session (post-initial-context, additional sessions) ───────────
    /// AMF → gNodeB: establish PDU session resource.
    PduSessionResourceSetupRequest,
    /// gNodeB → AMF: PDU session resource established.
    PduSessionResourceSetupResponse,
    /// gNodeB → AMF: PDU session resource establishment failed.
    PduSessionResourceSetupFailure,

    // ── Release ───────────────────────────────────────────────────────────
    /// AMF → gNodeB: release UE context.
    UeContextReleaseCommand { cause: NgapCause },
    /// gNodeB → AMF: context released.
    UeContextReleaseComplete(NgapUeContextReleaseComplete),
}

/// Initial UE Message IEs (5G NR).
#[derive(Debug, Clone)]
pub struct NgapInitialUeMessage {
    pub ran_ue_ngap_id:          u32,
    pub nas_pdu:                 Bytes,
    /// 5GS-TAI: PLMN(3) + 5GS-TAC(3). See module doc confidence note.
    pub tai:                     [u8; 6],
    /// NR-CGI. Inherited sizing from the original stub — see module doc.
    pub nr_cgi:                  [u8; 9],
    pub rrc_establishment_cause: u8,
}

/// Downlink NAS Transport IEs.
#[derive(Debug, Clone)]
pub struct NgapDownlinkNasTransport {
    pub amf_ue_ngap_id: u32,
    pub ran_ue_ngap_id: u32,
    pub nas_pdu:        Bytes,
}

/// Uplink NAS Transport IEs.
#[derive(Debug, Clone)]
pub struct NgapUplinkNasTransport {
    pub amf_ue_ngap_id: u32,
    pub ran_ue_ngap_id: u32,
    pub nas_pdu:        Bytes,
    pub tai:            [u8; 6],
    pub nr_cgi:         [u8; 9],
}

/// Initial Context Setup Request IEs.
///
/// Field names match what `amf::registration`'s Phase B branch constructs
/// (`handle_security_mode_complete`) — same intent as `s1ap`'s ICSR doc
/// comment.
#[derive(Debug, Clone)]
pub struct NgapInitialContextSetupRequest {
    pub amf_ue_ngap_id: u32,
    pub ran_ue_ngap_id: u32,
    /// PDU sessions to establish alongside the security context.
    pub pdu_sessions:   Vec<PduSessionToSetup>,
    /// NAS PDU to relay to UE (RegistrationAccept). gNodeB delivers via RRC.
    pub nas_pdu:        Option<Bytes>,
    /// Aggregate Maximum Bit Rate — (DL bps, UL bps).
    pub ue_ambr:        (u64, u64),
    /// AS security anchor key (5G: derived as part of KAMF → KgNB chain,
    /// TS 33.501 — analogous role to S1AP's Kasme-derived `security_key`,
    /// NOT the same derivation function).
    pub security_key:   [u8; 32],
}

/// PDU session to set up (in InitialContextSetupRequest).
#[derive(Debug, Clone)]
pub struct PduSessionToSetup {
    pub pdu_session_id:      u8,
    /// QoS Flow Identifier — 5G's per-flow QoS handle, the structural
    /// (not numerically equivalent) counterpart to LTE's per-bearer QCI.
    pub qfi:                 u8,
    /// UPF UL TEID as big-endian bytes.
    pub gtp_teid:            [u8; 4],
    /// UPF N3 (gNB-facing) IPv4 transport address.
    pub transport_layer_addr: [u8; 4],
}

/// Initial Context Setup Response IEs — sent by gNodeB after context established.
#[derive(Debug, Clone)]
pub struct NgapInitialContextSetupResponse {
    pub amf_ue_ngap_id:    u32,
    pub ran_ue_ngap_id:    u32,
    /// PDU sessions successfully established.
    pub pdu_sessions_setup: Vec<PduSessionSetupItem>,
    /// PDU sessions that failed (empty in normal case).
    pub pdu_sessions_failed: Vec<u8>,
}

/// PDU session setup item in Initial Context Setup Response.
///
/// `gtp_teid` is big-endian bytes so the AMF state machine can call
/// `u32::from_be_bytes(item.gtp_teid)` directly — same convention as
/// `s1ap::ErabSetupItem`.
#[derive(Debug, Clone, Copy)]
pub struct PduSessionSetupItem {
    pub pdu_session_id:       u8,
    /// gNodeB N3 IPv4 transport address.
    pub transport_layer_addr: [u8; 4],
    /// gNodeB-assigned DL TEID as big-endian bytes.
    pub gtp_teid:             [u8; 4],
}

/// UE Context Release Complete IEs.
#[derive(Debug, Clone)]
pub struct NgapUeContextReleaseComplete {
    pub amf_ue_ngap_id: u32,
    pub ran_ue_ngap_id: u32,
}

/// NGAP cause code (simplified) — structurally mirrors `s1ap::S1apCause`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NgapCause {
    RadioNetworkUnspecified,
    TransportUnspecified,
    NasNormalRelease,
    NasDeregister,
    NasAuthFailure,
    ProtocolUnspecified,
    MiscUnspecified,
    }
