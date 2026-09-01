// crates/midn-proto/src/ngap/codec.rs
//! NGAP-PDU PER encoder/decoder — built on `crate::per` + `ie_ids.rs`.
//!
//! Structurally identical to `s1ap::codec` — same PDU-wrapper shape, same
//! IE-container framing, same simplifications (see below) — because NGAP
//! and S1AP share the same underlying ALIGNED PER transport conventions.
//! If you're comparing the two files side by side, that similarity is
//! intentional, not copy-paste drift.
//!
//! ## Scope (this increment)
//!
//! Covers the four messages that drive the AMF state machine's Phase A and
//! Phase B: `InitialUeMessage`, `UplinkNasTransport`, `DownlinkNasTransport`
//! (Class 2, request-only), and `InitialContextSetupRequest`/`Response`
//! (Class 1 — one shared ProcedureCode, disambiguated by PDU choice, see
//! `PDU_CHOICE_*` below). `UeContextRelease*`, `NgSetup*`,
//! `PduSessionResourceSetup*` are NOT yet implemented here —
//! `encode_ngap_pdu` returns a `MalformedNgap` error for those variants
//! rather than silently producing wrong bytes.
//!
//! ## Wire shape
//!
//! ```text
//! NGAP-PDU ::= CHOICE { initiatingMessage, successfulOutcome, unsuccessfulOutcome }
//!   each one ::= SEQUENCE { procedureCode INTEGER(0..255),
//!                           criticality   Criticality,
//!                           value         OPEN TYPE }
//!   value    ::= SEQUENCE { protocolIEs ProtocolIE-Container }
//!   ProtocolIE-Container ::= SEQUENCE (SIZE(1..maxProtocolIEs)) OF ProtocolIE-Field
//!   ProtocolIE-Field ::= SEQUENCE { id ProtocolIE-ID, criticality Criticality, value OPEN TYPE }
//! ```
//!
//! Same simplification as `s1ap::codec` on the IE count field: real ALIGNED
//! PER would encode `SIZE(1..maxProtocolIEs)` as a fixed-width octet-aligned
//! constrained int; this uses the generic length-determinant instead. It's
//! internally consistent (round-trips against itself) but may not
//! byte-match a real gNB's framing of the count specifically.
//!
//! All four messages here are `initiatingMessage` except
//! `InitialContextSetupResponse`, which is `successfulOutcome` — see
//! `PDU_CHOICE_*` below and `ie_ids::PROC_INITIAL_CONTEXT_SETUP`'s doc for
//! why Class-1 procedures need the choice value threaded through decode,
//! unlike the three Class-2 messages which can hardcode it.
//!
//! ## TAI + NR-CGI bundling
//!
//! `InitialUeMessage` and `UplinkNasTransport` both carry `tai` and
//! `nr_cgi` bundled into a single `ID_USER_LOCATION_INFO` IE — see
//! `ie_ids` module doc "Known structural simplification" for why, and
//! `write_user_location_info`/`read_user_location_info` below for the
//! concatenation order (`nr_cgi (9 bytes) || tai (6 bytes)`).
//!
//! ## PDU-session list encoding (InitialContextSetupRequest/Response)
//!
//! Real NGAP models each PDU session list item as a much richer nested
//! structure — `PDUSessionResourceSetupItemCxtReq` carries an optional
//! S-NSSAI plus a FURTHER-nested `pDUSessionResourceSetupRequestTransfer`
//! OCTET STRING, itself its own ASN.1 SEQUENCE with UL-NGU-UP-TNLInformation
//! and PDU-Session-Aggregate-Maximum-Bit-Rate sub-IEs. `PduSessionToSetup`/
//! `PduSessionSetupItem` don't carry fields for any of that — this codec
//! writes only what those structs actually have
//! (`write_pdu_sessions_to_setup`/`write_pdu_sessions_setup` below), flat,
//! in a fixed field order. Same simplification tier as the TAI+NR-CGI
//! bundling above: internally consistent, not a byte-exact rendering of the
//! real nested transfer-IE structure. Flag if diffing against a real
//! capture.

use bytes::Bytes;

use crate::error::{ProtoError, Result};
use crate::ngap::ie_ids as ie;
use crate::ngap::messages::{
    NgapCause, NgapDownlinkNasTransport, NgapInitialContextSetupRequest,
    NgapInitialContextSetupResponse, NgapInitialUeMessage, NgapMessage, NgapUeContextReleaseComplete,
    NgapUplinkNasTransport, PduSessionSetupItem, PduSessionToSetup,
};
use crate::per::{PerReader, PerWriter};

const PDU_CHOICE_INITIATING_MESSAGE: u64 = 0;
/// InitialContextSetupResponse's PDU choice — see `ie::PROC_INITIAL_CONTEXT_
/// SETUP`'s doc for why this Class-1 procedure needs it threaded through
/// decode, unlike the Class-2 messages above which never write anything but
/// `PDU_CHOICE_INITIATING_MESSAGE`.
const PDU_CHOICE_SUCCESSFUL_OUTCOME: u64 = 1;

type IeEntry = (u32, u8, Vec<u8>);

/// Flat discriminant mapping for the wire — see `ie::CAUSE_MAX`'s doc for
/// why this isn't a real CHOICE-of-ENUMERATED encoding.
fn ngap_cause_to_u64(c: NgapCause) -> u64 {
    match c {
        NgapCause::RadioNetworkUnspecified => 0,
        NgapCause::TransportUnspecified => 1,
        NgapCause::NasNormalRelease => 2,
        NgapCause::NasDeregister => 3,
        NgapCause::NasAuthFailure => 4,
        NgapCause::ProtocolUnspecified => 5,
        NgapCause::MiscUnspecified => 6,
    }
}

fn ngap_cause_from_u64(v: u64) -> Option<NgapCause> {
    match v {
        0 => Some(NgapCause::RadioNetworkUnspecified),
        1 => Some(NgapCause::TransportUnspecified),
        2 => Some(NgapCause::NasNormalRelease),
        3 => Some(NgapCause::NasDeregister),
        4 => Some(NgapCause::NasAuthFailure),
        5 => Some(NgapCause::ProtocolUnspecified),
        6 => Some(NgapCause::MiscUnspecified),
        _ => None,
    }
}

// ── IE-container framing ──────────────────────────────────────────────────────
// Identical shape to s1ap::codec's — see that file's version for the fuller
// explanation of the count-field simplification.

fn write_ie_container(w: &mut PerWriter, entries: &[IeEntry]) {
    w.write_length_determinant(entries.len());
    for (id, crit, val) in entries {
        w.write_constrained_int(*id as u64, 0, ie::PROTOCOL_IE_ID_MAX);
        w.write_constrained_int(*crit as u64, 0, 2);
        w.write_octet_string(val);
    }
}

fn read_ie_container(r: &mut PerReader) -> Option<Vec<IeEntry>> {
    let count = r.read_length_determinant()?;
    let mut out = Vec::with_capacity(count);
    for _ in 0..count {
        let id = r.read_constrained_int(0, ie::PROTOCOL_IE_ID_MAX)? as u32;
        let crit = r.read_constrained_int(0, 2)? as u8;
        let val = r.read_octet_string()?;
        out.push((id, crit, val));
    }
    Some(out)
}

// ── PDU wrapper (choice + procedureCode + criticality + OPEN TYPE value) ─────

fn encode_pdu_wrapper(choice: u64, procedure_code: u32, criticality: u8, value_bytes: &[u8]) -> Bytes {
    let mut w = PerWriter::new();
    w.write_constrained_int(choice, 0, 2);
    w.write_constrained_int(procedure_code as u64, 0, ie::PROCEDURE_CODE_MAX);
    w.write_constrained_int(criticality as u64, 0, 2);
    w.write_octet_string(value_bytes);
    Bytes::from(w.into_bytes())
}

/// Returns `(choice, procedure_code, criticality, value_bytes)`. Unlike the
/// Class-2-only original version of this function, `choice` is now
/// returned rather than discarded — `decode_ngap_pdu`'s dispatch needs it
/// to tell `InitialContextSetupRequest` (choice=0) apart from `Response`
/// (choice=1), since both share `ie::PROC_INITIAL_CONTEXT_SETUP`.
fn decode_pdu_wrapper(buf: &[u8]) -> Option<(u64, u32, u8, Vec<u8>)> {
    let mut r = PerReader::new(buf);
    let choice = r.read_constrained_int(0, 2)?;
    let proc = r.read_constrained_int(0, ie::PROCEDURE_CODE_MAX)? as u32;
    let crit = r.read_constrained_int(0, 2)? as u8;
    let val = r.read_octet_string()?;
    Some((choice, proc, crit, val))
}

// ── Bundled TAI + NR-CGI helper ───────────────────────────────────────────────
// See ie_ids module doc "Known structural simplification" and this file's
// module doc "TAI + NR-CGI bundling".

fn write_user_location_info(w: &mut PerWriter, nr_cgi: &[u8; 9], tai: &[u8; 6]) {
    w.write_octets(nr_cgi);
    w.write_octets(tai);
}

fn read_user_location_info(r: &mut PerReader) -> Option<([u8; 9], [u8; 6])> {
    let cgi_v = r.read_octets(9)?;
    let tai_v = r.read_octets(6)?;
    let mut nr_cgi = [0u8; 9];
    let mut tai = [0u8; 6];
    nr_cgi.copy_from_slice(&cgi_v);
    tai.copy_from_slice(&tai_v);
    Some((nr_cgi, tai))
}

// ── PDU-session list helpers ──────────────────────────────────────────────────
// See module doc "PDU-session list encoding" for exactly what's simplified
// here versus the real nested ASN.1 structure.

fn write_pdu_sessions_to_setup(w: &mut PerWriter, sessions: &[PduSessionToSetup]) {
    w.write_length_determinant(sessions.len());
    for s in sessions {
        w.write_constrained_int(s.pdu_session_id as u64, 0, ie::PDU_SESSION_ID_MAX);
        w.write_constrained_int(s.qfi as u64, 0, ie::QFI_MAX);
        // pdu_session_id (8 bits) + qfi (6 bits) = 14 bits — NOT byte-aligned.
        // `write_octets` does not align itself (unlike `read_octets`, which
        // always does), so without this the reader silently eats 2 bits of
        // real gtp_teid data as phantom padding. Root cause of the
        // initial_context_setup_request_round_trip CI failure (build #252) —
        // see per.rs's write_octets/read_octets doc comments for the
        // asymmetric-alignment contract this call site was violating.
        w.align();
        w.write_octets(&s.gtp_teid);
        w.write_octets(&s.transport_layer_addr);
    }
}

fn read_pdu_sessions_to_setup(r: &mut PerReader) -> Option<Vec<PduSessionToSetup>> {
    let count = r.read_length_determinant()?;
    let mut out = Vec::with_capacity(count);
    for _ in 0..count {
        let pdu_session_id = r.read_constrained_int(0, ie::PDU_SESSION_ID_MAX)? as u8;
        let qfi = r.read_constrained_int(0, ie::QFI_MAX)? as u8;
        let teid_v = r.read_octets(4)?;
        let addr_v = r.read_octets(4)?;
        let mut gtp_teid = [0u8; 4];
        let mut transport_layer_addr = [0u8; 4];
        gtp_teid.copy_from_slice(&teid_v);
        transport_layer_addr.copy_from_slice(&addr_v);
        out.push(PduSessionToSetup { pdu_session_id, qfi, gtp_teid, transport_layer_addr });
    }
    Some(out)
}

fn write_pdu_sessions_setup(w: &mut PerWriter, items: &[PduSessionSetupItem]) {
    w.write_length_determinant(items.len());
    for it in items {
        w.write_constrained_int(it.pdu_session_id as u64, 0, ie::PDU_SESSION_ID_MAX);
        // Currently a no-op: PDU_SESSION_ID_MAX=255 -> exactly 8 bits, so
        // this is already byte-aligned. Kept explicit anyway so this stays
        // correct if PDU_SESSION_ID_MAX ever narrows below a full octet —
        // see write_pdu_sessions_to_setup above for what happens when a
        // sub-byte field precedes write_octets without this.
        w.align();
        w.write_octets(&it.transport_layer_addr);
        w.write_octets(&it.gtp_teid);
    }
}

fn read_pdu_sessions_setup(r: &mut PerReader) -> Option<Vec<PduSessionSetupItem>> {
    let count = r.read_length_determinant()?;
    let mut out = Vec::with_capacity(count);
    for _ in 0..count {
        let pdu_session_id = r.read_constrained_int(0, ie::PDU_SESSION_ID_MAX)? as u8;
        let addr_v = r.read_octets(4)?;
        let teid_v = r.read_octets(4)?;
        let mut transport_layer_addr = [0u8; 4];
        let mut gtp_teid = [0u8; 4];
        transport_layer_addr.copy_from_slice(&addr_v);
        gtp_teid.copy_from_slice(&teid_v);
        out.push(PduSessionSetupItem { pdu_session_id, transport_layer_addr, gtp_teid });
    }
    Some(out)
}

/// `pdu_sessions_failed` is just a flat list of PDU session IDs — no cause
/// code per item (matches `NgapInitialContextSetupResponse::
/// pdu_sessions_failed: Vec<u8>`'s own shape).
fn write_pdu_session_ids(w: &mut PerWriter, ids: &[u8]) {
    w.write_length_determinant(ids.len());
    for &id in ids {
        w.write_constrained_int(id as u64, 0, ie::PDU_SESSION_ID_MAX);
    }
}

fn read_pdu_session_ids(r: &mut PerReader) -> Option<Vec<u8>> {
    let count = r.read_length_determinant()?;
    let mut out = Vec::with_capacity(count);
    for _ in 0..count {
        out.push(r.read_constrained_int(0, ie::PDU_SESSION_ID_MAX)? as u8);
    }
    Some(out)
}

// ── InitialUeMessage ──────────────────────────────────────────────────────────

pub fn encode_initial_ue_message(msg: &NgapInitialUeMessage) -> Bytes {
    let mut entries: Vec<IeEntry> = Vec::with_capacity(4);

    {
        let mut w = PerWriter::new();
        w.write_constrained_int(msg.ran_ue_ngap_id as u64, 0, ie::RAN_UE_NGAP_ID_MAX);
        entries.push((ie::ID_RAN_UE_NGAP_ID, ie::CRITICALITY_REJECT, w.into_bytes()));
    }
    {
        let mut w = PerWriter::new();
        w.write_octet_string(&msg.nas_pdu);
        entries.push((ie::ID_NAS_PDU, ie::CRITICALITY_REJECT, w.into_bytes()));
    }
    {
        let mut w = PerWriter::new();
        write_user_location_info(&mut w, &msg.nr_cgi, &msg.tai);
        entries.push((ie::ID_USER_LOCATION_INFO, ie::CRITICALITY_IGNORE, w.into_bytes()));
    }
    {
        let mut w = PerWriter::new();
        w.write_constrained_int(
            msg.rrc_establishment_cause as u64,
            0,
            ie::RRC_ESTABLISHMENT_CAUSE_MAX,
        );
        entries.push((ie::ID_RRC_ESTABLISHMENT_CAUSE, ie::CRITICALITY_IGNORE, w.into_bytes()));
    }

    let mut value_w = PerWriter::new();
    write_ie_container(&mut value_w, &entries);

    encode_pdu_wrapper(PDU_CHOICE_INITIATING_MESSAGE, ie::PROC_INITIAL_UE_MESSAGE, ie::CRITICALITY_IGNORE, &value_w.into_bytes())
}

fn decode_initial_ue_message(entries: &[IeEntry]) -> Result<NgapMessage> {
    let mut ran_ue_ngap_id = None;
    let mut nas_pdu = None;
    let mut location = None;
    let mut rrc_cause = None;

    for (id, _crit, val) in entries {
        let mut r = PerReader::new(val);
        match *id {
            x if x == ie::ID_RAN_UE_NGAP_ID => {
                ran_ue_ngap_id = r.read_constrained_int(0, ie::RAN_UE_NGAP_ID_MAX).map(|v| v as u32);
            }
            x if x == ie::ID_NAS_PDU => {
                nas_pdu = r.read_octet_string();
            }
            x if x == ie::ID_USER_LOCATION_INFO => {
                location = read_user_location_info(&mut r);
            }
            x if x == ie::ID_RRC_ESTABLISHMENT_CAUSE => {
                rrc_cause = r
                    .read_constrained_int(0, ie::RRC_ESTABLISHMENT_CAUSE_MAX)
                    .map(|v| v as u8);
            }
            _ => {} // unknown IE — ignore, consistent with Criticality::ignore semantics
        }
    }

    let (nr_cgi, tai) =
        location.ok_or(ProtoError::MalformedNgap { reason: "missing UserLocationInformation" })?;

    Ok(NgapMessage::InitialUeMessage(NgapInitialUeMessage {
        ran_ue_ngap_id: ran_ue_ngap_id
            .ok_or(ProtoError::MalformedNgap { reason: "missing RAN-UE-NGAP-ID" })?,
        nas_pdu: Bytes::from(
            nas_pdu.ok_or(ProtoError::MalformedNgap { reason: "missing NAS-PDU" })?,
        ),
        tai,
        nr_cgi,
        rrc_establishment_cause: rrc_cause
            .ok_or(ProtoError::MalformedNgap { reason: "missing RRCEstablishmentCause" })?,
    }))
}

// ── UplinkNasTransport ────────────────────────────────────────────────────────

pub fn encode_uplink_nas_transport(msg: &NgapUplinkNasTransport) -> Bytes {
    let mut entries: Vec<IeEntry> = Vec::with_capacity(4);

    {
        let mut w = PerWriter::new();
        w.write_constrained_int(msg.amf_ue_ngap_id as u64, 0, ie::AMF_UE_NGAP_ID_MAX);
        entries.push((ie::ID_AMF_UE_NGAP_ID, ie::CRITICALITY_REJECT, w.into_bytes()));
    }
    {
        let mut w = PerWriter::new();
        w.write_constrained_int(msg.ran_ue_ngap_id as u64, 0, ie::RAN_UE_NGAP_ID_MAX);
        entries.push((ie::ID_RAN_UE_NGAP_ID, ie::CRITICALITY_REJECT, w.into_bytes()));
    }
    {
        let mut w = PerWriter::new();
        w.write_octet_string(&msg.nas_pdu);
        entries.push((ie::ID_NAS_PDU, ie::CRITICALITY_REJECT, w.into_bytes()));
    }
    {
        let mut w = PerWriter::new();
        write_user_location_info(&mut w, &msg.nr_cgi, &msg.tai);
        entries.push((ie::ID_USER_LOCATION_INFO, ie::CRITICALITY_IGNORE, w.into_bytes()));
    }

    let mut value_w = PerWriter::new();
    write_ie_container(&mut value_w, &entries);

    encode_pdu_wrapper(PDU_CHOICE_INITIATING_MESSAGE, ie::PROC_UPLINK_NAS_TRANSPORT, ie::CRITICALITY_IGNORE, &value_w.into_bytes())
}

fn decode_uplink_nas_transport(entries: &[IeEntry]) -> Result<NgapMessage> {
    let mut amf_ue_ngap_id = None;
    let mut ran_ue_ngap_id = None;
    let mut nas_pdu = None;
    let mut location = None;

    for (id, _crit, val) in entries {
        let mut r = PerReader::new(val);
        match *id {
            x if x == ie::ID_AMF_UE_NGAP_ID => {
                amf_ue_ngap_id = r.read_constrained_int(0, ie::AMF_UE_NGAP_ID_MAX).map(|v| v as u32);
            }
            x if x == ie::ID_RAN_UE_NGAP_ID => {
                ran_ue_ngap_id = r.read_constrained_int(0, ie::RAN_UE_NGAP_ID_MAX).map(|v| v as u32);
            }
            x if x == ie::ID_NAS_PDU => {
                nas_pdu = r.read_octet_string();
            }
            x if x == ie::ID_USER_LOCATION_INFO => {
                location = read_user_location_info(&mut r);
            }
            _ => {}
        }
    }

    let (nr_cgi, tai) =
        location.ok_or(ProtoError::MalformedNgap { reason: "missing UserLocationInformation" })?;

    Ok(NgapMessage::UplinkNasTransport(NgapUplinkNasTransport {
        amf_ue_ngap_id: amf_ue_ngap_id
            .ok_or(ProtoError::MalformedNgap { reason: "missing AMF-UE-NGAP-ID" })?,
        ran_ue_ngap_id: ran_ue_ngap_id
            .ok_or(ProtoError::MalformedNgap { reason: "missing RAN-UE-NGAP-ID" })?,
        nas_pdu: Bytes::from(
            nas_pdu.ok_or(ProtoError::MalformedNgap { reason: "missing NAS-PDU" })?,
        ),
        tai,
        nr_cgi,
    }))
}

// ── DownlinkNasTransport ──────────────────────────────────────────────────────

pub fn encode_downlink_nas_transport(msg: &NgapDownlinkNasTransport) -> Bytes {
    let mut entries: Vec<IeEntry> = Vec::with_capacity(3);

    {
        let mut w = PerWriter::new();
        w.write_constrained_int(msg.amf_ue_ngap_id as u64, 0, ie::AMF_UE_NGAP_ID_MAX);
        entries.push((ie::ID_AMF_UE_NGAP_ID, ie::CRITICALITY_REJECT, w.into_bytes()));
    }
    {
        let mut w = PerWriter::new();
        w.write_constrained_int(msg.ran_ue_ngap_id as u64, 0, ie::RAN_UE_NGAP_ID_MAX);
        entries.push((ie::ID_RAN_UE_NGAP_ID, ie::CRITICALITY_REJECT, w.into_bytes()));
    }
    {
        let mut w = PerWriter::new();
        w.write_octet_string(&msg.nas_pdu);
        entries.push((ie::ID_NAS_PDU, ie::CRITICALITY_REJECT, w.into_bytes()));
    }

    let mut value_w = PerWriter::new();
    write_ie_container(&mut value_w, &entries);

    encode_pdu_wrapper(PDU_CHOICE_INITIATING_MESSAGE, ie::PROC_DOWNLINK_NAS_TRANSPORT, ie::CRITICALITY_IGNORE, &value_w.into_bytes())
}

fn decode_downlink_nas_transport(entries: &[IeEntry]) -> Result<NgapMessage> {
    let mut amf_ue_ngap_id = None;
    let mut ran_ue_ngap_id = None;
    let mut nas_pdu = None;

    for (id, _crit, val) in entries {
        let mut r = PerReader::new(val);
        match *id {
            x if x == ie::ID_AMF_UE_NGAP_ID => {
                amf_ue_ngap_id = r.read_constrained_int(0, ie::AMF_UE_NGAP_ID_MAX).map(|v| v as u32);
            }
            x if x == ie::ID_RAN_UE_NGAP_ID => {
                ran_ue_ngap_id = r.read_constrained_int(0, ie::RAN_UE_NGAP_ID_MAX).map(|v| v as u32);
            }
            x if x == ie::ID_NAS_PDU => {
                nas_pdu = r.read_octet_string();
            }
            _ => {}
        }
    }

    Ok(NgapMessage::DownlinkNasTransport(NgapDownlinkNasTransport {
        amf_ue_ngap_id: amf_ue_ngap_id
            .ok_or(ProtoError::MalformedNgap { reason: "missing AMF-UE-NGAP-ID" })?,
        ran_ue_ngap_id: ran_ue_ngap_id
            .ok_or(ProtoError::MalformedNgap { reason: "missing RAN-UE-NGAP-ID" })?,
        nas_pdu: Bytes::from(
            nas_pdu.ok_or(ProtoError::MalformedNgap { reason: "missing NAS-PDU" })?,
        ),
    }))
}

// ── InitialContextSetupRequest ────────────────────────────────────────────────

pub fn encode_initial_context_setup_request(msg: &NgapInitialContextSetupRequest) -> Bytes {
    let mut entries: Vec<IeEntry> = Vec::with_capacity(6);

    {
        let mut w = PerWriter::new();
        w.write_constrained_int(msg.amf_ue_ngap_id as u64, 0, ie::AMF_UE_NGAP_ID_MAX);
        entries.push((ie::ID_AMF_UE_NGAP_ID, ie::CRITICALITY_REJECT, w.into_bytes()));
    }
    {
        let mut w = PerWriter::new();
        w.write_constrained_int(msg.ran_ue_ngap_id as u64, 0, ie::RAN_UE_NGAP_ID_MAX);
        entries.push((ie::ID_RAN_UE_NGAP_ID, ie::CRITICALITY_REJECT, w.into_bytes()));
    }
    {
        let mut w = PerWriter::new();
        w.write_octets(&msg.security_key);
        entries.push((ie::ID_SECURITY_KEY, ie::CRITICALITY_REJECT, w.into_bytes()));
    }
    {
        let mut w = PerWriter::new();
        w.write_constrained_int(msg.ue_ambr.0, 0, ie::BIT_RATE_MAX);
        w.write_constrained_int(msg.ue_ambr.1, 0, ie::BIT_RATE_MAX);
        entries.push((ie::ID_UE_AGGREGATE_MAX_BIT_RATE, ie::CRITICALITY_IGNORE, w.into_bytes()));
    }
    if !msg.pdu_sessions.is_empty() {
        let mut w = PerWriter::new();
        write_pdu_sessions_to_setup(&mut w, &msg.pdu_sessions);
        entries.push((ie::ID_PDU_SESSION_RESOURCE_SETUP_LIST_CTXT_REQ, ie::CRITICALITY_REJECT, w.into_bytes()));
    }
    if let Some(nas_pdu) = &msg.nas_pdu {
        let mut w = PerWriter::new();
        w.write_octet_string(nas_pdu);
        entries.push((ie::ID_NAS_PDU, ie::CRITICALITY_REJECT, w.into_bytes()));
    }

    let mut value_w = PerWriter::new();
    write_ie_container(&mut value_w, &entries);

    encode_pdu_wrapper(
        PDU_CHOICE_INITIATING_MESSAGE,
        ie::PROC_INITIAL_CONTEXT_SETUP,
        ie::CRITICALITY_REJECT,
        &value_w.into_bytes(),
    )
}

fn decode_initial_context_setup_request(entries: &[IeEntry]) -> Result<NgapMessage> {
    let mut amf_ue_ngap_id = None;
    let mut ran_ue_ngap_id = None;
    let mut security_key = None;
    let mut ue_ambr = None;
    let mut pdu_sessions = Vec::new();
    let mut nas_pdu = None;

    for (id, _crit, val) in entries {
        let mut r = PerReader::new(val);
        match *id {
            x if x == ie::ID_AMF_UE_NGAP_ID => {
                amf_ue_ngap_id = r.read_constrained_int(0, ie::AMF_UE_NGAP_ID_MAX).map(|v| v as u32);
            }
            x if x == ie::ID_RAN_UE_NGAP_ID => {
                ran_ue_ngap_id = r.read_constrained_int(0, ie::RAN_UE_NGAP_ID_MAX).map(|v| v as u32);
            }
            x if x == ie::ID_SECURITY_KEY => {
                if let Some(v) = r.read_octets(32) {
                    let mut key = [0u8; 32];
                    key.copy_from_slice(&v);
                    security_key = Some(key);
                }
            }
            x if x == ie::ID_UE_AGGREGATE_MAX_BIT_RATE => {
                let dl = r.read_constrained_int(0, ie::BIT_RATE_MAX);
                let ul = r.read_constrained_int(0, ie::BIT_RATE_MAX);
                if let (Some(dl), Some(ul)) = (dl, ul) {
                    ue_ambr = Some((dl, ul));
                }
            }
            x if x == ie::ID_PDU_SESSION_RESOURCE_SETUP_LIST_CTXT_REQ => {
                if let Some(v) = read_pdu_sessions_to_setup(&mut r) {
                    pdu_sessions = v;
                }
            }
            x if x == ie::ID_NAS_PDU => {
                nas_pdu = r.read_octet_string();
            }
            _ => {}
        }
    }

    Ok(NgapMessage::InitialContextSetupRequest(NgapInitialContextSetupRequest {
        amf_ue_ngap_id: amf_ue_ngap_id
            .ok_or(ProtoError::MalformedNgap { reason: "missing AMF-UE-NGAP-ID" })?,
        ran_ue_ngap_id: ran_ue_ngap_id
            .ok_or(ProtoError::MalformedNgap { reason: "missing RAN-UE-NGAP-ID" })?,
        pdu_sessions,
        nas_pdu: nas_pdu.map(Bytes::from),
        ue_ambr: ue_ambr
            .ok_or(ProtoError::MalformedNgap { reason: "missing UEAggregateMaximumBitRate" })?,
        security_key: security_key
            .ok_or(ProtoError::MalformedNgap { reason: "missing SecurityKey" })?,
    }))
}

// ── InitialContextSetupResponse ───────────────────────────────────────────────

pub fn encode_initial_context_setup_response(msg: &NgapInitialContextSetupResponse) -> Bytes {
    let mut entries: Vec<IeEntry> = Vec::with_capacity(4);

    {
        let mut w = PerWriter::new();
        w.write_constrained_int(msg.amf_ue_ngap_id as u64, 0, ie::AMF_UE_NGAP_ID_MAX);
        entries.push((ie::ID_AMF_UE_NGAP_ID, ie::CRITICALITY_REJECT, w.into_bytes()));
    }
    {
        let mut w = PerWriter::new();
        w.write_constrained_int(msg.ran_ue_ngap_id as u64, 0, ie::RAN_UE_NGAP_ID_MAX);
        entries.push((ie::ID_RAN_UE_NGAP_ID, ie::CRITICALITY_REJECT, w.into_bytes()));
    }
    if !msg.pdu_sessions_setup.is_empty() {
        let mut w = PerWriter::new();
        write_pdu_sessions_setup(&mut w, &msg.pdu_sessions_setup);
        entries.push((ie::ID_PDU_SESSION_RESOURCE_SETUP_LIST_CTXT_RES, ie::CRITICALITY_IGNORE, w.into_bytes()));
    }
    if !msg.pdu_sessions_failed.is_empty() {
        let mut w = PerWriter::new();
        write_pdu_session_ids(&mut w, &msg.pdu_sessions_failed);
        entries.push((
            ie::ID_PDU_SESSION_RESOURCE_FAILED_TO_SETUP_LIST_CTXT_RES,
            ie::CRITICALITY_IGNORE,
            w.into_bytes(),
        ));
    }

    let mut value_w = PerWriter::new();
    write_ie_container(&mut value_w, &entries);

    encode_pdu_wrapper(
        PDU_CHOICE_SUCCESSFUL_OUTCOME,
        ie::PROC_INITIAL_CONTEXT_SETUP,
        ie::CRITICALITY_REJECT,
        &value_w.into_bytes(),
    )
}

fn decode_initial_context_setup_response(entries: &[IeEntry]) -> Result<NgapMessage> {
    let mut amf_ue_ngap_id = None;
    let mut ran_ue_ngap_id = None;
    let mut pdu_sessions_setup = Vec::new();
    let mut pdu_sessions_failed = Vec::new();

    for (id, _crit, val) in entries {
        let mut r = PerReader::new(val);
        match *id {
            x if x == ie::ID_AMF_UE_NGAP_ID => {
                amf_ue_ngap_id = r.read_constrained_int(0, ie::AMF_UE_NGAP_ID_MAX).map(|v| v as u32);
            }
            x if x == ie::ID_RAN_UE_NGAP_ID => {
                ran_ue_ngap_id = r.read_constrained_int(0, ie::RAN_UE_NGAP_ID_MAX).map(|v| v as u32);
            }
            x if x == ie::ID_PDU_SESSION_RESOURCE_SETUP_LIST_CTXT_RES => {
                if let Some(v) = read_pdu_sessions_setup(&mut r) {
                    pdu_sessions_setup = v;
                }
            }
            x if x == ie::ID_PDU_SESSION_RESOURCE_FAILED_TO_SETUP_LIST_CTXT_RES => {
                if let Some(v) = read_pdu_session_ids(&mut r) {
                    pdu_sessions_failed = v;
                }
            }
            _ => {}
        }
    }

    Ok(NgapMessage::InitialContextSetupResponse(NgapInitialContextSetupResponse {
        amf_ue_ngap_id: amf_ue_ngap_id
            .ok_or(ProtoError::MalformedNgap { reason: "missing AMF-UE-NGAP-ID" })?,
        ran_ue_ngap_id: ran_ue_ngap_id
            .ok_or(ProtoError::MalformedNgap { reason: "missing RAN-UE-NGAP-ID" })?,
        pdu_sessions_setup,
        pdu_sessions_failed,
    }))
}

// ── UeContextReleaseCommand / Complete ─────────────────────────────────────────
// Class-1 (id-UEContextRelease, ProcedureCode=41), same PDU-choice threading
// as InitialContextSetupRequest/Response above. No new struct fields needed
// — `NgapMessage::UeContextReleaseCommand { cause }` and
// `NgapUeContextReleaseComplete { amf_ue_ngap_id, ran_ue_ngap_id }` already
// carry everything this codec encodes. One real simplification worth
// stating plainly: this simulation only ever has one UE per real socket
// (see `midn-sim`), so UeContextReleaseCommand's lack of a UE-ID IE isn't a
// correctness gap for that use case — real NGAP disambiguates which UE via
// `UE-NGAP-IDs` (a CHOICE of UE-NGAP-ID-pair / AMF-UE-NGAP-ID) that isn't
// modeled here. A multi-UE simulation would need that IE added; this one
// doesn't yet need it enough to justify the extra CHOICE-decoding
// complexity.

pub fn encode_ue_context_release_command(cause: NgapCause) -> Bytes {
    let mut entries: Vec<IeEntry> = Vec::with_capacity(1);
    {
        let mut w = PerWriter::new();
        w.write_constrained_int(ngap_cause_to_u64(cause), 0, ie::CAUSE_MAX);
        entries.push((ie::ID_CAUSE, ie::CRITICALITY_IGNORE, w.into_bytes()));
    }

    let mut value_w = PerWriter::new();
    write_ie_container(&mut value_w, &entries);

    encode_pdu_wrapper(
        PDU_CHOICE_INITIATING_MESSAGE, ie::PROC_UE_CONTEXT_RELEASE, ie::CRITICALITY_IGNORE,
        &value_w.into_bytes(),
    )
}

fn decode_ue_context_release_command(entries: &[IeEntry]) -> Result<NgapMessage> {
    let mut cause = None;
    for (id, _crit, val) in entries {
        if *id == ie::ID_CAUSE {
            let mut r = PerReader::new(val);
            cause = r.read_constrained_int(0, ie::CAUSE_MAX).and_then(ngap_cause_from_u64);
        }
    }
    Ok(NgapMessage::UeContextReleaseCommand {
        cause: cause.ok_or(ProtoError::MalformedNgap { reason: "missing or invalid Cause" })?,
    })
}

pub fn encode_ue_context_release_complete(msg: &NgapUeContextReleaseComplete) -> Bytes {
    let mut entries: Vec<IeEntry> = Vec::with_capacity(2);
    {
        let mut w = PerWriter::new();
        w.write_constrained_int(msg.amf_ue_ngap_id as u64, 0, ie::AMF_UE_NGAP_ID_MAX);
        entries.push((ie::ID_AMF_UE_NGAP_ID, ie::CRITICALITY_IGNORE, w.into_bytes()));
    }
    {
        let mut w = PerWriter::new();
        w.write_constrained_int(msg.ran_ue_ngap_id as u64, 0, ie::RAN_UE_NGAP_ID_MAX);
        entries.push((ie::ID_RAN_UE_NGAP_ID, ie::CRITICALITY_IGNORE, w.into_bytes()));
    }

    let mut value_w = PerWriter::new();
    write_ie_container(&mut value_w, &entries);

    encode_pdu_wrapper(
        PDU_CHOICE_SUCCESSFUL_OUTCOME, ie::PROC_UE_CONTEXT_RELEASE, ie::CRITICALITY_IGNORE,
        &value_w.into_bytes(),
    )
}

fn decode_ue_context_release_complete(entries: &[IeEntry]) -> Result<NgapMessage> {
    let mut amf_ue_ngap_id = None;
    let mut ran_ue_ngap_id = None;

    for (id, _crit, val) in entries {
        let mut r = PerReader::new(val);
        match *id {
            x if x == ie::ID_AMF_UE_NGAP_ID => {
                amf_ue_ngap_id = r.read_constrained_int(0, ie::AMF_UE_NGAP_ID_MAX).map(|v| v as u32);
            }
            x if x == ie::ID_RAN_UE_NGAP_ID => {
                ran_ue_ngap_id = r.read_constrained_int(0, ie::RAN_UE_NGAP_ID_MAX).map(|v| v as u32);
            }
            _ => {}
        }
    }

    Ok(NgapMessage::UeContextReleaseComplete(NgapUeContextReleaseComplete {
        amf_ue_ngap_id: amf_ue_ngap_id
            .ok_or(ProtoError::MalformedNgap { reason: "missing AMF-UE-NGAP-ID" })?,
        ran_ue_ngap_id: ran_ue_ngap_id
            .ok_or(ProtoError::MalformedNgap { reason: "missing RAN-UE-NGAP-ID" })?,
    }))
}

// ── Top-level dispatch ────────────────────────────────────────────────────────

/// Encode an `NgapMessage` to its ALIGNED PER wire bytes.
///
/// Returns `MalformedNgap` for any variant outside this increment's scope
/// (see module docs) rather than silently producing incorrect bytes.
pub fn encode_ngap_pdu(msg: &NgapMessage) -> Result<Bytes> {
    match msg {
        NgapMessage::InitialUeMessage(m) => Ok(encode_initial_ue_message(m)),
        NgapMessage::UplinkNasTransport(m) => Ok(encode_uplink_nas_transport(m)),
        NgapMessage::DownlinkNasTransport(m) => Ok(encode_downlink_nas_transport(m)),
        NgapMessage::InitialContextSetupRequest(m) => Ok(encode_initial_context_setup_request(m)),
        NgapMessage::InitialContextSetupResponse(m) => Ok(encode_initial_context_setup_response(m)),
        NgapMessage::UeContextReleaseCommand { cause } => Ok(encode_ue_context_release_command(*cause)),
        NgapMessage::UeContextReleaseComplete(m) => Ok(encode_ue_context_release_complete(m)),
        _ => Err(ProtoError::MalformedNgap {
            reason: "PER encoding not yet implemented for this NGAP message — \
                     only InitialUEMessage/Uplink/DownlinkNASTransport/ \
                     InitialContextSetupRequest/Response/UeContextReleaseCommand/Complete",
        }),
    }
}

/// Decode raw ALIGNED PER bytes into an `NgapMessage`.
pub fn decode_ngap_pdu(buf: &[u8]) -> Result<NgapMessage> {
    let (choice, proc_code, _crit, value) = decode_pdu_wrapper(buf)
        .ok_or(ProtoError::MalformedNgap { reason: "failed to decode PDU wrapper" })?;

    let mut vr = PerReader::new(&value);
    let entries = read_ie_container(&mut vr)
        .ok_or(ProtoError::MalformedNgap { reason: "failed to decode IE container" })?;

    match proc_code {
        x if x == ie::PROC_INITIAL_UE_MESSAGE => decode_initial_ue_message(&entries),
        x if x == ie::PROC_UPLINK_NAS_TRANSPORT => decode_uplink_nas_transport(&entries),
        x if x == ie::PROC_DOWNLINK_NAS_TRANSPORT => decode_downlink_nas_transport(&entries),
        x if x == ie::PROC_INITIAL_CONTEXT_SETUP && choice == PDU_CHOICE_INITIATING_MESSAGE => {
            decode_initial_context_setup_request(&entries)
        }
        x if x == ie::PROC_INITIAL_CONTEXT_SETUP && choice == PDU_CHOICE_SUCCESSFUL_OUTCOME => {
            decode_initial_context_setup_response(&entries)
        }
        x if x == ie::PROC_UE_CONTEXT_RELEASE && choice == PDU_CHOICE_INITIATING_MESSAGE => {
            decode_ue_context_release_command(&entries)
        }
        x if x == ie::PROC_UE_CONTEXT_RELEASE && choice == PDU_CHOICE_SUCCESSFUL_OUTCOME => {
            decode_ue_context_release_complete(&entries)
        }
        _ => Err(ProtoError::MalformedNgap {
            reason: "unsupported procedure code (or PDU choice) — only InitialUEMessage/Uplink/ \
                     DownlinkNASTransport/InitialContextSetupRequest/Response/ \
                     UeContextReleaseCommand/Complete",
        }),
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn initial_ue_message_round_trip() {
        let msg = NgapInitialUeMessage {
            ran_ue_ngap_id: 0x0001_0001,
            nas_pdu: Bytes::from_static(&[0x7E, 0x00, 0x41]),
            tai: [0x00, 0x01, 0x02, 0x00, 0x00, 0x01],
            nr_cgi: [0x00, 0x01, 0x02, 0x10, 0x20, 0x30, 0x40, 0x50, 0x60],
            rrc_establishment_cause: 3,
        };

        let bytes = encode_ngap_pdu(&NgapMessage::InitialUeMessage(msg.clone())).unwrap();
        let decoded = decode_ngap_pdu(&bytes).unwrap();

        match decoded {
            NgapMessage::InitialUeMessage(d) => {
                assert_eq!(d.ran_ue_ngap_id, msg.ran_ue_ngap_id);
                assert_eq!(d.nas_pdu, msg.nas_pdu);
                assert_eq!(d.tai, msg.tai);
                assert_eq!(d.nr_cgi, msg.nr_cgi);
                assert_eq!(d.rrc_establishment_cause, msg.rrc_establishment_cause);
            }
            other => panic!("wrong variant decoded: {other:?}"),
        }
    }

    #[test]
    fn uplink_nas_transport_round_trip() {
        let msg = NgapUplinkNasTransport {
            amf_ue_ngap_id: 0xCAFEBABE,
            ran_ue_ngap_id: 0x0001_0002,
            nas_pdu: Bytes::from_static(&[0x7E, 0x02, 0x08, 0xA5, 0x42, 0x11, 0xD5, 0xE3, 0xBA, 0x50, 0xBF]),
            tai: [1, 2, 3, 0, 0, 4],
            nr_cgi: [9, 8, 7, 6, 5, 4, 3, 2, 1],
        };

        let bytes = encode_ngap_pdu(&NgapMessage::UplinkNasTransport(msg.clone())).unwrap();
        let decoded = decode_ngap_pdu(&bytes).unwrap();

        match decoded {
            NgapMessage::UplinkNasTransport(d) => {
                assert_eq!(d.amf_ue_ngap_id, msg.amf_ue_ngap_id);
                assert_eq!(d.ran_ue_ngap_id, msg.ran_ue_ngap_id);
                assert_eq!(d.nas_pdu, msg.nas_pdu);
                assert_eq!(d.tai, msg.tai);
                assert_eq!(d.nr_cgi, msg.nr_cgi);
            }
            other => panic!("wrong variant decoded: {other:?}"),
        }
    }

    #[test]
    fn downlink_nas_transport_round_trip() {
        let msg = NgapDownlinkNasTransport {
            amf_ue_ngap_id: 42,
            ran_ue_ngap_id: 7,
            nas_pdu: Bytes::from_static(&[0x7E, 0x00, 0x42, 0x01]),
        };

        let bytes = encode_ngap_pdu(&NgapMessage::DownlinkNasTransport(msg.clone())).unwrap();
        let decoded = decode_ngap_pdu(&bytes).unwrap();

        match decoded {
            NgapMessage::DownlinkNasTransport(d) => {
                assert_eq!(d.amf_ue_ngap_id, msg.amf_ue_ngap_id);
                assert_eq!(d.ran_ue_ngap_id, msg.ran_ue_ngap_id);
                assert_eq!(d.nas_pdu, msg.nas_pdu);
            }
            other => panic!("wrong variant decoded: {other:?}"),
        }
    }

    #[test]
    fn initial_context_setup_request_round_trip() {
        let msg = NgapInitialContextSetupRequest {
            amf_ue_ngap_id: 0xCAFEBABE,
            ran_ue_ngap_id: 7,
            pdu_sessions: vec![PduSessionToSetup {
                pdu_session_id: 1,
                qfi: 9,
                gtp_teid: [0x00, 0x02, 0x00, 0x01],
                transport_layer_addr: [10, 0, 0, 1],
            }],
            nas_pdu: Some(Bytes::from_static(&[0x7E, 0x02, 0x42, 0x01])),
            ue_ambr: (50_000_000, 50_000_000),
            security_key: [0xAB; 32],
        };

        let bytes = encode_ngap_pdu(&NgapMessage::InitialContextSetupRequest(msg.clone())).unwrap();
        let decoded = decode_ngap_pdu(&bytes).unwrap();

        match decoded {
            NgapMessage::InitialContextSetupRequest(d) => {
                assert_eq!(d.amf_ue_ngap_id, msg.amf_ue_ngap_id);
                assert_eq!(d.ran_ue_ngap_id, msg.ran_ue_ngap_id);
                assert_eq!(d.pdu_sessions.len(), 1);
                assert_eq!(d.pdu_sessions[0].pdu_session_id, msg.pdu_sessions[0].pdu_session_id);
                assert_eq!(d.pdu_sessions[0].qfi, msg.pdu_sessions[0].qfi);
                assert_eq!(d.pdu_sessions[0].gtp_teid, msg.pdu_sessions[0].gtp_teid);
                assert_eq!(d.pdu_sessions[0].transport_layer_addr, msg.pdu_sessions[0].transport_layer_addr);
                assert_eq!(d.nas_pdu, msg.nas_pdu);
                assert_eq!(d.ue_ambr, msg.ue_ambr);
                assert_eq!(d.security_key, msg.security_key);
            }
            other => panic!("wrong variant decoded: {other:?}"),
        }
    }

    #[test]
    fn initial_context_setup_request_round_trip_no_pdu_session_no_nas_pdu() {
        // Both `pdu_sessions` and `nas_pdu` are optional in practice
        // (Phase A never bundles either) — confirms the `if !...is_empty()`/
        // `if let Some(...)` guards correctly omit the IE entirely rather
        // than writing a degenerate empty one.
        let msg = NgapInitialContextSetupRequest {
            amf_ue_ngap_id: 1,
            ran_ue_ngap_id: 2,
            pdu_sessions: vec![],
            nas_pdu: None,
            ue_ambr: (1, 1),
            security_key: [0u8; 32],
        };

        let bytes = encode_ngap_pdu(&NgapMessage::InitialContextSetupRequest(msg.clone())).unwrap();
        let decoded = decode_ngap_pdu(&bytes).unwrap();

        match decoded {
            NgapMessage::InitialContextSetupRequest(d) => {
                assert!(d.pdu_sessions.is_empty());
                assert!(d.nas_pdu.is_none());
            }
            other => panic!("wrong variant decoded: {other:?}"),
        }
    }

    #[test]
    fn initial_context_setup_response_round_trip() {
        let msg = NgapInitialContextSetupResponse {
            amf_ue_ngap_id: 42,
            ran_ue_ngap_id: 7,
            pdu_sessions_setup: vec![PduSessionSetupItem {
                pdu_session_id: 1,
                transport_layer_addr: [172, 16, 0, 5],
                gtp_teid: [0xAA, 0xBB, 0xCC, 0xDD],
            }],
            pdu_sessions_failed: vec![2, 3],
        };

        let bytes = encode_ngap_pdu(&NgapMessage::InitialContextSetupResponse(msg.clone())).unwrap();
        let decoded = decode_ngap_pdu(&bytes).unwrap();

        match decoded {
            NgapMessage::InitialContextSetupResponse(d) => {
                assert_eq!(d.amf_ue_ngap_id, msg.amf_ue_ngap_id);
                assert_eq!(d.ran_ue_ngap_id, msg.ran_ue_ngap_id);
                assert_eq!(d.pdu_sessions_setup.len(), 1);
                assert_eq!(d.pdu_sessions_setup[0].pdu_session_id, msg.pdu_sessions_setup[0].pdu_session_id);
                assert_eq!(d.pdu_sessions_setup[0].transport_layer_addr, msg.pdu_sessions_setup[0].transport_layer_addr);
                assert_eq!(d.pdu_sessions_setup[0].gtp_teid, msg.pdu_sessions_setup[0].gtp_teid);
                assert_eq!(d.pdu_sessions_failed, msg.pdu_sessions_failed);
            }
            other => panic!("wrong variant decoded: {other:?}"),
        }
    }

    #[test]
    fn initial_context_setup_request_and_response_share_procedure_code_but_not_choice() {
        // The actual thing this increment's architecture change was for:
        // both PDUs carry ie::PROC_INITIAL_CONTEXT_SETUP, and decode must
        // tell them apart by PDU choice, not procedure code. Direct
        // regression test for that, independent of the full round-trip
        // tests above.
        let req = NgapInitialContextSetupRequest {
            amf_ue_ngap_id: 1, ran_ue_ngap_id: 1, pdu_sessions: vec![],
            nas_pdu: None, ue_ambr: (1, 1), security_key: [0u8; 32],
        };
        let resp = NgapInitialContextSetupResponse {
            amf_ue_ngap_id: 1, ran_ue_ngap_id: 1,
            pdu_sessions_setup: vec![], pdu_sessions_failed: vec![],
        };

        let req_bytes = encode_ngap_pdu(&NgapMessage::InitialContextSetupRequest(req)).unwrap();
        let resp_bytes = encode_ngap_pdu(&NgapMessage::InitialContextSetupResponse(resp)).unwrap();

        assert!(matches!(decode_ngap_pdu(&req_bytes).unwrap(), NgapMessage::InitialContextSetupRequest(_)));
        assert!(matches!(decode_ngap_pdu(&resp_bytes).unwrap(), NgapMessage::InitialContextSetupResponse(_)));
    }

    #[test]
    fn ue_context_release_command_round_trip() {
        for cause in [
            NgapCause::RadioNetworkUnspecified,
            NgapCause::TransportUnspecified,
            NgapCause::NasNormalRelease,
            NgapCause::NasDeregister,
            NgapCause::NasAuthFailure,
            NgapCause::ProtocolUnspecified,
            NgapCause::MiscUnspecified,
        ] {
            let bytes = encode_ngap_pdu(&NgapMessage::UeContextReleaseCommand { cause }).unwrap();
            match decode_ngap_pdu(&bytes).unwrap() {
                NgapMessage::UeContextReleaseCommand { cause: d } => assert_eq!(d, cause),
                other => panic!("wrong variant decoded: {other:?}"),
            }
        }
    }

    #[test]
    fn ue_context_release_complete_round_trip() {
        let msg = NgapUeContextReleaseComplete { amf_ue_ngap_id: 0xCAFEBABE, ran_ue_ngap_id: 7 };
        let bytes = encode_ngap_pdu(&NgapMessage::UeContextReleaseComplete(msg.clone())).unwrap();
        match decode_ngap_pdu(&bytes).unwrap() {
            NgapMessage::UeContextReleaseComplete(d) => {
                assert_eq!(d.amf_ue_ngap_id, msg.amf_ue_ngap_id);
                assert_eq!(d.ran_ue_ngap_id, msg.ran_ue_ngap_id);
            }
            other => panic!("wrong variant decoded: {other:?}"),
        }
    }

    #[test]
    fn ue_context_release_command_and_complete_share_procedure_code_but_not_choice() {
        let cmd = NgapMessage::UeContextReleaseCommand { cause: NgapCause::NasDeregister };
        let complete = NgapMessage::UeContextReleaseComplete(NgapUeContextReleaseComplete {
            amf_ue_ngap_id: 1, ran_ue_ngap_id: 1,
        });

        let cmd_bytes = encode_ngap_pdu(&cmd).unwrap();
        let complete_bytes = encode_ngap_pdu(&complete).unwrap();

        let (cmd_choice, cmd_proc, ..) = decode_pdu_wrapper(&cmd_bytes).unwrap();
        let (complete_choice, complete_proc, ..) = decode_pdu_wrapper(&complete_bytes).unwrap();

        assert_eq!(cmd_proc, ie::PROC_UE_CONTEXT_RELEASE);
        assert_eq!(complete_proc, ie::PROC_UE_CONTEXT_RELEASE);
        assert_ne!(cmd_choice, complete_choice, "Command/Complete must differ in PDU choice, not procedure code");

        assert!(matches!(decode_ngap_pdu(&cmd_bytes).unwrap(), NgapMessage::UeContextReleaseCommand { .. }));
        assert!(matches!(decode_ngap_pdu(&complete_bytes).unwrap(), NgapMessage::UeContextReleaseComplete(_)));
    }

    #[test]
    fn unsupported_variant_returns_error_not_garbage() {
        // NgSetupRequest/Response remain genuinely out of scope — unlike
        // UeContextReleaseCommand, which this test used to check here before
        // gaining real codec support this session.
        let result = encode_ngap_pdu(&NgapMessage::NgSetupRequest);
        assert!(result.is_err(), "out-of-scope variants must error, not silently mis-encode");
    }

    #[test]
    fn decode_rejects_truncated_buffer() {
        assert!(decode_ngap_pdu(&[0x00]).is_err());
    }

    #[test]
    fn decode_rejects_unknown_procedure_code() {
        let mut value_w = PerWriter::new();
        write_ie_container(&mut value_w, &[]);
        let bytes = encode_pdu_wrapper(PDU_CHOICE_INITIATING_MESSAGE, 250, ie::CRITICALITY_IGNORE, &value_w.into_bytes());
        assert!(decode_ngap_pdu(&bytes).is_err());
    }

    #[test]
    fn user_location_info_round_trip() {
        let mut w = PerWriter::new();
        let nr_cgi = [1u8, 2, 3, 4, 5, 6, 7, 8, 9];
        let tai = [10u8, 11, 12, 13, 14, 15];
        write_user_location_info(&mut w, &nr_cgi, &tai);
        let bytes = w.into_bytes();
        let mut r = PerReader::new(&bytes);
        let (d_cgi, d_tai) = read_user_location_info(&mut r).unwrap();
        assert_eq!(d_cgi, nr_cgi);
        assert_eq!(d_tai, tai);
    }
                                             }
