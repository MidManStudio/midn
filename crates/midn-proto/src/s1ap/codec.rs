// crates/midn-proto/src/s1ap/codec.rs
//! S1AP-PDU PER encoder/decoder — built on `per.rs` + `ie_ids.rs`.
//!
//! ## Scope
//!
//! Covers the three messages that drive the MME state machine
//! (`InitialUeMessage`, `UplinkNasTransport`, `DownlinkNasTransport`) plus
//! `InitialContextSetupRequest`/`Response` — the LTE counterpart of
//! `ngap::codec`'s own ICSR/Response support, added the same way and hitting
//! the same two real architectural issues that increment did:
//!
//! 1. **PDU choice threading.** `id-InitialContextSetup` is a Class-1
//!    procedure (has a response) — Request and Response share ONE
//!    ProcedureCode (9), disambiguated by the PDU choice
//!    (`initiatingMessage`=0 / `successfulOutcome`=1), NOT by distinct
//!    procedure codes the way the three Class-2 (request-only) messages
//!    this codec started with do. `encode_pdu_wrapper`/`decode_pdu_wrapper`
//!    used to hardcode `initiatingMessage` and discard the choice value on
//!    decode (`let _choice = ...`) because nothing needed it. Both now take
//!    / return the real choice.
//! 2. **Bit alignment.** `write_erabs_to_setup`/`write_erabs_setup` each
//!    write a sub-byte constrained-int field (E-RAB-ID is 4 bits) right
//!    before raw octet fields — `write_octets` doesn't align itself
//!    (unlike `read_octets`, which always does), so an explicit `align()`
//!    is required at each of those call sites. This is the exact bug class
//!    that broke `ngap::codec`'s own PDU-session encoding (CI build #252) —
//!    caught proactively here rather than shipping it a second time.
//!
//! `UeContextRelease*`, `S1Setup*` remain NOT implemented — `encode_s1ap_pdu`
//! returns a `MalformedS1ap` error for those variants rather than silently
//! producing wrong bytes. Same phased pattern as everywhere else in this
//! codebase (NAS codec grew the same way: Attach → Auth → SecMode → Detach →
//! security, one increment at a time).
//!
//! ## Wire shape
//!
//! Real S1AP is NOT "PER-encode the Rust struct directly" — it's an
//! IE-container format:
//!
//! ```text
//! S1AP-PDU ::= CHOICE { initiatingMessage, successfulOutcome, unsuccessfulOutcome }
//!   each one ::= SEQUENCE { procedureCode INTEGER(0..255),
//!                           criticality   Criticality,
//!                           value         OPEN TYPE }
//!   value    ::= SEQUENCE { protocolIEs ProtocolIE-Container }
//!   ProtocolIE-Container ::= SEQUENCE (SIZE(1..maxProtocolIEs)) OF ProtocolIE-Field
//!   ProtocolIE-Field ::= SEQUENCE { id ProtocolIE-ID, criticality Criticality, value OPEN TYPE }
//! ```
//!
//! This codec implements that shape. One simplification: the real spec's
//! `SIZE(1..maxProtocolIEs)` constraint on the IE count would, under strict
//! ALIGNED PER, encode as a fixed-width octet-aligned constrained int (since
//! maxProtocolIEs is a large explicit bound). We instead use the generic
//! `write_length_determinant`/`read_length_determinant` for the count — it's
//! internally consistent (round-trips correctly against itself, see tests
//! below) but may not byte-match a real eNodeB's encoding of the count field
//! specifically. If you're diffing against a real capture and everything
//! else matches except the IE count framing, this is the first place to look.
//!
//! E-RAB list encoding (both directions) is a deliberate flat/simplified
//! structure — real S1AP nests a much richer transfer-IE structure this
//! codebase's structs don't have fields for anyway; documented, not silently
//! glossed over. Same simplification `ngap::codec`'s PDU-session lists
//! already make for 5G.

use bytes::Bytes;

use crate::error::{ProtoError, Result};
use crate::s1ap::ie_ids as ie;
use crate::s1ap::messages::{
    DownlinkNasTransport, ErabSetupItem, ErabToSetup, InitialContextSetupRequest,
    InitialContextSetupResponse, InitialUeMessage, S1apMessage, UplinkNasTransport,
};
use crate::per::{PerReader, PerWriter};

const PDU_CHOICE_INITIATING_MESSAGE: u64 = 0;
const PDU_CHOICE_SUCCESSFUL_OUTCOME: u64 = 1;
// unsuccessfulOutcome = 2 — no message this codec emits uses it yet
// (InitialContextSetupFailure isn't implemented, same as UeContextRelease*).

type IeEntry = (u32, u8, Vec<u8>);

// ── IE-container framing ──────────────────────────────────────────────────────

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

/// Returns `(choice, procedure_code, criticality, value_bytes)`. `choice`
/// now actually matters — see module docs on why Class-1 procedures like
/// `id-InitialContextSetup` need it to disambiguate Request from Response.
fn decode_pdu_wrapper(buf: &[u8]) -> Option<(u64, u32, u8, Vec<u8>)> {
    let mut r = PerReader::new(buf);
    let choice = r.read_constrained_int(0, 2)?;
    let proc = r.read_constrained_int(0, ie::PROCEDURE_CODE_MAX)? as u32;
    let crit = r.read_constrained_int(0, 2)? as u8;
    let val = r.read_octet_string()?;
    Some((choice, proc, crit, val))
}

// ── InitialUeMessage ──────────────────────────────────────────────────────────

pub fn encode_initial_ue_message(msg: &InitialUeMessage) -> Bytes {
    let mut entries: Vec<IeEntry> = Vec::with_capacity(5);

    {
        let mut w = PerWriter::new();
        w.write_constrained_int(msg.enb_ue_s1ap_id as u64, 0, ie::ENB_UE_S1AP_ID_MAX);
        entries.push((ie::ID_ENB_UE_S1AP_ID, ie::CRITICALITY_REJECT, w.into_bytes()));
    }
    {
        let mut w = PerWriter::new();
        w.write_octet_string(&msg.nas_pdu);
        entries.push((ie::ID_NAS_PDU, ie::CRITICALITY_REJECT, w.into_bytes()));
    }
    {
        let mut w = PerWriter::new();
        w.write_octets(&msg.tai); // fixed-size, no length prefix needed
        entries.push((ie::ID_TAI, ie::CRITICALITY_IGNORE, w.into_bytes()));
    }
    {
        let mut w = PerWriter::new();
        w.write_octets(&msg.eutran_cgi);
        entries.push((ie::ID_EUTRAN_CGI, ie::CRITICALITY_IGNORE, w.into_bytes()));
    }
    {
        let mut w = PerWriter::new();
        w.write_constrained_int(msg.rrc_cause as u64, 0, ie::RRC_ESTABLISHMENT_CAUSE_MAX);
        entries.push((ie::ID_RRC_ESTABLISHMENT_CAUSE, ie::CRITICALITY_IGNORE, w.into_bytes()));
    }

    let mut value_w = PerWriter::new();
    write_ie_container(&mut value_w, &entries);

    encode_pdu_wrapper(PDU_CHOICE_INITIATING_MESSAGE, ie::PROC_INITIAL_UE_MESSAGE, ie::CRITICALITY_IGNORE, &value_w.into_bytes())
}

fn decode_initial_ue_message(entries: &[IeEntry]) -> Result<S1apMessage> {
    let mut enb_ue_s1ap_id = None;
    let mut nas_pdu = None;
    let mut tai = None;
    let mut eutran_cgi = None;
    let mut rrc_cause = None;

    for (id, _crit, val) in entries {
        let mut r = PerReader::new(val);
        match *id {
            x if x == ie::ID_ENB_UE_S1AP_ID => {
                enb_ue_s1ap_id = r.read_constrained_int(0, ie::ENB_UE_S1AP_ID_MAX).map(|v| v as u32);
            }
            x if x == ie::ID_NAS_PDU => {
                nas_pdu = r.read_octet_string();
            }
            x if x == ie::ID_TAI => {
                tai = r.read_octets(5).map(|v| {
                    let mut a = [0u8; 5];
                    a.copy_from_slice(&v);
                    a
                });
            }
            x if x == ie::ID_EUTRAN_CGI => {
                eutran_cgi = r.read_octets(7).map(|v| {
                    let mut a = [0u8; 7];
                    a.copy_from_slice(&v);
                    a
                });
            }
            x if x == ie::ID_RRC_ESTABLISHMENT_CAUSE => {
                rrc_cause = r
                    .read_constrained_int(0, ie::RRC_ESTABLISHMENT_CAUSE_MAX)
                    .map(|v| v as u8);
            }
            _ => {} // unknown IE — ignore, consistent with Criticality::ignore semantics
        }
    }

    Ok(S1apMessage::InitialUeMessage(InitialUeMessage {
        enb_ue_s1ap_id: enb_ue_s1ap_id
            .ok_or(ProtoError::MalformedS1ap { reason: "missing eNB-UE-S1AP-ID" })?,
        nas_pdu: Bytes::from(
            nas_pdu.ok_or(ProtoError::MalformedS1ap { reason: "missing NAS-PDU" })?,
        ),
        tai: tai.ok_or(ProtoError::MalformedS1ap { reason: "missing TAI" })?,
        eutran_cgi: eutran_cgi.ok_or(ProtoError::MalformedS1ap { reason: "missing E-UTRAN CGI" })?,
        rrc_cause: rrc_cause
            .ok_or(ProtoError::MalformedS1ap { reason: "missing RRC-Establishment-Cause" })?,
    }))
}

// ── UplinkNasTransport ────────────────────────────────────────────────────────

pub fn encode_uplink_nas_transport(msg: &UplinkNasTransport) -> Bytes {
    let mut entries: Vec<IeEntry> = Vec::with_capacity(5);

    {
        let mut w = PerWriter::new();
        w.write_constrained_int(msg.mme_ue_s1ap_id as u64, 0, ie::MME_UE_S1AP_ID_MAX);
        entries.push((ie::ID_MME_UE_S1AP_ID, ie::CRITICALITY_REJECT, w.into_bytes()));
    }
    {
        let mut w = PerWriter::new();
        w.write_constrained_int(msg.enb_ue_s1ap_id as u64, 0, ie::ENB_UE_S1AP_ID_MAX);
        entries.push((ie::ID_ENB_UE_S1AP_ID, ie::CRITICALITY_REJECT, w.into_bytes()));
    }
    {
        let mut w = PerWriter::new();
        w.write_octet_string(&msg.nas_pdu);
        entries.push((ie::ID_NAS_PDU, ie::CRITICALITY_REJECT, w.into_bytes()));
    }
    {
        let mut w = PerWriter::new();
        w.write_octets(&msg.tai);
        entries.push((ie::ID_TAI, ie::CRITICALITY_IGNORE, w.into_bytes()));
    }
    {
        let mut w = PerWriter::new();
        w.write_octets(&msg.eutran_cgi);
        entries.push((ie::ID_EUTRAN_CGI, ie::CRITICALITY_IGNORE, w.into_bytes()));
    }

    let mut value_w = PerWriter::new();
    write_ie_container(&mut value_w, &entries);

    encode_pdu_wrapper(PDU_CHOICE_INITIATING_MESSAGE, ie::PROC_UPLINK_NAS_TRANSPORT, ie::CRITICALITY_IGNORE, &value_w.into_bytes())
}

fn decode_uplink_nas_transport(entries: &[IeEntry]) -> Result<S1apMessage> {
    let mut mme_ue_s1ap_id = None;
    let mut enb_ue_s1ap_id = None;
    let mut nas_pdu = None;
    let mut tai = None;
    let mut eutran_cgi = None;

    for (id, _crit, val) in entries {
        let mut r = PerReader::new(val);
        match *id {
            x if x == ie::ID_MME_UE_S1AP_ID => {
                mme_ue_s1ap_id = r.read_constrained_int(0, ie::MME_UE_S1AP_ID_MAX).map(|v| v as u32);
            }
            x if x == ie::ID_ENB_UE_S1AP_ID => {
                enb_ue_s1ap_id = r.read_constrained_int(0, ie::ENB_UE_S1AP_ID_MAX).map(|v| v as u32);
            }
            x if x == ie::ID_NAS_PDU => {
                nas_pdu = r.read_octet_string();
            }
            x if x == ie::ID_TAI => {
                tai = r.read_octets(5).map(|v| {
                    let mut a = [0u8; 5];
                    a.copy_from_slice(&v);
                    a
                });
            }
            x if x == ie::ID_EUTRAN_CGI => {
                eutran_cgi = r.read_octets(7).map(|v| {
                    let mut a = [0u8; 7];
                    a.copy_from_slice(&v);
                    a
                });
            }
            _ => {}
        }
    }

    Ok(S1apMessage::UplinkNasTransport(UplinkNasTransport {
        mme_ue_s1ap_id: mme_ue_s1ap_id
            .ok_or(ProtoError::MalformedS1ap { reason: "missing MME-UE-S1AP-ID" })?,
        enb_ue_s1ap_id: enb_ue_s1ap_id
            .ok_or(ProtoError::MalformedS1ap { reason: "missing eNB-UE-S1AP-ID" })?,
        nas_pdu: Bytes::from(
            nas_pdu.ok_or(ProtoError::MalformedS1ap { reason: "missing NAS-PDU" })?,
        ),
        tai: tai.ok_or(ProtoError::MalformedS1ap { reason: "missing TAI" })?,
        eutran_cgi: eutran_cgi.ok_or(ProtoError::MalformedS1ap { reason: "missing E-UTRAN CGI" })?,
    }))
}

// ── DownlinkNasTransport ──────────────────────────────────────────────────────

pub fn encode_downlink_nas_transport(msg: &DownlinkNasTransport) -> Bytes {
    let mut entries: Vec<IeEntry> = Vec::with_capacity(3);

    {
        let mut w = PerWriter::new();
        w.write_constrained_int(msg.mme_ue_s1ap_id as u64, 0, ie::MME_UE_S1AP_ID_MAX);
        entries.push((ie::ID_MME_UE_S1AP_ID, ie::CRITICALITY_REJECT, w.into_bytes()));
    }
    {
        let mut w = PerWriter::new();
        w.write_constrained_int(msg.enb_ue_s1ap_id as u64, 0, ie::ENB_UE_S1AP_ID_MAX);
        entries.push((ie::ID_ENB_UE_S1AP_ID, ie::CRITICALITY_REJECT, w.into_bytes()));
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

fn decode_downlink_nas_transport(entries: &[IeEntry]) -> Result<S1apMessage> {
    let mut mme_ue_s1ap_id = None;
    let mut enb_ue_s1ap_id = None;
    let mut nas_pdu = None;

    for (id, _crit, val) in entries {
        let mut r = PerReader::new(val);
        match *id {
            x if x == ie::ID_MME_UE_S1AP_ID => {
                mme_ue_s1ap_id = r.read_constrained_int(0, ie::MME_UE_S1AP_ID_MAX).map(|v| v as u32);
            }
            x if x == ie::ID_ENB_UE_S1AP_ID => {
                enb_ue_s1ap_id = r.read_constrained_int(0, ie::ENB_UE_S1AP_ID_MAX).map(|v| v as u32);
            }
            x if x == ie::ID_NAS_PDU => {
                nas_pdu = r.read_octet_string();
            }
            _ => {}
        }
    }

    Ok(S1apMessage::DownlinkNasTransport(DownlinkNasTransport {
        mme_ue_s1ap_id: mme_ue_s1ap_id
            .ok_or(ProtoError::MalformedS1ap { reason: "missing MME-UE-S1AP-ID" })?,
        enb_ue_s1ap_id: enb_ue_s1ap_id
            .ok_or(ProtoError::MalformedS1ap { reason: "missing eNB-UE-S1AP-ID" })?,
        nas_pdu: Bytes::from(
            nas_pdu.ok_or(ProtoError::MalformedS1ap { reason: "missing NAS-PDU" })?,
        ),
    }))
}

// ── InitialContextSetupRequest / Response ─────────────────────────────────────

fn write_erabs_to_setup(w: &mut PerWriter, erabs: &[ErabToSetup]) {
    w.write_length_determinant(erabs.len());
    for e in erabs {
        w.write_constrained_int(e.erab_id as u64, 0, ie::ERAB_ID_MAX); // 4 bits
        w.write_constrained_int(e.qci as u64, 0, ie::QCI_MAX); // 8 bits
        // erab_id(4) + qci(8) = 12 bits — NOT byte-aligned. write_octets
        // doesn't align itself (unlike read_octets, which always does) —
        // see module doc, this is the exact bug class that broke ngap's
        // PDU-session encoding.
        w.align();
        w.write_octets(&e.gtp_teid);
        w.write_octets(&e.transport_layer_addr);
    }
}

fn read_erabs_to_setup(r: &mut PerReader) -> Option<Vec<ErabToSetup>> {
    let count = r.read_length_determinant()?;
    let mut out = Vec::with_capacity(count);
    for _ in 0..count {
        let erab_id = r.read_constrained_int(0, ie::ERAB_ID_MAX)? as u8;
        let qci = r.read_constrained_int(0, ie::QCI_MAX)? as u8;
        let teid_v = r.read_octets(4)?;
        let addr_v = r.read_octets(4)?;
        let mut gtp_teid = [0u8; 4];
        gtp_teid.copy_from_slice(&teid_v);
        let mut transport_layer_addr = [0u8; 4];
        transport_layer_addr.copy_from_slice(&addr_v);
        out.push(ErabToSetup { erab_id, qci, gtp_teid, transport_layer_addr });
    }
    Some(out)
}

fn write_erabs_setup(w: &mut PerWriter, items: &[ErabSetupItem]) {
    w.write_length_determinant(items.len());
    for it in items {
        w.write_constrained_int(it.e_rab_id as u64, 0, ie::ERAB_ID_MAX); // 4 bits
        // Not byte-aligned (4 bits) — same reasoning as write_erabs_to_setup.
        // Unlike ngap's response-side equivalent (which happened to stay
        // aligned by luck, e_rab_id is NOT 8 bits here), this one genuinely
        // needs it.
        w.align();
        w.write_octets(&it.transport_layer_addr);
        w.write_octets(&it.gtp_teid);
    }
}

fn read_erabs_setup(r: &mut PerReader) -> Option<Vec<ErabSetupItem>> {
    let count = r.read_length_determinant()?;
    let mut out = Vec::with_capacity(count);
    for _ in 0..count {
        let e_rab_id = r.read_constrained_int(0, ie::ERAB_ID_MAX)? as u8;
        let addr_v = r.read_octets(4)?;
        let teid_v = r.read_octets(4)?;
        let mut transport_layer_addr = [0u8; 4];
        transport_layer_addr.copy_from_slice(&addr_v);
        let mut gtp_teid = [0u8; 4];
        gtp_teid.copy_from_slice(&teid_v);
        out.push(ErabSetupItem { e_rab_id, transport_layer_addr, gtp_teid });
    }
    Some(out)
}

fn write_erab_ids(w: &mut PerWriter, ids: &[u8]) {
    w.write_length_determinant(ids.len());
    for &id in ids {
        w.write_constrained_int(id as u64, 0, ie::ERAB_ID_MAX);
    }
}

fn read_erab_ids(r: &mut PerReader) -> Option<Vec<u8>> {
    let count = r.read_length_determinant()?;
    let mut out = Vec::with_capacity(count);
    for _ in 0..count {
        out.push(r.read_constrained_int(0, ie::ERAB_ID_MAX)? as u8);
    }
    Some(out)
}

pub fn encode_initial_context_setup_request(msg: &InitialContextSetupRequest) -> Bytes {
    let mut entries: Vec<IeEntry> = Vec::with_capacity(6);

    {
        let mut w = PerWriter::new();
        w.write_constrained_int(msg.mme_ue_s1ap_id as u64, 0, ie::MME_UE_S1AP_ID_MAX);
        entries.push((ie::ID_MME_UE_S1AP_ID, ie::CRITICALITY_REJECT, w.into_bytes()));
    }
    {
        let mut w = PerWriter::new();
        w.write_constrained_int(msg.enb_ue_s1ap_id as u64, 0, ie::ENB_UE_S1AP_ID_MAX);
        entries.push((ie::ID_ENB_UE_S1AP_ID, ie::CRITICALITY_REJECT, w.into_bytes()));
    }
    {
        let mut w = PerWriter::new();
        w.write_constrained_int(msg.ue_ambr.0, 0, ie::BIT_RATE_MAX);
        w.write_constrained_int(msg.ue_ambr.1, 0, ie::BIT_RATE_MAX);
        entries.push((ie::ID_UE_AGGREGATE_MAXIMUM_BITRATE, ie::CRITICALITY_REJECT, w.into_bytes()));
    }
    {
        let mut w = PerWriter::new();
        w.write_octets(&msg.security_key); // fresh writer, aligned from bit 0
        entries.push((ie::ID_SECURITY_KEY, ie::CRITICALITY_REJECT, w.into_bytes()));
    }
    if !msg.e_rabs.is_empty() {
        let mut w = PerWriter::new();
        write_erabs_to_setup(&mut w, &msg.e_rabs);
        entries.push((ie::ID_E_RAB_TO_BE_SETUP_LIST_CTXT_SU_REQ, ie::CRITICALITY_REJECT, w.into_bytes()));
    }
    if let Some(nas_pdu) = &msg.nas_pdu {
        let mut w = PerWriter::new();
        w.write_octet_string(nas_pdu);
        entries.push((ie::ID_NAS_PDU, ie::CRITICALITY_REJECT, w.into_bytes()));
    }

    let mut value_w = PerWriter::new();
    write_ie_container(&mut value_w, &entries);

    encode_pdu_wrapper(
        PDU_CHOICE_INITIATING_MESSAGE, ie::PROC_INITIAL_CONTEXT_SETUP, ie::CRITICALITY_REJECT,
        &value_w.into_bytes(),
    )
}

fn decode_initial_context_setup_request(entries: &[IeEntry]) -> Result<S1apMessage> {
    let mut mme_ue_s1ap_id = None;
    let mut enb_ue_s1ap_id = None;
    let mut ue_ambr = None;
    let mut security_key = None;
    let mut e_rabs = Vec::new();
    let mut nas_pdu = None;

    for (id, _crit, val) in entries {
        let mut r = PerReader::new(val);
        match *id {
            x if x == ie::ID_MME_UE_S1AP_ID => {
                mme_ue_s1ap_id = r.read_constrained_int(0, ie::MME_UE_S1AP_ID_MAX).map(|v| v as u32);
            }
            x if x == ie::ID_ENB_UE_S1AP_ID => {
                enb_ue_s1ap_id = r.read_constrained_int(0, ie::ENB_UE_S1AP_ID_MAX).map(|v| v as u32);
            }
            x if x == ie::ID_UE_AGGREGATE_MAXIMUM_BITRATE => {
                let dl = r.read_constrained_int(0, ie::BIT_RATE_MAX);
                let ul = r.read_constrained_int(0, ie::BIT_RATE_MAX);
                if let (Some(dl), Some(ul)) = (dl, ul) {
                    ue_ambr = Some((dl, ul));
                }
            }
            x if x == ie::ID_SECURITY_KEY => {
                security_key = r.read_octets(32).map(|v| {
                    let mut a = [0u8; 32];
                    a.copy_from_slice(&v);
                    a
                });
            }
            x if x == ie::ID_E_RAB_TO_BE_SETUP_LIST_CTXT_SU_REQ => {
                if let Some(v) = read_erabs_to_setup(&mut r) {
                    e_rabs = v;
                }
            }
            x if x == ie::ID_NAS_PDU => {
                nas_pdu = r.read_octet_string();
            }
            _ => {}
        }
    }

    Ok(S1apMessage::InitialContextSetupRequest(InitialContextSetupRequest {
        mme_ue_s1ap_id: mme_ue_s1ap_id
            .ok_or(ProtoError::MalformedS1ap { reason: "missing MME-UE-S1AP-ID" })?,
        enb_ue_s1ap_id: enb_ue_s1ap_id
            .ok_or(ProtoError::MalformedS1ap { reason: "missing eNB-UE-S1AP-ID" })?,
        e_rabs,
        nas_pdu: nas_pdu.map(Bytes::from),
        ue_ambr: ue_ambr.ok_or(ProtoError::MalformedS1ap { reason: "missing UE-AggregateMaximumBitrate" })?,
        security_key: security_key.ok_or(ProtoError::MalformedS1ap { reason: "missing SecurityKey" })?,
    }))
}

pub fn encode_initial_context_setup_response(msg: &InitialContextSetupResponse) -> Bytes {
    let mut entries: Vec<IeEntry> = Vec::with_capacity(4);

    {
        let mut w = PerWriter::new();
        w.write_constrained_int(msg.mme_ue_s1ap_id as u64, 0, ie::MME_UE_S1AP_ID_MAX);
        entries.push((ie::ID_MME_UE_S1AP_ID, ie::CRITICALITY_REJECT, w.into_bytes()));
    }
    {
        let mut w = PerWriter::new();
        w.write_constrained_int(msg.enb_ue_s1ap_id as u64, 0, ie::ENB_UE_S1AP_ID_MAX);
        entries.push((ie::ID_ENB_UE_S1AP_ID, ie::CRITICALITY_REJECT, w.into_bytes()));
    }
    if !msg.e_rabs_setup.is_empty() {
        let mut w = PerWriter::new();
        write_erabs_setup(&mut w, &msg.e_rabs_setup);
        entries.push((ie::ID_E_RAB_SETUP_LIST_CTXT_SU_RES, ie::CRITICALITY_REJECT, w.into_bytes()));
    }
    if !msg.e_rabs_failed.is_empty() {
        let mut w = PerWriter::new();
        write_erab_ids(&mut w, &msg.e_rabs_failed);
        entries.push((ie::ID_E_RAB_FAILED_TO_SETUP_LIST_CTXT_SU_RES, ie::CRITICALITY_IGNORE, w.into_bytes()));
    }

    let mut value_w = PerWriter::new();
    write_ie_container(&mut value_w, &entries);

    encode_pdu_wrapper(
        PDU_CHOICE_SUCCESSFUL_OUTCOME, ie::PROC_INITIAL_CONTEXT_SETUP, ie::CRITICALITY_REJECT,
        &value_w.into_bytes(),
    )
}

fn decode_initial_context_setup_response(entries: &[IeEntry]) -> Result<S1apMessage> {
    let mut mme_ue_s1ap_id = None;
    let mut enb_ue_s1ap_id = None;
    let mut e_rabs_setup = Vec::new();
    let mut e_rabs_failed = Vec::new();

    for (id, _crit, val) in entries {
        let mut r = PerReader::new(val);
        match *id {
            x if x == ie::ID_MME_UE_S1AP_ID => {
                mme_ue_s1ap_id = r.read_constrained_int(0, ie::MME_UE_S1AP_ID_MAX).map(|v| v as u32);
            }
            x if x == ie::ID_ENB_UE_S1AP_ID => {
                enb_ue_s1ap_id = r.read_constrained_int(0, ie::ENB_UE_S1AP_ID_MAX).map(|v| v as u32);
            }
            x if x == ie::ID_E_RAB_SETUP_LIST_CTXT_SU_RES => {
                if let Some(v) = read_erabs_setup(&mut r) {
                    e_rabs_setup = v;
                }
            }
            x if x == ie::ID_E_RAB_FAILED_TO_SETUP_LIST_CTXT_SU_RES => {
                if let Some(v) = read_erab_ids(&mut r) {
                    e_rabs_failed = v;
                }
            }
            _ => {}
        }
    }

    Ok(S1apMessage::InitialContextSetupResponse(InitialContextSetupResponse {
        mme_ue_s1ap_id: mme_ue_s1ap_id
            .ok_or(ProtoError::MalformedS1ap { reason: "missing MME-UE-S1AP-ID" })?,
        enb_ue_s1ap_id: enb_ue_s1ap_id
            .ok_or(ProtoError::MalformedS1ap { reason: "missing eNB-UE-S1AP-ID" })?,
        e_rabs_setup,
        e_rabs_failed,
    }))
}

// ── Top-level dispatch ────────────────────────────────────────────────────────

/// Encode an `S1apMessage` to its ALIGNED PER wire bytes.
///
/// Returns `MalformedS1ap` for any variant outside this codec's scope (see
/// module docs) rather than silently producing incorrect bytes.
pub fn encode_s1ap_pdu(msg: &S1apMessage) -> Result<Bytes> {
    match msg {
        S1apMessage::InitialUeMessage(m) => Ok(encode_initial_ue_message(m)),
        S1apMessage::UplinkNasTransport(m) => Ok(encode_uplink_nas_transport(m)),
        S1apMessage::DownlinkNasTransport(m) => Ok(encode_downlink_nas_transport(m)),
        S1apMessage::InitialContextSetupRequest(m) => Ok(encode_initial_context_setup_request(m)),
        S1apMessage::InitialContextSetupResponse(m) => Ok(encode_initial_context_setup_response(m)),
        _ => Err(ProtoError::MalformedS1ap {
            reason: "PER encoding not yet implemented for this S1AP message — \
                     only InitialUEMessage/Uplink/DownlinkNASTransport/InitialContextSetupRequest/Response",
        }),
    }
}

/// Decode raw ALIGNED PER bytes into an `S1apMessage`.
pub fn decode_s1ap_pdu(buf: &[u8]) -> Result<S1apMessage> {
    let (choice, proc_code, _crit, value) = decode_pdu_wrapper(buf)
        .ok_or(ProtoError::MalformedS1ap { reason: "failed to decode PDU wrapper" })?;

    let mut vr = PerReader::new(&value);
    let entries = read_ie_container(&mut vr)
        .ok_or(ProtoError::MalformedS1ap { reason: "failed to decode IE container" })?;

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
        _ => Err(ProtoError::MalformedS1ap {
            reason: "unsupported procedure code — only InitialUEMessage/Uplink/DownlinkNASTransport/InitialContextSetupRequest/Response",
        }),
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn initial_ue_message_round_trip() {
        let msg = InitialUeMessage {
            enb_ue_s1ap_id: 0x0001_0001,
            nas_pdu: Bytes::from_static(&[0x07, 0x41, 0x00]),
            tai: [0x00, 0x01, 0x02, 0x00, 0x01],
            eutran_cgi: [0x00, 0x01, 0x02, 0x10, 0x20, 0x30, 0x40],
            rrc_cause: 3,
        };

        let bytes = encode_s1ap_pdu(&S1apMessage::InitialUeMessage(msg.clone())).unwrap();
        let decoded = decode_s1ap_pdu(&bytes).unwrap();

        match decoded {
            S1apMessage::InitialUeMessage(d) => {
                assert_eq!(d.enb_ue_s1ap_id, msg.enb_ue_s1ap_id);
                assert_eq!(d.nas_pdu, msg.nas_pdu);
                assert_eq!(d.tai, msg.tai);
                assert_eq!(d.eutran_cgi, msg.eutran_cgi);
                assert_eq!(d.rrc_cause, msg.rrc_cause);
            }
            other => panic!("wrong variant decoded: {other:?}"),
        }
    }

    #[test]
    fn uplink_nas_transport_round_trip() {
        let msg = UplinkNasTransport {
            mme_ue_s1ap_id: 0xCAFEBABE,
            enb_ue_s1ap_id: 0x0001_0002,
            nas_pdu: Bytes::from_static(&[0x07, 0x53, 0x08, 0xA5, 0x42, 0x11, 0xD5, 0xE3, 0xBA, 0x50, 0xBF]),
            tai: [1, 2, 3, 4, 5],
            eutran_cgi: [9, 8, 7, 6, 5, 4, 3],
        };

        let bytes = encode_s1ap_pdu(&S1apMessage::UplinkNasTransport(msg.clone())).unwrap();
        let decoded = decode_s1ap_pdu(&bytes).unwrap();

        match decoded {
            S1apMessage::UplinkNasTransport(d) => {
                assert_eq!(d.mme_ue_s1ap_id, msg.mme_ue_s1ap_id);
                assert_eq!(d.enb_ue_s1ap_id, msg.enb_ue_s1ap_id);
                assert_eq!(d.nas_pdu, msg.nas_pdu);
                assert_eq!(d.tai, msg.tai);
                assert_eq!(d.eutran_cgi, msg.eutran_cgi);
            }
            other => panic!("wrong variant decoded: {other:?}"),
        }
    }

    #[test]
    fn downlink_nas_transport_round_trip() {
        let msg = DownlinkNasTransport {
            mme_ue_s1ap_id: 42,
            enb_ue_s1ap_id: 7,
            nas_pdu: Bytes::from_static(&[0x07, 0x5D, 0x24, 0x70]),
        };

        let bytes = encode_s1ap_pdu(&S1apMessage::DownlinkNasTransport(msg.clone())).unwrap();
        let decoded = decode_s1ap_pdu(&bytes).unwrap();

        match decoded {
            S1apMessage::DownlinkNasTransport(d) => {
                assert_eq!(d.mme_ue_s1ap_id, msg.mme_ue_s1ap_id);
                assert_eq!(d.enb_ue_s1ap_id, msg.enb_ue_s1ap_id);
                assert_eq!(d.nas_pdu, msg.nas_pdu);
            }
            other => panic!("wrong variant decoded: {other:?}"),
        }
    }

    #[test]
    fn initial_context_setup_request_round_trip() {
        let msg = InitialContextSetupRequest {
            mme_ue_s1ap_id: 0xCAFEBABE,
            enb_ue_s1ap_id: 7,
            e_rabs: vec![ErabToSetup {
                erab_id: 5,
                qci: 9,
                gtp_teid: [0x00, 0x02, 0x00, 0x01],
                transport_layer_addr: [10, 0, 0, 1],
            }],
            nas_pdu: Some(Bytes::from_static(&[0x07, 0x42, 0x01, 0x02])),
            ue_ambr: (50_000_000, 50_000_000),
            security_key: [0x5Au8; 32],
        };

        let bytes = encode_s1ap_pdu(&S1apMessage::InitialContextSetupRequest(msg.clone())).unwrap();
        let decoded = decode_s1ap_pdu(&bytes).unwrap();

        match decoded {
            S1apMessage::InitialContextSetupRequest(d) => {
                assert_eq!(d.mme_ue_s1ap_id, msg.mme_ue_s1ap_id);
                assert_eq!(d.enb_ue_s1ap_id, msg.enb_ue_s1ap_id);
                assert_eq!(d.e_rabs.len(), 1);
                assert_eq!(d.e_rabs[0].erab_id, msg.e_rabs[0].erab_id);
                assert_eq!(d.e_rabs[0].qci, msg.e_rabs[0].qci);
                assert_eq!(d.e_rabs[0].gtp_teid, msg.e_rabs[0].gtp_teid);
                assert_eq!(d.e_rabs[0].transport_layer_addr, msg.e_rabs[0].transport_layer_addr);
                assert_eq!(d.nas_pdu, msg.nas_pdu);
                assert_eq!(d.ue_ambr, msg.ue_ambr);
                assert_eq!(d.security_key, msg.security_key);
            }
            other => panic!("wrong variant decoded: {other:?}"),
        }
    }

    #[test]
    fn initial_context_setup_request_round_trip_no_erabs_no_nas_pdu() {
        let msg = InitialContextSetupRequest {
            mme_ue_s1ap_id: 1,
            enb_ue_s1ap_id: 1,
            e_rabs: vec![],
            nas_pdu: None,
            ue_ambr: (1_000, 1_000),
            security_key: [0u8; 32],
        };

        let bytes = encode_s1ap_pdu(&S1apMessage::InitialContextSetupRequest(msg.clone())).unwrap();
        let decoded = decode_s1ap_pdu(&bytes).unwrap();

        match decoded {
            S1apMessage::InitialContextSetupRequest(d) => {
                assert!(d.e_rabs.is_empty());
                assert!(d.nas_pdu.is_none());
                assert_eq!(d.ue_ambr, msg.ue_ambr);
            }
            other => panic!("wrong variant decoded: {other:?}"),
        }
    }

    #[test]
    fn initial_context_setup_response_round_trip() {
        let msg = InitialContextSetupResponse {
            mme_ue_s1ap_id: 42,
            enb_ue_s1ap_id: 7,
            e_rabs_setup: vec![ErabSetupItem {
                e_rab_id: 5,
                transport_layer_addr: [172, 16, 0, 5],
                gtp_teid: [0xAA, 0xBB, 0xCC, 0xDD],
            }],
            e_rabs_failed: vec![],
        };

        let bytes = encode_s1ap_pdu(&S1apMessage::InitialContextSetupResponse(msg.clone())).unwrap();
        let decoded = decode_s1ap_pdu(&bytes).unwrap();

        match decoded {
            S1apMessage::InitialContextSetupResponse(d) => {
                assert_eq!(d.mme_ue_s1ap_id, msg.mme_ue_s1ap_id);
                assert_eq!(d.enb_ue_s1ap_id, msg.enb_ue_s1ap_id);
                assert_eq!(d.e_rabs_setup.len(), 1);
                assert_eq!(d.e_rabs_setup[0].e_rab_id, msg.e_rabs_setup[0].e_rab_id);
                assert_eq!(d.e_rabs_setup[0].transport_layer_addr, msg.e_rabs_setup[0].transport_layer_addr);
                assert_eq!(d.e_rabs_setup[0].gtp_teid, msg.e_rabs_setup[0].gtp_teid);
                assert!(d.e_rabs_failed.is_empty());
            }
            other => panic!("wrong variant decoded: {other:?}"),
        }
    }

    #[test]
    fn initial_context_setup_response_round_trip_with_failed_erab() {
        let msg = InitialContextSetupResponse {
            mme_ue_s1ap_id: 42,
            enb_ue_s1ap_id: 7,
            e_rabs_setup: vec![],
            e_rabs_failed: vec![6],
        };

        let bytes = encode_s1ap_pdu(&S1apMessage::InitialContextSetupResponse(msg.clone())).unwrap();
        let decoded = decode_s1ap_pdu(&bytes).unwrap();

        match decoded {
            S1apMessage::InitialContextSetupResponse(d) => {
                assert!(d.e_rabs_setup.is_empty());
                assert_eq!(d.e_rabs_failed, vec![6]);
            }
            other => panic!("wrong variant decoded: {other:?}"),
        }
    }

    #[test]
    fn initial_context_setup_request_and_response_share_procedure_code_but_not_choice() {
        let req = InitialContextSetupRequest {
            mme_ue_s1ap_id: 1,
            enb_ue_s1ap_id: 1,
            e_rabs: vec![],
            nas_pdu: None,
            ue_ambr: (1, 1),
            security_key: [0u8; 32],
        };
        let resp = InitialContextSetupResponse {
            mme_ue_s1ap_id: 1,
            enb_ue_s1ap_id: 1,
            e_rabs_setup: vec![],
            e_rabs_failed: vec![],
        };

        let req_bytes = encode_s1ap_pdu(&S1apMessage::InitialContextSetupRequest(req)).unwrap();
        let resp_bytes = encode_s1ap_pdu(&S1apMessage::InitialContextSetupResponse(resp)).unwrap();

        let (req_choice, req_proc, ..) = decode_pdu_wrapper(&req_bytes).unwrap();
        let (resp_choice, resp_proc, ..) = decode_pdu_wrapper(&resp_bytes).unwrap();

        assert_eq!(req_proc, ie::PROC_INITIAL_CONTEXT_SETUP);
        assert_eq!(resp_proc, ie::PROC_INITIAL_CONTEXT_SETUP);
        assert_ne!(req_choice, resp_choice, "Request/Response must differ in PDU choice, not procedure code");
        assert_eq!(req_choice, PDU_CHOICE_INITIATING_MESSAGE);
        assert_eq!(resp_choice, PDU_CHOICE_SUCCESSFUL_OUTCOME);

        // Decoding each other's bytes with the right dispatcher must land
        // on the right variant — proof `decode_s1ap_pdu` is actually
        // branching on choice, not just procedure code.
        assert!(matches!(
            decode_s1ap_pdu(&req_bytes).unwrap(),
            S1apMessage::InitialContextSetupRequest(_)
        ));
        assert!(matches!(
            decode_s1ap_pdu(&resp_bytes).unwrap(),
            S1apMessage::InitialContextSetupResponse(_)
        ));
    }

    #[test]
    fn unsupported_variant_returns_error_not_garbage() {
        let result = encode_s1ap_pdu(&S1apMessage::UeContextReleaseCommand {
            cause: crate::s1ap::messages::S1apCause::NasNormalRelease,
        });
        assert!(result.is_err(), "out-of-scope variants must error, not silently mis-encode");
    }

    #[test]
    fn decode_rejects_truncated_buffer() {
        assert!(decode_s1ap_pdu(&[0x00]).is_err());
    }

    #[test]
    fn decode_rejects_unknown_procedure_code() {
        // Hand-build a PDU wrapper with a bogus procedure code (250) and an
        // empty IE container, to confirm the dispatcher actually checks it.
        let mut value_w = PerWriter::new();
        write_ie_container(&mut value_w, &[]);
        let bytes = encode_pdu_wrapper(PDU_CHOICE_INITIATING_MESSAGE, 250, ie::CRITICALITY_IGNORE, &value_w.into_bytes());
        assert!(decode_s1ap_pdu(&bytes).is_err());
    }
    }
