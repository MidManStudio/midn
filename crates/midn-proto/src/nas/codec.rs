// crates/midn-proto/src/nas/codec.rs
//! NAS message binary encoder/decoder for the LTE attach procedure.
//!
//! Implements the wire format of 3GPP TS 24.301 for the messages
//! required to complete a full UE attachment:
//!
//! ```text
//! UE → MME : AttachRequest
//! MME → UE : AuthenticationRequest
//! UE → MME : AuthenticationResponse
//! MME → UE : SecurityModeCommand
//! UE → MME : SecurityModeComplete
//! MME → UE : AttachAccept
//! UE → MME : AttachComplete
//! UE → MME : DetachRequest
//! MME → UE : DetachAccept
//! ```
//!
//! ## Wire format
//!
//! Plain (unsecured) NAS PDU:
//! ```text
//! Octet 1: 0x07  EPS Mobility Management, no security
//! Octet 2: message type
//! Octets 3+: IEs
//! ```
//!
//! Protected NAS PDU envelope (see `encode_protected`/`decode_protected`
//! below, backed by `nas::security::NasSecurityContext`):
//! ```text
//! Octet 1     : [security header type, 4 bits] | [protocol discriminator 0x7, 4 bits]
//! Octets 2-5  : MAC-I (4 bytes)
//! Octet 6     : NAS sequence number (low-order COUNT byte)
//! Octets 7+   : payload — a complete plain NAS PDU (octets as above),
//!               ciphered in place if the negotiated EEA is not Eea0
//! ```
//!
//! ## Spec compliance note
//!
//! This implements the critical-path IEs needed for Phase 2. Optional IEs
//! and full bitfield packing per 3GPP TS 24.301 will be tightened in Phase 3
//! for real UE interop.

use bytes::Bytes;
use crate::error::{ProtoError, Result};
use crate::nas::ie::{
    decode_imsi, decode_security_algorithms, encode_imsi, encode_security_algorithms,
    find_tlv, read_lv, write_lv, write_tlv, NasEeaAlgorithm, NasEiaAlgorithm,
};
use crate::nas::security::NasSecurityContext;

// ── NAS constants ─────────────────────────────────────────────────────────────

pub const NAS_EPS_MM_PD: u8     = 0x07; // Protocol Discriminator: EPS Mobility Management
pub const NAS_PLAIN_HEADER: u8  = 0x07; // First byte of unsecured EPS-MM PDU

// Message type identifiers (3GPP TS 24.301 Table 9.8.1)
pub const MT_ATTACH_REQUEST:          u8 = 0x41;
pub const MT_ATTACH_ACCEPT:           u8 = 0x42;
pub const MT_ATTACH_COMPLETE:         u8 = 0x43;
pub const MT_DETACH_REQUEST:          u8 = 0x45;
pub const MT_DETACH_ACCEPT:           u8 = 0x46;
pub const MT_AUTHENTICATION_REQUEST:  u8 = 0x52;
pub const MT_AUTHENTICATION_RESPONSE: u8 = 0x53;
pub const MT_AUTHENTICATION_REJECT:   u8 = 0x54;
pub const MT_SECURITY_MODE_COMMAND:   u8 = 0x5D;
pub const MT_SECURITY_MODE_COMPLETE:  u8 = 0x5E;
pub const MT_SECURITY_MODE_REJECT:    u8 = 0x5F;

// IEI values for optional IEs in Attach Accept
const IEI_GUTI:     u8 = 0x50;
const IEI_APN:      u8 = 0x28;
const IEI_PDN_ADDR: u8 = 0x29;

// Security header types (3GPP TS 24.301 Table 9.3.1) — used by the protected
// envelope below, NOT by `decode_nas` (which only ever sees sht == 0, the
// inner plain PDU, after `decode_protected` has stripped the envelope).
pub const SHT_PLAIN:                      u8 = 0;
pub const SHT_INTEGRITY:                  u8 = 1;
pub const SHT_INTEGRITY_CIPHERED:         u8 = 2;
pub const SHT_INTEGRITY_NEW_CTX:          u8 = 3;
pub const SHT_INTEGRITY_CIPHERED_NEW_CTX: u8 = 4;

// ── Top-level decode ──────────────────────────────────────────────────────────

/// Decoded NAS PDU — the parsed representation of a raw NAS byte buffer.
#[derive(Debug, Clone)]
pub enum NasPdu {
    AttachRequest(DecodedAttachRequest),
    AuthenticationRequest(DecodedAuthenticationRequest),
    AuthenticationResponse(DecodedAuthenticationResponse),
    SecurityModeCommand(DecodedSecurityModeCommand),
    SecurityModeComplete,
    AttachAccept(DecodedAttachAccept),
    AttachComplete,
    DetachRequest(DecodedDetachRequest),
    DetachAccept,
}

/// Parse a raw, PLAIN NAS PDU byte buffer (security header type 0).
///
/// Protected envelopes must go through `decode_protected` first to recover
/// the inner plain bytes — `decode_nas` rejects anything with sht != 0.
pub fn decode_nas(buf: &[u8]) -> Result<NasPdu> {
    if buf.len() < 2 {
        return Err(ProtoError::TooShort { expected: 2, got: buf.len() });
    }
    // Octet 1: security header type (high nibble) | protocol discriminator (low nibble)
    let pd  = buf[0] & 0x0F;
    let sht = (buf[0] >> 4) & 0x0F;
    if pd != (NAS_EPS_MM_PD & 0x0F) {
        return Err(ProtoError::MalformedNas { reason: "expected EPS-MM protocol discriminator 0x7" });
    }
    if sht != 0 {
        return Err(ProtoError::MalformedNas { reason: "protected NAS not supported in Phase 2" });
    }
    let msg_type = buf[1];
    let body     = &buf[2..];

    match msg_type {
        MT_ATTACH_REQUEST          => decode_attach_request(body),
        MT_AUTHENTICATION_REQUEST  => decode_auth_request(body),
        MT_AUTHENTICATION_RESPONSE => decode_auth_response(body),
        MT_SECURITY_MODE_COMMAND   => decode_sec_mode_cmd(body),
        MT_SECURITY_MODE_COMPLETE  => Ok(NasPdu::SecurityModeComplete),
        MT_ATTACH_ACCEPT           => decode_attach_accept(body),
        MT_ATTACH_COMPLETE         => Ok(NasPdu::AttachComplete),
        MT_DETACH_REQUEST          => decode_detach_request(body),
        MT_DETACH_ACCEPT           => Ok(NasPdu::DetachAccept),
        other => Err(ProtoError::UnknownGtpMsgType(other)),
    }
}

// ── Attach Request ────────────────────────────────────────────────────────────

/// Decoded fields from a NAS Attach Request.
#[derive(Debug, Clone)]
pub struct DecodedAttachRequest {
    pub eps_attach_type: u8,
    pub nas_ksi:         u8,
    /// Subscriber identity — IMSI if provided, else None (GUTI attach)
    pub imsi:            Option<u64>,
    pub ue_network_cap:  Vec<u8>,
}

fn decode_attach_request(body: &[u8]) -> Result<NasPdu> {
    if body.is_empty() {
        return Err(ProtoError::TooShort { expected: 3, got: 0 });
    }
    // Octet 3: [EPS Attach Type (3b)] | [spare (1b)] | [NAS KSI (3b)] | [spare (1b)]
    // Simplified: high nibble = NAS KSI, low nibble = attach type + spare
    let eps_attach_type = body[0] & 0x07;
    let nas_ksi         = (body[0] >> 4) & 0x07;
    let rest            = &body[1..];

    // Mobile Identity (IMSI or GUTI) — LV encoded
    let (identity_bytes, rest) = read_lv(rest)
        .ok_or(ProtoError::MalformedNas { reason: "missing mobile identity" })?;

    let imsi = decode_imsi(identity_bytes); // None if GUTI

    // UE Network Capability — LV encoded
    let ue_network_cap = if let Some((cap, _)) = read_lv(rest) {
        cap.to_vec()
    } else {
        vec![]
    };

    Ok(NasPdu::AttachRequest(DecodedAttachRequest {
        eps_attach_type, nas_ksi, imsi, ue_network_cap,
    }))
}

/// Encode a NAS Attach Request (used by mock UE in tests).
pub fn encode_attach_request(imsi: u64, eps_attach_type: u8, nas_ksi: u8) -> Bytes {
    let mut buf = vec![NAS_PLAIN_HEADER, MT_ATTACH_REQUEST];

    // Octet 3: NAS KSI | attach type
    buf.push(((nas_ksi & 0x07) << 4) | (eps_attach_type & 0x07));

    // Mobile Identity: IMSI as LV
    let imsi_bytes = encode_imsi(imsi);
    write_lv(&mut buf, &imsi_bytes);

    // UE Network Capability (minimal — just EEA2+EIA2 support)
    write_lv(&mut buf, &[0x20, 0x40]); // EEA2, EIA2 capability bits

    Bytes::from(buf)
}

// ── Authentication Request ────────────────────────────────────────────────────

/// Decoded fields from a NAS Authentication Request.
#[derive(Debug, Clone)]
pub struct DecodedAuthenticationRequest {
    pub nas_ksi: u8,
    pub rand:    [u8; 16],
    pub autn:    [u8; 16],
}

fn decode_auth_request(body: &[u8]) -> Result<NasPdu> {
    if body.len() < 1 {
        return Err(ProtoError::TooShort { expected: 35, got: body.len() });
    }
    let nas_ksi = (body[0] >> 4) & 0x07;
    let rest    = &body[1..];

    // RAND: LV, length = 16
    let (rand_bytes, rest) = read_lv(rest)
        .ok_or(ProtoError::MalformedNas { reason: "missing RAND" })?;
    if rand_bytes.len() != 16 {
        return Err(ProtoError::MalformedNas { reason: "RAND must be exactly 16 bytes" });
    }
    let rand: [u8; 16] = rand_bytes.try_into().unwrap();

    // AUTN: LV, length = 16
    let (autn_bytes, _) = read_lv(rest)
        .ok_or(ProtoError::MalformedNas { reason: "missing AUTN" })?;
    if autn_bytes.len() != 16 {
        return Err(ProtoError::MalformedNas { reason: "AUTN must be exactly 16 bytes" });
    }
    let autn: [u8; 16] = autn_bytes.try_into().unwrap();

    Ok(NasPdu::AuthenticationRequest(DecodedAuthenticationRequest { nas_ksi, rand, autn }))
}

/// Encode a NAS Authentication Request.
pub fn encode_auth_request(nas_ksi: u8, rand: &[u8; 16], autn: &[u8; 16]) -> Bytes {
    let mut buf = vec![NAS_PLAIN_HEADER, MT_AUTHENTICATION_REQUEST];

    // NAS KSI in high nibble, spare in low nibble
    buf.push((nas_ksi & 0x07) << 4);

    write_lv(&mut buf, rand);   // RAND: LV
    write_lv(&mut buf, autn);   // AUTN: LV

    Bytes::from(buf)
}

// ── Authentication Response ───────────────────────────────────────────────────

/// Decoded fields from a NAS Authentication Response.
#[derive(Debug, Clone)]
pub struct DecodedAuthenticationResponse {
    pub res: [u8; 8],
}

fn decode_auth_response(body: &[u8]) -> Result<NasPdu> {
    let (res_bytes, _) = read_lv(body)
        .ok_or(ProtoError::MalformedNas { reason: "missing RES" })?;
    if res_bytes.len() != 8 {
        return Err(ProtoError::MalformedNas { reason: "RES must be exactly 8 bytes" });
    }
    let res: [u8; 8] = res_bytes.try_into().unwrap();
    Ok(NasPdu::AuthenticationResponse(DecodedAuthenticationResponse { res }))
}

/// Encode a NAS Authentication Response (used by mock UE in tests).
pub fn encode_auth_response(res: &[u8; 8]) -> Bytes {
    let mut buf = vec![NAS_PLAIN_HEADER, MT_AUTHENTICATION_RESPONSE];
    write_lv(&mut buf, res);    // RES: LV
    Bytes::from(buf)
}

// ── Security Mode Command ─────────────────────────────────────────────────────

/// Decoded fields from a NAS Security Mode Command.
#[derive(Debug, Clone)]
pub struct DecodedSecurityModeCommand {
    pub eea: NasEeaAlgorithm,
    pub eia: NasEiaAlgorithm,
    pub nas_ksi: u8,
}

fn decode_sec_mode_cmd(body: &[u8]) -> Result<NasPdu> {
    if body.len() < 2 {
        return Err(ProtoError::TooShort { expected: 2, got: body.len() });
    }
    let (eea, eia) = decode_security_algorithms(body[0]);
    let nas_ksi    = (body[1] >> 4) & 0x07;
    Ok(NasPdu::SecurityModeCommand(DecodedSecurityModeCommand { eea, eia, nas_ksi }))
}

/// Encode a NAS Security Mode Command.
pub fn encode_sec_mode_cmd(
    eea: NasEeaAlgorithm,
    eia: NasEiaAlgorithm,
    nas_ksi: u8,
    ue_cap: &[u8],
) -> Bytes {
    let mut buf = vec![NAS_PLAIN_HEADER, MT_SECURITY_MODE_COMMAND];
    buf.push(encode_security_algorithms(eea, eia));  // selected algorithms
    buf.push((nas_ksi & 0x07) << 4);                // NAS KSI
    write_lv(&mut buf, ue_cap);                      // replayed UE security capabilities
    Bytes::from(buf)
}

/// Encode a NAS Security Mode Complete (used by mock UE in tests).
pub fn encode_sec_mode_complete() -> Bytes {
    Bytes::from(vec![NAS_PLAIN_HEADER, MT_SECURITY_MODE_COMPLETE])
}

// ── Attach Accept ─────────────────────────────────────────────────────────────

/// Decoded fields from a NAS Attach Accept.
#[derive(Debug, Clone)]
pub struct DecodedAttachAccept {
    pub attach_result: u8,
    pub t3412_value:   u8,
    pub guti:          Option<[u8; 10]>,
    pub ip_address:    Option<[u8; 4]>,
    pub apn:           Option<String>,
}

fn decode_attach_accept(body: &[u8]) -> Result<NasPdu> {
    if body.len() < 2 {
        return Err(ProtoError::TooShort { expected: 2, got: body.len() });
    }
    let attach_result = body[0] & 0x07;
    let t3412_value   = body[1];
    let rest          = &body[2..];

    let mut guti       = None;
    let mut ip_address = None;
    let mut apn        = None;

    // TAI list (mandatory LV, skip it)
    let rest = if let Some((_, r)) = read_lv(rest) { r } else { rest };

    // Parse optional TLV IEs
    let mut remaining = rest;
    while remaining.len() >= 2 {
        match remaining[0] {
            IEI_GUTI => {
                if let Some((_, val, r)) = find_tlv(remaining, IEI_GUTI)
                    .and_then(|s| crate::nas::ie::read_tlv(s))
                {
                    if val.len() == 10 {
                        let mut g = [0u8; 10];
                        g.copy_from_slice(val);
                        guti = Some(g);
                    }
                    remaining = r;
                } else { break; }
            }
            IEI_PDN_ADDR => {
                if let Some((_, val, r)) = crate::nas::ie::read_tlv(remaining) {
                    // PDN address: first byte = address type, then IP
                    if val.len() >= 5 && val[0] == 0x01 { // IPv4
                        let mut ip = [0u8; 4];
                        ip.copy_from_slice(&val[1..5]);
                        ip_address = Some(ip);
                    }
                    remaining = r;
                } else { break; }
            }
            IEI_APN => {
                if let Some((_, val, r)) = crate::nas::ie::read_tlv(remaining) {
                    apn = String::from_utf8(val.to_vec()).ok();
                    remaining = r;
                } else { break; }
            }
            _ => {
                // Unknown TLV: skip
                if remaining.len() < 2 { break; }
                let skip = remaining[1] as usize + 2;
                if remaining.len() < skip { break; }
                remaining = &remaining[skip..];
            }
        }
    }

    Ok(NasPdu::AttachAccept(DecodedAttachAccept {
        attach_result, t3412_value, guti, ip_address, apn
    }))
}

/// Encode a NAS Attach Accept.
pub fn encode_attach_accept(
    attach_result: u8,
    t3412_value:   u8,
    tai_list:      &[[u8; 5]],
    ip_address:    Option<[u8; 4]>,
    apn:           Option<&str>,
) -> Bytes {
    let mut buf = vec![NAS_PLAIN_HEADER, MT_ATTACH_ACCEPT];
    buf.push(attach_result & 0x07);
    buf.push(t3412_value);

    // TAI list (mandatory LV — write empty if none)
    if tai_list.is_empty() {
        write_lv(&mut buf, &[]);
    } else {
        let mut tai_bytes = vec![(tai_list.len() as u8 - 1) | 0x18]; // list type + count
        for tai in tai_list { tai_bytes.extend_from_slice(tai); }
        write_lv(&mut buf, &tai_bytes);
    }

    // Optional: PDN address (TLV, IEI = 0x29)
    if let Some(ip) = ip_address {
        let mut addr = vec![0x01u8]; // IPv4 type
        addr.extend_from_slice(&ip);
        write_tlv(&mut buf, IEI_PDN_ADDR, &addr);
    }

    // Optional: APN (TLV, IEI = 0x28)
    if let Some(apn_str) = apn {
        write_tlv(&mut buf, IEI_APN, apn_str.as_bytes());
    }

    Bytes::from(buf)
}

/// Encode a NAS Attach Complete (used by mock UE in tests).
pub fn encode_attach_complete() -> Bytes {
    Bytes::from(vec![NAS_PLAIN_HEADER, MT_ATTACH_COMPLETE])
}

// ── Detach Request / Accept ───────────────────────────────────────────────────
//
// Models the UE-initiated detach procedure (3GPP TS 24.301 Section 5.5.2.2).
// Network-initiated detach is not driven via NAS in this simulation — the MME
// drives that path directly through S1AP UeContextReleaseCommand instead (see
// midn_core::mme::detach). Both paths converge on the same teardown code.
//
// Simplification: real 3GPP defines distinct message type values for
// UE-originating vs network-originating detach request/accept. This
// simulation only models the UE-originating direction, so a single pair of
// constants (MT_DETACH_REQUEST / MT_DETACH_ACCEPT) covers it.

/// Decoded fields from a NAS Detach Request (UE → MME).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DecodedDetachRequest {
    /// Detach type, 3 bits — 1=EPS detach, 2=IMSI detach, 3=combined, etc.
    /// The simulation doesn't branch on this beyond carrying it through.
    pub detach_type: u8,
    /// Switch-off flag — true if the UE is powering down. When true the MME
    /// skips sending DetachAccept, since the UE won't process it.
    pub switch_off:  bool,
    pub nas_ksi:     u8,
}

fn decode_detach_request(body: &[u8]) -> Result<NasPdu> {
    if body.is_empty() {
        return Err(ProtoError::TooShort { expected: 1, got: 0 });
    }
    // Octet 3: [NAS KSI (3b, high)] | [switch-off (1b)] | [detach type (3b, low)]
    let byte        = body[0];
    let detach_type = byte & 0x07;
    let switch_off  = (byte >> 3) & 0x01 != 0;
    let nas_ksi     = (byte >> 4) & 0x07;
    // Mobile identity (GUTI, LV-encoded) follows but is unused here — the
    // entity is resolved via mme_ue_s1ap_id at the S1AP layer, not the NAS
    // identity IE. Bytes accepted for wire realism, then ignored.
    Ok(NasPdu::DetachRequest(DecodedDetachRequest { detach_type, switch_off, nas_ksi }))
}

/// Encode a NAS Detach Request (used by mock UE in tests).
pub fn encode_detach_request(
    detach_type: u8,
    switch_off:  bool,
    nas_ksi:     u8,
    guti:        &[u8; 10],
) -> Bytes {
    let mut buf = vec![NAS_PLAIN_HEADER, MT_DETACH_REQUEST];
    let byte = ((nas_ksi & 0x07) << 4) | (((switch_off as u8) & 0x01) << 3) | (detach_type & 0x07);
    buf.push(byte);
    write_lv(&mut buf, guti); // Mobile identity (GUTI) — LV, for wire realism
    Bytes::from(buf)
}

/// Encode a NAS Detach Accept (MME → UE). No IEs — header only.
///
/// Not sent for switch-off detaches (the UE has already powered down).
pub fn encode_detach_accept() -> Bytes {
    Bytes::from(vec![NAS_PLAIN_HEADER, MT_DETACH_ACCEPT])
}

// ── Protected NAS envelope ────────────────────────────────────────────────────
//
// Generic wrapper/unwrapper for any plain NAS PDU bytes (the output of any
// `encode_*` function above), backed by `nas::security::NasSecurityContext`.
// Called from `midn_core::mme::attach::handle_security_mode_complete`
// (encode_protected, for AttachAccept) and `Mme::handle_uplink_nas`
// (decode_protected, for any post-security uplink message — auto-detected
// via the security header type nibble) — see `nas::security` module docs
// for the activation point and what's still simplified.

/// Wrap an already-built plain NAS message in a protected envelope
/// (MME → UE direction — uses `NasSecurityContext::protect_downlink`).
///
/// `sht` should normally be [`SHT_INTEGRITY_CIPHERED`]; use one of the
/// `*_NEW_CTX` variants for the first protected message sent immediately
/// after a new security context is established (TS 24.301 §4.4.3).
pub fn encode_protected(
    ctx:         &mut NasSecurityContext,
    sht:         u8,
    bearer:      u8,
    inner_plain: &[u8],
) -> Bytes {
    let protected = ctx.protect_downlink(bearer, inner_plain);
    let mut buf = Vec::with_capacity(6 + protected.payload.len());
    buf.push((sht << 4) | NAS_EPS_MM_PD);
    buf.extend_from_slice(&protected.mac_i);
    buf.push((protected.count & 0xFF) as u8);
    buf.extend_from_slice(&protected.payload);
    Bytes::from(buf)
}

/// Unwrap a protected NAS envelope (UE → MME direction — uses
/// `NasSecurityContext::unprotect_uplink`).
///
/// Returns the inner plain NAS bytes on success — feed those to
/// [`decode_nas`] to get the actual `NasPdu`. Returns `None` on integrity
/// failure or a malformed/too-short buffer; never panics on attacker input.
pub fn decode_protected(
    ctx:    &mut NasSecurityContext,
    buf:    &[u8],
    bearer: u8,
) -> Option<Vec<u8>> {
    if buf.len() < 6 { return None; }
    let sht = (buf[0] >> 4) & 0x0F;
    if sht == 0 { return None; } // plain — caller should use decode_nas directly
    let mut mac_i = [0u8; 4];
    mac_i.copy_from_slice(&buf[1..5]);
    let seq_byte   = buf[5];
    let ciphertext = &buf[6..];
    ctx.unprotect_uplink(bearer, seq_byte, mac_i, ciphertext)
}

/// Wrap an already-built plain NAS message in a protected envelope for the
/// UPLINK direction (UE → MME) — uses `NasSecurityContext::protect_uplink`.
/// UE-role mirror of [`encode_protected`]: a genuine UE-role caller (e.g.
/// `mme-sim`'s mock UE, encoding AttachComplete) needs its own
/// uplink-tagged protect, not a relabeled network-role one — same DIRECTION
/// mismatch this codebase already hit and fixed once on the 5G side (see
/// `nas5gs::codec::encode_protected_uplink`'s doc for the fuller
/// rationale). This is the same gap on the LTE side, closed the same way.
pub fn encode_protected_uplink(
    ctx:         &mut NasSecurityContext,
    sht:         u8,
    bearer:      u8,
    inner_plain: &[u8],
) -> Bytes {
    let protected = ctx.protect_uplink(bearer, inner_plain);
    let mut buf = Vec::with_capacity(6 + protected.payload.len());
    buf.push((sht << 4) | NAS_EPS_MM_PD);
    buf.extend_from_slice(&protected.mac_i);
    buf.push((protected.count & 0xFF) as u8);
    buf.extend_from_slice(&protected.payload);
    Bytes::from(buf)
}

/// Unwrap a protected NAS envelope for the DOWNLINK direction (MME → UE) —
/// uses `NasSecurityContext::unprotect_downlink`. UE-role mirror of
/// [`decode_protected`] — see `nas5gs::codec::decode_protected_downlink`
/// for the identical rationale one level up the stack.
///
/// Returns the inner plain NAS bytes on success — feed those to
/// [`decode_nas`] to get the actual `NasPdu`. Returns `None` on integrity
/// failure or a malformed/too-short buffer; never panics on attacker input.
pub fn decode_protected_downlink(
    ctx:    &mut NasSecurityContext,
    buf:    &[u8],
    bearer: u8,
) -> Option<Vec<u8>> {
    if buf.len() < 6 { return None; }
    let sht = (buf[0] >> 4) & 0x0F;
    if sht == 0 { return None; } // plain — caller should use decode_nas directly
    let mut mac_i = [0u8; 4];
    mac_i.copy_from_slice(&buf[1..5]);
    let seq_byte   = buf[5];
    let ciphertext = &buf[6..];
    ctx.unprotect_downlink(bearer, seq_byte, mac_i, ciphertext)
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::nas::security::{NasSecurityContext, Direction, eea2_apply, eia2_compute_mac, derive_nas_keys, NAS_BEARER};

    #[test]
    fn auth_request_round_trip() {
        let rand = [0x23u8; 16];
        let autn = [0xAAu8; 16];
        let encoded = encode_auth_request(7, &rand, &autn);
        let decoded = decode_nas(&encoded).expect("should decode");
        match decoded {
            NasPdu::AuthenticationRequest(d) => {
                assert_eq!(d.nas_ksi, 7);
                assert_eq!(d.rand, rand);
                assert_eq!(d.autn, autn);
            }
            _ => panic!("wrong message type"),
        }
    }

    #[test]
    fn auth_response_round_trip() {
        let res = [0xA5u8, 0x42, 0x11, 0xD5, 0xE3, 0xBA, 0x50, 0xBF];
        let encoded = encode_auth_response(&res);
        let decoded = decode_nas(&encoded).expect("should decode");
        match decoded {
            NasPdu::AuthenticationResponse(d) => {
                assert_eq!(d.res, res);
            }
            _ => panic!("wrong message type"),
        }
    }

    #[test]
    fn attach_request_imsi_round_trip() {
        let imsi = 234_15_1234567890_u64;
        let encoded = encode_attach_request(imsi, 1, 7);
        let decoded = decode_nas(&encoded).expect("should decode");
        match decoded {
            NasPdu::AttachRequest(d) => {
                assert_eq!(d.imsi, Some(imsi), "IMSI should round-trip");
                assert_eq!(d.eps_attach_type, 1);
            }
            _ => panic!("wrong message type"),
        }
    }

    #[test]
    fn sec_mode_command_round_trip() {
        let ue_cap = [0x20u8, 0x40];
        let encoded = encode_sec_mode_cmd(
            NasEeaAlgorithm::Eea2, NasEiaAlgorithm::Eia2, 7, &ue_cap
        );
        let decoded = decode_nas(&encoded).expect("should decode");
        match decoded {
            NasPdu::SecurityModeCommand(d) => {
                assert_eq!(d.eea, NasEeaAlgorithm::Eea2);
                assert_eq!(d.eia, NasEiaAlgorithm::Eia2);
            }
            _ => panic!("wrong message type"),
        }
    }

    #[test]
    fn security_mode_complete_decode() {
        let encoded = encode_sec_mode_complete();
        let decoded = decode_nas(&encoded).expect("should decode");
        assert!(matches!(decoded, NasPdu::SecurityModeComplete));
    }

    #[test]
    fn attach_accept_with_ip() {
        let ip = [10u8, 0, 0, 1];
        let encoded = encode_attach_accept(1, 0x54, &[], Some(ip), Some("internet"));
        let decoded = decode_nas(&encoded).expect("should decode");
        match decoded {
            NasPdu::AttachAccept(d) => {
                assert_eq!(d.ip_address, Some(ip));
                assert_eq!(d.apn.as_deref(), Some("internet"));
            }
            _ => panic!("wrong message type"),
        }
    }

    #[test]
    fn attach_complete_decode() {
        let encoded = encode_attach_complete();
        let decoded = decode_nas(&encoded).expect("should decode");
        assert!(matches!(decoded, NasPdu::AttachComplete));
    }

    #[test]
    fn decode_rejects_wrong_pd() {
        // Protocol discriminator = 0x05 (MM, not EPS-MM)
        let bad = [0x05u8, 0x52, 0x00];
        assert!(decode_nas(&bad).is_err());
    }

    #[test]
    fn detach_request_round_trip_normal() {
        let guti = [0xABu8; 10];
        let encoded = encode_detach_request(1, false, 5, &guti);
        let decoded = decode_nas(&encoded).expect("should decode");
        match decoded {
            NasPdu::DetachRequest(d) => {
                assert_eq!(d.detach_type, 1);
                assert!(!d.switch_off);
                assert_eq!(d.nas_ksi, 5);
            }
            _ => panic!("wrong message type"),
        }
    }

    #[test]
    fn detach_request_switch_off_flag_round_trips() {
        let guti = [0u8; 10];
        let encoded = encode_detach_request(1, true, 0, &guti);
        let decoded = decode_nas(&encoded).expect("should decode");
        match decoded {
            NasPdu::DetachRequest(d) => assert!(d.switch_off),
            _ => panic!("wrong message type"),
        }
    }

    #[test]
    fn detach_accept_decode() {
        let encoded = encode_detach_accept();
        let decoded = decode_nas(&encoded).expect("should decode");
        assert!(matches!(decoded, NasPdu::DetachAccept));
    }

    // ── Protected envelope ─────────────────────────────────────────────────────

    #[test]
    fn encode_protected_envelope_is_well_formed_and_verifiable() {
        let kasme = [0x33u8; 32];
        let mut ctx = NasSecurityContext::new(&kasme, NasEeaAlgorithm::Eea2, NasEiaAlgorithm::Eia2);
        let inner_plain = encode_attach_accept(1, 0x54, &[], Some([10, 0, 0, 1]), Some("internet"));

        let envelope = encode_protected(&mut ctx, SHT_INTEGRITY_CIPHERED, NAS_BEARER, &inner_plain);

        // Header byte: sht in high nibble, PD in low nibble.
        assert_eq!((envelope[0] >> 4) & 0x0F, SHT_INTEGRITY_CIPHERED);
        assert_eq!(envelope[0] & 0x0F, NAS_EPS_MM_PD);
        // Sequence byte = COUNT (first message, COUNT = 0).
        assert_eq!(envelope[5], 0);

        // Independently verify + decrypt using the same derived keys and Downlink direction.
        let (k_enc, k_int) = derive_nas_keys(&kasme, NasEeaAlgorithm::Eea2, NasEiaAlgorithm::Eia2);
        let mac_i: [u8; 4]    = envelope[1..5].try_into().unwrap();
        let ciphertext        = &envelope[6..];
        assert!(crate::nas::security::eia2_verify_mac(
            &k_int, 0, NAS_BEARER, Direction::Downlink, ciphertext, &mac_i,
        ));
        let mut recovered = ciphertext.to_vec();
        eea2_apply(&k_enc, 0, NAS_BEARER, Direction::Downlink, &mut recovered);
        assert_eq!(recovered, inner_plain.to_vec());
    }

    #[test]
    fn decode_protected_recovers_inner_plain_nas_pdu() {
        let kasme = [0x44u8; 32];
        let mut ctx = NasSecurityContext::new(&kasme, NasEeaAlgorithm::Eea2, NasEiaAlgorithm::Eia2);
        let inner_plain = encode_auth_response(&[0xA5, 0x42, 0x11, 0xD5, 0xE3, 0xBA, 0x50, 0xBF]);

        // Build a "UE-sent" envelope by hand: same keys, Uplink direction.
        let (k_enc, k_int) = derive_nas_keys(&kasme, NasEeaAlgorithm::Eea2, NasEiaAlgorithm::Eia2);
        let count = 0u32;
        let mut ciphertext = inner_plain.to_vec();
        eea2_apply(&k_enc, count, NAS_BEARER, Direction::Uplink, &mut ciphertext);
        let mac_i = eia2_compute_mac(&k_int, count, NAS_BEARER, Direction::Uplink, &ciphertext);

        let mut envelope = vec![(SHT_INTEGRITY_CIPHERED << 4) | NAS_EPS_MM_PD];
        envelope.extend_from_slice(&mac_i);
        envelope.push(count as u8);
        envelope.extend_from_slice(&ciphertext);

        let recovered = decode_protected(&mut ctx, &envelope, NAS_BEARER)
            .expect("valid envelope should decode");
        assert_eq!(recovered, inner_plain.to_vec());

        // And it parses as a real NasPdu once unwrapped.
        match decode_nas(&recovered).unwrap() {
            NasPdu::AuthenticationResponse(d) => {
                assert_eq!(d.res, [0xA5, 0x42, 0x11, 0xD5, 0xE3, 0xBA, 0x50, 0xBF]);
            }
            other => panic!("wrong inner PDU type: {other:?}"),
        }
    }

    #[test]
    fn decode_protected_rejects_tampered_envelope() {
        let kasme = [0x66u8; 32];
        let mut ctx = NasSecurityContext::new(&kasme, NasEeaAlgorithm::Eea2, NasEiaAlgorithm::Eia2);
        let inner_plain = encode_sec_mode_complete();

        let (k_enc, k_int) = derive_nas_keys(&kasme, NasEeaAlgorithm::Eea2, NasEiaAlgorithm::Eia2);
        let mut ciphertext = inner_plain.to_vec();
        eea2_apply(&k_enc, 0, NAS_BEARER, Direction::Uplink, &mut ciphertext);
        let mac_i = eia2_compute_mac(&k_int, 0, NAS_BEARER, Direction::Uplink, &ciphertext);

        let mut envelope = vec![(SHT_INTEGRITY_CIPHERED << 4) | NAS_EPS_MM_PD];
        envelope.extend_from_slice(&mac_i);
        envelope.push(0u8);
        envelope.extend_from_slice(&ciphertext);

        // Flip a ciphertext bit — MAC should no longer verify.
        let last = envelope.len() - 1;
        envelope[last] ^= 0x01;

        assert!(decode_protected(&mut ctx, &envelope, NAS_BEARER).is_none());
    }

    #[test]
    fn decode_protected_rejects_too_short_buffer() {
        let kasme = [0x88u8; 32];
        let mut ctx = NasSecurityContext::new(&kasme, NasEeaAlgorithm::Eea2, NasEiaAlgorithm::Eia2);
        assert!(decode_protected(&mut ctx, &[0x27, 0x00], NAS_BEARER).is_none());
    }

    #[test]
    fn decode_protected_rejects_plain_sht() {
        let kasme = [0x11u8; 32];
        let mut ctx = NasSecurityContext::new(&kasme, NasEeaAlgorithm::Eea2, NasEiaAlgorithm::Eia2);
        // sht = 0 in the high nibble — decode_protected should refuse to touch it.
        let buf = [NAS_EPS_MM_PD, 0, 0, 0, 0, 0, 0xAA];
        assert!(decode_protected(&mut ctx, &buf, NAS_BEARER).is_none());
    }

    // ── UE-role (encode_protected_uplink / decode_protected_downlink) ───────────
    // Mirrors nas5gs::codec's own test suite for the identical UE-role pair —
    // same rationale, one level down the stack (LTE instead of 5G).

    #[test]
    fn encode_protected_uplink_decode_protected_downlink_round_trip() {
        let kasme = [0x22u8; 32];
        let mut ue_ctx = NasSecurityContext::new(&kasme, NasEeaAlgorithm::Eea2, NasEiaAlgorithm::Eia2);
        let mut mme_ctx = NasSecurityContext::new(&kasme, NasEeaAlgorithm::Eea2, NasEiaAlgorithm::Eia2);
        let inner_plain = encode_attach_complete();

        // UE encodes uplink (AttachComplete-style)...
        let envelope = encode_protected_uplink(&mut ue_ctx, SHT_INTEGRITY_CIPHERED, NAS_BEARER, &inner_plain);
        // ...MME must decode it with decode_protected (unprotect_uplink), not
        // decode_protected_downlink — that's the network-role function this
        // envelope is meant for.
        let recovered = decode_protected(&mut mme_ctx, &envelope, NAS_BEARER)
            .expect("MME should be able to decode a real UE-role uplink envelope");
        assert_eq!(recovered, inner_plain.to_vec());
    }

    #[test]
    fn decode_protected_downlink_wrong_direction_rejects_even_untampered_envelope() {
        // Same failure mode as nas5gs's own
        // decode_protected_wrong_direction_rejects_even_untampered_envelope,
        // one level down the stack: decode_protected (unprotect_uplink)
        // opening an encode_protected (protect_downlink) envelope always
        // fails on DIRECTION alone, with no tampering involved — the exact
        // gap `mme-sim`'s mock UE would have hit if it tried to decode
        // AttachAccept with the network-role decode_protected.
        let kasme = [0x33u8; 32];
        let mut mme_ctx = NasSecurityContext::new(&kasme, NasEeaAlgorithm::Eea2, NasEiaAlgorithm::Eia2);
        let mut ue_ctx = NasSecurityContext::new(&kasme, NasEeaAlgorithm::Eea2, NasEiaAlgorithm::Eia2);

        let envelope = encode_protected(&mut mme_ctx, SHT_INTEGRITY_CIPHERED, NAS_BEARER, b"AttachAccept-shaped plaintext");
        assert!(decode_protected(&mut ue_ctx, &envelope, NAS_BEARER).is_none(), "wrong-direction decode must fail");
        // decode_protected_downlink (unprotect_downlink) on the SAME
        // envelope must succeed — proof this is genuinely about direction,
        // not a broken envelope.
        let mut ue_ctx2 = NasSecurityContext::new(&kasme, NasEeaAlgorithm::Eea2, NasEiaAlgorithm::Eia2);
        assert!(decode_protected_downlink(&mut ue_ctx2, &envelope, NAS_BEARER).is_some());
    }

    #[test]
    fn protected_envelope_advances_counts_independently_per_direction_ue_role() {
        let kasme = [0x77u8; 32];
        let mut mme_ctx = NasSecurityContext::new(&kasme, NasEeaAlgorithm::Eea2, NasEiaAlgorithm::Eia2);
        let mut ue_ctx = NasSecurityContext::new(&kasme, NasEeaAlgorithm::Eea2, NasEiaAlgorithm::Eia2);

        let first = encode_protected(&mut mme_ctx, SHT_INTEGRITY_CIPHERED, NAS_BEARER, b"one");
        let second = encode_protected(&mut mme_ctx, SHT_INTEGRITY_CIPHERED, NAS_BEARER, b"two");
        assert_ne!(first, second, "COUNT must advance between messages");

        assert!(decode_protected_downlink(&mut ue_ctx, &first, NAS_BEARER).is_some());
        assert!(decode_protected_downlink(&mut ue_ctx, &second, NAS_BEARER).is_some());
    }
        }
