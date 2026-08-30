// crates/midn-proto/src/nas/security.rs
//! NAS security — 128-EEA2 ciphering and 128-EIA2 integrity protection.
//!
//! Implements the algorithms 3GPP actually specifies for EEA2/EIA2:
//!   - **128-EEA2** (TS 35.216 / TS 33.401 Annex B.1.3): AES-128 in CTR mode,
//!     with the initial counter block built from COUNT ‖ BEARER ‖ DIRECTION.
//!   - **128-EIA2** (TS 35.217 / TS 33.401 Annex B.2.3): AES-128-CMAC over
//!     the same COUNT ‖ BEARER ‖ DIRECTION prefix ‖ message, truncated to the
//!     leftmost 32 bits (MAC-I).
//!   - **NAS key derivation** (TS 33.401 Annex A.7): HMAC-SHA-256(Kasme, S),
//!     taking the 128 *least* significant bits of the 256-bit output.
//!
//! ## Wiring status
//!
//! As of the "Wire NAS security into MME" increment, this IS used by
//! `midn_core::mme::attach::handle_security_mode_complete` (derives the
//! context from CK/IK and protects AttachAccept) and `Mme::handle_uplink_nas`
//! (auto-detects + unwraps any protected uplink message via the security
//! header type nibble). See `nas::codec::{encode_protected, decode_protected}`
//! for the wire envelope this rides in.
//!
//! Still simplified / not yet done:
//! - `Kasme` itself is still the placeholder `CK ‖ IK` concatenation from
//!   `midn_core::mme::attach::derive_kasme` (flagged there already as needing
//!   the real TS 33.401 §A.2 KDF). This module is correct *given* a correct
//!   Kasme, but the input it's fed today isn't the real one.
//! - SecurityModeCommand/SecurityModeComplete remain plain NAS — NAS
//!   security activates starting with AttachAccept (the first message sent
//!   after SecurityModeComplete is verified). Real 3GPP also
//!   integrity-protects SecurityModeCommand itself (with the "new EPS
//!   security context" header type, unciphered); modeling that split is a
//!   separate, smaller increment if you want it later.
//! - No official 3GPP TS 35.216/35.217 test vectors are hardcoded below —
//!   see the `#[ignore]` stub at the bottom. Hand-typing crypto constants
//!   from memory and having them silently "pass" is worse than not having
//!   them; the tests here instead verify the implementation's structural
//!   correctness (round-trips, tamper detection, count sensitivity).
//!
//! ## Bearer parameter for NAS
//!
//! TS 33.401 fixes BEARER = 0 for NAS-level security (NAS is per-UE, not
//! per-radio-bearer — BEARER only matters for the RRC/UP security context).
//! Use [`NAS_BEARER`] when calling into this module from NAS code. The
//! low-level functions still take `bearer` as a parameter in case this ever
//! extends to RRC/UP security, where it would be a real radio bearer ID.

use aes::Aes128;
use aes::cipher::generic_array::GenericArray;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::nas::ie::{NasEeaAlgorithm, NasEiaAlgorithm};

/// BEARER value to use for all NAS (non-RRC, non-UP) security operations —
/// TS 33.401: NAS security is per-UE, so BEARER is fixed at 0.
pub const NAS_BEARER: u8 = 0;

/// Direction of the message being protected — part of the EEA2/EIA2 input,
/// not just metadata. The same plaintext ciphers/MACs differently depending
/// on which way it's travelling.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Direction {
    Uplink   = 0,
    Downlink = 1,
}

// ── 128-EEA2 (AES-128 CTR) ──────────────────────────────────────────────────

type Aes128Ctr = ctr::Ctr128BE<Aes128>;

/// Build the 128-bit initial counter block for 128-EEA2 (TS 35.216 §3 /
/// TS 33.401 Annex B.1.3).
///
/// Layout:
/// ```text
/// bytes 0-3  : COUNT, big-endian
/// byte  4    : BEARER (bits 7-3) | DIRECTION (bit 2) | 0 0 (bits 1-0)
/// bytes 5-15 : zero
/// ```
/// This block IS the AES-CTR initial counter — `Ctr128BE` increments the
/// full 128 bits as a big-endian integer per subsequent block, which is
/// exactly what the spec's counter-mode construction requires.
fn eea2_counter_block(count: u32, bearer: u8, direction: Direction) -> [u8; 16] {
    let mut cb = [0u8; 16];
    cb[0..4].copy_from_slice(&count.to_be_bytes());
    cb[4] = ((bearer & 0x1F) << 3) | (((direction as u8) & 0x01) << 2);
    cb
}

/// Apply the 128-EEA2 keystream to `data` in place.
///
/// CTR mode is its own inverse — calling this twice with the same
/// (key, count, bearer, direction) on ciphertext recovers the plaintext.
/// There is deliberately no separate "decrypt" function.
pub fn eea2_apply(key: &[u8; 16], count: u32, bearer: u8, direction: Direction, data: &mut [u8]) {
    use ctr::cipher::{KeyIvInit, StreamCipher};
    let cb      = eea2_counter_block(count, bearer, direction);
    let key_arr = GenericArray::from_slice(key);
    let iv_arr  = GenericArray::from_slice(&cb);
    let mut cipher = Aes128Ctr::new(key_arr, iv_arr);
    cipher.apply_keystream(data);
}

// ── 128-EIA2 (AES-128 CMAC) ─────────────────────────────────────────────────

/// Compute the 128-EIA2 MAC-I — the leftmost 32 bits of AES-128-CMAC over
/// COUNT ‖ BEARER/DIRECTION-byte ‖ `message` (TS 35.217 §3 / TS 33.401
/// Annex B.2.3).
pub fn eia2_compute_mac(
    key:       &[u8; 16],
    count:     u32,
    bearer:    u8,
    direction: Direction,
    message:   &[u8],
) -> [u8; 4] {
    use cmac::{Cmac, Mac};

    let mut prefix = [0u8; 5];
    prefix[0..4].copy_from_slice(&count.to_be_bytes());
    prefix[4] = ((bearer & 0x1F) << 3) | (((direction as u8) & 0x01) << 2);

    let mut mac = Cmac::<Aes128>::new_from_slice(key)
        .expect("AES-128 key is always the correct length");
    mac.update(&prefix);
    mac.update(message);
    let tag = mac.finalize().into_bytes();

    let mut mac_i = [0u8; 4];
    mac_i.copy_from_slice(&tag[0..4]);
    mac_i
}

/// Constant-time MAC-I verification.
///
/// SECURITY (Rule 1 — platform-optimization.md): never compare MAC values
/// with `==`. A timing oracle on NAS integrity verification is the same
/// class of attack as a timing oracle on RES verification.
pub fn eia2_verify_mac(
    key:          &[u8; 16],
    count:        u32,
    bearer:       u8,
    direction:    Direction,
    message:      &[u8],
    received_mac: &[u8; 4],
) -> bool {
    use subtle::ConstantTimeEq;
    let expected = eia2_compute_mac(key, count, bearer, direction, message);
    bool::from(expected.ct_eq(received_mac))
}

// ── NAS key derivation (TS 33.401 Annex A.7) ────────────────────────────────

type HmacSha256 = hmac::Hmac<sha2::Sha256>;

const FC_NAS_ALGO_KEY_DERIVATION: u8 = 0x15;
const ALGO_DISTINGUISHER_NAS_ENC: u8 = 0x01;
const ALGO_DISTINGUISHER_NAS_INT: u8 = 0x02;

/// KDF(Kasme, S) → 256 bits; the derived 128-bit NAS key is the 128 LEAST
/// significant bits of that output (TS 33.401 Annex A.7).
///
/// `S = FC ‖ P0 ‖ L0 ‖ P1 ‖ L1`:
///   FC = 0x15 (NAS algorithm key derivation)
///   P0 = algorithm type distinguisher (0x01 enc / 0x02 int), L0 = 0x0001
///   P1 = algorithm identity (e.g. 2 for *EA2/*IA2),           L1 = 0x0001
fn kdf_nas_key(kasme: &[u8; 32], algorithm_distinguisher: u8, algorithm_identity: u8) -> [u8; 16] {
    use hmac::Mac;

    let mut s = Vec::with_capacity(7);
    s.push(FC_NAS_ALGO_KEY_DERIVATION);
    s.push(algorithm_distinguisher);
    s.extend_from_slice(&1u16.to_be_bytes()); // L0 = len(P0) = 1 byte
    s.push(algorithm_identity);
    s.extend_from_slice(&1u16.to_be_bytes()); // L1 = len(P1) = 1 byte

    let mut mac = HmacSha256::new_from_slice(kasme)
        .expect("HMAC-SHA-256 accepts a 32-byte key");
    mac.update(&s);
    let out = mac.finalize().into_bytes(); // 32 bytes

    let mut key = [0u8; 16];
    key.copy_from_slice(&out[16..32]); // least-significant 128 bits
    key
}

/// Derive both NAS session keys from Kasme for the negotiated algorithm pair.
pub fn derive_nas_keys(
    kasme: &[u8; 32],
    eea:   NasEeaAlgorithm,
    eia:   NasEiaAlgorithm,
) -> ([u8; 16], [u8; 16]) {
    let k_nas_enc = kdf_nas_key(kasme, ALGO_DISTINGUISHER_NAS_ENC, eea as u8);
    let k_nas_int = kdf_nas_key(kasme, ALGO_DISTINGUISHER_NAS_INT, eia as u8);
    (k_nas_enc, k_nas_int)
}

// ── NAS COUNT reconstruction ─────────────────────────────────────────────────

/// Reconstruct the full 32-bit NAS COUNT from a received low-order sequence
/// byte (TS 24.301 §4.4.3.1 — only the low octet of COUNT travels on the
/// wire; the receiver tracks the high 24 bits locally).
///
/// Picks the smallest full COUNT (using the current high bits, or high bits
/// + 1 on apparent wraparound) that is `>= last_count` and whose low byte
/// matches `received_seq_byte`.
pub fn reconstruct_count(last_count: u32, received_seq_byte: u8) -> u32 {
    let high      = last_count & 0xFFFF_FF00;
    let candidate = high | (received_seq_byte as u32);
    if candidate >= last_count {
        candidate
    } else {
        high.wrapping_add(0x100) | (received_seq_byte as u32)
    }
}

// ── NasSecurityContext ───────────────────────────────────────────────────────

/// Result of protecting one outbound NAS message: the COUNT it consumed,
/// the computed MAC-I, and the (possibly ciphered) payload bytes.
#[derive(Debug, Clone)]
pub struct ProtectedNas {
    pub count:   u32,
    pub mac_i:   [u8; 4],
    pub payload: Vec<u8>,
}

/// Per-subscriber NAS security state — derived keys + algorithm choice +
/// independently-tracked uplink/downlink COUNT.
///
/// Order of operations is **encrypt-then-MAC** on protect, **verify-then-decrypt**
/// on unprotect — MAC-I covers the ciphertext, and a message is never
/// deciphered before its integrity is confirmed.
///
/// Keys are zeroized on drop. `Clone` is provided so `Mme`'s
/// clone-mutate-reinsert pattern for `AttachContext` (see
/// `midn_core::mme::state_machine::World::get_attach_context`) keeps working
/// once this is embedded in it — same tradeoff already accepted for
/// `AuthKey`/`OpCode` elsewhere in the workspace.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct NasSecurityContext {
    pub k_nas_enc: [u8; 16],
    pub k_nas_int: [u8; 16],
    #[zeroize(skip)]
    pub eea: NasEeaAlgorithm,
    #[zeroize(skip)]
    pub eia: NasEiaAlgorithm,
    dl_count: u32,
    ul_count: u32,
}

impl NasSecurityContext {
    /// Derive a fresh security context from Kasme and the algorithms agreed
    /// in SecurityModeCommand/Complete. Both COUNTs start at 0.
    pub fn new(kasme: &[u8; 32], eea: NasEeaAlgorithm, eia: NasEiaAlgorithm) -> Self {
        let (k_nas_enc, k_nas_int) = derive_nas_keys(kasme, eea, eia);
        Self { k_nas_enc, k_nas_int, eea, eia, dl_count: 0, ul_count: 0 }
    }

    pub fn dl_count(&self) -> u32 { self.dl_count }
    pub fn ul_count(&self) -> u32 { self.ul_count }

    /// Protect an outbound (MME → UE) message. Consumes and advances the
    /// downlink COUNT.
    pub fn protect_downlink(&mut self, bearer: u8, plain: &[u8]) -> ProtectedNas {
        let count = self.dl_count;
        self.dl_count = self.dl_count.wrapping_add(1);
        self.protect(count, bearer, Direction::Downlink, plain)
    }

    /// Verify and decrypt an inbound (UE → MME) message.
    ///
    /// `seq_byte` is the low-order COUNT byte carried on the wire; the full
    /// COUNT is reconstructed against the locally tracked `ul_count`. On
    /// success, `ul_count` is advanced past the accepted COUNT — a message
    /// at or below the last accepted COUNT will reconstruct to a candidate
    /// `>= ul_count` per [`reconstruct_count`], so a stale replay either
    /// fails the MAC check or (if somehow re-signed) still can't move COUNT
    /// backward. This is a simplified monotonic check appropriate for the
    /// simulation, not the full TS 24.301 §4.4.3.5 replay window.
    pub fn unprotect_uplink(
        &mut self,
        bearer:     u8,
        seq_byte:   u8,
        mac_i:      [u8; 4],
        ciphertext: &[u8],
    ) -> Option<Vec<u8>> {
        let count = reconstruct_count(self.ul_count, seq_byte);
        let plain = self.unprotect(count, bearer, Direction::Uplink, mac_i, ciphertext)?;
        self.ul_count = count.wrapping_add(1);
        Some(plain)
    }

    /// Protect an outbound (UE → MME) message. Consumes and advances the
    /// uplink COUNT. UE-role mirror of `protect_downlink` — the DIRECTION
    /// bit that feeds `eea2_apply`/`eia2_compute_mac` is a property of which
    /// way a given message travels, not of which side is doing the
    /// encrypting, so a genuine UE-role caller (`mme-sim`'s mock UE) needs
    /// its own uplink-tagged protect, not a relabeled `protect_downlink`.
    /// Mirrors `nas5gs::security::Nas5gsSecurityContext::protect_uplink`
    /// exactly, one level down the stack — this codebase closed the
    /// identical gap on the 5G side already; this closes it on the LTE
    /// side. See `codec::encode_protected_uplink`.
    pub fn protect_uplink(&mut self, bearer: u8, plain: &[u8]) -> ProtectedNas {
        let count = self.ul_count;
        self.ul_count = self.ul_count.wrapping_add(1);
        self.protect(count, bearer, Direction::Uplink, plain)
    }

    /// Verify and decrypt an inbound (MME → UE) message. UE-role mirror of
    /// `unprotect_uplink` — reconstructs COUNT off `dl_count` and verifies
    /// with `Direction::Downlink`, matching what the network side used in
    /// `protect_downlink` for the same message. Using `unprotect_uplink`
    /// here instead (same COUNT baseline, wrong DIRECTION) would compute a
    /// different keystream/MAC than the sender did and always fail — see
    /// `nas5gs::security::Nas5gsSecurityContext::unprotect_downlink`'s doc
    /// for the fuller rationale, identical here one level down the stack.
    /// See `codec::decode_protected_downlink`.
    pub fn unprotect_downlink(
        &mut self,
        bearer:     u8,
        seq_byte:   u8,
        mac_i:      [u8; 4],
        ciphertext: &[u8],
    ) -> Option<Vec<u8>> {
        let count = reconstruct_count(self.dl_count, seq_byte);
        let plain = self.unprotect(count, bearer, Direction::Downlink, mac_i, ciphertext)?;
        self.dl_count = count.wrapping_add(1);
        Some(plain)
    }

    fn protect(&self, count: u32, bearer: u8, dir: Direction, plain: &[u8]) -> ProtectedNas {
        let mut payload = plain.to_vec();
        if self.eea != NasEeaAlgorithm::Eea0 {
            eea2_apply(&self.k_nas_enc, count, bearer, dir, &mut payload);
        }
        let mac_i = if self.eia != NasEiaAlgorithm::Eia0 {
            eia2_compute_mac(&self.k_nas_int, count, bearer, dir, &payload)
        } else {
            [0u8; 4]
        };
        ProtectedNas { count, mac_i, payload }
    }

    fn unprotect(
        &self,
        count:      u32,
        bearer:     u8,
        dir:        Direction,
        mac_i:      [u8; 4],
        ciphertext: &[u8],
    ) -> Option<Vec<u8>> {
        if self.eia != NasEiaAlgorithm::Eia0
            && !eia2_verify_mac(&self.k_nas_int, count, bearer, dir, ciphertext, &mac_i)
        {
            return None;
        }
        let mut payload = ciphertext.to_vec();
        if self.eea != NasEeaAlgorithm::Eea0 {
            eea2_apply(&self.k_nas_enc, count, bearer, dir, &mut payload);
        }
        Some(payload)
    }
}

impl core::fmt::Debug for NasSecurityContext {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        // Never print k_nas_enc/k_nas_int — they're session secrets, same
        // redaction pattern as AuthVector in midn-auth.
        f.debug_struct("NasSecurityContext")
            .field("eea", &self.eea)
            .field("eia", &self.eia)
            .field("dl_count", &self.dl_count)
            .field("ul_count", &self.ul_count)
            .field("k_nas_enc", &"[REDACTED]")
            .field("k_nas_int", &"[REDACTED]")
            .finish()
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn k() -> [u8; 16] {
        [0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
         0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00]
    }

    // ── 128-EEA2 ──────────────────────────────────────────────────────────────

    #[test]
    fn eea2_round_trip_recovers_plaintext() {
        let key   = k();
        let plain = b"AttachAccept payload bytes go here".to_vec();
        let mut buf = plain.clone();

        eea2_apply(&key, 0, NAS_BEARER, Direction::Downlink, &mut buf);
        assert_ne!(buf, plain, "ciphertext should differ from plaintext");

        eea2_apply(&key, 0, NAS_BEARER, Direction::Downlink, &mut buf);
        assert_eq!(buf, plain, "second pass with identical params recovers plaintext");
    }

    #[test]
    fn eea2_different_count_gives_different_ciphertext() {
        let key   = k();
        let plain = b"same plaintext, different count".to_vec();
        let mut a = plain.clone();
        let mut b = plain.clone();
        eea2_apply(&key, 0, NAS_BEARER, Direction::Downlink, &mut a);
        eea2_apply(&key, 1, NAS_BEARER, Direction::Downlink, &mut b);
        assert_ne!(a, b);
    }

    #[test]
    fn eea2_different_direction_gives_different_ciphertext() {
        let key   = k();
        let plain = b"same count, different direction".to_vec();
        let mut a = plain.clone();
        let mut b = plain.clone();
        eea2_apply(&key, 5, NAS_BEARER, Direction::Uplink,   &mut a);
        eea2_apply(&key, 5, NAS_BEARER, Direction::Downlink, &mut b);
        assert_ne!(a, b);
    }

    // ── 128-EIA2 ──────────────────────────────────────────────────────────────

    #[test]
    fn eia2_mac_is_deterministic() {
        let key = k();
        let msg = b"integrity protect me";
        let m1  = eia2_compute_mac(&key, 7, NAS_BEARER, Direction::Downlink, msg);
        let m2  = eia2_compute_mac(&key, 7, NAS_BEARER, Direction::Downlink, msg);
        assert_eq!(m1, m2);
    }

    #[test]
    fn eia2_mac_changes_with_count() {
        let key = k();
        let msg = b"integrity protect me";
        let m1  = eia2_compute_mac(&key, 7, NAS_BEARER, Direction::Downlink, msg);
        let m2  = eia2_compute_mac(&key, 8, NAS_BEARER, Direction::Downlink, msg);
        assert_ne!(m1, m2);
    }

    #[test]
    fn eia2_verify_accepts_correct_mac() {
        let key = k();
        let msg = b"valid message";
        let mac = eia2_compute_mac(&key, 3, NAS_BEARER, Direction::Uplink, msg);
        assert!(eia2_verify_mac(&key, 3, NAS_BEARER, Direction::Uplink, msg, &mac));
    }

    #[test]
    fn eia2_verify_rejects_tampered_message() {
        let key     = k();
        let msg     = b"valid message".to_vec();
        let mac     = eia2_compute_mac(&key, 3, NAS_BEARER, Direction::Uplink, &msg);
        let mut bad = msg.clone();
        bad[0] ^= 0x01;
        assert!(!eia2_verify_mac(&key, 3, NAS_BEARER, Direction::Uplink, &bad, &mac));
    }

    #[test]
    fn eia2_verify_rejects_tampered_mac() {
        let key = k();
        let msg = b"valid message";
        let mut mac = eia2_compute_mac(&key, 3, NAS_BEARER, Direction::Uplink, msg);
        mac[0] ^= 0x01;
        assert!(!eia2_verify_mac(&key, 3, NAS_BEARER, Direction::Uplink, msg, &mac));
    }

    // ── KDF ───────────────────────────────────────────────────────────────────

    #[test]
    fn kdf_is_deterministic() {
        let kasme = [0xAB; 32];
        let (a1, a2) = derive_nas_keys(&kasme, NasEeaAlgorithm::Eea2, NasEiaAlgorithm::Eia2);
        let (b1, b2) = derive_nas_keys(&kasme, NasEeaAlgorithm::Eea2, NasEiaAlgorithm::Eia2);
        assert_eq!(a1, b1);
        assert_eq!(a2, b2);
    }

    #[test]
    fn kdf_enc_and_int_keys_differ() {
        let kasme = [0xCD; 32];
        let (k_enc, k_int) = derive_nas_keys(&kasme, NasEeaAlgorithm::Eea2, NasEiaAlgorithm::Eia2);
        assert_ne!(k_enc, k_int, "enc and int keys must use different KDF inputs");
    }

    #[test]
    fn kdf_changes_with_kasme() {
        let (a, _) = derive_nas_keys(&[0x01; 32], NasEeaAlgorithm::Eea2, NasEiaAlgorithm::Eia2);
        let (b, _) = derive_nas_keys(&[0x02; 32], NasEeaAlgorithm::Eea2, NasEiaAlgorithm::Eia2);
        assert_ne!(a, b);
    }

    // ── COUNT reconstruction ──────────────────────────────────────────────────

    #[test]
    fn reconstruct_count_no_wrap() {
        // last_count's high bits still apply; received byte just below.
        assert_eq!(reconstruct_count(0x0000_0010, 0x20), 0x0000_0020);
    }

    #[test]
    fn reconstruct_count_handles_wraparound() {
        // last_count = 0x...01F0 (low byte 0xF0). Next message's low byte
        // wrapped past 0xFF back to 0x05 — high bits must bump by one.
        let last = 0x0000_01F0;
        let got  = reconstruct_count(last, 0x05);
        assert_eq!(got, 0x0000_0205);
    }

    #[test]
    fn reconstruct_count_same_high_bits_when_byte_increases() {
        let last = 0x0000_0150;
        let got  = reconstruct_count(last, 0x60);
        assert_eq!(got, 0x0000_0160);
    }

    // ── NasSecurityContext: MME→UE path (manual verify with raw functions) ────

    #[test]
    fn context_protect_downlink_is_verifiable_independently() {
        let kasme = [0x42; 32];
        let mut ctx = NasSecurityContext::new(&kasme, NasEeaAlgorithm::Eea2, NasEiaAlgorithm::Eia2);
        let plain = b"AttachAccept goes here".to_vec();

        let protected = ctx.protect_downlink(NAS_BEARER, &plain);
        assert_eq!(protected.count, 0);
        assert_eq!(ctx.dl_count(), 1, "dl_count must advance after protect");

        // Verify independently using the raw functions + the same derived keys.
        let (k_enc, k_int) = derive_nas_keys(&kasme, NasEeaAlgorithm::Eea2, NasEiaAlgorithm::Eia2);
        assert!(eia2_verify_mac(
            &k_int, protected.count, NAS_BEARER, Direction::Downlink,
            &protected.payload, &protected.mac_i,
        ));

        let mut recovered = protected.payload.clone();
        eea2_apply(&k_enc, protected.count, NAS_BEARER, Direction::Downlink, &mut recovered);
        assert_eq!(recovered, plain);
    }

    // ── NasSecurityContext: UE→MME path (manual protect, real unprotect) ──────

    #[test]
    fn context_unprotect_uplink_round_trip() {
        let kasme = [0x99; 32];
        let mut ctx = NasSecurityContext::new(&kasme, NasEeaAlgorithm::Eea2, NasEiaAlgorithm::Eia2);
        let plain = b"AuthenticationResponse RES goes here".to_vec();

        // Simulate the "UE side": protect with the SAME derived keys, Uplink direction.
        let (k_enc, k_int) = derive_nas_keys(&kasme, NasEeaAlgorithm::Eea2, NasEiaAlgorithm::Eia2);
        let count = 0u32;
        let mut ciphertext = plain.clone();
        eea2_apply(&k_enc, count, NAS_BEARER, Direction::Uplink, &mut ciphertext);
        let mac_i = eia2_compute_mac(&k_int, count, NAS_BEARER, Direction::Uplink, &ciphertext);

        let recovered = ctx
            .unprotect_uplink(NAS_BEARER, count as u8, mac_i, &ciphertext)
            .expect("valid MAC should verify");
        assert_eq!(recovered, plain);
        assert_eq!(ctx.ul_count(), 1, "ul_count must advance after successful unprotect");
    }

    #[test]
    fn context_unprotect_uplink_rejects_bad_mac() {
        let kasme = [0x77; 32];
        let mut ctx = NasSecurityContext::new(&kasme, NasEeaAlgorithm::Eea2, NasEiaAlgorithm::Eia2);
        let plain = b"tampered message".to_vec();

        let (k_enc, _) = derive_nas_keys(&kasme, NasEeaAlgorithm::Eea2, NasEiaAlgorithm::Eia2);
        let mut ciphertext = plain.clone();
        eea2_apply(&k_enc, 0, NAS_BEARER, Direction::Uplink, &mut ciphertext);

        let bad_mac = [0xFF; 4];
        assert!(ctx.unprotect_uplink(NAS_BEARER, 0, bad_mac, &ciphertext).is_none());
        assert_eq!(ctx.ul_count(), 0, "ul_count must NOT advance on a rejected message");
    }

    #[test]
    fn eea0_eia0_null_algorithms_pass_through_unciphered() {
        let kasme = [0x55; 32];
        let mut ctx = NasSecurityContext::new(&kasme, NasEeaAlgorithm::Eea0, NasEiaAlgorithm::Eia0);
        let plain = b"null algorithms still envelope correctly".to_vec();

        let protected = ctx.protect_downlink(NAS_BEARER, &plain);
        assert_eq!(protected.payload, plain, "Eea0 must not cipher");
        assert_eq!(protected.mac_i, [0u8; 4], "Eia0 must produce a zero MAC-I");
    }

    // ── Official spec test vectors — not yet sourced ──────────────────────────

    #[test]
    #[ignore = "fill in real 3GPP TS 35.216 (128-EEA2) / TS 35.217 (128-EIA2) test vectors"]
    fn official_3gpp_test_vectors() {
        // The tests above validate the implementation's structural
        // correctness (round-trips, count/direction sensitivity, tamper
        // detection) but do NOT confirm byte-for-byte conformance against
        // the official spec test sets. Pull the real KEY/COUNT/BEARER/
        // DIRECTION/MESSAGE/expected-output values from TS 35.216 Annex 4
        // and TS 35.217 Annex 4 and assert against them here, same pattern
        // as midn-auth::milenage's test_set_4..6.
        todo!()
    }
    }
