// crates/midn-proto/src/nas/mod.rs
//! NAS — Non-Access Stratum (3GPP TS 24.301 / 24.501)

pub mod codec;
pub mod ie;
pub mod messages;
pub mod security;

pub use codec::{
    decode_nas,
    encode_attach_request,
    encode_attach_accept,          // ← was wrongly named encode_attach_response_accept
    encode_auth_request,
    encode_auth_response,
    encode_sec_mode_cmd,
    encode_sec_mode_complete,
    encode_attach_complete,
    encode_detach_request,
    encode_detach_accept,
    encode_protected,
    decode_protected,
    encode_protected_uplink,
    decode_protected_downlink,
    DecodedAttachAccept,
    DecodedAttachRequest,
    DecodedAuthenticationRequest,
    DecodedAuthenticationResponse,
    DecodedSecurityModeCommand,
    DecodedDetachRequest,
    NasPdu,
    MT_ATTACH_REQUEST,
    MT_AUTHENTICATION_REQUEST,
    MT_AUTHENTICATION_RESPONSE,
    MT_SECURITY_MODE_COMMAND,
    MT_SECURITY_MODE_COMPLETE,
    MT_ATTACH_ACCEPT,
    MT_ATTACH_COMPLETE,
    MT_DETACH_REQUEST,
    MT_DETACH_ACCEPT,
    NAS_EPS_MM_PD,
    SHT_PLAIN,
    SHT_INTEGRITY,
    SHT_INTEGRITY_CIPHERED,
    SHT_INTEGRITY_NEW_CTX,
    SHT_INTEGRITY_CIPHERED_NEW_CTX,
};
pub use ie::{NasEeaAlgorithm, NasEiaAlgorithm};
pub use messages::NasMessage;
pub use security::{
    derive_nas_keys, eea2_apply, eia2_compute_mac, eia2_verify_mac,
    reconstruct_count, Direction, NasSecurityContext, ProtectedNas, NAS_BEARER,
};
