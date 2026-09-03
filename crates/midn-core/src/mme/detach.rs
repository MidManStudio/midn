// crates/midn-core/src/mme/detach.rs
//! UE-initiated detach procedure — 3GPP TS 23.401 Section 5.3.8.2 /
//! TS 24.301 Section 5.5.2.2.
//!
//! ## Sequence
//!
//! ```text
//! UE → MME      : NAS DetachRequest          (via UplinkNasTransport)
//! MME → UE      : NAS DetachAccept            (skipped if switch_off — the UE
//!                                               is powering down and will not
//!                                               process a reply; protected if
//!                                               NAS security is already active)
//! MME → eNodeB  : S1AP UeContextReleaseCommand
//! eNodeB → MME  : S1AP UeContextReleaseComplete
//! ```
//!
//! The actual teardown (entity despawn, IMSI deregister, `UpfEvent::RemoveSession`,
//! TEID release) happens on `UeContextReleaseComplete`, handled by
//! `state_machine::Mme::handle_release_complete` — the SAME code path used for
//! network-initiated release. This module only drives the *trigger*.

use midn_proto::nas::{
    decode_nas, encode_detach_accept, encode_protected,
    NasPdu, NAS_BEARER, SHT_INTEGRITY_CIPHERED,
};
use midn_proto::s1ap::{DownlinkNasTransport, S1apCause, S1apMessage};
use midn_ecs::World;

/// Process an `UplinkNasTransport` whose NAS PDU is a `DetachRequest`.
pub fn handle_detach_request(
    world:          &mut World,
    enb_ue_s1ap_id: u32,
    mme_ue_s1ap_id: u32,
    nas_pdu:        &[u8],
) -> Vec<S1apMessage> {
    let switch_off = match decode_nas(nas_pdu) {
        Ok(NasPdu::DetachRequest(d)) => d.switch_off,
        _ => {
            tracing::warn!(mme_ue_s1ap_id, "handle_detach_request: bad NAS PDU");
            return vec![];
        }
    };

    if !world.is_live(mme_ue_s1ap_id) {
        tracing::warn!(mme_ue_s1ap_id, "handle_detach_request: no context for entity");
        return vec![];
    }

    let mut out = Vec::with_capacity(2);

    if !switch_off {
        let detach_accept_plain = encode_detach_accept();

        let nas_pdu_out = match world.nas_security_mut(mme_ue_s1ap_id) {
            Some(nas_ctx) => encode_protected(
                nas_ctx, SHT_INTEGRITY_CIPHERED, NAS_BEARER, &detach_accept_plain,
            ),
            None => {
                tracing::debug!(
                    mme_ue_s1ap_id,
                    "handle_detach_request: no NAS security context — sending DetachAccept plain"
                );
                detach_accept_plain
            }
        };

        out.push(S1apMessage::DownlinkNasTransport(DownlinkNasTransport {
            enb_ue_s1ap_id,
            mme_ue_s1ap_id,
            nas_pdu: nas_pdu_out,
        }));
    }

    out.push(S1apMessage::UeContextReleaseCommand {
        mme_ue_s1ap_id, enb_ue_s1ap_id, cause: S1apCause::NasDetach,
    });

    tracing::info!(
        mme_ue_s1ap_id, switch_off,
        "DetachRequest processed — UeContextReleaseCommand issued"
    );
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use midn_ecs::{IdentityComponent, SecurityContext};
    use midn_proto::nas::{
        decode_nas, derive_nas_keys, eea2_apply, eia2_verify_mac, Direction,
        NasEeaAlgorithm, NasEiaAlgorithm, NasPdu, NasSecurityContext,
    };
    use midn_proto::nas::encode_detach_request;

    fn world_with_entity() -> (World, u32) {
        let mut w = World::new();
        let entity = w.spawn();
        w.insert_identity(entity, IdentityComponent {
            imsi: 1, enb_ue_s1ap_id: 0, ue_ip: [0; 4],
        });
        w.insert_security(entity, SecurityContext::new_empty());
        (w, entity)
    }

    #[test]
    fn normal_detach_sends_accept_then_release_command() {
        let (mut world, entity) = world_with_entity();
        let nas_pdu = encode_detach_request(1, false, 0, &[0; 10]);
        let out     = handle_detach_request(&mut world, 1, entity, &nas_pdu);

        assert_eq!(out.len(), 2, "expect DetachAccept + UeContextReleaseCommand");
        assert!(matches!(out[0], S1apMessage::DownlinkNasTransport(_)));
        assert!(matches!(
            out[1],
            S1apMessage::UeContextReleaseCommand { mme_ue_s1ap_id, enb_ue_s1ap_id: 1, cause: S1apCause::NasDetach }
            if mme_ue_s1ap_id == entity
        ));
    }

    #[test]
    fn switch_off_detach_skips_accept() {
        let (mut world, entity) = world_with_entity();
        let nas_pdu = encode_detach_request(1, true, 0, &[0; 10]);
        let out     = handle_detach_request(&mut world, 1, entity, &nas_pdu);

        assert_eq!(out.len(), 1, "switch-off skips DetachAccept");
        assert!(matches!(
            out[0],
            S1apMessage::UeContextReleaseCommand { mme_ue_s1ap_id, enb_ue_s1ap_id: 1, cause: S1apCause::NasDetach }
            if mme_ue_s1ap_id == entity
        ));
    }

    #[test]
    fn detach_for_unknown_entity_is_noop() {
        let mut world = World::new();
        let nas_pdu   = encode_detach_request(1, false, 0, &[0; 10]);
        let out       = handle_detach_request(&mut world, 1, 999, &nas_pdu);
        assert!(out.is_empty());
    }

    #[test]
    fn bad_nas_pdu_is_noop() {
        let (mut world, entity) = world_with_entity();
        let out = handle_detach_request(&mut world, 1, entity, &[0xFF, 0xFF]);
        assert!(out.is_empty());
    }

    #[test]
    fn detach_accept_is_protected_when_nas_security_is_active() {
        let kasme = [0x5Au8; 32];
        let mut world = World::new();
        let entity = world.spawn();
        world.insert_identity(entity, IdentityComponent {
            imsi: 1, enb_ue_s1ap_id: 0, ue_ip: [0; 4],
        });
        world.insert_security(entity, SecurityContext::new_empty());
        world.set_nas_security(entity, NasSecurityContext::new(
            &kasme, NasEeaAlgorithm::Eea2, NasEiaAlgorithm::Eia2,
        ));

        let nas_pdu = encode_detach_request(1, false, 0, &[0; 10]);
        let out     = handle_detach_request(&mut world, 1, entity, &nas_pdu);

        assert_eq!(out.len(), 2);
        let envelope = match &out[0] {
            S1apMessage::DownlinkNasTransport(m) => m.nas_pdu.clone(),
            _ => panic!("expected DownlinkNasTransport"),
        };

        let sht = (envelope[0] >> 4) & 0x0F;
        assert_ne!(sht, 0, "DetachAccept should be protected once NAS security is active");

        let mac_i: [u8; 4] = envelope[1..5].try_into().unwrap();
        let count           = envelope[5] as u32;
        let mut ciphertext  = envelope[6..].to_vec();

        let (k_enc, k_int) = derive_nas_keys(&kasme, NasEeaAlgorithm::Eea2, NasEiaAlgorithm::Eia2);
        assert!(eia2_verify_mac(&k_int, count, NAS_BEARER, Direction::Downlink, &ciphertext, &mac_i));

        eea2_apply(&k_enc, count, NAS_BEARER, Direction::Downlink, &mut ciphertext);
        assert!(matches!(decode_nas(&ciphertext).unwrap(), NasPdu::DetachAccept));
    }
            }
