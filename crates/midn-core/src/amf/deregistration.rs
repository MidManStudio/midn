// crates/midn-core/src/amf/deregistration.rs
//! UE-initiated deregistration procedure — 3GPP TS 23.502 §4.2.2.3 /
//! TS 24.501 §5.5.2.2. 5G counterpart to `mme::detach`.
//!
//! ## Sequence
//!
//! ```text
//! UE → AMF      : NAS DeregistrationRequest    (via UplinkNasTransport)
//! AMF → UE      : NAS DeregistrationAccept      (skipped if switch_off — the UE
//!                                                 is powering down and will not
//!                                                 process a reply; protected if
//!                                                 NAS security is already active)
//! AMF → gNodeB  : NGAP UeContextReleaseCommand
//! gNodeB → AMF  : NGAP UeContextReleaseComplete
//! ```
//!
//! The actual teardown (entity despawn, IMSI deregister, `N3Event::RemoveSession`,
//! TEID release) happens on `UeContextReleaseComplete`, handled by
//! `state_machine::Amf::handle_release_complete` — the SAME shape
//! `mme::state_machine::handle_release_complete` uses for LTE (this module
//! only drives the *trigger*, exactly mirroring `mme::detach`'s own doc on
//! that split).
//!
//! Models the UE-originating direction only — same simplification
//! `nas5gs::codec`'s Deregistration Request/Accept doc already flags for the
//! NAS layer this module decodes: network-initiated deregistration isn't
//! modeled here either.

use midn_ecs::World;
use midn_proto::nas5gs::{
    decode_nas5gs, encode_deregistration_accept, encode_protected, Nas5gsPdu,
    NAS5GS_SHT_INTEGRITY_CIPHERED,
};
use midn_proto::ngap::messages::{NgapCause, NgapDownlinkNasTransport, NgapMessage};

/// Process an `UplinkNasTransport` whose NAS PDU is a `DeregistrationRequest`.
pub fn handle_deregistration_request(
    world: &mut World,
    ran_ue_ngap_id: u32,
    amf_ue_ngap_id: u32,
    nas_pdu: &[u8],
) -> Vec<NgapMessage> {
    let switch_off = match decode_nas5gs(nas_pdu) {
        Ok(Nas5gsPdu::DeregistrationRequest { switch_off }) => switch_off,
        _ => {
            tracing::warn!(amf_ue_ngap_id, "handle_deregistration_request: bad NAS PDU");
            return vec![];
        }
    };

    if !world.is_live(amf_ue_ngap_id) {
        tracing::warn!(amf_ue_ngap_id, "handle_deregistration_request: no context for entity");
        return vec![];
    }

    let mut out = Vec::with_capacity(2);

    if !switch_off {
        let deregistration_accept_plain = encode_deregistration_accept();

        let nas_pdu_out = match world.nas_security5g_mut(amf_ue_ngap_id) {
            Some(nas_ctx) => encode_protected(
                nas_ctx, NAS5GS_SHT_INTEGRITY_CIPHERED, &deregistration_accept_plain,
            ),
            None => {
                tracing::debug!(
                    amf_ue_ngap_id,
                    "handle_deregistration_request: no NAS security context — sending DeregistrationAccept plain"
                );
                deregistration_accept_plain
            }
        };

        out.push(NgapMessage::DownlinkNasTransport(NgapDownlinkNasTransport {
            amf_ue_ngap_id,
            ran_ue_ngap_id,
            nas_pdu: nas_pdu_out,
        }));
    }

    out.push(NgapMessage::UeContextReleaseCommand { cause: NgapCause::NasDeregister });

    tracing::info!(
        amf_ue_ngap_id, switch_off,
        "DeregistrationRequest processed — UeContextReleaseCommand issued"
    );
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use midn_ecs::IdentityComponent;
    use midn_proto::nas5gs::{
        decode_protected_downlink, encode_deregistration_request, Nas5gsSecurityContext,
        NAS5GS_SHT_PLAIN,
    };

    fn world_with_entity() -> (World, u32) {
        let mut w = World::new();
        let entity = w.spawn();
        w.insert_identity(entity, IdentityComponent {
            imsi: 1, enb_ue_s1ap_id: 0, ue_ip: [0; 4],
        });
        (w, entity)
    }

    #[test]
    fn normal_deregistration_sends_accept_then_release_command() {
        let (mut world, entity) = world_with_entity();
        let nas_pdu = encode_deregistration_request(false);
        let out = handle_deregistration_request(&mut world, 1, entity, &nas_pdu);

        assert_eq!(out.len(), 2, "expect DeregistrationAccept + UeContextReleaseCommand");
        assert!(matches!(out[0], NgapMessage::DownlinkNasTransport(_)));
        assert!(matches!(
            out[1],
            NgapMessage::UeContextReleaseCommand { cause: NgapCause::NasDeregister }
        ));
    }

    #[test]
    fn switch_off_deregistration_skips_accept() {
        let (mut world, entity) = world_with_entity();
        let nas_pdu = encode_deregistration_request(true);
        let out = handle_deregistration_request(&mut world, 1, entity, &nas_pdu);

        assert_eq!(out.len(), 1, "switch-off skips DeregistrationAccept");
        assert!(matches!(
            out[0],
            NgapMessage::UeContextReleaseCommand { cause: NgapCause::NasDeregister }
        ));
    }

    #[test]
    fn deregistration_for_unknown_entity_is_noop() {
        let mut world = World::new();
        let nas_pdu = encode_deregistration_request(false);
        let out = handle_deregistration_request(&mut world, 1, 999, &nas_pdu);
        assert!(out.is_empty());
    }

    #[test]
    fn bad_nas_pdu_is_noop() {
        let (mut world, entity) = world_with_entity();
        let out = handle_deregistration_request(&mut world, 1, entity, &[0xFF, 0xFF]);
        assert!(out.is_empty());
    }

    #[test]
    fn deregistration_accept_is_protected_when_nas_security_is_active() {
        let kamf = [0x5Au8; 32];
        let (mut world, entity) = world_with_entity();
        world.set_nas_security5g(entity, Nas5gsSecurityContext::new(&kamf, 2, 2));

        let nas_pdu = encode_deregistration_request(false);
        let out = handle_deregistration_request(&mut world, 1, entity, &nas_pdu);

        assert_eq!(out.len(), 2);
        let envelope = match &out[0] {
            NgapMessage::DownlinkNasTransport(m) => m.nas_pdu.clone(),
            _ => panic!("expected DownlinkNasTransport"),
        };

        let sht = envelope.get(1).map(|b| b & 0x0F).unwrap_or(0);
        assert_ne!(sht, NAS5GS_SHT_PLAIN, "DeregistrationAccept should be protected once NAS security is active");

        // Independent mock-UE context, same pattern `amf::registration`'s own
        // tests use to prove `decode_protected_downlink` actually opens what
        // the AMF sent — not just that `encode_protected` ran without
        // panicking.
        let mut mock_ue_nas_ctx = Nas5gsSecurityContext::new(&kamf, 2, 2);
        let plain = decode_protected_downlink(&mut mock_ue_nas_ctx, &envelope)
            .expect("mock UE must be able to decrypt+verify what the AMF sent");
        assert!(matches!(decode_nas5gs(&plain), Ok(Nas5gsPdu::DeregistrationAccept)));
    }
}
