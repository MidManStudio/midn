// crates/midn-core/src/amf/state_machine.rs
//! AMF — dispatch layer over `registration`. Mirrors `mme::state_machine`'s
//! structure: entry point matches on the incoming `NgapMessage` variant and
//! either starts a new procedure directly (`InitialUeMessage`) or decodes
//! the NAS PDU inside `UplinkNasTransport` and routes on ITS variant.
//!
//! `Amf` owns its own `World`, `ImsiRegistry`, and `Hss` — a separate
//! instance from `Mme`'s, not shared. See `registration` module doc's
//! "AUSF/UDM simplification" section for why, and for the known
//! consequence (a subscriber needs provisioning into both if a scenario
//! ever runs LTE and 5G side by side).
//!
//! ## Phase modes
//!
//! | Mode    | Trigger                     | SecModeComplete response             |
//! |---------|------------------------------|---------------------------------------|
//! | Phase A | `Amf::new()`                 | DownlinkNasTransport(RegistrationAccept) |
//! | Phase B | `.with_phase_b(upf_addr)`    | InitialContextSetupRequest            |
//!
//! Exact same two-mode shape as `mme::state_machine`'s Phase 2/Phase 3 —
//! see `registration` module doc "Phase A vs Phase B" for why Phase B
//! doesn't need any `ngap::codec` PER support to work (it doesn't touch
//! wire bytes at all — `process_ngap` dispatches on the `NgapMessage` enum
//! directly, same as `process_s1ap` does for `S1apMessage`).
//!
//! ## TEID lifecycle
//!
//! `TeidAllocator` is reused as-is from `crate::mme` — pure counter/free-list
//! bookkeeping with no subscriber-identifying state, so sharing the type
//! (not an instance — `Amf` and `Mme` each own a separate `TeidAllocator`)
//! doesn't compromise the deliberate `Amf`/`Mme` state separation described
//! above. `Amf`'s instance starts at a different base (`0x0002_0000` vs
//! `Mme`'s `0x0001_0000`) purely so TEID values are visibly distinguishable
//! in logs/tests if the two ever run side by side — they're allocated from
//! independent counters either way, so this isn't load-bearing for
//! correctness, just readability.

use midn_ecs::{ImsiRegistry, World};
use midn_proto::nas5gs::{decode_nas5gs, decode_protected, Nas5gsPdu, NAS5GS_SHT_PLAIN};
use midn_proto::ngap::messages::{
    NgapInitialContextSetupResponse, NgapMessage, NgapUeContextReleaseComplete,
    NgapUplinkNasTransport,
};

use crate::amf::{deregistration, registration};
use crate::hss::Hss;
use crate::mme::TeidAllocator;

// ── N3Event ──────────────────────────────────────────────────────────────────
// 5G-flavored mirror of `mme::UpfEvent` — same purpose (tell whatever's
// listening what a real UPF/N3 endpoint would need to do), 5G-correct field
// names where the concepts genuinely differ (`qfi`/`pdu_session_id` instead
// of `qci`/`erab_id`, `gnb_addr` instead of `enb_addr`). Not a type alias or
// a reuse of `UpfEvent` itself — the field sets are different shapes, and
// conflating LTE's QCI with 5G's QFI would misrepresent both (see
// `registration::DEFAULT_QFI` doc).

#[derive(Debug, Clone)]
pub enum N3Event {
    CreateSession {
        ul_teid: u32,
        entity_id: u32,
        imsi: u64,
        pdu_session_id: u8,
        qfi: u8,
        ue_ip: [u8; 4],
        gnb_addr: [u8; 4],
    },
    UpdateBearer {
        ul_teid: u32,
        dl_teid: u32,
        gnb_addr: [u8; 4],
    },
    RemoveSession {
        ul_teid: u32,
    },
}

pub struct Amf {
    pub(crate) world: World,
    pub(crate) registry: ImsiRegistry,
    pub hss: Hss,
    phase_b_upf: Option<[u8; 4]>,
    teid_allocator: TeidAllocator,
}

impl Amf {
    pub fn new() -> Self {
        Self {
            world: World::new(),
            registry: ImsiRegistry::new(),
            hss: Hss::new(),
            phase_b_upf: None,
            teid_allocator: TeidAllocator::new(0x0002_0000),
        }
    }

    /// Switch to Phase B: SecurityModeComplete now produces
    /// `InitialContextSetupRequest` (RegistrationAccept + one bundled
    /// default PDU session) instead of `DownlinkNasTransport`. Mirrors
    /// `Mme::with_phase3` exactly.
    pub fn with_phase_b(mut self, upf_addr: [u8; 4]) -> Self {
        self.phase_b_upf = Some(upf_addr);
        self
    }

    pub fn hss_mut(&mut self) -> &mut Hss { &mut self.hss }

    pub fn alloc_ul_teid(&mut self) -> u32 {
        self.teid_allocator.alloc()
    }

    pub fn release_ul_teid(&mut self, teid: u32) {
        self.teid_allocator.release(teid);
    }

    pub fn free_teid_count(&self) -> usize {
        self.teid_allocator.free_count()
    }

    pub fn subscriber_count(&self) -> usize { self.world.subscriber_count() }

    pub async fn process_ngap(&mut self, msg: NgapMessage) -> (Vec<NgapMessage>, Vec<N3Event>) {
        match msg {
            NgapMessage::InitialUeMessage(ium) => registration::start_registration(
                &mut self.world, ium.ran_ue_ngap_id, &ium.nas_pdu, ium.tai,
            ),
            NgapMessage::UplinkNasTransport(unt) => self.handle_uplink_nas(unt),
            NgapMessage::InitialContextSetupResponse(icrsp) => self.handle_ics_response(icrsp),
            NgapMessage::UeContextReleaseComplete(rel) => self.handle_release_complete(rel),
            _ => {
                tracing::debug!("process_ngap: unhandled NGAP message variant (out of scope)");
                (vec![], vec![])
            }
        }
    }

    /// Decode the NAS PDU inside an `UplinkNasTransport` — auto-detecting
    /// plain vs protected by security header type, same pattern
    /// `mme::state_machine::handle_uplink_nas` uses for LTE — then route on
    /// the decoded NAS message's own variant.
    ///
    /// 5G's security header type lives in byte[1]'s low nibble (byte[0] is
    /// the full-octet Extended Protocol Discriminator) — NOT byte[0]'s high
    /// nibble like NAS-EPS. See `nas5gs::codec` module doc for why the
    /// header shape genuinely differs, not just a width tweak.
    fn handle_uplink_nas(&mut self, unt: NgapUplinkNasTransport) -> (Vec<NgapMessage>, Vec<N3Event>) {
        let amf_ue_ngap_id = unt.amf_ue_ngap_id;
        let ran_ue_ngap_id = unt.ran_ue_ngap_id;

        let sht = unt.nas_pdu.get(1).map(|b| b & 0x0F).unwrap_or(0);

        let plain_pdu: Vec<u8> = if sht == NAS5GS_SHT_PLAIN {
            unt.nas_pdu.to_vec()
        } else {
            let ctx = match self.world.nas_security5g_mut(amf_ue_ngap_id) {
                Some(c) => c,
                None => {
                    tracing::warn!(amf_ue_ngap_id, "UplinkNasTransport: protected PDU but no NAS security context");
                    return (vec![], vec![]);
                }
            };
            match decode_protected(ctx, &unt.nas_pdu) {
                Some(inner) => inner,
                None => {
                    tracing::warn!(amf_ue_ngap_id, "UplinkNasTransport: NAS integrity check failed");
                    return (vec![], vec![]);
                }
            }
        };

        match decode_nas5gs(&plain_pdu) {
            Ok(Nas5gsPdu::IdentityResponse(_)) => registration::handle_identity_response(
                &mut self.world, &mut self.registry, &mut self.hss,
                ran_ue_ngap_id, amf_ue_ngap_id, &plain_pdu,
            ),
            Ok(Nas5gsPdu::AuthenticationResponse(_)) => registration::handle_auth_response(
                &mut self.world, ran_ue_ngap_id, amf_ue_ngap_id, &plain_pdu,
            ),
            Ok(Nas5gsPdu::SecurityModeComplete) => registration::handle_security_mode_complete(
                &mut self.world, ran_ue_ngap_id, amf_ue_ngap_id,
                self.phase_b_upf, &mut self.teid_allocator,
            ),
            Ok(Nas5gsPdu::RegistrationComplete) => registration::handle_registration_complete(
                &mut self.world, amf_ue_ngap_id,
            ),
            Ok(Nas5gsPdu::DeregistrationRequest { .. }) => {
                let responses = deregistration::handle_deregistration_request(
                    &mut self.world, ran_ue_ngap_id, amf_ue_ngap_id, &plain_pdu,
                );
                (responses, vec![])
            }
            _ => {
                tracing::warn!(amf_ue_ngap_id, "UplinkNasTransport: unknown or unsupported NAS PDU");
                (vec![], vec![])
            }
        }
    }

    /// gNodeB confirms the security context (+ bundled PDU session) from
    /// Phase B's `InitialContextSetupRequest`. Records the real DL TEID and
    /// gNB N3 address, emits `N3Event::UpdateBearer` for whatever's
    /// listening on the UPF side. Mirrors `mme::state_machine::handle_icsrsp`
    /// exactly — same "first item only, no tunnel component means Phase A
    /// mode" shape.
    fn handle_ics_response(
        &mut self,
        resp: NgapInitialContextSetupResponse,
    ) -> (Vec<NgapMessage>, Vec<N3Event>) {
        let entity = resp.amf_ue_ngap_id;

        let session = match resp.pdu_sessions_setup.first() {
            Some(s) => s,
            None => {
                tracing::warn!(entity, "ICSResponse: no PDU sessions in response");
                return (vec![], vec![]);
            }
        };

        let dl_teid = u32::from_be_bytes(session.gtp_teid);
        let gnb_addr = session.transport_layer_addr;

        if let Some(t) = self.world.tunnel_mut(entity) {
            let ul_teid = t.ul_teid;
            t.dl_teid = dl_teid;
            t.enb_addr = gnb_addr;
            return (vec![], vec![N3Event::UpdateBearer { ul_teid, dl_teid, gnb_addr }]);
        }

        tracing::warn!(entity, "ICSResponse: no tunnel component — Phase A mode?");
        (vec![], vec![])
    }

    /// gNodeB confirms UE context release — the tail end of deregistration
    /// (or any other release trigger). Mirrors `mme::state_machine::
    /// handle_release_complete` exactly: despawn, deregister the IMSI,
    /// release the TEID if one was ever allocated (Phase A entities never
    /// get one, so `ul_teid` is `None` and this degrades to a plain
    /// despawn). Safe to call on an already-gone entity — every step here
    /// is a no-op rather than a panic in that case.
    fn handle_release_complete(
        &mut self,
        msg: NgapUeContextReleaseComplete,
    ) -> (Vec<NgapMessage>, Vec<N3Event>) {
        let entity = msg.amf_ue_ngap_id;

        let ul_teid = self.world.tunnel(entity).map(|t| t.ul_teid);

        if let Some(identity) = self.world.identity(entity) {
            self.registry.deregister(identity.imsi);
        }

        self.world.despawn(entity);
        tracing::info!(entity, "UeContextReleaseComplete — entity despawned");

        match ul_teid {
            Some(t) => {
                self.teid_allocator.release(t);
                (vec![], vec![N3Event::RemoveSession { ul_teid: t }])
            }
            None => (vec![], vec![]),
        }
    }
}

impl Default for Amf {
    fn default() -> Self { Self::new() }
}

#[cfg(test)]
mod tests {
    use super::*;
    use midn_auth::keys::{Amf as MilenageAmf, Rand, Sqn};
    use midn_auth::{AuthKey, MilenageContext, OpCode};
    use midn_ecs::AuthState;
    use midn_proto::nas5gs::{
        encode_deregistration_request, encode_identity_response_suci, encode_registration_request,
        Suci,
    };
    use midn_proto::ngap::messages::{
        NgapCause, NgapInitialContextSetupResponse, NgapInitialUeMessage,
        NgapUeContextReleaseComplete, PduSessionSetupItem,
    };

    // Must round-trip through `registration::resolve_suci_to_imsi`'s 5-byte
    // MSIN-as-IMSI scheme (< 2^40 ≈ 1.0995e12 — see that function's doc).
    // The original 15-digit value here (901_700_000_000_001) silently
    // truncated on resolve (901700000000001 -> 100465223681), so the AMF
    // looked up a different subscriber than `Hss` was provisioned under and
    // dropped the IdentityResponse as unknown — the actual root cause of
    // this test's CI failure, not the protected-envelope direction bug
    // below (that one's real too, but this test never got far enough to
    // hit it). Trimmed to 12 digits, which fits.
    const TEST_IMSI: u64 = 901_700_000_001;
    const TEST_K: &str = "465b5ce8b199b49faa5f0a2ee238a6bc";
    const TEST_OPC: &str = "cd63cb71954a9f4e48a5994e37a02baf";
    const TEST_PLMN: [u8; 3] = [0x00, 0x11, 0x22];
    const TEST_TAI: [u8; 6] = [0x00, 0x11, 0x22, 0x00, 0x00, 0x01];
    const TEST_UPF_ADDR: [u8; 4] = [10, 0, 0, 1];

    fn test_amf() -> Amf {
        let mut amf = Amf::new();
        amf.hss_mut().provision_hex(TEST_IMSI, TEST_K, TEST_OPC).expect("valid test hex");
        amf
    }

    fn test_amf_phase_b() -> Amf {
        let mut amf = Amf::new().with_phase_b(TEST_UPF_ADDR);
        amf.hss_mut().provision_hex(TEST_IMSI, TEST_K, TEST_OPC).expect("valid test hex");
        amf
    }

    /// Encode a null-scheme SUCI carrying `imsi` — the exact inverse of
    /// `registration::resolve_suci_to_imsi`. See that function's doc for
    /// why MSIN's 5 bytes are the whole story.
    fn suci_for_imsi(imsi: u64) -> Suci {
        let bytes = imsi.to_be_bytes();
        let mut msin = [0u8; 5];
        msin.copy_from_slice(&bytes[3..8]);
        Suci { mcc: [0, 0, 0], mnc: [0, 0, 0], routing_indicator: 0, protection_scheme: 0, home_network_pki: 0, msin }
    }

    fn initial_ue_message(ran_ue_ngap_id: u32) -> NgapMessage {
        let nas = encode_registration_request(1, 0, None, 0x00C0);
        NgapMessage::InitialUeMessage(NgapInitialUeMessage {
            ran_ue_ngap_id,
            nas_pdu: nas,
            tai: TEST_TAI,
            nr_cgi: [0u8; 9],
            rrc_establishment_cause: 0,
        })
    }

    fn uplink(ran_ue_ngap_id: u32, amf_ue_ngap_id: u32, nas_pdu: bytes::Bytes) -> NgapMessage {
        NgapMessage::UplinkNasTransport(NgapUplinkNasTransport {
            amf_ue_ngap_id, ran_ue_ngap_id, nas_pdu, tai: TEST_TAI, nr_cgi: [0u8; 9],
        })
    }

    /// Extract the single `NgapDownlinkNasTransport` from a one-message
    /// response, panicking with a useful message otherwise — every step in
    /// this procedure (Phase A) sends exactly zero or one message.
    fn expect_single_downlink(resp: Vec<NgapMessage>) -> (u32, u32, bytes::Bytes) {
        assert_eq!(resp.len(), 1, "expected exactly one response message");
        match resp.into_iter().next().unwrap() {
            NgapMessage::DownlinkNasTransport(dl) => (dl.amf_ue_ngap_id, dl.ran_ue_ngap_id, dl.nas_pdu),
            _ => panic!("expected DownlinkNasTransport"),
        }
    }

    /// Drives Steps 1-3 (RegistrationRequest through AuthenticationResponse)
    /// — identical in Phase A and Phase B mode, since the two modes only
    /// diverge at Step 4's *transport* (DownlinkNasTransport vs
    /// InitialContextSetupRequest), not the crypto chain. Returns
    /// everything a caller needs to independently re-derive KAMF and verify
    /// Step 4's output, mirroring the "mock UE re-derives the whole chain"
    /// approach `full_registration_flow_end_to_end` already established.
    async fn run_through_security_mode_command(amf: &mut Amf, ran_ue_ngap_id: u32) -> (u32, u32, [u8; 32]) {
        let (resp, _events) = amf.process_ngap(initial_ue_message(ran_ue_ngap_id)).await;
        let (amf_ue_ngap_id, ran_ue_ngap_id, id_req_pdu) = expect_single_downlink(resp);
        assert!(matches!(decode_nas5gs(&id_req_pdu), Ok(Nas5gsPdu::IdentityRequest { .. })));

        let id_resp_pdu = encode_identity_response_suci(&suci_for_imsi(TEST_IMSI));
        let (resp, _events) = amf.process_ngap(uplink(ran_ue_ngap_id, amf_ue_ngap_id, id_resp_pdu)).await;
        let (_, _, auth_req_pdu) = expect_single_downlink(resp);
        let (rand, _autn) = match decode_nas5gs(&auth_req_pdu) {
            Ok(Nas5gsPdu::AuthenticationRequest(d)) => (d.rand, d.autn),
            other => panic!("expected AuthenticationRequest, got {other:?}"),
        };

        let mock_ctx = MilenageContext::new(
            AuthKey::from_hex(TEST_K).unwrap(),
            OpCode::from_hex(TEST_OPC).unwrap(),
        );
        let sqn_used = [0u8; 6];
        let milenage_amf = MilenageAmf([0x80, 0x00]);
        let vector = mock_ctx.generate_vector_with_rand(
            Sqn::from_bytes(&sqn_used), milenage_amf, Rand(rand),
        );
        let snn = crate::kdf::serving_network_name(&TEST_PLMN);
        let res_star = crate::kdf::derive_res_star(&vector.ck, &vector.ik, &snn, &rand, &vector.res);

        let auth_resp_pdu = midn_proto::nas5gs::encode_auth_response(&res_star);
        let (resp, _events) = amf.process_ngap(uplink(ran_ue_ngap_id, amf_ue_ngap_id, auth_resp_pdu)).await;
        let (_, _, sec_cmd_pdu) = expect_single_downlink(resp);
        assert!(matches!(decode_nas5gs(&sec_cmd_pdu), Ok(Nas5gsPdu::SecurityModeCommand(_))));
        assert!(amf.world.is_authenticated(amf_ue_ngap_id));

        let sqn_xor_ak: [u8; 6] = core::array::from_fn(|i| sqn_used[i] ^ vector.ak[i]);
        let kausf = crate::kdf::derive_kausf(&vector.ck, &vector.ik, &snn, &sqn_xor_ak);
        let kseaf = crate::kdf::derive_kseaf(&kausf, &snn);
        let supi = TEST_IMSI.to_string().into_bytes();
        let kamf = crate::kdf::derive_kamf(&kseaf, &supi, &[0x00, 0x00]);

        (amf_ue_ngap_id, ran_ue_ngap_id, kamf)
    }

    #[tokio::test]
    async fn new_amf_has_no_subscribers() {
        let amf = Amf::new();
        assert_eq!(amf.subscriber_count(), 0);
    }

    #[tokio::test]
    async fn start_registration_rejects_guti_based_request() {
        let mut amf = test_amf();
        let nas = encode_registration_request(1, 0, Some(&[0xABu8; 11]), 0x00C0);
        let msg = NgapMessage::InitialUeMessage(NgapInitialUeMessage {
            ran_ue_ngap_id: 1, nas_pdu: nas, tai: TEST_TAI, nr_cgi: [0u8; 9], rrc_establishment_cause: 0,
        });
        let (resp, events) = amf.process_ngap(msg).await;
        assert!(resp.is_empty(), "GUTI-based registration isn't supported — should be silently dropped, not crash");
        assert!(events.is_empty());
        assert_eq!(amf.subscriber_count(), 0, "no entity should be spawned for an unsupported GUTI attempt");
    }

    #[tokio::test]
    async fn start_registration_sends_identity_request_and_spawns_entity() {
        let mut amf = test_amf();
        let (resp, events) = amf.process_ngap(initial_ue_message(7)).await;
        assert!(events.is_empty(), "no N3Event this early in the flow, Phase A or B");
        let (amf_ue_ngap_id, ran_ue_ngap_id, nas_pdu) = expect_single_downlink(resp);
        assert_eq!(ran_ue_ngap_id, 7);
        assert_eq!(amf.subscriber_count(), 1);

        match decode_nas5gs(&nas_pdu) {
            Ok(Nas5gsPdu::IdentityRequest { identity_type }) => {
                assert_eq!(identity_type, midn_proto::nas5gs::IDTYPE_SUCI);
            }
            other => panic!("expected IdentityRequest, got {other:?}"),
        }
        let _ = amf_ue_ngap_id;
    }

    #[tokio::test]
    async fn full_registration_flow_end_to_end() {
        let mut amf = test_amf();

        let (amf_ue_ngap_id, ran_ue_ngap_id, kamf) =
            run_through_security_mode_command(&mut amf, 7).await;

        // Step 4: SecurityModeComplete -> ciphered RegistrationAccept via
        // DownlinkNasTransport (Phase A — no `.with_phase_b(..)`).
        let sec_complete_pdu = midn_proto::nas5gs::encode_sec_mode_complete();
        let (resp, events) = amf.process_ngap(uplink(ran_ue_ngap_id, amf_ue_ngap_id, sec_complete_pdu)).await;
        assert!(events.is_empty(), "Phase A never emits N3Event — no PDU session bundled");
        let (_, _, accept_envelope) = expect_single_downlink(resp);

        // Mock UE independently derives the same KAUSF -> KSEAF -> KAMF ->
        // NAS-key chain to build its own Nas5gsSecurityContext, proving
        // decode_protected_downlink actually opens what the AMF sent — not
        // just that encode_protected ran without panicking.
        let mut mock_ue_nas_ctx = midn_proto::nas5gs::Nas5gsSecurityContext::new(&kamf, 2, 2);
        let accept_plain = midn_proto::nas5gs::decode_protected_downlink(&mut mock_ue_nas_ctx, &accept_envelope)
            .expect("mock UE must be able to decrypt+verify what the AMF sent");
        match decode_nas5gs(&accept_plain) {
            Ok(Nas5gsPdu::RegistrationAccept(d)) => assert_eq!(d.registration_result, 1),
            other => panic!("expected RegistrationAccept, got {other:?}"),
        }
        assert!(amf.world.nas_security5g(amf_ue_ngap_id).is_some());

        // Step 5: RegistrationComplete -> no response, subscriber is online.
        let complete_pdu = midn_proto::nas5gs::encode_registration_complete();
        let (resp, events) = amf.process_ngap(uplink(ran_ue_ngap_id, amf_ue_ngap_id, complete_pdu)).await;
        assert!(resp.is_empty());
        assert!(events.is_empty());
        assert!(amf.world.is_authenticated(amf_ue_ngap_id));
    }

    #[tokio::test]
    async fn full_registration_flow_phase_b_bundles_pdu_session_and_completes_ics() {
        let mut amf = test_amf_phase_b();

        let (amf_ue_ngap_id, ran_ue_ngap_id, kamf) =
            run_through_security_mode_command(&mut amf, 7).await;

        // Step 4, Phase B: SecurityModeComplete -> InitialContextSetupRequest
        // (RegistrationAccept + one bundled default PDU session), not
        // DownlinkNasTransport.
        let sec_complete_pdu = midn_proto::nas5gs::encode_sec_mode_complete();
        let (resp, events) = amf.process_ngap(uplink(ran_ue_ngap_id, amf_ue_ngap_id, sec_complete_pdu)).await;
        assert_eq!(resp.len(), 1);
        let icsr = match resp.into_iter().next().unwrap() {
            NgapMessage::InitialContextSetupRequest(icsr) => icsr,
            other => panic!("expected InitialContextSetupRequest, got {other:?}"),
        };
        assert_eq!(icsr.amf_ue_ngap_id, amf_ue_ngap_id);
        assert_eq!(icsr.ran_ue_ngap_id, ran_ue_ngap_id);
        assert_eq!(icsr.security_key, kamf);
        assert_eq!(icsr.pdu_sessions.len(), 1);
        assert_eq!(icsr.pdu_sessions[0].pdu_session_id, 1);
        let ul_teid = u32::from_be_bytes(icsr.pdu_sessions[0].gtp_teid);
        assert_eq!(icsr.pdu_sessions[0].transport_layer_addr, TEST_UPF_ADDR);

        assert_eq!(events.len(), 1);
        match &events[0] {
            N3Event::CreateSession { ul_teid: evt_teid, entity_id, imsi, pdu_session_id, .. } => {
                assert_eq!(*evt_teid, ul_teid);
                assert_eq!(*entity_id, amf_ue_ngap_id);
                assert_eq!(*imsi, TEST_IMSI);
                assert_eq!(*pdu_session_id, 1);
            }
            other => panic!("expected N3Event::CreateSession, got {other:?}"),
        }

        // The piggybacked NAS PDU is still a normal ciphered RegistrationAccept
        // — Phase B doesn't change the NAS body at all, only the NGAP transport.
        let mut mock_ue_nas_ctx = midn_proto::nas5gs::Nas5gsSecurityContext::new(&kamf, 2, 2);
        let accept_envelope = icsr.nas_pdu.expect("Phase B ICSR must piggyback RegistrationAccept");
        let accept_plain = midn_proto::nas5gs::decode_protected_downlink(&mut mock_ue_nas_ctx, &accept_envelope)
            .expect("mock UE must be able to decrypt+verify what the AMF sent");
        assert!(matches!(decode_nas5gs(&accept_plain), Ok(Nas5gsPdu::RegistrationAccept(_))));

        // gNodeB confirms: real DL TEID + its own N3 address come back.
        let gnb_addr = [172, 16, 0, 5];
        let dl_teid: u32 = 0xAABB_CCDD;
        let icrsp = NgapMessage::InitialContextSetupResponse(NgapInitialContextSetupResponse {
            amf_ue_ngap_id,
            ran_ue_ngap_id,
            pdu_sessions_setup: vec![PduSessionSetupItem {
                pdu_session_id: 1,
                transport_layer_addr: gnb_addr,
                gtp_teid: dl_teid.to_be_bytes(),
            }],
            pdu_sessions_failed: vec![],
        });
        let (resp, events) = amf.process_ngap(icrsp).await;
        assert!(resp.is_empty(), "ICSResponse produces no NGAP reply, only an N3Event");
        assert_eq!(events.len(), 1);
        match &events[0] {
            N3Event::UpdateBearer { ul_teid: evt_ul, dl_teid: evt_dl, gnb_addr: evt_addr } => {
                assert_eq!(*evt_ul, ul_teid);
                assert_eq!(*evt_dl, dl_teid);
                assert_eq!(*evt_addr, gnb_addr);
            }
            other => panic!("expected N3Event::UpdateBearer, got {other:?}"),
        }

        let tunnel = amf.world.tunnel(amf_ue_ngap_id).expect("tunnel component set in Phase B's Step 4");
        assert_eq!(tunnel.ul_teid, ul_teid);
        assert_eq!(tunnel.dl_teid, dl_teid);
        assert_eq!(tunnel.enb_addr, gnb_addr);
    }

    #[tokio::test]
    async fn phase_b_deregistration_releases_teid_and_despawns_entity() {
        let mut amf = test_amf_phase_b();

        let (amf_ue_ngap_id, ran_ue_ngap_id, _kamf) =
            run_through_security_mode_command(&mut amf, 7).await;

        let sec_complete_pdu = midn_proto::nas5gs::encode_sec_mode_complete();
        let (resp, events) = amf.process_ngap(uplink(ran_ue_ngap_id, amf_ue_ngap_id, sec_complete_pdu)).await;
        assert_eq!(resp.len(), 1);
        let icsr = match resp.into_iter().next().unwrap() {
            NgapMessage::InitialContextSetupRequest(icsr) => icsr,
            other => panic!("expected InitialContextSetupRequest, got {other:?}"),
        };
        let ul_teid = u32::from_be_bytes(icsr.pdu_sessions[0].gtp_teid);
        assert!(matches!(&events[0], N3Event::CreateSession { .. }));
        assert_eq!(amf.free_teid_count(), 0, "freshly allocated TEID is not free");
        assert_eq!(amf.subscriber_count(), 1);

        // gNodeB confirms the security context + PDU session — same
        // exchange `full_registration_flow_phase_b_bundles_pdu_session_and_completes_ics`
        // above already proves in detail; only needed here to get a real
        // tunnel component onto the entity before deregistering it.
        let icrsp = NgapMessage::InitialContextSetupResponse(NgapInitialContextSetupResponse {
            amf_ue_ngap_id,
            ran_ue_ngap_id,
            pdu_sessions_setup: vec![PduSessionSetupItem {
                pdu_session_id: 1,
                transport_layer_addr: [172, 16, 0, 5],
                gtp_teid: 0xAABB_CCDDu32.to_be_bytes(),
            }],
            pdu_sessions_failed: vec![],
        });
        amf.process_ngap(icrsp).await;

        // DeregistrationAccept's own protected-envelope correctness is
        // `deregistration::tests::deregistration_accept_is_protected_when_
        // nas_security_is_active`'s job, not this test's — this one is
        // about the release/teardown mechanics end to end.
        let deregistration_pdu = encode_deregistration_request(false);
        let (resp, events) = amf.process_ngap(uplink(ran_ue_ngap_id, amf_ue_ngap_id, deregistration_pdu)).await;
        assert_eq!(resp.len(), 2, "expect DeregistrationAccept + UeContextReleaseCommand");
        assert!(matches!(resp[0], NgapMessage::DownlinkNasTransport(_)));
        assert!(matches!(
            resp[1],
            NgapMessage::UeContextReleaseCommand { amf_ue_ngap_id: a, ran_ue_ngap_id: r, cause: NgapCause::NasDeregister }
            if a == amf_ue_ngap_id && r == ran_ue_ngap_id
        ));
        assert!(events.is_empty(), "no N3Event until UeContextReleaseComplete");

        let release_complete = NgapMessage::UeContextReleaseComplete(NgapUeContextReleaseComplete {
            amf_ue_ngap_id, ran_ue_ngap_id,
        });
        let (resp, events) = amf.process_ngap(release_complete).await;
        assert!(resp.is_empty());
        match &events[0] {
            N3Event::RemoveSession { ul_teid: t } => assert_eq!(*t, ul_teid),
            other => panic!("expected RemoveSession, got {other:?}"),
        }
        assert_eq!(amf.subscriber_count(), 0, "entity despawned");
        assert_eq!(amf.free_teid_count(), 1, "TEID returned to the free list");
    }

    #[tokio::test]
    async fn handle_auth_response_rejects_wrong_res_star() {
        let mut amf = test_amf();
        let (resp, _events) = amf.process_ngap(initial_ue_message(7)).await;
        let (amf_ue_ngap_id, ran_ue_ngap_id, _) = expect_single_downlink(resp);

        let id_resp_pdu = encode_identity_response_suci(&suci_for_imsi(TEST_IMSI));
        amf.process_ngap(uplink(ran_ue_ngap_id, amf_ue_ngap_id, id_resp_pdu)).await;

        let wrong_res_star = [0xFFu8; 16];
        let auth_resp_pdu = midn_proto::nas5gs::encode_auth_response(&wrong_res_star);
        let (resp, events) = amf.process_ngap(uplink(ran_ue_ngap_id, amf_ue_ngap_id, auth_resp_pdu)).await;

        assert!(resp.is_empty(), "wrong RES* must not produce a SecurityModeCommand");
        assert!(events.is_empty());
        assert_eq!(amf.world.auth_state(amf_ue_ngap_id), Some(AuthState::Failed(midn_ecs::AuthFailReason::ResMismatch)));
    }

    #[tokio::test]
    async fn unknown_subscriber_is_silently_dropped() {
        let mut amf = Amf::new(); // no provisioning at all
        let (resp, _events) = amf.process_ngap(initial_ue_message(7)).await;
        let (amf_ue_ngap_id, ran_ue_ngap_id, _) = expect_single_downlink(resp);

        let id_resp_pdu = encode_identity_response_suci(&suci_for_imsi(999_999_999));
        let (resp, events) = amf.process_ngap(uplink(ran_ue_ngap_id, amf_ue_ngap_id, id_resp_pdu)).await;
        assert!(resp.is_empty(), "unknown subscriber must not produce an AuthenticationRequest");
        assert!(events.is_empty());
    }
    }
