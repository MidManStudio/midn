// crates/midn-core/src/amf/mod.rs
//! AMF — Access and Mobility Function (3GPP TS 23.501 / 38.413)
//!
//! 5G NR counterpart to the LTE MME. Communicates with gNodeBs via NGAP.
//!
//! Key differences from MME:
//!   - Registration replaces Attach (more lightweight)
//!   - PDU Sessions replace EPS Bearers (more flexible QoS)
//!   - AUSF/UDM replace HSS (separated in real 5G; collapsed into one `Hss`
//!     here — see `registration` module doc's "AUSF/UDM simplification")
//!   - SMF handles session management (split from AMF)
//!
//! ## Status
//!
//! `registration` — 5G Registration procedure, full flow through
//! RegistrationComplete, real 5G-AKA (Milenage via `Hss` + the TS 33.501
//! Annex A KAUSF/KSEAF/KAMF chain in `midn_core::kdf`), real NAS security
//! activation. Two modes, same shape as `mme`'s Phase 2/Phase 3 split:
//!   - Phase A (`Amf::new()`): RegistrationAccept via `DownlinkNasTransport`,
//!     no PDU session, no TEID/UPF interaction.
//!   - Phase B (`Amf::new().with_phase_b(upf_addr)`): RegistrationAccept +
//!     one bundled default PDU session via `InitialContextSetupRequest`,
//!     `InitialContextSetupResponse` updates the tunnel with the real DL
//!     TEID/gNB address. See `registration` module doc's "Phase A vs
//!     Phase B" for exactly what's bundled and — importantly — why this
//!     didn't actually need any `ngap::codec` PER support to build (a
//!     correction to an earlier handover note that claimed otherwise).
//!
//! `deregistration` — UE-initiated deregistration (TS 23.502 §4.2.2.3):
//! DeregistrationRequest -> (DeregistrationAccept unless switch_off) ->
//! UeContextReleaseCommand -> UeContextReleaseComplete triggers the actual
//! teardown (entity despawn, IMSI deregister, TEID release,
//! `N3Event::RemoveSession`) in `state_machine::Amf::handle_release_complete`
//! — same trigger/teardown split `mme::detach`/`handle_release_complete`
//! use for LTE.

pub mod deregistration;
pub mod registration;
pub mod state_machine;

pub use state_machine::{Amf, N3Event};
