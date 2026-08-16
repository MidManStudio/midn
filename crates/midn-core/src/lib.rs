// crates/midn-core/src/lib.rs
//! midn-core — MME/AMF state machine, ECS subscriber registry, in-memory HSS.
//!
//! ## Public surface
//!
//! | Item           | Path                         |
//! |----------------|------------------------------|
//! | Mme            | `midn_core::mme::Mme`        |
//! | Amf            | `midn_core::amf::Amf`        |
//! | N3Event        | `midn_core::amf::N3Event`    |
//! | UpfEvent       | `midn_core::UpfEvent`        |
//! | Hss            | `midn_core::hss::Hss`        |
//! | HssAuthInfo    | `midn_core::hss::HssAuthInfo`|
//! | kdf            | `midn_core::kdf` (LTE Kasme derivation, TS 33.401 Annex A.2, AND the 5G-AKA KAUSF/KSEAF/KAMF chain, TS 33.501 Annex A.2/A.6/A.7 — see that module's doc for confidence notes) |
//!
//! `amf` was a stub (`registration.rs` — a comment-only placeholder) two
//! increments ago. Now implements the full 5G Registration procedure in
//! two modes (Phase A: NAS-only; Phase B: bundles a default PDU session via
//! `InitialContextSetupRequest`, mirroring `mme`'s own Phase 2/Phase 3 split)
//! — see `amf::registration` and `amf::mod` module docs for exactly what
//! each mode does. `pub mod amf;` was deliberately left out of this file
//! until there was real content behind it — see that decision recorded in
//! project history; no longer applies.
//!
//! S1AP types are re-exported as `crate::s1ap` within this crate (backed by
//! `midn_proto::s1ap`).  External users import directly from `midn_proto`.

pub mod amf;
pub mod hss;
pub mod kdf;
pub mod mme;

/// Thin re-export so every module inside midn-core can write
/// `use crate::s1ap::S1apMessage` without pulling in the full proto path.
pub(crate) mod s1ap {
    pub use midn_proto::s1ap::*;
}

// UpfEvent re-exported at crate root per key_api spec
// (`re_exported_as: midn_core::UpfEvent`).
pub use mme::state_machine::UpfEvent;
