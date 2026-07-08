//! `mnemos-f-seal` — capability tokens and the add-chunk ownership gate.
//!
//! The first canonical surface here is a capability *check* stub. The
//! Phase 0 contract is strictly an ownership gate — no encryption, no
//! key server, no threshold cryptography. The real Seal AEAD path is
//! custody-adjacent and deferred to Phase 1. The guiding principle is
//! preserved on the module documentation in [`capability`]: a
//! capability is a fixed-width `#[repr(u8)]` enum tag.
//!
//! Canonical surface: [`capability::CapabilityKind`] /
//! [`capability::Capability`] / [`capability::CapabilityError`] /
//! [`capability::check_capability`].
//!
//! Canonical surface: [`ownership::assert_add_chunk_owner`] — the
//! off-chain Rust gate that pairs with the Move `add_chunk` owner-only
//! entry function (`memory_root.move`, `E_NOT_OWNER = 1`). Double-gate
//! boundary: off-chain reject → on-chain reject (access control layer).
//!
//! [`mnemos_d_move::SuiAddress`] is reused byte-for-byte. No parallel
//! address shape is introduced.
#![deny(missing_docs)]
#![forbid(unsafe_code)]

pub mod capability;
pub mod ownership;
pub mod stage_b_envelope;
pub mod stage_b_stub;
pub mod stage_b_wording;

pub use capability::{Capability, CapabilityError, CapabilityKind, check_capability};
pub use ownership::assert_add_chunk_owner;
pub use stage_b_envelope::stage_b_seal_envelope;
pub use stage_b_stub::{StageBSealStubEnvelope, StageBSealStubError, StageBSealStubPolicy};
pub use stage_b_wording::{STAGE_B_SEAL_STUB_BOUNDARY_PHRASE, stage_b_wording_ok};
