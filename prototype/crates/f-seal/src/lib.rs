//! `mnemos-f-seal` — capability tokens and the add-chunk ownership gate.
//!
//! Atom #37 · F.0.1 lands the first canonical surface here: a
//! capability *check* stub. The Phase 0 contract is strictly an
//! ownership gate — no encryption, no key server, no threshold
//! cryptography. The real Seal AEAD path is custody-adjacent and
//! deferred to Phase 1 per §3.4 master ("custody 인접이라 *지금* 안
//! 건드림", ATOM_PLAN line 699-700). The 광기 line is preserved on
//! the module documentation in [`capability`]: a capability is a
//! fixed-width `#[repr(u8)]` enum tag.
//!
//! Canonical OUT (atom #37 · F.0.1 · ATOM_PLAN line 1194):
//! [`capability::CapabilityKind`] / [`capability::Capability`] /
//! [`capability::CapabilityError`] / [`capability::check_capability`].
//!
//! Canonical OUT (atom #38 · F.0.2 · ATOM_PLAN line 1204):
//! [`ownership::assert_add_chunk_owner`] — the off-chain Rust gate
//! that pairs with the Move `add_chunk` owner-only entry function
//! (atom #16 · D.0.2 · `memory_root.move` line 76-77,
//! `E_NOT_OWNER = 1`). Double-gate boundary: off-chain reject →
//! on-chain reject (ATOM_PLAN line 1205, §10.6 access control layer).
//!
//! Canonical IN — [`mnemos_d_move::SuiAddress`] (atom #15 · D.0.1)
//! is reused byte-for-byte (atom #33/#34/#35/#36 precedent). No
//! parallel address shape is introduced.
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
