//! Stage C 6-step mainnet checklist type (C-WP-04A · atom #204 · C.1.3).
//!
//! Canonical OUT (§4.2): [`MainnetChecklistStep`], [`MainnetChecklist`].
//!
//! # Madness invariants (atom #204)
//!
//! * **"Green" is machine-checkable.** The checklist is a `u8` bitmask plus a
//!   32-byte evidence hash, not prose. [`MainnetChecklist::all_green`] is a pure
//!   mask comparison against [`MainnetChecklist::ALL_GREEN_MASK`]; a step is
//!   green only if its bit (see [`MainnetChecklistStep::bit`]) is set.
//! * **Missing evidence is red.** [`MainnetChecklist::ready_state`] returns the
//!   safe [`Locked`](MainnetExecutionState::Locked) posture unless *every* step
//!   bit is set **and** the evidence hash is non-zero. A checklist with any step
//!   unfilled, or with a zero evidence hash, is never "ready".
//! * **The ceiling is `ApprovalPending`, never `Executed`.** Even an all-green
//!   checklist only advances [`ready_state`](MainnetChecklist::ready_state) to
//!   [`ApprovalPending`](MainnetExecutionState::ApprovalPending). This type
//!   cannot, by construction, represent an executed mainnet mutation; reaching
//!   [`Executed`](MainnetExecutionState::Executed) requires the later operator
//!   approval ceremony (atom #210 + multisig/timelock packages), not this
//!   checklist.
//! * **No re-mint.** The execution posture reuses the §4.1
//!   [`MainnetExecutionState`] (atom #173, `a-core`); no parallel mainnet-state
//!   enum is introduced here.

use mnemos_a_core::stage_c_env::MainnetExecutionState;

/// Fixed serialized byte width of a [`MainnetChecklist`]: `1` (green mask) +
/// `1` (state discriminant) + `32` (evidence hash).
pub const MAINNET_CHECKLIST_BYTES: usize = 1 + 1 + 32;

/// The six ordered gate steps of the mainnet readiness checklist (§4.2).
///
/// Discriminants are `1..=6`; [`bit`](Self::bit) maps each to a distinct bit of
/// the [`MainnetChecklist`] mask (`StageBEvidence` → bit 0 … `OperatorApproval`
/// → bit 5).
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
#[repr(u8)]
pub enum MainnetChecklistStep {
    /// Step 1 — deterministic Stage B testnet replay evidence (atom #205).
    StageBEvidence = 1,
    /// Step 2 — Move Prover + gas trace bound to one package digest (atom #206).
    ProofAndGas = 2,
    /// Step 3 — no open High/Critical audit findings (atom #207).
    AuditResolved = 3,
    /// Step 4 — multisig roster + timelock policy present (atom #208).
    MultisigTimelock = 4,
    /// Step 5 — deny-by-default Gas Station policy green (atom #209).
    GasStationPolicy = 5,
    /// Step 6 — explicit operator approval (atom #210).
    OperatorApproval = 6,
}

impl MainnetChecklistStep {
    /// Every step in discriminant order. Used to iterate the full checklist.
    pub const ALL: [MainnetChecklistStep; 6] = [
        Self::StageBEvidence,
        Self::ProofAndGas,
        Self::AuditResolved,
        Self::MultisigTimelock,
        Self::GasStationPolicy,
        Self::OperatorApproval,
    ];

    /// The raw `#[repr(u8)]` discriminant (`1..=6`).
    #[inline]
    pub const fn as_u8(self) -> u8 {
        self as u8
    }

    /// Parse from the discriminant byte, rejecting unknown values.
    #[inline]
    pub const fn from_u8(byte: u8) -> Option<Self> {
        match byte {
            1 => Some(Self::StageBEvidence),
            2 => Some(Self::ProofAndGas),
            3 => Some(Self::AuditResolved),
            4 => Some(Self::MultisigTimelock),
            5 => Some(Self::GasStationPolicy),
            6 => Some(Self::OperatorApproval),
            _ => None,
        }
    }

    /// The single mask bit owned by this step: `1 << (discriminant - 1)`, so the
    /// six steps occupy bits `0..=5` of a `u8`.
    #[inline]
    pub const fn bit(self) -> u8 {
        1u8 << (self as u8 - 1)
    }
}

/// The mainnet readiness checklist (§4.2): a bitmask of green steps, the current
/// (gated) execution posture, and a 32-byte evidence hash binding the checklist
/// to its evidence bundle.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub struct MainnetChecklist {
    /// Bit `i` (`0..=5`) is set when step `i+1` is green. See
    /// [`MainnetChecklistStep::bit`].
    pub green_mask_u8: u8,
    /// The gated execution posture. Defaults to
    /// [`Locked`](MainnetExecutionState::Locked).
    pub state: MainnetExecutionState,
    /// 32-byte hash binding this checklist to its evidence bundle. Zero means
    /// "no evidence bound" and forces [`ready_state`](Self::ready_state) to stay
    /// locked.
    pub evidence_hash_32: [u8; 32],
}

impl MainnetChecklist {
    /// Mask with all six step bits set (`0b0011_1111` = `63`).
    pub const ALL_GREEN_MASK: u8 = 0b0011_1111;

    /// A fresh, safe checklist: no steps green, [`Locked`](MainnetExecutionState::Locked),
    /// and a zero evidence hash.
    #[inline]
    pub const fn new_locked() -> Self {
        Self {
            green_mask_u8: 0,
            state: MainnetExecutionState::Locked,
            evidence_hash_32: [0u8; 32],
        }
    }

    /// Return a copy with one step's bit set or cleared.
    #[inline]
    pub const fn with_step(mut self, step: MainnetChecklistStep, green: bool) -> Self {
        if green {
            self.green_mask_u8 |= step.bit();
        } else {
            self.green_mask_u8 &= !step.bit();
        }
        self
    }

    /// Return a copy with the evidence hash set.
    #[inline]
    pub const fn with_evidence_hash(mut self, evidence_hash_32: [u8; 32]) -> Self {
        self.evidence_hash_32 = evidence_hash_32;
        self
    }

    /// Whether a given step's bit is set.
    #[inline]
    pub const fn is_step_green(&self, step: MainnetChecklistStep) -> bool {
        self.green_mask_u8 & step.bit() != 0
    }

    /// Whether every step bit is set.
    #[inline]
    pub const fn all_green(&self) -> bool {
        self.green_mask_u8 == Self::ALL_GREEN_MASK
    }

    /// Whether the evidence hash is non-zero (some evidence bundle is bound).
    #[inline]
    pub const fn has_evidence_hash(&self) -> bool {
        let h = &self.evidence_hash_32;
        let mut i = 0;
        while i < 32 {
            if h[i] != 0 {
                return true;
            }
            i += 1;
        }
        false
    }

    /// The execution posture this checklist *permits*.
    ///
    /// Returns [`ApprovalPending`](MainnetExecutionState::ApprovalPending) only
    /// when [`all_green`](Self::all_green) **and** [`has_evidence_hash`](Self::has_evidence_hash);
    /// otherwise [`Locked`](MainnetExecutionState::Locked). It never returns
    /// [`Executed`](MainnetExecutionState::Executed) — execution is gated by the
    /// later operator-approval ceremony, not by this type.
    #[inline]
    pub const fn ready_state(&self) -> MainnetExecutionState {
        if self.all_green() && self.has_evidence_hash() {
            MainnetExecutionState::ApprovalPending
        } else {
            MainnetExecutionState::Locked
        }
    }

    /// Serialize to the fixed [`MAINNET_CHECKLIST_BYTES`] byte form:
    /// `green_mask_u8 ‖ state ‖ evidence_hash_32`.
    pub fn to_bytes(&self) -> [u8; MAINNET_CHECKLIST_BYTES] {
        let mut out = [0u8; MAINNET_CHECKLIST_BYTES];
        out[0] = self.green_mask_u8;
        out[1] = self.state.as_u8();
        out[2..MAINNET_CHECKLIST_BYTES].copy_from_slice(&self.evidence_hash_32);
        out
    }

    /// Parse a checklist from its fixed [`MAINNET_CHECKLIST_BYTES`] byte form,
    /// rejecting an unknown execution-state discriminant.
    pub fn from_bytes(bytes: &[u8; MAINNET_CHECKLIST_BYTES]) -> Option<Self> {
        let state = MainnetExecutionState::from_u8(bytes[1])?;
        let mut evidence_hash_32 = [0u8; 32];
        evidence_hash_32.copy_from_slice(&bytes[2..MAINNET_CHECKLIST_BYTES]);
        Some(Self {
            green_mask_u8: bytes[0],
            state,
            evidence_hash_32,
        })
    }
}

impl Default for MainnetChecklist {
    #[inline]
    fn default() -> Self {
        Self::new_locked()
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]
    use super::*;

    #[test]
    fn checklist_byte_width_is_34() {
        assert_eq!(MAINNET_CHECKLIST_BYTES, 34);
    }

    #[test]
    fn step_bit_mapping_is_distinct_and_covers_the_mask() {
        let mut union = 0u8;
        for (i, step) in MainnetChecklistStep::ALL.iter().enumerate() {
            assert_eq!(step.bit(), 1u8 << i);
            // each bit is distinct
            assert_eq!(union & step.bit(), 0);
            union |= step.bit();
        }
        assert_eq!(union, MainnetChecklist::ALL_GREEN_MASK);
        assert_eq!(MainnetChecklist::ALL_GREEN_MASK, 0b0011_1111);
    }

    #[test]
    fn step_rejects_unknown_discriminant() {
        for b in [0u8, 7, 8, 255] {
            assert!(MainnetChecklistStep::from_u8(b).is_none());
        }
        for b in 1u8..=6 {
            assert!(MainnetChecklistStep::from_u8(b).is_some());
        }
    }

    #[test]
    fn all_green_mask_requires_every_step() {
        let mut cl = MainnetChecklist::new_locked();
        assert!(!cl.all_green());
        for step in MainnetChecklistStep::ALL {
            assert!(!cl.is_step_green(step));
            cl = cl.with_step(step, true);
            assert!(cl.is_step_green(step));
        }
        assert!(cl.all_green());
        assert_eq!(cl.green_mask_u8, MainnetChecklist::ALL_GREEN_MASK);
        // clearing any single step breaks all_green
        let broken = cl.with_step(MainnetChecklistStep::OperatorApproval, false);
        assert!(!broken.all_green());
    }

    #[test]
    fn missing_evidence_is_red_even_when_all_steps_green() {
        // all six steps green but zero evidence hash → still Locked
        let mut cl = MainnetChecklist::new_locked();
        for step in MainnetChecklistStep::ALL {
            cl = cl.with_step(step, true);
        }
        assert!(cl.all_green());
        assert!(!cl.has_evidence_hash());
        assert_eq!(cl.ready_state(), MainnetExecutionState::Locked);

        // bind a non-zero evidence hash → ApprovalPending (never Executed)
        let ready = cl.with_evidence_hash([0x11; 32]);
        assert!(ready.has_evidence_hash());
        assert_eq!(ready.ready_state(), MainnetExecutionState::ApprovalPending);
        assert_ne!(ready.ready_state(), MainnetExecutionState::Executed);
        assert!(!ready.ready_state().is_executable());
    }

    #[test]
    fn partial_checklist_stays_locked() {
        let cl = MainnetChecklist::new_locked()
            .with_step(MainnetChecklistStep::StageBEvidence, true)
            .with_step(MainnetChecklistStep::ProofAndGas, true)
            .with_evidence_hash([0x22; 32]);
        assert!(!cl.all_green());
        assert_eq!(cl.ready_state(), MainnetExecutionState::Locked);
    }

    #[test]
    fn checklist_roundtrips_through_bytes() {
        let cl = MainnetChecklist::new_locked()
            .with_step(MainnetChecklistStep::StageBEvidence, true)
            .with_step(MainnetChecklistStep::ProofAndGas, true)
            .with_evidence_hash([0x33; 32]);
        let bytes = cl.to_bytes();
        assert_eq!(bytes.len(), MAINNET_CHECKLIST_BYTES);
        assert_eq!(MainnetChecklist::from_bytes(&bytes), Some(cl));
    }

    #[test]
    fn from_bytes_rejects_unknown_state() {
        let cl = MainnetChecklist::new_locked();
        let mut bad = cl.to_bytes();
        bad[1] = 99;
        assert!(MainnetChecklist::from_bytes(&bad).is_none());
    }

    #[test]
    fn default_is_locked_and_empty() {
        let cl = MainnetChecklist::default();
        assert_eq!(cl.green_mask_u8, 0);
        assert_eq!(cl.state, MainnetExecutionState::Locked);
        assert!(!cl.has_evidence_hash());
        assert_eq!(cl.ready_state(), MainnetExecutionState::Locked);
    }
}
