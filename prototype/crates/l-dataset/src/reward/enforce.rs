//! Reverify-only reward enforcement.
//!
//! # Design
//!
//! A positive reward label requires a **reverified** command + evidence hash, or
//! it is downgraded to explicit no-reward. Human approval and a model summary
//! carry **zero** reward authority: they can never grant or sustain reward on
//! their own. This is the last gate before a label can carry a positive scalar.
use crate::diet_kind::AtomDietKey;
use crate::reverify::ReplayClass;
use crate::stream_split::RewardEligibility;

use super::layered::{LayeredRewardLabel, RewardMilli};

/// The reverify evidence backing a reward label.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub struct ReverifyEvidence {
    /// The source atom.
    pub key: AtomDietKey,
    /// `sha256` of the exact replayed command (non-zero when present).
    pub command_hash_32: [u8; 32],
    /// `sha256` of the reverify evidence (non-zero when present).
    pub evidence_hash_32: [u8; 32],
    /// How the command may be replayed.
    pub replay: ReplayClass,
    /// Whether the reverify actually re-ran and passed.
    pub reverified_pass: bool,
}

impl ReverifyEvidence {
    /// Whether this evidence justifies a positive reward: the command is
    /// replayable, it was re-run and passed, and both hashes are present.
    pub fn justifies_reward(&self) -> bool {
        matches!(self.replay, ReplayClass::Replayable)
            && self.reverified_pass
            && self.command_hash_32 != [0u8; 32]
            && self.evidence_hash_32 != [0u8; 32]
    }
}

/// Enforce reverify-only reward: a positive label not backed by a reverify pass
/// is downgraded to `Zero` / `NoRewardUnverified`. A reverified label is kept; a
/// label that is already `Zero` is unchanged.
pub fn enforce(label: LayeredRewardLabel, evidence: &ReverifyEvidence) -> LayeredRewardLabel {
    let positive = !matches!(label.reward, RewardMilli::Zero);
    if positive && !evidence.justifies_reward() {
        return LayeredRewardLabel {
            reward: RewardMilli::Zero,
            eligible: RewardEligibility::NoRewardUnverified,
            ..label
        };
    }
    label
}

/// Apply a human approval / model verdict to a label. **Intentionally inert**:
/// attestations carry no reward authority, so the label is returned unchanged.
/// This makes the no-bypass invariant explicit and testable — an approval can
/// never raise a no-reward label.
pub fn apply_attestation(
    label: LayeredRewardLabel,
    _human_approved: bool,
    _model_verdict_positive: bool,
) -> LayeredRewardLabel {
    label
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::diet_kind::DietSourceStage;
    use crate::reward::failure_cause::FailureCause;
    use crate::reward::layered::{ExecutionResult, HardNullifiers, layered_reward};
    use crate::stream_split::StreamKind;

    fn key() -> AtomDietKey {
        AtomDietKey::new(DietSourceStage::Phase0, 390)
    }

    fn eligible_label() -> LayeredRewardLabel {
        layered_reward(
            key(),
            StreamKind::S1GroundTruth,
            RewardEligibility::Eligible,
            ExecutionResult::FullPass,
            false,
            FailureCause::Model,
            HardNullifiers::none(),
        )
    }

    fn reverified() -> ReverifyEvidence {
        ReverifyEvidence {
            key: key(),
            command_hash_32: [7u8; 32],
            evidence_hash_32: [9u8; 32],
            replay: ReplayClass::Replayable,
            reverified_pass: true,
        }
    }

    #[test]
    fn reverified_label_is_eligible() {
        let l = enforce(eligible_label(), &reverified());
        assert_eq!(l.reward, RewardMilli::One);
        assert_eq!(l.eligible, RewardEligibility::Eligible);
    }

    #[test]
    fn unverified_label_is_no_reward() {
        let mut ev = reverified();
        ev.reverified_pass = false;
        let l = enforce(eligible_label(), &ev);
        assert_eq!(l.reward, RewardMilli::Zero);
        assert_eq!(l.eligible, RewardEligibility::NoRewardUnverified);
    }

    #[test]
    fn live_command_cannot_be_reverified() {
        let mut ev = reverified();
        ev.replay = ReplayClass::LiveDenied;
        let l = enforce(eligible_label(), &ev);
        assert_eq!(l.reward, RewardMilli::Zero);
        assert!(!ev.justifies_reward());
    }

    #[test]
    fn missing_evidence_hash_cannot_be_reverified() {
        let mut ev = reverified();
        ev.evidence_hash_32 = [0u8; 32];
        let l = enforce(eligible_label(), &ev);
        assert_eq!(l.reward, RewardMilli::Zero);
    }

    #[test]
    fn human_approval_cannot_bypass() {
        // an unverified (no-reward) label stays no-reward even with approval +
        // a positive model verdict.
        let mut ev = reverified();
        ev.reverified_pass = false;
        let downgraded = enforce(eligible_label(), &ev);
        let after = apply_attestation(downgraded, true, true);
        assert_eq!(after.reward, RewardMilli::Zero);
        assert_eq!(after.eligible, RewardEligibility::NoRewardUnverified);
    }

    #[test]
    fn s2_label_earns_no_reward() {
        let s2 = layered_reward(
            key(),
            StreamKind::S2Narrative,
            RewardEligibility::Eligible,
            ExecutionResult::FullPass,
            true,
            FailureCause::Model,
            HardNullifiers::none(),
        );
        let l = enforce(s2, &reverified());
        assert_eq!(l.reward, RewardMilli::Zero);
        assert_eq!(l.eligible, RewardEligibility::NoRewardNarrative);
    }
}
