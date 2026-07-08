//! Layered reward labels (`LayeredRewardLabel` / `RewardMilli`).
//!
//! # Design
//!
//! `0 / 0.5 / 1.0 / +bonus` labels derive **only** from S1 execution results and
//! measured deltas. S2 narrative can never reach this API (a non-S1 stream
//! returns `NoRewardNarrative`). Before any positive label, eight hard nullifiers
//! fire — test/evaluator tamper, split leakage, secret/provider/private-memory/
//! sponsor/wallet leak, unapproved live side effect, canonical reinvention,
//! self-report reward, test deletion/weakening, and archive-as-consent — each
//! forcing reward to `Zero`. Surviving samples also carry the early Naite
//! composite weights (32/20/16/12/10/6/4 = 100). The repair-process axis is
//! denied until execution is green, and a [`DidacticSignal`](super::failure_cause::DidacticSignal)'s
//! `reward_allowed` must agree with the label's S1 eligibility.
//!
//! ## Secret custody
//!
//! This module holds **no** secret/wallet material and imports no
//! network/wallet/process/filesystem-write API. A secret / provider-body /
//! private-memory / sponsor-key / wallet-secret leak arrives as the
//! [`HardNullifiers::secret_or_wallet_leak`] bit (computed upstream by
//! `privacy_scanner::ScanReport` / `privacy::PrivacyReport`) and is a hard
//! nullifier: such a sample is forced to `reward = Zero`, `eligible =
//! NoRewardPrivacy`, and can never earn a positive label.
use crate::diet_kind::AtomDietKey;
use crate::stream_split::{RewardEligibility, StreamKind};

use super::failure_cause::FailureCause;

/// The early Naite composite axis weights, in percent (sum = 100): execution
/// correctness, evidence integrity, atom-scope/reuse/minimal-diff, repair
/// process, security/privacy chain, token/latency/gas perf, bilingual
/// explanation.
pub const NAITE_COMPOSITE_WEIGHTS_BPS: [u8; 7] = [32, 20, 16, 12, 10, 6, 4];

/// The sum of the Naite composite weights (must be `100`).
pub const fn naite_weight_sum() -> u16 {
    let w = NAITE_COMPOSITE_WEIGHTS_BPS;
    (w[0] as u16)
        + (w[1] as u16)
        + (w[2] as u16)
        + (w[3] as u16)
        + (w[4] as u16)
        + (w[5] as u16)
        + (w[6] as u16)
}

/// The discrete reward scalar (`RewardMilli`), in milli-units.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
#[repr(i16)]
pub enum RewardMilli {
    /// No reward.
    Zero = 0,
    /// Half reward (partial pass).
    Half = 500,
    /// Full reward (full pass).
    One = 1000,
    /// Full reward plus a measured-performance bonus.
    BonusMax = 1100,
}

impl RewardMilli {
    /// Numeric value in milli-units.
    pub const fn as_i16(self) -> i16 {
        self as i16
    }
}

/// The S1 execution outcome a reward derives from.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
#[repr(u8)]
pub enum ExecutionResult {
    /// The change did not compile / build.
    CompileFail = 1,
    /// The change partially passed (some tests/gates green).
    PartialPass = 2,
    /// The change fully passed (all required gates green).
    FullPass = 3,
}

/// The eight hard nullifiers that block any positive reward.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Hash)]
pub struct HardNullifiers {
    /// A test or evaluator was tampered with.
    pub test_or_evaluator_tamper: bool,
    /// Train/held-out split leakage was detected.
    pub split_leakage: bool,
    /// A secret / provider body / private memory / sponsor key / wallet secret leaked.
    pub secret_or_wallet_leak: bool,
    /// An unapproved live side effect occurred.
    pub unapproved_live_side_effect: bool,
    /// A canonical type was reinvented.
    pub canonical_reinvention: bool,
    /// Reward was claimed from a self-report.
    pub self_report_reward: bool,
    /// A test was deleted or weakened.
    pub test_deletion_or_weakening: bool,
    /// An archive locator / CID was treated as training consent.
    pub archive_as_consent: bool,
}

impl HardNullifiers {
    /// A nullifier set with nothing tripped.
    pub const fn none() -> Self {
        Self {
            test_or_evaluator_tamper: false,
            split_leakage: false,
            secret_or_wallet_leak: false,
            unapproved_live_side_effect: false,
            canonical_reinvention: false,
            self_report_reward: false,
            test_deletion_or_weakening: false,
            archive_as_consent: false,
        }
    }

    /// Whether any nullifier is tripped.
    pub const fn any(&self) -> bool {
        self.test_or_evaluator_tamper
            || self.split_leakage
            || self.secret_or_wallet_leak
            || self.unapproved_live_side_effect
            || self.canonical_reinvention
            || self.self_report_reward
            || self.test_deletion_or_weakening
            || self.archive_as_consent
    }
}

/// A layered reward label.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub struct LayeredRewardLabel {
    /// The source atom.
    pub key: AtomDietKey,
    /// The discrete reward scalar.
    pub reward: RewardMilli,
    /// The governed failure cause.
    pub cause: FailureCause,
    /// The S1 eligibility verdict.
    pub eligible: RewardEligibility,
}

/// The no-reward eligibility a masking cause forces, or `None` for a clean
/// `Model` cause that may proceed to a positive label.
const fn cause_masked_eligibility(cause: FailureCause) -> Option<RewardEligibility> {
    match cause {
        FailureCause::Infra | FailureCause::Timeout | FailureCause::ToolLoop => {
            Some(RewardEligibility::NoRewardInfra)
        }
        FailureCause::Privacy => Some(RewardEligibility::NoRewardPrivacy),
        FailureCause::HumanRejected => Some(RewardEligibility::NoRewardNarrative),
        FailureCause::Model => None,
    }
}

/// Compute the layered reward label for one sample.
///
/// Gating order (fail-closed): S2 stream → masking cause → hard nullifiers →
/// S1 reverify eligibility → execution-result reward. Only an S1 stream with a
/// clean `Model` cause, zero nullifiers, and a reverified-eligible S1 verdict can
/// earn a positive scalar.
pub fn layered_reward(
    key: AtomDietKey,
    stream: StreamKind,
    s1_eligibility: RewardEligibility,
    execution: ExecutionResult,
    performance_bonus: bool,
    cause: FailureCause,
    nullifiers: HardNullifiers,
) -> LayeredRewardLabel {
    if !matches!(stream, StreamKind::S1GroundTruth) {
        return LayeredRewardLabel {
            key,
            reward: RewardMilli::Zero,
            cause,
            eligible: RewardEligibility::NoRewardNarrative,
        };
    }
    if nullifiers.any() {
        let eligible = if nullifiers.secret_or_wallet_leak {
            RewardEligibility::NoRewardPrivacy
        } else {
            RewardEligibility::NoRewardNarrative
        };
        return LayeredRewardLabel {
            key,
            reward: RewardMilli::Zero,
            cause,
            eligible,
        };
    }
    if let Some(eligible) = cause_masked_eligibility(cause) {
        return LayeredRewardLabel {
            key,
            reward: RewardMilli::Zero,
            cause,
            eligible,
        };
    }
    if !s1_eligibility.is_eligible() {
        return LayeredRewardLabel {
            key,
            reward: RewardMilli::Zero,
            cause,
            eligible: s1_eligibility,
        };
    }
    let reward = match execution {
        ExecutionResult::CompileFail => RewardMilli::Zero,
        ExecutionResult::PartialPass => RewardMilli::Half,
        ExecutionResult::FullPass => {
            if performance_bonus {
                RewardMilli::BonusMax
            } else {
                RewardMilli::One
            }
        }
    };
    LayeredRewardLabel {
        key,
        reward,
        cause,
        eligible: RewardEligibility::Eligible,
    }
}

/// Whether the repair-process axis (weight 12) may score: only when execution is
/// green (`FullPass`) and the label is reward-eligible. "Process reward is denied
/// before execution green."
pub const fn process_axis_allowed(execution: ExecutionResult, eligible: RewardEligibility) -> bool {
    matches!(execution, ExecutionResult::FullPass) && eligible.is_eligible()
}

/// Whether a didactic signal's `reward_allowed` agrees with the label's S1
/// eligibility.
pub const fn didactic_reward_allowed_consistent(
    label: &LayeredRewardLabel,
    didactic_reward_allowed: bool,
) -> bool {
    label.eligible.is_eligible() == didactic_reward_allowed
}

/// Enforce didactic agreement: if a didactic signal's `reward_allowed` disagrees
/// with the label's S1 eligibility, the reward is voided (mismatch ⇒ zero).
pub fn enforce_didactic_agreement(
    label: LayeredRewardLabel,
    didactic_reward_allowed: bool,
) -> LayeredRewardLabel {
    if didactic_reward_allowed_consistent(&label, didactic_reward_allowed) {
        label
    } else {
        LayeredRewardLabel {
            reward: RewardMilli::Zero,
            eligible: RewardEligibility::NoRewardNarrative,
            ..label
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::diet_kind::DietSourceStage;

    fn key() -> AtomDietKey {
        AtomDietKey::new(DietSourceStage::Phase0, 389)
    }

    fn reward(
        stream: StreamKind,
        elig: RewardEligibility,
        exec: ExecutionResult,
        bonus: bool,
        cause: FailureCause,
        nulls: HardNullifiers,
    ) -> LayeredRewardLabel {
        layered_reward(key(), stream, elig, exec, bonus, cause, nulls)
    }

    #[test]
    fn weight_sum_is_100() {
        assert_eq!(naite_weight_sum(), 100);
    }

    #[test]
    fn compile_fail_is_zero() {
        let l = reward(
            StreamKind::S1GroundTruth,
            RewardEligibility::Eligible,
            ExecutionResult::CompileFail,
            false,
            FailureCause::Model,
            HardNullifiers::none(),
        );
        assert_eq!(l.reward, RewardMilli::Zero);
        assert_eq!(l.reward.as_i16(), 0);
    }

    #[test]
    fn partial_pass_is_half() {
        let l = reward(
            StreamKind::S1GroundTruth,
            RewardEligibility::Eligible,
            ExecutionResult::PartialPass,
            false,
            FailureCause::Model,
            HardNullifiers::none(),
        );
        assert_eq!(l.reward, RewardMilli::Half);
    }

    #[test]
    fn full_pass_is_one() {
        let l = reward(
            StreamKind::S1GroundTruth,
            RewardEligibility::Eligible,
            ExecutionResult::FullPass,
            false,
            FailureCause::Model,
            HardNullifiers::none(),
        );
        assert_eq!(l.reward, RewardMilli::One);
        assert_eq!(l.eligible, RewardEligibility::Eligible);
    }

    #[test]
    fn performance_bonus_is_bonus_max() {
        let l = reward(
            StreamKind::S1GroundTruth,
            RewardEligibility::Eligible,
            ExecutionResult::FullPass,
            true,
            FailureCause::Model,
            HardNullifiers::none(),
        );
        assert_eq!(l.reward, RewardMilli::BonusMax);
    }

    #[test]
    fn s2_stream_is_blocked() {
        let l = reward(
            StreamKind::S2Narrative,
            RewardEligibility::Eligible,
            ExecutionResult::FullPass,
            true,
            FailureCause::Model,
            HardNullifiers::none(),
        );
        assert_eq!(l.reward, RewardMilli::Zero);
        assert_eq!(l.eligible, RewardEligibility::NoRewardNarrative);
    }

    #[test]
    fn any_nullifier_is_zero() {
        let mut n = HardNullifiers::none();
        n.test_deletion_or_weakening = true;
        let l = reward(
            StreamKind::S1GroundTruth,
            RewardEligibility::Eligible,
            ExecutionResult::FullPass,
            true,
            FailureCause::Model,
            n,
        );
        assert_eq!(l.reward, RewardMilli::Zero);
    }

    #[test]
    fn secret_leak_nullifier_is_privacy_zero() {
        let mut n = HardNullifiers::none();
        n.secret_or_wallet_leak = true;
        let l = reward(
            StreamKind::S1GroundTruth,
            RewardEligibility::Eligible,
            ExecutionResult::FullPass,
            true,
            FailureCause::Model,
            n,
        );
        assert_eq!(l.reward, RewardMilli::Zero);
        assert_eq!(l.eligible, RewardEligibility::NoRewardPrivacy);
    }

    #[test]
    fn archive_as_consent_is_zero() {
        let mut n = HardNullifiers::none();
        n.archive_as_consent = true;
        let l = reward(
            StreamKind::S1GroundTruth,
            RewardEligibility::Eligible,
            ExecutionResult::FullPass,
            true,
            FailureCause::Model,
            n,
        );
        assert_eq!(l.reward, RewardMilli::Zero);
    }

    #[test]
    fn process_reward_denied_before_execution_green() {
        assert!(!process_axis_allowed(
            ExecutionResult::PartialPass,
            RewardEligibility::Eligible
        ));
        assert!(process_axis_allowed(
            ExecutionResult::FullPass,
            RewardEligibility::Eligible
        ));
        assert!(!process_axis_allowed(
            ExecutionResult::FullPass,
            RewardEligibility::NoRewardUnverified
        ));
    }

    #[test]
    fn didactic_reward_allowed_mismatch_is_zero() {
        let l = reward(
            StreamKind::S1GroundTruth,
            RewardEligibility::Eligible,
            ExecutionResult::FullPass,
            false,
            FailureCause::Model,
            HardNullifiers::none(),
        );
        // didactic says reward NOT allowed while the label is eligible ⇒ mismatch ⇒ void.
        let voided = enforce_didactic_agreement(l, false);
        assert_eq!(voided.reward, RewardMilli::Zero);
        assert_eq!(voided.eligible, RewardEligibility::NoRewardNarrative);
        // agreement preserves the label.
        let kept = enforce_didactic_agreement(l, true);
        assert_eq!(kept.reward, RewardMilli::One);
    }
}
