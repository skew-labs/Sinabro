//! Self-report reward firewall (atom #378 · E.2.7).
//!
//! The firewall enforces the consistency-lock rule **"only S1 may earn
//! reward"**: a `SAFE-TO-COMMIT` stamp, a `Grade-A` self-grade, a model verdict,
//! an assistant summary, or human praise can enter SFT *context* but can never
//! set a reward label. Reward eligibility is granted **only** when an
//! independent S1 ground-truth signal (a passing compiler/test/prover/gas
//! result, reverified) backs the sample — and even then downstream nullifiers
//! still apply. Reuses [`RewardEligibility`] (S2 reward is type-impossible).
use crate::stream_split::RewardEligibility;

/// The class of a self-reported claim seen in a sidecar.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
#[repr(u8)]
pub enum SelfReportClass {
    /// A `SAFE-TO-COMMIT` / `SAFE TO COMMIT` stamp.
    SafeToCommit = 1,
    /// A letter self-grade (`Grade-A`, `A+`, …).
    SelfGrade = 2,
    /// A model / assistant verdict or summary ("looks correct", "this works").
    ModelVerdict = 3,
    /// Human praise ("great job", "perfect").
    HumanPraise = 4,
    /// An S1 ground-truth claim (compiler/test/prover/gas) — eligible *iff* reverified.
    GroundTruthClaim = 5,
}

impl SelfReportClass {
    /// Numeric discriminant (`1..=5`).
    pub const fn as_u8(self) -> u8 {
        self as u8
    }

    /// Classify a claim string fail-closed: a self-report stamp dominates, and
    /// anything not an explicit ground-truth marker is treated as narrative.
    pub fn classify(claim: &str) -> Self {
        let c = claim.trim().to_ascii_lowercase();
        if c.contains("safe-to-commit") || c.contains("safe to commit") {
            Self::SafeToCommit
        } else if c.contains("grade-") || c.contains("grade ") || c.contains("self-grade") {
            Self::SelfGrade
        } else if c.contains("great job")
            || c.contains("well done")
            || c.contains("perfect")
            || c.contains("praise")
        {
            Self::HumanPraise
        } else if c.contains("tests pass")
            || c.contains("test pass")
            || c.contains("ground truth")
            || c.contains("reverified")
            || c.contains("exit 0")
        {
            Self::GroundTruthClaim
        } else {
            Self::ModelVerdict
        }
    }

    /// Whether this class is an S1 ground-truth claim (the only class that *can*
    /// be reward-eligible, and only when independently reverified).
    pub const fn is_ground_truth(self) -> bool {
        matches!(self, Self::GroundTruthClaim)
    }
}

/// Decide reward eligibility for a claim. A claim is reward-eligible **only** if
/// it is an S1 ground-truth class *and* `s1_reverified` is true; every
/// self-report / praise / verdict class yields `NoRewardNarrative`. An
/// unreverified ground-truth claim yields `NoRewardUnverified` (queued, not
/// rewarded). Self-report can never buy reward, even alongside a reverify claim.
pub fn firewall(class: SelfReportClass, s1_reverified: bool) -> RewardEligibility {
    match class {
        SelfReportClass::GroundTruthClaim if s1_reverified => RewardEligibility::Eligible,
        SelfReportClass::GroundTruthClaim => RewardEligibility::NoRewardUnverified,
        _ => RewardEligibility::NoRewardNarrative,
    }
}

/// Convenience: classify a claim string and apply the firewall.
pub fn firewall_claim(claim: &str, s1_reverified: bool) -> RewardEligibility {
    firewall(SelfReportClass::classify(claim), s1_reverified)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn safe_to_commit_never_rewards() {
        assert_eq!(
            SelfReportClass::classify("SAFE-TO-COMMIT: all tests pass"),
            SelfReportClass::SafeToCommit
        );
        // even with s1_reverified = true, a self-report stamp is narrative.
        assert_eq!(
            firewall(SelfReportClass::SafeToCommit, true),
            RewardEligibility::NoRewardNarrative
        );
        assert!(!firewall(SelfReportClass::SafeToCommit, true).is_eligible());
    }

    #[test]
    fn self_grade_never_rewards() {
        assert_eq!(
            SelfReportClass::classify("Grade-A work"),
            SelfReportClass::SelfGrade
        );
        assert_eq!(
            firewall_claim("Grade-A work", true),
            RewardEligibility::NoRewardNarrative
        );
    }

    #[test]
    fn human_praise_never_rewards() {
        assert_eq!(
            SelfReportClass::classify("great job, perfect"),
            SelfReportClass::HumanPraise
        );
        assert!(!firewall_claim("great job", true).is_eligible());
    }

    #[test]
    fn reverified_ground_truth_is_eligible() {
        assert_eq!(
            SelfReportClass::classify("all tests pass, reverified"),
            SelfReportClass::GroundTruthClaim
        );
        assert_eq!(
            firewall_claim("all tests pass", true),
            RewardEligibility::Eligible
        );
    }

    #[test]
    fn unreverified_ground_truth_is_queued_not_rewarded() {
        assert_eq!(
            firewall_claim("tests pass", false),
            RewardEligibility::NoRewardUnverified
        );
        assert!(!firewall_claim("tests pass", false).is_eligible());
    }
}
