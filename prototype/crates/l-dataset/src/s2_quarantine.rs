//! S2 narrative quarantine / export policy.
//!
//! Narrative (self-report, explanation, Korean rationale) is useful for **style,
//! honesty, and bilingual reasoning** and may be exported to SFT context — but it
//! is **toxic as reward** unless an independent S1 reverify backs it. This policy
//! composes the self-report firewall with the privacy gate: a narrative
//! is SFT-exportable when it is privacy-clean, and reward-blocked unless the
//! firewall returns `Eligible`. A hallucinated verdict (a claim contradicted by
//! S1) is kept only as negative context, never positive reward.
use crate::reward_firewall::{self, SelfReportClass};
use crate::stream_split::RewardEligibility;

/// The export / reward decision for one S2 narrative sample.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub struct S2QuarantineDecision {
    /// Exportable to SFT context (privacy-clean narrative is preserved).
    pub sft_exportable: bool,
    /// Reward is blocked (anything the firewall does not mark `Eligible`).
    pub reward_blocked: bool,
    /// The firewall eligibility verdict.
    pub eligibility: RewardEligibility,
    /// Negative-context-only: a verdict contradicted by S1 (hallucination).
    pub negative_context_only: bool,
}

/// Decide quarantine/export for an S2 narrative. `s1_reverified` must come from
/// an independent S1 signal, never from the narrative text. A contradiction with
/// S1 forces reward-blocked + negative-context-only, regardless of the claim.
pub fn decide(
    class: SelfReportClass,
    privacy_clean: bool,
    s1_reverified: bool,
    contradicted_by_s1: bool,
) -> S2QuarantineDecision {
    let eligibility = reward_firewall::firewall(class, s1_reverified && !contradicted_by_s1);
    S2QuarantineDecision {
        sft_exportable: privacy_clean,
        reward_blocked: !eligibility.is_eligible(),
        eligibility,
        negative_context_only: contradicted_by_s1,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn narrative_exports_to_sft_but_blocks_reward() {
        let d = decide(SelfReportClass::ModelVerdict, true, false, false);
        assert!(d.sft_exportable);
        assert!(d.reward_blocked);
        assert_eq!(d.eligibility, RewardEligibility::NoRewardNarrative);
    }

    #[test]
    fn honest_scope_narrative_is_preserved() {
        // a privacy-clean narrative is preserved for SFT even when not reward-eligible.
        let d = decide(SelfReportClass::HumanPraise, true, true, false);
        assert!(d.sft_exportable);
        assert!(d.reward_blocked);
    }

    #[test]
    fn s1_backed_ground_truth_is_reward_allowed() {
        let d = decide(SelfReportClass::GroundTruthClaim, true, true, false);
        assert_eq!(d.eligibility, RewardEligibility::Eligible);
        assert!(!d.reward_blocked);
        assert!(d.sft_exportable);
    }

    #[test]
    fn hallucinated_verdict_is_negative_context_only() {
        // contradicted by S1: even a ground-truth-shaped claim is blocked + negative.
        let d = decide(SelfReportClass::GroundTruthClaim, true, true, true);
        assert!(d.reward_blocked);
        assert!(d.negative_context_only);
        assert!(d.sft_exportable); // still kept, but only as negative context
        assert_eq!(d.eligibility, RewardEligibility::NoRewardUnverified);
    }

    #[test]
    fn privacy_dirty_narrative_is_not_exportable() {
        let d = decide(SelfReportClass::ModelVerdict, false, false, false);
        assert!(!d.sft_exportable);
        assert!(d.reward_blocked);
    }
}
