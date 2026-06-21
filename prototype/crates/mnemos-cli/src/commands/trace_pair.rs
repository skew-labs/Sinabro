//! `sinabro trace pair` — trace S1/S2 pairing + contribution rights view
//! (F-WP-06B, atom #456 · F.6.5).
//!
//! The user can see *why* a trace is S1 reward-eligible, S2 narrative-only,
//! private-only, eval-only, or contribution-denied. No reward is ever earned from
//! self-report, raw external-model output, a private repo without rights, or a
//! missing opt-in. Audit candidates are S2 / advisory until a local reproducer or
//! no-finding analysis is evidence-backed; a frontier consult can explain risk
//! but never certifies a bug.
//!
//! Reuse (no reinvention): the records are the Stage E [`S1GroundTruthRecord`] /
//! [`S2NarrativeRecord`]; eligibility is [`RewardEligibility`]; the stream tag is
//! [`StreamKind`] via [`stream_kind_of`]. This module performs no live action.

use crate::tui::RenderTruth;
use mnemos_l_dataset::DietFileKind;
use mnemos_l_dataset::stream_split::{
    RewardEligibility, S1GroundTruthRecord, S2NarrativeRecord, StreamKind, stream_kind_of,
};

/// Why a trace-pair command was refused (fail-closed).
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum TracePairReject {
    /// Raw external-model output is not a recordable trace.
    #[error("raw provider output cannot be a trace record")]
    ProviderOutput,
    /// The user opt-in / consent is missing.
    #[error("consent (opt-in) missing")]
    ConsentMissing,
}

/// How a trace may be used. Only [`TraceClass::S1RewardEligible`] earns reward.
#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TraceClass {
    /// S1 ground-truth, reward eligible.
    S1RewardEligible = 1,
    /// S2 narrative only — never reward.
    S2NarrativeOnly = 2,
    /// Kept private by the user — never contributed or rewarded.
    PrivateOnly = 3,
    /// Eval-only usage — not a reward record.
    EvalOnly = 4,
    /// Contribution denied (no rights / revoked).
    ContributionDenied = 5,
}

impl TraceClass {
    /// Stable u8 discriminant.
    #[must_use]
    pub const fn as_u8(self) -> u8 {
        self as u8
    }
}

/// The facts that decide a trace's class. All default `false`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub struct TraceFacts {
    /// The trace is an S1 ground-truth candidate.
    pub ground_truth: bool,
    /// The trace was locally reverified.
    pub verified: bool,
    /// The trace is a model self-report / self-grade.
    pub self_report: bool,
    /// The trace carries raw external-model (frontier) output.
    pub external_model_raw: bool,
    /// Contribution/usage rights are present.
    pub has_rights: bool,
    /// The user opt-in is present.
    pub opt_in: bool,
    /// The user marked the trace private-only.
    pub private_only: bool,
    /// The trace is for eval only.
    pub eval_only: bool,
    /// The trace originated from the audit detector.
    pub audit_candidate: bool,
    /// An audit candidate has a local reproducer/proof.
    pub local_repro_done: bool,
    /// Only a frontier consult backs the trace (no local proof).
    pub frontier_only: bool,
    /// Future contribution was revoked by the user.
    pub contribution_revoked: bool,
}

/// A `sinabro trace pair` projection: the trace class and whether it earns reward.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TracePairView {
    /// The trace class.
    pub class: TraceClass,
    /// Whether the trace is reward eligible (only when `class` is
    /// [`TraceClass::S1RewardEligible`]).
    pub reward_eligible: bool,
}

impl TracePairView {
    /// Whether the facts make the trace S1 reward-eligible. Reward needs a
    /// verified ground-truth trace, with rights + opt-in, that is not a
    /// self-report, not raw frontier output, not frontier-only, and — if it came
    /// from the audit detector — has a local reproducer/proof.
    #[must_use]
    fn is_reward_eligible(f: &TraceFacts) -> bool {
        f.ground_truth
            && f.verified
            && !f.self_report
            && !f.external_model_raw
            && f.has_rights
            && f.opt_in
            && !f.frontier_only
            && (!f.audit_candidate || f.local_repro_done)
    }

    /// Classify a trace. Raw provider output and a missing opt-in fail closed;
    /// otherwise the class (and thus reward eligibility) is derived from the facts.
    pub fn classify(f: TraceFacts) -> Result<Self, TracePairReject> {
        if f.external_model_raw {
            return Err(TracePairReject::ProviderOutput);
        }
        if !f.opt_in {
            return Err(TracePairReject::ConsentMissing);
        }
        let class = if f.contribution_revoked || !f.has_rights {
            TraceClass::ContributionDenied
        } else if f.private_only {
            TraceClass::PrivateOnly
        } else if f.eval_only {
            TraceClass::EvalOnly
        } else if Self::is_reward_eligible(&f) {
            TraceClass::S1RewardEligible
        } else {
            TraceClass::S2NarrativeOnly
        };
        Ok(Self {
            class,
            reward_eligible: matches!(class, TraceClass::S1RewardEligible),
        })
    }

    /// Render truth: a reward-eligible S1 trace is `Green`; an explicit
    /// contribution-denied trace is `Red`; every other class is `Yellow` (a
    /// visible non-reward posture).
    #[must_use]
    pub fn render_truth(&self) -> RenderTruth {
        match self.class {
            TraceClass::S1RewardEligible => RenderTruth::Green,
            TraceClass::ContributionDenied => RenderTruth::Red,
            _ => RenderTruth::Yellow,
        }
    }

    /// Colorless status lines bounded by `rows`.
    #[must_use]
    pub fn render(&self, rows: u16) -> Vec<String> {
        let lines = vec![
            format!("trace_class_u8={}", self.class.as_u8()),
            format!("reward_eligible={}", self.reward_eligible),
            format!("truth_u8={}", self.render_truth() as u8),
        ];
        lines.into_iter().take(rows as usize).collect()
    }
}

/// The reward eligibility an S1 ground-truth record carries (reuse).
#[must_use]
pub fn s1_record_reward(rec: &S1GroundTruthRecord) -> RewardEligibility {
    rec.reward
}

/// The reward eligibility an S2 narrative record carries — always blocked (reuse).
#[must_use]
pub fn s2_record_reward(rec: &S2NarrativeRecord) -> RewardEligibility {
    rec.reward
}

/// The stream a diet file kind belongs to (reuse of [`stream_kind_of`]).
#[must_use]
pub fn stream_of(kind: DietFileKind) -> StreamKind {
    stream_kind_of(kind)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    #![allow(clippy::expect_used)]
    #![allow(clippy::panic)]

    use super::*;
    use mnemos_l_dataset::AtomDietKey;
    use mnemos_l_dataset::diet_kind::DietSourceStage;

    const COMMERCE_TOKENS: &[&str] = &[
        "price", "pay", "buy", "sell", "checkout", "refund", "fee", "cost", "$",
    ];

    fn key() -> AtomDietKey {
        AtomDietKey::new(DietSourceStage::StageD, 252)
    }

    /// A fully clean, verified, rights-clear, opted-in ground-truth trace.
    fn clean() -> TraceFacts {
        TraceFacts {
            ground_truth: true,
            verified: true,
            has_rights: true,
            opt_in: true,
            ..TraceFacts::default()
        }
    }

    #[test]
    fn s1_eligible_is_rewarded() {
        let v = TracePairView::classify(clean()).unwrap();
        assert_eq!(v.class, TraceClass::S1RewardEligible);
        assert!(v.reward_eligible);
        assert_eq!(v.render_truth(), RenderTruth::Green);
    }

    #[test]
    fn s2_narrative_earns_no_reward() {
        let f = TraceFacts {
            ground_truth: false,
            ..clean()
        };
        let v = TracePairView::classify(f).unwrap();
        assert_eq!(v.class, TraceClass::S2NarrativeOnly);
        assert!(!v.reward_eligible);
    }

    #[test]
    fn unverified_earns_no_reward() {
        let f = TraceFacts {
            verified: false,
            ..clean()
        };
        let v = TracePairView::classify(f).unwrap();
        assert!(!v.reward_eligible);
    }

    #[test]
    fn privacy_without_rights_is_contribution_denied() {
        let f = TraceFacts {
            has_rights: false,
            ..clean()
        };
        let v = TracePairView::classify(f).unwrap();
        assert_eq!(v.class, TraceClass::ContributionDenied);
        assert!(!v.reward_eligible);
        assert_eq!(v.render_truth(), RenderTruth::Red);
    }

    #[test]
    fn raw_provider_output_denied() {
        let f = TraceFacts {
            external_model_raw: true,
            ..clean()
        };
        assert_eq!(
            TracePairView::classify(f),
            Err(TracePairReject::ProviderOutput)
        );
    }

    #[test]
    fn consent_missing_denied() {
        let f = TraceFacts {
            opt_in: false,
            ..clean()
        };
        assert_eq!(
            TracePairView::classify(f),
            Err(TracePairReject::ConsentMissing)
        );
    }

    #[test]
    fn revoked_contribution_is_denied() {
        let f = TraceFacts {
            contribution_revoked: true,
            ..clean()
        };
        let v = TracePairView::classify(f).unwrap();
        assert_eq!(v.class, TraceClass::ContributionDenied);
        assert!(!v.reward_eligible);
    }

    #[test]
    fn audit_candidate_is_s2_until_local_repro() {
        let pending = TraceFacts {
            audit_candidate: true,
            local_repro_done: false,
            ..clean()
        };
        let v = TracePairView::classify(pending).unwrap();
        assert_eq!(v.class, TraceClass::S2NarrativeOnly);
        assert!(!v.reward_eligible);

        let reproduced = TraceFacts {
            audit_candidate: true,
            local_repro_done: true,
            ..clean()
        };
        let v2 = TracePairView::classify(reproduced).unwrap();
        assert_eq!(v2.class, TraceClass::S1RewardEligible);
        assert!(v2.reward_eligible);
    }

    #[test]
    fn frontier_only_does_not_promote() {
        let f = TraceFacts {
            frontier_only: true,
            ..clean()
        };
        let v = TracePairView::classify(f).unwrap();
        assert_eq!(v.class, TraceClass::S2NarrativeOnly);
        assert!(!v.reward_eligible);
    }

    #[test]
    fn canonical_record_reward_reuse() {
        let s1 = S1GroundTruthRecord::eligible(key(), [1; 32], [2; 32]);
        assert_eq!(s1_record_reward(&s1), RewardEligibility::Eligible);
        let s2 = S2NarrativeRecord::new(key(), [3; 32]);
        assert_eq!(s2_record_reward(&s2), RewardEligibility::NoRewardNarrative);
        assert!(!s2_record_reward(&s2).is_eligible());
        // The stream tag is the canonical mapping.
        assert_eq!(
            stream_of(DietFileKind::InputContext),
            stream_kind_of(DietFileKind::InputContext)
        );
    }

    #[test]
    fn render_bounded_no_commerce_and_p95_within_100ms() {
        let v = TracePairView::classify(clean()).unwrap();
        assert!(v.render(2).len() <= 2);
        assert!(v.render(64).len() <= 3);
        for line in v.render(64) {
            for bad in COMMERCE_TOKENS {
                assert!(!line.contains(bad), "commerce token {bad} in {line}");
            }
        }
        let mut samples = Vec::with_capacity(256);
        for _ in 0..256 {
            let t = std::time::Instant::now();
            let lines = v.render(32);
            std::hint::black_box(&lines);
            samples.push(t.elapsed().as_nanos() as u64);
        }
        let p95 = crate::repl::latency::p95_ms(&samples) / 1_000_000;
        assert!(p95 <= 100, "trace pair p95 {p95}ms exceeds 100ms budget");
    }
}
