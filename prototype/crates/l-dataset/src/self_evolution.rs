//! Context-quality, harness-quality, and self-evolution-candidate schemas
//! (atom #400 · E.3.14, §4.5 `ContextQualitySignal` / `HarnessQualitySignal` /
//! `SelfEvolutionCandidateManifest`).
//!
//! # Madness
//!
//! Stage E never *runs* self-evolution and never promotes a candidate. It only
//! normalizes the A-D trajectory and D's measurement-only telemetry into
//! **schema-only** evidence that a later stage (J/K) may evaluate **inside a
//! sandbox**. These records are not reward and not runtime policy — they fix
//! "what to experiment with later" (Stage E atom plan §1).
//!
//! Three fail-closed invariants make the schema safe to mint in Stage E:
//!
//! * **Evidence-backed only.** A quality signal or candidate built with an
//!   all-zero evidence anchor is rejected ([`DietError::QualitySignalUnbacked`])
//!   — there is no "prompt vibes" record.
//! * **Drift is observable.** [`HarnessQualitySignal::from_trace`] derives
//!   `silent_change_detected` from the trace itself (predicted decision ≠
//!   observed outcome ⇒ drift), so a silently mutated harness cannot look clean.
//! * **Authority cannot widen.** A [`SelfEvolutionCandidateManifest`] minted in
//!   Stage E has every promotion guard `true` and `authority_expansion_denied`
//!   hard-`true`; no constructor, setter, or method promotes a candidate,
//!   mutates production, or widens authority. [`SelfEvolutionCandidateManifest::validate`]
//!   rejects any manifest that left a guard off.
use crate::diet_kind::AtomDietKey;
use crate::error::{DietError, DietResult};

/// Basis-points ceiling (100.00%); every context-quality axis is a `0..=10_000`
/// ratio.
pub const QUALITY_AXIS_BPS_MAX: u16 = 10_000;

/// `true` iff every byte of the 32-byte anchor is zero (an absent evidence
/// hash). `const` so the schema validators below can run in `const fn`.
const fn is_zero_32(h: &[u8; 32]) -> bool {
    let mut i = 0;
    while i < 32 {
        if h[i] != 0 {
            return false;
        }
        i += 1;
    }
    true
}

/// A context-quality signal (§4.5 `ContextQualitySignal`).
///
/// Five evidence-backed basis-point axes scoring how well the context window was
/// assembled for one atom. Schema-only: never reward, never runtime policy.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub struct ContextQualitySignal {
    /// The source atom the signal scores.
    pub key: AtomDietKey,
    /// How relevant the assembled context was (basis points, `0..=10_000`).
    pub relevance_bps: u16,
    /// Whether the context was sufficient for the task (basis points).
    pub sufficiency_bps: u16,
    /// How well unrelated context was isolated out (basis points).
    pub isolation_bps: u16,
    /// Token economy of the assembled context (basis points).
    pub economy_bps: u16,
    /// How faithfully the context's provenance was preserved (basis points).
    pub provenance_bps: u16,
    /// `sha256` anchor of the trace evidence the score derives from.
    pub evidence_hash_32: [u8; 32],
}

impl ContextQualitySignal {
    /// Build an evidence-backed context-quality signal.
    ///
    /// Rejects an all-zero `evidence_hash_32` (no "prompt vibes" record,
    /// [`DietError::QualitySignalUnbacked`]) and any axis above
    /// [`QUALITY_AXIS_BPS_MAX`] (a ratio cannot exceed 100%,
    /// [`DietError::QualityAxisOutOfRange`]).
    pub fn new(
        key: AtomDietKey,
        relevance_bps: u16,
        sufficiency_bps: u16,
        isolation_bps: u16,
        economy_bps: u16,
        provenance_bps: u16,
        evidence_hash_32: [u8; 32],
    ) -> DietResult<Self> {
        if is_zero_32(&evidence_hash_32) {
            return Err(DietError::QualitySignalUnbacked);
        }
        if relevance_bps > QUALITY_AXIS_BPS_MAX
            || sufficiency_bps > QUALITY_AXIS_BPS_MAX
            || isolation_bps > QUALITY_AXIS_BPS_MAX
            || economy_bps > QUALITY_AXIS_BPS_MAX
            || provenance_bps > QUALITY_AXIS_BPS_MAX
        {
            return Err(DietError::QualityAxisOutOfRange);
        }
        Ok(Self {
            key,
            relevance_bps,
            sufficiency_bps,
            isolation_bps,
            economy_bps,
            provenance_bps,
            evidence_hash_32,
        })
    }

    /// Whether the signal is evidence-backed and every axis is within range — a
    /// cheap re-check for a replay-constructed value (fields are public for
    /// schema fidelity).
    pub const fn is_well_formed(&self) -> bool {
        self.relevance_bps <= QUALITY_AXIS_BPS_MAX
            && self.sufficiency_bps <= QUALITY_AXIS_BPS_MAX
            && self.isolation_bps <= QUALITY_AXIS_BPS_MAX
            && self.economy_bps <= QUALITY_AXIS_BPS_MAX
            && self.provenance_bps <= QUALITY_AXIS_BPS_MAX
            && !is_zero_32(&self.evidence_hash_32)
    }
}

/// A harness-quality signal (§4.5 `HarnessQualitySignal`).
///
/// Binds four trace hashes for one atom and flags whether the harness changed
/// silently. Schema-only.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub struct HarnessQualitySignal {
    /// The source atom the signal scores.
    pub key: AtomDietKey,
    /// `sha256` of the harness component configuration observed.
    pub component_hash_32: [u8; 32],
    /// `sha256` of the decision trajectory observed.
    pub trajectory_hash_32: [u8; 32],
    /// `sha256` of the decision the harness *predicted* it would take.
    pub decision_prediction_hash_32: [u8; 32],
    /// `sha256` of the outcome actually *observed*.
    pub observed_outcome_hash_32: [u8; 32],
    /// `true` when the predicted decision and the observed outcome diverge — a
    /// silent harness drift the gate must surface.
    pub silent_change_detected: bool,
}

impl HarnessQualitySignal {
    /// Build a harness-quality signal from its trace hashes, deriving
    /// `silent_change_detected` as `decision_prediction_hash_32 !=
    /// observed_outcome_hash_32`.
    ///
    /// Rejects an all-zero `component_hash_32` or `trajectory_hash_32` (an
    /// unbacked harness signal, [`DietError::QualitySignalUnbacked`]).
    pub fn from_trace(
        key: AtomDietKey,
        component_hash_32: [u8; 32],
        trajectory_hash_32: [u8; 32],
        decision_prediction_hash_32: [u8; 32],
        observed_outcome_hash_32: [u8; 32],
    ) -> DietResult<Self> {
        if is_zero_32(&component_hash_32) || is_zero_32(&trajectory_hash_32) {
            return Err(DietError::QualitySignalUnbacked);
        }
        Ok(Self {
            key,
            component_hash_32,
            trajectory_hash_32,
            decision_prediction_hash_32,
            observed_outcome_hash_32,
            silent_change_detected: decision_prediction_hash_32 != observed_outcome_hash_32,
        })
    }
}

/// The kind of self-evolution candidate (§4.5 `SelfEvolutionCandidateKind`).
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
#[repr(u8)]
pub enum SelfEvolutionCandidateKind {
    /// A change to the agent's memory policy.
    MemoryPolicy = 1,
    /// A change to the context-assembly policy.
    ContextPolicy = 2,
    /// A change to the skill-selection policy.
    SkillPolicy = 3,
    /// A change to the execution harness.
    Harness = 4,
    /// A whole alternative agent variant.
    AgentVariant = 5,
}

/// A self-evolution candidate manifest (§4.5 `SelfEvolutionCandidateManifest`).
///
/// Schema-only evidence describing a *possible* future experiment. In Stage E
/// every promotion guard is `true` and `authority_expansion_denied` is `true`:
/// the candidate can only ever be evaluated later in a sandbox, never promoted
/// or applied from here.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub struct SelfEvolutionCandidateManifest {
    /// The source atom the candidate derives from.
    pub key: AtomDietKey,
    /// What kind of change is proposed.
    pub kind: SelfEvolutionCandidateKind,
    /// `sha256` anchor of the expected-effect description.
    pub expected_effect_hash_32: [u8; 32],
    /// `sha256` anchor of the supporting evidence bundle.
    pub evidence_bundle_hash_32: [u8; 32],
    /// The candidate must be evaluated in a sandbox before any use.
    pub sandbox_required: bool,
    /// The candidate must pass a held-out evaluation.
    pub heldout_eval_required: bool,
    /// The candidate must pass a safety-regression check.
    pub safety_regression_required: bool,
    /// A cost report is required before any decision.
    pub cost_report_required: bool,
    /// A rollback receipt is required before any application.
    pub rollback_receipt_required: bool,
    /// Human approval is required before any promotion.
    pub human_approval_required: bool,
    /// Authority expansion is denied — the candidate may never widen its own
    /// authority. Always `true` in Stage E.
    pub authority_expansion_denied: bool,
}

impl SelfEvolutionCandidateManifest {
    /// Mint a Stage E self-evolution candidate: schema-only and
    /// promotion-locked. Every promotion guard is forced `true` and
    /// `authority_expansion_denied` is `true`, regardless of caller intent.
    ///
    /// Rejects an all-zero `evidence_bundle_hash_32` (an unbacked candidate,
    /// [`DietError::QualitySignalUnbacked`]).
    pub fn stage_e_candidate(
        key: AtomDietKey,
        kind: SelfEvolutionCandidateKind,
        expected_effect_hash_32: [u8; 32],
        evidence_bundle_hash_32: [u8; 32],
    ) -> DietResult<Self> {
        if is_zero_32(&evidence_bundle_hash_32) {
            return Err(DietError::QualitySignalUnbacked);
        }
        Ok(Self {
            key,
            kind,
            expected_effect_hash_32,
            evidence_bundle_hash_32,
            sandbox_required: true,
            heldout_eval_required: true,
            safety_regression_required: true,
            cost_report_required: true,
            rollback_receipt_required: true,
            human_approval_required: true,
            authority_expansion_denied: true,
        })
    }

    /// Whether every promotion guard is set and authority expansion is denied —
    /// the only shape a Stage E candidate may take.
    pub const fn is_promotion_blocked(&self) -> bool {
        self.sandbox_required
            && self.heldout_eval_required
            && self.safety_regression_required
            && self.cost_report_required
            && self.rollback_receipt_required
            && self.human_approval_required
            && self.authority_expansion_denied
    }

    /// Fail-closed validation for a replay-constructed manifest: rejects an
    /// unbacked candidate ([`DietError::QualitySignalUnbacked`]) and any
    /// candidate that left a promotion guard off or allowed authority expansion
    /// ([`DietError::SelfEvolutionAuthorityWidened`]).
    pub fn validate(&self) -> DietResult<()> {
        if is_zero_32(&self.evidence_bundle_hash_32) {
            return Err(DietError::QualitySignalUnbacked);
        }
        if !self.is_promotion_blocked() {
            return Err(DietError::SelfEvolutionAuthorityWidened);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::diet_kind::DietSourceStage;

    fn key() -> AtomDietKey {
        AtomDietKey::new(DietSourceStage::Phase0, 400)
    }

    // ---- ContextQualitySignal ----
    #[test]
    fn context_signal_accepts_evidence_backed_in_range() -> DietResult<()> {
        let s = ContextQualitySignal::new(key(), 9000, 8000, 7000, 6000, 5000, [7u8; 32])?;
        assert!(s.is_well_formed());
        assert_eq!(s.relevance_bps, 9000);
        Ok(())
    }

    #[test]
    fn context_signal_rejects_zero_evidence() {
        // falsifiable canary: an all-zero evidence anchor is "prompt vibes".
        assert_eq!(
            ContextQualitySignal::new(key(), 1, 1, 1, 1, 1, [0u8; 32]),
            Err(DietError::QualitySignalUnbacked)
        );
    }

    #[test]
    fn context_signal_rejects_out_of_range_axis() {
        // falsifiable canary: 10_001 bps > 100%.
        assert_eq!(
            ContextQualitySignal::new(key(), QUALITY_AXIS_BPS_MAX + 1, 0, 0, 0, 0, [7u8; 32]),
            Err(DietError::QualityAxisOutOfRange)
        );
    }

    #[test]
    fn context_signal_accepts_exact_ceiling() -> DietResult<()> {
        // boundary: exactly 10_000 bps is in range.
        let s = ContextQualitySignal::new(
            key(),
            QUALITY_AXIS_BPS_MAX,
            QUALITY_AXIS_BPS_MAX,
            QUALITY_AXIS_BPS_MAX,
            QUALITY_AXIS_BPS_MAX,
            QUALITY_AXIS_BPS_MAX,
            [7u8; 32],
        )?;
        assert!(s.is_well_formed());
        Ok(())
    }

    // ---- HarnessQualitySignal ----
    #[test]
    fn harness_signal_flags_drift_when_prediction_differs() -> DietResult<()> {
        let s =
            HarnessQualitySignal::from_trace(key(), [1u8; 32], [2u8; 32], [3u8; 32], [4u8; 32])?;
        assert!(s.silent_change_detected);
        Ok(())
    }

    #[test]
    fn harness_signal_no_drift_when_prediction_matches() -> DietResult<()> {
        let s =
            HarnessQualitySignal::from_trace(key(), [1u8; 32], [2u8; 32], [9u8; 32], [9u8; 32])?;
        assert!(!s.silent_change_detected);
        Ok(())
    }

    #[test]
    fn harness_signal_rejects_unbacked() {
        // falsifiable canary: zero component hash ⇒ unbacked.
        assert_eq!(
            HarnessQualitySignal::from_trace(key(), [0u8; 32], [2u8; 32], [3u8; 32], [4u8; 32]),
            Err(DietError::QualitySignalUnbacked)
        );
    }

    // ---- SelfEvolutionCandidateManifest ----
    #[test]
    fn stage_e_candidate_is_promotion_blocked() -> DietResult<()> {
        let m = SelfEvolutionCandidateManifest::stage_e_candidate(
            key(),
            SelfEvolutionCandidateKind::Harness,
            [5u8; 32],
            [6u8; 32],
        )?;
        assert!(m.is_promotion_blocked());
        assert!(m.authority_expansion_denied);
        assert!(m.sandbox_required && m.human_approval_required);
        m.validate()?;
        Ok(())
    }

    #[test]
    fn stage_e_candidate_rejects_unbacked() {
        assert_eq!(
            SelfEvolutionCandidateManifest::stage_e_candidate(
                key(),
                SelfEvolutionCandidateKind::MemoryPolicy,
                [5u8; 32],
                [0u8; 32],
            ),
            Err(DietError::QualitySignalUnbacked)
        );
    }

    #[test]
    fn validate_rejects_authority_widened_candidate() {
        // falsifiable canary: a hand-built manifest that leaves authority open
        // (the safe constructor can never produce this) must be rejected.
        let widened = SelfEvolutionCandidateManifest {
            key: key(),
            kind: SelfEvolutionCandidateKind::AgentVariant,
            expected_effect_hash_32: [5u8; 32],
            evidence_bundle_hash_32: [6u8; 32],
            sandbox_required: true,
            heldout_eval_required: true,
            safety_regression_required: true,
            cost_report_required: true,
            rollback_receipt_required: true,
            human_approval_required: true,
            authority_expansion_denied: false,
        };
        assert_eq!(
            widened.validate(),
            Err(DietError::SelfEvolutionAuthorityWidened)
        );
        assert!(!widened.is_promotion_blocked());
    }

    #[test]
    fn validate_rejects_guard_left_off() {
        let no_sandbox = SelfEvolutionCandidateManifest {
            key: key(),
            kind: SelfEvolutionCandidateKind::ContextPolicy,
            expected_effect_hash_32: [5u8; 32],
            evidence_bundle_hash_32: [6u8; 32],
            sandbox_required: false,
            heldout_eval_required: true,
            safety_regression_required: true,
            cost_report_required: true,
            rollback_receipt_required: true,
            human_approval_required: true,
            authority_expansion_denied: true,
        };
        assert_eq!(
            no_sandbox.validate(),
            Err(DietError::SelfEvolutionAuthorityWidened)
        );
    }

    #[test]
    fn kind_repr_is_stable() {
        // repr(u8) discriminants are a cross-language schema lock.
        assert_eq!(SelfEvolutionCandidateKind::MemoryPolicy as u8, 1);
        assert_eq!(SelfEvolutionCandidateKind::ContextPolicy as u8, 2);
        assert_eq!(SelfEvolutionCandidateKind::SkillPolicy as u8, 3);
        assert_eq!(SelfEvolutionCandidateKind::Harness as u8, 4);
        assert_eq!(SelfEvolutionCandidateKind::AgentVariant as u8, 5);
    }
}
