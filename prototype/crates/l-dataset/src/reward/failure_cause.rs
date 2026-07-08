//! Failure-cause governance + didactic signals (`FailureCause`,
//! `OperationalMemoryClass`, `DidacticSignalClass`, `DidacticConceptMap`,
//! `DidacticSignal`).
//!
//! Research basis: reward-hacking / RLVR verifier-gaming warnings;
//! ReCode / StepCodeReasoner execution-and-process hard gates.
//!
//! # Design
//!
//! Infra OOM / timeout / rate-limit **mask** the trajectory — the failure is not
//! the model's, so it can never earn reward. Tool-loop overflow, semantic loop,
//! verification skip, claim contradiction, scope sprawl, topic drift, and cyclic
//! compression **penalize or quarantine** the affected step. A privacy failure
//! **rejects export** outright. Every eligible failure also emits a
//! [`DidacticConceptMap`] + [`DidacticSignal`] so the scheduler can schedule
//! deliberate practice instead of random replay. A low-confidence concept label becomes a
//! metacognitive-uncertainty *abstain* (review, not reward).
use crate::diet_kind::AtomDietKey;

use super::super::murphy::schema::FailureKind;

/// Below this confidence (basis points) a concept label abstains rather than
/// asserting — it becomes review/uncertainty signal, never reward.
pub const CONFIDENCE_ABSTAIN_BPS: u16 = 5000;

/// The governed cause of a failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
#[repr(u8)]
pub enum FailureCause {
    /// The model produced the failure (compile/test/clippy/move/security/…).
    Model = 1,
    /// Infrastructure masked the run (OOM / rate-limit / host) — not the model.
    Infra = 2,
    /// A tool / reasoning loop (tool-loop overflow, semantic loop, cyclic compression).
    ToolLoop = 3,
    /// The run timed out — masked, not creditable.
    Timeout = 4,
    /// A privacy / secret-residue failure — rejects export.
    Privacy = 5,
    /// A human reviewer rejected the change.
    HumanRejected = 6,
}

impl FailureCause {
    /// Numeric discriminant.
    pub const fn as_u8(self) -> u8 {
        self as u8
    }

    /// Whether this cause masks the trajectory (infra/timeout/loop) so it can
    /// never earn positive reward.
    pub const fn masks_trajectory(self) -> bool {
        matches!(self, Self::Infra | Self::Timeout | Self::ToolLoop)
    }
}

/// The operational-memory class a signal belongs to.
/// Kept strictly separate from the didactic signal class: operational class is
/// retention/lifecycle, never a reward proxy.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
#[repr(u8)]
pub enum OperationalMemoryClass {
    /// Discard.
    Drop = 1,
    /// Ephemeral (single turn).
    Ephemeral = 2,
    /// Session-scoped.
    Session = 3,
    /// Project-scoped.
    Project = 4,
    /// User-profile-scoped.
    UserProfile = 5,
    /// Evidence retention (audit).
    Evidence = 6,
    /// A training candidate (only when reward is allowed).
    TrainingCandidate = 7,
}

impl OperationalMemoryClass {
    /// Numeric discriminant.
    pub const fn as_u8(self) -> u8 {
        self as u8
    }
}

/// The teachable class of a didactic signal.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
#[repr(u8)]
pub enum DidacticSignalClass {
    /// A concept to learn.
    Concept = 1,
    /// A prerequisite that was missing.
    Prerequisite = 2,
    /// A misconception to correct.
    Misconception = 3,
    /// A procedure to follow.
    Procedure = 4,
    /// A failed attempt (kept as negative example).
    FailedAttempt = 5,
    /// A repair (failure → fix).
    Repair = 6,
    /// A retrieval-practice probe.
    RetrievalProbe = 7,
    /// A transfer-evaluation probe.
    TransferProbe = 8,
    /// Evidence of mastery.
    MasteryEvidence = 9,
    /// Metacognitive uncertainty (low-confidence abstain).
    MetacognitiveUncertainty = 10,
    /// Low learning value (drop / de-prioritize).
    LowLearningValue = 11,
}

impl DidacticSignalClass {
    /// Numeric discriminant.
    pub const fn as_u8(self) -> u8 {
        self as u8
    }
}

/// A concept map for one failure/success.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub struct DidacticConceptMap {
    /// The source atom.
    pub key: AtomDietKey,
    /// `sha256` of the concept label.
    pub concept_hash_32: [u8; 32],
    /// `sha256` of the prerequisite label.
    pub prerequisite_hash_32: [u8; 32],
    /// The governed failure cause this concept derives from.
    pub failure_cause: FailureCause,
    /// The gate axis (which gate surfaced the concept).
    pub gate_axis_u16: u16,
    /// The domain axis (which domain the concept lives in).
    pub domain_axis_u16: u16,
    /// `sha256` of the transfer-evaluation probe.
    pub transfer_probe_hash_32: [u8; 32],
}

/// A didactic signal for the training scheduler.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub struct DidacticSignal {
    /// The source atom.
    pub key: AtomDietKey,
    /// Retention class (never a reward proxy).
    pub operational_class: OperationalMemoryClass,
    /// The teachable class.
    pub signal_class: DidacticSignalClass,
    /// `sha256` of the concept label.
    pub concept_hash_32: [u8; 32],
    /// `sha256` of the prerequisite label.
    pub prerequisite_hash_32: [u8; 32],
    /// `sha256` of the backing evidence.
    pub evidence_hash_32: [u8; 32],
    /// The source atom number.
    pub source_atom_u16: u16,
    /// The gate axis.
    pub gate_axis_u16: u16,
    /// Difficulty, in basis points.
    pub difficulty_bps_u16: u16,
    /// Confidence in the label, in basis points.
    pub confidence_bps_u16: u16,
    /// Mastery delta, in milli-units.
    pub mastery_delta_milli_i16: i16,
    /// Spaced-repetition due epoch.
    pub due_for_recall_epoch_u64: u64,
    /// `sha256` of the transfer-evaluation probe.
    pub transfer_probe_hash_32: [u8; 32],
    /// Whether reward is allowed (must agree with S1 eligibility downstream).
    pub reward_allowed: bool,
}

/// A per-step governance verdict.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub struct StepGovernance {
    /// The governed cause.
    pub cause: FailureCause,
    /// Whether reward is blocked (masked / quarantined / privacy / human-rejected).
    pub reward_blocked: bool,
    /// Whether the step is quarantined (loop / skip / contradiction / sprawl / drift / compression).
    pub quarantined: bool,
}

/// A trajectory-health condition that penalizes or quarantines the affected
/// step. This is the failure-cause governance taxonomy (distinct from the
/// trajectory parser registry, which is owned by a separate module).
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
#[repr(u8)]
pub enum StepQuarantineKind {
    /// No trajectory pathology.
    None = 0,
    /// Tool-call loop overflow.
    ToolLoopOverflow = 1,
    /// Semantic (reasoning) loop.
    SemanticLoop = 2,
    /// A verification step was skipped.
    VerificationSkip = 3,
    /// A claim contradicted earlier evidence.
    ClaimContradiction = 4,
    /// The diff sprawled past the atom scope.
    ScopeSprawl = 5,
    /// The trajectory drifted off-topic.
    TopicDrift = 6,
    /// Cyclic compression (repeated re-summarization losing evidence).
    CyclicCompression = 7,
    /// Infrastructure out-of-memory.
    InfraOom = 8,
    /// The run timed out.
    Timeout = 9,
    /// A provider rate-limit masked the run.
    RateLimit = 10,
}

impl StepQuarantineKind {
    /// Numeric discriminant.
    pub const fn as_u8(self) -> u8 {
        self as u8
    }
}

/// Map a raw failure to its base cause. Trajectory pathologies are layered
/// on top by [`govern_step`].
pub const fn cause_of(failure: FailureKind) -> FailureCause {
    match failure {
        FailureKind::InfraMasked => FailureCause::Infra,
        FailureKind::Privacy => FailureCause::Privacy,
        FailureKind::HumanRejected => FailureCause::HumanRejected,
        _ => FailureCause::Model,
    }
}

/// Govern one step: combine its failure, a trajectory pathology, and the privacy
/// verdict into a cause + reward-block + quarantine decision. Fail-closed: any
/// masking / quarantine / privacy failure blocks reward.
pub const fn govern_step(
    failure: FailureKind,
    quarantine: StepQuarantineKind,
    privacy_pass: bool,
) -> StepGovernance {
    if !privacy_pass {
        return StepGovernance {
            cause: FailureCause::Privacy,
            reward_blocked: true,
            quarantined: false,
        };
    }
    match quarantine {
        StepQuarantineKind::Timeout => StepGovernance {
            cause: FailureCause::Timeout,
            reward_blocked: true,
            quarantined: false,
        },
        StepQuarantineKind::InfraOom | StepQuarantineKind::RateLimit => StepGovernance {
            cause: FailureCause::Infra,
            reward_blocked: true,
            quarantined: false,
        },
        StepQuarantineKind::ToolLoopOverflow
        | StepQuarantineKind::SemanticLoop
        | StepQuarantineKind::CyclicCompression => StepGovernance {
            cause: FailureCause::ToolLoop,
            reward_blocked: true,
            quarantined: true,
        },
        StepQuarantineKind::VerificationSkip
        | StepQuarantineKind::ClaimContradiction
        | StepQuarantineKind::ScopeSprawl
        | StepQuarantineKind::TopicDrift => StepGovernance {
            cause: cause_of(failure),
            reward_blocked: true,
            quarantined: true,
        },
        StepQuarantineKind::None => {
            let cause = cause_of(failure);
            StepGovernance {
                cause,
                reward_blocked: cause.masks_trajectory()
                    || matches!(cause, FailureCause::Privacy | FailureCause::HumanRejected),
                quarantined: false,
            }
        }
    }
}

/// Build a concept map for a governed failure.
pub fn concept_map(
    key: AtomDietKey,
    concept: &str,
    prerequisite: &str,
    cause: FailureCause,
    gate_axis_u16: u16,
    domain_axis_u16: u16,
    transfer_probe: &str,
) -> DidacticConceptMap {
    DidacticConceptMap {
        key,
        concept_hash_32: crate::sha256(concept.as_bytes()),
        prerequisite_hash_32: crate::sha256(prerequisite.as_bytes()),
        failure_cause: cause,
        gate_axis_u16,
        domain_axis_u16,
        transfer_probe_hash_32: crate::sha256(transfer_probe.as_bytes()),
    }
}

/// Inputs for emitting a [`DidacticSignal`] (bundled to keep the emitter's
/// argument count small and the call site self-documenting).
#[derive(Clone, Copy, Debug)]
pub struct DidacticInput<'a> {
    /// The source atom.
    pub key: AtomDietKey,
    /// The intended teachable class (overridden to uncertainty on abstain).
    pub signal_class: DidacticSignalClass,
    /// Concept label.
    pub concept: &'a str,
    /// Prerequisite label.
    pub prerequisite: &'a str,
    /// Backing evidence text.
    pub evidence: &'a str,
    /// Transfer-evaluation probe text.
    pub transfer_probe: &'a str,
    /// Source atom number.
    pub source_atom_u16: u16,
    /// Gate axis.
    pub gate_axis_u16: u16,
    /// Difficulty (bps).
    pub difficulty_bps_u16: u16,
    /// Confidence (bps).
    pub confidence_bps_u16: u16,
    /// Mastery delta (milli).
    pub mastery_delta_milli_i16: i16,
    /// Spaced-repetition due epoch.
    pub due_for_recall_epoch_u64: u64,
}

/// Emit a didactic signal. `reward_allowed` mirrors S1 eligibility AND requires
/// confidence at or above [`CONFIDENCE_ABSTAIN_BPS`]; a low-confidence label is
/// rewritten to [`DidacticSignalClass::MetacognitiveUncertainty`] and lands in
/// [`OperationalMemoryClass::Evidence`], never `TrainingCandidate`.
pub fn emit_signal(input: &DidacticInput, s1_eligible: bool) -> DidacticSignal {
    let abstain = input.confidence_bps_u16 < CONFIDENCE_ABSTAIN_BPS;
    let reward_allowed = s1_eligible && !abstain;
    let signal_class = if abstain {
        DidacticSignalClass::MetacognitiveUncertainty
    } else {
        input.signal_class
    };
    let operational_class = if reward_allowed {
        OperationalMemoryClass::TrainingCandidate
    } else {
        OperationalMemoryClass::Evidence
    };
    DidacticSignal {
        key: input.key,
        operational_class,
        signal_class,
        concept_hash_32: crate::sha256(input.concept.as_bytes()),
        prerequisite_hash_32: crate::sha256(input.prerequisite.as_bytes()),
        evidence_hash_32: crate::sha256(input.evidence.as_bytes()),
        source_atom_u16: input.source_atom_u16,
        gate_axis_u16: input.gate_axis_u16,
        difficulty_bps_u16: input.difficulty_bps_u16,
        confidence_bps_u16: input.confidence_bps_u16,
        mastery_delta_milli_i16: input.mastery_delta_milli_i16,
        due_for_recall_epoch_u64: input.due_for_recall_epoch_u64,
        transfer_probe_hash_32: crate::sha256(input.transfer_probe.as_bytes()),
        reward_allowed,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::diet_kind::DietSourceStage;

    fn key() -> AtomDietKey {
        AtomDietKey::new(DietSourceStage::Phase0, 388)
    }

    fn input(class: DidacticSignalClass, confidence: u16) -> DidacticInput<'static> {
        DidacticInput {
            key: key(),
            signal_class: class,
            concept: "borrow checker lifetimes",
            prerequisite: "ownership move semantics",
            evidence: "cargo build exit 0",
            transfer_probe: "explain why &mut aliasing fails",
            source_atom_u16: 388,
            gate_axis_u16: 1,
            difficulty_bps_u16: 6000,
            confidence_bps_u16: confidence,
            mastery_delta_milli_i16: 120,
            due_for_recall_epoch_u64: 42,
        }
    }

    #[test]
    fn compile_failure_is_model_fault() {
        assert_eq!(cause_of(FailureKind::Compile), FailureCause::Model);
    }

    #[test]
    fn test_failure_is_model_fault() {
        assert_eq!(cause_of(FailureKind::Test), FailureCause::Model);
    }

    #[test]
    fn infra_masked_is_infra_and_blocks_reward() {
        let g = govern_step(FailureKind::InfraMasked, StepQuarantineKind::InfraOom, true);
        assert_eq!(g.cause, FailureCause::Infra);
        assert!(g.reward_blocked);
        assert!(g.cause.masks_trajectory());
    }

    #[test]
    fn timeout_is_masked() {
        let g = govern_step(FailureKind::Test, StepQuarantineKind::Timeout, true);
        assert_eq!(g.cause, FailureCause::Timeout);
        assert!(g.reward_blocked);
    }

    #[test]
    fn privacy_failure_rejects_export() {
        let g = govern_step(FailureKind::Test, StepQuarantineKind::None, false);
        assert_eq!(g.cause, FailureCause::Privacy);
        assert!(g.reward_blocked);
    }

    #[test]
    fn semantic_loop_is_toolloop_quarantine() {
        let g = govern_step(FailureKind::Test, StepQuarantineKind::SemanticLoop, true);
        assert_eq!(g.cause, FailureCause::ToolLoop);
        assert!(g.quarantined);
        assert!(g.reward_blocked);
    }

    #[test]
    fn verification_skip_is_quarantined() {
        let g = govern_step(
            FailureKind::Test,
            StepQuarantineKind::VerificationSkip,
            true,
        );
        assert!(g.quarantined);
        assert!(g.reward_blocked);
    }

    #[test]
    fn cyclic_compression_is_quarantined() {
        let g = govern_step(
            FailureKind::Test,
            StepQuarantineKind::CyclicCompression,
            true,
        );
        assert_eq!(g.cause, FailureCause::ToolLoop);
        assert!(g.quarantined);
    }

    #[test]
    fn concept_tag_and_prerequisite_tag_are_hashed() {
        let cm = concept_map(
            key(),
            "concept-x",
            "prereq-y",
            FailureCause::Model,
            2,
            3,
            "probe-z",
        );
        assert_eq!(cm.concept_hash_32, crate::sha256(b"concept-x"));
        assert_eq!(cm.prerequisite_hash_32, crate::sha256(b"prereq-y"));
        assert_eq!(cm.gate_axis_u16, 2);
        assert_eq!(cm.domain_axis_u16, 3);
    }

    #[test]
    fn transfer_probe_is_hashed() {
        let cm = concept_map(
            key(),
            "c",
            "p",
            FailureCause::Model,
            0,
            0,
            "transfer-probe-abc",
        );
        assert_eq!(
            cm.transfer_probe_hash_32,
            crate::sha256(b"transfer-probe-abc")
        );
    }

    #[test]
    fn misconception_signal_survives_high_confidence() {
        let s = emit_signal(&input(DidacticSignalClass::Misconception, 9000), true);
        assert_eq!(s.signal_class, DidacticSignalClass::Misconception);
        assert!(s.reward_allowed);
        assert_eq!(
            s.operational_class,
            OperationalMemoryClass::TrainingCandidate
        );
    }

    #[test]
    fn low_confidence_abstains_no_reward() {
        let s = emit_signal(&input(DidacticSignalClass::Concept, 3000), true);
        assert_eq!(
            s.signal_class,
            DidacticSignalClass::MetacognitiveUncertainty
        );
        assert!(!s.reward_allowed);
        assert_eq!(s.operational_class, OperationalMemoryClass::Evidence);
    }

    #[test]
    fn s1_ineligible_blocks_reward_even_high_confidence() {
        let s = emit_signal(&input(DidacticSignalClass::MasteryEvidence, 9500), false);
        assert!(!s.reward_allowed);
    }
}
