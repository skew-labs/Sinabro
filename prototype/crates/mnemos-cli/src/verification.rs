//! `verification` — the Typed-Write-Admission TRUST-TIER ladder (P1-3 FULL; the
//! P-HALL anchor; plan `ops/evidence/stage_g/agent_loop/P1_ORCHESTRATOR_PLAN.md`).
//!
//! The hallucination loop (P-HALL) poisons itself when the autonomous loop writes
//! a pattern to permanent memory on the MODEL's own self-judgment of "success".
//! The physical fix: the MODEL never declares success — a typed RECEIPT does, and
//! that receipt is produced by a class-appropriate ORACLE (a deterministic
//! external check), NOT the model's text. This module is that deterministic ladder:
//!
//!   sub-task `kind` --classify--> VerificationClass --(class-typed ORACLE evidence)--> verdict
//!
//! ## The five trust tiers (DGM-H general; compiler = ONE class, NOT universal)
//!
//! Each class has its OWN oracle; none is the model's self-judgment:
//! * `Code`           — a compiler / test / formal exit-code bit (the real
//!   `sui move build` in the E6 network-DENIED sandbox; P1-3-full(a)).
//! * `PersonalOwner`  — PROVENANCE: owner-authored AND owner-confirmed (a model may
//!   NOT promote its own inference to an owner fact — structural, not advisory).
//! * `ExternalFact`   — `>= N` INDEPENDENT source-linked corroborations (a lone /
//!   weak source NEVER confirms; [`CORROBORATION_MIN`] is the floor).
//! * `ModelInference` — the LOWEST trust: advisory until DGM-H PERFORMANCE-TRACKING
//!   accumulates verified-good outcomes (retrieve→act→verified-good ⇒ reinforce;
//!   →failure ⇒ demote). The universal non-compiler oracle; breaks the RAG↔HALL
//!   compound. This is the TOTAL fail-safe: an UNKNOWN expert kind lands here.
//! * `CrossMemory`    — write-time CONTRADICTION-DETECTION vs the held LTM; a
//!   conflicting pattern is quarantined (Unverified), never written.
//!
//! ## drift-0 + token-min (META-LAW)
//!
//! This ENTIRE ladder is DETERMINISTIC RUST with 0 IO and 0 external LLM tokens:
//! `classify` is a TOTAL pure function (unknown kind ⇒ `ModelInference`, the
//! lowest-trust fail-safe) and `verify`'s verdict is a deterministic function of
//! `(class, typed evidence)` — the MODEL's answer TEXT is NEVER an input, so a model
//! cannot self-certify a Write. Evidence is TYPED: a model cannot fabricate a
//! `CodeOracle(true)` or an `OwnerConfirmed` (those come from the deterministic
//! oracle / a typed owner gate, not the model's words). Only a `Verified` receipt
//! ADMITS a permanent Write (P1-4 gates the Walrus Write on `admits_write`);
//! `Unverified` (failed / quarantined / advisory) and `NotApplicable` (honest
//! oracle-absence) never auto-admit. custody/funds stay HARD-LOCKED: pure, no IO.

use crate::provider::executor_route::ExecutorKind;

/// The minimum number of INDEPENDENT corroborations an [`VerificationClass::ExternalFact`]
/// needs before it can be `Verified` (a single source never confirms a fact). The
/// caller may demand MORE (its own `threshold`), never fewer — the verdict clamps up.
pub const CORROBORATION_MIN: u32 = 2;

/// The verification class a sub-task falls into — which kind of oracle can judge it.
/// OPEN to extension; these five are the v1 trust tiers.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum VerificationClass {
    /// Code / skill output a deterministic compiler / test / formal oracle judges
    /// (exit-code truth). The compiler rung.
    Code,
    /// A personal / owner memory: PROVENANCE is the oracle (owner-authored +
    /// owner-confirmed = highest trust; a model may not author an owner fact).
    PersonalOwner,
    /// An external fact: independent CORROBORATION is the oracle (`>= N` sources).
    ExternalFact,
    /// Model inference: the LOWEST trust — advisory until DGM-H PERFORMANCE-TRACKING
    /// confirms. The TOTAL fail-safe class for any unknown / un-mapped expert kind.
    ModelInference,
    /// A cross-memory write: the oracle is write-time CONTRADICTION-DETECTION vs the
    /// held LTM (a conflict is quarantined, never written).
    CrossMemory,
}

/// The typed verdict for a sub-task (the model never produces this).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum VerificationVerdict {
    /// A class-appropriate oracle confirmed the output (the only verdict that
    /// admits a Write).
    Verified,
    /// The oracle ran and rejected (failed compile / under-corroborated / not
    /// owner-confirmed / un-reinforced / quarantined contradiction). NOT admitted.
    Unverified,
    /// No oracle evidence applied (honest absence). NOT admitted.
    NotApplicable,
}

/// Owner provenance for a [`VerificationClass::PersonalOwner`] pattern. Supplied by a
/// TYPED owner gate, never by the model — a model has no constructor that yields
/// `OwnerConfirmed`, so it cannot promote its own inference to an owner fact.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OwnerProvenance {
    /// Owner-authored AND owner-confirmed via a human gate (highest trust).
    OwnerConfirmed,
    /// Owner-authored but NOT yet confirmed (pending the human gate).
    OwnerAuthoredUnconfirmed,
    /// Not owner-authored (a model-authored claim about an owner fact).
    NotOwner,
}

/// DGM-H PERFORMANCE-TRACKING score for a [`VerificationClass::ModelInference`] pattern:
/// how many times a class-appropriate downstream oracle later found this pattern good
/// (`reinforced`) vs failed (`demoted`). A pattern is "confirmed" only after it has been
/// independently verified-good AND never demoted — the model can never confirm itself.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub struct PerfScore {
    /// Verified-good downstream outcomes (retrieve→act→verified-good).
    pub reinforced: u32,
    /// Failed downstream outcomes (retrieve→act→failure).
    pub demoted: u32,
}

impl PerfScore {
    /// The number of verified-good reinforcements required before a model-inference
    /// pattern stops being advisory (≥1: it must be externally verified at least once;
    /// a larger floor = more paranoid, owner-tunable at P1-5).
    pub const CONFIRM_FLOOR: u32 = 1;

    /// Reinforce (a downstream oracle found this pattern good). Saturating.
    #[must_use]
    pub const fn reinforce(self) -> Self {
        Self {
            reinforced: self.reinforced.saturating_add(1),
            demoted: self.demoted,
        }
    }

    /// Demote (a downstream oracle found this pattern bad). Saturating.
    #[must_use]
    pub const fn demote(self) -> Self {
        Self {
            reinforced: self.reinforced,
            demoted: self.demoted.saturating_add(1),
        }
    }

    /// Confirmed iff reinforced at/above the floor AND never demoted (any single
    /// failure un-confirms — fail-closed, the paranoid posture).
    #[must_use]
    pub const fn is_confirmed(&self) -> bool {
        self.reinforced >= Self::CONFIRM_FLOOR && self.demoted == 0
    }
}

/// The class-typed ORACLE evidence — produced by a deterministic external check or a
/// typed gate, NEVER by the model's answer text. Each variant feeds exactly one class;
/// a variant that does not match the sub-task's class is fail-closed (`Unverified`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum VerificationEvidence {
    /// `Code`: the compiler / test oracle bit — `Some(true)` passed, `Some(false)`
    /// failed, `None` the oracle did not run (honest absence).
    CodeOracle(Option<bool>),
    /// `PersonalOwner`: the owner provenance of the pattern.
    OwnerProvenance(OwnerProvenance),
    /// `ExternalFact`: how many INDEPENDENT sources corroborate it, and the caller's
    /// required `threshold` (clamped up to [`CORROBORATION_MIN`]).
    Corroboration {
        /// Count of independent source-linked corroborations.
        independent_count: u32,
        /// The caller's required threshold (the verdict uses `max(threshold, MIN)`).
        threshold: u32,
    },
    /// `ModelInference`: the DGM-H performance-tracking score for this pattern.
    PerfTracking(PerfScore),
    /// `CrossMemory`: whether the pattern CONTRADICTS the held LTM (write-time).
    CrossMemory {
        /// `true` ⇒ the pattern conflicts with held memory ⇒ quarantined.
        contradicts_held_ltm: bool,
    },
    /// No oracle evidence supplied for this sub-task (honest absence ⇒ NotApplicable).
    Absent,
}

/// The typed verification receipt: the class, the oracle verdict, and a secret-zero
/// static reason. P1-4 gates the permanent Walrus Write on this.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerificationReceipt {
    /// The class the sub-task was verified under.
    pub class: VerificationClass,
    /// The oracle's verdict (NEVER the model's self-judgment).
    pub verdict: VerificationVerdict,
    /// A secret-zero static reason for the verdict.
    pub detail: String,
}

impl VerificationReceipt {
    /// Whether this receipt ADMITS a permanent Write (the P-HALL gate): ONLY a
    /// `Verified` verdict admits. `Unverified` (failed / quarantined / advisory) and
    /// `NotApplicable` (honest absence) do NOT — the autonomous loop never writes a
    /// model-self-certified "success".
    #[must_use]
    pub fn admits_write(&self) -> bool {
        matches!(self.verdict, VerificationVerdict::Verified)
    }
}

/// Map a sub-task's expert `kind` to its verification class — a TOTAL pure function
/// (drift-0; every kind resolves). The OPEN expert-set's well-known seeds map to their
/// tier; ANY unknown kind falls to `ModelInference`, the LOWEST-trust fail-safe (it is
/// never auto-verified — the paranoid default).
#[must_use]
pub fn classify(kind: &ExecutorKind) -> VerificationClass {
    let label = kind.label();
    if label == ExecutorKind::SUI_MOVE
        || label == ExecutorKind::SOLANA_ANCHOR
        || label == ExecutorKind::WEB3_FRONTEND
    {
        // implementation that COMPILES ⇒ a deterministic compiler/test oracle.
        VerificationClass::Code
    } else if label == ExecutorKind::PERSONAL_MEMORY {
        // an owner's personal memory ⇒ provenance + human gate.
        VerificationClass::PersonalOwner
    } else if label == ExecutorKind::EXTERNAL_FACT || label == ExecutorKind::RESEARCH {
        // a fact from the outside world ⇒ independent corroboration.
        VerificationClass::ExternalFact
    } else if label == ExecutorKind::CROSS_MEMORY {
        // a memory-vs-memory write ⇒ contradiction-detection vs held LTM.
        VerificationClass::CrossMemory
    } else {
        // audit (leads, not findings), nl_bridge, and ANY unknown expert ⇒ the
        // lowest-trust model-inference class (advisory until perf-tracking confirms).
        VerificationClass::ModelInference
    }
}

/// Produce the typed receipt for a sub-task from its `class` + the class-typed ORACLE
/// `evidence`. The verdict is a deterministic function of `(class, evidence)` — the
/// MODEL's answer TEXT is NEVER an input, so a model cannot self-certify a Write. An
/// evidence variant that does NOT match the class is fail-closed (`Unverified`); an
/// `Absent` evidence is the honest `NotApplicable`.
#[must_use]
pub fn verify(class: VerificationClass, evidence: &VerificationEvidence) -> VerificationReceipt {
    use VerificationClass as C;
    use VerificationEvidence as E;
    use VerificationVerdict::{NotApplicable, Unverified, Verified};
    let (verdict, detail): (VerificationVerdict, &str) = match (class, evidence) {
        // --- Code: the compiler / test oracle bit ---
        (C::Code, E::CodeOracle(Some(true))) => {
            (Verified, "code oracle passed (compiler/test exit ok)")
        }
        (C::Code, E::CodeOracle(Some(false))) => (
            Unverified,
            "code oracle failed (compiler/test exit nonzero)",
        ),
        (C::Code, E::CodeOracle(None)) => (NotApplicable, "code oracle not run (honest absence)"),
        // --- PersonalOwner: owner provenance ---
        (C::PersonalOwner, E::OwnerProvenance(OwnerProvenance::OwnerConfirmed)) => (
            Verified,
            "owner-authored + owner-confirmed (highest trust; model cannot author this)",
        ),
        (C::PersonalOwner, E::OwnerProvenance(OwnerProvenance::OwnerAuthoredUnconfirmed)) => (
            Unverified,
            "owner-authored but not yet owner-confirmed (pending the human gate)",
        ),
        (C::PersonalOwner, E::OwnerProvenance(OwnerProvenance::NotOwner)) => (
            Unverified,
            "not owner-authored (a model may not promote its inference to an owner fact)",
        ),
        // --- ExternalFact: independent corroboration (>= N, lone source never wins) ---
        (
            C::ExternalFact,
            E::Corroboration {
                independent_count,
                threshold,
            },
        ) => {
            let need = if *threshold > CORROBORATION_MIN {
                *threshold
            } else {
                CORROBORATION_MIN
            };
            if *independent_count >= need {
                (
                    Verified,
                    "external fact corroborated by >= N independent sources",
                )
            } else {
                (
                    Unverified,
                    "external fact under-corroborated (a lone/weak source never confirms)",
                )
            }
        }
        // --- ModelInference: DGM-H performance-tracking ---
        (C::ModelInference, E::PerfTracking(score)) => {
            if score.is_confirmed() {
                (
                    Verified,
                    "model inference confirmed by perf-tracking (reinforced, never demoted)",
                )
            } else {
                (
                    Unverified,
                    "model inference still advisory (perf-tracking has not confirmed it)",
                )
            }
        }
        // --- CrossMemory: write-time contradiction-detection ---
        (
            C::CrossMemory,
            E::CrossMemory {
                contradicts_held_ltm,
            },
        ) => {
            if *contradicts_held_ltm {
                (
                    Unverified,
                    "cross-memory contradiction: quarantined (conflicts with held LTM)",
                )
            } else {
                (Verified, "cross-memory consistent with the held LTM")
            }
        }
        // --- honest absence: no oracle evidence supplied for this class ---
        (_, E::Absent) => (
            NotApplicable,
            "no oracle evidence supplied (honest absence)",
        ),
        // --- paranoid fail-closed: the evidence variant does not match the class ---
        _ => (
            Unverified,
            "evidence/class mismatch (fail-closed; never admits a write)",
        ),
    };
    VerificationReceipt {
        class,
        verdict,
        detail: detail.to_string(),
    }
}

// ===========================================================================
// W4 Slice 3 — the P-HALL formalisms: two-derivation verify + held-out canary
// ===========================================================================

/// The SOURCE-INDEPENDENCE two-derivation gate (P-HALL; ensemble theory 2301.03962):
/// two verification receipts INDEPENDENTLY confirm a pattern iff BOTH `admits_write()`
/// AND their CLASSES DIFFER. The class IS the derivation's axis, so two passes from
/// DIFFERENT classes (e.g. a compiler oracle AND a cross-memory consistency check) are
/// independent — their agreement carries real verification gain. Two passes from the
/// SAME class are a self-compare (correlation 1 ⇒ 0 gain) and are REJECTED as vacuous:
/// a pattern is never "doubly verified" by re-checking the SAME oracle twice. This is
/// the deterministic shape of "falsifiable, not vacuous-true".
#[must_use]
pub fn two_derivation_admits(a: &VerificationReceipt, b: &VerificationReceipt) -> bool {
    a.class != b.class && a.admits_write() && b.admits_write()
}

/// The held-out CANARY: a fixed set of `(class, evidence) → expected verdict` cases the
/// deterministic gate MUST still classify correctly. Because [`verify`] is a pure
/// function it cannot drift at runtime — but a future edit that WEAKENED it (a "collapse"
/// admitting what it must reject, or rejecting what it must admit) flips a canary case.
/// A tiny held-out set catches collapse (SRT 2505.21444). The cases pin the load-bearing
/// admit/reject BOUNDARIES across every tier.
const CANARY: &[(VerificationClass, VerificationEvidence, VerificationVerdict)] = &[
    // the compiler oracle bit: a pass admits; a fail / honest absence never do
    (
        VerificationClass::Code,
        VerificationEvidence::CodeOracle(Some(true)),
        VerificationVerdict::Verified,
    ),
    (
        VerificationClass::Code,
        VerificationEvidence::CodeOracle(Some(false)),
        VerificationVerdict::Unverified,
    ),
    (
        VerificationClass::Code,
        VerificationEvidence::CodeOracle(None),
        VerificationVerdict::NotApplicable,
    ),
    // cross-memory: a contradiction is quarantined; consistency admits
    (
        VerificationClass::CrossMemory,
        VerificationEvidence::CrossMemory {
            contradicts_held_ltm: true,
        },
        VerificationVerdict::Unverified,
    ),
    (
        VerificationClass::CrossMemory,
        VerificationEvidence::CrossMemory {
            contradicts_held_ltm: false,
        },
        VerificationVerdict::Verified,
    ),
    // a model may NOT promote its own inference to an owner fact
    (
        VerificationClass::PersonalOwner,
        VerificationEvidence::OwnerProvenance(OwnerProvenance::NotOwner),
        VerificationVerdict::Unverified,
    ),
    // a lone source never confirms; >= N independent does
    (
        VerificationClass::ExternalFact,
        VerificationEvidence::Corroboration {
            independent_count: 1,
            threshold: 1,
        },
        VerificationVerdict::Unverified,
    ),
    (
        VerificationClass::ExternalFact,
        VerificationEvidence::Corroboration {
            independent_count: 2,
            threshold: 2,
        },
        VerificationVerdict::Verified,
    ),
    // a fresh model inference is advisory (perf-tracking has not confirmed it)
    (
        VerificationClass::ModelInference,
        VerificationEvidence::PerfTracking(PerfScore {
            reinforced: 0,
            demoted: 0,
        }),
        VerificationVerdict::Unverified,
    ),
    // evidence for the WRONG class is fail-closed (a forged OwnerConfirmed on a Code task)
    (
        VerificationClass::Code,
        VerificationEvidence::OwnerProvenance(OwnerProvenance::OwnerConfirmed),
        VerificationVerdict::Unverified,
    ),
];

/// Re-run the deterministic gate over the held-out [`CANARY`]; `true` iff EVERY case
/// still classifies to its expected verdict (the gate has NOT collapsed/weakened). The
/// autonomous write path checks this BEFORE admitting any write — a failing canary
/// fail-closes the whole write (no pattern is promoted while the gate is suspect).
#[must_use]
pub fn canary_intact() -> bool {
    CANARY
        .iter()
        .all(|(class, evidence, want)| verify(*class, evidence).verdict == *want)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use super::*;

    fn kind(label: &str) -> ExecutorKind {
        ExecutorKind::new(label).expect("valid label")
    }

    #[test]
    fn classify_is_total_over_the_five_tiers() {
        assert_eq!(
            classify(&kind(ExecutorKind::SUI_MOVE)),
            VerificationClass::Code
        );
        assert_eq!(
            classify(&kind(ExecutorKind::SOLANA_ANCHOR)),
            VerificationClass::Code
        );
        assert_eq!(
            classify(&kind(ExecutorKind::WEB3_FRONTEND)),
            VerificationClass::Code
        );
        assert_eq!(
            classify(&kind(ExecutorKind::PERSONAL_MEMORY)),
            VerificationClass::PersonalOwner
        );
        assert_eq!(
            classify(&kind(ExecutorKind::EXTERNAL_FACT)),
            VerificationClass::ExternalFact
        );
        assert_eq!(
            classify(&kind(ExecutorKind::RESEARCH)),
            VerificationClass::ExternalFact
        );
        assert_eq!(
            classify(&kind(ExecutorKind::CROSS_MEMORY)),
            VerificationClass::CrossMemory
        );
        // audit = leads not findings ⇒ model-inference; nl ⇒ model-inference.
        assert_eq!(
            classify(&kind(ExecutorKind::AUDIT)),
            VerificationClass::ModelInference
        );
        assert_eq!(
            classify(&kind(ExecutorKind::NL_BRIDGE)),
            VerificationClass::ModelInference
        );
        assert_eq!(
            classify(&kind("totally_unknown_expert")),
            VerificationClass::ModelInference,
            "unknown kind is the lowest-trust fail-safe (never auto-verified)"
        );
    }

    /// THE P-HALL PROOF: a Code sub-task admits a Write ONLY when the COMPILER oracle
    /// passed — never on the model's say-so (the model's text is not even an input).
    #[test]
    fn code_admits_only_on_a_passing_compiler_oracle() {
        let pass = verify(
            VerificationClass::Code,
            &VerificationEvidence::CodeOracle(Some(true)),
        );
        assert_eq!(pass.verdict, VerificationVerdict::Verified);
        assert!(pass.admits_write());

        let fail = verify(
            VerificationClass::Code,
            &VerificationEvidence::CodeOracle(Some(false)),
        );
        assert_eq!(fail.verdict, VerificationVerdict::Unverified);
        assert!(!fail.admits_write(), "a failed compile never admits");

        let not_run = verify(
            VerificationClass::Code,
            &VerificationEvidence::CodeOracle(None),
        );
        assert_eq!(not_run.verdict, VerificationVerdict::NotApplicable);
        assert!(!not_run.admits_write(), "an un-run oracle never admits");
    }

    /// PersonalOwner: only an owner-CONFIRMED provenance admits; an unconfirmed or
    /// model-authored claim does NOT (a model cannot promote itself to an owner fact).
    #[test]
    fn personal_owner_admits_only_when_owner_confirmed() {
        let confirmed = verify(
            VerificationClass::PersonalOwner,
            &VerificationEvidence::OwnerProvenance(OwnerProvenance::OwnerConfirmed),
        );
        assert_eq!(confirmed.verdict, VerificationVerdict::Verified);
        assert!(confirmed.admits_write());

        for prov in [
            OwnerProvenance::OwnerAuthoredUnconfirmed,
            OwnerProvenance::NotOwner,
        ] {
            let r = verify(
                VerificationClass::PersonalOwner,
                &VerificationEvidence::OwnerProvenance(prov),
            );
            assert_eq!(r.verdict, VerificationVerdict::Unverified, "{prov:?}");
            assert!(!r.admits_write(), "{prov:?} must not admit");
        }
    }

    /// ExternalFact: a lone source never confirms — the verdict clamps the threshold
    /// UP to `CORROBORATION_MIN`, so `threshold = 1` still needs `>= 2` independent.
    #[test]
    fn external_fact_needs_n_independent_corroborations() {
        // count 2, threshold 2 ⇒ Verified.
        let ok = verify(
            VerificationClass::ExternalFact,
            &VerificationEvidence::Corroboration {
                independent_count: 2,
                threshold: 2,
            },
        );
        assert!(ok.admits_write());
        // count 1 ⇒ Unverified (lone source).
        let lone = verify(
            VerificationClass::ExternalFact,
            &VerificationEvidence::Corroboration {
                independent_count: 1,
                threshold: 1,
            },
        );
        assert!(
            !lone.admits_write(),
            "a single source never confirms a fact"
        );
        // threshold below the floor is clamped UP: count 1, threshold 1 ⇒ need 2 ⇒ fail.
        let clamp = verify(
            VerificationClass::ExternalFact,
            &VerificationEvidence::Corroboration {
                independent_count: 1,
                threshold: 0,
            },
        );
        assert!(
            !clamp.admits_write(),
            "threshold clamps up to the MIN floor"
        );
        // a stricter caller threshold is honored: count 2, threshold 3 ⇒ fail.
        let stricter = verify(
            VerificationClass::ExternalFact,
            &VerificationEvidence::Corroboration {
                independent_count: 2,
                threshold: 3,
            },
        );
        assert!(
            !stricter.admits_write(),
            "a stricter caller threshold is honored"
        );
    }

    /// ModelInference: advisory until DGM-H perf-tracking confirms; any demotion
    /// un-confirms (the model never confirms itself).
    #[test]
    fn model_inference_admits_only_after_perf_confirms() {
        let fresh = verify(
            VerificationClass::ModelInference,
            &VerificationEvidence::PerfTracking(PerfScore::default()),
        );
        assert!(
            !fresh.admits_write(),
            "a fresh inference is advisory, not admitted"
        );

        let confirmed = verify(
            VerificationClass::ModelInference,
            &VerificationEvidence::PerfTracking(PerfScore::default().reinforce()),
        );
        assert!(
            confirmed.admits_write(),
            "one verified-good reinforcement confirms"
        );

        let demoted = verify(
            VerificationClass::ModelInference,
            &VerificationEvidence::PerfTracking(PerfScore::default().reinforce().demote()),
        );
        assert!(
            !demoted.admits_write(),
            "any demotion un-confirms (fail-closed)"
        );
    }

    /// CrossMemory: a pattern consistent with the held LTM is Verified; a contradiction
    /// is quarantined (Unverified) and never written.
    #[test]
    fn cross_memory_quarantines_contradictions() {
        let consistent = verify(
            VerificationClass::CrossMemory,
            &VerificationEvidence::CrossMemory {
                contradicts_held_ltm: false,
            },
        );
        assert!(consistent.admits_write());
        let conflict = verify(
            VerificationClass::CrossMemory,
            &VerificationEvidence::CrossMemory {
                contradicts_held_ltm: true,
            },
        );
        assert_eq!(conflict.verdict, VerificationVerdict::Unverified);
        assert!(!conflict.admits_write(), "a contradiction is quarantined");
    }

    /// Paranoid fail-closed: evidence for the WRONG class never admits (a forged
    /// `OwnerConfirmed` fed to a Code sub-task is a typed mismatch ⇒ Unverified), and
    /// `Absent` is the honest `NotApplicable`.
    #[test]
    fn mismatched_or_absent_evidence_never_admits() {
        let mismatch = verify(
            VerificationClass::Code,
            &VerificationEvidence::OwnerProvenance(OwnerProvenance::OwnerConfirmed),
        );
        assert_eq!(mismatch.verdict, VerificationVerdict::Unverified);
        assert!(
            !mismatch.admits_write(),
            "evidence/class mismatch never admits"
        );

        for class in [
            VerificationClass::Code,
            VerificationClass::PersonalOwner,
            VerificationClass::ExternalFact,
            VerificationClass::ModelInference,
            VerificationClass::CrossMemory,
        ] {
            let r = verify(class, &VerificationEvidence::Absent);
            assert_eq!(r.verdict, VerificationVerdict::NotApplicable, "{class:?}");
            assert!(!r.admits_write(), "{class:?} + Absent never admits");
        }
    }

    /// Falsifiability canary: `admits_write` is genuinely selective — Verified admits,
    /// the other two verdicts do not (a wrong impl that admitted all would FAIL here).
    #[test]
    fn admits_write_is_selective_canary() {
        let mk = |verdict| VerificationReceipt {
            class: VerificationClass::Code,
            verdict,
            detail: String::new(),
        };
        assert!(mk(VerificationVerdict::Verified).admits_write());
        assert!(!mk(VerificationVerdict::Unverified).admits_write());
        assert!(!mk(VerificationVerdict::NotApplicable).admits_write());
    }

    /// PerfScore arithmetic is saturating + monotone (the perf-tracking ledger).
    #[test]
    fn perf_score_is_saturating_and_monotone() {
        let s = PerfScore::default().reinforce().reinforce();
        assert_eq!(s.reinforced, 2);
        assert!(s.is_confirmed());
        assert!(!s.demote().is_confirmed(), "a demotion un-confirms");
        assert!(
            !PerfScore::default().is_confirmed(),
            "fresh is not confirmed"
        );
    }

    /// THE TWO-DERIVATION FORMALISM: two INDEPENDENT passing derivations (different
    /// classes) doubly-verify; a self-compare (same class) is vacuous (0 gain); a
    /// failing derivation never doubly-verifies.
    #[test]
    fn two_derivation_requires_independent_passing_axes() {
        let code_pass = verify(
            VerificationClass::Code,
            &VerificationEvidence::CodeOracle(Some(true)),
        );
        let cm_pass = verify(
            VerificationClass::CrossMemory,
            &VerificationEvidence::CrossMemory {
                contradicts_held_ltm: false,
            },
        );
        // two INDEPENDENT passes (Code ⟂ CrossMemory) ⇒ doubly verified
        assert!(two_derivation_admits(&code_pass, &cm_pass));
        assert!(
            two_derivation_admits(&cm_pass, &code_pass),
            "order-independent"
        );
        // a self-compare (SAME class) is correlation 1 ⇒ 0 gain ⇒ rejected as vacuous
        let cm_pass2 = verify(
            VerificationClass::CrossMemory,
            &VerificationEvidence::CrossMemory {
                contradicts_held_ltm: false,
            },
        );
        assert!(
            !two_derivation_admits(&cm_pass, &cm_pass2),
            "two same-class passes are vacuous, never doubly verified"
        );
        // a failing derivation never doubly-verifies, even paired with a pass
        let code_fail = verify(
            VerificationClass::Code,
            &VerificationEvidence::CodeOracle(Some(false)),
        );
        assert!(!two_derivation_admits(&code_fail, &cm_pass));
    }

    /// THE HELD-OUT CANARY: the shipped gate classifies every canary case correctly.
    #[test]
    fn canary_is_intact_for_the_shipped_gate() {
        assert!(
            canary_intact(),
            "the deterministic gate must classify every held-out canary correctly"
        );
    }

    /// CANARY NON-VACUITY: a canary would CATCH a collapsed gate — the real gate's
    /// verdict for a failed compile is NOT `Verified`, so a future edit that weakened
    /// the gate to admit a failed compile would flip the (Code, fail) → Unverified case.
    #[test]
    fn canary_would_catch_a_weakened_gate() {
        let collapsed = (
            VerificationClass::Code,
            VerificationEvidence::CodeOracle(Some(false)),
            VerificationVerdict::Verified, // WRONG: a failed compile must be Unverified
        );
        assert_ne!(
            verify(collapsed.0, &collapsed.1).verdict,
            collapsed.2,
            "the real gate rejects what a collapsed gate would admit ⇒ canary non-vacuous"
        );
    }
}
