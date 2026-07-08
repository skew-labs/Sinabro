//! `verification` — the Typed-Write-Admission TRUST-TIER ladder that anchors the
//! hallucination-loop defense.
//!
//! The hallucination loop (P-HALL) poisons itself when the autonomous loop writes
//! a pattern to permanent memory on the MODEL's own self-judgment of "success".
//! The physical fix: the MODEL never declares success — a typed RECEIPT does, and
//! that receipt is produced by a class-appropriate ORACLE (a deterministic
//! external check), NOT the model's text. This module is that deterministic ladder:
//!
//!   sub-task `kind` --classify--> VerificationClass --(class-typed ORACLE evidence)--> verdict
//!
//! ## The trust tiers, typed onto the Oracle Ladder (the compiler = ONE rung)
//!
//! Each class has its OWN oracle; none is the model's self-judgment. [`OracleRung`] names
//! each class's GUARANTEE strength (R0 strongest … R6 quarantine floor):
//! * `Code`           — a compiler / test / formal exit-code bit (the real
//!   `sui move build` in the network-DENIED sandbox). **R0**.
//! * `Invariant`      — a deterministic accounting/constraint identity the
//!   [`crate::reconcile_oracle`] re-derives FAIL-CLOSED: a reconciled certificate is
//!   sound on the arithmetic, NOT that the inputs are real (the honest LOCK). **R1**.
//! * `Induced`        — a checker INDUCED + held-out-CERTIFIED from the customer's recognition
//!   set ([`crate::recognition_synth`]): a certified `Accept` admits a provisional
//!   recognition-calibrated pattern; an `Escalate` defers. **R5**.
//! * `PersonalOwner`  — PROVENANCE: owner-authored AND owner-confirmed (a model may
//!   NOT promote its own inference to an owner fact — structural, not advisory). **R5**.
//! * `ExternalFact`   — `>= N` INDEPENDENT source-linked corroborations (a lone /
//!   weak source NEVER confirms; [`CORROBORATION_MIN`] is the floor). **R4**.
//! * `ModelInference` — the LOWEST trust: advisory until PERFORMANCE-TRACKING
//!   accumulates verified-good outcomes (retrieve→act→verified-good ⇒ reinforce;
//!   →failure ⇒ demote). The universal non-compiler oracle; breaks the RAG↔HALL
//!   compound. This is the TOTAL fail-safe: an UNKNOWN expert kind lands here. **R6**.
//! * `CrossMemory`    — write-time CONTRADICTION-DETECTION vs the held LTM; a
//!   conflicting pattern is quarantined (Unverified), never written. **R2** (a
//!   contradiction is a sound reject; consistency is "not-yet-falsified").
//! * `Metamorphic`    — a summarization METAMORPHIC relation (`summary ⊆ source`:
//!   quote + number containment + a compression target) the [`crate::metamorphic_oracle`]
//!   re-checks. A SOUND REJECTOR (rejector-only): a FALSIFIED relation is Unverified (a sound
//!   reject, never written); a `NotFalsified` is `NotApplicable` and NEVER admits a write (a
//!   metamorphic pass is "not-yet-falsified", not proof — so this class never even ADMITS). **R2**.
//! * `Strategy`       — a SKEW trading strategy conformal-CERTIFIED from its deterministic
//!   SHADOW track record (every candidate trade leg gated by the trade oracle; the
//!   [`crate::conformal::certify_far_default`] FAR bound). A CERTIFIED strategy admits a (doubly-
//!   verified) write; an uncertified one defers. certified ≠ profitable (honest LOCK). **R4**.
//!
//! ## drift-0 + token-min
//!
//! This ENTIRE ladder is DETERMINISTIC RUST with 0 IO and 0 external LLM tokens:
//! `classify` is a TOTAL pure function (unknown kind ⇒ `ModelInference`, the
//! lowest-trust fail-safe) and `verify`'s verdict is a deterministic function of
//! `(class, typed evidence)` — the MODEL's answer TEXT is NEVER an input, so a model
//! cannot self-certify a Write. Evidence is TYPED: a model cannot fabricate a
//! `CodeOracle(true)` or an `OwnerConfirmed` (those come from the deterministic
//! oracle / a typed owner gate, not the model's words). Only a `Verified` receipt
//! ADMITS a permanent Write (the permanent Walrus Write gates on `admits_write`);
//! `Unverified` (failed / quarantined / advisory) and `NotApplicable` (honest
//! oracle-absence) never auto-admit. custody/funds stay HARD-LOCKED: pure, no IO.

use crate::metamorphic_oracle::SummaryVerdict;
use crate::provider::executor_route::ExecutorKind;
use crate::recognition_synth::InducedVerdict;
use crate::reconcile_oracle::ReconcileVerdict;

/// The minimum number of INDEPENDENT corroborations an [`VerificationClass::ExternalFact`]
/// needs before it can be `Verified` (a single source never confirms a fact). The
/// caller may demand MORE (its own `threshold`), never fewer — the verdict clamps up.
pub const CORROBORATION_MIN: u32 = 2;

/// The Oracle Ladder rung — the TYPED strength hierarchy this
/// module's trust classes sit on. The rung names a class's GUARANTEE, not a new gate: the
/// load-bearing admit/reject decision is still [`verify`] (a pure function of `(class,
/// evidence)`), and [`VerificationClass::rung`] is a total projection onto this ladder.
///
/// The ladder generalizes across domains: a pattern is WRITTEN as
/// VERIFIED only when it cleared a rung whose guarantee its domain requires; R6 is the
/// quarantine floor that NEVER ACCUMULATEs as verified. The runtime oracle stays
/// DETERMINISTIC at every rung — the model PROPOSES, an L0 check judges (no LLM
/// judge, the reward-hacking block).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OracleRung {
    /// R0 — formal / compiler oracle (sound+complete-ish; free, deterministic). The
    /// strongest rung: an exit-code bit from a real compiler / test.
    R0Formal,
    /// R1 — invariant / constraint oracle (sound on the CHECKED invariant, incomplete).
    /// The finance reconciliation oracle lives here: it re-derives a stated identity
    /// FAIL-CLOSED. Sound on the arithmetic, NOT that the inputs are real (the honest LOCK).
    R1Invariant,
    /// R2 — metamorphic oracle (a SOUND REJECTOR only — it proves a VIOLATION, never
    /// truth). A write-time cross-memory contradiction is exactly this: a conflict is a
    /// sound reject; consistency is "not-yet-falsified", never proof of correctness.
    R2Metamorphic,
    /// R3 — simulation / reality oracle (correct within a tolerance). No v1 trust class
    /// maps here on its own (the sandboxed-exec dimension is folded into the R0 `Code`
    /// oracle); the rung is enumerated so the ladder is complete + future-extensible.
    R3Simulation,
    /// R4 — independent redundancy + conformal threshold (calibrated confidence). The
    /// external-fact tier: `>= N` INDEPENDENT corroborations, a lone source never confirms.
    R4Redundancy,
    /// R5 — calibrated-human (a customer recognition set + conformal; `P(correct) >= 1-α`).
    /// The owner-provenance tier: an owner-authored + owner-confirmed fact via a human gate.
    R5CalibratedHuman,
    /// R6 — deferred / quarantine: guarantee NONE, labeled UNVERIFIED, **NEVER ACCUMULATEs
    /// as verified**. The total fail-safe floor: an unknown / un-mapped expert kind, or a
    /// fresh model inference, sits here until an INDEPENDENT downstream oracle escalates it
    /// (the perf-tracking promotion is that escalation OUT of R6).
    R6Quarantine,
}

/// The verification class a sub-task falls into — which kind of oracle can judge it. OPEN to
/// extension; each maps to an [`OracleRung`]. The `Invariant` (R1) tier is produced by the
/// reconcile-oracle bridge ([`reconciliation_receipt`]), `Induced` (R5) by the
/// recognition-synthesis bridge ([`recognition_receipt`]), and `Metamorphic` (R2) by the
/// summarization bridge ([`metamorphic_receipt`]); the other five by `classify`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum VerificationClass {
    /// Code / skill output a deterministic compiler / test / formal oracle judges
    /// (exit-code truth). The compiler rung (Oracle Ladder R0).
    Code,
    /// An INVARIANT / constraint the deterministic [`crate::reconcile_oracle`] re-derives
    /// FAIL-CLOSED (Oracle Ladder R1). The non-coding analog of the compiler: a
    /// financial CERTIFICATE that reconciles with its STATED items is `Verified` — sound on
    /// the arithmetic, NOT that the positions/sources are real (the honest LOCK carries).
    /// This class is produced by the reconcile-oracle bridge ([`reconciliation_receipt`]),
    /// not by [`classify`]'s kind routing (it is an oracle-produced class, like the Code bit).
    Invariant,
    /// A checker INDUCED + held-out-CERTIFIED from the customer's recognition set (Oracle Ladder
    /// R5 — [`crate::recognition_synth`]). Its 3-way verdict (`Accept`/`Reject`/`Escalate`)
    /// is produced by the [`recognition_receipt`] bridge: a CERTIFIED `Accept` admits a write (a
    /// provisional, recognition-calibrated R5 pattern); an uncertified accept / a `Reject` does
    /// not; an `Escalate` defers (honest absence). The QUANTITATIVE conformal α-budget is deferred.
    Induced,
    /// A personal / owner memory: PROVENANCE is the oracle (owner-authored +
    /// owner-confirmed = highest trust; a model may not author an owner fact).
    PersonalOwner,
    /// An external fact: independent CORROBORATION is the oracle (`>= N` sources).
    ExternalFact,
    /// Model inference: the LOWEST trust — advisory until PERFORMANCE-TRACKING
    /// confirms. The TOTAL fail-safe class for any unknown / un-mapped expert kind.
    ModelInference,
    /// A cross-memory write: the oracle is write-time CONTRADICTION-DETECTION vs the
    /// held LTM (a conflict is quarantined, never written).
    CrossMemory,
    /// A summarization METAMORPHIC relation the [`crate::metamorphic_oracle`] re-checks
    /// (`summary ⊆ source`: quote + number containment + a compression target). A SOUND
    /// REJECTOR (Oracle Ladder R2): a falsified relation is `Unverified` (a sound reject,
    /// quarantined, never written); a `NotFalsified` is `NotApplicable` and NEVER admits a
    /// write (rejector-only — a metamorphic pass is "not-yet-falsified", not a verification).
    /// Produced by the [`metamorphic_receipt`] bridge, not by [`classify`]'s kind routing.
    Metamorphic,
    /// A SKEW trading STRATEGY conformal-CERTIFIED from its deterministic SHADOW track record
    /// (Oracle Ladder R4: independent redundancy + the exact conformal threshold). A strategy is
    /// shadow-evaluated over the real trade history with EVERY candidate trade leg gated by the
    /// trade oracle (no LLM judge); the [`crate::conformal::certify_far_default`] FAR bound CERTIFIES
    /// it iff its out-of-bounds proposal RATE is provably bounded (`k` oracle-denied fires in `n`
    /// total fires; `k=0, n≥10`). A CERTIFIED strategy admits a write (then still subject to the SAME
    /// canary + cross-memory + two-derivation gates — Strategy R4 ⟂ CrossMemory R2 ⇒ DOUBLY VERIFIED);
    /// an UNcertified one does not. Produced by the [`strategy_receipt`] bridge, not by [`classify`].
    /// HONEST LOCK: certified = proposals stay IN-BOUNDS (the affordability/safety property), NOT
    /// profitable; shadow money 0; the live sub-budget is the owner-armed path.
    Strategy,
}

impl VerificationClass {
    /// The Oracle Ladder rung this trust class sits on — a TOTAL projection
    /// (drift-0: every class resolves, exhaustively, so a future class forces a rung
    /// decision at compile time). The mapping names each class's GUARANTEE strength:
    /// * `Code`          → R0 (formal/compiler — sound+complete-ish);
    /// * `Invariant`     → R1 (the reconcile oracle — sound on the checked invariant);
    /// * `CrossMemory` / `Metamorphic` → R2 (metamorphic sound-rejectors — a contradiction /
    ///   a falsified `summary ⊆ source` relation is a SOUND REJECT; satisfaction is
    ///   "not-yet-falsified", never proof of truth);
    /// * `ExternalFact`  → R4 (independent redundancy — `>= N` corroborations);
    /// * `PersonalOwner` → R5 (calibrated-human — owner gate);
    /// * `ModelInference`→ R6 (quarantine — advisory/UNVERIFIED until perf-tracking escalates
    ///   it OUT of R6; never auto-ACCUMULATEs).
    ///
    /// (R3 simulation has no v1 class of its own — the sandboxed-exec dimension is folded
    /// into the R0 `Code` oracle. The rung is enumerated for ladder completeness.)
    #[must_use]
    pub const fn rung(self) -> OracleRung {
        match self {
            VerificationClass::Code => OracleRung::R0Formal,
            VerificationClass::Invariant => OracleRung::R1Invariant,
            // both a write-time cross-memory contradiction check AND the summarization
            // metamorphic checker are R2 sound-rejectors — the rung names the GUARANTEE, which
            // multiple oracle types share (like R5's PersonalOwner + Induced).
            VerificationClass::CrossMemory | VerificationClass::Metamorphic => {
                OracleRung::R2Metamorphic
            }
            // both the independent-corroboration external-fact tier AND a Skew strategy
            // conformal-certified from its shadow track record are R4 (independent redundancy + the
            // exact conformal threshold) — the rung names the GUARANTEE, shared by multiple oracle types.
            VerificationClass::ExternalFact | VerificationClass::Strategy => {
                OracleRung::R4Redundancy
            }
            // both the owner-provenance tier AND a checker induced+certified from the customer's
            // recognition set are calibrated-human (R5) — the rung names the guarantee
            // STRENGTH, which multiple oracle types can share.
            VerificationClass::PersonalOwner | VerificationClass::Induced => {
                OracleRung::R5CalibratedHuman
            }
            VerificationClass::ModelInference => OracleRung::R6Quarantine,
        }
    }
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

/// PERFORMANCE-TRACKING score for a [`VerificationClass::ModelInference`] pattern:
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
    /// a larger floor = more paranoid, owner-tunable).
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
    /// `Invariant` (R1): the deterministic [`crate::reconcile_oracle`] verdict for a finance
    /// CERTIFICATE — `Reconciled` admits, `Violated` is a sound reject, `NotApplicable` an
    /// honest absence. The model PROPOSES the certificate; this verdict is the L0 checker's,
    /// never the model's text (the no-LLM-judge boundary).
    Reconciliation(ReconcileVerdict),
    /// `Induced` (R5): the [`crate::recognition_synth`] checker's 3-way verdict on an example +
    /// whether the checker passed the held-out zero-false-accept CERTIFICATION. A
    /// CERTIFIED `Accept` admits; an uncertified accept / a `Reject` does not; an `Escalate`
    /// defers. The verdict is the induced checker's (pure geometry), never the model's text.
    Recognition {
        /// The induced checker's 3-way verdict for the example.
        verdict: InducedVerdict,
        /// Whether the checker passed the held-out zero-false-accept gate.
        certified: bool,
    },
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
    /// `ModelInference`: the performance-tracking score for this pattern.
    PerfTracking(PerfScore),
    /// `CrossMemory`: whether the pattern CONTRADICTS the held LTM (write-time).
    CrossMemory {
        /// `true` ⇒ the pattern conflicts with held memory ⇒ quarantined.
        contradicts_held_ltm: bool,
    },
    /// `Metamorphic` (R2): whether a summarization metamorphic relation was VIOLATED (the
    /// [`crate::metamorphic_oracle`] checker's bool). `true` ⇒ a sound reject (`Unverified`);
    /// `false` ⇒ NOT-falsified (`NotApplicable`, NEVER admits — rejector-only). The verdict is
    /// the checker's (pure string/integer geometry), never the model's text.
    Metamorphic {
        /// `true` ⇒ a metamorphic relation was falsified (a sound reject) ⇒ `Unverified`.
        violation: bool,
    },
    /// `Strategy` (R4): whether a Skew strategy passed the deterministic conformal SHADOW
    /// certification (`crate::conformal::certify_far_default(k, n)` over its oracle-gated shadow track
    /// record). `true` ⇒ CERTIFIED (admits); `false` ⇒ not certified (never admits). The bit is the
    /// deterministic FAR-bound result, never the model's say-so (the no-LLM-judge boundary).
    StrategyShadow {
        /// `true` ⇒ the strategy's out-of-bounds proposal rate is provably bounded (conformal-certified).
        certified: bool,
    },
    /// No oracle evidence supplied for this sub-task (honest absence ⇒ NotApplicable).
    Absent,
}

/// The typed verification receipt: the class, the oracle verdict, and a secret-zero
/// static reason. A permanent Walrus Write gates on this.
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
        // --- Invariant (R1): the reconcile oracle verdict (sound on the arithmetic only) ---
        (C::Invariant, E::Reconciliation(rv)) => match rv {
            ReconcileVerdict::Reconciled => (
                Verified,
                "invariant reconciled (R1: arithmetic-sound; NOT that positions/sources are real)",
            ),
            ReconcileVerdict::Violated => (
                Unverified,
                "invariant violated (R1 sound reject: insolvent / NAV mismatch)",
            ),
            ReconcileVerdict::NotApplicable => (
                NotApplicable,
                "invariant oracle not applicable (malformed/empty certificate; honest absence)",
            ),
        },
        // --- Induced (R5): the recognition-synthesized checker's verdict (certify-gated) ---
        (C::Induced, E::Recognition { verdict, certified }) => match (*verdict, *certified) {
            (InducedVerdict::Accept, true) => (
                Verified,
                "induced checker ACCEPT + held-out certified (R5 provisional; α-budget = O-3c)",
            ),
            (InducedVerdict::Accept, false) => (
                Unverified,
                "induced checker ACCEPT but NOT certified (held-out zero-false-accept gate unmet)",
            ),
            (InducedVerdict::Reject, _) => (
                Unverified,
                "induced checker REJECT (a sound trustworthy negative — never admits)",
            ),
            (InducedVerdict::Escalate, _) => (
                NotApplicable,
                "induced checker ESCALATE (deferred to a human; honest absence — R6 quarantine)",
            ),
        },
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
        // --- ModelInference: performance-tracking ---
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
        // --- Metamorphic (R2): a SOUND REJECTOR — NEVER yields Verified ---
        (C::Metamorphic, E::Metamorphic { violation }) => {
            if *violation {
                (
                    Unverified,
                    "metamorphic relation FALSIFIED (R2 sound reject: fabricated quote / unsupported number / over-compression — quarantined, never written)",
                )
            } else {
                (
                    NotApplicable,
                    "metamorphic relations NOT falsified (PROVISIONAL — may still OMIT key info; R2 rejector-only NEVER admits a write)",
                )
            }
        }
        // --- Strategy (R4): the conformal shadow-certification bit ---
        (C::Strategy, E::StrategyShadow { certified }) => {
            if *certified {
                (
                    Verified,
                    "skew strategy conformal-CERTIFIED (R4: out-of-bounds proposal rate provably bounded over the oracle-gated shadow record; certified ≠ profitable — honest LOCK)",
                )
            } else {
                (
                    Unverified,
                    "skew strategy NOT certified (insufficient in-bounds shadow fires or out-of-bounds rate too high — never admits)",
                )
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

/// The reconcile-oracle R1 entry — the SINGLE bridge from the deterministic
/// [`crate::reconcile_oracle`] checker to the [`VerificationClass::Invariant`] (R1) rung.
/// Produce the typed write-admission receipt for a finance reconciliation `verdict`: a
/// `Reconciled` certificate `admits_write()`; a `Violated` (a sound reject) / `NotApplicable`
/// (honest absence) one does NOT. The model never reaches [`verify`] — only the checker's
/// TYPED verdict does (the no-LLM-judge boundary). The honest LOCK carries through the
/// receipt detail: admitting means arithmetic-sound, NOT that the positions/sources are real.
#[must_use]
pub fn reconciliation_receipt(verdict: ReconcileVerdict) -> VerificationReceipt {
    verify(
        VerificationClass::Invariant,
        &VerificationEvidence::Reconciliation(verdict),
    )
}

/// The recognition-synthesis R5 entry — the SINGLE bridge from the induced
/// [`crate::recognition_synth`] checker to the [`VerificationClass::Induced`] (R5) rung. Produce
/// the typed write-admission receipt for an induced checker's `verdict` + its `certified` gate:
/// a CERTIFIED `Accept` `admits_write()`; an uncertified accept / a `Reject` does NOT; an
/// `Escalate` is the honest `NotApplicable` (deferred to a human, R6-quarantine-shaped). The
/// model never reaches [`verify`] — only the induced checker's TYPED verdict + the deterministic
/// certify bit do. HONEST LOCK: an admitted `Accept` is a PROVISIONAL R5 pattern (held-out
/// zero-false-accept gated); the quantitative conformal α-budget is deferred.
#[must_use]
pub fn recognition_receipt(verdict: InducedVerdict, certified: bool) -> VerificationReceipt {
    verify(
        VerificationClass::Induced,
        &VerificationEvidence::Recognition { verdict, certified },
    )
}

/// The summarization metamorphic R2 entry — the SINGLE bridge from the deterministic
/// [`crate::metamorphic_oracle`] checker to the [`VerificationClass::Metamorphic`] (R2) rung. A
/// SOUND REJECTOR, rejector-only: a `Rejected` verdict is `Unverified`
/// (a sound reject — it BLOCKS a write, never admits one); a `NotFalsified` is the honest
/// `NotApplicable` (PROVISIONAL — never admits; a metamorphic pass is "not-yet-falsified", not a
/// verification); a malformed input is the honest absence. Because this class NEVER yields
/// `Verified`, it is a pure write-time GATE — never an admitting derivation, so it cannot be
/// wrongly marked "doubly verified" (the same-rung two-derivation subtlety is moot). The model
/// never reaches [`verify`] — only the checker's TYPED verdict does (no-LLM-judge boundary).
#[must_use]
pub fn metamorphic_receipt(verdict: SummaryVerdict) -> VerificationReceipt {
    match verdict {
        // a falsified relation ⇒ Unverified (a SOUND reject; it BLOCKS the write).
        SummaryVerdict::Rejected => verify(
            VerificationClass::Metamorphic,
            &VerificationEvidence::Metamorphic { violation: true },
        ),
        // not-falsified ⇒ NotApplicable (PROVISIONAL; NEVER admits — rejector-only).
        SummaryVerdict::NotFalsified => verify(
            VerificationClass::Metamorphic,
            &VerificationEvidence::Metamorphic { violation: false },
        ),
        // malformed / empty ⇒ the honest absence (also never admits).
        SummaryVerdict::NotApplicable => verify(
            VerificationClass::Metamorphic,
            &VerificationEvidence::Absent,
        ),
    }
}

/// The strategy-certification R4 entry — the SINGLE bridge from the deterministic conformal
/// SHADOW certification ([`crate::conformal::certify_far_default`] over a strategy's oracle-gated shadow
/// track record) to the [`VerificationClass::Strategy`] (R4) rung. A CERTIFIED strategy `admits_write()`
/// (then still subject to the SAME canary + cross-memory + two-derivation gates — Strategy R4 ⟂
/// CrossMemory R2 ⇒ DOUBLY VERIFIED); an UNcertified one does NOT. The model never reaches [`verify`] —
/// only the deterministic conformal `certified` bit does (the no-LLM-judge boundary). HONEST LOCK:
/// admitting means the strategy's PROPOSALS stay in-bounds over the shadow distribution, NOT that it is
/// PROFITABLE; shadow money 0; the live sub-budget is the owner-armed path.
#[must_use]
pub fn strategy_receipt(certified: bool) -> VerificationReceipt {
    verify(
        VerificationClass::Strategy,
        &VerificationEvidence::StrategyShadow { certified },
    )
}

// ===========================================================================
// The P-HALL formalisms: two-derivation verify + held-out canary
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
    // the R1 invariant/reconciliation oracle: a reconciled cert admits; a violation never
    // does; a malformed cert is an honest NotApplicable (the boundaries that close ACCUMULATE)
    (
        VerificationClass::Invariant,
        VerificationEvidence::Reconciliation(ReconcileVerdict::Reconciled),
        VerificationVerdict::Verified,
    ),
    (
        VerificationClass::Invariant,
        VerificationEvidence::Reconciliation(ReconcileVerdict::Violated),
        VerificationVerdict::Unverified,
    ),
    (
        VerificationClass::Invariant,
        VerificationEvidence::Reconciliation(ReconcileVerdict::NotApplicable),
        VerificationVerdict::NotApplicable,
    ),
    // the R5 induced checker: only a CERTIFIED accept admits; uncertified/reject never; escalate
    // defers (the boundaries that gate the recognition-synthesis ACCUMULATE)
    (
        VerificationClass::Induced,
        VerificationEvidence::Recognition {
            verdict: InducedVerdict::Accept,
            certified: true,
        },
        VerificationVerdict::Verified,
    ),
    (
        VerificationClass::Induced,
        VerificationEvidence::Recognition {
            verdict: InducedVerdict::Accept,
            certified: false,
        },
        VerificationVerdict::Unverified,
    ),
    (
        VerificationClass::Induced,
        VerificationEvidence::Recognition {
            verdict: InducedVerdict::Reject,
            certified: true,
        },
        VerificationVerdict::Unverified,
    ),
    (
        VerificationClass::Induced,
        VerificationEvidence::Recognition {
            verdict: InducedVerdict::Escalate,
            certified: true,
        },
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
    // metamorphic (R2 rejector-only): a FALSIFIED relation is a sound reject (Unverified);
    // a NOT-falsified pass is the honest NotApplicable — NEITHER is ever Verified (the rejector
    // property pinned: a future edit that let a metamorphic pass ADMIT would flip the 2nd case).
    (
        VerificationClass::Metamorphic,
        VerificationEvidence::Metamorphic { violation: true },
        VerificationVerdict::Unverified,
    ),
    (
        VerificationClass::Metamorphic,
        VerificationEvidence::Metamorphic { violation: false },
        VerificationVerdict::NotApplicable,
    ),
    // strategy (R4): only a CONFORMAL-CERTIFIED strategy admits; an uncertified one never does
    // (the boundary that gates the strategy ACCUMULATE — a future edit letting an uncertified
    // strategy admit would flip the 2nd case).
    (
        VerificationClass::Strategy,
        VerificationEvidence::StrategyShadow { certified: true },
        VerificationVerdict::Verified,
    ),
    (
        VerificationClass::Strategy,
        VerificationEvidence::StrategyShadow { certified: false },
        VerificationVerdict::Unverified,
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

    /// ModelInference: advisory until perf-tracking confirms; any demotion
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
            VerificationClass::Invariant,
            VerificationClass::Induced,
            VerificationClass::PersonalOwner,
            VerificationClass::ExternalFact,
            VerificationClass::ModelInference,
            VerificationClass::CrossMemory,
            VerificationClass::Metamorphic,
            VerificationClass::Strategy,
        ] {
            let r = verify(class, &VerificationEvidence::Absent);
            assert_eq!(r.verdict, VerificationVerdict::NotApplicable, "{class:?}");
            assert!(!r.admits_write(), "{class:?} + Absent never admits");
        }
    }

    /// THE R4 STRATEGY RUNG: only a CONFORMAL-CERTIFIED strategy admits a write; an uncertified
    /// one defers (Unverified). The bit is the deterministic conformal cert, never the model's text;
    /// a certified strategy (R4) is INDEPENDENT of the write-time cross-memory axis (R2) ⇒ doubly
    /// verified. Wrong-class evidence fail-closes.
    #[test]
    fn strategy_rung_admits_only_a_certified_strategy() {
        let ok = strategy_receipt(true);
        assert_eq!(ok.class, VerificationClass::Strategy);
        assert_eq!(ok.class.rung(), OracleRung::R4Redundancy);
        assert_eq!(ok.verdict, VerificationVerdict::Verified);
        assert!(ok.admits_write(), "a certified strategy admits a write");

        let no = strategy_receipt(false);
        assert_eq!(no.verdict, VerificationVerdict::Unverified);
        assert!(!no.admits_write(), "an uncertified strategy never admits");

        // R4 ⟂ R2 (cross-memory) ⇒ a certified strategy is doubly verified (independent axes).
        let cm = verify(
            VerificationClass::CrossMemory,
            &VerificationEvidence::CrossMemory {
                contradicts_held_ltm: false,
            },
        );
        assert!(
            two_derivation_admits(&ok, &cm),
            "Strategy (R4) ⟂ CrossMemory (R2) = two independent passing derivations"
        );

        // wrong-class fail-closed: StrategyShadow evidence fed to a Code task never admits.
        let mismatch = verify(
            VerificationClass::Code,
            &VerificationEvidence::StrategyShadow { certified: true },
        );
        assert!(
            !mismatch.admits_write(),
            "strategy evidence on a non-Strategy class never admits (fail-closed)"
        );
    }

    /// THE ORACLE LADDER TYPING: every trust class projects to its rung TOTALLY, and the
    /// non-obvious mappings are pinned — the reconcile oracle is R1, a cross-memory check is
    /// the R2 sound-rejector, and model-inference is the R6 quarantine floor.
    #[test]
    fn every_class_projects_to_its_oracle_ladder_rung() {
        assert_eq!(VerificationClass::Code.rung(), OracleRung::R0Formal);
        assert_eq!(VerificationClass::Invariant.rung(), OracleRung::R1Invariant);
        assert_eq!(
            VerificationClass::CrossMemory.rung(),
            OracleRung::R2Metamorphic,
            "a contradiction check is a sound rejector (R2), never proof of truth"
        );
        assert_eq!(
            VerificationClass::Metamorphic.rung(),
            OracleRung::R2Metamorphic,
            "a summarization metamorphic checker is a sound rejector (R2) — shares the rung"
        );
        assert_eq!(
            VerificationClass::ExternalFact.rung(),
            OracleRung::R4Redundancy
        );
        assert_eq!(
            VerificationClass::PersonalOwner.rung(),
            OracleRung::R5CalibratedHuman
        );
        assert_eq!(
            VerificationClass::Induced.rung(),
            OracleRung::R5CalibratedHuman,
            "a checker induced+certified from the customer recognition set is calibrated-human (R5)"
        );
        assert_eq!(
            VerificationClass::ModelInference.rung(),
            OracleRung::R6Quarantine,
            "model inference is the R6 quarantine floor (never auto-ACCUMULATEs)"
        );
    }

    /// THE R5 INDUCED RUNG: only a CERTIFIED `Accept` admits a write; an uncertified accept
    /// and a `Reject` do not; an `Escalate` defers (the R6-quarantine-shaped honest absence).
    #[test]
    fn induced_rung_admits_only_a_certified_accept() {
        let ok = recognition_receipt(InducedVerdict::Accept, true);
        assert_eq!(ok.class, VerificationClass::Induced);
        assert!(ok.admits_write(), "a certified ACCEPT admits");

        assert!(
            !recognition_receipt(InducedVerdict::Accept, false).admits_write(),
            "an UNcertified accept never admits (certify-before-accumulate)"
        );
        assert!(
            !recognition_receipt(InducedVerdict::Reject, true).admits_write(),
            "a REJECT is a sound negative — never admits"
        );
        let esc = recognition_receipt(InducedVerdict::Escalate, true);
        assert_eq!(esc.verdict, VerificationVerdict::NotApplicable);
        assert!(!esc.admits_write(), "an ESCALATE defers — never admits");
    }

    /// THE R2 METAMORPHIC RUNG (rejector-only): a FALSIFIED relation is a sound reject
    /// (Unverified — blocks the write); a NOT-falsified pass is the honest NotApplicable. CRUCIAL:
    /// this class NEVER yields Verified — `metamorphic_receipt` cannot admit a write for ANY input,
    /// so it is a pure write-time GATE (the maximally-paranoid sound-rejector posture; it is never
    /// an admitting derivation, so the same-rung two-derivation subtlety cannot arise).
    #[test]
    fn metamorphic_rung_is_a_sound_rejector_that_never_admits() {
        use crate::metamorphic_oracle::SummaryVerdict;

        // a falsified relation ⇒ Unverified (a sound reject — never admits).
        let rejected = metamorphic_receipt(SummaryVerdict::Rejected);
        assert_eq!(rejected.class, VerificationClass::Metamorphic);
        assert_eq!(rejected.verdict, VerificationVerdict::Unverified);
        assert!(
            !rejected.admits_write(),
            "a metamorphic REJECT blocks a write, never admits one"
        );

        // a NOT-falsified pass ⇒ NotApplicable — PROVISIONAL, NEVER admits (rejector-only).
        let pass = metamorphic_receipt(SummaryVerdict::NotFalsified);
        assert_eq!(pass.verdict, VerificationVerdict::NotApplicable);
        assert!(
            !pass.admits_write(),
            "a metamorphic PASS is not-yet-falsified — it NEVER admits a write (R2 rejector-only)"
        );

        // a malformed input ⇒ the honest absence, also never admits.
        let na = metamorphic_receipt(SummaryVerdict::NotApplicable);
        assert_eq!(na.verdict, VerificationVerdict::NotApplicable);
        assert!(!na.admits_write());

        // THE REJECTOR PROPERTY: NO verdict the bridge can produce is Verified — so a metamorphic
        // derivation can NEVER be an admitting axis (it is a pure GATE).
        assert_eq!(
            VerificationClass::Metamorphic.rung(),
            OracleRung::R2Metamorphic
        );
        for v in [
            SummaryVerdict::Rejected,
            SummaryVerdict::NotFalsified,
            SummaryVerdict::NotApplicable,
        ] {
            assert_ne!(
                metamorphic_receipt(v).verdict,
                VerificationVerdict::Verified,
                "the R2 metamorphic rejector NEVER yields Verified for any input"
            );
        }

        // wrong-class fail-closed: Metamorphic evidence fed to a Code task never admits.
        let mismatch = verify(
            VerificationClass::Code,
            &VerificationEvidence::Metamorphic { violation: false },
        );
        assert!(
            !mismatch.admits_write(),
            "metamorphic evidence on a non-Metamorphic class never admits (fail-closed)"
        );
    }

    /// THE R1 RECONCILIATION RUNG: the reconcile oracle's verdict drives the typed
    /// write-admission — `Reconciled` admits (R1 Verified), `Violated` is a sound reject,
    /// a malformed cert is an honest `NotApplicable`. The model's text is never an input.
    #[test]
    fn invariant_rung_admits_only_a_reconciled_certificate() {
        let ok = reconciliation_receipt(ReconcileVerdict::Reconciled);
        assert_eq!(ok.class, VerificationClass::Invariant);
        assert_eq!(ok.verdict, VerificationVerdict::Verified);
        assert!(
            ok.admits_write(),
            "a reconciled R1 certificate admits a write"
        );

        let bad = reconciliation_receipt(ReconcileVerdict::Violated);
        assert_eq!(bad.verdict, VerificationVerdict::Unverified);
        assert!(!bad.admits_write(), "a violated certificate never admits");

        let na = reconciliation_receipt(ReconcileVerdict::NotApplicable);
        assert_eq!(na.verdict, VerificationVerdict::NotApplicable);
        assert!(!na.admits_write(), "a malformed certificate never admits");

        // wrong-class fail-closed: a reconcile verdict fed to a Code task is a typed mismatch.
        let mismatch = verify(
            VerificationClass::Code,
            &VerificationEvidence::Reconciliation(ReconcileVerdict::Reconciled),
        );
        assert!(
            !mismatch.admits_write(),
            "Reconciliation evidence on a non-Invariant class never admits (fail-closed)"
        );
    }

    /// The ladder closes ACCUMULATE: an R1 reconciliation admit is INDEPENDENT
    /// of the write-time cross-memory check (R1 ⟂ R2 ⇒ different classes), so a reconciled
    /// pattern is DOUBLY VERIFIED — the strongest trust, not a vacuous self-compare.
    #[test]
    fn r1_reconciliation_is_independent_of_the_cross_memory_axis() {
        let r1 = reconciliation_receipt(ReconcileVerdict::Reconciled);
        let cm = verify(
            VerificationClass::CrossMemory,
            &VerificationEvidence::CrossMemory {
                contradicts_held_ltm: false,
            },
        );
        assert!(
            two_derivation_admits(&r1, &cm),
            "R1 (invariant) ⟂ R2 (cross-memory) = two independent passing derivations"
        );
        assert_ne!(
            r1.class.rung(),
            cm.class.rung(),
            "the two derivations sit on different rungs (independent axes)"
        );
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
