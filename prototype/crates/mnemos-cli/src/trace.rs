//! All-command trace sidecar writer (atom #473 · F.8.6).
//!
//! Every executed command emits a canonical
//! [`crate::command::CommandTraceRecord`]. This module decides, per the user's
//! [`LearningMode`], *which* artifacts that record materializes and renders a
//! **redacted, hash-only** trace line for the local buffered sidecar — never a
//! raw output byte.
//!
//! - Implementation mode (our own build) always writes a trace + training
//!   sidecar; that policy lives in the build harness, not here.
//! - Released product mode obeys the user's learning mode: [`LearningMode::Off`]
//!   writes only the mandatory high-risk audit line; [`LearningMode::EvidenceOnly`]
//!   adds a local evidence artifact; [`LearningMode::LocalDiet`] /
//!   [`LearningMode::PrivateAdapter`] / [`LearningMode::ContributeRedacted`]
//!   progressively enable diet artifacts. Skipped / no-op decisions are
//!   first-class ([`TraceClassKind::NoOp`]).
//! - Self-evolution candidate manifests are display / read-only in Stage F and
//!   **cannot be applied**: [`TraceWriter::try_apply_self_evolution`] returns
//!   `Result<Infallible, _>`, so the success path is uninhabited by construction.
//!
//! Reuse (no reinvention): the record is the canonical
//! [`crate::command::CommandTraceRecord`]; the learning policy is the canonical
//! [`crate::config::LearningMode`]; the hashes use [`crate::hex32`] /
//! [`crate::sha256_32`]. This module performs no live action.

use crate::command::{CommandRisk, CommandTraceRecord};
use crate::config::LearningMode;
use crate::hex32;

/// The execution class of a traced command (atom #473 test list).
#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TraceClassKind {
    /// A pure read; no mutation.
    ReadOnly = 1,
    /// A command that performed a side effect.
    SideEffect = 2,
    /// A command that decided to do nothing (skipped / no-op) — first-class.
    NoOp = 3,
    /// A command that failed.
    Failure = 4,
}

impl TraceClassKind {
    /// The stable `u8` discriminant.
    #[must_use]
    pub const fn as_u8(self) -> u8 {
        self as u8
    }
}

/// What the trace writer will materialize for a record under the active mode.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TraceWriteDecision {
    /// The mandatory high-risk audit line is always written (true for a high-risk
    /// command or a failure, even when learning is off).
    pub mandatory_audit: bool,
    /// A local evidence artifact is written (mode >= `EvidenceOnly`).
    pub local_evidence: bool,
    /// A local diet artifact is written (mode >= `LocalDiet`).
    pub local_diet: bool,
    /// A redacted contribution review packet is staged (mode == `ContributeRedacted`).
    pub contribution_review: bool,
}

/// Why a trace write was refused (fail-closed).
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum TraceReject {
    /// A command with no classified [`CommandTraceRecord`] cannot be traced.
    #[error("untraced command: no command trace record")]
    Untraced,
    /// Applying a self-evolution candidate is forbidden in Stage F (no apply path
    /// exists; manifests are display / read-only).
    #[error("self-evolution apply is forbidden in stage F")]
    SelfEvolutionApplyForbidden,
}

/// The trace writer bound to the active learning mode.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TraceWriter {
    mode: LearningMode,
}

impl TraceWriter {
    /// A writer for the given learning mode.
    #[must_use]
    pub const fn new(mode: LearningMode) -> Self {
        Self { mode }
    }

    /// The active learning mode.
    #[must_use]
    pub const fn mode(&self) -> LearningMode {
        self.mode
    }

    /// Whether a record is high-risk (wallet signing / chain write / admin /
    /// training) — these always get the mandatory audit line regardless of the
    /// learning mode.
    #[must_use]
    pub const fn is_high_risk(record: &CommandTraceRecord) -> bool {
        matches!(
            record.envelope.risk,
            CommandRisk::WalletSign
                | CommandRisk::ChainWrite
                | CommandRisk::Admin
                | CommandRisk::Training
        )
    }

    /// Decide which artifacts a record produces under the active mode + class.
    #[must_use]
    pub const fn decide(
        &self,
        record: &CommandTraceRecord,
        class: TraceClassKind,
    ) -> TraceWriteDecision {
        let mandatory_audit =
            Self::is_high_risk(record) || matches!(class, TraceClassKind::Failure);
        let mode_u8 = self.mode as u8;
        TraceWriteDecision {
            mandatory_audit,
            local_evidence: mode_u8 >= LearningMode::EvidenceOnly as u8,
            local_diet: mode_u8 >= LearningMode::LocalDiet as u8,
            contribution_review: matches!(self.mode, LearningMode::ContributeRedacted),
        }
    }

    /// Render the redacted, hash-only trace line for the local buffered sidecar.
    /// Pure + allocation-bounded (p95 <= 5ms): it embeds only the envelope risk,
    /// the exit code, the class, the verb hash, and the redacted output hash —
    /// never a raw output byte.
    #[must_use]
    pub fn trace_line(&self, record: &CommandTraceRecord, class: TraceClassKind) -> String {
        let d = self.decide(record, class);
        format!(
            "trace risk={} exit={} class={} verb_hash={} out_hash={} mand={} ev={} diet={} contrib={}",
            record.envelope.risk as u8,
            record.exit_code_i32,
            class.as_u8(),
            hex32(&record.envelope.id.verb_hash_32),
            hex32(&record.redacted_output_hash_32),
            d.mandatory_audit,
            d.local_evidence,
            d.local_diet,
            d.contribution_review,
        )
    }

    /// Trace an optional record: `Some` writes the line; `None` is an untraced
    /// command and is refused (fail-closed) — every command must be classified
    /// into a [`CommandTraceRecord`] before it can be traced.
    pub fn try_trace(
        &self,
        record: Option<&CommandTraceRecord>,
        class: TraceClassKind,
    ) -> Result<String, TraceReject> {
        match record {
            Some(r) => Ok(self.trace_line(r, class)),
            None => Err(TraceReject::Untraced),
        }
    }

    /// Stage F self-evolution lock. There is no apply path: the success type is
    /// [`core::convert::Infallible`], so this can only ever return the
    /// [`TraceReject::SelfEvolutionApplyForbidden`] error. Self-evolution
    /// candidate manifests stay display / read-only.
    pub fn try_apply_self_evolution(&self) -> Result<core::convert::Infallible, TraceReject> {
        Err(TraceReject::SelfEvolutionApplyForbidden)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::command::{CliMode, CommandEnvelope};
    use crate::grammar::CliNamespace;
    use crate::repl::latency::p95_ms;
    use crate::{StageFEvidenceRef, StageFTraceLink};

    fn record(risk: CommandRisk) -> CommandTraceRecord {
        let envelope =
            CommandEnvelope::classify(CliNamespace::Trace, "list", CliMode::Run, risk, b"");
        let trace = StageFTraceLink::new([1u8; 32], 473, 200);
        let evidence = StageFEvidenceRef {
            path_hash_32: [2u8; 32],
            trace,
        };
        CommandTraceRecord {
            envelope,
            exit_code_i32: 0,
            evidence,
            redacted_output_hash_32: [3u8; 32],
        }
    }

    #[test]
    fn read_only_side_effect_no_op_and_failure_all_trace() {
        let w = TraceWriter::new(LearningMode::Off);
        let r = record(CommandRisk::ReadOnly);
        for class in [
            TraceClassKind::ReadOnly,
            TraceClassKind::SideEffect,
            TraceClassKind::NoOp,
            TraceClassKind::Failure,
        ] {
            let line = w.trace_line(&r, class);
            assert!(line.starts_with("trace risk="));
            assert!(line.contains(&format!("class={}", class.as_u8())));
        }
    }

    #[test]
    fn untraced_command_is_denied() {
        let w = TraceWriter::new(LearningMode::Off);
        assert_eq!(
            w.try_trace(None, TraceClassKind::ReadOnly),
            Err(TraceReject::Untraced)
        );
        // A classified record traces fine.
        let r = record(CommandRisk::ReadOnly);
        assert!(w.try_trace(Some(&r), TraceClassKind::ReadOnly).is_ok());
    }

    #[test]
    fn learning_off_writes_only_mandatory_audit() {
        let w = TraceWriter::new(LearningMode::Off);
        // High-risk command -> mandatory audit even with learning off, but no
        // evidence / diet / contribution artifacts.
        let d = w.decide(&record(CommandRisk::ChainWrite), TraceClassKind::SideEffect);
        assert!(d.mandatory_audit);
        assert!(!d.local_evidence);
        assert!(!d.local_diet);
        assert!(!d.contribution_review);
        // A low-risk read with learning off writes no mandatory audit either.
        let d2 = w.decide(&record(CommandRisk::ReadOnly), TraceClassKind::ReadOnly);
        assert!(!d2.mandatory_audit);
    }

    #[test]
    fn failure_class_forces_mandatory_audit_even_low_risk() {
        let w = TraceWriter::new(LearningMode::Off);
        let d = w.decide(&record(CommandRisk::ReadOnly), TraceClassKind::Failure);
        assert!(d.mandatory_audit);
    }

    #[test]
    fn evidence_only_enables_evidence_not_diet() {
        let w = TraceWriter::new(LearningMode::EvidenceOnly);
        let d = w.decide(&record(CommandRisk::ReadOnly), TraceClassKind::ReadOnly);
        assert!(d.local_evidence);
        assert!(!d.local_diet);
        assert!(!d.contribution_review);
    }

    #[test]
    fn local_diet_enables_diet_artifacts() {
        let w = TraceWriter::new(LearningMode::LocalDiet);
        let d = w.decide(&record(CommandRisk::ReadOnly), TraceClassKind::ReadOnly);
        assert!(d.local_evidence);
        assert!(d.local_diet);
        assert!(!d.contribution_review);
    }

    #[test]
    fn contribution_review_only_in_contribute_redacted() {
        let w = TraceWriter::new(LearningMode::ContributeRedacted);
        let d = w.decide(&record(CommandRisk::ReadOnly), TraceClassKind::ReadOnly);
        assert!(d.contribution_review);
        assert!(d.local_diet);
    }

    #[test]
    fn self_evolution_apply_command_is_absent() {
        let w = TraceWriter::new(LearningMode::LocalDiet);
        // The success type is uninhabited: this can only ever be the deny error.
        assert!(matches!(
            w.try_apply_self_evolution(),
            Err(TraceReject::SelfEvolutionApplyForbidden)
        ));
    }

    #[test]
    fn trace_line_carries_no_raw_output_only_hashes() {
        let w = TraceWriter::new(LearningMode::Off);
        let r = record(CommandRisk::WalletSign);
        let line = w.trace_line(&r, TraceClassKind::SideEffect);
        // Hash fields are 64-hex; the raw output never appears (we only hold a hash).
        assert!(line.contains("out_hash="));
        assert!(line.contains(&hex32(&[3u8; 32])));
    }

    #[test]
    fn trace_line_p95_within_5ms() {
        let w = TraceWriter::new(LearningMode::Off);
        let r = record(CommandRisk::ChainWrite);
        let mut samples = Vec::with_capacity(256);
        for _ in 0..256 {
            let t = std::time::Instant::now();
            let line = w.trace_line(&r, TraceClassKind::SideEffect);
            std::hint::black_box(&line);
            samples.push(t.elapsed().as_nanos() as u64);
        }
        let p95 = p95_ms(&samples) / 1_000_000;
        assert!(p95 <= 5, "trace write p95 {p95}ms exceeds 5ms");
    }
}
