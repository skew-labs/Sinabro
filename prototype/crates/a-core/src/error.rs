//! Core error taxonomy for MNEMOS.
//!
//! # Design rationale
//!
//! An error here is a **fixed-width plain value**, not a boxed message. Every
//! piece of metadata is a `#[repr(u8)]`/`#[repr(u16)]` enum with an explicit
//! discriminant, so a [`MnemosError`] is `Copy`, allocates nothing, and carries
//! **no dynamically formatted text**. The only human-readable strings are
//! `&'static` class labels chosen at compile time.
//!
//! The security spine is *source redaction*: the raw detail behind a failure
//! (a provider body, a tool argument, a nested error's `Display`) is **never
//! stored**. It is accepted as a parameter purely for call-site ergonomics and
//! immediately dropped, so it can never reach [`core::fmt::Debug`],
//! [`core::fmt::Display`], or [`std::error::Error::source`] (which is always
//! `None`). This is the type-level guarantee that a canary secret cannot leak
//! through the error channel.

/// Crate-wide result alias: every fallible MNEMOS API returns this.
pub type MnemosResult<T> = core::result::Result<T, MnemosError>;

/// Stable wire/log code for an error class. `#[repr(u16)]` so the discriminant
/// is a fixed two-byte value suitable for logs, metrics, and cross-language
/// schema locks; `#[non_exhaustive]` so adding a class later is not a breaking
/// change for downstream matches.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
#[repr(u16)]
pub enum ErrorCode {
    /// A state/phase/ownership/lifetime/unit-width invariant rejected the call.
    StateRejected = 0xA201,
    /// A tool invocation was refused by policy before any external effect.
    ToolDenied = 0xA202,
    /// An underlying source failed and its raw detail was redacted.
    SourceRedacted = 0xA203,
    /// The operation would exceed a configured budget and was stopped.
    BudgetExceeded = 0xA204,
}

/// The MNEMOS subsystem that produced an error. Plain one-byte tag.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum ErrorOp {
    /// Process bootstrap / startup wiring.
    Bootstrap = 1,
    /// Memory chunk store / persistence.
    Memory = 2,
    /// Walrus codec / transport.
    Walrus = 3,
    /// Sui / Move on-chain calls.
    Sui = 4,
    /// Wallet keystore / signing.
    Wallet = 5,
    /// Skill manifest / builtins.
    Skill = 6,
    /// Tool dispatch.
    Tool = 7,
    /// Agent turn loop.
    Agent = 8,
    /// Configuration loading / validation.
    Config = 9,
}

/// Why a state-rejection invariant fired.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum StateRejectReason {
    /// A phase gate was not satisfied.
    PhaseGate = 1,
    /// The caller did not own the target.
    Ownership = 2,
    /// A lifetime / lifecycle invariant was violated.
    Lifetime = 3,
    /// A typed-unit width mismatch was detected.
    UnitWidth = 4,
}

/// The external program a denied tool call targeted. `Other=255` keeps the tag
/// fixed-width while leaving room for the open set.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum ToolProgram {
    /// `cargo`.
    Cargo = 1,
    /// `git`.
    Git = 2,
    /// `sui`.
    Sui = 3,
    /// `walrus`.
    Walrus = 4,
    /// Any other / unclassified program.
    Other = 255,
}

/// Why a tool invocation was denied.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum ToolDenyReason {
    /// The program itself is not on the allowlist.
    Program = 1,
    /// The argument shape failed validation.
    ArgumentShape = 2,
    /// The call would touch a banned surface (mainnet, real secrets, …).
    BannedSurface = 3,
    /// The call requires explicit operator approval first.
    ApprovalRequired = 4,
}

/// Which budget axis was exhausted.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum BudgetAxis {
    /// CPU cycles.
    Cycles = 1,
    /// Heap allocations.
    Allocations = 2,
    /// Binary size in bytes.
    BinaryBytes = 3,
    /// LLM tokens.
    LlmTokens = 4,
    /// Sui gas.
    SuiGas = 5,
    /// Walrus bytes.
    WalrusBytes = 6,
}

/// Whether (and how) a failed operation may be retried.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum RetryDisposition {
    /// Never retry automatically.
    Never = 1,
    /// Retry only after an operator takes a corrective action.
    AfterOperatorAction = 2,
    /// Retry only if the operation is known to be idempotent.
    IdempotentOnly = 3,
    /// Retry only via an explicit manual step.
    ManualOnly = 4,
}

/// What is known about external mutation at the moment of failure. The
/// `UnknownAfterBoundary` state is the one that blocks blind retries.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum CommitState {
    /// The operation had not started any external effect.
    NotStarted = 1,
    /// The operation ran but produced no external mutation.
    NoExternalMutation = 2,
    /// Request bytes may have crossed an external boundary; effect is unknown.
    UnknownAfterBoundary = 3,
}

/// Severity ladder for routing and alerting.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum ErrorSeverity {
    /// Informational.
    Info = 1,
    /// A warning that does not stop the turn.
    Warn = 2,
    /// An error that stops the current operation.
    Error = 3,
    /// A fatal condition.
    Fatal = 4,
}

/// How safe the error projection is to expose to a given audience.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum RedactionClass {
    /// Safe for any audience.
    PublicSafe = 1,
    /// Safe for internal operators only.
    InternalSafe = 2,
    /// The underlying detail was secret-like and has been redacted.
    SecretLikeRedacted = 3,
}

/// The kind of follow-up action an error invites.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum Actionability {
    /// Fix the offending state.
    FixState = 1,
    /// Fix the policy / configuration.
    FixPolicy = 2,
    /// Inspect the audit trail.
    InspectAudit = 3,
    /// Reduce budget usage.
    ReduceBudgetUse = 4,
}

/// The audience a [`SafeErrorReport`] is being projected for.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum ErrorSink {
    /// End user.
    User = 1,
    /// Telegram gateway.
    Telegram = 2,
    /// LLM context.
    Llm = 3,
    /// Audit log.
    Audit = 4,
}

/// Opaque, private error payload. It stores **only plain scalar metadata** —
/// never a raw message, body, or nested error — so the derived
/// [`core::fmt::Debug`]/[`PartialEq`] impls cannot leak a secret. Keeping it
/// private makes the variant set an implementation detail that callers reach
/// only through the safe projection accessors.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ErrorKind {
    StateRejected {
        op: ErrorOp,
        reason: StateRejectReason,
    },
    ToolDenied {
        program: ToolProgram,
        arg_count_u16: u16,
        reason: ToolDenyReason,
        request_id_u64: u64,
    },
    SourceRedacted {
        op: ErrorOp,
    },
    BudgetExceeded {
        axis: BudgetAxis,
        observed_u64: u64,
        limit_u64: u64,
    },
}

/// A MNEMOS error: a `Copy`, heap-free, fixed-width value whose raw cause is
/// never retained. Construct it with the typed constructors and read its safe
/// metadata through the const accessors / [`MnemosError::safe_report`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MnemosError {
    kind: ErrorKind,
}

/// A fully-projected, audience-tagged view of an error. Every field is a fixed
/// scalar except `message`, which is a `&'static` class label — there is no
/// dynamic formatting and nothing that can hold a leaked secret.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SafeErrorReport {
    /// Audience this report was projected for.
    pub sink: ErrorSink,
    /// Stable error class code.
    pub code: ErrorCode,
    /// Whether/how the operation may be retried.
    pub retry: RetryDisposition,
    /// External-mutation knowledge at failure time.
    pub commit_state: CommitState,
    /// Severity for routing/alerting.
    pub severity: ErrorSeverity,
    /// Redaction class of the projection.
    pub redaction: RedactionClass,
    /// Suggested follow-up action.
    pub actionability: Actionability,
    /// Static, bounded, secret-free class label.
    pub message: &'static str,
}

/// Internal, fully-resolved projection of an [`ErrorKind`] to its safe
/// metadata. Computed once by [`MnemosError::projection`]; every public
/// accessor reads a single field of it so the mapping is total and deterministic
/// in exactly one place.
#[derive(Clone, Copy)]
struct ErrorProjection {
    code: ErrorCode,
    retry: RetryDisposition,
    commit_state: CommitState,
    severity: ErrorSeverity,
    redaction: RedactionClass,
    actionability: Actionability,
    message: &'static str,
}

impl MnemosError {
    /// A state/phase/ownership/lifetime/unit-width invariant rejected the call.
    pub const fn state_rejected(op: ErrorOp, reason: StateRejectReason) -> Self {
        Self {
            kind: ErrorKind::StateRejected { op, reason },
        }
    }

    /// A tool invocation was denied by policy. Only the program, an argument
    /// *count*, the reason, and a request id are retained — never the raw
    /// arguments or command line.
    pub const fn tool_denied(
        program: ToolProgram,
        arg_count_u16: u16,
        reason: ToolDenyReason,
        request_id_u64: u64,
    ) -> Self {
        Self {
            kind: ErrorKind::ToolDenied {
                program,
                arg_count_u16,
                reason,
                request_id_u64,
            },
        }
    }

    /// An underlying failure occurred; `_raw_detail` is accepted for call-site
    /// ergonomics and **immediately discarded** (it never reaches a field), so
    /// it cannot enter `Debug`/`Display`/`source`. Canary-0 by construction.
    pub const fn source_redacted(op: ErrorOp, _raw_detail: &str) -> Self {
        Self {
            kind: ErrorKind::SourceRedacted { op },
        }
    }

    /// Same as [`MnemosError::source_redacted`] but for a nested error object:
    /// `_source` is read for nothing and dropped, so its `Display`/`source`
    /// chain (which may contain secrets) is never absorbed.
    pub fn source_redacted_from_error(op: ErrorOp, _source: &(dyn std::error::Error + '_)) -> Self {
        Self {
            kind: ErrorKind::SourceRedacted { op },
        }
    }

    /// The operation would exceed a configured budget on `axis`. The observed
    /// and limit values are inline `u64`s, so extreme magnitudes never change
    /// the value's size.
    pub const fn budget_exceeded(axis: BudgetAxis, observed_u64: u64, limit_u64: u64) -> Self {
        Self {
            kind: ErrorKind::BudgetExceeded {
                axis,
                observed_u64,
                limit_u64,
            },
        }
    }

    /// The single, total projection from kind to safe metadata.
    const fn projection(&self) -> ErrorProjection {
        match self.kind {
            ErrorKind::StateRejected { .. } => ErrorProjection {
                code: ErrorCode::StateRejected,
                retry: RetryDisposition::Never,
                commit_state: CommitState::NotStarted,
                severity: ErrorSeverity::Error,
                redaction: RedactionClass::PublicSafe,
                actionability: Actionability::FixState,
                message: "state rejected by phase/ownership/lifetime/unit-width gate",
            },
            ErrorKind::ToolDenied { .. } => ErrorProjection {
                code: ErrorCode::ToolDenied,
                retry: RetryDisposition::Never,
                commit_state: CommitState::NotStarted,
                severity: ErrorSeverity::Warn,
                redaction: RedactionClass::InternalSafe,
                actionability: Actionability::FixPolicy,
                message: "tool invocation denied by policy",
            },
            ErrorKind::SourceRedacted { .. } => ErrorProjection {
                code: ErrorCode::SourceRedacted,
                retry: RetryDisposition::AfterOperatorAction,
                commit_state: CommitState::UnknownAfterBoundary,
                severity: ErrorSeverity::Error,
                redaction: RedactionClass::SecretLikeRedacted,
                actionability: Actionability::InspectAudit,
                message: "underlying source failed and was redacted; see audit",
            },
            ErrorKind::BudgetExceeded { .. } => ErrorProjection {
                code: ErrorCode::BudgetExceeded,
                retry: RetryDisposition::Never,
                commit_state: CommitState::NoExternalMutation,
                severity: ErrorSeverity::Warn,
                redaction: RedactionClass::PublicSafe,
                actionability: Actionability::ReduceBudgetUse,
                message: "operation would exceed configured budget",
            },
        }
    }

    /// Stable error class code.
    pub const fn code(&self) -> ErrorCode {
        self.projection().code
    }

    /// Whether/how the operation may be retried.
    pub const fn retry(&self) -> RetryDisposition {
        self.projection().retry
    }

    /// External-mutation knowledge at failure time.
    pub const fn commit_state(&self) -> CommitState {
        self.projection().commit_state
    }

    /// Severity for routing/alerting.
    pub const fn severity(&self) -> ErrorSeverity {
        self.projection().severity
    }

    /// Redaction class of the projection.
    pub const fn redaction(&self) -> RedactionClass {
        self.projection().redaction
    }

    /// Suggested follow-up action.
    pub const fn actionability(&self) -> Actionability {
        self.projection().actionability
    }

    /// Project this error into an audience-tagged [`SafeErrorReport`]. The
    /// message is `&'static`; nothing in the report can carry a leaked secret.
    pub const fn safe_report(&self, sink: ErrorSink) -> SafeErrorReport {
        let p = self.projection();
        SafeErrorReport {
            sink,
            code: p.code,
            retry: p.retry,
            commit_state: p.commit_state,
            severity: p.severity,
            redaction: p.redaction,
            actionability: p.actionability,
            message: p.message,
        }
    }
}

impl core::fmt::Display for MnemosError {
    /// Writes only the `&'static` class label — never any raw detail.
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(self.projection().message)
    }
}

impl std::error::Error for MnemosError {
    /// Always `None`: the raw source is never retained, so the error chain
    /// terminates here and cannot leak a nested cause.
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A recognizable secret used to prove it never reaches any projection.
    const CANARY: &str = "CANARY-SECRET-7f3a9b-do-not-leak";

    /// A nested source error that *deliberately* leaks the canary through its
    /// own `Display`, so the test proves [`MnemosError`] refuses to absorb it.
    #[derive(Debug)]
    struct NestedCanaryError;

    impl core::fmt::Display for NestedCanaryError {
        fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
            write!(f, "nested failure containing {CANARY}")
        }
    }

    impl std::error::Error for NestedCanaryError {}

    fn has_canary(s: &str) -> bool {
        s.contains(CANARY)
    }

    #[test]
    fn source_redaction_discards_raw_canaries() {
        let err = MnemosError::source_redacted(ErrorOp::Walrus, CANARY);
        assert!(!has_canary(&format!("{err:?}")));
        assert!(!has_canary(&format!("{err}")));
        assert!(!has_canary(err.safe_report(ErrorSink::Audit).message));
        assert!(std::error::Error::source(&err).is_none());
        assert_eq!(err.code(), ErrorCode::SourceRedacted);
    }

    #[test]
    fn source_redaction_discards_nested_source_object() {
        let nested = NestedCanaryError;
        // Precondition: the source object really does hold the canary.
        assert!(has_canary(&format!("{nested}")));
        let err = MnemosError::source_redacted_from_error(ErrorOp::Sui, &nested);
        assert!(!has_canary(&format!("{err:?}")));
        assert!(!has_canary(&format!("{err}")));
        assert!(std::error::Error::source(&err).is_none());
        assert_eq!(err.code(), ErrorCode::SourceRedacted);
    }

    #[test]
    fn command_denial_exposes_only_safe_metadata() {
        let err = MnemosError::tool_denied(ToolProgram::Sui, 3, ToolDenyReason::BannedSurface, 42);
        let rep = err.safe_report(ErrorSink::User);
        assert_eq!(rep.code, ErrorCode::ToolDenied);
        assert_eq!(rep.redaction, RedactionClass::InternalSafe);
        assert_eq!(rep.actionability, Actionability::FixPolicy);
        // Debug exposes only plain safe scalars, never a raw command string.
        let dbg = format!("{err:?}");
        assert!(dbg.contains("ToolDenied"));
        assert!(!has_canary(&dbg));
    }

    #[test]
    fn metadata_matrix_is_stable() {
        let cases = [
            MnemosError::state_rejected(ErrorOp::Memory, StateRejectReason::Ownership),
            MnemosError::tool_denied(ToolProgram::Cargo, 1, ToolDenyReason::Program, 1),
            MnemosError::source_redacted(ErrorOp::Config, "x"),
            MnemosError::budget_exceeded(BudgetAxis::LlmTokens, 6_000, 5_000),
        ];
        let expect = [
            (
                ErrorCode::StateRejected,
                RetryDisposition::Never,
                CommitState::NotStarted,
                ErrorSeverity::Error,
                RedactionClass::PublicSafe,
                Actionability::FixState,
            ),
            (
                ErrorCode::ToolDenied,
                RetryDisposition::Never,
                CommitState::NotStarted,
                ErrorSeverity::Warn,
                RedactionClass::InternalSafe,
                Actionability::FixPolicy,
            ),
            (
                ErrorCode::SourceRedacted,
                RetryDisposition::AfterOperatorAction,
                CommitState::UnknownAfterBoundary,
                ErrorSeverity::Error,
                RedactionClass::SecretLikeRedacted,
                Actionability::InspectAudit,
            ),
            (
                ErrorCode::BudgetExceeded,
                RetryDisposition::Never,
                CommitState::NoExternalMutation,
                ErrorSeverity::Warn,
                RedactionClass::PublicSafe,
                Actionability::ReduceBudgetUse,
            ),
        ];
        for (err, exp) in cases.iter().zip(expect.iter()) {
            assert_eq!(err.code(), exp.0);
            assert_eq!(err.retry(), exp.1);
            assert_eq!(err.commit_state(), exp.2);
            assert_eq!(err.severity(), exp.3);
            assert_eq!(err.redaction(), exp.4);
            assert_eq!(err.actionability(), exp.5);
            // Determinism: re-reading the projection yields the same code.
            let first = err.code();
            assert_eq!(first, err.code());
        }
    }

    #[test]
    fn safe_reports_are_bounded_static_messages() {
        const MAX_MSG: usize = 80;
        let kinds = [
            MnemosError::state_rejected(ErrorOp::Bootstrap, StateRejectReason::PhaseGate),
            MnemosError::tool_denied(ToolProgram::Walrus, 0, ToolDenyReason::ApprovalRequired, 0),
            MnemosError::source_redacted(ErrorOp::Wallet, ""),
            MnemosError::budget_exceeded(BudgetAxis::SuiGas, u64::MAX, 0),
        ];
        let sinks = [
            ErrorSink::User,
            ErrorSink::Telegram,
            ErrorSink::Llm,
            ErrorSink::Audit,
        ];
        for err in kinds.iter() {
            for sink in sinks.iter() {
                let rep = err.safe_report(*sink);
                assert!(rep.message.len() <= MAX_MSG);
                assert_eq!(rep.sink, *sink);
            }
        }
    }

    #[test]
    fn boundary_values_do_not_change_projection_size() {
        let small = MnemosError::budget_exceeded(BudgetAxis::Cycles, 1, 2);
        let huge = MnemosError::budget_exceeded(BudgetAxis::Cycles, u64::MAX, u64::MAX);
        let denied_small =
            MnemosError::tool_denied(ToolProgram::Other, 0, ToolDenyReason::ArgumentShape, 0);
        let denied_huge = MnemosError::tool_denied(
            ToolProgram::Other,
            u16::MAX,
            ToolDenyReason::ArgumentShape,
            u64::MAX,
        );
        // Size is a type-level property: extreme inputs cannot grow the value.
        assert_eq!(
            core::mem::size_of_val(&small),
            core::mem::size_of_val(&huge)
        );
        assert_eq!(
            core::mem::size_of_val(&denied_small),
            core::mem::size_of_val(&denied_huge)
        );
        // And the safe projection is identical regardless of magnitude.
        assert_eq!(
            small.safe_report(ErrorSink::Audit),
            huge.safe_report(ErrorSink::Audit)
        );
        assert_eq!(
            denied_small.safe_report(ErrorSink::User),
            denied_huge.safe_report(ErrorSink::User)
        );
    }

    #[test]
    fn layout_stays_bounded_and_plain() {
        // Fixed-width plain values: small, bounded, Copy, heap-free. The sizes
        // are pinned exactly (measured on this target) so any future layout
        // drift is caught by this test rather than a loose bound.
        assert_eq!(core::mem::size_of::<MnemosError>(), 24);
        assert_eq!(core::mem::size_of::<SafeErrorReport>(), 24);
        fn assert_copy<T: Copy>() {}
        assert_copy::<MnemosError>();
        assert_copy::<SafeErrorReport>();
        assert_copy::<ErrorCode>();
        // repr widths are explicit and minimal.
        assert_eq!(core::mem::size_of::<ErrorOp>(), 1);
        assert_eq!(core::mem::size_of::<ErrorCode>(), 2);
    }
}
