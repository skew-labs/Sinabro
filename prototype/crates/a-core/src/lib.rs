//! `mnemos-a-core` — core error taxonomy, async runtime supervisor, redacted logging and typed config.
//!
//! Phase 0 critical-path crate. Its modules are self-contained value
//! surfaces with fixed-width, `Copy`, allocation-free types; the crate
//! always keeps `cargo build --workspace` green.
//!
//! Modules:
//! - [`error`][]: fixed-width, heap-free, source-redacting error
//!   taxonomy. The raw cause is never retained, so a secret cannot leak through
//!   the error channel.
//! - [`runtime`][]: fixed-capacity, lock-free, allocation-free
//!   async task supervisor. Every state transition is a single atomic CAS;
//!   first-writer-wins on `finish` / `cancel` / `shutdown`; a stale lease is
//!   silently rejected; retry is forbidden at the type level once the task
//!   has crossed an external boundary with an unknown outcome.
//! - [`logging`][]: allowlist-only JSON logging surface. Every
//!   emitted line is a single JSON object whose keys are bounded by a static
//!   per-event allowlist; raw values are redacted to a class tag at the call
//!   site via the `const fn` [`logging::redact_for_log`], so a plaintext
//!   secret cannot enter a log line.
//! - [`config`][]: typed runtime configuration. The parser is
//!   the single boundary where text becomes a `Copy`, fixed-width
//!   [`config::RuntimeConfig`]; the token cap is enforced at parse time,
//!   unknown TOML fields and mainnet labels are rejected without any network
//!   call, and every failure folds through
//!   [`error::MnemosError::source_redacted`] so a raw config snippet (which
//!   might contain a canary) never enters `Debug`, `Display`, or `source()`.
#![deny(missing_docs)]

pub mod config;
pub mod error;
pub mod logging;
pub mod runtime;
pub mod stage_c_env;
pub mod stage_c_mainnet_config;
// Hosted/self/none sponsor-mode config. Self-contained, secret-free config
// that value-mirrors the `GasSponsorMode` discriminants (the authoritative
// enum lives in `g-wallet`, which `a-core` cannot depend on without a cycle).
// No live action.
pub mod stage_c_sponsor_mode;
pub mod trace;

#[doc(no_inline)]
pub use stage_c_env::{MainnetExecutionState, StageCChainEnv};
#[doc(no_inline)]
pub use stage_c_mainnet_config::{MainnetConfigError, SealedMainnetConfig};
#[doc(no_inline)]
pub use stage_c_sponsor_mode::{
    SponsorMode, SponsorModeConfig, SponsorModeConfigError, looks_like_secret,
};
#[doc(no_inline)]
pub use trace::{StageBTraceLink, StageCTraceLink, StageDTraceLink};

#[doc(no_inline)]
pub use error::{
    Actionability, BudgetAxis, CommitState, ErrorCode, ErrorOp, ErrorSeverity, ErrorSink,
    MnemosError, MnemosResult, RedactionClass, RetryDisposition, SafeErrorReport,
    StateRejectReason, ToolDenyReason, ToolProgram,
};

#[doc(no_inline)]
pub use logging::{
    LOG_SCHEMA_VERSION, LogInitStatus, LogRedactionKind, LogService, LogShutdownEvent,
    RedactedLogValue, emit_config_failure_log, emit_shutdown_log, emit_startup_log,
    init_json_logging, redact_for_log,
};

#[doc(no_inline)]
pub use runtime::{
    RuntimeAttempt, RuntimeBoundaryState, RuntimeCancelReason, RuntimeCancelResult,
    RuntimeDrainReport, RuntimeJoinOutcome, RuntimeRegisterError, RuntimeReleaseResult,
    RuntimeRetryPolicy, RuntimeShutdownRequestResult, RuntimeShutdownState, RuntimeSupervisor,
    RuntimeTaskId, RuntimeTaskKind, RuntimeTaskLease, RuntimeTaskReport, RuntimeTaskStatus,
    runtime_retry_allowed,
};

#[doc(no_inline)]
pub use config::{
    MAX_INPUT_TOKENS_PHASE0, MAX_PERSONA_BYTES_PHASE0, RuntimeAgentConfig, RuntimeCacheConfig,
    RuntimeCacheStrategy, RuntimeConfig, RuntimeEnv, RuntimeLlmBackend, RuntimeLlmConfig,
    RuntimeLogLevel, RuntimeObservabilityConfig, RuntimeSecurityConfig, RuntimeToolConfig,
    config_error_report, config_path_from_args, current_effective_uid_u32,
    load_runtime_config_from_path, validate_runtime_env,
};
