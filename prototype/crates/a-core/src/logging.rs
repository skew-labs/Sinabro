//! `A.logging` — Phase 0 structured, allowlist-only JSON logging surface.
//!
//! Wire shape: every line emitted by `emit_*_log` is a single JSON object on
//! one line; only the keys listed in the per-event allowlist ever appear in
//! the line. There is no `timestamp`/`level`/`target`/`thread` envelope —
//! the line *is* the record. Numeric fields are fixed-width scalars; string
//! fields are static, secret-free class labels (no external string
//! concatenation reaches the line).
//!
//! Canary policy: raw values that may hold secrets are routed through
//! [`redact_for_log`], a `const fn` that drops the raw input at the call
//! site and retains only a [`LogRedactionKind`] tag. The unit tests below
//! prove for every variant that the raw value never appears in any
//! `Display`, `Debug`, or hand-built JSON projection of the resulting
//! [`RedactedLogValue`].
//!
//! Reuse: `emit_config_failure_log` consumes the atom #2
//! [`SafeErrorReport`] projection so the line can never carry a leaked
//! cause. `emit_shutdown_log` takes the scalar fields of an atom #3
//! `RuntimeDrainReport` directly (no struct dependency), keeping
//! `a-core::logging` decoupled from `a-core::runtime` at the type level.

use core::fmt;
use core::fmt::Write as _;
use std::io::Write as _;

use crate::error::SafeErrorReport;

/// Stable wire-schema version stamped on every emitted line.
pub const LOG_SCHEMA_VERSION: &str = "mnemos.log.v0";

/// Status returned by [`init_json_logging`]. Calling more than once is
/// non-fatal — the second call returns [`Self::AlreadyInitialized`] instead
/// of panicking, so binaries can be safely re-initialized in tests.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum LogInitStatus {
    /// A JSON tracing subscriber was installed by this call.
    Installed = 1,
    /// A subscriber was already installed by an earlier call in the process.
    AlreadyInitialized = 2,
}

/// Which Phase 0 binary emitted the line.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum LogService {
    /// `mnemos-agent` (the long-running daemon).
    Agent = 1,
    /// `mnemos-cli` (the user-facing cockpit / REPL).
    Cli = 2,
}

/// A discrete step of the shutdown sequence.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum LogShutdownEvent {
    /// Termination signal received; supervisor was asked to stop.
    Requested = 1,
    /// Drain has started; in-flight tasks are settling.
    DrainStarted = 2,
    /// Drain deadline elapsed; some tasks remained active.
    DrainTimeout = 3,
    /// Drain completed cleanly within the deadline.
    Completed = 4,
}

/// The class of raw value being redacted before any log line can absorb it.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum LogRedactionKind {
    /// A wallet passphrase / mnemonic.
    WalletPassphrase = 1,
    /// A Sui private key.
    SuiPrivateKey = 2,
    /// Raw Sui transaction bytes (may contain plaintext arguments).
    SuiTxBytes = 3,
    /// Raw Walrus blob bytes.
    WalrusBytes = 4,
    /// Raw tool I/O bytes.
    ToolIo = 5,
    /// A user prompt body.
    Prompt = 6,
    /// An LLM provider request or response body.
    ProviderBody = 7,
    /// A source-chain identifier, signature, or proof bytes.
    SourceChain = 8,
    /// An external API token / session cookie.
    ApiToken = 9,
}

impl LogRedactionKind {
    /// A stable, secret-free class label suitable for log output. The label
    /// is `&'static` and is the only textual projection of the kind that
    /// ever reaches a log line.
    pub const fn class_label(self) -> &'static str {
        match self {
            Self::WalletPassphrase => "wallet_passphrase",
            Self::SuiPrivateKey => "sui_private_key",
            Self::SuiTxBytes => "sui_tx_bytes",
            Self::WalrusBytes => "walrus_bytes",
            Self::ToolIo => "tool_io",
            Self::Prompt => "prompt",
            Self::ProviderBody => "provider_body",
            Self::SourceChain => "source_chain",
            Self::ApiToken => "api_token",
        }
    }
}

/// A redacted view of a raw value. By construction the raw bytes are dropped
/// at the [`redact_for_log`] call site; only the [`LogRedactionKind`] tag is
/// retained. Both `Display` and `Debug` projections therefore expose only
/// the class label, never the raw value.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct RedactedLogValue {
    kind: LogRedactionKind,
}

impl RedactedLogValue {
    /// The class tag of the underlying redacted value.
    pub const fn kind(self) -> LogRedactionKind {
        self.kind
    }
}

impl fmt::Display for RedactedLogValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "<redacted:{}>", self.kind.class_label())
    }
}

impl fmt::Debug for RedactedLogValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Debug also exposes ONLY the class — never absorbs a raw value.
        f.debug_struct("RedactedLogValue")
            .field("class", &self.kind.class_label())
            .finish()
    }
}

/// Compile-time-enforced redaction: `_raw_value` is read for nothing and
/// dropped immediately; only the [`LogRedactionKind`] tag is retained. The
/// resulting [`RedactedLogValue`] therefore cannot carry the raw bytes
/// across any subsequent boundary.
pub const fn redact_for_log(_raw_value: &str, kind: LogRedactionKind) -> RedactedLogValue {
    RedactedLogValue { kind }
}

// ---------------------------------------------------------------------------
// JSON line builders (manual, allowlist-only).
// ---------------------------------------------------------------------------

const fn service_label(s: LogService) -> &'static str {
    match s {
        LogService::Agent => "agent",
        LogService::Cli => "cli",
    }
}

const fn shutdown_event_label(e: LogShutdownEvent) -> &'static str {
    match e {
        LogShutdownEvent::Requested => "requested",
        LogShutdownEvent::DrainStarted => "drain_started",
        LogShutdownEvent::DrainTimeout => "drain_timeout",
        LogShutdownEvent::Completed => "completed",
    }
}

fn build_startup_line(service: LogService) -> String {
    let mut s = String::with_capacity(96);
    let _ = write!(
        s,
        "{{\"event\":\"startup\",\"schema\":\"{schema}\",\"service\":\"{service_label}\",\"service_u8\":{service_u8}}}",
        schema = LOG_SCHEMA_VERSION,
        service_label = service_label(service),
        service_u8 = service as u8,
    );
    s
}

fn build_config_failure_line(service: LogService, report: SafeErrorReport) -> String {
    let mut s = String::with_capacity(256);
    let _ = write!(
        s,
        "{{\"event\":\"config_failure\",\"schema\":\"{schema}\",\"service\":\"{service_label}\",\"service_u8\":{service_u8},\"sink_u8\":{sink_u8},\"code_u16\":{code_u16},\"retry_u8\":{retry_u8},\"commit_state_u8\":{commit_state_u8},\"severity_u8\":{severity_u8},\"redaction_u8\":{redaction_u8},\"actionability_u8\":{actionability_u8},\"message\":\"{message}\"}}",
        schema = LOG_SCHEMA_VERSION,
        service_label = service_label(service),
        service_u8 = service as u8,
        sink_u8 = report.sink as u8,
        code_u16 = report.code as u16,
        retry_u8 = report.retry as u8,
        commit_state_u8 = report.commit_state as u8,
        severity_u8 = report.severity as u8,
        redaction_u8 = report.redaction as u8,
        actionability_u8 = report.actionability as u8,
        message = report.message,
    );
    s
}

fn build_shutdown_line(
    service: LogService,
    event: LogShutdownEvent,
    timeout_ms_u32: u32,
    elapsed_ms_u32: u32,
    active_count_u16: u16,
    timed_out_count_u16: u16,
    unknown_after_boundary_count_u16: u16,
) -> String {
    let mut s = String::with_capacity(320);
    let _ = write!(
        s,
        "{{\"event\":\"shutdown\",\"schema\":\"{schema}\",\"service\":\"{service_label}\",\"service_u8\":{service_u8},\"shutdown_event\":\"{shutdown_event_label}\",\"shutdown_event_u8\":{shutdown_event_u8},\"timeout_ms_u32\":{timeout_ms_u32},\"elapsed_ms_u32\":{elapsed_ms_u32},\"active_count_u16\":{active_count_u16},\"timed_out_count_u16\":{timed_out_count_u16},\"unknown_after_boundary_count_u16\":{unknown_after_boundary_count_u16}}}",
        schema = LOG_SCHEMA_VERSION,
        service_label = service_label(service),
        service_u8 = service as u8,
        shutdown_event_label = shutdown_event_label(event),
        shutdown_event_u8 = event as u8,
    );
    s
}

fn write_line_to_stderr(line: &str) {
    let stderr = std::io::stderr();
    let mut h = stderr.lock();
    // Best effort: a logging-write failure must not crash the process or
    // panic; we discard the Result and return silently if stderr cannot be
    // written. Observability is non-essential for correctness here.
    let _ = h.write_all(line.as_bytes());
    let _ = h.write_all(b"\n");
}

// ---------------------------------------------------------------------------
// Public surface.
// ---------------------------------------------------------------------------

/// Install the JSON tracing subscriber for the process. Subsequent calls
/// return [`LogInitStatus::AlreadyInitialized`] (non-fatal). The subscriber
/// applies to any `tracing::*` events emitted elsewhere in the process; the
/// `emit_*_log` functions below write their canonical envelope lines
/// directly to stderr and therefore do not depend on this subscriber being
/// installed.
pub fn init_json_logging() -> LogInitStatus {
    use tracing_subscriber::EnvFilter;
    use tracing_subscriber::layer::SubscriberExt;
    use tracing_subscriber::util::SubscriberInitExt;

    // Build a non-panicking filter: prefer RUST_LOG, then the static "info"
    // directive, finally an empty default. None of these branches calls a
    // panicking API.
    let filter = EnvFilter::try_from_default_env()
        .or_else(|_| EnvFilter::try_new("info"))
        .unwrap_or_else(|_| EnvFilter::default());

    let layer = tracing_subscriber::fmt::layer()
        .json()
        .with_writer(std::io::stderr)
        .with_target(false)
        .with_current_span(false)
        .with_span_list(false);

    match tracing_subscriber::registry()
        .with(filter)
        .with(layer)
        .try_init()
    {
        Ok(()) => LogInitStatus::Installed,
        Err(_) => LogInitStatus::AlreadyInitialized,
    }
}

/// Emit the startup event line.
pub fn emit_startup_log(service: LogService) {
    let line = build_startup_line(service);
    write_line_to_stderr(&line);
}

/// Emit the config-failure event line. The line carries the
/// [`SafeErrorReport`] scalar fields plus its `&'static` class message; no
/// raw cause can reach the line because [`SafeErrorReport`] itself cannot
/// carry one.
pub fn emit_config_failure_log(service: LogService, report: SafeErrorReport) {
    let line = build_config_failure_line(service, report);
    write_line_to_stderr(&line);
}

/// Emit a shutdown event line carrying the supervisor drain snapshot. The
/// scalar arguments mirror the relevant fields of the atom #3
/// `RuntimeDrainReport`; the wire shape is decoupled from the runtime
/// struct so a future schema change in one does not silently break the
/// other.
pub fn emit_shutdown_log(
    service: LogService,
    event: LogShutdownEvent,
    timeout_ms_u32: u32,
    elapsed_ms_u32: u32,
    active_count_u16: u16,
    timed_out_count_u16: u16,
    unknown_after_boundary_count_u16: u16,
) {
    let line = build_shutdown_line(
        service,
        event,
        timeout_ms_u32,
        elapsed_ms_u32,
        active_count_u16,
        timed_out_count_u16,
        unknown_after_boundary_count_u16,
    );
    write_line_to_stderr(&line);
}

// ---------------------------------------------------------------------------
// Tests (6 named per ATOM_PLAN atom #4 §6).
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    // Tests deliberately panic on failure; the prod deny list (no expect /
    // no panic) does not apply to assertion-driven test code.
    #![allow(clippy::expect_used)]

    use super::*;
    use crate::error::{ErrorCode, ErrorOp, ErrorSink, MnemosError};

    /// A recognizable secret used to prove it never reaches any projection.
    const CANARY: &str = "CANARY-SECRET-7f3a9b-DO-NOT-LEAK";

    fn has_canary(s: &str) -> bool {
        s.contains(CANARY)
    }

    // Allowlist key sets (per ATOM_PLAN §4.A A.logging wire spec).
    const STARTUP_KEYS: &[&str] = &["event", "schema", "service", "service_u8"];
    const CONFIG_FAILURE_KEYS: &[&str] = &[
        "event",
        "schema",
        "service",
        "service_u8",
        "sink_u8",
        "code_u16",
        "retry_u8",
        "commit_state_u8",
        "severity_u8",
        "redaction_u8",
        "actionability_u8",
        "message",
    ];
    const SHUTDOWN_KEYS: &[&str] = &[
        "event",
        "schema",
        "service",
        "service_u8",
        "shutdown_event",
        "shutdown_event_u8",
        "timeout_ms_u32",
        "elapsed_ms_u32",
        "active_count_u16",
        "timed_out_count_u16",
        "unknown_after_boundary_count_u16",
    ];

    const ALL_REDACTION_KINDS: &[LogRedactionKind] = &[
        LogRedactionKind::WalletPassphrase,
        LogRedactionKind::SuiPrivateKey,
        LogRedactionKind::SuiTxBytes,
        LogRedactionKind::WalrusBytes,
        LogRedactionKind::ToolIo,
        LogRedactionKind::Prompt,
        LogRedactionKind::ProviderBody,
        LogRedactionKind::SourceChain,
        LogRedactionKind::ApiToken,
    ];

    fn assert_single_json_line_with_keys(line: &str, expected_keys: &[&str]) {
        assert_eq!(
            line.matches('\n').count(),
            0,
            "line must be single-line; line={line}"
        );
        assert!(
            line.starts_with('{') && line.ends_with('}'),
            "line must be a JSON object; line={line}"
        );
        for &k in expected_keys {
            let needle = format!("\"{k}\":");
            assert!(line.contains(&needle), "missing key {k} in line={line}");
        }
        // No extra keys: each key contributes exactly one `":` occurrence;
        // string values used here ("startup", static labels, the
        // `&'static` SafeErrorReport message) never contain that bigram.
        let observed = line.matches("\":").count();
        assert_eq!(
            observed,
            expected_keys.len(),
            "extra-key drift in line={line}; expected={expected_keys:?}"
        );
    }

    #[test]
    fn double_init_returns_status_without_panic() {
        // The first call's outcome depends on test-binary order (the global
        // dispatcher may already be set by a sibling test); either status
        // is acceptable. The second call must always be AlreadyInitialized
        // and must not panic.
        let first = init_json_logging();
        assert!(matches!(
            first,
            LogInitStatus::Installed | LogInitStatus::AlreadyInitialized
        ));
        let second = init_json_logging();
        assert_eq!(second, LogInitStatus::AlreadyInitialized);
    }

    #[test]
    fn startup_event_is_single_json_line_with_allowlist_keys() {
        let line = build_startup_line(LogService::Agent);
        assert_single_json_line_with_keys(&line, STARTUP_KEYS);
        assert!(line.contains("\"event\":\"startup\""));
        assert!(line.contains("\"schema\":\"mnemos.log.v0\""));
        assert!(line.contains("\"service\":\"agent\""));
        assert!(line.contains("\"service_u8\":1"));

        // Cli variant maps to its own scalar tag without changing the
        // allowlist or the schema string.
        let cli_line = build_startup_line(LogService::Cli);
        assert_single_json_line_with_keys(&cli_line, STARTUP_KEYS);
        assert!(cli_line.contains("\"service\":\"cli\""));
        assert!(cli_line.contains("\"service_u8\":2"));
    }

    #[test]
    fn config_failure_event_is_single_json_line_with_allowlist_keys() {
        // Build a SourceRedacted report — the variant that proves the
        // raw-canary string is dropped at the error-projection boundary
        // before logging is even reached.
        let err = MnemosError::source_redacted(ErrorOp::Config, CANARY);
        let report = err.safe_report(ErrorSink::Audit);
        let line = build_config_failure_line(LogService::Cli, report);
        assert_single_json_line_with_keys(&line, CONFIG_FAILURE_KEYS);

        // Scalar/enum projections match SafeErrorReport's discriminants.
        let expected_code = ErrorCode::SourceRedacted as u16;
        assert!(line.contains(&format!("\"code_u16\":{expected_code}")));
        assert!(line.contains("\"sink_u8\":4")); // ErrorSink::Audit
        assert!(line.contains("\"service\":\"cli\""));
        assert!(line.contains("\"service_u8\":2"));

        // Canary policy: the raw redacted detail must never enter the line.
        assert!(!has_canary(&line), "canary leaked into config_failure line");
    }

    #[test]
    fn shutdown_event_is_single_json_line_with_allowlist_keys() {
        // Cover every LogShutdownEvent variant against the same allowlist.
        for (event, label, tag) in [
            (LogShutdownEvent::Requested, "requested", 1u8),
            (LogShutdownEvent::DrainStarted, "drain_started", 2),
            (LogShutdownEvent::DrainTimeout, "drain_timeout", 3),
            (LogShutdownEvent::Completed, "completed", 4),
        ] {
            let line = build_shutdown_line(
                LogService::Agent,
                event,
                5_000_u32,
                5_001_u32,
                2_u16,
                1_u16,
                0_u16,
            );
            assert_single_json_line_with_keys(&line, SHUTDOWN_KEYS);
            assert!(line.contains(&format!("\"shutdown_event\":\"{label}\"")));
            assert!(line.contains(&format!("\"shutdown_event_u8\":{tag}")));
            assert!(line.contains("\"timeout_ms_u32\":5000"));
            assert!(line.contains("\"elapsed_ms_u32\":5001"));
            assert!(line.contains("\"active_count_u16\":2"));
            assert!(line.contains("\"timed_out_count_u16\":1"));
            assert!(line.contains("\"unknown_after_boundary_count_u16\":0"));
        }
    }

    #[test]
    fn redacted_display_and_debug_keep_only_class() {
        for &kind in ALL_REDACTION_KINDS {
            let raw = format!("CANARY-RAW-{kind:?}-7f3a9b");
            let red = redact_for_log(&raw, kind);

            let display = format!("{red}");
            let debug = format!("{red:?}");
            assert!(
                !display.contains(&raw),
                "Display leaked raw for {kind:?}: {display}"
            );
            assert!(
                !debug.contains(&raw),
                "Debug leaked raw for {kind:?}: {debug}"
            );

            let label = kind.class_label();
            assert!(
                display.contains(label),
                "Display missing class label {label} for {kind:?}: {display}"
            );
            assert!(
                debug.contains(label),
                "Debug missing class label {label} for {kind:?}: {debug}"
            );
        }
    }

    #[test]
    fn redacted_values_do_not_leak_when_logged_as_json() {
        // For every LogRedactionKind variant, the raw bytes passed to
        // redact_for_log are not recoverable from any textual projection
        // of the resulting RedactedLogValue — including a hand-built JSON
        // line that embeds the redacted value via its Display impl.
        for &kind in ALL_REDACTION_KINDS {
            let raw = format!("CANARY-RAW-JSON-{kind:?}-7f3a9b");
            let red = redact_for_log(&raw, kind);

            let json_line = format!("{{\"redacted\":\"{red}\"}}");
            assert!(
                !json_line.contains(&raw),
                "JSON projection leaked raw for {kind:?}: {json_line}"
            );

            let debug_line = format!("{red:?}");
            assert!(
                !debug_line.contains(&raw),
                "Debug projection leaked raw for {kind:?}: {debug_line}"
            );

            // The class label is the only textual carrier of the kind.
            let label = kind.class_label();
            assert!(
                json_line.contains(label),
                "JSON projection missing class label {label} for {kind:?}: {json_line}"
            );
        }
    }
}
