//! `config.rs` — typed runtime configuration.
//!
//! # Design rationale
//!
//! Configuration is the single boundary where text from the disk becomes a
//! *fixed-width, `Copy`, heap-free* runtime value. The parser:
//!
//! * caps `max_input_tokens` at [`MAX_INPUT_TOKENS_PHASE0`] (5,000) at parse
//!   time, so an oversized prompt budget can never enter the runtime;
//! * rejects unknown TOML fields (every sub-schema carries
//!   `#[serde(deny_unknown_fields)]`), so an attempt to *enable* an
//!   unrecognized tool surface is rejected before the runtime exists;
//! * rejects any TOML string that contains the lowercase substring
//!   `"mainnet"`, so Phase 0 cannot be coerced into a mainnet posture by
//!   configuration;
//! * collapses every textual sub-config field to a `_lenN` length, so the
//!   runtime layout is `Copy`-able, bounded, and measurable;
//! * folds every parse / I/O failure through [`MnemosError::source_redacted`]
//!   ([`ErrorOp::Config`]), so a raw config snippet (which might contain a
//!   canary) never reaches `Debug`, `Display`, or
//!   [`std::error::Error::source`].
//!
//! Reuse: [`MnemosError`], [`MnemosResult`], [`SafeErrorReport`].

use std::ffi::OsString;
use std::path::Path;

use serde::Deserialize;

use crate::error::{
    BudgetAxis, ErrorOp, ErrorSink, MnemosError, MnemosResult, SafeErrorReport, StateRejectReason,
    ToolDenyReason, ToolProgram,
};

/// Hard ceiling on `max_input_tokens` at Phase 0; the parser rejects any
/// value above this so the runtime never sees an unbounded prompt budget.
pub const MAX_INPUT_TOKENS_PHASE0: u32 = 5_000;

/// Hard ceiling on the size of a persona file at Phase 0; the loader measures
/// the file once and rejects sizes above this.
pub const MAX_PERSONA_BYTES_PHASE0: u64 = 2_048;

/// Phase 0 inert tools may *list* command names but never run them. Listing
/// any of these well-known dangerous names is rejected even when `run` is
/// disabled.
const BANNED_COMMAND_NAMES: &[&str] = &[
    "rm", "rmdir", "dd", "mkfs", "curl", "wget", "nc", "ssh", "scp", "ftp", "sudo", "su", "doas",
    "git", "cargo", "sui", "walrus", "openssl", "gpg",
];

/// Allowlisted env keys for [`RuntimeEnv::from_pairs`] /
/// [`RuntimeEnv::from_process_allowlist`]. Every other key — and every name
/// containing a secret-like substring — is rejected.
const ENV_KEY_ALLOWLIST: &[&str] = &["MNEMOS_REFUSE_ROOT", "MNEMOS_PREFLIGHT"];

/// Substrings whose presence in an env *name* marks it as secret-like and
/// causes [`RuntimeEnv::from_pairs`] to reject it (the allowlist check happens
/// only after this filter, so a name matching both lists is still rejected).
const SECRET_LIKE_KEY_SUBSTRINGS: &[&str] = &[
    "KEY",
    "TOKEN",
    "SECRET",
    "PASS",
    "PRIVATE",
    "MNEMONIC",
    "CREDENTIAL",
];

// ===== three #[repr(u8)] enums =====

/// LLM backend identifier. Wire form: `"open_router"` / `"openai_compatible"`.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Deserialize)]
#[repr(u8)]
pub enum RuntimeLlmBackend {
    /// OpenRouter aggregator.
    #[serde(rename = "open_router")]
    OpenRouter = 1,
    /// Any OpenAI-compatible inference endpoint.
    #[serde(rename = "openai_compatible")]
    OpenAiCompatible = 2,
}

/// Cache strategy. Wire form: `"auto"`.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Deserialize)]
#[repr(u8)]
pub enum RuntimeCacheStrategy {
    /// Automatic cache placement.
    #[serde(rename = "auto")]
    Auto = 1,
}

/// Log verbosity. Wire form: `"trace"` / `"debug"` / `"info"` / `"warn"` /
/// `"error"`.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Deserialize)]
#[repr(u8)]
#[serde(rename_all = "lowercase")]
pub enum RuntimeLogLevel {
    /// Trace.
    Trace = 1,
    /// Debug.
    Debug = 2,
    /// Info (default).
    Info = 3,
    /// Warn.
    Warn = 4,
    /// Error.
    Error = 5,
}

// ===== compact sub-config structs (Copy, fixed-width) =====

/// Agent budget / persona limits (Copy fixed-width).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RuntimeAgentConfig {
    /// Max iterations per turn.
    pub max_iterations_u8: u8,
    /// Effective `max_input_tokens` (bounded by [`MAX_INPUT_TOKENS_PHASE0`]).
    pub max_input_tokens_u32: u32,
    /// Effective `max_output_tokens`.
    pub max_output_tokens_u32: u32,
    /// Daily token budget.
    pub daily_token_budget_u32: u32,
    /// Whether reasoning is enabled.
    pub reasoning_enabled: bool,
    /// Measured persona-file size in bytes (0 = no persona file).
    pub persona_file_bytes_u16: u16,
}

/// LLM endpoint configuration (Copy fixed-width; strings collapsed to
/// `_lenN`).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RuntimeLlmConfig {
    /// Backend identifier.
    pub backend: RuntimeLlmBackend,
    /// Byte length of the model id (the id text itself is not retained).
    pub model_id_len_u16: u16,
    /// Byte length of the fallback model id (0 = none).
    pub fallback_model_id_len_u16: u16,
    /// Request timeout in whole seconds.
    pub request_timeout_secs_u16: u16,
    /// First-token deadline in whole seconds.
    pub first_token_timeout_secs_u16: u16,
    /// Max retry attempts.
    pub max_retries_u8: u8,
    /// Retry backoff base in milliseconds.
    pub retry_base_ms_u16: u16,
}

/// Cache configuration (Copy fixed-width).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RuntimeCacheConfig {
    /// Strategy.
    pub strategy: RuntimeCacheStrategy,
    /// Max prompt-cache breakpoints.
    pub max_breakpoints_u8: u8,
    /// Whether counter telemetry is allowed.
    pub allow_counter_telemetry: bool,
}

/// Tool configuration (Copy fixed-width).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RuntimeToolConfig {
    /// Whether `read_file` is enabled.
    pub read_file_enabled: bool,
    /// Count of inert-listed commands (the command names themselves are
    /// validated at parse time and then *discarded* — only the count remains).
    pub inert_command_count_u8: u8,
}

/// Observability configuration (Copy fixed-width; `metrics_listen_len` only).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RuntimeObservabilityConfig {
    /// Log verbosity.
    pub log_level: RuntimeLogLevel,
    /// Whether logs are emitted as JSON.
    pub log_json: bool,
    /// Byte length of the metrics listen address (the address itself is not
    /// retained).
    pub metrics_listen_len_u16: u16,
}

/// Security posture (Copy fixed-width).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RuntimeSecurityConfig {
    /// Whether to fail if the config file is world-writable.
    pub fail_on_world_writable_config: bool,
    /// Whether to fail if a plaintext secret-like value is detected in
    /// config. (The strict schema already rejects unknown / secret-like
    /// *keys*; this flag mirrors operator intent for future tightening.)
    pub fail_on_plaintext_secret_in_config: bool,
    /// Daily USD cap in micro-USD (1 USD = 1_000_000 micro-USD).
    pub daily_usd_cap_micros_u32: u32,
}

/// Compact runtime configuration. Constructed by
/// [`RuntimeConfig::from_toml_str`] or [`load_runtime_config_from_path`]; the
/// parser is the *only* boundary where text turns into this `Copy` value.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RuntimeConfig {
    /// Agent sub-config.
    pub agent: RuntimeAgentConfig,
    /// LLM sub-config.
    pub llm: RuntimeLlmConfig,
    /// Cache sub-config.
    pub cache: RuntimeCacheConfig,
    /// Tool sub-config.
    pub tools: RuntimeToolConfig,
    /// Observability sub-config.
    pub observability: RuntimeObservabilityConfig,
    /// Security sub-config.
    pub security: RuntimeSecurityConfig,
}

/// Process-level environment posture. Constructed exclusively through one of
/// the [`RuntimeEnv`] constructors so the allowlist is enforced at the entry.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RuntimeEnv {
    /// Whether to refuse to start as effective uid 0 (root).
    pub refuse_root: bool,
    /// Whether the preflight self-check is required.
    pub preflight: bool,
}

// ===== RuntimeEnv constructors =====

impl RuntimeEnv {
    /// The Phase 0 default posture: refuse root, require preflight.
    pub const fn default_phase0() -> Self {
        Self {
            refuse_root: true,
            preflight: true,
        }
    }

    /// Build a [`RuntimeEnv`] from an iterator of `(key, value)` pairs. The
    /// key must appear in the allowlist *and* not contain any secret-like
    /// substring; an unparsable value or any other key is rejected through
    /// [`MnemosError::source_redacted`] (`ErrorOp::Config`).
    pub fn from_pairs<'a, I>(pairs: I) -> MnemosResult<Self>
    where
        I: IntoIterator<Item = (&'a str, &'a str)>,
    {
        let mut env = Self::default_phase0();
        for (key, value) in pairs {
            if key_is_secret_like(key) {
                return Err(MnemosError::source_redacted(ErrorOp::Config, ""));
            }
            if !ENV_KEY_ALLOWLIST.contains(&key) {
                return Err(MnemosError::source_redacted(ErrorOp::Config, ""));
            }
            match key {
                "MNEMOS_REFUSE_ROOT" => {
                    env.refuse_root = parse_env_bool(value)?;
                }
                "MNEMOS_PREFLIGHT" => {
                    env.preflight = parse_env_bool(value)?;
                }
                _ => {
                    return Err(MnemosError::source_redacted(ErrorOp::Config, ""));
                }
            }
        }
        Ok(env)
    }

    /// Read the process environment through the allowlist. Any unknown key is
    /// *silently ignored* (other processes may legitimately set unrelated
    /// variables); any secret-like name is also ignored at this entry. Use
    /// [`RuntimeEnv::from_pairs`] for strict explicit-pair parsing.
    pub fn from_process_allowlist() -> MnemosResult<Self> {
        let mut env = Self::default_phase0();
        for (key, value) in std::env::vars_os() {
            let Some(key_str) = key.to_str() else {
                continue;
            };
            if key_is_secret_like(key_str) {
                continue;
            }
            if !ENV_KEY_ALLOWLIST.contains(&key_str) {
                continue;
            }
            let Some(value_str) = value.to_str() else {
                continue;
            };
            match key_str {
                "MNEMOS_REFUSE_ROOT" => {
                    env.refuse_root = parse_env_bool(value_str)?;
                }
                "MNEMOS_PREFLIGHT" => {
                    env.preflight = parse_env_bool(value_str)?;
                }
                _ => continue,
            }
        }
        Ok(env)
    }
}

// ===== TOML intermediate schemas (parse-only; never retained) =====

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct TomlTop {
    agent: TomlAgent,
    llm: TomlLlm,
    cache: TomlCache,
    tools: TomlTools,
    observability: TomlObservability,
    security: TomlSecurity,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct TomlAgent {
    max_iterations_u8: u8,
    max_input_tokens_u32: u32,
    max_output_tokens_u32: u32,
    daily_token_budget_u32: u32,
    reasoning_enabled: bool,
    #[serde(default)]
    persona_file: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct TomlLlm {
    backend: RuntimeLlmBackend,
    model_id: String,
    #[serde(default)]
    fallback_model_id: Option<String>,
    request_timeout_secs_u16: u16,
    first_token_timeout_secs_u16: u16,
    max_retries_u8: u8,
    retry_base_ms_u16: u16,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct TomlCache {
    strategy: RuntimeCacheStrategy,
    max_breakpoints_u8: u8,
    allow_counter_telemetry: bool,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct TomlTools {
    read_file_enabled: bool,
    #[serde(default)]
    commands: Vec<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct TomlObservability {
    log_level: RuntimeLogLevel,
    log_json: bool,
    metrics_listen: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct TomlSecurity {
    fail_on_world_writable_config: bool,
    fail_on_plaintext_secret_in_config: bool,
    daily_usd_cap_micros_u32: u32,
}

impl RuntimeConfig {
    /// Parse a TOML document into a compact [`RuntimeConfig`]. The `env` is
    /// accepted for symmetry with [`load_runtime_config_from_path`] and
    /// reserved for future cross-checks; `persona_base` is the directory used
    /// to resolve `agent.persona_file` if present.
    pub fn from_toml_str(
        toml_text: &str,
        env: RuntimeEnv,
        persona_base: Option<&Path>,
    ) -> MnemosResult<Self> {
        let _ = env;
        let parsed: TomlTop = toml::from_str(toml_text)
            .map_err(|_| MnemosError::source_redacted(ErrorOp::Config, ""))?;

        // mainnet label refusal (no network call).
        if contains_mainnet(&parsed) {
            return Err(MnemosError::state_rejected(
                ErrorOp::Config,
                StateRejectReason::PhaseGate,
            ));
        }

        // token cap.
        if parsed.agent.max_input_tokens_u32 > MAX_INPUT_TOKENS_PHASE0 {
            return Err(MnemosError::budget_exceeded(
                BudgetAxis::LlmTokens,
                u64::from(parsed.agent.max_input_tokens_u32),
                u64::from(MAX_INPUT_TOKENS_PHASE0),
            ));
        }

        // banned command names (regardless of run-disabled).
        let command_count_raw = parsed.tools.commands.len();
        let inert_command_count_u8 = u8::try_from(command_count_raw).map_err(|_| {
            MnemosError::state_rejected(ErrorOp::Config, StateRejectReason::UnitWidth)
        })?;
        for name in &parsed.tools.commands {
            if BANNED_COMMAND_NAMES
                .iter()
                .any(|b| b.eq_ignore_ascii_case(name))
            {
                return Err(MnemosError::tool_denied(
                    ToolProgram::Other,
                    u16::from(inert_command_count_u8),
                    ToolDenyReason::BannedSurface,
                    0,
                ));
            }
        }

        // String length budgets (textual fields collapse to `_lenN`).
        let model_id_len_u16 = u16_from_byte_len(parsed.llm.model_id.len())?;
        let fallback_model_id_len_u16 = match parsed.llm.fallback_model_id.as_deref() {
            Some(s) => u16_from_byte_len(s.len())?,
            None => 0,
        };
        let metrics_listen_len_u16 = u16_from_byte_len(parsed.observability.metrics_listen.len())?;

        // Persona file measurement (cap-enforced, never read into memory).
        let persona_file_bytes_u16 = match (&parsed.agent.persona_file, persona_base) {
            (Some(rel), Some(base)) => measure_persona_file(base, rel)?,
            (Some(_), None) => {
                return Err(MnemosError::state_rejected(
                    ErrorOp::Config,
                    StateRejectReason::PhaseGate,
                ));
            }
            (None, _) => 0,
        };

        Ok(Self {
            agent: RuntimeAgentConfig {
                max_iterations_u8: parsed.agent.max_iterations_u8,
                max_input_tokens_u32: parsed.agent.max_input_tokens_u32,
                max_output_tokens_u32: parsed.agent.max_output_tokens_u32,
                daily_token_budget_u32: parsed.agent.daily_token_budget_u32,
                reasoning_enabled: parsed.agent.reasoning_enabled,
                persona_file_bytes_u16,
            },
            llm: RuntimeLlmConfig {
                backend: parsed.llm.backend,
                model_id_len_u16,
                fallback_model_id_len_u16,
                request_timeout_secs_u16: parsed.llm.request_timeout_secs_u16,
                first_token_timeout_secs_u16: parsed.llm.first_token_timeout_secs_u16,
                max_retries_u8: parsed.llm.max_retries_u8,
                retry_base_ms_u16: parsed.llm.retry_base_ms_u16,
            },
            cache: RuntimeCacheConfig {
                strategy: parsed.cache.strategy,
                max_breakpoints_u8: parsed.cache.max_breakpoints_u8,
                allow_counter_telemetry: parsed.cache.allow_counter_telemetry,
            },
            tools: RuntimeToolConfig {
                read_file_enabled: parsed.tools.read_file_enabled,
                inert_command_count_u8,
            },
            observability: RuntimeObservabilityConfig {
                log_level: parsed.observability.log_level,
                log_json: parsed.observability.log_json,
                metrics_listen_len_u16,
            },
            security: RuntimeSecurityConfig {
                fail_on_world_writable_config: parsed.security.fail_on_world_writable_config,
                fail_on_plaintext_secret_in_config: parsed
                    .security
                    .fail_on_plaintext_secret_in_config,
                daily_usd_cap_micros_u32: parsed.security.daily_usd_cap_micros_u32,
            },
        })
    }
}

// ===== free functions =====

/// Project an error into a [`SafeErrorReport`] tagged for the audit sink. The
/// raw cause is never retained, so the report contains only the `&'static`
/// class label and bounded scalar metadata.
pub const fn config_error_report(err: MnemosError) -> SafeErrorReport {
    err.safe_report(ErrorSink::Audit)
}

/// Load a [`RuntimeConfig`] from a path on disk. The file's parent directory
/// (if any) is used as the persona-file base.
pub fn load_runtime_config_from_path(
    path: impl AsRef<Path>,
    env: RuntimeEnv,
) -> MnemosResult<RuntimeConfig> {
    let path = path.as_ref();
    let text = std::fs::read_to_string(path)
        .map_err(|_| MnemosError::source_redacted(ErrorOp::Config, ""))?;
    let persona_base = path.parent();
    RuntimeConfig::from_toml_str(&text, env, persona_base)
}

/// Validate the runtime env against the effective uid. If `refuse_root` is
/// set and the uid is `0` *or* unknown (`None`), the call is rejected
/// fail-closed.
pub const fn validate_runtime_env(
    env: RuntimeEnv,
    effective_uid_u32: Option<u32>,
) -> MnemosResult<()> {
    if env.refuse_root {
        match effective_uid_u32 {
            Some(0) | None => {
                return Err(MnemosError::state_rejected(
                    ErrorOp::Config,
                    StateRejectReason::PhaseGate,
                ));
            }
            Some(_) => {}
        }
    }
    Ok(())
}

/// Return the effective unix uid via the POSIX `geteuid` syscall. Returns
/// `None` on non-unix targets.
#[cfg(unix)]
pub fn current_effective_uid_u32() -> Option<u32> {
    // SAFETY: POSIX `geteuid` has no side effects, is async-signal-safe,
    // never fails, and returns a `uid_t` whose value fits in `u32` on every
    // supported unix target (macOS arm64, Linux x86_64 / aarch64).
    unsafe extern "C" {
        safe fn geteuid() -> u32;
    }
    Some(geteuid())
}

/// Always `None` on non-unix targets.
#[cfg(not(unix))]
pub fn current_effective_uid_u32() -> Option<u32> {
    None
}

/// Strict `--config <path>` / `--config=<path>` extraction. Returns
/// `Ok(None)` when no `--config` argument is present. Any other token —
/// positional arg, unknown long flag, short flag, repeated `--config`, empty
/// path — is rejected.
pub fn config_path_from_args<I>(args: I) -> MnemosResult<Option<OsString>>
where
    I: IntoIterator<Item = OsString>,
{
    let mut path: Option<OsString> = None;
    let mut iter = args.into_iter();
    while let Some(arg) = iter.next() {
        let s = arg
            .to_str()
            .ok_or_else(|| MnemosError::source_redacted(ErrorOp::Config, ""))?;
        if let Some(rest) = s.strip_prefix("--config=") {
            if path.is_some() || rest.is_empty() {
                return Err(MnemosError::source_redacted(ErrorOp::Config, ""));
            }
            path = Some(OsString::from(rest));
        } else if s == "--config" {
            if path.is_some() {
                return Err(MnemosError::source_redacted(ErrorOp::Config, ""));
            }
            let next = iter
                .next()
                .ok_or_else(|| MnemosError::source_redacted(ErrorOp::Config, ""))?;
            if next.is_empty() {
                return Err(MnemosError::source_redacted(ErrorOp::Config, ""));
            }
            path = Some(next);
        } else {
            return Err(MnemosError::source_redacted(ErrorOp::Config, ""));
        }
    }
    Ok(path)
}

// ===== internal helpers =====

fn u16_from_byte_len(n: usize) -> MnemosResult<u16> {
    u16::try_from(n)
        .map_err(|_| MnemosError::state_rejected(ErrorOp::Config, StateRejectReason::UnitWidth))
}

fn measure_persona_file(base: &Path, rel: &str) -> MnemosResult<u16> {
    let path = base.join(rel);
    let meta =
        std::fs::metadata(&path).map_err(|_| MnemosError::source_redacted(ErrorOp::Config, ""))?;
    let size = meta.len();
    if size > MAX_PERSONA_BYTES_PHASE0 {
        return Err(MnemosError::budget_exceeded(
            BudgetAxis::BinaryBytes,
            size,
            MAX_PERSONA_BYTES_PHASE0,
        ));
    }
    // `size` is bounded above by `MAX_PERSONA_BYTES_PHASE0 = 2_048`, which
    // fits in `u16` without truncation.
    Ok(size as u16)
}

fn parse_env_bool(s: &str) -> MnemosResult<bool> {
    match s {
        "true" | "1" | "yes" => Ok(true),
        "false" | "0" | "no" => Ok(false),
        _ => Err(MnemosError::source_redacted(ErrorOp::Config, "")),
    }
}

fn key_is_secret_like(key: &str) -> bool {
    let upper = key.to_ascii_uppercase();
    SECRET_LIKE_KEY_SUBSTRINGS
        .iter()
        .any(|needle| upper.contains(needle))
}

fn str_has_mainnet(s: &str) -> bool {
    s.to_ascii_lowercase().contains("mainnet")
}

fn contains_mainnet(t: &TomlTop) -> bool {
    str_has_mainnet(&t.llm.model_id)
        || t.llm
            .fallback_model_id
            .as_deref()
            .is_some_and(str_has_mainnet)
        || t.agent.persona_file.as_deref().is_some_and(str_has_mainnet)
        || t.tools.commands.iter().any(|s| str_has_mainnet(s))
        || str_has_mainnet(&t.observability.metrics_listen)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use super::*;
    use crate::error::ErrorCode;

    const MINIMAL_TOML: &str = r#"
[agent]
max_iterations_u8 = 8
max_input_tokens_u32 = 4500
max_output_tokens_u32 = 1024
daily_token_budget_u32 = 100000
reasoning_enabled = false

[llm]
backend = "open_router"
model_id = "anthropic/claude-3"
request_timeout_secs_u16 = 30
first_token_timeout_secs_u16 = 5
max_retries_u8 = 3
retry_base_ms_u16 = 200

[cache]
strategy = "auto"
max_breakpoints_u8 = 4
allow_counter_telemetry = true

[tools]
read_file_enabled = false

[observability]
log_level = "info"
log_json = true
metrics_listen = "127.0.0.1:9100"

[security]
fail_on_world_writable_config = true
fail_on_plaintext_secret_in_config = true
daily_usd_cap_micros_u32 = 1000000
"#;

    fn env_default() -> RuntimeEnv {
        RuntimeEnv::default_phase0()
    }

    #[test]
    fn valid_minimal_config_parses_to_compact_runtime() {
        let cfg = RuntimeConfig::from_toml_str(MINIMAL_TOML, env_default(), None).unwrap();
        assert_eq!(cfg.agent.max_iterations_u8, 8);
        assert_eq!(cfg.agent.max_input_tokens_u32, 4_500);
        assert_eq!(cfg.agent.persona_file_bytes_u16, 0);
        assert!(!cfg.agent.reasoning_enabled);
        assert_eq!(cfg.llm.backend, RuntimeLlmBackend::OpenRouter);
        assert_eq!(
            cfg.llm.model_id_len_u16,
            u16::try_from("anthropic/claude-3".len()).unwrap()
        );
        assert_eq!(cfg.llm.fallback_model_id_len_u16, 0);
        assert_eq!(cfg.cache.strategy, RuntimeCacheStrategy::Auto);
        assert!(!cfg.tools.read_file_enabled);
        assert_eq!(cfg.tools.inert_command_count_u8, 0);
        assert_eq!(cfg.observability.log_level, RuntimeLogLevel::Info);
        assert!(cfg.observability.log_json);
        assert_eq!(
            cfg.observability.metrics_listen_len_u16,
            u16::try_from("127.0.0.1:9100".len()).unwrap()
        );
        assert!(cfg.security.fail_on_world_writable_config);
        assert_eq!(cfg.security.daily_usd_cap_micros_u32, 1_000_000);
    }

    #[test]
    fn unknown_toml_field_is_redacted_source_error() {
        let bad = format!("{MINIMAL_TOML}\n[bogus_section]\nextra = 1\n");
        let err = RuntimeConfig::from_toml_str(&bad, env_default(), None).unwrap_err();
        assert_eq!(err.code(), ErrorCode::SourceRedacted);
    }

    #[test]
    fn token_cap_above_phase0_limit_is_rejected() {
        let bad =
            MINIMAL_TOML.replace("max_input_tokens_u32 = 4500", "max_input_tokens_u32 = 5001");
        let err = RuntimeConfig::from_toml_str(&bad, env_default(), None).unwrap_err();
        assert_eq!(err.code(), ErrorCode::BudgetExceeded);
    }

    #[test]
    fn unsafe_tool_enablement_is_rejected() {
        // An unknown `[tools]` flag — e.g. one that would enable an unsafe
        // surface — is rejected by `deny_unknown_fields` before the runtime
        // exists, so an attacker cannot smuggle in a new boolean.
        let bad = MINIMAL_TOML.replace(
            "[tools]\nread_file_enabled = false",
            "[tools]\nread_file_enabled = false\nnetwork_egress_enabled = true",
        );
        let err = RuntimeConfig::from_toml_str(&bad, env_default(), None).unwrap_err();
        assert_eq!(err.code(), ErrorCode::SourceRedacted);
    }

    #[test]
    fn banned_command_names_are_rejected_even_when_run_disabled() {
        // `read_file_enabled = false` keeps the runner inert, yet a banned
        // name in the inert *list* must still be rejected.
        let bad = MINIMAL_TOML.replace(
            "[tools]\nread_file_enabled = false",
            "[tools]\nread_file_enabled = false\ncommands = [\"ls\", \"rm\"]",
        );
        let err = RuntimeConfig::from_toml_str(&bad, env_default(), None).unwrap_err();
        assert_eq!(err.code(), ErrorCode::ToolDenied);
    }

    #[test]
    fn mainnet_labels_are_rejected_without_network_calls() {
        let bad = MINIMAL_TOML.replace(
            "model_id = \"anthropic/claude-3\"",
            "model_id = \"sui/mainnet-fast\"",
        );
        let err = RuntimeConfig::from_toml_str(&bad, env_default(), None).unwrap_err();
        assert_eq!(err.code(), ErrorCode::StateRejected);
        // The check is purely textual: no socket, file, or env access. The
        // assertion is implicit (the function returned before any I/O), but
        // also: validating env_default() did not touch the network either.
        let _env = validate_runtime_env(env_default(), Some(1000));
    }

    #[test]
    fn env_parser_accepts_only_allowlisted_non_secret_keys() {
        let ok = RuntimeEnv::from_pairs([
            ("MNEMOS_REFUSE_ROOT", "false"),
            ("MNEMOS_PREFLIGHT", "true"),
        ])
        .unwrap();
        assert!(!ok.refuse_root);
        assert!(ok.preflight);

        let unknown = RuntimeEnv::from_pairs([("UNKNOWN_VAR", "x")]).unwrap_err();
        assert_eq!(unknown.code(), ErrorCode::SourceRedacted);

        let secret = RuntimeEnv::from_pairs([("ANTHROPIC_API_KEY", "sk-abc")]).unwrap_err();
        assert_eq!(secret.code(), ErrorCode::SourceRedacted);

        let bad_value = RuntimeEnv::from_pairs([("MNEMOS_REFUSE_ROOT", "maybe")]).unwrap_err();
        assert_eq!(bad_value.code(), ErrorCode::SourceRedacted);
    }

    #[test]
    fn persona_file_size_is_enforced() {
        let dir = std::env::temp_dir();
        let unique = format!(
            "mnemos_persona_{}_{}.bin",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0)
        );
        let path = dir.join(&unique);
        let oversize = usize::try_from(MAX_PERSONA_BYTES_PHASE0 + 1).unwrap();
        std::fs::write(&path, vec![b'x'; oversize]).unwrap();
        let toml = MINIMAL_TOML.replace(
            "reasoning_enabled = false",
            &format!("reasoning_enabled = false\npersona_file = \"{unique}\""),
        );
        let result = RuntimeConfig::from_toml_str(&toml, env_default(), Some(&dir));
        let _ = std::fs::remove_file(&path);
        let err = result.unwrap_err();
        assert_eq!(err.code(), ErrorCode::BudgetExceeded);
    }

    #[test]
    fn config_failure_report_never_contains_raw_canary() {
        const CANARY: &str = "CANARY-CONFIG-7f3a9b-do-not-leak";
        let bad = format!("[bogus]\nleak = \"{CANARY}\"\n{MINIMAL_TOML}\n");
        let err = RuntimeConfig::from_toml_str(&bad, env_default(), None).unwrap_err();
        let report = config_error_report(err);
        assert!(!report.message.contains(CANARY));
        assert!(!format!("{err:?}").contains(CANARY));
        assert!(!format!("{err}").contains(CANARY));
        assert_eq!(err.code(), ErrorCode::SourceRedacted);
    }

    #[test]
    fn config_arg_parser_is_strict() {
        let none = config_path_from_args::<Vec<OsString>>(vec![]).unwrap();
        assert!(none.is_none());

        let eq = config_path_from_args(vec![OsString::from("--config=foo.toml")]).unwrap();
        assert_eq!(eq.as_deref().and_then(|s| s.to_str()), Some("foo.toml"));

        let sep =
            config_path_from_args(vec![OsString::from("--config"), OsString::from("bar.toml")])
                .unwrap();
        assert_eq!(sep.as_deref().and_then(|s| s.to_str()), Some("bar.toml"));

        let dup = config_path_from_args(vec![
            OsString::from("--config=a"),
            OsString::from("--config=b"),
        ])
        .unwrap_err();
        assert_eq!(dup.code(), ErrorCode::SourceRedacted);

        let unknown = config_path_from_args(vec![OsString::from("--bogus-flag")]).unwrap_err();
        assert_eq!(unknown.code(), ErrorCode::SourceRedacted);

        let positional =
            config_path_from_args(vec![OsString::from("just_a_path.toml")]).unwrap_err();
        assert_eq!(positional.code(), ErrorCode::SourceRedacted);

        let empty = config_path_from_args(vec![OsString::from("--config=")]).unwrap_err();
        assert_eq!(empty.code(), ErrorCode::SourceRedacted);

        let missing = config_path_from_args(vec![OsString::from("--config")]).unwrap_err();
        assert_eq!(missing.code(), ErrorCode::SourceRedacted);
    }

    #[test]
    fn runtime_config_layout_is_bounded() {
        fn assert_copy<T: Copy>() {}
        assert_copy::<RuntimeConfig>();
        assert_copy::<RuntimeAgentConfig>();
        assert_copy::<RuntimeLlmConfig>();
        assert_copy::<RuntimeCacheConfig>();
        assert_copy::<RuntimeToolConfig>();
        assert_copy::<RuntimeObservabilityConfig>();
        assert_copy::<RuntimeSecurityConfig>();
        assert_copy::<RuntimeEnv>();

        assert_eq!(core::mem::size_of::<RuntimeLlmBackend>(), 1);
        assert_eq!(core::mem::size_of::<RuntimeCacheStrategy>(), 1);
        assert_eq!(core::mem::size_of::<RuntimeLogLevel>(), 1);

        // Compact RuntimeConfig stays within a small fixed bound; pinned
        // here so future layout drift is caught by this test.
        let total = core::mem::size_of::<RuntimeConfig>();
        assert!(
            total <= 80,
            "RuntimeConfig grew to {total} bytes; tighten or document the budget"
        );
    }
}
