//! OTel trace export.
//!
//! One answered consult may, when the operator opts in via
//! `SINABRO_OTEL_EXPORT=1`, additionally write ONE OTLP/JSON span line
//! (`ExportTraceServiceRequest`, the protojson encoding the OTel collector's
//! `otlpjsonfilereceiver` ingests) to the sinabro-owned directory
//! `$HOME/.mnemos/otel/` under a CONTENT-ADDRESSED filename
//! `<hex64(sha256(bytes))>.otlp.jsonl` — atomic, idempotent, zero egress.
//!
//! Cross-cutting guarantees:
//! - Content-addressing: the filename IS the sha256 of the bytes;
//!   `traceId`/`spanId` are domain-separated sha256 derivations of the run's
//!   captured truth — never random, never a counter.
//! - Deterministic projection: [`project_otlp_json`] is a PURE function of
//!   the receipt facts + captured times. No second truth is minted;
//!   the export re-derives from [`crate::agent_loop::AgentLoopOutcome`]
//!   exactly like the terminal receipt lines do.
//! - Byte-lock: the encoding is pinned byte-for-byte by an INDEPENDENT
//!   Python derivation (`scripts/check_otel_export_schema.py`, golden
//!   sha256 `83d39923…`) against [`GOLDEN_OTLP_JSON`].
//! - Fail-closed: strict env resolve (`unset`/`0` off · `1` on · anything
//!   else a VISIBLE typed refusal); clock/io/redaction trouble ⇒ a typed
//!   receipt line and NO file — never a silent fallback, never a fake
//!   "exported" claim (the success line renders only after the atomic write
//!   returned `Ok`).
//! - Bounded: one ~2KB file per explicitly-opted-in ceremony; string
//!   attributes are char-safe capped; the exporter runs ONCE, post-loop,
//!   off the egress path (zero loop/prompt byte delta).
//!
//! Shareable-tier content: a collector reading the directory is an UNAUDITED
//! process, and the operator's pipeline may forward off-box — so the bytes hold
//! ONLY counters, const typed labels, hex digests, and two variable strings:
//! the response-echoed `model` (redaction-belted + capped) and the tool trail
//! as a VERB-ONLY projection (first whitespace token per entry — model-authored
//! bytes and filesystem paths are structurally absent). The question, the
//! answer, memory content, and file content are NOT inputs to this module.

use std::path::{Path, PathBuf};
use std::time::SystemTime;

use sha2::{Digest, Sha256};

use crate::provider::redaction::{RedactionRequest, redact};

/// The opt-in environment variable. Telemetry is opt-in, off by default, and
/// never egresses.
pub(crate) const SINABRO_OTEL_EXPORT_ENV: &str = "SINABRO_OTEL_EXPORT";

/// Domain separator for the content-derived 16-byte `traceId`.
const TRACE_ID_DOMAIN: &[u8] = b"SINABRO-OTEL-V1-TRACE";
/// Domain separator for the content-derived 8-byte `spanId`.
const SPAN_ID_DOMAIN: &[u8] = b"SINABRO-OTEL-V1-SPAN";
/// Char-safe byte cap on the response-echoed model attribute.
const MODEL_ATTR_CAP_BYTES: usize = 200;
/// Char-safe byte cap on the joined verb-only trail attribute.
const TRAIL_ATTR_CAP_BYTES: usize = 400;
/// Sub-directory of `data_dir()` that holds the span files.
const OTEL_DIR_NAME: &str = "otel";
/// Filename suffix — `<hex64>.otlp.jsonl`, one JSON line per file.
const OTEL_FILE_SUFFIX: &str = ".otlp.jsonl";

/// The strict tri-state resolve of `SINABRO_OTEL_EXPORT`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum OtelExportSetting {
    /// Unset or the explicit `0`: no export, no receipt line (the default
    /// surface is byte-unchanged).
    Off,
    /// The exact value `1`: export one span for this ceremony.
    On,
    /// Any other value: the export is REFUSED with a visible typed line —
    /// never a silent default, never a guessed intent.
    Invalid,
}

/// Strictly resolve the raw environment value. Whitespace is NOT trimmed —
/// `" 1"` is an Invalid value, not a sloppy On: a config byte either matches
/// the contract or is refused.
#[must_use]
pub(crate) fn resolve_otel_export(raw: Option<&str>) -> OtelExportSetting {
    match raw {
        None | Some("0") => OtelExportSetting::Off,
        Some("1") => OtelExportSetting::On,
        Some(_) => OtelExportSetting::Invalid,
    }
}

/// Why an export write was refused (typed, fail-closed).
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub(crate) enum OtelExportError {
    /// `$HOME` could not be resolved (no data dir).
    #[error("HOME unresolved; no otel dir")]
    NoHome,
    /// Creating the directory or writing the file failed.
    #[error("otel export io failure")]
    Io,
}

/// The pure projection input — every field is receipt-class truth the
/// terminal already renders (counters, const labels, hex digests) plus the
/// captured wall-clock pair: time is CAPTURED once as an input, then the
/// projection is deterministic over it.
#[derive(Clone, Debug)]
pub(crate) struct OtelSpanInput<'a> {
    /// `service.version` / scope version (the crate version in production;
    /// a fixed string in the golden test so the lock survives version bumps).
    pub service_version: &'a str,
    /// Route backend label (`"openrouter"` / `"local_base"`).
    pub backend: &'a str,
    /// Response-echoed model id (belted + capped by the caller seam).
    pub model: &'a str,
    /// Typed stop class label (`AgentLoopStop::class_label`).
    pub stop_label: &'a str,
    /// The loop's tool trail (projected to verb-only inside).
    pub trail: &'a [String],
    /// Guard action label (`GuardAction::class_label`).
    pub guard_label: &'a str,
    /// Raw trajectory-health bits (rendered `0x%04x`).
    pub guard_signals_u16: u16,
    /// Live wire turns.
    pub turns_u8: u8,
    /// Tool iterations executed.
    pub tool_iters_u8: u8,
    /// Successful content reads.
    pub reads_u8: u8,
    /// Total prompt tokens.
    pub input_tokens_u64: u64,
    /// Total completion tokens.
    pub output_tokens_u64: u64,
    /// Provider-reported cached prompt tokens.
    pub cached_tokens_u64: u64,
    /// Ledger USD projection (micros; zero-rate sentinel until configured).
    pub usd_micros_u64: u64,
    /// Cache plan: byte-stable system prefix size.
    pub static_prefix_bytes_u32: u32,
    /// Cache plan: per-turn dynamic suffix size.
    pub dynamic_suffix_bytes_u32: u32,
    /// Measured strict-prefix-extension turn count.
    pub stable_prefix_turns_u8: u8,
    /// Last-turn request sha256 (full digest; the receipt renders 16 hex).
    pub request_sha_32: [u8; 32],
    /// Last-turn response sha256.
    pub response_sha_32: [u8; 32],
    /// Ceremony start, nanoseconds since the unix epoch.
    pub start_unix_nanos_u64: u64,
    /// Ceremony end, nanoseconds since the unix epoch.
    pub end_unix_nanos_u64: u64,
}

/// Lowercase hex of an arbitrary digest slice (the OTLP/JSON id encoding —
/// ids are hex, NOT the protojson base64 default; `hex32` is fixed-width so
/// this module carries its own minimal encoder).
#[must_use]
fn hex_lower(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        let hi = b >> 4;
        let lo = b & 0x0f;
        for nibble in [hi, lo] {
            out.push(char::from(if nibble < 10 {
                b'0' + nibble
            } else {
                b'a' + (nibble - 10)
            }));
        }
    }
    out
}

/// RFC 8259 string escape, byte-compatible with CPython `json.dumps`
/// (`ensure_ascii=False`): `"` `\` get a backslash; BS/FF/LF/CR/TAB use the
/// short forms; other control bytes < 0x20 use `\u00xx`; printable UTF-8
/// (Hangul included) passes through raw.
fn json_escape_into(out: &mut String, s: &str) {
    for ch in s.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\u{0008}' => out.push_str("\\b"),
            '\u{000c}' => out.push_str("\\f"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => {
                out.push_str("\\u");
                let code = c as u32;
                // 4-hex lowercase, matching CPython's \u00xx form.
                let digits = [
                    (code >> 12) & 0xf,
                    (code >> 8) & 0xf,
                    (code >> 4) & 0xf,
                    code & 0xf,
                ];
                for d in digits {
                    out.push(char::from_digit(d, 16).unwrap_or('0'));
                }
            }
            c => out.push(c),
        }
    }
}

/// Append one `{"key":…,"value":{"stringValue":…}}` attribute.
fn push_attr_str(out: &mut String, first: &mut bool, key: &str, value: &str) {
    if !*first {
        out.push(',');
    }
    *first = false;
    out.push_str("{\"key\":\"");
    json_escape_into(out, key);
    out.push_str("\",\"value\":{\"stringValue\":\"");
    json_escape_into(out, value);
    out.push_str("\"}}");
}

/// Append one `{"key":…,"value":{"intValue":"…"}}` attribute. protojson
/// encodes int64/uint64 as JSON STRINGS — the collector side rejects bare
/// numbers (Python-locked).
fn push_attr_u64(out: &mut String, first: &mut bool, key: &str, value: u64) {
    if !*first {
        out.push(',');
    }
    *first = false;
    out.push_str("{\"key\":\"");
    json_escape_into(out, key);
    out.push_str("\",\"value\":{\"intValue\":\"");
    out.push_str(&value.to_string());
    out.push_str("\"}}");
}

/// The VERB-ONLY trail projection: first whitespace token of every trail
/// entry, comma-joined, char-safe capped. Deterministic; drops paths, memory
/// ids, and any model-authored remainder structurally.
#[must_use]
fn trail_verbs(trail: &[String]) -> String {
    let joined = trail
        .iter()
        .map(|entry| entry.split_whitespace().next().unwrap_or(""))
        .collect::<Vec<_>>()
        .join(",");
    truncate_char_safe(&joined, TRAIL_ATTR_CAP_BYTES)
}

/// Char-boundary-safe truncation (the agent-loop cap idiom, local copy so
/// this module stays dependency-light on sibling internals).
#[must_use]
fn truncate_char_safe(text: &str, cap_bytes: usize) -> String {
    if text.len() <= cap_bytes {
        return text.to_string();
    }
    let mut end = cap_bytes;
    while end > 0 && !text.is_char_boundary(end) {
        end -= 1;
    }
    text[..end].to_string()
}

/// Content-derived span identifiers: `traceId` = first 16 bytes of a
/// domain-separated sha256 over (request sha ‖ response sha ‖ start ‖ end);
/// `spanId` = first 8 bytes of a second domain-separated sha256 over the
/// trace id. Deterministic per captured run; an all-zero id would need a
/// sha256 preimage with 128 leading zero bits (physically unreachable).
#[must_use]
fn derive_ids(input: &OtelSpanInput<'_>) -> ([u8; 16], [u8; 8]) {
    let mut hasher = Sha256::new();
    hasher.update(TRACE_ID_DOMAIN);
    hasher.update(input.request_sha_32);
    hasher.update(input.response_sha_32);
    hasher.update(input.start_unix_nanos_u64.to_le_bytes());
    hasher.update(input.end_unix_nanos_u64.to_le_bytes());
    let trace_digest = hasher.finalize();
    let mut trace_id = [0u8; 16];
    trace_id.copy_from_slice(&trace_digest[..16]);

    let mut hasher = Sha256::new();
    hasher.update(SPAN_ID_DOMAIN);
    hasher.update(trace_id);
    let span_digest = hasher.finalize();
    let mut span_id = [0u8; 8];
    span_id.copy_from_slice(&span_digest[..8]);
    (trace_id, span_id)
}

/// The PURE deterministic projection: receipt facts → ONE OTLP/JSON
/// `ExportTraceServiceRequest` line. Emission order, separators, id widths,
/// int64-as-string, enum-as-number, the 18-attribute set, and the status
/// mapping are all byte-locked by [`GOLDEN_OTLP_JSON`] and the independent
/// Python derivation. Total over every stop class: a non-`loop.completed` stop
/// maps to `status {"code":2,"message":…}`.
#[must_use]
pub(crate) fn project_otlp_json(input: &OtelSpanInput<'_>) -> String {
    let (trace_id, span_id) = derive_ids(input);
    let mut out = String::with_capacity(2048);

    out.push_str("{\"resourceSpans\":[{\"resource\":{\"attributes\":[");
    let mut first = true;
    push_attr_str(&mut out, &mut first, "service.name", "sinabro");
    push_attr_str(
        &mut out,
        &mut first,
        "service.version",
        input.service_version,
    );
    out.push_str("]},\"scopeSpans\":[{\"scope\":{\"name\":\"sinabro.agent_loop\",\"version\":\"");
    json_escape_into(&mut out, input.service_version);
    out.push_str("\"},\"spans\":[{\"traceId\":\"");
    out.push_str(&hex_lower(&trace_id));
    out.push_str("\",\"spanId\":\"");
    out.push_str(&hex_lower(&span_id));
    out.push_str("\",\"name\":\"sinabro.provider.consult\",\"kind\":1,\"startTimeUnixNano\":\"");
    out.push_str(&input.start_unix_nanos_u64.to_string());
    out.push_str("\",\"endTimeUnixNano\":\"");
    out.push_str(&input.end_unix_nanos_u64.to_string());
    out.push_str("\",\"attributes\":[");

    let mut first = true;
    push_attr_u64(
        &mut out,
        &mut first,
        "gen_ai.usage.input_tokens",
        input.input_tokens_u64,
    );
    push_attr_u64(
        &mut out,
        &mut first,
        "gen_ai.usage.output_tokens",
        input.output_tokens_u64,
    );
    push_attr_u64(
        &mut out,
        &mut first,
        "sinabro.usage.cached_tokens",
        input.cached_tokens_u64,
    );
    push_attr_u64(
        &mut out,
        &mut first,
        "sinabro.loop.turns",
        u64::from(input.turns_u8),
    );
    push_attr_u64(
        &mut out,
        &mut first,
        "sinabro.loop.tool_iters",
        u64::from(input.tool_iters_u8),
    );
    push_attr_u64(
        &mut out,
        &mut first,
        "sinabro.loop.reads",
        u64::from(input.reads_u8),
    );
    push_attr_str(&mut out, &mut first, "sinabro.loop.stop", input.stop_label);
    push_attr_str(
        &mut out,
        &mut first,
        "sinabro.loop.trail_verbs",
        &trail_verbs(input.trail),
    );
    push_attr_u64(
        &mut out,
        &mut first,
        "sinabro.cost.usd_micros",
        input.usd_micros_u64,
    );
    push_attr_u64(
        &mut out,
        &mut first,
        "sinabro.cache.static_prefix_bytes",
        u64::from(input.static_prefix_bytes_u32),
    );
    push_attr_u64(
        &mut out,
        &mut first,
        "sinabro.cache.dynamic_suffix_bytes",
        u64::from(input.dynamic_suffix_bytes_u32),
    );
    push_attr_u64(
        &mut out,
        &mut first,
        "sinabro.cache.stable_prefix_turns",
        u64::from(input.stable_prefix_turns_u8),
    );
    push_attr_str(
        &mut out,
        &mut first,
        "sinabro.guard.action",
        input.guard_label,
    );
    push_attr_str(
        &mut out,
        &mut first,
        "sinabro.guard.signals_hex",
        &format!("0x{:04x}", input.guard_signals_u16),
    );
    push_attr_str(
        &mut out,
        &mut first,
        "sinabro.request_sha256",
        &hex_lower(&input.request_sha_32),
    );
    push_attr_str(
        &mut out,
        &mut first,
        "sinabro.response_sha256",
        &hex_lower(&input.response_sha_32),
    );
    push_attr_str(&mut out, &mut first, "sinabro.backend", input.backend);
    push_attr_str(
        &mut out,
        &mut first,
        "sinabro.model",
        &truncate_char_safe(input.model, MODEL_ATTR_CAP_BYTES),
    );

    out.push_str("],\"status\":");
    if input.stop_label == "loop.completed" {
        out.push_str("{}");
    } else {
        out.push_str("{\"code\":2,\"message\":\"");
        json_escape_into(&mut out, input.stop_label);
        out.push_str("\"}");
    }
    out.push_str("}]}]}]}");
    out
}

/// The production span directory: `$HOME/.mnemos/otel/` — the `data_dir`
/// truth, one fixed sub-directory, no variable component.
pub(crate) fn production_otel_dir() -> Result<PathBuf, OtelExportError> {
    crate::memory_store::data_dir()
        .map(|d| d.join(OTEL_DIR_NAME))
        .map_err(|_| OtelExportError::NoHome)
}

/// Atomically write one span line under its content-addressed name and
/// return the filename. Idempotent: identical content maps to the identical
/// name, and an existing file short-circuits to `Ok` without a rewrite
/// (same bytes by construction — the name IS their hash).
pub(crate) fn export_otel_span(dir: &Path, json: &str) -> Result<String, OtelExportError> {
    std::fs::create_dir_all(dir).map_err(|_| OtelExportError::Io)?;
    let digest = Sha256::digest(json.as_bytes());
    let name = format!("{}{}", hex_lower(&digest), OTEL_FILE_SUFFIX);
    let path = dir.join(&name);
    if path.exists() {
        return Ok(name);
    }
    let mut bytes = Vec::with_capacity(json.len() + 1);
    bytes.extend_from_slice(json.as_bytes());
    bytes.push(b'\n');
    crate::memory_store::atomic_write(&path, &bytes).map_err(|_| OtelExportError::Io)?;
    Ok(name)
}

/// The ONE consult-side seam both executors consume — one fn, zero drift
/// between the frontier and local routes. Returns the receipt line to append,
/// or `None` when the setting is Off (the default surface stays byte-unchanged).
#[derive(Clone, Copy, Debug)]
pub(crate) struct ConsultOtelCtx<'a> {
    /// Resolved opt-in setting (env in production; injected in tests).
    pub setting: OtelExportSetting,
    /// Target directory override (tests); `None` = the production dir.
    pub dir_override: Option<&'a Path>,
    /// Route backend label.
    pub backend: &'a str,
    /// Response-echoed model id.
    pub model: &'a str,
    /// Live wire turns (executor-counted, receipt-identical).
    pub turns_u8: u8,
    /// Last-turn request sha256.
    pub request_sha_32: &'a [u8; 32],
    /// Last-turn response sha256.
    pub response_sha_32: &'a [u8; 32],
    /// Ceremony start (captured once; L4).
    pub started: SystemTime,
    /// Ceremony end (captured once; L4).
    pub ended: SystemTime,
}

/// Project + belt + write for one answered consult; every refusal is a
/// VISIBLE typed line: a side artifact may fail loudly, but it never destroys
/// the answer card and never fails silently.
pub(crate) fn consult_otel_line(
    outcome: &crate::agent_loop::AgentLoopOutcome,
    ctx: &ConsultOtelCtx<'_>,
) -> Option<String> {
    match ctx.setting {
        OtelExportSetting::Off => None,
        OtelExportSetting::Invalid => Some(
            "otel: export denied (SINABRO_OTEL_EXPORT invalid; 1 enables, unset/0 disables)"
                .to_string(),
        ),
        OtelExportSetting::On => Some(run_consult_export(outcome, ctx)),
    }
}

fn run_consult_export(
    outcome: &crate::agent_loop::AgentLoopOutcome,
    ctx: &ConsultOtelCtx<'_>,
) -> String {
    // Clock capture must be sane (fail-closed, typed; never a 1970 lie).
    let (Ok(start), Ok(end)) = (
        ctx.started.duration_since(SystemTime::UNIX_EPOCH),
        ctx.ended.duration_since(SystemTime::UNIX_EPOCH),
    ) else {
        return "otel: export denied (clock before epoch)".to_string();
    };
    let (Ok(start_ns), Ok(end_ns)) = (
        u64::try_from(start.as_nanos()),
        u64::try_from(end.as_nanos()),
    ) else {
        return "otel: export denied (clock overflow)".to_string();
    };
    // Redaction belt: the response-echoed model id is the only foreign-
    // controlled string that reaches the file; a hostile local server echoing
    // a key-shaped "model" must not get it persisted for third-party
    // collectors. Deny-not-fix; classify-fail = deny.
    let fragments = [ctx.model];
    match redact(&RedactionRequest {
        fragments: &fragments,
        candidate_memory_ids: &[],
        deleted_ids: &[],
        include_private_memory: false,
    }) {
        Ok(receipt) if receipt.secret_fragments_denied_u32() == 0 => {}
        _ => return "otel: export withheld (model string secret-shaped)".to_string(),
    }
    let guard = crate::provider::trajectory_health::recommended_action(outcome.health);
    let input = OtelSpanInput {
        service_version: env!("CARGO_PKG_VERSION"),
        backend: ctx.backend,
        model: ctx.model,
        stop_label: outcome.stop.class_label(),
        trail: &outcome.tool_trail,
        guard_label: guard.class_label(),
        guard_signals_u16: outcome.health.bits(),
        turns_u8: ctx.turns_u8,
        tool_iters_u8: outcome.iterations_u8,
        reads_u8: outcome.reads_u8,
        input_tokens_u64: outcome.input_tokens_u64,
        output_tokens_u64: outcome.output_tokens_u64,
        cached_tokens_u64: u64::from(outcome.cost.cached_tokens_u32()),
        usd_micros_u64: u64::from(outcome.cost.usd_micros().get()),
        static_prefix_bytes_u32: outcome.cache_plan.static_prefix_bytes_u32,
        dynamic_suffix_bytes_u32: outcome.cache_plan.dynamic_suffix_bytes_u32,
        stable_prefix_turns_u8: outcome.prefix_stable_turns_u8,
        request_sha_32: *ctx.request_sha_32,
        response_sha_32: *ctx.response_sha_32,
        start_unix_nanos_u64: start_ns,
        end_unix_nanos_u64: end_ns,
    };
    let json = project_otlp_json(&input);
    let dir = match ctx.dir_override {
        Some(d) => d.to_path_buf(),
        None => match production_otel_dir() {
            Ok(d) => d,
            Err(OtelExportError::NoHome) => {
                return "otel: export failed (HOME unresolved)".to_string();
            }
            Err(OtelExportError::Io) => return "otel: export failed (io)".to_string(),
        },
    };
    match export_otel_span(&dir, &json) {
        Ok(name) => {
            let prefix: String = name.chars().take(16).collect();
            format!(
                "otel: exported {prefix}.. spans=1 -> {} (OTLP/JSON; local file; no egress)",
                dir.display()
            )
        }
        Err(OtelExportError::NoHome) => "otel: export failed (HOME unresolved)".to_string(),
        Err(OtelExportError::Io) => "otel: export failed (io)".to_string(),
    }
}

// ---- read the exported OTel spans back (the GUI audit feed) -------------------
//
// This parses the byte-locked OTLP/JSON the writer above produces back into a
// structured per-span view. Std-only field extraction over the FIXED format (no
// JSON crate, no new dependency) — the format is pinned by `GOLDEN_OTLP_JSON` + the
// Python schema lock, so a targeted extractor is sufficient and drift-proof. The
// view carries ids + counts + already-redacted labels only — never raw content.

/// One parsed exported OTel span (the GUI audit feed row). Ids + labels +
/// captured times only — the writer already redacted the model + carries no raw
/// content, so reading is leak-free.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OtelSpanView {
    /// 32-hex trace id (content-derived; L1).
    pub trace_id_hex: String,
    /// 16-hex span id.
    pub span_id_hex: String,
    /// Span name (`sinabro.provider.consult`).
    pub name: String,
    /// Captured ceremony start (unix nanos).
    pub start_unix_nanos_u64: u64,
    /// Captured ceremony end (unix nanos).
    pub end_unix_nanos_u64: u64,
    /// Whether the span completed OK (`status {}`); a non-`loop.completed` stop
    /// maps to `status {code:2}` ⇒ `false`.
    pub ok: bool,
    /// The typed stop class label (`loop.completed` on OK, else the status message).
    pub stop_label: String,
    /// Route backend label (`openrouter` / `local_base`).
    pub backend: String,
    /// Redacted, response-echoed model id.
    pub model: String,
}

/// Why reading the span store failed (typed, fail-closed).
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum OtelReadError {
    /// `$HOME` could not be resolved (no otel dir).
    #[error("HOME unresolved; no otel dir")]
    NoHome,
}

/// Defensive cap on spans read in one feed (bounded GUI render).
const MAX_SPANS_READ: usize = 10_000;

/// Read + parse every well-formed exported span file under `dir`, sorted into
/// chronological feed order (by start time, then trace id for stability). A file
/// that is not a parseable span is skipped (never a false row). Bounded.
#[must_use]
pub fn read_otel_spans(dir: &Path) -> Vec<OtelSpanView> {
    let mut spans = Vec::new();
    let Ok(rd) = std::fs::read_dir(dir) else {
        return spans;
    };
    for dirent in rd.flatten() {
        if spans.len() >= MAX_SPANS_READ {
            break;
        }
        let path = dirent.path();
        let Some(name) = path.file_name().and_then(|n| n.to_str()) else {
            continue;
        };
        if !name.ends_with(OTEL_FILE_SUFFIX) {
            continue;
        }
        let Ok(text) = std::fs::read_to_string(&path) else {
            continue;
        };
        if let Some(view) = parse_otlp_span(&text) {
            spans.push(view);
        }
    }
    spans.sort_by(|a, b| {
        a.start_unix_nanos_u64
            .cmp(&b.start_unix_nanos_u64)
            .then_with(|| a.trace_id_hex.cmp(&b.trace_id_hex))
    });
    spans
}

/// Read the production span store (`~/.mnemos/otel`) for the GUI audit feed.
pub fn read_production_otel_spans() -> Result<Vec<OtelSpanView>, OtelReadError> {
    let dir = production_otel_dir().map_err(|_| OtelReadError::NoHome)?;
    Ok(read_otel_spans(&dir))
}

/// Parse one OTLP/JSON span line into a view (targeted field extraction over the
/// byte-locked format). Returns `None` if the mandatory ids/times are absent or
/// malformed.
fn parse_otlp_span(line: &str) -> Option<OtelSpanView> {
    let trace_id_hex = json_str_field(line, "traceId")?;
    let span_id_hex = json_str_field(line, "spanId")?;
    // `name` also appears in the scope before the spans array — search the span
    // region only (after `"spans":[`) so the SCOPE name never shadows it.
    let spans_at = line.find("\"spans\":[")?;
    let name = json_str_field(&line[spans_at..], "name")?;
    let start_unix_nanos_u64 = json_str_field(line, "startTimeUnixNano")?
        .parse::<u64>()
        .ok()?;
    let end_unix_nanos_u64 = json_str_field(line, "endTimeUnixNano")?
        .parse::<u64>()
        .ok()?;
    // status: `"status":{}` ⇒ OK; `"status":{"code":2,"message":"<stop>"}` ⇒ error.
    let ok = line.contains("\"status\":{}");
    let stop_label = if ok {
        attr_str_value(line, "sinabro.loop.stop").unwrap_or_else(|| "loop.completed".to_string())
    } else {
        json_str_field(line, "message").unwrap_or_else(|| "stop.unknown".to_string())
    };
    let backend = attr_str_value(line, "sinabro.backend").unwrap_or_default();
    let model = attr_str_value(line, "sinabro.model").unwrap_or_default();
    Some(OtelSpanView {
        trace_id_hex,
        span_id_hex,
        name,
        start_unix_nanos_u64,
        end_unix_nanos_u64,
        ok,
        stop_label,
        backend,
        model,
    })
}

/// Extract the string value of `"<key>":"<value>"` (the first occurrence), reading
/// to the next unescaped quote with minimal RFC-8259 unescaping.
fn json_str_field(hay: &str, key: &str) -> Option<String> {
    let pat = format!("\"{key}\":\"");
    let start = hay.find(&pat)? + pat.len();
    read_json_string(&hay[start..])
}

/// Extract an OTLP attribute's stringValue: the value of
/// `{"key":"<attr>","value":{"stringValue":"<v>"}}`.
fn attr_str_value(hay: &str, attr: &str) -> Option<String> {
    let pat = format!("\"key\":\"{attr}\",\"value\":{{\"stringValue\":\"");
    let start = hay.find(&pat)? + pat.len();
    read_json_string(&hay[start..])
}

/// Read a JSON string body (without the opening quote) up to the first unescaped
/// closing quote, applying the short + `\u00xx` escapes. `None` if unterminated.
fn read_json_string(s: &str) -> Option<String> {
    let mut out = String::new();
    let mut chars = s.chars();
    while let Some(c) = chars.next() {
        match c {
            '"' => return Some(out),
            '\\' => match chars.next()? {
                '"' => out.push('"'),
                '\\' => out.push('\\'),
                '/' => out.push('/'),
                'n' => out.push('\n'),
                'r' => out.push('\r'),
                't' => out.push('\t'),
                'b' => out.push('\u{0008}'),
                'f' => out.push('\u{000c}'),
                'u' => {
                    let mut code: u32 = 0;
                    for _ in 0..4 {
                        code = code * 16 + chars.next()?.to_digit(16)?;
                    }
                    out.push(char::from_u32(code).unwrap_or('\u{fffd}'));
                }
                other => out.push(other),
            },
            _ => out.push(c),
        }
    }
    None
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use super::*;
    use crate::agent_loop::{AgentLoopOutcome, AgentLoopStop};
    use mnemos_m_agent::{CacheBreakpointPlan, CostLedger};

    /// The Python-derived golden (scripts/check_otel_export_schema.py;
    /// sha256 83d3992384a2ab447d3dfd71572ff4ebe402a3c9d56690c841a9c64e0c1eb4a0,
    /// 1769 bytes). The script greps THIS constant and byte-compares — edit
    /// only together with the script's pinned inputs.
    const GOLDEN_OTLP_JSON: &str = "{\"resourceSpans\":[{\"resource\":{\"attributes\":[{\"key\":\"service.name\",\"value\":{\"stringValue\":\"sinabro\"}},{\"key\":\"service.version\",\"value\":{\"stringValue\":\"golden-ver\"}}]},\"scopeSpans\":[{\"scope\":{\"name\":\"sinabro.agent_loop\",\"version\":\"golden-ver\"},\"spans\":[{\"traceId\":\"02774a887ee8421a3bbc2fab0c78fea1\",\"spanId\":\"f6309a0c1c857cdc\",\"name\":\"sinabro.provider.consult\",\"kind\":1,\"startTimeUnixNano\":\"1700000000000000000\",\"endTimeUnixNano\":\"1700000001234567890\",\"attributes\":[{\"key\":\"gen_ai.usage.input_tokens\",\"value\":{\"intValue\":\"100\"}},{\"key\":\"gen_ai.usage.output_tokens\",\"value\":{\"intValue\":\"50\"}},{\"key\":\"sinabro.usage.cached_tokens\",\"value\":{\"intValue\":\"25\"}},{\"key\":\"sinabro.loop.turns\",\"value\":{\"intValue\":\"2\"}},{\"key\":\"sinabro.loop.tool_iters\",\"value\":{\"intValue\":\"1\"}},{\"key\":\"sinabro.loop.reads\",\"value\":{\"intValue\":\"1\"}},{\"key\":\"sinabro.loop.stop\",\"value\":{\"stringValue\":\"loop.completed\"}},{\"key\":\"sinabro.loop.trail_verbs\",\"value\":{\"stringValue\":\"index,read\"}},{\"key\":\"sinabro.cost.usd_micros\",\"value\":{\"intValue\":\"0\"}},{\"key\":\"sinabro.cache.static_prefix_bytes\",\"value\":{\"intValue\":\"2048\"}},{\"key\":\"sinabro.cache.dynamic_suffix_bytes\",\"value\":{\"intValue\":\"512\"}},{\"key\":\"sinabro.cache.stable_prefix_turns\",\"value\":{\"intValue\":\"1\"}},{\"key\":\"sinabro.guard.action\",\"value\":{\"stringValue\":\"continue\"}},{\"key\":\"sinabro.guard.signals_hex\",\"value\":{\"stringValue\":\"0x0000\"}},{\"key\":\"sinabro.request_sha256\",\"value\":{\"stringValue\":\"1111111111111111111111111111111111111111111111111111111111111111\"}},{\"key\":\"sinabro.response_sha256\",\"value\":{\"stringValue\":\"2222222222222222222222222222222222222222222222222222222222222222\"}},{\"key\":\"sinabro.backend\",\"value\":{\"stringValue\":\"local_base\"}},{\"key\":\"sinabro.model\",\"value\":{\"stringValue\":\"naite-local-smoke\"}}],\"status\":{}}]}]}]}";

    fn golden_trail() -> Vec<String> {
        vec!["index".to_string(), "read 1".to_string()]
    }

    fn golden_input(trail: &[String]) -> OtelSpanInput<'_> {
        OtelSpanInput {
            service_version: "golden-ver",
            backend: "local_base",
            model: "naite-local-smoke",
            stop_label: "loop.completed",
            trail,
            guard_label: "continue",
            guard_signals_u16: 0,
            turns_u8: 2,
            tool_iters_u8: 1,
            reads_u8: 1,
            input_tokens_u64: 100,
            output_tokens_u64: 50,
            cached_tokens_u64: 25,
            usd_micros_u64: 0,
            static_prefix_bytes_u32: 2048,
            dynamic_suffix_bytes_u32: 512,
            stable_prefix_turns_u8: 1,
            request_sha_32: [0x11; 32],
            response_sha_32: [0x22; 32],
            start_unix_nanos_u64: 1_700_000_000_000_000_000,
            end_unix_nanos_u64: 1_700_000_001_234_567_890,
        }
    }

    #[test]
    fn golden_byte_exact_cross_language_lock() {
        let trail = golden_trail();
        let json = project_otlp_json(&golden_input(&trail));
        assert_eq!(json, GOLDEN_OTLP_JSON);
        assert_eq!(json.len(), 1769);
        assert!(!json.contains('\n'), "one JSONL line, no embedded newline");
    }

    #[test]
    fn golden_parses_as_structurally_valid_otlp() {
        let trail = golden_trail();
        let json = project_otlp_json(&golden_input(&trail));
        let v: serde_json::Value = serde_json::from_str(&json).expect("valid JSON");
        let span = &v["resourceSpans"][0]["scopeSpans"][0]["spans"][0];
        let trace_id = span["traceId"].as_str().unwrap();
        let span_id = span["spanId"].as_str().unwrap();
        assert_eq!(trace_id.len(), 32);
        assert_eq!(span_id.len(), 16);
        assert!(
            trace_id
                .chars()
                .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase())
        );
        assert!(
            span_id
                .chars()
                .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase())
        );
        assert_ne!(trace_id, "0".repeat(32), "all-zero traceId is invalid OTLP");
        assert_ne!(span_id, "0".repeat(16), "all-zero spanId is invalid OTLP");
        // protojson: enum as number, u64 as string.
        assert!(span["kind"].is_number());
        assert!(span["startTimeUnixNano"].is_string());
        assert!(span["endTimeUnixNano"].is_string());
        let attrs = span["attributes"].as_array().unwrap();
        assert_eq!(attrs.len(), 18, "the locked 18-attribute set");
        for attr in attrs {
            let value = attr["value"].as_object().unwrap();
            assert_eq!(value.len(), 1);
            if let Some(int_value) = value.get("intValue") {
                assert!(int_value.is_string(), "int64 must encode as a string");
            }
        }
        assert!(span["status"].as_object().unwrap().is_empty());
    }

    #[test]
    fn determinism_and_id_sensitivity() {
        let trail = golden_trail();
        let a = project_otlp_json(&golden_input(&trail));
        let b = project_otlp_json(&golden_input(&trail));
        assert_eq!(a, b, "same captured inputs => identical bytes (L2)");
        let mut flipped = golden_input(&trail);
        flipped.response_sha_32 = [0x23; 32];
        let c = project_otlp_json(&flipped);
        assert_ne!(a, c);
        let va: serde_json::Value = serde_json::from_str(&a).unwrap();
        let vc: serde_json::Value = serde_json::from_str(&c).unwrap();
        let id = |v: &serde_json::Value, k: &str| {
            v["resourceSpans"][0]["scopeSpans"][0]["spans"][0][k]
                .as_str()
                .unwrap()
                .to_string()
        };
        assert_ne!(id(&va, "traceId"), id(&vc, "traceId"));
        assert_ne!(id(&va, "spanId"), id(&vc, "spanId"));
    }

    #[test]
    fn escaping_torture_roundtrips() {
        let trail = golden_trail();
        let mut input = golden_input(&trail);
        let nasty = "q\"uote\\back\nnew\tline\u{1}ctl 한글";
        input.model = nasty;
        let json = project_otlp_json(&input);
        let v: serde_json::Value = serde_json::from_str(&json).expect("escaped output parses");
        let attrs = v["resourceSpans"][0]["scopeSpans"][0]["spans"][0]["attributes"]
            .as_array()
            .unwrap()
            .clone();
        let model = attrs
            .iter()
            .find(|a| a["key"] == "sinabro.model")
            .and_then(|a| a["value"]["stringValue"].as_str())
            .unwrap()
            .to_string();
        assert_eq!(model, nasty, "semantic round-trip through the escaper");
    }

    #[test]
    fn trail_exports_verb_only_never_paths() {
        let trail = vec![
            "index".to_string(),
            "read 5".to_string(),
            "file /tmp/very-secret-path.txt".to_string(),
            "denied-tool TOOL: exec run /bin/sh".to_string(),
            "guard-lockdown".to_string(),
        ];
        let input = OtelSpanInput {
            trail: &trail,
            ..golden_input(&trail)
        };
        let json = project_otlp_json(&input);
        assert!(json.contains("index,read,file,denied-tool,guard-lockdown"));
        assert!(!json.contains("/tmp/"), "paths structurally absent (IV-O2)");
        assert!(!json.contains("/bin/sh"), "model-authored args absent");
    }

    #[test]
    fn model_attr_is_capped_char_safe() {
        let trail = golden_trail();
        let mut input = golden_input(&trail);
        let long = "한".repeat(400); // 3 bytes/char => 1200 bytes
        input.model = &long;
        let json = project_otlp_json(&input);
        let v: serde_json::Value = serde_json::from_str(&json).unwrap();
        let attrs = v["resourceSpans"][0]["scopeSpans"][0]["spans"][0]["attributes"]
            .as_array()
            .unwrap()
            .clone();
        let model = attrs
            .iter()
            .find(|a| a["key"] == "sinabro.model")
            .and_then(|a| a["value"]["stringValue"].as_str())
            .unwrap()
            .to_string();
        assert!(model.len() <= MODEL_ATTR_CAP_BYTES);
        assert!(model.chars().all(|c| c == '한'), "char-boundary safe");
    }

    #[test]
    fn non_completed_stop_maps_to_error_status() {
        let trail = golden_trail();
        let mut input = golden_input(&trail);
        input.stop_label = "loop.guard_lockdown";
        let json = project_otlp_json(&input);
        let v: serde_json::Value = serde_json::from_str(&json).unwrap();
        let status = &v["resourceSpans"][0]["scopeSpans"][0]["spans"][0]["status"];
        assert_eq!(status["code"], 2);
        assert_eq!(status["message"], "loop.guard_lockdown");
    }

    #[test]
    fn resolve_is_strict_tri_state() {
        assert_eq!(resolve_otel_export(None), OtelExportSetting::Off);
        assert_eq!(resolve_otel_export(Some("0")), OtelExportSetting::Off);
        assert_eq!(resolve_otel_export(Some("1")), OtelExportSetting::On);
        for bad in ["true", "yes", "2", " 1", "1 ", "on", ""] {
            assert_eq!(
                resolve_otel_export(Some(bad)),
                OtelExportSetting::Invalid,
                "{bad:?} must be refused, never guessed"
            );
        }
    }

    fn temp_dir(tag: &str) -> std::path::PathBuf {
        let dir =
            std::env::temp_dir().join(format!("sinabro-otel-test-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        dir
    }

    #[test]
    fn export_writes_content_addressed_and_idempotent() {
        let dir = temp_dir("export");
        let trail = golden_trail();
        let json = project_otlp_json(&golden_input(&trail));
        let name = export_otel_span(&dir, &json).expect("first export");
        let expected = format!(
            "{}{}",
            hex_lower(&Sha256::digest(json.as_bytes())),
            ".otlp.jsonl"
        );
        assert_eq!(name, expected, "filename IS the content hash (L1)");
        let on_disk = std::fs::read_to_string(dir.join(&name)).unwrap();
        assert_eq!(on_disk, format!("{json}\n"));
        // Idempotent re-export: same name, still exactly one file.
        let name2 = export_otel_span(&dir, &json).expect("re-export");
        assert_eq!(name2, name);
        let count = std::fs::read_dir(&dir).unwrap().count();
        assert_eq!(count, 1);
        let _ = std::fs::remove_dir_all(&dir);
    }

    fn outcome_for_line() -> AgentLoopOutcome {
        AgentLoopOutcome {
            answer: Some("ok".to_string()),
            stop: AgentLoopStop::Completed,
            iterations_u8: 1,
            reads_u8: 1,
            tool_trail: golden_trail(),
            input_tokens_u64: 100,
            output_tokens_u64: 50,
            cost: CostLedger::new(),
            cache_plan: CacheBreakpointPlan {
                static_prefix_bytes_u32: 2048,
                dynamic_suffix_bytes_u32: 512,
                breakpoints_u8: 1,
            },
            prefix_stable_turns_u8: 1,
            health: crate::commands::model_route::TrajectoryHealth::healthy(),
            verified_file_reads: Vec::new(),
        }
    }

    fn ctx_on<'a>(dir: &'a std::path::Path, model: &'a str) -> ConsultOtelCtx<'a> {
        ConsultOtelCtx {
            setting: OtelExportSetting::On,
            dir_override: Some(dir),
            backend: "local_base",
            model,
            turns_u8: 2,
            request_sha_32: &[0x11; 32],
            response_sha_32: &[0x22; 32],
            started: SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(1_700_000_000),
            ended: SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(1_700_000_001),
        }
    }

    #[test]
    fn consult_line_off_is_none_invalid_is_typed() {
        let outcome = outcome_for_line();
        let dir = temp_dir("line-off");
        let mut ctx = ctx_on(&dir, "m");
        ctx.setting = OtelExportSetting::Off;
        assert_eq!(consult_otel_line(&outcome, &ctx), None);
        ctx.setting = OtelExportSetting::Invalid;
        let line = consult_otel_line(&outcome, &ctx).unwrap();
        assert!(line.starts_with("otel: export denied (SINABRO_OTEL_EXPORT invalid"));
        assert!(!dir.exists(), "no file on Off/Invalid");
    }

    #[test]
    fn consult_line_on_writes_and_reports() {
        let outcome = outcome_for_line();
        let dir = temp_dir("line-on");
        let ctx = ctx_on(&dir, "naite-local-smoke");
        let line = consult_otel_line(&outcome, &ctx).unwrap();
        assert!(line.starts_with("otel: exported "), "line: {line}");
        assert!(line.contains("spans=1"));
        let entries: Vec<_> = std::fs::read_dir(&dir).unwrap().collect();
        assert_eq!(entries.len(), 1);
        let content = std::fs::read_to_string(entries[0].as_ref().unwrap().path()).unwrap();
        let v: serde_json::Value =
            serde_json::from_str(content.trim_end_matches('\n')).expect("file parses");
        assert!(v["resourceSpans"][0]["scopeSpans"][0]["spans"][0]["traceId"].is_string());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn consult_line_withholds_secret_shaped_model() {
        let outcome = outcome_for_line();
        let dir = temp_dir("line-secret");
        let secret_model = "key = \"suiprivkey1qexamplenotreal\"";
        let ctx = ctx_on(&dir, secret_model);
        let line = consult_otel_line(&outcome, &ctx).unwrap();
        assert_eq!(line, "otel: export withheld (model string secret-shaped)");
        assert!(!dir.exists(), "withheld export writes nothing");
    }

    #[test]
    fn consult_line_denies_pre_epoch_clock() {
        let outcome = outcome_for_line();
        let dir = temp_dir("line-clock");
        let mut ctx = ctx_on(&dir, "m");
        ctx.started = SystemTime::UNIX_EPOCH - std::time::Duration::from_secs(1);
        let line = consult_otel_line(&outcome, &ctx).unwrap();
        assert_eq!(line, "otel: export denied (clock before epoch)");
        assert!(!dir.exists());
    }

    // ---- read_otel_spans parser --------------------------------------------

    #[test]
    fn read_parses_the_golden_span() {
        let v = parse_otlp_span(GOLDEN_OTLP_JSON).expect("golden parses");
        assert_eq!(v.trace_id_hex, "02774a887ee8421a3bbc2fab0c78fea1");
        assert_eq!(v.span_id_hex, "f6309a0c1c857cdc");
        assert_eq!(v.name, "sinabro.provider.consult");
        assert_eq!(v.start_unix_nanos_u64, 1_700_000_000_000_000_000);
        assert_eq!(v.end_unix_nanos_u64, 1_700_000_001_234_567_890);
        assert!(v.ok);
        assert_eq!(v.stop_label, "loop.completed");
        assert_eq!(v.backend, "local_base");
        assert_eq!(v.model, "naite-local-smoke");
    }

    #[test]
    fn export_then_read_round_trips_the_real_writer_output() {
        let trail: Vec<String> = vec!["index a".to_string(), "read b".to_string()];
        let input = golden_input(&trail);
        let json = project_otlp_json(&input);
        // parse the writer's output directly...
        let v = parse_otlp_span(&json).expect("parse");
        assert_eq!(v.name, "sinabro.provider.consult");
        assert_eq!(v.backend, "local_base");
        assert_eq!(v.model, "naite-local-smoke");
        assert!(v.ok);
        // ...and via the real on-disk store (export -> read_otel_spans).
        let dir = temp_dir("read-rt");
        export_otel_span(&dir, &json).expect("export");
        let spans = read_otel_spans(&dir);
        assert_eq!(spans.len(), 1, "the exported span is read back");
        assert_eq!(spans[0], v);
        // a missing dir is an empty feed, not an error.
        assert!(read_otel_spans(&dir.join("nope")).is_empty());
    }

    #[test]
    fn read_maps_a_noncompleted_stop_to_not_ok() {
        let trail: Vec<String> = Vec::new();
        let mut input = golden_input(&trail);
        input.stop_label = "loop.budget_exhausted";
        let json = project_otlp_json(&input);
        let v = parse_otlp_span(&json).expect("parse");
        assert!(
            !v.ok,
            "a non-loop.completed stop is status code 2 => not ok"
        );
        assert_eq!(v.stop_label, "loop.budget_exhausted");
    }
}
