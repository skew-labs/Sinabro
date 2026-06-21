//! `provider::egress` — the bounded provider HTTP egress transport
//! (G-WP-09 atoms #603 G.8.9, #604 G.8.10, #606 G.8.12, #610 G.8.16).
//!
//! This is the FIRST real network capability in the project. It lifts the Phase-0
//! no-egress lock for PROVIDERS ONLY (Anthropic/OpenAI/Gemini/OpenRouter; the v1
//! live codec is OpenRouter only per SOT — see `send_live_text`), under the
//! safety kernel, as the designed RD-49 path — never a disabled-path workaround. Funds
//! custody is UNCHANGED: wallet / gas / chain / mainnet hosts are structurally
//! unrepresentable here and rejected by the allowlist (funds-egress = 0).
//!
//! Triple-gated and disabled by default — autonomous Phase-0 makes ZERO live
//! calls. The `provider-egress` cargo feature is OFF by default, so without it the
//! `reqwest` transport is not compiled and [`ProviderTransport::send`] returns
//! [`EgressDenied::TransportNotCompiled`]. The payload's
//! [`BoundedConsultRequest::live_dispatch_allowed`](crate::provider::frontier_consult::BoundedConsultRequest)
//! is the invariant `false` (flipped only by a separate same-message approval
//! ceremony, absent here), so `send` denies a non-live-dispatch request. And an
//! explicit [`EgressApproval`] granted in the same turn is required. Only an
//! allowlisted provider host over TLS, carrying a [`RedactedConsult`]
//! (type-structurally free of raw private content), can ever be sent.
//!
//! Secret custody (`G-G-SECRET-ZERO`, #604): the API key is held as a
//! [`SecretRefView`] (value never loaded); the value is read only at the TLS send
//! boundary (the feature-gated path) and dropped immediately, never logged /
//! cloned / persisted.
//!
//! Reuse (no reinvention): [`BoundedConsultRequest`] from
//! [`crate::provider::frontier_consult`], [`RedactionReceipt`] from
//! [`crate::provider::redaction`], [`SecretRefView`] from [`crate::secrets`]. New
//! here: [`ProviderHost`], [`RedactedConsult`], [`ProviderTransport`],
//! [`EgressApproval`], [`EgressDenied`].

use crate::command::CommandEnvelope;
use crate::commands::model_route::ConsultTrigger;
use crate::provider::frontier_consult::BoundedConsultRequest;
use crate::provider::redaction::RedactionReceipt;
use crate::repl::approval::ApprovalPrompt;
use crate::secrets::SecretRefView;
use crate::tui::approval_modal::ApprovalModal;

/// An allowlisted external provider host. ONLY these are reachable. There is
/// deliberately NO variant for a wallet, gas, chain, or mainnet RPC host — making
/// funds-egress structurally impossible. The enum is intentionally NOT
/// `#[non_exhaustive]` so the closed set stays auditable.
#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProviderHost {
    /// Anthropic API (direct; no codec in v1 — OpenRouter is the SOT backend).
    Anthropic = 1,
    /// OpenAI API (direct; no codec in v1).
    OpenAi = 2,
    /// Google Gemini API (direct; no codec in v1).
    Gemini = 3,
    /// OpenRouter — the SOT LLM backend (`RuntimeLlmBackend { OpenRouter=1 }`,
    /// `MNEMOS_ATOM_PLAN.md:310/1024`, OpenAI-compatible, OpenRouter→DeepSeek
    /// default). This is the ONLY host with a live codec in v1.
    OpenRouter = 4,
}

impl ProviderHost {
    /// The fixed TLS host authority for this provider (never a funds/chain host).
    #[must_use]
    pub const fn host(self) -> &'static str {
        match self {
            Self::Anthropic => "api.anthropic.com",
            Self::OpenAi => "api.openai.com",
            Self::Gemini => "generativelanguage.googleapis.com",
            Self::OpenRouter => "openrouter.ai",
        }
    }

    /// The full TLS base URL for this provider (always `https://`).
    #[must_use]
    pub const fn base_url(self) -> &'static str {
        match self {
            Self::Anthropic => "https://api.anthropic.com",
            Self::OpenAi => "https://api.openai.com",
            Self::Gemini => "https://generativelanguage.googleapis.com",
            Self::OpenRouter => "https://openrouter.ai/api/v1",
        }
    }

    /// The environment-variable name the key reference resolves from at the TLS
    /// boundary (feature-gated path only).
    #[cfg(feature = "provider-egress")]
    const fn key_env(self) -> &'static str {
        match self {
            Self::Anthropic => "ANTHROPIC_API_KEY",
            Self::OpenAi => "OPENAI_API_KEY",
            Self::Gemini => "GEMINI_API_KEY",
            Self::OpenRouter => "OPENROUTER_API_KEY",
        }
    }
}

/// The closed set of allowlisted provider hosts — the audit anchor for "providers
/// only". A host not in this set (including every funds / chain / mainnet RPC
/// host) is unreachable.
pub const ALLOWLISTED_PROVIDERS: [ProviderHost; 4] = [
    ProviderHost::Anthropic,
    ProviderHost::OpenAi,
    ProviderHost::Gemini,
    ProviderHost::OpenRouter,
];

/// Whether `host` is an allowlisted provider host. Any host that is not exactly an
/// allowlisted provider host — including every wallet / gas / chain / mainnet RPC
/// host — is rejected (funds-host unreachable, #610).
#[must_use]
pub fn host_is_allowlisted(host: &str) -> bool {
    ALLOWLISTED_PROVIDERS.iter().any(|p| p.host() == host)
}

/// A consult payload that is type-structurally free of raw private content: it
/// carries only the bounded, redacted, hash-linked [`BoundedConsultRequest`] and
/// the [`RedactionReceipt`] proving the body was redacted. It cannot be
/// constructed unless the receipt proves `provider_body_stored == false` and the
/// request is advisory + private-memory-free — making replan Operational-Law 3
/// physical (#606): the egress payload cannot carry raw private content.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RedactedConsult {
    /// The bounded consult request (disabled-by-default; advisory-only).
    pub request: BoundedConsultRequest,
    /// The before-send redaction receipt (`provider_body_stored == false`).
    pub redaction: RedactionReceipt,
}

impl RedactedConsult {
    /// Build a redacted consult, or `None` when the inputs do not prove a safe
    /// payload: the raw body must not be stored, and the request must be
    /// advisory-only with no private memory.
    #[must_use]
    pub fn new(request: BoundedConsultRequest, redaction: RedactionReceipt) -> Option<Self> {
        if redaction.provider_body_stored() {
            return None;
        }
        if request.packet.private_memory_included || !request.packet.advisory_only {
            return None;
        }
        Some(Self { request, redaction })
    }

    /// The redacted-payload hash — the only content reference that ever leaves.
    #[must_use]
    pub const fn payload_hash_32(&self) -> [u8; 32] {
        self.redaction.redacted_payload_hash_32()
    }
}

/// Proof that a same-message egress approval ceremony was completed this turn. An
/// egress send is denied unless one of these is present and granted. There is no
/// `Default` and no auto-grant: it is constructed only at an explicit approval
/// ceremony (the cockpit approval modal #583/#607).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EgressApproval {
    granted: bool,
}

impl EgressApproval {
    /// A denied (not-granted) approval — the autonomous Phase-0 default.
    #[must_use]
    pub const fn denied() -> Self {
        Self { granted: false }
    }

    /// Grant approval. Constructed ONLY at a same-message approval ceremony; never
    /// auto-granted on any code path that runs without explicit operator action.
    #[must_use]
    pub const fn grant() -> Self {
        Self { granted: true }
    }

    /// Whether approval was granted.
    #[must_use]
    pub const fn is_granted(self) -> bool {
        self.granted
    }
}

/// Why an egress send was denied (fail-closed). Every denial is explicit and
/// visible — there is no silent fallback.
#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EgressDenied {
    /// The `provider-egress` cargo feature is off — no transport is compiled (the
    /// offline std-core default).
    TransportNotCompiled = 1,
    /// The request is not approved for live dispatch
    /// (`live_dispatch_allowed == false`).
    LiveDispatchNotAllowed = 2,
    /// No same-message approval was granted.
    ApprovalMissing = 3,
    /// The target host is not an allowlisted provider host
    /// (funds / chain / other).
    HostNotAllowlisted = 4,
    /// The API-key reference is missing / not resolvable.
    KeyMissing = 5,
    /// The transport call itself failed (network / TLS / status).
    TransportError = 6,
}

/// The outcome of a permitted egress send: the host, the HTTP status, and the
/// SHA-256 of the response body (advisory until locally verified).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EgressOutcome {
    /// The provider host the consult was sent to.
    pub host: ProviderHost,
    /// The HTTP status code.
    pub status_u16: u16,
    /// SHA-256 of the response body (advisory; locally verified before trust).
    pub response_hash_32: [u8; 32],
}

/// The bounded provider HTTP egress transport. Holds the API-key reference (a
/// [`SecretRefView`] whose value is never loaded except at the TLS send boundary,
/// #604) and gates every send.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ProviderTransport {
    host: ProviderHost,
    key: SecretRefView,
}

impl ProviderTransport {
    /// A transport for `host` authenticating with the key reference `key` (the
    /// value is never loaded here).
    #[must_use]
    pub const fn new(host: ProviderHost, key: SecretRefView) -> Self {
        Self { host, key }
    }

    /// The provider host.
    #[must_use]
    pub const fn host(self) -> ProviderHost {
        self.host
    }

    /// Pre-flight gate: classify whether a send WOULD be permitted, performing no
    /// I/O. Returns `Ok(())` only when the request is live-dispatch approved, the
    /// same-message approval is granted, the host is allowlisted, and the key
    /// reference is present. In Phase 0 this cannot pass — `live_dispatch_allowed`
    /// is the invariant `false`.
    pub fn preflight(
        &self,
        consult: &RedactedConsult,
        approval: EgressApproval,
    ) -> Result<(), EgressDenied> {
        if !consult.request.live_dispatch_allowed {
            return Err(EgressDenied::LiveDispatchNotAllowed);
        }
        if !approval.is_granted() {
            return Err(EgressDenied::ApprovalMissing);
        }
        if !host_is_allowlisted(self.host.host()) {
            return Err(EgressDenied::HostNotAllowlisted);
        }
        if self.key.location == crate::secrets::SecretLocation::Missing
            || !self.key.value_never_loaded
        {
            return Err(EgressDenied::KeyMissing);
        }
        Ok(())
    }

    /// Send a redacted consult to the provider. ALWAYS denied in the default
    /// (offline, no-feature) build — the reqwest transport is not compiled. Even
    /// with the feature enabled, [`preflight`](Self::preflight) must pass, which in
    /// Phase 0 it cannot. No byte leaves unless every gate passes.
    pub fn send(
        &self,
        consult: &RedactedConsult,
        approval: EgressApproval,
    ) -> Result<EgressOutcome, EgressDenied> {
        self.preflight(consult, approval)?;
        self.send_over_tls(consult)
    }

    /// Offline std-core: no transport is compiled. The capability exists behind the
    /// `provider-egress` feature (reqwest, vendored) but is not built by default.
    #[cfg(not(feature = "provider-egress"))]
    #[allow(clippy::unused_self)]
    fn send_over_tls(&self, _consult: &RedactedConsult) -> Result<EgressOutcome, EgressDenied> {
        Err(EgressDenied::TransportNotCompiled)
    }

    /// Feature-gated TLS transport. Reached ONLY after [`preflight`](Self::preflight)
    /// passes (live-dispatch approved + same-message approval + allowlisted host +
    /// key present). The key value is loaded ONLY here, at the TLS boundary, and
    /// dropped at scope end (never logged / cloned / persisted); the body carries
    /// only the redacted payload hash — never raw text.
    #[cfg(feature = "provider-egress")]
    fn send_over_tls(&self, consult: &RedactedConsult) -> Result<EgressOutcome, EgressDenied> {
        let key = crate::secrets::Secret::new(
            std::env::var(self.host.key_env()).map_err(|_| EgressDenied::KeyMissing)?,
        );
        let client = reqwest::blocking::Client::builder()
            .timeout(std::time::Duration::from_millis(u64::from(
                consult.request.timeout_ms_u32,
            )))
            .build()
            .map_err(|_| EgressDenied::TransportError)?;
        let body = consult.payload_hash_32().to_vec();
        let response = client
            .post(self.host.base_url())
            .header("authorization", format!("Bearer {}", key.expose_secret()))
            .body(body)
            .send()
            .map_err(|_| EgressDenied::TransportError)?;
        let status_u16 = response.status().as_u16();
        let bytes = response.bytes().map_err(|_| EgressDenied::TransportError)?;
        Ok(EgressOutcome {
            host: self.host,
            status_u16,
            response_hash_32: crate::sha256_32(bytes.as_ref()),
        })
    }
}

// ---- P (owner-authorized 2026-06-10; OpenRouter per SOT): OpenAI-compatible codec
//
// SOT: `MNEMOS_ATOM_PLAN.md:310/1024` — `RuntimeLlmBackend { OpenRouter=1 }`,
// "trait은 OpenAI호환(OpenRouter→DeepSeek 기본)". The live consult goes to
// OpenRouter's OpenAI-compatible Chat Completions API: POST {base}/chat/completions
// with an `authorization: Bearer <OPENROUTER_API_KEY>` header and a
// {model, max_tokens, messages:[{role,content}]} JSON body; the response carries
// `choices[].message.content` (the answer), `choices[].finish_reason`, and
// `usage.{prompt_tokens,completion_tokens}`. `send_over_tls` above is the older
// G-WP-09 hash-POST skeleton (dead). Threat model:
// ops/evidence/stage_g/gui_desktop/PROVIDER_EGRESS_THREAT_MODEL.md.

/// Why a live consult failed (fail-closed; every label is static + secret-zero).
#[cfg(feature = "provider-egress")]
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum LiveConsultError {
    /// A gate in [`ProviderTransport::preflight`] (or the key/transport layer)
    /// denied the send.
    Denied(EgressDenied),
    /// The v1 codec implements OpenRouter (OpenAI-compatible) only; any other
    /// allowlisted host is an explicit typed denial (no silent fallback).
    CodecNotImplemented,
    /// The provider answered with a non-200 status. Carries ONLY the status and
    /// a sanitized error class label — never response prose.
    Http {
        /// The HTTP status code.
        status_u16: u16,
        /// The sanitized (alnum + `_`, ≤40 chars) error class label.
        error_type: String,
    },
    /// The 200 response body did not parse as a Chat Completions answer.
    MalformedResponse,
    /// The owner cancelled the streaming turn mid-flight (S-C true cancel) — a
    /// cooperative abort observed between SSE frames. Not a transport failure.
    Cancelled,
}

/// The outcome of ONE permitted live consult: the answer text, the
/// response-echoed model id, finish reason, token usage, and the request/response
/// SHA-256 receipts. Carries no key and no raw response body.
#[cfg(feature = "provider-egress")]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LiveConsultOutcome {
    /// The provider host the consult was sent to.
    pub host: ProviderHost,
    /// The HTTP status code (200 on this path).
    pub status_u16: u16,
    /// The model id echoed by the response (not assumed from the request).
    pub model: String,
    /// The answer: `choices[0].message.content`.
    pub answer_text: String,
    /// The response `finish_reason` (`stop`, `length`, ...).
    pub stop_reason: String,
    /// Input tokens billed (`usage.prompt_tokens`).
    pub input_tokens: u64,
    /// Output tokens billed (`usage.completion_tokens`).
    pub output_tokens: u64,
    /// Provider-reported cached prompt tokens — OpenAI-compatible
    /// `usage.prompt_tokens_details.cached_tokens`, or DeepSeek's
    /// `usage.prompt_cache_hit_tokens`; `0` when the provider reports
    /// neither. Cache-savings visibility (P2-1), never a charge input.
    pub cached_tokens: u64,
    /// SHA-256 of the exact request body sent.
    pub request_hash_32: [u8; 32],
    /// SHA-256 of the exact response body received.
    pub response_hash_32: [u8; 32],
}

/// The parsed fields of a 200 Chat Completions response (crate-internal).
/// Shared codec truth: consumed by this frontier codec AND the loopback
/// `local_chat` transport (P3-3) — ONE parse, no second codec to drift.
#[cfg(any(
    feature = "provider-egress",
    feature = "local-mlx",
    feature = "local-vllm"
))]
pub(crate) struct ParsedAnswer {
    pub(crate) model: String,
    pub(crate) answer_text: String,
    pub(crate) stop_reason: String,
    pub(crate) input_tokens: u64,
    pub(crate) output_tokens: u64,
    pub(crate) cached_tokens: u64,
}

/// Build the OpenAI-compatible Chat Completions request body. `serde_json` owns
/// all string escaping (quotes / newlines / non-ASCII travel full-fidelity).
/// Pure + deterministic — unit-tested by round-trip parse. Shared with the
/// loopback `local_chat` transport (P3-3): mlx/ollama/vLLM speak this SAME wire.
#[cfg(any(
    feature = "provider-egress",
    feature = "local-mlx",
    feature = "local-vllm"
))]
pub(crate) fn openai_chat_body(
    model: &str,
    max_output_tokens_u32: u32,
    system: &str,
    question: &str,
) -> String {
    // Step 1 of wrapping the LLM into a sinabro agent: a `system` message carries
    // sinabro's identity + capability catalog, so the model answers AS sinabro
    // (not as a bare deepseek). The agentic tool-call loop is step 2 (m-agent).
    serde_json::json!({
        "model": model,
        "max_tokens": max_output_tokens_u32,
        "messages": [
            { "role": "system", "content": system },
            { "role": "user", "content": question },
        ],
    })
    .to_string()
}

/// Parse a 200 Chat Completions response: lift `choices[0].message.content` (the
/// answer), `finish_reason`, model, and `usage.{prompt,completion}_tokens`.
/// Returns `None` when the body is not a Chat Completions answer (fail-closed;
/// caller renders a typed malformed-response label, never the body). Shared
/// with the loopback `local_chat` transport (P3-3) — same wire, same parse.
#[cfg(any(
    feature = "provider-egress",
    feature = "local-mlx",
    feature = "local-vllm"
))]
pub(crate) fn parse_openai_chat_response(bytes: &[u8]) -> Option<ParsedAnswer> {
    let v: serde_json::Value = serde_json::from_slice(bytes).ok()?;
    let first = v.get("choices")?.as_array()?.first()?;
    let answer_text = first.get("message")?.get("content")?.as_str()?.to_string();
    let stop_reason = first
        .get("finish_reason")
        .and_then(serde_json::Value::as_str)
        .unwrap_or("unknown")
        .to_string();
    let model = v
        .get("model")
        .and_then(serde_json::Value::as_str)
        .unwrap_or("unknown")
        .to_string();
    let usage = v.get("usage");
    let input_tokens = usage
        .and_then(|u| u.get("prompt_tokens"))
        .and_then(serde_json::Value::as_u64)
        .unwrap_or(0);
    let output_tokens = usage
        .and_then(|u| u.get("completion_tokens"))
        .and_then(serde_json::Value::as_u64)
        .unwrap_or(0);
    // Cached prompt tokens (cache-savings visibility, P2-1): the
    // OpenAI-compatible detail shape first, then DeepSeek's flat field;
    // absent ⇒ 0 (an honest zero, never a guess).
    let cached_tokens = usage
        .and_then(|u| u.get("prompt_tokens_details"))
        .and_then(|d| d.get("cached_tokens"))
        .and_then(serde_json::Value::as_u64)
        .or_else(|| {
            usage
                .and_then(|u| u.get("prompt_cache_hit_tokens"))
                .and_then(serde_json::Value::as_u64)
        })
        .unwrap_or(0);
    Some(ParsedAnswer {
        model,
        answer_text,
        stop_reason,
        input_tokens,
        output_tokens,
        cached_tokens,
    })
}

/// The streaming request body — identical to [`openai_chat_body`] plus `stream:true`
/// and `stream_options.include_usage` (so the final SSE frame still carries `usage`).
#[cfg(any(
    feature = "provider-egress",
    feature = "local-mlx",
    feature = "local-vllm"
))]
pub(crate) fn openai_chat_stream_body(
    model: &str,
    max_output_tokens_u32: u32,
    system: &str,
    question: &str,
) -> String {
    serde_json::json!({
        "model": model,
        "max_tokens": max_output_tokens_u32,
        "stream": true,
        "stream_options": { "include_usage": true },
        "messages": [
            { "role": "system", "content": system },
            { "role": "user", "content": question },
        ],
    })
    .to_string()
}

/// Parse ONE SSE `data:` payload of a streaming Chat Completions response: lift the
/// `choices[0].delta.content` piece (the incremental text), and fold any
/// `finish_reason`, `model`, and `usage.*` it carries into the accumulators. Returns
/// the delta piece (possibly empty) or `None` when the payload carries no choice (e.g.
/// the final usage-only frame — its usage is still folded before the `None`). The bytes
/// are UNTRUSTED network input (a loopback server's too) — fail-soft, never a panic.
#[cfg(any(
    feature = "provider-egress",
    feature = "local-mlx",
    feature = "local-vllm"
))]
pub(crate) fn parse_openai_stream_chunk(
    payload: &str,
    model_out: &mut String,
    stop_out: &mut String,
    input_tokens: &mut u64,
    output_tokens: &mut u64,
    cached_tokens: &mut u64,
) -> Option<String> {
    let v: serde_json::Value = serde_json::from_str(payload).ok()?;
    if let Some(m) = v.get("model").and_then(serde_json::Value::as_str) {
        if !m.is_empty() {
            *model_out = m.to_string();
        }
    }
    if let Some(usage) = v.get("usage") {
        if let Some(p) = usage
            .get("prompt_tokens")
            .and_then(serde_json::Value::as_u64)
        {
            *input_tokens = p;
        }
        if let Some(c) = usage
            .get("completion_tokens")
            .and_then(serde_json::Value::as_u64)
        {
            *output_tokens = c;
        }
        if let Some(ct) = usage
            .get("prompt_tokens_details")
            .and_then(|d| d.get("cached_tokens"))
            .and_then(serde_json::Value::as_u64)
            .or_else(|| {
                usage
                    .get("prompt_cache_hit_tokens")
                    .and_then(serde_json::Value::as_u64)
            })
        {
            *cached_tokens = ct;
        }
    }
    let first = v.get("choices")?.as_array()?.first()?;
    if let Some(fr) = first
        .get("finish_reason")
        .and_then(serde_json::Value::as_str)
    {
        *stop_out = fr.to_string();
    }
    Some(
        first
            .get("delta")
            .and_then(|d| d.get("content"))
            .and_then(serde_json::Value::as_str)
            .unwrap_or("")
            .to_string(),
    )
}

/// The fields assembled from a full SSE stream (the streaming twin of [`ParsedAnswer`]).
#[cfg(any(
    feature = "provider-egress",
    feature = "local-mlx",
    feature = "local-vllm"
))]
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct SseAssembled {
    pub(crate) answer: String,
    pub(crate) model: String,
    pub(crate) stop_reason: String,
    pub(crate) input_tokens: u64,
    pub(crate) output_tokens: u64,
    pub(crate) cached_tokens: u64,
    /// The concatenated raw frame payloads (the streaming response-hash input).
    pub(crate) frames_concat: Vec<u8>,
}

/// Why an SSE consume stopped early (mapped by the caller to a typed `LiveConsultError`).
#[cfg(any(
    feature = "provider-egress",
    feature = "local-mlx",
    feature = "local-vllm"
))]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum SseError {
    /// The owner cancelled between frames (S-C true cancel).
    Cancelled,
    /// An IO error reading the body.
    Transport,
}

/// Consume an OpenAI-compatible SSE body INCREMENTALLY from any [`std::io::BufRead`]
/// (the production reader is a `reqwest::blocking::Response`, which impls
/// `std::io::Read` — R-STREAM reconcile 2026-06-21: no `stream` feature, no async
/// runtime, no relock). Each non-empty `delta.content` piece is handed to `on_delta`
/// AS IT IS PARSED; `cancel` is checked BEFORE each frame's body runs, so a set flag
/// stops the read mid-stream (true mid-turn abort). Pure + reader-generic ⇒ unit-
/// testable over an in-memory cursor (deltas, [DONE], usage, finish, cancel).
#[cfg(any(
    feature = "provider-egress",
    feature = "local-mlx",
    feature = "local-vllm"
))]
pub(crate) fn consume_openai_sse<R: std::io::BufRead>(
    reader: R,
    on_delta: &mut dyn FnMut(&str),
    cancel: &std::sync::atomic::AtomicBool,
) -> Result<SseAssembled, SseError> {
    let mut a = SseAssembled::default();
    for line in reader.lines() {
        if cancel.load(std::sync::atomic::Ordering::SeqCst) {
            return Err(SseError::Cancelled);
        }
        let line = line.map_err(|_| SseError::Transport)?;
        let Some(payload) = line.strip_prefix("data:").map(str::trim_start) else {
            continue; // SSE comment (`:`), blank line, or an `event:` line
        };
        if payload == "[DONE]" {
            break;
        }
        if payload.is_empty() {
            continue;
        }
        a.frames_concat.extend_from_slice(payload.as_bytes());
        if let Some(piece) = parse_openai_stream_chunk(
            payload,
            &mut a.model,
            &mut a.stop_reason,
            &mut a.input_tokens,
            &mut a.output_tokens,
            &mut a.cached_tokens,
        ) {
            if !piece.is_empty() {
                a.answer.push_str(&piece);
                on_delta(&piece);
            }
        }
    }
    Ok(a)
}

/// Lift an error class from a non-200 body and sanitize it to a closed charset
/// (ASCII alnum + `_`, ≤40 chars). OpenAI/OpenRouter errors are
/// `{error:{message,type,code}}`; only `type` (else numeric `code`) is rendered
/// — never the `message` prose. The response bytes are UNTRUSTED network input
/// (a LOOPBACK server's bytes too — shared with `local_chat`, P3-3 IV-L7).
#[cfg(any(
    feature = "provider-egress",
    feature = "local-mlx",
    feature = "local-vllm"
))]
pub(crate) fn extract_error_type(bytes: &[u8]) -> String {
    let value = serde_json::from_slice::<serde_json::Value>(bytes).ok();
    let err = value.as_ref().and_then(|v| v.get("error"));
    let label = err
        .and_then(|e| e.get("type"))
        .and_then(serde_json::Value::as_str)
        .map(str::to_string)
        .or_else(|| err.and_then(|e| e.get("code")).map(ToString::to_string))
        .unwrap_or_else(|| "unparseable_error".to_string());
    label
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || *c == '_')
        .take(40)
        .collect()
}

#[cfg(feature = "provider-egress")]
impl ProviderTransport {
    /// Send ONE real, bounded, redacted consult and return the parsed answer.
    /// The FULL [`preflight`](Self::preflight) gate stack applies (live-dispatch
    /// flag + same-message approval + allowlist + key reference); the key value
    /// is read only at the TLS boundary and dropped with the request. One
    /// attempt, no retry. v1 codec = OpenRouter (OpenAI-compatible); other hosts
    /// are a typed denial.
    pub fn send_live_text(
        &self,
        consult: &RedactedConsult,
        approval: EgressApproval,
        system: &str,
        question: &str,
        model: &str,
        max_output_tokens_u32: u32,
    ) -> Result<LiveConsultOutcome, LiveConsultError> {
        self.preflight(consult, approval)
            .map_err(LiveConsultError::Denied)?;
        match self.host {
            ProviderHost::OpenRouter => self.openai_chat(
                consult.request.timeout_ms_u32,
                system,
                question,
                model,
                max_output_tokens_u32,
            ),
            ProviderHost::Anthropic | ProviderHost::OpenAi | ProviderHost::Gemini => {
                Err(LiveConsultError::CodecNotImplemented)
            }
        }
    }

    /// STREAMING sibling of [`send_live_text`](Self::send_live_text): the SAME full
    /// preflight gate stack, then a `stream:true` Chat Completions call whose body is
    /// parsed INCREMENTALLY — each delta is handed to `on_delta` as it arrives, and
    /// `cancel` is checked between SSE frames (true mid-turn abort). The assembled
    /// answer + usage are returned in the SAME [`LiveConsultOutcome`] shape. The key is
    /// read only at the TLS boundary and dropped with the request.
    #[allow(clippy::too_many_arguments)]
    pub fn send_live_text_stream(
        &self,
        consult: &RedactedConsult,
        approval: EgressApproval,
        system: &str,
        question: &str,
        model: &str,
        max_output_tokens_u32: u32,
        on_delta: &mut dyn FnMut(&str),
        cancel: &std::sync::atomic::AtomicBool,
    ) -> Result<LiveConsultOutcome, LiveConsultError> {
        self.preflight(consult, approval)
            .map_err(LiveConsultError::Denied)?;
        match self.host {
            ProviderHost::OpenRouter => self.openai_chat_stream(
                consult.request.timeout_ms_u32,
                system,
                question,
                model,
                max_output_tokens_u32,
                on_delta,
                cancel,
            ),
            ProviderHost::Anthropic | ProviderHost::OpenAi | ProviderHost::Gemini => {
                Err(LiveConsultError::CodecNotImplemented)
            }
        }
    }

    /// The OpenAI-compatible STREAMING Chat Completions call (feature-gated; reached
    /// only after preflight). `stream:true`; the body is read incrementally via the
    /// blocking response's `std::io::Read` ([`consume_openai_sse`]) — no `stream`
    /// feature, no async runtime. The key rides in the Bearer header, read only at the
    /// TLS boundary.
    #[allow(clippy::too_many_arguments)]
    fn openai_chat_stream(
        &self,
        timeout_ms_u32: u32,
        system: &str,
        question: &str,
        model: &str,
        max_output_tokens_u32: u32,
        on_delta: &mut dyn FnMut(&str),
        cancel: &std::sync::atomic::AtomicBool,
    ) -> Result<LiveConsultOutcome, LiveConsultError> {
        let body = openai_chat_stream_body(model, max_output_tokens_u32, system, question);
        let request_hash_32 = crate::sha256_32(body.as_bytes());
        let key = crate::secrets::Secret::new(
            std::env::var(self.host.key_env())
                .map_err(|_| LiveConsultError::Denied(EgressDenied::KeyMissing))?,
        );
        let client = reqwest::blocking::Client::builder()
            .timeout(std::time::Duration::from_millis(u64::from(timeout_ms_u32)))
            .https_only(true)
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .map_err(|_| LiveConsultError::Denied(EgressDenied::TransportError))?;
        let response = client
            .post(format!("{}/chat/completions", self.host.base_url()))
            .header("authorization", format!("Bearer {}", key.expose_secret()))
            .header("content-type", "application/json")
            .header("accept", "text/event-stream")
            .body(body)
            .send()
            .map_err(|_| LiveConsultError::Denied(EgressDenied::TransportError))?;
        let status_u16 = response.status().as_u16();
        if status_u16 != 200 {
            let bytes = response
                .bytes()
                .map_err(|_| LiveConsultError::Denied(EgressDenied::TransportError))?;
            return Err(LiveConsultError::Http {
                status_u16,
                error_type: extract_error_type(bytes.as_ref()),
            });
        }
        let assembled =
            match consume_openai_sse(std::io::BufReader::new(response), on_delta, cancel) {
                Ok(a) => a,
                Err(SseError::Cancelled) => return Err(LiveConsultError::Cancelled),
                Err(SseError::Transport) => {
                    return Err(LiveConsultError::Denied(EgressDenied::TransportError));
                }
            };
        let response_hash_32 = crate::sha256_32(&assembled.frames_concat);
        if assembled.answer.is_empty() && assembled.stop_reason.is_empty() {
            return Err(LiveConsultError::MalformedResponse);
        }
        Ok(LiveConsultOutcome {
            host: self.host,
            status_u16,
            model: if assembled.model.is_empty() {
                model.to_string()
            } else {
                assembled.model
            },
            answer_text: assembled.answer,
            stop_reason: if assembled.stop_reason.is_empty() {
                "stop".to_string()
            } else {
                assembled.stop_reason
            },
            input_tokens: assembled.input_tokens,
            output_tokens: assembled.output_tokens,
            cached_tokens: assembled.cached_tokens,
            request_hash_32,
            response_hash_32,
        })
    }

    /// The OpenAI-compatible Chat Completions call (feature-gated; reached only
    /// after preflight). The key rides in an `authorization: Bearer` header and
    /// is read only at the TLS boundary, dropped with the request.
    fn openai_chat(
        &self,
        timeout_ms_u32: u32,
        system: &str,
        question: &str,
        model: &str,
        max_output_tokens_u32: u32,
    ) -> Result<LiveConsultOutcome, LiveConsultError> {
        let body = openai_chat_body(model, max_output_tokens_u32, system, question);
        let request_hash_32 = crate::sha256_32(body.as_bytes());
        let key = crate::secrets::Secret::new(
            std::env::var(self.host.key_env())
                .map_err(|_| LiveConsultError::Denied(EgressDenied::KeyMissing))?,
        );
        let client = reqwest::blocking::Client::builder()
            .timeout(std::time::Duration::from_millis(u64::from(timeout_ms_u32)))
            .https_only(true)
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .map_err(|_| LiveConsultError::Denied(EgressDenied::TransportError))?;
        let response = client
            .post(format!("{}/chat/completions", self.host.base_url()))
            .header("authorization", format!("Bearer {}", key.expose_secret()))
            .header("content-type", "application/json")
            .body(body)
            .send()
            .map_err(|_| LiveConsultError::Denied(EgressDenied::TransportError))?;
        let status_u16 = response.status().as_u16();
        let bytes = response
            .bytes()
            .map_err(|_| LiveConsultError::Denied(EgressDenied::TransportError))?;
        let response_hash_32 = crate::sha256_32(bytes.as_ref());
        if status_u16 != 200 {
            return Err(LiveConsultError::Http {
                status_u16,
                error_type: extract_error_type(bytes.as_ref()),
            });
        }
        let parsed = parse_openai_chat_response(bytes.as_ref())
            .ok_or(LiveConsultError::MalformedResponse)?;
        Ok(LiveConsultOutcome {
            host: self.host,
            status_u16,
            model: parsed.model,
            answer_text: parsed.answer_text,
            stop_reason: parsed.stop_reason,
            input_tokens: parsed.input_tokens,
            output_tokens: parsed.output_tokens,
            cached_tokens: parsed.cached_tokens,
            request_hash_32,
            response_hash_32,
        })
    }
}

// Codec unit tests: pure functions only — NO test in this module (or anywhere)
// fires a live network call. A correct-phrase executor test could really egress
// when ANTHROPIC_API_KEY is present in the environment, so it is deliberately
// not written; the live fire is the OWNER's V2 step (threat model §VERIFICATION).
#[cfg(all(test, feature = "provider-egress"))]
mod live_codec_tests {
    use super::*;

    #[test]
    fn body_builder_escapes_and_round_trips() {
        let question = "what is \"sinabro\"?\nline2 한글 \\ backslash";
        let body = openai_chat_body("deepseek/deepseek-chat", 1024, "you are sinabro", question);
        let parsed = serde_json::from_str::<serde_json::Value>(&body).ok();
        assert!(parsed.is_some(), "body must be valid JSON");
        if let Some(v) = parsed {
            assert_eq!(v["model"], "deepseek/deepseek-chat");
            assert_eq!(v["max_tokens"], 1024);
            assert_eq!(v["messages"][0]["role"], "system");
            assert_eq!(v["messages"][0]["content"], "you are sinabro");
            assert_eq!(v["messages"][1]["role"], "user");
            assert_eq!(v["messages"][1]["content"], question);
        }
    }

    #[test]
    fn response_parser_extracts_text_and_usage() {
        let fixture = br#"{
            "id": "gen-01",
            "model": "deepseek/deepseek-chat",
            "choices": [
                {"message": {"role": "assistant", "content": "the answer"}, "finish_reason": "stop"}
            ],
            "usage": {"prompt_tokens": 12, "completion_tokens": 34}
        }"#;
        let parsed = parse_openai_chat_response(fixture);
        assert!(parsed.is_some());
        if let Some(p) = parsed {
            assert_eq!(p.model, "deepseek/deepseek-chat");
            assert_eq!(p.stop_reason, "stop");
            assert_eq!(p.answer_text, "the answer");
            assert_eq!(p.input_tokens, 12);
            assert_eq!(p.output_tokens, 34);
            assert_eq!(p.cached_tokens, 0, "no cached field reported ⇒ honest 0");
        }
    }

    /// P2-1 — cached prompt tokens parse from BOTH provider shapes (the
    /// OpenAI-compatible `prompt_tokens_details.cached_tokens` and the
    /// DeepSeek flat `prompt_cache_hit_tokens`); the detail shape wins when
    /// both are present; absent stays 0 (asserted in the base usage test).
    #[test]
    fn response_parser_extracts_cached_tokens_both_shapes() {
        let openai_shape = br#"{
            "model": "m",
            "choices": [{"message": {"content": "a"}, "finish_reason": "stop"}],
            "usage": {"prompt_tokens": 100, "completion_tokens": 5,
                      "prompt_tokens_details": {"cached_tokens": 64}}
        }"#;
        assert_eq!(
            parse_openai_chat_response(openai_shape).map(|p| p.cached_tokens),
            Some(64)
        );

        let deepseek_shape = br#"{
            "model": "m",
            "choices": [{"message": {"content": "a"}, "finish_reason": "stop"}],
            "usage": {"prompt_tokens": 100, "completion_tokens": 5,
                      "prompt_cache_hit_tokens": 48}
        }"#;
        assert_eq!(
            parse_openai_chat_response(deepseek_shape).map(|p| p.cached_tokens),
            Some(48)
        );

        let both = br#"{
            "model": "m",
            "choices": [{"message": {"content": "a"}, "finish_reason": "stop"}],
            "usage": {"prompt_tokens": 100, "completion_tokens": 5,
                      "prompt_tokens_details": {"cached_tokens": 64},
                      "prompt_cache_hit_tokens": 48}
        }"#;
        assert_eq!(
            parse_openai_chat_response(both).map(|p| p.cached_tokens),
            Some(64),
            "the detail shape wins when both exist"
        );
    }

    #[test]
    fn response_parser_rejects_non_answer_json() {
        assert!(parse_openai_chat_response(b"not json at all").is_none());
        assert!(parse_openai_chat_response(b"{\"choices\":[]}").is_none());
        assert!(parse_openai_chat_response(b"{\"error\":{}}").is_none());
    }

    #[test]
    fn error_type_is_sanitized_to_closed_charset() {
        // Raw byte-string: the JSON value decodes to `invalid_request_error<script>" x`
        // — angle brackets / quote / space are dropped, alnum survives (incl. the x).
        let raw = br#"{"error": {"type": "invalid_request_error<script>\" x"}}"#;
        assert_eq!(extract_error_type(raw), "invalid_request_errorscriptx");
        // numeric `code` fallback when there is no `type`
        assert_eq!(extract_error_type(br#"{"error": {"code": 401}}"#), "401");
        assert_eq!(extract_error_type(b"junk"), "unparseable_error");
        let long = format!("{{\"error\":{{\"type\":\"{}\"}}}}", "a".repeat(99));
        assert_eq!(extract_error_type(long.as_bytes()).len(), 40);
    }
}

/// The same-message egress approval ceremony (#607, G.8.13). Before a provider
/// consult is sent, the operator sees the provider identity, the typed trigger, the
/// bounded cost ceiling (the consult's token caps), and the REDACTED payload hash
/// (never the raw body), and must EXPLICITLY approve in the same turn. There is no
/// auto-approve: the default is denied; a bare Enter, a wrong response, or a timeout
/// denies; only an explicit confirm yields a granted [`EgressApproval`] (which
/// [`ProviderTransport::preflight`] then requires — a denied approval aborts the
/// send). Reuses the cockpit approval surfaces — [`ApprovalPrompt`] (CLI) and
/// [`ApprovalModal`] (TUI) — both driven by the consult's `Network`-risk
/// [`CommandEnvelope`] (`approval = Confirm`). Carries no secret and no raw content.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EgressConsultApproval {
    host: ProviderHost,
    trigger: ConsultTrigger,
    redacted_payload_hash_32: [u8; 32],
    max_input_tokens_u32: u32,
    max_output_tokens_u32: u32,
    envelope: CommandEnvelope,
}

impl EgressConsultApproval {
    /// Summarize a [`RedactedConsult`] for the same-message approval ceremony: the
    /// target `host`, the typed trigger, the redacted payload hash, the bounded
    /// token caps (the cost ceiling), and the consult's classified envelope.
    #[must_use]
    pub fn summarize(host: ProviderHost, consult: &RedactedConsult) -> Self {
        let packet = consult.request.packet;
        Self {
            host,
            trigger: packet.trigger,
            redacted_payload_hash_32: consult.payload_hash_32(),
            max_input_tokens_u32: packet.input_token_cap_u32,
            max_output_tokens_u32: packet.output_token_cap_u32,
            envelope: consult.request.envelope,
        }
    }

    /// The target provider host.
    #[must_use]
    pub const fn host(&self) -> ProviderHost {
        self.host
    }

    /// The typed trigger that provoked the consult.
    #[must_use]
    pub const fn trigger(&self) -> ConsultTrigger {
        self.trigger
    }

    /// The bounded cost ceiling: the maximum input + output tokens the consult may
    /// spend (shown to the operator before approval).
    #[must_use]
    pub const fn cost_ceiling_tokens(&self) -> u32 {
        self.max_input_tokens_u32
            .saturating_add(self.max_output_tokens_u32)
    }

    /// The same-message approval summary lines: provider id, trigger, cost ceiling,
    /// and the redacted payload hash. Colorless `key: value`; carries no secret and
    /// no raw body.
    #[must_use]
    pub fn render(&self) -> Vec<String> {
        vec![
            format!("provider: {}", self.host.host()),
            format!("trigger: {:?}", self.trigger),
            format!(
                "cost_ceiling_tokens: in={} out={} total={}",
                self.max_input_tokens_u32,
                self.max_output_tokens_u32,
                self.cost_ceiling_tokens()
            ),
            format!(
                "payload: {} (redacted; hash only)",
                &crate::hex32(&self.redacted_payload_hash_32)[..8]
            ),
            format!(
                "approval: {:?} (same-message; no auto-approve)",
                self.envelope.approval
            ),
        ]
    }

    /// Run the same-message approval ceremony with the operator's `response`,
    /// reusing the fail-closed [`ApprovalPrompt`]. Returns a granted
    /// [`EgressApproval`] ONLY on an explicit confirm; a bare Enter, a wrong
    /// response, or any other input yields a denied approval (no auto-approve; a
    /// denied approval aborts the send at [`ProviderTransport::preflight`]).
    #[must_use]
    pub fn decide(&self, response: &str) -> EgressApproval {
        let mut prompt = ApprovalPrompt::new(self.envelope.approval, "");
        if prompt.evaluate(response).is_approved() {
            EgressApproval::grant()
        } else {
            EgressApproval::denied()
        }
    }

    /// A timeout is always a denial (no auto-approve on timeout).
    #[must_use]
    pub fn on_timeout(&self) -> EgressApproval {
        EgressApproval::denied()
    }

    /// Build the TUI approval modal for this egress consult (reuses
    /// [`ApprovalModal`]). A provider consult is `Network`-risk (not high-risk), so
    /// only the trace id is mandatory; the redacted payload hash is shown as the
    /// capability diff and the cost ceiling as the cost impact (no chain rollback —
    /// an advisory consult has no on-chain side effect).
    #[must_use]
    pub fn approval_modal(&self, trace: crate::StageFTraceLink) -> ApprovalModal {
        ApprovalModal::new(
            self.envelope,
            self.redacted_payload_hash_32,
            u64::from(self.cost_ceiling_tokens()),
            [0u8; 32],
            trace,
            "",
        )
    }

    /// SHA-256 of the approval summary (host + trigger + redacted payload hash +
    /// caps) — the hash recorded in the route trace (#608) so the approval is
    /// auditable after the fact.
    #[must_use]
    pub fn summary_hash_32(&self) -> [u8; 32] {
        let mut buf = Vec::with_capacity(42);
        buf.push(self.host as u8);
        buf.push(self.trigger as u8);
        buf.extend_from_slice(&self.redacted_payload_hash_32);
        buf.extend_from_slice(&self.max_input_tokens_u32.to_le_bytes());
        buf.extend_from_slice(&self.max_output_tokens_u32.to_le_bytes());
        crate::sha256_32(&buf)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::commands::model_compress::ConsultScope;
    use crate::commands::model_route::ConsultTrigger;
    use crate::provider::frontier_consult::{self, BoundedConsultInputs};
    use crate::provider::redaction::{self, RedactionRequest};
    use crate::route::RouteExecutionState;
    use crate::secrets::classify_reference;

    fn key() -> SecretRefView {
        classify_reference("provider_key", "env:ANTHROPIC_API_KEY")
    }

    // Build a real bounded request, then (test-only) set `live_dispatch_allowed`
    // via struct-update — the PRODUCTION builder always leaves it `false`; only a
    // test can flip it, to exercise the downstream gates.
    fn bounded(live: bool) -> Option<BoundedConsultRequest> {
        let inputs = BoundedConsultInputs {
            route_state: RouteExecutionState::Slow,
            trigger: ConsultTrigger::RepeatedFailure,
            scope: ConsultScope::minimal(),
            redaction_report_hash_32: [1u8; 32],
            evidence_refs_hash_32: [2u8; 32],
            prompt_hash_32: [3u8; 32],
            timeout_ms_u32: 30_000,
            local_verification_command_hash_32: [4u8; 32],
        };
        let base = frontier_consult::build(&inputs)?;
        Some(BoundedConsultRequest {
            live_dispatch_allowed: live,
            ..base
        })
    }

    fn consult(live: bool) -> Option<RedactedConsult> {
        let request = bounded(live)?;
        let frags: [&str; 1] = ["route=advisory;evidence=hash"];
        let redaction = match redaction::redact(&RedactionRequest {
            fragments: &frags,
            candidate_memory_ids: &[],
            deleted_ids: &[],
            include_private_memory: false,
        }) {
            Ok(r) => r,
            Err(_) => return None,
        };
        RedactedConsult::new(request, redaction)
    }

    #[test]
    fn default_request_denies_live_dispatch() {
        // The production builder leaves live_dispatch_allowed = false → denied even
        // with a granted approval (the Phase-0 invariant).
        let c = consult(false);
        assert!(c.is_some());
        if let Some(c) = c {
            let t = ProviderTransport::new(ProviderHost::Anthropic, key());
            assert_eq!(
                t.send(&c, EgressApproval::grant()),
                Err(EgressDenied::LiveDispatchNotAllowed)
            );
        }
    }

    #[test]
    fn approval_required_even_when_live_dispatch_allowed() {
        let c = consult(true);
        assert!(c.is_some());
        if let Some(c) = c {
            let t = ProviderTransport::new(ProviderHost::Anthropic, key());
            assert_eq!(
                t.preflight(&c, EgressApproval::denied()),
                Err(EgressDenied::ApprovalMissing)
            );
        }
    }

    #[test]
    fn funds_host_unreachable() {
        // #610 redteam: no funds / chain / mainnet / local host is allowlisted.
        for h in [
            "rpc.mainnet.solana.com",
            "api.mainnet-beta.solana.com",
            "ethereum.publicnode.com",
            "api.devnet.solana.com",
            "127.0.0.1",
            "localhost",
            "evil.example.com",
        ] {
            assert!(!host_is_allowlisted(h), "{h} must NOT be allowlisted");
        }
        assert!(host_is_allowlisted(ProviderHost::Anthropic.host()));
        assert!(host_is_allowlisted(ProviderHost::OpenAi.host()));
        assert!(host_is_allowlisted(ProviderHost::Gemini.host()));
    }

    #[test]
    fn provider_hosts_are_tls() {
        for h in ALLOWLISTED_PROVIDERS {
            assert!(
                h.base_url().starts_with("https://"),
                "{h:?} base url must be https"
            );
        }
    }

    /// E0e-2 — SI-5 allowlist-excludes-chain (provider leg). A comprehensive
    /// funds / chain / wallet / RPC host corpus is rejected by
    /// [`host_is_allowlisted`], the closed [`ALLOWLISTED_PROVIDERS`] set is exactly
    /// the four provider hosts (no funds variant exists to allowlist), and no
    /// allowlisted host string even *looks* like a chain RPC. FAILS if a funds
    /// host ever becomes representable or reachable.
    #[test]
    fn si5_no_funds_or_chain_host_is_allowlisted_or_representable() {
        const FUNDS_HOSTS: &[&str] = &[
            "rpc.mainnet.solana.com",
            "api.mainnet-beta.solana.com",
            "api.devnet.solana.com",
            "api.testnet.solana.com",
            "solana-mainnet.g.alchemy.com",
            "mainnet.helius-rpc.com",
            "mainnet.block-engine.jito.wtf",
            "rpc.ankr.com",
            "ethereum.publicnode.com",
            "eth-mainnet.g.alchemy.com",
            "mainnet.infura.io",
            "polygon-rpc.com",
            "arb1.arbitrum.io",
            "mainnet.base.org",
            "bsc-dataseed.binance.org",
            "api.avax.network",
            "127.0.0.1",
            "localhost",
            "wallet.local",
            "evil.example.com",
        ];
        for h in FUNDS_HOSTS {
            assert!(!host_is_allowlisted(h), "{h} must NOT be allowlisted");
        }
        // The closed allowlist is exactly the four provider hosts (no funds variant).
        assert_eq!(ALLOWLISTED_PROVIDERS.len(), 4);
        for p in ALLOWLISTED_PROVIDERS {
            let host = p.host();
            for needle in [
                "solana",
                "mainnet",
                "rpc",
                "wallet",
                "chain",
                "infura",
                "alchemy",
                "ankr",
                "ethereum",
                "arbitrum",
                "polygon",
                "127.0.0.1",
                "localhost",
            ] {
                assert!(
                    !host.contains(needle),
                    "{host} looks like a funds/chain host (contains {needle})"
                );
            }
        }
        // The set is non-empty + correct: every provider host IS reachable.
        assert!(host_is_allowlisted(ProviderHost::Anthropic.host()));
        assert!(host_is_allowlisted(ProviderHost::OpenRouter.host()));
    }

    #[test]
    fn redacted_consult_rejects_stored_body() {
        let req = bounded(false);
        assert!(req.is_some());
        if let Some(req) = req {
            // SI-2: a forged receipt cannot be struct-literal'd outside
            // redaction.rs (private fields). The `#[cfg(test)]`-only forge lets
            // this test still exercise the `new` reject path for a stored body —
            // a state `redact` never emits in production.
            let unsafe_receipt = RedactionReceipt::forge_for_test(
                1,
                0,
                [5u8; 32],
                true,
                mnemos_a_core::RedactionClass::PublicSafe,
            );
            assert!(
                RedactedConsult::new(req, unsafe_receipt).is_none(),
                "a stored raw body must be rejected"
            );
        }
    }

    #[test]
    fn key_missing_denied() {
        let c = consult(true);
        assert!(c.is_some());
        if let Some(c) = c {
            let no_key = classify_reference("k", "plain-no-scheme");
            let t = ProviderTransport::new(ProviderHost::Anthropic, no_key);
            assert_eq!(
                t.preflight(&c, EgressApproval::grant()),
                Err(EgressDenied::KeyMissing)
            );
        }
    }

    #[test]
    fn payload_is_only_a_hash() {
        let c = consult(false);
        assert!(c.is_some());
        if let Some(c) = c {
            assert_eq!(c.payload_hash_32(), c.redaction.redacted_payload_hash_32());
        }
    }

    // With every gate satisfiable (test-only live dispatch + grant + allowlisted +
    // key present), the offline std-core STILL denies: no transport is compiled.
    #[cfg(not(feature = "provider-egress"))]
    #[test]
    fn transport_not_compiled_in_offline_core() {
        let c = consult(true);
        assert!(c.is_some());
        if let Some(c) = c {
            let t = ProviderTransport::new(ProviderHost::Anthropic, key());
            assert_eq!(
                t.send(&c, EgressApproval::grant()),
                Err(EgressDenied::TransportNotCompiled)
            );
        }
    }

    // ---- #607 same-message egress approval ceremony -----------------------

    #[test]
    fn egress_approval_shows_id_cost_trigger() {
        let c = consult(false);
        assert!(c.is_some());
        if let Some(c) = c {
            let ap = EgressConsultApproval::summarize(ProviderHost::Anthropic, &c);
            let text = ap.render().join("\n");
            assert!(text.contains("api.anthropic.com"), "provider id shown");
            assert!(text.contains("cost_ceiling_tokens"), "cost shown");
            assert!(text.contains("trigger"), "trigger shown");
            assert!(text.contains("redacted"), "payload is redacted (hash only)");
            assert_eq!(ap.host(), ProviderHost::Anthropic);
            assert_eq!(ap.trigger(), ConsultTrigger::RepeatedFailure);
            assert!(ap.cost_ceiling_tokens() > 0);
        }
    }

    #[test]
    fn explicit_approval_required_no_auto_approve() {
        let c = consult(false);
        assert!(c.is_some());
        if let Some(c) = c {
            let ap = EgressConsultApproval::summarize(ProviderHost::Anthropic, &c);
            // no auto-approve: bare Enter / wrong response / timeout all deny
            assert!(!ap.decide("").is_granted(), "bare Enter never approves");
            assert!(!ap.decide("no").is_granted());
            assert!(!ap.on_timeout().is_granted(), "timeout denies");
            // only an explicit confirm grants
            assert!(ap.decide("yes").is_granted(), "explicit confirm grants");
        }
    }

    #[test]
    fn denied_approval_aborts_send() {
        // even with live-dispatch test-flipped true, a denied approval aborts the
        // send (ApprovalMissing) before any transport is reached.
        let c = consult(true);
        assert!(c.is_some());
        if let Some(c) = c {
            let ap = EgressConsultApproval::summarize(ProviderHost::Anthropic, &c);
            let denied = ap.decide("");
            assert!(!denied.is_granted());
            let t = ProviderTransport::new(ProviderHost::Anthropic, key());
            assert_eq!(t.preflight(&c, denied), Err(EgressDenied::ApprovalMissing));
        }
    }

    #[test]
    fn approval_modal_binds_tui_and_decides_consistently() {
        let c = consult(false);
        assert!(c.is_some());
        if let Some(c) = c {
            let ap = EgressConsultApproval::summarize(ProviderHost::OpenAi, &c);
            let trace = crate::StageFTraceLink::new([7u8; 32], 607, 1);
            let mut modal = ap.approval_modal(trace);
            // the TUI modal renders the consult + decides via the same Confirm prompt
            let text = modal.render(16).join("\n");
            assert!(text.contains("approval"));
            assert!(
                !modal.decide("").is_approved(),
                "no auto-approve in TUI either"
            );
            assert!(modal.decide("yes").is_approved());
        }
    }

    // falsifiability canary: a different provider yields a different summary hash
    // (the recorded approval distinguishes consults), and the same summary is stable.
    #[test]
    fn summary_hash_distinguishes_consults_canary() {
        let c = consult(false);
        assert!(c.is_some());
        if let Some(c) = c {
            let a = EgressConsultApproval::summarize(ProviderHost::Anthropic, &c);
            let b = EgressConsultApproval::summarize(ProviderHost::OpenAi, &c);
            assert_ne!(
                a.summary_hash_32(),
                b.summary_hash_32(),
                "different provider => different summary hash"
            );
            assert_eq!(a.summary_hash_32(), a.summary_hash_32(), "stable");
        }
    }
}

// S-C streaming SSE codec — pure, reader-generic tests over an in-memory cursor (the
// incremental-over-a-real-socket property was proven by the R-STREAM probe; here we pin
// the parse/assembly/cancel LOGIC deterministically).
#[cfg(all(test, feature = "provider-egress"))]
mod stream_codec_tests {
    #![allow(clippy::unwrap_used)]
    use super::{SseError, consume_openai_sse};
    use std::io::Cursor;
    use std::sync::atomic::{AtomicBool, Ordering};

    #[test]
    fn sse_consume_assembles_deltas_in_order() {
        let sse = concat!(
            "data: {\"model\":\"deepseek\",\"choices\":[{\"delta\":{\"content\":\"Hel\"}}]}\n",
            "\n",
            ": keep-alive comment\n",
            "data: {\"choices\":[{\"delta\":{\"content\":\"lo \"}}]}\n",
            "data: {\"choices\":[{\"delta\":{\"content\":\"world\"},\"finish_reason\":\"stop\"}]}\n",
            "data: {\"choices\":[],\"usage\":{\"prompt_tokens\":7,\"completion_tokens\":3,\"prompt_tokens_details\":{\"cached_tokens\":2}}}\n",
            "data: [DONE]\n",
        );
        let mut pieces: Vec<String> = Vec::new();
        let cancel = AtomicBool::new(false);
        let a = consume_openai_sse(
            Cursor::new(sse.as_bytes()),
            &mut |d| pieces.push(d.to_string()),
            &cancel,
        )
        .unwrap();
        assert_eq!(a.answer, "Hello world");
        assert_eq!(
            pieces,
            vec!["Hel", "lo ", "world"],
            "deltas streamed in order"
        );
        assert_eq!(a.stop_reason, "stop");
        assert_eq!(a.model, "deepseek");
        assert_eq!(a.input_tokens, 7);
        assert_eq!(a.output_tokens, 3);
        assert_eq!(a.cached_tokens, 2);
    }

    #[test]
    fn sse_consume_cancels_mid_stream() {
        let sse = concat!(
            "data: {\"choices\":[{\"delta\":{\"content\":\"a\"}}]}\n",
            "data: {\"choices\":[{\"delta\":{\"content\":\"b\"}}]}\n",
            "data: {\"choices\":[{\"delta\":{\"content\":\"c\"}}]}\n",
            "data: {\"choices\":[{\"delta\":{\"content\":\"d\"}}]}\n",
            "data: [DONE]\n",
        );
        let cancel = AtomicBool::new(false);
        let mut pieces: Vec<String> = Vec::new();
        let result = {
            let mut sink = |d: &str| {
                pieces.push(d.to_string());
                if pieces.len() == 2 {
                    cancel.store(true, Ordering::SeqCst); // owner hits Esc after the 2nd delta
                }
            };
            consume_openai_sse(Cursor::new(sse.as_bytes()), &mut sink, &cancel)
        };
        assert_eq!(result, Err(SseError::Cancelled));
        assert_eq!(
            pieces,
            vec!["a", "b"],
            "stopped after the delta that requested cancel"
        );
    }

    #[test]
    fn sse_consume_ignores_non_data_lines() {
        let sse = "event: ping\n: a comment\n\ndata: [DONE]\n";
        let cancel = AtomicBool::new(false);
        let mut pieces: Vec<String> = Vec::new();
        let a = consume_openai_sse(
            Cursor::new(sse.as_bytes()),
            &mut |d| pieces.push(d.to_string()),
            &cancel,
        )
        .unwrap();
        assert!(a.answer.is_empty());
        assert!(pieces.is_empty(), "no data frames ⇒ no deltas");
    }

    // The permanent twin of the R-STREAM probe: consume_openai_sse over a REAL TCP
    // socket (a raw TcpStream client — no reqwest, so it adds no transport send call).
    // Proves the deltas arrive INCREMENTALLY (the server enforces 80ms gaps; a whole-
    // body buffer would deliver all three at ~one instant). The reqwest::blocking::
    // Response path is probe-proven + compile-checked in openai_chat_stream.
    #[test]
    fn sse_consume_incremental_over_real_socket() {
        use std::io::{Read, Write};
        use std::net::{TcpListener, TcpStream};
        use std::time::{Duration, Instant};
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let server = std::thread::spawn(move || {
            let (mut sock, _) = listener.accept().unwrap();
            sock.set_nodelay(true).unwrap();
            let mut buf = [0u8; 1024];
            let _ = sock.read(&mut buf); // consume the GET request
            // Connection-close streaming (no chunking) — the body is raw SSE frames; the
            // HTTP status + headers are non-`data:` lines the parser skips.
            sock.write_all(
                b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nConnection: close\r\n\r\n",
            )
            .unwrap();
            sock.flush().unwrap();
            for i in 0..3u8 {
                sock.write_all(
                    format!("data: {{\"choices\":[{{\"delta\":{{\"content\":\"p{i}\"}}}}]}}\n\n")
                        .as_bytes(),
                )
                .unwrap();
                sock.flush().unwrap();
                std::thread::sleep(Duration::from_millis(80));
            }
            // dropping `sock` closes the connection ⇒ the client reads to EOF
        });
        let mut client = TcpStream::connect(addr).unwrap();
        client.set_nodelay(true).unwrap();
        client
            .write_all(b"GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
            .unwrap();
        client.flush().unwrap();
        let start = Instant::now();
        let mut times: Vec<Duration> = Vec::new();
        let cancel = AtomicBool::new(false);
        let a = consume_openai_sse(
            std::io::BufReader::new(client),
            &mut |_d| times.push(start.elapsed()),
            &cancel,
        )
        .unwrap();
        server.join().unwrap();
        assert_eq!(a.answer, "p0p1p2", "all three deltas assembled");
        assert_eq!(times.len(), 3);
        let span = times[2].saturating_sub(times[0]);
        assert!(
            span >= Duration::from_millis(100),
            "deltas arrived INCREMENTALLY over a real socket (span {span:?} >= 100ms)"
        );
    }
}
