//! `telegram::egress` — the bounded Telegram Bot-API egress transport
//! (G-WP-10 atom #636 · G.9.12).
//!
//! This is the SECOND real network capability in the project (after
//! [`crate::provider::egress`]). It lifts the Phase-0 no-egress lock for the
//! Telegram Bot API ONLY, under the safety kernel, mirroring the provider egress
//! transport EXACTLY — never a disabled-path workaround. Funds custody is
//! UNCHANGED: wallet / gas / chain / mainnet hosts are structurally
//! unrepresentable here and rejected by the allowlist (funds-egress = 0).
//!
//! Triple-gated and disabled by default — autonomous Phase-0 makes ZERO live
//! sends. The `telegram-egress` cargo feature is OFF by default, so without it
//! the `reqwest` transport is not compiled and [`TelegramTransport::send`]
//! returns [`TelegramEgressDenied::TransportNotCompiled`]. A
//! [`RedactedTelegramSend`] is `dry_run` (the invariant `live_send_allowed =
//! false`) unless a separate same-message approval ceremony flips it, so `send`
//! denies a dry-run send. And an explicit [`TelegramEgressApproval`] granted in
//! the same turn is required. Only the allowlisted Telegram host over TLS,
//! carrying the shared [`MessageEnvelope`] and a redacted message hash (never raw
//! text), can ever be sent.
//!
//! Secret custody (`G-G-SECRET-ZERO`): the bot token is held as a
//! [`SecretRefView`] (value never loaded; this is the
//! [`crate::telegram::config::TelegramConfigView::bot_token_ref`]); the value is
//! read only at the TLS send boundary (the feature-gated path) and dropped
//! immediately, never logged / cloned / persisted.
//!
//! Reuse (no reinvention): [`MessageEnvelope`] from
//! [`crate::commands::platform_telegram`] is the SAME envelope the CLI carries
//! (channel parity); [`SecretRefView`] from [`crate::secrets`]. New here:
//! [`TelegramHost`], [`RedactedTelegramSend`], [`TelegramTransport`],
//! [`TelegramEgressApproval`], [`TelegramEgressDenied`].

use crate::commands::platform_telegram::MessageEnvelope;
use crate::provider::redaction::RedactionReceipt;
use crate::secrets::SecretRefView;

/// The single allowlisted Telegram Bot-API host. ONLY this is reachable. There is
/// deliberately NO variant for a wallet, gas, chain, mainnet, or provider host —
/// making funds-egress (and any non-Telegram egress) structurally impossible. The
/// enum is intentionally NOT `#[non_exhaustive]` so the closed set stays auditable.
#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TelegramHost {
    /// The Telegram Bot API.
    BotApi = 1,
}

impl TelegramHost {
    /// The fixed TLS host authority (never a funds / chain / provider host).
    #[must_use]
    pub const fn host(self) -> &'static str {
        match self {
            Self::BotApi => "api.telegram.org",
        }
    }

    /// The full TLS base URL (always `https://`).
    #[must_use]
    pub const fn base_url(self) -> &'static str {
        match self {
            Self::BotApi => "https://api.telegram.org",
        }
    }

    /// The environment-variable name the bot-token reference resolves from at the
    /// TLS boundary (feature-gated path only). Shared by the egress `sendMessage`
    /// and the E4 inbound `getUpdates` transports — ONE source for the env name (no
    /// cross-surface drift).
    #[cfg(any(feature = "telegram-egress", feature = "telegram-inbound"))]
    pub(crate) const fn token_env(self) -> &'static str {
        match self {
            Self::BotApi => "TELEGRAM_BOT_TOKEN",
        }
    }

    /// The environment-variable name the target chat id resolves from at the TLS
    /// boundary (feature-gated path only). The transport deliberately owns no chat
    /// id (T-F3): the value identifies the owner's chat and is treated secret-zero
    /// — read here, never rendered, never hashed into a receipt. Shared by the
    /// egress `sendMessage` target and the E4 inbound sender-pin (IV-T1: a reply is
    /// authorized only when its `chat.id` equals this value) — ONE source.
    #[cfg(any(feature = "telegram-egress", feature = "telegram-inbound"))]
    pub(crate) const fn chat_env(self) -> &'static str {
        match self {
            Self::BotApi => "TELEGRAM_CHAT_ID",
        }
    }
}

/// The closed set of allowlisted Telegram hosts — the audit anchor for
/// "Telegram only". A host not in this set (including every wallet / gas / chain /
/// mainnet RPC host AND every provider host) is unreachable.
pub const ALLOWLISTED_TELEGRAM_HOSTS: [TelegramHost; 1] = [TelegramHost::BotApi];

/// Whether `host` is the allowlisted Telegram host. Any other host — including
/// every wallet / gas / chain / mainnet RPC host and every provider host — is
/// rejected (funds-host and cross-egress unreachable).
#[must_use]
pub fn host_is_allowlisted(host: &str) -> bool {
    ALLOWLISTED_TELEGRAM_HOSTS.iter().any(|h| h.host() == host)
}

/// A Telegram send payload that is type-structurally free of raw content: it
/// carries only the shared [`MessageEnvelope`] (the SAME envelope the CLI carries
/// — channel parity) and the redacted message hash (never raw text). It is a
/// `dry_run` (the invariant `live_send_allowed = false`) unless a same-message
/// approval ceremony flips it — so the default surface never performs a live send.
///
/// # SI-2 — on the single egress choke
///
/// Fields are **private** and a send can be built ONLY from a
/// [`RedactionReceipt`] via [`dry_run`](Self::dry_run) (mirroring
/// [`RedactedConsult::new`](crate::provider::egress::RedactedConsult::new)) — so a
/// Telegram send is transitively `redact()`-only, and a hand-forged hash that
/// never passed redaction is UNREPRESENTABLE (PD-4). A struct literal outside
/// `telegram::egress` does NOT compile:
/// ```compile_fail
/// let _forged = sinabro::telegram::egress::RedactedTelegramSend {
///     envelope: todo!(),
///     redacted_message_hash_32: [0u8; 32],
///     live_send_allowed: true,
/// };
/// ```
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RedactedTelegramSend {
    /// The shared platform-neutral envelope (identical to the CLI's).
    envelope: MessageEnvelope,
    /// The redacted message hash — the only content reference that ever leaves.
    redacted_message_hash_32: [u8; 32],
    /// Whether a live send is allowed. `false` by default (dry-run); flipped only
    /// by [`into_live`](Self::into_live) with a granted approval (absent in
    /// autonomous Phase 0).
    live_send_allowed: bool,
}

impl RedactedTelegramSend {
    /// Build a dry-run send (the default posture: `live_send_allowed = false`)
    /// from a [`RedactionReceipt`] — the SI-2 choke. The body is represented ONLY
    /// by the receipt's redacted hash; a send cannot exist without a receipt, so
    /// it is transitively `redact()`-only (mirrors
    /// [`RedactedConsult::new`](crate::provider::egress::RedactedConsult::new)).
    /// `None` when the receipt proves a stored raw body — a state `redact` never
    /// emits — so the path is fail-closed.
    #[must_use]
    pub fn dry_run(envelope: MessageEnvelope, redaction: RedactionReceipt) -> Option<Self> {
        if redaction.provider_body_stored() {
            return None;
        }
        Some(Self {
            envelope,
            redacted_message_hash_32: redaction.redacted_payload_hash_32(),
            live_send_allowed: false,
        })
    }

    /// Flip to a live send — ONLY with a granted [`TelegramEgressApproval`]. A
    /// denied approval leaves the dry-run posture unchanged (fail-closed; no
    /// auto-live), so a `live_send_allowed == true` value cannot exist unless an
    /// approval was granted this turn.
    #[must_use]
    pub fn into_live(self, approval: TelegramEgressApproval) -> Self {
        if approval.is_granted() {
            Self {
                live_send_allowed: true,
                ..self
            }
        } else {
            self
        }
    }

    /// The redacted-payload hash — the only content reference that ever leaves.
    #[must_use]
    pub const fn payload_hash_32(&self) -> [u8; 32] {
        self.redacted_message_hash_32
    }

    /// The shared envelope (origin-independent command; CLI ⇔ Telegram parity).
    #[must_use]
    pub const fn envelope(&self) -> MessageEnvelope {
        self.envelope
    }
}

/// Proof that a same-message Telegram egress approval ceremony was completed this
/// turn. A send is denied unless one of these is present and granted. There is no
/// `Default` and no auto-grant: it is constructed only at an explicit approval
/// ceremony. Mirrors [`crate::provider::egress::EgressApproval`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TelegramEgressApproval {
    granted: bool,
}

impl TelegramEgressApproval {
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

/// Why a Telegram egress send was denied (fail-closed). Every denial is explicit
/// and visible — there is no silent fallback.
#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TelegramEgressDenied {
    /// The `telegram-egress` cargo feature is off — no transport is compiled (the
    /// offline std-core default).
    TransportNotCompiled = 1,
    /// The send is a dry-run (`live_send_allowed == false`) — the default posture.
    LiveSendNotAllowed = 2,
    /// No same-message approval was granted.
    ApprovalMissing = 3,
    /// The target host is not the allowlisted Telegram host (funds / chain /
    /// provider / other).
    HostNotAllowlisted = 4,
    /// The bot-token reference is missing / not resolvable.
    TokenMissing = 5,
    /// The transport call itself failed (network / TLS / status).
    TransportError = 6,
}

/// The outcome of a permitted Telegram send: the host, the HTTP status, and the
/// SHA-256 of the response body.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TelegramSendOutcome {
    /// The Telegram host the message was sent to.
    pub host: TelegramHost,
    /// The HTTP status code.
    pub status_u16: u16,
    /// SHA-256 of the response body.
    pub response_hash_32: [u8; 32],
}

/// The bounded Telegram Bot-API egress transport. Holds the bot-token reference (a
/// [`SecretRefView`] whose value is never loaded except at the TLS send boundary)
/// and gates every send. Mirrors [`crate::provider::egress::ProviderTransport`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TelegramTransport {
    host: TelegramHost,
    bot_token: SecretRefView,
}

impl TelegramTransport {
    /// A transport for the Telegram `host` authenticating with the bot-token
    /// reference `bot_token` (the value is never loaded here).
    #[must_use]
    pub const fn new(host: TelegramHost, bot_token: SecretRefView) -> Self {
        Self { host, bot_token }
    }

    /// The Telegram host.
    #[must_use]
    pub const fn host(self) -> TelegramHost {
        self.host
    }

    /// Pre-flight gate: classify whether a send WOULD be permitted, performing no
    /// I/O. Returns `Ok(())` only when the send is live-send approved, the
    /// same-message approval is granted, the host is the allowlisted Telegram host,
    /// and the bot-token reference is present. In Phase 0 a default `dry_run` send
    /// cannot pass — `live_send_allowed` is `false`.
    pub fn preflight(
        &self,
        send: &RedactedTelegramSend,
        approval: TelegramEgressApproval,
    ) -> Result<(), TelegramEgressDenied> {
        if !send.live_send_allowed {
            return Err(TelegramEgressDenied::LiveSendNotAllowed);
        }
        if !approval.is_granted() {
            return Err(TelegramEgressDenied::ApprovalMissing);
        }
        if !host_is_allowlisted(self.host.host()) {
            return Err(TelegramEgressDenied::HostNotAllowlisted);
        }
        if self.bot_token.location == crate::secrets::SecretLocation::Missing
            || !self.bot_token.value_never_loaded
        {
            return Err(TelegramEgressDenied::TokenMissing);
        }
        Ok(())
    }

    /// Send a redacted message to Telegram. ALWAYS denied in the default (offline,
    /// no-feature) build — the reqwest transport is not compiled. Even with the
    /// feature enabled, [`preflight`](Self::preflight) must pass, which a default
    /// dry-run send cannot. No byte leaves unless every gate passes.
    pub fn send(
        &self,
        send: &RedactedTelegramSend,
        approval: TelegramEgressApproval,
    ) -> Result<TelegramSendOutcome, TelegramEgressDenied> {
        self.preflight(send, approval)?;
        self.send_over_tls(send)
    }

    /// Offline std-core: no transport is compiled. The capability exists behind the
    /// `telegram-egress` feature (reqwest, vendored) but is not built by default.
    #[cfg(not(feature = "telegram-egress"))]
    #[allow(clippy::unused_self)]
    fn send_over_tls(
        &self,
        _send: &RedactedTelegramSend,
    ) -> Result<TelegramSendOutcome, TelegramEgressDenied> {
        Err(TelegramEgressDenied::TransportNotCompiled)
    }

    /// Feature-gated TLS transport. Reached ONLY after [`preflight`](Self::preflight)
    /// passes (live-send approved + same-message approval + allowlisted Telegram
    /// host + token present). The bot-token value is loaded ONLY here, at the TLS
    /// boundary, and dropped at scope end (never logged / cloned / persisted); the
    /// body carries only the redacted payload hash — never raw text.
    #[cfg(feature = "telegram-egress")]
    fn send_over_tls(
        &self,
        send: &RedactedTelegramSend,
    ) -> Result<TelegramSendOutcome, TelegramEgressDenied> {
        let token = crate::secrets::Secret::new(
            std::env::var(self.host.token_env()).map_err(|_| TelegramEgressDenied::TokenMissing)?,
        );
        let client = reqwest::blocking::Client::builder()
            .timeout(std::time::Duration::from_millis(30_000))
            .build()
            .map_err(|_| TelegramEgressDenied::TransportError)?;
        let url = format!(
            "{}/bot{}/sendMessage",
            self.host.base_url(),
            token.expose_secret()
        );
        let body = send.payload_hash_32().to_vec();
        let response = client
            .post(url)
            .body(body)
            .send()
            .map_err(|_| TelegramEgressDenied::TransportError)?;
        let status_u16 = response.status().as_u16();
        let bytes = response
            .bytes()
            .map_err(|_| TelegramEgressDenied::TransportError)?;
        Ok(TelegramSendOutcome {
            host: self.host,
            status_u16,
            response_hash_32: crate::sha256_32(bytes.as_ref()),
        })
    }
}

// ---- T (owner-authorized 2026-06-10): the REAL Bot-API sendMessage codec -------
//
// `send_over_tls` above is the G-WP-10 proof-of-egress skeleton (it posts the
// payload HASH as the raw body — it can never deliver a message). This section
// adds the real `sendMessage` codec behind the SAME feature + the SAME
// `preflight` gate stack: JSON body {chat_id, text}, response {ok,
// result.message_id | error_code}. TOKEN-IN-URL custody: the request URL embeds
// the bot token, so the URL is NEVER logged, hashed, or rendered; the request
// hash covers the BODY only. The `description` prose of an error response is
// NEVER surfaced (it can echo request content) — numeric `error_code` only.
// Threat model: ops/evidence/stage_g/gui_desktop/TELEGRAM_EGRESS_THREAT_MODEL.md.

/// Why a live Telegram send failed (fail-closed; static + numeric only).
#[cfg(feature = "telegram-egress")]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LiveTelegramError {
    /// A gate in [`TelegramTransport::preflight`] (or the token/transport layer)
    /// denied the send.
    Denied(TelegramEgressDenied),
    /// `TELEGRAM_CHAT_ID` is not present in the environment.
    ChatIdMissing,
    /// The Bot API answered `ok=false` (or a non-200 status). Carries ONLY the
    /// HTTP status and the numeric `error_code` — never the description prose.
    Api {
        /// The HTTP status code.
        status_u16: u16,
        /// The Bot API `error_code` (0 when absent/unparseable).
        error_code: i64,
    },
    /// The response body did not parse as a Bot API answer.
    MalformedResponse,
}

/// The outcome of ONE permitted live Telegram send. Carries no token, no chat
/// id, no URL, and no raw response body — the message id plus hash receipts.
#[cfg(feature = "telegram-egress")]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LiveTelegramOutcome {
    /// The Telegram host the message was sent to.
    pub host: TelegramHost,
    /// The HTTP status code (200 on this path).
    pub status_u16: u16,
    /// The delivered message id (`result.message_id`).
    pub message_id: u64,
    /// SHA-256 of the exact request BODY sent (never the URL — it holds the token).
    pub request_hash_32: [u8; 32],
    /// SHA-256 of the exact response body received.
    pub response_hash_32: [u8; 32],
}

/// The parsed fields of a Bot API response (internal).
#[cfg(feature = "telegram-egress")]
struct ParsedBotApiAnswer {
    ok: bool,
    message_id: u64,
    error_code: i64,
}

/// Build the `sendMessage` JSON body. `serde_json` owns all string escaping
/// (quotes / newlines / non-ASCII travel full-fidelity). Pure + deterministic.
#[cfg(feature = "telegram-egress")]
fn send_message_body(chat_id: &str, text: &str) -> String {
    serde_json::json!({ "chat_id": chat_id, "text": text }).to_string()
}

/// Parse a Bot API response. Returns `None` when the body is not a Bot API
/// answer. On `ok=false` the numeric `error_code` is lifted; the `description`
/// prose is deliberately ignored (untrusted; can echo request content).
#[cfg(feature = "telegram-egress")]
fn parse_send_message_response(bytes: &[u8]) -> Option<ParsedBotApiAnswer> {
    let v: serde_json::Value = serde_json::from_slice(bytes).ok()?;
    let ok = v.get("ok").and_then(serde_json::Value::as_bool)?;
    let message_id = v
        .get("result")
        .and_then(|r| r.get("message_id"))
        .and_then(serde_json::Value::as_u64)
        .unwrap_or(0);
    let error_code = v
        .get("error_code")
        .and_then(serde_json::Value::as_i64)
        .unwrap_or(0);
    Some(ParsedBotApiAnswer {
        ok,
        message_id,
        error_code,
    })
}

#[cfg(feature = "telegram-egress")]
impl TelegramTransport {
    /// Deliver ONE real, bounded, redacted text message to the owner's chat. The
    /// FULL [`preflight`](Self::preflight) gate stack applies (live-send flag +
    /// same-message approval + allowlist + token reference); the token and chat
    /// id are read only at the TLS boundary and dropped with the request. One
    /// attempt, no retry. The URL (which embeds the token) is never logged,
    /// hashed, or rendered.
    pub fn send_live_message(
        &self,
        send: &RedactedTelegramSend,
        approval: TelegramEgressApproval,
        text: &str,
    ) -> Result<LiveTelegramOutcome, LiveTelegramError> {
        self.preflight(send, approval)
            .map_err(LiveTelegramError::Denied)?;
        let token = crate::secrets::Secret::new(
            std::env::var(self.host.token_env())
                .map_err(|_| LiveTelegramError::Denied(TelegramEgressDenied::TokenMissing))?,
        );
        let chat_id = crate::secrets::Secret::new(
            std::env::var(self.host.chat_env()).map_err(|_| LiveTelegramError::ChatIdMissing)?,
        );
        let body = send_message_body(chat_id.expose_secret(), text);
        let request_hash_32 = crate::sha256_32(body.as_bytes());
        let client = reqwest::blocking::Client::builder()
            .timeout(std::time::Duration::from_millis(30_000))
            .https_only(true)
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .map_err(|_| LiveTelegramError::Denied(TelegramEgressDenied::TransportError))?;
        // The URL embeds the bot token: build it, send it, drop it — never log,
        // hash, render, or persist it (T gate 5).
        let url = format!(
            "{}/bot{}/sendMessage",
            self.host.base_url(),
            token.expose_secret()
        );
        let response = client
            .post(url)
            .header("content-type", "application/json")
            .body(body)
            .send()
            .map_err(|_| LiveTelegramError::Denied(TelegramEgressDenied::TransportError))?;
        let status_u16 = response.status().as_u16();
        let bytes = response
            .bytes()
            .map_err(|_| LiveTelegramError::Denied(TelegramEgressDenied::TransportError))?;
        let response_hash_32 = crate::sha256_32(bytes.as_ref());
        match parse_send_message_response(bytes.as_ref()) {
            Some(parsed) if parsed.ok => Ok(LiveTelegramOutcome {
                host: self.host,
                status_u16,
                message_id: parsed.message_id,
                request_hash_32,
                response_hash_32,
            }),
            Some(parsed) => Err(LiveTelegramError::Api {
                status_u16,
                error_code: parsed.error_code,
            }),
            None if status_u16 != 200 => Err(LiveTelegramError::Api {
                status_u16,
                error_code: 0,
            }),
            None => Err(LiveTelegramError::MalformedResponse),
        }
    }
}

// Codec unit tests: pure functions only — NO test fires a live send (a
// correct-phrase executor test with real env vars would egress; the live fire
// is the OWNER's V2 step — threat model §VERIFICATION).
#[cfg(all(test, feature = "telegram-egress"))]
mod live_codec_tests {
    use super::*;

    #[test]
    fn body_builder_escapes_and_round_trips() {
        let text = "deploy done \"ok\"\n한글 알림 \\ backslash";
        let body = send_message_body("123456789", text);
        let parsed = serde_json::from_str::<serde_json::Value>(&body).ok();
        assert!(parsed.is_some(), "body must be valid JSON");
        if let Some(v) = parsed {
            assert_eq!(v["chat_id"], "123456789");
            assert_eq!(v["text"], text);
        }
    }

    #[test]
    fn ok_response_yields_message_id() {
        let fixture = br#"{"ok": true, "result": {"message_id": 4242, "chat": {"id": 1}}}"#;
        let parsed = parse_send_message_response(fixture);
        assert!(parsed.is_some());
        if let Some(p) = parsed {
            assert!(p.ok);
            assert_eq!(p.message_id, 4242);
        }
    }

    #[test]
    fn error_response_yields_numeric_code_never_description() {
        let fixture =
            br#"{"ok": false, "error_code": 401, "description": "Unauthorized: secret-ish echo"}"#;
        let parsed = parse_send_message_response(fixture);
        assert!(parsed.is_some());
        if let Some(p) = parsed {
            assert!(!p.ok);
            assert_eq!(p.error_code, 401);
            // ParsedBotApiAnswer structurally CANNOT carry the description —
            // the prose is dropped at parse time (T gate 8).
        }
    }

    #[test]
    fn malformed_response_is_none() {
        assert!(parse_send_message_response(b"not json").is_none());
        assert!(parse_send_message_response(b"{\"result\": {}}").is_none());
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::command::{CliMode, CommandEnvelope, CommandRisk};
    use crate::commands::platform_telegram::PlatformOrigin;
    use crate::grammar::CliNamespace;
    use crate::secrets::classify_reference;

    fn token() -> SecretRefView {
        classify_reference("telegram_bot_token", "env:TELEGRAM_BOT_TOKEN")
    }

    fn command() -> CommandEnvelope {
        CommandEnvelope::classify(
            CliNamespace::Provider,
            "status",
            CliMode::Tui,
            CommandRisk::ReadOnly,
            b"",
        )
    }

    fn test_receipt() -> RedactionReceipt {
        use crate::provider::redaction::{RedactionRequest, redact};
        let frags: [&str; 1] = ["telegram-test-body"];
        redact(&RedactionRequest {
            fragments: &frags,
            candidate_memory_ids: &[],
            deleted_ids: &[],
            include_private_memory: false,
        })
        .expect("a benign public fragment redacts to a non-stored receipt")
    }

    fn dry_run_send() -> RedactedTelegramSend {
        let envelope = MessageEnvelope::new(PlatformOrigin::Telegram, command());
        RedactedTelegramSend::dry_run(envelope, test_receipt())
            .expect("a non-stored-body receipt builds a dry-run send")
    }

    // The PRODUCTION builder always leaves live_send_allowed = false; flipping it
    // to live REQUIRES a granted approval (into_live) — there is no struct-update.
    fn live_send() -> RedactedTelegramSend {
        dry_run_send().into_live(TelegramEgressApproval::grant())
    }

    #[test]
    fn default_send_is_dry_run_and_denied() {
        // The production builder leaves live_send_allowed = false → denied even
        // with a granted approval (the Phase-0 invariant; dry-run is the default).
        let s = dry_run_send();
        assert!(!s.live_send_allowed);
        let t = TelegramTransport::new(TelegramHost::BotApi, token());
        assert_eq!(
            t.send(&s, TelegramEgressApproval::grant()),
            Err(TelegramEgressDenied::LiveSendNotAllowed)
        );
    }

    #[test]
    fn approval_required_even_when_live_send_allowed() {
        let s = live_send();
        let t = TelegramTransport::new(TelegramHost::BotApi, token());
        assert_eq!(
            t.preflight(&s, TelegramEgressApproval::denied()),
            Err(TelegramEgressDenied::ApprovalMissing)
        );
    }

    #[test]
    fn only_telegram_host_allowlisted_funds_and_providers_unreachable() {
        // No funds / chain / mainnet / provider / local host is allowlisted.
        for h in [
            "rpc.mainnet.solana.com",
            "api.mainnet-beta.solana.com",
            "ethereum.publicnode.com",
            "api.anthropic.com",
            "api.openai.com",
            "127.0.0.1",
            "localhost",
            "evil.example.com",
        ] {
            assert!(!host_is_allowlisted(h), "{h} must NOT be allowlisted");
        }
        assert!(host_is_allowlisted(TelegramHost::BotApi.host()));
        assert_eq!(TelegramHost::BotApi.host(), "api.telegram.org");
    }

    #[test]
    fn telegram_host_is_tls() {
        assert!(
            TelegramHost::BotApi.base_url().starts_with("https://"),
            "telegram base url must be https"
        );
    }

    /// E0e-2 — SI-5 allowlist-excludes-chain (telegram leg). The telegram allowlist
    /// rejects every funds / chain / wallet / RPC host AND every provider host, is
    /// exactly the single Bot API host, and that host string does not look like a
    /// chain RPC. FAILS if a funds or cross-egress host ever becomes reachable.
    #[test]
    fn si5_telegram_allowlist_excludes_funds_chain_and_providers() {
        const REJECTED: &[&str] = &[
            "rpc.mainnet.solana.com",
            "api.mainnet-beta.solana.com",
            "api.devnet.solana.com",
            "ethereum.publicnode.com",
            "mainnet.infura.io",
            "polygon-rpc.com",
            "api.anthropic.com",
            "api.openai.com",
            "openrouter.ai",
            "generativelanguage.googleapis.com",
            "127.0.0.1",
            "localhost",
            "evil.example.com",
        ];
        for h in REJECTED {
            assert!(!host_is_allowlisted(h), "{h} must NOT be allowlisted");
        }
        assert_eq!(ALLOWLISTED_TELEGRAM_HOSTS.len(), 1);
        assert_eq!(TelegramHost::BotApi.host(), "api.telegram.org");
        for h in ALLOWLISTED_TELEGRAM_HOSTS {
            let host = h.host();
            for needle in ["solana", "mainnet", "rpc", "wallet", "chain", "infura"] {
                assert!(
                    !host.contains(needle),
                    "{host} looks like a funds/chain host (contains {needle})"
                );
            }
        }
        assert!(host_is_allowlisted(TelegramHost::BotApi.host()));
    }

    #[test]
    fn token_missing_denied() {
        let s = live_send();
        // An empty reference resolves to a Missing secret location.
        let no_token = classify_reference("telegram_bot_token", "");
        let t = TelegramTransport::new(TelegramHost::BotApi, no_token);
        assert_eq!(
            t.preflight(&s, TelegramEgressApproval::grant()),
            Err(TelegramEgressDenied::TokenMissing)
        );
    }

    #[test]
    fn payload_is_only_a_redacted_hash() {
        let s = dry_run_send();
        assert_eq!(s.payload_hash_32(), s.redacted_message_hash_32);
    }

    #[test]
    fn same_message_envelope_cli_and_telegram() {
        // CLI ⇔ Telegram parity: the SAME verb yields the SAME command on either
        // channel; only the transport origin differs.
        let cli = MessageEnvelope::new(PlatformOrigin::Cli, command());
        let send = dry_run_send();
        assert!(
            send.envelope().same_command(&cli),
            "the telegram send must carry the SAME command envelope as the CLI"
        );
        assert_ne!(send.envelope().origin, cli.origin);
    }

    #[test]
    fn bot_token_is_a_ref_value_never_loaded() {
        // The transport holds only a reference; the secret value is never loaded
        // (a structural invariant of SecretRefView — the token is never logged).
        let t = TelegramTransport::new(TelegramHost::BotApi, token());
        assert!(t.bot_token.value_never_loaded);
        assert_ne!(
            t.bot_token.location,
            crate::secrets::SecretLocation::Missing
        );
    }

    // With every gate satisfiable (test-only live send + grant + allowlisted host +
    // token present), the offline std-core STILL denies: no transport is compiled.
    #[cfg(not(feature = "telegram-egress"))]
    #[test]
    fn transport_not_compiled_in_offline_core() {
        let s = live_send();
        let t = TelegramTransport::new(TelegramHost::BotApi, token());
        assert_eq!(
            t.send(&s, TelegramEgressApproval::grant()),
            Err(TelegramEgressDenied::TransportNotCompiled)
        );
    }
}
