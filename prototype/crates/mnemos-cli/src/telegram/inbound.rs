//! `telegram::inbound` — the bounded Bot-API INBOUND transport (ENDGAME E4-1:
//! getUpdates long-poll RECEIVE + defensive PARSE).
//!
//! This is the INBOUND half of Telegram full-duplex (the outbound `sendMessage` is
//! [`crate::telegram::egress`]). It exists so the owner, while AWAY, can reply on
//! the phone to approve a pending gated action. INBOUND BYTES ARE UNTRUSTED — this
//! module RECEIVES and PARSES them DEFENSIVELY; it does NOT itself authorize
//! anything. Authorization (sender-pin + action-binding + the unforgeable SI-3
//! mint) is E4-2; the wire to the pending action is E4-3. Threat model:
//! `ops/evidence/stage_g/agent_loop/TELEGRAM_INBOUND_THREAT_MODEL.md` (⑪ IV-T1..).
//!
//! Owner-ratified seams (2026-06-12): **getUpdates long-poll** (no public endpoint /
//! no inbound server socket / no TLS cert — minimal CU, owner-only chat) under a
//! **new `telegram-inbound` cargo feature** (the default + the egress-only build
//! both have ZERO inbound). OFF by default: without the feature there is no
//! transport and no parser — only the pure, always-compiled bounding + offset
//! types, whose security invariants (IV-T5 bounded fields, IV-T8 monotone offset)
//! are testable in the default build.
//!
//! Defensive parse (IV-T5): the parser extracts ONLY three fields — `update_id`
//! (u64), `message.chat.id` (i64), and a LENGTH-BOUNDED `message.text` — and
//! ignores every other field of the Bot-API update. The text is bounded to
//! [`TELEGRAM_INBOUND_MAX_TEXT_BYTES`] at construction (an approval reply is a short
//! verb + a hash prefix). No inbound byte is logged raw or enters a prompt; raw
//! bytes never leave this module un-bounded. `serde_json` owns all unescaping.
//!
//! Monotone offset (IV-T8): [`UpdateOffset`] advances to `max(update_id)+1` over a
//! batch and can NEVER rewind — a replayed or lower `update_id` cannot re-deliver an
//! already-consumed update, so the same update is never re-fetched (transport-level
//! anti-replay, complementing the E4-2 `approval_sync` ledger).
//!
//! Reuse (no reinvention): the host allowlist + the bot-token env name are the
//! canonical [`crate::telegram::egress`] surface (ONE allowlisted host
//! `api.telegram.org`, SI-5; ONE env-name source). The bot token is a
//! [`crate::secrets::Secret`] read only at the TLS boundary, never logged.

/// Max bytes of inbound message text retained. An approval reply is a short verb
/// plus a 16-hex action-hash prefix; anything larger is bounded away (untrusted
/// input — IV-T5). A hostile oversized text cannot grow this module's memory or
/// reach a prompt: it is truncated at a UTF-8 boundary at construction.
pub const TELEGRAM_INBOUND_MAX_TEXT_BYTES: usize = 256;

/// Max updates consumed per long-poll cycle — a bounded batch (no unbounded buffer;
/// IV-T8). The getUpdates request also sets `limit` to this, so the server returns
/// at most this many; the parse-side `take` is defense-in-depth.
pub const TELEGRAM_INBOUND_BATCH_LIMIT: u16 = 10;

/// The long-poll timeout (seconds) the getUpdates request asks the server to hold
/// the connection open. Bounded; the HTTP client timeout is set strictly longer so
/// the client never aborts before the server's long-poll returns.
pub const TELEGRAM_INBOUND_POLL_TIMEOUT_S: u16 = 30;

/// A defensively-parsed inbound update: ONLY the three trusted-after-bounding
/// fields are retained. Every field is private; the ONLY constructor is
/// [`new_bounded`](Self::new_bounded), which bounds the text — so an `InboundUpdate`
/// whose text exceeds the cap is UNREPRESENTABLE (IV-T5). The text is still
/// UNTRUSTED content: it never enters a prompt or an egress body without passing the
/// SI-2 `redact()` choke (E4-2/E4-3).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InboundUpdate {
    update_id_u64: u64,
    sender_chat_id_i64: i64,
    text_bounded: String,
    truncated: bool,
}

impl InboundUpdate {
    /// Build an inbound update, BOUNDING the text to
    /// [`TELEGRAM_INBOUND_MAX_TEXT_BYTES`] at a UTF-8 char boundary (a hostile
    /// oversized text is truncated, never retained whole — IV-T5). The ONLY
    /// constructor, so no `InboundUpdate` can hold an unbounded text.
    #[must_use]
    pub fn new_bounded(update_id_u64: u64, sender_chat_id_i64: i64, raw_text: &str) -> Self {
        let mut text_bounded = String::new();
        let mut truncated = false;
        for ch in raw_text.chars() {
            if text_bounded.len() + ch.len_utf8() > TELEGRAM_INBOUND_MAX_TEXT_BYTES {
                truncated = true;
                break;
            }
            text_bounded.push(ch);
        }
        Self {
            update_id_u64,
            sender_chat_id_i64,
            text_bounded,
            truncated,
        }
    }

    /// The Telegram `update_id` — used ONLY to advance the monotone offset (IV-T8);
    /// it is not authority.
    #[must_use]
    pub const fn update_id(&self) -> u64 {
        self.update_id_u64
    }

    /// The sender's `chat.id`. The AUTH gate (E4-2) compares this against the
    /// `TELEGRAM_CHAT_ID` pin; a non-owner sender is dropped before any mint
    /// (IV-T1). It is a plain integer, never a secret value.
    #[must_use]
    pub const fn sender_chat_id(&self) -> i64 {
        self.sender_chat_id_i64
    }

    /// The bounded message text (UNTRUSTED). Never enters a prompt or an egress body
    /// without passing `redact()`.
    #[must_use]
    pub fn text(&self) -> &str {
        &self.text_bounded
    }

    /// Whether the original text exceeded the cap and was truncated (the surplus
    /// was attacker padding; the verb + hash prefix fit well within the cap).
    #[must_use]
    pub const fn was_truncated(&self) -> bool {
        self.truncated
    }
}

/// The monotone getUpdates offset cursor. Advances to `max(update_id)+1` over a
/// consumed batch; a replayed or lower `update_id` can NEVER rewind it (IV-T8), so
/// an already-consumed update is never re-fetched. Default = `0` (fetch from the
/// start of the unconfirmed backlog).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct UpdateOffset {
    next_u64: u64,
}

impl UpdateOffset {
    /// A fresh cursor (offset `0`).
    #[must_use]
    pub const fn new() -> Self {
        Self { next_u64: 0 }
    }

    /// The next offset to request (the smallest unconfirmed `update_id`).
    #[must_use]
    pub const fn next(&self) -> u64 {
        self.next_u64
    }

    /// Advance PAST a consumed `update_id` — monotone + saturating. A smaller or
    /// equal `update_id` is a no-op (the cursor never rewinds; IV-T8).
    pub fn advance_past(&mut self, update_id_u64: u64) {
        let candidate = update_id_u64.saturating_add(1);
        if candidate > self.next_u64 {
            self.next_u64 = candidate;
        }
    }
}

/// Why a raw Bot-API update element did not parse into an [`InboundUpdate`]
/// (fail-closed; the element is skipped, but the offset still advances past it so a
/// malformed update can never jam the poll — IV-T8).
#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum InboundParseReject {
    /// No `update_id` — not a Bot-API update at all.
    NotAnUpdate = 1,
    /// No `message` / `chat.id` / `text` — not an approvable text reply.
    NoMessage = 2,
}

/// Parse ONE raw Bot-API update value into an [`InboundUpdate`], defensively: only
/// `update_id` (u64) + `message.chat.id` (i64) + a bounded `message.text` are
/// extracted; every other field is ignored (IV-T5). Fail-closed on a missing field.
#[cfg(feature = "telegram-inbound")]
pub fn parse_update(value: &serde_json::Value) -> Result<InboundUpdate, InboundParseReject> {
    let update_id = value
        .get("update_id")
        .and_then(serde_json::Value::as_u64)
        .ok_or(InboundParseReject::NotAnUpdate)?;
    let message = value.get("message").ok_or(InboundParseReject::NoMessage)?;
    let chat_id = message
        .get("chat")
        .and_then(|c| c.get("id"))
        .and_then(serde_json::Value::as_i64)
        .ok_or(InboundParseReject::NoMessage)?;
    let text = message
        .get("text")
        .and_then(serde_json::Value::as_str)
        .ok_or(InboundParseReject::NoMessage)?;
    Ok(InboundUpdate::new_bounded(update_id, chat_id, text))
}

/// Parse a getUpdates response body into (the bounded approvable updates, the max
/// `update_id` seen for the offset advance). A non-`ok` / malformed body yields an
/// empty batch (fail-closed). The batch is bounded to [`TELEGRAM_INBOUND_BATCH_LIMIT`].
/// The max `update_id` is computed over EVERY element with an `update_id` (even ones
/// that don't parse to an approvable reply) so the offset advances past them too —
/// a malformed or non-owner update can never jam the poll (IV-T8).
#[cfg(feature = "telegram-inbound")]
#[must_use]
pub fn parse_batch(bytes: &[u8]) -> (Vec<InboundUpdate>, Option<u64>) {
    let Ok(v) = serde_json::from_slice::<serde_json::Value>(bytes) else {
        return (Vec::new(), None);
    };
    if v.get("ok").and_then(serde_json::Value::as_bool) != Some(true) {
        return (Vec::new(), None);
    }
    let Some(arr) = v.get("result").and_then(serde_json::Value::as_array) else {
        return (Vec::new(), None);
    };
    let mut updates = Vec::new();
    let mut max_id: Option<u64> = None;
    for elem in arr.iter().take(TELEGRAM_INBOUND_BATCH_LIMIT as usize) {
        if let Some(id) = elem.get("update_id").and_then(serde_json::Value::as_u64) {
            max_id = Some(max_id.map_or(id, |m| m.max(id)));
        }
        if let Ok(u) = parse_update(elem) {
            updates.push(u);
        }
    }
    (updates, max_id)
}

/// Why an inbound long-poll did not run (fail-closed; explicit). The inbound
/// transport, like egress, reaches the network ONLY behind the feature gate; the
/// host is re-checked against the single Telegram allowlist (SI-5) and the bot-token
/// reference must be present.
#[cfg(feature = "telegram-inbound")]
#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum InboundPollError {
    /// The target host is not the allowlisted Telegram host (funds / chain /
    /// provider / other) — structurally unreachable.
    HostNotAllowlisted = 1,
    /// The bot-token reference is missing / not resolvable.
    TokenMissing = 2,
    /// The transport call itself failed (network / TLS / status / body).
    TransportError = 3,
}

/// The bounded Telegram Bot-API INBOUND transport (getUpdates long-poll). Holds the
/// SAME host + bot-token reference shape as [`crate::telegram::egress::TelegramTransport`];
/// the token value is read only at the TLS boundary and dropped with the request,
/// never logged (the URL embeds the token — never logged/hashed/rendered). One
/// bounded long-poll per call, then the bounded parse; no unbounded buffer, no retry.
#[cfg(feature = "telegram-inbound")]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct InboundTransport {
    host: crate::telegram::egress::TelegramHost,
    bot_token: crate::secrets::SecretRefView,
}

#[cfg(feature = "telegram-inbound")]
impl InboundTransport {
    /// A transport for the Telegram `host` authenticating with the bot-token
    /// reference `bot_token` (the value is never loaded here).
    #[must_use]
    pub const fn new(
        host: crate::telegram::egress::TelegramHost,
        bot_token: crate::secrets::SecretRefView,
    ) -> Self {
        Self { host, bot_token }
    }

    /// Run ONE bounded long-poll at `offset`, returning the bounded approvable
    /// updates and the ADVANCED offset (monotone — never rewinds; IV-T8). Reached
    /// ONLY behind the feature gate; the host is re-checked against the Telegram
    /// allowlist (SI-5) and the bot-token reference must be present. The token rides
    /// in the URL path: the URL is built, sent, and dropped — never logged, hashed,
    /// or rendered. The body carries no secret. UNTRUSTED response bytes go straight
    /// to the bounded [`parse_batch`] (IV-T5).
    pub fn poll_once(
        &self,
        offset: UpdateOffset,
    ) -> Result<(Vec<InboundUpdate>, UpdateOffset), InboundPollError> {
        if !crate::telegram::egress::host_is_allowlisted(self.host.host()) {
            return Err(InboundPollError::HostNotAllowlisted);
        }
        if self.bot_token.location == crate::secrets::SecretLocation::Missing
            || !self.bot_token.value_never_loaded
        {
            return Err(InboundPollError::TokenMissing);
        }
        let token = crate::secrets::Secret::new(
            std::env::var(self.host.token_env()).map_err(|_| InboundPollError::TokenMissing)?,
        );
        // The HTTP timeout is strictly longer than the long-poll timeout so the
        // client never aborts before the server's long-poll returns.
        let client = reqwest::blocking::Client::builder()
            .timeout(std::time::Duration::from_secs(
                u64::from(TELEGRAM_INBOUND_POLL_TIMEOUT_S) + 10,
            ))
            .https_only(true)
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .map_err(|_| InboundPollError::TransportError)?;
        let body = serde_json::json!({
            "offset": offset.next(),
            "limit": TELEGRAM_INBOUND_BATCH_LIMIT,
            "timeout": TELEGRAM_INBOUND_POLL_TIMEOUT_S,
        })
        .to_string();
        // The URL embeds the bot token: build it, send it, drop it — never log,
        // hash, render, or persist it.
        let url = format!(
            "{}/bot{}/getUpdates",
            self.host.base_url(),
            token.expose_secret()
        );
        let response = client
            .post(url)
            .header("content-type", "application/json")
            .body(body)
            .send()
            .map_err(|_| InboundPollError::TransportError)?;
        let bytes = response
            .bytes()
            .map_err(|_| InboundPollError::TransportError)?;
        let (updates, max_id) = parse_batch(bytes.as_ref());
        let mut new_offset = offset;
        if let Some(id) = max_id {
            new_offset.advance_past(id);
        }
        Ok((updates, new_offset))
    }
}

// ---- Always-compiled core tests (default build): the security invariants that do
// NOT need serde_json — IV-T5 bounded text + IV-T8 monotone offset. ---------------
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn text_is_bounded_at_a_utf8_boundary_iv_t5() {
        // A short reply is retained whole, not truncated.
        let short = InboundUpdate::new_bounded(7, 1001, "approve a1b2c3d4e5f6a7b8");
        assert_eq!(short.text(), "approve a1b2c3d4e5f6a7b8");
        assert!(!short.was_truncated());
        // A hostile oversized text is bounded; the retained text never exceeds the
        // cap and stays valid UTF-8 (no panic, no unbounded retention).
        let huge = "한".repeat(10_000); // 3 bytes each => 30_000 bytes raw
        let u = InboundUpdate::new_bounded(8, 1001, &huge);
        assert!(u.was_truncated());
        assert!(u.text().len() <= TELEGRAM_INBOUND_MAX_TEXT_BYTES);
        // Truncation respected the char boundary: the bounded text is a valid prefix.
        assert!(huge.starts_with(u.text()));
    }

    #[test]
    fn offset_advances_monotonically_and_never_rewinds_iv_t8() {
        let mut off = UpdateOffset::new();
        assert_eq!(off.next(), 0);
        off.advance_past(40);
        assert_eq!(off.next(), 41);
        // A replayed / lower update_id can NEVER rewind the cursor.
        off.advance_past(40);
        assert_eq!(off.next(), 41);
        off.advance_past(10);
        assert_eq!(off.next(), 41);
        // A higher update_id advances it.
        off.advance_past(99);
        assert_eq!(off.next(), 100);
        // Saturating at the integer ceiling (no overflow panic).
        off.advance_past(u64::MAX);
        assert_eq!(off.next(), u64::MAX);
    }
}

// ---- Codec tests: pure functions on fixtures only — NO test fires a live poll (a
// real getUpdates against the Bot API is the OWNER's V2 step; the agent starts no
// real poll). serde_json-gated. ---------------------------------------------------
#[cfg(all(test, feature = "telegram-inbound"))]
mod codec_tests {
    #![allow(clippy::expect_used)]

    use super::*;

    #[test]
    fn parses_owner_text_reply_extracting_only_three_fields() {
        let fixture = br#"{"update_id": 555, "message": {"message_id": 9,
            "from": {"id": 1001, "is_bot": false, "username": "owner"},
            "chat": {"id": 1001, "type": "private"},
            "date": 1700000000, "text": "approve a1b2c3d4e5f6a7b8"}}"#;
        let v: serde_json::Value = serde_json::from_slice(fixture).expect("valid json");
        let parsed = parse_update(&v).expect("an owner text reply parses");
        assert_eq!(parsed.update_id(), 555);
        assert_eq!(parsed.sender_chat_id(), 1001);
        assert_eq!(parsed.text(), "approve a1b2c3d4e5f6a7b8");
    }

    #[test]
    fn non_message_or_textless_update_is_rejected_not_an_approval() {
        // An update with no message (e.g. an edited_channel_post / poll) is rejected.
        let no_msg = serde_json::json!({"update_id": 1, "edited_message": {"text": "x"}});
        assert_eq!(parse_update(&no_msg), Err(InboundParseReject::NoMessage));
        // A message with no text (e.g. a photo) is rejected.
        let no_text =
            serde_json::json!({"update_id": 2, "message": {"chat": {"id": 1001}, "photo": []}});
        assert_eq!(parse_update(&no_text), Err(InboundParseReject::NoMessage));
        // A value with no update_id is not a Bot-API update.
        let not_update = serde_json::json!({"message": {"chat": {"id": 1}, "text": "hi"}});
        assert_eq!(
            parse_update(&not_update),
            Err(InboundParseReject::NotAnUpdate)
        );
    }

    #[test]
    fn batch_is_bounded_and_offset_max_covers_unparsed_updates_iv_t8() {
        // A batch with one approvable reply + one non-approval (no text) but WITH an
        // update_id: the approvable one is returned, AND the max update_id covers the
        // non-approval so the offset advances past it (no jam).
        let body = br#"{"ok": true, "result": [
            {"update_id": 100, "message": {"chat": {"id": 1001}, "text": "approve deadbeef"}},
            {"update_id": 101, "message": {"chat": {"id": 1001}, "photo": []}}
        ]}"#;
        let (updates, max_id) = parse_batch(body);
        assert_eq!(updates.len(), 1);
        assert_eq!(updates[0].text(), "approve deadbeef");
        assert_eq!(max_id, Some(101)); // advances past the unparsed update too
    }

    #[test]
    fn not_ok_or_malformed_body_yields_empty_batch_fail_closed() {
        assert_eq!(parse_batch(b"not json"), (Vec::new(), None));
        let (u1, m1) = parse_batch(br#"{"ok": false, "error_code": 401}"#);
        assert!(u1.is_empty());
        assert_eq!(m1, None);
        let (u2, m2) = parse_batch(br#"{"ok": true}"#); // no result array
        assert!(u2.is_empty());
        assert_eq!(m2, None);
    }

    #[test]
    fn batch_caps_at_the_limit_no_unbounded_buffer() {
        // 25 approvable updates in one response: the parse takes at most the limit.
        let mut elems = Vec::new();
        for i in 0..25u64 {
            elems.push(format!(
                r#"{{"update_id": {i}, "message": {{"chat": {{"id": 1001}}, "text": "approve {i:08x}"}}}}"#
            ));
        }
        let body = format!(r#"{{"ok": true, "result": [{}]}}"#, elems.join(","));
        let (updates, max_id) = parse_batch(body.as_bytes());
        assert_eq!(updates.len(), TELEGRAM_INBOUND_BATCH_LIMIT as usize);
        // The max update_id is computed over the bounded window (0..limit-1).
        assert_eq!(max_id, Some(u64::from(TELEGRAM_INBOUND_BATCH_LIMIT) - 1));
    }
}
