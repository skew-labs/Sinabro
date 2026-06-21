//! `repl.rs` — Hermes-style local REPL (atom #45 · J.0.5).
//!
//! # Why this madness
//!
//! Phase 0 dogfooding (§9.5 — "PR #1부터 dogfooding") needs the same
//! `m-agent` turn engine that Telegram (atom #41 · J.0.1) calls into, but
//! reached through a plain local stdin/stdout cockpit. This atom lands
//! that cockpit as a single I/O loop: a `&'static str` prompt, a bounded
//! line history, an EOF-clean shutdown path, and an in-loop hook for the
//! atom #43 control-command grammar (`/clear`, `/kill`) so a smuggled
//! command word cannot be persisted as a history line.
//!
//! The atom is intentionally an I/O loop (criterion N/A per ATOM_PLAN
//! line 1286). The structural invariant the test set protects is the
//! history bound: the line ring never holds more than `history_cap_u16`
//! entries regardless of input length.
//!
//! ## Canonical OUT (verbatim from `MNEMOS_ATOM_PLAN.md` §4.J line 737-739)
//!
//! ```text
//! // J.0.5 prototype/bin/mnemos-cli/src/repl.rs
//! pub struct CliRepl { prompt: &'static str, history_cap_u16: u16 }
//! pub fn run_repl(repl: &CliRepl /*, llm, store, ... */) -> MnemosResult<()>;
//! // Hermes식 입력창
//! ```
//!
//! The `/*, llm, store, ... */` placeholder in the canonical signature
//! marks the future production wiring (live `LlmClient`, `b-memory`
//! store, etc.) that a Stage F/H atom threads through `run_repl`. This
//! atom keeps the canonical surface narrow (`&CliRepl` only) and lifts
//! the testable pieces into `pub(crate)` sibling functions so a mock
//! `LlmClient` can drive the turn engine in
//! [`tests::j0_5_drives_turn_engine`].
//!
//! ## Reuse
//!
//! - atom #4 (`a-core::logging` — implicit): `RedactedLogValue`,
//!   `LogRedactionKind`, `redact_for_log`. Not directly imported here;
//!   atom #44 (`j-ux::redact_outbound`) already forwards into the same
//!   kernel. The outbound surface call (`sendMessage` / CLI `stdout`)
//!   that wraps the LLM response is the future J-stage atom's
//!   responsibility — this atom proves the loop carrier without
//!   emitting any user-visible payload via `println!` (denied by
//!   clippy lint).
//! - atom #2 (`a-core::error`): `MnemosError::source_redacted_from_error`
//!   folds an `io::Error` (from `Stdin::read_line` / `Stdout::write_all`)
//!   into a payload-free, `Copy` error with the [`ErrorOp::Agent`] tag.
//!   The raw `io::Error` cause is dropped at the boundary — no
//!   filesystem path or `errno` text can ride out through the error
//!   channel.
//! - atom #21..#27 (`m-agent`): [`LlmClient`] / [`DeltaSink`] /
//!   [`ChatMessage`] / [`Role`] / [`LlmRequestView`] / [`LlmError`] /
//!   [`TurnUsage`] / [`LazyToolSchema`] / [`EMPTY_TOOL_REGISTRY`] /
//!   [`CacheBreakpointPlan`]. The turn-engine driver `drive_turn` is a
//!   generic over [`LlmClient`]; the production loop currently does not
//!   call it (the live HTTP client is deferred to a Stage M/H atom),
//!   but the surface is exercised by `j0_5_drives_turn_engine` against
//!   an inline mock — the same trait the future live transport will
//!   implement.
//! - atom #43 (`j-ux::slash`): [`SlashCommand`] / [`parse_slash`]. The
//!   REPL routes `/clear` and `/kill` before pushing the line into the
//!   history ring so a control word can never be persisted as a chat
//!   line. `/budget` and `/skill <id>` parse cleanly but their
//!   side-effect routing is the Stage F/H express-control-rail atom's
//!   responsibility — this atom recognises them as control input
//!   (skips history push) but performs no further action.
//! - atom #41..#44 (j-ux family, "공유 UX"): the REPL is a different
//!   transport surface from Telegram but shares the same redact /
//!   slash / progressive-edit grammar. No teloxide wiring on this
//!   atom — the j-ux crate has zero teloxide dep today.
//!
//! ## Non-goals (Phase 0 scope discipline)
//!
//! - Live LLM HTTP client (deferred to the M-stage atom that lands
//!   the live `LlmClient` impl).
//! - Persistent history file / readline integration / multi-line
//!   editor (not in §4.J canonical OUT — the carrier is
//!   `history_cap_u16: u16` only).
//! - `/budget` / `/skill <id>` routing (Stage F/H express control
//!   rail per ATOM_PLAN line 1263).
//! - Supervisor-driven `/kill` (atom #3 + Stage F/H wiring) — this
//!   atom only short-circuits the REPL loop on `/kill`.

use std::collections::VecDeque;
use std::io::{self, BufRead, Write};
use std::ops::ControlFlow;

use mnemos_a_core::{ErrorOp, MnemosError, MnemosResult};
use mnemos_j_ux::{SlashCommand, parse_slash};
use mnemos_m_agent::{
    CacheBreakpointPlan, ChatMessage, DeltaSink, EMPTY_TOOL_REGISTRY, LazyToolSchema, LlmClient,
    LlmError, LlmRequestView, Role, SseDelta, TurnUsage,
};

// ===========================================================================
// 1. Default REPL surface
// ===========================================================================

/// Default prompt rendered before every read. `&'static str` so the
/// carrier itself owns no bytes — the prompt source lives in the
/// `.rodata` of the linked binary.
pub(crate) const DEFAULT_PROMPT: &str = "mnemos> ";

/// Default ring capacity. `u16` so the upper bound is type-level
/// (`65_535` lines) — the canonical OUT field width.
pub(crate) const DEFAULT_HISTORY_CAP_U16: u16 = 256;

// ===========================================================================
// 2. CliRepl — REPL config carrier (canonical OUT)
// ===========================================================================

/// REPL configuration. Two private fields per §4.J line 738:
/// `prompt: &'static str` (no owned bytes) and
/// `history_cap_u16: u16` (type-level upper bound). The carrier is
/// `Copy` because every payload is `Copy`; snapshotting a config
/// before threading it into [`run_repl`] never moves the value.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub struct CliRepl {
    /// Prompt prefix written before every line read.
    prompt: &'static str,
    /// Maximum number of past input lines retained in the ring.
    history_cap_u16: u16,
}

impl CliRepl {
    /// Construct a [`CliRepl`] with the supplied prompt and ring
    /// capacity. `const fn` so a binary-local fixture can fold a
    /// config at compile time.
    #[inline]
    #[must_use]
    pub const fn new(prompt: &'static str, history_cap_u16: u16) -> Self {
        Self {
            prompt,
            history_cap_u16,
        }
    }

    /// The static prompt string. Canonical-OUT accessor; the
    /// production loop reads the field directly via
    /// `repl.prompt`, so the accessor is currently consumed only
    /// by the unit tests — `#[allow(dead_code)]` suppresses the
    /// resulting bin-crate dead-code warning. A Stage F/H atom
    /// that exposes the REPL surface from a sibling crate will
    /// activate the accessor.
    #[inline]
    #[must_use]
    #[allow(dead_code)]
    pub const fn prompt(&self) -> &'static str {
        self.prompt
    }

    /// The ring capacity (max retained history lines). Same
    /// dead-code rationale as [`Self::prompt`] — the production
    /// loop reads the field directly via `repl.history_cap_u16`.
    #[inline]
    #[must_use]
    #[allow(dead_code)]
    pub const fn history_cap_u16(&self) -> u16 {
        self.history_cap_u16
    }
}

impl Default for CliRepl {
    /// Default cockpit: prompt `"mnemos> "`, history cap 256.
    #[inline]
    fn default() -> Self {
        Self::new(DEFAULT_PROMPT, DEFAULT_HISTORY_CAP_U16)
    }
}

// ===========================================================================
// 3. run_repl — canonical OUT entry (production stdin/stdout)
// ===========================================================================

/// Drive the REPL against the process `stdin` / `stdout`.
///
/// Locks `stdin` and `stdout` once, builds a fresh [`History`]
/// ring sized by `repl.history_cap_u16()`, and delegates the
/// per-line loop to [`repl_loop_io`]. The loop terminates on EOF
/// (`Stdin::read_line` returning `Ok(0)`) or on a `/kill` line.
/// Any `io::Error` raised by the underlying stream is folded into
/// [`MnemosError::source_redacted_from_error`] with the
/// [`ErrorOp::Agent`] tag (atom #2 spine — the raw cause is
/// dropped at the boundary).
///
/// The canonical OUT signature carries a trailing
/// `/*, llm, store, ... */` placeholder for the future production
/// wiring; this atom keeps the surface to `&CliRepl` only.
#[inline]
pub fn run_repl(repl: &CliRepl) -> MnemosResult<()> {
    let stdin = io::stdin();
    let stdout = io::stdout();
    let mut reader = stdin.lock();
    let mut writer = stdout.lock();
    let mut history = History::new(repl.history_cap_u16);
    repl_loop_io(repl, &mut reader, &mut writer, &mut history)
}

// ===========================================================================
// 4. repl_loop_io — generic loop over BufRead / Write
// ===========================================================================

/// REPL loop generic over the input and output streams. Lifted out
/// of [`run_repl`] so the unit tests can drive the loop against a
/// `Cursor<&[u8]>` reader and a `Vec<u8>` writer without spawning
/// a child process.
///
/// On every iteration the loop:
///
/// 1. writes `repl.prompt()` and flushes;
/// 2. reads one newline-terminated line via [`read_prompt_line`];
/// 3. on `Ok(None)` (EOF) returns `Ok(())` cleanly;
/// 4. on `Ok(Some(line))` routes the line through [`parse_slash`]:
///    - `/clear` clears the ring (history truncated to 0);
///    - `/kill` returns `Ok(())` immediately (atom-level
///      short-circuit; Stage F/H later routes to the supervisor);
///    - `/budget` and `/skill <id>` are recognised but not yet
///      wired (skip history push, no side effect);
///    - any non-slash line is pushed into the ring (bounded by
///      `history.cap_u16`).
pub(crate) fn repl_loop_io<R, W>(
    repl: &CliRepl,
    reader: &mut R,
    writer: &mut W,
    history: &mut History,
) -> MnemosResult<()>
where
    R: BufRead,
    W: Write,
{
    loop {
        match write_prompt(writer, repl.prompt) {
            Ok(()) => {}
            Err(e) => return Err(MnemosError::source_redacted_from_error(ErrorOp::Agent, &e)),
        }
        match read_prompt_line(reader)? {
            None => return Ok(()),
            Some(line) => match parse_slash(&line) {
                Some(SlashCommand::Clear) => history.clear(),
                Some(SlashCommand::Kill) => return Ok(()),
                // `/budget`, `/skill <id>`, and any future non-exhaustive
                // control variant: parse cleanly, skip history push, no
                // side effect on this atom (Stage F/H express control
                // rail per ATOM_PLAN line 1263).
                Some(_) => {}
                None => history.push(line),
            },
        }
    }
}

// ===========================================================================
// 5. read_prompt_line — newline-stripped read of one line
// ===========================================================================

/// Read one newline-terminated line from `reader`.
///
/// Returns:
/// - `Ok(None)` on EOF (`Stdin::read_line` returned 0 bytes);
/// - `Ok(Some(line))` with any trailing `\n` (and a preceding
///   `\r` for CRLF input) stripped;
/// - `Err(MnemosError)` on an underlying `io::Error`, folded
///   through `source_redacted_from_error` so the raw cause is
///   never absorbed into the error channel.
///
/// The function allocates a single fresh `String` per call; the
/// outer loop in [`repl_loop_io`] either pushes that string into
/// the history ring (which then owns it) or drops it on a slash
/// match.
pub(crate) fn read_prompt_line<R: BufRead>(reader: &mut R) -> MnemosResult<Option<String>> {
    let mut buf = String::new();
    match reader.read_line(&mut buf) {
        Ok(0) => Ok(None),
        Ok(_) => {
            if buf.ends_with('\n') {
                let _ = buf.pop();
                if buf.ends_with('\r') {
                    let _ = buf.pop();
                }
            }
            Ok(Some(buf))
        }
        Err(e) => Err(MnemosError::source_redacted_from_error(ErrorOp::Agent, &e)),
    }
}

// ===========================================================================
// 6. write_prompt — flush-after-write
// ===========================================================================

/// Write `prompt` to `writer` and flush. Pure `io::Result<()>`; the
/// caller folds an error through [`MnemosError`].
fn write_prompt<W: Write>(writer: &mut W, prompt: &str) -> io::Result<()> {
    writer.write_all(prompt.as_bytes())?;
    writer.flush()
}

// ===========================================================================
// 7. History — bounded line ring (cap_u16)
// ===========================================================================

/// Bounded FIFO history ring. The newest line is at the back; the
/// oldest is at the front. Pushing past `cap_u16` evicts the
/// front entry (FIFO). A capacity of 0 yields a no-op ring (every
/// push is silently dropped) — the canonical "history off"
/// configuration.
///
/// The carrier holds at most `cap_u16` `String`s; the upper bound
/// is therefore type-level (`u16` fits in `usize` on every
/// supported target). The ring never resizes past `cap_u16`
/// entries.
#[derive(Debug)]
pub(crate) struct History {
    cap_u16: u16,
    lines: VecDeque<String>,
}

impl History {
    /// Construct an empty ring with the supplied capacity.
    pub(crate) fn new(cap_u16: u16) -> Self {
        let cap_usize = usize::from(cap_u16);
        Self {
            cap_u16,
            lines: VecDeque::with_capacity(cap_usize),
        }
    }

    /// Push one line into the ring. When the ring is at capacity,
    /// evicts the oldest entry first (FIFO). A `cap_u16 == 0`
    /// ring silently drops every push.
    pub(crate) fn push(&mut self, line: String) {
        let cap_usize = usize::from(self.cap_u16);
        if cap_usize == 0 {
            return;
        }
        while self.lines.len() >= cap_usize {
            let _ = self.lines.pop_front();
        }
        self.lines.push_back(line);
    }

    /// Truncate the ring to zero entries. Used by the `/clear`
    /// control command.
    pub(crate) fn clear(&mut self) {
        self.lines.clear();
    }

    /// Number of retained lines (always `<= cap_u16`).
    /// Test-only consumer at this atom; a future Stage F/H atom
    /// that exposes `/history` will activate it from production.
    #[allow(dead_code)]
    pub(crate) fn len(&self) -> usize {
        self.lines.len()
    }

    /// Ring capacity (the type-level upper bound).
    /// Test-only consumer at this atom (`Self::len` rationale).
    #[allow(dead_code)]
    pub(crate) const fn cap_u16(&self) -> u16 {
        self.cap_u16
    }

    /// Borrowed iterator from oldest to newest entry.
    /// Test-only consumer at this atom (`Self::len` rationale).
    #[allow(dead_code)]
    pub(crate) fn iter(&self) -> impl Iterator<Item = &str> {
        self.lines.iter().map(String::as_str)
    }
}

// ===========================================================================
// 8. NoopDeltaSink + drive_turn — m-agent driver (mock-LLM-testable)
// ===========================================================================

/// `DeltaSink` that discards every delta. Used by [`drive_turn`]
/// for the no-output-stream code path (the production J-stage
/// atom will replace this with a CLI-stdout / Telegram
/// `editMessageText` sink — both reuse the j-ux `redact_outbound`
/// projection from atom #44).
///
/// Activated by `j0_5_drives_turn_engine` only — the production
/// `run_repl` does not yet thread `drive_turn` (deferred to the
/// Stage F/H atom that lands the live `LlmClient`).
#[allow(dead_code)]
pub(crate) struct NoopDeltaSink;

impl DeltaSink for NoopDeltaSink {
    #[inline]
    fn on_delta(&mut self, _delta: SseDelta<'_>) -> ControlFlow<()> {
        ControlFlow::Continue(())
    }
}

/// Drive one turn of the m-agent engine against the supplied
/// [`LlmClient`].
///
/// Builds a single-message [`LlmRequestView`] (role User, content =
/// `user_input`, no tool-call id), pairs it with an empty
/// [`LazyToolSchema`] and the default [`CacheBreakpointPlan`], and
/// streams the response into a [`NoopDeltaSink`]. The function is
/// generic over [`LlmClient`] so the unit test can pass an inline
/// mock — the same trait surface the future live transport will
/// implement.
///
/// Returns the [`TurnUsage`] reported by the client on completion
/// or an [`LlmError`] on cancellation / transport failure (the
/// production caller folds [`LlmError`] into a [`MnemosError`] at
/// the boundary; this driver keeps the trait-native channel so
/// tests can match on variant directly).
///
/// Activated by `j0_5_drives_turn_engine` only — the production
/// `run_repl` does not yet thread `drive_turn` (deferred to the
/// Stage F/H atom that lands the live `LlmClient`).
#[allow(dead_code)]
pub(crate) fn drive_turn<L: LlmClient>(
    client: &mut L,
    user_input: &str,
) -> Result<TurnUsage, LlmError> {
    let messages = [ChatMessage {
        role: Role::User,
        content: user_input,
        tool_call_id: None,
    }];
    let request = LlmRequestView {
        messages: &messages,
        tools: LazyToolSchema::new(&[], &EMPTY_TOOL_REGISTRY),
        cache_plan: CacheBreakpointPlan::default(),
    };
    let mut sink = NoopDeltaSink;
    client.stream_chat(&request, &mut sink)
}

// ===========================================================================
// 9. Tests — 3 verbatim names per ATOM_PLAN atom #45 (line 1285)
// ===========================================================================

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use std::io::Cursor;

    // -----------------------------------------------------------------------
    // j0_5_repl_reads_prompt — read-line + prompt-write surface
    // -----------------------------------------------------------------------

    /// `j0_5_repl_reads_prompt` — the loop reads each newline-terminated
    /// line from the supplied reader, writes the prompt before every
    /// read attempt, strips the trailing `\n` (and `\r` for CRLF),
    /// and returns cleanly on EOF.
    #[test]
    fn j0_5_repl_reads_prompt() {
        // ---- Three lines + EOF; no slash commands ----
        let input: &[u8] = b"hello\nfoo\nbar\n";
        let mut reader = Cursor::new(input);
        let mut writer: Vec<u8> = Vec::new();
        let mut history = History::new(8);
        let repl = CliRepl::new("> ", 8);

        let r = repl_loop_io(&repl, &mut reader, &mut writer, &mut history);
        assert!(r.is_ok(), "loop must end Ok on EOF; got {r:?}");

        // Three non-slash lines pushed verbatim into the ring.
        assert_eq!(history.len(), 3);
        let lines: Vec<&str> = history.iter().collect();
        assert_eq!(lines, vec!["hello", "foo", "bar"]);

        // Prompt was written before each read attempt — three reads
        // returned a line and the fourth saw EOF, so the prompt
        // appears exactly four times in the captured output.
        let out = String::from_utf8(writer).expect("ascii prompt only");
        let prompt_count = out.matches("> ").count();
        assert_eq!(prompt_count, 4, "prompt count drift: {out:?}");

        // ---- read_prompt_line: trailing \n is stripped ----
        let mut r2 = Cursor::new(b"line\n" as &[u8]);
        assert_eq!(read_prompt_line(&mut r2).unwrap(), Some("line".to_string()));

        // ---- read_prompt_line: CRLF is fully stripped (no trailing \r) ----
        let mut r3 = Cursor::new(b"crlf\r\n" as &[u8]);
        assert_eq!(read_prompt_line(&mut r3).unwrap(), Some("crlf".to_string()));

        // ---- read_prompt_line: EOF returns None ----
        let mut r4 = Cursor::new(b"" as &[u8]);
        assert_eq!(read_prompt_line(&mut r4).unwrap(), None);

        // ---- read_prompt_line: empty line (only newline) returns Some("") ----
        let mut r5 = Cursor::new(b"\n" as &[u8]);
        assert_eq!(read_prompt_line(&mut r5).unwrap(), Some(String::new()));

        // ---- CliRepl accessors round-trip ----
        let cfg = CliRepl::new("mnemos> ", 42);
        assert_eq!(cfg.prompt(), "mnemos> ");
        assert_eq!(cfg.history_cap_u16(), 42);

        // ---- Default surfaces ----
        let dflt = CliRepl::default();
        assert_eq!(dflt.prompt(), DEFAULT_PROMPT);
        assert_eq!(dflt.history_cap_u16(), DEFAULT_HISTORY_CAP_U16);

        // ---- CliRepl is Copy + Eq (carrier never moves on snapshot) ----
        let snap = cfg;
        assert_eq!(snap, cfg);
    }

    // -----------------------------------------------------------------------
    // j0_5_history_bounded — ring never exceeds cap_u16; /clear + /kill
    // -----------------------------------------------------------------------

    /// `j0_5_history_bounded` — the line ring never holds more than
    /// `cap_u16` entries regardless of input length; eviction is
    /// FIFO (oldest line dropped first); `cap == 0` is a silent
    /// no-op; `/clear` truncates the ring; `/kill` short-circuits
    /// the loop.
    #[test]
    fn j0_5_history_bounded() {
        // ---- Cap-3 ring: 10 pushes → ring holds last 3 (FIFO eviction) ----
        let mut h = History::new(3);
        for i in 0..10_u16 {
            h.push(format!("line{i}"));
        }
        assert_eq!(h.len(), 3, "ring must not exceed cap");
        let last3: Vec<&str> = h.iter().collect();
        assert_eq!(last3, vec!["line7", "line8", "line9"]);
        assert_eq!(h.cap_u16(), 3);

        // ---- Cap-0 ring: every push silently dropped ----
        let mut h0 = History::new(0);
        h0.push("x".to_string());
        h0.push("y".to_string());
        assert_eq!(h0.len(), 0);
        assert_eq!(h0.cap_u16(), 0);

        // ---- /clear: REPL routes /clear to History::clear ----
        let input: &[u8] = b"a\nb\n/clear\nc\n";
        let mut reader = Cursor::new(input);
        let mut writer: Vec<u8> = Vec::new();
        let mut history = History::new(8);
        let repl = CliRepl::default();
        let r = repl_loop_io(&repl, &mut reader, &mut writer, &mut history);
        assert!(r.is_ok(), "loop must end Ok on EOF; got {r:?}");
        let after_clear: Vec<&str> = history.iter().collect();
        assert_eq!(after_clear, vec!["c"], "/clear must truncate the ring");

        // ---- /kill: REPL short-circuits the loop ----
        let input2: &[u8] = b"a\n/kill\nb\n";
        let mut r2 = Cursor::new(input2);
        let mut w2: Vec<u8> = Vec::new();
        let mut hist2 = History::new(8);
        let r = repl_loop_io(&repl, &mut r2, &mut w2, &mut hist2);
        assert!(r.is_ok(), "loop must return Ok on /kill; got {r:?}");
        let after_kill: Vec<&str> = hist2.iter().collect();
        assert_eq!(
            after_kill,
            vec!["a"],
            "/kill must short-circuit; 'b' must not be pushed"
        );

        // ---- /budget and /skill <id> parse cleanly, skip history push ----
        let input3: &[u8] = b"a\n/budget\n/skill 7\nb\n";
        let mut r3 = Cursor::new(input3);
        let mut w3: Vec<u8> = Vec::new();
        let mut hist3 = History::new(8);
        let r = repl_loop_io(&repl, &mut r3, &mut w3, &mut hist3);
        assert!(r.is_ok());
        let lines: Vec<&str> = hist3.iter().collect();
        assert_eq!(
            lines,
            vec!["a", "b"],
            "control commands must not be persisted as history"
        );

        // ---- Bound at exactly cap (boundary pin) ----
        let mut h_eq = History::new(2);
        h_eq.push("1".to_string());
        h_eq.push("2".to_string());
        assert_eq!(h_eq.len(), 2);
        h_eq.push("3".to_string());
        assert_eq!(h_eq.len(), 2);
        let last2: Vec<&str> = h_eq.iter().collect();
        assert_eq!(last2, vec!["2", "3"]);
    }

    // -----------------------------------------------------------------------
    // j0_5_drives_turn_engine — drive m-agent turn loop via a mock LLM
    // -----------------------------------------------------------------------

    /// `j0_5_drives_turn_engine` (mock llm) — `drive_turn` calls the
    /// supplied [`LlmClient::stream_chat`] exactly once, passing a
    /// single-message [`LlmRequestView`] whose only message is the
    /// user input under [`Role::User`]; the [`TurnUsage`] / [`LlmError`]
    /// returned by the client surfaces verbatim to the caller.
    #[test]
    fn j0_5_drives_turn_engine() {
        // ---- Mock client capturing the request shape and call count ----
        struct MockLlm {
            received_content: Option<String>,
            received_role: Option<Role>,
            received_msg_count: usize,
            received_tools_declared_len: usize,
            received_cache_plan: CacheBreakpointPlan,
            call_count: u32,
            usage: TurnUsage,
        }

        impl LlmClient for MockLlm {
            fn stream_chat(
                &mut self,
                req: &LlmRequestView<'_>,
                _sink: &mut dyn DeltaSink,
            ) -> Result<TurnUsage, LlmError> {
                self.call_count = self.call_count.saturating_add(1);
                self.received_msg_count = req.messages.len();
                if let Some(m) = req.messages.first() {
                    self.received_role = Some(m.role);
                    self.received_content = Some(m.content.to_string());
                }
                self.received_tools_declared_len = req.tools.declared().len();
                self.received_cache_plan = req.cache_plan;
                Ok(self.usage)
            }
        }

        let usage = TurnUsage {
            prompt_tokens_u32: 11,
            completion_tokens_u32: 22,
            cached_tokens_u32: 3,
        };
        let mut mock = MockLlm {
            received_content: None,
            received_role: None,
            received_msg_count: 0,
            received_tools_declared_len: 0,
            received_cache_plan: CacheBreakpointPlan::default(),
            call_count: 0,
            usage,
        };

        let r = drive_turn(&mut mock, "hello mnemos");
        assert_eq!(
            r,
            Ok(usage),
            "drive_turn must surface the mock's reported usage"
        );
        assert_eq!(
            mock.call_count, 1,
            "stream_chat must be called exactly once"
        );
        assert_eq!(mock.received_msg_count, 1, "exactly one message");
        assert_eq!(mock.received_role, Some(Role::User));
        assert_eq!(mock.received_content.as_deref(), Some("hello mnemos"));
        assert_eq!(
            mock.received_tools_declared_len, 0,
            "empty tool schema this atom"
        );
        assert_eq!(
            mock.received_cache_plan,
            CacheBreakpointPlan::default(),
            "default cache plan this atom"
        );

        // ---- Mock returning LlmError: the variant surfaces verbatim ----
        struct ErrLlm;
        impl LlmClient for ErrLlm {
            fn stream_chat(
                &mut self,
                _req: &LlmRequestView<'_>,
                _sink: &mut dyn DeltaSink,
            ) -> Result<TurnUsage, LlmError> {
                Err(LlmError::Cancelled)
            }
        }
        let mut e = ErrLlm;
        let r = drive_turn(&mut e, "ignored");
        assert_eq!(
            r,
            Err(LlmError::Cancelled),
            "LlmError must surface unchanged"
        );

        // ---- NoopDeltaSink: every delta returns ControlFlow::Continue ----
        let mut sink = NoopDeltaSink;
        assert!(matches!(
            sink.on_delta(SseDelta::Done),
            ControlFlow::Continue(())
        ));

        // ---- CliRepl size is bounded (Copy carrier, fits in small envelope) ----
        // &'static str (16B on 64-bit) + u16 (2B) + padding ≤ 24B.
        assert!(
            core::mem::size_of::<CliRepl>() <= 24,
            "CliRepl carrier size drift: {}",
            core::mem::size_of::<CliRepl>()
        );
    }
}
