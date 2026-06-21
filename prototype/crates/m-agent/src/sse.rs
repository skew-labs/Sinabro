//! `mnemos-m-agent::sse` — atom #22 · M.0.2 — zero-alloc SSE delta parser.
//!
//! Canonical OUT (§4.M — see ATOM_PLAN line 585-589 + atom #22 line 1017-1025):
//!
//! - [`SseDeltaParser`] (`<'a>`) — `// AI-HOT`. Single-cursor parser over a
//!   borrowed input buffer (`&'a [u8]`) — frame-by-frame advance, copy 0.
//! - [`SseDelta`] (`<'a>`) — `#[non_exhaustive]` 4-variant `Copy` enum
//!   (`ContentText(&'a str)` / `ToolCallArgs { index_u8: u8, fragment: &'a str }`
//!   / `Done` / `Usage(TurnUsage)`). Strings borrow into the parser's input
//!   buffer — no owned `String`, no allocation.
//! - [`SseParseError`] — `#[non_exhaustive]` 3-variant `Copy` enum
//!   (`Truncated` / `BadFrame` / `NonUtf8`). Payload-free — the channel
//!   cannot leak a raw provider body through `Debug`.
//!
//! ## Canonical-home migration (atom #21 disparity precedent)
//!
//! Atom #21 (M.0.1) shipped a forward-decl placeholder for [`SseDelta`] in
//! `m-agent::llm` (a `#[non_exhaustive]` `Pending(&'a [u8])` 1-variant stub)
//! so [`crate::llm::DeltaSink::on_delta`] had a typed argument. Atom #22
//! OWNS the canonical home (`m-agent::sse`) per §4.M; this module **moves**
//! the type here and grows the variant list to the §4.M shape. `llm.rs`
//! continues to re-export the symbol via `use crate::sse::SseDelta;`, so
//! the public re-export path through `mnemos_m_agent::SseDelta` (lib.rs)
//! remains stable — only the canonical home changed.
//!
//! The same atom-#21 atom-#22 inter-atom move pattern was forecast in
//! `BUILD_STATE.md §2 atom #22` disparity carry-forward note ("Session 1
//! of atom #22 decides MOVE-and-re-export-from-llm.rs vs CONSUME-from-llm.rs
//! strategy" — MOVE chosen).
//!
//! ## Wire-format scope
//!
//! The parser handles OpenAI-family SSE chat-streaming frames (the
//! provider survey of §9 master plan — OpenRouter, DeepSeek, Anthropic
//! chat-compat, OpenAI):
//!
//! ```text
//! data: {"choices":[{"delta":{"content":"Hello"}}]}\n\n
//! data: {"choices":[{"delta":{"tool_calls":[{"index":0,"function":{"arguments":"{\"x\":"}}]}}]}\n\n
//! data: {"usage":{"prompt_tokens":24,"completion_tokens":7,"cached_tokens":18}}\n\n
//! data: [DONE]\n\n
//! ```
//!
//! Each frame is a `data: <payload>` line terminated by `\n\n` (or
//! `\r\n\r\n` per HTML5 SSE). Comments (`:`-prefixed lines) and
//! event-type lines (`event:`/`id:`) are skipped before the next frame.
//!
//! The parser is **structural, not a JSON parser**. It scans for known
//! key-quoted byte patterns (`"content":"`, `"tool_calls":[`,
//! `"usage":{`) and extracts the immediate string / scalar / object
//! value as a borrowed slice into the original input buffer. Frames that
//! match no recognised pattern surface as [`SseParseError::BadFrame`]
//! (preserving fail-closed semantics; the consumer cannot silently
//! drop a malformed frame as zero-delta).
//!
//! Scope carve-outs (Session 2 ACCEPT/RAISE candidates — atom #20 / #21
//! disparity precedent):
//!
//! 1. **No JSON escape-sequence handling.** A borrowed `&'a str` slice
//!    cannot represent `\n` / `\u{...}` expansion without owning a
//!    fresh buffer. For OpenAI streaming, content deltas are ASCII-safe
//!    in the common case; escape sequences inside a captured slice are
//!    returned verbatim (the consumer at atom #23's `DeltaAccumulator`
//!    holds the JSON unescape contract). The parser still UTF-8 boundary
//!    checks every captured slice — non-UTF-8 bytes surface as
//!    [`SseParseError::NonUtf8`].
//! 2. **Single `data:` line per frame.** Multi-`data:` continuation
//!    frames (uncommon for OpenAI chat) are not joined; the second
//!    `data:` line within a frame parses as a separate frame. This
//!    matches the canonical OUT contract (one delta per call to
//!    [`SseDeltaParser::next`]).
//! 3. **No event/id field interpretation.** Lines beginning with
//!    `event:` / `id:` / `retry:` / `:` (comment) are skipped — only
//!    `data:` lines yield a delta.
//! 4. **First tool-call only per frame.** OpenAI streaming sends one
//!    `tool_calls[N]` element per frame in practice; the parser
//!    extracts the first `index` + `arguments` pair and surfaces it as
//!    a single [`SseDelta::ToolCallArgs`]. A frame with multiple
//!    tool-call elements has subsequent ones ignored (the higher-level
//!    accumulator at atom #23 re-assembles across frames anyway).
//! 5. **`#![forbid(unsafe_code)]` honoured.** The parser uses safe
//!    `str::from_utf8` / `slice::get` only — no raw pointer
//!    arithmetic, no unsafe slicing. Zero-alloc is achieved by
//!    returning `&'a str` slices via lifetime-tracked subslicing.

#![deny(missing_docs)]

use crate::turn::TurnUsage;

// ===========================================================================
// 1. Compile-time width pins (atom #21 / #20 precedent)
// ===========================================================================

/// `SseParseError` width pin. Three payload-free `Copy` variants ⇒ size
/// of the niche-optimised tag (`u8`). Any future variant that drags an
/// owned `Vec<u8>` or `String` would widen this and allow raw provider
/// bodies into the error channel — the build fails here first.
const _SSE_PARSE_ERROR_SIZE_IS_1: [(); 0 - !(core::mem::size_of::<SseParseError>() == 1) as usize] =
    [];

// ===========================================================================
// 2. SseDelta — canonical home (moved from m-agent::llm at atom #22)
// ===========================================================================

/// Parsed SSE delta from an OpenAI-family chat-streaming frame.
/// `Copy` and `#[non_exhaustive]` — variants may grow in later atoms
/// (e.g. an `Error` carrier for inline `{"error":...}` frames at
/// atom #26's tool loop) without breaking exhaustive matches.
///
/// `'a` is the input-buffer borrow. Every string slice (`ContentText`,
/// `ToolCallArgs::fragment`) points directly into the bytes the
/// [`SseDeltaParser`] was constructed over — no copy, no allocation.
///
/// The four variants mirror §4.M line 587 verbatim:
///
/// - `ContentText(&'a str)` — assistant text token. The slice is the
///   raw JSON string value of `choices[0].delta.content` (escape
///   sequences passed through verbatim per scope carve-out 1).
/// - `ToolCallArgs { index_u8, fragment }` — partial JSON fragment of
///   `choices[0].delta.tool_calls[index].function.arguments`. The
///   stream sends arguments byte-by-byte across frames; consumers
///   concatenate.
/// - `Done` — terminator frame (`data: [DONE]\n\n`). After this,
///   [`SseDeltaParser::next`] returns `Ok(None)`.
/// - `Usage(TurnUsage)` — final usage tally frame
///   (`data: {"usage":{...}}\n\n`). Atom #23's `DeltaAccumulator`
///   merges this into per-turn state.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
#[non_exhaustive]
pub enum SseDelta<'a> {
    /// Assistant content text token. Borrowed slice into the input
    /// buffer; escape sequences passed through verbatim.
    ContentText(&'a str),
    /// Partial tool-call arguments fragment for tool index `index_u8`.
    ToolCallArgs {
        /// Tool-call index within the assistant message
        /// (`choices[0].delta.tool_calls[N].index`).
        index_u8: u8,
        /// Argument-JSON fragment for this index. Concatenate across
        /// frames; complete JSON appears once the stream finishes.
        fragment: &'a str,
    },
    /// Stream-terminator frame (`data: [DONE]\n\n`).
    Done,
    /// Final usage tally frame (`data: {"usage":{...}}\n\n`).
    Usage(TurnUsage),
}

// ===========================================================================
// 3. SseParseError — payload-free parse failure channel
// ===========================================================================

/// SSE parse failure modes. `Copy`, `#[non_exhaustive]`, no owned
/// bytes — the channel cannot leak a raw provider response body
/// through `Debug`.
///
/// - `Truncated` — the input buffer ends in the middle of an SSE frame
///   (no `\n\n` terminator yet). The consumer is expected to buffer
///   more bytes and construct a fresh parser. Returned *only* when
///   the input contains a started-but-unterminated `data:` line; a
///   buffer that is fully consumed cleanly returns `Ok(None)` from
///   [`SseDeltaParser::next`].
/// - `BadFrame` — a complete frame was found but its payload matched
///   no recognised pattern (`[DONE]` / `"content":"..."` /
///   `"tool_calls":[...]` / `"usage":{...}`). Fail-closed — surfaces
///   to the caller rather than silently dropping the frame.
/// - `NonUtf8` — bytes inside a captured slice are not valid UTF-8.
///   The boundary check runs on every slice returned by `next`; if
///   any candidate slice fails, the variant surfaces and the cursor
///   is **not** advanced past the bad frame (the consumer can inspect
///   `pos()` to recover).
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
#[non_exhaustive]
pub enum SseParseError {
    /// Input ended mid-frame (no `\n\n` terminator). Buffer more bytes
    /// and retry with a fresh parser.
    Truncated,
    /// Complete frame found but payload matched no recognised pattern.
    BadFrame,
    /// Bytes inside a captured slice are not valid UTF-8.
    NonUtf8,
}

impl SseParseError {
    /// Stable class label for audit pipelines. Namespaced under
    /// `sse.*` (mirrors atom #15 `move_bind.*`, atom #20
    /// `sui_call_build.*`, atom #21 `llm.*`).
    #[inline]
    pub const fn class_label(&self) -> &'static str {
        match self {
            Self::Truncated => "sse.truncated",
            Self::BadFrame => "sse.bad_frame",
            Self::NonUtf8 => "sse.non_utf8",
        }
    }
}

// ===========================================================================
// 4. SseDeltaParser — AI-HOT zero-alloc cursor parser
// ===========================================================================

/// Zero-alloc cursor SSE delta parser. `// AI-HOT`. Construct once over
/// an input buffer slice; call [`Self::next`] until it returns
/// `Ok(None)` (no more frames) or `Err(SseParseError::Truncated)`
/// (need more bytes).
///
/// The parser owns nothing — every delta it produces borrows into the
/// caller-supplied `&'a [u8]`. A consumer streaming chunks from the
/// network typically:
///
/// 1. Appends new bytes to an owned buffer.
/// 2. Constructs `SseDeltaParser::new(&buf[unparsed_start..])`.
/// 3. Loops `next()` until `Ok(None)` or `Err(Truncated)`.
/// 4. If `Truncated`, advances `unparsed_start` by `pos()` so the next
///    poll keeps the partial frame at the head of the buffer.
///
/// The cursor (`pos`) advances past every successfully parsed frame
/// (including its `\n\n` terminator), so `pos()` is the exact byte
/// offset of the next unparsed byte after a clean run. On a fatal
/// error (`BadFrame` / `NonUtf8`) the cursor is **not** advanced —
/// the consumer can inspect the offending bytes at
/// `&buf[pos()..pos()+min(N, buf.len() - pos())]` for diagnostics.
// AI-HOT: criterion bench at benches/sse.rs (G-BENCH ±5%, alloc+0).
#[derive(Clone, Debug)]
pub struct SseDeltaParser<'a> {
    /// Input buffer being parsed. Borrowed for the parser's lifetime.
    buf: &'a [u8],
    /// Cursor into `buf`. Always `<= buf.len()`. Advances only on a
    /// successful frame parse (including the `\n\n` terminator).
    pos: usize,
}

impl<'a> SseDeltaParser<'a> {
    /// Construct a parser over a borrowed input buffer. `const fn` so
    /// fixture parsers can be folded at compile time in tests.
    #[inline]
    pub const fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0 }
    }

    /// Current cursor position. Always `<= buf.len()`. After a clean
    /// run (`Ok(None)`), equals `buf.len()` if the input ended on a
    /// frame boundary, or the start of an unfinished frame otherwise.
    #[inline]
    pub const fn pos(&self) -> usize {
        self.pos
    }

    /// Remaining unparsed bytes. Useful when a `Truncated` error
    /// forces the caller to ferry the unfinished frame into the next
    /// buffer.
    #[inline]
    pub const fn remaining(&self) -> &'a [u8] {
        // SAFETY-equivalent: `pos` invariant is `pos <= buf.len()`
        // and is only advanced past a `\n\n` terminator in `next`,
        // so this subslice is always in-bounds.
        let (_, tail) = self.buf.split_at(self.pos);
        tail
    }

    /// Parse the next SSE delta from the buffer.
    ///
    /// Return contract:
    /// - `Ok(Some(delta))` — one delta parsed; cursor advanced past
    ///   the frame's `\n\n` terminator.
    /// - `Ok(None)` — buffer fully consumed on a frame boundary; no
    ///   more deltas.
    /// - `Err(Truncated)` — an unterminated `data:` line remains in
    ///   the buffer; buffer more bytes and retry with a fresh parser
    ///   over the original-plus-new bytes.
    /// - `Err(BadFrame)` — a complete frame was found but its
    ///   payload matched no recognised pattern. Cursor is **not**
    ///   advanced.
    /// - `Err(NonUtf8)` — a captured slice contained non-UTF-8
    ///   bytes. Cursor is **not** advanced.
    ///
    /// The method name `next` is pinned by the §4.M canonical
    /// signature (ATOM_PLAN line 589). It does **not** implement
    /// [`Iterator::next`] — the return type carries an outer
    /// `Result<_, SseParseError>` so the consumer can distinguish
    /// `Truncated` (buffer more bytes, retry) from `Ok(None)`
    /// (clean end of stream); an `Iterator` wrapper would have to
    /// fold those two states together.
    #[allow(clippy::should_implement_trait)]
    pub fn next(&mut self) -> Result<Option<SseDelta<'a>>, SseParseError> {
        loop {
            // Skip leading blank lines / CRs between frames.
            self.skip_blank_lines();
            if self.pos >= self.buf.len() {
                return Ok(None);
            }

            // Try to locate the end-of-line terminator of the current line.
            let line_start = self.pos;
            let Some(line_end) = find_line_end(self.buf, line_start) else {
                // No `\n` in the remaining buffer — the line is
                // unterminated, so the whole frame is truncated.
                return Err(SseParseError::Truncated);
            };

            let line = match self.buf.get(line_start..line_end) {
                Some(slice) => slice,
                None => return Err(SseParseError::BadFrame),
            };
            let cr_trimmed = trim_trailing_cr(line);

            // Comment lines (start with `:`) → skip past line terminator.
            if cr_trimmed.first().copied() == Some(b':') {
                self.pos = advance_past_lf(self.buf, line_end);
                continue;
            }

            // Non-data field lines (e.g. `event:`, `id:`, `retry:`) → skip.
            if !starts_with_data_field(cr_trimmed) {
                self.pos = advance_past_lf(self.buf, line_end);
                continue;
            }

            // Frame complete only if the next line is blank (the
            // `\n\n` separator). For a `data:` line we need to peek
            // past the terminator and check for the blank line.
            let after_data_lf = advance_past_lf(self.buf, line_end);
            if !frame_terminated_at(self.buf, after_data_lf) {
                return Err(SseParseError::Truncated);
            }

            // Extract the payload bytes after `data:` (and optional
            // single space).
            let payload = data_payload(cr_trimmed);

            // Parse the payload into a delta. On success, advance the
            // cursor past the blank-line terminator.
            let delta = parse_payload(payload)?;
            self.pos = advance_past_blank_line(self.buf, after_data_lf);
            return Ok(Some(delta));
        }
    }

    /// Skip past any leading `\n` / `\r\n` blank lines between frames.
    fn skip_blank_lines(&mut self) {
        while self.pos < self.buf.len() {
            match self.buf[self.pos] {
                b'\n' => {
                    self.pos = self.pos.saturating_add(1);
                }
                b'\r' => {
                    // CR followed by LF — consume both; lone CR is
                    // not an SSE line terminator, leave it for the
                    // payload-extraction step to surface as BadFrame
                    // via the field parser.
                    if self.buf.get(self.pos.saturating_add(1)).copied() == Some(b'\n') {
                        self.pos = self.pos.saturating_add(2);
                    } else {
                        return;
                    }
                }
                _ => return,
            }
        }
    }
}

// ===========================================================================
// 5. Frame-scan helpers (zero-alloc; pure byte slicing)
// ===========================================================================

/// Locate the byte offset of the first `\n` at or after `start`. Returns
/// `None` if no `\n` exists in `buf[start..]`.
#[inline]
fn find_line_end(buf: &[u8], start: usize) -> Option<usize> {
    let tail = buf.get(start..)?;
    tail.iter().position(|&b| b == b'\n').map(|i| start + i)
}

/// Trim a trailing `\r` from a line slice (handles `\r\n` line endings).
#[inline]
fn trim_trailing_cr(line: &[u8]) -> &[u8] {
    match line.split_last() {
        Some((&b'\r', head)) => head,
        _ => line,
    }
}

/// Advance past a single `\n` at `lf_pos`. If `lf_pos` is past the end,
/// clamps at `buf.len()`.
#[inline]
fn advance_past_lf(buf: &[u8], lf_pos: usize) -> usize {
    if lf_pos < buf.len() {
        lf_pos.saturating_add(1)
    } else {
        buf.len()
    }
}

/// Returns true if the frame-terminator blank line begins at `pos`. A
/// blank line is either an empty line (immediate `\n`) or a `\r\n`
/// pair — and crucially, "EOF after the data-line LF without a blank
/// line" is *truncated*, not terminated. Returns false if the buffer
/// ends without a terminator (caller surfaces `Truncated`).
#[inline]
fn frame_terminated_at(buf: &[u8], pos: usize) -> bool {
    match buf.get(pos).copied() {
        Some(b'\n') => true,
        Some(b'\r') => buf.get(pos.saturating_add(1)).copied() == Some(b'\n'),
        _ => false,
    }
}

/// Advance past a blank-line terminator at `pos` (a `\n` or `\r\n`).
/// Caller must verify [`frame_terminated_at`] first.
#[inline]
fn advance_past_blank_line(buf: &[u8], pos: usize) -> usize {
    match buf.get(pos).copied() {
        Some(b'\n') => pos.saturating_add(1).min(buf.len()),
        Some(b'\r') if buf.get(pos.saturating_add(1)).copied() == Some(b'\n') => {
            pos.saturating_add(2).min(buf.len())
        }
        _ => pos,
    }
}

/// Returns true if `line` starts with the SSE `data:` field name.
#[inline]
fn starts_with_data_field(line: &[u8]) -> bool {
    line.starts_with(b"data:")
}

/// Extract the payload bytes after the `data:` field name, skipping a
/// single optional leading space (per SSE spec recommendation).
#[inline]
fn data_payload(line: &[u8]) -> &[u8] {
    debug_assert!(line.starts_with(b"data:"));
    let after_field = &line[5..];
    match after_field.split_first() {
        Some((&b' ', rest)) => rest,
        _ => after_field,
    }
}

// ===========================================================================
// 6. Payload classifier (recognise [DONE] / content / tool_calls / usage)
// ===========================================================================

/// Classify a `data:` payload into one of the four `SseDelta` variants,
/// returning `BadFrame` on no match and `NonUtf8` on invalid UTF-8 in
/// captured slices.
fn parse_payload(payload: &[u8]) -> Result<SseDelta<'_>, SseParseError> {
    // [DONE] terminator (verbatim — no JSON object).
    if payload == b"[DONE]" {
        return Ok(SseDelta::Done);
    }

    // Usage frame — `{"usage":{...}}`. Check first so a payload that
    // happens to also contain `"content":"..."` in a nested string
    // does not mis-classify.
    if let Some(usage) = try_parse_usage(payload)? {
        return Ok(SseDelta::Usage(usage));
    }

    // Content delta — `"content":"..."`.
    if let Some(text) = try_parse_content_text(payload)? {
        return Ok(SseDelta::ContentText(text));
    }

    // Tool-call args fragment — `"tool_calls":[{"index":N,...,"arguments":"..."`.
    if let Some((index_u8, fragment)) = try_parse_tool_call_args(payload)? {
        return Ok(SseDelta::ToolCallArgs { index_u8, fragment });
    }

    Err(SseParseError::BadFrame)
}

/// Try to extract `delta.content` as a borrowed UTF-8 slice. Returns
/// `Ok(None)` if the pattern is absent, `Err(NonUtf8)` if the captured
/// bytes are not valid UTF-8.
fn try_parse_content_text(payload: &[u8]) -> Result<Option<&str>, SseParseError> {
    const NEEDLE: &[u8] = b"\"content\":\"";
    let Some(start) = find_subsequence(payload, NEEDLE) else {
        return Ok(None);
    };
    let value_start = start + NEEDLE.len();
    let Some(rel_end) = find_unescaped_quote(&payload[value_start..]) else {
        // A `"content":"...` opening with no matching `"` closing — the
        // frame is structurally complete (it had a `\n\n`) but the
        // JSON is malformed. Surface as BadFrame.
        return Err(SseParseError::BadFrame);
    };
    let value = &payload[value_start..value_start + rel_end];
    let text = core::str::from_utf8(value).map_err(|_| SseParseError::NonUtf8)?;
    Ok(Some(text))
}

/// Try to extract a single `tool_calls[0]` `{index, arguments}` pair.
/// Returns `Ok(None)` if no `tool_calls` array is present.
fn try_parse_tool_call_args(payload: &[u8]) -> Result<Option<(u8, &str)>, SseParseError> {
    const TOOL_NEEDLE: &[u8] = b"\"tool_calls\":[";
    let Some(arr_start) = find_subsequence(payload, TOOL_NEEDLE) else {
        return Ok(None);
    };
    let scan_from = arr_start + TOOL_NEEDLE.len();

    // index_u8 — optional; the streaming protocol always sends it for
    // the first chunk but may omit it on continuation chunks. Default
    // to 0 if absent (matches OpenAI's "first tool call" implicit
    // index).
    let index_u8 = match find_subsequence(&payload[scan_from..], b"\"index\":") {
        Some(off) => {
            let n_start = scan_from + off + b"\"index\":".len();
            parse_small_u8(&payload[n_start..])?
        }
        None => 0u8,
    };

    // arguments — required for the fragment to mean anything.
    const ARGS_NEEDLE: &[u8] = b"\"arguments\":\"";
    let Some(args_off) = find_subsequence(&payload[scan_from..], ARGS_NEEDLE) else {
        return Ok(None);
    };
    let value_start = scan_from + args_off + ARGS_NEEDLE.len();
    let Some(rel_end) = find_unescaped_quote(&payload[value_start..]) else {
        return Err(SseParseError::BadFrame);
    };
    let value = &payload[value_start..value_start + rel_end];
    let fragment = core::str::from_utf8(value).map_err(|_| SseParseError::NonUtf8)?;
    Ok(Some((index_u8, fragment)))
}

/// Try to extract a `{"usage":{...}}` frame into a `TurnUsage`.
fn try_parse_usage(payload: &[u8]) -> Result<Option<TurnUsage>, SseParseError> {
    const USAGE_NEEDLE: &[u8] = b"\"usage\":{";
    let Some(u_off) = find_subsequence(payload, USAGE_NEEDLE) else {
        return Ok(None);
    };
    let scan_from = u_off + USAGE_NEEDLE.len();
    let prompt = find_num_field(&payload[scan_from..], b"\"prompt_tokens\":")?.unwrap_or(0);
    let completion = find_num_field(&payload[scan_from..], b"\"completion_tokens\":")?.unwrap_or(0);
    let cached = find_num_field(&payload[scan_from..], b"\"cached_tokens\":")?.unwrap_or(0);
    Ok(Some(TurnUsage {
        prompt_tokens_u32: prompt,
        completion_tokens_u32: completion,
        cached_tokens_u32: cached,
    }))
}

/// Locate the first `needle` in `hay`. Naive O(n·m) scan; needles in
/// this module are short literal byte strings ≤ ~16 B and payloads
/// are bounded by frame size, so the scan stays in CPU cache.
#[inline]
fn find_subsequence(hay: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || needle.len() > hay.len() {
        return None;
    }
    let last = hay.len() - needle.len();
    let mut i = 0;
    while i <= last {
        // Cheap first-byte filter before full compare.
        if hay[i] == needle[0] && &hay[i..i + needle.len()] == needle {
            return Some(i);
        }
        i += 1;
    }
    None
}

/// Locate the first unescaped `"` in `s`. Treats `\"` as an escaped
/// quote (does not terminate). A lone trailing backslash followed by
/// `"` is treated as escaped; this matches JSON string syntax.
#[inline]
fn find_unescaped_quote(s: &[u8]) -> Option<usize> {
    let mut i = 0;
    while i < s.len() {
        match s[i] {
            b'\\' => {
                // Skip the next byte (the escaped char).
                i = i.saturating_add(2);
            }
            b'"' => return Some(i),
            _ => i += 1,
        }
    }
    None
}

/// Parse a small unsigned decimal integer at the head of `bytes`,
/// stopping at the first non-digit. Returns 0 if no digit is present.
/// Saturates at `u8::MAX` for over-large values (tool_calls index is
/// bounded to `u8::MAX` by §4.M signature).
#[inline]
fn parse_small_u8(bytes: &[u8]) -> Result<u8, SseParseError> {
    let mut acc: u16 = 0;
    let mut saw_digit = false;
    for &b in bytes {
        match b {
            b'0'..=b'9' => {
                saw_digit = true;
                acc = acc.saturating_mul(10).saturating_add((b - b'0') as u16);
                if acc > u8::MAX as u16 {
                    return Ok(u8::MAX);
                }
            }
            _ => break,
        }
    }
    if !saw_digit {
        return Ok(0);
    }
    Ok(acc as u8)
}

/// Locate `"<key>":<digits>` and parse the digits as a `u32`. Returns
/// `Ok(None)` if the key is absent. Saturates at `u32::MAX` on
/// overflow.
#[inline]
fn find_num_field(hay: &[u8], key: &[u8]) -> Result<Option<u32>, SseParseError> {
    let Some(off) = find_subsequence(hay, key) else {
        return Ok(None);
    };
    let from = off + key.len();
    let mut acc: u64 = 0;
    let mut saw = false;
    for &b in &hay[from..] {
        match b {
            b' ' if !saw => continue,
            b'0'..=b'9' => {
                saw = true;
                acc = acc.saturating_mul(10).saturating_add((b - b'0') as u64);
            }
            _ => break,
        }
    }
    if !saw {
        return Ok(Some(0));
    }
    let clamped = if acc > u32::MAX as u64 {
        u32::MAX
    } else {
        acc as u32
    };
    Ok(Some(clamped))
}

// ===========================================================================
// 7. Inline unit tests (5 ATOM_PLAN-named + scaffolding + proptest)
// ===========================================================================

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    // ---- ATOM_PLAN line 1021 verbatim named tests --------------------------

    /// `m0_2_parses_content_delta` — verifies the parser extracts a
    /// `choices[0].delta.content` text string as a borrowed slice into
    /// the input buffer (pointer identity proves zero copy).
    #[test]
    fn m0_2_parses_content_delta() {
        let buf = b"data: {\"choices\":[{\"delta\":{\"content\":\"Hello\"}}]}\n\n";
        let mut parser = SseDeltaParser::new(buf);
        let delta = parser
            .next()
            .expect("parse must succeed")
            .expect("must yield a delta");
        match delta {
            SseDelta::ContentText(text) => {
                assert_eq!(text, "Hello");
                // Pointer identity: the slice lives inside the input
                // buffer, not in a fresh allocation.
                let text_ptr = text.as_ptr() as usize;
                let buf_lo = buf.as_ptr() as usize;
                let buf_hi = buf_lo + buf.len();
                assert!(
                    text_ptr >= buf_lo && text_ptr < buf_hi,
                    "content slice must point into the input buffer (zero-alloc)"
                );
            }
            other => panic!("expected ContentText, got {:?}", other),
        }
        assert!(matches!(parser.next(), Ok(None)));
    }

    /// `m0_2_parses_tool_call_fragment` — verifies a streaming
    /// tool-call arguments fragment surfaces as `ToolCallArgs` with
    /// the correct index and a borrowed fragment slice.
    #[test]
    fn m0_2_parses_tool_call_fragment() {
        let buf = concat!(
            "data: {\"choices\":[{\"delta\":{\"tool_calls\":[",
            "{\"index\":0,\"function\":{\"arguments\":\"{\\\"x\\\":\"}}]",
            "}}]}\n\n"
        )
        .as_bytes();
        let mut parser = SseDeltaParser::new(buf);
        let delta = parser.next().unwrap().unwrap();
        match delta {
            SseDelta::ToolCallArgs { index_u8, fragment } => {
                assert_eq!(index_u8, 0);
                // The fragment contains JSON-escaped bytes verbatim
                // (carve-out 1: no escape expansion at this layer).
                assert_eq!(fragment, r#"{\"x\":"#);
            }
            other => panic!("expected ToolCallArgs, got {:?}", other),
        }
    }

    /// `m0_2_truncated_frame_is_safe` — verifies a buffer that ends
    /// mid-frame surfaces `SseParseError::Truncated` and does NOT
    /// advance the cursor past the started-but-unterminated frame.
    #[test]
    fn m0_2_truncated_frame_is_safe() {
        // Frame begins but has no `\n\n` terminator yet.
        let buf = b"data: {\"choices\":[{\"delta\":{\"content\":\"Hel";
        let mut parser = SseDeltaParser::new(buf);
        let err = parser.next().unwrap_err();
        assert_eq!(err, SseParseError::Truncated);
        // Cursor not advanced — caller can prepend buffered bytes
        // and retry with a fresh parser over the concatenation.
        assert_eq!(parser.pos(), 0);
        // remaining() returns the full buffer.
        assert_eq!(parser.remaining(), buf);

        // Same scenario with a `data:` line that has a `\n` but no
        // trailing blank line (frame terminator missing).
        let buf2 = b"data: {\"choices\":[{\"delta\":{\"content\":\"Hi\"}}]}\n";
        let mut p2 = SseDeltaParser::new(buf2);
        assert_eq!(p2.next().unwrap_err(), SseParseError::Truncated);
    }

    /// `m0_2_non_utf8_rejected` — verifies non-UTF-8 bytes inside a
    /// captured slice surface as `SseParseError::NonUtf8` rather than
    /// triggering a panic or returning garbage.
    #[test]
    fn m0_2_non_utf8_rejected() {
        // Frame with a structurally valid `"content":"..."` whose
        // value bytes contain a lone 0xFF (invalid UTF-8 start byte).
        let mut buf: Vec<u8> = b"data: {\"content\":\"".to_vec();
        buf.push(0xFFu8);
        buf.extend_from_slice(b"\"}\n\n");
        let mut parser = SseDeltaParser::new(&buf);
        assert_eq!(parser.next().unwrap_err(), SseParseError::NonUtf8);
    }

    /// `m0_2_done_and_usage` — verifies the `[DONE]` terminator and
    /// the final `usage` frame parse correctly, including the
    /// `cached_tokens` split required by §9.5 cache-hit measurement.
    #[test]
    fn m0_2_done_and_usage() {
        let buf = concat!(
            "data: {\"usage\":{\"prompt_tokens\":24,\"completion_tokens\":7,",
            "\"cached_tokens\":18}}\n\n",
            "data: [DONE]\n\n",
        )
        .as_bytes();
        let mut parser = SseDeltaParser::new(buf);

        let usage = parser.next().unwrap().unwrap();
        match usage {
            SseDelta::Usage(u) => {
                assert_eq!(u.prompt_tokens_u32, 24);
                assert_eq!(u.completion_tokens_u32, 7);
                assert_eq!(u.cached_tokens_u32, 18);
            }
            other => panic!("expected Usage, got {:?}", other),
        }

        let done = parser.next().unwrap().unwrap();
        assert!(matches!(done, SseDelta::Done));

        assert!(matches!(parser.next(), Ok(None)));
        assert_eq!(parser.pos(), buf.len());
    }

    // ---- Scaffolding tests (atom #20 / #21 precedent) ----------------------

    #[test]
    fn parser_skips_comments_and_blank_lines() {
        let buf = b": comment\n\ndata: [DONE]\n\n";
        let mut parser = SseDeltaParser::new(buf);
        let d = parser.next().unwrap().unwrap();
        assert!(matches!(d, SseDelta::Done));
        assert!(matches!(parser.next(), Ok(None)));
    }

    #[test]
    fn parser_skips_event_and_id_field_lines() {
        let buf = b"event: chunk\nid: 42\ndata: [DONE]\n\n";
        let mut parser = SseDeltaParser::new(buf);
        let d = parser.next().unwrap().unwrap();
        assert!(matches!(d, SseDelta::Done));
    }

    #[test]
    fn parser_handles_crlf_line_endings() {
        let buf = b"data: [DONE]\r\n\r\n";
        let mut parser = SseDeltaParser::new(buf);
        let d = parser.next().unwrap().unwrap();
        assert!(matches!(d, SseDelta::Done));
        assert!(matches!(parser.next(), Ok(None)));
    }

    #[test]
    fn parser_data_without_leading_space_works() {
        let buf = b"data:[DONE]\n\n";
        let mut parser = SseDeltaParser::new(buf);
        let d = parser.next().unwrap().unwrap();
        assert!(matches!(d, SseDelta::Done));
    }

    #[test]
    fn parser_returns_bad_frame_on_unrecognised_payload() {
        let buf = b"data: {\"finish_reason\":\"stop\"}\n\n";
        let mut parser = SseDeltaParser::new(buf);
        assert_eq!(parser.next().unwrap_err(), SseParseError::BadFrame);
    }

    #[test]
    fn parser_handles_multiple_content_frames_in_order() {
        let buf = b"data: {\"content\":\"a\"}\n\ndata: {\"content\":\"b\"}\n\ndata: [DONE]\n\n";
        let mut parser = SseDeltaParser::new(buf);
        let mut seen: Vec<String> = Vec::new();
        loop {
            match parser.next().unwrap() {
                Some(SseDelta::ContentText(s)) => seen.push(s.to_string()),
                Some(SseDelta::Done) => break,
                Some(other) => panic!("unexpected delta {:?}", other),
                None => break,
            }
        }
        assert_eq!(seen, vec!["a".to_string(), "b".to_string()]);
    }

    #[test]
    fn sse_parse_error_class_labels_are_namespaced_and_unique() {
        let labels = [
            (SseParseError::Truncated, "sse.truncated"),
            (SseParseError::BadFrame, "sse.bad_frame"),
            (SseParseError::NonUtf8, "sse.non_utf8"),
        ];
        for (err, expected) in labels.iter() {
            assert!(expected.starts_with("sse."));
            assert_eq!(err.class_label(), *expected);
        }
        for i in 0..labels.len() {
            for j in (i + 1)..labels.len() {
                assert_ne!(labels[i].1, labels[j].1);
            }
        }
    }

    #[test]
    fn public_types_are_copy_and_fixed_width() {
        fn assert_copy<T: Copy>() {}
        assert_copy::<SseDelta<'static>>();
        assert_copy::<SseParseError>();
        assert_eq!(core::mem::size_of::<SseParseError>(), 1);
    }

    #[test]
    fn unescaped_quote_scan_skips_escapes() {
        assert_eq!(find_unescaped_quote(br#"\"\"hi""#), Some(6));
        assert_eq!(find_unescaped_quote(br#"plain"end"#), Some(5));
        assert_eq!(find_unescaped_quote(b"no closer"), None);
    }

    #[test]
    fn parser_extracts_index_u8_correctly() {
        let buf = b"data: {\"tool_calls\":[{\"index\":7,\"function\":{\"arguments\":\"ab\"}}]}\n\n";
        let mut parser = SseDeltaParser::new(buf);
        match parser.next().unwrap().unwrap() {
            SseDelta::ToolCallArgs { index_u8, fragment } => {
                assert_eq!(index_u8, 7);
                assert_eq!(fragment, "ab");
            }
            other => panic!("expected ToolCallArgs, got {:?}", other),
        }
    }

    // ---- proptest (ATOM_PLAN: 임의 청크분할에서 동일 델타열) ---------------

    /// Reference parser walking the whole buffer in a single pass —
    /// the "ground truth" against which the chunk-split harness
    /// compares.
    fn parse_all(buf: &[u8]) -> Vec<OwnedDelta> {
        let mut p = SseDeltaParser::new(buf);
        let mut out = Vec::new();
        while let Ok(Some(d)) = p.next() {
            out.push(OwnedDelta::from(d));
        }
        out
    }

    /// Owned mirror of `SseDelta` for comparing across parsers built
    /// over different (but byte-equivalent) input slices.
    #[derive(Clone, Debug, Eq, PartialEq)]
    enum OwnedDelta {
        ContentText(String),
        ToolCallArgs { index_u8: u8, fragment: String },
        Done,
        Usage(TurnUsage),
    }

    impl<'a> From<SseDelta<'a>> for OwnedDelta {
        fn from(d: SseDelta<'a>) -> Self {
            match d {
                SseDelta::ContentText(s) => OwnedDelta::ContentText(s.to_string()),
                SseDelta::ToolCallArgs { index_u8, fragment } => OwnedDelta::ToolCallArgs {
                    index_u8,
                    fragment: fragment.to_string(),
                },
                SseDelta::Done => OwnedDelta::Done,
                SseDelta::Usage(u) => OwnedDelta::Usage(u),
            }
        }
    }

    /// Re-parse `buf` by feeding chunks cyclically from `chunk_sizes`
    /// until the whole buffer is consumed, re-anchoring on `Truncated`
    /// (the production streaming pattern). Returns the concatenated
    /// delta sequence.
    fn parse_chunked(buf: &[u8], chunk_sizes: &[usize]) -> Vec<OwnedDelta> {
        assert!(!chunk_sizes.is_empty(), "chunk_sizes must be non-empty");
        let mut deltas = Vec::new();
        let mut staging: Vec<u8> = Vec::new();
        let mut consumed_in_staging = 0usize;
        let mut fed = 0usize;
        let mut cycle = 0usize;

        while fed < buf.len() {
            let chunk = chunk_sizes[cycle % chunk_sizes.len()].max(1);
            cycle = cycle.wrapping_add(1);
            let take = chunk.min(buf.len() - fed);
            staging.extend_from_slice(&buf[fed..fed + take]);
            fed += take;

            loop {
                let mut p = SseDeltaParser::new(&staging[consumed_in_staging..]);
                match p.next() {
                    Ok(Some(d)) => {
                        deltas.push(OwnedDelta::from(d));
                        consumed_in_staging += p.pos();
                    }
                    Ok(None) => {
                        // Buffer fully consumed; reset staging.
                        staging.clear();
                        consumed_in_staging = 0;
                        break;
                    }
                    Err(SseParseError::Truncated) => break,
                    Err(_) => break,
                }
            }
        }

        // Final drain after all bytes fed (in case the last `next`
        // returned `Truncated` but more data arrived).
        loop {
            let mut p = SseDeltaParser::new(&staging[consumed_in_staging..]);
            match p.next() {
                Ok(Some(d)) => {
                    deltas.push(OwnedDelta::from(d));
                    consumed_in_staging += p.pos();
                }
                Ok(None) => break,
                Err(_) => break,
            }
        }
        deltas
    }

    proptest! {
        /// ATOM_PLAN proptest contract: a fixed multi-frame buffer
        /// produces the same delta sequence regardless of how the
        /// network splits the bytes across chunks.
        #[test]
        fn m0_2_proptest_chunk_split_is_invariant(
            chunk_sizes in proptest::collection::vec(1usize..32usize, 1..32),
        ) {
            let buf: &[u8] = concat!(
                "data: {\"content\":\"alpha\"}\n\n",
                "data: {\"content\":\"beta\"}\n\n",
                "data: {\"tool_calls\":[{\"index\":0,\"function\":{\"arguments\":\"x\"}}]}\n\n",
                "data: {\"usage\":{\"prompt_tokens\":3,\"completion_tokens\":4,\"cached_tokens\":1}}\n\n",
                "data: [DONE]\n\n",
            ).as_bytes();

            let baseline = parse_all(buf);
            let chunked = parse_chunked(buf, &chunk_sizes);
            prop_assert_eq!(baseline, chunked);
        }
    }
}
