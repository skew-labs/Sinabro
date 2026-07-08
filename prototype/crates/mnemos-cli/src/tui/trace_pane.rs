//! Cockpit trace pane + output fold.
//!
//! Renders a command's (possibly huge) output without ever freezing the TUI:
//!
//! * raw secrets are redacted *before* display — every source line is run
//!   through the REPL history classifier ([`crate::repl::history::classify`])
//!   and, when sensitive, dropped at the [`mnemos_a_core::redact_for_log`] call
//!   site so only its class label survives;
//! * output is folded by a *specialized* compressor per source kind (compiler /
//!   cargo-test / log / tool / diff) rather than a blind head/tail, so the first
//!   failure, its file/line, and the root cause stay visible;
//! * the retained structure is bounded ([`MAX_RETAINED_LINES`]) and paged, so a
//!   10 MB transcript opens within budget — paging and rendering only ever touch
//!   a bounded slice;
//! * the raw transcript is never mutated: its byte length and SHA-256
//!   ([`TracePane::raw_transcript_hash_32`]) are kept so the unfolded original
//!   can be replayed, and the most recent tool lines are preserved raw.
//!
//! Like the rest of [`crate::tui`], this is a pure read/project model: it owns no
//! business state and does no I/O, so it is fully testable with no terminal.

use mnemos_a_core::{RedactedLogValue, redact_for_log};

use crate::repl::history::classify;
use crate::sha256_32;

/// Hard cap on retained folded lines. Ingest of an arbitrarily large transcript
/// always yields at most this many [`FoldedLine`]s, so paging / rendering are
/// O(page) regardless of input size (the no-freeze law).
pub const MAX_RETAINED_LINES: usize = 320;
/// Head lines kept verbatim (post-redaction) before the middle is folded.
pub const HEAD_KEPT_LINES: usize = 240;
/// Tail lines kept verbatim (post-redaction) for tail-follow.
pub const TAIL_KEPT_LINES: usize = 64;
/// Most-recent tool lines preserved raw (the "recent tool output stays raw" law).
pub const RECENT_RAW_TOOL_LINES: usize = 16;
/// Default page size for [`TracePane::page`].
pub const DEFAULT_PAGE_SIZE_U16: u16 = 32;

/// The source kind of a trace, which selects the specialized compressor.
#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TraceSourceKind {
    /// `rustc` / `cargo build` diagnostics.
    Compiler = 1,
    /// `cargo test` output.
    CargoTest = 2,
    /// Structured / stack log output.
    Log = 3,
    /// Tool-adapter output (recent lines kept raw).
    Tool = 4,
    /// A unified diff (`diff -u`).
    Diff = 5,
    /// Unstructured output (head + tail with a folded middle).
    Plain = 6,
}

/// One displayed line of a folded trace.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum FoldedLine {
    /// A line shown verbatim (a kept source line or a compressor summary).
    Raw(String),
    /// A sensitive line: the raw value was dropped; only the redaction class is
    /// shown (never the secret).
    Redacted(RedactedLogValue),
    /// A compressed block standing in for `hidden_lines_u32` folded source lines.
    Fold {
        /// Human summary of what was folded.
        summary: String,
        /// How many source lines this fold replaces.
        hidden_lines_u32: u32,
    },
}

impl FoldedLine {
    /// Whether this line redacts a secret.
    #[must_use]
    pub const fn is_redacted(&self) -> bool {
        matches!(self, Self::Redacted(_))
    }

    /// Whether this line is a fold marker.
    #[must_use]
    pub const fn is_fold(&self) -> bool {
        matches!(self, Self::Fold { .. })
    }

    /// The colorless display text of this line (never the raw secret).
    #[must_use]
    pub fn display(&self) -> String {
        match self {
            Self::Raw(s) => s.clone(),
            Self::Redacted(r) => r.to_string(),
            Self::Fold {
                summary,
                hidden_lines_u32,
            } => format!("… {summary} (+{hidden_lines_u32} folded)"),
        }
    }
}

/// Redact one source line: sensitive lines lose their raw value at the
/// `redact_for_log` call site; safe lines are kept verbatim.
fn redact_line(line: &str) -> FoldedLine {
    match classify(line) {
        Some(kind) => FoldedLine::Redacted(redact_for_log(line, kind)),
        None => FoldedLine::Raw(line.to_string()),
    }
}

/// Clamp a display string to `cols` characters (char-based, never splits a
/// secret because redaction already happened). Returns the whole string when it
/// fits.
fn clamp_width(s: &str, cols: u16) -> String {
    let cols = cols as usize;
    if cols == 0 {
        return String::new();
    }
    if s.chars().count() <= cols {
        return s.to_string();
    }
    // keep cols-1 chars + a single truncation marker, so overflow can never
    // overlap the next pane column.
    let keep = cols.saturating_sub(1);
    let mut out: String = s.chars().take(keep).collect();
    out.push('+');
    out
}

/// Fold `lines[from..]` (a contiguous run) into a single [`FoldedLine::Fold`].
fn fold_run(label: &str, hidden: usize) -> FoldedLine {
    FoldedLine::Fold {
        summary: label.to_string(),
        hidden_lines_u32: u32::try_from(hidden).unwrap_or(u32::MAX),
    }
}

/// Generic head/tail fold used by Plain (and as a fallback): keep the first
/// [`HEAD_KEPT_LINES`] and last [`TAIL_KEPT_LINES`] (redacted), folding the
/// middle into a count.
fn fold_head_tail(lines: &[&str]) -> Vec<FoldedLine> {
    let n = lines.len();
    if n <= HEAD_KEPT_LINES + TAIL_KEPT_LINES {
        return lines.iter().map(|l| redact_line(l)).collect();
    }
    let mut out = Vec::with_capacity(MAX_RETAINED_LINES);
    for l in &lines[..HEAD_KEPT_LINES] {
        out.push(redact_line(l));
    }
    out.push(fold_run(
        "middle output folded",
        n - HEAD_KEPT_LINES - TAIL_KEPT_LINES,
    ));
    for l in &lines[n - TAIL_KEPT_LINES..] {
        out.push(redact_line(l));
    }
    out
}

/// Compiler compressor: surface the first `error`/`error[..]` line and its
/// `-->` file:line, then a fold of the remaining diagnostics. The first failure
/// and its location stay visible (never a blind head/tail).
fn fold_compiler(lines: &[&str]) -> Vec<FoldedLine> {
    let mut out = Vec::with_capacity(8);
    let first_err = lines
        .iter()
        .position(|l| l.trim_start().starts_with("error"));
    match first_err {
        Some(i) => {
            out.push(redact_line(lines[i]));
            // the immediately following `-->` location line, if present.
            if let Some(loc) = lines.get(i + 1) {
                if loc.trim_start().starts_with("-->") {
                    out.push(redact_line(loc));
                }
            }
            let remaining = lines.len().saturating_sub(1);
            if remaining > 0 {
                out.push(fold_run("remaining compiler diagnostics", remaining));
            }
        }
        None => return fold_head_tail(lines),
    }
    out
}

/// Cargo-test compressor: surface the `test result:` summary and the first
/// failing test, fold the passing noise.
fn fold_cargo_test(lines: &[&str]) -> Vec<FoldedLine> {
    let mut out = Vec::with_capacity(8);
    let first_fail = lines.iter().position(|l| {
        let t = l.trim();
        t.ends_with("FAILED") || t.starts_with("---- ")
    });
    if let Some(i) = first_fail {
        out.push(redact_line(lines[i]));
    }
    if let Some(summary) = lines
        .iter()
        .rposition(|l| l.trim_start().starts_with("test result:"))
    {
        out.push(redact_line(lines[summary]));
    }
    if out.is_empty() {
        return fold_head_tail(lines);
    }
    let folded = lines.len().saturating_sub(out.len());
    if folded > 0 {
        out.push(fold_run("passing / setup test lines", folded));
    }
    out
}

/// A stable "signature" for a log/stack line: trimmed, with any leading frame
/// index (`  12:` / `at `) removed, so repeated frames collapse.
fn log_signature(line: &str) -> &str {
    let t = line.trim_start();
    let t = t.strip_prefix("at ").unwrap_or(t);
    t.trim_start_matches(|c: char| c.is_ascii_digit() || c == ':' || c == ' ')
}

/// Log compressor: collapse consecutive lines sharing a [`log_signature`] into
/// one fold-with-count, so a repeated stack signature does not flood the pane.
fn fold_log(lines: &[&str]) -> Vec<FoldedLine> {
    let mut out = Vec::with_capacity(lines.len().min(MAX_RETAINED_LINES));
    let mut i = 0usize;
    while i < lines.len() {
        if out.len() >= MAX_RETAINED_LINES.saturating_sub(2) {
            out.push(fold_run("further log lines", lines.len() - i));
            break;
        }
        let sig = log_signature(lines[i]);
        let mut j = i + 1;
        while j < lines.len() && log_signature(lines[j]) == sig && !sig.is_empty() {
            j += 1;
        }
        let run = j - i;
        if run >= 3 {
            out.push(redact_line(lines[i]));
            out.push(fold_run("repeated log signature", run - 1));
        } else {
            for l in &lines[i..j] {
                out.push(redact_line(l));
            }
        }
        i = j;
    }
    out
}

/// Tool compressor: keep the most recent [`RECENT_RAW_TOOL_LINES`] lines raw
/// (redacted), fold everything older.
fn fold_tool(lines: &[&str]) -> Vec<FoldedLine> {
    let n = lines.len();
    if n <= RECENT_RAW_TOOL_LINES {
        return lines.iter().map(|l| redact_line(l)).collect();
    }
    let mut out = Vec::with_capacity(RECENT_RAW_TOOL_LINES + 1);
    out.push(fold_run("older tool output", n - RECENT_RAW_TOOL_LINES));
    for l in &lines[n - RECENT_RAW_TOOL_LINES..] {
        out.push(redact_line(l));
    }
    out
}

/// Diff compressor: keep every `@@` hunk header and changed (`+`/`-`) line, fold
/// runs of unchanged context.
fn fold_diff(lines: &[&str]) -> Vec<FoldedLine> {
    let mut out = Vec::with_capacity(lines.len().min(MAX_RETAINED_LINES));
    let mut ctx = 0usize;
    let flush_ctx = |out: &mut Vec<FoldedLine>, ctx: &mut usize| {
        if *ctx >= 3 {
            out.push(fold_run("unchanged context", *ctx));
        } else {
            // tiny context runs are not worth a fold marker; they were already
            // skipped, so re-emit nothing (the hunk headers carry the location).
        }
        *ctx = 0;
    };
    for l in lines {
        let t = *l;
        let is_change = t.starts_with('+') || t.starts_with('-') || t.starts_with("@@");
        if is_change {
            if ctx > 0 {
                flush_ctx(&mut out, &mut ctx);
            }
            out.push(redact_line(t));
            if out.len() >= MAX_RETAINED_LINES.saturating_sub(1) {
                break;
            }
        } else {
            ctx += 1;
        }
    }
    if ctx > 0 {
        flush_ctx(&mut out, &mut ctx);
    }
    if out.is_empty() {
        return fold_head_tail(lines);
    }
    out
}

/// A folded, redacted, paged view of one command's output.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TracePane {
    kind: TraceSourceKind,
    raw_byte_len_u64: u64,
    raw_transcript_hash_32: [u8; 32],
    page_size_u16: u16,
    lines: Vec<FoldedLine>,
    redacted_count_u32: u32,
}

impl TracePane {
    /// Ingest a raw transcript: one linear pass redacts every line and the
    /// kind-specific compressor folds it into a bounded retained set. The raw
    /// bytes are hashed (for replay) but never stored.
    #[must_use]
    pub fn ingest(kind: TraceSourceKind, raw: &str, page_size_u16: u16) -> Self {
        let raw_byte_len_u64 = raw.len() as u64;
        let raw_transcript_hash_32 = sha256_32(raw.as_bytes());
        let src: Vec<&str> = raw.lines().collect();
        let mut lines = match kind {
            TraceSourceKind::Compiler => fold_compiler(&src),
            TraceSourceKind::CargoTest => fold_cargo_test(&src),
            TraceSourceKind::Log => fold_log(&src),
            TraceSourceKind::Tool => fold_tool(&src),
            TraceSourceKind::Diff => fold_diff(&src),
            TraceSourceKind::Plain => fold_head_tail(&src),
        };
        // Final hard bound: even a pathological compressor output is clamped.
        if lines.len() > MAX_RETAINED_LINES {
            let hidden = lines.len() - MAX_RETAINED_LINES + 1;
            lines.truncate(MAX_RETAINED_LINES - 1);
            lines.push(fold_run("output beyond retained cap", hidden));
        }
        let redacted_count_u32 =
            u32::try_from(lines.iter().filter(|l| l.is_redacted()).count()).unwrap_or(u32::MAX);
        let page_size_u16 = page_size_u16.max(1);
        Self {
            kind,
            raw_byte_len_u64,
            raw_transcript_hash_32,
            page_size_u16,
            lines,
            redacted_count_u32,
        }
    }

    /// The source kind.
    #[must_use]
    pub const fn kind(&self) -> TraceSourceKind {
        self.kind
    }

    /// The byte length of the original raw transcript (preserved for replay).
    #[must_use]
    pub const fn raw_byte_len(&self) -> u64 {
        self.raw_byte_len_u64
    }

    /// SHA-256 of the original raw transcript — the replay anchor. Re-hashing the
    /// raw bytes must reproduce this exactly.
    #[must_use]
    pub const fn raw_transcript_hash_32(&self) -> [u8; 32] {
        self.raw_transcript_hash_32
    }

    /// Number of retained folded lines (always `<= MAX_RETAINED_LINES`).
    #[must_use]
    pub fn retained_len(&self) -> usize {
        self.lines.len()
    }

    /// The retained folded lines.
    #[must_use]
    pub fn lines(&self) -> &[FoldedLine] {
        &self.lines
    }

    /// How many lines redact a secret (the redaction proof count).
    #[must_use]
    pub const fn redacted_count(&self) -> u32 {
        self.redacted_count_u32
    }

    /// Whether at least one fold marker is present (the output was compressed).
    #[must_use]
    pub fn has_fold(&self) -> bool {
        self.lines.iter().any(FoldedLine::is_fold)
    }

    /// Number of pages at the current page size.
    #[must_use]
    pub fn page_count(&self) -> usize {
        let ps = self.page_size_u16 as usize;
        self.lines.len().div_ceil(ps.max(1))
    }

    /// The bounded slice of folded lines for page `idx` (empty if out of range).
    /// This is the hot path: it is `O(page_size)` and never the full transcript.
    #[must_use]
    pub fn page(&self, idx: usize) -> &[FoldedLine] {
        let ps = self.page_size_u16 as usize;
        let start = idx.saturating_mul(ps);
        if start >= self.lines.len() {
            return &[];
        }
        let end = start.saturating_add(ps).min(self.lines.len());
        &self.lines[start..end]
    }

    /// The last page (tail-follow).
    #[must_use]
    pub fn tail_page(&self) -> &[FoldedLine] {
        let pc = self.page_count();
        if pc == 0 {
            return &[];
        }
        self.page(pc - 1)
    }

    /// Render the tail page as colorless, width-clamped text lines, at most
    /// `rows` of them. Bounded: never renders the whole transcript, and a line
    /// can never overflow `cols` (no overlap with the next pane).
    #[must_use]
    pub fn render(&self, cols: u16, rows: u16) -> Vec<String> {
        self.tail_page()
            .iter()
            .take(rows as usize)
            .map(|l| clamp_width(&l.display(), cols))
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn huge_output_is_bounded_and_keeps_head_and_tail() {
        let mut s = String::with_capacity(1 << 20);
        s.push_str("error[E0001]: boom\n");
        s.push_str(" --> src/main.rs:1:1\n");
        for i in 0..100_000 {
            s.push_str("line ");
            s.push_str(&i.to_string());
            s.push('\n');
        }
        s.push_str("LAST-TOOL-MARKER\n");
        let pane = TracePane::ingest(TraceSourceKind::Plain, &s, 32);
        // retained structure is bounded regardless of 100k input lines
        assert!(pane.retained_len() <= MAX_RETAINED_LINES);
        assert!(
            pane.has_fold(),
            "middle must be folded, not dropped silently"
        );
        // head error line survives
        assert!(
            pane.lines()
                .iter()
                .any(|l| l.display().contains("error[E0001]"))
        );
        // tail-follow: the last marker survives
        assert!(
            pane.lines()
                .iter()
                .any(|l| l.display().contains("LAST-TOOL-MARKER"))
        );
    }

    #[test]
    fn redaction_drops_raw_secret_before_display() {
        let secret = "a".repeat(64); // single keyish token >= 32 chars -> classified
        let raw = format!("ok line\n{secret}\nanother line");
        let pane = TracePane::ingest(TraceSourceKind::Plain, &raw, 32);
        assert!(pane.redacted_count() >= 1, "secret line must be redacted");
        // the raw secret never appears in any displayed line
        for l in pane.lines() {
            assert!(
                !l.display().contains(&secret),
                "raw secret leaked into display"
            );
        }
        // a redacted marker is present
        assert!(pane.lines().iter().any(FoldedLine::is_redacted));
    }

    #[test]
    fn diff_fold_keeps_hunk_headers_and_changes() {
        let mut raw = String::from("@@ -1,8 +1,8 @@\n");
        for _ in 0..40 {
            raw.push_str(" unchanged context\n");
        }
        raw.push_str("-removed line\n+added line\n");
        let pane = TracePane::ingest(TraceSourceKind::Diff, &raw, 32);
        assert!(pane.lines().iter().any(|l| l.display().contains("@@")));
        assert!(
            pane.lines()
                .iter()
                .any(|l| l.display().contains("+added line"))
        );
        assert!(
            pane.lines()
                .iter()
                .any(|l| l.display().contains("-removed line"))
        );
        // the big unchanged run is folded
        assert!(pane.has_fold());
    }

    #[test]
    fn tail_follow_returns_last_page() {
        let raw: String = (0..200).map(|i| format!("row {i}\n")).collect();
        let pane = TracePane::ingest(TraceSourceKind::Plain, &raw, 16);
        let tail = pane.tail_page();
        assert!(!tail.is_empty());
        assert!(tail.len() <= 16);
        // last retained line is on the tail page
        assert_eq!(tail.last(), pane.lines().last());
    }

    #[test]
    fn compiler_diagnostic_compression_surfaces_first_error_and_location() {
        let mut raw = String::from("   Compiling sinabro v0.0.0\n");
        raw.push_str("error[E0433]: failed to resolve\n");
        raw.push_str(" --> crates/mnemos-cli/src/tui/x.rs:9:5\n");
        for i in 0..500 {
            raw.push_str(&format!("note: extra diagnostic {i}\n"));
        }
        let pane = TracePane::ingest(TraceSourceKind::Compiler, &raw, 32);
        assert!(pane.lines()[0].display().contains("error[E0433]"));
        assert!(pane.lines()[1].display().contains("--> crates/mnemos-cli"));
        assert!(pane.has_fold());
        assert!(pane.retained_len() < 10, "noise must be folded");
    }

    #[test]
    fn cargo_test_failure_compression_surfaces_failed_and_summary() {
        let mut raw = String::new();
        for i in 0..300 {
            raw.push_str(&format!("test mod::case_{i} ... ok\n"));
        }
        raw.push_str("test mod::broken ... FAILED\n");
        raw.push_str("test result: FAILED. 300 passed; 1 failed\n");
        let pane = TracePane::ingest(TraceSourceKind::CargoTest, &raw, 32);
        assert!(pane.lines().iter().any(|l| l.display().contains("FAILED")));
        assert!(
            pane.lines()
                .iter()
                .any(|l| l.display().contains("test result:"))
        );
        assert!(pane.has_fold());
    }

    #[test]
    fn log_stack_signature_fold_collapses_repeats() {
        let mut raw = String::new();
        for i in 0..50 {
            raw.push_str(&format!("  {i}: same_frame::call\n"));
        }
        let pane = TracePane::ingest(TraceSourceKind::Log, &raw, 32);
        // 50 identical-signature frames collapse to one kept + one fold
        assert!(pane.has_fold());
        assert!(pane.retained_len() < 10);
    }

    #[test]
    fn recent_tool_output_stays_raw() {
        let raw: String = (0..200).map(|i| format!("tool stdout {i}\n")).collect();
        let pane = TracePane::ingest(TraceSourceKind::Tool, &raw, 64);
        // the most recent line is preserved raw
        assert!(
            pane.lines()
                .iter()
                .any(|l| matches!(l, FoldedLine::Raw(s) if s == "tool stdout 199"))
        );
        // older output is folded
        assert!(pane.has_fold());
        assert!(pane.retained_len() <= RECENT_RAW_TOOL_LINES + 1);
    }

    #[test]
    fn raw_hash_replay_is_stable_and_independent() {
        let raw = "line one\nline two\nline three";
        let pane = TracePane::ingest(TraceSourceKind::Plain, raw, 32);
        assert_eq!(pane.raw_transcript_hash_32(), sha256_32(raw.as_bytes()));
        assert_eq!(pane.raw_byte_len(), raw.len() as u64);
    }

    #[test]
    fn render_is_width_clamped_and_row_bounded() {
        let raw: String = (0..100)
            .map(|i| format!("a-very-long-row-{i}-with-extra-text\n"))
            .collect();
        let pane = TracePane::ingest(TraceSourceKind::Plain, &raw, 8);
        let frame = pane.render(12, 4);
        assert!(frame.len() <= 4, "row bound");
        for line in &frame {
            assert!(line.chars().count() <= 12, "col clamp prevents overlap");
        }
    }
}
