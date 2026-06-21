//! Paged trace / memory pane (atom #535 · G.4.4).
//!
//! The operational pane wraps the Stage F [`TracePane`] with the paging controls a
//! cockpit needs: a current-page cursor, a line [`PaneFilter`], a stale marker (the
//! underlying data moved on), a background-load flag (a heavy history is loading
//! off the hot path), and a raw-replay link (the SHA-256 of the original
//! transcript). The hot path renders only the current bounded page — the full
//! history is never rendered ([`PagedPane::full_render_denied`] is the structural
//! invariant `true`) (`G-G-OPERATIONAL-ENTRY`, `G-G-TERMINAL-DESIGN`, no-blocking
//! hot path). This module performs no I/O.
//!
//! Reuse (no reinvention): the fold / redaction / bounded paging is the Stage F
//! [`crate::tui::trace_pane`] (`TracePane` / `FoldedLine` / `TraceSourceKind`).

use crate::tui::trace_pane::{FoldedLine, TracePane, TraceSourceKind};

/// A line filter applied to a page before render.
#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PaneFilter {
    /// Show every retained line.
    All = 1,
    /// Show only redacted (secret-dropped) lines.
    RedactedOnly = 2,
    /// Show only fold markers (compressed runs).
    FoldsOnly = 3,
}

impl PaneFilter {
    /// Whether a folded line passes this filter.
    #[must_use]
    pub const fn passes(self, line: &FoldedLine) -> bool {
        match self {
            Self::All => true,
            Self::RedactedOnly => line.is_redacted(),
            Self::FoldsOnly => line.is_fold(),
        }
    }
}

/// An operational paged view over a Stage F [`TracePane`] (trace output or a
/// memory-id history), with a filter, a stale marker, a background-load flag, and a
/// raw-replay link.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PagedPane {
    trace: TracePane,
    cursor_page: usize,
    filter: PaneFilter,
    stale: bool,
    background_loading: bool,
}

impl PagedPane {
    /// Build a paged pane from a raw trace transcript (folded + redacted + paged by
    /// the reused [`TracePane`]).
    #[must_use]
    pub fn from_trace(
        kind: TraceSourceKind,
        raw: &str,
        page_size_u16: u16,
        filter: PaneFilter,
    ) -> Self {
        Self {
            trace: TracePane::ingest(kind, raw, page_size_u16),
            cursor_page: 0,
            filter,
            stale: false,
            background_loading: false,
        }
    }

    /// Build a paged pane from a memory-id history (each entry is a line; ingested
    /// as plain text so paging / bounding apply identically to a trace).
    #[must_use]
    pub fn from_memory_list(lines: &[String], page_size_u16: u16, filter: PaneFilter) -> Self {
        let raw = lines.join("\n");
        Self::from_trace(TraceSourceKind::Plain, &raw, page_size_u16, filter)
    }

    /// The number of pages.
    #[must_use]
    pub fn page_count(&self) -> usize {
        self.trace.page_count()
    }

    /// The current page index.
    #[must_use]
    pub const fn cursor_page(&self) -> usize {
        self.cursor_page
    }

    /// Move to a page (clamped to the last page); a no-op past the end keeps the
    /// last valid page.
    pub fn goto_page(&mut self, idx: usize) {
        let last = self.page_count().saturating_sub(1);
        self.cursor_page = idx.min(last);
    }

    /// The current page's lines after the active filter. This is the hot path:
    /// `O(page_size)` — never the whole transcript.
    #[must_use]
    pub fn current_page(&self) -> Vec<FoldedLine> {
        self.trace
            .page(self.cursor_page)
            .iter()
            .filter(|l| self.filter.passes(l))
            .cloned()
            .collect()
    }

    /// The first page (the cheapest hot-path read).
    #[must_use]
    pub fn first_page(&self) -> &[FoldedLine] {
        self.trace.page(0)
    }

    /// Set the active filter.
    pub fn set_filter(&mut self, filter: PaneFilter) {
        self.filter = filter;
    }

    /// The active filter.
    #[must_use]
    pub const fn filter(&self) -> PaneFilter {
        self.filter
    }

    /// Mark the pane stale (the underlying history moved on; a refresh is needed).
    pub fn mark_stale(&mut self) {
        self.stale = true;
    }

    /// Whether the pane is stale.
    #[must_use]
    pub const fn is_stale(&self) -> bool {
        self.stale
    }

    /// Set the background-load flag (a heavy history is loading off the hot path).
    pub fn set_background_loading(&mut self, loading: bool) {
        self.background_loading = loading;
    }

    /// Whether a background load is in progress.
    #[must_use]
    pub const fn is_background_loading(&self) -> bool {
        self.background_loading
    }

    /// The raw-replay link: the SHA-256 of the original transcript (re-hashing the
    /// raw bytes reproduces it). The raw bytes are never stored.
    #[must_use]
    pub const fn raw_replay_link(&self) -> [u8; 32] {
        self.trace.raw_transcript_hash_32()
    }

    /// Structural invariant: the pane never full-renders a large history — only a
    /// bounded page is ever produced. Always `true`.
    #[must_use]
    pub const fn full_render_denied() -> bool {
        true
    }

    /// Render the current page as colorless, row-bounded display lines (delegates
    /// width clamping to the reused pane for the tail render; here we display the
    /// current filtered page).
    #[must_use]
    pub fn render(&self, rows: u16) -> Vec<String> {
        self.current_page()
            .iter()
            .take(rows as usize)
            .map(FoldedLine::display)
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn huge_trace() -> PagedPane {
        let mut raw = String::from("error[E0001]: boom\n");
        for i in 0..5_000 {
            raw.push_str(&format!("line {i}\n"));
        }
        PagedPane::from_trace(TraceSourceKind::Plain, &raw, 32, PaneFilter::All)
    }

    #[test]
    fn page_1_is_bounded_and_nonempty() {
        let pane = huge_trace();
        let first = pane.first_page();
        assert!(!first.is_empty());
        assert!(first.len() <= 32, "first page is bounded by page size");
    }

    #[test]
    fn filter_redacted_only() {
        let secret = "a".repeat(64);
        let raw = format!("ok line\n{secret}\nmore");
        let mut pane = PagedPane::from_trace(TraceSourceKind::Plain, &raw, 32, PaneFilter::All);
        pane.set_filter(PaneFilter::RedactedOnly);
        let page = pane.current_page();
        assert!(!page.is_empty(), "the secret line is retained");
        assert!(page.iter().all(FoldedLine::is_redacted));
    }

    #[test]
    fn stale_marker() {
        let mut pane = huge_trace();
        assert!(!pane.is_stale());
        pane.mark_stale();
        assert!(pane.is_stale());
    }

    #[test]
    fn background_load_flag() {
        let mut pane = huge_trace();
        assert!(!pane.is_background_loading());
        pane.set_background_loading(true);
        assert!(pane.is_background_loading());
    }

    #[test]
    fn full_render_denied_and_bounded() {
        let pane = huge_trace();
        // even a 5000-line transcript retains a bounded, folded structure
        assert!(PagedPane::full_render_denied());
        let rendered = pane.render(64);
        assert!(rendered.len() <= 64, "render is row-bounded");
        assert!(pane.page_count() >= 1);
    }

    #[test]
    fn memory_list_pages_and_links_replay() {
        let lines: Vec<String> = (0..100).map(|i| format!("memory:{i}")).collect();
        let pane = PagedPane::from_memory_list(&lines, 16, PaneFilter::All);
        assert!(!pane.first_page().is_empty());
        assert_ne!(pane.raw_replay_link(), [0u8; 32]);
    }

    #[test]
    fn goto_page_clamps() {
        let mut pane = huge_trace();
        pane.goto_page(usize::MAX);
        assert_eq!(pane.cursor_page(), pane.page_count().saturating_sub(1));
    }
}
