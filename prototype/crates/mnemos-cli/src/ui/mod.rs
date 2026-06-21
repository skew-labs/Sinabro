//! Operational paged trace / memory pane (Stage G, G-WP-05 atom #535).
//!
//! Stage F minted the cockpit trace pane
//! ([`crate::tui::trace_pane::TracePane`]): a folded, redacted, paged view of one
//! command's output that never full-renders a large transcript. Stage G adds the
//! operational paged pane that wraps it with an explicit filter, a stale marker, a
//! background-load flag, and a raw-replay link, so a trace or memory history is
//! paged on the hot path and the full render is structurally denied
//! (`G-G-OPERATIONAL-ENTRY`, `G-G-TERMINAL-DESIGN`). This module performs no I/O
//! and holds no secret (redaction happens in the reused [`TracePane`]).

pub mod trace_pane;
