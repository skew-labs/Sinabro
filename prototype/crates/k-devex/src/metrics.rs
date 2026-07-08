//! Prometheus text exposition for the MNEMOS metrics surface.
//!
//! `MetricsExporter` is a fixed-capacity counter array (`[AtomicU64; 7]`) — no
//! heap, no labels, no provider response bodies, no user-tied data. Counters
//! cover seven axes:
//! LLM input/output tokens, cache hit ratio (basis points), Walrus PUT
//! latency (ms), Sui gas (MIST), tool denials, and daily spend
//! (USD micro-dollars). Exposition is plain Prometheus text — every axis emits
//! the canonical `# HELP` / `# TYPE` / `<name> <value>` triple with no label
//! dimension at all, so the secret-exposure surface is 0 by construction.

use core::fmt::Write as _;
use core::sync::atomic::{AtomicU64, Ordering};

/// MNEMOS counter axes — explicit `#[repr(u8)]` discriminants.
///
/// Variants are explicitly numbered 1..=7 so the discriminant is a stable
/// wire-style value and so `index()` can map `discriminant - 1` directly into
/// the counter array without a match table.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Metric {
    /// Cumulative count of LLM input tokens observed.
    LlmInputTokens = 1,
    /// Cumulative count of LLM output tokens observed.
    LlmOutputTokens = 2,
    /// Cumulative sum of cache hit ratio samples expressed in basis points
    /// (1 bp = 0.01%). The mean ratio is recovered by dividing by the
    /// number of contributing samples (tracked separately by callers).
    CacheHitRatioBp = 3,
    /// Cumulative sum of Walrus PUT latency samples in milliseconds.
    WalrusPutLatencyMs = 4,
    /// Cumulative Sui gas spend in MIST (1 SUI = 1_000_000_000 MIST).
    SuiGasMist = 5,
    /// Cumulative count of tool denial events (allowlist / policy refusals).
    ToolDenials = 6,
    /// Cumulative daily spend in USD micro-dollars (1 USD = 1_000_000).
    DailyUsdMicros = 7,
}

/// Total number of metric axes — fixed at compile time, matches
/// `Metric::ALL.len()` and the counter array width.
pub const METRIC_AXES: usize = 7;

impl Metric {
    /// All 7 metric axes in `#[repr(u8)]` discriminant order.
    pub const ALL: [Metric; METRIC_AXES] = [
        Metric::LlmInputTokens,
        Metric::LlmOutputTokens,
        Metric::CacheHitRatioBp,
        Metric::WalrusPutLatencyMs,
        Metric::SuiGasMist,
        Metric::ToolDenials,
        Metric::DailyUsdMicros,
    ];

    /// Prometheus exposition metric name for this axis.
    ///
    /// Names follow the Prometheus convention `mnemos_<snake_case>_total` —
    /// all axes are monotonic counters and so end in `_total`. Names are
    /// lowercase, contain no label dimension, and never embed a secret
    /// substring (no `KEY` / `SECRET` / `PASS` / `PRIVATE` / `MNEMONIC` /
    /// `CREDENTIAL` / `BEARER` in upper-case).
    pub const fn name(self) -> &'static str {
        match self {
            Metric::LlmInputTokens => "mnemos_llm_input_tokens_total",
            Metric::LlmOutputTokens => "mnemos_llm_output_tokens_total",
            Metric::CacheHitRatioBp => "mnemos_cache_hit_ratio_bp_total",
            Metric::WalrusPutLatencyMs => "mnemos_walrus_put_latency_ms_total",
            Metric::SuiGasMist => "mnemos_sui_gas_mist_total",
            Metric::ToolDenials => "mnemos_tool_denials_total",
            Metric::DailyUsdMicros => "mnemos_daily_usd_micros_total",
        }
    }

    /// Prometheus `# HELP` description text for this axis.
    pub const fn help(self) -> &'static str {
        match self {
            Metric::LlmInputTokens => "MNEMOS LLM input tokens (cumulative count).",
            Metric::LlmOutputTokens => "MNEMOS LLM output tokens (cumulative count).",
            Metric::CacheHitRatioBp => {
                "MNEMOS cache hit ratio sample sum in basis points (cumulative)."
            }
            Metric::WalrusPutLatencyMs => {
                "MNEMOS Walrus PUT latency sample sum in milliseconds (cumulative)."
            }
            Metric::SuiGasMist => "MNEMOS Sui gas spend in MIST (cumulative).",
            Metric::ToolDenials => "MNEMOS tool denial event count (cumulative).",
            Metric::DailyUsdMicros => "MNEMOS daily spend in USD micro-dollars (cumulative).",
        }
    }

    /// Index of this axis in the `[AtomicU64; METRIC_AXES]` counter array.
    const fn index(self) -> usize {
        // discriminants are 1-based; the counter array is 0-based.
        (self as u8 - 1) as usize
    }
}

/// Prometheus text-exposition counter exporter for the MNEMOS metric axes.
///
/// Storage is a fixed `[AtomicU64; METRIC_AXES]` (no heap, no allocation on
/// the `incr` hot path). Every axis is a monotonic counter; `incr` uses a
/// CAS loop with saturating addition, so a runaway producer cannot wrap a
/// counter to a misleadingly small value and the value is always atomic.
/// `render` emits Prometheus text exposition with no label dimension at all,
/// which keeps the secret-exposure surface 0 by construction (no `{k="v"}`
/// pair can carry an API key, mnemonic, or bearer token).
pub struct MetricsExporter {
    counters: [AtomicU64; METRIC_AXES],
}

impl MetricsExporter {
    /// Construct a fresh exporter with every counter zero.
    pub const fn new() -> Self {
        Self {
            counters: [
                AtomicU64::new(0),
                AtomicU64::new(0),
                AtomicU64::new(0),
                AtomicU64::new(0),
                AtomicU64::new(0),
                AtomicU64::new(0),
                AtomicU64::new(0),
            ],
        }
    }

    /// Atomically increment the counter for axis `m` by `by_u64` using
    /// saturating addition. Returns once the new value is visible to other
    /// threads with `Ordering::Relaxed` semantics (per-axis monotonicity is
    /// all that callers require; inter-axis ordering is not exposed).
    pub fn incr(&self, m: Metric, by_u64: u64) {
        let counter = &self.counters[m.index()];
        let mut current = counter.load(Ordering::Relaxed);
        loop {
            let next = current.saturating_add(by_u64);
            match counter.compare_exchange_weak(current, next, Ordering::Relaxed, Ordering::Relaxed)
            {
                Ok(_) => return,
                Err(observed) => current = observed,
            }
        }
    }

    /// Render the Prometheus text exposition for the `/metrics` endpoint.
    ///
    /// Every axis emits the canonical 3-line block:
    /// ```text
    /// # HELP <name> <description>
    /// # TYPE <name> counter
    /// <name> <value>
    /// ```
    /// No label dimension is emitted. The output ends with a newline.
    pub fn render(&self) -> String {
        // Each line is at most ~110 ASCII bytes; pre-size to avoid reallocs
        // along the exposition path (render is not on the hot path, but the
        // size bound is deterministic so this stays cheap).
        let mut out = String::with_capacity(METRIC_AXES * 256);
        for m in Metric::ALL {
            let value = self.counters[m.index()].load(Ordering::Relaxed);
            // writeln! on String cannot fail (no I/O); discard the trivially-Ok result.
            let _ = writeln!(out, "# HELP {} {}", m.name(), m.help());
            let _ = writeln!(out, "# TYPE {} counter", m.name());
            let _ = writeln!(out, "{} {}", m.name(), value);
        }
        out
    }
}

impl Default for MetricsExporter {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn k0_4_incr_and_render() {
        let exporter = MetricsExporter::new();

        // Initial render: every counter is 0.
        let initial = exporter.render();
        for m in Metric::ALL {
            let zero_line = format!("{} 0", m.name());
            assert!(
                initial.contains(&zero_line),
                "initial render missing '{zero_line}'",
            );
        }

        // Multiple increments accumulate.
        exporter.incr(Metric::LlmInputTokens, 100);
        exporter.incr(Metric::LlmInputTokens, 50);
        exporter.incr(Metric::ToolDenials, 3);
        exporter.incr(Metric::SuiGasMist, 1_000_000);

        let after = exporter.render();
        assert!(after.contains("mnemos_llm_input_tokens_total 150"));
        assert!(after.contains("mnemos_tool_denials_total 3"));
        assert!(after.contains("mnemos_sui_gas_mist_total 1000000"));
        // Untouched axes still zero.
        assert!(after.contains("mnemos_llm_output_tokens_total 0"));
        assert!(after.contains("mnemos_cache_hit_ratio_bp_total 0"));
        assert!(after.contains("mnemos_walrus_put_latency_ms_total 0"));
        assert!(after.contains("mnemos_daily_usd_micros_total 0"));

        // Saturating add: max + any positive stays at u64::MAX.
        exporter.incr(Metric::DailyUsdMicros, u64::MAX);
        exporter.incr(Metric::DailyUsdMicros, 1);
        let saturated = exporter.render();
        let max_line = format!("mnemos_daily_usd_micros_total {}", u64::MAX);
        assert!(
            saturated.contains(&max_line),
            "saturating add should pin at u64::MAX"
        );
    }

    #[test]
    fn k0_4_render_is_prometheus_text() {
        let exporter = MetricsExporter::new();
        exporter.incr(Metric::WalrusPutLatencyMs, 42);

        let rendered = exporter.render();

        // Output ends with a newline (Prometheus exposition convention).
        assert!(rendered.ends_with('\n'), "exposition must end with newline");

        // Every axis emits the canonical HELP / TYPE / value triple.
        for m in Metric::ALL {
            let help_prefix = format!("# HELP {} ", m.name());
            let type_line = format!("# TYPE {} counter", m.name());
            assert!(
                rendered.contains(&help_prefix),
                "missing '# HELP' line for {}",
                m.name()
            );
            assert!(
                rendered.contains(&type_line),
                "missing '# TYPE' line for {}",
                m.name()
            );
        }

        // Exact line count: 7 axes × 3 lines per axis = 21 lines.
        let line_count = rendered.lines().count();
        assert_eq!(
            line_count,
            METRIC_AXES * 3,
            "expected {} lines",
            METRIC_AXES * 3
        );

        // No label dimension is emitted — Prometheus label braces must not appear
        // anywhere in the exposition, which keeps `{k="secret"}` impossible by
        // construction.
        assert!(!rendered.contains('{'), "exposition must not contain '{{'");
        assert!(!rendered.contains('}'), "exposition must not contain '}}'");

        // Counter values render as plain decimal integers (no quoting).
        assert!(rendered.contains("mnemos_walrus_put_latency_ms_total 42"));
    }

    #[test]
    fn k0_4_no_secret_labels() {
        let exporter = MetricsExporter::new();
        // Drive every axis with a nonzero value so render exercises all 7.
        for m in Metric::ALL {
            exporter.incr(m, 1);
        }

        let rendered = exporter.render();

        // Label-brace dimension must be entirely absent so no `{k="secret"}`
        // pair can ever be emitted.
        assert!(!rendered.contains('{'));
        assert!(!rendered.contains('}'));

        // Render must not contain secret-class substrings in upper-case (the
        // `RuntimeEnv::from_pairs` filter set — KEY / TOKEN /
        // SECRET / PASS / PRIVATE / MNEMONIC / CREDENTIAL — plus the obvious
        // HTTP auth surface). All metric names are lower-case so these checks
        // pin "no secret-shaped identifier leaked into exposition text".
        for forbidden in [
            "KEY",
            "TOKEN",
            "SECRET",
            "PASS",
            "PRIVATE",
            "MNEMONIC",
            "CREDENTIAL",
            "BEARER",
            "Authorization",
        ] {
            assert!(
                !rendered.contains(forbidden),
                "render leaked secret-class substring '{forbidden}'",
            );
        }

        // No `=` outside of declarative HELP/TYPE words — label pairs like
        // `name="value"` would require '=', and we use neither labels nor
        // any `=` glyph in the exposition.
        assert!(
            !rendered.contains('='),
            "exposition must not contain '=' (would allow label-style key=value)"
        );
    }

    #[test]
    fn metric_discriminants_match_canonical_spec() {
        // Discriminants are pinned to 1..=7 in this exact order.
        assert_eq!(Metric::LlmInputTokens as u8, 1);
        assert_eq!(Metric::LlmOutputTokens as u8, 2);
        assert_eq!(Metric::CacheHitRatioBp as u8, 3);
        assert_eq!(Metric::WalrusPutLatencyMs as u8, 4);
        assert_eq!(Metric::SuiGasMist as u8, 5);
        assert_eq!(Metric::ToolDenials as u8, 6);
        assert_eq!(Metric::DailyUsdMicros as u8, 7);
        assert_eq!(Metric::ALL.len(), METRIC_AXES);
    }

    #[test]
    fn exporter_is_heap_free_fixed_width() {
        // [AtomicU64; 7] = 56 bytes, no padding beyond u64 alignment.
        assert_eq!(
            core::mem::size_of::<MetricsExporter>(),
            METRIC_AXES * core::mem::size_of::<u64>()
        );
        assert_eq!(
            core::mem::align_of::<MetricsExporter>(),
            core::mem::align_of::<u64>()
        );
    }
}
