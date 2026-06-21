//! REPL latency budget + p95 score (atom #416 F.1.7).
//!
//! Perceived-zero-latency is a *gate*, not a hope: the [`LatencyBudget`] holds
//! the per-axis p95 ceilings and [`LatencyScore`] compares measured p95 against
//! them. The p95 computation here is the testable canonical OUT; the criterion
//! statistical harness is deferred (build-state precedent), and
//! `benches/repl_latency.rs` is an offline `std::time` harness that scores real
//! measurements against this budget.

/// §4.3 — perceived-latency p95 budgets, in milliseconds.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LatencyBudget {
    /// Keypress-to-feedback p95 ceiling.
    pub keypress_p95_ms: u16,
    /// Line-parse p95 ceiling.
    pub parse_p95_ms: u16,
    /// Frame/strip render p95 ceiling.
    pub render_p95_ms: u16,
    /// Local-state refresh p95 ceiling.
    pub refresh_p95_ms: u16,
}

impl LatencyBudget {
    /// The Stage F default budget from the atom criteria: keypress ≤ 16ms,
    /// parse ≤ 10ms, render ≤ 5ms, refresh ≤ 50ms.
    pub const DEFAULT: Self = Self {
        keypress_p95_ms: 16,
        parse_p95_ms: 10,
        render_p95_ms: 5,
        refresh_p95_ms: 50,
    };
}

/// Nearest-rank p95 of `samples_ms`. Returns `0` for an empty slice. Does not
/// mutate the caller's slice.
#[must_use]
pub fn p95_ms(samples_ms: &[u64]) -> u64 {
    let n = samples_ms.len();
    if n == 0 {
        return 0;
    }
    let mut sorted = samples_ms.to_vec();
    sorted.sort_unstable();
    // nearest-rank: rank = ceil(0.95 * n), 1-based; index = rank - 1.
    let rank = (95 * n).div_ceil(100);
    let idx = rank.max(1) - 1;
    sorted[idx.min(n - 1)]
}

/// Per-axis pass/fail of measured p95 against a [`LatencyBudget`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LatencyScore {
    /// Keypress axis within budget.
    pub keypress_ok: bool,
    /// Parse axis within budget.
    pub parse_ok: bool,
    /// Render axis within budget.
    pub render_ok: bool,
    /// Refresh axis within budget.
    pub refresh_ok: bool,
}

impl LatencyScore {
    /// Score measured p95 values (ms) against `budget`.
    #[must_use]
    pub const fn evaluate(
        budget: LatencyBudget,
        keypress_p95_ms: u64,
        parse_p95_ms: u64,
        render_p95_ms: u64,
        refresh_p95_ms: u64,
    ) -> Self {
        Self {
            keypress_ok: keypress_p95_ms <= budget.keypress_p95_ms as u64,
            parse_ok: parse_p95_ms <= budget.parse_p95_ms as u64,
            render_ok: render_p95_ms <= budget.render_p95_ms as u64,
            refresh_ok: refresh_p95_ms <= budget.refresh_p95_ms as u64,
        }
    }

    /// Whether every axis is within budget.
    #[must_use]
    pub const fn all_ok(&self) -> bool {
        self.keypress_ok && self.parse_ok && self.render_ok && self.refresh_ok
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn p95_of_1_to_100_is_95() {
        let samples: Vec<u64> = (1..=100).collect();
        assert_eq!(p95_ms(&samples), 95);
    }

    #[test]
    fn p95_edge_cases() {
        assert_eq!(p95_ms(&[]), 0);
        assert_eq!(p95_ms(&[42]), 42);
        assert_eq!(p95_ms(&[5, 5, 5, 5]), 5);
    }

    #[test]
    fn p95_does_not_mutate_input_order() {
        let samples = [9u64, 1, 5, 3, 7];
        let _ = p95_ms(&samples);
        assert_eq!(samples, [9, 1, 5, 3, 7]);
    }

    #[test]
    fn within_budget_scores_all_ok() {
        let s = LatencyScore::evaluate(LatencyBudget::DEFAULT, 2, 1, 1, 10);
        assert!(s.all_ok());
    }

    #[test]
    fn over_budget_axis_fails() {
        // keypress 20ms > 16ms budget
        let s = LatencyScore::evaluate(LatencyBudget::DEFAULT, 20, 1, 1, 10);
        assert!(!s.keypress_ok);
        assert!(!s.all_ok());
        assert!(s.parse_ok && s.render_ok && s.refresh_ok);
    }

    #[test]
    fn default_budget_matches_atom_criteria() {
        let b = LatencyBudget::DEFAULT;
        assert_eq!(b.keypress_p95_ms, 16);
        assert_eq!(b.parse_p95_ms, 10);
        assert_eq!(b.render_p95_ms, 5);
        assert_eq!(b.refresh_p95_ms, 50);
    }
}
