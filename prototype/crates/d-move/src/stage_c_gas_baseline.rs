//! Stage C gas baseline + regression classifier.
//!
//! Canonical output: [`GasTraceBaseline`], [`GasRegressionDecision`],
//! [`classify_gas_regression`].
//!
//! # Invariants
//!
//! * **Budgets are typed and explicit.** The baseline stores per-function
//!   maxima as typed [`GasBudgetMist`]. The classifier compares a sample's
//!   gross spend (`computation + storage`, saturating) against the relevant
//!   baseline maximum.
//! * **`add_chunk` hard target is < 800k MIST.** [`ADD_CHUNK_HARD_CAP_MIST`] is
//!   the absolute ceiling for [`GasTraceFunction::MemoryAddChunk`]; a spend
//!   strictly greater than it is always [`GasRegressionDecision::Red`],
//!   independent of the baseline (the "later signed exception" path does not
//!   exist in this atom).
//! * **Constant-time / overflow-checked.** [`classify_gas_regression`] has a
//!   fixed branch structure and uses saturating arithmetic, so its decision is
//!   not data-dependent in timing and never overflows.

use crate::stage_c_gas_trace::{GasTraceFunction, GasTraceSample};
use crate::types::{GasBudgetMist, ObjectId};

/// Absolute hard ceiling for an `add_chunk` gas spend, in MIST. A gross spend
/// strictly above this is always a [`GasRegressionDecision::Red`] regression.
pub const ADD_CHUNK_HARD_CAP_MIST: u64 = 800_000;

/// Per-package gas baseline: the maximum accepted spend for the two
/// budgeted functions plus the number of samples that produced it.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub struct GasTraceBaseline {
    /// The package the baseline was measured against.
    pub package: ObjectId,
    /// Maximum accepted `add_chunk` gross spend.
    pub add_chunk_max: GasBudgetMist,
    /// Maximum accepted `audit_log::append` gross spend.
    pub audit_append_max: GasBudgetMist,
    /// Number of samples that established the baseline.
    pub samples_u32: u32,
}

/// The regression verdict for one sample against a baseline.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
#[repr(u8)]
pub enum GasRegressionDecision {
    /// Within budget.
    Green = 1,
    /// Above the baseline maximum but within the hard cap — investigate.
    Warn = 2,
    /// Above the hard cap (or, for capped functions, a breach) — block.
    Red = 3,
}

/// The relevant baseline maximum for a function, in raw MIST.
#[inline]
const fn relevant_baseline_mist(function: GasTraceFunction, baseline: &GasTraceBaseline) -> u64 {
    match function {
        GasTraceFunction::AuditAppend => baseline.audit_append_max.get(),
        // add_chunk and the remaining functions are budgeted against the
        // add_chunk maximum here (only add_chunk / audit have their own
        // baseline slot).
        _ => baseline.add_chunk_max.get(),
    }
}

/// The absolute hard cap for a function, in raw MIST. Only `add_chunk` has a
/// declared hard cap in this atom; every other function is uncapped here
/// (`u64::MAX`) and is governed by the baseline only.
#[inline]
const fn hard_cap_mist(function: GasTraceFunction) -> u64 {
    match function {
        GasTraceFunction::MemoryAddChunk => ADD_CHUNK_HARD_CAP_MIST,
        _ => u64::MAX,
    }
}

/// Classify a gas sample against a baseline.
///
/// Decision ladder (fixed branch order, saturating arithmetic):
/// 1. gross spend strictly above the function's hard cap → [`Red`](GasRegressionDecision::Red);
/// 2. else gross spend strictly above the baseline maximum → [`Warn`](GasRegressionDecision::Warn);
/// 3. else → [`Green`](GasRegressionDecision::Green).
///
/// "gross spend" is `computation + storage` (saturating), matching
/// [`GasTraceSample::gross_spent_mist`].
#[inline]
pub fn classify_gas_regression(
    sample: &GasTraceSample,
    baseline: &GasTraceBaseline,
) -> GasRegressionDecision {
    let spend = sample.gross_spent_mist();
    let cap = hard_cap_mist(sample.function);
    let base = relevant_baseline_mist(sample.function, baseline);
    if spend > cap {
        GasRegressionDecision::Red
    } else if spend > base {
        GasRegressionDecision::Warn
    } else {
        GasRegressionDecision::Green
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]
    use super::*;
    use crate::stage_c_gas_trace::GasTraceFunction;
    use mnemos_a_core::trace::{StageBTraceLink, StageCTraceLink};

    fn baseline() -> GasTraceBaseline {
        GasTraceBaseline {
            package: ObjectId::new([0x22; 32]),
            add_chunk_max: GasBudgetMist::new(600_000),
            audit_append_max: GasBudgetMist::new(300_000),
            samples_u32: 10,
        }
    }

    fn add_chunk_sample(computation: u64, storage: u64) -> GasTraceSample {
        GasTraceSample {
            function: GasTraceFunction::MemoryAddChunk,
            package: ObjectId::new([0x22; 32]),
            gas_budget: GasBudgetMist::new(1_000_000),
            computation_mist_u64: computation,
            storage_mist_u64: storage,
            rebate_mist_u64: 0,
            object_writes_u16: 1,
            event_bytes_u32: 0,
            tx_bytes_u32: 0,
            trace: StageCTraceLink::new(StageBTraceLink::new(1, 179, 0), 179, 0),
        }
    }

    #[test]
    fn green_warn_red_matrix() {
        let b = baseline();
        // Green: under baseline (400k <= 600k).
        assert_eq!(
            classify_gas_regression(&add_chunk_sample(300_000, 100_000), &b),
            GasRegressionDecision::Green
        );
        // Warn: over baseline (700k > 600k) but under hard cap (800k).
        assert_eq!(
            classify_gas_regression(&add_chunk_sample(500_000, 200_000), &b),
            GasRegressionDecision::Warn
        );
        // Red: over hard cap (900k > 800k).
        assert_eq!(
            classify_gas_regression(&add_chunk_sample(700_000, 200_000), &b),
            GasRegressionDecision::Red
        );
    }

    #[test]
    fn eight_hundred_k_edge_is_not_red_but_just_over_is() {
        let b = baseline();
        // Exactly at the 800k cap: spend == cap, `spend > cap` is false → not
        // Red by cap. 800k > 600k baseline → Warn.
        assert_eq!(
            classify_gas_regression(&add_chunk_sample(800_000, 0), &b),
            GasRegressionDecision::Warn
        );
        // One MIST over the cap → Red.
        assert_eq!(
            classify_gas_regression(&add_chunk_sample(800_001, 0), &b),
            GasRegressionDecision::Red
        );
    }

    #[test]
    fn overflow_is_saturating_not_panicking() {
        let b = baseline();
        // computation + storage overflows u64; saturating_add → u64::MAX, which
        // is above the 800k cap → Red, no panic.
        let s = add_chunk_sample(u64::MAX, u64::MAX);
        assert_eq!(classify_gas_regression(&s, &b), GasRegressionDecision::Red);
        assert_eq!(s.gross_spent_mist(), u64::MAX);
    }

    #[test]
    fn audit_append_uses_its_own_baseline_and_is_uncapped() {
        let b = baseline();
        let mut s = add_chunk_sample(250_000, 0);
        s.function = GasTraceFunction::AuditAppend;
        // 250k <= 300k audit baseline → Green.
        assert_eq!(
            classify_gas_regression(&s, &b),
            GasRegressionDecision::Green
        );
        // Above audit baseline but no hard cap → Warn (not Red), even far above
        // the add_chunk 800k cap, because audit is uncapped here.
        s.computation_mist_u64 = 5_000_000;
        assert_eq!(classify_gas_regression(&s, &b), GasRegressionDecision::Warn);
    }
}
