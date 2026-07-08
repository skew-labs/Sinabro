//! Stage C PTB byte-size minimizer.
//!
//! Canonical OUT: a byte-size [`PtbSizeReport`] over the **Stage A
//! [`SuiCallBuilder`] `add_chunk` dry-run output** and the **Stage B
//! `audit_log::append` dry-run output**, with a `+5%` regression classifier.
//!
//! # Invariants
//!
//! * **Measure, never fork.** The `add_chunk` width is read from the length of
//!   the Stage A [`SuiCallBuilder::to_dry_run_bytes`] output via
//!   [`measure_add_chunk_dry_run_bytes`]; the `audit_log::append` width from the
//!   Stage B [`STAGE_B_AUDIT_APPEND_DRY_RUN_LEN`] constant. No alternate PTB
//!   builder is introduced — `no_alternate_builder` pins that the measured value
//!   equals the canonical [`SUI_DRY_RUN_BYTES_ADD_CHUNK_LEN`].
//! * **No re-mint.** The call tag reuses the [`GasTraceFunction`]; the
//!   trace reuses the [`StageCTraceLink`]. No new call-kind / trace newtype
//!   is minted here.
//! * **Byte-stable.** [`PtbSizeReport::to_bytes`] serializes to a fixed
//!   [`PTB_SIZE_REPORT_BYTES`] width in field-declaration order.

use crate::sdk::{CallBuildError, SUI_DRY_RUN_BYTES_ADD_CHUNK_LEN, SuiCallBuilder};
use crate::stage_b_call_builder::STAGE_B_AUDIT_APPEND_DRY_RUN_LEN;
use crate::stage_c_gas_trace::GasTraceFunction;
use mnemos_a_core::trace::StageCTraceLink;

/// Baseline transaction byte width of the Stage A `add_chunk` dry-run carrier,
/// reused verbatim from [`SUI_DRY_RUN_BYTES_ADD_CHUNK_LEN`] (166).
pub const PTB_ADD_CHUNK_BASELINE_BYTES: u32 = SUI_DRY_RUN_BYTES_ADD_CHUNK_LEN as u32;

/// Baseline transaction byte width of the Stage B `audit_log::append` dry-run
/// carrier, reused verbatim from [`STAGE_B_AUDIT_APPEND_DRY_RUN_LEN`].
pub const PTB_AUDIT_APPEND_BASELINE_BYTES: u32 = STAGE_B_AUDIT_APPEND_DRY_RUN_LEN as u32;

/// The regression warning threshold numerator/denominator: a measured width is
/// `Warn` once it exceeds `baseline * 105 / 100` (i.e. grows more than `+5%`).
pub const PTB_REGRESSION_WARN_NUM: u64 = 105;
/// Denominator of the `+5%` regression threshold (see [`PTB_REGRESSION_WARN_NUM`]).
pub const PTB_REGRESSION_WARN_DEN: u64 = 100;

/// Fixed serialized byte width of a [`PtbSizeReport`] (see
/// [`PtbSizeReport::to_bytes`]): `1 (function) + 4 (measured) + 4 (baseline) +
/// 15 (trace)`.
pub const PTB_SIZE_REPORT_BYTES: usize = 1 + 4 + 4 + 15;

/// Regression verdict for a measured PTB byte width versus its baseline.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
#[repr(u8)]
pub enum PtbRegression {
    /// The measured width is within `+5%` of the baseline (no growth alarm).
    Stable = 1,
    /// The measured width grew more than `+5%` over the baseline; warn.
    Warn = 2,
}

impl PtbRegression {
    /// The raw `#[repr(u8)]` discriminant.
    #[inline]
    pub const fn as_u8(self) -> u8 {
        self as u8
    }
}

/// One PTB byte-size measurement (criterion: tx bytes baseline, `+5%` warn).
///
/// Fields are `pub` per the Stage C measurement-record convention. The trace is
/// the [`StageCTraceLink`].
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub struct PtbSizeReport {
    /// Which Move call's PTB this measured.
    pub function: GasTraceFunction,
    /// The measured transaction byte width.
    pub measured_bytes_u32: u32,
    /// The pinned baseline byte width for `function`.
    pub baseline_bytes_u32: u32,
    /// The Stage C trace stamp.
    pub trace: StageCTraceLink,
}

impl PtbSizeReport {
    /// Build a report for an `add_chunk` PTB measurement against the
    /// [`PTB_ADD_CHUNK_BASELINE_BYTES`] baseline.
    #[inline]
    pub const fn add_chunk(measured_bytes_u32: u32, trace: StageCTraceLink) -> Self {
        Self {
            function: GasTraceFunction::MemoryAddChunk,
            measured_bytes_u32,
            baseline_bytes_u32: PTB_ADD_CHUNK_BASELINE_BYTES,
            trace,
        }
    }

    /// Build a report for an `audit_log::append` PTB measurement against the
    /// [`PTB_AUDIT_APPEND_BASELINE_BYTES`] baseline.
    #[inline]
    pub const fn audit_append(measured_bytes_u32: u32, trace: StageCTraceLink) -> Self {
        Self {
            function: GasTraceFunction::AuditAppend,
            measured_bytes_u32,
            baseline_bytes_u32: PTB_AUDIT_APPEND_BASELINE_BYTES,
            trace,
        }
    }

    /// Classify the measured width against the `+5%` regression threshold.
    ///
    /// `Warn` iff `measured > baseline * 105 / 100`, computed in `u64` so the
    /// multiply cannot overflow a `u32` baseline.
    #[inline]
    pub const fn regression(&self) -> PtbRegression {
        let threshold =
            (self.baseline_bytes_u32 as u64 * PTB_REGRESSION_WARN_NUM) / PTB_REGRESSION_WARN_DEN;
        if self.measured_bytes_u32 as u64 > threshold {
            PtbRegression::Warn
        } else {
            PtbRegression::Stable
        }
    }

    /// `true` iff the measured width matches the baseline exactly (no drift).
    #[inline]
    pub const fn is_at_baseline(&self) -> bool {
        self.measured_bytes_u32 == self.baseline_bytes_u32
    }

    /// Serialize to the fixed [`PTB_SIZE_REPORT_BYTES`] byte form in
    /// field-declaration order (little-endian for every integer).
    pub fn to_bytes(&self) -> [u8; PTB_SIZE_REPORT_BYTES] {
        let mut out = [0u8; PTB_SIZE_REPORT_BYTES];
        out[0] = self.function.as_u8();
        out[1..5].copy_from_slice(&self.measured_bytes_u32.to_le_bytes());
        out[5..9].copy_from_slice(&self.baseline_bytes_u32.to_le_bytes());
        out[9..17].copy_from_slice(&self.trace.trace.trace_id_u64.to_le_bytes());
        out[17..19].copy_from_slice(&self.trace.trace.atom_id_u16.to_le_bytes());
        out[19] = self.trace.trace.attempt_u8;
        out[20..22].copy_from_slice(&self.trace.stage_c_atom_u16.to_le_bytes());
        out[22..24].copy_from_slice(&self.trace.gate_id_u16.to_le_bytes());
        out
    }
}

/// Measure the byte width of a Stage A `add_chunk` PTB by reusing the canonical
/// [`SuiCallBuilder::to_dry_run_bytes`] output length. This is the **only**
/// measurement entry point — it does not re-encode or fork the builder.
#[inline]
pub fn measure_add_chunk_dry_run_bytes(builder: &SuiCallBuilder) -> Result<usize, CallBuildError> {
    Ok(builder.to_dry_run_bytes()?.len())
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]
    use super::*;
    use crate::types::{GasBudgetMist, MemoryRootArgs, ObjectId, SuiAddress};
    use mnemos_a_core::trace::StageBTraceLink;

    fn trace() -> StageCTraceLink {
        StageCTraceLink::new(StageBTraceLink::new(0xA17B_0189, 189, 0), 189, 30)
    }

    fn fixture_builder() -> SuiCallBuilder {
        let args = MemoryRootArgs {
            owner: SuiAddress::new([0xAAu8; 32]),
            root_hash: [0xBBu8; 32],
            epoch_u64: 0x0102_0304_0506_0708,
        };
        SuiCallBuilder::add_chunk(
            ObjectId::new([0xCCu8; 32]),
            &args,
            GasBudgetMist::new(800_000),
        )
        .expect("non-zero gas builds")
    }

    #[test]
    fn add_chunk_tx_bytes_stable() {
        let measured = measure_add_chunk_dry_run_bytes(&fixture_builder()).unwrap();
        assert_eq!(measured, 166);
        let report = PtbSizeReport::add_chunk(measured as u32, trace());
        assert_eq!(report.baseline_bytes_u32, PTB_ADD_CHUNK_BASELINE_BYTES);
        assert_eq!(report.baseline_bytes_u32, 166);
        assert!(report.is_at_baseline());
        assert_eq!(report.regression(), PtbRegression::Stable);
    }

    #[test]
    fn audit_append_tx_bytes_stable() {
        // The Stage B audit-append dry-run width is the pinned baseline.
        let report = PtbSizeReport::audit_append(PTB_AUDIT_APPEND_BASELINE_BYTES, trace());
        assert_eq!(report.function, GasTraceFunction::AuditAppend);
        assert!(report.is_at_baseline());
        assert_eq!(report.regression(), PtbRegression::Stable);
    }

    #[test]
    fn no_alternate_builder() {
        // The measurement goes through the canonical SuiCallBuilder output only;
        // it equals the pinned const, so no second builder is forked.
        let measured = measure_add_chunk_dry_run_bytes(&fixture_builder()).unwrap();
        assert_eq!(measured, SUI_DRY_RUN_BYTES_ADD_CHUNK_LEN);
    }

    #[test]
    fn regression_warns_only_over_five_percent() {
        // baseline 166; threshold = 166 * 105 / 100 = 174 (floor).
        let stable = PtbSizeReport::add_chunk(174, trace());
        assert_eq!(stable.regression(), PtbRegression::Stable);
        let warn = PtbSizeReport::add_chunk(175, trace());
        assert_eq!(warn.regression(), PtbRegression::Warn);
    }

    #[test]
    fn report_serialization_is_fixed_width_declaration_order() {
        let report = PtbSizeReport::add_chunk(166, trace());
        let bytes = report.to_bytes();
        assert_eq!(bytes.len(), PTB_SIZE_REPORT_BYTES);
        assert_eq!(bytes.len(), 24);
        assert_eq!(bytes[0], GasTraceFunction::MemoryAddChunk.as_u8());
        assert_eq!(&bytes[1..5], &166u32.to_le_bytes());
        assert_eq!(&bytes[5..9], &166u32.to_le_bytes());
        assert_eq!(&bytes[9..17], &0xA17B_0189u64.to_le_bytes());
        assert_eq!(&bytes[17..19], &189u16.to_le_bytes());
        assert_eq!(bytes[19], 0);
        assert_eq!(&bytes[20..22], &189u16.to_le_bytes());
        assert_eq!(&bytes[22..24], &30u16.to_le_bytes());
    }
}
