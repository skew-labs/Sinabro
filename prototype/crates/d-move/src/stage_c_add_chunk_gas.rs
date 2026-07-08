//! `add_chunk` dry-run gas collector.
//!
//! Canonical OUT: a dry-run gas collector for the Stage A
//! `memory_root::add_chunk` Move call.
//!
//! # Invariants
//!
//! * **Use the canonical builder — no alternate PTB.** The collector routes the
//!   call exclusively through [`SuiCallBuilder::add_chunk`], built
//!   from the Stage B [`MemoryRootAnchorArgs`] (its embedded
//!   [`MoveAnchorArgsV1`](mnemos_c_walrus::MoveAnchorArgsV1) supplies the
//!   anchored `root_hash` via [`memory_root_args_from_anchor`]). It never
//!   assembles a Move call by hand.
//! * **Wrong function is rejected by construction.** Because the only call this
//!   collector can build is `add_chunk`, it is *structurally impossible* to
//!   emit a [`GasTraceSample`] tagged with any other function — a stronger
//!   guarantee than a runtime string check. The emitted sample is always
//!   [`GasTraceFunction::MemoryAddChunk`].
//! * **Zero gas budget is rejected.** A zero budget fails
//!   [`SuiCallBuilder::add_chunk`] and surfaces as
//!   [`AddChunkGasError::CallBuild`] — no sample is produced.
//! * **No live call.** The dry-run numbers are supplied by the caller (a
//!   dev-inspect / dry-run response parsed elsewhere); this collector performs
//!   no network egress.

use crate::sdk::SuiCallBuilder;
use crate::stage_b_types::MemoryRootAnchorArgs;
use crate::stage_c_gas_trace::{GasTraceFunction, GasTraceSample};
use crate::types::{GasBudgetMist, SuiAddress, memory_root_args_from_anchor};
use mnemos_a_core::trace::StageCTraceLink;

/// The gas numbers parsed from an `add_chunk` dry-run / dev-inspect response.
///
/// This is the "already parsed" carrier; the JSON/transport parse lives in the
/// caller (or a later live-integration atom). Keeping it a plain `Copy` struct
/// makes the collector a pure function of typed inputs.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub struct AddChunkGasDryRun {
    /// Computation cost in MIST.
    pub computation_mist_u64: u64,
    /// Storage cost in MIST.
    pub storage_mist_u64: u64,
    /// Storage rebate returned in MIST.
    pub rebate_mist_u64: u64,
    /// Number of objects written.
    pub object_writes_u16: u16,
    /// Total event bytes emitted.
    pub event_bytes_u32: u32,
    /// Total transaction bytes.
    pub tx_bytes_u32: u32,
}

/// Why an `add_chunk` gas collection failed.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
#[repr(u8)]
pub enum AddChunkGasError {
    /// The canonical [`SuiCallBuilder::add_chunk`] call could not be built
    /// (e.g. a zero gas budget, or the anchor → args projection failed).
    CallBuild = 1,
}

/// Collect a structured [`GasTraceSample`] for an `add_chunk` dry-run.
///
/// Builds the canonical `add_chunk` routing record from the Stage B
/// [`MemoryRootAnchorArgs`] (the target root + the verified Walrus anchor),
/// the owner address, the epoch, and the typed gas budget, then folds the
/// supplied dry-run numbers into a [`GasTraceFunction::MemoryAddChunk`] sample.
///
/// Returns [`AddChunkGasError::CallBuild`] if the canonical builder rejects the
/// inputs (zero gas budget or an invalid anchor projection).
pub fn collect_add_chunk_gas(
    anchor: &MemoryRootAnchorArgs,
    owner: SuiAddress,
    epoch_u64: u64,
    gas: GasBudgetMist,
    dry_run: &AddChunkGasDryRun,
    trace: StageCTraceLink,
) -> Result<GasTraceSample, AddChunkGasError> {
    // Project the B anchor into the Stage A add_chunk args (reuses the canonical
    // bridge; root_hash comes from the verified Walrus blob id).
    let args = memory_root_args_from_anchor(anchor.anchor(), owner, epoch_u64)
        .map_err(|_| AddChunkGasError::CallBuild)?;
    // Route exclusively through the canonical add_chunk builder.
    let builder = SuiCallBuilder::add_chunk(*anchor.root(), &args, gas)
        .map_err(|_| AddChunkGasError::CallBuild)?;
    Ok(GasTraceSample {
        // Structurally MemoryAddChunk — the only call this collector can build.
        function: GasTraceFunction::MemoryAddChunk,
        package: *builder.package(),
        gas_budget: builder.gas_budget(),
        computation_mist_u64: dry_run.computation_mist_u64,
        storage_mist_u64: dry_run.storage_mist_u64,
        rebate_mist_u64: dry_run.rebate_mist_u64,
        object_writes_u16: dry_run.object_writes_u16,
        event_bytes_u32: dry_run.event_bytes_u32,
        tx_bytes_u32: dry_run.tx_bytes_u32,
        trace,
    })
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]
    use super::*;
    use crate::stage_c_gas_baseline::{
        GasRegressionDecision, GasTraceBaseline, classify_gas_regression,
    };
    use crate::types::ObjectId;
    use mnemos_a_core::trace::StageBTraceLink;
    use mnemos_c_walrus::{BlobId, ChunkKind, MoveAnchorArgsV1};

    fn anchor() -> MemoryRootAnchorArgs {
        let move_anchor = MoveAnchorArgsV1 {
            blob_id: BlobId([0x7C; 32]),
            kind: ChunkKind::UserMessage,
            parent: None,
        };
        MemoryRootAnchorArgs::new(ObjectId::new([0x30; 32]), move_anchor, [0x9D; 32])
    }

    fn dry_run() -> AddChunkGasDryRun {
        AddChunkGasDryRun {
            computation_mist_u64: 400_000,
            storage_mist_u64: 150_000,
            rebate_mist_u64: 20_000,
            object_writes_u16: 2,
            event_bytes_u32: 96,
            tx_bytes_u32: 768,
        }
    }

    fn trace() -> StageCTraceLink {
        StageCTraceLink::new(StageBTraceLink::new(0xA180, 180, 0), 180, 5)
    }

    #[test]
    fn fake_dry_run_parses_into_a_gas_sample() {
        let sample = collect_add_chunk_gas(
            &anchor(),
            SuiAddress::new([0x01; 32]),
            1,
            GasBudgetMist::new(1_000_000),
            &dry_run(),
            trace(),
        )
        .expect("a non-zero gas budget builds the add_chunk call");
        // The dry-run numbers are carried verbatim into the sample.
        assert_eq!(sample.computation_mist_u64, 400_000);
        assert_eq!(sample.storage_mist_u64, 150_000);
        assert_eq!(sample.rebate_mist_u64, 20_000);
        assert_eq!(sample.object_writes_u16, 2);
        assert_eq!(sample.event_bytes_u32, 96);
        assert_eq!(sample.tx_bytes_u32, 768);
    }

    #[test]
    fn emitted_sample_is_always_memory_add_chunk() {
        let sample = collect_add_chunk_gas(
            &anchor(),
            SuiAddress::new([0x01; 32]),
            1,
            GasBudgetMist::new(700_000),
            &dry_run(),
            trace(),
        )
        .expect("builds");
        assert_eq!(sample.function, GasTraceFunction::MemoryAddChunk);
        assert_eq!(sample.gas_budget, GasBudgetMist::new(700_000));
    }

    #[test]
    fn zero_gas_budget_is_rejected_no_sample() {
        let err = collect_add_chunk_gas(
            &anchor(),
            SuiAddress::new([0x01; 32]),
            1,
            GasBudgetMist::new(0),
            &dry_run(),
            trace(),
        )
        .expect_err("a zero gas budget must be rejected by the canonical builder");
        assert_eq!(err, AddChunkGasError::CallBuild);
    }

    #[test]
    fn add_chunk_sample_classifies_green_under_800k() {
        let sample = collect_add_chunk_gas(
            &anchor(),
            SuiAddress::new([0x01; 32]),
            1,
            GasBudgetMist::new(1_000_000),
            &dry_run(), // gross = 400k + 150k = 550k < 800k
            trace(),
        )
        .expect("builds");
        let baseline = GasTraceBaseline {
            package: sample.package,
            add_chunk_max: GasBudgetMist::new(600_000),
            audit_append_max: GasBudgetMist::new(300_000),
            samples_u32: 8,
        };
        assert!(sample.gross_spent_mist() < 800_000);
        assert_eq!(
            classify_gas_regression(&sample, &baseline),
            GasRegressionDecision::Green
        );
    }
}
