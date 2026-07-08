//! `audit_log::append` dry-run gas collector.
//!
//! Canonical OUT: a dry-run gas collector for the Stage B `audit_log::append`
//! Move call.
//!
//! # Invariants
//!
//! * **Audit gas is measured separately.** `audit_log::append` gets its own
//!   collector and its own [`GasTraceFunction::AuditAppend`] sample so the audit
//!   write cost can never be folded into — and thus never hide a regression of —
//!   the `memory_root::add_chunk` memory-anchor cost.
//! * **Route through the canonical builder — no alternate PTB.** The collector
//!   builds the call exclusively via [`StageBCallBuilder::audit_append`],
//!   from the Stage B [`AuditAppendArgs`]. It never assembles
//!   a Move call by hand.
//! * **Wrong function is rejected by construction.** Because the only call this
//!   collector can build is `audit_log::append`, it is *structurally impossible*
//!   to emit a [`GasTraceSample`] tagged with any other function. The emitted
//!   sample is always [`GasTraceFunction::AuditAppend`].
//! * **Zero gas / non-testnet are rejected.** A zero budget or a non-testnet
//!   label fails [`StageBCallBuilder::audit_append`] and surfaces as
//!   [`AuditAppendGasError::CallBuild`] — no sample is produced.
//! * **No live call.** The dry-run numbers are supplied by the caller (a
//!   dev-inspect / dry-run response parsed elsewhere); this collector performs
//!   no network egress.

use crate::stage_b_call_builder::StageBCallBuilder;
use crate::stage_b_types::AuditAppendArgs;
use crate::stage_c_gas_trace::{GasTraceFunction, GasTraceSample};
use crate::types::GasBudgetMist;
use mnemos_a_core::trace::StageCTraceLink;

/// The gas numbers parsed from an `audit_log::append` dry-run / dev-inspect
/// response.
///
/// This is the "already parsed" carrier; the JSON/transport parse lives in the
/// caller (or a later live-integration atom). Keeping it a plain `Copy` struct
/// makes the collector a pure function of typed inputs.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub struct AuditAppendGasDryRun {
    /// Computation cost in MIST.
    pub computation_mist_u64: u64,
    /// Storage cost in MIST.
    pub storage_mist_u64: u64,
    /// Storage rebate returned in MIST.
    pub rebate_mist_u64: u64,
    /// Number of objects written.
    pub object_writes_u16: u16,
    /// Total event bytes emitted (the `AuditEntryAppended` event payload size).
    pub event_bytes_u32: u32,
    /// Total transaction bytes.
    pub tx_bytes_u32: u32,
}

/// Why an `audit_log::append` gas collection failed.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
#[repr(u8)]
pub enum AuditAppendGasError {
    /// The canonical [`StageBCallBuilder::audit_append`] call could not be built
    /// (a zero gas budget, or a non-testnet network label).
    CallBuild = 1,
}

/// Collect a structured [`GasTraceSample`] for an `audit_log::append` dry-run.
///
/// Builds the canonical `audit_log::append` routing record from the Stage B
/// [`AuditAppendArgs`] (the target `AuditLog` object + the 32-byte entry hash),
/// the network label, and the typed gas budget, then folds the supplied dry-run
/// numbers into a [`GasTraceFunction::AuditAppend`] sample.
///
/// Returns [`AuditAppendGasError::CallBuild`] if the canonical builder rejects
/// the inputs (zero gas budget or a non-testnet label).
pub fn collect_audit_append_gas(
    args: &AuditAppendArgs,
    network_label: &str,
    gas: GasBudgetMist,
    dry_run: &AuditAppendGasDryRun,
    trace: StageCTraceLink,
) -> Result<GasTraceSample, AuditAppendGasError> {
    // Route exclusively through the canonical audit-append builder. Any
    // rejection (non-testnet label, zero gas) collapses to CallBuild — no
    // sample is produced for a call the canonical builder would not accept.
    let builder = StageBCallBuilder::audit_append(network_label, args, gas)
        .map_err(|_| AuditAppendGasError::CallBuild)?;
    Ok(GasTraceSample {
        // Structurally AuditAppend — the only call this collector can build.
        function: GasTraceFunction::AuditAppend,
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
    use crate::stage_b_call_builder::{STAGE_B_CALL_TESTNET_LABEL, StageBCallKind};
    use crate::stage_c_gas_baseline::{
        GasRegressionDecision, GasTraceBaseline, classify_gas_regression,
    };
    use crate::types::ObjectId;
    use mnemos_a_core::trace::StageBTraceLink;

    fn args() -> AuditAppendArgs {
        AuditAppendArgs::new(ObjectId::new([0x4A; 32]), [0xE7; 32])
    }

    fn dry_run() -> AuditAppendGasDryRun {
        AuditAppendGasDryRun {
            computation_mist_u64: 120_000,
            storage_mist_u64: 80_000,
            rebate_mist_u64: 10_000,
            object_writes_u16: 1,
            event_bytes_u32: 64,
            tx_bytes_u32: 256,
        }
    }

    fn trace() -> StageCTraceLink {
        StageCTraceLink::new(StageBTraceLink::new(0xA181, 181, 0), 181, 5)
    }

    #[test]
    fn fake_append_dry_run_parses_into_a_gas_sample() {
        let sample = collect_audit_append_gas(
            &args(),
            STAGE_B_CALL_TESTNET_LABEL,
            GasBudgetMist::new(500_000),
            &dry_run(),
            trace(),
        )
        .expect("a non-zero testnet append call builds");
        // The dry-run numbers are carried verbatim into the sample.
        assert_eq!(sample.function, GasTraceFunction::AuditAppend);
        assert_eq!(sample.computation_mist_u64, 120_000);
        assert_eq!(sample.storage_mist_u64, 80_000);
        assert_eq!(sample.rebate_mist_u64, 10_000);
        assert_eq!(sample.object_writes_u16, 1);
        assert_eq!(sample.tx_bytes_u32, 256);
        assert_eq!(sample.gas_budget, GasBudgetMist::new(500_000));
    }

    #[test]
    fn event_bytes_are_recorded_on_the_sample() {
        let mut dr = dry_run();
        dr.event_bytes_u32 = 4096;
        let sample = collect_audit_append_gas(
            &args(),
            STAGE_B_CALL_TESTNET_LABEL,
            GasBudgetMist::new(400_000),
            &dr,
            trace(),
        )
        .expect("builds");
        assert_eq!(sample.event_bytes_u32, 4096);
        // The append builder targets the audit_log module (kind AuditAppend),
        // confirming the sample's function tag is not accidental.
        let builder = StageBCallBuilder::audit_append(
            STAGE_B_CALL_TESTNET_LABEL,
            &args(),
            GasBudgetMist::new(400_000),
        )
        .expect("builds");
        assert_eq!(builder.kind(), StageBCallKind::AuditAppend);
    }

    #[test]
    fn zero_gas_and_non_testnet_are_rejected_no_sample() {
        // Zero gas → CallBuild.
        let zero = collect_audit_append_gas(
            &args(),
            STAGE_B_CALL_TESTNET_LABEL,
            GasBudgetMist::new(0),
            &dry_run(),
            trace(),
        )
        .expect_err("zero gas is rejected by the canonical builder");
        assert_eq!(zero, AuditAppendGasError::CallBuild);
        // Non-testnet label → CallBuild (live boundary stays testnet-only).
        let net = collect_audit_append_gas(
            &args(),
            "mainnet",
            GasBudgetMist::new(400_000),
            &dry_run(),
            trace(),
        )
        .expect_err("a non-testnet label is rejected");
        assert_eq!(net, AuditAppendGasError::CallBuild);
    }

    #[test]
    fn audit_gas_cap_edge_classifies_against_its_own_baseline() {
        let sample = collect_audit_append_gas(
            &args(),
            STAGE_B_CALL_TESTNET_LABEL,
            GasBudgetMist::new(500_000),
            &dry_run(), // gross = 120k + 80k = 200k
            trace(),
        )
        .expect("builds");
        let baseline = GasTraceBaseline {
            package: sample.package,
            add_chunk_max: GasBudgetMist::new(600_000),
            audit_append_max: GasBudgetMist::new(250_000),
            samples_u32: 8,
        };
        // 200k <= 250k audit baseline → Green; audit has no hard cap, so even a
        // far-larger spend would be Warn (never Red) — measured separately from
        // the add_chunk 800k cap.
        assert_eq!(sample.gross_spent_mist(), 200_000);
        assert_eq!(
            classify_gas_regression(&sample, &baseline),
            GasRegressionDecision::Green
        );
        let mut over = sample;
        over.computation_mist_u64 = 9_000_000;
        assert_eq!(
            classify_gas_regression(&over, &baseline),
            GasRegressionDecision::Warn
        );
    }
}
