//! Gas regression comparator with prover coupling (C-WP-02A · atom #184 · C.0.13).
//!
//! Canonical OUT: a gas regression report for `add_chunk` / `audit_log::append`
//! that couples the [`classify_gas_regression`] verdict (atom #179) with a
//! prover digest-equivalence check.
//!
//! # Madness invariants (atom #184)
//!
//! * **Green requires proof-equivalence AND gas under cap.** A sample is only
//!   [`GasCompareDecision::Green`] when (a) its gas classifies Green against the
//!   baseline, (b) a Prover proof is present, and (c) the sample's package
//!   digest equals the *proved* package digest. A measurement against an
//!   unproved or different package is never green, regardless of how cheap it
//!   is.
//! * **Faster but unproved is red.** A lower gas number obtained on a package
//!   with no proof, or with a digest that does not match the proved one, is
//!   [`GasCompareDecision::Red`] — a speed win on an unproved package is a
//!   regression of trust, not an improvement.
//! * **Over the hard cap is always red.** A gas spend over the function's hard
//!   cap (the `add_chunk` 800k ceiling, atom #179) is red even when the package
//!   is proof-equivalent — the cap dominates.
//! * **Fixed branch order.** [`compare_gas`] evaluates hard-cap → proof-present
//!   → digest-equivalence → baseline in a fixed order, giving each rejection a
//!   distinct, audit-targetable [`GasCompareReason`].

use crate::stage_c_gas_baseline::{
    GasRegressionDecision, GasTraceBaseline, classify_gas_regression,
};
use crate::stage_c_gas_trace::GasTraceSample;

/// The 32-byte digest of the on-chain Move package a measurement / proof
/// targeted. Equality of two digests is the proof-equivalence test.
pub type PackageDigest32 = [u8; 32];

/// The inputs to a gas-vs-proof comparison.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub struct GasCompareInput {
    /// The measured gas sample (from atom #180 / #181 collectors).
    pub sample: GasTraceSample,
    /// The gas baseline to classify against (atom #179).
    pub baseline: GasTraceBaseline,
    /// The package digest the Prover actually proved.
    pub proved_package_digest: PackageDigest32,
    /// The package digest the measured sample was built against.
    pub sample_package_digest: PackageDigest32,
    /// Whether a Prover proof artifact is present for the proved digest.
    pub proof_present: bool,
}

/// The final accept/investigate/block verdict.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
#[repr(u8)]
pub enum GasCompareDecision {
    /// Proof-equivalent and within budget — accept.
    Green = 1,
    /// Proof-equivalent but over the baseline (under the hard cap) — investigate.
    Warn = 2,
    /// Over the hard cap, unproved, or not proof-equivalent — block.
    Red = 3,
}

/// The audit-targetable reason for a [`GasCompareDecision`].
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
#[repr(u8)]
pub enum GasCompareReason {
    /// Proof-equivalent digest and gas within the baseline → Green.
    WithinProvedBudget = 1,
    /// Proof-equivalent digest but gas over the baseline, under the hard cap → Warn.
    OverBaselineProved = 2,
    /// Gas over the function's hard cap → Red (dominates).
    OverHardCap = 3,
    /// No Prover proof present → Red (faster-but-unproved).
    Unproved = 4,
    /// The sample's package digest does not equal the proved one → Red.
    DigestMismatch = 5,
}

/// One gas regression report: the verdict plus its audit reason.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub struct GasCompareReport {
    /// The accept/investigate/block verdict.
    pub decision: GasCompareDecision,
    /// Why the verdict was reached.
    pub reason: GasCompareReason,
}

/// Compare a measured gas sample against its baseline AND the prover digest.
///
/// Fixed branch order:
/// 1. gas over the hard cap → [`Red`](GasCompareDecision::Red) /
///    [`OverHardCap`](GasCompareReason::OverHardCap);
/// 2. else no proof present → `Red` / [`Unproved`](GasCompareReason::Unproved);
/// 3. else sample digest ≠ proved digest → `Red` /
///    [`DigestMismatch`](GasCompareReason::DigestMismatch);
/// 4. else gas over baseline (under cap) → [`Warn`](GasCompareDecision::Warn) /
///    [`OverBaselineProved`](GasCompareReason::OverBaselineProved);
/// 5. else → [`Green`](GasCompareDecision::Green) /
///    [`WithinProvedBudget`](GasCompareReason::WithinProvedBudget).
pub fn compare_gas(input: &GasCompareInput) -> GasCompareReport {
    let gas = classify_gas_regression(&input.sample, &input.baseline);
    // 1. The hard cap dominates: an over-cap spend is red even if proof-equivalent.
    if gas == GasRegressionDecision::Red {
        return GasCompareReport {
            decision: GasCompareDecision::Red,
            reason: GasCompareReason::OverHardCap,
        };
    }
    // 2. No proof → red, even when the gas is the cheapest (faster-but-unproved).
    if !input.proof_present {
        return GasCompareReport {
            decision: GasCompareDecision::Red,
            reason: GasCompareReason::Unproved,
        };
    }
    // 3. Proof present but for a different package → not proof-equivalent → red.
    if input.sample_package_digest != input.proved_package_digest {
        return GasCompareReport {
            decision: GasCompareDecision::Red,
            reason: GasCompareReason::DigestMismatch,
        };
    }
    // 4/5. Proof-equivalent: map the gas verdict (Green/Warn only here — Red was
    // handled in step 1).
    match gas {
        GasRegressionDecision::Warn => GasCompareReport {
            decision: GasCompareDecision::Warn,
            reason: GasCompareReason::OverBaselineProved,
        },
        _ => GasCompareReport {
            decision: GasCompareDecision::Green,
            reason: GasCompareReason::WithinProvedBudget,
        },
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]
    use super::*;
    use crate::stage_c_gas_trace::GasTraceFunction;
    use crate::types::{GasBudgetMist, ObjectId};
    use mnemos_a_core::trace::{StageBTraceLink, StageCTraceLink};

    const PROVED: PackageDigest32 = [0xAB; 32];

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
            trace: StageCTraceLink::new(StageBTraceLink::new(1, 184, 0), 184, 0),
        }
    }

    fn input(
        sample: GasTraceSample,
        sample_digest: PackageDigest32,
        proof: bool,
    ) -> GasCompareInput {
        GasCompareInput {
            sample,
            baseline: baseline(),
            proved_package_digest: PROVED,
            sample_package_digest: sample_digest,
            proof_present: proof,
        }
    }

    #[test]
    fn faster_but_unproved_is_red() {
        // Cheapest possible gas (well under baseline) but NO proof → Red.
        let s = add_chunk_sample(100_000, 50_000);
        let r = compare_gas(&input(s, PROVED, false));
        assert_eq!(r.decision, GasCompareDecision::Red);
        assert_eq!(r.reason, GasCompareReason::Unproved);
    }

    #[test]
    fn proved_under_cap_is_green() {
        // Proof present + digest match + gas under baseline → Green.
        let s = add_chunk_sample(300_000, 100_000); // gross 400k <= 600k baseline
        let r = compare_gas(&input(s, PROVED, true));
        assert_eq!(r.decision, GasCompareDecision::Green);
        assert_eq!(r.reason, GasCompareReason::WithinProvedBudget);
    }

    #[test]
    fn over_cap_is_red_even_when_proof_equivalent() {
        // Gas over the 800k hard cap → Red regardless of proof-equivalence.
        let s = add_chunk_sample(700_000, 200_000); // gross 900k > 800k cap
        let r = compare_gas(&input(s, PROVED, true));
        assert_eq!(r.decision, GasCompareDecision::Red);
        assert_eq!(r.reason, GasCompareReason::OverHardCap);
    }

    #[test]
    fn digest_mismatch_is_red() {
        // Proof present + cheap gas but the sample was built on a DIFFERENT
        // package than the proved one → not proof-equivalent → Red.
        let s = add_chunk_sample(300_000, 100_000);
        let r = compare_gas(&input(s, [0xCD; 32], true));
        assert_eq!(r.decision, GasCompareDecision::Red);
        assert_eq!(r.reason, GasCompareReason::DigestMismatch);
    }

    #[test]
    fn proved_over_baseline_is_warn() {
        // Proof-equivalent but gas over baseline (under cap) → Warn.
        let s = add_chunk_sample(500_000, 200_000); // gross 700k > 600k base, < 800k cap
        let r = compare_gas(&input(s, PROVED, true));
        assert_eq!(r.decision, GasCompareDecision::Warn);
        assert_eq!(r.reason, GasCompareReason::OverBaselineProved);
    }
}
