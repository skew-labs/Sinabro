//! Object / event / storage effect-delta parser.
//!
//! Canonical OUT: a parser that extracts the object-write / event / storage
//! effect shape from a dry-run / dev-inspect response.
//!
//! # Invariants
//!
//! * **Gas without effect-shape is incomplete.** A raw MIST number says how much
//!   a call cost but not *what* it did. An [`EffectDelta`] records the object
//!   writes, event count / bytes, and the storage cost / rebate split, so the
//!   same parsed shape can feed both the gas trace and a future Gas
//!   Station effect allowlist.
//! * **Failed executions are rejected.** [`EffectDelta::from_dev_inspect`]
//!   refuses a non-success dev-inspect status ([`EffectDeltaError::ExecutionFailed`]);
//!   a measurement of a reverted call is not a usable effect shape.
//! * **Malformed wire is rejected fail-closed.** [`EffectDelta::from_bytes`]
//!   refuses any slice whose width is not exactly [`EFFECT_DELTA_BYTES`]
//!   ([`EffectDeltaError::MalformedLength`]).
//! * **Net storage cannot overflow.** [`EffectDelta::net_storage_mist`] computes
//!   `cost - rebate` over a widened `i128` and clamps to the `i64` range, so a
//!   rebate larger than the cost yields a negative net (a refund) and never
//!   panics.

/// Fixed serialized byte width of an [`EffectDelta`]:
/// `2` (object writes) + `2` (event count) + `4` (event bytes) + `8` (storage
/// cost) + `8` (storage rebate).
pub const EFFECT_DELTA_BYTES: usize = 24;

/// Why an effect-delta could not be produced.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
#[repr(u8)]
pub enum EffectDeltaError {
    /// A [`from_bytes`](EffectDelta::from_bytes) slice was not exactly
    /// [`EFFECT_DELTA_BYTES`] wide.
    MalformedLength = 1,
    /// A [`from_dev_inspect`](EffectDelta::from_dev_inspect) status was not
    /// success.
    ExecutionFailed = 2,
}

/// The object / event / storage effect shape of one dry-run measurement.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub struct EffectDelta {
    /// Number of objects written (created / mutated).
    pub object_writes_u16: u16,
    /// Number of events emitted.
    pub event_count_u16: u16,
    /// Total event payload bytes.
    pub event_bytes_u32: u32,
    /// Storage cost charged in MIST.
    pub storage_cost_mist_u64: u64,
    /// Storage rebate returned in MIST.
    pub storage_rebate_mist_u64: u64,
}

impl EffectDelta {
    /// Build an effect-delta from a parsed dev-inspect / dry-run response.
    ///
    /// Rejects a non-success status with [`EffectDeltaError::ExecutionFailed`] —
    /// the effect shape of a reverted call is not a usable measurement.
    #[inline]
    pub fn from_dev_inspect(
        success: bool,
        object_writes_u16: u16,
        event_count_u16: u16,
        event_bytes_u32: u32,
        storage_cost_mist_u64: u64,
        storage_rebate_mist_u64: u64,
    ) -> Result<Self, EffectDeltaError> {
        if !success {
            return Err(EffectDeltaError::ExecutionFailed);
        }
        Ok(Self {
            object_writes_u16,
            event_count_u16,
            event_bytes_u32,
            storage_cost_mist_u64,
            storage_rebate_mist_u64,
        })
    }

    /// Net storage charge = `cost - rebate`, computed over `i128` and clamped to
    /// the `i64` range. A rebate larger than the cost yields a negative net (a
    /// storage refund); never overflows or panics.
    #[inline]
    pub const fn net_storage_mist(&self) -> i64 {
        let net = self.storage_cost_mist_u64 as i128 - self.storage_rebate_mist_u64 as i128;
        if net > i64::MAX as i128 {
            i64::MAX
        } else if net < i64::MIN as i128 {
            i64::MIN
        } else {
            net as i64
        }
    }

    /// Whether this effect shape agrees with the effect fields a
    /// [`GasTraceSample`](crate::stage_c_gas_trace::GasTraceSample) carries
    /// (`object_writes`, `event_bytes`, storage cost / rebate). The parser feeds
    /// the gas trace; this is the consistency check that they did not drift.
    #[inline]
    pub fn agrees_with_sample(&self, sample: &crate::stage_c_gas_trace::GasTraceSample) -> bool {
        self.object_writes_u16 == sample.object_writes_u16
            && self.event_bytes_u32 == sample.event_bytes_u32
            && self.storage_cost_mist_u64 == sample.storage_mist_u64
            && self.storage_rebate_mist_u64 == sample.rebate_mist_u64
    }

    /// Serialize to the fixed [`EFFECT_DELTA_BYTES`] byte form, in
    /// field-declaration order (little-endian integers). Alloc-free.
    pub fn to_bytes(&self) -> [u8; EFFECT_DELTA_BYTES] {
        let mut out = [0u8; EFFECT_DELTA_BYTES];
        out[0..2].copy_from_slice(&self.object_writes_u16.to_le_bytes());
        out[2..4].copy_from_slice(&self.event_count_u16.to_le_bytes());
        out[4..8].copy_from_slice(&self.event_bytes_u32.to_le_bytes());
        out[8..16].copy_from_slice(&self.storage_cost_mist_u64.to_le_bytes());
        out[16..24].copy_from_slice(&self.storage_rebate_mist_u64.to_le_bytes());
        out
    }

    /// Parse from the fixed [`EFFECT_DELTA_BYTES`] byte form, inverting
    /// [`to_bytes`](Self::to_bytes). Rejects a wrong-width slice fail-closed.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, EffectDeltaError> {
        if bytes.len() != EFFECT_DELTA_BYTES {
            return Err(EffectDeltaError::MalformedLength);
        }
        let mut object_writes = [0u8; 2];
        object_writes.copy_from_slice(&bytes[0..2]);
        let mut event_count = [0u8; 2];
        event_count.copy_from_slice(&bytes[2..4]);
        let mut event_bytes = [0u8; 4];
        event_bytes.copy_from_slice(&bytes[4..8]);
        let mut cost = [0u8; 8];
        cost.copy_from_slice(&bytes[8..16]);
        let mut rebate = [0u8; 8];
        rebate.copy_from_slice(&bytes[16..24]);
        Ok(Self {
            object_writes_u16: u16::from_le_bytes(object_writes),
            event_count_u16: u16::from_le_bytes(event_count),
            event_bytes_u32: u32::from_le_bytes(event_bytes),
            storage_cost_mist_u64: u64::from_le_bytes(cost),
            storage_rebate_mist_u64: u64::from_le_bytes(rebate),
        })
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]
    use super::*;
    use crate::stage_c_gas_trace::{GasTraceFunction, GasTraceSample};
    use crate::types::{GasBudgetMist, ObjectId};
    use mnemos_a_core::trace::{StageBTraceLink, StageCTraceLink};

    fn delta() -> EffectDelta {
        EffectDelta::from_dev_inspect(true, 3, 2, 256, 180_000, 20_000)
            .expect("a success dev-inspect parses")
    }

    #[test]
    fn write_count_is_parsed_and_roundtrips() {
        let d = delta();
        assert_eq!(d.object_writes_u16, 3);
        // Byte roundtrip preserves every field.
        let bytes = d.to_bytes();
        assert_eq!(bytes.len(), EFFECT_DELTA_BYTES);
        assert_eq!(EffectDelta::from_bytes(&bytes).unwrap(), d);
    }

    #[test]
    fn event_count_and_bytes_are_parsed() {
        let d = delta();
        assert_eq!(d.event_count_u16, 2);
        assert_eq!(d.event_bytes_u32, 256);
    }

    #[test]
    fn storage_cost_rebate_net_can_be_negative_without_overflow() {
        // cost > rebate → positive net.
        let d = delta();
        assert_eq!(d.net_storage_mist(), 180_000 - 20_000);
        // rebate > cost → negative net (a refund), no underflow.
        let refund = EffectDelta::from_dev_inspect(true, 1, 0, 0, 10_000, 30_000).unwrap();
        assert_eq!(refund.net_storage_mist(), -20_000);
        // extreme: max cost, zero rebate clamps inside i64.
        let big = EffectDelta::from_dev_inspect(true, 1, 0, 0, u64::MAX, 0).unwrap();
        assert_eq!(big.net_storage_mist(), i64::MAX);
        // zero cost, max rebate → clamps to i64::MIN, no panic.
        let big_refund = EffectDelta::from_dev_inspect(true, 1, 0, 0, 0, u64::MAX).unwrap();
        assert_eq!(big_refund.net_storage_mist(), i64::MIN);
    }

    #[test]
    fn malformed_inputs_are_rejected() {
        // Non-success dev-inspect → ExecutionFailed.
        let failed = EffectDelta::from_dev_inspect(false, 1, 1, 1, 1, 1);
        assert_eq!(failed, Err(EffectDeltaError::ExecutionFailed));
        // Wrong-width byte slice → MalformedLength.
        assert_eq!(
            EffectDelta::from_bytes(&[0u8; EFFECT_DELTA_BYTES - 1]),
            Err(EffectDeltaError::MalformedLength)
        );
        assert_eq!(
            EffectDelta::from_bytes(&[0u8; EFFECT_DELTA_BYTES + 1]),
            Err(EffectDeltaError::MalformedLength)
        );
    }

    #[test]
    fn effect_delta_agrees_with_a_gas_sample_it_feeds() {
        let d = delta();
        let sample = GasTraceSample {
            function: GasTraceFunction::MemoryAddChunk,
            package: ObjectId::new([0x11; 32]),
            gas_budget: GasBudgetMist::new(1_000_000),
            computation_mist_u64: 400_000,
            storage_mist_u64: d.storage_cost_mist_u64,
            rebate_mist_u64: d.storage_rebate_mist_u64,
            object_writes_u16: d.object_writes_u16,
            event_bytes_u32: d.event_bytes_u32,
            tx_bytes_u32: 768,
            trace: StageCTraceLink::new(StageBTraceLink::new(0xA185, 185, 0), 185, 5),
        };
        assert!(d.agrees_with_sample(&sample));
        // A drifted sample (different object count) is detected.
        let mut drifted = sample;
        drifted.object_writes_u16 = 99;
        assert!(!d.agrees_with_sample(&drifted));
    }
}
