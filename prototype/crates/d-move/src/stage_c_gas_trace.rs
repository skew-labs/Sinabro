//! Stage C gas trace sample type (C-WP-01 · atom #178 · C.0.7).
//!
//! Canonical OUT (§4.1): [`GasTraceFunction`], [`GasTraceSample`].
//!
//! # Madness invariants (atom #178)
//!
//! * **Gas is structured, not pasted.** A [`GasTraceSample`] is a typed record
//!   of one dry-run / dev-inspect measurement: the Move function measured, the
//!   package, the typed [`GasBudgetMist`], the computation / storage / rebate
//!   MIST split, and the object-write / event-byte / tx-byte sizes. It carries
//!   a [`StageCTraceLink`] so the sample is greppable by Stage C atom + gate.
//! * **No re-mint.** The budget reuses the Stage A [`GasBudgetMist`]; the
//!   package reuses the Stage A [`ObjectId`]; the trace reuses the §4.0
//!   [`StageCTraceLink`]. No new gas / address / trace newtype is introduced.
//! * **Byte-stable.** [`GasTraceSample::to_bytes`] serializes the sample in
//!   field-declaration order to a fixed [`GAS_TRACE_SAMPLE_BYTES`] width, so a
//!   sample is comparable / hashable across a cross-language mirror.

use crate::types::{GasBudgetMist, ObjectId};
use mnemos_a_core::trace::StageCTraceLink;

/// Which Move function a [`GasTraceSample`] measured. `#[repr(u8)]` with the
/// §4.1 discriminants so the tag is byte-stable.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
#[repr(u8)]
pub enum GasTraceFunction {
    /// `memory_root::add_chunk`.
    MemoryAddChunk = 1,
    /// `memory_root::transfer_root`.
    MemoryTransferRoot = 2,
    /// `audit_log::append`.
    AuditAppend = 3,
    /// A Walrus PUT (publish).
    WalrusPut = 4,
    /// A Walrus GET (aggregator fetch).
    WalrusGet = 5,
}

impl GasTraceFunction {
    /// The raw `#[repr(u8)]` discriminant.
    #[inline]
    pub const fn as_u8(self) -> u8 {
        self as u8
    }

    /// Parse from the discriminant byte, rejecting unknown values.
    #[inline]
    pub const fn from_u8(byte: u8) -> Option<Self> {
        match byte {
            1 => Some(Self::MemoryAddChunk),
            2 => Some(Self::MemoryTransferRoot),
            3 => Some(Self::AuditAppend),
            4 => Some(Self::WalrusPut),
            5 => Some(Self::WalrusGet),
            _ => None,
        }
    }
}

/// Fixed serialized byte width of a [`GasTraceSample`] (see
/// [`GasTraceSample::to_bytes`]). `1 + 32 + 8 + 8 + 8 + 8 + 2 + 4 + 4 + 15`.
pub const GAS_TRACE_SAMPLE_BYTES: usize = 90;

/// One structured gas measurement (§4.1).
///
/// Fields are `pub` per §4.1. The MIST split is `computation + storage`
/// charged, with `rebate` returned; callers that want the net charge use
/// [`net_charged_mist`](Self::net_charged_mist).
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub struct GasTraceSample {
    /// Which Move function was measured.
    pub function: GasTraceFunction,
    /// The on-chain package the call targeted.
    pub package: ObjectId,
    /// The typed gas budget the call was submitted with.
    pub gas_budget: GasBudgetMist,
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
    /// The Stage C trace stamp.
    pub trace: StageCTraceLink,
}

impl GasTraceSample {
    /// Net MIST charged = `computation + storage - rebate`, saturating at the
    /// `u64` bounds (a rebate larger than the cost saturates to `0`).
    #[inline]
    pub const fn net_charged_mist(&self) -> u64 {
        self.computation_mist_u64
            .saturating_add(self.storage_mist_u64)
            .saturating_sub(self.rebate_mist_u64)
    }

    /// Gross MIST spent before rebate = `computation + storage`, saturating.
    #[inline]
    pub const fn gross_spent_mist(&self) -> u64 {
        self.computation_mist_u64
            .saturating_add(self.storage_mist_u64)
    }

    /// Serialize the sample to its fixed [`GAS_TRACE_SAMPLE_BYTES`] byte form,
    /// in field-declaration order (little-endian for every integer). The trace
    /// is appended as `trace_id_u64 ‖ atom_id_u16 ‖ attempt_u8 ‖
    /// stage_c_atom_u16 ‖ gate_id_u16`.
    pub fn to_bytes(&self) -> [u8; GAS_TRACE_SAMPLE_BYTES] {
        let mut out = [0u8; GAS_TRACE_SAMPLE_BYTES];
        out[0] = self.function.as_u8();
        out[1..33].copy_from_slice(self.package.as_bytes());
        out[33..41].copy_from_slice(&self.gas_budget.get().to_le_bytes());
        out[41..49].copy_from_slice(&self.computation_mist_u64.to_le_bytes());
        out[49..57].copy_from_slice(&self.storage_mist_u64.to_le_bytes());
        out[57..65].copy_from_slice(&self.rebate_mist_u64.to_le_bytes());
        out[65..67].copy_from_slice(&self.object_writes_u16.to_le_bytes());
        out[67..71].copy_from_slice(&self.event_bytes_u32.to_le_bytes());
        out[71..75].copy_from_slice(&self.tx_bytes_u32.to_le_bytes());
        out[75..83].copy_from_slice(&self.trace.trace.trace_id_u64.to_le_bytes());
        out[83..85].copy_from_slice(&self.trace.trace.atom_id_u16.to_le_bytes());
        out[85] = self.trace.trace.attempt_u8;
        out[86..88].copy_from_slice(&self.trace.stage_c_atom_u16.to_le_bytes());
        out[88..90].copy_from_slice(&self.trace.gate_id_u16.to_le_bytes());
        out
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]
    use super::*;
    use mnemos_a_core::trace::StageBTraceLink;

    fn sample() -> GasTraceSample {
        GasTraceSample {
            function: GasTraceFunction::MemoryAddChunk,
            package: ObjectId::new([0x11; 32]),
            gas_budget: GasBudgetMist::new(1_000_000),
            computation_mist_u64: 500_000,
            storage_mist_u64: 200_000,
            rebate_mist_u64: 50_000,
            object_writes_u16: 3,
            event_bytes_u32: 128,
            tx_bytes_u32: 1024,
            trace: StageCTraceLink::new(StageBTraceLink::new(0xA17B_0178, 178, 1), 178, 5),
        }
    }

    #[test]
    fn function_tag_roundtrips() {
        for f in [
            GasTraceFunction::MemoryAddChunk,
            GasTraceFunction::MemoryTransferRoot,
            GasTraceFunction::AuditAppend,
            GasTraceFunction::WalrusPut,
            GasTraceFunction::WalrusGet,
        ] {
            assert_eq!(GasTraceFunction::from_u8(f.as_u8()), Some(f));
        }
        for unknown in [0u8, 6, 7, 255] {
            assert!(GasTraceFunction::from_u8(unknown).is_none());
        }
    }

    #[test]
    fn sample_serialization_is_fixed_width_and_declaration_order() {
        let s = sample();
        let bytes = s.to_bytes();
        assert_eq!(bytes.len(), GAS_TRACE_SAMPLE_BYTES);
        assert_eq!(bytes.len(), 90);
        assert_eq!(bytes[0], 1); // MemoryAddChunk
        assert_eq!(&bytes[1..33], &[0x11u8; 32]);
        assert_eq!(&bytes[33..41], &1_000_000u64.to_le_bytes());
        assert_eq!(&bytes[41..49], &500_000u64.to_le_bytes());
        assert_eq!(&bytes[49..57], &200_000u64.to_le_bytes());
        assert_eq!(&bytes[57..65], &50_000u64.to_le_bytes());
        assert_eq!(&bytes[65..67], &3u16.to_le_bytes());
        assert_eq!(&bytes[67..71], &128u32.to_le_bytes());
        assert_eq!(&bytes[71..75], &1024u32.to_le_bytes());
        assert_eq!(&bytes[75..83], &0xA17B_0178u64.to_le_bytes());
        assert_eq!(&bytes[83..85], &178u16.to_le_bytes());
        assert_eq!(bytes[85], 1);
        assert_eq!(&bytes[86..88], &178u16.to_le_bytes());
        assert_eq!(&bytes[88..90], &5u16.to_le_bytes());
    }

    #[test]
    fn unit_widths_and_net_charge() {
        let s = sample();
        // gross = comp + storage; net = gross - rebate.
        assert_eq!(s.gross_spent_mist(), 700_000);
        assert_eq!(s.net_charged_mist(), 650_000);
        // rebate larger than cost saturates net to zero, never underflows.
        let mut over = sample();
        over.rebate_mist_u64 = u64::MAX;
        assert_eq!(over.net_charged_mist(), 0);
    }
}
