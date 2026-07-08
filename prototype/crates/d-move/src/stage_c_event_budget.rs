//! Stage C event byte-size budget.
//!
//! Canonical OUT: an explicit per-event byte **budget** for the Stage A
//! `memory_root::ChunkAnchored` event and the Stage B `audit_log::AuditAppended`
//! event, plus an over-budget classifier.
//!
//! # Invariants
//!
//! * **Events are training/ops truth, but they still cost bytes.** Each event
//!   gets an explicit byte budget ([`EVENT_BUDGET_CHUNK_ANCHORED_BYTES`],
//!   [`EVENT_BUDGET_AUDIT_APPENDED_BYTES`]); an [`EventByteSample`] whose measured
//!   width exceeds its budget classifies as [`EventBudgetVerdict::OverBudget`].
//! * **Raw content absent.** A sample carries only byte *counts* (`u32`), never
//!   the blob bytes, parent id, or entry hash — `raw_content_absent` pins that
//!   two events with different content but identical sizes serialize identically.
//! * **No re-mint.** The widths are derived from the canonical
//!   [`BLOB_ID_BYTES`](mnemos_c_walrus::BLOB_ID_BYTES) and
//!   [`STAGE_B_MOVE_VEC_LEN`]; the trace reuses the [`StageCTraceLink`].

use crate::stage_b_types::STAGE_B_MOVE_VEC_LEN;
use mnemos_a_core::trace::StageCTraceLink;
use mnemos_c_walrus::BLOB_ID_BYTES;

/// BCS `vector<u8>` length-prefix byte width for a 32-byte vector: `uleb128(32)`
/// is a single byte.
const VEC32_LEN_PREFIX_BYTES: usize = 1;
/// BCS `vector<u8>` length-prefix byte width for an empty vector: `uleb128(0)`.
const VEC0_LEN_PREFIX_BYTES: usize = 1;

/// Serialized BCS byte width of a `ChunkAnchored` event with **no** parent:
/// `root(32) + (uleb(32) + blob_id) + kind(1) + (uleb(0)) + epoch(8)`.
pub const EVENT_CHUNK_ANCHORED_BYTES_PARENT_NONE: usize =
    STAGE_B_MOVE_VEC_LEN + (VEC32_LEN_PREFIX_BYTES + BLOB_ID_BYTES) + 1 + VEC0_LEN_PREFIX_BYTES + 8;

/// Serialized BCS byte width of a `ChunkAnchored` event **with** a 32-byte
/// parent: `root(32) + (uleb(32) + blob_id) + kind(1) + (uleb(32) + parent) +
/// epoch(8)`.
pub const EVENT_CHUNK_ANCHORED_BYTES_PARENT_SOME: usize = STAGE_B_MOVE_VEC_LEN
    + (VEC32_LEN_PREFIX_BYTES + BLOB_ID_BYTES)
    + 1
    + (VEC32_LEN_PREFIX_BYTES + BLOB_ID_BYTES)
    + 8;

/// Explicit byte budget for a `ChunkAnchored` event: the worst case (parent
/// present). A measured event wider than this is over budget.
pub const EVENT_BUDGET_CHUNK_ANCHORED_BYTES: u32 = EVENT_CHUNK_ANCHORED_BYTES_PARENT_SOME as u32;

/// Explicit byte budget for an `AuditAppended` event payload: the audit entry
/// hash carried as a BCS `vector<u8>` (`uleb(32) + 32`) plus an 8-byte sequence
/// coordinate. Derived from the canonical [`STAGE_B_MOVE_VEC_LEN`] entry-hash
/// width; never carries the entry content itself.
pub const EVENT_BUDGET_AUDIT_APPENDED_BYTES: u32 =
    (VEC32_LEN_PREFIX_BYTES + STAGE_B_MOVE_VEC_LEN + 8) as u32;

/// Fixed serialized byte width of an [`EventByteSample`]:
/// `1 (kind) + 4 (measured) + 4 (budget) + 15 (trace)`.
pub const EVENT_BYTE_SAMPLE_BYTES: usize = 1 + 4 + 4 + 15;

/// Which event an [`EventByteSample`] budgets. `#[repr(u8)]` for a byte-stable
/// tag.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
#[repr(u8)]
pub enum StageCEventKind {
    /// `mnemos::memory_root::ChunkAnchored`.
    ChunkAnchored = 1,
    /// `mnemos::audit_log::AuditAppended`.
    AuditAppended = 2,
}

impl StageCEventKind {
    /// The raw `#[repr(u8)]` discriminant.
    #[inline]
    pub const fn as_u8(self) -> u8 {
        self as u8
    }

    /// The explicit byte budget for this event kind.
    #[inline]
    pub const fn budget_bytes_u32(self) -> u32 {
        match self {
            Self::ChunkAnchored => EVENT_BUDGET_CHUNK_ANCHORED_BYTES,
            Self::AuditAppended => EVENT_BUDGET_AUDIT_APPENDED_BYTES,
        }
    }
}

/// Whether a measured event size fits its explicit budget.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
#[repr(u8)]
pub enum EventBudgetVerdict {
    /// The measured width is within budget.
    WithinBudget = 1,
    /// The measured width exceeds the budget; warn.
    OverBudget = 2,
}

/// Compute the exact serialized byte width of a `ChunkAnchored` event from
/// whether the parent blob id is present. This "parses" the event size from the
/// canonical field widths without ever touching the field contents.
#[inline]
pub const fn chunk_anchored_event_bytes(parent_present: bool) -> usize {
    if parent_present {
        EVENT_CHUNK_ANCHORED_BYTES_PARENT_SOME
    } else {
        EVENT_CHUNK_ANCHORED_BYTES_PARENT_NONE
    }
}

/// One event byte-budget measurement. Carries only counts — never event content.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub struct EventByteSample {
    /// Which event this budgets.
    pub kind: StageCEventKind,
    /// The measured serialized event byte width.
    pub measured_bytes_u32: u32,
    /// The explicit byte budget for `kind`.
    pub budget_bytes_u32: u32,
    /// The Stage C trace stamp.
    pub trace: StageCTraceLink,
}

impl EventByteSample {
    /// Build a sample for `kind` with the measured width, binding the budget to
    /// the canonical [`StageCEventKind::budget_bytes_u32`].
    #[inline]
    pub const fn new(
        kind: StageCEventKind,
        measured_bytes_u32: u32,
        trace: StageCTraceLink,
    ) -> Self {
        Self {
            kind,
            measured_bytes_u32,
            budget_bytes_u32: kind.budget_bytes_u32(),
            trace,
        }
    }

    /// Classify the measured width against the budget.
    #[inline]
    pub const fn verdict(&self) -> EventBudgetVerdict {
        if self.measured_bytes_u32 > self.budget_bytes_u32 {
            EventBudgetVerdict::OverBudget
        } else {
            EventBudgetVerdict::WithinBudget
        }
    }

    /// Serialize to the fixed [`EVENT_BYTE_SAMPLE_BYTES`] form in
    /// field-declaration order (little-endian integers).
    pub fn to_bytes(&self) -> [u8; EVENT_BYTE_SAMPLE_BYTES] {
        let mut out = [0u8; EVENT_BYTE_SAMPLE_BYTES];
        out[0] = self.kind.as_u8();
        out[1..5].copy_from_slice(&self.measured_bytes_u32.to_le_bytes());
        out[5..9].copy_from_slice(&self.budget_bytes_u32.to_le_bytes());
        out[9..17].copy_from_slice(&self.trace.trace.trace_id_u64.to_le_bytes());
        out[17..19].copy_from_slice(&self.trace.trace.atom_id_u16.to_le_bytes());
        out[19] = self.trace.trace.attempt_u8;
        out[20..22].copy_from_slice(&self.trace.stage_c_atom_u16.to_le_bytes());
        out[22..24].copy_from_slice(&self.trace.gate_id_u16.to_le_bytes());
        out
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]
    use super::*;
    use mnemos_a_core::trace::StageBTraceLink;

    fn trace() -> StageCTraceLink {
        StageCTraceLink::new(StageBTraceLink::new(0xA17B_0190, 190, 0), 190, 31)
    }

    #[test]
    fn event_size_parse() {
        // ChunkAnchored width parses from the parent-present flag only.
        assert_eq!(chunk_anchored_event_bytes(false), 75);
        assert_eq!(chunk_anchored_event_bytes(true), 107);
        assert_eq!(EVENT_BUDGET_CHUNK_ANCHORED_BYTES, 107);
        assert_eq!(EVENT_BUDGET_AUDIT_APPENDED_BYTES, 41);
    }

    #[test]
    fn within_budget_when_at_or_under_cap() {
        let s = EventByteSample::new(
            StageCEventKind::ChunkAnchored,
            chunk_anchored_event_bytes(true) as u32,
            trace(),
        );
        assert_eq!(s.budget_bytes_u32, EVENT_BUDGET_CHUNK_ANCHORED_BYTES);
        assert_eq!(s.verdict(), EventBudgetVerdict::WithinBudget);
    }

    #[test]
    fn over_budget_warning() {
        let s = EventByteSample::new(
            StageCEventKind::AuditAppended,
            EVENT_BUDGET_AUDIT_APPENDED_BYTES + 1,
            trace(),
        );
        assert_eq!(s.verdict(), EventBudgetVerdict::OverBudget);
    }

    #[test]
    fn raw_content_absent() {
        // Two ChunkAnchored events with different content but the same byte
        // width produce byte-identical samples — only sizes are recorded.
        let with_parent_a = EventByteSample::new(
            StageCEventKind::ChunkAnchored,
            chunk_anchored_event_bytes(true) as u32,
            trace(),
        );
        let with_parent_b = EventByteSample::new(
            StageCEventKind::ChunkAnchored,
            chunk_anchored_event_bytes(true) as u32,
            trace(),
        );
        assert_eq!(with_parent_a.to_bytes(), with_parent_b.to_bytes());
    }

    #[test]
    fn sample_serialization_is_fixed_width() {
        let s = EventByteSample::new(StageCEventKind::ChunkAnchored, 107, trace());
        let bytes = s.to_bytes();
        assert_eq!(bytes.len(), EVENT_BYTE_SAMPLE_BYTES);
        assert_eq!(bytes.len(), 24);
        assert_eq!(bytes[0], 1);
        assert_eq!(&bytes[1..5], &107u32.to_le_bytes());
        assert_eq!(&bytes[5..9], &107u32.to_le_bytes());
    }
}
