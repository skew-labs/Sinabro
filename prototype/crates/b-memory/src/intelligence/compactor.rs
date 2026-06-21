//! Background tier compactor (Stage D Cluster 6, atom #326 · D.5.5).
//!
//! [`MemoryTier`] and [`CompactionPlan`] (§4.6) drive a recent → mid → ancient
//! aging compactor that runs as a **cooperative background step machine**: each
//! [`BackgroundCompactor::step`] processes at most a caller-supplied number of
//! entries and returns, so the foreground never blocks beyond one scheduling
//! tick. Stepping is **cancellation-safe** — progress is recorded in an internal
//! cursor, so stopping and resuming never reprocesses or loses an entry.
//!
//! Two invariants are structural:
//!
//! * **Tombstones are preserved.** A [`MemoryTier::DeletedTombstone`] entry is
//!   never aged or removed; a deleted memory cannot be resurrected by
//!   compaction.
//! * **Replay truth is preserved.** The reused [`ReplayCursor`] and the Stage B
//!   transcript anchor are carried through compaction unchanged — compaction
//!   reorders nothing in replay truth.

use crate::chunk::MemoryId;
use crate::replay::ReplayCursor;
use crate::stage_b_replay::StageBTranscriptHash32;

/// Memory age tier (§4.6).
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
#[repr(u8)]
pub enum MemoryTier {
    /// Most recent tier.
    Recent = 1,
    /// Middle-aged tier.
    Mid = 2,
    /// Ancient (coldest live) tier.
    Ancient = 3,
    /// Deleted tombstone — terminal, never aged or resurrected.
    DeletedTombstone = 4,
}

impl MemoryTier {
    /// Stable `u8` tag — mirrors the `#[repr(u8)]` discriminant.
    #[inline]
    pub const fn tag(self) -> u8 {
        self as u8
    }

    /// Whether this tier is the deleted tombstone (terminal, preserved).
    #[inline]
    pub const fn is_tombstone(self) -> bool {
        matches!(self, Self::DeletedTombstone)
    }

    /// The next aging tier (`Recent → Mid → Ancient`). `Ancient` and
    /// `DeletedTombstone` do not age further (`None`).
    #[must_use]
    pub const fn next_aging_tier(self) -> Option<Self> {
        match self {
            Self::Recent => Some(Self::Mid),
            Self::Mid => Some(Self::Ancient),
            Self::Ancient | Self::DeletedTombstone => None,
        }
    }
}

/// Compaction error set (frozen). Every variant is a data-free tag.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
#[non_exhaustive]
pub enum CompactionError {
    /// The target tier is not the legal next aging tier of the source.
    IllegalTransition,
    /// A tombstone tier can never be a compaction source.
    TombstoneNotCompactable,
}

/// A planned tier transition for a batch of memories (§4.6).
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub struct CompactionPlan {
    /// Tier the batch is aged from.
    pub source_tier: MemoryTier,
    /// Tier the batch is aged to (the legal next aging tier of the source).
    pub target_tier: MemoryTier,
    /// Number of inputs considered.
    pub input_count_u32: u32,
    /// Number of outputs produced.
    pub output_count_u32: u32,
    /// Per-tick stall budget in milliseconds (the foreground may not block
    /// longer than this).
    pub stall_budget_ms_u16: u16,
}

impl CompactionPlan {
    /// Validate and construct a compaction plan. The target must be the legal
    /// next aging tier of the source, and a tombstone is never a source.
    pub const fn new(
        source_tier: MemoryTier,
        target_tier: MemoryTier,
        input_count_u32: u32,
        output_count_u32: u32,
        stall_budget_ms_u16: u16,
    ) -> Result<Self, CompactionError> {
        if source_tier.is_tombstone() {
            return Err(CompactionError::TombstoneNotCompactable);
        }
        match source_tier.next_aging_tier() {
            Some(expected) if expected as u8 == target_tier as u8 => Ok(Self {
                source_tier,
                target_tier,
                input_count_u32,
                output_count_u32,
                stall_budget_ms_u16,
            }),
            _ => Err(CompactionError::IllegalTransition),
        }
    }
}

/// One entry the compactor tracks: a memory id and its current tier.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub struct CompactorEntry {
    /// The memory id.
    pub id: MemoryId,
    /// Its current tier.
    pub tier: MemoryTier,
}

/// Result of one bounded compaction step.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub struct CompactionStep {
    /// Entries visited this step.
    pub processed_u32: u32,
    /// Entries aged one tier this step.
    pub aged_u32: u32,
    /// Tombstone entries visited and preserved (untouched) this step.
    pub tombstones_preserved_u32: u32,
    /// Whether all entries have now been visited at least once.
    pub done: bool,
}

/// A cooperative background tier compactor.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BackgroundCompactor {
    entries: Vec<CompactorEntry>,
    cursor: usize,
    replay_link: ReplayCursor,
    transcript_anchor: StageBTranscriptHash32,
}

impl BackgroundCompactor {
    /// Create a compactor over a set of entries, carrying the replay cursor and
    /// the Stage B transcript anchor it is bound to (both preserved verbatim).
    #[must_use]
    pub fn new(
        entries: Vec<CompactorEntry>,
        replay_link: ReplayCursor,
        transcript_anchor: StageBTranscriptHash32,
    ) -> Self {
        Self {
            entries,
            cursor: 0,
            replay_link,
            transcript_anchor,
        }
    }

    /// The preserved replay cursor (compaction never mutates replay truth).
    #[must_use]
    pub const fn replay_link(&self) -> ReplayCursor {
        self.replay_link
    }

    /// The preserved Stage B transcript anchor.
    #[must_use]
    pub const fn transcript_anchor(&self) -> StageBTranscriptHash32 {
        self.transcript_anchor
    }

    /// Borrow the current entries (for inspection / verification).
    #[must_use]
    pub fn entries(&self) -> &[CompactorEntry] {
        &self.entries
    }

    /// Current resume cursor.
    #[must_use]
    pub const fn cursor(&self) -> usize {
        self.cursor
    }

    /// Whether every entry has been visited at least once in this pass.
    #[must_use]
    pub fn is_done(&self) -> bool {
        self.cursor >= self.entries.len()
    }

    /// Advance compaction by at most `max_items` entries from the resume cursor.
    /// Non-tombstone entries age one tier; tombstones are preserved untouched.
    /// Returns the per-step counts and whether the pass is complete. Stopping
    /// after any step and resuming later never reprocesses an entry.
    pub fn step(&mut self, max_items: u16) -> CompactionStep {
        let end = self
            .cursor
            .saturating_add(max_items as usize)
            .min(self.entries.len());
        let mut processed_u32: u32 = 0;
        let mut aged_u32: u32 = 0;
        let mut tombstones_preserved_u32: u32 = 0;
        for entry in &mut self.entries[self.cursor..end] {
            processed_u32 = processed_u32.saturating_add(1);
            if entry.tier.is_tombstone() {
                tombstones_preserved_u32 = tombstones_preserved_u32.saturating_add(1);
            } else if let Some(next) = entry.tier.next_aging_tier() {
                entry.tier = next;
                aged_u32 = aged_u32.saturating_add(1);
            }
        }
        self.cursor = end;
        CompactionStep {
            processed_u32,
            aged_u32,
            tombstones_preserved_u32,
            done: self.is_done(),
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    #![allow(clippy::expect_used)]
    #![allow(clippy::panic)]

    use super::*;
    use crate::stage_b_replay::stage_b_transcript_hash;

    fn anchor() -> StageBTranscriptHash32 {
        stage_b_transcript_hash(b"compactor-fixture-transcript")
    }

    fn entry(id: u64, tier: MemoryTier) -> CompactorEntry {
        CompactorEntry {
            id: MemoryId::new(id),
            tier,
        }
    }

    #[test]
    fn tier_transitions_follow_aging_order() {
        assert_eq!(MemoryTier::Recent.next_aging_tier(), Some(MemoryTier::Mid));
        assert_eq!(MemoryTier::Mid.next_aging_tier(), Some(MemoryTier::Ancient));
        assert_eq!(MemoryTier::Ancient.next_aging_tier(), None);
        assert_eq!(MemoryTier::DeletedTombstone.next_aging_tier(), None);
        assert!(CompactionPlan::new(MemoryTier::Recent, MemoryTier::Mid, 4, 4, 5).is_ok());
        assert_eq!(
            CompactionPlan::new(MemoryTier::Recent, MemoryTier::Ancient, 4, 4, 5),
            Err(CompactionError::IllegalTransition)
        );
        assert_eq!(
            CompactionPlan::new(MemoryTier::DeletedTombstone, MemoryTier::Ancient, 1, 0, 5),
            Err(CompactionError::TombstoneNotCompactable)
        );
    }

    #[test]
    fn stall_budget_bounds_work_per_step() {
        let entries = (0..5_u64).map(|i| entry(i, MemoryTier::Recent)).collect();
        let mut c = BackgroundCompactor::new(entries, ReplayCursor::start(), anchor());
        let s1 = c.step(2);
        assert_eq!(s1.processed_u32, 2);
        assert!(!s1.done);
        let s2 = c.step(2);
        assert_eq!(s2.processed_u32, 2);
        assert!(!s2.done);
        let s3 = c.step(2);
        assert_eq!(s3.processed_u32, 1);
        assert!(s3.done);
    }

    #[test]
    fn tombstone_is_preserved() {
        let entries = vec![
            entry(1, MemoryTier::Recent),
            entry(2, MemoryTier::DeletedTombstone),
        ];
        let mut c = BackgroundCompactor::new(entries, ReplayCursor::start(), anchor());
        let step = c.step(16);
        assert_eq!(step.tombstones_preserved_u32, 1);
        assert_eq!(step.aged_u32, 1);
        // The tombstone entry is unchanged; the recent entry aged to Mid.
        assert_eq!(c.entries()[0].tier, MemoryTier::Mid);
        assert_eq!(c.entries()[1].tier, MemoryTier::DeletedTombstone);
    }

    #[test]
    fn replay_link_and_transcript_preserved() {
        let cursor = ReplayCursor::from_replay(&[MemoryId::new(1), MemoryId::new(2)]);
        let transcript = anchor();
        let entries = (0..3_u64).map(|i| entry(i, MemoryTier::Recent)).collect();
        let mut c = BackgroundCompactor::new(entries, cursor, transcript);
        let _ = c.step(16);
        assert_eq!(
            c.replay_link(),
            cursor,
            "compaction must not mutate the replay cursor"
        );
        assert_eq!(
            c.transcript_anchor().as_bytes(),
            transcript.as_bytes(),
            "compaction must not mutate the transcript anchor"
        );
    }

    #[test]
    fn cancellation_safe_resume_visits_each_once() {
        let entries = (0..6_u64).map(|i| entry(i, MemoryTier::Recent)).collect();
        let mut c = BackgroundCompactor::new(entries, ReplayCursor::start(), anchor());
        let mut total_processed: u32 = 0;
        // Drive in irregular budgets, "cancelling" between each step.
        for budget in [1_u16, 3, 0, 2, 5] {
            let step = c.step(budget);
            total_processed = total_processed.saturating_add(step.processed_u32);
            if step.done {
                break;
            }
        }
        assert!(c.is_done());
        assert_eq!(
            total_processed, 6,
            "each entry visited exactly once across resumes"
        );
        // Every Recent entry has aged exactly one tier to Mid (no double-aging).
        assert!(c.entries().iter().all(|e| e.tier == MemoryTier::Mid));
    }
}
