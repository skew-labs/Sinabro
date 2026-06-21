//! sample dedup index (atom #369 · E.1.18).
//!
//! Samples dedup by task, diff, command, failure, and source lineage — folded
//! into one composite `sha256`. A duplicate shares a *leakage group* (= the
//! composite), so a downstream splitter assigns every copy of a sample to the
//! same split and a duplicate can never leak across the held-out boundary. The
//! index is a streaming `BTreeSet` of 32-byte composites: it bounds memory to
//! one hash per sample (raw content is never materialized), so a 1M-sample dedup
//! plan holds ~32 MB of composites, not the corpus, and iterates deterministically.
use std::collections::BTreeSet;

/// The five-axis dedup key for one sample. Two samples are exact duplicates iff
/// all five axes match (same [`Self::composite`]).
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub struct DedupKey {
    /// `sha256` of the task / issue identity.
    pub task_hash_32: [u8; 32],
    /// `sha256` of the diff.
    pub diff_hash_32: [u8; 32],
    /// `sha256` of the command(s).
    pub command_hash_32: [u8; 32],
    /// `sha256` of the failure signature.
    pub failure_hash_32: [u8; 32],
    /// `sha256` of the source lineage (see `provenance::ProvenanceChain`).
    pub lineage_hash_32: [u8; 32],
}

impl DedupKey {
    /// Construct a dedup key from its five axis hashes.
    pub const fn new(
        task_hash_32: [u8; 32],
        diff_hash_32: [u8; 32],
        command_hash_32: [u8; 32],
        failure_hash_32: [u8; 32],
        lineage_hash_32: [u8; 32],
    ) -> Self {
        Self {
            task_hash_32,
            diff_hash_32,
            command_hash_32,
            failure_hash_32,
            lineage_hash_32,
        }
    }

    /// The composite `sha256` over all five axes — the exact-duplicate identity.
    pub fn composite(&self) -> [u8; 32] {
        let mut buf = [0u8; 160];
        buf[0..32].copy_from_slice(&self.task_hash_32);
        buf[32..64].copy_from_slice(&self.diff_hash_32);
        buf[64..96].copy_from_slice(&self.command_hash_32);
        buf[96..128].copy_from_slice(&self.failure_hash_32);
        buf[128..160].copy_from_slice(&self.lineage_hash_32);
        crate::sha256(&buf)
    }

    /// The leakage group a sample belongs to (its composite). Every exact copy
    /// shares this group so a splitter keeps them on the same side of held-out.
    pub fn leakage_group(&self) -> [u8; 32] {
        self.composite()
    }

    /// A *near* duplicate: same task and same failure, but a different composite
    /// (e.g. a re-attempt with a different diff/command). Not an exact duplicate.
    pub fn is_near_duplicate(&self, other: &DedupKey) -> bool {
        self.task_hash_32 == other.task_hash_32
            && self.failure_hash_32 == other.failure_hash_32
            && self.composite() != other.composite()
    }
}

/// A streaming dedup index: a set of 32-byte composites. Memory is bounded to one
/// hash per inserted sample; the corpus is never materialized.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct DedupIndex {
    seen: BTreeSet<[u8; 32]>,
}

impl DedupIndex {
    /// An empty index.
    pub fn new() -> Self {
        Self::default()
    }

    /// Insert a sample. Returns `true` if it was new, `false` if it duplicates an
    /// already-seen composite.
    pub fn insert(&mut self, key: &DedupKey) -> bool {
        self.seen.insert(key.composite())
    }

    /// Whether a sample's composite is already present.
    pub fn contains(&self, key: &DedupKey) -> bool {
        self.seen.contains(&key.composite())
    }

    /// Number of distinct composites held.
    pub fn len(&self) -> usize {
        self.seen.len()
    }

    /// Whether the index is empty.
    pub fn is_empty(&self) -> bool {
        self.seen.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dk(task: u8, diff: u8, cmd: u8, fail: u8, lineage: u8) -> DedupKey {
        DedupKey::new([task; 32], [diff; 32], [cmd; 32], [fail; 32], [lineage; 32])
    }

    #[test]
    fn exact_duplicate_is_rejected_on_second_insert() {
        let mut idx = DedupIndex::new();
        let k = dk(1, 2, 3, 4, 5);
        assert!(idx.insert(&k));
        assert!(!idx.insert(&k));
        assert!(idx.contains(&k));
        assert_eq!(idx.len(), 1);
    }

    #[test]
    fn near_duplicate_same_task_and_failure_different_diff() {
        let a = dk(1, 2, 3, 9, 5);
        let b = dk(1, 7, 8, 9, 5); // same task(1) + failure(9), different diff/cmd
        assert!(a.is_near_duplicate(&b));
        // both are kept (not exact duplicates).
        let mut idx = DedupIndex::new();
        assert!(idx.insert(&a));
        assert!(idx.insert(&b));
        assert_eq!(idx.len(), 2);
    }

    #[test]
    fn same_issue_different_attempt_is_not_exact_duplicate() {
        let attempt1 = dk(1, 2, 3, 4, 5);
        let attempt2 = dk(1, 2, 9, 4, 5); // same task, different command (re-attempt)
        let mut idx = DedupIndex::new();
        assert!(idx.insert(&attempt1));
        assert!(idx.insert(&attempt2));
        assert_eq!(idx.len(), 2);
    }

    #[test]
    fn leakage_group_is_shared_by_exact_copies() {
        let a = dk(1, 2, 3, 4, 5);
        let copy = dk(1, 2, 3, 4, 5);
        assert_eq!(a.leakage_group(), copy.leakage_group());
        let other = dk(1, 2, 3, 4, 6); // different lineage
        assert_ne!(a.leakage_group(), other.leakage_group());
    }

    #[test]
    fn streaming_index_is_bounded_and_deterministic_at_100k() {
        const N: u32 = 100_000;
        let mut idx = DedupIndex::new();
        for i in 0..N {
            let h = crate::sha256(&i.to_le_bytes());
            let k = DedupKey::new(h, h, h, h, h);
            assert!(idx.insert(&k));
        }
        assert_eq!(idx.len(), N as usize);
        // re-inserting any earlier sample is a duplicate.
        let h0 = crate::sha256(&0u32.to_le_bytes());
        assert!(!idx.insert(&DedupKey::new(h0, h0, h0, h0, h0)));
    }
}
