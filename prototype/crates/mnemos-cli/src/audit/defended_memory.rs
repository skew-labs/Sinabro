//! Defended invariant memory (atom #527 · G.3.11).
//!
//! A move that does not break is not a failure — it is memory that lowers the
//! cost of the next read. [`DefendedInvariantMemory`] is the §3 record of an
//! explored-but-defended invariant: how many nodes were explored, how many were
//! defended, how many counterexamples were found, and a replay hash. The store
//! holds each defended invariant under a scope + expiry so the same dead end is
//! not re-explored within scope, while a stale (expired) or out-of-scope entry
//! does not suppress a fresh read. A defended invariant yields no finding and is
//! reward-neutral. This module performs no live action.
//!
//! Reuse (no reinvention): the scope/expiry replay idiom mirrors the Stage B
//! memory replay path; the reward-neutral outcome maps to the Stage E no-reward
//! labels (a defended invariant is never a positive training signal).

use crate::sha256_32;

/// §3 — the memory of an explored-but-defended invariant.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DefendedInvariantMemory {
    /// SHA-256 of the defended invariant.
    pub invariant_hash_32: [u8; 32],
    /// The number of search nodes explored.
    pub explored_nodes_u32: u32,
    /// The number of nodes that defended the invariant.
    pub defended_nodes_u32: u32,
    /// The number of counterexamples found (a finding path, not a defended one).
    pub counterexample_count_u32: u32,
    /// SHA-256 replay hint for the prior exploration.
    pub replay_hash_32: [u8; 32],
}

impl DefendedInvariantMemory {
    /// Whether this is a pure defended record (some node defended, none broke).
    #[must_use]
    pub const fn fully_defended(&self) -> bool {
        self.counterexample_count_u32 == 0 && self.defended_nodes_u32 > 0
    }

    /// A defended invariant is reward-neutral: it is never a positive reward (the
    /// Stage E no-reward labels) and never a finding. Always `true`.
    #[must_use]
    pub const fn reward_neutral() -> bool {
        true
    }
}

/// The scope an entry applies to (a repo + invariant family) and when it expires.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DefendedScope {
    /// SHA-256 of the scope (repo / protocol / invariant family).
    pub scope_hash_32: [u8; 32],
    /// The epoch at which the memory goes stale (must be re-explored).
    pub expiry_epoch_u64: u64,
}

/// One stored defended invariant under its scope.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct DefendedEntry {
    memory: DefendedInvariantMemory,
    scope: DefendedScope,
}

/// A store of defended invariants keyed by `(invariant, scope)`, with expiry.
#[derive(Clone, Debug, Default)]
pub struct DefendedInvariantStore {
    entries: Vec<DefendedEntry>,
}

impl DefendedInvariantStore {
    /// A new, empty store.
    #[must_use]
    pub fn new() -> Self {
        Self {
            entries: Vec::new(),
        }
    }

    /// Record a defended invariant under a scope.
    pub fn record(&mut self, memory: DefendedInvariantMemory, scope: DefendedScope) {
        self.entries.push(DefendedEntry { memory, scope });
    }

    /// The number of stored entries.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether the store is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Whether `(invariant, scope)` is a known dead end at `now_epoch`: stored,
    /// scope-matched, and not yet expired. A stale or out-of-scope entry returns
    /// `false` so the fresh read is not suppressed.
    #[must_use]
    pub fn is_known_dead_end(
        &self,
        invariant_hash_32: &[u8; 32],
        scope_hash_32: &[u8; 32],
        now_epoch_u64: u64,
    ) -> bool {
        self.entries.iter().any(|e| {
            e.memory.invariant_hash_32 == *invariant_hash_32
                && e.scope.scope_hash_32 == *scope_hash_32
                && now_epoch_u64 < e.scope.expiry_epoch_u64
        })
    }

    /// The replay hint for a stored `(invariant, scope)` entry, if present.
    #[must_use]
    pub fn replay_hint(
        &self,
        invariant_hash_32: &[u8; 32],
        scope_hash_32: &[u8; 32],
    ) -> Option<[u8; 32]> {
        self.entries
            .iter()
            .find(|e| {
                e.memory.invariant_hash_32 == *invariant_hash_32
                    && e.scope.scope_hash_32 == *scope_hash_32
            })
            .map(|e| e.memory.replay_hash_32)
    }
}

/// Build a defended-invariant memory, computing the replay hash from the
/// invariant + explored / defended / counterexample counts.
#[must_use]
pub fn defended(
    invariant_hash_32: [u8; 32],
    explored_nodes_u32: u32,
    defended_nodes_u32: u32,
    counterexample_count_u32: u32,
) -> DefendedInvariantMemory {
    let mut buf: Vec<u8> = Vec::with_capacity(44);
    buf.extend_from_slice(&invariant_hash_32);
    buf.extend_from_slice(&explored_nodes_u32.to_le_bytes());
    buf.extend_from_slice(&defended_nodes_u32.to_le_bytes());
    buf.extend_from_slice(&counterexample_count_u32.to_le_bytes());
    DefendedInvariantMemory {
        invariant_hash_32,
        explored_nodes_u32,
        defended_nodes_u32,
        counterexample_count_u32,
        replay_hash_32: sha256_32(&buf),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mem(inv: u8, counterexamples: u32) -> DefendedInvariantMemory {
        defended([inv; 32], 10, 9, counterexamples)
    }

    fn scope(s: u8, expiry: u64) -> DefendedScope {
        DefendedScope {
            scope_hash_32: [s; 32],
            expiry_epoch_u64: expiry,
        }
    }

    #[test]
    fn store_defended_known_dead_end() {
        let mut st = DefendedInvariantStore::new();
        st.record(mem(1, 0), scope(7, 100));
        assert!(st.is_known_dead_end(&[1u8; 32], &[7u8; 32], 50));
        assert_eq!(st.len(), 1);
        assert!(!st.is_empty());
    }

    #[test]
    fn stale_expiry_not_dead_end() {
        let mut st = DefendedInvariantStore::new();
        st.record(mem(1, 0), scope(7, 100));
        // now == expiry is already stale; later is stale too
        assert!(!st.is_known_dead_end(&[1u8; 32], &[7u8; 32], 100));
        assert!(!st.is_known_dead_end(&[1u8; 32], &[7u8; 32], 250));
    }

    #[test]
    fn scope_mismatch_not_dead_end() {
        let mut st = DefendedInvariantStore::new();
        st.record(mem(1, 0), scope(7, 100));
        assert!(!st.is_known_dead_end(&[1u8; 32], &[8u8; 32], 50));
    }

    #[test]
    fn replay_hint_present() {
        let mut st = DefendedInvariantStore::new();
        let m = mem(1, 0);
        st.record(m, scope(7, 100));
        assert_eq!(
            st.replay_hint(&[1u8; 32], &[7u8; 32]),
            Some(m.replay_hash_32)
        );
        assert_eq!(st.replay_hint(&[9u8; 32], &[7u8; 32]), None);
    }

    #[test]
    fn no_finding_reward_neutral() {
        let m = mem(1, 0);
        assert!(DefendedInvariantMemory::reward_neutral());
        assert!(m.fully_defended());
        // a counterexample path is not "fully defended"
        let broke = mem(1, 2);
        assert!(!broke.fully_defended());
    }
}
