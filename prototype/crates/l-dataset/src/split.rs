//! Split / held-out leakage guard (`SplitAssignment`,
//! `TrainingSplit`).
//!
//! # Design
//!
//! The same task, repo, issue, diff lineage, or MURPHY tree cannot leak across
//! train / val / test / held-out. Every sample is keyed by a *leakage group
//! hash*; the split is a deterministic function of that hash, so all samples in
//! a group always land on the same side. A quarantined sample goes to the
//! quarantine split. [`verify_no_leakage`] proves, after assignment, that no
//! group straddles two splits.
//!
//! Reuses the dedup composite ([`crate::dedup::DedupKey::leakage_group`])
//! and the MURPHY node-set digest as group keys.
use crate::dedup::DedupKey;
use crate::diet_kind::AtomDietKey;
use crate::error::{DietError, DietResult};
use std::collections::BTreeMap;

/// Which split a sample is assigned to.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
#[repr(u8)]
pub enum TrainingSplit {
    /// Training split.
    Train = 1,
    /// Validation split.
    Validation = 2,
    /// Test split.
    Test = 3,
    /// Held-out split (never trained on).
    HeldOut = 4,
    /// Quarantine (excluded from all training/eval splits).
    Quarantine = 5,
}

impl TrainingSplit {
    /// Numeric discriminant.
    pub const fn as_u8(self) -> u8 {
        self as u8
    }

    /// Parse from a discriminant; `None` if not `1..=5`.
    pub const fn from_u8(v: u8) -> Option<Self> {
        match v {
            1 => Some(Self::Train),
            2 => Some(Self::Validation),
            3 => Some(Self::Test),
            4 => Some(Self::HeldOut),
            5 => Some(Self::Quarantine),
            _ => None,
        }
    }
}

/// A split assignment for one sample.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub struct SplitAssignment {
    /// The source atom.
    pub key: AtomDietKey,
    /// The assigned split.
    pub split: TrainingSplit,
    /// The leakage group this sample belongs to (its grouping key).
    pub leakage_group_hash_32: [u8; 32],
}

/// The leakage group key from a dedup composite (task/diff/command/failure/
/// lineage). Samples sharing this key never split apart.
pub fn group_key(dedup: &DedupKey) -> [u8; 32] {
    dedup.leakage_group()
}

/// The leakage group key from a MURPHY node-set digest: every sample drawn from
/// the same failure-attempt tree shares this key (so a tree cannot leak).
pub const fn murphy_group_key(nodes_hash_32: [u8; 32]) -> [u8; 32] {
    nodes_hash_32
}

/// Deterministically bucket a leakage group hash into a non-quarantine split
/// (70 train / 15 validation / 10 test / 5 held-out).
fn bucket(group: &[u8; 32]) -> TrainingSplit {
    let mut b = [0u8; 8];
    b.copy_from_slice(&group[0..8]);
    match u64::from_le_bytes(b) % 100 {
        0..=69 => TrainingSplit::Train,
        70..=84 => TrainingSplit::Validation,
        85..=94 => TrainingSplit::Test,
        _ => TrainingSplit::HeldOut,
    }
}

/// Assign a sample to a split. A quarantined sample goes to
/// [`TrainingSplit::Quarantine`]; otherwise the split is a deterministic
/// function of the leakage group hash, so the same group always co-locates.
pub fn assign(
    key: AtomDietKey,
    leakage_group_hash_32: [u8; 32],
    quarantine: bool,
) -> SplitAssignment {
    let split = if quarantine {
        TrainingSplit::Quarantine
    } else {
        bucket(&leakage_group_hash_32)
    };
    SplitAssignment {
        key,
        split,
        leakage_group_hash_32,
    }
}

/// Verify that no leakage group straddles two splits. Fail-closed: a group seen
/// with two different splits is a [`DietError::SplitLeakageDetected`].
pub fn verify_no_leakage(assignments: &[SplitAssignment]) -> DietResult<()> {
    let mut seen: BTreeMap<[u8; 32], TrainingSplit> = BTreeMap::new();
    for a in assignments {
        match seen.get(&a.leakage_group_hash_32) {
            Some(prev) if *prev != a.split => return Err(DietError::SplitLeakageDetected),
            _ => {
                seen.insert(a.leakage_group_hash_32, a.split);
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::diet_kind::DietSourceStage;

    fn key(atom: u16) -> AtomDietKey {
        AtomDietKey::new(DietSourceStage::Phase0, atom)
    }

    fn dedup(diff: u8) -> DedupKey {
        DedupKey {
            task_hash_32: [1u8; 32],
            diff_hash_32: [diff; 32],
            command_hash_32: [3u8; 32],
            failure_hash_32: [4u8; 32],
            lineage_hash_32: [5u8; 32],
        }
    }

    #[test]
    fn same_issue_groups_to_same_split() {
        // two different atoms, identical leakage group ⇒ same split.
        let g = crate::sha256(b"issue-1234");
        let a = assign(key(1), g, false);
        let b = assign(key(2), g, false);
        assert_eq!(a.split, b.split);
    }

    #[test]
    fn same_diff_groups_to_same_split() {
        let g = group_key(&dedup(7));
        let a = assign(key(1), g, false);
        let b = assign(key(2), g, false);
        assert_eq!(a.split, b.split);
        // a different diff lineage may bucket elsewhere but stays internally consistent.
        let g2 = group_key(&dedup(8));
        let c = assign(key(3), g2, false);
        let d = assign(key(4), g2, false);
        assert_eq!(c.split, d.split);
    }

    #[test]
    fn murphy_tree_groups_to_same_split() {
        let nodes_hash = crate::sha256(b"murphy-tree-nodes");
        let g = murphy_group_key(nodes_hash);
        let a = assign(key(1), g, false);
        let b = assign(key(2), g, false);
        assert_eq!(a.split, b.split);
        assert_eq!(g, nodes_hash);
    }

    #[test]
    fn quarantine_is_assigned() {
        let g = crate::sha256(b"anything");
        let a = assign(key(1), g, true);
        assert_eq!(a.split, TrainingSplit::Quarantine);
    }

    #[test]
    fn held_out_group_stays_together_no_leakage() -> DietResult<()> {
        // a single group, two samples ⇒ same split ⇒ no leakage.
        let g = crate::sha256(b"held-out-candidate");
        let a = assign(key(1), g, false);
        let b = assign(key(2), g, false);
        assert_eq!(a.split, b.split);
        verify_no_leakage(&[a, b])?;
        Ok(())
    }

    #[test]
    fn straddling_group_is_leakage() {
        let g = [9u8; 32];
        let a = SplitAssignment {
            key: key(1),
            split: TrainingSplit::Train,
            leakage_group_hash_32: g,
        };
        let b = SplitAssignment {
            key: key(2),
            split: TrainingSplit::Test,
            leakage_group_hash_32: g,
        };
        assert_eq!(
            verify_no_leakage(&[a, b]),
            Err(DietError::SplitLeakageDetected)
        );
    }

    #[test]
    fn split_is_deterministic_over_many_samples() {
        // proxy for "split 1M deterministic": assigning the same hashes twice
        // yields identical splits.
        for i in 0u32..2000 {
            let g = crate::sha256(&i.to_le_bytes());
            assert_eq!(
                assign(key(1), g, false).split,
                assign(key(2), g, false).split
            );
        }
    }

    #[test]
    fn training_split_round_trips() {
        for v in 1u8..=5 {
            assert_eq!(TrainingSplit::from_u8(v).map(TrainingSplit::as_u8), Some(v));
        }
        assert!(TrainingSplit::from_u8(6).is_none());
    }
}
