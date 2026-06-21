//! ground-truth reverify scheduler (atom #368 · E.1.17).
//!
//! Unverified high-value S1 samples are *queued*, not rewarded. Only a
//! [`RewardEligibility::NoRewardUnverified`] sample is a queue candidate. A live
//! / on-chain / destructive command (#366) or commerce-shaped data always
//! requires manual approval and is recorded as skipped/quarantined — never run
//! by Stage E. Only a replayable candidate is actually queued for a future,
//! separately-authorized rerun. The finalized queue order is deterministic
//! regardless of insertion order, so a 100k-sample queue is reproducible.
use crate::diet_kind::AtomDietKey;
use crate::reverify::ReplayClass;
use crate::stream_split::RewardEligibility;

/// The scheduling decision for a queue candidate.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
#[repr(u8)]
pub enum QueueDecision {
    /// Queued for a future authorized rerun (replayable, public).
    Queued = 1,
    /// Skipped: a live / on-chain command (manual approval required).
    SkippedLive = 2,
    /// Skipped: a destructive command (manual approval required).
    SkippedDestructive = 3,
    /// Skipped: commerce-shaped data (quarantined).
    SkippedCommerce = 4,
    /// Held: the original run was infra-masked.
    InfraHeld = 5,
}

impl QueueDecision {
    /// Numeric discriminant (`1..=5`).
    pub const fn as_u8(self) -> u8 {
        self as u8
    }
}

/// One scheduled reverify entry.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub struct ReverifyQueueEntry {
    /// The source atom.
    pub key: AtomDietKey,
    /// `sha256` of the command to (maybe) replay.
    pub command_hash_32: [u8; 32],
    /// The scheduling decision.
    pub decision: QueueDecision,
}

/// A deterministic reverify queue for S1 no-reward / pending samples.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ReverifyQueue {
    entries: Vec<ReverifyQueueEntry>,
}

impl ReverifyQueue {
    /// An empty queue.
    pub fn new() -> Self {
        Self::default()
    }

    /// Number of recorded entries.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether the queue is empty.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// The recorded entries (deterministic order after [`Self::finalize`]).
    pub fn entries(&self) -> &[ReverifyQueueEntry] {
        &self.entries
    }

    /// Only an unverified S1 sample is a queue candidate; everything else
    /// (already eligible, narrative, privacy-blocked, infra) is not queued.
    pub const fn is_queue_candidate(eligibility: RewardEligibility) -> bool {
        matches!(eligibility, RewardEligibility::NoRewardUnverified)
    }

    /// Decide how to schedule a candidate by replay class and commerce shape.
    /// Commerce-shaped data is quarantined before any replay consideration.
    pub const fn decide(replay: ReplayClass, commerce_shaped: bool) -> QueueDecision {
        if commerce_shaped {
            QueueDecision::SkippedCommerce
        } else {
            match replay {
                ReplayClass::Replayable => QueueDecision::Queued,
                ReplayClass::InfraMasked => QueueDecision::InfraHeld,
                ReplayClass::LiveDenied => QueueDecision::SkippedLive,
                ReplayClass::DestructiveDenied => QueueDecision::SkippedDestructive,
            }
        }
    }

    /// Record a candidate's scheduling decision. Returns `true` if the sample was
    /// a candidate (and an entry was recorded), `false` otherwise.
    pub fn enqueue_candidate(
        &mut self,
        key: AtomDietKey,
        eligibility: RewardEligibility,
        replay: ReplayClass,
        command_hash_32: [u8; 32],
        commerce_shaped: bool,
    ) -> bool {
        if !Self::is_queue_candidate(eligibility) {
            return false;
        }
        self.entries.push(ReverifyQueueEntry {
            key,
            command_hash_32,
            decision: Self::decide(replay, commerce_shaped),
        });
        true
    }

    /// Sort the queue into its canonical, insertion-order-independent order
    /// (by source stage, atom number, command hash, then decision).
    pub fn finalize(&mut self) {
        self.entries.sort_by(|a, b| {
            (
                a.key.source.as_u8(),
                a.key.atom_u16,
                a.command_hash_32,
                a.decision.as_u8(),
            )
                .cmp(&(
                    b.key.source.as_u8(),
                    b.key.atom_u16,
                    b.command_hash_32,
                    b.decision.as_u8(),
                ))
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::diet_kind::DietSourceStage;

    fn key(atom: u16) -> AtomDietKey {
        AtomDietKey::new(DietSourceStage::StageD, atom)
    }

    #[test]
    fn replayable_unverified_is_queued() {
        let mut q = ReverifyQueue::new();
        let enq = q.enqueue_candidate(
            key(368),
            RewardEligibility::NoRewardUnverified,
            ReplayClass::Replayable,
            [1u8; 32],
            false,
        );
        assert!(enq);
        assert_eq!(q.len(), 1);
        assert_eq!(q.entries()[0].decision, QueueDecision::Queued);
    }

    #[test]
    fn move_test_rerun_is_queued() {
        assert_eq!(
            ReverifyQueue::decide(ReplayClass::Replayable, false),
            QueueDecision::Queued
        );
    }

    #[test]
    fn live_command_is_skipped() {
        assert_eq!(
            ReverifyQueue::decide(ReplayClass::LiveDenied, false),
            QueueDecision::SkippedLive
        );
    }

    #[test]
    fn commerce_shaped_is_skipped_before_replay() {
        // commerce shape quarantines even a replayable command.
        assert_eq!(
            ReverifyQueue::decide(ReplayClass::Replayable, true),
            QueueDecision::SkippedCommerce
        );
    }

    #[test]
    fn infra_masked_is_held() {
        assert_eq!(
            ReverifyQueue::decide(ReplayClass::InfraMasked, false),
            QueueDecision::InfraHeld
        );
    }

    #[test]
    fn non_candidate_eligibility_is_not_queued() {
        let mut q = ReverifyQueue::new();
        for elig in [
            RewardEligibility::Eligible,
            RewardEligibility::NoRewardNarrative,
            RewardEligibility::NoRewardPrivacy,
            RewardEligibility::NoRewardInfra,
        ] {
            assert!(!q.enqueue_candidate(key(1), elig, ReplayClass::Replayable, [0u8; 32], false));
        }
        assert!(q.is_empty());
    }

    #[test]
    fn queue_is_deterministic_at_100k_regardless_of_insertion_order() {
        const N: u32 = 100_000;
        let mut forward = ReverifyQueue::new();
        for i in 0..N {
            forward.enqueue_candidate(
                key((i % 60000) as u16),
                RewardEligibility::NoRewardUnverified,
                ReplayClass::Replayable,
                crate::sha256(&i.to_le_bytes()),
                false,
            );
        }
        let mut reverse = ReverifyQueue::new();
        for i in (0..N).rev() {
            reverse.enqueue_candidate(
                key((i % 60000) as u16),
                RewardEligibility::NoRewardUnverified,
                ReplayClass::Replayable,
                crate::sha256(&i.to_le_bytes()),
                false,
            );
        }
        forward.finalize();
        reverse.finalize();
        assert_eq!(forward.len(), N as usize);
        assert_eq!(forward.entries(), reverse.entries());
    }
}
