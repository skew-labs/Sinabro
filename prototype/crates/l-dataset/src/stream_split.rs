//! S1/S2 stream splitter (atom #367 · E.1.16, §4.3 `StreamKind`,
//! `S1GroundTruthRecord`, `S2NarrativeRecord`).
//!
//! Compiler / test / prover / gas evidence is **S1 ground truth**; self-report,
//! explanation, approval text, and verdict prose are **S2 narrative**. The split
//! reuses the file-kind partition from `atom_record` (#348): only the
//! S1-ground-truth stream maps to [`StreamKind::S1GroundTruth`]; narrative,
//! privacy, and trajectory streams all map to [`StreamKind::S2Narrative`].
//!
//! **S2 reward is type-impossible.** [`S2NarrativeRecord::new`] takes no reward
//! argument and always stores [`RewardEligibility::NoRewardNarrative`]; there is
//! no constructor or setter that can make an S2 record reward-eligible.
use crate::atom_record::{DietStream, stream_of};
use crate::diet_kind::{AtomDietKey, DietFileKind};

/// The two training streams (§4.3).
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
#[repr(u8)]
pub enum StreamKind {
    /// Verifiable execution ground truth (compiler/test/prover/gas evidence).
    S1GroundTruth = 1,
    /// Narrative / self-report / approval / verdict prose.
    S2Narrative = 2,
}

impl StreamKind {
    /// Numeric discriminant (`1..=2`).
    pub const fn as_u8(self) -> u8 {
        self as u8
    }

    /// Parse from a discriminant; `None` if not `1..=2`.
    pub const fn from_u8(v: u8) -> Option<Self> {
        match v {
            1 => Some(Self::S1GroundTruth),
            2 => Some(Self::S2Narrative),
            _ => None,
        }
    }
}

/// Reward eligibility for a stream record (§4.3). Only S1 may ever be
/// [`Self::Eligible`]; S2 records are constructed strictly non-eligible.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
#[repr(u8)]
pub enum RewardEligibility {
    /// S1 evidence that may earn reward (subject to downstream nullifiers).
    Eligible = 1,
    /// Narrative content — never reward by type.
    NoRewardNarrative = 2,
    /// S1-shaped but not yet reverified — queued, not rewarded.
    NoRewardUnverified = 3,
    /// Blocked by a privacy reject.
    NoRewardPrivacy = 4,
    /// Failure masked by infrastructure, not the model.
    NoRewardInfra = 5,
}

impl RewardEligibility {
    /// Numeric discriminant (`1..=5`).
    pub const fn as_u8(self) -> u8 {
        self as u8
    }

    /// Parse from a discriminant; `None` if not `1..=5`.
    pub const fn from_u8(v: u8) -> Option<Self> {
        match v {
            1 => Some(Self::Eligible),
            2 => Some(Self::NoRewardNarrative),
            3 => Some(Self::NoRewardUnverified),
            4 => Some(Self::NoRewardPrivacy),
            5 => Some(Self::NoRewardInfra),
            _ => None,
        }
    }

    /// Whether this eligibility actually permits reward.
    pub const fn is_eligible(self) -> bool {
        matches!(self, Self::Eligible)
    }
}

/// The S1/S2 stream a file kind belongs to: the `atom_record` S1-ground-truth
/// stream is S1; every other stream (narrative, privacy, trajectory) is S2.
pub const fn stream_kind_of(kind: DietFileKind) -> StreamKind {
    match stream_of(kind) {
        DietStream::S1GroundTruth => StreamKind::S1GroundTruth,
        _ => StreamKind::S2Narrative,
    }
}

/// An S1 ground-truth record (§4.3).
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub struct S1GroundTruthRecord {
    /// The source atom.
    pub key: AtomDietKey,
    /// `sha256` anchor of the repair trace.
    pub repair_hash_32: [u8; 32],
    /// `sha256` anchor of the measurement trace.
    pub measure_hash_32: [u8; 32],
    /// Reward eligibility (may be [`RewardEligibility::Eligible`]).
    pub reward: RewardEligibility,
}

impl S1GroundTruthRecord {
    /// Construct an S1 record with an explicit eligibility.
    pub const fn new(
        key: AtomDietKey,
        repair_hash_32: [u8; 32],
        measure_hash_32: [u8; 32],
        reward: RewardEligibility,
    ) -> Self {
        Self {
            key,
            repair_hash_32,
            measure_hash_32,
            reward,
        }
    }

    /// Construct a reward-eligible S1 record (downstream nullifiers still apply).
    pub const fn eligible(
        key: AtomDietKey,
        repair_hash_32: [u8; 32],
        measure_hash_32: [u8; 32],
    ) -> Self {
        Self::new(
            key,
            repair_hash_32,
            measure_hash_32,
            RewardEligibility::Eligible,
        )
    }
}

/// An S2 narrative record (§4.3). Its reward is fixed
/// [`RewardEligibility::NoRewardNarrative`] by construction.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub struct S2NarrativeRecord {
    /// The source atom.
    pub key: AtomDietKey,
    /// `sha256` anchor of the narrative content (hashed, never raw).
    pub narrative_hash_32: [u8; 32],
    /// Always [`RewardEligibility::NoRewardNarrative`].
    pub reward: RewardEligibility,
}

impl S2NarrativeRecord {
    /// Construct an S2 record. There is **no** way to make it reward-eligible:
    /// the reward is fixed to [`RewardEligibility::NoRewardNarrative`].
    pub const fn new(key: AtomDietKey, narrative_hash_32: [u8; 32]) -> Self {
        Self {
            key,
            narrative_hash_32,
            reward: RewardEligibility::NoRewardNarrative,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::diet_kind::DietSourceStage;

    fn key() -> AtomDietKey {
        AtomDietKey::new(DietSourceStage::StageD, 367)
    }

    #[test]
    fn s1_command_evidence_routes_to_s1() {
        for k in [
            DietFileKind::CommandManifest,
            DietFileKind::GateResults,
            DietFileKind::TestResults,
            DietFileKind::DenyAudit,
        ] {
            assert_eq!(stream_kind_of(k), StreamKind::S1GroundTruth);
        }
    }

    #[test]
    fn s2_verdict_and_narrative_route_to_s2() {
        for k in [
            DietFileKind::RewardLabels,
            DietFileKind::SftChat,
            DietFileKind::EvalSummary,
            DietFileKind::HumanReview,
            DietFileKind::PrivacyReport,
            DietFileKind::ApprovalEvents,
        ] {
            assert_eq!(stream_kind_of(k), StreamKind::S2Narrative);
        }
    }

    #[test]
    fn mixed_record_split_partitions_all_21() {
        let mut s1 = 0;
        let mut s2 = 0;
        for k in DietFileKind::ALL {
            match stream_kind_of(k) {
                StreamKind::S1GroundTruth => s1 += 1,
                StreamKind::S2Narrative => s2 += 1,
            }
        }
        // 8 S1-ground-truth kinds; the other 13 (narrative+privacy+trajectory) → S2.
        assert_eq!((s1, s2), (8, 13));
    }

    #[test]
    fn s2_reward_is_type_impossible() {
        let s2 = S2NarrativeRecord::new(key(), [1u8; 32]);
        assert_eq!(s2.reward, RewardEligibility::NoRewardNarrative);
        assert!(!s2.reward.is_eligible());
    }

    #[test]
    fn s1_can_be_eligible_or_not() {
        let elig = S1GroundTruthRecord::eligible(key(), [2u8; 32], [3u8; 32]);
        assert!(elig.reward.is_eligible());
        let unver = S1GroundTruthRecord::new(
            key(),
            [2u8; 32],
            [3u8; 32],
            RewardEligibility::NoRewardUnverified,
        );
        assert!(!unver.reward.is_eligible());
    }

    #[test]
    fn reward_eligibility_round_trips() {
        for v in 1u8..=5 {
            assert_eq!(
                RewardEligibility::from_u8(v).map(RewardEligibility::as_u8),
                Some(v)
            );
        }
        assert_eq!(RewardEligibility::from_u8(0), None);
        assert_eq!(RewardEligibility::from_u8(6), None);
    }
}
