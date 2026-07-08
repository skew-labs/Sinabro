//! Stage G SFT-smoke unlock packet.
//!
//! # Rationale
//!
//! The unlock packet is the single gate between a *dataset* and a *training run*.
//! [`StageGUnlockPacket::sft_smoke_ready`] can be `true` only when **every**
//! precondition is green: PII zero, the S1/S2 split is consistent, the shard
//! hashes exist, the dataset card exists, the evidence bundle exists, the
//! didactic-signal gate is green, and the self-evolution-candidate schema gate is
//! green. Two flags can **never** be flipped here, regardless of input:
//! `grpo_locked` and `self_evolution_promotion_locked` are hard-coded `true`.
//! GRPO and self-evolution promotion wait for an explicit Stage G decision that
//! does not exist in this crate.
use crate::hex32_encode;

/// The preconditions that must all be green before the Stage G SFT smoke unlocks.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub struct UnlockPreconditions {
    /// The dataset passed PII-zero.
    pub pii_zero: bool,
    /// The S1/S2 split is internally consistent (no leakage).
    pub split_ok: bool,
    /// Shard content hashes are present.
    pub shard_hashes_present: bool,
    /// The dataset card is present.
    pub dataset_card_present: bool,
    /// The evidence-lake bundle is present.
    pub evidence_bundle_present: bool,
    /// The didactic-signal gate is green.
    pub didactic_signal_ok: bool,
    /// The self-evolution-candidate schema gate is green.
    pub self_evolution_candidate_schema_ok: bool,
    /// The context-quality + harness-quality signal schema gate is green.
    pub context_harness_signal_ok: bool,
}

impl UnlockPreconditions {
    /// Whether *every* precondition is green (the unlock requirement).
    pub const fn all_green(&self) -> bool {
        self.pii_zero
            && self.split_ok
            && self.shard_hashes_present
            && self.dataset_card_present
            && self.evidence_bundle_present
            && self.didactic_signal_ok
            && self.self_evolution_candidate_schema_ok
            && self.context_harness_signal_ok
    }
}

/// A Stage G unlock packet.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub struct StageGUnlockPacket {
    /// `true` only when every [`UnlockPreconditions`] is green.
    pub sft_smoke_ready: bool,
    /// Always `true` in Stage E — GRPO export stays locked.
    pub grpo_locked: bool,
    /// The `sha256` of the dataset card the packet pins.
    pub dataset_card_hash_32: [u8; 32],
    /// The combined `sha256` of the shard set the packet pins.
    pub shards_hash_32: [u8; 32],
    /// The evidence-bundle merkle root the packet pins.
    pub evidence_bundle_root_32: [u8; 32],
    /// Always `true` in Stage E — self-evolution promotion stays locked.
    pub self_evolution_promotion_locked: bool,
}

impl StageGUnlockPacket {
    /// Render the packet as canonical JSON (hashes as lower-hex, fixed key
    /// order). Hand-formatted for a deterministic, serializer-independent layout
    /// so the on-disk `stage_g_unlock.json` artifact byte-matches this output.
    pub fn to_json(&self) -> String {
        format!(
            "{{\"sft_smoke_ready\":{},\"grpo_locked\":{},\"dataset_card_hash\":\"{}\",\"shards_hash\":\"{}\",\"evidence_bundle_root\":\"{}\",\"self_evolution_promotion_locked\":{}}}",
            self.sft_smoke_ready,
            self.grpo_locked,
            hex32_encode(&self.dataset_card_hash_32),
            hex32_encode(&self.shards_hash_32),
            hex32_encode(&self.evidence_bundle_root_32),
            self.self_evolution_promotion_locked,
        )
    }
}

/// Compute the unlock packet. `sft_smoke_ready` is the AND of all preconditions;
/// `grpo_locked` and `self_evolution_promotion_locked` are hard-coded `true` and
/// cannot be flipped by any input.
pub fn unlock(
    pre: UnlockPreconditions,
    dataset_card_hash_32: [u8; 32],
    shards_hash_32: [u8; 32],
    evidence_bundle_root_32: [u8; 32],
) -> StageGUnlockPacket {
    StageGUnlockPacket {
        sft_smoke_ready: pre.all_green(),
        grpo_locked: true,
        dataset_card_hash_32,
        shards_hash_32,
        evidence_bundle_root_32,
        self_evolution_promotion_locked: true,
    }
}

/// The conservative Stage E unlock packet. At the Stage E definition of done the
/// schema gates are green — PII-zero, the S1/S2 split, the dataset card, the
/// didactic-signal schema, the context/harness-signal schema, and the
/// self-evolution-candidate schema are all present — but **no corpus shard or
/// evidence bundle has been materialized** (`shard_hashes_present` and
/// `evidence_bundle_present` stay `false`), so `sft_smoke_ready` stays `false`
/// and corpus materialization is deferred to Stage G. Both locks remain `true`.
pub fn stage_e_locked(dataset_card_hash_32: [u8; 32]) -> StageGUnlockPacket {
    let pre = UnlockPreconditions {
        pii_zero: true,
        split_ok: true,
        shard_hashes_present: false,
        dataset_card_present: true,
        evidence_bundle_present: false,
        didactic_signal_ok: true,
        self_evolution_candidate_schema_ok: true,
        context_harness_signal_ok: true,
    };
    unlock(pre, dataset_card_hash_32, [0u8; 32], [0u8; 32])
}

#[cfg(test)]
mod tests {
    use super::*;

    fn all_green() -> UnlockPreconditions {
        UnlockPreconditions {
            pii_zero: true,
            split_ok: true,
            shard_hashes_present: true,
            dataset_card_present: true,
            evidence_bundle_present: true,
            didactic_signal_ok: true,
            self_evolution_candidate_schema_ok: true,
            context_harness_signal_ok: true,
        }
    }

    #[test]
    fn sft_ready_when_all_green() {
        let p = unlock(all_green(), [1; 32], [2; 32], [3; 32]);
        assert!(p.sft_smoke_ready);
    }

    #[test]
    fn missing_privacy_blocks_unlock() {
        let mut pre = all_green();
        pre.pii_zero = false;
        assert!(!unlock(pre, [1; 32], [2; 32], [3; 32]).sft_smoke_ready);
    }

    #[test]
    fn missing_card_blocks_unlock() {
        let mut pre = all_green();
        pre.dataset_card_present = false;
        assert!(!unlock(pre, [1; 32], [2; 32], [3; 32]).sft_smoke_ready);
    }

    #[test]
    fn missing_evidence_bundle_blocks_unlock() {
        let mut pre = all_green();
        pre.evidence_bundle_present = false;
        assert!(!unlock(pre, [1; 32], [2; 32], [3; 32]).sft_smoke_ready);
    }

    #[test]
    fn missing_didactic_signal_blocks_unlock() {
        let mut pre = all_green();
        pre.didactic_signal_ok = false;
        assert!(!unlock(pre, [1; 32], [2; 32], [3; 32]).sft_smoke_ready);
    }

    #[test]
    fn missing_candidate_schema_blocks_unlock() {
        let mut pre = all_green();
        pre.self_evolution_candidate_schema_ok = false;
        assert!(!unlock(pre, [1; 32], [2; 32], [3; 32]).sft_smoke_ready);
    }

    #[test]
    fn grpo_locked_is_always_true() {
        // even with every precondition green, GRPO stays locked.
        assert!(unlock(all_green(), [1; 32], [2; 32], [3; 32]).grpo_locked);
        let mut pre = all_green();
        pre.pii_zero = false;
        assert!(unlock(pre, [1; 32], [2; 32], [3; 32]).grpo_locked);
    }

    #[test]
    fn self_evolution_promotion_is_always_locked() {
        assert!(unlock(all_green(), [1; 32], [2; 32], [3; 32]).self_evolution_promotion_locked);
    }

    #[test]
    fn stage_e_packet_is_conservative_and_locked() {
        let p = stage_e_locked([9; 32]);
        assert!(!p.sft_smoke_ready);
        assert!(p.grpo_locked);
        assert!(p.self_evolution_promotion_locked);
        assert_eq!(p.dataset_card_hash_32, [9; 32]);
        assert_eq!(p.shards_hash_32, [0; 32]);
    }

    #[test]
    fn json_round_trips_fields() {
        let p = stage_e_locked([0xAB; 32]);
        let j = p.to_json();
        assert!(j.contains("\"sft_smoke_ready\":false"));
        assert!(j.contains("\"grpo_locked\":true"));
        assert!(j.contains("\"self_evolution_promotion_locked\":true"));
        assert!(j.contains(&hex32_encode(&[0xAB; 32])));
    }

    #[test]
    fn on_disk_unlock_json_matches_code() {
        // The committed datasets/stage_e/stage_g_unlock.json must byte-match the
        // packet the code emits for the canonical card — compile-time bound.
        let card_hash = crate::export::card::stage_e_v0().card_hash();
        let packet = stage_e_locked(card_hash);
        assert_eq!(
            packet.to_json(),
            include_str!("../../../../../datasets/stage_e/stage_g_unlock.json").trim_end()
        );
    }
}
