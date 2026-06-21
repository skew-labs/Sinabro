//! memory intelligence / replay signal (atom #364 · E.1.13).
//!
//! Memory *content* is excluded by default — only replay hashes, tombstone
//! counts, recall metrics, redacted summaries, and didactic signals may enter.
//! The operational-memory axis is **not** reward eligibility: an operational
//! record is never reward-eligible; only a high-confidence didactic candidate
//! with content excluded and no deleted-resurrection may be. A record carrying a
//! `raw_content` field violates content exclusion and is not eligible. A
//! tombstoned id reappearing is a deleted-resurrection reject.
//!
//! The memory evidence is a Stage B/D surface, not one of the 21 sidecar kinds;
//! [`DietFileKind::InputContext`] is used only as the error-context tag.
use crate::diet_kind::{AtomDietKey, DietFileKind};
use crate::error::DietResult;
use crate::{as_object, opt_bool, opt_str, opt_u64, parse_json};

const CARRIER: DietFileKind = DietFileKind::InputContext;
const CONFIDENCE_FLOOR_BPS: u64 = 5000;

/// memory intelligence / replay signal.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub struct MemorySignal {
    /// The source atom.
    pub key: AtomDietKey,
    /// Replay anchor (`sha256` of the replay id/hash string, never content).
    pub replay_hash_32: [u8; 32],
    /// Tombstone (deletion) count.
    pub tombstone_count_u32: u32,
    /// Recall metric in milli-units (`0..=1000`).
    pub recall_metric_milli_u32: u32,
    /// The record is operational-memory class (not reward eligibility).
    pub is_operational: bool,
    /// The record is a didactic candidate (the only reward-shaped axis).
    pub is_didactic_candidate: bool,
    /// No raw memory content was present (content exclusion held).
    pub content_excluded: bool,
    /// A tombstoned id reappeared (deleted-resurrection reject).
    pub deleted_resurrection: bool,
    /// The signal confidence is below the floor — review/abstain, not reward.
    pub low_confidence_review: bool,
    /// Reward precondition: didactic candidate, content excluded, no
    /// resurrection, confident, and not operational.
    pub reward_eligible: bool,
}

/// Collect a [`MemorySignal`] from a memory-evidence JSON document.
pub fn collect(key: AtomDietKey, memory_json: &str) -> DietResult<MemorySignal> {
    let v = parse_json(CARRIER, memory_json)?;
    let obj = as_object(&v, CARRIER, "$root")?;

    let replay_hash_32 = match opt_str(obj, "replay_hash") {
        Some(s) => crate::sha256(s.as_bytes()),
        None => crate::sha256(b"none"),
    };
    let tombstone_count_u32 = opt_u64(obj, "tombstone_count")
        .unwrap_or(0)
        .min(u32::MAX as u64) as u32;
    let recall_metric_milli_u32 = opt_u64(obj, "recall_milli").unwrap_or(0).min(1000) as u32;
    let is_operational = opt_bool(obj, "operational").unwrap_or(false);
    let is_didactic_candidate = opt_bool(obj, "didactic_candidate").unwrap_or(false);
    let content_excluded = !obj.contains_key("raw_content");
    let deleted_resurrection = opt_bool(obj, "deleted_resurrection").unwrap_or(false);
    let low_confidence_review = opt_u64(obj, "confidence_bps").unwrap_or(0) < CONFIDENCE_FLOOR_BPS;

    let reward_eligible = is_didactic_candidate
        && content_excluded
        && !deleted_resurrection
        && !low_confidence_review
        && !is_operational;

    Ok(MemorySignal {
        key,
        replay_hash_32,
        tombstone_count_u32,
        recall_metric_milli_u32,
        is_operational,
        is_didactic_candidate,
        content_excluded,
        deleted_resurrection,
        low_confidence_review,
        reward_eligible,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::diet_kind::DietSourceStage;

    fn key() -> AtomDietKey {
        AtomDietKey::new(DietSourceStage::StageD, 364)
    }

    #[test]
    fn replay_pass_didactic_is_eligible() -> DietResult<()> {
        let doc = r#"{"replay_hash":"abc123","didactic_candidate":true,"confidence_bps":8000,"recall_milli":900}"#;
        let s = collect(key(), doc)?;
        assert_ne!(s.replay_hash_32, crate::sha256(b"none"));
        assert!(s.content_excluded);
        assert!(s.reward_eligible);
        assert_eq!(s.recall_metric_milli_u32, 900);
        Ok(())
    }

    #[test]
    fn deleted_resurrection_rejects() -> DietResult<()> {
        let doc =
            r#"{"didactic_candidate":true,"confidence_bps":9000,"deleted_resurrection":true}"#;
        let s = collect(key(), doc)?;
        assert!(s.deleted_resurrection);
        assert!(!s.reward_eligible);
        Ok(())
    }

    #[test]
    fn raw_content_fixture_violates_exclusion() -> DietResult<()> {
        let doc =
            r#"{"didactic_candidate":true,"confidence_bps":9000,"raw_content":"user said ..."}"#;
        let s = collect(key(), doc)?;
        assert!(!s.content_excluded);
        assert!(!s.reward_eligible);
        Ok(())
    }

    #[test]
    fn operational_axis_is_not_reward() -> DietResult<()> {
        let doc = r#"{"operational":true,"didactic_candidate":true,"confidence_bps":9000}"#;
        let s = collect(key(), doc)?;
        assert!(s.is_operational);
        assert!(!s.reward_eligible);
        Ok(())
    }

    #[test]
    fn low_confidence_is_review_not_reward() -> DietResult<()> {
        let doc = r#"{"didactic_candidate":true,"confidence_bps":1000}"#;
        let s = collect(key(), doc)?;
        assert!(s.low_confidence_review);
        assert!(!s.reward_eligible);
        Ok(())
    }

    #[test]
    fn tombstone_and_recall_parse() -> DietResult<()> {
        let doc = r#"{"tombstone_count":5,"recall_milli":1500}"#;
        let s = collect(key(), doc)?;
        assert_eq!(s.tombstone_count_u32, 5);
        // recall is clamped to the 0..=1000 milli range.
        assert_eq!(s.recall_metric_milli_u32, 1000);
        Ok(())
    }
}
