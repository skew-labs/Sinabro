//! Training-sidecar parsers: SFT chat, preference pairs, reward labels, eval
//! summary (atom #347 · E.0.16).
//!
//! Sidecar-provided labels are *suggestions* until Stage E recomputes
//! eligibility. Self-reported reward is parsed for provenance but **quarantined**
//! — its `reward_eligible` is always `false` in E-WP-01; a later WorkPackage
//! grants eligibility only after an S1 reverify.
use crate::diet_kind::DietFileKind;
use crate::error::{DietError, DietResult};
use crate::{as_object, parse_json};
use serde_json::Value;

/// SFT corpus summary.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub struct SftSummary {
    /// Number of chats.
    pub chats_u32: u32,
    /// Total turns across all chats.
    pub turns_u32: u32,
}

/// Parse `sft_chat.jsonl`; each record needs a `turns` array whose entries have
/// `role` and `content`.
pub fn parse_sft_chat(text: &str) -> DietResult<SftSummary> {
    const KIND: DietFileKind = DietFileKind::SftChat;
    let mut chats = 0u32;
    let mut turns = 0u32;
    let mut rec = 0u32;
    for line in text.lines() {
        if line.trim().is_empty() {
            continue;
        }
        rec = rec.saturating_add(1);
        let v: Value = serde_json::from_str(line).map_err(|_| DietError::MalformedJsonl {
            kind: KIND,
            record_u32: rec,
        })?;
        let obj = v.as_object().ok_or(DietError::MalformedJsonl {
            kind: KIND,
            record_u32: rec,
        })?;
        let t = obj
            .get("turns")
            .and_then(|x| x.as_array())
            .ok_or(DietError::MissingField {
                kind: KIND,
                field: "turns",
            })?;
        for turn in t {
            let to = turn.as_object().ok_or(DietError::MalformedJsonl {
                kind: KIND,
                record_u32: rec,
            })?;
            if !to.contains_key("role") || !to.contains_key("content") {
                return Err(DietError::MissingField {
                    kind: KIND,
                    field: "role|content",
                });
            }
            turns = turns.saturating_add(1);
        }
        chats = chats.saturating_add(1);
    }
    Ok(SftSummary {
        chats_u32: chats,
        turns_u32: turns,
    })
}

/// Count `preference_pairs.jsonl` records; each needs `chosen` and `rejected`.
pub fn count_preference_pairs(text: &str) -> DietResult<u32> {
    const KIND: DietFileKind = DietFileKind::PreferencePairs;
    let mut n = 0u32;
    let mut rec = 0u32;
    for line in text.lines() {
        if line.trim().is_empty() {
            continue;
        }
        rec = rec.saturating_add(1);
        let v: Value = serde_json::from_str(line).map_err(|_| DietError::MalformedJsonl {
            kind: KIND,
            record_u32: rec,
        })?;
        let obj = v.as_object().ok_or(DietError::MalformedJsonl {
            kind: KIND,
            record_u32: rec,
        })?;
        if !obj.contains_key("chosen") || !obj.contains_key("rejected") {
            return Err(DietError::MissingField {
                kind: KIND,
                field: "chosen|rejected",
            });
        }
        n = n.saturating_add(1);
    }
    Ok(n)
}

/// A quarantined view of a self-reported reward label.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub struct RewardLabelView {
    /// Self-reported overall score in milli-units (`0..=1000`), for provenance.
    pub self_reported_milli_u32: u32,
    /// Always `true` in E-WP-01: self-reported reward is quarantined.
    pub quarantined: bool,
    /// Always `false` in E-WP-01: eligibility is recomputed later via S1 reverify.
    pub reward_eligible: bool,
}

/// Parse `reward_labels.json`. The self-reported score is read for provenance
/// only; the label is quarantined and never reward-eligible in E-WP-01.
pub fn parse_reward_labels(text: &str) -> DietResult<RewardLabelView> {
    const KIND: DietFileKind = DietFileKind::RewardLabels;
    let v = parse_json(KIND, text)?;
    let obj = as_object(&v, KIND, "$root")?;
    let scalar = obj
        .get("overall_scalar")
        .and_then(serde_json::Value::as_f64)
        .unwrap_or(0.0);
    let clamped = if scalar.is_finite() {
        scalar.clamp(0.0, 1.0)
    } else {
        0.0
    };
    let milli = (clamped * 1000.0).round() as u32;
    Ok(RewardLabelView {
        self_reported_milli_u32: milli,
        quarantined: true,
        reward_eligible: false,
    })
}

/// A hashed view of an `eval_summary.json` outcome.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub struct EvalSummaryView {
    /// `sha256` of the `outcome` string.
    pub outcome_hash_32: [u8; 32],
}

/// Parse `eval_summary.json` into a hashed outcome view.
pub fn parse_eval_summary(text: &str) -> DietResult<EvalSummaryView> {
    const KIND: DietFileKind = DietFileKind::EvalSummary;
    let v = parse_json(KIND, text)?;
    let obj = as_object(&v, KIND, "$root")?;
    let outcome = obj
        .get("outcome")
        .and_then(|x| x.as_str())
        .unwrap_or("unknown");
    Ok(EvalSummaryView {
        outcome_hash_32: crate::sha256(outcome.as_bytes()),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn valid_sft_chat_counts_turns() -> DietResult<()> {
        let doc = r#"{"chat_id":"a","turns":[{"role":"system","content":"x"},{"role":"user","content":"y"}]}"#;
        let s = parse_sft_chat(doc)?;
        assert_eq!(s.chats_u32, 1);
        assert_eq!(s.turns_u32, 2);
        Ok(())
    }

    #[test]
    fn malformed_sft_chat_rejects() {
        assert!(matches!(
            parse_sft_chat(r#"{"chat_id":"a"}"#),
            Err(DietError::MissingField {
                kind: DietFileKind::SftChat,
                field: "turns"
            })
        ));
    }

    #[test]
    fn preference_pair_requires_both_sides() -> DietResult<()> {
        assert_eq!(
            count_preference_pairs(r#"{"pair_id":"p","chosen":"a","rejected":"b"}"#)?,
            1
        );
        assert!(matches!(
            count_preference_pairs(r#"{"pair_id":"p","chosen":"a"}"#),
            Err(DietError::MissingField {
                field: "chosen|rejected",
                ..
            })
        ));
        Ok(())
    }

    #[test]
    fn reward_label_is_quarantined_not_eligible() -> DietResult<()> {
        let r = parse_reward_labels(r#"{"overall_reward":"POSITIVE","overall_scalar":0.8}"#)?;
        assert_eq!(r.self_reported_milli_u32, 800);
        assert!(r.quarantined);
        assert!(!r.reward_eligible);
        Ok(())
    }

    #[test]
    fn eval_summary_hashes_outcome() -> DietResult<()> {
        let r = parse_eval_summary(r#"{"outcome":"IMPLEMENTED_PENDING_VERIFICATION"}"#)?;
        assert_eq!(
            r.outcome_hash_32,
            crate::sha256(b"IMPLEMENTED_PENDING_VERIFICATION")
        );
        Ok(())
    }
}
