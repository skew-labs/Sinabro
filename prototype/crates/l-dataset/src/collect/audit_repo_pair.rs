//! audit-log to repo pairing parser (atom #365 · E.1.14, §4.4 `HumanReviewSignal`).
//!
//! Skew/Strike-style audit logs are paired with code and reverify commands.
//! Narrative claims (a reviewer comment, an audit-log assertion) remain S2 until
//! rerun: they are hashed for provenance but are never reward by themselves.
//! An audit log paired with a present repo *and* a reverify command is S1-
//! eligible; a missing repo or missing command keeps the sample SFT-only.
use crate::command_manifest;
use crate::diet_kind::AtomDietKey;
use crate::error::DietResult;
use crate::interactions::parse_approval_events;

/// Human-review signal (§4.4). Approval is metadata, never reward by itself.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub struct HumanReviewSignal {
    /// The source atom.
    pub key: AtomDietKey,
    /// At least one approval and no denials in the approval events.
    pub approved: bool,
    /// `sha256` of the reviewer identifier (`"none"` when absent).
    pub reviewer_hash_32: [u8; 32],
    /// `sha256` of the review comment (`"none"` when absent).
    pub comment_hash_32: [u8; 32],
}

/// Audit-log to repo pairing model.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub struct AuditRepoPair {
    /// The source atom.
    pub key: AtomDietKey,
    /// `sha256` of the audit-log text (provenance anchor, never raw export).
    pub audit_log_hash_32: [u8; 32],
    /// A paired code repo / diff was present.
    pub repo_present: bool,
    /// A reverify command was recorded for the sample.
    pub reverify_command_present: bool,
    /// Provenance was preserved (a non-empty audit log).
    pub provenance_preserved: bool,
    /// S1-eligible: paired repo *and* a reverify command. Else SFT-only / S2.
    pub s1_eligible: bool,
}

/// Build a [`HumanReviewSignal`] from optional `approval_events.jsonl` plus
/// optional reviewer/comment narrative strings (hashed, never stored raw).
pub fn human_review_signal(
    key: AtomDietKey,
    approval_events_jsonl: Option<&str>,
    reviewer: Option<&str>,
    comment: Option<&str>,
) -> DietResult<HumanReviewSignal> {
    let approved = match approval_events_jsonl {
        Some(a) => {
            let s = parse_approval_events(a)?;
            s.approvals_u32 > 0 && s.denials_u32 == 0
        }
        None => false,
    };
    Ok(HumanReviewSignal {
        key,
        approved,
        reviewer_hash_32: crate::sha256(reviewer.unwrap_or("none").as_bytes()),
        comment_hash_32: crate::sha256(comment.unwrap_or("none").as_bytes()),
    })
}

/// Pair an audit log with its repo presence and reverify command evidence.
pub fn collect(
    key: AtomDietKey,
    audit_log: &str,
    repo_present: bool,
    command_manifest_json: Option<&str>,
) -> DietResult<AuditRepoPair> {
    let reverify_command_present = match command_manifest_json {
        Some(c) => !command_manifest::parse(c)?.is_empty(),
        None => false,
    };
    let provenance_preserved = !audit_log.trim().is_empty();
    let s1_eligible = repo_present && reverify_command_present;
    Ok(AuditRepoPair {
        key,
        audit_log_hash_32: crate::sha256(audit_log.as_bytes()),
        repo_present,
        reverify_command_present,
        provenance_preserved,
        s1_eligible,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::diet_kind::DietSourceStage;

    fn key() -> AtomDietKey {
        AtomDietKey::new(DietSourceStage::StageD, 365)
    }

    const CMDS: &str = r#"{"commands":[{"cmd":"cargo test --workspace","exit":0}]}"#;

    #[test]
    fn paired_repo_and_command_is_s1_eligible() -> DietResult<()> {
        let s = collect(
            key(),
            "AI_AUDIT_LOG: atom #200 fix bridge invariant",
            true,
            Some(CMDS),
        )?;
        assert!(s.repo_present);
        assert!(s.reverify_command_present);
        assert!(s.provenance_preserved);
        assert!(s.s1_eligible);
        Ok(())
    }

    #[test]
    fn missing_repo_is_sft_only() -> DietResult<()> {
        let s = collect(key(), "audit note without code", false, Some(CMDS))?;
        assert!(!s.repo_present);
        assert!(!s.s1_eligible);
        Ok(())
    }

    #[test]
    fn missing_command_is_no_reward() -> DietResult<()> {
        let s = collect(key(), "audit note", true, None)?;
        assert!(!s.reverify_command_present);
        assert!(!s.s1_eligible);
        Ok(())
    }

    #[test]
    fn empty_audit_log_loses_provenance() -> DietResult<()> {
        let s = collect(key(), "   \n", true, Some(CMDS))?;
        assert!(!s.provenance_preserved);
        Ok(())
    }

    #[test]
    fn human_review_approved_is_metadata() -> DietResult<()> {
        let approve = r#"{"approvals_count":1,"denials_count":0,"events":[]}"#;
        let h = human_review_signal(key(), Some(approve), Some("owner"), Some("looks good"))?;
        assert!(h.approved);
        assert_eq!(h.reviewer_hash_32, crate::sha256(b"owner"));
        assert_ne!(h.comment_hash_32, crate::sha256(b"none"));
        Ok(())
    }

    #[test]
    fn human_review_denied_is_not_approved() -> DietResult<()> {
        let deny = r#"{"approvals_count":0,"denials_count":1,"events":[]}"#;
        assert!(!human_review_signal(key(), Some(deny), None, None)?.approved);
        Ok(())
    }
}
