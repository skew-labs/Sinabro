//! Interaction sidecar parsers: failed attempts, no-op decisions, human review,
//! approval events (atom #345 · E.0.14).
//!
//! Failed and rejected attempts are first-class training data, so they are
//! counted, not discarded. Approval is *metadata* — it never becomes reward
//! unless backed by S1 (a later WorkPackage). Any secret residue in a live
//! approval payload rejects.
use crate::diet_kind::DietFileKind;
use crate::error::{DietError, DietResult};
use crate::terminal::looks_secret;
use serde_json::Value;

fn count_records(kind: DietFileKind, text: &str) -> DietResult<u32> {
    let mut n = 0u32;
    let mut rec = 0u32;
    for line in text.lines() {
        if line.trim().is_empty() {
            continue;
        }
        rec = rec.saturating_add(1);
        let v: Value = serde_json::from_str(line).map_err(|_| DietError::MalformedJsonl {
            kind,
            record_u32: rec,
        })?;
        if !v.is_object() {
            return Err(DietError::MalformedJsonl {
                kind,
                record_u32: rec,
            });
        }
        n = n.saturating_add(1);
    }
    Ok(n)
}

/// Count `failed_attempts.jsonl` records (each a fail-then-fix cycle).
pub fn count_failed_attempts(text: &str) -> DietResult<u32> {
    count_records(DietFileKind::FailedAttempts, text)
}

/// Count `no_op_decisions.jsonl` records (deliberate non-implementations).
pub fn count_no_op_decisions(text: &str) -> DietResult<u32> {
    count_records(DietFileKind::NoOpDecisions, text)
}

/// Count `human_review.jsonl` records (user-instruction interpretations).
pub fn count_human_reviews(text: &str) -> DietResult<u32> {
    count_records(DietFileKind::HumanReview, text)
}

/// Approval-event summary. Approval is metadata, never reward by itself.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub struct ApprovalSummary {
    /// Number of approvals.
    pub approvals_u32: u32,
    /// Number of denials.
    pub denials_u32: u32,
    /// Number of live-action events.
    pub live_actions_u32: u32,
}

fn clamp(v: u64) -> u32 {
    v.min(u32::MAX as u64) as u32
}

/// Parse `approval_events.jsonl`, summing explicit counts and per-event
/// decisions. Secret residue in any event string is a hard reject.
pub fn parse_approval_events(text: &str) -> DietResult<ApprovalSummary> {
    const KIND: DietFileKind = DietFileKind::ApprovalEvents;
    let mut approvals = 0u64;
    let mut denials = 0u64;
    let mut live = 0u64;
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
        if let Some(c) = obj
            .get("approvals_count")
            .and_then(serde_json::Value::as_u64)
        {
            approvals = approvals.saturating_add(c);
        }
        if let Some(c) = obj.get("denials_count").and_then(serde_json::Value::as_u64) {
            denials = denials.saturating_add(c);
        }
        if let Some(events) = obj.get("events").and_then(|x| x.as_array()) {
            for ev in events {
                live = live.saturating_add(1);
                if let Some(eo) = ev.as_object() {
                    for val in eo.values() {
                        if let Some(s) = val.as_str() {
                            if looks_secret(s) {
                                return Err(DietError::SecretResidue { kind: KIND });
                            }
                        }
                    }
                    match eo.get("decision").and_then(|d| d.as_str()) {
                        Some(d)
                            if d.eq_ignore_ascii_case("approved")
                                || d.eq_ignore_ascii_case("approve") =>
                        {
                            approvals = approvals.saturating_add(1);
                        }
                        Some(d)
                            if d.eq_ignore_ascii_case("denied")
                                || d.eq_ignore_ascii_case("deny") =>
                        {
                            denials = denials.saturating_add(1);
                        }
                        _ => {}
                    }
                }
            }
        }
    }
    Ok(ApprovalSummary {
        approvals_u32: clamp(approvals),
        denials_u32: clamp(denials),
        live_actions_u32: clamp(live),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn counts_failed_and_no_op_chains() -> DietResult<()> {
        let failed = "{\"n\":1}\n{\"n\":2}\n{\"n\":3}\n";
        assert_eq!(count_failed_attempts(failed)?, 3);
        let no_op = "{\"n\":1}\n{\"n\":2}\n";
        assert_eq!(count_no_op_decisions(no_op)?, 2);
        Ok(())
    }

    #[test]
    fn approval_and_denial_counts() -> DietResult<()> {
        let approve = r#"{"approvals_count":1,"denials_count":0,"events":[]}"#;
        let s = parse_approval_events(approve)?;
        assert_eq!(s.approvals_u32, 1);
        assert_eq!(s.denials_u32, 0);
        let deny = r#"{"approvals_count":0,"denials_count":1,"events":[]}"#;
        assert_eq!(parse_approval_events(deny)?.denials_u32, 1);
        Ok(())
    }

    #[test]
    fn live_event_decisions_count() -> DietResult<()> {
        let doc = r#"{"events":[{"decision":"approved","detail":"deploy testnet"},{"decision":"denied","detail":"mainnet"}]}"#;
        let s = parse_approval_events(doc)?;
        assert_eq!(s.live_actions_u32, 2);
        assert_eq!(s.approvals_u32, 1);
        assert_eq!(s.denials_u32, 1);
        Ok(())
    }

    #[test]
    fn secret_in_live_approval_rejects() {
        let doc = r#"{"events":[{"decision":"approved","detail":"sk-live_ABCDEFGH012345"}]}"#;
        assert!(matches!(
            parse_approval_events(doc),
            Err(DietError::SecretResidue {
                kind: DietFileKind::ApprovalEvents
            })
        ));
    }

    #[test]
    fn non_object_record_rejects() {
        assert!(matches!(
            count_failed_attempts("[1,2,3]\n"),
            Err(DietError::MalformedJsonl {
                kind: DietFileKind::FailedAttempts,
                record_u32: 1
            })
        ));
    }
}
