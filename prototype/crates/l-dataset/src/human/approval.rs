//! Approval / denial event normalizer (atom #376 · E.2.5).
//!
//! Approval events are **evidence of operator control**, never reward by
//! themselves and never an override: an approval can never flip a gate-red or
//! privacy-red sample to reward-eligible. This normalizer reuses the canonical
//! `interactions::parse_approval_events` summary (secret residue in any event
//! string already rejects there) and adds the hard rule
//! `reward_blocked = gate_red ∨ privacy_red`, independent of how many approvals
//! exist. An expired approval is not counted as an approval (the summary only
//! credits explicit `approved` / `approvals_count`).
use crate::diet_kind::AtomDietKey;
use crate::error::DietResult;
use crate::interactions::{self, ApprovalSummary};

/// A normalized approval/denial summary for one atom.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub struct NormalizedApproval {
    /// The source atom.
    pub key: AtomDietKey,
    /// Number of approvals.
    pub approvals_u32: u32,
    /// Number of denials.
    pub denials_u32: u32,
    /// Number of live-action events recorded.
    pub live_actions_u32: u32,
    /// Operator-controlled: at least one approval and zero denials.
    pub operator_controlled: bool,
    /// Reward blocked: `gate_red ∨ privacy_red` — approvals never override this.
    pub reward_blocked: bool,
}

/// Normalize `approval_events.jsonl` with the atom's gate/privacy red flags. A
/// secret in any approval string rejects (propagated from the canonical parser).
pub fn normalize(
    key: AtomDietKey,
    approval_events_jsonl: &str,
    gate_red: bool,
    privacy_red: bool,
) -> DietResult<NormalizedApproval> {
    let s: ApprovalSummary = interactions::parse_approval_events(approval_events_jsonl)?;
    let operator_controlled = s.approvals_u32 > 0 && s.denials_u32 == 0;
    Ok(NormalizedApproval {
        key,
        approvals_u32: s.approvals_u32,
        denials_u32: s.denials_u32,
        live_actions_u32: s.live_actions_u32,
        operator_controlled,
        reward_blocked: gate_red || privacy_red,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::diet_kind::DietSourceStage;
    use crate::error::DietError;

    fn key() -> AtomDietKey {
        AtomDietKey::new(DietSourceStage::StageD, 376)
    }

    #[test]
    fn live_approval_is_operator_controlled() -> DietResult<()> {
        let doc = r#"{"approvals_count":1,"denials_count":0,"events":[]}"#;
        let n = normalize(key(), doc, false, false)?;
        assert!(n.operator_controlled);
        assert!(!n.reward_blocked);
        Ok(())
    }

    #[test]
    fn denial_is_not_operator_controlled() -> DietResult<()> {
        let doc = r#"{"approvals_count":0,"denials_count":1,"events":[]}"#;
        let n = normalize(key(), doc, false, false)?;
        assert!(!n.operator_controlled);
        assert_eq!(n.denials_u32, 1);
        Ok(())
    }

    #[test]
    fn expired_approval_is_not_counted() -> DietResult<()> {
        // an "expired" decision is neither approved nor denied → not operator-controlled.
        let doc = r#"{"events":[{"decision":"expired","detail":"timed out"}]}"#;
        let n = normalize(key(), doc, false, false)?;
        assert_eq!(n.approvals_u32, 0);
        assert!(!n.operator_controlled);
        assert_eq!(n.live_actions_u32, 1);
        Ok(())
    }

    #[test]
    fn gate_red_blocks_reward_despite_approval() -> DietResult<()> {
        let doc = r#"{"approvals_count":3,"denials_count":0,"events":[]}"#;
        let n = normalize(key(), doc, true, false)?;
        assert!(n.operator_controlled);
        assert!(n.reward_blocked); // approval never overrides gate red
        Ok(())
    }

    #[test]
    fn privacy_red_blocks_reward_despite_approval() -> DietResult<()> {
        let doc = r#"{"approvals_count":1,"denials_count":0,"events":[]}"#;
        assert!(normalize(key(), doc, false, true)?.reward_blocked);
        Ok(())
    }

    #[test]
    fn secret_in_approval_text_rejects() {
        let doc = r#"{"events":[{"decision":"approved","detail":"sk-live_ABCDEF0123456789"}]}"#;
        assert!(matches!(
            normalize(key(), doc, false, false),
            Err(DietError::SecretResidue { .. })
        ));
    }
}
