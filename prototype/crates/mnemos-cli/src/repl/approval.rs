//! Typed approval prompts + permission tuning (atom #415 F.1.6).
//!
//! This is the fail-closed approval surface for the cockpit. The hard laws:
//!
//! * wallet / chain / admin and other destructive actions require an *exact
//!   typed phrase*; a bare Enter (empty response) can never approve them;
//! * an approval, once granted, cannot be replayed (idempotency / replay deny);
//! * a timeout is always a denial;
//! * repeated-safe prompts may be converted only into *visible*
//!   allow-once / allow-session / revoke rules that carry an audit hash and (for
//!   session rules) an expiry — a rule without audit/expiry is rejected, so a
//!   hidden privilege escalation is impossible.
//!
//! It reuses the closed C/D approval policy via [`ApprovalRequirement`]
//! (`command.rs`); it never performs a wallet/chain/live action itself.

use crate::command::ApprovalRequirement;
use crate::sha256_32;

const ZERO32: [u8; 32] = [0u8; 32];

/// The decision a prompt yields.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ApprovalDecision {
    /// The action is approved.
    Approved,
    /// The action is denied.
    Denied,
}

impl ApprovalDecision {
    /// Whether this decision approves the action.
    #[must_use]
    pub const fn is_approved(self) -> bool {
        matches!(self, Self::Approved)
    }
}

/// A typed approval prompt bound to one [`ApprovalRequirement`]. For
/// `TypedPhrase` / `Multisig` it holds the exact phrase the user must type.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ApprovalPrompt {
    requirement: ApprovalRequirement,
    expected_phrase: String,
    consumed: bool,
}

impl ApprovalPrompt {
    /// A prompt for `requirement`. `expected_phrase` is the exact phrase needed
    /// for a typed-phrase / multisig approval (ignored for other requirements).
    #[must_use]
    pub fn new(requirement: ApprovalRequirement, expected_phrase: impl Into<String>) -> Self {
        Self {
            requirement,
            expected_phrase: expected_phrase.into().trim().to_string(),
            consumed: false,
        }
    }

    /// Whether this prompt was already satisfied (and so can't be replayed).
    #[must_use]
    pub const fn is_consumed(&self) -> bool {
        self.consumed
    }

    fn decide(&self, response: &str) -> ApprovalDecision {
        let r = response.trim();
        match self.requirement {
            ApprovalRequirement::None => ApprovalDecision::Approved,
            ApprovalRequirement::ForbiddenInStageF => ApprovalDecision::Denied,
            ApprovalRequirement::Confirm => {
                let lowered = r.to_ascii_lowercase();
                if matches!(lowered.as_str(), "y" | "yes" | "confirm") {
                    ApprovalDecision::Approved
                } else {
                    ApprovalDecision::Denied
                }
            }
            ApprovalRequirement::TypedPhrase | ApprovalRequirement::Multisig => {
                // A bare Enter (empty) can never approve a destructive action,
                // and the phrase must match exactly.
                if !r.is_empty() && !self.expected_phrase.is_empty() && r == self.expected_phrase {
                    ApprovalDecision::Approved
                } else {
                    ApprovalDecision::Denied
                }
            }
        }
    }

    /// Evaluate a user response. An already-consumed prompt always denies (replay
    /// deny). A denial never consumes the prompt (the user may retry); an
    /// approval consumes it.
    pub fn evaluate(&mut self, response: &str) -> ApprovalDecision {
        if self.consumed {
            return ApprovalDecision::Denied;
        }
        let decision = self.decide(response);
        if decision.is_approved() {
            self.consumed = true;
        }
        decision
    }

    /// A timeout is always a denial (and never consumes the prompt).
    #[must_use]
    pub const fn on_timeout() -> ApprovalDecision {
        ApprovalDecision::Denied
    }
}

/// §4.3 — how long a permission rule lasts.
#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PermissionDuration {
    /// Valid for a single use.
    Once = 1,
    /// Valid until the session expiry.
    Session = 2,
    /// Valid until explicitly revoked.
    Persistent = 3,
    /// Revoked (never active).
    Revoked = 4,
}

impl PermissionDuration {
    /// A short human label for the `permissions explain` command.
    #[must_use]
    pub const fn explain(self) -> &'static str {
        match self {
            Self::Once => "one-time (single use)",
            Self::Session => "this session (until expiry)",
            Self::Persistent => "persistent (until revoked)",
            Self::Revoked => "revoked",
        }
    }
}

/// §4.3 — a visible permission rule. Every rule carries an audit hash; session
/// rules carry an expiry. Constructors reject a rule that would escalate
/// silently (missing audit, or a session without expiry).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PermissionRuleView {
    /// SHA-256 identity of the rule (over duration + capability + expiry + audit).
    pub rule_hash_32: [u8; 32],
    /// How long the rule lasts.
    pub duration: PermissionDuration,
    /// SHA-256 of the capability the rule grants.
    pub capability_hash_32: [u8; 32],
    /// Expiry epoch (ms); `0` for `Once`, `u64::MAX` for `Persistent`.
    pub expires_at_epoch_ms: u64,
    /// SHA-256 of the audit record that justifies the rule (never zero).
    pub audit_hash_32: [u8; 32],
}

impl PermissionRuleView {
    fn build(
        duration: PermissionDuration,
        capability_hash_32: [u8; 32],
        expires_at_epoch_ms: u64,
        audit_hash_32: [u8; 32],
    ) -> Self {
        let mut buf = Vec::with_capacity(73);
        buf.push(duration as u8);
        buf.extend_from_slice(&capability_hash_32);
        buf.extend_from_slice(&expires_at_epoch_ms.to_le_bytes());
        buf.extend_from_slice(&audit_hash_32);
        Self {
            rule_hash_32: sha256_32(&buf),
            duration,
            capability_hash_32,
            expires_at_epoch_ms,
            audit_hash_32,
        }
    }

    /// An allow-once rule. Requires a non-zero audit hash; returns `None`
    /// otherwise (no silent grant).
    #[must_use]
    pub fn allow_once(capability_hash_32: [u8; 32], audit_hash_32: [u8; 32]) -> Option<Self> {
        if audit_hash_32 == ZERO32 {
            return None;
        }
        Some(Self::build(
            PermissionDuration::Once,
            capability_hash_32,
            0,
            audit_hash_32,
        ))
    }

    /// An allow-session rule. Requires both a non-zero audit hash *and* a
    /// non-zero expiry — a session that never expires, or has no audit, is
    /// rejected (`None`). This is the recommendation-reject path.
    #[must_use]
    pub fn allow_session(
        capability_hash_32: [u8; 32],
        audit_hash_32: [u8; 32],
        expires_at_epoch_ms: u64,
    ) -> Option<Self> {
        if audit_hash_32 == ZERO32 || expires_at_epoch_ms == 0 {
            return None;
        }
        Some(Self::build(
            PermissionDuration::Session,
            capability_hash_32,
            expires_at_epoch_ms,
            audit_hash_32,
        ))
    }

    /// A persistent rule. Requires a non-zero audit hash; returns `None`
    /// otherwise.
    #[must_use]
    pub fn persistent(capability_hash_32: [u8; 32], audit_hash_32: [u8; 32]) -> Option<Self> {
        if audit_hash_32 == ZERO32 {
            return None;
        }
        Some(Self::build(
            PermissionDuration::Persistent,
            capability_hash_32,
            u64::MAX,
            audit_hash_32,
        ))
    }

    /// Revoke this rule (returns a `Revoked` copy; identity is recomputed).
    #[must_use]
    pub fn revoke(self) -> Self {
        Self::build(
            PermissionDuration::Revoked,
            self.capability_hash_32,
            self.expires_at_epoch_ms,
            self.audit_hash_32,
        )
    }

    /// Whether the rule carries a (non-zero) audit hash.
    #[must_use]
    pub fn has_audit(&self) -> bool {
        self.audit_hash_32 != ZERO32
    }

    /// Whether the rule is active at `now_epoch_ms`.
    #[must_use]
    pub const fn is_active(&self, now_epoch_ms: u64) -> bool {
        match self.duration {
            PermissionDuration::Revoked => false,
            PermissionDuration::Once | PermissionDuration::Persistent => true,
            PermissionDuration::Session => now_epoch_ms < self.expires_at_epoch_ms,
        }
    }

    /// The human explanation for `permissions explain`.
    #[must_use]
    pub const fn explain(&self) -> &'static str {
        self.duration.explain()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn confirm_only_approves_on_yes() {
        let mut p = ApprovalPrompt::new(ApprovalRequirement::Confirm, "");
        assert_eq!(p.evaluate("no"), ApprovalDecision::Denied);
        assert_eq!(p.evaluate("yes"), ApprovalDecision::Approved);
    }

    #[test]
    fn typed_phrase_mismatch_denies_and_does_not_consume() {
        let mut p = ApprovalPrompt::new(ApprovalRequirement::TypedPhrase, "I APPROVE WALLET SIGN");
        assert_eq!(p.evaluate("nope"), ApprovalDecision::Denied);
        assert!(!p.is_consumed());
        assert_eq!(
            p.evaluate("I APPROVE WALLET SIGN"),
            ApprovalDecision::Approved
        );
        assert!(p.is_consumed());
    }

    #[test]
    fn bare_enter_never_approves_destructive() {
        let mut p = ApprovalPrompt::new(ApprovalRequirement::TypedPhrase, "CONFIRM CHAIN WRITE");
        assert_eq!(p.evaluate(""), ApprovalDecision::Denied);
        assert_eq!(p.evaluate("   "), ApprovalDecision::Denied);
        let mut m = ApprovalPrompt::new(ApprovalRequirement::Multisig, "MULTISIG OK");
        assert_eq!(m.evaluate(""), ApprovalDecision::Denied);
    }

    #[test]
    fn approval_cannot_be_replayed() {
        let mut p = ApprovalPrompt::new(ApprovalRequirement::TypedPhrase, "GO");
        assert_eq!(p.evaluate("GO"), ApprovalDecision::Approved);
        // replay of the same correct phrase is denied
        assert_eq!(p.evaluate("GO"), ApprovalDecision::Denied);
    }

    #[test]
    fn timeout_and_forbidden_always_deny() {
        assert_eq!(ApprovalPrompt::on_timeout(), ApprovalDecision::Denied);
        let mut f = ApprovalPrompt::new(ApprovalRequirement::ForbiddenInStageF, "whatever");
        assert_eq!(f.evaluate("whatever"), ApprovalDecision::Denied);
    }

    #[test]
    fn none_requirement_auto_approves() {
        let mut p = ApprovalPrompt::new(ApprovalRequirement::None, "");
        assert_eq!(p.evaluate(""), ApprovalDecision::Approved);
    }

    #[test]
    fn allow_once_requires_audit() {
        assert!(PermissionRuleView::allow_once([1u8; 32], ZERO32).is_none());
        let r = PermissionRuleView::allow_once([1u8; 32], [9u8; 32]);
        assert!(r.is_some());
        if let Some(rule) = r {
            assert_eq!(rule.duration, PermissionDuration::Once);
            assert!(rule.has_audit());
            assert!(rule.is_active(123));
        }
    }

    #[test]
    fn allow_session_requires_audit_and_expiry() {
        // no expiry -> rejected (recommendation reject)
        assert!(PermissionRuleView::allow_session([1u8; 32], [9u8; 32], 0).is_none());
        // no audit -> rejected
        assert!(PermissionRuleView::allow_session([1u8; 32], ZERO32, 1000).is_none());
        let r = PermissionRuleView::allow_session([1u8; 32], [9u8; 32], 1000);
        assert!(r.is_some());
        if let Some(rule) = r {
            assert_eq!(rule.duration, PermissionDuration::Session);
            assert!(rule.is_active(999));
            assert!(!rule.is_active(1000));
            assert!(!rule.is_active(2000));
        }
    }

    #[test]
    fn revoke_is_never_active_and_explains() {
        let r = PermissionRuleView::persistent([2u8; 32], [3u8; 32]);
        assert!(r.is_some());
        if let Some(rule) = r {
            assert!(rule.is_active(0));
            let revoked = rule.revoke();
            assert_eq!(revoked.duration, PermissionDuration::Revoked);
            assert!(!revoked.is_active(0));
            assert_eq!(revoked.explain(), "revoked");
            // revoking changes the rule identity
            assert_ne!(revoked.rule_hash_32, rule.rule_hash_32);
        }
    }
}
