//! Skill recommend / use / install dry-run surface.
//!
//! `recommend` projects the canonical [`SkillCardView`] into a listing row
//! (id / installs / capability / eval / provenance / trust) and ranks it so a card
//! below the security floor never sorts above a secure one (popularity never hides
//! a security problem). `use` / `install` is a dry-run plan that requires an
//! explicit approval and a sandbox tier. There is no buy / sell / checkout /
//! revenue / refund path: [`SkillRecommendation::is_commerce`] and
//! [`SkillInstallDryRun::is_commerce`] are always `false` (No-Commerce). This module
//! performs no live action.
//!
//! Reuse (no reinvention): [`SkillCardView`] / [`OfficialTrustDecision`] /
//! [`SECURITY_FLOOR_BPS`] from [`crate::tui::skill_cards`]; the risk → approval
//! mapping is the canonical [`approval_for`].

use crate::command::{ApprovalRequirement, CommandRisk, approval_for};
use crate::hex32;
use crate::tui::skill_cards::{OfficialTrustDecision, SECURITY_FLOOR_BPS, SkillCardView};

/// First 16 hex characters of a 32-byte digest — a redacted, display-only prefix.
#[must_use]
fn redact16(bytes: &[u8; 32]) -> String {
    hex32(bytes).chars().take(16).collect()
}

/// A recommend / inspect listing row projected from a [`SkillCardView`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SkillRecommendation {
    /// Redacted 16-hex prefix of the skill id.
    pub skill_id_redacted: String,
    /// Number of verified installs (popularity — never overrides security).
    pub verified_installs_u64: u64,
    /// Eval score in basis points.
    pub eval_score_bps: u16,
    /// Security score in basis points.
    pub security_score_bps: u16,
    /// Redacted 16-hex prefix of the capability-diff hash.
    pub capability_diff_redacted: String,
    /// Redacted 16-hex prefix of the provenance hash.
    pub provenance_redacted: String,
    /// The canonical official-trust verdict.
    pub trust_state: OfficialTrustDecision,
    /// Whether the card meets the security floor.
    pub secure_enough: bool,
}

impl SkillRecommendation {
    /// Project a recommendation row from a canonical [`SkillCardView`].
    #[must_use]
    pub fn from_card(card: &SkillCardView) -> Self {
        Self {
            skill_id_redacted: redact16(&card.skill_id_hash_32),
            verified_installs_u64: card.verified_installs_u64,
            eval_score_bps: card.eval_score_bps,
            security_score_bps: card.security_score_bps,
            capability_diff_redacted: redact16(&card.capability_diff_hash_32),
            provenance_redacted: redact16(&card.provenance_hash_32),
            trust_state: card.trust_state,
            secure_enough: card.security_score_bps >= SECURITY_FLOOR_BPS,
        }
    }

    /// Always `false`: a recommendation is never a commerce / checkout surface.
    #[must_use]
    pub const fn is_commerce(&self) -> bool {
        false
    }

    /// Redacted, colorless listing lines bounded by `rows`.
    #[must_use]
    pub fn render(&self, rows: u16) -> Vec<String> {
        let lines = vec![
            format!("skill={}", self.skill_id_redacted),
            format!("installs={}", self.verified_installs_u64),
            format!("eval_bps={}", self.eval_score_bps),
            format!("security_bps={}", self.security_score_bps),
            format!("capability={}", self.capability_diff_redacted),
            format!("provenance={}", self.provenance_redacted),
            format!(
                "trust_u8={} trusted={}",
                self.trust_state.as_u8(),
                self.trust_state.is_trusted()
            ),
            format!("secure_enough={}", self.secure_enough),
        ];
        lines.into_iter().take(rows as usize).collect()
    }
}

/// Rank skill cards into recommendations: a card below the security floor never
/// ranks above a secure one; within a security tier, higher eval ranks first, then
/// popularity. Popularity never overrides security.
#[must_use]
pub fn recommend(cards: &[SkillCardView]) -> Vec<SkillRecommendation> {
    let mut recs: Vec<SkillRecommendation> =
        cards.iter().map(SkillRecommendation::from_card).collect();
    recs.sort_by(|a, b| {
        b.secure_enough
            .cmp(&a.secure_enough)
            .then(b.eval_score_bps.cmp(&a.eval_score_bps))
            .then(b.verified_installs_u64.cmp(&a.verified_installs_u64))
    });
    recs
}

/// A `skill use` / `skill install` dry-run plan: an install needs an explicit
/// approval and a sandbox tier, and is never a commerce surface.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SkillInstallDryRun {
    /// The approval requirement (a local install is `LocalWrite` → `Confirm`).
    pub approval: ApprovalRequirement,
    /// The sandbox tier the install would run under.
    pub sandbox_tier_u8: u8,
    /// Invariant `false`: install is never a commerce / checkout surface.
    pub is_commerce: bool,
    /// Whether this is a dry-run (no live install / side effect).
    pub dry_run: bool,
}

impl SkillInstallDryRun {
    /// Plan a use / install dry-run at a sandbox tier. The approval is derived from
    /// the canonical risk mapping (`LocalWrite` → `Confirm`).
    #[must_use]
    pub fn plan(sandbox_tier_u8: u8) -> Self {
        Self {
            approval: approval_for(CommandRisk::LocalWrite),
            sandbox_tier_u8,
            is_commerce: false,
            dry_run: true,
        }
    }

    /// Colorless plan lines bounded by `rows`.
    #[must_use]
    pub fn render(&self, rows: u16) -> Vec<String> {
        let lines = vec![
            format!("approval_u8={}", self.approval as u8),
            format!("sandbox_tier={}", self.sandbox_tier_u8),
            format!("is_commerce={}", self.is_commerce),
            format!("dry_run={}", self.dry_run),
        ];
        lines.into_iter().take(rows as usize).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const COMMERCE_TOKENS: &[&str] = &[
        "price", "pay", "buy", "sell", "checkout", "refund", "fee", "cost", "$",
    ];

    fn card(
        id: u8,
        installs: u64,
        eval: u16,
        security: u16,
        trust: OfficialTrustDecision,
    ) -> SkillCardView {
        SkillCardView::new(
            [id; 32], installs, eval, security, [0x55; 32], [0x66; 32], [0x77; 32], trust,
        )
    }

    #[test]
    fn recommend_security_floor_over_popularity() {
        // an insecure-but-very-popular card must not rank above a secure one
        let insecure_popular = card(1, 1_000_000, 9000, 1000, OfficialTrustDecision::Quarantined);
        let secure_quiet = card(2, 5, 8000, 9000, OfficialTrustDecision::OfficialTrusted);
        let ranked = recommend(&[insecure_popular, secure_quiet]);
        assert_eq!(ranked.len(), 2);
        assert!(ranked[0].secure_enough, "secure card ranks first");
        assert_eq!(ranked[0].skill_id_redacted, redact16(&[2u8; 32]));
        assert!(!ranked[1].secure_enough);
    }

    #[test]
    fn inspect_projects_card() {
        let c = card(3, 42, 7000, 9000, OfficialTrustDecision::OfficialTrusted);
        let r = SkillRecommendation::from_card(&c);
        assert_eq!(r.skill_id_redacted.len(), 16);
        assert_eq!(r.verified_installs_u64, 42);
        assert!(r.secure_enough);
        assert!(r.trust_state.is_trusted());
    }

    #[test]
    fn use_dry_run_plan() {
        let p = SkillInstallDryRun::plan(2);
        assert!(p.dry_run);
        assert_eq!(p.sandbox_tier_u8, 2);
        assert!(!p.is_commerce);
    }

    #[test]
    fn install_requires_approval() {
        let p = SkillInstallDryRun::plan(1);
        assert_eq!(p.approval, ApprovalRequirement::Confirm);
    }

    #[test]
    fn commerce_deny() {
        let c = card(4, 10, 7000, 9000, OfficialTrustDecision::OfficialTrusted);
        let r = SkillRecommendation::from_card(&c);
        let p = SkillInstallDryRun::plan(1);
        assert!(!r.is_commerce());
        assert!(!p.is_commerce);
        for line in r.render(16).into_iter().chain(p.render(8)) {
            for bad in COMMERCE_TOKENS {
                assert!(!line.contains(bad), "commerce token {bad} in {line}");
            }
        }
    }
}
