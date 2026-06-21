//! §4.3 cockpit skill card list (atom #422 F.2.5) projecting the §4.4
//! [`SkillCardView`].
//!
//! A skill card is a *lightweight* listing projection: it shows id / verified
//! installs / eval / security / compatibility / capability-diff / provenance /
//! trust state, all as hashes or scores. The full manifest and heavy docs are
//! never loaded here — they load only on inspect (a later atom), so a 100-card
//! list renders fast.
//!
//! The hard law (`G-F-SKILL-QUARANTINE`): popularity can never hide a security
//! or quarantine problem. [`SkillCardView::render_truth`] returns `Red` for a
//! quarantined / revoked / insecure / incomplete card regardless of how many
//! verified installs it has, and [`SkillCardList::ranked`] never sorts such a
//! card above a healthy one.
//!
//! `trust_state` is the canonical [`mnemos_g_wallet::OfficialTrustDecision`]
//! (the §4.4 type) — imported, not re-minted (no-reinvent). The
//! `sinabro -> mnemos-g-wallet` edge is a pure-type, acyclic dependency
//! (user-locked T2 decision, F-WP-03A).

// Re-export the canonical trust verdict so the cockpit's public API is
// self-contained (integration tests / benches that compile against `sinabro`
// can name it without depending on g-wallet directly). This is reuse of the
// §4.4 type, not a re-mint.
pub use mnemos_g_wallet::OfficialTrustDecision;

use crate::hex32;
use crate::tui::RenderTruth;

/// Security score floor (basis points) below which a card is `Red` no matter how
/// popular it is.
pub const SECURITY_FLOOR_BPS: u16 = 5_000;
/// Eval score floor (basis points) below which an otherwise-trusted card is
/// downgraded to `Yellow`.
pub const EVAL_FLOOR_BPS: u16 = 5_000;

const ZERO32: [u8; 32] = [0u8; 32];

/// §4.4 — a lightweight skill listing card. All heavy fields are hashes; the
/// full manifest loads only on inspect.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SkillCardView {
    /// SHA-256 identity of the skill.
    pub skill_id_hash_32: [u8; 32],
    /// Number of verified installs (popularity — never overrides security).
    pub verified_installs_u64: u64,
    /// Eval score in basis points (0..=10000).
    pub eval_score_bps: u16,
    /// Security score in basis points (0..=10000).
    pub security_score_bps: u16,
    /// SHA-256 of the host-compatibility report.
    pub compatibility_hash_32: [u8; 32],
    /// SHA-256 of the capability diff (permission delta — never hidden).
    pub capability_diff_hash_32: [u8; 32],
    /// SHA-256 of the provenance lineage.
    pub provenance_hash_32: [u8; 32],
    /// Official-trust verdict (canonical g-wallet type).
    pub trust_state: OfficialTrustDecision,
}

impl SkillCardView {
    /// Construct a card view.
    #[must_use]
    #[allow(clippy::too_many_arguments)]
    pub const fn new(
        skill_id_hash_32: [u8; 32],
        verified_installs_u64: u64,
        eval_score_bps: u16,
        security_score_bps: u16,
        compatibility_hash_32: [u8; 32],
        capability_diff_hash_32: [u8; 32],
        provenance_hash_32: [u8; 32],
        trust_state: OfficialTrustDecision,
    ) -> Self {
        Self {
            skill_id_hash_32,
            verified_installs_u64,
            eval_score_bps,
            security_score_bps,
            compatibility_hash_32,
            capability_diff_hash_32,
            provenance_hash_32,
            trust_state,
        }
    }

    /// Whether every required listing field is present (non-zero). A card with a
    /// missing capability-diff / compatibility / provenance hash is incomplete
    /// and renders `Red` (a missing field is never silently green).
    #[must_use]
    pub fn is_complete(&self) -> bool {
        self.skill_id_hash_32 != ZERO32
            && self.compatibility_hash_32 != ZERO32
            && self.capability_diff_hash_32 != ZERO32
            && self.provenance_hash_32 != ZERO32
    }

    /// Whether the card is quarantined or revoked (security-fatal).
    #[must_use]
    pub fn is_quarantined_or_revoked(&self) -> bool {
        matches!(
            self.trust_state,
            OfficialTrustDecision::Quarantined | OfficialTrustDecision::Revoked
        )
    }

    /// Whether the security score clears the floor.
    #[must_use]
    pub const fn security_ok(&self) -> bool {
        self.security_score_bps >= SECURITY_FLOOR_BPS
    }

    /// The render truth for this card. The order of checks encodes the law that
    /// security / quarantine / completeness dominate popularity:
    ///
    /// * `Red`   — incomplete, quarantined/revoked, or below the security floor;
    /// * `Yellow`— complete & secure but not officially trusted, or low eval;
    /// * `Green` — complete, secure, officially trusted, eval above floor.
    #[must_use]
    pub fn render_truth(&self) -> RenderTruth {
        if !self.is_complete() || self.is_quarantined_or_revoked() || !self.security_ok() {
            return RenderTruth::Red;
        }
        if !self.trust_state.is_trusted() || self.eval_score_bps < EVAL_FLOOR_BPS {
            return RenderTruth::Yellow;
        }
        RenderTruth::Green
    }

    /// A short, stable label for the trust state (colorless-safe).
    #[must_use]
    pub const fn trust_label(&self) -> &'static str {
        match self.trust_state {
            OfficialTrustDecision::OfficialTrusted => "trusted",
            OfficialTrustDecision::LocalOnly => "local",
            OfficialTrustDecision::SelfHostedOnly => "self-hosted",
            OfficialTrustDecision::Quarantined => "QUARANTINED",
            OfficialTrustDecision::Revoked => "REVOKED",
        }
    }

    /// A short colorless label for the render truth.
    #[must_use]
    const fn truth_label(truth: RenderTruth) -> &'static str {
        match truth {
            RenderTruth::Green => "ok",
            RenderTruth::Yellow => "warn",
            RenderTruth::Red => "RED",
            RenderTruth::Unknown => "unknown",
        }
    }

    /// Compact one-line render for a narrow terminal. Always carries the trust +
    /// security signal — the narrow fallback never drops the safety information.
    #[must_use]
    pub fn render_compact(&self) -> String {
        let id = &hex32(&self.skill_id_hash_32)[..8];
        format!(
            "{id} [{truth}] {trust} sec={sec}",
            truth = Self::truth_label(self.render_truth()),
            trust = self.trust_label(),
            sec = self.security_score_bps,
        )
    }

    /// Full one-line render (wide terminal). Carries every listing field as a
    /// score/label — never the heavy manifest.
    #[must_use]
    pub fn render_full(&self) -> String {
        let id = &hex32(&self.skill_id_hash_32)[..12];
        format!(
            "{id} [{truth}] trust={trust} installs={inst} eval={eval} sec={sec} cap_diff={cap}",
            truth = Self::truth_label(self.render_truth()),
            trust = self.trust_label(),
            inst = self.verified_installs_u64,
            eval = self.eval_score_bps,
            sec = self.security_score_bps,
            cap = &hex32(&self.capability_diff_hash_32)[..8],
        )
    }
}

/// A sort weight for a render truth: lower is healthier, so security-failing
/// cards always sort last regardless of popularity.
const fn truth_rank(truth: RenderTruth) -> u8 {
    match truth {
        RenderTruth::Green => 0,
        RenderTruth::Yellow => 1,
        RenderTruth::Unknown => 2,
        RenderTruth::Red => 3,
    }
}

/// Why a card holds its rank (the ranking explanation surface).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RankExplanation {
    /// The card's render truth.
    pub truth: RenderTruth,
    /// Verified installs (the popularity input).
    pub verified_installs_u64: u64,
    /// Whether this card was held below more-popular cards because of a security
    /// / quarantine problem (popularity could not lift it).
    pub security_gated: bool,
}

/// §4.3 — a bounded list of skill cards with security-first ranking.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct SkillCardList {
    cards: Vec<SkillCardView>,
}

impl SkillCardList {
    /// An empty list.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Append a card.
    pub fn push(&mut self, card: SkillCardView) {
        self.cards.push(card);
    }

    /// The cards in insertion order.
    #[must_use]
    pub fn cards(&self) -> &[SkillCardView] {
        &self.cards
    }

    /// Number of cards.
    #[must_use]
    pub fn len(&self) -> usize {
        self.cards.len()
    }

    /// Whether the list is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.cards.is_empty()
    }

    /// Indices of the cards in display rank: healthiest first, then by verified
    /// installs (popularity) as a *tie-breaker only within the same health*. A
    /// quarantined / insecure card can never outrank a healthy one.
    #[must_use]
    pub fn ranked(&self) -> Vec<usize> {
        let mut idx: Vec<usize> = (0..self.cards.len()).collect();
        idx.sort_by(|&a, &b| {
            let ca = &self.cards[a];
            let cb = &self.cards[b];
            truth_rank(ca.render_truth())
                .cmp(&truth_rank(cb.render_truth()))
                .then(cb.verified_installs_u64.cmp(&ca.verified_installs_u64))
                .then(a.cmp(&b))
        });
        idx
    }

    /// The ranking explanation for card `i` (the position in insertion order).
    /// `security_gated` is true when a more-popular card sits *below* this one
    /// because the more-popular card failed security — i.e. popularity was
    /// overridden somewhere in the list.
    #[must_use]
    pub fn ranking_explanation(&self, i: usize) -> Option<RankExplanation> {
        let card = self.cards.get(i)?;
        let truth = card.render_truth();
        // A card is "security_gated" iff some other card with strictly more
        // installs has a worse (higher) truth rank — popularity did not win.
        let security_gated = self.cards.iter().any(|other| {
            other.verified_installs_u64 > card.verified_installs_u64
                && truth_rank(other.render_truth()) > truth_rank(truth)
        });
        Some(RankExplanation {
            truth,
            verified_installs_u64: card.verified_installs_u64,
            security_gated,
        })
    }

    /// Render a bounded page of compact card lines (narrow-terminal-safe),
    /// in ranked order. Never loads a manifest; `O(page)` only.
    #[must_use]
    pub fn render_compact_page(&self, page: usize, page_size: u16, rows: u16) -> Vec<String> {
        let ps = (page_size.max(1)) as usize;
        let ranked = self.ranked();
        let start = page.saturating_mul(ps);
        ranked
            .into_iter()
            .skip(start)
            .take(ps.min(rows as usize))
            .filter_map(|i| self.cards.get(i).map(SkillCardView::render_compact))
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn card(installs: u64, sec: u16, eval: u16, trust: OfficialTrustDecision) -> SkillCardView {
        SkillCardView::new(
            [1u8; 32], installs, eval, sec, [2u8; 32], [3u8; 32], [4u8; 32], trust,
        )
    }

    #[test]
    fn trusted_secure_complete_card_is_green() {
        let c = card(10, 9000, 9000, OfficialTrustDecision::OfficialTrusted);
        assert_eq!(c.render_truth(), RenderTruth::Green);
    }

    #[test]
    fn quarantined_card_is_red_even_with_huge_popularity() {
        let c = card(1_000_000, 9999, 9999, OfficialTrustDecision::Quarantined);
        assert_eq!(c.render_truth(), RenderTruth::Red);
    }

    #[test]
    fn low_security_card_is_red_even_if_trusted_and_popular() {
        let c = card(999_999, 1000, 9999, OfficialTrustDecision::OfficialTrusted);
        assert_eq!(c.render_truth(), RenderTruth::Red);
        assert!(!c.security_ok());
    }

    #[test]
    fn missing_field_renders_red() {
        // provenance hash zeroed -> incomplete -> red
        let mut c = card(10, 9000, 9000, OfficialTrustDecision::OfficialTrusted);
        c.provenance_hash_32 = [0u8; 32];
        assert!(!c.is_complete());
        assert_eq!(c.render_truth(), RenderTruth::Red);
    }

    #[test]
    fn local_only_secure_card_is_yellow_not_green() {
        let c = card(10, 9000, 9000, OfficialTrustDecision::LocalOnly);
        assert_eq!(c.render_truth(), RenderTruth::Yellow);
    }

    #[test]
    fn ranking_puts_healthy_above_popular_but_quarantined() {
        let mut list = SkillCardList::new();
        // index 0: wildly popular but quarantined (Red)
        list.push(card(
            1_000_000,
            9999,
            9999,
            OfficialTrustDecision::Quarantined,
        ));
        // index 1: modestly popular, healthy (Green)
        list.push(card(5, 9000, 9000, OfficialTrustDecision::OfficialTrusted));
        let ranked = list.ranked();
        assert_eq!(
            ranked[0], 1,
            "healthy card ranks first despite low popularity"
        );
        assert_eq!(
            ranked[1], 0,
            "quarantined card ranks last despite popularity"
        );
    }

    #[test]
    fn ranking_explanation_flags_security_gate() {
        let mut list = SkillCardList::new();
        list.push(card(
            1_000_000,
            1000,
            9999,
            OfficialTrustDecision::OfficialTrusted,
        )); // 0: popular but insecure (Red)
        list.push(card(5, 9000, 9000, OfficialTrustDecision::OfficialTrusted)); // 1: healthy (Green)
        // the healthy, less-popular card is gated above a more-popular insecure one
        let exp = list.ranking_explanation(1);
        assert_eq!(exp.map(|e| e.truth), Some(RenderTruth::Green));
        assert_eq!(
            exp.map(|e| e.security_gated),
            Some(true),
            "popularity was overridden by security"
        );
        // the insecure popular card is not itself security_gated (nothing more
        // popular sits below it)
        assert_eq!(
            list.ranking_explanation(0).map(|e| e.security_gated),
            Some(false)
        );
    }

    #[test]
    fn compact_render_always_carries_trust_and_security() {
        let c = card(10, 8000, 9000, OfficialTrustDecision::SelfHostedOnly);
        let line = c.render_compact();
        assert!(line.contains("self-hosted"));
        assert!(line.contains("sec=8000"));
    }

    #[test]
    fn render_page_is_bounded() {
        let mut list = SkillCardList::new();
        for i in 0..100 {
            list.push(card(i, 9000, 9000, OfficialTrustDecision::OfficialTrusted));
        }
        let page = list.render_compact_page(0, 16, 8);
        assert!(page.len() <= 8, "row-bounded render");
    }
}
