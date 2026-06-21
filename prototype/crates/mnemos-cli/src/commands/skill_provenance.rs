//! Provenance / registry preview (atom #442 · F.4.7): `sinabro registry|provenance`.
//!
//! A read-only CLI VIEW over a skill's content-addressed provenance: the fork
//! graph / ancestor chain, the package digest, the security + review state, the
//! official-trust verdict, and a reputation score — all visible BEFORE a publish
//! / use. It is a projection, never a registry mutation: no network fetch, no
//! upload, no wallet / chain / gas (the latency law; the graph render is
//! `O(nodes)` over a cached chain, criterion p95 <= 100ms for 100 nodes).
//!
//! `G-F-SKILL-REGISTRY`: an ancestor chain that is missing a link or contains a
//! cycle renders [`RenderTruth::Red`] (the canonical [`validate_ancestor_chain`]
//! gate); a quarantined / revoked security state or a rejected / quarantined
//! review state also renders `Red`; reputation never lifts an unsafe card.
//!
//! Reuse (no reinvention): the lineage primitive is the Stage D [`ProvenanceNode`]
//! plus [`validate_ancestor_chain`]; the reputation is the canonical
//! [`SkillRankScore`]; the review state is [`ReviewState`]; the trust verdict is
//! the g-wallet [`OfficialTrustDecision`]; the red/yellow/green verdict reuses the
//! cockpit [`RenderTruth`]. This module mints no new canonical type — there is no
//! `SkillProvenance`; a provenance graph IS a `&[ProvenanceNode]` ancestor chain,
//! exactly as the canonical validator models it.

use crate::hex32;
use crate::tui::RenderTruth;
use mnemos_e_skill::{
    ProvenanceNode, ReviewState, SkillPackageDigest32, SkillRankScore, SkillSecurityState,
    validate_ancestor_chain,
};
use mnemos_g_wallet::OfficialTrustDecision;

/// Why a provenance card could not be built.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SkillProvenanceReject {
    /// The ancestor chain was empty — there is no leaf to anchor a provenance
    /// view on.
    EmptyChain,
}

/// First 8 hex chars of a 32-byte hash, for a compact, redaction-safe display id.
fn hex8(bytes: &[u8; 32]) -> String {
    crate::hex32(bytes)[..8].to_string()
}

/// A short, colorless label for a review state.
const fn review_label(review: ReviewState) -> &'static str {
    match review {
        ReviewState::Pending => "pending",
        ReviewState::Approved => "approved",
        ReviewState::Rejected => "rejected",
        ReviewState::Quarantined => "quarantined",
    }
}

/// A short, colorless label for an official-trust verdict.
const fn trust_label(trust: OfficialTrustDecision) -> &'static str {
    match trust {
        OfficialTrustDecision::OfficialTrusted => "trusted",
        OfficialTrustDecision::LocalOnly => "local",
        OfficialTrustDecision::SelfHostedOnly => "self-hosted",
        OfficialTrustDecision::Quarantined => "quarantined",
        OfficialTrustDecision::Revoked => "revoked",
    }
}

/// A short, colorless label for a render truth.
const fn truth_label(truth: RenderTruth) -> &'static str {
    match truth {
        RenderTruth::Green => "ok",
        RenderTruth::Yellow => "warn",
        RenderTruth::Red => "RED",
        RenderTruth::Unknown => "unknown",
    }
}

/// A provenance / registry preview card for one skill package. Carries the
/// validated-lineage summary plus the security / review / trust / reputation
/// signals a user must see before a publish or use.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SkillProvenanceCard {
    /// The leaf package digest the lineage terminates at.
    pub package: SkillPackageDigest32,
    /// Depth of the leaf from its root (`0` means the leaf is itself a root).
    pub depth_u16: u16,
    /// Number of nodes in the ancestor chain (leaf..=root).
    pub ancestor_count: usize,
    /// Whether the ancestor chain passed [`validate_ancestor_chain`]. A `false`
    /// here (missing ancestor / cycle / malformed node) forces a `Red` truth.
    pub chain_valid: bool,
    /// The package security / audit state.
    pub security: SkillSecurityState,
    /// The maintainer review state.
    pub review: ReviewState,
    /// The official-trust verdict.
    pub trust: OfficialTrustDecision,
    /// The reputation total (`0` for a quarantined / revoked / incompatible skill).
    pub reputation_total_u32: u32,
}

impl SkillProvenanceCard {
    /// Build a provenance card from a leaf-first ancestor `chain` plus the
    /// package's security / review / trust state and its reputation score. The
    /// chain is validated by the canonical [`validate_ancestor_chain`]; an invalid
    /// chain still builds a card (so the user SEES the bad lineage) but with
    /// `chain_valid = false`, which renders `Red`. An empty chain has no leaf and
    /// is refused.
    pub fn build(
        chain: &[ProvenanceNode],
        security: SkillSecurityState,
        review: ReviewState,
        trust: OfficialTrustDecision,
        rank: &SkillRankScore,
    ) -> Result<Self, SkillProvenanceReject> {
        let leaf = chain.first().ok_or(SkillProvenanceReject::EmptyChain)?;
        let chain_valid = validate_ancestor_chain(chain);
        Ok(Self {
            package: leaf.package,
            depth_u16: leaf.provenance_depth_u16,
            ancestor_count: chain.len(),
            chain_valid,
            security,
            review,
            trust,
            reputation_total_u32: rank.total_u32,
        })
    }

    /// The render truth, encoding that lineage / security / review dominate
    /// reputation:
    ///
    /// * `Red`    — invalid chain, quarantined / revoked security, or rejected /
    ///   quarantined review;
    /// * `Yellow` — a pending review or a not-officially-trusted verdict;
    /// * `Green`  — valid chain, installable security, approved review, trusted.
    #[must_use]
    pub fn render_truth(&self) -> RenderTruth {
        if !self.chain_valid
            || matches!(
                self.security,
                SkillSecurityState::Quarantined | SkillSecurityState::Revoked
            )
            || matches!(
                self.review,
                ReviewState::Rejected | ReviewState::Quarantined
            )
        {
            return RenderTruth::Red;
        }
        if matches!(self.review, ReviewState::Pending) || !self.trust.is_trusted() {
            return RenderTruth::Yellow;
        }
        RenderTruth::Green
    }

    /// Always `false`: a provenance preview is never a commerce / checkout surface.
    #[must_use]
    pub const fn is_commerce(&self) -> bool {
        false
    }

    /// Render the card as bounded, colorless text lines — never a price / checkout
    /// field. Deterministic for snapshot stability.
    #[must_use]
    pub fn render(&self, rows: u16) -> Vec<String> {
        let lines = vec![
            format!("package={}", hex8(self.package.as_bytes())),
            format!("depth={}", self.depth_u16),
            format!("ancestors={}", self.ancestor_count),
            format!("chain_valid={}", self.chain_valid),
            format!("security={}", self.security.class_label()),
            format!("review={}", review_label(self.review)),
            format!("trust={}", trust_label(self.trust)),
            format!("reputation={}", self.reputation_total_u32),
            format!("truth={}", truth_label(self.render_truth())),
        ];
        lines.into_iter().take(rows as usize).collect()
    }
}

/// Render a leaf-first fork graph as bounded, colorless lines — one line per node
/// (`depth`, package digest prefix, parent digest prefix or `root`). `O(rows)`:
/// a 100-node cached chain renders well within the p95 <= 100ms criterion, and
/// the page is bounded so a deep lineage never floods the terminal.
#[must_use]
pub fn render_fork_graph(chain: &[ProvenanceNode], rows: u16) -> Vec<String> {
    chain
        .iter()
        .take(rows as usize)
        .map(|node| {
            let package = &hex32(node.package.as_bytes())[..8];
            match node.parent {
                Some(parent) => {
                    let parent = &hex32(parent.as_bytes())[..8];
                    format!("d{} {package} <- {parent}", node.provenance_depth_u16)
                }
                None => format!("d{} {package} <- root", node.provenance_depth_u16),
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use mnemos_e_skill::{SkillId, SuiAddress};

    fn addr(b: u8) -> SuiAddress {
        SuiAddress::new([b; 32])
    }
    fn pkg(b: u8) -> SkillPackageDigest32 {
        SkillPackageDigest32::new([b; 32])
    }

    fn root() -> ProvenanceNode {
        ProvenanceNode {
            skill: SkillId(1),
            package: pkg(0xA0),
            parent: None,
            author: addr(0x11),
            provenance_depth_u16: 0,
        }
    }
    fn leaf() -> ProvenanceNode {
        ProvenanceNode {
            skill: SkillId(1),
            package: pkg(0xB0),
            parent: Some(pkg(0xA0)),
            author: addr(0x22),
            provenance_depth_u16: 1,
        }
    }
    fn rank(total: u32) -> SkillRankScore {
        SkillRankScore {
            entry: SkillId(1),
            total_u32: total,
            eval_weight_u16: 0,
            security_weight_u16: 0,
            compatibility_weight_u16: 0,
            verified_weight_u16: 0,
        }
    }

    /// Build a card without `.expect()` / `.unwrap()` (the crate clippy deny-list
    /// applies to test targets too, matching the sibling skill_* command modules).
    fn build_card(
        chain: &[ProvenanceNode],
        security: SkillSecurityState,
        review: ReviewState,
        trust: OfficialTrustDecision,
        total: u32,
    ) -> Result<SkillProvenanceCard, SkillProvenanceReject> {
        SkillProvenanceCard::build(chain, security, review, trust, &rank(total))
    }

    #[test]
    fn valid_chain_card_is_green_when_approved_and_trusted() {
        let chain = [leaf(), root()];
        let r = build_card(
            &chain,
            SkillSecurityState::AuditPass,
            ReviewState::Approved,
            OfficialTrustDecision::OfficialTrusted,
            5000,
        );
        assert!(r.is_ok());
        if let Ok(card) = r {
            assert!(card.chain_valid);
            assert_eq!(card.ancestor_count, 2);
            assert_eq!(card.depth_u16, 1);
            assert_eq!(card.render_truth(), RenderTruth::Green);
        }
    }

    #[test]
    fn missing_ancestor_renders_red() {
        // The leaf's parent points to a digest that is not the next node's
        // package — the ancestor link is missing.
        let bad_leaf = ProvenanceNode {
            parent: Some(pkg(0xFF)),
            ..leaf()
        };
        let chain = [bad_leaf, root()];
        let r = build_card(
            &chain,
            SkillSecurityState::AuditPass,
            ReviewState::Approved,
            OfficialTrustDecision::OfficialTrusted,
            5000,
        );
        assert!(r.is_ok());
        if let Ok(card) = r {
            assert!(!card.chain_valid);
            assert_eq!(
                card.render_truth(),
                RenderTruth::Red,
                "a missing ancestor must render red"
            );
        }
    }

    #[test]
    fn cycle_renders_red() {
        // Two nodes with the same package digest -> the cycle-reject fires.
        let cyclic = ProvenanceNode {
            skill: SkillId(1),
            package: pkg(0xC0),
            parent: Some(pkg(0xC0)),
            author: addr(0x33),
            provenance_depth_u16: 1,
        };
        let chain = [cyclic, root()];
        let r = build_card(
            &chain,
            SkillSecurityState::AuditPass,
            ReviewState::Approved,
            OfficialTrustDecision::OfficialTrusted,
            1,
        );
        assert!(r.is_ok());
        if let Ok(card) = r {
            assert!(!card.chain_valid);
            assert_eq!(
                card.render_truth(),
                RenderTruth::Red,
                "a cycle must render red"
            );
        }
    }

    #[test]
    fn empty_chain_rejected() {
        let chain: [ProvenanceNode; 0] = [];
        assert_eq!(
            build_card(
                &chain,
                SkillSecurityState::Unknown,
                ReviewState::Pending,
                OfficialTrustDecision::LocalOnly,
                0,
            ),
            Err(SkillProvenanceReject::EmptyChain)
        );
    }

    #[test]
    fn quarantined_security_renders_red() {
        let chain = [leaf(), root()];
        let truth = build_card(
            &chain,
            SkillSecurityState::Quarantined,
            ReviewState::Approved,
            OfficialTrustDecision::OfficialTrusted,
            5000,
        )
        .map(|c| c.render_truth());
        assert_eq!(truth, Ok(RenderTruth::Red));
    }

    #[test]
    fn pending_review_or_untrusted_is_yellow() {
        let chain = [leaf(), root()];
        let pending = build_card(
            &chain,
            SkillSecurityState::AuditPass,
            ReviewState::Pending,
            OfficialTrustDecision::OfficialTrusted,
            5000,
        )
        .map(|c| c.render_truth());
        assert_eq!(pending, Ok(RenderTruth::Yellow));
        let untrusted = build_card(
            &chain,
            SkillSecurityState::AuditPass,
            ReviewState::Approved,
            OfficialTrustDecision::LocalOnly,
            5000,
        )
        .map(|c| c.render_truth());
        assert_eq!(untrusted, Ok(RenderTruth::Yellow));
    }

    #[test]
    fn provenance_card_snapshot_is_deterministic() {
        let chain = [leaf(), root()];
        let r = build_card(
            &chain,
            SkillSecurityState::AuditPass,
            ReviewState::Approved,
            OfficialTrustDecision::OfficialTrusted,
            5000,
        );
        assert!(r.is_ok());
        if let Ok(card) = r {
            let a = card.render(16);
            let b = card.render(16);
            assert_eq!(a, b, "render is deterministic (snapshot-stable)");
            assert!(a.iter().any(|l| l.starts_with("package=")));
            assert!(a.iter().any(|l| l == "ancestors=2"));
            assert!(a.iter().any(|l| l == "truth=ok"));
        }
    }

    #[test]
    fn fork_graph_render_is_bounded() {
        // A 100-node chain renders in O(rows); the page never exceeds `rows`.
        let chain: Vec<ProvenanceNode> = (0..100u16)
            .map(|i| ProvenanceNode {
                skill: SkillId(1),
                package: pkg(i as u8),
                parent: Some(pkg((i + 1) as u8)),
                author: addr(0x11),
                provenance_depth_u16: 99 - i,
            })
            .collect();
        let lines = render_fork_graph(&chain, 8);
        assert_eq!(lines.len(), 8, "render is row-bounded");
    }

    #[test]
    fn no_commerce_scan() {
        let chain = [leaf(), root()];
        let r = build_card(
            &chain,
            SkillSecurityState::AuditPass,
            ReviewState::Approved,
            OfficialTrustDecision::OfficialTrusted,
            5000,
        );
        assert!(r.is_ok());
        if let Ok(card) = r {
            assert!(!card.is_commerce());
            const FORBIDDEN: &[&str] = &[
                "price", "pay", "buy", "sell", "checkout", "refund", "fee", "cost", "$",
            ];
            for line in card.render(32) {
                for bad in FORBIDDEN {
                    assert!(
                        !line.contains(bad),
                        "commerce token {bad} in render: {line}"
                    );
                }
            }
        }
        let report = mnemos_e_skill::scan_surfaces(
            &["registry", "provenance", "graph", "ancestors"],
            &["SkillProvenanceCard", "SkillProvenanceReject"],
            &["--depth", "--rows"],
            "Preview a skill's provenance fork graph, ancestor chain, review state, and reputation offline.",
        );
        assert!(report.is_clean(), "no-commerce surface scan must be clean");
    }
}
