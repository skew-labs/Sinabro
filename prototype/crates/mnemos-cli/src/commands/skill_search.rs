//! Skill discovery flow: `sinabro skill search|inspect|recommend`.
//!
//! A CLI-first discovery surface over the Stage D signed catalog. Search turns
//! raw user intent into a ranked list of **lightweight** cards
//! ([`SkillCardSummary`]) — each carrying the verified-install count, eval,
//! security, compatibility, capability class, and the required permission diff —
//! plus a *ranking explanation* of why it placed where it did. The full manifest
//! / eval logs / provenance ([`SkillCardDetail`]) load only on an explicit
//! [`SkillDiscovery::inspect`] (progressive disclosure); search never
//! materializes a detail, and there is no hosted market page.
//!
//! Reuse (no reinvention): every datum and decision is a Stage D
//! `mnemos-e-skill` canonical type — [`SkillSearchQuery`] parsing, [`rank`] /
//! [`SkillRankScore`] scoring (security-over-popularity), the
//! [`SignedCatalogCache`] integrity/stale gate, the
//! [`crate::commands::skill_search::SkillDiscovery::search`] summary-only load
//! tier, [`progressive_inspect`] full detail, and the [`meets_security_floor`] /
//! [`auto_install_allowed`] recommendation policy. This module only
//! *orchestrates* them into a CLI flow and projects a render-safe view.
//!
//! `G-F-SKILL-REGISTRY`: search / inspect / recommend / ranking explanation /
//! lazy inspect are all covered. Offline + pure: no network, wallet, chain, gas,
//! or provider call on the hot path (the latency law; cached search p95 target
//! <= 150ms is met by an O(top_n) projection).
//!
//! Recommendation scope: the canonical [`mnemos_e_skill`] `Recommendation::build`
//! takes a `RecommendationContext` whose `gas_budget` is a `mnemos-d-move`
//! `GasBudgetMist` — a type the CLI crate cannot name without a *second* crate
//! edge (the locked edge is `e-skill` only). So the CLI `recommend` reuses the
//! canonical recommendation *policy* primitives ([`meets_security_floor`] +
//! [`auto_install_allowed`] + [`rank`] + permission preview) and preserves every
//! canonical invariant (security floor, permission preview, explicit confirm, no
//! auto-install) without the unconstructable aggregate.

use mnemos_e_skill::{
    CacheRefusal, CacheStatus, LoadTier, PermissionPreview, RankWeights, SearchParseError,
    SignedCatalogCache, SkillCardDetail, SkillCardSummary, SkillCatalogIndexEntry, SkillId,
    SkillRankScore, SkillSearchQuery, SkillSecurityState, auto_install_allowed, load_tier,
    meets_security_floor, progressive_inspect, rank, ranking_replay_hash,
};

/// Why a discovery search was refused before any rows were produced.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SkillSearchReject {
    /// The signed catalog cache failed its integrity check (recorded digest does
    /// not equal the recomputed digest) — a tampered/corrupt cache serves nothing.
    CacheIntegrityDrift,
    /// The raw query string did not parse.
    Query(SearchParseError),
}

/// A render-safe projection of *why* a skill ranked where it did. Built from the
/// canonical [`SkillRankScore`] so the explanation can never disagree with the
/// score. Popularity never overrides security: a gated-to-zero score is flagged.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RankingExplanation {
    /// The gated total (0 means blocked by the security/compatibility gate).
    pub total_u32: u32,
    /// Eval-axis component weight.
    pub eval_weight_u16: u16,
    /// Security-state component weight (0 for quarantined/revoked).
    pub security_weight_u16: u16,
    /// Compatibility component weight (0 for incompatible).
    pub compatibility_weight_u16: u16,
    /// Verified-install component weight (saturating-capped).
    pub verified_weight_u16: u16,
    /// `true` iff the skill was gated to a zero total (security/compat block).
    pub gated_to_zero: bool,
    /// A short, stable headline naming the dominant ranking factor.
    pub headline: &'static str,
}

impl RankingExplanation {
    /// Project a canonical [`SkillRankScore`] into a render-safe explanation. The
    /// headline names the dominant component in the documented weight priority
    /// (eval > security > compatibility > verified); a zero total is reported as a
    /// security/compatibility block that popularity cannot override.
    #[must_use]
    pub fn from_score(score: &SkillRankScore) -> Self {
        let gated_to_zero = score.total_u32 == 0;
        let headline = if gated_to_zero {
            "blocked: security/compatibility gate (popularity cannot override)"
        } else {
            let eval = score.eval_weight_u16;
            let security = score.security_weight_u16;
            let compat = score.compatibility_weight_u16;
            let verified = score.verified_weight_u16;
            let max = eval.max(security).max(compat).max(verified);
            if max == eval {
                "ranked by eval score"
            } else if max == security {
                "ranked by security state"
            } else if max == compat {
                "ranked by host compatibility"
            } else {
                "ranked by verified installs"
            }
        };
        Self {
            total_u32: score.total_u32,
            eval_weight_u16: score.eval_weight_u16,
            security_weight_u16: score.security_weight_u16,
            compatibility_weight_u16: score.compatibility_weight_u16,
            verified_weight_u16: score.verified_weight_u16,
            gated_to_zero,
            headline,
        }
    }
}

/// One discovery row: a lightweight card, its canonical rank score, the ranking
/// explanation, and whether the cache marks the package revoked (still shown for
/// discovery, but never installable).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SkillSearchRow {
    /// The lightweight catalog card (no full manifest / detail).
    pub card: SkillCardSummary,
    /// The canonical deterministic rank score.
    pub score: SkillRankScore,
    /// Why this skill ranked where it did.
    pub explanation: RankingExplanation,
    /// `true` iff the event stream revoked this package (discovery-visible,
    /// install-refused).
    pub revoked: bool,
}

/// The result of a discovery search: ranked lightweight rows, a stale-cache
/// warning, the load tier used (always [`LoadTier::Summary`] — proof that no full
/// detail was materialized), and a replay-stable ordering hash.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SkillSearchResult {
    /// Ranked rows, best first, at most `top_n`.
    pub rows: Vec<SkillSearchRow>,
    /// `true` iff the cache is behind the live registry head (discovery is still
    /// served; install/use must refresh first).
    pub stale_warning: bool,
    /// The load tier the search used — always [`LoadTier::Summary`].
    pub load_tier: LoadTier,
    /// Replay-stable hash over the shown ranked order.
    pub replay_hash_32: [u8; 32],
}

/// One recommendation candidate row. Mirrors the canonical recommendation
/// invariants: a permission preview is always present and confirmation is always
/// required (there is no auto-install path).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SkillRecommendationRow {
    /// The recommended skill.
    pub skill: SkillId,
    /// Its canonical rank score.
    pub score: SkillRankScore,
    /// The permission diff preview shown in this row (never omitted).
    pub permission_preview: PermissionPreview,
    /// Always `true`: use / install needs explicit user confirmation.
    pub requires_user_confirm: bool,
    /// Always `true` for an included row: it meets the requested security floor.
    pub meets_security_floor: bool,
}

/// An agent recommendation over the cached catalog. Reuses the canonical
/// recommendation policy: every candidate requires confirmation and
/// [`auto_install_allowed`] is always `false`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SkillRecommendation {
    /// The recommended candidates, best first.
    pub candidates: Vec<SkillRecommendationRow>,
    /// Always `false`: a recommendation never installs or uses a skill on its own.
    pub auto_install_allowed: bool,
    /// The minimum security state a recommended skill had to meet.
    pub security_floor: SkillSecurityState,
}

/// The CLI-first skill discovery flow over an injected signed catalog cache. Pure
/// projection: holds only a borrow of the cache, the live registry watermark, and
/// the ranking weights; performs no I/O.
#[derive(Clone, Copy, Debug)]
pub struct SkillDiscovery<'a> {
    cache: &'a SignedCatalogCache,
    live_watermark_32: [u8; 32],
    weights: RankWeights,
}

impl<'a> SkillDiscovery<'a> {
    /// Open a discovery flow over `cache`, judged fresh against `live_watermark_32`,
    /// using the documented default rank weights.
    #[must_use]
    pub fn new(cache: &'a SignedCatalogCache, live_watermark_32: [u8; 32]) -> Self {
        Self {
            cache,
            live_watermark_32,
            weights: RankWeights::default_weights(),
        }
    }

    /// Open a discovery flow with explicit rank weights.
    #[must_use]
    pub fn with_weights(
        cache: &'a SignedCatalogCache,
        live_watermark_32: [u8; 32],
        weights: RankWeights,
    ) -> Self {
        Self {
            cache,
            live_watermark_32,
            weights,
        }
    }

    /// Collect the cache's index entries (the search/rank input). Reads only the
    /// already-loaded cache rows — no manifest / detail is materialized here.
    fn entries(&self) -> Vec<SkillCatalogIndexEntry> {
        self.cache
            .cache()
            .entries()
            .iter()
            .map(|ce| ce.entry.clone())
            .collect()
    }

    /// Search the catalog for `raw_query`, returning at most `top_n` ranked
    /// lightweight rows. Refuses a drift cache (serves nothing); warns (does not
    /// refuse) on a stale cache. Only summaries are built — the full detail is
    /// never materialized here (lazy: see [`Self::inspect`]).
    pub fn search(
        &self,
        raw_query: &str,
        top_n: usize,
    ) -> Result<SkillSearchResult, SkillSearchReject> {
        if !self.cache.integrity_ok() {
            return Err(SkillSearchReject::CacheIntegrityDrift);
        }
        let query = SkillSearchQuery::parse(raw_query).map_err(SkillSearchReject::Query)?;
        let stale_warning = matches!(
            self.cache.status(self.live_watermark_32),
            CacheStatus::Stale
        );

        let entries = self.entries();
        let ranked = rank(&entries, &query, &self.weights);
        let shown: Vec<SkillRankScore> = ranked.into_iter().take(top_n).collect();
        let replay_hash_32 = ranking_replay_hash(&shown);

        let mut rows: Vec<SkillSearchRow> = Vec::with_capacity(shown.len());
        for score in &shown {
            if let Some(ce) = self.cache.cache().lookup(score.entry) {
                rows.push(SkillSearchRow {
                    card: SkillCardSummary::from_index_entry(&ce.entry),
                    score: *score,
                    explanation: RankingExplanation::from_score(score),
                    revoked: ce.revoked,
                });
            }
        }
        Ok(SkillSearchResult {
            rows,
            stale_warning,
            load_tier: load_tier(false),
            replay_hash_32,
        })
    }

    /// Load the full [`SkillCardDetail`] for one selected skill — the only path
    /// that materializes the heavy detail (progressive disclosure). Serves a fresh
    /// or stale cache, never a drifted one. `malicious_fixture_pass` is the
    /// red-team verdict for the skill.
    pub fn inspect(
        &self,
        skill: SkillId,
        malicious_fixture_pass: bool,
    ) -> Result<SkillCardDetail, CacheRefusal> {
        progressive_inspect(self.cache, skill, malicious_fixture_pass)
    }

    /// Build an agent recommendation: rank the cached catalog for `raw_query`,
    /// keep up to `top_n` candidates that meet `security_floor` (the canonical
    /// [`meets_security_floor`] policy), and attach a permission preview +
    /// confirmation requirement to each. Installs nothing
    /// ([`SkillRecommendation::auto_install_allowed`] is always `false`).
    pub fn recommend(
        &self,
        raw_query: &str,
        security_floor: SkillSecurityState,
        top_n: usize,
    ) -> Result<SkillRecommendation, SkillSearchReject> {
        if !self.cache.integrity_ok() {
            return Err(SkillSearchReject::CacheIntegrityDrift);
        }
        let query = SkillSearchQuery::parse(raw_query).map_err(SkillSearchReject::Query)?;
        let entries = self.entries();
        let ranked = rank(&entries, &query, &self.weights);

        let mut candidates: Vec<SkillRecommendationRow> = Vec::new();
        for score in ranked {
            if candidates.len() >= top_n {
                break;
            }
            if let Some(ce) = self.cache.cache().lookup(score.entry) {
                if !meets_security_floor(ce.entry.security, security_floor) {
                    continue;
                }
                candidates.push(SkillRecommendationRow {
                    skill: score.entry,
                    score,
                    permission_preview: PermissionPreview::from_diff(&ce.entry.capability_diff),
                    requires_user_confirm: true,
                    meets_security_floor: true,
                });
            }
        }
        Ok(SkillRecommendation {
            candidates,
            auto_install_allowed: auto_install_allowed(),
            security_floor,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mnemos_e_skill::{
        CapabilityDiff, CatalogCache, CompatibilityDecision, ProvenanceNode, SkillEvalScore,
        SkillPackageDigest32, SkillSecurityState, SuiAddress, reproducible_command_hash,
    };

    fn eval() -> SkillEvalScore {
        SkillEvalScore {
            rust_u16: 9_000,
            move_u16: 9_000,
            prover_u16: 9_000,
            gas_u16: 9_000,
            security_u16: 9_000,
            korean_u16: 9_000,
            reproducible_command_hash_32: reproducible_command_hash(&["cargo test"]),
        }
    }

    fn entry(
        skill: u16,
        security: SkillSecurityState,
        compat: CompatibilityDecision,
        added_mask: u64,
    ) -> SkillCatalogIndexEntry {
        let package = SkillPackageDigest32::new([(skill as u8).wrapping_add(1); 32]);
        SkillCatalogIndexEntry {
            skill: SkillId(skill),
            package,
            name_hash_32: [0x99; 32],
            downloads_u64: 100,
            verified_installs_u64: 10,
            active_users_u64: 2,
            eval: eval(),
            security,
            compatibility: compat,
            capability_diff: CapabilityDiff::new(added_mask, 0, Vec::new()),
            provenance: ProvenanceNode {
                skill: SkillId(skill),
                package,
                parent: None,
                author: SuiAddress::new([0x11; 32]),
                provenance_depth_u16: 0,
            },
        }
    }

    fn signed(entries: &[SkillCatalogIndexEntry]) -> SignedCatalogCache {
        SignedCatalogCache::sign(CatalogCache::rebuild(entries, &[]))
    }

    #[test]
    fn search_returns_ranked_summaries() {
        let cache = signed(&[
            entry(
                1,
                SkillSecurityState::Quarantined,
                CompatibilityDecision::Compatible,
                0,
            ),
            entry(
                2,
                SkillSecurityState::AuditPass,
                CompatibilityDecision::Compatible,
                0,
            ),
        ]);
        let live = cache.cache().watermark();
        let disc = SkillDiscovery::new(&cache, live);
        let result = disc.search("", 10);
        assert!(result.is_ok());
        if let Ok(r) = result {
            assert_eq!(r.load_tier, LoadTier::Summary);
            assert!(!r.stale_warning);
            assert_eq!(r.rows.len(), 2);
            // AuditPass ranks above the quarantined (gated-to-zero) skill.
            assert_eq!(r.rows[0].card.skill.0, 2);
            assert_ne!(r.replay_hash_32, [0u8; 32]);
            let quarantined = r.rows.iter().find(|row| row.card.skill.0 == 1);
            assert!(quarantined.is_some());
            if let Some(q) = quarantined {
                assert!(q.explanation.gated_to_zero);
                assert_eq!(q.score.total_u32, 0);
            }
        }
    }

    #[test]
    fn lazy_disclosure_search_summary_inspect_full() {
        let cache = signed(&[entry(
            7,
            SkillSecurityState::AuditPass,
            CompatibilityDecision::Compatible,
            0,
        )]);
        let live = cache.cache().watermark();
        let disc = SkillDiscovery::new(&cache, live);
        // Search uses the Summary tier only (no full detail built).
        let result = disc.search("", 10);
        assert!(result.is_ok());
        if let Ok(r) = result {
            assert_eq!(r.load_tier, LoadTier::Summary);
        }
        // Inspect is the only path that materializes the heavy detail.
        let detail = disc.inspect(SkillId(7), true);
        assert!(detail.is_ok());
        if let Ok(d) = detail {
            assert!(d.malicious_fixture_pass);
            assert_ne!(d.reproducible_command_hash_32, [0u8; 32]);
        }
    }

    #[test]
    fn recommend_security_floor() {
        let cache = signed(&[
            entry(
                1,
                SkillSecurityState::SandboxPass,
                CompatibilityDecision::Compatible,
                0,
            ),
            entry(
                2,
                SkillSecurityState::AuditPass,
                CompatibilityDecision::Compatible,
                0,
            ),
        ]);
        let live = cache.cache().watermark();
        let disc = SkillDiscovery::new(&cache, live);

        // Floor = Unknown: both included; never auto-install; always confirm.
        let rec = disc.recommend("", SkillSecurityState::Unknown, 10);
        assert!(rec.is_ok());
        if let Ok(rec) = rec {
            assert!(!rec.auto_install_allowed);
            assert_eq!(rec.candidates.len(), 2);
            assert!(rec.candidates.iter().all(|c| c.requires_user_confirm));
        }

        // Floor = AuditPass: excludes the SandboxPass skill.
        let rec2 = disc.recommend("", SkillSecurityState::AuditPass, 10);
        assert!(rec2.is_ok());
        if let Ok(rec2) = rec2 {
            assert_eq!(rec2.candidates.len(), 1);
            assert_eq!(rec2.candidates[0].skill.0, 2);
        }
    }

    #[test]
    fn ranking_explanation_present() {
        let cache = signed(&[entry(
            2,
            SkillSecurityState::AuditPass,
            CompatibilityDecision::Compatible,
            0,
        )]);
        let live = cache.cache().watermark();
        let disc = SkillDiscovery::new(&cache, live);
        let result = disc.search("", 10);
        assert!(result.is_ok());
        if let Ok(r) = result {
            assert!(!r.rows.is_empty());
            if let Some(row) = r.rows.first() {
                assert!(!row.explanation.gated_to_zero);
                assert!(!row.explanation.headline.is_empty());
            }
        }
    }

    #[test]
    fn stale_cache_still_serves_discovery() {
        let cache = signed(&[entry(
            1,
            SkillSecurityState::AuditPass,
            CompatibilityDecision::Compatible,
            0,
        )]);
        // A live watermark that differs from the cache's makes it stale.
        let disc = SkillDiscovery::new(&cache, [0xEE; 32]);
        let result = disc.search("", 10);
        assert!(result.is_ok());
        if let Ok(r) = result {
            assert!(r.stale_warning);
            assert_eq!(r.rows.len(), 1);
        }
    }

    #[test]
    fn drift_cache_refused() {
        let entries = [entry(
            1,
            SkillSecurityState::AuditPass,
            CompatibilityDecision::Compatible,
            0,
        )];
        let cache = CatalogCache::rebuild(&entries, &[]);
        // Bind a wrong recorded digest -> integrity fails.
        let drifted = SignedCatalogCache::from_parts(cache, [0u8; 32]);
        let disc = SkillDiscovery::new(&drifted, [0u8; 32]);
        assert_eq!(
            disc.search("", 10),
            Err(SkillSearchReject::CacheIntegrityDrift)
        );
        assert_eq!(
            disc.recommend("", SkillSecurityState::Unknown, 10),
            Err(SkillSearchReject::CacheIntegrityDrift)
        );
    }

    #[test]
    fn bad_query_rejected() {
        let cache = signed(&[entry(
            1,
            SkillSecurityState::AuditPass,
            CompatibilityDecision::Compatible,
            0,
        )]);
        let live = cache.cache().watermark();
        let disc = SkillDiscovery::new(&cache, live);
        let r = disc.search("price:cheap", 10);
        assert!(
            matches!(r, Err(SkillSearchReject::Query(_))),
            "expected a query parse reject, got {r:?}"
        );
    }
}
