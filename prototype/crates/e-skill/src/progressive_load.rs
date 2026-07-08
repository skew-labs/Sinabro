//! Progressive-disclosure loading policy for the skill catalog.
//!
//! ## Load policy
//!
//! Search loads only lightweight cards; the full manifest / README / fixtures /
//! WASM metadata / eval logs load only for a selected candidate.
//! [`progressive_search`] returns at most `top_n` [`SkillCardSummary`]
//! and **never** builds a [`SkillCardDetail`]; [`progressive_inspect`] is the
//! only path that materializes the full detail. This keeps a 10k+ catalog
//! usable in a terminal (top-20 search p95 ≤ 100ms at 10k:
//! search touches only the lightweight cards, no per-result manifest load).
//!
//! ## Reuse
//!
//! Cards are the [`SkillCardSummary`] / [`SkillCardDetail`]; the source is
//! a [`SignedCatalogCache`]. A signature-drifted cache serves nothing
//! ([`CacheRefusal::SignatureDrift`]); a stale cache still serves discovery
//! (offline fallback) with a [`ProgressiveSearchResult::stale_warning`].
//! Ranking is NOT done here; this module only governs the
//! load-tier (summary vs full) and the result cap.
//!
//! ## Offline boundary
//!
//! Pure, offline reads; no network, wallet, secret, or chain action.

#![deny(missing_docs)]

extern crate alloc;

use alloc::vec::Vec;

use crate::catalog_cache::{CacheRefusal, CacheStatus, SignedCatalogCache};
use crate::catalog_card::{SkillCardDetail, SkillCardSummary};
use crate::manifest::SkillId;

// ===========================================================================
// 1. LoadTier — the explicit load policy
// ===========================================================================

/// Which load tier an operation uses. Search is always [`Self::Summary`];
/// inspect is [`Self::Full`].
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum LoadTier {
    /// Lightweight card only (name hash, counters, eval, security, capability
    /// class + diff). No manifest / README / fixtures / WASM / eval logs.
    Summary,
    /// Full detail: the summary plus reproducible-command hash, malicious-
    /// fixture verdict, audit state, and provenance.
    Full,
}

/// The load tier for an operation: `inspect` loads [`LoadTier::Full`],
/// everything else (search/list) loads [`LoadTier::Summary`].
#[inline]
#[must_use]
pub const fn load_tier(is_inspect: bool) -> LoadTier {
    if is_inspect {
        LoadTier::Full
    } else {
        LoadTier::Summary
    }
}

// ===========================================================================
// 2. ProgressiveSearchResult
// ===========================================================================

/// The result of a progressive search: at most `top_n` lightweight summaries,
/// plus a stale-cache warning flag.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProgressiveSearchResult {
    /// The lightweight cards (never full detail).
    pub summaries: Vec<SkillCardSummary>,
    /// `true` iff the cache is behind the live registry head — discovery is
    /// still served, but the operator should refresh before install/use.
    pub stale_warning: bool,
}

// ===========================================================================
// 3. progressive_search / progressive_inspect
// ===========================================================================

/// Search the cache, returning at most `top_n` lightweight [`SkillCardSummary`]
/// cards. A signature-drifted cache serves nothing; a stale cache serves
/// discovery with `stale_warning = true`. Only `top_n` summaries are
/// materialized (no full detail), so a huge catalog never stalls a listing.
pub fn progressive_search(
    cache: &SignedCatalogCache,
    live_watermark_32: [u8; 32],
    top_n: usize,
) -> Result<ProgressiveSearchResult, CacheRefusal> {
    if !cache.integrity_ok() {
        return Err(CacheRefusal::SignatureDrift);
    }
    let stale_warning = matches!(cache.status(live_watermark_32), CacheStatus::Stale);
    let summaries: Vec<SkillCardSummary> = cache
        .cache()
        .entries()
        .iter()
        .take(top_n)
        .map(|ce| SkillCardSummary::from_index_entry(&ce.entry))
        .collect();
    Ok(ProgressiveSearchResult {
        summaries,
        stale_warning,
    })
}

/// Load the full [`SkillCardDetail`] for one selected skill (the only path that
/// materializes the heavy detail). Serves a fresh or stale cache (discovery),
/// but never a signature-drifted one. `malicious_fixture_pass` is the
/// adversarial-fixture verdict for the skill.
pub fn progressive_inspect(
    cache: &SignedCatalogCache,
    skill: SkillId,
    malicious_fixture_pass: bool,
) -> Result<SkillCardDetail, CacheRefusal> {
    let ce = cache.lookup_for_search(skill)?;
    Ok(SkillCardDetail::inspect(&ce.entry, malicious_fixture_pass))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use crate::catalog_cache::CatalogCache;
    use crate::catalog_index::SkillCatalogIndexEntry;
    use crate::compat::{HostEnvironment, MnemosVersion};
    use crate::package::SkillPackageDigest32;
    use crate::verify::sample_valid_package_toml;

    fn host() -> HostEnvironment {
        HostEnvironment {
            mnemos_version: MnemosVersion::new(0, 2, 0),
            chain_env_hash_32: [0xC0; 32],
            os_gpu_hash_32: [0x05; 32],
            toolchain_hash_32: [0x70; 32],
            model_provider_hash_32: [0x30; 32],
        }
    }

    fn template() -> SkillCatalogIndexEntry {
        SkillCatalogIndexEntry::from_package_toml(
            &sample_valid_package_toml(),
            &host(),
            [0x99; 32],
            10,
            7,
            3,
        )
        .expect("template entry")
    }

    fn entries(n: u64) -> Vec<SkillCatalogIndexEntry> {
        let base = template();
        (0..n)
            .map(|i| {
                let mut e = base.clone();
                let mut pk = [0u8; 32];
                pk[..8].copy_from_slice(&i.to_le_bytes());
                e.package = SkillPackageDigest32::new(pk);
                e.skill = SkillId((i % 60_000) as u16);
                e
            })
            .collect()
    }

    fn signed(entries: &[SkillCatalogIndexEntry]) -> SignedCatalogCache {
        SignedCatalogCache::sign(CatalogCache::rebuild(entries, &[]))
    }

    #[test]
    fn search_returns_summaries_not_details() {
        let es = entries(5);
        let cache = signed(&es);
        let live = cache.cache().watermark();
        let result = progressive_search(&cache, live, 20).expect("search");
        // Result is summaries; the type system guarantees no detail was loaded.
        assert_eq!(result.summaries.len(), 5);
        assert!(!result.stale_warning);
        assert_eq!(load_tier(false), LoadTier::Summary);
    }

    #[test]
    fn inspect_loads_full_detail() {
        let es = entries(3);
        let cache = signed(&es);
        let detail = progressive_inspect(&cache, es[0].skill, true).expect("inspect");
        assert!(detail.malicious_fixture_pass);
        // Full detail carries the reproducible-command hash (a heavy field).
        assert_eq!(
            detail.reproducible_command_hash_32,
            es[0].eval.reproducible_command_hash_32
        );
        assert_eq!(load_tier(true), LoadTier::Full);
    }

    #[test]
    fn cache_hit_on_fresh() {
        let es = entries(4);
        let cache = signed(&es);
        let live = cache.cache().watermark();
        assert!(progressive_search(&cache, live, 10).is_ok());
        assert!(progressive_inspect(&cache, es[0].skill, false).is_ok());
    }

    #[test]
    fn stale_warn_when_behind_live_head() {
        let es = entries(4);
        let cache = signed(&es);
        // A different live watermark => the cache is stale.
        let result = progressive_search(&cache, [0xEE; 32], 10).expect("stale search");
        assert!(result.stale_warning, "stale cache must warn");
        // Discovery is still served.
        assert_eq!(result.summaries.len(), 4);
    }

    #[test]
    fn signature_drift_refused() {
        let es = entries(2);
        // Bind a digest that does not match the cache => drift.
        let drifted = SignedCatalogCache::from_parts(CatalogCache::rebuild(&es, &[]), [0u8; 32]);
        assert_eq!(
            progressive_search(&drifted, [0u8; 32], 10).unwrap_err(),
            CacheRefusal::SignatureDrift
        );
    }

    #[test]
    fn huge_catalog_no_stall() {
        // 10k entries: search materializes only the top-20 summaries.
        let es = entries(10_000);
        let cache = signed(&es);
        let live = cache.cache().watermark();
        let result = progressive_search(&cache, live, 20).expect("search 10k");
        assert_eq!(result.summaries.len(), 20);
    }
}
