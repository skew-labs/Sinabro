//! `mnemos-e-skill::catalog_cache` — atom #306 · D.3.10 — the signed local
//! catalog cache with a replayable event source.
//!
//! A [`CatalogCache`] is a deterministic, content-addressed snapshot of the
//! catalog: a set of [`SkillCatalogIndexEntry`] (#296) whose three popularity
//! counters are **re-derived by replaying the install-event stream** (#297
//! [`VerifiedInstallReceipt`], the off-chain projection of the #287
//! `events.move` typed events) through the same order-independent
//! [`fold_counters`] used by the live indexer. Rebuilding from the same
//! `(entries, events)` always yields the same [`CatalogCache::cache_digest`]
//! — *cache rebuild deterministic* (#306 criterion).
//!
//! The 광기 invariant: the cache **accelerates discovery but never carries
//! authority**. It can never mint an install receipt
//! ([`CatalogCache::can_mint_install_receipt`] is always `false`), alter a
//! capability ([`CatalogCache::can_alter_capability`] is always `false`), or
//! override a revocation ([`CatalogCache::can_override_revocation`] is always
//! `false`). A package that the event stream revokes is marked
//! [`CatalogCacheEntry::revoked`] and refused for install/use even when the
//! cache is otherwise fresh. A [`SignedCatalogCache`] binds a recorded digest
//! so that any drift between the recorded digest and the recomputed digest is
//! caught as [`CacheStatus::SignatureDrift`]; a cache whose event watermark has
//! fallen behind the live registry head is [`CacheStatus::Stale`] and shows a
//! stale warning, requiring a refresh before any install/use while still
//! serving offline discovery.
//!
//! ## Offline / no-key boundary
//!
//! Phase 0 holds no wallet or signing secret, so "signed" here is
//! content-addressed integrity: the recorded 32-byte digest is what an author
//! signature would cover, and [`SignedCatalogCache::integrity_ok`] is the
//! offline verification. No live network, filesystem, wallet, or chain action
//! occurs in this module.

#![deny(missing_docs)]

extern crate alloc;

use alloc::vec::Vec;

use crate::catalog_counters::{VerifiedInstallReceipt, fold_counters};
use crate::catalog_index::SkillCatalogIndexEntry;
use crate::manifest::SkillId;

/// Domain tag for the stable catalog-cache content digest. Distinct per the
/// `mnemos.d.<area>.v1` scheme so a cache digest can never collide with an
/// index / watermark / package digest.
const DOMAIN_CATALOG_CACHE: &[u8] = b"mnemos.d.catalog_cache.v1";

/// Domain tag for the event-stream watermark digest.
const DOMAIN_CACHE_WATERMARK: &[u8] = b"mnemos.d.catalog_cache_watermark.v1";

/// One cached catalog row: a denormalized [`SkillCatalogIndexEntry`] whose
/// counters were re-derived from the event stream, plus a revocation flag
/// folded from the same stream.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CatalogCacheEntry {
    /// The denormalized, counter-folded catalog entry (#296).
    pub entry: SkillCatalogIndexEntry,
    /// `true` iff the event stream revoked this entry's package. A revoked row
    /// stays *visible* (discovery) but is never installable from the cache.
    pub revoked: bool,
}

/// A deterministic, content-addressed catalog snapshot built by replaying an
/// install-event stream over a set of verified index entries.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CatalogCache {
    /// Cached rows, sorted by `(skill id, package digest)` so the digest and
    /// any lookup are order-independent of how `rebuild` received its inputs.
    entries: Vec<CatalogCacheEntry>,
    /// Digest of the deduplicated event stream this cache was folded from. Two
    /// caches built from the same set of events share a watermark; a cache
    /// whose watermark differs from the live registry head is stale.
    events_watermark_32: [u8; 32],
}

impl CatalogCache {
    /// Rebuild the cache by replaying `events` over `base_entries`.
    ///
    /// For each base entry the counters are recomputed from the receipts whose
    /// `(skill, package)` match it, via the order-independent, replay-idempotent
    /// [`fold_counters`]; a package with any [`VerifiedInstallReceipt`] in a
    /// revoked state is flagged [`CatalogCacheEntry::revoked`]. Deterministic:
    /// the same `(base_entries, events)` always produce the same cache and the
    /// same [`CatalogCache::cache_digest`], regardless of input order.
    #[must_use]
    pub fn rebuild(
        base_entries: &[SkillCatalogIndexEntry],
        events: &[VerifiedInstallReceipt],
    ) -> Self {
        let events_watermark_32 = events_watermark(events);
        let mut entries: Vec<CatalogCacheEntry> = base_entries
            .iter()
            .map(|base| {
                let pkg_events: Vec<VerifiedInstallReceipt> = events
                    .iter()
                    .filter(|r| r.skill == base.skill && r.package == base.package)
                    .copied()
                    .collect();
                let counters = fold_counters(&pkg_events);
                let revoked = pkg_events.iter().any(|r| r.state.is_revoked());
                let entry = base.clone().with_counters(
                    counters.downloads_u64,
                    counters.verified_installs_u64,
                    counters.active_users_u64,
                );
                CatalogCacheEntry { entry, revoked }
            })
            .collect();
        entries.sort_by(|a, b| {
            a.entry
                .skill
                .0
                .cmp(&b.entry.skill.0)
                .then_with(|| a.entry.package.as_bytes().cmp(b.entry.package.as_bytes()))
        });
        Self {
            entries,
            events_watermark_32,
        }
    }

    /// The cached rows (sorted, read-only).
    #[must_use]
    pub fn entries(&self) -> &[CatalogCacheEntry] {
        &self.entries
    }

    /// The event-stream watermark this cache was folded from.
    #[must_use]
    pub fn watermark(&self) -> [u8; 32] {
        self.events_watermark_32
    }

    /// Find a cached row by skill id.
    #[must_use]
    pub fn lookup(&self, skill: SkillId) -> Option<&CatalogCacheEntry> {
        self.entries.iter().find(|ce| ce.entry.skill == skill)
    }

    /// Stable content digest over the whole cache (every row's index digest +
    /// its revocation flag + the event watermark). Same inputs always hash
    /// equal; any counter, revocation, or watermark change moves the digest.
    /// All parts are fixed-width and count-prefixed, so the no-separator
    /// `blake2b_256` framing is unambiguous.
    #[must_use]
    pub fn cache_digest(&self) -> [u8; 32] {
        let count = (self.entries.len() as u64).to_le_bytes();
        let mut rows: Vec<u8> = Vec::with_capacity(self.entries.len() * 33);
        for ce in &self.entries {
            rows.extend_from_slice(&ce.entry.index_digest());
            rows.push(u8::from(ce.revoked));
        }
        crate::package::blake2b_256(&[
            DOMAIN_CATALOG_CACHE,
            &count,
            &rows,
            &self.events_watermark_32,
        ])
    }

    /// Always `false`: a cache can never mint an install receipt. Install
    /// authority lives in the signed package + dry-run + capability approval +
    /// #271 install plan.
    #[must_use]
    pub const fn can_mint_install_receipt(&self) -> bool {
        false
    }

    /// Always `false`: a cache can never alter a package's capability set. The
    /// capability diff is carried verbatim from the verified package.
    #[must_use]
    pub const fn can_alter_capability(&self) -> bool {
        false
    }

    /// Always `false`: a cache can never override a revocation. A revoked row
    /// stays refused for install/use no matter how fresh the cache is.
    #[must_use]
    pub const fn can_override_revocation(&self) -> bool {
        false
    }
}

/// Digest over the deduplicated set of event replay keys. Order-independent and
/// replay-idempotent (duplicate receipts collapse), so it is a stable
/// watermark for the event stream.
#[must_use]
fn events_watermark(events: &[VerifiedInstallReceipt]) -> [u8; 32] {
    let mut keys: Vec<[u8; 32]> = events
        .iter()
        .map(VerifiedInstallReceipt::replay_key)
        .collect();
    keys.sort_unstable();
    keys.dedup();
    let count = (keys.len() as u64).to_le_bytes();
    let mut buf: Vec<u8> = Vec::with_capacity(keys.len() * 32);
    for k in &keys {
        buf.extend_from_slice(k);
    }
    crate::package::blake2b_256(&[DOMAIN_CACHE_WATERMARK, &count, &buf])
}

/// Freshness/integrity verdict of a [`SignedCatalogCache`] against the live
/// registry head.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum CacheStatus {
    /// Integrity holds and the watermark equals the live registry head.
    Fresh,
    /// Integrity holds but the watermark is behind the live head — discovery is
    /// allowed (offline fallback) but install/use must refresh first.
    Stale,
    /// The recomputed digest does not match the recorded digest — the cache is
    /// corrupt/tampered and serves nothing.
    SignatureDrift,
}

/// Reason a cache lookup was refused.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum CacheRefusal {
    /// Recorded digest ≠ recomputed digest.
    SignatureDrift,
    /// Cache is behind the live registry head; refresh required for install/use.
    Stale,
    /// The requested package was revoked by the event stream.
    Revoked,
    /// No cached row for the requested skill.
    NotFound,
}

impl CacheRefusal {
    /// Stable, leak-free class label (mirrors the `class_label` convention used
    /// across the crate).
    #[must_use]
    pub const fn class_label(&self) -> &'static str {
        match self {
            Self::SignatureDrift => "catalog_cache.signature_drift",
            Self::Stale => "catalog_cache.stale",
            Self::Revoked => "catalog_cache.revoked",
            Self::NotFound => "catalog_cache.not_found",
        }
    }
}

/// A [`CatalogCache`] bound to a recorded ("signed") content digest. In Phase 0
/// the recorded digest is content-addressed integrity (no wallet/secret to sign
/// with offline); a real author signature would cover exactly this digest.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SignedCatalogCache {
    cache: CatalogCache,
    recorded_digest_32: [u8; 32],
}

impl SignedCatalogCache {
    /// Sign a cache by recording its current digest.
    #[must_use]
    pub fn sign(cache: CatalogCache) -> Self {
        let recorded_digest_32 = cache.cache_digest();
        Self {
            cache,
            recorded_digest_32,
        }
    }

    /// Bind a cache to a digest recorded elsewhere (e.g. by a registry signer).
    /// A digest that does not match the cache surfaces as
    /// [`CacheStatus::SignatureDrift`].
    #[must_use]
    pub fn from_parts(cache: CatalogCache, recorded_digest_32: [u8; 32]) -> Self {
        Self {
            cache,
            recorded_digest_32,
        }
    }

    /// The underlying cache (read-only).
    #[must_use]
    pub fn cache(&self) -> &CatalogCache {
        &self.cache
    }

    /// The recorded ("signed") digest.
    #[must_use]
    pub fn recorded_digest(&self) -> [u8; 32] {
        self.recorded_digest_32
    }

    /// `true` iff the recomputed digest matches the recorded digest.
    #[must_use]
    pub fn integrity_ok(&self) -> bool {
        self.cache.cache_digest() == self.recorded_digest_32
    }

    /// Status against the live registry head watermark.
    #[must_use]
    pub fn status(&self, live_watermark_32: [u8; 32]) -> CacheStatus {
        if !self.integrity_ok() {
            CacheStatus::SignatureDrift
        } else if self.cache.events_watermark_32 != live_watermark_32 {
            CacheStatus::Stale
        } else {
            CacheStatus::Fresh
        }
    }

    /// Discovery lookup. Serves a fresh **or** stale cache (offline fallback),
    /// but never a cache whose integrity is broken. Returns the row only as a
    /// read-only view — never an install authority.
    pub fn lookup_for_search(&self, skill: SkillId) -> Result<&CatalogCacheEntry, CacheRefusal> {
        if !self.integrity_ok() {
            return Err(CacheRefusal::SignatureDrift);
        }
        self.cache.lookup(skill).ok_or(CacheRefusal::NotFound)
    }

    /// Install/use gate. Requires the cache to be [`CacheStatus::Fresh`] against
    /// the supplied live head (i.e. the caller has refreshed), integrity-ok, and
    /// the row non-revoked. This only decides whether the cached *view* is fresh
    /// enough to begin the install flow — the cache still mints no receipt and
    /// overrides no revocation; full install authority remains the signed
    /// package + dry-run + capability approval + #271 install plan.
    pub fn lookup_for_install(
        &self,
        skill: SkillId,
        live_watermark_32: [u8; 32],
    ) -> Result<&CatalogCacheEntry, CacheRefusal> {
        match self.status(live_watermark_32) {
            CacheStatus::SignatureDrift => return Err(CacheRefusal::SignatureDrift),
            CacheStatus::Stale => return Err(CacheRefusal::Stale),
            CacheStatus::Fresh => {}
        }
        let ce = self.cache.lookup(skill).ok_or(CacheRefusal::NotFound)?;
        if ce.revoked {
            return Err(CacheRefusal::Revoked);
        }
        Ok(ce)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use crate::catalog_counters::VerifiedInstallState;
    use crate::compat::{HostEnvironment, MnemosVersion};
    use crate::package::SkillPackageDigest32;
    use crate::verify::sample_valid_package_toml;
    use alloc::vec;
    use mnemos_a_core::{StageBTraceLink, StageCTraceLink, StageDTraceLink};

    fn host() -> HostEnvironment {
        HostEnvironment {
            mnemos_version: MnemosVersion::new(0, 2, 0),
            chain_env_hash_32: [0xC0; 32],
            os_gpu_hash_32: [0x05; 32],
            toolchain_hash_32: [0x70; 32],
            model_provider_hash_32: [0x30; 32],
        }
    }

    fn base_entry(skill: u16, pkg: u8) -> SkillCatalogIndexEntry {
        let toml = sample_valid_package_toml();
        let mut e = SkillCatalogIndexEntry::from_package_toml(&toml, &host(), [0x99; 32], 0, 0, 0)
            .expect("valid package indexes");
        e.skill = SkillId(skill);
        e.package = SkillPackageDigest32::new([pkg; 32]);
        e
    }

    fn trace(installer: u64, event: u16) -> StageDTraceLink {
        StageDTraceLink::new(
            StageCTraceLink::new(StageBTraceLink::new(installer, 306, 1), 306, 142),
            306,
            event,
        )
    }

    fn receipt(
        skill: u16,
        pkg: u8,
        state: VerifiedInstallState,
        event: u16,
    ) -> VerifiedInstallReceipt {
        VerifiedInstallReceipt::new(
            SkillId(skill),
            SkillPackageDigest32::new([pkg; 32]),
            state,
            [0x7E; 32],
            trace(1, event),
        )
    }

    #[test]
    fn cache_hit() {
        let base = vec![base_entry(1, 0xA0)];
        let events = vec![
            receipt(1, 0xA0, VerifiedInstallState::EvalPassed, 1),
            receipt(1, 0xA0, VerifiedInstallState::Downloaded, 2),
        ];
        let signed = SignedCatalogCache::sign(CatalogCache::rebuild(&base, &events));
        let hit = signed.lookup_for_search(SkillId(1)).expect("cache hit");
        // counters re-derived from the event stream: 2 unique downloads, 1 verified.
        assert_eq!(hit.entry.downloads_u64, 2);
        assert_eq!(hit.entry.verified_installs_u64, 1);
        assert!(!hit.revoked);
        assert!(signed.integrity_ok());
    }

    #[test]
    fn stale_cache() {
        let base = vec![base_entry(1, 0xA0)];
        let events = vec![receipt(1, 0xA0, VerifiedInstallState::EvalPassed, 1)];
        let signed = SignedCatalogCache::sign(CatalogCache::rebuild(&base, &events));
        // A live head with an extra event advances the watermark -> stale.
        let live = events_watermark(&[
            receipt(1, 0xA0, VerifiedInstallState::EvalPassed, 1),
            receipt(1, 0xA0, VerifiedInstallState::EvalPassed, 2),
        ]);
        assert_eq!(signed.status(live), CacheStatus::Stale);
        // Discovery still works while stale (offline fallback).
        assert!(signed.lookup_for_search(SkillId(1)).is_ok());
        // Install/use is refused until refresh.
        assert_eq!(
            signed.lookup_for_install(SkillId(1), live),
            Err(CacheRefusal::Stale)
        );
    }

    #[test]
    fn revoked_package_drift() {
        let base = vec![base_entry(1, 0xA0)];
        let events = vec![
            receipt(1, 0xA0, VerifiedInstallState::EvalPassed, 1),
            receipt(1, 0xA0, VerifiedInstallState::Revoked, 2),
        ];
        let cache = CatalogCache::rebuild(&base, &events);
        let live = cache.watermark();
        let signed = SignedCatalogCache::sign(cache);
        let row = signed.lookup_for_search(SkillId(1)).expect("still visible");
        assert!(row.revoked);
        // Fresh, integrity-ok, but revoked -> install refused. The cache cannot
        // override the revocation.
        assert_eq!(
            signed.lookup_for_install(SkillId(1), live),
            Err(CacheRefusal::Revoked)
        );
        assert!(!signed.cache().can_override_revocation());
    }

    #[test]
    fn signature_drift() {
        let base = vec![base_entry(1, 0xA0)];
        let events = vec![receipt(1, 0xA0, VerifiedInstallState::EvalPassed, 1)];
        let cache = CatalogCache::rebuild(&base, &events);
        let live = cache.watermark();
        // Bind a wrong recorded digest -> integrity fails.
        let signed = SignedCatalogCache::from_parts(cache, [0x00; 32]);
        assert!(!signed.integrity_ok());
        assert_eq!(signed.status(live), CacheStatus::SignatureDrift);
        assert_eq!(
            signed.lookup_for_search(SkillId(1)),
            Err(CacheRefusal::SignatureDrift)
        );
        assert_eq!(
            signed.lookup_for_install(SkillId(1), live),
            Err(CacheRefusal::SignatureDrift)
        );
    }

    #[test]
    fn offline_fallback() {
        let base = vec![base_entry(1, 0xA0)];
        let events = vec![receipt(1, 0xA0, VerifiedInstallState::EvalPassed, 1)];
        let signed = SignedCatalogCache::sign(CatalogCache::rebuild(&base, &events));
        // Offline: no live head to prove freshness. Discovery still works,
        assert!(signed.lookup_for_search(SkillId(1)).is_ok());
        // while install requires a live head match; a mismatched/empty head is stale.
        assert_eq!(
            signed.lookup_for_install(SkillId(1), [0xFF; 32]),
            Err(CacheRefusal::Stale)
        );
        // The cache carries no authority of any kind.
        assert!(!signed.cache().can_mint_install_receipt());
        assert!(!signed.cache().can_alter_capability());
        assert!(!signed.cache().can_override_revocation());
    }

    #[test]
    fn rebuild_deterministic() {
        let base = vec![base_entry(2, 0xB0), base_entry(1, 0xA0)];
        let forward = vec![
            receipt(1, 0xA0, VerifiedInstallState::EvalPassed, 1),
            receipt(2, 0xB0, VerifiedInstallState::ActiveTrace, 2),
            receipt(1, 0xA0, VerifiedInstallState::Downloaded, 3),
        ];
        let mut reversed = forward.clone();
        reversed.reverse();
        let a = CatalogCache::rebuild(&base, &forward);
        let b = CatalogCache::rebuild(&base, &reversed);
        // Order-independent inputs -> identical cache and digest.
        assert_eq!(a, b);
        assert_eq!(a.cache_digest(), b.cache_digest());
    }
}
