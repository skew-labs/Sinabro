//! model cache status (atom #430 F.3.3).
//!
//! `sinabro model cache status`. Surfaces prefix-cache / KV-cache / consult-cache
//! hit / miss / staleness with a *visible* denominator, window, provider + model
//! id, and stale reason. The cache can never hide a provider error
//! ([`CacheStatus::provider_errors_visible`]). The stable system prefix + tool
//! schema are byte-stable; a mutable trailer never busts the prefix
//! ([`CachePrefixBoundary`]). A [`CacheKey`] is scoped by
//! redaction / template / tool-schema / model-route, so a consult-cache entry
//! cannot be reused across a privacy / scope boundary, and a stale entry is never
//! served as fresh ([`ConsultCacheEntry::serve`]).
//!
//! Reuse: [`ProviderKind`] from [`super::provider`], [`crate::sha256_32`]. All
//! values are local projections — `status` never calls a provider
//! (`G-F-ADAPTIVE-ROUTER` speed law, `G-F-PROMPT-CACHE-BOUNDARY`).

use super::provider::ProviderKind;
use crate::commands::model_compress::{KvCacheMode, KvCacheModeStatus};
use crate::sha256_32;

const ZERO32: [u8; 32] = [0u8; 32];

/// Which cache a statistic describes.
#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CacheKind {
    /// Provider prompt **prefix** cache.
    Prefix = 1,
    /// **KV** cache.
    Kv = 2,
    /// Frontier **consult** cache.
    Consult = 3,
}

/// A single cache statistic row (`cache status`). The denominator and stale
/// reason are always visible; a provider error is never hidden.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CacheStat {
    /// Which cache.
    pub kind: CacheKind,
    /// The provider this cache belongs to.
    pub provider: ProviderKind,
    /// SHA-256 of the model id (always attached / visible).
    pub model_id_hash_32: [u8; 32],
    /// Hit count.
    pub hits_u32: u32,
    /// Miss count.
    pub misses_u32: u32,
    /// Stale count.
    pub stale_u32: u32,
    /// The measurement window (number of lookups counted).
    pub window_u32: u32,
    /// SHA-256 of the stale reason label (zero = none).
    pub stale_reason_hash_32: [u8; 32],
    /// Whether a provider error is visible on this cache (never hidden).
    pub provider_error_visible: bool,
}

impl CacheStat {
    /// The hit-rate denominator: `hits + misses + stale` (saturating).
    #[must_use]
    pub const fn denominator_u32(self) -> u32 {
        self.hits_u32
            .saturating_add(self.misses_u32)
            .saturating_add(self.stale_u32)
    }

    /// Hit rate in basis points (0..=10000). A zero denominator reports `0`.
    #[must_use]
    pub fn hit_rate_bps(self) -> u16 {
        let d = self.denominator_u32();
        if d == 0 {
            return 0;
        }
        ((u64::from(self.hits_u32) * 10000) / u64::from(d)) as u16
    }

    /// Whether the stale reason is visible (non-zero) when there are stale hits.
    #[must_use]
    pub fn stale_reason_visible(self) -> bool {
        self.stale_u32 == 0 || self.stale_reason_hash_32 != ZERO32
    }

    /// Whether this cache's measured hit-rate meets a target (basis points). The
    /// performance brain gates a "fast" claim on this: the system prefix cache
    /// targets 9500 bps (95%), the tool cache 9000 bps (90%). A zero denominator
    /// never meets a positive target, so a hit-rate is never claimed without
    /// measured evidence.
    #[must_use]
    pub fn meets_hit_target_bps(self, target_bps: u16) -> bool {
        self.denominator_u32() > 0 && self.hit_rate_bps() >= target_bps
    }
}

/// Route-visible prefix-cache (or KV-reuse) hit-rate evidence. A reuse cache can
/// never become a *stable* relied-upon path on a hit-rate claim alone: the claim
/// must carry the measured denominator, the accepted-token count, the rejected
/// (miss) cost, and a quality-regression signal. [`Self::is_stable_eligible`] is
/// the gate — a cache with a quality regression, with no measured denominator, or
/// below the hit target is never promoted to a stable path.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PrefixCacheHitEvidence {
    /// The underlying cache statistic (hits / misses / stale + visible denominator).
    pub stat: CacheStat,
    /// Tokens accepted (served) from the cache.
    pub accepted_tokens_u32: u32,
    /// Token cost paid on rejected (miss) lookups.
    pub rejected_cost_tokens_u32: u32,
    /// Whether output quality regressed under cache reuse (tracked, never hidden).
    pub quality_regressed: bool,
}

impl PrefixCacheHitEvidence {
    /// The measured hit-rate (basis points) from the underlying statistic.
    #[must_use]
    pub fn hit_rate_bps(self) -> u16 {
        self.stat.hit_rate_bps()
    }

    /// Whether this reuse cache is eligible to be a *stable* path: the kind is a
    /// reuse cache (`Prefix` / `Kv`), the denominator is measured (> 0), there is
    /// no quality regression, and the measured hit-rate meets `min_hit_bps`. A
    /// hit-rate alone is never enough — no stable path without the full evidence.
    #[must_use]
    pub fn is_stable_eligible(self, min_hit_bps: u16) -> bool {
        matches!(self.stat.kind, CacheKind::Prefix | CacheKind::Kv)
            && self.stat.denominator_u32() > 0
            && !self.quality_regressed
            && self.stat.meets_hit_target_bps(min_hit_bps)
    }

    /// Whether a *quantized* serving route backed by this evidence may be promoted
    /// from canary to STABLE (#620). Fail-closed: requires the KV mode to be
    /// quantized (only a quantized route is a canary; BF16 is the stable baseline),
    /// a paired A/B pass (`ab_passed`, supplied by #622), AND this evidence to be
    /// stable-eligible. Without all three the quantized route stays a canary —
    /// never a silent stable promotion.
    #[must_use]
    pub fn quantized_promotable(
        self,
        mode: KvCacheMode,
        ab_passed: bool,
        min_hit_bps: u16,
    ) -> bool {
        mode.is_quantized() && ab_passed && self.is_stable_eligible(min_hit_bps)
    }
}

/// The prompt-cache boundary: a byte-stable system prefix + tool schema, and a
/// mutable trailer that lives *after* the boundary and never busts the prefix.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CachePrefixBoundary {
    /// SHA-256 of the stable prefix bytes (system prefix + tool schema) only.
    pub stable_prefix_hash_32: [u8; 32],
    /// SHA-256 of the mutable trailer bytes (after the boundary).
    pub mutable_trailer_hash_32: [u8; 32],
}

impl CachePrefixBoundary {
    /// Build a boundary. The stable-prefix hash is computed from the stable bytes
    /// **only**, so changing the trailer cannot change it.
    #[must_use]
    pub fn new(stable_prefix: &[u8], mutable_trailer: &[u8]) -> Self {
        Self {
            stable_prefix_hash_32: sha256_32(stable_prefix),
            mutable_trailer_hash_32: sha256_32(mutable_trailer),
        }
    }

    /// Whether this boundary's stable prefix equals another's (byte equality).
    #[must_use]
    pub fn prefix_eq(&self, other: &Self) -> bool {
        self.stable_prefix_hash_32 == other.stable_prefix_hash_32
    }
}

/// The inputs that scope a [`CacheKey`].
#[derive(Clone, Copy, Debug)]
pub struct CacheKeyScope<'a> {
    /// The privacy / ownership scope bytes.
    pub scope: &'a [u8],
    /// The redaction-policy bytes.
    pub redaction: &'a [u8],
    /// The prompt-template bytes.
    pub template: &'a [u8],
    /// The tool-schema bytes.
    pub tool_schema: &'a [u8],
    /// The model-route bytes.
    pub model_route: &'a [u8],
}

/// A scoped cache key. Two entries from different scopes never collide.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CacheKey {
    /// SHA-256 over all scope components.
    pub key_hash_32: [u8; 32],
}

impl CacheKey {
    /// Derive a key from its scope. Every component contributes, so changing any
    /// one (scope / redaction / template / tool-schema / model-route) changes the
    /// key.
    #[must_use]
    pub fn derive(scope: &CacheKeyScope<'_>) -> Self {
        let mut buf = Vec::with_capacity(160);
        for part in [
            scope.scope,
            scope.redaction,
            scope.template,
            scope.tool_schema,
            scope.model_route,
        ] {
            buf.extend_from_slice(&sha256_32(part));
        }
        Self {
            key_hash_32: sha256_32(&buf),
        }
    }
}

/// A consult-cache entry. A stale entry is never served as fresh advice, and an
/// entry is never reused across a scope boundary (key mismatch).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ConsultCacheEntry {
    /// The scoped key this entry was stored under.
    pub key: CacheKey,
    /// Whether the entry is stale.
    pub stale: bool,
    /// Whether the cached advice is advisory only — invariant `true`.
    pub advisory_only: bool,
}

impl ConsultCacheEntry {
    /// Serve the entry only if it is fresh **and** its key matches `requested`.
    /// Returns `None` for a stale entry (stale frontier advice is never reused) or
    /// a key mismatch (no cross-scope reuse).
    #[must_use]
    pub fn serve(self, requested: &CacheKey) -> Option<CacheKey> {
        if self.stale {
            return None;
        }
        if self.key != *requested {
            return None;
        }
        Some(self.key)
    }
}

/// The cache status surface — a set of [`CacheStat`] rows.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct CacheStatus {
    stats: Vec<CacheStat>,
    kv_mode_status: Option<KvCacheModeStatus>,
}

impl CacheStatus {
    /// A new, empty cache-status surface.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Record a cache statistic.
    pub fn record(&mut self, stat: CacheStat) {
        self.stats.push(stat);
    }

    /// All recorded statistics.
    #[must_use]
    pub fn stats(&self) -> &[CacheStat] {
        &self.stats
    }

    /// The number of recorded statistics.
    #[must_use]
    pub fn len(&self) -> usize {
        self.stats.len()
    }

    /// Whether no statistics are recorded.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.stats.is_empty()
    }

    /// Whether any cache surfaces a provider error — the cache never hides one.
    #[must_use]
    pub fn provider_errors_visible(&self) -> bool {
        self.stats.iter().any(|s| s.provider_error_visible)
    }

    /// Attach the serving KV-cache mode status to this surface, so `model cache
    /// status` (CLI / Telegram) shows the live KV mode (BF16 / FP8 / TurboQuant)
    /// next to the hit-rate rows — KV-mode is route-visible, never hidden.
    pub fn set_kv_mode_status(&mut self, status: KvCacheModeStatus) {
        self.kv_mode_status = Some(status);
    }

    /// The attached KV-cache mode status, if any (the `model cache status` KV-mode
    /// line).
    #[must_use]
    pub fn kv_mode_status(&self) -> Option<KvCacheModeStatus> {
        self.kv_mode_status
    }

    /// Whether a KV cache statistic is present but its serving mode is NOT shown —
    /// a hidden KV compression mode (a no-silent-fallback violation). The
    /// performance brain asserts `!kv_mode_hidden()`: a served KV cache always
    /// shows its mode.
    #[must_use]
    pub fn kv_mode_hidden(&self) -> bool {
        self.stats.iter().any(|s| s.kind == CacheKind::Kv) && self.kv_mode_status.is_none()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::repl::latency::p95_ms;

    fn stat(kind: CacheKind, hits: u32, misses: u32, stale: u32) -> CacheStat {
        CacheStat {
            kind,
            provider: ProviderKind::Anthropic,
            model_id_hash_32: sha256_32(b"claude-opus-4-8"),
            hits_u32: hits,
            misses_u32: misses,
            stale_u32: stale,
            window_u32: hits + misses + stale,
            stale_reason_hash_32: if stale > 0 {
                sha256_32(b"ttl-expired")
            } else {
                ZERO32
            },
            provider_error_visible: false,
        }
    }

    #[test]
    fn cache_hit_miss() {
        let s = stat(CacheKind::Prefix, 95, 5, 0);
        assert_eq!(s.hit_rate_bps(), 9500);
        assert_eq!(s.denominator_u32(), 100);
    }

    #[test]
    fn stale_counts_in_denominator() {
        let s = stat(CacheKind::Kv, 80, 10, 10);
        assert_eq!(s.denominator_u32(), 100);
        assert_eq!(s.hit_rate_bps(), 8000);
        assert!(s.stale_reason_visible());
    }

    #[test]
    fn provider_error_is_visible() {
        let mut status = CacheStatus::new();
        let mut s = stat(CacheKind::Consult, 1, 1, 0);
        s.provider_error_visible = true;
        status.record(s);
        assert!(
            status.provider_errors_visible(),
            "cache must not hide a provider error"
        );
    }

    #[test]
    fn prefix_hit_rate() {
        let s = stat(CacheKind::Prefix, 7, 3, 0);
        assert_eq!(s.kind, CacheKind::Prefix);
        assert_eq!(s.hit_rate_bps(), 7000);
    }

    #[test]
    fn kv_hit_rate() {
        let s = stat(CacheKind::Kv, 1, 1, 0);
        assert_eq!(s.kind, CacheKind::Kv);
        assert_eq!(s.hit_rate_bps(), 5000);
    }

    #[test]
    fn stale_denominator_zero_is_zero_rate() {
        let s = stat(CacheKind::Prefix, 0, 0, 0);
        assert_eq!(s.denominator_u32(), 0);
        assert_eq!(s.hit_rate_bps(), 0);
    }

    #[test]
    fn provider_and_model_id_attached() {
        let s = stat(CacheKind::Prefix, 1, 0, 0);
        assert_eq!(s.provider, ProviderKind::Anthropic);
        assert_ne!(
            s.model_id_hash_32, ZERO32,
            "model id must be attached / visible"
        );
    }

    #[test]
    fn meets_hit_target_gates_on_measured_evidence() {
        // 95/100 = 9500 bps meets the 95% system target
        assert!(stat(CacheKind::Prefix, 95, 5, 0).meets_hit_target_bps(9500));
        // 94/100 = 9400 bps does NOT meet 95%
        assert!(!stat(CacheKind::Prefix, 94, 6, 0).meets_hit_target_bps(9500));
        // a zero denominator never meets a positive target (no claim without evidence)
        assert!(!stat(CacheKind::Prefix, 0, 0, 0).meets_hit_target_bps(9500));
    }

    #[test]
    fn stable_prefix_byte_equality() {
        let a = CachePrefixBoundary::new(b"SYSTEM+TOOLSCHEMA", b"trailer-1");
        let b = CachePrefixBoundary::new(b"SYSTEM+TOOLSCHEMA", b"trailer-1");
        assert!(a.prefix_eq(&b));
        assert_eq!(a, b);
    }

    #[test]
    fn mutable_trailer_does_not_bust_prefix() {
        let a = CachePrefixBoundary::new(b"SYSTEM+TOOLSCHEMA", b"trailer-1");
        let b = CachePrefixBoundary::new(b"SYSTEM+TOOLSCHEMA", b"a-totally-different-trailer");
        assert!(
            a.prefix_eq(&b),
            "a mutable trailer must not bust the stable prefix"
        );
        assert_ne!(a.mutable_trailer_hash_32, b.mutable_trailer_hash_32);
    }

    fn scope<'a>(
        scope: &'a [u8],
        redaction: &'a [u8],
        template: &'a [u8],
        tool_schema: &'a [u8],
        model_route: &'a [u8],
    ) -> CacheKeyScope<'a> {
        CacheKeyScope {
            scope,
            redaction,
            template,
            tool_schema,
            model_route,
        }
    }

    #[test]
    fn cache_key_scopes_by_every_component() {
        let base = CacheKey::derive(&scope(b"s", b"r", b"t", b"x", b"m"));
        // each component changes the key
        assert_ne!(base, CacheKey::derive(&scope(b"S", b"r", b"t", b"x", b"m")));
        assert_ne!(base, CacheKey::derive(&scope(b"s", b"R", b"t", b"x", b"m")));
        assert_ne!(base, CacheKey::derive(&scope(b"s", b"r", b"T", b"x", b"m")));
        assert_ne!(base, CacheKey::derive(&scope(b"s", b"r", b"t", b"X", b"m")));
        assert_ne!(base, CacheKey::derive(&scope(b"s", b"r", b"t", b"x", b"M")));
        // identical scope => identical key
        assert_eq!(base, CacheKey::derive(&scope(b"s", b"r", b"t", b"x", b"m")));
    }

    #[test]
    fn consult_cache_scope_boundary() {
        let key_a = CacheKey::derive(&scope(b"scopeA", b"r", b"t", b"x", b"m"));
        let key_b = CacheKey::derive(&scope(b"scopeB", b"r", b"t", b"x", b"m"));
        let entry = ConsultCacheEntry {
            key: key_a,
            stale: false,
            advisory_only: true,
        };
        assert_eq!(entry.serve(&key_a), Some(key_a));
        assert!(
            entry.serve(&key_b).is_none(),
            "no reuse across a scope boundary"
        );
    }

    #[test]
    fn stale_frontier_advice_deny() {
        let key = CacheKey::derive(&scope(b"s", b"r", b"t", b"x", b"m"));
        let stale = ConsultCacheEntry {
            key,
            stale: true,
            advisory_only: true,
        };
        assert!(
            stale.serve(&key).is_none(),
            "stale advice must never be served"
        );
    }

    #[test]
    fn kv_mode_shown_in_cache_status_no_hidden_mode() {
        let mut status = CacheStatus::new();
        status.record(stat(CacheKind::Kv, 80, 20, 0));
        // a KV cache stat is present but the mode is not yet shown = hidden (RED)
        assert!(
            status.kv_mode_hidden(),
            "a KV cache with no shown mode is a hidden compression mode"
        );
        // show the serving KV mode -> no longer hidden
        status.set_kv_mode_status(KvCacheModeStatus::for_mode(KvCacheMode::Bf16, true, false));
        assert!(
            !status.kv_mode_hidden(),
            "KV-mode is now visible on the status surface"
        );
        if let Some(kv) = status.kv_mode_status() {
            assert_eq!(kv.mode, KvCacheMode::Bf16);
            assert!(!kv.requires_stage_h_canary, "BF16 baseline needs no canary");
        }
    }

    #[test]
    fn turboquant_status_is_canary_only() {
        let mut status = CacheStatus::new();
        status.set_kv_mode_status(KvCacheModeStatus::for_mode(
            KvCacheMode::TurboQuant,
            true,
            false,
        ));
        if let Some(kv) = status.kv_mode_status() {
            assert!(kv.mode.is_quantized());
            assert!(
                kv.requires_stage_h_canary,
                "TurboQuant is canary-only; it never silently becomes stable"
            );
            assert_ne!(
                kv.status_truth(),
                crate::tui::RenderTruth::Green,
                "a quantized KV mode is never a false green"
            );
        }
    }

    #[test]
    fn prefix_hit_evidence_is_route_visible_with_denominator() {
        let ev = PrefixCacheHitEvidence {
            stat: stat(CacheKind::Prefix, 95, 5, 0),
            accepted_tokens_u32: 1900,
            rejected_cost_tokens_u32: 100,
            quality_regressed: false,
        };
        assert_eq!(ev.hit_rate_bps(), 9500);
        assert_eq!(ev.stat.denominator_u32(), 100, "denominator is visible");
        assert_eq!(ev.accepted_tokens_u32, 1900, "accepted tokens carried");
        assert_eq!(ev.rejected_cost_tokens_u32, 100, "rejected cost carried");
        // full evidence + meets target + no regression => eligible to be stable
        assert!(ev.is_stable_eligible(9000));
    }

    #[test]
    fn no_stable_prefix_path_without_evidence() {
        let base = PrefixCacheHitEvidence {
            stat: stat(CacheKind::Prefix, 95, 5, 0),
            accepted_tokens_u32: 1900,
            rejected_cost_tokens_u32: 100,
            quality_regressed: false,
        };
        assert!(base.is_stable_eligible(9000), "baseline is eligible");
        // a quality regression blocks the stable path
        let regressed = PrefixCacheHitEvidence {
            quality_regressed: true,
            ..base
        };
        assert!(
            !regressed.is_stable_eligible(9000),
            "a quality regression is never a stable path"
        );
        // a zero denominator (no measured evidence) blocks it
        let no_evidence = PrefixCacheHitEvidence {
            stat: stat(CacheKind::Prefix, 0, 0, 0),
            ..base
        };
        assert!(
            !no_evidence.is_stable_eligible(9000),
            "no measured denominator => no stable path"
        );
        // below the hit target blocks it
        let weak = PrefixCacheHitEvidence {
            stat: stat(CacheKind::Prefix, 80, 20, 0),
            ..base
        };
        assert!(
            !weak.is_stable_eligible(9000),
            "below the hit target => no stable path"
        );
    }

    #[test]
    fn quantized_route_canary_only_no_silent_promotion() {
        let strong = PrefixCacheHitEvidence {
            stat: stat(CacheKind::Kv, 96, 4, 0),
            accepted_tokens_u32: 1920,
            rejected_cost_tokens_u32: 80,
            quality_regressed: false,
        };
        // a quantized route with full evidence AND an A/B pass may promote to stable
        assert!(strong.quantized_promotable(KvCacheMode::Fp8, true, 9000));
        // without the A/B pass it stays a canary (no silent promotion)
        assert!(!strong.quantized_promotable(KvCacheMode::Fp8, false, 9000));
        // a quality regression keeps it a canary even with an A/B pass
        let regressed = PrefixCacheHitEvidence {
            quality_regressed: true,
            ..strong
        };
        assert!(!regressed.quantized_promotable(KvCacheMode::Fp8, true, 9000));
        // BF16 is the stable baseline, not a quantized canary (gate N/A -> false)
        assert!(!strong.quantized_promotable(KvCacheMode::Bf16, true, 9000));
    }

    #[test]
    fn status_p95_within_budget() {
        let mut status = CacheStatus::new();
        status.record(stat(CacheKind::Prefix, 90, 10, 0));
        status.record(stat(CacheKind::Kv, 50, 50, 0));
        let mut samples = Vec::with_capacity(256);
        for _ in 0..256 {
            let t = std::time::Instant::now();
            let rows = status.stats();
            std::hint::black_box(&rows);
            samples.push(t.elapsed().as_nanos() as u64);
        }
        let p95 = p95_ms(&samples) / 1_000_000;
        assert!(p95 <= 20, "cache status p95 {p95}ms exceeds 20ms budget");
    }
}
