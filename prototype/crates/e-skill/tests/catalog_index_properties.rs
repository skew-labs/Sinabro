//! Catalog index property/fuzz suite — atom #308 · D.3.12 (D-WP-05A).
//!
//! Property: any event-order replay of the catalog event stream yields the same
//! final index — identical [`fold_counters`] counters, identical
//! [`anti_gamed_counters`], and an identical signed-cache digest — or an
//! explicit conflict. No hidden nondeterminism (#308 광기).
//!
//! The headline `ten_thousand_streams_order_independent` test literally builds
//! 10,000 deterministically-generated event streams and folds each in natural
//! and shuffled order (the #308 "10k generated event streams" criterion). The
//! proptest properties cover shuffled events, duplicate events, revoked
//! packages, forged installs, and no-commerce event rejection (#308 test list).

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use proptest::prelude::*;

use mnemos_a_core::{StageBTraceLink, StageCTraceLink, StageDTraceLink};

use mnemos_e_skill::anti_gaming::anti_gamed_counters;
use mnemos_e_skill::catalog_cache::{CatalogCache, SignedCatalogCache};
use mnemos_e_skill::catalog_counters::{
    VerifiedInstallReceipt, VerifiedInstallState, fold_counters,
};
use mnemos_e_skill::catalog_index::{CatalogIndexError, SkillCatalogIndexEntry};
use mnemos_e_skill::compat::{HostEnvironment, MnemosVersion};
use mnemos_e_skill::manifest::SkillId;
use mnemos_e_skill::package::SkillPackageDigest32;
use mnemos_e_skill::package_policy::FORBIDDEN_COMMERCE_SUBSTRINGS;
use mnemos_e_skill::verify::sample_valid_package_toml;

fn host() -> HostEnvironment {
    HostEnvironment {
        mnemos_version: MnemosVersion::new(0, 2, 0),
        chain_env_hash_32: [0xC0; 32],
        os_gpu_hash_32: [0x05; 32],
        toolchain_hash_32: [0x70; 32],
        model_provider_hash_32: [0x30; 32],
    }
}

// Four base entries keyed `skill == package_byte == p` for p in 0..4, so a
// receipt for package `p` folds into entry `p`.
fn base_entries() -> Vec<SkillCatalogIndexEntry> {
    let toml = sample_valid_package_toml();
    (0u16..4)
        .map(|p| {
            let mut e =
                SkillCatalogIndexEntry::from_package_toml(&toml, &host(), [0x99; 32], 0, 0, 0)
                    .expect("valid package indexes");
            e.skill = SkillId(p);
            e.package = SkillPackageDigest32::new([p as u8; 32]);
            e
        })
        .collect()
}

fn trace(installer: u64, event: u16) -> StageDTraceLink {
    StageDTraceLink::new(
        StageCTraceLink::new(StageBTraceLink::new(installer, 308, 1), 308, 142),
        308,
        event,
    )
}

fn mk_receipt(
    installer: u64,
    pkg: u8,
    tag: u8,
    eval_nonzero: bool,
    event: u16,
) -> VerifiedInstallReceipt {
    let state = VerifiedInstallState::from_u8(tag).unwrap_or(VerifiedInstallState::Downloaded);
    let eval = if eval_nonzero { [0x7E; 32] } else { [0u8; 32] };
    VerifiedInstallReceipt::new(
        SkillId(u16::from(pkg)),
        SkillPackageDigest32::new([pkg; 32]),
        state,
        eval,
        trace(installer, event),
    )
}

#[test]
fn ten_thousand_streams_order_independent() {
    // 10,000 deterministically-generated streams (seeded LCG, no external rng).
    // Each is folded in natural order and Fisher-Yates-shuffled order; the
    // catalog counters, anti-gamed counters, and signed-cache digest must match.
    let base = base_entries();
    let mut lcg: u64 = 0x9E37_79B9_7F4A_7C15;
    let mut next = move || {
        lcg = lcg
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1_442_695_040_888_963_407);
        lcg
    };
    for stream in 0..10_000u32 {
        let n = (next() % 24) as usize;
        let mut events: Vec<VerifiedInstallReceipt> = Vec::with_capacity(n);
        for _ in 0..n {
            let installer = next() % 6;
            let pkg = (next() % 4) as u8;
            let tag = (next() % 5) as u8 + 1;
            let eval_nonzero = next() % 4 != 0;
            let event = (next() % 1000) as u16;
            events.push(mk_receipt(installer, pkg, tag, eval_nonzero, event));
        }
        let mut shuffled = events.clone();
        let len = shuffled.len();
        if len > 1 {
            let mut i = len - 1;
            while i > 0 {
                let j = (next() % (i as u64 + 1)) as usize;
                shuffled.swap(i, j);
                i -= 1;
            }
        }
        assert_eq!(
            fold_counters(&events),
            fold_counters(&shuffled),
            "stream {stream}: counters order-dependent"
        );
        assert_eq!(
            anti_gamed_counters(&events),
            anti_gamed_counters(&shuffled),
            "stream {stream}: anti-gamed order-dependent"
        );
        let a = SignedCatalogCache::sign(CatalogCache::rebuild(&base, &events));
        let b = SignedCatalogCache::sign(CatalogCache::rebuild(&base, &shuffled));
        assert_eq!(
            a.cache().cache_digest(),
            b.cache().cache_digest(),
            "stream {stream}: cache digest order-dependent"
        );
        assert!(a.integrity_ok() && b.integrity_ok());
    }
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 1_024, ..ProptestConfig::default() })]

    // shuffled events: a permutation of the same stream yields an identical
    // index (counters, anti-gamed counters, signed-cache digest).
    #[test]
    fn shuffled_events_same_index(
        raw in prop::collection::vec((0u64..6, 0u8..4, 1u8..=5, any::<bool>(), 0u16..500), 0..24),
        rot in 0usize..24,
    ) {
        let base = base_entries();
        let events: Vec<VerifiedInstallReceipt> =
            raw.iter().map(|&(i, p, t, e, ev)| mk_receipt(i, p, t, e, ev)).collect();
        let mut shuffled = events.clone();
        if !shuffled.is_empty() {
            let k = rot % shuffled.len();
            shuffled.rotate_left(k);
            shuffled.reverse();
        }
        prop_assert_eq!(fold_counters(&events), fold_counters(&shuffled));
        prop_assert_eq!(anti_gamed_counters(&events), anti_gamed_counters(&shuffled));
        let a = SignedCatalogCache::sign(CatalogCache::rebuild(&base, &events));
        let b = SignedCatalogCache::sign(CatalogCache::rebuild(&base, &shuffled));
        prop_assert_eq!(a.cache().cache_digest(), b.cache().cache_digest());
    }

    // duplicate events: appending duplicates never changes the (download,
    // verified, active) signal (replay idempotency).
    #[test]
    fn duplicate_events_idempotent(
        raw in prop::collection::vec((0u64..6, 0u8..4, 1u8..=5, any::<bool>(), 0u16..500), 1..16),
    ) {
        let events: Vec<VerifiedInstallReceipt> =
            raw.iter().map(|&(i, p, t, e, ev)| mk_receipt(i, p, t, e, ev)).collect();
        let mut doubled = events.clone();
        doubled.extend(events.clone());
        prop_assert_eq!(fold_counters(&events), fold_counters(&doubled));
        let a = anti_gamed_counters(&events);
        let b = anti_gamed_counters(&doubled);
        prop_assert_eq!(a.downloads_u64, b.downloads_u64);
        prop_assert_eq!(a.verified_installs_u64, b.verified_installs_u64);
        prop_assert_eq!(a.active_users_u64, b.active_users_u64);
    }

    // revoked package: a revoked receipt removes its pair from the verified
    // count and marks the cache row revoked.
    #[test]
    fn revoked_never_inflates_verified(
        installer in 0u64..6, pkg in 0u8..4, ev1 in 0u16..250, ev2 in 250u16..500,
    ) {
        let rs = [
            mk_receipt(installer, pkg, VerifiedInstallState::EvalPassed.as_u8(), true, ev1),
            mk_receipt(installer, pkg, VerifiedInstallState::Revoked.as_u8(), false, ev2),
        ];
        let c = anti_gamed_counters(&rs);
        prop_assert_eq!(c.verified_installs_u64, 0);
        prop_assert!(c.rejected_revoked_u64 >= 1);
        let base = base_entries();
        let cache = CatalogCache::rebuild(&base, &rs);
        let row = cache.lookup(SkillId(u16::from(pkg))).expect("pkg < 4 is indexed");
        prop_assert!(row.revoked);
    }

    // forged install: a verified-state receipt with a zero eval hash never
    // counts as a verified install.
    #[test]
    fn forged_eval_rejected(installer in 0u64..6, pkg in 0u8..4, ev in 0u16..500) {
        let c = anti_gamed_counters(&[
            mk_receipt(installer, pkg, VerifiedInstallState::EvalPassed.as_u8(), false, ev),
        ]);
        prop_assert_eq!(c.verified_installs_u64, 0);
        prop_assert_eq!(c.rejected_forged_eval_u64, 1);
    }

    // no-commerce event reject: a package carrying a forbidden commerce field
    // never indexes into the catalog (the verifier rejects it first).
    #[test]
    fn no_commerce_event_reject(idx in 0usize..FORBIDDEN_COMMERCE_SUBSTRINGS.len()) {
        let token = FORBIDDEN_COMMERCE_SUBSTRINGS[idx];
        let toml = format!("{}\n[extensions]\n{token}_field = 1\n", sample_valid_package_toml());
        prop_assert_eq!(
            SkillCatalogIndexEntry::from_package_toml(&toml, &host(), [0x99; 32], 0, 0, 0),
            Err(CatalogIndexError::Unverified),
        );
    }
}
