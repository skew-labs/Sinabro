//! Criterion bench harness — atom #309 · D.3.13 (D-WP-05A).
//!
//! Measures the catalog hot path the CLI calls interactively: deterministic
//! ranking (#303 [`rank`]) over a warm entry set, and signed catalog cache
//! rebuild (#306 [`CatalogCache::rebuild`]). Skill search must feel like
//! terminal search, not a slow app store (#309 광기): the criterion is
//! warm top-20 query **p95 <= 100 ms at 10k entries**. The sweep covers
//! 1k / 10k / 100k entries plus a 10k cache rebuild.
//!
//! Two run modes share the binary (atom #13 · C.0.7 / atom #254 precedent):
//! * Default `cargo bench` -> criterion statistical sweep.
//! * `MNEMOS_BENCH_EMIT_BASELINE=1 cargo bench` -> deterministic 100-warmup +
//!   1000-measured warm top-20 query at 10k entries, emitting p50/p95 nanos +
//!   the entry struct/footprint byte sizes to `MNEMOS_BENCH_BASELINE_PATH`
//!   (default `baseline.json`).
//!
//! Smoke gate: `cargo bench --no-run --offline --locked --workspace` exits 0
//! (G-BENCH-SMOKE). The `[[bench]]` target is dev-only; the release binaries
//! are byte-identical (the catalog surface is dead-code-eliminated from them).

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::print_stdout,
    clippy::print_stderr,
    clippy::cast_precision_loss,
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    dead_code
)]

use std::mem::size_of;
use std::time::Instant;

use criterion::{Criterion, black_box};

use mnemos_a_core::{StageBTraceLink, StageCTraceLink, StageDTraceLink};
use mnemos_e_skill::catalog_cache::CatalogCache;
use mnemos_e_skill::catalog_counters::{VerifiedInstallReceipt, VerifiedInstallState};
use mnemos_e_skill::catalog_index::SkillCatalogIndexEntry;
use mnemos_e_skill::compat::{CompatibilityDecision, HostEnvironment, MnemosVersion};
use mnemos_e_skill::manifest::SkillId;
use mnemos_e_skill::package::{SkillPackageDigest32, SkillSecurityState};
use mnemos_e_skill::ranking::{RankWeights, rank};
use mnemos_e_skill::search_query::SkillSearchQuery;
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

// Build `n` distinct entries cheaply: verify one canonical package, then clone +
// mutate identity / counters / security / compat (no n-fold re-verification).
fn build_entries(n: usize) -> Vec<SkillCatalogIndexEntry> {
    let toml = sample_valid_package_toml();
    let template =
        SkillCatalogIndexEntry::from_package_toml(&toml, &host(), [0x99; 32], 0, 0, 0).unwrap();
    let securities = [
        SkillSecurityState::AuditPass,
        SkillSecurityState::SandboxPass,
        SkillSecurityState::Unknown,
        SkillSecurityState::Quarantined,
    ];
    let compats = [
        CompatibilityDecision::Compatible,
        CompatibilityDecision::Warn,
        CompatibilityDecision::Unknown,
        CompatibilityDecision::Incompatible,
    ];
    (0..n)
        .map(|i| {
            let mut e = template.clone();
            e.skill = SkillId((i % 60_000) as u16);
            e.package = SkillPackageDigest32::new([(i % 256) as u8; 32]);
            e.verified_installs_u64 = (i % 1_000) as u64;
            e.downloads_u64 = (i as u64).saturating_mul(7);
            e.security = securities[i % securities.len()];
            e.compatibility = compats[i % compats.len()];
            e
        })
        .collect()
}

fn build_events(n: usize) -> Vec<VerifiedInstallReceipt> {
    (0..n)
        .map(|i| {
            let trace = StageDTraceLink::new(
                StageCTraceLink::new(StageBTraceLink::new(i as u64, 309, 1), 309, 142),
                309,
                (i % 1000) as u16,
            );
            VerifiedInstallReceipt::new(
                SkillId((i % 60_000) as u16),
                SkillPackageDigest32::new([(i % 256) as u8; 32]),
                VerifiedInstallState::EvalPassed,
                [0x7E; 32],
                trace,
            )
        })
        .collect()
}

fn warm_top20(
    entries: &[SkillCatalogIndexEntry],
    query: &SkillSearchQuery,
    weights: &RankWeights,
) -> usize {
    let scores = rank(black_box(entries), black_box(query), black_box(weights));
    let top: Vec<_> = scores.into_iter().take(20).collect();
    black_box(&top).len()
}

fn bench_catalog(c: &mut Criterion) {
    let query = SkillSearchQuery::parse("").expect("empty query parses");
    let weights = RankWeights::default_weights();

    for &n in &[1_000usize, 10_000, 100_000] {
        let entries = build_entries(n);
        c.bench_function(&format!("rank_warm_top20_{n}"), |b| {
            b.iter(|| {
                black_box(warm_top20(&entries, &query, &weights));
            });
        });
    }

    let entries = build_entries(10_000);
    let events = build_events(10_000);
    c.bench_function("cache_rebuild_10k", |b| {
        b.iter(|| {
            let cache = CatalogCache::rebuild(black_box(&entries), black_box(&events));
            black_box(cache.cache_digest());
        });
    });
}

fn percentile(sorted: &[u64], pct: usize) -> u64 {
    let idx = (sorted.len().saturating_sub(1) * pct) / 100;
    sorted[idx]
}

fn emit_baseline_json(path: &str) {
    let query = SkillSearchQuery::parse("").unwrap();
    let weights = RankWeights::default_weights();
    let entries = build_entries(10_000);

    let warmup = 100usize;
    let measured = 1000usize;
    for _ in 0..warmup {
        black_box(warm_top20(&entries, &query, &weights));
    }
    let mut samples: Vec<u64> = Vec::with_capacity(measured);
    for _ in 0..measured {
        let t0 = Instant::now();
        black_box(warm_top20(&entries, &query, &weights));
        samples.push(t0.elapsed().as_nanos() as u64);
    }
    samples.sort_unstable();
    let p50 = percentile(&samples, 50);
    let p95 = percentile(&samples, 95);
    let entry_bytes = size_of::<SkillCatalogIndexEntry>();

    let json = format!(
        "{{\n  \"op\": \"rank_warm_top20\",\n  \"entries\": {},\n  \"warmup\": {},\n  \"measured\": {},\n  \"p50_nanos\": {},\n  \"p95_nanos\": {},\n  \"p95_ms\": {:.3},\n  \"entry_struct_bytes\": {},\n  \"entries_footprint_bytes\": {}\n}}\n",
        entries.len(),
        warmup,
        measured,
        p50,
        p95,
        (p95 as f64) / 1_000_000.0,
        entry_bytes,
        entry_bytes * entries.len(),
    );
    std::fs::write(path, json).expect("write baseline");
    eprintln!("baseline written: {path} (p50={p50}ns p95={p95}ns)");
}

fn main() {
    if std::env::var("MNEMOS_BENCH_EMIT_BASELINE").is_ok() {
        let path = std::env::var("MNEMOS_BENCH_BASELINE_PATH")
            .unwrap_or_else(|_| "baseline.json".to_string());
        emit_baseline_json(&path);
        return;
    }
    let mut c = Criterion::default().configure_from_args();
    bench_catalog(&mut c);
    c.final_summary();
}
