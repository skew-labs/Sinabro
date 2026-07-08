//! Criterion bench harness — atom #254 · D.0.13.
//!
//! Measures [`mnemos_e_skill::verify::verify_skill_package`] on a small,
//! canonical, signed package (the §252 verifier). Package verification must
//! be cheap enough for search/ranking to call repeatedly without blocking
//! the CLI (§254 광기); the criterion sweep reports p50/p95 and the
//! baseline-emit mode records a deterministic p50/p95 + allocation snapshot
//! to `ops/evidence/stage_d/package_bench.md` data.
//!
//! Two run modes share the same binary (atom #13 · C.0.7 precedent):
//! * Default `cargo bench` → criterion statistical sweep.
//! * `MNEMOS_BENCH_EMIT_BASELINE=1 cargo bench` → deterministic
//!   100-warmup + 1000-measured run, emitting p50/p95 nanos + alloc counts +
//!   the package metadata byte size to `MNEMOS_BENCH_BASELINE_PATH`
//!   (default `baseline.json`).
//!
//! Smoke gate: `cargo bench --no-run --offline --locked --workspace` must
//! exit 0 (G-BENCH-SMOKE). The counting allocator is scoped to this bench
//! binary; the lib crate and release binaries are untouched.

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

use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;

use criterion::{Criterion, black_box};

use mnemos_e_skill::verify::{
    MAX_PACKAGE_METADATA_BYTES, sample_valid_package_toml, verify_skill_package,
};

// ---------------------------------------------------------------------------
// Counting allocator (scoped to this bench binary only).
// ---------------------------------------------------------------------------

struct CountingAllocator;

static ALLOC_COUNT: AtomicU64 = AtomicU64::new(0);
static ALLOC_BYTES: AtomicU64 = AtomicU64::new(0);

unsafe impl GlobalAlloc for CountingAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        ALLOC_COUNT.fetch_add(1, Ordering::Relaxed);
        ALLOC_BYTES.fetch_add(layout.size() as u64, Ordering::Relaxed);
        // SAFETY: forwarding to the system allocator with the same layout.
        unsafe { System.alloc(layout) }
    }
    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        // SAFETY: forwarding to the system allocator with the same layout.
        unsafe { System.dealloc(ptr, layout) }
    }
}

#[global_allocator]
static GLOBAL: CountingAllocator = CountingAllocator;

// ---------------------------------------------------------------------------
// Criterion sweep.
// ---------------------------------------------------------------------------

fn bench_verify(c: &mut Criterion) {
    let bytes = sample_valid_package_toml();
    // Sanity: the fixture must actually verify, else we'd bench the error path.
    assert!(verify_skill_package(&bytes).is_ok());
    assert!(bytes.len() <= MAX_PACKAGE_METADATA_BYTES);

    c.bench_function("verify_skill_package_small", |b| {
        b.iter(|| {
            let verified = verify_skill_package(black_box(&bytes)).unwrap();
            black_box(verified);
        });
    });
}

// ---------------------------------------------------------------------------
// Deterministic baseline emit (MNEMOS_BENCH_EMIT_BASELINE=1).
// ---------------------------------------------------------------------------

fn emit_baseline_json(path: &str) {
    let bytes = sample_valid_package_toml();
    assert!(verify_skill_package(&bytes).is_ok());

    let warmup = 100usize;
    let measured = 1000usize;

    for _ in 0..warmup {
        let v = verify_skill_package(black_box(&bytes)).unwrap();
        black_box(v);
    }

    ALLOC_COUNT.store(0, Ordering::Relaxed);
    ALLOC_BYTES.store(0, Ordering::Relaxed);

    let mut samples: Vec<u64> = Vec::with_capacity(measured);
    for _ in 0..measured {
        let t0 = Instant::now();
        let v = verify_skill_package(black_box(&bytes)).unwrap();
        black_box(v);
        samples.push(t0.elapsed().as_nanos() as u64);
    }

    let alloc_count = ALLOC_COUNT.load(Ordering::Relaxed);
    let alloc_bytes = ALLOC_BYTES.load(Ordering::Relaxed);

    samples.sort_unstable();
    let p50 = samples[measured / 2];
    let p95 = samples[(measured * 95) / 100];

    let json = format!(
        "{{\n  \"op\": \"verify_skill_package_small\",\n  \"metadata_bytes\": {},\n  \"max_metadata_bytes\": {},\n  \"warmup\": {},\n  \"measured\": {},\n  \"p50_nanos\": {},\n  \"p95_nanos\": {},\n  \"alloc_count_per_run\": {},\n  \"alloc_bytes_per_run\": {}\n}}\n",
        bytes.len(),
        MAX_PACKAGE_METADATA_BYTES,
        warmup,
        measured,
        p50,
        p95,
        alloc_count / measured as u64,
        alloc_bytes / measured as u64,
    );
    std::fs::write(path, json).expect("write baseline");
    eprintln!("baseline written: {path} (p50={p50}ns p95={p95}ns)");
}

// ---------------------------------------------------------------------------
// Entry.
// ---------------------------------------------------------------------------

fn main() {
    if std::env::var("MNEMOS_BENCH_EMIT_BASELINE").is_ok() {
        let path = std::env::var("MNEMOS_BENCH_BASELINE_PATH")
            .unwrap_or_else(|_| "baseline.json".to_string());
        emit_baseline_json(&path);
        return;
    }

    let mut c = Criterion::default().configure_from_args();
    bench_verify(&mut c);
    c.final_summary();
}
