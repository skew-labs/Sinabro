//! Criterion bench harness — atom #30 · B.0.2.
//!
//! Measures the in-memory store's `append` / `get` / `recent` AI-HOT
//! paths and pins the `alloc_count = 0` claim made by the store
//! contract. Mirrors the dual-mode shape of `c-walrus::benches::codec`
//! (atom #13) and `m-agent::benches::tokens` (atom #28): a default
//! criterion sweep plus an `MNEMOS_BENCH_EMIT_BASELINE=1` JSON-commit
//! emitter for the atom #46 K.0.1 CI regression baseline.
//!
//! Ops measured:
//!
//! 1. `inmem_store::append` — single chunk append into a pre-sized
//!    arena. Bench resets the store every iteration so it never
//!    saturates capacity (the `CapacityExceeded` branch is exercised
//!    by `b0_2_capacity_exceeded_rejected`, not here).
//! 2. `inmem_store::get` — linear-scan lookup by id over a fully
//!    populated arena. Picks the worst-case (last-appended) id so the
//!    scan walks the full occupied prefix.
//! 3. `inmem_store::recent` — slice-iterator over the last `N` chunks
//!    of a fully populated arena. The reported per-op time is the
//!    cost of iterating + visiting every yielded chunk (counted via
//!    `black_box`), not the cost of the call alone.
//!
//! Content sizes for the appended envelopes follow the same ladder as
//! `c-walrus::benches::codec` (64 B / 1 KiB / 16 KiB) capped at the
//! lower end of the codec ladder — the store does no encoding so larger
//! sizes only measure heap copies of the envelope's `Vec<u8>`, which
//! belong to atom #13's perf surface and not this one.
//!
//! Two run modes share the same binary:
//!
//! * Default `cargo bench` → criterion statistical sweep with throughput
//!   reporting + allocation counters dumped after each group.
//! * `MNEMOS_BENCH_EMIT_BASELINE=1 cargo bench --bench store` → bypass
//!   criterion and write a single canonical `store_baseline.json` record
//!   (deterministic 100 warmup + 1000 measured iterations per `(op,
//!   size)` cell). Output path defaults to `store_baseline.json` in cwd,
//!   overridable via `MNEMOS_BENCH_BASELINE_PATH`.
//!
//! The counting global allocator (`CountingAllocator`) wraps `System`
//! and records `alloc_count` / `alloc_bytes` / `dealloc_count` /
//! `dealloc_bytes` atomically. It is scoped to this bench binary; the
//! lib crate and the release binaries are untouched.
//!
//! Smoke gate: `cargo bench --bench store --no-run --offline --locked`
//! must exit 0 (G-BENCH-SMOKE). Full numerical runs are reserved for
//! the atom #46 K.0.1 CI nightly job.

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

use criterion::{BenchmarkGroup, Criterion, Throughput, black_box};

use mnemos_b_memory::{InMemStore, MemoryId};
use mnemos_c_walrus::codec::{ChunkEnvelopeV1, ChunkKind, MemoryRole};

// ---------------------------------------------------------------------------
// Counting global allocator (bench-binary local; lib crate untouched).
// ---------------------------------------------------------------------------

struct CountingAllocator;

static ALLOC_COUNT: AtomicU64 = AtomicU64::new(0);
static ALLOC_BYTES: AtomicU64 = AtomicU64::new(0);
static DEALLOC_COUNT: AtomicU64 = AtomicU64::new(0);
static DEALLOC_BYTES: AtomicU64 = AtomicU64::new(0);

unsafe impl GlobalAlloc for CountingAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        ALLOC_COUNT.fetch_add(1, Ordering::Relaxed);
        ALLOC_BYTES.fetch_add(layout.size() as u64, Ordering::Relaxed);
        // SAFETY: forwarded to the system allocator with the same layout.
        unsafe { System.alloc(layout) }
    }
    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        DEALLOC_COUNT.fetch_add(1, Ordering::Relaxed);
        DEALLOC_BYTES.fetch_add(layout.size() as u64, Ordering::Relaxed);
        // SAFETY: forwarded to the system allocator with the same layout.
        unsafe { System.dealloc(ptr, layout) }
    }
}

#[global_allocator]
static GLOBAL: CountingAllocator = CountingAllocator;

#[derive(Clone, Copy, Debug)]
struct AllocSnapshot {
    alloc_count: u64,
    alloc_bytes: u64,
    dealloc_count: u64,
    dealloc_bytes: u64,
}

#[derive(Clone, Copy, Debug, Default)]
struct AllocDelta {
    alloc_count: u64,
    alloc_bytes: u64,
    dealloc_count: u64,
    dealloc_bytes: u64,
}

fn alloc_snapshot() -> AllocSnapshot {
    AllocSnapshot {
        alloc_count: ALLOC_COUNT.load(Ordering::Relaxed),
        alloc_bytes: ALLOC_BYTES.load(Ordering::Relaxed),
        dealloc_count: DEALLOC_COUNT.load(Ordering::Relaxed),
        dealloc_bytes: DEALLOC_BYTES.load(Ordering::Relaxed),
    }
}

fn alloc_delta(start: AllocSnapshot, end: AllocSnapshot) -> AllocDelta {
    AllocDelta {
        alloc_count: end.alloc_count.wrapping_sub(start.alloc_count),
        alloc_bytes: end.alloc_bytes.wrapping_sub(start.alloc_bytes),
        dealloc_count: end.dealloc_count.wrapping_sub(start.dealloc_count),
        dealloc_bytes: end.dealloc_bytes.wrapping_sub(start.dealloc_bytes),
    }
}

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

/// `CAP` for the populated-arena fixtures used by `get` / `recent`.
/// Large enough that a worst-case linear scan exercises a non-trivial
/// number of slots; small enough to fit on the stack without blowing
/// the bench-binary frame size.
const FIXTURE_CAP: usize = 256;

/// Number of chunks pre-populated for the `get` / `recent` arenas. We
/// fill the fixture but stop short of `FIXTURE_CAP` so additional
/// `append` calls would still succeed (the bench file does not
/// exercise the boundary-refusal path; that is unit-test territory).
const FIXTURE_POPULATED: usize = 200;

/// Content-size ladder for the per-op measurements. Capped at 16 KiB
/// because the store does no encoding — beyond that we are measuring
/// `Vec::clone` from the envelope, which belongs to atom #13's surface.
const SIZE_LADDER: &[usize] = &[64, 1 << 10, 16 << 10];

const WARMUP_ITERS: u32 = 100;
const MEASURED_ITERS: u32 = 1_000;

fn build_envelope(content_len: usize) -> ChunkEnvelopeV1 {
    ChunkEnvelopeV1 {
        kind: ChunkKind::UserMessage,
        role: MemoryRole::User,
        parent: None,
        content: vec![0u8; content_len],
        embedding: None,
        signature: None,
        provenance: None,
    }
}

fn populated_store(content_len: usize) -> (InMemStore<FIXTURE_CAP>, Vec<MemoryId>) {
    let mut store: InMemStore<FIXTURE_CAP> = InMemStore::new();
    let mut ids = Vec::with_capacity(FIXTURE_POPULATED);
    for _ in 0..FIXTURE_POPULATED {
        let id = store.append(build_envelope(content_len)).unwrap();
        ids.push(id);
    }
    (store, ids)
}

// ---------------------------------------------------------------------------
// Criterion benches
// ---------------------------------------------------------------------------

fn bench_append(c: &mut Criterion) {
    let mut g: BenchmarkGroup<'_, _> = c.benchmark_group("inmem_store::append");
    for &size in SIZE_LADDER {
        g.throughput(Throughput::Bytes(size as u64));
        g.bench_function(format!("size_{size}B"), |b| {
            b.iter_batched_ref(
                || {
                    let store: InMemStore<FIXTURE_CAP> = InMemStore::new();
                    let envelope = build_envelope(size);
                    (store, envelope)
                },
                |(store, envelope)| {
                    let id = store.append(envelope.clone()).unwrap();
                    black_box(id);
                },
                criterion::BatchSize::SmallInput,
            );
        });
    }
    g.finish();
}

fn bench_get(c: &mut Criterion) {
    let mut g: BenchmarkGroup<'_, _> = c.benchmark_group("inmem_store::get");
    for &size in SIZE_LADDER {
        let (store, ids) = populated_store(size);
        // Worst case for the linear scan: the last-appended id (scan
        // walks the full occupied prefix).
        let probe = *ids.last().unwrap();
        g.bench_function(format!("size_{size}B"), |b| {
            b.iter(|| {
                let found = store.get(black_box(probe));
                black_box(found.is_some());
            });
        });
    }
    g.finish();
}

fn bench_recent(c: &mut Criterion) {
    let mut g: BenchmarkGroup<'_, _> = c.benchmark_group("inmem_store::recent");
    for &size in SIZE_LADDER {
        let (store, _) = populated_store(size);
        g.bench_function(format!("size_{size}B_n10"), |b| {
            b.iter(|| {
                let mut count: usize = 0;
                for chunk in store.recent(black_box(10)) {
                    black_box(chunk.id());
                    count = count.wrapping_add(1);
                }
                black_box(count);
            });
        });
    }
    g.finish();
}

// ---------------------------------------------------------------------------
// Deterministic baseline emitter (MNEMOS_BENCH_EMIT_BASELINE=1)
// ---------------------------------------------------------------------------

fn measure_append(content_len: usize) -> (u128, AllocDelta) {
    let envelope = build_envelope(content_len);
    // Warmup loop with fresh stores so capacity never trips.
    for _ in 0..WARMUP_ITERS {
        let mut store: InMemStore<FIXTURE_CAP> = InMemStore::new();
        let id = store.append(envelope.clone()).unwrap();
        black_box(id);
    }
    let s = alloc_snapshot();
    let t0 = Instant::now();
    for _ in 0..MEASURED_ITERS {
        let mut store: InMemStore<FIXTURE_CAP> = InMemStore::new();
        let id = store.append(black_box(envelope.clone())).unwrap();
        black_box(id);
    }
    let ns = t0.elapsed().as_nanos();
    let e = alloc_snapshot();
    (ns, alloc_delta(s, e))
}

fn measure_get(content_len: usize) -> (u128, AllocDelta) {
    let (store, ids) = populated_store(content_len);
    let probe = *ids.last().unwrap();
    for _ in 0..WARMUP_ITERS {
        let found = store.get(probe);
        black_box(found.is_some());
    }
    let s = alloc_snapshot();
    let t0 = Instant::now();
    for _ in 0..MEASURED_ITERS {
        let found = store.get(black_box(probe));
        black_box(found.is_some());
    }
    let ns = t0.elapsed().as_nanos();
    let e = alloc_snapshot();
    (ns, alloc_delta(s, e))
}

fn measure_recent(content_len: usize) -> (u128, AllocDelta) {
    let (store, _) = populated_store(content_len);
    for _ in 0..WARMUP_ITERS {
        let mut count: usize = 0;
        for chunk in store.recent(10) {
            black_box(chunk.id());
            count = count.wrapping_add(1);
        }
        black_box(count);
    }
    let s = alloc_snapshot();
    let t0 = Instant::now();
    for _ in 0..MEASURED_ITERS {
        let mut count: usize = 0;
        for chunk in store.recent(black_box(10)) {
            black_box(chunk.id());
            count = count.wrapping_add(1);
        }
        black_box(count);
    }
    let ns = t0.elapsed().as_nanos();
    let e = alloc_snapshot();
    (ns, alloc_delta(s, e))
}

fn iso8601_utc_now_or_placeholder() -> String {
    std::env::var("SOURCE_DATE_EPOCH").unwrap_or_else(|_| "placeholder".to_string())
}

fn emit_baseline_json(path: &str) {
    let mut s = String::new();
    s.push_str("{\n");
    s.push_str("  \"schema\": \"mnemos.bench.v0\",\n");
    s.push_str("  \"atom\": 30,\n");
    s.push_str("  \"id\": \"B.0.2\",\n");
    s.push_str(&format!(
        "  \"generated_utc\": \"{}\",\n",
        iso8601_utc_now_or_placeholder()
    ));
    s.push_str(&format!(
        "  \"host\": {{ \"os\": \"{}\", \"arch\": \"{}\" }},\n",
        std::env::consts::OS,
        std::env::consts::ARCH
    ));
    s.push_str(&format!(
        "  \"fixture\": {{ \"cap\": {FIXTURE_CAP}, \"populated\": {FIXTURE_POPULATED} }},\n"
    ));
    s.push_str(&format!("  \"warmup_iters\": {WARMUP_ITERS},\n"));
    s.push_str(&format!("  \"measured_iters\": {MEASURED_ITERS},\n"));
    s.push_str("  \"results\": [\n");

    type OpMeasureFn = fn(usize) -> (u128, AllocDelta);
    let mut rows: Vec<String> = Vec::new();
    let ops: [(&str, OpMeasureFn); 3] = [
        ("append", measure_append),
        ("get", measure_get),
        ("recent", measure_recent),
    ];

    for (op_name, op_fn) in ops {
        for &size in SIZE_LADDER {
            let (ns_total, delta) = op_fn(size);
            let ns_per_op = (ns_total as f64) / (MEASURED_ITERS as f64);
            let alloc_per_op = (delta.alloc_count as f64) / (MEASURED_ITERS as f64);
            let dealloc_per_op = (delta.dealloc_count as f64) / (MEASURED_ITERS as f64);
            let alloc_bytes_per_op = (delta.alloc_bytes as f64) / (MEASURED_ITERS as f64);
            rows.push(format!(
                "    {{ \"op\": \"{op}\", \"content_bytes\": {size}, \"ns_per_op\": {ns:.2}, \"alloc_count_per_op\": {alloc:.3}, \"dealloc_count_per_op\": {dealloc:.3}, \"alloc_bytes_per_op\": {abytes:.2} }}",
                op = op_name,
                size = size,
                ns = ns_per_op,
                alloc = alloc_per_op,
                dealloc = dealloc_per_op,
                abytes = alloc_bytes_per_op,
            ));
        }
    }

    s.push_str(&rows.join(",\n"));
    s.push_str("\n  ]\n");
    s.push_str("}\n");

    std::fs::write(path, s.as_bytes()).expect("write store_baseline.json");
    eprintln!("baseline written: {path}");
}

// ---------------------------------------------------------------------------
// Entry — dispatch between criterion and baseline modes
// ---------------------------------------------------------------------------

fn main() {
    if std::env::var("MNEMOS_BENCH_EMIT_BASELINE").is_ok() {
        let path = std::env::var("MNEMOS_BENCH_BASELINE_PATH")
            .unwrap_or_else(|_| "store_baseline.json".to_string());
        emit_baseline_json(&path);
        return;
    }

    let mut c = Criterion::default().configure_from_args();
    bench_append(&mut c);
    bench_get(&mut c);
    bench_recent(&mut c);
    c.final_summary();
}
