//! Criterion bench harness — atom #85 · B.1.4 (folds in atom #84 · B.1.3),
//! extended by atom #98 · B.1.17 (schema size/alloc bench).
//!
//! Measures the Stage B chunk-schema AI-HOT paths and pins their
//! allocation profile. The atom #85 paths claim `alloc_count = 0`; the atom
//! #98 paths measure the bounded encode/decode allocation profile (the wire
//! `Vec` and the decoded body `Vec` are real, bounded allocations — the
//! criterion is "alloc stable", not zero) and pin the digest path at zero.
//!
//! atom #85 (alloc/op = 0):
//!
//! 1. `stage_b::header_to_bytes` — [`StageBChunkHeaderV1::to_bytes`], the
//!    content-free fixed-85-byte header encode. Stack array, no heap; this is
//!    the atom #84 `alloc = 0` criterion's throughput bench, deferred from
//!    atom #84 and folded into atom #85's `G-B-BENCH`.
//! 2. `stage_b::view_new` — [`StageBChunkView::new`], the borrowed-view
//!    constructor with the content cap. The view only borrows the envelope
//!    (`&ChunkEnvelopeV1`), so its construction never copies the body and
//!    never allocates — the atom #85 `alloc/op = 0` criterion. The fixture
//!    envelope is built **once, outside** the measured loop so the body
//!    `Vec` allocation is not attributed to the constructor.
//!
//! atom #98 (size/alloc profile — encode/decode bounded, digest zero):
//!
//! 3. `stage_b::encode` — [`encode_stage_b_chunk`] (atom #91 · B.1.10), the
//!    thin wrapper over Stage A `encode_chunk_v1`. Each call allocates the
//!    output wire `Vec` (the body is copied in), so `alloc/op` is a bounded
//!    constant, not zero; the criterion is allocation *stability* across the
//!    content-size ladder.
//! 4. `stage_b::decode` — [`decode_stage_b_chunk`] (atom #92 · B.1.11), the
//!    thin wrapper over Stage A `decode_chunk_v1`. The wire bytes are built
//!    **once, outside** the measured loop; each decode allocates a fresh
//!    [`ChunkEnvelopeV1`] body `Vec` (bounded by the content size).
//! 5. `stage_b::digest` — [`stage_b_chunk_digest`] (atom #86 · B.1.5) over a
//!    borrowed [`StageBChunkView`]. Allocation-free by construction (stack
//!    header encode + in-place content absorb + stack `[u8; 32]` hashes); the
//!    view is built **once, outside** the measured loop so the body `Vec` is
//!    not attributed to the digest.
//!
//! atom #98 NON-GOAL: a `sign` cell. The Stage B sign path
//! (`sign_stage_b_chunk`) is atom #150 (g-wallet `ScopedSecretKey` binding) and
//! exists only as a doc-comment forward-reference on disk this atom — it is NOT
//! benched here (recorded in `no_op_decisions.jsonl`). The atom #98 reuse list
//! (#86, #91, #92) confirms the implementable scope is digest/encode/decode.
//!
//! The content-size ladder mirrors `c-walrus::benches::codec` (64 B / 1 KiB /
//! 16 KiB). For `header_to_bytes` the size is irrelevant (the header is
//! content-free), so it is measured at one representative size; for `view_new`
//! the ladder confirms the borrow stays `alloc = 0` regardless of body size.
//!
//! Two run modes share the same binary (mirrors `benches/store.rs`):
//!
//! * Default `cargo bench` → criterion statistical sweep.
//! * `MNEMOS_BENCH_EMIT_BASELINE=1 cargo bench --bench chunk_schema` → bypass
//!   criterion and write a single canonical `chunk_schema_baseline.json`
//!   record (deterministic 100 warmup + 1000 measured iterations per cell).
//!   Path defaults to `chunk_schema_baseline.json`, overridable via
//!   `MNEMOS_BENCH_BASELINE_PATH`.
//!
//! The counting global allocator (`CountingAllocator`) wraps `System` and
//! records alloc/dealloc counts atomically. It is scoped to this bench binary;
//! the lib crate and the release binaries are untouched.
//!
//! Smoke gate: `cargo bench --bench chunk_schema --no-run --offline --locked`
//! must exit 0 (G-B-BENCH smoke). Full numerical runs are reserved for the
//! atom #46 K.0.1 CI nightly job.

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

use mnemos_b_memory::{
    MAX_STAGE_B_CONTENT_BYTES, STAGE_B_CHUNK_HEADER_ENCODED_LEN, StageBChunkFlags,
    StageBChunkHeaderV1, StageBChunkView, StageBTraceLink, decode_stage_b_chunk,
    encode_stage_b_chunk, stage_b_chunk_digest,
};
use mnemos_c_walrus::PublishPayloadClass;
use mnemos_c_walrus::codec::{ChunkEnvelopeV1, ChunkKind, MemoryRole};
use mnemos_d_move::SuiAddress;

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

/// Content-size ladder for `view_new`. The view only borrows, so every cell
/// must report `alloc = 0` regardless of the body size.
const SIZE_LADDER: &[usize] = &[64, 1 << 10, 16 << 10];

/// Representative size for `header_to_bytes` — the header is content-free, so
/// its encode cost and `alloc = 0` claim do not vary with body size.
const HEADER_REPRESENTATIVE_SIZE: usize = 64;

const WARMUP_ITERS: u32 = 100;
const MEASURED_ITERS: u32 = 1_000;

fn fixture_owner() -> SuiAddress {
    SuiAddress::new([0x55; 32])
}

fn fixture_trace() -> StageBTraceLink {
    StageBTraceLink::new(85, 85, 0)
}

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

fn build_header(content_len: u32) -> StageBChunkHeaderV1 {
    StageBChunkHeaderV1::new(
        ChunkKind::UserMessage,
        MemoryRole::User,
        PublishPayloadClass::SyntheticPublicFixture,
        StageBChunkFlags::None as u8,
        content_len,
        fixture_owner(),
        None,
        fixture_trace(),
    )
    .expect("fixture header valid")
}

// ---------------------------------------------------------------------------
// Criterion benches
// ---------------------------------------------------------------------------

fn bench_header_to_bytes(c: &mut Criterion) {
    let mut g: BenchmarkGroup<'_, _> = c.benchmark_group("stage_b::header_to_bytes");
    let header = build_header(HEADER_REPRESENTATIVE_SIZE as u32);
    g.throughput(Throughput::Bytes(STAGE_B_CHUNK_HEADER_ENCODED_LEN as u64));
    g.bench_function("fixed_85B", |b| {
        b.iter(|| {
            let bytes = black_box(&header).to_bytes();
            black_box(bytes);
        });
    });
    g.finish();
}

fn bench_view_new(c: &mut Criterion) {
    let mut g: BenchmarkGroup<'_, _> = c.benchmark_group("stage_b::view_new");
    for &size in SIZE_LADDER {
        // Envelope + header built ONCE outside the measured loop so the body
        // `Vec` allocation is not attributed to `StageBChunkView::new`.
        let envelope = build_envelope(size);
        let header = build_header(size as u32);
        g.throughput(Throughput::Bytes(size as u64));
        g.bench_function(format!("size_{size}B"), |b| {
            b.iter(|| {
                let view = StageBChunkView::new(black_box(header), black_box(&envelope));
                black_box(view.is_some());
            });
        });
    }
    g.finish();
}

// atom #98 · B.1.17 — encode / decode / digest size·alloc paths.

fn bench_encode(c: &mut Criterion) {
    let mut g: BenchmarkGroup<'_, _> = c.benchmark_group("stage_b::encode");
    for &size in SIZE_LADDER {
        // Envelope built ONCE outside the measured loop so its body `Vec` is
        // not attributed to the encode; the encode's own output `Vec` is.
        let envelope = build_envelope(size);
        g.throughput(Throughput::Bytes(size as u64));
        g.bench_function(format!("size_{size}B"), |b| {
            b.iter(|| {
                let wire = encode_stage_b_chunk(black_box(&envelope)).expect("encode fixture");
                black_box(wire);
            });
        });
    }
    g.finish();
}

fn bench_decode(c: &mut Criterion) {
    let mut g: BenchmarkGroup<'_, _> = c.benchmark_group("stage_b::decode");
    for &size in SIZE_LADDER {
        // The wire bytes are encoded ONCE outside the measured loop; each decode
        // allocates a fresh `ChunkEnvelopeV1` body `Vec` (bounded by `size`).
        let wire = encode_stage_b_chunk(&build_envelope(size)).expect("encode fixture");
        g.throughput(Throughput::Bytes(wire.len() as u64));
        g.bench_function(format!("size_{size}B"), |b| {
            b.iter(|| {
                let env = decode_stage_b_chunk(black_box(&wire)).expect("decode fixture");
                black_box(env);
            });
        });
    }
    g.finish();
}

fn bench_digest(c: &mut Criterion) {
    let mut g: BenchmarkGroup<'_, _> = c.benchmark_group("stage_b::digest");
    for &size in SIZE_LADDER {
        // Envelope + header + view built ONCE outside the measured loop so the
        // body `Vec` is not attributed to the alloc-free digest.
        let envelope = build_envelope(size);
        let header = build_header(size as u32);
        let view = StageBChunkView::new(header, &envelope).expect("view fixture");
        g.throughput(Throughput::Bytes(size as u64));
        g.bench_function(format!("size_{size}B"), |b| {
            b.iter(|| {
                let digest = stage_b_chunk_digest(black_box(&view)).expect("digest fixture");
                black_box(digest);
            });
        });
    }
    g.finish();
}

// ---------------------------------------------------------------------------
// Deterministic baseline emitter (MNEMOS_BENCH_EMIT_BASELINE=1)
// ---------------------------------------------------------------------------

fn measure_header_to_bytes() -> (u128, AllocDelta) {
    let header = build_header(HEADER_REPRESENTATIVE_SIZE as u32);
    for _ in 0..WARMUP_ITERS {
        black_box(header.to_bytes());
    }
    let s = alloc_snapshot();
    let t0 = Instant::now();
    for _ in 0..MEASURED_ITERS {
        black_box(black_box(&header).to_bytes());
    }
    let ns = t0.elapsed().as_nanos();
    let e = alloc_snapshot();
    (ns, alloc_delta(s, e))
}

fn measure_view_new(content_len: usize) -> (u128, AllocDelta) {
    // Build the body once, outside the measured window.
    let envelope = build_envelope(content_len);
    let header = build_header(content_len as u32);
    for _ in 0..WARMUP_ITERS {
        let v = StageBChunkView::new(header, &envelope);
        black_box(v.is_some());
    }
    let s = alloc_snapshot();
    let t0 = Instant::now();
    for _ in 0..MEASURED_ITERS {
        let v = StageBChunkView::new(black_box(header), black_box(&envelope));
        black_box(v.is_some());
    }
    let ns = t0.elapsed().as_nanos();
    let e = alloc_snapshot();
    (ns, alloc_delta(s, e))
}

/// A baseline measurement function: maps a content size to `(ns_total, alloc_delta)`
/// over `MEASURED_ITERS` iterations. Used by the atom #98 op-table loop.
type MeasureFn = fn(usize) -> (u128, AllocDelta);

fn measure_encode(content_len: usize) -> (u128, AllocDelta) {
    let envelope = build_envelope(content_len);
    for _ in 0..WARMUP_ITERS {
        black_box(encode_stage_b_chunk(&envelope).expect("encode"));
    }
    let s = alloc_snapshot();
    let t0 = Instant::now();
    for _ in 0..MEASURED_ITERS {
        black_box(encode_stage_b_chunk(black_box(&envelope)).expect("encode"));
    }
    let ns = t0.elapsed().as_nanos();
    let e = alloc_snapshot();
    (ns, alloc_delta(s, e))
}

fn measure_decode(content_len: usize) -> (u128, AllocDelta) {
    // Wire encoded once, outside the measured window.
    let wire = encode_stage_b_chunk(&build_envelope(content_len)).expect("encode");
    for _ in 0..WARMUP_ITERS {
        black_box(decode_stage_b_chunk(&wire).expect("decode"));
    }
    let s = alloc_snapshot();
    let t0 = Instant::now();
    for _ in 0..MEASURED_ITERS {
        black_box(decode_stage_b_chunk(black_box(&wire)).expect("decode"));
    }
    let ns = t0.elapsed().as_nanos();
    let e = alloc_snapshot();
    (ns, alloc_delta(s, e))
}

fn measure_digest(content_len: usize) -> (u128, AllocDelta) {
    // Envelope + header + view built once, outside the measured window.
    let envelope = build_envelope(content_len);
    let header = build_header(content_len as u32);
    let view = StageBChunkView::new(header, &envelope).expect("view");
    for _ in 0..WARMUP_ITERS {
        black_box(stage_b_chunk_digest(&view).expect("digest"));
    }
    let s = alloc_snapshot();
    let t0 = Instant::now();
    for _ in 0..MEASURED_ITERS {
        black_box(stage_b_chunk_digest(black_box(&view)).expect("digest"));
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
    s.push_str("  \"atom\": 85,\n");
    s.push_str("  \"id\": \"B.1.4\",\n");
    s.push_str("  \"folds_in_atom\": 84,\n");
    s.push_str("  \"extended_by_atom\": 98,\n");
    s.push_str("  \"extended_by_id\": \"B.1.17\",\n");
    s.push_str("  \"extension_ops\": [\"encode\", \"decode\", \"digest\"],\n");
    s.push_str("  \"sign_op_deferred_to_atom\": 150,\n");
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
        "  \"content_cap_bytes\": {MAX_STAGE_B_CONTENT_BYTES},\n"
    ));
    s.push_str(&format!(
        "  \"header_encoded_len\": {STAGE_B_CHUNK_HEADER_ENCODED_LEN},\n"
    ));
    s.push_str(&format!("  \"warmup_iters\": {WARMUP_ITERS},\n"));
    s.push_str(&format!("  \"measured_iters\": {MEASURED_ITERS},\n"));
    s.push_str("  \"results\": [\n");

    let mut rows: Vec<String> = Vec::new();

    // header_to_bytes (content-free; one representative cell).
    {
        let (ns_total, delta) = measure_header_to_bytes();
        let ns_per_op = (ns_total as f64) / (MEASURED_ITERS as f64);
        let alloc_per_op = (delta.alloc_count as f64) / (MEASURED_ITERS as f64);
        let dealloc_per_op = (delta.dealloc_count as f64) / (MEASURED_ITERS as f64);
        let alloc_bytes_per_op = (delta.alloc_bytes as f64) / (MEASURED_ITERS as f64);
        rows.push(format!(
            "    {{ \"op\": \"header_to_bytes\", \"content_bytes\": {hsize}, \"ns_per_op\": {ns:.2}, \"alloc_count_per_op\": {alloc:.3}, \"dealloc_count_per_op\": {dealloc:.3}, \"alloc_bytes_per_op\": {abytes:.2} }}",
            hsize = HEADER_REPRESENTATIVE_SIZE,
            ns = ns_per_op,
            alloc = alloc_per_op,
            dealloc = dealloc_per_op,
            abytes = alloc_bytes_per_op,
        ));
    }

    // view_new across the content-size ladder.
    for &size in SIZE_LADDER {
        let (ns_total, delta) = measure_view_new(size);
        let ns_per_op = (ns_total as f64) / (MEASURED_ITERS as f64);
        let alloc_per_op = (delta.alloc_count as f64) / (MEASURED_ITERS as f64);
        let dealloc_per_op = (delta.dealloc_count as f64) / (MEASURED_ITERS as f64);
        let alloc_bytes_per_op = (delta.alloc_bytes as f64) / (MEASURED_ITERS as f64);
        rows.push(format!(
            "    {{ \"op\": \"view_new\", \"content_bytes\": {size}, \"ns_per_op\": {ns:.2}, \"alloc_count_per_op\": {alloc:.3}, \"dealloc_count_per_op\": {dealloc:.3}, \"alloc_bytes_per_op\": {abytes:.2} }}",
            size = size,
            ns = ns_per_op,
            alloc = alloc_per_op,
            dealloc = dealloc_per_op,
            abytes = alloc_bytes_per_op,
        ));
    }

    // atom #98 · B.1.17 — encode/decode/digest across the content-size ladder.
    // `op` discriminates the path; encode/decode report a bounded (non-zero)
    // alloc_count_per_op, digest reports 0.
    let cases: [(&str, MeasureFn); 3] = [
        ("encode", measure_encode),
        ("decode", measure_decode),
        ("digest", measure_digest),
    ];
    for (op, measure) in cases {
        for &size in SIZE_LADDER {
            let (ns_total, delta) = measure(size);
            let ns_per_op = (ns_total as f64) / (MEASURED_ITERS as f64);
            let alloc_per_op = (delta.alloc_count as f64) / (MEASURED_ITERS as f64);
            let dealloc_per_op = (delta.dealloc_count as f64) / (MEASURED_ITERS as f64);
            let alloc_bytes_per_op = (delta.alloc_bytes as f64) / (MEASURED_ITERS as f64);
            rows.push(format!(
                "    {{ \"op\": \"{op}\", \"content_bytes\": {size}, \"ns_per_op\": {ns:.2}, \"alloc_count_per_op\": {alloc:.3}, \"dealloc_count_per_op\": {dealloc:.3}, \"alloc_bytes_per_op\": {abytes:.2} }}",
                op = op,
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

    std::fs::write(path, s.as_bytes()).expect("write chunk_schema_baseline.json");
    eprintln!("baseline written: {path}");
}

// ---------------------------------------------------------------------------
// Entry — dispatch between criterion and baseline modes
// ---------------------------------------------------------------------------

fn main() {
    if std::env::var("MNEMOS_BENCH_EMIT_BASELINE").is_ok() {
        let path = std::env::var("MNEMOS_BENCH_BASELINE_PATH")
            .unwrap_or_else(|_| "chunk_schema_baseline.json".to_string());
        emit_baseline_json(&path);
        return;
    }

    let mut c = Criterion::default().configure_from_args();
    bench_header_to_bytes(&mut c);
    bench_view_new(&mut c);
    bench_encode(&mut c);
    bench_decode(&mut c);
    bench_digest(&mut c);
    c.final_summary();
}
