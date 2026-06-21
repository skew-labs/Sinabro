//! Criterion bench harness — atom #13 · C.0.7.
//!
//! This bench file is the criterion infrastructure for the `c-walrus`
//! critical path. It measures three operations across a fixed content-size
//! ladder and emits a `baseline.json` record that K.0.1's CI gate compares
//! against future PRs (±5 % latency / alloc+0 regression block).
//!
//! Ops measured:
//!
//! 1. `encode_chunk_v1` — atom #7 codec, content size N → BCS wire bytes.
//! 2. `decode_chunk_v1` — atom #7 codec, wire bytes → `ChunkEnvelopeV1`.
//! 3. `derive_blob_id` — atom #10 blob id derivation (zero-alloc claim).
//!
//! Content sizes: 64 B / 1 KiB / 16 KiB / 256 KiB / 1 MiB. The smallest is
//! near `MIN_EMPTY_CHUNK_V1_BYTES = 10` (atom #7 wire floor); the largest
//! is well below `MAX_CONTENT_BYTES = 13_000_000` (atom #7 cap) yet large
//! enough to dominate uleb128 framing overhead.
//!
//! Two run modes share the same binary:
//!
//! * Default `cargo bench` → criterion statistical sweep with throughput
//!   reporting.
//! * `MNEMOS_BENCH_EMIT_BASELINE=1 cargo bench` → bypass criterion and
//!   write a single canonical `baseline.json` record (deterministic 100
//!   warmup + 1000 measured iterations per `(op, size)` cell). Output path
//!   defaults to `baseline.json` in cwd, overridable via
//!   `MNEMOS_BENCH_BASELINE_PATH`.
//!
//! The counting global allocator (`CountingAllocator`) wraps `System` and
//! records `alloc_count` / `alloc_bytes` / `dealloc_count` / `dealloc_bytes`
//! atomically. It is scoped to this bench binary; the lib crate and the
//! release binaries are untouched.
//!
//! `// AI-HOT` markers in `codec.rs::encode_chunk_v1`, `decode_chunk_v1`,
//! and `blob_id.rs::derive_blob_id` document the hot paths this bench
//! pins. Smoke gate: `cargo bench --no-run --offline --locked --workspace`
//! must exit 0 (G-BENCH-SMOKE).

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

use mnemos_c_walrus::codec::{
    ChunkEnvelopeV1, ChunkKind, MemoryRole, decode_chunk_v1, encode_chunk_v1,
};
use mnemos_c_walrus::{DOMAIN_TAG_V0, derive_blob_id};

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

fn alloc_snapshot() -> AllocSnapshot {
    AllocSnapshot {
        alloc_count: ALLOC_COUNT.load(Ordering::Relaxed),
        alloc_bytes: ALLOC_BYTES.load(Ordering::Relaxed),
        dealloc_count: DEALLOC_COUNT.load(Ordering::Relaxed),
        dealloc_bytes: DEALLOC_BYTES.load(Ordering::Relaxed),
    }
}

#[derive(Clone, Copy, Debug)]
struct AllocDelta {
    alloc_count: u64,
    alloc_bytes: u64,
    dealloc_count: u64,
    dealloc_bytes: u64,
}

fn alloc_delta(start: AllocSnapshot, end: AllocSnapshot) -> AllocDelta {
    AllocDelta {
        alloc_count: end.alloc_count - start.alloc_count,
        alloc_bytes: end.alloc_bytes - start.alloc_bytes,
        dealloc_count: end.dealloc_count - start.dealloc_count,
        dealloc_bytes: end.dealloc_bytes - start.dealloc_bytes,
    }
}

// ---------------------------------------------------------------------------
// Fixture construction.
// ---------------------------------------------------------------------------

const SIZE_LADDER: &[usize] = &[64, 1_024, 16_384, 262_144, 1_048_576];

fn build_envelope(content_len: usize) -> ChunkEnvelopeV1 {
    // Deterministic non-zero pattern so an aggressive optimiser cannot fold
    // the body into a single repeated byte and skew throughput numbers.
    let mut content = Vec::with_capacity(content_len);
    let mut x: u8 = 0xA5;
    for _ in 0..content_len {
        content.push(x);
        x = x.wrapping_add(31);
    }
    ChunkEnvelopeV1 {
        kind: ChunkKind::UserMessage,
        role: MemoryRole::User,
        parent: None,
        content,
        embedding: None,
        signature: None,
        provenance: None,
    }
}

fn encode_for_size(content_len: usize) -> Vec<u8> {
    let env = build_envelope(content_len);
    encode_chunk_v1(&env).unwrap()
}

// ---------------------------------------------------------------------------
// Criterion bench groups (default `cargo bench` path).
// ---------------------------------------------------------------------------

fn bench_encode(c: &mut Criterion) {
    let mut group: BenchmarkGroup<'_, _> = c.benchmark_group("encode_chunk_v1");
    for &size in SIZE_LADDER {
        let env = build_envelope(size);
        group.throughput(Throughput::Bytes(size as u64));
        group.bench_function(format!("content_{size}B"), |b| {
            b.iter(|| {
                let wire = encode_chunk_v1(black_box(&env)).unwrap();
                black_box(wire);
            });
        });
    }
    group.finish();
}

fn bench_decode(c: &mut Criterion) {
    let mut group: BenchmarkGroup<'_, _> = c.benchmark_group("decode_chunk_v1");
    for &size in SIZE_LADDER {
        let wire = encode_for_size(size);
        group.throughput(Throughput::Bytes(size as u64));
        group.bench_function(format!("content_{size}B"), |b| {
            b.iter(|| {
                let env = decode_chunk_v1(black_box(&wire)).unwrap();
                black_box(env);
            });
        });
    }
    group.finish();
}

fn bench_derive_blob_id(c: &mut Criterion) {
    let mut group: BenchmarkGroup<'_, _> = c.benchmark_group("derive_blob_id");
    for &size in SIZE_LADDER {
        let env = build_envelope(size);
        let content = env.content.clone();
        group.throughput(Throughput::Bytes(size as u64));
        group.bench_function(format!("content_{size}B"), |b| {
            b.iter(|| {
                let id = derive_blob_id(black_box(&content));
                black_box(id);
            });
        });
    }
    group.finish();
}

// ---------------------------------------------------------------------------
// Deterministic baseline emit (MNEMOS_BENCH_EMIT_BASELINE=1).
// ---------------------------------------------------------------------------

const WARMUP_ITERS: u64 = 100;
const MEASURED_ITERS: u64 = 1_000;

fn measure_encode(content_len: usize) -> (u128, AllocDelta) {
    let env = build_envelope(content_len);
    // Warm up: discard timing + allocator effects.
    for _ in 0..WARMUP_ITERS {
        let wire = encode_chunk_v1(&env).unwrap();
        black_box(wire);
    }
    let s = alloc_snapshot();
    let t0 = Instant::now();
    for _ in 0..MEASURED_ITERS {
        let wire = encode_chunk_v1(black_box(&env)).unwrap();
        black_box(wire);
    }
    let ns = t0.elapsed().as_nanos();
    let e = alloc_snapshot();
    (ns, alloc_delta(s, e))
}

fn measure_decode(content_len: usize) -> (u128, AllocDelta) {
    let wire = encode_for_size(content_len);
    for _ in 0..WARMUP_ITERS {
        let env = decode_chunk_v1(&wire).unwrap();
        black_box(env);
    }
    let s = alloc_snapshot();
    let t0 = Instant::now();
    for _ in 0..MEASURED_ITERS {
        let env = decode_chunk_v1(black_box(&wire)).unwrap();
        black_box(env);
    }
    let ns = t0.elapsed().as_nanos();
    let e = alloc_snapshot();
    (ns, alloc_delta(s, e))
}

fn measure_derive_blob_id(content_len: usize) -> (u128, AllocDelta) {
    let env = build_envelope(content_len);
    let content = env.content.clone();
    for _ in 0..WARMUP_ITERS {
        let id = derive_blob_id(&content);
        black_box(id);
    }
    let s = alloc_snapshot();
    let t0 = Instant::now();
    for _ in 0..MEASURED_ITERS {
        let id = derive_blob_id(black_box(&content));
        black_box(id);
    }
    let ns = t0.elapsed().as_nanos();
    let e = alloc_snapshot();
    (ns, alloc_delta(s, e))
}

fn iso8601_utc_now_or_placeholder() -> String {
    // We deliberately avoid the `chrono` / `time` crates (c-walrus
    // zero-runtime-deps invariant; bench is dev-only but we still keep the
    // dep graph minimal). The baseline JSON consumer treats this field as
    // free-form; if `SOURCE_DATE_EPOCH` is set we honour it, else we emit
    // `placeholder`.
    std::env::var("SOURCE_DATE_EPOCH").unwrap_or_else(|_| "placeholder".to_string())
}

fn emit_baseline_json(path: &str) {
    let mut s = String::new();
    s.push_str("{\n");
    s.push_str("  \"schema\": \"mnemos.bench.v0\",\n");
    s.push_str("  \"atom\": 13,\n");
    s.push_str("  \"id\": \"C.0.7\",\n");
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
        "  \"reuse\": {{ \"codec_atom\": 7, \"blob_id_atom\": 10, \"domain_tag_v0_hex\": \"{}\" }},\n",
        DOMAIN_TAG_V0
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>()
    ));
    s.push_str(&format!("  \"warmup_iters\": {WARMUP_ITERS},\n"));
    s.push_str(&format!("  \"measured_iters\": {MEASURED_ITERS},\n"));
    s.push_str("  \"results\": [\n");

    type OpMeasureFn = fn(usize) -> (u128, AllocDelta);
    let mut rows: Vec<String> = Vec::new();
    let ops: [(&str, OpMeasureFn); 3] = [
        ("encode_chunk_v1", measure_encode),
        ("decode_chunk_v1", measure_decode),
        ("derive_blob_id", measure_derive_blob_id),
    ];

    for (op_name, op_fn) in ops {
        for &size in SIZE_LADDER {
            let (ns_total, delta) = op_fn(size);
            let ns_per_op = (ns_total as f64) / (MEASURED_ITERS as f64);
            let bytes_per_sec = if ns_per_op > 0.0 {
                (size as f64) * 1.0e9 / ns_per_op
            } else {
                0.0
            };
            let mb_per_sec = bytes_per_sec / 1.0e6;
            let alloc_per_op = (delta.alloc_count as f64) / (MEASURED_ITERS as f64);
            let dealloc_per_op = (delta.dealloc_count as f64) / (MEASURED_ITERS as f64);
            let alloc_bytes_per_op = (delta.alloc_bytes as f64) / (MEASURED_ITERS as f64);
            rows.push(format!(
                "    {{ \"op\": \"{op}\", \"content_bytes\": {size}, \"ns_per_op\": {ns:.2}, \"mb_per_sec\": {mb:.2}, \"alloc_count_per_op\": {alloc:.3}, \"dealloc_count_per_op\": {dealloc:.3}, \"alloc_bytes_per_op\": {abytes:.2} }}",
                op = op_name,
                size = size,
                ns = ns_per_op,
                mb = mb_per_sec,
                alloc = alloc_per_op,
                dealloc = dealloc_per_op,
                abytes = alloc_bytes_per_op,
            ));
        }
    }

    s.push_str(&rows.join(",\n"));
    s.push_str("\n  ]\n");
    s.push_str("}\n");

    std::fs::write(path, s.as_bytes()).expect("write baseline.json");
    eprintln!("baseline written: {path}");
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
    bench_encode(&mut c);
    bench_decode(&mut c);
    bench_derive_blob_id(&mut c);
    c.final_summary();
}
