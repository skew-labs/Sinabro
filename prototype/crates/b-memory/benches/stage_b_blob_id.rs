//! Criterion bench harness — atom #107 · B.2.6 (local blob-id derive throughput).
//!
//! Measures the Stage B [`derive_walrus_blob_id`] AI-HOT path and pins its
//! allocation behaviour:
//!
//! * `stage_b::derive_walrus_blob_id` — derive the 32-byte [`BlobId`] from the
//!   **canonical encoded chunk bytes** (atom #91
//!   [`encode_stage_b_chunk`]). The cost scales with the encoded byte length (the
//!   ARX absorb walks the bytes), so it is swept across the content-size ladder.
//!   Allocation-free per op: the bytes are absorbed in place and the only output
//!   is the 32-byte id on the caller stack. The encoded `Vec` is built **once,
//!   outside** the measured loop so its allocation is not attributed to derive.
//!
//! The content-size ladder mirrors `benches/chunk_digest.rs` (64 B / 1 KiB /
//! 16 KiB).
//!
//! Two run modes share the same binary (mirrors `benches/chunk_digest.rs`):
//!
//! * Default `cargo bench` → criterion statistical sweep.
//! * `MNEMOS_BENCH_EMIT_BASELINE=1 cargo bench --bench stage_b_blob_id` → bypass
//!   criterion and write a single canonical `stage_b_blob_id_baseline.json`
//!   record (deterministic 100 warmup + 1000 measured iterations per cell). Path
//!   defaults to `stage_b_blob_id_baseline.json`, overridable via
//!   `MNEMOS_BENCH_BASELINE_PATH`.
//!
//! The counting global allocator (`CountingAllocator`) wraps `System` and
//! records alloc/dealloc counts atomically. It is scoped to this bench binary;
//! the lib crate and the release binaries are untouched.
//!
//! Smoke gate: `cargo bench --bench stage_b_blob_id --no-run --offline --locked`
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

use mnemos_b_memory::{derive_walrus_blob_id, encode_stage_b_chunk};
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

/// Encode a fixture chunk of `content_len` body bytes to its canonical wire
/// (atom #91). Built once per size, outside the measured loop.
fn encoded_fixture(content_len: usize) -> Vec<u8> {
    encode_stage_b_chunk(&build_envelope(content_len)).expect("fixture encodes within Stage A cap")
}

// ---------------------------------------------------------------------------
// Criterion bench
// ---------------------------------------------------------------------------

fn bench_derive(c: &mut Criterion) {
    let mut g: BenchmarkGroup<'_, _> = c.benchmark_group("stage_b::derive_walrus_blob_id");
    for &size in SIZE_LADDER {
        // Encoded chunk built ONCE outside the measured loop so its `Vec`
        // allocation is not attributed to the alloc-free derive.
        let encoded = encoded_fixture(size);
        g.throughput(Throughput::Bytes(encoded.len() as u64));
        g.bench_function(format!("body_{size}B"), |b| {
            b.iter(|| {
                let id = derive_walrus_blob_id(black_box(&encoded));
                black_box(id);
            });
        });
    }
    g.finish();
}

// ---------------------------------------------------------------------------
// Deterministic baseline emitter (MNEMOS_BENCH_EMIT_BASELINE=1)
// ---------------------------------------------------------------------------

fn measure_derive(size: usize) -> (u128, usize, AllocDelta) {
    let encoded = encoded_fixture(size);
    for _ in 0..WARMUP_ITERS {
        black_box(derive_walrus_blob_id(&encoded));
    }
    let s = alloc_snapshot();
    let t0 = Instant::now();
    for _ in 0..MEASURED_ITERS {
        black_box(derive_walrus_blob_id(black_box(&encoded)));
    }
    let ns = t0.elapsed().as_nanos();
    let e = alloc_snapshot();
    (ns, encoded.len(), alloc_delta(s, e))
}

fn iso8601_utc_now_or_placeholder() -> String {
    std::env::var("SOURCE_DATE_EPOCH").unwrap_or_else(|_| "placeholder".to_string())
}

fn emit_baseline_json(path: &str) {
    let mut s = String::new();
    s.push_str("{\n");
    s.push_str("  \"schema\": \"mnemos.bench.v0\",\n");
    s.push_str("  \"atom\": 107,\n");
    s.push_str("  \"id\": \"B.2.6\",\n");
    s.push_str(&format!(
        "  \"generated_utc\": \"{}\",\n",
        iso8601_utc_now_or_placeholder()
    ));
    s.push_str(&format!(
        "  \"host\": {{ \"os\": \"{}\", \"arch\": \"{}\" }},\n",
        std::env::consts::OS,
        std::env::consts::ARCH
    ));
    s.push_str(&format!("  \"warmup_iters\": {WARMUP_ITERS},\n"));
    s.push_str(&format!("  \"measured_iters\": {MEASURED_ITERS},\n"));
    s.push_str("  \"results\": [\n");

    let mut rows: Vec<String> = Vec::new();
    for &size in SIZE_LADDER {
        let (ns_total, encoded_bytes, delta) = measure_derive(size);
        rows.push(row(
            "derive_walrus_blob_id",
            size,
            encoded_bytes,
            ns_total,
            delta,
        ));
    }

    s.push_str(&rows.join(",\n"));
    s.push_str("\n  ]\n");
    s.push_str("}\n");

    std::fs::write(path, s.as_bytes()).expect("write stage_b_blob_id_baseline.json");
    eprintln!("baseline written: {path}");
}

fn row(
    op: &str,
    body_size: usize,
    encoded_bytes: usize,
    ns_total: u128,
    delta: AllocDelta,
) -> String {
    let ns_per_op = (ns_total as f64) / (MEASURED_ITERS as f64);
    let alloc_per_op = (delta.alloc_count as f64) / (MEASURED_ITERS as f64);
    let dealloc_per_op = (delta.dealloc_count as f64) / (MEASURED_ITERS as f64);
    let alloc_bytes_per_op = (delta.alloc_bytes as f64) / (MEASURED_ITERS as f64);
    format!(
        "    {{ \"op\": \"{op}\", \"body_bytes\": {body_size}, \"encoded_bytes\": {encoded_bytes}, \"ns_per_op\": {ns:.2}, \"alloc_count_per_op\": {alloc:.3}, \"dealloc_count_per_op\": {dealloc:.3}, \"alloc_bytes_per_op\": {abytes:.2} }}",
        ns = ns_per_op,
        alloc = alloc_per_op,
        dealloc = dealloc_per_op,
        abytes = alloc_bytes_per_op,
    )
}

// ---------------------------------------------------------------------------
// Entry — dispatch between criterion and baseline modes
// ---------------------------------------------------------------------------

fn main() {
    if std::env::var("MNEMOS_BENCH_EMIT_BASELINE").is_ok() {
        let path = std::env::var("MNEMOS_BENCH_BASELINE_PATH")
            .unwrap_or_else(|_| "stage_b_blob_id_baseline.json".to_string());
        emit_baseline_json(&path);
        return;
    }

    let mut c = Criterion::default().configure_from_args();
    bench_derive(&mut c);
    c.final_summary();
}
