//! Criterion bench harness — atom #22 · M.0.2.
//!
//! Measures the zero-alloc SSE delta parser across a fixed
//! frame-count ladder and emits an optional baseline JSON record for
//! K.0.1's future CI regression gate (±5 % latency / alloc+0).
//!
//! Ops measured:
//!
//! 1. `parse_full_stream` — construct `SseDeltaParser::new(&buf)`,
//!    drain with `next()` until `Ok(None)`. Mirrors the production
//!    streaming hot path (after a full network buffer arrives, the
//!    parser walks all frames at once).
//!
//! Frame ladders: 8 / 64 / 512 / 4_096 frames. Each frame is a
//! representative OpenAI-shape `content` delta of 32 bytes payload —
//! large enough that the inner `find_subsequence` loop dominates,
//! small enough that the throughput stays interesting at 4_096 frames.
//!
//! Two run modes share the same binary (atom #13 codec bench
//! pattern):
//!
//! * Default `cargo bench` → criterion statistical sweep with
//!   throughput reporting + allocation counters dumped after each
//!   group.
//! * `MNEMOS_BENCH_EMIT_BASELINE=1 cargo bench` → bypass criterion
//!   and write a single canonical `baseline.json` record
//!   (deterministic 100 warmup + 1000 measured iterations per
//!   `(op, frame_count)` cell). Output path defaults to
//!   `baseline.json` in cwd, overridable via
//!   `MNEMOS_BENCH_BASELINE_PATH`.
//!
//! Smoke gate `cargo bench --no-run --offline --locked --workspace`
//! must exit 0 (G-BENCH-SMOKE). Full bench runs are reserved for the
//! atom-#46 K.0.1 CI nightly job.

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

use mnemos_m_agent::sse::{SseDelta, SseDeltaParser};

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
static A: CountingAllocator = CountingAllocator;

fn snapshot_counters() -> (u64, u64, u64, u64) {
    (
        ALLOC_COUNT.load(Ordering::Relaxed),
        ALLOC_BYTES.load(Ordering::Relaxed),
        DEALLOC_COUNT.load(Ordering::Relaxed),
        DEALLOC_BYTES.load(Ordering::Relaxed),
    )
}

fn delta_counters(before: (u64, u64, u64, u64), after: (u64, u64, u64, u64)) -> (u64, u64) {
    (
        after.0.saturating_sub(before.0),
        after.1.saturating_sub(before.1),
    )
}

// ---------------------------------------------------------------------------
// Fixture generation
// ---------------------------------------------------------------------------

const FRAME_COUNTS: &[usize] = &[8, 64, 512, 4_096];

/// Build a multi-frame SSE buffer with `count` content deltas plus a
/// terminating `[DONE]` frame. Each content payload is 32 bytes of
/// ASCII filler — large enough that the parser's inner scan loops
/// dominate, small enough that 4_096 frames fits in CPU cache.
fn build_buffer(count: usize) -> Vec<u8> {
    const PAYLOAD: &str = "abcdefghijklmnopqrstuvwxyzABCDEF"; // 32 bytes
    let mut buf = Vec::with_capacity(count * (PAYLOAD.len() + 32));
    for _ in 0..count {
        buf.extend_from_slice(b"data: {\"content\":\"");
        buf.extend_from_slice(PAYLOAD.as_bytes());
        buf.extend_from_slice(b"\"}\n\n");
    }
    buf.extend_from_slice(b"data: [DONE]\n\n");
    buf
}

/// Drain a parser over `buf`, summing observed delta byte lengths to
/// keep the optimiser from eliding the work. Returns the sum so the
/// caller can `black_box` it.
fn parse_full_stream(buf: &[u8]) -> usize {
    let mut p = SseDeltaParser::new(buf);
    let mut sum = 0usize;
    while let Ok(Some(d)) = p.next() {
        match d {
            SseDelta::ContentText(s) => sum = sum.wrapping_add(s.len()),
            SseDelta::ToolCallArgs { fragment, .. } => sum = sum.wrapping_add(fragment.len()),
            SseDelta::Done => sum = sum.wrapping_add(1),
            SseDelta::Usage(_) => sum = sum.wrapping_add(2),
            // `SseDelta` is `#[non_exhaustive]`; the bench is an
            // external crate (consumes via `mnemos_m_agent::sse`)
            // and must wildcard future variants. Counted as a
            // single-byte contribution so a future variant cannot
            // inflate throughput numbers by being skipped.
            _ => sum = sum.wrapping_add(1),
        }
    }
    sum
}

// ---------------------------------------------------------------------------
// Criterion entry
// ---------------------------------------------------------------------------

fn bench_sse(c: &mut Criterion) {
    let mut g: BenchmarkGroup<'_, _> = c.benchmark_group("sse_parse_full_stream");
    for &count in FRAME_COUNTS {
        let buf = build_buffer(count);
        g.throughput(Throughput::Bytes(buf.len() as u64));
        g.bench_function(format!("frames={count}"), |b| {
            b.iter(|| {
                let n = parse_full_stream(black_box(&buf));
                black_box(n);
            });
        });
    }
    g.finish();
}

// ---------------------------------------------------------------------------
// Baseline emitter (deterministic JSON record; bypasses criterion)
// ---------------------------------------------------------------------------

fn emit_baseline() {
    let path =
        std::env::var("MNEMOS_BENCH_BASELINE_PATH").unwrap_or_else(|_| "baseline.json".to_string());

    let warmup = 100usize;
    let measured = 1000usize;
    let mut cells: Vec<String> = Vec::new();

    for &count in FRAME_COUNTS {
        let buf = build_buffer(count);

        // Warmup.
        for _ in 0..warmup {
            let n = parse_full_stream(&buf);
            black_box(n);
        }

        // Measured run — collect per-iteration nanoseconds + alloc deltas.
        let mut total_ns: u128 = 0;
        let before = snapshot_counters();
        let t0 = Instant::now();
        for _ in 0..measured {
            let n = parse_full_stream(&buf);
            black_box(n);
        }
        total_ns = total_ns.saturating_add(t0.elapsed().as_nanos());
        let after = snapshot_counters();
        let (alloc_delta, alloc_bytes) = delta_counters(before, after);

        let ns_per_iter = total_ns / (measured as u128);
        let bytes_per_sec = if ns_per_iter > 0 {
            (buf.len() as u128).saturating_mul(1_000_000_000) / ns_per_iter
        } else {
            0
        };

        cells.push(format!(
            "    {{\"op\":\"parse_full_stream\",\"frames\":{count},\"buf_bytes\":{buf_bytes},\
             \"warmup\":{warmup},\"measured\":{measured},\
             \"ns_per_iter\":{ns_per_iter},\"bytes_per_sec\":{bytes_per_sec},\
             \"alloc_count_delta\":{alloc_delta},\"alloc_bytes_delta\":{alloc_bytes}}}",
            buf_bytes = buf.len()
        ));
    }

    let body = format!(
        "{{\n  \"atom\":\"M.0.2\",\n  \"bench\":\"sse_parse_full_stream\",\n  \"cells\":[\n{}\n  ]\n}}\n",
        cells.join(",\n")
    );
    std::fs::write(&path, body).expect("write baseline.json");
    println!("[bench] wrote {} cells to {}", FRAME_COUNTS.len(), path);
}

// ---------------------------------------------------------------------------
// Main — dispatch between criterion and baseline modes
// ---------------------------------------------------------------------------

fn main() {
    if std::env::var("MNEMOS_BENCH_EMIT_BASELINE").is_ok() {
        emit_baseline();
        return;
    }
    let mut c = Criterion::default().configure_from_args();
    bench_sse(&mut c);
    c.final_summary();
}
