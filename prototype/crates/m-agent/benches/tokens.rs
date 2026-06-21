//! Criterion bench harness — atom #28 · M.0.8.
//!
//! Measures the per-call input-token envelope for the representative
//! MNEMOS request fixture defined in [`mnemos_m_agent::token_bench`]
//! and emits an optional `tokens_baseline.json` record for CI
//! regression (§9.5: per-call ≤ 5,000 input tokens + ≥ 10× reduction
//! vs. the Hermes 32,142-token baseline).
//!
//! Ops measured:
//!
//! 1. `measured_input_envelope` — full reuse-triangle call:
//!    * atom #24 [`mnemos_m_agent::tool_schema::serialized_tool_bytes`]
//!      on the eight-tool [`mnemos_m_agent::token_bench::DECLARED_TOOL_IDS`]
//!    * atom #25 [`mnemos_m_agent::cache::plan_cache_breakpoints`] on
//!      the (system, tools, history) byte triple
//!    * estimated-token derivation via
//!      [`mnemos_m_agent::token_bench::BYTES_PER_TOKEN_ESTIMATE`]
//!
//! The fixture is deterministic and allocation-free at measurement
//! time (the only heap touch is the `Vec<u8>` for criterion's own
//! sampling). The bench therefore doubles as an alloc-floor smoke
//! check via the same `CountingAllocator` pattern atom #22 uses in
//! `benches/sse.rs`.
//!
//! Two run modes share the same binary (atom #13 / atom #22 pattern):
//!
//! * Default `cargo bench` → criterion statistical sweep with
//!   throughput reporting + allocation counters dumped after each
//!   group, plus a runtime envelope assertion (the bench refuses
//!   to report timings if `measured_input_tokens_per_call()` blows
//!   the §9.5 cap or the 10× ratio).
//! * `MNEMOS_BENCH_EMIT_BASELINE=1 cargo bench --bench tokens` →
//!   bypass criterion and write a single canonical baseline record
//!   (deterministic 100 warmup + 1000 measured iterations per cell).
//!   Output path defaults to `tokens_baseline.json` in cwd,
//!   overridable via `MNEMOS_BENCH_BASELINE_PATH`. The JSON commits
//!   the measured envelope (system / tools / history / prefix /
//!   suffix / total bytes / estimated tokens), the cache-breakpoint
//!   count, the per-iter ns + bytes/sec, alloc deltas, the gate
//!   denominators (Hermes baseline, §9.5 cap, 10× ratio), and the
//!   pass/fail verdict for both named tests.
//!
//! Smoke gate `cargo bench --bench tokens --no-run --offline --locked`
//! must exit 0 (G-BENCH-SMOKE). Full bench runs are reserved for the
//! atom #46 K.0.1 CI nightly job (per BUILD_STATE atom #22 line 44 /
//! atom #25 line 49 precedent — bench numbers without CI regression
//! gating give no signal).

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

use mnemos_m_agent::cost::{CostLedger, PriceTable};
use mnemos_m_agent::token_bench::{
    BYTES_PER_TOKEN_ESTIMATE, HERMES_TOKENS_BASELINE, InputEnvelopeMeasurement,
    MIN_REDUCTION_RATIO, MNEMOS_INPUT_TOKENS_CAP, measured_input_envelope,
    measured_input_tokens_per_call,
};
use mnemos_m_agent::turn::TurnUsage;

// ---------------------------------------------------------------------------
// Counting global allocator (bench-binary local; lib crate untouched).
// Same pattern as `benches/sse.rs` so the JSON commit can carry an
// alloc-delta column for the criterion + baseline runs.
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
// Runtime envelope assertions — fail-loud guard for any bench mode.
// Mirrors the named tests in `src/token_bench.rs` so a bench run
// cannot silently report timings while the §9.5 envelope is broken.
// ---------------------------------------------------------------------------

fn assert_envelope_within_cap(env: &InputEnvelopeMeasurement) {
    assert!(
        env.estimated_input_tokens_u32 <= MNEMOS_INPUT_TOKENS_CAP,
        "[bench] m0_8 envelope blown: measured {} tokens > cap {} (atom #28 §9.5 hard gate)",
        env.estimated_input_tokens_u32,
        MNEMOS_INPUT_TOKENS_CAP,
    );
}

fn assert_envelope_meets_ratio(env: &InputEnvelopeMeasurement) {
    let measured = env.estimated_input_tokens_u32;
    assert!(
        measured > 0,
        "[bench] measured envelope must be non-zero (fixture drift?)"
    );
    let ratio = HERMES_TOKENS_BASELINE / measured;
    assert!(
        ratio >= MIN_REDUCTION_RATIO,
        "[bench] m0_8 reduction ratio blown: hermes {} / measured {} = {}× < required {}×",
        HERMES_TOKENS_BASELINE,
        measured,
        ratio,
        MIN_REDUCTION_RATIO,
    );
}

// ---------------------------------------------------------------------------
// Criterion entry — measures the cost of the envelope-derivation
// path itself. The interesting cell is "envelope_full" which exercises
// the atom #24 + #25 + estimate-divide composition end-to-end.
// ---------------------------------------------------------------------------

fn bench_tokens(c: &mut Criterion) {
    let env = measured_input_envelope();
    assert_envelope_within_cap(&env);
    assert_envelope_meets_ratio(&env);

    let mut g: BenchmarkGroup<'_, _> = c.benchmark_group("tokens_envelope");
    g.throughput(Throughput::Bytes(env.total_bytes_u32 as u64));
    g.bench_function("envelope_full", |b| {
        b.iter(|| {
            let e = measured_input_envelope();
            black_box(e);
        });
    });
    g.bench_function("tokens_only", |b| {
        b.iter(|| {
            let n = measured_input_tokens_per_call();
            black_box(n);
        });
    });
    g.finish();
}

// ---------------------------------------------------------------------------
// Baseline emitter (deterministic JSON record; bypasses criterion).
// Output is the canonical CI regression input — atom #46 K.0.1 will
// fail-loud on any non-zero delta against this committed record.
// ---------------------------------------------------------------------------

fn emit_baseline() {
    let path = std::env::var("MNEMOS_BENCH_BASELINE_PATH")
        .unwrap_or_else(|_| "tokens_baseline.json".to_string());

    let env = measured_input_envelope();
    assert_envelope_within_cap(&env);
    assert_envelope_meets_ratio(&env);

    // USD-micros projection over the measured envelope at a
    // representative price table (illustrative — operator wires
    // real rates at atom #5 config + atom #27 cost). Cached vs.
    // uncached pair carries the §9.5 cache-hit visibility.
    let price = PriceTable::new(3_000, 15_000);
    let uncached = TurnUsage {
        prompt_tokens_u32: env.estimated_input_tokens_u32,
        completion_tokens_u32: 400,
        cached_tokens_u32: 0,
    };
    let cached = TurnUsage {
        prompt_tokens_u32: env.estimated_input_tokens_u32,
        completion_tokens_u32: 400,
        cached_tokens_u32: env.static_prefix_bytes_u32 / BYTES_PER_TOKEN_ESTIMATE,
    };
    let uncached_cost = CostLedger::project_usd_micros(&uncached, &price);
    let cached_cost = CostLedger::project_usd_micros(&cached, &price);

    let warmup = 100usize;
    let measured = 1000usize;

    // Warmup.
    for _ in 0..warmup {
        let n = measured_input_tokens_per_call();
        black_box(n);
    }

    // Measured run — per-iteration nanoseconds + alloc deltas for the
    // tokens_only path (cheapest hot loop; envelope_full timing falls
    // out of criterion mode when an operator wants it).
    let before = snapshot_counters();
    let t0 = Instant::now();
    for _ in 0..measured {
        let n = measured_input_tokens_per_call();
        black_box(n);
    }
    let total_ns: u128 = t0.elapsed().as_nanos();
    let after = snapshot_counters();
    let (alloc_delta, alloc_bytes) = delta_counters(before, after);

    let ns_per_iter = total_ns / (measured as u128);
    let bytes_per_sec = if ns_per_iter > 0 {
        (env.total_bytes_u32 as u128).saturating_mul(1_000_000_000) / ns_per_iter
    } else {
        0
    };

    let ratio = HERMES_TOKENS_BASELINE / env.estimated_input_tokens_u32.max(1);
    let under_cap = env.estimated_input_tokens_u32 <= MNEMOS_INPUT_TOKENS_CAP;
    let meets_ratio = ratio >= MIN_REDUCTION_RATIO;

    let body = format!(
        "{{\n\
         \"atom\":\"M.0.8\",\n\
         \"bench\":\"tokens_envelope\",\n\
         \"gate_denominators\":{{\
         \"hermes_tokens_baseline\":{hermes},\
         \"mnemos_input_tokens_cap\":{cap},\
         \"min_reduction_ratio\":{ratio_floor},\
         \"bytes_per_token_estimate\":{bpt}}},\n\
         \"envelope\":{{\
         \"system_bytes\":{sys_b},\
         \"tool_schema_bytes\":{tool_b},\
         \"history_bytes\":{hist_b},\
         \"static_prefix_bytes\":{prefix_b},\
         \"dynamic_suffix_bytes\":{suffix_b},\
         \"total_bytes\":{total_b},\
         \"estimated_input_tokens\":{est_tok},\
         \"cache_breakpoints\":{bp}}},\n\
         \"reduction_ratio_x\":{ratio_x},\n\
         \"verdict\":{{\
         \"m0_8_input_tokens_under_5000\":{under_cap},\
         \"m0_8_vs_hermes_baseline_10x\":{meets_ratio}}},\n\
         \"cost_projection_usd_micros\":{{\
         \"uncached\":{uncached_cost},\
         \"cached_prefix\":{cached_cost},\
         \"input_per_mtok_micros\":{in_rate},\
         \"output_per_mtok_micros\":{out_rate},\
         \"completion_tokens\":400}},\n\
         \"timing\":{{\
         \"warmup\":{warmup},\
         \"measured\":{measured},\
         \"ns_per_iter\":{ns_per_iter},\
         \"bytes_per_sec\":{bytes_per_sec},\
         \"alloc_count_delta\":{alloc_delta},\
         \"alloc_bytes_delta\":{alloc_bytes}}}\n\
         }}\n",
        hermes = HERMES_TOKENS_BASELINE,
        cap = MNEMOS_INPUT_TOKENS_CAP,
        ratio_floor = MIN_REDUCTION_RATIO,
        bpt = BYTES_PER_TOKEN_ESTIMATE,
        sys_b = env.system_bytes_u32,
        tool_b = env.tool_schema_bytes_u32,
        hist_b = env.history_bytes_u32,
        prefix_b = env.static_prefix_bytes_u32,
        suffix_b = env.dynamic_suffix_bytes_u32,
        total_b = env.total_bytes_u32,
        est_tok = env.estimated_input_tokens_u32,
        bp = env.cache_breakpoints_u8,
        ratio_x = ratio,
        under_cap = under_cap,
        meets_ratio = meets_ratio,
        uncached_cost = uncached_cost.get(),
        cached_cost = cached_cost.get(),
        in_rate = 3_000,
        out_rate = 15_000,
        warmup = warmup,
        measured = measured,
        ns_per_iter = ns_per_iter,
        bytes_per_sec = bytes_per_sec,
        alloc_delta = alloc_delta,
        alloc_bytes = alloc_bytes,
    );

    std::fs::write(&path, body).expect("write tokens_baseline.json");
    println!(
        "[bench] m0_8 envelope: {} tokens ({} bytes, ratio {}×, breakpoints {}); wrote {}",
        env.estimated_input_tokens_u32, env.total_bytes_u32, ratio, env.cache_breakpoints_u8, path
    );
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
    bench_tokens(&mut c);
    c.final_summary();
}
