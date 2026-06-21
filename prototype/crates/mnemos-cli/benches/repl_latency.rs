//! Offline REPL latency harness (atom #416 F.1.7).
//!
//! `harness = false` — no criterion dependency (deferred per build-state). This
//! measures the real hot-path REPL operations with `std::time` and scores their
//! p95 against [`LatencyBudget::DEFAULT`] using the same [`p95_ms`] the unit
//! tests verify. It writes a report to stdout via a `Write` handle (not the
//! `println!` macro, so the workspace clippy `print_stdout` deny stays clean).
//!
//! Run: `cargo bench --bench repl_latency`.

use std::hint::black_box;
use std::io::Write;
use std::time::Instant;

use sinabro::command::CliMode;
use sinabro::grammar;
use sinabro::repl::complete::Completer;
use sinabro::repl::latency::{LatencyBudget, LatencyScore, p95_ms};
use sinabro::repl::prompt::{PromptStatus, render_status_strip};
use sinabro::repl::{ReplEngine, palette};

const ITERS: usize = 4000;

fn measure<F: FnMut()>(mut op: F) -> Vec<u64> {
    let mut samples = Vec::with_capacity(ITERS);
    for _ in 0..ITERS {
        let t = Instant::now();
        op();
        samples.push(t.elapsed().as_nanos() as u64);
    }
    samples
}

fn sample_status() -> PromptStatus {
    PromptStatus {
        workspace_hash_32: [1u8; 32],
        model_hash_32: [0u8; 32],
        context_pressure_bps: 1200,
        last_checkpoint_hash_32: [3u8; 32],
        budget_remaining_micros: 500_000,
        sandbox_tier_u8: 1,
        pending_approvals_u16: 0,
        pending_tasks_u16: 2,
    }
}

fn main() {
    let status = sample_status();
    let engine = ReplEngine::new();

    let parse_ns = measure(|| {
        black_box(grammar::parse(black_box("checkpoint")));
    });
    let keypress_ns = measure(|| {
        black_box(engine.handle_line(black_box("skill search redact")));
    });
    let palette_ns = measure(|| {
        black_box(palette::resolve(
            black_box("/skill use weather"),
            CliMode::Repl,
        ));
    });
    let completion_ns = measure(|| {
        black_box(Completer::complete_namespace(black_box("me")));
    });
    let render_ns = measure(|| {
        black_box(render_status_strip(black_box(&status)));
    });

    // p95_ms is unit-agnostic nearest-rank; feed nanosecond samples.
    let parse_p95 = p95_ms(&parse_ns);
    let keypress_p95 = p95_ms(&keypress_ns);
    let palette_p95 = p95_ms(&palette_ns);
    let completion_p95 = p95_ms(&completion_ns);
    let render_p95 = p95_ms(&render_ns);

    let to_ms = |ns: u64| ns / 1_000_000;
    // The keypress axis ceiling covers the worst of the per-keypress operations.
    let keypress_ms = to_ms(keypress_p95.max(palette_p95).max(completion_p95));
    let score = LatencyScore::evaluate(
        LatencyBudget::DEFAULT,
        keypress_ms,
        to_ms(parse_p95),
        to_ms(render_p95),
        to_ms(completion_p95),
    );

    let budget = LatencyBudget::DEFAULT;
    let mut out = std::io::stdout().lock();
    let _ = writeln!(
        out,
        "repl_latency harness  iters={ITERS}  (p95 nearest-rank)"
    );
    let _ = writeln!(
        out,
        "  parse      p95={parse_p95:>8} ns  budget {:>2} ms",
        budget.parse_p95_ms
    );
    let _ = writeln!(
        out,
        "  keypress   p95={keypress_p95:>8} ns  budget {:>2} ms",
        budget.keypress_p95_ms
    );
    let _ = writeln!(out, "  palette    p95={palette_p95:>8} ns");
    let _ = writeln!(out, "  completion p95={completion_p95:>8} ns");
    let _ = writeln!(
        out,
        "  render     p95={render_p95:>8} ns  budget {:>2} ms",
        budget.render_p95_ms
    );
    let _ = writeln!(
        out,
        "  score: parse_ok={} keypress_ok={} render_ok={} refresh_ok={} all_ok={}",
        score.parse_ok,
        score.keypress_ok,
        score.render_ok,
        score.refresh_ok,
        score.all_ok()
    );
}
