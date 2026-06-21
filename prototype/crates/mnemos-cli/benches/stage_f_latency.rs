//! Offline Stage F latency scorecard harness (atom #474 · F.8.7).
//!
//! `harness = false` — no criterion dependency (deferred per build-state). This
//! measures the new F-WP-08 hot paths — the audit 10k filter, the trace-line
//! write, and the release secret scan — with `std::time` and scores their p95
//! against the §4.3 [`LatencyBudget`] using the same [`p95_ms`] the unit tests
//! verify. It writes via a `Write` handle (not `println!`, so the workspace
//! clippy `print_stdout` deny stays clean).
//!
//! Run: `cargo bench --bench stage_f_latency`.

use std::hint::black_box;
use std::io::Write;
use std::time::Instant;

use sinabro::command::{CliMode, CommandEnvelope, CommandRisk, CommandTraceRecord};
use sinabro::commands::audit::{AuditAction, AuditEntry, AuditTrail};
use sinabro::commands::release_secret_scan::{ReleaseSecretScan, ReleaseSurface};
use sinabro::config::LearningMode;
use sinabro::grammar::CliNamespace;
use sinabro::repl::latency::{LatencyBudget, LatencyScore, p95_ms};
use sinabro::trace::{TraceClassKind, TraceWriter};
use sinabro::{StageFEvidenceRef, StageFTraceLink, sha256_32};

const ITERS: usize = 2000;

fn measure<F: FnMut()>(mut op: F) -> Vec<u64> {
    let mut samples = Vec::with_capacity(ITERS);
    for _ in 0..ITERS {
        let t = Instant::now();
        op();
        samples.push(t.elapsed().as_nanos() as u64);
    }
    samples
}

fn build_trail(n: u32) -> AuditTrail {
    let mut trail = AuditTrail::new();
    for i in 0..n {
        let atom = 401 + (i % 80) as u16;
        let link = StageFTraceLink::new(sha256_32(&i.to_le_bytes()), atom, 100);
        let ev = StageFEvidenceRef {
            path_hash_32: sha256_32(&atom.to_le_bytes()),
            trace: link,
        };
        trail.push(AuditEntry::seal(AuditAction::Kill, link, ev));
    }
    trail
}

fn sample_record() -> CommandTraceRecord {
    let envelope = CommandEnvelope::classify(
        CliNamespace::Trace,
        "list",
        CliMode::Run,
        CommandRisk::ChainWrite,
        b"",
    );
    let link = StageFTraceLink::new([1u8; 32], 473, 200);
    let evidence = StageFEvidenceRef {
        path_hash_32: [2u8; 32],
        trace: link,
    };
    CommandTraceRecord {
        envelope,
        exit_code_i32: 0,
        evidence,
        redacted_output_hash_32: [3u8; 32],
    }
}

fn main() {
    let trail = build_trail(10_000);
    let writer = TraceWriter::new(LearningMode::Off);
    let record = sample_record();
    let candidate = "BUILD_EXIT=0\nnormal evidence line\nmemory_root.move ok\n";

    let filter_ns = measure(|| {
        black_box(trail.filter_action(black_box(AuditAction::Kill)));
    });
    let trace_ns = measure(|| {
        black_box(writer.trace_line(black_box(&record), TraceClassKind::SideEffect));
    });
    let scan_ns = measure(|| {
        let mut s = ReleaseSecretScan::new();
        s.add(ReleaseSurface::Repo, black_box(candidate));
        black_box(s.is_clean());
    });

    let to_ms = |ns: u64| ns / 1_000_000;
    let filter_p95 = p95_ms(&filter_ns);
    let trace_p95 = p95_ms(&trace_ns);
    let scan_p95 = p95_ms(&scan_ns);

    // The audit 10k filter rides the refresh axis (250ms ceiling); the trace line
    // and the secret scan ride the render axis (5ms ceiling).
    let budget = LatencyBudget {
        keypress_p95_ms: 16,
        parse_p95_ms: 10,
        render_p95_ms: 5,
        refresh_p95_ms: 250,
    };
    let score = LatencyScore::evaluate(
        budget,
        0,
        0,
        to_ms(trace_p95.max(scan_p95)),
        to_ms(filter_p95),
    );

    let mut out = std::io::stdout().lock();
    let _ = writeln!(
        out,
        "stage_f_latency harness  iters={ITERS}  (p95 nearest-rank)"
    );
    let _ = writeln!(
        out,
        "  audit_filter_10k p95={filter_p95:>10} ns  budget {:>3} ms",
        budget.refresh_p95_ms
    );
    let _ = writeln!(
        out,
        "  trace_line       p95={trace_p95:>10} ns  budget {:>3} ms",
        budget.render_p95_ms
    );
    let _ = writeln!(
        out,
        "  release_scan     p95={scan_p95:>10} ns  budget {:>3} ms",
        budget.render_p95_ms
    );
    let _ = writeln!(
        out,
        "  score: render_ok={} refresh_ok={} all_ok={}",
        score.render_ok,
        score.refresh_ok,
        score.all_ok()
    );
}
