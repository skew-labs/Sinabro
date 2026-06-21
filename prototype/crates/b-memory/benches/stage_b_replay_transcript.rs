//! Criterion bench harness — atom #166 · B.5.3 (replay transcript hash throughput).
//!
//! Measures the [`stage_b_transcript_hash`] AI-HOT path: the domain-separated ARX
//! content hash over a finished replay transcript buffer. The cost scales with the
//! transcript byte length (the ARX absorb walks the bytes), so it is swept across a
//! record-count ladder. Each replay record is a fixed 106 bytes (1 tag + 8
//! event_seq + 1 decision + 32 blob_id + 32 digest + 32 root), built **once,
//! outside** the measured loop.
//!
//! Two run modes share the same binary (mirrors `benches/stage_b_blob_id.rs`):
//!
//! * Default `cargo bench` → criterion statistical sweep.
//! * `MNEMOS_BENCH_EMIT_BASELINE=1 cargo bench --bench stage_b_replay_transcript`
//!   → bypass criterion and write a single canonical
//!   `stage_b_replay_transcript_baseline.json` record (deterministic 100 warmup +
//!   1000 measured iterations per cell). Path overridable via
//!   `MNEMOS_BENCH_BASELINE_PATH`.
//!
//! Smoke gate: `cargo bench --bench stage_b_replay_transcript --no-run --offline
//! --locked` must exit 0 (G-B-BENCH smoke). Full numerical runs are reserved for
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

use std::time::Instant;

use criterion::{BenchmarkGroup, Criterion, Throughput, black_box};

use mnemos_b_memory::stage_b_transcript_hash;

const RECORD_BYTES: usize = 106;
const RECORD_LADDER: &[usize] = &[16, 256, 4096];
const WARMUP_ITERS: u32 = 100;
const MEASURED_ITERS: u32 = 1_000;

/// Build a deterministic transcript buffer of `records` fixed-width records.
fn transcript_buffer(records: usize) -> Vec<u8> {
    let mut buf = Vec::with_capacity(records * RECORD_BYTES);
    for i in 0..records {
        let seq = i as u64;
        buf.push((i % 2) as u8); // tag (anchor/audit)
        buf.extend_from_slice(&seq.to_le_bytes());
        buf.push(((i % 5) + 1) as u8); // decision discriminant 1..5
        buf.extend_from_slice(&[(i & 0xFF) as u8; 32]); // blob_id / log
        buf.extend_from_slice(&[((i >> 8) & 0xFF) as u8; 32]); // digest / entry_hash
        buf.extend_from_slice(&[((i >> 16) & 0xFF) as u8; 32]); // root
    }
    buf
}

fn bench_transcript(c: &mut Criterion) {
    let mut g: BenchmarkGroup<'_, _> = c.benchmark_group("stage_b::transcript_hash");
    for &records in RECORD_LADDER {
        let buf = transcript_buffer(records);
        g.throughput(Throughput::Bytes(buf.len() as u64));
        g.bench_function(format!("records_{records}"), |b| {
            b.iter(|| {
                let h = stage_b_transcript_hash(black_box(&buf));
                black_box(h);
            });
        });
    }
    g.finish();
}

fn measure(records: usize) -> (u128, usize) {
    let buf = transcript_buffer(records);
    for _ in 0..WARMUP_ITERS {
        black_box(stage_b_transcript_hash(&buf));
    }
    let t0 = Instant::now();
    for _ in 0..MEASURED_ITERS {
        black_box(stage_b_transcript_hash(black_box(&buf)));
    }
    (t0.elapsed().as_nanos(), buf.len())
}

fn emit_baseline_json(path: &str) {
    let mut s = String::new();
    s.push_str("{\n");
    s.push_str("  \"schema\": \"mnemos.bench.v0\",\n");
    s.push_str("  \"atom\": 166,\n");
    s.push_str("  \"id\": \"B.5.3\",\n");
    s.push_str(&format!(
        "  \"host\": {{ \"os\": \"{}\", \"arch\": \"{}\" }},\n",
        std::env::consts::OS,
        std::env::consts::ARCH
    ));
    s.push_str(&format!("  \"warmup_iters\": {WARMUP_ITERS},\n"));
    s.push_str(&format!("  \"measured_iters\": {MEASURED_ITERS},\n"));
    s.push_str("  \"results\": [\n");

    let mut rows: Vec<String> = Vec::new();
    for &records in RECORD_LADDER {
        let (ns_total, bytes) = measure(records);
        let ns_per_op = (ns_total as f64) / (MEASURED_ITERS as f64);
        rows.push(format!(
            "    {{ \"op\": \"stage_b_transcript_hash\", \"records\": {records}, \"bytes\": {bytes}, \"ns_per_op\": {ns_per_op:.2} }}"
        ));
    }

    s.push_str(&rows.join(",\n"));
    s.push_str("\n  ]\n");
    s.push_str("}\n");

    std::fs::write(path, s.as_bytes()).expect("write stage_b_replay_transcript_baseline.json");
    eprintln!("baseline written: {path}");
}

fn main() {
    if std::env::var("MNEMOS_BENCH_EMIT_BASELINE").is_ok() {
        let path = std::env::var("MNEMOS_BENCH_BASELINE_PATH")
            .unwrap_or_else(|_| "stage_b_replay_transcript_baseline.json".to_string());
        emit_baseline_json(&path);
        return;
    }

    let mut c = Criterion::default().configure_from_args();
    bench_transcript(&mut c);
    c.final_summary();
}
