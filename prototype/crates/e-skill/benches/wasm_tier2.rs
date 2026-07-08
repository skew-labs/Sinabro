//! D-WP-02 · atom #273 · D.1.17 — WASM Tier-2 policy overhead benchmark.
//!
//! Measures the *policy* surface (module-id validation, metering, the hostcall
//! table hash, and a filesystem deny check). Under the D-WP-02 policy model
//! there is no real engine to cold/warm start, so these are the per-decision
//! overheads the CLI / agent pays; all sit far under the 2 s try-before-use
//! budget. Results are written to `ops/evidence/stage_d/wasm_bench.md`.

use std::hint::black_box;

use criterion::{Criterion, criterion_group, criterion_main};
use mnemos_e_skill::{
    ResourceDemand, SkillRuntimePermission, WasmRuntimeLimits, WasmTier2ModuleId, enforce_meter,
    evaluate_fs_access, hostcall_table_hash,
};

fn wasm_tier2_benches(c: &mut Criterion) {
    let valid_module = [0x00u8, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00];
    c.bench_function("module_id_from_wasm_bytes", |b| {
        b.iter(|| WasmTier2ModuleId::from_wasm_bytes(black_box(&valid_module)));
    });

    let limits = WasmRuntimeLimits::deny_small();
    let demand = ResourceDemand::minimal();
    c.bench_function("enforce_meter", |b| {
        b.iter(|| enforce_meter(black_box(&limits), black_box(&demand)));
    });

    c.bench_function("hostcall_table_hash", |b| b.iter(hostcall_table_hash));

    let declared = ["input/sample.json"];
    c.bench_function("evaluate_fs_access", |b| {
        b.iter(|| {
            evaluate_fs_access(
                black_box(&declared),
                black_box("input/sample.json"),
                SkillRuntimePermission::FileRead,
            )
        });
    });
}

criterion_group!(benches, wasm_tier2_benches);
criterion_main!(benches);
