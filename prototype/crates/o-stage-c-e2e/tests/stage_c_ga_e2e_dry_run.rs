//! Stage C GA E2E dry-run (C-WP-03A · atom #198 · C.0.27).
//!
//! Canonical OUT: the complete product path exercised end-to-end WITHOUT a
//! mainnet write — signed chunk → Walrus verified fixture → Sui dry-run → gas
//! trace → replay-hash stability.
//!
//! Reuse (no re-mint): g-wallet ed25519 signing, c-walrus offline blob-id
//! derive/verify, d-move `SuiCallBuilder` dry-run + `GasTraceSample`, the §4.0
//! `StageCTraceLink`, b-memory `ContentHash32`, and the atom #191
//! [`StageCSuiEventLedger`] for replay idempotency. No live network, no mainnet.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use mnemos_a_core::trace::{StageBTraceLink, StageCTraceLink};
use mnemos_b_memory::chunk_digest::ContentHash32;
use mnemos_c_walrus::{
    PublisherReportedBlobId, derive_blob_id, encode_base64url_no_pad_32, verify_reported_blob_id,
};
use mnemos_d_move::stage_c_gas_trace::{GasTraceFunction, GasTraceSample};
use mnemos_d_move::stage_c_idempotency::{StageCSuiEventLedger, SuiEventCoord, SuiEventOutcome};
use mnemos_d_move::{
    GasBudgetMist, MemoryRootArgs, ObjectId, SUI_DRY_RUN_BYTES_ADD_CHUNK_LEN, SuiAddress,
    SuiCallBuilder,
};
use mnemos_g_wallet::{SealedKeypair, sign_move_tx};

/// Deterministic synthetic-public-fixture content for the dry-run.
const E2E_CONTENT: &[u8] = b"mnemos stage-c ga e2e synthetic public fixture";

fn e2e_trace() -> StageCTraceLink {
    StageCTraceLink::new(StageBTraceLink::new(0xA17B_0198, 198, 0), 198, 37)
}

fn fixture_args() -> MemoryRootArgs {
    MemoryRootArgs {
        owner: SuiAddress::new([0xAAu8; 32]),
        root_hash: [0xBBu8; 32],
        epoch_u64: 0x0102_0304_0506_0708,
    }
}

fn fixture_dry_run_bytes() -> Vec<u8> {
    SuiCallBuilder::add_chunk(
        ObjectId::new([0xCCu8; 32]),
        &fixture_args(),
        GasBudgetMist::new(800_000),
    )
    .expect("non-zero gas builds")
    .to_dry_run_bytes()
    .expect("dry-run bytes are infallible for fixed-len inputs")
}

fn fixture_gas_sample(tx_bytes_u32: u32) -> GasTraceSample {
    GasTraceSample {
        function: GasTraceFunction::MemoryAddChunk,
        package: ObjectId::new([0u8; 32]),
        gas_budget: GasBudgetMist::new(800_000),
        computation_mist_u64: 500_000,
        storage_mist_u64: 200_000,
        rebate_mist_u64: 50_000,
        object_writes_u16: 1,
        event_bytes_u32: 107,
        tx_bytes_u32,
        trace: e2e_trace(),
    }
}

/// Assemble the DETERMINISTIC dry-run evidence bundle (Walrus verified blob id ‖
/// Sui dry-run bytes ‖ gas-sample bytes — everything except the per-run random
/// signature) and return its stable replay hash.
fn replay_bundle_hash() -> [u8; 32] {
    let blob = derive_blob_id(E2E_CONTENT);
    let text = encode_base64url_no_pad_32(blob.as_bytes());
    let reported = PublisherReportedBlobId::try_from_text(&text).expect("derived id parses");
    let verified = verify_reported_blob_id(E2E_CONTENT, &reported).expect("derived id verifies");

    let dry = fixture_dry_run_bytes();
    let gas = fixture_gas_sample(dry.len() as u32);

    let mut bundle = Vec::new();
    bundle.extend_from_slice(verified.as_blob_id().as_bytes());
    bundle.extend_from_slice(&dry);
    bundle.extend_from_slice(&gas.to_bytes());
    *ContentHash32::of(&bundle).as_bytes()
}

#[test]
fn e2e_dry_run_green() {
    // Step 1 — signed chunk: a real ed25519 signature over the dry-run bytes.
    // The only external path to a ScopedSecretKey is seal+unseal (no public bare
    // constructor), so the key is freshly sealed under a test passphrase.
    let dry = fixture_dry_run_bytes();
    let sealed = SealedKeypair::create_encrypted("e2e-dry-run-passphrase").expect("seal");
    let key = sealed.unseal("e2e-dry-run-passphrase").expect("unseal");
    let sig = sign_move_tx(&key, &dry);
    assert_eq!(sig.as_bytes().len(), 64, "ed25519 signature is 64 bytes");

    // Step 2 — Walrus verified fixture: offline derive → reported → verify.
    let blob = derive_blob_id(E2E_CONTENT);
    let text = encode_base64url_no_pad_32(blob.as_bytes());
    let reported = PublisherReportedBlobId::try_from_text(&text).expect("parse");
    let verified = verify_reported_blob_id(E2E_CONTENT, &reported).expect("verify");
    assert_eq!(verified.as_blob_id().as_bytes(), blob.as_bytes());

    // Step 3 — Sui dry-run carrier is the pinned 166-byte width.
    assert_eq!(dry.len(), SUI_DRY_RUN_BYTES_ADD_CHUNK_LEN);
    assert_eq!(dry.len(), 166);
}

#[test]
fn trace_linked() {
    // The gas sample carries the Stage C trace, greppable by atom + gate.
    let gas = fixture_gas_sample(166);
    assert_eq!(gas.trace.stage_c_atom_u16, 198);
    assert_eq!(gas.trace.gate_id_u16, 37);
    assert_eq!(gas.trace.trace.atom_id_u16, 198);
    assert_eq!(gas.trace.trace.trace_id_u64, 0xA17B_0198);
}

#[test]
fn gas_sample_green() {
    let dry = fixture_dry_run_bytes();
    let gas = fixture_gas_sample(dry.len() as u32);
    assert_eq!(gas.to_bytes().len(), 90);
    assert_eq!(gas.tx_bytes_u32, 166);
    // gross = comp + storage; net = gross - rebate.
    assert_eq!(gas.net_charged_mist(), 650_000);
}

#[test]
fn replay_hash_stable() {
    // The deterministic dry-run bundle hashes identically across two independent
    // assemblies — the replay evidence hash is stable.
    assert_eq!(replay_bundle_hash(), replay_bundle_hash());

    // And replaying the same on-chain event coordinate is idempotent: a
    // duplicate reconciles, it does not re-apply.
    let mut ledger = StageCSuiEventLedger::new();
    let coord = SuiEventCoord::new([0x11u8; 32], 0);
    assert_eq!(
        ledger.observe(coord, e2e_trace()),
        SuiEventOutcome::FirstSeen
    );
    assert_eq!(
        ledger.observe(coord, e2e_trace()),
        SuiEventOutcome::DuplicateIgnored
    );
    assert_eq!(ledger.len(), 1);
}
