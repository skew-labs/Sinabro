//! Stage C cross-type binding test for the incident pause (C-WP-08 · atom #237).
//!
//! The atom #237 incident pause lives in `k-devex` and gates a Gas Station
//! sponsor decision as a plain `bool` rather than importing the atom #218
//! `g-wallet` `GasStationDecision` type — so `k-devex` gains no `g-wallet`
//! dependency (Sinabro Physical Law 1: the test home owns both symbols, and this
//! `o-stage-c-e2e` crate already dev-depends on `g-wallet` + `k-devex` +
//! `d-move` + `a-core`). This test is the binding that proves "reuse #218": the
//! boolean the pause withholds is exactly a real `evaluate_sponsorship` verdict's
//! `accepted` field.
//!
//! No live action: all values are in-memory; nothing signs, sponsors, or submits.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use mnemos_a_core::trace::{StageBTraceLink, StageCTraceLink};
use mnemos_d_move::sdk::SuiCallBuilder;
use mnemos_d_move::stage_c_effect_delta::EffectDelta;
use mnemos_d_move::types::{GasBudgetMist, MemoryRootArgs, ObjectId, SuiAddress};
use mnemos_g_wallet::{
    GasIntent, GasSponsorMode, GasStationDecision, GasStationPolicy, OfficialTrustDecision,
    SafetyKernelAttestation, SafetyKernelBuildRef, SponsoredFunction, SponsorshipRequest,
    evaluate_sponsorship,
};
use mnemos_k_devex::{IncidentPause, PauseReason};

fn trace() -> StageCTraceLink {
    StageCTraceLink::new(StageBTraceLink::new(0xA17B_0237, 237, 0), 237, 18)
}

fn sample_call() -> SuiCallBuilder {
    let args = MemoryRootArgs {
        owner: SuiAddress::new([0x01; 32]),
        root_hash: [0x02; 32],
        epoch_u64: 1,
    };
    SuiCallBuilder::add_chunk(
        ObjectId::new([0x03; 32]),
        &args,
        GasBudgetMist::new(800_000),
    )
    .expect("call builds")
}

fn valid_att(expires: u64) -> SafetyKernelAttestation {
    SafetyKernelAttestation {
        build: SafetyKernelBuildRef {
            build_id_u64: 1,
            release_hash_32: [0x11; 32],
        },
        sbom_hash_32: [0x22; 32],
        reproducible_build_hash_32: [0x33; 32],
        sandbox_policy_hash_32: [0x44; 32],
        evidence_schema_hash_32: [0x55; 32],
        expires_epoch_u64: expires,
    }
}

fn effect() -> EffectDelta {
    EffectDelta::from_dev_inspect(true, 1, 1, 64, 1000, 0).expect("effect builds")
}

fn accepted_decision() -> GasStationDecision {
    let call = sample_call();
    let policy = GasStationPolicy {
        mode: GasSponsorMode::Hosted,
        package: *call.package(),
        max_gas_per_tx: GasBudgetMist::new(800_000),
        max_txs_per_epoch_u32: 1_000,
        max_storage_bytes_u32: 1_000_000,
        allowed_mask_u16: GasStationPolicy::INITIAL_ALLOWED_MASK,
        update_semantics_via_add_chunk: true,
        require_official_safety_kernel: true,
    };
    let req = SponsorshipRequest {
        intent: GasIntent::TypedCall(&call),
        function: SponsoredFunction::MemoryAddChunk,
        presented_package: *call.package(),
        observed_effect: effect(),
        expected_effect: effect(),
        attestation: Some(valid_att(100)),
        now_epoch_u64: 10,
        requested_gas: GasBudgetMist::new(800_000),
        nonce_fresh: true,
        within_quota: true,
        lease_valid: true,
    };
    evaluate_sponsorship(&policy, &req, trace())
}

/// A real, fully-conforming `evaluate_sponsorship` verdict is `accepted`; while
/// the incident pause is clear it may proceed, but once the pause is engaged the
/// very same accepted decision is withheld. This is the reuse-#218 binding: the
/// pause gates the real decision's `accepted` field.
#[test]
fn pause_withholds_real_accepted_sponsor_decision() {
    let decision = accepted_decision();
    // The real decision is accepted and officially trusted (sanity: this is a
    // genuine accept, not a fabricated bool).
    assert!(decision.accepted);
    assert_eq!(decision.reject, None);
    assert_eq!(decision.trust, OfficialTrustDecision::OfficialTrusted);

    // Pause clear → the accepted decision may proceed.
    let mut gate = IncidentPause::running();
    assert!(gate.allows_sponsor_decision(decision.accepted));

    // Pause engaged → the same accepted decision is withheld before any signer
    // boundary.
    gate.pause(PauseReason::GasStationAnomaly);
    assert!(!gate.allows_sponsor_decision(decision.accepted));
}

/// A rejected sponsor decision stays rejected whether or not the pause is
/// engaged — the pause only ever *withholds*, never grants.
#[test]
fn pause_never_grants_a_rejected_decision() {
    // Build a rejected decision by offering an opaque-bytes intent.
    let call = sample_call();
    let policy = GasStationPolicy {
        mode: GasSponsorMode::Hosted,
        package: *call.package(),
        max_gas_per_tx: GasBudgetMist::new(800_000),
        max_txs_per_epoch_u32: 1_000,
        max_storage_bytes_u32: 1_000_000,
        allowed_mask_u16: GasStationPolicy::INITIAL_ALLOWED_MASK,
        update_semantics_via_add_chunk: true,
        require_official_safety_kernel: true,
    };
    let req = SponsorshipRequest {
        intent: GasIntent::OpaqueBytes,
        function: SponsoredFunction::MemoryAddChunk,
        presented_package: *call.package(),
        observed_effect: effect(),
        expected_effect: effect(),
        attestation: Some(valid_att(100)),
        now_epoch_u64: 10,
        requested_gas: GasBudgetMist::new(800_000),
        nonce_fresh: true,
        within_quota: true,
        lease_valid: true,
    };
    let decision = evaluate_sponsorship(&policy, &req, trace());
    assert!(!decision.accepted);

    // Running pause does not turn a rejected decision into an allowed one.
    let gate = IncidentPause::running();
    assert!(!gate.allows_sponsor_decision(decision.accepted));
}
