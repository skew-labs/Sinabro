//! Integration test — Stage B **live Walrus testnet PUT** (atom #116 · B.2.15).
//!
//! # What this atom is
//!
//! The canonical OUT is *live PUT evidence for one synthetic fixture*: this test
//! drives the real Stage A `c-walrus` reqwest transport ([`ReqwestPublisher`],
//! `feature = "net-testnet"`) through the real publisher loop
//! ([`publish_blob_with_transport`]) against the public Walrus testnet publisher,
//! using the Stage B `b-memory` PUT-plan seam ([`WalrusPutPlan::plan`], atom
//! #103) and the §4.0 attestation companion surface minted at this atom
//! ([`StageBTrustBoundaryReceipt`] / [`SafetyKernelBuildRef`] /
//! [`StageBTrustMode`]). The recorded evidence is a redacted receipt: the
//! reported blob id, the local content digest, the local placeholder derive, the
//! endpoint label, the latency, and the trust-boundary receipt — never the
//! secret body of anything (the fixture is public-safe by construction).
//!
//! # Why this test is `#[ignore]`d and feature-gated
//!
//! - **`#![cfg(feature = "net-testnet")]`**: without the feature the file
//!   compiles to nothing, so the default offline `cargo test --workspace`
//!   (`G-B-WALRUS-OFFLINE`) never references a network type.
//! - **`#[ignore]`**: even with the feature, the live PUT never runs
//!   automatically. It must be invoked explicitly, and only after the operator
//!   approves a single synthetic-fixture PUT in the same message
//!   (`G-B-WALRUS-TESTNET`). Run with:
//!   `cargo test -p mnemos-b-memory --features net-testnet --test stage_b_live_put -- --ignored --nocapture`
//!
//! # Approval scope (user, same-message, this session)
//!
//! One live PUT only; Walrus testnet only; synthetic public fixture payload
//! only; no mainnet, no private memory, no provider body, no secrets; no
//! automatic retry after an unknown boundary (enforced structurally by
//! `max_attempts = 1` — exactly one `put_blob` call); record only a redacted
//! receipt + blob id + digest + endpoint label + latency + evidence hash; the
//! memory owner is the user-controlled Sui address, never the publisher.
//!
//! # ADVISORY — local-derive vs reported id (atom #117 boundary)
//!
//! [`derive_walrus_blob_id`] is the **Phase 0 placeholder ARX** derivation
//! (`c-walrus::blob_id::derive_blob_id` — the real Walrus Reed-Solomon / BLAKE2b
//! algorithm is the documented but **not-yet-implemented** `net-testnet` swap
//! seam). So the public publisher's reported blob id will **not** byte-match the
//! local derive, and `stage_b_verify_blob_id` would return `RootMismatch`. This
//! atom (#116) therefore only *records* the reported id and the local derive
//! side by side; it does **not** assert they match. Promoting a reported id to a
//! `VerifiedBlobId` (atom #108) over a live GET is atom #117's job and is blocked
//! until the real algorithm is swapped in — recorded as a no-op decision for the
//! verifier, not fixed here.

#![cfg(feature = "net-testnet")]
#![allow(clippy::unwrap_used)]
#![allow(clippy::expect_used)]
#![allow(clippy::panic)]
#![allow(clippy::print_stdout)]

use mnemos_b_memory::{
    ContentHash32, SafetyKernelBuildRef, StageBTraceEvidence, StageBTraceLink,
    StageBTrustBoundaryReceipt, StageBTrustMode, WalrusPutPlan, WalrusTestnetEndpoint,
    WalrusTestnetPreflightReport, derive_walrus_blob_id, feature_compiled,
};
use mnemos_c_walrus::publisher::{
    EpochCount, PublishPayloadClass, PublisherResponseDecision, publish_blob_with_transport,
};
use mnemos_c_walrus::reqwest_transport::ReqwestPublisher;
use mnemos_d_move::SuiAddress;

/// User-approved (same-message, OD-1) owner address: the user-controlled Sui
/// testnet address whose memory this live PUT belongs to. Recorded as the
/// receipt owner — never the publisher / a helper key.
/// `0x2278c912799f1036862e2af2606caf21d5205dd043cd7ad753d3370a80e6ee4d`.
const OWNER_ADDRESS_BYTES: [u8; 32] = [
    0x22, 0x78, 0xc9, 0x12, 0x79, 0x9f, 0x10, 0x36, 0x86, 0x2e, 0x2a, 0xf2, 0x60, 0x6c, 0xaf, 0x21,
    0xd5, 0x20, 0x5d, 0xd0, 0x43, 0xcd, 0x7a, 0xd7, 0x53, 0xd3, 0x37, 0x0a, 0x80, 0xe6, 0xee, 0x4d,
];

/// Per-attempt timeout for the live PUT (also fed to the #114 preflight). Within
/// `[MIN_PREFLIGHT_TIMEOUT_MS, MAX_PREFLIGHT_TIMEOUT_MS]`.
const LIVE_PUT_TIMEOUT_MS: u32 = 30_000;

/// Render a 32-byte array as lower-case hex for evidence lines (public-safe — a
/// content digest / blob id is not secret).
fn hex32(bytes: &[u8; 32]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(64);
    for &b in bytes {
        out.push(HEX[(b >> 4) as usize] as char);
        out.push(HEX[(b & 0x0f) as usize] as char);
    }
    out
}

/// Live Walrus testnet PUT of one synthetic public fixture. Records the reported
/// blob id, the local content digest, the local placeholder derive, the
/// endpoint label, the latency, and a §4.0 trust-boundary receipt. Asserts:
///
/// 1. the live PUT is `Accepted` with a non-empty reported blob id;
/// 2. the safety-kernel build reference is recorded in the receipt (honest
///    unattested-local sentinel — `LocalOnly`, never silently "official");
/// 3. the recorded owner is the user-controlled address (non-zero, equal to the
///    approved address), never the publisher.
#[test]
#[ignore = "live Walrus testnet PUT; requires same-message user approval + network. Run: --features net-testnet --test stage_b_live_put -- --ignored --nocapture"]
fn b2_15_live_walrus_testnet_put_synthetic_fixture() {
    // Synthetic, public, hand-authored fixture — no user memory, no provider
    // body, no secret. The only payload class admitted to the public testnet.
    let payload: &[u8] =
        b"mnemos atom 116 B.2.15 synthetic public fixture -- live Walrus testnet PUT";

    // Per-action trace stamp (atom #81 / #94). atom_id 116 (!= 0) so the trace
    // is stamped rather than the missing-trace sentinel.
    let trace = StageBTraceLink::new(0xB215_0001, 116, 0);
    let ev = StageBTraceEvidence::from_trace(trace)
        .expect("atom_id 116 is non-zero so the trace is stamped");

    // #114 preflight readiness BEFORE a single byte leaves: feature compiled,
    // endpoint sanctioned, payload class admitted, timeout in range, trace
    // stamped. A not-ready report aborts before any network contact.
    let preflight = WalrusTestnetPreflightReport::assess(
        WalrusTestnetEndpoint::testnet(),
        true, // dns_resolved: we are about to reach the network; the PUT proves it.
        feature_compiled(),
        PublishPayloadClass::SyntheticPublicFixture,
        LIVE_PUT_TIMEOUT_MS,
        trace,
    );
    assert!(
        preflight.is_ready(),
        "preflight must be ready before a live PUT: {preflight:?}"
    );
    assert!(
        feature_compiled(),
        "this test only compiles under --features net-testnet"
    );

    // #103 PUT plan: content-class policy + body cap + stamped trace, BEFORE any
    // transport type is built. 1 epoch (minimal). The synthetic public fixture
    // is the only class that plans.
    let put_plan: WalrusPutPlan<'_> = WalrusPutPlan::plan(
        WalrusTestnetEndpoint::testnet(),
        EpochCount::new(1).expect("1 epoch is positive"),
        payload,
        PublishPayloadClass::SyntheticPublicFixture,
        ev,
    )
    .expect("synthetic public fixture within cap plans");

    // Local derivations the owner holds independently of the server.
    let content_digest = ContentHash32::of(payload);
    let local_derive = derive_walrus_blob_id(payload);

    // The real reqwest transport (net-testnet) — one TCP pool, positive timeout.
    let mut transport =
        ReqwestPublisher::new(LIVE_PUT_TIMEOUT_MS).expect("client builds with a positive timeout");

    // Drive the REAL c-walrus publisher loop. `max_attempts = 1` makes "one live
    // PUT only" structural: exactly one `put_blob` call, and an unknown boundary
    // can never trigger an automatic second PUT.
    let run = publish_blob_with_transport(&mut transport, &put_plan.request, 0xB215_0001, 1)
        .expect("the publisher loop returns a well-formed run for a single attempt");

    // ----- evidence (public-safe; no body bytes) -----
    println!(
        "LIVE_PUT_EVIDENCE atom=116 endpoint=publisher.walrus-testnet.walrus.space \
         attempts={} payload_len={} content_digest={} local_derive_placeholder={}",
        run.attempts_u16,
        payload.len(),
        hex32(content_digest.as_bytes()),
        hex32(local_derive.as_bytes()),
    );
    for diag in &run.diagnostics {
        println!("LIVE_PUT_DIAGNOSTIC {diag}");
    }

    // (1) the live PUT is Accepted with a non-empty reported blob id.
    let reported = match run.decision {
        PublisherResponseDecision::Accepted {
            variant,
            reported_blob_id,
        } => {
            println!(
                "LIVE_PUT_ACCEPTED variant={} reported_blob_id={}",
                variant.class_label(),
                reported_blob_id.as_str()
            );
            reported_blob_id
        }
        PublisherResponseDecision::Stopped {
            reason,
            retry,
            boundary,
        } => panic!(
            "expected Accepted from the live testnet PUT, got Stopped(reason={}, retry={}, boundary={})",
            reason.class_label(),
            retry.class_label(),
            boundary.class_label()
        ),
        // `PublisherResponseDecision` is #[non_exhaustive]; a cross-crate match
        // requires a wildcard. No other variant exists today.
        other => panic!("unexpected PublisherResponseDecision variant: {other:?}"),
    };
    assert_eq!(
        run.attempts_u16, 1,
        "exactly one live PUT (max_attempts = 1)"
    );
    assert!(
        !reported.as_str().is_empty(),
        "the publisher reported a non-empty blob id"
    );

    // §4.0 attestation companion: build the trust-boundary receipt. This is an
    // unattested local CLI run (mnemos is not a git repo this phase, no official
    // attestation), so the safety-kernel build reference is the honest
    // unattested-local sentinel — recorded, never fabricated as "official".
    let build = SafetyKernelBuildRef::unattested_local();
    let owner = SuiAddress::new(OWNER_ADDRESS_BYTES);
    let receipt = StageBTrustBoundaryReceipt::new(build, owner, trace);
    println!(
        "LIVE_PUT_ATTESTATION trust_mode={} safety_kernel_hash={} owner={}",
        receipt.build.trust_mode.class_label(),
        hex32(&receipt.build.safety_kernel_hash_32),
        hex32(receipt.owner.as_bytes()),
    );

    // (2) the safety-kernel build reference is recorded, honestly unattested.
    assert_eq!(
        receipt.build.trust_mode,
        StageBTrustMode::LocalOnly,
        "an unattested local CLI run records LocalOnly"
    );
    assert!(
        !receipt.build.is_official_attested(),
        "an unattested local run never reads as officially attested"
    );
    // The safety-kernel hash field exists and is recorded in the receipt (the
    // unattested-local sentinel for this run).
    assert_eq!(
        receipt.build.safety_kernel_hash_32, build.safety_kernel_hash_32,
        "the safety-kernel hash is recorded in the receipt"
    );

    // (3) the recorded owner is the user-controlled address, never the server.
    assert_eq!(
        receipt.owner,
        SuiAddress::new(OWNER_ADDRESS_BYTES),
        "the owner is the user-approved Sui address"
    );
    assert_ne!(
        receipt.owner.as_bytes(),
        &[0u8; 32],
        "the owner key is a real user-controlled address, not the zero sentinel"
    );
}
