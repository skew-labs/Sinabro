//! Integration test — Stage B **live Walrus testnet GET + verify**
//! (atom #117 · B.2.16). `feature = "net-testnet"` only, `#[ignore]`d.
//!
//! # What this atom is
//!
//! The canonical OUT is *live GET evidence + a Stage A [`VerifiedBlobId`]* for
//! one synthetic fixture. The fixture is the public blob Stage B atom #116
//! (`B.2.15`) already PUT to the public Walrus testnet — reported id
//! `TjKHSEwJcAqzBaxGMmB0fYWcgYdxBUnMZRdnV7c-UEk`, still alive. **This atom does
//! not PUT.** It performs exactly one read-only GET of that existing blob and
//! proves the bytes are ours.
//!
//! The flow, in order:
//!
//! 1. **Pre-GET promotion** — re-derive the *official* Walrus RS2 oracle id
//!    ([`stage_b_verify_testnet_blob_id`], bridge atom #116.5) over the exact
//!    #116 bytes we hold and require a byte-match against the reported id. The
//!    server is **not** an oracle: a [`VerifiedBlobId`] exists only because our
//!    own local derivation matched.
//! 2. **Plan + GET** — plan the GET against the sealed public testnet aggregator
//!    ([`WalrusGetPlan::plan`], atom #105); the GET URL is the #116.75 base64url
//!    form, composed only from the verified id. Fire one read-only GET through
//!    the real `c-walrus` [`ReqwestAggregator`] (`net-testnet`).
//! 3. **Verify returned bytes** — parse + cap the body ([`parse_walrus_get_response`],
//!    atom #106), assert the returned bytes equal the #116 fixture byte-for-byte
//!    (the 광기 spec: *GET returned bytes must match local digest and reported
//!    id; self-report is never enough*), then re-derive the official id from the
//!    **returned** bytes and confirm it matches the local official derive.
//!
//! # Why this test is `#[ignore]`d and feature-gated
//!
//! - **`#![cfg(feature = "net-testnet")]`**: without the feature the file
//!   compiles to nothing, so the default offline `cargo test --workspace`
//!   (`G-B-WALRUS-OFFLINE`) never references a network type.
//! - **`#[ignore]`**: even with the feature, the live GET never runs
//!   automatically. It must be invoked explicitly, and only after the operator
//!   approves a single read-only GET in the same message (`G-B-WALRUS-TESTNET`).
//!   Run with:
//!   `cargo test -p mnemos-b-memory --features net-testnet --test stage_b_live_get_verify -- --ignored --nocapture`
//!
//! # Approval scope (user, same-message, this session)
//!
//! One read-only GET only; Walrus testnet only; the existing #116 blob only; no
//! PUT, no extra blob, no mainnet, no wallet signing, no wallet secret; record
//! only redacted evidence (latency, endpoint class, reported id, local derive,
//! `VerifiedBlobId` promotion); fail closed on any byte / blob-id mismatch with
//! no blind retry (structurally: exactly one `get_blob` call, every fallible
//! step `expect`s so a failure aborts the test instead of retrying).

#![cfg(feature = "net-testnet")]
#![allow(clippy::unwrap_used)]
#![allow(clippy::expect_used)]
#![allow(clippy::panic)]
#![allow(clippy::print_stdout)]

use mnemos_b_memory::{
    StageBTraceEvidence, StageBTraceLink, WalrusGetBody, WalrusGetPlan,
    derive_walrus_testnet_blob_id, parse_walrus_get_response, stage_b_verify_testnet_blob_id,
};
use mnemos_c_walrus::publisher::PublisherReportedBlobId;
use mnemos_c_walrus::reqwest_transport::ReqwestAggregator;
use mnemos_c_walrus::{AggregatorEndpoint, AggregatorTransport};

/// The exact synthetic public fixture PUT by Stage B atom #116 (`B.2.15`) — the
/// only payload this read-only GET targets. Pinned identically to the #116.5
/// oracle test fixture.
const ATOM_116_PAYLOAD: &[u8] =
    b"mnemos atom 116 B.2.15 synthetic public fixture -- live Walrus testnet PUT";

/// The blob id the public Walrus testnet publisher reported for
/// [`ATOM_116_PAYLOAD`] at atom #116 (URL-safe base64, no padding, 43 chars).
const ATOM_116_REPORTED_ID: &str = "TjKHSEwJcAqzBaxGMmB0fYWcgYdxBUnMZRdnV7c-UEk";

/// Per-attempt timeout for the one live GET, in milliseconds.
const LIVE_GET_TIMEOUT_MS: u32 = 30_000;

/// Render a 32-byte id as lower-case hex for evidence lines (public-safe — a
/// content-addressed blob id is not secret).
fn hex32(bytes: &[u8; 32]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(64);
    for &b in bytes {
        out.push(HEX[(b >> 4) as usize] as char);
        out.push(HEX[(b & 0x0f) as usize] as char);
    }
    out
}

/// Live Walrus testnet GET of the existing #116 blob, then verify the returned
/// bytes against the official RS2 oracle. Asserts:
///
/// 1. the reported id verifies against the #116 bytes we hold (pre-GET
///    promotion to a [`VerifiedBlobId`] via the local official derive);
/// 2. the GET-returned bytes equal the #116 fixture byte-for-byte;
/// 3. the official id re-derived from the **returned** bytes equals the local
///    official derive — self-report alone never promotes a blob id.
#[test]
#[ignore = "live Walrus testnet GET; requires same-message user approval + network. Run: --features net-testnet --test stage_b_live_get_verify -- --ignored --nocapture"]
fn b2_16_live_walrus_testnet_get_verify_atom_116_fixture() {
    // Per-action trace stamp (atom #81 / #94). atom_id 117 (!= 0) so the trace is
    // stamped rather than the missing-trace sentinel.
    let trace = StageBTraceLink::new(0xB216_0001, 117, 0);
    let evidence = StageBTraceEvidence::from_trace(trace)
        .expect("atom_id 117 is non-zero so the trace is stamped");

    // Server self-report: text validation only (well-formed base64url-43), not
    // yet trusted as an id.
    let reported = PublisherReportedBlobId::try_from_text(ATOM_116_REPORTED_ID)
        .expect("the #116 reported id is well-formed base64url-43 text");

    // (1) PRE-GET promotion. Re-derive the OFFICIAL RS2 oracle id over the EXACT
    // #116 bytes we hold and require a byte-match against the reported id. The
    // server is not an oracle — the VerifiedBlobId exists only because OUR local
    // derive matched (bridge atom #116.5 + #108 verify seam).
    let verified = stage_b_verify_testnet_blob_id(ATOM_116_PAYLOAD, &reported)
        .expect("the #116 reported id verifies against the #116 bytes under the RS2 oracle");

    // The locally derived official id, held independently of any server response.
    let local_official = derive_walrus_testnet_blob_id(ATOM_116_PAYLOAD)
        .expect("the #116 fixture is well under the encoding's max blob size");
    assert_eq!(
        verified.as_blob_id().as_bytes(),
        local_official.as_bytes(),
        "the verified id must wrap the locally derived official id, not server bytes"
    );

    // (2) Plan the GET against the sealed public testnet aggregator. The GET URL
    // is the #116.75 base64url form, composed only from the verified id.
    let plan = WalrusGetPlan::plan(AggregatorEndpoint::testnet_public(), &verified, evidence);
    let url = plan.get_url();
    println!(
        "LIVE_GET_PLAN atom=117 endpoint_class=testnet_public reported_id={} local_derive={} get_url={}",
        ATOM_116_REPORTED_ID,
        hex32(local_official.as_bytes()),
        url.as_str(),
    );

    // ONE read-only live GET. No PUT, no second attempt: a single `get_blob`
    // call, and a transport error fails closed (the `expect` aborts the test)
    // rather than triggering a blind retry.
    let mut aggregator = ReqwestAggregator::new(LIVE_GET_TIMEOUT_MS)
        .expect("aggregator client builds with a positive timeout");
    let response = aggregator
        .get_blob(&plan.request)
        .expect("exactly one live Walrus testnet GET completes (fail-closed; no retry)");

    println!(
        "LIVE_GET_EVIDENCE atom=117 http_status={} body_len={} latency_ms={}",
        response.http_status_u16,
        response.body.len(),
        response.elapsed_ms_u32,
    );

    // Parse + cap the response body (#106). A non-200 status or an over-cap body
    // fails closed here before any over-cap copy.
    let fetched: WalrusGetBody =
        parse_walrus_get_response(response.http_status_u16, &response.body)
            .expect("HTTP 200 within the encoded-chunk cap is a found blob");

    // (2 cont.) 광기 spec: the GET-returned bytes must equal the local fixture
    // byte-for-byte.
    assert_eq!(
        fetched.body(),
        ATOM_116_PAYLOAD,
        "the bytes the aggregator returned must equal the #116 fixture byte-for-byte"
    );

    // (3) Re-derive the official id from the RETURNED bytes and promote them to a
    // VerifiedBlobId — proving the server's bytes hash to the reported id, not
    // merely that the server echoed an id (self-report is never enough).
    let verified_from_get = stage_b_verify_testnet_blob_id(fetched.body(), &reported)
        .expect("the GET-returned bytes derive the reported official id under the oracle");
    assert_eq!(
        verified_from_get.as_blob_id().as_bytes(),
        local_official.as_bytes(),
        "the id verified from the GET-returned bytes equals the local official derive"
    );

    println!(
        "LIVE_GET_VERIFIED atom=117 verified_blob_id={} verified_from_get={} match=true",
        hex32(verified.as_blob_id().as_bytes()),
        hex32(verified_from_get.as_blob_id().as_bytes()),
    );
}
