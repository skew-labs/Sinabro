//! Integration tests for the Stage B Walrus client — offline **mock transport
//! matrix** (atom #115 · B.2.14).
//!
//! # What this atom is
//!
//! The canonical OUT is a *fake PUT/GET transport covering success / failure /
//! retry*: two in-test transport doubles ([`MockPublisherTransport`] /
//! [`MockAggregatorTransport`]) implement the Stage A `c-walrus`
//! [`PublisherTransport`] / [`AggregatorTransport`] traits and return canned
//! outcomes in FIFO order. The tests drive the real Stage A retry/boundary loops
//! ([`publish_blob_with_transport`] / [`fetch_blob_with_transport`]) through
//! those doubles, then wrap the loop outputs through the Stage B `b-memory`
//! seam (#104 PUT-response parse, #106 GET-response parse, #108 reported-id
//! verify, #109 round-trip receipt, #110 boundary/retry, #111 PUT idempotency
//! ledger). The madness invariant — *all logic except live bytes is testable
//! offline* — is what makes a memory owner's Walrus path trustworthy before a
//! single live testnet byte is ever sent.
//!
//! # Why the loop is driven, not re-implemented (OD-1 = R1, user-locked 2026-05-30)
//!
//! The §4.2 design names `stage_b_put_with_transport` / `stage_b_get_with_transport`
//! as the transport-driving entry points, but the implemented `b-memory` surface
//! decomposed them into plan-builders (`WalrusPutPlan::plan`, `WalrusGetPlan::plan`)
//! plus response-parsers; the actual retry/boundary loop lives in `c-walrus`
//! (`publish_blob_with_transport` @ publisher.rs, `fetch_blob_with_transport` @
//! aggregator.rs). So *covering retry* means driving the real `c-walrus` loop
//! with a fake transport — retry/boundary come from production code, never from
//! a test-authored fake — and asserting that the `b-memory` wrappers consume the
//! loop outputs. `mnemos-c-walrus` is a normal (non-dev) dependency of
//! `mnemos-b-memory` (`b-memory -> c-walrus`, no cycle), so this test may use
//! both crates' surfaces.
//!
//! # Offline posture (`G-B-WALRUS-OFFLINE` + `G-B-PROPTEST`)
//!
//! No `std::net`, no `reqwest`, no live egress: every byte is supplied by the
//! mock transports. The `net-testnet` feature is **not** required — the loop
//! functions and every `b-memory` wrapper used here are in the default,
//! non-feature-gated surface.

#![allow(clippy::unwrap_used)]
#![allow(clippy::expect_used)]
#![allow(clippy::panic)]

use std::collections::VecDeque;

use mnemos_b_memory::{
    ContentHash32, StageBTraceEvidence, StageBTraceLink, StorageObjectRef, WalrusBoundaryState,
    WalrusClientError, WalrusGetPlan, WalrusPutDecision, WalrusPutLedger, WalrusPutPlan,
    WalrusRetry, WalrusRoundTripReceipt, WalrusTestnetEndpoint, derive_walrus_blob_id,
    parse_walrus_get_response, parse_walrus_put_response, stage_b_verify_blob_id,
};
use mnemos_c_walrus::aggregator::{
    AggregatorEndpoint, AggregatorGetRequest, AggregatorResponseDecision, AggregatorTransport,
    FetchStopReason, fetch_blob_with_transport,
};
use mnemos_c_walrus::publisher::{
    BoundaryState, EpochCount, PublishPayloadClass, PublishStopReason, PublisherPutRequest,
    PublisherResponseDecision, PublisherRetryDisposition, PublisherTransport,
    PublisherTransportFailure, PublisherTransportResponse, TransportFailureKind,
    publish_blob_with_transport,
};
use mnemos_c_walrus::{BlobId, PublisherReportedBlobId};

use proptest::prelude::*;

// ===========================================================================
// Mock transports — record every call, return canned outcomes in FIFO order.
//
// Both the publisher and aggregator transport traits return the SAME
// `Result<PublisherTransportResponse, PublisherTransportFailure>` (the c-walrus
// atom #8/#9 design), so a single `Canned` outcome type serves both doubles.
// This mirrors the established `c-walrus/tests/{publisher,aggregator}.rs`
// `FakeTransport` / `FakeAggregatorTransport` convention.
// ===========================================================================

enum Canned {
    Ok(PublisherTransportResponse),
    Err(PublisherTransportFailure),
}

/// Fake PUT transport: drives `publish_blob_with_transport` with canned
/// per-attempt outcomes and records how many `put_blob` calls the loop made.
struct MockPublisherTransport {
    canned: Vec<Canned>,
    call_count: usize,
}

impl MockPublisherTransport {
    fn new(canned: Vec<Canned>) -> Self {
        Self {
            canned,
            call_count: 0,
        }
    }
}

impl PublisherTransport for MockPublisherTransport {
    fn put_blob(
        &mut self,
        _request: &PublisherPutRequest<'_>,
    ) -> Result<PublisherTransportResponse, PublisherTransportFailure> {
        let idx = self.call_count;
        self.call_count += 1;
        match self.canned.get(idx) {
            Some(Canned::Ok(r)) => Ok(r.clone()),
            Some(Canned::Err(f)) => Err(*f),
            // Running out of programmed outcomes is a test bug, not a transport
            // event; surface it loudly rather than silently cancelling.
            None => panic!("MockPublisherTransport ran out of programmed outcomes"),
        }
    }
}

/// Fake GET transport: drives `fetch_blob_with_transport` with canned
/// per-attempt outcomes and records how many `get_blob` calls the loop made.
struct MockAggregatorTransport {
    outcomes: VecDeque<Canned>,
    invocations: u32,
}

impl MockAggregatorTransport {
    fn new(outcomes: Vec<Canned>) -> Self {
        Self {
            outcomes: outcomes.into_iter().collect(),
            invocations: 0,
        }
    }

    fn invocation_count(&self) -> u32 {
        self.invocations
    }

    fn remaining(&self) -> usize {
        self.outcomes.len()
    }
}

impl AggregatorTransport for MockAggregatorTransport {
    fn get_blob(
        &mut self,
        _request: &AggregatorGetRequest<'_>,
    ) -> Result<PublisherTransportResponse, PublisherTransportFailure> {
        self.invocations = self.invocations.saturating_add(1);
        match self.outcomes.pop_front() {
            Some(Canned::Ok(r)) => Ok(r),
            Some(Canned::Err(f)) => Err(f),
            None => panic!("MockAggregatorTransport ran out of programmed outcomes"),
        }
    }
}

// ===========================================================================
// Helpers
// ===========================================================================

/// A canned successful HTTP response (status + body), shared by both doubles.
fn ok_resp(http_status_u16: u16, body: Vec<u8>) -> Canned {
    Canned::Ok(PublisherTransportResponse {
        http_status_u16,
        body,
        elapsed_ms_u32: 17,
    })
}

/// A canned transport-level failure with an explicit observed boundary.
fn err_resp(kind: TransportFailureKind, boundary: BoundaryState) -> Canned {
    Canned::Err(PublisherTransportFailure {
        kind,
        boundary,
        elapsed_ms_u32: 4,
    })
}

/// A Walrus publisher `newlyCreated` success body carrying `blob_id` as text.
/// Reproduced from the `c-walrus` publisher test helper (the publisher response
/// JSON shape that `classify_publisher_response` / `parse_walrus_put_response`
/// both parse).
fn newly_created_body(blob_id: &str) -> Vec<u8> {
    format!("{{\"newlyCreated\":{{\"blobObject\":{{\"blobId\":\"{blob_id}\",\"epochs\":2}}}}}}")
        .into_bytes()
}

/// Test-only URL-safe base64 (no padding) encoder for a 32-byte id — the
/// faithful inverse of `c-walrus`'s private `decode_base64url_no_pad_32`. The
/// real encoder is `pub(crate)`, so a cross-crate test cannot call it; this is
/// the test-only duplicate established by the #108/#109 tests, reproduced here to
/// synthesize a *correctly* reported id text so the only `VerifiedBlobId`
/// constructor (#108 `stage_b_verify_blob_id`) can be driven.
fn base64url_no_pad_encode_32(raw: &[u8; 32]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut out = String::with_capacity(43);
    let mut buf: u32 = 0;
    let mut bits: u32 = 0;
    for &b in raw {
        buf = (buf << 8) | (b as u32);
        bits += 8;
        while bits >= 6 {
            bits -= 6;
            out.push(ALPHABET[((buf >> bits) & 0x3f) as usize] as char);
        }
    }
    if bits > 0 {
        out.push(ALPHABET[((buf << (6 - bits)) & 0x3f) as usize] as char);
    }
    out
}

/// The publisher-reported id text a *correct* publisher would return for `id`.
fn reported_for(id: &BlobId) -> PublisherReportedBlobId {
    let text = base64url_no_pad_encode_32(id.as_bytes());
    PublisherReportedBlobId::try_from_text(&text).unwrap()
}

/// A stamped trace evidence (atom #94) for atom #115; `atom_id_u16 = 115 != 0`
/// so `from_trace` admits it (never the missing-trace sentinel).
fn trace_evidence(trace_id_u64: u64, attempt_u8: u8) -> StageBTraceEvidence {
    StageBTraceEvidence::from_trace(StageBTraceLink::new(trace_id_u64, 115, attempt_u8))
        .expect("atom_id 115 is non-zero so the trace is stamped")
}

// ===========================================================================
// Test 1 — success roundtrip
//
// PUT loop accepts on the first attempt; the reported id verifies against the
// local derive (#108); a GET loop fetches the same bytes back; the #104/#106
// parsers agree with the loop on the same raw bodies; a #109 round-trip receipt
// is minted carrying only the body LENGTH.
// ===========================================================================

#[test]
fn b2_14_success_roundtrip() {
    let payload = b"mnemos atom 115 synthetic public fixture round trip";
    let ev = trace_evidence(0xB214_0001, 0);

    // Local derive — the id is a pure function of the bytes the owner holds.
    let derived: BlobId = derive_walrus_blob_id(payload);
    let reported_text = base64url_no_pad_encode_32(derived.as_bytes());
    let success_body = newly_created_body(&reported_text);

    // #103 PUT plan: content-class policy + body cap + stamped trace, BEFORE any
    // transport type is built.
    let put_plan: WalrusPutPlan<'_> = WalrusPutPlan::plan(
        WalrusTestnetEndpoint::testnet(),
        EpochCount::new(2).unwrap(),
        payload,
        PublishPayloadClass::SyntheticPublicFixture,
        ev,
    )
    .expect("synthetic public fixture within cap plans");

    // Drive the real c-walrus PUT loop with one canned 200 success.
    let mut put_transport = MockPublisherTransport::new(vec![ok_resp(200, success_body.clone())]);
    let run = publish_blob_with_transport(&mut put_transport, &put_plan.request, 0xB214_0001, 5)
        .expect("a 200 success drives the loop to Accepted");
    assert_eq!(put_transport.call_count, 1, "success needs exactly one PUT");
    assert_eq!(run.attempts_u16, 1);
    let reported = match run.decision {
        PublisherResponseDecision::Accepted {
            reported_blob_id, ..
        } => reported_blob_id,
        other => panic!("expected Accepted, got {other:?}"),
    };
    assert_eq!(reported.as_str(), reported_text.as_str());

    // #104: the b-memory PUT-response parser agrees with the loop on the raw
    // body — same reported token, undecoded and untrusted.
    let parsed = parse_walrus_put_response(&success_body).expect("success body parses");
    assert_eq!(parsed.as_str(), Some(reported_text.as_str()));

    // #108: verify the reported id against the LOCAL derive — the only path that
    // can mint a VerifiedBlobId; it wraps the locally derived id, not the
    // reported bytes (server is not an oracle).
    let verified = stage_b_verify_blob_id(payload, &reported)
        .expect("a reported id equal to the local derive verifies");
    assert_eq!(verified.as_blob_id().as_bytes(), derived.as_bytes());

    // #105 GET plan over the VerifiedBlobId, then drive the real GET loop.
    let get_plan: WalrusGetPlan<'_> =
        WalrusGetPlan::plan(AggregatorEndpoint::testnet_public(), &verified, ev);
    let mut get_transport = MockAggregatorTransport::new(vec![ok_resp(200, payload.to_vec())]);
    let decision = fetch_blob_with_transport(&mut get_transport, &get_plan.request, 0xB214_0002, 4)
        .expect("a 200 body drives the loop to Fetched");
    let fetched = match decision {
        AggregatorResponseDecision::Fetched { body, .. } => body,
        other => panic!("expected Fetched, got {other:?}"),
    };
    assert_eq!(
        fetched.as_slice(),
        payload,
        "round-trip returns the same bytes"
    );
    assert_eq!(get_transport.invocation_count(), 1);

    // #106: the b-memory GET-response parser agrees on the same raw body.
    let get_body = parse_walrus_get_response(200, &fetched).expect("200 body parses");
    assert_eq!(get_body.body(), payload);
    assert_eq!(get_body.content_length() as usize, payload.len());

    // #109: round-trip receipt — records only the body LENGTH, never the bytes.
    let trace_link = StageBTraceLink::new(0xB214_0001, 115, 0);
    let storage = StorageObjectRef::walrus_primary(*derived.as_bytes(), verified);
    let receipt =
        WalrusRoundTripReceipt::from_round_trip(verified, storage, 12, 7, &fetched, trace_link)
            .expect("payload length is within u32");
    assert_eq!(receipt.bytes_u32() as usize, payload.len());
    assert_eq!(receipt.blob().as_blob_id().as_bytes(), derived.as_bytes());
    assert_eq!(receipt.total_ms_u64(), 19);
}

// ===========================================================================
// Test 2 — write timeout before boundary
//
// The first PUT attempt fails with a write timeout observed BEFORE the external
// boundary (NoExternalMutation); the loop retries (bytes never left) and the
// second attempt succeeds. The #110 boundary/retry types and the #111 ledger
// agree: a before-boundary outcome permits an automatic retry.
// ===========================================================================

#[test]
fn b2_14_write_timeout_before_boundary() {
    let payload = b"mnemos atom 115 write timeout before boundary";
    let ev = trace_evidence(0xB214_0021, 0);

    let derived = derive_walrus_blob_id(payload);
    let success_body = newly_created_body(&base64url_no_pad_encode_32(derived.as_bytes()));

    let put_plan = WalrusPutPlan::plan(
        WalrusTestnetEndpoint::testnet(),
        EpochCount::new(2).unwrap(),
        payload,
        PublishPayloadClass::SyntheticPublicFixture,
        ev,
    )
    .expect("plans");

    // WriteTimeout @ NoExternalMutation, then a 200 success → loop retries once.
    let mut put_transport = MockPublisherTransport::new(vec![
        err_resp(
            TransportFailureKind::WriteTimeout,
            BoundaryState::NoExternalMutation,
        ),
        ok_resp(200, success_body),
    ]);
    let run = publish_blob_with_transport(&mut put_transport, &put_plan.request, 0xB214_0021, 5)
        .expect("a before-boundary failure is retry-safe and then succeeds");
    assert_eq!(
        put_transport.call_count, 2,
        "the loop retries after a NoExternalMutation failure"
    );
    assert_eq!(run.attempts_u16, 2);
    assert!(
        matches!(run.decision, PublisherResponseDecision::Accepted { .. }),
        "the retry succeeds, got {:?}",
        run.decision
    );

    // #110: the observed boundary maps to an auto-retryable decision.
    let boundary = WalrusBoundaryState::NoExternalMutation;
    assert!(!boundary.requires_manual_reconcile());
    assert_eq!(boundary.retry(), WalrusRetry::BeforeBoundaryOnly);
    assert!(boundary.retry().allows_automatic_retry());

    // #111: the ledger records the before-boundary attempt and still permits an
    // automatic PUT for the same trace + digest.
    let digest = ContentHash32::of(payload);
    let mut ledger = WalrusPutLedger::new();
    assert_eq!(ledger.decide(&digest, &ev), WalrusPutDecision::FirstAttempt);
    ledger.record_attempt(&digest, &ev, boundary);
    let decision = ledger.decide(&digest, &ev);
    assert_eq!(
        decision,
        WalrusPutDecision::Retry(WalrusRetry::BeforeBoundaryOnly)
    );
    assert!(
        decision.allows_automatic_put(),
        "a before-boundary outcome permits an automatic retry"
    );
}

// ===========================================================================
// Test 3 — timeout unknown (no blind second PUT)
//
// The PUT attempt fails with a response timeout observed AFTER the bytes were on
// the wire (UnknownAfterBoundary); the loop must STOP after exactly one call —
// no blind second PUT. The #110 boundary/retry types and the #111 ledger agree:
// an unknown-after-boundary outcome forbids an automatic PUT.
// ===========================================================================

#[test]
fn b2_14_timeout_unknown() {
    let payload = b"mnemos atom 115 timeout unknown after boundary";
    let ev = trace_evidence(0xB214_0031, 0);

    let put_plan = WalrusPutPlan::plan(
        WalrusTestnetEndpoint::testnet(),
        EpochCount::new(2).unwrap(),
        payload,
        PublishPayloadClass::SyntheticPublicFixture,
        ev,
    )
    .expect("plans");

    // ResponseTimeout @ UnknownAfterBoundary, plus a sentinel success that MUST
    // NOT be consumed — a second PUT would be a duplicate anchor.
    let mut put_transport = MockPublisherTransport::new(vec![
        err_resp(
            TransportFailureKind::ResponseTimeout,
            BoundaryState::UnknownAfterBoundary,
        ),
        ok_resp(200, newly_created_body("SENTINEL-must-not-be-used")),
    ]);
    let run = publish_blob_with_transport(&mut put_transport, &put_plan.request, 0xB214_0031, 5)
        .expect("the loop stops cleanly without a second PUT");
    assert_eq!(
        put_transport.call_count, 1,
        "an unknown boundary absorbs the retry — exactly one PUT"
    );
    assert_eq!(run.attempts_u16, 1);
    match run.decision {
        PublisherResponseDecision::Stopped {
            reason,
            retry,
            boundary,
        } => {
            assert_eq!(reason, PublishStopReason::ProtocolFailure);
            assert_eq!(retry, PublisherRetryDisposition::ManualReconcile);
            assert_eq!(boundary, BoundaryState::UnknownAfterBoundary);
        }
        other => panic!("expected Stopped(UnknownAfterBoundary), got {other:?}"),
    }

    // #110: the observed boundary forbids an automatic retry.
    let boundary = WalrusBoundaryState::UnknownAfterBoundary;
    assert!(boundary.requires_manual_reconcile());
    assert_eq!(boundary.retry(), WalrusRetry::ManualReconcile);
    assert!(boundary.retry().requires_manual_reconcile());
    assert!(!boundary.retry().allows_automatic_retry());

    // #111: the ledger records the unknown-boundary attempt and refuses an
    // automatic second PUT for the same trace + digest (the safety invariant).
    let digest = ContentHash32::of(payload);
    let mut ledger = WalrusPutLedger::new();
    ledger.record_attempt(&digest, &ev, boundary);
    let decision = ledger.decide(&digest, &ev);
    assert_eq!(
        decision,
        WalrusPutDecision::Retry(WalrusRetry::ManualReconcile)
    );
    assert!(
        !decision.allows_automatic_put(),
        "an unknown-after-boundary outcome forbids a blind second PUT"
    );
}

// ===========================================================================
// Test 4 — get not found
//
// The GET loop returns HTTP 404; the loop stops immediately (Never ×
// NoExternalMutation) without consuming the sentinel. The #106 parser collapses
// a 404 to the frozen-7 `Protocol` tag (no `NotFound` variant), and no receipt
// is minted (a missing blob produces no round trip).
// ===========================================================================

#[test]
fn b2_14_get_not_found() {
    // A VerifiedBlobId is required to plan a GET — built via the only sanctioned
    // path (#108) from bytes we hold locally; the aggregator then 404s on it.
    let absent = b"mnemos atom 115 blob that the aggregator does not have";
    let derived = derive_walrus_blob_id(absent);
    let verified = stage_b_verify_blob_id(absent, &reported_for(&derived))
        .expect("local derive verifies its own reported id");
    let ev = trace_evidence(0xB214_0041, 0);

    let get_plan = WalrusGetPlan::plan(AggregatorEndpoint::testnet_public(), &verified, ev);

    // 404, plus a sentinel 200 that MUST NOT be consumed (404 is terminal).
    let mut get_transport =
        MockAggregatorTransport::new(vec![ok_resp(404, Vec::new()), ok_resp(200, vec![0xFF])]);
    let decision = fetch_blob_with_transport(&mut get_transport, &get_plan.request, 0xB214_0041, 4)
        .expect("a 404 drives the loop to a clean Stopped");
    match decision {
        AggregatorResponseDecision::Stopped {
            reason,
            retry,
            boundary,
        } => {
            assert_eq!(reason, FetchStopReason::NotFound);
            assert_eq!(retry, PublisherRetryDisposition::Never);
            assert_eq!(boundary, BoundaryState::NoExternalMutation);
        }
        other => panic!("expected Stopped(NotFound), got {other:?}"),
    }
    assert_eq!(
        get_transport.invocation_count(),
        1,
        "404 is terminal — one GET"
    );
    assert_eq!(get_transport.remaining(), 1, "the sentinel is untouched");

    // #106: a 404 collapses to the content-free frozen-7 `Protocol` tag — there
    // is no `NotFound` variant, and a GET only ever targets a locally-verified
    // id, so a miss is a protocol/availability anomaly, not a benign absence.
    assert_eq!(
        parse_walrus_get_response(404, &[]),
        Err(WalrusClientError::Protocol)
    );
}

// ===========================================================================
// Proptest (G-B-PROPTEST) — the two cross-cutting invariants over random input.
// ===========================================================================

proptest! {
    #![proptest_config(ProptestConfig { cases: 256, ..Default::default() })]

    /// For ANY synthetic bytes the owner holds:
    ///
    /// (a) **server is not an oracle** — a correctly-reported id verifies to a
    ///     `VerifiedBlobId` wrapping the LOCAL derive byte-for-byte; and
    ///
    /// (b) **never a blind second PUT** — once an attempt is recorded, the #111
    ///     ledger permits an automatic PUT iff the observed #110 boundary did not
    ///     cross (NoExternalMutation), and forbids it otherwise
    ///     (BytesMayHaveCrossed / UnknownAfterBoundary).
    #[test]
    fn b2_14_proptest_roundtrip_verify_and_no_blind_second_put(
        bytes in proptest::collection::vec(any::<u8>(), 0..512usize),
        boundary_tag in 1u8..=3u8,
    ) {
        // (a) server-not-oracle round trip holds for every input slice.
        let derived = derive_walrus_blob_id(&bytes);
        let reported = reported_for(&derived);
        let verified = stage_b_verify_blob_id(&bytes, &reported)
            .expect("a correctly-reported id always verifies");
        prop_assert_eq!(verified.as_blob_id().as_bytes(), derived.as_bytes());

        // (b) the ledger decision tracks the observed boundary exactly.
        let boundary = match boundary_tag {
            1 => WalrusBoundaryState::NoExternalMutation,
            2 => WalrusBoundaryState::BytesMayHaveCrossed,
            _ => WalrusBoundaryState::UnknownAfterBoundary,
        };
        let digest = ContentHash32::of(&bytes);
        let ev = trace_evidence(u64::from(boundary_tag) + 1, 0);
        let mut ledger = WalrusPutLedger::new();
        ledger.record_attempt(&digest, &ev, boundary);
        let decision = ledger.decide(&digest, &ev);
        prop_assert_eq!(decision.allows_automatic_put(), !boundary.requires_manual_reconcile());
    }
}
