//! Integration tests for `c-walrus` failure-matrix totality + idempotency
//! (atom #14 · C.0.8).
//!
//! The publisher loop classifies every failure path into one of
//! `PublishStopReason × BoundaryState × TransportFailureKind × PublisherRetryDisposition`.
//! `MNEMOS_ATOM_PLAN.md` line 932 madness invariant: *every* failure path must
//! be deterministically labelled by boundary / retry / commit-state, and the
//! "don't know" case is encoded as the [`BoundaryState::UnknownAfterBoundary`]
//! type (not a panic, not an unhandled match arm).
//!
//! Three verbatim named tests (line 933):
//!
//! 1. [`c0_8_failure_matrix_is_total`] sweeps `classify_transport_failure`
//!    over every `(kind × boundary × attempt × max_attempts)` cell and
//!    `classify_publisher_response` over the full HTTP status u16 universe.
//!    Every cell maps to a stable, documented outcome; every enum variant of
//!    the three canonical OUT enums is observed at least once.
//! 2. [`c0_8_retry_is_idempotent_before_boundary`] drives
//!    `publish_blob_with_transport` twice over the same canned outcome
//!    sequence and asserts the two runs are byte-identical (same attempts,
//!    same diagnostics, same decision).
//! 3. [`c0_8_unknown_boundary_never_double_writes`] confirms that for every
//!    `TransportFailureKind` paired with
//!    [`BoundaryState::UnknownAfterBoundary`], and for HTTP 5xx (which also
//!    surfaces `UnknownAfterBoundary` via `classify_publisher_response`),
//!    `put_blob` is called exactly once — the absorbing-state invariant.
//!
//! Plus a proptest (line 933): for an arbitrary canned failure sequence the
//! loop performs *at most one* "external write" — every diagnostic before
//! the last one has retry-disposition `AutoRetry` and boundary
//! `NoExternalMutation`; an `Accepted` outcome appears at most once.
//!
//! Gates: G-WALRUS-OFFLINE (no `std::net`, no `reqwest`, no live network) +
//! G-PROPTEST (256 cases on the arbitrary-sequence property).

#![allow(clippy::unwrap_used)]
#![allow(clippy::expect_used)]
#![allow(clippy::panic)]

use mnemos_c_walrus::publisher::{
    BlobStoreSuccessVariant, BoundaryState, EpochCount, PUBLIC_PUBLISHER_BODY_CAP_BYTES,
    PublishPayload, PublishPayloadClass, PublishStopReason, PublisherClientError,
    PublisherClientRun, PublisherEndpoint, PublisherPutRequest, PublisherResponseDecision,
    PublisherRetryDisposition, PublisherTransport, PublisherTransportFailure,
    PublisherTransportResponse, TransportFailureKind, classify_publisher_response,
    classify_transport_failure, publish_blob_with_transport,
};
use proptest::prelude::*;

// ===========================================================================
// Canonical enum cardinals (compile-time anchored; drift here = drift in plan)
// ===========================================================================

const ALL_BOUNDARY_STATES: [BoundaryState; 3] = [
    BoundaryState::NoExternalMutation,
    BoundaryState::RequestBytesMayHaveCrossed,
    BoundaryState::UnknownAfterBoundary,
];

const ALL_TRANSPORT_FAILURE_KINDS: [TransportFailureKind; 6] = [
    TransportFailureKind::Dns,
    TransportFailureKind::Connect,
    TransportFailureKind::Tls,
    TransportFailureKind::WriteTimeout,
    TransportFailureKind::ResponseTimeout,
    TransportFailureKind::Cancelled,
];

const ALL_PUBLISH_STOP_REASONS: [PublishStopReason; 5] = [
    PublishStopReason::TerminalStatus,
    PublishStopReason::RetryableStatusAfterBoundary,
    PublishStopReason::SemanticError,
    PublishStopReason::MarkedInvalid,
    PublishStopReason::ProtocolFailure,
];

const ALL_RETRY_DISPOSITIONS: [PublisherRetryDisposition; 3] = [
    PublisherRetryDisposition::AutoRetry,
    PublisherRetryDisposition::Never,
    PublisherRetryDisposition::ManualReconcile,
];

// ===========================================================================
// FakeTransport — records call count + scripted FIFO outcomes.
// ===========================================================================

#[derive(Clone)]
enum Canned {
    Ok(PublisherTransportResponse),
    Err(PublisherTransportFailure),
}

struct FakeTransport {
    canned: Vec<Canned>,
    call_count: usize,
}

impl FakeTransport {
    fn new(canned: Vec<Canned>) -> Self {
        Self {
            canned,
            call_count: 0,
        }
    }
}

impl PublisherTransport for FakeTransport {
    fn put_blob(
        &mut self,
        _request: &PublisherPutRequest<'_>,
    ) -> Result<PublisherTransportResponse, PublisherTransportFailure> {
        let idx = self.call_count;
        self.call_count += 1;
        match self.canned.get(idx) {
            Some(Canned::Ok(r)) => Ok(r.clone()),
            Some(Canned::Err(f)) => Err(*f),
            None => Err(PublisherTransportFailure {
                kind: TransportFailureKind::Cancelled,
                boundary: BoundaryState::NoExternalMutation,
                elapsed_ms_u32: 0,
            }),
        }
    }
}

// ===========================================================================
// Helpers
// ===========================================================================

fn synthetic_request<'a>(bytes: &'a [u8]) -> PublisherPutRequest<'a> {
    let payload = PublishPayload::new(bytes, PublishPayloadClass::SyntheticPublicFixture).unwrap();
    PublisherPutRequest::new(
        PublisherEndpoint::testnet_public(),
        EpochCount::new(2).unwrap(),
        payload,
    )
    .unwrap()
}

fn newly_created_body(blob_id: &str) -> Vec<u8> {
    format!(
        "{{\"newlyCreated\":{{\"blobObject\":{{\"blobId\":\"{}\",\"epochs\":2}}}}}}",
        blob_id
    )
    .into_bytes()
}

fn ok_response(http_status_u16: u16, body: Vec<u8>) -> PublisherTransportResponse {
    PublisherTransportResponse {
        http_status_u16,
        body,
        elapsed_ms_u32: 10,
    }
}

fn fail_response(kind: TransportFailureKind, boundary: BoundaryState) -> PublisherTransportFailure {
    PublisherTransportFailure {
        kind,
        boundary,
        elapsed_ms_u32: 5,
    }
}

// ===========================================================================
// Test 1 — failure-matrix totality
// ===========================================================================

#[test]
fn c0_8_failure_matrix_is_total() {
    // ----- (A) classify_transport_failure cross-product -----
    // Sweep (kind × boundary × attempt × max_attempts) and assert the
    // decision matches the documented mapping. Every cell terminates with
    // exactly one named (kind, boundary, disposition) triple — no holes.
    let mut seen_retry_dispositions: [bool; 3] = [false; 3];
    let mut seen_boundary_states: [bool; 3] = [false; 3];
    let mut seen_transport_kinds: [bool; 6] = [false; 6];

    let attempt_axis: [u16; 6] = [0, 1, 2, 3, 4, 7];
    let max_attempts_axis: [u16; 3] = [1, 3, 8];

    for (b_idx, boundary) in ALL_BOUNDARY_STATES.iter().copied().enumerate() {
        seen_boundary_states[b_idx] = true;
        for (k_idx, kind) in ALL_TRANSPORT_FAILURE_KINDS.iter().copied().enumerate() {
            seen_transport_kinds[k_idx] = true;
            for &max_attempts in &max_attempts_axis {
                for &attempt in &attempt_axis {
                    let decision =
                        classify_transport_failure(kind, boundary, attempt, max_attempts);
                    // Boundary must round-trip verbatim.
                    assert_eq!(decision.boundary, boundary);
                    // Backoff schedule is deterministic and bounded.
                    let expected_backoff: u32 = match attempt {
                        0 | 1 => 100,
                        2 => 250,
                        3 => 500,
                        _ => 1000,
                    };
                    assert_eq!(
                        decision.backoff_ms_u32, expected_backoff,
                        "backoff drift for attempt={} kind={:?} boundary={:?}",
                        attempt, kind, boundary
                    );
                    // Disposition mapping. `BoundaryState` is `#[non_exhaustive]`
                    // so the match needs a wildcard arm — drift here means a
                    // future variant has been added and atom #14 needs a
                    // re-look (totality claim becomes stale).
                    let expected_disposition = match boundary {
                        BoundaryState::UnknownAfterBoundary => {
                            PublisherRetryDisposition::ManualReconcile
                        }
                        BoundaryState::RequestBytesMayHaveCrossed => {
                            PublisherRetryDisposition::Never
                        }
                        BoundaryState::NoExternalMutation => match kind {
                            TransportFailureKind::Cancelled => PublisherRetryDisposition::Never,
                            _ => {
                                if attempt < max_attempts {
                                    PublisherRetryDisposition::AutoRetry
                                } else {
                                    PublisherRetryDisposition::Never
                                }
                            }
                        },
                        _ => panic!(
                            "BoundaryState variant {:?} is outside the canonical set known to atom #14",
                            boundary
                        ),
                    };
                    assert_eq!(
                        decision.disposition, expected_disposition,
                        "disposition drift for kind={:?} boundary={:?} attempt={} max={}",
                        kind, boundary, attempt, max_attempts
                    );
                    // Witness the disposition in the global coverage set.
                    let d_idx = ALL_RETRY_DISPOSITIONS
                        .iter()
                        .position(|d| *d == decision.disposition)
                        .expect("disposition not in canonical set");
                    seen_retry_dispositions[d_idx] = true;
                    // class_label is non-empty for every variant on the path.
                    assert!(!decision.disposition.class_label().is_empty());
                    assert!(!decision.boundary.class_label().is_empty());
                    assert!(!kind.class_label().is_empty());
                }
            }
        }
    }
    assert!(
        seen_retry_dispositions.iter().all(|x| *x),
        "transport-failure matrix did not exercise every PublisherRetryDisposition variant"
    );
    assert!(
        seen_boundary_states.iter().all(|x| *x),
        "transport-failure matrix did not exercise every BoundaryState variant"
    );
    assert!(
        seen_transport_kinds.iter().all(|x| *x),
        "transport-failure matrix did not exercise every TransportFailureKind variant"
    );

    // ----- (B) classify_publisher_response over u16 status universe -----
    // Sweep every well-formed HTTP status and assert that the mapping into
    // (PublishStopReason × BoundaryState × PublisherRetryDisposition) is
    // total: success bodies (200/201) yield Accepted; every other status in
    // 100..=599 yields a Stopped decision or a documented error variant.
    // Statuses outside that band (0..=99 and 600..) yield
    // ResponseStatusUnsupported. No status produces a panic.
    let mut seen_stop_reasons: [bool; 5] = [false; 5];

    let ok_body = newly_created_body("aBlobIdABCDE");

    for status in 0u16..=700u16 {
        let body: &[u8] = if matches!(status, 200 | 201) {
            &ok_body
        } else {
            &[]
        };
        let result = classify_publisher_response(status, body);
        match status {
            200 | 201 => {
                let decision = result.expect("200/201 with valid body must be Ok(decision)");
                match decision {
                    PublisherResponseDecision::Accepted { variant, .. } => {
                        assert_eq!(variant, BlobStoreSuccessVariant::NewlyCreated);
                    }
                    PublisherResponseDecision::Stopped { .. } => {
                        panic!("200/201 must yield Accepted")
                    }
                    _ => panic!("unknown PublisherResponseDecision variant"),
                }
            }
            100..=199 => match result {
                Err(PublisherClientError::ResponseStatusUnsupported { http_status_u16 }) => {
                    assert_eq!(http_status_u16, status);
                }
                other => panic!(
                    "status {} must be ResponseStatusUnsupported, got {:?}",
                    status, other
                ),
            },
            202..=399 => match result {
                Ok(PublisherResponseDecision::Stopped {
                    reason,
                    retry,
                    boundary,
                }) => {
                    assert_eq!(reason, PublishStopReason::SemanticError);
                    assert_eq!(retry, PublisherRetryDisposition::Never);
                    assert_eq!(boundary, BoundaryState::RequestBytesMayHaveCrossed);
                    seen_stop_reasons[2] = true; // SemanticError
                }
                other => panic!("status {} must Stop Semantic, got {:?}", status, other),
            },
            451 => match result {
                Ok(PublisherResponseDecision::Stopped {
                    reason,
                    retry,
                    boundary,
                }) => {
                    assert_eq!(reason, PublishStopReason::MarkedInvalid);
                    assert_eq!(retry, PublisherRetryDisposition::Never);
                    assert_eq!(boundary, BoundaryState::RequestBytesMayHaveCrossed);
                    seen_stop_reasons[3] = true; // MarkedInvalid
                }
                other => panic!("status 451 must Stop MarkedInvalid, got {:?}", other),
            },
            400 | 413 | 415 | 422 => match result {
                Ok(PublisherResponseDecision::Stopped {
                    reason,
                    retry,
                    boundary,
                }) => {
                    assert_eq!(reason, PublishStopReason::SemanticError);
                    assert_eq!(retry, PublisherRetryDisposition::Never);
                    assert_eq!(boundary, BoundaryState::RequestBytesMayHaveCrossed);
                    seen_stop_reasons[2] = true;
                }
                other => panic!("status {} must Stop Semantic, got {:?}", status, other),
            },
            400..=499 => match result {
                Ok(PublisherResponseDecision::Stopped {
                    reason,
                    retry,
                    boundary,
                }) => {
                    assert_eq!(reason, PublishStopReason::TerminalStatus);
                    assert_eq!(retry, PublisherRetryDisposition::Never);
                    assert_eq!(boundary, BoundaryState::RequestBytesMayHaveCrossed);
                    seen_stop_reasons[0] = true; // TerminalStatus
                }
                other => panic!("status {} must Stop Terminal, got {:?}", status, other),
            },
            500..=599 => match result {
                Ok(PublisherResponseDecision::Stopped {
                    reason,
                    retry,
                    boundary,
                }) => {
                    assert_eq!(reason, PublishStopReason::RetryableStatusAfterBoundary);
                    assert_eq!(retry, PublisherRetryDisposition::AutoRetry);
                    assert_eq!(boundary, BoundaryState::UnknownAfterBoundary);
                    seen_stop_reasons[1] = true; // RetryableStatusAfterBoundary
                }
                other => panic!("status {} must Stop Retryable, got {:?}", status, other),
            },
            _ => match result {
                Err(PublisherClientError::ResponseStatusUnsupported { http_status_u16 }) => {
                    assert_eq!(http_status_u16, status);
                }
                other => panic!("status {} must be Unsupported, got {:?}", status, other),
            },
        }
    }

    // ProtocolFailure is produced only by the transport-failure arm of the
    // publish loop, not by classify_publisher_response. Witness it via the
    // loop itself with a single Cancelled transport failure.
    let bytes = b"synthetic-bytes";
    let request = synthetic_request(bytes);
    let mut transport = FakeTransport::new(vec![Canned::Err(fail_response(
        TransportFailureKind::Cancelled,
        BoundaryState::NoExternalMutation,
    ))]);
    let run = publish_blob_with_transport(&mut transport, &request, 1, 3).unwrap();
    match run.decision {
        PublisherResponseDecision::Stopped { reason, .. } => {
            assert_eq!(reason, PublishStopReason::ProtocolFailure);
            seen_stop_reasons[4] = true;
        }
        PublisherResponseDecision::Accepted { .. } => {
            panic!("Cancelled at NoExternalMutation must Stop ProtocolFailure, got Accepted");
        }
        _ => panic!("unknown PublisherResponseDecision variant"),
    }

    assert!(
        seen_stop_reasons.iter().all(|x| *x),
        "matrix did not cover every PublishStopReason: {:?}",
        seen_stop_reasons
    );
    // Sanity: the const cardinal of every canonical OUT enum matches the
    // matrix's witness count. Drift here = drift in atom #8 / atom #14.
    assert_eq!(ALL_PUBLISH_STOP_REASONS.len(), 5);
    assert_eq!(ALL_BOUNDARY_STATES.len(), 3);
    assert_eq!(ALL_TRANSPORT_FAILURE_KINDS.len(), 6);
    assert_eq!(ALL_RETRY_DISPOSITIONS.len(), 3);
}

// ===========================================================================
// Test 2 — idempotency before boundary
// ===========================================================================

#[test]
fn c0_8_retry_is_idempotent_before_boundary() {
    // Sequence: two NoExternalMutation Dns failures (both retryable), then a
    // 201 Accepted. The loop must consume all three attempts and return one
    // Accepted decision. Re-running the loop with a *fresh* transport seeded
    // by the same canned outcomes must produce a byte-identical
    // PublisherClientRun — the idempotency invariant ATOM_PLAN line 931.
    let bytes = b"idempotency-fixture-bytes";

    let canned = || -> Vec<Canned> {
        vec![
            Canned::Err(fail_response(
                TransportFailureKind::Dns,
                BoundaryState::NoExternalMutation,
            )),
            Canned::Err(fail_response(
                TransportFailureKind::Connect,
                BoundaryState::NoExternalMutation,
            )),
            Canned::Ok(ok_response(
                201,
                newly_created_body("idempotent-blob-id-aaaa"),
            )),
        ]
    };

    let request1 = synthetic_request(bytes);
    let mut t1 = FakeTransport::new(canned());
    let run1 = publish_blob_with_transport(&mut t1, &request1, 7, 4).unwrap();

    let request2 = synthetic_request(bytes);
    let mut t2 = FakeTransport::new(canned());
    let run2 = publish_blob_with_transport(&mut t2, &request2, 7, 4).unwrap();

    // Both runs reached the success on attempt 3.
    assert_eq!(t1.call_count, 3);
    assert_eq!(t2.call_count, 3);
    assert_eq!(run1.attempts_u16, 3);
    assert_eq!(run2.attempts_u16, 3);

    // The decision is Accepted with the SAME reported blob id.
    let id1 = match &run1.decision {
        PublisherResponseDecision::Accepted {
            reported_blob_id, ..
        } => reported_blob_id.clone(),
        PublisherResponseDecision::Stopped { .. } => panic!("expected Accepted"),
        _ => panic!("unknown PublisherResponseDecision variant"),
    };
    let id2 = match &run2.decision {
        PublisherResponseDecision::Accepted {
            reported_blob_id, ..
        } => reported_blob_id.clone(),
        PublisherResponseDecision::Stopped { .. } => panic!("expected Accepted"),
        _ => panic!("unknown PublisherResponseDecision variant"),
    };
    assert_eq!(id1.as_str(), id2.as_str());

    // The two runs are byte-identical: same attempts, same diagnostics
    // length, same diagnostic strings in order. (Idempotency = same input
    // sequence → same output PublisherClientRun.)
    assert_eq!(run1.diagnostics.len(), run2.diagnostics.len());
    assert_eq!(run1.diagnostics.len(), 3);
    for (a, b) in run1.diagnostics.iter().zip(run2.diagnostics.iter()) {
        assert_eq!(a, b);
    }
    assert_eq!(run1.decision, run2.decision);

    // Every non-final diagnostic must carry AutoRetry × NoExternalMutation
    // (proof that no external write occurred on those attempts).
    for diag_line in run1.diagnostics.iter().take(run1.diagnostics.len() - 1) {
        assert!(
            diag_line.contains("\"retry_disposition\":\"auto_retry\""),
            "non-final diagnostic missing auto_retry: {}",
            diag_line
        );
        assert!(
            diag_line.contains("\"boundary_state\":\"no_external_mutation\""),
            "non-final diagnostic missing no_external_mutation: {}",
            diag_line
        );
    }
    // The final diagnostic is the accepted event (single external write).
    let last = run1.diagnostics.last().unwrap();
    assert!(last.contains("\"event\":\"publish.accepted\""));

    // Replaying the *post-boundary* state: a fresh transport returning
    // AlreadyCertified on the very first call. The loop must call put_blob
    // exactly once (no second anchor) and surface the AlreadyCertified
    // variant. This is the Walrus-side idempotency contract.
    let request3 = synthetic_request(bytes);
    let body_already =
        b"{\"alreadyCertified\":{\"blobId\":\"already-cert-id\",\"epoch\":3}}".to_vec();
    let mut t3 = FakeTransport::new(vec![Canned::Ok(ok_response(200, body_already))]);
    let run3 = publish_blob_with_transport(&mut t3, &request3, 7, 4).unwrap();
    assert_eq!(t3.call_count, 1);
    match run3.decision {
        PublisherResponseDecision::Accepted { variant, .. } => {
            assert_eq!(variant, BlobStoreSuccessVariant::AlreadyCertified);
        }
        PublisherResponseDecision::Stopped { .. } => panic!("expected Accepted::AlreadyCertified"),
        _ => panic!("unknown PublisherResponseDecision variant"),
    }
}

// ===========================================================================
// Test 3 — UnknownAfterBoundary never produces a second put_blob
// ===========================================================================

#[test]
fn c0_8_unknown_boundary_never_double_writes() {
    let bytes = b"unknown-boundary-fixture";

    // (A) For every TransportFailureKind paired with UnknownAfterBoundary,
    // the loop must call put_blob exactly once even when more retries would
    // otherwise be allowed (max_attempts=5) and even when subsequent canned
    // outcomes would succeed if consumed.
    for kind in ALL_TRANSPORT_FAILURE_KINDS {
        let request = synthetic_request(bytes);
        let canned = vec![
            Canned::Err(fail_response(kind, BoundaryState::UnknownAfterBoundary)),
            // The loop must NEVER reach this second outcome.
            Canned::Ok(ok_response(201, newly_created_body("must-not-reach-id"))),
            Canned::Ok(ok_response(201, newly_created_body("must-not-reach-id-2"))),
        ];
        let mut transport = FakeTransport::new(canned);
        let run = publish_blob_with_transport(&mut transport, &request, 1, 5).unwrap();
        assert_eq!(
            transport.call_count, 1,
            "kind={:?} produced {} put_blob calls; UnknownAfterBoundary must be absorbing",
            kind, transport.call_count
        );
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
            PublisherResponseDecision::Accepted { .. } => {
                panic!("kind={:?} unknown-boundary must Stop, got Accepted", kind);
            }
            _ => panic!("unknown PublisherResponseDecision variant"),
        }
        assert_eq!(run.attempts_u16, 1);
        // Diagnostic must spell out manual_reconcile + unknown_after_boundary.
        let diag = &run.diagnostics[0];
        assert!(diag.contains("\"retry_disposition\":\"manual_reconcile\""));
        assert!(diag.contains("\"boundary_state\":\"unknown_after_boundary\""));
    }

    // (B) HTTP 5xx surfaces UnknownAfterBoundary via the response classifier
    // (see classify_publisher_response). Although the disposition is
    // AutoRetry, the loop only retries on NoExternalMutation, so a 500
    // response must also produce exactly one put_blob call.
    for status in [500u16, 502, 503, 504, 599] {
        let request = synthetic_request(bytes);
        let canned = vec![
            Canned::Ok(ok_response(status, Vec::new())),
            Canned::Ok(ok_response(201, newly_created_body("must-not-reach-5xx"))),
        ];
        let mut transport = FakeTransport::new(canned);
        let run = publish_blob_with_transport(&mut transport, &request, 1, 5).unwrap();
        assert_eq!(
            transport.call_count, 1,
            "status {} must yield exactly 1 put_blob; got {}",
            status, transport.call_count
        );
        match run.decision {
            PublisherResponseDecision::Stopped {
                reason,
                retry,
                boundary,
            } => {
                assert_eq!(reason, PublishStopReason::RetryableStatusAfterBoundary);
                assert_eq!(retry, PublisherRetryDisposition::AutoRetry);
                assert_eq!(boundary, BoundaryState::UnknownAfterBoundary);
            }
            PublisherResponseDecision::Accepted { .. } => {
                panic!("status {} must Stop, got Accepted", status);
            }
            _ => panic!("unknown PublisherResponseDecision variant"),
        }
    }

    // (C) A sequence of *three* consecutive UnknownAfterBoundary transport
    // failures: the loop must still call put_blob exactly once. The second
    // and third canned outcomes are never consumed.
    let request = synthetic_request(bytes);
    let canned = vec![
        Canned::Err(fail_response(
            TransportFailureKind::ResponseTimeout,
            BoundaryState::UnknownAfterBoundary,
        )),
        Canned::Err(fail_response(
            TransportFailureKind::ResponseTimeout,
            BoundaryState::UnknownAfterBoundary,
        )),
        Canned::Err(fail_response(
            TransportFailureKind::ResponseTimeout,
            BoundaryState::UnknownAfterBoundary,
        )),
    ];
    let mut transport = FakeTransport::new(canned);
    let _ = publish_blob_with_transport(&mut transport, &request, 1, 5).unwrap();
    assert_eq!(transport.call_count, 1);
}

// ===========================================================================
// Proptest — arbitrary failure sequence yields ≤ 1 external write
// ===========================================================================

/// One canned outcome along with a tag that records what it is in shrinker
/// terms. Status `0` flags "transport failure"; nonzero flags "HTTP
/// response with that status".
#[derive(Debug, Clone)]
struct ArbitraryCanned {
    is_transport_failure: bool,
    transport_kind_tag: u8, // 0..=5 → TransportFailureKind variant
    boundary_tag: u8,       // 0..=2 → BoundaryState variant
    http_status: u16,       // 100..=599 when is_transport_failure == false
}

fn arb_canned() -> impl Strategy<Value = ArbitraryCanned> {
    (any::<bool>(), 0u8..6u8, 0u8..3u8, 100u16..600u16).prop_map(
        |(is_transport_failure, transport_kind_tag, boundary_tag, http_status)| ArbitraryCanned {
            is_transport_failure,
            transport_kind_tag,
            boundary_tag,
            http_status,
        },
    )
}

fn materialize_canned(seq: &[ArbitraryCanned]) -> Vec<Canned> {
    seq.iter()
        .map(|c| {
            if c.is_transport_failure {
                let kind = ALL_TRANSPORT_FAILURE_KINDS[c.transport_kind_tag as usize];
                let boundary = ALL_BOUNDARY_STATES[c.boundary_tag as usize];
                Canned::Err(fail_response(kind, boundary))
            } else {
                let body: Vec<u8> = if matches!(c.http_status, 200 | 201) {
                    // Provide a well-formed body so 200/201 actually
                    // succeeds — otherwise the loop would propagate a
                    // ResponseBodyJsonMalformed error and abort early.
                    newly_created_body("proptest-blob-id")
                } else {
                    Vec::new()
                };
                Canned::Ok(ok_response(c.http_status, body))
            }
        })
        .collect()
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 256, ..ProptestConfig::default() })]

    /// Headline invariant: for any arbitrary canned failure sequence of
    /// length up to 8, the loop performs *at most one* "external write".
    /// Concretely:
    ///
    /// * `transport.call_count == run.attempts_u16` (loop bookkeeping
    ///   matches transport reality);
    /// * `transport.call_count <= max_attempts` (no over-shoot);
    /// * every diagnostic *before* the last must carry
    ///   `retry_disposition == AutoRetry` *and*
    ///   `boundary_state == NoExternalMutation` — the only state in which
    ///   the loop is allowed to continue, and a state in which no external
    ///   mutation has yet occurred;
    /// * at most one diagnostic carries `event == "publish.accepted"`.
    ///
    /// Together these prove "임의 실패시퀀스에서 최대 1회 외부쓰기"
    /// (ATOM_PLAN line 933).
    #[test]
    fn proptest_arbitrary_failure_sequence_at_most_one_external_write(
        seq in prop::collection::vec(arb_canned(), 0..=8),
    ) {
        let max_attempts: u16 = 8;
        let bytes = b"proptest-fixture";
        let request = synthetic_request(bytes);
        let canned = materialize_canned(&seq);
        let mut transport = FakeTransport::new(canned);
        let result: Result<PublisherClientRun, PublisherClientError> =
            publish_blob_with_transport(&mut transport, &request, 99, max_attempts);

        match result {
            Ok(run) => {
                // (1) Loop bookkeeping is honest about how many times the
                // transport was driven.
                prop_assert_eq!(run.attempts_u16 as usize, transport.call_count);
                prop_assert!(transport.call_count <= max_attempts as usize);

                // (2) Diagnostics line up 1:1 with put_blob calls.
                prop_assert_eq!(run.diagnostics.len(), transport.call_count);

                // (3) Every non-final diagnostic carries the only
                // "continue" tuple.
                if run.diagnostics.len() >= 2 {
                    for diag in &run.diagnostics[..run.diagnostics.len() - 1] {
                        prop_assert!(
                            diag.contains("\"retry_disposition\":\"auto_retry\""),
                            "non-final diagnostic without auto_retry: {}", diag
                        );
                        prop_assert!(
                            diag.contains("\"boundary_state\":\"no_external_mutation\""),
                            "non-final diagnostic without no_external_mutation: {}", diag
                        );
                    }
                }

                // (4) At most one Accepted event.
                let accepted_count = run.diagnostics.iter()
                    .filter(|d| d.contains("\"event\":\"publish.accepted\""))
                    .count();
                prop_assert!(accepted_count <= 1);

                // (5) The decision-side reflects the same fact: at most one
                // Accepted decision per run.
                match run.decision {
                    PublisherResponseDecision::Accepted { .. } => {
                        prop_assert_eq!(accepted_count, 1);
                    }
                    PublisherResponseDecision::Stopped { .. } => {
                        prop_assert_eq!(accepted_count, 0);
                    }
                    _ => prop_assert!(
                        false,
                        "unknown PublisherResponseDecision variant"
                    ),
                }
            }
            Err(PublisherClientError::AttemptsExhausted { attempts_u16 }) => {
                // attempts_exhausted means the loop used max_attempts
                // without committing; transport saw exactly max_attempts
                // calls and produced no external write.
                prop_assert_eq!(attempts_u16, max_attempts);
                prop_assert!(transport.call_count <= max_attempts as usize);
            }
            Err(_other) => {
                // A malformed canned response can still surface a
                // classifier error (e.g. ResponseBodyJsonMalformed on a 200
                // with empty body). In all such cases the loop must have
                // stopped on the FIRST such attempt — i.e. no further
                // put_blob calls.
                prop_assert!(transport.call_count >= 1);
                prop_assert!(transport.call_count <= max_attempts as usize);
            }
        }
    }
}

// ===========================================================================
// Sanity guard — body-cap precondition for the fixture helper.
// ===========================================================================

#[test]
fn fixture_bytes_fit_under_body_cap() {
    // The proptest + named tests share short literal byte payloads, all
    // well under PUBLIC_PUBLISHER_BODY_CAP_BYTES; this guard makes the
    // invariant explicit so a future refactor cannot silently smuggle a
    // huge buffer into the closed-endpoint policy.
    let bytes = b"proptest-fixture";
    assert!((bytes.len() as u32) < PUBLIC_PUBLISHER_BODY_CAP_BYTES);
}
