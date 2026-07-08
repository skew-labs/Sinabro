//! Integration tests for `c-walrus::publisher` (atom #8 · C.0.2).
//!
//! Nine `c0_2_*` tests verbatim from `MNEMOS_ATOM_PLAN.md` line 873. The
//! transport is faked end-to-end; no `std::net`, no `reqwest`, no live
//! network egress (gate `G-WALRUS-OFFLINE`).

#![allow(clippy::unwrap_used)]
#![allow(clippy::expect_used)]
#![allow(clippy::panic)]

use mnemos_c_walrus::publisher::{
    BlobStoreSuccessVariant, BoundaryState, EpochCount, MAX_PUBLISHER_RESPONSE_BYTES,
    MAX_REPORTED_BLOB_ID_TEXT_BYTES, PUBLIC_PUBLISHER_BODY_CAP_BYTES, PublishPayload,
    PublishPayloadClass, PublishStopReason, PublisherClientError, PublisherClientRun,
    PublisherDiagnostic, PublisherEndpoint, PublisherPutRequest, PublisherReportedBlobId,
    PublisherResponseDecision, PublisherRetryDisposition, PublisherTransport,
    PublisherTransportFailure, PublisherTransportResponse, TESTNET_PUBLISHER_BASE_URL,
    TransportFailureKind, WALRUS_PUT_BLOB_PATH, classify_publisher_response,
    classify_transport_failure, publish_blob_with_transport, validate_publisher_put_url,
};

// ===========================================================================
// Fake transport — records every call, returns canned outcomes in FIFO order.
// ===========================================================================

enum Canned {
    Ok(PublisherTransportResponse),
    Err(PublisherTransportFailure),
}

struct FakeTransport {
    canned: Vec<Canned>,
    call_count: usize,
    observed_body_ptr: Option<*const u8>,
    observed_body_len: Option<usize>,
}

impl FakeTransport {
    fn new(canned: Vec<Canned>) -> Self {
        Self {
            canned,
            call_count: 0,
            observed_body_ptr: None,
            observed_body_len: None,
        }
    }
}

impl PublisherTransport for FakeTransport {
    fn put_blob(
        &mut self,
        request: &PublisherPutRequest<'_>,
    ) -> Result<PublisherTransportResponse, PublisherTransportFailure> {
        self.call_count += 1;
        let body = request.body();
        self.observed_body_ptr = Some(body.as_ptr());
        self.observed_body_len = Some(body.len());
        let idx = self.call_count - 1;
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

fn ok_synthetic_request<'a>(bytes: &'a [u8]) -> PublisherPutRequest<'a> {
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

fn already_certified_body(blob_id: &str) -> Vec<u8> {
    format!(
        "{{\"alreadyCertified\":{{\"blobId\":\"{}\",\"epoch\":3}}}}",
        blob_id
    )
    .into_bytes()
}

// ===========================================================================
// Test 1
// ===========================================================================

#[test]
fn c0_2_policy_rejects_non_synthetic_payloads_before_request_plan() {
    let endpoint = PublisherEndpoint::testnet_public();
    let epochs = EpochCount::new(1).unwrap();
    let body = b"any-bytes";
    let rejected_classes = [
        PublishPayloadClass::RealUserMemory,
        PublishPayloadClass::PromptOrProviderText,
        PublishPayloadClass::ToolOutput,
        PublishPayloadClass::SecretLike,
        PublishPayloadClass::PrivateProvenance,
    ];
    for class in rejected_classes {
        let payload = PublishPayload::new(body, class).unwrap();
        let err = PublisherPutRequest::new(endpoint, epochs, payload).unwrap_err();
        match err {
            PublisherClientError::PayloadClassRejected { class: rejected } => {
                assert_eq!(rejected, class);
            }
            other => panic!("expected PayloadClassRejected, got {:?}", other),
        }
    }
    // Synthetic accepted.
    let synthetic = PublishPayload::new(body, PublishPayloadClass::SyntheticPublicFixture).unwrap();
    let ok = PublisherPutRequest::new(endpoint, epochs, synthetic);
    assert!(ok.is_ok());

    // Transport must never be reached for rejected classes. We construct a
    // fake transport, never plumb it, and confirm `call_count == 0`.
    let transport = FakeTransport::new(Vec::new());
    let payload = PublishPayload::new(body, PublishPayloadClass::RealUserMemory).unwrap();
    let req_attempt = PublisherPutRequest::new(endpoint, epochs, payload);
    assert!(req_attempt.is_err());
    assert_eq!(transport.call_count, 0);
}

// ===========================================================================
// Test 2
// ===========================================================================

#[test]
fn c0_2_request_plan_is_closed_and_borrows_body() {
    let bytes: Vec<u8> = (0u8..=255u8).collect();
    let request = ok_synthetic_request(&bytes);
    // Endpoint is closed: only the single sanctioned constructor exists.
    assert_eq!(request.endpoint().base_url(), TESTNET_PUBLISHER_BASE_URL);
    assert_eq!(request.endpoint().put_path(), WALRUS_PUT_BLOB_PATH);
    assert_eq!(request.epochs().get(), 2);
    assert_eq!(
        request.payload().class(),
        PublishPayloadClass::SyntheticPublicFixture
    );
    // Borrow semantics: the same pointer + length as the caller's slice.
    assert_eq!(request.body().as_ptr(), bytes.as_ptr());
    assert_eq!(request.body().len(), bytes.len());
    assert_eq!(request.payload().bytes().as_ptr(), bytes.as_ptr());
    // u32 width is honest (256 ≤ u32::MAX).
    assert_eq!(request.payload().len_u32() as usize, bytes.len());

    // Body cap is enforced at PublishPayload::new before any request is built.
    let too_big = vec![0u8; PUBLIC_PUBLISHER_BODY_CAP_BYTES as usize + 1];
    let err =
        PublishPayload::new(&too_big, PublishPayloadClass::SyntheticPublicFixture).unwrap_err();
    match err {
        PublisherClientError::PayloadTooLarge {
            observed_u32: _,
            cap_u32,
        } => assert_eq!(cap_u32, PUBLIC_PUBLISHER_BODY_CAP_BYTES),
        other => panic!("expected PayloadTooLarge, got {:?}", other),
    }
}

// ===========================================================================
// Test 3
// ===========================================================================

#[test]
fn c0_2_endpoint_query_policy_rejects_everything_but_epochs() {
    // Accept: canonical shape with valid u16 epochs.
    let ok = validate_publisher_put_url(
        "https://publisher.walrus-testnet.walrus.space/v1/blobs?epochs=2",
    )
    .unwrap();
    assert_eq!(ok.epochs().get(), 2);
    let ok_high = validate_publisher_put_url(
        "https://publisher.walrus-testnet.walrus.space/v1/blobs?epochs=65535",
    )
    .unwrap();
    assert_eq!(ok_high.epochs().get(), 65535);

    // Reject: wrong scheme.
    assert!(matches!(
        validate_publisher_put_url(
            "http://publisher.walrus-testnet.walrus.space/v1/blobs?epochs=2"
        ),
        Err(PublisherClientError::EndpointSchemeForbidden)
    ));
    // Reject: wrong host.
    assert!(matches!(
        validate_publisher_put_url("https://attacker.example.com/v1/blobs?epochs=2"),
        Err(PublisherClientError::EndpointHostForbidden)
    ));
    // Reject: explicit port.
    assert!(matches!(
        validate_publisher_put_url(
            "https://publisher.walrus-testnet.walrus.space:443/v1/blobs?epochs=2"
        ),
        Err(PublisherClientError::EndpointPortForbidden)
    ));
    // Reject: userinfo.
    assert!(matches!(
        validate_publisher_put_url(
            "https://user:pass@publisher.walrus-testnet.walrus.space/v1/blobs?epochs=2"
        ),
        Err(PublisherClientError::EndpointForbiddenUserinfo)
    ));
    // Reject: wrong path.
    assert!(matches!(
        validate_publisher_put_url(
            "https://publisher.walrus-testnet.walrus.space/v2/blobs?epochs=2"
        ),
        Err(PublisherClientError::EndpointPathMismatch)
    ));
    // Reject: fragment.
    assert!(matches!(
        validate_publisher_put_url(
            "https://publisher.walrus-testnet.walrus.space/v1/blobs?epochs=2#frag"
        ),
        Err(PublisherClientError::EndpointForbiddenFragment)
    ));
    // Reject: extra query key.
    assert!(matches!(
        validate_publisher_put_url(
            "https://publisher.walrus-testnet.walrus.space/v1/blobs?epochs=2&secret=1"
        ),
        Err(PublisherClientError::EndpointQueryKeyForbidden)
    ));
    // Reject: only the extra key, no epochs.
    assert!(matches!(
        validate_publisher_put_url(
            "https://publisher.walrus-testnet.walrus.space/v1/blobs?other=1"
        ),
        Err(PublisherClientError::EndpointQueryKeyForbidden)
    ));
    // Reject: missing query entirely.
    assert!(matches!(
        validate_publisher_put_url("https://publisher.walrus-testnet.walrus.space/v1/blobs"),
        Err(PublisherClientError::EndpointQueryEpochsMissing)
    ));
    // Reject: empty epochs value.
    assert!(matches!(
        validate_publisher_put_url(
            "https://publisher.walrus-testnet.walrus.space/v1/blobs?epochs="
        ),
        Err(PublisherClientError::EndpointQueryEpochsMalformed)
    ));
    // Reject: duplicate epochs.
    assert!(matches!(
        validate_publisher_put_url(
            "https://publisher.walrus-testnet.walrus.space/v1/blobs?epochs=2&epochs=3"
        ),
        Err(PublisherClientError::EndpointQueryEpochsDuplicate)
    ));
    // Reject: zero epochs.
    assert!(matches!(
        validate_publisher_put_url(
            "https://publisher.walrus-testnet.walrus.space/v1/blobs?epochs=0"
        ),
        Err(PublisherClientError::EndpointQueryEpochsZero)
    ));
    // Reject: non-numeric epochs.
    assert!(matches!(
        validate_publisher_put_url(
            "https://publisher.walrus-testnet.walrus.space/v1/blobs?epochs=abc"
        ),
        Err(PublisherClientError::EndpointQueryEpochsMalformed)
    ));
    // Reject: epochs out of u16 range.
    assert!(matches!(
        validate_publisher_put_url(
            "https://publisher.walrus-testnet.walrus.space/v1/blobs?epochs=65536"
        ),
        Err(PublisherClientError::EndpointQueryEpochsMalformed)
    ));
}

// ===========================================================================
// Test 4
// ===========================================================================

#[test]
fn c0_2_response_matrix_accepts_only_success_variants_with_reported_id() {
    // 200 + newlyCreated body → Accepted::NewlyCreated.
    let body = newly_created_body("blob-id-A");
    let d = classify_publisher_response(200, &body).unwrap();
    match d {
        PublisherResponseDecision::Accepted {
            variant,
            reported_blob_id,
        } => {
            assert_eq!(variant, BlobStoreSuccessVariant::NewlyCreated);
            assert_eq!(reported_blob_id.as_str(), "blob-id-A");
        }
        other => panic!("expected Accepted{{NewlyCreated}}, got {:?}", other),
    }
    // 201 + alreadyCertified body → Accepted::AlreadyCertified.
    let body = already_certified_body("blob-id-B");
    let d = classify_publisher_response(201, &body).unwrap();
    match d {
        PublisherResponseDecision::Accepted {
            variant,
            reported_blob_id,
        } => {
            assert_eq!(variant, BlobStoreSuccessVariant::AlreadyCertified);
            assert_eq!(reported_blob_id.as_str(), "blob-id-B");
        }
        other => panic!("expected Accepted{{AlreadyCertified}}, got {:?}", other),
    }
    // 200 + body without a recognised success key → JsonMalformed.
    let mystery = br#"{"unknown":{"blobId":"x"}}"#;
    let err = classify_publisher_response(200, mystery).unwrap_err();
    assert!(matches!(
        err,
        PublisherClientError::ResponseBodyJsonMalformed
    ));
    // 200 + recognised key but missing blobId → ReportedBlobIdMissing.
    let no_id = br#"{"newlyCreated":{"blobObject":{"epochs":1}}}"#;
    let err = classify_publisher_response(200, no_id).unwrap_err();
    assert!(matches!(
        err,
        PublisherClientError::ResponseReportedBlobIdMissing
    ));
    // 200 + recognised key + blobId empty → ReportedBlobIdEmpty.
    let empty = br#"{"newlyCreated":{"blobObject":{"blobId":""}}}"#;
    let err = classify_publisher_response(200, empty).unwrap_err();
    assert!(matches!(
        err,
        PublisherClientError::ResponseReportedBlobIdEmpty
    ));
    // Oversized body → ResponseBodyTooLarge.
    let oversize = vec![b' '; MAX_PUBLISHER_RESPONSE_BYTES + 1];
    let err = classify_publisher_response(200, &oversize).unwrap_err();
    match err {
        PublisherClientError::ResponseBodyTooLarge {
            observed_bytes,
            cap_bytes,
        } => {
            assert_eq!(observed_bytes, MAX_PUBLISHER_RESPONSE_BYTES + 1);
            assert_eq!(cap_bytes, MAX_PUBLISHER_RESPONSE_BYTES);
        }
        other => panic!("expected ResponseBodyTooLarge, got {:?}", other),
    }
    // Oversize blob-id text → ReportedBlobIdTooLong.
    let big_id: String = "z".repeat(MAX_REPORTED_BLOB_ID_TEXT_BYTES + 1);
    let body = newly_created_body(&big_id);
    let err = classify_publisher_response(200, &body).unwrap_err();
    match err {
        PublisherClientError::ResponseReportedBlobIdTooLong {
            observed_bytes,
            cap_bytes,
        } => {
            assert_eq!(observed_bytes, MAX_REPORTED_BLOB_ID_TEXT_BYTES + 1);
            assert_eq!(cap_bytes, MAX_REPORTED_BLOB_ID_TEXT_BYTES);
        }
        other => panic!("expected ResponseReportedBlobIdTooLong, got {:?}", other),
    }
    // Standalone PublisherReportedBlobId::try_from_text guard.
    assert!(matches!(
        PublisherReportedBlobId::try_from_text(""),
        Err(PublisherClientError::ResponseReportedBlobIdEmpty)
    ));
    let ok = PublisherReportedBlobId::try_from_text("blob-id-X").unwrap();
    assert_eq!(ok.as_str(), "blob-id-X");
    assert_eq!(ok.byte_len(), "blob-id-X".len());
}

// ===========================================================================
// Test 5
// ===========================================================================

#[test]
fn c0_2_response_matrix_stops_for_error_invalid_and_proxy_status() {
    // 400 → SemanticError, Never, RequestBytesMayHaveCrossed.
    let d = classify_publisher_response(400, b"").unwrap();
    match d {
        PublisherResponseDecision::Stopped {
            reason,
            retry,
            boundary,
        } => {
            assert_eq!(reason, PublishStopReason::SemanticError);
            assert_eq!(retry, PublisherRetryDisposition::Never);
            assert_eq!(boundary, BoundaryState::RequestBytesMayHaveCrossed);
        }
        other => panic!("expected Stopped, got {:?}", other),
    }
    // 413 / 415 / 422 also Semantic.
    for status in [413u16, 415, 422] {
        let d = classify_publisher_response(status, b"").unwrap();
        assert!(matches!(
            d,
            PublisherResponseDecision::Stopped {
                reason: PublishStopReason::SemanticError,
                ..
            }
        ));
    }
    // 451 → MarkedInvalid.
    let d = classify_publisher_response(451, b"").unwrap();
    assert!(matches!(
        d,
        PublisherResponseDecision::Stopped {
            reason: PublishStopReason::MarkedInvalid,
            retry: PublisherRetryDisposition::Never,
            boundary: BoundaryState::RequestBytesMayHaveCrossed,
        }
    ));
    // 404 / 410 → TerminalStatus (other 4xx).
    for status in [404u16, 410] {
        let d = classify_publisher_response(status, b"").unwrap();
        assert!(matches!(
            d,
            PublisherResponseDecision::Stopped {
                reason: PublishStopReason::TerminalStatus,
                retry: PublisherRetryDisposition::Never,
                boundary: BoundaryState::RequestBytesMayHaveCrossed,
            }
        ));
    }
    // 3xx proxy → SemanticError on closed endpoint (no redirects allowed).
    for status in [301u16, 302, 307, 308] {
        let d = classify_publisher_response(status, b"").unwrap();
        assert!(matches!(
            d,
            PublisherResponseDecision::Stopped {
                reason: PublishStopReason::SemanticError,
                retry: PublisherRetryDisposition::Never,
                boundary: BoundaryState::RequestBytesMayHaveCrossed,
            }
        ));
    }
    // 5xx → RetryableStatusAfterBoundary + AutoRetry + UnknownAfterBoundary.
    for status in [500u16, 502, 503, 504] {
        let d = classify_publisher_response(status, b"").unwrap();
        assert!(matches!(
            d,
            PublisherResponseDecision::Stopped {
                reason: PublishStopReason::RetryableStatusAfterBoundary,
                retry: PublisherRetryDisposition::AutoRetry,
                boundary: BoundaryState::UnknownAfterBoundary,
            }
        ));
    }
    // Unsupported status (outside 100..=599).
    let err = classify_publisher_response(99, b"").unwrap_err();
    assert!(matches!(
        err,
        PublisherClientError::ResponseStatusUnsupported {
            http_status_u16: 99
        }
    ));
    let err = classify_publisher_response(700, b"").unwrap_err();
    assert!(matches!(
        err,
        PublisherClientError::ResponseStatusUnsupported {
            http_status_u16: 700
        }
    ));
}

// ===========================================================================
// Test 6
// ===========================================================================

#[test]
fn c0_2_unknown_after_boundary_retry_is_absorbing() {
    // Every transport-failure kind, combined with UnknownAfterBoundary,
    // must yield ManualReconcile and preserve the boundary.
    let kinds = [
        TransportFailureKind::Dns,
        TransportFailureKind::Connect,
        TransportFailureKind::Tls,
        TransportFailureKind::WriteTimeout,
        TransportFailureKind::ResponseTimeout,
        TransportFailureKind::Cancelled,
    ];
    for kind in kinds {
        for attempt in 0u16..6 {
            let d =
                classify_transport_failure(kind, BoundaryState::UnknownAfterBoundary, attempt, 5);
            assert_eq!(d.disposition, PublisherRetryDisposition::ManualReconcile);
            assert_eq!(d.boundary, BoundaryState::UnknownAfterBoundary);
        }
    }
    // RequestBytesMayHaveCrossed is non-retryable.
    let d = classify_transport_failure(
        TransportFailureKind::ResponseTimeout,
        BoundaryState::RequestBytesMayHaveCrossed,
        0,
        5,
    );
    assert_eq!(d.disposition, PublisherRetryDisposition::Never);
    // NoExternalMutation × non-Cancelled × attempt < max → AutoRetry.
    let d = classify_transport_failure(
        TransportFailureKind::Connect,
        BoundaryState::NoExternalMutation,
        0,
        5,
    );
    assert_eq!(d.disposition, PublisherRetryDisposition::AutoRetry);
    // NoExternalMutation × Cancelled → Never.
    let d = classify_transport_failure(
        TransportFailureKind::Cancelled,
        BoundaryState::NoExternalMutation,
        0,
        5,
    );
    assert_eq!(d.disposition, PublisherRetryDisposition::Never);
    // NoExternalMutation × attempt == max → Never (last attempt).
    let d = classify_transport_failure(
        TransportFailureKind::Connect,
        BoundaryState::NoExternalMutation,
        5,
        5,
    );
    assert_eq!(d.disposition, PublisherRetryDisposition::Never);
}

// ===========================================================================
// Test 7
// ===========================================================================

#[test]
fn c0_2_publish_loop_retries_only_before_external_mutation() {
    // Two transport failures at NoExternalMutation, then a success.
    let success = newly_created_body("blob-id-retry-7");
    let canned = vec![
        Canned::Err(PublisherTransportFailure {
            kind: TransportFailureKind::Dns,
            boundary: BoundaryState::NoExternalMutation,
            elapsed_ms_u32: 11,
        }),
        Canned::Err(PublisherTransportFailure {
            kind: TransportFailureKind::Connect,
            boundary: BoundaryState::NoExternalMutation,
            elapsed_ms_u32: 22,
        }),
        Canned::Ok(PublisherTransportResponse {
            http_status_u16: 200,
            body: success,
            elapsed_ms_u32: 33,
        }),
    ];
    let mut transport = FakeTransport::new(canned);
    let body = b"synthetic-payload";
    let request = ok_synthetic_request(body);
    let run: PublisherClientRun =
        publish_blob_with_transport(&mut transport, &request, 0xdead_beef_u64, 5).unwrap();
    assert_eq!(transport.call_count, 3);
    assert_eq!(run.attempts_u16, 3);
    match run.decision {
        PublisherResponseDecision::Accepted {
            variant,
            reported_blob_id,
        } => {
            assert_eq!(variant, BlobStoreSuccessVariant::NewlyCreated);
            assert_eq!(reported_blob_id.as_str(), "blob-id-retry-7");
        }
        other => panic!("expected Accepted, got {:?}", other),
    }
    assert_eq!(run.diagnostics.len(), 3);
    // First two diagnostics are transport_failure, last one is accepted.
    assert!(run.diagnostics[0].contains("\"event\":\"publish.transport_failure\""));
    assert!(run.diagnostics[1].contains("\"event\":\"publish.transport_failure\""));
    assert!(run.diagnostics[2].contains("\"event\":\"publish.accepted\""));
}

// ===========================================================================
// Test 8
// ===========================================================================

#[test]
fn c0_2_publish_loop_stops_after_unknown_boundary_without_second_put() {
    // First (and only) call fails at UnknownAfterBoundary.
    let canned = vec![Canned::Err(PublisherTransportFailure {
        kind: TransportFailureKind::ResponseTimeout,
        boundary: BoundaryState::UnknownAfterBoundary,
        elapsed_ms_u32: 99,
    })];
    let mut transport = FakeTransport::new(canned);
    let body = b"synthetic-payload-8";
    let request = ok_synthetic_request(body);
    let run = publish_blob_with_transport(&mut transport, &request, 7u64, 5).unwrap();
    assert_eq!(transport.call_count, 1);
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
        other => panic!("expected Stopped, got {:?}", other),
    }
    assert_eq!(run.diagnostics.len(), 1);
    assert!(run.diagnostics[0].contains("\"event\":\"publish.transport_failure\""));
    assert!(run.diagnostics[0].contains("\"boundary_state\":\"unknown_after_boundary\""));
    assert!(run.diagnostics[0].contains("\"retry_disposition\":\"manual_reconcile\""));

    // Same shape for a 5xx response: the response says AutoRetry, but the
    // boundary is UnknownAfterBoundary → loop must still stop with exactly
    // one transport call.
    let canned = vec![Canned::Ok(PublisherTransportResponse {
        http_status_u16: 503,
        body: Vec::new(),
        elapsed_ms_u32: 12,
    })];
    let mut transport = FakeTransport::new(canned);
    let request = ok_synthetic_request(body);
    let run = publish_blob_with_transport(&mut transport, &request, 8u64, 5).unwrap();
    assert_eq!(transport.call_count, 1);
    assert_eq!(run.attempts_u16, 1);
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
        other => panic!("expected Stopped, got {:?}", other),
    }
}

// ===========================================================================
// Test 9
// ===========================================================================

#[test]
fn c0_2_safe_diagnostic_drops_body_and_uses_allowlisted_keys() {
    // Build a diagnostic carrying every field; render it; assert the JSON
    // line has exactly the nine allowlisted keys, and that the surrounding
    // payload body never appears.
    let diag = PublisherDiagnostic {
        event: "publish.accepted",
        attempt_u16: 3,
        request_id_u64: 0x1122_3344_5566_7788,
        payload_len_bytes: 42,
        http_status_u16: Some(201),
        elapsed_ms_u32: 17,
        backoff_ms_u32: 250,
        retry_disposition: PublisherRetryDisposition::Never,
        boundary_state: BoundaryState::RequestBytesMayHaveCrossed,
    };
    let line = diag.to_json_line();
    // Single line.
    assert!(!line.contains('\n'));
    // Starts/ends with brace.
    assert!(line.starts_with('{'));
    assert!(line.ends_with('}'));
    // All nine allowlist keys appear, in canonical order.
    let allowlist = [
        "\"event\":",
        "\"attempt\":",
        "\"request_id\":",
        "\"payload_len_bytes\":",
        "\"http_status\":",
        "\"elapsed_ms\":",
        "\"backoff_ms\":",
        "\"retry_disposition\":",
        "\"boundary_state\":",
    ];
    let mut cursor = 0usize;
    for key in allowlist {
        let idx = line[cursor..]
            .find(key)
            .unwrap_or_else(|| panic!("key {} missing from {}", key, line));
        cursor += idx + key.len();
    }
    // Values render as expected.
    assert!(line.contains("\"event\":\"publish.accepted\""));
    assert!(line.contains("\"attempt\":3"));
    assert!(line.contains("\"request_id\":1234605616436508552"));
    assert!(line.contains("\"payload_len_bytes\":42"));
    assert!(line.contains("\"http_status\":201"));
    assert!(line.contains("\"elapsed_ms\":17"));
    assert!(line.contains("\"backoff_ms\":250"));
    assert!(line.contains("\"retry_disposition\":\"never\""));
    assert!(line.contains("\"boundary_state\":\"request_bytes_may_have_crossed\""));

    // http_status renders as null when None.
    let diag_null = PublisherDiagnostic {
        event: "publish.transport_failure",
        attempt_u16: 1,
        request_id_u64: 1,
        payload_len_bytes: 0,
        http_status_u16: None,
        elapsed_ms_u32: 0,
        backoff_ms_u32: 0,
        retry_disposition: PublisherRetryDisposition::ManualReconcile,
        boundary_state: BoundaryState::UnknownAfterBoundary,
    };
    assert!(diag_null.to_json_line().contains("\"http_status\":null"));

    // End-to-end: a real loop with a payload containing an obvious canary
    // must not emit that canary anywhere in its diagnostics.
    let canary = b"CANARY_PAYLOAD_DROP_8a59c";
    let canary_str = "CANARY_PAYLOAD_DROP_8a59c";
    let canned = vec![Canned::Ok(PublisherTransportResponse {
        http_status_u16: 200,
        // Response body also contains canary-like substrings to make sure
        // we don't accidentally splice it in either.
        body: newly_created_body("CANARY-BLOB-ID-do-not-leak"),
        elapsed_ms_u32: 5,
    })];
    let mut transport = FakeTransport::new(canned);
    let request = ok_synthetic_request(canary);
    let run = publish_blob_with_transport(&mut transport, &request, 9u64, 3).unwrap();
    for line in &run.diagnostics {
        assert!(
            !line.contains(canary_str),
            "diagnostic leaked canary payload: {}",
            line
        );
        assert!(
            !line.contains("CANARY-BLOB-ID-do-not-leak"),
            "diagnostic leaked reported blob-id text: {}",
            line
        );
        assert!(
            !line.contains("blobId"),
            "diagnostic must not carry response keys: {}",
            line
        );
        assert!(
            !line.contains("newlyCreated"),
            "diagnostic must not carry response keys: {}",
            line
        );
    }
    // Sanity: the run itself preserves the reported id (via decision).
    if let PublisherResponseDecision::Accepted {
        reported_blob_id, ..
    } = &run.decision
    {
        assert_eq!(reported_blob_id.as_str(), "CANARY-BLOB-ID-do-not-leak");
    } else {
        panic!("expected Accepted, got {:?}", run.decision);
    }
}
