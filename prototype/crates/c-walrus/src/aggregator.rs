//! Walrus aggregator GET transport (atom #9 · C.0.3).
//!
//! # Madness invariants (§4.C `C.aggregator`)
//!
//! 1. **Closed endpoint.** The aggregator base URL is pinned to
//!    [`TESTNET_AGGREGATOR_BASE_URL`] and the path is exactly
//!    [`WALRUS_GET_BLOB_PATH`] followed by a 64-character lowercase hex
//!    encoding of the [`BlobId`] bytes. Every other scheme, host, port,
//!    userinfo, path prefix, blob-id text, query, or fragment is rejected by
//!    [`validate_aggregator_get_url`].
//! 2. **Read-only retry is simple.** A GET never mutates the server, so the
//!    boundary state is always [`BoundaryState::NoExternalMutation`]. The
//!    loop retries iff `disposition == AutoRetry`; in particular, a 5xx
//!    response or a transport-level failure (other than
//!    [`TransportFailureKind::Cancelled`]) is retried while attempts remain.
//! 3. **Body cap before allocation.** [`classify_aggregator_response`]
//!    rejects bodies whose length exceeds `max_body_u32` *before* the
//!    [`AggregatorResponseDecision::Fetched`] variant is constructed (the
//!    response body is never cloned into a `Vec` past the cap). The atom #12
//!    `ReqwestAggregator` is expected to enforce the same cap at read time
//!    so the transport itself never allocates past `max_body_u32`.
//!
//! # Notes (`atom #9` clarifications of §4.C)
//!
//! * The blob-id path segment uses lowercase hexadecimal (64 characters for
//!   a 32-byte [`BlobId`]). The codec.rs test vector already uses hex as the
//!   byte-stable cross-language form, so atom #9 inherits that convention
//!   rather than inventing a second encoding. Atom #12 (net feature) is
//!   responsible for any translation to/from the Walrus testnet's actual
//!   path encoding.
//! * The error type is [`PublisherClientError`] (the `#[non_exhaustive]`
//!   reuse target introduced by atom #8). No new variants are added: the
//!   aggregator reuses `Endpoint*`, `ResponseBodyTooLarge`,
//!   `ResponseStatusUnsupported`, and `AttemptsExhausted` with the obvious
//!   semantics. `EndpointQueryKeyForbidden` is repurposed to mean "any
//!   query key is forbidden in the aggregator context"; the publisher
//!   docstring's mention of `epochs` does not apply here.
//! * `request_id_u64` is accepted for caller correlation symmetry with
//!   [`crate::publisher::publish_blob_with_transport`] but atom #9 does not
//!   emit it. Atom #12 (net feature) may introduce tracing emission keyed
//!   on this id; until then it is a forward-looking parameter.

use crate::blob_id::{
    WALRUS_BLOB_ID_TEXT_LEN_BASE64URL, decode_base64url_no_pad_32, encode_base64url_no_pad_32,
};
use crate::codec::{BLOB_ID_BYTES, BlobId};
use crate::publisher::{
    BoundaryState, PublisherClientError, PublisherRetryDisposition, PublisherTransportFailure,
    PublisherTransportResponse, TransportFailureKind, TransportRetryDecision,
};

// ===========================================================================
// 1. Module-level wire / policy constants (§4.C C.aggregator)
// ===========================================================================

/// Base URL of the Walrus public testnet aggregator. The aggregator transport
/// refuses every other host.
pub const TESTNET_AGGREGATOR_BASE_URL: &str = "https://aggregator.walrus-testnet.walrus.space";

/// HTTP path prefix for the Walrus GET-blob endpoint. The full path is this
/// prefix concatenated with the URL-safe base64 (no padding) encoding of the
/// [`BlobId`] — the exact form the real Walrus testnet aggregator parses
/// (bridge atom #116.75 · B.2.15.75; a hex segment is rejected live with HTTP
/// 400 "failed to parse a blob ID").
pub const WALRUS_GET_BLOB_PATH: &str = "/v1/blobs/";

/// Backoff (milliseconds) reported when `attempt_u16` is 0 or 1.
const BACKOFF_MS_ATTEMPT_0_1: u32 = 100;
/// Backoff (milliseconds) reported when `attempt_u16` is 2.
const BACKOFF_MS_ATTEMPT_2: u32 = 250;
/// Backoff (milliseconds) reported when `attempt_u16` is 3.
const BACKOFF_MS_ATTEMPT_3: u32 = 500;
/// Backoff (milliseconds) reported when `attempt_u16` is 4 or more.
const BACKOFF_MS_ATTEMPT_4_PLUS: u32 = 1000;

/// Pinned aggregator host (authority without scheme or path).
const PINNED_AGGREGATOR_HOST: &str = "aggregator.walrus-testnet.walrus.space";

// ===========================================================================
// 2. AggregatorEndpoint
// ===========================================================================

/// Closed aggregator endpoint marker. The only constructor is
/// [`AggregatorEndpoint::testnet_public`]; there is no host or path field to
/// override.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub struct AggregatorEndpoint {
    _seal: (),
}

impl AggregatorEndpoint {
    /// The single sanctioned endpoint: Walrus public testnet aggregator.
    #[inline]
    pub const fn testnet_public() -> Self {
        Self { _seal: () }
    }

    /// Base URL ([`TESTNET_AGGREGATOR_BASE_URL`]).
    #[inline]
    pub const fn base_url(self) -> &'static str {
        TESTNET_AGGREGATOR_BASE_URL
    }

    /// GET path prefix ([`WALRUS_GET_BLOB_PATH`]). The URL-safe base64 blob-id
    /// segment is appended at compose time.
    #[inline]
    pub const fn get_path_prefix(self) -> &'static str {
        WALRUS_GET_BLOB_PATH
    }
}

// ===========================================================================
// 3. AggregatorGetUrl
// ===========================================================================

/// A composed (or validated) Walrus aggregator GET URL. Construction is the
/// only way to obtain one: either via [`AggregatorGetUrl::compose`] (which
/// guarantees correctness by construction) or via
/// [`validate_aggregator_get_url`] (which checks an external candidate).
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct AggregatorGetUrl {
    url: String,
}

impl AggregatorGetUrl {
    /// Compose the canonical aggregator GET URL for a given blob id. The blob-id
    /// path segment is the URL-safe base64 (no padding) encoding of the 32 raw
    /// bytes — the exact form the real Walrus testnet aggregator parses (bridge
    /// atom #116.75); a hex segment is rejected by the live aggregator.
    pub fn compose(endpoint: AggregatorEndpoint, blob_id: &BlobId) -> Self {
        let base = endpoint.base_url();
        let path = endpoint.get_path_prefix();
        let mut url =
            String::with_capacity(base.len() + path.len() + WALRUS_BLOB_ID_TEXT_LEN_BASE64URL);
        url.push_str(base);
        url.push_str(path);
        url.push_str(&encode_base64url_no_pad_32(&blob_id.0));
        Self { url }
    }

    /// Borrowed view of the URL text.
    #[inline]
    pub fn as_str(&self) -> &str {
        &self.url
    }

    /// Length of the URL text in bytes.
    #[inline]
    pub fn byte_len(&self) -> usize {
        self.url.len()
    }
}

/// Validate a candidate aggregator GET URL against the closed-endpoint
/// policy. Returns an [`AggregatorGetUrl`] iff every check passes.
///
/// The accepted shape is exactly:
///
/// ```text
/// https://aggregator.walrus-testnet.walrus.space/v1/blobs/{43 URL-safe base64 chars}
/// ```
///
/// Every other scheme, host, port, userinfo, fragment, path prefix, blob-id
/// segment shape, or query is rejected with a specific
/// [`PublisherClientError`] variant.
pub fn validate_aggregator_get_url(url: &str) -> Result<AggregatorGetUrl, PublisherClientError> {
    // Strip scheme "https://".
    let scheme_https = "https://";
    let after_scheme = match url.strip_prefix(scheme_https) {
        Some(rest) => rest,
        None => return Err(PublisherClientError::EndpointSchemeForbidden),
    };

    // No fragment.
    if after_scheme.contains('#') {
        return Err(PublisherClientError::EndpointForbiddenFragment);
    }

    // Locate the first '/' to split authority from path+query.
    let authority_end = match after_scheme.find('/') {
        Some(idx) => idx,
        None => return Err(PublisherClientError::EndpointPathMismatch),
    };
    let authority = &after_scheme[..authority_end];
    let path_and_query = &after_scheme[authority_end..];

    // No userinfo (no '@' in authority).
    if authority.contains('@') {
        return Err(PublisherClientError::EndpointForbiddenUserinfo);
    }
    // No port (no ':' in authority).
    if authority.contains(':') {
        return Err(PublisherClientError::EndpointPortForbidden);
    }
    // Host must be the pinned aggregator host.
    if authority != PINNED_AGGREGATOR_HOST {
        return Err(PublisherClientError::EndpointHostForbidden);
    }

    // Split path from query.
    let (path, query) = match path_and_query.find('?') {
        Some(idx) => (&path_and_query[..idx], Some(&path_and_query[idx + 1..])),
        None => (path_and_query, None),
    };

    // Path must start with WALRUS_GET_BLOB_PATH and then be followed by exactly
    // WALRUS_BLOB_ID_TEXT_LEN_BASE64URL URL-safe base64 (no padding) chars that
    // decode to a 32-byte blob id (bridge atom #116.75). A hex segment, a wrong
    // length, or any non-alphabet character is rejected fail-closed.
    let blob_id_segment = match path.strip_prefix(WALRUS_GET_BLOB_PATH) {
        Some(rest) => rest,
        None => return Err(PublisherClientError::EndpointPathMismatch),
    };
    if blob_id_segment.len() != WALRUS_BLOB_ID_TEXT_LEN_BASE64URL {
        return Err(PublisherClientError::EndpointPathMismatch);
    }
    if decode_base64url_no_pad_32(blob_id_segment).is_none() {
        return Err(PublisherClientError::EndpointPathMismatch);
    }

    // No query of any kind (aggregator GET takes no parameters; even a
    // bare trailing '?' is rejected).
    if query.is_some() {
        return Err(PublisherClientError::EndpointQueryKeyForbidden);
    }

    Ok(AggregatorGetUrl {
        url: url.to_owned(),
    })
}

// ===========================================================================
// 4. AggregatorGetRequest
// ===========================================================================

/// A planned GET request. The blob id is borrowed so the aggregator never
/// owns a copy of the caller's `BlobId`.
#[derive(Clone, Copy, Debug)]
pub struct AggregatorGetRequest<'a> {
    endpoint: AggregatorEndpoint,
    blob_id: &'a BlobId,
}

impl<'a> AggregatorGetRequest<'a> {
    /// Plan a GET request for the given blob id at the given endpoint.
    #[inline]
    pub const fn new(endpoint: AggregatorEndpoint, blob_id: &'a BlobId) -> Self {
        Self { endpoint, blob_id }
    }

    /// Endpoint this request targets.
    #[inline]
    pub const fn endpoint(&self) -> AggregatorEndpoint {
        self.endpoint
    }

    /// Borrowed blob id this request targets.
    #[inline]
    pub const fn blob_id(&self) -> &'a BlobId {
        self.blob_id
    }

    /// Build the canonical GET URL for this request.
    #[inline]
    pub fn get_url(&self) -> AggregatorGetUrl {
        AggregatorGetUrl::compose(self.endpoint, self.blob_id)
    }
}

// ===========================================================================
// 5. FetchStopReason
// ===========================================================================

/// Why the aggregator loop stopped without producing a
/// [`AggregatorResponseDecision::Fetched`] outcome.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
#[non_exhaustive]
#[repr(u8)]
pub enum FetchStopReason {
    /// Server returned HTTP 404.
    NotFound = 1,
    /// 4xx-class HTTP terminal status that is not specifically NotFound or
    /// SemanticError.
    TerminalStatus = 2,
    /// Reserved for content-length-based pre-read rejection by the
    /// atom #12 network transport (the offline classifier surfaces oversized
    /// bodies as [`PublisherClientError::ResponseBodyTooLarge`] instead).
    OversizedBody = 3,
    /// Server returned a semantically invalid response (3xx redirect from
    /// the closed endpoint, 400/413/415/422, 451, or unexpected 2xx other
    /// than 200).
    SemanticError = 4,
    /// Transport-level failure that exhausted retries or whose kind was
    /// non-retryable ([`TransportFailureKind::Cancelled`]).
    ProtocolFailure = 5,
}

impl FetchStopReason {
    /// Stable `&'static str` label used by diagnostics.
    #[inline]
    pub const fn class_label(self) -> &'static str {
        match self {
            Self::NotFound => "not_found",
            Self::TerminalStatus => "terminal_status",
            Self::OversizedBody => "oversized_body",
            Self::SemanticError => "semantic_error",
            Self::ProtocolFailure => "protocol_failure",
        }
    }

    /// One-byte wire tag for this stop reason.
    #[inline]
    pub const fn tag(self) -> u8 {
        self as u8
    }
}

// ===========================================================================
// 6. AggregatorResponseDecision
// ===========================================================================

/// Outcome of a single aggregator GET attempt's response classification.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum AggregatorResponseDecision {
    /// Server returned the blob body.
    Fetched {
        /// Response bytes (length `<= max_body_u32`).
        body: Vec<u8>,
        /// Length of [`Self::Fetched::body`] in bytes, fit into `u32`.
        content_len_u32: u32,
    },
    /// Server returned a non-success status (or the loop ran out of safe
    /// retries).
    Stopped {
        /// Why we stopped.
        reason: FetchStopReason,
        /// Whether retrying could ever be safe.
        retry: PublisherRetryDisposition,
        /// Boundary state observed (always
        /// [`BoundaryState::NoExternalMutation`] for a GET).
        boundary: BoundaryState,
    },
}

// ===========================================================================
// 7. AggregatorTransport
// ===========================================================================

/// Abstraction over the underlying HTTP client. The trait is intentionally
/// minimal so that offline tests can drive [`fetch_blob_with_transport`]
/// with a fake transport while atom #12 (net feature) provides a real
/// reqwest-backed implementation under a feature flag.
///
/// The trait reuses [`PublisherTransportResponse`] /
/// [`PublisherTransportFailure`] verbatim from atom #8 so a single fake
/// transport implementation can serve both PUT and GET tests if desired.
pub trait AggregatorTransport {
    /// Issue a single GET-blob attempt and return either the server's
    /// response or a transport-level failure.
    fn get_blob(
        &mut self,
        request: &AggregatorGetRequest<'_>,
    ) -> Result<PublisherTransportResponse, PublisherTransportFailure>;
}

// ===========================================================================
// 8. classify_aggregator_response
// ===========================================================================

/// Classify a single aggregator response into either a [`Fetched`] or a
/// [`Stopped`] decision. Returns a [`PublisherClientError`] only for
/// physically invalid inputs (oversized body, status outside HTTP's 100–599
/// range) — every other outcome is a well-formed
/// [`AggregatorResponseDecision::Stopped`].
///
/// `max_body_u32` is enforced **before** the [`Fetched`] variant is
/// constructed: a body whose length exceeds the cap is rejected as
/// [`PublisherClientError::ResponseBodyTooLarge`] without any allocation
/// past the cap.
///
/// [`Fetched`]: AggregatorResponseDecision::Fetched
/// [`Stopped`]: AggregatorResponseDecision::Stopped
pub fn classify_aggregator_response(
    http_status_u16: u16,
    body: &[u8],
    max_body_u32: u32,
) -> Result<AggregatorResponseDecision, PublisherClientError> {
    if body.len() > max_body_u32 as usize {
        return Err(PublisherClientError::ResponseBodyTooLarge {
            observed_bytes: body.len(),
            cap_bytes: max_body_u32 as usize,
        });
    }
    match http_status_u16 {
        200 => {
            let content_len_u32 = body.len() as u32;
            let owned: Vec<u8> = body.to_vec();
            Ok(AggregatorResponseDecision::Fetched {
                body: owned,
                content_len_u32,
            })
        }
        100..=199 => Err(PublisherClientError::ResponseStatusUnsupported { http_status_u16 }),
        201..=299 => Ok(AggregatorResponseDecision::Stopped {
            reason: FetchStopReason::SemanticError,
            retry: PublisherRetryDisposition::Never,
            boundary: BoundaryState::NoExternalMutation,
        }),
        300..=399 => Ok(AggregatorResponseDecision::Stopped {
            reason: FetchStopReason::SemanticError,
            retry: PublisherRetryDisposition::Never,
            boundary: BoundaryState::NoExternalMutation,
        }),
        404 => Ok(AggregatorResponseDecision::Stopped {
            reason: FetchStopReason::NotFound,
            retry: PublisherRetryDisposition::Never,
            boundary: BoundaryState::NoExternalMutation,
        }),
        451 => Ok(AggregatorResponseDecision::Stopped {
            reason: FetchStopReason::SemanticError,
            retry: PublisherRetryDisposition::Never,
            boundary: BoundaryState::NoExternalMutation,
        }),
        400 | 413 | 415 | 422 => Ok(AggregatorResponseDecision::Stopped {
            reason: FetchStopReason::SemanticError,
            retry: PublisherRetryDisposition::Never,
            boundary: BoundaryState::NoExternalMutation,
        }),
        400..=499 => Ok(AggregatorResponseDecision::Stopped {
            reason: FetchStopReason::TerminalStatus,
            retry: PublisherRetryDisposition::Never,
            boundary: BoundaryState::NoExternalMutation,
        }),
        500..=599 => Ok(AggregatorResponseDecision::Stopped {
            reason: FetchStopReason::SemanticError,
            retry: PublisherRetryDisposition::AutoRetry,
            boundary: BoundaryState::NoExternalMutation,
        }),
        _ => Err(PublisherClientError::ResponseStatusUnsupported { http_status_u16 }),
    }
}

// ===========================================================================
// 9. classify_aggregator_transport_failure
// ===========================================================================

/// Decide what the aggregator loop should do with a transport-level failure
/// observed at a given attempt index.
///
/// Because a GET never mutates the server, the boundary state is always
/// [`BoundaryState::NoExternalMutation`]: any boundary reported by the
/// transport is collapsed to that value before dispatch. The disposition is
/// then [`PublisherRetryDisposition::AutoRetry`] while attempts remain
/// (except for [`TransportFailureKind::Cancelled`], which is always
/// non-retryable), and [`PublisherRetryDisposition::Never`] otherwise.
///
/// `backoff_ms_u32` follows the same schedule as
/// [`crate::publisher::classify_transport_failure`]: `100 ms` for attempt
/// 0–1, `250 ms` for 2, `500 ms` for 3, `1000 ms` for 4 and above.
pub const fn classify_aggregator_transport_failure(
    kind: TransportFailureKind,
    _observed_boundary: BoundaryState,
    attempt_u16: u16,
    max_attempts_u16: u16,
) -> TransportRetryDecision {
    let backoff_ms_u32 = match attempt_u16 {
        0 | 1 => BACKOFF_MS_ATTEMPT_0_1,
        2 => BACKOFF_MS_ATTEMPT_2,
        3 => BACKOFF_MS_ATTEMPT_3,
        _ => BACKOFF_MS_ATTEMPT_4_PLUS,
    };
    let disposition = match kind {
        TransportFailureKind::Cancelled => PublisherRetryDisposition::Never,
        _ => {
            if attempt_u16 < max_attempts_u16 {
                PublisherRetryDisposition::AutoRetry
            } else {
                PublisherRetryDisposition::Never
            }
        }
    };
    TransportRetryDecision {
        disposition,
        boundary: BoundaryState::NoExternalMutation,
        backoff_ms_u32,
    }
}

// ===========================================================================
// 10. fetch_blob_with_transport
// ===========================================================================

/// Execute the aggregator GET loop against an [`AggregatorTransport`].
/// Returns the final [`AggregatorResponseDecision`] (`Fetched` or `Stopped`)
/// when the loop terminates without an internal error.
///
/// Retry policy (`atom #9` madness 2): the loop retries iff
/// `disposition == AutoRetry`. Because a GET is read-only, the boundary
/// is always [`BoundaryState::NoExternalMutation`], so the retry-safety
/// check reduces to "disposition is AutoRetry and attempts remain".
///
/// `request_id_u64` is accepted for symmetry with the publisher loop; the
/// offline atom does not emit it.
pub fn fetch_blob_with_transport<T: AggregatorTransport>(
    transport: &mut T,
    request: &AggregatorGetRequest<'_>,
    request_id_u64: u64,
    max_attempts_u16: u16,
) -> Result<AggregatorResponseDecision, PublisherClientError> {
    let _ = request_id_u64;
    if max_attempts_u16 == 0 {
        return Err(PublisherClientError::AttemptsExhausted { attempts_u16: 0 });
    }
    let max_body_u32: u32 = u32::MAX;
    let mut attempt_u16: u16 = 0;
    loop {
        if attempt_u16 == max_attempts_u16 {
            return Err(PublisherClientError::AttemptsExhausted {
                attempts_u16: max_attempts_u16,
            });
        }
        attempt_u16 = attempt_u16.saturating_add(1);
        match transport.get_blob(request) {
            Ok(response) => {
                let status = response.http_status_u16;
                let decision = classify_aggregator_response(status, &response.body, max_body_u32)?;
                match decision {
                    AggregatorResponseDecision::Fetched { .. } => return Ok(decision),
                    AggregatorResponseDecision::Stopped {
                        reason,
                        retry,
                        boundary,
                    } => {
                        let retry_safe = matches!(retry, PublisherRetryDisposition::AutoRetry)
                            && matches!(boundary, BoundaryState::NoExternalMutation)
                            && attempt_u16 < max_attempts_u16;
                        if retry_safe {
                            continue;
                        }
                        return Ok(AggregatorResponseDecision::Stopped {
                            reason,
                            retry,
                            boundary,
                        });
                    }
                }
            }
            Err(failure) => {
                let retry_decision = classify_aggregator_transport_failure(
                    failure.kind,
                    failure.boundary,
                    attempt_u16.saturating_sub(1),
                    max_attempts_u16,
                );
                let retry_safe = matches!(
                    retry_decision.disposition,
                    PublisherRetryDisposition::AutoRetry
                ) && attempt_u16 < max_attempts_u16;
                if retry_safe {
                    continue;
                }
                return Ok(AggregatorResponseDecision::Stopped {
                    reason: FetchStopReason::ProtocolFailure,
                    retry: retry_decision.disposition,
                    boundary: BoundaryState::NoExternalMutation,
                });
            }
        }
    }
}

// ===========================================================================
// 11. Compile-time reuse marker
// ===========================================================================

// Static reuse marker against `atom #7`. The aggregator never decodes a
// blob-id back into raw bytes inside this crate, but the GET URL composition
// depends on `BLOB_ID_BYTES == 32`. `[(); 0 - condition as usize]` triggers a
// const-evaluation failure if the expected condition is false.
#[allow(dead_code)]
const AGGREGATOR_REUSES_ATOM7_BLOB_ID_BYTES_32: [(); 0 - !(BLOB_ID_BYTES == 32) as usize] = [];

// Static reuse marker against `atom #8`. The aggregator collapses every
// observed boundary to `NoExternalMutation`; this assert guards against any
// future enum-renumbering of `BoundaryState`.
#[allow(dead_code)]
const AGGREGATOR_REUSES_ATOM8_NO_MUT_TAG: [(); 0
    - !(BoundaryState::NoExternalMutation as u8 == 1) as usize] = [];

// ===========================================================================
// 12. Inline unit tests
// ===========================================================================

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    #![allow(clippy::expect_used)]
    use super::*;

    #[test]
    fn fetch_stop_reason_tags_are_stable_and_in_order() {
        assert_eq!(FetchStopReason::NotFound.tag(), 1);
        assert_eq!(FetchStopReason::TerminalStatus.tag(), 2);
        assert_eq!(FetchStopReason::OversizedBody.tag(), 3);
        assert_eq!(FetchStopReason::SemanticError.tag(), 4);
        assert_eq!(FetchStopReason::ProtocolFailure.tag(), 5);
    }

    #[test]
    fn fetch_stop_reason_class_labels_are_namespaced() {
        let labels = [
            FetchStopReason::NotFound.class_label(),
            FetchStopReason::TerminalStatus.class_label(),
            FetchStopReason::OversizedBody.class_label(),
            FetchStopReason::SemanticError.class_label(),
            FetchStopReason::ProtocolFailure.class_label(),
        ];
        for label in labels {
            assert!(!label.is_empty());
            assert!(
                label
                    .bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_'),
                "label not snake-case ascii: {}",
                label
            );
        }
        // No duplicates.
        let mut sorted = labels.to_vec();
        sorted.sort();
        sorted.dedup();
        assert_eq!(sorted.len(), labels.len());
    }

    #[test]
    fn validate_aggregator_get_url_round_trips_compose() {
        let blob = BlobId([0xAB; BLOB_ID_BYTES]);
        let composed = AggregatorGetUrl::compose(AggregatorEndpoint::testnet_public(), &blob);
        let validated = validate_aggregator_get_url(composed.as_str()).unwrap();
        assert_eq!(composed, validated);
    }

    #[test]
    fn aggregator_endpoint_constants_are_pinned() {
        let endpoint = AggregatorEndpoint::testnet_public();
        assert_eq!(endpoint.base_url(), TESTNET_AGGREGATOR_BASE_URL);
        assert_eq!(endpoint.get_path_prefix(), WALRUS_GET_BLOB_PATH);
        assert_eq!(
            TESTNET_AGGREGATOR_BASE_URL,
            "https://aggregator.walrus-testnet.walrus.space"
        );
        assert_eq!(WALRUS_GET_BLOB_PATH, "/v1/blobs/");
    }

    /// `bridge_116_75_compose_matches_live_aggregator_form` — the composed GET
    /// URL for the exact atom #116 blob id is byte-identical to the URL-safe
    /// base64 form the real Walrus testnet aggregator served HTTP 200 for. The
    /// 32 id bytes are the local RS2 derivation recorded at #116
    /// (`4e3287484c09700ab305ac463260747d859c8187710549cc65176757b73e5049`); the
    /// reported text (`TjKHSEwJcAqzBaxGMmB0fYWcgYdxBUnMZRdnV7c-UEk`) is the live
    /// aggregator path segment. A hex path (`/v1/blobs/4e3287...`) is rejected
    /// live with HTTP 400, which is why this bridge atom exists.
    #[test]
    fn bridge_116_75_compose_matches_live_aggregator_form() {
        let atom116_id_bytes: [u8; BLOB_ID_BYTES] = [
            0x4e, 0x32, 0x87, 0x48, 0x4c, 0x09, 0x70, 0x0a, 0xb3, 0x05, 0xac, 0x46, 0x32, 0x60,
            0x74, 0x7d, 0x85, 0x9c, 0x81, 0x87, 0x71, 0x05, 0x49, 0xcc, 0x65, 0x17, 0x67, 0x57,
            0xb7, 0x3e, 0x50, 0x49,
        ];
        let blob = BlobId(atom116_id_bytes);
        let composed = AggregatorGetUrl::compose(AggregatorEndpoint::testnet_public(), &blob);
        assert_eq!(
            composed.as_str(),
            "https://aggregator.walrus-testnet.walrus.space/v1/blobs/\
             TjKHSEwJcAqzBaxGMmB0fYWcgYdxBUnMZRdnV7c-UEk",
            "composed GET URL must byte-match the live-200 base64url form"
        );
        // The base64url path segment is exactly 43 chars (32 raw bytes).
        let seg = composed
            .as_str()
            .strip_prefix("https://aggregator.walrus-testnet.walrus.space/v1/blobs/")
            .expect("canonical prefix");
        assert_eq!(seg.len(), WALRUS_BLOB_ID_TEXT_LEN_BASE64URL);
        assert_eq!(seg, "TjKHSEwJcAqzBaxGMmB0fYWcgYdxBUnMZRdnV7c-UEk");
        // compose -> validate round-trips on the real id.
        let validated = validate_aggregator_get_url(composed.as_str()).unwrap();
        assert_eq!(composed, validated);
    }

    #[test]
    fn classify_aggregator_transport_failure_collapses_boundary_to_no_external_mutation() {
        let d = classify_aggregator_transport_failure(
            TransportFailureKind::WriteTimeout,
            BoundaryState::UnknownAfterBoundary,
            0,
            3,
        );
        assert_eq!(d.boundary, BoundaryState::NoExternalMutation);
        assert_eq!(d.disposition, PublisherRetryDisposition::AutoRetry);
        assert_eq!(d.backoff_ms_u32, 100);
    }

    #[test]
    fn classify_aggregator_transport_failure_cancelled_is_never_retried() {
        let d = classify_aggregator_transport_failure(
            TransportFailureKind::Cancelled,
            BoundaryState::NoExternalMutation,
            0,
            3,
        );
        assert_eq!(d.disposition, PublisherRetryDisposition::Never);
        assert_eq!(d.boundary, BoundaryState::NoExternalMutation);
    }

    #[test]
    fn classify_aggregator_transport_failure_backoff_schedule_is_deterministic() {
        for (attempt, expected) in [
            (0u16, 100u32),
            (1, 100),
            (2, 250),
            (3, 500),
            (4, 1000),
            (9, 1000),
        ] {
            let d = classify_aggregator_transport_failure(
                TransportFailureKind::WriteTimeout,
                BoundaryState::NoExternalMutation,
                attempt,
                u16::MAX,
            );
            assert_eq!(d.backoff_ms_u32, expected, "attempt={}", attempt);
        }
    }

    /// `bridge_116_75_validate_rejects_hex_segment` — a 64-char lowercase-hex
    /// blob-id segment (the pre-bridge form) is now rejected as a path mismatch:
    /// its length (64) is not [`WALRUS_BLOB_ID_TEXT_LEN_BASE64URL`] (43). This is
    /// the offline mirror of the live HTTP 400 the hex form produced.
    #[test]
    fn bridge_116_75_validate_rejects_hex_segment() {
        let hex_url = "https://aggregator.walrus-testnet.walrus.space/v1/blobs/\
                       4e3287484c09700ab305ac463260747d859c8187710549cc65176757b73e5049";
        assert!(matches!(
            validate_aggregator_get_url(hex_url),
            Err(PublisherClientError::EndpointPathMismatch)
        ));
        // A 43-char segment with a non-base64url char ('+') is also rejected.
        let bad_alpha = "https://aggregator.walrus-testnet.walrus.space/v1/blobs/\
                         TjKHSEwJcAqzBaxGMmB0fYWcgYdxBUnMZRdnV7c+UEk";
        assert!(matches!(
            validate_aggregator_get_url(bad_alpha),
            Err(PublisherClientError::EndpointPathMismatch)
        ));
    }
}
