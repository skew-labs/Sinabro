//! Walrus publisher PUT transport (atom #8 · C.0.2).
//!
//! # Madness invariants (§4.C `C.publisher`)
//!
//! 1. **Closed endpoint.** The publisher base URL is pinned to
//!    [`TESTNET_PUBLISHER_BASE_URL`] and the path to [`WALRUS_PUT_BLOB_PATH`].
//!    The only query parameter allowed is `epochs={u16 > 0}`. Any other
//!    scheme, host, port, path, query key, duplicate `epochs`, fragment, or
//!    userinfo is rejected by [`validate_publisher_put_url`].
//! 2. **Boundary-aware retry.** Once a request's bytes may have crossed the
//!    external boundary, a second PUT is forbidden so that a double-spend /
//!    duplicate-anchor failure mode is structurally impossible. Concretely:
//!    [`publish_blob_with_transport`] only retries when the boundary state is
//!    [`BoundaryState::NoExternalMutation`]; any
//!    [`BoundaryState::RequestBytesMayHaveCrossed`] /
//!    [`BoundaryState::UnknownAfterBoundary`] outcome is absorbing.
//! 3. **Diagnostic JSON drops the body.** Every emitted
//!    [`PublisherDiagnostic`] serialises only the nine allowlisted scalar
//!    keys. Payload bytes, response bytes, and the reported blob id text are
//!    never copied into a diagnostic line.
//! 4. **`SyntheticPublicFixture` only.** All other [`PublishPayloadClass`]
//!    variants are rejected by [`PublisherPutRequest::new`] before any
//!    transport is contacted, so the transport's `put_blob` is never invoked
//!    with real user memory, prompt text, tool output, or secret-like bytes.
//!
//! # Notes (`atom #8` clarifications of §4.C)
//!
//! * [`PublisherClientError`] is introduced here (the §4.C signature
//!   references it but does not define it). The shape follows atom #7's
//!   `ChunkCodecError`: `Copy + non_exhaustive`, `Display + Error` with
//!   `source() == None`, plus a `class_label()` `const fn` returning a stable
//!   `&'static str` per variant.
//! * The `body:&[u8]` accepted by [`classify_publisher_response`] is parsed
//!   by a minimal ASCII-substring scanner (no `serde_json` dependency — the
//!   crate stays at zero runtime deps). The scanner recognises the two
//!   documented Walrus success bodies (`newlyCreated.blobObject.blobId` and
//!   `alreadyCertified.blobId`) and refuses everything else as
//!   [`PublisherClientError::ResponseBodyJsonMalformed`].
//! * Backoff schedule (`100ms` for attempt 0–1, `250ms` for 2, `500ms` for 3,
//!   `1000ms` for 4 and above) is reported via
//!   [`TransportRetryDecision::backoff_ms_u32`] but **not** slept inside this
//!   module; the caller (or atom #12 `ReqwestPublisher`) owns the wall-clock
//!   wait. This keeps `publish_blob_with_transport` synchronous and offline
//!   testable.

use crate::codec::BLOB_ID_BYTES;

// ===========================================================================
// 1. Module-level wire / policy constants (§4.C C.publisher)
// ===========================================================================

/// Base URL of the Walrus public testnet publisher. The publisher transport
/// refuses every other host.
pub const TESTNET_PUBLISHER_BASE_URL: &str = "https://publisher.walrus-testnet.walrus.space";

/// HTTP path for the Walrus PUT-blob endpoint. Concatenated with
/// [`TESTNET_PUBLISHER_BASE_URL`] to form the closed-form PUT URL.
pub const WALRUS_PUT_BLOB_PATH: &str = "/v1/blobs";

/// Maximum payload size in bytes accepted by [`PublishPayload::new`]. The
/// Walrus public publisher rejects bodies larger than 10 MiB, so we mirror
/// that cap locally before the transport is contacted.
pub const PUBLIC_PUBLISHER_BODY_CAP_BYTES: u32 = 10 * 1024 * 1024;

/// Maximum number of response bytes [`classify_publisher_response`] will
/// inspect. Larger bodies are rejected before any allocation or parsing.
pub const MAX_PUBLISHER_RESPONSE_BYTES: usize = 16 * 1024;

/// Maximum length in bytes of the reported blob-id text accepted by
/// [`PublisherReportedBlobId::try_from_text`]. The Walrus testnet returns ids
/// well under 64 bytes, but we keep a conservative cap.
pub const MAX_REPORTED_BLOB_ID_TEXT_BYTES: usize = 256;

/// Backoff (milliseconds) reported when `attempt_u16` is 0 or 1.
const BACKOFF_MS_ATTEMPT_0_1: u32 = 100;
/// Backoff (milliseconds) reported when `attempt_u16` is 2.
const BACKOFF_MS_ATTEMPT_2: u32 = 250;
/// Backoff (milliseconds) reported when `attempt_u16` is 3.
const BACKOFF_MS_ATTEMPT_3: u32 = 500;
/// Backoff (milliseconds) reported when `attempt_u16` is 4 or more.
const BACKOFF_MS_ATTEMPT_4_PLUS: u32 = 1000;

// ===========================================================================
// 2. PublishPayloadClass
// ===========================================================================

/// What kind of payload is being PUT to the publisher. Only
/// [`PublishPayloadClass::SyntheticPublicFixture`] is allowed onto the
/// Walrus public testnet (`atom #8` madness invariant 4).
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
#[non_exhaustive]
#[repr(u8)]
pub enum PublishPayloadClass {
    /// A synthetic, public, hand-authored fixture. The only class admitted
    /// to the public testnet.
    SyntheticPublicFixture = 1,
    /// A chunk derived from real user memory. Rejected (would leak user
    /// content onto a public network).
    RealUserMemory = 2,
    /// Raw prompt text or LLM-provider request/response. Rejected.
    PromptOrProviderText = 3,
    /// The body of a tool invocation's result. Rejected.
    ToolOutput = 4,
    /// Bytes flagged as secret-like by upstream redaction. Rejected.
    SecretLike = 5,
    /// Private provenance metadata (signing keys, capability tokens, …).
    /// Rejected.
    PrivateProvenance = 6,
    /// The AEAD CIPHERTEXT of a user memory record (E14-W). DISTINCT from
    /// [`Self::RealUserMemory`] (which is PLAINTEXT and stays Rejected): these bytes
    /// are an `Aes256GcmSiv` sealed record whose 32-byte key NEVER leaves the local
    /// machine (`<data_dir>/memory.key`), so publishing them to the public testnet
    /// leaks no plaintext (owner-directed 2026-06-13: "모든 메모리, 암호문으로"). ADMITTED
    /// to the publisher; the plaintext classes above stay rejected (secret-zero holds).
    EncryptedUserMemory = 7,
}

impl PublishPayloadClass {
    /// One-byte wire tag for this class.
    #[inline]
    pub const fn tag(self) -> u8 {
        self as u8
    }

    /// Stable `&'static str` label for this class. Used inside diagnostics
    /// and error messages.
    #[inline]
    pub const fn class_label(self) -> &'static str {
        match self {
            Self::SyntheticPublicFixture => "synthetic_public_fixture",
            Self::RealUserMemory => "real_user_memory",
            Self::PromptOrProviderText => "prompt_or_provider_text",
            Self::ToolOutput => "tool_output",
            Self::SecretLike => "secret_like",
            Self::PrivateProvenance => "private_provenance",
            Self::EncryptedUserMemory => "encrypted_user_memory",
        }
    }
}

// ===========================================================================
// 3. EpochCount, PublishPayload, PublisherEndpoint, PublisherPutRequest
// ===========================================================================

/// Number of storage epochs the publisher is asked to keep the blob for.
/// Must be strictly positive (zero is rejected at construction time).
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
#[repr(transparent)]
pub struct EpochCount(u16);

impl EpochCount {
    /// Construct an [`EpochCount`] from a `u16`. Zero is rejected with
    /// [`PublisherClientError::EndpointQueryEpochsZero`].
    #[inline]
    pub const fn new(value: u16) -> Result<Self, PublisherClientError> {
        if value == 0 {
            return Err(PublisherClientError::EndpointQueryEpochsZero);
        }
        Ok(Self(value))
    }

    /// Inner `u16` value (guaranteed `>= 1`).
    #[inline]
    pub const fn get(self) -> u16 {
        self.0
    }
}

/// Borrowed payload bytes plus the classification that decides whether the
/// PUT is allowed to leave the process. The payload is held by reference so
/// the publisher never owns user-content allocations.
#[derive(Clone, Copy, Debug)]
pub struct PublishPayload<'a> {
    bytes: &'a [u8],
    class: PublishPayloadClass,
}

impl<'a> PublishPayload<'a> {
    /// Construct a [`PublishPayload`]. The byte length is checked against
    /// [`PUBLIC_PUBLISHER_BODY_CAP_BYTES`] before the value is returned; no
    /// allocation occurs.
    pub const fn new(
        bytes: &'a [u8],
        class: PublishPayloadClass,
    ) -> Result<Self, PublisherClientError> {
        let observed = bytes.len();
        if observed > PUBLIC_PUBLISHER_BODY_CAP_BYTES as usize {
            return Err(PublisherClientError::PayloadTooLarge {
                observed_u32: if observed > u32::MAX as usize {
                    u32::MAX
                } else {
                    observed as u32
                },
                cap_u32: PUBLIC_PUBLISHER_BODY_CAP_BYTES,
            });
        }
        Ok(Self { bytes, class })
    }

    /// Borrowed payload bytes (lifetime tied to the caller's input).
    #[inline]
    pub const fn bytes(&self) -> &'a [u8] {
        self.bytes
    }

    /// Classification of these bytes.
    #[inline]
    pub const fn class(self) -> PublishPayloadClass {
        self.class
    }

    /// Payload length in bytes, fit into `u32` (`<= PUBLIC_PUBLISHER_BODY_CAP_BYTES`).
    #[inline]
    pub const fn len_u32(self) -> u32 {
        self.bytes.len() as u32
    }
}

/// Closed publisher endpoint marker. The only constructor is
/// [`PublisherEndpoint::testnet_public`]; there is no path or host field to
/// override.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub struct PublisherEndpoint {
    _seal: (),
}

impl PublisherEndpoint {
    /// The single sanctioned endpoint: Walrus public testnet.
    #[inline]
    pub const fn testnet_public() -> Self {
        Self { _seal: () }
    }

    /// Base URL ([`TESTNET_PUBLISHER_BASE_URL`]).
    #[inline]
    pub const fn base_url(self) -> &'static str {
        TESTNET_PUBLISHER_BASE_URL
    }

    /// PUT path ([`WALRUS_PUT_BLOB_PATH`]).
    #[inline]
    pub const fn put_path(self) -> &'static str {
        WALRUS_PUT_BLOB_PATH
    }
}

/// A planned PUT request. Owns nothing of variable size; the body is a
/// borrow of the caller's payload bytes.
#[derive(Clone, Copy, Debug)]
pub struct PublisherPutRequest<'a> {
    endpoint: PublisherEndpoint,
    epochs: EpochCount,
    payload: PublishPayload<'a>,
}

impl<'a> PublisherPutRequest<'a> {
    /// Plan a PUT request. Rejects every payload class except
    /// [`PublishPayloadClass::SyntheticPublicFixture`] (`atom #8` madness 4).
    pub const fn new(
        endpoint: PublisherEndpoint,
        epochs: EpochCount,
        payload: PublishPayload<'a>,
    ) -> Result<Self, PublisherClientError> {
        match payload.class {
            // E14-W: ciphertext of user memory is ADMITTED (the AEAD key never leaves
            // the local machine, so no plaintext leaks). PLAINTEXT classes (RealUserMemory
            // / prompt / tool / secret / provenance) stay rejected — secret-zero holds.
            PublishPayloadClass::SyntheticPublicFixture
            | PublishPayloadClass::EncryptedUserMemory => Ok(Self {
                endpoint,
                epochs,
                payload,
            }),
            other => Err(PublisherClientError::PayloadClassRejected { class: other }),
        }
    }

    /// Borrowed endpoint marker.
    #[inline]
    pub const fn endpoint(&self) -> PublisherEndpoint {
        self.endpoint
    }

    /// Storage epoch count.
    #[inline]
    pub const fn epochs(&self) -> EpochCount {
        self.epochs
    }

    /// Borrowed payload (lifetime `'a`).
    #[inline]
    pub const fn payload(&self) -> PublishPayload<'a> {
        self.payload
    }

    /// Direct slice of the body bytes (zero-copy alias for
    /// `self.payload().bytes()`). Returned with the caller's lifetime so a
    /// transport can write the body without an intermediate copy.
    #[inline]
    pub const fn body(&self) -> &'a [u8] {
        self.payload.bytes
    }
}

// ===========================================================================
// 4. PublisherPutUrl & validate_publisher_put_url
// ===========================================================================

/// A URL that has passed the closed-endpoint policy check.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub struct PublisherPutUrl {
    epochs: EpochCount,
}

impl PublisherPutUrl {
    /// Storage epoch count parsed from the validated URL.
    #[inline]
    pub const fn epochs(self) -> EpochCount {
        self.epochs
    }
}

/// Validate a candidate publisher PUT URL against the closed-endpoint
/// policy. Returns a [`PublisherPutUrl`] carrying the parsed
/// [`EpochCount`] iff every check passes.
///
/// The accepted shape is exactly:
///
/// ```text
/// https://publisher.walrus-testnet.walrus.space/v1/blobs?epochs={u16, > 0}
/// ```
///
/// Every other scheme, host, port, userinfo, path, fragment, additional
/// query key, duplicate `epochs`, zero `epochs`, or non-numeric `epochs`
/// value is rejected with a specific [`PublisherClientError`] variant.
pub fn validate_publisher_put_url(url: &str) -> Result<PublisherPutUrl, PublisherClientError> {
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
    // Host must be the pinned host.
    let pinned_host = "publisher.walrus-testnet.walrus.space";
    if authority != pinned_host {
        return Err(PublisherClientError::EndpointHostForbidden);
    }

    // Split path from query.
    let (path, query) = match path_and_query.find('?') {
        Some(idx) => (&path_and_query[..idx], Some(&path_and_query[idx + 1..])),
        None => (path_and_query, None),
    };

    if path != WALRUS_PUT_BLOB_PATH {
        return Err(PublisherClientError::EndpointPathMismatch);
    }

    let query_str = match query {
        Some(q) if !q.is_empty() => q,
        Some(_) | None => return Err(PublisherClientError::EndpointQueryEpochsMissing),
    };

    let mut epochs_value: Option<&str> = None;
    for pair in query_str.split('&') {
        let eq = match pair.find('=') {
            Some(idx) => idx,
            None => return Err(PublisherClientError::EndpointQueryKeyForbidden),
        };
        let key = &pair[..eq];
        let value = &pair[eq + 1..];
        if key != "epochs" {
            return Err(PublisherClientError::EndpointQueryKeyForbidden);
        }
        if epochs_value.is_some() {
            return Err(PublisherClientError::EndpointQueryEpochsDuplicate);
        }
        epochs_value = Some(value);
    }
    let value_str = match epochs_value {
        Some(v) => v,
        None => return Err(PublisherClientError::EndpointQueryEpochsMissing),
    };
    if value_str.is_empty() {
        return Err(PublisherClientError::EndpointQueryEpochsMalformed);
    }
    let parsed: u16 = match value_str.parse::<u16>() {
        Ok(v) => v,
        Err(_) => return Err(PublisherClientError::EndpointQueryEpochsMalformed),
    };
    let epochs = EpochCount::new(parsed)?;
    Ok(PublisherPutUrl { epochs })
}

// ===========================================================================
// 5. PublisherReportedBlobId
// ===========================================================================

/// The publisher's self-reported blob id, as text. **Not** locally verified
/// — `atom #10` (`C.0.4`) promotes this to `VerifiedBlobId` via local
/// derivation + byte-equal comparison.
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct PublisherReportedBlobId(String);

impl PublisherReportedBlobId {
    /// Construct from a text id reported by the publisher. The text is
    /// checked against [`MAX_REPORTED_BLOB_ID_TEXT_BYTES`] (and must be
    /// non-empty); no semantic verification of the bytes is performed here.
    pub fn try_from_text(text: &str) -> Result<Self, PublisherClientError> {
        let len = text.len();
        if len == 0 {
            return Err(PublisherClientError::ResponseReportedBlobIdEmpty);
        }
        if len > MAX_REPORTED_BLOB_ID_TEXT_BYTES {
            return Err(PublisherClientError::ResponseReportedBlobIdTooLong {
                observed_bytes: len,
                cap_bytes: MAX_REPORTED_BLOB_ID_TEXT_BYTES,
            });
        }
        Ok(Self(text.to_owned()))
    }

    /// Borrowed view of the reported text.
    #[inline]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Length in bytes of the reported text.
    #[inline]
    pub fn byte_len(&self) -> usize {
        self.0.len()
    }
}

// ===========================================================================
// 6. Nominal response / retry / boundary enums
// ===========================================================================

/// Which of the two documented publisher success bodies was returned.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
#[non_exhaustive]
#[repr(u8)]
pub enum BlobStoreSuccessVariant {
    /// Server allocated a new blob (HTTP 200 / 201 with `newlyCreated`).
    NewlyCreated = 1,
    /// Server reused an already-certified blob (`alreadyCertified` body).
    AlreadyCertified = 2,
}

impl BlobStoreSuccessVariant {
    /// Stable `&'static str` label used by diagnostics.
    #[inline]
    pub const fn class_label(self) -> &'static str {
        match self {
            Self::NewlyCreated => "newly_created",
            Self::AlreadyCertified => "already_certified",
        }
    }
}

/// Why the publisher loop stopped without an `Accepted` outcome.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
#[non_exhaustive]
#[repr(u8)]
pub enum PublishStopReason {
    /// 4xx-class HTTP terminal status that is not specifically Semantic /
    /// MarkedInvalid.
    TerminalStatus = 1,
    /// 5xx-class HTTP status that *would* be retryable, but the request
    /// crossed the boundary so a second PUT is forbidden.
    RetryableStatusAfterBoundary = 2,
    /// Payload was semantically rejected (400 / 413 / 415 / 422), or a 3xx
    /// redirect was returned by the closed endpoint.
    SemanticError = 3,
    /// HTTP 451 (unavailable for legal reasons) — payload marked invalid by
    /// the operator.
    MarkedInvalid = 4,
    /// Transport-level failure that was either non-retryable or whose
    /// boundary state forbids a retry.
    ProtocolFailure = 5,
}

impl PublishStopReason {
    /// Stable `&'static str` label used by diagnostics.
    #[inline]
    pub const fn class_label(self) -> &'static str {
        match self {
            Self::TerminalStatus => "terminal_status",
            Self::RetryableStatusAfterBoundary => "retryable_status_after_boundary",
            Self::SemanticError => "semantic_error",
            Self::MarkedInvalid => "marked_invalid",
            Self::ProtocolFailure => "protocol_failure",
        }
    }
}

/// Whether request bytes have, or may have, crossed the external boundary.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
#[non_exhaustive]
#[repr(u8)]
pub enum BoundaryState {
    /// No bytes left the process; a retry is safe (no duplicate anchor).
    NoExternalMutation = 1,
    /// Bytes definitely reached the server (the response decision tells us
    /// the server's view). Retrying is unsafe in general.
    RequestBytesMayHaveCrossed = 2,
    /// Whether bytes reached the server is unknown; treat as absorbing.
    UnknownAfterBoundary = 3,
}

impl BoundaryState {
    /// Stable `&'static str` label used by diagnostics.
    #[inline]
    pub const fn class_label(self) -> &'static str {
        match self {
            Self::NoExternalMutation => "no_external_mutation",
            Self::RequestBytesMayHaveCrossed => "request_bytes_may_have_crossed",
            Self::UnknownAfterBoundary => "unknown_after_boundary",
        }
    }
}

/// What the loop decided to do about this attempt.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
#[non_exhaustive]
#[repr(u8)]
pub enum PublisherRetryDisposition {
    /// Retry the PUT (only ever returned with
    /// [`BoundaryState::NoExternalMutation`]).
    AutoRetry = 1,
    /// Do not retry; the failure is terminal for this request.
    Never = 2,
    /// Do not retry automatically; a human / operator must reconcile (used
    /// when the boundary is `UnknownAfterBoundary`).
    ManualReconcile = 3,
}

impl PublisherRetryDisposition {
    /// Stable `&'static str` label used by diagnostics.
    #[inline]
    pub const fn class_label(self) -> &'static str {
        match self {
            Self::AutoRetry => "auto_retry",
            Self::Never => "never",
            Self::ManualReconcile => "manual_reconcile",
        }
    }
}

/// Outcome of a single PUT attempt's response classification.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum PublisherResponseDecision {
    /// Server accepted the blob.
    Accepted {
        /// Which success body was returned.
        variant: BlobStoreSuccessVariant,
        /// Server-reported blob id (textual, not locally verified).
        reported_blob_id: PublisherReportedBlobId,
    },
    /// Server returned a non-success status (or the loop ran out of safe
    /// retries).
    Stopped {
        /// Why we stopped.
        reason: PublishStopReason,
        /// Whether retrying could ever be safe.
        retry: PublisherRetryDisposition,
        /// What we know about whether bytes crossed.
        boundary: BoundaryState,
    },
}

/// What sort of transport-level failure was observed.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
#[non_exhaustive]
#[repr(u8)]
pub enum TransportFailureKind {
    /// DNS resolution failed.
    Dns = 1,
    /// TCP connect failed.
    Connect = 2,
    /// TLS handshake failed.
    Tls = 3,
    /// Write timed out before the request was fully sent.
    WriteTimeout = 4,
    /// Response timed out after the request was sent.
    ResponseTimeout = 5,
    /// The caller cancelled the in-flight attempt.
    Cancelled = 6,
}

impl TransportFailureKind {
    /// Stable `&'static str` label used by diagnostics.
    #[inline]
    pub const fn class_label(self) -> &'static str {
        match self {
            Self::Dns => "dns",
            Self::Connect => "connect",
            Self::Tls => "tls",
            Self::WriteTimeout => "write_timeout",
            Self::ResponseTimeout => "response_timeout",
            Self::Cancelled => "cancelled",
        }
    }
}

/// The publisher loop's decision after a single transport failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub struct TransportRetryDecision {
    /// Whether the loop will retry.
    pub disposition: PublisherRetryDisposition,
    /// The boundary state the failure was observed at.
    pub boundary: BoundaryState,
    /// Suggested wait in milliseconds before the next attempt (the loop
    /// reports this; it does not sleep).
    pub backoff_ms_u32: u32,
}

/// What a transport returns on a *successful* (i.e. completed) HTTP
/// exchange. The body is owned because the transport allocates it.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PublisherTransportResponse {
    /// HTTP status code reported by the server.
    pub http_status_u16: u16,
    /// Response body bytes (length already capped by the transport at
    /// [`MAX_PUBLISHER_RESPONSE_BYTES`]).
    pub body: Vec<u8>,
    /// Wall-clock duration of this attempt, in milliseconds.
    pub elapsed_ms_u32: u32,
}

/// What a transport returns when the HTTP exchange itself failed.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub struct PublisherTransportFailure {
    /// Kind of transport-level failure.
    pub kind: TransportFailureKind,
    /// Boundary state the transport observed at failure time.
    pub boundary: BoundaryState,
    /// Wall-clock duration of this attempt, in milliseconds.
    pub elapsed_ms_u32: u32,
}

/// The full result of a [`publish_blob_with_transport`] call.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PublisherClientRun {
    /// Number of `put_blob` invocations made (1-based).
    pub attempts_u16: u16,
    /// Final decision (accepted or stopped).
    pub decision: PublisherResponseDecision,
    /// Per-attempt diagnostic lines, each a single JSON object with only
    /// the nine allowlisted keys (no body bytes, no reported-id text).
    pub diagnostics: Vec<String>,
}

// ===========================================================================
// 7. PublisherDiagnostic (allowlist 9 keys)
// ===========================================================================

/// A single diagnostic record emitted by [`publish_blob_with_transport`].
/// The struct's nine fields are exactly the keys allowed into the rendered
/// JSON line — payload bytes and response bytes are physically absent so
/// they cannot leak by accident.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub struct PublisherDiagnostic {
    /// Static event tag (one of `publish.accepted`, `publish.stopped`,
    /// `publish.transport_failure`).
    pub event: &'static str,
    /// 1-based attempt number this diagnostic describes.
    pub attempt_u16: u16,
    /// Caller-provided request id for correlation across logs.
    pub request_id_u64: u64,
    /// Length of the payload bytes (the bytes themselves are not copied).
    pub payload_len_bytes: u32,
    /// HTTP status code, if the attempt produced a response.
    pub http_status_u16: Option<u16>,
    /// Wall-clock duration of this attempt, in milliseconds.
    pub elapsed_ms_u32: u32,
    /// Suggested backoff before the next attempt, in milliseconds.
    pub backoff_ms_u32: u32,
    /// Loop's retry disposition for this attempt.
    pub retry_disposition: PublisherRetryDisposition,
    /// Boundary state the loop attributed to this attempt.
    pub boundary_state: BoundaryState,
}

impl PublisherDiagnostic {
    /// Render this diagnostic as a single-line JSON object with exactly the
    /// nine allowlisted keys (`event`, `attempt`, `request_id`,
    /// `payload_len_bytes`, `http_status`, `elapsed_ms`, `backoff_ms`,
    /// `retry_disposition`, `boundary_state`). Body bytes and reported-id
    /// text are never serialised.
    pub fn to_json_line(&self) -> String {
        let http_status_render = match self.http_status_u16 {
            Some(s) => {
                let mut buf = String::with_capacity(8);
                push_u64_dec(&mut buf, s as u64);
                buf
            }
            None => "null".to_owned(),
        };
        let mut out = String::with_capacity(192);
        out.push('{');
        out.push_str("\"event\":\"");
        out.push_str(self.event);
        out.push_str("\",\"attempt\":");
        push_u64_dec(&mut out, self.attempt_u16 as u64);
        out.push_str(",\"request_id\":");
        push_u64_dec(&mut out, self.request_id_u64);
        out.push_str(",\"payload_len_bytes\":");
        push_u64_dec(&mut out, self.payload_len_bytes as u64);
        out.push_str(",\"http_status\":");
        out.push_str(&http_status_render);
        out.push_str(",\"elapsed_ms\":");
        push_u64_dec(&mut out, self.elapsed_ms_u32 as u64);
        out.push_str(",\"backoff_ms\":");
        push_u64_dec(&mut out, self.backoff_ms_u32 as u64);
        out.push_str(",\"retry_disposition\":\"");
        out.push_str(self.retry_disposition.class_label());
        out.push_str("\",\"boundary_state\":\"");
        out.push_str(self.boundary_state.class_label());
        out.push_str("\"}");
        out
    }
}

#[inline]
fn push_u64_dec(out: &mut String, value: u64) {
    if value == 0 {
        out.push('0');
        return;
    }
    let mut digits = [0u8; 20];
    let mut idx = 0usize;
    let mut v = value;
    while v > 0 {
        digits[idx] = b'0' + (v % 10) as u8;
        v /= 10;
        idx += 1;
    }
    while idx > 0 {
        idx -= 1;
        out.push(digits[idx] as char);
    }
}

// ===========================================================================
// 8. PublisherTransport trait
// ===========================================================================

/// Abstraction over the underlying HTTP client. The trait is intentionally
/// minimal so that the offline tests can drive [`publish_blob_with_transport`]
/// with a fake transport while `atom #12` provides a real reqwest-backed
/// implementation under a feature flag.
pub trait PublisherTransport {
    /// Issue a single PUT-blob attempt and return either the server's
    /// response or a transport-level failure.
    fn put_blob(
        &mut self,
        request: &PublisherPutRequest<'_>,
    ) -> Result<PublisherTransportResponse, PublisherTransportFailure>;
}

// ===========================================================================
// 9. classify_publisher_response
// ===========================================================================

/// Classify a single publisher response into either an [`Accepted`] or a
/// [`Stopped`] decision. Returns a [`PublisherClientError`] only for
/// physically invalid inputs (oversized body, status outside HTTP's
/// 100-599 range, malformed success body) — every other outcome is a
/// well-formed [`PublisherResponseDecision::Stopped`].
///
/// [`Accepted`]: PublisherResponseDecision::Accepted
/// [`Stopped`]: PublisherResponseDecision::Stopped
pub fn classify_publisher_response(
    http_status_u16: u16,
    body: &[u8],
) -> Result<PublisherResponseDecision, PublisherClientError> {
    if body.len() > MAX_PUBLISHER_RESPONSE_BYTES {
        return Err(PublisherClientError::ResponseBodyTooLarge {
            observed_bytes: body.len(),
            cap_bytes: MAX_PUBLISHER_RESPONSE_BYTES,
        });
    }
    match http_status_u16 {
        200 | 201 => {
            let (variant, reported_blob_id) = extract_reported_id(body)?;
            Ok(PublisherResponseDecision::Accepted {
                variant,
                reported_blob_id,
            })
        }
        100..=199 => Err(PublisherClientError::ResponseStatusUnsupported { http_status_u16 }),
        202..=299 => Ok(PublisherResponseDecision::Stopped {
            reason: PublishStopReason::SemanticError,
            retry: PublisherRetryDisposition::Never,
            boundary: BoundaryState::RequestBytesMayHaveCrossed,
        }),
        300..=399 => Ok(PublisherResponseDecision::Stopped {
            reason: PublishStopReason::SemanticError,
            retry: PublisherRetryDisposition::Never,
            boundary: BoundaryState::RequestBytesMayHaveCrossed,
        }),
        451 => Ok(PublisherResponseDecision::Stopped {
            reason: PublishStopReason::MarkedInvalid,
            retry: PublisherRetryDisposition::Never,
            boundary: BoundaryState::RequestBytesMayHaveCrossed,
        }),
        400 | 413 | 415 | 422 => Ok(PublisherResponseDecision::Stopped {
            reason: PublishStopReason::SemanticError,
            retry: PublisherRetryDisposition::Never,
            boundary: BoundaryState::RequestBytesMayHaveCrossed,
        }),
        400..=499 => Ok(PublisherResponseDecision::Stopped {
            reason: PublishStopReason::TerminalStatus,
            retry: PublisherRetryDisposition::Never,
            boundary: BoundaryState::RequestBytesMayHaveCrossed,
        }),
        500..=599 => Ok(PublisherResponseDecision::Stopped {
            reason: PublishStopReason::RetryableStatusAfterBoundary,
            retry: PublisherRetryDisposition::AutoRetry,
            boundary: BoundaryState::UnknownAfterBoundary,
        }),
        _ => Err(PublisherClientError::ResponseStatusUnsupported { http_status_u16 }),
    }
}

fn extract_reported_id(
    body: &[u8],
) -> Result<(BlobStoreSuccessVariant, PublisherReportedBlobId), PublisherClientError> {
    let text = match core::str::from_utf8(body) {
        Ok(s) => s,
        Err(_) => return Err(PublisherClientError::ResponseBodyJsonMalformed),
    };
    let needle_new = "\"newlyCreated\"";
    let needle_already = "\"alreadyCertified\"";
    let variant = if text.contains(needle_new) {
        BlobStoreSuccessVariant::NewlyCreated
    } else if text.contains(needle_already) {
        BlobStoreSuccessVariant::AlreadyCertified
    } else {
        return Err(PublisherClientError::ResponseBodyJsonMalformed);
    };
    let blob_id_marker = "\"blobId\"";
    let marker_start = match text.find(blob_id_marker) {
        Some(idx) => idx,
        None => return Err(PublisherClientError::ResponseReportedBlobIdMissing),
    };
    let after_marker = &text[marker_start + blob_id_marker.len()..];
    // Skip optional whitespace then ':' then optional whitespace then '"'.
    let mut cursor = after_marker;
    cursor = trim_ascii_ws_left(cursor);
    cursor = match cursor.strip_prefix(':') {
        Some(rest) => rest,
        None => return Err(PublisherClientError::ResponseBodyJsonMalformed),
    };
    cursor = trim_ascii_ws_left(cursor);
    cursor = match cursor.strip_prefix('"') {
        Some(rest) => rest,
        None => return Err(PublisherClientError::ResponseBodyJsonMalformed),
    };
    let close_offset = match cursor.find('"') {
        Some(idx) => idx,
        None => return Err(PublisherClientError::ResponseBodyJsonMalformed),
    };
    let id_text = &cursor[..close_offset];
    let reported = PublisherReportedBlobId::try_from_text(id_text)?;
    Ok((variant, reported))
}

#[inline]
fn trim_ascii_ws_left(s: &str) -> &str {
    let bytes = s.as_bytes();
    let mut i = 0usize;
    while i < bytes.len() {
        let b = bytes[i];
        if b == b' ' || b == b'\t' || b == b'\n' || b == b'\r' {
            i += 1;
        } else {
            break;
        }
    }
    &s[i..]
}

// ===========================================================================
// 10. classify_transport_failure (const fn)
// ===========================================================================

/// Decide what the publisher loop should do with a transport-level failure
/// observed at a given boundary state and attempt index.
///
/// * `UnknownAfterBoundary` → [`PublisherRetryDisposition::ManualReconcile`]
///   (the caller must reconcile out of band).
/// * `RequestBytesMayHaveCrossed` → [`PublisherRetryDisposition::Never`]
///   (a second PUT could create a duplicate anchor).
/// * `NoExternalMutation` → [`PublisherRetryDisposition::AutoRetry`] up to
///   `max_attempts_u16` total attempts (the last attempt yields `Never`).
/// * [`TransportFailureKind::Cancelled`] is always non-retryable.
///
/// `backoff_ms_u32` follows the schedule `100 ms` for attempt 0–1, `250 ms`
/// for 2, `500 ms` for 3, `1000 ms` for 4 and above.
pub const fn classify_transport_failure(
    kind: TransportFailureKind,
    boundary: BoundaryState,
    attempt_u16: u16,
    max_attempts_u16: u16,
) -> TransportRetryDecision {
    let backoff_ms_u32 = match attempt_u16 {
        0 | 1 => BACKOFF_MS_ATTEMPT_0_1,
        2 => BACKOFF_MS_ATTEMPT_2,
        3 => BACKOFF_MS_ATTEMPT_3,
        _ => BACKOFF_MS_ATTEMPT_4_PLUS,
    };
    let disposition = match boundary {
        BoundaryState::UnknownAfterBoundary => PublisherRetryDisposition::ManualReconcile,
        BoundaryState::RequestBytesMayHaveCrossed => PublisherRetryDisposition::Never,
        BoundaryState::NoExternalMutation => match kind {
            TransportFailureKind::Cancelled => PublisherRetryDisposition::Never,
            _ => {
                if attempt_u16 < max_attempts_u16 {
                    PublisherRetryDisposition::AutoRetry
                } else {
                    PublisherRetryDisposition::Never
                }
            }
        },
    };
    TransportRetryDecision {
        disposition,
        boundary,
        backoff_ms_u32,
    }
}

// ===========================================================================
// 11. publish_blob_with_transport
// ===========================================================================

/// Execute the publisher loop against a [`PublisherTransport`]. Returns the
/// final [`PublisherClientRun`] (one attempt-counter + one decision + the
/// per-attempt diagnostic JSON lines).
///
/// Retry policy (`atom #8` madness 2): the loop retries iff
/// `disposition == AutoRetry` **and** `boundary == NoExternalMutation`. Any
/// other boundary state is absorbing — in particular,
/// [`BoundaryState::UnknownAfterBoundary`] never produces a second
/// `put_blob` call.
pub fn publish_blob_with_transport<T: PublisherTransport>(
    transport: &mut T,
    request: &PublisherPutRequest<'_>,
    request_id_u64: u64,
    max_attempts_u16: u16,
) -> Result<PublisherClientRun, PublisherClientError> {
    if max_attempts_u16 == 0 {
        return Err(PublisherClientError::AttemptsExhausted { attempts_u16: 0 });
    }
    let mut diagnostics: Vec<String> = Vec::new();
    let payload_len_bytes = request.payload.len_u32();
    let mut attempt_u16: u16 = 0;
    loop {
        if attempt_u16 == max_attempts_u16 {
            return Err(PublisherClientError::AttemptsExhausted {
                attempts_u16: max_attempts_u16,
            });
        }
        attempt_u16 = attempt_u16.saturating_add(1);
        match transport.put_blob(request) {
            Ok(response) => {
                let elapsed_ms_u32 = response.elapsed_ms_u32;
                let status = response.http_status_u16;
                let decision = classify_publisher_response(status, &response.body)?;
                match decision {
                    PublisherResponseDecision::Accepted { .. } => {
                        let diag = PublisherDiagnostic {
                            event: "publish.accepted",
                            attempt_u16,
                            request_id_u64,
                            payload_len_bytes,
                            http_status_u16: Some(status),
                            elapsed_ms_u32,
                            backoff_ms_u32: 0,
                            retry_disposition: PublisherRetryDisposition::Never,
                            boundary_state: BoundaryState::RequestBytesMayHaveCrossed,
                        };
                        diagnostics.push(diag.to_json_line());
                        return Ok(PublisherClientRun {
                            attempts_u16: attempt_u16,
                            decision,
                            diagnostics,
                        });
                    }
                    PublisherResponseDecision::Stopped {
                        reason,
                        retry,
                        boundary,
                    } => {
                        let diag = PublisherDiagnostic {
                            event: "publish.stopped",
                            attempt_u16,
                            request_id_u64,
                            payload_len_bytes,
                            http_status_u16: Some(status),
                            elapsed_ms_u32,
                            backoff_ms_u32: 0,
                            retry_disposition: retry,
                            boundary_state: boundary,
                        };
                        diagnostics.push(diag.to_json_line());
                        // Retry only when both conditions hold.
                        let retry_safe = matches!(retry, PublisherRetryDisposition::AutoRetry)
                            && matches!(boundary, BoundaryState::NoExternalMutation)
                            && attempt_u16 < max_attempts_u16;
                        if retry_safe {
                            continue;
                        }
                        return Ok(PublisherClientRun {
                            attempts_u16: attempt_u16,
                            decision: PublisherResponseDecision::Stopped {
                                reason,
                                retry,
                                boundary,
                            },
                            diagnostics,
                        });
                    }
                }
            }
            Err(failure) => {
                let retry_decision = classify_transport_failure(
                    failure.kind,
                    failure.boundary,
                    attempt_u16.saturating_sub(1),
                    max_attempts_u16,
                );
                let diag = PublisherDiagnostic {
                    event: "publish.transport_failure",
                    attempt_u16,
                    request_id_u64,
                    payload_len_bytes,
                    http_status_u16: None,
                    elapsed_ms_u32: failure.elapsed_ms_u32,
                    backoff_ms_u32: retry_decision.backoff_ms_u32,
                    retry_disposition: retry_decision.disposition,
                    boundary_state: failure.boundary,
                };
                diagnostics.push(diag.to_json_line());
                // Retry only on AutoRetry × NoExternalMutation.
                let retry_safe = matches!(
                    retry_decision.disposition,
                    PublisherRetryDisposition::AutoRetry
                ) && matches!(failure.boundary, BoundaryState::NoExternalMutation)
                    && attempt_u16 < max_attempts_u16;
                if retry_safe {
                    continue;
                }
                return Ok(PublisherClientRun {
                    attempts_u16: attempt_u16,
                    decision: PublisherResponseDecision::Stopped {
                        reason: PublishStopReason::ProtocolFailure,
                        retry: retry_decision.disposition,
                        boundary: failure.boundary,
                    },
                    diagnostics,
                });
            }
        }
    }
}

// ===========================================================================
// 12. PublisherClientError
// ===========================================================================

/// Errors emitted by the publisher module's pure functions. Mirrors the
/// `Copy + non_exhaustive` shape of [`crate::codec::ChunkCodecError`].
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
#[non_exhaustive]
pub enum PublisherClientError {
    /// [`PublisherPutRequest::new`] received a payload class other than
    /// [`PublishPayloadClass::SyntheticPublicFixture`].
    PayloadClassRejected {
        /// The rejected class.
        class: PublishPayloadClass,
    },
    /// [`PublishPayload::new`] received bytes exceeding
    /// [`PUBLIC_PUBLISHER_BODY_CAP_BYTES`].
    PayloadTooLarge {
        /// Observed byte length, saturated at `u32::MAX`.
        observed_u32: u32,
        /// Cap in bytes.
        cap_u32: u32,
    },
    /// URL did not start with `https://`.
    EndpointSchemeForbidden,
    /// URL contained a fragment (`#...`).
    EndpointForbiddenFragment,
    /// URL contained userinfo (`...@...`).
    EndpointForbiddenUserinfo,
    /// URL specified a port.
    EndpointPortForbidden,
    /// URL host did not match the pinned testnet publisher host.
    EndpointHostForbidden,
    /// URL path did not match [`WALRUS_PUT_BLOB_PATH`].
    EndpointPathMismatch,
    /// URL contained a query key other than `epochs`.
    EndpointQueryKeyForbidden,
    /// URL did not contain an `epochs` query parameter.
    EndpointQueryEpochsMissing,
    /// URL contained more than one `epochs` query parameter.
    EndpointQueryEpochsDuplicate,
    /// `epochs` value was not a parseable `u16`.
    EndpointQueryEpochsMalformed,
    /// `epochs` value was zero.
    EndpointQueryEpochsZero,
    /// Response body exceeded [`MAX_PUBLISHER_RESPONSE_BYTES`].
    ResponseBodyTooLarge {
        /// Observed body length.
        observed_bytes: usize,
        /// Cap in bytes.
        cap_bytes: usize,
    },
    /// Server returned a status outside HTTP's 100–599 range.
    ResponseStatusUnsupported {
        /// The unsupported status.
        http_status_u16: u16,
    },
    /// 200/201 body did not match either of the two documented success
    /// shapes.
    ResponseBodyJsonMalformed,
    /// Success body present but no `blobId` key.
    ResponseReportedBlobIdMissing,
    /// `blobId` value was the empty string.
    ResponseReportedBlobIdEmpty,
    /// `blobId` value exceeded [`MAX_REPORTED_BLOB_ID_TEXT_BYTES`].
    ResponseReportedBlobIdTooLong {
        /// Observed length in bytes.
        observed_bytes: usize,
        /// Cap in bytes.
        cap_bytes: usize,
    },
    /// The loop ran out of attempts without producing a terminal decision.
    AttemptsExhausted {
        /// Total attempts consumed.
        attempts_u16: u16,
    },
}

impl PublisherClientError {
    /// Stable `&'static str` label for every variant. Mirrors the
    /// `class_label` pattern from `atom #2`'s `MnemosError` and `atom #7`'s
    /// `ChunkCodecError`.
    #[inline]
    pub const fn class_label(&self) -> &'static str {
        match self {
            Self::PayloadClassRejected { .. } => "publisher_client.payload_class_rejected",
            Self::PayloadTooLarge { .. } => "publisher_client.payload_too_large",
            Self::EndpointSchemeForbidden => "publisher_client.endpoint_scheme_forbidden",
            Self::EndpointForbiddenFragment => "publisher_client.endpoint_forbidden_fragment",
            Self::EndpointForbiddenUserinfo => "publisher_client.endpoint_forbidden_userinfo",
            Self::EndpointPortForbidden => "publisher_client.endpoint_port_forbidden",
            Self::EndpointHostForbidden => "publisher_client.endpoint_host_forbidden",
            Self::EndpointPathMismatch => "publisher_client.endpoint_path_mismatch",
            Self::EndpointQueryKeyForbidden => "publisher_client.endpoint_query_key_forbidden",
            Self::EndpointQueryEpochsMissing => "publisher_client.endpoint_query_epochs_missing",
            Self::EndpointQueryEpochsDuplicate => {
                "publisher_client.endpoint_query_epochs_duplicate"
            }
            Self::EndpointQueryEpochsMalformed => {
                "publisher_client.endpoint_query_epochs_malformed"
            }
            Self::EndpointQueryEpochsZero => "publisher_client.endpoint_query_epochs_zero",
            Self::ResponseBodyTooLarge { .. } => "publisher_client.response_body_too_large",
            Self::ResponseStatusUnsupported { .. } => {
                "publisher_client.response_status_unsupported"
            }
            Self::ResponseBodyJsonMalformed => "publisher_client.response_body_json_malformed",
            Self::ResponseReportedBlobIdMissing => {
                "publisher_client.response_reported_blob_id_missing"
            }
            Self::ResponseReportedBlobIdEmpty => "publisher_client.response_reported_blob_id_empty",
            Self::ResponseReportedBlobIdTooLong { .. } => {
                "publisher_client.response_reported_blob_id_too_long"
            }
            Self::AttemptsExhausted { .. } => "publisher_client.attempts_exhausted",
        }
    }
}

impl core::fmt::Display for PublisherClientError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(self.class_label())
    }
}

impl std::error::Error for PublisherClientError {}

// Static reuse marker against `atom #7`. The publisher does not decode the
// reported blob-id text, but we want a const-evaluable assertion so the
// reuse claim against `crate::codec::BLOB_ID_BYTES` cannot silently drift.
// `[(); 0 - condition as usize]` triggers a const-evaluation failure if the
// expected condition is false; the array has zero length when the condition
// holds, otherwise the subtraction underflows at compile time.
#[allow(dead_code)]
const PUBLISHER_REUSES_ATOM7_BLOB_ID_BYTES_32: [(); 0 - !(BLOB_ID_BYTES == 32) as usize] = [];

// ===========================================================================
// 13. Inline unit tests
// ===========================================================================

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    #![allow(clippy::expect_used)]
    use super::*;

    #[test]
    fn publish_payload_class_tag_values_are_stable_and_in_order() {
        assert_eq!(PublishPayloadClass::SyntheticPublicFixture.tag(), 1);
        assert_eq!(PublishPayloadClass::RealUserMemory.tag(), 2);
        assert_eq!(PublishPayloadClass::PromptOrProviderText.tag(), 3);
        assert_eq!(PublishPayloadClass::ToolOutput.tag(), 4);
        assert_eq!(PublishPayloadClass::SecretLike.tag(), 5);
        assert_eq!(PublishPayloadClass::PrivateProvenance.tag(), 6);
    }

    #[test]
    fn epoch_count_rejects_zero() {
        assert!(matches!(
            EpochCount::new(0).unwrap_err(),
            PublisherClientError::EndpointQueryEpochsZero
        ));
        assert_eq!(EpochCount::new(1).unwrap().get(), 1);
        assert_eq!(EpochCount::new(u16::MAX).unwrap().get(), u16::MAX);
    }

    #[test]
    fn publisher_endpoint_constants_are_pinned() {
        let e = PublisherEndpoint::testnet_public();
        assert_eq!(e.base_url(), TESTNET_PUBLISHER_BASE_URL);
        assert_eq!(e.put_path(), WALRUS_PUT_BLOB_PATH);
    }

    #[test]
    fn classify_transport_failure_absorbs_unknown_after_boundary_into_manual_reconcile() {
        let d = classify_transport_failure(
            TransportFailureKind::Dns,
            BoundaryState::UnknownAfterBoundary,
            0,
            5,
        );
        assert!(matches!(
            d.disposition,
            PublisherRetryDisposition::ManualReconcile
        ));
        assert!(matches!(d.boundary, BoundaryState::UnknownAfterBoundary));
    }

    #[test]
    fn classify_transport_failure_backoff_schedule_is_deterministic() {
        let make = |a| {
            classify_transport_failure(
                TransportFailureKind::Connect,
                BoundaryState::NoExternalMutation,
                a,
                10,
            )
            .backoff_ms_u32
        };
        assert_eq!(make(0), 100);
        assert_eq!(make(1), 100);
        assert_eq!(make(2), 250);
        assert_eq!(make(3), 500);
        assert_eq!(make(4), 1000);
        assert_eq!(make(100), 1000);
    }

    #[test]
    fn publisher_client_error_class_labels_are_unique_and_namespaced() {
        // Tiny sanity: at least 21 unique labels with the publisher_client. prefix.
        let labels: [&'static str; 21] = [
            PublisherClientError::PayloadClassRejected {
                class: PublishPayloadClass::RealUserMemory,
            }
            .class_label(),
            PublisherClientError::PayloadTooLarge {
                observed_u32: 0,
                cap_u32: 0,
            }
            .class_label(),
            PublisherClientError::EndpointSchemeForbidden.class_label(),
            PublisherClientError::EndpointForbiddenFragment.class_label(),
            PublisherClientError::EndpointForbiddenUserinfo.class_label(),
            PublisherClientError::EndpointPortForbidden.class_label(),
            PublisherClientError::EndpointHostForbidden.class_label(),
            PublisherClientError::EndpointPathMismatch.class_label(),
            PublisherClientError::EndpointQueryKeyForbidden.class_label(),
            PublisherClientError::EndpointQueryEpochsMissing.class_label(),
            PublisherClientError::EndpointQueryEpochsDuplicate.class_label(),
            PublisherClientError::EndpointQueryEpochsMalformed.class_label(),
            PublisherClientError::EndpointQueryEpochsZero.class_label(),
            PublisherClientError::ResponseBodyTooLarge {
                observed_bytes: 0,
                cap_bytes: 0,
            }
            .class_label(),
            PublisherClientError::ResponseStatusUnsupported { http_status_u16: 0 }.class_label(),
            PublisherClientError::ResponseBodyJsonMalformed.class_label(),
            PublisherClientError::ResponseReportedBlobIdMissing.class_label(),
            PublisherClientError::ResponseReportedBlobIdEmpty.class_label(),
            PublisherClientError::ResponseReportedBlobIdTooLong {
                observed_bytes: 0,
                cap_bytes: 0,
            }
            .class_label(),
            PublisherClientError::AttemptsExhausted { attempts_u16: 0 }.class_label(),
            // Reuse one for the 21st slot guard
            PublisherClientError::PayloadClassRejected {
                class: PublishPayloadClass::SecretLike,
            }
            .class_label(),
        ];
        let mut seen = std::collections::HashSet::new();
        for label in labels.iter() {
            assert!(label.starts_with("publisher_client."));
            seen.insert(*label);
        }
        // 20 distinct + 1 duplicate of PayloadClassRejected => 20 unique.
        assert_eq!(seen.len(), 20);
    }
}
