//! `mnemos-c-walrus` — Walrus blob codec (BCS) and publisher/aggregator transport.
//!
//! Phase 0 critical-path crate. Modules are filled in atom-by-atom per
//! `MNEMOS_ATOM_PLAN.md` §4.C; their canonical signatures live there. Each
//! finished atom keeps `cargo build --workspace` green.
//!
//! Filled so far:
//! - [`codec`] (atom #7 · C.0.1): BCS + uleb128 chunk-envelope codec. The
//!   wire format is byte-stable across Rust / Python / Move (cross-language
//!   schema lock); the body cap is enforced before any `Vec` allocation;
//!   decode is strict-canonical (decode → re-encode → byte-compare).
//! - [`publisher`] (atom #8 · C.0.2): closed-endpoint PUT transport with
//!   boundary-aware retry, body-dropping diagnostic JSON, and a
//!   `SyntheticPublicFixture`-only payload policy. The module is offline
//!   testable end-to-end (network is feature-gated to atom #12).
//! - [`aggregator`] (atom #9 · C.0.3): closed-endpoint GET transport with
//!   read-only retry semantics (boundary always
//!   [`publisher::BoundaryState::NoExternalMutation`]) and a body-cap check
//!   before allocation. Reuses [`publisher::PublisherTransportResponse`] /
//!   `Failure` and [`codec::BlobId`].
//! - [`blob_id`] (atom #10 · C.0.4): locally derived Walrus blob ids. The
//!   text-only [`publisher::PublisherReportedBlobId`] is promoted to
//!   [`blob_id::VerifiedBlobId`] only after a byte-for-byte match against
//!   [`blob_id::derive_blob_id`] — the Walrus-side §10.2 self-report ban.
//!   The Phase 0 derivation algorithm is a placeholder; atom #12
//!   (`C.0.6`, `feature = "net-testnet"`) swaps it for the real Walrus
//!   encoding rule with a byte-stable public signature.
//!
//! - [`stream`] (atom #11 · C.0.5): bounded, length-prefixed chunk-frame
//!   stream. The reader returns zero-copy `&'a [u8]` slices borrowed from
//!   its source; the writer enforces a cumulative byte cap and refuses
//!   any push that would exceed it (with a one-way close transition).
//!   Reuses the canonical `uleb128` wire helpers introduced in atom #7.
//!
//! - [`reqwest_transport`] (atom #12 · C.0.6, **feature-gated** behind
//!   `net-testnet`): synchronous `reqwest::blocking::Client`-backed
//!   [`publisher::PublisherTransport`] /
//!   [`aggregator::AggregatorTransport`] implementations. With the feature
//!   off (default) this module is removed at parse time, so the crate's
//!   runtime dependency surface is byte-identical to atoms #7-#11.
//!
//! Failure-matrix totality (atom #14 · C.0.8) is an invariant carried by the
//! integration tests in `tests/failure_matrix.rs`: every cell of
//! [`publisher::PublishStopReason`] × [`publisher::BoundaryState`] ×
//! [`publisher::TransportFailureKind`] is observed at least once, and an
//! arbitrary canned failure sequence is proven (proptest 256 cases) to
//! produce at most one "external write". The
//! [`publisher::BoundaryState::UnknownAfterBoundary`] state is absorbing —
//! the loop never issues a second `put_blob` after a boundary-unknown
//! outcome, regardless of [`publisher::TransportFailureKind`] or HTTP 5xx
//! response status.
#![deny(unsafe_code)]
#![deny(missing_docs)]

pub mod aggregator;
pub mod blob_id;
/// bridge atom #116.5 · B.2.15.5: isolated official Walrus RS2 blob-id oracle.
/// `net-testnet`-gated; removed at parse time with the feature off, so the
/// default build's derive/verify path stays the atom #10/#11 placeholder.
#[cfg(feature = "net-testnet")]
pub mod blob_id_rs2;
pub mod codec;
pub mod publisher;
#[cfg(feature = "net-testnet")]
pub mod reqwest_transport;
pub mod stage_c_idempotency;
pub mod stage_c_mainnet_endpoint;
pub mod stage_c_mainnet_preflight;
pub mod stage_c_mainnet_verify;
pub mod stream;
mod wire;

#[doc(no_inline)]
pub use aggregator::{
    AggregatorEndpoint, AggregatorGetRequest, AggregatorGetUrl, AggregatorResponseDecision,
    AggregatorTransport, FetchStopReason, TESTNET_AGGREGATOR_BASE_URL, WALRUS_GET_BLOB_PATH,
    classify_aggregator_response, classify_aggregator_transport_failure, fetch_blob_with_transport,
    validate_aggregator_get_url,
};

#[doc(no_inline)]
pub use blob_id::{
    BlobIdError, DOMAIN_TAG_V0, VerifiedBlobId, WALRUS_BLOB_ID_TEXT_LEN_BASE64URL,
    blob_id_from_text, derive_blob_id, encode_base64url_no_pad_32, verify_reported_blob_id,
};

// bridge atom #116.5 · B.2.15.5: official Walrus RS2 oracle entry points,
// re-exported only under `net-testnet`. The existing `derive_blob_id` /
// `verify_reported_blob_id` placeholder names above are unchanged.
#[cfg(feature = "net-testnet")]
#[doc(no_inline)]
pub use blob_id_rs2::{
    WALRUS_TESTNET_N_SHARDS, WalrusOracleError, derive_testnet_blob_id,
    verify_reported_testnet_blob_id,
};

#[doc(no_inline)]
pub use codec::{
    BLOB_ID_BYTES, BlobId, ChunkCodecError, ChunkEnvelopeV1, ChunkKind, EMBEDDING_WIRE_BYTES,
    EmbeddingRefV1, MAX_CONTENT_BYTES, MIN_EMPTY_CHUNK_V1_BYTES, MemoryRole, MoveAnchorArgsV1,
    MoveAnchorSeedV1, PROVENANCE_ID_BYTES, PROVENANCE_WIRE_BYTES, ProvenanceNamespace,
    ProvenanceRefV1, PublicTypeSizesV1, SCHEMA_VERSION_V1, SIGNATURE_BYTES, SIGNATURE_WIRE_BYTES,
    SignatureBytes, SignaturePlaceholderV1, SignatureScheme, decode_chunk_v1, encode_chunk_v1,
    encoded_len_for_content_len, metadata_overhead_for_content_len, public_type_sizes_v1,
};

#[doc(no_inline)]
pub use publisher::{
    BlobStoreSuccessVariant, BoundaryState, EpochCount, MAX_PUBLISHER_RESPONSE_BYTES,
    MAX_REPORTED_BLOB_ID_TEXT_BYTES, PUBLIC_PUBLISHER_BODY_CAP_BYTES, PublishPayload,
    PublishPayloadClass, PublishStopReason, PublisherClientError, PublisherClientRun,
    PublisherDiagnostic, PublisherEndpoint, PublisherPutRequest, PublisherPutUrl,
    PublisherReportedBlobId, PublisherResponseDecision, PublisherRetryDisposition,
    PublisherTransport, PublisherTransportFailure, PublisherTransportResponse,
    TESTNET_PUBLISHER_BASE_URL, TransportFailureKind, TransportRetryDecision, WALRUS_PUT_BLOB_PATH,
    classify_publisher_response, classify_transport_failure, publish_blob_with_transport,
    validate_publisher_put_url,
};

#[doc(no_inline)]
pub use stream::{ChunkStreamReader, ChunkStreamWriter, StreamError, uleb128_encoded_len_u32};

// C-WP-06A · atoms #220/#222/#224: Stage C Walrus mainnet prep surfaces.
#[doc(no_inline)]
pub use stage_c_mainnet_endpoint::{
    MainnetEndpointError, MainnetEndpointMode, MainnetWalrusEndpoint,
    WALRUS_MAINNET_AGGREGATOR_BASE_URL, WALRUS_MAINNET_PUBLISHER_BASE_URL,
};
#[doc(no_inline)]
pub use stage_c_mainnet_preflight::{
    MAINNET_PREFLIGHT_TIMEOUT_SECS, PreflightReject, WalrusMainnetPreflight,
    preflight_mainnet_endpoint,
};
#[doc(no_inline)]
pub use stage_c_mainnet_verify::{
    MainnetSyntheticBlobReceipt, MainnetVerifyError, verify_synthetic_blob,
};
