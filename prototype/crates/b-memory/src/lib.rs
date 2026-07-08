//! `mnemos-b-memory` — memory chunk model, bounded in-memory store, persistence and crash replay.
//!
//! Each module carries the canonical types for one concern; the wire
//! surface is reused verbatim from `c-walrus` — there is no
//! `b-memory`-specific encode/decode.
//!
//! Modules:
//!
//! - [`chunk`][]: `MemoryChunk` + `MemoryId(u64)` +
//!   `StorageBackendKind` / `StorageBackendRole` / `StorageBackendPhase` +
//!   `StorageObjectRef` with `walrus_primary` / `future_only` const
//!   constructors. Walrus is the Phase 0 primary backend (`Enabled`);
//!   IPFS/Filecoin are admissible labels but always `FutureOnly`.
//! - [`store`][]: `InMemStore<const CAP: usize>` —
//!   fixed-capacity append-only arena (`[Option<MemoryChunk>; CAP]`,
//!   zero heap reallocation over the store's lifetime). `append` /
//!   `get` / `recent` + `StoreError` (`CapacityExceeded` / `NotFound`).
//!   First consumer of the `MemoryChunk::new` constructor and
//!   `MemoryId::next` saturating sentinel.
//! - [`persist`][]: `MemoryPersist::plan_persist` →
//!   `StorageWritePlan<'_>` { `primary` = Walrus, `payload` =
//!   `PublishPayload<SyntheticPublicFixture>`, `anchor` =
//!   `MoveAnchorArgsV1` with locally-derived `blob_id`, `mirror_phase` =
//!   `FutureOnly` } + `PersistError` (`Codec` / `Publish` / `Anchor` /
//!   `BackendDenied`). Walrus-primary persistence plan that emits a
//!   typed manifest *only* — no socket, no `reqwest`, no live IPFS /
//!   Filecoin endpoint. First consumer of `c-walrus`'s `PublishPayload`,
//!   `MoveAnchorArgsV1` and `derive_blob_id` at the b-memory boundary.
//! - [`replay`][]: `ReplayCursor { last_id,
//!   recovered_u32 }` + `replay_from_anchors(&[MoveAnchorArgsV1]) ->
//!   Result<Vec<MemoryId>, PersistError>`. Anchor-only crash-recovery
//!   entry point: rebuilds the canonical `MemoryId` sequence from the
//!   on-chain anchor stream alone (no backend URL / CID / deal-id
//!   self-report), idempotent over duplicate anchors and
//!   backend-location invariant by construction. Pairs with the
//!   runtime supervisor (`RuntimeBoundaryState::UnknownAfterBoundary`)
//!   and the drain-then-reboot path.
//!
//! ## Stage B
//!
//! - [`stage_b_handoff`][]: `StageAHandoffDigest` (11
//!   evidence-hash slots with `missing_evidence_mask` / `all_evidence_present`
//!   and `to_bytes`/`from_bytes`), `StageBTraceLink` (trace/atom/attempt
//!   stamp), and `EvidenceBundleManifestV1` (local-only evidence hook —
//!   `training_eligibility=false` and no remote locator by construction),
//!   plus `EvidenceRedactionClass` / `EvidenceRightsClass`. Pure value
//!   carriers for the Stage A to Stage B hand-off; no Stage A canonical type
//!   is pulled in yet (network/chunk schema enter later).
//! - [`network`][]: `StageBNetwork::Testnet` — the testnet
//!   network typed boundary. A one-variant `#[repr(u8)]` enum: no
//!   production-network variant is representable, so the no-mainnet
//!   typed guard holds by construction. `parse_label` accepts only the
//!   canonical `testnet` label (ASCII-case-insensitive, trimmed) and rejects
//!   every other label fail-closed (`Option`, no canonical error type,
//!   following the handoff module's precedent); `resolve_override` resolves
//!   an optional override label without ever echoing its raw bytes
//!   (redaction by construction).
//! - [`chunk_schema`][]: `StageBChunkFlags`
//!   (`None`/`HasParent`/`HasAuditLink`/`SealStubbed`) — the one Stage-B-owned
//!   chunk tag enum, a bounded flag bitset layered on Stage A's chunk wire. No
//!   new wire tag is minted: `ChunkKind` / `MemoryRole` / `PublishPayloadClass`
//!   are re-exported verbatim from `c-walrus`, and Stage A's codec
//!   unknown-tag reject (`from_tag` → `ChunkCodecError`) is reused as-is.
//!   Reserved flag bits are rejected fail-closed by `validate_flag_bits`
//!   (`Option`, no canonical error minted). The same module also provides
//!   `StageBChunkHeaderV1` — the
//!   content-free fixed header (`schema_version` / kind / role / content-class
//!   / flags / content-len / owner / parent / trace) whose `new` enforces
//!   parent-flag consistency and reserved-flag reject fail-closed, and whose
//!   `to_bytes` encodes a constant 85-byte ownership + replay boundary with
//!   zero heap allocation and **no** chunk body. The `owner` reuses Stage A's
//!   `SuiAddress` verbatim; `STAGE_B_CHUNK_SCHEMA_V1` is minted
//!   here as the header's version source.
//!   The same module also provides `StageBChunkView<'a>` — the
//!   zero-copy lens pairing a validated header with a **borrowed** Stage A
//!   `ChunkEnvelopeV1` — plus the `MAX_STAGE_B_CONTENT_BYTES` (1 MiB) policy
//!   cap. `StageBChunkView::new` rejects an oversized body fail-closed *before*
//!   any Stage A codec allocation, and pins the header's declared
//!   `content_len_u32` to the borrowed body length. The view allocates nothing
//!   (it only borrows), satisfying the zero-allocation-per-operation criterion.
//! - [`chunk_digest`][]: `ContentHash32` / `ChunkDigest32`
//!   (`#[repr(transparent)]` 32-byte newtypes) + `stage_b_chunk_digest`. The
//!   digest absorbs the domain `mnemos.stage_b.chunk.v1.testnet`
//!   (`CHUNK_DIGEST_DOMAIN`), hashes the body alone into a `ContentHash32` under
//!   a separate `CONTENT_HASH_DOMAIN`, then binds the fixed 85-byte header
//!   (`StageBChunkHeaderV1::to_bytes`) together with that content hash into one
//!   `ChunkDigest32`. The ARX core mirrors Stage A's `derive_blob_id` (pure,
//!   alloc-free, `unsafe`-free; no cryptographic claim). `stage_b_chunk_digest`
//!   re-checks the `MAX_STAGE_B_CONTENT_BYTES` cap fail-closed before hashing and
//!   returns `StageBChunkError::ContentTooLarge` on an over-cap body —
//!   `StageBChunkError` is minted here (its full variant set; this is the
//!   first signature to return it).
//! - [`chunk_chain`][]: the parent validation helpers
//!   `parent_linkage_consistent` / `is_genesis` / `declares_parent`. A chunk's
//!   parent lives in three places once a Stage B header lenses a Stage A
//!   envelope — the `HasParent` flag, the header's `parent`, and the borrowed
//!   `ChunkEnvelopeV1::parent` — and `parent_linkage_consistent` holds all three
//!   in agreement: it re-affirms the header-internal flag⇔parent invariant
//!   and adds the **cross-binding** of the header's parent against the borrowed
//!   envelope's parent. Parent
//!   is integrity linkage only — bound into the [`ChunkDigest32`] through the
//!   header bytes, so a different parent moves the digest — and imposes **no**
//!   replay order (a `bool` predicate, no new `StageBChunkError` variant; the
//!   set is frozen `#[non_exhaustive]`).
#![deny(missing_docs)]
#![deny(unsafe_code)]
//! - [`owner`][]: the owner ↔ signing-public-key boundary.
//!   `SigningPublicKey` is a `#[repr(transparent)]` 32-byte newtype, type-distinct
//!   from Stage A's `SuiAddress`, constructed fail-closed from a runtime `&[u8]`
//!   (length 32 accepted, every other length rejected) or read from its
//!   home-of-record `SignaturePlaceholderV1::public_key` (`from_placeholder`).
//!   `OwnerPublicKeyBinding` carries the `SuiAddress` owner and the
//!   `SigningPublicKey` side-by-side **without** converting one into the other —
//!   the public-key → `SuiAddress` derivation is the exclusive job of the d-move
//!   binding seam. Both types carry a redacting `Debug` and
//!   implement no `Display`, so raw owner / key bytes never leak. The owner reuses
//!   `SuiAddress` verbatim and the key reuses `SignaturePlaceholderV1.public_key`
//!   verbatim — no new address / key type is minted.
//! - [`chunk_signature`][]: the Stage B chunk-sign domain and the
//!   digest-level signature verify. `CHUNK_SIGN_DOMAIN` =
//!   `mnemos.stage_b.chunk_sig.v1.testnet` is mixed in front of a `ChunkDigest32`
//!   (`chunk_sign_preimage` → `CHUNK_SIGN_DOMAIN || digest`, 67 bytes) before
//!   signing, so a chunk signature lives in its own domain — disjoint from the
//!   digest domains and, by its leading byte `m` (`0x6d`), from both Sui
//!   intent scopes (`TransactionData` = `0x00`, `PersonalMessage` = `0x03`); the
//!   same ed25519 key can never confuse a chunk signature with a Sui transaction
//!   signature. `verify_stage_b_chunk` reconstructs the preimage and checks the
//!   reused 64-byte `SignatureBytes` against the `OwnerPublicKeyBinding`'s
//!   public key with `ed25519-dalek` `verify_strict`, returning
//!   `StageBChunkError::SignatureInvalid` on any failure. The production sign path
//!   (`ScopedSecretKey`) and the owner(`SuiAddress`)→key derivation live in later
//!   modules; this module owns the domain, the preimage and the verify only.
//! - [`signed_chunk`][]: the signed chunk constructor.
//!   `StageBSignedChunkV1` carries the four fields — an owned Stage A
//!   `ChunkEnvelopeV1` body, the `ChunkDigest32` that commits it, the
//!   64-byte ed25519 `SignatureBytes` over that digest, and the
//!   `StageBTraceLink`. `StageBSignedChunkV1::new` binds **digest → verify** in one
//!   path: it recomputes the digest from the borrowed `StageBChunkView`
//!   and requires the supplied signature to verify over that recomputed digest
//!   (`verify_stage_b_chunk`) before the value can be minted — a tampered
//!   body or a wrong-owner key fails fail-closed with
//!   `StageBChunkError::SignatureInvalid` (no new variant minted; the set is
//!   frozen `#[non_exhaustive]`). The `sign` half (`ScopedSecretKey`) stays in
//!   `mnemos-g-wallet`; the caller signs
//!   the preimage and hands the signature to `new`. Only the content
//!   *hash* is committed (the digest binds the body's hash, not a raw copy); the
//!   body is kept once in `envelope` for the encode / decode / replay seams.
//! - [`chunk_codec`][]: the Stage B canonical encode entry point
//!   `encode_stage_b_chunk`. A **thin wrapper** over Stage A's `encode_chunk_v1`
//!   that emits byte-identical canonical V1 wire — Stage B mints **no** new BCS
//!   wire. The Stage B digest and signature preimages are
//!   separate surfaces layered *beside* this byte stream, not folded into it, so
//!   the cross-language Move/Rust anchor on the Move side and the verified-blob
//!   decode read stays stable. The wrapper returns Stage A's
//!   `ChunkCodecError` unchanged and does not enforce the tighter
//!   `MAX_STAGE_B_CONTENT_BYTES` cap — that policy lives at the view/digest layer
//!   as `StageBChunkError::ContentTooLarge`. Decode and its
//!   non-canonical reject live in a later module; so does the production signer.
//! - [`content_policy`][]: the default Stage B publish-class
//!   admission predicate `stage_b_publish_allowed`. Returns `true` for **only**
//!   [`PublishPayloadClass`](chunk_schema::PublishPayloadClass)`::SyntheticPublicFixture`
//!   and `false` for every other class (real user memory, prompt / provider text,
//!   tool output, secret-like bytes, private provenance), so a chunk derived from
//!   real user content never reaches a public network through the default policy.
//!   It reuses the re-exported `PublishPayloadClass` verbatim, mints no new
//!   classifier, and returns a `bool` (the denial is mapped onto the frozen
//!   `StageBChunkError::PublishClassDenied` at the publish boundary, not
//!   here). The owner-flagged override that could admit user-owned content is the
//!   seal-stub surface (a later module); this no-owner-flag predicate
//!   denies user-owned content by construction.
//! - [`trace_link`][]: `StageBTraceEvidence` — the content-free
//!   evidence carrier that binds a chunk to its `StageBTraceLink`.
//!   `embed` reads the header's `trace` field and rejects the
//!   missing/unstamped sentinel (`atom_id_u16 == 0`) fail-closed (`Option`, no
//!   new `StageBChunkError` variant), so no evidence record exists for an action
//!   not bound to a real trace — memory is never separated from its measurement.
//!   It carries **only** the three trace ids (never body / owner / parent), so
//!   `evidence_ids` is a redaction-safe log/metrics projection by construction;
//!   the a-core log/metrics *emission* seam is a later integration point. Reuses
//!   `StageBTraceLink` and `StageBChunkHeaderV1` verbatim; mints no new stamp or
//!   wire tag.
//! - [`audit_digest`][]: `stage_b_audit_entry_hash` +
//!   `AUDIT_ENTRY_DOMAIN` — the 32-byte audit-log entry hash a memory owner's
//!   append-only log records per chunk. It binds, in
//!   one domain-separated digest (`mnemos.stage_b.audit_entry.v1.testnet`), the
//!   chunk digest (`StageBSignedChunkV1::digest`), the
//!   `VerifiedBlobId`, and the `StageBTraceLink` stamp. Owner is bound
//!   **transitively** through the chunk digest (the 85-byte header the digest
//!   commits includes the owner) — faithful to the two-argument canonical entry point
//!   `stage_b_audit_entry_hash(signed_chunk, blob_id) -> [u8; 32]`. Every input
//!   is a fixed-width hash/id, so the audit log never stores raw content. Reuses
//!   the signed-chunk and trace-evidence types verbatim and re-states the digest
//!   ARX core inside this single file; mints no new dependency, wire format or
//!   `StageBChunkError` variant.
//! - [`stage_b_walrus_endpoint`][]: `WalrusTestnetEndpoint` —
//!   the Walrus testnet client endpoint allowlist. Binds Stage A's
//!   sealed `PublisherEndpoint` (`c-walrus`) to the
//!   [`StageBNetwork`](network::StageBNetwork) boundary verbatim. The only
//!   constructor is `testnet` (and the `from_label` gate, which succeeds only for
//!   the canonical `testnet` label), so an arbitrary URL, a query-injected URL,
//!   or a `mainnet` label is not representable as a constructed endpoint; the
//!   `accepts_base_url` / `normalize_put_path` predicates express the same
//!   fail-closed allowlist for externally-supplied URL/path strings (query
//!   injection, path traversal, wrong host/path all rejected with a data-free
//!   `false`/`None`). Pure and offline — no socket, no HTTP/TLS, testnet-only.
//!   The wrapper lives in `b-memory`
//!   (orchestration), not `c-walrus` (raw transport), to keep the crate
//!   dependency edge one-way and avoid a `c-walrus -> b-memory` cycle.
//! - [`stage_b_http`][]: `StageBReqwestWalrusClient` — the
//!   Walrus testnet HTTP client wrapper, **feature-gated** behind
//!   `net-testnet`. The default build pulls 0 network types and 0 transitive
//!   HTTP/TLS deps; `b-memory` declares no direct `reqwest` dependency and its
//!   `net-testnet` feature forwards to `mnemos-c-walrus/net-testnet`, so the raw
//!   `reqwest::blocking` transport stays in `c-walrus` and only the
//!   testnet-only orchestration wrapper lives here. The only constructor is
//!   `testnet` (binding `WalrusTestnetEndpoint` — testnet-only, `mainnet`
//!   not representable) and it builds both the Stage A `ReqwestPublisher` /
//!   `ReqwestAggregator` with one shared timeout, rejecting a zero timeout
//!   fail-closed. It is the client seam only — no PUT/GET (the planners live in
//!   separate modules) and no socket is opened.
//! - [`stage_b_put`][]: `WalrusPutPlan<'a>` — the Walrus
//!   testnet PUT **request planner**, plus the client error
//!   `WalrusClientError`. `WalrusPutPlan::plan` borrows the caller's payload
//!   bytes (zero copy), enforces the `stage_b_publish_allowed`
//!   content-class policy **before** any Stage A request type is constructed (a
//!   private/secret-like payload is denied with
//!   `WalrusClientError::PayloadClassDenied` before reaching the raw `c-walrus`
//!   boundary), and binds the PUT to a *stamped* `StageBTraceLink`.
//!   "trace required" is a type-level guarantee: the trace is taken as a
//!   `StageBTraceEvidence`, which can only exist for `atom_id_u16 != 0`, so a
//!   plan without a real trace is not representable (no error variant needed).
//!   The planner does **no** PUT and opens no socket; transport execution and
//!   the response parser live in separate modules.
//!   `WalrusClientError` is minted here in `b-memory` (the first Walrus-client
//!   signature to return it) as the
//!   Stage B orchestration/policy error, distinct from `c-walrus`'s raw
//!   `PublisherClientError`; its full variant set is frozen
//!   `#[non_exhaustive]`, every variant a data-free `walrus.*`-labelled tag
//!   (this planner consumes `PayloadClassDenied` + `OversizedBody`, the rest are
//!   forward-reserved for later planners and transport).
//! - [`stage_b_get`][]: `WalrusGetPlan<'a>` — the Walrus
//!   testnet GET **request planner**. `WalrusGetPlan::plan` accepts only a
//!   `c-walrus` `VerifiedBlobId` (whose sole construction path is the
//!   local derive-and-match), so an unverified server self-report cannot fetch
//!   or anchor; a bare `ReportedBlobId` or raw
//!   `&str` is **not representable** as input. The endpoint is the sealed
//!   testnet `AggregatorEndpoint` (no host/path override), and the trace is a
//!   stamped `StageBTraceEvidence` (so a plan without a real trace is
//!   not representable). All three guarantees are type-level, so
//!   the constructor is a total `const fn` returning `Self` (no `Result`, no
//!   `WalrusClientError` at plan time). The planner does **no** GET and opens no
//!   socket; transport execution lives in a later module.
//! - [`stage_b_get`][]: `WalrusGetBody` +
//!   `parse_walrus_get_response` — the GET **response parser**. It reuses
//!   the Stage A canonical `classify_aggregator_response` (the `b-memory ->
//!   c-walrus` edge) and maps the outcome onto the frozen `WalrusClientError`:
//!   HTTP 200 within cap → `WalrusGetBody` (body bytes + content length, capped
//!   at the maximum legal encoded chunk **before** allocation); oversized →
//!   `OversizedBody`; 404 not-found and every other malformed status →
//!   `Protocol` (no new variant; the set is frozen at seven). `WalrusGetBody`'s
//!   `Debug` is redacted (content length only), and the parser sees an
//!   already-received body, opening no socket.
//! - [`stage_b_blob_id`][]: `derive_walrus_blob_id` — the Stage
//!   B **local** blob-id derivation seam. A **thin wrapper** over Stage A's
//!   `derive_blob_id` (`c-walrus`), mirroring how `encode_stage_b_chunk`
//!   wraps `encode_chunk_v1`: Stage B mints no second algorithm. The id is a pure
//!   function of the canonical encoded chunk bytes (`encode_stage_b_chunk`),
//!   so a publisher's self-reported id text is never an oracle — it is only ever
//!   matched against this local derivation at the verify seam
//!   (`stage_b_verify_blob_id`, the sole `VerifiedBlobId` constructor). Derivation
//!   is total (every `&[u8]`, including `b""`, yields a 32-byte `BlobId`), so the
//!   signature returns a bare `BlobId` with no `Result` and opens no socket
//!   by construction. Reuses `derive_blob_id` + `BlobId`
//!   verbatim; mints no new id type, error or wire.
//! - [`stage_b_verify_blob_id`](stage_b_blob_id::stage_b_verify_blob_id):
//!   the Stage B **reported-id verify** seam — promotes a
//!   publisher's self-reported blob-id text to a `VerifiedBlobId` only on an
//!   exact byte match against the local derivation. A **thin wrapper** over Stage
//!   A's `verify_reported_blob_id` (`c-walrus`), whose internal derive is the
//!   same algorithm `derive_walrus_blob_id` exposes: Stage B mints no second
//!   verify path, no second base64 decoder and no new error type (`BlobIdError`
//!   returned verbatim — `LengthMismatch` / `Base64Decode` / `RootMismatch`).
//!   This is the **only** `VerifiedBlobId` constructor from a reported id; the
//!   returned value wraps the locally derived id (the reported bytes are
//!   discarded once they serve as the equality witness), so the server is never a
//!   blob-id oracle. Pure over `&[u8]` + `&PublisherReportedBlobId`, opens no
//!   socket by construction.

pub mod audit_digest;
pub mod chunk;
pub mod chunk_chain;
pub mod chunk_codec;
pub mod chunk_digest;
pub mod chunk_schema;
pub mod chunk_signature;
pub mod content_policy;
pub mod intelligence;
pub mod network;
pub mod owner;
pub mod persist;
pub mod replay;
pub mod signed_chunk;
pub mod stage_b_attestation;
pub mod stage_b_blob_id;
pub mod stage_b_diag;
pub mod stage_b_get;
pub mod stage_b_handoff;
pub mod stage_b_http;
pub mod stage_b_idempotency;
pub mod stage_b_measure;
pub mod stage_b_policy;
pub mod stage_b_preflight;
pub mod stage_b_put;
pub mod stage_b_receipt;
pub mod stage_b_replay;
pub mod stage_b_retry;
pub mod stage_b_seal_integration;
pub mod stage_b_walrus_endpoint;
pub mod stage_c_handoff;
pub mod stage_c_replay_import;
pub mod stage_c_synthetic_payload;
pub mod stage_c_walrus_measure;
pub mod store;
pub mod trace_link;

#[doc(no_inline)]
pub use audit_digest::{AUDIT_ENTRY_DOMAIN, stage_b_audit_entry_hash};
#[doc(no_inline)]
pub use chunk::{
    MemoryChunk, MemoryId, StorageBackendKind, StorageBackendPhase, StorageBackendRole,
    StorageObjectRef,
};
#[doc(no_inline)]
pub use chunk_chain::{declares_parent, is_genesis, parent_linkage_consistent};
#[doc(no_inline)]
pub use chunk_codec::{decode_stage_b_chunk, encode_stage_b_chunk};
// Re-export the canonical chunk-envelope types so the
// surface crate (sinabro) can mint a `MemoryChunk` for the persisted store
// WITHOUT naming `mnemos-c-walrus` directly (it is `dev`/optional there;
// b-memory is its one-way prod consumer, so this re-export keeps the
// c-walrus=dev isolation intact).
#[doc(no_inline)]
pub use chunk_digest::{
    CHUNK_DIGEST_DOMAIN, CONTENT_HASH_BYTES, CONTENT_HASH_DOMAIN, ChunkDigest32, ContentHash32,
    StageBChunkError, stage_b_chunk_digest,
};
#[doc(no_inline)]
pub use chunk_schema::{
    MAX_STAGE_B_CONTENT_BYTES, STAGE_B_CHUNK_HEADER_ENCODED_LEN, STAGE_B_CHUNK_SCHEMA_V1,
    StageBChunkFlags, StageBChunkHeaderV1, StageBChunkView,
};
#[doc(no_inline)]
pub use chunk_signature::{
    CHUNK_SIGN_DIGEST_BYTES, CHUNK_SIGN_DOMAIN, CHUNK_SIGN_PREIMAGE_BYTES, chunk_sign_preimage,
    verify_stage_b_chunk,
};
#[doc(no_inline)]
pub use content_policy::stage_b_publish_allowed;
#[doc(no_inline)]
pub use mnemos_c_walrus::codec::{ChunkEnvelopeV1, ChunkKind, MemoryRole};
// Memory Intelligence — the canonical types plus the read-only intelligence
// boundary. `DeleteSemantics` is declared at the boundary so `UserModelDelta`
// compiles here; the `delete_semantics` module owns its tombstone
// policy and the `portability` module the export / import / replay bundle.
#[doc(no_inline)]
pub use intelligence::compactor::{
    BackgroundCompactor, CompactionError, CompactionPlan, CompactionStep, CompactorEntry,
    MemoryTier,
};
#[doc(no_inline)]
pub use intelligence::delete_semantics::{
    RedactedDeletion, ResurrectionScan, TOMBSTONE_POLICY_PERFORMS_LIVE_ACTION, TombstoneError,
    TombstonePolicy,
};
#[doc(no_inline)]
pub use intelligence::feedback::{FeedbackLabel, ModelCuriosity, ResolvedFeedback, resolve};
#[doc(no_inline)]
pub use intelligence::importance::{
    ImportanceError, ImportanceFeatures, ImportanceModel, ImportanceScore, MAX_IMPORTANCE_SCORE,
};
#[doc(no_inline)]
pub use intelligence::ingest::{IngestError, IngestOutcome, IngestProvenance, VectorIngestor};
// The fixed 336-byte memory-index catalog record, its deterministic summary
// `f(content)` and the pure trust-tier retrieval selectors.
#[doc(no_inline)]
pub use intelligence::memory_index::{
    INDEX_IMAGE_MAGIC, IndexFoldOutcome, IndexImageError, MEMORY_INDEX_RECORD_ALIGN,
    MEMORY_INDEX_RECORD_BYTES, MemoryIndexError, MemoryIndexRecord, MemoryPrivacy, MemoryReadDeny,
    SUMMARY_CAP, UNCLASSIFIED_IS_PRIVATE, catalog_select, derive_summary, fold_index,
    fold_index_classified, index_from_bytes, index_to_bytes, read_select,
};
#[doc(no_inline)]
pub use intelligence::portability::{
    BUNDLE_CARRIES_AUTO_APPLY_POLICY, ImportedRoot, PORTABILITY_PERFORMS_LIVE_ACTION,
    PortabilityError, PortableMemoryBundle, ProviderMigration, ReplayPortabilityReport,
    compare_policies_offline, export_bundle, import_bundle, user_model_bundle_hash,
};
#[doc(no_inline)]
pub use intelligence::user_model::{ChangedComponents, UserModel, UserModelDelta};
#[doc(no_inline)]
pub use intelligence::vector_index::{HnswInt8Config, Int8VectorIndex, VectorIndexError};
#[doc(no_inline)]
pub use intelligence::{
    ARCHIVE_LOCATOR_IS_MEMORY_TRUTH, DeleteSemantics, ReadOnlyBaseline, StageDEvidenceRef,
    StageDPolicyObservation, StageDPolicyObservationKind,
};
#[doc(no_inline)]
pub use network::{NETWORK_OVERRIDE_ENV_KEY, StageBNetwork};
#[doc(no_inline)]
pub use owner::{OwnerPublicKeyBinding, SIGNING_PUBLIC_KEY_BYTES, SigningPublicKey};
#[doc(no_inline)]
pub use persist::{MemoryPersist, PersistError, StorageWritePlan};
#[doc(no_inline)]
pub use replay::{ReplayCursor, replay_from_anchors};
#[doc(no_inline)]
pub use signed_chunk::StageBSignedChunkV1;
#[doc(no_inline)]
pub use stage_b_attestation::{SafetyKernelBuildRef, StageBTrustBoundaryReceipt, StageBTrustMode};
#[doc(no_inline)]
pub use stage_b_blob_id::{derive_walrus_blob_id, stage_b_verify_blob_id};
#[doc(no_inline)]
pub use stage_b_replay::{
    BlobFetchOutcome, NormalizedEventStream, ReplayBlobIndex, StageBAuditAppendedEvent,
    StageBChunkAnchoredEvent, StageBEventCoord, StageBReplayDecision, StageBReplayError,
    StageBReplayInput, StageBReplayReport, StageBReplayState, StageBTranscriptHash32,
    derive_chunk_blob_id, fetch_for_anchor, normalize_event_stream, replay_stage_b,
    stage_b_transcript_hash,
};
#[doc(no_inline)]
pub use stage_b_seal_integration::{seal_stubbed_flag_consistent, stage_b_seal_publish_plan_guard};
// Official Walrus RS2 oracle Stage B wrappers,
// re-exported only under `net-testnet` (the c-walrus adapter they wrap exists
// only then). The placeholder names above are unchanged.
#[cfg(feature = "net-testnet")]
#[doc(no_inline)]
pub use stage_b_blob_id::{derive_walrus_testnet_blob_id, stage_b_verify_testnet_blob_id};
#[doc(no_inline)]
pub use stage_b_diag::{DIAGNOSTIC_KEYS, STATUS_OK_LABEL, WalrusDiagnostics};
#[doc(no_inline)]
pub use stage_b_get::{WalrusGetBody, WalrusGetPlan, parse_walrus_get_response};
#[doc(no_inline)]
pub use stage_b_handoff::{
    EvidenceBundleManifestV1, EvidenceRedactionClass, EvidenceRightsClass, HANDOFF_DIGEST_BYTES,
    HANDOFF_SLOT_COUNT, StageAHandoffDigest, StageBTraceLink,
};
// Feature-gated — the client type only exists under
// `net-testnet`, so the re-export is gated too (default build names no network type).
#[cfg(feature = "net-testnet")]
#[doc(no_inline)]
pub use stage_b_http::StageBReqwestWalrusClient;
#[doc(no_inline)]
pub use stage_b_idempotency::{WalrusPutDecision, WalrusPutLedger, WalrusPutLedgerError};
#[doc(no_inline)]
pub use stage_b_measure::{MEASURE_KEYS, StageBWalrusMeasure, WalrusActionKind};
#[doc(no_inline)]
pub use stage_b_policy::{StageBPublishDecision, stage_b_publish_decision};
#[doc(no_inline)]
pub use stage_b_preflight::{
    MAX_PREFLIGHT_TIMEOUT_MS, MIN_PREFLIGHT_TIMEOUT_MS, PreflightReadiness,
    WalrusTestnetPreflightReport, feature_compiled,
};
#[doc(no_inline)]
pub use stage_b_put::{
    ReportedBlobId, WalrusClientError, WalrusPutPlan, parse_walrus_put_response,
};
#[doc(no_inline)]
pub use stage_b_receipt::WalrusRoundTripReceipt;
#[doc(no_inline)]
pub use stage_b_retry::{WalrusBoundaryState, WalrusRetry};
#[doc(no_inline)]
pub use stage_b_walrus_endpoint::WalrusTestnetEndpoint;
#[doc(no_inline)]
pub use store::{InMemStore, StoreError};
#[doc(no_inline)]
pub use trace_link::StageBTraceEvidence;
