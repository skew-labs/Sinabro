//! Walrus-primary persistence plan for a [`MemoryChunk`].
//!
//! `b-memory` is network-blind: this module turns a chunk into a *plan*
//! that names what would be PUT to Walrus and what would be anchored to
//! Sui Move, but it never opens a socket, never imports `reqwest`, and
//! never reads a credential. The real PUT runs through `c-walrus`'s
//! feature-gated transport and the real anchor runs
//! through `d-move`'s SDK builder. This module only
//! emits the typed manifest, so the whole test suite runs `--offline`.
//!
//! # Invariants
//!
//! * **Walrus is the only Phase 0 primary.** The emitted plan pins
//!   `primary == StorageBackendKind::Walrus` and there is no caller
//!   knob to swap it. `LocalEncrypted` is `Enabled` as a
//!   *kind* but is not addressable as the Phase 0 persistence primary
//!   in this planner — its writer lives later under `f-seal`.
//!   `IpfsMirror` / `FilecoinArchive` are `FutureOnly` (via
//!   `phase_in_phase0`) and cannot be promoted to the primary slot
//!   from inside this planner — there is no constructor for them in
//!   [`StorageWritePlan`] at all.
//! * **Synthetic class only.** The publisher refuses
//!   every [`PublishPayloadClass`] other than
//!   [`PublishPayloadClass::SyntheticPublicFixture`]. `plan_persist`
//!   tags the plan with that class, so even if a Phase 1 transport
//!   were wired up by mistake it would be rejected at
//!   [`PublisherPutRequest::new`] before any byte left the process.
//!   The Phase 1 promotion path (real-user-memory) is *not* this module.
//! * **No live IPFS / Filecoin endpoint.** The `mirror_phase` field
//!   is `StorageBackendPhase::FutureOnly` in the plan, and the plan
//!   struct carries no URL, no host, no credential, no endpoint
//!   marker for those backends. A `cargo test --offline` run cannot
//!   reach a mirror network even if a downstream layer tries to.
//! * **Anchor args mirror chunk metadata.** The `MoveAnchorArgsV1`
//!   in the plan carries `kind` and `parent` straight from the chunk
//!   envelope, and a locally-derived `blob_id`
//!   ([`derive_blob_id`]) computed over the chunk
//!   content bytes. This enforces the self-report ban (the publisher-
//!   reported blob id is *not* used; the local derivation is canonical).
//! * **Codec / publish / anchor errors are typed.** Failures map onto
//!   [`PersistError`] variants — codec rejections (oversize body that
//!   would not encode under the codec's `MAX_CONTENT_BYTES`),
//!   publisher-cap rejections (body over `PUBLIC_PUBLISHER_BODY_CAP_BYTES`),
//!   anchor projection failures (reserved), and chunks whose existing
//!   storage ref pins a non-Walrus primary backend
//!   ([`PersistError::BackendDenied`]).
//! * **Plan borrows the chunk; no allocation.** [`StorageWritePlan`]
//!   borrows the chunk's `content` bytes via `PublishPayload<'a>` and
//!   carries the rest by value (anchor args, kind / role / phase
//!   enums). There is no heap allocation in `plan_persist`'s happy
//!   path beyond what the input already owns.
//!
//! # Reuse map
//!
//! * [`PublishPayload`] · [`PublishPayloadClass`] —
//!   `mnemos_c_walrus::publisher`.
//! * [`MoveAnchorArgsV1`] · [`ChunkCodecError`] · [`encoded_len_for_content_len`]
//!   — `mnemos_c_walrus::codec`.
//! * [`derive_blob_id`] — `mnemos_c_walrus::blob_id`.
//! * [`MemoryChunk`] · [`StorageBackendKind`] · [`StorageBackendPhase`]
//!   · [`StorageBackendRole`] — `crate::chunk`.
//! * Anchor-args downstream consumer —
//!   `mnemos-d-move::types::memory_root_args_from_anchor`.

use mnemos_c_walrus::{
    ChunkCodecError, MoveAnchorArgsV1, PublishPayload, PublishPayloadClass, derive_blob_id,
    encoded_len_for_content_len,
};

use crate::chunk::{MemoryChunk, StorageBackendKind, StorageBackendPhase, StorageBackendRole};

// ===========================================================================
// 1. PersistError — typed failure surface
// ===========================================================================

/// Failure modes for [`MemoryPersist::plan_persist`]. Mirrors the
/// `#[non_exhaustive]` + `Copy` shape of the sibling error types
/// ([`ChunkCodecError`], `StoreError`) so the
/// error channel never owns a heap allocation and never carries user
/// content.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum PersistError {
    /// The chunk's content would not encode under the codec
    /// (e.g. `content.len() > MAX_CONTENT_BYTES`). Carries the codec's
    /// own error variant verbatim so the upstream cap is visible to
    /// the caller without re-deriving it.
    Codec(ChunkCodecError),
    /// The chunk's content would exceed the Walrus publisher body cap
    /// (`PUBLIC_PUBLISHER_BODY_CAP_BYTES`, 10 MiB) at PUT time. The
    /// publisher's own typed error is collapsed into this stable label
    /// so `PersistError` stays `Copy` and `#[non_exhaustive]` without
    /// leaking the publisher's internal error variants.
    Publish,
    /// Anchor projection failed. Reserved for future SDK-side errors
    /// surfaced by `memory_root_args_from_anchor` (today
    /// the projection is total, so this variant is declared but not
    /// emitted by `plan_persist`).
    Anchor,
    /// The chunk's existing [`crate::chunk::StorageObjectRef`] pins a
    /// primary backend that is not Walrus (i.e. attempts to promote
    /// `LocalEncrypted` / `IpfsMirror` / `FilecoinArchive` to the
    /// Phase 0 primary slot). Phase 0's persistence planner refuses
    /// any non-Walrus primary by construction.
    BackendDenied,
}

impl PersistError {
    /// Static class label for the error. Mirrors the error-redaction
    /// policy in `mnemos-c-walrus::codec::ChunkCodecError::class_label`
    /// — every variant maps to a stable `&'static` string so logs and
    /// metrics never carry a dynamically formatted body.
    #[inline]
    pub const fn class_label(&self) -> &'static str {
        match self {
            Self::Codec(_) => "persist.codec",
            Self::Publish => "persist.publish",
            Self::Anchor => "persist.anchor",
            Self::BackendDenied => "persist.backend_denied",
        }
    }
}

impl core::fmt::Display for PersistError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(self.class_label())
    }
}

impl std::error::Error for PersistError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        None
    }
}

impl From<ChunkCodecError> for PersistError {
    #[inline]
    fn from(err: ChunkCodecError) -> Self {
        Self::Codec(err)
    }
}

// ===========================================================================
// 2. StorageWritePlan — typed persistence manifest
// ===========================================================================

/// Persistence manifest emitted by [`MemoryPersist::plan_persist`].
/// Borrows the chunk's content bytes through [`PublishPayload<'a>`] and
/// carries every other field by value. The struct exposes only
/// read-only accessors; there is no constructor outside this module
/// and no setter for any field, so a plan with a non-Walrus primary
/// or with a live IPFS / Filecoin endpoint is structurally
/// unrepresentable.
///
/// The lifetime `'a` is the lifetime of the [`MemoryChunk`] reference
/// passed to [`MemoryPersist::plan_persist`].
#[derive(Clone, Copy, Debug)]
pub struct StorageWritePlan<'a> {
    primary: StorageBackendKind,
    payload: PublishPayload<'a>,
    anchor: MoveAnchorArgsV1,
    mirror_phase: StorageBackendPhase,
}

impl<'a> StorageWritePlan<'a> {
    /// Primary backend for the planned write. Always
    /// [`StorageBackendKind::Walrus`] in Phase 0 by construction —
    /// there is no constructor that admits any other value.
    #[inline]
    pub const fn primary(&self) -> StorageBackendKind {
        self.primary
    }

    /// Borrowed publisher payload. Carries the chunk content bytes
    /// and the [`PublishPayloadClass::SyntheticPublicFixture`] tag.
    #[inline]
    pub const fn payload(&self) -> PublishPayload<'a> {
        self.payload
    }

    /// Move-side anchor arguments computed from the chunk envelope.
    /// `blob_id` is locally derived via [`derive_blob_id`]
    /// — the publisher-reported text is never trusted here.
    #[inline]
    pub const fn anchor(&self) -> MoveAnchorArgsV1 {
        self.anchor
    }

    /// Mirror-slot phase. Always [`StorageBackendPhase::FutureOnly`]
    /// in Phase 0 — IPFS / Filecoin mirrors are admissible as labels
    /// but no Phase 0 writer exists. Encoded in the plan so a future
    /// Phase 1 promotion is a single source-side flip.
    #[inline]
    pub const fn mirror_phase(&self) -> StorageBackendPhase {
        self.mirror_phase
    }
}

// ===========================================================================
// 3. MemoryPersist — zero-state planner
// ===========================================================================

/// Stateless planner that turns a [`MemoryChunk`] into a
/// [`StorageWritePlan`]. Holds no fields and owns no I/O; the type
/// exists only to namespace [`MemoryPersist::plan_persist`] under a
/// stable receiver shape for future Phase 1 extension (e.g. a
/// `MemoryPersist::new_with_policy(...)` constructor that selects
/// a non-default mirror policy without changing the `plan_persist`
/// signature).
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Hash)]
pub struct MemoryPersist;

impl MemoryPersist {
    /// Emit a Walrus-primary [`StorageWritePlan`] for the chunk.
    ///
    /// # Phase 0 contract
    ///
    /// * `primary` is always [`StorageBackendKind::Walrus`].
    /// * `payload.class()` is always
    ///   [`PublishPayloadClass::SyntheticPublicFixture`].
    /// * `mirror_phase` is always [`StorageBackendPhase::FutureOnly`].
    /// * `anchor.kind` and `anchor.parent` mirror
    ///   `chunk.envelope().kind` and `chunk.envelope().parent`.
    /// * `anchor.blob_id` is the local digest
    ///   `derive_blob_id(chunk.envelope().content)`.
    ///
    /// # Errors
    ///
    /// * [`PersistError::Codec`] — `chunk.envelope().content.len()`
    ///   exceeds the codec's `MAX_CONTENT_BYTES`.
    /// * [`PersistError::Publish`] — `chunk.envelope().content.len()`
    ///   exceeds the publisher's `PUBLIC_PUBLISHER_BODY_CAP_BYTES` cap.
    /// * [`PersistError::BackendDenied`] — `chunk.storage()` already
    ///   pins a primary-role backend other than Walrus.
    pub fn plan_persist(chunk: &MemoryChunk) -> Result<StorageWritePlan<'_>, PersistError> {
        // 1. Refuse a pre-existing non-Walrus primary pin. Walrus +
        //    Primary is the only admissible Phase 0 pin; everything
        //    else (LocalEncrypted / IpfsMirror / FilecoinArchive
        //    promoted to Primary) is denied by construction.
        if let Some(existing) = chunk.storage() {
            if matches!(existing.role(), StorageBackendRole::Primary)
                && !matches!(existing.backend(), StorageBackendKind::Walrus)
            {
                return Err(PersistError::BackendDenied);
            }
        }

        // 2. Length budget — codec cap (MAX_CONTENT_BYTES)
        //    first, then publisher cap (the body cap) via the
        //    real PublishPayload constructor. usize → u32 narrowing
        //    is saturating so an absurd 32-bit-overflow length still
        //    routes through the typed codec error rather than panic.
        let content_bytes: &[u8] = chunk.envelope().content.as_slice();
        let content_len_u32: u32 = if content_bytes.len() > u32::MAX as usize {
            u32::MAX
        } else {
            content_bytes.len() as u32
        };
        if let Err(codec_err) = encoded_len_for_content_len(content_len_u32) {
            return Err(PersistError::Codec(codec_err));
        }

        // 3. Build the publisher payload. The publisher's typed error
        //    surface is collapsed into the stable `Publish` label so
        //    `PersistError` does not import the publisher's full
        //    `PublisherClientError` enum (keeps the b-memory surface
        //    independent of publisher-side variant churn).
        let payload =
            match PublishPayload::new(content_bytes, PublishPayloadClass::SyntheticPublicFixture) {
                Ok(p) => p,
                Err(_) => return Err(PersistError::Publish),
            };

        // 4. Project the Move anchor args. `derive_blob_id` runs over
        //    the same bytes that the publisher would PUT, so the
        //    anchor's `blob_id` is the locally-derived id of the
        //    chunk content — never the publisher's reported text.
        let envelope = chunk.envelope();
        let anchor = MoveAnchorArgsV1 {
            blob_id: derive_blob_id(content_bytes),
            kind: envelope.kind,
            parent: envelope.parent,
        };

        Ok(StorageWritePlan {
            primary: StorageBackendKind::Walrus,
            payload,
            anchor,
            mirror_phase: StorageBackendPhase::FutureOnly,
        })
    }
}

// ===========================================================================
// 4. Compile-time reuse markers
// ===========================================================================

// Pin the cross-crate byte invariant: this module assumes the publisher
// class tag for `SyntheticPublicFixture` is the single-byte value 1
// and that the Phase 0 primary kind is
// `StorageBackendKind::Walrus` with tag 2. A future drift
// on either side is caught at compile time by a zero-length array
// index.
const _SYNTHETIC_FIXTURE_TAG_IS_STABLE: [(); 0 - !(PublishPayloadClass::SyntheticPublicFixture
    .tag()
    == 1) as usize] = [];
const _WALRUS_PRIMARY_TAG_IS_STABLE: [(); 0 - !(StorageBackendKind::Walrus.tag() == 2) as usize] =
    [];
const _MIRROR_PHASE_FUTURE_ONLY_TAG_IS_STABLE: [(); 0 - !(StorageBackendPhase::FutureOnly.tag()
    == 3) as usize] = [];

// ===========================================================================
// 5. Inline unit tests
// ===========================================================================

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    #![allow(clippy::expect_used)]
    #![allow(clippy::panic)]

    use super::*;
    use crate::chunk::{MemoryChunk, MemoryId, StorageObjectRef};
    use mnemos_c_walrus::{
        BlobId, ChunkEnvelopeV1, ChunkKind, MemoryRole, PublishPayloadClass, derive_blob_id,
    };

    /// Build a minimal `ChunkEnvelopeV1` for tests. We borrow `c-walrus`'s
    /// canonical type so any drift in the codec wire shape is caught by
    /// the test compiling (or not).
    fn sample_envelope(content: &[u8]) -> ChunkEnvelopeV1 {
        ChunkEnvelopeV1 {
            kind: ChunkKind::UserMessage,
            role: MemoryRole::User,
            parent: None,
            content: content.to_vec(),
            embedding: None,
            signature: None,
            provenance: None,
        }
    }

    /// Build an envelope with a non-None parent so the
    /// `b0_3_anchor_args_match_chunk` test exercises the `Option<BlobId>`
    /// mirror path (not just `None == None`).
    fn sample_envelope_with_parent(content: &[u8], parent: BlobId) -> ChunkEnvelopeV1 {
        ChunkEnvelopeV1 {
            kind: ChunkKind::AssistantMessage,
            role: MemoryRole::Assistant,
            parent: Some(parent),
            content: content.to_vec(),
            embedding: None,
            signature: None,
            provenance: None,
        }
    }

    /// `b0_3_plan_produces_storage_write_plan` — A fresh `MemoryChunk`
    /// passed to `plan_persist` yields `Ok(StorageWritePlan)` whose
    /// accessors are all readable. This is the happy-path totality
    /// witness for the planner.
    #[test]
    fn b0_3_plan_produces_storage_write_plan() {
        let chunk = MemoryChunk::new(MemoryId::new(0), sample_envelope(b"plan-happy-path"));
        let plan = MemoryPersist::plan_persist(&chunk).expect("happy path must yield Ok");
        // Every accessor must be callable on the returned plan.
        let _ = plan.primary();
        let _ = plan.payload();
        let _ = plan.anchor();
        let _ = plan.mirror_phase();
    }

    /// `b0_3_primary_backend_is_walrus` — The primary backend of the
    /// emitted plan is always `StorageBackendKind::Walrus` (Phase 0
    /// invariant). Asserted across a fresh chunk and a chunk that
    /// already has a non-primary Walrus mirror pin (still Walrus
    /// primary). There is no admissible code path that yields any
    /// other primary backend.
    #[test]
    fn b0_3_primary_backend_is_walrus() {
        let chunk_a = MemoryChunk::new(MemoryId::new(1), sample_envelope(b"primary-walrus-a"));
        let plan_a = MemoryPersist::plan_persist(&chunk_a).expect("happy path A");
        assert_eq!(
            plan_a.primary(),
            StorageBackendKind::Walrus,
            "Phase 0 primary must be Walrus on fresh chunk"
        );

        // A chunk that already carries a non-primary IPFS mirror ref
        // still emits a Walrus primary plan. The pre-existing mirror
        // ref does not promote IPFS to primary.
        let mirror_hash: [u8; 32] = *derive_blob_id(b"non-primary-mirror-witness").as_bytes();
        let mirror_ref = StorageObjectRef::future_only(
            StorageBackendKind::IpfsMirror,
            StorageBackendRole::Mirror,
            mirror_hash,
        );
        let chunk_b = MemoryChunk::new(MemoryId::new(2), sample_envelope(b"primary-walrus-b"))
            .with_storage(mirror_ref);
        let plan_b = MemoryPersist::plan_persist(&chunk_b).expect("non-primary mirror is allowed");
        assert_eq!(
            plan_b.primary(),
            StorageBackendKind::Walrus,
            "Phase 0 primary must remain Walrus even when chunk has a non-primary IPFS mirror ref"
        );
        assert_eq!(
            plan_b.mirror_phase(),
            StorageBackendPhase::FutureOnly,
            "mirror_phase must always be FutureOnly in Phase 0 — no live IPFS writer"
        );
    }

    /// `b0_3_payload_is_synthetic_class_in_phase0` — The planner tags
    /// the payload with `PublishPayloadClass::SyntheticPublicFixture`
    /// — the only class `PublisherPutRequest::new` admits.
    /// A Phase 1 promotion to `RealUserMemory` is a deliberate
    /// future change, not an accidental one.
    #[test]
    fn b0_3_payload_is_synthetic_class_in_phase0() {
        let chunk = MemoryChunk::new(MemoryId::new(3), sample_envelope(b"synthetic-only"));
        let plan = MemoryPersist::plan_persist(&chunk).expect("happy path");
        assert_eq!(
            plan.payload().class(),
            PublishPayloadClass::SyntheticPublicFixture,
            "Phase 0 must always tag the payload as SyntheticPublicFixture"
        );
        // The payload bytes must be the chunk content (no copy, no
        // re-encoding) — the planner borrows the chunk.
        assert_eq!(plan.payload().bytes(), b"synthetic-only".as_slice());
        assert_eq!(plan.payload().len_u32(), b"synthetic-only".len() as u32);
    }

    /// `b0_3_anchor_args_match_chunk` — The anchor args carry exactly
    /// the chunk's `kind` and `parent`, and a locally-derived
    /// `blob_id` computed over the chunk content via
    /// `derive_blob_id`. The publisher-reported text is never used.
    #[test]
    fn b0_3_anchor_args_match_chunk() {
        // Case 1: parent = None. Anchor.kind / parent mirror envelope.
        let chunk_none = MemoryChunk::new(MemoryId::new(4), sample_envelope(b"anchor-no-parent"));
        let plan_none = MemoryPersist::plan_persist(&chunk_none).expect("happy path none");
        assert_eq!(plan_none.anchor().kind, ChunkKind::UserMessage);
        assert_eq!(plan_none.anchor().parent, None);
        let expected_id_none = derive_blob_id(b"anchor-no-parent");
        assert_eq!(
            plan_none.anchor().blob_id,
            expected_id_none,
            "blob_id must equal derive_blob_id(content) — no publisher-reported text"
        );

        // Case 2: parent = Some(BlobId(...)). Mirror through `Some`.
        let parent_bytes: [u8; 32] = *derive_blob_id(b"parent-blob-witness").as_bytes();
        let parent = BlobId(parent_bytes);
        let chunk_some = MemoryChunk::new(
            MemoryId::new(5),
            sample_envelope_with_parent(b"anchor-with-parent", parent),
        );
        let plan_some = MemoryPersist::plan_persist(&chunk_some).expect("happy path some");
        assert_eq!(plan_some.anchor().kind, ChunkKind::AssistantMessage);
        assert_eq!(plan_some.anchor().parent, Some(parent));
        assert_eq!(
            plan_some.anchor().blob_id,
            derive_blob_id(b"anchor-with-parent")
        );

        // The anchor's `seed()` projection drops
        // `blob_id` and keeps `kind` + `parent` — i.e. is by
        // construction the deduplication key b-memory will use to
        // detect a duplicate anchor request before any PUT.
        let seed = plan_some.anchor().seed();
        assert_eq!(seed.kind, ChunkKind::AssistantMessage);
        assert_eq!(seed.parent, Some(parent));
    }

    /// `b0_3_no_ipfs_filecoin_live_writer` — There is no admissible
    /// path through this planner that emits a plan with an IPFS or
    /// Filecoin primary backend, and there is no field on
    /// `StorageWritePlan` that carries an IPFS / Filecoin live
    /// endpoint, host, port, or credential. A chunk whose existing
    /// `StorageObjectRef` pins IPFS / Filecoin to the *primary* role
    /// is rejected with `PersistError::BackendDenied`. Non-primary
    /// (Mirror / Archive) pins for those backends are silently
    /// non-promoted and the plan emits Walrus as the primary.
    #[test]
    fn b0_3_no_ipfs_filecoin_live_writer() {
        let content_hash: [u8; 32] = *derive_blob_id(b"no-live-ipfs-witness").as_bytes();

        // 1. IPFS pinned to Primary role → BackendDenied.
        //    (We craft the `StorageObjectRef` via the only public
        //    constructor `future_only`; the *role* is what selects
        //    Primary vs Mirror — kind→phase is enforced separately.)
        let bad_ipfs_primary = StorageObjectRef::future_only(
            StorageBackendKind::IpfsMirror,
            StorageBackendRole::Primary,
            content_hash,
        );
        let chunk_ipfs = MemoryChunk::new(MemoryId::new(6), sample_envelope(b"bad-ipfs"))
            .with_storage(bad_ipfs_primary);
        let denied_ipfs = MemoryPersist::plan_persist(&chunk_ipfs);
        match denied_ipfs {
            Err(PersistError::BackendDenied) => {}
            other => panic!("IPFS Primary must yield BackendDenied; got {other:?}"),
        }
        assert_eq!(
            PersistError::BackendDenied.class_label(),
            "persist.backend_denied"
        );

        // 2. Filecoin pinned to Primary role → BackendDenied.
        let bad_filecoin_primary = StorageObjectRef::future_only(
            StorageBackendKind::FilecoinArchive,
            StorageBackendRole::Primary,
            content_hash,
        );
        let chunk_filecoin = MemoryChunk::new(MemoryId::new(7), sample_envelope(b"bad-filecoin"))
            .with_storage(bad_filecoin_primary);
        let denied_filecoin = MemoryPersist::plan_persist(&chunk_filecoin);
        match denied_filecoin {
            Err(PersistError::BackendDenied) => {}
            other => panic!("Filecoin Primary must yield BackendDenied; got {other:?}"),
        }

        // 3. LocalEncrypted pinned to Primary → also denied (Phase 0
        //    primary is Walrus and only Walrus; f-seal lands later).
        let bad_local_primary = StorageObjectRef::future_only(
            StorageBackendKind::LocalEncrypted,
            StorageBackendRole::Primary,
            content_hash,
        );
        let chunk_local = MemoryChunk::new(MemoryId::new(8), sample_envelope(b"bad-local"))
            .with_storage(bad_local_primary);
        let denied_local = MemoryPersist::plan_persist(&chunk_local);
        match denied_local {
            Err(PersistError::BackendDenied) => {}
            other => panic!("LocalEncrypted Primary must yield BackendDenied; got {other:?}"),
        }

        // 4. IPFS pinned to Mirror role (non-primary) → allowed, plan
        //    still emits Walrus as primary and `mirror_phase` is
        //    `FutureOnly`.
        let ok_ipfs_mirror = StorageObjectRef::future_only(
            StorageBackendKind::IpfsMirror,
            StorageBackendRole::Mirror,
            content_hash,
        );
        let chunk_ok = MemoryChunk::new(MemoryId::new(9), sample_envelope(b"ok-ipfs-mirror"))
            .with_storage(ok_ipfs_mirror);
        let plan_ok =
            MemoryPersist::plan_persist(&chunk_ok).expect("non-primary IPFS mirror is admissible");
        assert_eq!(plan_ok.primary(), StorageBackendKind::Walrus);
        assert_eq!(plan_ok.mirror_phase(), StorageBackendPhase::FutureOnly);

        // 5. Structural absence of a live-writer field — there is no
        //    `endpoint`, `host`, `url`, or `credential` accessor on
        //    `StorageWritePlan`. The four public accessors below are
        //    the *complete* set; the absence of any IPFS/Filecoin
        //    endpoint accessor is what makes a live writer
        //    impossible by construction. (Compiled here as a witness
        //    — if a future change adds such a field, the four-accessor
        //    invocation will fail to remain exhaustive and code
        //    review will catch the drift.)
        let _ = plan_ok.primary();
        let _ = plan_ok.payload();
        let _ = plan_ok.anchor();
        let _ = plan_ok.mirror_phase();
    }
}
