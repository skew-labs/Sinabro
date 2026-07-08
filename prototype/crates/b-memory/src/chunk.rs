//! Memory chunk model.
//!
//! `b-memory` reuses the `c-walrus` codec wire types verbatim — there is
//! zero duplicate wire surface in this crate. A [`MemoryChunk`] wraps a
//! canonical [`ChunkEnvelopeV1`] together with a
//! single-source-of-truth local [`MemoryId`] and an *optional* persistence
//! reference [`StorageObjectRef`]. The `storage` field is `None` until the
//! chunk has been planned for persistence — i.e. a chunk
//! that has only been appended to the in-memory store
//! carries no backend pointer.
//!
//! # Design invariants
//!
//! * **Codec reuse, zero duplicate wire.** [`MemoryChunk`] holds a real
//!   [`ChunkEnvelopeV1`] from `c-walrus`; no separate wire encoding exists
//!   in `b-memory`. Encode/decode goes through the codec's
//!   `encode_chunk_v1` / `decode_chunk_v1`. This is the cross-language
//!   schema-lock contract carried forward from the codec.
//! * **Monotone local id.** [`MemoryId`] is a single `u64`; ids are minted
//!   by the in-memory store and only ever increase within a
//!   single supervisor lifetime. Crash recovery re-derives ids
//!   from on-chain anchors, not from `MemoryId` bytes.
//! * **Walrus = Phase 0 primary, anchor = truth.** The storage backend
//!   taxonomy distinguishes the *kind* of backend ([`StorageBackendKind`])
//!   from its *role* in the persistence plan ([`StorageBackendRole`]) and
//!   from its *Phase 0 lifecycle phase* ([`StorageBackendPhase`]). Walrus
//!   is marked `Primary` + `Enabled` in Phase 0, but the canonical truth
//!   of a memory remains the envelope hash + owner signature + Sui anchor.
//!   `LocalEncrypted` is `Enabled` (purely local; no network).
//!   IPFS/Filecoin are *future mirror/archive labels only* — they are
//!   admissible as type tags but have `StorageBackendPhase::FutureOnly`
//!   in Phase 0, and any code path that tries to construct a non-future
//!   `StorageObjectRef` for them through the safe constructors yields
//!   the future-only phase by construction.
//! * **`Option<StorageObjectRef>` not `StorageObjectRef`.** A freshly
//!   appended chunk has no persistence pointer; promotion to `Some(_)` is
//!   the responsibility of the persistence plan. Decoupling
//!   here keeps the in-memory store network-blind.
//!
//! # Reuse map
//!
//! * [`ChunkEnvelopeV1`] — `mnemos-c-walrus::codec`.
//! * [`VerifiedBlobId`] — `mnemos-c-walrus::blob_id`.

use mnemos_c_walrus::{ChunkEnvelopeV1, VerifiedBlobId};

// ===========================================================================
// 1. MemoryId — monotone local identifier
// ===========================================================================

/// Monotone local memory chunk identifier minted by the in-memory store.
/// The wrapped `u64` is private; ids are obtained
/// either from the store's `append` return value or by reconstructing the
/// `MemoryId` from on-chain anchors during replay.
///
/// A `MemoryId` is **not** a content-addressable digest; the canonical
/// content hash lives in [`StorageObjectRef::content_hash_32`] and
/// the anchor seed (the codec's `MoveAnchorSeedV1`).
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash, Ord, PartialOrd)]
#[repr(transparent)]
pub struct MemoryId(u64);

impl MemoryId {
    /// Construct a `MemoryId` from a raw `u64`. The store is
    /// the only intended caller — external callers obtain a `MemoryId`
    /// via the store's `append` return value or via crash replay.
    /// Exposed here so the cross-crate boundary between the chunk
    /// type and the store does not require re-opening this module
    /// later.
    #[inline]
    pub const fn new(raw: u64) -> Self {
        Self(raw)
    }

    /// Read the raw `u64` value.
    #[inline]
    pub const fn get(self) -> u64 {
        self.0
    }

    /// Return the immediate successor `MemoryId`. Saturates at `u64::MAX`
    /// so a full-store overflow can never produce a wrap-around id
    /// silently — the saturating sentinel is what the store's
    /// monotonicity test and its `CapacityExceeded` path will
    /// surface to the store.
    #[inline]
    pub const fn next(self) -> Self {
        Self(self.0.saturating_add(1))
    }
}

// ===========================================================================
// 2. Storage backend taxonomy — kind · role · phase
// ===========================================================================

/// Kind of persistence backend. `#[repr(u8)]` with explicit discriminants
/// so the bytes are stable for any future cross-language tabular form
/// (Phase 1+). No tag overlap with the codec enums by virtue of
/// being a separate concept.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
#[repr(u8)]
#[non_exhaustive]
pub enum StorageBackendKind {
    /// On-disk encrypted blob (no network). Implemented later under
    /// `f-seal`. Phase 0 lifecycle: `Enabled`.
    LocalEncrypted = 1,
    /// Walrus blob (off-chain content). Phase 0 lifecycle: `Enabled`;
    /// real PUT happens through `c-walrus`'s feature-gated transport,
    /// planned offline by `MemoryPersist`.
    Walrus = 2,
    /// IPFS mirror. Phase 0 lifecycle: `FutureOnly` — admissible as a
    /// label but **no live writer** exists in Phase 0.
    IpfsMirror = 3,
    /// Filecoin long-term archive. Phase 0 lifecycle: `FutureOnly` —
    /// admissible as a label but **no live writer** exists in Phase 0.
    FilecoinArchive = 4,
}

impl StorageBackendKind {
    /// Phase 0 lifecycle phase for this backend kind. Defines the
    /// "tag-vs-live-writer" mapping that the persistence planner
    /// consults before emitting a write plan. This is a
    /// `const fn` so the mapping is enforced at compile time when a
    /// `StorageObjectRef` is constructed via a `const` constructor.
    #[inline]
    pub const fn phase_in_phase0(self) -> StorageBackendPhase {
        match self {
            Self::LocalEncrypted | Self::Walrus => StorageBackendPhase::Enabled,
            Self::IpfsMirror | Self::FilecoinArchive => StorageBackendPhase::FutureOnly,
        }
    }

    /// Stable u8 tag — mirrors the `#[repr(u8)]` discriminant. Provided
    /// as a `const fn` for downstream serialization layers
    /// that need a byte-level handle without `as` casting at call sites.
    #[inline]
    pub const fn tag(self) -> u8 {
        self as u8
    }
}

/// Role of the backend in a persistence plan. `Primary` is the canonical
/// destination for a chunk in a given plan; `Mirror`/`Archive` are
/// secondary copies (deferred to Phase 1+ for IPFS/Filecoin). `HotCache`
/// is reserved for a future in-memory acceleration layer.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
#[repr(u8)]
#[non_exhaustive]
pub enum StorageBackendRole {
    /// In-memory cache layer (no persistence guarantee).
    HotCache = 1,
    /// Canonical persisted destination for the chunk in this plan.
    Primary = 2,
    /// Secondary copy on a different backend kind.
    Mirror = 3,
    /// Long-term archival copy.
    Archive = 4,
}

impl StorageBackendRole {
    /// Stable u8 tag — mirrors the `#[repr(u8)]` discriminant.
    #[inline]
    pub const fn tag(self) -> u8 {
        self as u8
    }
}

/// Phase 0 lifecycle phase for a backend slot. Distinguishes "live writer
/// exists" (`Enabled`), "dry-run plan only, no network egress"
/// (`DryRunOnly`), and "tag-admissible but no Phase 0 implementation"
/// (`FutureOnly`). This is what makes IPFS/Filecoin admissible as labels
/// without ever firing a network call in Phase 0.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
#[repr(u8)]
#[non_exhaustive]
pub enum StorageBackendPhase {
    /// A live writer exists for this backend in Phase 0.
    Enabled = 1,
    /// The plan is emitted but no I/O happens (used by the offline
    /// persistence planner).
    DryRunOnly = 2,
    /// Tag-admissible label only; no Phase 0 writer exists. IPFS and
    /// Filecoin fall here in Phase 0.
    FutureOnly = 3,
}

impl StorageBackendPhase {
    /// Stable u8 tag — mirrors the `#[repr(u8)]` discriminant.
    #[inline]
    pub const fn tag(self) -> u8 {
        self as u8
    }
}

// ===========================================================================
// 3. StorageObjectRef — kind/role/phase + content hash + optional Walrus id
// ===========================================================================

/// Persistence pointer for a [`MemoryChunk`]. The pointer carries the
/// backend triple ([`StorageBackendKind`] · [`StorageBackendRole`] ·
/// [`StorageBackendPhase`]), the 32-byte canonical content hash of the
/// chunk envelope (the codec's `BlobId`-domain bytes), and an optional
/// [`VerifiedBlobId`]. The blob id is `Some(_)` exactly
/// when the backend is `Walrus` and the publisher's reported id has been
/// locally re-derived and byte-matched (the self-report ban).
///
/// All fields are private; the struct is constructed via the
/// [`walrus_primary`](Self::walrus_primary) /
/// [`future_only`](Self::future_only) `const` constructors which encode
/// the kind→phase mapping at compile time.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub struct StorageObjectRef {
    backend: StorageBackendKind,
    role: StorageBackendRole,
    phase: StorageBackendPhase,
    content_hash_32: [u8; 32],
    walrus_blob: Option<VerifiedBlobId>,
}

impl StorageObjectRef {
    /// Construct a `StorageObjectRef` pointing at Walrus as the
    /// `Primary` `Enabled` backend, carrying a [`VerifiedBlobId`]
    /// (self-report-refused). Used by the persistence planner
    /// when emitting a Walrus PUT plan.
    #[inline]
    pub const fn walrus_primary(content_hash_32: [u8; 32], blob: VerifiedBlobId) -> Self {
        Self {
            backend: StorageBackendKind::Walrus,
            role: StorageBackendRole::Primary,
            phase: StorageBackendKind::Walrus.phase_in_phase0(),
            content_hash_32,
            walrus_blob: Some(blob),
        }
    }

    /// Construct a `StorageObjectRef` for a `FutureOnly` backend (IPFS
    /// mirror or Filecoin archive). The constructor overwrites the
    /// caller's phase intent with the backend's Phase 0 phase, so an
    /// IPFS/Filecoin ref is *always* `FutureOnly` regardless of how the
    /// constructor is called. `walrus_blob` is `None` by construction
    /// (only `walrus_primary` admits a blob id).
    #[inline]
    pub const fn future_only(
        backend: StorageBackendKind,
        role: StorageBackendRole,
        content_hash_32: [u8; 32],
    ) -> Self {
        Self {
            backend,
            role,
            phase: backend.phase_in_phase0(),
            content_hash_32,
            walrus_blob: None,
        }
    }

    /// Backend kind. Read-only accessor.
    #[inline]
    pub const fn backend(&self) -> StorageBackendKind {
        self.backend
    }

    /// Backend role. Read-only accessor.
    #[inline]
    pub const fn role(&self) -> StorageBackendRole {
        self.role
    }

    /// Backend lifecycle phase. Read-only accessor.
    #[inline]
    pub const fn phase(&self) -> StorageBackendPhase {
        self.phase
    }

    /// 32-byte canonical content hash (the `BlobId` domain).
    #[inline]
    pub const fn content_hash_32(&self) -> &[u8; 32] {
        &self.content_hash_32
    }

    /// Optional Walrus-side verified blob id (always `Some(_)` for the
    /// `walrus_primary` constructor and always `None` for `future_only`).
    #[inline]
    pub const fn walrus_blob(&self) -> Option<&VerifiedBlobId> {
        self.walrus_blob.as_ref()
    }
}

// ===========================================================================
// 4. MemoryChunk — envelope + local id + optional storage ref
// ===========================================================================

/// In-memory representation of a single chunk of memory: the canonical
/// envelope (`c-walrus`'s [`ChunkEnvelopeV1`]) plus a local
/// [`MemoryId`] plus an *optional* persistence reference.
///
/// The envelope is held by value — `b-memory` is the owner of the
/// canonical bytes in this Phase 0 in-mem world; persistence
/// borrows the envelope to plan a write. No `b-memory`-specific wire
/// representation exists — encode/decode flows through `c-walrus`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MemoryChunk {
    id: MemoryId,
    envelope: ChunkEnvelopeV1,
    storage: Option<StorageObjectRef>,
}

impl MemoryChunk {
    /// Construct a `MemoryChunk` from a local id and a canonical
    /// envelope. The `storage` field is `None` at construction time;
    /// promotion to `Some(_)` is the persistence planner's job
    /// and is performed via [`with_storage`].
    /// Intended caller: the in-memory store.
    #[inline]
    pub const fn new(id: MemoryId, envelope: ChunkEnvelopeV1) -> Self {
        Self {
            id,
            envelope,
            storage: None,
        }
    }

    /// Attach a persistence reference. Consuming `self` and returning a
    /// new `MemoryChunk` keeps the type immutable from the consumer
    /// side — the persistence planner produces the post-plan chunk, the
    /// store may then replace the slot. Re-attachment overwrites a previous
    /// `Some(_)`; this matches the persistence-replan contract for
    /// recovered chunks.
    #[inline]
    #[must_use]
    pub fn with_storage(mut self, storage: StorageObjectRef) -> Self {
        self.storage = Some(storage);
        self
    }

    /// Local memory id.
    #[inline]
    pub const fn id(&self) -> MemoryId {
        self.id
    }

    /// Canonical envelope (`c-walrus` reuse).
    #[inline]
    pub const fn envelope(&self) -> &ChunkEnvelopeV1 {
        &self.envelope
    }

    /// Optional persistence reference. `None` before the persistence
    /// planner emits a plan; `Some(_)` after persistence has been planned.
    #[inline]
    pub const fn storage(&self) -> Option<&StorageObjectRef> {
        self.storage.as_ref()
    }

    /// Whether this chunk has been bound to a persistence backend.
    /// Convenience predicate for store tests; equivalent to
    /// `self.storage().is_some()`.
    #[inline]
    pub const fn is_persisted_plan_bound(&self) -> bool {
        self.storage.is_some()
    }
}

// ===========================================================================
// 5. Compile-time reuse markers
// ===========================================================================

// Pin the cross-module byte invariant: this module assumes `MemoryId` is the
// width of a single `u64` and that `StorageBackendPhase` discriminants are
// stable. A future drift on either side is caught at compile time by a
// zero-length array index.
const _MEMORY_ID_IS_U64_WIDE: [(); 0 - !(core::mem::size_of::<MemoryId>() == 8) as usize] = [];
const _PHASE_TAGS_ARE_STABLE: [(); 0 - !(StorageBackendPhase::Enabled.tag() == 1
    && StorageBackendPhase::DryRunOnly.tag() == 2
    && StorageBackendPhase::FutureOnly.tag() == 3)
    as usize] = [];
const _BACKEND_KIND_TAGS_ARE_STABLE: [(); 0 - !(StorageBackendKind::LocalEncrypted.tag() == 1
    && StorageBackendKind::Walrus.tag() == 2
    && StorageBackendKind::IpfsMirror.tag() == 3
    && StorageBackendKind::FilecoinArchive.tag() == 4)
    as usize] = [];
const _BACKEND_ROLE_TAGS_ARE_STABLE: [(); 0 - !(StorageBackendRole::HotCache.tag() == 1
    && StorageBackendRole::Primary.tag() == 2
    && StorageBackendRole::Mirror.tag() == 3
    && StorageBackendRole::Archive.tag() == 4)
    as usize] = [];

// ===========================================================================
// 6. Inline unit tests
// ===========================================================================

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    #![allow(clippy::expect_used)]
    #![allow(clippy::panic)]

    use super::*;
    use mnemos_c_walrus::{ChunkEnvelopeV1, ChunkKind, MemoryRole, VerifiedBlobId, derive_blob_id};

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

    /// Build a `VerifiedBlobId` via the public `derive_blob_id` +
    /// `verify_reported_blob_id` round-trip path. We rely on
    /// `c-walrus`'s test-only `encode_base64url_no_pad_32` not being
    /// reachable from outside that crate, so this test obtains a
    /// `VerifiedBlobId` indirectly by deriving the bytes here and
    /// constructing the storage ref via the only public route
    /// (`walrus_primary`) — which is satisfied by re-using a
    /// `VerifiedBlobId` produced by a successful round-trip in
    /// `c-walrus`'s own tests. Since this crate has no public
    /// constructor for `VerifiedBlobId`, we instead use the
    /// integration seam: we construct a `derive_blob_id` digest and
    /// rely on `c-walrus` exposing a `pub fn verify_reported_blob_id`
    /// that returns a `VerifiedBlobId` on byte-match. For unit-test
    /// purposes here we use the publisher transport in `c-walrus`'s
    /// test fixtures, available only via integration tests. As a
    /// unit-level proxy, we wrap the derived bytes into a
    /// `VerifiedBlobId` using `c-walrus`'s public seam via a
    /// helper: see `c-walrus::verify_reported_blob_id`. This unit
    /// suite therefore only exercises constructors that do **not**
    /// require a `VerifiedBlobId`, and the integration test under
    /// `tests/` carries the full Walrus path.
    fn sample_content_hash() -> [u8; 32] {
        *derive_blob_id(b"unit-test-content-hash").as_bytes()
    }

    /// Build a `VerifiedBlobId` for unit tests. We re-use the public
    /// `c-walrus::verify_reported_blob_id` API: encode our derived bytes
    /// to URL-safe base64 (matching `c-walrus::WALRUS_BLOB_ID_TEXT_LEN_BASE64URL`)
    /// and feed that back as the "reported" text — a round-trip that the
    /// production code accepts only when bytes match, which they do here
    /// because both sides derive from the same content.
    fn sample_verified_blob_id() -> VerifiedBlobId {
        use mnemos_c_walrus::{PublisherReportedBlobId, verify_reported_blob_id};
        let content = b"verified-blob-id-witness";
        let derived = derive_blob_id(content);
        let text = encode_b64url(derived.as_bytes());
        let reported = PublisherReportedBlobId::try_from_text(&text).expect("base64url length 43");
        verify_reported_blob_id(content, &reported).expect("round-trip self-derived must verify")
    }

    /// Local helper duplicating `c-walrus`'s `encode_base64url_no_pad_32`
    /// (which is `pub(crate)` over there). Lives only inside this
    /// `cfg(test)` module — production code in this crate never encodes
    /// blob ids.
    fn encode_b64url(raw: &[u8; 32]) -> String {
        const ALPHABET: &[u8; 64] =
            b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
        let mut out = String::with_capacity(43);
        let mut buf: u32 = 0;
        let mut bits: u32 = 0;
        for &b in raw {
            buf = (buf << 8) | (b as u32);
            bits += 8;
            while bits >= 6 {
                bits -= 6;
                let v = ((buf >> bits) & 0x3F) as usize;
                out.push(ALPHABET[v] as char);
            }
        }
        if bits > 0 {
            let v = ((buf << (6 - bits)) & 0x3F) as usize;
            out.push(ALPHABET[v] as char);
        }
        out
    }

    /// `b0_1_chunk_wraps_envelope` — A `MemoryChunk` constructed from a
    /// canonical `ChunkEnvelopeV1` exposes the *same* envelope by
    /// reference. There is no separate `b-memory` wire copy.
    #[test]
    fn b0_1_chunk_wraps_envelope() {
        let env = sample_envelope(b"hello memory");
        let env_clone = env.clone();
        let chunk = MemoryChunk::new(MemoryId::new(0), env);
        assert_eq!(
            chunk.envelope(),
            &env_clone,
            "MemoryChunk must wrap the c-walrus ChunkEnvelopeV1 verbatim — \
             no b-memory-side re-encoding"
        );
        assert!(
            chunk.storage().is_none(),
            "fresh chunk must have no storage ref (persistence is atom #31)"
        );
    }

    /// `b0_1_memory_id_monotone` — `MemoryId::next` is strictly monotone
    /// over the non-saturated range and saturates at `u64::MAX` rather
    /// than wrapping silently. Property checked at the boundary
    /// (saturation) and across a small range.
    #[test]
    fn b0_1_memory_id_monotone() {
        let zero = MemoryId::new(0);
        let one = zero.next();
        assert_eq!(one.get(), 1);
        let two = one.next();
        assert_eq!(two.get(), 2);
        assert!(one > zero);
        assert!(two > one);

        // Saturating boundary — never wraps to 0.
        let max = MemoryId::new(u64::MAX);
        let still_max = max.next();
        assert_eq!(
            still_max.get(),
            u64::MAX,
            "MemoryId::next must saturate at u64::MAX, never wrap to 0"
        );
    }

    /// `b0_1_unpersisted_has_no_storage_ref` — A chunk that has never had
    /// `with_storage` called on it carries `None` in `storage` and
    /// reports `is_persisted_plan_bound() == false`.
    #[test]
    fn b0_1_unpersisted_has_no_storage_ref() {
        let chunk = MemoryChunk::new(MemoryId::new(42), sample_envelope(b"x"));
        assert!(chunk.storage().is_none());
        assert!(!chunk.is_persisted_plan_bound());

        // After explicit attach, storage is `Some(_)` and the predicate
        // flips. This pins the asymmetry: unpersisted = None, planned = Some.
        let storage = StorageObjectRef::future_only(
            StorageBackendKind::IpfsMirror,
            StorageBackendRole::Mirror,
            sample_content_hash(),
        );
        let promoted = chunk.with_storage(storage);
        assert!(promoted.storage().is_some());
        assert!(promoted.is_persisted_plan_bound());
    }

    /// `b0_1_storage_backend_tags_are_stable` — The `#[repr(u8)]`
    /// discriminants for `StorageBackendKind`, `StorageBackendRole`,
    /// and `StorageBackendPhase` are exactly the values declared in
    /// the schema. A future drift in any enum value
    /// would break this test (and the compile-time `_TAGS_ARE_STABLE`
    /// pins above).
    #[test]
    fn b0_1_storage_backend_tags_are_stable() {
        // Kind tags
        assert_eq!(StorageBackendKind::LocalEncrypted.tag(), 1);
        assert_eq!(StorageBackendKind::Walrus.tag(), 2);
        assert_eq!(StorageBackendKind::IpfsMirror.tag(), 3);
        assert_eq!(StorageBackendKind::FilecoinArchive.tag(), 4);

        // Role tags
        assert_eq!(StorageBackendRole::HotCache.tag(), 1);
        assert_eq!(StorageBackendRole::Primary.tag(), 2);
        assert_eq!(StorageBackendRole::Mirror.tag(), 3);
        assert_eq!(StorageBackendRole::Archive.tag(), 4);

        // Phase tags
        assert_eq!(StorageBackendPhase::Enabled.tag(), 1);
        assert_eq!(StorageBackendPhase::DryRunOnly.tag(), 2);
        assert_eq!(StorageBackendPhase::FutureOnly.tag(), 3);
    }

    /// `b0_1_filecoin_ipfs_are_future_only` — IPFS and Filecoin always
    /// produce `StorageBackendPhase::FutureOnly` in Phase 0, regardless
    /// of the role passed to `future_only`. Walrus is `Enabled` (live
    /// writer exists, transport gated to feature `net-testnet`).
    /// `LocalEncrypted` is `Enabled` (pure local; no network).
    #[test]
    fn b0_1_filecoin_ipfs_are_future_only() {
        // Phase mapping is canonical at the kind level.
        assert_eq!(
            StorageBackendKind::IpfsMirror.phase_in_phase0(),
            StorageBackendPhase::FutureOnly
        );
        assert_eq!(
            StorageBackendKind::FilecoinArchive.phase_in_phase0(),
            StorageBackendPhase::FutureOnly
        );
        assert_eq!(
            StorageBackendKind::Walrus.phase_in_phase0(),
            StorageBackendPhase::Enabled
        );
        assert_eq!(
            StorageBackendKind::LocalEncrypted.phase_in_phase0(),
            StorageBackendPhase::Enabled
        );

        // `future_only` constructor pins IPFS/Filecoin to `FutureOnly`
        // and refuses to leak a `walrus_blob` (always `None`).
        let h = sample_content_hash();
        let ipfs = StorageObjectRef::future_only(
            StorageBackendKind::IpfsMirror,
            StorageBackendRole::Mirror,
            h,
        );
        assert_eq!(ipfs.backend(), StorageBackendKind::IpfsMirror);
        assert_eq!(ipfs.role(), StorageBackendRole::Mirror);
        assert_eq!(ipfs.phase(), StorageBackendPhase::FutureOnly);
        assert!(ipfs.walrus_blob().is_none());
        assert_eq!(ipfs.content_hash_32(), &h);

        let filecoin = StorageObjectRef::future_only(
            StorageBackendKind::FilecoinArchive,
            StorageBackendRole::Archive,
            h,
        );
        assert_eq!(filecoin.backend(), StorageBackendKind::FilecoinArchive);
        assert_eq!(filecoin.role(), StorageBackendRole::Archive);
        assert_eq!(filecoin.phase(), StorageBackendPhase::FutureOnly);
        assert!(filecoin.walrus_blob().is_none());

        // `walrus_primary` pins phase to `Enabled` and *requires* a
        // verified blob id (by type). The Walrus blob id is `Some(_)`.
        let blob = sample_verified_blob_id();
        let walrus = StorageObjectRef::walrus_primary(h, blob);
        assert_eq!(walrus.backend(), StorageBackendKind::Walrus);
        assert_eq!(walrus.role(), StorageBackendRole::Primary);
        assert_eq!(walrus.phase(), StorageBackendPhase::Enabled);
        assert!(walrus.walrus_blob().is_some());
    }
}
