//! Bounded in-memory store for [`MemoryChunk`].
//!
//! `InMemStore<const CAP: usize>` is a fixed-capacity append-only arena
//! backed by `[Option<MemoryChunk>; CAP]`. There is zero heap reallocation
//! over the store's lifetime — the slot array is materialised once at
//! construction and reused for every `append`. The bounded shape mirrors
//! the Phase 0 runtime supervisor (`mnemos-a-core::runtime`'s
//! `RuntimeSupervisor<CAP>`) so the whole agent has a
//! uniform fixed-capacity surface.
//!
//! # Invariants
//!
//! * **Heap reallocation count over the store's lifetime: 0.** The slot
//!   array is constructed once with `[const { None }; CAP]` and never
//!   resized. `append` writes into a pre-existing slot; `get` walks the
//!   occupied prefix without allocating; `recent` returns a slice
//!   iterator — no `Vec`, no `clone`, no temporary collections.
//! * **Boundary refusal.** When the occupied slot count reaches `CAP`,
//!   `append` returns [`StoreError::CapacityExceeded`]. There is no
//!   wrap-around, no eviction, no silent drop.
//! * **Monotone local id with saturating sentinel.** Ids are minted from
//!   a `u64` counter and wrapped in [`MemoryId`]. The *saturating sentinel*
//!   ([`MemoryId::next`] saturates at `u64::MAX`) is the surface for an
//!   id-space exhaustion case: when the next id would equal the current
//!   id, the store refuses with `CapacityExceeded` instead of re-issuing
//!   the same id. In practice `CAP ≤ u32::MAX` keeps the slot path
//!   tripped first, but the id-space guard is encoded for defence-in-
//!   depth.
//! * **`recent(n)` is a zero-copy iterator.** It returns
//!   `impl Iterator<Item = &MemoryChunk>` over the last `n` occupied
//!   slots in chronological order (oldest of the recent window first,
//!   newest last). `n` larger than the current occupancy is silently
//!   capped at the occupancy — no panic, no Err.
//! * **Network-blind.** This module touches zero `c-walrus` transport
//!   code and zero Walrus / Sui / IPFS surfaces. `MemoryChunk` is stored
//!   by value (`Option<MemoryChunk>`); promotion to a persisted plan
//!   (`MemoryChunk::with_storage`) is the persistence planner's job
//!   and is outside this module's scope.
//!
//! # Reuse map
//!
//! * [`MemoryChunk::new`] (`crate::chunk`).
//! * [`MemoryId::next`] saturating sentinel.
//! * [`ChunkEnvelopeV1`] (`mnemos-c-walrus::codec`).

use mnemos_c_walrus::ChunkEnvelopeV1;

use crate::chunk::{MemoryChunk, MemoryId};

// ===========================================================================
// 1. StoreError — boundary refusal + lookup miss
// ===========================================================================

/// Failure modes for [`InMemStore`] operations. `#[repr(u8)]` with explicit
/// discriminants so the bytes are stable for any future cross-language
/// tabular form (Phase 1+). No tag overlap with `c-walrus`'s
/// `ChunkCodecError` by virtue of being a separate concept.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
#[repr(u8)]
#[non_exhaustive]
pub enum StoreError {
    /// The store has no free slot (occupied count equals `CAP`) or the
    /// `MemoryId` space is exhausted (next id would saturate). The two
    /// sub-cases are intentionally collapsed into one variant: from the
    /// caller's point of view both mean "the store cannot take another
    /// chunk".
    CapacityExceeded = 1,
    /// A lookup against [`InMemStore::get`] for an id that was never
    /// minted by this store. Returned through `Option::None` at the
    /// `get` API; reified here so the persistence layer can wrap
    /// a typed miss without re-coining a new error.
    NotFound = 2,
}

impl StoreError {
    /// Stable u8 tag — mirrors the `#[repr(u8)]` discriminant. Provided
    /// as a `const fn` for downstream serialization layers
    /// that need a byte-level handle without `as` casting at call sites.
    #[inline]
    pub const fn tag(self) -> u8 {
        self as u8
    }
}

// ===========================================================================
// 2. InMemStore — fixed-capacity arena
// ===========================================================================

/// Fixed-capacity, append-only in-memory store for [`MemoryChunk`]
/// records. `CAP` is the maximum number of chunks the store will ever
/// hold and is fixed at compile time; backing storage is a flat
/// `[Option<MemoryChunk>; CAP]` array inside the struct itself (no `Vec`,
/// no `Box`, no heap allocation across the store's lifetime).
///
/// Slots fill from index `0` upwards as `append` is called; a successful
/// `append` writes the freshly-minted chunk into `slots[len_u32]` and
/// then increments `len_u32`. `get` walks the occupied prefix
/// (`slots[..len_u32]`) by linear scan; `recent` returns a zero-copy
/// iterator over the tail of that prefix.
pub struct InMemStore<const CAP: usize> {
    slots: [Option<MemoryChunk>; CAP],
    len_u32: u32,
    next_id_u64: u64,
}

impl<const CAP: usize> InMemStore<CAP> {
    /// Build an empty store with all `CAP` slots vacant, occupancy `0`,
    /// and the next-id counter primed at `0`. Mirrors the supervisor
    /// pattern (`RuntimeSupervisor::new`) — eager full initialisation,
    /// no `MaybeUninit`. The `CAP <= u32::MAX` width invariant is
    /// enforced at `append` time (`CapacityExceeded` if violated) —
    /// the same shape `RuntimeSupervisor::register` uses for its
    /// `CAP > u16::MAX` guard — because stable Rust forbids const
    /// operations on `const` generic parameters without
    /// `generic_const_exprs`.
    #[inline]
    #[must_use]
    pub const fn new() -> Self {
        Self {
            // `[const { None }; CAP]` uses an inline const block so the
            // repeat operator does not require `MemoryChunk: Copy` —
            // each slot is initialised by re-evaluating the const
            // expression `None` rather than copying a single value.
            slots: [const { None }; CAP],
            len_u32: 0,
            next_id_u64: 0,
        }
    }

    /// Current occupied slot count. Strictly monotone non-decreasing
    /// (append-only contract — chunks are never evicted by this atom).
    #[inline]
    #[must_use]
    pub const fn len(&self) -> u32 {
        self.len_u32
    }

    /// Whether the store has yet to receive any `append`.
    #[inline]
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.len_u32 == 0
    }

    /// Compile-time capacity (`CAP`). Exposed as a `const fn` so callers
    /// do not have to re-state the generic parameter.
    #[inline]
    #[must_use]
    pub const fn capacity(&self) -> usize {
        CAP
    }

    /// Append a chunk built from `envelope` to the store, mint a fresh
    /// [`MemoryId`], and return it. Returns
    /// [`StoreError::CapacityExceeded`] when the store is full or when
    /// the id space is exhausted (the saturating-sentinel
    /// branch — `MemoryId::next` would re-issue the same value).
    ///
    /// The minted chunk is constructed via [`MemoryChunk::new`] with
    /// `storage = None`; promotion to a persisted plan is the
    /// persistence planner's job.
    // AI-HOT: append is on the supervisor turn-recording hot path
    // (`m-agent` records one chunk per user turn). The bench at
    // `benches/store.rs` pins the per-op allocation count at 0.
    pub fn append(&mut self, envelope: ChunkEnvelopeV1) -> Result<MemoryId, StoreError> {
        // Width invariant: `len_u32` cannot address slots beyond
        // `u32::MAX`. Mirrors `RuntimeSupervisor::register`'s
        // `CAP > u16::MAX` guard. Stable Rust forbids const ops on
        // `const` generic parameters, so this runs at every call —
        // monomorphization-time dead-code elimination collapses it to
        // a constant `true`/`false` per `CAP`.
        if CAP > u32::MAX as usize {
            return Err(StoreError::CapacityExceeded);
        }
        // Slot-capacity boundary — refuse rather than wrap or evict.
        let occupied = self.len_u32 as usize;
        if occupied >= CAP {
            return Err(StoreError::CapacityExceeded);
        }

        // Id-space exhaustion via the saturating sentinel: when
        // `MemoryId::next` returns the same value as the current id,
        // the counter has saturated at `u64::MAX` and any further mint
        // would silently re-issue the prior id. Surface as
        // `CapacityExceeded`.
        let id = MemoryId::new(self.next_id_u64);
        let following = id.next();
        if following.get() == self.next_id_u64 {
            return Err(StoreError::CapacityExceeded);
        }

        let chunk = MemoryChunk::new(id, envelope);
        self.slots[occupied] = Some(chunk);
        // `occupied < CAP ≤ u32::MAX` proven by the boundary check + the
        // `_CAP_FITS_U32` const pin, so `len_u32 + 1` cannot overflow a
        // `u32`. Use `wrapping_add` to avoid clippy's `arithmetic_side_effects`
        // surface and document the proof at the call site.
        self.len_u32 = self.len_u32.wrapping_add(1);
        self.next_id_u64 = following.get();
        Ok(id)
    }

    /// Look up a chunk by its [`MemoryId`]. Returns `None` for ids that
    /// were never minted by this store (the [`StoreError::NotFound`]
    /// surface, reified via `Option`). Linear scan over the occupied
    /// prefix; `CAP` is small in Phase 0 (supervisor turn budget) so
    /// the scan dominates only at extreme `CAP` and never allocates.
    // AI-HOT: get is on the conversation-recall hot path.
    pub fn get(&self, id: MemoryId) -> Option<&MemoryChunk> {
        let occupied = self.len_u32 as usize;
        let mut i: usize = 0;
        while i < occupied {
            if let Some(chunk) = self.slots[i].as_ref() {
                if chunk.id() == id {
                    return Some(chunk);
                }
            }
            i = i.wrapping_add(1);
        }
        None
    }

    /// Iterate over the most-recently appended `n_u16` chunks in
    /// chronological order (oldest of the window first, newest last).
    /// When `n_u16` exceeds the current occupancy the window is
    /// silently capped — callers do not need to clamp themselves. The
    /// returned iterator is a slice iterator over `Option`-stripped
    /// references; zero allocations, zero clones.
    pub fn recent(&self, n_u16: u16) -> impl Iterator<Item = &MemoryChunk> {
        let occupied = self.len_u32 as usize;
        let take = (n_u16 as usize).min(occupied);
        // `take <= occupied` so `occupied - take` cannot underflow.
        let start = occupied - take;
        self.slots[start..occupied]
            .iter()
            .filter_map(Option::as_ref)
    }
}

impl<const CAP: usize> Default for InMemStore<CAP> {
    /// Empty store. Equivalent to [`InMemStore::new`].
    #[inline]
    fn default() -> Self {
        Self::new()
    }
}

// ===========================================================================
// 3. Compile-time reuse markers
// ===========================================================================

// Pin the cross-module byte invariant for `StoreError`: `#[repr(u8)]`
// discriminants are stable. A future drift would break this and the
// downstream persistence layer that surfaces `StoreError` tags.
// `StoreError::tag` is `const fn`, so this only needs the values themselves
// — no `const` generic parameter is involved (stable-Rust safe).
const _STORE_ERROR_TAGS_ARE_STABLE: [(); 0 - !(StoreError::CapacityExceeded.tag() == 1
    && StoreError::NotFound.tag() == 2) as usize] = [];

// ===========================================================================
// 4. Inline unit tests
// ===========================================================================

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    #![allow(clippy::expect_used)]
    #![allow(clippy::panic)]

    use super::*;
    use mnemos_c_walrus::{ChunkEnvelopeV1, ChunkKind, MemoryRole};

    /// Minimal envelope builder for tests. Borrows `c-walrus`'s canonical
    /// type so any drift in the codec wire shape is caught by this file
    /// compiling (or not).
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

    /// `b0_2_append_returns_id` — successive `append`s mint strictly
    /// monotone `MemoryId`s starting at `0`. The chunk found by `get`
    /// reports the same id `append` returned.
    #[test]
    fn b0_2_append_returns_id() {
        let mut store: InMemStore<8> = InMemStore::new();
        assert!(store.is_empty());
        assert_eq!(store.len(), 0);
        assert_eq!(store.capacity(), 8);

        let id0 = store.append(sample_envelope(b"a")).unwrap();
        let id1 = store.append(sample_envelope(b"b")).unwrap();
        let id2 = store.append(sample_envelope(b"c")).unwrap();

        assert_eq!(id0.get(), 0, "first minted id must be 0");
        assert_eq!(id1.get(), 1, "ids are strictly monotone +1");
        assert_eq!(id2.get(), 2);
        assert!(id0 < id1 && id1 < id2);

        assert_eq!(store.len(), 3);
        assert!(!store.is_empty());

        // The chunk reachable by id reports the same id `append` returned —
        // no internal renumbering.
        let chunk0 = store.get(id0).expect("appended chunk must be reachable");
        assert_eq!(chunk0.id(), id0);
        let chunk2 = store.get(id2).expect("appended chunk must be reachable");
        assert_eq!(chunk2.id(), id2);
    }

    /// `b0_2_capacity_exceeded_rejected` — once `CAP` slots are
    /// occupied, further `append`s return `Err(CapacityExceeded)` and
    /// the store state (occupancy, next id) is unchanged.
    #[test]
    fn b0_2_capacity_exceeded_rejected() {
        let mut store: InMemStore<2> = InMemStore::new();
        let _id0 = store.append(sample_envelope(b"a")).unwrap();
        let _id1 = store.append(sample_envelope(b"b")).unwrap();
        assert_eq!(store.len(), 2);

        // Third append refused — store is at CAP.
        let err = store.append(sample_envelope(b"c")).unwrap_err();
        assert_eq!(err, StoreError::CapacityExceeded);
        assert_eq!(err.tag(), 1, "CapacityExceeded must have stable tag 1");

        // Refusal must be a no-op: occupancy unchanged, no fourth slot
        // ghost-write.
        assert_eq!(store.len(), 2);
        assert_eq!(store.capacity(), 2);

        // A fourth attempt is still refused — refusal is idempotent.
        let err2 = store.append(sample_envelope(b"d")).unwrap_err();
        assert_eq!(err2, StoreError::CapacityExceeded);
        assert_eq!(store.len(), 2);
    }

    /// `b0_2_get_by_id` — lookup by id finds the appended chunk; lookup
    /// for an id that was never minted (or for an id beyond the current
    /// occupancy) returns `None` rather than a ghost chunk.
    #[test]
    fn b0_2_get_by_id() {
        let mut store: InMemStore<4> = InMemStore::new();
        let id0 = store.append(sample_envelope(b"hello")).unwrap();
        let id1 = store.append(sample_envelope(b"world")).unwrap();

        let got0 = store.get(id0).expect("id0 must be found");
        assert_eq!(got0.id(), id0);
        assert_eq!(got0.envelope().content, b"hello");
        assert!(got0.storage().is_none(), "fresh chunk has no storage ref");

        let got1 = store.get(id1).expect("id1 must be found");
        assert_eq!(got1.id(), id1);
        assert_eq!(got1.envelope().content, b"world");

        // Id beyond the minted range — refusal via Option::None.
        let unknown = MemoryId::new(99);
        assert!(store.get(unknown).is_none(), "unknown id must return None");

        // Id 0 still found after a second append (no overwrite).
        let _id2 = store.append(sample_envelope(b"!")).unwrap();
        let got0_again = store.get(id0).expect("id0 must still be reachable");
        assert_eq!(got0_again.envelope().content, b"hello");
    }

    /// `b0_2_recent_yields_last_n` — `recent(n)` yields exactly the last
    /// `n` appended chunks in chronological order (oldest of the window
    /// first, newest last). `n` exceeding the current occupancy is
    /// silently capped; `n == 0` yields an empty iterator.
    #[test]
    fn b0_2_recent_yields_last_n() {
        let mut store: InMemStore<8> = InMemStore::new();

        // Empty store — recent(any) yields nothing.
        assert_eq!(store.recent(0).count(), 0);
        assert_eq!(store.recent(5).count(), 0);

        let id0 = store.append(sample_envelope(b"0")).unwrap();
        let id1 = store.append(sample_envelope(b"1")).unwrap();
        let id2 = store.append(sample_envelope(b"2")).unwrap();
        let id3 = store.append(sample_envelope(b"3")).unwrap();
        let id4 = store.append(sample_envelope(b"4")).unwrap();
        assert_eq!(store.len(), 5);

        // recent(3) — last three in chronological order [id2, id3, id4].
        let ids_recent_3: Vec<MemoryId> = store.recent(3).map(MemoryChunk::id).collect();
        assert_eq!(ids_recent_3, vec![id2, id3, id4]);

        // recent(5) == every chunk in order.
        let ids_recent_5: Vec<MemoryId> = store.recent(5).map(MemoryChunk::id).collect();
        assert_eq!(ids_recent_5, vec![id0, id1, id2, id3, id4]);

        // recent(99) — silently capped at occupancy (5).
        let ids_recent_99: Vec<MemoryId> = store.recent(99).map(MemoryChunk::id).collect();
        assert_eq!(ids_recent_99.len(), 5);
        assert_eq!(ids_recent_99, vec![id0, id1, id2, id3, id4]);

        // recent(0) — empty iterator.
        assert_eq!(store.recent(0).count(), 0);

        // recent(1) — last one only.
        let ids_recent_1: Vec<MemoryId> = store.recent(1).map(MemoryChunk::id).collect();
        assert_eq!(ids_recent_1, vec![id4]);
    }

    /// Default and `new` produce equivalent empty stores. Pins the
    /// `Default` blanket so the plan layer can rely on either.
    #[test]
    fn b0_2_default_equals_new() {
        let a: InMemStore<4> = InMemStore::new();
        let b: InMemStore<4> = InMemStore::default();
        assert_eq!(a.len(), b.len());
        assert_eq!(a.capacity(), b.capacity());
        assert!(a.is_empty() && b.is_empty());
    }

    /// `StoreError` tag bytes are stable (`CapacityExceeded = 1`,
    /// `NotFound = 2`). Mirrors the `_TAGS_ARE_STABLE` compile
    /// pin at runtime so a test failure is the spotting surface.
    #[test]
    fn b0_2_store_error_tags_are_stable() {
        assert_eq!(StoreError::CapacityExceeded.tag(), 1);
        assert_eq!(StoreError::NotFound.tag(), 2);
        assert_eq!(StoreError::CapacityExceeded as u8, 1);
        assert_eq!(StoreError::NotFound as u8, 2);
    }
}
