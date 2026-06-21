//! Crash-recovery replay of memory chunks from on-chain anchors
//! (atom #32 · B.0.4).
//!
//! `b-memory` recovers its append-only chunk history not from any local
//! disk cache (which would imply trusting self-reported backend URLs,
//! CIDs, or Filecoin deal ids — banned by §10.2) but from the
//! on-chain anchor stream itself. The anchor is the ground-truth
//! ledger: each [`MoveAnchorArgsV1`] (atom #7 · C.0.1, surfaced into
//! `b-memory` via atom #31 · B.0.3's persistence planner) names a
//! `blob_id` (content-derived per atom #10 · C.0.4), a [`ChunkKind`],
//! and an optional parent — and **nothing else**. Backend location
//! (Walrus vs IPFS mirror vs Filecoin archive) is structurally absent
//! from the anchor type, so the same anchor at any backend produces
//! the same replay output by construction.
//!
//! This atom pairs with atom #3's runtime supervisor: the supervisor
//! treats any work past the external boundary as
//! `RuntimeBoundaryState::UnknownAfterBoundary` and refuses retries —
//! the crash-recovery path must therefore re-derive state from a
//! source that is **not** "what the in-flight task said happened" but
//! "what the anchor ledger says happened". `replay_from_anchors` is
//! that re-derivation entrypoint, and it returns the canonical
//! `MemoryId` sequence that the in-memory store (atom #30 · B.0.2)
//! would re-emit on a fresh boot from the same anchor history. The
//! supervisor + systemd (atom #6 · A.0.6, K.0.2) pair handles the
//! reboot; `replay_from_anchors` handles the memory re-hydration.
//!
//! # Madness invariants (`MNEMOS_ATOM_PLAN.md` §B.0.4)
//!
//! * **Anchor-only ground truth.** Replay consumes
//!   `&[MoveAnchorArgsV1]` and nothing else. There is no `backend`,
//!   `url`, `cid`, `deal_id`, or `endpoint` argument on this entry
//!   point, and the anchor type carries none of those fields itself.
//!   The §10.2 ban on backend self-report is enforced by the type
//!   surface — a Phase 1 future where backend metadata is surfaced
//!   would require a deliberate new entry point, not a hidden field
//!   on the existing one.
//! * **Idempotent over duplicate anchors.** The same anchor appearing
//!   twice in the input stream contributes exactly one [`MemoryId`].
//!   Equality on [`MoveAnchorArgsV1`] is over `(blob_id, kind,
//!   parent)` (atom #7 derives `PartialEq` / `Eq` / `Hash`), so a
//!   retry storm that re-anchors the same chunk produces the same
//!   replay output as a single emission. The result is the
//!   "deduplicated prefix" of the input.
//! * **Backend-location invariant.** Two anchors with the same
//!   `(blob_id, kind, parent)` triple are structurally
//!   indistinguishable — they cannot encode "stored on Walrus" vs
//!   "stored on IPFS" without changing the equality bytes. A future
//!   atom that tags anchors with their backend would necessarily
//!   change `MoveAnchorArgsV1`'s wire shape (`c-walrus` codec
//!   atom #7) and would surface as a compile-time test failure on
//!   atom #7's `public_type_sizes_v1` and on atom #31's
//!   `b0_3_anchor_args_match_chunk`.
//! * **Deterministic order.** Recovery walks the input slice in
//!   order. The first occurrence of a given anchor produces the
//!   smallest `MemoryId`; subsequent occurrences are skipped. There
//!   is no shuffle, no parallelism, and no implementation-defined
//!   iteration order (no `HashSet` in the public hot path) — same
//!   input slice = same output `Vec<MemoryId>`. This is what the
//!   proptest in this module proves.
//! * **Prefix-consistency.** For any prefix `&anchors[..n]` of an
//!   anchor stream, the replay of the prefix is exactly the prefix
//!   of the replay of the whole stream. The "partial recovery
//!   resumes" test exercises this: a crash mid-stream cannot
//!   produce ids that disagree with a full-stream replay on the
//!   anchors that were already accepted.
//! * **`MemoryId` sequence starts at `MemoryId::new(0)`.** The first
//!   unique anchor produces `MemoryId(0)`, the second `MemoryId(1)`,
//!   and so on. This is the **replay**-domain id sequence; it does
//!   not need to match the live store's `next_id_u64` allocation
//!   trajectory (which can differ if some live chunks were rolled
//!   back before being anchored). Replay produces the
//!   anchor-ledger-canonical id sequence.
//! * **Overflow guarded by typed error.** A slice with more than
//!   `u32::MAX` entries cannot fit in [`ReplayCursor::recovered_u32`]
//!   and is rejected with [`PersistError::Anchor`] before any
//!   allocation, rather than silently saturating. Phase 0 input
//!   sizes are nowhere near this boundary but the explicit guard
//!   keeps the typed surface honest.
//! * **No allocation per anchor beyond `Vec` growth.** The dedup
//!   structure is a linear scan over a `Vec<MoveAnchorArgsV1>` (the
//!   anchor type is `Copy` and 113 bytes — small enough that a
//!   linear scan beats a `HashSet` for Phase 0 input sizes and
//!   avoids pulling `std::collections` into the hot path).
//! * **No external I/O.** This module imports nothing from the
//!   network stack. `cargo test --offline` covers the full atom; a
//!   `--no-default-features` build would behave identically because
//!   there are no default features that toggle replay.
//!
//! # Reuse map (atom contract)
//!
//! * [`MoveAnchorArgsV1`] · [`ChunkKind`] — atom #7 · C.0.1
//!   (`mnemos_c_walrus::codec`).
//! * [`MemoryId`] · [`MemoryId::new`] — atom #29 · B.0.1
//!   (`crate::chunk`).
//! * [`PersistError::Anchor`] — atom #31 · B.0.3
//!   (`crate::persist`). The `Anchor` variant was declared but not
//!   emitted by atom #31's planner (reserved for future SDK-side
//!   anchor projection failures); atom #32 is its first emission
//!   site, used for the `u32::MAX` overflow guard.
//! * Crash-recovery framing — atom #3 · A.0.3 runtime supervisor's
//!   `RuntimeBoundaryState::UnknownAfterBoundary` (`a-core::runtime`).

use mnemos_c_walrus::MoveAnchorArgsV1;

use crate::chunk::MemoryId;
use crate::persist::PersistError;

// ===========================================================================
// 1. ReplayCursor — post-replay state summary
// ===========================================================================

/// Summary of a [`replay_from_anchors`] outcome. Captures the last
/// [`MemoryId`] produced and the count of unique anchors actually
/// recovered. Constructed either from a fresh sentinel ([`Self::start`])
/// or by post-derivation from a replay result slice ([`Self::from_replay`]).
///
/// `recovered_u32` is the count of **unique** anchors, not the input
/// slice length: a slice of `[a, a, b]` yields `recovered_u32 == 2`
/// because `a` is deduplicated.
///
/// `last_id` is the id of the most recently produced
/// [`MemoryId`]. When `recovered_u32 == 0` (no anchors yet), `last_id`
/// is the sentinel [`MemoryId::new(0)`]. Callers that need to
/// distinguish "empty replay" from "replay produced exactly one chunk"
/// must consult `recovered_u32`, not `last_id`.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub struct ReplayCursor {
    last_id: MemoryId,
    recovered_u32: u32,
}

impl ReplayCursor {
    /// Empty starting cursor: `recovered_u32 == 0`, `last_id ==
    /// MemoryId::new(0)`. Use this as the boot-time sentinel before
    /// any anchor has been observed.
    #[inline]
    pub const fn start() -> Self {
        Self {
            last_id: MemoryId::new(0),
            recovered_u32: 0,
        }
    }

    /// Derive a cursor from the `Vec<MemoryId>` produced by
    /// [`replay_from_anchors`]. The `last_id` is the slice's final
    /// entry (or the [`Self::start`] sentinel for an empty slice).
    /// `recovered_u32` saturates at `u32::MAX` for input lengths
    /// beyond that boundary, but [`replay_from_anchors`] itself
    /// refuses such inputs up-front via [`PersistError::Anchor`], so
    /// the saturating branch is defensive only.
    #[inline]
    pub fn from_replay(ids: &[MemoryId]) -> Self {
        let recovered_u32: u32 = if ids.len() > u32::MAX as usize {
            u32::MAX
        } else {
            ids.len() as u32
        };
        let last_id: MemoryId = match ids.last() {
            Some(id) => *id,
            None => MemoryId::new(0),
        };
        Self {
            last_id,
            recovered_u32,
        }
    }

    /// Id of the most recently produced [`MemoryId`]. Sentinel
    /// `MemoryId::new(0)` when no anchor has been recovered yet.
    #[inline]
    pub const fn last_id(self) -> MemoryId {
        self.last_id
    }

    /// Count of unique anchors recovered (deduplicated input slice
    /// length). Equals the length of the [`Vec<MemoryId>`] returned
    /// by [`replay_from_anchors`].
    #[inline]
    pub const fn recovered_u32(self) -> u32 {
        self.recovered_u32
    }
}

// ===========================================================================
// 2. replay_from_anchors — anchor stream → MemoryId sequence
// ===========================================================================

/// Re-derive the local [`MemoryId`] sequence from an on-chain anchor
/// stream after a crash.
///
/// # Behavior
///
/// * Walks `anchors` in slice order.
/// * The **first** occurrence of each unique [`MoveAnchorArgsV1`]
///   value contributes one [`MemoryId`], starting at
///   `MemoryId::new(0)` and incrementing by one per unique anchor.
/// * Subsequent occurrences of an already-seen anchor are skipped
///   (idempotent dedup).
/// * Anchor equality is over the full `(blob_id, kind, parent)`
///   triple. Backend identity (Walrus / IPFS / Filecoin) is **not**
///   part of the anchor type and therefore cannot influence the
///   output.
///
/// # Errors
///
/// * [`PersistError::Anchor`] — `anchors.len() > u32::MAX as usize`
///   (would not fit in [`ReplayCursor::recovered_u32`]). The slice
///   is rejected before any allocation.
///
/// # Reuse
///
/// The returned `Vec<MemoryId>` is the canonical input to the
/// in-memory store's (atom #30 · B.0.2) post-boot rehydration: the
/// store's `next_id_u64` allocator picks up where the cursor's
/// `last_id` leaves off, and the recovered chunks are re-inserted in
/// the order this function returns.
pub fn replay_from_anchors(anchors: &[MoveAnchorArgsV1]) -> Result<Vec<MemoryId>, PersistError> {
    // Overflow guard — slices longer than u32::MAX cannot fit in
    // ReplayCursor::recovered_u32. Reject before allocation so the
    // failure mode is a typed error, not a silent saturation.
    if anchors.len() > u32::MAX as usize {
        return Err(PersistError::Anchor);
    }

    // Linear-scan dedup over `Vec<MoveAnchorArgsV1>`. The anchor type
    // is `Copy` and small (3 fields: 32 + 1 + 33 bytes incl. enum tag
    // padding), so a linear scan beats a HashSet for Phase 0 input
    // sizes and keeps the surface free of std::collections.
    let mut unique_seen: Vec<MoveAnchorArgsV1> = Vec::with_capacity(anchors.len());
    let mut ids: Vec<MemoryId> = Vec::with_capacity(anchors.len());
    for anchor in anchors {
        let already_seen: bool = unique_seen.iter().any(|seen| seen == anchor);
        if already_seen {
            continue;
        }
        // Next index is the current length of `ids` (== current
        // length of `unique_seen`). u64 conversion is total because
        // anchors.len() <= u32::MAX < u64::MAX.
        let next_index_u64: u64 = ids.len() as u64;
        ids.push(MemoryId::new(next_index_u64));
        unique_seen.push(*anchor);
    }

    Ok(ids)
}

// ===========================================================================
// 3. Inline unit tests — atom #32 spine
// ===========================================================================

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    #![allow(clippy::expect_used)]
    #![allow(clippy::panic)]

    use super::*;
    use mnemos_c_walrus::{BlobId, ChunkKind, derive_blob_id};

    /// Build a [`MoveAnchorArgsV1`] from raw bytes by deriving the
    /// blob id locally (atom #10 · C.0.4) — the canonical anchor
    /// constructor used across atoms #31 and #32.
    fn anchor(content: &[u8], kind: ChunkKind, parent: Option<BlobId>) -> MoveAnchorArgsV1 {
        MoveAnchorArgsV1 {
            blob_id: derive_blob_id(content),
            kind,
            parent,
        }
    }

    /// `b0_4_replay_restores_order` — Three distinct anchors in input
    /// order produce `[MemoryId(0), MemoryId(1), MemoryId(2)]` in
    /// that order. Walking the slice in order is the sole admissible
    /// strategy — there is no shuffle, no parallel branch.
    #[test]
    fn b0_4_replay_restores_order() {
        let a = anchor(b"chunk-a", ChunkKind::UserMessage, None);
        let b = anchor(b"chunk-b", ChunkKind::AssistantMessage, None);
        let c = anchor(b"chunk-c", ChunkKind::UserMessage, None);

        let ids = replay_from_anchors(&[a, b, c]).expect("happy path replay must yield Ok");

        assert_eq!(
            ids,
            vec![MemoryId::new(0), MemoryId::new(1), MemoryId::new(2)],
            "three distinct anchors must produce MemoryId(0..3) in slice order"
        );

        // Cursor mirror: post-replay derivation matches the returned ids.
        let cursor = ReplayCursor::from_replay(&ids);
        assert_eq!(cursor.recovered_u32(), 3);
        assert_eq!(cursor.last_id(), MemoryId::new(2));
    }

    /// `b0_4_duplicate_anchor_is_idempotent` — Same anchor appearing
    /// twice in the input contributes exactly one MemoryId. Replaying
    /// the same slice twice yields the same Vec.
    #[test]
    fn b0_4_duplicate_anchor_is_idempotent() {
        let a = anchor(b"dup-a", ChunkKind::UserMessage, None);
        let b = anchor(b"dup-b", ChunkKind::AssistantMessage, None);

        // [a, a, b] dedupes to [a, b] → [MemoryId(0), MemoryId(1)].
        let ids = replay_from_anchors(&[a, a, b]).expect("happy path");
        assert_eq!(
            ids,
            vec![MemoryId::new(0), MemoryId::new(1)],
            "duplicate anchor must produce exactly one MemoryId (idempotent)"
        );

        // Calling replay a second time with the same slice yields the
        // same ids (function-level determinism).
        let ids_again = replay_from_anchors(&[a, a, b]).expect("happy path 2");
        assert_eq!(ids, ids_again, "replay must be deterministic across calls");

        // A retry storm that re-anchors `a` ten times still produces
        // exactly one MemoryId for `a`.
        let storm: [MoveAnchorArgsV1; 10] = [a; 10];
        let storm_ids = replay_from_anchors(&storm).expect("happy storm");
        assert_eq!(
            storm_ids,
            vec![MemoryId::new(0)],
            "ten copies of the same anchor must produce exactly one MemoryId"
        );

        // Cursor mirror.
        let cursor = ReplayCursor::from_replay(&storm_ids);
        assert_eq!(cursor.recovered_u32(), 1);
        assert_eq!(cursor.last_id(), MemoryId::new(0));
    }

    /// `b0_4_partial_recovery_resumes` — Replaying a prefix
    /// `anchors[..n]` is a prefix of replaying the full slice
    /// `anchors[..m]` for `n <= m`. A crash mid-stream cannot produce
    /// ids that disagree with a full-stream replay on the anchors
    /// that were already observed.
    #[test]
    fn b0_4_partial_recovery_resumes() {
        let a = anchor(b"resume-a", ChunkKind::UserMessage, None);
        let b = anchor(b"resume-b", ChunkKind::AssistantMessage, None);
        let c = anchor(b"resume-c", ChunkKind::UserMessage, None);
        let d = anchor(b"resume-d", ChunkKind::ToolResult, None);

        let prefix_ids = replay_from_anchors(&[a, b]).expect("prefix happy");
        let full_ids = replay_from_anchors(&[a, b, c, d]).expect("full happy");

        assert_eq!(prefix_ids.len(), 2, "prefix length matches unique prefix");
        assert_eq!(full_ids.len(), 4, "full length matches unique full");
        assert_eq!(
            &full_ids[..prefix_ids.len()],
            &prefix_ids[..],
            "prefix replay must be a prefix of full replay"
        );

        // Cursor invariants on both runs.
        let cursor_prefix = ReplayCursor::from_replay(&prefix_ids);
        assert_eq!(cursor_prefix.recovered_u32(), 2);
        assert_eq!(cursor_prefix.last_id(), MemoryId::new(1));

        let cursor_full = ReplayCursor::from_replay(&full_ids);
        assert_eq!(cursor_full.recovered_u32(), 4);
        assert_eq!(cursor_full.last_id(), MemoryId::new(3));

        // Start sentinel.
        let start = ReplayCursor::start();
        assert_eq!(start.recovered_u32(), 0);
        assert_eq!(start.last_id(), MemoryId::new(0));

        // Empty replay.
        let empty_ids = replay_from_anchors(&[]).expect("empty happy");
        assert!(empty_ids.is_empty(), "empty input yields empty output");
        let cursor_empty = ReplayCursor::from_replay(&empty_ids);
        assert_eq!(cursor_empty, start, "empty replay equals start sentinel");
    }

    /// `b0_4_backend_location_does_not_change_replay` — The anchor
    /// type carries no backend / URL / CID / deal-id field, so two
    /// anchors with the same `(blob_id, kind, parent)` triple are
    /// structurally indistinguishable regardless of which backend
    /// stored them. Replay output is therefore backend-location
    /// invariant by construction.
    #[test]
    fn b0_4_backend_location_does_not_change_replay() {
        // 1. Equality of MoveAnchorArgsV1 is purely over
        //    (blob_id, kind, parent). Two independently-constructed
        //    anchors with the same triple are equal.
        let content = b"backend-invariant-witness";
        let anchor_x = anchor(content, ChunkKind::UserMessage, None);
        let same_anchor = MoveAnchorArgsV1 {
            blob_id: derive_blob_id(content),
            kind: ChunkKind::UserMessage,
            parent: None,
        };
        assert_eq!(
            anchor_x, same_anchor,
            "anchor equality is content+kind+parent only — no backend tag"
        );

        // 2. Replay treats them as the same anchor.
        let ids_x = replay_from_anchors(&[anchor_x]).expect("happy x");
        let ids_same = replay_from_anchors(&[same_anchor]).expect("happy same");
        assert_eq!(
            ids_x, ids_same,
            "same anchor triple must produce same replay regardless of which constructor"
        );

        // 3. Two slices that interleave "same anchor at different
        //    backends" (which is structurally impossible — the anchor
        //    has no backend field) collapse to one chunk in the
        //    deduplicated replay.
        let mixed = [anchor_x, same_anchor, anchor_x];
        let ids_mixed = replay_from_anchors(&mixed).expect("happy mixed");
        assert_eq!(
            ids_mixed,
            vec![MemoryId::new(0)],
            "three references to the structurally-same anchor must yield one MemoryId"
        );

        // 4. Structural witness — the only public accessors on the
        //    anchor type are blob_id / kind / parent / seed(). The
        //    absence of any backend accessor is what makes a backend
        //    leak impossible. If a future atom adds such a field,
        //    atom #7's `public_type_sizes_v1` test would change and
        //    the codec schema-lock would surface the drift.
        let _ = anchor_x.blob_id;
        let _ = anchor_x.kind;
        let _ = anchor_x.parent;
        let _seed = anchor_x.seed();
    }

    // -----------------------------------------------------------------------
    // 4. Proptest — deterministic recovery over arbitrary anchor sequences
    // -----------------------------------------------------------------------

    proptest::proptest! {
        /// `b0_4_proptest_deterministic_recovery_over_arbitrary_anchors`
        /// — For any randomly generated anchor sequence, replay is
        /// deterministic (same input = same output), the output
        /// length equals the unique-anchor count, and the cursor
        /// derivation agrees with the result vector.
        #[test]
        fn b0_4_proptest_deterministic_recovery_over_arbitrary_anchors(
            seq in proptest::collection::vec((0u8..16u8, 1u8..6u8), 0..32usize)
        ) {
            // Map (content_seed, kind_tag) tuples to MoveAnchorArgsV1.
            // The content_seed is bounded so that some seeds collide
            // (forcing the dedup branch to fire) and some are unique.
            let anchors: Vec<MoveAnchorArgsV1> = seq.iter().map(|(content_seed, kind_tag)| {
                let buf: [u8; 8] = [*content_seed; 8];
                let kind = ChunkKind::from_tag(*kind_tag).unwrap_or(ChunkKind::UserMessage);
                MoveAnchorArgsV1 {
                    blob_id: derive_blob_id(&buf),
                    kind,
                    parent: None,
                }
            }).collect();

            // Determinism: two replays of the same slice agree.
            let ids1 = replay_from_anchors(&anchors).expect("replay 1");
            let ids2 = replay_from_anchors(&anchors).expect("replay 2");
            proptest::prop_assert_eq!(&ids1, &ids2);

            // Output length equals unique-anchor count (independent
            // dedup over the same slice).
            let mut uniques: Vec<MoveAnchorArgsV1> = Vec::new();
            for a in anchors.iter() {
                if !uniques.iter().any(|u| u == a) {
                    uniques.push(*a);
                }
            }
            proptest::prop_assert_eq!(ids1.len(), uniques.len());

            // Ids are strictly monotonic, starting at MemoryId(0).
            for (idx, id) in ids1.iter().enumerate() {
                proptest::prop_assert_eq!(*id, MemoryId::new(idx as u64));
            }

            // Cursor mirror.
            let cursor = ReplayCursor::from_replay(&ids1);
            proptest::prop_assert_eq!(cursor.recovered_u32() as usize, ids1.len());
            if let Some(last) = ids1.last().copied() {
                proptest::prop_assert_eq!(cursor.last_id(), last);
            } else {
                proptest::prop_assert_eq!(cursor.last_id(), MemoryId::new(0));
            }
        }
    }
}
