//! #163 (B.5.0) — event snapshot normalizer.
//!
//! Canonical OUT (§4.5 + plan #163): normalized Sui `ChunkAnchored` and
//! `AuditAppended` events. Event order is normalized by
//! `(checkpoint, tx_digest, event_seq)`, and any fixed-width field that is not
//! exactly 32 bytes is rejected with
//! [`StageBReplayError::MissingLen32Field`](super::StageBReplayError::MissingLen32Field).
//!
//! Offline normalizer; no live egress. The `ChunkAnchored` / `AuditAppended`
//! names here are *event-type references* (the on-chain shapes minted by Move
//! atoms #127 / #130), not a live action: this file only reorders and validates
//! an already-observed event stream.
//!
//! ## Why normalize first
//!
//! A Sui RPC may return events for a checkpoint in any order and may repeat a
//! page on retry. Replay determinism (#166) requires that the *order* the
//! cursor (#165) applies anchors in is a pure function of the on-chain history,
//! not of fetch timing. The on-chain emission order is total under
//! `(checkpoint, tx_digest, event_seq)`, so sorting by that coordinate — and
//! refusing a stream whose coordinates are not unique — pins the order before
//! any state is touched.

use mnemos_c_walrus::MoveAnchorArgsV1;
use mnemos_d_move::{AuditAppendArgs, MemoryRootAnchorArgs, ObjectId};

use super::StageBReplayError;

/// Sui event coordinate — the total-order key for a Stage B on-chain event.
///
/// Ordering is the derived lexicographic order over the fields in declaration
/// order: `checkpoint_u64`, then `tx_digest`, then `event_seq_u64`. That is
/// exactly the on-chain emission order (a later checkpoint is always later; a
/// tie within a checkpoint breaks on the transaction digest; a tie within a
/// transaction breaks on the per-tx event sequence number).
///
/// `tx_digest` is held as raw `[u8; 32]` (the Sui transaction digest is a
/// 32-byte hash). The bytes are public because this is an *observed* coordinate,
/// not a secret; nothing about ordering is content-sensitive.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct StageBEventCoord {
    /// Sui checkpoint sequence number the event was committed in.
    pub checkpoint_u64: u64,
    /// 32-byte Sui transaction digest the event was emitted by.
    pub tx_digest: [u8; 32],
    /// Per-transaction event sequence number.
    pub event_seq_u64: u64,
}

impl StageBEventCoord {
    /// Construct a coordinate. `const` so coordinates can be built in fixtures
    /// and `const` contexts.
    #[inline]
    pub const fn new(checkpoint_u64: u64, tx_digest: [u8; 32], event_seq_u64: u64) -> Self {
        Self {
            checkpoint_u64,
            tx_digest,
            event_seq_u64,
        }
    }
}

/// A normalized `ChunkAnchored` event: an on-chain anchor ([`MemoryRootAnchorArgs`],
/// the §4.3 call-args form carrying `root`, the verified [`MoveAnchorArgsV1`], and
/// the 32-byte content `digest`) tagged with the [`StageBEventCoord`] it was
/// emitted at.
///
/// The `anchor` field is the *typed* form: building it has already enforced the
/// `len == 32` invariant on the digest (see [`Self::from_move_vectors`]), so a
/// value of this type cannot carry a short digest.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct StageBChunkAnchoredEvent {
    /// On-chain ordering coordinate.
    pub coord: StageBEventCoord,
    /// Typed anchor call args (§4.3), digest already len32-validated.
    pub anchor: MemoryRootAnchorArgs,
}

impl StageBChunkAnchoredEvent {
    /// Pair an already-typed anchor with its coordinate. Total / infallible —
    /// the typed [`MemoryRootAnchorArgs`] has already passed len32 validation.
    #[inline]
    pub const fn new(coord: StageBEventCoord, anchor: MemoryRootAnchorArgs) -> Self {
        Self { coord, anchor }
    }

    /// Build from the raw Move boundary: the target `root` object id, the
    /// verified Walrus [`MoveAnchorArgsV1`] (blob id + kind + optional parent),
    /// and the inbound `digest` `vector<u8>`.
    ///
    /// Rejects a `digest` whose length is not 32 with
    /// [`StageBReplayError::MissingLen32Field`], reusing the d-move boundary
    /// adapter [`MemoryRootAnchorArgs::try_from_move_vectors`] (atom #132) — the
    /// single canonical place the Move↔Rust len32 invariant lives.
    #[inline]
    pub fn from_move_vectors(
        coord: StageBEventCoord,
        root: ObjectId,
        anchor: MoveAnchorArgsV1,
        digest: &[u8],
    ) -> Result<Self, StageBReplayError> {
        let anchor = MemoryRootAnchorArgs::try_from_move_vectors(root, anchor, digest)
            .map_err(|_| StageBReplayError::MissingLen32Field)?;
        Ok(Self { coord, anchor })
    }
}

/// A normalized `AuditAppended` event: an on-chain audit append
/// ([`AuditAppendArgs`], carrying the `log` object id and the 32-byte
/// `entry_hash`) tagged with the [`StageBEventCoord`] it was emitted at.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct StageBAuditAppendedEvent {
    /// On-chain ordering coordinate.
    pub coord: StageBEventCoord,
    /// Typed audit-append call args (§4.3), entry hash already len32-validated.
    pub audit: AuditAppendArgs,
}

impl StageBAuditAppendedEvent {
    /// Pair an already-typed audit append with its coordinate. Total /
    /// infallible.
    #[inline]
    pub const fn new(coord: StageBEventCoord, audit: AuditAppendArgs) -> Self {
        Self { coord, audit }
    }

    /// Build from the raw Move boundary: the target `log` object id and the
    /// inbound `entry_hash` `vector<u8>`.
    ///
    /// Rejects an `entry_hash` whose length is not 32 with
    /// [`StageBReplayError::MissingLen32Field`], reusing
    /// [`AuditAppendArgs::try_from_move_entry_hash`] (atom #132).
    #[inline]
    pub fn from_move_vectors(
        coord: StageBEventCoord,
        log: ObjectId,
        entry_hash: &[u8],
    ) -> Result<Self, StageBReplayError> {
        let audit = AuditAppendArgs::try_from_move_entry_hash(log, entry_hash)
            .map_err(|_| StageBReplayError::MissingLen32Field)?;
        Ok(Self { coord, audit })
    }
}

/// The output of [`normalize_event_stream`]: the anchor and audit events, each
/// sorted into on-chain order, with stream-wide coordinate uniqueness already
/// proven.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NormalizedEventStream {
    /// `ChunkAnchored` events in ascending [`StageBEventCoord`] order.
    pub anchors: Vec<StageBChunkAnchoredEvent>,
    /// `AuditAppended` events in ascending [`StageBEventCoord`] order.
    pub audit: Vec<StageBAuditAppendedEvent>,
}

/// Normalize a raw (any-order, possibly duplicate-paged) Stage B event stream.
///
/// 1. Reject a stream longer than `u32::MAX` events with
///    [`StageBReplayError::EventCountOverflow`] before any work (the report's
///    counters are `u32`-bounded).
/// 2. Sort `anchors` and `audit` independently by [`StageBEventCoord`].
/// 3. Prove that **every** coordinate across the union of both streams is
///    unique. A repeated coordinate is a [`StageBReplayError::DuplicateEventId`]
///    — a single on-chain event id must map to a single event. (This is the
///    "duplicate event id" reject; it is *not* the idempotent "duplicate anchor"
///    case, which is a later [`StageBReplayDecision`](super::StageBReplayDecision)
///    over distinct events that happen to anchor the same blob.)
///
/// The result is the canonical, deterministic input order for the replay cursor
/// (#165). The function is pure and offline.
pub fn normalize_event_stream(
    mut anchors: Vec<StageBChunkAnchoredEvent>,
    mut audit: Vec<StageBAuditAppendedEvent>,
) -> Result<NormalizedEventStream, StageBReplayError> {
    if anchors.len() > u32::MAX as usize || audit.len() > u32::MAX as usize {
        return Err(StageBReplayError::EventCountOverflow);
    }

    anchors.sort_by(|a, b| a.coord.cmp(&b.coord));
    audit.sort_by(|a, b| a.coord.cmp(&b.coord));

    // Stream-wide coordinate uniqueness. Collect every coordinate, sort, and
    // check adjacency — O(n log n) without pulling in std::collections, mirroring
    // the linear/sort style of `replay_from_anchors` (atom #32).
    let mut coords: Vec<StageBEventCoord> = Vec::with_capacity(anchors.len() + audit.len());
    coords.extend(anchors.iter().map(|event| event.coord));
    coords.extend(audit.iter().map(|event| event.coord));
    coords.sort();
    for pair in coords.windows(2) {
        if pair[0] == pair[1] {
            return Err(StageBReplayError::DuplicateEventId);
        }
    }

    Ok(NormalizedEventStream { anchors, audit })
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use super::*;
    use mnemos_c_walrus::{BlobId, ChunkKind};

    fn coord(checkpoint: u64, tx: u8, seq: u64) -> StageBEventCoord {
        StageBEventCoord::new(checkpoint, [tx; 32], seq)
    }

    fn anchor_args() -> MoveAnchorArgsV1 {
        MoveAnchorArgsV1 {
            blob_id: BlobId([0xAB; 32]),
            kind: ChunkKind::UserMessage,
            parent: None,
        }
    }

    fn chunk_event(c: StageBEventCoord, digest_byte: u8) -> StageBChunkAnchoredEvent {
        StageBChunkAnchoredEvent::from_move_vectors(
            c,
            ObjectId::new([0x11; 32]),
            anchor_args(),
            &[digest_byte; 32],
        )
        .expect("len32 digest is valid")
    }

    fn audit_event(c: StageBEventCoord, hash_byte: u8) -> StageBAuditAppendedEvent {
        StageBAuditAppendedEvent::from_move_vectors(c, ObjectId::new([0x33; 32]), &[hash_byte; 32])
            .expect("len32 entry hash is valid")
    }

    #[test]
    fn b5_0_order_is_normalized_by_coordinate() {
        // Insert out of on-chain order: later checkpoint first, then a tie broken
        // by tx digest, then by event seq.
        let a = chunk_event(coord(7, 0x01, 0), 0xA1);
        let b = chunk_event(coord(5, 0x02, 9), 0xA2);
        let c = chunk_event(coord(5, 0x02, 3), 0xA3);
        let d = chunk_event(coord(5, 0x01, 0), 0xA4);

        let out = normalize_event_stream(vec![a, b, c, d], vec![]).expect("well-formed");
        let order: Vec<StageBEventCoord> = out.anchors.iter().map(|e| e.coord).collect();
        assert_eq!(
            order,
            vec![
                coord(5, 0x01, 0),
                coord(5, 0x02, 3),
                coord(5, 0x02, 9),
                coord(7, 0x01, 0),
            ],
            "events must be sorted by (checkpoint, tx_digest, event_seq)"
        );
    }

    #[test]
    fn b5_0_short_digest_is_len32_rejected() {
        let err = StageBChunkAnchoredEvent::from_move_vectors(
            coord(1, 0x01, 0),
            ObjectId::new([0x11; 32]),
            anchor_args(),
            &[0xAA; 31], // one byte short
        )
        .expect_err("31-byte digest must be rejected");
        assert_eq!(err, StageBReplayError::MissingLen32Field);

        let err2 = StageBAuditAppendedEvent::from_move_vectors(
            coord(1, 0x01, 1),
            ObjectId::new([0x33; 32]),
            &[],
        )
        .expect_err("empty entry hash must be rejected");
        assert_eq!(err2, StageBReplayError::MissingLen32Field);
    }

    #[test]
    fn b5_0_duplicate_event_id_is_rejected() {
        let dup = coord(5, 0x02, 3);
        // Two distinct anchor events at the same coordinate.
        let a = chunk_event(dup, 0xA1);
        let b = chunk_event(dup, 0xB2);
        let err = normalize_event_stream(vec![a, b], vec![]).expect_err("duplicate coord");
        assert_eq!(err, StageBReplayError::DuplicateEventId);

        // A coordinate shared across an anchor and an audit event is also a
        // collision (event ids are unique across the whole stream).
        let anchor = chunk_event(dup, 0xA1);
        let audit = audit_event(dup, 0xE5);
        let err = normalize_event_stream(vec![anchor], vec![audit]).expect_err("cross-stream dup");
        assert_eq!(err, StageBReplayError::DuplicateEventId);
    }

    #[test]
    fn b5_0_distinct_coords_pass() {
        let anchor = chunk_event(coord(5, 0x01, 0), 0xA1);
        let audit = audit_event(coord(5, 0x01, 1), 0xE5);
        let out = normalize_event_stream(vec![anchor], vec![audit]).expect("distinct coords ok");
        assert_eq!(out.anchors.len(), 1);
        assert_eq!(out.audit.len(), 1);
    }
}
