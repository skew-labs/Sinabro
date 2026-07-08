//! Replay cursor and apply order.
//!
//! Canonical OUT: [`StageBReplayState`], [`StageBReplayDecision`], and the
//! per-event apply logic that the top-level
//! [`replay_stage_b`](super::transcript::replay_stage_b) walks.
//!
//! Invariant: *replay reuses the Stage A
//! [`ReplayCursor`](crate::replay::ReplayCursor) inside a Stage B event state
//! machine, not a best-effort scan; duplicate anchors are idempotent.* Offline
//! cursor; no live egress.
//!
//! ## The state machine
//!
//! Replay walks the normalized anchor stream in order. For each anchor it makes
//! exactly one [`StageBReplayDecision`]:
//!
//! - **OwnerMismatch** — the anchor targets a different `MemoryRoot` than the one
//!   this replay is bound to. The first anchor establishes the bound root; any
//!   later anchor on a different root is a foreign record spliced into the
//!   stream and is refused. (Audit events bind the `AuditLog` the same way.)
//! - **DuplicateIgnored** — an anchor identical (same `(blob_id, kind, parent)`)
//!   to one already applied. Idempotent: re-anchoring the same chunk does not
//!   produce a second `MemoryId`. This is *not* the
//!   [`DuplicateEventId`](super::StageBReplayError::DuplicateEventId) case (two
//!   events at the same on-chain coordinate), which the normalizer already
//!   refused.
//! - **MissingBlob** / **DigestMismatch** — the verified-blob outcome from
//!   [`fetch_for_anchor`].
//! - **Applied** — a fresh, owner-consistent anchor whose verified blob's digest
//!   matches: the [`ReplayCursor`] advances by one `MemoryId`.
//!
//! "Replay never guesses": every anchor is exactly one of those five outcomes,
//! and none of them panics.

use mnemos_c_walrus::MoveAnchorArgsV1;
use mnemos_d_move::{AuditAppendArgs, MemoryRootAnchorArgs, ObjectId};

use crate::chunk::MemoryId;
use crate::replay::ReplayCursor;
use crate::signed_chunk::StageBSignedChunkV1;

use super::blob_fetch::{BlobFetchOutcome, ReplayBlobIndex, fetch_for_anchor};

/// Replay input — the on-chain anchor and audit streams (already normalized
/// into on-chain order by the normalizer) plus the set of published signed
/// chunks the anchors point at.
///
/// The `anchors` / `audit` vectors are assumed to be in canonical
/// [`StageBEventCoord`](super::events::StageBEventCoord) order; build them from
/// [`normalize_event_stream`](super::events::normalize_event_stream) so the
/// replay (and its transcript hash) is invariant to RPC fetch order.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StageBReplayInput {
    /// Ordered `ChunkAnchored` call-args.
    pub anchors: Vec<MemoryRootAnchorArgs>,
    /// Ordered `AuditAppended` call-args.
    pub audit: Vec<AuditAppendArgs>,
    /// The published signed chunks the anchors are verified against.
    pub blobs: Vec<StageBSignedChunkV1>,
}

/// Replay state — the Stage A [`ReplayCursor`] wrapped with Stage B
/// progress counters.
///
/// `cursor` is the canonical Stage A crash-recovery cursor: its
/// `recovered_u32` equals the number of applied (unique, verified) chunk anchors
/// and its `last_id` is the last `MemoryId` produced. `event_seq_u64` counts
/// every event *observed* (applied or not); `chunk_count_u64` counts only
/// applied chunk anchors.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct StageBReplayState {
    /// Stage A crash-recovery cursor over the applied `MemoryId` sequence.
    pub cursor: ReplayCursor,
    /// Count of events observed (anchors + audit), applied or rejected.
    pub event_seq_u64: u64,
    /// Count of applied (unique, verified) chunk anchors.
    pub chunk_count_u64: u64,
}

impl StageBReplayState {
    /// Empty starting state: the [`ReplayCursor::start`] sentinel and zero
    /// counters.
    #[inline]
    pub const fn start() -> Self {
        Self {
            cursor: ReplayCursor::start(),
            event_seq_u64: 0,
            chunk_count_u64: 0,
        }
    }
}

/// Per-anchor / per-event decision. `#[repr(u8)]` with fixed
/// discriminants (`Applied=1 … OwnerMismatch=5`) so the value is byte-stable for
/// the transcript hash and any future cross-language mirror.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum StageBReplayDecision {
    /// A fresh, owner-consistent, verified anchor was applied (cursor advanced),
    /// or a consistent audit append was accepted.
    Applied = 1,
    /// An anchor identical to one already applied — ignored idempotently.
    DuplicateIgnored = 2,
    /// No published blob derives to the anchor's claimed blob id.
    MissingBlob = 3,
    /// A blob matched the claimed id but its digest did not match the anchored
    /// digest.
    DigestMismatch = 4,
    /// The event targets a different `MemoryRoot` / `AuditLog` than the one this
    /// replay is bound to.
    OwnerMismatch = 5,
}

impl StageBReplayDecision {
    /// The discriminant byte. Used by the transcript hash.
    #[inline]
    pub const fn as_u8(self) -> u8 {
        self as u8
    }
}

/// The owner-object binding a replay establishes from its first events: the
/// single `MemoryRoot` its anchors target and the single `AuditLog` its audit
/// events target.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) struct ReplayBinding {
    root: Option<ObjectId>,
    log: Option<ObjectId>,
}

impl ReplayBinding {
    /// A binding with no root/log fixed yet.
    #[inline]
    pub(crate) const fn new() -> Self {
        Self {
            root: None,
            log: None,
        }
    }

    /// Bind / check the `MemoryRoot`. Returns `true` if `root` is consistent with
    /// the binding (always `true` for the first anchor, which fixes it).
    fn bind_root(&mut self, root: &ObjectId) -> bool {
        match &self.root {
            None => {
                self.root = Some(*root);
                true
            }
            Some(bound) => bound.as_bytes() == root.as_bytes(),
        }
    }

    /// Bind / check the `AuditLog`. Returns `true` if `log` is consistent with the
    /// binding (always `true` for the first audit event, which fixes it).
    fn bind_log(&mut self, log: &ObjectId) -> bool {
        match &self.log {
            None => {
                self.log = Some(*log);
                true
            }
            Some(bound) => bound.as_bytes() == log.as_bytes(),
        }
    }
}

/// Apply one chunk anchor to the replay, returning its decision and advancing
/// `state` / `applied_ids` / `seen` only on [`StageBReplayDecision::Applied`].
///
/// `seen` holds the `(blob_id, kind, parent)` keys of anchors already applied
/// (the idempotent-dedup set); `applied_ids` is the growing `MemoryId` sequence
/// whose numbering matches Stage A's
/// [`replay_from_anchors`](crate::replay::replay_from_anchors) (index `n` → the
/// `n`-th unique applied anchor).
pub(crate) fn apply_anchor(
    anchor: &MemoryRootAnchorArgs,
    index: &ReplayBlobIndex<'_>,
    binding: &mut ReplayBinding,
    seen: &mut Vec<MoveAnchorArgsV1>,
    applied_ids: &mut Vec<MemoryId>,
    state: &mut StageBReplayState,
) -> StageBReplayDecision {
    state.event_seq_u64 = state.event_seq_u64.saturating_add(1);

    // (1) owner binding: a foreign root is refused before anything else.
    if !binding.bind_root(anchor.root()) {
        return StageBReplayDecision::OwnerMismatch;
    }

    // (2) idempotent duplicate: same anchor already applied → ignore.
    let anchor_key: MoveAnchorArgsV1 = *anchor.anchor();
    if seen.iter().any(|existing| existing == &anchor_key) {
        return StageBReplayDecision::DuplicateIgnored;
    }

    // (3) verified-blob + digest match.
    match fetch_for_anchor(index, anchor) {
        BlobFetchOutcome::MissingBlob => StageBReplayDecision::MissingBlob,
        BlobFetchOutcome::DigestMismatch => StageBReplayDecision::DigestMismatch,
        BlobFetchOutcome::Verified(_chunk) => {
            seen.push(anchor_key);
            // MemoryId numbering matches replay_from_anchors: 0-based per unique
            // applied anchor.
            let next = MemoryId::new(applied_ids.len() as u64);
            applied_ids.push(next);
            state.chunk_count_u64 = state.chunk_count_u64.saturating_add(1);
            state.cursor = ReplayCursor::from_replay(applied_ids);
            StageBReplayDecision::Applied
        }
    }
}

/// Apply one audit append to the replay, returning its decision. Audit events
/// carry no blob; they only bind the `AuditLog` and are accepted when consistent.
pub(crate) fn apply_audit(
    audit: &AuditAppendArgs,
    binding: &mut ReplayBinding,
    state: &mut StageBReplayState,
) -> StageBReplayDecision {
    state.event_seq_u64 = state.event_seq_u64.saturating_add(1);
    if binding.bind_log(audit.log()) {
        StageBReplayDecision::Applied
    } else {
        StageBReplayDecision::OwnerMismatch
    }
}
