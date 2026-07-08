//! Stage B replay — deterministic crash-recovery
//! replay of the Stage B custody chain.
//!
//! The Stage B custody chain is: a memory owner's [`StageBSignedChunkV1`] is
//! published to Walrus, the locally-derived [`VerifiedBlobId`] is anchored on
//! Sui (`memory_root::add_chunk` → `ChunkAnchored`), and the audit entry hash is
//! appended (`audit_log::append` → `AuditAppended`). After a crash, the local
//! store is rebuilt **only** from that on-chain event stream plus the verified
//! blobs it points at — never from local best-effort state.
//!
//! This module turns that recovery into a *deterministic, fail-closed* pipeline
//! so two honest replays of the same on-chain history always produce the same
//! transcript hash, and any malformed / tampered / missing input is either an
//! exact per-anchor [`StageBReplayDecision`] or a whole-stream
//! [`StageBReplayError`] — never a panic and never a silent guess.
//!
//! Submodules:
//! - [`events`][]: normalize the on-chain `ChunkAnchored` / `AuditAppended`
//!   stream into a totally-ordered, len32-validated form.
//! - [`blob_fetch`][]: fetch by [`VerifiedBlobId`] only and decode the
//!   signed chunk, checking the decoded digest against the anchored digest.
//! - [`cursor`][]: the replay state machine that reuses the Stage A
//!   [`ReplayCursor`](crate::replay::ReplayCursor) and yields one decision per
//!   anchor.
//! - [`transcript`][]: the deterministic transcript hash + replay report,
//!   and the top-level [`replay_stage_b`].
//!
//! Offline by construction: nothing in this module performs network or wallet
//! I/O. The one approved live roundtrip drives this code from a separate
//! script + evidence ceremony rail, not from inside a `cargo test`.

pub mod blob_fetch;
pub mod cursor;
pub mod events;
pub mod transcript;

pub use blob_fetch::{BlobFetchOutcome, ReplayBlobIndex, derive_chunk_blob_id, fetch_for_anchor};
pub use cursor::{StageBReplayDecision, StageBReplayInput, StageBReplayState};
pub use events::{
    NormalizedEventStream, StageBAuditAppendedEvent, StageBChunkAnchoredEvent, StageBEventCoord,
    normalize_event_stream,
};
pub use transcript::{
    StageBReplayReport, StageBTranscriptHash32, replay_stage_b, stage_b_transcript_hash,
};

/// Replay error — the **whole-stream abort** conditions for
/// [`replay_stage_b`] and the normalizer.
///
/// These are structural malformations of the *event stream itself*: a replay
/// that hits one of them cannot be trusted at all, so it is refused outright.
/// They are distinct from a per-anchor [`StageBReplayDecision`] (apply / ignore
/// duplicate / missing blob / digest mismatch / owner mismatch), which is a
/// *recorded, counted* outcome for a single anchor against an otherwise
/// well-formed stream.
///
/// `Copy` + no owned bytes (mirrors
/// [`StageBChunkError`](crate::chunk_digest::StageBChunkError) and
/// [`ChunkCodecError`](mnemos_c_walrus::ChunkCodecError)): the error channel
/// cannot leak a raw body or a private substring through `Debug`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum StageBReplayError {
    /// An on-chain event field that must be exactly 32 bytes
    /// ([`STAGE_B_MOVE_VEC_LEN`](mnemos_d_move::STAGE_B_MOVE_VEC_LEN)) arrived
    /// with a different length (`blob_id`, `parent`, `digest`, `entry_hash`,
    /// `root`, or `log`). A short or absent fixed-width field is a truncated or
    /// forged event, so the whole replay is refused rather than zero-padded.
    MissingLen32Field,
    /// Two distinct events carried the same
    /// `(checkpoint, tx_digest, event_seq)` coordinate. An event id is unique
    /// on-chain; a collision means the stream was mis-assembled or tampered
    /// with, so the order it implies cannot be trusted.
    DuplicateEventId,
    /// The event stream length exceeded `u32::MAX` and cannot be counted in the
    /// saturating `u32`/`u64` counters of the [`StageBReplayReport`]. Rejected
    /// before any allocation, mirroring
    /// [`replay_from_anchors`](crate::replay::replay_from_anchors).
    EventCountOverflow,
}

impl StageBReplayError {
    /// Stable, allow-listed `class_label` for diagnostic JSON envelopes,
    /// mirroring
    /// [`StageBChunkError::class_label`](crate::chunk_digest::StageBChunkError::class_label).
    /// The label set is frozen and content-free.
    #[inline]
    pub const fn class_label(self) -> &'static str {
        match self {
            Self::MissingLen32Field => "replay_missing_len32_field",
            Self::DuplicateEventId => "replay_duplicate_event_id",
            Self::EventCountOverflow => "replay_event_count_overflow",
        }
    }
}
