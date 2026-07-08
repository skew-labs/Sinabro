//! Transcript hash determinism + replay report + the top-level
//! [`replay_stage_b`].
//!
//! Canonical OUT: [`StageBTranscriptHash32`], [`StageBReplayReport`], and
//! [`replay_stage_b`].
//!
//! Invariant: *the same inputs always produce the same
//! transcript hash across process restarts and event fetch order.* Offline; no
//! live egress.
//!
//! ## How determinism is achieved
//!
//! `replay_stage_b` walks the (already coordinate-normalized) anchor stream
//! then the audit stream, recording one fixed-width record per event into a
//! transcript buffer: a stream tag, the observed `event_seq`, the
//! [`StageBReplayDecision`] discriminant, and the event's identifying 32-byte
//! fields (anchor: `blob_id ‖ digest ‖ root`; audit: `log ‖ entry_hash`). The
//! buffer is then hashed once with the crate's domain-separated ARX content hash
//! ([`derive_walrus_blob_id`], the same primitive that derives blob
//! ids), under a replay-transcript domain tag.
//!
//! Because the input order is canonical (sorted by event coordinate before the
//! input is built) and the per-event record is a pure function of the event and
//! its decision, two honest replays of the same on-chain history — in any RPC
//! fetch order, across process restarts — produce the **same** 32 bytes. Any
//! single-bit change to any recorded field changes the hash.

use crate::stage_b_blob_id::derive_walrus_blob_id;

use super::StageBReplayError;
use super::cursor::{
    ReplayBinding, StageBReplayDecision, StageBReplayInput, StageBReplayState, apply_anchor,
    apply_audit,
};
use mnemos_c_walrus::MoveAnchorArgsV1;

/// Domain tag mixed in front of the transcript bytes so a replay transcript hash
/// can never collide with a blob-id derivation or any other ARX use.
const STAGE_B_REPLAY_TRANSCRIPT_DOMAIN: &[u8] = b"mnemos.stage_b.replay.transcript.v1";

/// Stream tag for a `ChunkAnchored` record in the transcript.
const TRANSCRIPT_TAG_ANCHOR: u8 = 0x00;
/// Stream tag for an `AuditAppended` record in the transcript.
const TRANSCRIPT_TAG_AUDIT: u8 = 0x01;

/// Transcript hash — a 32-byte deterministic digest of a full replay.
///
/// `#[repr(transparent)]` over `[u8; 32]` with private inner bytes (mirrors
/// [`ChunkDigest32`](crate::chunk_digest::ChunkDigest32)): a value can only be
/// produced by [`stage_b_transcript_hash`] / [`replay_stage_b`], never minted
/// from an arbitrary array.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
#[repr(transparent)]
pub struct StageBTranscriptHash32([u8; 32]);

impl StageBTranscriptHash32 {
    /// Borrow the 32-byte transcript hash.
    #[inline]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// Replay report — the transcript hash plus the applied / duplicate /
/// rejected event counts.
///
/// `applied_u64` counts every event accepted (verified chunk anchors **and**
/// consistent audit appends); `duplicate_u64` counts idempotently-ignored
/// anchors; `rejected_u64` counts every other decision (missing blob, digest
/// mismatch, owner mismatch). The three counts sum to the total event count.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct StageBReplayReport {
    /// Deterministic 32-byte transcript hash of the whole replay.
    pub transcript: StageBTranscriptHash32,
    /// Count of applied (accepted) events.
    pub applied_u64: u64,
    /// Count of idempotently-ignored duplicate anchors.
    pub duplicate_u64: u64,
    /// Count of rejected events (missing blob / digest mismatch / owner mismatch).
    pub rejected_u64: u64,
}

/// Hash a finished transcript byte buffer under the replay-transcript domain.
///
/// Exposed (alongside [`replay_stage_b`]) so the criterion bench can measure the
/// hash throughput directly; production callers use [`replay_stage_b`].
#[inline]
pub fn stage_b_transcript_hash(records: &[u8]) -> StageBTranscriptHash32 {
    // AI-HOT: transcript-hash throughput is measured by
    // `benches/stage_b_replay_transcript.rs` (criterion). The hot work
    // is the ARX content hash inside `derive_walrus_blob_id`; this wrapper only
    // prepends the domain tag.
    let mut buf: Vec<u8> =
        Vec::with_capacity(STAGE_B_REPLAY_TRANSCRIPT_DOMAIN.len() + records.len());
    buf.extend_from_slice(STAGE_B_REPLAY_TRANSCRIPT_DOMAIN);
    buf.extend_from_slice(records);
    let id = derive_walrus_blob_id(&buf);
    StageBTranscriptHash32(*id.as_bytes())
}

/// Append one anchor record to the transcript buffer.
fn push_anchor_record(
    buf: &mut Vec<u8>,
    event_seq_u64: u64,
    decision: StageBReplayDecision,
    anchor: &mnemos_d_move::MemoryRootAnchorArgs,
) {
    buf.push(TRANSCRIPT_TAG_ANCHOR);
    buf.extend_from_slice(&event_seq_u64.to_le_bytes());
    buf.push(decision.as_u8());
    let claimed: MoveAnchorArgsV1 = *anchor.anchor();
    buf.extend_from_slice(claimed.blob_id.as_bytes());
    buf.extend_from_slice(anchor.digest());
    buf.extend_from_slice(anchor.root().as_bytes());
}

/// Append one audit record to the transcript buffer.
fn push_audit_record(
    buf: &mut Vec<u8>,
    event_seq_u64: u64,
    decision: StageBReplayDecision,
    audit: &mnemos_d_move::AuditAppendArgs,
) {
    buf.push(TRANSCRIPT_TAG_AUDIT);
    buf.extend_from_slice(&event_seq_u64.to_le_bytes());
    buf.push(decision.as_u8());
    buf.extend_from_slice(audit.log().as_bytes());
    buf.extend_from_slice(audit.entry_hash());
}

/// Replay the Stage B custody chain from a normalized input, producing a
/// deterministic [`StageBReplayReport`].
///
/// Walks the anchor stream then the audit stream, applying each event through the
/// state machine, recording a transcript, and hashing it once. Returns
/// [`StageBReplayError::EventCountOverflow`] if either stream is longer than
/// `u32::MAX` (the per-stream coordinate uniqueness and len32 invariants are
/// established earlier, by the normalizer that builds the input).
pub fn replay_stage_b(input: &StageBReplayInput) -> Result<StageBReplayReport, StageBReplayError> {
    if input.anchors.len() > u32::MAX as usize || input.audit.len() > u32::MAX as usize {
        return Err(StageBReplayError::EventCountOverflow);
    }

    let index = super::blob_fetch::ReplayBlobIndex::build(&input.blobs);
    let mut binding = ReplayBinding::new();
    let mut seen: Vec<MoveAnchorArgsV1> = Vec::new();
    let mut applied_ids: Vec<crate::chunk::MemoryId> = Vec::new();
    let mut state = StageBReplayState::start();

    let mut applied_u64: u64 = 0;
    let mut duplicate_u64: u64 = 0;
    let mut rejected_u64: u64 = 0;
    let mut transcript: Vec<u8> = Vec::new();

    for anchor in &input.anchors {
        let decision = apply_anchor(
            anchor,
            &index,
            &mut binding,
            &mut seen,
            &mut applied_ids,
            &mut state,
        );
        push_anchor_record(&mut transcript, state.event_seq_u64, decision, anchor);
        match decision {
            StageBReplayDecision::Applied => applied_u64 = applied_u64.saturating_add(1),
            StageBReplayDecision::DuplicateIgnored => {
                duplicate_u64 = duplicate_u64.saturating_add(1);
            }
            _ => rejected_u64 = rejected_u64.saturating_add(1),
        }
    }

    for audit in &input.audit {
        let decision = apply_audit(audit, &mut binding, &mut state);
        push_audit_record(&mut transcript, state.event_seq_u64, decision, audit);
        match decision {
            StageBReplayDecision::Applied => applied_u64 = applied_u64.saturating_add(1),
            StageBReplayDecision::DuplicateIgnored => {
                duplicate_u64 = duplicate_u64.saturating_add(1);
            }
            _ => rejected_u64 = rejected_u64.saturating_add(1),
        }
    }

    Ok(StageBReplayReport {
        transcript: stage_b_transcript_hash(&transcript),
        applied_u64,
        duplicate_u64,
        rejected_u64,
    })
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use super::*;

    #[test]
    fn b5_3_same_bytes_same_hash() {
        let records = b"a deterministic replay transcript buffer";
        let h1 = stage_b_transcript_hash(records);
        let h2 = stage_b_transcript_hash(records);
        assert_eq!(h1, h2, "same transcript bytes must hash identically");
    }

    #[test]
    fn b5_3_single_bit_flip_changes_hash() {
        let mut records = vec![0u8; 200];
        records[123] = 0x10;
        let base = stage_b_transcript_hash(&records);
        records[123] ^= 0x01; // flip one bit
        let flipped = stage_b_transcript_hash(&records);
        assert_ne!(
            base, flipped,
            "a one-bit change in the transcript must change the hash"
        );
    }

    #[test]
    fn b5_3_domain_separation() {
        // The domain tag must make the transcript hash differ from a bare
        // blob-id derivation of the same bytes.
        let records = b"domain separation check";
        let transcript = stage_b_transcript_hash(records);
        let bare = derive_walrus_blob_id(records);
        assert_ne!(
            transcript.as_bytes(),
            bare.as_bytes(),
            "transcript hash must be domain-separated from blob-id derivation"
        );
    }
}
