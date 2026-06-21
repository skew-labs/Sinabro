//! #164 (B.5.1) — Walrus blob fetch + signed chunk decode + digest match.
//!
//! Canonical OUT (plan #164): fetch verified blobs and decode
//! [`StageBSignedChunkV1`]. Madness clause: *replay uses verified blob id only;
//! the decoded chunk digest must match the event digest.*
//!
//! ## Verified blob id only
//!
//! The on-chain `ChunkAnchored` event carries a *claimed* `blob_id`
//! ([`MoveAnchorArgsV1::blob_id`](mnemos_c_walrus::MoveAnchorArgsV1)). Replay
//! never trusts that claim directly. Instead it re-encodes each available signed
//! chunk (atom #91 [`encode_stage_b_chunk`]) and derives the blob id **locally**
//! (atom #108 [`derive_walrus_blob_id`]). A claimed `blob_id` is honored only if
//! some local chunk derives to exactly that id — the same "server is not an
//! oracle" rule [`stage_b_verify_blob_id`](crate::stage_b_blob_id::stage_b_verify_blob_id)
//! enforces on the live PUT path, applied here on the replay/GET path.
//!
//! ## Digest must match
//!
//! Finding a blob whose derived id matches the anchor is necessary but not
//! sufficient: the anchor also carries a 32-byte content `digest`. The blob's own
//! committed [`ChunkDigest32`](crate::chunk_digest::ChunkDigest32) must equal it,
//! or the anchor and the blob disagree about what was published and the anchor is
//! refused as a [`DigestMismatch`](BlobFetchOutcome::DigestMismatch). This is the
//! defense against an on-chain anchor whose digest was forged to point a real
//! blob id at a different claimed content commitment.
//!
//! Offline by construction: this module derives and compares in memory. The live
//! Walrus GET (#168) supplies the bytes through the separate ceremony rail and
//! then runs this exact verification.

use mnemos_c_walrus::{BlobId, ChunkCodecError};
use mnemos_d_move::MemoryRootAnchorArgs;

use crate::chunk_codec::encode_stage_b_chunk;
use crate::signed_chunk::StageBSignedChunkV1;
use crate::stage_b_blob_id::derive_walrus_blob_id;

/// Derive the canonical Walrus blob id of a signed chunk by re-encoding its
/// envelope (atom #91) and running the local derive (atom #108).
///
/// This is the **verified** id — locally recomputed from the bytes, never a
/// server- or chain-reported string. Returns the underlying
/// [`ChunkCodecError`] if the envelope is not canonically encodable (a chunk
/// that cannot round-trip cannot be matched to any anchor).
#[inline]
pub fn derive_chunk_blob_id(chunk: &StageBSignedChunkV1) -> Result<BlobId, ChunkCodecError> {
    let encoded = encode_stage_b_chunk(&chunk.envelope)?;
    Ok(derive_walrus_blob_id(&encoded))
}

/// An index of the published blobs available to a replay, keyed by their
/// **locally-derived** blob id.
///
/// Built once at the start of a replay over the
/// [`StageBReplayInput::blobs`](super::cursor::StageBReplayInput::blobs) set. A
/// blob whose envelope cannot re-encode is silently dropped from the index, so an
/// anchor that points at it resolves to
/// [`MissingBlob`](BlobFetchOutcome::MissingBlob) — the fail-closed outcome,
/// never a panic.
pub struct ReplayBlobIndex<'a> {
    entries: Vec<(BlobId, &'a StageBSignedChunkV1)>,
}

impl<'a> ReplayBlobIndex<'a> {
    /// Derive and index every blob. Non-encodable blobs are skipped.
    pub fn build(blobs: &'a [StageBSignedChunkV1]) -> Self {
        let mut entries: Vec<(BlobId, &'a StageBSignedChunkV1)> = Vec::with_capacity(blobs.len());
        for blob in blobs {
            if let Ok(id) = derive_chunk_blob_id(blob) {
                entries.push((id, blob));
            }
        }
        Self { entries }
    }

    /// Number of indexed (encodable) blobs.
    #[inline]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether the index is empty.
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Look up a blob by its locally-derived id. Linear scan (Phase 0 input
    /// sizes; no `std::collections`, mirroring atom #32's dedup style).
    fn get(&self, id: &BlobId) -> Option<&'a StageBSignedChunkV1> {
        self.entries
            .iter()
            .find(|(key, _)| key.as_bytes() == id.as_bytes())
            .map(|(_, blob)| *blob)
    }
}

/// The outcome of resolving one anchor against a [`ReplayBlobIndex`].
///
/// These map onto the per-anchor
/// [`StageBReplayDecision`](super::cursor::StageBReplayDecision) at the cursor:
/// [`Verified`](Self::Verified) → `Applied`, [`MissingBlob`](Self::MissingBlob)
/// → `MissingBlob`, [`DigestMismatch`](Self::DigestMismatch) → `DigestMismatch`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BlobFetchOutcome<'a> {
    /// A blob whose derived id equals the anchor's claimed id **and** whose
    /// committed digest equals the anchored digest. Carries the verified chunk.
    Verified(&'a StageBSignedChunkV1),
    /// No indexed blob derives to the anchor's claimed blob id.
    MissingBlob,
    /// A blob matched the claimed blob id, but its committed digest did not equal
    /// the anchored digest.
    DigestMismatch,
}

/// Resolve one anchor against the blob index: verified-id match, then digest
/// match. Pure and total.
pub fn fetch_for_anchor<'a>(
    index: &ReplayBlobIndex<'a>,
    anchor: &MemoryRootAnchorArgs,
) -> BlobFetchOutcome<'a> {
    // The claimed blob id is the on-chain anchor's `MoveAnchorArgsV1.blob_id`.
    let claimed: BlobId = anchor.anchor().blob_id;
    match index.get(&claimed) {
        None => BlobFetchOutcome::MissingBlob,
        Some(chunk) => {
            // Digest must match the anchored digest byte-for-byte.
            if chunk.digest().as_bytes() == anchor.digest() {
                BlobFetchOutcome::Verified(chunk)
            } else {
                BlobFetchOutcome::DigestMismatch
            }
        }
    }
}
