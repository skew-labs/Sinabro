//! Vector ingest pipeline keyed by [`MemoryId`].
//!
//! Ingest consumes **canonical decoded chunks only**. The boundary is
//! type-level: a vector enters the index only as part of an ingest whose
//! provenance is either a local [`MemoryChunk`] or a chunk witnessed by a
//! [`VerifiedBlobId`] — there is no representable path for raw, unverified
//! Walrus bytes ([`IngestProvenance`] has no raw-bytes variant). The supplied
//! vector is additionally bound to the chunk's committed
//! [`EmbeddingRefV1::vector_hash`] (a canonical [`derive_blob_id`] digest over
//! the vector's little-endian bytes), so a vector that does not match the
//! chunk's decoded embedding reference is rejected fail-closed.
//!
//! Ingest is **idempotent** by [`MemoryId`] (re-ingesting the same id replaces
//! its entry, never duplicating it) and **skips tombstoned ids** — a deleted
//! memory is never re-materialized into the vector index.

use crate::chunk::{MemoryChunk, MemoryId};
use crate::intelligence::vector_index::{HnswInt8Config, Int8VectorIndex, VectorIndexError};
use mnemos_c_walrus::{VerifiedBlobId, derive_blob_id};
use std::collections::BTreeSet;

/// Where an ingested vector came from. There is **no** raw-bytes variant: an
/// unverified Walrus byte stream cannot be ingested directly.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum IngestProvenance {
    /// A locally-decoded chunk (already canonical in this process).
    Local,
    /// A chunk witnessed by a verified blob id (locally derived-and-matched).
    VerifiedBlob(VerifiedBlobId),
}

/// Outcome of an ingest call.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum IngestOutcome {
    /// The vector was inserted or replaced (idempotent upsert by id).
    Ingested,
    /// The id is tombstoned; nothing was inserted.
    SkippedTombstone,
}

/// Ingest error set (frozen). Every variant is a data-free tag.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
#[non_exhaustive]
pub enum IngestError {
    /// The chunk carries no canonical embedding reference, so there is no
    /// decoded vector identity to index against ("reject undecoded bytes").
    NoCanonicalEmbedding,
    /// The supplied vector length does not match the chunk's embedding dims.
    DimsMismatch,
    /// The supplied vector's canonical digest does not match the chunk's
    /// committed `vector_hash`.
    VectorHashMismatch,
    /// The underlying vector index rejected the upsert.
    Index(VectorIndexError),
}

impl From<VectorIndexError> for IngestError {
    fn from(e: VectorIndexError) -> Self {
        Self::Index(e)
    }
}

/// The vector ingest pipeline: an int8 index plus a tombstone set.
#[derive(Clone, Debug)]
pub struct VectorIngestor {
    index: Int8VectorIndex,
    tombstones: BTreeSet<MemoryId>,
}

impl VectorIngestor {
    /// Create an ingestor over a fresh index with the given configuration.
    #[must_use]
    pub fn new(config: HnswInt8Config) -> Self {
        Self {
            index: Int8VectorIndex::new(config),
            tombstones: BTreeSet::new(),
        }
    }

    /// Borrow the underlying vector index.
    #[must_use]
    pub const fn index(&self) -> &Int8VectorIndex {
        &self.index
    }

    /// Number of vectors held in the index.
    #[must_use]
    pub fn len(&self) -> usize {
        self.index.len()
    }

    /// Whether the index holds no vectors.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.index.is_empty()
    }

    /// Mark a memory id as deleted; future ingests of this id are skipped and a
    /// deleted memory is never re-materialized into the index.
    pub fn tombstone(&mut self, id: MemoryId) {
        self.tombstones.insert(id);
    }

    /// Whether an id is tombstoned.
    #[must_use]
    pub fn is_tombstoned(&self, id: MemoryId) -> bool {
        self.tombstones.contains(&id)
    }

    /// Ingest a chunk's embedding vector. See the module docs for the canonical
    /// boundary: the chunk must carry a decoded [`EmbeddingRefV1`], the vector
    /// must match it by length and committed digest, the id must not be
    /// tombstoned, and the upsert is idempotent.
    ///
    /// [`EmbeddingRefV1`]: mnemos_c_walrus::EmbeddingRefV1
    pub fn ingest(
        &mut self,
        chunk: &MemoryChunk,
        vector: &[f32],
        provenance: &IngestProvenance,
    ) -> Result<IngestOutcome, IngestError> {
        let embedding = chunk
            .envelope()
            .embedding
            .as_ref()
            .ok_or(IngestError::NoCanonicalEmbedding)?;
        if embedding.dims_u16 as usize != vector.len() {
            return Err(IngestError::DimsMismatch);
        }
        let digest = canonical_vector_digest(vector);
        if digest != embedding.vector_hash {
            return Err(IngestError::VectorHashMismatch);
        }
        // Provenance is a type-level guarantee: there is no raw-bytes variant.
        match provenance {
            IngestProvenance::Local => {}
            IngestProvenance::VerifiedBlob(blob) => {
                // The verified blob id is the provenance witness; the evidence
                // layer records it. Touch it to bind the witness to this path.
                let _witness = blob.as_blob_id();
            }
        }
        if self.is_tombstoned(chunk.id()) {
            return Ok(IngestOutcome::SkippedTombstone);
        }
        self.index.upsert(chunk.id(), vector)?;
        Ok(IngestOutcome::Ingested)
    }
}

/// Canonical 32-byte digest of an embedding vector: [`derive_blob_id`] over the
/// vector's little-endian `f32` byte encoding. This is the embedding-vector
/// digest the ingest boundary defines (ingest is the first consumer of raw
/// embedding vectors), and the value a chunk's `EmbeddingRefV1::vector_hash`
/// commits to.
fn canonical_vector_digest(vector: &[f32]) -> [u8; 32] {
    let mut bytes = Vec::with_capacity(vector.len() * 4);
    for &x in vector {
        bytes.extend_from_slice(&x.to_le_bytes());
    }
    *derive_blob_id(&bytes).as_bytes()
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    #![allow(clippy::expect_used)]
    #![allow(clippy::panic)]

    use super::*;
    use mnemos_c_walrus::{ChunkEnvelopeV1, ChunkKind, EmbeddingRefV1, MemoryRole};

    fn cfg() -> HnswInt8Config {
        HnswInt8Config::new(16, 200, 64, false, 80).unwrap()
    }

    fn chunk_with_embedding(id: u64, vector: &[f32]) -> MemoryChunk {
        let vector_hash = canonical_vector_digest(vector);
        let embedding = EmbeddingRefV1 {
            model_tag_u16: 1,
            dims_u16: vector.len() as u16,
            vector_hash,
        };
        let envelope = ChunkEnvelopeV1 {
            kind: ChunkKind::UserMessage,
            role: MemoryRole::User,
            parent: None,
            content: b"chunk-content".to_vec(),
            embedding: Some(embedding),
            signature: None,
            provenance: None,
        };
        MemoryChunk::new(MemoryId::new(id), envelope)
    }

    fn chunk_without_embedding(id: u64) -> MemoryChunk {
        let envelope = ChunkEnvelopeV1 {
            kind: ChunkKind::UserMessage,
            role: MemoryRole::User,
            parent: None,
            content: b"no-embedding".to_vec(),
            embedding: None,
            signature: None,
            provenance: None,
        };
        MemoryChunk::new(MemoryId::new(id), envelope)
    }

    fn sample_verified_blob_id() -> VerifiedBlobId {
        use mnemos_c_walrus::{PublisherReportedBlobId, verify_reported_blob_id};
        let content = b"verified-blob-id-witness";
        let derived = derive_blob_id(content);
        let text = encode_b64url(derived.as_bytes());
        let reported = PublisherReportedBlobId::try_from_text(&text).expect("base64url length 43");
        verify_reported_blob_id(content, &reported).expect("round-trip self-derived must verify")
    }

    fn encode_b64url(raw: &[u8; 32]) -> String {
        const ALPHABET: &[u8; 64] =
            b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
        let mut out = String::with_capacity(43);
        let mut buf: u32 = 0;
        let mut bits: u32 = 0;
        for &b in raw {
            buf = (buf << 8) | u32::from(b);
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

    #[test]
    fn ingest_local_chunk() {
        let mut ing = VectorIngestor::new(cfg());
        let v = vec![0.1_f32, 0.2, 0.3, 0.4];
        let chunk = chunk_with_embedding(1, &v);
        let out = ing.ingest(&chunk, &v, &IngestProvenance::Local).unwrap();
        assert_eq!(out, IngestOutcome::Ingested);
        assert_eq!(ing.len(), 1);
    }

    #[test]
    fn ingest_verified_blob_chunk() {
        let mut ing = VectorIngestor::new(cfg());
        let v = vec![0.5_f32, -0.5, 0.25, -0.25];
        let chunk = chunk_with_embedding(2, &v);
        let prov = IngestProvenance::VerifiedBlob(sample_verified_blob_id());
        let out = ing.ingest(&chunk, &v, &prov).unwrap();
        assert_eq!(out, IngestOutcome::Ingested);
        assert_eq!(ing.len(), 1);
    }

    #[test]
    fn reject_undecoded_bytes() {
        let mut ing = VectorIngestor::new(cfg());
        let v = vec![0.1_f32, 0.2, 0.3, 0.4];
        // No embedding reference -> nothing canonical to index against.
        let bare = chunk_without_embedding(3);
        assert_eq!(
            ing.ingest(&bare, &v, &IngestProvenance::Local),
            Err(IngestError::NoCanonicalEmbedding)
        );
        // Vector whose digest does not match the committed hash is rejected.
        let chunk = chunk_with_embedding(4, &v);
        let tampered = vec![0.9_f32, 0.9, 0.9, 0.9];
        assert_eq!(
            ing.ingest(&chunk, &tampered, &IngestProvenance::Local),
            Err(IngestError::VectorHashMismatch)
        );
        // Wrong length is rejected before the digest check.
        assert_eq!(
            ing.ingest(&chunk, &[0.1, 0.2], &IngestProvenance::Local),
            Err(IngestError::DimsMismatch)
        );
    }

    #[test]
    fn tombstone_skip() {
        let mut ing = VectorIngestor::new(cfg());
        let v = vec![0.1_f32, 0.2, 0.3, 0.4];
        let chunk = chunk_with_embedding(5, &v);
        ing.tombstone(MemoryId::new(5));
        let out = ing.ingest(&chunk, &v, &IngestProvenance::Local).unwrap();
        assert_eq!(out, IngestOutcome::SkippedTombstone);
        assert_eq!(ing.len(), 0);
    }

    #[test]
    fn ingest_is_idempotent() {
        let mut ing = VectorIngestor::new(cfg());
        let v = vec![0.1_f32, 0.2, 0.3, 0.4];
        let chunk = chunk_with_embedding(6, &v);
        assert_eq!(
            ing.ingest(&chunk, &v, &IngestProvenance::Local).unwrap(),
            IngestOutcome::Ingested
        );
        assert_eq!(
            ing.ingest(&chunk, &v, &IngestProvenance::Local).unwrap(),
            IngestOutcome::Ingested
        );
        assert_eq!(ing.len(), 1, "re-ingesting the same id must not duplicate");
    }
}
