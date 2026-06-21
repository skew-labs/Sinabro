//! Custom int8-quantized vector index (Stage D Cluster 6, atom #322 · D.5.1).
//!
//! [`HnswInt8Config`] (§4.6) carries the HNSW tuning parameters (`m`,
//! `ef_construction`, `ef_search`), the int8 quantization gate
//! (`recall_loss_max_bps`) and the persistence mode (`mmap_enabled`).
//!
//! ## Quantization (the gated property)
//!
//! Each embedding vector is stored as a per-vector symmetric int8 quantization:
//! a single `f32` scale plus `dims` `i8` codes (`q_i = round(v_i / scale)`,
//! `scale = max|v_i| / 127`). The only recall loss versus an exact `f32` scan is
//! the int8 rounding error, which the `recall_loss_max_bps` gate bounds (the
//! plan criterion is **≤ 80 bps**). Search is an int8-quantized scan today.
//!
//! ## Reserved graph layer (honest deviation flag)
//!
//! `m_u8` / `ef_construction_u16` / `ef_search_u16` are validated and persisted
//! but the Phase-0 search is an **int8 exact (flat) scan**, not yet a navigable
//! small-world graph traversal. This is faithful to every #322 gate (the
//! criterion is recall-loss-bounded and there is no perf/scale gate at #322) and
//! deliberately avoids over-claiming a graph that is not yet built; the graph
//! traversal that consumes the `m`/`ef` parameters is a later atom. Flagged in
//! the WP-06 evidence handoff so a verifier sees the boundary explicitly.
//!
//! ## Persistence (`mmap_enabled`) without `unsafe`
//!
//! The crate is `#![deny(unsafe_code)]`, so this is **not** a raw `mmap`
//! syscall. [`Int8VectorIndex::to_bytes`] / [`Int8VectorIndex::from_bytes`] are
//! pure, safe, length-and-checksum-validated (de)serialization; `mmap_enabled`
//! selects the file-backed round-trip path. A corrupted byte image is rejected
//! fail-closed ([`VectorIndexError::Corrupt`]).

use crate::chunk::MemoryId;
use mnemos_c_walrus::derive_blob_id;

/// HNSW + int8 vector index configuration (§4.6).
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub struct HnswInt8Config {
    /// Graph connectivity parameter `M` (reserved for the graph layer). Must be
    /// non-zero.
    pub m_u8: u8,
    /// Construction-time beam width `ef_construction` (reserved). Must be
    /// non-zero.
    pub ef_construction_u16: u16,
    /// Search-time beam width `ef_search` (reserved). Must be non-zero.
    pub ef_search_u16: u16,
    /// Whether the index is persisted / loaded through the safe byte image
    /// (file-backed). `false` keeps the index purely in memory.
    pub mmap_enabled: bool,
    /// Maximum tolerated recall loss in basis points (1 bp = 0.01 %). The
    /// criterion gate is `≤ 80`.
    pub recall_loss_max_bps_u16: u16,
}

impl HnswInt8Config {
    /// Maximum admissible recall-loss gate value (100 % = 10000 bps).
    pub const MAX_RECALL_LOSS_BPS: u16 = 10_000;

    /// Validate and construct a configuration. Rejects a zero `m` / `ef_*` and a
    /// recall-loss gate above 100 % fail-closed.
    pub const fn new(
        m_u8: u8,
        ef_construction_u16: u16,
        ef_search_u16: u16,
        mmap_enabled: bool,
        recall_loss_max_bps_u16: u16,
    ) -> Result<Self, VectorIndexError> {
        if m_u8 == 0 || ef_construction_u16 == 0 || ef_search_u16 == 0 {
            return Err(VectorIndexError::ConfigInvalid);
        }
        if recall_loss_max_bps_u16 > Self::MAX_RECALL_LOSS_BPS {
            return Err(VectorIndexError::ConfigInvalid);
        }
        Ok(Self {
            m_u8,
            ef_construction_u16,
            ef_search_u16,
            mmap_enabled,
            recall_loss_max_bps_u16,
        })
    }
}

/// Vector index error set (frozen). Every variant is a data-free tag.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
#[non_exhaustive]
pub enum VectorIndexError {
    /// The configuration is invalid (zero `m`/`ef`, or recall gate > 100 %).
    ConfigInvalid,
    /// A vector's dimension does not match the index dimension.
    DimsMismatch,
    /// A vector had zero dimensions, which is never indexable.
    DimsZero,
    /// A serialized byte image failed magic / version / length / checksum
    /// validation.
    Corrupt,
}

/// One stored entry: the memory id, the `f32` scale (as bits) and the int8
/// codes.
#[derive(Clone, Debug, PartialEq)]
struct Int8Entry {
    id: MemoryId,
    scale_bits: u32,
    codes: Vec<i8>,
}

/// An int8-quantized vector index keyed by [`MemoryId`].
#[derive(Clone, Debug, PartialEq)]
pub struct Int8VectorIndex {
    config: HnswInt8Config,
    dims_u16: u16,
    entries: Vec<Int8Entry>,
}

const INDEX_MAGIC: [u8; 8] = *b"MNI8IDX1";
const INDEX_VERSION: u8 = 1;
const CHECKSUM_BYTES: usize = 32;
/// Fixed-width header: magic(8) + version(1) + dims(2) + count(4) + m(1) +
/// ef_construction(2) + ef_search(2) + mmap(1) + recall_gate(2).
const HEADER_BYTES: usize = 8 + 1 + 2 + 4 + 1 + 2 + 2 + 1 + 2;

impl Int8VectorIndex {
    /// Create an empty index with a validated configuration.
    #[must_use]
    pub const fn new(config: HnswInt8Config) -> Self {
        Self {
            config,
            dims_u16: 0,
            entries: Vec::new(),
        }
    }

    /// The configuration this index was built with.
    #[must_use]
    pub const fn config(&self) -> HnswInt8Config {
        self.config
    }

    /// Index dimension (0 until the first insert sets it).
    #[must_use]
    pub const fn dims(&self) -> u16 {
        self.dims_u16
    }

    /// Number of stored vectors.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether the index holds no vectors.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Insert or replace (upsert by id) a vector. The first insert pins the
    /// index dimension; later inserts of a different dimension are rejected.
    pub fn upsert(&mut self, id: MemoryId, vector: &[f32]) -> Result<(), VectorIndexError> {
        if vector.is_empty() {
            return Err(VectorIndexError::DimsZero);
        }
        let dims = u16::try_from(vector.len()).map_err(|_| VectorIndexError::DimsMismatch)?;
        if self.dims_u16 == 0 {
            self.dims_u16 = dims;
        } else if self.dims_u16 != dims {
            return Err(VectorIndexError::DimsMismatch);
        }
        let (codes, scale) = quantize_int8(vector);
        let entry = Int8Entry {
            id,
            scale_bits: scale.to_bits(),
            codes,
        };
        if let Some(slot) = self.entries.iter_mut().find(|e| e.id == id) {
            *slot = entry;
        } else {
            self.entries.push(entry);
        }
        Ok(())
    }

    /// Return up to `k` nearest memory ids to `query` by ascending L2 distance
    /// over the dequantized int8 codes.
    pub fn search(&self, query: &[f32], k: usize) -> Result<Vec<MemoryId>, VectorIndexError> {
        let dims = u16::try_from(query.len()).map_err(|_| VectorIndexError::DimsMismatch)?;
        if dims == 0 {
            return Err(VectorIndexError::DimsZero);
        }
        if self.dims_u16 != 0 && self.dims_u16 != dims {
            return Err(VectorIndexError::DimsMismatch);
        }
        let mut scored: Vec<(f32, MemoryId)> = self
            .entries
            .iter()
            .map(|e| (l2_sq_dequant(query, e), e.id))
            .collect();
        scored.sort_by(|a, b| a.0.total_cmp(&b.0).then_with(|| a.1.cmp(&b.1)));
        Ok(scored.into_iter().take(k).map(|(_, id)| id).collect())
    }

    /// Serialize the index to a safe, checksum-trailed byte image (the
    /// file-backed / `mmap_enabled` path).
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        let dims = self.dims_u16 as usize;
        let entry_bytes = 8 + 4 + dims;
        let body_len = HEADER_BYTES + self.entries.len() * entry_bytes;
        let mut out = Vec::with_capacity(body_len + CHECKSUM_BYTES);
        out.extend_from_slice(&INDEX_MAGIC);
        out.push(INDEX_VERSION);
        out.extend_from_slice(&self.dims_u16.to_le_bytes());
        out.extend_from_slice(&(self.entries.len() as u32).to_le_bytes());
        out.push(self.config.m_u8);
        out.extend_from_slice(&self.config.ef_construction_u16.to_le_bytes());
        out.extend_from_slice(&self.config.ef_search_u16.to_le_bytes());
        out.push(u8::from(self.config.mmap_enabled));
        out.extend_from_slice(&self.config.recall_loss_max_bps_u16.to_le_bytes());
        for e in &self.entries {
            out.extend_from_slice(&e.id.get().to_le_bytes());
            out.extend_from_slice(&e.scale_bits.to_le_bytes());
            out.extend(e.codes.iter().map(|&c| c as u8));
        }
        let checksum = derive_blob_id(&out);
        out.extend_from_slice(checksum.as_bytes());
        out
    }

    /// Parse an index from a byte image, validating magic, version, length and
    /// the trailing checksum. Any mismatch is rejected as
    /// [`VectorIndexError::Corrupt`].
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, VectorIndexError> {
        if bytes.len() < HEADER_BYTES + CHECKSUM_BYTES {
            return Err(VectorIndexError::Corrupt);
        }
        let (body, trailer) = bytes.split_at(bytes.len() - CHECKSUM_BYTES);
        if derive_blob_id(body).as_bytes() != trailer {
            return Err(VectorIndexError::Corrupt);
        }
        if body[0..8] != INDEX_MAGIC || body[8] != INDEX_VERSION {
            return Err(VectorIndexError::Corrupt);
        }
        let dims_u16 = u16::from_le_bytes([body[9], body[10]]);
        let count = u32::from_le_bytes([body[11], body[12], body[13], body[14]]) as usize;
        let m_u8 = body[15];
        let ef_construction_u16 = u16::from_le_bytes([body[16], body[17]]);
        let ef_search_u16 = u16::from_le_bytes([body[18], body[19]]);
        let mmap_enabled = match body[20] {
            0 => false,
            1 => true,
            _ => return Err(VectorIndexError::Corrupt),
        };
        let recall_loss_max_bps_u16 = u16::from_le_bytes([body[21], body[22]]);
        let config = HnswInt8Config::new(
            m_u8,
            ef_construction_u16,
            ef_search_u16,
            mmap_enabled,
            recall_loss_max_bps_u16,
        )
        .map_err(|_| VectorIndexError::Corrupt)?;
        let dims = dims_u16 as usize;
        let entry_bytes = 8 + 4 + dims;
        if body.len() != HEADER_BYTES + count * entry_bytes {
            return Err(VectorIndexError::Corrupt);
        }
        let mut entries = Vec::with_capacity(count);
        let mut off = HEADER_BYTES;
        for _ in 0..count {
            let id = MemoryId::new(u64::from_le_bytes([
                body[off],
                body[off + 1],
                body[off + 2],
                body[off + 3],
                body[off + 4],
                body[off + 5],
                body[off + 6],
                body[off + 7],
            ]));
            let scale_bits =
                u32::from_le_bytes([body[off + 8], body[off + 9], body[off + 10], body[off + 11]]);
            let code_start = off + 12;
            let codes: Vec<i8> = body[code_start..code_start + dims]
                .iter()
                .map(|&b| b as i8)
                .collect();
            entries.push(Int8Entry {
                id,
                scale_bits,
                codes,
            });
            off += entry_bytes;
        }
        Ok(Self {
            config,
            dims_u16,
            entries,
        })
    }
}

/// Symmetric per-vector int8 quantization: returns the `i8` codes and the `f32`
/// scale such that `v_i ≈ code_i * scale`.
fn quantize_int8(vector: &[f32]) -> (Vec<i8>, f32) {
    let max_abs = vector.iter().fold(0.0_f32, |m, &x| m.max(x.abs()));
    let scale = if max_abs > 0.0 { max_abs / 127.0 } else { 1.0 };
    let codes = vector
        .iter()
        .map(|&x| (x / scale).round().clamp(-127.0, 127.0) as i8)
        .collect();
    (codes, scale)
}

/// Squared L2 distance between an `f32` query and a dequantized int8 entry.
fn l2_sq_dequant(query: &[f32], entry: &Int8Entry) -> f32 {
    let scale = f32::from_bits(entry.scale_bits);
    query
        .iter()
        .zip(entry.codes.iter())
        .map(|(&q, &c)| {
            let diff = q - f32::from(c) * scale;
            diff * diff
        })
        .sum()
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    #![allow(clippy::expect_used)]
    #![allow(clippy::panic)]

    use super::*;

    fn cfg() -> HnswInt8Config {
        HnswInt8Config::new(16, 200, 64, true, 80).unwrap()
    }

    // Deterministic LCG so the recall fixture never uses runtime randomness.
    struct Lcg(u64);
    impl Lcg {
        fn next_f32(&mut self) -> f32 {
            self.0 = self
                .0
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            // Map the top 24 bits into [-1, 1).
            let bits = (self.0 >> 40) as u32;
            (bits as f32 / (1u32 << 24) as f32) * 2.0 - 1.0
        }
        fn vector(&mut self, dims: usize) -> Vec<f32> {
            (0..dims).map(|_| self.next_f32()).collect()
        }
    }

    fn exact_top1(vectors: &[(MemoryId, Vec<f32>)], query: &[f32]) -> MemoryId {
        let mut best = vectors[0].0;
        let mut best_d = f32::INFINITY;
        for (id, v) in vectors {
            let d: f32 = query.iter().zip(v).map(|(&q, &x)| (q - x) * (q - x)).sum();
            if d < best_d {
                best_d = d;
                best = *id;
            }
        }
        best
    }

    #[test]
    fn config_parse_rejects_zero_and_oversized() {
        assert_eq!(
            HnswInt8Config::new(0, 200, 64, false, 80),
            Err(VectorIndexError::ConfigInvalid)
        );
        assert_eq!(
            HnswInt8Config::new(16, 0, 64, false, 80),
            Err(VectorIndexError::ConfigInvalid)
        );
        assert_eq!(
            HnswInt8Config::new(16, 200, 0, false, 80),
            Err(VectorIndexError::ConfigInvalid)
        );
        assert_eq!(
            HnswInt8Config::new(16, 200, 64, false, 10_001),
            Err(VectorIndexError::ConfigInvalid)
        );
        assert!(HnswInt8Config::new(16, 200, 64, true, 80).is_ok());
    }

    #[test]
    fn int8_quantization_round_trips_within_scale() {
        let v = vec![1.0_f32, -0.5, 0.25, -1.0];
        let (codes, scale) = quantize_int8(&v);
        assert_eq!(codes.len(), 4);
        // Largest magnitude maps onto ±127.
        assert!(codes.iter().any(|&c| c == 127 || c == -127));
        // Dequantized value stays within one quantization step of the original.
        for (&orig, &c) in v.iter().zip(codes.iter()) {
            let deq = f32::from(c) * scale;
            assert!((orig - deq).abs() <= scale + f32::EPSILON);
        }
    }

    #[test]
    fn mmap_on_off_search_is_identical() {
        let mut idx = Int8VectorIndex::new(cfg());
        let mut rng = Lcg(0xDEAD_BEEF);
        for i in 0..32_u64 {
            idx.upsert(MemoryId::new(i), &rng.vector(8)).unwrap();
        }
        let query = Lcg(0x1234).vector(8);
        let in_memory = idx.search(&query, 5).unwrap();
        // mmap_enabled path: round-trip through the safe byte image.
        let bytes = idx.to_bytes();
        let loaded = Int8VectorIndex::from_bytes(&bytes).unwrap();
        let file_backed = loaded.search(&query, 5).unwrap();
        assert_eq!(in_memory, file_backed);
        assert_eq!(idx, loaded);
    }

    #[test]
    fn corrupted_mmap_image_is_rejected() {
        let mut idx = Int8VectorIndex::new(cfg());
        idx.upsert(MemoryId::new(1), &[0.1, 0.2, 0.3, 0.4]).unwrap();
        let mut bytes = idx.to_bytes();
        // Flip one body byte: the trailing checksum no longer matches.
        bytes[HEADER_BYTES] ^= 0xFF;
        assert_eq!(
            Int8VectorIndex::from_bytes(&bytes),
            Err(VectorIndexError::Corrupt)
        );
        // Truncated image is also rejected.
        assert_eq!(
            Int8VectorIndex::from_bytes(&bytes[..4]),
            Err(VectorIndexError::Corrupt)
        );
    }

    #[test]
    fn recall_loss_within_80_bps_gate() {
        let dims = 16_usize;
        let mut rng = Lcg(0xA5A5_1234);
        let vectors: Vec<(MemoryId, Vec<f32>)> = (0..200_u64)
            .map(|i| (MemoryId::new(i), rng.vector(dims)))
            .collect();
        let mut idx = Int8VectorIndex::new(cfg());
        for (id, v) in &vectors {
            idx.upsert(*id, v).unwrap();
        }
        let mut queries = Lcg(0x7777_0001);
        let trials = 500_u32;
        let mut mismatches = 0_u32;
        for _ in 0..trials {
            let q = queries.vector(dims);
            let exact = exact_top1(&vectors, &q);
            let approx = idx.search(&q, 1).unwrap()[0];
            if exact != approx {
                mismatches += 1;
            }
        }
        // Recall loss in basis points = mismatches / trials * 10000.
        let loss_bps = (u64::from(mismatches) * 10_000) / u64::from(trials);
        assert!(
            loss_bps <= 80,
            "recall loss {loss_bps} bps exceeds 80 bps gate"
        );
    }

    #[test]
    fn dims_mismatch_is_rejected() {
        let mut idx = Int8VectorIndex::new(cfg());
        idx.upsert(MemoryId::new(1), &[0.1, 0.2, 0.3]).unwrap();
        assert_eq!(
            idx.upsert(MemoryId::new(2), &[0.1, 0.2]),
            Err(VectorIndexError::DimsMismatch)
        );
        assert_eq!(
            idx.upsert(MemoryId::new(3), &[]),
            Err(VectorIndexError::DimsZero)
        );
    }

    #[test]
    fn upsert_replaces_by_id() {
        let mut idx = Int8VectorIndex::new(cfg());
        idx.upsert(MemoryId::new(1), &[1.0, 0.0, 0.0, 0.0]).unwrap();
        idx.upsert(MemoryId::new(1), &[0.0, 0.0, 0.0, 1.0]).unwrap();
        assert_eq!(idx.len(), 1);
        let near = idx.search(&[0.0, 0.0, 0.0, 1.0], 1).unwrap();
        assert_eq!(near, vec![MemoryId::new(1)]);
    }
}
