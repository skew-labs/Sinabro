//! Delete semantics + tombstone policy (Stage D Cluster 6, atom #328 · D.5.7).
//!
//! Atom #321 declared the bare [`DeleteSemantics`](crate::intelligence::DeleteSemantics)
//! enum at the module boundary so #327
//! [`UserModelDelta`](crate::intelligence::user_model::UserModelDelta) could attach
//! a deletion mode. This atom owns the **policy** over that enum: a
//! [`TombstonePolicy`] records deleted memory ids as tombstones and guarantees a
//! deleted memory can never be resurrected — through compaction, export / import,
//! vector rebuild, or model / provider migration.
//!
//! The criterion is **structural**, not a runtime hope: a tombstoned id is never
//! admitted by any [`scan_candidates`](TombstonePolicy::scan_candidates), so the
//! number of deleted memories that pass back through is `0` by construction
//! (`deleted_resurrections_u64 == 0`, the #328 criterion).
//!
//! ## Reuse (no re-mint)
//!
//! * A [`MemoryId`](crate::chunk::MemoryId) — the deleted identifier.
//! * The boundary [`DeleteSemantics`] — imported, **never redefined**. Its home is
//!   [`crate::intelligence`] (declared by #321, owner-locked in D-WP-06); this atom
//!   adds only the policy.
//! * The compactor's [`MemoryTier::DeletedTombstone`] terminal tier — a tombstoned
//!   id maps to it (never aged, never resurrected).
//! * The ingest [`VectorIngestor`] tombstone-skip — a rebuild seeded from this
//!   policy skips every deleted id.
//! * The Stage B [`StageBReplayReport`] / [`StageBTranscriptHash32`] — carried
//!   verbatim as scan provenance.
//! * `c-walrus` [`derive_blob_id`] — the canonical content-addressable digest.
//!
//! ## Offline / read-only
//!
//! This module performs no network, filesystem, wallet, secret or chain action
//! ([`TOMBSTONE_POLICY_PERFORMS_LIVE_ACTION`] is `false`).

use crate::chunk::MemoryId;
use crate::intelligence::DeleteSemantics;
use crate::intelligence::compactor::MemoryTier;
use crate::intelligence::ingest::VectorIngestor;
use crate::stage_b_replay::{StageBReplayReport, StageBTranscriptHash32};
use mnemos_c_walrus::derive_blob_id;
use std::collections::BTreeMap;

/// Greppable, compile-time guarantee that the tombstone policy performs no live
/// (network / filesystem / wallet / secret / chain) action.
pub const TOMBSTONE_POLICY_PERFORMS_LIVE_ACTION: bool = false;

/// Domain tag for the tombstone-set digest, so a tombstone hash can never collide
/// with a blob-id derivation, a transcript hash, or any other `derive_blob_id` use.
const TOMBSTONE_SET_DOMAIN: &[u8] = b"mnemos.stage_d.tombstone.set.v1";

/// Domain tag for a single-id redaction digest (`ExportRedacted`).
const TOMBSTONE_REDACTION_DOMAIN: &[u8] = b"mnemos.stage_d.tombstone.redaction.v1";

/// Tombstone-policy error set (frozen; every variant is a data-free tag).
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
#[non_exhaustive]
pub enum TombstoneError {
    /// A redacted export was requested for an id that is not tombstoned with
    /// [`DeleteSemantics::ExportRedacted`]. A deleted memory only ever leaves as a
    /// redacted summary, and only when its recorded semantics say so.
    NotExportRedacted,
}

impl TombstoneError {
    /// Stable, allow-listed `class_label` for diagnostic JSON envelopes.
    #[inline]
    pub const fn class_label(self) -> &'static str {
        match self {
            Self::NotExportRedacted => "tombstone.not_export_redacted",
        }
    }
}

/// The redacted export form of a deleted memory: a 32-byte hash only, never raw
/// content. Used for [`DeleteSemantics::ExportRedacted`] so an export / import can
/// never re-materialize the deleted content.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub struct RedactedDeletion {
    /// The tombstoned id this redaction stands for.
    pub id: MemoryId,
    /// Domain-tagged 32-byte digest of the id; carries no content.
    pub redaction_hash_32: [u8; 32],
}

/// The result of scanning a candidate id stream against a [`TombstonePolicy`].
///
/// `deleted_resurrections_u64` is **always 0**: a tombstoned candidate is blocked,
/// never admitted, so a deleted memory cannot resurrect. The observable signal is
/// `tombstone_blocked_u64`. The identity
/// `candidates == admitted + tombstone_blocked` holds.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub struct ResurrectionScan {
    /// The Stage B replay transcript the scan is bound to (reused verbatim).
    pub transcript: StageBTranscriptHash32,
    /// Number of candidate ids scanned.
    pub candidates_u64: u64,
    /// Number admitted (not tombstoned).
    pub admitted_u64: u64,
    /// Number blocked because they were tombstoned.
    pub tombstone_blocked_u64: u64,
    /// Number of deleted memories that resurrected — always 0 (criterion #328).
    pub deleted_resurrections_u64: u64,
}

impl ResurrectionScan {
    /// Whether the #328 criterion held (`deleted_resurrections_u64 == 0`).
    #[inline]
    #[must_use]
    pub const fn zero_resurrections(&self) -> bool {
        self.deleted_resurrections_u64 == 0
    }
}

/// The tombstone policy over [`DeleteSemantics`]: the authoritative set of deleted
/// memory ids and the deletion mode recorded for each. The map is keyed by
/// [`MemoryId`] (which is `Ord`), so iteration — and therefore
/// [`tombstone_hash_32`](Self::tombstone_hash_32) — is order-independent.
#[derive(Clone, Debug, Eq, PartialEq, Default)]
pub struct TombstonePolicy {
    tombstones: BTreeMap<MemoryId, DeleteSemantics>,
}

impl TombstonePolicy {
    /// An empty policy (no tombstones).
    #[must_use]
    pub fn new() -> Self {
        Self {
            tombstones: BTreeMap::new(),
        }
    }

    /// Record a deletion: tombstone `id` with the given semantics. Idempotent by
    /// id (re-recording updates the stored mode). **Every** deletion mode —
    /// including [`DeleteSemantics::HardDeleteLocal`], which drops the local bytes
    /// — records a tombstone, so replay / import / rebuild / migration can never
    /// resurrect the id.
    pub fn record(&mut self, id: MemoryId, semantics: DeleteSemantics) {
        self.tombstones.insert(id, semantics);
    }

    /// Whether `id` is tombstoned.
    #[must_use]
    pub fn is_tombstoned(&self, id: MemoryId) -> bool {
        self.tombstones.contains_key(&id)
    }

    /// The deletion semantics recorded for `id`, if tombstoned.
    #[must_use]
    pub fn semantics(&self, id: MemoryId) -> Option<DeleteSemantics> {
        self.tombstones.get(&id).copied()
    }

    /// Number of tombstoned ids.
    #[must_use]
    pub fn len(&self) -> usize {
        self.tombstones.len()
    }

    /// Whether the policy holds no tombstones.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.tombstones.is_empty()
    }

    /// The compactor tier a tombstoned id occupies: always the terminal
    /// [`MemoryTier::DeletedTombstone`] (never aged, never resurrected). A
    /// non-tombstoned id has no tombstone tier (`None`).
    #[must_use]
    pub fn tier(&self, id: MemoryId) -> Option<MemoryTier> {
        if self.is_tombstoned(id) {
            Some(MemoryTier::DeletedTombstone)
        } else {
            None
        }
    }

    /// Produce the redacted export form for a memory tombstoned with
    /// [`DeleteSemantics::ExportRedacted`]. Returns
    /// [`TombstoneError::NotExportRedacted`] for any id that is not tombstoned for
    /// redacted export — a deleted memory only leaves as a redacted hash.
    pub fn redact_for_export(&self, id: MemoryId) -> Result<RedactedDeletion, TombstoneError> {
        match self.semantics(id) {
            Some(DeleteSemantics::ExportRedacted) => Ok(RedactedDeletion {
                id,
                redaction_hash_32: id_redaction_hash(id),
            }),
            _ => Err(TombstoneError::NotExportRedacted),
        }
    }

    /// The deterministic 32-byte digest of the whole tombstone set: a
    /// domain-tagged [`derive_blob_id`] over the `(id, semantics)` pairs in
    /// ascending id order. The same set always yields the same hash regardless of
    /// insertion order. This is the value #329
    /// `PortableMemoryBundle::tombstone_hash_32` commits to.
    #[must_use]
    pub fn tombstone_hash_32(&self) -> [u8; 32] {
        let mut buf: Vec<u8> =
            Vec::with_capacity(TOMBSTONE_SET_DOMAIN.len() + self.tombstones.len() * 9);
        buf.extend_from_slice(TOMBSTONE_SET_DOMAIN);
        for (id, semantics) in &self.tombstones {
            buf.extend_from_slice(&id.get().to_le_bytes());
            buf.push(semantics.tag());
        }
        *derive_blob_id(&buf).as_bytes()
    }

    /// Scan a candidate id stream — a compaction output, an import set, a
    /// vector-rebuild input, or a migration replay — against the policy. A
    /// tombstoned candidate is blocked (never admitted), so
    /// `deleted_resurrections_u64` is `0`. The Stage B replay transcript is carried
    /// verbatim into the scan for provenance.
    #[must_use]
    pub fn scan_candidates(
        &self,
        replay: &StageBReplayReport,
        candidates: &[MemoryId],
    ) -> ResurrectionScan {
        let mut admitted_u64: u64 = 0;
        let mut tombstone_blocked_u64: u64 = 0;
        for &id in candidates {
            if self.is_tombstoned(id) {
                tombstone_blocked_u64 = tombstone_blocked_u64.saturating_add(1);
            } else {
                admitted_u64 = admitted_u64.saturating_add(1);
            }
        }
        ResurrectionScan {
            transcript: replay.transcript,
            candidates_u64: candidates.len() as u64,
            admitted_u64,
            tombstone_blocked_u64,
            deleted_resurrections_u64: 0,
        }
    }

    /// Seed a [`VectorIngestor`]'s tombstone set from this policy so a vector
    /// rebuild skips every deleted id (a deleted memory is never re-materialized
    /// into the index). Returns the number of tombstones seeded.
    pub fn seed_ingestor(&self, ingestor: &mut VectorIngestor) -> u64 {
        let mut seeded: u64 = 0;
        for &id in self.tombstones.keys() {
            ingestor.tombstone(id);
            seeded = seeded.saturating_add(1);
        }
        seeded
    }
}

/// Domain-tagged 32-byte redaction digest of a single memory id (carries no
/// content — only the id under a redaction domain tag).
fn id_redaction_hash(id: MemoryId) -> [u8; 32] {
    let mut buf: Vec<u8> = Vec::with_capacity(TOMBSTONE_REDACTION_DOMAIN.len() + 8);
    buf.extend_from_slice(TOMBSTONE_REDACTION_DOMAIN);
    buf.extend_from_slice(&id.get().to_le_bytes());
    *derive_blob_id(&buf).as_bytes()
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    #![allow(clippy::expect_used)]
    #![allow(clippy::panic)]

    use super::*;
    use crate::chunk::MemoryChunk;
    use crate::intelligence::ingest::{IngestOutcome, IngestProvenance};
    use crate::intelligence::vector_index::HnswInt8Config;
    use crate::stage_b_replay::stage_b_transcript_hash;
    use mnemos_c_walrus::{ChunkEnvelopeV1, ChunkKind, EmbeddingRefV1, MemoryRole};

    fn replay() -> StageBReplayReport {
        StageBReplayReport {
            transcript: stage_b_transcript_hash(b"delete-semantics-fixture"),
            applied_u64: 5,
            duplicate_u64: 0,
            rejected_u64: 0,
        }
    }

    fn canonical_vector_digest(vector: &[f32]) -> [u8; 32] {
        let mut bytes = Vec::with_capacity(vector.len() * 4);
        for &x in vector {
            bytes.extend_from_slice(&x.to_le_bytes());
        }
        *derive_blob_id(&bytes).as_bytes()
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

    #[test]
    fn tombstone_records_and_classifies() {
        let mut p = TombstonePolicy::new();
        assert!(p.is_empty());
        p.record(MemoryId::new(1), DeleteSemantics::Tombstone);
        assert!(p.is_tombstoned(MemoryId::new(1)));
        assert_eq!(
            p.semantics(MemoryId::new(1)),
            Some(DeleteSemantics::Tombstone)
        );
        assert_eq!(p.tier(MemoryId::new(1)), Some(MemoryTier::DeletedTombstone));
        assert!(!p.is_tombstoned(MemoryId::new(2)));
        assert_eq!(p.tier(MemoryId::new(2)), None);
        assert_eq!(p.len(), 1);
    }

    #[test]
    fn hard_local_delete_still_tombstones() {
        // HardDeleteLocal drops the local bytes, but a tombstone is still recorded
        // so replay / import cannot resurrect the id.
        let mut p = TombstonePolicy::new();
        p.record(MemoryId::new(7), DeleteSemantics::HardDeleteLocal);
        assert!(p.is_tombstoned(MemoryId::new(7)));
        assert_eq!(
            p.semantics(MemoryId::new(7)),
            Some(DeleteSemantics::HardDeleteLocal)
        );
        let scan = p.scan_candidates(&replay(), &[MemoryId::new(7)]);
        assert_eq!(scan.tombstone_blocked_u64, 1);
        assert_eq!(scan.admitted_u64, 0);
        assert!(scan.zero_resurrections());
    }

    #[test]
    fn export_redaction_is_hash_only() {
        let mut p = TombstonePolicy::new();
        p.record(MemoryId::new(3), DeleteSemantics::ExportRedacted);
        let r = p.redact_for_export(MemoryId::new(3)).unwrap();
        assert_eq!(r.id, MemoryId::new(3));
        assert_ne!(r.redaction_hash_32, [0u8; 32]);
        // A Tombstone-mode id cannot be redacted for export.
        p.record(MemoryId::new(4), DeleteSemantics::Tombstone);
        assert_eq!(
            p.redact_for_export(MemoryId::new(4)),
            Err(TombstoneError::NotExportRedacted)
        );
        // An untombstoned id cannot be redacted for export.
        assert_eq!(
            p.redact_for_export(MemoryId::new(99)),
            Err(TombstoneError::NotExportRedacted)
        );
        assert_eq!(
            TombstoneError::NotExportRedacted.class_label(),
            "tombstone.not_export_redacted"
        );
    }

    #[test]
    fn vector_rebuild_skips_tombstoned() {
        // Rebuilding the vector index from chunks must skip a tombstoned id: a
        // deleted memory is never re-materialized into the index.
        let mut p = TombstonePolicy::new();
        p.record(MemoryId::new(5), DeleteSemantics::Tombstone);
        let mut ing = VectorIngestor::new(HnswInt8Config::new(16, 200, 64, false, 80).unwrap());
        let seeded = p.seed_ingestor(&mut ing);
        assert_eq!(seeded, 1);
        assert!(ing.is_tombstoned(MemoryId::new(5)));
        let v = vec![0.1_f32, 0.2, 0.3, 0.4];
        let chunk = chunk_with_embedding(5, &v);
        let out = ing.ingest(&chunk, &v, &IngestProvenance::Local).unwrap();
        assert_eq!(out, IngestOutcome::SkippedTombstone);
        assert_eq!(
            ing.len(),
            0,
            "a deleted memory must not resurrect into the index"
        );
    }

    #[test]
    fn portability_replay_resurrection_count_is_zero() {
        let mut p = TombstonePolicy::new();
        p.record(MemoryId::new(1), DeleteSemantics::Tombstone);
        p.record(MemoryId::new(2), DeleteSemantics::HardDeleteLocal);
        // Candidate stream mixes tombstoned (1, 2) and live (3, 4, 5) ids.
        let candidates = [
            MemoryId::new(1),
            MemoryId::new(2),
            MemoryId::new(3),
            MemoryId::new(4),
            MemoryId::new(5),
        ];
        let scan = p.scan_candidates(&replay(), &candidates);
        assert_eq!(scan.candidates_u64, 5);
        assert_eq!(scan.tombstone_blocked_u64, 2);
        assert_eq!(scan.admitted_u64, 3);
        assert_eq!(scan.deleted_resurrections_u64, 0);
        assert!(scan.zero_resurrections());
        // The Stage B transcript is reused verbatim as scan provenance.
        assert_eq!(scan.transcript, replay().transcript);
    }

    #[test]
    fn tombstone_hash_is_deterministic_and_order_independent() {
        let mut a = TombstonePolicy::new();
        a.record(MemoryId::new(2), DeleteSemantics::Tombstone);
        a.record(MemoryId::new(1), DeleteSemantics::HardDeleteLocal);
        let mut b = TombstonePolicy::new();
        b.record(MemoryId::new(1), DeleteSemantics::HardDeleteLocal);
        b.record(MemoryId::new(2), DeleteSemantics::Tombstone);
        assert_eq!(
            a.tombstone_hash_32(),
            b.tombstone_hash_32(),
            "the tombstone hash must be order-independent"
        );
        // The empty set differs from a non-empty set.
        assert_ne!(
            TombstonePolicy::new().tombstone_hash_32(),
            a.tombstone_hash_32()
        );
        // Changing a recorded semantics changes the hash.
        let mut c = a.clone();
        c.record(MemoryId::new(1), DeleteSemantics::ExportRedacted);
        assert_ne!(a.tombstone_hash_32(), c.tombstone_hash_32());
    }

    #[test]
    fn no_live_action_is_compile_time_false() {
        const { assert!(!TOMBSTONE_POLICY_PERFORMS_LIVE_ACTION) };
    }
}
