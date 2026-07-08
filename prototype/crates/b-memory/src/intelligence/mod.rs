//! Memory Intelligence module boundary.
//!
//! This module is the **read-only intelligence boundary** layered on top of the
//! Stage A/B memory truth. It reads [`MemoryChunk`](crate::chunk::MemoryChunk)
//! content, Stage B replay transcripts
//! ([`StageBReplayReport`](crate::stage_b_replay::StageBReplayReport)) and the
//! Stage B/C evidence summaries, but it **never** replaces:
//!
//! * the chunk codec (`c-walrus` encode/decode),
//! * blob-id verification ([`VerifiedBlobId`](mnemos_c_walrus::VerifiedBlobId)),
//! * owner checks,
//! * replay truth, or
//! * evidence rights truth.
//!
//! Cold raw archive retrieval is **not** part of the hot path: an evidence
//! reference here is a redacted hash ([`StageDEvidenceRef`]), never a raw
//! archive locator, and an archive locator is never treated as memory truth or
//! training consent ([`ARCHIVE_LOCATOR_IS_MEMORY_TRUTH`]).
//!
//! Any memory / context / harness self-evolution signal is a measurement-only
//! [`StageDPolicyObservation`] whose `production_change_allowed` is `false` by
//! construction (it cannot promote itself into a runtime policy mutation — that
//! authority lives in Stage E behind sandbox/held-out approval).
//!
//! The persistence planner [`MemoryPersist`](crate::persist::MemoryPersist) is
//! explicitly outside the read-only baseline path: intelligence observes, it
//! does not persist.
//!
//! ## Layer invariants
//!
//! * **No wire re-mint.** No chunk / blob / replay canonical type is duplicated
//!   here; the intelligence layer reuses the Stage A/B types verbatim.
//! * **Read-only baseline.** [`ReadOnlyBaseline`] derives counts only; it owns
//!   no mutation path over memory truth.
//! * **Measurement-only self-evolution.** Observations are evidence, never
//!   authority ([`StageDPolicyObservation::production_change_allowed`]).
//!
//! ## Cross-module boundary note (DeleteSemantics)
//!
//! [`DeleteSemantics`] is declared here as a shared module-boundary enum so
//! that [`user_model`]'s `UserModelDelta` can compile alongside it. The
//! [`delete_semantics`] module imports this bare enum and owns the
//! resurrection-prevention **policy** (`deleted_resurrections == 0`), and the
//! [`portability`] module consumes that policy for export / import /
//! replay. The enum carries no policy logic here.

pub mod compactor;
pub mod delete_semantics;
pub mod feedback;
pub mod importance;
pub mod ingest;
pub mod memory_index;
pub mod portability;
pub mod user_model;
pub mod vector_index;

use crate::chunk::MemoryChunk;
use crate::stage_b_replay::StageBReplayReport;
use mnemos_a_core::StageDTraceLink;

// ===========================================================================
// 1. DeleteSemantics — shared enum (cross-module boundary, see module doc)
// ===========================================================================

/// How a deleted memory is removed. Declared at the module boundary so
/// `UserModelDelta` can attach deletion semantics; the [`delete_semantics`]
/// module imports this enum and owns the tombstone / resurrection
/// **policy**. The enum itself carries no policy.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
#[repr(u8)]
pub enum DeleteSemantics {
    /// Logical deletion: a tombstone is recorded and the id can never be
    /// silently re-materialized (the tombstone policy enforces zero resurrection).
    Tombstone = 1,
    /// Local hard delete: the local bytes are dropped; a tombstone still
    /// records the deletion so replay/import cannot resurrect the id.
    HardDeleteLocal = 2,
    /// Export with redaction: the memory leaves only as a redacted summary,
    /// never as raw retrievable content.
    ExportRedacted = 3,
}

impl DeleteSemantics {
    /// Stable `u8` tag — mirrors the `#[repr(u8)]` discriminant for any future
    /// byte-level form, without an `as` cast at the call site.
    #[inline]
    pub const fn tag(self) -> u8 {
        self as u8
    }
}

// ===========================================================================
// 2. StageDEvidenceRef — redacted evidence reference
// ===========================================================================

/// A redacted reference to a Stage D evidence artifact: a 32-byte path
/// hash plus the [`StageDTraceLink`] that produced it. It carries a **hash**,
/// never a raw archive locator or path, so the intelligence layer can cite
/// evidence provenance without ever pulling a cold archive into the hot path.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub struct StageDEvidenceRef {
    /// 32-byte hash of the evidence artifact path (redacted; not a raw locator).
    pub path_hash_32: [u8; 32],
    /// Stage D trace stamp of the action that produced the evidence.
    pub trace: StageDTraceLink,
}

impl StageDEvidenceRef {
    /// Construct a redacted evidence reference from a path hash and a trace.
    #[inline]
    pub const fn new(path_hash_32: [u8; 32], trace: StageDTraceLink) -> Self {
        Self {
            path_hash_32,
            trace,
        }
    }
}

/// An archive locator is **never** memory truth, training consent, or skill
/// recommendation authority. This boundary constant
/// makes that policy greppable and testable: cold raw archive retrieval is out
/// of the intelligence hot path by construction.
pub const ARCHIVE_LOCATOR_IS_MEMORY_TRUTH: bool = false;

// ===========================================================================
// 3. StageDPolicyObservation — measurement-only self-evolution signal
// ===========================================================================

/// Kind of measurement-only policy observation. Each names a surface the
/// agent may *measure* for Stage E, never mutate in Stage D production.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
#[repr(u8)]
pub enum StageDPolicyObservationKind {
    /// Memory-retrieval policy quality observation.
    MemoryRetrieval = 1,
    /// Context-selection policy quality observation.
    ContextSelection = 2,
    /// Skill-recommendation policy quality observation.
    SkillRecommendation = 3,
    /// Harness / workflow policy observation.
    HarnessWorkflow = 4,
}

impl StageDPolicyObservationKind {
    /// Stable `u8` tag — mirrors the `#[repr(u8)]` discriminant.
    #[inline]
    pub const fn tag(self) -> u8 {
        self as u8
    }
}

/// A measurement-only self-evolution observation.
///
/// It records an expected vs measured effect for one policy surface, bound to a
/// redacted [`StageDEvidenceRef`]. Crucially, `production_change_allowed` is a
/// **private** field fixed to `false` by [`new`](Self::new): there is no
/// constructor or setter in this crate that can make an observation promote
/// itself into a production policy mutation. This keeps the observation as
/// evidence, never authority. Promotion is a Stage E decision
/// behind sandbox / held-out approval.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct StageDPolicyObservation {
    /// Which policy surface was observed.
    pub kind: StageDPolicyObservationKind,
    /// Redacted evidence reference for the observation.
    pub evidence: StageDEvidenceRef,
    /// 32-byte hash of the expected effect (offline-computed).
    pub expected_effect_hash_32: [u8; 32],
    /// 32-byte hash of the measured effect (offline-observed).
    pub measured_effect_hash_32: [u8; 32],
    /// Fixed `false` by construction — an observation can never promote itself.
    production_change_allowed: bool,
}

impl StageDPolicyObservation {
    /// Construct a measurement-only observation. `production_change_allowed` is
    /// always `false` — there is no path here to make it `true`.
    #[inline]
    pub const fn new(
        kind: StageDPolicyObservationKind,
        evidence: StageDEvidenceRef,
        expected_effect_hash_32: [u8; 32],
        measured_effect_hash_32: [u8; 32],
    ) -> Self {
        Self {
            kind,
            evidence,
            expected_effect_hash_32,
            measured_effect_hash_32,
            production_change_allowed: false,
        }
    }

    /// Whether this observation is allowed to change production policy. Always
    /// `false` (measurement-only); Stage E owns any promotion.
    #[inline]
    pub const fn production_change_allowed(&self) -> bool {
        self.production_change_allowed
    }
}

// ===========================================================================
// 4. ReadOnlyBaseline — read-only A/B observation
// ===========================================================================

/// A read-only baseline observed from Stage A chunks and a Stage B replay
/// report. It holds **counts only** and exposes no mutation path over memory
/// truth — the intelligence layer observes, it never rewrites chunk, blob,
/// owner or replay state.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Default)]
pub struct ReadOnlyBaseline {
    /// Number of chunks observed.
    pub observed_chunks_u64: u64,
    /// Total observed chunk content bytes (a size signal, not the content).
    pub observed_content_bytes_u64: u64,
    /// Replay events applied, copied from the Stage B replay report.
    pub replay_applied_u64: u64,
    /// Replay events rejected, copied from the Stage B replay report.
    pub replay_rejected_u64: u64,
}

impl ReadOnlyBaseline {
    /// Observe a baseline from borrowed Stage A chunks and a borrowed Stage B
    /// replay report. Pure read: the inputs are borrowed and never mutated, and
    /// no persistence ([`MemoryPersist`](crate::persist::MemoryPersist)) is
    /// triggered.
    #[must_use]
    pub fn observe(chunks: &[MemoryChunk], replay: &StageBReplayReport) -> Self {
        let mut observed_content_bytes_u64: u64 = 0;
        for chunk in chunks {
            let len = chunk.envelope().content.len() as u64;
            observed_content_bytes_u64 = observed_content_bytes_u64.saturating_add(len);
        }
        Self {
            observed_chunks_u64: chunks.len() as u64,
            observed_content_bytes_u64,
            replay_applied_u64: replay.applied_u64,
            replay_rejected_u64: replay.rejected_u64,
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    #![allow(clippy::expect_used)]
    #![allow(clippy::panic)]

    use super::*;
    use crate::persist::MemoryPersist;
    use crate::stage_b_replay::stage_b_transcript_hash;
    use mnemos_a_core::{StageBTraceLink, StageCTraceLink};
    use mnemos_c_walrus::{ChunkEnvelopeV1, ChunkKind, MemoryRole};

    fn sample_chunk(id: u64, content: &[u8]) -> MemoryChunk {
        let envelope = ChunkEnvelopeV1 {
            kind: ChunkKind::UserMessage,
            role: MemoryRole::User,
            parent: None,
            content: content.to_vec(),
            embedding: None,
            signature: None,
            provenance: None,
        };
        MemoryChunk::new(crate::chunk::MemoryId::new(id), envelope)
    }

    fn sample_replay() -> StageBReplayReport {
        StageBReplayReport {
            transcript: stage_b_transcript_hash(b"intelligence-baseline-fixture"),
            applied_u64: 3,
            duplicate_u64: 1,
            rejected_u64: 2,
        }
    }

    fn sample_trace() -> StageDTraceLink {
        StageDTraceLink::new(
            StageCTraceLink::new(StageBTraceLink::new(7, 321, 0), 321, 99),
            321,
            0,
        )
    }

    #[test]
    fn imports_a_and_b_types_read_only_baseline() {
        // Proves the intelligence boundary imports Stage A (`MemoryChunk`) and
        // Stage B (`StageBReplayReport`) types without re-minting them.
        let chunks = [sample_chunk(1, b"hello"), sample_chunk(2, b"world!!")];
        let replay = sample_replay();
        let baseline = ReadOnlyBaseline::observe(&chunks, &replay);
        assert_eq!(baseline.observed_chunks_u64, 2);
        // "hello" = 5 bytes, "world!!" = 7 bytes.
        assert_eq!(baseline.observed_content_bytes_u64, 5 + 7);
        assert_eq!(baseline.replay_applied_u64, 3);
        assert_eq!(baseline.replay_rejected_u64, 2);
        // `MemoryPersist` is named to pin the reuse boundary; the read-only
        // baseline never constructs a persistence plan.
        let _persist_is_out_of_read_path = core::marker::PhantomData::<MemoryPersist>;
    }

    #[test]
    fn policy_observation_cannot_promote() {
        let trace = sample_trace();
        let evidence = StageDEvidenceRef::new([0x11; 32], trace);
        for kind in [
            StageDPolicyObservationKind::MemoryRetrieval,
            StageDPolicyObservationKind::ContextSelection,
            StageDPolicyObservationKind::SkillRecommendation,
            StageDPolicyObservationKind::HarnessWorkflow,
        ] {
            let obs = StageDPolicyObservation::new(kind, evidence, [0x22; 32], [0x33; 32]);
            assert!(
                !obs.production_change_allowed(),
                "observation must never be allowed to promote production policy"
            );
        }
    }

    #[test]
    fn archive_locator_is_not_memory_truth() {
        // Compile-time enforced: an archive locator is never memory truth.
        const { assert!(!ARCHIVE_LOCATOR_IS_MEMORY_TRUTH) };
    }

    #[test]
    fn evidence_ref_is_hash_only() {
        let trace = sample_trace();
        let evidence = StageDEvidenceRef::new([0xAB; 32], trace);
        assert_eq!(evidence.path_hash_32, [0xAB; 32]);
        assert_eq!(evidence.trace, trace);
    }

    #[test]
    fn delete_semantics_discriminants_stable() {
        assert_eq!(DeleteSemantics::Tombstone.tag(), 1);
        assert_eq!(DeleteSemantics::HardDeleteLocal.tag(), 2);
        assert_eq!(DeleteSemantics::ExportRedacted.tag(), 3);
    }

    #[test]
    fn policy_observation_kind_discriminants_stable() {
        assert_eq!(StageDPolicyObservationKind::MemoryRetrieval.tag(), 1);
        assert_eq!(StageDPolicyObservationKind::ContextSelection.tag(), 2);
        assert_eq!(StageDPolicyObservationKind::SkillRecommendation.tag(), 3);
        assert_eq!(StageDPolicyObservationKind::HarnessWorkflow.tag(), 4);
    }
}
