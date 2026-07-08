//! AtomDietRecord assembler.
//!
//! One atom sidecar becomes one [`AtomDietRecord`]: a validated manifest plus
//! five *stream-isolated* digests. The 21 file kinds are partitioned into four
//! disjoint streams (S1 ground-truth, S2 narrative, privacy, trajectory) so a
//! change in one stream cannot perturb another stream's hash — no sample crosses
//! streams at assembly time. `compression_hash` is the raw-replay anchor over
//! *all* content hashes, so a compressed proof always links back to the raw
//! evidence. Training/reward eligibility defaults `false`.
use crate::artifacts;
use crate::completeness;
use crate::diet_kind::{AtomDietKey, DietFileKind};
use crate::discover::DiscoveredAtom;
use crate::error::DietResult;
use crate::manifest::{AtomDietManifest, DietCompleteness, DietFileRef};
use crate::{StageETraceLink, sha256};

/// Which evidence stream a file kind belongs to. The four streams are disjoint
/// and together cover all 21 kinds (verified by the exhaustive match in
/// [`stream_of`]).
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum DietStream {
    /// Verifiable execution evidence (commands, gates, tests, env, deps, diff).
    S1GroundTruth,
    /// Narrative / self-reported (chat, preference, reward, eval, human review).
    S2Narrative,
    /// Privacy surface (privacy report, redacted terminal).
    Privacy,
    /// Process trajectory (context, action trace, failures, no-ops, approvals).
    Trajectory,
}

/// The stream a file kind belongs to. Exhaustive — every kind is partitioned
/// exactly once, so the compiler rejects any future kind left unassigned.
pub const fn stream_of(kind: DietFileKind) -> DietStream {
    match kind {
        DietFileKind::CommandManifest
        | DietFileKind::EnvLock
        | DietFileKind::ArtifactHashes
        | DietFileKind::CodeDiff
        | DietFileKind::TestResults
        | DietFileKind::GateResults
        | DietFileKind::Review5Pack
        | DietFileKind::DenyAudit => DietStream::S1GroundTruth,
        DietFileKind::HumanReview
        | DietFileKind::SftChat
        | DietFileKind::PreferencePairs
        | DietFileKind::RewardLabels
        | DietFileKind::EvalSummary => DietStream::S2Narrative,
        DietFileKind::TerminalRedacted | DietFileKind::PrivacyReport => DietStream::Privacy,
        DietFileKind::InputContext
        | DietFileKind::ActionTrace
        | DietFileKind::FailedAttempts
        | DietFileKind::NoOpDecisions
        | DietFileKind::RedteamDecision
        | DietFileKind::ApprovalEvents => DietStream::Trajectory,
    }
}

/// One source atom rendered as a typed, hash-pinned record.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AtomDietRecord {
    /// The validated per-atom manifest.
    pub manifest: AtomDietManifest,
    /// Digest of the S1 ground-truth stream.
    pub s1_hash_32: [u8; 32],
    /// Digest of the S2 narrative stream.
    pub s2_hash_32: [u8; 32],
    /// Digest of the privacy stream.
    pub privacy_hash_32: [u8; 32],
    /// Digest of the trajectory stream.
    pub trajectory_hash_32: [u8; 32],
    /// Raw-replay anchor: digest over *all* content hashes.
    pub compression_hash_32: [u8; 32],
}

impl AtomDietRecord {
    /// Whether this record is training/reward eligible. Always `false`:
    /// eligibility is recomputed by a later stage only after S1 reverify and a
    /// privacy pass. Dataset-build never grants reward.
    pub const fn training_eligible(&self) -> bool {
        false
    }

    /// A deterministic digest over the manifest and all five stream hashes.
    pub fn record_hash(&self) -> [u8; 32] {
        let mut buf = Vec::with_capacity(32 * 6);
        buf.extend_from_slice(&self.manifest.manifest_hash());
        buf.extend_from_slice(&self.s1_hash_32);
        buf.extend_from_slice(&self.s2_hash_32);
        buf.extend_from_slice(&self.privacy_hash_32);
        buf.extend_from_slice(&self.trajectory_hash_32);
        buf.extend_from_slice(&self.compression_hash_32);
        sha256(&buf)
    }
}

/// Assemble a record from already-built file refs and a completeness verdict.
/// The manifest is validated (schema/dup/empty-hash/consistency) before the
/// record is returned.
pub fn assemble(
    key: AtomDietKey,
    trace: StageETraceLink,
    refs: Vec<DietFileRef>,
    verdict: DietCompleteness,
) -> DietResult<AtomDietRecord> {
    let mut order: Vec<&DietFileRef> = refs.iter().collect();
    order.sort_by_key(|r| r.kind.as_u8());
    let mut s1 = Vec::new();
    let mut s2 = Vec::new();
    let mut privacy = Vec::new();
    let mut trajectory = Vec::new();
    let mut all = Vec::new();
    for r in order {
        all.extend_from_slice(&r.content_hash_32);
        match stream_of(r.kind) {
            DietStream::S1GroundTruth => s1.extend_from_slice(&r.content_hash_32),
            DietStream::S2Narrative => s2.extend_from_slice(&r.content_hash_32),
            DietStream::Privacy => privacy.extend_from_slice(&r.content_hash_32),
            DietStream::Trajectory => trajectory.extend_from_slice(&r.content_hash_32),
        }
    }
    let manifest = AtomDietManifest::current(key, refs, verdict, trace);
    manifest.validate()?;
    Ok(AtomDietRecord {
        manifest,
        s1_hash_32: sha256(&s1),
        s2_hash_32: sha256(&s2),
        privacy_hash_32: sha256(&privacy),
        trajectory_hash_32: sha256(&trajectory),
        compression_hash_32: sha256(&all),
    })
}

/// Assemble a record directly from a discovered atom directory, hashing each
/// present file from disk and classifying completeness.
pub fn assemble_from_discovered(
    discovered: &DiscoveredAtom,
    trace: StageETraceLink,
) -> DietResult<AtomDietRecord> {
    let mut refs = Vec::with_capacity(discovered.present.len());
    for (kind, path) in &discovered.present {
        refs.push(artifacts::ref_from_disk(*kind, path)?);
    }
    let verdict = completeness::classify(&discovered.present_kinds(), discovered.unknown_count);
    let key = AtomDietKey::new(discovered.source, discovered.atom_u16);
    assemble(key, trace, refs, verdict)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::diet_kind::DietSourceStage;

    fn key() -> AtomDietKey {
        AtomDietKey::new(DietSourceStage::StageD, 348)
    }

    fn trace() -> StageETraceLink {
        StageETraceLink::new([3u8; 32], 348, 11)
    }

    fn ref_for(kind: DietFileKind, content: u8) -> DietFileRef {
        DietFileRef::new(kind, [kind.as_u8().wrapping_add(100); 32], [content; 32], 1)
    }

    fn all_refs() -> Vec<DietFileRef> {
        DietFileKind::ALL
            .into_iter()
            .map(|k| ref_for(k, k.as_u8()))
            .collect()
    }

    #[test]
    fn stream_partition_covers_all_21_disjointly() {
        let mut s1 = 0;
        let mut s2 = 0;
        let mut pv = 0;
        let mut tr = 0;
        for k in DietFileKind::ALL {
            match stream_of(k) {
                DietStream::S1GroundTruth => s1 += 1,
                DietStream::S2Narrative => s2 += 1,
                DietStream::Privacy => pv += 1,
                DietStream::Trajectory => tr += 1,
            }
        }
        assert_eq!((s1, s2, pv, tr), (8, 5, 2, 6));
        assert_eq!(s1 + s2 + pv + tr, 21);
    }

    #[test]
    fn full_assembly_validates_and_is_not_eligible() -> DietResult<()> {
        let rec = assemble(key(), trace(), all_refs(), DietCompleteness::Complete)?;
        assert!(!rec.training_eligible());
        assert_eq!(rec.manifest.files.len(), 21);
        // the four stream digests are distinct from one another.
        assert_ne!(rec.s1_hash_32, rec.s2_hash_32);
        assert_ne!(rec.privacy_hash_32, rec.trajectory_hash_32);
        Ok(())
    }

    #[test]
    fn partial_and_rejected_assemble_but_are_not_eligible() -> DietResult<()> {
        let subset = vec![
            ref_for(DietFileKind::EnvLock, 5),
            ref_for(DietFileKind::SftChat, 18),
        ];
        let partial = assemble(
            key(),
            trace(),
            subset.clone(),
            DietCompleteness::PartialNoReward,
        )?;
        assert!(!partial.training_eligible());
        let rejected = assemble(key(), trace(), subset, DietCompleteness::Rejected)?;
        assert!(!rejected.training_eligible());
        Ok(())
    }

    #[test]
    fn assembly_is_order_independent() -> DietResult<()> {
        let forward = assemble(key(), trace(), all_refs(), DietCompleteness::Complete)?;
        let mut rev = all_refs();
        rev.reverse();
        let reversed = assemble(key(), trace(), rev, DietCompleteness::Complete)?;
        assert_eq!(forward.record_hash(), reversed.record_hash());
        Ok(())
    }

    #[test]
    fn streams_do_not_cross() -> DietResult<()> {
        let base = assemble(key(), trace(), all_refs(), DietCompleteness::Complete)?;
        // mutate only an S2 file (sft_chat) content hash.
        let mut mutated = all_refs();
        for r in mutated.iter_mut() {
            if r.kind == DietFileKind::SftChat {
                *r = DietFileRef::new(r.kind, r.path_hash_32, [0xEE; 32], r.bytes_u64);
            }
        }
        let after = assemble(key(), trace(), mutated, DietCompleteness::Complete)?;
        assert_eq!(
            base.s1_hash_32, after.s1_hash_32,
            "S1 must be untouched by an S2 change"
        );
        assert_eq!(base.privacy_hash_32, after.privacy_hash_32);
        assert_eq!(base.trajectory_hash_32, after.trajectory_hash_32);
        assert_ne!(base.s2_hash_32, after.s2_hash_32, "S2 must change");
        assert_ne!(
            base.compression_hash_32, after.compression_hash_32,
            "raw-replay anchor must change"
        );
        Ok(())
    }

    #[test]
    fn assemble_from_disk_partial() -> Result<(), Box<dyn std::error::Error>> {
        use std::fs;
        let root = std::env::temp_dir().join("mnemos_ld_record_disk");
        let _ = fs::remove_dir_all(&root);
        let atom = root.join("phase_0").join("atom_007");
        fs::create_dir_all(&atom)?;
        fs::write(atom.join("env_lock.json"), b"{\"host\":{\"os\":\"x\"}}\n")?;
        fs::write(atom.join("command_manifest.json"), b"{\"commands\":[]}\n")?;
        let discovered = crate::discover::discover_stage(&root, DietSourceStage::Phase0)?;
        assert_eq!(discovered.len(), 1);
        let rec = assemble_from_discovered(&discovered[0], trace())?;
        assert_eq!(rec.manifest.completeness, DietCompleteness::PartialNoReward);
        assert!(!rec.training_eligible());
        let _ = fs::remove_dir_all(&root);
        Ok(())
    }
}
