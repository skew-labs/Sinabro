//! `memory export / import / delete / replay / mirror-dry-run / archive-dry-run`
//! portability command group (F-WP-05B, atom #445 · F.5.2).
//!
//! Read-only projections + thin wrappers over the canonical Stage B replay and
//! Stage D portability surfaces (both owned by `b-memory`). Three Stage F
//! invariants are structural:
//!
//! * **Root hash + transcript preserved.** Export/import/replay carry the bundle's
//!   verified root blob and Stage B transcript verbatim ([`import_bundle`] rejects
//!   a tampered root with [`MemoryPortabilityReject::RootMismatch`]).
//! * **Delete is permanent.** [`MemoryDeleteReceipt::delete`] writes an auditable
//!   tombstone; a deleted id can never be resurrected by import, compaction, or
//!   replay ([`ReplayPortabilityReport::deleted_resurrections_u64`] is always `0`).
//! * **IPFS/Filecoin are dry-run only.** [`MemoryDryRunPlan`] produces a plan /
//!   evidence hash only — never a live upload in Stage F
//!   ([`MemoryDryRunPlan::live_upload`] is `false`,
//!   [`StorageBackendPhase::FutureOnly`]).

use crate::command::{ApprovalRequirement, CommandRisk, approval_for};
use crate::{hex32, sha256_32};
use mnemos_b_memory::{
    DeleteSemantics, MemoryId, PortableMemoryBundle, ReplayPortabilityReport,
    StageBTranscriptHash32, StorageBackendKind, StorageBackendPhase, TombstonePolicy,
    import_bundle,
};

/// First 16 hex characters of a 32-byte digest — a redacted, display-only prefix.
#[must_use]
fn redact16(bytes: &[u8; 32]) -> String {
    hex32(bytes).chars().take(16).collect()
}

/// Why a portability command was refused (fail-closed).
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum MemoryPortabilityReject {
    /// The recomputed bundle digest did not match the claimed one — the root is not
    /// the bundle it claims to be (tamper / drift).
    #[error("bundle root hash mismatch")]
    RootMismatch,
}

/// A read-only projection of a canonical [`PortableMemoryBundle`]: the four
/// user-owned roots (root blob, transcript, user-model hash, tombstone hash) plus
/// the bundle digest, all redacted for display.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MemoryExportView {
    /// Redacted 16-hex prefix of the bundle digest.
    pub bundle_hash_redacted: String,
    /// Redacted 16-hex prefix of the verified root blob id.
    pub root_blob_redacted: String,
    /// Redacted 16-hex prefix of the Stage B replay transcript hash.
    pub transcript_redacted: String,
    /// Redacted 16-hex prefix of the user-model hash.
    pub user_model_hash_redacted: String,
    /// Redacted 16-hex prefix of the tombstone-set hash.
    pub tombstone_hash_redacted: String,
}

impl MemoryExportView {
    /// Project a [`PortableMemoryBundle`]. The verified root blob is reached via
    /// the bundle's `root_blob` field accessor chain (no `VerifiedBlobId` type
    /// import — that type is a `c-walrus` concern kept out of the production edge).
    #[must_use]
    pub fn from_bundle(bundle: &PortableMemoryBundle) -> Self {
        Self {
            bundle_hash_redacted: redact16(&bundle.bundle_hash_32()),
            root_blob_redacted: redact16(bundle.root_blob.as_blob_id().as_bytes()),
            transcript_redacted: redact16(bundle.transcript.as_bytes()),
            user_model_hash_redacted: redact16(&bundle.user_model_hash_32),
            tombstone_hash_redacted: redact16(&bundle.tombstone_hash_32),
        }
    }

    /// The command risk of committing an export (it writes a local file).
    #[must_use]
    pub const fn risk(&self) -> CommandRisk {
        CommandRisk::LocalWrite
    }

    /// The approval requirement for an export (Confirm).
    #[must_use]
    pub fn approval(&self) -> ApprovalRequirement {
        approval_for(self.risk())
    }

    /// Redacted, colorless export lines bounded by `rows`.
    #[must_use]
    pub fn render(&self, rows: u16) -> Vec<String> {
        let lines = vec![
            format!("bundle_hash={}", self.bundle_hash_redacted),
            format!("root_blob={}", self.root_blob_redacted),
            format!("transcript={}", self.transcript_redacted),
            format!("user_model_hash={}", self.user_model_hash_redacted),
            format!("tombstone_hash={}", self.tombstone_hash_redacted),
        ];
        lines.into_iter().take(rows as usize).collect()
    }
}

/// Import a portable bundle by verifying its digest against the claimed identity
/// (reuses the canonical [`import_bundle`]). On success returns the projected
/// export view; on mismatch the root-mismatch rejection. Import performs no live
/// mainnet / RPC action (the optional mainnet anchor is not taken here).
pub fn import_status(
    bundle: PortableMemoryBundle,
    claimed_bundle_hash_32: &[u8; 32],
) -> Result<MemoryExportView, MemoryPortabilityReject> {
    match import_bundle(bundle, claimed_bundle_hash_32, None) {
        Ok(root) => Ok(MemoryExportView::from_bundle(&root.bundle)),
        Err(_) => Err(MemoryPortabilityReject::RootMismatch),
    }
}

/// Receipt for a memory deletion: every deletion mode writes an auditable
/// tombstone, so the id can never be resurrected by import, compaction, or replay.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MemoryDeleteReceipt {
    /// The deleted memory id.
    pub memory_id_u64: u64,
    /// The recorded deletion-semantics tag.
    pub delete_semantics_u8: u8,
    /// Whether the id is now tombstoned (always `true` after a successful delete).
    pub tombstoned: bool,
}

impl MemoryDeleteReceipt {
    /// Delete a memory: record an auditable tombstone in `policy` (reuses the
    /// canonical [`TombstonePolicy::record`]) and return the receipt.
    #[must_use]
    pub fn delete(policy: &mut TombstonePolicy, id: MemoryId, semantics: DeleteSemantics) -> Self {
        policy.record(id, semantics);
        Self {
            memory_id_u64: id.get(),
            delete_semantics_u8: semantics.tag(),
            tombstoned: policy.is_tombstoned(id),
        }
    }

    /// The command risk of a delete (a local, auditable write).
    #[must_use]
    pub const fn risk(&self) -> CommandRisk {
        CommandRisk::LocalWrite
    }

    /// The approval requirement for a delete (Confirm).
    #[must_use]
    pub fn approval(&self) -> ApprovalRequirement {
        approval_for(self.risk())
    }

    /// Redacted, colorless delete-receipt lines bounded by `rows`.
    #[must_use]
    pub fn render(&self, rows: u16) -> Vec<String> {
        let lines = vec![
            format!("memory_id={}", self.memory_id_u64),
            format!("delete_semantics_u8={}", self.delete_semantics_u8),
            format!("tombstoned={}", self.tombstoned),
        ];
        lines.into_iter().take(rows as usize).collect()
    }
}

/// A read-only projection of a canonical [`ReplayPortabilityReport`]: the
/// offline replay outcome across a model/provider/platform migration.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MemoryReplayView {
    /// Candidate ids re-applied (not tombstoned).
    pub replayed_chunks_u64: u64,
    /// Candidate ids rejected (tombstoned; blocked from resurrection).
    pub rejected_chunks_u64: u64,
    /// Deleted memories that resurrected — always `0`.
    pub deleted_resurrections_u64: u64,
    /// Redacted 16-hex prefix of the carried Stage B transcript hash.
    pub transcript_redacted: String,
    /// Whether both #329 criteria held (transcript stable + zero resurrections).
    pub transcript_stable: bool,
}

impl MemoryReplayView {
    /// Project a [`ReplayPortabilityReport`], checking it upholds the criteria
    /// against the expected transcript (reuses
    /// [`ReplayPortabilityReport::upholds_criteria`]).
    #[must_use]
    pub fn from_report(
        report: &ReplayPortabilityReport,
        expected_transcript: &StageBTranscriptHash32,
    ) -> Self {
        Self {
            replayed_chunks_u64: report.replayed_chunks_u64,
            rejected_chunks_u64: report.rejected_chunks_u64,
            deleted_resurrections_u64: report.deleted_resurrections_u64,
            transcript_redacted: redact16(report.transcript.as_bytes()),
            transcript_stable: report.upholds_criteria(expected_transcript),
        }
    }

    /// Replay status is a read-only local summary (no approval).
    #[must_use]
    pub const fn risk(&self) -> CommandRisk {
        CommandRisk::ReadOnly
    }

    /// Redacted, colorless replay-status lines bounded by `rows`.
    #[must_use]
    pub fn render(&self, rows: u16) -> Vec<String> {
        let lines = vec![
            format!("replayed_chunks={}", self.replayed_chunks_u64),
            format!("rejected_chunks={}", self.rejected_chunks_u64),
            format!("deleted_resurrections={}", self.deleted_resurrections_u64),
            format!("transcript={}", self.transcript_redacted),
            format!("transcript_stable={}", self.transcript_stable),
        ];
        lines.into_iter().take(rows as usize).collect()
    }
}

/// An IPFS-mirror / Filecoin-archive **dry-run** plan: a plan/evidence hash only,
/// never a live upload in Stage F. The backend is always a `FutureOnly` label.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MemoryDryRunPlan {
    /// The mirror/archive backend kind tag (IPFS or Filecoin).
    pub backend_kind_u8: u8,
    /// The backend lifecycle phase tag (always `FutureOnly`).
    pub phase_u8: u8,
    /// Redacted 16-hex prefix of the dry-run plan/evidence hash.
    pub plan_hash_redacted: String,
    /// Whether a live upload occurs — always `false` in Stage F.
    pub live_upload: bool,
}

impl MemoryDryRunPlan {
    /// Build an IPFS-mirror dry-run plan from the plan seed bytes (no live upload).
    #[must_use]
    pub fn ipfs_mirror(plan_seed: &[u8]) -> Self {
        Self {
            backend_kind_u8: StorageBackendKind::IpfsMirror.tag(),
            phase_u8: StorageBackendPhase::FutureOnly.tag(),
            plan_hash_redacted: redact16(&sha256_32(plan_seed)),
            live_upload: false,
        }
    }

    /// Build a Filecoin-archive dry-run plan from the plan seed bytes (no live
    /// upload).
    #[must_use]
    pub fn filecoin_archive(plan_seed: &[u8]) -> Self {
        Self {
            backend_kind_u8: StorageBackendKind::FilecoinArchive.tag(),
            phase_u8: StorageBackendPhase::FutureOnly.tag(),
            plan_hash_redacted: redact16(&sha256_32(plan_seed)),
            live_upload: false,
        }
    }

    /// Whether a live archive/mirror writer is (correctly) denied: no live upload
    /// and the backend sits in the `FutureOnly` phase.
    #[must_use]
    pub const fn live_writer_denied(&self) -> bool {
        !self.live_upload && self.phase_u8 == StorageBackendPhase::FutureOnly.tag()
    }

    /// Redacted, colorless dry-run lines bounded by `rows`.
    #[must_use]
    pub fn render(&self, rows: u16) -> Vec<String> {
        let lines = vec![
            format!("backend_kind_u8={}", self.backend_kind_u8),
            format!("phase_u8={}", self.phase_u8),
            format!("plan_hash={}", self.plan_hash_redacted),
            format!("live_upload={}", self.live_upload),
            format!("live_writer_denied={}", self.live_writer_denied()),
        ];
        lines.into_iter().take(rows as usize).collect()
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    #![allow(clippy::expect_used)]
    #![allow(clippy::panic)]

    use super::*;
    use mnemos_b_memory::{
        ProviderMigration, SigningPublicKey, StageBReplayReport, UserModel, UserModelDelta,
        export_bundle, stage_b_transcript_hash,
    };
    use mnemos_c_walrus::{
        PublisherReportedBlobId, VerifiedBlobId, derive_blob_id, verify_reported_blob_id,
    };

    const COMMERCE_TOKENS: &[&str] = &[
        "price", "pay", "buy", "sell", "checkout", "refund", "fee", "cost", "$",
    ];

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

    fn verified_blob(seed: &[u8]) -> VerifiedBlobId {
        let derived = derive_blob_id(seed);
        let text = encode_b64url(derived.as_bytes());
        let reported = PublisherReportedBlobId::try_from_text(&text).expect("base64url length 43");
        verify_reported_blob_id(seed, &reported).expect("self-derived round-trip must verify")
    }

    fn owner() -> SigningPublicKey {
        SigningPublicKey::from_bytes(&[9_u8; 32]).expect("32-byte owner key")
    }

    fn user_model() -> UserModelDelta {
        let mut m = UserModel::empty(owner());
        m.set_preferences(b"terse-replies");
        m.set_facts(b"lives-in-seoul");
        m.to_delta(DeleteSemantics::Tombstone)
    }

    fn tombstones() -> TombstonePolicy {
        let mut p = TombstonePolicy::new();
        p.record(MemoryId::new(10), DeleteSemantics::Tombstone);
        p.record(MemoryId::new(11), DeleteSemantics::HardDeleteLocal);
        p
    }

    fn replay() -> StageBReplayReport {
        StageBReplayReport {
            transcript: stage_b_transcript_hash(b"portability-cli-fixture"),
            applied_u64: 8,
            duplicate_u64: 0,
            rejected_u64: 0,
        }
    }

    fn bundle() -> PortableMemoryBundle {
        export_bundle(
            verified_blob(b"root"),
            &replay(),
            &user_model(),
            &tombstones(),
        )
    }

    #[test]
    fn export_import_roundtrip() {
        let b = bundle();
        let view = MemoryExportView::from_bundle(&b);
        assert_eq!(view.approval(), ApprovalRequirement::Confirm);
        let h = b.bundle_hash_32();
        let imported = import_status(b, &h).unwrap();
        assert_eq!(imported, view);
    }

    #[test]
    fn root_mismatch_import_deny() {
        let b = bundle();
        let mut wrong = b.bundle_hash_32();
        wrong[0] ^= 0x01;
        assert_eq!(
            import_status(b, &wrong),
            Err(MemoryPortabilityReject::RootMismatch)
        );
    }

    #[test]
    fn replay_deterministic_and_transcript_stable() {
        let b = bundle();
        let tombs = tombstones();
        let candidates = [
            MemoryId::new(10),
            MemoryId::new(11),
            MemoryId::new(12),
            MemoryId::new(13),
        ];
        let r1 = ProviderMigration::new(1, 2).replay_portable(&b, &tombs, &candidates, &replay());
        let r2 = ProviderMigration::new(1, 2).replay_portable(&b, &tombs, &candidates, &replay());
        let v1 = MemoryReplayView::from_report(&r1, &b.transcript);
        let v2 = MemoryReplayView::from_report(&r2, &b.transcript);
        assert_eq!(v1, v2, "replay must be deterministic");
        assert_eq!(v1.replayed_chunks_u64, 2); // 12, 13 live
        assert_eq!(v1.rejected_chunks_u64, 2); // 10, 11 tombstoned
        assert_eq!(v1.deleted_resurrections_u64, 0);
        assert!(v1.transcript_stable);
        assert_eq!(v1.risk(), CommandRisk::ReadOnly);
    }

    #[test]
    fn delete_tombstone_write() {
        let mut p = TombstonePolicy::new();
        let receipt =
            MemoryDeleteReceipt::delete(&mut p, MemoryId::new(5), DeleteSemantics::Tombstone);
        assert!(receipt.tombstoned);
        assert_eq!(receipt.memory_id_u64, 5);
        assert_eq!(
            receipt.delete_semantics_u8,
            DeleteSemantics::Tombstone.tag()
        );
        assert!(p.is_tombstoned(MemoryId::new(5)));
        assert_eq!(receipt.approval(), ApprovalRequirement::Confirm);
    }

    #[test]
    fn delete_resurrection_deny() {
        let mut p = TombstonePolicy::new();
        let _ = MemoryDeleteReceipt::delete(&mut p, MemoryId::new(5), DeleteSemantics::Tombstone);
        // After delete, the id is blocked from any candidate re-application.
        let scan = p.scan_candidates(&replay(), &[MemoryId::new(5), MemoryId::new(6)]);
        assert_eq!(scan.tombstone_blocked_u64, 1);
        assert_eq!(scan.admitted_u64, 1);
        assert_eq!(scan.deleted_resurrections_u64, 0);
        assert!(scan.zero_resurrections());
    }

    #[test]
    fn compact_after_delete_deny() {
        // A deleted id occupies the terminal DeletedTombstone tier — compaction can
        // never age or resurrect it (deletion wins over compaction).
        let mut p = TombstonePolicy::new();
        let _ =
            MemoryDeleteReceipt::delete(&mut p, MemoryId::new(5), DeleteSemantics::HardDeleteLocal);
        assert_eq!(
            p.tier(MemoryId::new(5)),
            Some(mnemos_b_memory::MemoryTier::DeletedTombstone)
        );
    }

    #[test]
    fn ipfs_mirror_dry_run() {
        let plan = MemoryDryRunPlan::ipfs_mirror(b"root-to-mirror");
        assert_eq!(plan.backend_kind_u8, StorageBackendKind::IpfsMirror.tag());
        assert_eq!(plan.phase_u8, StorageBackendPhase::FutureOnly.tag());
        assert!(!plan.live_upload);
        assert!(plan.live_writer_denied());
    }

    #[test]
    fn filecoin_archive_dry_run() {
        let plan = MemoryDryRunPlan::filecoin_archive(b"root-to-archive");
        assert_eq!(
            plan.backend_kind_u8,
            StorageBackendKind::FilecoinArchive.tag()
        );
        assert_eq!(plan.phase_u8, StorageBackendPhase::FutureOnly.tag());
        assert!(!plan.live_upload);
        assert!(plan.live_writer_denied());
    }

    #[test]
    fn live_archive_writer_denied() {
        assert!(MemoryDryRunPlan::ipfs_mirror(b"x").live_writer_denied());
        assert!(MemoryDryRunPlan::filecoin_archive(b"y").live_writer_denied());
    }

    #[test]
    fn no_commerce_render() {
        let b = bundle();
        let export = MemoryExportView::from_bundle(&b);
        let mut p = TombstonePolicy::new();
        let del = MemoryDeleteReceipt::delete(&mut p, MemoryId::new(1), DeleteSemantics::Tombstone);
        let mirror = MemoryDryRunPlan::ipfs_mirror(b"x");
        for line in export
            .render(32)
            .into_iter()
            .chain(del.render(32))
            .chain(mirror.render(32))
        {
            for bad in COMMERCE_TOKENS {
                assert!(!line.contains(bad), "commerce token {bad} in: {line}");
            }
        }
    }
}
