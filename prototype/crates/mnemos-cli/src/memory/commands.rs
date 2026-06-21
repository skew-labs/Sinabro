//! `sinabro memory status / export / delete / replay` command surface
//! (atom #533 · G.4.2).
//!
//! User-owned memory is inspectable and controllable. `status` is a hot-path
//! summary that never triggers a full replay; `export` / `delete` / `replay`
//! delegate to the canonical Stage F portability views over the local / owned
//! Stage B/D memory roots. A deleted tombstone can never be resurrected by import,
//! compaction, or replay, and the archive location is never the truth
//! (`G-G-MEMORY-OWNERSHIP`).
//!
//! Secret custody (`G-G-SECRET-ZERO`): the surface holds no secret / wallet
//! material — every projected field is a redacted 16-hex prefix, a `u64` count, or
//! an enum tag, so [`MemoryCommandSurface::holds_no_secret`] and
//! [`MemoryStatusView::holds_no_secret`] are the structural invariant `true`
//! (mirroring [`crate::secrets::SecretRefView`] and the audit report draft).
//!
//! Reuse (no reinvention): [`MemoryExportView`] / [`MemoryDeleteReceipt`] /
//! [`MemoryReplayView`] from [`crate::commands::memory_portability`]; the deletion
//! / replay semantics are the canonical Stage B/D `TombstonePolicy` /
//! `ReplayPortabilityReport`.

use crate::command::CommandRisk;
use crate::commands::memory_portability::{
    MemoryDeleteReceipt, MemoryExportView, MemoryReplayView,
};
use crate::hex32;
use mnemos_b_memory::{
    DeleteSemantics, MemoryId, PortableMemoryBundle, ReplayPortabilityReport,
    StageBTranscriptHash32, TombstonePolicy,
};

/// First 16 hex characters of a 32-byte digest — a redacted, display-only prefix.
#[must_use]
fn redact16(bytes: &[u8; 32]) -> String {
    hex32(bytes).chars().take(16).collect()
}

/// The four memory operations exposed by the surface.
#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MemoryCommand {
    /// Read-only hot-path status (no full replay).
    Status = 1,
    /// Export the user-owned bundle (local write).
    Export = 2,
    /// Delete a memory (local, auditable tombstone write).
    Delete = 3,
    /// Replay the bundle offline across a migration (read-only).
    Replay = 4,
}

impl MemoryCommand {
    /// Stable `u8` discriminant.
    #[must_use]
    pub const fn as_u8(self) -> u8 {
        self as u8
    }

    /// The command risk: `status` / `replay` are read-only; `export` / `delete`
    /// are local writes.
    #[must_use]
    pub const fn risk(self) -> CommandRisk {
        match self {
            Self::Status | Self::Replay => CommandRisk::ReadOnly,
            Self::Export | Self::Delete => CommandRisk::LocalWrite,
        }
    }

    /// Structural invariant: a memory command carries no secret / wallet material.
    /// Always `true`.
    #[must_use]
    pub const fn holds_no_secret(self) -> bool {
        true
    }
}

/// A hot-path memory status summary: the redacted tombstone-set + memory-root
/// hashes, and the proof that the status path never triggered a full replay.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MemoryStatusView {
    /// Redacted 16-hex prefix of the tombstone-set hash.
    pub tombstone_set_redacted: String,
    /// Redacted 16-hex prefix of the user-owned memory root.
    pub memory_root_redacted: String,
    /// Invariant `false`: the status hot path never triggers a full replay.
    pub full_replay_triggered: bool,
}

impl MemoryStatusView {
    /// Summarize memory status from a tombstone policy and the owned memory root.
    /// O(tombstone-set hash) — never a full replay / export.
    #[must_use]
    pub fn summarize(policy: &TombstonePolicy, memory_root_32: [u8; 32]) -> Self {
        Self {
            tombstone_set_redacted: redact16(&policy.tombstone_hash_32()),
            memory_root_redacted: redact16(&memory_root_32),
            full_replay_triggered: false,
        }
    }

    /// Status is read-only.
    #[must_use]
    pub const fn risk(&self) -> CommandRisk {
        CommandRisk::ReadOnly
    }

    /// Whether the status path triggered a full replay (always `false` — the
    /// hot-path / no-blocking law).
    #[must_use]
    pub const fn full_replay_on_hot_path(&self) -> bool {
        self.full_replay_triggered
    }

    /// Structural invariant: the status view holds no secret. Always `true`.
    #[must_use]
    pub const fn holds_no_secret(&self) -> bool {
        true
    }

    /// Redacted, colorless status lines bounded by `rows`.
    #[must_use]
    pub fn render(&self, rows: u16) -> Vec<String> {
        let lines = vec![
            format!("tombstone_set={}", self.tombstone_set_redacted),
            format!("memory_root={}", self.memory_root_redacted),
            format!("full_replay_triggered={}", self.full_replay_triggered),
        ];
        lines.into_iter().take(rows as usize).collect()
    }
}

/// The operational memory command surface. A zero-field composition layer over the
/// canonical Stage F portability views — it owns no secret and mints no new memory
/// truth.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MemoryCommandSurface;

impl MemoryCommandSurface {
    /// `memory status` — a hot-path summary (no full replay).
    #[must_use]
    pub fn status(policy: &TombstonePolicy, memory_root_32: [u8; 32]) -> MemoryStatusView {
        MemoryStatusView::summarize(policy, memory_root_32)
    }

    /// `memory export --dry-run` — the redacted projection of the user-owned bundle.
    #[must_use]
    pub fn export_dry_run(bundle: &PortableMemoryBundle) -> MemoryExportView {
        MemoryExportView::from_bundle(bundle)
    }

    /// `memory delete --dry-run` — record an auditable tombstone (deletion wins
    /// over compaction / import / replay).
    #[must_use]
    pub fn delete_dry_run(
        policy: &mut TombstonePolicy,
        id: MemoryId,
        semantics: DeleteSemantics,
    ) -> MemoryDeleteReceipt {
        MemoryDeleteReceipt::delete(policy, id, semantics)
    }

    /// `memory replay --dry-run` — the offline replay outcome across a migration
    /// (zero deleted resurrections by construction).
    #[must_use]
    pub fn replay_dry_run(
        report: &ReplayPortabilityReport,
        expected_transcript: &StageBTranscriptHash32,
    ) -> MemoryReplayView {
        MemoryReplayView::from_report(report, expected_transcript)
    }

    /// Whether a memory id is deleted (tombstoned) — a deleted id can never be
    /// resurrected.
    #[must_use]
    pub fn is_deleted(policy: &TombstonePolicy, id: MemoryId) -> bool {
        policy.is_tombstoned(id)
    }

    /// Structural invariant: the surface holds no secret / wallet material. Always
    /// `true`.
    #[must_use]
    pub const fn holds_no_secret() -> bool {
        true
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    #![allow(clippy::expect_used)]
    use super::*;
    use crate::sha256_32;
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
            transcript: stage_b_transcript_hash(b"memory-cli-fixture"),
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
    fn status_hot_path_no_full_replay() {
        let p = tombstones();
        let s = MemoryCommandSurface::status(&p, sha256_32(b"root"));
        assert!(!s.full_replay_on_hot_path());
        assert_eq!(s.risk(), CommandRisk::ReadOnly);
        assert_eq!(s.tombstone_set_redacted.len(), 16);
        assert!(s.holds_no_secret());
    }

    #[test]
    fn export_dry_run() {
        let b = bundle();
        let v = MemoryCommandSurface::export_dry_run(&b);
        assert_eq!(v.risk(), CommandRisk::LocalWrite);
        assert_eq!(v.bundle_hash_redacted.len(), 16);
    }

    #[test]
    fn delete_dry_run_tombstone() {
        let mut p = TombstonePolicy::new();
        let r = MemoryCommandSurface::delete_dry_run(
            &mut p,
            MemoryId::new(5),
            DeleteSemantics::Tombstone,
        );
        assert!(r.tombstoned);
        assert!(MemoryCommandSurface::is_deleted(&p, MemoryId::new(5)));
        assert_eq!(MemoryCommand::Delete.risk(), CommandRisk::LocalWrite);
    }

    #[test]
    fn replay_dry_run_zero_resurrection() {
        let b = bundle();
        let tombs = tombstones();
        let candidates = [
            MemoryId::new(10),
            MemoryId::new(11),
            MemoryId::new(12),
            MemoryId::new(13),
        ];
        let report =
            ProviderMigration::new(1, 2).replay_portable(&b, &tombs, &candidates, &replay());
        let v = MemoryCommandSurface::replay_dry_run(&report, &b.transcript);
        assert_eq!(v.deleted_resurrections_u64, 0);
        assert!(v.transcript_stable);
        assert_eq!(v.risk(), CommandRisk::ReadOnly);
    }

    #[test]
    fn tombstone_deny_no_resurrection() {
        let mut p = TombstonePolicy::new();
        let _ = MemoryCommandSurface::delete_dry_run(
            &mut p,
            MemoryId::new(5),
            DeleteSemantics::Tombstone,
        );
        let scan = p.scan_candidates(&replay(), &[MemoryId::new(5), MemoryId::new(6)]);
        assert_eq!(scan.deleted_resurrections_u64, 0);
        assert!(scan.zero_resurrections());
    }

    #[test]
    fn secret_zero_no_commerce() {
        let p = tombstones();
        let s = MemoryCommandSurface::status(&p, sha256_32(b"root"));
        assert!(MemoryCommandSurface::holds_no_secret());
        assert!(MemoryCommand::Status.holds_no_secret());
        for line in s.render(8) {
            for bad in COMMERCE_TOKENS {
                assert!(!line.contains(bad), "commerce token {bad} in {line}");
            }
        }
    }
}
