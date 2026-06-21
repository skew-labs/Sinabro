//! Evidence pack manifest (atom #531 · G.4.0).
//!
//! Provider consult, audit candidate, memory replay, Telegram event, command
//! trace, gate result, and local repro receipts are grouped by task / session
//! into one [`EvidencePackManifest`] with a stable, order-independent
//! [`EvidencePackManifest::pack_hash_32`]. A missing (zero) artifact hash or a
//! duplicate evidence kind is refused (fail-closed). The manifest carries only
//! `[u8; 32]` hashes and counts — never a secret, a provider body, or private
//! memory (`G-G-EVIDENCE-MANIFEST`). This module performs no live action.
//!
//! Reuse (no reinvention): the evidence-lake anchor is the Stage E
//! [`EvidenceLakeReceipt`] (`manifest_hash_32`); a command-trace entry is built
//! from the Stage F [`CommandTraceRecord`] (`redacted_output_hash_32`).

use crate::command::CommandTraceRecord;
use crate::{hex32, sha256_32};
use mnemos_l_dataset::export::shard::EvidenceLakeReceipt;

/// First 16 hex characters of a 32-byte digest — a redacted, display-only prefix.
#[must_use]
fn redact16(bytes: &[u8; 32]) -> String {
    hex32(bytes).chars().take(16).collect()
}

/// The kind of evidence grouped into a pack. Every kind is a local projection.
#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EvidenceKind {
    /// A bounded frontier-provider consult record.
    ProviderConsult = 1,
    /// A local audit candidate (never a finding on its own).
    AuditCandidate = 2,
    /// A memory replay outcome.
    MemoryReplay = 3,
    /// A Telegram notification event.
    TelegramEvent = 4,
    /// A command trace record.
    CommandTrace = 5,
    /// A gate result.
    GateResult = 6,
    /// A local repro runner receipt.
    LocalReproReceipt = 7,
}

impl EvidenceKind {
    /// Stable `u8` discriminant.
    #[must_use]
    pub const fn as_u8(self) -> u8 {
        self as u8
    }
}

/// Why building an evidence pack was refused (fail-closed).
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum PackReject {
    /// An entry carried a zero (missing) artifact hash.
    #[error("missing artifact hash")]
    MissingHash,
    /// The same evidence kind was added twice.
    #[error("duplicate evidence kind")]
    DuplicateKind,
}

/// One grouped evidence entry: a kind plus its `[u8; 32]` artifact hash.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EvidencePackEntry {
    /// The evidence kind.
    pub kind: EvidenceKind,
    /// SHA-256 of the evidence artifact (never the raw artifact / secret).
    pub evidence_hash_32: [u8; 32],
}

impl EvidencePackEntry {
    /// A pack entry from a kind and its artifact hash.
    #[must_use]
    pub const fn new(kind: EvidenceKind, evidence_hash_32: [u8; 32]) -> Self {
        Self {
            kind,
            evidence_hash_32,
        }
    }

    /// A [`EvidenceKind::CommandTrace`] entry from a Stage F [`CommandTraceRecord`]
    /// (uses the already-redacted output hash; the raw output is never carried).
    #[must_use]
    pub const fn from_command_trace(record: &CommandTraceRecord) -> Self {
        Self {
            kind: EvidenceKind::CommandTrace,
            evidence_hash_32: record.redacted_output_hash_32,
        }
    }
}

/// Compute the stable, order-independent pack hash over the task / session /
/// evidence-lake anchor and the (kind, hash) entries (entries are sorted by kind
/// so insertion order never changes the hash).
fn compute_pack_hash(
    task_id_hash_32: &[u8; 32],
    session_id_hash_32: &[u8; 32],
    evidence_lake_root_32: &[u8; 32],
    entries: &[EvidencePackEntry],
) -> [u8; 32] {
    let mut sorted: Vec<EvidencePackEntry> = entries.to_vec();
    sorted.sort_by_key(|e| e.kind.as_u8());
    let mut buf: Vec<u8> = Vec::with_capacity(24 + 32 * 3 + 4 + sorted.len() * 33);
    buf.extend_from_slice(b"sinabro.evidence.pack.v1");
    buf.extend_from_slice(task_id_hash_32);
    buf.extend_from_slice(session_id_hash_32);
    buf.extend_from_slice(evidence_lake_root_32);
    buf.extend_from_slice(
        &u32::try_from(sorted.len())
            .unwrap_or(u32::MAX)
            .to_le_bytes(),
    );
    for e in &sorted {
        buf.push(e.kind.as_u8());
        buf.extend_from_slice(&e.evidence_hash_32);
    }
    sha256_32(&buf)
}

/// A builder that groups evidence entries under a task / session and an optional
/// evidence-lake anchor, refusing missing hashes and duplicate kinds before
/// sealing a stable [`EvidencePackManifest`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EvidencePackBuilder {
    task_id_hash_32: [u8; 32],
    session_id_hash_32: [u8; 32],
    evidence_lake_root_32: [u8; 32],
    entries: Vec<EvidencePackEntry>,
}

impl EvidencePackBuilder {
    /// A new builder for the given task / session ids (the evidence-lake anchor is
    /// unset until [`EvidencePackBuilder::anchor_evidence_lake`]).
    #[must_use]
    pub const fn new(task_id_hash_32: [u8; 32], session_id_hash_32: [u8; 32]) -> Self {
        Self {
            task_id_hash_32,
            session_id_hash_32,
            evidence_lake_root_32: [0u8; 32],
            entries: Vec::new(),
        }
    }

    /// Anchor the pack to a Stage E [`EvidenceLakeReceipt`] (records the receipt's
    /// `manifest_hash_32` as the local-CAS-anchored evidence-lake root).
    #[must_use]
    pub fn anchor_evidence_lake(mut self, receipt: &EvidenceLakeReceipt) -> Self {
        self.evidence_lake_root_32 = receipt.manifest_hash_32;
        self
    }

    /// Add an evidence entry. Refuses a zero (missing) hash and a duplicate kind.
    pub fn add(&mut self, entry: EvidencePackEntry) -> Result<(), PackReject> {
        if entry.evidence_hash_32 == [0u8; 32] {
            return Err(PackReject::MissingHash);
        }
        if self.entries.iter().any(|e| e.kind == entry.kind) {
            return Err(PackReject::DuplicateKind);
        }
        self.entries.push(entry);
        Ok(())
    }

    /// The grouped entries so far.
    #[must_use]
    pub fn entries(&self) -> &[EvidencePackEntry] {
        &self.entries
    }

    /// Seal the manifest, computing the stable pack hash last.
    #[must_use]
    pub fn build(&self) -> EvidencePackManifest {
        EvidencePackManifest {
            task_id_hash_32: self.task_id_hash_32,
            session_id_hash_32: self.session_id_hash_32,
            evidence_lake_root_32: self.evidence_lake_root_32,
            entry_count_u32: u32::try_from(self.entries.len()).unwrap_or(u32::MAX),
            pack_hash_32: compute_pack_hash(
                &self.task_id_hash_32,
                &self.session_id_hash_32,
                &self.evidence_lake_root_32,
                &self.entries,
            ),
        }
    }
}

/// A sealed evidence pack manifest: task / session ids, the evidence-lake anchor,
/// the entry count, and the stable pack hash. Hashes + counts only — never a
/// secret.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EvidencePackManifest {
    /// SHA-256 of the task id the pack groups.
    pub task_id_hash_32: [u8; 32],
    /// SHA-256 of the session id the pack groups.
    pub session_id_hash_32: [u8; 32],
    /// SHA-256 evidence-lake root (zero = no lake anchor).
    pub evidence_lake_root_32: [u8; 32],
    /// Number of grouped entries.
    pub entry_count_u32: u32,
    /// Stable, order-independent pack hash.
    pub pack_hash_32: [u8; 32],
}

impl EvidencePackManifest {
    /// The pack hash (the replay / verification anchor).
    #[must_use]
    pub const fn pack_hash_32(&self) -> [u8; 32] {
        self.pack_hash_32
    }

    /// The redacted (16-hex) pack-hash prefix for display.
    #[must_use]
    pub fn redacted_pack_hash(&self) -> String {
        redact16(&self.pack_hash_32)
    }

    /// Whether the manifest links the given task / session ids.
    #[must_use]
    pub fn links(&self, task_id_hash_32: &[u8; 32], session_id_hash_32: &[u8; 32]) -> bool {
        &self.task_id_hash_32 == task_id_hash_32 && &self.session_id_hash_32 == session_id_hash_32
    }

    /// Recompute the pack hash from a candidate entry set under this manifest's
    /// task / session / lake anchor (used by replay to prove determinism).
    #[must_use]
    pub fn recompute_pack_hash(&self, entries: &[EvidencePackEntry]) -> [u8; 32] {
        compute_pack_hash(
            &self.task_id_hash_32,
            &self.session_id_hash_32,
            &self.evidence_lake_root_32,
            entries,
        )
    }

    /// Structural invariant: the manifest carries no secret / provider body /
    /// private memory — every field is a `[u8; 32]` hash or a count. Always `true`.
    #[must_use]
    pub const fn holds_no_secret(&self) -> bool {
        true
    }

    /// Redacted, colorless manifest lines bounded by `rows`.
    #[must_use]
    pub fn render(&self, rows: u16) -> Vec<String> {
        let lines = vec![
            format!("task={}", redact16(&self.task_id_hash_32)),
            format!("session={}", redact16(&self.session_id_hash_32)),
            format!(
                "evidence_lake_root={}",
                redact16(&self.evidence_lake_root_32)
            ),
            format!("entries={}", self.entry_count_u32),
            format!("pack_hash={}", self.redacted_pack_hash()),
        ];
        lines.into_iter().take(rows as usize).collect()
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    #![allow(clippy::expect_used)]
    use super::*;

    const COMMERCE_TOKENS: &[&str] = &[
        "price", "pay", "buy", "sell", "checkout", "refund", "fee", "cost", "$",
    ];

    fn entry(kind: EvidenceKind, b: u8) -> EvidencePackEntry {
        EvidencePackEntry::new(kind, [b; 32])
    }

    fn builder() -> EvidencePackBuilder {
        EvidencePackBuilder::new(sha256_32(b"task-7"), sha256_32(b"session-3"))
    }

    #[test]
    fn pack_create() {
        let mut b = builder();
        b.add(entry(EvidenceKind::ProviderConsult, 0x11)).unwrap();
        b.add(entry(EvidenceKind::AuditCandidate, 0x22)).unwrap();
        b.add(entry(EvidenceKind::GateResult, 0x33)).unwrap();
        let m = b.build();
        assert_eq!(m.entry_count_u32, 3);
        assert_ne!(m.pack_hash_32, [0u8; 32]);
    }

    #[test]
    fn missing_hash_reject() {
        let mut b = builder();
        assert_eq!(
            b.add(EvidencePackEntry::new(
                EvidenceKind::ProviderConsult,
                [0u8; 32]
            )),
            Err(PackReject::MissingHash)
        );
    }

    #[test]
    fn duplicate_reject() {
        let mut b = builder();
        b.add(entry(EvidenceKind::MemoryReplay, 0x44)).unwrap();
        assert_eq!(
            b.add(entry(EvidenceKind::MemoryReplay, 0x55)),
            Err(PackReject::DuplicateKind)
        );
    }

    #[test]
    fn redaction_proof_holds_no_secret() {
        let mut b = builder();
        b.add(entry(EvidenceKind::CommandTrace, 0x66)).unwrap();
        let m = b.build();
        assert_eq!(m.redacted_pack_hash().len(), 16);
        assert!(m.holds_no_secret());
        let full = hex32(&m.pack_hash_32);
        for line in m.render(8) {
            assert!(!line.contains(&full), "full hash leaked into {line}");
            for bad in COMMERCE_TOKENS {
                assert!(!line.contains(bad), "commerce token {bad} in {line}");
            }
        }
    }

    #[test]
    fn task_session_link() {
        let m = builder().build();
        assert!(m.links(&sha256_32(b"task-7"), &sha256_32(b"session-3")));
        assert!(!m.links(&sha256_32(b"task-9"), &sha256_32(b"session-3")));
    }

    #[test]
    fn pack_hash_is_order_independent() {
        let mut a = builder();
        a.add(entry(EvidenceKind::ProviderConsult, 0x11)).unwrap();
        a.add(entry(EvidenceKind::LocalReproReceipt, 0x22)).unwrap();
        let mut b = builder();
        b.add(entry(EvidenceKind::LocalReproReceipt, 0x22)).unwrap();
        b.add(entry(EvidenceKind::ProviderConsult, 0x11)).unwrap();
        assert_eq!(a.build().pack_hash_32, b.build().pack_hash_32);
    }

    #[test]
    fn command_trace_entry_uses_redacted_output_hash() {
        use crate::command::{CliMode, CommandEnvelope, CommandRisk};
        use crate::grammar::CliNamespace;
        use crate::{StageFEvidenceRef, StageFTraceLink};
        let env = CommandEnvelope::classify(
            CliNamespace::Trace,
            "list",
            CliMode::Run,
            CommandRisk::ReadOnly,
            b"",
        );
        let rec = CommandTraceRecord {
            envelope: env,
            exit_code_i32: 0,
            evidence: StageFEvidenceRef {
                path_hash_32: [0x77; 32],
                trace: StageFTraceLink::new([0x88; 32], 531, 1),
            },
            redacted_output_hash_32: [0x99; 32],
        };
        let e = EvidencePackEntry::from_command_trace(&rec);
        assert_eq!(e.kind, EvidenceKind::CommandTrace);
        assert_eq!(e.evidence_hash_32, [0x99; 32]);
    }

    #[test]
    fn pack_anchors_evidence_lake_receipt() {
        use mnemos_l_dataset::diet_kind::DietSourceStage;
        use mnemos_l_dataset::export::shard::EvidenceLakeReceipt;
        use mnemos_l_dataset::{AtomDietKey, StageETraceLink};
        let receipt = EvidenceLakeReceipt::new(
            AtomDietKey::new(DietSourceStage::StageD, 531),
            [0x11; 32],
            [0x22; 32],
            [0u8; 32],
            [0x33; 32],
            false,
            StageETraceLink::new([0x44; 32], 531, 1),
        )
        .expect("valid receipt");
        let mut b = builder().anchor_evidence_lake(&receipt);
        b.add(entry(EvidenceKind::ProviderConsult, 0x11)).unwrap();
        let m = b.build();
        // the evidence-lake root is the receipt's manifest hash (canonical IN reuse)
        assert_eq!(m.evidence_lake_root_32, [0x11; 32]);
        assert_ne!(m.pack_hash_32, [0u8; 32]);
    }
}
