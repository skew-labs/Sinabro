//! Evidence replay dry-run command (atom #532 · G.4.1).
//!
//! `sinabro evidence replay` explains what happened in a pack *offline*: it
//! re-derives the pack hash from the recorded entries and proves it is stable,
//! without re-running any live provider / tool / wallet / gas side effect. A
//! missing (zero) artifact hash is red ([`ReplayReject::MissingArtifact`]); a
//! drifted entry set is a replay mismatch; a live side effect is structurally
//! denied ([`ReplayReject::LiveSideEffectDenied`]) (`G-G-EVIDENCE-MANIFEST`). This
//! module performs no live action and carries no secret.
//!
//! Reuse (no reinvention): the determinism check is the Stage F
//! [`EvidenceReplayView::replay`] (re-run hash must equal recorded hash); the pack
//! is the [`super::pack_manifest::EvidencePackManifest`].

use super::pack_manifest::{EvidencePackEntry, EvidencePackManifest};
use crate::commands::evidence::EvidenceReplayView;
use crate::hex32;

/// First 16 hex characters of a 32-byte digest — a redacted, display-only prefix.
#[must_use]
fn redact16(bytes: &[u8; 32]) -> String {
    hex32(bytes).chars().take(16).collect()
}

/// Why an evidence replay was refused (fail-closed).
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum ReplayReject {
    /// An entry carried a zero (missing) artifact hash — the pack is incomplete.
    #[error("missing artifact hash")]
    MissingArtifact,
    /// The re-derived pack hash did not match the recorded one (entry drift).
    #[error("replay mismatch")]
    ReplayMismatch,
    /// A live side effect was attempted during replay — always denied.
    #[error("live side effect denied")]
    LiveSideEffectDenied,
}

/// A deterministic, offline replay of an evidence pack.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EvidenceReplayDryRun {
    /// The pack hash that was replayed.
    pub pack_hash_32: [u8; 32],
    /// Number of entries replayed.
    pub replayed_entry_count_u32: u32,
    /// Whether the re-derived trace hash equals the recorded one (determinism).
    pub trace_hash_stable: bool,
    /// Invariant `false`: replay never runs a live provider / tool / wallet / gas
    /// side effect.
    pub live_side_effect: bool,
}

impl EvidenceReplayDryRun {
    /// Replay a pack offline from its recorded entries. Refuses a missing artifact
    /// hash and a drifted entry set; never runs a live side effect.
    pub fn replay(
        manifest: &EvidencePackManifest,
        recorded_entries: &[EvidencePackEntry],
    ) -> Result<Self, ReplayReject> {
        for e in recorded_entries {
            if e.evidence_hash_32 == [0u8; 32] {
                return Err(ReplayReject::MissingArtifact);
            }
        }
        let rerun = manifest.recompute_pack_hash(recorded_entries);
        // Reuse the Stage F determinism check: the re-run hash must equal the
        // recorded pack hash, else a replay mismatch.
        EvidenceReplayView::replay(manifest.pack_hash_32(), rerun)
            .map_err(|_| ReplayReject::ReplayMismatch)?;
        Ok(Self {
            pack_hash_32: manifest.pack_hash_32(),
            replayed_entry_count_u32: u32::try_from(recorded_entries.len()).unwrap_or(u32::MAX),
            trace_hash_stable: true,
            live_side_effect: false,
        })
    }

    /// Attempt a live side effect during replay — always refused (replay is a
    /// pure offline explanation).
    pub const fn try_live_side_effect(&self) -> Result<(), ReplayReject> {
        Err(ReplayReject::LiveSideEffectDenied)
    }

    /// The redacted (16-hex) replayed-pack prefix for a terminal view.
    #[must_use]
    pub fn terminal_redacted(&self) -> String {
        redact16(&self.pack_hash_32)
    }

    /// Structural invariant: the replay view holds no secret — every field is a
    /// `[u8; 32]` hash, a count, or a bool. Always `true`.
    #[must_use]
    pub const fn holds_no_secret(&self) -> bool {
        true
    }

    /// Redacted, colorless replay lines bounded by `rows`.
    #[must_use]
    pub fn render(&self, rows: u16) -> Vec<String> {
        let lines = vec![
            format!("pack_hash={}", self.terminal_redacted()),
            format!("replayed_entries={}", self.replayed_entry_count_u32),
            format!("trace_hash_stable={}", self.trace_hash_stable),
            format!("live_side_effect={}", self.live_side_effect),
        ];
        lines.into_iter().take(rows as usize).collect()
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;
    use crate::evidence::pack_manifest::{EvidenceKind, EvidencePackBuilder};
    use crate::sha256_32;

    fn pack() -> (EvidencePackManifest, Vec<EvidencePackEntry>) {
        let mut b = EvidencePackBuilder::new(sha256_32(b"task"), sha256_32(b"session"));
        b.add(EvidencePackEntry::new(
            EvidenceKind::ProviderConsult,
            [0x11; 32],
        ))
        .unwrap();
        b.add(EvidencePackEntry::new(EvidenceKind::GateResult, [0x22; 32]))
            .unwrap();
        let entries = b.entries().to_vec();
        (b.build(), entries)
    }

    #[test]
    fn replay_pack() {
        let (m, entries) = pack();
        let r = EvidenceReplayDryRun::replay(&m, &entries).unwrap();
        assert!(r.trace_hash_stable);
        assert_eq!(r.replayed_entry_count_u32, 2);
        assert!(!r.live_side_effect);
    }

    #[test]
    fn missing_artifact() {
        let (m, mut entries) = pack();
        entries.push(EvidencePackEntry::new(
            EvidenceKind::MemoryReplay,
            [0u8; 32],
        ));
        assert_eq!(
            EvidenceReplayDryRun::replay(&m, &entries),
            Err(ReplayReject::MissingArtifact)
        );
    }

    #[test]
    fn live_side_effect_denied() {
        let (m, entries) = pack();
        let r = EvidenceReplayDryRun::replay(&m, &entries).unwrap();
        assert_eq!(
            r.try_live_side_effect(),
            Err(ReplayReject::LiveSideEffectDenied)
        );
    }

    #[test]
    fn redacted_terminal() {
        let (m, entries) = pack();
        let r = EvidenceReplayDryRun::replay(&m, &entries).unwrap();
        assert_eq!(r.terminal_redacted().len(), 16);
        assert!(r.holds_no_secret());
    }

    #[test]
    fn trace_hash_mismatch_on_drift() {
        let (m, _entries) = pack();
        // a drifted entry set re-derives a different pack hash -> replay mismatch
        let drifted = vec![EvidencePackEntry::new(
            EvidenceKind::ProviderConsult,
            [0x99; 32],
        )];
        assert_eq!(
            EvidenceReplayDryRun::replay(&m, &drifted),
            Err(ReplayReject::ReplayMismatch)
        );
    }
}
