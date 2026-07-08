//! `sinabro evidence pack / verify / replay / archive --dry-run` — evidence
//! controls.
//!
//! Evidence packing / verification / replay is local and deterministic;
//! archiving is dry-run / background only and can never imply training
//! consent.
//!
//! Reuse: a packed evidence record is the canonical
//! [`mnemos_l_dataset::export::shard::EvidenceLakeReceipt`] (local-CAS-anchored;
//! `training_eligibility` is carried but never executed here); a local evidence
//! bundle is the canonical [`mnemos_b_memory::EvidenceBundleManifestV1`]
//! (local-only hook). This module projects those — it mints no new evidence type
//! and performs no live action.

use crate::hex32;
use crate::tui::RenderTruth;
use mnemos_b_memory::EvidenceBundleManifestV1;
use mnemos_l_dataset::export::shard::EvidenceLakeReceipt;

/// First 16 hex characters of a 32-byte hash — a redacted, display-only prefix.
#[must_use]
fn redact16(bytes: &[u8; 32]) -> String {
    hex32(bytes).chars().take(16).collect()
}

/// Why an evidence command was refused (fail-closed).
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum EvidenceReject {
    /// A replay produced a different transcript than the recorded one.
    #[error("replay mismatch")]
    ReplayMismatch,
    /// A live archive upload is denied (dry-run only).
    #[error("live archive denied")]
    LiveArchiveDenied,
}

/// A `sinabro evidence pack` projection over a canonical [`EvidenceLakeReceipt`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EvidencePackView {
    /// Redacted manifest hash.
    pub manifest_redacted: String,
    /// Redacted local content-addressed store root.
    pub local_cas_root_redacted: String,
    /// Whether a remote archive locator is present.
    pub has_remote_locator: bool,
    /// Training eligibility carried by the receipt (display only; training is
    /// never executed here).
    pub training_eligibility: bool,
}

impl EvidencePackView {
    /// Project a pack view from a canonical receipt.
    #[must_use]
    pub fn from_receipt(r: &EvidenceLakeReceipt) -> Self {
        Self {
            manifest_redacted: redact16(&r.manifest_hash_32),
            local_cas_root_redacted: redact16(&r.local_cas_root_32),
            has_remote_locator: r.has_remote_locator(),
            training_eligibility: r.training_eligibility,
        }
    }

    /// Verify a packed receipt against an expected manifest hash. A match with a
    /// non-zero local CAS root is `Green`; a mismatch or a missing CAS root is
    /// `Red`.
    #[must_use]
    pub fn verify(r: &EvidenceLakeReceipt, expected_manifest_hash_32: &[u8; 32]) -> RenderTruth {
        let matches = &r.manifest_hash_32 == expected_manifest_hash_32;
        let anchored = r.local_cas_root_32 != [0u8; 32];
        if matches && anchored {
            RenderTruth::Green
        } else {
            RenderTruth::Red
        }
    }

    /// Colorless status lines bounded by `rows`.
    #[must_use]
    pub fn render(&self, rows: u16) -> Vec<String> {
        let lines = vec![
            format!("manifest={}", self.manifest_redacted),
            format!("local_cas_root={}", self.local_cas_root_redacted),
            format!("has_remote_locator={}", self.has_remote_locator),
            format!("training_eligibility={}", self.training_eligibility),
        ];
        lines.into_iter().take(rows as usize).collect()
    }
}

/// A `sinabro evidence replay` projection: replay is local + deterministic.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EvidenceReplayView {
    transcript_hash_32: [u8; 32],
    /// Whether the replay was deterministic (re-run hash equals recorded hash).
    pub deterministic: bool,
}

impl EvidenceReplayView {
    /// Replay a recorded transcript and check determinism: the re-run hash must
    /// equal the recorded one, else [`EvidenceReject::ReplayMismatch`].
    pub fn replay(
        recorded_hash_32: [u8; 32],
        rerun_hash_32: [u8; 32],
    ) -> Result<Self, EvidenceReject> {
        if recorded_hash_32 == rerun_hash_32 {
            Ok(Self {
                transcript_hash_32: recorded_hash_32,
                deterministic: true,
            })
        } else {
            Err(EvidenceReject::ReplayMismatch)
        }
    }

    /// The redacted replayed-transcript prefix.
    #[must_use]
    pub fn transcript_redacted(&self) -> String {
        redact16(&self.transcript_hash_32)
    }
}

/// A `sinabro evidence archive --dry-run` plan: archiving never uploads and
/// never implies training consent. The default is the safe dry-run
/// plan.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub struct EvidenceArchivePlan {
    /// Whether a live upload would occur — always `false`.
    pub live_upload: bool,
    /// Whether the archive implies training consent — always `false`.
    pub implies_training_consent: bool,
}

impl EvidenceArchivePlan {
    /// A dry-run archive plan (no live upload, no training consent).
    #[must_use]
    pub fn dry_run() -> Self {
        Self::default()
    }

    /// Attempt a live archive — always refused.
    pub const fn try_live_archive(&self) -> Result<(), EvidenceReject> {
        Err(EvidenceReject::LiveArchiveDenied)
    }
}

/// A `sinabro evidence bundle` projection over a canonical
/// [`EvidenceBundleManifestV1`] (local-only hook).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EvidenceBundleStatusView {
    /// Source atom id the bundle belongs to.
    pub atom_id_u16: u16,
    /// Training eligibility carried by the bundle (the local hook hard-codes
    /// `false`).
    pub training_eligibility: bool,
    /// Whether a remote storage locator is present.
    pub remote_locator_present: bool,
}

impl EvidenceBundleStatusView {
    /// Project a bundle status from a canonical local bundle manifest.
    #[must_use]
    pub fn from_manifest(m: &EvidenceBundleManifestV1) -> Self {
        Self {
            atom_id_u16: m.atom_id_u16,
            training_eligibility: m.training_eligibility,
            remote_locator_present: m.remote_locator_present(),
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    #![allow(clippy::expect_used)]
    #![allow(clippy::panic)]

    use super::*;
    use mnemos_a_core::StageBTraceLink;
    use mnemos_b_memory::{EvidenceRedactionClass, EvidenceRightsClass};
    use mnemos_l_dataset::diet_kind::DietSourceStage;
    use mnemos_l_dataset::{AtomDietKey, StageETraceLink};

    const COMMERCE_TOKENS: &[&str] = &[
        "price", "pay", "buy", "sell", "checkout", "refund", "fee", "cost", "$",
    ];

    /// Build a canonical evidence receipt. `archive_locator` is left zero so no
    /// remote locator is implied (avoids the canonical `RemoteLocatorBypass`).
    fn receipt(training: bool) -> EvidenceLakeReceipt {
        EvidenceLakeReceipt::new(
            AtomDietKey::new(DietSourceStage::StageD, 251),
            [0x11; 32],
            [0x22; 32],
            [0u8; 32],
            [0x33; 32],
            training,
            StageETraceLink::new([0x44; 32], 251, 1),
        )
        .expect("valid receipt")
    }

    #[test]
    fn evidence_pack_projects_receipt() {
        let r = receipt(false);
        let v = EvidencePackView::from_receipt(&r);
        assert!(!v.has_remote_locator);
        assert!(!v.training_eligibility);
        assert_eq!(v.manifest_redacted.len(), 16);
        assert!(v.render(8).iter().any(|l| l.starts_with("manifest=")));
    }

    #[test]
    fn evidence_verify_green_on_match_red_on_mismatch() {
        let r = receipt(false);
        assert_eq!(
            EvidencePackView::verify(&r, &[0x11; 32]),
            RenderTruth::Green
        );
        assert_eq!(EvidencePackView::verify(&r, &[0x99; 32]), RenderTruth::Red);
    }

    #[test]
    fn evidence_replay_is_deterministic_or_mismatch() {
        let ok = EvidenceReplayView::replay([0x55; 32], [0x55; 32]).unwrap();
        assert!(ok.deterministic);
        assert_eq!(ok.transcript_redacted().len(), 16);
        assert_eq!(
            EvidenceReplayView::replay([0x55; 32], [0x66; 32]),
            Err(EvidenceReject::ReplayMismatch)
        );
    }

    #[test]
    fn archive_is_dry_run_and_live_denied() {
        let p = EvidenceArchivePlan::dry_run();
        assert!(!p.live_upload);
        assert!(!p.implies_training_consent);
        assert_eq!(p.try_live_archive(), Err(EvidenceReject::LiveArchiveDenied));
    }

    #[test]
    fn training_eligibility_displayed_not_executed() {
        // The flag is shown for transparency; training is never run here.
        let v = EvidencePackView::from_receipt(&receipt(true));
        assert!(v.training_eligibility);
    }

    #[test]
    fn evidence_bundle_local_hook_projection() {
        let m = EvidenceBundleManifestV1::new_local_hook(
            454,
            0,
            [0x10; 32],
            [0x20; 32],
            [0x30; 32],
            EvidenceRedactionClass::Redacted,
            EvidenceRightsClass::LocalUserOnly,
            0,
            StageBTraceLink::new(0xABCD, 454, 0),
        );
        let v = EvidenceBundleStatusView::from_manifest(&m);
        assert_eq!(v.atom_id_u16, 454);
        // The local hook hard-codes training_eligibility=false.
        assert!(!v.training_eligibility);
        assert!(!v.remote_locator_present);
    }

    #[test]
    fn render_bounded_no_commerce() {
        let v = EvidencePackView::from_receipt(&receipt(false));
        assert!(v.render(2).len() <= 2);
        for line in v.render(8) {
            for bad in COMMERCE_TOKENS {
                assert!(!line.contains(bad), "commerce token {bad} in {line}");
            }
        }
    }
}
