//! `sinabro dataset label / split / export` — dataset label/split/export
//! controls (F-WP-06B, atom #455 · F.6.4).
//!
//! S1/S2 split, PII-zero, leakage, the shard manifest and the dataset card are
//! all visible; export requires the quality gates and respects the learning mode.
//! `local_diet` writes local files only; `contribute_redacted` builds a review
//! packet that never uploads without approval. Audit records export only as
//! *neutral distilled* training records (problem → invariant → code context →
//! failure hypothesis → local repro/proof → fix/no-finding → gates → evidence
//! hash); raw provider output, exploit instructions, rights-less private data and
//! pattern-only guesses stay out of positive train splits.
//!
//! Reuse (no reinvention): the split is the Stage E
//! [`mnemos_l_dataset::split`] (`TrainingSplit` / `SplitAssignment` /
//! `verify_no_leakage`); quality is [`QualityReport`] +
//! [`mnemos_l_dataset::quality::verify_reward_provenance`]; manifest/card are
//! [`DatasetShardManifest`] / [`DatasetCard`]; S2 reward impossibility is
//! [`S2NarrativeRecord`]. This module performs no live action.

use crate::config::LearningMode;
use crate::hex32;
use crate::tui::RenderTruth;
use mnemos_l_dataset::export::card::DatasetCard;
use mnemos_l_dataset::export::shard::DatasetShardManifest;
use mnemos_l_dataset::quality::{self, QualityReport};
use mnemos_l_dataset::split::{self, SplitAssignment, TrainingSplit};
use mnemos_l_dataset::stream_split::S2NarrativeRecord;

/// First 16 hex characters of a 32-byte hash — a redacted, display-only prefix.
#[must_use]
fn redact16(bytes: &[u8; 32]) -> String {
    hex32(bytes).chars().take(16).collect()
}

/// Why a dataset-export command was refused (fail-closed).
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum DatasetExportReject {
    /// An S2 narrative record is never reward eligible.
    #[error("S2 narrative is never reward eligible")]
    S2RewardDenied,
    /// Privacy residue (PII / secret / encoded) is present.
    #[error("privacy residue present")]
    PrivacyResidue,
    /// A split would leak a leakage-group across two splits.
    #[error("split leakage conflict")]
    LeakageConflict,
    /// A contribution upload requires explicit approval that was not supplied.
    #[error("contribution upload requires explicit approval")]
    NoUploadWithoutApproval,
    /// Raw frontier model output cannot enter a train split.
    #[error("raw frontier output cannot enter a train split")]
    RawFrontierOutput,
    /// Exploit wording cannot enter a train split.
    #[error("exploit wording cannot enter a train split")]
    ExploitWording,
    /// Contribution rights are missing.
    #[error("contribution rights missing")]
    RightsMissing,
    /// A pattern-only audit guess cannot enter a positive train split.
    #[error("pattern-only audit guess cannot enter a positive train split")]
    PatternOnly,
}

/// A per-split count summary, produced only after the canonical leakage check
/// passes.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub struct SplitSummary {
    /// Count assigned to the train split.
    pub train_u32: u32,
    /// Count assigned to the validation split.
    pub validation_u32: u32,
    /// Count assigned to the test split.
    pub test_u32: u32,
    /// Count assigned to the held-out split.
    pub held_out_u32: u32,
    /// Count assigned to the quarantine split.
    pub quarantine_u32: u32,
}

impl SplitSummary {
    /// Summarise split assignments, failing closed if the canonical
    /// [`split::verify_no_leakage`] detects a straddling leakage group.
    pub fn from_assignments(assignments: &[SplitAssignment]) -> Result<Self, DatasetExportReject> {
        split::verify_no_leakage(assignments).map_err(|_| DatasetExportReject::LeakageConflict)?;
        let mut s = Self::default();
        for a in assignments {
            match a.split {
                TrainingSplit::Train => s.train_u32 = s.train_u32.saturating_add(1),
                TrainingSplit::Validation => s.validation_u32 = s.validation_u32.saturating_add(1),
                TrainingSplit::Test => s.test_u32 = s.test_u32.saturating_add(1),
                TrainingSplit::HeldOut => s.held_out_u32 = s.held_out_u32.saturating_add(1),
                TrainingSplit::Quarantine => s.quarantine_u32 = s.quarantine_u32.saturating_add(1),
            }
        }
        Ok(s)
    }

    /// Total assignments across all splits.
    #[must_use]
    pub fn total(&self) -> u32 {
        self.train_u32
            .saturating_add(self.validation_u32)
            .saturating_add(self.test_u32)
            .saturating_add(self.held_out_u32)
            .saturating_add(self.quarantine_u32)
    }
}

/// The reward eligibility an S2 narrative record carries — always blocked. Reuse
/// of the type-impossible [`S2NarrativeRecord`] reward.
#[must_use]
pub fn s2_reward_blocked(rec: &S2NarrativeRecord) -> bool {
    !rec.reward.is_eligible()
}

/// Whether reward provenance is sound (reuse of the canonical S1-gated
/// [`quality::verify_reward_provenance`]): a reward-eligible record must be
/// S1-reverified.
#[must_use]
pub fn reward_provenance_ok(reward_eligible: bool, s1_reverified: bool) -> bool {
    quality::verify_reward_provenance(reward_eligible, s1_reverified).is_ok()
}

/// A `sinabro dataset` quality-gate projection over a canonical [`QualityReport`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct QualityGateView {
    /// Records scanned.
    pub records_u64: u64,
    /// PII hit count.
    pub pii_hits_u32: u32,
    /// Secret hit count.
    pub secret_hits_u32: u32,
    /// Encoded-secret hit count.
    pub encoded_hits_u32: u32,
    /// Whether the report is clean (zero hits).
    pub clean: bool,
}

impl QualityGateView {
    /// Project a quality gate from a canonical report.
    #[must_use]
    pub fn from_report(r: &QualityReport) -> Self {
        Self {
            records_u64: r.records_u64,
            pii_hits_u32: r.pii_hits_u32,
            secret_hits_u32: r.secret_hits_u32,
            encoded_hits_u32: r.encoded_hits_u32,
            clean: r.clean(),
        }
    }

    /// Fail closed unless the report is PII/secret/encoded clean.
    pub fn assert_clean(r: &QualityReport) -> Result<(), DatasetExportReject> {
        if r.clean() {
            Ok(())
        } else {
            Err(DatasetExportReject::PrivacyResidue)
        }
    }

    /// Render truth: a clean report is `Green`, otherwise `Red`.
    #[must_use]
    pub fn render_truth(&self) -> RenderTruth {
        if self.clean {
            RenderTruth::Green
        } else {
            RenderTruth::Red
        }
    }
}

/// A `sinabro dataset` shard-manifest projection (redacted, display-only).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ShardManifestView {
    /// Redacted shard hash.
    pub shard_redacted: String,
    /// Redacted merkle root.
    pub merkle_redacted: String,
    /// Redacted signer id.
    pub signer_redacted: String,
    /// Export-kind discriminant.
    pub export_u8: u8,
    /// Sample count in the shard.
    pub sample_count_u64: u64,
    /// Whether the shard is PII-zero.
    pub pii_zero: bool,
}

impl ShardManifestView {
    /// Project a manifest view from a canonical [`DatasetShardManifest`].
    #[must_use]
    pub fn from_manifest(m: &DatasetShardManifest) -> Self {
        Self {
            shard_redacted: redact16(&m.shard_hash_32),
            merkle_redacted: redact16(&m.merkle_root_32),
            signer_redacted: redact16(&m.signer_hash_32),
            export_u8: m.export.as_u8(),
            sample_count_u64: m.sample_count_u64,
            pii_zero: m.pii_zero,
        }
    }

    /// Render truth: a PII-zero shard is `Green`, otherwise `Red`.
    #[must_use]
    pub fn render_truth(&self) -> RenderTruth {
        if self.pii_zero {
            RenderTruth::Green
        } else {
            RenderTruth::Red
        }
    }

    /// Redacted, colorless manifest lines bounded by `rows`.
    #[must_use]
    pub fn render(&self, rows: u16) -> Vec<String> {
        let lines = vec![
            format!("shard={}", self.shard_redacted),
            format!("merkle={}", self.merkle_redacted),
            format!("signer={}", self.signer_redacted),
            format!("export_u8={}", self.export_u8),
            format!("sample_count={}", self.sample_count_u64),
            format!("pii_zero={}", self.pii_zero),
            format!("truth_u8={}", self.render_truth() as u8),
        ];
        lines.into_iter().take(rows as usize).collect()
    }
}

/// A `sinabro dataset card` projection over a canonical [`DatasetCard`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DatasetCardView {
    /// The dataset version label.
    pub dataset_version: String,
    /// Total source samples across all source counts.
    pub total_samples_u64: u64,
    /// Whether the dataset is PII-zero.
    pub pii_zero: bool,
    /// Whether GRPO is locked.
    pub grpo_locked: bool,
    /// Whether split leakage is guarded.
    pub split_leakage_guarded: bool,
}

impl DatasetCardView {
    /// Project a card view from a canonical [`DatasetCard`].
    #[must_use]
    pub fn from_card(c: &DatasetCard) -> Self {
        Self {
            dataset_version: c.dataset_version.clone(),
            total_samples_u64: c.source_counts.total(),
            pii_zero: c.pii_zero,
            grpo_locked: c.grpo_locked,
            split_leakage_guarded: c.split_leakage_guarded,
        }
    }
}

/// Where an export may land, given the learning mode.
#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ExportTarget {
    /// Local files only (no upload).
    LocalFilesOnly = 1,
    /// A redacted review packet that never uploads without approval.
    ReviewPacketNoUpload = 2,
}

/// The export target for a learning mode. `Off` / `evidence_only` export nothing;
/// `local_diet` / `private_adapter` write local files only; `contribute_redacted`
/// builds a review packet that never uploads without approval.
#[must_use]
pub fn export_target(mode: LearningMode) -> Option<ExportTarget> {
    match mode {
        LearningMode::Off | LearningMode::EvidenceOnly => None,
        LearningMode::LocalDiet | LearningMode::PrivateAdapter => {
            Some(ExportTarget::LocalFilesOnly)
        }
        LearningMode::ContributeRedacted => Some(ExportTarget::ReviewPacketNoUpload),
    }
}

/// The outcome of a contribution-upload request. There is no variant that means
/// "uploaded" — Stage F performs no live upload.
#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ContributionDecision {
    /// Approval recorded; the redacted packet may be reviewed at a future
    /// (non-Stage-F) boundary. No bytes leave the machine in Stage F.
    ApprovedForFutureReview = 1,
}

/// Request a contribution upload. Without approval it is refused; with approval
/// only the gate is recorded (Stage F still uploads nothing).
pub fn request_contribution_upload(
    approved: bool,
) -> Result<ContributionDecision, DatasetExportReject> {
    if approved {
        Ok(ContributionDecision::ApprovedForFutureReview)
    } else {
        Err(DatasetExportReject::NoUploadWithoutApproval)
    }
}

/// A neutral distilled audit training record (problem → invariant → code context
/// → failure hypothesis → local repro/proof → fix/no-finding → gates → evidence).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NeutralAuditRecord {
    /// Problem statement hash.
    pub problem_hash_32: [u8; 32],
    /// Affected invariant hash.
    pub invariant_hash_32: [u8; 32],
    /// Code-context hash.
    pub code_context_hash_32: [u8; 32],
    /// Failure-hypothesis hash.
    pub failure_hypothesis_hash_32: [u8; 32],
    /// Local repro/proof hash.
    pub local_repro_hash_32: [u8; 32],
    /// Fix or no-finding hash.
    pub fix_or_nofinding_hash_32: [u8; 32],
    /// Gates hash.
    pub gates_hash_32: [u8; 32],
    /// Evidence hash.
    pub evidence_hash_32: [u8; 32],
}

/// A candidate audit record being considered for export, with the gating facts.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AuditDistillCandidate {
    /// Problem statement hash.
    pub problem_hash_32: [u8; 32],
    /// Affected invariant hash.
    pub invariant_hash_32: [u8; 32],
    /// Code-context hash.
    pub code_context_hash_32: [u8; 32],
    /// Failure-hypothesis hash.
    pub failure_hypothesis_hash_32: [u8; 32],
    /// Local repro/proof hash.
    pub local_repro_hash_32: [u8; 32],
    /// Fix or no-finding hash.
    pub fix_or_nofinding_hash_32: [u8; 32],
    /// Gates hash.
    pub gates_hash_32: [u8; 32],
    /// Evidence hash.
    pub evidence_hash_32: [u8; 32],
    /// Whether a local reproducer/proof backs the candidate.
    pub has_local_repro: bool,
    /// Whether contribution/usage rights are present.
    pub rights_ok: bool,
    /// Whether the candidate carries raw frontier model output.
    pub raw_frontier_output: bool,
    /// Whether the candidate carries exploit wording.
    pub exploit_wording: bool,
    /// Whether the candidate is a pattern-only guess.
    pub pattern_only: bool,
}

impl AuditDistillCandidate {
    /// Distil to a neutral training record, or fail closed. Raw frontier output,
    /// exploit wording, missing rights, and pattern-only / unreproduced guesses
    /// all stay out of positive train splits.
    pub fn into_neutral(&self) -> Result<NeutralAuditRecord, DatasetExportReject> {
        if self.raw_frontier_output {
            return Err(DatasetExportReject::RawFrontierOutput);
        }
        if self.exploit_wording {
            return Err(DatasetExportReject::ExploitWording);
        }
        if !self.rights_ok {
            return Err(DatasetExportReject::RightsMissing);
        }
        if self.pattern_only || !self.has_local_repro {
            return Err(DatasetExportReject::PatternOnly);
        }
        Ok(NeutralAuditRecord {
            problem_hash_32: self.problem_hash_32,
            invariant_hash_32: self.invariant_hash_32,
            code_context_hash_32: self.code_context_hash_32,
            failure_hypothesis_hash_32: self.failure_hypothesis_hash_32,
            local_repro_hash_32: self.local_repro_hash_32,
            fix_or_nofinding_hash_32: self.fix_or_nofinding_hash_32,
            gates_hash_32: self.gates_hash_32,
            evidence_hash_32: self.evidence_hash_32,
        })
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    #![allow(clippy::expect_used)]
    #![allow(clippy::panic)]

    use super::*;
    use mnemos_l_dataset::AtomDietKey;
    use mnemos_l_dataset::diet_kind::DietSourceStage;
    use mnemos_l_dataset::export::ExportKind;
    use mnemos_l_dataset::privacy::PrivacyDecision;

    const COMMERCE_TOKENS: &[&str] = &[
        "price", "pay", "buy", "sell", "checkout", "refund", "fee", "cost", "$",
    ];

    fn key(atom: u16) -> AtomDietKey {
        AtomDietKey::new(DietSourceStage::StageD, atom)
    }

    fn assignment(atom: u16, split: TrainingSplit, group: u8) -> SplitAssignment {
        SplitAssignment {
            key: key(atom),
            split,
            leakage_group_hash_32: [group; 32],
        }
    }

    fn report(pii: u32, secret: u32) -> QualityReport {
        let decision = if pii == 0 && secret == 0 {
            PrivacyDecision::Pass
        } else {
            PrivacyDecision::Reject
        };
        QualityReport {
            records_u64: 10,
            pii_hits_u32: pii,
            secret_hits_u32: secret,
            encoded_hits_u32: 0,
            duplicate_u32: 0,
            malformed_u32: 0,
            oversize_u32: 0,
            decision,
        }
    }

    #[test]
    fn s2_reward_is_always_denied() {
        let rec = S2NarrativeRecord::new(key(252), [0x01; 32]);
        assert!(s2_reward_blocked(&rec));
        // reward provenance: an "eligible" claim without S1 reverify is rejected.
        assert!(!reward_provenance_ok(true, false));
        assert!(reward_provenance_ok(false, false));
    }

    #[test]
    fn pii_fail_blocks_export() {
        let dirty = report(3, 0);
        assert_eq!(
            QualityGateView::assert_clean(&dirty),
            Err(DatasetExportReject::PrivacyResidue)
        );
        let v = QualityGateView::from_report(&dirty);
        assert!(!v.clean);
        assert_eq!(v.render_truth(), RenderTruth::Red);
        let clean = report(0, 0);
        assert!(QualityGateView::assert_clean(&clean).is_ok());
        assert_eq!(
            QualityGateView::from_report(&clean).render_truth(),
            RenderTruth::Green
        );
    }

    #[test]
    fn leakage_conflict_rejected_clean_split_ok() {
        // Same leakage group straddling two splits is a leak.
        let leaky = vec![
            assignment(1, TrainingSplit::Train, 7),
            assignment(2, TrainingSplit::Test, 7),
        ];
        assert_eq!(
            SplitSummary::from_assignments(&leaky),
            Err(DatasetExportReject::LeakageConflict)
        );
        // Distinct leakage groups are fine.
        let ok = vec![
            assignment(1, TrainingSplit::Train, 1),
            assignment(2, TrainingSplit::Test, 2),
            assignment(3, TrainingSplit::HeldOut, 3),
        ];
        let s = SplitSummary::from_assignments(&ok).unwrap();
        assert_eq!(s.total(), 3);
        assert_eq!(s.train_u32, 1);
        assert_eq!(s.test_u32, 1);
        assert_eq!(s.held_out_u32, 1);
    }

    #[test]
    fn manifest_display_redacted() {
        let m = DatasetShardManifest {
            shard_hash_32: [0xAB; 32],
            merkle_root_32: [0xCD; 32],
            signer_hash_32: [0xEF; 32],
            export: ExportKind::SftChat,
            sample_count_u64: 42,
            pii_zero: true,
            evidence_manifest_hash_32: [0x11; 32],
        };
        let v = ShardManifestView::from_manifest(&m);
        assert_eq!(v.shard_redacted.len(), 16);
        assert_eq!(v.sample_count_u64, 42);
        assert_eq!(v.export_u8, ExportKind::SftChat.as_u8());
        assert_eq!(v.render_truth(), RenderTruth::Green);
        assert!(v.render(8).iter().any(|l| l == "sample_count=42"));
    }

    #[test]
    fn local_export_and_contribution_review_packet() {
        assert_eq!(export_target(LearningMode::Off), None);
        assert_eq!(export_target(LearningMode::EvidenceOnly), None);
        assert_eq!(
            export_target(LearningMode::LocalDiet),
            Some(ExportTarget::LocalFilesOnly)
        );
        assert_eq!(
            export_target(LearningMode::PrivateAdapter),
            Some(ExportTarget::LocalFilesOnly)
        );
        assert_eq!(
            export_target(LearningMode::ContributeRedacted),
            Some(ExportTarget::ReviewPacketNoUpload)
        );
    }

    #[test]
    fn no_upload_without_approval() {
        assert_eq!(
            request_contribution_upload(false),
            Err(DatasetExportReject::NoUploadWithoutApproval)
        );
        assert_eq!(
            request_contribution_upload(true),
            Ok(ContributionDecision::ApprovedForFutureReview)
        );
    }

    #[test]
    fn audit_distillation_neutral_and_deny_paths() {
        let base = AuditDistillCandidate {
            problem_hash_32: [1; 32],
            invariant_hash_32: [2; 32],
            code_context_hash_32: [3; 32],
            failure_hypothesis_hash_32: [4; 32],
            local_repro_hash_32: [5; 32],
            fix_or_nofinding_hash_32: [6; 32],
            gates_hash_32: [7; 32],
            evidence_hash_32: [8; 32],
            has_local_repro: true,
            rights_ok: true,
            raw_frontier_output: false,
            exploit_wording: false,
            pattern_only: false,
        };
        // A clean, reproduced, rights-clear candidate distils to a neutral record.
        let neutral = base.into_neutral().unwrap();
        assert_eq!(neutral.invariant_hash_32, [2; 32]);
        // Deny paths.
        assert_eq!(
            AuditDistillCandidate {
                raw_frontier_output: true,
                ..base
            }
            .into_neutral(),
            Err(DatasetExportReject::RawFrontierOutput)
        );
        assert_eq!(
            AuditDistillCandidate {
                exploit_wording: true,
                ..base
            }
            .into_neutral(),
            Err(DatasetExportReject::ExploitWording)
        );
        assert_eq!(
            AuditDistillCandidate {
                rights_ok: false,
                ..base
            }
            .into_neutral(),
            Err(DatasetExportReject::RightsMissing)
        );
        assert_eq!(
            AuditDistillCandidate {
                pattern_only: true,
                ..base
            }
            .into_neutral(),
            Err(DatasetExportReject::PatternOnly)
        );
        assert_eq!(
            AuditDistillCandidate {
                has_local_repro: false,
                ..base
            }
            .into_neutral(),
            Err(DatasetExportReject::PatternOnly)
        );
    }

    #[test]
    fn dataset_card_view_projects_card() {
        let card = mnemos_l_dataset::export::card::stage_e_v0();
        let v = DatasetCardView::from_card(&card);
        assert_eq!(v.dataset_version, card.dataset_version);
        assert_eq!(v.grpo_locked, card.grpo_locked);
        assert_eq!(v.pii_zero, card.pii_zero);
    }

    #[test]
    fn render_bounded_no_commerce_and_p95_within_100ms() {
        let m = DatasetShardManifest {
            shard_hash_32: [0xAB; 32],
            merkle_root_32: [0xCD; 32],
            signer_hash_32: [0xEF; 32],
            export: ExportKind::Eval,
            sample_count_u64: 7,
            pii_zero: true,
            evidence_manifest_hash_32: [0x11; 32],
        };
        let v = ShardManifestView::from_manifest(&m);
        assert!(v.render(3).len() <= 3);
        assert!(v.render(64).len() <= 7);
        for line in v.render(64) {
            for bad in COMMERCE_TOKENS {
                assert!(!line.contains(bad), "commerce token {bad} in {line}");
            }
        }
        let mut samples = Vec::with_capacity(256);
        for _ in 0..256 {
            let t = std::time::Instant::now();
            let lines = v.render(32);
            std::hint::black_box(&lines);
            samples.push(t.elapsed().as_nanos() as u64);
        }
        let p95 = crate::repl::latency::p95_ms(&samples) / 1_000_000;
        assert!(
            p95 <= 100,
            "dataset export manifest p95 {p95}ms exceeds 100ms budget"
        );
    }
}
