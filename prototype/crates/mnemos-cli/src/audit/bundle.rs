//! Audit evidence bundle export.
//!
//! A bundle packages the local audit-game-tree evidence for one outcome: the
//! affected invariant, the candidate's search node, the local repro/proof/replay
//! result, the defended no-finding (if any), the source anchor, and the
//! remediation note. A finding bundle requires a reproduced, local-only receipt
//! ([`BundleReject::MissingReceipt`]); a candidate or defended bundle carries no
//! finding claim. The bundle hash is stable, the export is local-only (a live
//! upload is structurally denied, [`BundleReject::LiveExportDenied`]), and it holds
//! no private memory or provider body — every field is a `[u8; 32]` hash, a bool,
//! or an `Option` of a secret-zero record. This module performs no live action.
//!
//! Live-export boundary: mirroring
//! [`crate::commands::evidence::EvidenceArchivePlan::try_live_archive`], there is
//! no live-upload path — [`AuditBundle::try_live_export`] always refuses, so no
//! same-message approval is required (fail-closed).
//!
//! Reuse (no reinvention): [`AuditGameTreeCandidate`] / [`DefendedNoFinding`],
//! [`LocalReproRunnerReceipt`], [`AuditReportDraft`],
//! [`DefendedInvariantMemory`].

use crate::audit::candidate::AuditGameTreeCandidate;
use crate::audit::defended_memory::DefendedInvariantMemory;
use crate::audit::report_draft::{AuditReportDraft, ReportDraftInputs};
use crate::audit::repro_receipt::LocalReproRunnerReceipt;
use crate::{hex32, sha256_32};

/// First 16 hex characters of a 32-byte digest — a redacted, display-only prefix.
#[must_use]
fn redact16(bytes: &[u8; 32]) -> String {
    hex32(bytes).chars().take(16).collect()
}

/// The kind of audit bundle.
#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BundleKind {
    /// A candidate-only bundle (no finding claim).
    Candidate = 1,
    /// A reproduced finding bundle (carries a report draft).
    Finding = 2,
    /// A defended no-finding bundle (reward-neutral).
    Defended = 3,
}

impl BundleKind {
    /// Stable `u8` discriminant.
    #[must_use]
    pub const fn as_u8(self) -> u8 {
        self as u8
    }
}

/// Why building / exporting a bundle was refused (fail-closed).
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum BundleReject {
    /// A finding bundle was requested without a reproduced, local-only receipt.
    #[error("missing reproduced local receipt")]
    MissingReceipt,
    /// The report draft was incomplete (missing remediation / source anchor).
    #[error("incomplete report draft")]
    IncompleteReport,
    /// A live export / upload was attempted — always denied.
    #[error("live export denied")]
    LiveExportDenied,
}

/// Compute the stable bundle hash over the kind + invariant + node + repro result
/// + source anchor + remediation.
fn compute_bundle_hash(
    kind: BundleKind,
    invariant_hash_32: &[u8; 32],
    candidate_node_hash_32: &[u8; 32],
    repro_result_hash_32: &[u8; 32],
    source_anchor_hash_32: &[u8; 32],
    remediation_hash_32: &[u8; 32],
) -> [u8; 32] {
    let mut buf: Vec<u8> = Vec::with_capacity(23 + 1 + 32 * 5);
    buf.extend_from_slice(b"sinabro.audit.bundle.v1");
    buf.push(kind.as_u8());
    buf.extend_from_slice(invariant_hash_32);
    buf.extend_from_slice(candidate_node_hash_32);
    buf.extend_from_slice(repro_result_hash_32);
    buf.extend_from_slice(source_anchor_hash_32);
    buf.extend_from_slice(remediation_hash_32);
    sha256_32(&buf)
}

/// A local-only audit evidence bundle — hashes + bounded flags + secret-zero
/// records only, never a secret / provider body / private memory.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AuditBundle {
    /// The bundle kind.
    pub kind: BundleKind,
    /// SHA-256 of the affected invariant.
    pub invariant_hash_32: [u8; 32],
    /// SHA-256 of the candidate's search node (zero for a defended bundle).
    pub candidate_node_hash_32: [u8; 32],
    /// SHA-256 of the local repro/proof/replay result (zero for a bare candidate).
    pub repro_result_hash_32: [u8; 32],
    /// The local-only report draft (present only for a finding bundle).
    pub report_draft: Option<AuditReportDraft>,
    /// The defended-invariant memory (present only for a defended bundle).
    pub defended: Option<DefendedInvariantMemory>,
    /// SHA-256 of the source anchor.
    pub source_anchor_hash_32: [u8; 32],
    /// SHA-256 of the remediation note.
    pub remediation_hash_32: [u8; 32],
    /// The stable bundle hash.
    pub bundle_hash_32: [u8; 32],
    /// Invariant `false`: a bundle is never a live export / upload.
    pub live_export: bool,
    /// Invariant `true`: the bundle holds no secret / provider body / private memory.
    pub holds_no_secret: bool,
}

impl AuditBundle {
    /// A candidate-only bundle (no finding claim, no receipt). Carries the invariant
    /// and the candidate's node plus the source anchor and remediation note.
    #[must_use]
    pub fn candidate(
        candidate: &AuditGameTreeCandidate,
        source_anchor_hash_32: [u8; 32],
        remediation_hash_32: [u8; 32],
    ) -> Self {
        let kind = BundleKind::Candidate;
        let invariant_hash_32 = candidate.inner.invariant_hash_32;
        let candidate_node_hash_32 = candidate.node_hash_32;
        let repro_result_hash_32 = [0u8; 32];
        Self {
            kind,
            invariant_hash_32,
            candidate_node_hash_32,
            repro_result_hash_32,
            report_draft: None,
            defended: None,
            source_anchor_hash_32,
            remediation_hash_32,
            bundle_hash_32: compute_bundle_hash(
                kind,
                &invariant_hash_32,
                &candidate_node_hash_32,
                &repro_result_hash_32,
                &source_anchor_hash_32,
                &remediation_hash_32,
            ),
            live_export: false,
            holds_no_secret: true,
        }
    }

    /// A finding bundle. Requires a reproduced, local-only receipt that backs the
    /// candidate's node and a complete report draft (remediation + source anchor).
    pub fn finding(
        candidate: &AuditGameTreeCandidate,
        receipt: &LocalReproRunnerReceipt,
        inputs: &ReportDraftInputs,
    ) -> Result<Self, BundleReject> {
        if !receipt.promotes() {
            return Err(BundleReject::MissingReceipt);
        }
        let draft = AuditReportDraft::from_receipt(receipt, inputs)
            .map_err(|_| BundleReject::IncompleteReport)?;
        let kind = BundleKind::Finding;
        let invariant_hash_32 = candidate.inner.invariant_hash_32;
        let candidate_node_hash_32 = candidate.node_hash_32;
        let repro_result_hash_32 = receipt.result_hash_32;
        Ok(Self {
            kind,
            invariant_hash_32,
            candidate_node_hash_32,
            repro_result_hash_32,
            report_draft: Some(draft),
            defended: None,
            source_anchor_hash_32: inputs.source_anchor_hash_32,
            remediation_hash_32: inputs.remediation_hash_32,
            bundle_hash_32: compute_bundle_hash(
                kind,
                &invariant_hash_32,
                &candidate_node_hash_32,
                &repro_result_hash_32,
                &inputs.source_anchor_hash_32,
                &inputs.remediation_hash_32,
            ),
            live_export: false,
            holds_no_secret: true,
        })
    }

    /// A defended no-finding bundle (reward-neutral): the invariant held, recorded
    /// so the same dead end is not re-read.
    #[must_use]
    pub fn defended(
        memory: DefendedInvariantMemory,
        source_anchor_hash_32: [u8; 32],
        remediation_hash_32: [u8; 32],
    ) -> Self {
        let kind = BundleKind::Defended;
        let invariant_hash_32 = memory.invariant_hash_32;
        let repro_result_hash_32 = memory.replay_hash_32;
        Self {
            kind,
            invariant_hash_32,
            candidate_node_hash_32: [0u8; 32],
            repro_result_hash_32,
            report_draft: None,
            defended: Some(memory),
            source_anchor_hash_32,
            remediation_hash_32,
            bundle_hash_32: compute_bundle_hash(
                kind,
                &invariant_hash_32,
                &[0u8; 32],
                &repro_result_hash_32,
                &source_anchor_hash_32,
                &remediation_hash_32,
            ),
            live_export: false,
            holds_no_secret: true,
        }
    }

    /// The stable bundle hash.
    #[must_use]
    pub const fn bundle_hash_32(&self) -> [u8; 32] {
        self.bundle_hash_32
    }

    /// The redacted (16-hex) bundle-hash prefix for display.
    #[must_use]
    pub fn redacted_bundle_hash(&self) -> String {
        redact16(&self.bundle_hash_32)
    }

    /// Attempt a live export / upload — always refused (export is local-only).
    pub const fn try_live_export(&self) -> Result<(), BundleReject> {
        Err(BundleReject::LiveExportDenied)
    }

    /// Whether the bundle satisfies its secret-zero + local-only invariants.
    #[must_use]
    pub const fn secret_zero_local_only(&self) -> bool {
        self.holds_no_secret && !self.live_export
    }

    /// Redacted, colorless bundle lines bounded by `rows`.
    #[must_use]
    pub fn render(&self, rows: u16) -> Vec<String> {
        let lines = vec![
            format!("kind={}", self.kind.as_u8()),
            format!("invariant={}", redact16(&self.invariant_hash_32)),
            format!("node={}", redact16(&self.candidate_node_hash_32)),
            format!("repro_result={}", redact16(&self.repro_result_hash_32)),
            format!("source_anchor={}", redact16(&self.source_anchor_hash_32)),
            format!("remediation={}", redact16(&self.remediation_hash_32)),
            format!("bundle_hash={}", self.redacted_bundle_hash()),
            format!("live_export={}", self.live_export),
        ];
        lines.into_iter().take(rows as usize).collect()
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;
    use crate::audit::candidate::CandidateOrigin;
    use crate::audit::defended_memory::defended;
    use crate::audit::repro_receipt::ReproReceiptHashes;
    use crate::commands::eval_core::AuditCandidate;

    const COMMERCE_TOKENS: &[&str] = &[
        "price", "pay", "buy", "sell", "checkout", "refund", "fee", "cost", "$",
    ];

    fn candidate(node: u8) -> AuditGameTreeCandidate {
        AuditGameTreeCandidate {
            inner: AuditCandidate {
                rule_id_hash_32: [0x11; 32],
                location_hash_32: [0x22; 32],
                invariant_hash_32: [0x33; 32],
                evidence_hash_32: [0x44; 32],
                confidence_bps_u16: 7000,
                repro_plan_safe_local: true,
                local_repro_done: false,
            },
            origin: CandidateOrigin::SuspiciousInvariantGap,
            node_hash_32: [node; 32],
        }
    }

    fn receipt(node: u8, reproduced: bool) -> LocalReproRunnerReceipt {
        LocalReproRunnerReceipt::record(
            &ReproReceiptHashes {
                node_hash_32: [node; 32],
                command_hash_32: [2u8; 32],
                fixture_hash_32: [3u8; 32],
                result_hash_32: [4u8; 32],
            },
            reproduced,
            false,
            false,
        )
        .unwrap()
    }

    fn inputs() -> ReportDraftInputs {
        ReportDraftInputs {
            impact_summary_hash_32: [0x10; 32],
            affected_invariant_hash_32: [0x33; 32],
            remediation_hash_32: [0x30; 32],
            source_anchor_hash_32: [0x40; 32],
            scope_hash_32: [0x50; 32],
        }
    }

    #[test]
    fn candidate_bundle() {
        let b = AuditBundle::candidate(&candidate(5), [0x40; 32], [0x30; 32]);
        assert_eq!(b.kind, BundleKind::Candidate);
        assert_eq!(b.repro_result_hash_32, [0u8; 32]);
        assert!(b.report_draft.is_none());
        assert_ne!(b.bundle_hash_32, [0u8; 32]);
        assert!(b.holds_no_secret);
    }

    #[test]
    fn finding_bundle() {
        let b = AuditBundle::finding(&candidate(5), &receipt(5, true), &inputs()).unwrap();
        assert_eq!(b.kind, BundleKind::Finding);
        assert!(b.report_draft.is_some());
        assert_eq!(b.repro_result_hash_32, [4u8; 32]);
    }

    #[test]
    fn defended_bundle() {
        let mem = defended([0x33; 32], 10, 9, 0);
        let b = AuditBundle::defended(mem, [0x40; 32], [0x30; 32]);
        assert_eq!(b.kind, BundleKind::Defended);
        assert!(b.defended.is_some());
        assert_eq!(b.repro_result_hash_32, mem.replay_hash_32);
    }

    #[test]
    fn missing_receipt_reject() {
        // a non-reproduced receipt cannot back a finding bundle
        assert_eq!(
            AuditBundle::finding(&candidate(5), &receipt(5, false), &inputs()),
            Err(BundleReject::MissingReceipt)
        );
    }

    #[test]
    fn secret_zero_and_live_export_denied() {
        let b = AuditBundle::candidate(&candidate(5), [0x40; 32], [0x30; 32]);
        assert!(b.secret_zero_local_only());
        assert_eq!(b.try_live_export(), Err(BundleReject::LiveExportDenied));
        for line in b.render(16) {
            for bad in COMMERCE_TOKENS {
                assert!(!line.contains(bad), "commerce token {bad} in {line}");
            }
        }
    }

    #[test]
    fn bundle_hash_stable() {
        let a = AuditBundle::candidate(&candidate(5), [0x40; 32], [0x30; 32]);
        let b = AuditBundle::candidate(&candidate(5), [0x40; 32], [0x30; 32]);
        assert_eq!(a.bundle_hash_32, b.bundle_hash_32);
        assert_eq!(a.redacted_bundle_hash().len(), 16);
    }
}
