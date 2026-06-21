//! Local-only audit report draft (atom #528 · G.3.12).
//!
//! A report draft is generated *only* from a reproduced local repro receipt. It
//! records the impact, the affected invariant, the local repro/proof/replay
//! result, the remediation, the scope, and a non-production guarantee. It never
//! encourages active exploitation, and it never carries a secret, a provider
//! body, or private memory — only hashes, ids, and bounded flags
//! (`G-G-AUDIT-GAME-TREE`, `G-G-SECRET-ZERO`). A draft from a non-reproduced
//! receipt, or one missing the remediation or source anchor, is refused. This
//! module performs no live action.
//!
//! Secret custody (`G-G-SECRET-ZERO`): the [`AuditReportDraft`] type has no field
//! that can hold a secret/provider body/private memory — every field is a `[u8;
//! 32]` hash or a `bool` — so [`AuditReportDraft::holds_no_secret`] is the
//! structural invariant `true`.
//!
//! Reuse (no reinvention): the receipt is
//! [`crate::audit::repro_receipt::LocalReproRunnerReceipt`]; the canonical Stage E
//! finding is the promotion target via [`crate::audit::candidate`].

use crate::audit::repro_receipt::LocalReproRunnerReceipt;

/// Why generating an [`AuditReportDraft`] was refused (fail-closed).
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum ReportDraftReject {
    /// The receipt did not reproduce — a candidate cannot be reported.
    #[error("candidate not reproduced")]
    CandidateNotReproduced,
    /// The receipt was not safe-local (production rpc / live tx used).
    #[error("receipt not local-only")]
    ReceiptNotLocalOnly,
    /// The remediation was missing.
    #[error("missing remediation")]
    MissingRemediation,
    /// The source anchor was missing.
    #[error("missing source anchor")]
    MissingSourceAnchor,
}

/// The narrative hashes for a report draft (impact / invariant / remediation /
/// anchor / scope). Hashes only — never raw text.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ReportDraftInputs {
    /// SHA-256 of the impact summary.
    pub impact_summary_hash_32: [u8; 32],
    /// SHA-256 of the affected invariant.
    pub affected_invariant_hash_32: [u8; 32],
    /// SHA-256 of the remediation guidance (mandatory).
    pub remediation_hash_32: [u8; 32],
    /// SHA-256 of the source anchor (mandatory).
    pub source_anchor_hash_32: [u8; 32],
    /// SHA-256 of the scope.
    pub scope_hash_32: [u8; 32],
}

/// A local-only audit report draft — hashes + bounded flags only, never a secret.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AuditReportDraft {
    /// SHA-256 of the impact summary.
    pub impact_summary_hash_32: [u8; 32],
    /// SHA-256 of the affected invariant.
    pub affected_invariant_hash_32: [u8; 32],
    /// SHA-256 of the local repro/proof/replay result (from the receipt).
    pub repro_receipt_result_hash_32: [u8; 32],
    /// SHA-256 of the remediation guidance.
    pub remediation_hash_32: [u8; 32],
    /// SHA-256 of the source anchor.
    pub source_anchor_hash_32: [u8; 32],
    /// SHA-256 of the scope.
    pub scope_hash_32: [u8; 32],
    /// Invariant `true`: the report carries a non-production guarantee.
    pub non_production_guarantee: bool,
    /// Invariant `false`: the report never encourages active exploitation.
    pub encourages_exploitation: bool,
    /// Invariant `true`: the report holds no secret / provider body / private memory.
    pub holds_no_secret: bool,
}

impl AuditReportDraft {
    /// Generate a draft from a reproduced local receipt. Refuses a non-reproduced
    /// or non-local receipt, and a missing remediation or source anchor.
    pub fn from_receipt(
        receipt: &LocalReproRunnerReceipt,
        inputs: &ReportDraftInputs,
    ) -> Result<Self, ReportDraftReject> {
        if !receipt.is_safe_local() {
            return Err(ReportDraftReject::ReceiptNotLocalOnly);
        }
        if !receipt.reproduced {
            return Err(ReportDraftReject::CandidateNotReproduced);
        }
        if inputs.remediation_hash_32 == [0u8; 32] {
            return Err(ReportDraftReject::MissingRemediation);
        }
        if inputs.source_anchor_hash_32 == [0u8; 32] {
            return Err(ReportDraftReject::MissingSourceAnchor);
        }
        Ok(Self {
            impact_summary_hash_32: inputs.impact_summary_hash_32,
            affected_invariant_hash_32: inputs.affected_invariant_hash_32,
            repro_receipt_result_hash_32: receipt.result_hash_32,
            remediation_hash_32: inputs.remediation_hash_32,
            source_anchor_hash_32: inputs.source_anchor_hash_32,
            scope_hash_32: inputs.scope_hash_32,
            non_production_guarantee: true,
            encourages_exploitation: false,
            holds_no_secret: true,
        })
    }

    /// Whether the draft satisfies its secret-zero + non-exploitation invariants.
    #[must_use]
    pub const fn secret_zero_and_defensive(&self) -> bool {
        self.holds_no_secret && self.non_production_guarantee && !self.encourages_exploitation
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;
    use crate::audit::repro_receipt::ReproReceiptHashes;

    fn receipt(reproduced: bool) -> LocalReproRunnerReceipt {
        LocalReproRunnerReceipt::record(
            &ReproReceiptHashes {
                node_hash_32: [1u8; 32],
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
            affected_invariant_hash_32: [0x20; 32],
            remediation_hash_32: [0x30; 32],
            source_anchor_hash_32: [0x40; 32],
            scope_hash_32: [0x50; 32],
        }
    }

    #[test]
    fn candidate_deny_without_repro() {
        // a non-reproduced receipt cannot generate a report
        assert_eq!(
            AuditReportDraft::from_receipt(&receipt(false), &inputs()),
            Err(ReportDraftReject::CandidateNotReproduced)
        );
    }

    #[test]
    fn repro_report() {
        let r = AuditReportDraft::from_receipt(&receipt(true), &inputs()).unwrap();
        assert_eq!(r.repro_receipt_result_hash_32, [4u8; 32]);
        assert!(r.secret_zero_and_defensive());
    }

    #[test]
    fn no_exploit_prose_and_secret_zero() {
        let r = AuditReportDraft::from_receipt(&receipt(true), &inputs()).unwrap();
        assert!(!r.encourages_exploitation);
        assert!(r.holds_no_secret);
        assert!(r.non_production_guarantee);
    }

    #[test]
    fn remediation_present_required() {
        let mut i = inputs();
        i.remediation_hash_32 = [0u8; 32];
        assert_eq!(
            AuditReportDraft::from_receipt(&receipt(true), &i),
            Err(ReportDraftReject::MissingRemediation)
        );
    }

    #[test]
    fn source_anchors_required() {
        let mut i = inputs();
        i.source_anchor_hash_32 = [0u8; 32];
        assert_eq!(
            AuditReportDraft::from_receipt(&receipt(true), &i),
            Err(ReportDraftReject::MissingSourceAnchor)
        );
    }
}
