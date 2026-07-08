//! Candidate-before-finding boundary.
//!
//! A pattern match, an LLM narrative, a scary diff, or a suspicious invariant gap
//! is a *candidate* only. A finding opens only after a local repro / proof /
//! replay receipt, or it is recorded as a defended no-finding. This module wraps
//! the [`AuditCandidate`] with its game-tree origin and gates promotion
//! through the canonical [`route_to_finding`]: a candidate with no reproduced,
//! local-only receipt that backs its node can never become a finding. This
//! module performs no live action.
//!
//! Reuse (no reinvention): [`AuditCandidate`] / [`route_to_finding`] /
//! [`EvalReject`] from [`crate::commands::eval_core`]; the local receipt is
//! [`crate::audit::repro_receipt::LocalReproRunnerReceipt`]; the canonical finding
//! and severity types come from `mnemos_l_dataset`.

use crate::audit::repro_receipt::LocalReproRunnerReceipt;
use crate::commands::eval_core::{AuditCandidate, EvalReject, route_to_finding};
use mnemos_l_dataset::AtomDietKey;
use mnemos_l_dataset::security::audit_finding::AuditFinding;
use mnemos_l_dataset::security::source::SecuritySeverity;

/// Where a candidate came from. Every origin is *candidate-only* — never a finding
/// on its own.
#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CandidateOrigin {
    /// A static pattern match.
    PatternMatch = 1,
    /// An LLM narrative / story.
    LlmNarrative = 2,
    /// A scary-looking diff.
    ScaryDiff = 3,
    /// A suspicious invariant gap.
    SuspiciousInvariantGap = 4,
}

/// Why promoting a candidate to a finding was refused (fail-closed).
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum PromotionReject {
    /// The local receipt did not reproduce the candidate.
    #[error("receipt not reproduced")]
    ReceiptNotReproduced,
    /// The local receipt was not safe-local (production rpc / live tx used).
    #[error("receipt not local-only")]
    ReceiptNotLocalOnly,
    /// The receipt did not back this candidate's search node.
    #[error("receipt node mismatch")]
    ReceiptNodeMismatch,
    /// The canonical finding route refused (candidate incomplete / no evidence).
    #[error("finding route refused")]
    FindingRouteRefused,
}

impl From<EvalReject> for PromotionReject {
    fn from(_: EvalReject) -> Self {
        Self::FindingRouteRefused
    }
}

/// An audit-game-tree candidate: an [`AuditCandidate`] plus the
/// game-tree origin and the search node it sits on.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AuditGameTreeCandidate {
    /// The reused candidate (rule / location / invariant / evidence).
    pub inner: AuditCandidate,
    /// The candidate origin (always candidate-only).
    pub origin: CandidateOrigin,
    /// SHA-256 of the search node this candidate sits on.
    pub node_hash_32: [u8; 32],
}

impl AuditGameTreeCandidate {
    /// Whether this is still a pattern-only candidate (no local reproduction yet).
    #[must_use]
    pub fn is_pattern_only(&self) -> bool {
        !self.inner.local_repro_done
    }

    /// Promote the candidate to a canonical finding using a local repro receipt.
    /// Refuses unless the receipt is safe-local, reproduced, and backs this
    /// candidate's node — then routes through the canonical [`route_to_finding`],
    /// which re-checks candidate completeness. A finding can never open without a
    /// reproduced, local-only receipt.
    pub fn promote(
        &self,
        receipt: &LocalReproRunnerReceipt,
        key: AtomDietKey,
        severity: SecuritySeverity,
    ) -> Result<AuditFinding, PromotionReject> {
        if !receipt.is_safe_local() {
            return Err(PromotionReject::ReceiptNotLocalOnly);
        }
        if !receipt.reproduced {
            return Err(PromotionReject::ReceiptNotReproduced);
        }
        if receipt.node_hash_32 != self.node_hash_32 {
            return Err(PromotionReject::ReceiptNodeMismatch);
        }
        // The receipt reproduced locally: mark the reused candidate reproduced and
        // route it through the canonical finding gate (re-checks completeness).
        let reproduced = AuditCandidate {
            local_repro_done: true,
            ..self.inner
        };
        Ok(route_to_finding(&reproduced, key, severity)?)
    }
}

/// A defended no-finding outcome: the boundary recorded that no finding opened.
/// Reward-neutral — never a positive signal.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DefendedNoFinding {
    /// SHA-256 of the invariant that held.
    pub invariant_hash_32: [u8; 32],
    /// SHA-256 of the search node explored.
    pub node_hash_32: [u8; 32],
}

impl DefendedNoFinding {
    /// A defended outcome opens no finding and is reward-neutral. Always `true`.
    #[must_use]
    pub const fn reward_neutral() -> bool {
        true
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;
    use crate::audit::repro_receipt::ReproReceiptHashes;
    use mnemos_l_dataset::diet_kind::DietSourceStage;

    fn key() -> AtomDietKey {
        AtomDietKey::new(DietSourceStage::StageD, 253)
    }

    fn cand(origin: CandidateOrigin, evidence_ok: bool, node: u8) -> AuditGameTreeCandidate {
        AuditGameTreeCandidate {
            inner: AuditCandidate {
                rule_id_hash_32: [0x11; 32],
                location_hash_32: [0x22; 32],
                invariant_hash_32: [0x33; 32],
                evidence_hash_32: if evidence_ok { [0x44; 32] } else { [0u8; 32] },
                confidence_bps_u16: 7000,
                repro_plan_safe_local: true,
                local_repro_done: false,
            },
            origin,
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

    #[test]
    fn pattern_only_stays_candidate() {
        let c = cand(CandidateOrigin::PatternMatch, true, 5);
        assert!(c.is_pattern_only());
        // a non-reproduced receipt never promotes
        assert_eq!(
            c.promote(&receipt(5, false), key(), SecuritySeverity::High),
            Err(PromotionReject::ReceiptNotReproduced)
        );
    }

    #[test]
    fn repro_promotes() {
        let c = cand(CandidateOrigin::SuspiciousInvariantGap, true, 5);
        let f = c
            .promote(&receipt(5, true), key(), SecuritySeverity::High)
            .unwrap();
        assert!(f.evidence_present);
    }

    #[test]
    fn proof_promotes() {
        // a "proof" is also a reproduced, local-only receipt
        let c = cand(CandidateOrigin::ScaryDiff, true, 9);
        assert!(
            c.promote(&receipt(9, true), key(), SecuritySeverity::Medium)
                .is_ok()
        );
    }

    #[test]
    fn defended_invariant_reward_neutral() {
        let d = DefendedNoFinding {
            invariant_hash_32: [0x33; 32],
            node_hash_32: [5u8; 32],
        };
        assert!(DefendedNoFinding::reward_neutral());
        assert_eq!(d.node_hash_32, [5u8; 32]);
    }

    #[test]
    fn report_denied_without_repro() {
        // node mismatch => denied
        let c = cand(CandidateOrigin::PatternMatch, true, 5);
        assert_eq!(
            c.promote(&receipt(6, true), key(), SecuritySeverity::High),
            Err(PromotionReject::ReceiptNodeMismatch)
        );
        // incomplete evidence => canonical route refuses even with a reproduced receipt
        let incomplete = cand(CandidateOrigin::LlmNarrative, false, 7);
        assert_eq!(
            incomplete.promote(&receipt(7, true), key(), SecuritySeverity::High),
            Err(PromotionReject::FindingRouteRefused)
        );
    }

    #[test]
    fn positive_finding_without_receipt_count_zero() {
        // a batch of pattern-only candidates with non-reproduced receipts yields 0 findings
        let cands = [
            cand(CandidateOrigin::PatternMatch, true, 1),
            cand(CandidateOrigin::ScaryDiff, true, 2),
        ];
        let mut findings = 0u32;
        for (i, c) in cands.iter().enumerate() {
            let node = u8::try_from(i + 1).unwrap_or(1);
            if c.promote(&receipt(node, false), key(), SecuritySeverity::Low)
                .is_ok()
            {
                findings += 1;
            }
        }
        assert_eq!(findings, 0);
    }
}
