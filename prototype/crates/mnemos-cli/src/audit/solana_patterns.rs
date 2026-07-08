//! Solana / Anchor audit pattern surface.
//!
//! PDA seeds, signer, account owner, `remaining_accounts`, oracle freshness,
//! liquidation, CU grief, and receipt parity are *detectors*, not findings. Each
//! detection produces an [`AuditCandidate`] that is candidate-only
//! (`local_repro_done = false`) — it can never become a finding without a local
//! repro receipt. There is no Solana RPC / Anchor client
//! here (no live Solana tool surface yet): this module is a
//! pure pattern descriptor and performs no live action.
//!
//! Reuse (no reinvention): [`AuditCandidate`] / [`AuditProfile`] from
//! [`crate::commands::eval_core`]; the economic-invariant candidate corpus
//! is the source, never a live target.

use crate::commands::eval_core::{AuditCandidate, AuditProfile};
use crate::sha256_32;

/// A Solana / Anchor audit pattern. A detector, never a finding.
#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SolanaPattern {
    /// PDA seeds / bump binding.
    PdaSeeds = 1,
    /// Signer authority.
    Signer = 2,
    /// Account owner check.
    AccountOwner = 3,
    /// `remaining_accounts` handling.
    RemainingAccounts = 4,
    /// Oracle price freshness.
    OracleFreshness = 5,
    /// Liquidation path.
    Liquidation = 6,
    /// Compute-unit grief.
    CuGrief = 7,
    /// Receipt / settlement parity.
    ReceiptParity = 8,
}

impl SolanaPattern {
    /// Stable u8 discriminant.
    #[must_use]
    pub const fn as_u8(self) -> u8 {
        self as u8
    }

    /// The audit profile a Solana pattern detector scans under.
    #[must_use]
    pub const fn profile(self) -> AuditProfile {
        AuditProfile::SolanaSource
    }

    /// A stable rule-id hash for this pattern.
    #[must_use]
    pub fn rule_id_hash_32(self) -> [u8; 32] {
        sha256_32(&[b'S', b'O', b'L', self.as_u8()])
    }

    /// Build a candidate-only detection for this pattern. The candidate carries
    /// the source location + affected invariant + local evidence, with
    /// `local_repro_done = false` — a detector, never a finding.
    #[must_use]
    pub fn detect(
        self,
        location_hash_32: [u8; 32],
        invariant_hash_32: [u8; 32],
        evidence_hash_32: [u8; 32],
        confidence_bps_u16: u16,
    ) -> AuditCandidate {
        AuditCandidate {
            rule_id_hash_32: self.rule_id_hash_32(),
            location_hash_32,
            invariant_hash_32,
            evidence_hash_32,
            confidence_bps_u16: confidence_bps_u16.min(10_000),
            repro_plan_safe_local: true,
            local_repro_done: false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn det(p: SolanaPattern) -> AuditCandidate {
        p.detect([0x22; 32], [0x33; 32], [0x44; 32], 6000)
    }

    #[test]
    fn signer_pda_owner_detectors_candidate_only() {
        for p in [
            SolanaPattern::Signer,
            SolanaPattern::PdaSeeds,
            SolanaPattern::AccountOwner,
        ] {
            let c = det(p);
            assert!(c.fields_complete());
            // a detector is candidate-only: never high-reward without a local repro
            assert!(!c.high_reward_allowed());
            assert_eq!(p.profile(), AuditProfile::SolanaSource);
        }
    }

    #[test]
    fn remaining_accounts_oracle_detectors_candidate_only() {
        for p in [
            SolanaPattern::RemainingAccounts,
            SolanaPattern::OracleFreshness,
        ] {
            let c = det(p);
            assert!(!c.high_reward_allowed());
            assert_ne!(p.rule_id_hash_32(), [0u8; 32]);
        }
    }

    #[test]
    fn liquidation_cu_detectors_candidate_only() {
        for p in [SolanaPattern::Liquidation, SolanaPattern::CuGrief] {
            let c = det(p);
            assert!(!c.high_reward_allowed());
        }
    }

    #[test]
    fn all_patterns_candidate_only_with_distinct_rule_ids() {
        let all = [
            SolanaPattern::PdaSeeds,
            SolanaPattern::Signer,
            SolanaPattern::AccountOwner,
            SolanaPattern::RemainingAccounts,
            SolanaPattern::OracleFreshness,
            SolanaPattern::Liquidation,
            SolanaPattern::CuGrief,
            SolanaPattern::ReceiptParity,
        ];
        for p in all {
            assert!(
                !det(p).high_reward_allowed(),
                "every detection is candidate-only"
            );
        }
        // distinct rule ids
        for (i, a) in all.iter().enumerate() {
            for b in all.iter().skip(i + 1) {
                assert_ne!(a.rule_id_hash_32(), b.rule_id_hash_32());
            }
        }
    }
}
