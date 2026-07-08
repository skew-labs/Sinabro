//! Sui / Move / Walrus audit pattern surface.
//!
//! Object ownership, resource movement, event/audit log, blob-id/root mismatch,
//! epoch/storage proof, gas boundary, and permissionless settlement are
//! *candidates* until a Move test / prover / replay confirms them. Each detection
//! produces an [`AuditCandidate`] that is candidate-only
//! (`local_repro_done = false`) — never a finding without a local proof / replay.
//! This module is a pure pattern descriptor and performs
//! no live action.
//!
//! Reuse (no reinvention): [`AuditCandidate`] / [`AuditProfile`] from
//! [`crate::commands::eval_core`]; the Move/Walrus evidence is the source
//! corpus, never a live target.

use crate::commands::eval_core::{AuditCandidate, AuditProfile};
use crate::sha256_32;

/// A Sui / Move / Walrus audit pattern. A detector, never a finding.
#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SuiMovePattern {
    /// Object ownership / transfer authority.
    ObjectOwnership = 1,
    /// Resource movement / linear-type discipline.
    ResourceMovement = 2,
    /// Event / audit-log emission.
    EventAuditLog = 3,
    /// Walrus blob-id / memory-root mismatch.
    BlobIdRootMismatch = 4,
    /// Epoch / storage proof.
    EpochStorageProof = 5,
    /// Gas boundary.
    GasBoundary = 6,
    /// Permissionless settlement.
    PermissionlessSettlement = 7,
}

impl SuiMovePattern {
    /// Stable u8 discriminant.
    #[must_use]
    pub const fn as_u8(self) -> u8 {
        self as u8
    }

    /// The audit profile a pattern detector scans under. A Walrus blob/root
    /// mismatch is a storage concern; the rest are Sui-source concerns.
    #[must_use]
    pub const fn profile(self) -> AuditProfile {
        match self {
            Self::BlobIdRootMismatch | Self::EpochStorageProof => AuditProfile::Storage,
            _ => AuditProfile::SuiSource,
        }
    }

    /// A stable rule-id hash for this pattern.
    #[must_use]
    pub fn rule_id_hash_32(self) -> [u8; 32] {
        sha256_32(&[b'S', b'U', b'I', self.as_u8()])
    }

    /// Build a candidate-only detection for this pattern (`local_repro_done = false`).
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

    fn det(p: SuiMovePattern) -> AuditCandidate {
        p.detect([0x22; 32], [0x33; 32], [0x44; 32], 6000)
    }

    #[test]
    fn owner_resource_event_candidate_only() {
        for p in [
            SuiMovePattern::ObjectOwnership,
            SuiMovePattern::ResourceMovement,
            SuiMovePattern::EventAuditLog,
        ] {
            let c = det(p);
            assert!(c.fields_complete());
            assert!(!c.high_reward_allowed());
            assert_eq!(p.profile(), AuditProfile::SuiSource);
        }
    }

    #[test]
    fn blob_id_epoch_are_storage_candidates() {
        for p in [
            SuiMovePattern::BlobIdRootMismatch,
            SuiMovePattern::EpochStorageProof,
        ] {
            let c = det(p);
            assert!(!c.high_reward_allowed());
            assert_eq!(p.profile(), AuditProfile::Storage);
        }
    }

    #[test]
    fn gas_permissionless_candidate_only() {
        for p in [
            SuiMovePattern::GasBoundary,
            SuiMovePattern::PermissionlessSettlement,
        ] {
            let c = det(p);
            assert!(!c.high_reward_allowed());
            assert_ne!(p.rule_id_hash_32(), [0u8; 32]);
        }
    }

    #[test]
    fn all_patterns_candidate_only() {
        let all = [
            SuiMovePattern::ObjectOwnership,
            SuiMovePattern::ResourceMovement,
            SuiMovePattern::EventAuditLog,
            SuiMovePattern::BlobIdRootMismatch,
            SuiMovePattern::EpochStorageProof,
            SuiMovePattern::GasBoundary,
            SuiMovePattern::PermissionlessSettlement,
        ];
        for p in all {
            assert!(
                !det(p).high_reward_allowed(),
                "every detection is candidate-only"
            );
        }
    }
}
