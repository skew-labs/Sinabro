//! Static detector bridge.
//!
//! Reentrancy, overflow, auth, oracle, PDA, panic, and unsafe detectors produce
//! typed candidates with source anchors — never bounty claims. Each detection is
//! an [`AuditCandidate`] (candidate-only); a low-confidence detection is
//! quarantined as a likely false positive. No detection can become a finding
//! without a local repro receipt. This module performs no
//! live action.
//!
//! Reuse (no reinvention): [`AuditCandidate`] / [`AuditProfile`] / [`AuditScanView`]
//! from [`crate::commands::eval_core`].

use crate::commands::eval_core::{AuditCandidate, AuditProfile, AuditScanView};
use crate::sha256_32;

/// A static-analysis detector kind.
#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DetectorKind {
    /// Reentrancy / re-entrant call.
    Reentrancy = 1,
    /// Integer overflow / underflow.
    Overflow = 2,
    /// Authorization / signer check.
    Auth = 3,
    /// Oracle freshness / staleness.
    Oracle = 4,
    /// PDA seeds / object identity.
    Pda = 5,
    /// Panic / unwrap on a fallible path.
    Panic = 6,
    /// `unsafe` block.
    Unsafe = 7,
}

impl DetectorKind {
    /// Stable u8 discriminant.
    #[must_use]
    pub const fn as_u8(self) -> u8 {
        self as u8
    }

    /// A stable rule-id hash for this detector under a profile.
    #[must_use]
    pub fn rule_id_hash_32(self, profile: AuditProfile) -> [u8; 32] {
        sha256_32(&[b'D', self.as_u8(), profile.as_u8()])
    }
}

/// The confidence (in basis points) below which a detection is quarantined as a
/// likely false positive.
pub const FALSE_POSITIVE_QUARANTINE_BPS: u16 = 3000;

/// A typed static-detector candidate with a source anchor + detector kind + profile.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StaticCandidate {
    /// The detector kind.
    pub kind: DetectorKind,
    /// The audit profile (language surface) scanned.
    pub profile: AuditProfile,
    /// The reused candidate (candidate-only).
    pub candidate: AuditCandidate,
}

impl StaticCandidate {
    /// Detect a static candidate. The `source_anchor_hash_32` (the location) must
    /// be non-zero; the candidate is candidate-only (`local_repro_done = false`).
    #[must_use]
    pub fn detect(
        kind: DetectorKind,
        profile: AuditProfile,
        source_anchor_hash_32: [u8; 32],
        invariant_hash_32: [u8; 32],
        evidence_hash_32: [u8; 32],
        confidence_bps_u16: u16,
    ) -> Option<Self> {
        if source_anchor_hash_32 == [0u8; 32] {
            return None;
        }
        Some(Self {
            kind,
            profile,
            candidate: AuditCandidate {
                rule_id_hash_32: kind.rule_id_hash_32(profile),
                location_hash_32: source_anchor_hash_32,
                invariant_hash_32,
                evidence_hash_32,
                confidence_bps_u16: confidence_bps_u16.min(10_000),
                repro_plan_safe_local: true,
                local_repro_done: false,
            },
        })
    }

    /// Whether this detection is quarantined as a likely false positive (low
    /// confidence).
    #[must_use]
    pub const fn is_quarantined(&self) -> bool {
        self.candidate.confidence_bps_u16 < FALSE_POSITIVE_QUARANTINE_BPS
    }

    /// The source anchor (location) hash.
    #[must_use]
    pub const fn source_anchor_hash_32(&self) -> [u8; 32] {
        self.candidate.location_hash_32
    }

    /// No finding without a receipt: a static candidate is never high-reward on
    /// its own.
    #[must_use]
    pub fn no_finding_without_receipt(&self) -> bool {
        !self.candidate.high_reward_allowed()
    }
}

/// Aggregate static candidates into a local-only scan view (reuse the
/// [`AuditScanView`]).
#[must_use]
pub fn scan(
    profile: AuditProfile,
    changed_only: bool,
    candidates: &[StaticCandidate],
) -> AuditScanView {
    let inner: Vec<AuditCandidate> = candidates.iter().map(|c| c.candidate).collect();
    AuditScanView::scan(profile, changed_only, &inner)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;

    fn det(kind: DetectorKind, profile: AuditProfile, conf: u16) -> Option<StaticCandidate> {
        StaticCandidate::detect(kind, profile, [0x22; 32], [0x33; 32], [0x44; 32], conf)
    }

    #[test]
    fn rust_detector() {
        let c = det(DetectorKind::Overflow, AuditProfile::Rust, 6000).unwrap();
        assert!(c.no_finding_without_receipt());
        assert_eq!(c.source_anchor_hash_32(), [0x22; 32]);
        assert!(!c.is_quarantined());
    }

    #[test]
    fn move_detector() {
        let c = det(DetectorKind::Auth, AuditProfile::Move, 7000).unwrap();
        assert!(c.no_finding_without_receipt());
    }

    #[test]
    fn anchor_detector() {
        let c = det(DetectorKind::Pda, AuditProfile::SolanaSource, 8000).unwrap();
        assert!(c.no_finding_without_receipt());
    }

    #[test]
    fn source_anchor_required() {
        // a zero source anchor is refused (no anchorless candidate)
        assert!(
            StaticCandidate::detect(
                DetectorKind::Reentrancy,
                AuditProfile::Rust,
                [0u8; 32],
                [0x33; 32],
                [0x44; 32],
                9000,
            )
            .is_none()
        );
    }

    #[test]
    fn false_positive_quarantine() {
        let low = det(DetectorKind::Oracle, AuditProfile::SolanaSource, 1000).unwrap();
        assert!(
            low.is_quarantined(),
            "a low-confidence detection is quarantined"
        );
        let high = det(DetectorKind::Oracle, AuditProfile::SolanaSource, 9000).unwrap();
        assert!(!high.is_quarantined());
    }

    #[test]
    fn scan_aggregates_candidate_count() {
        let a = det(DetectorKind::Panic, AuditProfile::Rust, 6000).unwrap();
        let b = det(DetectorKind::Unsafe, AuditProfile::Rust, 6000).unwrap();
        let view = scan(AuditProfile::Rust, true, &[a, b]);
        assert_eq!(view.candidate_count_u32, 2);
        assert!(view.is_local_only());
        assert!(view.made_no_live_call());
    }
}
