//! Audit detector pattern surface (atom #543 · G.4.12).
//!
//! A unified surface over the Stage G detectors (static, Solana/Anchor,
//! Sui/Move/Walrus): each detector can *flag* suspicious code, but every flag is
//! routed to the candidate boundary as an [`AuditGameTreeCandidate`] with
//! `local_repro_done = false` and origin [`CandidateOrigin::PatternMatch`]. No
//! detector can emit a confirmed finding directly — a finding opens only after a
//! local repro receipt promotes the candidate ([`crate::audit::candidate`]). The
//! direct-finding count is therefore structurally `0`
//! ([`DetectorSurface::direct_finding_count`]) (`G-G-AUDIT-GAME-TREE`). This module
//! performs no live action.
//!
//! Reuse (no reinvention): [`StaticCandidate`] / [`DetectorKind`] (#525),
//! [`SolanaPattern`] (#523), [`SuiMovePattern`] (#524), [`AuditCandidate`] /
//! [`AuditProfile`] / [`AuditScanView`] (#521 spine).

use crate::audit::candidate::{AuditGameTreeCandidate, CandidateOrigin};
use crate::audit::solana_patterns::SolanaPattern;
use crate::audit::static_detector::{DetectorKind, StaticCandidate};
use crate::audit::sui_move_patterns::SuiMovePattern;
use crate::commands::eval_core::{AuditCandidate, AuditProfile, AuditScanView};
use crate::sha256_32;

/// The search-node hash a detector candidate sits on (domain-tagged over the rule
/// id + source location), so a later local repro receipt can back exactly this node.
fn node_hash(rule_id_hash_32: &[u8; 32], location_hash_32: &[u8; 32]) -> [u8; 32] {
    let mut buf: Vec<u8> = Vec::with_capacity(21 + 64);
    buf.extend_from_slice(b"sinabro.audit.node.v1");
    buf.extend_from_slice(rule_id_hash_32);
    buf.extend_from_slice(location_hash_32);
    sha256_32(&buf)
}

/// Wrap a Stage F [`AuditCandidate`] as a candidate-only game-tree node (a
/// detector flag is always a `PatternMatch` origin, never a finding).
fn wrap(inner: AuditCandidate) -> AuditGameTreeCandidate {
    let node_hash_32 = node_hash(&inner.rule_id_hash_32, &inner.location_hash_32);
    AuditGameTreeCandidate {
        inner,
        origin: CandidateOrigin::PatternMatch,
        node_hash_32,
    }
}

/// The detector surface: every method flags a candidate-only node, never a finding.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DetectorSurface;

impl DetectorSurface {
    /// Flag a static-analysis detection (reentrancy / overflow / auth / oracle /
    /// PDA / panic / unsafe). Returns `None` if the source anchor is zero (no
    /// anchorless candidate); otherwise a candidate-only node.
    #[must_use]
    pub fn flag_static(
        kind: DetectorKind,
        profile: AuditProfile,
        source_anchor_hash_32: [u8; 32],
        invariant_hash_32: [u8; 32],
        evidence_hash_32: [u8; 32],
        confidence_bps_u16: u16,
    ) -> Option<AuditGameTreeCandidate> {
        StaticCandidate::detect(
            kind,
            profile,
            source_anchor_hash_32,
            invariant_hash_32,
            evidence_hash_32,
            confidence_bps_u16,
        )
        .map(|sc| wrap(sc.candidate))
    }

    /// Flag a Solana / Anchor pattern detection (candidate-only node).
    #[must_use]
    pub fn flag_solana(
        pattern: SolanaPattern,
        location_hash_32: [u8; 32],
        invariant_hash_32: [u8; 32],
        evidence_hash_32: [u8; 32],
        confidence_bps_u16: u16,
    ) -> AuditGameTreeCandidate {
        wrap(pattern.detect(
            location_hash_32,
            invariant_hash_32,
            evidence_hash_32,
            confidence_bps_u16,
        ))
    }

    /// Flag a Sui / Move / Walrus pattern detection (candidate-only node).
    #[must_use]
    pub fn flag_sui_move(
        pattern: SuiMovePattern,
        location_hash_32: [u8; 32],
        invariant_hash_32: [u8; 32],
        evidence_hash_32: [u8; 32],
        confidence_bps_u16: u16,
    ) -> AuditGameTreeCandidate {
        wrap(pattern.detect(
            location_hash_32,
            invariant_hash_32,
            evidence_hash_32,
            confidence_bps_u16,
        ))
    }

    /// The number of candidates that are *not* pattern-only (i.e. already a direct
    /// finding). A detector can never emit a finding directly, so this is always
    /// `0` for detector output.
    #[must_use]
    pub fn direct_finding_count(candidates: &[AuditGameTreeCandidate]) -> u32 {
        u32::try_from(candidates.iter().filter(|c| !c.is_pattern_only()).count())
            .unwrap_or(u32::MAX)
    }

    /// E11-2: wrap a REAL source-scan [`AuditCandidate`] (from
    /// [`crate::commands::source_scan::scan_tree`]) as a candidate-only
    /// `PatternMatch` game-tree node — the bridge from the real source walk into
    /// the audit game tree. A source flag is ALWAYS a candidate, never a finding
    /// (reuses [`wrap`]: `local_repro_done` is preserved from the source candidate
    /// — `false` for a pattern hit — and the origin is [`CandidateOrigin::PatternMatch`]).
    #[must_use]
    pub fn flag_source_candidate(inner: AuditCandidate) -> AuditGameTreeCandidate {
        wrap(inner)
    }

    /// Aggregate detector candidates into a local-only Stage F scan view.
    #[must_use]
    pub fn scan(
        profile: AuditProfile,
        changed_only: bool,
        candidates: &[AuditGameTreeCandidate],
    ) -> AuditScanView {
        let inner: Vec<AuditCandidate> = candidates.iter().map(|c| c.inner).collect();
        AuditScanView::scan(profile, changed_only, &inner)
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;

    fn anchor() -> [u8; 32] {
        [0x22; 32]
    }

    #[test]
    fn auth_detector_is_candidate_only() {
        let c = DetectorSurface::flag_static(
            DetectorKind::Auth,
            AuditProfile::Rust,
            anchor(),
            [0x33; 32],
            [0x44; 32],
            7000,
        )
        .unwrap();
        assert!(c.is_pattern_only());
        assert!(!c.inner.high_reward_allowed());
    }

    #[test]
    fn overflow_detector_is_candidate_only() {
        let c = DetectorSurface::flag_static(
            DetectorKind::Overflow,
            AuditProfile::Rust,
            anchor(),
            [0x33; 32],
            [0x44; 32],
            6000,
        )
        .unwrap();
        assert!(c.is_pattern_only());
    }

    #[test]
    fn oracle_detector_is_candidate_only() {
        let c = DetectorSurface::flag_solana(
            SolanaPattern::OracleFreshness,
            anchor(),
            [0x33; 32],
            [0x44; 32],
            8000,
        );
        assert!(c.is_pattern_only());
        assert!(!c.inner.high_reward_allowed());
    }

    #[test]
    fn pda_detector_is_candidate_only() {
        let c = DetectorSurface::flag_solana(
            SolanaPattern::PdaSeeds,
            anchor(),
            [0x33; 32],
            [0x44; 32],
            8000,
        );
        assert!(c.is_pattern_only());
    }

    #[test]
    fn move_owner_detector_is_candidate_only() {
        let c = DetectorSurface::flag_sui_move(
            SuiMovePattern::ObjectOwnership,
            anchor(),
            [0x33; 32],
            [0x44; 32],
            7500,
        );
        assert!(c.is_pattern_only());
    }

    #[test]
    fn walrus_id_detector_is_candidate_only() {
        let c = DetectorSurface::flag_sui_move(
            SuiMovePattern::BlobIdRootMismatch,
            anchor(),
            [0x33; 32],
            [0x44; 32],
            7500,
        );
        assert!(c.is_pattern_only());
    }

    #[test]
    fn direct_finding_count_is_zero() {
        let batch = vec![
            DetectorSurface::flag_static(
                DetectorKind::Auth,
                AuditProfile::Rust,
                anchor(),
                [0x33; 32],
                [0x44; 32],
                7000,
            )
            .unwrap(),
            DetectorSurface::flag_solana(
                SolanaPattern::OracleFreshness,
                anchor(),
                [0x33; 32],
                [0x44; 32],
                8000,
            ),
            DetectorSurface::flag_sui_move(
                SuiMovePattern::ObjectOwnership,
                anchor(),
                [0x33; 32],
                [0x44; 32],
                7500,
            ),
        ];
        assert_eq!(DetectorSurface::direct_finding_count(&batch), 0);
        let view = DetectorSurface::scan(AuditProfile::Rust, true, &batch);
        assert_eq!(view.candidate_count_u32, 3);
        assert!(view.is_local_only());
        assert!(view.made_no_live_call());
    }

    #[test]
    fn anchorless_static_detection_is_rejected() {
        assert!(
            DetectorSurface::flag_static(
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
}
