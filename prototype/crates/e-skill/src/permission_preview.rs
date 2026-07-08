//! `mnemos-e-skill::permission_preview` — the permission
//! diff preview shown before trial / install.
//!
//! The CLI and agent **must** show a [`PermissionPreview`] before a skill is
//! used, before a dry-run is escalated, and before an install. The preview is
//! derived deterministically from a [`CapabilityDiff`] (#244): no diff means no
//! use and no install ([`gate_action`] returns [`PreviewGate::Blocked`] for a
//! missing or inconsistent diff). Popularity never enters here — a high-risk
//! permission is flagged regardless of download counts.

#![deny(missing_docs)]

extern crate alloc;

use alloc::vec::Vec;

use mnemos_f_seal::capability::CapabilityKind;

use crate::capability_diff::{CapabilityDiff, SkillRuntimePermission};

/// All ten runtime permissions in discriminant order, for decoding a mask.
const ALL_PERMISSIONS: [SkillRuntimePermission; 10] = [
    SkillRuntimePermission::FileRead,
    SkillRuntimePermission::FileWrite,
    SkillRuntimePermission::Network,
    SkillRuntimePermission::Wallet,
    SkillRuntimePermission::Chain,
    SkillRuntimePermission::Secret,
    SkillRuntimePermission::MemoryRead,
    SkillRuntimePermission::MemoryWrite,
    SkillRuntimePermission::AnchorChunk,
    SkillRuntimePermission::ToolInvoke,
];

/// `true` for a permission whose addition is high-risk and must be surfaced
/// prominently: file write, network, wallet, chain, or secret.
#[must_use]
const fn is_high_risk(permission: SkillRuntimePermission) -> bool {
    matches!(
        permission,
        SkillRuntimePermission::FileWrite
            | SkillRuntimePermission::Network
            | SkillRuntimePermission::Wallet
            | SkillRuntimePermission::Chain
            | SkillRuntimePermission::Secret
    )
}

/// Decode the permissions set in `mask`, in discriminant order.
#[must_use]
fn decode_mask(mask: u64) -> Vec<SkillRuntimePermission> {
    let mut out = Vec::new();
    for p in ALL_PERMISSIONS {
        if mask & p.mask_bit() != 0 {
            out.push(p);
        }
    }
    out
}

/// Deterministic, display-ready view of a [`CapabilityDiff`]. Built only via
/// [`Self::from_diff`], so the same diff always yields the same preview.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PermissionPreview {
    /// Permissions this version adds.
    pub added: Vec<SkillRuntimePermission>,
    /// Permissions this version removes.
    pub removed: Vec<SkillRuntimePermission>,
    /// A capabilities implied by the added permissions.
    pub a_capabilities: Vec<CapabilityKind>,
    /// Whether any added permission is high-risk.
    pub high_risk: bool,
    /// The diff's stable display digest, carried verbatim.
    pub human_digest_32: [u8; 32],
}

impl PermissionPreview {
    /// Build the preview from a capability diff. Deterministic: the added /
    /// removed permission lists and the high-risk flag are decoded from the
    /// masks, and the display digest is carried from the diff verbatim.
    #[must_use]
    pub fn from_diff(diff: &CapabilityDiff) -> Self {
        let added = decode_mask(diff.added_mask_u64);
        let high_risk = added.iter().any(|p| is_high_risk(*p));
        Self {
            added,
            removed: decode_mask(diff.removed_mask_u64),
            a_capabilities: diff.a_capabilities.clone(),
            high_risk,
            human_digest_32: diff.human_digest_32,
        }
    }
}

/// Whether an action (use / dry-run escalation / install) may proceed given the
/// available capability diff.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PreviewGate {
    /// The action may proceed — a consistent diff is present to show.
    Allowed,
    /// The action is blocked — no diff, or an inconsistent (permission-hiding)
    /// diff, so neither use nor install may proceed.
    Blocked,
}

/// Gate a use / dry-run / install on the presence of a **consistent** capability
/// diff. A missing diff (`None`) or a diff that fails
/// [`CapabilityDiff::is_consistent`] (a hidden permission) blocks the action.
#[must_use]
pub fn gate_action(diff: Option<&CapabilityDiff>) -> PreviewGate {
    match diff {
        Some(d) if d.is_consistent() => PreviewGate::Allowed,
        _ => PreviewGate::Blocked,
    }
}

/// Sort key for the permission-diff-first card / candidate ordering (#301): a
/// high-risk preview returns `0` (sorts before), any other preview returns `1`.
/// Pairs with [`PermissionPreview::high_risk`] so a high-risk permission is
/// surfaced before any use / install CTA, regardless of popularity.
#[must_use]
pub const fn high_risk_first_key(preview: &PermissionPreview) -> u8 {
    if preview.high_risk { 0 } else { 1 }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn no_diff_blocks_use_and_install() {
        assert_eq!(gate_action(None), PreviewGate::Blocked);
    }

    #[test]
    fn inconsistent_diff_blocks() {
        let mut tampered =
            CapabilityDiff::new(SkillRuntimePermission::MemoryRead.mask_bit(), 0, Vec::new());
        tampered.added_mask_u64 |= SkillRuntimePermission::Wallet.mask_bit();
        assert!(!tampered.is_consistent());
        assert_eq!(gate_action(Some(&tampered)), PreviewGate::Blocked);
    }

    #[test]
    fn consistent_diff_allows() {
        let diff =
            CapabilityDiff::new(SkillRuntimePermission::MemoryRead.mask_bit(), 0, Vec::new());
        assert_eq!(gate_action(Some(&diff)), PreviewGate::Allowed);
    }

    #[test]
    fn a_capability_display() {
        let added = SkillRuntimePermission::MemoryRead.mask_bit()
            | SkillRuntimePermission::AnchorChunk.mask_bit();
        let diff = CapabilityDiff::new(added, 0, Vec::new());
        let preview = PermissionPreview::from_diff(&diff);
        assert_eq!(
            preview.a_capabilities,
            alloc::vec![CapabilityKind::ReadMemory, CapabilityKind::AnchorChunk]
        );
        assert!(!preview.high_risk);
    }

    #[test]
    fn high_risk_permission_flagged() {
        let diff = CapabilityDiff::new(SkillRuntimePermission::Wallet.mask_bit(), 0, Vec::new());
        let preview = PermissionPreview::from_diff(&diff);
        assert!(preview.high_risk);
        assert_eq!(preview.added, alloc::vec![SkillRuntimePermission::Wallet]);
    }

    #[test]
    fn high_risk_sorts_first() {
        let wallet = PermissionPreview::from_diff(&CapabilityDiff::new(
            SkillRuntimePermission::Wallet.mask_bit(),
            0,
            Vec::new(),
        ));
        let read = PermissionPreview::from_diff(&CapabilityDiff::new(
            SkillRuntimePermission::MemoryRead.mask_bit(),
            0,
            Vec::new(),
        ));
        assert_eq!(high_risk_first_key(&wallet), 0);
        assert_eq!(high_risk_first_key(&read), 1);
    }
}
