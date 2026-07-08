//! `mnemos-e-skill::capability_diff` — the permission
//! diff shown before a skill is used or installed.
//!
//! ## Overview
//!
//! - [`SkillRuntimePermission`] — 10-variant `#[repr(u8)]` runtime
//!   permission label `{FileRead=1, FileWrite=2, Network=3, Wallet=4,
//!   Chain=5, Secret=6, MemoryRead=7, MemoryWrite=8, AnchorChunk=9,
//!   ToolInvoke=10}`. This is a Stage D **runtime permission space** that
//!   the core [`CapabilityKind`] cannot express (file / network / wallet /
//!   chain / secret / tool). The three memory/anchor permissions
//!   (`MemoryRead`/`MemoryWrite`/`AnchorChunk`) map onto the core
//!   `CapabilityKind` (`ReadMemory`/`WriteMemory`/`AnchorChunk`) — that is
//!   the only place Stage D touches the core capability surface.
//! - [`CapabilityDiff`] — added/removed permission masks + the mapped
//!   capabilities + declared tool ids + a stable `human_digest_32`. The
//!   masks are over [`SkillRuntimePermission`] (bit `n-1` = permission with
//!   discriminant `n`). A diff is only honest if its `human_digest_32`
//!   recomputes ([`CapabilityDiff::is_consistent`]) — a permission silently
//!   present in a mask but absent from the displayed digest is a **hidden
//!   permission** and is rejected.
//!
//! No install plan may proceed without this diff digest.
//! No field here grants a live wallet / secret action — these are *labels*
//! only; the WASM-sandbox capability token is what gates execution.

#![deny(missing_docs)]

extern crate alloc;

use alloc::vec::Vec;

use mnemos_f_seal::capability::CapabilityKind;
use mnemos_m_agent::tool_schema::ToolId;

use crate::package::blake2b_256;

/// Domain tag for the [`CapabilityDiff`] human digest.
pub(crate) const DOMAIN_CAP_DIFF: &[u8] = b"mnemos.d.capability_diff.v1";

// ===========================================================================
// 1. SkillRuntimePermission — 10-variant runtime permission label
// ===========================================================================

/// Stage D runtime permission. `#[repr(u8)]` 1-byte discriminant.
/// The 10-variant set is fixed (no `#[non_exhaustive]`).
/// Discriminants `1..=10` map to bit `n-1` in a [`CapabilityDiff`] mask.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
#[repr(u8)]
pub enum SkillRuntimePermission {
    /// Read a file path (scoped by the sandbox capability token).
    FileRead = 1,
    /// Write a file path (scoped).
    FileWrite = 2,
    /// Network egress (scoped; denied by default in the WASM sandbox).
    Network = 3,
    /// Wallet access (label only here — no live wallet).
    Wallet = 4,
    /// Chain action (label only — dry-run dominated).
    Chain = 5,
    /// Secret access (label only — never exported).
    Secret = 6,
    /// Read a memory chunk — maps to A [`CapabilityKind::ReadMemory`].
    MemoryRead = 7,
    /// Write a memory chunk — maps to A [`CapabilityKind::WriteMemory`].
    MemoryWrite = 8,
    /// Anchor a chunk envelope — maps to A [`CapabilityKind::AnchorChunk`].
    AnchorChunk = 9,
    /// Invoke a declared tool id.
    ToolInvoke = 10,
}

impl SkillRuntimePermission {
    /// Bit position of this permission in a [`CapabilityDiff`] mask:
    /// `1u64 << (discriminant - 1)`. `FileRead` ⇒ bit 0, `ToolInvoke` ⇒ bit 9.
    #[inline]
    #[must_use]
    pub const fn mask_bit(&self) -> u64 {
        1u64 << ((*self as u8) - 1)
    }

    /// The A [`CapabilityKind`] this permission maps to, if it is a
    /// memory/anchor permission; `None` for file/network/wallet/chain/
    /// secret/tool permissions (which have no A capability projection).
    #[inline]
    #[must_use]
    pub fn a_capability(&self) -> Option<CapabilityKind> {
        match self {
            Self::MemoryRead => Some(CapabilityKind::ReadMemory),
            Self::MemoryWrite => Some(CapabilityKind::WriteMemory),
            Self::AnchorChunk => Some(CapabilityKind::AnchorChunk),
            _ => None,
        }
    }
}

/// Fixed order of the memory/anchor permissions used to project an
/// `added_mask` onto its A capabilities. The projection order is stable so
/// the `a_capabilities` vector has exactly one canonical shape per mask.
const MAPPED_PERMISSIONS: [SkillRuntimePermission; 3] = [
    SkillRuntimePermission::MemoryRead,
    SkillRuntimePermission::MemoryWrite,
    SkillRuntimePermission::AnchorChunk,
];

/// Project an `added_mask` onto the A [`CapabilityKind`] list it implies,
/// in [`MAPPED_PERMISSIONS`] order. This is the canonical
/// `a_capabilities` for a given mask; any other vector is inconsistent.
#[must_use]
pub fn a_capabilities_for_mask(added_mask_u64: u64) -> Vec<CapabilityKind> {
    let mut out = Vec::new();
    for perm in MAPPED_PERMISSIONS {
        if added_mask_u64 & perm.mask_bit() != 0 {
            if let Some(kind) = perm.a_capability() {
                out.push(kind);
            }
        }
    }
    out
}

// ===========================================================================
// 2. CapabilityDiff — added/removed masks + mapped A caps + digest
// ===========================================================================

/// Permission diff shown before use/install. The masks are over
/// [`SkillRuntimePermission`]; `a_capabilities` is the canonical A-capability
/// projection of `added_mask_u64`; `tool_ids` are the declared tools; and
/// `human_digest_32` is a stable display digest over all four. Construct via
/// [`Self::new`] so the digest and the A-capability projection are always
/// consistent; [`Self::is_consistent`] re-derives both for the verifier.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CapabilityDiff {
    /// Bitmask of permissions this skill version *adds*.
    pub added_mask_u64: u64,
    /// Bitmask of permissions this skill version *removes*.
    pub removed_mask_u64: u64,
    /// A capabilities implied by `added_mask_u64`, in canonical order.
    pub a_capabilities: Vec<CapabilityKind>,
    /// Declared tool ids (cross-checked against the manifest by the verifier).
    pub tool_ids: Vec<ToolId>,
    /// Stable display digest over the masks, A capabilities, and tool ids.
    pub human_digest_32: [u8; 32],
}

impl CapabilityDiff {
    /// Build a consistent diff: the A-capability projection and the human
    /// digest are derived from the inputs, so the result always satisfies
    /// [`Self::is_consistent`].
    #[must_use]
    pub fn new(added_mask_u64: u64, removed_mask_u64: u64, tool_ids: Vec<ToolId>) -> Self {
        let a_capabilities = a_capabilities_for_mask(added_mask_u64);
        let human_digest_32 =
            Self::compute_digest(added_mask_u64, removed_mask_u64, &a_capabilities, &tool_ids);
        Self {
            added_mask_u64,
            removed_mask_u64,
            a_capabilities,
            tool_ids,
            human_digest_32,
        }
    }

    /// Borrow the stable display digest.
    #[inline]
    #[must_use]
    pub fn human_digest_32(&self) -> &[u8; 32] {
        &self.human_digest_32
    }

    /// Recompute the display digest from the current fields.
    #[must_use]
    fn compute_digest(
        added_mask_u64: u64,
        removed_mask_u64: u64,
        a_capabilities: &[CapabilityKind],
        tool_ids: &[ToolId],
    ) -> [u8; 32] {
        let mut buf: Vec<u8> = Vec::new();
        buf.extend_from_slice(&added_mask_u64.to_le_bytes());
        buf.extend_from_slice(&removed_mask_u64.to_le_bytes());
        buf.extend_from_slice(&(a_capabilities.len() as u32).to_le_bytes());
        for cap in a_capabilities {
            buf.push(*cap as u8);
        }
        buf.extend_from_slice(&(tool_ids.len() as u32).to_le_bytes());
        for tool in tool_ids {
            buf.extend_from_slice(&tool.0.to_le_bytes());
        }
        blake2b_256(&[DOMAIN_CAP_DIFF, &buf])
    }

    /// `true` iff (a) the `a_capabilities` vector is exactly the canonical
    /// projection of `added_mask_u64`, AND (b) `human_digest_32` recomputes.
    /// A diff that fails either check is hiding a permission and is rejected.
    #[must_use]
    pub fn is_consistent(&self) -> bool {
        if self.a_capabilities != a_capabilities_for_mask(self.added_mask_u64) {
            return false;
        }
        let expected = Self::compute_digest(
            self.added_mask_u64,
            self.removed_mask_u64,
            &self.a_capabilities,
            &self.tool_ids,
        );
        expected == self.human_digest_32
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn permission_mask_bits_are_one_indexed() {
        assert_eq!(SkillRuntimePermission::FileRead.mask_bit(), 1 << 0);
        assert_eq!(SkillRuntimePermission::ToolInvoke.mask_bit(), 1 << 9);
        assert_eq!(SkillRuntimePermission::MemoryRead as u8, 7);
    }

    #[test]
    fn a_capability_mapping_only_for_memory_anchor() {
        assert_eq!(
            SkillRuntimePermission::MemoryRead.a_capability(),
            Some(CapabilityKind::ReadMemory)
        );
        assert_eq!(
            SkillRuntimePermission::MemoryWrite.a_capability(),
            Some(CapabilityKind::WriteMemory)
        );
        assert_eq!(
            SkillRuntimePermission::AnchorChunk.a_capability(),
            Some(CapabilityKind::AnchorChunk)
        );
        assert_eq!(SkillRuntimePermission::FileRead.a_capability(), None);
        assert_eq!(SkillRuntimePermission::Wallet.a_capability(), None);
        assert_eq!(SkillRuntimePermission::Secret.a_capability(), None);
    }

    #[test]
    fn added_removed_mask_and_a_capabilities_project() {
        // Add FileRead + MemoryRead + AnchorChunk; remove Network.
        let added = SkillRuntimePermission::FileRead.mask_bit()
            | SkillRuntimePermission::MemoryRead.mask_bit()
            | SkillRuntimePermission::AnchorChunk.mask_bit();
        let removed = SkillRuntimePermission::Network.mask_bit();
        let diff = CapabilityDiff::new(added, removed, vec![ToolId(1)]);
        assert_eq!(diff.added_mask_u64, added);
        assert_eq!(diff.removed_mask_u64, removed);
        // FileRead has no A projection; MemoryRead + AnchorChunk do, in order.
        assert_eq!(
            diff.a_capabilities,
            vec![CapabilityKind::ReadMemory, CapabilityKind::AnchorChunk]
        );
        assert!(diff.is_consistent());
    }

    #[test]
    fn display_digest_is_stable() {
        let added = SkillRuntimePermission::MemoryWrite.mask_bit();
        let a = CapabilityDiff::new(added, 0, vec![ToolId(2)]);
        let b = CapabilityDiff::new(added, 0, vec![ToolId(2)]);
        assert_eq!(a.human_digest_32(), b.human_digest_32());
        // A different mask moves the digest.
        let c = CapabilityDiff::new(
            added | SkillRuntimePermission::Wallet.mask_bit(),
            0,
            vec![ToolId(2)],
        );
        assert_ne!(a.human_digest_32(), c.human_digest_32());
    }

    #[test]
    fn hidden_permission_is_rejected() {
        // Honest diff first.
        let mut tampered =
            CapabilityDiff::new(SkillRuntimePermission::MemoryRead.mask_bit(), 0, vec![]);
        assert!(tampered.is_consistent());

        // Smuggle a Wallet permission into the mask WITHOUT updating the
        // displayed digest — a hidden permission. is_consistent must fail.
        tampered.added_mask_u64 |= SkillRuntimePermission::Wallet.mask_bit();
        assert!(!tampered.is_consistent(), "hidden permission must reject");

        // Smuggle a stale A capability that the mask does not justify.
        let mut stale = CapabilityDiff::new(0, 0, vec![]);
        stale.a_capabilities.push(CapabilityKind::WriteMemory);
        assert!(
            !stale.is_consistent(),
            "unjustified A capability must reject"
        );
    }
}
