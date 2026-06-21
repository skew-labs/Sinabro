//! `mnemos-e-skill::wasm_tier2::grant` — atom #258 · D.1.2 — WASM capability
//! grants.
//!
//! ## Canonical OUT (§4.2)
//!
//! - [`WasmCapabilityGrant`] — `{skill, owner, permission, expires_epoch_u64}`.
//!   A grant is **owner-scoped, skill-scoped, permission-scoped, and
//!   epoch-bounded**: a request that does not match an unexpired grant on all
//!   four axes denies with
//!   [`crate::wasm_tier2::WasmSandboxDecision::CapabilityMissing`]
//!   (deny-by-default — a missing grant denies).
//! - [`ScopedSkillCapabilityToken`] — the richer package-bound token with a
//!   permission bitmask, path / network scope hashes, an expiry epoch, and a
//!   revocation hash.
//!
//! ## Secret-custody boundary (no-debug / no-clone of a secret)
//!
//! A grant carries **no key material and no secret bytes** — only a [`SkillId`],
//! the owner [`SuiAddress`], a single [`SkillRuntimePermission`] *label*, and an
//! expiry epoch. There is no `SealedKeypair` / `ScopedSecretKey` field to clone
//! or to leak through `Debug`. The `Wallet` / `Secret` / `Chain` permissions are
//! deny-labels with no A-[`CapabilityKind`] projection ([`Self::a_capability`]
//! returns `None` for them), so a grant for one of them confers no memory
//! capability and the sandbox denies its execution. This module performs no
//! live action: it is a pure checking surface (no live network, no wallet
//! signing, no chain write).

#![deny(missing_docs)]

use mnemos_d_move::types::SuiAddress;
use mnemos_f_seal::capability::CapabilityKind;

use crate::capability_diff::SkillRuntimePermission;
use crate::manifest::SkillId;
use crate::package::SkillPackageDigest32;
use crate::wasm_tier2::WasmSandboxDecision;

// ===========================================================================
// 1. WasmCapabilityGrant — §4.2 single-permission, four-axis-scoped grant
// ===========================================================================

/// §4.2 single-permission capability grant. Owner-scoped, skill-scoped,
/// permission-scoped, epoch-bounded. Carries no key material — see the module
/// secret-custody note.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct WasmCapabilityGrant {
    /// The skill this grant is bound to.
    pub skill: SkillId,
    /// The owner address that authorized the grant.
    pub owner: SuiAddress,
    /// The single runtime permission label this grant covers.
    pub permission: SkillRuntimePermission,
    /// The epoch after which the grant is no longer valid (`now > expires`
    /// denies).
    pub expires_epoch_u64: u64,
}

impl WasmCapabilityGrant {
    /// Construct a grant from its four scoping axes.
    #[inline]
    #[must_use]
    pub const fn new(
        skill: SkillId,
        owner: SuiAddress,
        permission: SkillRuntimePermission,
        expires_epoch_u64: u64,
    ) -> Self {
        Self {
            skill,
            owner,
            permission,
            expires_epoch_u64,
        }
    }

    /// The A [`CapabilityKind`] this grant's permission projects to, if any.
    /// Memory/anchor permissions map to an A capability; file / network /
    /// wallet / chain / secret / tool permissions project to `None` — a grant
    /// for them confers no A capability and the sandbox denies their execution.
    #[inline]
    #[must_use]
    pub fn a_capability(&self) -> Option<CapabilityKind> {
        self.permission.a_capability()
    }

    /// Deny-by-default authorization. Returns
    /// [`WasmSandboxDecision::Allow`] **only** when the request matches this
    /// grant on `skill`, `owner`, and `permission` AND the grant has not
    /// expired at `now_epoch_u64`. Any mismatch or expiry returns
    /// [`WasmSandboxDecision::CapabilityMissing`].
    #[must_use]
    pub fn authorize(
        &self,
        skill: SkillId,
        owner: SuiAddress,
        permission: SkillRuntimePermission,
        now_epoch_u64: u64,
    ) -> WasmSandboxDecision {
        if self.skill != skill || self.owner != owner || self.permission != permission {
            return WasmSandboxDecision::CapabilityMissing;
        }
        if now_epoch_u64 > self.expires_epoch_u64 {
            return WasmSandboxDecision::CapabilityMissing;
        }
        WasmSandboxDecision::Allow
    }
}

/// Deny-by-default authorization over a set of grants: returns
/// [`WasmSandboxDecision::Allow`] iff *any* grant authorizes the request, else
/// [`WasmSandboxDecision::CapabilityMissing`]. An empty grant set always
/// denies.
#[must_use]
pub fn authorize_with_grants(
    grants: &[WasmCapabilityGrant],
    skill: SkillId,
    owner: SuiAddress,
    permission: SkillRuntimePermission,
    now_epoch_u64: u64,
) -> WasmSandboxDecision {
    if grants.iter().any(|g| {
        g.authorize(skill, owner, permission, now_epoch_u64)
            .is_allow()
    }) {
        WasmSandboxDecision::Allow
    } else {
        WasmSandboxDecision::CapabilityMissing
    }
}

// ===========================================================================
// 2. ScopedSkillCapabilityToken — §4.2 package-bound permission-mask token
// ===========================================================================

/// §4.2 package-bound capability token. Binds a permission bitmask (over
/// [`SkillRuntimePermission`]) to a package digest, path / network scope
/// hashes, an expiry epoch, and a revocation hash. Like the grant, it carries
/// no key material.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ScopedSkillCapabilityToken {
    /// The skill this token is bound to.
    pub skill: SkillId,
    /// The exact package digest this token is scoped to.
    pub package: SkillPackageDigest32,
    /// Bitmask of granted permissions (bit `n-1` = permission discriminant `n`).
    pub permission_mask_u64: u64,
    /// Hash committing the declared filesystem path scope.
    pub path_scope_hash_32: [u8; 32],
    /// Hash committing the declared network destination scope.
    pub network_scope_hash_32: [u8; 32],
    /// Epoch after which the token is no longer valid.
    pub expires_epoch_u64: u64,
    /// Hash that, once published, revokes this token.
    pub revocation_hash_32: [u8; 32],
}

impl ScopedSkillCapabilityToken {
    /// `true` iff `permission`'s bit is set in the mask. A display/preview
    /// helper — it does **not** account for expiry or revocation.
    #[inline]
    #[must_use]
    pub const fn grants_permission(&self, permission: SkillRuntimePermission) -> bool {
        self.permission_mask_u64 & permission.mask_bit() != 0
    }

    /// Deny-by-default execution check. Returns [`WasmSandboxDecision::Allow`]
    /// only when the token is not `revoked`, not expired at `now_epoch_u64`,
    /// and the permission bit is set. A revoked token returns
    /// [`WasmSandboxDecision::Deny`] (a revoked artifact must never execute);
    /// an expired token or an unset bit returns
    /// [`WasmSandboxDecision::CapabilityMissing`].
    #[must_use]
    pub fn permits(
        &self,
        permission: SkillRuntimePermission,
        now_epoch_u64: u64,
        revoked: bool,
    ) -> WasmSandboxDecision {
        if revoked {
            return WasmSandboxDecision::Deny;
        }
        if now_epoch_u64 > self.expires_epoch_u64 {
            return WasmSandboxDecision::CapabilityMissing;
        }
        if !self.grants_permission(permission) {
            return WasmSandboxDecision::CapabilityMissing;
        }
        WasmSandboxDecision::Allow
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn addr(b: u8) -> SuiAddress {
        SuiAddress::new([b; 32])
    }

    fn grant() -> WasmCapabilityGrant {
        WasmCapabilityGrant::new(
            SkillId(7),
            addr(0xAA),
            SkillRuntimePermission::MemoryRead,
            100,
        )
    }

    #[test]
    fn exact_match_unexpired_allows() {
        let g = grant();
        assert_eq!(
            g.authorize(
                SkillId(7),
                addr(0xAA),
                SkillRuntimePermission::MemoryRead,
                100
            ),
            WasmSandboxDecision::Allow
        );
    }

    #[test]
    fn owner_mismatch_denies() {
        let g = grant();
        assert_eq!(
            g.authorize(
                SkillId(7),
                addr(0xBB),
                SkillRuntimePermission::MemoryRead,
                50
            ),
            WasmSandboxDecision::CapabilityMissing
        );
    }

    #[test]
    fn wrong_skill_denies() {
        let g = grant();
        assert_eq!(
            g.authorize(
                SkillId(8),
                addr(0xAA),
                SkillRuntimePermission::MemoryRead,
                50
            ),
            WasmSandboxDecision::CapabilityMissing
        );
    }

    #[test]
    fn wrong_permission_denies() {
        let g = grant();
        assert_eq!(
            g.authorize(SkillId(7), addr(0xAA), SkillRuntimePermission::Network, 50),
            WasmSandboxDecision::CapabilityMissing
        );
    }

    #[test]
    fn expired_grant_denies() {
        let g = grant();
        assert_eq!(
            g.authorize(
                SkillId(7),
                addr(0xAA),
                SkillRuntimePermission::MemoryRead,
                101
            ),
            WasmSandboxDecision::CapabilityMissing
        );
    }

    #[test]
    fn memory_permission_maps_to_a_capability() {
        let g = grant();
        assert_eq!(g.a_capability(), Some(CapabilityKind::ReadMemory));
        // wallet/secret/chain permissions never project to an A capability.
        let w =
            WasmCapabilityGrant::new(SkillId(7), addr(0xAA), SkillRuntimePermission::Wallet, 100);
        assert_eq!(w.a_capability(), None);
        let s =
            WasmCapabilityGrant::new(SkillId(7), addr(0xAA), SkillRuntimePermission::Secret, 100);
        assert_eq!(s.a_capability(), None);
    }

    #[test]
    fn authorize_with_grants_denies_empty_set() {
        assert_eq!(
            authorize_with_grants(
                &[],
                SkillId(7),
                addr(0xAA),
                SkillRuntimePermission::MemoryRead,
                1
            ),
            WasmSandboxDecision::CapabilityMissing
        );
    }

    #[test]
    fn authorize_with_grants_allows_on_match() {
        let grants = [
            WasmCapabilityGrant::new(SkillId(1), addr(1), SkillRuntimePermission::FileRead, 10),
            grant(),
        ];
        assert_eq!(
            authorize_with_grants(
                &grants,
                SkillId(7),
                addr(0xAA),
                SkillRuntimePermission::MemoryRead,
                100
            ),
            WasmSandboxDecision::Allow
        );
    }

    fn token() -> ScopedSkillCapabilityToken {
        ScopedSkillCapabilityToken {
            skill: SkillId(3),
            package: SkillPackageDigest32::new([9u8; 32]),
            permission_mask_u64: SkillRuntimePermission::MemoryRead.mask_bit(),
            path_scope_hash_32: [0u8; 32],
            network_scope_hash_32: [0u8; 32],
            expires_epoch_u64: 100,
            revocation_hash_32: [0u8; 32],
        }
    }

    #[test]
    fn token_permits_set_bit_unexpired_unrevoked() {
        assert_eq!(
            token().permits(SkillRuntimePermission::MemoryRead, 100, false),
            WasmSandboxDecision::Allow
        );
    }

    #[test]
    fn token_revoked_denies() {
        assert_eq!(
            token().permits(SkillRuntimePermission::MemoryRead, 100, true),
            WasmSandboxDecision::Deny
        );
    }

    #[test]
    fn token_expired_or_unset_bit_missing() {
        assert_eq!(
            token().permits(SkillRuntimePermission::MemoryRead, 101, false),
            WasmSandboxDecision::CapabilityMissing
        );
        assert_eq!(
            token().permits(SkillRuntimePermission::Network, 100, false),
            WasmSandboxDecision::CapabilityMissing
        );
    }
}
