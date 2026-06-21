//! atom #288 · D.2.12 — Rust chain bindings (BCS arg builders) for the
//! `mnemos_skill_registry` Move package.
//!
//! The e-skill crate intentionally keeps no `serde`/`bcs` dependency on its
//! canonical value types, so this module carries a small MANUAL fixed-layout BCS
//! encoder whose byte layout is parity-pinned with the Move package (see
//! `tests/move_bcs_parity.rs` here and `tests/parity.move` there). No raw,
//! opaque transaction bytes are accepted at the public API; no commerce field is
//! present. Pure / offline: no network, no wallet, no chain action.
//!
//! Canonical layout (identical on both sides):
//! `u16`/`u64` little-endian · `u8` 1 byte · digest (32 B) as `vector<u8>`
//! (`uleb(32)=0x20 ++ 32 bytes`) · address / object id as 32 raw bytes ·
//! `Option<digest>` as `0x00` (None) or `0x01 ++ 0x20 ++ 32 bytes` (Some).

use mnemos_d_move::types::{ObjectId, SuiAddress};

use crate::install_state::InstallState;
use crate::manifest::SkillId;
use crate::package::SkillPackageDigest32;
use crate::provenance::ProvenanceNode;

// ---- manual BCS primitives (parity-pinned with Move `sui::bcs`) ----

fn put_uleb128(out: &mut Vec<u8>, mut value: u64) {
    loop {
        let byte = (value & 0x7f) as u8;
        value >>= 7;
        if value == 0 {
            out.push(byte);
            break;
        }
        out.push(byte | 0x80);
    }
}

fn put_u16_le(out: &mut Vec<u8>, v: u16) {
    out.extend_from_slice(&v.to_le_bytes());
}

fn put_u64_le(out: &mut Vec<u8>, v: u64) {
    out.extend_from_slice(&v.to_le_bytes());
}

fn put_address(out: &mut Vec<u8>, a: &[u8; 32]) {
    out.extend_from_slice(a);
}

fn put_digest_vec(out: &mut Vec<u8>, d: &[u8; 32]) {
    put_uleb128(out, 32);
    out.extend_from_slice(d);
}

fn put_option_digest(out: &mut Vec<u8>, opt: Option<&[u8; 32]>) {
    match opt {
        None => out.push(0x00),
        Some(d) => {
            out.push(0x01);
            put_digest_vec(out, d);
        }
    }
}

/// §4.3 `SkillChainAction` — the on-chain action a registry call performs.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
#[repr(u8)]
pub enum SkillChainAction {
    /// Publish a root skill package.
    Publish = 1,
    /// Fork a derivative from an existing parent.
    Fork = 2,
    /// Publish a new immutable digest linked to a prior one.
    UpdateMetadata = 3,
    /// Revoke an install receipt.
    Revoke = 4,
    /// Record a new install receipt.
    RecordInstall = 5,
}

impl SkillChainAction {
    /// The raw discriminant byte.
    #[inline]
    #[must_use]
    pub const fn as_u8(self) -> u8 {
        self as u8
    }

    /// Parse from the discriminant byte, rejecting unknown values.
    #[inline]
    #[must_use]
    pub const fn from_u8(byte: u8) -> Option<Self> {
        match byte {
            1 => Some(Self::Publish),
            2 => Some(Self::Fork),
            3 => Some(Self::UpdateMetadata),
            4 => Some(Self::Revoke),
            5 => Some(Self::RecordInstall),
            _ => None,
        }
    }
}

/// §4.3 `InstallReceiptId` — the Sui object id of an install receipt.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
#[repr(transparent)]
pub struct InstallReceiptId(
    /// The underlying 32-byte Sui object id.
    pub ObjectId,
);

impl InstallReceiptId {
    /// Wrap an [`ObjectId`].
    #[inline]
    #[must_use]
    pub const fn new(id: ObjectId) -> Self {
        Self(id)
    }

    /// The underlying object id.
    #[inline]
    #[must_use]
    pub const fn object_id(&self) -> &ObjectId {
        &self.0
    }
}

/// §4.3 `SkillRegistryArgs` — args for `publish_skill` / `fork_skill`.
///
/// BCS field order: `skill`, `package`, `author`, `parent`.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub struct SkillRegistryArgs {
    /// The skill id.
    pub skill: SkillId,
    /// The 32-byte package digest.
    pub package: SkillPackageDigest32,
    /// The author (must equal the on-chain signer).
    pub author: SuiAddress,
    /// The parent package digest, or `None` for a root publish.
    pub parent: Option<SkillPackageDigest32>,
}

impl SkillRegistryArgs {
    /// Encode to the canonical BCS byte layout (parity with `parity.move`).
    #[must_use]
    pub fn to_bcs(&self) -> Vec<u8> {
        let mut out = Vec::new();
        put_u16_le(&mut out, self.skill.0);
        put_digest_vec(&mut out, self.package.as_bytes());
        put_address(&mut out, self.author.as_bytes());
        put_option_digest(
            &mut out,
            self.parent.as_ref().map(SkillPackageDigest32::as_bytes),
        );
        out
    }
}

/// §4.3 `InstallReceiptArgs` — args for `record_install`.
///
/// BCS field order: `skill`, `package`, `user`, `local_install_digest`,
/// `capability_approval_hash`.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub struct InstallReceiptArgs {
    /// The skill id.
    pub skill: SkillId,
    /// The 32-byte package digest.
    pub package: SkillPackageDigest32,
    /// The installing user (must equal the on-chain signer).
    pub user: SuiAddress,
    /// The local install digest (dry-run trace hash); must be non-zero.
    pub local_install_digest_32: [u8; 32],
    /// The capability-approval hash; must be non-zero.
    pub capability_approval_hash_32: [u8; 32],
}

impl InstallReceiptArgs {
    /// Encode to the canonical BCS byte layout (parity with `parity.move`).
    #[must_use]
    pub fn to_bcs(&self) -> Vec<u8> {
        let mut out = Vec::new();
        put_u16_le(&mut out, self.skill.0);
        put_digest_vec(&mut out, self.package.as_bytes());
        put_address(&mut out, self.user.as_bytes());
        put_digest_vec(&mut out, &self.local_install_digest_32);
        put_digest_vec(&mut out, &self.capability_approval_hash_32);
        out
    }
}

/// §4.3 `InstallReceiptView` — a decoded on-chain install receipt.
///
/// BCS field order: `id`, `state`, `user`, `package`, `recorded_epoch`.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub struct InstallReceiptView {
    /// The receipt object id.
    pub id: InstallReceiptId,
    /// The install state.
    pub state: InstallState,
    /// The owning user.
    pub user: SuiAddress,
    /// The 32-byte package digest.
    pub package: SkillPackageDigest32,
    /// The epoch the receipt was recorded.
    pub recorded_epoch_u64: u64,
}

impl InstallReceiptView {
    /// Encode to the canonical BCS byte layout (parity with `parity.move`).
    #[must_use]
    pub fn to_bcs(&self) -> Vec<u8> {
        let mut out = Vec::new();
        put_address(&mut out, self.id.0.as_bytes());
        out.push(self.state.as_u8());
        put_address(&mut out, self.user.as_bytes());
        put_digest_vec(&mut out, self.package.as_bytes());
        put_u64_le(&mut out, self.recorded_epoch_u64);
        out
    }
}

/// Encode a §4.1 [`ProvenanceNode`] to the canonical BCS byte layout (parity
/// with `parity.move`). BCS field order: `skill`, `package`, `parent`,
/// `author`, `depth`.
#[must_use]
pub fn encode_provenance_node_bcs(node: &ProvenanceNode) -> Vec<u8> {
    let mut out = Vec::new();
    put_u16_le(&mut out, node.skill.0);
    put_digest_vec(&mut out, node.package.as_bytes());
    put_option_digest(
        &mut out,
        node.parent.as_ref().map(SkillPackageDigest32::as_bytes),
    );
    put_address(&mut out, node.author.as_bytes());
    put_u16_le(&mut out, node.provenance_depth_u16);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn raw32(b: u8) -> [u8; 32] {
        [b; 32]
    }

    #[test]
    fn registry_args_none_layout() {
        let args = SkillRegistryArgs {
            skill: SkillId(7),
            package: SkillPackageDigest32::new(raw32(0x11)),
            author: SuiAddress::new(raw32(0xA2)),
            parent: None,
        };
        let b = args.to_bcs();
        assert_eq!(b.len(), 68);
        assert_eq!(&b[0..2], &[0x07, 0x00]);
        assert_eq!(b[2], 0x20);
        assert_eq!(&b[3..35], &raw32(0x11));
        assert_eq!(&b[35..67], &raw32(0xA2));
        assert_eq!(b[67], 0x00);
    }

    #[test]
    fn registry_args_some_layout() {
        let args = SkillRegistryArgs {
            skill: SkillId(8),
            package: SkillPackageDigest32::new(raw32(0x22)),
            author: SuiAddress::new(raw32(0xA2)),
            parent: Some(SkillPackageDigest32::new(raw32(0x11))),
        };
        let b = args.to_bcs();
        assert_eq!(b.len(), 101);
        assert_eq!(b[67], 0x01);
        assert_eq!(b[68], 0x20);
        assert_eq!(&b[69..101], &raw32(0x11));
    }

    #[test]
    fn install_receipt_args_layout() {
        let args = InstallReceiptArgs {
            skill: SkillId(7),
            package: SkillPackageDigest32::new(raw32(0x11)),
            user: SuiAddress::new(raw32(0xC4)),
            local_install_digest_32: raw32(0x22),
            capability_approval_hash_32: raw32(0x33),
        };
        assert_eq!(args.to_bcs().len(), 133);
    }

    #[test]
    fn install_receipt_view_layout() {
        let view = InstallReceiptView {
            id: InstallReceiptId::new(ObjectId::new(raw32(0xE5))),
            state: InstallState::Installed,
            user: SuiAddress::new(raw32(0xC4)),
            package: SkillPackageDigest32::new(raw32(0x11)),
            recorded_epoch_u64: 42,
        };
        let b = view.to_bcs();
        assert_eq!(b.len(), 106);
        assert_eq!(&b[0..32], &raw32(0xE5));
        assert_eq!(b[32], 3);
    }

    #[test]
    fn skill_chain_action_roundtrip() {
        let mut v = 1u8;
        while v <= 5 {
            let a = SkillChainAction::from_u8(v);
            assert!(a.is_some());
            if let Some(act) = a {
                assert_eq!(act.as_u8(), v);
            }
            v += 1;
        }
        assert!(SkillChainAction::from_u8(0).is_none());
        assert!(SkillChainAction::from_u8(6).is_none());
    }
}
