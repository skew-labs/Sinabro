//! Starter skill pack manifest.
//!
//! ## Pack model
//!
//! - [`SkillStarterPack`] — `{ bundle_hash_32, packages, compatibility,
//!   pack_eval_hash_32 }`. A starter pack groups already-verified skill
//!   packages (by task / domain / toolchain / security floor / compatibility)
//!   into one curated bundle so initial traction comes from useful **default
//!   packs, not a paid marketplace**. The pack is content-addressed:
//!   `bundle_hash_32` folds the member package digests and `pack_eval_hash_32`
//!   folds their eval hashes, both order-independently, so the same member set
//!   always yields the same pack digest (the pack manifest digest is stable).
//!
//! ## Reuse
//!
//! A pack never re-mints a package or a compatibility model: members are
//! [`crate::package::SkillPackageDigest32`] and the pack-level
//! [`crate::compat::CompatibilityDecision`] is the **worst-case
//! fold** of the members' decisions — one unsafe member blocks the whole pack
//! (one incompatible member blocks the pack). Building a pack that
//! references a digest not present in the verified member set is rejected
//! ([`StarterPackError::MissingSkill`]) — a pack can never name a skill that was
//! not verified.
//!
//! ## No-commerce + offline boundary
//!
//! A starter pack carries only content digests and a compatibility decision —
//! no price, checkout, revenue, or payment field. Building a
//! pack is a pure, offline fold: no network, wallet, secret, or chain action.

#![deny(missing_docs)]

extern crate alloc;

use alloc::vec::Vec;

use crate::compat::CompatibilityDecision;
use crate::package::{SkillPackageDigest32, blake2b_256};

/// Domain tag for the starter-pack bundle digest (member package digests).
const DOMAIN_STARTER_PACK_BUNDLE: &[u8] = b"mnemos.d.starter_pack_bundle.v1";
/// Domain tag for the starter-pack eval digest (member eval hashes).
const DOMAIN_STARTER_PACK_EVAL: &[u8] = b"mnemos.d.starter_pack_eval.v1";

// ===========================================================================
// 1. StarterPackMember — one verified candidate for a pack
// ===========================================================================

/// A verified skill package eligible for a starter pack. Carries the member's
/// content digest, its host-compatibility decision, and the 32-byte
/// hash of its eval score. These are the only inputs a pack needs; a
/// member is always a package that already passed the catalog surface.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub struct StarterPackMember {
    /// Content address of the member package.
    pub package: SkillPackageDigest32,
    /// The member's compatibility decision against the target host.
    pub compatibility: CompatibilityDecision,
    /// 32-byte hash of the member's eval score. Folded into the pack
    /// eval digest so two packs with different member evals never collide.
    pub eval_hash_32: [u8; 32],
}

// ===========================================================================
// 2. StarterPackError — why a pack could not be built
// ===========================================================================

/// Why [`SkillStarterPack::build`] rejected a pack request.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum StarterPackError {
    /// A requested package digest is not present in the verified member set —
    /// a pack can never name an unverified / missing skill.
    MissingSkill,
    /// A pack must contain at least one member.
    Empty,
}

impl StarterPackError {
    /// Stable, leak-free class label (mirrors the crate `class_label` idiom).
    #[inline]
    #[must_use]
    pub const fn class_label(&self) -> &'static str {
        match self {
            Self::MissingSkill => "starter_pack.missing_skill",
            Self::Empty => "starter_pack.empty",
        }
    }
}

// ===========================================================================
// 3. compatibility worst-case fold
// ===========================================================================

/// Rank a [`CompatibilityDecision`] for the worst-case fold: a higher rank is
/// "worse" and dominates the pack decision. `Incompatible` is fatal (blocks
/// the pack); `Unknown` (cannot confirm safe) dominates `Warn`; `Compatible`
/// is the floor.
#[inline]
const fn severity(d: CompatibilityDecision) -> u8 {
    match d {
        CompatibilityDecision::Compatible => 0,
        CompatibilityDecision::Warn => 1,
        CompatibilityDecision::Unknown => 2,
        CompatibilityDecision::Incompatible => 3,
    }
}

/// Fold member compatibility decisions into the pack decision: the most severe
/// member wins. An empty slice folds to [`CompatibilityDecision::Unknown`] (no
/// evidence), but [`SkillStarterPack::build`] rejects empty packs before this.
#[must_use]
fn fold_compatibility(members: &[StarterPackMember]) -> CompatibilityDecision {
    let mut worst = CompatibilityDecision::Compatible;
    let mut empty = true;
    for m in members {
        empty = false;
        if severity(m.compatibility) > severity(worst) {
            worst = m.compatibility;
        }
    }
    if empty {
        CompatibilityDecision::Unknown
    } else {
        worst
    }
}

// ===========================================================================
// 4. SkillStarterPack — curated bundle
// ===========================================================================

/// A curated starter pack. Built by [`Self::build`] from a verified
/// member set; the member package digests are stored sorted so the bundle is
/// order-independent, and the pack compatibility is the worst-case fold of its
/// members.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SkillStarterPack {
    /// Content digest over the sorted member package digests.
    pub bundle_hash_32: [u8; 32],
    /// The member package digests, sorted (order-independent identity).
    pub packages: Vec<SkillPackageDigest32>,
    /// Worst-case compatibility fold over the members.
    pub compatibility: CompatibilityDecision,
    /// Content digest over the sorted member eval hashes.
    pub pack_eval_hash_32: [u8; 32],
}

impl SkillStarterPack {
    /// Build a starter pack from a verified member set and the requested
    /// package digests. Every requested digest MUST appear in `available`
    /// (else [`StarterPackError::MissingSkill`]); the request must be non-empty
    /// (else [`StarterPackError::Empty`]). The resolved members are sorted by
    /// package digest, so the resulting `bundle_hash_32` / `pack_eval_hash_32`
    /// are independent of the request order (digest stable).
    pub fn build(
        available: &[StarterPackMember],
        requested: &[SkillPackageDigest32],
    ) -> Result<Self, StarterPackError> {
        if requested.is_empty() {
            return Err(StarterPackError::Empty);
        }
        let mut resolved: Vec<StarterPackMember> = Vec::with_capacity(requested.len());
        for want in requested {
            match available.iter().find(|m| &m.package == want) {
                Some(m) => resolved.push(*m),
                None => return Err(StarterPackError::MissingSkill),
            }
        }
        resolved.sort_by(|a, b| a.package.as_bytes().cmp(b.package.as_bytes()));

        let compatibility = fold_compatibility(&resolved);
        let packages: Vec<SkillPackageDigest32> = resolved.iter().map(|m| m.package).collect();

        let count = (resolved.len() as u64).to_le_bytes();
        let mut bundle_buf: Vec<u8> = Vec::with_capacity(resolved.len() * 32);
        let mut eval_buf: Vec<u8> = Vec::with_capacity(resolved.len() * 32);
        for m in &resolved {
            bundle_buf.extend_from_slice(m.package.as_bytes());
            eval_buf.extend_from_slice(&m.eval_hash_32);
        }
        let bundle_hash_32 = blake2b_256(&[DOMAIN_STARTER_PACK_BUNDLE, &count, &bundle_buf]);
        let pack_eval_hash_32 = blake2b_256(&[DOMAIN_STARTER_PACK_EVAL, &count, &eval_buf]);

        Ok(Self {
            bundle_hash_32,
            packages,
            compatibility,
            pack_eval_hash_32,
        })
    }

    /// `true` iff the pack is installable as a whole — i.e. no member made it
    /// [`CompatibilityDecision::Incompatible`]. A `Warn`/`Unknown` pack is
    /// still installable (the operator is warned), but one incompatible member
    /// blocks the pack.
    #[inline]
    #[must_use]
    pub const fn is_installable(&self) -> bool {
        !matches!(self.compatibility, CompatibilityDecision::Incompatible)
    }

    /// Number of member packages.
    #[inline]
    #[must_use]
    pub fn len(&self) -> usize {
        self.packages.len()
    }

    /// `true` iff the pack has no members (never true for a built pack).
    #[inline]
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.packages.is_empty()
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    fn member(tag: u8, compat: CompatibilityDecision) -> StarterPackMember {
        StarterPackMember {
            package: SkillPackageDigest32::new([tag; 32]),
            compatibility: compat,
            eval_hash_32: [tag ^ 0x5A; 32],
        }
    }

    fn available() -> Vec<StarterPackMember> {
        alloc::vec![
            member(0x51, CompatibilityDecision::Compatible), // "sui"
            member(0x52, CompatibilityDecision::Compatible), // "sui"
            member(0x53, CompatibilityDecision::Compatible), // "solana"
            member(0x54, CompatibilityDecision::Warn),       // "solana"
            member(0x55, CompatibilityDecision::Compatible), // "rust"
            member(0x56, CompatibilityDecision::Incompatible),
        ]
    }

    #[test]
    fn sui_pack_builds_compatible() {
        let pack = SkillStarterPack::build(
            &available(),
            &[
                SkillPackageDigest32::new([0x51; 32]),
                SkillPackageDigest32::new([0x52; 32]),
            ],
        )
        .expect("sui pack must build");
        assert_eq!(pack.len(), 2);
        assert_eq!(pack.compatibility, CompatibilityDecision::Compatible);
        assert!(pack.is_installable());
    }

    #[test]
    fn solana_pack_warn_still_installable() {
        // A Warn member keeps the pack installable but warns.
        let pack = SkillStarterPack::build(
            &available(),
            &[
                SkillPackageDigest32::new([0x53; 32]),
                SkillPackageDigest32::new([0x54; 32]),
            ],
        )
        .expect("solana pack must build");
        assert_eq!(pack.compatibility, CompatibilityDecision::Warn);
        assert!(pack.is_installable());
    }

    #[test]
    fn rust_pack_single_member() {
        let pack = SkillStarterPack::build(&available(), &[SkillPackageDigest32::new([0x55; 32])])
            .expect("rust pack must build");
        assert_eq!(pack.len(), 1);
        assert_eq!(pack.compatibility, CompatibilityDecision::Compatible);
    }

    #[test]
    fn missing_skill_rejected() {
        let err = SkillStarterPack::build(
            &available(),
            &[SkillPackageDigest32::new([0xAA; 32])], // not in member set
        )
        .expect_err("missing skill must reject");
        assert_eq!(err, StarterPackError::MissingSkill);
        assert_eq!(err.class_label(), "starter_pack.missing_skill");
    }

    #[test]
    fn incompatible_member_blocks_pack() {
        let pack = SkillStarterPack::build(
            &available(),
            &[
                SkillPackageDigest32::new([0x55; 32]), // compatible
                SkillPackageDigest32::new([0x56; 32]), // incompatible
            ],
        )
        .expect("pack builds but is blocked");
        assert_eq!(pack.compatibility, CompatibilityDecision::Incompatible);
        assert!(
            !pack.is_installable(),
            "one incompatible member blocks the pack"
        );
    }

    #[test]
    fn empty_request_rejected() {
        let err = SkillStarterPack::build(&available(), &[]).expect_err("empty must reject");
        assert_eq!(err, StarterPackError::Empty);
    }

    #[test]
    fn pack_digest_is_order_independent_and_stable() {
        let a = SkillStarterPack::build(
            &available(),
            &[
                SkillPackageDigest32::new([0x51; 32]),
                SkillPackageDigest32::new([0x53; 32]),
            ],
        )
        .expect("a");
        let b = SkillStarterPack::build(
            &available(),
            &[
                SkillPackageDigest32::new([0x53; 32]),
                SkillPackageDigest32::new([0x51; 32]),
            ],
        )
        .expect("b");
        // Same member set, different request order -> identical pack digest.
        assert_eq!(a.bundle_hash_32, b.bundle_hash_32);
        assert_eq!(a.pack_eval_hash_32, b.pack_eval_hash_32);
        assert_ne!(a.bundle_hash_32, [0u8; 32]);
    }
}
