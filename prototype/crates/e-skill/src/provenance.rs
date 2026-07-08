//! Provenance node and ancestor-chain validation.
//!
//! ## Provenance model
//!
//! - [`ProvenanceNode`] — `{skill, package, parent, author,
//!   provenance_depth_u16}`. Every derivative has **exactly one** parent
//!   package digest, or it is a root (`parent == None`, `depth == 0`). The
//!   ancestor chain is **content-addressed** (parent is a
//!   [`SkillPackageDigest32`], never a name).
//!
//! Node-local validity ([`ProvenanceNode::is_well_formed`]):
//! - a fork (`depth > 0`) MUST carry a parent digest;
//! - a root (`depth == 0`) MUST NOT carry a parent;
//! - the author MUST be non-zero (missing author rejected);
//! - the parent digest MUST differ from the node's own package digest
//!   (a self-parent is a 1-cycle);
//! - `depth <= MAX_PROVENANCE_DEPTH` (bounds traversal cost).
//!
//! Chain validity ([`validate_ancestor_chain`]) is deterministic:
//! leaf-first linkage, strictly-decreasing depth, a unique
//! package digest at every level (cycle reject), and a well-formed root.

#![deny(missing_docs)]

extern crate alloc;

use alloc::collections::BTreeSet;
use alloc::vec::Vec;

use mnemos_d_move::types::SuiAddress;

use crate::manifest::SkillId;
use crate::package::{SkillPackageDigest32, blake2b_256};

/// Domain tag for the [`ProvenanceNode`] fold digest.
pub(crate) const DOMAIN_PROVENANCE: &[u8] = b"mnemos.d.provenance.v1";

/// Maximum legal provenance depth. Bounds ancestor-chain traversal so a
/// crafted package cannot force unbounded work.
pub const MAX_PROVENANCE_DEPTH: u16 = 1_024;

// ===========================================================================
// 1. ProvenanceNode — single-parent content-addressed lineage
// ===========================================================================

/// One node in a skill's provenance chain. `parent == None` marks a
/// root; otherwise the node is a fork of exactly one parent package digest.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub struct ProvenanceNode {
    /// Skill id this package belongs to.
    pub skill: SkillId,
    /// Content address of this package.
    pub package: SkillPackageDigest32,
    /// Parent package digest (single parent), or `None` for a root.
    pub parent: Option<SkillPackageDigest32>,
    /// Author address. Must be non-zero.
    pub author: SuiAddress,
    /// Depth from the root: `0` for a root, `parent.depth + 1` for a fork.
    pub provenance_depth_u16: u16,
}

impl ProvenanceNode {
    /// `true` iff this node is a root (`parent == None`, `depth == 0`).
    #[inline]
    #[must_use]
    pub fn is_root(&self) -> bool {
        self.parent.is_none() && self.provenance_depth_u16 == 0
    }

    /// `true` iff the node is locally well-formed (see module docs). This
    /// does NOT validate ancestor linkage — see [`validate_ancestor_chain`].
    #[must_use]
    pub fn is_well_formed(&self) -> bool {
        // Missing author rejected.
        if *self.author.as_bytes() == [0u8; 32] {
            return false;
        }
        // Depth bound.
        if self.provenance_depth_u16 > MAX_PROVENANCE_DEPTH {
            return false;
        }
        match self.parent {
            None => {
                // A node without a parent must be a depth-0 root.
                self.provenance_depth_u16 == 0
            }
            Some(parent) => {
                // A fork must have depth >= 1 and a parent that is not
                // itself (a self-parent is a 1-cycle).
                self.provenance_depth_u16 >= 1 && parent != self.package
            }
        }
    }

    /// 32-byte fold digest, folded into the package content digest.
    #[must_use]
    pub(crate) fn digest_32(&self) -> [u8; 32] {
        let mut buf: Vec<u8> = Vec::new();
        buf.extend_from_slice(&self.skill.0.to_le_bytes());
        buf.extend_from_slice(self.package.as_bytes());
        match self.parent {
            Some(parent) => {
                buf.push(1);
                buf.extend_from_slice(parent.as_bytes());
            }
            None => {
                buf.push(0);
                buf.extend_from_slice(&[0u8; 32]);
            }
        }
        buf.extend_from_slice(self.author.as_bytes());
        buf.extend_from_slice(&self.provenance_depth_u16.to_le_bytes());
        blake2b_256(&[DOMAIN_PROVENANCE, &buf])
    }
}

// ===========================================================================
// 2. validate_ancestor_chain — deterministic leaf→root walk
// ===========================================================================

/// Validate a leaf-first ancestor chain. `chain[0]` is the leaf;
/// `chain[chain.len()-1]` is the root. Returns `true` iff:
/// - every node is locally well-formed;
/// - each non-root node's `parent` equals the next node's `package`;
/// - depth strictly decreases by exactly 1 at each step;
/// - the last node is a root;
/// - every package digest in the chain is unique (cycle reject).
///
/// An empty chain is invalid (there is no leaf to anchor).
#[must_use]
pub fn validate_ancestor_chain(chain: &[ProvenanceNode]) -> bool {
    if chain.is_empty() {
        return false;
    }
    let mut seen: BTreeSet<[u8; 32]> = BTreeSet::new();
    for (i, node) in chain.iter().enumerate() {
        if !node.is_well_formed() {
            return false;
        }
        // Cycle reject: a package digest may appear at most once.
        if !seen.insert(*node.package.as_bytes()) {
            return false;
        }
        let is_last = i + 1 == chain.len();
        if is_last {
            // The terminal node must be a root.
            if !node.is_root() {
                return false;
            }
        } else {
            let next = &chain[i + 1];
            // Linkage: this node's parent is the next node's package.
            match node.parent {
                Some(parent) if parent == next.package => {}
                _ => return false,
            }
            // Depth strictly decreases by exactly 1.
            if node.provenance_depth_u16 != next.provenance_depth_u16 + 1 {
                return false;
            }
        }
    }
    true
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    fn addr(b: u8) -> SuiAddress {
        SuiAddress::new([b; 32])
    }
    fn pkg(b: u8) -> SkillPackageDigest32 {
        SkillPackageDigest32::new([b; 32])
    }

    fn root() -> ProvenanceNode {
        ProvenanceNode {
            skill: SkillId(1),
            package: pkg(0xA0),
            parent: None,
            author: addr(0x11),
            provenance_depth_u16: 0,
        }
    }

    #[test]
    fn root_is_well_formed() {
        assert!(root().is_root());
        assert!(root().is_well_formed());
    }

    #[test]
    fn fork_requires_parent_digest() {
        // depth > 0 but no parent → not well-formed.
        let mut bad = root();
        bad.provenance_depth_u16 = 1;
        assert!(
            !bad.is_well_formed(),
            "depth-1 root without parent must reject"
        );

        // proper fork.
        let fork = ProvenanceNode {
            skill: SkillId(1),
            package: pkg(0xB0),
            parent: Some(pkg(0xA0)),
            author: addr(0x22),
            provenance_depth_u16: 1,
        };
        assert!(fork.is_well_formed());
    }

    #[test]
    fn missing_author_rejected() {
        let mut bad = root();
        bad.author = addr(0x00);
        assert!(!bad.is_well_formed(), "zero author must reject");
    }

    #[test]
    fn self_parent_cycle_rejected() {
        let cyclic = ProvenanceNode {
            skill: SkillId(1),
            package: pkg(0xC0),
            parent: Some(pkg(0xC0)), // self-parent
            author: addr(0x33),
            provenance_depth_u16: 1,
        };
        assert!(!cyclic.is_well_formed(), "self-parent must reject");
    }

    #[test]
    fn depth_bound_enforced() {
        let mut deep = ProvenanceNode {
            skill: SkillId(1),
            package: pkg(0xD0),
            parent: Some(pkg(0xA0)),
            author: addr(0x44),
            provenance_depth_u16: MAX_PROVENANCE_DEPTH,
        };
        assert!(deep.is_well_formed());
        deep.provenance_depth_u16 = MAX_PROVENANCE_DEPTH + 1;
        assert!(!deep.is_well_formed(), "depth over bound must reject");
    }

    #[test]
    fn ancestor_chain_traversal_is_deterministic() {
        let leaf = ProvenanceNode {
            skill: SkillId(1),
            package: pkg(0xB0),
            parent: Some(pkg(0xA0)),
            author: addr(0x22),
            provenance_depth_u16: 1,
        };
        let chain = [leaf, root()];
        assert!(validate_ancestor_chain(&chain));

        // Broken linkage: leaf parent does not match next package.
        let bad_leaf = ProvenanceNode {
            parent: Some(pkg(0xFF)),
            ..leaf
        };
        assert!(!validate_ancestor_chain(&[bad_leaf, root()]));

        // Cycle: two nodes with the same package digest.
        let dup = ProvenanceNode {
            package: pkg(0xA0),
            parent: Some(pkg(0xA0)),
            provenance_depth_u16: 1,
            ..leaf
        };
        assert!(
            !validate_ancestor_chain(&[dup, root()]),
            "cycle must reject"
        );

        // Empty chain invalid.
        assert!(!validate_ancestor_chain(&[]));
    }
}
