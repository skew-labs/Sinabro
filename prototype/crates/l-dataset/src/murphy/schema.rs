//! MURPHY failure-attempt tree schema (`MurphyNode`, `MurphyTree`, and the
//! `FailureKind` taxonomy).
//!
//! # Invariants
//!
//! Every failed attempt can point to a later verified success: the parent/child
//! chain is explicit, so success credit can flow back to the failures that led
//! to it (the credit assignment lives in [`super::build`]). Orphan attempts —
//! failures with no parent linkage — are *kept* in the node set (they are real
//! trajectory data) but receive no back-propagated credit. A broken parent
//! reference, a duplicate node id, or a parent cycle is rejected fail-closed: a
//! learnable tree must be acyclic and closed.
//!
//! The `FailureKind` taxonomy is defined in this module — its first use — so it
//! is not reinvented downstream.
use crate::diet_kind::AtomDietKey;
use crate::error::{DietError, DietResult};
use std::collections::BTreeMap;

/// The verified failure surface a repair step hit. Defined here so that MURPHY
/// nodes and repair traces ([`super::build::RepairStep`]) share one failure
/// taxonomy.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
#[repr(u8)]
pub enum FailureKind {
    /// `cargo build` / compiler error.
    Compile = 1,
    /// `cargo clippy` lint failure.
    Clippy = 2,
    /// `cargo test` unit/integration failure.
    Test = 3,
    /// Miri undefined-behaviour detection.
    Miri = 4,
    /// Fuzz crash.
    Fuzz = 5,
    /// Criterion / performance regression.
    Criterion = 6,
    /// Move `build` failure.
    MoveBuild = 7,
    /// Move `test` failure.
    MoveTest = 8,
    /// Move Prover / spec failure.
    MoveProver = 9,
    /// Gas budget / metering failure.
    Gas = 10,
    /// Walrus BCS / blob round-trip failure.
    Walrus = 11,
    /// Security finding (audit / exploit repro).
    Security = 12,
    /// Privacy / secret-residue failure.
    Privacy = 13,
    /// Human reviewer rejection.
    HumanRejected = 14,
    /// Failure masked by infrastructure (OOM / timeout / rate-limit), not the model.
    InfraMasked = 15,
}

impl FailureKind {
    /// Numeric discriminant.
    pub const fn as_u8(self) -> u8 {
        self as u8
    }

    /// Parse from a discriminant; `None` if not `1..=15`.
    pub const fn from_u8(v: u8) -> Option<Self> {
        match v {
            1 => Some(Self::Compile),
            2 => Some(Self::Clippy),
            3 => Some(Self::Test),
            4 => Some(Self::Miri),
            5 => Some(Self::Fuzz),
            6 => Some(Self::Criterion),
            7 => Some(Self::MoveBuild),
            8 => Some(Self::MoveTest),
            9 => Some(Self::MoveProver),
            10 => Some(Self::Gas),
            11 => Some(Self::Walrus),
            12 => Some(Self::Security),
            13 => Some(Self::Privacy),
            14 => Some(Self::HumanRejected),
            15 => Some(Self::InfraMasked),
            _ => None,
        }
    }

    /// Whether this failure was masked by infrastructure (no reward, no model
    /// blame — the trajectory is held, not scored).
    pub const fn is_infra_masked(self) -> bool {
        matches!(self, Self::InfraMasked)
    }
}

/// One node in a MURPHY failure-attempt tree.
///
/// `parent_id == None` marks a root or an orphan attempt. `success_credit_milli`
/// is filled by [`super::build`]; it is `0` until a later verified success
/// back-propagates credit (and even then, only when privacy passes).
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub struct MurphyNode {
    /// Stable, unique node id within the tree.
    pub node_id_u64: u64,
    /// Parent node id, or `None` for a root / orphan attempt.
    pub parent_id: Option<u64>,
    /// The source atom this attempt belongs to.
    pub key: AtomDietKey,
    /// The repair step index this node represents.
    pub step_u16: u16,
    /// The failure surface this attempt hit.
    pub failure: FailureKind,
    /// Back-propagated success credit, in milli-units (`0` = no credit).
    pub success_credit_milli_i16: i16,
}

impl MurphyNode {
    /// Construct a MURPHY node.
    pub const fn new(
        node_id_u64: u64,
        parent_id: Option<u64>,
        key: AtomDietKey,
        step_u16: u16,
        failure: FailureKind,
        success_credit_milli_i16: i16,
    ) -> Self {
        Self {
            node_id_u64,
            parent_id,
            key,
            step_u16,
            failure,
            success_credit_milli_i16,
        }
    }

    /// Whether this node is a root or an orphan (no parent linkage).
    pub const fn is_orphan_or_root(&self) -> bool {
        self.parent_id.is_none()
    }
}

/// A MURPHY failure-attempt tree summary.
///
/// `nodes_hash_32` is the order-independent digest of the validated node set
/// (see [`nodes_hash`]); `gamma_bps_u16` is the per-hop discount applied to
/// back-propagated success credit (e.g. `8500` = 0.85).
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub struct MurphyTree {
    /// The root node id.
    pub root_id_u64: u64,
    /// Order-independent `sha256` of the validated node set.
    pub nodes_hash_32: [u8; 32],
    /// Per-hop success-credit discount, in basis points.
    pub gamma_bps_u16: u16,
}

impl MurphyTree {
    /// Construct a tree summary from its components.
    pub const fn new(root_id_u64: u64, nodes_hash_32: [u8; 32], gamma_bps_u16: u16) -> Self {
        Self {
            root_id_u64,
            nodes_hash_32,
            gamma_bps_u16,
        }
    }
}

/// Serialize one node into the canonical 24-byte little-endian record used by
/// [`nodes_hash`]. The `parent_id` tag is `1` (present) or `0` (root/orphan).
fn node_record(n: &MurphyNode) -> [u8; 24] {
    let mut b = [0u8; 24];
    b[0..8].copy_from_slice(&n.node_id_u64.to_le_bytes());
    match n.parent_id {
        Some(p) => {
            b[8] = 1;
            b[9..17].copy_from_slice(&p.to_le_bytes());
        }
        None => {
            b[8] = 0;
        }
    }
    b[17] = n.key.source.as_u8();
    b[18..20].copy_from_slice(&n.key.atom_u16.to_le_bytes());
    b[20..22].copy_from_slice(&n.step_u16.to_le_bytes());
    b[22] = n.failure.as_u8();
    // success credit is intentionally excluded from the structural identity:
    // the tree's *shape* is what dedup/split key on, not the (post-hoc) credit.
    b[23] = 0;
    b
}

/// Order-independent `sha256` over a node set: the records are sorted by
/// `node_id` before hashing, so the digest depends only on the set, not on
/// insertion order. The success-credit field is excluded from the identity.
pub fn nodes_hash(nodes: &[MurphyNode]) -> [u8; 32] {
    let mut sorted: Vec<&MurphyNode> = nodes.iter().collect();
    sorted.sort_by_key(|n| n.node_id_u64);
    let mut buf = Vec::with_capacity(sorted.len() * 24);
    for n in sorted {
        buf.extend_from_slice(&node_record(n));
    }
    crate::sha256(&buf)
}

/// Validate that `nodes` forms a closed, acyclic forest: unique node ids, every
/// `Some(parent)` resolves to a present node, and no parent chain cycles.
/// Orphans / roots (`parent_id == None`) are accepted — they are kept but earn
/// no credit. Fail-closed: any violation is a typed reject.
pub fn validate_nodes(nodes: &[MurphyNode]) -> DietResult<()> {
    let mut parents: BTreeMap<u64, Option<u64>> = BTreeMap::new();
    for n in nodes {
        if parents.insert(n.node_id_u64, n.parent_id).is_some() {
            return Err(DietError::MurphyDuplicateNode {
                node_id_u64: n.node_id_u64,
            });
        }
    }
    for n in nodes {
        if let Some(p) = n.parent_id {
            if !parents.contains_key(&p) {
                return Err(DietError::MurphyBrokenChain {
                    node_id_u64: n.node_id_u64,
                });
            }
        }
    }
    // O(n log n) cycle detection over the functional graph (each node has at
    // most one parent). Three colors: absent = unvisited, 1 = on the current
    // walk, 2 = cleared (no cycle reachable). Each node is colored at most once
    // across all walks, so a 100k linear chain is linear, not quadratic.
    let mut color: BTreeMap<u64, u8> = BTreeMap::new();
    for &start in parents.keys() {
        if matches!(color.get(&start), Some(&1 | &2)) {
            continue;
        }
        let mut path: Vec<u64> = Vec::new();
        let mut cur = start;
        loop {
            match color.get(&cur) {
                Some(&1) => return Err(DietError::MurphyCycle),
                Some(&2) => break,
                _ => {}
            }
            color.insert(cur, 1);
            path.push(cur);
            match parents.get(&cur) {
                Some(&Some(p)) => cur = p,
                _ => break,
            }
        }
        for id in path {
            color.insert(id, 2);
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::diet_kind::DietSourceStage;

    fn key() -> AtomDietKey {
        AtomDietKey::new(DietSourceStage::Phase0, 386)
    }

    fn node(id: u64, parent: Option<u64>, step: u16) -> MurphyNode {
        MurphyNode::new(id, parent, key(), step, FailureKind::Compile, 0)
    }

    #[test]
    fn failure_kind_round_trips_all_15() {
        for v in 1u8..=15 {
            assert_eq!(FailureKind::from_u8(v).map(FailureKind::as_u8), Some(v));
        }
        assert!(FailureKind::from_u8(0).is_none());
        assert!(FailureKind::from_u8(16).is_none());
    }

    #[test]
    fn simple_tree_validates() -> DietResult<()> {
        // 1 (root) -> 2 -> 3
        let nodes = [node(1, None, 0), node(2, Some(1), 1), node(3, Some(2), 2)];
        validate_nodes(&nodes)?;
        let tree = MurphyTree::new(1, nodes_hash(&nodes), 8500);
        assert_eq!(tree.gamma_bps_u16, 8500);
        assert_eq!(tree.root_id_u64, 1);
        Ok(())
    }

    #[test]
    fn orphan_is_kept_not_rejected() -> DietResult<()> {
        // 1 (root) -> 2 ; 9 is an orphan attempt (parent None, not the root).
        let nodes = [node(1, None, 0), node(2, Some(1), 1), node(9, None, 7)];
        validate_nodes(&nodes)?;
        assert!(nodes[2].is_orphan_or_root());
        Ok(())
    }

    #[test]
    fn cycle_is_rejected() {
        // 1 -> 2 -> 1 (cycle)
        let nodes = [node(1, Some(2), 0), node(2, Some(1), 1)];
        assert_eq!(validate_nodes(&nodes), Err(DietError::MurphyCycle));
    }

    #[test]
    fn broken_parent_reference_is_rejected() {
        let nodes = [node(1, None, 0), node(2, Some(42), 1)];
        assert_eq!(
            validate_nodes(&nodes),
            Err(DietError::MurphyBrokenChain { node_id_u64: 2 })
        );
    }

    #[test]
    fn duplicate_node_id_is_rejected() {
        let nodes = [node(1, None, 0), node(1, None, 1)];
        assert_eq!(
            validate_nodes(&nodes),
            Err(DietError::MurphyDuplicateNode { node_id_u64: 1 })
        );
    }

    #[test]
    fn nodes_hash_is_order_independent() {
        let a = [node(1, None, 0), node(2, Some(1), 1)];
        let b = [node(2, Some(1), 1), node(1, None, 0)];
        assert_eq!(nodes_hash(&a), nodes_hash(&b));
    }

    #[test]
    fn nodes_hash_excludes_credit() {
        let plain = [node(1, None, 0)];
        let mut credited = node(1, None, 0);
        credited.success_credit_milli_i16 = 850;
        assert_eq!(nodes_hash(&plain), nodes_hash(&[credited]));
    }
}
