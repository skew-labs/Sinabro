//! Audit move generator (atom #518 · G.3.2).
//!
//! The audit game tree reads like baduk: from a parent [`AuditSearchNode`] the
//! generator expands an [`AuditMove`] (current move, expected response,
//! refutation, the invariant it tests, the resulting state, and a stop condition)
//! into a child node. [`AuditMoveGenerator`] is the §3 record of the generator
//! config — it is bound to an invariant (`invariant_bound = true`), refuses an
//! invariant-less search, caps depth and per-node branching, and never allows a
//! production probe or a random-fuzz mode (`G-G-AUDIT-GAME-TREE`). This module
//! performs no live action.
//!
//! Reuse (no reinvention): [`crate::sha256_32`]; a reproduced node routes to a
//! finding only through the Stage F [`crate::commands::eval_core::route_to_finding`]
//! after a local repro receipt ([`crate::audit::repro_receipt`]).

use crate::sha256_32;

/// Why a search node may stop expanding.
#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StopCondition {
    /// The invariant held against the move (defended).
    InvariantDefended = 1,
    /// A counterexample broke the invariant locally.
    CounterexampleFound = 2,
    /// The depth cap was reached.
    DepthCapReached = 3,
    /// The branching cap was reached.
    BranchCapReached = 4,
}

/// A single audit move (a baduk variation): the move, its expected response, the
/// refutation considered, the invariant it tests, the resulting state, and a stop
/// condition.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AuditMove {
    /// SHA-256 of the instruction/entrypoint move.
    pub current_move_hash_32: [u8; 32],
    /// SHA-256 of the expected protocol response.
    pub expected_response_hash_32: [u8; 32],
    /// SHA-256 of the refutation considered (zero = none recorded yet).
    pub refutation_hash_32: [u8; 32],
    /// SHA-256 of the invariant this move tests (must be non-zero).
    pub invariant_hash_32: [u8; 32],
    /// SHA-256 of the resulting bounded state.
    pub resulting_state_hash_32: [u8; 32],
    /// The stop condition for this move.
    pub stop: StopCondition,
}

impl AuditMove {
    /// Whether a refutation has been recorded for this move.
    #[must_use]
    pub fn has_refutation(&self) -> bool {
        self.refutation_hash_32 != [0u8; 32]
    }
}

/// §3 — a node in the audit search tree.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AuditSearchNode {
    /// SHA-256 identity of this node.
    pub node_hash_32: [u8; 32],
    /// SHA-256 of the parent node (zero for a root).
    pub parent_hash_32: [u8; 32],
    /// SHA-256 of the invariant under test.
    pub invariant_hash_32: [u8; 32],
    /// SHA-256 of the instruction sequence to this node.
    pub sequence_hash_32: [u8; 32],
    /// SHA-256 of the bounded state at this node.
    pub state_hash_32: [u8; 32],
    /// The node depth (root = 0).
    pub depth_u8: u8,
}

/// Why a move expansion was rejected (fail-closed).
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum MoveReject {
    /// The move tested no invariant — an invariant-less search is refused.
    #[error("invariant-less search refused")]
    InvariantLessSearch,
    /// The child depth would exceed the depth cap.
    #[error("depth cap exceeded")]
    DepthCapExceeded,
    /// The child index would exceed the per-node branching cap.
    #[error("branch cap exceeded")]
    BranchCapExceeded,
    /// A random-fuzz mode (a search with no invariant) was requested.
    #[error("random fuzz denied")]
    RandomFuzzDenied,
    /// A production probe was requested.
    #[error("production probe denied")]
    ProductionProbeDenied,
}

/// §3 — the audit move generator config + running sequence counter.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AuditMoveGenerator {
    /// SHA-256 of the generator config (the generator identity).
    pub generator_hash_32: [u8; 32],
    /// Maximum search depth.
    pub max_depth_u8: u8,
    /// Maximum children per node.
    pub branching_cap_u16: u16,
    /// The number of moves expanded so far.
    pub sequence_count_u32: u32,
    /// Invariant `true`: every search is bound to an invariant.
    pub invariant_bound: bool,
    /// Invariant `false`: a production probe is never allowed.
    pub production_probe_allowed: bool,
}

impl AuditMoveGenerator {
    /// A new generator. `invariant_bound` is the invariant `true`;
    /// `production_probe_allowed` is the invariant `false`.
    #[must_use]
    pub fn new(max_depth_u8: u8, branching_cap_u16: u16) -> Self {
        let mut buf = [0u8; 3];
        buf[0] = max_depth_u8;
        buf[1..3].copy_from_slice(&branching_cap_u16.to_le_bytes());
        Self {
            generator_hash_32: sha256_32(&buf),
            max_depth_u8,
            branching_cap_u16,
            sequence_count_u32: 0,
            invariant_bound: true,
            production_probe_allowed: false,
        }
    }

    /// The root node of a search, bound to an invariant + bounded state.
    #[must_use]
    pub fn root(
        &self,
        invariant_hash_32: [u8; 32],
        sequence_hash_32: [u8; 32],
        state_hash_32: [u8; 32],
    ) -> AuditSearchNode {
        let mut buf: Vec<u8> = Vec::with_capacity(96);
        buf.extend_from_slice(&invariant_hash_32);
        buf.extend_from_slice(&sequence_hash_32);
        buf.extend_from_slice(&state_hash_32);
        AuditSearchNode {
            node_hash_32: sha256_32(&buf),
            parent_hash_32: [0u8; 32],
            invariant_hash_32,
            sequence_hash_32,
            state_hash_32,
            depth_u8: 0,
        }
    }

    /// Expand a child node from `parent` along `mv` as the `child_index`-th child.
    /// Refuses an invariant-less move, a child index over the per-node branching
    /// cap, and a depth over the depth cap.
    pub fn expand(
        &mut self,
        parent: &AuditSearchNode,
        mv: &AuditMove,
        child_index_u16: u16,
    ) -> Result<AuditSearchNode, MoveReject> {
        if mv.invariant_hash_32 == [0u8; 32] {
            return Err(MoveReject::InvariantLessSearch);
        }
        if child_index_u16 >= self.branching_cap_u16 {
            return Err(MoveReject::BranchCapExceeded);
        }
        let depth_u8 = match parent.depth_u8.checked_add(1) {
            Some(d) if d <= self.max_depth_u8 => d,
            _ => return Err(MoveReject::DepthCapExceeded),
        };
        let mut seq_buf: Vec<u8> = Vec::with_capacity(64);
        seq_buf.extend_from_slice(&parent.sequence_hash_32);
        seq_buf.extend_from_slice(&mv.current_move_hash_32);
        let sequence_hash_32 = sha256_32(&seq_buf);
        let mut node_buf: Vec<u8> = Vec::with_capacity(160);
        node_buf.extend_from_slice(&parent.node_hash_32);
        node_buf.extend_from_slice(&mv.current_move_hash_32);
        node_buf.extend_from_slice(&mv.invariant_hash_32);
        node_buf.extend_from_slice(&sequence_hash_32);
        node_buf.extend_from_slice(&mv.resulting_state_hash_32);
        node_buf.push(depth_u8);
        node_buf.extend_from_slice(&child_index_u16.to_le_bytes());
        self.sequence_count_u32 = self.sequence_count_u32.saturating_add(1);
        Ok(AuditSearchNode {
            node_hash_32: sha256_32(&node_buf),
            parent_hash_32: parent.node_hash_32,
            invariant_hash_32: mv.invariant_hash_32,
            sequence_hash_32,
            state_hash_32: mv.resulting_state_hash_32,
            depth_u8,
        })
    }

    /// A random-fuzz mode (a search without an invariant) is always refused.
    pub const fn try_random_fuzz() -> Result<(), MoveReject> {
        Err(MoveReject::RandomFuzzDenied)
    }

    /// A production probe is always refused.
    pub const fn try_production_probe() -> Result<(), MoveReject> {
        Err(MoveReject::ProductionProbeDenied)
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;

    fn mv(inv: u8, refut: u8) -> AuditMove {
        AuditMove {
            current_move_hash_32: [0x10; 32],
            expected_response_hash_32: [0x20; 32],
            refutation_hash_32: if refut == 0 { [0u8; 32] } else { [refut; 32] },
            invariant_hash_32: if inv == 0 { [0u8; 32] } else { [inv; 32] },
            resulting_state_hash_32: [0x30; 32],
            stop: StopCondition::InvariantDefended,
        }
    }

    fn gen_root(g: &AuditMoveGenerator) -> AuditSearchNode {
        g.root([1u8; 32], [2u8; 32], [3u8; 32])
    }

    #[test]
    fn depth_cap_exceeded() {
        let mut g = AuditMoveGenerator::new(1, 4);
        let root = gen_root(&g);
        let c1 = g.expand(&root, &mv(5, 0), 0).unwrap();
        assert_eq!(c1.depth_u8, 1);
        // a second level would be depth 2 > max_depth 1
        assert_eq!(
            g.expand(&c1, &mv(5, 0), 0),
            Err(MoveReject::DepthCapExceeded)
        );
    }

    #[test]
    fn branch_cap_exceeded() {
        let mut g = AuditMoveGenerator::new(4, 2);
        let root = gen_root(&g);
        assert!(g.expand(&root, &mv(5, 0), 0).is_ok());
        assert!(g.expand(&root, &mv(5, 0), 1).is_ok());
        assert_eq!(
            g.expand(&root, &mv(5, 0), 2),
            Err(MoveReject::BranchCapExceeded)
        );
    }

    #[test]
    fn invariant_linked_move() {
        let mut g = AuditMoveGenerator::new(4, 4);
        let root = gen_root(&g);
        let c = g.expand(&root, &mv(7, 9), 0).unwrap();
        assert_eq!(c.invariant_hash_32, [7u8; 32]);
        assert_eq!(c.parent_hash_32, root.node_hash_32);
        assert_eq!(c.depth_u8, 1);
        assert_eq!(g.sequence_count_u32, 1);
    }

    #[test]
    fn refutation_record() {
        assert!(mv(5, 9).has_refutation());
        assert!(!mv(5, 0).has_refutation());
    }

    #[test]
    fn no_random_fuzz_mode() {
        let mut g = AuditMoveGenerator::new(4, 4);
        let root = gen_root(&g);
        assert_eq!(
            AuditMoveGenerator::try_random_fuzz(),
            Err(MoveReject::RandomFuzzDenied)
        );
        // generator refuses an invariant-less search (the criterion)
        assert_eq!(
            g.expand(&root, &mv(0, 0), 0),
            Err(MoveReject::InvariantLessSearch)
        );
        assert!(g.invariant_bound);
        assert!(!g.production_probe_allowed);
        assert_eq!(
            AuditMoveGenerator::try_production_probe(),
            Err(MoveReject::ProductionProbeDenied)
        );
    }
}
