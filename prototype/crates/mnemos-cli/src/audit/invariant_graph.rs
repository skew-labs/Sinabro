//! Audit invariant graph (atom #516 · G.3.0).
//!
//! Stage F's `audit scan` ([`crate::commands::eval_core::AuditScanView`]) is a
//! local-only candidate *surface*. Stage G's audit game tree starts one layer
//! earlier: an audit begins from the invariants that must not break, never from a
//! grep smell. [`AuditInvariantGraph`] is the §3 canonical record of that node
//! set — solvency, signer/owner, oracle freshness, PDA/object identity, receipt
//! integrity, replay/delete, permission, gas/cost, and economic PnL are explicit
//! [`InvariantKind`] nodes, each carrying a non-zero invariant hash and a non-zero
//! source-evidence hash. A node with no invariant hash or no source evidence is
//! rejected (`G-G-AUDIT-GAME-TREE`); a duplicate invariant hash is merged, not
//! double counted. This module performs no live action.
//!
//! Reuse (no reinvention): [`crate::sha256_32`] for the graph + evidence roots;
//! the invariant vocabulary mirrors the Stage E security corpus axes and the
//! economic-invariant lunchbox (`datasets/economic_invariant_diet/manifest.json`).

use crate::sha256_32;

/// The economic / authority / state axis an invariant node belongs to.
#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum InvariantAxis {
    /// Value / solvency / gas-cost / PnL invariants.
    Economic = 1,
    /// Signer / owner / permission / identity invariants.
    Authority = 2,
    /// Oracle / replay / receipt / state-integrity invariants.
    State = 3,
}

/// An explicit audit invariant node kind. Audit reads start from these, never
/// from a pattern smell.
#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum InvariantKind {
    /// Protocol solvency / non-negative balance.
    Solvency = 1,
    /// Signer / account-owner authority.
    SignerOwner = 2,
    /// Oracle price freshness / staleness bound.
    OracleFreshness = 3,
    /// PDA seeds / object identity binding.
    PdaObjectIdentity = 4,
    /// Receipt / settlement parity integrity.
    ReceiptIntegrity = 5,
    /// Replay / delete (tombstone) idempotence.
    ReplayDelete = 6,
    /// Permission / capability boundary.
    Permission = 7,
    /// Gas / compute cost boundary.
    GasCost = 8,
    /// Economic profit-and-loss invariant.
    EconomicPnl = 9,
}

impl InvariantKind {
    /// Stable u8 discriminant.
    #[must_use]
    pub const fn as_u8(self) -> u8 {
        self as u8
    }

    /// The axis this invariant belongs to.
    #[must_use]
    pub const fn axis(self) -> InvariantAxis {
        match self {
            Self::Solvency | Self::GasCost | Self::EconomicPnl => InvariantAxis::Economic,
            Self::SignerOwner | Self::PdaObjectIdentity | Self::Permission => {
                InvariantAxis::Authority
            }
            Self::OracleFreshness | Self::ReceiptIntegrity | Self::ReplayDelete => {
                InvariantAxis::State
            }
        }
    }
}

/// Why adding an invariant node was rejected (fail-closed).
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum InvariantReject {
    /// The invariant hash was zero (an audit cannot start from "nothing").
    #[error("missing invariant hash")]
    MissingInvariantHash,
    /// The source-evidence hash was zero (every invariant must cite a source).
    #[error("missing source evidence")]
    MissingSourceEvidence,
}

/// §3 — the audit invariant graph: the bounded set of invariants an audit must
/// not break, with the per-axis share (in basis points) and an evidence root.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AuditInvariantGraph {
    /// SHA-256 over the ordered invariant hashes (the graph identity).
    pub graph_hash_32: [u8; 32],
    /// The number of distinct invariant nodes.
    pub invariant_count_u32: u32,
    /// Economic-axis share, in basis points (0..=10000).
    pub economic_axis_bps: u16,
    /// Authority-axis share, in basis points (0..=10000).
    pub authority_axis_bps: u16,
    /// State-axis share, in basis points (0..=10000).
    pub state_axis_bps: u16,
    /// SHA-256 over the ordered source-evidence hashes.
    pub evidence_root_32: [u8; 32],
}

/// One invariant node before the graph is sealed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct InvariantNode {
    kind: InvariantKind,
    invariant_hash_32: [u8; 32],
    source_evidence_hash_32: [u8; 32],
}

/// Builder that accumulates invariant nodes, rejects empty ones, and merges
/// duplicates by invariant hash before sealing an [`AuditInvariantGraph`].
#[derive(Clone, Debug, Default)]
pub struct InvariantGraphBuilder {
    nodes: Vec<InvariantNode>,
}

impl InvariantGraphBuilder {
    /// A new, empty builder.
    #[must_use]
    pub fn new() -> Self {
        Self { nodes: Vec::new() }
    }

    /// Add an invariant node. A zero invariant or source-evidence hash is
    /// rejected. A duplicate invariant hash is merged (returns `Ok(false)` — not
    /// newly added); a fresh node returns `Ok(true)`.
    pub fn add(
        &mut self,
        kind: InvariantKind,
        invariant_hash_32: [u8; 32],
        source_evidence_hash_32: [u8; 32],
    ) -> Result<bool, InvariantReject> {
        if invariant_hash_32 == [0u8; 32] {
            return Err(InvariantReject::MissingInvariantHash);
        }
        if source_evidence_hash_32 == [0u8; 32] {
            return Err(InvariantReject::MissingSourceEvidence);
        }
        if self
            .nodes
            .iter()
            .any(|n| n.invariant_hash_32 == invariant_hash_32)
        {
            return Ok(false);
        }
        self.nodes.push(InvariantNode {
            kind,
            invariant_hash_32,
            source_evidence_hash_32,
        });
        Ok(true)
    }

    /// The current distinct node count.
    #[must_use]
    pub fn len(&self) -> usize {
        self.nodes.len()
    }

    /// Whether the builder holds no nodes.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.nodes.is_empty()
    }

    /// Count of nodes on a given axis.
    fn axis_count(&self, axis: InvariantAxis) -> usize {
        self.nodes.iter().filter(|n| n.kind.axis() == axis).count()
    }

    /// Seal the accumulated nodes into an [`AuditInvariantGraph`].
    #[must_use]
    pub fn build(&self) -> AuditInvariantGraph {
        let total = self.nodes.len();
        let mut graph_buf: Vec<u8> = Vec::with_capacity(total * 32);
        let mut evidence_buf: Vec<u8> = Vec::with_capacity(total * 32);
        for n in &self.nodes {
            graph_buf.extend_from_slice(&n.invariant_hash_32);
            evidence_buf.extend_from_slice(&n.source_evidence_hash_32);
        }
        AuditInvariantGraph {
            graph_hash_32: sha256_32(&graph_buf),
            invariant_count_u32: u32::try_from(total).unwrap_or(u32::MAX),
            economic_axis_bps: axis_share_bps(self.axis_count(InvariantAxis::Economic), total),
            authority_axis_bps: axis_share_bps(self.axis_count(InvariantAxis::Authority), total),
            state_axis_bps: axis_share_bps(self.axis_count(InvariantAxis::State), total),
            evidence_root_32: sha256_32(&evidence_buf),
        }
    }
}

/// Share of `count` within `total`, in basis points (0..=10000). Zero total → 0.
fn axis_share_bps(count: usize, total: usize) -> u16 {
    if total == 0 {
        return 0;
    }
    let count_u32 = u32::try_from(count).unwrap_or(u32::MAX);
    let total_u32 = u32::try_from(total).unwrap_or(u32::MAX);
    let bps = count_u32.saturating_mul(10_000) / total_u32;
    u16::try_from(bps).unwrap_or(10_000)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;
    use crate::repl::latency::p95_ms;

    fn h(b: u8) -> [u8; 32] {
        [b; 32]
    }

    const KINDS: [InvariantKind; 9] = [
        InvariantKind::Solvency,
        InvariantKind::SignerOwner,
        InvariantKind::OracleFreshness,
        InvariantKind::PdaObjectIdentity,
        InvariantKind::ReceiptIntegrity,
        InvariantKind::ReplayDelete,
        InvariantKind::Permission,
        InvariantKind::GasCost,
        InvariantKind::EconomicPnl,
    ];

    fn full_graph() -> InvariantGraphBuilder {
        let mut b = InvariantGraphBuilder::new();
        for (i, k) in KINDS.iter().enumerate() {
            let idx = u8::try_from(i + 1).unwrap_or(1);
            b.add(*k, h(idx), h(idx + 100)).unwrap();
        }
        b
    }

    #[test]
    fn graph_schema_counts_and_axes() {
        let g = full_graph().build();
        assert_eq!(g.invariant_count_u32, 9);
        // 3 economic / 3 authority / 3 state => each 3333 bps (floor)
        assert_eq!(g.economic_axis_bps, 3333);
        assert_eq!(g.authority_axis_bps, 3333);
        assert_eq!(g.state_axis_bps, 3333);
        assert_ne!(g.graph_hash_32, [0u8; 32]);
        assert_ne!(g.evidence_root_32, [0u8; 32]);
    }

    #[test]
    fn missing_invariant_reject() {
        let mut b = InvariantGraphBuilder::new();
        assert_eq!(
            b.add(InvariantKind::Solvency, [0u8; 32], h(1)),
            Err(InvariantReject::MissingInvariantHash)
        );
        assert_eq!(
            b.add(InvariantKind::Solvency, h(1), [0u8; 32]),
            Err(InvariantReject::MissingSourceEvidence)
        );
        assert!(b.is_empty());
    }

    #[test]
    fn duplicate_merge() {
        let mut b = InvariantGraphBuilder::new();
        assert_eq!(b.add(InvariantKind::Solvency, h(1), h(2)), Ok(true));
        // same invariant hash merges (not newly added), even with a new kind/source
        assert_eq!(b.add(InvariantKind::GasCost, h(1), h(9)), Ok(false));
        assert_eq!(b.len(), 1);
    }

    #[test]
    fn economic_invariant_node() {
        assert_eq!(InvariantKind::EconomicPnl.axis(), InvariantAxis::Economic);
        assert_eq!(InvariantKind::Solvency.axis(), InvariantAxis::Economic);
        let mut b = InvariantGraphBuilder::new();
        b.add(InvariantKind::EconomicPnl, h(9), h(99)).unwrap();
        let g = b.build();
        assert_eq!(g.economic_axis_bps, 10_000);
        assert_eq!(g.authority_axis_bps, 0);
        assert_eq!(g.state_axis_bps, 0);
    }

    #[test]
    fn source_evidence_hash_binds_root() {
        let g1 = full_graph().build();
        let mut b2 = InvariantGraphBuilder::new();
        for (i, k) in KINDS.iter().enumerate() {
            let idx = u8::try_from(i + 1).unwrap_or(1);
            // change only the first node's source-evidence hash
            let ev = if i == 0 { h(250) } else { h(idx + 100) };
            b2.add(*k, h(idx), ev).unwrap();
        }
        let g2 = b2.build();
        assert_eq!(
            g1.graph_hash_32, g2.graph_hash_32,
            "same invariants => same graph hash"
        );
        assert_ne!(
            g1.evidence_root_32, g2.evidence_root_32,
            "different source evidence => different evidence root"
        );
    }

    #[test]
    fn graph_build_p95_within_100ms() {
        let b = full_graph();
        let mut samples = Vec::with_capacity(256);
        for _ in 0..256 {
            let t = std::time::Instant::now();
            let g = b.build();
            std::hint::black_box(&g);
            samples.push(t.elapsed().as_nanos() as u64);
        }
        let p95 = p95_ms(&samples) / 1_000_000;
        assert!(p95 <= 100, "graph build p95 {p95}ms exceeds 100ms");
    }
}
