//! Bounded protocol state space.
//!
//! An audit game tree searches a *bounded* state space, never an unbounded fuzz.
//! [`ProtocolStateSpace`] is the record of the bounded axes — account, object,
//! oracle, cache, epoch, permission, amount — plus the economic price / sequence
//! / reward / collateral axes, which are folded into the state hash so they bind
//! the space identity. Every axis is capped by a branch cap and a depth cap; a
//! zero axis is rejected (the space must be non-empty *and* bounded), and a
//! "production probe" axis is forbidden outright (no
//! production probing). This module performs no live action.
//!
//! Reuse (no reinvention): [`crate::sha256_32`]; the axis vocabulary mirrors the
//! chain-state concepts and the audit namespace.

use crate::sha256_32;

/// The bounded state axes an audit search may branch on.
#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StateAxis {
    /// Account axis.
    Account = 1,
    /// Object axis.
    Object = 2,
    /// Oracle axis.
    Oracle = 3,
    /// Cache axis.
    Cache = 4,
    /// Epoch axis.
    Epoch = 5,
    /// Permission axis.
    Permission = 6,
    /// Amount axis (economic).
    Amount = 7,
    /// Price axis (economic).
    Price = 8,
    /// Sequence axis.
    Sequence = 9,
    /// Reward axis (economic).
    Reward = 10,
    /// Collateral axis (economic).
    Collateral = 11,
}

/// Why building a [`ProtocolStateSpace`] was rejected (fail-closed).
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum StateSpaceReject {
    /// An axis cardinality was zero (the space must be bounded *and* non-empty).
    #[error("axis cardinality is zero")]
    AxisZero,
    /// An axis cardinality exceeded the branch cap (unbounded fuzz is refused).
    #[error("axis over branch cap")]
    AxisOverCap,
    /// A production-probe axis was requested (forbidden — no production probing).
    #[error("production axis forbidden")]
    ProductionAxisForbidden,
}

/// The per-axis cardinalities for a bounded search (account..collateral).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AxisCardinalities {
    /// Account axis count.
    pub account: u16,
    /// Object axis count.
    pub object: u16,
    /// Oracle axis count.
    pub oracle: u16,
    /// Cache axis count.
    pub cache: u16,
    /// Epoch axis count.
    pub epoch: u16,
    /// Permission axis count.
    pub permission: u16,
    /// Amount axis count (economic).
    pub amount: u16,
    /// Price axis count (economic).
    pub price: u16,
    /// Sequence axis count.
    pub sequence: u16,
    /// Reward axis count (economic).
    pub reward: u16,
    /// Collateral axis count (economic).
    pub collateral: u16,
}

/// The bounded protocol state space an audit search explores.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ProtocolStateSpace {
    /// SHA-256 over all axis cardinalities + caps (the space identity).
    pub state_hash_32: [u8; 32],
    /// Account axis cardinality.
    pub account_axis_u16: u16,
    /// Object axis cardinality.
    pub object_axis_u16: u16,
    /// Oracle axis cardinality.
    pub oracle_axis_u16: u16,
    /// Cache axis cardinality.
    pub cache_axis_u16: u16,
    /// Epoch axis cardinality.
    pub epoch_axis_u16: u16,
    /// Permission axis cardinality.
    pub permission_axis_u16: u16,
    /// Amount axis cardinality (economic).
    pub amount_axis_u16: u16,
}

impl ProtocolStateSpace {
    /// Whether every axis is bounded non-zero.
    #[must_use]
    pub const fn all_axes_nonzero(&self) -> bool {
        self.account_axis_u16 != 0
            && self.object_axis_u16 != 0
            && self.oracle_axis_u16 != 0
            && self.cache_axis_u16 != 0
            && self.epoch_axis_u16 != 0
            && self.permission_axis_u16 != 0
            && self.amount_axis_u16 != 0
    }
}

/// The branch cap + depth cap that bound an audit search.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StateSpaceBounds {
    branch_cap_u16: u16,
    depth_cap_u8: u8,
}

impl StateSpaceBounds {
    /// A new bound set. A zero branch/depth cap clamps to 1 (always bounded).
    #[must_use]
    pub const fn new(branch_cap_u16: u16, depth_cap_u8: u8) -> Self {
        Self {
            branch_cap_u16: if branch_cap_u16 == 0 {
                1
            } else {
                branch_cap_u16
            },
            depth_cap_u8: if depth_cap_u8 == 0 { 1 } else { depth_cap_u8 },
        }
    }

    /// The branch cap.
    #[must_use]
    pub const fn branch_cap(self) -> u16 {
        self.branch_cap_u16
    }

    /// Whether `depth_u8` is within the depth cap.
    #[must_use]
    pub const fn depth_within(self, depth_u8: u8) -> bool {
        depth_u8 <= self.depth_cap_u8
    }

    /// A production-probe axis is always forbidden.
    pub const fn try_production_axis() -> Result<(), StateSpaceReject> {
        Err(StateSpaceReject::ProductionAxisForbidden)
    }

    /// Build a bounded state space. Every axis must be in `1..=branch_cap`; the
    /// economic price / sequence / reward / collateral axes are folded into the
    /// state hash so they bind the space identity.
    pub fn bounded(self, axes: &AxisCardinalities) -> Result<ProtocolStateSpace, StateSpaceReject> {
        let all = [
            axes.account,
            axes.object,
            axes.oracle,
            axes.cache,
            axes.epoch,
            axes.permission,
            axes.amount,
            axes.price,
            axes.sequence,
            axes.reward,
            axes.collateral,
        ];
        for a in all {
            if a == 0 {
                return Err(StateSpaceReject::AxisZero);
            }
            if a > self.branch_cap_u16 {
                return Err(StateSpaceReject::AxisOverCap);
            }
        }
        let mut buf: Vec<u8> = Vec::with_capacity(all.len() * 2 + 3);
        for a in all {
            buf.extend_from_slice(&a.to_le_bytes());
        }
        buf.extend_from_slice(&self.branch_cap_u16.to_le_bytes());
        buf.push(self.depth_cap_u8);
        Ok(ProtocolStateSpace {
            state_hash_32: sha256_32(&buf),
            account_axis_u16: axes.account,
            object_axis_u16: axes.object,
            oracle_axis_u16: axes.oracle,
            cache_axis_u16: axes.cache,
            epoch_axis_u16: axes.epoch,
            permission_axis_u16: axes.permission,
            amount_axis_u16: axes.amount,
        })
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;

    fn axes() -> AxisCardinalities {
        AxisCardinalities {
            account: 4,
            object: 3,
            oracle: 2,
            cache: 2,
            epoch: 2,
            permission: 3,
            amount: 5,
            price: 3,
            sequence: 2,
            reward: 2,
            collateral: 2,
        }
    }

    #[test]
    fn axis_schema_bounded_nonzero() {
        let s = StateSpaceBounds::new(16, 6).bounded(&axes()).unwrap();
        assert!(s.all_axes_nonzero());
        assert_eq!(s.account_axis_u16, 4);
        assert_eq!(s.amount_axis_u16, 5);
        assert_ne!(s.state_hash_32, [0u8; 32]);
    }

    #[test]
    fn zero_axis_rejected() {
        let mut a = axes();
        a.oracle = 0;
        assert_eq!(
            StateSpaceBounds::new(16, 6).bounded(&a),
            Err(StateSpaceReject::AxisZero)
        );
    }

    #[test]
    fn branch_cap_enforced() {
        // amount=5 over a branch cap of 4
        assert_eq!(
            StateSpaceBounds::new(4, 6).bounded(&axes()),
            Err(StateSpaceReject::AxisOverCap)
        );
    }

    #[test]
    fn depth_cap_enforced() {
        let b = StateSpaceBounds::new(16, 6);
        assert!(b.depth_within(6));
        assert!(!b.depth_within(7));
        // a zero cap clamps to 1, never to "unbounded"
        assert_eq!(StateSpaceBounds::new(0, 0).branch_cap(), 1);
    }

    #[test]
    fn forbidden_production_axis() {
        assert_eq!(
            StateSpaceBounds::try_production_axis(),
            Err(StateSpaceReject::ProductionAxisForbidden)
        );
    }

    #[test]
    fn economic_axis_folds_into_hash() {
        let base = StateSpaceBounds::new(16, 6).bounded(&axes()).unwrap();
        let mut a2 = axes();
        a2.reward = 4; // change an economic axis only
        let other = StateSpaceBounds::new(16, 6).bounded(&a2).unwrap();
        assert_ne!(
            base.state_hash_32, other.state_hash_32,
            "an economic axis must bind the state hash"
        );
        assert!(base.amount_axis_u16 > 0);
    }
}
