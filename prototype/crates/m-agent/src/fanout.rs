//! Subagent fan-out budget partition (agent-core lane, roadmap §3.A;
//! threat model `ops/evidence/stage_g/agent_loop/SUBAGENT_FANOUT_THREAT_MODEL.md`
//! D-2).
//!
//! Pure arithmetic, no IO: ONE parent token cap is PARTITIONED across N
//! child budgets with `Σ child caps ≤ parent cap` held as a typed,
//! plan-time invariant — fan-out **re-distributes** the ceremony's
//! authorized spend, it never multiplies it (cross-cutting CU law L6,
//! "bounded-everything"; the roadmap's `Σ child_budget ≤ parent_budget`).
//!
//! v1 split is EQUAL (`child_cap = parent / n`, integer floor): the
//! invariant `child_cap × n ≤ parent` is then a property of integer
//! division, not of discipline. The unallocated remainder is exposed
//! ([`SubagentBudgetPlan::remainder_u32`]) and RESERVED for a future
//! parent synthesis turn (TM R4): a later weighted split changes this
//! module, never the invariant.
//!
//! Reuses [`DailyTokenBudget`] (atom #26) as the child budget carrier —
//! each child charges its own slice with the same charge-gated law the
//! single loop uses; no second budget type is minted.

use crate::loop_budget::DailyTokenBudget;

/// Hard cap on children per fan (pure-type bound; live bindings may bind
/// tighter — the v1 dispatch surface uses 4).
pub const MAX_SUBAGENT_CHILDREN: u8 = 8;

/// Typed, data-free partition failures (fail-closed at PLAN time: a plan
/// that could only produce instantly-exhausted children is refused before
/// any thread or socket exists).
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
#[non_exhaustive]
pub enum SubagentPartitionError {
    /// Zero children requested — a fan of nothing is a caller bug.
    ZeroChildren,
    /// More than [`MAX_SUBAGENT_CHILDREN`] requested.
    TooManyChildren,
    /// The parent cap cannot fund even one token per child
    /// (`parent / n == 0`) — every child would stop `BudgetExceeded` on
    /// its first turn, so the plan is refused up front.
    ZeroChildCap,
}

impl SubagentPartitionError {
    /// Stable, allow-listed `class_label` for diagnostic envelopes
    /// (namespaced under `fanout.*`).
    #[inline]
    #[must_use]
    pub const fn class_label(self) -> &'static str {
        match self {
            Self::ZeroChildren => "fanout.zero_children",
            Self::TooManyChildren => "fanout.too_many_children",
            Self::ZeroChildCap => "fanout.zero_child_cap",
        }
    }
}

/// An equal-split fan-out budget plan: `child_count` children, each funded
/// `child_cap = parent / child_count` tokens.
///
/// Fields are private; the only constructor is [`split`](Self::split),
/// which validates the bounds — a plan violating `Σ ≤ parent` is
/// unrepresentable through this API.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub struct SubagentBudgetPlan {
    parent_cap_u32: u32,
    child_cap_u32: u32,
    child_count_u8: u8,
}

impl SubagentBudgetPlan {
    /// Partition `parent_cap_u32` equally across `child_count_u8` children.
    /// Fail-closed: zero children, over-cap children and a parent too small
    /// to fund one token per child are all typed refusals at plan time.
    pub const fn split(
        parent_cap_u32: u32,
        child_count_u8: u8,
    ) -> Result<Self, SubagentPartitionError> {
        if child_count_u8 == 0 {
            return Err(SubagentPartitionError::ZeroChildren);
        }
        if child_count_u8 > MAX_SUBAGENT_CHILDREN {
            return Err(SubagentPartitionError::TooManyChildren);
        }
        let child_cap_u32 = parent_cap_u32 / child_count_u8 as u32;
        if child_cap_u32 == 0 {
            return Err(SubagentPartitionError::ZeroChildCap);
        }
        Ok(Self {
            parent_cap_u32,
            child_cap_u32,
            child_count_u8,
        })
    }

    /// The parent ceremony's total cap.
    #[inline]
    #[must_use]
    pub const fn parent_cap_u32(&self) -> u32 {
        self.parent_cap_u32
    }

    /// One child's token cap.
    #[inline]
    #[must_use]
    pub const fn child_cap_u32(&self) -> u32 {
        self.child_cap_u32
    }

    /// Number of children in the plan.
    #[inline]
    #[must_use]
    pub const fn child_count_u8(&self) -> u8 {
        self.child_count_u8
    }

    /// `Σ` of all child caps — the invariant accessor. Cannot overflow and
    /// cannot exceed the parent: `child_cap = parent / n` ⇒
    /// `child_cap × n ≤ parent ≤ u32::MAX` (integer-division floor).
    #[inline]
    #[must_use]
    pub const fn total_children_cap_u32(&self) -> u32 {
        self.child_cap_u32 * self.child_count_u8 as u32
    }

    /// Unallocated remainder (`parent − Σ children`, the floor residue).
    /// RESERVED for a future parent synthesis turn (TM R4) — a later
    /// consumer draws from here, never from a new budget.
    #[inline]
    #[must_use]
    pub const fn remainder_u32(&self) -> u32 {
        self.parent_cap_u32 - self.total_children_cap_u32()
    }

    /// Mint child `child_index_u8`'s [`DailyTokenBudget`] (equal slice; the
    /// index is range-checked so a caller cannot mint budgets past the
    /// plan). `None` ⇔ index out of range.
    #[inline]
    #[must_use]
    pub const fn child_budget(&self, child_index_u8: u8) -> Option<DailyTokenBudget> {
        if child_index_u8 < self.child_count_u8 {
            Some(DailyTokenBudget::new(self.child_cap_u32))
        } else {
            None
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    #![allow(clippy::expect_used)]
    #![allow(clippy::panic)]

    use super::*;

    /// D-2 — the partition invariant `Σ child caps ≤ parent` holds for
    /// EVERY admissible child count over representative parent caps, and
    /// the remainder is the exact floor residue.
    #[test]
    fn sum_of_child_caps_never_exceeds_parent() {
        for parent in [1u32, 7, 19_999, 20_000, 1_000_003, u32::MAX] {
            for n in 1u8..=MAX_SUBAGENT_CHILDREN {
                match SubagentBudgetPlan::split(parent, n) {
                    Ok(plan) => {
                        assert!(
                            plan.total_children_cap_u32() <= parent,
                            "parent={parent} n={n}"
                        );
                        assert_eq!(plan.remainder_u32(), parent - plan.total_children_cap_u32());
                        assert_eq!(plan.child_cap_u32(), parent / u32::from(n));
                        assert_eq!(plan.child_count_u8(), n);
                    }
                    Err(SubagentPartitionError::ZeroChildCap) => {
                        assert!(
                            parent / u32::from(n) == 0,
                            "ZeroChildCap only when the floor is zero (parent={parent} n={n})"
                        );
                    }
                    Err(other) => panic!("unexpected refusal {other:?} parent={parent} n={n}"),
                }
            }
        }
    }

    /// Plan-time refusals are typed and fail-closed: zero children, too
    /// many children, and a parent that cannot fund one token per child.
    #[test]
    fn refusals_are_typed_at_plan_time() {
        assert_eq!(
            SubagentBudgetPlan::split(20_000, 0),
            Err(SubagentPartitionError::ZeroChildren)
        );
        assert_eq!(
            SubagentBudgetPlan::split(20_000, MAX_SUBAGENT_CHILDREN + 1),
            Err(SubagentPartitionError::TooManyChildren)
        );
        assert_eq!(
            SubagentBudgetPlan::split(0, 1),
            Err(SubagentPartitionError::ZeroChildCap)
        );
        assert_eq!(
            SubagentBudgetPlan::split(3, 4),
            Err(SubagentPartitionError::ZeroChildCap)
        );
        assert_eq!(
            SubagentPartitionError::ZeroChildren.class_label(),
            "fanout.zero_children"
        );
        assert_eq!(
            SubagentPartitionError::TooManyChildren.class_label(),
            "fanout.too_many_children"
        );
        assert_eq!(
            SubagentPartitionError::ZeroChildCap.class_label(),
            "fanout.zero_child_cap"
        );
    }

    /// Child budgets mint the equal slice, are index-range-checked, and
    /// each child charges its OWN slice (isolation at the budget layer).
    #[test]
    fn child_budgets_are_isolated_slices() {
        let plan = SubagentBudgetPlan::split(20_000, 4).expect("valid plan");
        assert_eq!(plan.child_cap_u32(), 5_000);
        assert_eq!(plan.total_children_cap_u32(), 20_000);
        assert_eq!(plan.remainder_u32(), 0);

        let mut a = plan.child_budget(0).expect("child 0");
        let b = plan.child_budget(3).expect("child 3");
        assert!(plan.child_budget(4).is_none(), "index past the plan");

        // Charging child A's slice does not touch child B's.
        assert!(a.try_charge(crate::llm::TokenCount::new(5_000)).is_ok());
        assert!(a.is_exhausted());
        assert_eq!(b.remaining_u32(), 5_000);
    }
}
