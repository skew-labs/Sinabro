//! RepairTrace → MURPHY tree builder.
//!
//! Defines the `RepairStep` / `RepairTrace` registry types and turns a repair
//! trace into a [`MurphyNode`] chain plus a [`MurphyTree`] summary.
//!
//! # Design rationale
//!
//! Failed attempts get success credit **only if a later verified success exists
//! in the same leakage group and privacy passes**. A `RepairTrace` is one
//! atom's repair sequence (one `key`), so its steps are inherently one leakage
//! group; the "later verified success" is `final_pass == true`. When there is no
//! verified success, or privacy did not pass, every node's credit stays `0` — a
//! failed trajectory is kept as data but never rewarded. Credit flows back from
//! the terminal success node, discounted by `gamma` per hop, so the step nearest
//! the fix earns the most.
use crate::StageETraceLink;
use crate::command_manifest::CommandResult;
use crate::diet_kind::AtomDietKey;
use crate::error::DietResult;

use super::schema::{FailureKind, MurphyNode, MurphyTree, nodes_hash, validate_nodes};

/// Default per-hop success-credit discount (0.85 in basis points).
pub const GAMMA_BPS_DEFAULT: u16 = 8500;

/// Full success credit assigned to the terminal verified-success node (milli).
const ONE_MILLI: i32 = 1000;

/// One step of a repair trace.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub struct RepairStep {
    /// The step index within the trace.
    pub step_u16: u16,
    /// The failure surface this step hit.
    pub failure: FailureKind,
    /// The replay-addressable command result for this step.
    pub command: CommandResult,
    /// `sha256` of the diff this step produced.
    pub diff_hash_32: [u8; 32],
}

impl RepairStep {
    /// Construct a repair step.
    pub const fn new(
        step_u16: u16,
        failure: FailureKind,
        command: CommandResult,
        diff_hash_32: [u8; 32],
    ) -> Self {
        Self {
            step_u16,
            failure,
            command,
            diff_hash_32,
        }
    }
}

/// A full repair trace for one source atom.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RepairTrace {
    /// The source atom.
    pub key: AtomDietKey,
    /// The ordered repair steps (oldest first).
    pub steps: Vec<RepairStep>,
    /// Whether the trace ended in a verified success.
    pub final_pass: bool,
    /// Stage E trace stamp.
    pub trace: StageETraceLink,
}

impl RepairTrace {
    /// Construct a repair trace.
    pub const fn new(
        key: AtomDietKey,
        steps: Vec<RepairStep>,
        final_pass: bool,
        trace: StageETraceLink,
    ) -> Self {
        Self {
            key,
            steps,
            final_pass,
            trace,
        }
    }
}

/// Clamp an `i32` credit into the `i16` success-credit range.
const fn clamp_i16(v: i32) -> i16 {
    if v > i16::MAX as i32 {
        i16::MAX
    } else if v < i16::MIN as i32 {
        i16::MIN
    } else {
        v as i16
    }
}

/// Build a MURPHY node chain + tree summary from `trace`.
///
/// Nodes form a linear chain (step `i` is the child of step `i-1`); the first
/// step is the root. Success credit is back-propagated from the terminal node
/// **only** when `trace.final_pass && privacy_pass`; otherwise every node stays
/// at `0`. The result is validated (acyclic, closed) before return. Deterministic
/// and `O(n)` — a 100k-step trace builds identically on every run.
pub fn build_tree(
    trace: &RepairTrace,
    privacy_pass: bool,
    gamma_bps: u16,
) -> DietResult<(Vec<MurphyNode>, MurphyTree)> {
    let n = trace.steps.len();
    let mut nodes: Vec<MurphyNode> = Vec::with_capacity(n);
    for (i, step) in trace.steps.iter().enumerate() {
        let id = (i as u64) + 1;
        let parent = if i == 0 { None } else { Some(i as u64) };
        nodes.push(MurphyNode::new(
            id,
            parent,
            trace.key,
            step.step_u16,
            step.failure,
            0,
        ));
    }

    if trace.final_pass && privacy_pass && n > 0 {
        let mut credit: i32 = ONE_MILLI;
        for node in nodes.iter_mut().rev() {
            node.success_credit_milli_i16 = clamp_i16(credit);
            credit = (credit * gamma_bps as i32) / 10000;
        }
    }

    validate_nodes(&nodes)?;
    let root_id = nodes.first().map_or(0, |r| r.node_id_u64);
    let tree = MurphyTree::new(root_id, nodes_hash(&nodes), gamma_bps);
    Ok((nodes, tree))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::command_manifest::CommandExitClass;
    use crate::diet_kind::DietSourceStage;

    fn key() -> AtomDietKey {
        AtomDietKey::new(DietSourceStage::Phase0, 387)
    }

    fn cmd(exit: CommandExitClass) -> CommandResult {
        CommandResult::new([0u8; 32], exit, 0, 0)
    }

    fn trace(steps: Vec<RepairStep>, final_pass: bool) -> RepairTrace {
        RepairTrace::new(
            key(),
            steps,
            final_pass,
            StageETraceLink::new([0u8; 32], 387, 1),
        )
    }

    #[test]
    fn fail_then_fix_credits_both_steps() -> DietResult<()> {
        let steps = vec![
            RepairStep::new(
                0,
                FailureKind::Compile,
                cmd(CommandExitClass::Fail),
                [1u8; 32],
            ),
            RepairStep::new(1, FailureKind::Test, cmd(CommandExitClass::Pass), [2u8; 32]),
        ];
        let (nodes, tree) = build_tree(&trace(steps, true), true, GAMMA_BPS_DEFAULT)?;
        // terminal node gets full credit; the earlier failure gets gamma-discounted.
        assert_eq!(nodes[1].success_credit_milli_i16, 1000);
        assert_eq!(nodes[0].success_credit_milli_i16, 850);
        assert_eq!(tree.gamma_bps_u16, 8500);
        assert_eq!(tree.root_id_u64, 1);
        Ok(())
    }

    #[test]
    fn multi_fail_then_success_back_propagates_with_gamma() -> DietResult<()> {
        let steps = vec![
            RepairStep::new(
                0,
                FailureKind::Compile,
                cmd(CommandExitClass::Fail),
                [1u8; 32],
            ),
            RepairStep::new(
                1,
                FailureKind::Clippy,
                cmd(CommandExitClass::Fail),
                [2u8; 32],
            ),
            RepairStep::new(2, FailureKind::Test, cmd(CommandExitClass::Pass), [3u8; 32]),
        ];
        let (nodes, _) = build_tree(&trace(steps, true), true, GAMMA_BPS_DEFAULT)?;
        assert_eq!(nodes[2].success_credit_milli_i16, 1000);
        assert_eq!(nodes[1].success_credit_milli_i16, 850);
        assert_eq!(nodes[0].success_credit_milli_i16, 722); // 850 * 0.85 floored
        Ok(())
    }

    #[test]
    fn no_success_no_credit() -> DietResult<()> {
        let steps = vec![
            RepairStep::new(
                0,
                FailureKind::Compile,
                cmd(CommandExitClass::Fail),
                [1u8; 32],
            ),
            RepairStep::new(
                1,
                FailureKind::Compile,
                cmd(CommandExitClass::Fail),
                [2u8; 32],
            ),
        ];
        let (nodes, _) = build_tree(&trace(steps, false), true, GAMMA_BPS_DEFAULT)?;
        assert!(nodes.iter().all(|n| n.success_credit_milli_i16 == 0));
        Ok(())
    }

    #[test]
    fn privacy_reject_no_credit() -> DietResult<()> {
        let steps = vec![RepairStep::new(
            0,
            FailureKind::Test,
            cmd(CommandExitClass::Pass),
            [1u8; 32],
        )];
        // final_pass=true but privacy_pass=false ⇒ no credit.
        let (nodes, _) = build_tree(&trace(steps, true), false, GAMMA_BPS_DEFAULT)?;
        assert_eq!(nodes[0].success_credit_milli_i16, 0);
        Ok(())
    }

    #[test]
    fn build_100k_steps_is_deterministic() -> DietResult<()> {
        let steps: Vec<RepairStep> = (0..100_000u32)
            .map(|i| {
                RepairStep::new(
                    (i & 0xffff) as u16,
                    FailureKind::Compile,
                    cmd(CommandExitClass::Fail),
                    [(i % 251) as u8; 32],
                )
            })
            .collect();
        let t = trace(steps, true);
        let (_, tree_a) = build_tree(&t, true, GAMMA_BPS_DEFAULT)?;
        let (_, tree_b) = build_tree(&t, true, GAMMA_BPS_DEFAULT)?;
        assert_eq!(tree_a, tree_b);
        Ok(())
    }
}
