//! Operational tool-adapter budget bridge.
//!
//! The normalized [`ToolCallView`] (adapter, capabilities, sandbox tier, risk,
//! approval, and state) and the [`BudgetCap`] ledger are minted upstream. This
//! module *bridges* them: every Python / MCP / CLI / HTTP / WASM tool call shares one
//! capability diff, sandbox tier, and the same token/cost/latency budget, and
//! must pass both the capability/approval gate and the budget gate before
//! dispatch. Network egress (an HTTP service, or any `Network` capability) is
//! denied at the bridge by default; only an [`ToolState::Approved`] tool may run.
//!
//! The bridge reuses the canonical [`BudgetCap`] *ledger* via its
//! [`BudgetCap::view`] (token / cost remaining + deadline) and applies a
//! tool-call gate — distinct from the consult-state token cap, which is for
//! frontier consults, not tool calls. Pure projection; no tool is executed.
//!
//! Reuse (no reinvention): [`ToolCallView`] / [`ToolAdapterKind`] /
//! [`ToolState`] from [`crate::commands::tool`]; [`BudgetCap`] / [`BudgetCharge`]
//! / [`BudgetReject`] from [`crate::commands::budget`]; [`CapabilityKind`] /
//! [`CapabilitySet`] from [`crate::commands::capability`].

use crate::commands::budget::{BudgetCap, BudgetCharge, BudgetReject};
use crate::commands::capability::{CapabilityKind, CapabilitySet};
use crate::commands::tool::{ToolAdapterKind, ToolCallView, ToolState};

/// Why the tool budget bridge refused a dispatch (fail-closed).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ToolBridgeReject {
    /// The tool is not in [`ToolState::Approved`] — it may not run.
    NotApproved,
    /// Network egress (HTTP service / `Network` capability) is denied by default.
    NetworkEgressDenied,
    /// The shared budget ledger refused the dispatch.
    Budget(BudgetReject),
}

/// The bridge view of a tool call: adapter, sandbox tier, capability diff, the
/// network-egress flag, and whether the tool is runnable.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ToolBridgeView {
    /// The backing adapter.
    pub adapter: ToolAdapterKind,
    /// The visible sandbox tier.
    pub sandbox_tier_u8: u8,
    /// Whether the tool requests network egress (HTTP service / `Network` cap).
    pub network_egress: bool,
    /// The effective capability set (the capability diff surface).
    pub capabilities: CapabilitySet,
    /// Whether the tool is runnable (approved and not network-denied).
    pub runnable: bool,
}

/// A tool dispatch to be gated against the shared budget. Unlike a frontier
/// consult, a tool call is not subject to the consult-state token cap.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ToolDispatch {
    /// Tokens (input + output) the call will charge.
    pub tokens_u32: u32,
    /// Cost in micro-units the call will charge.
    pub cost_micro_u64: u64,
    /// Projected wall-time of the call in milliseconds.
    pub projected_ms_u32: u32,
}

/// Whether a tool call requests network egress: an HTTP-service adapter, or any
/// tool that declares the `Network` capability.
#[must_use]
pub fn requests_network_egress(view: &ToolCallView) -> bool {
    matches!(view.adapter, ToolAdapterKind::HttpService)
        || view.capabilities.contains(CapabilityKind::Network)
}

/// The bridge view of a tool call.
#[must_use]
pub fn bridge_view(view: &ToolCallView) -> ToolBridgeView {
    let network_egress = requests_network_egress(view);
    ToolBridgeView {
        adapter: view.adapter,
        sandbox_tier_u8: view.sandbox_tier_u8,
        network_egress,
        capabilities: view.capabilities,
        runnable: matches!(view.state, ToolState::Approved) && !network_egress,
    }
}

/// Authorize a tool dispatch against the shared budget. Fail-closed: an
/// unapproved tool, a network-egress tool, or a dispatch that exceeds the
/// remaining budget / deadline is refused. On success returns the
/// [`BudgetCharge`] to apply to the ledger after the call completes.
pub fn authorize(
    view: &ToolCallView,
    cap: &BudgetCap,
    dispatch: &ToolDispatch,
) -> Result<BudgetCharge, ToolBridgeReject> {
    if !matches!(view.state, ToolState::Approved) {
        return Err(ToolBridgeReject::NotApproved);
    }
    if requests_network_egress(view) {
        return Err(ToolBridgeReject::NetworkEgressDenied);
    }
    let ledger = cap.view();
    if dispatch.projected_ms_u32 > ledger.deadline_ms_u32 {
        return Err(ToolBridgeReject::Budget(BudgetReject::DeadlineExceeded));
    }
    if dispatch.tokens_u32 > ledger.token_remaining_u32 {
        return Err(ToolBridgeReject::Budget(BudgetReject::TokenBudgetExceeded));
    }
    if dispatch.cost_micro_u64 > ledger.cost_remaining_micro_u64 {
        return Err(ToolBridgeReject::Budget(BudgetReject::CostBudgetExceeded));
    }
    Ok(BudgetCharge {
        tokens_u32: dispatch.tokens_u32,
        cost_micro_u64: dispatch.cost_micro_u64,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::command::{ApprovalRequirement, CommandRisk, approval_for};
    use crate::repl::latency::p95_ms;

    fn view(
        adapter: ToolAdapterKind,
        caps: CapabilitySet,
        state: ToolState,
        risk: CommandRisk,
    ) -> ToolCallView {
        ToolCallView {
            adapter,
            tool_id_hash_32: [1u8; 32],
            capabilities: caps,
            sandbox_tier_u8: 4,
            risk,
            approval: approval_for(risk),
            state,
        }
    }

    fn generous_cap() -> BudgetCap {
        BudgetCap::new(100_000, 1_000_000, 100_000)
    }

    fn dispatch() -> ToolDispatch {
        ToolDispatch {
            tokens_u32: 100,
            cost_micro_u64: 10,
            projected_ms_u32: 100,
        }
    }

    #[test]
    fn cli_read_only_allowed() {
        let v = view(
            ToolAdapterKind::CliBinary,
            CapabilitySet::with(CapabilityKind::ReadLocal),
            ToolState::Approved,
            CommandRisk::ReadOnly,
        );
        assert_eq!(view_approval(&v), ApprovalRequirement::None);
        assert!(authorize(&v, &generous_cap(), &dispatch()).is_ok());
        assert!(bridge_view(&v).runnable);
    }

    fn view_approval(v: &ToolCallView) -> ApprovalRequirement {
        v.approval
    }

    #[test]
    fn http_denied() {
        let v = view(
            ToolAdapterKind::HttpService,
            CapabilitySet::with(CapabilityKind::Network),
            ToolState::Approved,
            CommandRisk::Network,
        );
        assert_eq!(
            authorize(&v, &generous_cap(), &dispatch()),
            Err(ToolBridgeReject::NetworkEgressDenied)
        );
        assert!(!bridge_view(&v).runnable);
    }

    #[test]
    fn mcp_allowed() {
        let v = view(
            ToolAdapterKind::Mcp,
            CapabilitySet::with(CapabilityKind::ReadLocal),
            ToolState::Approved,
            CommandRisk::ReadOnly,
        );
        assert!(authorize(&v, &generous_cap(), &dispatch()).is_ok());
    }

    #[test]
    fn python_sandbox_visible() {
        let v = view(
            ToolAdapterKind::Python,
            CapabilitySet::with(CapabilityKind::PureCompute),
            ToolState::Approved,
            CommandRisk::ReadOnly,
        );
        let bv = bridge_view(&v);
        assert_eq!(bv.adapter, ToolAdapterKind::Python);
        assert_eq!(bv.sandbox_tier_u8, 4, "sandbox tier must be visible");
        assert!(authorize(&v, &generous_cap(), &dispatch()).is_ok());
    }

    #[test]
    fn budget_lower_denies() {
        let v = view(
            ToolAdapterKind::CliBinary,
            CapabilitySet::with(CapabilityKind::ReadLocal),
            ToolState::Approved,
            CommandRisk::ReadOnly,
        );
        // token cap below the dispatch's 100 tokens
        let tight = BudgetCap::new(5, 1_000_000, 100_000);
        assert_eq!(
            authorize(&v, &tight, &dispatch()),
            Err(ToolBridgeReject::Budget(BudgetReject::TokenBudgetExceeded))
        );
    }

    #[test]
    fn capability_diff_visible() {
        let caps =
            CapabilitySet::with(CapabilityKind::ReadLocal).insert(CapabilityKind::PureCompute);
        let v = view(
            ToolAdapterKind::Mcp,
            caps,
            ToolState::Approved,
            CommandRisk::ReadOnly,
        );
        let bv = bridge_view(&v);
        assert!(bv.capabilities.contains(CapabilityKind::ReadLocal));
        assert!(bv.capabilities.contains(CapabilityKind::PureCompute));
        assert!(!bv.capabilities.contains(CapabilityKind::Network));
    }

    #[test]
    fn unapproved_tool_cannot_run() {
        let v = view(
            ToolAdapterKind::CliBinary,
            CapabilitySet::with(CapabilityKind::ReadLocal),
            ToolState::Registered,
            CommandRisk::ReadOnly,
        );
        assert_eq!(
            authorize(&v, &generous_cap(), &dispatch()),
            Err(ToolBridgeReject::NotApproved)
        );
        assert!(!bridge_view(&v).runnable);
    }

    #[test]
    fn bridge_route_p95_within_10ms() {
        let v = view(
            ToolAdapterKind::CliBinary,
            CapabilitySet::with(CapabilityKind::ReadLocal),
            ToolState::Approved,
            CommandRisk::ReadOnly,
        );
        let cap = generous_cap();
        let d = dispatch();
        let mut samples = Vec::with_capacity(256);
        for _ in 0..256 {
            let t = std::time::Instant::now();
            let r = authorize(&v, &cap, &d);
            std::hint::black_box(&r);
            samples.push(t.elapsed().as_nanos() as u64);
        }
        let p95 = p95_ms(&samples) / 1_000_000;
        assert!(p95 <= 10, "tool bridge route p95 {p95}ms exceeds 10ms");
    }
}
