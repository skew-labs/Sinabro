//! Token / cost / deadline budget cap enforcement (atom #433 F.3.6).
//!
//! `sinabro budget cap` / the `/budget` slash command. The budget gate is a
//! **control-express** check: it runs *before* a dispatch is sent, never after a
//! provider response, so an over-budget call is refused before it can cost
//! anything (`G-F-SAFETY`, `G-F-CONTROL-EXPRESS`). The check is a pure,
//! synchronous projection (no provider/network call) so it preempts the model
//! path within the 5ms cap-check budget.
//!
//! The adaptive consult-state caps are hard and reuse the canonical
//! [`consult_token_cap`] (`G-F-ADAPTIVE-ROUTER`): `Fast`/`Normal`/`Lockdown`
//! deny a standard bounded consult outright (0 external tokens, approval cannot
//! rescue them — escalation goes through an explicit route transition);
//! `Slow`/`Stuck`/`Audit` allow a bounded consult up to their cap and require an
//! explicit approval (+ visible reason + route trace) to exceed it; `UserFull`
//! is the explicit user-requested full run, allowed only with that same explicit
//! approval. Every cap-exceeding dispatch needs an estimate, a reason, an
//! approval, and a route trace before it is allowed.
//!
//! Reuse (no reinvention): the saturating-ledger / refusal-channel semantics
//! mirror Stage A's `DailyTokenBudget` (`crates/m-agent/src/loop_budget.rs`),
//! modeled here as a local enforcement view rather than imported.

use crate::commands::model_route::consult_token_cap;
use crate::route::RouteExecutionState;
use crate::tui::RenderTruth;

const ZERO32: [u8; 32] = [0u8; 32];

/// The MNEMOS Phase-0 per-call input-token ceiling: no single dispatch may send
/// more than this many input tokens, regardless of route state or approval. A
/// hard operational cap (the ≤5000 input/call goal), tighter than — and composed
/// on top of — the per-state consult caps, so a cap-less call is structurally
/// impossible.
pub const MAX_INPUT_TOKENS_PER_CALL: u32 = 5_000;

/// Whether a dispatch's input-token estimate is within the hard per-call input
/// ceiling [`MAX_INPUT_TOKENS_PER_CALL`].
#[must_use]
pub const fn within_per_call_input_cap(input_tokens_u32: u32) -> bool {
    input_tokens_u32 <= MAX_INPUT_TOKENS_PER_CALL
}

/// Why the budget gate refused a dispatch (fail-closed). Every reason renders
/// `Red`.
#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BudgetReject {
    /// No cost estimate was supplied — an estimate is mandatory before dispatch.
    MissingCostEstimate = 1,
    /// The projected time exceeds the deadline.
    DeadlineExceeded = 2,
    /// A consult on a `Fast`/`Normal`/`Lockdown` route (0-token cap) — denied
    /// outright; approval cannot rescue it.
    ConsultDeniedForState = 3,
    /// Input/output tokens exceed the route-state cap and the dispatch lacks the
    /// required approval (+ reason + route trace).
    UnapprovedCapExceed = 4,
    /// Tokens exceed the remaining token budget.
    TokenBudgetExceeded = 5,
    /// Cost exceeds the remaining cost budget.
    CostBudgetExceeded = 6,
}

impl BudgetReject {
    /// A rejected dispatch always renders `Red` (cap-exceed is never healthy).
    #[must_use]
    pub const fn render_truth(self) -> RenderTruth {
        RenderTruth::Red
    }
}

/// The charge a dispatch would incur, returned by a successful authorization so
/// the caller can [`BudgetCap::apply`] it after the dispatch completes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BudgetCharge {
    /// Total tokens (input + output) to charge.
    pub tokens_u32: u32,
    /// Cost in micro-units to charge.
    pub cost_micro_u64: u64,
}

/// A dispatch request to be gated *before* it is sent.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DispatchRequest {
    /// The route state the dispatch runs under.
    pub route_state: RouteExecutionState,
    /// Estimated input tokens.
    pub input_tokens_u32: u32,
    /// Estimated output tokens.
    pub output_tokens_u32: u32,
    /// Estimated cost in micro-units — `None` means no estimate (refused).
    pub estimated_cost_micro: Option<u64>,
    /// Projected wall-time of the dispatch in milliseconds.
    pub projected_ms_u32: u32,
    /// Whether the dispatch carries an explicit approval (for cap-exceed / `UserFull`).
    pub approved: bool,
    /// SHA-256 of the visible reason (zero = no visible reason).
    pub reason_hash_32: [u8; 32],
    /// SHA-256 of the attached route trace (zero = no route trace).
    pub route_trace_hash_32: [u8; 32],
}

impl DispatchRequest {
    /// Whether this request carries the full explicit-approval evidence:
    /// approved flag + visible reason + route trace.
    #[must_use]
    pub fn has_explicit_approval(&self) -> bool {
        self.approved && self.reason_hash_32 != ZERO32 && self.route_trace_hash_32 != ZERO32
    }
}

/// The remaining budget. A saturating ledger (mirrors `DailyTokenBudget`):
/// `spent <= cap` always holds and arithmetic never overflows.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BudgetCap {
    token_cap_u32: u32,
    token_spent_u32: u32,
    cost_cap_micro_u64: u64,
    cost_spent_micro_u64: u64,
    deadline_ms_u32: u32,
}

impl BudgetCap {
    /// A new budget with a token cap, a cost cap (micro-units), and a deadline.
    #[must_use]
    pub const fn new(token_cap_u32: u32, cost_cap_micro_u64: u64, deadline_ms_u32: u32) -> Self {
        Self {
            token_cap_u32,
            token_spent_u32: 0,
            cost_cap_micro_u64,
            cost_spent_micro_u64: 0,
            deadline_ms_u32,
        }
    }

    /// Tokens remaining (saturating).
    #[must_use]
    pub const fn token_remaining(self) -> u32 {
        self.token_cap_u32.saturating_sub(self.token_spent_u32)
    }

    /// Cost remaining in micro-units (saturating).
    #[must_use]
    pub const fn cost_remaining_micro(self) -> u64 {
        self.cost_cap_micro_u64
            .saturating_sub(self.cost_spent_micro_u64)
    }

    /// The micro-unit budget the job rail syncs to (= cost remaining).
    #[must_use]
    pub const fn job_rail_remaining_micros(self) -> u64 {
        self.cost_remaining_micro()
    }

    /// Authorize a dispatch **before** it is sent. Returns the [`BudgetCharge`]
    /// to apply on success, or a [`BudgetReject`] (fail-closed) otherwise. This
    /// is a pure check — it never mutates the ledger and never calls a provider.
    ///
    /// Order: estimate present → deadline → route-state consult cap → token
    /// budget → cost budget.
    pub fn authorize(&self, req: &DispatchRequest) -> Result<BudgetCharge, BudgetReject> {
        let Some(estimated_cost_micro) = req.estimated_cost_micro else {
            return Err(BudgetReject::MissingCostEstimate);
        };
        if req.projected_ms_u32 > self.deadline_ms_u32 {
            return Err(BudgetReject::DeadlineExceeded);
        }
        let (cap_in, cap_out) = consult_token_cap(req.route_state);
        let over_cap = req.input_tokens_u32 > cap_in || req.output_tokens_u32 > cap_out;
        if over_cap {
            // Fast/Normal/Lockdown have a 0-token cap that approval cannot lift.
            if matches!(
                req.route_state,
                RouteExecutionState::Fast
                    | RouteExecutionState::Normal
                    | RouteExecutionState::Lockdown
            ) {
                return Err(BudgetReject::ConsultDeniedForState);
            }
            // Slow/Stuck/Audit over-cap, or UserFull: explicit approval required.
            if !req.has_explicit_approval() {
                return Err(BudgetReject::UnapprovedCapExceed);
            }
        }
        let tokens = req.input_tokens_u32.saturating_add(req.output_tokens_u32);
        if tokens > self.token_remaining() {
            return Err(BudgetReject::TokenBudgetExceeded);
        }
        if estimated_cost_micro > self.cost_remaining_micro() {
            return Err(BudgetReject::CostBudgetExceeded);
        }
        Ok(BudgetCharge {
            tokens_u32: tokens,
            cost_micro_u64: estimated_cost_micro,
        })
    }

    /// Apply a charge to the ledger after a dispatch completes (saturating; the
    /// `spent <= cap` invariant is preserved by clamping).
    pub fn apply(&mut self, charge: BudgetCharge) {
        self.token_spent_u32 = self
            .token_spent_u32
            .saturating_add(charge.tokens_u32)
            .min(self.token_cap_u32);
        self.cost_spent_micro_u64 = self
            .cost_spent_micro_u64
            .saturating_add(charge.cost_micro_u64)
            .min(self.cost_cap_micro_u64);
    }

    /// The `/budget` display projection.
    #[must_use]
    pub const fn view(self) -> BudgetView {
        let truth = if self.token_remaining() == 0 || self.cost_remaining_micro() == 0 {
            RenderTruth::Red
        } else {
            RenderTruth::Green
        };
        BudgetView {
            token_remaining_u32: self.token_remaining(),
            cost_remaining_micro_u64: self.cost_remaining_micro(),
            deadline_ms_u32: self.deadline_ms_u32,
            truth,
        }
    }
}

/// The `/budget` status display.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BudgetView {
    /// Tokens remaining.
    pub token_remaining_u32: u32,
    /// Cost remaining (micro-units).
    pub cost_remaining_micro_u64: u64,
    /// Deadline (ms).
    pub deadline_ms_u32: u32,
    /// Truth: `Red` when token or cost budget is exhausted, else `Green`.
    pub truth: RenderTruth,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::repl::latency::p95_ms;

    fn req(state: RouteExecutionState, input: u32, output: u32) -> DispatchRequest {
        DispatchRequest {
            route_state: state,
            input_tokens_u32: input,
            output_tokens_u32: output,
            estimated_cost_micro: Some(10),
            projected_ms_u32: 100,
            approved: false,
            reason_hash_32: ZERO32,
            route_trace_hash_32: ZERO32,
        }
    }

    fn approve(mut r: DispatchRequest) -> DispatchRequest {
        r.approved = true;
        r.reason_hash_32 = [1u8; 32];
        r.route_trace_hash_32 = [2u8; 32];
        r
    }

    #[test]
    fn over_token_cap_is_rejected() {
        let cap = BudgetCap::new(100, 1_000_000, 10_000);
        // Slow cap is (8000,2000) so 60+40 passes the consult cap; the 100-token
        // budget is the binding limit: 60+50 = 110 > 100 remaining.
        let r = req(RouteExecutionState::Slow, 60, 50);
        assert_eq!(cap.authorize(&r), Err(BudgetReject::TokenBudgetExceeded));
    }

    #[test]
    fn deadline_exceeded_is_rejected() {
        let cap = BudgetCap::new(100_000, 1_000_000, 50);
        let mut r = req(RouteExecutionState::Slow, 10, 10);
        r.projected_ms_u32 = 80; // > 50ms deadline
        assert_eq!(cap.authorize(&r), Err(BudgetReject::DeadlineExceeded));
    }

    #[test]
    fn budget_display_reflects_remaining() {
        let mut cap = BudgetCap::new(1_000, 5_000, 30_000);
        cap.apply(BudgetCharge {
            tokens_u32: 200,
            cost_micro_u64: 1_000,
        });
        let v = cap.view();
        assert_eq!(v.token_remaining_u32, 800);
        assert_eq!(v.cost_remaining_micro_u64, 4_000);
        assert_eq!(v.truth, RenderTruth::Green);
    }

    #[test]
    fn job_rail_syncs_to_remaining_cost() {
        let mut cap = BudgetCap::new(1_000, 5_000, 30_000);
        assert_eq!(cap.job_rail_remaining_micros(), 5_000);
        cap.apply(BudgetCharge {
            tokens_u32: 10,
            cost_micro_u64: 1_500,
        });
        assert_eq!(cap.job_rail_remaining_micros(), 3_500);
    }

    #[test]
    fn fast_normal_consult_denied_outright() {
        let cap = BudgetCap::new(100_000, 1_000_000, 100_000);
        for state in [RouteExecutionState::Fast, RouteExecutionState::Normal] {
            // even with explicit approval, a 0-token-cap state denies the consult
            let r = approve(req(state, 1, 1));
            assert_eq!(
                cap.authorize(&r),
                Err(BudgetReject::ConsultDeniedForState),
                "{state:?} must deny a standard bounded consult"
            );
        }
    }

    #[test]
    fn slow_within_cap_is_allowed_over_cap_needs_approval() {
        let cap = BudgetCap::new(100_000, 1_000_000, 100_000);
        // within Slow cap (8000/2000): allowed, no approval needed
        assert!(
            cap.authorize(&req(RouteExecutionState::Slow, 8_000, 2_000))
                .is_ok()
        );
        // over the input cap, unapproved -> rejected
        assert_eq!(
            cap.authorize(&req(RouteExecutionState::Slow, 8_001, 2_000)),
            Err(BudgetReject::UnapprovedCapExceed)
        );
        // over cap WITH explicit approval -> allowed
        assert!(
            cap.authorize(&approve(req(RouteExecutionState::Slow, 8_001, 2_000)))
                .is_ok()
        );
    }

    #[test]
    fn stuck_and_audit_caps_are_enforced() {
        let cap = BudgetCap::new(100_000, 1_000_000, 100_000);
        // Stuck cap (16000/4000)
        assert!(
            cap.authorize(&req(RouteExecutionState::Stuck, 16_000, 4_000))
                .is_ok()
        );
        assert_eq!(
            cap.authorize(&req(RouteExecutionState::Stuck, 16_001, 4_000)),
            Err(BudgetReject::UnapprovedCapExceed)
        );
        // Audit cap (12000/4000)
        assert!(
            cap.authorize(&req(RouteExecutionState::Audit, 12_000, 4_000))
                .is_ok()
        );
        assert_eq!(
            cap.authorize(&req(RouteExecutionState::Audit, 12_000, 4_001)),
            Err(BudgetReject::UnapprovedCapExceed)
        );
    }

    #[test]
    fn user_full_requires_explicit_approval() {
        let cap = BudgetCap::new(100_000, 1_000_000, 100_000);
        // UserFull cap is (0,0): any consult is over-cap and needs explicit approval
        assert_eq!(
            cap.authorize(&req(RouteExecutionState::UserFull, 100, 50)),
            Err(BudgetReject::UnapprovedCapExceed)
        );
        assert!(
            cap.authorize(&approve(req(RouteExecutionState::UserFull, 100, 50)))
                .is_ok(),
            "UserFull with explicit approval must be allowed"
        );
    }

    #[test]
    fn cost_estimate_is_required() {
        let cap = BudgetCap::new(100_000, 1_000_000, 100_000);
        let mut r = req(RouteExecutionState::Slow, 10, 10);
        r.estimated_cost_micro = None;
        assert_eq!(cap.authorize(&r), Err(BudgetReject::MissingCostEstimate));
    }

    #[test]
    fn cap_exceed_renders_red() {
        assert_eq!(
            BudgetReject::TokenBudgetExceeded.render_truth(),
            RenderTruth::Red
        );
        assert_eq!(
            BudgetReject::ConsultDeniedForState.render_truth(),
            RenderTruth::Red
        );
        // exhausted budget view is red
        let mut cap = BudgetCap::new(100, 100, 10_000);
        cap.apply(BudgetCharge {
            tokens_u32: 100,
            cost_micro_u64: 100,
        });
        assert_eq!(cap.view().truth, RenderTruth::Red);
    }

    #[test]
    fn cost_budget_exceeded_is_rejected() {
        let cap = BudgetCap::new(100_000, 50, 100_000);
        let mut r = req(RouteExecutionState::Slow, 10, 10);
        r.estimated_cost_micro = Some(60); // > 50 cost cap
        assert_eq!(cap.authorize(&r), Err(BudgetReject::CostBudgetExceeded));
    }

    #[test]
    fn per_call_input_cap_boundary_is_5000() {
        assert_eq!(MAX_INPUT_TOKENS_PER_CALL, 5_000);
        assert!(within_per_call_input_cap(0));
        assert!(within_per_call_input_cap(MAX_INPUT_TOKENS_PER_CALL));
        assert!(!within_per_call_input_cap(MAX_INPUT_TOKENS_PER_CALL + 1));
        assert!(
            !within_per_call_input_cap(8_000),
            "even Slow's 8000 consult cap is over the hard 5000 input ceiling"
        );
    }

    #[test]
    fn cap_check_p95_within_5ms_budget() {
        let cap = BudgetCap::new(100_000, 1_000_000, 100_000);
        let r = req(RouteExecutionState::Slow, 1_000, 500);
        let mut samples = Vec::with_capacity(256);
        for _ in 0..256 {
            let t = std::time::Instant::now();
            let v = cap.authorize(&r);
            std::hint::black_box(&v);
            samples.push(t.elapsed().as_nanos() as u64);
        }
        let p95 = p95_ms(&samples) / 1_000_000;
        assert!(p95 <= 5, "budget cap-check p95 {p95}ms exceeds 5ms budget");
    }
}
