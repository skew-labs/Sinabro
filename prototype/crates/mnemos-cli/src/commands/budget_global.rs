//! Global budget command — the `/budget` slash command.
//!
//! `sinabro budget` / the `/budget` slash command, lifted from the per-dispatch
//! [`crate::commands::budget`] gate to a *global* budget that spans token, money
//! (micro-units), gas (`MIST`), wall-time (deadline), and live job count. An
//! overrun blocks dispatch *before* any side effect.
//!
//! `budget cap lower` is a control-plane **express** command, not a normal job:
//! it bypasses the background / full / replay / train queues and updates the
//! shared (version-stamped) cap before any next provider / tool / gas / wallet
//! side effect can start. A lower is one-way — a cap can
//! only tighten on the express path — so a tightened cap can never be silently
//! widened by a racing job, and every side effect must re-check the current cap
//! ([`GlobalBudget::preflight_recheck`]) before it runs.
//!
//! Reuse: the token / cost / deadline / route-consult / approval
//! decision is the canonical [`crate::commands::budget::BudgetCap`],
//! reconstructed from the current lowerable caps on each check so a
//! tightened cap is enforced without re-minting the authorize logic; the gas cap
//! is the canonical [`mnemos_d_move::GasBudgetMist`] typed unit; the
//! red/yellow/green verdict is [`crate::tui::RenderTruth`]. This
//! module performs no live action.

use crate::commands::budget::{
    BudgetCap, BudgetCharge, BudgetReject, DispatchRequest, within_per_call_input_cap,
};
use crate::tui::RenderTruth;
use mnemos_d_move::GasBudgetMist;

/// Why the global budget refused a dispatch (fail-closed). Every reason renders
/// `Red`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum GlobalBudgetReject {
    /// No cost estimate was supplied — an estimate is mandatory before dispatch.
    #[error("missing cost estimate")]
    MissingCostEstimate,
    /// Projected time exceeds the deadline (the time budget).
    #[error("deadline exceeded")]
    DeadlineExceeded,
    /// Tokens exceed the token budget.
    #[error("token budget exceeded")]
    TokenBudgetExceeded,
    /// A cap-exceeding dispatch lacks the required approval + reason + route trace.
    #[error("unapproved cap exceed")]
    UnapprovedCapExceed,
    /// Cost (money) exceeds the money budget.
    #[error("money budget exceeded")]
    MoneyBudgetExceeded,
    /// Gas exceeds the remaining gas budget.
    #[error("gas budget exceeded")]
    GasBudgetExceeded,
    /// Starting this dispatch would exceed the live job-count cap.
    #[error("job count exceeded")]
    JobCountExceeded,
    /// A single dispatch's input tokens exceed the hard per-call input ceiling
    /// ([`crate::commands::budget::MAX_INPUT_TOKENS_PER_CALL`], ≤5000) — refused
    /// regardless of route state or approval.
    #[error("per-call input cap exceeded")]
    PerCallInputCapExceeded,
}

impl GlobalBudgetReject {
    /// A rejected dispatch always renders `Red`.
    #[must_use]
    pub const fn render_truth(self) -> RenderTruth {
        RenderTruth::Red
    }

    /// Map a per-dispatch [`BudgetReject`] into the global taxonomy.
    const fn from_budget(r: BudgetReject) -> Self {
        match r {
            BudgetReject::MissingCostEstimate => Self::MissingCostEstimate,
            BudgetReject::DeadlineExceeded => Self::DeadlineExceeded,
            BudgetReject::ConsultDeniedForState | BudgetReject::UnapprovedCapExceed => {
                Self::UnapprovedCapExceed
            }
            BudgetReject::TokenBudgetExceeded => Self::TokenBudgetExceeded,
            BudgetReject::CostBudgetExceeded => Self::MoneyBudgetExceeded,
        }
    }
}

/// A dispatch to gate against the global budget: the per-dispatch
/// [`DispatchRequest`] (token / cost / deadline / route) plus the gas it would
/// spend and the job slots it would occupy.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct GlobalDispatch {
    /// The token / cost / deadline / route request (the canonical request type).
    pub request: DispatchRequest,
    /// Gas this dispatch would spend (`MIST`).
    pub gas_mist: GasBudgetMist,
    /// Live job slots this dispatch would occupy.
    pub job_slots_u32: u32,
}

/// The acknowledgement of an express `budget cap lower`: the new (tightened)
/// caps, the bumped shared version, and proof the express rail bypassed the
/// queue.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CapLowerAck {
    /// The shared cap version after the lower (monotonic).
    pub version_u32: u32,
    /// Always `true`: the express command bypassed the normal / background queues.
    pub bypassed_queue: bool,
    /// The token cap after the lower.
    pub token_cap_u32: u32,
    /// The money cap (micro-units) after the lower.
    pub money_cap_micro_u64: u64,
    /// The gas cap (`MIST`) after the lower.
    pub gas_cap_mist_u64: u64,
    /// The job-count cap after the lower.
    pub job_cap_u32: u32,
}

/// The global budget: a token / money / gas / job-count cap set (each
/// express-lowerable) plus a fixed time deadline, with a monotonic version that
/// the express `cap lower` bumps so two observers can confirm they read the same
/// (tightened) cap. The token / money / deadline / route decision reuses the
/// canonical [`BudgetCap`], reconstructed from the current caps on each check.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct GlobalBudget {
    token_cap_u32: u32,
    money_cap_micro_u64: u64,
    gas_cap_mist_u64: u64,
    job_cap_u32: u32,
    deadline_ms_u32: u32,
    token_spent_u32: u32,
    money_spent_micro_u64: u64,
    gas_spent_mist_u64: u64,
    jobs_live_u32: u32,
    version_u32: u32,
}

impl GlobalBudget {
    /// A new global budget from a *fresh* (unspent) token / cost / deadline
    /// [`BudgetCap`], a gas cap, and a live job-count cap.
    #[must_use]
    pub const fn new(cap: BudgetCap, gas_cap: GasBudgetMist, job_cap_u32: u32) -> Self {
        let v = cap.view();
        Self {
            token_cap_u32: v.token_remaining_u32,
            money_cap_micro_u64: v.cost_remaining_micro_u64,
            gas_cap_mist_u64: gas_cap.get(),
            job_cap_u32,
            deadline_ms_u32: v.deadline_ms_u32,
            token_spent_u32: 0,
            money_spent_micro_u64: 0,
            gas_spent_mist_u64: 0,
            jobs_live_u32: 0,
            version_u32: 0,
        }
    }

    /// The shared cap version (bumped by every express `cap lower`).
    #[must_use]
    pub const fn version(&self) -> u32 {
        self.version_u32
    }

    /// Remaining gas (`MIST`, saturating).
    #[must_use]
    pub const fn gas_remaining_mist(&self) -> u64 {
        self.gas_cap_mist_u64
            .saturating_sub(self.gas_spent_mist_u64)
    }

    /// Record the number of currently-live jobs (for the job-count cap check).
    pub const fn set_jobs_live(&mut self, jobs_live_u32: u32) {
        self.jobs_live_u32 = jobs_live_u32;
    }

    /// The canonical [`BudgetCap`] for the *current* token / money / deadline
    /// caps, with the already-spent amounts applied.
    fn current_cap(&self) -> BudgetCap {
        let mut c = BudgetCap::new(
            self.token_cap_u32,
            self.money_cap_micro_u64,
            self.deadline_ms_u32,
        );
        c.apply(BudgetCharge {
            tokens_u32: self.token_spent_u32,
            cost_micro_u64: self.money_spent_micro_u64,
        });
        c
    }

    /// Check a dispatch against every budget axis *before* it is sent. Pure (no
    /// mutation, no provider call), so it preempts the model path within the 5ms
    /// cap-check budget. Order: token / money / deadline / route / approval
    /// (canonical [`BudgetCap`]) → gas → job count.
    pub fn check(&self, d: &GlobalDispatch) -> Result<(), GlobalBudgetReject> {
        self.current_cap()
            .authorize(&d.request)
            .map_err(GlobalBudgetReject::from_budget)?;
        let gas = d.gas_mist.get();
        if gas.saturating_add(self.gas_spent_mist_u64) > self.gas_cap_mist_u64 {
            return Err(GlobalBudgetReject::GasBudgetExceeded);
        }
        if self.jobs_live_u32.saturating_add(d.job_slots_u32) > self.job_cap_u32 {
            return Err(GlobalBudgetReject::JobCountExceeded);
        }
        Ok(())
    }

    /// Re-check a dispatch against the *current* cap immediately before its side
    /// effect runs. Identical to [`Self::check`], named to mark the mandatory
    /// preflight re-check after a possible express `cap lower`
    /// (every side effect re-reads control state).
    pub fn preflight_recheck(&self, d: &GlobalDispatch) -> Result<(), GlobalBudgetReject> {
        self.check(d)
    }

    /// Authorize an *operational* dispatch: the hard per-call input ceiling
    /// ([`within_per_call_input_cap`], ≤5000 input tokens, no approval rescue) AND
    /// every global budget axis ([`Self::check`]). The input ceiling is checked
    /// first, so a runaway input is refused before anything else. Fail-closed —
    /// this is the live performance brain's per-call dispatch gate.
    pub fn authorize_operational_call(&self, d: &GlobalDispatch) -> Result<(), GlobalBudgetReject> {
        if !within_per_call_input_cap(d.request.input_tokens_u32) {
            return Err(GlobalBudgetReject::PerCallInputCapExceeded);
        }
        self.check(d)
    }

    /// Express `budget cap lower`: tighten the caps on the control plane, bump
    /// the shared version, and acknowledge on the hot path without entering any
    /// queue. Each cap moves to the *minimum* of its current and requested value
    /// (a lower is one-way — a cap is never widened here).
    pub const fn express_cap_lower(
        &mut self,
        token_cap_u32: u32,
        money_cap_micro_u64: u64,
        gas_cap_mist_u64: u64,
        job_cap_u32: u32,
    ) -> CapLowerAck {
        if token_cap_u32 < self.token_cap_u32 {
            self.token_cap_u32 = token_cap_u32;
        }
        if money_cap_micro_u64 < self.money_cap_micro_u64 {
            self.money_cap_micro_u64 = money_cap_micro_u64;
        }
        if gas_cap_mist_u64 < self.gas_cap_mist_u64 {
            self.gas_cap_mist_u64 = gas_cap_mist_u64;
        }
        if job_cap_u32 < self.job_cap_u32 {
            self.job_cap_u32 = job_cap_u32;
        }
        self.version_u32 = self.version_u32.saturating_add(1);
        CapLowerAck {
            version_u32: self.version_u32,
            bypassed_queue: true,
            token_cap_u32: self.token_cap_u32,
            money_cap_micro_u64: self.money_cap_micro_u64,
            gas_cap_mist_u64: self.gas_cap_mist_u64,
            job_cap_u32: self.job_cap_u32,
        }
    }

    /// Apply a completed dispatch's charge to the ledger (saturating; spent is
    /// clamped to the current caps).
    pub fn apply_charge(
        &mut self,
        tokens_u32: u32,
        cost_micro_u64: u64,
        gas_mist_u64: u64,
        jobs_started_u32: u32,
    ) {
        self.token_spent_u32 = self
            .token_spent_u32
            .saturating_add(tokens_u32)
            .min(self.token_cap_u32);
        self.money_spent_micro_u64 = self
            .money_spent_micro_u64
            .saturating_add(cost_micro_u64)
            .min(self.money_cap_micro_u64);
        self.gas_spent_mist_u64 = self
            .gas_spent_mist_u64
            .saturating_add(gas_mist_u64)
            .min(self.gas_cap_mist_u64);
        self.jobs_live_u32 = self.jobs_live_u32.saturating_add(jobs_started_u32);
    }

    /// The render truth: `Red` when any budget axis is exhausted, else `Green`.
    #[must_use]
    pub const fn render_truth(&self) -> RenderTruth {
        let token_out = self.token_cap_u32.saturating_sub(self.token_spent_u32) == 0;
        let money_out = self
            .money_cap_micro_u64
            .saturating_sub(self.money_spent_micro_u64)
            == 0;
        let gas_out = self.gas_remaining_mist() == 0;
        let jobs_out = self.jobs_live_u32 >= self.job_cap_u32;
        if token_out || money_out || gas_out || jobs_out {
            RenderTruth::Red
        } else {
            RenderTruth::Green
        }
    }

    /// Colorless `/budget` status lines bounded by `rows` (hot-path render).
    #[must_use]
    pub fn render(&self, rows: u16) -> Vec<String> {
        let lines = vec![
            format!(
                "token_remaining={}",
                self.token_cap_u32.saturating_sub(self.token_spent_u32)
            ),
            format!(
                "money_remaining_micros={}",
                self.money_cap_micro_u64
                    .saturating_sub(self.money_spent_micro_u64)
            ),
            format!("gas_remaining_mist={}", self.gas_remaining_mist()),
            format!(
                "jobs_remaining={}",
                self.job_cap_u32.saturating_sub(self.jobs_live_u32)
            ),
            format!("deadline_ms={}", self.deadline_ms_u32),
            format!("cap_version={}", self.version_u32),
            format!("truth_u8={}", self.render_truth() as u8),
        ];
        lines.into_iter().take(rows as usize).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::repl::latency::p95_ms;
    use crate::route::RouteExecutionState;

    const ZERO32: [u8; 32] = [0u8; 32];

    fn dispatch(
        state: RouteExecutionState,
        input: u32,
        output: u32,
        gas_mist: u64,
        job_slots_u32: u32,
    ) -> GlobalDispatch {
        GlobalDispatch {
            request: DispatchRequest {
                route_state: state,
                input_tokens_u32: input,
                output_tokens_u32: output,
                estimated_cost_micro: Some(10),
                projected_ms_u32: 100,
                approved: false,
                reason_hash_32: ZERO32,
                route_trace_hash_32: ZERO32,
            },
            gas_mist: GasBudgetMist::new(gas_mist),
            job_slots_u32,
        }
    }

    fn approve(mut d: GlobalDispatch) -> GlobalDispatch {
        d.request.approved = true;
        d.request.reason_hash_32 = [1u8; 32];
        d.request.route_trace_hash_32 = [2u8; 32];
        d
    }

    fn budget() -> GlobalBudget {
        // Generous base; Slow route consult cap is (8000, 2000).
        GlobalBudget::new(
            BudgetCap::new(100_000, 1_000_000, 100_000),
            GasBudgetMist::new(1_000_000),
            8,
        )
    }

    #[test]
    fn token_cap_is_enforced() {
        let b = GlobalBudget::new(
            BudgetCap::new(100, 1_000_000, 100_000),
            GasBudgetMist::new(1_000_000),
            8,
        );
        // 60 + 50 = 110 > 100 token cap (within Slow consult cap, so token-bound).
        assert_eq!(
            b.check(&dispatch(RouteExecutionState::Slow, 60, 50, 0, 1)),
            Err(GlobalBudgetReject::TokenBudgetExceeded)
        );
    }

    #[test]
    fn money_cap_is_enforced() {
        let b = GlobalBudget::new(
            BudgetCap::new(100_000, 50, 100_000),
            GasBudgetMist::new(1_000_000),
            8,
        );
        let mut d = dispatch(RouteExecutionState::Slow, 10, 10, 0, 1);
        d.request.estimated_cost_micro = Some(60); // > 50 money cap
        assert_eq!(b.check(&d), Err(GlobalBudgetReject::MoneyBudgetExceeded));
    }

    #[test]
    fn gas_cap_is_enforced() {
        let b = GlobalBudget::new(
            BudgetCap::new(100_000, 1_000_000, 100_000),
            GasBudgetMist::new(500),
            8,
        );
        assert_eq!(
            b.check(&dispatch(RouteExecutionState::Slow, 10, 10, 600, 1)),
            Err(GlobalBudgetReject::GasBudgetExceeded)
        );
        // within gas cap -> ok
        assert!(
            b.check(&dispatch(RouteExecutionState::Slow, 10, 10, 400, 1))
                .is_ok()
        );
    }

    #[test]
    fn deadline_is_enforced() {
        let b = GlobalBudget::new(
            BudgetCap::new(100_000, 1_000_000, 50),
            GasBudgetMist::new(1_000_000),
            8,
        );
        let mut d = dispatch(RouteExecutionState::Slow, 10, 10, 0, 1);
        d.request.projected_ms_u32 = 80; // > 50ms deadline
        assert_eq!(b.check(&d), Err(GlobalBudgetReject::DeadlineExceeded));
    }

    #[test]
    fn job_count_cap_is_enforced() {
        let mut b = budget();
        b.set_jobs_live(8); // cap is 8
        assert_eq!(
            b.check(&dispatch(RouteExecutionState::Slow, 10, 10, 0, 1)),
            Err(GlobalBudgetReject::JobCountExceeded)
        );
    }

    #[test]
    fn over_consult_cap_needs_approval() {
        let b = budget();
        // Slow input cap is 8000; 8001 over-cap, unapproved -> rejected.
        assert_eq!(
            b.check(&dispatch(RouteExecutionState::Slow, 8_001, 100, 0, 1)),
            Err(GlobalBudgetReject::UnapprovedCapExceed)
        );
        // With explicit approval -> allowed.
        assert!(
            b.check(&approve(dispatch(
                RouteExecutionState::Slow,
                8_001,
                100,
                0,
                1
            )))
            .is_ok()
        );
    }

    #[test]
    fn missing_estimate_is_rejected() {
        let b = budget();
        let mut d = dispatch(RouteExecutionState::Slow, 10, 10, 0, 1);
        d.request.estimated_cost_micro = None;
        assert_eq!(b.check(&d), Err(GlobalBudgetReject::MissingCostEstimate));
    }

    #[test]
    fn express_cap_lower_is_one_way_and_bumps_version() {
        let mut b = budget();
        let v0 = b.version();
        let ack = b.express_cap_lower(1_000, 500_000, 800_000, 4);
        assert!(ack.bypassed_queue);
        assert_eq!(ack.version_u32, v0 + 1);
        assert_eq!(ack.token_cap_u32, 1_000);
        assert_eq!(ack.job_cap_u32, 4);
        // A "raise" attempt cannot widen any cap (one-way lower).
        let ack2 = b.express_cap_lower(9_999_999, 9_999_999, 9_999_999, 99);
        assert_eq!(ack2.token_cap_u32, 1_000); // unchanged
        assert_eq!(ack2.job_cap_u32, 4); // unchanged
        assert_eq!(ack2.version_u32, v0 + 2); // version still advances (processed)
    }

    #[test]
    fn cap_lower_bypasses_queue_even_when_job_saturated() {
        let mut b = budget();
        b.set_jobs_live(8); // saturated at the job cap
        // The express cap-lower is NOT enqueued behind the full job set.
        let ack = b.express_cap_lower(10, 10, 10, 1);
        assert!(ack.bypassed_queue);
    }

    #[test]
    fn side_effect_preflight_recheck_after_lower() {
        let mut b = budget();
        let d = dispatch(RouteExecutionState::Slow, 5_000, 1_000, 0, 1);
        assert!(b.check(&d).is_ok());
        // Lower the token cap below the in-flight dispatch's need.
        b.express_cap_lower(100, 1_000_000, 1_000_000, 8);
        // The mandatory preflight re-check now refuses the same dispatch.
        assert_eq!(
            b.preflight_recheck(&d),
            Err(GlobalBudgetReject::TokenBudgetExceeded)
        );
    }

    #[test]
    fn apply_charge_then_remaining_and_truth() {
        let mut b = budget();
        b.apply_charge(40_000, 400_000, 600_000, 2);
        assert!(b.gas_remaining_mist() == 400_000);
        assert_eq!(b.render_truth(), RenderTruth::Green);
        // Exhaust gas -> Red.
        b.apply_charge(0, 0, 400_000, 0);
        assert_eq!(b.gas_remaining_mist(), 0);
        assert_eq!(b.render_truth(), RenderTruth::Red);
    }

    #[test]
    fn render_is_bounded() {
        let b = budget();
        assert!(b.render(3).len() <= 3);
        assert!(b.render(64).len() <= 7);
    }

    #[test]
    fn per_call_input_cap_is_hard_and_beats_consult_cap() {
        let b = budget();
        // within the 5000 input ceiling -> ok
        assert!(
            b.authorize_operational_call(&dispatch(RouteExecutionState::Slow, 5_000, 100, 0, 1))
                .is_ok()
        );
        // over 5000 input -> refused, even though Slow's consult cap is 8000
        assert_eq!(
            b.authorize_operational_call(&dispatch(RouteExecutionState::Slow, 5_001, 100, 0, 1)),
            Err(GlobalBudgetReject::PerCallInputCapExceeded)
        );
        // approval cannot rescue the hard operational ceiling
        assert_eq!(
            b.authorize_operational_call(&approve(dispatch(
                RouteExecutionState::Slow,
                6_000,
                100,
                0,
                1
            ))),
            Err(GlobalBudgetReject::PerCallInputCapExceeded)
        );
    }

    #[test]
    fn budget_check_p95_within_5ms() {
        let b = budget();
        let d = dispatch(RouteExecutionState::Slow, 1_000, 500, 1_000, 1);
        let mut samples = Vec::with_capacity(256);
        for _ in 0..256 {
            let t = std::time::Instant::now();
            let v = b.check(&d);
            std::hint::black_box(&v);
            samples.push(t.elapsed().as_nanos() as u64);
        }
        let p95 = p95_ms(&samples) / 1_000_000;
        assert!(p95 <= 5, "budget check p95 {p95}ms exceeds 5ms");
    }

    #[test]
    fn cap_lower_ack_p95_within_16ms_under_saturation() {
        let mut b = budget();
        b.set_jobs_live(8); // saturated background fixture
        let mut samples = Vec::with_capacity(256);
        for i in 0..256u32 {
            let t = std::time::Instant::now();
            // Each lower tightens monotonically (i descending bound).
            let ack = b.express_cap_lower(100_000 - i, 1_000_000, 1_000_000, 8);
            std::hint::black_box(&ack);
            samples.push(t.elapsed().as_nanos() as u64);
        }
        let p95 = p95_ms(&samples) / 1_000_000;
        assert!(p95 <= 16, "cap-lower ack p95 {p95}ms exceeds 16ms");
    }
}
