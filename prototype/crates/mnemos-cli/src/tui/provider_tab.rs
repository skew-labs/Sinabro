//! Provider health dashboard tab.
//!
//! A pure projection (like the rest of [`crate::tui`]) of provider truth the
//! provider/router atoms own: per-provider health, latency, error rate, fallback
//! pending, and cost, plus the route state, consult trigger, model role,
//! input/output token cap, redaction status, prompt-cache hit, actual/estimated
//! cost, and whether a frontier output is still advisory or locally verified.
//!
//! The render law: a degraded or offline provider is never
//! `Green`; a row whose redaction status is missing is `Red`; an advisory
//! (not-yet-locally-verified) output is never `Green`. The refresh is a status
//! projection only — it makes **no provider call** (the adaptive-router speed
//! law), so the dashboard refreshes within budget regardless of provider
//! liveness.
//!
//! Reuse (no reinvention): [`ProviderView`] / [`ProviderKind`] / [`ModelRole`]
//! from [`crate::commands::provider`] (the provider commands), the
//! [`ConsultTrigger`] from [`crate::commands::model_route`], and
//! [`crate::tui::RenderTruth`].

use crate::commands::model_route::ConsultTrigger;
use crate::commands::provider::{ModelRole, ProviderKind, ProviderView};
use crate::route::RouteExecutionState;
use crate::tui::RenderTruth;

/// Live provider health beyond config validity: liveness + error rate.
#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProviderLiveness {
    /// Responding normally.
    Healthy = 1,
    /// Degraded — elevated latency or error rate (never `Green`).
    Degraded = 2,
    /// Offline / unreachable (`Red`).
    Offline = 3,
    /// Not yet probed — `Unknown`, never a false `Green`.
    Unknown = 4,
}

impl ProviderLiveness {
    /// Project liveness onto the cockpit render truth.
    #[must_use]
    pub const fn render_truth(self) -> RenderTruth {
        match self {
            Self::Healthy => RenderTruth::Green,
            Self::Degraded => RenderTruth::Yellow,
            Self::Offline => RenderTruth::Red,
            Self::Unknown => RenderTruth::Unknown,
        }
    }
}

/// Whether a frontier output has been locally verified yet.
#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AdvisoryState {
    /// Advisory only — not yet locally verified (never `Green`).
    Advisory = 1,
    /// Locally verified — may be trusted (`Green`).
    LocallyVerified = 2,
}

impl AdvisoryState {
    /// Project onto the cockpit render truth.
    #[must_use]
    pub const fn render_truth(self) -> RenderTruth {
        match self {
            Self::Advisory => RenderTruth::Yellow,
            Self::LocallyVerified => RenderTruth::Green,
        }
    }
}

/// The dynamic (non-config) health inputs for one provider row. Bundled so
/// [`ProviderHealthRow::new`] stays within the argument-count budget.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ProviderHealthInputs {
    /// Live liveness.
    pub liveness: ProviderLiveness,
    /// Error rate in basis points.
    pub error_rate_bps: u16,
    /// Measured p95 latency (ms).
    pub latency_p95_ms_u32: u32,
    /// Current route state.
    pub route_state: RouteExecutionState,
    /// The consult trigger, if a consult is in flight (visible).
    pub consult_trigger: Option<ConsultTrigger>,
    /// Input token cap for the current route state.
    pub input_token_cap_u32: u32,
    /// Output token cap for the current route state.
    pub output_token_cap_u32: u32,
    /// Whether a redaction report is present (missing => `Red`).
    pub redaction_present: bool,
    /// Prompt-cache hit rate in basis points.
    pub prompt_cache_hit_bps: u16,
    /// Estimated cost (micro-units).
    pub estimated_cost_micro_u64: u64,
    /// Actual cost so far (micro-units).
    pub actual_cost_micro_u64: u64,
    /// Cost cap (micro-units); exceeding it is a warning.
    pub cost_cap_micro_u64: u64,
    /// Advisory vs locally-verified state of the frontier output.
    pub advisory_state: AdvisoryState,
    /// Whether a fallback is pending (not yet a healthy state).
    pub fallback_pending: bool,
}

/// One provider health row in the dashboard.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ProviderHealthRow {
    /// Which provider.
    pub kind: ProviderKind,
    /// Routing role.
    pub role: ModelRole,
    /// SHA-256 of the model identity (visible / non-zero).
    pub model_identity_hash_32: [u8; 32],
    /// Live liveness.
    pub liveness: ProviderLiveness,
    /// Error rate (bps).
    pub error_rate_bps: u16,
    /// Measured p95 latency (ms).
    pub latency_p95_ms_u32: u32,
    /// Current route state.
    pub route_state: RouteExecutionState,
    /// Consult trigger in flight (visible).
    pub consult_trigger: Option<ConsultTrigger>,
    /// Input token cap.
    pub input_token_cap_u32: u32,
    /// Output token cap.
    pub output_token_cap_u32: u32,
    /// Whether a redaction report is present.
    pub redaction_present: bool,
    /// Prompt-cache hit rate (bps).
    pub prompt_cache_hit_bps: u16,
    /// Estimated cost (micro-units).
    pub estimated_cost_micro_u64: u64,
    /// Actual cost (micro-units).
    pub actual_cost_micro_u64: u64,
    /// Cost cap (micro-units).
    pub cost_cap_micro_u64: u64,
    /// Advisory vs locally-verified state.
    pub advisory_state: AdvisoryState,
    /// Whether a fallback is pending.
    pub fallback_pending: bool,
    /// Invariant `false`: the row is a cached projection — no provider call is
    /// made to build it.
    pub provider_call_made: bool,
}

impl ProviderHealthRow {
    /// Build a health row from a reused [`ProviderView`] (the provider command
    /// surface) and the dynamic health inputs. `provider_call_made` is always
    /// `false` — building the row never calls a provider.
    #[must_use]
    pub fn new(view: ProviderView, inputs: ProviderHealthInputs) -> Self {
        Self {
            kind: view.kind,
            role: view.role,
            model_identity_hash_32: view.model_identity_hash_32,
            liveness: inputs.liveness,
            error_rate_bps: inputs.error_rate_bps,
            latency_p95_ms_u32: inputs.latency_p95_ms_u32,
            route_state: inputs.route_state,
            consult_trigger: inputs.consult_trigger,
            input_token_cap_u32: inputs.input_token_cap_u32,
            output_token_cap_u32: inputs.output_token_cap_u32,
            redaction_present: inputs.redaction_present,
            prompt_cache_hit_bps: inputs.prompt_cache_hit_bps,
            estimated_cost_micro_u64: inputs.estimated_cost_micro_u64,
            actual_cost_micro_u64: inputs.actual_cost_micro_u64,
            cost_cap_micro_u64: inputs.cost_cap_micro_u64,
            advisory_state: inputs.advisory_state,
            fallback_pending: inputs.fallback_pending,
            provider_call_made: false,
        }
    }

    /// Whether actual or estimated cost has exceeded the cost cap.
    #[must_use]
    pub const fn cost_over_cap(&self) -> bool {
        self.actual_cost_micro_u64 > self.cost_cap_micro_u64
            || self.estimated_cost_micro_u64 > self.cost_cap_micro_u64
    }

    /// The overall render truth of this row (worst-axis precedence, no false
    /// green): redaction-missing or offline => `Red`; unprobed => `Unknown`;
    /// degraded / fallback-pending / cost-over-cap / advisory => `Yellow`;
    /// otherwise `Green`.
    #[must_use]
    pub const fn health_truth(&self) -> RenderTruth {
        if !self.redaction_present {
            return RenderTruth::Red;
        }
        match self.liveness {
            ProviderLiveness::Offline => return RenderTruth::Red,
            ProviderLiveness::Unknown => return RenderTruth::Unknown,
            ProviderLiveness::Degraded | ProviderLiveness::Healthy => {}
        }
        if matches!(self.liveness, ProviderLiveness::Degraded)
            || self.fallback_pending
            || self.cost_over_cap()
            || matches!(self.advisory_state, AdvisoryState::Advisory)
        {
            return RenderTruth::Yellow;
        }
        RenderTruth::Green
    }
}

/// The provider health dashboard tab — a list of provider rows.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ProviderHealthTab {
    rows: Vec<ProviderHealthRow>,
}

impl ProviderHealthTab {
    /// A new, empty dashboard.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a provider row.
    pub fn push(&mut self, row: ProviderHealthRow) {
        self.rows.push(row);
    }

    /// The provider rows.
    #[must_use]
    pub fn rows(&self) -> &[ProviderHealthRow] {
        &self.rows
    }

    /// Number of rows.
    #[must_use]
    pub fn len(&self) -> usize {
        self.rows.len()
    }

    /// Whether the dashboard is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.rows.is_empty()
    }

    /// Recompute the per-row render truths (the dashboard refresh). A pure
    /// projection — no provider call is made.
    #[must_use]
    pub fn refresh(&self) -> Vec<RenderTruth> {
        self.rows
            .iter()
            .map(ProviderHealthRow::health_truth)
            .collect()
    }

    /// Whether every provider row is healthy (`Green`).
    #[must_use]
    pub fn is_all_healthy(&self) -> bool {
        self.rows.iter().all(|r| r.health_truth().is_healthy())
    }

    /// The no-call invariant: a refresh never makes a provider call.
    #[must_use]
    pub fn refresh_made_no_provider_call(&self) -> bool {
        self.rows.iter().all(|r| !r.provider_call_made)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::commands::provider::{ProviderRegistry, ProviderSpec};
    use crate::repl::latency::p95_ms;

    fn view(kind: ProviderKind) -> ProviderView {
        let mut reg = ProviderRegistry::new();
        let spec = ProviderSpec {
            kind,
            model_id: "model-x",
            role: kind.default_role(),
            secret_name: "key",
            secret_reference: "env:PROVIDER_KEY",
            cost_micro_per_1k_u32: 10,
            latency_p50_ms_u16: 100,
        };
        assert!(
            reg.attach(&spec),
            "attach with a reference secret must succeed"
        );
        reg.list()[0]
    }

    fn healthy_inputs() -> ProviderHealthInputs {
        ProviderHealthInputs {
            liveness: ProviderLiveness::Healthy,
            error_rate_bps: 0,
            latency_p95_ms_u32: 80,
            route_state: RouteExecutionState::Slow,
            consult_trigger: Some(ConsultTrigger::RepeatedFailure),
            input_token_cap_u32: 8_000,
            output_token_cap_u32: 2_000,
            redaction_present: true,
            prompt_cache_hit_bps: 6_000,
            estimated_cost_micro_u64: 100,
            actual_cost_micro_u64: 90,
            cost_cap_micro_u64: 1_000,
            advisory_state: AdvisoryState::LocallyVerified,
            fallback_pending: false,
        }
    }

    fn row(kind: ProviderKind, inputs: ProviderHealthInputs) -> ProviderHealthRow {
        ProviderHealthRow::new(view(kind), inputs)
    }

    #[test]
    fn healthy_local_provider_is_green() {
        let r = row(ProviderKind::Naite, healthy_inputs());
        assert_eq!(r.health_truth(), RenderTruth::Green);
    }

    #[test]
    fn degraded_provider_is_not_green() {
        let mut i = healthy_inputs();
        i.liveness = ProviderLiveness::Degraded;
        let r = row(ProviderKind::Anthropic, i);
        assert_eq!(r.health_truth(), RenderTruth::Yellow);
        assert!(!r.health_truth().is_healthy());
    }

    #[test]
    fn offline_provider_is_red() {
        let mut i = healthy_inputs();
        i.liveness = ProviderLiveness::Offline;
        assert_eq!(
            row(ProviderKind::OpenAi, i).health_truth(),
            RenderTruth::Red
        );
    }

    #[test]
    fn fallback_pending_is_not_green() {
        let mut i = healthy_inputs();
        i.fallback_pending = true;
        let r = row(ProviderKind::Gemini, i);
        assert_eq!(r.health_truth(), RenderTruth::Yellow);
    }

    #[test]
    fn cost_cap_warning_is_not_green() {
        let mut i = healthy_inputs();
        i.actual_cost_micro_u64 = 2_000; // > 1_000 cap
        let r = row(ProviderKind::Anthropic, i);
        assert!(r.cost_over_cap());
        assert_eq!(r.health_truth(), RenderTruth::Yellow);
    }

    #[test]
    fn consult_trigger_is_visible() {
        let r = row(ProviderKind::Anthropic, healthy_inputs());
        assert_eq!(r.consult_trigger, Some(ConsultTrigger::RepeatedFailure));
    }

    #[test]
    fn redaction_missing_is_red() {
        let mut i = healthy_inputs();
        i.redaction_present = false;
        // even a fully healthy provider is Red if redaction is missing
        assert_eq!(row(ProviderKind::Naite, i).health_truth(), RenderTruth::Red);
    }

    #[test]
    fn advisory_output_is_not_green() {
        let mut i = healthy_inputs();
        i.advisory_state = AdvisoryState::Advisory;
        let r = row(ProviderKind::OpenAi, i);
        assert!(!r.health_truth().is_healthy());
        assert_eq!(r.advisory_state.render_truth(), RenderTruth::Yellow);
    }

    #[test]
    fn unprobed_provider_is_unknown_not_green() {
        let mut i = healthy_inputs();
        i.liveness = ProviderLiveness::Unknown;
        let r = row(ProviderKind::Vllm, i);
        assert_eq!(r.health_truth(), RenderTruth::Unknown);
        assert!(!r.health_truth().is_healthy());
    }

    #[test]
    fn refresh_makes_no_provider_call() {
        let mut tab = ProviderHealthTab::new();
        tab.push(row(ProviderKind::Naite, healthy_inputs()));
        tab.push(row(ProviderKind::Anthropic, healthy_inputs()));
        assert!(tab.refresh_made_no_provider_call());
        assert_eq!(tab.refresh().len(), 2);
        assert!(tab.is_all_healthy());
    }

    #[test]
    fn provider_tab_refresh_p95_within_100ms() {
        let mut tab = ProviderHealthTab::new();
        for k in [
            ProviderKind::Naite,
            ProviderKind::Anthropic,
            ProviderKind::OpenAi,
            ProviderKind::Gemini,
        ] {
            tab.push(row(k, healthy_inputs()));
        }
        let mut samples = Vec::with_capacity(256);
        for _ in 0..256 {
            let t = std::time::Instant::now();
            let v = tab.refresh();
            std::hint::black_box(&v);
            samples.push(t.elapsed().as_nanos() as u64);
        }
        let p95 = p95_ms(&samples) / 1_000_000;
        assert!(
            p95 <= 100,
            "provider tab refresh p95 {p95}ms exceeds 100ms budget"
        );
    }
}
