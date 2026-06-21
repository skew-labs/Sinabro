//! model route / fallback diff display (atom #428 F.3.1).
//!
//! `sinabro model route` (status / policy / trace / consult --dry-run). Reuses
//! the canonical [`RouteExecutionState`] FSM and the [`ModelRole`] / [`ProviderKind`]
//! from [`super::provider`]. Enforces the adaptive-router amendment:
//!
//! * Naite/local is the default executor; a frontier consult is allowed only for
//!   a typed [`ConsultTrigger`] and only on `Slow`/`Stuck`/`Audit`.
//! * `Fast`/`Normal`/`Lockdown`/`UserFull` default to **0** external tokens — a
//!   standard bounded consult is denied there (user-ask escalation goes through
//!   an explicit [`ModelRouter::transition`], never a silent upgrade).
//! * every consult packet carries token caps, a redaction-report hash, evidence
//!   and prompt hashes, a `private_memory_included = false` flag, a
//!   `local_verification_required = true` flag, and is `advisory_only`.
//! * a fallback requires an explicit, approved, visible diff — a silent fallback
//!   is denied (`G-F-NO-SILENT-FALLBACK`).
//!
//! All views are pure in-memory projections — no provider call on the status hot
//! path (`G-F-ADAPTIVE-ROUTER` speed law).

use super::provider::{ModelRole, ProviderKind};
use crate::route::RouteExecutionState;
use crate::sha256_32;
use crate::tui::RenderTruth;

const ZERO32: [u8; 32] = [0u8; 32];

/// Typed reason a frontier consult may be requested. Discriminants are locked by
/// the adaptive-router amendment.
#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ConsultTrigger {
    /// Repeated local failure on the same step.
    RepeatedFailure = 1,
    /// The plan and the disk truth contradict each other.
    PlanDiskContradiction = 2,
    /// A crate / module dependency cycle was found.
    DependencyCycle = 3,
    /// An ABI / wire-format mismatch.
    AbiMismatch = 4,
    /// A safety boundary was tripped.
    SafetyBoundary = 5,
    /// An audit-impact question (no exploit procedure).
    AuditImpact = 6,
    /// Low confidence on a high-blast-radius decision.
    LowConfidenceHighBlastRadius = 7,
    /// Two verifiers disagree.
    VerifierConflict = 8,
    /// The user explicitly asked for a consult.
    UserRequested = 9,
}

impl ConsultTrigger {
    /// All typed consult triggers — the COMPLETE evidence-backed set (#605 RD-49).
    /// There is no untyped / prompt-vibe trigger: a frontier consult, and therefore
    /// a provider egress, can be requested ONLY by naming one of these typed reasons
    /// (the egress builder takes a `ConsultTrigger`, never an `Option`). Used for
    /// exhaustive policy enumeration so a new variant cannot silently escape the
    /// 0-unprovoked-egress proof.
    pub const ALL: [ConsultTrigger; 9] = [
        Self::RepeatedFailure,
        Self::PlanDiskContradiction,
        Self::DependencyCycle,
        Self::AbiMismatch,
        Self::SafetyBoundary,
        Self::AuditImpact,
        Self::LowConfidenceHighBlastRadius,
        Self::VerifierConflict,
        Self::UserRequested,
    ];
}

/// Per-state frontier-consult token caps `(input, output)`. The amendment Token
/// Law, read as decimal thousands (`8k = 8000`). `Fast`/`Normal`/`Lockdown`/
/// `UserFull` are `(0, 0)`: no standard bounded consult without explicit
/// escalation (`UserFull` uses the separate explicit-budget background path).
///
/// NOTE (Session 2 / owner): the amendment wrote "8k/2k/16k/4k/12k" without
/// pinning decimal vs binary; this is the **decimal** reading. The binary reading
/// would be `Slow (8192, 2048)`, `Stuck (16384, 4096)`, `Audit (12288, 4096)`.
#[must_use]
pub const fn consult_token_cap(state: RouteExecutionState) -> (u32, u32) {
    match state {
        RouteExecutionState::Slow => (8000, 2000),
        RouteExecutionState::Stuck => (16000, 4000),
        RouteExecutionState::Audit => (12000, 4000),
        RouteExecutionState::Fast
        | RouteExecutionState::Normal
        | RouteExecutionState::Lockdown
        | RouteExecutionState::UserFull => (0, 0),
    }
}

/// One unhealthy trajectory signal (gate `G-F-TRAJECTORY-HEALTH`). Each value is
/// a distinct bit folded into a [`TrajectoryHealth`] bitset.
#[repr(u16)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TrajectorySignal {
    /// The agent is looping over the same semantic step.
    SemanticLoop = 1,
    /// A verification step was skipped.
    VerificationSkip = 2,
    /// An unresolved contradiction.
    Contradiction = 4,
    /// Scope is sprawling beyond the task.
    ScopeSprawl = 8,
    /// The topic is drifting off-target.
    TopicDrift = 16,
    /// Compression is cycling on itself.
    CyclicCompression = 32,
    /// Evidence does not match the claim.
    EvidenceMismatch = 64,
    /// An approval boundary was bypassed.
    ApprovalBypass = 128,
    /// A gas-drain risk was detected.
    GasRisk = 256,
    /// A secret was touched.
    SecretTouch = 512,
    /// A tool-capability escalation was attempted.
    ToolEscalation = 1024,
}

/// A typed trajectory-health summary (never prose). Unhealthy signals are a
/// bitset; any unhealthy signal means the agent must not keep running.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct TrajectoryHealth {
    unhealthy_bits_u16: u16,
}

impl TrajectoryHealth {
    /// A fully healthy trajectory (no signals).
    #[must_use]
    pub const fn healthy() -> Self {
        Self {
            unhealthy_bits_u16: 0,
        }
    }

    /// Record an unhealthy signal.
    pub fn record(&mut self, signal: TrajectorySignal) {
        self.unhealthy_bits_u16 |= signal as u16;
    }

    /// The raw unhealthy-signal bitset.
    #[must_use]
    pub const fn bits(self) -> u16 {
        self.unhealthy_bits_u16
    }

    /// Whether the trajectory is healthy (no signals set).
    #[must_use]
    pub const fn is_healthy(self) -> bool {
        self.unhealthy_bits_u16 == 0
    }

    /// Project onto the cockpit [`RenderTruth`]: healthy → `Green`, otherwise
    /// `Red` (no false green).
    #[must_use]
    pub const fn render_truth(self) -> RenderTruth {
        if self.is_healthy() {
            RenderTruth::Green
        } else {
            RenderTruth::Red
        }
    }

    /// Whether the agent must halt — true iff any unhealthy signal is set.
    #[must_use]
    pub const fn should_halt(self) -> bool {
        !self.is_healthy()
    }
}

/// A status-only view of what a frontier consult *would* send (the
/// `route consult --dry-run` projection). Advisory-only; never sent by default.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FrontierConsultPacketView {
    /// The route state that authorized the consult.
    pub route_state: RouteExecutionState,
    /// The typed trigger.
    pub trigger: ConsultTrigger,
    /// Input token cap for this state.
    pub input_token_cap_u32: u32,
    /// Output token cap for this state.
    pub output_token_cap_u32: u32,
    /// SHA-256 of the redaction report (must exist before dispatch).
    pub redaction_report_hash_32: [u8; 32],
    /// SHA-256 of the evidence references.
    pub evidence_refs_hash_32: [u8; 32],
    /// SHA-256 of the compiled prompt.
    pub prompt_hash_32: [u8; 32],
    /// Whether private memory is included — invariant `false` (default deny).
    pub private_memory_included: bool,
    /// Whether local verification is required before the output is trusted —
    /// invariant `true`.
    pub local_verification_required: bool,
    /// Whether the output is advisory only until locally verified — invariant `true`.
    pub advisory_only: bool,
    /// Estimated cost (micro-units).
    pub estimated_cost_micro_u64: u64,
    /// Estimated latency (ms).
    pub estimated_latency_ms_u32: u32,
}

/// The route decision view (`route status`). A pure projection of router state.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ModelRouteDecisionView {
    /// The primary (executor) role.
    pub primary_role: ModelRole,
    /// The optional reviewer role.
    pub reviewer_role: Option<ModelRole>,
    /// SHA-256 of the active provider identity (visible / non-zero).
    pub provider_identity_hash_32: [u8; 32],
    /// Whether the no-silent-fallback kernel feature is on — invariant `true`.
    pub no_silent_fallback: bool,
    /// The current route state.
    pub route_state: RouteExecutionState,
    /// The typed trajectory-health summary.
    pub trajectory: TrajectoryHealth,
    /// Estimated cost (micro-units).
    pub estimated_cost_micro_u64: u64,
    /// Estimated latency (ms).
    pub estimated_latency_ms_u32: u32,
    /// Whether the decision is approved (default `false`).
    pub approved: bool,
}

/// A proposed provider/model fallback. A fallback is *silent* — and therefore
/// denied — unless it carries a visible reason and explicit approval.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FallbackDiff {
    /// The provider being routed away from.
    pub from_kind: ProviderKind,
    /// The provider being routed to.
    pub to_kind: ProviderKind,
    /// SHA-256 of the current model identity.
    pub from_model_hash_32: [u8; 32],
    /// SHA-256 of the proposed model identity.
    pub to_model_hash_32: [u8; 32],
    /// SHA-256 of the visible reason (zero = no visible diff).
    pub reason_hash_32: [u8; 32],
    /// Whether the user explicitly approved this fallback.
    pub approved: bool,
}

impl FallbackDiff {
    /// Whether this fallback is silent: no visible reason, or not approved.
    #[must_use]
    pub fn is_silent(&self) -> bool {
        self.reason_hash_32 == ZERO32 || !self.approved
    }

    /// Whether applying this fallback is permitted (explicit + visible).
    #[must_use]
    pub fn is_permitted(&self) -> bool {
        !self.is_silent()
    }

    /// Whether this fallback changes the model identity (drift).
    #[must_use]
    pub fn is_identity_drift(&self) -> bool {
        self.from_model_hash_32 != self.to_model_hash_32
    }
}

/// The model router (status surface). Holds the current FSM state plus the
/// role / identity / trajectory it projects; mutation is explicit and visible.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ModelRouter {
    state: RouteExecutionState,
    prev_state: RouteExecutionState,
    primary: ModelRole,
    reviewer: Option<ModelRole>,
    provider_identity_hash_32: [u8; 32],
    trajectory: TrajectoryHealth,
    est_cost_micro_u64: u64,
    est_latency_ms_u32: u32,
}

impl ModelRouter {
    /// A new router bound to a provider identity. Starts `Normal`, primary =
    /// `LocalExecutor`, no reviewer, healthy trajectory.
    #[must_use]
    pub const fn new(provider_identity_hash_32: [u8; 32]) -> Self {
        Self {
            state: RouteExecutionState::Normal,
            prev_state: RouteExecutionState::Normal,
            primary: ModelRole::LocalExecutor,
            reviewer: None,
            provider_identity_hash_32,
            trajectory: TrajectoryHealth::healthy(),
            est_cost_micro_u64: 0,
            est_latency_ms_u32: 0,
        }
    }

    /// The current route state.
    #[must_use]
    pub const fn state(&self) -> RouteExecutionState {
        self.state
    }

    /// The current trajectory-health summary.
    #[must_use]
    pub const fn trajectory(&self) -> TrajectoryHealth {
        self.trajectory
    }

    /// Set the reviewer role.
    pub fn set_reviewer(&mut self, role: ModelRole) {
        self.reviewer = Some(role);
    }

    /// Set the cost / latency estimates surfaced in the decision view.
    pub fn set_estimates(&mut self, cost_micro_u64: u64, latency_ms_u32: u32) {
        self.est_cost_micro_u64 = cost_micro_u64;
        self.est_latency_ms_u32 = latency_ms_u32;
    }

    /// Record an unhealthy trajectory signal.
    pub fn record_trajectory(&mut self, signal: TrajectorySignal) {
        self.trajectory.record(signal);
    }

    /// Transition the route state with hysteresis / no-flap: an *immediate*
    /// reversal back to the state we just came from (`A -> B -> A` in
    /// consecutive steps) is rejected (`false`); otherwise the transition is
    /// applied and `true` is returned.
    pub fn transition(&mut self, to: RouteExecutionState) -> bool {
        if to == self.prev_state && to != self.state {
            return false;
        }
        self.prev_state = self.state;
        self.state = to;
        true
    }

    /// The stuck-to-audit gate: a `Stuck` route escalates to `Audit` (it never
    /// silently keeps running). Returns the resulting state.
    pub fn escalate_if_stuck(&mut self) -> RouteExecutionState {
        if matches!(self.state, RouteExecutionState::Stuck) {
            self.prev_state = self.state;
            self.state = RouteExecutionState::Audit;
        }
        self.state
    }

    /// The `route status` decision projection.
    #[must_use]
    pub fn decision_view(&self) -> ModelRouteDecisionView {
        ModelRouteDecisionView {
            primary_role: self.primary,
            reviewer_role: self.reviewer,
            provider_identity_hash_32: self.provider_identity_hash_32,
            no_silent_fallback: true,
            route_state: self.state,
            trajectory: self.trajectory,
            estimated_cost_micro_u64: self.est_cost_micro_u64,
            estimated_latency_ms_u32: self.est_latency_ms_u32,
            approved: false,
        }
    }

    /// A stable fingerprint of the route display (the `route diff` snapshot).
    #[must_use]
    pub fn route_display_fingerprint(&self) -> [u8; 32] {
        let mut buf = Vec::with_capacity(40);
        buf.push(self.state as u8);
        buf.push(self.prev_state as u8);
        buf.push(self.primary as u8);
        buf.push(self.reviewer.map_or(0u8, |r| r as u8));
        buf.extend_from_slice(&self.provider_identity_hash_32);
        buf.extend_from_slice(&self.trajectory.bits().to_le_bytes());
        sha256_32(&buf)
    }

    /// Build the bounded frontier-consult packet (`route consult --dry-run`).
    /// Returns `None` — i.e. **denies** — when:
    ///
    /// * `trigger` is `None` (no typed trigger);
    /// * the current state's token cap is `(0, 0)` (FAST/NORMAL/LOCKDOWN/USER_FULL
    ///   deny a standard bounded consult);
    /// * any of the redaction-report / evidence / prompt hashes is zero (a missing
    ///   redaction report or route-trace reference is denied).
    ///
    /// On success the packet is `advisory_only`, requires local verification, and
    /// never includes private memory.
    #[must_use]
    pub fn consult_packet(
        &self,
        trigger: Option<ConsultTrigger>,
        redaction_report_hash_32: [u8; 32],
        evidence_refs_hash_32: [u8; 32],
        prompt_hash_32: [u8; 32],
    ) -> Option<FrontierConsultPacketView> {
        let trigger = trigger?;
        let (input_token_cap_u32, output_token_cap_u32) = consult_token_cap(self.state);
        if input_token_cap_u32 == 0 && output_token_cap_u32 == 0 {
            return None;
        }
        if redaction_report_hash_32 == ZERO32
            || evidence_refs_hash_32 == ZERO32
            || prompt_hash_32 == ZERO32
        {
            return None;
        }
        Some(FrontierConsultPacketView {
            route_state: self.state,
            trigger,
            input_token_cap_u32,
            output_token_cap_u32,
            redaction_report_hash_32,
            evidence_refs_hash_32,
            prompt_hash_32,
            private_memory_included: false,
            local_verification_required: true,
            advisory_only: true,
            estimated_cost_micro_u64: self.est_cost_micro_u64,
            estimated_latency_ms_u32: self.est_latency_ms_u32,
        })
    }

    /// Apply a fallback. A silent fallback (no visible reason or not approved) is
    /// denied (`false`); a permitted fallback re-pins the provider identity and
    /// returns `true`.
    pub fn apply_fallback(&mut self, diff: &FallbackDiff) -> bool {
        if !diff.is_permitted() {
            return false;
        }
        self.provider_identity_hash_32 = diff.to_model_hash_32;
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::repl::latency::p95_ms;

    fn router() -> ModelRouter {
        ModelRouter::new([1u8; 32])
    }

    fn fallback(approved: bool, reason: [u8; 32], to: [u8; 32]) -> FallbackDiff {
        FallbackDiff {
            from_kind: ProviderKind::Naite,
            to_kind: ProviderKind::Anthropic,
            from_model_hash_32: [1u8; 32],
            to_model_hash_32: to,
            reason_hash_32: reason,
            approved,
        }
    }

    #[test]
    fn silent_fallback_deny() {
        let mut r = router();
        // not approved -> silent -> denied
        assert!(!r.apply_fallback(&fallback(false, [7u8; 32], [9u8; 32])));
        // approved but no visible reason -> silent -> denied
        assert!(!r.apply_fallback(&fallback(true, ZERO32, [9u8; 32])));
        assert_eq!(r.decision_view().provider_identity_hash_32, [1u8; 32]);
    }

    #[test]
    fn explicit_fallback_approve() {
        let mut r = router();
        assert!(r.apply_fallback(&fallback(true, [7u8; 32], [9u8; 32])));
        assert_eq!(r.decision_view().provider_identity_hash_32, [9u8; 32]);
    }

    #[test]
    fn route_diff_snapshot() {
        let r = router();
        assert_eq!(r.route_display_fingerprint(), r.route_display_fingerprint());
        let mut r2 = router();
        r2.record_trajectory(TrajectorySignal::SemanticLoop);
        assert_ne!(
            r.route_display_fingerprint(),
            r2.route_display_fingerprint()
        );
    }

    #[test]
    fn model_identity_drift_deny() {
        let mut r = router();
        let drift = fallback(false, [7u8; 32], [42u8; 32]);
        assert!(drift.is_identity_drift());
        assert!(
            !r.apply_fallback(&drift),
            "unapproved identity drift must be denied"
        );
        assert_eq!(r.decision_view().provider_identity_hash_32, [1u8; 32]);
    }

    #[test]
    fn route_trace_missing_deny() {
        let mut r = router();
        assert!(r.transition(RouteExecutionState::Slow));
        // zero evidence / prompt hash => route-trace / redaction missing => deny
        assert!(
            r.consult_packet(
                Some(ConsultTrigger::RepeatedFailure),
                [1u8; 32],
                ZERO32,
                [3u8; 32]
            )
            .is_none()
        );
    }

    #[test]
    fn route_state_transition() {
        let mut r = router();
        assert!(r.transition(RouteExecutionState::Slow));
        assert_eq!(r.state(), RouteExecutionState::Slow);
    }

    #[test]
    fn hysteresis_no_flap() {
        let mut r = router();
        assert!(r.transition(RouteExecutionState::Slow));
        // immediate reverse back to Normal (the state we came from) is a flap
        assert!(!r.transition(RouteExecutionState::Normal));
        assert_eq!(r.state(), RouteExecutionState::Slow);
    }

    #[test]
    fn stuck_to_audit_gate() {
        let mut r = router();
        assert!(r.transition(RouteExecutionState::Stuck));
        assert_eq!(r.escalate_if_stuck(), RouteExecutionState::Audit);
    }

    #[test]
    fn consult_trigger_missing_deny() {
        let mut r = router();
        assert!(r.transition(RouteExecutionState::Slow));
        assert!(
            r.consult_packet(None, [1u8; 32], [2u8; 32], [3u8; 32])
                .is_none(),
            "a consult without a typed trigger must be denied"
        );
    }

    #[test]
    fn fast_normal_external_consult_deny() {
        let r = router(); // Normal
        assert!(
            r.consult_packet(
                Some(ConsultTrigger::UserRequested),
                [1u8; 32],
                [2u8; 32],
                [3u8; 32]
            )
            .is_none(),
            "NORMAL must deny a standard bounded consult (0 external tokens)"
        );
        let mut fast = router();
        assert!(fast.transition(RouteExecutionState::Fast));
        assert!(
            fast.consult_packet(
                Some(ConsultTrigger::RepeatedFailure),
                [1u8; 32],
                [2u8; 32],
                [3u8; 32]
            )
            .is_none()
        );
    }

    #[test]
    fn slow_token_cap() {
        assert_eq!(consult_token_cap(RouteExecutionState::Slow), (8000, 2000));
    }

    #[test]
    fn stuck_token_cap() {
        assert_eq!(consult_token_cap(RouteExecutionState::Stuck), (16000, 4000));
    }

    #[test]
    fn audit_local_verification_required() {
        let mut r = router();
        assert!(r.transition(RouteExecutionState::Audit));
        let packet = r.consult_packet(
            Some(ConsultTrigger::AuditImpact),
            [1u8; 32],
            [2u8; 32],
            [3u8; 32],
        );
        assert!(
            packet.is_some(),
            "AUDIT consult must be permitted with full evidence"
        );
        if let Some(p) = packet {
            assert!(p.local_verification_required);
            assert!(!p.private_memory_included);
            assert_eq!(p.input_token_cap_u32, 12000);
            assert_eq!(p.output_token_cap_u32, 4000);
        }
    }

    #[test]
    fn frontier_output_advisory_only() {
        let mut r = router();
        assert!(r.transition(RouteExecutionState::Slow));
        let packet = r.consult_packet(
            Some(ConsultTrigger::RepeatedFailure),
            [1u8; 32],
            [2u8; 32],
            [3u8; 32],
        );
        assert!(
            packet.is_some(),
            "SLOW consult must be permitted with full evidence"
        );
        if let Some(p) = packet {
            assert!(p.advisory_only);
            assert!(p.local_verification_required);
        }
    }

    #[test]
    fn unhealthy_trajectory_must_halt() {
        let mut r = router();
        assert!(r.trajectory().is_healthy());
        r.record_trajectory(TrajectorySignal::EvidenceMismatch);
        assert!(r.trajectory().should_halt());
        assert_eq!(r.trajectory().render_truth(), RenderTruth::Red);
    }

    #[test]
    fn route_display_p95_within_budget() {
        let r = router();
        let mut samples = Vec::with_capacity(256);
        for _ in 0..256 {
            let t = std::time::Instant::now();
            let v = r.decision_view();
            std::hint::black_box(&v);
            samples.push(t.elapsed().as_nanos() as u64);
        }
        let p95 = p95_ms(&samples) / 1_000_000;
        assert!(p95 <= 30, "route display p95 {p95}ms exceeds 30ms budget");
    }
}
