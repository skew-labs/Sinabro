//! Operational route FSM + per-state effect mapping (atom #498 · G.1.7).
//!
//! Stage F minted [`RouteExecutionState`] (the FAST/NORMAL/SLOW/STUCK/AUDIT/
//! LOCKDOWN/USER_FULL enum) and [`ModelRouter`] (transition with hysteresis /
//! no-flap + `escalate_if_stuck`). Stage G adds the *operational effect mapping*:
//! each route state binds a concrete budget (consult token cap), provider tier,
//! approval level, and audit level, and is rendered with the canonical
//! [`RouteExecutionState::render_truth`] (no false green). The state is visible
//! and cannot flap without hysteresis (delegated to [`ModelRouter::transition`]).
//!
//! Reuse (no reinvention): [`RouteExecutionState`] from [`crate::route`],
//! [`ModelRouter`] + [`consult_token_cap`] from [`crate::commands::model_route`],
//! [`RenderTruth`] from [`crate::tui`].

use crate::commands::model_route::{ModelRouter, consult_token_cap};
use crate::route::RouteExecutionState;
use crate::tui::RenderTruth;

/// The provider tier a route state authorizes.
#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProviderTier {
    /// Local executor only — no external consult.
    LocalOnly = 1,
    /// Local executor with a bounded frontier-advisory consult permitted.
    FrontierAdvisory = 2,
    /// All routing frozen (safety boundary).
    Locked = 3,
}

/// The approval level a route state requires before a cap-relevant side effect.
#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ApprovalLevel {
    /// No approval (routine local work).
    None = 1,
    /// A single confirm.
    Confirm = 2,
    /// Explicit approval (reason + route trace) required.
    Explicit = 3,
    /// Frozen — no side effect may proceed.
    Frozen = 4,
}

/// The audit-detector level a route state activates.
#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AuditLevel {
    /// Audit detector idle.
    Off = 1,
    /// Audit detector watching.
    Watch = 2,
    /// Audit detector active (route not healthy).
    Active = 3,
}

/// The operational effects a route state binds. The `consult_*_cap` fields reuse
/// the canonical [`consult_token_cap`]; `render` reuses
/// [`RouteExecutionState::render_truth`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RouteEffects {
    /// The route state these effects belong to.
    pub state: RouteExecutionState,
    /// Bounded-consult input token cap for this state (0 = consult denied).
    pub consult_input_cap_u32: u32,
    /// Bounded-consult output token cap for this state (0 = consult denied).
    pub consult_output_cap_u32: u32,
    /// The provider tier authorized.
    pub provider_tier: ProviderTier,
    /// The approval level required.
    pub approval_level: ApprovalLevel,
    /// The audit-detector level activated.
    pub audit_level: AuditLevel,
    /// The cockpit render truth (canonical, no false green).
    pub render: RenderTruth,
}

impl RouteEffects {
    /// The operational effects bound to `state`.
    #[must_use]
    pub const fn for_state(state: RouteExecutionState) -> Self {
        let (consult_input_cap_u32, consult_output_cap_u32) = consult_token_cap(state);
        let (provider_tier, approval_level, audit_level) = match state {
            RouteExecutionState::Fast | RouteExecutionState::Normal => (
                ProviderTier::LocalOnly,
                ApprovalLevel::None,
                AuditLevel::Off,
            ),
            RouteExecutionState::Slow => (
                ProviderTier::FrontierAdvisory,
                ApprovalLevel::Confirm,
                AuditLevel::Watch,
            ),
            RouteExecutionState::Stuck | RouteExecutionState::Audit => (
                ProviderTier::FrontierAdvisory,
                ApprovalLevel::Explicit,
                AuditLevel::Active,
            ),
            RouteExecutionState::Lockdown => (
                ProviderTier::Locked,
                ApprovalLevel::Frozen,
                AuditLevel::Active,
            ),
            RouteExecutionState::UserFull => (
                ProviderTier::LocalOnly,
                ApprovalLevel::Explicit,
                AuditLevel::Watch,
            ),
        };
        Self {
            state,
            consult_input_cap_u32,
            consult_output_cap_u32,
            provider_tier,
            approval_level,
            audit_level,
            render: state.render_truth(),
        }
    }
}

/// The operational route FSM. Wraps the canonical [`ModelRouter`] for hysteresis
/// transitions and projects the per-state [`RouteEffects`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RouteFsm {
    router: ModelRouter,
}

impl RouteFsm {
    /// A new FSM bound to a provider identity (starts `Normal`, healthy).
    #[must_use]
    pub const fn new(provider_identity_hash_32: [u8; 32]) -> Self {
        Self {
            router: ModelRouter::new(provider_identity_hash_32),
        }
    }

    /// The current route state.
    #[must_use]
    pub const fn state(&self) -> RouteExecutionState {
        self.router.state()
    }

    /// Transition to `to`, delegating hysteresis / no-flap to the canonical
    /// [`ModelRouter::transition`]. Returns `false` when the transition is an
    /// immediate flap-back and is rejected.
    pub fn transition(&mut self, to: RouteExecutionState) -> bool {
        self.router.transition(to)
    }

    /// The operational effects for the current state.
    #[must_use]
    pub const fn effects(&self) -> RouteEffects {
        RouteEffects::for_state(self.state())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::repl::latency::p95_ms;

    fn fsm() -> RouteFsm {
        RouteFsm::new([1u8; 32])
    }

    #[test]
    fn fast_is_local_only_no_consult() {
        let e = RouteEffects::for_state(RouteExecutionState::Fast);
        assert_eq!(e.provider_tier, ProviderTier::LocalOnly);
        assert_eq!(e.consult_input_cap_u32, 0);
        assert_eq!(e.consult_output_cap_u32, 0);
        assert_eq!(e.render, RenderTruth::Green);
    }

    #[test]
    fn slow_allows_bounded_consult() {
        let e = RouteEffects::for_state(RouteExecutionState::Slow);
        assert_eq!(e.provider_tier, ProviderTier::FrontierAdvisory);
        assert_eq!(e.consult_input_cap_u32, 8000);
        assert_eq!(e.consult_output_cap_u32, 2000);
        assert_eq!(e.render, RenderTruth::Yellow);
    }

    #[test]
    fn stuck_is_active_audit_explicit() {
        let e = RouteEffects::for_state(RouteExecutionState::Stuck);
        assert_eq!(e.approval_level, ApprovalLevel::Explicit);
        assert_eq!(e.audit_level, AuditLevel::Active);
        assert_eq!(e.consult_input_cap_u32, 16000);
        assert_eq!(e.render, RenderTruth::Red);
    }

    #[test]
    fn audit_state_effects() {
        let e = RouteEffects::for_state(RouteExecutionState::Audit);
        assert_eq!(e.audit_level, AuditLevel::Active);
        assert_eq!(e.consult_input_cap_u32, 12000);
        assert_eq!(e.consult_output_cap_u32, 4000);
        assert_eq!(e.render, RenderTruth::Red);
    }

    #[test]
    fn lockdown_freezes_all() {
        let e = RouteEffects::for_state(RouteExecutionState::Lockdown);
        assert_eq!(e.provider_tier, ProviderTier::Locked);
        assert_eq!(e.approval_level, ApprovalLevel::Frozen);
        assert_eq!(e.consult_input_cap_u32, 0);
        assert_eq!(e.render, RenderTruth::Red);
    }

    #[test]
    fn hysteresis_no_flap() {
        let mut f = fsm(); // starts Normal
        assert!(f.transition(RouteExecutionState::Slow));
        assert_eq!(f.state(), RouteExecutionState::Slow);
        // immediate reverse back to Normal (the state we came from) is a flap
        assert!(!f.transition(RouteExecutionState::Normal));
        assert_eq!(f.state(), RouteExecutionState::Slow);
    }

    #[test]
    fn state_render_matches_canonical() {
        for s in [
            RouteExecutionState::Fast,
            RouteExecutionState::Normal,
            RouteExecutionState::Slow,
            RouteExecutionState::Stuck,
            RouteExecutionState::Audit,
            RouteExecutionState::Lockdown,
            RouteExecutionState::UserFull,
        ] {
            assert_eq!(RouteEffects::for_state(s).render, s.render_truth());
        }
    }

    #[test]
    fn route_decision_p95_within_5ms() {
        let f = fsm();
        let mut samples = Vec::with_capacity(256);
        for _ in 0..256 {
            let t = std::time::Instant::now();
            let e = f.effects();
            std::hint::black_box(&e);
            samples.push(t.elapsed().as_nanos() as u64);
        }
        let p95 = p95_ms(&samples) / 1_000_000;
        assert!(p95 <= 5, "route decision p95 {p95}ms exceeds 5ms");
    }
}
