//! Operational adaptive model-escalation heuristic (atom #501 · G.1.10).
//!
//! Stage F minted [`ConsultTrigger`] (the typed reasons a frontier consult may be
//! requested) and [`consult_token_cap`] (per-state token caps; FAST/NORMAL/
//! LOCKDOWN/USER_FULL = `(0,0)`). Stage G adds the *escalation decision*: routine
//! work stays on the local executor (no consult); a frontier consult opens only
//! for a typed trigger on a route state whose cap is non-zero
//! (SLOW/STUCK/AUDIT), and a user-requested deep review additionally needs the
//! user's approval. This is a pure decision — no provider call.
//!
//! Reuse (no reinvention): [`ConsultTrigger`] + [`consult_token_cap`] from
//! [`crate::commands::model_route`], [`RouteExecutionState`] from
//! [`crate::route`].

use crate::commands::model_route::{ConsultTrigger, consult_token_cap};
use crate::route::RouteExecutionState;

/// The escalation decision for a step.
#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EscalationDecision {
    /// Routine work — stay on the local executor, no frontier consult.
    NoConsultLocal = 1,
    /// Open a bounded frontier-advisory consult.
    ConsultFrontier = 2,
    /// Denied: the route state denies a standard bounded consult
    /// (FAST/NORMAL/LOCKDOWN/USER_FULL have a 0-token cap).
    DeniedByState = 3,
    /// Denied: a user-requested deep review without the user's approval.
    DeniedByUser = 4,
}

impl EscalationDecision {
    /// Whether this decision opens a frontier consult.
    #[must_use]
    pub const fn opens_consult(self) -> bool {
        matches!(self, Self::ConsultFrontier)
    }
}

/// The inputs to an escalation decision.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EscalationInputs {
    /// The current route state.
    pub route_state: RouteExecutionState,
    /// The typed consult trigger, if any. `None` = routine work.
    pub trigger: Option<ConsultTrigger>,
    /// Whether the user explicitly approved a deep review.
    pub user_approved: bool,
}

/// Decide whether to escalate to a frontier consult. Routine work (no trigger)
/// stays local; a trigger on a 0-token-cap state is denied by state; a
/// user-requested deep review without approval is denied; otherwise a bounded
/// consult opens.
#[must_use]
pub fn decide(inputs: &EscalationInputs) -> EscalationDecision {
    let Some(trigger) = inputs.trigger else {
        return EscalationDecision::NoConsultLocal;
    };
    let (cap_in, cap_out) = consult_token_cap(inputs.route_state);
    if cap_in == 0 && cap_out == 0 {
        return EscalationDecision::DeniedByState;
    }
    if matches!(trigger, ConsultTrigger::UserRequested) && !inputs.user_approved {
        return EscalationDecision::DeniedByUser;
    }
    EscalationDecision::ConsultFrontier
}

/// The RD-49 typed-trigger egress consult policy (#605). A provider egress consult
/// may be requested ONLY for a TYPED `trigger` (the parameter is a [`ConsultTrigger`],
/// never an `Option` — there is NO untyped / prompt-vibe escalation path) on a
/// consult-capable route state. FAST / NORMAL / LOCKDOWN / USER_FULL deny (their
/// 0-token cap → 0 unprovoked egress); [`ConsultTrigger::UserRequested`] additionally
/// needs the user's approval. Reuses [`decide`]; the resulting consult is recorded
/// in the route trace as [`crate::route::RouteEvent::ConsultOpened`] (the trigger is
/// always visible — a consult is never silent).
#[must_use]
pub fn egress_consult_decision(
    route_state: RouteExecutionState,
    trigger: ConsultTrigger,
    user_approved: bool,
) -> EscalationDecision {
    decide(&EscalationInputs {
        route_state,
        trigger: Some(trigger),
        user_approved,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::repl::latency::p95_ms;

    fn inputs(
        route_state: RouteExecutionState,
        trigger: Option<ConsultTrigger>,
        user_approved: bool,
    ) -> EscalationInputs {
        EscalationInputs {
            route_state,
            trigger,
            user_approved,
        }
    }

    #[test]
    fn routine_no_consult() {
        let d = decide(&inputs(RouteExecutionState::Normal, None, false));
        assert_eq!(d, EscalationDecision::NoConsultLocal);
        assert!(!d.opens_consult());
    }

    #[test]
    fn stuck_consult() {
        let d = decide(&inputs(
            RouteExecutionState::Stuck,
            Some(ConsultTrigger::RepeatedFailure),
            false,
        ));
        assert_eq!(d, EscalationDecision::ConsultFrontier);
        assert!(d.opens_consult());
    }

    #[test]
    fn high_risk_consult() {
        let d = decide(&inputs(
            RouteExecutionState::Audit,
            Some(ConsultTrigger::AuditImpact),
            false,
        ));
        assert_eq!(d, EscalationDecision::ConsultFrontier);
    }

    #[test]
    fn user_denial_then_approval() {
        let denied = decide(&inputs(
            RouteExecutionState::Slow,
            Some(ConsultTrigger::UserRequested),
            false,
        ));
        assert_eq!(denied, EscalationDecision::DeniedByUser);
        let allowed = decide(&inputs(
            RouteExecutionState::Slow,
            Some(ConsultTrigger::UserRequested),
            true,
        ));
        assert_eq!(allowed, EscalationDecision::ConsultFrontier);
    }

    #[test]
    fn token_cap_state_denies_consult() {
        for state in [
            RouteExecutionState::Fast,
            RouteExecutionState::Normal,
            RouteExecutionState::Lockdown,
            RouteExecutionState::UserFull,
        ] {
            let d = decide(&inputs(state, Some(ConsultTrigger::RepeatedFailure), true));
            assert_eq!(
                d,
                EscalationDecision::DeniedByState,
                "{state:?} has a 0-token cap and must deny a standard consult"
            );
        }
    }

    #[test]
    fn decision_p95_within_5ms() {
        let i = inputs(
            RouteExecutionState::Slow,
            Some(ConsultTrigger::RepeatedFailure),
            true,
        );
        let mut samples = Vec::with_capacity(256);
        for _ in 0..256 {
            let t = std::time::Instant::now();
            let d = decide(&i);
            std::hint::black_box(&d);
            samples.push(t.elapsed().as_nanos() as u64);
        }
        let p95 = p95_ms(&samples) / 1_000_000;
        assert!(p95 <= 5, "escalation decision p95 {p95}ms exceeds 5ms");
    }

    // ---- #605 typed-trigger egress policy ---------------------------------

    #[test]
    fn every_typed_trigger_opens_consult_on_capable_state() {
        // each typed trigger on a consult-capable state (STUCK) opens a consult;
        // UserRequested additionally needs approval (supplied here).
        for trigger in ConsultTrigger::ALL {
            let d = egress_consult_decision(RouteExecutionState::Stuck, trigger, true);
            assert_eq!(
                d,
                EscalationDecision::ConsultFrontier,
                "{trigger:?} on STUCK must open a consult"
            );
            assert!(d.opens_consult());
        }
    }

    #[test]
    fn fast_normal_never_consult_for_any_trigger() {
        // 0 unprovoked egress: FAST/NORMAL (0-token cap) deny EVERY typed trigger.
        for trigger in ConsultTrigger::ALL {
            for state in [RouteExecutionState::Fast, RouteExecutionState::Normal] {
                assert_eq!(
                    egress_consult_decision(state, trigger, true),
                    EscalationDecision::DeniedByState,
                    "{state:?} must never consult ({trigger:?})"
                );
            }
        }
    }

    #[test]
    fn untyped_escalation_is_local_no_egress() {
        // there is no untyped path to egress: no trigger => stay local (decide(None)).
        let d = decide(&inputs(RouteExecutionState::Stuck, None, true));
        assert_eq!(d, EscalationDecision::NoConsultLocal);
        assert!(!d.opens_consult());
    }

    #[test]
    fn trigger_is_recorded_in_route_trace_never_silent() {
        use crate::commands::model_route::TrajectoryHealth;
        use crate::route::{RouteEvent, RouterDecisionTrace};
        let trigger = ConsultTrigger::AbiMismatch;
        assert!(egress_consult_decision(RouteExecutionState::Stuck, trigger, true).opens_consult());
        let mut trace = RouterDecisionTrace::new();
        trace.record(
            RouteExecutionState::Stuck,
            TrajectoryHealth::healthy(),
            RouteEvent::ConsultOpened(trigger),
        );
        assert_eq!(trace.len(), 1);
        assert_eq!(trace.steps()[0].event, RouteEvent::ConsultOpened(trigger));
        assert!(
            trace.is_no_silent_fallback(),
            "a consult is never a silent fallback"
        );
        // falsifiability: a different trigger is a distinct recorded event
        assert_ne!(
            RouteEvent::ConsultOpened(trigger),
            RouteEvent::ConsultOpened(ConsultTrigger::RepeatedFailure)
        );
    }
}
