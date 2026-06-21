//! Operational trajectory-health guard (atom #499 · G.1.8).
//!
//! Stage F minted [`TrajectoryHealth`] (a `u16` bitset of [`TrajectorySignal`]
//! flags, with `record` / `should_halt`). Stage G adds the *operational guard*
//! that maps a set of unhealthy signals to a concrete route action — continue,
//! slow, audit, or lockdown — and the route state that action implies.
//!
//! Secret-custody invariant (`G-G-SECRET-ZERO`): this guard reads **only** the
//! typed [`TrajectoryHealth`] bitset. It never stores, clones, `Debug`-prints, or
//! transmits any raw secret, wallet, or gas value — `SecretTouch` / `GasRisk` are
//! abstract typed flags, carrying no payload. The guard performs no I/O.
//!
//! Reuse (no reinvention): [`TrajectoryHealth`] / [`TrajectorySignal`] from
//! [`crate::commands::model_route`], [`RouteExecutionState`] from
//! [`crate::route`].

use crate::commands::model_route::{TrajectoryHealth, TrajectorySignal};
use crate::route::RouteExecutionState;

/// The route action the guard recommends. Discriminants are ordered by severity:
/// `Continue < Slow < Audit < Lockdown`, so the most severe action across all set
/// signals wins.
#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GuardAction {
    /// Healthy — keep running.
    Continue = 1,
    /// Slow the route (degraded trajectory).
    Slow = 2,
    /// Escalate to audit (claim/evidence problem).
    Audit = 3,
    /// Lock the route down (security boundary touched).
    Lockdown = 4,
}

/// Every trajectory signal, in bit order, so the guard can fold a whole bitset.
const SIGNALS: [TrajectorySignal; 11] = [
    TrajectorySignal::SemanticLoop,
    TrajectorySignal::VerificationSkip,
    TrajectorySignal::Contradiction,
    TrajectorySignal::ScopeSprawl,
    TrajectorySignal::TopicDrift,
    TrajectorySignal::CyclicCompression,
    TrajectorySignal::EvidenceMismatch,
    TrajectorySignal::ApprovalBypass,
    TrajectorySignal::GasRisk,
    TrajectorySignal::SecretTouch,
    TrajectorySignal::ToolEscalation,
];

/// The guard action a single signal implies. Security-boundary signals
/// (`SecretTouch` / `ApprovalBypass` / `GasRisk` / `ToolEscalation`) force a
/// lockdown; claim/evidence problems force an audit; the rest slow the route.
#[must_use]
pub const fn action_for_signal(signal: TrajectorySignal) -> GuardAction {
    match signal {
        TrajectorySignal::SecretTouch
        | TrajectorySignal::ApprovalBypass
        | TrajectorySignal::GasRisk
        | TrajectorySignal::ToolEscalation => GuardAction::Lockdown,
        TrajectorySignal::Contradiction | TrajectorySignal::EvidenceMismatch => GuardAction::Audit,
        TrajectorySignal::SemanticLoop
        | TrajectorySignal::VerificationSkip
        | TrajectorySignal::ScopeSprawl
        | TrajectorySignal::TopicDrift
        | TrajectorySignal::CyclicCompression => GuardAction::Slow,
    }
}

impl GuardAction {
    /// Stable, render-ready label (consumed by the agent-loop receipt, P2-2).
    #[inline]
    #[must_use]
    pub const fn class_label(self) -> &'static str {
        match self {
            Self::Continue => "continue",
            Self::Slow => "slow",
            Self::Audit => "audit",
            Self::Lockdown => "lockdown",
        }
    }
}

/// The route state a guard action implies.
#[must_use]
pub const fn route_for_action(action: GuardAction) -> RouteExecutionState {
    match action {
        GuardAction::Continue => RouteExecutionState::Normal,
        GuardAction::Slow => RouteExecutionState::Slow,
        GuardAction::Audit => RouteExecutionState::Audit,
        GuardAction::Lockdown => RouteExecutionState::Lockdown,
    }
}

/// Fold a [`TrajectoryHealth`] bitset into the most severe recommended
/// [`GuardAction`]. A healthy trajectory recommends [`GuardAction::Continue`].
#[must_use]
pub fn recommended_action(health: TrajectoryHealth) -> GuardAction {
    let bits = health.bits();
    let mut action = GuardAction::Continue;
    for signal in SIGNALS {
        if bits & (signal as u16) != 0 {
            let candidate = action_for_signal(signal);
            if (candidate as u8) > (action as u8) {
                action = candidate;
            }
        }
    }
    action
}

/// The route state recommended for a [`TrajectoryHealth`] bitset.
#[must_use]
pub fn recommended_route(health: TrajectoryHealth) -> RouteExecutionState {
    route_for_action(recommended_action(health))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn with(signal: TrajectorySignal) -> TrajectoryHealth {
        let mut h = TrajectoryHealth::healthy();
        h.record(signal);
        h
    }

    #[test]
    fn healthy_continues_at_normal() {
        let h = TrajectoryHealth::healthy();
        assert_eq!(recommended_action(h), GuardAction::Continue);
        assert_eq!(recommended_route(h), RouteExecutionState::Normal);
    }

    #[test]
    fn semantic_loop_slows() {
        let h = with(TrajectorySignal::SemanticLoop);
        assert_eq!(recommended_action(h), GuardAction::Slow);
        assert_eq!(recommended_route(h), RouteExecutionState::Slow);
    }

    #[test]
    fn verification_skip_slows() {
        assert_eq!(
            recommended_action(with(TrajectorySignal::VerificationSkip)),
            GuardAction::Slow
        );
    }

    #[test]
    fn scope_sprawl_and_drift_slow() {
        assert_eq!(
            recommended_action(with(TrajectorySignal::ScopeSprawl)),
            GuardAction::Slow
        );
        assert_eq!(
            recommended_action(with(TrajectorySignal::TopicDrift)),
            GuardAction::Slow
        );
    }

    #[test]
    fn cyclic_compression_slows() {
        assert_eq!(
            recommended_action(with(TrajectorySignal::CyclicCompression)),
            GuardAction::Slow
        );
    }

    #[test]
    fn contradiction_and_evidence_mismatch_audit() {
        assert_eq!(
            recommended_action(with(TrajectorySignal::Contradiction)),
            GuardAction::Audit
        );
        let h = with(TrajectorySignal::EvidenceMismatch);
        assert_eq!(recommended_action(h), GuardAction::Audit);
        assert_eq!(recommended_route(h), RouteExecutionState::Audit);
    }

    #[test]
    fn secret_touch_locks_down() {
        let h = with(TrajectorySignal::SecretTouch);
        assert_eq!(recommended_action(h), GuardAction::Lockdown);
        assert_eq!(recommended_route(h), RouteExecutionState::Lockdown);
    }

    #[test]
    fn most_severe_signal_wins() {
        let mut h = TrajectoryHealth::healthy();
        h.record(TrajectorySignal::SemanticLoop); // Slow
        h.record(TrajectorySignal::SecretTouch); // Lockdown (more severe)
        assert_eq!(recommended_action(h), GuardAction::Lockdown);
    }
}
