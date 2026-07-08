//! Cockpit top status bar.
//!
//! The status bar is a *pure projection* of truth the core owns: workspace /
//! provider+model / context pressure / budget / sandbox / pending counts (from
//! [`PromptStatus`]), plus the router FSM state
//! ([`crate::route::RouteExecutionState`]), the active gate truth, and a
//! trajectory-health summary. The render law: a cell is `Green` only when the
//! underlying state is actually healthy; `Stuck` / `Audit` / `Lockdown` route
//! states and any unwired subsystem can never be shown as `Green`.

use crate::repl::prompt::PromptStatus;
use crate::route::RouteExecutionState;
use crate::tui::RenderTruth;

/// The projected cockpit status bar.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StatusBar {
    /// The underlying prompt/status fields (workspace, model, context, budget…).
    pub status: PromptStatus,
    /// Router FSM execution state.
    pub route_state: RouteExecutionState,
    /// Truth of the most recent gate run for the active surface.
    pub gate: RenderTruth,
    /// Trajectory-health summary truth. A *faithful* projection: `Unknown` until
    /// the trajectory-health subsystem wires a measured value,
    /// and rendered verbatim — never upgraded to `Green`.
    pub trajectory: RenderTruth,
}

impl StatusBar {
    /// Build a status bar from its sources.
    #[must_use]
    pub const fn new(
        status: PromptStatus,
        route_state: RouteExecutionState,
        gate: RenderTruth,
        trajectory: RenderTruth,
    ) -> Self {
        Self {
            status,
            route_state,
            gate,
            trajectory,
        }
    }

    /// The route axis truth (mapped from the FSM state).
    #[must_use]
    pub const fn route_truth(self) -> RenderTruth {
        self.route_state.render_truth()
    }

    /// Context-pressure truth from `context_pressure_bps`: green below 7500 bps,
    /// yellow below 9000, red at/above 9000.
    #[must_use]
    pub const fn context_truth(self) -> RenderTruth {
        match self.status.context_pressure_bps {
            0..=7499 => RenderTruth::Green,
            7500..=8999 => RenderTruth::Yellow,
            _ => RenderTruth::Red,
        }
    }

    /// Whether the *whole* bar may be shown as healthy. Healthy iff route, gate,
    /// and trajectory are all `Green`. Any non-green axis — including `Unknown`
    /// — makes the bar non-healthy (no false-green).
    #[must_use]
    pub const fn is_healthy(self) -> bool {
        self.route_truth().is_healthy() && self.gate.is_healthy() && self.trajectory.is_healthy()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn status(pressure_bps: u16) -> PromptStatus {
        PromptStatus {
            workspace_hash_32: [1u8; 32],
            model_hash_32: [2u8; 32],
            context_pressure_bps: pressure_bps,
            last_checkpoint_hash_32: [3u8; 32],
            budget_remaining_micros: 1_000_000,
            sandbox_tier_u8: 1,
            pending_approvals_u16: 0,
            pending_tasks_u16: 0,
        }
    }

    #[test]
    fn all_green_bar_is_healthy() {
        let bar = StatusBar::new(
            status(0),
            RouteExecutionState::Normal,
            RenderTruth::Green,
            RenderTruth::Green,
        );
        assert!(bar.is_healthy());
        assert_eq!(bar.route_truth(), RenderTruth::Green);
    }

    #[test]
    fn stuck_route_makes_bar_unhealthy() {
        let bar = StatusBar::new(
            status(0),
            RouteExecutionState::Stuck,
            RenderTruth::Green,
            RenderTruth::Green,
        );
        assert_eq!(bar.route_truth(), RenderTruth::Red);
        assert!(!bar.is_healthy());
    }

    #[test]
    fn lockdown_and_audit_routes_are_never_healthy() {
        for s in [RouteExecutionState::Lockdown, RouteExecutionState::Audit] {
            let bar = StatusBar::new(status(0), s, RenderTruth::Green, RenderTruth::Green);
            assert!(!bar.is_healthy());
        }
    }

    #[test]
    fn unknown_trajectory_is_not_healthy() {
        let bar = StatusBar::new(
            status(0),
            RouteExecutionState::Normal,
            RenderTruth::Green,
            RenderTruth::Unknown,
        );
        assert!(!bar.is_healthy());
    }

    #[test]
    fn context_pressure_red_yellow_green_mapping() {
        assert_eq!(
            StatusBar::new(
                status(0),
                RouteExecutionState::Fast,
                RenderTruth::Green,
                RenderTruth::Green
            )
            .context_truth(),
            RenderTruth::Green
        );
        assert_eq!(
            StatusBar::new(
                status(8000),
                RouteExecutionState::Fast,
                RenderTruth::Green,
                RenderTruth::Green
            )
            .context_truth(),
            RenderTruth::Yellow
        );
        assert_eq!(
            StatusBar::new(
                status(9500),
                RouteExecutionState::Fast,
                RenderTruth::Green,
                RenderTruth::Green
            )
            .context_truth(),
            RenderTruth::Red
        );
    }

    #[test]
    fn red_gate_makes_bar_unhealthy() {
        let bar = StatusBar::new(
            status(0),
            RouteExecutionState::Normal,
            RenderTruth::Red,
            RenderTruth::Green,
        );
        assert!(!bar.is_healthy());
    }
}
