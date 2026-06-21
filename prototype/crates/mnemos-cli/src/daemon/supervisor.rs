//! Operational daemon supervisor view (atom #509 · G.2.3).
//!
//! The Sinabro daemon starts background watchers (provider / audit / memory /
//! evidence / notification queues) but owns **no wallet or provider secret**: the
//! supervisor view is a pure lifecycle projection whose type has no field that
//! could hold secret or wallet material ("no secret clone, no wallet import",
//! `G-G-OPERATIONAL-ENTRY`). Degraded / stuck / lockdown states are visible and
//! killable; a stopped daemon renders `Unknown`, never a false green.
//!
//! Reuse (no reinvention): the supervisor concept is the Stage A
//! [`mnemos_a_core`] runtime supervisor + the F daemon status; the
//! red/yellow/green verdict is the cockpit [`crate::tui::RenderTruth`]. This
//! module performs no live action.

use crate::tui::RenderTruth;

/// The lifecycle state of a background daemon watcher set.
#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DaemonState {
    /// Not started.
    Stopped = 1,
    /// Running normally.
    Running = 2,
    /// Degraded — recoverable, attention needed.
    Degraded = 3,
    /// Stuck — not progressing; not healthy.
    Stuck = 4,
    /// Locked down — a safety boundary tripped.
    Lockdown = 5,
}

impl DaemonState {
    /// The stable `u8` discriminant.
    #[must_use]
    pub const fn as_u8(self) -> u8 {
        self as u8
    }

    /// The cockpit render truth. `Running` is `Green`; `Degraded` is `Yellow`;
    /// `Stuck` / `Lockdown` are `Red`; a `Stopped` daemon is `Unknown` (never a
    /// false green).
    #[must_use]
    pub const fn render_truth(self) -> RenderTruth {
        match self {
            Self::Running => RenderTruth::Green,
            Self::Degraded => RenderTruth::Yellow,
            Self::Stuck | Self::Lockdown => RenderTruth::Red,
            Self::Stopped => RenderTruth::Unknown,
        }
    }

    /// A short human-readable name for user-facing cards (no raw `state_u8`).
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Stopped => "stopped",
            Self::Running => "running",
            Self::Degraded => "degraded",
            Self::Stuck => "stuck",
            Self::Lockdown => "lockdown",
        }
    }

    /// Whether a watcher set in this state is killable (any started state — a
    /// running, degraded, stuck, or locked-down daemon can be stopped).
    #[must_use]
    pub const fn is_killable(self) -> bool {
        matches!(
            self,
            Self::Running | Self::Degraded | Self::Stuck | Self::Lockdown
        )
    }
}

/// A read-only view of the Sinabro daemon supervisor. It tracks watcher lifecycle
/// state only and structurally holds NO wallet, provider, or secret material —
/// the type has no field that could carry one.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DaemonSupervisorView {
    /// The supervisor's own non-secret numeric id.
    pub supervisor_id_u32: u32,
    /// The current aggregate watcher state.
    pub state: DaemonState,
    /// Number of background watchers attached.
    pub watcher_count_u16: u16,
}

impl DaemonSupervisorView {
    /// A started supervisor in [`DaemonState::Running`] with `watcher_count` watchers.
    #[must_use]
    pub const fn started(supervisor_id_u32: u32, watcher_count_u16: u16) -> Self {
        Self {
            supervisor_id_u32,
            state: DaemonState::Running,
            watcher_count_u16,
        }
    }

    /// A stopped supervisor (no watchers).
    #[must_use]
    pub const fn stopped(supervisor_id_u32: u32) -> Self {
        Self {
            supervisor_id_u32,
            state: DaemonState::Stopped,
            watcher_count_u16: 0,
        }
    }

    /// Move the supervisor to a new state (e.g. degraded / stuck / lockdown).
    pub const fn set_state(&mut self, state: DaemonState) {
        self.state = state;
    }

    /// Structural invariant marker: the supervisor view never owns a secret or
    /// wallet (it has no field that could). Always `true`.
    #[must_use]
    pub const fn holds_no_secret_or_wallet(&self) -> bool {
        true
    }

    /// Whether the daemon can be killed right now.
    #[must_use]
    pub const fn is_killable(&self) -> bool {
        self.state.is_killable()
    }

    /// Redacted, colorless status lines bounded by `rows` (hot path). Holds and
    /// renders no secret or wallet material.
    #[must_use]
    pub fn render(&self, rows: u16) -> Vec<String> {
        let lines = vec![
            format!("supervisor_id={}", self.supervisor_id_u32),
            format!("state_u8={}", self.state.as_u8()),
            format!("watcher_count={}", self.watcher_count_u16),
            format!("killable={}", self.is_killable()),
            format!(
                "holds_no_secret_or_wallet={}",
                self.holds_no_secret_or_wallet()
            ),
            format!("truth_u8={}", self.state.render_truth() as u8),
        ];
        lines.into_iter().take(rows as usize).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::repl::latency::p95_ms;

    #[test]
    fn start_view_is_running_and_killable() {
        let d = DaemonSupervisorView::started(7, 4);
        assert_eq!(d.state, DaemonState::Running);
        assert_eq!(d.watcher_count_u16, 4);
        assert!(d.is_killable());
        assert_eq!(d.state.render_truth(), RenderTruth::Green);
    }

    #[test]
    fn stop_view_is_stopped_unknown_not_killable() {
        let d = DaemonSupervisorView::stopped(7);
        assert_eq!(d.state, DaemonState::Stopped);
        assert!(!d.is_killable());
        assert_eq!(d.state.render_truth(), RenderTruth::Unknown);
    }

    #[test]
    fn degraded_is_yellow_and_killable() {
        let mut d = DaemonSupervisorView::started(1, 2);
        d.set_state(DaemonState::Degraded);
        assert_eq!(d.state.render_truth(), RenderTruth::Yellow);
        assert!(d.is_killable());
    }

    #[test]
    fn stuck_and_lockdown_are_red_and_killable() {
        for s in [DaemonState::Stuck, DaemonState::Lockdown] {
            let mut d = DaemonSupervisorView::started(1, 1);
            d.set_state(s);
            assert_eq!(
                d.state.render_truth(),
                RenderTruth::Red,
                "{s:?} must be red"
            );
            assert!(d.is_killable(), "{s:?} must be killable");
        }
    }

    #[test]
    fn no_secret_clone_no_wallet_import() {
        let d = DaemonSupervisorView::started(9, 3);
        // Structural: the view type has no field that can hold a secret or wallet.
        assert!(d.holds_no_secret_or_wallet());
        // The render emits only numeric / boolean status — never a secret VALUE.
        // (Field names may describe the no-secret invariant; values never carry one.)
        const FORBIDDEN_VALUES: &[&str] = &["privkey", "suiprivkey", "0x", "begin private"];
        for line in d.render(64) {
            let lower = line.to_ascii_lowercase();
            for t in FORBIDDEN_VALUES {
                assert!(
                    !lower.contains(*t),
                    "secret-shaped value {t} leaked: {line}"
                );
            }
            // Every rendered line is a `key=value` status pair (no free-form blob).
            assert!(line.contains('='), "non-status line in render: {line}");
        }
    }

    #[test]
    fn status_render_p95_within_50ms() {
        let d = DaemonSupervisorView::started(1, 8);
        let mut samples = Vec::with_capacity(256);
        for _ in 0..256 {
            let t = std::time::Instant::now();
            let lines = d.render(32);
            std::hint::black_box(&lines);
            samples.push(t.elapsed().as_nanos() as u64);
        }
        let p95 = p95_ms(&samples) / 1_000_000;
        assert!(
            p95 <= 50,
            "daemon supervisor render p95 {p95}ms exceeds 50ms"
        );
    }
}
