//! `sinabro federation` — federation opt-in controls (atom #465 · F.7.6
//! federation opt-in/dp-budget).
//!
//! A read-only control surface for the (future) federated-learning capability.
//! Federation is **explicit opt-in**: the default is [`FederationMode::Off`] and
//! **no data leaves by default** ([`FederationControlView::data_leaves_by_default`]
//! is always `false`). The differential-privacy budget and the audit-event count
//! are visible. Crucially, opting in does *not* start anything in Stage F: a
//! federated round is locked ([`FederationControlView::round_locked_in_stage_f`]
//! is always `true`, the G-F-FEDERATION-LOCK posture) — this atom only exposes
//! the control + status, never the L3 training itself.
//!
//! Disparity note (atom #465 reuse): the atom plan lists *"Stage K federation
//! plan"* under reuse, but Stage K does not exist on disk (no federation type is
//! defined in any crate — verified). This module therefore mints a local,
//! locked control-surface VIEW, exactly as the F-WP-06B `eval_core::EvalRunView`
//! handled a reuse-name that named no on-disk type. It introduces no new crate
//! edge and performs no live action.

use crate::tui::RenderTruth;

/// Whether the user has opted into federation. Default is [`Off`](Self::Off):
/// data stays local.
#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FederationMode {
    /// Federation is off — the safe default; nothing federates and no data
    /// leaves.
    Off = 1,
    /// The user has explicitly opted in. (In Stage F the round itself is still
    /// locked; this records the intent + budget only.)
    OptIn = 2,
}

impl FederationMode {
    /// The stable `u8` discriminant.
    #[must_use]
    pub const fn as_u8(self) -> u8 {
        self as u8
    }
}

/// A differential-privacy budget, in milli-epsilon units (so a fractional
/// epsilon is representable without floats). The budget is visible so a user can
/// see how much privacy budget a (future) federated round would consume.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DpBudget {
    /// The total privacy budget, in milli-epsilon (e.g. `1500` == ε 1.5).
    pub epsilon_milli: u32,
    /// The amount already spent, in milli-epsilon.
    pub spent_milli: u32,
}

impl DpBudget {
    /// Build a DP budget.
    #[must_use]
    pub const fn new(epsilon_milli: u32, spent_milli: u32) -> Self {
        Self {
            epsilon_milli,
            spent_milli,
        }
    }

    /// The remaining privacy budget (saturating; never negative).
    #[must_use]
    pub const fn remaining_milli(&self) -> u32 {
        self.epsilon_milli.saturating_sub(self.spent_milli)
    }

    /// Whether the privacy budget is exhausted (spent ≥ total).
    #[must_use]
    pub const fn exhausted(&self) -> bool {
        self.spent_milli >= self.epsilon_milli
    }
}

/// The federation control + status view.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FederationControlView {
    mode: FederationMode,
    dp: DpBudget,
    audit_event_count: u32,
}

impl FederationControlView {
    /// The safe default: federation off, an empty DP budget, no audit events.
    #[must_use]
    pub const fn off() -> Self {
        Self {
            mode: FederationMode::Off,
            dp: DpBudget::new(0, 0),
            audit_event_count: 0,
        }
    }

    /// An opted-in view with a DP budget and an audit-event count.
    #[must_use]
    pub const fn opt_in(dp: DpBudget, audit_event_count: u32) -> Self {
        Self {
            mode: FederationMode::OptIn,
            dp,
            audit_event_count,
        }
    }

    /// The current opt-in mode.
    #[must_use]
    pub const fn mode(&self) -> FederationMode {
        self.mode
    }

    /// The DP budget.
    #[must_use]
    pub const fn dp_budget(&self) -> DpBudget {
        self.dp
    }

    /// The number of recorded federation audit events.
    #[must_use]
    pub const fn audit_event_count(&self) -> u32 {
        self.audit_event_count
    }

    /// Always `false`: federation never sends data by default (default-deny),
    /// regardless of mode.
    #[must_use]
    pub const fn data_leaves_by_default(&self) -> bool {
        false
    }

    /// Always `true`: a federated round is locked in Stage F. Opting in records
    /// intent + budget but cannot start L3 training here (G-F-FEDERATION-LOCK).
    #[must_use]
    pub const fn round_locked_in_stage_f(&self) -> bool {
        true
    }

    /// The render truth. `Off` (default-deny, safe) is `Green`; an opted-in view
    /// with budget remaining is `Yellow` (degraded from max-safety, and still
    /// locked); an opted-in view whose DP budget is exhausted is `Red`.
    #[must_use]
    pub const fn render_truth(&self) -> RenderTruth {
        match self.mode {
            FederationMode::Off => RenderTruth::Green,
            FederationMode::OptIn => {
                if self.dp.exhausted() {
                    RenderTruth::Red
                } else {
                    RenderTruth::Yellow
                }
            }
        }
    }

    /// Colorless federation status lines bounded by `rows`.
    #[must_use]
    pub fn render(&self, rows: u16) -> Vec<String> {
        let lines = vec![
            format!("mode_u8={}", self.mode.as_u8()),
            format!("data_leaves_by_default={}", self.data_leaves_by_default()),
            format!("round_locked={}", self.round_locked_in_stage_f()),
            format!("dp_epsilon_milli={}", self.dp.epsilon_milli),
            format!("dp_spent_milli={}", self.dp.spent_milli),
            format!("dp_remaining_milli={}", self.dp.remaining_milli()),
            format!("dp_exhausted={}", self.dp.exhausted()),
            format!("audit_events={}", self.audit_event_count),
            format!("truth_u8={}", self.render_truth() as u8),
        ];
        lines.into_iter().take(rows as usize).collect()
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    #![allow(clippy::expect_used)]
    #![allow(clippy::panic)]

    use super::*;

    #[test]
    fn default_is_off_and_default_deny() {
        let v = FederationControlView::off();
        assert_eq!(v.mode(), FederationMode::Off);
        assert!(!v.data_leaves_by_default());
        assert_eq!(v.render_truth(), RenderTruth::Green);
    }

    #[test]
    fn opt_in_is_explicit_and_still_locked() {
        let v = FederationControlView::opt_in(DpBudget::new(1500, 100), 3);
        assert_eq!(v.mode(), FederationMode::OptIn);
        // Opting in never bypasses the Stage F federation lock, and never
        // changes the default-deny egress posture.
        assert!(v.round_locked_in_stage_f());
        assert!(!v.data_leaves_by_default());
        assert_eq!(v.render_truth(), RenderTruth::Yellow);
    }

    #[test]
    fn dp_budget_remaining_and_exhausted() {
        let ok = DpBudget::new(1000, 250);
        assert_eq!(ok.remaining_milli(), 750);
        assert!(!ok.exhausted());
        let spent = DpBudget::new(1000, 1000);
        assert_eq!(spent.remaining_milli(), 0);
        assert!(spent.exhausted());
        // Over-spend saturates, never underflows.
        let over = DpBudget::new(1000, 1500);
        assert_eq!(over.remaining_milli(), 0);
        assert!(over.exhausted());
    }

    #[test]
    fn exhausted_dp_budget_while_opted_in_is_red() {
        let v = FederationControlView::opt_in(DpBudget::new(1000, 1000), 5);
        assert!(v.dp_budget().exhausted());
        assert_eq!(v.render_truth(), RenderTruth::Red);
    }

    #[test]
    fn audit_view_is_visible() {
        let v = FederationControlView::opt_in(DpBudget::new(2000, 0), 7);
        assert_eq!(v.audit_event_count(), 7);
        assert!(v.render(64).iter().any(|l| l == "audit_events=7"));
    }

    #[test]
    fn render_is_bounded_and_no_commerce() {
        let v = FederationControlView::opt_in(DpBudget::new(1500, 500), 2);
        assert!(v.render(3).len() <= 3);
        assert!(v.render(64).len() <= 9);
        const COMMERCE: &[&str] = &["price", "buy", "sell", "checkout", "refund", "$"];
        for line in v.render(64) {
            for t in COMMERCE {
                assert!(!line.contains(*t), "commerce token {t} leaked: {line}");
            }
        }
    }
}
