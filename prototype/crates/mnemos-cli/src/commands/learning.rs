//! `sinabro learning` — learning-mode control surface (F-WP-06B, atom #454 ·
//! F.6.3 learning mode).
//!
//! Product users choose `off` / `evidence_only` / `local_diet` /
//! `private_adapter` / `contribute_redacted`; the **default is `off`** — no
//! learning artifact is produced and nothing leaves the machine. Switching modes
//! is a [`CommandRisk::LocalWrite`] (a confirm); turning on *contribution*
//! requires explicit approval on top and never uploads silently. Training on
//! external model output stays denied in every mode.
//!
//! Reuse (no reinvention): the posture is the canonical §4.2
//! [`crate::config::LearningControlView`] / [`crate::config::LearningMode`] /
//! [`crate::config::DataEgressMode`]. This module mints no new learning type — it
//! is a switch + projection over the config truth, and performs no live action.

use crate::command::{ApprovalRequirement, CommandRisk, approval_for};
use crate::config::{DataEgressMode, LearningControlView, LearningMode};
use crate::tui::RenderTruth;

/// Why a learning-mode command was refused (fail-closed).
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum LearningReject {
    /// The requested token is not one of the five closed learning modes.
    #[error("unknown learning mode")]
    UnknownMode,
    /// Turning on redacted contribution requires explicit approval that was not
    /// supplied (contribution never happens silently).
    #[error("contribution requires explicit approval")]
    ContributionNeedsApproval,
}

/// The `sinabro learning` command surface: a projection over the canonical
/// [`LearningControlView`] plus a fail-closed mode switch. The default value is
/// the safe default posture (learning off, egress none).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub struct LearningCommandView {
    control: LearningControlView,
}

impl LearningCommandView {
    /// A view at the safe default (learning **off**, egress **none**).
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Project an existing learning control posture.
    #[must_use]
    pub const fn from_control(control: LearningControlView) -> Self {
        Self { control }
    }

    /// The active learning mode.
    #[must_use]
    pub const fn mode(&self) -> LearningMode {
        self.control.mode
    }

    /// The active data-egress mode.
    #[must_use]
    pub const fn egress(&self) -> DataEgressMode {
        self.control.egress
    }

    /// The underlying canonical control view.
    #[must_use]
    pub const fn control(&self) -> LearningControlView {
        self.control
    }

    /// Whether learning is off (the default posture).
    #[must_use]
    pub fn is_off(&self) -> bool {
        matches!(self.control.mode, LearningMode::Off)
    }

    /// Whether any data egress is enabled (false at the default).
    #[must_use]
    pub fn egress_enabled(&self) -> bool {
        !matches!(self.control.egress, DataEgressMode::None)
    }

    /// The approval gate a mode switch must pass: a local config write needs a
    /// confirm (the canonical [`approval_for`] mapping). Contribution layers an
    /// extra explicit approval on top (see [`Self::switch`]).
    #[must_use]
    pub fn switch_approval(&self) -> ApprovalRequirement {
        approval_for(CommandRisk::LocalWrite)
    }

    /// Switch to a parsed mode token. `contribute_redacted` requires
    /// `contribution_approved == true` (no silent contribution); every other mode
    /// is a plain local switch. An unknown token is refused. The egress mode is
    /// derived from the learning mode, and external-model-output training stays
    /// denied unconditionally.
    pub fn switch(&self, token: &str, contribution_approved: bool) -> Result<Self, LearningReject> {
        let mode = LearningMode::parse(token).ok_or(LearningReject::UnknownMode)?;
        if matches!(mode, LearningMode::ContributeRedacted) && !contribution_approved {
            return Err(LearningReject::ContributionNeedsApproval);
        }
        let egress = match mode {
            LearningMode::Off => DataEgressMode::None,
            LearningMode::EvidenceOnly | LearningMode::LocalDiet => DataEgressMode::LocalOnly,
            LearningMode::PrivateAdapter => DataEgressMode::SelfHosted,
            LearningMode::ContributeRedacted => DataEgressMode::ExplicitContribution,
        };
        Ok(Self {
            control: LearningControlView {
                mode,
                egress,
                global_contribution: matches!(mode, LearningMode::ContributeRedacted),
                external_model_output_training_denied: true,
            },
        })
    }

    /// Render truth: **off** is the safe `Green` default; any active learning mode
    /// is `Yellow` (a deliberate opt-in posture the user should see); an
    /// inconsistent posture (egress enabled while off, or external-model training
    /// somehow allowed) is `Red`.
    #[must_use]
    pub fn render_truth(&self) -> RenderTruth {
        if !self.control.external_model_output_training_denied {
            return RenderTruth::Red;
        }
        match self.control.mode {
            LearningMode::Off => {
                if self.egress_enabled() {
                    RenderTruth::Red
                } else {
                    RenderTruth::Green
                }
            }
            _ => RenderTruth::Yellow,
        }
    }

    /// Colorless status lines bounded by `rows`.
    #[must_use]
    pub fn render(&self, rows: u16) -> Vec<String> {
        let lines = vec![
            format!("learning_mode_u8={}", self.control.mode as u8),
            format!("data_egress_u8={}", self.control.egress as u8),
            format!("global_contribution={}", self.control.global_contribution),
            format!(
                "external_model_output_training_denied={}",
                self.control.external_model_output_training_denied
            ),
            format!("is_off={}", self.is_off()),
            format!("egress_enabled={}", self.egress_enabled()),
            format!("switch_approval_u8={}", self.switch_approval() as u8),
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

    const COMMERCE_TOKENS: &[&str] = &[
        "price", "pay", "buy", "sell", "checkout", "refund", "fee", "cost", "$",
    ];

    #[test]
    fn default_is_off_and_green() {
        let v = LearningCommandView::new();
        assert!(v.is_off());
        assert!(!v.egress_enabled());
        assert_eq!(v.mode(), LearningMode::Off);
        assert_eq!(v.egress(), DataEgressMode::None);
        assert_eq!(v.render_truth(), RenderTruth::Green);
    }

    #[test]
    fn switch_to_local_modes_sets_local_egress_and_yellow() {
        let v = LearningCommandView::new();
        let ev = v.switch("evidence_only", false).unwrap();
        assert_eq!(ev.mode(), LearningMode::EvidenceOnly);
        assert_eq!(ev.egress(), DataEgressMode::LocalOnly);
        assert_eq!(ev.render_truth(), RenderTruth::Yellow);
        let ld = v.switch("local_diet", false).unwrap();
        assert_eq!(ld.egress(), DataEgressMode::LocalOnly);
        assert_eq!(ld.render_truth(), RenderTruth::Yellow);
    }

    #[test]
    fn contribution_requires_explicit_approval() {
        let v = LearningCommandView::new();
        assert_eq!(
            v.switch("contribute_redacted", false),
            Err(LearningReject::ContributionNeedsApproval)
        );
        let ok = v.switch("contribute_redacted", true).unwrap();
        assert_eq!(ok.mode(), LearningMode::ContributeRedacted);
        assert_eq!(ok.egress(), DataEgressMode::ExplicitContribution);
        assert!(ok.control().global_contribution);
    }

    #[test]
    fn unknown_mode_rejected() {
        let v = LearningCommandView::new();
        assert_eq!(
            v.switch("train_now", true),
            Err(LearningReject::UnknownMode)
        );
    }

    #[test]
    fn switch_is_local_write_confirm() {
        assert_eq!(
            LearningCommandView::new().switch_approval(),
            ApprovalRequirement::Confirm
        );
    }

    #[test]
    fn external_model_training_always_denied() {
        let v = LearningCommandView::new();
        assert!(v.control().external_model_output_training_denied);
        for token in ["evidence_only", "local_diet", "private_adapter"] {
            let s = v.switch(token, true).unwrap();
            assert!(
                s.control().external_model_output_training_denied,
                "{token} must keep external-model training denied"
            );
        }
    }

    #[test]
    fn render_bounded_and_no_commerce() {
        let v = LearningCommandView::new()
            .switch("private_adapter", true)
            .unwrap();
        assert!(v.render(3).len() <= 3);
        assert!(v.render(64).len() <= 8);
        for line in v.render(64) {
            for bad in COMMERCE_TOKENS {
                assert!(!line.contains(bad), "commerce token {bad} in {line}");
            }
        }
    }
}
