//! Incident pause / resume.
//!
//! `sinabro incident pause` / `resume`. An incident pause stops *risky* command
//! classes while keeping read-only status / doctor available, so an operator can
//! freeze side effects during an incident without going blind. Pause is an
//! **express** control command: it bypasses the normal / background / full /
//! replay / train / evidence queues and acknowledges on the hot path,
//! and every side effect must re-check the pause state
//! ([`IncidentController::preflight`]) before it runs. Resume is gated: it
//! requires the same typed approval an admin action does.
//!
//! Reuse: the risk taxonomy and the approval requirement are the
//! canonical safety policies [`crate::command::CommandRisk`] /
//! [`crate::command::ApprovalRequirement`] / [`crate::command::approval_for`]; the
//! red/yellow/green verdict is [`crate::tui::RenderTruth`]. This module performs
//! no live action.

use crate::command::{ApprovalRequirement, CommandRisk, approval_for};
use crate::tui::RenderTruth;

/// The incident lifecycle state.
#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IncidentState {
    /// Normal operation; command classes run subject to their own gates.
    Active = 1,
    /// Incident pause; only read-only commands run, risky classes are frozen.
    Paused = 2,
}

impl IncidentState {
    /// The stable `u8` discriminant.
    #[must_use]
    pub const fn as_u8(self) -> u8 {
        self as u8
    }
}

/// Why an incident command was refused (fail-closed).
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum IncidentReject {
    /// A risky command class was attempted while paused.
    #[error("command class frozen by incident pause")]
    PausedRiskyCommand,
    /// Resume was attempted without the required typed approval.
    #[error("resume requires typed approval")]
    ResumeNeedsApproval,
}

/// The acknowledgement of an express pause / resume.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PauseAck {
    /// The incident state after the transition.
    pub state: IncidentState,
    /// The control version after the transition (monotonic).
    pub version_u32: u32,
    /// Always `true`: the express control bypassed the normal / background queues.
    pub bypassed_queue: bool,
}

/// The incident controller: the shared incident state plus a monotonic version
/// bumped on every express transition.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct IncidentController {
    state: IncidentState,
    version_u32: u32,
}

impl Default for IncidentController {
    fn default() -> Self {
        Self::new()
    }
}

impl IncidentController {
    /// A new controller in [`IncidentState::Active`].
    #[must_use]
    pub const fn new() -> Self {
        Self {
            state: IncidentState::Active,
            version_u32: 0,
        }
    }

    /// The current incident state.
    #[must_use]
    pub const fn state(&self) -> IncidentState {
        self.state
    }

    /// The control version (bumped on every express transition).
    #[must_use]
    pub const fn version(&self) -> u32 {
        self.version_u32
    }

    /// Express incident pause: freeze risky command classes on the control plane,
    /// bump the version, and acknowledge on the hot path without entering any
    /// queue. Pausing an already-paused controller is idempotent (still paused).
    pub const fn express_pause(&mut self) -> PauseAck {
        self.state = IncidentState::Paused;
        self.version_u32 = self.version_u32.saturating_add(1);
        PauseAck {
            state: self.state,
            version_u32: self.version_u32,
            bypassed_queue: true,
        }
    }

    /// Resume from a pause. Gated: the caller must present the typed approval an
    /// admin action requires ([`approval_for`]`(`[`CommandRisk::Admin`]`)`), else
    /// the resume is refused (fail-closed).
    pub fn resume(&mut self, presented: ApprovalRequirement) -> Result<PauseAck, IncidentReject> {
        if presented != approval_for(CommandRisk::Admin) {
            return Err(IncidentReject::ResumeNeedsApproval);
        }
        self.state = IncidentState::Active;
        self.version_u32 = self.version_u32.saturating_add(1);
        Ok(PauseAck {
            state: self.state,
            version_u32: self.version_u32,
            bypassed_queue: true,
        })
    }

    /// The policy check: is a command of `risk` allowed in the current state?
    /// Read-only commands always run (status / doctor stay available); while
    /// paused, every other class is frozen. Pure and synchronous (p95 ≤ 5ms).
    pub const fn policy_check(&self, risk: CommandRisk) -> Result<(), IncidentReject> {
        match self.state {
            IncidentState::Active => Ok(()),
            IncidentState::Paused => {
                if matches!(risk, CommandRisk::ReadOnly) {
                    Ok(())
                } else {
                    Err(IncidentReject::PausedRiskyCommand)
                }
            }
        }
    }

    /// Re-check the pause state immediately before a side effect runs
    /// (every side effect re-reads control state). Identical
    /// to [`Self::policy_check`], named to mark the mandatory preflight.
    pub const fn preflight(&self, risk: CommandRisk) -> Result<(), IncidentReject> {
        self.policy_check(risk)
    }

    /// The render truth: `Green` when active, `Yellow` when paused (degraded, not
    /// failing — read-only commands still run).
    #[must_use]
    pub const fn render_truth(&self) -> RenderTruth {
        match self.state {
            IncidentState::Active => RenderTruth::Green,
            IncidentState::Paused => RenderTruth::Yellow,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::repl::latency::p95_ms;

    #[test]
    fn active_allows_every_class() {
        let c = IncidentController::new();
        for risk in [
            CommandRisk::ReadOnly,
            CommandRisk::LocalWrite,
            CommandRisk::Network,
            CommandRisk::WalletSign,
            CommandRisk::ChainWrite,
            CommandRisk::Admin,
        ] {
            assert!(
                c.policy_check(risk).is_ok(),
                "{risk:?} should run when active"
            );
        }
    }

    #[test]
    fn pause_freezes_install_gas_and_chain_write() {
        let mut c = IncidentController::new();
        c.express_pause();
        // install/remove (LocalWrite), gas (Network), chain write (ChainWrite).
        for risk in [
            CommandRisk::LocalWrite,
            CommandRisk::Network,
            CommandRisk::ChainWrite,
            CommandRisk::WalletSign,
        ] {
            assert_eq!(
                c.policy_check(risk),
                Err(IncidentReject::PausedRiskyCommand),
                "{risk:?} must be frozen while paused"
            );
        }
    }

    #[test]
    fn read_only_is_allowed_while_paused() {
        let mut c = IncidentController::new();
        c.express_pause();
        // status / doctor stay available.
        assert!(c.policy_check(CommandRisk::ReadOnly).is_ok());
    }

    #[test]
    fn pause_is_express_and_bypasses_queue() {
        let mut c = IncidentController::new();
        let ack = c.express_pause();
        assert!(ack.bypassed_queue);
        assert_eq!(ack.state, IncidentState::Paused);
        assert_eq!(ack.version_u32, 1);
    }

    #[test]
    fn pause_is_idempotent_state_but_versioned() {
        let mut c = IncidentController::new();
        let a = c.express_pause();
        let b = c.express_pause();
        assert_eq!(b.state, IncidentState::Paused); // still paused
        assert!(b.version_u32 > a.version_u32); // processed again, not queued
    }

    #[test]
    fn resume_requires_typed_approval() {
        let mut c = IncidentController::new();
        c.express_pause();
        // The required approval for an admin action is TypedPhrase.
        assert_eq!(
            approval_for(CommandRisk::Admin),
            ApprovalRequirement::TypedPhrase
        );
        // A weaker approval is refused.
        assert_eq!(
            c.resume(ApprovalRequirement::Confirm),
            Err(IncidentReject::ResumeNeedsApproval)
        );
        assert_eq!(c.state(), IncidentState::Paused);
        // The required typed approval resumes.
        let ack = c.resume(ApprovalRequirement::TypedPhrase);
        assert_eq!(
            ack,
            Ok(PauseAck {
                state: IncidentState::Active,
                version_u32: c.version(),
                bypassed_queue: true,
            })
        );
        assert_eq!(c.state(), IncidentState::Active);
    }

    #[test]
    fn side_effect_preflight_recheck_after_pause() {
        let mut c = IncidentController::new();
        // A risky command is fine before the pause...
        assert!(c.preflight(CommandRisk::ChainWrite).is_ok());
        c.express_pause();
        // ...and the mandatory preflight re-check refuses it after the pause.
        assert_eq!(
            c.preflight(CommandRisk::ChainWrite),
            Err(IncidentReject::PausedRiskyCommand)
        );
    }

    #[test]
    fn pause_while_full_job_saturated_acks_on_hot_path() {
        // The pause does not wait behind a saturated background queue; the ack is
        // synchronous (the controller holds no queue at all on this path).
        let mut c = IncidentController::new();
        let ack = c.express_pause();
        assert!(ack.bypassed_queue);
    }

    #[test]
    fn render_truth_active_green_paused_yellow() {
        let mut c = IncidentController::new();
        assert_eq!(c.render_truth(), RenderTruth::Green);
        c.express_pause();
        assert_eq!(c.render_truth(), RenderTruth::Yellow);
    }

    #[test]
    fn policy_check_p95_within_5ms() {
        let mut c = IncidentController::new();
        c.express_pause();
        let mut samples = Vec::with_capacity(256);
        for _ in 0..256 {
            let t = std::time::Instant::now();
            let v = c.policy_check(CommandRisk::ChainWrite);
            std::hint::black_box(&v);
            samples.push(t.elapsed().as_nanos() as u64);
        }
        let p95 = p95_ms(&samples) / 1_000_000;
        assert!(p95 <= 5, "incident policy check p95 {p95}ms exceeds 5ms");
    }
}
