//! Skill install-state command group (atom #440 · F.4.5):
//! `sinabro skill enable|disable|update|remove|quarantine`.
//!
//! Each operation is explicit, traced, idempotent (where the canonical lifecycle
//! is idempotent), and tied to a [`LocalInstallReceipt`]. State moves go through
//! the canonical [`apply_transition`] over [`LocalSkillState`], so there is no
//! `available -> enabled` bypass, an `update` is compatibility-gated, and a
//! removed / quarantined skill can never transition back to an executable state.
//! Every successful state change appends a [`SkillStateAudit`] bound to the
//! receipt id (`G-F-SAFETY` — no side effect without an audit).
//!
//! Reuse (no reinvention): the lifecycle, transition table, and rollback ops are
//! the canonical `mnemos-e-skill` surface; the reported lifecycle is the canonical
//! on-chain-pinned [`InstallState`]; the risk → approval mapping is canonical.
//! Pure / offline: no network, wallet, chain, gas, or provider action.

use crate::command::{ApprovalRequirement, CommandRisk, approval_for};
use crate::sha256_32;
use mnemos_e_skill::{
    CompatibilityDecision, InstallState, LocalInstallReceipt, LocalSkillState,
    LocalSkillTransition, TransitionAudit, TransitionError, apply_transition,
};

/// Why a state command was refused. Wraps the canonical [`TransitionError`] so a
/// bypass attempt and an incompatible update stay distinguishable.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SkillStateReject {
    /// The `(state, transition)` move is illegal — a bypass, or any move out of a
    /// terminal (removed/revoked) state, or an incompatible update.
    Transition(TransitionError),
}

/// One audited state change (`G-F-SAFETY`). Bound to the receipt it acted on, so
/// the local install lifecycle has a replayable, attributable audit trail.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SkillStateAudit {
    /// SHA-256 fingerprint of the install-receipt id this change acted on.
    pub receipt_fingerprint_32: [u8; 32],
    /// The skill id (newtype inner) the receipt is for.
    pub skill_id_u16: u16,
    /// State before the transition.
    pub from: LocalSkillState,
    /// The transition applied.
    pub transition: LocalSkillTransition,
    /// State after the transition.
    pub to: LocalSkillState,
    /// The command risk class of a state mutation (local write).
    pub risk: CommandRisk,
    /// The approval requirement derived from the risk.
    pub approval: ApprovalRequirement,
}

/// First 8 hex chars of a 32-byte hash, for a compact, redaction-safe display id.
fn hex8(bytes: &[u8; 32]) -> String {
    crate::hex32(bytes)[..8].to_string()
}

/// Project a [`LocalSkillState`] (`rollback` lifecycle) onto the canonical
/// on-chain-pinned [`InstallState`] for status reporting. A 1:1 mapping.
const fn project_install_state(state: LocalSkillState) -> InstallState {
    match state {
        LocalSkillState::Available => InstallState::None,
        LocalSkillState::DryRunPassed => InstallState::DryRun,
        LocalSkillState::Installed => InstallState::Installed,
        LocalSkillState::Enabled => InstallState::Enabled,
        LocalSkillState::Disabled => InstallState::Disabled,
        LocalSkillState::Removed => InstallState::Removed,
        LocalSkillState::Revoked => InstallState::Revoked,
    }
}

/// The skill install-state controller for one installed skill, driven by its
/// [`LocalInstallReceipt`]. Holds the current lifecycle state and an append-only
/// audit log; every successful state change is audited.
#[derive(Clone, Debug)]
pub struct SkillStateController {
    receipt: LocalInstallReceipt,
    state: LocalSkillState,
    risk: CommandRisk,
    audit: Vec<SkillStateAudit>,
}

impl SkillStateController {
    /// Open a controller over an existing [`LocalInstallReceipt`], starting from
    /// the receipt's recorded lifecycle state.
    #[must_use]
    pub fn from_receipt(receipt: LocalInstallReceipt) -> Self {
        Self {
            state: receipt.state,
            receipt,
            // A state mutation writes local state -> LocalWrite -> Confirm.
            risk: CommandRisk::LocalWrite,
            audit: Vec::new(),
        }
    }

    /// The current local lifecycle state.
    #[must_use]
    pub const fn state(&self) -> LocalSkillState {
        self.state
    }

    /// The receipt this controller is driven by.
    #[must_use]
    pub const fn receipt(&self) -> LocalInstallReceipt {
        self.receipt
    }

    /// The current state reported as the canonical on-chain-pinned lifecycle.
    #[must_use]
    pub const fn install_state(&self) -> InstallState {
        project_install_state(self.state)
    }

    /// Whether the skill may execute now (only `Installed` / `Enabled`).
    #[must_use]
    pub const fn is_executable(&self) -> bool {
        self.state.is_executable()
    }

    /// The approval requirement for a state mutation, via the canonical mapping.
    #[must_use]
    pub const fn approval_requirement(&self) -> ApprovalRequirement {
        approval_for(self.risk)
    }

    /// The append-only audit log of successful state changes.
    #[must_use]
    pub fn audit_log(&self) -> &[SkillStateAudit] {
        &self.audit
    }

    /// Apply a forward lifecycle transition via the canonical [`apply_transition`].
    /// On success the state advances and a [`SkillStateAudit`] is appended; a
    /// rejected move changes nothing and is **not** audited (no side effect). A
    /// removed / quarantined skill only accepts its own idempotent terminal move.
    pub fn apply(
        &mut self,
        transition: LocalSkillTransition,
        compat: Option<CompatibilityDecision>,
    ) -> Result<TransitionAudit, SkillStateReject> {
        let result = apply_transition(self.state, transition, compat)
            .map_err(SkillStateReject::Transition)?;
        self.state = result.to;
        self.audit.push(SkillStateAudit {
            receipt_fingerprint_32: sha256_32(self.receipt.id.as_bytes()),
            skill_id_u16: self.receipt.skill.0,
            from: result.from,
            transition,
            to: result.to,
            risk: self.risk,
            approval: approval_for(self.risk),
        });
        Ok(result)
    }

    /// Enable an installed / disabled skill.
    pub fn enable(&mut self) -> Result<TransitionAudit, SkillStateReject> {
        self.apply(LocalSkillTransition::Enable, None)
    }

    /// Disable an installed / enabled skill.
    pub fn disable(&mut self) -> Result<TransitionAudit, SkillStateReject> {
        self.apply(LocalSkillTransition::Disable, None)
    }

    /// Re-validate an installed skill against a new package; compatibility-gated
    /// (an incompatible decision is refused).
    pub fn update(
        &mut self,
        compat: CompatibilityDecision,
    ) -> Result<TransitionAudit, SkillStateReject> {
        self.apply(LocalSkillTransition::Update, Some(compat))
    }

    /// Remove (tombstone) the skill — terminal, non-executable, idempotent.
    pub fn remove(&mut self) -> Result<TransitionAudit, SkillStateReject> {
        self.apply(LocalSkillTransition::Remove, None)
    }

    /// Quarantine / revoke the skill — terminal, non-executable, idempotent. A
    /// quarantined skill can never be re-enabled (fail-closed).
    pub fn quarantine(&mut self) -> Result<TransitionAudit, SkillStateReject> {
        self.apply(LocalSkillTransition::Revoke, None)
    }

    /// Render the controller as bounded, colorless text lines — never a price /
    /// checkout field.
    #[must_use]
    pub fn render(&self, rows: u16) -> Vec<String> {
        let lines = vec![
            format!("skill={}", self.receipt.skill.0),
            format!("install_state_u8={}", self.install_state().as_u8()),
            format!("executable={}", self.is_executable()),
            format!("audit_records={}", self.audit.len()),
            format!("receipt_id={}", hex8(self.receipt.id.as_bytes())),
        ];
        lines.into_iter().take(rows as usize).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mnemos_a_core::{StageBTraceLink, StageCTraceLink, StageDTraceLink};
    use mnemos_e_skill::{
        CompatibilityDecision, LocalInstallReceipt, LocalInstallReceiptId, LocalSkillState,
        SkillId, SkillPackageDigest32, SuiAddress,
    };

    fn trace() -> StageDTraceLink {
        let b = StageBTraceLink::new(0xF440_0001, 440, 0);
        let c = StageCTraceLink::new(b, 240, 9);
        StageDTraceLink::new(c, 440, 1)
    }

    fn receipt(state: LocalSkillState) -> LocalInstallReceipt {
        LocalInstallReceipt {
            id: LocalInstallReceiptId::new([0x33; 32]),
            skill: SkillId(7),
            package: SkillPackageDigest32::new([0x44; 32]),
            user: SuiAddress::new([0xAB; 32]),
            state,
            capability_approval_hash_32: [0x77; 32],
            trace: trace(),
        }
    }

    #[test]
    fn receipt_tied_and_install_state_reported() {
        let c = SkillStateController::from_receipt(receipt(LocalSkillState::Installed));
        assert_eq!(c.state(), LocalSkillState::Installed);
        assert_eq!(c.install_state(), InstallState::Installed);
        assert!(c.is_executable());
    }

    #[test]
    fn install_gate_no_bypass() {
        // A use/trial receipt sits at DryRunPassed; enabling without installing is
        // an illegal bypass and is refused with no audit (no side effect).
        let mut c = SkillStateController::from_receipt(receipt(LocalSkillState::DryRunPassed));
        let r = c.enable();
        assert_eq!(
            r,
            Err(SkillStateReject::Transition(
                TransitionError::InvalidTransition
            ))
        );
        assert!(!c.is_executable());
        assert!(c.audit_log().is_empty());
    }

    #[test]
    fn enable_disable_audited_and_tied_to_receipt() {
        let mut c = SkillStateController::from_receipt(receipt(LocalSkillState::Installed));
        assert!(c.enable().is_ok());
        assert_eq!(c.state(), LocalSkillState::Enabled);
        assert!(c.disable().is_ok());
        assert_eq!(c.state(), LocalSkillState::Disabled);
        assert_eq!(c.audit_log().len(), 2);
        if let Some(first) = c.audit_log().first() {
            assert_eq!(first.skill_id_u16, 7);
            assert_ne!(first.receipt_fingerprint_32, [0u8; 32]);
            assert_eq!(first.from, LocalSkillState::Installed);
            assert_eq!(first.to, LocalSkillState::Enabled);
        }
    }

    #[test]
    fn update_is_compatibility_gated() {
        let mut c = SkillStateController::from_receipt(receipt(LocalSkillState::Installed));
        // Compatible update keeps the installed-family state.
        assert!(c.update(CompatibilityDecision::Compatible).is_ok());
        assert_eq!(c.state(), LocalSkillState::Installed);
        // Incompatible update is refused.
        assert_eq!(
            c.update(CompatibilityDecision::Incompatible),
            Err(SkillStateReject::Transition(TransitionError::Incompatible))
        );
    }

    #[test]
    fn remove_rollback_is_terminal_and_idempotent() {
        let mut c = SkillStateController::from_receipt(receipt(LocalSkillState::Enabled));
        assert!(c.remove().is_ok());
        assert_eq!(c.state(), LocalSkillState::Removed);
        assert!(!c.is_executable());
        // Idempotent: removing again stays Removed.
        assert!(c.remove().is_ok());
        assert_eq!(c.state(), LocalSkillState::Removed);
    }

    #[test]
    fn quarantine_deny_fail_closed() {
        let mut c = SkillStateController::from_receipt(receipt(LocalSkillState::Enabled));
        assert!(c.quarantine().is_ok());
        assert_eq!(c.state(), LocalSkillState::Revoked);
        assert_eq!(c.install_state(), InstallState::Revoked);
        assert!(!c.is_executable());
        // A quarantined skill can never be re-enabled.
        assert_eq!(
            c.enable(),
            Err(SkillStateReject::Transition(
                TransitionError::InvalidTransition
            ))
        );
        assert!(!c.is_executable());
    }

    #[test]
    fn every_state_change_is_audited() {
        let mut c = SkillStateController::from_receipt(receipt(LocalSkillState::Installed));
        let _ = c.enable();
        let _ = c.disable();
        let _ = c.enable();
        assert_eq!(c.audit_log().len(), 3);
        for record in c.audit_log() {
            assert_eq!(record.risk, CommandRisk::LocalWrite);
            assert_eq!(record.approval, ApprovalRequirement::Confirm);
        }
    }

    #[test]
    fn render_has_no_commerce_token() {
        let c = SkillStateController::from_receipt(receipt(LocalSkillState::Enabled));
        const FORBIDDEN: &[&str] = &[
            "price", "pay", "buy", "sell", "checkout", "refund", "fee", "cost", "$",
        ];
        for line in c.render(16) {
            for bad in FORBIDDEN {
                assert!(
                    !line.contains(bad),
                    "commerce token {bad} in render: {line}"
                );
            }
        }
    }
}
