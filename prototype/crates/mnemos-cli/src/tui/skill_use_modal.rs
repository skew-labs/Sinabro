//! Cockpit skill use / install status modal projecting the [`SkillUseView`].
//!
//! The modal shows the capability diff, the dry-run trace, the install-receipt
//! state, the rollback / remove path, and an explicit user-confirmation gate. It
//! is fail-closed: a quarantined or timed-out skill can never proceed, and a
//! skill that requires confirmation cannot install until the user confirms.
//!
//! No-commerce law: there is no checkout / buy / pay / refund surface here.
//! [`SkillUseModal::is_commerce`] is always `false`, the rendered lines carry no
//! price/payment token, and there is no method that could open a checkout.

use crate::tui::RenderTruth;

const ZERO32: [u8; 32] = [0u8; 32];

/// The use/install status projection for one skill.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SkillUseView {
    /// SHA-256 identity of the skill.
    pub skill_id_hash_32: [u8; 32],
    /// SHA-256 of the package being used/installed.
    pub package_hash_32: [u8; 32],
    /// SHA-256 of the dry-run (try-before-use) trace.
    pub dry_run_trace_hash_32: [u8; 32],
    /// SHA-256 of the install receipt.
    pub install_receipt_hash_32: [u8; 32],
    /// SHA-256 of the trust receipt (provenance / signature attestation).
    pub trust_receipt_hash_32: [u8; 32],
    /// Whether an explicit user confirmation is required before proceeding.
    pub requires_user_confirmation: bool,
}

impl SkillUseView {
    /// Construct a use view.
    #[must_use]
    pub const fn new(
        skill_id_hash_32: [u8; 32],
        package_hash_32: [u8; 32],
        dry_run_trace_hash_32: [u8; 32],
        install_receipt_hash_32: [u8; 32],
        trust_receipt_hash_32: [u8; 32],
        requires_user_confirmation: bool,
    ) -> Self {
        Self {
            skill_id_hash_32,
            package_hash_32,
            dry_run_trace_hash_32,
            install_receipt_hash_32,
            trust_receipt_hash_32,
            requires_user_confirmation,
        }
    }

    /// Whether a dry-run trace is present (a use must be tried before install).
    #[must_use]
    pub fn has_dry_run(&self) -> bool {
        self.dry_run_trace_hash_32 != ZERO32
    }

    /// Whether an install receipt is present.
    #[must_use]
    pub fn has_install_receipt(&self) -> bool {
        self.install_receipt_hash_32 != ZERO32
    }
}

/// The lifecycle status of a skill use/install.
#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum InstallStatus {
    /// Dry-run requested, not yet finished.
    DryRunPending = 1,
    /// Dry-run passed on redacted fixtures.
    DryRunPassed = 2,
    /// Dry-run failed (fail-closed: cannot install).
    DryRunFailed = 3,
    /// Installed (success).
    Installed = 4,
    /// Removed / rolled back.
    Removed = 5,
    /// Quarantined (security-fatal; sticky and fail-closed).
    Quarantined = 6,
    /// The operation timed out (a timeout is always a denial).
    TimedOut = 7,
}

impl InstallStatus {
    /// Whether this status forbids proceeding to install (fail-closed states).
    #[must_use]
    pub const fn is_blocking(self) -> bool {
        matches!(
            self,
            Self::DryRunFailed | Self::Quarantined | Self::TimedOut
        )
    }
}

/// The skill use/install modal. Pure projection; performs no install and
/// opens no checkout.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SkillUseModal {
    view: SkillUseView,
    status: InstallStatus,
    capability_diff_hash_32: [u8; 32],
    rollback_hash_32: [u8; 32],
    confirmed: bool,
}

impl SkillUseModal {
    /// Open a modal for `view`, showing `capability_diff` and the
    /// `rollback`/remove path. Starts in [`InstallStatus::DryRunPending`],
    /// unconfirmed.
    #[must_use]
    pub const fn new(
        view: SkillUseView,
        capability_diff_hash_32: [u8; 32],
        rollback_hash_32: [u8; 32],
    ) -> Self {
        Self {
            view,
            status: InstallStatus::DryRunPending,
            capability_diff_hash_32,
            rollback_hash_32,
            confirmed: false,
        }
    }

    /// The underlying view.
    #[must_use]
    pub const fn view(&self) -> SkillUseView {
        self.view
    }

    /// The current status.
    #[must_use]
    pub const fn status(&self) -> InstallStatus {
        self.status
    }

    /// Always `false`: this modal is never a commerce / checkout surface.
    #[must_use]
    pub const fn is_commerce(&self) -> bool {
        false
    }

    /// Non-blocking status refresh. Fail-closed: once [`InstallStatus::Quarantined`]
    /// the status is sticky (a quarantine can never be cleared by a refresh), so
    /// a later "passed"/"installed" can never override a quarantine.
    pub const fn refresh(&mut self, status: InstallStatus) {
        if matches!(self.status, InstallStatus::Quarantined) {
            return;
        }
        self.status = status;
    }

    /// Record an explicit user confirmation. Only meaningful when the view
    /// requires it.
    pub const fn confirm(&mut self) {
        if self.view.requires_user_confirmation {
            self.confirmed = true;
        }
    }

    /// Whether the user confirmation gate is satisfied (vacuously true when the
    /// view does not require confirmation).
    #[must_use]
    pub const fn confirmation_satisfied(&self) -> bool {
        !self.view.requires_user_confirmation || self.confirmed
    }

    /// Whether the rollback / remove path is available (a non-zero rollback
    /// hash). The modal always surfaces a removal route for an installed skill.
    #[must_use]
    pub fn has_rollback_path(&self) -> bool {
        self.rollback_hash_32 != ZERO32
    }

    /// Whether install may proceed. Requires a passed dry-run, a satisfied
    /// confirmation gate, and a non-blocking status. Fail-closed otherwise.
    #[must_use]
    pub const fn can_install(&self) -> bool {
        matches!(self.status, InstallStatus::DryRunPassed)
            && self.confirmation_satisfied()
            && !self.status.is_blocking()
    }

    /// The render truth: `Green` only when installed; `Red` for any fail-closed
    /// state; `Yellow` while pending / passed / removed.
    #[must_use]
    pub const fn render_truth(&self) -> RenderTruth {
        match self.status {
            InstallStatus::Installed => RenderTruth::Green,
            InstallStatus::DryRunFailed | InstallStatus::Quarantined | InstallStatus::TimedOut => {
                RenderTruth::Red
            }
            InstallStatus::DryRunPending | InstallStatus::DryRunPassed | InstallStatus::Removed => {
                RenderTruth::Yellow
            }
        }
    }

    /// A short colorless status label.
    #[must_use]
    pub const fn status_label(&self) -> &'static str {
        match self.status {
            InstallStatus::DryRunPending => "dry-run pending",
            InstallStatus::DryRunPassed => "dry-run passed",
            InstallStatus::DryRunFailed => "dry-run FAILED",
            InstallStatus::Installed => "installed",
            InstallStatus::Removed => "removed",
            InstallStatus::Quarantined => "QUARANTINED",
            InstallStatus::TimedOut => "TIMED OUT",
        }
    }

    /// Render the modal as bounded, colorless text lines. Surfaces capability
    /// diff, dry-run trace presence, install-receipt presence, rollback path,
    /// confirmation requirement, and status — never a price/checkout field.
    #[must_use]
    pub fn render(&self, rows: u16) -> Vec<String> {
        let lines = vec![
            format!("status: {}", self.status_label()),
            format!("capability_diff: {}", hex8(&self.capability_diff_hash_32)),
            format!("dry_run_trace: present={}", self.view.has_dry_run()),
            format!(
                "install_receipt: present={}",
                self.view.has_install_receipt()
            ),
            format!("rollback_path: present={}", self.has_rollback_path()),
            format!(
                "requires_confirmation={} confirmed={}",
                self.view.requires_user_confirmation, self.confirmed
            ),
            format!("can_install={}", self.can_install()),
        ];
        lines.into_iter().take(rows as usize).collect()
    }
}

/// First 8 hex chars of a 32-byte hash (compact display id).
fn hex8(bytes: &[u8; 32]) -> String {
    crate::hex32(bytes)[..8].to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn view(requires_confirm: bool) -> SkillUseView {
        SkillUseView::new(
            [1u8; 32],
            [2u8; 32],
            [3u8; 32], // dry-run trace present
            [4u8; 32], // install receipt present
            [5u8; 32],
            requires_confirm,
        )
    }

    fn modal(requires_confirm: bool) -> SkillUseModal {
        SkillUseModal::new(view(requires_confirm), [6u8; 32], [7u8; 32])
    }

    #[test]
    fn dry_run_pass_then_confirm_allows_install() {
        let mut m = modal(true);
        assert!(!m.can_install(), "pending + unconfirmed cannot install");
        m.refresh(InstallStatus::DryRunPassed);
        assert!(!m.can_install(), "passed but not yet confirmed");
        m.confirm();
        assert!(m.can_install(), "passed + confirmed installs");
    }

    #[test]
    fn dry_run_fail_blocks_install() {
        let mut m = modal(false);
        m.refresh(InstallStatus::DryRunFailed);
        assert!(!m.can_install());
        assert_eq!(m.render_truth(), RenderTruth::Red);
    }

    #[test]
    fn install_receipt_present_is_green_when_installed() {
        let mut m = modal(false);
        m.refresh(InstallStatus::DryRunPassed);
        m.refresh(InstallStatus::Installed);
        assert_eq!(m.render_truth(), RenderTruth::Green);
        assert!(m.view().has_install_receipt());
    }

    #[test]
    fn remove_path_is_always_available() {
        let m = modal(false);
        assert!(m.has_rollback_path());
    }

    #[test]
    fn quarantine_is_sticky_and_fail_closed() {
        let mut m = modal(false);
        m.refresh(InstallStatus::DryRunPassed);
        m.refresh(InstallStatus::Quarantined);
        assert_eq!(m.status(), InstallStatus::Quarantined);
        // a later "passed"/"installed" refresh can NOT clear a quarantine
        m.refresh(InstallStatus::Installed);
        assert_eq!(m.status(), InstallStatus::Quarantined);
        assert!(!m.can_install());
        assert_eq!(m.render_truth(), RenderTruth::Red);
    }

    #[test]
    fn timeout_is_a_denial() {
        let mut m = modal(false);
        m.refresh(InstallStatus::DryRunPassed);
        m.refresh(InstallStatus::TimedOut);
        assert!(!m.can_install());
        assert_eq!(m.render_truth(), RenderTruth::Red);
    }

    #[test]
    fn never_commerce_and_no_price_in_render() {
        let m = modal(true);
        assert!(!m.is_commerce());
        const FORBIDDEN: &[&str] = &[
            "price", "pay", "buy", "sell", "checkout", "refund", "fee", "cost", "$",
        ];
        for line in m.render(16) {
            for bad in FORBIDDEN {
                assert!(!line.contains(bad), "commerce token {bad} in render");
            }
        }
    }

    #[test]
    fn confirmation_not_required_when_view_says_so() {
        let mut m = modal(false);
        m.refresh(InstallStatus::DryRunPassed);
        // requires_user_confirmation=false -> gate vacuously satisfied
        assert!(m.confirmation_satisfied());
        assert!(m.can_install());
    }
}
