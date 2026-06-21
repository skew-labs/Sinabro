//! `mnemos-e-skill::rollback` — atom #272 · D.1.16 — rollback / remove /
//! quarantine plan.
//!
//! Every install mutation has a reverse operation or a tombstone, and a
//! rollback can be run twice safely: each [`RollbackOp`] maps to a fixed
//! terminal [`LocalSkillState`], so applying the same op again is idempotent.
//! `Quarantine` and `Remove` map to non-executable states
//! ([`LocalSkillState::Revoked`] / [`LocalSkillState::Removed`]), so they can
//! never leave an executable artifact active
//! ([`LocalSkillState::is_executable`]).
//!
//! This module **first-mints** the §4.5 [`LocalSkillState`] as its first
//! consumer; the later adoption WorkPackage reuses it and never re-mints it.

#![deny(missing_docs)]

/// §4.5 local skill lifecycle state. `#[repr(u8)]` 1-byte discriminant
/// (`1..=7`). Minted here (D-WP-02) as the first consumer.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
#[repr(u8)]
pub enum LocalSkillState {
    /// Known but not trialed or installed.
    Available = 1,
    /// Passed a try-before-use dry-run.
    DryRunPassed = 2,
    /// Installed but not enabled.
    Installed = 3,
    /// Installed and enabled (active).
    Enabled = 4,
    /// Installed but disabled (inactive).
    Disabled = 5,
    /// Removed (tombstoned) — not executable.
    Removed = 6,
    /// Revoked / quarantined — not executable.
    Revoked = 7,
}

impl LocalSkillState {
    /// Whether a skill in this state may execute. Only [`Self::Installed`] and
    /// [`Self::Enabled`] execute; every other state (including the
    /// quarantine/remove sinks) never does.
    #[inline]
    #[must_use]
    pub const fn is_executable(self) -> bool {
        matches!(self, Self::Installed | Self::Enabled)
    }
}

/// A reverse / terminating operation on local install state.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum RollbackOp {
    /// Undo a failed / partial install back to [`LocalSkillState::Available`].
    FailedInstall,
    /// Deactivate an installed skill ([`LocalSkillState::Disabled`]).
    Disable,
    /// Remove (tombstone) a skill ([`LocalSkillState::Removed`]).
    Remove,
    /// Quarantine / revoke a skill ([`LocalSkillState::Revoked`]).
    Quarantine,
}

/// Apply a rollback op. The target state depends only on `op`, not on the
/// `_current` state, so applying the same op twice is idempotent — running
/// rollback again is always safe. `Remove` and `Quarantine` map to
/// non-executable terminal states.
#[inline]
#[must_use]
pub const fn apply_rollback(_current: LocalSkillState, op: RollbackOp) -> LocalSkillState {
    match op {
        RollbackOp::FailedInstall => LocalSkillState::Available,
        RollbackOp::Disable => LocalSkillState::Disabled,
        RollbackOp::Remove => LocalSkillState::Removed,
        RollbackOp::Quarantine => LocalSkillState::Revoked,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn failed_install_rolls_back_to_available() {
        assert_eq!(
            apply_rollback(LocalSkillState::Installed, RollbackOp::FailedInstall),
            LocalSkillState::Available
        );
    }

    #[test]
    fn remove_rolls_back_to_removed_non_executable() {
        let s = apply_rollback(LocalSkillState::Installed, RollbackOp::Remove);
        assert_eq!(s, LocalSkillState::Removed);
        assert!(!s.is_executable());
    }

    #[test]
    fn quarantine_rolls_back_to_revoked_non_executable() {
        let s = apply_rollback(LocalSkillState::Enabled, RollbackOp::Quarantine);
        assert_eq!(s, LocalSkillState::Revoked);
        assert!(!s.is_executable());
    }

    #[test]
    fn rollback_is_idempotent() {
        let once = apply_rollback(LocalSkillState::Installed, RollbackOp::Remove);
        let twice = apply_rollback(once, RollbackOp::Remove);
        assert_eq!(once, twice);
    }

    #[test]
    fn only_installed_or_enabled_execute() {
        assert!(LocalSkillState::Installed.is_executable());
        assert!(LocalSkillState::Enabled.is_executable());
        for s in [
            LocalSkillState::Available,
            LocalSkillState::DryRunPassed,
            LocalSkillState::Disabled,
            LocalSkillState::Removed,
            LocalSkillState::Revoked,
        ] {
            assert!(!s.is_executable(), "{s:?} must not execute");
        }
    }
}
