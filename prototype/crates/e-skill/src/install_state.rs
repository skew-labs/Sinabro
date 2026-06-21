//! atom #284 · D.2.8 — on-chain install-state model + runtime-usable decision.
//!
//! [`InstallState`] is the §4.3 lifecycle enum, byte-pinned to the Move
//! `mnemos_skill_registry::install_receipt` `STATE_*` constants
//! (`None=1 … Revoked=7`). Runtime use requires `Installed` or `Enabled`;
//! `Disabled`/`Removed`/`Revoked` always deny, and a stale local receipt is
//! denied until refreshed. Pure / offline: no network, no wallet, no chain
//! action. Complements [`crate::install_plan`] (#271): the install plan decides
//! whether to install; this state decides whether an existing install may run.
//!
//! ## #316 · D.4.5 — local install state machine
//!
//! This module is also the home for the **local** install state machine over
//! the reused §4.5 [`crate::rollback::LocalSkillState`] (NOT the on-chain
//! [`InstallState`] above). [`apply_transition`] encodes the only valid local
//! transitions — `dry_run -> installed -> enabled/disabled`, idempotent
//! install, `update` (compat-gated via #315), and `remove`/`revoke` (reusing
//! the `rollback` ops) — with no `available -> enabled` bypass. Every
//! transition emits a [`TransitionAudit`] for the audit trail, and a terminal
//! `Removed`/`Revoked` skill can never transition back to an executable state.
//! Pure / offline; no network, wallet, secret, or chain action.

use crate::compat::CompatibilityDecision;
use crate::install_receipt::compatibility_admits_install;
use crate::rollback::{LocalSkillState, RollbackOp, apply_rollback};

/// On-chain install lifecycle state (§4.3), byte-pinned to the Move
/// `install_receipt::STATE_*` constants.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
#[repr(u8)]
pub enum InstallState {
    /// No install recorded.
    None = 1,
    /// A try-before-use dry-run passed but nothing is installed yet.
    DryRun = 2,
    /// Installed and runtime-usable.
    Installed = 3,
    /// Explicitly enabled and runtime-usable.
    Enabled = 4,
    /// Disabled — not runtime-usable until re-enabled.
    Disabled = 5,
    /// Removed (terminal) — not runtime-usable.
    Removed = 6,
    /// Revoked (terminal) — not runtime-usable.
    Revoked = 7,
}

impl InstallState {
    /// The raw discriminant byte (matches the Move `STATE_*` constant).
    #[inline]
    #[must_use]
    pub const fn as_u8(self) -> u8 {
        self as u8
    }

    /// Parse from the discriminant byte, rejecting unknown values.
    #[inline]
    #[must_use]
    pub const fn from_u8(byte: u8) -> Option<Self> {
        match byte {
            1 => Some(Self::None),
            2 => Some(Self::DryRun),
            3 => Some(Self::Installed),
            4 => Some(Self::Enabled),
            5 => Some(Self::Disabled),
            6 => Some(Self::Removed),
            7 => Some(Self::Revoked),
            _ => None,
        }
    }

    /// Runtime use requires `Installed` or `Enabled`.
    #[inline]
    #[must_use]
    pub const fn is_runtime_usable(self) -> bool {
        matches!(self, Self::Installed | Self::Enabled)
    }

    /// Terminal states (`Removed`, `Revoked`) can never become usable again.
    #[inline]
    #[must_use]
    pub const fn is_terminal(self) -> bool {
        matches!(self, Self::Removed | Self::Revoked)
    }
}

/// Whether a skill may run NOW: a runtime-usable state AND a local install
/// digest that still matches the on-chain receipt. A stale local copy
/// (`local_digest_matches == false`) is denied until refreshed — a local flag
/// can never re-enable a disabled / removed / revoked or drifted install.
#[inline]
#[must_use]
pub fn runtime_decision(state: InstallState, local_digest_matches: bool) -> bool {
    state.is_runtime_usable() && local_digest_matches
}

// ===========================================================================
// #316 · D.4.5 — local skill install state machine over LocalSkillState
// ===========================================================================

/// A forward operation on the local skill lifecycle (#316). Distinct from the
/// reverse-only [`crate::rollback::RollbackOp`]: these are the *forward* moves
/// (`dry_run`, `install`, `enable`, `disable`, `update`) plus the two
/// terminating moves (`remove`, `revoke`) that reuse the rollback ops.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum LocalSkillTransition {
    /// Run a try-before-use dry-run (`Available -> DryRunPassed`).
    DryRun,
    /// Install after a passing dry-run (`DryRunPassed -> Installed`); idempotent
    /// when already `Installed`.
    Install,
    /// Enable an installed/disabled skill (`-> Enabled`).
    Enable,
    /// Disable an installed/enabled skill (`-> Disabled`).
    Disable,
    /// Re-validate an installed skill against a new package/compat (stays in the
    /// same state); requires a compatible decision (#315 / #300).
    Update,
    /// Remove (tombstone) the skill (`-> Removed`), reusing the rollback op.
    Remove,
    /// Revoke / quarantine the skill (`-> Revoked`), reusing the rollback op.
    Revoke,
}

/// Why a local transition was rejected.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum TransitionError {
    /// The `(state, transition)` pair is not a legal move — e.g. a direct
    /// `Available -> Enabled` bypass, or any move out of a terminal state.
    InvalidTransition,
    /// An `Update` was attempted without a compatible decision (#315).
    Incompatible,
}

impl TransitionError {
    /// Stable, leak-free class label.
    #[inline]
    #[must_use]
    pub const fn class_label(&self) -> &'static str {
        match self {
            Self::InvalidTransition => "install_state.invalid_transition",
            Self::Incompatible => "install_state.update_incompatible",
        }
    }
}

/// One audited local transition: the state moved from, the transition applied,
/// and the resulting state. Emitted by [`apply_transition`] so the local
/// install lifecycle has a replayable audit trail.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub struct TransitionAudit {
    /// State before the transition.
    pub from: LocalSkillState,
    /// The transition applied.
    pub transition: LocalSkillTransition,
    /// State after the transition.
    pub to: LocalSkillState,
}

/// Apply a forward local transition, returning the audited result or a
/// [`TransitionError`]. The transition table is explicit; there is no
/// `Available -> Installed/Enabled` bypass (install requires a prior dry-run),
/// `Update` requires a compatible decision (#315
/// [`compatibility_admits_install`]), `Remove`/`Revoke` reuse the
/// [`apply_rollback`] terminal ops, and a terminal `Removed`/`Revoked` skill
/// only accepts its own idempotent self-loop.
pub fn apply_transition(
    current: LocalSkillState,
    transition: LocalSkillTransition,
    compat: Option<CompatibilityDecision>,
) -> Result<TransitionAudit, TransitionError> {
    use LocalSkillState as S;
    use LocalSkillTransition as T;
    let to = match (current, transition) {
        (S::Available, T::DryRun) | (S::DryRunPassed, T::DryRun) => S::DryRunPassed,
        // Install requires a prior dry-run; idempotent once installed.
        (S::DryRunPassed, T::Install) | (S::Installed, T::Install) => S::Installed,
        (S::Installed, T::Enable) | (S::Disabled, T::Enable) => S::Enabled,
        (S::Installed, T::Disable) | (S::Enabled, T::Disable) => S::Disabled,
        // Update is compat-gated and keeps the current installed-family state.
        (S::Installed | S::Enabled | S::Disabled, T::Update) => match compat {
            Some(decision) if compatibility_admits_install(decision) => current,
            _ => return Err(TransitionError::Incompatible),
        },
        // Remove / Revoke from any non-terminal, plus idempotent terminal loops,
        // reuse the rollback terminal ops.
        (
            S::Available | S::DryRunPassed | S::Installed | S::Enabled | S::Disabled | S::Removed,
            T::Remove,
        ) => apply_rollback(current, RollbackOp::Remove),
        (
            S::Available | S::DryRunPassed | S::Installed | S::Enabled | S::Disabled | S::Revoked,
            T::Revoke,
        ) => apply_rollback(current, RollbackOp::Quarantine),
        _ => return Err(TransitionError::InvalidTransition),
    };
    Ok(TransitionAudit {
        from: current,
        transition,
        to,
    })
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod transition_tests {
    use super::*;

    #[test]
    fn valid_forward_path() {
        let s = LocalSkillState::Available;
        let a = apply_transition(s, LocalSkillTransition::DryRun, None).expect("dry-run");
        assert_eq!(a.to, LocalSkillState::DryRunPassed);
        let a = apply_transition(a.to, LocalSkillTransition::Install, None).expect("install");
        assert_eq!(a.to, LocalSkillState::Installed);
        let a = apply_transition(a.to, LocalSkillTransition::Enable, None).expect("enable");
        assert_eq!(a.to, LocalSkillState::Enabled);
        assert!(a.to.is_executable());
        let a = apply_transition(a.to, LocalSkillTransition::Disable, None).expect("disable");
        assert_eq!(a.to, LocalSkillState::Disabled);
        assert!(!a.to.is_executable());
    }

    #[test]
    fn invalid_transitions_rejected() {
        // No direct search/available -> enabled or -> installed bypass.
        assert_eq!(
            apply_transition(
                LocalSkillState::Available,
                LocalSkillTransition::Enable,
                None
            ),
            Err(TransitionError::InvalidTransition)
        );
        assert_eq!(
            apply_transition(
                LocalSkillState::Available,
                LocalSkillTransition::Install,
                None
            ),
            Err(TransitionError::InvalidTransition)
        );
        // A revoked skill can never be re-enabled.
        assert_eq!(
            apply_transition(LocalSkillState::Revoked, LocalSkillTransition::Enable, None),
            Err(TransitionError::InvalidTransition)
        );
    }

    #[test]
    fn idempotent_install() {
        let once = apply_transition(
            LocalSkillState::DryRunPassed,
            LocalSkillTransition::Install,
            None,
        )
        .expect("install once");
        let twice = apply_transition(once.to, LocalSkillTransition::Install, None)
            .expect("install twice is idempotent");
        assert_eq!(once.to, twice.to);
        assert_eq!(twice.to, LocalSkillState::Installed);
    }

    #[test]
    fn update_with_compat_check() {
        // Compatible / Warn admit the update.
        assert_eq!(
            apply_transition(
                LocalSkillState::Installed,
                LocalSkillTransition::Update,
                Some(CompatibilityDecision::Compatible),
            )
            .expect("compatible update")
            .to,
            LocalSkillState::Installed
        );
        // Incompatible blocks the update.
        assert_eq!(
            apply_transition(
                LocalSkillState::Installed,
                LocalSkillTransition::Update,
                Some(CompatibilityDecision::Incompatible),
            ),
            Err(TransitionError::Incompatible)
        );
        // Missing compat evidence blocks the update.
        assert_eq!(
            apply_transition(
                LocalSkillState::Installed,
                LocalSkillTransition::Update,
                None
            ),
            Err(TransitionError::Incompatible)
        );
    }

    #[test]
    fn remove_rollback_to_non_executable() {
        let a = apply_transition(LocalSkillState::Enabled, LocalSkillTransition::Remove, None)
            .expect("remove");
        assert_eq!(a.to, LocalSkillState::Removed);
        assert!(!a.to.is_executable());
        // Idempotent: removing again stays Removed.
        let b = apply_transition(a.to, LocalSkillTransition::Remove, None).expect("remove again");
        assert_eq!(b.to, LocalSkillState::Removed);
    }

    #[test]
    fn revoke_is_terminal() {
        let a = apply_transition(LocalSkillState::Enabled, LocalSkillTransition::Revoke, None)
            .expect("revoke");
        assert_eq!(a.to, LocalSkillState::Revoked);
        // Idempotent revoke; no path back out.
        assert_eq!(
            apply_transition(a.to, LocalSkillTransition::Revoke, None)
                .expect("revoke again")
                .to,
            LocalSkillState::Revoked
        );
        assert_eq!(
            apply_transition(a.to, LocalSkillTransition::Install, None),
            Err(TransitionError::InvalidTransition)
        );
    }

    #[test]
    fn audit_trace_records_from_transition_to() {
        let a = apply_transition(
            LocalSkillState::Installed,
            LocalSkillTransition::Enable,
            None,
        )
        .expect("enable");
        assert_eq!(a.from, LocalSkillState::Installed);
        assert_eq!(a.transition, LocalSkillTransition::Enable);
        assert_eq!(a.to, LocalSkillState::Enabled);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn discriminants_match_move_constants() {
        assert_eq!(InstallState::None.as_u8(), 1);
        assert_eq!(InstallState::DryRun.as_u8(), 2);
        assert_eq!(InstallState::Installed.as_u8(), 3);
        assert_eq!(InstallState::Enabled.as_u8(), 4);
        assert_eq!(InstallState::Disabled.as_u8(), 5);
        assert_eq!(InstallState::Removed.as_u8(), 6);
        assert_eq!(InstallState::Revoked.as_u8(), 7);
    }

    #[test]
    fn from_u8_roundtrips_all_states_and_rejects_unknown() {
        let mut b = 1u8;
        while b <= 7 {
            let parsed = InstallState::from_u8(b);
            assert!(parsed.is_some());
            if let Some(s) = parsed {
                assert_eq!(s.as_u8(), b);
            }
            b += 1;
        }
        assert!(InstallState::from_u8(0).is_none());
        assert!(InstallState::from_u8(8).is_none());
    }

    #[test]
    fn runtime_usable_matrix() {
        assert!(InstallState::Installed.is_runtime_usable());
        assert!(InstallState::Enabled.is_runtime_usable());
        assert!(!InstallState::None.is_runtime_usable());
        assert!(!InstallState::DryRun.is_runtime_usable());
        assert!(!InstallState::Disabled.is_runtime_usable());
        assert!(!InstallState::Removed.is_runtime_usable());
        assert!(!InstallState::Revoked.is_runtime_usable());
    }

    #[test]
    fn stale_local_receipt_denied_until_refreshed() {
        assert!(!runtime_decision(InstallState::Installed, false));
        assert!(!runtime_decision(InstallState::Enabled, false));
        assert!(runtime_decision(InstallState::Installed, true));
        assert!(runtime_decision(InstallState::Enabled, true));
        assert!(!runtime_decision(InstallState::Disabled, true));
        assert!(!runtime_decision(InstallState::Revoked, true));
    }

    #[test]
    fn terminal_states() {
        assert!(InstallState::Removed.is_terminal());
        assert!(InstallState::Revoked.is_terminal());
        assert!(!InstallState::Installed.is_terminal());
        assert!(!InstallState::Enabled.is_terminal());
    }
}
