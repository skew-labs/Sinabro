//! rollback / undo command (atom #470 · F.8.3, part 2 of 2).
//!
//! `sinabro rollback` + `undo files/task/all`, built on the sibling
//! [`crate::commands::checkpoint`] store. `undo` reverts the most recent
//! checkpoint in a scope; `skill rollback` reuses the canonical Stage-E/D
//! [`apply_rollback`] state machine; `config rollback` reverts the most recent
//! configuration checkpoint. Every revert is user-change protected (it cannot
//! silently clobber edits the user made after the checkpoint) and idempotent
//! (re-undoing an already-reverted target is a no-op), so the undo path is never
//! irreversible or confusing (`G-F-CHECKPOINT` / `G-F-CONCURRENCY`).
//!
//! Reuse (no reinvention): the remove/rollback primitive is the canonical
//! [`mnemos_e_skill`] [`RollbackOp`] / [`apply_rollback`] / [`LocalSkillState`];
//! the checkpoint store + restore (with its user-change protection and trace
//! binding) is the sibling [`crate::commands::checkpoint`]. This module performs
//! no live action.

use crate::commands::checkpoint::{
    CheckpointError, CheckpointScope, CheckpointStore, RestoreOutcome,
};
use mnemos_e_skill::{LocalSkillState, RollbackOp, apply_rollback};

/// The scope of an `undo` command.
#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum UndoScope {
    /// Undo the most recent file change.
    Files = 1,
    /// Undo the most recent task's outputs.
    Task = 2,
    /// Undo the most recent change of any scope.
    All = 3,
}

impl UndoScope {
    /// The stable `u8` discriminant.
    #[must_use]
    pub const fn as_u8(self) -> u8 {
        self as u8
    }
}

/// Why a rollback / undo was refused (fail-closed).
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum RollbackReject {
    /// There is no checkpoint to undo in the requested scope.
    #[error("nothing to undo")]
    NothingToUndo,
    /// The target was changed by the user since the checkpoint; the revert is
    /// refused so it cannot clobber that work.
    #[error("target changed by user; rollback refused")]
    UserChangeProtected,
}

impl RollbackReject {
    /// Map a checkpoint error into the rollback taxonomy.
    const fn from_checkpoint(e: CheckpointError) -> Self {
        match e {
            CheckpointError::UserModifiedSinceCheckpoint => Self::UserChangeProtected,
            _ => Self::NothingToUndo,
        }
    }
}

/// The outcome of an `undo`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct UndoOutcome {
    /// The scope that was undone.
    pub scope: UndoScope,
    /// The checkpoint id that was reverted.
    pub reverted_id_u64: u64,
    /// Whether the target was already at the restore point (idempotent no-op).
    pub idempotent_noop: bool,
}

/// The rollback / undo controller, wrapping a [`CheckpointStore`].
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct RollbackController {
    store: CheckpointStore,
}

impl RollbackController {
    /// A new controller with an empty checkpoint store.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// The checkpoint store (read-only).
    #[must_use]
    pub fn store(&self) -> &CheckpointStore {
        &self.store
    }

    /// Mutable access to the store (to record auto-checkpoints).
    pub fn store_mut(&mut self) -> &mut CheckpointStore {
        &mut self.store
    }

    /// Undo the most recent checkpoint in `scope` (`All` = most recent overall),
    /// user-change protected and idempotent.
    pub fn undo(
        &self,
        scope: UndoScope,
        observed_current_hash_32: [u8; 32],
        force: bool,
    ) -> Result<UndoOutcome, RollbackReject> {
        let target = match scope {
            UndoScope::Files => self
                .store
                .list()
                .iter()
                .rev()
                .find(|c| c.scope == CheckpointScope::Files),
            UndoScope::Task => self
                .store
                .list()
                .iter()
                .rev()
                .find(|c| c.scope == CheckpointScope::Task),
            UndoScope::All => self.store.list().last(),
        };
        let Some(cp) = target else {
            return Err(RollbackReject::NothingToUndo);
        };
        let out = self
            .store
            .restore(cp.id_u64, observed_current_hash_32, force)
            .map_err(RollbackReject::from_checkpoint)?;
        Ok(UndoOutcome {
            scope,
            reverted_id_u64: out.id_u64,
            idempotent_noop: out.idempotent_noop,
        })
    }

    /// Roll a skill back through the canonical [`apply_rollback`] state machine
    /// (idempotent by construction — the result depends only on the op).
    #[must_use]
    pub const fn skill_rollback(state: LocalSkillState, op: RollbackOp) -> LocalSkillState {
        apply_rollback(state, op)
    }

    /// Roll the configuration back to its most recent checkpoint (user-change
    /// protected).
    pub fn config_rollback(
        &self,
        observed_current_hash_32: [u8; 32],
        force: bool,
    ) -> Result<RestoreOutcome, RollbackReject> {
        let cp = self
            .store
            .list()
            .iter()
            .rev()
            .find(|c| c.scope == CheckpointScope::Config)
            .ok_or(RollbackReject::NothingToUndo)?;
        self.store
            .restore(cp.id_u64, observed_current_hash_32, force)
            .map_err(RollbackReject::from_checkpoint)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::StageFTraceLink;

    fn trace() -> StageFTraceLink {
        StageFTraceLink::new([0x70; 32], 470, 470)
    }

    fn h(seed: u8) -> [u8; 32] {
        [seed; 32]
    }

    fn controller_with(scopes: &[(CheckpointScope, u8, u8)]) -> RollbackController {
        let mut c = RollbackController::new();
        for &(scope, pre, applied) in scopes {
            c.store_mut()
                .auto_checkpoint(scope, h(pre), h(applied), trace());
        }
        c
    }

    #[test]
    fn undo_files_task_all() {
        let c = controller_with(&[
            (CheckpointScope::Files, 1, 2),
            (CheckpointScope::Task, 3, 4),
        ]);
        // undo files -> reverts the Files checkpoint (observed == applied h(2)).
        assert!(matches!(
            c.undo(UndoScope::Files, h(2), false),
            Ok(UndoOutcome {
                scope: UndoScope::Files,
                reverted_id_u64: 0,
                ..
            })
        ));
        // undo task.
        assert!(matches!(
            c.undo(UndoScope::Task, h(4), false),
            Ok(UndoOutcome {
                scope: UndoScope::Task,
                reverted_id_u64: 1,
                ..
            })
        ));
        // undo all -> most recent overall (the Task checkpoint, id 1).
        assert!(matches!(
            c.undo(UndoScope::All, h(4), false),
            Ok(UndoOutcome {
                reverted_id_u64: 1,
                ..
            })
        ));
    }

    #[test]
    fn failed_rollback_when_nothing_to_undo() {
        let c = RollbackController::new();
        assert_eq!(
            c.undo(UndoScope::Files, h(1), false),
            Err(RollbackReject::NothingToUndo)
        );
        assert_eq!(
            c.undo(UndoScope::All, h(1), false),
            Err(RollbackReject::NothingToUndo)
        );
    }

    #[test]
    fn rollback_is_idempotent() {
        let c = controller_with(&[(CheckpointScope::Files, 1, 2)]);
        // first undo (observed applied h(2)) -> reverts to pre h(1).
        assert!(matches!(
            c.undo(UndoScope::Files, h(2), false),
            Ok(UndoOutcome {
                idempotent_noop: false,
                ..
            })
        ));
        // second undo observes the restored state h(1) -> idempotent no-op.
        assert!(matches!(
            c.undo(UndoScope::Files, h(1), false),
            Ok(UndoOutcome {
                idempotent_noop: true,
                ..
            })
        ));
    }

    #[test]
    fn user_change_protected() {
        let c = controller_with(&[(CheckpointScope::Files, 1, 2)]);
        // observed is neither pre nor applied -> protected.
        assert_eq!(
            c.undo(UndoScope::Files, h(9), false),
            Err(RollbackReject::UserChangeProtected)
        );
        // force overrides.
        assert!(c.undo(UndoScope::Files, h(9), true).is_ok());
    }

    #[test]
    fn skill_rollback_reuses_canonical_apply_rollback() {
        // Remove tombstones an installed skill; idempotent (op-determined).
        let removed =
            RollbackController::skill_rollback(LocalSkillState::Installed, RollbackOp::Remove);
        assert_eq!(removed, LocalSkillState::Removed);
        let removed_again = RollbackController::skill_rollback(removed, RollbackOp::Remove);
        assert_eq!(removed_again, LocalSkillState::Removed);
        // Quarantine -> Revoked.
        let revoked =
            RollbackController::skill_rollback(LocalSkillState::Enabled, RollbackOp::Quarantine);
        assert_eq!(revoked, LocalSkillState::Revoked);
    }

    #[test]
    fn config_rollback_reverts_config_checkpoint() {
        let c = controller_with(&[
            (CheckpointScope::Files, 1, 2),
            (CheckpointScope::Config, 5, 6),
        ]);
        assert!(c.config_rollback(h(6), false).is_ok());
        // No config checkpoint -> nothing to undo.
        let empty = controller_with(&[(CheckpointScope::Files, 1, 2)]);
        assert_eq!(
            empty.config_rollback(h(2), false),
            Err(RollbackReject::NothingToUndo)
        );
    }

    #[test]
    fn interleaved_ops_preserve_invariants() {
        // Many repeated undos of an already-reverted target are always idempotent
        // no-ops (no duplicate side effect); the store never panics or double-
        // reverts (G-F-CONCURRENCY).
        let c = controller_with(&[
            (CheckpointScope::Files, 1, 2),
            (CheckpointScope::Task, 3, 4),
            (CheckpointScope::Config, 5, 6),
        ]);
        for _ in 0..100 {
            assert!(matches!(
                c.undo(UndoScope::Files, h(1), false),
                Ok(UndoOutcome {
                    idempotent_noop: true,
                    ..
                })
            ));
        }
    }
}
