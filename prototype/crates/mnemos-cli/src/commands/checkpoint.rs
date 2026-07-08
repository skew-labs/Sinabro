//! Checkpoint / restore command.
//!
//! `sinabro checkpoint list/diff/restore/tag/clean`. Every file-changing command
//! must create an automatic checkpoint *before* it mutates
//! ([`CheckpointStore::requires_checkpoint`] over the canonical
//! [`crate::command::CommandRisk`]), so no irreversible edit / install / config
//! write happens without a recorded restore point. A restore
//! is *scoped* and *user-change protected*: if the user edited the target since
//! the checkpoint, the restore is refused unless explicitly forced, so a restore
//! can never silently clobber unrelated user work. Restore is idempotent
//! (restoring to an already-restored state is a no-op).
//!
//! Reuse: the file-changing risk classes are the canonical
//! [`crate::command::CommandRisk`] safety policy; the trace link is
//! [`crate::StageFTraceLink`]. Diffs are byte-accurate via content hashes — this
//! module stores only 32-byte digests, never file contents, and performs no live
//! action.

use crate::StageFTraceLink;
use crate::command::CommandRisk;

/// What a checkpoint covers. A restore is scoped to one of these — it never
/// reverts files outside the recorded scope.
#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CheckpointScope {
    /// Working-tree files.
    Files = 1,
    /// A single task's outputs.
    Task = 2,
    /// Everything the session may revert.
    All = 3,
    /// Configuration.
    Config = 4,
    /// An installed skill.
    Skill = 5,
}

impl CheckpointScope {
    /// The stable `u8` discriminant.
    #[must_use]
    pub const fn as_u8(self) -> u8 {
        self as u8
    }
}

/// One recorded checkpoint: the pre-mutation content hash (the restore target),
/// the hash the command applied (so a later user edit is detectable), an optional
/// tag, and the trace it is bound to. Holds only digests, never file content.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Checkpoint {
    /// Stable checkpoint id.
    pub id_u64: u64,
    /// What this checkpoint covers.
    pub scope: CheckpointScope,
    /// SHA-256 of the content *before* the mutation (the restore target).
    pub pre_hash_32: [u8; 32],
    /// SHA-256 of the content the command *applied* (the expected current state).
    pub applied_hash_32: [u8; 32],
    /// An optional user tag (a 32-byte name hash).
    pub tag_32: Option<[u8; 32]>,
    /// The trace this checkpoint is bound to.
    pub trace: StageFTraceLink,
}

/// Why a checkpoint operation was refused (fail-closed).
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum CheckpointError {
    /// No checkpoint with the requested id exists.
    #[error("checkpoint not found")]
    NotFound,
    /// The target was modified by the user since the checkpoint; restoring would
    /// clobber that work, so it is refused unless forced.
    #[error("target modified since checkpoint; restore refused")]
    UserModifiedSinceCheckpoint,
}

/// The outcome of a successful restore.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RestoreOutcome {
    /// The checkpoint restored from.
    pub id_u64: u64,
    /// The scope restored.
    pub scope: CheckpointScope,
    /// The hash the target was restored to (the checkpoint's `pre_hash_32`).
    pub restored_to_hash_32: [u8; 32],
    /// Whether the target was already at the restore target (idempotent no-op).
    pub idempotent_noop: bool,
}

/// The checkpoint store: an ordered list of checkpoints with monotonic ids.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct CheckpointStore {
    items: Vec<Checkpoint>,
    next_id: u64,
}

impl CheckpointStore {
    /// An empty store.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Whether a command of `risk` must auto-checkpoint before it runs. File-
    /// changing classes (local write / wallet sign / chain write / admin) do;
    /// read-only and network-only classes do not.
    #[must_use]
    pub const fn requires_checkpoint(risk: CommandRisk) -> bool {
        matches!(
            risk,
            CommandRisk::LocalWrite
                | CommandRisk::WalletSign
                | CommandRisk::ChainWrite
                | CommandRisk::Admin
        )
    }

    /// Record an automatic checkpoint *before* a mutation. Returns the new id.
    pub fn auto_checkpoint(
        &mut self,
        scope: CheckpointScope,
        pre_hash_32: [u8; 32],
        applied_hash_32: [u8; 32],
        trace: StageFTraceLink,
    ) -> u64 {
        let id_u64 = self.next_id;
        self.next_id = self.next_id.saturating_add(1);
        self.items.push(Checkpoint {
            id_u64,
            scope,
            pre_hash_32,
            applied_hash_32,
            tag_32: None,
            trace,
        });
        id_u64
    }

    /// All checkpoints, in record order.
    #[must_use]
    pub fn list(&self) -> &[Checkpoint] {
        &self.items
    }

    /// Checkpoints in a given scope.
    #[must_use]
    pub fn list_scope(&self, scope: CheckpointScope) -> Vec<&Checkpoint> {
        self.items.iter().filter(|c| c.scope == scope).collect()
    }

    /// The checkpoint with `id`, if present.
    #[must_use]
    pub fn get(&self, id_u64: u64) -> Option<&Checkpoint> {
        self.items.iter().find(|c| c.id_u64 == id_u64)
    }

    /// Whether the current content differs from the checkpoint's restore target
    /// (byte-accurate via the content hash).
    pub fn diff(&self, id_u64: u64, current_hash_32: [u8; 32]) -> Result<bool, CheckpointError> {
        let cp = self.get(id_u64).ok_or(CheckpointError::NotFound)?;
        Ok(cp.pre_hash_32 != current_hash_32)
    }

    /// Restore the target of checkpoint `id` to its pre-mutation content. Scoped
    /// and user-change protected:
    /// - if the target is already at the restore target → idempotent no-op;
    /// - else if the target is exactly what the command applied → restore;
    /// - else (the user edited it) → refused unless `force`.
    pub fn restore(
        &self,
        id_u64: u64,
        observed_current_hash_32: [u8; 32],
        force: bool,
    ) -> Result<RestoreOutcome, CheckpointError> {
        let cp = self.get(id_u64).ok_or(CheckpointError::NotFound)?;
        if observed_current_hash_32 == cp.pre_hash_32 {
            return Ok(RestoreOutcome {
                id_u64,
                scope: cp.scope,
                restored_to_hash_32: cp.pre_hash_32,
                idempotent_noop: true,
            });
        }
        if observed_current_hash_32 != cp.applied_hash_32 && !force {
            return Err(CheckpointError::UserModifiedSinceCheckpoint);
        }
        Ok(RestoreOutcome {
            id_u64,
            scope: cp.scope,
            restored_to_hash_32: cp.pre_hash_32,
            idempotent_noop: false,
        })
    }

    /// Tag a checkpoint with a 32-byte name hash.
    pub fn tag(&mut self, id_u64: u64, tag_32: [u8; 32]) -> Result<(), CheckpointError> {
        let cp = self
            .items
            .iter_mut()
            .find(|c| c.id_u64 == id_u64)
            .ok_or(CheckpointError::NotFound)?;
        cp.tag_32 = Some(tag_32);
        Ok(())
    }

    /// Prune all but the most recent `keep` checkpoints. Returns the number
    /// removed.
    pub fn clean(&mut self, keep: usize) -> usize {
        if self.items.len() <= keep {
            return 0;
        }
        let remove = self.items.len() - keep;
        self.items.drain(0..remove);
        remove
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn trace() -> StageFTraceLink {
        StageFTraceLink::new([0x70; 32], 470, 470)
    }

    fn h(seed: u8) -> [u8; 32] {
        [seed; 32]
    }

    #[test]
    fn file_changing_commands_require_checkpoint() {
        assert!(CheckpointStore::requires_checkpoint(
            CommandRisk::LocalWrite
        ));
        assert!(CheckpointStore::requires_checkpoint(
            CommandRisk::ChainWrite
        ));
        assert!(CheckpointStore::requires_checkpoint(
            CommandRisk::WalletSign
        ));
        assert!(CheckpointStore::requires_checkpoint(CommandRisk::Admin));
        assert!(!CheckpointStore::requires_checkpoint(CommandRisk::ReadOnly));
        assert!(!CheckpointStore::requires_checkpoint(CommandRisk::Network));
    }

    #[test]
    fn auto_checkpoint_records_before_mutation() {
        let mut s = CheckpointStore::new();
        let id = s.auto_checkpoint(CheckpointScope::Files, h(1), h(2), trace());
        assert_eq!(id, 0);
        assert_eq!(s.list().len(), 1);
        let id2 = s.auto_checkpoint(CheckpointScope::Config, h(3), h(4), trace());
        assert_eq!(id2, 1);
        assert_eq!(s.list().len(), 2);
    }

    #[test]
    fn list_scope_filters() {
        let mut s = CheckpointStore::new();
        s.auto_checkpoint(CheckpointScope::Files, h(1), h(2), trace());
        s.auto_checkpoint(CheckpointScope::Config, h(3), h(4), trace());
        s.auto_checkpoint(CheckpointScope::Files, h(5), h(6), trace());
        assert_eq!(s.list_scope(CheckpointScope::Files).len(), 2);
        assert_eq!(s.list_scope(CheckpointScope::Config).len(), 1);
    }

    #[test]
    fn diff_is_byte_accurate() {
        let mut s = CheckpointStore::new();
        let id = s.auto_checkpoint(CheckpointScope::Files, h(1), h(2), trace());
        assert_eq!(s.diff(id, h(1)), Ok(false)); // == pre_hash -> no diff
        assert_eq!(s.diff(id, h(9)), Ok(true)); // differs
        assert_eq!(s.diff(404, h(1)), Err(CheckpointError::NotFound));
    }

    #[test]
    fn restore_from_applied_state() {
        let mut s = CheckpointStore::new();
        let id = s.auto_checkpoint(CheckpointScope::Files, h(1), h(2), trace());
        // observed == applied_hash -> restore to pre_hash
        assert_eq!(
            s.restore(id, h(2), false),
            Ok(RestoreOutcome {
                id_u64: id,
                scope: CheckpointScope::Files,
                restored_to_hash_32: h(1),
                idempotent_noop: false,
            })
        );
    }

    #[test]
    fn restore_is_idempotent_when_already_at_target() {
        let mut s = CheckpointStore::new();
        let id = s.auto_checkpoint(CheckpointScope::Files, h(1), h(2), trace());
        // A restore that observes the already-restored pre_hash h(1) is a no-op.
        let second = s.restore(id, h(1), false);
        assert!(matches!(
            second,
            Ok(RestoreOutcome {
                idempotent_noop: true,
                ..
            })
        ));
    }

    #[test]
    fn user_change_is_protected_unless_forced() {
        let mut s = CheckpointStore::new();
        let id = s.auto_checkpoint(CheckpointScope::Files, h(1), h(2), trace());
        // observed is neither pre nor applied -> the user edited it.
        assert_eq!(
            s.restore(id, h(7), false),
            Err(CheckpointError::UserModifiedSinceCheckpoint)
        );
        // force overrides the protection.
        assert!(matches!(
            s.restore(id, h(7), true),
            Ok(RestoreOutcome {
                idempotent_noop: false,
                ..
            })
        ));
    }

    #[test]
    fn tag_and_not_found() {
        let mut s = CheckpointStore::new();
        let id = s.auto_checkpoint(CheckpointScope::Skill, h(1), h(2), trace());
        assert_eq!(s.tag(id, h(0xaa)), Ok(()));
        assert_eq!(s.get(id).and_then(|c| c.tag_32), Some(h(0xaa)));
        assert_eq!(s.tag(404, h(0xaa)), Err(CheckpointError::NotFound));
    }

    #[test]
    fn clean_keeps_most_recent() {
        let mut s = CheckpointStore::new();
        for i in 0..5u8 {
            s.auto_checkpoint(CheckpointScope::Files, h(i), h(i + 100), trace());
        }
        let removed = s.clean(2);
        assert_eq!(removed, 3);
        assert_eq!(s.list().len(), 2);
        // The most recent (ids 3 and 4) are kept.
        assert_eq!(s.list()[0].id_u64, 3);
        assert_eq!(s.list()[1].id_u64, 4);
        // clean with keep >= len removes nothing.
        assert_eq!(s.clean(10), 0);
    }
}
