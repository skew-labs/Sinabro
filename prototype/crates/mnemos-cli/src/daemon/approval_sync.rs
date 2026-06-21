//! Operational approval event sync (atom #514 · G.2.8).
//!
//! Provider fallback, tool side effect, memory export/delete, Telegram remote
//! control, and Stage H handoff approvals are each recorded once, bound by a
//! non-zero event hash and tagged with the source channel (CLI / Telegram). A
//! hash-less event is refused (it cannot be bound to evidence) and a replayed hash
//! is refused (`G-G-EVIDENCE-MANIFEST`, `G-G-CONTROL-EXPRESS`), so an approval can
//! never be silently duplicated or orphaned.
//!
//! Reuse (no reinvention): the source channel is the F
//! [`crate::commands::platform_telegram::PlatformOrigin`]; the dedupe set is a
//! `BTreeSet` of event hashes. This module performs no live action.

use crate::commands::platform_telegram::PlatformOrigin;
use std::collections::BTreeSet;

/// The all-zero hash — an event carrying it has no evidence binding.
const ZERO32: [u8; 32] = [0u8; 32];

/// The action classes whose approval is synced across channels.
#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ApprovalAction {
    /// A provider/model fallback was approved.
    ProviderFallback = 1,
    /// A tool side effect was approved.
    ToolSideEffect = 2,
    /// A memory export or delete was approved.
    MemoryExportDelete = 3,
    /// A Telegram remote-control action was approved.
    TelegramRemoteControl = 4,
    /// A Stage H training handoff was approved (handoff, not a trained model).
    StageHHandoff = 5,
}

impl ApprovalAction {
    /// The stable `u8` discriminant.
    #[must_use]
    pub const fn as_u8(self) -> u8 {
        self as u8
    }
}

/// The decision recorded for an approval event.
#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SyncDecision {
    /// The action was approved.
    Approved = 1,
    /// The action was denied.
    Denied = 2,
}

impl SyncDecision {
    /// The stable `u8` discriminant.
    #[must_use]
    pub const fn as_u8(self) -> u8 {
        self as u8
    }
}

/// A single approval event: the action, the source channel, the decision, and a
/// non-zero event hash binding it to its evidence.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ApprovalEvent {
    /// The action whose approval this records.
    pub action: ApprovalAction,
    /// The channel the approval came from.
    pub source: PlatformOrigin,
    /// The recorded decision.
    pub decision: SyncDecision,
    /// SHA-256 binding the event to its evidence (zero = no binding, refused).
    pub event_hash_32: [u8; 32],
}

/// Why an approval event was refused (fail-closed).
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum ApprovalSyncReject {
    /// The event carries no hash (zero) — it cannot be bound to evidence.
    #[error("approval event missing hash")]
    MissingHash,
    /// The event hash was already recorded — a replay is refused.
    #[error("approval event replay denied")]
    ReplayDenied,
}

/// The approval-sync ledger: records each approval event once, bound by its hash,
/// from any channel (CLI / Telegram). A replayed hash is refused; a hash-less
/// event is refused.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ApprovalSyncLedger {
    seen: BTreeSet<[u8; 32]>,
    recorded_u32: u32,
}

impl ApprovalSyncLedger {
    /// A new, empty ledger.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// The number of distinct approval events recorded.
    #[must_use]
    pub const fn recorded(&self) -> u32 {
        self.recorded_u32
    }

    /// Record an approval event. Fails closed on a missing hash or on a replay of
    /// an already-recorded hash. A denial is a valid recorded decision (it still
    /// needs a binding hash).
    pub fn record(&mut self, event: ApprovalEvent) -> Result<(), ApprovalSyncReject> {
        if event.event_hash_32 == ZERO32 {
            return Err(ApprovalSyncReject::MissingHash);
        }
        if !self.seen.insert(event.event_hash_32) {
            return Err(ApprovalSyncReject::ReplayDenied);
        }
        self.recorded_u32 = self.recorded_u32.saturating_add(1);
        Ok(())
    }

    /// Whether an event hash has already been recorded.
    #[must_use]
    pub fn contains(&self, event_hash_32: &[u8; 32]) -> bool {
        self.seen.contains(event_hash_32)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ev(
        action: ApprovalAction,
        source: PlatformOrigin,
        decision: SyncDecision,
        seed: u8,
    ) -> ApprovalEvent {
        ApprovalEvent {
            action,
            source,
            decision,
            event_hash_32: [seed; 32],
        }
    }

    #[test]
    fn cli_approval_recorded() {
        let mut l = ApprovalSyncLedger::new();
        let e = ev(
            ApprovalAction::ProviderFallback,
            PlatformOrigin::Cli,
            SyncDecision::Approved,
            1,
        );
        assert!(l.record(e).is_ok());
        assert!(l.contains(&[1u8; 32]));
        assert_eq!(l.recorded(), 1);
    }

    #[test]
    fn telegram_approval_recorded() {
        let mut l = ApprovalSyncLedger::new();
        let e = ev(
            ApprovalAction::TelegramRemoteControl,
            PlatformOrigin::Telegram,
            SyncDecision::Approved,
            2,
        );
        assert!(l.record(e).is_ok());
        assert_eq!(l.recorded(), 1);
    }

    #[test]
    fn denied_approval_recorded_with_hash() {
        let mut l = ApprovalSyncLedger::new();
        // A denial is a recorded decision (with its binding hash).
        let e = ev(
            ApprovalAction::MemoryExportDelete,
            PlatformOrigin::Cli,
            SyncDecision::Denied,
            3,
        );
        assert!(l.record(e).is_ok());
        assert_eq!(l.recorded(), 1);
    }

    #[test]
    fn missing_hash_refused() {
        let mut l = ApprovalSyncLedger::new();
        let e = ev(
            ApprovalAction::ToolSideEffect,
            PlatformOrigin::Cli,
            SyncDecision::Approved,
            0,
        );
        assert_eq!(l.record(e), Err(ApprovalSyncReject::MissingHash));
        assert_eq!(l.recorded(), 0);
    }

    #[test]
    fn replay_denied() {
        let mut l = ApprovalSyncLedger::new();
        let e = ev(
            ApprovalAction::StageHHandoff,
            PlatformOrigin::Telegram,
            SyncDecision::Approved,
            5,
        );
        assert!(l.record(e).is_ok());
        // The same event hash replayed is refused, and does not increment the count.
        assert_eq!(l.record(e), Err(ApprovalSyncReject::ReplayDenied));
        assert_eq!(l.recorded(), 1);
    }
}
