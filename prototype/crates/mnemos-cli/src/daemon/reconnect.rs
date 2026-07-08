//! Operational reconnect/resume receipt.
//!
//! After a restart, the CLI and the Telegram bridge must see the *same*
//! task/session/context/budget state. Both reconnect against one shared state and
//! present the hash they last saw; a matching hash is `Fresh`, a non-matching hash
//! is `Stale` and is refused — a stale UI is never silently accepted (Red). The
//! CLI and Telegram reconnect against the SAME current state, so they cannot
//! diverge by origin.
//!
//! Reuse (no reinvention): the channel identity is the
//! [`crate::commands::platform_telegram::PlatformOrigin`]; the state hash uses the
//! crate [`crate::sha256_32`]. This module performs no live action.

use crate::commands::platform_telegram::PlatformOrigin;
use crate::sha256_32;

/// The shared session/context/budget/task state both the CLI and Telegram
/// observe. Reconnect compares an observer's last-seen hash against the current
/// hash derived from this state.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SharedRuntimeState {
    /// Number of tasks in the shared inbox.
    pub task_count_u32: u32,
    /// The active session id.
    pub session_id_u64: u64,
    /// The context map version.
    pub context_version_u32: u32,
    /// The remaining budget (micro-units) the rail syncs to.
    pub budget_remaining_micros_u64: u64,
}

impl SharedRuntimeState {
    /// The 32-byte content hash over the canonical, order-fixed encoding. Two
    /// observers of the same state derive the same hash.
    #[must_use]
    pub fn state_hash(&self) -> [u8; 32] {
        let mut buf = Vec::with_capacity(24);
        buf.extend_from_slice(&self.task_count_u32.to_le_bytes());
        buf.extend_from_slice(&self.session_id_u64.to_le_bytes());
        buf.extend_from_slice(&self.context_version_u32.to_le_bytes());
        buf.extend_from_slice(&self.budget_remaining_micros_u64.to_le_bytes());
        sha256_32(&buf)
    }
}

/// The verdict of a reconnect.
#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReconnectVerdict {
    /// The observer's view matches the current shared state (fresh).
    Fresh = 1,
    /// The observer's view is stale; the UI must refresh before acting (Red).
    Stale = 2,
}

impl ReconnectVerdict {
    /// The stable `u8` discriminant.
    #[must_use]
    pub const fn as_u8(self) -> u8 {
        self as u8
    }

    /// Whether the reconnect may proceed (only a fresh view).
    #[must_use]
    pub const fn is_fresh(self) -> bool {
        matches!(self, Self::Fresh)
    }
}

/// A reconnect receipt: which channel reconnected, the verdict, and the current
/// shared-state hash it was checked against.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ReconnectReceipt {
    /// The channel that reconnected.
    pub origin: PlatformOrigin,
    /// The reconnect verdict.
    pub verdict: ReconnectVerdict,
    /// The current shared-state hash (the truth the observer must match).
    pub current_hash_32: [u8; 32],
}

/// Reconnect a channel after a restart. The observer presents the hash it last
/// saw; if it equals the current shared-state hash the reconnect is `Fresh`,
/// otherwise `Stale` (the UI must refresh). The CLI and Telegram reconnect against
/// the SAME current state, so they cannot diverge.
#[must_use]
pub fn reconnect(
    origin: PlatformOrigin,
    current: &SharedRuntimeState,
    observed_hash_32: [u8; 32],
) -> ReconnectReceipt {
    let current_hash_32 = current.state_hash();
    let verdict = if observed_hash_32 == current_hash_32 {
        ReconnectVerdict::Fresh
    } else {
        ReconnectVerdict::Stale
    };
    ReconnectReceipt {
        origin,
        verdict,
        current_hash_32,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn state() -> SharedRuntimeState {
        SharedRuntimeState {
            task_count_u32: 3,
            session_id_u64: 7,
            context_version_u32: 2,
            budget_remaining_micros_u64: 5_000,
        }
    }

    #[test]
    fn state_hash_is_stable_across_restart() {
        let s = state();
        assert_eq!(s.state_hash(), s.state_hash());
        assert_eq!(s.state_hash().len(), 32);
    }

    #[test]
    fn reconnect_cli_fresh_when_hash_matches() {
        let s = state();
        let r = reconnect(PlatformOrigin::Cli, &s, s.state_hash());
        assert!(r.verdict.is_fresh());
        assert_eq!(r.origin, PlatformOrigin::Cli);
    }

    #[test]
    fn reconnect_telegram_fresh_and_same_hash_as_cli() {
        let s = state();
        let cli = reconnect(PlatformOrigin::Cli, &s, s.state_hash());
        let tg = reconnect(PlatformOrigin::Telegram, &s, s.state_hash());
        assert!(tg.verdict.is_fresh());
        // CLI and Telegram observe the SAME shared state -> identical hash.
        assert_eq!(cli.current_hash_32, tg.current_hash_32);
        assert_ne!(cli.origin, tg.origin);
    }

    #[test]
    fn stale_view_is_refused() {
        let s = state();
        let r = reconnect(PlatformOrigin::Tui, &s, [0xAB; 32]);
        assert_eq!(r.verdict, ReconnectVerdict::Stale);
        assert!(!r.verdict.is_fresh());
    }

    #[test]
    fn state_hash_equality_across_observers() {
        let a = state();
        let b = state();
        assert_eq!(a.state_hash(), b.state_hash());
        // A changed field changes the hash (no stale acceptance).
        let mut c = state();
        c.budget_remaining_micros_u64 = 4_999;
        assert_ne!(a.state_hash(), c.state_hash());
    }
}
