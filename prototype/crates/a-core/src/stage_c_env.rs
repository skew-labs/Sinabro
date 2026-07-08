//! Stage C chain-environment matrix.
//!
//! Provides [`StageCChainEnv`] and [`MainnetExecutionState`].
//!
//! # Design invariants
//!
//! * **`TestnetVerified` and `MainnetPrepared` are distinct states.** They are
//!   two discriminants of the same `#[repr(u8)]` enum; there is no third
//!   "arbitrary endpoint" state. [`StageCChainEnv::from_u8`] rejects any byte
//!   that is not one of the two known discriminants — an arbitrary / unknown
//!   network value can never be parsed into a chain env.
//! * **Mainnet execution cannot be represented without checklist state.** A
//!   prepared mainnet is *not* an executing mainnet. [`MainnetExecutionState`]
//!   defaults to [`Locked`](MainnetExecutionState::Locked); only
//!   [`Executed`](MainnetExecutionState::Executed) means a real mainnet
//!   mutation happened, and reaching it is gated by the checklist / approval
//!   ceremony built in later work packages (multisig + timelock + operator
//!   approval). This module performs **no live egress**.
//! * **Approval-gated, disabled-by-default.** [`MainnetExecutionState::is_executable`]
//!   is `true` only for [`Executed`](MainnetExecutionState::Executed); every
//!   other state (including [`ApprovalPending`](MainnetExecutionState::ApprovalPending)
//!   and [`TimelockQueued`](MainnetExecutionState::TimelockQueued)) reports
//!   *not yet executable*, so a default-constructed gate is always `Locked`.
//!
//! # Reuse map
//!
//! Reuse is conceptual, not by import: this enum mirrors the testnet/mainnet
//! distinction that Stage B expresses with `StageBNetwork`
//! (`b-memory/src/network.rs`), and it lives beside the Stage A
//! [`RuntimeConfig`](crate::config::RuntimeConfig) posture. `a-core` is the
//! dependency root and deliberately does **not** import `b-memory`, so the
//! Stage B network type is not pulled here (that would invert the dependency
//! direction); the distinct-states invariant is re-stated locally instead of
//! re-minting the Stage B wire.

/// Which chain environment a Stage C action is targeting.
///
/// Exactly two states exist. `TestnetVerified` is the Stage B proven testnet
/// posture; `MainnetPrepared` means the mainnet path has been *prepared and
/// gated* but not executed. There is intentionally no variant for an arbitrary
/// or operator-supplied endpoint.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
#[repr(u8)]
pub enum StageCChainEnv {
    /// Stage B testnet, verified by round-trip evidence.
    TestnetVerified = 1,
    /// Mainnet, prepared and gated — never executed by this type alone.
    MainnetPrepared = 2,
}

impl StageCChainEnv {
    /// The raw `#[repr(u8)]` discriminant.
    #[inline]
    pub const fn as_u8(self) -> u8 {
        self as u8
    }

    /// Parse a chain env from its discriminant byte, rejecting any value that
    /// is not one of the two known states (the "arbitrary URL / unknown
    /// network rejected" invariant).
    #[inline]
    pub const fn from_u8(byte: u8) -> Option<Self> {
        match byte {
            1 => Some(Self::TestnetVerified),
            2 => Some(Self::MainnetPrepared),
            _ => None,
        }
    }

    /// Whether this env is the prepared-mainnet posture. Even when `true`, no
    /// mutation is possible without a [`MainnetExecutionState::Executed`]
    /// produced by the later approval ceremony.
    #[inline]
    pub const fn is_mainnet_prepared(self) -> bool {
        matches!(self, Self::MainnetPrepared)
    }
}

/// The execution posture of the (single, gated) mainnet path.
///
/// Default / safe value is [`Locked`](Self::Locked). The ladder
/// `Locked -> DryRunOnly -> ApprovalPending -> TimelockQueued -> Executed`
/// can only advance through the checklist + ceremony surfaces built in later
/// work packages; [`Paused`](Self::Paused) is the incident-pause sink.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
#[repr(u8)]
pub enum MainnetExecutionState {
    /// No mainnet action possible. The default, safe posture.
    Locked = 1,
    /// Only dry-run / dev-inspect is allowed; no state mutation.
    DryRunOnly = 2,
    /// Waiting on explicit operator approval before anything is queued.
    ApprovalPending = 3,
    /// Approved and sitting in the timelock queue, not yet executed.
    TimelockQueued = 4,
    /// A real mainnet mutation has executed.
    Executed = 5,
    /// Incident pause sink — execution halted.
    Paused = 6,
}

impl MainnetExecutionState {
    /// The default, safe posture: [`Locked`](Self::Locked).
    #[inline]
    pub const fn default_locked() -> Self {
        Self::Locked
    }

    /// The raw `#[repr(u8)]` discriminant.
    #[inline]
    pub const fn as_u8(self) -> u8 {
        self as u8
    }

    /// Parse from the discriminant byte, rejecting unknown values.
    #[inline]
    pub const fn from_u8(byte: u8) -> Option<Self> {
        match byte {
            1 => Some(Self::Locked),
            2 => Some(Self::DryRunOnly),
            3 => Some(Self::ApprovalPending),
            4 => Some(Self::TimelockQueued),
            5 => Some(Self::Executed),
            6 => Some(Self::Paused),
            _ => None,
        }
    }

    /// Whether a real mainnet mutation is permitted in this state. Only
    /// [`Executed`](Self::Executed) is executable; every other state — most
    /// importantly the default [`Locked`](Self::Locked) — is not. There is no
    /// single state value that lets a mutation happen "by default".
    #[inline]
    pub const fn is_executable(self) -> bool {
        matches!(self, Self::Executed)
    }
}

impl Default for MainnetExecutionState {
    #[inline]
    fn default() -> Self {
        Self::default_locked()
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]
    use super::*;

    #[test]
    fn testnet_verified_is_accepted_and_distinct_from_mainnet() {
        let testnet = StageCChainEnv::from_u8(1).expect("discriminant 1 is TestnetVerified");
        assert_eq!(testnet, StageCChainEnv::TestnetVerified);
        assert!(!testnet.is_mainnet_prepared());
        assert_ne!(
            StageCChainEnv::TestnetVerified,
            StageCChainEnv::MainnetPrepared
        );
    }

    #[test]
    fn mainnet_prepared_is_locked_by_default_not_executable() {
        let prepared = StageCChainEnv::from_u8(2).expect("discriminant 2 is MainnetPrepared");
        assert!(prepared.is_mainnet_prepared());
        // A prepared mainnet does not imply an executable one.
        assert_eq!(
            MainnetExecutionState::default(),
            MainnetExecutionState::Locked
        );
        assert!(!MainnetExecutionState::default().is_executable());
        assert!(!MainnetExecutionState::ApprovalPending.is_executable());
        assert!(!MainnetExecutionState::TimelockQueued.is_executable());
        assert!(MainnetExecutionState::Executed.is_executable());
    }

    #[test]
    fn arbitrary_unknown_network_byte_is_rejected() {
        for byte in [0u8, 3, 4, 99, 255] {
            assert!(StageCChainEnv::from_u8(byte).is_none());
        }
    }

    #[test]
    fn mainnet_execution_state_rejects_unknown_discriminant() {
        for byte in [0u8, 7, 8, 255] {
            assert!(MainnetExecutionState::from_u8(byte).is_none());
        }
        for byte in 1u8..=6 {
            assert!(MainnetExecutionState::from_u8(byte).is_some());
        }
    }
}
