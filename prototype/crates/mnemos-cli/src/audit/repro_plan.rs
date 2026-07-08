//! Local repro plan.
//!
//! Before a candidate may be reproduced, it must state a *local* plan: the repo,
//! the fixture, the command, and the expected failure — and it must deny
//! production RPC, a live tx, and any third-party-funds touch. [`LocalReproPlan`]
//! is report-first / exploit-last: a passive description of how to reproduce
//! locally, never an executor. A plan that requests production RPC, a live tx, or
//! third-party funds, or that omits the command or the expected failure, is
//! refused. This module performs no live action.
//!
//! Reuse (no reinvention): mirrors the local-repro signal; a reproduced
//! plan is recorded as a [`crate::audit::repro_receipt::LocalReproRunnerReceipt`].

/// Why a [`LocalReproPlan`] was refused (fail-closed).
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum ReproPlanReject {
    /// The plan omitted the reproduction command.
    #[error("missing command")]
    MissingCommand,
    /// The plan omitted the expected failure.
    #[error("missing expected failure")]
    MissingExpectedFailure,
    /// The plan requested production RPC (forbidden).
    #[error("production rpc requested")]
    ProductionRpcRequested,
    /// The plan requested a live transaction (forbidden).
    #[error("live tx requested")]
    LiveTxRequested,
    /// The plan would touch third-party funds (forbidden).
    #[error("third-party funds requested")]
    ThirdPartyFundsRequested,
}

/// The requested safety flags for a repro plan (all must be safe/local).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub struct ReproPlanFlags {
    /// Whether the plan requests production RPC (must be `false`).
    pub uses_production_rpc: bool,
    /// Whether the plan requests a live transaction (must be `false`).
    pub uses_live_tx: bool,
    /// Whether the plan would touch third-party funds (must be `false`).
    pub touches_third_party_funds: bool,
}

/// The inputs to build a [`LocalReproPlan`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ReproPlanInputs {
    /// SHA-256 of the target repo.
    pub repo_hash_32: [u8; 32],
    /// SHA-256 of the local fixture.
    pub fixture_hash_32: [u8; 32],
    /// SHA-256 of the reproduction command.
    pub command_hash_32: [u8; 32],
    /// SHA-256 of the expected failure (the invariant break to observe).
    pub expected_failure_hash_32: [u8; 32],
}

/// A local-only, report-first reproduction plan for an audit candidate.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LocalReproPlan {
    /// SHA-256 of the target repo.
    pub repo_hash_32: [u8; 32],
    /// SHA-256 of the local fixture.
    pub fixture_hash_32: [u8; 32],
    /// SHA-256 of the reproduction command.
    pub command_hash_32: [u8; 32],
    /// SHA-256 of the expected failure (the invariant break to observe).
    pub expected_failure_hash_32: [u8; 32],
    /// Invariant `true`: the plan is local-only.
    pub local_only: bool,
}

impl LocalReproPlan {
    /// Build a local-only repro plan. Refuses production RPC / live tx /
    /// third-party funds, and a missing command or expected failure. The repo and
    /// fixture hashes may be zero (an in-memory fixture); the command and the
    /// expected failure are mandatory.
    pub fn new(inputs: &ReproPlanInputs, flags: ReproPlanFlags) -> Result<Self, ReproPlanReject> {
        if flags.uses_production_rpc {
            return Err(ReproPlanReject::ProductionRpcRequested);
        }
        if flags.uses_live_tx {
            return Err(ReproPlanReject::LiveTxRequested);
        }
        if flags.touches_third_party_funds {
            return Err(ReproPlanReject::ThirdPartyFundsRequested);
        }
        if inputs.command_hash_32 == [0u8; 32] {
            return Err(ReproPlanReject::MissingCommand);
        }
        if inputs.expected_failure_hash_32 == [0u8; 32] {
            return Err(ReproPlanReject::MissingExpectedFailure);
        }
        Ok(Self {
            repo_hash_32: inputs.repo_hash_32,
            fixture_hash_32: inputs.fixture_hash_32,
            command_hash_32: inputs.command_hash_32,
            expected_failure_hash_32: inputs.expected_failure_hash_32,
            local_only: true,
        })
    }

    /// Whether the plan schema is complete: local-only with a command + expected
    /// failure.
    #[must_use]
    pub fn schema_complete(&self) -> bool {
        self.local_only
            && self.command_hash_32 != [0u8; 32]
            && self.expected_failure_hash_32 != [0u8; 32]
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;

    fn inputs() -> ReproPlanInputs {
        ReproPlanInputs {
            repo_hash_32: [0x10; 32],
            fixture_hash_32: [0x20; 32],
            command_hash_32: [0x30; 32],
            expected_failure_hash_32: [0x40; 32],
        }
    }

    #[test]
    fn local_only_pass() {
        let p = LocalReproPlan::new(&inputs(), ReproPlanFlags::default()).unwrap();
        assert!(p.local_only);
        assert!(p.schema_complete());
    }

    #[test]
    fn production_rpc_deny() {
        let flags = ReproPlanFlags {
            uses_production_rpc: true,
            ..ReproPlanFlags::default()
        };
        assert_eq!(
            LocalReproPlan::new(&inputs(), flags),
            Err(ReproPlanReject::ProductionRpcRequested)
        );
    }

    #[test]
    fn live_tx_deny() {
        let flags = ReproPlanFlags {
            uses_live_tx: true,
            ..ReproPlanFlags::default()
        };
        assert_eq!(
            LocalReproPlan::new(&inputs(), flags),
            Err(ReproPlanReject::LiveTxRequested)
        );
    }

    #[test]
    fn third_party_funds_deny() {
        let flags = ReproPlanFlags {
            touches_third_party_funds: true,
            ..ReproPlanFlags::default()
        };
        assert_eq!(
            LocalReproPlan::new(&inputs(), flags),
            Err(ReproPlanReject::ThirdPartyFundsRequested)
        );
    }

    #[test]
    fn missing_command_reject() {
        let mut i = inputs();
        i.command_hash_32 = [0u8; 32];
        assert_eq!(
            LocalReproPlan::new(&i, ReproPlanFlags::default()),
            Err(ReproPlanReject::MissingCommand)
        );
    }

    #[test]
    fn expected_failure_required() {
        let mut i = inputs();
        i.expected_failure_hash_32 = [0u8; 32];
        assert_eq!(
            LocalReproPlan::new(&i, ReproPlanFlags::default()),
            Err(ReproPlanReject::MissingExpectedFailure)
        );
    }
}
