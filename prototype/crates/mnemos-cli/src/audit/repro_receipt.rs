//! Local repro runner receipt.
//!
//! [`LocalReproRunnerReceipt`] is the record that a candidate was reproduced
//! *locally*. It is mandatory before a candidate can become a finding: a receipt
//! pins `local_only = true`, `production_rpc_used = false`, and
//! `live_tx_used = false`, and carries the node / command / fixture / result
//! hashes. A receipt that used production RPC or a live tx, or that omits any
//! mandatory hash, is refused. A receipt may record a
//! non-reproduced outcome (a defended invariant) without becoming a finding. This
//! module performs no live action.
//!
//! Reuse (no reinvention): mirrors the exploit-repro signal — a finding
//! needs a reproducible local receipt, never a pattern-only claim.

/// Why recording a [`LocalReproRunnerReceipt`] was refused (fail-closed).
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum ReproReceiptReject {
    /// Production RPC was used — refused (local-only boundary).
    #[error("production rpc used")]
    ProductionRpcUsed,
    /// A live transaction was used — refused (local-only boundary).
    #[error("live tx used")]
    LiveTxUsed,
    /// The node hash was zero.
    #[error("missing node hash")]
    MissingNodeHash,
    /// The command hash was zero.
    #[error("missing command hash")]
    MissingCommandHash,
    /// The fixture hash was zero.
    #[error("missing fixture hash")]
    MissingFixtureHash,
    /// The result hash was zero.
    #[error("missing result hash")]
    MissingResultHash,
}

/// The mandatory hashes for a receipt (node, command, fixture, result).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ReproReceiptHashes {
    /// SHA-256 of the search node.
    pub node_hash_32: [u8; 32],
    /// SHA-256 of the local reproduction command.
    pub command_hash_32: [u8; 32],
    /// SHA-256 of the local fixture.
    pub fixture_hash_32: [u8; 32],
    /// SHA-256 of the reproduction result.
    pub result_hash_32: [u8; 32],
}

/// A receipt that a candidate was (or was not) reproduced locally.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LocalReproRunnerReceipt {
    /// SHA-256 of the search node the receipt backs.
    pub node_hash_32: [u8; 32],
    /// SHA-256 of the local reproduction command.
    pub command_hash_32: [u8; 32],
    /// SHA-256 of the local fixture.
    pub fixture_hash_32: [u8; 32],
    /// SHA-256 of the reproduction result.
    pub result_hash_32: [u8; 32],
    /// Invariant `true`: the reproduction was local-only.
    pub local_only: bool,
    /// Invariant `false`: production RPC was not used.
    pub production_rpc_used: bool,
    /// Invariant `false`: a live transaction was not used.
    pub live_tx_used: bool,
    /// Whether the candidate reproduced (a finding needs `true`).
    pub reproduced: bool,
}

impl LocalReproRunnerReceipt {
    /// Record a receipt. Refuses any production-RPC / live-tx use and any missing
    /// mandatory hash; `local_only` is pinned `true`.
    pub fn record(
        hashes: &ReproReceiptHashes,
        reproduced: bool,
        production_rpc_used: bool,
        live_tx_used: bool,
    ) -> Result<Self, ReproReceiptReject> {
        if production_rpc_used {
            return Err(ReproReceiptReject::ProductionRpcUsed);
        }
        if live_tx_used {
            return Err(ReproReceiptReject::LiveTxUsed);
        }
        if hashes.node_hash_32 == [0u8; 32] {
            return Err(ReproReceiptReject::MissingNodeHash);
        }
        if hashes.command_hash_32 == [0u8; 32] {
            return Err(ReproReceiptReject::MissingCommandHash);
        }
        if hashes.fixture_hash_32 == [0u8; 32] {
            return Err(ReproReceiptReject::MissingFixtureHash);
        }
        if hashes.result_hash_32 == [0u8; 32] {
            return Err(ReproReceiptReject::MissingResultHash);
        }
        Ok(Self {
            node_hash_32: hashes.node_hash_32,
            command_hash_32: hashes.command_hash_32,
            fixture_hash_32: hashes.fixture_hash_32,
            result_hash_32: hashes.result_hash_32,
            local_only: true,
            production_rpc_used: false,
            live_tx_used: false,
            reproduced,
        })
    }

    /// Whether the receipt is a safe, local-only reproduction.
    #[must_use]
    pub const fn is_safe_local(&self) -> bool {
        self.local_only && !self.production_rpc_used && !self.live_tx_used
    }

    /// Whether the receipt may promote a candidate to a finding
    /// (safe-local *and* reproduced).
    #[must_use]
    pub const fn promotes(&self) -> bool {
        self.is_safe_local() && self.reproduced
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;

    fn hashes() -> ReproReceiptHashes {
        ReproReceiptHashes {
            node_hash_32: [1u8; 32],
            command_hash_32: [2u8; 32],
            fixture_hash_32: [3u8; 32],
            result_hash_32: [4u8; 32],
        }
    }

    #[test]
    fn reproduced_promotes() {
        let r = LocalReproRunnerReceipt::record(&hashes(), true, false, false).unwrap();
        assert!(r.is_safe_local());
        assert!(r.promotes());
    }

    #[test]
    fn not_reproduced_no_promote() {
        // a defended (non-reproduced) outcome is a valid receipt but never promotes
        let r = LocalReproRunnerReceipt::record(&hashes(), false, false, false).unwrap();
        assert!(r.is_safe_local());
        assert!(!r.promotes());
    }

    #[test]
    fn production_rpc_reject() {
        assert_eq!(
            LocalReproRunnerReceipt::record(&hashes(), true, true, false),
            Err(ReproReceiptReject::ProductionRpcUsed)
        );
    }

    #[test]
    fn live_tx_reject() {
        assert_eq!(
            LocalReproRunnerReceipt::record(&hashes(), true, false, true),
            Err(ReproReceiptReject::LiveTxUsed)
        );
    }

    #[test]
    fn hash_missing_reject() {
        let mut hs = hashes();
        hs.command_hash_32 = [0u8; 32];
        assert_eq!(
            LocalReproRunnerReceipt::record(&hs, true, false, false),
            Err(ReproReceiptReject::MissingCommandHash)
        );
        let mut hs2 = hashes();
        hs2.result_hash_32 = [0u8; 32];
        assert_eq!(
            LocalReproRunnerReceipt::record(&hs2, true, false, false),
            Err(ReproReceiptReject::MissingResultHash)
        );
    }
}
