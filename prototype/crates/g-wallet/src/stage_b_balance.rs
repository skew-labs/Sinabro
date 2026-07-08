//! Stage B faucet / balance preflight.
//!
//! Canonical output: a testnet balance
//! preflight report. The governing rule: "Stage B uses testnet gas only. no
//! sponsor wallet, no Gas Station, no mainnet."
//!
//! # Invariants
//!
//! * **Testnet gas only.** The preflight compares a wallet's own
//!   (faucet-funded) testnet balance against the configured per-action gas
//!   ceiling. There is **no** sponsor-wallet field and **no** Gas-Station
//!   path — a Stage B action funds itself from testnet faucet gas.
//! * **No mainnet.** [`StageBBalancePreflight::evaluate_for_endpoint`] parses
//!   an endpoint label through the reused fail-closed
//!   [`StageBNetwork::parse_label`] and rejects any non-testnet endpoint with
//!   [`StageBWalletError::NetworkNotTestnet`]. The typed [`StageBBalancePreflight::evaluate`]
//!   path takes an already-testnet [`StageBTestnetWalletConfig`], so the
//!   guard is satisfied by construction there.
//! * **No live network here.** The balance is an input (caller-supplied /
//!   mock); this module performs no RPC. A live balance read is a later,
//!   live-approved concern (the disabled-by-default submitter, #155).
//!
//! # Reuse map (atom contract)
//!
//! * **reuse: #146** — [`StageBTestnetWalletConfig`] (the gas ceiling and the
//!   testnet network binding the preflight is evaluated against).

use crate::stage_b_config::{StageBTestnetWalletConfig, StageBWalletError};
use mnemos_b_memory::network::StageBNetwork;

/// The verdict of a balance preflight.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum StageBBalanceVerdict {
    /// The wallet balance covers at least the configured gas ceiling.
    Sufficient,
    /// The wallet balance is below the configured gas ceiling — top up via
    /// the testnet faucet before acting.
    Low,
}

/// A testnet balance preflight report (canonical output).
///
/// Records the observed balance, the required gas ceiling, and the verdict.
/// All values are public MIST counts; there is no secret or sponsor field.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub struct StageBBalancePreflight {
    balance_mist: u64,
    required_mist: u64,
    verdict: StageBBalanceVerdict,
}

impl StageBBalancePreflight {
    /// Evaluate a balance preflight against a testnet `config`'s gas ceiling.
    /// The `balance_mist` is the wallet's own testnet (faucet-funded)
    /// balance. Infallible — `config` is already testnet-typed.
    #[must_use]
    pub fn evaluate(config: &StageBTestnetWalletConfig, balance_mist: u64) -> Self {
        let required_mist = config.max_gas_mist().get();
        let verdict = if balance_mist >= required_mist {
            StageBBalanceVerdict::Sufficient
        } else {
            StageBBalanceVerdict::Low
        };
        Self {
            balance_mist,
            required_mist,
            verdict,
        }
    }

    /// Evaluate a balance preflight the way a runtime entry point would — from
    /// a raw `endpoint_label` plus the testnet `config` and observed balance.
    ///
    /// # Errors
    ///
    /// - [`StageBWalletError::NetworkNotTestnet`] when `endpoint_label` is not
    ///   the canonical testnet label. The rejected label is not echoed into
    ///   the error.
    pub fn evaluate_for_endpoint(
        endpoint_label: &str,
        config: &StageBTestnetWalletConfig,
        balance_mist: u64,
    ) -> Result<Self, StageBWalletError> {
        match StageBNetwork::parse_label(endpoint_label) {
            Some(StageBNetwork::Testnet) => Ok(Self::evaluate(config, balance_mist)),
            None => Err(StageBWalletError::NetworkNotTestnet),
        }
    }

    /// The observed wallet balance (MIST).
    #[inline]
    #[must_use]
    pub fn balance_mist(&self) -> u64 {
        self.balance_mist
    }

    /// The required gas ceiling (MIST).
    #[inline]
    #[must_use]
    pub fn required_mist(&self) -> u64 {
        self.required_mist
    }

    /// The verdict.
    #[inline]
    #[must_use]
    pub fn verdict(&self) -> StageBBalanceVerdict {
        self.verdict
    }

    /// `true` iff the balance covers the gas ceiling.
    #[inline]
    #[must_use]
    pub fn is_sufficient(&self) -> bool {
        matches!(self.verdict, StageBBalanceVerdict::Sufficient)
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    #![allow(clippy::expect_used)]
    #![allow(clippy::panic)]

    use super::*;
    use mnemos_d_move::types::GasBudgetMist;

    fn cfg(max_gas: u64) -> StageBTestnetWalletConfig {
        StageBTestnetWalletConfig::new(StageBNetwork::Testnet, GasBudgetMist::new(max_gas))
    }

    /// `b4_8_mock_balance_ok` — a balance at or above the gas ceiling is
    /// `Sufficient`; the exact-equal boundary counts as sufficient.
    #[test]
    fn b4_8_mock_balance_ok() {
        let c = cfg(800_000);
        let above = StageBBalancePreflight::evaluate(&c, 1_000_000);
        assert_eq!(above.verdict(), StageBBalanceVerdict::Sufficient);
        assert!(above.is_sufficient());
        assert_eq!(above.required_mist(), 800_000);
        assert_eq!(above.balance_mist(), 1_000_000);

        // Exact-equal boundary.
        let exact = StageBBalancePreflight::evaluate(&c, 800_000);
        assert_eq!(exact.verdict(), StageBBalanceVerdict::Sufficient);
    }

    /// `b4_8_mock_balance_low` — a balance below the gas ceiling is `Low`,
    /// including the zero-balance and one-below-boundary cases.
    #[test]
    fn b4_8_mock_balance_low() {
        let c = cfg(800_000);
        for bal in [0u64, 1, 799_999] {
            let p = StageBBalancePreflight::evaluate(&c, bal);
            assert_eq!(
                p.verdict(),
                StageBBalanceVerdict::Low,
                "balance {bal} must be Low"
            );
            assert!(!p.is_sufficient());
        }
    }

    /// `b4_8_mainnet_endpoint_reject` — a non-testnet endpoint label is
    /// rejected fail-closed; the canonical testnet label resolves. The
    /// forbidden production label appears only here as reject evidence.
    #[test]
    fn b4_8_mainnet_endpoint_reject() {
        let c = cfg(1);
        for bad in ["mainnet", "devnet", "localnet", "", "  "] {
            assert_eq!(
                StageBBalancePreflight::evaluate_for_endpoint(bad, &c, 10).err(),
                Some(StageBWalletError::NetworkNotTestnet),
                "endpoint {bad:?} must be rejected",
            );
        }
        let ok = StageBBalancePreflight::evaluate_for_endpoint("testnet", &c, 10)
            .expect("testnet endpoint resolves");
        assert_eq!(ok.verdict(), StageBBalanceVerdict::Sufficient);
    }
}
