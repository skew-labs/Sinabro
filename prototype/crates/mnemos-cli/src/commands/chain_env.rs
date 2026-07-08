//! `sinabro chain env` — chain environment status
//! (chain env / testnet / mainnet).
//!
//! A read-only projection of the chain posture: the active environment
//! (testnet-verified / mainnet-prepared), the deployed package id, the fullnode
//! endpoint, the gas sponsor mode, and the mainnet execution-gate state. Two
//! structural invariants live here:
//!
//! * **Mainnet write requires explicit approval.** A mainnet mutation is never a
//!   default. [`ChainEnvView::mainnet_write_requires_approval`] reuses the
//!   canonical [`approval_for`]`(`[`CommandRisk::ChainWrite`]`)` mapping, which
//!   is the invariant [`ApprovalRequirement::Multisig`]; the gate is *surfaced*,
//!   never exercised (no live action).
//! * **No arbitrary endpoint, no silent mainnet.** The environment is the
//!   canonical two-state [`StageCChainEnv`] (there is no third "arbitrary URL"
//!   state), and a mainnet env renders [`RenderTruth::Red`] until the
//!   [`MainnetExecutionState::Executed`] ceremony — which this build never reaches.
//!   A testnet env carrying a mainnet-ladder posture is an *env mismatch* and
//!   also renders `Red`.
//!
//! Reuse: the env + execution posture are the canonical
//! [`mnemos_a_core::StageCChainEnv`] / [`mnemos_a_core::MainnetExecutionState`];
//! the gas mode is the canonical [`mnemos_g_wallet::GasSponsorMode`]; the package
//! id is the canonical [`mnemos_d_move::ObjectId`]; the red/yellow/green verdict
//! is the cockpit [`crate::tui::RenderTruth`]. This module mints no new chain
//! type — it is a projection over the a-core / d-move / g-wallet types.

use crate::command::{ApprovalRequirement, CommandRisk, approval_for};
use crate::hex32;
use crate::tui::RenderTruth;
use mnemos_a_core::{MainnetExecutionState, StageCChainEnv};
use mnemos_d_move::ObjectId;
use mnemos_g_wallet::GasSponsorMode;

/// First 16 hex characters of a 32-byte id — a redacted, display-only prefix.
#[must_use]
fn redact16(bytes: &[u8; 32]) -> String {
    hex32(bytes).chars().take(16).collect()
}

/// A read-only view of the active chain environment. Holds no secret: the
/// package id is shown redacted and the rest are public posture values.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ChainEnvView {
    /// The active chain environment (testnet-verified or mainnet-prepared).
    pub env: StageCChainEnv,
    /// The mainnet execution-gate posture (defaults to `Locked`; only `Executed`
    /// is executable, and this build never reaches it).
    pub execution_state: MainnetExecutionState,
    /// The gas sponsor mode (hosted / self-hosted / none).
    pub gas_mode: GasSponsorMode,
    /// The deployed on-chain package id (shown redacted).
    pub package: ObjectId,
    /// The public fullnode endpoint label.
    pub fullnode_endpoint: String,
}

impl ChainEnvView {
    /// Build a chain environment view from the active env, execution posture, gas
    /// mode, package id, and fullnode endpoint label.
    #[must_use]
    pub fn new(
        env: StageCChainEnv,
        execution_state: MainnetExecutionState,
        gas_mode: GasSponsorMode,
        package: ObjectId,
        fullnode_endpoint: &str,
    ) -> Self {
        Self {
            env,
            execution_state,
            gas_mode,
            package,
            fullnode_endpoint: fullnode_endpoint.to_string(),
        }
    }

    /// Whether a mainnet write requires explicit approval. Always `true`: the
    /// canonical [`approval_for`]`(`[`CommandRisk::ChainWrite`]`)` is
    /// [`ApprovalRequirement::Multisig`], so a mainnet mutation can never happen
    /// without the multisig approval gate.
    #[must_use]
    pub fn mainnet_write_requires_approval(&self) -> bool {
        matches!(
            approval_for(CommandRisk::ChainWrite),
            ApprovalRequirement::Multisig
        )
    }

    /// Whether the env and the execution posture are consistent. The mainnet
    /// execution ladder only applies to a `MainnetPrepared` env; a
    /// `TestnetVerified` env must sit at the safe `Locked` posture. A testnet env
    /// carrying any mainnet-ladder state is an env mismatch.
    #[must_use]
    pub fn env_consistent(&self) -> bool {
        match self.env {
            StageCChainEnv::TestnetVerified => {
                matches!(self.execution_state, MainnetExecutionState::Locked)
            }
            StageCChainEnv::MainnetPrepared => true,
        }
    }

    /// The render truth for this environment:
    ///
    /// * `Red`    — env mismatch (testnet with a mainnet-ladder posture), or a
    ///   `MainnetPrepared` env whose mainnet write path is still gated (the
    ///   default here, since `Executed` is never reached);
    /// * `Yellow` — a `MainnetPrepared` env reporting `Executed` (a live mainnet,
    ///   never produced here);
    /// * `Green`  — a consistent `TestnetVerified` env (the operating env here).
    #[must_use]
    pub fn render_truth(&self) -> RenderTruth {
        if !self.env_consistent() {
            return RenderTruth::Red;
        }
        match self.env {
            StageCChainEnv::TestnetVerified => RenderTruth::Green,
            StageCChainEnv::MainnetPrepared => {
                if self.execution_state.is_executable() {
                    RenderTruth::Yellow
                } else {
                    RenderTruth::Red
                }
            }
        }
    }

    /// Redacted, colorless status lines bounded by `rows`.
    #[must_use]
    pub fn render(&self, rows: u16) -> Vec<String> {
        let lines = vec![
            format!("env_u8={}", self.env.as_u8()),
            format!("execution_state_u8={}", self.execution_state.as_u8()),
            format!("gas_mode_u8={}", self.gas_mode.as_u8()),
            format!("package={}", redact16(self.package.as_bytes())),
            format!("fullnode_endpoint={}", self.fullnode_endpoint),
            format!(
                "mainnet_write_requires_approval={}",
                self.mainnet_write_requires_approval()
            ),
            format!("env_consistent={}", self.env_consistent()),
            format!("truth_u8={}", self.render_truth() as u8),
        ];
        lines.into_iter().take(rows as usize).collect()
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    #![allow(clippy::expect_used)]
    #![allow(clippy::panic)]

    use super::*;
    use crate::repl::latency::p95_ms;

    fn view(env: StageCChainEnv, state: MainnetExecutionState) -> ChainEnvView {
        ChainEnvView::new(
            env,
            state,
            GasSponsorMode::None,
            ObjectId::new([0x11; 32]),
            "https://fullnode.testnet.sui.io",
        )
    }

    #[test]
    fn testnet_and_mainnet_switch() {
        let testnet = view(
            StageCChainEnv::TestnetVerified,
            MainnetExecutionState::Locked,
        );
        assert_eq!(testnet.env, StageCChainEnv::TestnetVerified);
        assert_eq!(testnet.render_truth(), RenderTruth::Green);
        // Package id is redacted to 16 hex chars (never the full 64).
        assert!(
            testnet
                .render(16)
                .iter()
                .any(|l| l == "package=1111111111111111")
        );

        let mainnet = view(
            StageCChainEnv::MainnetPrepared,
            MainnetExecutionState::Locked,
        );
        assert_eq!(mainnet.env, StageCChainEnv::MainnetPrepared);
    }

    #[test]
    fn mainnet_gate_red() {
        // A prepared mainnet whose write path is still gated (the default
        // here) renders Red — the mainnet write is blocked.
        let v = view(
            StageCChainEnv::MainnetPrepared,
            MainnetExecutionState::Locked,
        );
        assert_eq!(v.render_truth(), RenderTruth::Red);
        // Even the approval-pending / timelock-queued ladder states are not
        // executable, so the gate stays Red.
        let pending = view(
            StageCChainEnv::MainnetPrepared,
            MainnetExecutionState::ApprovalPending,
        );
        assert_eq!(pending.render_truth(), RenderTruth::Red);
    }

    #[test]
    fn env_mismatch_is_red() {
        // Testnet env carrying a mainnet-ladder posture is an env mismatch.
        let v = view(
            StageCChainEnv::TestnetVerified,
            MainnetExecutionState::DryRunOnly,
        );
        assert!(!v.env_consistent());
        assert_eq!(v.render_truth(), RenderTruth::Red);
    }

    #[test]
    fn mainnet_write_always_requires_approval() {
        let v = view(
            StageCChainEnv::TestnetVerified,
            MainnetExecutionState::Locked,
        );
        assert!(v.mainnet_write_requires_approval());
    }

    #[test]
    fn render_is_bounded() {
        let v = view(
            StageCChainEnv::TestnetVerified,
            MainnetExecutionState::Locked,
        );
        assert!(v.render(3).len() <= 3);
        assert!(v.render(64).len() <= 8);
    }

    #[test]
    fn chain_env_p95_within_30ms() {
        let v = view(
            StageCChainEnv::MainnetPrepared,
            MainnetExecutionState::Locked,
        );
        let mut samples = Vec::with_capacity(256);
        for _ in 0..256 {
            let t = std::time::Instant::now();
            let lines = v.render(32);
            std::hint::black_box(&lines);
            samples.push(t.elapsed().as_nanos() as u64);
        }
        let p95 = p95_ms(&samples) / 1_000_000;
        assert!(p95 <= 30, "chain env p95 {p95}ms exceeds 30ms budget");
    }
}
