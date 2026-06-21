//! Stage C sealed mainnet config (C-WP-05 · atom #219 · C.2.0).
//!
//! Canonical OUT: a sealed mainnet config whose chain env is
//! [`MainnetPrepared`](crate::stage_c_env::StageCChainEnv::MainnetPrepared).
//!
//! # Madness invariants (atom #219)
//!
//! * **Prepare, never execute.** A [`SealedMainnetConfig`] can describe the
//!   prepared mainnet posture, but it can never carry an executable state.
//!   [`from_toml_str`](SealedMainnetConfig::from_toml_str) rejects an
//!   `execution_state` that is [`Executed`](crate::stage_c_env::MainnetExecutionState::Executed)
//!   or [`TimelockQueued`](crate::stage_c_env::MainnetExecutionState::TimelockQueued)
//!   — those belong to the later operator-approval ceremony — and
//!   [`can_execute`](SealedMainnetConfig::can_execute) is always `false`.
//! * **A checklist receipt is mandatory.** A config with a zero
//!   `checklist_receipt_hash` is rejected with
//!   [`MainnetConfigError::MissingChecklist`]: a mainnet endpoint cannot be
//!   prepared without binding the §4.2 checklist receipt that gates it.
//! * **No re-mint, no inverted dependency.** The execution posture reuses the
//!   §4.1 [`MainnetExecutionState`](crate::stage_c_env::MainnetExecutionState)
//!   and [`StageCChainEnv`](crate::stage_c_env::StageCChainEnv) (atom #173,
//!   same crate). The atom #204 checklist is referenced **by its 32-byte
//!   evidence hash only** — `a-core` is the dependency root and does not import
//!   the `k-devex` checklist type, so there is no `a-core -> k-devex`
//!   dependency inversion.
//!
//! # Reuse map (atom contract)
//!
//! * **reuse: #173** — [`MainnetExecutionState`](crate::stage_c_env::MainnetExecutionState),
//!   [`StageCChainEnv`](crate::stage_c_env::StageCChainEnv).
//! * **reuse: #204** — the `MainnetChecklist` evidence hash, by value (a
//!   `[u8; 32]`), not by type.

use crate::stage_c_env::{MainnetExecutionState, StageCChainEnv};
use serde::Deserialize;

/// Sealed mainnet configuration (canonical OUT).
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub struct SealedMainnetConfig {
    /// The chain env. Always [`MainnetPrepared`](StageCChainEnv::MainnetPrepared)
    /// for a sealed mainnet config.
    pub chain_env: StageCChainEnv,
    /// The (non-executable) execution posture. Never `Executed`/`TimelockQueued`.
    pub execution_state: MainnetExecutionState,
    /// The §4.2 checklist evidence hash this config is gated on. Non-zero by
    /// construction.
    pub checklist_receipt_hash_32: [u8; 32],
}

/// Sealed-config parse / validation error. Every variant is data-free.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
#[repr(u8)]
pub enum MainnetConfigError {
    /// The config TOML failed to parse or carried unknown fields.
    TomlParse = 1,
    /// The checklist receipt hash was all-zero.
    MissingChecklist = 2,
    /// The chain-env label was not a known value, or was not `MainnetPrepared`.
    ChainEnvInvalid = 3,
    /// The execution-state label was unknown, or was an executable / queued
    /// state forbidden for a prepared config.
    ExecutionStateForbidden = 4,
    /// The checklist receipt hash string was not 64 hex characters.
    ChecklistHashFormat = 5,
}

impl core::fmt::Display for MainnetConfigError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let msg = match self {
            Self::TomlParse => "stage_c mainnet config: toml parse failed",
            Self::MissingChecklist => {
                "stage_c mainnet config: checklist receipt required (non-zero)"
            }
            Self::ChainEnvInvalid => "stage_c mainnet config: chain env must be MainnetPrepared",
            Self::ExecutionStateForbidden => {
                "stage_c mainnet config: execution state forbidden (prepare-only)"
            }
            Self::ChecklistHashFormat => "stage_c mainnet config: checklist hash format invalid",
        };
        f.write_str(msg)
    }
}

impl core::error::Error for MainnetConfigError {}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct TomlMainnet {
    chain_env: String,
    execution_state: String,
    checklist_receipt_hash: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct TomlMainnetTop {
    mainnet: TomlMainnet,
}

const fn hex_nibble(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

fn decode_hash_hex(raw: &str) -> Result<[u8; 32], MainnetConfigError> {
    let hex = raw.strip_prefix("0x").unwrap_or(raw);
    if hex.len() != 64 {
        return Err(MainnetConfigError::ChecklistHashFormat);
    }
    let bytes = hex.as_bytes();
    let mut out = [0u8; 32];
    let mut i = 0usize;
    while i < 32 {
        let hi = hex_nibble(bytes[i * 2]).ok_or(MainnetConfigError::ChecklistHashFormat)?;
        let lo = hex_nibble(bytes[i * 2 + 1]).ok_or(MainnetConfigError::ChecklistHashFormat)?;
        out[i] = (hi << 4) | lo;
        i += 1;
    }
    Ok(out)
}

fn parse_chain_env(label: &str) -> Result<StageCChainEnv, MainnetConfigError> {
    match label {
        "MainnetPrepared" => Ok(StageCChainEnv::MainnetPrepared),
        // A sealed *mainnet* config must be the prepared-mainnet posture.
        _ => Err(MainnetConfigError::ChainEnvInvalid),
    }
}

fn parse_execution_state(label: &str) -> Result<MainnetExecutionState, MainnetConfigError> {
    let state = match label {
        "Locked" => MainnetExecutionState::Locked,
        "DryRunOnly" => MainnetExecutionState::DryRunOnly,
        "ApprovalPending" => MainnetExecutionState::ApprovalPending,
        "Paused" => MainnetExecutionState::Paused,
        // TimelockQueued / Executed are produced by the later ceremony, never
        // by a sealed config.
        _ => return Err(MainnetConfigError::ExecutionStateForbidden),
    };
    Ok(state)
}

const fn is_zero_32(h: &[u8; 32]) -> bool {
    let mut i = 0;
    while i < 32 {
        if h[i] != 0 {
            return false;
        }
        i += 1;
    }
    true
}

impl SealedMainnetConfig {
    /// Parse a sealed mainnet config from a `[mainnet]` TOML document.
    ///
    /// # Errors
    ///
    /// [`MainnetConfigError`] variants for malformed TOML, an invalid chain env
    /// / execution state, a missing checklist receipt, or a malformed hash.
    pub fn from_toml_str(toml_text: &str) -> Result<Self, MainnetConfigError> {
        let parsed: TomlMainnetTop =
            toml::from_str(toml_text).map_err(|_| MainnetConfigError::TomlParse)?;
        let chain_env = parse_chain_env(&parsed.mainnet.chain_env)?;
        let execution_state = parse_execution_state(&parsed.mainnet.execution_state)?;
        let checklist_receipt_hash_32 = decode_hash_hex(&parsed.mainnet.checklist_receipt_hash)?;
        if is_zero_32(&checklist_receipt_hash_32) {
            return Err(MainnetConfigError::MissingChecklist);
        }
        Ok(Self {
            chain_env,
            execution_state,
            checklist_receipt_hash_32,
        })
    }

    /// Whether this config permits a real mainnet write. Always `false`: a
    /// sealed config can prepare an endpoint, but execution requires the later
    /// operator-approval ceremony, never the config itself.
    #[inline]
    #[must_use]
    pub const fn can_execute(&self) -> bool {
        self.execution_state.is_executable()
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    #![allow(clippy::expect_used)]
    #![allow(clippy::panic)]

    use super::*;

    const GOOD: &str = "[mainnet]\nchain_env = \"MainnetPrepared\"\nexecution_state = \"Locked\"\nchecklist_receipt_hash = \"0x1111111111111111111111111111111111111111111111111111111111111111\"\n";

    /// `c2_0_config_parse` — a well-formed config parses to a prepared,
    /// non-executable posture with the checklist receipt bound.
    #[test]
    fn c2_0_config_parse() {
        let cfg = SealedMainnetConfig::from_toml_str(GOOD).expect("config parses");
        assert_eq!(cfg.chain_env, StageCChainEnv::MainnetPrepared);
        assert_eq!(cfg.execution_state, MainnetExecutionState::Locked);
        assert_eq!(cfg.checklist_receipt_hash_32, [0x11u8; 32]);
        assert!(!cfg.can_execute());

        // Unknown field rejected.
        let bad = format!("{GOOD}extra = 1\n");
        assert_eq!(
            SealedMainnetConfig::from_toml_str(&bad),
            Err(MainnetConfigError::TomlParse),
        );
    }

    /// `c2_0_execution_state_locked` — the config can never carry an executable
    /// or queued state; `can_execute` is always false.
    #[test]
    fn c2_0_execution_state_locked() {
        // Executed / TimelockQueued are forbidden in a sealed config.
        let executed = GOOD.replace("\"Locked\"", "\"Executed\"");
        assert_eq!(
            SealedMainnetConfig::from_toml_str(&executed),
            Err(MainnetConfigError::ExecutionStateForbidden),
        );
        let queued = GOOD.replace("\"Locked\"", "\"TimelockQueued\"");
        assert_eq!(
            SealedMainnetConfig::from_toml_str(&queued),
            Err(MainnetConfigError::ExecutionStateForbidden),
        );

        // The allowed prepared states are all non-executable.
        for label in ["Locked", "DryRunOnly", "ApprovalPending", "Paused"] {
            let doc = GOOD.replace("\"Locked\"", &format!("\"{label}\""));
            let cfg = SealedMainnetConfig::from_toml_str(&doc)
                .unwrap_or_else(|_| panic!("{label} must parse"));
            assert!(!cfg.can_execute(), "{label} must not be executable");
        }

        // A non-mainnet chain env is rejected (sealed *mainnet* config).
        let testnet = GOOD.replace("\"MainnetPrepared\"", "\"TestnetVerified\"");
        assert_eq!(
            SealedMainnetConfig::from_toml_str(&testnet),
            Err(MainnetConfigError::ChainEnvInvalid),
        );
    }

    /// `c2_0_missing_checklist_reject` — a zero checklist receipt is rejected.
    #[test]
    fn c2_0_missing_checklist_reject() {
        let zero = GOOD.replace(
            "0x1111111111111111111111111111111111111111111111111111111111111111",
            "0x0000000000000000000000000000000000000000000000000000000000000000",
        );
        assert_eq!(
            SealedMainnetConfig::from_toml_str(&zero),
            Err(MainnetConfigError::MissingChecklist),
        );

        // A malformed hash is rejected before the zero check.
        let badhash = GOOD.replace(
            "0x1111111111111111111111111111111111111111111111111111111111111111",
            "0xdeadbeef",
        );
        assert_eq!(
            SealedMainnetConfig::from_toml_str(&badhash),
            Err(MainnetConfigError::ChecklistHashFormat),
        );
    }
}
