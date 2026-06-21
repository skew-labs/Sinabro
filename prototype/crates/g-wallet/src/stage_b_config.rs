//! Stage B testnet wallet config (atom #146 · B.4.0, WorkPackage B-WP-03).
//!
//! The first canonical surface of the Stage B wallet package. Its single
//! job is to pin, at the type level, that a Stage B wallet may operate on
//! exactly one network — Sui/Walrus **testnet** — and never a production
//! network (`MNEMOS_STAGE_B_ATOM_PLAN.md` §4.4):
//!
//! ```text
//! pub struct StageBTestnetWalletConfig { pub network: StageBNetwork, pub max_gas_mist: GasBudgetMist }
//! pub enum StageBWalletError { Decrypt, Sign, PlaintextRefused, NetworkNotTestnet, RotationFailed }
//! ```
//!
//! # Madness invariants (§4.4 / atom #146)
//!
//! * **`network` carries [`StageBNetwork::Testnet`] and a production network
//!   is unrepresentable.** The field's type (atom #82 ·
//!   [`mnemos_b_memory::network::StageBNetwork`]) is a one-variant enum, so
//!   no value — present or future — can select a production network by
//!   constructing this config. The `G-B-NO-MAINNET` typed-network guard is
//!   satisfied by construction, not by a runtime check that could be
//!   bypassed.
//! * **Label-driven construction is fail-closed.** [`StageBTestnetWalletConfig::from_label`]
//!   accepts only the canonical `testnet` label (via the reused
//!   [`StageBNetwork::parse_label`]) and rejects every other label with
//!   [`StageBWalletError::NetworkNotTestnet`]; the rejected raw label is not
//!   embedded in the error (a data-free variant), so a secret accidentally
//!   placed in the label cannot leak through the error value.
//! * **The gas cap is a typed unit.** `max_gas_mist` reuses atom #15's
//!   [`GasBudgetMist`] newtype so a raw `u64` (token count, byte length,
//!   epoch) can never be silently passed where a gas budget is expected.
//!
//! # Reuse map (atom contract)
//!
//! * **reuse: #82** — [`StageBNetwork`] (`b-memory/src/network.rs:73`). No
//!   second network type is minted here.
//! * **reuse: #135** — [`GasBudgetMist`] (`d-move/src/types.rs:118`). No
//!   second gas-budget unit is minted here.
//!
//! `StageBWalletError` is the package-wide error type (§4.4). Its emission
//! sites land across atoms #146–#155; the variants are declared here so
//! every wallet surface speaks one coarse, redaction-safe error vocabulary.

use mnemos_b_memory::network::StageBNetwork;
use mnemos_d_move::types::GasBudgetMist;

/// Stage B testnet wallet configuration (§4.4 canonical OUT).
///
/// `network` is type-locked to [`StageBNetwork`] (one variant, `Testnet`);
/// `max_gas_mist` is the per-action gas ceiling as a typed [`GasBudgetMist`].
/// The struct is `Copy` — both fields are 1-byte / 8-byte `Copy` newtypes —
/// so it can be threaded through preflight / signing / submit surfaces
/// without cloning secret-adjacent state (it carries none).
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub struct StageBTestnetWalletConfig {
    /// The Stage B network. One inhabitant by construction: testnet.
    pub network: StageBNetwork,
    /// The maximum gas budget (MIST) a Stage B action may spend. Stage B
    /// is testnet-only, so this is a faucet-funded ceiling, never a
    /// production-value cap.
    pub max_gas_mist: GasBudgetMist,
}

impl StageBTestnetWalletConfig {
    /// Build a testnet wallet config directly from the typed network and
    /// gas ceiling. Infallible — both inputs are already typed (a
    /// production network is not representable as a [`StageBNetwork`]).
    #[inline]
    #[must_use]
    pub const fn new(network: StageBNetwork, max_gas_mist: GasBudgetMist) -> Self {
        Self {
            network,
            max_gas_mist,
        }
    }

    /// Build a testnet wallet config the way a runtime entry point would —
    /// from a raw network `label` (conceptually the value of
    /// [`mnemos_b_memory::network::NETWORK_OVERRIDE_ENV_KEY`]) plus a gas
    /// ceiling.
    ///
    /// The label is parsed by the reused [`StageBNetwork::parse_label`],
    /// which accepts only the canonical `testnet` label
    /// (ASCII-case-insensitive, trimmed) and rejects everything else
    /// fail-closed.
    ///
    /// # Errors
    ///
    /// - [`StageBWalletError::NetworkNotTestnet`] when `label` is not the
    ///   canonical testnet label. The rejected raw label is **not** echoed
    ///   into the error (the variant carries no data), so a secret placed in
    ///   the label cannot leak through the return value.
    pub fn from_label(label: &str, max_gas_mist: GasBudgetMist) -> Result<Self, StageBWalletError> {
        match StageBNetwork::parse_label(label) {
            Some(network) => Ok(Self::new(network, max_gas_mist)),
            None => Err(StageBWalletError::NetworkNotTestnet),
        }
    }

    /// The configured network (always [`StageBNetwork::Testnet`]).
    #[inline]
    #[must_use]
    pub const fn network(&self) -> StageBNetwork {
        self.network
    }

    /// The configured gas ceiling.
    #[inline]
    #[must_use]
    pub const fn max_gas_mist(&self) -> GasBudgetMist {
        self.max_gas_mist
    }
}

/// Package-wide Stage B wallet error (§4.4 canonical OUT).
///
/// Variants are deliberately coarse and **data-free**: no variant carries a
/// passphrase, key byte, raw label, or transport body, so an error value can
/// never become a leak channel for secret or attacker-probed material. The
/// disk-side / network-side attacker MUST NOT learn whether a decrypt failed
/// for "wrong passphrase" vs "tampered ciphertext"; both collapse into
/// [`StageBWalletError::Decrypt`] (mirrors the Stage A `WalletError::Decrypt`
/// uniform-privacy posture, `keystore.rs:191`).
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum StageBWalletError {
    /// AEAD authentication failed OR the stored ciphertext is structurally
    /// malformed. Surfaced uniformly for wrong passphrase, tampered
    /// nonce/salt, tampered pubkey prefix, truncated blob, or an OS CSPRNG /
    /// AEAD failure. Maps the Stage A `WalletError::Decrypt`.
    Decrypt,
    /// A signing surface refused or failed. Maps the Stage A
    /// `WalletError::Sign`.
    Sign,
    /// An empty passphrase / plaintext-key path was requested. Plaintext
    /// secret storage is structurally refused. Maps the Stage A
    /// `WalletError::PlaintextRefused`.
    PlaintextRefused,
    /// A non-testnet network label was supplied to a Stage B wallet surface.
    /// Stage B may select only testnet; every other label is rejected
    /// fail-closed. The rejected raw label is not carried by this variant.
    NetworkNotTestnet,
    /// Key rotation refused or failed (same-passphrase rotation, or the
    /// cryptographically-impossible address-collision canary). Maps the
    /// Stage A `WalletError::KeyRotation`.
    RotationFailed,
}

impl core::fmt::Display for StageBWalletError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let msg = match self {
            Self::Decrypt => {
                "stage_b wallet decrypt: authentication failed or ciphertext malformed"
            }
            Self::Sign => "stage_b wallet sign: signing surface refused or failed",
            Self::PlaintextRefused => {
                "stage_b wallet seal refused: empty passphrase / plaintext path"
            }
            Self::NetworkNotTestnet => "stage_b wallet network: only testnet is permitted",
            Self::RotationFailed => "stage_b wallet rotation: refused or failed",
        };
        f.write_str(msg)
    }
}

impl core::error::Error for StageBWalletError {}

/// Map the Stage A §4.G [`WalletError`](crate::keystore::WalletError) onto the
/// Stage B package error. The mapping is total and preserves the uniform
/// privacy posture: `Decrypt` stays `Decrypt` (wrong-pass vs tamper remain
/// indistinguishable), and the Stage A `KeyRotation` variant becomes
/// [`StageBWalletError::RotationFailed`]. No Stage A error carries data, so
/// the mapped Stage B error stays data-free too. Reused by the Stage B
/// keystore (#147) and rotation (#153) surfaces.
impl From<crate::keystore::WalletError> for StageBWalletError {
    fn from(e: crate::keystore::WalletError) -> Self {
        match e {
            crate::keystore::WalletError::Decrypt => Self::Decrypt,
            crate::keystore::WalletError::Sign => Self::Sign,
            crate::keystore::WalletError::KeyRotation => Self::RotationFailed,
            crate::keystore::WalletError::PlaintextRefused => Self::PlaintextRefused,
        }
    }
}

#[cfg(test)]
mod tests {
    // Test helpers favour direct failure surfaces (`assert` / `expect`) over
    // `Result`-bubbling; suppress prod-only clippy denies inside this module
    // (Stage A #33 / #82 precedent).
    #![allow(clippy::unwrap_used)]
    #![allow(clippy::expect_used)]
    #![allow(clippy::panic)]

    use super::*;

    /// `b4_0_testnet_config_accepted` — the canonical testnet label (and
    /// case/whitespace variants) builds a config whose network tag is `1`
    /// and whose gas ceiling round-trips verbatim.
    #[test]
    fn b4_0_testnet_config_accepted() {
        let gas = GasBudgetMist::new(800_000);
        let cfg = StageBTestnetWalletConfig::from_label("testnet", gas)
            .expect("canonical testnet label must build a config");
        assert_eq!(cfg.network(), StageBNetwork::Testnet);
        assert_eq!(cfg.network().tag(), 1);
        assert_eq!(cfg.max_gas_mist().get(), 800_000);

        // Case-insensitive + trimmed, reusing the #82 parser semantics.
        for ok in ["Testnet", "TESTNET", "  testnet \t"] {
            assert_eq!(
                StageBTestnetWalletConfig::from_label(ok, gas)
                    .expect("case/whitespace variant accepted")
                    .network(),
                StageBNetwork::Testnet,
            );
        }

        // The direct typed constructor is infallible and equivalent.
        let direct = StageBTestnetWalletConfig::new(StageBNetwork::Testnet, gas);
        assert_eq!(direct, cfg);
    }

    /// `b4_0_nontestnet_env_rejected` — every non-testnet label is rejected
    /// fail-closed with `NetworkNotTestnet`, and a secret-bearing rejected
    /// label never appears in the error's `Debug` / `Display` rendering
    /// (the variant is data-free). The forbidden production label appears
    /// only here, inside `#[cfg(test)]`, as reject *evidence* — never on the
    /// production parse path (which compares only against `testnet`).
    #[test]
    fn b4_0_nontestnet_env_rejected() {
        let gas = GasBudgetMist::new(1);
        for bad in [
            "mainnet",
            "Mainnet",
            "devnet",
            "localnet",
            "custom-rpc",
            "",
            "   ",
        ] {
            assert_eq!(
                StageBTestnetWalletConfig::from_label(bad, gas),
                Err(StageBWalletError::NetworkNotTestnet),
                "label {bad:?} must be rejected fail-closed",
            );
        }

        // A secret-bearing non-testnet label is rejected, and none of its
        // distinctive substrings can be recovered from the error rendering.
        let secret_label = "mainnet://0xDEADBEEFprivkey?token=s3cr3t";
        let err = StageBTestnetWalletConfig::from_label(secret_label, gas)
            .expect_err("non-testnet override must be rejected");
        let rendered = format!("{err:?} {err}");
        for leaked in ["DEADBEEF", "privkey", "s3cr3t", "0x"] {
            assert!(
                !rendered.contains(leaked),
                "rejected label must not leak {leaked:?} into the error ({rendered:?})",
            );
        }
    }

    /// `b4_0_gas_cap_parse` — the gas ceiling is a typed `GasBudgetMist`
    /// carried verbatim across construction, including the `0` and `u64::MAX`
    /// edges (the config does not reject a zero cap — that is a downstream
    /// `add_chunk` / submit concern, atom #20 precedent).
    #[test]
    fn b4_0_gas_cap_parse() {
        for raw in [0u64, 1, 800_000, u64::MAX] {
            let cfg =
                StageBTestnetWalletConfig::new(StageBNetwork::Testnet, GasBudgetMist::new(raw));
            assert_eq!(cfg.max_gas_mist().get(), raw);
        }
    }

    /// `b4_0_error_is_data_free` — the package error type is `Copy` and
    /// every variant renders without echoing any caller-supplied bytes
    /// (structural redaction: there is no field that could carry them).
    #[test]
    fn b4_0_error_is_data_free() {
        for e in [
            StageBWalletError::Decrypt,
            StageBWalletError::Sign,
            StageBWalletError::PlaintextRefused,
            StageBWalletError::NetworkNotTestnet,
            StageBWalletError::RotationFailed,
        ] {
            // `Copy` round-trip (compile-time proof the type is Copy).
            let copied = e;
            assert_eq!(e, copied);
            // Display is non-empty and prefixed with the package namespace.
            assert!(format!("{e}").starts_with("stage_b wallet"));
        }
    }
}
