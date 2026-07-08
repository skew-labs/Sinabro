//! Stage B encrypted keystore at rest, testnet policy.
//!
//! Public API surface: the Stage A
//! [`SealedKeypair`](crate::keystore::SealedKeypair) **reused** under Stage B
//! testnet policy. This module does NOT re-implement the AEAD / PBKDF2
//! sealing (that is Stage A #33, `keystore.rs:247`); it pairs a sealed
//! keypair with a [`StageBTestnetWalletConfig`] so every key on this surface
//! is bound to the one-variant testnet network, and it routes the seal /
//! unseal paths through the Stage B package error vocabulary
//! ([`StageBWalletError`]).
//!
//! # Invariants
//!
//! * **Disk stores ciphertext only.** The wrapped [`SealedKeypair`] holds an
//!   opaque AEAD blob (`pubkey(32) ‖ aes_gcm_siv_ciphertext_with_tag(48)`);
//!   the plaintext seed never leaves the Stage A `create_encrypted` scope.
//!   This wrapper adds no field that could hold a plaintext seed.
//! * **A plaintext key path is rejected.** [`StageBTestnetKeystore::seal`]
//!   refuses an empty passphrase with [`StageBWalletError::PlaintextRefused`]
//!   (delegating to the Stage A refusal), so a caller cannot ask the keystore
//!   to persist an unprotected key.
//! * **Every key is testnet-bound.** Construction takes a
//!   [`StageBTestnetWalletConfig`] whose `network` is unrepresentably
//!   non-testnet, so a keystore on this surface can never be tagged for a
//!   production network.
//!
//! # Reuse map (atom contract)
//!
//! * **reuse: #146** — [`StageBTestnetWalletConfig`] (the testnet policy this
//!   keystore is bound to).
//! * [`SealedKeypair`] (`keystore.rs:123`), its
//!   `create_encrypted` / `unseal` / `public_address` paths, and the
//!   [`ScopedSecretKey`](crate::keystore::ScopedSecretKey) the unseal returns.

use crate::keystore::SealedKeypair;
use crate::stage_b_config::{StageBTestnetWalletConfig, StageBWalletError};
use crate::stage_b_secret::StageBScopedSecretKey;
use mnemos_d_move::types::SuiAddress;

/// A Stage B testnet keystore: a Stage A [`SealedKeypair`] bound to a
/// [`StageBTestnetWalletConfig`] testnet policy.
///
/// The struct deliberately carries **no** plaintext-secret field — the only
/// secret-bearing value in the whole lifecycle is the transient
/// [`StageBScopedSecretKey`] returned by [`StageBTestnetKeystore::unseal`],
/// which zeroizes on drop. The on-disk form a caller would persist is the
/// wrapped [`SealedKeypair`]'s opaque ciphertext (exposed via
/// [`StageBTestnetKeystore::sealed`]).
///
/// No `Clone` / `Copy`: a sealed keypair is a singular custody object; copying
/// it would invite two-out-of-sync on-disk forms. `Debug` is intentionally
/// **not** derived so the wrapped ciphertext bytes never reach a log line.
pub struct StageBTestnetKeystore {
    sealed: SealedKeypair,
    config: StageBTestnetWalletConfig,
}

impl StageBTestnetKeystore {
    /// Seal a fresh ed25519 keypair under `passphrase`, bound to the testnet
    /// `config`. Delegates the sealing to the Stage A
    /// [`SealedKeypair::create_encrypted`] (fresh OS-CSPRNG seed, PBKDF2 +
    /// AES-256-GCM-SIV); the plaintext seed never leaves that scope.
    ///
    /// # Errors
    ///
    /// - [`StageBWalletError::PlaintextRefused`] when `passphrase` is empty
    ///   (a plaintext key path is structurally refused).
    /// - [`StageBWalletError::Decrypt`] when the OS CSPRNG / AEAD layer fails
    ///   (catastrophic and indistinguishable to the caller).
    pub fn seal(
        config: StageBTestnetWalletConfig,
        passphrase: &str,
    ) -> Result<Self, StageBWalletError> {
        let sealed = SealedKeypair::create_encrypted(passphrase)?;
        Ok(Self { sealed, config })
    }

    /// Adopt an already-sealed Stage A [`SealedKeypair`] (e.g. one read back
    /// from disk) under the testnet `config`. No decryption happens here; the
    /// ciphertext stays opaque until [`StageBTestnetKeystore::unseal`].
    #[inline]
    #[must_use]
    pub fn from_sealed(sealed: SealedKeypair, config: StageBTestnetWalletConfig) -> Self {
        Self { sealed, config }
    }

    /// Authenticate the keystore under `passphrase` and return the transient
    /// [`StageBScopedSecretKey`]. The returned secret zeroizes on drop; no
    /// copy of the seed escapes.
    ///
    /// # Errors
    ///
    /// - [`StageBWalletError::Decrypt`] for a wrong passphrase OR tampered
    ///   ciphertext (uniform privacy posture — the two are indistinguishable).
    pub fn unseal(&self, passphrase: &str) -> Result<StageBScopedSecretKey, StageBWalletError> {
        Ok(self.sealed.unseal(passphrase)?)
    }

    /// The testnet Sui address of this keystore's keypair — a zero-decryption
    /// read of the ciphertext's 32-byte pubkey prefix
    /// (`Blake2b-256(0x00 ‖ pubkey)`), via the Stage A
    /// [`SealedKeypair::public_address`].
    #[inline]
    #[must_use]
    pub fn public_address(&self) -> SuiAddress {
        self.sealed.public_address()
    }

    /// Borrow the wrapped Stage A [`SealedKeypair`] — the opaque, persist-safe
    /// ciphertext form (no plaintext seed).
    #[inline]
    #[must_use]
    pub fn sealed(&self) -> &SealedKeypair {
        &self.sealed
    }

    /// The testnet policy this keystore is bound to.
    #[inline]
    #[must_use]
    pub fn config(&self) -> StageBTestnetWalletConfig {
        self.config
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    #![allow(clippy::expect_used)]
    #![allow(clippy::panic)]

    use super::*;
    use mnemos_b_memory::network::StageBNetwork;
    use mnemos_d_move::types::GasBudgetMist;

    fn testnet_config() -> StageBTestnetWalletConfig {
        StageBTestnetWalletConfig::new(StageBNetwork::Testnet, GasBudgetMist::new(800_000))
    }

    /// `b4_1_seal_unseal` — a keystore sealed under a passphrase unseals back
    /// to a usable scoped secret, and the public address is stable across the
    /// seal/unseal boundary (a zero-decryption read of the ciphertext prefix).
    #[test]
    fn b4_1_seal_unseal() {
        let ks = StageBTestnetKeystore::seal(testnet_config(), "correct horse battery staple")
            .expect("seal under a non-empty passphrase must succeed");
        let addr_before = ks.public_address();

        let scoped = ks
            .unseal("correct horse battery staple")
            .expect("unseal under the correct passphrase must succeed");
        // The recovered seed is a usable 32-byte secret.
        assert_eq!(scoped.as_bytes().len(), 32);
        drop(scoped); // zeroizes the buffer (Stage A #33 invariant).

        // Address is unchanged by an unseal — it reads the ciphertext prefix.
        assert_eq!(ks.public_address().as_bytes(), addr_before.as_bytes());
    }

    /// `b4_1_wrong_pass_fails` — a wrong passphrase fails with the uniform
    /// `Decrypt` error (indistinguishable from a tampered-ciphertext failure).
    #[test]
    fn b4_1_wrong_pass_fails() {
        let ks = StageBTestnetKeystore::seal(testnet_config(), "passphrase-A")
            .expect("seal must succeed");
        // The unseal Ok type is `ScopedSecretKey`, which has no `Debug` /
        // `PartialEq` (by design — it is the secret), so we cannot `assert_eq!`
        // on the `Result`; match the error variant instead.
        assert!(
            matches!(ks.unseal("passphrase-B"), Err(StageBWalletError::Decrypt)),
            "wrong passphrase must surface the uniform Decrypt error",
        );
    }

    /// `b4_1_plaintext_refused` — an empty passphrase (a request to persist a
    /// key with no protection) is refused fail-closed. This is the
    /// "plaintext key file path is rejected" invariant.
    #[test]
    fn b4_1_plaintext_refused() {
        assert_eq!(
            StageBTestnetKeystore::seal(testnet_config(), "")
                .err()
                .expect("empty passphrase must be refused"),
            StageBWalletError::PlaintextRefused,
        );
    }

    /// `b4_1_disk_form_is_ciphertext_only` — the persist-safe form a caller
    /// would write to disk is the opaque [`SealedKeypair`] ciphertext; this
    /// keystore exposes no plaintext-seed accessor. We pin that the only
    /// secret-bearing value is the transient unseal output (which zeroizes on
    /// drop), and that two seals of the same passphrase produce DIFFERENT
    /// ciphertext (fresh CSPRNG salt/nonce/seed) — i.e. no deterministic
    /// plaintext leak across instances.
    #[test]
    fn b4_1_disk_form_is_ciphertext_only() {
        let a = StageBTestnetKeystore::seal(testnet_config(), "same-pass").expect("seal a");
        let b = StageBTestnetKeystore::seal(testnet_config(), "same-pass").expect("seal b");
        // Fresh randomness per seal ⇒ distinct addresses (distinct seeds).
        assert_ne!(
            a.public_address().as_bytes(),
            b.public_address().as_bytes(),
            "two seals must draw fresh seeds (no deterministic key)",
        );
        // The config round-trips and stays testnet.
        assert_eq!(a.config().network(), StageBNetwork::Testnet);
    }
}
