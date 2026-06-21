//! Stage B sign Sui tx intent, testnet-only (atom #151 · B.4.5, WorkPackage
//! B-WP-03).
//!
//! Canonical OUT (`MNEMOS_STAGE_B_ATOM_PLAN.md` §4.4): a testnet-only Sui
//! transaction signing helper. It signs the byte-stable dry-run
//! representation of a Stage B [`StageBCallBuilder`] (atom #134) under the Sui
//! `TransactionData` intent, via the reused Stage A
//! [`sign_move_tx`](crate::sign_tx::sign_move_tx).
//!
//! # Madness invariants (§4.4 / atom #151)
//!
//! * **The signer accepts only Stage B testnet call-builder output.** The
//!   entry point takes `&StageBCallBuilder`, and a [`StageBCallBuilder`] can
//!   be constructed ONLY through its `create_root` / `add_chunk` /
//!   `audit_append` constructors, each of which rejects a non-testnet network
//!   label with [`StageBMoveBindError::NetworkNotTestnet`] before any byte
//!   work (`d-move/src/stage_b_call_builder.rs`). There is therefore **no
//!   type path** by which a production-network transaction's bytes could
//!   reach this signer — the testnet gate is upstream of, and structurally
//!   required for, the value this function consumes.
//! * **The Sui tx intent domain is separate from the chunk-sign domain.** The
//!   signature is produced under the `TransactionData` prefix `[0,0,0]`
//!   (Stage A #34), disjoint from the atom #89 chunk-sign domain (#150) and
//!   the personal-message scope `[3,0,0]` (#35) — a tx signature cannot be
//!   replayed as a chunk or personal-message signature.
//! * **No secret escapes.** The seed is borrowed from the caller's
//!   [`ScopedSecretKey`] for the call only (Stage A #34 zeroize posture).
//!
//! # Reuse map (atom contract)
//!
//! * **reuse: #134** — [`StageBCallBuilder`] and its testnet-gated
//!   `to_dry_run_bytes` carrier.
//! * **reuse: #148** — the [`ScopedSecretKey`] that signs.

use crate::keystore::ScopedSecretKey;
use crate::sign_tx::sign_move_tx;
use mnemos_c_walrus::SignatureBytes;
use mnemos_d_move::StageBCallBuilder;

/// Sign the dry-run byte representation of a Stage B testnet
/// [`StageBCallBuilder`] under the Sui `TransactionData` intent, returning the
/// raw 64-byte ed25519 [`SignatureBytes`].
///
/// The `builder` is testnet by construction (its constructors reject a
/// non-testnet label), so this signer has no type path to production-network
/// bytes. The signed message is `intent_prefix[0,0,0] ‖ builder.to_dry_run_bytes()`,
/// assembled by the reused [`sign_move_tx`].
///
/// Total over the builder — returns [`SignatureBytes`] directly: the builder
/// already encodes a valid testnet call, and ed25519 signing accepts any
/// message length.
#[must_use]
pub fn sign_testnet_call(key: &ScopedSecretKey, builder: &StageBCallBuilder) -> SignatureBytes {
    // `to_dry_run_bytes` is the byte-stable, unsigned carrier (#134). It is
    // testnet-only because the builder that produced it is.
    let intent_tx_bytes = builder.to_dry_run_bytes();
    sign_move_tx(key, &intent_tx_bytes)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    #![allow(clippy::expect_used)]
    #![allow(clippy::panic)]

    use super::*;
    use crate::sign_msg::sign_message;
    use crate::sign_tx::SUI_INTENT_PREFIX_TRANSACTION_DATA;
    use ed25519_dalek::{Signature, SigningKey, Verifier, VerifyingKey};
    use mnemos_d_move::StageBMoveBindError;
    use mnemos_d_move::types::GasBudgetMist;

    const TEST_SEED: [u8; 32] = [
        0x13, 0x37, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE, //
        0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, //
        0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10, //
        0x0A, 0x1B, 0x2C, 0x3D, 0x4E, 0x5F, 0x60, 0x71, //
    ];

    fn testnet_builder() -> StageBCallBuilder {
        StageBCallBuilder::create_root("testnet", GasBudgetMist::new(900_000))
            .expect("testnet create_root must build")
    }

    /// `b4_5_testnet_intent_vector` — a signature over a testnet builder's
    /// dry-run bytes verifies under the derived public key when the verifier
    /// reconstructs the SAME `TransactionData`-prefixed message, and is 64
    /// bytes.
    #[test]
    fn b4_5_testnet_intent_vector() {
        let key = ScopedSecretKey::from_seed_for_test(TEST_SEED);
        let builder = testnet_builder();
        let sig = sign_testnet_call(&key, &builder);
        assert_eq!(sig.as_bytes().len(), 64);

        // Independently reconstruct the signed message and verify.
        let signing = SigningKey::from_bytes(&TEST_SEED);
        let verifying: VerifyingKey = signing.verifying_key();
        let mut signed_msg: Vec<u8> = Vec::new();
        signed_msg.extend_from_slice(&SUI_INTENT_PREFIX_TRANSACTION_DATA);
        signed_msg.extend_from_slice(&builder.to_dry_run_bytes());
        let signature = Signature::from_bytes(sig.as_bytes());
        verifying
            .verify(&signed_msg, &signature)
            .expect("tx signature must verify under the TransactionData intent");

        // The SAME signature must FAIL when the prefix is omitted — proving
        // the intent prefix is actually mixed in.
        assert!(
            verifying
                .verify(&builder.to_dry_run_bytes(), &signature)
                .is_err(),
            "signature must not verify without the intent prefix",
        );
    }

    /// `b4_5_mainnet_rejected` — a non-testnet network label has no type path
    /// to this signer: the [`StageBCallBuilder`] constructor rejects it
    /// fail-closed, so no builder (and thus no signature) is ever produced.
    /// The forbidden production label appears only here, inside `#[cfg(test)]`,
    /// as reject evidence.
    #[test]
    fn b4_5_mainnet_rejected() {
        for bad in ["mainnet", "devnet", "localnet", ""] {
            assert_eq!(
                StageBCallBuilder::create_root(bad, GasBudgetMist::new(900_000)).err(),
                Some(StageBMoveBindError::NetworkNotTestnet),
                "label {bad:?} must be rejected before any builder exists",
            );
        }
    }

    /// `b4_5_tx_message_domain_separated` — a `TransactionData`-domain
    /// signature over the builder bytes differs from a `PersonalMessage`-domain
    /// signature over the SAME bytes, and the tx signature does NOT verify
    /// under the personal-message prefix. Pins the cross-scope replay barrier.
    #[test]
    fn b4_5_tx_message_domain_separated() {
        let key = ScopedSecretKey::from_seed_for_test(TEST_SEED);
        let builder = testnet_builder();
        let bytes = builder.to_dry_run_bytes();

        let tx_sig = sign_testnet_call(&key, &builder);
        let msg_sig = sign_message(&key, &bytes);
        assert_ne!(
            tx_sig.as_bytes(),
            msg_sig.as_bytes(),
            "tx-domain and personal-message-domain signatures over the same bytes must differ",
        );

        // The tx signature must not verify under the personal-message prefix.
        let signing = SigningKey::from_bytes(&TEST_SEED);
        let verifying = signing.verifying_key();
        let mut pm_msg: Vec<u8> = Vec::new();
        pm_msg.extend_from_slice(&crate::sign_msg::SUI_INTENT_PREFIX_PERSONAL_MESSAGE);
        pm_msg.extend_from_slice(&bytes);
        let tx_signature = Signature::from_bytes(tx_sig.as_bytes());
        assert!(
            verifying.verify(&pm_msg, &tx_signature).is_err(),
            "tx signature must not verify under the personal-message scope",
        );
    }
}
