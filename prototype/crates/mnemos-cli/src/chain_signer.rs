//! `chain_signer` — MNEMOS × SKEW K-2 (ONCHAIN PIVOT C-2): the ISOLATED ed25519 signer.
//!
//! # The user-owned signing boundary (-4 / -5)
//! The signing key is an ISOLATED Sinabro-owned ed25519 key — NEVER the Skew keeper key, NEVER the
//! owner's main wallet. The 32-byte secret seed lives ONLY inside a [`zeroize::Zeroizing`] buffer
//! (overwritten on drop), is never logged / rendered / hashed into a surface, and is never placed
//! in the model's context. The dispatch layer loads the seed from a 0600 owner-controlled file (the
//! secure source, like an ssh key) and constructs an [`IsolatedSigner`] for ONE signing call;
//! `agent_loop` reaches no signer symbol (the model holds no signer and types no key, -12).
//!
//! Signing uses `ed25519-dalek` (audited; we never hand-roll the curve) over the EXACT serialized
//! Solana legacy message bytes (the thing D13 compares), producing a 64-byte signature. The public
//! key is the Solana account address (the fee payer / signer).
//!
//! Total compromise is bounded by what the owner funds this isolated key with (= the
//! `CustodyGrant.total_budget` = max escrow — three walls, one number, plan idea #12).

use crate::solana_codec::Pubkey;
use ed25519_dalek::{Signer, SigningKey};
use zeroize::Zeroizing;

/// An isolated ed25519 signer over a zeroize-on-drop secret seed. Deliberately NOT `Debug` /
/// `Clone` / `Display` (no accidental seed leak). One signer signs ONE Solana message; the seed
/// never leaves this type except through the owner-controlled persist file the dispatch layer owns.
pub struct IsolatedSigner {
    /// The 32-byte ed25519 secret SEED — zeroized on drop, never logged.
    seed: Zeroizing<[u8; 32]>,
}

impl IsolatedSigner {
    /// Build a signer from a 32-byte seed (wrapped in a zeroizing buffer immediately).
    #[must_use]
    pub fn from_seed(seed: [u8; 32]) -> Self {
        Self {
            seed: Zeroizing::new(seed),
        }
    }

    /// Generate a FRESH isolated seed from the OS CSPRNG (`getrandom`). `None` (fail-closed) if the
    /// OS RNG is unavailable — never a weak / fixed key.
    #[must_use]
    pub fn generate() -> Option<Self> {
        let mut seed = [0u8; 32];
        getrandom::getrandom(&mut seed).ok()?;
        Some(Self::from_seed(seed))
    }

    /// The Solana account address (ed25519 public key) of this isolated key — the fee payer /
    /// signer. Safe to display (it is a public key, not the secret).
    #[must_use]
    pub fn pubkey(&self) -> Pubkey {
        let signing = SigningKey::from_bytes(&self.seed);
        Pubkey(signing.verifying_key().to_bytes())
    }

    /// Sign the EXACT serialized Solana legacy-message bytes, returning the 64-byte ed25519
    /// signature. The transient `SigningKey` is derived from the borrowed seed for this call only.
    #[must_use]
    pub fn sign_message(&self, message: &[u8]) -> [u8; 64] {
        let signing = SigningKey::from_bytes(&self.seed);
        signing.sign(message).to_bytes()
    }

    /// The base58 form of the SECRET seed — used ONLY by the dispatch layer to persist the key to a
    /// 0600 owner-controlled file (the secure source). It is NEVER rendered to a surface, logged, or
    /// placed in the model's context (-5). Returned inside a zeroizing string so the secret
    /// copy is overwritten when the persist write completes.
    #[must_use]
    pub fn seed_base58_for_persist(&self) -> Zeroizing<String> {
        Zeroizing::new(crate::solana_codec::base58_encode(self.seed.as_ref()))
    }

    /// Parse a persisted base58 seed back into a 32-byte seed (fail-closed: `None` unless exactly 32
    /// bytes decode). Accepts the 32-byte seed form this module persists.
    #[must_use]
    pub fn parse_base58_seed(s: &str) -> Option<[u8; 32]> {
        let bytes = crate::skew_read::base58_decode(s.trim())?;
        bytes.try_into().ok()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A deterministic seed ⇒ a deterministic pubkey + signature; the signature verifies under the
    /// derived public key; a different message ⇒ a different signature.
    #[test]
    fn sign_is_deterministic_and_verifies() {
        use ed25519_dalek::{Signature, Verifier, VerifyingKey};
        let signer = IsolatedSigner::from_seed([0x42u8; 32]);
        let pk = signer.pubkey();
        let msg = b"the assembled solana legacy message bytes";
        let sig = signer.sign_message(msg);
        // verifies under the public key.
        let vk = VerifyingKey::from_bytes(&pk.0).expect("valid pubkey");
        assert!(
            vk.verify(msg, &Signature::from_bytes(&sig)).is_ok(),
            "signature verifies"
        );
        // deterministic (ed25519 is deterministic): same seed+msg ⇒ same sig.
        assert_eq!(
            IsolatedSigner::from_seed([0x42u8; 32]).sign_message(msg),
            sig
        );
        // a different message ⇒ a different signature.
        assert_ne!(signer.sign_message(b"other message"), sig);
    }

    /// The seed round-trips through base58 persist/parse; a different seed ⇒ a different pubkey.
    #[test]
    fn seed_round_trips_and_keys_are_isolated() {
        let signer = IsolatedSigner::from_seed([0x07u8; 32]);
        let persisted = signer.seed_base58_for_persist();
        let parsed = IsolatedSigner::parse_base58_seed(&persisted).expect("parses");
        assert_eq!(parsed, [0x07u8; 32]);
        // distinct seeds ⇒ distinct (isolated) pubkeys.
        assert_ne!(
            IsolatedSigner::from_seed([1u8; 32]).pubkey(),
            IsolatedSigner::from_seed([2u8; 32]).pubkey()
        );
        // a malformed seed ⇒ None (fail-closed).
        assert!(IsolatedSigner::parse_base58_seed("not-base58-!@#").is_none());
        assert!(IsolatedSigner::parse_base58_seed("11").is_none()); // too short
    }

    /// `generate()` yields a working, unique key (OS RNG present in test env).
    #[test]
    fn generate_yields_a_unique_signing_key() {
        let a = IsolatedSigner::generate().expect("rng");
        let b = IsolatedSigner::generate().expect("rng");
        assert_ne!(a.pubkey(), b.pubkey(), "two generated keys differ");
        // it can sign + verify.
        use ed25519_dalek::{Signature, Verifier, VerifyingKey};
        let sig = a.sign_message(b"x");
        let vk = VerifyingKey::from_bytes(&a.pubkey().0).expect("pk");
        assert!(vk.verify(b"x", &Signature::from_bytes(&sig)).is_ok());
    }
}
