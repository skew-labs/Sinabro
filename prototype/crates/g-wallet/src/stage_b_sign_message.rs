//! Stage B sign personal chunk message.
//!
//! Canonical output: sign a Stage B chunk
//! digest under the chunk-sign domain, producing a 64-byte ed25519
//! [`SignatureBytes`] that the reused
//! [`verify_stage_b_chunk`](mnemos_b_memory::chunk_signature::verify_stage_b_chunk)
//! accepts. This is the *sign* half of the chunk-signature seam the
//! verifier doc reserved "the production sign path" for.
//!
//! # Invariants
//!
//! * **Chunk signing and Sui tx signing are separate domains.** The preimage
//!   is the reused [`chunk_sign_preimage`] — `CHUNK_SIGN_DOMAIN ‖ digest`,
//!   where `CHUNK_SIGN_DOMAIN` (`b"mnemos.stage_b.chunk_sig.v1.testnet"`)
//!   begins with byte `0x6d` (`m`), disjoint from every Sui intent prefix
//!   (`TransactionData = 0x00`, `PersonalMessage = 0x03`). A signature
//!   produced here therefore cannot verify under the Sui transaction-data or
//!   personal-message scope, and vice versa — the domain separation is
//!   structural, not a runtime tag.
//! * **The preimage is byte-identical to the verifier's.** Both the signer
//!   (this atom) and [`verify_stage_b_chunk`] (#89) build the preimage from
//!   the one canonical [`chunk_sign_preimage`] helper, so they cannot drift.
//! * **No secret escapes.** The 32-byte seed is borrowed from the caller's
//!   [`ScopedSecretKey`] for the duration of this call only; `SigningKey::from_bytes`
//!   copies it into ed25519-dalek's internal state, which zeroizes on drop
//!   (ed25519-dalek 2.x default), and the caller's secret zeroizes when its
//!   `Drop` runs.
//!
//! # Reuse map (atom contract)
//!
//! * **reuse: #89** — [`chunk_sign_preimage`] / `verify_stage_b_chunk` /
//!   `CHUNK_SIGN_DOMAIN` (`b-memory/src/chunk_signature.rs`).
//! * **reuse: #148** — the [`ScopedSecretKey`] whose seed signs the preimage.

use crate::keystore::ScopedSecretKey;
use ed25519_dalek::{Signature, Signer, SigningKey};
use mnemos_b_memory::chunk_digest::ChunkDigest32;
use mnemos_b_memory::chunk_signature::chunk_sign_preimage;
use mnemos_c_walrus::SignatureBytes;

/// Sign a Stage B [`ChunkDigest32`] under the chunk-sign domain with
/// the borrowed ed25519 secret seed.
///
/// Builds the domain-separated preimage (`CHUNK_SIGN_DOMAIN ‖ digest`) via the
/// reused [`chunk_sign_preimage`] and returns the raw 64-byte ed25519
/// signature. The returned [`SignatureBytes`] verifies under
/// [`verify_stage_b_chunk`](mnemos_b_memory::chunk_signature::verify_stage_b_chunk)
/// when presented with the owner binding for this key, and FAILS verification
/// under any Sui intent scope (the domain prefix is mixed into the digest).
///
/// Total over the digest — returns [`SignatureBytes`] directly, not a
/// `Result`: the ed25519 signer accepts any preimage and the digest is
/// already a validated 32-byte commitment.
#[must_use]
pub fn sign_chunk_digest(key: &ScopedSecretKey, digest: ChunkDigest32) -> SignatureBytes {
    let signing = SigningKey::from_bytes(key.as_bytes());
    // The preimage is the one canonical chunk-sign byte sequence (#89), so
    // signer and verifier cannot diverge on the bytes under signature.
    let preimage = chunk_sign_preimage(&digest);
    let signature: Signature = signing.sign(&preimage);
    SignatureBytes(signature.to_bytes())
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    #![allow(clippy::expect_used)]
    #![allow(clippy::panic)]

    use super::*;
    use crate::stage_b_address::owner_binding;
    use ed25519_dalek::SigningKey;
    use mnemos_b_memory::chunk_digest::stage_b_chunk_digest;
    use mnemos_b_memory::chunk_schema::{StageBChunkFlags, StageBChunkHeaderV1, StageBChunkView};
    use mnemos_b_memory::chunk_signature::verify_stage_b_chunk;
    use mnemos_b_memory::owner::SigningPublicKey;
    use mnemos_b_memory::stage_b_handoff::StageBTraceLink;
    use mnemos_c_walrus::PublishPayloadClass;
    use mnemos_c_walrus::codec::{ChunkEnvelopeV1, ChunkKind, MemoryRole};
    use mnemos_d_move::types::SuiAddress;

    /// Fixed 32-byte ed25519 seed for the deterministic test vector.
    const TEST_SEED: [u8; 32] = [
        0x24, 0x68, 0xAC, 0xF0, 0x13, 0x57, 0x9B, 0xDF, //
        0x02, 0x46, 0x8A, 0xCE, 0x11, 0x55, 0x99, 0xDD, //
        0x31, 0x75, 0xB9, 0xFD, 0x20, 0x64, 0xA8, 0xEC, //
        0x42, 0x86, 0xCA, 0x0E, 0x53, 0x97, 0xDB, 0x1F, //
    ];

    /// Produce a real [`ChunkDigest32`] from a minimal in-cap chunk (mirrors
    /// the reused chunk-digest test helper — a `content` body, genesis parent, no
    /// embedding/sig/provenance).
    fn digest_of(content: &[u8]) -> ChunkDigest32 {
        let envelope = ChunkEnvelopeV1 {
            kind: ChunkKind::UserMessage,
            role: MemoryRole::User,
            parent: None,
            content: content.to_vec(),
            embedding: None,
            signature: None,
            provenance: None,
        };
        let header = StageBChunkHeaderV1::new(
            ChunkKind::UserMessage,
            MemoryRole::User,
            PublishPayloadClass::SyntheticPublicFixture,
            StageBChunkFlags::None as u8,
            content.len() as u32,
            SuiAddress::new([0x55; 32]),
            None,
            StageBTraceLink::new(150, 150, 0),
        )
        .expect("known header valid");
        let view = StageBChunkView::new(header, &envelope).expect("within cap");
        stage_b_chunk_digest(&view).expect("digest ok")
    }

    /// The owner binding for `TEST_SEED`'s key: derive the ed25519 public key,
    /// then pair it with its derived testnet address.
    fn binding_for_seed() -> mnemos_b_memory::owner::OwnerPublicKeyBinding {
        let signing = SigningKey::from_bytes(&TEST_SEED);
        let pubkey_bytes = signing.verifying_key().to_bytes();
        let pubkey = SigningPublicKey::from_bytes(&pubkey_bytes).expect("32-byte key");
        owner_binding(&pubkey)
    }

    /// `b4_4_signs_chunk_vector` — a signature produced over a real chunk
    /// digest verifies under the #89 verifier with the signer's owner
    /// binding, and is exactly 64 bytes.
    #[test]
    fn b4_4_signs_chunk_vector() {
        let key = ScopedSecretKey::from_seed_for_test(TEST_SEED);
        let digest = digest_of(b"stage-b chunk body for signing");

        let sig = sign_chunk_digest(&key, digest);
        assert_eq!(sig.as_bytes().len(), 64, "ed25519 signature is 64 bytes");

        let binding = binding_for_seed();
        verify_stage_b_chunk(&sig, digest, &binding)
            .expect("signature must verify under the #89 chunk-sign verifier");
    }

    /// `b4_4_wrong_domain_fails_verify` — a signature produced under the Sui
    /// transaction-data domain (`sign_move_tx`) over the SAME digest
    /// bytes does NOT verify under the chunk-sign domain, proving the
    /// `CHUNK_SIGN_DOMAIN` prefix is actually mixed into the digest.
    #[test]
    fn b4_4_wrong_domain_fails_verify() {
        let key = ScopedSecretKey::from_seed_for_test(TEST_SEED);
        let digest = digest_of(b"stage-b chunk body for signing");
        let binding = binding_for_seed();

        // Sign the raw digest bytes under the Sui TransactionData scope, NOT
        // the chunk-sign domain.
        let wrong_domain_sig = crate::sign_tx::sign_move_tx(&key, digest.as_bytes());
        assert!(
            verify_stage_b_chunk(&wrong_domain_sig, digest, &binding).is_err(),
            "a Sui-tx-domain signature must NOT verify under the chunk-sign domain",
        );

        // The correct-domain signature for the same digest DOES verify — the
        // only difference is the domain, so this pins domain separation as the
        // cause of the rejection above.
        let chunk_sig = sign_chunk_digest(&key, digest);
        verify_stage_b_chunk(&chunk_sig, digest, &binding)
            .expect("correct-domain signature must verify");
    }

    /// `b4_4_wrong_key_fails_verify` — a signature from one key does not
    /// verify under a different key's binding (sanity that the verifier binds
    /// to the public key, not just the digest).
    #[test]
    fn b4_4_wrong_key_fails_verify() {
        let key = ScopedSecretKey::from_seed_for_test(TEST_SEED);
        let digest = digest_of(b"body");
        let sig = sign_chunk_digest(&key, digest);

        // A different seed ⇒ a different binding.
        let other_signing = SigningKey::from_bytes(&[0x07u8; 32]);
        let other_pubkey = other_signing.verifying_key().to_bytes();
        let other_binding =
            owner_binding(&SigningPublicKey::from_bytes(&other_pubkey).expect("32 bytes"));
        assert!(
            verify_stage_b_chunk(&sig, digest, &other_binding).is_err(),
            "signature must not verify under a different key's binding",
        );
    }
}
