//! `chunk_signature.rs` — the Stage B **chunk-sign domain**
//! and the digest-level signature **verify** surface.
//!
//! A Stage B memory chunk is signed over its [`ChunkDigest32`], never
//! over the raw header or the raw body. This module mints two things:
//!
//! * [`CHUNK_SIGN_DOMAIN`] — the domain string mixed in front of the digest before
//!   it is signed, so a chunk signature lives in its **own** domain, disjoint from
//!   the Sui transaction-intent domain (and from Sui's personal-message intent
//!   domain). The same ed25519 key can sign a Sui transaction *and* a memory chunk
//!   without the two signatures ever being confusable.
//! * [`verify_stage_b_chunk`] — the digest-level verify: given a 64-byte
//!   [`SignatureBytes`] (reused verbatim from Stage A `c-walrus`), the
//!   [`ChunkDigest32`] it claims to cover, and the owner↔key binding
//!   ([`OwnerPublicKeyBinding`]), it reconstructs the domain-separated
//!   preimage and checks the ed25519 signature against the binding's public key.
//!
//! # Design invariant
//!
//! > Keep the chunk signature domain separate from the Sui transaction signature
//! > domain. Even the same key must never confuse the two message domains.
//!
//! The chunk-sign preimage is `CHUNK_SIGN_DOMAIN || digest` (see
//! [`chunk_sign_preimage`]). `CHUNK_SIGN_DOMAIN` starts with the ASCII byte `m`
//! (`0x6d`), whereas every Sui intent message starts with an `IntentScope`
//! discriminant byte — `0x00` for `TransactionData`
//! (`mnemos_g_wallet::SUI_INTENT_PREFIX_TRANSACTION_DATA`) and `0x03` for
//! `PersonalMessage` (`mnemos_g_wallet::SUI_INTENT_PREFIX_PERSONAL_MESSAGE`). A
//! chunk preimage can therefore **never** equal a Sui-intent-prefixed message at
//! byte 0, so a chunk signature can never be replayed as a Sui transaction (or
//! personal-message) signature, and vice versa — exactly the cross-domain barrier
//! `mnemos-g-wallet` pins between the two Sui scopes, extended here
//! to a third, Stage-B-private scope. The domain is also distinct from the digest
//! domains (`CHUNK_DIGEST_DOMAIN` / `CONTENT_HASH_DOMAIN`): hashing and
//! signing occupy separate domains so a digest value can never be mistaken for a
//! signature preimage. The `.testnet` suffix keeps the Stage B chunk-sign domain
//! disjoint from any future mainnet domain by construction.
//!
//! # Scope — verify only; production sign is a later module
//!
//! The chunk schema declares two function signatures over the digest:
//!
//! ```rust,ignore
//! pub fn sign_stage_b_chunk(digest: ChunkDigest32, key: &ScopedSecretKey) -> SignatureBytes;
//! pub fn verify_stage_b_chunk(sig: &SignatureBytes, digest: ChunkDigest32, owner: SuiAddress) -> Result<(), StageBChunkError>;
//! ```
//!
//! This module's reuse is [`ChunkDigest32`] and [`OwnerPublicKeyBinding`] — it
//! deliberately does **not** pull in `mnemos-g-wallet`. The production sign path
//! (which borrows a `ScopedSecretKey`) lives in `g-wallet`
//! (`stage_b_sign_message.rs`, canonical OUT "sign chunk digest"). This module mints
//! the **domain** + the **preimage** (so the signer signs byte-identically to what this
//! module verifies) + the **verify** surface; it does not bring a wallet
//! dependency into `b-memory`. The verify produced here is keyed on the
//! [`OwnerPublicKeyBinding`] rather than the canonical `owner: SuiAddress`: an ed25519
//! check needs the 32-byte public key, and the public-key → `SuiAddress`
//! derivation is deferred to the d-move binding seam
//! ("owner pubkey matches chunk owner"). The binding carries the
//! `SuiAddress` owner *and* the [`SigningPublicKey`] side-by-side, so this verify
//! checks the signature against the public key the binding claims for that owner —
//! the owner⇔key consistency (that the key actually derives to the address) stays
//! the d-move binding's job.
//!
//! # Signature primitive (real ed25519; the digest itself is a Phase 0 placeholder)
//!
//! The signature is a real `ed25519-dalek` signature, identical in shape to the
//! `mnemos-g-wallet` signing surface — one 64-byte
//! [`SignatureBytes`] type flows across the storage (`c-walrus`), signing
//! (`g-wallet`) and verify (`b-memory`) domains. Verification uses
//! `VerifyingKey::verify_strict` (the strict, malleability-rejecting check
//! `g-wallet` already uses). Only the *digest* under the signature is a Phase 0
//! ARX placeholder; the signature over it is
//! genuine and swaps to the real digest at the net-testnet seam with no change to
//! this verify surface.
//!
//! # Reuse (zero re-invention)
//!
//! * [`ChunkDigest32`] — the value signed over (its 32-byte width is the only
//!   variable part of the preimage).
//! * [`OwnerPublicKeyBinding`] / [`SigningPublicKey`] — the verify key carrier.
//! * Stage A's `mnemos-c-walrus::SignatureBytes` — the 64-byte signature type, reused
//!   verbatim (no parallel signature wrapper minted).
//! * `ed25519-dalek` — the verify primitive, already a workspace dependency
//!   (already used by `mnemos-g-wallet`); newly added to `b-memory` for this verify.

use ed25519_dalek::{Signature, VerifyingKey};
use mnemos_c_walrus::SignatureBytes;

use crate::chunk_digest::{ChunkDigest32, StageBChunkError};
use crate::owner::OwnerPublicKeyBinding;

// ===========================================================================
// 1. Chunk-sign domain
// ===========================================================================

/// Domain string mixed in front of a [`ChunkDigest32`] before it is signed (the
/// design rule: keep the chunk signature domain separate from the Sui
/// transaction signature domain). This **is** the Stage B chunk-sign domain.
///
/// Distinct from the digest domains (`CHUNK_DIGEST_DOMAIN` /
/// `CONTENT_HASH_DOMAIN`) so hashing and signing never share a domain, and — by
/// its leading byte `m` (`0x6d`) — disjoint from every Sui intent prefix
/// (`TransactionData` = `0x00`, `PersonalMessage` = `0x03`). The `.testnet`
/// suffix keeps it disjoint from any future mainnet chunk-sign domain.
pub const CHUNK_SIGN_DOMAIN: &[u8] = b"mnemos.stage_b.chunk_sig.v1.testnet";

/// Byte width of the value signed over inside a chunk-sign preimage — the
/// [`ChunkDigest32`] width, taken from the type itself
/// (`size_of::<ChunkDigest32>()` = 32) rather than a second `32` literal, so the
/// preimage cannot drift from the digest if the digest width ever changes.
pub const CHUNK_SIGN_DIGEST_BYTES: usize = core::mem::size_of::<ChunkDigest32>();

/// Total byte length of a chunk-sign preimage: `CHUNK_SIGN_DOMAIN` (35 bytes)
/// followed by the digest (32 bytes) = 67 bytes. A compile-time constant so the
/// signer and this verifier agree on the exact preimage length.
pub const CHUNK_SIGN_PREIMAGE_BYTES: usize = CHUNK_SIGN_DOMAIN.len() + CHUNK_SIGN_DIGEST_BYTES;

/// Compile-time pin: the chunk-sign domain must not collide with the Sui
/// transaction-data intent scope at byte 0 (`0x00`). If a future edit makes the
/// domain start with `0x00`, this fails the build before any test runs — the
/// cross-domain barrier with `mnemos-g-wallet`'s `TransactionData` scope would
/// otherwise silently weaken.
const _CHUNK_SIGN_DOMAIN_NOT_TX_SCOPE: [(); 0 - !(CHUNK_SIGN_DOMAIN[0] != 0) as usize] = [];

/// Compile-time pin: the chunk-sign domain must not collide with the Sui
/// personal-message intent scope at byte 0 (`0x03`).
const _CHUNK_SIGN_DOMAIN_NOT_PMSG_SCOPE: [(); 0 - !(CHUNK_SIGN_DOMAIN[0] != 3) as usize] = [];

// ===========================================================================
// 2. Preimage
// ===========================================================================

/// Build the domain-separated chunk-sign preimage `CHUNK_SIGN_DOMAIN || digest`.
///
/// Allocation-free: the 67-byte preimage is assembled on the caller stack. This
/// is the exact byte sequence the signer signs and
/// [`verify_stage_b_chunk`] verifies, so it is `pub` to keep the two byte-identical
/// at one canonical source.
#[inline]
#[must_use]
pub fn chunk_sign_preimage(digest: &ChunkDigest32) -> [u8; CHUNK_SIGN_PREIMAGE_BYTES] {
    let mut preimage = [0u8; CHUNK_SIGN_PREIMAGE_BYTES];
    // Split at the constant domain length: the left half is exactly
    // `CHUNK_SIGN_DOMAIN.len()` bytes and the right half is exactly
    // `CHUNK_SIGN_DIGEST_BYTES` (= the digest width), so both `copy_from_slice`
    // calls are length-matched by construction and cannot panic.
    let (domain_half, digest_half) = preimage.split_at_mut(CHUNK_SIGN_DOMAIN.len());
    domain_half.copy_from_slice(CHUNK_SIGN_DOMAIN);
    digest_half.copy_from_slice(digest.as_bytes());
    preimage
}

// ===========================================================================
// 3. Verify
// ===========================================================================

/// Verify a Stage B chunk signature over a [`ChunkDigest32`].
///
/// Reconstructs the domain-separated preimage ([`chunk_sign_preimage`]) and checks
/// the 64-byte ed25519 [`SignatureBytes`] against the public key carried by
/// `signer` ([`OwnerPublicKeyBinding::signing_key`]), using the strict,
/// malleability-rejecting `verify_strict`. Returns:
///
/// * `Ok(())` — the signature is a valid ed25519 signature over
///   `CHUNK_SIGN_DOMAIN || digest` under the binding's public key.
/// * `Err(`[`StageBChunkError::SignatureInvalid`]`)` — the public-key bytes are
///   not a valid ed25519 point, **or** the signature does not verify (wrong key,
///   wrong digest, or a signature produced under a different domain). This is the
///   `SignatureInvalid` variant reserved for the verify surface.
///
/// The owner⇔key derivation (that `signer.owner()` actually corresponds to
/// `signer.signing_key()`) is **not** checked here — that is the d-move binding
/// seam's job. This verify answers only "is
/// the signature valid under the public key bound to this owner?".
pub fn verify_stage_b_chunk(
    sig: &SignatureBytes,
    digest: ChunkDigest32,
    signer: &OwnerPublicKeyBinding,
) -> Result<(), StageBChunkError> {
    let signing_key = signer.signing_key();
    let verifying_key = VerifyingKey::from_bytes(signing_key.as_bytes())
        .map_err(|_| StageBChunkError::SignatureInvalid)?;
    let signature = Signature::from_bytes(sig.as_bytes());
    let preimage = chunk_sign_preimage(&digest);
    verifying_key
        .verify_strict(&preimage, &signature)
        .map_err(|_| StageBChunkError::SignatureInvalid)
}

#[cfg(test)]
mod tests {
    // Test helpers prefer direct failure surfaces over `Result`-bubbling;
    // suppress prod-only clippy denies inside this module (the b-memory
    // precedent).
    #![allow(clippy::unwrap_used)]
    #![allow(clippy::expect_used)]
    #![allow(clippy::panic)]

    use super::*;
    use crate::chunk_digest::stage_b_chunk_digest;
    use crate::chunk_schema::{StageBChunkFlags, StageBChunkHeaderV1, StageBChunkView};
    use crate::owner::SigningPublicKey;
    use crate::stage_b_handoff::StageBTraceLink;
    use ed25519_dalek::{Signer, SigningKey};
    use mnemos_c_walrus::PublishPayloadClass;
    use mnemos_c_walrus::codec::{ChunkEnvelopeV1, ChunkKind, MemoryRole};
    use mnemos_d_move::SuiAddress;

    /// Build a minimal valid envelope (mirrors the chunk_digest.rs test
    /// helper): a `content` body, genesis parent, no embedding/sig/provenance.
    fn env(content: &[u8]) -> ChunkEnvelopeV1 {
        ChunkEnvelopeV1 {
            kind: ChunkKind::UserMessage,
            role: MemoryRole::User,
            parent: None,
            content: content.to_vec(),
            embedding: None,
            signature: None,
            provenance: None,
        }
    }

    /// Build a minimal valid header (genesis, no flags, owner = `0x55`*32).
    fn header(content_len: u32) -> StageBChunkHeaderV1 {
        StageBChunkHeaderV1::new(
            ChunkKind::UserMessage,
            MemoryRole::User,
            PublishPayloadClass::SyntheticPublicFixture,
            StageBChunkFlags::None as u8,
            content_len,
            SuiAddress::new([0x55; 32]),
            None,
            StageBTraceLink::new(89, 89, 0),
        )
        .expect("known header valid")
    }

    /// Produce a real ChunkDigest32 from a minimal in-cap chunk.
    fn digest_of(content: &[u8]) -> ChunkDigest32 {
        let e = env(content);
        let h = header(content.len() as u32);
        let view = StageBChunkView::new(h, &e).expect("within cap");
        stage_b_chunk_digest(&view).expect("digest ok")
    }

    /// An (owner, signing-key, ed25519 SigningKey) fixture from a fixed seed.
    fn keyed(seed: [u8; 32], owner_byte: u8) -> (SigningKey, OwnerPublicKeyBinding) {
        let signing = SigningKey::from_bytes(&seed);
        let pubkey = signing.verifying_key().to_bytes();
        let signing_public = SigningPublicKey::from_bytes(&pubkey).expect("32-byte pubkey");
        let owner = SuiAddress::new([owner_byte; 32]);
        (signing, OwnerPublicKeyBinding::new(owner, signing_public))
    }

    /// Sign the chunk-sign preimage with a raw ed25519 key (the test stands in
    /// for the wallet signer; the production sign path is deferred).
    fn sign(signing: &SigningKey, digest: &ChunkDigest32) -> SignatureBytes {
        let preimage = chunk_sign_preimage(digest);
        SignatureBytes(signing.sign(&preimage).to_bytes())
    }

    /// `b1_8_signature_length_64` — the signature width is exactly 64 bytes (the
    /// reused Stage A `SignatureBytes` shape), and the preimage is the pinned
    /// 67 = 35 (domain) + 32 (digest) bytes.
    #[test]
    fn b1_8_signature_length_64() {
        assert_eq!(core::mem::size_of::<SignatureBytes>(), 64);
        assert_eq!(CHUNK_SIGN_PREIMAGE_BYTES, 67);
        assert_eq!(CHUNK_SIGN_DOMAIN.len(), 35);
        assert_eq!(CHUNK_SIGN_DIGEST_BYTES, 32);

        let digest = digest_of(b"hello");
        let (signing, _binding) = keyed([0x11; 32], 0x55);
        let sig = sign(&signing, &digest);
        assert_eq!(sig.as_bytes().len(), 64);
    }

    /// `b1_8_valid_signature_verifies` — a signature over `CHUNK_SIGN_DOMAIN ||
    /// digest` verifies under the binding's public key (positive case).
    #[test]
    fn b1_8_valid_signature_verifies() {
        let digest = digest_of(b"valid chunk body");
        let (signing, binding) = keyed([0x22; 32], 0x55);
        let sig = sign(&signing, &digest);
        assert!(
            verify_stage_b_chunk(&sig, digest, &binding).is_ok(),
            "valid chunk-domain signature must verify",
        );
    }

    /// `b1_8_wrong_domain_fails` — a signature produced under a DIFFERENT domain
    /// (here the digest domain, and separately the Sui personal-message
    /// intent prefix) must FAIL chunk verify. Proves `CHUNK_SIGN_DOMAIN` is
    /// genuinely mixed into the signed bytes, not advisory.
    #[test]
    fn b1_8_wrong_domain_fails() {
        let digest = digest_of(b"domain separation body");
        let (signing, binding) = keyed([0x33; 32], 0x55);

        // (a) sign over `CHUNK_DIGEST_DOMAIN || digest` (the hashing
        //     domain) instead of the chunk-SIGN domain.
        let mut wrong_a = Vec::new();
        wrong_a.extend_from_slice(crate::chunk_digest::CHUNK_DIGEST_DOMAIN);
        wrong_a.extend_from_slice(digest.as_bytes());
        let sig_a = SignatureBytes(signing.sign(&wrong_a).to_bytes());
        assert_eq!(
            verify_stage_b_chunk(&sig_a, digest, &binding),
            Err(StageBChunkError::SignatureInvalid),
            "signature under the digest domain must NOT verify as a chunk signature",
        );

        // (b) sign over a payload prefixed with the Sui PersonalMessage intent
        //     scope (`[3,0,0]`) — the cross-domain replay attempt.
        let mut wrong_b = Vec::new();
        wrong_b.extend_from_slice(&[3u8, 0, 0]);
        wrong_b.extend_from_slice(digest.as_bytes());
        let sig_b = SignatureBytes(signing.sign(&wrong_b).to_bytes());
        assert_eq!(
            verify_stage_b_chunk(&sig_b, digest, &binding),
            Err(StageBChunkError::SignatureInvalid),
            "Sui personal-message-scoped signature must NOT verify as a chunk signature",
        );
    }

    /// `b1_8_wrong_owner_fails` — a signature made with owner A's key must FAIL
    /// verify under owner B's binding (a different public key). The chunk-sign
    /// domain and digest are identical; only the owner↔key binding differs.
    #[test]
    fn b1_8_wrong_owner_fails() {
        let digest = digest_of(b"owner mismatch body");
        let (signing_a, _binding_a) = keyed([0x44; 32], 0xAA);
        let (_signing_b, binding_b) = keyed([0x99; 32], 0xBB);

        // signed by A, verified against B's binding
        let sig = sign(&signing_a, &digest);
        assert_eq!(
            verify_stage_b_chunk(&sig, digest, &binding_b),
            Err(StageBChunkError::SignatureInvalid),
            "signature under owner A's key must NOT verify under owner B's binding",
        );
    }

    /// `b1_8_wrong_digest_fails` — a valid signature over digest X must FAIL
    /// verify when presented against a different digest Y (defense in depth: the
    /// digest is bound into the preimage, so tampering moves the verified bytes).
    #[test]
    fn b1_8_wrong_digest_fails() {
        let digest_x = digest_of(b"body X");
        let digest_y = digest_of(b"body Y");
        assert_ne!(
            digest_x.as_bytes(),
            digest_y.as_bytes(),
            "distinct bodies must yield distinct digests",
        );
        let (signing, binding) = keyed([0x55; 32], 0x55);
        let sig = sign(&signing, &digest_x);
        assert!(verify_stage_b_chunk(&sig, digest_x, &binding).is_ok());
        assert_eq!(
            verify_stage_b_chunk(&sig, digest_y, &binding),
            Err(StageBChunkError::SignatureInvalid),
            "a signature over digest X must not verify against digest Y",
        );
    }

    /// `b1_8_domain_distinct_and_disjoint` — the chunk-sign domain differs from
    /// both digest domains and is disjoint from both Sui intent scopes
    /// at byte 0 (the runtime witness of the compile-time pins).
    #[test]
    fn b1_8_domain_distinct_and_disjoint() {
        assert_ne!(CHUNK_SIGN_DOMAIN, crate::chunk_digest::CHUNK_DIGEST_DOMAIN);
        assert_ne!(CHUNK_SIGN_DOMAIN, crate::chunk_digest::CONTENT_HASH_DOMAIN);
        // byte 0 is ASCII 'm' (0x6d) — neither Sui intent scope discriminant.
        assert_eq!(CHUNK_SIGN_DOMAIN[0], 0x6d);
        assert_ne!(
            CHUNK_SIGN_DOMAIN[0], 0,
            "must not collide with TransactionData scope"
        );
        assert_ne!(
            CHUNK_SIGN_DOMAIN[0], 3,
            "must not collide with PersonalMessage scope"
        );
    }
}
