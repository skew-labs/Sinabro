//! `signed_chunk.rs` (atom #90 · B.1.9) — the Stage B **signed chunk
//! constructor**.
//!
//! This module mints the §4.1 [`StageBSignedChunkV1`] value carrier and the one
//! constructor that can mint it: [`StageBSignedChunkV1::new`]. A signed chunk is
//! the unit a memory owner publishes to Walrus and anchors on Sui — a Stage A
//! [`ChunkEnvelopeV1`] body, the domain-separated [`ChunkDigest32`] that commits
//! it (atom #86), the 64-byte ed25519 [`SignatureBytes`] over that digest, and the
//! per-action [`StageBTraceLink`] (atom #81).
//!
//! # Madness invariant (`MNEMOS_STAGE_B_ATOM_PLAN.md` atom #90)
//!
//! > constructor는 digest→sign→verify를 같은 경로로 묶고, content hash만 signed
//! > chunk에 보관한다.
//!
//! The constructor binds the **digest → verify** link in one path: it recomputes
//! the digest from the borrowed view (atom #86 [`stage_b_chunk_digest`]) and then
//! requires the supplied signature to verify over *that* freshly recomputed digest
//! (atom #89 [`verify_stage_b_chunk`]) before a [`StageBSignedChunkV1`] can exist.
//! A signed chunk whose signature does not verify over its own digest is therefore
//! **unrepresentable** — there is no other way to build the type with a valid
//! `digest`/`signature` pair (the struct fields are `pub` per §4.1, but a raw
//! literal would have to forge a verifying signature to be meaningful, and the
//! canonical mint path refuses anything that does not verify).
//!
//! ## Where the `sign` link lives (scope of atom #90)
//!
//! §4.1 declares the production signer separately:
//!
//! ```rust,ignore
//! pub fn sign_stage_b_chunk(digest: ChunkDigest32, key: &ScopedSecretKey) -> SignatureBytes;
//! ```
//!
//! That signer borrows a `ScopedSecretKey` and therefore lives in
//! `mnemos-g-wallet` (atom #150) — exactly the dependency atom #89 deliberately
//! kept out of `b-memory`, and atom #90's reuse field (`#85-#89`) keeps out too.
//! So the `sign` link is the **caller's** half of the chain: the caller signs the
//! atom #89 [`chunk_sign_preimage`](crate::chunk_signature::chunk_sign_preimage)
//! (with the wallet at #150, or a raw ed25519 key in tests, standing in for it)
//! and hands the resulting signature to [`StageBSignedChunkV1::new`], which closes
//! the chain by recomputing the digest and verifying. This is the strongest
//! binding atom #90 can make without pulling a wallet dependency into the memory
//! crate, and it is faithful to the spec's "same path": no signed chunk exists
//! whose signature was not checked against its own recomputed digest.
//!
//! ## "content hash만 보관" — what the signed chunk stores
//!
//! §4.1 fixes the four fields verbatim: `{ envelope, digest, signature, trace }`.
//! The `digest` commits the body only through its content **hash** (atom #86
//! hashes the body alone into a [`ContentHash32`](crate::ContentHash32) and binds
//! that hash, never the raw body, into the [`ChunkDigest32`]) — so the *signed /
//! committed* surface carries only the content hash, not a second raw copy of the
//! body. The body itself is kept once, in the `envelope`, because the canonical
//! type is the unit that flows into the BCS encode (atom #91), the verified-blob
//! decode (atom #92) and the replay re-derivation (atom #101), all of which need
//! the body to recompute and compare the digest. The signed chunk therefore stores
//! the body exactly once and the *commitment* over it as a hash, never duplicating
//! raw content into the digest/signature path.
//!
//! # Reuse (재발명 0)
//!
//! * #85 [`StageBChunkView`] — the borrowed lens the constructor reads (header by
//!   value + envelope by shared borrow); its `header.trace` is the stamp stored.
//! * #86 [`stage_b_chunk_digest`] / [`ChunkDigest32`] / [`StageBChunkError`] — the
//!   digest recompute and the shared error surface (no new variant minted; the
//!   §4.1 set is frozen `#[non_exhaustive]`).
//! * #89 [`verify_stage_b_chunk`] — the digest-level ed25519 verify.
//! * A `mnemos-c-walrus::SignatureBytes` — the 64-byte signature, reused verbatim.
//! * #81 [`StageBTraceLink`] — the per-action stamp, copied from the header.
//!
//! No new dependency, no new wire format, no new error variant, no signing key.

use mnemos_c_walrus::SignatureBytes;
use mnemos_c_walrus::codec::ChunkEnvelopeV1;

use crate::chunk_digest::{ChunkDigest32, StageBChunkError, stage_b_chunk_digest};
use crate::chunk_schema::StageBChunkView;
use crate::chunk_signature::verify_stage_b_chunk;
use crate::owner::OwnerPublicKeyBinding;
use crate::stage_b_handoff::StageBTraceLink;

/// §4.1 signed chunk — a memory owner's publishable unit.
///
/// The four fields are §4.1 verbatim. A value of this type is only meaningful when
/// built through [`StageBSignedChunkV1::new`], which guarantees the `signature`
/// verifies over the `digest` and the `digest` commits the `envelope` body
/// (through the body's content hash, atom #86). The fields are `pub` to match the
/// §4.1 declaration and to let the BCS encode (atom #91) / replay (atom #101)
/// read them; the canonical mint path is [`new`](Self::new).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StageBSignedChunkV1 {
    /// The Stage A chunk body + wire-level fields, owned. The body is kept once
    /// here (the digest commits it only as a content hash — see the module docs).
    pub envelope: ChunkEnvelopeV1,
    /// The atom #86 domain-separated digest that commits `envelope` (header +
    /// content hash). The signature is over this value.
    pub digest: ChunkDigest32,
    /// The 64-byte ed25519 signature over `CHUNK_SIGN_DOMAIN || digest` (atom #89
    /// preimage). Verified against the owner's public key at construction.
    pub signature: SignatureBytes,
    /// The per-action replay/evidence stamp (atom #81), copied from the chunk
    /// header so the signed chunk and its header agree on provenance.
    pub trace: StageBTraceLink,
}

impl StageBSignedChunkV1 {
    /// Mint a signed chunk, binding digest → verify in one path.
    ///
    /// 1. Recompute the digest from the borrowed `view` (atom #86
    ///    [`stage_b_chunk_digest`]). Propagates
    ///    [`StageBChunkError::ContentTooLarge`] if the borrowed body exceeds the
    ///    Stage B content cap (the digest's own fail-closed re-check — defense in
    ///    depth against a raw view literal that bypassed
    ///    [`StageBChunkView::new`]).
    /// 2. Verify `signature` over *that* recomputed digest under the owner's public
    ///    key (atom #89 [`verify_stage_b_chunk`]). Returns
    ///    [`StageBChunkError::SignatureInvalid`] on any mismatch — a tampered body
    ///    (whose recomputed digest no longer matches what was signed), a wrong
    ///    owner key, a wrong domain, or a malformed signature.
    /// 3. Only on success, construct the signed chunk: the `envelope` is cloned
    ///    out of the borrow, `digest` is the recomputed value (never a
    ///    caller-supplied one), and `trace` is copied from `view.header.trace`.
    ///
    /// Because the stored `digest` is always the freshly recomputed one and the
    /// signature is checked against it, the `(digest, signature)` pair in the
    /// returned value is internally consistent by construction.
    pub fn new(
        view: &StageBChunkView<'_>,
        signature: SignatureBytes,
        signer: &OwnerPublicKeyBinding,
    ) -> Result<Self, StageBChunkError> {
        // (1) digest: recompute from the borrowed view, never trust a passed-in
        //     digest. Fail-closed cap re-check lives inside `stage_b_chunk_digest`.
        let digest = stage_b_chunk_digest(view)?;
        // (2) verify: the supplied signature must cover this exact digest under the
        //     binding's public key, or no chunk is minted.
        verify_stage_b_chunk(&signature, digest, signer)?;
        // (3) mint: body owned once; digest is the recomputed value; trace copied
        //     from the header so the signed chunk carries the same provenance stamp.
        Ok(Self {
            envelope: view.envelope.clone(),
            digest,
            signature,
            trace: view.header.trace,
        })
    }

    /// Re-verify the stored signature against the stored digest under `signer`.
    ///
    /// Reuses the atom #89 [`verify_stage_b_chunk`] over the already-committed
    /// `(signature, digest)` pair. Useful on the replay / fetched-blob path (atom
    /// #92 / #101), where a signed chunk arrives already built and must be checked
    /// before it is trusted. Returns [`StageBChunkError::SignatureInvalid`] if the
    /// signature does not verify under the supplied owner binding.
    ///
    /// This checks the signature against the **stored** digest; it does not
    /// recompute the digest from `envelope` (that needs the chunk header, which the
    /// signed chunk does not carry — digest recompute belongs to the constructor
    /// and to the replay seam that holds the header).
    #[inline]
    pub fn verify(&self, signer: &OwnerPublicKeyBinding) -> Result<(), StageBChunkError> {
        verify_stage_b_chunk(&self.signature, self.digest, signer)
    }

    /// Borrow the committed digest.
    #[inline]
    pub const fn digest(&self) -> &ChunkDigest32 {
        &self.digest
    }

    /// Borrow the signature.
    #[inline]
    pub const fn signature(&self) -> &SignatureBytes {
        &self.signature
    }

    /// Borrow the trace stamp.
    #[inline]
    pub const fn trace(&self) -> &StageBTraceLink {
        &self.trace
    }
}

#[cfg(test)]
mod tests {
    // Test helpers prefer direct failure surfaces over `Result`-bubbling;
    // suppress prod-only clippy denies inside this module (b-memory #86/#88/#89
    // precedent).
    #![allow(clippy::unwrap_used)]
    #![allow(clippy::expect_used)]
    #![allow(clippy::panic)]

    use super::*;
    use crate::chunk_schema::{StageBChunkFlags, StageBChunkHeaderV1};
    use crate::chunk_signature::chunk_sign_preimage;
    use crate::owner::SigningPublicKey;
    use ed25519_dalek::{Signer, SigningKey};
    use mnemos_c_walrus::PublishPayloadClass;
    use mnemos_c_walrus::codec::{ChunkKind, MemoryRole};
    use mnemos_d_move::SuiAddress;

    /// Build a minimal valid envelope (mirrors the chunk_signature.rs #89 test
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

    /// Build a minimal valid header (genesis, no flags, owner = `0x55`*32, trace
    /// stamped to atom #90).
    fn header(content_len: u32) -> StageBChunkHeaderV1 {
        StageBChunkHeaderV1::new(
            ChunkKind::UserMessage,
            MemoryRole::User,
            PublishPayloadClass::SyntheticPublicFixture,
            StageBChunkFlags::None as u8,
            content_len,
            SuiAddress::new([0x55; 32]),
            None,
            StageBTraceLink::new(90, 90, 0),
        )
        .expect("known header valid")
    }

    /// An (ed25519 SigningKey, owner↔key binding) fixture from a fixed seed.
    fn keyed(seed: [u8; 32], owner_byte: u8) -> (SigningKey, OwnerPublicKeyBinding) {
        let signing = SigningKey::from_bytes(&seed);
        let pubkey = signing.verifying_key().to_bytes();
        let signing_public = SigningPublicKey::from_bytes(&pubkey).expect("32-byte pubkey");
        let owner = SuiAddress::new([owner_byte; 32]);
        (signing, OwnerPublicKeyBinding::new(owner, signing_public))
    }

    /// Sign the chunk-sign preimage over `digest` with a raw ed25519 key (the test
    /// stands in for the atom #150 wallet signer — production sign is deferred).
    fn sign(signing: &SigningKey, digest: &ChunkDigest32) -> SignatureBytes {
        let preimage = chunk_sign_preimage(digest);
        SignatureBytes(signing.sign(&preimage).to_bytes())
    }

    /// Compute the digest of a content body through a genesis view.
    fn digest_of(content: &[u8]) -> ChunkDigest32 {
        let e = env(content);
        let h = header(content.len() as u32);
        let view = StageBChunkView::new(h, &e).expect("within cap");
        stage_b_chunk_digest(&view).expect("digest ok")
    }

    /// `b1_9_construct_valid_signed_chunk` — a body signed under the owner's key
    /// over its digest constructs successfully; the stored fields match
    /// (recomputed digest, copied trace, owned body, 64-byte signature) and the
    /// minted chunk re-verifies under the same binding.
    #[test]
    fn b1_9_construct_valid_signed_chunk() {
        let body = b"valid signed chunk body";
        let e = env(body);
        let h = header(body.len() as u32);
        let view = StageBChunkView::new(h, &e).expect("within cap");
        let digest = stage_b_chunk_digest(&view).expect("digest ok");

        let (signing, binding) = keyed([0x22; 32], 0x55);
        let sig = sign(&signing, &digest);

        let signed = StageBSignedChunkV1::new(&view, sig, &binding).expect("valid chunk mints");

        // stored digest is the recomputed value
        assert_eq!(
            signed.digest(),
            &digest,
            "stored digest is the recomputed one"
        );
        // trace copied from the header
        assert_eq!(signed.trace(), &h.trace, "trace copied from header");
        // body owned verbatim (kept once)
        assert_eq!(signed.envelope, e, "envelope owned verbatim");
        // signature reused verbatim, 64 bytes
        assert_eq!(signed.signature(), &sig);
        assert_eq!(signed.signature().as_bytes().len(), 64);
        // and the minted chunk re-verifies under the same owner binding
        assert!(signed.verify(&binding).is_ok(), "minted chunk re-verifies");
    }

    /// `b1_9_tampered_content_fails_verify` — a signature made over body X must
    /// FAIL to mint a signed chunk over a tampered body Y: the constructor
    /// recomputes the digest from Y, which no longer matches the digest X was
    /// signed over, so verify rejects. Proves the digest is recomputed in the mint
    /// path (not trusted from the signer).
    #[test]
    fn b1_9_tampered_content_fails_verify() {
        let (signing, binding) = keyed([0x33; 32], 0x55);

        // sign over body X's digest
        let digest_x = digest_of(b"original body X");
        let sig = sign(&signing, &digest_x);

        // present body Y (tampered) with X's signature
        let e_y = env(b"tampered body Y");
        let h_y = header((b"tampered body Y" as &[u8]).len() as u32);
        let view_y = StageBChunkView::new(h_y, &e_y).expect("within cap");

        assert_eq!(
            StageBSignedChunkV1::new(&view_y, sig, &binding),
            Err(StageBChunkError::SignatureInvalid),
            "a signature over body X must not mint a signed chunk over tampered body Y",
        );
    }

    /// `b1_9_owner_mismatch_fails` — a signature made with owner A's key must FAIL
    /// to mint under owner B's binding. The body and digest are identical; only the
    /// owner↔key binding differs (atom #89 `wrong_owner` semantics, at the
    /// constructor seam).
    #[test]
    fn b1_9_owner_mismatch_fails() {
        let body = b"owner mismatch body";
        let e = env(body);
        let h = header(body.len() as u32);
        let view = StageBChunkView::new(h, &e).expect("within cap");
        let digest = stage_b_chunk_digest(&view).expect("digest ok");

        let (signing_a, _binding_a) = keyed([0x44; 32], 0xAA);
        let (_signing_b, binding_b) = keyed([0x99; 32], 0xBB);

        // signed by A, minted against B's binding
        let sig = sign(&signing_a, &digest);
        assert_eq!(
            StageBSignedChunkV1::new(&view, sig, &binding_b),
            Err(StageBChunkError::SignatureInvalid),
            "a signature under owner A's key must not mint under owner B's binding",
        );
    }

    /// `b1_9_digest_binds_content` — distinct bodies yield distinct stored digests,
    /// and a chunk minted over one body never re-verifies against the digest of a
    /// different body. Defense in depth for the schema-lock aspect of
    /// G-B-CHUNK-SCHEMA (the committed digest tracks the body).
    #[test]
    fn b1_9_digest_binds_content() {
        let (signing, binding) = keyed([0x66; 32], 0x55);

        let e1 = env(b"body one");
        let h1 = header((b"body one" as &[u8]).len() as u32);
        let v1 = StageBChunkView::new(h1, &e1).expect("within cap");
        let d1 = stage_b_chunk_digest(&v1).expect("digest ok");
        let s1 = StageBSignedChunkV1::new(&v1, sign(&signing, &d1), &binding).expect("mints");

        let e2 = env(b"body two");
        let h2 = header((b"body two" as &[u8]).len() as u32);
        let v2 = StageBChunkView::new(h2, &e2).expect("within cap");
        let d2 = stage_b_chunk_digest(&v2).expect("digest ok");
        let s2 = StageBSignedChunkV1::new(&v2, sign(&signing, &d2), &binding).expect("mints");

        assert_ne!(
            s1.digest(),
            s2.digest(),
            "distinct bodies → distinct digests"
        );
        assert_ne!(s1.envelope, s2.envelope, "distinct bodies kept distinct");
    }

    /// `b1_9_verify_roundtrip_independent_binding` — a minted chunk re-verifies
    /// under its own binding but not under a foreign one, exercising the standalone
    /// [`StageBSignedChunkV1::verify`] replay-path surface.
    #[test]
    fn b1_9_verify_roundtrip_independent_binding() {
        let body = b"roundtrip body";
        let e = env(body);
        let h = header(body.len() as u32);
        let view = StageBChunkView::new(h, &e).expect("within cap");
        let digest = stage_b_chunk_digest(&view).expect("digest ok");

        let (signing, binding) = keyed([0x77; 32], 0x55);
        let (_other_signing, other_binding) = keyed([0x88; 32], 0xCC);

        let signed = StageBSignedChunkV1::new(&view, sign(&signing, &digest), &binding)
            .expect("mints under own binding");

        assert!(
            signed.verify(&binding).is_ok(),
            "re-verifies under own binding"
        );
        assert_eq!(
            signed.verify(&other_binding),
            Err(StageBChunkError::SignatureInvalid),
            "must not re-verify under a foreign owner binding",
        );
    }
}
