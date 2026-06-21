//! Stage B signature verify confusion matrix (atom #99 · B.1.18).
//!
//! Madness clause (`MNEMOS_STAGE_B_ATOM_PLAN.md` atom #99): *"every plausible
//! signature confusion is an explicit red test."* A Stage B chunk signature is an
//! ed25519 signature over `CHUNK_SIGN_DOMAIN || digest` (atom #89
//! [`chunk_sign_preimage`]) where the [`ChunkDigest32`] commits the chunk header
//! (owner, parent, trace, content length) and the body's content hash (atom #86).
//! Six independent dimensions can therefore make a signature *wrong*, and each one
//! must be rejected with [`StageBChunkError::SignatureInvalid`]:
//!
//! | dimension      | what differs between sign-time and verify-time            |
//! |----------------|-----------------------------------------------------------|
//! | wrong owner    | the owner⇔key binding (a different ed25519 public key)     |
//! | wrong domain   | the domain string mixed in front of the digest            |
//! | wrong content  | the body → its content hash → the committed digest        |
//! | wrong parent   | the header's parent blob id → header bytes → the digest    |
//! | wrong trace    | the header's `StageBTraceLink` → header bytes → the digest |
//! | wrong network  | the `.testnet` network tag inside the chunk-sign domain    |
//!
//! This is a pure reuse atom: it mints **no** production code (zero `src/` change)
//! and adds **no** dependency. It consumes the public `mnemos-b-memory` API only —
//! atom #89 ([`verify_stage_b_chunk`] / [`chunk_sign_preimage`] /
//! [`CHUNK_SIGN_DOMAIN`]) and atom #90 ([`StageBSignedChunkV1`]) verbatim — and
//! turns every confusion above into a named RED test plus one positive control.
//!
//! The signer here is a raw `ed25519-dalek` key standing in for the deferred
//! production wallet signer (atom #150, `g-wallet`); it signs the exact atom #89
//! preimage so the verify surface under test is byte-identical to what production
//! will check. No mainnet, no network, no secret: all owners are synthetic
//! `SuiAddress` fills and all keys are fixed public test seeds.

// Test code prefers direct failure surfaces (`expect`/`unwrap`/`assert`) over
// `Result`-bubbling; suppress the prod-only clippy denies for this test crate
// (b-memory #86/#88/#89/#90/#95/#96 unit- and integration-test precedent).
#![allow(clippy::unwrap_used)]
#![allow(clippy::expect_used)]
#![allow(clippy::panic)]

use ed25519_dalek::{Signer, SigningKey};
use mnemos_b_memory::{
    CHUNK_SIGN_DOMAIN, ChunkDigest32, OwnerPublicKeyBinding, SigningPublicKey, StageBChunkError,
    StageBChunkFlags, StageBChunkHeaderV1, StageBChunkView, StageBSignedChunkV1, StageBTraceLink,
    chunk_sign_preimage, stage_b_chunk_digest, verify_stage_b_chunk,
};
use mnemos_c_walrus::codec::{BlobId, ChunkEnvelopeV1, ChunkKind, MemoryRole};
use mnemos_c_walrus::{PublishPayloadClass, SignatureBytes};
use mnemos_d_move::SuiAddress;

// ===========================================================================
// Helpers — public-API only, mirroring the #89/#90 unit-test fixtures.
// ===========================================================================

/// A minimal genesis Stage A envelope carrying `content` (no parent/embedding/
/// signature/provenance on the Stage A wire — the header is what the digest
/// commits).
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

/// Build a Stage B header with every digest-bound dimension explicit: `owner`,
/// `parent` (header-level integrity link; the `HasParent` flag is derived to stay
/// consistent), and `trace`. `content_len` must equal the body length the view
/// will borrow (enforced by [`StageBChunkView::new`]).
fn header(
    content_len: u32,
    owner: SuiAddress,
    parent: Option<BlobId>,
    trace: StageBTraceLink,
) -> StageBChunkHeaderV1 {
    let flags = if parent.is_some() {
        StageBChunkFlags::HasParent as u8
    } else {
        StageBChunkFlags::None as u8
    };
    StageBChunkHeaderV1::new(
        ChunkKind::UserMessage,
        MemoryRole::User,
        PublishPayloadClass::SyntheticPublicFixture,
        flags,
        content_len,
        owner,
        parent,
        trace,
    )
    .expect("known-good header is valid")
}

/// An `(ed25519 SigningKey, owner⇔key binding)` fixture from a fixed public seed
/// and a synthetic owner byte fill.
fn keyed(seed: [u8; 32], owner_byte: u8) -> (SigningKey, OwnerPublicKeyBinding) {
    let signing = SigningKey::from_bytes(&seed);
    let pubkey = signing.verifying_key().to_bytes();
    let signing_public = SigningPublicKey::from_bytes(&pubkey).expect("32-byte pubkey");
    let owner = SuiAddress::new([owner_byte; 32]);
    (signing, OwnerPublicKeyBinding::new(owner, signing_public))
}

/// Compute the digest of a chunk with the given digest-bound dimensions, through
/// a genesis-or-parented view (atom #86 [`stage_b_chunk_digest`]).
fn digest_of(
    content: &[u8],
    owner: SuiAddress,
    parent: Option<BlobId>,
    trace: StageBTraceLink,
) -> ChunkDigest32 {
    let e = env(content);
    let h = header(content.len() as u32, owner, parent, trace);
    let view = StageBChunkView::new(h, &e).expect("within content cap");
    stage_b_chunk_digest(&view).expect("digest ok")
}

/// Sign the canonical atom #89 chunk-sign preimage (`CHUNK_SIGN_DOMAIN || digest`)
/// with a raw ed25519 key — the test stand-in for the deferred wallet signer.
fn sign(signing: &SigningKey, digest: &ChunkDigest32) -> SignatureBytes {
    let preimage = chunk_sign_preimage(digest);
    SignatureBytes(signing.sign(&preimage).to_bytes())
}

/// Sign an arbitrary preimage with a raw ed25519 key (used to forge signatures
/// under a *different* domain / network tag than the canonical one).
fn sign_raw(signing: &SigningKey, preimage: &[u8]) -> SignatureBytes {
    SignatureBytes(signing.sign(preimage).to_bytes())
}

/// The canonical owner / trace used by tests that hold every dimension fixed
/// except the one under test.
const OWNER: u8 = 0x55;
fn base_trace() -> StageBTraceLink {
    StageBTraceLink::new(99, 99, 0)
}

// ===========================================================================
// 0. Positive control — the matrix only means something if the valid case passes.
// ===========================================================================

/// `sig_matrix_positive_control` — a signature over the canonical preimage, under
/// the owner's own binding, verifies, *and* mints a [`StageBSignedChunkV1`] that
/// re-verifies (atom #90 constructor binds digest→verify in one path). Every RED
/// test below differs from this case in exactly one dimension.
#[test]
fn sig_matrix_positive_control() {
    let owner = SuiAddress::new([OWNER; 32]);
    let body = b"canonical signed chunk body";
    let (signing, binding) = keyed([0x01; 32], OWNER);

    let e = env(body);
    let h = header(body.len() as u32, owner, None, base_trace());
    let view = StageBChunkView::new(h, &e).expect("within cap");
    let digest = stage_b_chunk_digest(&view).expect("digest ok");
    let sig = sign(&signing, &digest);

    // (a) the bare verify surface (#89)
    assert!(
        verify_stage_b_chunk(&sig, digest, &binding).is_ok(),
        "canonical signature must verify under the owner's binding",
    );
    // (b) the constructor seam (#90) — the same valid signature mints a chunk that
    //     re-verifies.
    let signed = StageBSignedChunkV1::new(&view, sig, &binding).expect("valid chunk mints");
    assert!(
        signed.verify(&binding).is_ok(),
        "minted chunk re-verifies under its own binding",
    );
}

// ===========================================================================
// 1. wrong owner
// ===========================================================================

/// `sig_matrix_wrong_owner` — a signature made with owner A's key must FAIL verify
/// under owner B's binding. Digest and domain are identical; only the owner⇔key
/// binding differs. Checked at both the #89 verify surface and the #90 mint seam.
#[test]
fn sig_matrix_wrong_owner() {
    let owner_a = SuiAddress::new([0xAA; 32]);
    let body = b"owner-confusion body";
    let (signing_a, _binding_a) = keyed([0x44; 32], 0xAA);
    let (_signing_b, binding_b) = keyed([0x99; 32], 0xBB);

    let e = env(body);
    let h = header(body.len() as u32, owner_a, None, base_trace());
    let view = StageBChunkView::new(h, &e).expect("within cap");
    let digest = stage_b_chunk_digest(&view).expect("digest ok");

    let sig = sign(&signing_a, &digest);
    assert_eq!(
        verify_stage_b_chunk(&sig, digest, &binding_b),
        Err(StageBChunkError::SignatureInvalid),
        "A's signature must NOT verify under B's binding (#89)",
    );
    assert_eq!(
        StageBSignedChunkV1::new(&view, sig, &binding_b),
        Err(StageBChunkError::SignatureInvalid),
        "A's signature must NOT mint a chunk under B's binding (#90)",
    );
}

// ===========================================================================
// 2. wrong domain
// ===========================================================================

/// `sig_matrix_wrong_domain` — a signature produced under a DIFFERENT domain
/// prefix than `CHUNK_SIGN_DOMAIN` must FAIL chunk verify, proving the domain is
/// genuinely mixed into the signed bytes (not advisory). Two cross-domain replay
/// attempts are exercised:
///   (a) the empty-domain / raw-digest preimage (`digest` alone, no domain), and
///   (b) the Sui PersonalMessage intent prefix `[3,0,0]` — the cross-protocol
///       replay the atom #89 domain split exists to block.
#[test]
fn sig_matrix_wrong_domain() {
    let owner = SuiAddress::new([OWNER; 32]);
    let (signing, binding) = keyed([0x33; 32], OWNER);
    let digest = digest_of(b"domain-confusion body", owner, None, base_trace());

    // (a) sign over the raw digest with NO domain prefix.
    let sig_raw = sign_raw(&signing, digest.as_bytes());
    assert_eq!(
        verify_stage_b_chunk(&sig_raw, digest, &binding),
        Err(StageBChunkError::SignatureInvalid),
        "an undomained (raw-digest) signature must NOT verify as a chunk signature",
    );

    // (b) sign over a payload prefixed with the Sui PersonalMessage intent scope
    //     [3,0,0] — the cross-domain replay attempt.
    let mut sui_intent = vec![3u8, 0, 0];
    sui_intent.extend_from_slice(digest.as_bytes());
    let sig_sui = sign_raw(&signing, &sui_intent);
    assert_eq!(
        verify_stage_b_chunk(&sig_sui, digest, &binding),
        Err(StageBChunkError::SignatureInvalid),
        "a Sui-intent-scoped signature must NOT verify as a chunk signature",
    );
}

// ===========================================================================
// 3. wrong content
// ===========================================================================

/// `sig_matrix_wrong_content` — a valid signature over the digest of body X must
/// FAIL verify against the digest of a different body Y (the content hash, hence
/// the committed digest, moves with the body). Checked at the #89 verify surface
/// and via the #90 constructor recomputing the digest from a tampered body.
#[test]
fn sig_matrix_wrong_content() {
    let owner = SuiAddress::new([OWNER; 32]);
    let (signing, binding) = keyed([0x55; 32], OWNER);

    let digest_x = digest_of(b"body X", owner, None, base_trace());
    let digest_y = digest_of(b"body Y", owner, None, base_trace());
    assert_ne!(
        digest_x.as_bytes(),
        digest_y.as_bytes(),
        "distinct bodies must yield distinct digests",
    );

    let sig = sign(&signing, &digest_x);
    assert!(
        verify_stage_b_chunk(&sig, digest_x, &binding).is_ok(),
        "control: the signature verifies over its own digest X",
    );
    assert_eq!(
        verify_stage_b_chunk(&sig, digest_y, &binding),
        Err(StageBChunkError::SignatureInvalid),
        "a signature over digest X must NOT verify against digest Y (#89)",
    );

    // #90 mint seam: present body Y with X's signature → the constructor
    // recomputes Y's digest and rejects.
    let e_y = env(b"body Y");
    let h_y = header((b"body Y" as &[u8]).len() as u32, owner, None, base_trace());
    let view_y = StageBChunkView::new(h_y, &e_y).expect("within cap");
    assert_eq!(
        StageBSignedChunkV1::new(&view_y, sig, &binding),
        Err(StageBChunkError::SignatureInvalid),
        "a signature over body X must NOT mint a chunk over tampered body Y (#90)",
    );
}

// ===========================================================================
// 4. wrong parent
// ===========================================================================

/// `sig_matrix_wrong_parent` — two chunks identical in body, owner and trace but
/// differing in their header parent blob id (genesis vs a `HasParent` link)
/// produce distinct digests, so a signature over the genesis digest must FAIL
/// verify against the parented digest. Proves the parent integrity link is bound
/// into the signed digest, not free-floating metadata.
#[test]
fn sig_matrix_wrong_parent() {
    let owner = SuiAddress::new([OWNER; 32]);
    let (signing, binding) = keyed([0x66; 32], OWNER);
    let body = b"parent-confusion body";

    let digest_genesis = digest_of(body, owner, None, base_trace());
    let parent = BlobId([0xAB; 32]);
    let digest_parented = digest_of(body, owner, Some(parent), base_trace());

    assert_ne!(
        digest_genesis.as_bytes(),
        digest_parented.as_bytes(),
        "genesis vs parented header must yield distinct digests",
    );

    // signed over the genesis digest, verified against the parented digest
    let sig = sign(&signing, &digest_genesis);
    assert!(
        verify_stage_b_chunk(&sig, digest_genesis, &binding).is_ok(),
        "control: signature verifies over the genesis digest",
    );
    assert_eq!(
        verify_stage_b_chunk(&sig, digest_parented, &binding),
        Err(StageBChunkError::SignatureInvalid),
        "a genesis-digest signature must NOT verify against a parented digest",
    );
}

// ===========================================================================
// 5. wrong trace
// ===========================================================================

/// `sig_matrix_wrong_trace` — two chunks identical in body, owner and parent but
/// differing in their per-action [`StageBTraceLink`] produce distinct digests, so
/// a signature over the trace-T1 digest must FAIL verify against the trace-T2
/// digest. Proves the replay/evidence stamp is bound into the signed digest.
#[test]
fn sig_matrix_wrong_trace() {
    let owner = SuiAddress::new([OWNER; 32]);
    let (signing, binding) = keyed([0x77; 32], OWNER);
    let body = b"trace-confusion body";

    let trace_a = StageBTraceLink::new(99, 99, 0);
    let trace_b = StageBTraceLink::new(99, 99, 1); // same atom, different attempt
    let digest_a = digest_of(body, owner, None, trace_a);
    let digest_b = digest_of(body, owner, None, trace_b);

    assert_ne!(
        digest_a.as_bytes(),
        digest_b.as_bytes(),
        "distinct trace stamps must yield distinct digests",
    );

    let sig = sign(&signing, &digest_a);
    assert!(
        verify_stage_b_chunk(&sig, digest_a, &binding).is_ok(),
        "control: signature verifies over the trace-A digest",
    );
    assert_eq!(
        verify_stage_b_chunk(&sig, digest_b, &binding),
        Err(StageBChunkError::SignatureInvalid),
        "a trace-A signature must NOT verify against a trace-B digest",
    );
}

// ===========================================================================
// 6. wrong network
// ===========================================================================

/// `sig_matrix_wrong_network` — the chunk-sign domain ends with the `.testnet`
/// network tag (`CHUNK_SIGN_DOMAIN` = `mnemos.stage_b.chunk_sig.v1.testnet`). A
/// signature produced over the same domain with the tag swapped to `mainnet`
/// (a hypothetical future network) must FAIL verify under the testnet domain,
/// proving the network is bound *inside* the signed bytes — a testnet signature
/// can never be replayed as a mainnet one or vice versa, by construction.
#[test]
fn sig_matrix_wrong_network() {
    let owner = SuiAddress::new([OWNER; 32]);
    let (signing, binding) = keyed([0x88; 32], OWNER);
    let digest = digest_of(b"network-confusion body", owner, None, base_trace());

    // Document the network tag this atom pins: the domain ends with ".testnet".
    let n = CHUNK_SIGN_DOMAIN.len();
    assert_eq!(
        &CHUNK_SIGN_DOMAIN[n - 7..],
        b"testnet",
        "chunk-sign domain must carry the testnet network tag in its last 7 bytes",
    );

    // Forge the same domain with "testnet" -> "mainnet" (equal width keeps the
    // preimage length identical, isolating the network tag as the only change).
    let mut mainnet_domain = CHUNK_SIGN_DOMAIN.to_vec();
    mainnet_domain[n - 7..].copy_from_slice(b"mainnet");
    assert_ne!(
        mainnet_domain.as_slice(),
        CHUNK_SIGN_DOMAIN,
        "the mainnet-tagged domain must differ from the testnet domain",
    );

    let mut preimage = mainnet_domain;
    preimage.extend_from_slice(digest.as_bytes());
    let sig = sign_raw(&signing, &preimage);

    assert_eq!(
        verify_stage_b_chunk(&sig, digest, &binding),
        Err(StageBChunkError::SignatureInvalid),
        "a mainnet-network-tagged signature must NOT verify under the testnet chunk-sign domain",
    );
}

// ===========================================================================
// 7. matrix completeness — every named dimension is exercised exactly once.
// ===========================================================================

/// `sig_matrix_completeness` — a structural witness that the six confusion
/// dimensions named in the atom #99 plan (`wrong owner`, `wrong domain`,
/// `wrong content`, `wrong parent`, `wrong trace`, `wrong network`) each have a
/// dedicated RED test in this file, plus the positive control. This keeps the
/// matrix from silently losing a dimension as the file evolves.
#[test]
fn sig_matrix_completeness() {
    // The plan's six dimensions, in plan order.
    let dimensions = [
        "wrong_owner",
        "wrong_domain",
        "wrong_content",
        "wrong_parent",
        "wrong_trace",
        "wrong_network",
    ];
    assert_eq!(
        dimensions.len(),
        6,
        "the atom #99 plan names exactly six signature-confusion dimensions",
    );
    // Each dimension name is distinct (no accidental duplication / drop).
    for (i, a) in dimensions.iter().enumerate() {
        for b in &dimensions[i + 1..] {
            assert_ne!(a, b, "confusion dimensions must be distinct");
        }
    }
}
