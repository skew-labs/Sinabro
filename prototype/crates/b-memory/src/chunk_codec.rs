//! `chunk_codec.rs` — the Stage B **canonical codec** (encode and
//! decode).
//!
//! This module mints the [`encode_stage_b_chunk`] entry point: the single
//! Stage B name for "produce the canonical wire bytes a memory owner publishes to
//! Walrus and anchors on Sui". It is a **thin wrapper** over Stage A's
//! [`encode_chunk_v1`](mnemos_c_walrus::codec::encode_chunk_v1) — Stage B does
//! **not** mint a second BCS wire.
//!
//! # Design invariant
//!
//! > A thin wrapper over `encode_chunk_v1`. It does not create a new BCS wire;
//! > it only adds the Stage B digest/signature preimage.
//!
//! The byte stream this function emits is **byte-identical** to Stage A's
//! canonical V1 encoder — there is no Stage-B-specific framing, length prefix,
//! domain tag, or trailing byte. Stage B's own additions live in **separate**
//! surfaces that consume these very bytes (or the body inside them):
//!
//! * the domain-separated **digest** preimage,
//!   [`stage_b_chunk_digest`](crate::stage_b_chunk_digest), which binds the fixed
//!   85-byte header and the body's content hash, **not** this wire — and
//! * the **signature** preimage,
//!   [`chunk_sign_preimage`](crate::chunk_sign_preimage), which prefixes
//!   `CHUNK_SIGN_DOMAIN` in front of that digest.
//!
//! So "adds only the Stage B digest/signature preimage" is satisfied by composition:
//! `encode_stage_b_chunk` reuses Stage A's wire verbatim, and the digest / sign
//! layers (already minted) sit *beside* it. Pinning the encode to
//! Stage A's exact bytes keeps the cross-language Move/Rust anchor stable — a
//! Stage-B-only re-frame here would silently fork the wire the Move side
//! and the verified-blob decode both read.
//!
//! # Why a named wrapper rather than a bare re-export
//!
//! A `pub use` would also keep the bytes identical, but the canonical OUT
//! is a `fn` with a Stage B name. Giving Stage B one explicit
//! `encode_stage_b_chunk` symbol means the Walrus PUT path, the blob-id
//! derivation and the decode path all reference a single Stage B entry point
//! (and one doc home for the "no new wire" invariant), while the wrapper stays
//! zero-cost — it forwards the borrow straight to `encode_chunk_v1` with no extra
//! allocation, copy or branch.
//!
//! # Scope
//!
//! Encode and decode. [`decode_stage_b_chunk`] is the matching thin
//! wrapper over Stage A's [`decode_chunk_v1`](mnemos_c_walrus::codec::decode_chunk_v1);
//! its decode → re-encode non-canonical reject is Stage A's, reused not
//! reinvented. The production signer
//! `sign_stage_b_chunk(digest, &ScopedSecretKey)` is a later module. This wrapper
//! returns Stage A's [`ChunkCodecError`] unchanged — it does **not** enforce the
//! tighter Stage B `MAX_STAGE_B_CONTENT_BYTES` (1 MiB) cap, because that policy
//! cap lives one layer up at [`StageBChunkView::new`](crate::StageBChunkView) /
//! [`stage_b_chunk_digest`](crate::stage_b_chunk_digest) and is
//! expressed as [`StageBChunkError::ContentTooLarge`], a type this A-wire encoder
//! does not return. Stage A's own `MAX_CONTENT_BYTES` reject is still in force
//! (it is inside `encode_chunk_v1`).
//!
//! # Reuse (zero re-invention)
//!
//! * Stage A [`encode_chunk_v1`](mnemos_c_walrus::codec::encode_chunk_v1) — the canonical
//!   V1 encoder; the wrapper delegates to it verbatim.
//! * Stage A [`ChunkEnvelopeV1`](mnemos_c_walrus::codec::ChunkEnvelopeV1) — the input
//!   envelope, reused verbatim (no Stage-B-specific envelope).
//! * Stage A [`ChunkCodecError`](mnemos_c_walrus::codec::ChunkCodecError) — the error
//!   surface, returned unchanged (no new Stage B variant).
//! * [`StageBChunkView`](crate::StageBChunkView) — the borrowed lens; a caller
//!   holding a view encodes `view.envelope` (exercised in tests).
//! * [`StageBSignedChunkV1`](crate::StageBSignedChunkV1) — the signed unit; a
//!   caller holding one encodes `signed.envelope` (exercised in tests).
//!
//! No new dependency, no new wire format, no new error variant.

use mnemos_c_walrus::codec::{ChunkCodecError, ChunkEnvelopeV1, decode_chunk_v1, encode_chunk_v1};

/// Serialize a [`ChunkEnvelopeV1`] to its canonical Stage A V1 wire bytes.
///
/// A **thin wrapper** over [`encode_chunk_v1`]: the returned bytes are
/// byte-identical to Stage A's canonical encoder — Stage B mints no new wire.
/// The Stage B digest and signature preimages are separate
/// surfaces layered *beside* this byte stream, not folded into it.
///
/// Returns the same [`ChunkCodecError`] cases `encode_chunk_v1` does
/// (`ContentTooLarge` if the body exceeds Stage A's `MAX_CONTENT_BYTES`,
/// `ZeroEmbeddingDims` if an embedding declares zero dims). It does **not**
/// enforce the tighter Stage B `MAX_STAGE_B_CONTENT_BYTES` cap — that policy lives
/// at the view/digest layer and is expressed as
/// [`StageBChunkError::ContentTooLarge`](crate::StageBChunkError), which this
/// A-wire encoder does not return.
#[inline]
pub fn encode_stage_b_chunk(chunk: &ChunkEnvelopeV1) -> Result<Vec<u8>, ChunkCodecError> {
    encode_chunk_v1(chunk)
}

/// Decode canonical Stage B chunk wire bytes back into a [`ChunkEnvelopeV1`].
///
/// This is the canonical decode entry point. It is a **thin,
/// zero-cost wrapper** over Stage A's
/// [`decode_chunk_v1`](mnemos_c_walrus::codec::decode_chunk_v1),
/// mirroring how [`encode_stage_b_chunk`] wraps the encoder. Stage B mints no
/// second parser: pinning decode to Stage A's exact bytes keeps the
/// decode ⇄ encode round-trip byte-identical, so the same wire the Walrus
/// client GETs and the replay path re-reads stays consistent
/// with the Move anchor (`ChunkAnchored.blob_id`).
///
/// The design rule "if a decode-then-re-encode differs from the input, reject as
/// NonCanonical" is satisfied by reuse, not reinvention: Stage A's decoder already
/// re-encodes the decoded value and returns [`ChunkCodecError::NonCanonical`]
/// when the re-encode does not reproduce the input (e.g. non-minimal LEB128),
/// [`ChunkCodecError::TrailingBytes`] when bytes remain after the envelope, and
/// the `Unknown*` / `ShortBuffer` / `LengthOverflow` rejects for malformed
/// prefixes. Stage B adds nothing to the byte contract — it only re-publishes
/// the entry point under the single Stage B name.
///
/// # Errors
///
/// Returns the Stage A [`ChunkCodecError`](mnemos_c_walrus::codec::ChunkCodecError) unchanged.
#[inline]
pub fn decode_stage_b_chunk(bytes: &[u8]) -> Result<ChunkEnvelopeV1, ChunkCodecError> {
    decode_chunk_v1(bytes)
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
    use crate::chunk_schema::{
        MAX_STAGE_B_CONTENT_BYTES, StageBChunkFlags, StageBChunkHeaderV1, StageBChunkView,
    };
    use crate::chunk_signature::chunk_sign_preimage;
    use crate::owner::{OwnerPublicKeyBinding, SigningPublicKey};
    use crate::signed_chunk::StageBSignedChunkV1;
    use crate::stage_b_chunk_digest;
    use crate::stage_b_handoff::StageBTraceLink;
    use ed25519_dalek::{Signer, SigningKey};
    use mnemos_c_walrus::PublishPayloadClass;
    use mnemos_c_walrus::SignatureBytes;
    use mnemos_c_walrus::codec::{ChunkKind, MemoryRole, decode_chunk_v1, encode_chunk_v1};
    use mnemos_d_move::SuiAddress;

    /// Build a minimal valid envelope (mirrors the signed_chunk.rs test
    /// helper): a `content` body, genesis parent, no embedding/sig/provenance.
    fn env(content: Vec<u8>) -> ChunkEnvelopeV1 {
        ChunkEnvelopeV1 {
            kind: ChunkKind::UserMessage,
            role: MemoryRole::User,
            parent: None,
            content,
            embedding: None,
            signature: None,
            provenance: None,
        }
    }

    /// `b1_10_golden_bytes` — a known genesis envelope encodes to the exact
    /// canonical V1 byte vector (Python-verified golden: 12 bytes), and that
    /// vector is byte-identical to Stage A's `encode_chunk_v1` (proves the wrapper
    /// mints no new wire). The golden layout is:
    /// `[version=1][kind=1][role=1][reserved_flags=0,0][parent_none=0]`
    /// `[content_len_uleb=2]['h','i'][emb_none=0][sig_none=0][prov_none=0]`.
    #[test]
    fn b1_10_golden_bytes() {
        let e = env(b"hi".to_vec());
        let got = encode_stage_b_chunk(&e).expect("encode ok");

        // Golden literal (Python-verified: decimal
        // [1,1,1,0,0,0,2,104,105,0,0,0], 12 bytes).
        let golden: [u8; 12] = [
            0x01, 0x01, 0x01, 0x00, 0x00, 0x00, 0x02, b'h', b'i', 0x00, 0x00, 0x00,
        ];
        assert_eq!(got.as_slice(), &golden, "canonical V1 golden bytes");

        // And byte-identical to Stage A's encoder — no Stage B re-frame.
        assert_eq!(
            got,
            encode_chunk_v1(&e).expect("A encode ok"),
            "no new wire"
        );
    }

    /// `b1_10_empty_content` — an empty body encodes to the smallest canonical
    /// form (content_len uleb128 = 0, body absent), still byte-identical to A.
    #[test]
    fn b1_10_empty_content() {
        let e = env(Vec::new());
        let got = encode_stage_b_chunk(&e).expect("encode ok");

        // version,kind,role,reserved(2),parent_none,len=0,emb_none,sig_none,prov_none
        let golden: [u8; 10] = [0x01, 0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
        assert_eq!(got.as_slice(), &golden, "empty-body canonical bytes");
        assert_eq!(
            got,
            encode_chunk_v1(&e).expect("A encode ok"),
            "no new wire"
        );
    }

    /// `b1_10_max_edge` — at the Stage B policy ceiling `MAX_STAGE_B_CONTENT_BYTES`
    /// (1 MiB) the encode succeeds and stays byte-identical to A. The 1 MiB body
    /// also crosses the uleb128 length-prefix boundary into 3 bytes
    /// (`16384..=2097151` → 3-byte uleb), exercising the canonical multi-byte
    /// length prefix. (The Stage A `MAX_CONTENT_BYTES` = 13 MB *reject* edge is
    /// not exercised here — it would need a 13 MB+ allocation.)
    #[test]
    fn b1_10_max_edge() {
        let len = MAX_STAGE_B_CONTENT_BYTES as usize; // 1_048_576
        let e = env(vec![0xABu8; len]);
        let got = encode_stage_b_chunk(&e).expect("1 MiB body encodes");

        // uleb128(1_048_576) = 0x80 0x80 0x40 (3 bytes): the canonical multi-byte
        // length prefix. Fixed prefix before it = 6 bytes
        // (version,kind,role,reserved(2),parent_none).
        assert_eq!(
            &got[0..6],
            &[0x01, 0x01, 0x01, 0x00, 0x00, 0x00],
            "fixed header prefix"
        );
        assert_eq!(
            &got[6..9],
            &[0x80, 0x80, 0x40],
            "3-byte uleb128 length prefix at 1 MiB"
        );
        // body follows, then the three trailing option-none tags.
        assert_eq!(
            got.len(),
            9 + len + 3,
            "header + body + 3 option tags, no slack"
        );
        assert_eq!(
            got,
            encode_chunk_v1(&e).expect("A encode ok"),
            "no new wire"
        );
    }

    /// `b1_10_no_trailing_bytes` — the encoded output carries no bytes beyond the
    /// canonical envelope: a `decode_chunk_v1` of the output round-trips back to
    /// the exact input (Stage A's decoder rejects trailing bytes as
    /// `NonCanonical`, so a clean round-trip proves there are none), and a
    /// re-encode reproduces the same bytes.
    #[test]
    fn b1_10_no_trailing_bytes() {
        let e = env(b"no trailing slack please".to_vec());
        let got = encode_stage_b_chunk(&e).expect("encode ok");

        // decode round-trips (rejects trailing bytes by construction) ...
        let back = decode_chunk_v1(&got).expect("clean decode — no trailing bytes");
        assert_eq!(back, e, "decode(encode(x)) == x");
        // ... and re-encode is byte-stable.
        assert_eq!(
            encode_stage_b_chunk(&back).expect("re-encode"),
            got,
            "re-encode stable"
        );
    }

    /// `b1_10_encode_via_stage_b_view` — reuse: a caller holding a
    /// [`StageBChunkView`] encodes its borrowed `envelope` and gets the canonical
    /// bytes (the view's body is the envelope's body, unchanged).
    #[test]
    fn b1_10_encode_via_stage_b_view() {
        let body = b"view-borrowed body";
        let e = env(body.to_vec());
        let header = StageBChunkHeaderV1::new(
            ChunkKind::UserMessage,
            MemoryRole::User,
            PublishPayloadClass::SyntheticPublicFixture,
            StageBChunkFlags::None as u8,
            body.len() as u32,
            SuiAddress::new([0x55; 32]),
            None,
            StageBTraceLink::new(91, 91, 0),
        )
        .expect("header valid");
        let view = StageBChunkView::new(header, &e).expect("within cap");

        let got = encode_stage_b_chunk(view.envelope).expect("encode via view");
        assert_eq!(
            got,
            encode_chunk_v1(&e).expect("A encode ok"),
            "view path == direct"
        );
    }

    /// `b1_10_encode_via_signed_chunk` — reuse: a caller holding a minted
    /// [`StageBSignedChunkV1`] encodes its owned `envelope`; the bytes are the
    /// canonical wire for the publishable unit. Also exercises the chain
    /// digest → sign-preimage → signed chunk → encode.
    #[test]
    fn b1_10_encode_via_signed_chunk() {
        let body = b"signed publishable body";
        let e = env(body.to_vec());
        let header = StageBChunkHeaderV1::new(
            ChunkKind::UserMessage,
            MemoryRole::User,
            PublishPayloadClass::SyntheticPublicFixture,
            StageBChunkFlags::None as u8,
            body.len() as u32,
            SuiAddress::new([0x55; 32]),
            None,
            StageBTraceLink::new(91, 91, 0),
        )
        .expect("header valid");
        let view = StageBChunkView::new(header, &e).expect("within cap");
        let digest = stage_b_chunk_digest(&view).expect("digest ok");

        let signing = SigningKey::from_bytes(&[0x22; 32]);
        let pubkey = signing.verifying_key().to_bytes();
        let binding = OwnerPublicKeyBinding::new(
            SuiAddress::new([0x55; 32]),
            SigningPublicKey::from_bytes(&pubkey).expect("32-byte pubkey"),
        );
        let sig = SignatureBytes(signing.sign(&chunk_sign_preimage(&digest)).to_bytes());

        let signed = StageBSignedChunkV1::new(&view, sig, &binding).expect("mints");

        let got = encode_stage_b_chunk(&signed.envelope).expect("encode signed envelope");
        assert_eq!(
            got,
            encode_chunk_v1(&e).expect("A encode ok"),
            "signed path == direct"
        );
    }

    // ---------------------------------------------------------------------
    // decode_stage_b_chunk + noncanonical reject.
    // ---------------------------------------------------------------------

    /// std-only deterministic PRNG for the property loop. The proptest crate is a
    /// b-memory dev-dep but this module keeps its codec property coverage self-contained
    /// in a fixed-seed splitmix64 sweep (the dedicated codec property/fuzz infra
    /// is a later module); no randomness source, fully reproducible.
    fn splitmix64(state: &mut u64) -> u64 {
        *state = state.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = *state;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }

    /// `b1_11_decode_golden` — a known envelope round-trips (encode → decode is
    /// the identity) and the exact golden wire decodes to the canonical envelope.
    #[test]
    fn b1_11_decode_golden() {
        let e = env(b"hi".to_vec());
        let wire = encode_stage_b_chunk(&e).expect("encode");
        let back = decode_stage_b_chunk(&wire).expect("decode golden");
        assert_eq!(back, e, "decode reproduces the envelope");

        // The exact b1_10_golden_bytes literal decodes to the same envelope.
        let golden: [u8; 12] = [
            0x01, 0x01, 0x01, 0x00, 0x00, 0x00, 0x02, b'h', b'i', 0x00, 0x00, 0x00,
        ];
        assert_eq!(
            decode_stage_b_chunk(&golden).expect("golden decodes"),
            e,
            "golden wire decodes to the canonical envelope"
        );
    }

    /// `b1_11_trailing_reject` — one extra byte after a complete envelope is
    /// rejected by Stage A's canonical guard as `NonCanonical` (the re-encode of
    /// the parsed envelope is shorter than the input, so it cannot match).
    #[test]
    fn b1_11_trailing_reject() {
        let e = env(b"tail".to_vec());
        let mut wire = encode_stage_b_chunk(&e).expect("encode");
        wire.push(0xFF);
        assert_eq!(
            decode_stage_b_chunk(&wire),
            Err(ChunkCodecError::NonCanonical),
            "trailing byte after envelope rejected"
        );
    }

    /// `b1_11_noncanonical_length_reject` — the content_len for "hi" is the single
    /// minimal LEB128 byte `0x02` at index 6 (after `[ver,kind,role,resv,resv,
    /// parent_none]`). Replacing it with a non-minimal 2-byte encoding of 2
    /// (`0x82,0x00`) is rejected by Stage A's uleb128 reader at parse time as
    /// `InvalidLengthPrefix` (the `WireError::NonCanonicalUleb` → `InvalidLengthPrefix`
    /// mapping fires before the decode → re-encode `NonCanonical` guard ever runs).
    /// Either way the non-minimal length is rejected fail-closed; the variant pins
    /// which Stage A guard caught it (verified by the real test run, not assumed).
    #[test]
    fn b1_11_noncanonical_length_reject() {
        let noncanon = vec![
            0x01, 0x01, 0x01, 0x00, 0x00, 0x00, 0x82, 0x00, b'h', b'i', 0x00, 0x00, 0x00,
        ];
        assert_eq!(
            decode_stage_b_chunk(&noncanon),
            Err(ChunkCodecError::InvalidLengthPrefix),
            "non-minimal LEB128 length rejected at parse time"
        );
    }

    /// `b1_11_unknown_tag_reject` — `ChunkKind` discriminants are `1..=5`; corrupt
    /// the kind tag (index 1) to an unknown value and Stage A rejects it with
    /// `UnknownKind`.
    #[test]
    fn b1_11_unknown_tag_reject() {
        let e = env(b"x".to_vec());
        let mut wire = encode_stage_b_chunk(&e).expect("encode");
        wire[1] = 0xEE;
        assert_eq!(
            decode_stage_b_chunk(&wire),
            Err(ChunkCodecError::UnknownKind { tag: 0xEE }),
            "unknown chunk-kind tag rejected"
        );
    }

    /// `b1_11_prop_roundtrip_and_no_panic` — property sweep (std-only): over 512
    /// deterministic inputs assert (a) every valid envelope round-trips
    /// encode → decode == original, (b) decode of arbitrary bytes never panics
    /// (Ok or Err only), (c) appending any trailing byte to a valid wire is
    /// always rejected.
    #[test]
    fn b1_11_prop_roundtrip_and_no_panic() {
        let mut s = 0x0DDB_1A5E_5EED_1234u64;
        for _ in 0..512 {
            // body_len spans the 1-byte / 2-byte uleb128 boundary (127 → 128).
            let body_len = (splitmix64(&mut s) % 300) as usize;
            let body: Vec<u8> = (0..body_len)
                .map(|_| (splitmix64(&mut s) & 0xff) as u8)
                .collect();
            let e = env(body);

            // (a) round-trip preserves the envelope.
            let wire = encode_stage_b_chunk(&e).expect("encode valid");
            let back = decode_stage_b_chunk(&wire).expect("decode valid round-trips");
            assert_eq!(back, e, "round-trip preserves envelope");

            // (b) arbitrary bytes must not panic.
            let n = (splitmix64(&mut s) % 64) as usize;
            let garbage: Vec<u8> = (0..n).map(|_| (splitmix64(&mut s) & 0xff) as u8).collect();
            let _ = decode_stage_b_chunk(&garbage);

            // (c) trailing byte on a valid wire is always rejected.
            let mut tampered = wire.clone();
            tampered.push((splitmix64(&mut s) & 0xff) as u8);
            assert!(
                decode_stage_b_chunk(&tampered).is_err(),
                "trailing byte on valid wire rejected"
            );
        }
    }
}
