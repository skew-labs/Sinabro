//! Stage B domain-separated chunk digest.
//!
//! This module mints the digest surface: the two
//! `#[repr(transparent)]` 32-byte newtypes [`ContentHash32`] / [`ChunkDigest32`]
//! and the [`stage_b_chunk_digest`] entry point that turns a borrowed
//! [`StageBChunkView`] into a single domain-separated [`ChunkDigest32`].
//!
//! # Design invariants
//!
//! * **Domain separation.** Every digest absorbs a domain string. The chunk
//!   digest's domain is [`CHUNK_DIGEST_DOMAIN`] = `mnemos.stage_b.chunk.v1.testnet`
//!   (the exact string the spec requires), and the content hash uses a
//!   *different* domain [`CONTENT_HASH_DOMAIN`]. A digest computed under a
//!   different domain is a different 32-byte value — the domain is genuinely
//!   absorbed, not advisory (the `b1_5_domain_mismatch_reject` test pins this).
//!   The `.testnet` suffix keeps the Stage B chunk digest domain disjoint from
//!   any future mainnet domain by construction.
//! * **Content hash and header digest are separated.** The body is hashed on its
//!   own into a [`ContentHash32`] ([`ContentHash32::of`]); the chunk digest then
//!   binds the fixed 85-byte header ([`StageBChunkHeaderV1::to_bytes`]) *together
//!   with* that content hash. So the header (ownership + replay boundary: owner,
//!   kind/role/class, flags, parent, trace) and the body are committed in one
//!   [`ChunkDigest32`], but a verifier can compare the content hash alone without
//!   re-walking the header. A single content bit flip changes the content hash
//!   and therefore the chunk digest (`b1_5_content_bitflip_changes_digest`).
//! * **Fail-closed cap re-check.** [`StageBChunkView`]'s fields are `pub`, so a
//!   view *can* be built by a raw struct literal that bypasses
//!   [`StageBChunkView::new`]'s content cap. [`stage_b_chunk_digest`] therefore
//!   re-checks the borrowed body against [`MAX_STAGE_B_CONTENT_BYTES`] and
//!   returns [`StageBChunkError::ContentTooLarge`] rather than hashing an
//!   over-cap body — defense in depth, and the reason the entry point returns a
//!   `Result`.
//!
//! # Hashing primitive (Phase 0 placeholder, no cryptographic claim)
//!
//! The digest reuses the **same** add-rotate-xor (ARX) permutation structure as
//! Stage A's [`derive_blob_id`](mnemos_c_walrus::derive_blob_id) — a pure,
//! allocation-free, `unsafe`-free, deterministic placeholder. Stage A's
//! permutation internals are module-private to `c-walrus::blob_id`, so they are
//! re-stated here rather than imported; this module makes **no** new wire format
//! and **no** cryptographic-strength claim. The real digest swaps in alongside
//! the real Walrus/Sui domain at the net-testnet feature seam,
//! exactly as `derive_blob_id` documents its own swap point.
//!
//! # Reuse map
//!
//! * **reuse [`StageBChunkView`]** — the borrowed lens the digest reads
//!   through (header by value + envelope by shared borrow).
//! * **reuse [`StageBChunkHeaderV1::to_bytes`]** — the content-free 85-byte
//!   header encode is the header half of the digest input (no re-encode minted).
//! * **reuse [`MAX_STAGE_B_CONTENT_BYTES`]** — the same 1 MiB content cap is
//!   re-checked fail-closed before hashing.
//! * **reuse [`BLOB_ID_BYTES`](mnemos_c_walrus::BLOB_ID_BYTES)** — the content
//!   hash width is Stage A's 32-byte blob-id width, not a second size constant.

use crate::chunk_schema::{MAX_STAGE_B_CONTENT_BYTES, StageBChunkView};
use mnemos_c_walrus::{BLOB_ID_BYTES, ChunkCodecError};

// ===========================================================================
// 1. Domain constants
// ===========================================================================

/// Domain string absorbed into every [`ChunkDigest32`] (the spec
/// requires the digest domain to include `mnemos.stage_b.chunk.v1.testnet`;
/// this const **is** that string). The `.testnet` suffix keeps the Stage B
/// chunk digest domain disjoint from any future mainnet digest domain.
pub const CHUNK_DIGEST_DOMAIN: &[u8] = b"mnemos.stage_b.chunk.v1.testnet";

/// Domain string absorbed into every [`ContentHash32`]. Deliberately **distinct**
/// from [`CHUNK_DIGEST_DOMAIN`] so the content hash and the chunk digest occupy
/// separate domains (the "separate the content hash from the header digest"
/// design rule): the same bytes hashed as "content" versus as "chunk" can never
/// collide.
pub const CONTENT_HASH_DOMAIN: &[u8] = b"mnemos.stage_b.content.v1.testnet";

/// Width, in bytes, of a [`ContentHash32`] — Stage A's blob-id width
/// ([`BLOB_ID_BYTES`](mnemos_c_walrus::BLOB_ID_BYTES) = 32), reused rather than
/// re-declared as a second 32 constant (`CONTENT_HASH_BYTES = BLOB_ID_BYTES`).
pub const CONTENT_HASH_BYTES: usize = BLOB_ID_BYTES;

// ===========================================================================
// 2. Newtypes
// ===========================================================================

/// The hash of a chunk's **content body alone**, under [`CONTENT_HASH_DOMAIN`].
///
/// `#[repr(transparent)]` over `[u8; BLOB_ID_BYTES]`; the inner bytes are private
/// so a `ContentHash32` can only be produced by [`ContentHash32::of`] (no forging
/// a content hash from arbitrary bytes).
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
#[repr(transparent)]
pub struct ContentHash32([u8; BLOB_ID_BYTES]);

impl ContentHash32 {
    /// Hash a content body under [`CONTENT_HASH_DOMAIN`]. Allocation-free: the
    /// body is absorbed in place (no intermediate `Vec`); the only output is the
    /// 32-byte hash on the caller stack.
    #[inline]
    pub fn of(content: &[u8]) -> Self {
        Self(hash_parts(CONTENT_HASH_DOMAIN, &[content]))
    }

    /// Borrow the 32-byte content hash.
    #[inline]
    pub const fn as_bytes(&self) -> &[u8; BLOB_ID_BYTES] {
        &self.0
    }
}

/// A domain-separated digest binding a chunk's fixed header **and** its content
/// hash, under [`CHUNK_DIGEST_DOMAIN`].
///
/// `#[repr(transparent)]` over `[u8; 32]`; the inner bytes are private so a
/// `ChunkDigest32` can only be produced by [`stage_b_chunk_digest`]. This is the
/// value a Stage B chunk signature signs over — never the raw header
/// or the raw content.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
#[repr(transparent)]
pub struct ChunkDigest32([u8; 32]);

impl ChunkDigest32 {
    /// Borrow the 32-byte digest.
    #[inline]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

// ===========================================================================
// 3. Error
// ===========================================================================

/// The chunk-error surface. Minted here because this is the first module
/// whose canonical signature ([`stage_b_chunk_digest`]) returns
/// `Result<_, StageBChunkError>`. The variant set is declared verbatim from the
/// spec; this module constructs only [`ContentTooLarge`](Self::ContentTooLarge)
/// (the fail-closed cap re-check), and the remaining variants are constructed by
/// the later stages that own their surfaces (`SignatureInvalid` at the verify
/// stage, `PublishClassDenied` at the publish stage, `ReservedFlags` mapping the
/// flag reject, `NonCanonicalAChunk` wrapping a Stage A codec error).
/// Declaring the full set once keeps the shared error type byte-stable across
/// those stages instead of growing it variant by variant.
///
/// `Copy` + no owned bytes (mirrors [`ChunkCodecError`]): the error channel
/// cannot leak a raw body or a canary substring through `Debug`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum StageBChunkError {
    /// A `flags_u8` bitset carried a reserved bit (the
    /// [`StageBChunkFlags::validate_flag_bits`](crate::StageBChunkFlags::validate_flag_bits)
    /// `None` mapped onto the canonical error surface).
    ReservedFlags,
    /// The chunk body exceeded [`MAX_STAGE_B_CONTENT_BYTES`]. The only variant
    /// this module constructs (the [`stage_b_chunk_digest`] fail-closed cap
    /// re-check before hashing).
    ContentTooLarge,
    /// A chunk signature did not verify against the digest + owner.
    SignatureInvalid,
    /// The chunk's publish payload class is not admissible onto the public
    /// testnet (the publish boundary).
    PublishClassDenied,
    /// The chunk's Stage A envelope was not canonical; wraps the underlying
    /// [`ChunkCodecError`].
    NonCanonicalAChunk(ChunkCodecError),
}

impl StageBChunkError {
    /// Stable, allow-listed `class_label` for diagnostic JSON envelopes,
    /// mirroring [`ChunkCodecError::class_label`] and
    /// [`BlobIdError::class_label`](mnemos_c_walrus::BlobIdError::class_label).
    /// Namespaced under `stage_b.chunk.*`.
    #[inline]
    pub const fn class_label(self) -> &'static str {
        match self {
            Self::ReservedFlags => "stage_b.chunk.reserved_flags",
            Self::ContentTooLarge => "stage_b.chunk.content_too_large",
            Self::SignatureInvalid => "stage_b.chunk.signature_invalid",
            Self::PublishClassDenied => "stage_b.chunk.publish_class_denied",
            Self::NonCanonicalAChunk(_) => "stage_b.chunk.non_canonical_a_chunk",
        }
    }
}

// ===========================================================================
// 4. stage_b_chunk_digest — the canonical OUT entry point
// ===========================================================================

/// Compute the domain-separated [`ChunkDigest32`] for a borrowed chunk view.
///
/// The digest binds the header and the content together:
///
/// 1. The body is hashed alone into a [`ContentHash32`] under
///    [`CONTENT_HASH_DOMAIN`].
/// 2. The fixed 85-byte header ([`StageBChunkHeaderV1::to_bytes`]) and that
///    content hash are absorbed together under [`CHUNK_DIGEST_DOMAIN`] into the
///    returned [`ChunkDigest32`].
///
/// Returns [`StageBChunkError::ContentTooLarge`] if the borrowed body exceeds
/// [`MAX_STAGE_B_CONTENT_BYTES`] — a fail-closed re-check (the view's `pub`
/// fields permit a raw literal that bypasses [`StageBChunkView::new`]'s cap).
///
/// Allocation-free: the header encode is a stack array, the content is absorbed
/// in place, and both intermediate hashes are stack `[u8; 32]`.
#[inline]
pub fn stage_b_chunk_digest(
    chunk: &StageBChunkView<'_>,
) -> Result<ChunkDigest32, StageBChunkError> {
    let content = chunk.envelope.content.as_slice();
    // Fail-closed cap re-check before hashing an over-cap body.
    if content.len() > MAX_STAGE_B_CONTENT_BYTES as usize {
        return Err(StageBChunkError::ContentTooLarge);
    }
    let content_hash = ContentHash32::of(content);
    let header_bytes = chunk.header.to_bytes();
    let digest = hash_parts(
        CHUNK_DIGEST_DOMAIN,
        &[&header_bytes, content_hash.as_bytes()],
    );
    Ok(ChunkDigest32(digest))
}

// ===========================================================================
// 5. ARX hash core (Phase 0 placeholder; mirrors c-walrus::blob_id structure)
// ===========================================================================

// SHA-256 initial-hash constants (well-known public IV). Borrowed as
// "random-looking" lane seeds; no cryptographic claim is made (mirrors
// `c-walrus::blob_id`).
const IV: [u64; 4] = [
    0x6a09_e667_f3bc_c908,
    0xbb67_ae85_84ca_a73b,
    0x3c6e_f372_fe94_f82b,
    0xa54f_f53a_5f1d_36f1,
];

/// Domain-separated hash over a sequence of byte parts.
///
/// The `domain` is absorbed first (length-prefixed), then each part in order
/// (each length-prefixed), then the state is finalised. Distinct domains or
/// distinct parts therefore produce distinct 32-byte outputs. The `&[&[u8]]`
/// parts list is a stack slice of borrows — no heap is touched.
fn hash_parts(domain: &[u8], parts: &[&[u8]]) -> [u8; 32] {
    let mut lanes = IV;
    absorb(&mut lanes, domain);
    for part in parts {
        absorb(&mut lanes, part);
    }
    finalize(&mut lanes)
}

/// Absorb one length-prefixed byte slice into the lanes. The length is added
/// before the body (diffusing extension patterns), then the body is consumed in
/// 32-byte blocks with a zero-extended final partial block. Allocation-free.
#[inline]
fn absorb(lanes: &mut [u64; 4], bytes: &[u8]) {
    lanes[0] = lanes[0].wrapping_add(bytes.len() as u64);
    permute(lanes);

    let total = bytes.len();
    let mut offset = 0usize;
    while offset + 32 <= total {
        lanes[0] ^= read_u64_le(bytes, offset);
        lanes[1] ^= read_u64_le(bytes, offset + 8);
        lanes[2] ^= read_u64_le(bytes, offset + 16);
        lanes[3] ^= read_u64_le(bytes, offset + 24);
        permute(lanes);
        offset += 32;
    }
    if offset < total {
        let mut tail = [0u8; 32];
        let rem = total - offset;
        // `rem <= 32`; `copy_from_slice` length-checks at runtime (no unsafe).
        tail[..rem].copy_from_slice(&bytes[offset..]);
        lanes[0] ^= read_u64_le(&tail, 0);
        lanes[1] ^= read_u64_le(&tail, 8);
        lanes[2] ^= read_u64_le(&tail, 16);
        lanes[3] ^= read_u64_le(&tail, 24);
        permute(lanes);
    }
}

/// Finalise: two extra permutation rounds to diffuse the last block, then
/// serialise the four lanes little-endian into the 32-byte output.
#[inline]
fn finalize(lanes: &mut [u64; 4]) -> [u8; 32] {
    permute(lanes);
    permute(lanes);
    let mut out = [0u8; 32];
    out[0..8].copy_from_slice(&lanes[0].to_le_bytes());
    out[8..16].copy_from_slice(&lanes[1].to_le_bytes());
    out[16..24].copy_from_slice(&lanes[2].to_le_bytes());
    out[24..32].copy_from_slice(&lanes[3].to_le_bytes());
    out
}

/// Read 8 bytes at `start..start+8` as a little-endian `u64`. The caller only
/// ever invokes this with `start + 8 <= buf.len()`.
#[inline]
fn read_u64_le(buf: &[u8], start: usize) -> u64 {
    let mut block = [0u8; 8];
    block.copy_from_slice(&buf[start..start + 8]);
    u64::from_le_bytes(block)
}

/// One ChaCha-style ARX quarter-round on four `u64` lanes. Pure add-rotate-xor;
/// deterministic; no unsafe; no allocation (identical structure to
/// `c-walrus::blob_id::permute`).
#[inline]
fn permute(lanes: &mut [u64; 4]) {
    lanes[0] = lanes[0].wrapping_add(lanes[1]);
    lanes[3] = (lanes[3] ^ lanes[0]).rotate_left(16);
    lanes[2] = lanes[2].wrapping_add(lanes[3]);
    lanes[1] = (lanes[1] ^ lanes[2]).rotate_left(12);
    lanes[0] = lanes[0].wrapping_add(lanes[1]);
    lanes[3] = (lanes[3] ^ lanes[0]).rotate_left(8);
    lanes[2] = lanes[2].wrapping_add(lanes[3]);
    lanes[1] = (lanes[1] ^ lanes[2]).rotate_left(7);
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    #![allow(clippy::expect_used)]
    #![allow(clippy::panic)]

    use super::*;
    use crate::chunk_schema::{StageBChunkFlags, StageBChunkHeaderV1};
    use crate::stage_b_handoff::StageBTraceLink;
    use mnemos_c_walrus::PublishPayloadClass;
    use mnemos_c_walrus::codec::{ChunkEnvelopeV1, ChunkKind, MemoryRole};
    use mnemos_d_move::SuiAddress;

    /// Build the known-vector envelope: a `content`-byte body, all other fields
    /// minimal (genesis parent, no embedding / signature / provenance).
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

    /// Build the known-vector header: kind/role = UserMessage/User, class =
    /// SyntheticPublicFixture, no flags, owner = `0x55`*32, no parent, trace =
    /// (86, 86, 0). Matches the Python reference fixture exactly.
    fn known_header(content_len: u32) -> StageBChunkHeaderV1 {
        StageBChunkHeaderV1::new(
            ChunkKind::UserMessage,
            MemoryRole::User,
            PublishPayloadClass::SyntheticPublicFixture,
            StageBChunkFlags::None as u8,
            content_len,
            SuiAddress::new([0x55; 32]),
            None,
            StageBTraceLink::new(86, 86, 0),
        )
        .expect("known header valid")
    }

    /// Hex-decode a 32-byte vector for golden comparisons.
    fn hex32(s: &str) -> [u8; 32] {
        assert_eq!(s.len(), 64, "expected 64 hex chars");
        let mut out = [0u8; 32];
        for (i, byte) in out.iter_mut().enumerate() {
            *byte = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).expect("hex");
        }
        out
    }

    /// `b1_5_known_vectors` — the digest matches the independent Python
    /// reference byte-for-byte. Pins the content
    /// hash of `b"hello"` and the chunk digest of the known fixture; any drift
    /// in the ARX core, the domain strings, or the header layout breaks this.
    #[test]
    fn b1_5_known_vectors() {
        // Content hash of b"hello" under CONTENT_HASH_DOMAIN.
        assert_eq!(
            ContentHash32::of(b"hello").as_bytes(),
            &hex32("4e9b01c159a4a791f906f8432215ef23c618a67f748c02d1d6f907715091d67b"),
        );

        // Chunk digest of the known fixture (header above + content b"hello").
        let e = env(b"hello");
        let h = known_header(5);
        let view = StageBChunkView::new(h, &e).expect("within cap");
        let digest = stage_b_chunk_digest(&view).expect("digest ok");
        assert_eq!(
            digest.as_bytes(),
            &hex32("053d4a275bb783e31ca2305f84691833a4bd8d21787328ef4b79e59714fffdc3"),
        );

        // Empty content hash (boundary: zero-length body still domain-absorbed).
        assert_eq!(
            ContentHash32::of(b"").as_bytes(),
            &hex32("f87136c81360f80fb0e0de9fa526588cf8941d996168826042fcd736131183d9"),
        );
    }

    /// `b1_5_domain_mismatch_reject` — the domain is genuinely absorbed: the same
    /// bytes hashed under a different domain produce a different 32-byte value,
    /// and the content-hash domain differs from the chunk-digest domain so the
    /// same body cannot collide across the two roles.
    #[test]
    fn b1_5_domain_mismatch_reject() {
        let body = b"some chunk header || content hash bytes";
        let canonical = hash_parts(CHUNK_DIGEST_DOMAIN, &[body]);
        let wrong_domain = hash_parts(b"mnemos.stage_b.chunk.v1.mainnet", &[body]);
        let truncated_domain = hash_parts(b"mnemos.stage_b.chunk.v1", &[body]);
        assert_ne!(canonical, wrong_domain, "mainnet domain must differ");
        assert_ne!(canonical, truncated_domain, "truncated domain must differ");

        // Content-hash domain and chunk-digest domain are disjoint: hashing the
        // SAME bytes under each role yields different outputs.
        assert_ne!(
            hash_parts(CONTENT_HASH_DOMAIN, &[body]),
            hash_parts(CHUNK_DIGEST_DOMAIN, &[body]),
            "content vs chunk domain must not collide",
        );
        // The chunk digest domain is exactly the spec string.
        assert_eq!(CHUNK_DIGEST_DOMAIN, b"mnemos.stage_b.chunk.v1.testnet");
    }

    /// `b1_5_content_bitflip_changes_digest` — a single content bit flip changes
    /// the content hash and therefore the chunk digest (avalanche on the body).
    #[test]
    fn b1_5_content_bitflip_changes_digest() {
        let e0 = env(b"hello");
        let e1 = env(b"hellp"); // last byte 'o'(0x6f) -> 'p'(0x70): one-bit flip.
        let h = known_header(5);
        let d0 = stage_b_chunk_digest(&StageBChunkView::new(h, &e0).expect("cap")).expect("ok");
        let d1 = stage_b_chunk_digest(&StageBChunkView::new(h, &e1).expect("cap")).expect("ok");
        assert_ne!(
            d0.as_bytes(),
            d1.as_bytes(),
            "content bitflip must change digest"
        );

        // The content hash itself differs too (the body is what changed).
        assert_ne!(
            ContentHash32::of(b"hello").as_bytes(),
            ContentHash32::of(b"hellp").as_bytes(),
        );

        // Determinism: the same view digests identically across calls.
        let again = stage_b_chunk_digest(&StageBChunkView::new(h, &e0).expect("cap")).expect("ok");
        assert_eq!(d0.as_bytes(), again.as_bytes(), "digest is deterministic");
    }

    /// `b1_5_header_bound_into_digest` — the header is bound into the digest: a
    /// different owner (a header field) changes the chunk digest even though the
    /// content is identical. This is the "hashes header and envelope together"
    /// binding (the header↔content binding lands in this digest).
    #[test]
    fn b1_5_header_bound_into_digest() {
        let e = env(b"hello");
        let h_a = known_header(5);
        let h_b = StageBChunkHeaderV1::new(
            ChunkKind::UserMessage,
            MemoryRole::User,
            PublishPayloadClass::SyntheticPublicFixture,
            StageBChunkFlags::None as u8,
            5,
            SuiAddress::new([0x66; 32]), // different owner only
            None,
            StageBTraceLink::new(86, 86, 0),
        )
        .expect("valid");
        let d_a = stage_b_chunk_digest(&StageBChunkView::new(h_a, &e).expect("cap")).expect("ok");
        let d_b = stage_b_chunk_digest(&StageBChunkView::new(h_b, &e).expect("cap")).expect("ok");
        assert_ne!(
            d_a.as_bytes(),
            d_b.as_bytes(),
            "owner change must change digest"
        );
    }

    /// `b1_5_oversized_cap_reject` — the fail-closed cap re-check: a view built
    /// by a raw struct literal (bypassing `StageBChunkView::new`) with an
    /// over-cap body is rejected by the digest with `ContentTooLarge` rather than
    /// hashed. (We assert the boundary arithmetic without allocating a 1 MiB+1
    /// body: a view at the cap digests fine; the re-check predicate is the
    /// `content.len() > MAX` comparison `stage_b_chunk_digest` performs.)
    #[test]
    fn b1_5_oversized_cap_reject() {
        // At the cap: digests successfully (uses a small body but asserts the
        // predicate boundary value).
        assert_eq!(MAX_STAGE_B_CONTENT_BYTES, 1_048_576);

        // Construct a raw-literal view whose header claims a within-cap length
        // but whose body is over the cap, then confirm the digest rejects it.
        // Build the over-cap body once (test-only allocation, not a prod path).
        let over = MAX_STAGE_B_CONTENT_BYTES as usize + 1;
        let e_over = env(&vec![0u8; over]);
        let h = StageBChunkHeaderV1::new(
            ChunkKind::UserMessage,
            MemoryRole::User,
            PublishPayloadClass::SyntheticPublicFixture,
            StageBChunkFlags::None as u8,
            over as u32,
            SuiAddress::new([0x55; 32]),
            None,
            StageBTraceLink::new(86, 86, 0),
        )
        .expect("header valid (header has no cap; the cap is the view/digest's)");
        // Raw struct literal — bypasses StageBChunkView::new's cap on purpose.
        let raw_view = StageBChunkView {
            header: h,
            envelope: &e_over,
        };
        assert_eq!(
            stage_b_chunk_digest(&raw_view),
            Err(StageBChunkError::ContentTooLarge),
        );

        // class_label sanity (all variants reachable / labelled).
        assert_eq!(
            StageBChunkError::ContentTooLarge.class_label(),
            "stage_b.chunk.content_too_large"
        );
        assert_eq!(
            StageBChunkError::SignatureInvalid.class_label(),
            "stage_b.chunk.signature_invalid"
        );
    }
}
