//! Locally derived Walrus blob identifiers.
//!
//! The publisher's text-only [`PublisherReportedBlobId`] is *self-reported*
//! and not trusted by `c-walrus`. This module promotes it to a
//! [`VerifiedBlobId`] only after a local byte-for-byte match against
//! [`derive_blob_id`] — the Walrus-side self-report ban.
//!
//! # Invariants
//!
//! * **No self-report acceptance.** [`VerifiedBlobId`] has no public
//!   constructor. The only way a caller can obtain one is via a successful
//!   [`verify_reported_blob_id`] where the locally derived 32-byte id
//!   matches the publisher's reported text byte-for-byte. A corrupt or
//!   substituted server response cannot synthesise a `VerifiedBlobId`.
//! * **Zero-copy derivation.** [`derive_blob_id`] reads the input slice
//!   directly. No `Vec::with_capacity`, no `to_owned`, no allocator entry.
//!   The only output is the 32-byte [`BlobId`] on the caller stack.
//! * **AI-HOT marker.** [`derive_blob_id`] carries an `// AI-HOT` comment.
//!   Throughput is measured by `benches/blob_id.rs` (criterion infra is
//!   carried alongside the codec bench; this module
//!   keeps the source marker so the future bench knows where to point).
//! * **Anchor trust root.** Once `b-memory` chains a chunk to an on-chain
//!   anchor, the anchor's `blob_id` field is matched against a locally
//!   derived id via this module; an inconsistent server response is
//!   refused before any reference can leak into the memory store.
//!
//! # Phase 0 derivation algorithm — placeholder, later swap
//!
//! Real Walrus blob ids are derived from a Reed-Solomon-encoded sliver tree
//! whose root hash uses BLAKE2b-256; that algorithm is not committed to
//! disk inside this offline workspace. So the derivation **body** is
//! implemented here as a
//! deterministic 32-byte content-addressable digest built from public
//! SHA-256 IV constants and a ChaCha-style quarter-round permutation.
//! The digest is:
//!
//! * **Deterministic** — same input slice ⇒ identical 32 bytes.
//! * **Domain-separated** — XORs `DOMAIN_TAG_V0 = b"WALRUSv0"` into the
//!   lanes so a future placeholder version (`v1`, real Walrus) cannot
//!   accidentally collide.
//! * **Length-prefixed** — the body length is absorbed before the bytes,
//!   so an extension attack (`f(content) == f(content || pad)`) is
//!   diffused by the final permutation rounds.
//! * **No-deps + no-unsafe** — uses only stack arrays and arithmetic; the
//!   crate-level `#![deny(unsafe_code)]` is preserved.
//!
//! The `feature = "net-testnet"` build is the canonical seam where
//! this placeholder is swapped for the real Walrus algorithm; the public
//! signature of [`derive_blob_id`] is byte-stable across the swap (input
//! `&[u8]`, output `BlobId([u8; 32])`).

use crate::codec::{BLOB_ID_BYTES, BlobId};
use crate::publisher::PublisherReportedBlobId;

// ===========================================================================
// 1. Wire / text constants
// ===========================================================================

/// Length, in ASCII bytes, of a canonical Walrus blob-id text token when
/// encoded as URL-safe base64 without padding (RFC 4648 §5). 32 raw bytes
/// require `ceil(32 * 4 / 3) = 43` base64 characters.
pub const WALRUS_BLOB_ID_TEXT_LEN_BASE64URL: usize = 43;

/// Domain-separation tag absorbed into every [`derive_blob_id`] invocation.
/// The 8-byte ASCII string `"WALRUSv0"` marks the Phase 0 placeholder
/// algorithm; a later version introduces a different tag (`v1` or the real
/// Walrus domain) so the swap is visible at the byte level.
pub const DOMAIN_TAG_V0: [u8; 8] = *b"WALRUSv0";

// ===========================================================================
// 2. Error type
// ===========================================================================

/// Reasons `verify_reported_blob_id` refuses to promote a
/// [`PublisherReportedBlobId`] to a [`VerifiedBlobId`].
///
/// Mirrors the `Copy` + `non_exhaustive` + `class_label()` discipline used
/// by [`crate::codec::ChunkCodecError`] and
/// [`crate::publisher::PublisherClientError`].
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
#[non_exhaustive]
pub enum BlobIdError {
    /// The reported text was not exactly
    /// [`WALRUS_BLOB_ID_TEXT_LEN_BASE64URL`] ASCII bytes long. The
    /// observed length is reported so diagnostics can name the drift.
    LengthMismatch {
        /// Number of bytes in the reported text token.
        observed: usize,
    },
    /// The reported text was the correct length but contained at least one
    /// character outside the URL-safe base64 alphabet (`A-Z`, `a-z`,
    /// `0-9`, `-`, `_`).
    Base64Decode,
    /// Decode succeeded but the locally derived 32-byte blob id and the
    /// publisher's reported 32 bytes differed in at least one position.
    /// This is the self-report-refusal trigger.
    RootMismatch,
    /// (`net-testnet` only) The official Walrus RS2 blob-id oracle
    /// ([`crate::blob_id_rs2`]) could not compute a local id
    /// for `content` (the blob exceeds the encoding's maximum size). Distinct
    /// from [`Self::RootMismatch`]: no comparison was possible, so the reported
    /// id is neither accepted nor proven wrong. Only constructible on the
    /// `net-testnet` official-oracle verify path
    /// ([`crate::blob_id_rs2::verify_reported_testnet_blob_id`]); the default
    /// placeholder verify never yields it.
    #[cfg(feature = "net-testnet")]
    OracleUnavailable,
}

impl BlobIdError {
    /// Stable, allow-listed `class_label` for diagnostic JSON envelopes.
    /// Namespaced under `blob_id.*` so consumer logs can filter on a
    /// single prefix.
    #[inline]
    pub const fn class_label(self) -> &'static str {
        match self {
            Self::LengthMismatch { .. } => "blob_id.length_mismatch",
            Self::Base64Decode => "blob_id.base64_decode",
            Self::RootMismatch => "blob_id.root_mismatch",
            #[cfg(feature = "net-testnet")]
            Self::OracleUnavailable => "blob_id.oracle_unavailable",
        }
    }
}

// ===========================================================================
// 3. VerifiedBlobId
// ===========================================================================

/// A [`BlobId`] that has been verified against the publisher's reported
/// text by local derivation. The wrapped field is **private**; the only
/// way to construct a `VerifiedBlobId` outside this module is to call
/// [`verify_reported_blob_id`] and have it return `Ok`.
///
/// This is the type that `b-memory` and the anchor pipeline accept as a
/// trust root; never accept a bare `BlobId` from a server.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
#[repr(transparent)]
pub struct VerifiedBlobId(BlobId);

impl VerifiedBlobId {
    /// Borrow the verified 32-byte id. The returned reference is good for
    /// the lifetime of `self` and never exposes the internal field.
    #[inline]
    pub const fn as_blob_id(&self) -> &BlobId {
        &self.0
    }

    /// (`net-testnet` only) Crate-internal promotion used by the official Walrus
    /// RS2 verify seam ([`crate::blob_id_rs2::verify_reported_testnet_blob_id`])
    /// to wrap a **locally derived** id after it has matched
    /// the publisher's reported bytes byte-for-byte. Mirrors the
    /// `Ok(VerifiedBlobId(derived))` promotion in [`verify_reported_blob_id`]:
    /// there is still **no public constructor**, so a server response can never
    /// synthesise a `VerifiedBlobId` — the self-report ban is preserved.
    #[cfg(feature = "net-testnet")]
    #[inline]
    pub(crate) const fn from_local_derivation(id: BlobId) -> Self {
        Self(id)
    }
}

// ===========================================================================
// 4. derive_blob_id — Phase 0 placeholder, AI-HOT
// ===========================================================================

// SHA-256 initial-hash constants (well-known public IV). We borrow them as
// "random-looking" lane seeds; no cryptographic claim is made.
const IV: [u64; 4] = [
    0x6a09_e667_f3bc_c908,
    0xbb67_ae85_84ca_a73b,
    0x3c6e_f372_fe94_f82b,
    0xa54f_f53a_5f1d_36f1,
];

/// Locally derive a 32-byte Walrus blob id from `content`.
///
/// **AI-HOT.** Phase 0 placeholder algorithm — see the module-level
/// docstring for the swap point (`feature = "net-testnet"`). The function is
/// zero-copy on `content`:
/// the only allocation is the 32-byte [`BlobId`] on the caller stack.
#[inline]
pub fn derive_blob_id(content: &[u8]) -> BlobId {
    // AI-HOT: criterion target `benches/blob_id.rs` (the marker
    // pre-pins the seam).
    let tag = u64::from_le_bytes(DOMAIN_TAG_V0);
    let mut lanes: [u64; 4] = [
        IV[0] ^ tag,
        IV[1] ^ tag.rotate_left(13),
        IV[2] ^ tag.rotate_left(29),
        IV[3] ^ tag.rotate_left(47),
    ];
    // Length-prefix absorbed before the body so that extension attacks
    // (`f(content) == f(content || pad)`) are diffused by the final
    // permutation rounds.
    lanes[0] = lanes[0].wrapping_add(content.len() as u64);
    permute(&mut lanes);

    // Absorb body in 32-byte blocks. We read directly from `content`
    // (no intermediate `Vec`); the last partial block is zero-extended
    // into a stack array. The four absorb lines are unrolled — both for
    // AI-HOT readability of the hot path and to satisfy clippy
    // `needless_range_loop` (the bound `0..4` is structural, not data).
    let total = content.len();
    let mut offset = 0usize;
    while offset + 32 <= total {
        lanes[0] ^= read_u64_le(content, offset);
        lanes[1] ^= read_u64_le(content, offset + 8);
        lanes[2] ^= read_u64_le(content, offset + 16);
        lanes[3] ^= read_u64_le(content, offset + 24);
        permute(&mut lanes);
        offset += 32;
    }
    if offset < total {
        let mut tail = [0u8; 32];
        let rem = total - offset;
        // Bounded by `rem <= 32`; `copy_from_slice` checks length at
        // runtime — no `unsafe` needed.
        tail[..rem].copy_from_slice(&content[offset..]);
        lanes[0] ^= read_u64_le(&tail, 0);
        lanes[1] ^= read_u64_le(&tail, 8);
        lanes[2] ^= read_u64_le(&tail, 16);
        lanes[3] ^= read_u64_le(&tail, 24);
        permute(&mut lanes);
    }

    // Finalise: two extra permutation rounds to diffuse the last block.
    permute(&mut lanes);
    permute(&mut lanes);

    let mut out = [0u8; BLOB_ID_BYTES];
    out[0..8].copy_from_slice(&lanes[0].to_le_bytes());
    out[8..16].copy_from_slice(&lanes[1].to_le_bytes());
    out[16..24].copy_from_slice(&lanes[2].to_le_bytes());
    out[24..32].copy_from_slice(&lanes[3].to_le_bytes());
    BlobId(out)
}

/// Read 8 bytes at `start..start+8` as a little-endian `u64`. The caller
/// guarantees the slice has enough bytes; otherwise the
/// `try_into().unwrap_or(...)` fallback (allowed pattern — see
/// `try_into_or_zero`) yields zero rather than panicking, but we always
/// invoke it with sufficient bytes.
#[inline]
fn read_u64_le(buf: &[u8], start: usize) -> u64 {
    let mut block = [0u8; 8];
    block.copy_from_slice(&buf[start..start + 8]);
    u64::from_le_bytes(block)
}

/// One round of a ChaCha-style quarter-round on four `u64` lanes. Pure
/// add-rotate-xor (ARX); deterministic; no unsafe; no allocation.
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

// ===========================================================================
// 5. verify_reported_blob_id — self-report refusal
// ===========================================================================

/// Verify the publisher's reported text id by re-deriving it locally and
/// comparing all 32 bytes. Returns:
///
/// * `Err(BlobIdError::LengthMismatch { observed })` if the reported text
///   is not exactly [`WALRUS_BLOB_ID_TEXT_LEN_BASE64URL`] bytes.
/// * `Err(BlobIdError::Base64Decode)` if the reported text contains any
///   character outside `A-Z a-z 0-9 - _`.
/// * `Err(BlobIdError::RootMismatch)` if the reported decoded bytes differ
///   from the locally derived id in **any** of the 32 positions.
/// * `Ok(VerifiedBlobId)` wrapping the **locally derived** id on success
///   (not the reported bytes — they are discarded once they have served
///   as the equality witness).
pub fn verify_reported_blob_id(
    content: &[u8],
    reported: &PublisherReportedBlobId,
) -> Result<VerifiedBlobId, BlobIdError> {
    let text = reported.as_str();
    if text.len() != WALRUS_BLOB_ID_TEXT_LEN_BASE64URL {
        return Err(BlobIdError::LengthMismatch {
            observed: text.len(),
        });
    }
    let reported_bytes = decode_base64url_no_pad_32(text).ok_or(BlobIdError::Base64Decode)?;
    let derived = derive_blob_id(content);
    if derived.as_bytes() != &reported_bytes {
        return Err(BlobIdError::RootMismatch);
    }
    Ok(VerifiedBlobId(derived))
}

/// Decode exactly [`WALRUS_BLOB_ID_TEXT_LEN_BASE64URL`] URL-safe base64
/// characters (no padding) into 32 raw bytes. Returns `None` on any
/// non-alphabet character. The trailing 2 bits of the 43-character input
/// (43 * 6 - 32 * 8 = 2) are not validated as zero — that strictness is
/// deferred to the network feature where the encoding is pinned by a real round-trip.
///
/// `pub(crate)` (visibility-only widening) so the
/// `net-testnet` official-oracle verify seam ([`crate::blob_id_rs2`]) reuses the
/// exact same reported-text decoder rather than minting a second base64 path.
/// The function body and the default-build output are byte-identical.
/// Parse a base64url-no-pad Walrus blob-id TEXT (43 chars) into a [`BlobId`] — the
/// public 32-byte content address. `None` on a malformed text. This lets a client
/// FETCH a blob by a STORED id (no content in hand); the fetched bytes' integrity is
/// the AEAD tag on those bytes, not this id.
#[must_use]
pub fn blob_id_from_text(text: &str) -> Option<BlobId> {
    decode_base64url_no_pad_32(text).map(BlobId)
}

#[inline]
pub(crate) fn decode_base64url_no_pad_32(s: &str) -> Option<[u8; 32]> {
    let bytes = s.as_bytes();
    if bytes.len() != WALRUS_BLOB_ID_TEXT_LEN_BASE64URL {
        return None;
    }
    let mut out = [0u8; 32];
    let mut out_idx = 0usize;
    let mut buf: u32 = 0;
    let mut bits: u32 = 0;
    for &c in bytes {
        let v = match c {
            b'A'..=b'Z' => c - b'A',
            b'a'..=b'z' => c - b'a' + 26,
            b'0'..=b'9' => c - b'0' + 52,
            b'-' => 62,
            b'_' => 63,
            _ => return None,
        };
        buf = (buf << 6) | (v as u32);
        bits += 6;
        if bits >= 8 && out_idx < 32 {
            bits -= 8;
            out[out_idx] = ((buf >> bits) & 0xFF) as u8;
            out_idx += 1;
        }
    }
    if out_idx == 32 { Some(out) } else { None }
}

/// Encode 32 raw bytes as URL-safe base64 (no padding); inverse of
/// [`decode_base64url_no_pad_32`]. Produces exactly
/// [`WALRUS_BLOB_ID_TEXT_LEN_BASE64URL`] (43) characters.
///
/// Canonical blob-id text encoder: the
/// aggregator GET URL composition
/// ([`AggregatorGetUrl::compose`](crate::aggregator::AggregatorGetUrl::compose))
/// addresses a blob by its URL-safe base64 id — the exact form the real Walrus
/// testnet aggregator parses — rather than by hex. Visibility widened from the
/// prior `#[cfg(test)] pub(crate)`; the function body and the default-build
/// output are byte-identical.
#[inline]
pub fn encode_base64url_no_pad_32(raw: &[u8; 32]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut out = String::with_capacity(WALRUS_BLOB_ID_TEXT_LEN_BASE64URL);
    let mut buf: u32 = 0;
    let mut bits: u32 = 0;
    for &b in raw {
        buf = (buf << 8) | (b as u32);
        bits += 8;
        while bits >= 6 {
            bits -= 6;
            let v = ((buf >> bits) & 0x3F) as usize;
            out.push(ALPHABET[v] as char);
        }
    }
    if bits > 0 {
        let v = ((buf << (6 - bits)) & 0x3F) as usize;
        out.push(ALPHABET[v] as char);
    }
    out
}

// ===========================================================================
// 6. Compile-time reuse markers
// ===========================================================================

// Pin the cross-module byte invariant: `BLOB_ID_BYTES == 32`
// and `WALRUS_BLOB_ID_TEXT_LEN_BASE64URL == 43`
// (ceil(32 * 4 / 3)). A future drift on either side is caught at compile
// time by a zero-length array index.
const _BLOB_ID_REUSES_ATOM7_32: [(); 0 - !(BLOB_ID_BYTES == 32) as usize] = [];
const _TEXT_LEN_MATCHES_BASE64URL_OF_32: [(); 0 - !(WALRUS_BLOB_ID_TEXT_LEN_BASE64URL
    == (32usize * 4).div_ceil(3)) as usize] = [];

// ===========================================================================
// 7. Inline unit tests
// ===========================================================================

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    #![allow(clippy::expect_used)]
    #![allow(clippy::panic)]

    use super::*;

    #[test]
    fn derive_blob_id_is_deterministic_on_repeated_calls() {
        let content = b"the mnemos chunk that is to be persisted";
        let a = derive_blob_id(content);
        let b = derive_blob_id(content);
        assert_eq!(a, b);
    }

    #[test]
    fn derive_blob_id_is_length_sensitive() {
        let a = derive_blob_id(b"abc");
        let b = derive_blob_id(b"abcd");
        assert_ne!(a, b, "extending the input must change the digest");
    }

    #[test]
    fn derive_blob_id_is_byte_sensitive() {
        let a = derive_blob_id(b"abcd");
        let b = derive_blob_id(b"abce");
        assert_ne!(
            a, b,
            "flipping any byte of the input must change the digest"
        );
    }

    #[test]
    fn empty_content_yields_a_stable_digest() {
        // Stability across runs is what matters here; the exact value is
        // recorded once and pinned by `c0_4_derive_matches_known_vector`
        // (integration test) plus the Python oracle. We only re-check it
        // is non-zero (a zero output would indicate a missing absorb step).
        let id = derive_blob_id(b"");
        assert_ne!(id.as_bytes(), &[0u8; 32]);
    }

    #[test]
    fn blob_id_error_class_labels_are_namespaced_under_blob_id() {
        assert_eq!(
            BlobIdError::LengthMismatch { observed: 0 }.class_label(),
            "blob_id.length_mismatch"
        );
        assert_eq!(
            BlobIdError::Base64Decode.class_label(),
            "blob_id.base64_decode"
        );
        assert_eq!(
            BlobIdError::RootMismatch.class_label(),
            "blob_id.root_mismatch"
        );
    }

    #[test]
    fn base64url_round_trip_on_random_looking_id_bytes() {
        let mut raw = [0u8; 32];
        for (i, slot) in raw.iter_mut().enumerate() {
            *slot = (i as u8).wrapping_mul(37).wrapping_add(11);
        }
        let text = encode_base64url_no_pad_32(&raw);
        assert_eq!(text.len(), WALRUS_BLOB_ID_TEXT_LEN_BASE64URL);
        let decoded = decode_base64url_no_pad_32(&text).expect("alphabet check");
        assert_eq!(decoded, raw);
    }

    #[test]
    fn decode_rejects_non_alphabet_character() {
        let mut text = "A".repeat(WALRUS_BLOB_ID_TEXT_LEN_BASE64URL);
        // Replace one ASCII char with `*` (outside URL-safe alphabet).
        text.replace_range(10..11, "*");
        assert!(decode_base64url_no_pad_32(&text).is_none());
    }

    #[test]
    fn decode_rejects_wrong_length() {
        let too_short = "A".repeat(WALRUS_BLOB_ID_TEXT_LEN_BASE64URL - 1);
        assert!(decode_base64url_no_pad_32(&too_short).is_none());
        let too_long = "A".repeat(WALRUS_BLOB_ID_TEXT_LEN_BASE64URL + 1);
        assert!(decode_base64url_no_pad_32(&too_long).is_none());
    }

    #[test]
    fn verified_blob_id_is_repr_transparent_over_blob_id() {
        // The wrapped field is private but the layout must be byte-equal
        // to `BlobId([u8; 32])` so the network swap can store
        // verified ids without a wider wire representation.
        assert_eq!(
            core::mem::size_of::<VerifiedBlobId>(),
            core::mem::size_of::<BlobId>()
        );
    }
}
