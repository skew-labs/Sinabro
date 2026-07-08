//! `stage_b_blob_id.rs` — the Stage B **local** Walrus blob-id
//! derivation and verification seam.
//!
//! This module mints two entry points:
//!
//! * [`derive_walrus_blob_id`]: the single Stage B name for "compute
//!   the blob id of a chunk **from the local encoded bytes**, never from what a
//!   server says". It is a **thin wrapper** over Stage A's
//!   [`derive_blob_id`](mnemos_c_walrus::derive_blob_id) —
//!   Stage B mints **no** second derivation algorithm, mirroring how
//!   [`encode_stage_b_chunk`](crate::encode_stage_b_chunk) is a thin wrapper over
//!   Stage A's `encode_chunk_v1`.
//! * [`stage_b_verify_blob_id`]: the single Stage B name for "promote
//!   a publisher's *self-reported* blob-id text to a
//!   [`VerifiedBlobId`](mnemos_c_walrus::VerifiedBlobId) **only** when it matches
//!   the local derivation byte-for-byte". It is a **thin wrapper** over Stage A's
//!   [`verify_reported_blob_id`](mnemos_c_walrus::verify_reported_blob_id) (the
//!   self-report-refusal seam), whose internal derivation is the
//!   same algorithm [`derive_walrus_blob_id`] exposes — Stage B mints **no**
//!   second verify path and **no** second base64 decoder. This is the **only**
//!   path that can construct a `VerifiedBlobId` from a reported id.
//!
//! # Key invariant
//!
//! > blob id derives from local bytes. Server is not an oracle.
//!
//! The id this function returns is a pure function of the `&[u8]` the caller
//! holds locally — the canonical Stage B chunk wire produced by
//! [`encode_stage_b_chunk`]. A Walrus publisher's *self-reported* blob-id text
//! (`PublisherReportedBlobId`) is **never** consulted here: it is
//! only ever compared against this local derivation at the verify seam
//! (`stage_b_verify_blob_id`), which is the **only** path that can promote a
//! reported id to a `VerifiedBlobId`. So a corrupt or substituted server response
//! cannot move the derived id by a single bit — the server is not an oracle.
//!
//! # Scope
//!
//! Derivation only. This module does **not**:
//!
//! * verify a reported id or construct a
//!   [`VerifiedBlobId`](mnemos_c_walrus::VerifiedBlobId) — that is
//!   [`stage_b_verify_blob_id`], which calls this function and then matches the
//!   result byte-for-byte against the publisher's reported text;
//! * open a socket or touch the network (holds by
//!   construction — the function is pure and total over `&[u8]`);
//! * mint a new error type — derivation is total (every `&[u8]`, including the
//!   empty slice, yields a 32-byte id), so the signature returns a bare
//!   [`BlobId`] with no `Result`.
//!
//! # Reuse (zero reinvention)
//!
//! * [`derive_blob_id`](mnemos_c_walrus::derive_blob_id) — the canonical placeholder
//!   blob-id derivation (domain-separated, length-prefixed ARX digest; the real
//!   Walrus Reed-Solomon / BLAKE2b algorithm is swapped in at the `c-walrus`
//!   `feature = "net-testnet"` seam, with the `&[u8] -> BlobId`
//!   signature byte-stable across the swap). The wrapper delegates verbatim.
//! * [`BlobId`](mnemos_c_walrus::BlobId) — the 32-byte id type, returned
//!   unchanged (no Stage-B-specific id newtype).
//! * [`encode_stage_b_chunk`](crate::encode_stage_b_chunk) — the production
//!   caller that produces the `encoded_chunk` bytes this function derives from.
//!
//! No new dependency, no new wire format, no new error type.

use mnemos_c_walrus::{
    BlobId, BlobIdError, PublisherReportedBlobId, VerifiedBlobId, derive_blob_id,
    verify_reported_blob_id,
};

/// Locally derive the 32-byte Walrus [`BlobId`] of a Stage B chunk from its
/// **canonical encoded bytes**.
///
/// A **thin, zero-cost wrapper** over Stage A's [`derive_blob_id`]: it forwards
/// the borrow straight through with no extra allocation, copy or branch, so the
/// derived id is byte-identical to Stage A's canonical derivation of the same
/// bytes — Stage B mints no second algorithm.
///
/// `encoded_chunk` is the canonical Stage B chunk wire produced by
/// [`encode_stage_b_chunk`](crate::encode_stage_b_chunk) — the exact bytes a
/// memory owner PUTs to Walrus. Deriving from these local bytes (rather than
/// trusting the publisher's reported id text) is the "server is not an oracle"
/// invariant: the verify seam
/// ([`stage_b_verify_blob_id`](crate::stage_b_blob_id)) promotes a reported id to
/// a `VerifiedBlobId` only when it matches this local derivation byte-for-byte.
///
/// The derivation is total: every `&[u8]` — including the empty slice — yields a
/// 32-byte id, so there is no error path.
#[inline]
pub fn derive_walrus_blob_id(encoded_chunk: &[u8]) -> BlobId {
    // AI-HOT: derive throughput is measured by `benches/stage_b_blob_id.rs`
    // (criterion sweep + baseline emitter). The hot work is entirely
    // inside Stage A's `derive_blob_id` (zero-copy ARX over `encoded_chunk`); this
    // wrapper adds no allocation, copy or branch.
    derive_blob_id(encoded_chunk)
}

/// Verify a publisher's *self-reported* Walrus blob-id text against the **local**
/// derivation of `encoded_chunk`, promoting it to a [`VerifiedBlobId`] only on an
/// exact 32-byte match.
///
/// A **thin, zero-cost wrapper** over Stage A's
/// [`verify_reported_blob_id`](mnemos_c_walrus::verify_reported_blob_id) (the
/// self-report-refusal seam): it forwards the borrow straight through, so
/// Stage B mints **no** second verify path, **no** second base64 decoder, and
/// **no** new error type. The internal local derivation Stage A performs is the
/// exact same algorithm [`derive_walrus_blob_id`] exposes (both call Stage A's
/// `derive_blob_id` over the same bytes), so this verify is consistent with the
/// Stage B derive by construction.
///
/// This is the **only** path that can construct a `VerifiedBlobId` from a
/// publisher-reported id: the wrapped `BlobId` field is private to `c-walrus`,
/// and the returned value wraps the **locally derived** id (not the reported
/// bytes — they are discarded once they have served as the equality witness). So
/// a corrupt or substituted server response can never become a trust root: the
/// server is not an oracle.
///
/// `encoded_chunk` is the canonical Stage B chunk wire produced by
/// [`encode_stage_b_chunk`](crate::encode_stage_b_chunk) — the exact bytes the
/// memory owner PUT to Walrus. `reported` is the publisher's
/// [`PublisherReportedBlobId`](mnemos_c_walrus::PublisherReportedBlobId) text
/// (the Stage B PUT-response parser yields the reported token; wiring
/// that token into a `PublisherReportedBlobId` is the caller/round-trip seam —
/// out of scope here).
///
/// # Errors
/// Returns the Stage A [`BlobIdError`](mnemos_c_walrus::BlobIdError) verbatim
/// (Stage B adds no variant):
/// * `BlobIdError::LengthMismatch { observed }` — reported text is not the fixed
///   base64url id length;
/// * `BlobIdError::Base64Decode` — reported text has a non-URL-safe-base64
///   character;
/// * `BlobIdError::RootMismatch` — reported bytes decode cleanly but differ from
///   the local derivation in at least one of the 32 positions (the
///   self-report-refusal trigger).
#[inline]
pub fn stage_b_verify_blob_id(
    encoded_chunk: &[u8],
    reported: &PublisherReportedBlobId,
) -> Result<VerifiedBlobId, BlobIdError> {
    verify_reported_blob_id(encoded_chunk, reported)
}

// ===========================================================================
// official Walrus RS2 oracle (net-testnet)
// ===========================================================================
//
// The two functions above are the **placeholder** derive/verify and are
// byte-identical under both builds. This section adds the **official**
// Walrus testnet (`n_shards = 1000`) oracle on **new** names, gated behind
// `net-testnet`, as thin wrappers over the isolated c-walrus adapter
// `mnemos_c_walrus::blob_id_rs2`. The live GET + verify path consumes
// these to promote the live-PUT reported id to a real `VerifiedBlobId`; the
// existing `derive_walrus_blob_id` / `stage_b_verify_blob_id` are left untouched.

#[cfg(feature = "net-testnet")]
use mnemos_c_walrus::blob_id_rs2::{
    WalrusOracleError, derive_testnet_blob_id, verify_reported_testnet_blob_id,
};

/// (`net-testnet` only) Locally derive the **official** Walrus [`BlobId`] of a
/// Stage B chunk's bytes for the testnet `n_shards = 1000` committee.
///
/// A **thin, zero-cost wrapper** over the c-walrus official-oracle adapter
/// [`derive_testnet_blob_id`](mnemos_c_walrus::blob_id_rs2::derive_testnet_blob_id):
/// it forwards the borrow straight through, so the derived id is byte-identical
/// to `walrus blob-id --n-shards 1000` over the same bytes — Stage B mints no
/// second oracle. This is the real RS2/RedStuff-metadata -> Blake2b256
/// Merkle-root -> blob-id rule, **not** the placeholder
/// [`derive_walrus_blob_id`] exposes.
///
/// `encoded_chunk` is the exact local byte string that was PUT to Walrus.
///
/// # Errors
/// [`WalrusOracleError::EncodingTooLarge`](mnemos_c_walrus::blob_id_rs2::WalrusOracleError::EncodingTooLarge)
/// if the bytes exceed the encoding's maximum blob size (the only failure mode
/// of the upstream encoder; Stage B chunks are bounded well under it).
#[cfg(feature = "net-testnet")]
#[inline]
pub fn derive_walrus_testnet_blob_id(encoded_chunk: &[u8]) -> Result<BlobId, WalrusOracleError> {
    derive_testnet_blob_id(encoded_chunk)
}

/// (`net-testnet` only) Verify a publisher's *self-reported* Walrus blob-id text
/// against the **official RS2 oracle** derivation of `encoded_chunk`, promoting
/// it to a [`VerifiedBlobId`] only on an exact 32-byte match.
///
/// A **thin, zero-cost wrapper** over the c-walrus official-oracle verify seam
/// [`verify_reported_testnet_blob_id`](mnemos_c_walrus::blob_id_rs2::verify_reported_testnet_blob_id).
/// The `net-testnet` counterpart of [`stage_b_verify_blob_id`]: identical
/// reported-text validation, but the local id is re-derived with the **real**
/// Walrus oracle instead of the placeholder. It is the path
/// used to promote the live-PUT reported id to a trust root, and like the
/// placeholder verify it returns the **locally derived** id (the reported bytes
/// are discarded once they have served as the equality witness — server is not
/// an oracle).
///
/// # Errors
/// Returns the c-walrus [`BlobIdError`](mnemos_c_walrus::BlobIdError) verbatim:
/// * `LengthMismatch { observed }` / `Base64Decode` — reported-text validation;
/// * `RootMismatch` — reported bytes decode cleanly but differ from the
///   official-oracle derivation (self-report refusal);
/// * `OracleUnavailable` — the oracle could not derive a local id for the bytes
///   (oversized blob), so no comparison was possible.
#[cfg(feature = "net-testnet")]
#[inline]
pub fn stage_b_verify_testnet_blob_id(
    encoded_chunk: &[u8],
    reported: &PublisherReportedBlobId,
) -> Result<VerifiedBlobId, BlobIdError> {
    verify_reported_testnet_blob_id(encoded_chunk, reported)
}

#[cfg(test)]
mod tests {
    // Test helpers prefer direct failure surfaces over `Result`-bubbling;
    // suppress prod-only clippy denies inside this module.
    #![allow(clippy::unwrap_used)]
    #![allow(clippy::expect_used)]
    #![allow(clippy::panic)]

    use super::*;

    /// The known-vector input. Pinned cross-language: the expected
    /// digest below is computed by a Python oracle replicating
    /// `c-walrus::blob_id::derive_blob_id`, and re-checked here by
    /// the Rust derivation — a drift on either side fails this test.
    const KNOWN_INPUT: &[u8] = b"mnemos atom 107 derive walrus blob id known vector";

    /// Python-oracle-computed digest of [`KNOWN_INPUT`] (len 50). If the Rust
    /// `derive_walrus_blob_id` ever drifts from the pinned algorithm, this
    /// 32-byte vector stops matching.
    const KNOWN_EXPECTED: [u8; 32] = [
        0x0e, 0x67, 0x42, 0x3d, 0x18, 0xd1, 0x02, 0x74, 0xa0, 0xa8, 0x25, 0x0f, 0x6a, 0x12, 0xb7,
        0xc0, 0xe0, 0xa9, 0xbf, 0xb7, 0xcf, 0x1b, 0xe4, 0xdb, 0x26, 0xe1, 0x2b, 0x5d, 0xd1, 0x97,
        0x09, 0xf6,
    ];

    /// Python-oracle-computed digest of the **empty** slice `b""`. Pinned so the
    /// "empty bytes vector" case is a known vector, not merely a non-panic check.
    const EMPTY_EXPECTED: [u8; 32] = [
        0x4b, 0xd2, 0x7c, 0x39, 0x76, 0xd3, 0x05, 0xaa, 0x5f, 0xdd, 0x45, 0xf5, 0x46, 0xcd, 0xe5,
        0x20, 0xe5, 0x50, 0x6c, 0x02, 0xcf, 0x6d, 0xed, 0xa5, 0x92, 0x31, 0x23, 0x88, 0x12, 0xfd,
        0xac, 0xf0,
    ];

    /// `known vector` — the derived id equals the cross-language Python oracle
    /// vector, and is byte-identical to Stage A's `derive_blob_id` on the same
    /// bytes (the thin-wrapper faithfulness invariant).
    #[test]
    fn b2_6_derive_matches_known_vector() {
        let id = derive_walrus_blob_id(KNOWN_INPUT);
        assert_eq!(
            id.as_bytes(),
            &KNOWN_EXPECTED,
            "derive_walrus_blob_id drifted from the pinned Python-oracle vector"
        );
        // Faithful thin wrapper: Stage B derive == Stage A derive on same bytes.
        assert_eq!(
            id.as_bytes(),
            derive_blob_id(KNOWN_INPUT).as_bytes(),
            "Stage B wrapper must equal Stage A derive_blob_id byte-for-byte"
        );
    }

    /// `bitflip changes id` — flipping a single bit of the input moves the
    /// derived id (the server cannot substitute bytes without moving the id).
    #[test]
    fn b2_6_bitflip_changes_id() {
        let mut flipped = KNOWN_INPUT.to_vec();
        let last = flipped.len() - 1;
        flipped[last] ^= 0x01;
        let id = derive_walrus_blob_id(KNOWN_INPUT);
        let id_flipped = derive_walrus_blob_id(&flipped);
        assert_ne!(
            id.as_bytes(),
            id_flipped.as_bytes(),
            "a one-bit input change must change the derived blob id"
        );
    }

    /// `empty bytes vector` — the empty slice derives to a stable, non-zero,
    /// pinned vector (a zero output would signal a missing absorb step), and
    /// matches Stage A's derive on `b""`.
    #[test]
    fn b2_6_empty_bytes_vector() {
        let id = derive_walrus_blob_id(b"");
        assert_eq!(
            id.as_bytes(),
            &EMPTY_EXPECTED,
            "empty-slice derive drifted from the pinned Python-oracle vector"
        );
        assert_ne!(
            id.as_bytes(),
            &[0u8; 32],
            "empty-slice derive must not be all-zero"
        );
        assert_eq!(
            id.as_bytes(),
            derive_blob_id(b"").as_bytes(),
            "Stage B empty derive must equal Stage A derive_blob_id(b\"\")"
        );
    }

    /// Determinism — same input slice yields an identical id across calls.
    #[test]
    fn b2_6_derive_is_deterministic() {
        assert_eq!(
            derive_walrus_blob_id(KNOWN_INPUT),
            derive_walrus_blob_id(KNOWN_INPUT)
        );
    }

    /// Faithful wrapper across a content-size ladder — at every size the Stage B
    /// derive equals the Stage A canonical derive byte-for-byte (no Stage-B-only
    /// reframing of the input bytes).
    #[test]
    fn b2_6_wrapper_is_faithful_across_size_ladder() {
        for &size in &[0usize, 1, 31, 32, 33, 64, 1 << 10] {
            let buf = vec![0xa5u8; size];
            assert_eq!(
                derive_walrus_blob_id(&buf).as_bytes(),
                derive_blob_id(&buf).as_bytes(),
                "wrapper diverged from Stage A derive at size {size}"
            );
        }
    }

    // ----- reported blob-id verify -----

    /// Test-only URL-safe base64 (no padding) encoder for a 32-byte id — the
    /// faithful inverse of `c-walrus`'s private `decode_base64url_no_pad_32`.
    /// `c-walrus`'s own `encode_base64url_no_pad_32` is `pub(crate)`, so a
    /// cross-crate test cannot call it; this is a test-only duplicate,
    /// used only to synthesize a
    /// *correctly* reported id text so the match-accepted path can be exercised.
    fn base64url_no_pad_encode_32(raw: &[u8; 32]) -> String {
        const ALPHABET: &[u8; 64] =
            b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
        let mut out = String::with_capacity(43);
        let mut buf: u32 = 0;
        let mut bits: u32 = 0;
        for &b in raw {
            buf = (buf << 8) | (b as u32);
            bits += 8;
            while bits >= 6 {
                bits -= 6;
                out.push(ALPHABET[((buf >> bits) & 0x3f) as usize] as char);
            }
        }
        if bits > 0 {
            out.push(ALPHABET[((buf << (6 - bits)) & 0x3f) as usize] as char);
        }
        out
    }

    /// Build a `PublisherReportedBlobId` from the base64url encoding of `id`.
    fn reported_for(id: &BlobId) -> PublisherReportedBlobId {
        let text = base64url_no_pad_encode_32(id.as_bytes());
        PublisherReportedBlobId::try_from_text(&text).unwrap()
    }

    /// `match accepted` — a publisher-reported id that equals the local
    /// derivation promotes to a `VerifiedBlobId` wrapping the **locally derived**
    /// id (not the reported bytes), and the Stage B wrapper returns exactly what
    /// Stage A's `verify_reported_blob_id` returns (thin-wrapper faithfulness).
    #[test]
    fn b2_7_match_accepted() {
        let id = derive_walrus_blob_id(KNOWN_INPUT);
        let reported = reported_for(&id);
        let verified = stage_b_verify_blob_id(KNOWN_INPUT, &reported)
            .expect("a reported id equal to the local derive must verify");
        assert_eq!(
            verified.as_blob_id().as_bytes(),
            &KNOWN_EXPECTED,
            "verified id must wrap the locally derived id, not the reported bytes"
        );
        assert_eq!(
            stage_b_verify_blob_id(KNOWN_INPUT, &reported),
            verify_reported_blob_id(KNOWN_INPUT, &reported),
            "Stage B verify must equal Stage A verify_reported_blob_id on same input"
        );
    }

    /// `mismatch rejected` — a reported id that is the *valid* base64url encoding
    /// of a **different** chunk's id is refused with `RootMismatch` when verified
    /// against these bytes (the publisher cannot substitute another blob's id).
    #[test]
    fn b2_7_mismatch_rejected() {
        // `reported` is the genuine encoding of the EMPTY chunk's id...
        let empty_id = derive_walrus_blob_id(b"");
        let reported = reported_for(&empty_id);
        // ...but we verify it against KNOWN_INPUT, whose derive differs.
        let err = stage_b_verify_blob_id(KNOWN_INPUT, &reported).unwrap_err();
        assert_eq!(err, BlobIdError::RootMismatch);
    }

    /// `malformed reported rejected` (length) — a reported text that is not the
    /// fixed base64url id length is refused with `LengthMismatch` before any
    /// decode, naming the observed length.
    #[test]
    fn b2_7_malformed_length_rejected() {
        let reported = PublisherReportedBlobId::try_from_text("too-short").unwrap();
        let err = stage_b_verify_blob_id(KNOWN_INPUT, &reported).unwrap_err();
        assert_eq!(err, BlobIdError::LengthMismatch { observed: 9 });
    }

    /// `malformed reported rejected` (alphabet) — a reported text of the correct
    /// length but carrying a non-URL-safe-base64 character (`*`) is refused with
    /// `Base64Decode`.
    #[test]
    fn b2_7_malformed_base64_rejected() {
        let id = derive_walrus_blob_id(KNOWN_INPUT);
        let mut text = base64url_no_pad_encode_32(id.as_bytes());
        assert_eq!(
            text.len(),
            43,
            "32-byte id encodes to exactly 43 base64url chars"
        );
        text.replace_range(0..1, "*"); // length stays 43; '*' is outside the alphabet
        let reported = PublisherReportedBlobId::try_from_text(&text).unwrap();
        let err = stage_b_verify_blob_id(KNOWN_INPUT, &reported).unwrap_err();
        assert_eq!(err, BlobIdError::Base64Decode);
    }
}
