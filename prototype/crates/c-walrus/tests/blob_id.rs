//! Integration tests for `mnemos_c_walrus::blob_id` (atom #10 · C.0.4).
//!
//! The four named tests (`c0_4_*`) map verbatim to `MNEMOS_ATOM_PLAN.md`
//! line 894. They are joined by a `proptest!` block covering derivation
//! determinism and the verify-roundtrip, plus a single cross-language
//! known-vector test whose hex literals are produced by the Python oracle
//! at `ops/evidence/phase_0/atom_010/oracle_blob_id_v0.py`.
//!
//! The Phase 0 algorithm implemented by [`derive_blob_id`] is a
//! placeholder; atom #12 (`C.0.6`, `feature = "net-testnet"`) swaps it
//! for the real Walrus encoding rule. At that point the Python oracle and
//! the hex literals below are updated in lockstep — the *invariants*
//! exercised here (zero-copy, deterministic, byte-equal verification, no
//! self-report acceptance) are intentionally algorithm-independent.

#![allow(clippy::unwrap_used)]
#![allow(clippy::expect_used)]
#![allow(clippy::panic)]

use mnemos_c_walrus::blob_id::{
    BlobIdError, DOMAIN_TAG_V0, VerifiedBlobId, WALRUS_BLOB_ID_TEXT_LEN_BASE64URL, derive_blob_id,
    verify_reported_blob_id,
};
use mnemos_c_walrus::codec::{BLOB_ID_BYTES, BlobId};
use mnemos_c_walrus::publisher::PublisherReportedBlobId;

use proptest::prelude::*;

// ---------------------------------------------------------------------------
// Test-local helpers — a minimal base64url-no-pad encoder for fabricating
// `PublisherReportedBlobId` text fixtures inside this integration suite.
// The production module exposes the decoder; the encoder is `cfg(test)`
// + `pub(crate)`, so integration tests reproduce it here (≤30 LoC, no
// allocation beyond the returned `String`).
// ---------------------------------------------------------------------------

const BASE64URL_ALPHABET: &[u8; 64] =
    b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

fn encode_base64url_no_pad_32(raw: &[u8; 32]) -> String {
    let mut out = String::with_capacity(WALRUS_BLOB_ID_TEXT_LEN_BASE64URL);
    let mut buf: u32 = 0;
    let mut bits: u32 = 0;
    for &b in raw {
        buf = (buf << 8) | (b as u32);
        bits += 8;
        while bits >= 6 {
            bits -= 6;
            let v = ((buf >> bits) & 0x3F) as usize;
            out.push(BASE64URL_ALPHABET[v] as char);
        }
    }
    if bits > 0 {
        let v = ((buf << (6 - bits)) & 0x3F) as usize;
        out.push(BASE64URL_ALPHABET[v] as char);
    }
    out
}

fn report_for(content: &[u8]) -> PublisherReportedBlobId {
    let derived = derive_blob_id(content);
    let text = encode_base64url_no_pad_32(derived.as_bytes());
    PublisherReportedBlobId::try_from_text(&text).expect("encoded text fits MAX_REPORTED_BLOB_ID")
}

fn hex_decode_32(hex: &str) -> [u8; BLOB_ID_BYTES] {
    assert_eq!(hex.len(), BLOB_ID_BYTES * 2, "hex literal must be 64 chars");
    let mut out = [0u8; BLOB_ID_BYTES];
    let bytes = hex.as_bytes();
    for i in 0..BLOB_ID_BYTES {
        let hi = parse_hex_nibble(bytes[i * 2]);
        let lo = parse_hex_nibble(bytes[i * 2 + 1]);
        out[i] = (hi << 4) | lo;
    }
    out
}

fn parse_hex_nibble(c: u8) -> u8 {
    match c {
        b'0'..=b'9' => c - b'0',
        b'a'..=b'f' => c - b'a' + 10,
        b'A'..=b'F' => c - b'A' + 10,
        _ => panic!("non-hex character"),
    }
}

// ===========================================================================
// 1. ATOM_PLAN line 894 verbatim test names
// ===========================================================================

/// Locally derived ids match the cross-language known vector produced by
/// `ops/evidence/phase_0/atom_010/oracle_blob_id_v0.py`. Both sides hold
/// the same hex constants on disk so a one-sided drift is caught at the
/// next `cargo test` or Python oracle re-run.
#[test]
fn c0_4_derive_matches_known_vector() {
    // KNOWN_*_HEX values were produced by the Python oracle and are
    // byte-stable as long as the placeholder algorithm holds. atom #12
    // updates both files in lockstep.
    const KNOWN_EMPTY_HEX: &str =
        "4bd27c3976d305aa5fdd45f546cde520e5506c02cf6deda59231238812fdacf0";
    const KNOWN_MNEMOS_HEX: &str =
        "11e9e7adef5d2b9206df156c0447c84bb0a9620f0d25ff257cdf47c3eaf2999d";
    const KNOWN_PHRASE_HEX: &str =
        "550b0c970781754063f298d0c634676b31aed947587bc540a2b7f1e6b51ac787";

    assert_eq!(
        derive_blob_id(b"").as_bytes(),
        &hex_decode_32(KNOWN_EMPTY_HEX),
        "derive(b\"\") must match Python oracle"
    );
    assert_eq!(
        derive_blob_id(b"mnemos").as_bytes(),
        &hex_decode_32(KNOWN_MNEMOS_HEX),
        "derive(b\"mnemos\") must match Python oracle"
    );
    assert_eq!(
        derive_blob_id(b"the mnemos chunk that is to be persisted").as_bytes(),
        &hex_decode_32(KNOWN_PHRASE_HEX),
        "derive(phrase) must match Python oracle"
    );

    // Domain tag is exposed so future placeholder versions or the real
    // Walrus swap (atom #12) reveal themselves at the byte level.
    assert_eq!(&DOMAIN_TAG_V0, b"WALRUSv0");
}

/// A reported text whose decoded bytes differ from the locally derived id
/// in *any* of the 32 positions is rejected with `RootMismatch`. The
/// derivation never trusts the publisher — the local re-derivation is the
/// witness, the reported bytes are the candidate.
#[test]
fn c0_4_reported_mismatch_is_rejected() {
    let content: &[u8] = b"mnemos";
    let truth = derive_blob_id(content);

    // Flip the first byte of the locally derived id and re-encode the
    // corrupt 32 bytes back into a base64url text token. The text is
    // syntactically valid (43 chars, alphabet-clean) but the decoded
    // bytes disagree with the local derivation, so RootMismatch fires.
    let mut tampered = *truth.as_bytes();
    tampered[0] = tampered[0].wrapping_add(1);
    let bad_text = encode_base64url_no_pad_32(&tampered);
    let bad_report =
        PublisherReportedBlobId::try_from_text(&bad_text).expect("tampered text within length cap");

    let err = verify_reported_blob_id(content, &bad_report).expect_err("must reject mismatch");
    assert!(matches!(err, BlobIdError::RootMismatch));
    assert_eq!(err.class_label(), "blob_id.root_mismatch");

    // Spot-check additional positions: flipping the last byte still
    // fails — we are not pattern-matching only the first byte.
    let mut tampered_last = *truth.as_bytes();
    tampered_last[31] = tampered_last[31].wrapping_add(1);
    let last_text = encode_base64url_no_pad_32(&tampered_last);
    let last_report = PublisherReportedBlobId::try_from_text(&last_text).unwrap();
    assert!(matches!(
        verify_reported_blob_id(content, &last_report),
        Err(BlobIdError::RootMismatch)
    ));
}

/// A reported text whose length is anything other than
/// `WALRUS_BLOB_ID_TEXT_LEN_BASE64URL` (43) is rejected with
/// `LengthMismatch` *before* any base64url decode is attempted.
#[test]
fn c0_4_length_mismatch_rejected() {
    let content: &[u8] = b"mnemos";

    // 42 ASCII bytes — one short. Still alphabet-clean so we are sure
    // LengthMismatch (not Base64Decode) is what fires.
    let too_short = "A".repeat(WALRUS_BLOB_ID_TEXT_LEN_BASE64URL - 1);
    let report_short = PublisherReportedBlobId::try_from_text(&too_short).expect("text within cap");
    assert!(matches!(
        verify_reported_blob_id(content, &report_short),
        Err(BlobIdError::LengthMismatch { observed }) if observed == WALRUS_BLOB_ID_TEXT_LEN_BASE64URL - 1
    ));

    // 44 ASCII bytes — one long.
    let too_long = "A".repeat(WALRUS_BLOB_ID_TEXT_LEN_BASE64URL + 1);
    let report_long = PublisherReportedBlobId::try_from_text(&too_long).expect("text within cap");
    assert!(matches!(
        verify_reported_blob_id(content, &report_long),
        Err(BlobIdError::LengthMismatch { observed }) if observed == WALRUS_BLOB_ID_TEXT_LEN_BASE64URL + 1
    ));

    // Length-43 token containing a non-alphabet character must reach the
    // base64 decoder, not the length gate.
    let mut alphabet_violation = "A".repeat(WALRUS_BLOB_ID_TEXT_LEN_BASE64URL);
    alphabet_violation.replace_range(7..8, "*");
    let report_bad_alpha =
        PublisherReportedBlobId::try_from_text(&alphabet_violation).expect("length-43 ASCII");
    assert!(matches!(
        verify_reported_blob_id(content, &report_bad_alpha),
        Err(BlobIdError::Base64Decode)
    ));
}

/// `VerifiedBlobId` has no public constructor besides
/// `verify_reported_blob_id`, and the value it wraps is the **locally
/// derived** id, not the reported bytes. This test exercises the latter
/// invariant directly; the former is enforced by visibility (the field
/// is private, the type has no `From`/`new`/`from_bytes`).
#[test]
fn c0_4_verified_id_only_via_local_derivation() {
    let content: &[u8] = b"the mnemos chunk that is to be persisted";
    let report = report_for(content);

    let verified = verify_reported_blob_id(content, &report).expect("matching report");
    let local = derive_blob_id(content);

    // The wrapped id must equal the local derivation byte-for-byte.
    assert_eq!(verified.as_blob_id().as_bytes(), local.as_bytes());

    // `VerifiedBlobId` is `Copy` and `repr(transparent)` over `BlobId`,
    // so its byte size and the underlying id's byte size are identical.
    assert_eq!(
        core::mem::size_of::<VerifiedBlobId>(),
        core::mem::size_of::<BlobId>()
    );
    assert_eq!(core::mem::size_of::<VerifiedBlobId>(), BLOB_ID_BYTES);

    // Same content + same report ⇒ the verification is idempotent.
    let again = verify_reported_blob_id(content, &report).expect("idempotent");
    assert_eq!(verified.as_blob_id(), again.as_blob_id());

    // Different content with the *same* report must fail RootMismatch:
    // the reported text was produced for `content`, not for `other`.
    let other: &[u8] = b"a different chunk entirely";
    assert!(matches!(
        verify_reported_blob_id(other, &report),
        Err(BlobIdError::RootMismatch)
    ));
}

// ===========================================================================
// 2. proptest properties (256 cases each)
// ===========================================================================

proptest! {
    /// `derive_blob_id` is deterministic on arbitrary byte slices up to
    /// a comfortably above-block-size length. Calling it twice on the
    /// same input yields the same 32 bytes.
    #[test]
    fn proptest_derive_is_deterministic(content in prop::collection::vec(any::<u8>(), 0..=257)) {
        let a = derive_blob_id(&content);
        let b = derive_blob_id(&content);
        prop_assert_eq!(a.as_bytes(), b.as_bytes());
    }

    /// `verify_reported_blob_id` accepts the canonical reported text
    /// that was produced from the *same* content, and the verified id
    /// matches the local derivation byte-for-byte.
    #[test]
    fn proptest_verify_roundtrips_on_canonical_report(
        content in prop::collection::vec(any::<u8>(), 0..=257)
    ) {
        let derived = derive_blob_id(&content);
        let text = encode_base64url_no_pad_32(derived.as_bytes());
        prop_assert_eq!(text.len(), WALRUS_BLOB_ID_TEXT_LEN_BASE64URL);
        let report = PublisherReportedBlobId::try_from_text(&text)
            .expect("encoded id fits MAX_REPORTED_BLOB_ID_TEXT_BYTES");
        let verified = verify_reported_blob_id(&content, &report)
            .expect("canonical report must verify");
        prop_assert_eq!(verified.as_blob_id().as_bytes(), derived.as_bytes());
    }
}
