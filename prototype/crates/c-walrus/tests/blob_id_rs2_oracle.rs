//! Integration test — official Walrus **RS2 blob-id oracle** parity + verify
//! (bridge atom #116.5 · B.2.15.5). `feature = "net-testnet"` only.
//!
//! # What this proves
//!
//! 1. **3-way parity** on the #116 live-PUT fixture: the in-process
//!    [`derive_testnet_blob_id`] equals the `walrus blob-id --n-shards 1000` CLI
//!    output **and** the id the public testnet publisher reported for the same
//!    bytes (`TjKHSEwJcAqzBaxGMmB0fYWcgYdxBUnMZRdnV7c-UEk`, recorded by atom
//!    #116). The CLI leg is run out-of-band in the atom #116.5 oracle proof; this
//!    file pins the in-process leg against the recorded reported id.
//! 2. **Verify promotes** the #116 reported id to a `VerifiedBlobId` over the
//!    exact #116 local bytes via [`verify_reported_testnet_blob_id`].
//! 3. **Mismatch is still refused** with `RootMismatch` (the official oracle of a
//!    *different* blob's bytes does not verify against the #116 bytes).
//! 4. Reported-text validation (`LengthMismatch` / `Base64Decode`) is unchanged.
//!
//! This is pure local computation — **no network, no live GET/PUT, no
//! `Command`**. With `net-testnet` off the file compiles to nothing.

#![cfg(feature = "net-testnet")]
#![allow(clippy::unwrap_used)]
#![allow(clippy::expect_used)]
#![allow(clippy::panic)]

use mnemos_c_walrus::blob_id_rs2::{
    WALRUS_TESTNET_N_SHARDS, derive_testnet_blob_id, verify_reported_testnet_blob_id,
};
use mnemos_c_walrus::publisher::PublisherReportedBlobId;
use mnemos_c_walrus::{BlobIdError, WALRUS_BLOB_ID_TEXT_LEN_BASE64URL};

/// The exact synthetic public fixture PUT by Stage B atom #116 (`B.2.15`).
const ATOM_116_PAYLOAD: &[u8] =
    b"mnemos atom 116 B.2.15 synthetic public fixture -- live Walrus testnet PUT";

/// The blob id the public Walrus testnet publisher reported for
/// [`ATOM_116_PAYLOAD`] at atom #116, re-confirmed by
/// `walrus blob-id --n-shards 1000` in the atom #116.5 oracle proof.
const ATOM_116_REPORTED_ID: &str = "TjKHSEwJcAqzBaxGMmB0fYWcgYdxBUnMZRdnV7c-UEk";

/// Test-only URL-safe base64 (no padding) encoder for a 32-byte id — the
/// faithful inverse of c-walrus's `decode_base64url_no_pad_32`, duplicated here
/// because that decoder is `pub(crate)` (the #95/#105/#108 test-only base64
/// helper precedent). Used only to render an oracle id for comparison.
fn base64url_no_pad_encode_32(raw: &[u8; 32]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut out = String::with_capacity(WALRUS_BLOB_ID_TEXT_LEN_BASE64URL);
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

/// (1) The in-process oracle reproduces the #116 reported id byte-for-byte —
/// the local Rust leg of the CLI == walrus-core == local-Rust 3-way parity.
#[test]
fn rs2_oracle_reproduces_atom_116_reported_id() {
    assert_eq!(WALRUS_TESTNET_N_SHARDS, 1000, "testnet committee n_shards");
    let id = derive_testnet_blob_id(ATOM_116_PAYLOAD).expect("oracle derives the fixture id");
    let text = base64url_no_pad_encode_32(id.as_bytes());
    assert_eq!(
        text, ATOM_116_REPORTED_ID,
        "in-process RS2 oracle must equal the CLI / publisher-reported #116 id"
    );
    assert_eq!(
        text.len(),
        WALRUS_BLOB_ID_TEXT_LEN_BASE64URL,
        "a 32-byte id renders to 43 base64url chars"
    );
}

/// The oracle is deterministic — same bytes, same id across calls.
#[test]
fn rs2_oracle_is_deterministic() {
    let a = derive_testnet_blob_id(ATOM_116_PAYLOAD).expect("derive a");
    let b = derive_testnet_blob_id(ATOM_116_PAYLOAD).expect("derive b");
    assert_eq!(a.as_bytes(), b.as_bytes());
}

/// (2) Verify promotes the #116 reported id to a `VerifiedBlobId` wrapping the
/// **locally derived** official id over the exact #116 bytes.
#[test]
fn verify_promotes_atom_116_reported_id() {
    let reported = PublisherReportedBlobId::try_from_text(ATOM_116_REPORTED_ID)
        .expect("the recorded #116 id is a well-formed reported token");
    let verified = verify_reported_testnet_blob_id(ATOM_116_PAYLOAD, &reported)
        .expect("the #116 reported id must verify against the #116 bytes under the oracle");
    let local = derive_testnet_blob_id(ATOM_116_PAYLOAD).expect("oracle derive");
    assert_eq!(
        verified.as_blob_id().as_bytes(),
        local.as_bytes(),
        "the verified id wraps the locally derived official id, not the reported bytes"
    );
    assert_eq!(
        base64url_no_pad_encode_32(verified.as_blob_id().as_bytes()),
        ATOM_116_REPORTED_ID,
    );
}

/// (3) A reported id that is the *valid* official encoding of a **different**
/// blob's bytes is refused with `RootMismatch` when verified against the #116
/// bytes — the publisher cannot substitute another blob's id.
#[test]
fn verify_rejects_other_blobs_official_id_with_root_mismatch() {
    let other_payload: &[u8] = b"mnemos atom 116.5 a DIFFERENT synthetic fixture for mismatch";
    let other_id = derive_testnet_blob_id(other_payload).expect("oracle derives the other id");
    let other_text = base64url_no_pad_encode_32(other_id.as_bytes());
    assert_ne!(
        other_text, ATOM_116_REPORTED_ID,
        "the two fixtures must have distinct official ids"
    );
    let reported = PublisherReportedBlobId::try_from_text(&other_text).expect("valid token");
    let err = verify_reported_testnet_blob_id(ATOM_116_PAYLOAD, &reported)
        .expect_err("a different blob's id must not verify against the #116 bytes");
    assert_eq!(err, BlobIdError::RootMismatch);
}

/// (4) Reported-text validation is unchanged: a wrong-length token is refused
/// with `LengthMismatch` before any oracle derivation, and a correct-length
/// token with a non-alphabet character is refused with `Base64Decode`.
#[test]
fn verify_rejects_malformed_reported_text() {
    let short = PublisherReportedBlobId::try_from_text("too-short").expect("token");
    assert_eq!(
        verify_reported_testnet_blob_id(ATOM_116_PAYLOAD, &short).unwrap_err(),
        BlobIdError::LengthMismatch { observed: 9 },
    );

    let mut bad = ATOM_116_REPORTED_ID.to_string();
    bad.replace_range(0..1, "*"); // stays 43 chars; '*' is outside the alphabet
    let bad_report = PublisherReportedBlobId::try_from_text(&bad).expect("token");
    assert_eq!(
        verify_reported_testnet_blob_id(ATOM_116_PAYLOAD, &bad_report).unwrap_err(),
        BlobIdError::Base64Decode,
    );
}
