//! Integration test — Stage B official Walrus **RS2 oracle** wrappers
//! (bridge atom #116.5 · B.2.15.5). `feature = "net-testnet"` only.
//!
//! Proves the b-memory thin wrappers
//! [`derive_walrus_testnet_blob_id`](mnemos_b_memory::derive_walrus_testnet_blob_id)
//! and
//! [`stage_b_verify_testnet_blob_id`](mnemos_b_memory::stage_b_verify_testnet_blob_id)
//! forward faithfully to the c-walrus official-oracle adapter:
//!
//! 1. the Stage B derive equals the c-walrus oracle byte-for-byte and reproduces
//!    the #116 live-PUT reported id (`TjKHSEwJcAqzBaxGMmB0fYWcgYdxBUnMZRdnV7c-UEk`);
//! 2. the Stage B verify promotes the #116 reported id to a `VerifiedBlobId` over
//!    the exact #116 bytes — the path Stage B atom #117 consumes;
//! 3. a different blob's official id is still refused with `RootMismatch`.
//!
//! Pure local computation — no network, no live GET/PUT, no `Command`. With
//! `net-testnet` off the file compiles to nothing.

#![cfg(feature = "net-testnet")]
#![allow(clippy::unwrap_used)]
#![allow(clippy::expect_used)]
#![allow(clippy::panic)]

use mnemos_b_memory::{derive_walrus_testnet_blob_id, stage_b_verify_testnet_blob_id};
use mnemos_c_walrus::blob_id_rs2::derive_testnet_blob_id;
use mnemos_c_walrus::publisher::PublisherReportedBlobId;
use mnemos_c_walrus::{BlobIdError, WALRUS_BLOB_ID_TEXT_LEN_BASE64URL};

/// The exact synthetic public fixture PUT by Stage B atom #116 (`B.2.15`).
const ATOM_116_PAYLOAD: &[u8] =
    b"mnemos atom 116 B.2.15 synthetic public fixture -- live Walrus testnet PUT";

/// The blob id the public Walrus testnet publisher reported for
/// [`ATOM_116_PAYLOAD`] at atom #116.
const ATOM_116_REPORTED_ID: &str = "TjKHSEwJcAqzBaxGMmB0fYWcgYdxBUnMZRdnV7c-UEk";

/// Test-only URL-safe base64 (no padding) encoder for a 32-byte id (the #108
/// test-only base64 helper precedent), used only to render an oracle id for
/// comparison against the recorded reported text.
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

/// (1) The Stage B oracle wrapper equals the c-walrus oracle byte-for-byte and
/// reproduces the #116 reported id (thin-wrapper faithfulness).
#[test]
fn stage_b_derive_equals_c_walrus_oracle_and_reproduces_atom_116() {
    let stage_b = derive_walrus_testnet_blob_id(ATOM_116_PAYLOAD).expect("stage B oracle derive");
    let c_walrus = derive_testnet_blob_id(ATOM_116_PAYLOAD).expect("c-walrus oracle derive");
    assert_eq!(
        stage_b.as_bytes(),
        c_walrus.as_bytes(),
        "Stage B wrapper must equal the c-walrus oracle byte-for-byte"
    );
    assert_eq!(
        base64url_no_pad_encode_32(stage_b.as_bytes()),
        ATOM_116_REPORTED_ID,
        "Stage B oracle must reproduce the #116 reported id"
    );
}

/// (2) The Stage B verify wrapper promotes the #116 reported id to a
/// `VerifiedBlobId` over the exact #116 bytes — the atom #117 path.
#[test]
fn stage_b_verify_promotes_atom_116_reported_id() {
    let reported = PublisherReportedBlobId::try_from_text(ATOM_116_REPORTED_ID)
        .expect("well-formed reported token");
    let verified = stage_b_verify_testnet_blob_id(ATOM_116_PAYLOAD, &reported)
        .expect("the #116 reported id verifies against the #116 bytes under the oracle");
    assert_eq!(
        base64url_no_pad_encode_32(verified.as_blob_id().as_bytes()),
        ATOM_116_REPORTED_ID,
        "the verified id wraps the locally derived official id"
    );
}

/// (3) A different blob's official id is refused with `RootMismatch`.
#[test]
fn stage_b_verify_rejects_other_blobs_official_id() {
    let other: &[u8] = b"mnemos atom 116.5 a DIFFERENT synthetic fixture for mismatch";
    let other_text = base64url_no_pad_encode_32(
        derive_walrus_testnet_blob_id(other)
            .expect("derive")
            .as_bytes(),
    );
    let reported = PublisherReportedBlobId::try_from_text(&other_text).expect("valid token");
    let err = stage_b_verify_testnet_blob_id(ATOM_116_PAYLOAD, &reported)
        .expect_err("a different blob's id must not verify against the #116 bytes");
    assert_eq!(err, BlobIdError::RootMismatch);
}
