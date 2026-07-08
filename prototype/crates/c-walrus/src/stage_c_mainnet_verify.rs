//! Stage C mainnet blob local verify plan.
//!
//! Canonical OUT: [`MainnetSyntheticBlobReceipt`] — the receipt minted
//! after a synthetic mainnet blob's reported id has been **locally re-derived
//! and byte-matched**. Even on mainnet, a publisher-reported blob id never
//! becomes trusted by self-report: it is promoted to a
//! [`VerifiedBlobId`](crate::blob_id::VerifiedBlobId) only through
//! [`verify_reported_blob_id`](crate::blob_id::verify_reported_blob_id) (the
//! self-report ban).
//!
//! # Invariants
//!
//! * **Local derive, then trust.** [`verify_synthetic_blob`] re-derives the
//!   blob id from the content and compares all 32 bytes; only on an exact match
//!   does a [`VerifiedBlobId`](crate::blob_id::VerifiedBlobId) enter the
//!   receipt. A reported id that does not match is rejected
//!   ([`MainnetVerifyError::BlobMismatch`]).
//! * **No public `VerifiedBlobId` constructor.** Because
//!   [`VerifiedBlobId`](crate::blob_id::VerifiedBlobId) has no public
//!   constructor, an unverified reported id can never enter the receipt by any
//!   path other than [`verify_synthetic_blob`].
//! * **No re-mint, no network.** Reuses the verify path verbatim; this
//!   module opens no socket.

use crate::blob_id::{BlobIdError, VerifiedBlobId, verify_reported_blob_id};
use crate::publisher::PublisherReportedBlobId;

/// Receipt for a locally verified synthetic mainnet blob.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub struct MainnetSyntheticBlobReceipt {
    /// The locally derived, byte-matched blob id.
    pub blob: VerifiedBlobId,
    /// The 32-byte payload hash prepared for the ceremony, carried
    /// verbatim into the receipt.
    pub payload_hash_32: [u8; 32],
    /// The 32-byte ceremony hash binding this receipt to the ceremony plan,
    /// carried verbatim.
    pub ceremony_hash_32: [u8; 32],
}

/// Local-verify error. Data-free.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
#[repr(u8)]
pub enum MainnetVerifyError {
    /// The reported id text was malformed (wrong length or non-alphabet).
    ReportedTextInvalid = 1,
    /// The reported id did not match the locally derived id (root mismatch).
    BlobMismatch = 2,
}

impl core::fmt::Display for MainnetVerifyError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let msg = match self {
            Self::ReportedTextInvalid => "mainnet verify: reported id text invalid",
            Self::BlobMismatch => "mainnet verify: reported id != locally derived id",
        };
        f.write_str(msg)
    }
}

impl core::error::Error for MainnetVerifyError {}

/// Verify a synthetic mainnet blob's reported id against `content` by local
/// derivation, and mint the receipt on success.
///
/// `payload_hash_32` and `ceremony_hash_32` are carried
/// verbatim into the receipt; the trust decision is solely the local
/// re-derivation of the blob id.
///
/// # Errors
///
/// [`MainnetVerifyError::ReportedTextInvalid`] for a malformed reported text,
/// or [`MainnetVerifyError::BlobMismatch`] when the reported id does not match
/// the locally derived id.
pub fn verify_synthetic_blob(
    content: &[u8],
    reported: &PublisherReportedBlobId,
    payload_hash_32: [u8; 32],
    ceremony_hash_32: [u8; 32],
) -> Result<MainnetSyntheticBlobReceipt, MainnetVerifyError> {
    let blob = verify_reported_blob_id(content, reported).map_err(|e| match e {
        BlobIdError::RootMismatch => MainnetVerifyError::BlobMismatch,
        _ => MainnetVerifyError::ReportedTextInvalid,
    })?;
    Ok(MainnetSyntheticBlobReceipt {
        blob,
        payload_hash_32,
        ceremony_hash_32,
    })
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;
    use crate::blob_id::{derive_blob_id, encode_base64url_no_pad_32};

    fn reported_for(content: &[u8]) -> PublisherReportedBlobId {
        let id = derive_blob_id(content);
        let text = encode_base64url_no_pad_32(id.as_bytes());
        PublisherReportedBlobId::try_from_text(&text).expect("43-char reported text")
    }

    /// A correctly reported synthetic blob verifies and the receipt carries the
    /// locally derived id + the supplied hashes.
    #[test]
    fn c2_5_synthetic_receipt_vector() {
        let content = b"synthetic-public-fixture-payload-v1";
        let reported = reported_for(content);
        let payload_hash = [0x22u8; 32];
        let ceremony_hash = [0x33u8; 32];
        let receipt = verify_synthetic_blob(content, &reported, payload_hash, ceremony_hash)
            .expect("verifies");
        assert_eq!(receipt.payload_hash_32, payload_hash);
        assert_eq!(receipt.ceremony_hash_32, ceremony_hash);
        assert_eq!(receipt.blob.as_blob_id(), &derive_blob_id(content));
    }

    /// A reported id derived from *different* content is rejected as a root
    /// mismatch; no receipt is produced.
    #[test]
    fn c2_5_mismatch_reject() {
        let content = b"synthetic-public-fixture-payload-v1";
        let wrong = reported_for(b"a-different-payload");
        assert_eq!(
            verify_synthetic_blob(content, &wrong, [0u8; 32], [0u8; 32]),
            Err(MainnetVerifyError::BlobMismatch),
        );
    }

    /// A malformed reported text cannot mint a receipt; the only path to a
    /// `VerifiedBlobId` is the local-derive verify, so an unverified id is
    /// structurally excluded.
    #[test]
    fn c2_5_unverified_reported_id_cannot_enter_receipt() {
        let content = b"synthetic-public-fixture-payload-v1";
        let too_short = PublisherReportedBlobId::try_from_text("deadbeef").expect("non-empty text");
        assert_eq!(
            verify_synthetic_blob(content, &too_short, [0u8; 32], [0u8; 32]),
            Err(MainnetVerifyError::ReportedTextInvalid),
        );
    }
}
