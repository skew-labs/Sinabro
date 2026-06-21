//! Official Walrus **RS2 blob-id oracle** — bridge atom #116.5 · B.2.15.5,
//! `feature = "net-testnet"` only.
//!
//! # Why this module exists
//!
//! The default/offline [`derive_blob_id`](crate::blob_id::derive_blob_id) is a
//! Phase-0 **placeholder** ARX digest (atom #10): deterministic and
//! domain-separated, but *not* the real Walrus blob id. So a publisher-reported
//! id from a live testnet PUT (Stage B atom #116) can never byte-match the
//! placeholder, and
//! [`verify_reported_blob_id`](crate::blob_id::verify_reported_blob_id) would
//! reject it as [`BlobIdError::RootMismatch`].
//!
//! This module is the **isolated official-oracle adapter**: under
//! `feature = "net-testnet"` it computes the *real* Walrus blob id by calling
//! the upstream [`walrus_core`] crate in-process — the same
//! RS2/RedStuff sliver-pair metadata -> Blake2b256 Merkle root -> blob-id rule
//! the `walrus blob-id --n-shards 1000` CLI uses. The bridge atom proves 3-way
//! parity on the #116 fixture: `walrus blob-id` CLI == `walrus-core` ==
//! [`derive_testnet_blob_id`].
//!
//! # Invariants (광기)
//!
//! * **Default build is untouched.** The whole module is removed at parse time
//!   with the feature off; the placeholder derive/verify path (atoms #10/#11)
//!   and every offline test stay byte-identical. `walrus-core` is an optional
//!   dependency that never links into the default `--offline --workspace` build.
//! * **No new semantics on the existing names.**
//!   [`derive_blob_id`](crate::blob_id::derive_blob_id) and
//!   [`verify_reported_blob_id`](crate::blob_id::verify_reported_blob_id) keep
//!   their Phase-0 placeholder meaning under **both** builds. The official
//!   oracle lives on the **new** names here ([`derive_testnet_blob_id`],
//!   [`verify_reported_testnet_blob_id`]); Stage B atom #117 consumes those.
//! * **Server is not an oracle.** [`verify_reported_testnet_blob_id`] re-derives
//!   the id locally from `content` and only promotes the reported text to a
//!   [`VerifiedBlobId`] on an exact 32-byte match; the returned value wraps the
//!   **locally derived** id, never the reported bytes.
//! * **No network, no `Command`, no hot path.** The oracle is pure CPU-bound
//!   erasure-coding math over the local bytes; it opens no socket and shells out
//!   to nothing. It is a *verification/readiness* oracle, not a production
//!   hot-path dependency.

use core::num::NonZeroU16;

use walrus_core::EncodingType;
use walrus_core::encoding::{EncodingConfig, EncodingFactory};

use crate::blob_id::{
    BlobIdError, VerifiedBlobId, WALRUS_BLOB_ID_TEXT_LEN_BASE64URL, decode_base64url_no_pad_32,
};
use crate::codec::{BLOB_ID_BYTES, BlobId};
use crate::publisher::PublisherReportedBlobId;

/// The Walrus **testnet** committee shard count. The blob id is a function of
/// `n_shards` (it parameterises the RS2 encoding and therefore the Merkle tree
/// over sliver pairs), so the oracle pins the value the public testnet — and the
/// #116 live PUT — used. The `walrus blob-id --n-shards 1000` invocation in the
/// atom #116.5 oracle proof uses the same constant.
pub const WALRUS_TESTNET_N_SHARDS: u16 = 1000;

// Compile-time pins:
// (1) the testnet shard count is non-zero, so the `NonZeroU16` construction in
//     `derive_testnet_blob_id` provably never takes its fallback branch.
const _N_SHARDS_NONZERO: [(); 0 - !(WALRUS_TESTNET_N_SHARDS != 0) as usize] = [];
// (2) our 32-byte `BlobId` and `walrus_core::BlobId` agree on length, so the
//     `BlobId(walrus_id.0)` copy below is total and lossless.
const _BLOB_ID_LEN_MATCHES_WALRUS: [(); 0 - !(BLOB_ID_BYTES == walrus_core::BlobId::LENGTH)
    as usize] = [];

/// Reasons the official Walrus RS2 oracle could not produce a local id.
///
/// Mirrors the `Copy` + `non_exhaustive` + `class_label()` discipline of
/// [`BlobIdError`]. Kept as a small, dependency-free adapter error so the
/// `net-testnet` feature introduces no heavy error crate into the library.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
#[non_exhaustive]
pub enum WalrusOracleError {
    /// `content` exceeds the RS2 encoding's maximum blob size for this
    /// `n_shards`, so the upstream `walrus_core` encoder refused it
    /// (`DataTooLargeError`). Stage B chunks are bounded well under this cap, so
    /// this is a defensive total-function arm rather than an expected outcome.
    EncodingTooLarge,
}

impl WalrusOracleError {
    /// Stable, allow-listed `class_label` for diagnostic JSON envelopes,
    /// namespaced under `walrus_oracle.*`.
    #[inline]
    pub const fn class_label(self) -> &'static str {
        match self {
            Self::EncodingTooLarge => "walrus_oracle.encoding_too_large",
        }
    }
}

/// Compute the **official** Walrus blob id of `content` for the testnet
/// `n_shards = 1000` committee, in-process via [`walrus_core`].
///
/// This is the real RS2/RedStuff rule: `content` is erasure-coded into sliver
/// pairs, a Blake2b256 Merkle tree is built over their metadata, and the blob id
/// is `Blake2b256(encoding_type || unencoded_length_le || merkle_root)`. The
/// result is byte-identical to `walrus blob-id --n-shards 1000` and to the id a
/// Walrus publisher reports for the same bytes.
///
/// Pure computation: no socket, no `Command`, no global state.
///
/// # Errors
/// [`WalrusOracleError::EncodingTooLarge`] if `content` exceeds the encoding's
/// maximum blob size (the only failure mode of the upstream encoder).
pub fn derive_testnet_blob_id(content: &[u8]) -> Result<BlobId, WalrusOracleError> {
    // `WALRUS_TESTNET_N_SHARDS` is non-zero (pinned by `_N_SHARDS_NONZERO`), so
    // `new` always yields `Some`; the `unwrap_or` fallback is unreachable and
    // present only to keep the function panic-free under the crate's clippy
    // `-D unwrap_used / expect_used / panic` deny set.
    let n_shards = NonZeroU16::new(WALRUS_TESTNET_N_SHARDS).unwrap_or(NonZeroU16::MIN);
    let walrus_id = EncodingConfig::new(n_shards)
        .get_for_type(EncodingType::RS2)
        .compute_blob_id(content)
        .map_err(|_| WalrusOracleError::EncodingTooLarge)?;
    // `walrus_core::BlobId(pub [u8; 32])` -> our `BlobId([u8; 32])`; the length
    // equality is pinned by `_BLOB_ID_LEN_MATCHES_WALRUS`.
    Ok(BlobId(walrus_id.0))
}

/// Verify a publisher's *self-reported* Walrus blob-id text against the
/// **official RS2 oracle** derivation of `content`, promoting it to a
/// [`VerifiedBlobId`] only on an exact 32-byte match.
///
/// The `net-testnet` counterpart of
/// [`verify_reported_blob_id`](crate::blob_id::verify_reported_blob_id): it
/// performs the identical length / base64 checks (reusing the same private
/// decoder), but re-derives the local id with [`derive_testnet_blob_id`] instead
/// of the Phase-0 placeholder. This is the path Stage B atom #117 uses to
/// promote the #116 live-PUT reported id to a trust root. The existing
/// placeholder verify is left untouched.
///
/// # Errors
/// * [`BlobIdError::LengthMismatch`] / [`BlobIdError::Base64Decode`] — same
///   reported-text validation as the placeholder verify;
/// * [`BlobIdError::RootMismatch`] — the reported bytes decode cleanly but
///   differ from the official-oracle derivation (self-report refusal);
/// * [`BlobIdError::OracleUnavailable`] — the oracle could not derive a local id
///   for `content` (oversized blob), so no comparison was possible.
pub fn verify_reported_testnet_blob_id(
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
    let derived = derive_testnet_blob_id(content).map_err(|_| BlobIdError::OracleUnavailable)?;
    if derived.as_bytes() != &reported_bytes {
        return Err(BlobIdError::RootMismatch);
    }
    Ok(VerifiedBlobId::from_local_derivation(derived))
}
