//! Stage B testnet tx submitter (atom #155 · B.4.9, WorkPackage B-WP-03).
//!
//! Canonical OUT (`MNEMOS_STAGE_B_ATOM_PLAN.md` §4.4): a testnet-only submit
//! wrapper for a signed PTB. The madness spec: "submitter is disabled by
//! default and only used by live-approved atoms. dry-run path remains
//! primary."
//!
//! # Madness invariants (§4.4 / atom #155)
//!
//! * **Disabled by default.** [`StageBSubmitter::default`] (and
//!   [`StageBSubmitter::disabled`]) produce a submitter whose
//!   [`StageBSubmitter::submit_mock`] returns
//!   [`StageBSubmitOutcome::DisabledByDefault`] without doing anything. A
//!   submitter is enabled ONLY through [`StageBSubmitter::enabled_for_testnet`],
//!   which is the seam a future live-approved atom calls — the default
//!   construction path can never submit.
//! * **Dry-run remains primary.** This wrapper performs **no live network
//!   I/O**; the response is supplied by the caller (a mock transport in
//!   tests, a live-approved transport in a future atom). The byte-stable
//!   dry-run carrier (atom #134 `to_dry_run_bytes`) stays the primary,
//!   always-available path.
//! * **No mainnet.** [`StageBSubmitter::enabled_for_testnet`] parses an
//!   endpoint label through the reused fail-closed
//!   [`StageBNetwork::parse_label`] and rejects any non-testnet endpoint with
//!   [`StageBWalletError::NetworkNotTestnet`].
//!
//! # Reuse map (atom contract)
//!
//! * **reuse: #151** — the testnet-only signed call ([`SignatureBytes`]) this
//!   submitter would wrap.
//! * **reuse: #154** — the testnet endpoint / network guard posture.

use crate::stage_b_config::StageBWalletError;
use mnemos_b_memory::network::StageBNetwork;
use mnemos_c_walrus::SignatureBytes;

/// Byte width of a Sui transaction digest.
pub const STAGE_B_TX_DIGEST_BYTES: usize = 32;

/// A parsed 32-byte Sui transaction digest (public). `#[repr(transparent)]`
/// over `[u8; 32]`.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
#[repr(transparent)]
pub struct StageBTxDigest([u8; STAGE_B_TX_DIGEST_BYTES]);

impl StageBTxDigest {
    /// Parse a transaction digest from a runtime byte slice, **fail-closed on
    /// length**: returns `Some` iff `bytes.len() == 32`, `None` otherwise. No
    /// canonical error variant is minted (reject-as-predicate precedent).
    #[must_use]
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        if bytes.len() != STAGE_B_TX_DIGEST_BYTES {
            return None;
        }
        let mut out = [0u8; STAGE_B_TX_DIGEST_BYTES];
        out.copy_from_slice(bytes);
        Some(Self(out))
    }

    /// Borrow the 32-byte digest.
    #[inline]
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; STAGE_B_TX_DIGEST_BYTES] {
        &self.0
    }
}

/// The outcome of a (mock) submit attempt.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StageBSubmitOutcome {
    /// The submitter was disabled (the default). Nothing was submitted; the
    /// caller should use the primary dry-run path.
    DisabledByDefault,
    /// The submit produced a parsed transaction digest.
    Submitted(StageBTxDigest),
}

/// A testnet-only tx submitter. Disabled by default; enabling it is the
/// explicit, testnet-gated seam a live-approved atom uses.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct StageBSubmitter {
    enabled: bool,
}

impl Default for StageBSubmitter {
    /// The default submitter is **disabled** — the primary path is dry-run.
    fn default() -> Self {
        Self { enabled: false }
    }
}

impl StageBSubmitter {
    /// An explicitly-disabled submitter (same as [`StageBSubmitter::default`]).
    #[inline]
    #[must_use]
    pub fn disabled() -> Self {
        Self { enabled: false }
    }

    /// Enable the submitter for a testnet endpoint. This is the seam a future
    /// live-approved atom calls; the default path never reaches it.
    ///
    /// # Errors
    ///
    /// - [`StageBWalletError::NetworkNotTestnet`] when `endpoint_label` is not
    ///   the canonical testnet label.
    pub fn enabled_for_testnet(endpoint_label: &str) -> Result<Self, StageBWalletError> {
        match StageBNetwork::parse_label(endpoint_label) {
            Some(StageBNetwork::Testnet) => Ok(Self { enabled: true }),
            None => Err(StageBWalletError::NetworkNotTestnet),
        }
    }

    /// `true` iff this submitter is enabled.
    #[inline]
    #[must_use]
    pub fn is_enabled(&self) -> bool {
        self.enabled
    }

    /// Submit a signed call against a caller-supplied transport response
    /// (`mock_response` — the bytes a transport would return). Performs **no**
    /// live network I/O.
    ///
    /// * If the submitter is disabled (the default), returns
    ///   [`StageBSubmitOutcome::DisabledByDefault`] and ignores the inputs.
    /// * If enabled, parses a 32-byte transaction digest from `mock_response`
    ///   and returns [`StageBSubmitOutcome::Submitted`].
    ///
    /// # Errors
    ///
    /// - [`StageBWalletError::Sign`] when the submitter is enabled but
    ///   `mock_response` does not parse as a 32-byte tx digest (a malformed
    ///   transport response on the signed-submit path).
    pub fn submit_mock(
        &self,
        _signed_call: &SignatureBytes,
        mock_response: &[u8],
    ) -> Result<StageBSubmitOutcome, StageBWalletError> {
        if !self.enabled {
            return Ok(StageBSubmitOutcome::DisabledByDefault);
        }
        match StageBTxDigest::from_bytes(mock_response) {
            Some(digest) => Ok(StageBSubmitOutcome::Submitted(digest)),
            None => Err(StageBWalletError::Sign),
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    #![allow(clippy::expect_used)]
    #![allow(clippy::panic)]

    use super::*;

    fn dummy_sig() -> SignatureBytes {
        SignatureBytes([0x11u8; 64])
    }

    /// `b4_9_disabled_by_default` — the default and explicit-disabled
    /// submitters do not submit; they return `DisabledByDefault` regardless of
    /// the response bytes.
    #[test]
    fn b4_9_disabled_by_default() {
        for s in [StageBSubmitter::default(), StageBSubmitter::disabled()] {
            assert!(!s.is_enabled());
            let out = s
                .submit_mock(&dummy_sig(), &[0xABu8; 32])
                .expect("disabled submit is infallible");
            assert_eq!(out, StageBSubmitOutcome::DisabledByDefault);
        }
    }

    /// `b4_9_mock_submit` — an enabled testnet submitter parses a 32-byte mock
    /// response into a `Submitted` tx digest matching the response bytes.
    #[test]
    fn b4_9_mock_submit() {
        let s = StageBSubmitter::enabled_for_testnet("testnet").expect("testnet enables");
        assert!(s.is_enabled());
        let response = [0x7Eu8; 32];
        let out = s
            .submit_mock(&dummy_sig(), &response)
            .expect("valid digest");
        match out {
            StageBSubmitOutcome::Submitted(d) => assert_eq!(d.as_bytes(), &response),
            StageBSubmitOutcome::DisabledByDefault => panic!("enabled submitter must submit"),
        }
    }

    /// `b4_9_tx_digest_parse` — the digest parser is fail-closed on length.
    #[test]
    fn b4_9_tx_digest_parse() {
        for bad_len in [0usize, 1, 16, 31, 33, 64] {
            assert!(
                StageBTxDigest::from_bytes(&vec![0u8; bad_len]).is_none(),
                "length {bad_len} must be rejected",
            );
        }
        let ok = StageBTxDigest::from_bytes(&[0x42u8; 32]).expect("32 bytes parses");
        assert_eq!(ok.as_bytes(), &[0x42u8; 32]);

        // An enabled submitter surfaces a malformed (non-32) response as Sign.
        let s = StageBSubmitter::enabled_for_testnet("testnet").expect("enables");
        assert_eq!(
            s.submit_mock(&dummy_sig(), &[0x00u8; 31]).err(),
            Some(StageBWalletError::Sign),
        );
    }

    /// `b4_9_mainnet_reject` — a non-testnet endpoint cannot enable the
    /// submitter. The forbidden production label appears only here as reject
    /// evidence.
    #[test]
    fn b4_9_mainnet_reject() {
        for bad in ["mainnet", "devnet", "localnet", ""] {
            assert_eq!(
                StageBSubmitter::enabled_for_testnet(bad).err(),
                Some(StageBWalletError::NetworkNotTestnet),
                "endpoint {bad:?} must not enable the submitter",
            );
        }
    }
}
