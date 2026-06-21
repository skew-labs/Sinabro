//! Stage B Walrus testnet endpoint allowlist (atom #101 · B.2.0).
//!
//! This module mints [`WalrusTestnetEndpoint`] — the canonical §4.2 binding of
//! Stage A's sealed [`PublisherEndpoint`](mnemos_c_walrus::PublisherEndpoint)
//! transport marker to the Stage B [`StageBNetwork`](crate::network::StageBNetwork)
//! typed network boundary. It is the Cluster 2 (Walrus testnet client) entry
//! point and lives in `b-memory` rather than `c-walrus` by an explicit
//! architecture decision: `c-walrus` is the raw-transport / endpoint / blob
//! primitive crate (the workspace's lowest layer, depending on no other mnemos
//! crate), while `b-memory` is the Stage B memory-ownership-policy + trace +
//! signed-chunk + **Walrus orchestration wrapper** layer that already depends on
//! `c-walrus`. Placing the wrapper here keeps the dependency edge one-way
//! (`b-memory -> c-walrus`); placing it in `c-walrus` would require importing
//! `StageBNetwork` from `b-memory` and form a `c-walrus -> b-memory -> c-walrus`
//! cycle that cargo rejects. The §4.2 field list is honoured verbatim; only the
//! plan's `file:` crate is corrected.
//!
//! ## Allowlist invariant
//!
//! A [`WalrusTestnetEndpoint`] can only ever name the single sanctioned Walrus
//! public **testnet** endpoint. The only constructor is [`testnet`] (and the
//! label gate [`from_label`], which itself can only succeed for the canonical
//! `testnet` label). There is deliberately no constructor that accepts a host,
//! base URL, or path, so an arbitrary URL, a query-injected URL, or a
//! production-network ("mainnet") label is *not representable* as a constructed
//! endpoint. The standalone predicates [`accepts_base_url`] and
//! [`normalize_put_path`] express the same allowlist for callers validating an
//! externally-supplied URL or path string: both are fail-closed and return a
//! data-free reject (`false` / `None`) so a rejected raw URL/path cannot leak
//! through the return value (the atom #82 redaction-by-construction precedent).
//!
//! This module is pure and offline: it performs no I/O, opens no socket, and
//! pulls in no HTTP/TLS surface (`G-B-WALRUS-OFFLINE`). The only network it can
//! name is testnet (`G-B-NO-MAINNET`).
//!
//! [`testnet`]: WalrusTestnetEndpoint::testnet
//! [`from_label`]: WalrusTestnetEndpoint::from_label
//! [`accepts_base_url`]: WalrusTestnetEndpoint::accepts_base_url
//! [`normalize_put_path`]: WalrusTestnetEndpoint::normalize_put_path

use mnemos_c_walrus::{PublisherEndpoint, TESTNET_PUBLISHER_BASE_URL, WALRUS_PUT_BLOB_PATH};

use crate::network::StageBNetwork;

/// The canonical Walrus PUT path, split into its non-empty segments. The
/// normalizer in [`WalrusTestnetEndpoint::normalize_put_path`] accepts a
/// candidate path iff its non-empty, non-`.` segments equal this sequence
/// exactly (case-sensitive), which is the segment view of [`WALRUS_PUT_BLOB_PATH`]
/// (`/v1/blobs`).
const PUT_PATH_SEGMENTS: [&str; 2] = ["v1", "blobs"];

/// The single sanctioned Stage B Walrus endpoint: Walrus public **testnet**.
///
/// Binds Stage A's sealed [`PublisherEndpoint`] (which itself has only the
/// `testnet_public` constructor — no host/path field to override) to the Stage B
/// [`StageBNetwork`] typed boundary (one variant, `Testnet`). Both fields are the
/// §4.2 canonical shape verbatim. The type is a plain `Copy` value carrier with
/// no secret material, so the derived `Debug` cannot leak anything (the endpoint
/// is a zero-size marker and the network is a one-variant tag).
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub struct WalrusTestnetEndpoint {
    /// The sealed Stage A transport endpoint marker (testnet by construction).
    pub endpoint: PublisherEndpoint,
    /// The Stage B network boundary — always [`StageBNetwork::Testnet`].
    pub network: StageBNetwork,
}

impl WalrusTestnetEndpoint {
    /// The only constructor: returns the single sanctioned Walrus testnet
    /// endpoint. There is no parameter, so no caller can ever name another host,
    /// network, or path.
    #[inline]
    pub const fn testnet() -> Self {
        Self {
            endpoint: PublisherEndpoint::testnet_public(),
            network: StageBNetwork::Testnet,
        }
    }

    /// Build an endpoint from a network label, accepting **only** the canonical
    /// `testnet` label (ASCII-case-insensitive, surrounding whitespace trimmed —
    /// the atom #82 [`StageBNetwork::parse_label`] allowlist) and rejecting every
    /// other label (`mainnet`, `devnet`, `custom`, …) fail-closed with `None`.
    ///
    /// The rejected raw label is never embedded in the result: the output is a
    /// typed endpoint or a data-free `None`, so a secret placed in the label
    /// cannot reach a diagnostic (redaction by construction).
    #[inline]
    pub fn from_label(label: &str) -> Option<Self> {
        // `parse_label` only ever yields `StageBNetwork::Testnet` (the sole
        // variant), so any accepted label maps to the testnet endpoint.
        StageBNetwork::parse_label(label).map(|StageBNetwork::Testnet| Self::testnet())
    }

    /// Allowlist predicate for an externally-supplied base URL: returns `true`
    /// iff the candidate (whitespace-trimmed) is **exactly** the canonical
    /// testnet publisher base URL ([`TESTNET_PUBLISHER_BASE_URL`]).
    ///
    /// Every other input is rejected fail-closed — an arbitrary host, a
    /// production-network ("mainnet") host, and a query-injected or
    /// fragment-appended URL all differ from the single canonical string and so
    /// return `false`. The reject carries no data, so a rejected URL cannot leak
    /// through the return value.
    #[inline]
    pub fn accepts_base_url(candidate: &str) -> bool {
        candidate.trim() == TESTNET_PUBLISHER_BASE_URL
    }

    /// Normalize and allowlist an externally-supplied PUT path, returning
    /// `Some(`[`WALRUS_PUT_BLOB_PATH`]`)` iff the candidate normalizes to the
    /// canonical `/v1/blobs` path, and `None` (fail-closed, data-free) otherwise.
    ///
    /// Normalization is deliberately conservative:
    ///
    /// * a query string (`?`) or fragment (`#`) — i.e. query injection — is
    ///   rejected outright;
    /// * any backslash or internal whitespace, or any non-ASCII byte, is
    ///   rejected;
    /// * an empty or relative (non-`/`-leading) path is rejected;
    /// * empty segments (`//`) and `.` segments are collapsed;
    /// * a `..` segment (path traversal) is rejected;
    /// * the remaining segments must equal [`PUT_PATH_SEGMENTS`]
    ///   (`v1` / `blobs`) exactly and case-sensitively.
    ///
    /// So `/v1/blobs`, `/v1/blobs/`, `/v1//blobs`, and `/v1/./blobs` all
    /// normalize to the canonical path, while `/v1/blobs?x=1`, `/v1/../v1/blobs`,
    /// `/v2/blobs`, and `/v1/blobs/extra` are rejected.
    pub fn normalize_put_path(candidate: &str) -> Option<&'static str> {
        let path = candidate.trim();
        if path.is_empty() || !path.is_ascii() {
            return None;
        }
        // Query injection / fragment / backslash / internal whitespace reject.
        if path.contains(['?', '#', '\\', ' ', '\t', '\n', '\r']) {
            return None;
        }
        // Must be an absolute path.
        if !path.starts_with('/') {
            return None;
        }
        let mut matched = 0usize;
        for segment in path.split('/') {
            if segment.is_empty() || segment == "." {
                continue; // collapse `//` and `.`
            }
            if segment == ".." {
                return None; // path traversal
            }
            if matched >= PUT_PATH_SEGMENTS.len() || segment != PUT_PATH_SEGMENTS[matched] {
                return None;
            }
            matched += 1;
        }
        if matched == PUT_PATH_SEGMENTS.len() {
            Some(WALRUS_PUT_BLOB_PATH)
        } else {
            None
        }
    }

    /// The canonical testnet publisher base URL ([`TESTNET_PUBLISHER_BASE_URL`]).
    #[inline]
    pub const fn base_url(&self) -> &'static str {
        self.endpoint.base_url()
    }

    /// The canonical Walrus PUT path ([`WALRUS_PUT_BLOB_PATH`]).
    #[inline]
    pub const fn put_path(&self) -> &'static str {
        self.endpoint.put_path()
    }

    /// The bound Stage B network — always [`StageBNetwork::Testnet`].
    #[inline]
    pub const fn network(&self) -> StageBNetwork {
        self.network
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `b2_0_testnet_accepted` — the only constructor yields the canonical
    /// testnet endpoint; the `testnet` label is accepted in every ASCII-case /
    /// whitespace variant; and the bound network, base URL, and PUT path are the
    /// canonical Stage A surfaces.
    #[test]
    fn b2_0_testnet_accepted() {
        let ep = WalrusTestnetEndpoint::testnet();
        assert_eq!(ep.network(), StageBNetwork::Testnet);
        assert_eq!(ep.base_url(), TESTNET_PUBLISHER_BASE_URL);
        assert_eq!(ep.put_path(), WALRUS_PUT_BLOB_PATH);
        assert_eq!(ep.endpoint, PublisherEndpoint::testnet_public());

        for label in ["testnet", "Testnet", "TESTNET", "  testnet \t"] {
            assert_eq!(
                WalrusTestnetEndpoint::from_label(label),
                Some(WalrusTestnetEndpoint::testnet()),
                "label {label:?} must build the testnet endpoint",
            );
        }

        // The canonical base URL is accepted (trimmed).
        assert!(WalrusTestnetEndpoint::accepts_base_url(
            TESTNET_PUBLISHER_BASE_URL
        ));
        assert!(WalrusTestnetEndpoint::accepts_base_url(
            "  https://publisher.walrus-testnet.walrus.space \t"
        ));
    }

    /// `b2_0_custom_and_mainnet_rejected` — every non-`testnet` label, every
    /// non-canonical base URL (arbitrary host, mainnet host, query injection),
    /// is rejected fail-closed with no data echoed back.
    #[test]
    fn b2_0_custom_and_mainnet_rejected() {
        for bad in [
            "mainnet",
            "devnet",
            "custom",
            "localnet",
            "test",
            "",
            "main net",
            "testnet ; mainnet",
        ] {
            assert_eq!(
                WalrusTestnetEndpoint::from_label(bad),
                None,
                "label {bad:?} must be rejected",
            );
        }

        for bad_url in [
            // production-network host
            "https://publisher.walrus-mainnet.walrus.space",
            // arbitrary / look-alike host
            "https://evil.example.com",
            "http://publisher.walrus-testnet.walrus.space", // wrong scheme
            "https://publisher.walrus-testnet.walrus.space.evil.com",
            // query injection / fragment on the canonical host
            "https://publisher.walrus-testnet.walrus.space?redirect=evil",
            "https://publisher.walrus-testnet.walrus.space#frag",
            // trailing path is not the base URL
            "https://publisher.walrus-testnet.walrus.space/v1/blobs",
            "",
        ] {
            assert!(
                !WalrusTestnetEndpoint::accepts_base_url(bad_url),
                "url {bad_url:?} must be rejected",
            );
        }
    }

    /// `b2_0_path_normalization` — the PUT path normalizer collapses `//`/`.`
    /// and a trailing slash to the canonical `/v1/blobs`, and rejects query
    /// injection, path traversal, a wrong path, and an over-long path.
    #[test]
    fn b2_0_path_normalization() {
        // Accepted (normalize to canonical).
        for ok in [
            "/v1/blobs",
            "/v1/blobs/",
            "/v1//blobs",
            "/v1/./blobs",
            "  /v1/blobs  ",
        ] {
            assert_eq!(
                WalrusTestnetEndpoint::normalize_put_path(ok),
                Some(WALRUS_PUT_BLOB_PATH),
                "path {ok:?} must normalize to the canonical PUT path",
            );
        }

        // Rejected.
        for bad in [
            "/v1/blobs?x=1",   // query injection
            "/v1/blobs#frag",  // fragment
            "/v1/../v1/blobs", // path traversal
            "/../v1/blobs",    // path traversal
            "/v2/blobs",       // wrong version segment
            "/v1/blob",        // wrong leaf segment
            "/V1/blobs",       // case-sensitive segment mismatch
            "/v1/blobs/extra", // over-long path
            "v1/blobs",        // relative
            "",                // empty
            "/v1/blobs\\",     // backslash
            "/v1/ blobs",      // internal whitespace
        ] {
            assert_eq!(
                WalrusTestnetEndpoint::normalize_put_path(bad),
                None,
                "path {bad:?} must be rejected",
            );
        }
    }
}
