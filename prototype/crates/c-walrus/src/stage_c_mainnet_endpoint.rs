//! Stage C Walrus **mainnet** endpoint typed prep.
//!
//! Canonical OUT: [`MainnetWalrusEndpoint`] — a typed Walrus **mainnet**
//! endpoint wrapper that is constructed *only* from a sealed mainnet
//! config ([`SealedMainnetConfig`]) and still drives the Stage A
//! [`PublisherTransport`](crate::publisher::PublisherTransport) /
//! [`AggregatorTransport`](crate::aggregator::AggregatorTransport) abstractions
//! verbatim. It is **not** a generic `StorageBackend` writer and it performs
//! **no** network I/O: this module is *prepare-only*. No PUT, no GET, no socket.
//!
//! # Invariants
//!
//! * **Prepare, never execute.** The endpoint can only be built from a
//!   [`SealedMainnetConfig`] whose [`can_execute`](SealedMainnetConfig::can_execute)
//!   is `false` (always, by construction). A config that somehow
//!   carries an executable posture is rejected with
//!   [`MainnetEndpointError::ExecutableConfigForbidden`] — defense in depth.
//! * **Checklist receipt mandatory.** A config with an all-zero checklist
//!   receipt hash is rejected with [`MainnetEndpointError::ChecklistMissing`]
//!   (the config parser already enforces this at parse time; re-checked here so a
//!   directly constructed config literal cannot bypass it).
//! * **No arbitrary endpoint.** [`MainnetEndpointMode::OfficialMainnet`] names
//!   the single sanctioned Walrus mainnet publisher/aggregator hosts
//!   ([`WALRUS_MAINNET_PUBLISHER_BASE_URL`] /
//!   [`WALRUS_MAINNET_AGGREGATOR_BASE_URL`]); a caller-supplied custom URL is
//!   rejected ([`MainnetEndpointError::CustomUrlForbidden`]) unless the
//!   explicit [`MainnetEndpointMode::SelfHost`] mode is selected. Even in
//!   self-host mode an `ipfs://` / `filecoin://` / non-`https` endpoint is
//!   rejected ([`MainnetEndpointError::NonWalrusEndpoint`]): this endpoint
//!   speaks Walrus over `https` only and is never a generic storage writer.
//! * **Transport-trait reuse, no re-mint.** This module mints **no** new
//!   transport trait. Callers drive the endpoint through the canonical
//!   [`PublisherTransport`](crate::publisher::PublisherTransport) /
//!   [`AggregatorTransport`](crate::aggregator::AggregatorTransport) traits.
//!
//! # New crate edge
//!
//! This module introduces the one-way path dependency `c-walrus -> a-core`
//! (for [`SealedMainnetConfig`] / [`StageCChainEnv`]). `a-core` depends on no
//! workspace member, so the edge is acyclic. It mirrors the existing
//! `b-memory`/`d-move`/`k-devex -> a-core` and `g-wallet -> a-core`
//! edges. Path-only: pure types, no network / HTTP / TLS.

use mnemos_a_core::{SealedMainnetConfig, StageCChainEnv};

/// The single sanctioned Walrus **mainnet** publisher base URL. Same host
/// family as the testnet base URL, on the `walrus-mainnet` subdomain.
pub const WALRUS_MAINNET_PUBLISHER_BASE_URL: &str = "https://publisher.walrus-mainnet.walrus.space";

/// The single sanctioned Walrus **mainnet** aggregator base URL.
pub const WALRUS_MAINNET_AGGREGATOR_BASE_URL: &str =
    "https://aggregator.walrus-mainnet.walrus.space";

/// How a [`MainnetWalrusEndpoint`] resolves its base URLs.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
#[repr(u8)]
pub enum MainnetEndpointMode {
    /// Official Walrus mainnet hosts. No custom URL may be supplied.
    OfficialMainnet = 1,
    /// Operator-run self-hosted Walrus. A custom `https` URL is required.
    SelfHost = 2,
}

/// Construction / validation error for a [`MainnetWalrusEndpoint`]. Data-free,
/// so a rejected raw URL can never leak through the return value.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
#[repr(u8)]
pub enum MainnetEndpointError {
    /// The sealed config's chain env was not `MainnetPrepared`.
    NotMainnetPrepared = 1,
    /// The sealed config carried an executable posture (forbidden for prep).
    ExecutableConfigForbidden = 2,
    /// The sealed config's checklist receipt hash was all-zero.
    ChecklistMissing = 3,
    /// A custom URL was supplied in [`MainnetEndpointMode::OfficialMainnet`].
    CustomUrlForbidden = 4,
    /// [`MainnetEndpointMode::SelfHost`] was selected but no custom URL given.
    SelfHostUrlRequired = 5,
    /// The supplied endpoint is not an `https` Walrus endpoint (e.g. an
    /// `ipfs://` / `filecoin://` / non-`https` / query-injected URL).
    NonWalrusEndpoint = 6,
}

impl core::fmt::Display for MainnetEndpointError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let msg = match self {
            Self::NotMainnetPrepared => "mainnet endpoint: chain env must be MainnetPrepared",
            Self::ExecutableConfigForbidden => "mainnet endpoint: executable config forbidden",
            Self::ChecklistMissing => "mainnet endpoint: checklist receipt required (non-zero)",
            Self::CustomUrlForbidden => "mainnet endpoint: custom URL forbidden outside self-host",
            Self::SelfHostUrlRequired => "mainnet endpoint: self-host mode requires a custom URL",
            Self::NonWalrusEndpoint => "mainnet endpoint: not an https Walrus endpoint",
        };
        f.write_str(msg)
    }
}

impl core::error::Error for MainnetEndpointError {}

const fn is_zero_32(h: &[u8; 32]) -> bool {
    let mut i = 0;
    while i < 32 {
        if h[i] != 0 {
            return false;
        }
        i += 1;
    }
    true
}

/// Allowlist predicate for a self-hosted Walrus base URL: `https` scheme only,
/// non-empty host, ASCII, no whitespace, and no query / fragment injection. An
/// `ipfs://` / `filecoin://` / `http://` / `file://` URL fails the `https://`
/// prefix and is rejected fail-closed.
fn is_valid_walrus_https_url(url: &str) -> bool {
    let u = url.trim();
    let Some(rest) = u.strip_prefix("https://") else {
        return false;
    };
    !rest.is_empty()
        && u.is_ascii()
        && !u.contains(|c: char| c.is_whitespace())
        && !u.contains('?')
        && !u.contains('#')
}

/// A typed Walrus **mainnet** endpoint (canonical shape).
///
/// Built only from a sealed mainnet config; carries the resolved base URLs and
/// the checklist receipt hash it is gated on. Holds no secret material.
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct MainnetWalrusEndpoint {
    mode: MainnetEndpointMode,
    publisher_base_url: String,
    aggregator_base_url: String,
    checklist_receipt_hash_32: [u8; 32],
}

impl MainnetWalrusEndpoint {
    /// Construct a mainnet endpoint from a sealed config.
    ///
    /// In [`MainnetEndpointMode::OfficialMainnet`] no custom URL may be passed
    /// (`Some(_)` → [`MainnetEndpointError::CustomUrlForbidden`]); the official
    /// hosts are used. In [`MainnetEndpointMode::SelfHost`] both custom URLs are
    /// required and validated by [`is_valid_walrus_https_url`].
    ///
    /// # Errors
    ///
    /// [`MainnetEndpointError`] for a non-mainnet / executable / checklist-less
    /// config, a custom URL in official mode, a missing self-host URL, or a
    /// non-`https`-Walrus endpoint.
    pub fn from_sealed_config(
        config: &SealedMainnetConfig,
        mode: MainnetEndpointMode,
        custom_publisher_url: Option<&str>,
        custom_aggregator_url: Option<&str>,
    ) -> Result<Self, MainnetEndpointError> {
        // Defense-in-depth config gates (the config parser already enforces
        // these at parse time; re-checked so a directly built config literal
        // cannot bypass them).
        if config.chain_env != StageCChainEnv::MainnetPrepared {
            return Err(MainnetEndpointError::NotMainnetPrepared);
        }
        if config.can_execute() {
            return Err(MainnetEndpointError::ExecutableConfigForbidden);
        }
        if is_zero_32(&config.checklist_receipt_hash_32) {
            return Err(MainnetEndpointError::ChecklistMissing);
        }

        let (publisher_base_url, aggregator_base_url) = match mode {
            MainnetEndpointMode::OfficialMainnet => {
                if custom_publisher_url.is_some() || custom_aggregator_url.is_some() {
                    return Err(MainnetEndpointError::CustomUrlForbidden);
                }
                (
                    WALRUS_MAINNET_PUBLISHER_BASE_URL.to_owned(),
                    WALRUS_MAINNET_AGGREGATOR_BASE_URL.to_owned(),
                )
            }
            MainnetEndpointMode::SelfHost => {
                let p = custom_publisher_url.ok_or(MainnetEndpointError::SelfHostUrlRequired)?;
                let a = custom_aggregator_url.ok_or(MainnetEndpointError::SelfHostUrlRequired)?;
                if !is_valid_walrus_https_url(p) || !is_valid_walrus_https_url(a) {
                    return Err(MainnetEndpointError::NonWalrusEndpoint);
                }
                (p.trim().to_owned(), a.trim().to_owned())
            }
        };

        Ok(Self {
            mode,
            publisher_base_url,
            aggregator_base_url,
            checklist_receipt_hash_32: config.checklist_receipt_hash_32,
        })
    }

    /// The endpoint's resolution mode.
    #[inline]
    #[must_use]
    pub const fn mode(&self) -> MainnetEndpointMode {
        self.mode
    }

    /// The resolved publisher base URL.
    #[inline]
    #[must_use]
    pub fn publisher_base_url(&self) -> &str {
        &self.publisher_base_url
    }

    /// The resolved aggregator base URL.
    #[inline]
    #[must_use]
    pub fn aggregator_base_url(&self) -> &str {
        &self.aggregator_base_url
    }

    /// The checklist receipt hash this endpoint is gated on (non-zero).
    #[inline]
    #[must_use]
    pub const fn checklist_receipt_hash_32(&self) -> &[u8; 32] {
        &self.checklist_receipt_hash_32
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;
    use crate::aggregator::{AggregatorGetRequest, AggregatorTransport};
    use crate::publisher::{
        BoundaryState, PublisherPutRequest, PublisherTransport, PublisherTransportFailure,
        PublisherTransportResponse, TransportFailureKind,
    };
    use mnemos_a_core::MainnetExecutionState;

    fn good_config() -> SealedMainnetConfig {
        SealedMainnetConfig {
            chain_env: StageCChainEnv::MainnetPrepared,
            execution_state: MainnetExecutionState::Locked,
            checklist_receipt_hash_32: [0x11u8; 32],
        }
    }

    /// A config with a zero checklist receipt hash is rejected (defense in
    /// depth over the parser's parse-time check).
    #[test]
    fn c2_1_checklist_missing_reject() {
        let mut cfg = good_config();
        cfg.checklist_receipt_hash_32 = [0u8; 32];
        assert_eq!(
            MainnetWalrusEndpoint::from_sealed_config(
                &cfg,
                MainnetEndpointMode::OfficialMainnet,
                None,
                None,
            ),
            Err(MainnetEndpointError::ChecklistMissing),
        );

        // An executable config is also rejected (cannot happen via the config
        // parser, re-checked here).
        let mut exec = good_config();
        exec.execution_state = MainnetExecutionState::Executed;
        assert_eq!(
            MainnetWalrusEndpoint::from_sealed_config(
                &exec,
                MainnetEndpointMode::OfficialMainnet,
                None,
                None,
            ),
            Err(MainnetEndpointError::ExecutableConfigForbidden),
        );
    }

    // Stub transports proving the mainnet endpoint reuses the canonical
    // transport traits (no new trait is minted). `put_blob` / `get_blob` are
    // never invoked here — this test issues no PUT/GET.
    struct StubPublisherTransport;
    impl PublisherTransport for StubPublisherTransport {
        fn put_blob(
            &mut self,
            _request: &PublisherPutRequest<'_>,
        ) -> Result<PublisherTransportResponse, PublisherTransportFailure> {
            Err(PublisherTransportFailure {
                kind: TransportFailureKind::Connect,
                boundary: BoundaryState::NoExternalMutation,
                elapsed_ms_u32: 0,
            })
        }
    }
    struct StubAggregatorTransport;
    impl AggregatorTransport for StubAggregatorTransport {
        fn get_blob(
            &mut self,
            _request: &AggregatorGetRequest<'_>,
        ) -> Result<PublisherTransportResponse, PublisherTransportFailure> {
            Err(PublisherTransportFailure {
                kind: TransportFailureKind::Connect,
                boundary: BoundaryState::NoExternalMutation,
                elapsed_ms_u32: 0,
            })
        }
    }
    fn binds<T: PublisherTransport, A: AggregatorTransport>(_t: &T, _a: &A) {}

    /// The official mainnet endpoint resolves to the sanctioned hosts and
    /// composes with the canonical `PublisherTransport` / `AggregatorTransport`
    /// traits (compile-time proof; no PUT/GET is issued).
    #[test]
    fn c2_1_transport_trait_reuse() {
        let cfg = good_config();
        let ep = MainnetWalrusEndpoint::from_sealed_config(
            &cfg,
            MainnetEndpointMode::OfficialMainnet,
            None,
            None,
        )
        .expect("official endpoint");
        assert_eq!(ep.publisher_base_url(), WALRUS_MAINNET_PUBLISHER_BASE_URL);
        assert_eq!(ep.aggregator_base_url(), WALRUS_MAINNET_AGGREGATOR_BASE_URL);
        assert_eq!(ep.mode(), MainnetEndpointMode::OfficialMainnet);

        let t = StubPublisherTransport;
        let a = StubAggregatorTransport;
        binds(&t, &a);
    }

    /// A custom URL is rejected in official mode and accepted (when a valid
    /// `https` Walrus URL) in self-host mode.
    #[test]
    fn c2_1_custom_url_reject_unless_self_host() {
        let cfg = good_config();
        // Official mode + custom URL → forbidden.
        assert_eq!(
            MainnetWalrusEndpoint::from_sealed_config(
                &cfg,
                MainnetEndpointMode::OfficialMainnet,
                Some("https://publisher.example-walrus.internal"),
                None,
            ),
            Err(MainnetEndpointError::CustomUrlForbidden),
        );
        // Self-host mode + missing URL → required.
        assert_eq!(
            MainnetWalrusEndpoint::from_sealed_config(
                &cfg,
                MainnetEndpointMode::SelfHost,
                None,
                None,
            ),
            Err(MainnetEndpointError::SelfHostUrlRequired),
        );
        // Self-host mode + valid https URLs → ok.
        let ep = MainnetWalrusEndpoint::from_sealed_config(
            &cfg,
            MainnetEndpointMode::SelfHost,
            Some("https://publisher.example-walrus.internal"),
            Some("https://aggregator.example-walrus.internal"),
        )
        .expect("self-host endpoint");
        assert_eq!(ep.mode(), MainnetEndpointMode::SelfHost);
        assert_eq!(
            ep.publisher_base_url(),
            "https://publisher.example-walrus.internal"
        );
    }

    /// `ipfs://` / `filecoin://` / non-`https` / query-injected endpoints are
    /// rejected even in self-host mode.
    #[test]
    fn c2_1_ipfs_filecoin_endpoint_rejected() {
        let cfg = good_config();
        for bad in [
            "ipfs://QmSyntheticFixtureHash",
            "filecoin://f01234/synthetic",
            "http://publisher.walrus-mainnet.walrus.space",
            "file:///tmp/blob",
            "https://publisher.example-walrus.internal?redirect=evil",
            "https://publisher.example-walrus.internal#frag",
            "https://",
        ] {
            assert_eq!(
                MainnetWalrusEndpoint::from_sealed_config(
                    &cfg,
                    MainnetEndpointMode::SelfHost,
                    Some(bad),
                    Some("https://aggregator.example-walrus.internal"),
                ),
                Err(MainnetEndpointError::NonWalrusEndpoint),
                "endpoint {bad:?} must be rejected",
            );
        }
    }
}
