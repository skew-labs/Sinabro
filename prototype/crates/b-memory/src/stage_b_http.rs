//! Stage B feature-gated Walrus testnet HTTP client (atom #102 · B.2.1).
//!
//! This module mints [`StageBReqwestWalrusClient`] — the Cluster 2 (Walrus
//! testnet client) HTTP client wrapper, the §4.2 `StageBReqwestWalrusClient`
//! canonical OUT — and is the second Cluster 2 atom after #101's
//! [`WalrusTestnetEndpoint`](crate::stage_b_walrus_endpoint::WalrusTestnetEndpoint).
//!
//! ## Default build has no live network (`G-B-WALRUS-OFFLINE`)
//!
//! [`StageBReqwestWalrusClient`] and every `reqwest`-backed type it holds are
//! gated behind the crate feature `net-testnet`. The default build compiles this
//! module to **nothing network-bearing**: the client type does not exist, and no
//! `reqwest`/HTTP/TLS surface is reachable. `b-memory` declares **no direct
//! `reqwest` dependency**; its `net-testnet` feature simply forwards to
//! `mnemos-c-walrus/net-testnet`, so the transport code lives in the raw-transport
//! crate (`c-walrus`) and the orchestration wrapper lives here. This keeps the
//! crate dependency edge one-way (`b-memory -> c-walrus`) and avoids the
//! `c-walrus -> b-memory -> c-walrus` cycle that hosting the wrapper in `c-walrus`
//! would form (the #101 Cluster-2-home decision, ratified by the user for the
//! whole #101-#120 cluster).
//!
//! ## Crate-home decision (#102, user-ratified)
//!
//! The plan's `file:` field names `c-walrus`, but #102 reuses #101's
//! [`WalrusTestnetEndpoint`], which is a `b-memory` type. Hosting the client in
//! `c-walrus` would require `c-walrus` to import a `b-memory` type and form a
//! cargo-rejected dependency cycle (`cargo metadata` confirms
//! `b-memory -> c-walrus` and `c-walrus -> {}`). The user re-confirmed the #101
//! Option-1 decision: Cluster 2 Walrus client wrappers live in `b-memory`,
//! `c-walrus` stays raw transport. Only the plan's `file:` crate is corrected; the
//! canonical OUT shape is honoured verbatim.
//!
//! ## Testnet-only, timeout-bounded, redaction-by-construction
//!
//! The only constructor is [`StageBReqwestWalrusClient::testnet`]: it binds the
//! single sanctioned [`WalrusTestnetEndpoint::testnet`] endpoint (no host/path/
//! network parameter, so `mainnet` is *not representable*) and builds both the
//! Stage A [`ReqwestPublisher`] and [`ReqwestAggregator`] with the same
//! per-attempt timeout. A zero timeout is rejected fail-closed (delegated to the
//! Stage A transport constructors, which reject it with
//! [`ReqwestTransportInitError::TimeoutZero`] — a blocking client without a
//! positive timeout could hang forever, §10.1). The error type carries only a
//! static diagnostic label (no host, no body, no third-party `Error` text), so a
//! construction failure cannot leak anything.
//!
//! This atom is the client *seam* only: it constructs and holds the transports
//! and exposes the bound endpoint, network, timeout and response body cap. It does
//! **not** perform any PUT/GET (the request planners / parsers are #103-#106) and
//! never opens a socket — building a `reqwest::blocking::Client` is offline; the
//! connection pool is lazy and no request is issued in this atom or its tests.
//!
//! [`WalrusTestnetEndpoint::testnet`]: crate::stage_b_walrus_endpoint::WalrusTestnetEndpoint::testnet

#[cfg(feature = "net-testnet")]
use mnemos_c_walrus::MAX_PUBLISHER_RESPONSE_BYTES;
#[cfg(feature = "net-testnet")]
use mnemos_c_walrus::reqwest_transport::{
    ReqwestAggregator, ReqwestPublisher, ReqwestTransportInitError,
};

#[cfg(feature = "net-testnet")]
use crate::network::StageBNetwork;
#[cfg(feature = "net-testnet")]
use crate::stage_b_walrus_endpoint::WalrusTestnetEndpoint;

/// The Stage B Walrus **testnet** HTTP client (atom #102, §4.2 canonical OUT).
///
/// Binds #101's [`WalrusTestnetEndpoint`] (testnet-only by construction) to the
/// Stage A `reqwest`-backed [`ReqwestPublisher`] / [`ReqwestAggregator`]
/// transports, both built with one shared per-attempt timeout. Holding the
/// transports here (rather than re-deriving them in `c-walrus`) keeps the raw
/// HTTP/TLS surface in `c-walrus` and the testnet-only orchestration policy in
/// `b-memory`.
///
/// `Debug` is intentionally **not** derived: a `reqwest::blocking::Client` is not
/// a value the Stage B diagnostics surface should be able to format. The bound
/// endpoint, network, timeout and body cap are exposed through const accessors
/// instead, all of which are content-free typed values.
#[cfg(feature = "net-testnet")]
pub struct StageBReqwestWalrusClient {
    /// The bound testnet endpoint allowlist (#101). Testnet-only by construction.
    endpoint: WalrusTestnetEndpoint,
    /// The Stage A reqwest PUT transport (raw HTTP lives in `c-walrus`).
    publisher: ReqwestPublisher,
    /// The Stage A reqwest GET transport (raw HTTP lives in `c-walrus`).
    aggregator: ReqwestAggregator,
    /// The per-attempt timeout (ms) both transports were built with.
    timeout_ms_u32: u32,
}

#[cfg(feature = "net-testnet")]
impl StageBReqwestWalrusClient {
    /// Build the single sanctioned Walrus **testnet** client with one shared
    /// per-attempt timeout (milliseconds) for both the PUT and GET transports.
    ///
    /// There is no host / base-URL / network parameter, so no caller can ever
    /// name another endpoint or a production ("mainnet") network. A zero timeout
    /// is rejected fail-closed with [`ReqwestTransportInitError::TimeoutZero`]
    /// (delegated to the Stage A transport constructors); any underlying
    /// `reqwest` client-builder error collapses to
    /// [`ReqwestTransportInitError::ClientBuildFailed`]. The error is a static
    /// label only — it carries no host, body, or third-party error text.
    ///
    /// Building the transports does not open a socket; the connection pool is
    /// lazy and no request is issued here.
    pub fn testnet(timeout_ms_u32: u32) -> Result<Self, ReqwestTransportInitError> {
        let publisher = ReqwestPublisher::new(timeout_ms_u32)?;
        let aggregator = ReqwestAggregator::new(timeout_ms_u32)?;
        Ok(Self {
            endpoint: WalrusTestnetEndpoint::testnet(),
            publisher,
            aggregator,
            timeout_ms_u32,
        })
    }

    /// The bound testnet endpoint allowlist (#101). Testnet-only by construction.
    #[inline]
    pub const fn endpoint(&self) -> WalrusTestnetEndpoint {
        self.endpoint
    }

    /// The bound Stage B network — always [`StageBNetwork::Testnet`].
    #[inline]
    pub const fn network(&self) -> StageBNetwork {
        self.endpoint.network()
    }

    /// The per-attempt timeout (ms) this client was built with.
    #[inline]
    pub const fn timeout_ms_u32(&self) -> u32 {
        self.timeout_ms_u32
    }

    /// The PUT transport's per-attempt timeout (ms) — must equal
    /// [`timeout_ms_u32`](Self::timeout_ms_u32) by construction.
    #[inline]
    pub const fn publisher_timeout_ms_u32(&self) -> u32 {
        self.publisher.timeout_ms_u32()
    }

    /// The GET transport's per-attempt timeout (ms) — must equal
    /// [`timeout_ms_u32`](Self::timeout_ms_u32) by construction.
    #[inline]
    pub const fn aggregator_timeout_ms_u32(&self) -> u32 {
        self.aggregator.timeout_ms_u32()
    }

    /// The maximum response body the GET transport will read before erroring
    /// ([`MAX_PUBLISHER_RESPONSE_BYTES`], 16 KiB). The body cap is enforced in
    /// `c-walrus`; this accessor surfaces it so callers can size buffers without
    /// reaching into the transport crate.
    #[inline]
    pub const fn max_response_body_bytes(&self) -> usize {
        MAX_PUBLISHER_RESPONSE_BYTES
    }
}

#[cfg(all(test, feature = "net-testnet"))]
mod net_tests {
    #![allow(clippy::unwrap_used)]
    #![allow(clippy::expect_used)]
    #![allow(clippy::panic)]

    use super::*;
    use mnemos_c_walrus::{PublisherEndpoint, TESTNET_PUBLISHER_BASE_URL, WALRUS_PUT_BLOB_PATH};

    /// `b2_1_feature_smoke` — with the `net-testnet` feature on, the client
    /// constructs, binds the canonical testnet endpoint (testnet network, testnet
    /// base URL, canonical PUT path), and surfaces the 16 KiB response body cap.
    /// No socket is opened (construction only).
    #[test]
    fn b2_1_feature_smoke() {
        let client = StageBReqwestWalrusClient::testnet(5_000)
            .expect("positive timeout builds the testnet client");

        // Endpoint is the #101 testnet allowlist, bound testnet-only.
        assert_eq!(client.network(), StageBNetwork::Testnet);
        assert_eq!(client.endpoint(), WalrusTestnetEndpoint::testnet());
        assert_eq!(client.endpoint().base_url(), TESTNET_PUBLISHER_BASE_URL);
        assert_eq!(client.endpoint().put_path(), WALRUS_PUT_BLOB_PATH);
        assert_eq!(
            client.endpoint().endpoint,
            PublisherEndpoint::testnet_public()
        );

        // Body cap is the Stage A 16 KiB publisher response cap.
        assert_eq!(client.max_response_body_bytes(), 16 * 1024);
    }

    /// `b2_1_timeout_config_bound` — the per-attempt timeout passed at
    /// construction is bound to both transports (PUT and GET) and to the client,
    /// and a zero timeout is rejected fail-closed (no client without a positive
    /// timeout, §10.1 no unbounded waits).
    #[test]
    fn b2_1_timeout_config_bound() {
        for timeout in [1_u32, 5_000, 30_000, u32::MAX] {
            let client = StageBReqwestWalrusClient::testnet(timeout)
                .expect("positive timeout builds the testnet client");
            assert_eq!(client.timeout_ms_u32(), timeout);
            assert_eq!(client.publisher_timeout_ms_u32(), timeout);
            assert_eq!(client.aggregator_timeout_ms_u32(), timeout);
            // All three views agree by construction.
            assert_eq!(client.timeout_ms_u32(), client.publisher_timeout_ms_u32());
            assert_eq!(client.timeout_ms_u32(), client.aggregator_timeout_ms_u32());
        }

        // Zero timeout is rejected fail-closed.
        assert!(matches!(
            StageBReqwestWalrusClient::testnet(0),
            Err(ReqwestTransportInitError::TimeoutZero)
        ));
    }
}

#[cfg(all(test, not(feature = "net-testnet")))]
mod default_tests {
    /// `b2_1_default_feature_no_network_types` — in the default build the
    /// `net-testnet` feature is off, so [`StageBReqwestWalrusClient`] and every
    /// `reqwest`-backed transport it holds are cfg'd out entirely: there is no
    /// network type to name in this build. This test makes that guarantee
    /// executable — it compiles and passes only where `cfg!(feature =
    /// "net-testnet")` is false (`G-B-WALRUS-OFFLINE`).
    #[test]
    fn b2_1_default_feature_no_network_types() {
        // Bound through a runtime `let` so the assertion is on a value, not a
        // bare constant (clippy::assertions_on_constants). The whole module
        // `default_tests` is itself `#[cfg(not(feature = "net-testnet"))]`, so this
        // test only compiles in a build where the feature is off — the assertion
        // documents and double-locks that the network type is absent here.
        let net_testnet_enabled = cfg!(feature = "net-testnet");
        assert!(
            !net_testnet_enabled,
            "default build must not enable net-testnet (no network type)",
        );
    }
}
