//! Self-host (bring-your-own) Walrus **mainnet** transport.
//!
//! The deploy-time model: each user runs their OWN `walrus publisher` (their
//! wallet pays) or a hosted one, and plugs its **https** URL + a bearer **token**
//! into the config. Our app then stores its two-tier encrypted memory there.
//!
//! # Why this is an EGRESS transport, NOT custody (the safety reframe)
//!
//! A self-host PUT = an *authenticated HTTP PUT* to the user's publisher. The publisher
//! pays and Sui-signs; **our app holds no Sui key, never signs, never pays**. So this is
//! a peer of the other egress transports ([`super::web_fetch`] / `download_fetch` /
//! `web3_rpc` + the c-walrus testnet publisher), and **custody stays HARD-LOCKED**
//! (`CustodyCapability` uninhabited; a raw Sui private key is never represented here).
//!
//! # The paranoia set (mirrors [`super::web_fetch::WebFetchTransport`])
//!
//! * Endpoint URL is validated by an ALWAYS-COMPILED wall ([`classify_walrus_endpoint`]):
//!   the base-URL rule (https-only, ascii, no whitespace, no `?`/`#` — the same rule as
//!   c-walrus `is_valid_walrus_https_url`) composed with the canonical SSRF wall
//!   ([`super::web_fetch::classify_url`]: no IP-literal / localhost / userinfo / chain-RPC).
//! * The reqwest client is `https_only(true)` + `redirect(none)` + `no_proxy()` + a per-call
//!   timeout (a 3xx → internal-host exfil is impossible; no proxy MITM).
//! * The bearer **token** rides `WALRUS_PUBLISHER_TOKEN` (a memory-only secret). It is read
//!   ONLY at the TLS boundary inside [`WalrusSelfHostTransport::put_blob`], sent ONLY as
//!   `Authorization: Bearer`, and is never logged / rendered / persisted.
//! * Content is secret-screened before a PUT: only `EncryptedUserMemory` (AEAD ciphertext,
//!   key stays local) or a `SyntheticPublicFixture` may leave — every PLAINTEXT class is
//!   denied (kept byte-in-sync with the c-walrus testnet admit by a verifier).
//! * Body cap (`PUBLIC_PUBLISHER_BODY_CAP_BYTES`) + response cap; the GET receipt is an
//!   aggregator round-trip byte-match (the mainnet RS2 oracle differs, so a local
//!   re-derive is testnet-only — the byte-match is the honest mainnet receipt).
//!
//! Reads (GET) are READ-class autonomous; WRITES (PUT) fire only from the owner-armed
//! ceremony in `dispatch.rs`. This module mints the transport primitives only.

use super::web_fetch::{SafeUrl, WebFetchDenied, classify_url};

/// The env var carrying the self-host publisher BEARER token. A memory-only secret
/// (the GUI sets it via the `set_secret` allowlist; the CLI reads it from the
/// environment). Read ONLY at the TLS boundary in [`WalrusSelfHostTransport::put_blob`],
/// sent ONLY as `Authorization: Bearer`, NEVER logged / rendered / persisted. This is
/// NEVER a Sui private key — our app holds no key and never signs.
pub const WALRUS_PUBLISHER_TOKEN_ENV: &str = "WALRUS_PUBLISHER_TOKEN";

/// Default storage epochs for a self-host write (conservative; the user's publisher
/// pays per epoch). Mirrors the testnet `EpochCount::new(1)`.
pub const WALRUS_MAINNET_DEFAULT_EPOCHS: u16 = 1;

/// Per-call timeout (ms) for the self-host transport. Matches the testnet
/// `PUT_FIXTURE_TIMEOUT_MS` so propagation behaviour is comparable.
pub const WALRUS_SELFHOST_TIMEOUT_MS: u32 = 30_000;

/// Why a configured Walrus endpoint URL was refused (fail-closed). The raw URL is
/// not echoed back (only the SSRF sub-reason is carried) so a rejected URL cannot
/// leak verbatim through the error.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum WalrusEndpointDenied {
    /// Empty / whitespace-only after trim.
    Empty,
    /// Non-ASCII bytes in the URL (an IDN / homograph surface).
    NonAscii,
    /// Embedded whitespace.
    Whitespace,
    /// A `?` query or `#` fragment in a base URL (an injection surface; a base URL
    /// is host-only). Mirrors c-walrus `is_valid_walrus_https_url`.
    QueryOrFragment,
    /// Failed the canonical SSRF wall ([`classify_url`]): not-https, IP-literal,
    /// localhost-class, embedded userinfo, or a known chain-RPC host.
    Ssrf(WebFetchDenied),
}

/// A Walrus endpoint base URL that PASSED both the base-URL rule (https-only, ascii,
/// no whitespace, no `?`/`#`) AND the canonical SSRF wall ([`classify_url`]).
/// Construction is the proof it is safe to dial. The trailing `/` is normalized off
/// so `{base}/v1/blobs…` never double-slashes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SafeWalrusEndpoint {
    base_url: String,
    host: String,
}

impl SafeWalrusEndpoint {
    /// The normalized base URL (https, no trailing slash). Safe to dial.
    #[inline]
    #[must_use]
    pub fn base_url(&self) -> &str {
        &self.base_url
    }

    /// The lowercased host (DNS name — never an IP literal / localhost).
    #[inline]
    #[must_use]
    pub fn host(&self) -> &str {
        &self.host
    }
}

/// ALWAYS-COMPILED wall: validate a configured Walrus endpoint base URL. Composes the
/// base-URL rule (the c-walrus `is_valid_walrus_https_url` rule: https-only + ascii +
/// no whitespace + no `?`/`#`) with the canonical SSRF wall ([`classify_url`]:
/// https-only, no IP-literal / localhost / userinfo / chain-RPC host). Fail-closed.
/// Testable in the default build (no feature needed).
///
/// # Errors
///
/// [`WalrusEndpointDenied`] for an empty / non-ascii / whitespace / query-or-fragment
/// URL, or [`WalrusEndpointDenied::Ssrf`] for anything the SSRF wall refuses.
pub fn classify_walrus_endpoint(raw: &str) -> Result<SafeWalrusEndpoint, WalrusEndpointDenied> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Err(WalrusEndpointDenied::Empty);
    }
    if !trimmed.is_ascii() {
        return Err(WalrusEndpointDenied::NonAscii);
    }
    if trimmed.contains(char::is_whitespace) {
        return Err(WalrusEndpointDenied::Whitespace);
    }
    if trimmed.contains('?') || trimmed.contains('#') {
        return Err(WalrusEndpointDenied::QueryOrFragment);
    }
    // Canonical SSRF wall (reused, not re-minted): https-only + no userinfo / IP-literal /
    // localhost / known chain-RPC host. A deny here cannot be bypassed.
    let safe: SafeUrl = classify_url(trimmed).map_err(WalrusEndpointDenied::Ssrf)?;
    let base_url = trimmed.trim_end_matches('/').to_string();
    Ok(SafeWalrusEndpoint {
        base_url,
        host: safe.host().to_string(),
    })
}

// ===========================================================================
// Config resolvers (always-compiled — no reqwest; the SINGLE source of "is the
// self-host endpoint configured + valid", consumed by BOTH the dispatch WRITE
// ceremony and the auto-activate READ path)
// ===========================================================================

/// Read the owner-configured self-host endpoint VALUES (publisher, aggregator) from the
/// persisted config — the SAME read path as the other config-derived surfaces
/// (`read_owner_web3_rpc_endpoint`). Absent / unreadable / empty ⇒ `None`.
fn read_owner_walrus_endpoints() -> (Option<String>, Option<String>) {
    let Ok(dir) = crate::memory_store::data_dir() else {
        return (None, None);
    };
    let path = dir.join(crate::config::CONFIG_PERSIST_FILE);
    let Ok(text) = std::fs::read_to_string(&path) else {
        return (None, None);
    };
    let Ok(cfg) = crate::config::parse_layer(&text) else {
        return (None, None);
    };
    let layers = [(crate::config::ConfigLayer::User, cfg)];
    (
        crate::config::effective_walrus_publisher_endpoint(&layers),
        crate::config::effective_walrus_aggregator_endpoint(&layers),
    )
}

/// The configured self-host PUBLISHER endpoint, validated through the wall, or `None`
/// when unset / invalid (honest "not configured"). The ONLY input to a self-host PUT.
#[must_use]
pub fn configured_walrus_publisher() -> Option<SafeWalrusEndpoint> {
    classify_walrus_endpoint(&read_owner_walrus_endpoints().0?).ok()
}

/// The configured self-host AGGREGATOR endpoint, validated through the wall, or `None`
/// when unset / invalid. The ONLY input to a self-host GET (the auto-activate READ).
#[must_use]
pub fn configured_walrus_aggregator() -> Option<SafeWalrusEndpoint> {
    classify_walrus_endpoint(&read_owner_walrus_endpoints().1?).ok()
}

// ===========================================================================
// Feature-gated executable transport (walrus-mainnet)
// ===========================================================================

/// Why a self-host PUT / GET denied (fail-closed; no partial trust). A wrong /
/// unverified blob-id is never returned as success.
#[cfg(feature = "walrus-mainnet")]
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum WalrusSelfHostDenied {
    /// The reqwest client builder itself failed.
    TransportInit,
    /// `epochs == 0` (a blob with zero storage epochs is meaningless).
    EpochsZero,
    /// The payload class is not wire-admitted (a PLAINTEXT class) — secret-zero.
    ContentClassRejected,
    /// The body exceeded `PUBLIC_PUBLISHER_BODY_CAP_BYTES`.
    BodyOverCap,
    /// Network / TLS / timeout — the endpoint was not reached, or the read failed.
    Unreachable,
    /// The publisher / aggregator returned a non-2xx status.
    HttpStatus(u16),
    /// A 2xx publisher response carried no parseable blob-id.
    BlobIdUnreported,
    /// The reported / requested blob-id is not a valid Walrus id (43-char b64url).
    BlobIdInvalid,
    /// The response body exceeded its cap before completion.
    ResponseOverCap,
}

/// The live self-host transport (compiled ONLY under `walrus-mainnet`). Holds ONE
/// pooled blocking client with the paranoia set (`https_only(true)`, `redirect(none)`,
/// `no_proxy()`, per-call timeout). PUT carries the bearer (read at the boundary); GET
/// is secret-zero (no auth header).
#[cfg(feature = "walrus-mainnet")]
#[derive(Debug)]
pub struct WalrusSelfHostTransport {
    client: reqwest::blocking::Client,
}

#[cfg(feature = "walrus-mainnet")]
impl WalrusSelfHostTransport {
    /// Build the transport with the default timeout + the paranoia set. `None` only when
    /// the client builder itself fails (typed fail-closed).
    #[must_use]
    pub fn new() -> Option<Self> {
        let client = reqwest::blocking::Client::builder()
            .timeout(std::time::Duration::from_millis(u64::from(
                WALRUS_SELFHOST_TIMEOUT_MS,
            )))
            .https_only(true)
            .redirect(reqwest::redirect::Policy::none())
            .no_proxy()
            .user_agent("sinabro-walrus-selfhost/1.0")
            .build()
            .ok()?;
        Some(Self { client })
    }

    /// PUT `body` (class-screened) to the self-host publisher and return the
    /// publisher-REPORTED blob-id TEXT (UNVERIFIED — the caller proves it by an
    /// aggregator round-trip GET byte-match; the mainnet RS2 oracle differs from
    /// testnet, so a local re-derive is testnet-only).
    ///
    /// The `WALRUS_PUBLISHER_TOKEN` bearer (if set) is read HERE, at the TLS boundary,
    /// sent ONLY as `Authorization: Bearer`, and never logged.
    ///
    /// # Errors
    ///
    /// [`WalrusSelfHostDenied`] for a rejected content class, an over-cap body, an
    /// unreachable / non-2xx endpoint, or an unreported / invalid blob-id.
    pub fn put_blob(
        &self,
        publisher: &SafeWalrusEndpoint,
        epochs: u16,
        body: &[u8],
        class: mnemos_c_walrus::publisher::PublishPayloadClass,
    ) -> Result<String, WalrusSelfHostDenied> {
        use mnemos_c_walrus::publisher::{
            EpochCount, MAX_PUBLISHER_RESPONSE_BYTES, PublishPayload, PublishPayloadClass,
            PublisherResponseDecision, classify_publisher_response,
        };
        use std::io::Read as _;

        // Content secret-screen (mirrors c-walrus `PublisherPutRequest::new`):
        // ONLY ciphertext (EncryptedUserMemory) or a synthetic fixture may leave the
        // process; every PLAINTEXT class is denied (secret-zero). A verifier pins
        // these two admit arms == the c-walrus testnet admit arms, so the two paths
        // can never drift.
        match class {
            PublishPayloadClass::SyntheticPublicFixture
            | PublishPayloadClass::EncryptedUserMemory => {}
            _ => return Err(WalrusSelfHostDenied::ContentClassRejected),
        }
        // Body cap (canonical, reused): `PublishPayload::new` checks
        // `PUBLIC_PUBLISHER_BODY_CAP_BYTES` before any allocation.
        PublishPayload::new(body, class).map_err(|_| WalrusSelfHostDenied::BodyOverCap)?;
        // Canonical positive-epoch check (reused).
        let epochs = EpochCount::new(epochs)
            .map_err(|_| WalrusSelfHostDenied::EpochsZero)?
            .get();

        let url = format!("{}/v1/blobs?epochs={}", publisher.base_url(), epochs);
        let mut req = self
            .client
            .put(&url)
            .header(reqwest::header::CONTENT_TYPE, "application/octet-stream");
        // BEARER: read the memory-only secret at the boundary; redacted everywhere else.
        if let Ok(token) = std::env::var(WALRUS_PUBLISHER_TOKEN_ENV) {
            if !token.is_empty() {
                req = req.header(reqwest::header::AUTHORIZATION, format!("Bearer {token}"));
            }
        }
        let resp = req
            .body(body.to_vec())
            .send()
            .map_err(|_| WalrusSelfHostDenied::Unreachable)?;
        let status = resp.status().as_u16();
        // Response cap (16 KiB publisher JSON) before alloc/parse.
        let mut buf = Vec::new();
        let read_cap = (MAX_PUBLISHER_RESPONSE_BYTES as u64).saturating_add(1);
        resp.take(read_cap)
            .read_to_end(&mut buf)
            .map_err(|_| WalrusSelfHostDenied::Unreachable)?;
        if buf.len() > MAX_PUBLISHER_RESPONSE_BYTES {
            return Err(WalrusSelfHostDenied::ResponseOverCap);
        }
        // Parse the reported blob-id via the canonical c-walrus classifier (same JSON
        // shapes as testnet: `newlyCreated.blobObject.blobId` / `alreadyCertified.blobId`).
        match classify_publisher_response(status, &buf) {
            Ok(PublisherResponseDecision::Accepted {
                reported_blob_id, ..
            }) => {
                let text = reported_blob_id.as_str().to_string();
                // Sanity: the reported id must be a structurally valid Walrus id; the
                // round-trip GET byte-match (S3) is the real proof.
                if mnemos_c_walrus::blob_id_from_text(&text).is_none() {
                    return Err(WalrusSelfHostDenied::BlobIdInvalid);
                }
                Ok(text)
            }
            Ok(_) => Err(WalrusSelfHostDenied::HttpStatus(status)),
            Err(_) => Err(WalrusSelfHostDenied::BlobIdUnreported),
        }
    }

    /// GET a blob by id text from the self-host aggregator (READ-class, secret-zero —
    /// no auth header). Returns the raw bytes (UNTRUSTED until the caller's AEAD open
    /// verifies the tag). The response cap equals the PUT body cap so a round-trip can
    /// always return the full blob for a byte-match.
    ///
    /// # Errors
    ///
    /// [`WalrusSelfHostDenied`] for an invalid id, an unreachable / non-2xx aggregator,
    /// or an over-cap body.
    pub fn get_blob(
        &self,
        aggregator: &SafeWalrusEndpoint,
        blob_id_text: &str,
    ) -> Result<Vec<u8>, WalrusSelfHostDenied> {
        use mnemos_c_walrus::publisher::PUBLIC_PUBLISHER_BODY_CAP_BYTES;
        use std::io::Read as _;

        // Validate the id (43-char b64url) before building the URL (no path injection).
        if mnemos_c_walrus::blob_id_from_text(blob_id_text).is_none() {
            return Err(WalrusSelfHostDenied::BlobIdInvalid);
        }
        let url = format!("{}/v1/blobs/{}", aggregator.base_url(), blob_id_text);
        let resp = self
            .client
            .get(&url)
            .send()
            .map_err(|_| WalrusSelfHostDenied::Unreachable)?;
        let status = resp.status().as_u16();
        if !(200..=299).contains(&status) {
            return Err(WalrusSelfHostDenied::HttpStatus(status));
        }
        let mut buf = Vec::new();
        let read_cap = (PUBLIC_PUBLISHER_BODY_CAP_BYTES as u64).saturating_add(1);
        resp.take(read_cap)
            .read_to_end(&mut buf)
            .map_err(|_| WalrusSelfHostDenied::Unreachable)?;
        if buf.len() > PUBLIC_PUBLISHER_BODY_CAP_BYTES as usize {
            return Err(WalrusSelfHostDenied::ResponseOverCap);
        }
        Ok(buf)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // The wall runs in the DEFAULT build (no feature needed) — these prove it is not
    // vacuous: a real https Walrus URL is admitted, every unsafe shape is denied.

    #[test]
    fn admits_a_valid_https_walrus_url() {
        let ok = classify_walrus_endpoint("https://publisher.walrus-mainnet.walrus.space")
            .expect("a plain https host is admitted");
        assert_eq!(
            ok.base_url(),
            "https://publisher.walrus-mainnet.walrus.space"
        );
        assert_eq!(ok.host(), "publisher.walrus-mainnet.walrus.space");
        // A trailing slash is normalized off (no double-slash in `{base}/v1/blobs`).
        let trimmed = classify_walrus_endpoint("https://agg.example.test/").expect("admit");
        assert_eq!(trimmed.base_url(), "https://agg.example.test");
    }

    #[test]
    fn denies_non_https_and_ssrf_shapes() {
        // Non-https → SSRF wall NotHttps.
        assert!(matches!(
            classify_walrus_endpoint("http://publisher.walrus.space"),
            Err(WalrusEndpointDenied::Ssrf(_))
        ));
        // IP literal, localhost, userinfo → SSRF wall.
        for bad in [
            "https://127.0.0.1",
            "https://localhost",
            "https://user:pass@publisher.walrus.space",
            "https://[::1]",
        ] {
            assert!(
                matches!(
                    classify_walrus_endpoint(bad),
                    Err(WalrusEndpointDenied::Ssrf(_))
                ),
                "must SSRF-deny {bad:?}"
            );
        }
    }

    #[test]
    fn denies_query_fragment_whitespace_nonascii_empty() {
        assert_eq!(
            classify_walrus_endpoint("https://pub.example.test?x=1"),
            Err(WalrusEndpointDenied::QueryOrFragment)
        );
        assert_eq!(
            classify_walrus_endpoint("https://pub.example.test#frag"),
            Err(WalrusEndpointDenied::QueryOrFragment)
        );
        assert_eq!(
            classify_walrus_endpoint("https://pub.example.test/a b"),
            Err(WalrusEndpointDenied::Whitespace)
        );
        assert_eq!(
            classify_walrus_endpoint("https://pub.exämple.test"),
            Err(WalrusEndpointDenied::NonAscii)
        );
        assert_eq!(
            classify_walrus_endpoint("   "),
            Err(WalrusEndpointDenied::Empty)
        );
    }

    /// LIVE self-host TESTNET round-trip (the NO-RISK proof of the mainnet code path).
    /// Points the self-host transport at the public Walrus TESTNET endpoints (valid
    /// self-host-shaped https URLs) and round-trips a SYNTHETIC fixture: PUT → reported
    /// blob-id → aggregator GET → BYTE-MATCH. This exercises the EXACT mainnet path (the
    /// direct-reqwest PUT/GET + the c-walrus response parse + the round-trip receipt) with
    /// ZERO mainnet funds/risk — the safe proving ground before the owner fires the real
    /// mainnet ceremony.
    ///
    /// `#[ignore]`d: it performs real network I/O, so it never runs in the default
    /// suite. Run after owner approval:
    ///   cargo test -p sinabro --features walrus-mainnet selfhost_testnet_round_trip -- --ignored --nocapture
    #[cfg(feature = "walrus-mainnet")]
    #[test]
    #[ignore = "G-WALRUS-NET: live testnet network round-trip; run with --ignored after owner approval"]
    fn selfhost_testnet_round_trip_synthetic() {
        use mnemos_c_walrus::publisher::PublishPayloadClass;
        let publisher = classify_walrus_endpoint("https://publisher.walrus-testnet.walrus.space")
            .expect("testnet publisher URL passes the wall");
        let aggregator = classify_walrus_endpoint("https://aggregator.walrus-testnet.walrus.space")
            .expect("testnet aggregator URL passes the wall");
        let transport = WalrusSelfHostTransport::new().expect("transport builds");
        let fixture = b"sinabro-walrus-selfhost-testnet-roundtrip-fixture-v1";
        let blob_id = transport
            .put_blob(
                &publisher,
                1,
                fixture,
                PublishPayloadClass::SyntheticPublicFixture,
            )
            .expect("PUT returns a reported blob-id");
        let fetched = transport
            .get_blob(&aggregator, &blob_id)
            .expect("GET fetches the blob back");
        assert_eq!(
            fetched.as_slice(),
            &fixture[..],
            "round-trip byte-match (the mainnet receipt discipline)"
        );
    }
}
