//! `reqwest`-backed `PublisherTransport` / `AggregatorTransport` implementations.
//!
//! This module is **feature-gated** behind `net-testnet`. The default
//! workspace build never compiles `reqwest` or any transport HTTP code, so
//! the c-walrus crate's runtime dependency surface stays exactly identical
//! to atoms #7-#11 unless the feature is explicitly enabled.
//!
//! Madness contract (atom #12 · `MNEMOS_ATOM_PLAN.md` §4.C
//! `C.reqwest_transport`):
//!
//! - Network is isolated behind the cargo feature. With `net-testnet` off,
//!   `cargo build --offline` does not pull `reqwest` at all (verified by the
//!   workspace `Cargo.lock` carrying `reqwest` only as an optional package
//!   whose code paths never link).
//! - SHA-pinning is delegated to `Cargo.lock`. Every package the feature
//!   transitively introduces is recorded with a `checksum = "..."` line in
//!   `Cargo.lock`, so a `--offline --locked` build refuses any drift.
//! - Only [`PublishPayloadClass::SyntheticPublicFixture`] is allowed onto the
//!   wire. The blob-allowlist gate sits inside [`PublisherPutRequest::new`]
//!   (atom #8); this transport only re-asserts it via the strongly typed
//!   borrow it receives.
//! - The synchronous `reqwest::blocking::Client` is used so that the c-walrus
//!   crate stays runtime-agnostic. The caller threads (atom #12+ glue) bring
//!   their own scheduling.
//!
//! Gate: **G-WALRUS-NET** (mandatory user in-message approval before
//! `c0_6_testnet_put_get_round_trip_synthetic_only` is exercised; `mainnet`
//! is forbidden by §10.3). The round-trip integration test ships
//! `#[ignore]`d in `tests/reqwest_transport_offline.rs` so it never runs
//! automatically; it must be invoked explicitly with `--ignored` after the
//! operator approves a single synthetic fixture round-trip.
//!
//! [`PublishPayloadClass::SyntheticPublicFixture`]: crate::publisher::PublishPayloadClass::SyntheticPublicFixture
//! [`PublisherPutRequest::new`]: crate::publisher::PublisherPutRequest::new

use core::time::Duration;
use std::error::Error as _;
use std::io::Read;
use std::time::Instant;

use crate::aggregator::{AggregatorGetRequest, AggregatorTransport};
use crate::publisher::{
    BoundaryState, MAX_PUBLISHER_RESPONSE_BYTES, PublisherPutRequest, PublisherTransport,
    PublisherTransportFailure, PublisherTransportResponse, TransportFailureKind,
};

// ===========================================================================
// 1. ReqwestTransportInitError
// ===========================================================================

/// Reason a [`ReqwestPublisher`] or [`ReqwestAggregator`] could not be built.
///
/// The variant set is intentionally narrow: the only failure modes admitted
/// at construction time are an out-of-range timeout (rejected before the
/// reqwest client is touched at all) and an opaque
/// [`ReqwestTransportInitError::ClientBuildFailed`] mapped from
/// `reqwest::Error`. The original error is dropped so this enum stays
/// `Copy` and the c-walrus crate's `#![deny(unsafe_code)]` boundary cannot
/// observe any third-party `Error` body bytes.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
#[non_exhaustive]
#[repr(u8)]
pub enum ReqwestTransportInitError {
    /// `timeout_ms_u32` was zero. A blocking client without a positive
    /// timeout could hang forever; §10.1 (no unbounded waits).
    TimeoutZero = 1,
    /// `reqwest::blocking::Client::builder().build()` returned an error.
    ClientBuildFailed = 2,
}

impl ReqwestTransportInitError {
    /// One-byte wire tag for this init error.
    #[inline]
    pub const fn tag(self) -> u8 {
        self as u8
    }

    /// Stable `&'static str` label used by diagnostics; namespaced
    /// `reqwest_transport_init.*`.
    #[inline]
    pub const fn class_label(self) -> &'static str {
        match self {
            Self::TimeoutZero => "reqwest_transport_init.timeout_zero",
            Self::ClientBuildFailed => "reqwest_transport_init.client_build_failed",
        }
    }
}

// ===========================================================================
// 2. ReqwestPublisher
// ===========================================================================

/// A [`PublisherTransport`] backed by `reqwest::blocking::Client`.
///
/// One [`ReqwestPublisher`] reuses one TCP connection pool across multiple
/// PUT attempts (so retries don't pay TLS handshake again). Construction
/// validates `timeout_ms_u32 > 0` before touching `reqwest`.
#[derive(Debug)]
pub struct ReqwestPublisher {
    client: reqwest::blocking::Client,
    timeout_ms_u32: u32,
}

impl ReqwestPublisher {
    /// Build a publisher with the given per-attempt timeout in milliseconds.
    ///
    /// `timeout_ms_u32 == 0` is rejected with
    /// [`ReqwestTransportInitError::TimeoutZero`]. Any underlying
    /// `reqwest::Error` from the client builder collapses to
    /// [`ReqwestTransportInitError::ClientBuildFailed`].
    pub fn new(timeout_ms_u32: u32) -> Result<Self, ReqwestTransportInitError> {
        if timeout_ms_u32 == 0 {
            return Err(ReqwestTransportInitError::TimeoutZero);
        }
        let builder = reqwest::blocking::Client::builder()
            .timeout(Duration::from_millis(timeout_ms_u32 as u64))
            .https_only(true)
            .redirect(reqwest::redirect::Policy::none());
        match builder.build() {
            Ok(client) => Ok(Self {
                client,
                timeout_ms_u32,
            }),
            Err(_) => Err(ReqwestTransportInitError::ClientBuildFailed),
        }
    }

    /// The per-attempt timeout this publisher was built with.
    #[inline]
    pub const fn timeout_ms_u32(&self) -> u32 {
        self.timeout_ms_u32
    }
}

impl PublisherTransport for ReqwestPublisher {
    fn put_blob(
        &mut self,
        request: &PublisherPutRequest<'_>,
    ) -> Result<PublisherTransportResponse, PublisherTransportFailure> {
        let endpoint = request.endpoint();
        let mut url = String::with_capacity(96);
        url.push_str(endpoint.base_url());
        url.push_str(endpoint.put_path());
        url.push_str("?epochs=");
        push_u64_dec(&mut url, request.epochs().get() as u64);

        let body_bytes = request.body().to_vec();

        let started = Instant::now();
        let send_result = self
            .client
            .put(&url)
            .header(reqwest::header::CONTENT_TYPE, "application/octet-stream")
            .body(body_bytes)
            .send();
        run_response(send_result, started)
    }
}

// ===========================================================================
// 3. ReqwestAggregator
// ===========================================================================

/// An [`AggregatorTransport`] backed by `reqwest::blocking::Client`. The
/// aggregator only ever performs GETs, so every transport-level failure is
/// classified with boundary [`BoundaryState::NoExternalMutation`].
#[derive(Debug)]
pub struct ReqwestAggregator {
    client: reqwest::blocking::Client,
    timeout_ms_u32: u32,
}

impl ReqwestAggregator {
    /// Build an aggregator with the given per-attempt timeout in milliseconds.
    ///
    /// `timeout_ms_u32 == 0` is rejected with
    /// [`ReqwestTransportInitError::TimeoutZero`]. Any underlying
    /// `reqwest::Error` from the client builder collapses to
    /// [`ReqwestTransportInitError::ClientBuildFailed`].
    pub fn new(timeout_ms_u32: u32) -> Result<Self, ReqwestTransportInitError> {
        if timeout_ms_u32 == 0 {
            return Err(ReqwestTransportInitError::TimeoutZero);
        }
        let builder = reqwest::blocking::Client::builder()
            .timeout(Duration::from_millis(timeout_ms_u32 as u64))
            .https_only(true)
            .redirect(reqwest::redirect::Policy::none());
        match builder.build() {
            Ok(client) => Ok(Self {
                client,
                timeout_ms_u32,
            }),
            Err(_) => Err(ReqwestTransportInitError::ClientBuildFailed),
        }
    }

    /// The per-attempt timeout this aggregator was built with.
    #[inline]
    pub const fn timeout_ms_u32(&self) -> u32 {
        self.timeout_ms_u32
    }
}

impl AggregatorTransport for ReqwestAggregator {
    fn get_blob(
        &mut self,
        request: &AggregatorGetRequest<'_>,
    ) -> Result<PublisherTransportResponse, PublisherTransportFailure> {
        let url = request.get_url();

        let started = Instant::now();
        let send_result = self.client.get(url.as_str()).send();
        let response = match send_result {
            Ok(resp) => resp,
            Err(err) => {
                let elapsed_ms_u32 = elapsed_millis_saturating(started.elapsed());
                let kind = classify_reqwest_error_kind(&err, ReqwestPhase::SendOrConnect);
                // GET is read-only by contract — boundary always
                // `NoExternalMutation` (matches atom #9's `classify_aggregator_transport_failure`).
                return Err(PublisherTransportFailure {
                    kind,
                    boundary: BoundaryState::NoExternalMutation,
                    elapsed_ms_u32,
                });
            }
        };

        let http_status_u16 = response.status().as_u16();
        let mut body = Vec::new();
        let read_limit = (MAX_PUBLISHER_RESPONSE_BYTES as u64).saturating_add(1);
        let read_result = (response).take(read_limit).read_to_end(&mut body);
        let elapsed_ms_u32 = elapsed_millis_saturating(started.elapsed());
        match read_result {
            Ok(_) => Ok(PublisherTransportResponse {
                http_status_u16,
                body,
                elapsed_ms_u32,
            }),
            Err(_) => Err(PublisherTransportFailure {
                kind: TransportFailureKind::ResponseTimeout,
                boundary: BoundaryState::NoExternalMutation,
                elapsed_ms_u32,
            }),
        }
    }
}

// ===========================================================================
// 4. Shared helpers
// ===========================================================================

/// Which phase of a reqwest call produced an error.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ReqwestPhase {
    /// Pre-response: builder, DNS, connect, TLS, or request bytes write.
    SendOrConnect,
}

/// Translate a `reqwest::Error` into a [`TransportFailureKind`]. The mapping
/// is conservative — when reqwest's error cannot be decisively attributed,
/// we collapse to [`TransportFailureKind::ResponseTimeout`] (which is the
/// boundary-pessimistic choice on the publisher path; the aggregator path
/// will then attach [`BoundaryState::NoExternalMutation`] separately).
fn classify_reqwest_error_kind(err: &reqwest::Error, _phase: ReqwestPhase) -> TransportFailureKind {
    if err.is_timeout() {
        return TransportFailureKind::ResponseTimeout;
    }
    if err.is_connect() {
        return TransportFailureKind::Connect;
    }
    if is_dns_error(err) {
        return TransportFailureKind::Dns;
    }
    if is_tls_error(err) {
        return TransportFailureKind::Tls;
    }
    if err.is_request() {
        return TransportFailureKind::WriteTimeout;
    }
    TransportFailureKind::ResponseTimeout
}

/// Inspect the error's source chain for a DNS/name resolution hint. The
/// `reqwest::Error` API does not expose DNS as a first-class predicate, so
/// we look for the canonical hyper-util / std error strings. The match is
/// best-effort; on no-hit we fall through to other heuristics.
fn is_dns_error(err: &reqwest::Error) -> bool {
    let mut next: Option<&dyn std::error::Error> = err.source();
    while let Some(cause) = next {
        let s = format!("{cause}");
        if s.contains("dns")
            || s.contains("DNS")
            || s.contains("name resolution")
            || s.contains("nodename nor servname")
        {
            return true;
        }
        next = cause.source();
    }
    false
}

/// Inspect the error's source chain for a TLS-handshake hint. Same caveat
/// as [`is_dns_error`].
fn is_tls_error(err: &reqwest::Error) -> bool {
    let mut next: Option<&dyn std::error::Error> = err.source();
    while let Some(cause) = next {
        let s = format!("{cause}");
        if s.contains("tls")
            || s.contains("TLS")
            || s.contains("certificate")
            || s.contains("handshake")
        {
            return true;
        }
        next = cause.source();
    }
    false
}

/// Read the response body up to `MAX_PUBLISHER_RESPONSE_BYTES + 1` (so that
/// `classify_publisher_response` / `classify_aggregator_response` can reject
/// an oversized body without allocating beyond the cap) and return a
/// completed [`PublisherTransportResponse`]. Failures during body read
/// degrade to a publisher-shaped [`PublisherTransportFailure`] with
/// boundary [`BoundaryState::UnknownAfterBoundary`] (response phase — bytes
/// have already crossed in some unknown amount).
fn run_response(
    send_result: Result<reqwest::blocking::Response, reqwest::Error>,
    started: Instant,
) -> Result<PublisherTransportResponse, PublisherTransportFailure> {
    let response = match send_result {
        Ok(resp) => resp,
        Err(err) => {
            let elapsed_ms_u32 = elapsed_millis_saturating(started.elapsed());
            let kind = classify_reqwest_error_kind(&err, ReqwestPhase::SendOrConnect);
            // Publisher boundary: if the error attributes to "post-send"
            // (timeout / response phase), we must mark UnknownAfterBoundary.
            let boundary = match kind {
                TransportFailureKind::Dns
                | TransportFailureKind::Connect
                | TransportFailureKind::Tls
                | TransportFailureKind::WriteTimeout
                | TransportFailureKind::Cancelled => BoundaryState::NoExternalMutation,
                TransportFailureKind::ResponseTimeout => BoundaryState::UnknownAfterBoundary,
            };
            return Err(PublisherTransportFailure {
                kind,
                boundary,
                elapsed_ms_u32,
            });
        }
    };

    let http_status_u16 = response.status().as_u16();
    let mut body = Vec::new();
    let read_limit = (MAX_PUBLISHER_RESPONSE_BYTES as u64).saturating_add(1);
    let read_result = (response).take(read_limit).read_to_end(&mut body);
    let elapsed_ms_u32 = elapsed_millis_saturating(started.elapsed());
    match read_result {
        Ok(_) => Ok(PublisherTransportResponse {
            http_status_u16,
            body,
            elapsed_ms_u32,
        }),
        Err(_) => Err(PublisherTransportFailure {
            kind: TransportFailureKind::ResponseTimeout,
            boundary: BoundaryState::UnknownAfterBoundary,
            elapsed_ms_u32,
        }),
    }
}

/// Saturate a `Duration` to `u32` milliseconds. Used for diagnostics only;
/// the value is not on any control-flow path.
#[inline]
fn elapsed_millis_saturating(d: Duration) -> u32 {
    let ms = d.as_millis();
    if ms > u32::MAX as u128 {
        u32::MAX
    } else {
        ms as u32
    }
}

/// Append the decimal rendering of `value` to `out`. Copied verbatim in
/// spirit from `publisher::push_u64_dec` so this module does not need to
/// pull a `serde_json`-style stack in.
#[inline]
fn push_u64_dec(out: &mut String, value: u64) {
    if value == 0 {
        out.push('0');
        return;
    }
    let mut digits = [0u8; 20];
    let mut idx = 0usize;
    let mut v = value;
    while v > 0 {
        digits[idx] = b'0' + (v % 10) as u8;
        v /= 10;
        idx += 1;
    }
    while idx > 0 {
        idx -= 1;
        out.push(digits[idx] as char);
    }
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        clippy::print_stdout,
        clippy::print_stderr
    )]

    use super::*;

    #[test]
    fn init_rejects_zero_timeout_for_publisher() {
        assert_eq!(
            ReqwestPublisher::new(0).unwrap_err(),
            ReqwestTransportInitError::TimeoutZero
        );
    }

    #[test]
    fn init_rejects_zero_timeout_for_aggregator() {
        assert_eq!(
            ReqwestAggregator::new(0).unwrap_err(),
            ReqwestTransportInitError::TimeoutZero
        );
    }

    #[test]
    fn init_error_tags_and_labels_are_stable() {
        assert_eq!(ReqwestTransportInitError::TimeoutZero.tag(), 1);
        assert_eq!(ReqwestTransportInitError::ClientBuildFailed.tag(), 2);
        assert_eq!(
            ReqwestTransportInitError::TimeoutZero.class_label(),
            "reqwest_transport_init.timeout_zero"
        );
        assert_eq!(
            ReqwestTransportInitError::ClientBuildFailed.class_label(),
            "reqwest_transport_init.client_build_failed"
        );
    }

    #[test]
    fn push_u64_dec_matches_format() {
        let mut s = String::new();
        push_u64_dec(&mut s, 0);
        assert_eq!(s, "0");
        let mut s = String::new();
        push_u64_dec(&mut s, 1);
        assert_eq!(s, "1");
        let mut s = String::new();
        push_u64_dec(&mut s, 12345);
        assert_eq!(s, "12345");
        let mut s = String::new();
        push_u64_dec(&mut s, u32::MAX as u64);
        assert_eq!(s, format!("{}", u32::MAX));
    }

    #[test]
    fn elapsed_millis_saturates() {
        assert_eq!(elapsed_millis_saturating(Duration::from_millis(0)), 0);
        assert_eq!(elapsed_millis_saturating(Duration::from_millis(42)), 42);
        assert_eq!(
            elapsed_millis_saturating(Duration::from_secs(u32::MAX as u64 + 1)),
            u32::MAX
        );
    }

    #[test]
    fn publisher_constructs_with_nonzero_timeout() {
        let pubr = ReqwestPublisher::new(5_000).expect("client builds with 5s timeout");
        assert_eq!(pubr.timeout_ms_u32(), 5_000);
    }

    #[test]
    fn aggregator_constructs_with_nonzero_timeout() {
        let agg = ReqwestAggregator::new(5_000).expect("client builds with 5s timeout");
        assert_eq!(agg.timeout_ms_u32(), 5_000);
    }
}
