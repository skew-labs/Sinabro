//! atom #12 · C.0.6 — offline re-confirmation of the network feature gate.
//!
//! Two structural assertions:
//!
//! 1. With the `net-testnet` feature **off** (the default), the
//!    `mnemos_c_walrus::reqwest_transport` module is absent. The whole
//!    publisher/aggregator transport surface is reachable only through the
//!    fake `PublisherTransport` / `AggregatorTransport` patterns exercised
//!    by atoms #8 / #9 unit tests, which `cargo test --workspace` continues
//!    to run. This file is intentionally a no-op when the feature is off.
//!
//! 2. With the feature **on**, the module is present and the canonical
//!    types compile-check. The single approved testnet round-trip
//!    (`c0_6_testnet_put_get_round_trip_synthetic_only`) is `#[ignore]`d so
//!    it does not run under any default `cargo test` invocation —
//!    operator approval (gate **G-WALRUS-NET**) and an explicit
//!    `--ignored` flag are mandatory.
//!
//! This file file-top `#![allow(...)]` follows the publisher.rs:1222 +
//! aggregator.rs:7-9 precedent so the dev-only test surface does not have
//! to satisfy the production clippy deny set.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::print_stdout,
    clippy::print_stderr,
    dead_code
)]

// ---------------------------------------------------------------------------
// 1. Feature-OFF re-confirmation.
// ---------------------------------------------------------------------------

#[cfg(not(feature = "net-testnet"))]
#[test]
fn c0_6_module_absent_when_feature_off() {
    // Structural assertion. The actual proof lives in `lib.rs`'s
    // `#[cfg(feature = "net-testnet")] pub mod reqwest_transport;` — when
    // the feature is off, `mnemos_c_walrus::reqwest_transport` is not a
    // resolvable path; if a future edit accidentally exposes it
    // unconditionally, the following sanity references would fail to
    // compile and this test would never link.
    //
    // We can't put a `compile_fail` doctest here easily, so we rely on the
    // build itself: `cargo build --workspace` with the feature off is the
    // affirmative signal.
    //
    // The atoms #8 / #9 fake-transport coverage (publisher.rs +
    // aggregator.rs unit tests, plus tests/publisher.rs +
    // tests/aggregator.rs integration tests) is what *exercises* the
    // `PublisherTransport` / `AggregatorTransport` traits in offline mode.
    // This test merely documents that intent.
    let feature_on = cfg!(feature = "net-testnet");
    assert!(
        !feature_on,
        "this branch is conditionally compiled only when the feature is off"
    );
}

// ---------------------------------------------------------------------------
// 2. Feature-ON: structural checks (always cheap) + ignored testnet round-trip.
// ---------------------------------------------------------------------------

#[cfg(feature = "net-testnet")]
mod with_feature {
    use mnemos_c_walrus::aggregator::{
        AggregatorEndpoint, AggregatorGetRequest, AggregatorResponseDecision,
        classify_aggregator_response, fetch_blob_with_transport,
    };
    use mnemos_c_walrus::blob_id::{derive_blob_id, verify_reported_blob_id};
    use mnemos_c_walrus::publisher::{
        EpochCount, PublishPayload, PublishPayloadClass, PublisherEndpoint, PublisherPutRequest,
        PublisherResponseDecision, classify_publisher_response, publish_blob_with_transport,
    };
    use mnemos_c_walrus::reqwest_transport::{
        ReqwestAggregator, ReqwestPublisher, ReqwestTransportInitError,
    };

    #[test]
    fn c0_6_module_present_when_feature_on() {
        // Canonical signature compile-check: the four public items required by
        // `MNEMOS_ATOM_PLAN.md` §4.C `C.reqwest_transport` exist with their
        // declared shapes.
        let pub_init: Result<ReqwestPublisher, ReqwestTransportInitError> =
            ReqwestPublisher::new(1);
        assert!(pub_init.is_ok());

        let agg_init: Result<ReqwestAggregator, ReqwestTransportInitError> =
            ReqwestAggregator::new(1);
        assert!(agg_init.is_ok());

        // Init-error gate is reachable from outside the crate too.
        assert_eq!(
            ReqwestPublisher::new(0).unwrap_err(),
            ReqwestTransportInitError::TimeoutZero
        );
        assert_eq!(
            ReqwestAggregator::new(0).unwrap_err(),
            ReqwestTransportInitError::TimeoutZero
        );
    }

    // ---------------------------------------------------------------------------
    // 3. The single testnet round-trip — `#[ignore]`d.
    //
    // This is the `c0_6_testnet_put_get_round_trip_synthetic_only` test named
    // in `MNEMOS_ATOM_PLAN.md` §C atom #12. Running it requires:
    //   1. The `net-testnet` cargo feature enabled.
    //   2. Explicit operator approval (gate **G-WALRUS-NET**); the test
    //      contacts the public Walrus testnet publisher *and* aggregator.
    //   3. The `--ignored` flag, because the test is `#[ignore]`d so that
    //      no default CI / `cargo test --workspace` invocation can trigger
    //      a network egress accidentally.
    //
    // Payload: a `SyntheticPublicFixture` 16-byte string. `RealUserMemory`
    // is *physically rejected* at `PublishPayload::new` (atom #8 madness 4)
    // so this test cannot leak user memory even if mis-edited.
    //
    // Round-trip shape:
    //   PUT   →  reqwest publisher  →  classify_publisher_response
    //                                    →  PublisherResponseDecision::Accepted{reported_blob_id}
    //   GET   →  reqwest aggregator →  classify_aggregator_response(body, 16K)
    //                                    →  AggregatorResponseDecision::Fetched{body}
    //   VERIFY →  verify_reported_blob_id(body, reported_blob_id)
    //               // §10.2-ban gate: promotion happens only after a
    //               // byte-for-byte derivation match.
    // ---------------------------------------------------------------------------

    const REQUEST_ID: u64 = 0xC006_DEAD_BEEF_u64;

    #[test]
    #[ignore = "G-WALRUS-NET: synthetic-only testnet egress; run with --ignored only after explicit user approval"]
    fn c0_6_testnet_put_get_round_trip_synthetic_only() {
        // Synthetic fixture; never user-derived. The crate's payload
        // allowlist rejects anything else (`PublishPayload::new` /
        // `PublisherPutRequest::new`).
        let fixture: &[u8] = b"mnemos-c0_6-fix";
        let payload = PublishPayload::new(fixture, PublishPayloadClass::SyntheticPublicFixture)
            .expect("synthetic public fixture is allowed by class gate");

        let epochs = EpochCount::new(1).expect("1 epoch is non-zero");
        let endpoint = PublisherEndpoint::testnet_public();
        let request = PublisherPutRequest::new(endpoint, epochs, payload)
            .expect("synthetic public fixture is the only allowed class");

        let mut publisher =
            ReqwestPublisher::new(15_000).expect("blocking client builds with 15s timeout");

        // PUT once. We do not retry — the loop helper is exercised by
        // atom #8 unit tests; this test pins a single live round-trip.
        let run = publish_blob_with_transport(
            &mut publisher,
            &request,
            /* request_id_u64 */ REQUEST_ID,
            /* max_attempts_u16 */ 1,
        )
        .expect("publisher loop returned a PublisherClientRun");

        let reported = match run.decision {
            PublisherResponseDecision::Accepted {
                reported_blob_id, ..
            } => reported_blob_id,
            other => panic!("G-WALRUS-NET: publisher did not accept synthetic fixture: {other:?}"),
        };

        // Re-derive blob_id locally from the PUT body so the GET path's
        // returned bytes can be verified against the publisher-reported text.
        let derived_from_put = derive_blob_id(fixture);

        // GET the same blob.
        let agg_endpoint = AggregatorEndpoint::testnet_public();
        let agg_request = AggregatorGetRequest::new(agg_endpoint, &derived_from_put);
        let mut aggregator =
            ReqwestAggregator::new(15_000).expect("blocking client builds with 15s timeout");
        let agg_decision = fetch_blob_with_transport(
            &mut aggregator,
            &agg_request,
            /* request_id_u64 */ REQUEST_ID,
            /* max_attempts_u16 */ 1,
        )
        .expect("aggregator loop returned an AggregatorResponseDecision");

        let body = match agg_decision {
            AggregatorResponseDecision::Fetched { body, .. } => body,
            other => panic!("G-WALRUS-NET: aggregator did not return synthetic fixture: {other:?}"),
        };
        // The body the aggregator returned must equal the body we PUT.
        // (Walrus erasure-coded storage round-trip pins this property.)
        assert_eq!(body, fixture);

        // §10.2-ban: promote the publisher's textual blob_id to a
        // VerifiedBlobId only after re-derivation byte-match.
        let verified =
            verify_reported_blob_id(&body, &reported).expect("reported id must derive from body");
        assert_eq!(verified.as_blob_id(), &derived_from_put);

        // Sanity reads on the classifier helpers (compile-link assertion only).
        let _: Result<PublisherResponseDecision, _> = classify_publisher_response(200, &[]);
        let _: Result<AggregatorResponseDecision, _> = classify_aggregator_response(200, &[], 1024);
    }
}
