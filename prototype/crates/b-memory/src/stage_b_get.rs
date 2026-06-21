//! Stage B Walrus testnet GET **request planner** (atom #105 · B.2.4) and
//! **response parser** (atom #106 · B.2.5).
//!
//! This module mints the §4.2 canonical OUT [`WalrusGetPlan`] — the borrowed,
//! trace-stamped description of a single Walrus testnet GET (blob fetch) — plus
//! the #106 GET response parser [`parse_walrus_get_response`], which classifies
//! a received aggregator response into the fetched blob body
//! ([`WalrusGetBody`], body bytes + content length, capped before allocation)
//! or a content-free [`WalrusClientError`]. It is the fifth and sixth Cluster 2
//! atoms, after #101's
//! [`WalrusTestnetEndpoint`](crate::stage_b_walrus_endpoint::WalrusTestnetEndpoint),
//! #102's [`StageBReqwestWalrusClient`](crate::stage_b_http::StageBReqwestWalrusClient),
//! and #103/#104's PUT planner + response parser
//! ([`WalrusPutPlan`](crate::stage_b_put::WalrusPutPlan) /
//! [`parse_walrus_put_response`](crate::stage_b_put::parse_walrus_put_response)).
//!
//! ## What a GET planner is (and is not)
//!
//! A [`WalrusGetPlan`] is a *plan*, not an action. [`WalrusGetPlan::plan`]
//! borrows a [`VerifiedBlobId`] (zero copy) and binds an atom #81
//! [`StageBTraceLink`] to the planned request so every external fetch is
//! traceable. It performs **no** GET, opens no socket, and constructs no HTTP
//! type: the transport execution (`stage_b_get_with_transport`, §4.2) is a
//! later atom. The GET response parser (#106 · [`parse_walrus_get_response`])
//! lives in this module (below); it classifies an *already-received* response
//! body and never opens a socket. The plan is a `Copy` value
//! carrier holding a borrow of the verified id, so it can be inspected,
//! asserted on, and handed to a transport without an intermediate allocation.
//!
//! ## Verified-id-only by construction (`G-B-BLOB-ID-VERIFY`)
//!
//! The madness invariant for a GET is *no-trust on the server's self-report*:
//! a Walrus aggregator GET must target an id the caller has **locally derived
//! and verified**, never a bare server-reported text. The planner enforces this
//! at the type level — [`WalrusGetPlan::plan`] accepts only a
//! [`VerifiedBlobId`], whose sole construction path is
//! [`verify_reported_blob_id`](mnemos_c_walrus::verify_reported_blob_id) (atom
//! #108, a byte-for-byte local-derive match). A
//! [`ReportedBlobId`](crate::stage_b_put::ReportedBlobId) (the #104 undecoded,
//! untrusted publisher token) or any raw `&str` is **not representable** as a
//! GET input: there is no constructor overload that takes one. "an unverified
//! server text cannot fetch or anchor" is therefore a compile-time guarantee,
//! not a runtime branch — mirroring #103's "trace required by construction".
//!
//! ## Endpoint sanctioned by construction
//!
//! The GET endpoint is the Stage A closed
//! [`AggregatorEndpoint`](mnemos_c_walrus::AggregatorEndpoint), whose only
//! constructor is `AggregatorEndpoint::testnet_public()` (a sealed marker with
//! no host or path field to override). The public testnet aggregator is thus
//! the only reachable target — the GET-side structural equivalent of #101's
//! PUT endpoint allowlist — so no endpoint reject is producible here and the
//! planner returns no [`WalrusClientError::EndpointDenied`].
//!
//! ## Trace required by construction (`G-B-TRACE`)
//!
//! As with #103, the planner takes the trace as an atom #94
//! [`StageBTraceEvidence`], not a bare [`StageBTraceLink`].
//! `StageBTraceEvidence` can only exist for a *stamped* trace
//! (`atom_id_u16 != 0`); the unstamped / missing sentinel (`atom_id_u16 == 0`,
//! Stage A atom `#0` `RESET`) is rejected fail-closed by
//! [`StageBTraceEvidence::from_trace`] / `::embed` and so is **not
//! representable** as a planner input. The §4.2 [`WalrusGetPlan::trace`] field
//! stores the unwrapped [`StageBTraceLink`].
//!
//! ## Infallible by construction (no `Result`)
//!
//! Because all three inputs are guaranteed by their types —
//! [`AggregatorEndpoint`](mnemos_c_walrus::AggregatorEndpoint) is testnet by
//! construction, [`VerifiedBlobId`] is verified by construction, and
//! [`StageBTraceEvidence`] is stamped by construction — there is no plan-time
//! failure mode. [`WalrusGetPlan::plan`] is therefore a total `const fn`
//! returning `Self`, not a `Result`. No [`WalrusClientError`] is returned at
//! plan time (the transport execution atom owns the runtime error surface); the
//! enum is named here only in the doc trust-boundary narrative.
//!
//! ## Crate-home decision (#101-#104, user-ratified — applies to #105)
//!
//! The plan's `file:` field names `c-walrus`, but #105 reuses the `b-memory`
//! types [`StageBTraceLink`] and [`StageBTraceEvidence`] and binds them above
//! the raw transport. Hosting the planner in `c-walrus` would require
//! `c-walrus` to import `b-memory` types and form a cargo-rejected
//! `c-walrus -> b-memory -> c-walrus` cycle (`cargo metadata` confirms the sole
//! edge is `b-memory -> c-walrus`). The user ratified the Cluster 2 home
//! decision for the whole #101-#120 cluster: Walrus client wrappers live in
//! `b-memory`, `c-walrus` stays raw transport. Only the plan's `file:` crate is
//! corrected; the §4.2 canonical OUT shape is honoured verbatim.
//!
//! [`StageBTraceEvidence`]: crate::trace_link::StageBTraceEvidence
//! [`StageBTraceEvidence::from_trace`]: crate::trace_link::StageBTraceEvidence::from_trace
//! [`StageBTraceLink`]: crate::stage_b_handoff::StageBTraceLink
//! [`VerifiedBlobId`]: mnemos_c_walrus::VerifiedBlobId
//! [`WalrusClientError`]: crate::stage_b_put::WalrusClientError
//! [`WalrusClientError::EndpointDenied`]: crate::stage_b_put::WalrusClientError::EndpointDenied

use mnemos_c_walrus::{
    AggregatorEndpoint, AggregatorGetRequest, AggregatorGetUrl, AggregatorResponseDecision,
    MAX_CONTENT_BYTES, PublisherClientError, VerifiedBlobId, classify_aggregator_response,
    encoded_len_for_content_len,
};

use crate::stage_b_handoff::StageBTraceLink;
use crate::stage_b_put::WalrusClientError;
use crate::trace_link::StageBTraceEvidence;

/// A planned Walrus testnet GET (§4.2 canonical OUT). Owns nothing of variable
/// size: the blob id is a borrow of a caller-held [`VerifiedBlobId`] (lifetime
/// `'a`), held inside the Stage A [`AggregatorGetRequest`]. Build it with
/// [`WalrusGetPlan::plan`], which accepts only a verified id (a server's
/// undecoded report is not representable as input) and requires a stamped trace
/// by construction.
///
/// The fields are `pub` per the §4.2 canonical registry; [`plan`](Self::plan)
/// is the enforcing constructor and [`trace`](Self::trace) /
/// [`get_url`](Self::get_url) are zero-cost accessors. The type is `Copy` and
/// `Debug`-only (no `Display`), and the trace is the content-free
/// `(trace_id, atom_id, attempt)` stamp, so a formatted plan reveals no memory
/// content.
#[derive(Clone, Copy, Debug)]
pub struct WalrusGetPlan<'a> {
    /// The Stage A planned GET request: sealed testnet aggregator endpoint +
    /// borrowed, locally-verified blob id. Reused verbatim from `c-walrus`.
    pub request: AggregatorGetRequest<'a>,
    /// The atom #81 trace stamp this GET is bound to. Always a *stamped* trace
    /// (`atom_id_u16 != 0`), guaranteed by the [`StageBTraceEvidence`] input to
    /// [`plan`](Self::plan).
    pub trace: StageBTraceLink,
}

impl<'a> WalrusGetPlan<'a> {
    /// Plan a Walrus testnet GET, requiring a locally-verified blob id and a
    /// stamped trace — both enforced at the type level, so the constructor is
    /// total (`const fn`, no `Result`).
    ///
    /// Steps, in order:
    ///
    /// 1. **Verified id only** (`G-B-BLOB-ID-VERIFY`): `verified` is a
    ///    [`VerifiedBlobId`], whose only construction path is the #108 local
    ///    derive-and-match. A bare [`ReportedBlobId`](crate::stage_b_put::ReportedBlobId)
    ///    or `&str` cannot be passed, so an unverified server self-report can
    ///    never fetch or anchor.
    /// 2. **Sanctioned endpoint**: `endpoint` is the closed
    ///    [`AggregatorEndpoint`](mnemos_c_walrus::AggregatorEndpoint) (testnet
    ///    by construction, no host/path override), so no endpoint reject is
    ///    producible here.
    /// 3. **Borrow the id** (Stage A [`AggregatorGetRequest::new`], zero copy):
    ///    the request borrows the verified id for lifetime `'a`; the aggregator
    ///    never owns a copy.
    /// 4. **Stamp the trace**: the `trace` argument is a [`StageBTraceEvidence`],
    ///    which can only exist for a stamped trace, so the stored
    ///    [`StageBTraceLink`] is never the missing sentinel.
    #[inline]
    #[must_use]
    pub const fn plan(
        endpoint: AggregatorEndpoint,
        verified: &'a VerifiedBlobId,
        trace: StageBTraceEvidence,
    ) -> Self {
        // The request borrows the *verified* id only; `as_blob_id` exposes the
        // inner 32-byte id without ever surfacing a raw, server-trusted id.
        let request = AggregatorGetRequest::new(endpoint, verified.as_blob_id());
        Self {
            request,
            // Unwrap the stamped trace (atom_id_u16 != 0 guaranteed by #94).
            trace: trace.trace(),
        }
    }

    /// The trace stamp this GET is bound to (always stamped, `atom_id_u16 != 0`).
    #[inline]
    #[must_use]
    pub const fn trace(&self) -> StageBTraceLink {
        self.trace
    }

    /// The canonical aggregator GET URL this plan targets. Composed from the
    /// sealed testnet endpoint and the verified blob id, so the path encoding is
    /// stable and deterministic (lowercase hex blob-id segment).
    #[inline]
    #[must_use]
    pub fn get_url(&self) -> AggregatorGetUrl {
        self.request.get_url()
    }
}

// ===========================================================================
// atom #106 (B.2.5) — GET response parser: fetched blob body, capped.
// ===========================================================================

/// Maximum GET response body the parser will admit, in bytes.
///
/// A Walrus aggregator GET returns the *stored blob*, which in this system is
/// an encoded Stage A chunk ([`encode_chunk_v1`](mnemos_c_walrus::encode_chunk_v1)).
/// The largest legal blob is therefore the encoded length of a maximum-content
/// chunk, [`encoded_len_for_content_len`]`(`[`MAX_CONTENT_BYTES`]`)` — the body
/// cap is derived from the codec contract rather than hard-coded, so it tracks
/// the chunk limit automatically. Anything larger than this is a misbehaving
/// aggregator or a proxy dumping an oversized page, and is rejected
/// [`WalrusClientError::OversizedBody`] **before** any allocation past the cap
/// (`classify_aggregator_response` checks the length first; see
/// [`parse_walrus_get_response`]).
const WALRUS_GET_BODY_CAP_BYTES: u32 = match encoded_len_for_content_len(MAX_CONTENT_BYTES) {
    Ok(encoded_len) => encoded_len as u32,
    // Unreachable: `MAX_CONTENT_BYTES` is in range by definition, so the codec
    // never rejects it. Fail-closed to the strictly-smaller content cap (never
    // a larger bound) if the codec contract ever changes underneath us.
    Err(_) => MAX_CONTENT_BYTES,
};

/// A fetched Walrus testnet blob body (§4.2 GET response, atom #106).
///
/// Owns the bytes returned by the aggregator together with their content length
/// (`content_length_u32 == body.len()`, guaranteed by construction). The body
/// is admitted only after the [`WALRUS_GET_BODY_CAP_BYTES`] cap check, so a
/// value of this type can never hold more than the maximum legal encoded chunk.
///
/// The bytes are the *retrieved* memory content, so [`Debug`] is **redacted**:
/// it prints only `content_length_u32` and a `..` marker, never the body bytes,
/// mirroring the content-free posture of the rest of Cluster 2 (`G-B-SEAL-STUB`
/// redaction-by-construction). Use [`body`](Self::body) to read the bytes
/// explicitly. This type is *not* a verified blob: matching the bytes against a
/// locally-derived id is the verify stage (`verify_reported_blob_id`, #108).
#[derive(Clone, PartialEq, Eq)]
pub struct WalrusGetBody {
    /// The fetched blob bytes, length `<= WALRUS_GET_BODY_CAP_BYTES`.
    body: Vec<u8>,
    /// Length of [`Self::body`] in bytes (`== body.len()`), fit into `u32`.
    content_length_u32: u32,
}

impl WalrusGetBody {
    /// The fetched blob bytes (borrowed; the body the aggregator returned).
    #[inline]
    #[must_use]
    pub fn body(&self) -> &[u8] {
        &self.body
    }

    /// The content length in bytes (`== self.body().len()`).
    #[inline]
    #[must_use]
    pub const fn content_length(&self) -> u32 {
        self.content_length_u32
    }

    /// Consume the parsed response and take ownership of the blob bytes (for the
    /// #108 verify stage, which derives the local id and matches it).
    #[inline]
    #[must_use]
    pub fn into_body(self) -> Vec<u8> {
        self.body
    }
}

/// Redacted `Debug`: the fetched bytes are memory content and are never printed.
impl core::fmt::Debug for WalrusGetBody {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("WalrusGetBody")
            .field("content_length_u32", &self.content_length_u32)
            .finish_non_exhaustive()
    }
}

/// Parses a Walrus testnet GET response — HTTP status + received body — into the
/// fetched blob body, capping the body **before** allocation.
///
/// The classification of the HTTP status into a fetch outcome is the Stage A
/// canonical [`classify_aggregator_response`]; this Stage B wrapper reuses it
/// verbatim (the `b-memory -> c-walrus` edge) and maps the raw outcome onto the
/// frozen §4.2 [`WalrusClientError`] surface, so a caller sees a single,
/// content-free Stage B error type. The body cap is fixed at
/// [`WALRUS_GET_BODY_CAP_BYTES`] (the maximum legal encoded chunk); the caller
/// cannot widen it.
///
/// # Returns / Errors
/// - `Ok(`[`WalrusGetBody`]`)` — **found**: HTTP 200 with a body within the cap.
/// - [`WalrusClientError::OversizedBody`] — the body exceeds the cap (mapped
///   from Stage A's `ResponseBodyTooLarge`, rejected before any over-cap copy).
/// - [`WalrusClientError::Protocol`] — every non-fetched outcome: **not found**
///   (HTTP 404), a 3xx/4xx/5xx terminal/semantic status (**malformed status**),
///   and an unsupported status (1xx or outside HTTP's 100–599 range). Because
///   §4.2's `WalrusClientError` is frozen at seven variants with no `NotFound`,
///   a 404 collapses to `Protocol`: a GET only ever targets a
///   [`VerifiedBlobId`] (the caller already locally derived the id from bytes it
///   holds), so the aggregator failing to return that blob is a protocol /
///   availability anomaly, not a benign miss. Every variant is a data-free tag
///   carrying no status code, host, or body, so a logged error leaks nothing.
///
/// `BoundaryUnknown` / `Transport` are not produced here: a GET is read-only
/// (no external-mutation boundary) and this parser sees an already-received
/// body, not a live socket — those tags belong to the transport / retry atoms.
pub fn parse_walrus_get_response(
    http_status_u16: u16,
    body: &[u8],
) -> Result<WalrusGetBody, WalrusClientError> {
    match classify_aggregator_response(http_status_u16, body, WALRUS_GET_BODY_CAP_BYTES) {
        // Found: HTTP 200 with a within-cap body. `content_len_u32 == body.len()`
        // is guaranteed by the Stage A classifier.
        Ok(AggregatorResponseDecision::Fetched {
            body: fetched,
            content_len_u32,
        }) => Ok(WalrusGetBody {
            body: fetched,
            content_length_u32: content_len_u32,
        }),
        // Any non-fetched outcome (404 not-found, 3xx/4xx/5xx malformed status):
        // no trustworthy blob body, so the response shape is rejected. The
        // non-exhaustive wildcard keeps a future decision variant denied-by-default.
        Ok(AggregatorResponseDecision::Stopped { .. }) | Ok(_) => Err(WalrusClientError::Protocol),
        // Over-cap body — the only oversized signal — maps to the content-free
        // oversized tag (no over-cap allocation happened).
        Err(PublisherClientError::ResponseBodyTooLarge { .. }) => {
            Err(WalrusClientError::OversizedBody)
        }
        // Unsupported status (1xx or outside 100–599) and any future physically-
        // invalid input: a malformed status with no extractable blob → Protocol.
        Err(PublisherClientError::ResponseStatusUnsupported { .. }) | Err(_) => {
            Err(WalrusClientError::Protocol)
        }
    }
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    #![allow(clippy::expect_used)]
    #![allow(clippy::panic)]

    use super::*;
    use mnemos_c_walrus::{PublisherReportedBlobId, derive_blob_id, verify_reported_blob_id};

    /// URL-safe base64 (no pad) over a 32-byte id — duplicates `c-walrus`'s
    /// `pub(crate)` encoder (chunk_vectors.rs / #95 test-helper precedent). The
    /// only local-verify path to a [`VerifiedBlobId`] from outside `c-walrus`.
    fn encode_b64url(raw: &[u8; 32]) -> String {
        const ALPHABET: &[u8; 64] =
            b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
        let mut out = String::with_capacity(43);
        let mut buf: u32 = 0;
        let mut bits: u32 = 0;
        for &b in raw {
            buf = (buf << 8) | u32::from(b);
            bits += 8;
            while bits >= 6 {
                bits -= 6;
                out.push(ALPHABET[((buf >> bits) & 0x3F) as usize] as char);
            }
        }
        if bits > 0 {
            out.push(ALPHABET[((buf << (6 - bits)) & 0x3F) as usize] as char);
        }
        out
    }

    /// Build a [`VerifiedBlobId`] from `witness` via the public
    /// `derive_blob_id` then `verify_reported_blob_id` round-trip (a raw
    /// `BlobId` is unrepresentable at this seam, so this is the only
    /// construction path — atom #108).
    fn verified_blob(witness: &[u8]) -> VerifiedBlobId {
        let derived = derive_blob_id(witness);
        let text = encode_b64url(derived.as_bytes());
        let reported = PublisherReportedBlobId::try_from_text(&text).expect("base64url length 43");
        verify_reported_blob_id(witness, &reported).expect("self-derived round-trip verifies")
    }

    /// A stamped trace evidence for atom #105, for the happy-path tests.
    fn stamped_trace() -> StageBTraceEvidence {
        StageBTraceEvidence::from_trace(StageBTraceLink::new(0xA70F_0105, 105, 0))
            .expect("atom_id 105 is a stamped (non-zero) trace")
    }

    /// `b2_4_verified_id_required` — a GET plan can only be built from a
    /// [`VerifiedBlobId`]; the plan's request targets exactly that verified id
    /// (`G-B-BLOB-ID-VERIFY`). The no-trust invariant is type-level: there is no
    /// constructor that accepts a [`ReportedBlobId`](crate::stage_b_put::ReportedBlobId)
    /// or a raw `&str`, so an unverified server self-report cannot fetch.
    #[test]
    fn b2_4_verified_id_required() {
        let witness = b"synthetic-public-fixture-get";
        let verified = verified_blob(witness);
        let plan = WalrusGetPlan::plan(
            AggregatorEndpoint::testnet_public(),
            &verified,
            stamped_trace(),
        );
        // The request borrows the *same* verified id (pointer + bytes equal).
        assert_eq!(
            plan.request.blob_id().as_bytes(),
            verified.as_blob_id().as_bytes(),
            "the planned request must target exactly the verified id",
        );
        assert_eq!(
            plan.request.blob_id() as *const _,
            verified.as_blob_id() as *const _,
            "the id is borrowed, not copied",
        );
        // Independent positive control: the verified id matches a fresh local
        // derivation of the same witness (the server is never the oracle).
        assert_eq!(
            verified.as_blob_id().as_bytes(),
            derive_blob_id(witness).as_bytes(),
        );
    }

    /// `b2_4_path_encoding_stable` — the GET URL composed from the plan is the
    /// canonical, deterministic aggregator URL: it equals the direct
    /// `AggregatorGetUrl::compose` of the same endpoint + id, is byte-stable
    /// across repeated composition, and carries a 43-char URL-safe base64
    /// blob-id segment under the sanctioned testnet base + path (bridge atom
    /// #116.75 — the form the real aggregator parses, not hex).
    #[test]
    fn b2_4_path_encoding_stable() {
        let verified = verified_blob(b"path-encoding-witness");
        let endpoint = AggregatorEndpoint::testnet_public();
        let plan = WalrusGetPlan::plan(endpoint, &verified, stamped_trace());

        let url_a = plan.get_url();
        let url_b = plan.get_url();
        assert_eq!(url_a, url_b, "URL composition is deterministic");

        // Equals the canonical direct composition (independent derivation).
        let direct = AggregatorGetUrl::compose(endpoint, verified.as_blob_id());
        assert_eq!(url_a, direct, "plan URL is the canonical aggregator URL");

        let url_text = url_a.as_str();
        assert!(
            url_text.starts_with(endpoint.base_url()),
            "URL is under the sanctioned testnet base: {url_text}",
        );
        assert!(
            url_text.contains(endpoint.get_path_prefix()),
            "URL carries the GET blob path prefix: {url_text}",
        );
        // The trailing blob-id segment is exactly 43 URL-safe base64 chars.
        let segment = &url_text[url_text.len() - 43..];
        assert!(
            segment
                .bytes()
                .all(|c| c.is_ascii_alphanumeric() || c == b'-' || c == b'_'),
            "blob-id segment is URL-safe base64: {segment}",
        );
    }

    /// `b2_4_trace_required` — a missing/unstamped trace (`atom_id_u16 == 0`) is
    /// not representable as a planner input: [`StageBTraceEvidence::from_trace`]
    /// rejects it fail-closed, so no [`WalrusGetPlan`] can be built without a
    /// real trace (`G-B-TRACE`). A stamped trace builds a plan and is preserved
    /// verbatim on the §4.2 `trace` field.
    #[test]
    fn b2_4_trace_required() {
        // Unstamped trace cannot even produce the evidence the planner requires.
        assert!(
            StageBTraceEvidence::from_trace(StageBTraceLink::new(11, 0, 0)).is_none(),
            "atom_id 0 is the missing-trace sentinel and must be rejected",
        );

        // A stamped trace is accepted and stored verbatim.
        let link = StageBTraceLink::new(0xFEED_0105, 105, 3);
        let evidence = StageBTraceEvidence::from_trace(link).expect("atom_id 105 is stamped");
        let verified = verified_blob(b"trace-required-witness");
        let plan = WalrusGetPlan::plan(AggregatorEndpoint::testnet_public(), &verified, evidence);
        assert_eq!(plan.trace(), link);
        assert_eq!(plan.trace, link);
    }

    /// `b2_4_endpoint_testnet_pinned` — the only constructible endpoint is the
    /// sealed public testnet aggregator; the plan's request reflects that base
    /// URL (no host/path override is representable, so no mainnet/arbitrary host
    /// can be targeted).
    #[test]
    fn b2_4_endpoint_testnet_pinned() {
        let verified = verified_blob(b"endpoint-pin-witness");
        let endpoint = AggregatorEndpoint::testnet_public();
        let plan = WalrusGetPlan::plan(endpoint, &verified, stamped_trace());
        assert_eq!(
            plan.request.endpoint().base_url(),
            AggregatorEndpoint::testnet_public().base_url(),
            "request endpoint is the sanctioned testnet aggregator",
        );
    }

    /// `b2_4_plan_is_copy` — the §4.2 plan is a `Copy` value carrier (it holds a
    /// borrow of the verified id, not an owned allocation), so it can be passed
    /// to a transport by value without a move-out of the caller's id.
    #[test]
    fn b2_4_plan_is_copy() {
        let verified = verified_blob(b"copy-witness");
        let plan = WalrusGetPlan::plan(
            AggregatorEndpoint::testnet_public(),
            &verified,
            stamped_trace(),
        );
        let copied = plan; // Copy, not move.
        assert_eq!(plan.trace(), copied.trace());
        assert_eq!(
            plan.request.blob_id().as_bytes(),
            copied.request.blob_id().as_bytes(),
        );
    }

    // -----------------------------------------------------------------------
    // atom #106 (B.2.5) — GET response parser tests.
    // -----------------------------------------------------------------------

    /// `b2_5_found` — an HTTP 200 with a within-cap body parses to a
    /// [`WalrusGetBody`] holding exactly those bytes, with `content_length`
    /// equal to the body length.
    #[test]
    fn b2_5_found() {
        let blob = b"synthetic-public-fixture-blob-body";
        let parsed = parse_walrus_get_response(200, blob).expect("200 within cap is found");
        assert_eq!(parsed.body(), blob, "the fetched body is returned verbatim");
        assert_eq!(
            parsed.content_length() as usize,
            blob.len(),
            "content_length equals the body length",
        );
        assert_eq!(parsed.content_length() as usize, parsed.body().len());
    }

    /// `b2_5_found_empty` — a 200 with an empty body is a valid (zero-length)
    /// fetch, not an error: `content_length == 0`.
    #[test]
    fn b2_5_found_empty() {
        let parsed = parse_walrus_get_response(200, b"").expect("200 empty body is found");
        assert_eq!(parsed.content_length(), 0);
        assert!(parsed.body().is_empty());
    }

    /// `b2_5_not_found` — an HTTP 404 (the aggregator does not hold the blob)
    /// maps to [`WalrusClientError::Protocol`]. §4.2 has no `NotFound` variant
    /// (frozen at seven), and a GET only ever targets a locally-verified id, so
    /// a 404 is a protocol / availability anomaly, not a benign miss.
    #[test]
    fn b2_5_not_found() {
        assert_eq!(
            parse_walrus_get_response(404, b""),
            Err(WalrusClientError::Protocol),
            "404 (blob absent) maps to the content-free Protocol tag",
        );
        // A 404 with a proxy body is still not-found, never the body.
        assert_eq!(
            parse_walrus_get_response(404, b"<html>404 Not Found</html>"),
            Err(WalrusClientError::Protocol),
        );
    }

    /// `b2_5_oversized` — a body one byte over the cap is rejected
    /// [`WalrusClientError::OversizedBody`] before any over-cap copy; a body of
    /// exactly the cap is still admitted (boundary is inclusive).
    #[test]
    fn b2_5_oversized() {
        let cap = WALRUS_GET_BODY_CAP_BYTES as usize;

        let over = vec![0u8; cap + 1];
        assert_eq!(
            parse_walrus_get_response(200, &over),
            Err(WalrusClientError::OversizedBody),
            "one byte over the cap is rejected oversized",
        );

        // Exactly at the cap is accepted (the cap is the max legal encoded chunk).
        let at_cap = vec![0u8; cap];
        let parsed = parse_walrus_get_response(200, &at_cap).expect("a body at the cap is found");
        assert_eq!(parsed.content_length() as usize, cap);
    }

    /// `b2_5_malformed_status` — every non-200, non-404 status with no
    /// extractable blob (a 3xx redirect, a 4xx terminal, a 5xx server error, a
    /// 1xx informational, and an out-of-range status) maps to
    /// [`WalrusClientError::Protocol`].
    #[test]
    fn b2_5_malformed_status() {
        for status in [302u16, 400, 403, 451, 500, 503, 100, 600, 0] {
            assert_eq!(
                parse_walrus_get_response(status, b"<html>error</html>"),
                Err(WalrusClientError::Protocol),
                "status {status} has no fetchable blob and maps to Protocol",
            );
        }
    }

    /// `b2_5_debug_redacts_body` — the fetched bytes are memory content, so a
    /// `Debug`-formatted [`WalrusGetBody`] reveals only the content length, never
    /// the body bytes (redaction by construction).
    #[test]
    fn b2_5_debug_redacts_body() {
        let secret_marker = b"DO-NOT-LEAK-THIS-CONTENT";
        let parsed =
            parse_walrus_get_response(200, secret_marker).expect("200 within cap is found");
        let rendered = format!("{parsed:?}");
        assert!(
            !rendered.contains("DO-NOT-LEAK-THIS-CONTENT"),
            "Debug must not print the body bytes: {rendered}",
        );
        assert!(
            rendered.contains("content_length_u32"),
            "Debug exposes only the length: {rendered}",
        );
    }

    /// `b2_5_into_body_roundtrips` — `into_body` yields exactly the fetched bytes
    /// for the #108 verify stage.
    #[test]
    fn b2_5_into_body_roundtrips() {
        let blob = b"round-trip-witness-bytes";
        let parsed = parse_walrus_get_response(200, blob).expect("200 within cap is found");
        assert_eq!(parsed.into_body(), blob);
    }
}
