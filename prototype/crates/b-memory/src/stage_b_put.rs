//! Stage B Walrus testnet PUT **request planner**.
//!
//! This module mints the canonical [`WalrusPutPlan`] — the borrowed,
//! policy-gated, trace-stamped description of a single Walrus testnet PUT — plus
//! the client error enum [`WalrusClientError`]. It builds on
//! [`WalrusTestnetEndpoint`](crate::stage_b_walrus_endpoint::WalrusTestnetEndpoint)
//! and
//! [`StageBReqwestWalrusClient`](crate::stage_b_http::StageBReqwestWalrusClient).
//!
//! ## What a planner is (and is not)
//!
//! A [`WalrusPutPlan`] is a *plan*, not an action. [`WalrusPutPlan::plan`]
//! borrows the caller's payload bytes (zero copy), enforces the Stage B publish
//! content-class policy **before** any transport type is touched, and binds a
//! [`StageBTraceLink`] to the planned request so every external action
//! is traceable. It performs **no** PUT, opens no socket, and constructs no HTTP
//! type: the transport execution (`stage_b_put_with_transport`) is a separate
//! concern. The PUT response parser (`parse_walrus_put_response`) lives in
//! this module (below); it returns the publisher-reported blob id **untrusted**.
//! The plan is a `Copy` value carrier
//! that holds a borrow of the body, so it can be inspected, asserted on, and
//! handed to a transport without an intermediate allocation.
//!
//! ## Content-class policy enforced before transport (`G-B-SEAL-STUB`)
//!
//! The planner reads
//! [`stage_b_publish_decision`](crate::stage_b_policy::stage_b_publish_decision)
//! — the three-way decision layered over [`stage_b_publish_allowed`]
//! — *first*. Only [`PublishPayloadClass::SyntheticPublicFixture`] decides
//! [`Admit`](crate::stage_b_policy::StageBPublishDecision::Admit) and is admitted
//! onto the public testnet; user-owned real memory decides
//! [`RequireOwnerSignature`](crate::stage_b_policy::StageBPublishDecision::RequireOwnerSignature),
//! and prompt / provider text, tool output, secret-like bytes, and private
//! provenance decide [`DenyClass`](crate::stage_b_policy::StageBPublishDecision::DenyClass)
//! — all denied fail-closed with [`WalrusClientError::PayloadClassDenied`]
//! **before** the Stage A [`PublishPayload`] / [`PublisherPutRequest`] are ever
//! constructed, so a private, secret-like, or user-owned payload never reaches
//! the raw `c-walrus` request boundary. Stage A's `PublisherPutRequest::new`
//! re-enforces the same single-class admission as an independent inner defense;
//! if the two layers ever disagree the inner reject also maps to
//! `PayloadClassDenied`.
//!
//! ## Trace required by construction (`G-B-TRACE`)
//!
//! The planner takes the trace as a [`StageBTraceEvidence`], not a bare
//! [`StageBTraceLink`]. `StageBTraceEvidence` can only exist for a *stamped*
//! trace (`atom_id_u16 != 0`); the unstamped / missing sentinel
//! (`atom_id_u16 == 0`, the `RESET` marker) is rejected fail-closed by
//! [`StageBTraceEvidence::from_trace`] / `::embed` and so is **not representable**
//! as a planner input. "trace required" is therefore a type-level guarantee, not
//! a runtime branch — there is no `WalrusClientError` variant for a missing trace
//! because a plan without a real trace cannot be built. The
//! [`WalrusPutPlan::trace`] field stores the unwrapped [`StageBTraceLink`].
//!
//! ## `WalrusClientError` — Stage B Walrus orchestration / policy error
//!
//! [`WalrusClientError`] is minted here (the first signature to
//! return it — following the same pattern as
//! [`StageBChunkError`](crate::StageBChunkError), whose first-returning
//! signature mints its error set). Its
//! home is `b-memory`, not `c-walrus`: it is the Stage B **orchestration /
//! policy / trace / blob-verify / boundary** error, layered *above* the raw
//! transport. The raw publisher URL / payload / body / response-parser error
//! stays in `c-walrus` as
//! [`PublisherClientError`](mnemos_c_walrus::PublisherClientError); the two are
//! deliberately distinct types at distinct layers. The
//! full variant set is minted frozen `#[non_exhaustive]`; this module consumes
//! [`PayloadClassDenied`](WalrusClientError::PayloadClassDenied) and
//! [`OversizedBody`](WalrusClientError::OversizedBody), and the remaining
//! variants are forward-reserved for later work (see each variant
//! doc). Every variant is a data-free `Copy` tag carrying only a static
//! `&'static str` label — no host, URL, body, provider text, secret, response
//! body, or third-party error string can be embedded, so a client error cannot
//! leak anything (redaction by construction).
//!
//! ## Crate-home decision
//!
//! The plan's `file:` field names `c-walrus`, but this module reuses several
//! `b-memory` types and binds them above the raw transport. Hosting the
//! planner in `c-walrus` would require `c-walrus` to import `b-memory` types and
//! form a cargo-rejected `c-walrus -> b-memory -> c-walrus` cycle. The home
//! decision for the whole Walrus client cluster is:
//! Walrus client wrappers live in `b-memory`, `c-walrus` stays raw transport.
//! Only the plan's `file:` crate is corrected; the canonical output shape is
//! honoured verbatim.
//!
//! [`stage_b_publish_allowed`]: crate::content_policy::stage_b_publish_allowed
//! [`StageBTraceEvidence`]: crate::trace_link::StageBTraceEvidence
//! [`StageBTraceEvidence::from_trace`]: crate::trace_link::StageBTraceEvidence::from_trace
//! [`StageBTraceLink`]: crate::stage_b_handoff::StageBTraceLink
//! [`PublishPayloadClass::SyntheticPublicFixture`]: mnemos_c_walrus::PublishPayloadClass::SyntheticPublicFixture

use mnemos_c_walrus::{PublishPayload, PublisherPutRequest};

use crate::chunk_schema::PublishPayloadClass;
use crate::stage_b_handoff::StageBTraceLink;
use crate::stage_b_policy::{StageBPublishDecision, stage_b_publish_decision};
use crate::stage_b_walrus_endpoint::WalrusTestnetEndpoint;
use crate::trace_link::StageBTraceEvidence;

// Re-exported for reuse; named here so the constructor signature and
// the doc links resolve without a full path at every use site.
use mnemos_c_walrus::EpochCount;

/// Stage B Walrus client error. The orchestration / policy / trace /
/// blob-verify / boundary error layered *above* the raw `c-walrus` transport,
/// minted in `b-memory` (the first signature to return
/// it). Distinct from `c-walrus`'s raw
/// [`PublisherClientError`](mnemos_c_walrus::PublisherClientError).
///
/// Every variant is a data-free `Copy` tag: it carries no host, URL, body,
/// provider text, secret, response body, or third-party error string, so a
/// client error can never leak content (redaction by construction). The set is
/// frozen `#[non_exhaustive]` so a future variant is denied-by-default at every
/// `match` and never silently admitted.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
#[non_exhaustive]
pub enum WalrusClientError {
    /// The requested endpoint is not the sanctioned Walrus testnet endpoint.
    /// Forward-reserved: a planner variant that accepts an externally-supplied
    /// candidate URL/endpoint maps an allowlist reject here. Currently the
    /// endpoint is the already-validated [`WalrusTestnetEndpoint`] (testnet
    /// by construction), so this variant is not produced by [`WalrusPutPlan::plan`].
    EndpointDenied,
    /// The payload's content class is not admissible onto the public testnet.
    /// **Consumed here**: [`WalrusPutPlan::plan`] returns this when
    /// [`stage_b_publish_allowed`](crate::content_policy::stage_b_publish_allowed)
    /// denies the class (and as the mapped form of Stage A's independent inner
    /// `PublisherPutRequest::new` class reject).
    PayloadClassDenied,
    /// A transport-level failure (DNS, connect, TLS, timeout, reset). Forward-
    /// reserved for the transport execution path (`stage_b_put_with_transport`);
    /// never produced by the offline planner.
    Transport,
    /// The server's response violated the expected Walrus protocol shape.
    /// Forward-reserved for the #104 PUT response parser.
    Protocol,
    /// A server-reported blob id did not match the locally-derived blob id.
    /// Forward-reserved for the #108 reported-blob-id verify (the server is never
    /// trusted as a blob-id oracle).
    BlobIdMismatch,
    /// A body exceeded the allowed cap. **Consumed at #103** as the mapped form
    /// of Stage A's `PublishPayload::new` `PayloadTooLarge`
    /// (`PUBLIC_PUBLISHER_BODY_CAP_BYTES`); also forward-reserved for the #104
    /// oversized-response-body reject.
    OversizedBody,
    /// The transport crossed the external-mutation boundary with an unknown
    /// outcome (bytes may or may not have landed). Forward-reserved for the #110
    /// boundary-aware retry; a planner produces no boundary state.
    BoundaryUnknown,
}

impl WalrusClientError {
    /// Stable `&'static str` label for this error, namespaced `walrus.*`. Used in
    /// diagnostics in place of any captured host / body / third-party text, so a
    /// logged client error stays content-free.
    #[inline]
    pub const fn class_label(self) -> &'static str {
        match self {
            Self::EndpointDenied => "walrus.endpoint_denied",
            Self::PayloadClassDenied => "walrus.payload_class_denied",
            Self::Transport => "walrus.transport",
            Self::Protocol => "walrus.protocol",
            Self::BlobIdMismatch => "walrus.blob_id_mismatch",
            Self::OversizedBody => "walrus.oversized_body",
            Self::BoundaryUnknown => "walrus.boundary_unknown",
        }
    }
}

/// A planned Walrus testnet PUT. Owns nothing of variable
/// size: the body is a borrow of the caller's payload bytes (lifetime `'a`),
/// held inside the Stage A [`PublisherPutRequest`]. Build it with
/// [`WalrusPutPlan::plan`], which enforces the content-class policy before the
/// request is constructed and requires a stamped trace by construction.
///
/// The fields are `pub` per the canonical registry; [`plan`](Self::plan) is
/// the enforcing constructor and [`body`](Self::body) / [`trace`](Self::trace)
/// are zero-cost accessors. The type is `Copy` and `Debug`-only (no `Display`),
/// and the trace is the content-free `(trace_id, atom_id, attempt)` stamp, so a
/// formatted plan reveals no payload content.
#[derive(Clone, Copy, Debug)]
pub struct WalrusPutPlan<'a> {
    /// The Stage A planned PUT request: sealed testnet endpoint + epoch count +
    /// borrowed, class-checked payload. Reused verbatim from `c-walrus`.
    pub request: PublisherPutRequest<'a>,
    /// The trace stamp this PUT is bound to. Always a *stamped* trace
    /// (`atom_id_u16 != 0`), guaranteed by the [`StageBTraceEvidence`] input to
    /// [`plan`](Self::plan).
    pub trace: StageBTraceLink,
}

impl<'a> WalrusPutPlan<'a> {
    /// Plan a Walrus testnet PUT, enforcing the Stage B publish policy *before*
    /// any transport type is constructed and binding a stamped trace.
    ///
    /// Steps, in order:
    ///
    /// 1. **Content-class policy before transport**: consult
    ///    [`stage_b_publish_decision`](crate::stage_b_policy::stage_b_publish_decision).
    ///    Only [`StageBPublishDecision::Admit`](crate::stage_b_policy::StageBPublishDecision::Admit)
    ///    continues; both [`DenyClass`](crate::stage_b_policy::StageBPublishDecision::DenyClass)
    ///    and [`RequireOwnerSignature`](crate::stage_b_policy::StageBPublishDecision::RequireOwnerSignature)
    ///    return [`WalrusClientError::PayloadClassDenied`] immediately — before
    ///    the Stage A [`PublishPayload`] / [`PublisherPutRequest`] are touched,
    ///    so a private / secret-like / user-owned payload never reaches the raw
    ///    request boundary.
    /// 2. **Borrow bytes + body cap** (Stage A [`PublishPayload::new`], zero
    ///    copy): an over-cap body (`PUBLIC_PUBLISHER_BODY_CAP_BYTES`) maps to
    ///    [`WalrusClientError::OversizedBody`].
    /// 3. **Build the request** (Stage A [`PublisherPutRequest::new`]): its
    ///    independent single-class admission is the inner defense; any reject
    ///    maps to [`WalrusClientError::PayloadClassDenied`].
    /// 4. **Stamp the trace**: the `trace` argument is a [`StageBTraceEvidence`],
    ///    which can only exist for a stamped trace, so the stored
    ///    [`StageBTraceLink`] is never the missing sentinel.
    ///
    /// `endpoint` is the already-validated [`WalrusTestnetEndpoint`]
    /// (testnet by construction), so no endpoint reject is produced here.
    pub const fn plan(
        endpoint: WalrusTestnetEndpoint,
        epochs: EpochCount,
        bytes: &'a [u8],
        class: PublishPayloadClass,
        trace: StageBTraceEvidence,
    ) -> Result<Self, WalrusClientError> {
        // 1. Stage B content-class policy gate, BEFORE any c-walrus
        //    request type. The richer three-way decision distinguishes the
        //    owner-signature dimension; both denial arms fail closed to
        //    `PayloadClassDenied` so a private / secret-like / user-owned payload
        //    never builds a transport request (zero transport calls on denial).
        match stage_b_publish_decision(class) {
            StageBPublishDecision::Admit => {}
            StageBPublishDecision::DenyClass | StageBPublishDecision::RequireOwnerSignature => {
                return Err(WalrusClientError::PayloadClassDenied);
            }
        }
        // 2. Borrow the bytes and enforce the body cap (zero-copy; Stage A).
        let payload = match PublishPayload::new(bytes, class) {
            Ok(payload) => payload,
            Err(_) => return Err(WalrusClientError::OversizedBody),
        };
        // 3. Build the Stage A request. Its inner single-class admission is an
        //    independent defense; map any reject to the Stage B policy error.
        let request = match PublisherPutRequest::new(endpoint.endpoint, epochs, payload) {
            Ok(request) => request,
            Err(_) => return Err(WalrusClientError::PayloadClassDenied),
        };
        // 4. Unwrap the stamped trace (atom_id_u16 != 0 guaranteed by #94).
        Ok(Self {
            request,
            trace: trace.trace(),
        })
    }

    /// The trace stamp this PUT is bound to (always stamped, `atom_id_u16 != 0`).
    #[inline]
    pub const fn trace(&self) -> StageBTraceLink {
        self.trace
    }

    /// The borrowed body bytes (lifetime `'a`), a zero-copy alias of the
    /// caller's payload — `plan(bytes)` stores the same slice the request will
    /// write, with no intermediate copy.
    #[inline]
    pub const fn body(&self) -> &'a [u8] {
        self.request.body()
    }
}

// ===========================================================================
// PUT response parser: reported (untrusted) blob id.
// ===========================================================================

/// Maximum Walrus PUT response body the parser will read (oversized → error).
///
/// A success response is a small JSON object; anything larger is a misbehaving
/// publisher or a proxy dumping an error page, and is rejected before parsing.
/// Mirrors the 16 KiB request-body cap.
const WALRUS_PUT_RESPONSE_MAX_BYTES: usize = 16 * 1024;

/// Maximum length (bytes) of a reported blob-id token the parser will accept.
///
/// A Walrus blob id is URL-safe `base64` (no padding) over 32 bytes = 43 chars.
/// A little headroom is allowed; anything longer is treated as malformed. The
/// exact `base64` decode and 32-byte length check belong to the verify stage
/// (#108) — this parser does not interpret the token.
const REPORTED_BLOB_ID_MAX_LEN: usize = 64;

/// A publisher-**reported** Walrus blob id, parsed from a PUT response.
///
/// Holds the blob-id token exactly as the publisher reported it (URL-safe
/// `base64`, **undecoded**). It is deliberately *not* a `VerifiedBlobId`:
/// obtaining one of those requires decoding this token and matching it against
/// the locally derived id (`verify_reported_blob_id`). Keeping the
/// two types distinct means a reported id can never be mistaken for a verified
/// one at a call site — the publisher is never a blob-id oracle.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReportedBlobId {
    /// Reported token bytes, zero-padded; `len` marks the valid prefix.
    bytes: [u8; REPORTED_BLOB_ID_MAX_LEN],
    /// Number of valid bytes in `bytes` (always `<= REPORTED_BLOB_ID_MAX_LEN`).
    len: usize,
}

impl ReportedBlobId {
    /// The reported token as raw bytes (the `base64url` string, undecoded).
    #[inline]
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        // `len` is `<= REPORTED_BLOB_ID_MAX_LEN` by construction.
        &self.bytes[..self.len]
    }

    /// The reported token as a string slice, for the verify stage (#108).
    ///
    /// Always `Some` for a value produced by [`parse_walrus_put_response`]
    /// (only token bytes from a JSON string are stored); the `Option` keeps the
    /// accessor total without an internal panic.
    #[inline]
    #[must_use]
    pub fn as_str(&self) -> Option<&str> {
        core::str::from_utf8(self.as_bytes()).ok()
    }
}

/// Outcome of looking up a JSON string field by key.
enum JsonStringField<'a> {
    /// No `"key": "<string>"` pair was found.
    Absent,
    /// The key and an opening quote were found, but the string never closed.
    Unterminated,
    /// The value string was found (raw bytes between the quotes, undecoded).
    Value(&'a [u8]),
}

/// Parses a Walrus testnet PUT response body and returns the **reported** blob
/// id — without trusting it.
///
/// The publisher is never treated as a blob-id oracle: this returns the token
/// exactly as reported (undecoded). Local derivation and the byte-for-byte
/// match are the verify stage (`verify_reported_blob_id`). Both
/// publisher success shapes are handled (`newlyCreated` and `alreadyCertified`),
/// each carrying a `blobId` string.
///
/// # Errors
/// - [`WalrusClientError::OversizedBody`] — `body` exceeds the 16 KiB response
///   cap (the same content-free oversized tag the planner already mints).
/// - [`WalrusClientError::Protocol`] — the body is not the expected publisher
///   JSON shape (not a JSON object, or no `blobId` and no `error` object).
/// - [`WalrusClientError::BlobIdMismatch`] — never produced here; it is the
///   verify-stage tag, listed only so callers see the boundary.
///
/// A proxy / gateway HTML error page or a publisher JSON `error` object both
/// map to [`WalrusClientError::Protocol`] (no shape we can extract a blob id
/// from); an empty / unterminated / over-long `blobId` value also maps to
/// [`WalrusClientError::Protocol`].
pub fn parse_walrus_put_response(body: &[u8]) -> Result<ReportedBlobId, WalrusClientError> {
    if body.len() > WALRUS_PUT_RESPONSE_MAX_BYTES {
        return Err(WalrusClientError::OversizedBody);
    }
    let trimmed = body.trim_ascii();
    match trimmed.first() {
        // Empty body, or a reverse-proxy / gateway HTML error page (`<...>`),
        // or any non-object body: not a publisher blob result.
        None | Some(b'<') => return Err(WalrusClientError::Protocol),
        // Publisher responses are a JSON object.
        Some(b'{') => {}
        Some(_) => return Err(WalrusClientError::Protocol),
    }
    match find_json_string_field(trimmed, b"blobId") {
        JsonStringField::Value(token) => build_reported_blob_id(token),
        // Present-but-unterminated, missing, or a JSON `error` object: in every
        // case there is no trustworthy reported id, so the shape is rejected.
        JsonStringField::Unterminated | JsonStringField::Absent => Err(WalrusClientError::Protocol),
    }
}

/// Builds a [`ReportedBlobId`] from raw token bytes, bounding the length.
///
/// An empty or over-long token has no valid blob-id token, so the response
/// shape is rejected as [`WalrusClientError::Protocol`].
fn build_reported_blob_id(token: &[u8]) -> Result<ReportedBlobId, WalrusClientError> {
    if token.is_empty() || token.len() > REPORTED_BLOB_ID_MAX_LEN {
        return Err(WalrusClientError::Protocol);
    }
    let mut bytes = [0u8; REPORTED_BLOB_ID_MAX_LEN];
    bytes[..token.len()].copy_from_slice(token);
    Ok(ReportedBlobId {
        bytes,
        len: token.len(),
    })
}

/// Finds the string value of a JSON key (`"key": "value"`) in `body`.
///
/// Scans for the quoted key token followed by `:` and a quoted string, and
/// returns the raw bytes between the value quotes. A minimal, allocation-free
/// scanner for the fixed Walrus response shapes — **not** a general JSON
/// parser, and it never decodes or interprets the value.
fn find_json_string_field<'a>(body: &'a [u8], key: &[u8]) -> JsonStringField<'a> {
    let n = body.len();
    let mut i = 0;
    while i < n {
        if body[i] == b'"' && key_matches_at(body, i + 1, key) {
            // Index just past the closing quote of the key token.
            let mut j = skip_ascii_ws(body, i + 1 + key.len() + 1);
            if j < n && body[j] == b':' {
                j = skip_ascii_ws(body, j + 1);
                if j < n && body[j] == b'"' {
                    return scan_json_string(body, j + 1);
                }
            }
        }
        i += 1;
    }
    JsonStringField::Absent
}

/// True when `key` followed by a closing quote sits at `start` in `body`.
fn key_matches_at(body: &[u8], start: usize, key: &[u8]) -> bool {
    let end = start + key.len();
    end < body.len() && &body[start..end] == key && body[end] == b'"'
}

/// Returns the first index `>= from` whose byte is not ASCII whitespace.
fn skip_ascii_ws(body: &[u8], from: usize) -> usize {
    let mut j = from;
    while j < body.len() && body[j].is_ascii_whitespace() {
        j += 1;
    }
    j
}

/// Scans a JSON string body starting at `from` (just past the opening quote).
fn scan_json_string(body: &[u8], from: usize) -> JsonStringField<'_> {
    let n = body.len();
    let mut k = from;
    while k < n {
        match body[k] {
            b'"' => return JsonStringField::Value(&body[from..k]),
            // Skip an escaped character so an escaped quote cannot close it.
            b'\\' => k += 2,
            _ => k += 1,
        }
    }
    JsonStringField::Unterminated
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    #![allow(clippy::expect_used)]
    #![allow(clippy::panic)]

    use super::*;

    /// A stamped trace evidence for the happy-path tests.
    fn stamped_trace() -> StageBTraceEvidence {
        StageBTraceEvidence::from_trace(StageBTraceLink::new(0xA70F_0103, 103, 0))
            .expect("atom_id 103 is a stamped (non-zero) trace")
    }

    fn epochs() -> EpochCount {
        EpochCount::new(5).expect("5 is a positive epoch count")
    }

    /// `b2_2_private_denied_before_request` — every non-synthetic class (real
    /// user memory, prompt/provider text, tool output, secret-like, private
    /// provenance) is denied with [`WalrusClientError::PayloadClassDenied`]. The
    /// #93 gate fires *before* the Stage A `PublishPayload` / `PublisherPutRequest`
    /// are ever built, so a private/secret-like payload never reaches the raw
    /// request boundary (`G-B-SEAL-STUB`).
    #[test]
    fn b2_2_private_denied_before_request() {
        let body = b"would-be-private-payload";
        for class in [
            PublishPayloadClass::RealUserMemory,
            PublishPayloadClass::PromptOrProviderText,
            PublishPayloadClass::ToolOutput,
            PublishPayloadClass::SecretLike,
            PublishPayloadClass::PrivateProvenance,
        ] {
            let result = WalrusPutPlan::plan(
                WalrusTestnetEndpoint::testnet(),
                epochs(),
                body,
                class,
                stamped_trace(),
            );
            // `WalrusPutPlan` holds a `PublisherPutRequest` (no `PartialEq`), so
            // match on the error rather than `assert_eq!` the whole `Result`.
            assert!(
                matches!(result, Err(WalrusClientError::PayloadClassDenied)),
                "class {} must be denied before any request is built",
                class.class_label(),
            );
        }
    }

    /// `b2_2_trace_required` — a missing/unstamped trace (`atom_id_u16 == 0`) is
    /// not representable as a planner input: [`StageBTraceEvidence::from_trace`]
    /// rejects it fail-closed, so no [`WalrusPutPlan`] can be built without a real
    /// trace (`G-B-TRACE`). A stamped trace builds a plan and is preserved
    /// verbatim on the `trace` field.
    #[test]
    fn b2_2_trace_required() {
        // Unstamped trace cannot even produce the evidence the planner requires.
        assert!(
            StageBTraceEvidence::from_trace(StageBTraceLink::new(7, 0, 0)).is_none(),
            "atom_id 0 is the missing-trace sentinel and must be rejected",
        );

        // A stamped trace is accepted and stored verbatim.
        let link = StageBTraceLink::new(0xDEAD_BEEF, 103, 2);
        let evidence = StageBTraceEvidence::from_trace(link).expect("atom_id 103 is stamped");
        let plan = WalrusPutPlan::plan(
            WalrusTestnetEndpoint::testnet(),
            epochs(),
            b"synthetic-public-fixture",
            PublishPayloadClass::SyntheticPublicFixture,
            evidence,
        )
        .expect("synthetic class + stamped trace builds a plan");
        assert_eq!(plan.trace(), link);
        assert_eq!(plan.trace, link);
    }

    /// `b2_2_body_borrowed` — the plan holds a zero-copy borrow of the caller's
    /// bytes: `plan.body()` is the *same* slice (pointer + length) that was passed
    /// in, so no payload allocation is made by the planner.
    #[test]
    fn b2_2_body_borrowed() {
        let body: &[u8] = b"synthetic-public-fixture-bytes";
        let plan = WalrusPutPlan::plan(
            WalrusTestnetEndpoint::testnet(),
            epochs(),
            body,
            PublishPayloadClass::SyntheticPublicFixture,
            stamped_trace(),
        )
        .expect("synthetic class builds a plan");

        assert_eq!(plan.body().as_ptr(), body.as_ptr(), "body must be borrowed");
        assert_eq!(plan.body().len(), body.len());
        assert_eq!(plan.body(), body);
        // The request's own body view agrees (single borrowed slice throughout).
        assert_eq!(plan.request.body().as_ptr(), body.as_ptr());
    }

    /// `b2_2_synthetic_accepted` — the happy path: the one admissible class binds
    /// the testnet endpoint, the positive epoch count, and the stamped trace into
    /// a plan whose request reflects all three.
    #[test]
    fn b2_2_synthetic_accepted() {
        let body = b"synthetic-public-fixture";
        let plan = WalrusPutPlan::plan(
            WalrusTestnetEndpoint::testnet(),
            epochs(),
            body,
            PublishPayloadClass::SyntheticPublicFixture,
            stamped_trace(),
        )
        .expect("synthetic class builds a plan");

        assert_eq!(
            plan.request.payload().class(),
            PublishPayloadClass::SyntheticPublicFixture,
        );
        assert_eq!(plan.request.epochs().get(), 5);
        // The request's endpoint is the bound testnet endpoint (independent
        // derivation: request built from `endpoint.endpoint` vs a fresh
        // `WalrusTestnetEndpoint::testnet()`).
        assert_eq!(
            plan.request.endpoint().base_url(),
            WalrusTestnetEndpoint::testnet().base_url(),
        );
        assert_eq!(
            plan.request.endpoint().put_path(),
            WalrusTestnetEndpoint::testnet().put_path(),
        );
        assert_eq!(plan.trace().atom_id_u16, 103);
    }

    /// `b2_12_planner_consumes_decision` — the planner
    /// gate is driven by [`stage_b_publish_decision`], not the bare predicate.
    /// Only [`StageBPublishDecision::Admit`] (synthetic) builds a plan; both
    /// [`DenyClass`](StageBPublishDecision::DenyClass) (secret-like / private) and
    /// [`RequireOwnerSignature`](StageBPublishDecision::RequireOwnerSignature)
    /// (user-owned real memory) fail closed to
    /// [`WalrusClientError::PayloadClassDenied`] **before** the Stage A
    /// `PublishPayload` / `PublisherPutRequest` are built, so a denied payload
    /// makes zero transport calls. This binds the planner's branch to each
    /// decision arm (the "denied payload makes zero transport calls" +
    /// "user-owned public requires owner signature" plan tests at the seam).
    #[test]
    fn b2_12_planner_consumes_decision() {
        // Admit → a plan is built (the only allow path).
        assert_eq!(
            stage_b_publish_decision(PublishPayloadClass::SyntheticPublicFixture),
            StageBPublishDecision::Admit,
        );
        assert!(
            WalrusPutPlan::plan(
                WalrusTestnetEndpoint::testnet(),
                epochs(),
                b"synthetic-public-fixture",
                PublishPayloadClass::SyntheticPublicFixture,
                stamped_trace(),
            )
            .is_ok(),
            "Admit must build a plan",
        );

        // RequireOwnerSignature (user-owned public) and DenyClass (secret-like,
        // private) both fail closed to PayloadClassDenied — no request is built.
        let denied = [
            (
                PublishPayloadClass::RealUserMemory,
                StageBPublishDecision::RequireOwnerSignature,
            ),
            (
                PublishPayloadClass::SecretLike,
                StageBPublishDecision::DenyClass,
            ),
            (
                PublishPayloadClass::PrivateProvenance,
                StageBPublishDecision::DenyClass,
            ),
        ];
        for (class, expected_decision) in denied {
            assert_eq!(
                stage_b_publish_decision(class),
                expected_decision,
                "decision drift for {}",
                class.class_label(),
            );
            let result = WalrusPutPlan::plan(
                WalrusTestnetEndpoint::testnet(),
                epochs(),
                b"would-be-payload",
                class,
                stamped_trace(),
            );
            assert!(
                matches!(result, Err(WalrusClientError::PayloadClassDenied)),
                "class {} ({:?}) must be denied before any request is built",
                class.class_label(),
                expected_decision,
            );
        }
    }

    /// `b2_2_error_labels_namespaced` — every [`WalrusClientError`] variant has a
    /// stable, distinct `walrus.*` label and carries no data, so a logged error
    /// is content-free.
    #[test]
    fn b2_2_error_labels_namespaced() {
        let all = [
            WalrusClientError::EndpointDenied,
            WalrusClientError::PayloadClassDenied,
            WalrusClientError::Transport,
            WalrusClientError::Protocol,
            WalrusClientError::BlobIdMismatch,
            WalrusClientError::OversizedBody,
            WalrusClientError::BoundaryUnknown,
        ];
        for err in all {
            let label = err.class_label();
            assert!(
                label.starts_with("walrus."),
                "label {label:?} must be namespaced walrus.*",
            );
        }
        // Labels are pairwise distinct.
        for (i, a) in all.iter().enumerate() {
            for b in &all[i + 1..] {
                assert_ne!(a.class_label(), b.class_label());
            }
        }
    }

    // --- PUT response parser ---------------------------

    /// A representative Walrus blob-id token (URL-safe `base64`, no padding).
    /// The parser does not decode it; it carries no `blobId` substring so the
    /// scanner cannot confuse the value for the key.
    const SAMPLE_TOKEN: &str = "Tok3n_ABCdef-123_xyz";

    /// `b2_3_newly_created_success` — a `newlyCreated` response (the token nested
    /// in `blobObject`) yields the reported token verbatim, undecoded.
    #[test]
    fn b2_3_newly_created_success() {
        let body =
            br#"{"newlyCreated":{"blobObject":{"id":"0xabc","blobId":"Tok3n_ABCdef-123_xyz","size":64}}}"#;
        let reported =
            parse_walrus_put_response(body).expect("newlyCreated carries a blobId string");
        assert_eq!(reported.as_str(), Some(SAMPLE_TOKEN));
        assert_eq!(reported.as_bytes(), SAMPLE_TOKEN.as_bytes());
    }

    /// `b2_3_already_certified_success` — the other success shape
    /// (`alreadyCertified`, `blobId` at the top of the inner object) parses too.
    #[test]
    fn b2_3_already_certified_success() {
        let body = br#"{"alreadyCertified":{"blobId":"Tok3n_ABCdef-123_xyz","endEpoch":105}}"#;
        let reported =
            parse_walrus_put_response(body).expect("alreadyCertified carries a blobId string");
        assert_eq!(reported.as_str(), Some(SAMPLE_TOKEN));
    }

    /// `b2_3_reported_returned_untrusted` — the token is returned exactly as
    /// reported (no decode, no length check): a 12-char token round-trips even
    /// though a real blob id is 43 chars. Verification is the #108 stage.
    #[test]
    fn b2_3_reported_returned_untrusted() {
        let body = br#"{"alreadyCertified":{"blobId":"short-token1"}}"#;
        let reported = parse_walrus_put_response(body).expect("any non-empty token is reported");
        assert_eq!(reported.as_str(), Some("short-token1"));
        assert_eq!(reported.as_bytes().len(), 12);
    }

    /// `b2_3_malformed_json` — an unterminated `blobId` string (no closing quote)
    /// is not the expected shape and maps to [`WalrusClientError::Protocol`].
    #[test]
    fn b2_3_malformed_json() {
        let body = br#"{"newlyCreated":{"blobId":"abc123"#;
        assert_eq!(
            parse_walrus_put_response(body),
            Err(WalrusClientError::Protocol),
        );
    }

    /// `b2_3_oversized_response` — a body over the 16 KiB cap is rejected before
    /// parsing with [`WalrusClientError::OversizedBody`].
    #[test]
    fn b2_3_oversized_response() {
        let body = vec![b'{'; WALRUS_PUT_RESPONSE_MAX_BYTES + 1];
        assert_eq!(
            parse_walrus_put_response(&body),
            Err(WalrusClientError::OversizedBody),
        );
        // Exactly at the cap is not oversized (it then fails on shape instead).
        let at_cap = vec![b'{'; WALRUS_PUT_RESPONSE_MAX_BYTES];
        assert_eq!(
            parse_walrus_put_response(&at_cap),
            Err(WalrusClientError::Protocol),
        );
    }

    /// `b2_3_proxy_error` — a reverse-proxy / gateway HTML error page (`<...>`)
    /// is not a publisher JSON response and maps to
    /// [`WalrusClientError::Protocol`].
    #[test]
    fn b2_3_proxy_error() {
        let body = br#"<html><body><h1>502 Bad Gateway</h1></body></html>"#;
        assert_eq!(
            parse_walrus_put_response(body),
            Err(WalrusClientError::Protocol),
        );
    }

    /// `b2_3_missing_blob_id` — a JSON object with no `blobId` (and no `error`)
    /// is the wrong shape: [`WalrusClientError::Protocol`].
    #[test]
    fn b2_3_missing_blob_id() {
        let body = br#"{"alreadyCertified":{"endEpoch":1}}"#;
        assert_eq!(
            parse_walrus_put_response(body),
            Err(WalrusClientError::Protocol),
        );
    }

    /// `b2_3_error_object` — a publisher JSON `error` object carries no blob
    /// result, so it also maps to [`WalrusClientError::Protocol`].
    #[test]
    fn b2_3_error_object() {
        let body = br#"{"error":{"code":500,"message":"upstream"}}"#;
        assert_eq!(
            parse_walrus_put_response(body),
            Err(WalrusClientError::Protocol),
        );
    }

    /// `b2_3_empty_blob_id` — a present-but-empty `blobId` value has no token to
    /// report: [`WalrusClientError::Protocol`].
    #[test]
    fn b2_3_empty_blob_id() {
        let body = br#"{"alreadyCertified":{"blobId":"","endEpoch":1}}"#;
        assert_eq!(
            parse_walrus_put_response(body),
            Err(WalrusClientError::Protocol),
        );
    }

    /// `b2_3_oversized_token` — a `blobId` value longer than any blob-id token
    /// can be (> `REPORTED_BLOB_ID_MAX_LEN`) is rejected as the wrong shape.
    #[test]
    fn b2_3_oversized_token() {
        // 65 `A`s inside the value, one over REPORTED_BLOB_ID_MAX_LEN (64).
        let body = br#"{"alreadyCertified":{"blobId":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}}"#;
        assert_eq!(
            parse_walrus_put_response(body),
            Err(WalrusClientError::Protocol),
        );
    }

    /// `b2_3_leading_whitespace_ok` — a body with leading/trailing whitespace
    /// still parses (the parser trims ASCII whitespace before inspecting shape).
    #[test]
    fn b2_3_leading_whitespace_ok() {
        let body = b"  \n\t{\"alreadyCertified\":{\"blobId\":\"Tok3n_ABCdef-123_xyz\"}}\n  ";
        let reported = parse_walrus_put_response(body).expect("trimmed body parses");
        assert_eq!(reported.as_str(), Some(SAMPLE_TOKEN));
    }
}
