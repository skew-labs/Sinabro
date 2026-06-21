//! Stage B Walrus PUT idempotency ledger (atom #111 · B.2.10).
//!
//! A Walrus testnet PUT crosses an **external-mutation boundary** (atom #110 ·
//! `stage_b_retry.rs`): once the bytes may have been durably stored, a blind
//! automatic second PUT is forbidden because it could mint a duplicate stored
//! blob (and a duplicate on-chain anchor / audit append downstream). The retry
//! classifier answers "may I retry *this* attempt?" from a single observed
//! boundary state; this ledger answers the **idempotency** question that spans
//! attempts:
//!
//! > **the same bytes, seen again under the same trace after an unknown
//! > boundary, return [`WalrusRetry::ManualReconcile`] — never a blind second
//! > PUT.**
//!
//! It does so as a pure, offline map keyed by **content digest + trace id**
//! (`MNEMOS_STAGE_B_ATOM_PLAN.md` §4.2 / atom #111 canonical OUT
//! [`WalrusPutLedger`]):
//!
//! * The **trace id** is the atom #81 [`StageBTraceLink::trace_id_u64`] carried
//!   by a fail-closed [`StageBTraceEvidence`] (#94) — an unstamped sentinel
//!   (`atom_id_u16 == 0`) is not representable as evidence, so a ledger key can
//!   never be detached from a measured action.
//! * The **content digest** is the atom #86 [`ContentHash32`] of the payload
//!   body — "the same bytes" is literally byte-equality of this hash.
//!
//! ## Decision grid ([`WalrusPutLedger::decide`])
//!
//! | prior record for this trace id        | [`WalrusPutDecision`]                |
//! |---------------------------------------|-------------------------------------|
//! | none                                  | [`FirstAttempt`]                    |
//! | same content digest                   | [`Retry`]`(boundary.retry())`       |
//! | **different** content digest          | [`TraceDigestConflict`]             |
//!
//! The middle row is the madness invariant: a prior attempt that ended in
//! [`WalrusBoundaryState::BytesMayHaveCrossed`] or
//! [`WalrusBoundaryState::UnknownAfterBoundary`] reuses the atom #110
//! [`WalrusBoundaryState::retry`] enforcement point and yields
//! [`Retry`]`(`[`ManualReconcile`]`)` — no new retry logic is invented here.
//!
//! ## Crash-reload fixture
//!
//! [`WalrusPutLedger::to_fixture_bytes`] / [`WalrusPutLedger::from_fixture_bytes`]
//! are a deterministic, dependency-free fixed-width codec (no `serde`) so a
//! ledger rebuilt from a post-crash fixture decides identically to the original.
//! The codec carries only content-free tags — a 32-byte content hash, the
//! `(trace_id, atom_id, attempt)` ids, and a 1-byte boundary tag — so a fixture
//! never persists a payload body.
//!
//! ## Boundary
//!
//! Pure / offline / `#![deny(unsafe_code)]`-clean. No transport, no network, no
//! secret, no payload body. The §4.2 [`WalrusClientError`](crate::WalrusClientError)
//! surface is **not** touched (it is frozen at 7 variants); the ledger's own
//! reject channel is the data-free [`WalrusPutLedgerError`].
//!
//! [`FirstAttempt`]: WalrusPutDecision::FirstAttempt
//! [`Retry`]: WalrusPutDecision::Retry
//! [`TraceDigestConflict`]: WalrusPutDecision::TraceDigestConflict
//! [`ManualReconcile`]: WalrusRetry::ManualReconcile

use std::collections::BTreeMap;

use crate::chunk_digest::{CONTENT_HASH_BYTES, ContentHash32};
use crate::stage_b_retry::{WalrusBoundaryState, WalrusRetry};
use crate::trace_link::StageBTraceEvidence;

/// Per-entry fixture width: `trace_id_u64` (8) + content hash (32) +
/// `atom_id_u16` (2) + `attempt_u8` (1) + boundary tag (1).
const ENTRY_FIXTURE_BYTES: usize = 8 + CONTENT_HASH_BYTES + 2 + 1 + 1;

/// Width of the `u32` big-endian entry-count prefix that opens a fixture.
const FIXTURE_COUNT_PREFIX_BYTES: usize = 4;

/// Reconstruct a [`WalrusBoundaryState`] from its stable `#[repr(u8)]` tag.
///
/// The atom #110 type exposes [`WalrusBoundaryState::tag`] but no inverse
/// (and that module is frozen), so the inverse lives here as a local helper.
/// The three arms mirror the §4.2 discriminants `1/2/3`; the
/// `boundary_tag_roundtrip` test pins `from_tag(s.tag()) == Some(s)` for every
/// variant so a discriminant drift is caught, and an unknown tag fails closed to
/// `None`.
const fn boundary_from_tag(tag: u8) -> Option<WalrusBoundaryState> {
    match tag {
        1 => Some(WalrusBoundaryState::NoExternalMutation),
        2 => Some(WalrusBoundaryState::BytesMayHaveCrossed),
        3 => Some(WalrusBoundaryState::UnknownAfterBoundary),
        _ => None,
    }
}

/// One recorded PUT attempt outcome. Content-free: the only payload-derived
/// field is the 32-byte content hash, never the body.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct LedgerEntry {
    /// The atom #86 [`ContentHash32`] bytes of the payload body that was PUT.
    content_hash: [u8; CONTENT_HASH_BYTES],
    /// The atom #81 trace id (the per-attempt-spanning logical key).
    trace_id_u64: u64,
    /// The atom this attempt belonged to (always non-zero — the evidence input
    /// to [`WalrusPutLedger::record_attempt`] rejects the `0` sentinel).
    atom_id_u16: u16,
    /// The retry attempt counter observed at record time.
    attempt_u8: u8,
    /// The observed external-mutation boundary state of the attempt.
    boundary: WalrusBoundaryState,
}

/// The decision a [`WalrusPutLedger`] returns for a candidate PUT.
///
/// Data-free `Copy` tag wrapping the reused atom #110 [`WalrusRetry`]; it carries
/// no host, body, or blob id, so a decision can never leak content through a
/// `Debug` rendering.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum WalrusPutDecision {
    /// No prior record for this trace id — the first PUT may proceed.
    FirstAttempt,
    /// A prior attempt for this trace id stored the **same** content digest. The
    /// inner [`WalrusRetry`] is the atom #110 boundary decision of that prior
    /// attempt: `BeforeBoundaryOnly` (auto-retry safe) or `ManualReconcile`
    /// (blind second PUT forbidden).
    Retry(WalrusRetry),
    /// A prior attempt for this trace id stored a **different** content digest —
    /// a trace id must not be reused for different bytes. Fail-closed reject.
    TraceDigestConflict,
}

impl WalrusPutDecision {
    /// `true` iff an automatic PUT is permitted with no human reconcile: a
    /// [`FirstAttempt`](Self::FirstAttempt), or a
    /// [`Retry`](Self::Retry) whose boundary
    /// [`allows_automatic_retry`](WalrusRetry::allows_automatic_retry).
    ///
    /// [`TraceDigestConflict`](Self::TraceDigestConflict) and a
    /// [`Retry`](Self::Retry)`(`[`ManualReconcile`](WalrusRetry::ManualReconcile)`)`
    /// both forbid it — this is the "never a blind second PUT" guard.
    #[inline]
    pub const fn allows_automatic_put(self) -> bool {
        match self {
            Self::FirstAttempt => true,
            Self::Retry(retry) => retry.allows_automatic_retry(),
            Self::TraceDigestConflict => false,
        }
    }
}

/// A malformed-fixture error from [`WalrusPutLedger::from_fixture_bytes`].
///
/// `Copy` + no owned bytes (mirrors [`WalrusClientError`](crate::WalrusClientError)):
/// the error channel cannot leak a raw body or a canary substring through
/// `Debug`. `#[non_exhaustive]` so a future variant is denied-by-default at every
/// `match`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum WalrusPutLedgerError {
    /// The fixture byte length did not match the `u32` entry-count prefix times
    /// the fixed per-entry width (truncated, padded, or a wrong count prefix).
    Truncated,
    /// A per-entry boundary tag byte was not a known `#[repr(u8)]` discriminant
    /// (`1/2/3`); [`boundary_from_tag`] failed closed.
    UnknownBoundaryTag,
}

/// A PUT idempotency ledger keyed by **content digest + trace id** (atom #111
/// canonical OUT).
///
/// One entry per atom #81 trace id (the logical PUT spanning retry attempts).
/// A [`BTreeMap`] is used over a hash map so iteration — and therefore
/// [`to_fixture_bytes`](Self::to_fixture_bytes) — is deterministic with no extra
/// dependency.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct WalrusPutLedger {
    /// trace id → the latest recorded attempt for that logical PUT.
    entries: BTreeMap<u64, LedgerEntry>,
}

impl WalrusPutLedger {
    /// An empty ledger.
    #[inline]
    #[must_use]
    pub const fn new() -> Self {
        Self {
            entries: BTreeMap::new(),
        }
    }

    /// The number of recorded logical PUTs (distinct trace ids).
    #[inline]
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// `true` iff no PUT has been recorded.
    #[inline]
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Record the observed outcome of a PUT attempt under `trace`'s trace id,
    /// binding it to the content `digest` and the observed `boundary` state.
    ///
    /// The latest record for a trace id replaces any prior one (a later attempt
    /// supersedes its predecessor's boundary state). Callers gate the actual PUT
    /// on [`decide`](Self::decide) first — `record_attempt` only journals the
    /// outcome. The `trace` is a fail-closed [`StageBTraceEvidence`], so the
    /// `atom_id_u16 == 0` sentinel is unrepresentable here by construction.
    pub fn record_attempt(
        &mut self,
        digest: &ContentHash32,
        trace: &StageBTraceEvidence,
        boundary: WalrusBoundaryState,
    ) {
        let entry = LedgerEntry {
            content_hash: *digest.as_bytes(),
            trace_id_u64: trace.trace_id_u64(),
            atom_id_u16: trace.atom_id_u16(),
            attempt_u8: trace.attempt_u8(),
            boundary,
        };
        self.entries.insert(trace.trace_id_u64(), entry);
    }

    /// Decide whether a candidate PUT of `digest` under `trace` may proceed.
    ///
    /// See the module-level decision grid. The madness invariant lives in the
    /// `Retry` arm: it reuses the atom #110 [`WalrusBoundaryState::retry`]
    /// enforcement point verbatim, so a prior unknown/crossed boundary yields
    /// [`WalrusRetry::ManualReconcile`] and never a blind second PUT.
    #[must_use]
    pub fn decide(&self, digest: &ContentHash32, trace: &StageBTraceEvidence) -> WalrusPutDecision {
        match self.entries.get(&trace.trace_id_u64()) {
            None => WalrusPutDecision::FirstAttempt,
            Some(entry) if entry.content_hash != *digest.as_bytes() => {
                WalrusPutDecision::TraceDigestConflict
            }
            Some(entry) => WalrusPutDecision::Retry(entry.boundary.retry()),
        }
    }

    /// Serialize the ledger to a deterministic, dependency-free fixture.
    ///
    /// Layout: a `u32` big-endian entry count, then each entry (in ascending
    /// trace-id order) as `trace_id_u64` (8, BE) ++ content hash (32) ++
    /// `atom_id_u16` (2, BE) ++ `attempt_u8` (1) ++ boundary tag (1).
    #[must_use]
    pub fn to_fixture_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(
            FIXTURE_COUNT_PREFIX_BYTES + self.entries.len() * ENTRY_FIXTURE_BYTES,
        );
        let count = self.entries.len() as u32;
        out.extend_from_slice(&count.to_be_bytes());
        for entry in self.entries.values() {
            out.extend_from_slice(&entry.trace_id_u64.to_be_bytes());
            out.extend_from_slice(&entry.content_hash);
            out.extend_from_slice(&entry.atom_id_u16.to_be_bytes());
            out.push(entry.attempt_u8);
            out.push(entry.boundary.tag());
        }
        out
    }

    /// Rebuild a ledger from a [`to_fixture_bytes`](Self::to_fixture_bytes)
    /// fixture (a post-crash reload).
    ///
    /// Fail-closed: any length mismatch is [`WalrusPutLedgerError::Truncated`]
    /// and any unknown boundary tag is [`WalrusPutLedgerError::UnknownBoundaryTag`].
    /// A duplicate trace id in the fixture keeps its last occurrence (consistent
    /// with [`record_attempt`](Self::record_attempt)'s replace semantics).
    pub fn from_fixture_bytes(bytes: &[u8]) -> Result<Self, WalrusPutLedgerError> {
        if bytes.len() < FIXTURE_COUNT_PREFIX_BYTES {
            return Err(WalrusPutLedgerError::Truncated);
        }
        let count_prefix: [u8; FIXTURE_COUNT_PREFIX_BYTES] = bytes[..FIXTURE_COUNT_PREFIX_BYTES]
            .try_into()
            .map_err(|_| WalrusPutLedgerError::Truncated)?;
        let count = u32::from_be_bytes(count_prefix) as usize;
        let expected = FIXTURE_COUNT_PREFIX_BYTES + count * ENTRY_FIXTURE_BYTES;
        if bytes.len() != expected {
            return Err(WalrusPutLedgerError::Truncated);
        }

        let mut entries = BTreeMap::new();
        let mut off = FIXTURE_COUNT_PREFIX_BYTES;
        for _ in 0..count {
            let trace_id_bytes: [u8; 8] = bytes[off..off + 8]
                .try_into()
                .map_err(|_| WalrusPutLedgerError::Truncated)?;
            off += 8;
            let content_hash: [u8; CONTENT_HASH_BYTES] = bytes[off..off + CONTENT_HASH_BYTES]
                .try_into()
                .map_err(|_| WalrusPutLedgerError::Truncated)?;
            off += CONTENT_HASH_BYTES;
            let atom_id_bytes: [u8; 2] = bytes[off..off + 2]
                .try_into()
                .map_err(|_| WalrusPutLedgerError::Truncated)?;
            off += 2;
            let attempt_u8 = bytes[off];
            off += 1;
            let boundary =
                boundary_from_tag(bytes[off]).ok_or(WalrusPutLedgerError::UnknownBoundaryTag)?;
            off += 1;

            let trace_id_u64 = u64::from_be_bytes(trace_id_bytes);
            entries.insert(
                trace_id_u64,
                LedgerEntry {
                    content_hash,
                    trace_id_u64,
                    atom_id_u16: u16::from_be_bytes(atom_id_bytes),
                    attempt_u8,
                    boundary,
                },
            );
        }
        Ok(Self { entries })
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use super::*;
    use crate::stage_b_handoff::StageBTraceLink;

    /// A fail-closed trace evidence for tests (atom_id non-zero so it is valid).
    fn evidence(trace_id: u64, atom_id: u16, attempt: u8) -> StageBTraceEvidence {
        StageBTraceEvidence::from_trace(StageBTraceLink::new(trace_id, atom_id, attempt))
            .expect("non-zero atom id is a valid trace")
    }

    fn digest(body: &[u8]) -> ContentHash32 {
        ContentHash32::of(body)
    }

    #[test]
    fn b2_10_first_attempt_for_unseen_trace() {
        let ledger = WalrusPutLedger::new();
        assert_eq!(
            ledger.decide(&digest(b"alpha"), &evidence(0xA1, 111, 0)),
            WalrusPutDecision::FirstAttempt,
        );
        assert!(ledger.is_empty());
    }

    #[test]
    fn b2_10_duplicate_same_digest_after_unknown_boundary_is_manual_reconcile() {
        // The madness: same bytes after an unknown boundary returns
        // ManualReconcile, not a blind second PUT.
        let mut ledger = WalrusPutLedger::new();
        let d = digest(b"same-bytes");
        let trace = evidence(0xBEEF, 111, 0);
        ledger.record_attempt(&d, &trace, WalrusBoundaryState::UnknownAfterBoundary);

        let decision = ledger.decide(&d, &trace);
        assert_eq!(
            decision,
            WalrusPutDecision::Retry(WalrusRetry::ManualReconcile),
        );
        assert!(!decision.allows_automatic_put(), "no blind second PUT");
    }

    #[test]
    fn b2_10_duplicate_same_digest_before_boundary_allows_auto_retry() {
        let mut ledger = WalrusPutLedger::new();
        let d = digest(b"same-bytes");
        let trace = evidence(0xBEEF, 111, 0);
        ledger.record_attempt(&d, &trace, WalrusBoundaryState::NoExternalMutation);

        let decision = ledger.decide(&d, &trace);
        assert_eq!(
            decision,
            WalrusPutDecision::Retry(WalrusRetry::BeforeBoundaryOnly),
        );
        assert!(
            decision.allows_automatic_put(),
            "bytes never crossed → safe"
        );
    }

    #[test]
    fn b2_10_different_bytes_same_trace_reject() {
        let mut ledger = WalrusPutLedger::new();
        let trace = evidence(0xCAFE, 111, 0);
        ledger.record_attempt(
            &digest(b"original-bytes"),
            &trace,
            WalrusBoundaryState::NoExternalMutation,
        );

        // Same trace id, different content digest → reject.
        let decision = ledger.decide(&digest(b"different-bytes"), &trace);
        assert_eq!(decision, WalrusPutDecision::TraceDigestConflict);
        assert!(!decision.allows_automatic_put());
    }

    #[test]
    fn b2_10_same_digest_different_trace_is_first_attempt() {
        // Distinct trace ids are distinct keys even for identical bytes.
        let mut ledger = WalrusPutLedger::new();
        let d = digest(b"same-bytes");
        ledger.record_attempt(
            &d,
            &evidence(0x01, 111, 0),
            WalrusBoundaryState::UnknownAfterBoundary,
        );
        assert_eq!(
            ledger.decide(&d, &evidence(0x02, 111, 0)),
            WalrusPutDecision::FirstAttempt,
        );
    }

    #[test]
    fn b2_10_crash_reload_fixture_decides_identically() {
        let mut ledger = WalrusPutLedger::new();
        let d_unknown = digest(b"unknown-boundary-bytes");
        let t_unknown = evidence(0x11, 111, 2);
        ledger.record_attempt(
            &d_unknown,
            &t_unknown,
            WalrusBoundaryState::UnknownAfterBoundary,
        );
        let d_clean = digest(b"clean-bytes");
        let t_clean = evidence(0x22, 110, 0);
        ledger.record_attempt(&d_clean, &t_clean, WalrusBoundaryState::NoExternalMutation);
        let d_crossed = digest(b"crossed-bytes");
        let t_crossed = evidence(0x33, 109, 1);
        ledger.record_attempt(
            &d_crossed,
            &t_crossed,
            WalrusBoundaryState::BytesMayHaveCrossed,
        );

        let fixture = ledger.to_fixture_bytes();
        let reloaded =
            WalrusPutLedger::from_fixture_bytes(&fixture).expect("valid fixture reloads");

        assert_eq!(reloaded, ledger, "reloaded ledger is byte-identical state");
        assert_eq!(
            reloaded.decide(&d_unknown, &t_unknown),
            WalrusPutDecision::Retry(WalrusRetry::ManualReconcile),
        );
        assert_eq!(
            reloaded.decide(&d_clean, &t_clean),
            WalrusPutDecision::Retry(WalrusRetry::BeforeBoundaryOnly),
        );
        assert_eq!(
            reloaded.decide(&d_crossed, &t_crossed),
            WalrusPutDecision::Retry(WalrusRetry::ManualReconcile),
        );
        // Re-serializing the reload is byte-identical (deterministic codec).
        assert_eq!(reloaded.to_fixture_bytes(), fixture);
    }

    #[test]
    fn b2_10_empty_ledger_fixture_roundtrips() {
        let fixture = WalrusPutLedger::new().to_fixture_bytes();
        assert_eq!(fixture, 0u32.to_be_bytes().to_vec());
        assert_eq!(
            WalrusPutLedger::from_fixture_bytes(&fixture).expect("empty fixture"),
            WalrusPutLedger::new(),
        );
    }

    #[test]
    fn b2_10_truncated_fixture_rejected() {
        assert_eq!(
            WalrusPutLedger::from_fixture_bytes(&[0, 0, 0]),
            Err(WalrusPutLedgerError::Truncated),
        );
        // Count says 1 entry but no entry body follows.
        assert_eq!(
            WalrusPutLedger::from_fixture_bytes(&[0, 0, 0, 1]),
            Err(WalrusPutLedgerError::Truncated),
        );
    }

    #[test]
    fn b2_10_unknown_boundary_tag_rejected() {
        let mut ledger = WalrusPutLedger::new();
        ledger.record_attempt(
            &digest(b"x"),
            &evidence(0x1, 111, 0),
            WalrusBoundaryState::NoExternalMutation,
        );
        let mut fixture = ledger.to_fixture_bytes();
        // The boundary tag is the final byte; 0 and 4 are not valid discriminants.
        let last = fixture.len() - 1;
        fixture[last] = 0;
        assert_eq!(
            WalrusPutLedger::from_fixture_bytes(&fixture),
            Err(WalrusPutLedgerError::UnknownBoundaryTag),
        );
    }

    #[test]
    fn b2_10_boundary_tag_roundtrip() {
        // Pins boundary_from_tag against the §4.2 #[repr(u8)] discriminants so a
        // drift in either is caught.
        for state in [
            WalrusBoundaryState::NoExternalMutation,
            WalrusBoundaryState::BytesMayHaveCrossed,
            WalrusBoundaryState::UnknownAfterBoundary,
        ] {
            assert_eq!(boundary_from_tag(state.tag()), Some(state));
        }
        assert_eq!(boundary_from_tag(0), None);
        assert_eq!(boundary_from_tag(4), None);
    }

    #[test]
    fn b2_10_later_attempt_supersedes_boundary() {
        // A NoExternalMutation attempt #0, then an UnknownAfterBoundary retry #1
        // under the same trace id: the later (stricter) boundary wins.
        let mut ledger = WalrusPutLedger::new();
        let d = digest(b"retry-bytes");
        ledger.record_attempt(
            &d,
            &evidence(0x7, 111, 0),
            WalrusBoundaryState::NoExternalMutation,
        );
        ledger.record_attempt(
            &d,
            &evidence(0x7, 111, 1),
            WalrusBoundaryState::UnknownAfterBoundary,
        );
        assert_eq!(ledger.len(), 1, "same trace id is one logical PUT");
        assert_eq!(
            ledger.decide(&d, &evidence(0x7, 111, 1)),
            WalrusPutDecision::Retry(WalrusRetry::ManualReconcile),
        );
    }
}
