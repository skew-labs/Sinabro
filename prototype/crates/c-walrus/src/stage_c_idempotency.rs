//! Stage C Walrus PUT retry/idempotency GA polish (C-WP-03A · atom #191 · C.0.20).
//!
//! Canonical OUT (Walrus half): a Stage C evidence wrapper proving that a Walrus
//! PUT failure observed at an **unknown** external-mutation boundary never
//! auto-retries the write.
//!
//! # Madness invariants (atom #191)
//!
//! * **Unknown boundary never auto-retries writes.** The retry disposition is
//!   computed by reusing the atom #8 [`classify_transport_failure`] decision
//!   point verbatim — an [`BoundaryState::UnknownAfterBoundary`] yields
//!   [`PublisherRetryDisposition::ManualReconcile`], so
//!   [`StageCWalrusRetryEvidence::allows_automatic_retry`] is `false`.
//! * **No re-mint.** The boundary, the disposition, and the classifier are all
//!   the canonical c-walrus publisher types; this module adds only a greppable
//!   Stage C evidence record with no new retry logic.
//! * **Trace-free by design.** `c-walrus` deliberately does not depend on
//!   `a-core`; the §4.0 `StageCTraceLink` stamp is applied at the `d-move` /
//!   integration composition layer (mirrors the atom #182
//!   `WalrusMeasureSample`-lives-in-`b-memory` boundary).

use crate::publisher::{
    BoundaryState, PublisherRetryDisposition, TransportFailureKind, classify_transport_failure,
};

/// Fixed serialized byte width of a [`StageCWalrusRetryEvidence`]:
/// `1 (boundary) + 1 (disposition) + 2 (attempt) + 2 (max attempts)`.
pub const STAGE_C_WALRUS_RETRY_EVIDENCE_BYTES: usize = 1 + 1 + 2 + 2;

/// Stage C evidence that a Walrus PUT failure was classified for retry safety.
///
/// Carries no host, body, or blob id — only the observed boundary, the reused
/// disposition, and the attempt indices.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub struct StageCWalrusRetryEvidence {
    /// The observed external-mutation boundary state.
    pub boundary: BoundaryState,
    /// The disposition returned by [`classify_transport_failure`] (reused verbatim).
    pub disposition: PublisherRetryDisposition,
    /// The attempt index that failed.
    pub attempt_u16: u16,
    /// The configured maximum attempts.
    pub max_attempts_u16: u16,
}

impl StageCWalrusRetryEvidence {
    /// Classify a Walrus PUT transport failure at `boundary` and record the
    /// Stage C evidence, reusing the canonical [`classify_transport_failure`]
    /// decision point (no new retry logic).
    #[inline]
    pub const fn classify(
        kind: TransportFailureKind,
        boundary: BoundaryState,
        attempt_u16: u16,
        max_attempts_u16: u16,
    ) -> Self {
        let decision = classify_transport_failure(kind, boundary, attempt_u16, max_attempts_u16);
        Self {
            boundary,
            disposition: decision.disposition,
            attempt_u16,
            max_attempts_u16,
        }
    }

    /// `true` iff an automatic PUT retry is permitted — only when the
    /// disposition is [`PublisherRetryDisposition::AutoRetry`]. An unknown
    /// boundary (`ManualReconcile`) and a terminal failure (`Never`) both
    /// forbid it: the "no blind second PUT" guard.
    #[inline]
    pub const fn allows_automatic_retry(&self) -> bool {
        matches!(self.disposition, PublisherRetryDisposition::AutoRetry)
    }

    /// Serialize to the fixed [`STAGE_C_WALRUS_RETRY_EVIDENCE_BYTES`] form in
    /// field-declaration order (little-endian integers).
    pub fn to_bytes(&self) -> [u8; STAGE_C_WALRUS_RETRY_EVIDENCE_BYTES] {
        let mut out = [0u8; STAGE_C_WALRUS_RETRY_EVIDENCE_BYTES];
        out[0] = self.boundary as u8;
        out[1] = self.disposition as u8;
        out[2..4].copy_from_slice(&self.attempt_u16.to_le_bytes());
        out[4..6].copy_from_slice(&self.max_attempts_u16.to_le_bytes());
        out
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]
    use super::*;

    #[test]
    fn walrus_unknown_no_retry() {
        // A failure at an unknown boundary must NEVER auto-retry the write.
        let ev = StageCWalrusRetryEvidence::classify(
            TransportFailureKind::ResponseTimeout,
            BoundaryState::UnknownAfterBoundary,
            0,
            3,
        );
        assert_eq!(ev.disposition, PublisherRetryDisposition::ManualReconcile);
        assert!(!ev.allows_automatic_retry(), "no blind second PUT");
    }

    #[test]
    fn no_external_mutation_within_attempts_auto_retries() {
        // Reuses the canonical classifier: bytes never crossed → auto-retry safe.
        let ev = StageCWalrusRetryEvidence::classify(
            TransportFailureKind::Connect,
            BoundaryState::NoExternalMutation,
            0,
            3,
        );
        assert_eq!(ev.disposition, PublisherRetryDisposition::AutoRetry);
        assert!(ev.allows_automatic_retry());
    }

    #[test]
    fn crossed_boundary_never_retries() {
        let ev = StageCWalrusRetryEvidence::classify(
            TransportFailureKind::ResponseTimeout,
            BoundaryState::RequestBytesMayHaveCrossed,
            0,
            3,
        );
        assert_eq!(ev.disposition, PublisherRetryDisposition::Never);
        assert!(!ev.allows_automatic_retry());
    }

    #[test]
    fn evidence_serialization_is_fixed_width() {
        let ev = StageCWalrusRetryEvidence::classify(
            TransportFailureKind::ResponseTimeout,
            BoundaryState::UnknownAfterBoundary,
            1,
            3,
        );
        let bytes = ev.to_bytes();
        assert_eq!(bytes.len(), STAGE_C_WALRUS_RETRY_EVIDENCE_BYTES);
        assert_eq!(bytes.len(), 6);
        assert_eq!(bytes[0], BoundaryState::UnknownAfterBoundary as u8);
        assert_eq!(bytes[1], PublisherRetryDisposition::ManualReconcile as u8);
        assert_eq!(&bytes[2..4], &1u16.to_le_bytes());
        assert_eq!(&bytes[4..6], &3u16.to_le_bytes());
    }
}
