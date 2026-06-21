//! Stage C Sui add_chunk/audit retry/idempotency GA polish
//! (C-WP-03A · atom #191 · C.0.20).
//!
//! Canonical OUT (Sui half): combined retry/idempotency evidence for the Sui
//! `add_chunk` / `audit_log::append` writes — an unknown external-mutation
//! boundary never auto-retries, and a duplicate on-chain event is reconciled
//! (idempotently ignored), not re-applied.
//!
//! # Madness invariants (atom #191)
//!
//! * **Unknown boundary never auto-retries writes.** The Sui write boundary is
//!   the SAME external-mutation boundary as a Walrus PUT, so the retry
//!   disposition reuses the canonical c-walrus
//!   [`classify_transport_failure`](mnemos_c_walrus::classify_transport_failure)
//!   decision point — `UnknownAfterBoundary` ⇒
//!   [`ManualReconcile`](mnemos_c_walrus::PublisherRetryDisposition::ManualReconcile).
//! * **Duplicate evidence reconciles, not repeats.** A
//!   [`StageCSuiEventLedger`] keyed by a content-free [`SuiEventCoord`]
//!   (`tx_digest`, `event_seq`) returns [`SuiEventOutcome::DuplicateIgnored`] for
//!   a re-seen event, mirroring the Stage B replay idempotency principle without
//!   taking a `b-memory` dependency (which would form a cargo cycle).
//! * **No re-mint.** Boundary / disposition / classifier are the canonical
//!   c-walrus publisher types; the trace reuses the §4.0 [`StageCTraceLink`].

use std::collections::BTreeMap;

use mnemos_a_core::trace::StageCTraceLink;
use mnemos_c_walrus::{
    BoundaryState, PublisherRetryDisposition, TransportFailureKind, classify_transport_failure,
};

/// Whether a Sui write at the observed boundary may be auto-retried. Reuses the
/// canonical c-walrus classifier verbatim: an unknown boundary is never
/// auto-retried.
#[inline]
pub fn sui_write_allows_auto_retry(
    kind: TransportFailureKind,
    boundary: BoundaryState,
    attempt_u16: u16,
    max_attempts_u16: u16,
) -> bool {
    let decision = classify_transport_failure(kind, boundary, attempt_u16, max_attempts_u16);
    matches!(decision.disposition, PublisherRetryDisposition::AutoRetry)
}

/// A content-free on-chain event identity: the Sui transaction digest plus the
/// event sequence within that transaction. Carries no payload, hash, or address
/// — only the coordinate that makes an event unique.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct SuiEventCoord {
    /// 32-byte Sui transaction digest the event was emitted in.
    pub tx_digest: [u8; 32],
    /// The event's sequence index within the transaction.
    pub event_seq_u64: u64,
}

impl SuiEventCoord {
    /// Construct an event coordinate.
    #[inline]
    pub const fn new(tx_digest: [u8; 32], event_seq_u64: u64) -> Self {
        Self {
            tx_digest,
            event_seq_u64,
        }
    }
}

/// The outcome of observing an event coordinate against a [`StageCSuiEventLedger`].
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
#[repr(u8)]
pub enum SuiEventOutcome {
    /// The coordinate was not seen before; it is now recorded.
    FirstSeen = 1,
    /// The coordinate was already recorded; the duplicate is ignored.
    DuplicateIgnored = 2,
}

/// An idempotency ledger for Sui `add_chunk` / `audit` events, keyed by a
/// content-free [`SuiEventCoord`]. A re-seen coordinate reconciles to
/// [`SuiEventOutcome::DuplicateIgnored`] rather than re-applying the event.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct StageCSuiEventLedger {
    seen: BTreeMap<([u8; 32], u64), StageCTraceLink>,
}

impl StageCSuiEventLedger {
    /// An empty ledger.
    #[inline]
    #[must_use]
    pub const fn new() -> Self {
        Self {
            seen: BTreeMap::new(),
        }
    }

    /// The number of distinct event coordinates recorded.
    #[inline]
    #[must_use]
    pub fn len(&self) -> usize {
        self.seen.len()
    }

    /// `true` iff no event has been recorded.
    #[inline]
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.seen.is_empty()
    }

    /// Observe `coord`, recording it on first sight and reporting the outcome.
    /// A duplicate is ignored (the ledger does not grow and the original trace
    /// is retained).
    pub fn observe(&mut self, coord: SuiEventCoord, trace: StageCTraceLink) -> SuiEventOutcome {
        let key = (coord.tx_digest, coord.event_seq_u64);
        if self.seen.contains_key(&key) {
            return SuiEventOutcome::DuplicateIgnored;
        }
        self.seen.insert(key, trace);
        SuiEventOutcome::FirstSeen
    }

    /// `true` iff `coord` has already been recorded.
    #[inline]
    #[must_use]
    pub fn contains(&self, coord: &SuiEventCoord) -> bool {
        self.seen
            .contains_key(&(coord.tx_digest, coord.event_seq_u64))
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]
    use super::*;
    use mnemos_a_core::trace::StageBTraceLink;

    fn trace() -> StageCTraceLink {
        StageCTraceLink::new(StageBTraceLink::new(0xA17B_0191, 191, 0), 191, 32)
    }

    #[test]
    fn sui_unknown_no_retry() {
        // A Sui write failure at an unknown boundary never auto-retries.
        assert!(!sui_write_allows_auto_retry(
            TransportFailureKind::ResponseTimeout,
            BoundaryState::UnknownAfterBoundary,
            0,
            3,
        ));
        // Bytes never crossed → auto-retry safe (reuses the canonical classifier).
        assert!(sui_write_allows_auto_retry(
            TransportFailureKind::Connect,
            BoundaryState::NoExternalMutation,
            0,
            3,
        ));
    }

    #[test]
    fn duplicate_event_idempotent() {
        let mut ledger = StageCSuiEventLedger::new();
        let coord = SuiEventCoord::new([0x11u8; 32], 0);
        assert_eq!(ledger.observe(coord, trace()), SuiEventOutcome::FirstSeen);
        // The same coordinate re-observed reconciles to a duplicate, not a repeat.
        assert_eq!(
            ledger.observe(coord, trace()),
            SuiEventOutcome::DuplicateIgnored
        );
        assert_eq!(ledger.len(), 1, "duplicate does not grow the ledger");
        assert!(ledger.contains(&coord));
    }

    #[test]
    fn distinct_coords_are_distinct_events() {
        let mut ledger = StageCSuiEventLedger::new();
        let a = SuiEventCoord::new([0x11u8; 32], 0);
        let b = SuiEventCoord::new([0x11u8; 32], 1); // same tx, next event seq
        let c = SuiEventCoord::new([0x22u8; 32], 0); // different tx
        assert_eq!(ledger.observe(a, trace()), SuiEventOutcome::FirstSeen);
        assert_eq!(ledger.observe(b, trace()), SuiEventOutcome::FirstSeen);
        assert_eq!(ledger.observe(c, trace()), SuiEventOutcome::FirstSeen);
        assert_eq!(ledger.len(), 3);
    }

    #[test]
    fn empty_ledger_is_empty() {
        let ledger = StageCSuiEventLedger::new();
        assert!(ledger.is_empty());
        assert_eq!(ledger.len(), 0);
    }
}
