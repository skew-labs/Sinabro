//! Stage B Walrus boundary-aware retry policy.
//!
//! A Walrus testnet PUT crosses an **external-mutation boundary**: at some point
//! the request's bytes leave the client and may be durably stored by the network.
//! Once that may have happened, an *automatic* second PUT is forbidden — a blind
//! retry could create a duplicate stored blob (and a duplicate on-chain anchor /
//! audit append downstream). This module encodes that single invariant:
//!
//! > **if bytes may have crossed, automatic second PUT is forbidden — manual
//! > reconcile only.**
//!
//! It does so as a pure, offline classifier over two canonical OUT enums:
//!
//! ```text
//! pub enum WalrusBoundaryState { NoExternalMutation=1, BytesMayHaveCrossed=2, UnknownAfterBoundary=3 }
//! pub enum WalrusRetry         { Never=1, BeforeBoundaryOnly=2, ManualReconcile=3 }
//! ```
//!
//! The decision [`WalrusBoundaryState::retry`] is the enforcement point:
//!
//! | observed boundary        | retry decision          | meaning                                   |
//! |--------------------------|-------------------------|-------------------------------------------|
//! | `NoExternalMutation`     | `BeforeBoundaryOnly`    | bytes never left → an auto-retry is safe  |
//! | `BytesMayHaveCrossed`    | `ManualReconcile`       | bytes may be stored → no auto second PUT  |
//! | `UnknownAfterBoundary`   | `ManualReconcile`       | outcome unknown → the unknown absorbs the |
//! |                          |                         | retry; reconcile by hand, never blind-PUT |
//!
//! [`WalrusRetry::BeforeBoundaryOnly`] is the *only* decision that permits an
//! automatic retry ([`WalrusRetry::allows_automatic_retry`]); both ambiguous
//! boundary states fail **closed** to a manual reconcile, so the invariant
//! holds for every input by construction (proved over all states by the
//! `b2_9_proptest_madness_invariant` property).
//!
//! # Invariants
//!
//! * **Bytes-may-have-crossed forbids an automatic PUT.** Neither
//!   `BytesMayHaveCrossed` nor `UnknownAfterBoundary` can ever yield a decision
//!   whose [`allows_automatic_retry`](WalrusRetry::allows_automatic_retry) is
//!   `true`. The only auto-retryable state is `NoExternalMutation`.
//! * **A GET is read-only.** A Walrus aggregator GET fetches already-published
//!   bytes and crosses no external-mutation boundary, so its boundary is
//!   `NoExternalMutation` by construction ([`for_read_only_get`]) and it is
//!   always safe to retry. (`crates/b-memory/src/stage_b_get.rs:289` documents
//!   the same read-only property at the parser layer: a GET produces no
//!   `BoundaryUnknown`.)
//! * **Only a boundary-naming error implies a boundary.** Of the seven
//!   [`WalrusClientError`] variants, only
//!   [`BoundaryUnknown`](WalrusClientError::BoundaryUnknown) carries a definite
//!   boundary meaning (its own docs: "crossed the external-mutation boundary with
//!   an unknown outcome"); it bridges to `UnknownAfterBoundary`. Every other
//!   error's boundary position is decided by the transport-execution atom where
//!   the request lifecycle is observed, not guessed by this pure classifier — so
//!   [`from_boundary_naming_error`](WalrusBoundaryState::from_boundary_naming_error)
//!   returns `None` for them. The reject is fail-closed: `None` means "the caller
//!   must supply the observed boundary," never "a safe retry."
//! * **No canonical type beyond the two enums is minted.** The error→boundary
//!   bridge and the GET/PUT decisions are inherent methods, not new canonical
//!   signatures, and no new [`WalrusClientError`] variant is introduced (the set
//!   stays frozen at seven). `Never` is a forward-reserved decision (see below),
//!   mirroring the forward-reserved error-variant precedent.
//!
//! # `WalrusRetry::Never` — forward-reserved
//!
//! `Never` is the strictest decision: *no* retry path at all, distinct from
//! `ManualReconcile` (which permits a human-driven reconcile). No function here
//! produces it; it is reserved for a structurally one-shot / already-committed
//! operation that must never be retried — e.g. a PUT idempotency
//! ledger may classify a confirmed-committed content digest as `Never` to forbid
//! even a manual second PUT. It is exercised here only by its stable tag, label,
//! and predicates, exactly as the earlier forward-reserved
//! `WalrusClientError` variants (`Transport`, `Protocol`, …) were before a later
//! stage produced them.
//!
//! # Reuse map
//!
//! * [`WalrusClientError`](crate::stage_b_put::WalrusClientError) — the
//!   layered Stage B client error. Consumed here through the unambiguous
//!   `BoundaryUnknown → UnknownAfterBoundary` bridge (the single error variant
//!   whose docs name the boundary).
//! * the PUT request/response path (`WalrusPutPlan` /
//!   `parse_walrus_put_response`) is the *mutating* operation whose boundary this
//!   module classifies; not imported (this module is the pure policy, the transport
//!   execution that observes the boundary is the `stage_b_put_with_transport`
//!   path). Flagged, not forced — the "defer unconsumed canonical"
//!   precedent.
//! * the GET request/response path (`WalrusGetPlan` /
//!   `parse_walrus_get_response`) is read-only; its read-only property is the
//!   reason [`for_read_only_get`] is unconditionally `NoExternalMutation`.

use crate::stage_b_put::WalrusClientError;

/// The state of the external-mutation boundary for a Walrus operation.
///
/// `#[repr(u8)]` with explicit discriminants so the byte tag is stable for any
/// future tabular/diagnostic form (mirrors `StageBNetwork` and the
/// `Evidence*Class` enums). The type is a data-free `Copy` tag — it carries no
/// host, body, blob id, or error text — so a boundary state can never leak
/// content through a `Debug` rendering.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
#[repr(u8)]
pub enum WalrusBoundaryState {
    /// The bytes never left the client: the operation failed (or was rejected)
    /// before the external-mutation boundary, or the operation is read-only.
    /// Nothing external changed, so an automatic retry is safe.
    NoExternalMutation = 1,
    /// The bytes may have been written externally (e.g. a response was received
    /// from the network indicating the request reached the store). An automatic
    /// second PUT is forbidden — only a manual reconcile may proceed.
    BytesMayHaveCrossed = 2,
    /// The outcome after the boundary is unknown (e.g. a timeout or reset after
    /// the bytes were put on the wire). Fail-closed: treated exactly like
    /// `BytesMayHaveCrossed` for retry purposes — the unknown absorbs the retry.
    UnknownAfterBoundary = 3,
}

/// The retry decision implied by a [`WalrusBoundaryState`].
///
/// `#[repr(u8)]` with explicit discriminants for a stable byte tag. Data-free
/// `Copy` tag (no content can leak through it). [`BeforeBoundaryOnly`] is the
/// only decision that permits an automatic retry.
///
/// [`BeforeBoundaryOnly`]: WalrusRetry::BeforeBoundaryOnly
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
#[repr(u8)]
pub enum WalrusRetry {
    /// No retry path at all (the strictest decision) — forward-reserved for a
    /// structurally one-shot / already-committed operation. See the module-level
    /// "`WalrusRetry::Never` — forward-reserved" note. Distinct from
    /// `ManualReconcile`, which permits a human-driven reconcile.
    Never = 1,
    /// An automatic retry is permitted, but only because the external-mutation
    /// boundary has not been crossed (the bytes never left, or the operation is
    /// read-only). This is the only auto-retryable decision.
    BeforeBoundaryOnly = 2,
    /// Bytes may have crossed the boundary (or the outcome is unknown): an
    /// automatic second PUT is forbidden. A human-driven reconcile is the only
    /// permitted continuation.
    ManualReconcile = 3,
}

impl WalrusBoundaryState {
    /// Stable `u8` tag — mirrors the `#[repr(u8)]` discriminant.
    #[inline]
    pub const fn tag(self) -> u8 {
        self as u8
    }

    /// Stable `&'static str` label, namespaced `walrus.boundary.*`. Content-free,
    /// safe to log in place of any captured host/body/error text.
    #[inline]
    pub const fn class_label(self) -> &'static str {
        match self {
            Self::NoExternalMutation => "walrus.boundary.no_external_mutation",
            Self::BytesMayHaveCrossed => "walrus.boundary.bytes_may_have_crossed",
            Self::UnknownAfterBoundary => "walrus.boundary.unknown_after_boundary",
        }
    }

    /// `true` iff this boundary state forbids an automatic retry — i.e. the bytes
    /// may have crossed the boundary (`BytesMayHaveCrossed` or
    /// `UnknownAfterBoundary`). The complement (`NoExternalMutation`) is the only
    /// auto-retryable state.
    #[inline]
    pub const fn requires_manual_reconcile(self) -> bool {
        match self {
            Self::NoExternalMutation => false,
            Self::BytesMayHaveCrossed | Self::UnknownAfterBoundary => true,
        }
    }

    /// The boundary state of a read-only GET: **always** `NoExternalMutation`. A
    /// Walrus aggregator GET fetches already-published bytes and crosses no
    /// external-mutation boundary, so retrying it is read-only-safe regardless of
    /// the transport outcome (cf. `stage_b_get.rs:289`).
    #[inline]
    pub const fn for_read_only_get() -> Self {
        Self::NoExternalMutation
    }

    /// Bridge a [`WalrusClientError`] that *names* the boundary to its boundary
    /// state. Only [`WalrusClientError::BoundaryUnknown`] carries a definite
    /// boundary meaning (its docs: "crossed the external-mutation boundary with an
    /// unknown outcome") and maps to [`UnknownAfterBoundary`]; every other error's
    /// boundary position is decided by the transport-execution atom that observes
    /// the request lifecycle, not guessed here, so they return `None`.
    ///
    /// Fail-closed: `None` means "the caller must supply the observed boundary,"
    /// never "a safe retry." The `_` arm makes any future error variant default
    /// to `None` (supply-a-boundary) rather than silently to a retry.
    ///
    /// [`UnknownAfterBoundary`]: WalrusBoundaryState::UnknownAfterBoundary
    #[inline]
    pub const fn from_boundary_naming_error(err: WalrusClientError) -> Option<Self> {
        match err {
            WalrusClientError::BoundaryUnknown => Some(Self::UnknownAfterBoundary),
            _ => None,
        }
    }

    /// The retry decision for this boundary state — the enforcement
    /// point.
    ///
    /// * `NoExternalMutation` → [`WalrusRetry::BeforeBoundaryOnly`] (auto-retry
    ///   safe; bytes never left).
    /// * `BytesMayHaveCrossed` → [`WalrusRetry::ManualReconcile`] (automatic
    ///   second PUT forbidden).
    /// * `UnknownAfterBoundary` → [`WalrusRetry::ManualReconcile`] (the unknown
    ///   absorbs the retry).
    ///
    /// The invariant — `self.requires_manual_reconcile()` implies
    /// `!self.retry().allows_automatic_retry()` — holds for every state.
    #[inline]
    pub const fn retry(self) -> WalrusRetry {
        match self {
            Self::NoExternalMutation => WalrusRetry::BeforeBoundaryOnly,
            Self::BytesMayHaveCrossed | Self::UnknownAfterBoundary => WalrusRetry::ManualReconcile,
        }
    }
}

impl WalrusRetry {
    /// Stable `u8` tag — mirrors the `#[repr(u8)]` discriminant.
    #[inline]
    pub const fn tag(self) -> u8 {
        self as u8
    }

    /// Stable `&'static str` label, namespaced `walrus.retry.*`. Content-free.
    #[inline]
    pub const fn class_label(self) -> &'static str {
        match self {
            Self::Never => "walrus.retry.never",
            Self::BeforeBoundaryOnly => "walrus.retry.before_boundary_only",
            Self::ManualReconcile => "walrus.retry.manual_reconcile",
        }
    }

    /// `true` iff an automatic (machine-driven) retry is permitted. Only
    /// [`BeforeBoundaryOnly`](WalrusRetry::BeforeBoundaryOnly) qualifies; both
    /// `Never` and `ManualReconcile` forbid an automatic retry.
    #[inline]
    pub const fn allows_automatic_retry(self) -> bool {
        match self {
            Self::BeforeBoundaryOnly => true,
            Self::Never | Self::ManualReconcile => false,
        }
    }

    /// `true` iff a human-driven manual reconcile is the required continuation
    /// (`ManualReconcile` only). `Never` forbids even a manual reconcile.
    #[inline]
    pub const fn requires_manual_reconcile(self) -> bool {
        matches!(self, Self::ManualReconcile)
    }

    /// The retry decision for a read-only GET: [`BeforeBoundaryOnly`] — a GET
    /// crosses no external-mutation boundary, so it is always safe to retry.
    /// Equivalent to `WalrusBoundaryState::for_read_only_get().retry()`.
    ///
    /// [`BeforeBoundaryOnly`]: WalrusRetry::BeforeBoundaryOnly
    #[inline]
    pub const fn for_read_only_get() -> Self {
        WalrusBoundaryState::for_read_only_get().retry()
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    #![allow(clippy::expect_used)]
    #![allow(clippy::panic)]

    use super::*;

    /// `b2_9_before_boundary_retries` — in the before-boundary state
    /// (`NoExternalMutation`) an automatic retry is permitted: the decision is
    /// `BeforeBoundaryOnly`, `allows_automatic_retry` is `true`, and no manual
    /// reconcile is required. Stable tags 1/2/3.
    #[test]
    fn b2_9_before_boundary_retries() {
        let s = WalrusBoundaryState::NoExternalMutation;
        assert_eq!(s.tag(), 1);
        assert!(!s.requires_manual_reconcile());
        assert_eq!(s.retry(), WalrusRetry::BeforeBoundaryOnly);
        assert!(s.retry().allows_automatic_retry());
        assert!(!s.retry().requires_manual_reconcile());

        // Stable discriminants for both enums.
        assert_eq!(WalrusBoundaryState::BytesMayHaveCrossed.tag(), 2);
        assert_eq!(WalrusBoundaryState::UnknownAfterBoundary.tag(), 3);
        assert_eq!(WalrusRetry::Never.tag(), 1);
        assert_eq!(WalrusRetry::BeforeBoundaryOnly.tag(), 2);
        assert_eq!(WalrusRetry::ManualReconcile.tag(), 3);
    }

    /// `b2_9_unknown_absorbs_retry` — the unknown-after-boundary state absorbs the
    /// retry: the decision is `ManualReconcile`, never an automatic retry. The
    /// `BoundaryUnknown` client error bridges to exactly this state.
    #[test]
    fn b2_9_unknown_absorbs_retry() {
        let s = WalrusBoundaryState::UnknownAfterBoundary;
        assert!(s.requires_manual_reconcile());
        assert_eq!(s.retry(), WalrusRetry::ManualReconcile);
        assert!(!s.retry().allows_automatic_retry());
        assert!(s.retry().requires_manual_reconcile());

        // The single boundary-naming error bridges here.
        assert_eq!(
            WalrusBoundaryState::from_boundary_naming_error(WalrusClientError::BoundaryUnknown),
            Some(WalrusBoundaryState::UnknownAfterBoundary),
        );
    }

    /// `b2_9_get_retry_read_only` — a read-only GET crosses no external-mutation
    /// boundary, so its boundary is `NoExternalMutation` and retrying it is always
    /// safe (`BeforeBoundaryOnly`). The `WalrusRetry::for_read_only_get` shortcut
    /// agrees with the boundary-derived decision.
    #[test]
    fn b2_9_get_retry_read_only() {
        assert_eq!(
            WalrusBoundaryState::for_read_only_get(),
            WalrusBoundaryState::NoExternalMutation,
        );
        assert_eq!(
            WalrusBoundaryState::for_read_only_get().retry(),
            WalrusRetry::BeforeBoundaryOnly,
        );
        assert_eq!(
            WalrusRetry::for_read_only_get(),
            WalrusRetry::BeforeBoundaryOnly
        );
        assert!(WalrusRetry::for_read_only_get().allows_automatic_retry());
    }

    /// `b2_9_bytes_crossed_forbids_auto_put` — the invariant's core case:
    /// once bytes may have crossed, the decision is `ManualReconcile` and an
    /// automatic second PUT is forbidden.
    #[test]
    fn b2_9_bytes_crossed_forbids_auto_put() {
        let s = WalrusBoundaryState::BytesMayHaveCrossed;
        assert!(s.requires_manual_reconcile());
        assert_eq!(s.retry(), WalrusRetry::ManualReconcile);
        assert!(
            !s.retry().allows_automatic_retry(),
            "bytes-may-have-crossed must forbid an automatic retry",
        );
    }

    /// `b2_9_never_forward_reserved` — `WalrusRetry::Never` is the strictest
    /// decision: stable tag 1, a content-free label, no automatic retry, and not
    /// even a manual reconcile (distinct from `ManualReconcile`). It is produced
    /// by no decision this atom (forward-reserved) but carries real behavior.
    #[test]
    fn b2_9_never_forward_reserved() {
        let r = WalrusRetry::Never;
        assert_eq!(r.tag(), 1);
        assert_eq!(r.class_label(), "walrus.retry.never");
        assert!(!r.allows_automatic_retry());
        assert!(!r.requires_manual_reconcile());
        // No boundary state's decision is `Never`.
        for s in [
            WalrusBoundaryState::NoExternalMutation,
            WalrusBoundaryState::BytesMayHaveCrossed,
            WalrusBoundaryState::UnknownAfterBoundary,
        ] {
            assert_ne!(s.retry(), WalrusRetry::Never);
        }
    }

    /// `b2_9_error_bridge_only_boundary_unknown` — the error→boundary bridge maps
    /// only `BoundaryUnknown` (→ `UnknownAfterBoundary`); every other client error
    /// returns `None` (fail-closed: the caller must supply the observed boundary).
    #[test]
    fn b2_9_error_bridge_only_boundary_unknown() {
        assert_eq!(
            WalrusBoundaryState::from_boundary_naming_error(WalrusClientError::BoundaryUnknown),
            Some(WalrusBoundaryState::UnknownAfterBoundary),
        );
        for err in [
            WalrusClientError::EndpointDenied,
            WalrusClientError::PayloadClassDenied,
            WalrusClientError::Transport,
            WalrusClientError::Protocol,
            WalrusClientError::BlobIdMismatch,
            WalrusClientError::OversizedBody,
        ] {
            assert_eq!(
                WalrusBoundaryState::from_boundary_naming_error(err),
                None,
                "non-boundary-naming error {err:?} must not imply a boundary",
            );
        }
    }

    /// `b2_9_labels_distinct` — every boundary-state and retry label is a distinct,
    /// content-free `walrus.*` string (no host/body/error text leaks through a
    /// diagnostic label).
    #[test]
    fn b2_9_labels_distinct() {
        let b = [
            WalrusBoundaryState::NoExternalMutation.class_label(),
            WalrusBoundaryState::BytesMayHaveCrossed.class_label(),
            WalrusBoundaryState::UnknownAfterBoundary.class_label(),
        ];
        let r = [
            WalrusRetry::Never.class_label(),
            WalrusRetry::BeforeBoundaryOnly.class_label(),
            WalrusRetry::ManualReconcile.class_label(),
        ];
        for label in b.iter().chain(r.iter()) {
            assert!(
                label.starts_with("walrus."),
                "label {label:?} not namespaced"
            );
        }
        // All six labels are pairwise distinct.
        let mut all: Vec<&str> = b.iter().chain(r.iter()).copied().collect();
        all.sort_unstable();
        all.dedup();
        assert_eq!(all.len(), 6, "labels must be pairwise distinct");
    }

    proptest::proptest! {
        /// `b2_9_proptest_madness_invariant` — over an arbitrary boundary state
        /// (sampled across all three inhabitants) the invariant
        /// holds: a state that requires a manual reconcile NEVER produces a
        /// decision that allows an automatic retry, and conversely the only state
        /// whose decision allows an automatic retry is `NoExternalMutation`. The
        /// decision is also total and deterministic (same input = same output).
        #[test]
        fn b2_9_proptest_madness_invariant(tag in 1u8..=3u8) {
            let state = match tag {
                1 => WalrusBoundaryState::NoExternalMutation,
                2 => WalrusBoundaryState::BytesMayHaveCrossed,
                _ => WalrusBoundaryState::UnknownAfterBoundary,
            };

            let decision = state.retry();
            // Determinism: re-deriving yields the identical decision.
            proptest::prop_assert_eq!(decision, state.retry());

            // Core invariant: may-have-crossed ⇒ no automatic retry.
            if state.requires_manual_reconcile() {
                proptest::prop_assert!(!decision.allows_automatic_retry());
                proptest::prop_assert_eq!(decision, WalrusRetry::ManualReconcile);
            }

            // Converse: an auto-retryable decision arises only before the boundary.
            if decision.allows_automatic_retry() {
                proptest::prop_assert_eq!(state, WalrusBoundaryState::NoExternalMutation);
                proptest::prop_assert_eq!(decision, WalrusRetry::BeforeBoundaryOnly);
            }
        }

        /// `b2_9_proptest_error_bridge_fail_closed` — over an arbitrary client
        /// error (sampled across all seven variants by tag), the error→boundary
        /// bridge yields `Some` only for `BoundaryUnknown`, and that `Some` is
        /// always `UnknownAfterBoundary` (whose decision forbids an automatic
        /// retry). Every other variant is fail-closed `None`.
        #[test]
        fn b2_9_proptest_error_bridge_fail_closed(tag in 0u8..7u8) {
            let err = match tag {
                0 => WalrusClientError::EndpointDenied,
                1 => WalrusClientError::PayloadClassDenied,
                2 => WalrusClientError::Transport,
                3 => WalrusClientError::Protocol,
                4 => WalrusClientError::BlobIdMismatch,
                5 => WalrusClientError::OversizedBody,
                _ => WalrusClientError::BoundaryUnknown,
            };

            match WalrusBoundaryState::from_boundary_naming_error(err) {
                Some(state) => {
                    proptest::prop_assert_eq!(err, WalrusClientError::BoundaryUnknown);
                    proptest::prop_assert_eq!(state, WalrusBoundaryState::UnknownAfterBoundary);
                    proptest::prop_assert!(!state.retry().allows_automatic_retry());
                }
                None => {
                    proptest::prop_assert_ne!(err, WalrusClientError::BoundaryUnknown);
                }
            }
        }
    }
}
