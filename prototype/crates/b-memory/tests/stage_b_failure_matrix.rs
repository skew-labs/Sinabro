//! Integration tests for the Stage B Walrus client — total **failure matrix**
//! (atom #119 · B.2.18).
//!
//! # What this atom is
//!
//! The canonical OUT is a *total matrix of status / failure / boundary / retry*:
//! an exhaustive, offline, deterministic enumeration proving the atom #119 madness
//! invariant —
//!
//! > **every failure maps to a deterministic retry/stop decision.**
//!
//! Unlike atom #115 (the offline *mock transport* matrix, which drives the real
//! `c-walrus` retry/boundary loop with fake transports to prove the loop produces
//! the right `(stop reason, boundary)`), this atom is a pure *decision matrix* over
//! the atom #110 boundary-aware retry classifier. It takes the loop's two
//! observable axes —
//!
//! * **status / failure**: the diagnostic status of an operation, modelled as
//!   `Option<WalrusClientError>` (`None` = success, `Some(e)` = one of the seven
//!   frozen [`WalrusClientError`] variants), and
//! * **boundary**: the observed external-mutation boundary
//!   ([`WalrusBoundaryState`], three states),
//!
//! and asserts that the cross product maps **totally and deterministically** onto a
//! retry/stop decision ([`WalrusRetry`]), with the key safety property that an
//! *unknown* boundary never yields an automatic retry.
//!
//! # Why the decision depends on the boundary, and the failure only *hints* it
//!
//! A Walrus PUT's retry safety is decided by whether bytes may have crossed the
//! external-mutation boundary, not by the error label: a `Transport` failure that
//! happened *before* the boundary is auto-retryable, while the same label *after*
//! the boundary is not. So the retry decision is [`WalrusBoundaryState::retry`],
//! and a failure contributes only a *boundary hint*: of the seven errors, only
//! [`WalrusClientError::BoundaryUnknown`] names a definite boundary
//! ([`WalrusBoundaryState::from_boundary_naming_error`] →
//! `Some(UnknownAfterBoundary)`); the other six return `None`, fail-closed, meaning
//! "the caller must supply the observed boundary," never "a safe retry." The
//! matrix therefore ranges over `(status, observed_boundary)` and proves the
//! mapping is total over every combination.
//!
//! # Offline posture (`G-B-WALRUS-OFFLINE` + `G-B-PROPTEST`)
//!
//! No `std::net`, no `reqwest`, no live egress, no subprocess: the matrix is a pure
//! function of two content-free `Copy` tag enums. The `net-testnet` feature is
//! **not** required — every symbol used here is in the default, non-feature-gated
//! `mnemos-b-memory` surface (atom #103 [`WalrusClientError`], atom #110
//! [`WalrusBoundaryState`] / [`WalrusRetry`]). The two proptests give the
//! `G-B-PROPTEST` coverage; the deterministic enumeration gives the `matrix total`
//! coverage.
//!
//! # Reuse map (atom contract — reuse #110, #115)
//!
//! * **#110** [`WalrusBoundaryState`] / [`WalrusRetry`] — the boundary-aware retry
//!   classifier under test: `retry`, `requires_manual_reconcile`,
//!   `allows_automatic_retry`, `from_boundary_naming_error`. The matrix is an
//!   exhaustive table of this classifier's decisions.
//! * **#115** the offline-matrix discipline: a `tests/` integration matrix with no
//!   live byte, `G-B-WALRUS-OFFLINE` + `G-B-PROPTEST`. #115 sources failures by
//!   driving the production loop; #119 enumerates the decision space directly, so
//!   the two matrices are complementary, not duplicative (the loop is already
//!   covered at #115 and is not re-driven here).

#![allow(clippy::unwrap_used)]
#![allow(clippy::expect_used)]
#![allow(clippy::panic)]

use mnemos_b_memory::{WalrusBoundaryState, WalrusClientError, WalrusRetry};

use proptest::prelude::*;

/// All seven frozen [`WalrusClientError`] variants (atom #103, §4.2 frozen-7),
/// in stable order. The matrix's *failure* axis.
const ALL_ERRORS: [WalrusClientError; 7] = [
    WalrusClientError::EndpointDenied,
    WalrusClientError::PayloadClassDenied,
    WalrusClientError::Transport,
    WalrusClientError::Protocol,
    WalrusClientError::BlobIdMismatch,
    WalrusClientError::OversizedBody,
    WalrusClientError::BoundaryUnknown,
];

/// All three [`WalrusBoundaryState`] inhabitants (atom #110, §4.2), in stable
/// discriminant order. The matrix's *boundary* axis.
const ALL_BOUNDARIES: [WalrusBoundaryState; 3] = [
    WalrusBoundaryState::NoExternalMutation,
    WalrusBoundaryState::BytesMayHaveCrossed,
    WalrusBoundaryState::UnknownAfterBoundary,
];

/// The matrix's *status* axis: a Walrus operation's diagnostic status is either
/// success (`None`) or one of the seven failures (`Some`). Eight inhabitants.
fn all_statuses() -> Vec<Option<WalrusClientError>> {
    let mut v: Vec<Option<WalrusClientError>> = Vec::with_capacity(8);
    v.push(None);
    for e in ALL_ERRORS {
        v.push(Some(e));
    }
    v
}

/// Decode an arbitrary `u8` boundary tag to its [`WalrusBoundaryState`], or `None`
/// for any out-of-range / unknown byte. Mirrors the production decoder pattern in
/// `stage_b_idempotency.rs:82` (`boundary_from_tag`). Used by the
/// arbitrary-status proptest to model an unrecognized boundary tag.
fn decode_boundary(tag: u8) -> Option<WalrusBoundaryState> {
    match tag {
        1 => Some(WalrusBoundaryState::NoExternalMutation),
        2 => Some(WalrusBoundaryState::BytesMayHaveCrossed),
        3 => Some(WalrusBoundaryState::UnknownAfterBoundary),
        _ => None,
    }
}

/// Decode an arbitrary `u8` status tag to its [`WalrusClientError`] failure, or
/// `None` for success (tag `0`) **and** for any out-of-range / unknown byte. The
/// matrix's *failure* axis as a total function over `u8`.
fn decode_status(tag: u8) -> Option<WalrusClientError> {
    match tag {
        1 => Some(WalrusClientError::EndpointDenied),
        2 => Some(WalrusClientError::PayloadClassDenied),
        3 => Some(WalrusClientError::Transport),
        4 => Some(WalrusClientError::Protocol),
        5 => Some(WalrusClientError::BlobIdMismatch),
        6 => Some(WalrusClientError::OversizedBody),
        7 => Some(WalrusClientError::BoundaryUnknown),
        _ => None,
    }
}

/// The atom #119 total decision: given a (status, observed boundary) cell, the
/// retry/stop decision is the boundary's [`WalrusBoundaryState::retry`]. The
/// failure status does not override the boundary — it only *hints* a boundary
/// elsewhere (`from_boundary_naming_error`); the enforcement point is the boundary.
/// This function is total over every `(Option<WalrusClientError>, WalrusBoundaryState)`.
fn decide(_status: Option<WalrusClientError>, boundary: WalrusBoundaryState) -> WalrusRetry {
    boundary.retry()
}

/// The fail-closed decision when the boundary is **unknown / unrecognized** (the
/// decoder returned `None`): an unknown boundary can never yield an automatic
/// retry, so it absorbs into [`WalrusRetry::ManualReconcile`]. This is the
/// "unknown boundary no retry" property at the decoder edge.
fn decide_unknown_boundary() -> WalrusRetry {
    WalrusRetry::ManualReconcile
}

/// `b2_18_matrix_total` — the total matrix. Every (status × boundary) cell of the
/// 8×3 = 24-cell matrix maps to exactly one deterministic [`WalrusRetry`]
/// decision, the decision is never the forward-reserved `Never`, both real
/// decisions actually occur (the matrix is not collapsed), and the failure→boundary
/// bridge is total over all seven errors.
#[test]
fn b2_18_matrix_total() {
    let statuses = all_statuses();
    assert_eq!(
        statuses.len(),
        8,
        "status axis = success + 7 frozen failures"
    );
    assert_eq!(ALL_BOUNDARIES.len(), 3, "boundary axis = 3 states");

    // Build the full matrix. Each cell is recorded as
    // (status, boundary, decision); a re-derivation must yield the identical
    // decision (determinism), and the decision must be a real, total decision.
    let mut cells: Vec<(Option<WalrusClientError>, WalrusBoundaryState, WalrusRetry)> =
        Vec::with_capacity(24);
    let mut saw_before_boundary = false;
    let mut saw_manual_reconcile = false;

    for &status in &statuses {
        for &boundary in &ALL_BOUNDARIES {
            let decision = decide(status, boundary);

            // Determinism: the same cell re-derives the identical decision.
            assert_eq!(
                decision,
                decide(status, boundary),
                "matrix cell ({status:?}, {boundary:?}) is not deterministic",
            );

            // Totality: every cell is a real decision, never the forward-reserved
            // `Never` (no boundary state produces it — atom #110 invariant).
            assert!(
                matches!(
                    decision,
                    WalrusRetry::BeforeBoundaryOnly | WalrusRetry::ManualReconcile
                ),
                "cell ({status:?}, {boundary:?}) produced a non-total / reserved decision {decision:?}",
            );
            assert_ne!(
                decision,
                WalrusRetry::Never,
                "the classifier must never produce the forward-reserved `Never`",
            );

            // The decision agrees with the boundary's documented mapping.
            match boundary {
                WalrusBoundaryState::NoExternalMutation => {
                    assert_eq!(decision, WalrusRetry::BeforeBoundaryOnly);
                    assert!(decision.allows_automatic_retry());
                    saw_before_boundary = true;
                }
                WalrusBoundaryState::BytesMayHaveCrossed
                | WalrusBoundaryState::UnknownAfterBoundary => {
                    assert_eq!(decision, WalrusRetry::ManualReconcile);
                    assert!(!decision.allows_automatic_retry());
                    saw_manual_reconcile = true;
                }
            }

            cells.push((status, boundary, decision));
        }
    }

    // The matrix is complete: exactly 24 cells, one per (status, boundary).
    assert_eq!(
        cells.len(),
        24,
        "matrix must be total over 8 statuses × 3 boundaries"
    );

    // The matrix is not collapsed: both real decisions occur.
    assert!(saw_before_boundary, "an auto-retryable cell must exist");
    assert!(saw_manual_reconcile, "a manual-reconcile cell must exist");

    // The failure→boundary bridge is total over all seven errors: only
    // `BoundaryUnknown` names a boundary (→ `UnknownAfterBoundary`); the other six
    // are fail-closed `None`.
    let mut bridged = 0usize;
    for err in ALL_ERRORS {
        match WalrusBoundaryState::from_boundary_naming_error(err) {
            Some(state) => {
                assert_eq!(err, WalrusClientError::BoundaryUnknown);
                assert_eq!(state, WalrusBoundaryState::UnknownAfterBoundary);
                // A bridged failure's implied decision forbids an automatic retry.
                assert!(!state.retry().allows_automatic_retry());
                bridged += 1;
            }
            None => assert_ne!(err, WalrusClientError::BoundaryUnknown),
        }
    }
    assert_eq!(
        bridged, 1,
        "exactly one of the seven errors names a boundary"
    );
}

/// `b2_18_unknown_boundary_no_retry` — an unknown boundary never yields an
/// automatic retry. The `UnknownAfterBoundary` state maps to `ManualReconcile`
/// (the unknown absorbs the retry); the `BoundaryUnknown` error bridges to exactly
/// that state; and every other error is fail-closed `None` (the caller must supply
/// the observed boundary — never a silent retry).
#[test]
fn b2_18_unknown_boundary_no_retry() {
    let unknown = WalrusBoundaryState::UnknownAfterBoundary;
    assert!(unknown.requires_manual_reconcile());
    assert_eq!(unknown.retry(), WalrusRetry::ManualReconcile);
    assert!(
        !unknown.retry().allows_automatic_retry(),
        "an unknown boundary must forbid an automatic retry",
    );
    assert!(unknown.retry().requires_manual_reconcile());

    // The only boundary-naming error bridges to the unknown state.
    assert_eq!(
        WalrusBoundaryState::from_boundary_naming_error(WalrusClientError::BoundaryUnknown),
        Some(WalrusBoundaryState::UnknownAfterBoundary),
    );

    // Every other error is fail-closed `None` (supply-a-boundary), never a retry.
    for err in ALL_ERRORS {
        if err == WalrusClientError::BoundaryUnknown {
            continue;
        }
        assert_eq!(
            WalrusBoundaryState::from_boundary_naming_error(err),
            None,
            "non-boundary-naming error {err:?} must not imply a boundary (fail-closed)",
        );
    }

    // The decoder edge: an unrecognized boundary tag is also no-retry by
    // construction.
    assert_eq!(decide_unknown_boundary(), WalrusRetry::ManualReconcile);
    assert!(!decide_unknown_boundary().allows_automatic_retry());
}

proptest! {
    /// `b2_18_no_panic_arbitrary_status` — over an *arbitrary* status byte and an
    /// *arbitrary* boundary byte (the full `u8` space, including bytes that name no
    /// known status or boundary), the decision pipeline never panics, is total
    /// (always yields a decision), and is fail-closed: an unrecognized boundary
    /// tag yields `ManualReconcile` and never an automatic retry. A recognized
    /// boundary follows the atom #110 classifier regardless of the (arbitrary)
    /// status byte.
    #[test]
    fn b2_18_no_panic_arbitrary_status(status_tag in any::<u8>(), boundary_tag in any::<u8>()) {
        let status = decode_status(status_tag);

        let decision = match decode_boundary(boundary_tag) {
            // Recognized boundary: the classifier decides; the arbitrary status
            // byte does not override it.
            Some(boundary) => decide(status, boundary),
            // Unrecognized boundary byte: fail-closed, never an automatic retry.
            None => decide_unknown_boundary(),
        };

        // Totality: the decision is always one of the two real decisions (never
        // the forward-reserved `Never`).
        prop_assert!(matches!(
            decision,
            WalrusRetry::BeforeBoundaryOnly | WalrusRetry::ManualReconcile
        ));

        // Fail-closed at the unknown-boundary edge.
        if decode_boundary(boundary_tag).is_none() {
            prop_assert_eq!(decision, WalrusRetry::ManualReconcile);
            prop_assert!(!decision.allows_automatic_retry());
        }

        // An auto-retryable decision can only arise from the before-boundary state.
        if decision.allows_automatic_retry() {
            prop_assert_eq!(decode_boundary(boundary_tag), Some(WalrusBoundaryState::NoExternalMutation));
            prop_assert_eq!(decision, WalrusRetry::BeforeBoundaryOnly);
        }
    }

    /// `b2_18_proptest_matrix_total_deterministic` — over an arbitrary in-range
    /// (status, boundary) cell, the matrix decision is deterministic and total, and
    /// the atom #110 madness invariant holds: a boundary that requires a manual
    /// reconcile NEVER yields an automatic retry, and conversely the only state
    /// whose decision allows an automatic retry is `NoExternalMutation`. The
    /// `BoundaryUnknown` failure's boundary hint is consistent with the matrix.
    #[test]
    fn b2_18_proptest_matrix_total_deterministic(status_tag in 0u8..8, boundary_tag in 1u8..=3) {
        let status = decode_status(status_tag);
        let boundary = decode_boundary(boundary_tag).expect("boundary_tag is in 1..=3");

        let decision = decide(status, boundary);
        // Determinism: re-deriving the same cell yields the identical decision.
        prop_assert_eq!(decision, decide(status, boundary));

        // Totality: a real decision, never the forward-reserved `Never`.
        prop_assert!(matches!(
            decision,
            WalrusRetry::BeforeBoundaryOnly | WalrusRetry::ManualReconcile
        ));

        // Core invariant: may-have-crossed ⇒ no automatic retry.
        if boundary.requires_manual_reconcile() {
            prop_assert!(!decision.allows_automatic_retry());
            prop_assert_eq!(decision, WalrusRetry::ManualReconcile);
        }

        // Converse: an auto-retryable decision arises only before the boundary.
        if decision.allows_automatic_retry() {
            prop_assert_eq!(boundary, WalrusBoundaryState::NoExternalMutation);
            prop_assert_eq!(decision, WalrusRetry::BeforeBoundaryOnly);
        }

        // The failure's boundary hint is consistent: a `BoundaryUnknown` status
        // names the unknown-after-boundary state, whose decision forbids auto retry.
        if status == Some(WalrusClientError::BoundaryUnknown) {
            prop_assert_eq!(
                WalrusBoundaryState::from_boundary_naming_error(WalrusClientError::BoundaryUnknown),
                Some(WalrusBoundaryState::UnknownAfterBoundary),
            );
        }
    }
}
