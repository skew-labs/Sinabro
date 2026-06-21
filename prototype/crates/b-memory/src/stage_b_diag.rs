//! `stage_b_diag.rs` (atom #112 · B.2.11 diagnostics redaction) — the Stage B
//! **content-free** diagnostics record emitted for a Walrus testnet action.
//!
//! This module mints the atom #112 canonical OUT: [`WalrusDiagnostics`] — the
//! redacted Walrus diagnostics schema. It is exactly the "A canonical을 조합하는
//! … receipt/evidence 타입" category that §4.0 permits Stage B to mint: it
//! composes earlier-atom canonicals and introduces no new wire, no new error
//! type, no new id/address newtype, and no dependency. A diagnostics record can
//! be emitted to a log / metrics line without any byte of user memory leaving
//! the machine.
//!
//! # Madness invariant (`MNEMOS_STAGE_B_ATOM_PLAN.md` atom #112)
//!
//! > diagnostics include status/latency/retry/trace only. body and payload
//! > never logged.
//!
//! * **Status / latency / retry / trace only (redaction by construction).** The
//!   struct has exactly four fields — a content-free [`status`](Self::status),
//!   the measured [`latency_ms_u32`](Self::latency_ms_u32), the
//!   [`retry`](Self::retry) decision, and the content-free
//!   [`StageBTraceEvidence`] [`trace`](Self::trace_evidence). There is **no**
//!   `Vec<u8>` / `&[u8]` body field, no payload field, no owner
//!   [`SuiAddress`](mnemos_d_move::SuiAddress), no URL/host, and — unlike the
//!   atom #109 round-trip receipt — not even a transferred *length*. The plan
//!   line admits only those four diagnostic dimensions, so a length count is out
//!   of scope here and is omitted. A payload body is therefore not expressible
//!   in this schema; "body and payload never logged" is enforced by the type,
//!   not by a runtime redaction pass (the `b2_11_canary_payload_not_logged`
//!   proof).
//!
//! * **Status is the content-free Walrus outcome class.** [`status`](Self::status)
//!   reuses the atom #103 [`WalrusClientError`] — a data-free `Copy` tag whose
//!   every variant carries no host/body/provider text — wrapped in an
//!   [`Option`]: `None` is success ([`STATUS_OK_LABEL`]), `Some(e)` is the
//!   error's namespaced [`class_label`](WalrusClientError::class_label). No new
//!   status enum is minted and the frozen `#[non_exhaustive]` §4.2 error set is
//!   not widened.
//!
//! * **Retry decision carried verbatim.** [`retry`](Self::retry) is the atom
//!   #110 [`WalrusRetry`] decision; its namespaced
//!   [`class_label`](WalrusRetry::class_label) (`walrus.retry.*`) is the only
//!   thing emitted to JSON — content-free.
//!
//! * **Trace linked (fail-closed).** A diagnostics record holds a
//!   [`StageBTraceEvidence`] (atom #94), whose only constructor
//!   ([`from_trace`](StageBTraceEvidence::from_trace)) rejects the
//!   missing/unstamped sentinel (`atom_id_u16 == 0`) by returning `None`. So
//!   [`record`](WalrusDiagnostics::record) is fail-closed: a Walrus action not
//!   bound to a real atom mints **no** diagnostics record (the
//!   `b2_11_trace_required_fail_closed` proof — the G-B-TRACE gate enforced at
//!   the type level, mirroring the atom #94 / #109 seam).
//!
//! * **JSON allowlist keys only.** [`to_redacted_json`](WalrusDiagnostics::to_redacted_json)
//!   emits a fixed-shape object whose every key is drawn from
//!   [`DIAGNOSTIC_KEYS`]; every value is a fixed ASCII class label or an integer,
//!   so no user string can ever appear (the `b2_11_json_allowlist_keys_only`
//!   proof). This is the atom #112 "Stage A redaction" reuse applied as a
//!   *discipline* — `mnemos-b-memory` carries no `mnemos-a-core` dependency, so
//!   the redaction-by-construction pattern (atom #94 deferral precedent) is
//!   reused rather than the a-core `redact_for_log` kernel imported.
//!
//! # Reuse (재발명 0)
//!
//! * #103 [`WalrusClientError`](crate::stage_b_put::WalrusClientError) — the
//!   data-free, frozen-7 client error, used verbatim as the error half of the
//!   status. No new error type, no §4.2 widening.
//! * #110 [`WalrusRetry`](crate::stage_b_retry::WalrusRetry) — the retry
//!   decision tag, carried verbatim.
//! * #94 [`StageBTraceEvidence`](crate::trace_link::StageBTraceEvidence) — the
//!   content-free trace projection, held directly so an unstamped action cannot
//!   produce a record.
//! * #81 [`StageBTraceLink`](crate::stage_b_handoff::StageBTraceLink) — the
//!   `(trace_id, atom_id, attempt)` stamp the evidence binds; no second stamp
//!   type is minted.
//!
//! No new dependency, no new wire format, no new error type, no network.

use crate::stage_b_handoff::StageBTraceLink;
use crate::stage_b_put::WalrusClientError;
use crate::stage_b_retry::WalrusRetry;
use crate::trace_link::StageBTraceEvidence;

/// The status label used when a Walrus action succeeded (no [`WalrusClientError`]).
///
/// Namespaced `walrus.*` to match the content-free error/retry class labels, so
/// a diagnostics line reads the success case in the same vocabulary as the
/// failure cases without ever naming a host, body, or provider string.
pub const STATUS_OK_LABEL: &str = "walrus.ok";

/// The complete, closed set of JSON keys [`WalrusDiagnostics::to_redacted_json`]
/// may emit — the redaction allowlist.
///
/// Every key in the rendered object is one of these seven; there is no key
/// through which a payload body, owner address, host, or provider text could be
/// emitted. The `b2_11_json_allowlist_keys_only` test scans the rendered JSON
/// and asserts each key it finds is a member of this slice, so a future field
/// that widened the surface would fail the gate.
pub const DIAGNOSTIC_KEYS: &[&str] = &[
    "status",
    "latency_ms",
    "retry",
    "trace",
    "trace_id",
    "atom_id",
    "attempt",
];

/// Content-free diagnostics for a single Walrus testnet action.
///
/// The atom #112 canonical OUT. It records **only** the four diagnostic
/// dimensions the plan admits — status, latency, retry, trace — and deliberately
/// nothing else. There is no field that could hold the chunk body, the payload,
/// the owner address, or any provider text, so the record is redaction-safe by
/// construction and `Copy`.
///
/// Construct it via [`record`](Self::record), which is fail-closed on the
/// missing/unstamped trace sentinel (`atom_id_u16 == 0`).
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub struct WalrusDiagnostics {
    /// The Walrus action outcome: `None` is success ([`STATUS_OK_LABEL`]),
    /// `Some(e)` is the atom #103 data-free [`WalrusClientError`] class. No
    /// content can leak through this tag.
    status: Option<WalrusClientError>,
    /// Measured wall-clock cost of the action in milliseconds.
    latency_ms_u32: u32,
    /// The atom #110 retry decision for the action.
    retry: WalrusRetry,
    /// The atom #94 content-free trace evidence binding this action to a real
    /// atom (`atom_id_u16 != 0` guaranteed by the constructor).
    trace: StageBTraceEvidence,
}

impl WalrusDiagnostics {
    /// Record diagnostics for a Walrus action, fail-closed on an unstamped trace.
    ///
    /// `status` is `None` for success or `Some(e)` for the content-free atom #103
    /// error class. `latency_ms_u32` is the measured cost; `retry` is the atom
    /// #110 decision; `trace` is the atom #81 per-action stamp.
    ///
    /// Returns `None` if `trace` is the missing/unstamped sentinel
    /// (`atom_id_u16 == 0`) — a Walrus action not bound to a real atom mints no
    /// diagnostics record (the G-B-TRACE invariant, reusing the atom #94
    /// [`StageBTraceEvidence::from_trace`] fail-closed constructor).
    #[inline]
    pub const fn record(
        status: Option<WalrusClientError>,
        latency_ms_u32: u32,
        retry: WalrusRetry,
        trace: StageBTraceLink,
    ) -> Option<Self> {
        match StageBTraceEvidence::from_trace(trace) {
            Some(trace) => Some(Self {
                status,
                latency_ms_u32,
                retry,
                trace,
            }),
            None => None,
        }
    }

    /// The content-free status of the action: success or the atom #103 error.
    #[inline]
    pub const fn status(&self) -> Option<WalrusClientError> {
        self.status
    }

    /// The content-free status label: [`STATUS_OK_LABEL`] on success, else the
    /// atom #103 [`WalrusClientError::class_label`] (`walrus.*`). Safe to emit in
    /// place of any captured host/body/error text.
    #[inline]
    pub const fn status_label(&self) -> &'static str {
        match self.status {
            None => STATUS_OK_LABEL,
            Some(err) => err.class_label(),
        }
    }

    /// The measured action latency in milliseconds (a count only).
    #[inline]
    pub const fn latency_ms_u32(&self) -> u32 {
        self.latency_ms_u32
    }

    /// The atom #110 retry decision for the action.
    #[inline]
    pub const fn retry(&self) -> WalrusRetry {
        self.retry
    }

    /// The bound atom #94 content-free trace evidence.
    #[inline]
    pub const fn trace_evidence(&self) -> StageBTraceEvidence {
        self.trace
    }

    /// Render this record as a redacted JSON object.
    ///
    /// Every key is a member of [`DIAGNOSTIC_KEYS`] and every value is a fixed
    /// ASCII class label or an integer, so the output is content-free by
    /// construction — there is no key or value through which a payload body,
    /// owner, host, or provider string could appear. The labels contain only
    /// `[a-z0-9._]` and the integers are plain decimals, so no JSON escaping is
    /// needed; the object is emitted directly.
    #[inline]
    pub fn to_redacted_json(&self) -> String {
        let (trace_id, atom_id, attempt) = self.trace.evidence_ids();
        format!(
            "{{\"status\":\"{status}\",\"latency_ms\":{latency},\"retry\":\"{retry}\",\
             \"trace\":{{\"trace_id\":{trace_id},\"atom_id\":{atom_id},\"attempt\":{attempt}}}}}",
            status = self.status_label(),
            latency = self.latency_ms_u32,
            retry = self.retry.class_label(),
            trace_id = trace_id,
            atom_id = atom_id,
            attempt = attempt,
        )
    }
}

#[cfg(test)]
mod tests {
    // Test helpers prefer direct failure surfaces over `Result`-bubbling;
    // suppress prod-only clippy denies inside this module (b-memory
    // #94/#109/#110 precedent).
    #![allow(clippy::unwrap_used)]
    #![allow(clippy::expect_used)]
    #![allow(clippy::panic)]

    use super::*;

    /// Extract every JSON object key (a `"…"` token immediately followed by `:`)
    /// from `json`. Used by the allowlist test; deliberately minimal (the
    /// rendered objects contain only ASCII labels and decimals, never a `:`
    /// inside a value), so a `"x":` slice unambiguously marks a key.
    fn json_keys(json: &str) -> Vec<String> {
        let bytes = json.as_bytes();
        let mut keys = Vec::new();
        let mut i = 0;
        while i < bytes.len() {
            if bytes[i] == b'"' {
                // Find the closing quote of this token.
                let start = i + 1;
                let mut j = start;
                while j < bytes.len() && bytes[j] != b'"' {
                    j += 1;
                }
                // A key is a quoted token whose next non-space char is ':'.
                let mut k = j + 1;
                while k < bytes.len() && bytes[k] == b' ' {
                    k += 1;
                }
                if k < bytes.len() && bytes[k] == b':' {
                    keys.push(json[start..j].to_string());
                }
                i = j + 1;
            } else {
                i += 1;
            }
        }
        keys
    }

    /// `canary payload not logged` — the diagnostics for a *failed PUT of a
    /// distinctive payload* carry only content-free status/latency/retry/trace;
    /// the payload body appears in neither the JSON nor the `Debug` projection.
    ///
    /// Falsifiable: the payload is a real `&[u8]` in scope at the construction
    /// site, yet [`record`](WalrusDiagnostics::record) offers no parameter to
    /// pass a body — a field that captured it would surface "CANARY" here and
    /// fail the assertions.
    #[test]
    fn b2_11_canary_payload_not_logged() {
        let payload: &[u8] = b"CANARY-PRIVATE-MEMORY-BODY-0xDEADBEEF-never-log-me";
        let canary = core::str::from_utf8(payload).expect("ascii canary");

        // Diagnostics for a failed PUT of `payload`: only the content-free
        // dimensions are recorded — the body cannot be passed in at all.
        let trace = StageBTraceLink::new(0x00C0_FFEE, 112, 1);
        let diag = WalrusDiagnostics::record(
            Some(WalrusClientError::Protocol),
            134,
            WalrusRetry::ManualReconcile,
            trace,
        )
        .expect("an atom-stamped trace records");

        let json = diag.to_redacted_json();
        let dbg = format!("{diag:?}");

        assert!(
            !json.contains(canary) && !json.contains("CANARY"),
            "the payload body must never appear in the diagnostics JSON: {json}"
        );
        assert!(
            !dbg.contains(canary) && !dbg.contains("CANARY"),
            "the payload body must never appear in the diagnostics Debug: {dbg}"
        );
        // The recorded status is the content-free class, not the payload.
        assert_eq!(diag.status_label(), "walrus.protocol");
    }

    /// `JSON allowlist keys only` — every key the rendered object emits is a
    /// member of [`DIAGNOSTIC_KEYS`], and the top-level shape is exactly the four
    /// admitted diagnostic dimensions. A field that widened the surface beyond
    /// the allowlist would fail here.
    #[test]
    fn b2_11_json_allowlist_keys_only() {
        let trace = StageBTraceLink::new(7, 112, 0);
        let diag = WalrusDiagnostics::record(None, 42, WalrusRetry::BeforeBoundaryOnly, trace)
            .expect("stamped trace records");
        let json = diag.to_redacted_json();

        let keys = json_keys(&json);
        assert!(!keys.is_empty(), "the object must have keys: {json}");
        for key in &keys {
            assert!(
                DIAGNOSTIC_KEYS.contains(&key.as_str()),
                "key {key:?} is not in the redaction allowlist {DIAGNOSTIC_KEYS:?}: {json}"
            );
        }

        // The top-level keys are exactly the four admitted dimensions (the nested
        // trace object then contributes trace_id/atom_id/attempt).
        assert!(json.contains("\"status\":"));
        assert!(json.contains("\"latency_ms\":"));
        assert!(json.contains("\"retry\":"));
        assert!(json.contains("\"trace\":{"));
        // Exact rendered shape (content-free values only).
        assert_eq!(
            json,
            "{\"status\":\"walrus.ok\",\"latency_ms\":42,\
             \"retry\":\"walrus.retry.before_boundary_only\",\
             \"trace\":{\"trace_id\":7,\"atom_id\":112,\"attempt\":0}}"
        );
    }

    /// `trace required (fail-closed)` — the G-B-TRACE invariant: a record cannot
    /// be built for the missing/unstamped sentinel (`atom_id_u16 == 0`); a real
    /// atom-stamped trace records.
    #[test]
    fn b2_11_trace_required_fail_closed() {
        // Missing/unstamped (atom #0 RESET) — fail-closed to None.
        let unstamped = StageBTraceLink::new(123, 0, 0);
        assert!(
            WalrusDiagnostics::record(None, 1, WalrusRetry::BeforeBoundaryOnly, unstamped)
                .is_none(),
            "an unstamped (atom_id_u16 == 0) action mints no diagnostics record"
        );

        // A non-zero trace id but atom_id == 0 is still missing.
        let no_atom = StageBTraceLink::new(0xABCD, 0, 2);
        assert!(
            WalrusDiagnostics::record(
                Some(WalrusClientError::Transport),
                9,
                WalrusRetry::ManualReconcile,
                no_atom
            )
            .is_none(),
            "atom_id == 0 is the missing sentinel regardless of trace id"
        );

        // A real atom-stamped trace records, and the evidence ids round-trip.
        let stamped = StageBTraceLink::new(0xDEAD_BEEF, 112, 3);
        let diag = WalrusDiagnostics::record(None, 5, WalrusRetry::BeforeBoundaryOnly, stamped)
            .expect("a stamped trace records");
        assert_eq!(diag.trace_evidence().evidence_ids(), (0xDEAD_BEEF, 112, 3));
    }

    /// `status success and error labels` — `None` projects to the success label;
    /// `Some(err)` projects to the atom #103 namespaced class label.
    #[test]
    fn b2_11_status_success_and_error_labels() {
        let trace = StageBTraceLink::new(1, 112, 0);

        let ok = WalrusDiagnostics::record(None, 0, WalrusRetry::BeforeBoundaryOnly, trace)
            .expect("records");
        assert_eq!(ok.status(), None);
        assert_eq!(ok.status_label(), STATUS_OK_LABEL);
        assert_eq!(ok.status_label(), "walrus.ok");

        let err = WalrusDiagnostics::record(
            Some(WalrusClientError::BoundaryUnknown),
            0,
            WalrusRetry::ManualReconcile,
            trace,
        )
        .expect("records");
        assert_eq!(err.status(), Some(WalrusClientError::BoundaryUnknown));
        assert_eq!(err.status_label(), "walrus.boundary_unknown");
    }

    /// `retry and latency preserved` — the retry decision and latency count are
    /// carried verbatim, and the record is `Copy` (owns no heap body).
    #[test]
    fn b2_11_retry_and_latency_preserved() {
        let trace = StageBTraceLink::new(99, 112, 4);
        let diag = WalrusDiagnostics::record(
            Some(WalrusClientError::OversizedBody),
            u32::MAX,
            WalrusRetry::Never,
            trace,
        )
        .expect("records");

        assert_eq!(diag.latency_ms_u32(), u32::MAX, "latency carried verbatim");
        assert_eq!(diag.retry(), WalrusRetry::Never, "retry carried verbatim");

        // The record is Copy — it owns no heap body.
        let copied: WalrusDiagnostics = diag;
        assert_eq!(copied, diag);

        // The retry label is the content-free atom #110 class label.
        assert_eq!(diag.retry().class_label(), "walrus.retry.never");
    }
}
