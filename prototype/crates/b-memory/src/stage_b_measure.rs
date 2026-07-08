//! Trace telemetry for Walrus testnet actions — the
//! Stage B **content-free** measure/telemetry record emitted for a Walrus
//! testnet action so the action's cost is bound to the atom that produced it.
//!
//! This module mints the canonical type: [`StageBWalrusMeasure`] — a
//! per-action measure record that pairs the Walrus action *kind*
//! ([`WalrusActionKind`]) with the content-free [`WalrusDiagnostics`].
//! It falls in the category of evidence types Stage B may mint by composing
//! earlier canonical types — it introduces
//! no new wire, no new error type, no new id/address newtype, and no
//! dependency. A measure record can be emitted to an a-core log / metrics line
//! ([`to_evidence_jsonl`](StageBWalrusMeasure::to_evidence_jsonl)) without any
//! byte of user memory leaving the machine, and it is usable by a later Stage E
//! reward/eval pass — but it carries **no reward label yet**.
//!
//! # Invariant
//!
//! > Walrus actions produce trace/measure evidence usable by later Stage E, but
//! > no reward label yet.
//!
//! * **Trace/measure evidence, never the payload.** A measure record holds only
//!   the action [`kind`](Self::action) and the [`WalrusDiagnostics`]
//!   (status / latency / retry / trace) — there is **no** `Vec<u8>` / `&[u8]`
//!   body field, no payload field, no owner
//!   [`SuiAddress`](mnemos_d_move::SuiAddress), no URL/host, and not even a
//!   transferred length. A payload body is therefore not expressible in this
//!   schema; "no payload body" is enforced by the type, not by a runtime
//!   redaction pass (the `b2_17_no_payload_body` proof, mirroring the
//!   `b2_11_canary_payload_not_logged` seam).
//!
//! * **Trace id linked (fail-closed).** [`record`](Self::record) composes the
//!   [`WalrusDiagnostics::record`], whose only constructor path runs
//!   through the [`StageBTraceEvidence::from_trace`] fail-closed gate:
//!   the missing/unstamped sentinel (`atom_id_u16 == 0`) returns `None`. So a
//!   Walrus action not bound to a real atom mints **no** measure record (the
//!   trace-link invariant enforced at the type level — the `b2_17_trace_id_linked`
//!   proof). The emitted evidence carries the same atom number the memory side
//!   stamped, so memory and measurement are never separated (an executable invariant).
//!
//! * **Action kind is a content-free class tag.** [`WalrusActionKind`] has
//!   exactly three variants — [`Put`](WalrusActionKind::Put),
//!   [`Get`](WalrusActionKind::Get), [`Verify`](WalrusActionKind::Verify) — each
//!   projecting to a namespaced `walrus.action.*`
//!   [`class_label`](WalrusActionKind::class_label) drawn from `[a-z0-9._]`. The
//!   fourth telemetry dimension — *failure* — is **not** a separate
//!   action kind: it is carried by the reused `status`
//!   ([`Option<WalrusClientError>`](crate::stage_b_put::WalrusClientError)), so
//!   success-vs-failure has a single source of truth and a failed action is
//!   `action = put|get|verify` *and* `status = walrus.<error>` (the
//!   `b2_17_failure_via_status` proof).
//!
//! * **No reward label yet.** The record has **no** reward field — a reward
//!   scalar/label is structurally not expressible here. The evidence line emits a
//!   fixed `"reward_label":null` and
//!   [`reward_label_assigned`](Self::reward_label_assigned) is always `false`; a
//!   later Stage E pass is the consumer that assigns the real label. This is the
//!   `EvidenceBundleManifestV1` `training_eligibility=false` discipline applied at
//!   the per-action grain (the `b2_17_reward_label_absent` proof).
//!
//! * **JSON allowlist keys only.** [`to_evidence_jsonl`](Self::to_evidence_jsonl)
//!   emits a fixed-shape object whose every key is drawn from [`MEASURE_KEYS`];
//!   every value is a fixed ASCII class label, an integer, or the literal `null`,
//!   so no user string can ever appear (the `b2_17_event_shape` proof). This is
//!   the logging/redaction + metrics reuse applied as a
//!   **discipline** — `mnemos-b-memory` carries no `mnemos-a-core` dependency, so
//!   the redaction-by-construction + allowlist pattern (an established deferral
//!   precedent) is reused rather than the a-core logging/metrics kernel imported.
//!   Adding an a-core edge here would step outside the reuse contract and into a
//!   later integration stage's scope.
//!
//! # Reuse (zero reinvention)
//!
//! * [`WalrusDiagnostics`](crate::stage_b_diag::WalrusDiagnostics) — the
//!   content-free status/latency/retry/trace record, composed verbatim and given
//!   its first consumer here. No status/latency/retry/trace logic is reinvented.
//! * [`StageBTraceEvidence`](crate::trace_link::StageBTraceEvidence) —
//!   reached transitively through `WalrusDiagnostics::record`; its fail-closed
//!   `from_trace` is what makes an unstamped action mint no record.
//! * [`StageBTraceLink`](crate::stage_b_handoff::StageBTraceLink) — the
//!   `(trace_id, atom_id, attempt)` stamp the diagnostics binds; no second stamp
//!   type is minted.
//! * [`WalrusClientError`](crate::stage_b_put::WalrusClientError) /
//!   [`WalrusRetry`](crate::stage_b_retry::WalrusRetry) — their content-free
//!   `class_label`s are read through the diagnostics; the frozen
//!   `#[non_exhaustive]` error set is not widened.
//!
//! No new dependency, no new wire format, no new error type, no network.

use crate::stage_b_diag::WalrusDiagnostics;
use crate::stage_b_handoff::StageBTraceLink;
use crate::stage_b_put::WalrusClientError;
use crate::stage_b_retry::WalrusRetry;

/// The complete, closed set of JSON keys
/// [`StageBWalrusMeasure::to_evidence_jsonl`] may emit — the measure-evidence
/// allowlist.
///
/// Every key in the rendered object is one of these nine; there is no key
/// through which a payload body, owner address, host, or provider text could be
/// emitted. The `b2_17_event_shape` test scans the rendered JSONL and asserts
/// each key it finds is a member of this slice, so a future field that widened
/// the surface would fail the gate. The first five are top-level; the final
/// three are the nested `trace` object's ids.
pub const MEASURE_KEYS: &[&str] = &[
    "action",
    "status",
    "latency_ms",
    "retry",
    "reward_label",
    "trace",
    "trace_id",
    "atom_id",
    "attempt",
];

/// The kind of Walrus testnet action a measure record describes.
///
/// Content-free by construction: each variant is a plain tag carrying no host,
/// body, or provider text. Three variants only — *failure* is the reused
/// `status` dimension, not a fourth action kind, so success-vs-failure has a
/// single source of truth.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum WalrusActionKind {
    /// A blob PUT to the Walrus testnet publisher.
    Put,
    /// A blob GET from the Walrus testnet aggregator.
    Get,
    /// A local blob-id verify over GET-returned bytes (server-not-oracle).
    Verify,
}

impl WalrusActionKind {
    /// The content-free namespaced class label for this action kind
    /// (`walrus.action.*`), drawn from `[a-z0-9._]`. Safe to emit in place of any
    /// captured host/endpoint/provider string.
    #[inline]
    pub const fn class_label(self) -> &'static str {
        match self {
            WalrusActionKind::Put => "walrus.action.put",
            WalrusActionKind::Get => "walrus.action.get",
            WalrusActionKind::Verify => "walrus.action.verify",
        }
    }
}

/// Content-free measure/telemetry for a single Walrus testnet action.
///
/// The canonical measure type. It records **only** the action
/// [`kind`](Self::action) and the [`WalrusDiagnostics`] — and
/// deliberately nothing else. There is no field that could hold the chunk body,
/// the payload, the owner address, any provider text, or a reward label, so the
/// record is redaction-safe by construction, reward-unlabeled by construction,
/// and `Copy`.
///
/// Construct it via [`record`](Self::record), which is fail-closed on the
/// missing/unstamped trace sentinel (`atom_id_u16 == 0`) through the composed
/// constructor.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub struct StageBWalrusMeasure {
    /// The kind of Walrus action this record measures.
    action: WalrusActionKind,
    /// The content-free diagnostics: status / latency / retry / trace.
    /// Holds no body; carries the fail-closed trace evidence.
    diag: WalrusDiagnostics,
}

impl StageBWalrusMeasure {
    /// Record measure/telemetry for a Walrus action, fail-closed on an unstamped
    /// trace.
    ///
    /// `action` is the content-free [`WalrusActionKind`]; `status` is `None` for
    /// success or `Some(e)` for the content-free error class (this is
    /// how a *failure* is recorded — there is no `Failure` action kind);
    /// `latency_ms_u32` is the measured cost; `retry` is the retry decision;
    /// `trace` is the per-action stamp.
    ///
    /// Returns `None` if `trace` is the missing/unstamped sentinel
    /// (`atom_id_u16 == 0`) — a Walrus action not bound to a real atom mints no
    /// measure record (the trace-link invariant, reusing the
    /// [`WalrusDiagnostics::record`] fail-closed path).
    #[inline]
    pub const fn record(
        action: WalrusActionKind,
        status: Option<WalrusClientError>,
        latency_ms_u32: u32,
        retry: WalrusRetry,
        trace: StageBTraceLink,
    ) -> Option<Self> {
        match WalrusDiagnostics::record(status, latency_ms_u32, retry, trace) {
            Some(diag) => Some(Self { action, diag }),
            None => None,
        }
    }

    /// The kind of Walrus action this record measures.
    #[inline]
    pub const fn action(&self) -> WalrusActionKind {
        self.action
    }

    /// The composed content-free diagnostics (status/latency/retry/trace).
    #[inline]
    pub const fn diagnostics(&self) -> WalrusDiagnostics {
        self.diag
    }

    /// Whether a Stage E reward label has been assigned to this record.
    ///
    /// Always `false` at Stage B: a measure record has no reward field, so a
    /// label is structurally not expressible here. A later Stage E reward/eval
    /// pass is the consumer that assigns one ("no reward label yet").
    #[inline]
    pub const fn reward_label_assigned(&self) -> bool {
        false
    }

    /// Render this record as a single redacted measure-evidence JSONL line.
    ///
    /// Every key is a member of [`MEASURE_KEYS`] and every value is a fixed ASCII
    /// class label, an integer, or the literal `null` (`reward_label`), so the
    /// output is content-free by construction — there is no key or value through
    /// which a payload body, owner, host, provider string, or reward scalar could
    /// appear. The labels contain only `[a-z0-9._]` and the integers are plain
    /// decimals, so no JSON escaping is needed; the object is emitted directly.
    #[inline]
    pub fn to_evidence_jsonl(&self) -> String {
        let (trace_id, atom_id, attempt) = self.diag.trace_evidence().evidence_ids();
        format!(
            "{{\"action\":\"{action}\",\"status\":\"{status}\",\"latency_ms\":{latency},\
             \"retry\":\"{retry}\",\"reward_label\":null,\
             \"trace\":{{\"trace_id\":{trace_id},\"atom_id\":{atom_id},\"attempt\":{attempt}}}}}",
            action = self.action.class_label(),
            status = self.diag.status_label(),
            latency = self.diag.latency_ms_u32(),
            retry = self.diag.retry().class_label(),
            trace_id = trace_id,
            atom_id = atom_id,
            attempt = attempt,
        )
    }
}

#[cfg(test)]
mod tests {
    // Test helpers prefer direct failure surfaces over `Result`-bubbling;
    // suppress prod-only clippy denies inside this module (an established
    // b-memory precedent).
    #![allow(clippy::unwrap_used)]
    #![allow(clippy::expect_used)]
    #![allow(clippy::panic)]

    use super::*;

    /// Extract every JSON object key (a `"…"` token immediately followed by `:`)
    /// from `json`. Mirrors the allowlist helper; deliberately minimal
    /// (the rendered objects contain only ASCII labels, decimals, and `null`,
    /// never a `:` inside a value), so a `"x":` slice unambiguously marks a key.
    fn json_keys(json: &str) -> Vec<String> {
        let bytes = json.as_bytes();
        let mut keys = Vec::new();
        let mut i = 0;
        while i < bytes.len() {
            if bytes[i] == b'"' {
                let start = i + 1;
                let mut j = start;
                while j < bytes.len() && bytes[j] != b'"' {
                    j += 1;
                }
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

    /// `event shape` — the rendered measure-evidence line has the exact, fixed
    /// shape for a PUT action, every key is a member of [`MEASURE_KEYS`], and the
    /// top-level dimensions are exactly action/status/latency_ms/retry/
    /// reward_label/trace. A field that widened the surface beyond the allowlist
    /// would fail here.
    #[test]
    fn b2_17_event_shape() {
        let trace = StageBTraceLink::new(7, 118, 0);
        let measure =
            StageBWalrusMeasure::record(WalrusActionKind::Put, None, 42, WalrusRetry::Never, trace)
                .expect("a stamped trace records");
        let json = measure.to_evidence_jsonl();

        let keys = json_keys(&json);
        assert!(!keys.is_empty(), "the object must have keys: {json}");
        for key in &keys {
            assert!(
                MEASURE_KEYS.contains(&key.as_str()),
                "key {key:?} is not in the measure allowlist {MEASURE_KEYS:?}: {json}"
            );
        }

        // The top-level keys are exactly the five admitted dimensions (the nested
        // trace object then contributes trace_id/atom_id/attempt).
        assert!(json.contains("\"action\":"));
        assert!(json.contains("\"status\":"));
        assert!(json.contains("\"latency_ms\":"));
        assert!(json.contains("\"retry\":"));
        assert!(json.contains("\"reward_label\":"));
        assert!(json.contains("\"trace\":{"));

        // Exact rendered shape (content-free values only; reward_label is null).
        assert_eq!(
            json,
            "{\"action\":\"walrus.action.put\",\"status\":\"walrus.ok\",\"latency_ms\":42,\
             \"retry\":\"walrus.retry.never\",\"reward_label\":null,\
             \"trace\":{\"trace_id\":7,\"atom_id\":118,\"attempt\":0}}"
        );
    }

    /// `no payload body` — the measure for a *failed PUT of a distinctive
    /// payload* carries only content-free action/status/latency/retry/trace; the
    /// payload body appears in neither the JSONL nor the `Debug` projection.
    ///
    /// Falsifiable: the payload is a real `&[u8]` in scope at the construction
    /// site, yet [`record`](StageBWalrusMeasure::record) offers no parameter to
    /// pass a body — a field that captured it would surface "CANARY" here and
    /// fail the assertions.
    #[test]
    fn b2_17_no_payload_body() {
        let payload: &[u8] = b"CANARY-PRIVATE-MEMORY-BODY-0xDEADBEEF-never-measure-me";
        let canary = core::str::from_utf8(payload).expect("ascii canary");

        let trace = StageBTraceLink::new(0x00C0_FFEE, 118, 1);
        let measure = StageBWalrusMeasure::record(
            WalrusActionKind::Put,
            Some(WalrusClientError::Protocol),
            134,
            WalrusRetry::ManualReconcile,
            trace,
        )
        .expect("an atom-stamped trace records");

        let json = measure.to_evidence_jsonl();
        let dbg = format!("{measure:?}");

        assert!(
            !json.contains(canary) && !json.contains("CANARY"),
            "the payload body must never appear in the measure JSONL: {json}"
        );
        assert!(
            !dbg.contains(canary) && !dbg.contains("CANARY"),
            "the payload body must never appear in the measure Debug: {dbg}"
        );
        // The record is Copy — it owns no heap body.
        let copied: StageBWalrusMeasure = measure;
        assert_eq!(copied, measure);
    }

    /// `trace id linked` — the trace-link invariant: a measure record cannot be
    /// built for the missing/unstamped sentinel (`atom_id_u16 == 0`); a real
    /// atom-stamped trace records and the emitted evidence reports the same atom
    /// number the memory side stamped (memory and measurement never separated).
    #[test]
    fn b2_17_trace_id_linked() {
        // Missing/unstamped (atom_id 0 sentinel) — fail-closed to None.
        let unstamped = StageBTraceLink::new(123, 0, 0);
        assert!(
            StageBWalrusMeasure::record(
                WalrusActionKind::Get,
                None,
                1,
                WalrusRetry::BeforeBoundaryOnly,
                unstamped
            )
            .is_none(),
            "an unstamped (atom_id_u16 == 0) action mints no measure record"
        );

        // A non-zero trace id but atom_id == 0 is still missing.
        let no_atom = StageBTraceLink::new(0xABCD, 0, 2);
        assert!(
            StageBWalrusMeasure::record(
                WalrusActionKind::Verify,
                Some(WalrusClientError::Transport),
                9,
                WalrusRetry::ManualReconcile,
                no_atom
            )
            .is_none(),
            "atom_id == 0 is the missing sentinel regardless of trace id"
        );

        // A real atom-stamped trace records; the trace ids round-trip and the
        // emitted line carries the same atom number.
        let stamped = StageBTraceLink::new(0xDEAD_BEEF, 118, 3);
        let measure = StageBWalrusMeasure::record(
            WalrusActionKind::Verify,
            None,
            5,
            WalrusRetry::BeforeBoundaryOnly,
            stamped,
        )
        .expect("a stamped trace records");
        assert_eq!(
            measure.diagnostics().trace_evidence().evidence_ids(),
            (0xDEAD_BEEF, 118, 3)
        );
        let json = measure.to_evidence_jsonl();
        assert!(
            json.contains("\"atom_id\":118"),
            "the measure line must carry the stamped atom number: {json}"
        );
    }

    /// `action labels cover put/get/verify` — the three action kinds project to
    /// distinct namespaced `walrus.action.*` labels, and each is the value of the
    /// `action` key in the emitted line.
    #[test]
    fn b2_17_action_labels_put_get_verify() {
        assert_eq!(WalrusActionKind::Put.class_label(), "walrus.action.put");
        assert_eq!(WalrusActionKind::Get.class_label(), "walrus.action.get");
        assert_eq!(
            WalrusActionKind::Verify.class_label(),
            "walrus.action.verify"
        );

        let trace = StageBTraceLink::new(1, 118, 0);
        for (kind, label) in [
            (WalrusActionKind::Put, "walrus.action.put"),
            (WalrusActionKind::Get, "walrus.action.get"),
            (WalrusActionKind::Verify, "walrus.action.verify"),
        ] {
            let json = StageBWalrusMeasure::record(kind, None, 0, WalrusRetry::Never, trace)
                .expect("records")
                .to_evidence_jsonl();
            assert!(
                json.contains(&format!("\"action\":\"{label}\"")),
                "action {kind:?} must emit label {label}: {json}"
            );
        }
    }

    /// `reward label absent` — every emitted measure line carries a fixed
    /// `"reward_label":null` (no reward scalar/label is expressible at Stage B),
    /// and [`reward_label_assigned`](StageBWalrusMeasure::reward_label_assigned)
    /// is always `false`. A later Stage E pass assigns the real label.
    #[test]
    fn b2_17_reward_label_absent() {
        let trace = StageBTraceLink::new(99, 118, 4);
        for kind in [
            WalrusActionKind::Put,
            WalrusActionKind::Get,
            WalrusActionKind::Verify,
        ] {
            let measure = StageBWalrusMeasure::record(
                kind,
                Some(WalrusClientError::OversizedBody),
                u32::MAX,
                WalrusRetry::Never,
                trace,
            )
            .expect("records");

            assert!(
                !measure.reward_label_assigned(),
                "no reward label is assigned at Stage B"
            );

            let json = measure.to_evidence_jsonl();
            assert!(
                json.contains("\"reward_label\":null"),
                "the measure line must mark the reward label absent (null): {json}"
            );
            // No numeric reward scalar leaked into the line.
            assert!(
                !json.contains("\"reward\":") && !json.contains("\"scalar\":"),
                "no reward scalar may appear in the measure line: {json}"
            );
        }
    }

    /// `failure via status` — a failed action is NOT a separate action kind: it
    /// is `action = put|get|verify` *and* `status = walrus.<error>`. The
    /// emitted line carries both, so the put/get/verify/**failure**
    /// telemetry is covered without a `Failure` variant.
    #[test]
    fn b2_17_failure_via_status() {
        let trace = StageBTraceLink::new(0xFEED, 118, 2);
        let measure = StageBWalrusMeasure::record(
            WalrusActionKind::Get,
            Some(WalrusClientError::Protocol),
            77,
            WalrusRetry::ManualReconcile,
            trace,
        )
        .expect("records");

        // Action kind is preserved; failure rides on the status dimension.
        assert_eq!(measure.action(), WalrusActionKind::Get);
        assert_eq!(
            measure.diagnostics().status(),
            Some(WalrusClientError::Protocol)
        );
        assert_eq!(measure.diagnostics().status_label(), "walrus.protocol");

        let json = measure.to_evidence_jsonl();
        assert!(json.contains("\"action\":\"walrus.action.get\""), "{json}");
        assert!(json.contains("\"status\":\"walrus.protocol\""), "{json}");
    }
}
