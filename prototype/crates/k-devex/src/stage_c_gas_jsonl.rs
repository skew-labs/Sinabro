//! Gas/effect trace JSONL line builder.
//!
//! The append-only JSONL record shape for gas + effect samples,
//! mirrored by the JSON Schema `ops/schemas/stage_c_gas_trace.schema.json`.
//!
//! # Invariants
//!
//! * **No raw payload body, no secret labels.** The line is built only from a
//!   typed [`GasTraceSample`] and [`EffectDelta`] — both
//!   are scalar / 32-byte-id records with no body field. Any free-text note must
//!   arrive as a [`RedactedLogValue`] (via `redact_for_log`), which dropped
//!   its raw value at the call site; only its redaction *class label* is
//!   emitted. There is no channel through which a raw body or secret can reach
//!   the JSONL.
//! * **Allowlist-only keys.** Every key the builder emits is in
//!   [`STAGE_C_GAS_TRACE_KEYS`]; the JSON Schema sets `additionalProperties:
//!   false`, so an unknown field is rejected by a validator.
//! * **Append-only and versioned.** The record carries an explicit
//!   [`STAGE_C_GAS_TRACE_SCHEMA`] version so later revisions can evolve the schema
//!   additively without breaking earlier lines.

use core::fmt::Write;
use mnemos_a_core::RedactedLogValue;
use mnemos_d_move::ObjectId;
use mnemos_d_move::stage_c_effect_delta::EffectDelta;
use mnemos_d_move::stage_c_gas_trace::GasTraceSample;

/// The append-only schema id stamped on every gas-trace JSONL record.
pub const STAGE_C_GAS_TRACE_SCHEMA: &str = "mnemos.stage_c.gas_trace.v1";

/// The complete allowlist of JSON keys a gas-trace record may contain. The JSON
/// Schema pins `additionalProperties: false` to the same set.
pub const STAGE_C_GAS_TRACE_KEYS: &[&str] = &[
    "schema",
    "event",
    "function_u8",
    "package_hex",
    "gas_budget_mist",
    "computation_mist",
    "storage_mist",
    "rebate_mist",
    "object_writes",
    "event_count",
    "event_bytes",
    "net_storage_mist",
    "tx_bytes",
    "trace_id_u64",
    "atom_id_u16",
    "attempt_u8",
    "stage_c_atom_u16",
    "gate_id_u16",
    "note_class",
];

/// Lower-case hex of a 32-byte package id (64 chars, no `0x` prefix).
fn hex32(bytes: &[u8; 32]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(64);
    for &b in bytes {
        s.push(HEX[(b >> 4) as usize] as char);
        s.push(HEX[(b & 0x0f) as usize] as char);
    }
    s
}

/// Build one append-only gas/effect trace JSONL line from a gas sample, its
/// effect-shape delta, and a redacted note.
///
/// The gas fields (`function`, `package`, `gas_budget`, MIST split,
/// `object_writes`, `event_bytes`, `tx_bytes`, trace) come from `sample`; the
/// richer effect-shape fields (`event_count`, `net_storage_mist`) come from
/// `delta`. The `note` contributes only its redaction class label
/// (`note_class`) — never a raw value.
pub fn build_gas_trace_line(
    sample: &GasTraceSample,
    delta: &EffectDelta,
    note: RedactedLogValue,
) -> String {
    let package: &ObjectId = &sample.package;
    let mut s = String::with_capacity(512);
    // `write!` into a String is infallible; mirror a-core logging by discarding
    // the formatter Result rather than unwrapping.
    let _ = write!(
        s,
        concat!(
            "{{\"schema\":\"{schema}\",\"event\":\"gas_trace\",",
            "\"function_u8\":{function_u8},\"package_hex\":\"{package_hex}\",",
            "\"gas_budget_mist\":{gas_budget_mist},\"computation_mist\":{computation_mist},",
            "\"storage_mist\":{storage_mist},\"rebate_mist\":{rebate_mist},",
            "\"object_writes\":{object_writes},\"event_count\":{event_count},",
            "\"event_bytes\":{event_bytes},\"net_storage_mist\":{net_storage_mist},",
            "\"tx_bytes\":{tx_bytes},\"trace_id_u64\":{trace_id_u64},",
            "\"atom_id_u16\":{atom_id_u16},\"attempt_u8\":{attempt_u8},",
            "\"stage_c_atom_u16\":{stage_c_atom_u16},\"gate_id_u16\":{gate_id_u16},",
            "\"note_class\":\"{note_class}\"}}"
        ),
        schema = STAGE_C_GAS_TRACE_SCHEMA,
        function_u8 = sample.function.as_u8(),
        package_hex = hex32(package.as_bytes()),
        gas_budget_mist = sample.gas_budget.get(),
        computation_mist = sample.computation_mist_u64,
        storage_mist = sample.storage_mist_u64,
        rebate_mist = sample.rebate_mist_u64,
        object_writes = sample.object_writes_u16,
        event_count = delta.event_count_u16,
        event_bytes = sample.event_bytes_u32,
        net_storage_mist = delta.net_storage_mist(),
        tx_bytes = sample.tx_bytes_u32,
        trace_id_u64 = sample.trace.trace.trace_id_u64,
        atom_id_u16 = sample.trace.trace.atom_id_u16,
        attempt_u8 = sample.trace.trace.attempt_u8,
        stage_c_atom_u16 = sample.trace.stage_c_atom_u16,
        gate_id_u16 = sample.trace.gate_id_u16,
        note_class = note.kind().class_label(),
    );
    s
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]
    use super::*;
    use mnemos_a_core::trace::{StageBTraceLink, StageCTraceLink};
    use mnemos_a_core::{LogRedactionKind, redact_for_log};
    use mnemos_d_move::stage_c_gas_trace::GasTraceFunction;
    use mnemos_d_move::types::{GasBudgetMist, ObjectId};

    fn sample() -> GasTraceSample {
        GasTraceSample {
            function: GasTraceFunction::MemoryAddChunk,
            package: ObjectId::new([0xAB; 32]),
            gas_budget: GasBudgetMist::new(1_000_000),
            computation_mist_u64: 400_000,
            storage_mist_u64: 150_000,
            rebate_mist_u64: 20_000,
            object_writes_u16: 2,
            event_bytes_u32: 96,
            tx_bytes_u32: 768,
            trace: StageCTraceLink::new(StageBTraceLink::new(0xA186, 186, 0), 186, 5),
        }
    }

    fn delta() -> EffectDelta {
        EffectDelta::from_dev_inspect(true, 2, 1, 96, 150_000, 20_000).unwrap()
    }

    /// Walk the JSON object and collect the keys (quote-aware so a `:` inside a
    /// string value is never mistaken for a key delimiter).
    fn object_keys(s: &str) -> Vec<String> {
        let bytes = s.as_bytes();
        let mut keys = Vec::new();
        let mut i = 0usize;
        while i < bytes.len() {
            if bytes[i] == b'"' {
                // read the quoted token
                let start = i + 1;
                let mut j = start;
                while j < bytes.len() && bytes[j] != b'"' {
                    j += 1;
                }
                let token = &s[start..j];
                // skip whitespace after the closing quote
                let mut k = j + 1;
                while k < bytes.len() && (bytes[k] == b' ' || bytes[k] == b'\n') {
                    k += 1;
                }
                if k < bytes.len() && bytes[k] == b':' {
                    keys.push(token.to_string());
                }
                i = j + 1;
            } else {
                i += 1;
            }
        }
        keys
    }

    #[test]
    fn schema_line_carries_the_version_and_required_fields() {
        let line = build_gas_trace_line(
            &sample(),
            &delta(),
            redact_for_log("", LogRedactionKind::ProviderBody),
        );
        assert!(line.contains("\"schema\":\"mnemos.stage_c.gas_trace.v1\""));
        assert!(line.contains("\"event\":\"gas_trace\""));
        assert!(line.contains("\"function_u8\":1"));
        assert!(line.contains(
            "\"package_hex\":\"abababababababababababababababababababababababababababababababab\""
        ));
        assert!(line.contains("\"net_storage_mist\":130000"));
        assert!(line.contains("\"stage_c_atom_u16\":186"));
        // one JSON object, one line (JSONL): no embedded newline.
        assert!(!line.contains('\n'));
    }

    #[test]
    fn canary_body_is_absent_only_the_redaction_class_survives() {
        // A note carrying a "secret" raw value is redacted at the call site; the
        // line must contain only the class label, never the raw bytes.
        let secret = "SECRET_TX_BYTES_DEADBEEF_0123456789";
        let line = build_gas_trace_line(
            &sample(),
            &delta(),
            redact_for_log(secret, LogRedactionKind::SuiTxBytes),
        );
        assert!(line.contains("\"note_class\":\"sui_tx_bytes\""));
        assert!(!line.contains("SECRET_TX_BYTES"));
        assert!(!line.contains("DEADBEEF"));
    }

    #[test]
    fn every_emitted_key_is_in_the_allowlist_no_unknown_field() {
        let line = build_gas_trace_line(
            &sample(),
            &delta(),
            redact_for_log("", LogRedactionKind::ProviderBody),
        );
        let keys = object_keys(&line);
        // Every emitted key is allowlisted (no unknown field).
        for k in &keys {
            assert!(
                STAGE_C_GAS_TRACE_KEYS.contains(&k.as_str()),
                "unexpected key: {k}"
            );
        }
        // And the full allowlist is present (no dropped field).
        for expected in STAGE_C_GAS_TRACE_KEYS {
            assert!(
                keys.iter().any(|k| k == expected),
                "missing key: {expected}"
            );
        }
        assert_eq!(keys.len(), STAGE_C_GAS_TRACE_KEYS.len());
    }
}
