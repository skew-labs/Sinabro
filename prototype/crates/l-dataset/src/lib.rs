//! `mnemos-l-dataset` — Stage E AtomDiet dataset builder (Cluster 1: schema +
//! manifest + sidecar parsers, atoms #331-#350 / E-WP-01).
//!
//! # What this crate is
//!
//! Stage E turns the closed 21-file A-D "sidecar" (the Coder's per-atom diet)
//! into a *learnable truth*: a typed [`AtomDietRecord`] per source atom, built
//! only from content-hashed evidence. This crate is **dataset-build-only** — it
//! never trains, never runs LoRA/QLoRA/GRPO/vLLM, never mutates the original
//! A-D sidecars, and never emits a positive reward. It reads
//! `ops/training/{phase_or_stage}/{atom_###,wp_*}/` read-only and produces a
//! derived, hash-pinned model under later `datasets/stage_e/*` outputs.
//!
//! # Madness invariants
//!
//! * **Path is never provenance.** Every [`DietFileRef`] carries a content hash
//!   *and* a path hash; a moved or rewritten evidence file invalidates the
//!   downstream sample.
//! * **Fail-closed.** Unknown file kinds, hash drift, schema downgrade, secret
//!   residue, and privacy inconsistency *reject* rather than silently pass.
//!   Partial records may enter diagnostics but never earn reward.
//! * **No secret echo.** Parser errors ([`DietError`]) carry only fixed scalar
//!   metadata (a file kind, a count, a static field label) — never raw file
//!   bytes — mirroring the `a-core` source-redaction spine.
//! * **No canonical reinvention.** The trace/handoff types below are the §4.0
//!   Stage E registry verbatim; signal/reward/didactic/export types live in
//!   later Stage E WorkPackages (#351+).
#![deny(missing_docs)]

pub mod artifacts;
pub mod atom_record;
pub mod collect;
pub mod command_manifest;
pub mod completeness;
pub mod dedup;
pub mod deny_audit;
pub mod diet_kind;
pub mod diff;
pub mod discover;
pub mod env_lock;
pub mod error;
pub mod export;
pub mod gate_results;
pub mod human;
pub mod interactions;
pub mod korean;
pub mod license_governance;
pub mod manifest;
pub mod murphy;
pub mod privacy;
pub mod privacy_scanner;
pub mod provenance;
pub mod quality;
pub mod redaction_policy;
pub mod reverify;
pub mod reverify_queue;
pub mod review5;
pub mod reward;
pub mod reward_firewall;
pub mod s2_quarantine;
pub mod security;
pub mod self_evolution;
pub mod sidecar_training;
pub mod split;
pub mod stream_split;
pub mod terminal;

pub use atom_record::AtomDietRecord;
pub use diet_kind::{AtomDietKey, DietFileKind, DietSourceStage, FileFormat};
pub use error::{DietError, DietResult};
pub use manifest::{AtomDietManifest, DietCompleteness, DietFileRef};

// ===========================================================================
// §4.0 Handoff + trace (atom #331 · E.0.0)
// ===========================================================================

/// Stage E per-artifact trace stamp (§4.0 canonical registry).
///
/// Unlike the Stage C/D trace links (which *compose* the prior stage's link),
/// the Stage E stamp is self-contained: it carries an opaque source-trace hash
/// (the upstream A-D trace digest), the Stage E atom number, and the gate id
/// that emitted the artifact. It is embedded in every [`AtomDietManifest`].
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub struct StageETraceLink {
    /// Opaque digest of the upstream A-D action trace this record derives from.
    pub source_trace_hash_32: [u8; 32],
    /// Stage E atom number (#331-#400) the artifact belongs to.
    pub stage_e_atom_u16: u16,
    /// Gate-registry id that produced the artifact.
    pub gate_id_u16: u16,
}

impl StageETraceLink {
    /// Construct a Stage E trace stamp from its three components.
    #[inline]
    pub const fn new(
        source_trace_hash_32: [u8; 32],
        stage_e_atom_u16: u16,
        gate_id_u16: u16,
    ) -> Self {
        Self {
            source_trace_hash_32,
            stage_e_atom_u16,
            gate_id_u16,
        }
    }
}

/// Stage E A-D handoff digest (§4.0 canonical registry, atom #331).
///
/// The six `sha256` anchors that Stage E starts from. Stage E may begin only
/// when all six resolve to the named on-disk authority artifacts; a missing or
/// drifted anchor halts the stage (enforced operationally by `check_stage_entry`
/// and recorded as hash evidence in `ops/evidence/stage_e/handoff.md`).
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub struct StageEHandoffDigest {
    /// `sha256(MNEMOS_ATOM_PLAN.md)` — Stage A atom plan.
    pub atom_plan_a_hash_32: [u8; 32],
    /// `sha256(atom/MNEMOS_STAGE_B_ATOM_PLAN.md)`.
    pub stage_b_plan_hash_32: [u8; 32],
    /// `sha256(atom/MNEMOS_STAGE_C_ATOM_PLAN.md)`.
    pub stage_c_plan_hash_32: [u8; 32],
    /// `sha256(atom/MNEMOS_STAGE_D_ATOM_PLAN.md)`.
    pub stage_d_plan_hash_32: [u8; 32],
    /// `sha256(ops/evidence/stage_d/stage_d_dod.md)` — Stage D DoD closure.
    pub stage_d_dod_hash_32: [u8; 32],
    /// `sha256(scripts/check_sidecar_contract.py)` — the 21-file sidecar contract.
    pub sidecar_contract_hash_32: [u8; 32],
}

impl StageEHandoffDigest {
    /// Construct a handoff digest from its six `sha256` anchor hashes.
    #[inline]
    pub const fn new(
        atom_plan_a_hash_32: [u8; 32],
        stage_b_plan_hash_32: [u8; 32],
        stage_c_plan_hash_32: [u8; 32],
        stage_d_plan_hash_32: [u8; 32],
        stage_d_dod_hash_32: [u8; 32],
        sidecar_contract_hash_32: [u8; 32],
    ) -> Self {
        Self {
            atom_plan_a_hash_32,
            stage_b_plan_hash_32,
            stage_c_plan_hash_32,
            stage_d_plan_hash_32,
            stage_d_dod_hash_32,
            sidecar_contract_hash_32,
        }
    }
}

// ===========================================================================
// Crate-root hashing + hex primitives (consumed by manifest / artifacts /
// atom_record / terminal / diff). Kept at the dependency root so no parser
// module owns a cross-parser helper.
// ===========================================================================

/// Compute the `sha256` of `bytes` as a fixed `[u8; 32]`. The on-disk sidecar
/// hash encoding is the 64-hex form of this value (see [`hex32_encode`]).
pub(crate) fn sha256(bytes: &[u8]) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let digest = Sha256::digest(bytes);
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest);
    out
}

/// Stream `reader` through a `sha256` in bounded memory (8 KiB window), never
/// materializing the whole input — used for large logs / diffs / evidence files
/// so a 10 MB artifact hashes in constant memory.
pub(crate) fn sha256_reader<R: std::io::Read>(mut reader: R) -> std::io::Result<[u8; 32]> {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    let mut buf = [0u8; 8192];
    loop {
        let n = reader.read(&mut buf)?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    let digest = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest);
    Ok(out)
}

/// Lower-case hex of a 32-byte hash (64 chars). Used for evidence rendering and
/// for comparing against the sidecar's stored hex strings.
pub fn hex32_encode(hash: &[u8; 32]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(64);
    for &b in hash.iter() {
        s.push(HEX[(b >> 4) as usize] as char);
        s.push(HEX[(b & 0x0f) as usize] as char);
    }
    s
}

/// Parse a 64-char lower/upper-hex string into a `[u8; 32]`. Rejects wrong
/// length and non-hex characters *by position* — the raw string is never
/// echoed into the error.
pub(crate) fn hex32_decode(s: &str) -> DietResult<[u8; 32]> {
    let bytes = s.as_bytes();
    if bytes.len() != 64 {
        return Err(DietError::InvalidHexLength {
            got_u32: bytes.len() as u32,
        });
    }
    let mut out = [0u8; 32];
    let mut i = 0;
    while i < 32 {
        let hi = hex_nibble(bytes[i * 2]).ok_or(DietError::InvalidHexChar {
            at_u32: (i * 2) as u32,
        })?;
        let lo = hex_nibble(bytes[i * 2 + 1]).ok_or(DietError::InvalidHexChar {
            at_u32: (i * 2 + 1) as u32,
        })?;
        out[i] = (hi << 4) | lo;
        i += 1;
    }
    Ok(out)
}

fn hex_nibble(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        b'A'..=b'F' => Some(c - b'A' + 10),
        _ => None,
    }
}

// ===========================================================================
// JSON extraction helpers (tolerant `Value` navigation for the sidecar
// parsers). A-D sidecars vary per atom (optional fields, `consciousness` /
// `verifier_section` appends, 8-vs-9 check sets), so parsers read field-by-
// field with typed, *redacted* errors rather than `deny_unknown_fields`.
// ===========================================================================
use serde_json::{Map, Value};

/// Parse a whole-file JSON document, mapping syntax errors to a redacted
/// line/column — the raw bytes are never echoed.
pub(crate) fn parse_json(kind: DietFileKind, text: &str) -> DietResult<Value> {
    serde_json::from_str(text).map_err(|e| DietError::MalformedJson {
        kind,
        line_u32: e.line() as u32,
        column_u32: e.column() as u32,
    })
}

/// Borrow a JSON object or fail with a typed, redacted error.
pub(crate) fn as_object<'a>(
    v: &'a Value,
    kind: DietFileKind,
    field: &'static str,
) -> DietResult<&'a Map<String, Value>> {
    v.as_object()
        .ok_or(DietError::UnexpectedType { kind, field })
}

/// Required string field.
pub(crate) fn req_str<'a>(
    obj: &'a Map<String, Value>,
    kind: DietFileKind,
    field: &'static str,
) -> DietResult<&'a str> {
    match obj.get(field) {
        None => Err(DietError::MissingField { kind, field }),
        Some(v) => v.as_str().ok_or(DietError::UnexpectedType { kind, field }),
    }
}

/// Optional string field (absent or non-string ⇒ `None`).
pub(crate) fn opt_str<'a>(obj: &'a Map<String, Value>, field: &str) -> Option<&'a str> {
    obj.get(field).and_then(|v| v.as_str())
}

/// Optional signed integer field.
pub(crate) fn opt_i64(obj: &Map<String, Value>, field: &str) -> Option<i64> {
    obj.get(field).and_then(serde_json::Value::as_i64)
}

/// Optional unsigned integer field.
pub(crate) fn opt_u64(obj: &Map<String, Value>, field: &str) -> Option<u64> {
    obj.get(field).and_then(serde_json::Value::as_u64)
}

/// Optional boolean field.
pub(crate) fn opt_bool(obj: &Map<String, Value>, field: &str) -> Option<bool> {
    obj.get(field).and_then(serde_json::Value::as_bool)
}

/// Required array field.
pub(crate) fn req_array<'a>(
    obj: &'a Map<String, Value>,
    kind: DietFileKind,
    field: &'static str,
) -> DietResult<&'a Vec<Value>> {
    match obj.get(field) {
        None => Err(DietError::MissingField { kind, field }),
        Some(v) => v
            .as_array()
            .ok_or(DietError::UnexpectedType { kind, field }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // sha256 known-answer vectors are independent constants (NIST), not a
    // self-comparison — the harness can genuinely fail if hashing drifts.
    #[test]
    fn sha256_empty_vector() {
        assert_eq!(
            hex32_encode(&sha256(b"")),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    #[test]
    fn sha256_abc_vector() {
        assert_eq!(
            hex32_encode(&sha256(b"abc")),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn sha256_reader_matches_oneshot() -> std::io::Result<()> {
        let data = b"the quick brown fox jumps over the lazy dog";
        assert_eq!(sha256_reader(&data[..])?, sha256(data));
        Ok(())
    }

    #[test]
    fn hex32_round_trip() -> DietResult<()> {
        let h = sha256(b"mnemos stage e");
        assert_eq!(hex32_decode(&hex32_encode(&h))?, h);
        Ok(())
    }

    #[test]
    fn hex32_decode_rejects_wrong_length() {
        assert!(matches!(
            hex32_decode("abcd"),
            Err(DietError::InvalidHexLength { got_u32: 4 })
        ));
    }

    #[test]
    fn hex32_decode_rejects_non_hex() {
        let bad = "z".repeat(64);
        assert!(matches!(
            hex32_decode(&bad),
            Err(DietError::InvalidHexChar { at_u32: 0 })
        ));
    }

    #[test]
    fn hex32_decode_rejects_uppercase_out_of_range() {
        // 'G' is just past 'F'; must reject, not wrap.
        let mut s = "a".repeat(63);
        s.push('G');
        assert!(matches!(
            hex32_decode(&s),
            Err(DietError::InvalidHexChar { at_u32: 63 })
        ));
    }

    #[test]
    fn trace_and_handoff_full_width() {
        let t = StageETraceLink::new([0xAB; 32], u16::MAX, u16::MAX);
        assert_eq!(t.stage_e_atom_u16, u16::MAX);
        assert_eq!(t.gate_id_u16, u16::MAX);
        assert_eq!(t.source_trace_hash_32, [0xAB; 32]);
        let d = StageEHandoffDigest::new([1; 32], [2; 32], [3; 32], [4; 32], [5; 32], [6; 32]);
        assert_eq!(d.stage_d_dod_hash_32, [5; 32]);
        assert_eq!(d.sidecar_contract_hash_32, [6; 32]);
    }
}
