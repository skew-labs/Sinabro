//! `mnemos-e-skill::wasm_tier2::trace` — sandbox evaluation trace.
//!
//! Every sandbox outcome — allow, deny, meter-exceeded, capability-missing,
//! nondeterministic — produces exactly one [`SandboxTraceRecord`], so trace
//! coverage is 100%. The record carries only ids, labels, and **digests**
//! (never raw output or secret bytes), so the trace itself cannot leak file
//! contents or secrets. [`SandboxTraceRecord::to_jsonl`] renders a stable JSONL
//! line with a fixed field order, so identical records render byte-identically.
//! Reuses the [`mnemos_a_core::StageDTraceLink`] stamp (which composes the
//! Stage C / Stage B identity).

#![deny(missing_docs)]

extern crate alloc;

use alloc::format;
use alloc::string::String;

use mnemos_a_core::StageDTraceLink;

use crate::capability_diff::SkillRuntimePermission;
use crate::wasm_tier2::WasmSandboxDecision;
use crate::wasm_tier2::hostcalls::SkillHostcall;
use crate::wasm_tier2::module_id::WasmTier2ModuleId;

/// Lowercase hex alphabet for the digest fields.
const HEX: &[u8; 16] = b"0123456789abcdef";

/// Lowercase hex of a 32-byte digest.
fn hex32(bytes: &[u8; 32]) -> String {
    let mut s = String::with_capacity(64);
    for b in bytes {
        s.push(HEX[(b >> 4) as usize] as char);
        s.push(HEX[(b & 0x0f) as usize] as char);
    }
    s
}

/// One sandbox evaluation trace record. Carries only ids, labels, and digests —
/// never raw output or secret bytes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SandboxTraceRecord {
    /// The Stage D trace stamp (composes Stage C / Stage B identity).
    pub trace: StageDTraceLink,
    /// The module the run evaluated.
    pub module: WasmTier2ModuleId,
    /// The sandbox decision for this outcome.
    pub decision: WasmSandboxDecision,
    /// The permission under evaluation, if the outcome was permission-scoped.
    pub permission: Option<SkillRuntimePermission>,
    /// The hostcall under evaluation, if the outcome was hostcall-scoped.
    pub hostcall: Option<SkillHostcall>,
    /// Fuel charged to the run (0 for a pre-execution denial).
    pub fuel_u64: u64,
    /// Memory pages charged to the run.
    pub memory_pages_u32: u32,
    /// Digest of the (redacted, capped) output — never the raw output.
    pub output_digest_32: [u8; 32],
}

impl SandboxTraceRecord {
    /// Serialize to one stable JSONL line with a **fixed** field order, so two
    /// records with identical data render byte-identically.
    #[must_use]
    pub fn to_jsonl(&self) -> String {
        let permission = self
            .permission
            .map_or_else(|| String::from("null"), |p| format!("{}", p as u8));
        let hostcall = self.hostcall.map_or_else(
            || String::from("null"),
            |h| format!("{}", h.trace_event_u16()),
        );
        format!(
            "{{\"trace_id\":{},\"stage_c_atom\":{},\"stage_d_atom\":{},\"event\":{},\"decision\":{},\"module\":\"{}\",\"permission\":{},\"hostcall\":{},\"fuel\":{},\"memory_pages\":{},\"output_digest\":\"{}\"}}",
            self.trace.trace.trace.trace_id_u64,
            self.trace.trace.stage_c_atom_u16,
            self.trace.stage_d_atom_u16,
            self.trace.sandbox_event_u16,
            self.decision.discriminant(),
            hex32(self.module.bytes()),
            permission,
            hostcall,
            self.fuel_u64,
            self.memory_pages_u32,
            hex32(&self.output_digest_32),
        )
    }

    /// `true` iff this record's decision is an allow.
    #[inline]
    #[must_use]
    pub const fn is_allow(&self) -> bool {
        self.decision.is_allow()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mnemos_a_core::{StageBTraceLink, StageCTraceLink};

    fn link() -> StageDTraceLink {
        let b = StageBTraceLink::new(0xD268_0001, 268, 0);
        let c = StageCTraceLink::new(b, 240, 9);
        StageDTraceLink::new(c, 268, 1)
    }

    fn record(decision: WasmSandboxDecision) -> SandboxTraceRecord {
        SandboxTraceRecord {
            trace: link(),
            module: WasmTier2ModuleId::from_bytes([0xAB; 32]),
            decision,
            permission: Some(SkillRuntimePermission::MemoryRead),
            hostcall: Some(SkillHostcall::MemoryRead),
            fuel_u64: 1234,
            memory_pages_u32: 5,
            output_digest_32: [0xCD; 32],
        }
    }

    #[test]
    fn trace_on_allow_has_digests_and_decision() {
        let line = record(WasmSandboxDecision::Allow).to_jsonl();
        assert!(line.contains("\"decision\":1"));
        assert!(line.contains("\"module\":\"abab"));
        assert!(line.contains("\"output_digest\":\"cdcd"));
        assert!(line.contains("\"permission\":7"));
        assert!(line.contains("\"hostcall\":4"));
    }

    #[test]
    fn trace_on_deny_records_decision() {
        let line = record(WasmSandboxDecision::Deny).to_jsonl();
        assert!(line.contains("\"decision\":2"));
    }

    #[test]
    fn trace_carries_no_raw_secret_only_digests() {
        // Even if the output digest were of a secret, the JSONL holds only the
        // digest hex — the raw secret string never appears.
        let mut r = record(WasmSandboxDecision::Allow);
        r.permission = None;
        r.hostcall = None;
        let line = r.to_jsonl();
        assert!(!line.contains("deadbeef-secret"));
        assert!(line.contains("\"permission\":null"));
        assert!(line.contains("\"hostcall\":null"));
    }

    #[test]
    fn trace_ordering_is_stable() {
        assert_eq!(
            record(WasmSandboxDecision::MeterExceeded).to_jsonl(),
            record(WasmSandboxDecision::MeterExceeded).to_jsonl()
        );
    }
}
