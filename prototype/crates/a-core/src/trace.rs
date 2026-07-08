//! Cross-stage action trace primitives.
//!
//! This module is the **foundational home** for the action-trace value
//! carriers that more than one domain crate must embed. It exists in `a-core`
//! (the dependency root) so that the low crates `d-move` (gas trace) and
//! `k-devex` (evidence ref) can stamp a trace without
//! taking a cyclic dependency on `b-memory`.
//!
//! * [`StageBTraceLink`] — the `(trace_id_u64, atom_id_u16,
//!   attempt_u8)` triple. It was originally defined in
//!   `b-memory/src/stage_b_handoff.rs`; in Stage C the *definition*
//!   was relocated here so it sits below `d-move`/`k-devex`. `b-memory`
//!   re-exports it verbatim from `stage_b_handoff`, so every existing Stage B
//!   path (`mnemos_b_memory::stage_b_handoff::StageBTraceLink`,
//!   `crate::StageBTraceLink`) keeps resolving to the identical type with the
//!   identical byte layout — no signing preimage or replay digest changes.
//! * [`StageCTraceLink`] — the Stage C stamp. It *composes* (never
//!   re-mints) [`StageBTraceLink`] and adds the Stage C atom number and the
//!   gate id so a gas / evidence / ceremony artifact is greppable by Stage C
//!   atom and by the gate that produced it.
//! * [`StageDTraceLink`] — the Stage D stamp. It *composes* (never
//!   re-mints) [`StageCTraceLink`] and adds the Stage D atom number and a
//!   sandbox-event id so a WASM-sandbox / try-before-use evidence line is
//!   greppable by Stage D atom and by the sandbox event that produced it.
//!   It is minted here so that the trace-link family stays in `a-core` and
//!   no consumer crate inverts a dependency
//!   on `a-core` to stamp a Stage D trace.
//!
//! # Design invariants
//!
//! * **No re-mint.** [`StageCTraceLink`] holds a `StageBTraceLink` by value;
//!   it does not duplicate the `(trace_id, atom_id, attempt)` triple. The
//!   single source of truth for an action trace stays [`StageBTraceLink`].
//! * **Trace widths are fixed.** `stage_c_atom_u16` and `gate_id_u16` are
//!   `u16` by type; the Stage C atom space and the gate registry
//!   fit with headroom, and the round-trip test pins the full width.

// ===========================================================================
// 1. StageBTraceLink — (trace_id, atom_id, attempt)  [relocated from b-memory]
// ===========================================================================

/// Per-action trace stamp. Every external action (Walrus PUT/GET, Sui anchor,
/// audit append, replay, gas dry-run) carries one of these so the evidence
/// trail can be filtered by trace id, atom and attempt.
///
/// Fields are `pub` per the Stage B canonical registry; [`new`](Self::new)
/// is provided for ergonomic construction at call sites.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub struct StageBTraceLink {
    /// Opaque per-run trace identifier (caller-assigned, monotone within a
    /// run is conventional but not enforced here).
    pub trace_id_u64: u64,
    /// Atom number the action belongs to (e.g. `81`). A `u16` so the full
    /// Stage A+B+C atom space fits with headroom.
    pub atom_id_u16: u16,
    /// Retry attempt counter for the action, starting at `0`.
    pub attempt_u8: u8,
}

impl StageBTraceLink {
    /// Construct a trace link from its three components.
    #[inline]
    pub const fn new(trace_id_u64: u64, atom_id_u16: u16, attempt_u8: u8) -> Self {
        Self {
            trace_id_u64,
            atom_id_u16,
            attempt_u8,
        }
    }
}

// ===========================================================================
// 2. StageCTraceLink — Stage B trace + Stage C atom + gate id
// ===========================================================================

/// Stage C per-artifact trace stamp.
///
/// Composes the underlying Stage B [`StageBTraceLink`] (the run/atom/attempt
/// identity) and adds the Stage C atom number and the gate id that emitted the
/// artifact. A gas sample, an evidence ref, a Gas
/// Station decision and a mainnet ceremony record all carry one
/// of these.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub struct StageCTraceLink {
    /// The underlying Stage B action trace, reused verbatim (no re-mint).
    pub trace: StageBTraceLink,
    /// Stage C atom number the artifact belongs to (e.g. `178`). A `u16`
    /// covers the Stage C atom span with headroom.
    pub stage_c_atom_u16: u16,
    /// Gate-registry id that produced the artifact (e.g. the numeric id of
    /// a gas-trace gate). A `u16` keeps the gate space open-ended.
    pub gate_id_u16: u16,
}

impl StageCTraceLink {
    /// Construct a Stage C trace stamp from a Stage B trace plus the Stage C
    /// atom number and gate id.
    #[inline]
    pub const fn new(trace: StageBTraceLink, stage_c_atom_u16: u16, gate_id_u16: u16) -> Self {
        Self {
            trace,
            stage_c_atom_u16,
            gate_id_u16,
        }
    }

    /// Borrow the underlying Stage B trace stamp.
    #[inline]
    pub const fn stage_b_trace(&self) -> StageBTraceLink {
        self.trace
    }
}

// ===========================================================================
// 3. StageDTraceLink — Stage C trace + Stage D atom + sandbox event id
// ===========================================================================

/// Stage D per-artifact trace stamp (minted here so the trace-link family
/// stays in `a-core`, so no consumer crate inverts a dependency to stamp a
/// trace).
///
/// Composes the underlying [`StageCTraceLink`] (which itself composes the
/// Stage B run/atom/attempt identity — no re-mint at any layer) and adds the
/// Stage D atom number and a sandbox-event id. Every WASM Tier-2 sandbox
/// outcome (allow / deny / meter-exceeded), every try-before-use run
/// (`TryBeforeUseRun`) and every sandbox eval-trace line carries one of these so
/// the offline evidence trail is greppable by Stage D atom and by the sandbox
/// event that produced it.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub struct StageDTraceLink {
    /// The underlying Stage C trace stamp, reused verbatim (no re-mint). It
    /// already carries the Stage B `(trace_id, atom_id, attempt)` identity and
    /// the Stage C atom + gate id.
    pub trace: StageCTraceLink,
    /// Stage D atom number the artifact belongs to (e.g. `267`). A `u16`
    /// covers the Stage D atom span with headroom.
    pub stage_d_atom_u16: u16,
    /// Sandbox-event id that produced the artifact (e.g. a hostcall id or a
    /// `WasmSandboxDecision` discriminant). A `u16` keeps the event space
    /// open-ended without re-minting any decision enum in this foundational
    /// crate.
    pub sandbox_event_u16: u16,
}

impl StageDTraceLink {
    /// Construct a Stage D trace stamp from a Stage C trace plus the Stage D
    /// atom number and the sandbox-event id.
    #[inline]
    pub const fn new(
        trace: StageCTraceLink,
        stage_d_atom_u16: u16,
        sandbox_event_u16: u16,
    ) -> Self {
        Self {
            trace,
            stage_d_atom_u16,
            sandbox_event_u16,
        }
    }

    /// Borrow the underlying Stage C trace stamp.
    #[inline]
    pub const fn stage_c_trace(&self) -> StageCTraceLink {
        self.trace
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stage_b_trace_link_preserves_full_field_widths() {
        let t = StageBTraceLink::new(u64::MAX, u16::MAX, u8::MAX);
        assert_eq!(t.trace_id_u64, u64::MAX);
        assert_eq!(t.atom_id_u16, u16::MAX);
        assert_eq!(t.attempt_u8, u8::MAX);
    }

    #[test]
    fn stage_c_trace_link_composes_stage_b_without_reminting() {
        let b = StageBTraceLink::new(0xA17B_0171, 171, 2);
        let c = StageCTraceLink::new(b, 178, 5);
        // The Stage B identity survives verbatim.
        assert_eq!(c.stage_b_trace(), b);
        assert_eq!(c.trace.trace_id_u64, 0xA17B_0171);
        assert_eq!(c.trace.atom_id_u16, 171);
        assert_eq!(c.trace.attempt_u8, 2);
        // The Stage C dimensions carry their own full width.
        assert_eq!(c.stage_c_atom_u16, 178);
        assert_eq!(c.gate_id_u16, 5);
    }

    #[test]
    fn stage_c_trace_link_full_field_widths() {
        let b = StageBTraceLink::new(0, 0, 0);
        let c = StageCTraceLink::new(b, u16::MAX, u16::MAX);
        assert_eq!(c.stage_c_atom_u16, u16::MAX);
        assert_eq!(c.gate_id_u16, u16::MAX);
    }

    #[test]
    fn stage_d_trace_link_composes_stage_c_without_reminting() {
        let b = StageBTraceLink::new(0xD241_0107, 241, 1);
        let c = StageCTraceLink::new(b, 240, 9);
        let d = StageDTraceLink::new(c, 267, 3);
        // The Stage C identity (and the Stage B identity it carries) survive verbatim.
        assert_eq!(d.stage_c_trace(), c);
        assert_eq!(d.trace.trace.trace_id_u64, 0xD241_0107);
        assert_eq!(d.trace.stage_c_atom_u16, 240);
        // The Stage D dimensions carry their own full width.
        assert_eq!(d.stage_d_atom_u16, 267);
        assert_eq!(d.sandbox_event_u16, 3);
    }

    #[test]
    fn stage_d_trace_link_full_field_widths() {
        let b = StageBTraceLink::new(u64::MAX, u16::MAX, u8::MAX);
        let c = StageCTraceLink::new(b, u16::MAX, u16::MAX);
        let d = StageDTraceLink::new(c, u16::MAX, u16::MAX);
        assert_eq!(d.stage_d_atom_u16, u16::MAX);
        assert_eq!(d.sandbox_event_u16, u16::MAX);
    }
}
