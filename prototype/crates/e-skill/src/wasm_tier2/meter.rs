//! `mnemos-e-skill::wasm_tier2::meter` — atom #264 · D.1.8 —
//! fuel / instruction / memory / hostcall metering enforcement.
//!
//! The meter compares a **declared resource demand** to the run's
//! [`WasmRuntimeLimits`] *before* execution. Under the policy model nothing here
//! allocates or runs a module, so a "loop bomb", "alloc bomb", "recursion bomb",
//! or "hostcall flood" is a *number that exceeds a cap*, not a process the host
//! actually runs — every over-budget run stops as
//! [`WasmSandboxDecision::MeterExceeded`], never an OOM or a panic.

#![deny(missing_docs)]

use crate::wasm_tier2::WasmSandboxDecision;
use crate::wasm_tier2::limits::WasmRuntimeLimits;

/// Hard cap on hostcalls per run — a hostcall flood beyond this meters out.
pub const MAX_HOSTCALLS_PER_RUN_U32: u32 = 100_000;
/// Hard cap on declared call-stack depth — a recursion bomb beyond this meters
/// out.
pub const MAX_STACK_DEPTH_U32: u32 = 1_024;

/// A declared resource demand for a run. Every field is a *claim* the policy
/// checks against the limits; the host never executes the module, so these
/// numbers — not real allocations — are what the meter bounds.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub struct ResourceDemand {
    /// Declared fuel (logical instruction budget) the run will consume.
    pub fuel_u64: u64,
    /// Declared linear-memory pages the run will allocate.
    pub memory_pages_u32: u32,
    /// Declared wall-clock milliseconds the run will take.
    pub wall_ms_u32: u32,
    /// Declared output bytes the run will emit.
    pub output_bytes_u32: u32,
    /// Declared maximum call-stack depth the run will reach.
    pub stack_depth_u32: u32,
    /// Declared number of hostcalls the run will make.
    pub hostcall_count_u32: u32,
}

impl ResourceDemand {
    /// A trivially-in-budget demand (all ones) for tests / callers that only
    /// vary one dimension.
    #[inline]
    #[must_use]
    pub const fn minimal() -> Self {
        Self {
            fuel_u64: 1,
            memory_pages_u32: 1,
            wall_ms_u32: 1,
            output_bytes_u32: 1,
            stack_depth_u32: 1,
            hostcall_count_u32: 1,
        }
    }
}

/// Enforce the meter against a declared `demand`. Returns
/// [`WasmSandboxDecision::MeterExceeded`] for the first over-budget dimension
/// (limits-checked fuel/memory/wall/output, then stack depth, then hostcall
/// count), or [`WasmSandboxDecision::Allow`] if everything fits. Never panics,
/// never allocates, never OOMs.
#[must_use]
pub fn enforce_meter(limits: &WasmRuntimeLimits, demand: &ResourceDemand) -> WasmSandboxDecision {
    if limits
        .check_demand(
            demand.fuel_u64,
            demand.memory_pages_u32,
            demand.wall_ms_u32,
            demand.output_bytes_u32,
        )
        .is_err()
    {
        return WasmSandboxDecision::MeterExceeded;
    }
    if demand.stack_depth_u32 > MAX_STACK_DEPTH_U32 {
        return WasmSandboxDecision::MeterExceeded;
    }
    if demand.hostcall_count_u32 > MAX_HOSTCALLS_PER_RUN_U32 {
        return WasmSandboxDecision::MeterExceeded;
    }
    WasmSandboxDecision::Allow
}

#[cfg(test)]
mod tests {
    use super::*;

    fn limits() -> WasmRuntimeLimits {
        WasmRuntimeLimits::deny_small()
    }

    #[test]
    fn loop_bomb_meters_out() {
        let mut d = ResourceDemand::minimal();
        d.fuel_u64 = u64::MAX;
        assert_eq!(
            enforce_meter(&limits(), &d),
            WasmSandboxDecision::MeterExceeded
        );
    }

    #[test]
    fn alloc_bomb_meters_out() {
        let mut d = ResourceDemand::minimal();
        d.memory_pages_u32 = u32::MAX;
        assert_eq!(
            enforce_meter(&limits(), &d),
            WasmSandboxDecision::MeterExceeded
        );
    }

    #[test]
    fn recursion_bomb_meters_out() {
        let mut d = ResourceDemand::minimal();
        d.stack_depth_u32 = u32::MAX;
        assert_eq!(
            enforce_meter(&limits(), &d),
            WasmSandboxDecision::MeterExceeded
        );
    }

    #[test]
    fn hostcall_flood_meters_out() {
        let mut d = ResourceDemand::minimal();
        d.hostcall_count_u32 = u32::MAX;
        assert_eq!(
            enforce_meter(&limits(), &d),
            WasmSandboxDecision::MeterExceeded
        );
    }

    #[test]
    fn in_budget_demand_allows() {
        assert_eq!(
            enforce_meter(&limits(), &ResourceDemand::minimal()),
            WasmSandboxDecision::Allow
        );
    }
}
