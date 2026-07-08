//! [`WasmRuntimeLimits`], the explicit deny-small resource budget every Tier-2
//! sandbox run is checked against *before* it is allowed to proceed.
//!
//! ## Resource budget
//!
//! - [`WasmRuntimeLimits`] — `{fuel_u64, memory_pages_u32, wall_ms_u32,
//!   output_bytes_u32}`. Every field is an upper bound. A run with a zero field
//!   does not exist ([`WasmRuntimeLimits::new`] rejects it), and the defaults
//!   are **deny-small, not allow-big** ([`WasmRuntimeLimits::deny_small`]).
//! - [`LimitExceeded`] — which single budget a declared demand exceeded; the
//!   meter maps it to
//!   [`crate::wasm_tier2::WasmSandboxDecision::MeterExceeded`].
//!
//! The cap check ([`WasmRuntimeLimits::check_demand`]) is a pure comparison run
//! *before* any execution would occur — no allocation, no I/O, no panic.

#![deny(missing_docs)]

// ===========================================================================
// 1. Hard ceilings + deny-small defaults
// ===========================================================================

/// Hard fuel ceiling — a requested `fuel_u64` above this is rejected so a
/// manifest cannot ask for an unbounded compute budget.
pub const MAX_FUEL_U64: u64 = 1_000_000_000;
/// Hard memory ceiling: 1024 pages × 64 KiB = 64 MiB.
pub const MAX_MEMORY_PAGES_U32: u32 = 1_024;
/// Hard wall-time ceiling: 10 s.
pub const MAX_WALL_MS_U32: u32 = 10_000;
/// Hard output ceiling: 1 MiB.
pub const MAX_OUTPUT_BYTES_U32: u32 = 1_048_576;

/// Deny-small default fuel (far below [`MAX_FUEL_U64`]).
pub const DEFAULT_FUEL_U64: u64 = 5_000_000;
/// Deny-small default memory: 64 pages × 64 KiB = 4 MiB.
pub const DEFAULT_MEMORY_PAGES_U32: u32 = 64;
/// Deny-small default wall time: 2 s (the try-before-use p95 budget).
pub const DEFAULT_WALL_MS_U32: u32 = 2_000;
/// Deny-small default output: 64 KiB.
pub const DEFAULT_OUTPUT_BYTES_U32: u32 = 65_536;

// ===========================================================================
// 2. Error / outcome enums
// ===========================================================================

/// Why a [`WasmRuntimeLimits`] value is invalid.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum LimitsError {
    /// A limit field was zero. A zero budget can never run anything, so it is
    /// rejected as a configuration error rather than silently denying later.
    ZeroLimit,
    /// A limit field exceeded its hard ceiling.
    AboveCeiling,
}

/// Which budget a declared demand exceeded. The meter maps any of these
/// to [`crate::wasm_tier2::WasmSandboxDecision::MeterExceeded`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LimitExceeded {
    /// Declared fuel exceeded `fuel_u64`.
    Fuel,
    /// Declared memory pages exceeded `memory_pages_u32`.
    Memory,
    /// Declared wall time exceeded `wall_ms_u32`.
    Wall,
    /// Declared output bytes exceeded `output_bytes_u32`.
    Output,
}

// ===========================================================================
// 3. WasmRuntimeLimits — explicit per-run budget
// ===========================================================================

/// Explicit per-run resource budget. Every field is an *upper bound*; a
/// run with no budget does not exist. Construct via [`Self::new`] (which
/// rejects any zero or above-ceiling field) or [`Self::deny_small`] (the
/// conservative default). The public fields mirror the canonical
/// signature byte-for-byte; the verifier-style guard lives in [`Self::new`].
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub struct WasmRuntimeLimits {
    /// Maximum logical fuel units the run may consume.
    pub fuel_u64: u64,
    /// Maximum linear-memory pages (64 KiB each) the run may allocate.
    pub memory_pages_u32: u32,
    /// Maximum wall-clock milliseconds the run may take.
    pub wall_ms_u32: u32,
    /// Maximum output bytes the run may emit.
    pub output_bytes_u32: u32,
}

impl WasmRuntimeLimits {
    /// The conservative deny-small default budget.
    #[inline]
    #[must_use]
    pub const fn deny_small() -> Self {
        Self {
            fuel_u64: DEFAULT_FUEL_U64,
            memory_pages_u32: DEFAULT_MEMORY_PAGES_U32,
            wall_ms_u32: DEFAULT_WALL_MS_U32,
            output_bytes_u32: DEFAULT_OUTPUT_BYTES_U32,
        }
    }

    /// Build a validated limit set: every field must be non-zero and at or
    /// below its hard ceiling.
    ///
    /// # Errors
    ///
    /// [`LimitsError::ZeroLimit`] if any field is `0`;
    /// [`LimitsError::AboveCeiling`] if any field exceeds its `MAX_*` ceiling.
    pub const fn new(
        fuel_u64: u64,
        memory_pages_u32: u32,
        wall_ms_u32: u32,
        output_bytes_u32: u32,
    ) -> Result<Self, LimitsError> {
        if fuel_u64 == 0 || memory_pages_u32 == 0 || wall_ms_u32 == 0 || output_bytes_u32 == 0 {
            return Err(LimitsError::ZeroLimit);
        }
        if fuel_u64 > MAX_FUEL_U64
            || memory_pages_u32 > MAX_MEMORY_PAGES_U32
            || wall_ms_u32 > MAX_WALL_MS_U32
            || output_bytes_u32 > MAX_OUTPUT_BYTES_U32
        {
            return Err(LimitsError::AboveCeiling);
        }
        Ok(Self {
            fuel_u64,
            memory_pages_u32,
            wall_ms_u32,
            output_bytes_u32,
        })
    }

    /// Cap-check a declared resource demand **before execution**. Returns the
    /// first budget the demand would exceed, or `Ok(())` if it fits entirely.
    /// This is a pure comparison — it never runs the module.
    ///
    /// # Errors
    ///
    /// The first [`LimitExceeded`] budget the demand overruns, checked in the
    /// fixed order fuel → memory → wall → output.
    pub const fn check_demand(
        &self,
        fuel_u64: u64,
        memory_pages_u32: u32,
        wall_ms_u32: u32,
        output_bytes_u32: u32,
    ) -> Result<(), LimitExceeded> {
        if fuel_u64 > self.fuel_u64 {
            return Err(LimitExceeded::Fuel);
        }
        if memory_pages_u32 > self.memory_pages_u32 {
            return Err(LimitExceeded::Memory);
        }
        if wall_ms_u32 > self.wall_ms_u32 {
            return Err(LimitExceeded::Wall);
        }
        if output_bytes_u32 > self.output_bytes_u32 {
            return Err(LimitExceeded::Output);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn zero_limit_is_rejected() {
        assert_eq!(
            WasmRuntimeLimits::new(0, 64, 2_000, 65_536),
            Err(LimitsError::ZeroLimit)
        );
        assert_eq!(
            WasmRuntimeLimits::new(5_000_000, 0, 2_000, 65_536),
            Err(LimitsError::ZeroLimit)
        );
        assert_eq!(
            WasmRuntimeLimits::new(5_000_000, 64, 0, 65_536),
            Err(LimitsError::ZeroLimit)
        );
        assert_eq!(
            WasmRuntimeLimits::new(5_000_000, 64, 2_000, 0),
            Err(LimitsError::ZeroLimit)
        );
    }

    #[test]
    fn at_ceiling_ok_above_ceiling_rejected() {
        assert!(
            WasmRuntimeLimits::new(
                MAX_FUEL_U64,
                MAX_MEMORY_PAGES_U32,
                MAX_WALL_MS_U32,
                MAX_OUTPUT_BYTES_U32,
            )
            .is_ok()
        );
        assert_eq!(
            WasmRuntimeLimits::new(MAX_FUEL_U64 + 1, 64, 2_000, 65_536),
            Err(LimitsError::AboveCeiling)
        );
        assert_eq!(
            WasmRuntimeLimits::new(5_000_000, MAX_MEMORY_PAGES_U32 + 1, 2_000, 65_536),
            Err(LimitsError::AboveCeiling)
        );
    }

    #[test]
    fn deny_small_is_valid_and_conservative() {
        let d = WasmRuntimeLimits::deny_small();
        // deny_small must itself satisfy new()'s invariants.
        assert!(
            WasmRuntimeLimits::new(
                d.fuel_u64,
                d.memory_pages_u32,
                d.wall_ms_u32,
                d.output_bytes_u32
            )
            .is_ok()
        );
        // and sit strictly below every ceiling.
        assert!(d.fuel_u64 < MAX_FUEL_U64);
        assert!(d.memory_pages_u32 < MAX_MEMORY_PAGES_U32);
        assert!(d.wall_ms_u32 < MAX_WALL_MS_U32);
        assert!(d.output_bytes_u32 < MAX_OUTPUT_BYTES_U32);
    }

    #[test]
    fn fuel_exhausted_detected() {
        let l = WasmRuntimeLimits::deny_small();
        assert_eq!(
            l.check_demand(l.fuel_u64 + 1, 1, 1, 1),
            Err(LimitExceeded::Fuel)
        );
    }

    #[test]
    fn memory_exhausted_detected() {
        let l = WasmRuntimeLimits::deny_small();
        assert_eq!(
            l.check_demand(1, l.memory_pages_u32 + 1, 1, 1),
            Err(LimitExceeded::Memory)
        );
    }

    #[test]
    fn output_cap_detected() {
        let l = WasmRuntimeLimits::deny_small();
        assert_eq!(
            l.check_demand(1, 1, 1, l.output_bytes_u32 + 1),
            Err(LimitExceeded::Output)
        );
    }

    #[test]
    fn in_budget_demand_fits() {
        let l = WasmRuntimeLimits::deny_small();
        assert_eq!(
            l.check_demand(
                l.fuel_u64,
                l.memory_pages_u32,
                l.wall_ms_u32,
                l.output_bytes_u32
            ),
            Ok(())
        );
    }
}
