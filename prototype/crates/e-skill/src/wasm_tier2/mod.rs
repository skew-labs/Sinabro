//! `mnemos-e-skill::wasm_tier2` — Stage D WASM Tier-2 sandbox policy surface
//! (D-WP-02, atoms #256-#275 · §4.2).
//!
//! ## Execution model — policy + declarative fixtures, real engine deferred
//!
//! This cluster is the **deny-by-default capability / metering / hostcall
//! policy** for a Stage D skill sandbox. Per the D-WP-02 architecture decision
//! (owner-locked 2026-06-04) it does **not** embed a real WASM execution engine:
//! `wasmtime` / `wasmi` / `wasmer` are absent from the offline build cache, and
//! the §4.2 canonical types carry no engine handle. Instead every "run" is
//! evaluated against a *declarative fixture* that states the module's content id
//! and the resources / hostcalls / paths it declares it will touch; the policy
//! layer maps that declaration to a [`WasmSandboxDecision`] with no ambient
//! authority, no host I/O, no allocation bomb, and no panic. A later stage may
//! add a real engine in `n-sandbox` under explicit approval — the limits,
//! grants, hostcall table, and decision surface authored here are the contract
//! it will be required to enforce.
//!
//! Nothing in this cluster performs live network egress, wallet signing,
//! payment, chain write, or host filesystem mutation
//! (G-D-NO-COMMERCE · G-D-TRUST-BOUNDARY · G-D-WASM-T2).
//!
//! ## Modules
//!
//! - [`limits`] (#256): the deny-small per-run resource budget.
//! - [`module_id`] (#257): the content address of a sandbox module.
//! - [`grant`] (#258): owner/skill/permission/epoch-scoped capability grants.
//! - [`fs_policy`] (#259): filesystem deny-by-default.
//! - [`net_policy`] (#260): network deny-by-default.
//! - [`secret_policy`] (#261): wallet/chain/secret deny matrix.
//! - [`hostcalls`] (#262): the closed, versioned hostcall table.
//! - [`determinism`] (#263): replayable logical time + run-id seed.
//! - [`meter`] (#264): fuel/memory/stack/hostcall metering.
//! - [`output`] (#265): redacted output envelope + size cap.
//! - [`trace`] (#268): sandbox eval trace (JSONL, `StageDTraceLink`).

#![deny(missing_docs)]

pub mod determinism;
pub mod fs_policy;
pub mod grant;
pub mod hostcalls;
pub mod limits;
pub mod meter;
pub mod module_id;
pub mod net_policy;
pub mod output;
pub mod secret_policy;
pub mod trace;

// ===========================================================================
// WasmSandboxDecision — §4.2 single outcome enum for every Tier-2 evaluation
// ===========================================================================

/// §4.2 sandbox decision — the single outcome enum for every Tier-2
/// evaluation. `#[repr(u8)]` 1-byte discriminant (`1..=5`); the discriminant
/// doubles as the `sandbox_event_u16` carried by
/// [`mnemos_a_core::StageDTraceLink`].
///
/// A decision is **never** [`Self::Allow`] by omission: a missing grant is
/// [`Self::CapabilityMissing`], an over-budget run is [`Self::MeterExceeded`],
/// a run that declares ambient time / randomness it may not observe is
/// [`Self::Nondeterministic`], and any other undeclared filesystem / network /
/// secret / chain surface is [`Self::Deny`]. Only a fully-declared,
/// fully-granted, in-budget, deterministic run reaches [`Self::Allow`].
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
#[repr(u8)]
pub enum WasmSandboxDecision {
    /// Fully declared, granted, in-budget, deterministic — the only allow path.
    Allow = 1,
    /// An undeclared filesystem / network / secret / chain surface was touched.
    Deny = 2,
    /// A fuel / memory / wall-time / output budget was exceeded.
    MeterExceeded = 3,
    /// No capability grant covers the requested permission.
    CapabilityMissing = 4,
    /// The run declared ambient time / randomness it is not allowed to observe.
    Nondeterministic = 5,
}

impl WasmSandboxDecision {
    /// `true` iff this is [`Self::Allow`]. Every other variant is a
    /// fail-closed denial class, so the policy layer can gate execution on a
    /// single `is_allow()` check.
    #[inline]
    #[must_use]
    pub const fn is_allow(self) -> bool {
        matches!(self, Self::Allow)
    }

    /// The 1-byte discriminant, also used verbatim as the
    /// [`mnemos_a_core::StageDTraceLink`] `sandbox_event_u16`.
    #[inline]
    #[must_use]
    pub const fn discriminant(self) -> u8 {
        self as u8
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_allow_is_allow() {
        assert!(WasmSandboxDecision::Allow.is_allow());
        for d in [
            WasmSandboxDecision::Deny,
            WasmSandboxDecision::MeterExceeded,
            WasmSandboxDecision::CapabilityMissing,
            WasmSandboxDecision::Nondeterministic,
        ] {
            assert!(!d.is_allow(), "{d:?} must be a denial class");
        }
    }

    #[test]
    fn discriminants_are_one_based_and_stable() {
        assert_eq!(WasmSandboxDecision::Allow.discriminant(), 1);
        assert_eq!(WasmSandboxDecision::Deny.discriminant(), 2);
        assert_eq!(WasmSandboxDecision::MeterExceeded.discriminant(), 3);
        assert_eq!(WasmSandboxDecision::CapabilityMissing.discriminant(), 4);
        assert_eq!(WasmSandboxDecision::Nondeterministic.discriminant(), 5);
    }
}
