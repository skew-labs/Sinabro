//! `mnemos-d-move::stage_b_gas` — Stage B gas budget
//! cap policy over the reused [`crate::types::GasBudgetMist`].
//!
//! ## Canonical OUT
//!
//! - [`StageBGasBudgetPolicy`] — a testnet gas ceiling carrier. It checks a
//!   requested gas budget (in `MIST`) against a configured maximum BEFORE
//!   the call builder produces dry-run bytes, so an over-budget Stage B
//!   transaction is rejected fail-closed rather than measured.
//! - [`StageBGasError`] — the policy-layer failure channel (zero / cap /
//!   addition-overflow).
//! - [`STAGE_B_DEFAULT_MAX_GAS_MIST`] — a documented Stage-B testnet policy
//!   ceiling default.
//!
//! Invariant: MIST cannot be confused with a raw token
//! count or a blob byte length because the budget crosses every surface here
//! as the [`GasBudgetMist`] `#[repr(transparent)]` newtype — never a
//! bare `u64`. The cap is enforced before dry-run.
//!
//! ## No canonical signature for a gas cap policy
//!
//! The canonical registry declares the Move-binding shapes but NOT a gas-cap
//! policy type; Stage B is free to mint NEW types that
//! *combine* a canonical one (here: a `policy` over [`GasBudgetMist`]). So this
//! module mints [`StageBGasBudgetPolicy`] / [`StageBGasError`] as new policy
//! surfaces while REUSING the gas typed unit verbatim (no second gas type).
//!
//! The [`crate::StageBMoveBindError`] channel is frozen at five
//! variants (a sixth variant would be drift — the
//! cross-language schema lock). Its `GasBudgetZero` variant is the *call
//! builder* layer's zero guard (`require_nonzero_gas`). The cap
//! and the addition-overflow rejects have NO home in that frozen channel, so
//! this module routes ALL three policy-layer rejects through a dedicated
//! [`StageBGasError`] enum and leaves `StageBMoveBindError` byte-stable.
//!
//! ## `STAGE_B_DEFAULT_MAX_GAS_MIST` is a policy ceiling, not a protocol constant
//!
//! [`STAGE_B_DEFAULT_MAX_GAS_MIST`] is `1_000_000_000` = **1 SUI** (1 SUI =
//! 10^9 MIST). It is a CONSERVATIVE Stage-B-internal safety ceiling, NOT a
//! claim about the Sui protocol `max_tx_gas`. The Stage B PTBs here are tiny
//! (dry-run bytes are 65 / 130 / 162 / 123 bytes), so a 1-SUI cap is
//! far above any honest testnet cost while bounding a fat-fingered budget. The
//! value is NOT load-bearing for correctness: a policy is constructed with an
//! explicit cap via [`StageBGasBudgetPolicy::new`]; the const only seeds
//! [`StageBGasBudgetPolicy::with_default_cap`]. Stage B has no mainnet path,
//! so this ceiling never gates real funds.
#![allow(clippy::module_name_repetitions)]

use crate::types::GasBudgetMist;

// ===========================================================================
// 1. Compile-time reuse pin
// ===========================================================================

/// Pins the reuse: a [`GasBudgetMist`] is exactly 8 bytes (`u64`). Any drift
/// in the newtype width breaks the build via a zero-length-array
/// index trick before any test runs — so a policy that silently widened or
/// boxed the gas unit cannot compile. Mirror of
/// `stage_b_types::_STAGE_B_MOVE_VEC_LEN_REUSES_BLOB_ID_BYTES_32`.
const _GAS_BUDGET_MIST_REUSE_IS_8_BYTES: [(); 0 - !(core::mem::size_of::<GasBudgetMist>() == 8)
    as usize] = [];

// ===========================================================================
// 2. Documented Stage-B testnet policy ceiling
// ===========================================================================

/// Default Stage B testnet gas ceiling in `MIST`. `1_000_000_000` = 1 SUI
/// (1 SUI = 10^9 MIST). This is a Stage-B-internal conservative
/// safety ceiling, NOT a Sui protocol `max_tx_gas` constant, and is not
/// load-bearing for correctness (a policy may be built with any explicit cap).
pub const STAGE_B_DEFAULT_MAX_GAS_MIST: u64 = 1_000_000_000;

// ===========================================================================
// 3. Policy-layer failure channel (NEW — not StageBMoveBindError; see OD-A)
// ===========================================================================

/// Failure modes raised by the Stage B gas-budget cap policy. `Copy`, with no
/// owned bytes, so the channel cannot leak a raw budget value through `Debug`
/// / `Display`. Class labels are namespaced `stage_b_gas.*`, mirroring the
/// [`crate::StageBMoveBindError::class_label`] discipline.
///
/// This is a SEPARATE channel from the frozen five-variant
/// [`crate::StageBMoveBindError`]. The cap and overflow
/// rejects have no home there, and adding a sixth variant would break the
/// cross-language schema lock.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum StageBGasError {
    /// A gas budget of zero `MIST` was supplied. Sui validators reject a
    /// zero-budget transaction, so the policy refuses it before dry-run
    /// (parallels the call-builder layer's `StageBMoveBindError::GasBudgetZero`,
    /// routed through this policy channel).
    GasBudgetZero,
    /// The supplied (or accumulated) gas budget exceeded the policy ceiling
    /// ([`StageBGasBudgetPolicy::max`]). The over-budget value is NOT carried
    /// in the error (the channel is `Copy`, dataless).
    GasBudgetCapExceeded,
    /// Accumulating a slice of per-call gas budgets overflowed `u64` before
    /// the cap could even be applied ([`StageBGasBudgetPolicy::checked_total`]).
    GasBudgetAdditionOverflow,
}

impl StageBGasError {
    /// Stable class label of this failure mode, namespaced under
    /// `stage_b_gas.*` so audit pipelines can fan out on one prefix.
    #[inline]
    pub const fn class_label(&self) -> &'static str {
        match self {
            Self::GasBudgetZero => "stage_b_gas.budget_zero",
            Self::GasBudgetCapExceeded => "stage_b_gas.budget_cap_exceeded",
            Self::GasBudgetAdditionOverflow => "stage_b_gas.budget_addition_overflow",
        }
    }
}

// ===========================================================================
// 4. Gas budget cap policy (NEW combinational policy over GasBudgetMist)
// ===========================================================================

/// A Stage B testnet gas ceiling. Holds a single maximum [`GasBudgetMist`]
/// and validates requested budgets against it BEFORE the call builder emits
/// dry-run bytes. `Copy` (a single `GasBudgetMist` field); no heap, no owned
/// bytes.
///
/// The policy enforces two invariants on every accepted budget:
/// 1. non-zero (`MIST > 0`) — Sui rejects a zero-budget tx; and
/// 2. within the ceiling (`MIST <= max`) — fail-closed against a fat-fingered
///    or overflowing budget.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub struct StageBGasBudgetPolicy {
    /// Inclusive maximum gas budget this policy will accept.
    max: GasBudgetMist,
}

impl StageBGasBudgetPolicy {
    /// Build a policy with an explicit ceiling. `const` so a policy can be
    /// built in a const context. The ceiling itself is NOT required to be
    /// non-zero here — a zero ceiling is a valid (if useless) "reject
    /// everything" policy, since [`Self::check`] rejects a zero *request*
    /// before comparing against the ceiling.
    #[inline]
    pub const fn new(max: GasBudgetMist) -> Self {
        Self { max }
    }

    /// Build a policy seeded with the documented Stage-B default ceiling
    /// ([`STAGE_B_DEFAULT_MAX_GAS_MIST`] = 1 SUI in MIST).
    #[inline]
    pub const fn with_default_cap() -> Self {
        Self::new(GasBudgetMist::new(STAGE_B_DEFAULT_MAX_GAS_MIST))
    }

    /// Borrow the configured ceiling.
    #[inline]
    pub const fn max(&self) -> GasBudgetMist {
        self.max
    }

    /// Validate a single requested gas budget against the policy. Returns the
    /// same budget on success so the call site can thread the validated value
    /// straight into the call builder.
    ///
    /// Reject order: zero first ([`StageBGasError::GasBudgetZero`]), then over
    /// the ceiling ([`StageBGasError::GasBudgetCapExceeded`]). The boundary
    /// `requested == max` is ACCEPTED (the ceiling is inclusive).
    #[inline]
    pub const fn check(&self, requested: GasBudgetMist) -> Result<GasBudgetMist, StageBGasError> {
        if requested.get() == 0 {
            return Err(StageBGasError::GasBudgetZero);
        }
        if requested.get() > self.max.get() {
            return Err(StageBGasError::GasBudgetCapExceeded);
        }
        Ok(requested)
    }

    /// Sum a slice of per-call gas budgets with checked `u64` addition, then
    /// validate the total against the policy. Used when a single Stage B
    /// session fans a budget across several calls (e.g. `create_root` +
    /// `add_chunk` + `audit_log::append`) and the aggregate must stay under
    /// the ceiling.
    ///
    /// Reject order:
    /// 1. any `u64` overflow while accumulating →
    ///    [`StageBGasError::GasBudgetAdditionOverflow`];
    /// 2. then the total is run through [`Self::check`] — an empty slice (or
    ///    a slice of all-zero budgets) totals zero and is rejected with
    ///    [`StageBGasError::GasBudgetZero`]; an over-ceiling total is rejected
    ///    with [`StageBGasError::GasBudgetCapExceeded`].
    #[inline]
    pub fn checked_total(
        &self,
        budgets: &[GasBudgetMist],
    ) -> Result<GasBudgetMist, StageBGasError> {
        let mut total: u64 = 0;
        for budget in budgets {
            total = total
                .checked_add(budget.get())
                .ok_or(StageBGasError::GasBudgetAdditionOverflow)?;
        }
        self.check(GasBudgetMist::new(total))
    }
}

// ===========================================================================
// 5. Inline unit tests (module-internal invariants only)
// ===========================================================================

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use core::mem::size_of;

    fn policy(cap: u64) -> StageBGasBudgetPolicy {
        StageBGasBudgetPolicy::new(GasBudgetMist::new(cap))
    }

    /// `zero reject`: a zero request is rejected on both the single-budget and
    /// the accumulated path, and an empty slice (total zero) is rejected too.
    #[test]
    fn b3_14_zero_rejected() {
        let p = policy(1_000_000);
        assert_eq!(
            p.check(GasBudgetMist::new(0)),
            Err(StageBGasError::GasBudgetZero)
        );
        assert_eq!(
            p.checked_total(&[GasBudgetMist::new(0)]),
            Err(StageBGasError::GasBudgetZero)
        );
        // Empty slice totals zero → same zero reject.
        assert_eq!(p.checked_total(&[]), Err(StageBGasError::GasBudgetZero));
        // All-zero slice also totals zero.
        assert_eq!(
            p.checked_total(&[GasBudgetMist::new(0), GasBudgetMist::new(0)]),
            Err(StageBGasError::GasBudgetZero)
        );
    }

    /// `cap reject`: over the ceiling is rejected; the inclusive boundary
    /// `requested == max` and one below are accepted (and the validated value
    /// is returned verbatim).
    #[test]
    fn b3_14_cap_rejected() {
        const CAP: u64 = 800_000;
        let p = policy(CAP);

        assert_eq!(
            p.check(GasBudgetMist::new(CAP + 1)),
            Err(StageBGasError::GasBudgetCapExceeded)
        );
        // Boundary equal is accepted (inclusive ceiling) and echoed back.
        assert_eq!(
            p.check(GasBudgetMist::new(CAP)),
            Ok(GasBudgetMist::new(CAP))
        );
        // One below is accepted.
        assert_eq!(
            p.check(GasBudgetMist::new(CAP - 1)),
            Ok(GasBudgetMist::new(CAP - 1))
        );
        // The accumulated path applies the same ceiling.
        assert_eq!(
            p.checked_total(&[GasBudgetMist::new(CAP), GasBudgetMist::new(1)]),
            Err(StageBGasError::GasBudgetCapExceeded)
        );
    }

    /// `checked addition`: a normal sum stays under the ceiling and returns the
    /// total; a `u64` overflow is caught as `GasBudgetAdditionOverflow` (not a
    /// silent wrap, not a panic).
    #[test]
    fn b3_14_checked_addition() {
        let p = policy(1_000_000);

        // Normal accumulation: 100k + 250k + 300k = 650k <= 1_000_000.
        assert_eq!(
            p.checked_total(&[
                GasBudgetMist::new(100_000),
                GasBudgetMist::new(250_000),
                GasBudgetMist::new(300_000),
            ]),
            Ok(GasBudgetMist::new(650_000))
        );

        // u64 overflow is caught before the cap check (overflow reject wins).
        assert_eq!(
            p.checked_total(&[GasBudgetMist::new(u64::MAX), GasBudgetMist::new(1)]),
            Err(StageBGasError::GasBudgetAdditionOverflow)
        );

        // A single-element slice round-trips through the accumulator.
        assert_eq!(
            p.checked_total(&[GasBudgetMist::new(42)]),
            Ok(GasBudgetMist::new(42))
        );
    }

    /// Reuse pin — the gas unit stays the 8-byte newtype (no second
    /// gas type minted here).
    #[test]
    fn b3_14_gas_budget_mist_reuse_is_8_bytes() {
        assert_eq!(size_of::<GasBudgetMist>(), 8);
        // Policy is just that one field → also 8 bytes, Copy.
        assert_eq!(size_of::<StageBGasBudgetPolicy>(), 8);
        fn assert_copy<T: Copy>() {}
        assert_copy::<StageBGasBudgetPolicy>();
        assert_copy::<StageBGasError>();
    }

    /// Class labels are namespaced `stage_b_gas.*` and pairwise unique.
    #[test]
    fn b3_14_class_labels_namespaced_unique() {
        let labels = [
            StageBGasError::GasBudgetZero.class_label(),
            StageBGasError::GasBudgetCapExceeded.class_label(),
            StageBGasError::GasBudgetAdditionOverflow.class_label(),
        ];
        for label in labels {
            assert!(
                label.starts_with("stage_b_gas."),
                "class label {label} not under stage_b_gas.*"
            );
        }
        for i in 0..labels.len() {
            for j in (i + 1)..labels.len() {
                assert_ne!(labels[i], labels[j]);
            }
        }
    }

    /// The default ceiling is 1 SUI = 10^9 MIST and threads through
    /// `with_default_cap`.
    #[test]
    fn b3_14_default_cap_is_one_sui_in_mist() {
        assert_eq!(STAGE_B_DEFAULT_MAX_GAS_MIST, 1_000_000_000);
        assert_eq!(
            StageBGasBudgetPolicy::with_default_cap().max().get(),
            1_000_000_000
        );
        // A typical 800k-MIST budget is well within the default ceiling.
        assert_eq!(
            StageBGasBudgetPolicy::with_default_cap().check(GasBudgetMist::new(800_000)),
            Ok(GasBudgetMist::new(800_000))
        );
    }
}
