//! Stage C sponsor hot-wallet policy (C-WP-07 · atom #229 · C.2.10).
//!
//! Canonical OUT (§4.3): [`SponsorHotWalletPolicy`].
//!
//! # Madness invariants (atom #229)
//!
//! * **Bounded loss.** A sponsor hot wallet pays gas; it is *expected* to be
//!   drainable. The policy caps the daily burn and the number of concurrent gas
//!   coin leases so that, in the worst case, only the hot wallet empties — the
//!   cold treasury is never reachable from this surface. There is no signer, no
//!   transaction submitter and no key material anywhere in this module: it is a
//!   pure typed cap policy.
//! * **Caps must be real.** A zero cap (nothing can ever be sponsored) and an
//!   unbounded cap (`u64::MAX` daily burn / `u16::MAX` leases — effectively no
//!   cap at all) are both rejected at construction. A cap only protects the
//!   treasury if it is a finite, non-zero number.
//! * **Checked arithmetic.** Accumulating today's spend against the daily cap
//!   uses checked addition; an overflowing accumulator is a rejected request,
//!   never a silent wrap to a small (passing) number.
//!
//! # Reuse map (atom contract)
//!
//! * **reuse: A [`SuiAddress`](mnemos_d_move::types::SuiAddress),
//!   [`GasBudgetMist`](mnemos_d_move::types::GasBudgetMist)** — the hot-wallet
//!   address and the daily burn cap are the d-move §4.D canonical types, not
//!   re-minted.
//!
//! This surface produces no live action. `MainnetExecutionState` stays
//! [`Locked`](mnemos_a_core::stage_c_env::MainnetExecutionState::Locked); gas
//! spend authorization remains behind the atom #227 signer boundary.

use mnemos_d_move::types::{GasBudgetMist, SuiAddress};

/// The largest representable daily burn cap, treated as "unbounded" and refused
/// — a cap that can never be hit is not a cap.
pub const UNBOUNDED_DAILY_BURN_MIST: u64 = u64::MAX;

/// The largest representable lease cap, treated as "unbounded" and refused.
pub const UNBOUNDED_MAX_COIN_LEASES: u16 = u16::MAX;

/// Sponsor hot-wallet cap policy (§4.3). Three typed fields, no key material.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub struct SponsorHotWalletPolicy {
    /// The hot wallet that pays sponsored gas. Distinct from the cold treasury.
    pub hot_wallet: SuiAddress,
    /// The per-day burn cap in MIST. Finite and non-zero by construction.
    pub daily_burn_cap: GasBudgetMist,
    /// The maximum number of gas coin leases that may be inflight concurrently.
    /// Finite and non-zero by construction.
    pub max_coin_leases_u16: u16,
}

/// Hot-wallet policy construction / accounting error. Every variant is
/// data-free.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
#[repr(u8)]
pub enum HotWalletPolicyError {
    /// The daily burn cap was zero — nothing could ever be sponsored.
    DailyBurnCapZero = 1,
    /// The daily burn cap was `u64::MAX` — effectively unbounded.
    DailyBurnCapUnbounded = 2,
    /// The lease cap was zero — no lease could ever be granted.
    LeaseCapZero = 3,
    /// The lease cap was `u16::MAX` — effectively unbounded.
    LeaseCapUnbounded = 4,
    /// Accumulating a spend against the daily cap overflowed `u64`.
    SpendAccumulatorOverflow = 5,
    /// A spend would exceed the remaining daily burn cap.
    DailyBurnCapExceeded = 6,
}

impl core::fmt::Display for HotWalletPolicyError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let msg = match self {
            Self::DailyBurnCapZero => "stage_c hot wallet: daily burn cap must be non-zero",
            Self::DailyBurnCapUnbounded => "stage_c hot wallet: daily burn cap must be bounded",
            Self::LeaseCapZero => "stage_c hot wallet: lease cap must be non-zero",
            Self::LeaseCapUnbounded => "stage_c hot wallet: lease cap must be bounded",
            Self::SpendAccumulatorOverflow => "stage_c hot wallet: spend accumulator overflow",
            Self::DailyBurnCapExceeded => "stage_c hot wallet: daily burn cap exceeded",
        };
        f.write_str(msg)
    }
}

impl core::error::Error for HotWalletPolicyError {}

impl SponsorHotWalletPolicy {
    /// Build a hot-wallet policy, rejecting zero and unbounded caps.
    ///
    /// # Errors
    ///
    /// [`HotWalletPolicyError::DailyBurnCapZero`] /
    /// [`HotWalletPolicyError::DailyBurnCapUnbounded`] /
    /// [`HotWalletPolicyError::LeaseCapZero`] /
    /// [`HotWalletPolicyError::LeaseCapUnbounded`] as appropriate.
    pub const fn new(
        hot_wallet: SuiAddress,
        daily_burn_cap: GasBudgetMist,
        max_coin_leases_u16: u16,
    ) -> Result<Self, HotWalletPolicyError> {
        let cap = daily_burn_cap.get();
        if cap == 0 {
            return Err(HotWalletPolicyError::DailyBurnCapZero);
        }
        if cap == UNBOUNDED_DAILY_BURN_MIST {
            return Err(HotWalletPolicyError::DailyBurnCapUnbounded);
        }
        if max_coin_leases_u16 == 0 {
            return Err(HotWalletPolicyError::LeaseCapZero);
        }
        if max_coin_leases_u16 == UNBOUNDED_MAX_COIN_LEASES {
            return Err(HotWalletPolicyError::LeaseCapUnbounded);
        }
        Ok(Self {
            hot_wallet,
            daily_burn_cap,
            max_coin_leases_u16,
        })
    }

    /// Whether a number of concurrent leases is within the policy cap.
    #[inline]
    #[must_use]
    pub const fn leases_within_cap(&self, inflight_leases_u16: u16) -> bool {
        inflight_leases_u16 <= self.max_coin_leases_u16
    }

    /// Add `spend` to the running daily total and verify it stays within the
    /// daily burn cap. Returns the new running total on success.
    ///
    /// # Errors
    ///
    /// [`HotWalletPolicyError::SpendAccumulatorOverflow`] if the running total
    /// would overflow `u64`, and [`HotWalletPolicyError::DailyBurnCapExceeded`]
    /// if it would exceed the daily burn cap.
    pub const fn accumulate_spend(
        &self,
        running_total: GasBudgetMist,
        spend: GasBudgetMist,
    ) -> Result<GasBudgetMist, HotWalletPolicyError> {
        let next = match running_total.get().checked_add(spend.get()) {
            Some(v) => v,
            None => return Err(HotWalletPolicyError::SpendAccumulatorOverflow),
        };
        if next > self.daily_burn_cap.get() {
            return Err(HotWalletPolicyError::DailyBurnCapExceeded);
        }
        Ok(GasBudgetMist::new(next))
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]
    use super::*;

    fn addr() -> SuiAddress {
        SuiAddress::new([0x11; 32])
    }

    #[test]
    fn cap_zero_reject() {
        assert_eq!(
            SponsorHotWalletPolicy::new(addr(), GasBudgetMist::new(0), 4),
            Err(HotWalletPolicyError::DailyBurnCapZero)
        );
        assert_eq!(
            SponsorHotWalletPolicy::new(addr(), GasBudgetMist::new(1_000), 0),
            Err(HotWalletPolicyError::LeaseCapZero)
        );
    }

    #[test]
    fn unbounded_cap_reject() {
        assert_eq!(
            SponsorHotWalletPolicy::new(addr(), GasBudgetMist::new(UNBOUNDED_DAILY_BURN_MIST), 4),
            Err(HotWalletPolicyError::DailyBurnCapUnbounded)
        );
        assert_eq!(
            SponsorHotWalletPolicy::new(
                addr(),
                GasBudgetMist::new(1_000),
                UNBOUNDED_MAX_COIN_LEASES
            ),
            Err(HotWalletPolicyError::LeaseCapUnbounded)
        );
    }

    #[test]
    fn cap_arithmetic_checked() {
        let p = SponsorHotWalletPolicy::new(addr(), GasBudgetMist::new(1_000), 4)
            .expect("valid policy");
        // Within cap accumulates.
        let t1 = p
            .accumulate_spend(GasBudgetMist::new(0), GasBudgetMist::new(600))
            .expect("under cap");
        assert_eq!(t1.get(), 600);
        // Crossing the cap is rejected, not wrapped.
        assert_eq!(
            p.accumulate_spend(t1, GasBudgetMist::new(600)),
            Err(HotWalletPolicyError::DailyBurnCapExceeded)
        );
        // Overflowing the accumulator is rejected, not wrapped to a small value.
        assert_eq!(
            p.accumulate_spend(GasBudgetMist::new(u64::MAX), GasBudgetMist::new(1)),
            Err(HotWalletPolicyError::SpendAccumulatorOverflow)
        );
        // Lease cap boundary.
        assert!(p.leases_within_cap(4));
        assert!(!p.leases_within_cap(5));
    }
}
