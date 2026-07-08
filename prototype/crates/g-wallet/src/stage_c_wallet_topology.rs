//! Stage C cold treasury / hot sponsor topology.
//!
//! The cold-treasury / hot-sponsor wallet topology.
//!
//! # Invariants
//!
//! * **Hot wallet loss is capped.** The hot sponsor's standing balance cap
//!   ([`hot_balance_cap`](ColdHotTopology::hot_balance_cap)) is strictly below
//!   the [`daily_burn_cap`](ColdHotTopology::daily_burn_cap), so the hot wallet
//!   never holds a full day's gas at once — if the hot key is compromised the
//!   loss is bounded to less than one day's budget, not the whole treasury. A
//!   topology with `hot_balance_cap >= daily_burn_cap` is rejected fail-closed
//!   with [`WalletTopologyError::HotCapNotBelowDailyBurn`].
//! * **Cold treasury requires multisig.** [`ColdHotTopology::new`] takes a
//!   `&`[`MultisigRoster`] (`threshold >= 2` by construction) and
//!   binds the cold treasury to its signer-set hash. The topology is
//!   *unrepresentable* without a multisig roster — a single-key cold treasury
//!   cannot be built, not merely discouraged.
//! * **Rate-limited refill, disabled by default.** `auto_refill_enabled` is
//!   `false` after [`new`](ColdHotTopology::new); it can only be turned on by an
//!   explicit [`enable_auto_refill`](ColdHotTopology::enable_auto_refill) opt-in.
//!   The per-epoch refill cap is non-zero and cannot exceed the hot balance cap
//!   ([`WalletTopologyError::RefillCapExceedsHotCap`]), so a single refill can
//!   never push the hot wallet above its loss bound.
//! * **Inert datatype, no execution.** No I/O, no network, no `sui` invocation,
//!   no transfer, no gas spend. This is the topology policy a later ceremony
//!   reads; `MainnetExecutionState` stays `Locked`.
//!
//! # Reuse
//!
//! * `SuiAddress` — [`mnemos_d_move::types::SuiAddress`]
//!   (`d-move/src/types.rs:134`).
//! * `GasBudgetMist` — [`mnemos_d_move::types::GasBudgetMist`]
//!   (`d-move/src/types.rs:109`); the cap fields are typed gas units, not raw
//!   `u64`.
//! * `MultisigRoster` — [`crate::stage_c_multisig::MultisigRoster`]; the cold
//!   treasury binds to its `signer_hash`. No parallel roster is minted.

use mnemos_d_move::types::{GasBudgetMist, SuiAddress};

use crate::stage_c_multisig::MultisigRoster;

/// The cold-treasury / hot-sponsor wallet topology.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub struct ColdHotTopology {
    /// The cold treasury address. Spends require the bound multisig roster.
    pub cold_treasury: SuiAddress,
    /// The hot sponsor address. Loss is bounded by `hot_balance_cap`.
    pub hot_sponsor: SuiAddress,
    /// The signer-set hash of the multisig roster gating the cold treasury
    /// (`MultisigRoster::signer_hash`).
    pub cold_roster_hash_32: [u8; 32],
    /// Maximum standing balance the hot sponsor may hold — the loss bound.
    /// Strictly below `daily_burn_cap` by construction.
    pub hot_balance_cap: GasBudgetMist,
    /// Maximum gas burned per day across all sponsored transactions.
    pub daily_burn_cap: GasBudgetMist,
    /// Maximum amount a single rate-limited refill may move cold → hot. Non-zero
    /// and `<= hot_balance_cap` by construction.
    pub refill_per_epoch_cap: GasBudgetMist,
    /// Whether automatic cold → hot refill is enabled. `false` after `new`;
    /// turned on only by an explicit opt-in.
    pub auto_refill_enabled: bool,
}

/// Topology construction error. Every variant is data-free.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
#[repr(u8)]
pub enum WalletTopologyError {
    /// The cold treasury and hot sponsor were the same address.
    TreasuryEqualsSponsor = 1,
    /// The hot balance cap was zero.
    HotCapZero = 2,
    /// The daily burn cap was zero.
    DailyBurnCapZero = 3,
    /// The hot balance cap was not strictly below the daily burn cap — the loss
    /// bound would let the hot wallet hold a full day's gas.
    HotCapNotBelowDailyBurn = 4,
    /// The per-epoch refill cap was zero.
    RefillCapZero = 5,
    /// The per-epoch refill cap exceeded the hot balance cap — a single refill
    /// could push the hot wallet above its loss bound.
    RefillCapExceedsHotCap = 6,
}

impl core::fmt::Display for WalletTopologyError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let msg = match self {
            Self::TreasuryEqualsSponsor => {
                "stage_c wallet topology: cold treasury equals hot sponsor"
            }
            Self::HotCapZero => "stage_c wallet topology: hot balance cap is zero",
            Self::DailyBurnCapZero => "stage_c wallet topology: daily burn cap is zero",
            Self::HotCapNotBelowDailyBurn => {
                "stage_c wallet topology: hot balance cap not below daily burn cap"
            }
            Self::RefillCapZero => "stage_c wallet topology: per-epoch refill cap is zero",
            Self::RefillCapExceedsHotCap => {
                "stage_c wallet topology: per-epoch refill cap exceeds hot balance cap"
            }
        };
        f.write_str(msg)
    }
}

impl core::error::Error for WalletTopologyError {}

impl ColdHotTopology {
    /// Build a cold/hot topology. The cold treasury is bound to a multisig
    /// roster (`threshold >= 2`), so a single-key cold treasury is
    /// unrepresentable. `auto_refill_enabled` starts `false`.
    ///
    /// # Errors
    ///
    /// - [`WalletTopologyError::TreasuryEqualsSponsor`] when the two addresses
    ///   are equal.
    /// - [`WalletTopologyError::HotCapZero`] / [`WalletTopologyError::DailyBurnCapZero`]
    ///   / [`WalletTopologyError::RefillCapZero`] on a zero cap.
    /// - [`WalletTopologyError::HotCapNotBelowDailyBurn`] when `hot_balance_cap >=
    ///   daily_burn_cap`.
    /// - [`WalletTopologyError::RefillCapExceedsHotCap`] when `refill_per_epoch_cap
    ///   > hot_balance_cap`.
    pub fn new(
        cold_treasury: SuiAddress,
        hot_sponsor: SuiAddress,
        cold_roster: &MultisigRoster,
        hot_balance_cap: GasBudgetMist,
        daily_burn_cap: GasBudgetMist,
        refill_per_epoch_cap: GasBudgetMist,
    ) -> Result<Self, WalletTopologyError> {
        if cold_treasury == hot_sponsor {
            return Err(WalletTopologyError::TreasuryEqualsSponsor);
        }
        if hot_balance_cap.get() == 0 {
            return Err(WalletTopologyError::HotCapZero);
        }
        if daily_burn_cap.get() == 0 {
            return Err(WalletTopologyError::DailyBurnCapZero);
        }
        if hot_balance_cap.get() >= daily_burn_cap.get() {
            return Err(WalletTopologyError::HotCapNotBelowDailyBurn);
        }
        if refill_per_epoch_cap.get() == 0 {
            return Err(WalletTopologyError::RefillCapZero);
        }
        if refill_per_epoch_cap.get() > hot_balance_cap.get() {
            return Err(WalletTopologyError::RefillCapExceedsHotCap);
        }
        Ok(Self {
            cold_treasury,
            hot_sponsor,
            cold_roster_hash_32: cold_roster.signer_hash(),
            hot_balance_cap,
            daily_burn_cap,
            refill_per_epoch_cap,
            auto_refill_enabled: false,
        })
    }

    /// Explicit opt-in to automatic cold → hot refill. Off by default; the
    /// caller must call this to enable it.
    #[inline]
    #[must_use]
    pub const fn enable_auto_refill(mut self) -> Self {
        self.auto_refill_enabled = true;
        self
    }

    /// The multisig signer-set hash gating the cold treasury.
    #[inline]
    #[must_use]
    pub const fn cold_roster_hash(&self) -> [u8; 32] {
        self.cold_roster_hash_32
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    #![allow(clippy::expect_used)]
    #![allow(clippy::panic)]

    use super::*;

    fn roster() -> MultisigRoster {
        MultisigRoster::from_signers(
            &[SuiAddress::new([0x11; 32]), SuiAddress::new([0x22; 32])],
            2,
        )
        .expect("2-of-2 roster builds")
    }

    /// `c2_9_hot_cap_below_daily_burn` — a topology where the hot balance cap is
    /// strictly below the daily burn cap is accepted; one where it is equal or
    /// above is fail-closed.
    #[test]
    fn c2_9_hot_cap_below_daily_burn() {
        let r = roster();
        // hot cap (100k) < daily burn (1M) → accepted.
        let topo = ColdHotTopology::new(
            SuiAddress::new([0xAA; 32]),
            SuiAddress::new([0xBB; 32]),
            &r,
            GasBudgetMist::new(100_000),
            GasBudgetMist::new(1_000_000),
            GasBudgetMist::new(50_000),
        )
        .unwrap();
        assert_eq!(topo.hot_balance_cap.get(), 100_000);
        assert!(topo.hot_balance_cap.get() < topo.daily_burn_cap.get());

        // hot cap == daily burn → rejected.
        assert_eq!(
            ColdHotTopology::new(
                SuiAddress::new([0xAA; 32]),
                SuiAddress::new([0xBB; 32]),
                &r,
                GasBudgetMist::new(1_000_000),
                GasBudgetMist::new(1_000_000),
                GasBudgetMist::new(50_000),
            ),
            Err(WalletTopologyError::HotCapNotBelowDailyBurn),
        );
        // hot cap > daily burn → rejected.
        assert_eq!(
            ColdHotTopology::new(
                SuiAddress::new([0xAA; 32]),
                SuiAddress::new([0xBB; 32]),
                &r,
                GasBudgetMist::new(2_000_000),
                GasBudgetMist::new(1_000_000),
                GasBudgetMist::new(50_000),
            ),
            Err(WalletTopologyError::HotCapNotBelowDailyBurn),
        );
    }

    /// `c2_9_cold_requires_multisig` — the cold treasury binds to the roster's
    /// signer-set hash; the topology cannot be built without a `&MultisigRoster`
    /// (a `threshold >= 2` value), so a single-key cold treasury is
    /// unrepresentable.
    #[test]
    fn c2_9_cold_requires_multisig() {
        let r = roster();
        assert!(r.threshold_u8 >= 2);
        let topo = ColdHotTopology::new(
            SuiAddress::new([0xAA; 32]),
            SuiAddress::new([0xBB; 32]),
            &r,
            GasBudgetMist::new(100_000),
            GasBudgetMist::new(1_000_000),
            GasBudgetMist::new(50_000),
        )
        .unwrap();
        assert_eq!(topo.cold_roster_hash(), r.signer_hash());
        assert_ne!(topo.cold_roster_hash(), [0u8; 32]);
    }

    /// `c2_9_auto_refill_disabled_by_default` — refill is off after `new` and
    /// only an explicit opt-in turns it on.
    #[test]
    fn c2_9_auto_refill_disabled_by_default() {
        let r = roster();
        let topo = ColdHotTopology::new(
            SuiAddress::new([0xAA; 32]),
            SuiAddress::new([0xBB; 32]),
            &r,
            GasBudgetMist::new(100_000),
            GasBudgetMist::new(1_000_000),
            GasBudgetMist::new(50_000),
        )
        .unwrap();
        assert!(!topo.auto_refill_enabled);
        let enabled = topo.enable_auto_refill();
        assert!(enabled.auto_refill_enabled);
    }

    /// `c2_9_reject_edges` — treasury==sponsor, zero caps, and a refill cap above
    /// the hot cap are all fail-closed.
    #[test]
    fn c2_9_reject_edges() {
        let r = roster();
        let same = SuiAddress::new([0xAA; 32]);
        assert_eq!(
            ColdHotTopology::new(
                same,
                same,
                &r,
                GasBudgetMist::new(100_000),
                GasBudgetMist::new(1_000_000),
                GasBudgetMist::new(50_000),
            ),
            Err(WalletTopologyError::TreasuryEqualsSponsor),
        );
        // refill cap (200k) > hot cap (100k) → rejected.
        assert_eq!(
            ColdHotTopology::new(
                SuiAddress::new([0xAA; 32]),
                SuiAddress::new([0xBB; 32]),
                &r,
                GasBudgetMist::new(100_000),
                GasBudgetMist::new(1_000_000),
                GasBudgetMist::new(200_000),
            ),
            Err(WalletTopologyError::RefillCapExceedsHotCap),
        );
        // zero hot cap → rejected.
        assert_eq!(
            ColdHotTopology::new(
                SuiAddress::new([0xAA; 32]),
                SuiAddress::new([0xBB; 32]),
                &r,
                GasBudgetMist::new(0),
                GasBudgetMist::new(1_000_000),
                GasBudgetMist::new(50_000),
            ),
            Err(WalletTopologyError::HotCapZero),
        );
    }
}
