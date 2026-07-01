//! `skew_oracle` — MNEMOS × SKEW K-1: the PURE, byte-locked TRADE ORACLE. Given a proposed Skew
//! trade + the owner's bound numbers, it RE-DERIVES Skew's OWN worst-case escrow LOCALLY and returns
//! a TYPED, fail-closed verdict (AFFORDABLE & IN-BOUNDS | DENIED(reason)) — with **no LLM judge, no
//! signing, money 0**. This is C-3's first concrete domain + Sinabro as a 4th verification lane atop
//! Skew's on-chain solvency, and the §2 thesis made real: on the collateralized path the trade's
//! worst-case escrow IS the max loss, so `Σ(escrows) ≤ total_budget ⇒ total max loss ≤ total_budget`
//! — a **theorem**, not a probability.
//!
//! ## PURE + byte-locked (money 0, no key, no network, no Solana-crate dep; mirrors `skew_read`)
//! Every worst-case formula is copied **byte-exact** from the verified Skew source — NOT hand-guessed
//! ([[no-formula-guessing]]). Sources (read 2026-06-30):
//! - **USM-VM (0x81)** — `skew-mainnet/sdk/src/collateral/policy.ts:39-69` (`resolveUsmVm`):
//!   `required_initial = notional × initial_bps / 10_000` (BigInt floor div; the SDK keyless
//!   `previewCollateral` readout, the user's "read the margin → deposit exactly that" primitive).
//! - **FIXED-LOCK (0x11)** — `policy.ts:79-94` (`resolveFixedLock`): `required_initial = locked_amount`.
//! - **WCC affine corner (0x1B)** — `programs/skew_otc/src/collateral/wcc.rs:312-398`
//!   (`WccCollateralPolicy::evaluate`): `WCL = q · cs · max(0, gap)` (Long `gap = Pc − collar_lo`,
//!   Short `gap = collar_hi − Pc`), with the UDSI P7 ceiling `WCL ≤ u64::MAX`. The analytic envelope
//!   of ANY affine forward/swap/collar over the declared collar.
//! - **Perp `epoch_wcl_linear`** — `programs/skew_otc/src/perp/epoch_wcl.rs:47-91`:
//!   `E_epoch = cs · |q| · max(0, corner-gap) + |q| · funding_cap` (long worst at `lo`, short at
//!   `hi`). Honest scope: perp is ISOLATED margin + funding/`force_reduce`, so its bound is
//!   "free collateral at risk + funding," weaker than "initial escrow = max loss" (§2).
//! - **Perp `e_epoch_from_notional`** — `programs/skew_otc/src/perp/position_math.rs:165-194`: the
//!   SAME `E_epoch` from a stored net `position_notional` (reproduces a live `PerpPositionPda`'s
//!   on-chain `reserved_collateral` from its decoded fields).
//! - **Certified per-unit bound** — `programs/skew_otc/src/state/product_template.rs:483` stores a
//!   permissionless WCC template's chain-certified per-unit `wcl_bound_atoms` (`max(certified_long,
//!   certified_short)`); for non-affine / piecewise families the SOUND worst-case escrow upper bound
//!   for `qty` units is `qty × wcl_bound_atoms` (the protocol's OWN certified number, never a guess).
//!
//! ## Honest scope (K-1)
//! - The clean max-loss **theorem** holds on the collateralized path (USM-VM / FIXED-LOCK / WCC
//!   affine / certified-bound). Perp is modelled honestly as a weaker (isolated + funding) bound.
//! - The oracle DECIDES with deterministic integer math; the model only PROPOSES the trade. It does
//!   NOT sign, does NOT broadcast, does NOT mint a capability, does NOT dial the chain (the live
//!   portfolio comes from K-0's read). The owner bounds are PLAIN NUMBERS — the oracle never touches
//!   the grant machinery; the real `CustodyGrant` authorize + signing transport is K-2.
//! - For non-affine / piecewise instruments the oracle uses the chain's certified per-unit bound
//!   (a sound upper bound on escrow = affordability-correct); the exact grid-max re-derivation from
//!   decoded payoff breakpoints is the next deepening.

/// The owner's bound numbers the verdict checks a trade against. PLAIN integer minor units (no float,
/// no grant-machinery type) — the oracle is fully decoupled from `commands::grant` (the real
/// `CustodyGrant` authorize is K-2). Every field is an UPPER limit.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct OracleBounds {
    /// The maximum worst-case escrow of a SINGLE trade (the per-tx ceiling).
    pub per_tx_max_minor: u128,
    /// The maximum CUMULATIVE escrow across all trades under the grant (the total budget).
    pub total_budget_minor: u128,
    /// The maximum acceptable resulting portfolio worst-case (the owner's drawdown dial). Set equal
    /// to `total_budget_minor` for the clean `Σ(escrows) ≤ budget` theorem, or tighter.
    pub drawdown_max_minor: u128,
}

/// Why the oracle did not affirm a trade (fail-closed; explicit). Mirrors the bound-breach reasons of
/// `commands::grant::CustodyDenied` (the K-2 authorize) so the two layers speak the same language.
#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OracleDenied {
    /// The worst-case formula could not be re-derived (checked-arith overflow, empty band, or an
    /// out-of-range parameter) — fail-closed, never a fabricated escrow.
    InvalidParams = 1,
    /// `escrow > per_tx_max` — the single-trade ceiling is exceeded.
    PerTxExceeded = 2,
    /// `spent + escrow > total_budget` (or the sum overflowed) — the budget is exceeded.
    BudgetExceeded = 3,
    /// `portfolio_locked + escrow > drawdown_max` (or the sum overflowed) — the drawdown bound is
    /// exceeded (the resulting portfolio worst-case is too large).
    DrawdownExceeded = 4,
}

impl OracleDenied {
    /// Stable display label.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::InvalidParams => "invalid-params (worst-case not re-derivable; fail-closed)",
            Self::PerTxExceeded => "per-tx-exceeded (escrow > per_tx_max)",
            Self::BudgetExceeded => "budget-exceeded (spent + escrow > total_budget)",
            Self::DrawdownExceeded => "drawdown-exceeded (portfolio + escrow > drawdown_max)",
        }
    }
}

/// The oracle's typed verdict for one proposed trade.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TradeVerdict {
    /// The trade's worst-case escrow is affordable AND within every owner bound.
    AffordableInBounds {
        /// The re-derived worst-case escrow (minor units) — the exact amount the chain would lock.
        escrow_minor: u128,
    },
    /// The trade is refused, with the reason (fail-closed).
    Denied(OracleDenied),
}

impl TradeVerdict {
    /// Did the oracle affirm the trade?
    #[must_use]
    pub const fn is_affordable(self) -> bool {
        matches!(self, Self::AffordableInBounds { .. })
    }
}

// ============================================================================
// Collateral policy classification (byte-locked policy ids).
// ============================================================================

/// `SKEW_COLLATERAL_USM_VM_V1` dispatcher byte (`usm_vm.rs:60`; stored u16 = `0x0F81`, low byte 0x81).
pub const POLICY_ID_USM_VM: u8 = 0x81;
/// `SKEW_COLLATERAL_FIXED_LOCK_V1` dispatcher byte (`fixed_lock.rs:35`; stored u16 = `0x2511`).
pub const POLICY_ID_FIXED_LOCK: u8 = 0x11;
/// `SKEW_COLLATERAL_WCC_V1` dispatcher byte (`wcc.rs:58`; stored u16 = `0x1B1B`, low byte 0x1B).
pub const POLICY_ID_WCC: u8 = 0x1B;

/// A template's collateral policy, classified from its (u16) `collateral_policy_id`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CollateralPolicyClass {
    /// USM-VM (variation-margin forward): escrow = `notional × initial_bps / 10_000`.
    UsmVm,
    /// FIXED-LOCK: escrow = `locked_amount`.
    FixedLock,
    /// WCC (worst-case-collateralized, the UDSI default): escrow = the affine corner WCL, or, for a
    /// permissionless listing, the certified per-unit `wcl_bound_atoms`.
    Wcc,
    /// A policy id outside the K-1 set (carries the raw u16).
    Other(u16),
}

impl CollateralPolicyClass {
    /// Stable display label.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::UsmVm => "USM-VM (0x81)",
            Self::FixedLock => "FIXED-LOCK (0x11)",
            Self::Wcc => "WCC (0x1B)",
            Self::Other(_) => "other",
        }
    }
}

/// Classify a template's (u16) `collateral_policy_id` by its dispatcher LOW byte — the canonical
/// dispatcher id the program narrows to (`(POLICY_ID_U16 as u8) == POLICY_ID` is a source invariant;
/// `usm_vm.rs:401-404`), so this is robust to both the legacy u8-range and the widened u16 storage.
#[must_use]
pub fn classify_collateral_policy(collateral_policy_id: u16) -> CollateralPolicyClass {
    match (collateral_policy_id & 0x00FF) as u8 {
        POLICY_ID_USM_VM => CollateralPolicyClass::UsmVm,
        POLICY_ID_FIXED_LOCK => CollateralPolicyClass::FixedLock,
        POLICY_ID_WCC => CollateralPolicyClass::Wcc,
        _ => CollateralPolicyClass::Other(collateral_policy_id),
    }
}

// ============================================================================
// Byte-exact worst-case escrow primitives (each fail-closed → Option<u128>).
// ============================================================================

/// Which side of an affine forward / perp this trade sits on. Mirrors
/// `wcc::WccPartyDirection`: a Long loses as the price FALLS (worst at the collar LOW), a Short loses
/// as it RISES (worst at the collar HIGH).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PartyDirection {
    /// Long the forward: loss when settlement `< Pc`; worst at `collar_lo`.
    Long,
    /// Short the forward: loss when settlement `> Pc`; worst at `collar_hi`.
    Short,
}

/// USM-VM (0x81) required-initial escrow — the SDK keyless `previewCollateral` readout, byte-exact
/// from `policy.ts:61` (`required = notional × initial_bps / 10_000`, BigInt floor division).
/// Fail-closed (`None`) on `initial_bps > 10_000` (the `resolveUsmVm` RangeError) or a `checked_mul`
/// overflow — never a fabricated escrow.
#[must_use]
pub fn escrow_usm_vm(notional_minor: u128, initial_bps: u32) -> Option<u128> {
    if initial_bps > 10_000 {
        return None;
    }
    notional_minor
        .checked_mul(u128::from(initial_bps))
        .map(|n| n / 10_000)
}

/// USM-VM (0x81) maintenance requirement — byte-exact from `policy.ts:62`
/// (`maintenance = notional × maintenance_bps / 10_000`). The keyless preview returns this alongside
/// the required-initial. Fail-closed on `maintenance_bps > initial_bps` (the `resolveUsmVm` gate,
/// `policy.ts:56`), `> 10_000`, or overflow.
#[must_use]
pub fn maintenance_usm_vm(
    notional_minor: u128,
    initial_bps: u32,
    maintenance_bps: u32,
) -> Option<u128> {
    if maintenance_bps > 10_000 || maintenance_bps > initial_bps {
        return None;
    }
    notional_minor
        .checked_mul(u128::from(maintenance_bps))
        .map(|n| n / 10_000)
}

/// FIXED-LOCK (0x11) escrow — byte-exact from `policy.ts:88` (`required_initial = locked_amount`).
/// The caller-provided lock is the entire commitment; always representable (no failure path).
#[must_use]
pub const fn escrow_fixed_lock(locked_amount_minor: u128) -> u128 {
    locked_amount_minor
}

/// WCC affine corner-WCL (0x1B) escrow — byte-exact from `wcc.rs:349-387`. The analytic worst-case
/// loss of an affine forward over the declared collar `[collar_lo, collar_hi]` with strike `Pc`:
/// `WCL = q · cs · max(0, gap)` where Long's `gap = Pc − collar_lo`, Short's `gap = collar_hi − Pc`.
/// Fail-closed (`None`) on an invalid collar (`collar_lo >= collar_hi`, G3), a `checked_sub`/
/// `checked_mul` overflow, or `WCL > u64::MAX` (UDSI P7 custody-representability, G7). The two
/// admission gates the program ALSO runs at submit (sup-provider mode = A, the tick lattice) are not
/// part of the escrow magnitude and are out of scope here.
#[must_use]
pub fn escrow_wcc_affine_corner(
    direction: PartyDirection,
    quantity_q: u64,
    contract_size: u128,
    collar_lo: i128,
    collar_hi: i128,
    forward_price_pc: i128,
) -> Option<u128> {
    // G3 — the collar must be a non-empty interval.
    if collar_lo >= collar_hi {
        return None;
    }
    // WCL magnitude at the loss-bearing collar endpoint (Mode-A analytic corner).
    let gap: i128 = match direction {
        PartyDirection::Long => forward_price_pc.checked_sub(collar_lo)?,
        PartyDirection::Short => collar_hi.checked_sub(forward_price_pc)?,
    };
    let magnitude: u128 = wcl_gap_magnitude(gap);
    // wcl = q · cs · magnitude (two checked_mul; exact integer, ceil identity).
    let wcl = u128::from(quantity_q)
        .checked_mul(contract_size)?
        .checked_mul(magnitude)?;
    // G7 (P7) — WCL must be custody-representable in token width.
    if wcl > u128::from(u64::MAX) {
        return None;
    }
    Some(wcl)
}

/// Perp `epoch_wcl_linear` escrow — byte-exact from `epoch_wcl.rs:47-91`. The closed-form epoch
/// worst-case loss of a single linear perp position: `E_epoch = cs · |q| · max(0, corner-gap) + |q| ·
/// funding_cap` (Long worst at `lo_price`, Short worst at `hi_price`). Fail-closed (`None`) on an
/// empty band (`lo_price >= hi_price`, G3) or any `u128` overflow. HONEST: perp is isolated +
/// funding/`force_reduce`, so this is the per-order worst-case reservation, a weaker bound than the
/// collateralized path's "escrow = max loss".
#[must_use]
pub fn escrow_perp_epoch_wcl(
    signed_qty: i64,
    contract_size: u128,
    entry_price: i128,
    lo_price: i128,
    hi_price: i128,
    funding_cap_per_unit: u128,
) -> Option<u128> {
    // G3 — non-empty band.
    if lo_price >= hi_price {
        return None;
    }
    // Worst-case loss magnitude at the loss-bearing corner (affine ⇒ corner-extremal).
    let magnitude: u128 = if signed_qty > 0 {
        let gap = entry_price.checked_sub(lo_price)?;
        wcl_gap_magnitude(gap)
    } else if signed_qty < 0 {
        let gap = hi_price.checked_sub(entry_price)?;
        wcl_gap_magnitude(gap)
    } else {
        0
    };
    let abs_qty: u128 = u128::from(signed_qty.unsigned_abs());
    // position worst-case loss = |q| · cs · magnitude.
    let position_loss = abs_qty.checked_mul(contract_size)?.checked_mul(magnitude)?;
    // funding-prepaid reservation = |q| · funding_cap_per_unit.
    let funding_prepaid = abs_qty.checked_mul(funding_cap_per_unit)?;
    position_loss.checked_add(funding_prepaid)
}

/// Perp `e_epoch_from_notional` escrow — byte-exact from `position_math.rs:165-194`. The SAME
/// `E_epoch` computed from a stored net `position_notional = signed_qty · per_unit_entry`:
/// `gap = PN − q·corner` (Long `q·lo`, Short `q·hi`), `E = cs · max(0, gap) + |q| · funding_cap`.
/// Reproduces a live `PerpPositionPda.reserved_collateral` from its decoded fields. Fail-closed on an
/// empty band or any overflow.
#[must_use]
pub fn escrow_perp_from_notional(
    signed_qty: i64,
    position_notional: i128,
    contract_size: u128,
    lo_price: i128,
    hi_price: i128,
    funding_cap_per_unit: u128,
) -> Option<u128> {
    if lo_price >= hi_price {
        return None;
    }
    let gap: i128 = if signed_qty > 0 {
        position_notional.checked_sub(i128::from(signed_qty).checked_mul(lo_price)?)?
    } else if signed_qty < 0 {
        position_notional.checked_sub(i128::from(signed_qty).checked_mul(hi_price)?)?
    } else {
        0
    };
    let mag: u128 = wcl_gap_magnitude(gap);
    let abs_qty: u128 = u128::from(signed_qty.unsigned_abs());
    // position worst-case loss = cs · gap (gap already carries the |q| factor).
    let position_loss = contract_size.checked_mul(mag)?;
    let funding_prepaid = abs_qty.checked_mul(funding_cap_per_unit)?;
    position_loss.checked_add(funding_prepaid)
}

/// `max(0, gap)` as a `u128` — the loss clamp shared by the perp / WCC corner formulas (`gap <= 0` ⇒
/// the position is in-the-money across the whole band ⇒ 0).
#[must_use]
const fn wcl_gap_magnitude(gap: i128) -> u128 {
    if gap > 0 { gap as u128 } else { 0 }
}

/// Certified per-unit-bound escrow upper bound — `qty × wcl_bound_atoms`, where `wcl_bound_atoms` is
/// a permissionless WCC template's chain-CERTIFIED per-unit worst-case-loss bound
/// (`product_template.rs:483`). A SOUND upper bound on the escrow of `qty` units of ANY non-affine /
/// piecewise instrument (option / spread / digital / straddle / custom) — affordability-correct
/// (never under-estimates), using the protocol's OWN certified number, not a guess. Fail-closed on
/// overflow.
#[must_use]
pub fn escrow_certified_bound(wcl_bound_per_unit: u64, quantity_q: u64) -> Option<u128> {
    u128::from(wcl_bound_per_unit).checked_mul(u128::from(quantity_q))
}

/// One piecewise segment for the WCL re-derivation — mirrors `mode_c::PieceSegment`
/// (`x_hi`/`coeff`/`konst`, all signed `i128`; `f(S) = konst + coeff·S` on the segment).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PiecewiseSeg {
    /// Inclusive upper breakpoint of this segment (on-lattice).
    pub x_hi: i128,
    /// Slope on this segment.
    pub coeff: i128,
    /// Intercept on this segment.
    pub konst: i128,
}

/// The CU/segment cap (`mode_c::MAX_SEGMENTS`).
const PIECEWISE_MAX_SEGMENTS: usize = 16;

/// Piecewise-affine 1-D WCL escrow — byte-exact from `mode_c.rs:856` (`piecewise_grid_bound`):
/// the EXACT O(m) breakpoint-enumeration worst-case loss of a piecewise-affine payoff over its
/// declared collar lattice `D = {lo, lo+tau, ..=hi}`. `WCL = max(0, −min_{S∈D} f(S))`; the min is
/// attained at a segment endpoint (each lattice point lies in one segment; an affine fn's min over
/// an interval is at an endpoint; both endpoints are on-lattice breakpoints — the precise thing a
/// forbidden corner-probe misses). This is the escrow `form_piecewise_contract` pulls PER LEG (the
/// `certified.bound`), so the oracle re-derives the EXACT on-chain escrow (amount-binding, IV-K2-3).
/// Fail-closed (`None`) on a degenerate / non-partition domain (mirrors `check_piecewise_domain`:
/// `lo < hi`, `tau >= 1`, `(hi−lo)` an exact multiple of `tau`, `1 <= m <= 16`, contiguous on-lattice
/// segments with the last `x_hi == hi`) or any `i128` overflow — never a fabricated escrow.
#[must_use]
pub fn escrow_wcc_piecewise(
    lo: i128,
    hi: i128,
    tau: u128,
    segments: &[PiecewiseSeg],
) -> Option<u128> {
    // ---- domain gate (mirror mode_c::check_piecewise_domain) ----
    if lo >= hi || tau == 0 {
        return None;
    }
    let span = hi.checked_sub(lo)? as u128; // lo < hi ⇒ span > 0 ⇒ the cast is exact.
    if span % tau != 0 {
        return None;
    }
    let m = segments.len();
    if m == 0 || m > PIECEWISE_MAX_SEGMENTS {
        return None;
    }
    let tau_i = i128::try_from(tau).ok()?;
    // partition walk: contiguous, on-lattice, ascending, last x_hi == hi.
    let mut x_lo = lo;
    for (idx, seg) in segments.iter().enumerate() {
        if seg.x_hi < x_lo || seg.x_hi > hi {
            return None; // non-empty + in-band
        }
        let off = seg.x_hi.checked_sub(lo)? as u128; // x_hi >= x_lo >= lo ⇒ non-negative.
        if off % tau != 0 {
            return None; // on-lattice (UDSI P8)
        }
        if idx == m - 1 {
            if seg.x_hi != hi {
                return None; // the last segment must cover up to the collar high.
            }
        } else {
            x_lo = seg.x_hi.checked_add(tau_i)?;
            if x_lo > hi {
                return None;
            }
        }
    }
    // ---- breakpoint enumeration: global_min over each segment's two endpoints ----
    let mut global_min: i128 = i128::MAX;
    let mut x_lo = lo;
    for seg in segments {
        let f_lo = seg.coeff.checked_mul(x_lo)?.checked_add(seg.konst)?;
        let f_hi = seg.coeff.checked_mul(seg.x_hi)?.checked_add(seg.konst)?;
        if f_lo < global_min {
            global_min = f_lo;
        }
        if f_hi < global_min {
            global_min = f_hi;
        }
        x_lo = seg.x_hi.checked_add(tau_i)?; // advances every iter (final may step past hi, never read)
    }
    // WCL = max(0, −global_min); checked_neg guards the i128::MIN edge.
    if global_min >= 0 {
        Some(0)
    } else {
        global_min.checked_neg().map(|n| n as u128)
    }
}

/// The bilateral funding-swap CEIL worst-case escrow `escrow_long + escrow_short` — byte-exact from
/// `collateral/funding_swap.rs:138-167` (`compute_escrows` + `funding_wcl_ceil` + `ceil_mul_div`,
/// `FUNDING_BPS_DENOM = 10_000`). The fixed leg (long / `fixed_payer`) worst-cases at `obs = rate_hi`
/// (`max(0, rate_hi − F)`); the floating leg (short / `floating_payer`) at `obs = rate_lo`
/// (`max(0, F − rate_lo)`); each escrow = `CEIL(q · cs · diff / 10_000)`. This is the `/10_000`
/// FLOOR-slope payoff the piecewise-affine engine cannot express — its dedicated path. Returns the
/// SUM the program pulls into the shared vault (amount-binding, IV-K2-3); fail-closed `None` on any
/// overflow. PURE; no LLM judgment — the model never an arbiter.
#[must_use]
pub fn escrow_funding_swap(
    quantity: u64,
    contract_size: u128,
    fixed_rate_bps: i64,
    rate_lo: i64,
    rate_hi: i64,
) -> Option<u128> {
    /// bps→fraction denominator (`funding_swap.rs:53` `FUNDING_BPS_DENOM`).
    const FUNDING_BPS_DENOM: u128 = 10_000;
    // `CEIL(amount · mul / denom)`, overflow-safe — the loser-margin rounding (the CEIL sibling of
    // `floor_mul_div`, un-gated on `mul`); byte-exact from `funding_swap.rs:82-89`.
    fn ceil_mul_div(amount: u128, mul: u128, denom: u128) -> Option<u128> {
        let q = amount.checked_div(denom)?;
        let r = amount.checked_rem(denom)?; // r < denom
        let r_mul = r.checked_mul(mul)?; // r < denom (10_000) ⇒ bounded
        let r_term = r_mul.div_ceil(denom); // CEIL
        let q_term = q.checked_mul(mul)?;
        q_term.checked_add(r_term)
    }
    let qty_times_size = u128::from(quantity).checked_mul(contract_size)?;
    // long (fixed_payer) worst at obs=rate_hi: max(0, rate_hi − F).
    let hi_minus_f = i128::from(rate_hi).checked_sub(i128::from(fixed_rate_bps))?;
    let long_diff = u128::try_from(hi_minus_f.max(0)).ok()?;
    // short (floating_payer) worst at obs=rate_lo: max(0, F − rate_lo).
    let f_minus_lo = i128::from(fixed_rate_bps).checked_sub(i128::from(rate_lo))?;
    let short_diff = u128::try_from(f_minus_lo.max(0)).ok()?;
    let escrow_long = ceil_mul_div(qty_times_size, long_diff, FUNDING_BPS_DENOM)?;
    let escrow_short = ceil_mul_div(qty_times_size, short_diff, FUNDING_BPS_DENOM)?;
    escrow_long.checked_add(escrow_short)
}

// ============================================================================
// The typed trade + the verdict.
// ============================================================================

/// A proposed Skew trade, carrying the per-class params needed to re-derive its worst-case escrow.
/// The model PROPOSES one of these; the oracle DECIDES. (No signing payload — that is K-2.)
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SkewTrade {
    /// USM-VM (0x81) variation-margin forward: escrow = `notional × initial_bps / 10_000`.
    UsmVmForward {
        /// Trade notional in minor units (qty × price).
        notional_minor: u128,
        /// Initial-margin schedule in basis points (`0..=10_000`).
        initial_bps: u32,
    },
    /// FIXED-LOCK (0x11): escrow = `locked_amount`.
    FixedLock {
        /// Locked collateral in minor units.
        locked_amount_minor: u128,
    },
    /// WCC (0x1B) affine forward / swap / collar: escrow = the analytic corner WCL.
    WccAffineForward {
        /// Which side the trade is on.
        direction: PartyDirection,
        /// Integer contract count.
        quantity_q: u64,
        /// Contract-size multiplier (mint scale).
        contract_size: u128,
        /// Declared collar low bound (signed price axis).
        collar_lo: i128,
        /// Declared collar high bound (signed price axis).
        collar_hi: i128,
        /// Forward / strike price `Pc` (signed).
        forward_price_pc: i128,
    },
    /// Perp (isolated margin): escrow = `epoch_wcl_linear`. HONEST weaker bound (funding /
    /// `force_reduce`).
    Perp {
        /// Net signed position quantity (`+` long, `−` short).
        signed_qty: i64,
        /// Contract-size multiplier.
        contract_size: u128,
        /// Entry / reference price (signed).
        entry_price: i128,
        /// Epoch band low bound (signed).
        lo_price: i128,
        /// Epoch band high bound (signed).
        hi_price: i128,
        /// Per-unit funding cap reserved up front (`0` until the funding wiring).
        funding_cap_per_unit: u128,
    },
    /// Non-affine / piecewise via the chain-certified per-unit bound: escrow upper bound =
    /// `qty × wcl_bound_atoms`.
    CertifiedBound {
        /// The template's certified per-unit worst-case-loss bound (`wcl_bound_atoms`).
        wcl_bound_per_unit: u64,
        /// Integer contract count.
        quantity_q: u64,
    },
}

impl SkewTrade {
    /// Re-derive this trade's worst-case escrow (minor units) by dispatching to the byte-exact
    /// primitive for its class. Fail-closed (`None`) on any out-of-range / overflow / empty-band
    /// input — never a fabricated escrow.
    #[must_use]
    pub fn worst_case_escrow(&self) -> Option<u128> {
        match *self {
            Self::UsmVmForward {
                notional_minor,
                initial_bps,
            } => escrow_usm_vm(notional_minor, initial_bps),
            Self::FixedLock {
                locked_amount_minor,
            } => Some(escrow_fixed_lock(locked_amount_minor)),
            Self::WccAffineForward {
                direction,
                quantity_q,
                contract_size,
                collar_lo,
                collar_hi,
                forward_price_pc,
            } => escrow_wcc_affine_corner(
                direction,
                quantity_q,
                contract_size,
                collar_lo,
                collar_hi,
                forward_price_pc,
            ),
            Self::Perp {
                signed_qty,
                contract_size,
                entry_price,
                lo_price,
                hi_price,
                funding_cap_per_unit,
            } => escrow_perp_epoch_wcl(
                signed_qty,
                contract_size,
                entry_price,
                lo_price,
                hi_price,
                funding_cap_per_unit,
            ),
            Self::CertifiedBound {
                wcl_bound_per_unit,
                quantity_q,
            } => escrow_certified_bound(wcl_bound_per_unit, quantity_q),
        }
    }

    /// Short class label for rendering.
    #[must_use]
    pub const fn class_label(&self) -> &'static str {
        match self {
            Self::UsmVmForward { .. } => "usm-vm forward",
            Self::FixedLock { .. } => "fixed-lock",
            Self::WccAffineForward { .. } => "wcc affine forward",
            Self::Perp { .. } => "perp (isolated)",
            Self::CertifiedBound { .. } => "certified-bound (non-affine/piecewise)",
        }
    }
}

/// Evaluate a fail-closed verdict for ONE trade whose worst-case escrow is already re-derived
/// (`escrow_minor`), given the cumulative `spent_minor`, the current `portfolio_locked_minor`, and
/// the owner's `bounds`. Check order mirrors `commands::grant::CustodyGrantCore::authorize`
/// (per-tx → budget) plus the drawdown dial; every check is an upper limit, ANY breach denies
/// (checked add, overflow ⇒ deny — never a silent authorize).
#[must_use]
pub fn evaluate_trade(
    escrow_minor: u128,
    spent_minor: u128,
    portfolio_locked_minor: u128,
    bounds: &OracleBounds,
) -> TradeVerdict {
    // (a) per-tx ceiling.
    if escrow_minor > bounds.per_tx_max_minor {
        return TradeVerdict::Denied(OracleDenied::PerTxExceeded);
    }
    // (b) total budget (checked add; overflow ⇒ deny).
    match spent_minor.checked_add(escrow_minor) {
        Some(total) if total <= bounds.total_budget_minor => {}
        _ => return TradeVerdict::Denied(OracleDenied::BudgetExceeded),
    }
    // (c) resulting portfolio worst-case ≤ the owner's drawdown bound (checked add; overflow ⇒ deny).
    match portfolio_locked_minor.checked_add(escrow_minor) {
        Some(total) if total <= bounds.drawdown_max_minor => {}
        _ => return TradeVerdict::Denied(OracleDenied::DrawdownExceeded),
    }
    TradeVerdict::AffordableInBounds { escrow_minor }
}

/// The full oracle: re-derive a proposed `trade`'s worst-case escrow, then evaluate it against the
/// owner bounds. A non-re-derivable escrow (overflow / empty band / out-of-range) is
/// `Denied(InvalidParams)` — fail-closed. No LLM judge, no signing, money 0.
#[must_use]
pub fn oracle_verdict(
    trade: &SkewTrade,
    spent_minor: u128,
    portfolio_locked_minor: u128,
    bounds: &OracleBounds,
) -> TradeVerdict {
    match trade.worst_case_escrow() {
        Some(escrow_minor) => {
            evaluate_trade(escrow_minor, spent_minor, portfolio_locked_minor, bounds)
        }
        None => TradeVerdict::Denied(OracleDenied::InvalidParams),
    }
}

// ============================================================================
// Byte-exact on-chain decode (for the LIVE devnet read; mirrors `skew_read`).
// ============================================================================

/// The margin-relevant fields of a `ProductTemplatePda` (228 bytes = 8 disc + 220 body). Offsets
/// copied byte-exact from `product_template.rs:523-544` (the SPACE layout table) + the body-relative
/// offset tests; account-relative = body offset + 8.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TemplateMargin {
    /// 32-byte template id (account `@8`).
    pub template_id: [u8; 32],
    /// The collateral policy id (u16 LE, account `@80`).
    pub collateral_policy_id: u16,
    /// Whether the template is enabled (account `@118`; `1` = true).
    pub enabled: bool,
    /// How the template was admitted (account `@152`; `0` = admin, `1` = permissionless WCC).
    pub listing_kind: u8,
    /// Which sup-provider mode certified the WCL bound (account `@153`; `1` = GridMaxB / `2` =
    /// AffineCornerC).
    pub cert_via_mode: u8,
    /// The chain-certified per-unit worst-case-loss bound recorded at listing (u64 LE, account
    /// `@154`; `0` for the admin path).
    pub wcl_bound_atoms: u64,
    /// The settlement mint validated at listing (account `@194`; zero for the admin path).
    pub settlement_mint: [u8; 32],
}

impl TemplateMargin {
    /// The classified collateral policy.
    #[must_use]
    pub fn policy_class(&self) -> CollateralPolicyClass {
        classify_collateral_policy(self.collateral_policy_id)
    }
}

/// The full on-chain `ProductTemplatePda` account size (8 Anchor discriminator + 220 Pod body).
pub const PRODUCT_TEMPLATE_PDA_SPACE: usize = 228;

/// Decode the margin-relevant fields of a `ProductTemplatePda` from RAW account bytes (incl. the
/// 8-byte discriminator). Returns `None` (fail-closed) unless the bytes are exactly
/// [`PRODUCT_TEMPLATE_PDA_SPACE`] AND carry the verified template discriminator — a read never
/// mis-attributes a wrong-shaped account. Offsets byte-exact from `product_template.rs`.
#[must_use]
pub fn decode_product_template(account_data: &[u8]) -> Option<TemplateMargin> {
    if account_data.len() != PRODUCT_TEMPLATE_PDA_SPACE
        || account_data[..8] != crate::skew_read::PRODUCT_TEMPLATE_DISCRIMINATOR
    {
        return None;
    }
    let rd_u16 = |o: usize| -> u16 { u16::from_le_bytes([account_data[o], account_data[o + 1]]) };
    let mut template_id = [0u8; 32];
    template_id.copy_from_slice(&account_data[8..40]);
    let mut wcl = [0u8; 8];
    wcl.copy_from_slice(&account_data[154..162]);
    let mut settlement_mint = [0u8; 32];
    settlement_mint.copy_from_slice(&account_data[194..226]);
    Some(TemplateMargin {
        template_id,
        collateral_policy_id: rd_u16(80),
        enabled: account_data[118] == 1,
        listing_kind: account_data[152],
        cert_via_mode: account_data[153],
        wcl_bound_atoms: u64::from_le_bytes(wcl),
        settlement_mint,
    })
}

/// The margin-relevant fields of a `PerpPositionPda` (154 bytes = 8 disc + 146 body). Offsets
/// byte-exact from `perp_position.rs:160-224` + the layout tests; account-relative = body offset + 8.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PerpPositionEscrow {
    /// The perp market id (account `@8`).
    pub market_id: [u8; 32],
    /// Net signed position quantity (i64 LE, account `@72`).
    pub signed_qty: i64,
    /// Net position notional `PN = signed_qty · per_unit_entry` (i128 LE, account `@80`).
    pub entry_notional: i128,
    /// The position's RESERVED margin = its on-chain `E_epoch` (u128 LE, account `@136`). This is the
    /// chain's OWN computed worst-case escrow for the position — the oracle can reproduce it via
    /// [`escrow_perp_from_notional`] given the market band.
    pub reserved_collateral: u128,
    /// Lifecycle status byte (account `@152`; `1` = Open).
    pub status: u8,
}

/// The full on-chain `PerpPositionPda` account size (8 Anchor discriminator + 146 Pod body).
pub const PERP_POSITION_PDA_SPACE: usize = 154;

/// Decode the margin-relevant fields of a `PerpPositionPda` from RAW account bytes (incl. the 8-byte
/// discriminator). Returns `None` (fail-closed) unless the bytes are exactly
/// [`PERP_POSITION_PDA_SPACE`] AND carry the verified perp-position discriminator. Offsets byte-exact
/// from `perp_position.rs`.
#[must_use]
pub fn decode_perp_position(account_data: &[u8]) -> Option<PerpPositionEscrow> {
    if account_data.len() != PERP_POSITION_PDA_SPACE
        || account_data[..8] != crate::skew_read::PERP_POSITION_DISCRIMINATOR
    {
        return None;
    }
    let mut market_id = [0u8; 32];
    market_id.copy_from_slice(&account_data[8..40]);
    let mut q = [0u8; 8];
    q.copy_from_slice(&account_data[72..80]);
    let mut pn = [0u8; 16];
    pn.copy_from_slice(&account_data[80..96]);
    let mut rc = [0u8; 16];
    rc.copy_from_slice(&account_data[136..152]);
    Some(PerpPositionEscrow {
        market_id,
        signed_qty: i64::from_le_bytes(q),
        entry_notional: i128::from_le_bytes(pn),
        reserved_collateral: u128::from_le_bytes(rc),
        status: account_data[152],
    })
}

// ============================================================================
// Render helpers (PURE; the dispatch glue calls these).
// ============================================================================

/// Render a one-line verdict for a proposed trade against owner bounds (PURE).
#[must_use]
pub fn render_verdict(
    trade: &SkewTrade,
    spent_minor: u128,
    portfolio_locked_minor: u128,
    bounds: &OracleBounds,
) -> String {
    let escrow = trade
        .worst_case_escrow()
        .map_or_else(|| "n/a(fail-closed)".to_string(), |e| e.to_string());
    let verdict = oracle_verdict(trade, spent_minor, portfolio_locked_minor, bounds);
    let verdict_str = match verdict {
        TradeVerdict::AffordableInBounds { escrow_minor } => {
            format!("AFFORDABLE & IN-BOUNDS (escrow={escrow_minor} minor)")
        }
        TradeVerdict::Denied(reason) => format!("DENIED: {}", reason.as_str()),
    };
    format!(
        "skew oracle [{}] worst-case escrow={escrow} minor\n  bounds: per_tx_max={} total_budget={} drawdown_max={} (spent={spent_minor} portfolio_locked={portfolio_locked_minor})\n  verdict: {verdict_str}\n  (deterministic re-derivation of Skew's own worst-case; no LLM judge; money 0; not signed — K-2)\n",
        trade.class_label(),
        bounds.per_tx_max_minor,
        bounds.total_budget_minor,
        bounds.drawdown_max_minor,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    // ---- byte-exact formula goldens (matching the Skew source's own golden vectors) ----------

    #[test]
    fn usm_vm_matches_sdk_preview_floor_and_gate() {
        // policy.ts: required = notional × initial_bps / 10_000 (floor).
        // notional 100_000_000 × 80 bps / 10_000 = 800_000.
        assert_eq!(escrow_usm_vm(100_000_000, 80), Some(800_000));
        // floor: 1_000 × 1 bps / 10_000 = 0 (0.1 floored).
        assert_eq!(escrow_usm_vm(1_000, 1), Some(0));
        // 1_000_000 × 250 / 10_000 = 25_000.
        assert_eq!(escrow_usm_vm(1_000_000, 250), Some(25_000));
        // initial_bps > 10_000 ⇒ fail-closed (resolveUsmVm RangeError).
        assert_eq!(escrow_usm_vm(1, 10_001), None);
        // boundary: 10_000 bps (100%) ⇒ notional.
        assert_eq!(escrow_usm_vm(777, 10_000), Some(777));
        // overflow ⇒ None (never fabricated).
        assert_eq!(escrow_usm_vm(u128::MAX, 2), None);
    }

    #[test]
    fn usm_vm_maintenance_matches_sdk_and_gate() {
        // maintenance = notional × maintenance_bps / 10_000, gated by maintenance_bps ≤ initial_bps.
        assert_eq!(maintenance_usm_vm(1_000_000, 250, 100), Some(10_000));
        // maintenance_bps > initial_bps ⇒ fail-closed (resolveUsmVm gate).
        assert_eq!(maintenance_usm_vm(1_000_000, 100, 250), None);
        assert_eq!(maintenance_usm_vm(1, 10_000, 10_001), None);
    }

    #[test]
    fn fixed_lock_is_the_locked_amount() {
        // policy.ts: required_initial = locked_amount.
        assert_eq!(escrow_fixed_lock(1_000_000), 1_000_000);
        assert_eq!(escrow_fixed_lock(0), 0);
    }

    #[test]
    fn wcc_affine_corner_matches_wcc_evaluate_golden() {
        // wcc.rs isomorphism golden (epoch_wcl_isomorphic_to_wcc, funding 0):
        // long q=3 cs=7 Pc=100 collar[60,130]: gap = 100−60 = 40; wcl = 3·7·40 = 840.
        assert_eq!(
            escrow_wcc_affine_corner(PartyDirection::Long, 3, 7, 60, 130, 100),
            Some(840)
        );
        // short: gap = 130−100 = 30; wcl = 3·7·30 = 630.
        assert_eq!(
            escrow_wcc_affine_corner(PartyDirection::Short, 3, 7, 60, 130, 100),
            Some(630)
        );
        // in-the-money across the whole band ⇒ gap ≤ 0 ⇒ wcl 0.
        assert_eq!(
            escrow_wcc_affine_corner(PartyDirection::Long, 5, 2, 100, 140, 90),
            Some(0)
        );
        // invalid collar (lo ≥ hi) ⇒ None (G3).
        assert_eq!(
            escrow_wcc_affine_corner(PartyDirection::Long, 1, 1, 100, 100, 50),
            None
        );
        // G7: WCL > u64::MAX ⇒ None (P7 custody-representability).
        assert_eq!(
            escrow_wcc_affine_corner(PartyDirection::Long, u64::MAX, u64::MAX as u128, 0, 2, 1),
            None
        );
    }

    #[test]
    fn perp_epoch_wcl_matches_epoch_wcl_linear_plan_vectors() {
        // epoch_wcl.rs golden vectors (q, cs, entry, lo, hi, fcap, expected):
        // long@lo: 5,2,100,80,140,0 ⇒ 200; short@hi: -5,2,100,80,140,0 ⇒ 400.
        assert_eq!(escrow_perp_epoch_wcl(5, 2, 100, 80, 140, 0), Some(200));
        assert_eq!(escrow_perp_epoch_wcl(-5, 2, 100, 80, 140, 0), Some(400));
        // long+funding: 5,2,100,80,140,3 ⇒ 200 + 5·3 = 215.
        assert_eq!(escrow_perp_epoch_wcl(5, 2, 100, 80, 140, 3), Some(215));
        // flat q=0 ⇒ 0; long-no-loss (entry below band) ⇒ 0.
        assert_eq!(escrow_perp_epoch_wcl(0, 2, 100, 80, 140, 5), Some(0));
        assert_eq!(escrow_perp_epoch_wcl(5, 2, 70, 80, 140, 0), Some(0));
        // empty band ⇒ None (G3).
        assert_eq!(escrow_perp_epoch_wcl(5, 2, 100, 140, 80, 0), None);
    }

    #[test]
    fn perp_from_notional_matches_e_epoch_from_notional() {
        // position_math.rs: long q=5, PN = 5·100 = 500, cs=2, lo=80,hi=140 ⇒
        // gap = 500 − 5·80 = 100; E = cs·gap = 2·100 = 200 (same as epoch_wcl long@lo above).
        assert_eq!(escrow_perp_from_notional(5, 500, 2, 80, 140, 0), Some(200));
        // short q=−5, PN = −5·100 = −500 ⇒ gap = −500 − (−5·140) = 200; E = 2·200 = 400.
        assert_eq!(
            escrow_perp_from_notional(-5, -500, 2, 80, 140, 0),
            Some(400)
        );
        // with funding: long + |q|·fcap = 200 + 5·3 = 215.
        assert_eq!(escrow_perp_from_notional(5, 500, 2, 80, 140, 3), Some(215));
        assert_eq!(escrow_perp_from_notional(5, 500, 2, 140, 80, 0), None);
    }

    #[test]
    fn certified_bound_is_per_unit_times_qty() {
        assert_eq!(escrow_certified_bound(1_000, 50), Some(50_000));
        assert_eq!(escrow_certified_bound(0, 7), Some(0));
        // u64 × u64 always fits u128 ((2^64−1)^2 < 2^128) ⇒ Some, never overflows; checked_mul is
        // belt-and-suspenders.
        let max = u128::from(u64::MAX) * u128::from(u64::MAX);
        assert_eq!(escrow_certified_bound(u64::MAX, u64::MAX), Some(max));
    }

    #[test]
    fn piecewise_escrow_matches_grid_bound_golden() {
        // The deployed straddle (mode_c.rs `aether-opt-straddle-1`, `f = |S−50| − 8` over [0,100]
        // τ10): long WCL = 8 (the premium / apex loss), short WCL = 42 (intrinsic_max − premium).
        let long = [
            PiecewiseSeg {
                x_hi: 50,
                coeff: -1,
                konst: 42,
            },
            PiecewiseSeg {
                x_hi: 100,
                coeff: 1,
                konst: -58,
            },
        ];
        let short = [
            PiecewiseSeg {
                x_hi: 50,
                coeff: 1,
                konst: -42,
            },
            PiecewiseSeg {
                x_hi: 100,
                coeff: -1,
                konst: 58,
            },
        ];
        assert_eq!(escrow_wcc_piecewise(0, 100, 10, &long), Some(8));
        assert_eq!(escrow_wcc_piecewise(0, 100, 10, &short), Some(42));
        // A long call K=60 prem 5: WCL_long == the premium (`f = max(0,S-60) - 5` ⇒ min −5).
        let call_long = [
            PiecewiseSeg {
                x_hi: 60,
                coeff: 0,
                konst: -5,
            },
            PiecewiseSeg {
                x_hi: 100,
                coeff: 1,
                konst: -65,
            },
        ];
        assert_eq!(escrow_wcc_piecewise(0, 100, 10, &call_long), Some(5));

        // Fail-closed: empty band, tau 0, off-lattice breakpoint, non-partition (last != hi),
        // and m=0 ⇒ None (mirrors mode_c::check_piecewise_domain).
        assert_eq!(escrow_wcc_piecewise(100, 0, 10, &long), None); // lo >= hi
        assert_eq!(escrow_wcc_piecewise(0, 100, 0, &long), None); // tau == 0
        let off_lattice = [PiecewiseSeg {
            x_hi: 55,
            coeff: -1,
            konst: 0,
        }];
        assert_eq!(escrow_wcc_piecewise(0, 100, 10, &off_lattice), None); // 55 off-lattice + != hi
        let not_to_hi = [PiecewiseSeg {
            x_hi: 50,
            coeff: -1,
            konst: 0,
        }];
        assert_eq!(escrow_wcc_piecewise(0, 100, 10, &not_to_hi), None); // last x_hi != hi
        assert_eq!(escrow_wcc_piecewise(0, 100, 10, &[]), None); // m == 0
    }

    // ---- policy classification ------------------------------------------------------------------

    #[test]
    fn classify_collateral_policy_by_low_byte() {
        // u16 stored values (and their legacy u8-range low bytes) classify the same.
        assert_eq!(
            classify_collateral_policy(0x0F81),
            CollateralPolicyClass::UsmVm
        );
        assert_eq!(
            classify_collateral_policy(0x0081),
            CollateralPolicyClass::UsmVm
        );
        assert_eq!(
            classify_collateral_policy(0x2511),
            CollateralPolicyClass::FixedLock
        );
        assert_eq!(
            classify_collateral_policy(0x1B1B),
            CollateralPolicyClass::Wcc
        );
        assert_eq!(
            classify_collateral_policy(0x0042),
            CollateralPolicyClass::Other(0x0042)
        );
    }

    // ---- the verdict ----------------------------------------------------------------------------

    fn bounds(per_tx: u128, budget: u128, drawdown: u128) -> OracleBounds {
        OracleBounds {
            per_tx_max_minor: per_tx,
            total_budget_minor: budget,
            drawdown_max_minor: drawdown,
        }
    }

    #[test]
    fn verdict_affordable_within_all_bounds() {
        // escrow 800_000 ≤ per_tx 1_000_000; spent 0 + 800_000 ≤ budget 2_000_000; portfolio 0 +
        // 800_000 ≤ drawdown 2_000_000 ⇒ affordable.
        let trade = SkewTrade::UsmVmForward {
            notional_minor: 100_000_000,
            initial_bps: 80,
        };
        assert_eq!(
            oracle_verdict(&trade, 0, 0, &bounds(1_000_000, 2_000_000, 2_000_000)),
            TradeVerdict::AffordableInBounds {
                escrow_minor: 800_000
            }
        );
    }

    #[test]
    fn verdict_denies_every_bound_breach_fail_closed() {
        let trade = SkewTrade::FixedLock {
            locked_amount_minor: 1_000,
        };
        // per-tx ceiling exceeded (1_000 > 500).
        assert_eq!(
            oracle_verdict(&trade, 0, 0, &bounds(500, 10_000, 10_000)),
            TradeVerdict::Denied(OracleDenied::PerTxExceeded)
        );
        // total budget exceeded (spent 9_500 + 1_000 > 10_000).
        assert_eq!(
            oracle_verdict(&trade, 9_500, 0, &bounds(10_000, 10_000, 100_000)),
            TradeVerdict::Denied(OracleDenied::BudgetExceeded)
        );
        // drawdown exceeded (portfolio 9_999 + 1_000 > 10_000, budget ample).
        assert_eq!(
            oracle_verdict(&trade, 0, 9_999, &bounds(100_000, 100_000, 10_000)),
            TradeVerdict::Denied(OracleDenied::DrawdownExceeded)
        );
        // invalid params (un-re-derivable escrow) ⇒ InvalidParams.
        let bad = SkewTrade::Perp {
            signed_qty: 5,
            contract_size: 2,
            entry_price: 100,
            lo_price: 140, // empty band (lo ≥ hi)
            hi_price: 80,
            funding_cap_per_unit: 0,
        };
        assert_eq!(
            oracle_verdict(&bad, 0, 0, &bounds(u128::MAX, u128::MAX, u128::MAX)),
            TradeVerdict::Denied(OracleDenied::InvalidParams)
        );
    }

    #[test]
    fn verdict_budget_checked_add_overflow_denies() {
        let trade = SkewTrade::FixedLock {
            locked_amount_minor: 1,
        };
        // spent u128::MAX + 1 overflows ⇒ BudgetExceeded (never a silent authorize).
        assert_eq!(
            oracle_verdict(
                &trade,
                u128::MAX,
                0,
                &bounds(u128::MAX, u128::MAX, u128::MAX)
            ),
            TradeVerdict::Denied(OracleDenied::BudgetExceeded)
        );
    }

    #[test]
    fn sigma_escrows_bounded_by_budget_theorem() {
        // The §2 theorem on the collateralized path: a sequence of in-bounds trades keeps
        // Σ(escrows) ≤ total_budget; the trade that would breach it is denied (fail-closed).
        let b = bounds(1_000, 1_000, 1_000);
        let t = SkewTrade::FixedLock {
            locked_amount_minor: 400,
        };
        // spent 0 → ok; spent 400 → ok (800 ≤ 1000); spent 800 → DENIED (1200 > 1000).
        assert!(oracle_verdict(&t, 0, 0, &b).is_affordable());
        assert!(oracle_verdict(&t, 400, 0, &b).is_affordable());
        assert_eq!(
            oracle_verdict(&t, 800, 0, &b),
            TradeVerdict::Denied(OracleDenied::BudgetExceeded)
        );
    }

    // ---- byte-exact on-chain decode -------------------------------------------------------------

    /// Build a 228-byte ProductTemplate account = disc ‖ body, with a WCC policy + a certified
    /// per-unit bound. Offsets byte-exact (account-relative).
    fn wcc_template(policy_u16: u16, wcl_bound: u64) -> Vec<u8> {
        let mut a = vec![0u8; PRODUCT_TEMPLATE_PDA_SPACE];
        a[..8].copy_from_slice(&crate::skew_read::PRODUCT_TEMPLATE_DISCRIMINATOR);
        a[8..40].copy_from_slice(&[0xAB; 32]); // template_id
        a[80..82].copy_from_slice(&policy_u16.to_le_bytes()); // collateral_policy_id @80
        a[118] = 1; // enabled @118
        a[152] = 1; // listing_kind @152 = PermissionlessWcc
        a[153] = 2; // cert_via_mode @153 = AffineCornerC
        a[154..162].copy_from_slice(&wcl_bound.to_le_bytes()); // wcl_bound_atoms @154
        a[194..226].copy_from_slice(&[0x6B; 32]); // settlement_mint @194
        a
    }

    #[test]
    fn decode_product_template_byte_exact_and_fail_closed() {
        let acct = wcc_template(0x1B1B, 1_000_000);
        let m = decode_product_template(&acct).expect("decodes");
        assert_eq!(m.template_id, [0xAB; 32]);
        assert_eq!(m.collateral_policy_id, 0x1B1B);
        assert_eq!(m.policy_class(), CollateralPolicyClass::Wcc);
        assert!(m.enabled);
        assert_eq!(m.listing_kind, 1);
        assert_eq!(m.cert_via_mode, 2);
        assert_eq!(m.wcl_bound_atoms, 1_000_000);
        assert_eq!(m.settlement_mint, [0x6B; 32]);
        // the certified per-unit bound feeds the oracle: 1_000_000 × 3 = 3_000_000.
        assert_eq!(
            escrow_certified_bound(m.wcl_bound_atoms, 3),
            Some(3_000_000)
        );
        // wrong length ⇒ None.
        assert!(decode_product_template(&acct[..200]).is_none());
        // wrong discriminator ⇒ None (never mis-attribute).
        let mut bad = acct.clone();
        bad[0] ^= 0xFF;
        assert!(decode_product_template(&bad).is_none());
    }

    /// Build a 154-byte PerpPosition = disc ‖ body with a stored reserved_collateral (the chain's
    /// E_epoch) reproducible from entry_notional via e_epoch_from_notional.
    fn perp_position(signed_qty: i64, entry_notional: i128, reserved: u128) -> Vec<u8> {
        let mut a = vec![0u8; PERP_POSITION_PDA_SPACE];
        a[..8].copy_from_slice(&crate::skew_read::PERP_POSITION_DISCRIMINATOR);
        a[8..40].copy_from_slice(&[0x11; 32]); // market_id
        a[72..80].copy_from_slice(&signed_qty.to_le_bytes()); // signed_qty @72
        a[80..96].copy_from_slice(&entry_notional.to_le_bytes()); // entry_notional @80
        a[136..152].copy_from_slice(&reserved.to_le_bytes()); // reserved_collateral @136
        a[152] = 1; // status @152 = Open
        a
    }

    #[test]
    fn decode_perp_position_reproduces_chain_e_epoch() {
        // A long position q=5 PN=500 with reserved E_epoch=200 (cs=2, band[80,140]) on chain.
        let acct = perp_position(5, 500, 200);
        let p = decode_perp_position(&acct).expect("decodes");
        assert_eq!(p.signed_qty, 5);
        assert_eq!(p.entry_notional, 500);
        assert_eq!(p.reserved_collateral, 200);
        assert_eq!(p.status, 1);
        // the oracle reproduces the chain's stored E_epoch from the decoded fields + the market band.
        assert_eq!(
            escrow_perp_from_notional(p.signed_qty, p.entry_notional, 2, 80, 140, 0),
            Some(p.reserved_collateral)
        );
        // fail-closed on wrong shape.
        assert!(decode_perp_position(&acct[..150]).is_none());
        let mut bad = acct.clone();
        bad[0] ^= 0xFF;
        assert!(decode_perp_position(&bad).is_none());
    }

    #[test]
    fn render_verdict_is_honest_and_complete() {
        let trade = SkewTrade::WccAffineForward {
            direction: PartyDirection::Long,
            quantity_q: 3,
            contract_size: 7,
            collar_lo: 60,
            collar_hi: 130,
            forward_price_pc: 100,
        };
        let r = render_verdict(&trade, 0, 0, &bounds(1_000, 10_000, 10_000));
        assert!(r.contains("worst-case escrow=840"));
        assert!(r.contains("AFFORDABLE & IN-BOUNDS"));
        assert!(r.contains("no LLM judge"));
        assert!(r.contains("not signed"));
    }
}
