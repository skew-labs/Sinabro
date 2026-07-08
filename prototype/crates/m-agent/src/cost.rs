//! `m-agent::cost` — cost telemetry with type-safe USD micros +
//! cached-token visibility + daily hard-cap gate.
//!
//! Completes the token-saving spine: [`TokenCount`] supplies the
//! typed-unit width for "LLM tokens"; [`TurnUsage`] supplies the
//! per-turn 3-counter breakdown; [`DailyTokenBudget`] supplies the
//! saturating ledger + refusal channel via
//! [`MnemosError::budget_exceeded`]. This module projects a [`TurnUsage`]
//! through a [`PriceTable`] into an accumulated [`UsdMicros`] cost on a
//! [`CostLedger`], and exposes [`CostLedger::try_charge_and_record`] as
//! the atomic "gate then record" sibling that ties the prepaid daily
//! cap to the cost projection in one observable step.
//!
//! ## Canonical signature
//!
//! ```text
//! // cost.rs
//! pub struct UsdMicros(u32);
//! pub struct CostLedger {
//!     input_tokens_u32: u32,
//!     output_tokens_u32: u32,
//!     cached_tokens_u32: u32,
//!     usd_micros: UsdMicros,
//! }
//! impl CostLedger {
//!     pub fn record(&mut self, usage: &TurnUsage, price: &PriceTable);
//!     pub fn usd_micros(&self) -> UsdMicros;
//! }
//! pub struct PriceTable {
//!     input_per_mtok_micros_u32: u32,
//!     output_per_mtok_micros_u32: u32,
//! }
//! ```
//!
//! ## Rationale
//!
//! - **Typed-unit barrier (zero unit confusion).** [`UsdMicros`] is a
//!   `#[repr(transparent)]` newtype over `u32` that mirrors the
//!   [`TokenCount`] shape. The compiler refuses any silent coercion
//!   between "tokens" and "USD-millionths": both are `u32`-shaped but
//!   the type system never lets a [`TokenCount`] flow into a price
//!   computation or a [`UsdMicros`] flow into a budget charge.
//!
//! - **Cached-token visibility (savings made visible).** [`CostLedger`]
//!   tracks `cached_tokens_u32` as a separate counter (subset of the
//!   prompt-side token count per [`TurnUsage`] documentation). The
//!   cost formula treats the cached portion of `prompt_tokens_u32` as
//!   free (provider cache hits the static prefix at zero marginal
//!   charge), so a turn with `cached_tokens_u32 > 0` projects a
//!   strictly lower [`UsdMicros`] delta than the same prompt count
//!   with `cached_tokens_u32 == 0`. The cache-hit ratio
//!   (`cached / prompt`) is measurable straight off the ledger.
//!
//! - **Daily hard cap (prepaid).** [`CostLedger::try_charge_and_record`]
//!   gates the record against a caller-supplied [`DailyTokenBudget`]:
//!   the budget is charged `prompt + completion`
//!   (saturating sum, widened through [`TokenCount`]) BEFORE any
//!   ledger field mutates. If the charge would breach the daily token
//!   cap, the budget refuses with
//!   [`MnemosError::budget_exceeded(BudgetAxis::LlmTokens, observed, limit)`]
//!   and **both the budget and the ledger stay byte-identical**. The
//!   [`DailyTokenBudget`] monotonicity invariant ("a refused charge does not
//!   mutate `spent_u32`") composes with this module's by-construction
//!   guarantee that no [`CostLedger`] field changes when the budget
//!   short-circuits.
//!
//! - **Saturating arithmetic + monotonic ledger.** Every counter on
//!   [`CostLedger`] uses `u{32,64}::saturating_*`; no `record` call
//!   ever decrements a field. The width pins below turn any future
//!   layout drift into a compile-time failure, and the
//!   `m0_7_ledger_monotone` test proves the runtime invariant.
//!
//! ## Reuse surface
//!
//! - [`TurnUsage`] — the per-turn 3-counter
//!   carrier this ledger projects through a [`PriceTable`]. Public
//!   fields per the "no invariant beyond inner value" rationale.
//! - [`DailyTokenBudget`] — the daily token cap
//!   gate this module composes with for the prepaid spec. Private
//!   fields + `pub const fn` accessors; the
//!   [`DailyTokenBudget::try_charge`] entry point owns the
//!   `spent_u32 <= cap_u32` invariant.
//! - [`TokenCount`] — the `#[repr(transparent)]`
//!   newtype over `u32` that pairs with [`UsdMicros`] at the
//!   single-byte-vs-u32 unit-confusion boundary.
//! - [`MnemosError::budget_exceeded`] +
//!   [`mnemos_a_core::error::BudgetAxis::LlmTokens`] — the canonical
//!   refusal channel for any LLM-spend
//!   budget axis. Re-used verbatim; no new variant introduced.
//!
//! ## Carve-outs
//!
//! 1. **[`CostLedger`] fields are private.** The canonical
//!    signature shows the fields without explicit `pub`; the
//!    [`DailyTokenBudget`] private-field precedent applies — fields
//!    that participate in a multi-field invariant (here: monotonic
//!    saturating ledger; `usd_micros` must equal the saturating sum
//!    of every recorded turn's projected delta) are private with
//!    `pub const fn` accessors.
//!
//! 2. **[`PriceTable`] fields are public.** Per the canonical signature;
//!    `PriceTable` carries no invariant beyond "two independent
//!    `u32` rates" — the [`TurnUsage`] rationale applies.
//!    A named [`PriceTable::new`] constructor is provided for the
//!    `const fn` literal-folding pattern; `Default` returns the
//!    zero-rate sentinel (any non-zero token count projects to 0
//!    USD micros until an operator wires the production rates).
//!
//! 3. **[`UsdMicros`] mirrors [`TokenCount`] verbatim.**
//!    `#[repr(transparent)]` over `u32`, `Copy` + `Default` + `Eq` +
//!    `Hash`, `const fn new(u32)` + `const fn get() -> u32`. No
//!    `Add` / `Sub` impls — the only mutation path for a ledger's
//!    `usd_micros` is [`CostLedger::record`] /
//!    [`CostLedger::try_charge_and_record`], which the saturating
//!    invariant holds.
//!
//! 4. **`record` is infallible (saturating); [`CostLedger::try_charge_and_record`]
//!    is the daily-cap entry point.** The canonical signature pins `record` as
//!    `fn record(&mut self, …)` — no `Result` return. The daily/monthly
//!    hard cap (prepaid) lives on the sibling
//!    [`CostLedger::try_charge_and_record`] method (beyond
//!    the canonical signature), which integrates the
//!    [`DailyTokenBudget::try_charge`] refusal channel. This split
//!    matches the [`DailyTokenBudget`] pattern: [`ToolLoop::check_iter_cap`]
//!    (infallible structural check) vs.
//!    [`DailyTokenBudget::try_charge`] (the `Result`-returning gate).
//!
//! 5. **Cost formula treats cached prompt tokens as free.** The
//!    [`PriceTable`] has only `input_per_mtok_micros_u32` and
//!    `output_per_mtok_micros_u32` — no separate `cached_per_mtok_*`
//!    rate. Two faithful interpretations: (a) cached portion of
//!    prompt is charged at full input rate (cached counter is
//!    visibility-only, no discount) or (b) cached portion is charged
//!    at zero. The rationale requires the savings to be visible — the discount must
//!    be visible in the ledger sum, otherwise the cached counter is
//!    a useless decoration. This module implements (b) — cached portion
//!    of `prompt_tokens_u32` is subtracted from the input-rate
//!    multiplier; the `m0_7_cached_tokens_discounted` test asserts
//!    strict inequality between cached / non-cached projections.
//!    Operators who want a non-zero cached rate can supply a
//!    second [`PriceTable`] and call [`CostLedger::project_usd_micros`]
//!    twice; this module does not bake the discount ratio into the
//!    canonical surface.
//!
//! 6. **Daily-cap charge unit = `prompt + completion`.**
//!    [`CostLedger::try_charge_and_record`] charges the
//!    [`DailyTokenBudget`] `prompt + completion` (saturating sum)
//!    tokens. The daily cap is the daily LLM token
//!    consumption — both input and output count against the
//!    operator-prepaid cap. Cached tokens are NOT subtracted from
//!    the charge (provider still streams the cached prefix; the
//!    cap counts all tokens that cross the wire).
//!
//! 7. **No criterion bench.** Cost projection is a few `u64` multiplies +
//!    a `u32` saturating sum — not a perf hot spot, so there is no
//!    benchmark for it.

#![deny(missing_docs)]

use mnemos_a_core::error::MnemosError;

use crate::llm::TokenCount;
use crate::loop_budget::DailyTokenBudget;
use crate::turn::TurnUsage;

// ===========================================================================
// 1. Compile-time width pins
// ===========================================================================

/// `UsdMicros` width pin. One `u32` field, `#[repr(transparent)]` ⇒
/// exactly 4 bytes (alignment 4). Pairs with the
/// `TokenCount` width pin so the unit-confusion barrier between
/// "tokens" and "USD-millionths" is structurally measurable at compile
/// time.
const _USD_MICROS_SIZE_IS_4: [(); 0 - !(core::mem::size_of::<UsdMicros>() == 4) as usize] = [];

/// `PriceTable` width pin. Two `u32` fields ⇒ exactly 8 bytes
/// (alignment 4). Any future rate addition (e.g. cached-prefix rate)
/// is forced through this constant rather than silently widening the
/// carrier footprint.
const _PRICE_TABLE_SIZE_IS_8: [(); 0 - !(core::mem::size_of::<PriceTable>() == 8) as usize] = [];

/// `CostLedger` width pin. Three `u32` counters + one `UsdMicros`
/// (which is itself one `u32`) ⇒ exactly 16 bytes (alignment 4). Any
/// future field addition (e.g. monthly cap field, last-record
/// timestamp) is forced through this constant rather than silently
/// expanding the carrier footprint.
const _COST_LEDGER_SIZE_IS_16: [(); 0 - !(core::mem::size_of::<CostLedger>() == 16) as usize] = [];

// ===========================================================================
// 2. UsdMicros — typed-unit newtype over u32 (mirror of TokenCount)
// ===========================================================================

/// USD micros (one-millionth of a US dollar) — the typed-unit width
/// for every cost projection on the m-agent crate. `#[repr(transparent)]`
/// over `u32` matches the [`TokenCount`] shape and pairs with
/// it at the single unit-confusion boundary (`u32` for tokens vs.
/// `u32` for USD-millionths). The compiler refuses any silent
/// coercion between the two types.
///
/// Saturates at `u32::MAX` ≈ 4.29 × 10⁹ micros ≈ $4,294.96 — well
/// above the per-call cost envelope (5_000 tokens ×
/// ≤ $15/Mtok output rate ≈ $0.075 per call) and any reasonable
/// daily-ledger horizon an operator would configure.
///
/// No `Add` / `Sub` / `Mul` impls: the only mutation path for a
/// ledger's `usd_micros` is [`CostLedger::record`] /
/// [`CostLedger::try_charge_and_record`], which holds the saturating
/// monotonic invariant.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash, Default, PartialOrd, Ord)]
#[repr(transparent)]
pub struct UsdMicros(u32);

impl UsdMicros {
    /// Construct a [`UsdMicros`] from a raw `u32`. `const fn` so cost
    /// literals can be folded into compile-time constants (mirrors
    /// [`TokenCount::new`]).
    #[inline]
    pub const fn new(n: u32) -> Self {
        Self(n)
    }

    /// The underlying `u32` USD-micros count.
    #[inline]
    pub const fn get(self) -> u32 {
        self.0
    }
}

// ===========================================================================
// 3. PriceTable — operator-supplied per-Mtok rates (public fields)
// ===========================================================================

/// Provider price table: USD micros charged per million tokens, on
/// each rate axis. Public fields per the [`TurnUsage`]
/// rationale (no invariant beyond "two independent `u32` rates").
///
/// - `input_per_mtok_micros_u32` — USD micros per 1_000_000 input
///   tokens. The cached portion of [`TurnUsage::prompt_tokens_u32`]
///   is subtracted from the multiplier before this rate is applied
///   (cached prefix is charged at zero per carve-out 5).
/// - `output_per_mtok_micros_u32` — USD micros per 1_000_000 output
///   (completion) tokens.
///
/// `Default` returns the zero-rate sentinel — any non-zero usage
/// projects to 0 USD micros until an operator wires the production
/// rates. This makes "forgot to configure prices" a structurally
/// visible failure (cost ledger stays at 0 USD micros while token
/// counters climb) rather than a silent default-pricing rollout.
///
/// `#[repr(C)]` so the layout is stable
/// across rebuilds.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash, Default)]
#[repr(C)]
pub struct PriceTable {
    /// USD micros charged per 1_000_000 input tokens (cached prefix
    /// excluded — see [`CostLedger::project_usd_micros`]).
    pub input_per_mtok_micros_u32: u32,
    /// USD micros charged per 1_000_000 output (completion) tokens.
    pub output_per_mtok_micros_u32: u32,
}

impl PriceTable {
    /// Construct a [`PriceTable`] with operator-supplied rates.
    /// `const fn` so rate literals can be folded at compile time.
    #[inline]
    pub const fn new(input_per_mtok_micros_u32: u32, output_per_mtok_micros_u32: u32) -> Self {
        Self {
            input_per_mtok_micros_u32,
            output_per_mtok_micros_u32,
        }
    }
}

// ===========================================================================
// 4. CostLedger — saturating monotonic ledger (private fields)
// ===========================================================================

/// Per-operator cost ledger. Private fields + `pub const fn`
/// accessors + named constructor (following the [`DailyTokenBudget`]
/// private-field precedent). The invariants:
///
/// 1. **Monotonic counters.** Every field is non-decreasing across
///    [`Self::record`] / [`Self::try_charge_and_record`] calls;
///    private fields prevent external code from regressing a counter.
/// 2. **Cost equals saturating sum of projected deltas.** `usd_micros`
///    equals the saturating sum of every recorded turn's
///    [`Self::project_usd_micros`] output; the private field
///    forbids direct mutation that would break this projection
///    invariant.
///
/// `#[repr(C)]` so the layout is stable
/// across rebuilds; `Default` returns the empty ledger (every
/// counter zero).
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash, Default)]
#[repr(C)]
pub struct CostLedger {
    /// Cumulative prompt-side input tokens (includes cached prefix).
    input_tokens_u32: u32,
    /// Cumulative completion-side output tokens.
    output_tokens_u32: u32,
    /// Cumulative cached-prefix tokens (subset of `input_tokens_u32`,
    /// tracked separately for cache-hit-ratio visibility).
    cached_tokens_u32: u32,
    /// Cumulative USD micros charged (saturating).
    usd_micros: UsdMicros,
}

impl CostLedger {
    /// Construct a fresh empty ledger. `const fn` so a default ledger
    /// can be folded into compile-time constants.
    #[inline]
    pub const fn new() -> Self {
        Self {
            input_tokens_u32: 0,
            output_tokens_u32: 0,
            cached_tokens_u32: 0,
            usd_micros: UsdMicros(0),
        }
    }

    /// Cumulative input tokens (prompt-side; includes cached prefix
    /// per [`TurnUsage`] documentation).
    #[inline]
    pub const fn input_tokens_u32(&self) -> u32 {
        self.input_tokens_u32
    }

    /// Cumulative output (completion) tokens.
    #[inline]
    pub const fn output_tokens_u32(&self) -> u32 {
        self.output_tokens_u32
    }

    /// Cumulative cached-prefix tokens (subset of
    /// [`Self::input_tokens_u32`]).
    #[inline]
    pub const fn cached_tokens_u32(&self) -> u32 {
        self.cached_tokens_u32
    }

    /// Cumulative USD micros charged.
    #[inline]
    pub const fn usd_micros(&self) -> UsdMicros {
        self.usd_micros
    }

    /// Pure projection: compute the USD micros delta for a single
    /// [`TurnUsage`] at [`PriceTable`] rates. Does not mutate `self`
    /// (associated function — no `self` parameter). `const fn` so a
    /// cost projection can be folded at compile time when both
    /// arguments are known statically.
    ///
    /// Formula (per carve-out 5 — cached prefix charged at zero):
    ///
    /// ```text
    /// non_cached_prompt = prompt - cached            (saturating_sub)
    /// input_cost  = non_cached_prompt * input_per_mtok  / 1_000_000
    /// output_cost = completion        * output_per_mtok / 1_000_000
    /// delta       = saturate_to_u32(input_cost + output_cost)
    /// ```
    ///
    /// All intermediate arithmetic widens to `u64` and uses
    /// `saturating_*` so no `u32::MAX` token count or rate value
    /// can panic; the final cast to `u32` clamps at `u32::MAX`.
    #[inline]
    pub const fn project_usd_micros(usage: &TurnUsage, price: &PriceTable) -> UsdMicros {
        let non_cached = usage
            .prompt_tokens_u32
            .saturating_sub(usage.cached_tokens_u32);
        let input_cost =
            (non_cached as u64).saturating_mul(price.input_per_mtok_micros_u32 as u64) / 1_000_000;
        let output_cost = (usage.completion_tokens_u32 as u64)
            .saturating_mul(price.output_per_mtok_micros_u32 as u64)
            / 1_000_000;
        let total = input_cost.saturating_add(output_cost);
        let clamped = if total > u32::MAX as u64 {
            u32::MAX
        } else {
            total as u32
        };
        UsdMicros(clamped)
    }

    /// Record a turn's token usage at the supplied
    /// rates. Infallible by design — every counter uses
    /// `saturating_add` and the projection clamps at `u32::MAX`.
    /// The daily-cap gate lives on [`Self::try_charge_and_record`]
    /// (carve-out 4).
    pub fn record(&mut self, usage: &TurnUsage, price: &PriceTable) {
        self.input_tokens_u32 = self
            .input_tokens_u32
            .saturating_add(usage.prompt_tokens_u32);
        self.output_tokens_u32 = self
            .output_tokens_u32
            .saturating_add(usage.completion_tokens_u32);
        self.cached_tokens_u32 = self
            .cached_tokens_u32
            .saturating_add(usage.cached_tokens_u32);
        let delta = Self::project_usd_micros(usage, price);
        self.usd_micros = UsdMicros(self.usd_micros.0.saturating_add(delta.0));
    }

    /// Carve-out 4 (daily/monthly hard cap): atomic charge-then-record.
    /// Charges `prompt + completion` (saturating sum, widened to
    /// [`TokenCount`]) against the supplied [`DailyTokenBudget`] via
    /// [`DailyTokenBudget::try_charge`]. On `Ok(())`, mutates `self`
    /// identically to [`Self::record`] and returns the projected
    /// [`UsdMicros`] delta. On `Err(MnemosError::budget_exceeded(...))`,
    /// returns the error unchanged and **neither** the budget nor
    /// the ledger mutates (the [`DailyTokenBudget`] monotonic refusal invariant
    /// composes with this module's by-construction record-after-accept
    /// guarantee).
    pub fn try_charge_and_record(
        &mut self,
        usage: &TurnUsage,
        price: &PriceTable,
        budget: &mut DailyTokenBudget,
    ) -> Result<UsdMicros, MnemosError> {
        let total_tokens = usage
            .prompt_tokens_u32
            .saturating_add(usage.completion_tokens_u32);
        budget.try_charge(TokenCount::new(total_tokens))?;
        let delta = Self::project_usd_micros(usage, price);
        self.input_tokens_u32 = self
            .input_tokens_u32
            .saturating_add(usage.prompt_tokens_u32);
        self.output_tokens_u32 = self
            .output_tokens_u32
            .saturating_add(usage.completion_tokens_u32);
        self.cached_tokens_u32 = self
            .cached_tokens_u32
            .saturating_add(usage.cached_tokens_u32);
        self.usd_micros = UsdMicros(self.usd_micros.0.saturating_add(delta.0));
        Ok(delta)
    }
}

// ===========================================================================
// 5. Inline unit tests
// ===========================================================================

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use mnemos_a_core::error::BudgetAxis;

    // ---- line 1081 verbatim tests -------------------------------

    /// `m0_7_records_usage_to_usd` — verifies that [`CostLedger::record`]
    /// projects a [`TurnUsage`] through a [`PriceTable`] into the
    /// documented `non_cached * input_per_mtok / 1M + completion *
    /// output_per_mtok / 1M` formula, and that every counter field
    /// on the ledger advances by the exact amount of the recorded
    /// usage.
    #[test]
    fn m0_7_records_usage_to_usd() {
        let mut ledger = CostLedger::new();
        // Representative Phase 0 rates ($3 / Mtok input, $15 / Mtok output).
        let price = PriceTable::new(3_000_000, 15_000_000);
        let usage = TurnUsage {
            prompt_tokens_u32: 1_000,
            completion_tokens_u32: 500,
            cached_tokens_u32: 0,
        };

        ledger.record(&usage, &price);

        // Token counters advance verbatim.
        assert_eq!(ledger.input_tokens_u32(), 1_000);
        assert_eq!(ledger.output_tokens_u32(), 500);
        assert_eq!(ledger.cached_tokens_u32(), 0);
        // Formula: (1_000 - 0) * 3_000_000 / 1_000_000 + 500 * 15_000_000 / 1_000_000
        //        = 3_000 + 7_500 = 10_500 USD micros = $0.0105.
        assert_eq!(ledger.usd_micros(), UsdMicros::new(10_500));
        assert_eq!(ledger.usd_micros().get(), 10_500);

        // Pure projection helper agrees with the recorded delta.
        let projected = CostLedger::project_usd_micros(&usage, &price);
        assert_eq!(projected, UsdMicros::new(10_500));

        // A second record accumulates (saturating_add) the deltas.
        ledger.record(&usage, &price);
        assert_eq!(ledger.input_tokens_u32(), 2_000);
        assert_eq!(ledger.output_tokens_u32(), 1_000);
        assert_eq!(ledger.cached_tokens_u32(), 0);
        assert_eq!(ledger.usd_micros(), UsdMicros::new(21_000));

        // Type-level invariant: ledger width is pinned to 16 bytes
        // and stays so across rebuilds (the size pin above is the
        // compile-time gate; this is the runtime witness).
        assert_eq!(core::mem::size_of::<CostLedger>(), 16);
        assert_eq!(core::mem::size_of::<UsdMicros>(), 4);
        assert_eq!(core::mem::size_of::<PriceTable>(), 8);
    }

    /// `m0_7_cached_tokens_discounted` — verifies that the cached
    /// portion of [`TurnUsage::prompt_tokens_u32`] is charged at
    /// zero (carve-out 5 — savings made visible). A turn with cached prefix
    /// strictly projects a lower [`UsdMicros`] delta than the same
    /// prompt count with zero cache, and the difference is exactly
    /// `cached * input_per_mtok / 1M`.
    #[test]
    fn m0_7_cached_tokens_discounted() {
        let price = PriceTable::new(3_000_000, 15_000_000);

        let usage_no_cache = TurnUsage {
            prompt_tokens_u32: 1_000,
            completion_tokens_u32: 500,
            cached_tokens_u32: 0,
        };
        let usage_with_cache = TurnUsage {
            prompt_tokens_u32: 1_000,
            completion_tokens_u32: 500,
            cached_tokens_u32: 800,
        };

        let cost_no = CostLedger::project_usd_micros(&usage_no_cache, &price);
        let cost_with = CostLedger::project_usd_micros(&usage_with_cache, &price);

        // Strict inequality: cached prefix saves cost.
        assert!(cost_with.get() < cost_no.get());

        // Exact savings = cached * input_per_mtok / 1M.
        let expected_savings = 800u64 * 3_000_000u64 / 1_000_000;
        assert_eq!(
            (cost_no.get() - cost_with.get()) as u64,
            expected_savings,
            "cached savings must equal cached_tokens * input_rate / 1M"
        );

        // Boundary: cached == prompt ⇒ entire prompt is free.
        let usage_full_cache = TurnUsage {
            prompt_tokens_u32: 1_000,
            completion_tokens_u32: 500,
            cached_tokens_u32: 1_000,
        };
        let cost_full = CostLedger::project_usd_micros(&usage_full_cache, &price);
        // 0 * 3_000_000 / 1M + 500 * 15_000_000 / 1M = 7_500 micros.
        assert_eq!(cost_full, UsdMicros::new(7_500));

        // Boundary: cached > prompt ⇒ saturating_sub clamps to 0
        // (no negative cost, no panic).
        let usage_overcache = TurnUsage {
            prompt_tokens_u32: 100,
            completion_tokens_u32: 0,
            cached_tokens_u32: 9_999,
        };
        let cost_over = CostLedger::project_usd_micros(&usage_overcache, &price);
        assert_eq!(cost_over, UsdMicros::new(0));

        // Ledger integration: record with cached > 0 and confirm
        // counters track separately.
        let mut ledger = CostLedger::new();
        ledger.record(&usage_with_cache, &price);
        assert_eq!(ledger.cached_tokens_u32(), 800);
        assert_eq!(ledger.input_tokens_u32(), 1_000);
        assert_eq!(ledger.usd_micros(), cost_with);
    }

    /// `m0_7_ledger_monotone` — verifies that every counter on
    /// [`CostLedger`] is non-decreasing across [`CostLedger::record`]
    /// calls (monotonic invariant). Includes a saturation boundary
    /// to prove that hitting `u32::MAX` on any counter does not wrap.
    #[test]
    fn m0_7_ledger_monotone() {
        let price = PriceTable::new(3_000_000, 15_000_000);
        let mut ledger = CostLedger::new();

        let snapshots: [TurnUsage; 4] = [
            TurnUsage {
                prompt_tokens_u32: 100,
                completion_tokens_u32: 50,
                cached_tokens_u32: 0,
            },
            TurnUsage {
                prompt_tokens_u32: 200,
                completion_tokens_u32: 75,
                cached_tokens_u32: 10,
            },
            TurnUsage {
                prompt_tokens_u32: 50,
                completion_tokens_u32: 25,
                cached_tokens_u32: 30,
            },
            TurnUsage {
                prompt_tokens_u32: 0,
                completion_tokens_u32: 0,
                cached_tokens_u32: 0,
            },
        ];

        let mut prev_input = 0u32;
        let mut prev_output = 0u32;
        let mut prev_cached = 0u32;
        let mut prev_usd = UsdMicros::new(0);

        for snap in &snapshots {
            ledger.record(snap, &price);
            assert!(
                ledger.input_tokens_u32() >= prev_input,
                "input counter regressed"
            );
            assert!(
                ledger.output_tokens_u32() >= prev_output,
                "output counter regressed"
            );
            assert!(
                ledger.cached_tokens_u32() >= prev_cached,
                "cached counter regressed"
            );
            assert!(ledger.usd_micros() >= prev_usd, "usd_micros regressed");
            prev_input = ledger.input_tokens_u32();
            prev_output = ledger.output_tokens_u32();
            prev_cached = ledger.cached_tokens_u32();
            prev_usd = ledger.usd_micros();
        }

        // Saturation boundary: drive a counter to u32::MAX and prove
        // a subsequent record does not wrap.
        let mut saturated = CostLedger::new();
        let huge_usage = TurnUsage {
            prompt_tokens_u32: u32::MAX,
            completion_tokens_u32: u32::MAX,
            cached_tokens_u32: 0,
        };
        // Use zero-rate price so the USD ledger doesn't dominate the
        // test; we only want to prove token counters saturate.
        let zero_price = PriceTable::default();
        saturated.record(&huge_usage, &zero_price);
        assert_eq!(saturated.input_tokens_u32(), u32::MAX);
        assert_eq!(saturated.output_tokens_u32(), u32::MAX);

        let usd_after_first = saturated.usd_micros();
        // Second record at saturation ⇒ no wrap; counters stay at MAX.
        saturated.record(&huge_usage, &zero_price);
        assert_eq!(saturated.input_tokens_u32(), u32::MAX);
        assert_eq!(saturated.output_tokens_u32(), u32::MAX);
        assert!(
            saturated.usd_micros() >= usd_after_first,
            "saturating ledger must not regress at u32::MAX"
        );

        // USD saturation: a huge-rate turn pushes usd_micros to its
        // u32 ceiling without panic.
        let huge_rate = PriceTable::new(u32::MAX, u32::MAX);
        let mut usd_sat = CostLedger::new();
        usd_sat.record(&huge_usage, &huge_rate);
        assert_eq!(usd_sat.usd_micros().get(), u32::MAX);
        let usd_after = usd_sat.usd_micros();
        usd_sat.record(&huge_usage, &huge_rate);
        assert_eq!(
            usd_sat.usd_micros(),
            usd_after,
            "saturated USD ledger must not wrap"
        );
    }

    /// `m0_7_daily_cap_enforced` — verifies the prepaid daily
    /// hard cap (see `try_charge_and_record`). A charge
    /// that would breach [`DailyTokenBudget::cap_u32`] is refused
    /// with [`MnemosError::budget_exceeded(BudgetAxis::LlmTokens,
    /// projected, cap)`], and **both** the budget and the ledger
    /// stay byte-identical.
    #[test]
    fn m0_7_daily_cap_enforced() {
        let price = PriceTable::new(3_000_000, 15_000_000);
        // Phase 0 daily cap = 1_000 tokens (small for test clarity).
        let mut budget = DailyTokenBudget::new(1_000);
        let mut ledger = CostLedger::new();

        // Within-cap charge ⇒ Ok, both budget + ledger advance.
        let small_usage = TurnUsage {
            prompt_tokens_u32: 300,
            completion_tokens_u32: 200,
            cached_tokens_u32: 0,
        };
        let delta = ledger.try_charge_and_record(&small_usage, &price, &mut budget);
        assert!(delta.is_ok());
        let delta_value = match delta {
            Ok(d) => d,
            Err(_) => panic!("expected within-cap charge to succeed"),
        };
        // Projected delta: (300-0)*3 + 200*15 = 900 + 3_000 = 3_900 micros.
        assert_eq!(delta_value, UsdMicros::new(3_900));
        assert_eq!(budget.spent_u32(), 500);
        assert_eq!(budget.remaining_u32(), 500);
        assert_eq!(ledger.input_tokens_u32(), 300);
        assert_eq!(ledger.output_tokens_u32(), 200);
        assert_eq!(ledger.usd_micros(), UsdMicros::new(3_900));

        // Snapshot pre-overshoot state.
        let pre_spent = budget.spent_u32();
        let pre_input = ledger.input_tokens_u32();
        let pre_output = ledger.output_tokens_u32();
        let pre_cached = ledger.cached_tokens_u32();
        let pre_usd = ledger.usd_micros();

        // Over-cap charge ⇒ Err; both budget + ledger stay byte-identical.
        let big_usage = TurnUsage {
            prompt_tokens_u32: 400,
            completion_tokens_u32: 200,
            cached_tokens_u32: 0,
        }; // total tokens charged = 600; 500 + 600 = 1_100 > 1_000 cap.
        let err = ledger.try_charge_and_record(&big_usage, &price, &mut budget);
        let expected = MnemosError::budget_exceeded(BudgetAxis::LlmTokens, 1_100, 1_000);
        assert_eq!(err, Err(expected));

        // Budget invariant: refused charge must NOT mutate spent_u32.
        assert_eq!(budget.spent_u32(), pre_spent);
        assert_eq!(budget.remaining_u32(), 500);
        // Ledger invariant: refused charge must NOT mutate any field.
        assert_eq!(ledger.input_tokens_u32(), pre_input);
        assert_eq!(ledger.output_tokens_u32(), pre_output);
        assert_eq!(ledger.cached_tokens_u32(), pre_cached);
        assert_eq!(ledger.usd_micros(), pre_usd);

        // A subsequent within-remaining charge still succeeds — the
        // refused charge does not "poison" the gate.
        let small_again = TurnUsage {
            prompt_tokens_u32: 200,
            completion_tokens_u32: 100,
            cached_tokens_u32: 50,
        };
        let delta2 = ledger.try_charge_and_record(&small_again, &price, &mut budget);
        assert!(delta2.is_ok());
        assert_eq!(budget.spent_u32(), 800);
        assert_eq!(budget.remaining_u32(), 200);
        assert_eq!(ledger.input_tokens_u32(), 500);
        assert_eq!(ledger.output_tokens_u32(), 300);
        assert_eq!(ledger.cached_tokens_u32(), 50);

        // Drive spent exactly to cap ⇒ budget exhausted; any
        // subsequent non-zero charge refused.
        let fill = TurnUsage {
            prompt_tokens_u32: 100,
            completion_tokens_u32: 100,
            cached_tokens_u32: 0,
        };
        let delta3 = ledger.try_charge_and_record(&fill, &price, &mut budget);
        assert!(delta3.is_ok());
        assert_eq!(budget.spent_u32(), 1_000);
        assert!(budget.is_exhausted());

        let leftover = TurnUsage {
            prompt_tokens_u32: 1,
            completion_tokens_u32: 0,
            cached_tokens_u32: 0,
        };
        let err2 = ledger.try_charge_and_record(&leftover, &price, &mut budget);
        let expected2 = MnemosError::budget_exceeded(BudgetAxis::LlmTokens, 1_001, 1_000);
        assert_eq!(err2, Err(expected2));
        // Budget + ledger unchanged after the second refusal.
        assert_eq!(budget.spent_u32(), 1_000);
        assert_eq!(ledger.input_tokens_u32(), 600);
    }
}
