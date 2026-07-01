//! `skew_strategy` — MNEMOS × SKEW K-4: the strict TYPED STRATEGY DSL + the deterministic
//! shadow→certify spine, with the LLM **OFF the hot path**.
//!
//! The frontier PROPOSES a trading strategy as a strict typed DSL (serde, parsed from TOML). A
//! malformed / hallucinated proposal is a **PARSE ERROR** (`#[serde(deny_unknown_fields)]` + strict
//! typed enums + bounded fields) — it can never become a bad trade. The deterministic runtime then
//! EXECUTES the DSL over the REAL K-3 history series, emits candidate [`crate::skew_oracle::SkewTrade`]
//! legs, and gates EACH with the K-1 trade oracle ([`crate::skew_oracle::oracle_verdict`] — escrow ≤
//! per-tx, spent+escrow ≤ budget, ≤ drawdown; a `Denied` leg never proceeds, no LLM judge). A
//! paper-trade SHADOW track record accumulates (money 0); the EXACT conformal cert
//! ([`crate::conformal::certify_far_default`], the O-3c Clopper-Pearson FAR bound) CERTIFIES a strategy
//! iff its out-of-bounds proposal RATE is provably bounded (`k` oracle-denied fires in `n` total fires;
//! `k=0, n≥10 ⇒ certified`). Only a CERTIFIED strategy ACCUMULATEs into the certified corpus (the K-4
//! dispatch glue runs it through `autonomy_evolve::strategy_candidate` →
//! `autonomy_evolve::select_evolution_writes` — the P-HALL two-derivation gate; a hallucinated "win"
//! NEVER writes).
//!
//! ## PURE (no Solana / serde-json / net / clock / float / RNG / key / chain-write dependency)
//! Every signal analyzer + the rule evaluation is pure integer math over the slot-sorted K-3 window;
//! byte-identical re-runs. The model never computes a candle / signal / verdict; the oracle DECIDES.
//! The wire format is **TOML** (the always-compiled default codec — `serde_json` is feature-gated, so
//! TOML keeps the DSL pure + golden-tested in the default build). This module reaches NO key, NO
//! grant, NO custody, NO socket; the live sub-budget is the EXISTING owner-armed K-2 path.
//!
//! ## Honest scope (K-4)
//! "Certified" means the strategy's PROPOSALS provably stay IN-BOUNDS over the shadow distribution
//! (the affordability/safety property), NOT that the strategy is PROFITABLE (a P&L/return cert would
//! need a deterministic outcome oracle — NEVER an LLM judge — and is a future deepening). v1 uses
//! fixed per-rule trade params (so within ONE rule `k ∈ {0, n}`; a MULTI-rule strategy gives a genuine
//! `0 ≤ k ≤ n`). shadow money 0; the live sub-budget is the owner go-live (K-2).

use serde::{Deserialize, Serialize};

use crate::conformal::certify_far_default;
use crate::skew_history::{HistorySample, HistoryWindow, SeriesKind};
use crate::skew_oracle::{OracleBounds, PartyDirection, SkewTrade, TradeVerdict, oracle_verdict};

/// The maximum number of rules ONE strategy may carry (bounded; a hostile/hallucinated DSL can never
/// allocate past this — fail-closed at parse).
pub const MAX_RULES: usize = 32;
/// The maximum strategy / rule name length (bounded).
pub const MAX_NAME_LEN: usize = 64;
/// The maximum signal lookback window (bounded; a huge lookback is rejected at parse).
pub const MAX_LOOKBACK: u32 = 512;
/// The maximum number of shadow FIRES counted toward the conformal cert (= the conformal `N_BOUND`).
/// The backtest stops counting past this (bounded), so `n ≤ N_BOUND` always and the exact cert applies.
pub const MAX_SHADOW_FIRES: u32 = 1024;

/// The AEAD associated-data binding a SEALED certified-strategy corpus entry — DISTINCT from the
/// memory-record, walrus-index, settings, and skew-history AADs (so a corpus blob can never be opened
/// as another payload). `PersistedStore::seal_strategy_corpus` / `open_strategy_corpus` bind to this.
pub const STRATEGY_CORPUS_AAD: &[u8] = b"sinabro.skew.strategy.v1";

// ============================================================================
// The strict typed DSL (serde; parsed from TOML; deny_unknown_fields everywhere).
// ============================================================================

/// The strategy archetype label — owner Q1 ("전부다 … 범위의 제약을 두지마"): the grammar is general,
/// covering market-making / HFT / hedge / directional / secondary / custom. The label is for
/// awareness + the corpus topic; the SAFETY is invariant (every leg is oracle-gated regardless).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StrategyArchetype {
    /// Two-sided batch quoting (a bid leg + an ask leg).
    MarketMaking,
    /// Signal-driven rapid entries.
    Hft,
    /// A hedging overlay (offsetting legs).
    Hedge,
    /// A directional view (one-sided).
    Directional,
    /// A secondary-market action (list/quote/accept an existing position).
    Secondary,
    /// Any other / experimental archetype.
    Custom,
}

impl StrategyArchetype {
    /// Stable display label.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::MarketMaking => "market_making",
            Self::Hft => "hft",
            Self::Hedge => "hedge",
            Self::Directional => "directional",
            Self::Secondary => "secondary",
            Self::Custom => "custom",
        }
    }
}

/// Which K-3 time-series a signal reads.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SeriesSel {
    /// The `ReferenceSnapshot` price (OHLC) series.
    Price,
    /// The `SettlementReceipt` volume / realized-price series.
    Volume,
    /// The `FundingState` cumulative-funding series (signed).
    Funding,
}

impl SeriesSel {
    /// The matching K-3 [`SeriesKind`].
    #[must_use]
    pub const fn kind(self) -> SeriesKind {
        match self {
            Self::Price => SeriesKind::ReferencePrice,
            Self::Volume => SeriesKind::SettlementVolume,
            Self::Funding => SeriesKind::FundingRate,
        }
    }
}

/// A deterministic integer signal feature computed over the K-3 series (no float, no clock, no LLM).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SignalFeature {
    /// The price at the current sample (`price_atoms`).
    LastClose,
    /// The simple moving average of `price_atoms` over the trailing `lookback` samples.
    Sma,
    /// `price_atoms[i] − price_atoms[i − lookback]` (signed price change).
    Momentum,
    /// The latest funding delta `cumulative[i] − cumulative[i−1]` (signed; the funding series).
    FundingStep,
    /// The cumulative funding index at the current sample (signed).
    FundingCumulative,
    /// The summed `amount_atoms` (volume) over the trailing `lookback` samples.
    VolumeSum,
    /// `max(price) − min(price)` over the trailing `lookback` samples (a volatility proxy).
    Spread,
}

/// A signal spec: a deterministic feature over a chosen series with a bounded lookback.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Signal {
    /// Which deterministic feature to compute.
    pub feature: SignalFeature,
    /// Which K-3 series to read.
    pub series: SeriesSel,
    /// The trailing window length (bounded by [`MAX_LOOKBACK`]; clamped to ≥1 at eval).
    pub lookback: u32,
}

/// A comparison operator for the parametric rule.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CompareOp {
    /// `signal > threshold`.
    GreaterThan,
    /// `signal < threshold`.
    LessThan,
    /// `signal >= threshold`.
    GreaterEqual,
    /// `signal <= threshold`.
    LessEqual,
    /// `signal` crossed the threshold upward (prev ≤ threshold < current).
    CrossesAbove,
    /// `signal` crossed the threshold downward (prev ≥ threshold > current).
    CrossesBelow,
}

/// The parametric condition: `signal <op> threshold` (the threshold is TOML-native `i64`, widened to
/// `i128` for the comparison).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Condition {
    /// The comparison operator.
    pub op: CompareOp,
    /// The parametric threshold (signed).
    pub threshold: i64,
}

/// Which side of an affine forward / perp a trade leg sits on (mirrors
/// [`crate::skew_oracle::PartyDirection`]).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Side {
    /// Long.
    Long,
    /// Short.
    Short,
}

impl Side {
    const fn direction(self) -> PartyDirection {
        match self {
            Self::Long => PartyDirection::Long,
            Self::Short => PartyDirection::Short,
        }
    }
}

/// The trade leg a rule emits when it FIRES — an externally-tagged enum over the 5 K-1 payoff classes
/// (`[rule.trade.<kind>]` in TOML). Every variant maps to a [`SkewTrade`] and is oracle-gated; there is
/// NO un-gated action in the grammar (no "exec" / "sign" / "address" field exists — IV-K4-1/IV-K4-4).
/// Amounts are TOML-native `u64` / prices `i64`, widened to the oracle's `u128` / `i128`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TradeTemplate {
    /// USM-VM (0x81) variation-margin forward: escrow = `notional × initial_bps / 10_000`.
    UsmVm {
        /// Trade notional in minor units.
        notional: u64,
        /// Initial-margin schedule in basis points (`0..=10_000`).
        initial_bps: u32,
    },
    /// FIXED-LOCK (0x11): escrow = `locked_amount`.
    FixedLock {
        /// Locked collateral in minor units.
        locked_amount: u64,
    },
    /// WCC (0x1B) affine forward / swap / collar: escrow = the analytic corner WCL.
    WccAffine {
        /// Which side the leg is on.
        direction: Side,
        /// Integer contract count.
        quantity: u64,
        /// Contract-size multiplier (mint scale).
        contract_size: u64,
        /// Declared collar low bound.
        collar_lo: i64,
        /// Declared collar high bound.
        collar_hi: i64,
        /// Forward / strike price `Pc`.
        forward_price: i64,
    },
    /// Perp (isolated margin): escrow = `epoch_wcl_linear` (the HONEST weaker bound).
    Perp {
        /// Net signed position quantity (`+` long, `−` short).
        signed_qty: i64,
        /// Contract-size multiplier.
        contract_size: u64,
        /// Entry / reference price.
        entry_price: i64,
        /// Epoch band low bound.
        lo_price: i64,
        /// Epoch band high bound.
        hi_price: i64,
        /// Per-unit funding cap reserved up front.
        funding_cap: u64,
    },
    /// Non-affine / piecewise via the chain-certified per-unit bound: escrow upper bound =
    /// `qty × wcl_bound_per_unit` (option / spread / digital / straddle / custom / a secondary-market
    /// position acquire whose escrow is the position's certified worst case).
    CertifiedBound {
        /// The template's certified per-unit worst-case-loss bound.
        wcl_bound_per_unit: u64,
        /// Integer contract count.
        quantity: u64,
    },
}

impl TradeTemplate {
    /// Resolve this leg to a concrete [`SkewTrade`] (widening TOML `u64`/`i64` to the oracle's
    /// `u128`/`i128`). The oracle then re-derives its worst-case escrow + the verdict.
    #[must_use]
    pub fn to_skew_trade(&self) -> SkewTrade {
        match *self {
            Self::UsmVm {
                notional,
                initial_bps,
            } => SkewTrade::UsmVmForward {
                notional_minor: u128::from(notional),
                initial_bps,
            },
            Self::FixedLock { locked_amount } => SkewTrade::FixedLock {
                locked_amount_minor: u128::from(locked_amount),
            },
            Self::WccAffine {
                direction,
                quantity,
                contract_size,
                collar_lo,
                collar_hi,
                forward_price,
            } => SkewTrade::WccAffineForward {
                direction: direction.direction(),
                quantity_q: quantity,
                contract_size: u128::from(contract_size),
                collar_lo: i128::from(collar_lo),
                collar_hi: i128::from(collar_hi),
                forward_price_pc: i128::from(forward_price),
            },
            Self::Perp {
                signed_qty,
                contract_size,
                entry_price,
                lo_price,
                hi_price,
                funding_cap,
            } => SkewTrade::Perp {
                signed_qty,
                contract_size: u128::from(contract_size),
                entry_price: i128::from(entry_price),
                lo_price: i128::from(lo_price),
                hi_price: i128::from(hi_price),
                funding_cap_per_unit: u128::from(funding_cap),
            },
            Self::CertifiedBound {
                wcl_bound_per_unit,
                quantity,
            } => SkewTrade::CertifiedBound {
                wcl_bound_per_unit,
                quantity_q: quantity,
            },
        }
    }

    /// A short class label.
    #[must_use]
    pub const fn class_label(&self) -> &'static str {
        match self {
            Self::UsmVm { .. } => "usm-vm",
            Self::FixedLock { .. } => "fixed-lock",
            Self::WccAffine { .. } => "wcc-affine",
            Self::Perp { .. } => "perp",
            Self::CertifiedBound { .. } => "certified-bound",
        }
    }
}

/// One parametric rule: a deterministic signal over a series + a comparison + a trade leg to emit when
/// the comparison FIRES.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StrategyRule {
    /// A short rule name (bounded).
    pub name: NameStr,
    /// The deterministic signal.
    pub signal: Signal,
    /// The comparison condition.
    pub condition: Condition,
    /// The trade leg emitted on a fire.
    pub trade: TradeTemplate,
}

/// A bounded name string newtype — deserializes from a TOML string but fail-closes (parse error) if it
/// exceeds [`MAX_NAME_LEN`], so a hostile/hallucinated proposal can never carry an unbounded name.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct NameStr(String);

impl NameStr {
    /// The inner string.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl<'de> Deserialize<'de> for NameStr {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let s = String::deserialize(d)?;
        if s.len() > MAX_NAME_LEN {
            return Err(serde::de::Error::custom("name exceeds MAX_NAME_LEN"));
        }
        Ok(Self(s))
    }
}

/// The strict typed strategy DSL. The frontier PROPOSES one of these as TOML; a malformed / unknown-
/// field / wrong-typed / over-cap proposal is a PARSE ERROR (never a partial strategy, never a trade).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StrategyDsl {
    /// The strategy name (bounded).
    pub name: NameStr,
    /// The archetype label (market-making / HFT / hedge / directional / secondary / custom).
    pub archetype: StrategyArchetype,
    /// The bounded set of parametric rules (≥1, ≤ [`MAX_RULES`]; validated at parse).
    pub rules: Vec<StrategyRule>,
}

/// Why a proposed DSL did not parse into a valid strategy (fail-closed; explicit). A serde error
/// (unknown field / wrong type / missing field) is [`StrategyParseError::Toml`]; the bound checks are
/// the rest. A hallucination lands HERE, never as a trade.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum StrategyParseError {
    /// The TOML did not deserialize into the strict typed DSL (unknown field, wrong type, missing
    /// field, unknown enum variant — the serde-fail-closed wall).
    #[error("strategy DSL parse error (serde-fail-closed): {0}")]
    Toml(String),
    /// The strategy has no rules (a strategy must carry ≥1 rule).
    #[error("strategy has no rules")]
    NoRules,
    /// The strategy exceeds [`MAX_RULES`].
    #[error("strategy exceeds MAX_RULES ({0} > {MAX_RULES})")]
    TooManyRules(usize),
    /// A rule's lookback exceeds [`MAX_LOOKBACK`].
    #[error("rule lookback exceeds MAX_LOOKBACK ({0} > {MAX_LOOKBACK})")]
    LookbackTooLarge(u32),
}

/// Parse + validate a proposed strategy DSL from TOML — the serde-fail-closed wall (IV-K4-1). A
/// malformed / unknown-field / wrong-typed proposal is `Err(Toml)`; the bound checks (≥1 rule, ≤
/// MAX_RULES, lookback ≤ MAX_LOOKBACK) are the rest. The frontier's free text becomes a trade ONLY
/// through this gate.
///
/// # Errors
/// Returns [`StrategyParseError`] on a serde failure or a bound violation (never a partial strategy).
pub fn parse_strategy_toml(src: &str) -> Result<StrategyDsl, StrategyParseError> {
    let dsl: StrategyDsl =
        toml::from_str(src).map_err(|e| StrategyParseError::Toml(e.to_string()))?;
    if dsl.rules.is_empty() {
        return Err(StrategyParseError::NoRules);
    }
    if dsl.rules.len() > MAX_RULES {
        return Err(StrategyParseError::TooManyRules(dsl.rules.len()));
    }
    for r in &dsl.rules {
        if r.signal.lookback > MAX_LOOKBACK {
            return Err(StrategyParseError::LookbackTooLarge(r.signal.lookback));
        }
    }
    Ok(dsl)
}

impl StrategyDsl {
    /// Serialize the (already-validated) DSL back to canonical TOML — the corpus stores THIS as the
    /// pattern content (re-parseable, drift-0). Pure.
    ///
    /// # Errors
    /// Returns the `toml` serialization error if the DSL cannot be rendered (never for a valid DSL).
    pub fn to_toml(&self) -> Result<String, toml::ser::Error> {
        toml::to_string(self)
    }

    /// A bounded topic/goal string for the corpus pattern (`skew-strategy: <archetype>/<name>`).
    #[must_use]
    pub fn corpus_goal(&self) -> String {
        format!(
            "skew-strategy:{}/{}",
            self.archetype.as_str(),
            self.name.as_str()
        )
    }
}

// ============================================================================
// Deterministic signal analyzers (pure integer math; no float, no clock, no RNG).
// ============================================================================

/// Saturating `u128 → i128` (real prices are tiny; saturate rather than panic — determinism).
const fn to_i128(v: u128) -> i128 {
    if v > i128::MAX as u128 {
        i128::MAX
    } else {
        v as i128
    }
}

/// Compute the deterministic signal value at sample index `i` over a slot-sorted `samples` slice, for
/// `feature` with `lookback`. Returns `None` (no fire at this index) when there is not enough history
/// for the feature (e.g. momentum needs `i ≥ lookback`). Pure integer; never panics, never a float.
#[must_use]
pub fn compute_signal(
    feature: SignalFeature,
    samples: &[HistorySample],
    lookback: u32,
    i: usize,
) -> Option<i128> {
    if i >= samples.len() {
        return None;
    }
    let lb = lookback.max(1) as usize;
    match feature {
        SignalFeature::LastClose => Some(to_i128(samples[i].price_atoms)),
        SignalFeature::FundingCumulative => Some(samples[i].signed_atoms),
        SignalFeature::FundingStep => {
            if i == 0 {
                return None;
            }
            Some(
                samples[i]
                    .signed_atoms
                    .saturating_sub(samples[i - 1].signed_atoms),
            )
        }
        SignalFeature::Sma => {
            if i + 1 < lb {
                return None;
            }
            let start = i + 1 - lb;
            let mut sum: i128 = 0;
            for s in &samples[start..=i] {
                sum = sum.saturating_add(to_i128(s.price_atoms));
            }
            Some(sum / lb as i128)
        }
        SignalFeature::Momentum => {
            if i < lb {
                return None;
            }
            Some(
                to_i128(samples[i].price_atoms)
                    .saturating_sub(to_i128(samples[i - lb].price_atoms)),
            )
        }
        SignalFeature::VolumeSum => {
            if i + 1 < lb {
                return None;
            }
            let start = i + 1 - lb;
            let mut sum: i128 = 0;
            for s in &samples[start..=i] {
                sum = sum.saturating_add(to_i128(s.amount_atoms));
            }
            Some(sum)
        }
        SignalFeature::Spread => {
            if i + 1 < lb {
                return None;
            }
            let start = i + 1 - lb;
            let mut lo = i128::MAX;
            let mut hi = i128::MIN;
            for s in &samples[start..=i] {
                let p = to_i128(s.price_atoms);
                lo = lo.min(p);
                hi = hi.max(p);
            }
            Some(hi.saturating_sub(lo))
        }
    }
}

/// Whether `signal <op> threshold` FIRES at index `i`. For the cross operators, `prev` is the signal
/// at `i−1` (a cross needs both points; `None` ⇒ no cross). Pure integer comparison.
#[must_use]
pub fn condition_fires(cond: &Condition, signal: i128, prev: Option<i128>) -> bool {
    let t = i128::from(cond.threshold);
    match cond.op {
        CompareOp::GreaterThan => signal > t,
        CompareOp::LessThan => signal < t,
        CompareOp::GreaterEqual => signal >= t,
        CompareOp::LessEqual => signal <= t,
        CompareOp::CrossesAbove => prev.is_some_and(|p| p <= t && signal > t),
        CompareOp::CrossesBelow => prev.is_some_and(|p| p >= t && signal < t),
    }
}

// ============================================================================
// The shadow backtest + the conformal certification.
// ============================================================================

/// The per-rule shadow result over the history.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RuleShadow {
    /// The rule name.
    pub rule_name: String,
    /// The trade class label.
    pub trade_class: String,
    /// How many times the rule FIRED over the history (shadow trades).
    pub fires: u32,
    /// Of those, how many cleared the K-1 oracle (in-bounds wins).
    pub in_bounds: u32,
    /// Of those, how many the oracle DENIED (out-of-bounds — the strategy's false accepts).
    pub denied: u32,
    /// The re-derived worst-case escrow of this rule's (fixed) trade leg, or `None` (fail-closed).
    pub escrow_minor: Option<u128>,
}

/// The whole-strategy shadow track record (money 0). `fires`/`in_bounds`/`denied` are aggregated
/// across all rules; `denied` is the conformal `k` and `fires` (capped at [`MAX_SHADOW_FIRES`]) is `n`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ShadowReport {
    /// The strategy name.
    pub strategy_name: String,
    /// The archetype label.
    pub archetype: StrategyArchetype,
    /// Total shadow FIRES across all rules (the conformal `n`; bounded by [`MAX_SHADOW_FIRES`]).
    pub fires: u32,
    /// Total fires that cleared the oracle (in-bounds wins).
    pub in_bounds: u32,
    /// Total fires the oracle DENIED (the conformal `k`; the strategy's out-of-bounds rate numerator).
    pub denied: u32,
    /// Total history samples walked across all referenced series.
    pub samples_seen: u32,
    /// The per-rule breakdown.
    pub per_rule: Vec<RuleShadow>,
}

/// The conformal certification verdict for a shadow track record (the O-3c FAR bound — drift-0).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StrategyCert {
    /// Whether the strategy is CERTIFIED (its out-of-bounds proposal rate is provably bounded:
    /// `certify_far_default(k, n)`; `k=0, n≥10 ⇒ certified`).
    pub certified: bool,
    /// The conformal `k` = oracle-denied fires (out-of-bounds false accepts).
    pub k: u32,
    /// The conformal `n` = total fires counted (bounded by [`MAX_SHADOW_FIRES`]).
    pub n: u32,
}

/// Pick the series window matching a [`SeriesSel`] (the first window of that kind), if accumulated.
fn window_for(windows: &[HistoryWindow], sel: SeriesSel) -> Option<&HistoryWindow> {
    let kind = sel.kind();
    windows.iter().find(|w| w.kind == kind)
}

/// Shadow-evaluate one rule over its series window: walk the slot-sorted samples, compute the signal,
/// evaluate the condition, and on each FIRE gate the (fixed) trade leg with the K-1 oracle
/// ([`oracle_verdict`] at a `spent=0` / `portfolio=0` baseline — "is this trade individually
/// in-bounds"). Returns the per-rule shadow + the count of fires consumed (so the whole-strategy cap is
/// honored). Pure: no float, no clock, no LLM judge.
#[must_use]
pub fn shadow_rule(
    rule: &StrategyRule,
    windows: &[HistoryWindow],
    bounds: &OracleBounds,
    remaining_budget: u32,
) -> (RuleShadow, u32) {
    let trade = rule.trade.to_skew_trade();
    let escrow_minor = trade.worst_case_escrow();
    let mut shadow = RuleShadow {
        rule_name: rule.name.as_str().to_string(),
        trade_class: rule.trade.class_label().to_string(),
        fires: 0,
        in_bounds: 0,
        denied: 0,
        escrow_minor,
    };
    let Some(window) = window_for(windows, rule.signal.series) else {
        return (shadow, 0);
    };
    let samples = &window.samples;
    let mut prev: Option<i128> = None;
    let mut consumed = 0u32;
    for i in 0..samples.len() {
        if consumed >= remaining_budget {
            break; // the whole-strategy fire cap is honored (bounded; IV-K4-7)
        }
        let Some(signal) = compute_signal(rule.signal.feature, samples, rule.signal.lookback, i)
        else {
            // not enough history for the feature yet — no signal, so no cross-prev either.
            continue;
        };
        let fired = condition_fires(&rule.condition, signal, prev);
        prev = Some(signal);
        if !fired {
            continue;
        }
        shadow.fires += 1;
        consumed += 1;
        // EACH fire is oracle-gated — a Denied leg is an out-of-bounds false accept (k), never proceeds.
        match oracle_verdict(&trade, 0, 0, bounds) {
            TradeVerdict::AffordableInBounds { .. } => shadow.in_bounds += 1,
            TradeVerdict::Denied(_) => shadow.denied += 1,
        }
    }
    (shadow, consumed)
}

/// Shadow-evaluate a whole strategy over the accumulated K-3 history (money 0). Aggregates the per-rule
/// fires/in-bounds/denied; the whole-strategy fire count is bounded by [`MAX_SHADOW_FIRES`] so the exact
/// conformal cert applies. Deterministic — byte-identical re-runs.
#[must_use]
pub fn shadow_evaluate(
    dsl: &StrategyDsl,
    windows: &[HistoryWindow],
    bounds: &OracleBounds,
) -> ShadowReport {
    let mut report = ShadowReport {
        strategy_name: dsl.name.as_str().to_string(),
        archetype: dsl.archetype,
        fires: 0,
        in_bounds: 0,
        denied: 0,
        samples_seen: 0,
        per_rule: Vec::with_capacity(dsl.rules.len()),
    };
    // count the distinct series the strategy reads (for the samples_seen honesty field).
    let mut seen_series: Vec<SeriesKind> = Vec::new();
    for rule in &dsl.rules {
        let remaining = MAX_SHADOW_FIRES.saturating_sub(report.fires);
        let (shadow, _consumed) = shadow_rule(rule, windows, bounds, remaining);
        report.fires = report.fires.saturating_add(shadow.fires);
        report.in_bounds = report.in_bounds.saturating_add(shadow.in_bounds);
        report.denied = report.denied.saturating_add(shadow.denied);
        let kind = rule.signal.series.kind();
        if !seen_series.contains(&kind) {
            seen_series.push(kind);
            if let Some(w) = window_for(windows, rule.signal.series) {
                report.samples_seen = report
                    .samples_seen
                    .saturating_add(u32::try_from(w.samples.len()).unwrap_or(u32::MAX));
            }
        }
        report.per_rule.push(shadow);
    }
    report
}

/// CERTIFY a strategy from its shadow track record (the O-3c exact Clopper-Pearson FAR bound — reuse
/// [`certify_far_default`], owner Q2). `k` = oracle-denied fires (out-of-bounds false accepts), `n` =
/// total fires. A strategy certifies iff its out-of-bounds RATE is provably bounded (`k=0, n≥10`); a
/// degenerate `n=0` strategy (never fired) never certifies. NO LLM judge — the cert is the deterministic
/// integer inequality.
#[must_use]
pub fn certify_strategy(report: &ShadowReport) -> StrategyCert {
    let certified = certify_far_default(u64::from(report.denied), u64::from(report.fires));
    StrategyCert {
        certified,
        k: report.denied,
        n: report.fires,
    }
}

/// Render the shadow report + the cert verdict (PURE; the dispatch glue calls this). Honest: shadow
/// money 0; certified = in-bounds rate provably bounded, NOT profitable; the live sub-budget is K-2.
#[must_use]
pub fn render_shadow(report: &ShadowReport, cert: &StrategyCert) -> String {
    use std::fmt::Write as _;
    let mut out = String::new();
    let _ = writeln!(
        out,
        "skew strategy [{}] archetype={} (shadow backtest over REAL K-3 history; deterministic; no LLM judge; money 0)",
        report.strategy_name,
        report.archetype.as_str()
    );
    let _ = writeln!(
        out,
        "  samples_seen={} fires(n)={} in_bounds={} denied(k)={}",
        report.samples_seen, report.fires, report.in_bounds, report.denied
    );
    for r in &report.per_rule {
        let escrow = r
            .escrow_minor
            .map_or_else(|| "n/a(fail-closed)".to_string(), |e| e.to_string());
        let _ = writeln!(
            out,
            "    rule [{}] trade={} escrow={} fires={} in_bounds={} denied={}",
            r.rule_name, r.trade_class, escrow, r.fires, r.in_bounds, r.denied
        );
    }
    let _ = writeln!(
        out,
        "  CONFORMAL CERT (Clopper-Pearson FAR≤0.27@95%, k={} n={}): {}",
        cert.k,
        cert.n,
        if cert.certified {
            "CERTIFIED (out-of-bounds proposal rate provably bounded; eligible to ACCUMULATE)"
        } else {
            "NOT certified (insufficient in-bounds fires or out-of-bounds rate too high)"
        }
    );
    let _ = writeln!(
        out,
        "  (honest: certified = proposals stay in-bounds, NOT profitable; shadow ≠ live; the live sub-budget is the owner-armed K-2 path)"
    );
    out
}

/// A canonical EXAMPLE strategy DSL (the grammar reference the frontier/owner can copy + edit) — a
/// two-leg market-making strategy on the funding series. Pure string.
#[must_use]
pub fn example_strategy_toml() -> &'static str {
    r#"# skew strategy DSL (TOML) — the frontier proposes one of these; a malformed proposal is a
# serde parse error, never a trade. Every leg is oracle-gated (K-1) and the strategy is certified
# by the deterministic conformal FAR bound before it can accumulate. Owner Q1: no scope restriction.
name = "mm-funding-skew"
archetype = "market_making"

# bid leg: when funding skews negative, propose a fixed-lock long forward.
[[rules]]
name = "bid"
signal = { feature = "funding_cumulative", series = "funding", lookback = 1 }
condition = { op = "less_equal", threshold = 0 }
trade = { fixed_lock = { locked_amount = 500000 } }

# ask leg: when funding skews positive, propose a fixed-lock short.
[[rules]]
name = "ask"
signal = { feature = "funding_cumulative", series = "funding", lookback = 1 }
condition = { op = "greater_equal", threshold = 0 }
trade = { fixed_lock = { locked_amount = 500000 } }
"#
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::skew_history::SeriesKind;

    fn bounds(per_tx: u128, budget: u128) -> OracleBounds {
        OracleBounds {
            per_tx_max_minor: per_tx,
            total_budget_minor: budget,
            drawdown_max_minor: budget,
        }
    }

    fn funding_window(cumulatives: &[i128]) -> HistoryWindow {
        let mut w = HistoryWindow::new(SeriesKind::FundingRate, [0x33; 32]);
        for (i, c) in cumulatives.iter().enumerate() {
            w.append_sample(HistorySample {
                slot: 100 + i as u64,
                price_atoms: 0,
                amount_atoms: 0,
                signed_atoms: *c,
                aux_u32: 0,
                exponent: 0,
            });
        }
        w
    }

    fn price_window(prices: &[u128]) -> HistoryWindow {
        let mut w = HistoryWindow::new(SeriesKind::ReferencePrice, [0x44; 32]);
        for (i, p) in prices.iter().enumerate() {
            w.append_sample(HistorySample {
                slot: 100 + i as u64,
                price_atoms: *p,
                amount_atoms: 0,
                signed_atoms: 0,
                aux_u32: 0,
                exponent: 6,
            });
        }
        w
    }

    // ---- IV-K4-1: serde-fail-closed parse ------------------------------------------------------

    #[test]
    fn parse_accepts_a_well_formed_dsl_golden() {
        let dsl = parse_strategy_toml(example_strategy_toml()).expect("the example parses");
        assert_eq!(dsl.name.as_str(), "mm-funding-skew");
        assert_eq!(dsl.archetype, StrategyArchetype::MarketMaking);
        assert_eq!(dsl.rules.len(), 2);
        assert_eq!(
            dsl.rules[0].signal.feature,
            SignalFeature::FundingCumulative
        );
        assert_eq!(dsl.rules[0].condition.op, CompareOp::LessEqual);
        assert_eq!(
            dsl.rules[0].trade,
            TradeTemplate::FixedLock {
                locked_amount: 500_000
            }
        );
        // round-trips through canonical TOML.
        let toml = dsl.to_toml().expect("serializes");
        let back = parse_strategy_toml(&toml).expect("re-parses");
        assert_eq!(back, dsl);
    }

    #[test]
    fn parse_rejects_a_hallucinated_or_malformed_dsl() {
        // an UNKNOWN field (deny_unknown_fields) — the hallucination wall.
        let unknown = r#"
name = "x"
archetype = "market_making"
[[rules]]
name = "r"
signal = { feature = "last_close", series = "price", lookback = 1 }
condition = { op = "greater_than", threshold = 1 }
trade = { fixed_lock = { locked_amount = 1 } }
exec = "rm -rf /"
"#;
        assert!(matches!(
            parse_strategy_toml(unknown),
            Err(StrategyParseError::Toml(_))
        ));
        // an UNKNOWN enum variant (a hallucinated feature) — strict typed enum wall.
        let bad_enum = r#"
name = "x"
archetype = "market_making"
[[rules]]
name = "r"
signal = { feature = "moon_phase", series = "price", lookback = 1 }
condition = { op = "greater_than", threshold = 1 }
trade = { fixed_lock = { locked_amount = 1 } }
"#;
        assert!(matches!(
            parse_strategy_toml(bad_enum),
            Err(StrategyParseError::Toml(_))
        ));
        // an UNKNOWN trade kind (a hallucinated payoff) — externally-tagged enum wall.
        let bad_trade = r#"
name = "x"
archetype = "market_making"
[[rules]]
name = "r"
signal = { feature = "last_close", series = "price", lookback = 1 }
condition = { op = "greater_than", threshold = 1 }
trade = { rug_pull = { amount = 1 } }
"#;
        assert!(matches!(
            parse_strategy_toml(bad_trade),
            Err(StrategyParseError::Toml(_))
        ));
        // a MISSING field (no condition) — fail-closed.
        let missing = r#"
name = "x"
archetype = "hft"
[[rules]]
name = "r"
signal = { feature = "last_close", series = "price", lookback = 1 }
trade = { fixed_lock = { locked_amount = 1 } }
"#;
        assert!(matches!(
            parse_strategy_toml(missing),
            Err(StrategyParseError::Toml(_))
        ));
    }

    #[test]
    fn parse_enforces_bounds_fail_closed() {
        // no rules ⇒ NoRules.
        let no_rules = "name = \"x\"\narchetype = \"custom\"\nrules = []\n";
        assert_eq!(
            parse_strategy_toml(no_rules),
            Err(StrategyParseError::NoRules)
        );
        // a lookback over the cap ⇒ LookbackTooLarge.
        let big_lb = format!(
            "name = \"x\"\narchetype = \"hft\"\n[[rules]]\nname = \"r\"\nsignal = {{ feature = \"sma\", series = \"price\", lookback = {} }}\ncondition = {{ op = \"greater_than\", threshold = 1 }}\ntrade = {{ fixed_lock = {{ locked_amount = 1 }} }}\n",
            MAX_LOOKBACK + 1
        );
        assert_eq!(
            parse_strategy_toml(&big_lb),
            Err(StrategyParseError::LookbackTooLarge(MAX_LOOKBACK + 1))
        );
        // a name over the cap ⇒ a serde custom error (NameStr fail-closes).
        let long_name = format!(
            "name = \"{}\"\narchetype = \"custom\"\n[[rules]]\nname = \"r\"\nsignal = {{ feature = \"last_close\", series = \"price\", lookback = 1 }}\ncondition = {{ op = \"greater_than\", threshold = 1 }}\ntrade = {{ fixed_lock = {{ locked_amount = 1 }} }}\n",
            "z".repeat(MAX_NAME_LEN + 1)
        );
        assert!(matches!(
            parse_strategy_toml(&long_name),
            Err(StrategyParseError::Toml(_))
        ));
    }

    #[test]
    fn too_many_rules_is_rejected() {
        let mut s = String::from("name = \"x\"\narchetype = \"custom\"\n");
        for i in 0..(MAX_RULES + 1) {
            s.push_str(&format!(
                "[[rules]]\nname = \"r{i}\"\nsignal = {{ feature = \"last_close\", series = \"price\", lookback = 1 }}\ncondition = {{ op = \"greater_than\", threshold = 0 }}\ntrade = {{ fixed_lock = {{ locked_amount = 1 }} }}\n"
            ));
        }
        assert_eq!(
            parse_strategy_toml(&s),
            Err(StrategyParseError::TooManyRules(MAX_RULES + 1))
        );
    }

    // ---- IV-K4-2: deterministic signal math ----------------------------------------------------

    #[test]
    fn signals_are_pure_integer_and_history_aware() {
        let prices = [100u128, 110, 90, 130];
        let w = price_window(&prices);
        let s = &w.samples;
        // last_close at each index.
        assert_eq!(compute_signal(SignalFeature::LastClose, s, 1, 0), Some(100));
        assert_eq!(compute_signal(SignalFeature::LastClose, s, 1, 3), Some(130));
        // sma over lookback 2 at i=3: (90+130)/2 = 110.
        assert_eq!(compute_signal(SignalFeature::Sma, s, 2, 3), Some(110));
        // sma needs enough history: i=0, lookback=2 ⇒ None.
        assert_eq!(compute_signal(SignalFeature::Sma, s, 2, 0), None);
        // momentum lookback 2 at i=3: 130 − 110 = 20.
        assert_eq!(compute_signal(SignalFeature::Momentum, s, 2, 3), Some(20));
        // spread over the whole window (lookback 4) at i=3: max130 − min90 = 40.
        assert_eq!(compute_signal(SignalFeature::Spread, s, 4, 3), Some(40));

        let f = funding_window(&[100, 130, 90]);
        let fs = &f.samples;
        // funding_cumulative.
        assert_eq!(
            compute_signal(SignalFeature::FundingCumulative, fs, 1, 1),
            Some(130)
        );
        // funding_step: 130 − 100 = 30; then 90 − 130 = −40 (signed); i=0 ⇒ None.
        assert_eq!(compute_signal(SignalFeature::FundingStep, fs, 1, 0), None);
        assert_eq!(
            compute_signal(SignalFeature::FundingStep, fs, 1, 1),
            Some(30)
        );
        assert_eq!(
            compute_signal(SignalFeature::FundingStep, fs, 1, 2),
            Some(-40)
        );
        // determinism: re-run identical.
        assert_eq!(
            compute_signal(SignalFeature::Momentum, s, 2, 3),
            compute_signal(SignalFeature::Momentum, s, 2, 3)
        );
    }

    #[test]
    fn condition_fires_including_crosses() {
        let gt = Condition {
            op: CompareOp::GreaterThan,
            threshold: 50,
        };
        assert!(condition_fires(&gt, 60, None));
        assert!(!condition_fires(&gt, 50, None));
        // crosses_above needs prev ≤ t < current.
        let xa = Condition {
            op: CompareOp::CrossesAbove,
            threshold: 50,
        };
        assert!(
            condition_fires(&xa, 60, Some(40)),
            "40→60 crosses 50 upward"
        );
        assert!(
            !condition_fires(&xa, 60, Some(55)),
            "already above ⇒ no cross"
        );
        assert!(!condition_fires(&xa, 60, None), "no prev ⇒ no cross");
    }

    // ---- IV-K4-3: every fire is oracle-gated ---------------------------------------------------

    #[test]
    fn shadow_gates_every_fire_with_the_oracle() {
        // a strategy that fires on every funding sample (cumulative ≥ 0) with an AFFORDABLE trade.
        let dsl = StrategyDsl {
            name: NameStr("always-in-bounds".to_string()),
            archetype: StrategyArchetype::Hft,
            rules: vec![StrategyRule {
                name: NameStr("r".to_string()),
                signal: Signal {
                    feature: SignalFeature::FundingCumulative,
                    series: SeriesSel::Funding,
                    lookback: 1,
                },
                condition: Condition {
                    op: CompareOp::GreaterEqual,
                    threshold: 0,
                },
                trade: TradeTemplate::FixedLock {
                    locked_amount: 1_000,
                },
            }],
        };
        let w = funding_window(&[10, 20, 30, 40, 50, 60, 70, 80, 90, 100, 110, 120]);
        // ample bounds ⇒ every fire is in-bounds ⇒ k=0, n=12 ⇒ certified.
        let report = shadow_evaluate(&dsl, std::slice::from_ref(&w), &bounds(10_000, 1_000_000));
        assert_eq!(report.fires, 12);
        assert_eq!(report.in_bounds, 12);
        assert_eq!(report.denied, 0);
        assert!(
            certify_strategy(&report).certified,
            "0/12 in-bounds ⇒ certified"
        );

        // TIGHT bounds (per-tx 500 < escrow 1000) ⇒ EVERY fire is oracle-DENIED ⇒ k=n ⇒ never certified.
        let denied = shadow_evaluate(&dsl, std::slice::from_ref(&w), &bounds(500, 1_000_000));
        assert_eq!(denied.fires, 12);
        assert_eq!(denied.in_bounds, 0);
        assert_eq!(denied.denied, 12);
        assert!(
            !certify_strategy(&denied).certified,
            "every leg oracle-denied ⇒ never certified (the gate is load-bearing)"
        );
    }

    // ---- IV-K4-5 / Q2: the conformal cert is the certify gate -----------------------------------

    #[test]
    fn certification_needs_enough_in_bounds_fires() {
        // a strategy that fires only a FEW times can't certify (n < 10 — the §6.5 boundary).
        let dsl = StrategyDsl {
            name: NameStr("rare".to_string()),
            archetype: StrategyArchetype::Directional,
            rules: vec![StrategyRule {
                name: NameStr("r".to_string()),
                signal: Signal {
                    feature: SignalFeature::FundingCumulative,
                    series: SeriesSel::Funding,
                    lookback: 1,
                },
                condition: Condition {
                    op: CompareOp::GreaterThan,
                    threshold: 1_000,
                },
                trade: TradeTemplate::FixedLock { locked_amount: 1 },
            }],
        };
        // only 3 samples exceed 1000 ⇒ 3 fires ⇒ not certified (need ≥10).
        let w = funding_window(&[0, 0, 0, 2000, 2000, 2000]);
        let report = shadow_evaluate(
            &dsl,
            std::slice::from_ref(&w),
            &bounds(1_000_000, 1_000_000),
        );
        assert_eq!(report.fires, 3);
        assert!(
            !certify_strategy(&report).certified,
            "3 in-bounds fires < 10 ⇒ not certified (the conformal n≥10 boundary)"
        );
        // a strategy that NEVER fires has n=0 ⇒ never certified (no track record).
        let never = funding_window(&[0, 0, 0]);
        let r2 = shadow_evaluate(
            &dsl,
            std::slice::from_ref(&never),
            &bounds(1_000_000, 1_000_000),
        );
        assert_eq!(r2.fires, 0);
        assert!(!certify_strategy(&r2).certified, "n=0 ⇒ never certified");
    }

    #[test]
    fn multi_rule_strategy_aggregates_k_and_n() {
        // rule A (good): fires in-bounds 12×; rule B (bad): fires but oracle-denied 12× ⇒ k=12 n=24.
        let dsl = StrategyDsl {
            name: NameStr("two-leg".to_string()),
            archetype: StrategyArchetype::MarketMaking,
            rules: vec![
                StrategyRule {
                    name: NameStr("good".to_string()),
                    signal: Signal {
                        feature: SignalFeature::FundingCumulative,
                        series: SeriesSel::Funding,
                        lookback: 1,
                    },
                    condition: Condition {
                        op: CompareOp::GreaterEqual,
                        threshold: 0,
                    },
                    trade: TradeTemplate::FixedLock { locked_amount: 100 },
                },
                StrategyRule {
                    name: NameStr("bad".to_string()),
                    signal: Signal {
                        feature: SignalFeature::FundingCumulative,
                        series: SeriesSel::Funding,
                        lookback: 1,
                    },
                    condition: Condition {
                        op: CompareOp::GreaterEqual,
                        threshold: 0,
                    },
                    // escrow 10_000 > per-tx 1_000 ⇒ every fire of this leg is DENIED.
                    trade: TradeTemplate::FixedLock {
                        locked_amount: 10_000,
                    },
                },
            ],
        };
        let w = funding_window(&[1; 12]);
        let report = shadow_evaluate(&dsl, std::slice::from_ref(&w), &bounds(1_000, 1_000_000));
        assert_eq!(report.fires, 24, "12 per leg × 2 legs");
        assert_eq!(report.in_bounds, 12);
        assert_eq!(report.denied, 12);
        assert_eq!(report.per_rule.len(), 2);
        // k=12, n=24 ⇒ a 50% out-of-bounds rate ⇒ NOT certified.
        let cert = certify_strategy(&report);
        assert_eq!(cert.k, 12);
        assert_eq!(cert.n, 24);
        assert!(!cert.certified, "a 50% out-of-bounds rate never certifies");
    }

    #[test]
    fn shadow_fires_are_bounded() {
        // a strategy that would fire on every sample of a huge window is capped at MAX_SHADOW_FIRES.
        let dsl = StrategyDsl {
            name: NameStr("firehose".to_string()),
            archetype: StrategyArchetype::Hft,
            rules: vec![StrategyRule {
                name: NameStr("r".to_string()),
                signal: Signal {
                    feature: SignalFeature::LastClose,
                    series: SeriesSel::Price,
                    lookback: 1,
                },
                condition: Condition {
                    op: CompareOp::GreaterEqual,
                    threshold: 0,
                },
                trade: TradeTemplate::FixedLock { locked_amount: 1 },
            }],
        };
        // 2000 samples, all firing ⇒ capped at MAX_SHADOW_FIRES (1024).
        let prices: Vec<u128> = (0..2000u128).collect();
        let w = price_window(&prices);
        let report = shadow_evaluate(&dsl, std::slice::from_ref(&w), &bounds(10, 10));
        assert_eq!(report.fires, MAX_SHADOW_FIRES, "fires bounded by the cap");
    }

    #[test]
    fn render_is_honest_and_complete() {
        let dsl = parse_strategy_toml(example_strategy_toml()).expect("parses");
        let w = funding_window(&[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
        let report = shadow_evaluate(
            &dsl,
            std::slice::from_ref(&w),
            &bounds(1_000_000, 1_000_000),
        );
        let cert = certify_strategy(&report);
        let r = render_shadow(&report, &cert);
        assert!(r.contains("shadow backtest over REAL K-3 history"));
        assert!(r.contains("no LLM judge"));
        assert!(r.contains("CONFORMAL CERT"));
        assert!(r.contains("NOT profitable"));
        assert!(r.contains("the live sub-budget is the owner-armed K-2 path"));
    }

    #[test]
    fn trade_template_maps_to_every_skew_trade_class() {
        // every payoff class is representable (owner Q1: 전부다) and maps to a SkewTrade.
        let usm = TradeTemplate::UsmVm {
            notional: 100_000_000,
            initial_bps: 80,
        };
        assert_eq!(usm.to_skew_trade().worst_case_escrow(), Some(800_000));
        let fl = TradeTemplate::FixedLock {
            locked_amount: 1_000_000,
        };
        assert_eq!(fl.to_skew_trade().worst_case_escrow(), Some(1_000_000));
        let wcc = TradeTemplate::WccAffine {
            direction: Side::Long,
            quantity: 3,
            contract_size: 7,
            collar_lo: 60,
            collar_hi: 130,
            forward_price: 100,
        };
        assert_eq!(wcc.to_skew_trade().worst_case_escrow(), Some(840));
        let perp = TradeTemplate::Perp {
            signed_qty: 5,
            contract_size: 2,
            entry_price: 100,
            lo_price: 80,
            hi_price: 140,
            funding_cap: 0,
        };
        assert_eq!(perp.to_skew_trade().worst_case_escrow(), Some(200));
        let cb = TradeTemplate::CertifiedBound {
            wcl_bound_per_unit: 1_000,
            quantity: 50,
        };
        assert_eq!(cb.to_skew_trade().worst_case_escrow(), Some(50_000));
    }
}
