//! `m-agent::loop_budget` — tool-loop iteration cap + daily token budget.
//!
//! Stops a tool-using agent turn at one of four terminal signals — the
//! per-turn iteration cap, the daily token budget, a clean completion, or a
//! tool-dispatch denial — without owning any prompt bytes, without retaining
//! any provider body, and without depending on any tokio / HTTP / SSE surface.
//! This module is structural: it ships the iteration-cap carrier ([`ToolLoop`]),
//! the four-variant terminal signal ([`LoopStop`]), the daily token budget
//! ([`DailyTokenBudget`]), and the measured-only [`DailyTokenBudget::try_charge`]
//! function. The live driver wiring maps a-core
//! `MnemosError::tool_denied` payloads + LLM `Done` frames into
//! [`LoopStop::ToolDenied`] / [`LoopStop::Completed`] respectively.
//!
//! ## Canonical signature
//!
//! ```text
//! pub struct DailyTokenBudget { spent_u32: u32, cap_u32: u32 }
//! pub enum   LoopStop { MaxIterReached, BudgetExceeded, Completed, ToolDenied }
//! pub struct ToolLoop { max_iter_u8: u8 }     // default 5; an unbounded loop is unrepresentable
//! impl DailyTokenBudget {
//!     pub fn try_charge(&mut self, n: TokenCount) -> Result<(), MnemosError>;
//! }
//! ```
//!
//! ## Design invariants
//!
//! - **Type-level iteration cap (an unbounded loop is unrepresentable).**
//!   [`ToolLoop::max_iter_u8`] is `u8` — the *type itself* caps the loop at
//!   255 iterations; no representable [`ToolLoop`] value can express an
//!   unbounded loop. The default is 5 (matching the token-saving
//!   spine; the Hermes 96-call flat-prompt baseline is the regression bar).
//!   [`ToolLoop::check_iter_cap`] folds the per-iter check into a `const fn`
//!   so the driver pays one `u8` compare per iteration.
//!
//! - **Budget exceeded → [`a_core::MnemosError::budget_exceeded`] (reuse
//!   spine).** When [`DailyTokenBudget::try_charge`] refuses a charge, the
//!   returned error is the canonical `MnemosError::budget_exceeded(
//!   BudgetAxis::LlmTokens, observed_u64, limit_u64)` projection from a-core.
//!   The driver translates that error into
//!   [`LoopStop::BudgetExceeded`] for the loop's terminal signal. The
//!   Telegram alert wiring consumes the `MnemosError`
//!   `SafeErrorReport` projection at a future stage; this module does not
//!   open the Telegram surface.
//!
//! - **Measured tokens only — no self-report.** [`DailyTokenBudget::try_charge`]
//!   accepts an externally-measured [`TokenCount`] (from `m-agent::llm` /
//!   `m-agent::turn` after the SSE stream reports its `Usage` frame). The
//!   budget never reads a model's "I used N tokens" self-report; the charge
//!   is the bytes-on-the-wire token count. `TurnUsage` is the
//!   production source.
//!
//! - **Saturating + invariant-protected ledger.** `spent_u32` increments
//!   saturating-add only on `Ok(())` outcomes; a refused charge leaves
//!   `spent_u32` unchanged. The invariant `spent_u32 <= cap_u32` is held
//!   for every observable state — proven by the monotonicity test
//!   `m0_6_charge_is_monotone`.
//!
//! ## Reuse surface
//!
//! - `a-core::error::MnemosError::budget_exceeded` + `a-core::error::BudgetAxis::LlmTokens`
//!   — canonical refusal channel.
//! - `m-agent::llm::TokenCount` — typed-unit width pin
//!   (`#[repr(transparent)]` over `u32`); the unit-confusion barrier between
//!   "tokens" and any other `u32`-shaped width on the m-agent crate.
//! - `m-agent::tool_schema::ToolId` — referenced via the
//!   `loop.tool_denied` class label semantics. The driver maps any
//!   a-core `MnemosError::tool_denied(ToolProgram, _, ToolDenyReason, _)`
//!   payload into [`LoopStop::ToolDenied`].
//! - e-skill builtin whitelist — referenced as the dispatch
//!   policy boundary the driver consults; no e-skill type is imported
//!   here (e-skill crate is intentionally not in `m-agent`'s dep tree).
//!
//! ## Design notes
//!
//! 1. **No live driver / dispatch loop.** The canonical surface pins four
//!    types only (one struct, one enum, one struct, one method). This
//!    module does **not** define a `run_tool_loop` driver. A later
//!    binding stage wires the iteration counter +
//!    budget + tool dispatch into a closed `Result<TurnUsage,
//!    LoopStop>` loop. This module supplies the structural primitives
//!    only — same pattern as the LLM trait surface (trait surface, no live
//!    transport) and the provider-cache plan struct (no live request
//!    client).
//!
//! 2. **`DailyTokenBudget` fields are private.** The canonical
//!    signature shows the fields as `spent_u32` / `cap_u32`;
//!    the same MOVE-family precedent promoted
//!    invariant-protected fields to private with `pub const fn`
//!    accessors when an invariant exists between fields. Here the
//!    invariant `spent_u32 <= cap_u32` is enforced by
//!    [`DailyTokenBudget::try_charge`]; private fields, accessors,
//!    and a named constructor remove the only path that could break
//!    it (direct field mutation). The `TurnState` /
//!    `LazyToolSchema` precedent applies.
//!
//! 3. **`ToolLoop` fields are public.** The canonical signature is verbatim;
//!    `max_iter_u8` carries no invariant beyond "fits in `u8`",
//!    which the type itself enforces. The `TurnUsage`
//!    rationale ("no invariant beyond inner value, so public is
//!    correct") applies. A named constructor is supplied for the
//!    default (5); operators with non-default caps use
//!    [`ToolLoop::with_max_iter`].
//!
//! 4. **No `From<LlmError>` bridge yet.** The canonical spec says
//!    "on budget exceeded, `MnemosError::budget_exceeded`(reuse a-core)
//!    → Telegram alert". The Telegram alert is the
//!    `SafeErrorReport`-projection consumer at a later stage.
//!    `LlmError::BudgetExceeded` and
//!    `MnemosError::budget_exceeded` are not bridged here — the
//!    driver routes `try_charge` errors directly into
//!    [`LoopStop::BudgetExceeded`] and the `MnemosError` flows
//!    through `MnemosResult<...>` on the supervisor's outer
//!    return type.
//!
//! 5. **No criterion bench.** Loop control is
//!    a per-iter `u8` compare and a saturating-add — not a token-counting
//!    operation; neither is a
//!    perf hot spot worth a criterion sweep. The token-counting
//!    bench lives in a separate module (G-BENCH, ≤5_000 tokens/call
//!    target).
//!
//! 6. **`LoopStop` class labels.** Following crate-wide
//!    precedent — every closed-set enum on the m-agent crate
//!    exports a `class_label() -> &'static str` for audit
//!    pipelines (`loop.*` namespace). The four labels are
//!    pairwise distinct and `&'static str` so the carrier stays
//!    `Copy` and the channel cannot leak a runtime-formatted
//!    string.

#![deny(missing_docs)]

use mnemos_a_core::error::{BudgetAxis, MnemosError};

use crate::llm::TokenCount;

// ===========================================================================
// 1. Compile-time width pins
// ===========================================================================

/// `LoopStop` size pin. Four payload-free `Copy` variants ⇒ size of the
/// niche-optimised tag (`u8`). Any future variant that drags an owned
/// `Vec<u8>` / `String` would widen this and let a raw provider body into
/// the terminal-signal channel — the build fails here first.
const _LOOP_STOP_SIZE_IS_1: [(); 0 - !(core::mem::size_of::<LoopStop>() == 1) as usize] = [];

/// `ToolLoop` size pin. One `u8` field ⇒ exactly 1 byte (no padding;
/// alignment 1). Any future field addition would widen this and force a
/// signature drift through the canonical struct pin.
const _TOOL_LOOP_SIZE_IS_1: [(); 0 - !(core::mem::size_of::<ToolLoop>() == 1) as usize] = [];

/// `DailyTokenBudget` size pin. Two `u32` fields ⇒ exactly 8 bytes
/// (alignment 4). Pinned so a future field addition (e.g. carry-over to
/// monthly cap) is forced through this constant rather than silently
/// expanding the carrier footprint.
const _DAILY_BUDGET_SIZE_IS_8: [(); 0 - !(core::mem::size_of::<DailyTokenBudget>() == 8) as usize] =
    [];

// ===========================================================================
// 2. Public constants
// ===========================================================================

/// Default per-turn iteration cap. Part of the token-saving spine
/// — five tool-using rounds per turn matches the budget envelope
/// (≤ 5_000 input tokens per call). Operators with stricter envelopes can
/// override via [`ToolLoop::with_max_iter`].
pub const DEFAULT_MAX_ITER_U8: u8 = 5;

// ===========================================================================
// 3. LoopStop — four-variant terminal signal
// ===========================================================================

/// Terminal reason for a tool-using loop. Closed set of four variants;
/// `Copy`, payload-free, `#[repr(u8)]` so the discriminant doubles as a
/// stable wire tag. The driver returns one of these
/// from the per-turn loop:
///
/// - [`LoopStop::MaxIterReached`] — the iteration counter hit
///   [`ToolLoop::max_iter_u8`]. Surfaced by [`ToolLoop::check_iter_cap`].
/// - [`LoopStop::BudgetExceeded`] — [`DailyTokenBudget::try_charge`]
///   refused a charge (the underlying `MnemosError::budget_exceeded`
///   payload travels through the supervisor's `MnemosResult` channel;
///   the loop signal stays payload-free).
/// - [`LoopStop::Completed`] — the LLM stream reported a clean `Done`
///   (`SseDelta::Done`).
/// - [`LoopStop::ToolDenied`] — the dispatch boundary refused a tool
///   call (`MnemosError::tool_denied` from a-core, mapped
///   regardless of the underlying [`a_core::error::ToolDenyReason`]).
///
/// Class labels namespaced under `loop.*` so audit pipelines can fan
/// out on a single prefix (mirrors `llm.*` / `sse.*` / `tool_registry.*`
/// / `tool_schema.*`).
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
#[repr(u8)]
pub enum LoopStop {
    /// Iteration counter reached [`ToolLoop::max_iter_u8`].
    MaxIterReached = 1,
    /// Token budget refused the latest charge.
    BudgetExceeded = 2,
    /// LLM stream reported a clean `Done` frame.
    Completed = 3,
    /// Tool dispatch boundary refused a call.
    ToolDenied = 4,
}

impl LoopStop {
    /// Stable class label of this terminal signal. Namespaced under
    /// `loop.*` so audit pipelines can fan out on a single prefix
    /// (mirrors the crate-wide class-label precedent).
    #[inline]
    pub const fn class_label(&self) -> &'static str {
        match self {
            Self::MaxIterReached => "loop.max_iter_reached",
            Self::BudgetExceeded => "loop.budget_exceeded",
            Self::Completed => "loop.completed",
            Self::ToolDenied => "loop.tool_denied",
        }
    }

    /// Stable wire-tag byte (`#[repr(u8)]` discriminant). `const fn` so
    /// the tag can be folded into compile-time constants.
    #[inline]
    pub const fn tag(self) -> u8 {
        self as u8
    }
}

// ===========================================================================
// 4. ToolLoop — type-level iteration cap
// ===========================================================================

/// Per-turn tool-using iteration cap. One `u8` field — the type itself is
/// the cap (255 absolute maximum; default 5). No
/// representable [`ToolLoop`] value can express an unbounded loop.
///
/// Public field per the `TurnUsage` rationale: the only
/// invariant is "fits in `u8`", which the type enforces; no `try_*`
/// validator is needed. Named constructors are provided for the
/// default and for operator-supplied caps.
///
/// `#[repr(C)]` so the layout is stable
/// across rebuilds; `Default` returns the
/// default ([`DEFAULT_MAX_ITER_U8`]).
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
#[repr(C)]
pub struct ToolLoop {
    /// Per-turn iteration cap. Default 5 ([`DEFAULT_MAX_ITER_U8`]);
    /// the `u8` width is the type-level upper bound.
    pub max_iter_u8: u8,
}

impl Default for ToolLoop {
    /// Default loop carries the default cap ([`DEFAULT_MAX_ITER_U8`]).
    #[inline]
    fn default() -> Self {
        Self::new()
    }
}

impl ToolLoop {
    /// Construct a [`ToolLoop`] with the default iteration cap
    /// ([`DEFAULT_MAX_ITER_U8`] = 5). `const fn` so the default can be
    /// folded into compile-time constants.
    #[inline]
    pub const fn new() -> Self {
        Self {
            max_iter_u8: DEFAULT_MAX_ITER_U8,
        }
    }

    /// Construct a [`ToolLoop`] with an operator-supplied iteration
    /// cap. `const fn` so non-default caps can also be folded at
    /// compile time. The `u8` width pins the upper bound (`max_iter_u8
    /// == 0` ⇒ the very first [`Self::check_iter_cap`] call signals
    /// [`LoopStop::MaxIterReached`] — useful for "disabled" loops).
    #[inline]
    pub const fn with_max_iter(max_iter_u8: u8) -> Self {
        Self { max_iter_u8 }
    }

    /// Check whether `iter_u8` has reached the cap. Returns
    /// `Some(LoopStop::MaxIterReached)` when the driver should stop;
    /// `None` while the loop should continue.
    ///
    /// `// AI-HOT` — one `u8` compare per driver iteration; `const fn`
    /// so the call is folded away on constant `iter_u8` test inputs.
    /// The semantics: the call **after** iteration `n` has run sees
    /// `iter_u8 == n + 1`; reaching `max_iter_u8` is the stop signal.
    #[inline]
    pub const fn check_iter_cap(&self, iter_u8: u8) -> Option<LoopStop> {
        if iter_u8 >= self.max_iter_u8 {
            Some(LoopStop::MaxIterReached)
        } else {
            None
        }
    }
}

// ===========================================================================
// 5. DailyTokenBudget — saturating ledger with invariant `spent <= cap`
// ===========================================================================

/// Daily token budget. Private fields + `pub const fn` accessors +
/// named constructor (following the `LazyToolSchema` precedent;
/// the `TurnState` invariant-protection precedent). The invariant
/// `spent_u32 <= cap_u32` holds for every observable state — proven
/// by [`Self::try_charge`]'s pre-commit check and the
/// `m0_6_charge_is_monotone` test.
///
/// `#[repr(C)]` so the layout is stable
/// across rebuilds; `Default` returns the zero-cap budget (every
/// non-zero charge fails — useful as a default-deny sentinel until
/// the supervisor wires the operator-configured cap).
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash, Default)]
#[repr(C)]
pub struct DailyTokenBudget {
    /// Cumulative tokens charged today. Strictly `<= cap_u32`.
    spent_u32: u32,
    /// Daily cap, in tokens.
    cap_u32: u32,
}

impl DailyTokenBudget {
    /// Construct a fresh budget with an operator-supplied daily cap.
    /// `const fn` so cap literals can be folded at compile time; the
    /// new budget starts at `spent_u32 = 0`.
    #[inline]
    pub const fn new(cap_u32: u32) -> Self {
        Self {
            spent_u32: 0,
            cap_u32,
        }
    }

    /// Cumulative tokens charged today.
    #[inline]
    pub const fn spent_u32(&self) -> u32 {
        self.spent_u32
    }

    /// Daily cap, in tokens.
    #[inline]
    pub const fn cap_u32(&self) -> u32 {
        self.cap_u32
    }

    /// Tokens still chargeable today (`cap_u32 - spent_u32`,
    /// saturating). `const fn` for use in compile-time bound checks.
    #[inline]
    pub const fn remaining_u32(&self) -> u32 {
        self.cap_u32.saturating_sub(self.spent_u32)
    }

    /// `true` when the budget would refuse any non-zero charge
    /// (`spent_u32 == cap_u32`). `const fn`.
    #[inline]
    pub const fn is_exhausted(&self) -> bool {
        self.spent_u32 >= self.cap_u32
    }

    /// Attempt to charge `n` tokens against the daily cap. Returns
    /// `Ok(())` and increments `spent_u32` (saturating-add) when the
    /// post-charge total still fits under `cap_u32`. Returns
    /// `Err(MnemosError::budget_exceeded(BudgetAxis::LlmTokens,
    /// observed_u64, limit_u64))` and leaves `spent_u32` unchanged
    /// otherwise.
    ///
    /// The `observed_u64` field carries the would-be total (current
    /// spent + requested charge, saturating at `u32::MAX` then
    /// widened to `u64`); `limit_u64` carries `cap_u32` widened to
    /// `u64`. The driver maps this `MnemosError` into
    /// [`LoopStop::BudgetExceeded`] for the terminal loop signal.
    ///
    /// `n` is the externally-measured token count (`TurnUsage`
    /// output, post-`Done` frame); the budget never
    /// reads a model self-report.
    pub fn try_charge(&mut self, n: TokenCount) -> Result<(), MnemosError> {
        let requested = n.get();
        let projected = self.spent_u32.saturating_add(requested);
        if projected > self.cap_u32 {
            return Err(MnemosError::budget_exceeded(
                BudgetAxis::LlmTokens,
                projected as u64,
                self.cap_u32 as u64,
            ));
        }
        self.spent_u32 = projected;
        Ok(())
    }
}

// ===========================================================================
// 6. Inline unit tests
// ===========================================================================

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use mnemos_a_core::error::{ToolDenyReason, ToolProgram};

    // ---- Canonical behavior tests -------------------------------

    /// `m0_6_loop_stops_at_max_iter` — verifies the type-level
    /// iteration cap (an unbounded loop is unrepresentable). The default
    /// loop ([`DEFAULT_MAX_ITER_U8`] = 5) returns
    /// `Some(LoopStop::MaxIterReached)` exactly when the iteration
    /// counter reaches 5; the call after iteration `n` ran sees
    /// `iter_u8 == n + 1`.
    #[test]
    fn m0_6_loop_stops_at_max_iter() {
        let lp = ToolLoop::new();
        assert_eq!(lp.max_iter_u8, 5);
        assert_eq!(lp.max_iter_u8, DEFAULT_MAX_ITER_U8);

        // Counter 0..4 (four iterations have NOT yet run before
        // iter_u8==0; then 1, 2, 3, 4 mean 1..4 have run) — still
        // continuing.
        for iter_u8 in 0u8..5u8 {
            assert_eq!(lp.check_iter_cap(iter_u8), None, "iter_u8={iter_u8}");
        }

        // Counter == max ⇒ stop signal.
        assert_eq!(lp.check_iter_cap(5), Some(LoopStop::MaxIterReached));
        // Counter > max ⇒ still the same stop signal (defensive: the
        // driver should not race past the cap, but if it does, we
        // still report a terminal signal rather than panic).
        assert_eq!(lp.check_iter_cap(6), Some(LoopStop::MaxIterReached));
        assert_eq!(lp.check_iter_cap(255), Some(LoopStop::MaxIterReached));

        // with_max_iter(0) ⇒ stop at the very first check.
        let disabled = ToolLoop::with_max_iter(0);
        assert_eq!(disabled.check_iter_cap(0), Some(LoopStop::MaxIterReached));

        // with_max_iter(255) ⇒ the u8 ceiling. Continues at every
        // count < 255; stops at exactly 255.
        let max_u8 = ToolLoop::with_max_iter(u8::MAX);
        assert_eq!(max_u8.check_iter_cap(254), None);
        assert_eq!(max_u8.check_iter_cap(255), Some(LoopStop::MaxIterReached));

        // Type-level invariant: max_iter_u8 is `u8`, so any
        // representable ToolLoop has a finite cap (no infinite loop
        // is expressible). The size pin below makes this measurable.
        assert_eq!(core::mem::size_of::<ToolLoop>(), 1);
    }

    /// `m0_6_budget_exceeded_stops_and_errors` — verifies that
    /// [`DailyTokenBudget::try_charge`] refuses a charge that would
    /// breach `cap_u32`, returns the canonical
    /// `MnemosError::budget_exceeded(BudgetAxis::LlmTokens, ...)`,
    /// and the driver maps it into [`LoopStop::BudgetExceeded`].
    #[test]
    fn m0_6_budget_exceeded_stops_and_errors() {
        // Cap = 5_000 tokens / call.
        let mut budget = DailyTokenBudget::new(5_000);
        assert_eq!(budget.spent_u32(), 0);
        assert_eq!(budget.cap_u32(), 5_000);
        assert_eq!(budget.remaining_u32(), 5_000);
        assert!(!budget.is_exhausted());

        // First charge (3_000) fits.
        assert_eq!(budget.try_charge(TokenCount::new(3_000)), Ok(()));
        assert_eq!(budget.spent_u32(), 3_000);
        assert_eq!(budget.remaining_u32(), 2_000);

        // Second charge (2_001) overflows the cap — refused; spent
        // unchanged.
        let err = budget.try_charge(TokenCount::new(2_001));
        let expected = MnemosError::budget_exceeded(BudgetAxis::LlmTokens, 5_001, 5_000);
        assert_eq!(err, Err(expected));
        assert_eq!(
            budget.spent_u32(),
            3_000,
            "refused charge must NOT mutate spent_u32"
        );
        assert_eq!(budget.remaining_u32(), 2_000);

        // The driver translates that error to LoopStop::BudgetExceeded
        // for the terminal loop signal (the MnemosError continues to
        // travel through the supervisor's MnemosResult channel).
        let stop = match err {
            Err(_) => LoopStop::BudgetExceeded,
            Ok(()) => panic!("expected charge to fail"),
        };
        assert_eq!(stop, LoopStop::BudgetExceeded);
        assert_eq!(stop.class_label(), "loop.budget_exceeded");

        // A subsequent charge that DOES fit (1_500) still succeeds —
        // the budget is not "poisoned" by a refused charge.
        assert_eq!(budget.try_charge(TokenCount::new(1_500)), Ok(()));
        assert_eq!(budget.spent_u32(), 4_500);
        assert_eq!(budget.remaining_u32(), 500);

        // Driving spent_u32 exactly to cap_u32 ⇒ is_exhausted true,
        // remaining_u32 zero.
        assert_eq!(budget.try_charge(TokenCount::new(500)), Ok(()));
        assert_eq!(budget.spent_u32(), 5_000);
        assert_eq!(budget.remaining_u32(), 0);
        assert!(budget.is_exhausted());

        // Charging zero against an exhausted budget still succeeds
        // (cap check is `> cap`, not `>= cap`, when projected ==
        // cap).
        assert_eq!(budget.try_charge(TokenCount::new(0)), Ok(()));
        assert_eq!(budget.spent_u32(), 5_000);

        // Saturating-add behaviour at u32::MAX — a single huge
        // charge against a cap < u32::MAX is refused; spent
        // unchanged.
        let mut big = DailyTokenBudget::new(1_000);
        let huge_err = big.try_charge(TokenCount::new(u32::MAX));
        let huge_expected =
            MnemosError::budget_exceeded(BudgetAxis::LlmTokens, u64::from(u32::MAX), 1_000);
        assert_eq!(huge_err, Err(huge_expected));
        assert_eq!(big.spent_u32(), 0);
    }

    /// `m0_6_tool_denied_stops_loop` — verifies that a tool-dispatch
    /// denial (a-core `MnemosError::tool_denied(...)`)
    /// maps into [`LoopStop::ToolDenied`] regardless of the
    /// underlying [`ToolDenyReason`]. The mapping is the driver's
    /// concern; this module ships the terminal-signal variant + class
    /// label that the driver returns.
    #[test]
    fn m0_6_tool_denied_stops_loop() {
        // The LoopStop variant is distinct, payload-free, and has a
        // stable class label.
        let stop = LoopStop::ToolDenied;
        assert_eq!(stop.class_label(), "loop.tool_denied");
        assert_eq!(stop.tag(), 4);

        // Driver mapping: any ToolDenyReason from a-core flows into
        // a single LoopStop::ToolDenied — the loop stops regardless
        // of which sub-reason fired. This pins the structural
        // invariant: the terminal signal is reason-agnostic so a
        // future ToolDenyReason variant cannot silently bypass the
        // stop signal.
        fn map_deny(_reason: ToolDenyReason) -> LoopStop {
            LoopStop::ToolDenied
        }
        for reason in [
            ToolDenyReason::Program,
            ToolDenyReason::ArgumentShape,
            ToolDenyReason::BannedSurface,
            ToolDenyReason::ApprovalRequired,
        ] {
            assert_eq!(map_deny(reason), LoopStop::ToolDenied);
        }

        // The corresponding MnemosError carrier from a-core: the
        // driver receives this on a refused dispatch and projects
        // it through the supervisor's MnemosResult channel; the
        // LoopStop signal is the payload-free loop-control return.
        let err = MnemosError::tool_denied(
            ToolProgram::Sui,
            0,
            ToolDenyReason::BannedSurface,
            0xDEAD_BEEF_CAFE_BABE,
        );
        // Distinct from the budget-exceeded error path — the loop
        // stops via two different terminal signals.
        let budget_err = MnemosError::budget_exceeded(BudgetAxis::LlmTokens, 6_000, 5_000);
        assert_ne!(err, budget_err);

        // Final structural pin: the LoopStop discriminant set is
        // exactly four variants — adding a fifth without a
        // corresponding driver branch would silently drop a stop
        // signal.
        let variants = [
            LoopStop::MaxIterReached,
            LoopStop::BudgetExceeded,
            LoopStop::Completed,
            LoopStop::ToolDenied,
        ];
        for i in 0..variants.len() {
            for j in (i + 1)..variants.len() {
                assert_ne!(variants[i], variants[j]);
                assert_ne!(variants[i].class_label(), variants[j].class_label());
            }
        }
    }

    /// `m0_6_charge_is_monotone` — verifies that
    /// [`DailyTokenBudget::spent_u32`] is monotone non-decreasing:
    /// every `Ok(())` charge strictly increases (or holds, for a
    /// zero-token charge) spent; every `Err(_)` charge leaves spent
    /// unchanged. The invariant `spent_u32 <= cap_u32` holds for
    /// every observable state.
    #[test]
    fn m0_6_charge_is_monotone() {
        let mut budget = DailyTokenBudget::new(10_000);
        let mut prev_spent = budget.spent_u32();

        // Sequence of charges. Mix of fitting + refused. After each
        // step verify the monotonicity invariant.
        let charges_then_expect_ok = [
            (TokenCount::new(0), true), // zero-token charge ⇒ holds.
            (TokenCount::new(100), true),
            (TokenCount::new(2_000), true),
            (TokenCount::new(7_000), true),
            (TokenCount::new(1_500), false), // 9_100 + 1_500 = 10_600 > 10_000 ⇒ refused.
            (TokenCount::new(500), true),    // 9_100 + 500 = 9_600 ⇒ fits.
            (TokenCount::new(401), false),   // 9_600 + 401 = 10_001 > 10_000 ⇒ refused.
            (TokenCount::new(400), true),    // 9_600 + 400 = 10_000 ⇒ exactly at cap.
            (TokenCount::new(1), false),     // exhausted ⇒ refused.
            (TokenCount::new(0), true),      // zero-charge against exhausted ⇒ Ok, holds.
        ];

        for (n, expect_ok) in charges_then_expect_ok {
            let outcome = budget.try_charge(n);
            let now_spent = budget.spent_u32();

            if expect_ok {
                assert_eq!(
                    outcome,
                    Ok(()),
                    "expected charge {} to succeed; prev_spent={} now_spent={}",
                    n.get(),
                    prev_spent,
                    now_spent
                );
                // Monotone non-decreasing.
                assert!(
                    now_spent >= prev_spent,
                    "Ok charge must not decrease spent; prev={} now={}",
                    prev_spent,
                    now_spent
                );
                // Exact accounting: spent grew by n (no wrap).
                assert_eq!(now_spent, prev_spent.saturating_add(n.get()));
            } else {
                assert!(
                    outcome.is_err(),
                    "expected charge {} to fail; prev_spent={} now_spent={}",
                    n.get(),
                    prev_spent,
                    now_spent
                );
                // Refused charge leaves spent untouched.
                assert_eq!(
                    now_spent, prev_spent,
                    "Err charge must NOT mutate spent; prev={} now={}",
                    prev_spent, now_spent
                );
            }

            // Universal invariant.
            assert!(now_spent <= budget.cap_u32());
            prev_spent = now_spent;
        }

        // Final state: exactly at cap.
        assert_eq!(budget.spent_u32(), budget.cap_u32());
        assert!(budget.is_exhausted());
    }

    // ---- Scaffolding tests ----------------

    #[test]
    fn public_types_are_copy_and_fixed_width() {
        fn assert_copy<T: Copy>() {}
        assert_copy::<LoopStop>();
        assert_copy::<ToolLoop>();
        assert_copy::<DailyTokenBudget>();

        // Width pins (also enforced at compile time by the const
        // _SIZE_IS_… blocks; tested here so the verifier can spot
        // drift via cargo test output alone).
        assert_eq!(core::mem::size_of::<LoopStop>(), 1);
        assert_eq!(core::mem::size_of::<ToolLoop>(), 1);
        assert_eq!(core::mem::size_of::<DailyTokenBudget>(), 8);
    }

    #[test]
    fn loop_stop_class_labels_are_namespaced_and_unique() {
        let labels = [
            (LoopStop::MaxIterReached, "loop.max_iter_reached", 1u8),
            (LoopStop::BudgetExceeded, "loop.budget_exceeded", 2u8),
            (LoopStop::Completed, "loop.completed", 3u8),
            (LoopStop::ToolDenied, "loop.tool_denied", 4u8),
        ];
        for (stop, expected_label, expected_tag) in labels.iter() {
            assert!(expected_label.starts_with("loop."));
            assert_eq!(stop.class_label(), *expected_label);
            assert_eq!(stop.tag(), *expected_tag);
        }
        // Pairwise distinct (labels + tags).
        for i in 0..labels.len() {
            for j in (i + 1)..labels.len() {
                assert_ne!(labels[i].1, labels[j].1);
                assert_ne!(labels[i].2, labels[j].2);
            }
        }
    }

    #[test]
    fn tool_loop_constructors_and_default() {
        assert_eq!(ToolLoop::new().max_iter_u8, 5);
        assert_eq!(ToolLoop::default().max_iter_u8, 5);
        assert_eq!(ToolLoop::with_max_iter(0).max_iter_u8, 0);
        assert_eq!(ToolLoop::with_max_iter(1).max_iter_u8, 1);
        assert_eq!(ToolLoop::with_max_iter(u8::MAX).max_iter_u8, u8::MAX);

        // Equality propagates through the single field.
        assert_eq!(ToolLoop::new(), ToolLoop::with_max_iter(5));
        assert_ne!(ToolLoop::new(), ToolLoop::with_max_iter(6));
    }

    #[test]
    fn daily_token_budget_constructors_and_default() {
        let zero = DailyTokenBudget::default();
        assert_eq!(zero.spent_u32(), 0);
        assert_eq!(zero.cap_u32(), 0);
        assert_eq!(zero.remaining_u32(), 0);
        assert!(zero.is_exhausted());

        let configured = DailyTokenBudget::new(5_000);
        assert_eq!(configured.spent_u32(), 0);
        assert_eq!(configured.cap_u32(), 5_000);
        assert_eq!(configured.remaining_u32(), 5_000);
        assert!(!configured.is_exhausted());

        // A zero-cap budget refuses any non-zero charge.
        let mut zero = DailyTokenBudget::new(0);
        let err = zero.try_charge(TokenCount::new(1));
        let expected = MnemosError::budget_exceeded(BudgetAxis::LlmTokens, 1, 0);
        assert_eq!(err, Err(expected));
        assert_eq!(zero.spent_u32(), 0);
    }
}
