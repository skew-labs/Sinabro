//! `m-agent::cache` — provider-cache breakpoint planner.
//!
//! Splits one outgoing LLM request's byte budget into a stable
//! **static prefix** (system prompt + tool defs) and a churning
//! **dynamic suffix** (conversation tail) so the provider's native
//! prompt cache (`L1` / `L2`) can hit on the static
//! prefix across turns without re-uploading the dynamic history.
//!
//! ## Canonical signature
//!
//! ```text
//! pub struct CacheBreakpointPlan {
//!     static_prefix_bytes_u32:  u32,
//!     dynamic_suffix_bytes_u32: u32,
//!     breakpoints_u8:           u8,
//! }
//! pub fn plan_cache_breakpoints(
//!     system_bytes_u32:    u32,
//!     tools_bytes_u32:     u32,
//!     history_bytes_u32:   u32,
//!     max_breakpoints_u8:  u8,
//! ) -> CacheBreakpointPlan;
//! ```
//!
//! ## Re-export stability
//!
//! [`CacheBreakpointPlan`] lives here; its public re-export path
//! `mnemos_m_agent::CacheBreakpointPlan` (via `lib.rs`) is stable, so
//! downstream consumers (`LlmRequestView::cache_plan`, the size pin
//! `assert_eq!(core::mem::size_of::<CacheBreakpointPlan>(), 12)`, and
//! the provider client) compile against the same
//! `Copy` / `Eq` / `Hash` / `Default` type.
//!
//! ## Design invariants
//!
//! - **Static prefix isolation.** `static_prefix_bytes_u32` is the
//!   saturating sum of `system_bytes_u32 + tools_bytes_u32`. The
//!   conversation tail (`history_bytes_u32`) never leaks into the
//!   static count: a per-user dynamic suffix cannot pollute the
//!   provider's cache key for an operator-stable prefix.
//!
//! - **Bounded breakpoint count.** `breakpoints_u8` is capped by
//!   `max_breakpoints_u8` (the operator-supplied upper bound from
//!   `a-core::config::RuntimeCacheConfig::max_breakpoints_u8`).
//!   The cap is type-level (`u8`), so a runaway
//!   planner cannot push the provider over its per-request
//!   breakpoint cap. `max_breakpoints_u8 == 0` ⇒ zero breakpoints
//!   regardless of prefix size — "cache off" is honoured by the
//!   plan, not by an out-of-band kill switch.
//!
//! - **No plaintext on the API surface.** The planner accepts byte
//!   *counts* (`u32`), not byte slices. The plan therefore cannot
//!   retain a copy of the prefix payload; the hashing / cache-key
//!   surface stays with the provider client. Two prefixes that
//!   differ in content but agree in byte length produce identical
//!   plans (cross-user leak prevention). The carrier itself
//!   is exactly 12 bytes — too small to hold a prefix payload by
//!   construction.
//!
//! - **Determinism.** Pure function: identical inputs produce
//!   identical outputs across calls. No clocks, no RNG, no
//!   `'static mut`, no thread-local state. The plan is a function
//!   of its four inputs only.
//!
//! ## Reuse surface
//!
//! - `a-core::config::RuntimeCacheConfig::max_breakpoints_u8`
//!   — the operator-configured upper bound that the supervisor
//!   threads into [`plan_cache_breakpoints`] at request time. This
//!   module does not re-validate the runtime config (single source
//!   of truth in `a-core`); it only enforces the breakpoint cap
//!   that the config carries.
//! - `m-agent::tool_schema::serialized_tool_bytes` — supplies
//!   `tools_bytes_u32`. Disabled tools contribute 0 bytes by
//!   construction, so the static prefix size shrinks automatically
//!   when tools turn off.
//! - `m-agent::llm::LlmRequestView::cache_plan` — primary consumer;
//!   binds the plan into the borrowed request bundle.
//!
//! ## Design notes
//!
//! 1. **No SHA-256 / BLAKE3 helper.** The canonical surface pins the
//!    3-field plan struct and the planner free function — no
//!    hashing API. The "prefix only hashed" invariant is enforced
//!    *structurally*: the planner accepts byte counts only, and the
//!    plan carrier cannot store a payload. Adding a hash helper
//!    would expand the surface; it is deferred until runtime hashing
//!    is required on the m-agent side.
//!
//! 2. **No measurement of cache-hit rate.** The `L1` 95% / `L2` 90%
//!    hit-rate targets are separate measurement axes. This module
//!    ships the *plan surface* that makes those hits possible; the
//!    benchmark suite lives elsewhere.
//!
//! 3. **`max_breakpoints_u8` is a cap, not a target.** The current
//!    plan resolves to `0` or `1` breakpoint(s): one anchor at the
//!    prefix / suffix boundary. A future multi-tier plan (e.g.
//!    Anthropic's 4-cache-control protocol) may resolve to a
//!    larger count, still bounded by `max_breakpoints_u8`. Tests
//!    pin the **upper bound** behaviour rather than the exact
//!    count so a future expansion does not break the bounds
//!    invariant.

// ===========================================================================
// 1. CacheBreakpointPlan
// ===========================================================================

/// Provider-cache breakpoint plan for one outgoing request.
///
/// 3-field shape (`static_prefix_bytes_u32` /
/// `dynamic_suffix_bytes_u32` / `breakpoints_u8`). The public
/// re-export path (`mnemos_m_agent::CacheBreakpointPlan` via
/// `lib.rs`) is stable.
///
/// `breakpoints_u8` is a bounded count (max `u8::MAX = 255`)
/// so a runaway planner cannot push the provider over its
/// per-request breakpoint cap — the type itself enforces the
/// upper bound, and [`plan_cache_breakpoints`] further caps
/// the count by the operator-supplied `max_breakpoints_u8`.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash, Default)]
pub struct CacheBreakpointPlan {
    /// Static-prefix byte count
    /// (`system_bytes_u32` + `tools_bytes_u32`, saturating sum).
    pub static_prefix_bytes_u32: u32,
    /// Dynamic-suffix byte count (conversation tail).
    pub dynamic_suffix_bytes_u32: u32,
    /// Number of cache breakpoints requested (bounded by
    /// `max_breakpoints_u8` and by the type ceiling
    /// `u8::MAX = 255`).
    pub breakpoints_u8: u8,
}

// ===========================================================================
// 2. plan_cache_breakpoints — pure planner
// ===========================================================================

/// Plans provider-cache breakpoints for one outgoing request.
///
/// `system_bytes_u32` and `tools_bytes_u32` are summed
/// (saturating) into the static prefix; `history_bytes_u32`
/// becomes the dynamic suffix verbatim. `max_breakpoints_u8`
/// caps the breakpoint count.
///
/// Returns a [`CacheBreakpointPlan`] whose:
///
/// - `static_prefix_bytes_u32` =
///   `system_bytes_u32.saturating_add(tools_bytes_u32)`.
/// - `dynamic_suffix_bytes_u32` = `history_bytes_u32`.
/// - `breakpoints_u8` = `0` when `static_prefix_bytes_u32 == 0`
///   or when `max_breakpoints_u8 == 0`; otherwise `1` (a single
///   anchor at the prefix / suffix boundary), already within
///   `max_breakpoints_u8` since `1 ≤ u8::MAX`.
///
/// The function is `const`, pure, total, and does not allocate.
/// No plaintext flows through the planner — only byte counts.
#[must_use]
pub const fn plan_cache_breakpoints(
    system_bytes_u32: u32,
    tools_bytes_u32: u32,
    history_bytes_u32: u32,
    max_breakpoints_u8: u8,
) -> CacheBreakpointPlan {
    let static_prefix_bytes_u32 = system_bytes_u32.saturating_add(tools_bytes_u32);
    let dynamic_suffix_bytes_u32 = history_bytes_u32;
    let breakpoints_u8 = if static_prefix_bytes_u32 == 0 || max_breakpoints_u8 == 0 {
        0
    } else {
        1
    };
    CacheBreakpointPlan {
        static_prefix_bytes_u32,
        dynamic_suffix_bytes_u32,
        breakpoints_u8,
    }
}

// ===========================================================================
// 3. Tests — criterion mirror (4 named tests)
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    // -----------------------------------------------------------------------
    // m0_5_static_prefix_isolated — §V.5 cross-user leak prevention
    // -----------------------------------------------------------------------

    /// Static prefix (system + tools) and dynamic suffix
    /// (history) are summed into separate carrier fields; the
    /// history byte count never enters the static prefix
    /// account. This is the structural §V.5 cross-user leak
    /// barrier: a per-user dynamic tail cannot mutate the
    /// provider cache key derived from the static prefix.
    #[test]
    fn m0_5_static_prefix_isolated() {
        let plan = plan_cache_breakpoints(100, 200, 500, 4);
        assert_eq!(plan.static_prefix_bytes_u32, 300);
        assert_eq!(plan.dynamic_suffix_bytes_u32, 500);

        // Saturating add at the upper boundary: no panic, no wrap.
        let saturated = plan_cache_breakpoints(u32::MAX, 7, 0, 4);
        assert_eq!(saturated.static_prefix_bytes_u32, u32::MAX);
        assert_eq!(saturated.dynamic_suffix_bytes_u32, 0);

        // History is a passthrough — even at u32::MAX it does
        // not bleed into the static prefix.
        let pass = plan_cache_breakpoints(0, 0, u32::MAX, 4);
        assert_eq!(pass.static_prefix_bytes_u32, 0);
        assert_eq!(pass.dynamic_suffix_bytes_u32, u32::MAX);

        // Zero prefix ⇒ zero breakpoints regardless of dynamic
        // size (cannot anchor a cache at an empty prefix).
        assert_eq!(pass.breakpoints_u8, 0);
    }

    // -----------------------------------------------------------------------
    // m0_5_breakpoint_count_bounded — operator cap honoured
    // -----------------------------------------------------------------------

    /// `breakpoints_u8` is bounded by `max_breakpoints_u8`. The
    /// `u8` carrier widens the bound to its type-level ceiling
    /// `u8::MAX = 255`; the operator cap is enforced
    /// independently for `max == 0` (cache disabled) versus
    /// `max ≥ 1` (single anchor at the prefix/suffix boundary).
    #[test]
    fn m0_5_breakpoint_count_bounded() {
        // max_breakpoints_u8 == 0 ⇒ cache disabled — zero
        // breakpoints even when the prefix would otherwise
        // qualify.
        let disabled = plan_cache_breakpoints(500, 500, 100, 0);
        assert_eq!(disabled.breakpoints_u8, 0);

        // max_breakpoints_u8 == 1 ⇒ exactly one breakpoint at
        // the prefix / suffix boundary when the prefix is
        // non-empty.
        let one = plan_cache_breakpoints(500, 500, 100, 1);
        assert_eq!(one.breakpoints_u8, 1);
        assert!(one.breakpoints_u8 <= 1);

        // Higher caps still resolve to a single anchor (current
        // single-tier plan); the cap is the **upper bound**, not
        // the target. A future multi-tier plan can expand within
        // this bound without breaking the test.
        let four = plan_cache_breakpoints(500, 500, 100, 4);
        assert!(four.breakpoints_u8 <= 4);
        assert_eq!(four.breakpoints_u8, 1);

        let max_cap = plan_cache_breakpoints(500, 500, 100, u8::MAX);
        // Single-anchor invariant holds at the type ceiling too;
        // the operator cap is not the target. Direct equality is
        // an exact pin, not a tautology over `u8::MAX`.
        assert_eq!(max_cap.breakpoints_u8, 1);

        // Empty prefix overrides any non-zero cap.
        let no_prefix = plan_cache_breakpoints(0, 0, 999, u8::MAX);
        assert_eq!(no_prefix.breakpoints_u8, 0);
    }

    // -----------------------------------------------------------------------
    // m0_5_prefix_only_hashed — §V.5 structural payload-less invariant
    // -----------------------------------------------------------------------

    /// The planner cannot leak prefix plaintext: it accepts
    /// byte *counts* (`u32`), not byte slices, so no per-user
    /// payload reaches the plan. Two prefixes that differ in
    /// content but agree in byte length produce identical
    /// plans — the cache identity is a function of byte counts
    /// only, which is the "prefix only hashed" §V.5 invariant
    /// expressed at the type level (the actual hashing happens
    /// at the provider client, not here).
    ///
    /// The plan carrier itself is exactly 12 bytes (two `u32`
    /// fields, one `u8` field, three bytes of tail padding) —
    /// too small to hold a raw prefix payload by construction.
    /// This is a structural, not runtime, guarantee.
    #[test]
    fn m0_5_prefix_only_hashed() {
        // Carrier size pin — mirrors the `llm.rs` size-of pin.
        // If a future refactor adds an owned field
        // (Vec / String / [u8;N] for N>=32), the size grows
        // and this assertion catches the regression before any
        // prefix payload could enter the carrier.
        assert_eq!(core::mem::size_of::<CacheBreakpointPlan>(), 12);

        // Two distinct conceptual prefixes whose byte lengths
        // coincide produce identical plans. The planner has no
        // channel through which the underlying bytes could
        // differentiate the two cases.
        let prefix_alpha = plan_cache_breakpoints(123, 456, 789, 4);
        let prefix_beta = plan_cache_breakpoints(123, 456, 789, 4);
        assert_eq!(prefix_alpha, prefix_beta);

        // Even when the system / tools split differs, the
        // static prefix count is the saturating sum and the
        // plan is identical — the planner cannot recover the
        // split, so the split cannot leak through the plan.
        let split_left = plan_cache_breakpoints(100, 500, 200, 4);
        let split_right = plan_cache_breakpoints(300, 300, 200, 4);
        assert_eq!(split_left, split_right);

        // Saturating add at the boundary: two distinct (system,
        // tools) decompositions that both saturate to u32::MAX
        // collapse to the same plan — the carrier exposes the
        // saturated sum only.
        let sat_left = plan_cache_breakpoints(u32::MAX, 0, 0, 4);
        let sat_right = plan_cache_breakpoints(u32::MAX, u32::MAX, 0, 4);
        assert_eq!(sat_left.static_prefix_bytes_u32, u32::MAX);
        assert_eq!(sat_right.static_prefix_bytes_u32, u32::MAX);
        assert_eq!(sat_left, sat_right);
    }

    // -----------------------------------------------------------------------
    // m0_5_plan_is_deterministic — pure function, no hidden state
    // -----------------------------------------------------------------------

    /// `plan_cache_breakpoints` is pure: 16 identical
    /// invocations across five representative input vectors
    /// must produce a single result each. No clocks, no RNG,
    /// no thread-local mutation can be smuggled in.
    #[test]
    fn m0_5_plan_is_deterministic() {
        let inputs: [(u32, u32, u32, u8); 5] = [
            (0, 0, 0, 0),
            (1, 2, 3, 4),
            (100, 200, 300, 1),
            (5_000, 1_000, 10_000, 255),
            (u32::MAX, u32::MAX, u32::MAX, u8::MAX),
        ];
        for (system, tools, history, max) in inputs {
            let first = plan_cache_breakpoints(system, tools, history, max);
            for _ in 0..16 {
                assert_eq!(plan_cache_breakpoints(system, tools, history, max), first,);
            }
        }
    }
}
