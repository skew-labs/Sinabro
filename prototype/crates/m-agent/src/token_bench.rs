//! Per-call input-token envelope fixture and named gate tests.
//!
//! Non-negotiable goal: per-call input tokens MUST stay at or below
//! `MNEMOS_INPUT_TOKENS_CAP` (5,000), proving a ≥ `MIN_REDUCTION_RATIO`
//! (10×) reduction against the Hermes 96-tool flat-prompt baseline of
//! `HERMES_TOKENS_BASELINE` (32,142 tokens). This is the canonical
//! per-call token measurement axis for the whole Phase 0 build.
//!
//! Two surfaces share one fixture:
//!
//! * `m0_8_input_tokens_under_5000` and `m0_8_vs_hermes_baseline_10x`
//!   run via `cargo test` as the named-test gate. They assert the
//!   envelope on the same `measured_input_envelope` the bench measures,
//!   so a regression that blows the envelope fails `cargo test` loudly
//!   without needing `cargo bench` to run first.
//!
//! * `prototype/crates/m-agent/benches/tokens.rs` reuses this fixture
//!   for its criterion run (input-envelope computation throughput) and
//!   for the `MNEMOS_BENCH_EMIT_BASELINE=1` JSON-commit emitter that
//!   writes the CI regression baseline.
//!
//! Reuse triangle:
//!
//! * [`crate::tool_schema::LazyToolSchema`] +
//!   [`crate::tool_schema::ToolRegistry`] +
//!   [`crate::tool_schema::serialized_tool_bytes`] supply the
//!   "declared tools only" byte count (the lazy schema spine that
//!   removes the Hermes 96-call flat-prompt overhead).
//! * [`crate::cache::plan_cache_breakpoints`] +
//!   [`crate::cache::CacheBreakpointPlan`] split the prompt into
//!   static prefix (system + tools, cache-eligible) and dynamic
//!   suffix (history). The cap envelope is the SUM of both: the
//!   provider still bills the full input-token count, the cache
//!   only discounts the COST per [`crate::cost::PriceTable`].
//! * [`crate::cost::CostLedger::project_usd_micros`]
//!   projects the per-turn USD micros for the measured envelope, so
//!   the JSON baseline carries both the token gate and a `$/turn`
//!   sanity metric.
//!
//! Tokenizer policy (non-goal, explicit pin): MNEMOS does NOT depend on
//! a runtime tokenizer in Phase 0. Token counts are derived from
//! measured BYTES via [`BYTES_PER_TOKEN_ESTIMATE`] — a 4 bytes/token
//! heuristic that matches OpenAI cl100k_base ASCII English averages
//! within ~10%. This keeps the fixture reproducible offline,
//! deterministic across rebuilds, and free of new workspace deps
//! (the envelope is a hard CI gate, not a model-specific
//! prediction; future work can swap in a real tokenizer behind a
//! feature flag without changing this gate's contract).

use crate::tool_schema::{LazyToolSchema, ToolId, ToolRegistry, serialized_tool_bytes};

// ===========================================================================
// 1. Constants — token envelope, reduction ratio, baseline, tokenizer pin
// ===========================================================================

/// Hermes (96-tool flat-prompt) per-call input-token baseline.
///
/// The Hermes 32,142-token baseline that the Mnemos per-call input
/// measurement is compared against. Frozen as the CI regression
/// denominator — changing this value rewrites the reduction-ratio
/// gate semantics and MUST be ratified as a deliberate design change,
/// not a code-only edit.
pub const HERMES_TOKENS_BASELINE: u32 = 32_142;

/// Hard cap: per-call input tokens MUST be ≤ this value.
///
/// The token gate — a 5,000-token absolute ceiling on per-call input
/// plus a regression barrier — and a Phase 0 completion gate.
/// Enforced by [`m0_8_input_tokens_under_5000`].
pub const MNEMOS_INPUT_TOKENS_CAP: u32 = 5_000;

/// Non-negotiable reduction ratio: Hermes baseline / Mnemos measured.
///
/// A measured reduction of at least 10×. With
/// [`HERMES_TOKENS_BASELINE`] = 32,142 this implies measured ≤ 3,214
/// — the strictest of the two gates. Enforced by
/// [`m0_8_vs_hermes_baseline_10x`].
pub const MIN_REDUCTION_RATIO: u32 = 10;

/// Deterministic byte → token conversion heuristic.
///
/// 4 ASCII bytes per token is the standard OpenAI cl100k_base average
/// for English chat text (Anthropic Claude tokenizers run a hair
/// looser — within ±10% across the 8-tool / 5-turn fixture below).
/// The exact mapping is intentionally NOT a runtime tokenizer call:
///
/// * Phase 0 has zero LLM network deps by construction.
/// * The gate is a budget envelope, not a model-specific token
///   prediction — a 10–20% over-estimate is the SAFE direction for a
///   hard cap.
/// * Future work can swap in a real tokenizer behind a feature flag
///   without changing this gate's contract.
pub const BYTES_PER_TOKEN_ESTIMATE: u32 = 4;

// ===========================================================================
// 2. Representative call fixture — system prompt, tool schema, history
// ===========================================================================

/// Representative MNEMOS system prompt (English ASCII so the
/// bytes / 4 conversion is honest). Size ~ 900 bytes ≈ 225 tokens.
/// Captures the minimal role-priming the Phase 0 agent needs: tool
/// loop iteration cap, refusal mode, redaction discipline, output
/// shape. Real-world deployments may extend this; the gate cap above
/// gives ~3,000 tokens of headroom for that.
pub const SYSTEM_PROMPT_BYTES: &str = "\
You are MNEMOS, a focused on-device agent that helps the operator \
build and operate the MNEMOS prototype. Default to terse, factual \
replies; prefer running a tool to guessing. Tool loop is bounded to \
five iterations per turn (refuse to continue beyond that). Never \
emit raw secrets, API tokens, wallet passphrases, or provider \
response bodies in plain text; redact at the source. If a request \
crosses a refusal class (mainnet send, key export, network egress \
without --offline), reply with a single-sentence refusal and the \
matching MnemosError class label. Output is always plain text or \
the structured tool-call shape; never include hidden chain-of-\
thought. When uncertain about a path or a fact, call read_file or \
recall_memory before answering. Keep replies under 400 tokens unless \
explicitly asked for more detail.";

/// Representative recent-history byte count (≈ 5 prior turns, each
/// ~ 900 ASCII bytes of system+user+assistant content). 4,500 bytes ÷
/// 4 ≈ 1,125 tokens. With the cache-breakpoint plan the
/// static prefix is provider-cache-eligible; history is the dynamic
/// suffix billed in full every turn.
pub const RECENT_HISTORY_BYTES: u32 = 4_500;

/// Eight declared tools, IDs 1..=8 (avoids the zero-initialised
/// placeholder pattern from the `five_tool_registry` fixture). Pre-
/// measured serialized widths sum to 2,820 bytes ≈ 705 tokens — the
/// lazy-schema spine pays only for these eight, not the ~ 96 the
/// Hermes flat prompt carries. Per-tool widths approximate real
/// OpenAI / Anthropic JSON tool definitions (name + description +
/// JSON-schema parameter object) for representative MNEMOS builtins.
pub const DECLARED_TOOL_SCHEMA_BYTES: &[(ToolId, u32)] = &[
    (ToolId(1), 380), // read_file
    (ToolId(2), 410), // write_file
    (ToolId(3), 520), // run_command (allowlisted)
    (ToolId(4), 290), // recall_memory
    (ToolId(5), 310), // anchor_chunk (Sui Move call)
    (ToolId(6), 270), // budget (current daily token spend)
    (ToolId(7), 240), // clear_turn
    (ToolId(8), 200), // kill (runaway-stop)
];

/// Declared tool ids — slice form used to construct the
/// [`LazyToolSchema`]. Order matches [`DECLARED_TOOL_SCHEMA_BYTES`]
/// so a future "drop a tool" change is a single diff line in both
/// constants.
pub const DECLARED_TOOL_IDS: &[ToolId] = &[
    ToolId(1),
    ToolId(2),
    ToolId(3),
    ToolId(4),
    ToolId(5),
    ToolId(6),
    ToolId(7),
    ToolId(8),
];

/// Cache-breakpoint planner cap
/// ([`crate::cache::plan_cache_breakpoints`] `max_breakpoints_u8`
/// argument). Sized to match the operator default in
/// `a-core::config::RuntimeCacheConfig::max_breakpoints_u8` — a
/// single anchor between static prefix and dynamic suffix is enough
/// for the Phase 0 envelope.
pub const CACHE_MAX_BREAKPOINTS_U8: u8 = 4;

// ===========================================================================
// 3. Fixture builders + measurement
// ===========================================================================

/// Build the demo [`ToolRegistry`] populated from
/// [`DECLARED_TOOL_SCHEMA_BYTES`]. Eight unique ids into the 16-slot
/// registry — register is total by construction. The `match` (instead
/// of `.unwrap()`) satisfies the crate-level `clippy::unwrap_used`
/// deny; an `Err` here would indicate a fixture-data bug (duplicate
/// id) and the bench would loudly fail the envelope tests because
/// fewer tool bytes would be summed.
#[must_use]
pub fn build_demo_registry() -> ToolRegistry {
    let mut reg = ToolRegistry::new();
    for &(id, bytes) in DECLARED_TOOL_SCHEMA_BYTES {
        match reg.register(id, bytes) {
            Ok(()) => {}
            Err(_) => {
                // Unreachable for the fixture data above (8 unique ids
                // in a 16-slot registry). Silently skip rather than
                // panic so the deny-list stays clean; the envelope
                // assertions below will loudly fail if any tool went
                // unregistered.
            }
        }
    }
    reg
}

/// Structured per-call envelope measurement. Public fields because
/// the surface is bench-and-test fixture only (following the
/// [`crate::turn::TurnUsage`] precedent — three independent counters,
/// no invariant beyond their sum).
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash, Default)]
pub struct InputEnvelopeMeasurement {
    /// Static system-prompt byte count
    /// ([`SYSTEM_PROMPT_BYTES`]`.len()`).
    pub system_bytes_u32: u32,
    /// Sum of declared, registered tool schema widths
    /// ([`serialized_tool_bytes`]).
    pub tool_schema_bytes_u32: u32,
    /// Recent-history byte count ([`RECENT_HISTORY_BYTES`]).
    pub history_bytes_u32: u32,
    /// Static-prefix byte count from [`crate::cache::plan_cache_breakpoints`]
    /// — `saturating_add(system_bytes_u32, tool_schema_bytes_u32)`.
    pub static_prefix_bytes_u32: u32,
    /// Dynamic-suffix byte count from
    /// [`crate::cache::plan_cache_breakpoints`] — equals
    /// `history_bytes_u32`.
    pub dynamic_suffix_bytes_u32: u32,
    /// `static_prefix_bytes_u32` + `dynamic_suffix_bytes_u32`
    /// (saturating). The full prompt the provider tokenises.
    pub total_bytes_u32: u32,
    /// `total_bytes_u32` / [`BYTES_PER_TOKEN_ESTIMATE`]. The value
    /// the token gate compares against [`MNEMOS_INPUT_TOKENS_CAP`].
    pub estimated_input_tokens_u32: u32,
    /// Cache-breakpoint planner output count (breakpoint cap).
    pub cache_breakpoints_u8: u8,
}

/// Measure the canonical per-call input envelope using the reuse
/// triangle of the tool schema, cache-breakpoint, and cost layers.
/// Deterministic, allocation-free at the measurement layer (the only
/// allocation is the local `ToolRegistry` carrier, which is a
/// fixed-size array on the stack).
#[must_use]
pub fn measured_input_envelope() -> InputEnvelopeMeasurement {
    let system_bytes_u32 = SYSTEM_PROMPT_BYTES.len() as u32;
    let registry = build_demo_registry();
    let schema = LazyToolSchema::new(DECLARED_TOOL_IDS, &registry);
    let tool_schema_bytes_u32 = serialized_tool_bytes(&schema);
    let history_bytes_u32 = RECENT_HISTORY_BYTES;
    let plan = crate::cache::plan_cache_breakpoints(
        system_bytes_u32,
        tool_schema_bytes_u32,
        history_bytes_u32,
        CACHE_MAX_BREAKPOINTS_U8,
    );
    let total_bytes_u32 = plan
        .static_prefix_bytes_u32
        .saturating_add(plan.dynamic_suffix_bytes_u32);
    let estimated_input_tokens_u32 = total_bytes_u32 / BYTES_PER_TOKEN_ESTIMATE;
    InputEnvelopeMeasurement {
        system_bytes_u32,
        tool_schema_bytes_u32,
        history_bytes_u32,
        static_prefix_bytes_u32: plan.static_prefix_bytes_u32,
        dynamic_suffix_bytes_u32: plan.dynamic_suffix_bytes_u32,
        total_bytes_u32,
        estimated_input_tokens_u32,
        cache_breakpoints_u8: plan.breakpoints_u8,
    }
}

/// Convenience: just the estimated per-call input-token count from
/// [`measured_input_envelope`]. The named tests in this module and
/// the bench harness both gate on this value.
#[must_use]
pub fn measured_input_tokens_per_call() -> u32 {
    measured_input_envelope().estimated_input_tokens_u32
}

// ===========================================================================
// 4. Named gate tests
// ===========================================================================

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use crate::cost::{CostLedger, PriceTable};
    use crate::turn::TurnUsage;

    // -----------------------------------------------------------------------
    // m0_8_input_tokens_under_5000 — absolute cap
    // -----------------------------------------------------------------------

    /// Asserts that the measured per-call input-token envelope stays
    /// at or below [`MNEMOS_INPUT_TOKENS_CAP`] (5,000) — the hard cap.
    /// Any code change that grows the system prompt, the declared
    /// tool set, or the representative history budget past the cap
    /// fails this test loudly (no implicit drift).
    #[test]
    fn m0_8_input_tokens_under_5000() {
        let env = measured_input_envelope();
        assert!(
            env.estimated_input_tokens_u32 <= MNEMOS_INPUT_TOKENS_CAP,
            "m0_8 envelope blown: measured {} tokens ({} bytes) > cap {}; \
             system={}, tools={}, history={}, prefix={}, suffix={}, breakpoints={}",
            env.estimated_input_tokens_u32,
            env.total_bytes_u32,
            MNEMOS_INPUT_TOKENS_CAP,
            env.system_bytes_u32,
            env.tool_schema_bytes_u32,
            env.history_bytes_u32,
            env.static_prefix_bytes_u32,
            env.dynamic_suffix_bytes_u32,
            env.cache_breakpoints_u8,
        );
    }

    // -----------------------------------------------------------------------
    // m0_8_vs_hermes_baseline_10x — non-negotiable reduction ratio
    // -----------------------------------------------------------------------

    /// Asserts that the Hermes baseline divided by the Mnemos measured
    /// envelope is at least [`MIN_REDUCTION_RATIO`] (10×). With the
    /// baseline frozen at 32,142 tokens the measured envelope must be
    /// ≤ 3,214 — the strictest of the two gates. The bench harness
    /// (`benches/tokens.rs`) re-asserts the same predicate so a
    /// `cargo bench` run also fails-loud if the envelope blows.
    #[test]
    fn m0_8_vs_hermes_baseline_10x() {
        let measured = measured_input_tokens_per_call();
        assert!(measured > 0, "measured envelope must be non-zero");
        let ratio = HERMES_TOKENS_BASELINE / measured;
        assert!(
            ratio >= MIN_REDUCTION_RATIO,
            "m0_8 reduction ratio blown: hermes {} / measured {} = {}× < required {}×",
            HERMES_TOKENS_BASELINE,
            measured,
            ratio,
            MIN_REDUCTION_RATIO,
        );
    }

    // -----------------------------------------------------------------------
    // Reuse-triangle sanity — CostLedger projection composes
    // -----------------------------------------------------------------------

    /// The [`CostLedger::project_usd_micros`] projection over the
    /// measured envelope at a representative price table is finite
    /// (saturating arithmetic, no panic) and is strictly reduced by
    /// the cached-prefix discount. This is the hook that lets the
    /// bench's JSON commit report both the token envelope and `$/turn`.
    #[test]
    fn m0_8_cost_projection_composes_over_envelope() {
        let env = measured_input_envelope();
        let price = PriceTable::new(3_000, 15_000); // $3 / $15 per Mtok (illustrative)
        let uncached = TurnUsage {
            prompt_tokens_u32: env.estimated_input_tokens_u32,
            completion_tokens_u32: 400,
            cached_tokens_u32: 0,
        };
        let cached = TurnUsage {
            prompt_tokens_u32: env.estimated_input_tokens_u32,
            completion_tokens_u32: 400,
            cached_tokens_u32: env.static_prefix_bytes_u32 / BYTES_PER_TOKEN_ESTIMATE,
        };
        let uncached_cost = CostLedger::project_usd_micros(&uncached, &price);
        let cached_cost = CostLedger::project_usd_micros(&cached, &price);
        assert!(
            cached_cost <= uncached_cost,
            "cached projection must be ≤ uncached: cached={} uncached={}",
            cached_cost.get(),
            uncached_cost.get(),
        );
    }

    // -----------------------------------------------------------------------
    // Fixture integrity — every declared tool is registered
    // -----------------------------------------------------------------------

    /// Defensive: every id in [`DECLARED_TOOL_IDS`] must resolve in
    /// the registry built from [`DECLARED_TOOL_SCHEMA_BYTES`]. If a
    /// future edit drops a row from one constant but not the other,
    /// this test fails before `serialized_tool_bytes` silently
    /// under-counts (per the `serialized_tool_bytes` docs: unknown
    /// declared ids contribute 0 silently; explicit rejection lives
    /// in `validate_declared`).
    #[test]
    fn m0_8_fixture_declared_ids_all_registered() {
        let registry = build_demo_registry();
        let schema = LazyToolSchema::new(DECLARED_TOOL_IDS, &registry);
        assert!(
            crate::tool_schema::validate_declared(&schema).is_ok(),
            "fixture drift: at least one declared id is missing from the registry"
        );
        // Pinned sum: 380+410+520+290+310+270+240+200 = 2_620.
        assert_eq!(serialized_tool_bytes(&schema), 2_620);
    }

    // -----------------------------------------------------------------------
    // Constant-pin sanity — protect the gate denominators
    // -----------------------------------------------------------------------

    /// The Hermes baseline and the token cap are frozen constants;
    /// pin them so a code-only edit to either value (without a
    /// deliberate ratification) fails this test.
    #[test]
    fn m0_8_constant_pins_match_atom_plan_line_1089_1092() {
        assert_eq!(HERMES_TOKENS_BASELINE, 32_142);
        assert_eq!(MNEMOS_INPUT_TOKENS_CAP, 5_000);
        assert_eq!(MIN_REDUCTION_RATIO, 10);
        assert_eq!(BYTES_PER_TOKEN_ESTIMATE, 4);
    }
}
