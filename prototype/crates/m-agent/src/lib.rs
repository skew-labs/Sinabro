//! `mnemos-m-agent` — LLM client, SSE delta parsing, turn loop, token budget and cost ledger.
//!
//! Phase 0 critical-path crate. Modules are filled in incrementally.
//! Canonical signatures are defined per module below. Each
//! finished module keeps `cargo build --workspace` green.
//!
//! Filled so far:
//! - [`llm`][]: `LlmClient` / `DeltaSink` trait pair,
//!   `ChatMessage<'a>` borrowed message record, `Role` `#[repr(u8)]`
//!   wire-tag enum (System=1 / User=2 / Assistant=3 / Tool=4),
//!   `LlmRequestView<'a>` borrowed request bundle, `LlmError`
//!   `#[non_exhaustive]` 5-variant `Copy` failure channel with
//!   `llm.*` class labels, `TokenCount` `#[repr(transparent)]`
//!   newtype over `u32`. The remaining forward-decl placeholder
//!   types (`TurnUsage` / `LazyToolSchema<'a>` / `ToolId` /
//!   `CacheBreakpointPlan`) carry the signature surfaces until
//!   their canonical homes land in later modules.
//!   This module is trait-surface only — no live transport, no tokio
//!   surface, no `MnemosError` coupling.
//! - [`sse`][]: zero-alloc SSE delta parser.
//!   `SseDeltaParser<'a>` (`// AI-HOT`), the canonical home for
//!   `SseDelta<'a>` (moved from `llm.rs` as part of the
//!   forward-declaration carve-out), and `SseParseError`
//!   (`#[non_exhaustive]` 3-variant `Copy` enum with `sse.*` class
//!   labels). Parser is structural-byte-scan over OpenAI-family SSE
//!   frames; every returned string slice borrows into the caller's
//!   input buffer (copy 0). `mnemos-m-agent` adds `proptest` +
//!   `criterion` as dev-deps only; release lib has
//!   zero workspace deps.
//! - [`turn`][]: delta-driven turn state.
//!   `TurnState` (per-turn ledger with one-way `finished` latch and
//!   prompt / completion baseline folded from `Usage` frames),
//!   `DeltaAccumulator` (fixed-width per-delta accumulator with
//!   saturating `content_len_u32` and `tool_calls_u8` counters), and
//!   the canonical home for `TurnUsage` (moved from `llm.rs` as
//!   part of the forward-declaration carve-out, following the
//!   `SseDelta<'a>` MOVE family pattern). State and accumulator
//!   never retain borrowed bytes — memory bound is the size of the
//!   carrier itself, independent of stream length.
//! - [`tool_schema`][]: lazy tool schema +
//!   compact tool registry. Canonical home for `LazyToolSchema<'a>`
//!   and `ToolId` (moved from `llm.rs` per the
//!   forward-decl carve-out; following the `SseDelta<'a>` /
//!   `TurnUsage` MOVE family pattern). Adds
//!   `ToolRegistry` (fixed 16-slot compact map),
//!   `ToolRegistrySlot`, `serialized_tool_bytes`,
//!   `validate_declared`, `ToolRegistryError`, `ToolSchemaError`,
//!   `EMPTY_TOOL_REGISTRY` static, and `TOOL_REGISTRY_CAPACITY`
//!   constant. The invariant — "only declared tools enter the prompt"
//!   — is encoded structurally: tools registered but not declared
//!   contribute 0 bytes.
//! - [`cache`][]: provider-cache breakpoint
//!   planner. Canonical home for `CacheBreakpointPlan` (moved
//!   from `llm.rs` per the forward-decl
//!   carve-out; closes the MOVE family started by the earlier
//!   modules). Adds `plan_cache_breakpoints` — the pure
//!   `const fn` that splits a request budget into a static
//!   prefix (`system_bytes_u32 + tools_bytes_u32`, saturating
//!   sum) and a dynamic suffix (`history_bytes_u32`), bounded
//!   by an operator-supplied `max_breakpoints_u8` cap (sourced
//!   from `a-core::config::RuntimeCacheConfig::max_breakpoints_u8`).
//!   Every forward-decl
//!   placeholder now has its canonical home.
//! - [`cost`][]: cost telemetry with type-safe USD
//!   micros (`UsdMicros` — `#[repr(transparent)]` newtype over `u32`,
//!   mirror of `TokenCount` shape; size pin 4) +
//!   operator-supplied per-Mtok rate table (`PriceTable` — two public
//!   `u32` rate fields, following the `TurnUsage` rationale; size pin 8) +
//!   saturating monotonic ledger (`CostLedger` — private fields +
//!   `pub const fn` accessors per the `DailyTokenBudget`
//!   precedent; size pin 16). `CostLedger::record(&TurnUsage,
//!   &PriceTable)` is the infallible saturating canonical path;
//!   `CostLedger::try_charge_and_record(&TurnUsage, &PriceTable,
//!   &mut DailyTokenBudget)` is the sibling that gates
//!   the record on the prepaid daily token cap via
//!   `DailyTokenBudget::try_charge` — refusal returns
//!   `MnemosError::budget_exceeded(BudgetAxis::LlmTokens, ...)`
//!   from a-core verbatim and leaves both the budget
//!   and the ledger byte-identical. Cached tokens are charged at
//!   zero (savings are made visible) so a turn with cache hit
//!   strictly projects a lower `UsdMicros` delta than the same
//!   prompt count without cache. This module reuses the
//!   `mnemos-a-core` path-dep edge for `MnemosError` /
//!   `BudgetAxis::LlmTokens`; zero new workspace deps.
//! - [`token_bench`][]: per-call input-token
//!   envelope fixture + named gate tests
//!   (`m0_8_input_tokens_under_5000`, `m0_8_vs_hermes_baseline_10x`).
//!   Composes the reuse triangle from
//!   [`tool_schema`] (lazy tool schema bytes),
//!   [`cache`] (static prefix / dynamic suffix split), and
//!   [`cost`] (USD-micros projection over the measured envelope)
//!   into a deterministic, offline, allocation-free measurement of
//!   the non-negotiable token envelope (≤ 5,000 input tokens per call;
//!   ≥ 10× reduction vs. the 32,142-token Hermes baseline). The
//!   companion `prototype/crates/m-agent/benches/tokens.rs` criterion
//!   harness reuses this fixture for throughput sweep plus the
//!   `MNEMOS_BENCH_EMIT_BASELINE=1` JSON-commit emitter. This module
//!   adds zero workspace deps; criterion was already wired for
//!   `benches/sse.rs`.
//! - [`loop_budget`][]: tool-loop iteration cap
//!   (`ToolLoop` — `#[repr(C)]` carrier over a single `u8`
//!   `max_iter_u8`, default 5 via [`loop_budget::DEFAULT_MAX_ITER_U8`];
//!   the `u8` width is the type-level upper bound — no
//!   representable `ToolLoop` can express an unbounded loop) +
//!   four-variant terminal signal (`LoopStop` — `#[repr(u8)]`
//!   payload-free enum: `MaxIterReached` / `BudgetExceeded` /
//!   `Completed` / `ToolDenied` with `loop.*` class labels) +
//!   daily token budget (`DailyTokenBudget` — private-field
//!   carrier holding the invariant `spent_u32 <= cap_u32`).
//!   `DailyTokenBudget::try_charge(TokenCount) -> Result<(),
//!   MnemosError>` is the canonical refusal channel: a charge
//!   that would overflow the daily cap returns
//!   `MnemosError::budget_exceeded(BudgetAxis::LlmTokens,
//!   observed_u64, limit_u64)` from a-core (reuse spine) and
//!   leaves `spent_u32` unchanged. This module
//!   adds the **first cross-crate dep on the m-agent crate**
//!   (`mnemos-a-core = { path = "../a-core" }`); the earlier
//!   modules kept m-agent at zero workspace deps.
#![deny(missing_docs)]
#![deny(unsafe_code)]

pub mod cache;
pub mod cost;
pub mod fanout;
pub mod llm;
pub mod loop_budget;
pub mod sse;
pub mod token_bench;
pub mod tool_schema;
pub mod turn;

#[doc(no_inline)]
pub use cache::{CacheBreakpointPlan, plan_cache_breakpoints};
#[doc(no_inline)]
pub use cost::{CostLedger, PriceTable, UsdMicros};
#[doc(no_inline)]
pub use fanout::{MAX_SUBAGENT_CHILDREN, SubagentBudgetPlan, SubagentPartitionError};
#[doc(no_inline)]
pub use llm::{ChatMessage, DeltaSink, LlmClient, LlmError, LlmRequestView, Role, TokenCount};
#[doc(no_inline)]
pub use loop_budget::{DEFAULT_MAX_ITER_U8, DailyTokenBudget, LoopStop, ToolLoop};
#[doc(no_inline)]
pub use sse::{SseDelta, SseDeltaParser, SseParseError};
#[doc(no_inline)]
pub use tool_schema::{
    EMPTY_TOOL_REGISTRY, LazyToolSchema, TOOL_REGISTRY_CAPACITY, ToolId, ToolRegistry,
    ToolRegistryError, ToolRegistrySlot, ToolSchemaError, serialized_tool_bytes, validate_declared,
};
#[doc(no_inline)]
pub use turn::{DeltaAccumulator, TurnState, TurnUsage};
