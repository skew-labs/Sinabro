//! `mnemos-m-agent::llm` — LLM client trait + message types.
//!
//! Public surface:
//! - [`Role`] (`#[repr(u8)]`) — 4-variant System=1 / User=2 / Assistant=3
//!   / Tool=4 wire-tag enum with const [`Role::tag`] / [`Role::from_tag`]
//!   round-trip.
//! - [`TokenCount`] — `#[repr(transparent)]` newtype over `u32`. Typed
//!   unit; the unit-confusion barrier between "token count" and any
//!   other `u32` width (cache bytes, schema bytes, etc.). Pairs with
//!   `UsdMicros` for cost ledgering.
//! - [`ChatMessage<'a>`] — borrowed 3-field record (role · `&'a str`
//!   content · optional `&'a str` tool_call_id). Zero owned bytes;
//!   the LLM hot path never copies prompt text in this carrier.
//! - [`LlmRequestView<'a>`] — borrowed view bundling the messages
//!   slice plus the tool schema and cache plan. The `tools` /
//!   `cache_plan` fields reference types whose canonical homes are
//!   other modules in the crate (see below).
//! - [`LlmError`] — `#[non_exhaustive]` 5-variant `Copy` failure
//!   channel (`Transport` / `RateLimited` / `BudgetExceeded` /
//!   `Protocol` / `Cancelled`) with namespaced class labels
//!   under the `llm.*` prefix.
//! - [`LlmClient`] — single-method trait. The sole hot-path entry
//!   for an LLM provider; `stream_chat` consumes a borrowed
//!   request view, drives a [`DeltaSink`], and returns a
//!   [`TurnUsage`] tally on completion. OpenAI-compatible by
//!   construction (OpenRouter → DeepSeek default).
//! - [`DeltaSink`] — single-method trait. `on_delta` consumes one
//!   parsed SSE delta and returns `ControlFlow<()>` so the caller
//!   can early-exit the stream without unwinding (`SseDelta` lives
//!   in [`crate::sse`]).
//!
//! ## Type re-exports
//!
//! Several types referenced by this module's request/response
//! surface are defined in sibling modules and re-exported here
//! for API stability:
//!
//! - `SseDelta` — canonical home [`crate::sse`], with the full
//!   delta variant list (`ContentText` / `ToolCallArgs` / `Done`
//!   / `Usage(TurnUsage)`). This module imports the canonical
//!   symbol via `use crate::sse::SseDelta;` so
//!   [`DeltaSink::on_delta`] keeps its typed argument and the
//!   public re-export path (`mnemos_m_agent::SseDelta` via
//!   `lib.rs`) stays stable.
//! - [`TurnUsage`] — canonical home [`crate::turn`], which also
//!   layers `TurnState` / `DeltaAccumulator` on top of the same
//!   carrier. This module imports the canonical symbol via
//!   `use crate::turn::TurnUsage;` so
//!   [`LlmClient::stream_chat`]'s return type and the public
//!   re-export path (`mnemos_m_agent::TurnUsage` via `lib.rs`)
//!   stay stable.
//! - [`LazyToolSchema`] — canonical home [`crate::tool_schema`],
//!   with the canonical 2-field shape (`declared` + `registry`).
//!   This module imports the canonical symbol via
//!   `use crate::tool_schema::LazyToolSchema;` so
//!   [`LlmRequestView::tools`] keeps its typed field and the
//!   public re-export path (`mnemos_m_agent::LazyToolSchema`
//!   via `lib.rs`) stays stable. The `declared` field is
//!   private, with read access through
//!   `LazyToolSchema::declared()` (in-crate test surface
//!   updated; no external consumer).
//! - `ToolId` — canonical home [`crate::tool_schema`], defined
//!   alongside [`LazyToolSchema`]. Public re-export
//!   path (`mnemos_m_agent::ToolId` via `lib.rs`) preserved.
//! - `CacheBreakpointPlan` — canonical home [`crate::cache`],
//!   alongside the canonical free function
//!   [`crate::cache::plan_cache_breakpoints`]. Public
//!   re-export path (`mnemos_m_agent::CacheBreakpointPlan` via
//!   `lib.rs`) preserved. This module imports the canonical
//!   symbol via `use crate::cache::CacheBreakpointPlan;` so
//!   [`LlmRequestView::cache_plan`] keeps its typed field
//!   verbatim across the move.
//!
//! ## Carve-outs
//!
//! 1. **No live transport.** This atom defines the trait surface
//!    only. No HTTP client, no SSE byte reader, no OpenRouter
//!    URL constant, no API-key field. Live transport is the
//!    domain of a later atom (post Stage M trait stack lands).
//!    [`LlmError::Transport`] is the carrier; the trait
//!    contract pins it as `Copy` with no owned payload so no
//!    raw response body can leak.
//! 2. **No tokio surface.** `stream_chat` is `&mut self` and
//!    synchronous in the trait signature — the trait contract
//!    permits a blocking adapter (mock / fake) or a
//!    block-on-async impl in a later atom. Pinning `async fn`
//!    in the trait would force an early tokio dep and an
//!    `async-trait` choice; both are deferred.
//! 3. **No `MnemosError` coupling.** [`LlmError`] is its own
//!    `Copy` enum. A later tool-loop integration will introduce
//!    the `From<LlmError> for MnemosError` (or the inverse)
//!    when the budget axis bridges the two. Currently the
//!    m-agent crate has zero workspace deps — Cargo.lock
//!    unchanged.
//! 4. **`ControlFlow<()>` not `ControlFlow<LlmError>`.** This
//!    module uses `ControlFlow<()>` so a sink can request
//!    early-exit without paying the error-channel cost on the
//!    cancellation path. Errors flow through `stream_chat`'s
//!    return, not through the sink. Documented to prevent a
//!    later change from drifting the signature.
//! 5. **Send + Sync NOT required.** The trait does not bound
//!    impls on `Send + Sync` — adding them would constrain a
//!    blocking single-threaded test mock (and the reference
//!    signature is silent on auto-traits). A future change
//!    may add `: Send` on the trait if the runtime wiring
//!    requires it.

#![deny(missing_docs)]

use core::ops::ControlFlow;

use crate::cache::CacheBreakpointPlan;
use crate::sse::SseDelta;
use crate::tool_schema::LazyToolSchema;
use crate::turn::TurnUsage;

// ===========================================================================
// 1. Compile-time width pins
// ===========================================================================

/// `Role` discriminant byte width pin. Mirrors the
/// `MnemosError`/`ErrorCode` family — any future widening to
/// `#[repr(u16)]` would change wire encoding for free-floating
/// streams; the build fails here first.
const _ROLE_REPR_IS_U8: [(); 0 - !(core::mem::size_of::<Role>() == 1) as usize] = [];

/// `LlmError` size pin. Five payload-free `Copy` variants ⇒ size
/// of the niche-optimised tag (`u8`). Any future variant that
/// drags an owned `Vec<u8>` or `String` would widen this and
/// allow raw provider bodies into the error channel — the build
/// fails here first.
const _LLM_ERROR_SIZE_IS_1: [(); 0 - !(core::mem::size_of::<LlmError>() == 1) as usize] = [];

/// `TokenCount` width pin. Newtype is `#[repr(transparent)]`
/// over `u32` ⇒ exactly 4 bytes. Pairing types (`UsdMicros`)
/// follow the same width; any divergence here
/// flags a unit-confusion regression at compile time.
const _TOKEN_COUNT_SIZE_IS_4: [(); 0 - !(core::mem::size_of::<TokenCount>() == 4) as usize] = [];

// ===========================================================================
// 2. Role — chat message wire tag
// ===========================================================================

/// Chat message role. `#[repr(u8)]` so the discriminant is the
/// wire tag — OpenAI-compatible providers use string roles on
/// the wire ("system" / "user" / "assistant" / "tool"); this
/// numeric tag is the in-process projection used by the lazy
/// request serialiser.
///
/// The four variants exhaust the OpenAI-family chat schema as
/// of the provider survey (OpenRouter, DeepSeek,
/// Anthropic chat-compat, OpenAI). Future provider extensions
/// (e.g. `Function`) would land as a new variant with a fresh
/// `#[repr(u8)]` tag; until then [`Role::from_tag`] returns
/// `None` for any non-`{1,2,3,4}` byte, preventing silent
/// drift on a renamed provider role.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
#[repr(u8)]
pub enum Role {
    /// System prompt role.
    System = 1,
    /// End-user message role.
    User = 2,
    /// Assistant (model) message role.
    Assistant = 3,
    /// Tool-result message role (function/tool-call response).
    Tool = 4,
}

impl Role {
    /// Stable wire-tag byte of this role. `const fn` so the tag
    /// can be folded into compile-time constants (the SSE
    /// parser uses it to dispatch frame role tokens).
    #[inline]
    pub const fn tag(self) -> u8 {
        self as u8
    }

    /// Parse a wire-tag byte. Returns `None` for any byte not in
    /// `{1, 2, 3, 4}` — the gate that prevents a silently
    /// renamed provider role from being accepted as a known one.
    #[inline]
    pub const fn from_tag(tag: u8) -> Option<Self> {
        match tag {
            1 => Some(Self::System),
            2 => Some(Self::User),
            3 => Some(Self::Assistant),
            4 => Some(Self::Tool),
            _ => None,
        }
    }
}

// ===========================================================================
// 3. TokenCount — typed unit for prompt/completion token widths
// ===========================================================================

/// LLM token count. `#[repr(transparent)]` newtype over `u32`
/// — the unit-confusion barrier between token widths and any
/// other `u32` byte/length counter that flows through the
/// m-agent crate. Pairs with `UsdMicros` (also a
/// `u32` newtype) so the cost ledger cannot silently swap
/// "tokens" and "USD-millionths" through `From` coercions.
///
/// Saturates at `u32::MAX` ≈ 4.29 × 10⁹ tokens — well above
/// the daily budget cap (5_000 tokens per call) and
/// every reasonable lifetime cap an operator would set.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash, Default)]
#[repr(transparent)]
pub struct TokenCount(u32);

impl TokenCount {
    /// Construct a [`TokenCount`] from a raw `u32`. `const fn`
    /// so token-budget literals can be folded into compile-time
    /// constants (the `DailyTokenBudget` cap default
    /// lives in a const).
    #[inline]
    pub const fn new(n: u32) -> Self {
        Self(n)
    }

    /// The underlying `u32` token count.
    #[inline]
    pub const fn get(self) -> u32 {
        self.0
    }
}

// ===========================================================================
// 4. ChatMessage — borrowed chat record (zero owned bytes)
// ===========================================================================

/// One chat message in a request view. Borrows the `content`
/// and optional `tool_call_id` strings — the m-agent crate
/// never owns prompt text at this carrier, so a 32K-token
/// prompt costs zero heap allocations to thread through the
/// trait surface.
///
/// `tool_call_id` is `Some` only for [`Role::Tool`] messages
/// (OpenAI-family chat protocol); the field is part of the
/// canonical signature so a tool-result roundtrip is
/// expressible without a sibling carrier struct.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub struct ChatMessage<'a> {
    /// Sender role of the message.
    pub role: Role,
    /// Message content as a borrowed UTF-8 slice. No owned bytes.
    pub content: &'a str,
    /// Tool-call id for [`Role::Tool`] result messages; `None`
    /// for system / user / assistant turns.
    pub tool_call_id: Option<&'a str>,
}

// ===========================================================================
// 5. Type re-exports (canonical homes live in sibling modules)
// ===========================================================================

// `SseDelta` canonical home is [`crate::sse`]. This module
// imports the canonical symbol via the top-level
// `use crate::sse::SseDelta;` so `DeltaSink::on_delta`
// keeps its typed argument and the public re-export path
// (`mnemos_m_agent::SseDelta` via `lib.rs`) stays stable. See the
// "Type re-exports" section above for details.

// `TurnUsage` canonical home is [`crate::turn`]. This module
// imports the canonical symbol via the
// top-level `use crate::turn::TurnUsage;` so
// [`LlmClient::stream_chat`]'s return type stays stable and the
// public re-export path (`mnemos_m_agent::TurnUsage` via `lib.rs`)
// is preserved bit-for-bit. See the "Type re-exports"
// section above for details.

// `LazyToolSchema` canonical home is [`crate::tool_schema`].
// This module imports the canonical symbol
// via the top-level `use crate::tool_schema::LazyToolSchema;` so
// [`LlmRequestView::tools`] keeps its typed field and the public
// re-export path (`mnemos_m_agent::LazyToolSchema` via `lib.rs`)
// stays stable. See the "Type re-exports" section above
// for details.
//
// `ToolId` canonical home is [`crate::tool_schema`], defined
// alongside `LazyToolSchema`. Public re-export path
// (`mnemos_m_agent::ToolId` via `lib.rs`) preserved.

// `CacheBreakpointPlan` canonical home is
// [`crate::cache`], alongside
// `plan_cache_breakpoints`. Public re-export path
// (`mnemos_m_agent::CacheBreakpointPlan` via `lib.rs`)
// preserved; this module continues to bind the typed field
// `LlmRequestView::cache_plan: CacheBreakpointPlan` via the
// module-level `use crate::cache::CacheBreakpointPlan;`.

// ===========================================================================
// 6. LlmRequestView — borrowed request bundle
// ===========================================================================

/// Borrowed view of one LLM request. Bundles the message
/// slice, the lazy tool schema, and the cache breakpoint
/// plan into a single trait-method argument without owning
/// any of the underlying bytes.
///
/// Lifetime `'a` is the message buffer borrow (the same
/// lifetime parametrises [`ChatMessage`] and
/// [`LazyToolSchema`]); the cache plan is `Copy` so it has
/// no lifetime of its own.
///
/// The `tools` and
/// `cache_plan` fields reference types defined in sibling
/// modules (`LazyToolSchema` / `CacheBreakpointPlan`) — see the
/// module-level "Type re-exports" section.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub struct LlmRequestView<'a> {
    /// Borrowed slice of chat messages. Zero owned bytes.
    pub messages: &'a [ChatMessage<'a>],
    /// Declared tools — disabled tools never enter the prompt.
    pub tools: LazyToolSchema<'a>,
    /// Provider-cache breakpoint plan.
    pub cache_plan: CacheBreakpointPlan,
}

// ===========================================================================
// 7. LlmError — payload-free failure channel
// ===========================================================================

/// Failure modes for [`LlmClient::stream_chat`]. `Copy`,
/// `#[non_exhaustive]`, no owned bytes — the channel cannot
/// leak a raw provider response body through `Debug`. Class
/// labels namespaced under `llm.*`.
///
/// - `Transport` — network / IO failure before any usable
///   delta arrives. Live transport details (status code,
///   header text) deliberately do not enter this variant; a
///   future atom may layer a richer adapter `Result` outside
///   the trait surface.
/// - `RateLimited` — provider returned a rate-limit signal
///   (429 / equivalent) before the stream produced usable
///   tokens. Distinct from `Transport` so the tool loop
///   can apply a backoff policy without parsing
///   the cause.
/// - `BudgetExceeded` — the local `DailyTokenBudget`
///   refused the charge; the LLM call was
///   aborted before any network egress. Pairs with the
///   `MnemosError::budget_exceeded(BudgetAxis::LlmTokens, …)`
///   bridge a future change adds at the boundary.
/// - `Protocol` — the SSE stream parsed but violated the
///   chat-protocol contract (unexpected role, malformed
///   tool-call schema). The SSE parser surfaces structural
///   parse errors; this variant covers higher-level shape
///   violations.
/// - `Cancelled` — the caller requested cancellation (e.g.
///   via [`DeltaSink::on_delta`] returning `ControlFlow::Break`).
///   Distinct from `Transport` so accounting can treat
///   cancellations as a non-failure for SLA purposes.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
#[non_exhaustive]
pub enum LlmError {
    /// Network / IO failure before any usable delta arrived.
    Transport,
    /// Provider rate-limit signal (429 or equivalent).
    RateLimited,
    /// Local token-budget refusal before any network egress.
    BudgetExceeded,
    /// SSE stream parsed but chat-protocol shape was violated.
    Protocol,
    /// Caller requested cancellation via the delta sink.
    Cancelled,
}

impl LlmError {
    /// Stable class label of this failure mode. Namespaced
    /// under `llm.*` so audit pipelines can fan out on a
    /// single prefix (mirrors `move_bind.*` and
    /// `sui_call_build.*`).
    #[inline]
    pub const fn class_label(&self) -> &'static str {
        match self {
            Self::Transport => "llm.transport",
            Self::RateLimited => "llm.rate_limited",
            Self::BudgetExceeded => "llm.budget_exceeded",
            Self::Protocol => "llm.protocol",
            Self::Cancelled => "llm.cancelled",
        }
    }
}

// ===========================================================================
// 8. Traits — LlmClient + DeltaSink
// ===========================================================================

/// LLM provider contract. One synchronous-looking entry point
/// drives a streaming chat completion against a borrowed
/// request view, hands every parsed delta to a [`DeltaSink`],
/// and returns the per-turn token usage on completion.
///
/// `&mut self` (not `&self`) so a single-connection adapter
/// can mutate its internal cursor / SSE buffer without
/// interior mutability or `Send` constraints. A multi-call
/// concurrent adapter would wrap one `LlmClient` per task.
///
/// The trait is intentionally NOT `async fn` — pinning
/// async on the trait would force an early tokio dep and an
/// `async-trait` choice (both deferred to the atom that wires
/// the live HTTP client). A blocking adapter calling
/// `tokio::runtime::Handle::block_on` is the expected
/// production shape; the test path here is a synchronous
/// mock.
pub trait LlmClient {
    /// Stream a chat completion. Hands every parsed SSE
    /// delta to `sink` in arrival order; returns the final
    /// [`TurnUsage`] on `Done` or an [`LlmError`] on failure
    /// / cancellation.
    fn stream_chat(
        &mut self,
        req: &LlmRequestView<'_>,
        sink: &mut dyn DeltaSink,
    ) -> Result<TurnUsage, LlmError>;
}

/// Streaming delta receiver. The [`LlmClient`] hands every
/// parsed SSE frame to the sink; the sink decides whether to
/// keep streaming (`ControlFlow::Continue(())`) or break
/// early (`ControlFlow::Break(())`). Cancellation flows
/// through this return — errors flow through
/// [`LlmClient::stream_chat`].
///
/// `&mut self` so an accumulator sink (the
/// `DeltaAccumulator`) can update its internal counters
/// without interior mutability.
pub trait DeltaSink {
    /// Receive one parsed delta. Returns
    /// `ControlFlow::Continue(())` to keep streaming or
    /// `ControlFlow::Break(())` to request cancellation
    /// (the [`LlmClient`] then returns
    /// [`LlmError::Cancelled`]).
    fn on_delta(&mut self, delta: SseDelta<'_>) -> ControlFlow<()>;
}

// ===========================================================================
// 9. Inline unit tests
// ===========================================================================

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    // LazyToolSchema fields are private; tests
    // construct via the new() constructor and point at EMPTY_TOOL_REGISTRY
    // for the empty-registry fixture. `ToolId` is
    // only referenced from the test module so it is imported here, not at
    // the file level.
    use crate::tool_schema::{EMPTY_TOOL_REGISTRY, ToolId};

    // ---- Test mocks (trait contract harness) -------------------------------

    /// Test-only mock client. Records `stream_chat` calls and
    /// drives the supplied sink with a fixed delta sequence,
    /// then returns a configured `Result<TurnUsage, LlmError>`.
    struct MockLlmClient {
        deltas_to_emit: Vec<u8>,
        outcome: Result<TurnUsage, LlmError>,
        call_count: u32,
        last_message_count: u32,
        last_breakpoints_u8: u8,
    }

    impl MockLlmClient {
        fn new(deltas_to_emit: Vec<u8>, outcome: Result<TurnUsage, LlmError>) -> Self {
            Self {
                deltas_to_emit,
                outcome,
                call_count: 0,
                last_message_count: 0,
                last_breakpoints_u8: 0,
            }
        }
    }

    impl LlmClient for MockLlmClient {
        fn stream_chat(
            &mut self,
            req: &LlmRequestView<'_>,
            sink: &mut dyn DeltaSink,
        ) -> Result<TurnUsage, LlmError> {
            self.call_count = self.call_count.saturating_add(1);
            self.last_message_count = req.messages.len() as u32;
            self.last_breakpoints_u8 = req.cache_plan.breakpoints_u8;
            // The mock drives the sink with `ContentText`
            // deltas built from the configured byte sequence. Each
            // chunk is interpreted as ASCII text (the bytes used in
            // tests are all `0x..` ASCII printable / non-control).
            for chunk in self.deltas_to_emit.chunks(1) {
                let text = core::str::from_utf8(chunk).unwrap_or("");
                let delta = SseDelta::ContentText(text);
                if let ControlFlow::Break(()) = sink.on_delta(delta) {
                    return Err(LlmError::Cancelled);
                }
            }
            self.outcome
        }
    }

    /// Test-only sink. Records every delta seen and optionally
    /// breaks after `break_after_n` deltas.
    struct MockDeltaSink {
        deltas_seen: u32,
        break_after_n: Option<u32>,
    }

    impl MockDeltaSink {
        fn new() -> Self {
            Self {
                deltas_seen: 0,
                break_after_n: None,
            }
        }

        fn with_break_after(n: u32) -> Self {
            Self {
                deltas_seen: 0,
                break_after_n: Some(n),
            }
        }
    }

    impl DeltaSink for MockDeltaSink {
        fn on_delta(&mut self, _delta: SseDelta<'_>) -> ControlFlow<()> {
            self.deltas_seen = self.deltas_seen.saturating_add(1);
            match self.break_after_n {
                Some(n) if self.deltas_seen >= n => ControlFlow::Break(()),
                _ => ControlFlow::Continue(()),
            }
        }
    }

    // ---- line 1011 verbatim tests --------------------------------

    /// `m0_1_request_view_borrows_messages` — verifies the
    /// request view carries a `&'a [ChatMessage<'a>]` slice
    /// (zero owned bytes) and that the messages remain
    /// reachable for the borrow lifetime.
    #[test]
    fn m0_1_request_view_borrows_messages() {
        let system_text = "you are a careful assistant";
        let user_text = "what is the meaning of life";
        let messages = [
            ChatMessage {
                role: Role::System,
                content: system_text,
                tool_call_id: None,
            },
            ChatMessage {
                role: Role::User,
                content: user_text,
                tool_call_id: None,
            },
        ];
        let tools: [ToolId; 0] = [];
        let req = LlmRequestView {
            messages: &messages,
            tools: LazyToolSchema::new(&tools, &EMPTY_TOOL_REGISTRY),
            cache_plan: CacheBreakpointPlan::default(),
        };
        assert_eq!(req.messages.len(), 2);
        // Pointer identity: the slice on the view points into
        // the local `messages` array — no owned copy.
        assert_eq!(
            req.messages.as_ptr() as usize,
            messages.as_ptr() as usize,
            "request view must borrow the messages slice, not copy it"
        );
        // Content strings are also borrowed: pointer identity
        // proves it.
        assert_eq!(
            req.messages[0].content.as_ptr() as usize,
            system_text.as_ptr() as usize,
            "system content must be borrowed from the local buffer"
        );
        assert_eq!(
            req.messages[1].content.as_ptr() as usize,
            user_text.as_ptr() as usize,
            "user content must be borrowed from the local buffer"
        );
        assert!(req.messages[0].tool_call_id.is_none());
        assert!(req.messages[1].tool_call_id.is_none());
        assert_eq!(req.tools.declared().len(), 0);
        assert_eq!(req.cache_plan.breakpoints_u8, 0);
    }

    /// `m0_1_role_tag_roundtrip` — verifies the
    /// `#[repr(u8)]` Role discriminant is the stable wire tag
    /// and that `Role::tag` / `Role::from_tag` round-trip
    /// across the full enumerated set, rejecting unknown
    /// bytes.
    #[test]
    fn m0_1_role_tag_roundtrip() {
        // Tag values are 1..=4.
        assert_eq!(Role::System.tag(), 1);
        assert_eq!(Role::User.tag(), 2);
        assert_eq!(Role::Assistant.tag(), 3);
        assert_eq!(Role::Tool.tag(), 4);

        // Round-trip on every valid tag.
        for r in [Role::System, Role::User, Role::Assistant, Role::Tool] {
            assert_eq!(Role::from_tag(r.tag()), Some(r));
        }

        // Unknown bytes are rejected — 0 and 5..=255 all None.
        assert_eq!(Role::from_tag(0), None);
        assert_eq!(Role::from_tag(5), None);
        assert_eq!(Role::from_tag(127), None);
        assert_eq!(Role::from_tag(255), None);

        // The discriminant is exactly one byte; transmuted
        // round-trip via `tag()` is sufficient.
        assert_eq!(core::mem::size_of::<Role>(), 1);
    }

    /// `m0_1_mock_client_honors_trait_contract` — a mock-client
    /// trait-contract test. Verifies the [`LlmClient`] + [`DeltaSink`]
    /// trait pair exercises the full happy-path contract: the
    /// client receives a borrowed request view, drives the
    /// sink with every emitted delta, observes the message
    /// count + cache plan, and returns the configured
    /// [`TurnUsage`].
    #[test]
    fn m0_1_mock_client_honors_trait_contract() {
        let messages = [
            ChatMessage {
                role: Role::System,
                content: "system",
                tool_call_id: None,
            },
            ChatMessage {
                role: Role::User,
                content: "hello",
                tool_call_id: None,
            },
            ChatMessage {
                role: Role::Tool,
                content: "{\"result\":42}",
                tool_call_id: Some("call_abc"),
            },
        ];
        let tools = [ToolId(7), ToolId(11)];
        let req = LlmRequestView {
            messages: &messages,
            tools: LazyToolSchema::new(&tools, &EMPTY_TOOL_REGISTRY),
            cache_plan: CacheBreakpointPlan {
                static_prefix_bytes_u32: 512,
                dynamic_suffix_bytes_u32: 128,
                breakpoints_u8: 2,
            },
        };
        let usage = TurnUsage {
            prompt_tokens_u32: 24,
            completion_tokens_u32: 7,
            cached_tokens_u32: 18,
        };
        let mut client = MockLlmClient::new(vec![0x61, 0x62, 0x63], Ok(usage));
        let mut sink = MockDeltaSink::new();

        let result = client.stream_chat(&req, &mut sink);

        assert_eq!(result, Ok(usage));
        assert_eq!(client.call_count, 1);
        assert_eq!(client.last_message_count, 3);
        assert_eq!(client.last_breakpoints_u8, 2);
        // Sink saw every delta the client emitted.
        assert_eq!(sink.deltas_seen, 3);
        // Tool-call id is carried on the tool message.
        assert_eq!(req.messages[2].tool_call_id, Some("call_abc"));
        assert_eq!(req.messages[2].role.tag(), 4);
    }

    // ---- Scaffolding tests --------------------------------------------------

    #[test]
    fn llm_error_class_labels_are_namespaced_and_unique() {
        let labels = [
            (LlmError::Transport, "llm.transport"),
            (LlmError::RateLimited, "llm.rate_limited"),
            (LlmError::BudgetExceeded, "llm.budget_exceeded"),
            (LlmError::Protocol, "llm.protocol"),
            (LlmError::Cancelled, "llm.cancelled"),
        ];
        for (err, expected) in labels.iter() {
            assert!(expected.starts_with("llm."));
            assert_eq!(err.class_label(), *expected);
        }
        // Pairwise distinct.
        for i in 0..labels.len() {
            for j in (i + 1)..labels.len() {
                assert_ne!(labels[i].1, labels[j].1);
            }
        }
    }

    #[test]
    fn token_count_round_trips_through_new_and_get() {
        assert_eq!(TokenCount::new(0).get(), 0);
        assert_eq!(TokenCount::new(5_000).get(), 5_000);
        assert_eq!(TokenCount::new(u32::MAX).get(), u32::MAX);
        assert_eq!(TokenCount::default().get(), 0);
        // Pairwise equality is by inner value.
        assert_eq!(TokenCount::new(42), TokenCount::new(42));
        assert_ne!(TokenCount::new(42), TokenCount::new(43));
    }

    #[test]
    fn public_types_are_copy_and_fixed_width() {
        fn assert_copy<T: Copy>() {}
        assert_copy::<Role>();
        assert_copy::<TokenCount>();
        assert_copy::<ChatMessage<'static>>();
        assert_copy::<LlmRequestView<'static>>();
        assert_copy::<LlmError>();
        assert_copy::<SseDelta<'static>>();
        assert_copy::<TurnUsage>();
        assert_copy::<LazyToolSchema<'static>>();
        assert_copy::<ToolId>();
        assert_copy::<CacheBreakpointPlan>();

        // Width pins (also enforced at compile time by the
        // const _SIZE_IS blocks; tested here so the verifier
        // can spot drift via cargo test output alone).
        assert_eq!(core::mem::size_of::<Role>(), 1);
        assert_eq!(core::mem::size_of::<TokenCount>(), 4);
        assert_eq!(core::mem::size_of::<LlmError>(), 1);
        assert_eq!(core::mem::size_of::<ToolId>(), 2);
        // TurnUsage = 3 × u32 = 12 bytes (no padding on
        // current alignment).
        assert_eq!(core::mem::size_of::<TurnUsage>(), 12);
        // CacheBreakpointPlan = 2 × u32 + 1 × u8 + 3 bytes
        // alignment padding = 12 bytes.
        assert_eq!(core::mem::size_of::<CacheBreakpointPlan>(), 12);
    }

    #[test]
    fn mock_client_returns_cancelled_when_sink_breaks() {
        let messages = [ChatMessage {
            role: Role::User,
            content: "hi",
            tool_call_id: None,
        }];
        let tools: [ToolId; 0] = [];
        let req = LlmRequestView {
            messages: &messages,
            tools: LazyToolSchema::new(&tools, &EMPTY_TOOL_REGISTRY),
            cache_plan: CacheBreakpointPlan::default(),
        };
        let outcome = Ok(TurnUsage::default());
        // Emit 5 deltas but sink breaks after 2.
        let mut client = MockLlmClient::new(vec![0u8; 5], outcome);
        let mut sink = MockDeltaSink::with_break_after(2);
        let result = client.stream_chat(&req, &mut sink);
        assert_eq!(result, Err(LlmError::Cancelled));
        assert_eq!(sink.deltas_seen, 2);
    }

    #[test]
    fn sse_delta_borrowed_text_flows_through_sink() {
        // `SseDelta` canonical home is `crate::sse`.
        // This test pins that the `DeltaSink::on_delta(SseDelta<'_>)`
        // contract still accepts a borrowed `&'a str` into a local
        // buffer (zero owned bytes on the sink boundary).
        let text = String::from("hi");
        let delta = SseDelta::ContentText(&text);
        let mut sink = MockDeltaSink::new();
        let flow = sink.on_delta(delta);
        assert_eq!(flow, ControlFlow::Continue(()));
        match delta {
            SseDelta::ContentText(s) => {
                assert_eq!(s.as_ptr() as usize, text.as_ptr() as usize);
                assert_eq!(s.len(), 2);
            }
            other => panic!("expected ContentText, got {:?}", other),
        }
    }
}
