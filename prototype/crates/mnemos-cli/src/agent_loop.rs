//! Agentic memory-retrieval loop driver — step 4 of
//! `ops/evidence/stage_g/agent_loop/MEMORY_INDEX_DESIGN.md` (§6/§8) over the
//! threat model `MEMORY_RETRIEVAL_THREAT_MODEL.md` (IV1-IV6).
//!
//! The loop (design §6): question → LLM turn → the model may reply with a
//! READ-ONLY tool line (`TOOL: memory index` / `TOOL: memory read <id>`) →
//! the executor runs the gated frontier projection → the result is appended
//! to the next turn's user message → … → `ANSWER: <final>`. Read CU is
//! `O(K)` by construction: the model sees the cheap fixed-width catalog and
//! only the K memories it explicitly reads.
//!
//! # Wire-protocol decision (v1, physics-derived)
//!
//! The model speaks a ONE-LINE deterministic tool grammar over the EXISTING
//! single-shot OpenAI-compatible codec (`egress::send_live_text`) instead of
//! the OpenAI `tools` array: zero new egress codec surface (the riskiest
//! layer stays frozen), model-agnostic (works on the deepseek default),
//! trivially deterministic to parse, and every iteration is one bounded
//! consult. The native tool-call codec is a later refinement, not a v1 need.
//!
//! # m-agent reuse (owner brief 2026-06-10)
//!
//! [`ToolLoop`] (u8 iteration cap), [`LoopStop`] (typed stop taxonomy),
//! [`DailyTokenBudget`] + [`TokenCount`] (charge-gated token cap) are the
//! REAL m-agent atoms #25-#27 — not re-mints. The loop cannot run away:
//! every stop class is typed and rendered (kills the runaway-loop class).
//!
//! # Trust tier (the whole game — IV1/IV2)
//!
//! This driver is FRONTIER-BOUND: everything it assembles lands in an
//! external provider's prompt. Therefore the tool executors run the same
//! pure selectors as the local verbs but with `frontier_bound = true`:
//! private records are pre-filtered out of the catalog (IV2), a private
//! read is denied (IV2/D7), every read re-verifies content hash (IV4/D6),
//! and the canonical `redaction::redact` gate runs on every tool result AND
//! on every assembled outbound message (IV1, defense in depth). funds /
//! wallet / chain stay structurally unreachable: the ONLY verbs the model
//! can trigger are the two read-only memory tools — any other proposed tool
//! is denied WITHOUT execution and ends the loop ([`LoopStop::ToolDenied`],
//! IV6).
//!
//! The driver itself is pure (no egress, no cfg): tests drive it with a
//! scripted transport; the live OpenRouter binding lives in `dispatch.rs`
//! behind `provider-egress`.

use crate::commands::authority::ReadCapability;
use crate::commands::model_route::{TrajectoryHealth, TrajectorySignal};
use crate::file_edit::VerifiedFileRead;
use crate::provider::redaction::{RedactionRequest, redact};
use crate::provider::trajectory_health::{GuardAction, recommended_action};
use mnemos_b_memory::{MemoryId, MemoryIndexRecord, TombstonePolicy, catalog_select, read_select};
use mnemos_m_agent::{
    CacheBreakpointPlan, CostLedger, DailyTokenBudget, LoopStop, PriceTable, TokenCount, ToolLoop,
    TurnUsage, plan_cache_breakpoints,
};

// ===========================================================================
// 1. Bounds (IV5/D8 — every dimension capped, documented, testable)
// ===========================================================================

/// Maximum loop iterations (tool turns) under ONE approval ceremony — feeds
/// the m-agent [`ToolLoop`] cap.
pub const AGENT_LOOP_MAX_ITER: u8 = 5;

/// Per-invocation token cap (input + output across all turns) for the BOUNDED
/// AUTONOMOUS loop (the daemon runner) — feeds the m-agent [`DailyTokenBudget`].
/// Exceeding it stops the loop before any further transport call. The INTERACTIVE
/// chat uses [`CHAT_TOKEN_CAP`] instead (P0 #1).
pub const AGENT_LOOP_TOKEN_CAP: u32 = 20_000;

/// INTERACTIVE CHAT token cap (input + output across all turns) — P0 #1, owner
/// 2026-06-30 ("토큰 풀어"). The interactive `provider consult` (desktop / CLI chat)
/// runs with a MUCH larger budget than the bounded autonomous loop so a conversation
/// with long context / pasted material does NOT die at 20k. The AUTONOMOUS daemon loop
/// KEEPS [`AGENT_LOOP_TOKEN_CAP`] (bounded autonomy — unchanged). Still bounded (no
/// runaway): one consult, not a whole session.
pub const CHAT_TOKEN_CAP: u32 = 256_000;

/// INTERACTIVE CHAT iteration cap — a bit more agentic headroom than the autonomous
/// [`AGENT_LOOP_MAX_ITER`] (the READ wall [`AGENT_LOOP_MAX_READS`] is unchanged).
pub const CHAT_MAX_ITER: u8 = 8;

/// IV5's K: at most this many SUCCESSFUL content reads enter the context.
/// Deliberately below [`AGENT_LOOP_MAX_ITER`] so the read wall is reachable
/// and independently tested (defense in depth — the iteration cap alone
/// already bounds the loop).
pub const AGENT_LOOP_MAX_READS: u8 = 3;

/// Per-tool-result byte cap inside the assembled user message (char-safe
/// truncation with an explicit marker).
pub const AGENT_LOOP_TOOL_RESULT_CAP_BYTES: usize = 2_000;

/// Total assembled user-message byte cap per turn (question + tool results).
pub const AGENT_LOOP_USER_MSG_CAP_BYTES: usize = 6_000;

/// Bounded number of catalog records a frontier index result lists.
pub const AGENT_LOOP_INDEX_RENDER_CAP: usize = 32;

/// The tool grammar taught to the model — appended to the sinabro system
/// prompt for loop turns. Deterministic, closed: exactly fifteen read-only
/// tools exist; anything else is denied without execution (IV6).
pub const SINABRO_LOOP_PROTOCOL: &str = "\
TOOL PROTOCOL (bounded, read-only): you may consult the owner's memory \
index, attached local files, named public web pages (fetch a URL or search a \
query), a local source tree \
(audit detect), a project file index (context index), language-server \
diagnostics (lsp diagnostics), read-only tools on a configured local MCP \
server (mcp), the local git repo (git status/diff/log/show/blame), a \
workspace package's tests (test run), a regex search across the workspace \
source (search), a semantic codebase index (codebase), and the Skew capability catalog \
(skew capabilities) before answering. \
Reply with EXACTLY ONE line in one of these forms and nothing else:\n\
TOOL: memory index\n\
TOOL: memory read <id>\n\
TOOL: memory walrus-index\n\
TOOL: memory walrus-fetch <id>\n\
TOOL: file read <path>\n\
TOOL: web fetch <https-url>\n\
TOOL: web search <query>\n\
TOOL: audit detect <path>\n\
TOOL: context index [<path>]\n\
TOOL: lsp diagnostics <path>\n\
TOOL: mcp <server> <tool> [json-args]\n\
TOOL: git <subcommand> [args]\n\
TOOL: test run <pkg>\n\
TOOL: search <regex>\n\
TOOL: codebase <query>\n\
TOOL: skew capabilities\n\
ANSWER: <your final answer>\n\
Rules: each tool result is appended to your next user message; you have at \
most a few turns and a few reads; ONLY the sixteen read-only tools above exist \
— proposing any other tool or side effect (write/exec/delete) is denied and \
ends the loop; when you have enough context, reply with ANSWER. Every turn, \
reply with TOOL: ... or ANSWER: ... only.\n\
SKEW CAPABILITIES lists the full Skew Solana derivatives surface (perp / OTC / \
options / digital / spread / straddle / secondary market / permissionless \
listing / keeper) that Sinabro knows — a pure READ (money 0). Trading any of \
them is a separate owner-armed bounded action, NEVER originated from this loop.\n\
WEB FETCH is a gated public READ: https only (http / an IP address / \
localhost / a chain-RPC host are denied), no login or header is sent, \
redirects are not followed, the page is redacted and quote-limited, and a web \
answer is ADVISORY ONLY (verify it locally before acting) — it is never proof \
of code execution. In a build without web egress it answers \"web transport \
not compiled\". A web fetch counts against your read budget.\n\
WEB SEARCH is a gated public READ that returns a results page (advisory). Do NOT \
give up after one weak or empty search: retry with an ALTERNATE query (translate \
the terms to English, drop or add qualifiers, or add the entity's likely domain \
— e.g. \"<name> crypto\", \"<name> company\", \"<name> fund\"), and OPEN the most \
relevant result link with \"web fetch <url>\" to read the page before you answer. \
Only answer that you could not find something AFTER you have tried alternate \
queries AND fetched the top candidate links and they truly had nothing — all \
within your read budget.\n\
AUDIT DETECT is a gated metadata-only READ: it walks a local source tree and \
reports pattern CANDIDATES (counts + a per-rule histogram + an impact rank) — \
never the raw source, never a confirmed finding. A candidate becomes a finding \
ONLY after a reproduced local repro receipt, which the OWNER runs in a kernel \
sandbox (no network); you can PROPOSE an audit detect but you CANNOT promote a \
candidate or run a repro yourself. An audit detect counts against your read \
budget.\n\
CONTEXT INDEX is a content-free project READ: a bare \"context index\" lists the \
registered project roots, and \"context index <path>\" lists a bounded, \
denylist-pruned file index of that path (names, kinds, sizes only — NEVER file \
CONTENT; symlinks are reported, never followed). To read a file's CONTENT use \
\"file read <path>\". A context index counts against your read budget.\n\
WALRUS MEMORY is your decentralized 2-tier long-term memory: \"memory \
walrus-index\" reads the MAIN INDEX (every memory's id + topic), and \"memory \
walrus-fetch <id>\" enters that memory's SUB-STORE and returns its decrypted \
detail. Everything is AES-encrypted (the key never leaves this machine), so it \
costs no funds and leaks no plaintext. Use the index to find the right memory, \
then fetch its detail and apply it. When the owner has configured a self-host \
Walrus endpoint (mainnet), these AUTO-USE that MAINNET store — your real \
long-term memory then lives on the owner's OWN Walrus; otherwise they use the \
testnet store. (Writing a fresh mainnet backup is an owner-only ceremony; you \
read it freely.) In a build without the Walrus transport these answer \"not \
compiled\". Each counts against your read budget.\n\
LSP DIAGNOSTICS is a gated compiler-truth READ: \"lsp diagnostics <path>\" runs the \
REAL language server (rust-analyzer for .rs, move-analyzer for .move) over the file, \
SANDBOXED (no network, no write), and returns the compiler's OWN diagnostics (errors / \
warnings with line:col) — ground truth, NOT a guess; use it to VERIFY whether code \
actually compiles instead of assuming. If the server is not installed it says so \
honestly (never a fabricated result). An lsp diagnostics counts against your read \
budget.\n\
MCP is a gated tool-ecosystem READ: \"mcp <server> <tool> [json-args]\" calls a \
READ-only tool on a LOCAL MCP server the owner configured, run SANDBOXED (no \
network, no write — the child cannot egress or reach a chain). Only a configured \
server + a tool it advertises in tools/list is allowed (an unknown server or tool \
is denied); the argument AND the result both pass the redaction wall, and the \
result is ADVISORY ONLY (verify it locally — never proof of execution). In a build \
without the MCP client it answers \"not compiled\". An mcp call counts against your \
read budget.\n\
GIT is a gated repo READ: \"git <subcommand> [args]\" runs a READ-only git \
subcommand (status / diff / log / show / blame ONLY) on the local repo, run \
SANDBOXED (no network, no write — a commit / push physically cannot run, and the \
network is kernel-DENIED). Any OTHER subcommand (commit / add / push / branch / \
config …) is DENIED — committing, branching, and pushing are an owner-approved \
action, not a read tool. To commit or branch, PROPOSE-EXEC the git command (e.g. \
COMMAND: git commit -m \"...\") — it runs in a network-DENIED local sandbox AFTER the \
owner approves; a history-rewriting force-push is refused outright. The output is \
redacted; if the directory is not a git repo it says so honestly. A git read counts \
against your read budget.\n\
TEST RUN is a gated oracle READ: \"test run <pkg>\" runs the REAL test runner on a \
workspace package — `sui move test` for a Move.toml package, `cargo test` for a \
Cargo.toml package — SANDBOXED (no network) and returns the PASS/FAIL verdict + the \
failure lines. This is COMPILER/TEST ground truth, not a guess: use it to VERIFY a \
fix actually passes instead of assuming. The package path must be under the \
workspace (no escape); a non-package path or a missing toolchain says so honestly. \
After a FAIL, PROPOSE-EXEC the fix, then re-run to confirm. A test run counts \
against your read budget.\n\
SEARCH is a gated find-in-files READ: \"search <regex>\" runs a regular \
expression over the workspace source (NO subprocess, NO network) and returns \
the matching \"path:line: content\" hits — use it to LOCATE code by pattern \
instead of guessing a file path (then \"file read <path>\" the hit to see more). \
The regex is case-sensitive (use \"(?i)\" for case-insensitive); each file is \
read through the same denylist + size cap + redaction wall as file read, so a \
secret-shaped line is withheld; the walk is bounded (it says so if it caps). A \
search counts against your read budget.\n\
CHANGE PROPOSALS (edits + commands): you cannot directly write, delete, or run \
anything — there is no write/exec tool, and a TOOL: line asking for one is \
denied and ends the loop. Instead you PROPOSE the change in your FINAL ANSWER; \
it stays inert until the OWNER approves it (on their phone, or you proceed \
within an autonomy grant they armed). To propose an edit to a file \
you READ this session, make your final answer EXACTLY:\n\
ANSWER: PROPOSE-EDIT\n\
TARGET: <path exactly as you read it>\n\
CONTENT:\n\
<the complete new file content>\n\
To propose running a command, make your final answer EXACTLY:\n\
ANSWER: PROPOSE-EXEC\n\
COMMAND: <the single command line>\n\
The owner reviews the diff or command and approves it separately; you cannot \
apply or run it yourself. A proposed command runs ONLY in a kernel sandbox (no \
network) after the owner approves. Edit content is written verbatim and \
normalized to end with one newline. You never touch the owner's funds, wallet, \
or any chain write — that is hard-locked.";

// ===========================================================================
// 2. Transport seam + memory state (the two injection points)
// ===========================================================================

/// One LLM turn's deliverable: the raw text plus usage for the budget gate.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AgentTurn {
    /// The model's raw reply text (parsed by the tool grammar).
    pub answer_text: String,
    /// Prompt tokens charged for this turn.
    pub input_tokens_u64: u64,
    /// Completion tokens charged for this turn.
    pub output_tokens_u64: u64,
    /// Provider-reported cached prompt tokens for this turn (a subset of
    /// `input_tokens_u64`; `0` when the provider reports none). Feeds the
    /// loop's [`CostLedger`] cache-savings visibility (P2-1) — never a
    /// charge input.
    pub cached_tokens_u64: u64,
}

/// A typed, secret-zero transport failure: a stable class label only —
/// never a response body, never a key.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AgentTransportError {
    /// Sanitized failure class (e.g. the consult denial taxonomy).
    pub class_label: String,
}

/// The ONE seam between the pure loop driver and a live LLM transport. The
/// production impl wraps the gated OpenRouter codec; tests use a script.
pub trait AgentTransport {
    /// Execute one bounded LLM turn.
    fn turn(&mut self, system: &str, user_message: &str) -> Result<AgentTurn, AgentTransportError>;

    /// Execute one bounded LLM turn, STREAMING the answer as deltas while the model
    /// generates (S-C). Each content delta is handed to `on_delta` AS IT ARRIVES;
    /// `cancel` is checked between deltas (cooperative mid-turn abort). The DEFAULT is
    /// the non-streaming path — run [`turn`](Self::turn), then emit the whole answer
    /// once — so every existing transport (incl. the test transports) keeps working
    /// unchanged; only the live frontier/local transports OVERRIDE this with a real
    /// SSE codec. The CALLER (not the transport) routes each delta through the
    /// redaction wall before it leaves the process (the codec yields RAW deltas).
    fn turn_streaming(
        &mut self,
        system: &str,
        user_message: &str,
        on_delta: &mut dyn FnMut(&str),
        _cancel: &std::sync::atomic::AtomicBool,
    ) -> Result<AgentTurn, AgentTransportError> {
        let turn = self.turn(system, user_message)?;
        on_delta(&turn.answer_text);
        Ok(turn)
    }
}

/// Adapter: any `FnMut(system, user_message) -> Result<AgentTurn, _>` is a
/// transport. Lets the live binding capture its codec + receipt locals in a
/// closure without naming transport generics.
pub struct FnTransport<F>(pub F);

impl<F> AgentTransport for FnTransport<F>
where
    F: FnMut(&str, &str) -> Result<AgentTurn, AgentTransportError>,
{
    fn turn(&mut self, system: &str, user_message: &str) -> Result<AgentTurn, AgentTransportError> {
        (self.0)(system, user_message)
    }
}

/// A cooperative cancel flag shared across threads (S-C true mid-turn cancel): the GUI
/// holds a clone and sets it on Esc; the SSE codec checks it between frames and the
/// agent loop checks it between turns. It NEVER touches funds/wallet/chain — it only
/// stops a read/consult turn early (custody stays locked, PD-6; the loop is read-only).
#[derive(Clone, Debug, Default)]
pub struct CancelToken(std::sync::Arc<std::sync::atomic::AtomicBool>);

impl CancelToken {
    /// A fresh, not-yet-cancelled token.
    #[must_use]
    pub fn new() -> Self {
        Self(std::sync::Arc::new(std::sync::atomic::AtomicBool::new(
            false,
        )))
    }
    /// Request cancellation (idempotent). Any holder of a clone observes it.
    pub fn cancel(&self) {
        self.0.store(true, std::sync::atomic::Ordering::SeqCst);
    }
    /// Whether cancellation has been requested.
    #[must_use]
    pub fn is_cancelled(&self) -> bool {
        self.0.load(std::sync::atomic::Ordering::SeqCst)
    }
    /// The shared flag, to hand to a codec that checks `&AtomicBool` directly
    /// (between SSE frames).
    #[must_use]
    pub fn flag(&self) -> &std::sync::atomic::AtomicBool {
        &self.0
    }
}

/// Adapter: any streaming closure
/// `FnMut(system, user, on_delta, cancel) -> Result<AgentTurn, _>` is a transport that
/// REALLY streams (overrides [`turn_streaming`](AgentTransport::turn_streaming)). Its
/// non-streaming [`turn`](AgentTransport::turn) delegates with a discarding sink + a
/// never-set cancel, so it is a drop-in for the loop's non-streaming entry too. The
/// live frontier/local consult bindings use this in place of [`FnTransport`].
pub struct StreamingFnTransport<F>(pub F);

impl<F> AgentTransport for StreamingFnTransport<F>
where
    F: FnMut(
        &str,
        &str,
        &mut dyn FnMut(&str),
        &std::sync::atomic::AtomicBool,
    ) -> Result<AgentTurn, AgentTransportError>,
{
    fn turn(&mut self, system: &str, user_message: &str) -> Result<AgentTurn, AgentTransportError> {
        let never = std::sync::atomic::AtomicBool::new(false);
        (self.0)(system, user_message, &mut |_| {}, &never)
    }
    fn turn_streaming(
        &mut self,
        system: &str,
        user_message: &str,
        on_delta: &mut dyn FnMut(&str),
        cancel: &std::sync::atomic::AtomicBool,
    ) -> Result<AgentTurn, AgentTransportError> {
        (self.0)(system, user_message, on_delta, cancel)
    }
}

/// The memory surface the tool executors project from — the SAME records /
/// contents / delete-truth shape the local verbs consume (single logic
/// truth; the trust tier is the only difference).
#[derive(Clone, Copy, Debug)]
pub struct MemoryToolState<'a> {
    /// The folded index records (design §3).
    pub records: &'a [MemoryIndexRecord],
    /// Content bytes per memory id (step-3 store wiring; empty in Phase 0).
    pub contents: &'a [(MemoryId, &'a [u8])],
    /// The delete truth (IV3 layer 1).
    pub policy: &'a TombstonePolicy,
}

// ===========================================================================
// 3. Outcome (typed, render-ready, secret-zero)
// ===========================================================================

/// Why the loop ended. Mirrors the m-agent [`LoopStop`] taxonomy plus the
/// transport-failure class (which `LoopStop` — a pure type — cannot carry).
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
#[non_exhaustive]
pub enum AgentLoopStop {
    /// The model produced a final answer.
    Completed,
    /// The m-agent iteration cap fired (bounded loop).
    MaxIterReached,
    /// The m-agent token budget fired (bounded spend).
    BudgetExceeded,
    /// The model proposed a tool outside the closed read-only set — denied
    /// WITHOUT execution (IV6).
    ToolDenied,
    /// The transport failed (denial / HTTP / parse) — label in the trail.
    TransportFailed,
    /// The in-core trajectory guard folded to [`GuardAction::Lockdown`]
    /// (P2-2, AUTO-DRIFT): a security-boundary signal (e.g. the model
    /// steering reads into secret-shaped content) ended the loop BEFORE any
    /// further egress turn. The model cannot disable this (L7 in-core).
    GuardLockdown,
    /// The owner cancelled the turn (S-C true cancel): a cooperative abort checked
    /// between SSE frames (in the streaming codec) + between turns (in the loop).
    /// NOT a failure — an honest owner-initiated stop; nothing further runs.
    Cancelled,
}

impl AgentLoopStop {
    /// Stable class label (m-agent `loop.*` namespace continued).
    #[inline]
    #[must_use]
    pub const fn class_label(self) -> &'static str {
        match self {
            Self::Completed => "loop.completed",
            Self::MaxIterReached => "loop.max_iter_reached",
            Self::BudgetExceeded => "loop.budget_exceeded",
            Self::ToolDenied => "loop.tool_denied",
            Self::TransportFailed => "loop.transport_failed",
            Self::GuardLockdown => "loop.guard_lockdown",
            Self::Cancelled => "loop.cancelled",
        }
    }

    /// Map an m-agent [`LoopStop`] into this taxonomy (1:1 on the shared
    /// variants).
    #[inline]
    #[must_use]
    pub const fn from_loop_stop(stop: LoopStop) -> Self {
        match stop {
            LoopStop::Completed => Self::Completed,
            LoopStop::MaxIterReached => Self::MaxIterReached,
            LoopStop::BudgetExceeded => Self::BudgetExceeded,
            LoopStop::ToolDenied => Self::ToolDenied,
        }
    }
}

/// The loop's full, render-ready receipt: answer (when completed), typed
/// stop, bounded counters and the tool trail (verb + id labels ONLY — never
/// tool-result content, never a key).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AgentLoopOutcome {
    /// The final answer when `stop == Completed`.
    pub answer: Option<String>,
    /// Why the loop ended.
    pub stop: AgentLoopStop,
    /// Tool turns executed (≤ [`AGENT_LOOP_MAX_ITER`]).
    pub iterations_u8: u8,
    /// Successful content reads (≤ [`AGENT_LOOP_MAX_READS`], IV5's K).
    pub reads_u8: u8,
    /// Verb-level trail, e.g. `["index", "read 1", "denied-tool …"]`.
    pub tool_trail: Vec<String>,
    /// Total prompt tokens across turns.
    pub input_tokens_u64: u64,
    /// Total completion tokens across turns.
    pub output_tokens_u64: u64,
    /// The m-agent cost ledger over every turn that crossed the wire (P2-1):
    /// in/out/cached token counters plus the USD projection at the loop's
    /// [`PriceTable`] (the zero-rate sentinel until an operator wires real
    /// rates — counters climb, `usd_micros` stays 0; an honest unconfigured
    /// state, never silent default pricing).
    pub cost: CostLedger,
    /// The cache-breakpoint plan of the LAST turn (P2-1): `static_prefix` =
    /// the byte-stable system prompt, `dynamic_suffix` = the per-turn user
    /// message. Pure byte counts — structure visibility, not a savings claim.
    pub cache_plan: CacheBreakpointPlan,
    /// How many turns (from the 2nd) sent a user message that EXTENDS the
    /// previous turn's as a strict prefix — the property a provider-side
    /// prefix cache keys on. Truncation (the user-message cap sliding the
    /// kept-results window) honestly breaks this count. MEASURED, not
    /// assumed; the provider-reported `cost.cached_tokens_u32()` is the
    /// ground-truth savings metric.
    pub prefix_stable_turns_u8: u8,
    /// The in-core trajectory-health bitset over this run (P2-2,
    /// AUTO-DRIFT): every signal the loop MECHANICALLY observed (repeated
    /// tool call ⇒ `SemanticLoop`; out-of-grammar tool ⇒ `ToolEscalation`;
    /// secret-shaped withhold ⇒ `SecretTouch`; integrity-mismatch denial ⇒
    /// `EvidenceMismatch`). The recommended guard action is RE-DERIVED from
    /// these bits (`recommended_action`) — never stored as a second truth.
    pub health: TrajectoryHealth,
    /// The loop's OWN record of every VERIFIED file read this run (P3-2,
    /// IV-W2): `{path as typed, canonical path, sha256 of the bytes that
    /// entered the prompt}`. The propose path binds a `PROPOSE-EDIT` answer
    /// to exactly these records — never to model-claimed hashes. Denied /
    /// withheld / binary reads are NEVER recorded.
    pub verified_file_reads: Vec<VerifiedFileRead>,
}

/// ENDGAME E1 (audit-soul recall citation): the memory ids RECALLED in a run,
/// derived from its typed tool trail — every VERIFIED `memory read <id>` (trail
/// entry `read <id>`), in order. A denied (`read-denied`), read-capped
/// (`read-cap`), repeated (`repeat read`), or file read is NOT a recall and is
/// excluded. A FREE fn over the trail (not only the [`AgentLoopOutcome`]
/// method) so a render can cite recall from `&outcome.tool_trail` alone — e.g.
/// after `outcome.answer` has been moved out for rendering.
#[must_use]
pub fn recalled_memory_ids_from_trail(tool_trail: &[String]) -> Vec<u64> {
    tool_trail
        .iter()
        .filter_map(|entry| entry.strip_prefix("read ")?.parse::<u64>().ok())
        .collect()
}

impl AgentLoopOutcome {
    /// The memory ids this run RECALLED — see [`recalled_memory_ids_from_trail`].
    /// Lets the answer card show the owner which of their own memories fed the
    /// answer — recall is autonomous (PD-3) but never invisible.
    #[must_use]
    pub fn recalled_memory_ids(&self) -> Vec<u64> {
        recalled_memory_ids_from_trail(&self.tool_trail)
    }
}

// ===========================================================================
// 4. Tool grammar parse (deterministic, closed)
// ===========================================================================

/// The parsed shape of one model reply.
#[derive(Clone, Debug, Eq, PartialEq)]
enum ParsedTurn<'a> {
    /// `TOOL: memory index`
    ToolIndex,
    /// `TOOL: memory read <id>`
    ToolRead(u64),
    /// `TOOL: file read <path>` (lane A; path keeps its original case).
    ToolFileRead(&'a str),
    /// `TOOL: web fetch <https-url>` (E11-1b; url keeps its original case — the
    /// SSRF wall lowercases the host itself).
    ToolWebFetch(&'a str),
    /// `TOOL: web search <query>` (P3b) — search the configured endpoint (env override
    /// or the keyless DuckDuckGo default). Routes to the SAME web-fetch path (build the
    /// search URL → SSRF wall → secret-zero GET → redacted advisory); no new executor.
    ToolWebSearch(&'a str),
    /// `TOOL: audit detect <path>` (E11-2; path keeps its original case). A pure
    /// metadata-only READ over a local source tree — the agent can PROPOSE it but
    /// CANNOT promote a candidate or run a repro (IV-AE6).
    ToolAuditDetect(&'a str),
    /// `TOOL: context index [<path>]` (E11-4-2; path keeps its original case; an
    /// empty path = the registered project roots). A content-free PROJECT
    /// enumeration (rel-paths / kinds / sizes — NEVER file CONTENT), the 6th
    /// typed-READ tool. DISTINCT from the memory `ToolIndex` (shareable records).
    ToolContextIndex(&'a str),
    /// `TOOL: memory walrus-index` (E14-W2) — read the agent's MAIN INDEX from the 2-tier
    /// Walrus memory (id + topic + sub-store ref per memory). A typed READ; the agent
    /// navigates its decentralized long-term memory.
    ToolWalrusIndex,
    /// `TOOL: memory walrus-fetch <id>` (E14-W2) — enter the SUB-STORE for `<id>` and
    /// fetch + decrypt its detail from Walrus. A typed READ.
    ToolWalrusFetch(u64),
    /// `TOOL: lsp diagnostics <path>` (A①, CURSOR PARITY keystone-1; path keeps
    /// its original case). Run the REAL language server (rust-analyzer /
    /// move-analyzer) sandboxed over the file and surface the COMPILER's
    /// diagnostics — ground truth, not a model guess (AXIS-2 / P-HALL). The 9th
    /// typed-READ tool.
    ToolLspDiagnostics(&'a str),
    /// `TOOL: mcp <server> <tool> [json-args]` (B⑫, CURSOR PARITY keystone-3).
    /// Call a READ-class tool on an owner-configured LOCAL stdio MCP server
    /// (network kernel-DENIED); `server` + `tool` are single tokens (case-PRESERVED),
    /// `args` is the optional trailing JSON object (case-PRESERVED). The 11th
    /// typed-READ tool. Fields: `(server, tool, args)`.
    ToolMcp(&'a str, &'a str, &'a str),
    /// `TOOL: git <subcommand> [args]` (A⑤, CURSOR PARITY git-as-capability-type).
    /// Run a READ-only git subcommand (status/diff/log/show/blame) on the local
    /// repo, SANDBOXED (network + write kernel-DENIED); `subcommand` is the first
    /// token (case-PRESERVED), `args` is the remainder (case-PRESERVED). The 12th
    /// typed-READ tool. Fields: `(subcommand, args)`.
    ToolGit(&'a str, &'a str),
    /// `TOOL: test run <pkg>` (A②, CURSOR PARITY oracle test-loop). Run the REAL
    /// test runner (`sui move test` / `cargo test`) on a workspace package
    /// SANDBOXED (network kernel-DENIED) and surface the pass/fail + failure lines —
    /// ground truth, not a guess (AXIS-2 / P-HALL). The 13th typed-READ tool. Field:
    /// the package path (case-PRESERVED, relative to the workspace root).
    ToolTestRun(&'a str),
    /// `TOOL: search <regex>` (A④-rg, CURSOR PARITY find-in-files). Run a
    /// linear-time REGEX over the workspace source (NO subprocess) and surface
    /// `path:line: content` hits — locate code by pattern instead of guessing a
    /// path. The 14th typed-READ tool. Field: the regex (case-PRESERVED — a regex
    /// is case-sensitive; use `(?i)` for case-insensitive).
    ToolSearch(&'a str),
    /// `TOOL: codebase <query>` ([4] B⑨, semantic codebase index). Retrieve the top-K
    /// semantically + lexically relevant chunks from the LOCAL encrypted-at-rest codebase
    /// index (local embeddings — they never leave the box; each chunk redacted). The 15th
    /// typed-READ tool. Field: the natural-language / identifier query.
    ToolCodebase(&'a str),
    /// `TOOL: skew capabilities` (K-0a-3) — read the Skew capability catalog (the
    /// `skew_catalog` single source of truth) mid-reasoning: a PURE static READ (no key,
    /// no network, money 0) so the agent KNOWS the full Skew Solana surface (perp / OTC /
    /// options / secondary market / permissionless listing / keeper). Trading is NOT a loop
    /// tool — it is a separate owner-armed bounded action (K-2). The 16th typed-READ tool.
    ToolSkewCapabilities,
    /// A `TOOL:` line outside the closed set (denied, IV6).
    ToolUnknown(&'a str),
    /// Anything else: the final answer (`ANSWER:` prefix stripped if given).
    Answer(&'a str),
}

/// The closed `file read ` tool prefix (ASCII ⇒ byte-slicing the original is
/// safe at this boundary, which preserves the path's case).
const FILE_READ_PREFIX: &str = "file read ";

/// The closed `web fetch ` tool prefix (E11-1b; ASCII ⇒ byte-slicing the
/// original preserves the URL's case — path/query are case-sensitive).
const WEB_FETCH_PREFIX: &str = "web fetch ";

/// The closed `web search ` tool prefix (P3b; ASCII ⇒ byte-slicing preserves the
/// query's case). Distinct from `web fetch ` — a query, not a URL.
const WEB_SEARCH_PREFIX: &str = "web search ";

/// The closed `audit detect ` tool prefix (E11-2; ASCII ⇒ byte-slicing the
/// original preserves the path's case). `audit promote` / `audit run` / a bare
/// `audit detect` (no path) do NOT match — they fall through to `ToolUnknown`
/// (denied; the agent cannot promote a candidate or run a repro — IV-AE6).
const AUDIT_DETECT_PREFIX: &str = "audit detect ";

/// The closed `context index` tool (E11-4-2). A BARE `context index` (no path)
/// lists the registered project roots; `context index <path>` indexes that path.
/// Both are content-free (rel-paths / kinds / sizes — never file bytes). `context
/// file`, `context write`, `context delete`, etc. do NOT match — they fall through
/// to `ToolUnknown` (denied; the loop cannot read CONTENT via this tool or widen it
/// into a write — IV-F11, PD-1).
const CONTEXT_INDEX_PREFIX: &str = "context index ";
/// The BARE `context index` form (no path) — the registered-roots registry view.
const CONTEXT_INDEX_BARE: &str = "context index";

/// The closed `lsp diagnostics ` tool prefix (A①; ASCII ⇒ byte-slicing the
/// original preserves the path's case). `lsp definition` / `lsp references` / a
/// bare `lsp diagnostics` (no path) do NOT match — they fall through to
/// `ToolUnknown` (denied; v1 is diagnostics-only, the grammar stays closed).
const LSP_DIAGNOSTICS_PREFIX: &str = "lsp diagnostics ";

/// The closed `mcp ` tool prefix (B⑫; ASCII ⇒ byte-slicing the original preserves
/// the server / tool / JSON-arg case). `mcp <server> <tool> [json]` — `server` +
/// `tool` are the first two whitespace tokens, the rest (optional JSON object) is
/// the args. A bare `mcp` (no server+tool) falls through to `ToolUnknown` (denied;
/// v1 is read-call-only, the grammar stays closed).
const MCP_PREFIX: &str = "mcp ";

/// The closed `git ` tool prefix (A⑤; ASCII ⇒ byte-slicing the original preserves
/// the subcommand / arg case). `git <subcommand> [args]` — `subcommand` is the
/// first whitespace token, the rest is the args. A bare `git` (no subcommand) falls
/// through to `ToolUnknown`; a non-READ subcommand is denied by the chokepoint's
/// allowlist (v1 is READ-only — status/diff/log/show/blame).
const GIT_PREFIX: &str = "git ";

/// The closed `test run ` tool prefix (A②; ASCII ⇒ byte-slicing the original
/// preserves the package path's case). `test run <pkg>` — the rest is the package
/// path (relative to the workspace root). A bare `test run` (no pkg) / any other
/// `test …` (`test list`, etc.) falls through to `ToolUnknown` (denied; the runner
/// is fixed — `sui move test` / `cargo test` — never an arbitrary command).
const TEST_RUN_PREFIX: &str = "test run ";

/// The closed `search ` tool prefix (A④-rg; ASCII ⇒ byte-slicing the original
/// preserves the regex's case — a regex is case-sensitive). `search <regex>` — the
/// rest is the regex pattern (may contain spaces). A bare `search` (no pattern)
/// falls through to `ToolUnknown` (denied; the grammar stays closed, PD-1). Distinct
/// from `web search ` (a web query) — this searches the LOCAL workspace source.
const SEARCH_PREFIX: &str = "search ";

/// The closed `codebase ` tool prefix ([4] B⑨ semantic index) — the rest is the
/// retrieval query. A bare `codebase` (no query) falls through to `ToolUnknown`
/// (grammar closed, PD-1). Distinct from `search ` (a regex over raw source) — this
/// retrieves semantically/lexically relevant chunks from the local encrypted index.
const CODEBASE_PREFIX: &str = "codebase ";

/// Parse one model reply. The FIRST non-empty line decides: a `TOOL:` line
/// is matched against the CLOSED three-tool grammar (case-insensitive verb,
/// strict `u64` id, case-PRESERVED file path); everything else is the final
/// answer — a model that answers directly without the protocol completes.
/// Split `s` at the first ASCII-whitespace run: `(first_token, rest)` where `rest`
/// is the remainder with its leading whitespace trimmed (empty if `s` has no
/// whitespace). Peels the `<server>` then `<tool>` token off an `mcp` tool line
/// while leaving the trailing JSON args intact (B⑫).
fn split_first_token(s: &str) -> (&str, &str) {
    match s.find(char::is_whitespace) {
        Some(idx) => (&s[..idx], s[idx..].trim_start()),
        None => (s, ""),
    }
}

fn parse_turn(text: &str) -> ParsedTurn<'_> {
    let first = text
        .lines()
        .map(str::trim)
        .find(|line| !line.is_empty())
        .unwrap_or("");
    if let Some(tool) = first.strip_prefix("TOOL:") {
        let tool_trimmed = tool.trim();
        let lower = tool_trimmed.to_ascii_lowercase();
        if lower == "memory index" {
            return ParsedTurn::ToolIndex;
        }
        if let Some(id_text) = lower.strip_prefix("memory read ") {
            if let Ok(id) = id_text.trim().parse::<u64>() {
                return ParsedTurn::ToolRead(id);
            }
        }
        // E14-W2: navigate the 2-tier Walrus memory. `memory walrus-index` (bare) reads
        // the MAIN INDEX; `memory walrus-fetch <id>` enters a SUB-STORE.
        if lower == "memory walrus-index" {
            return ParsedTurn::ToolWalrusIndex;
        }
        if let Some(id_text) = lower.strip_prefix("memory walrus-fetch ") {
            if let Ok(id) = id_text.trim().parse::<u64>() {
                return ParsedTurn::ToolWalrusFetch(id);
            }
        }
        // File path must keep its original case ⇒ slice the ORIGINAL by the
        // ASCII prefix length, not the lowercased copy.
        if lower.starts_with(FILE_READ_PREFIX) {
            let path = tool_trimmed[FILE_READ_PREFIX.len()..].trim();
            if !path.is_empty() {
                return ParsedTurn::ToolFileRead(path);
            }
        }
        // Web URL must keep its original case (path/query are case-sensitive) ⇒
        // slice the ORIGINAL by the ASCII prefix length. `web post`, `web …` with
        // no url, etc. fall through to ToolUnknown (denied; the model cannot POST
        // or widen — IV-WF10).
        if lower.starts_with(WEB_FETCH_PREFIX) {
            let url = tool_trimmed[WEB_FETCH_PREFIX.len()..].trim();
            if !url.is_empty() {
                return ParsedTurn::ToolWebFetch(url);
            }
        }
        // P3b: `web search <query>` — the query keeps its original case ⇒ slice the
        // ORIGINAL by the ASCII prefix length. A bare `web search` (no query) falls
        // through to ToolUnknown (denied).
        if lower.starts_with(WEB_SEARCH_PREFIX) {
            let query = tool_trimmed[WEB_SEARCH_PREFIX.len()..].trim();
            if !query.is_empty() {
                return ParsedTurn::ToolWebSearch(query);
            }
        }
        // Audit detect path keeps its original case ⇒ slice the ORIGINAL by the
        // ASCII prefix length. `audit promote`, `audit run`, a bare `audit detect`
        // with no path, etc. fall through to ToolUnknown (denied; the agent cannot
        // promote a candidate or run a repro — IV-AE6).
        if lower.starts_with(AUDIT_DETECT_PREFIX) {
            let path = tool_trimmed[AUDIT_DETECT_PREFIX.len()..].trim();
            if !path.is_empty() {
                return ParsedTurn::ToolAuditDetect(path);
            }
        }
        // `context index` (bare) ⇒ the registered project roots; `context index
        // <path>` ⇒ a bounded, content-free project file index (path keeps its
        // original case ⇒ slice the ORIGINAL). Any other `context …`
        // (file/write/delete) falls through to ToolUnknown (denied — the loop
        // cannot read CONTENT via this tool or widen it into a write; IV-F11, PD-1).
        if lower == CONTEXT_INDEX_BARE {
            return ParsedTurn::ToolContextIndex("");
        }
        if lower.starts_with(CONTEXT_INDEX_PREFIX) {
            let path = tool_trimmed[CONTEXT_INDEX_PREFIX.len()..].trim();
            if !path.is_empty() {
                return ParsedTurn::ToolContextIndex(path);
            }
        }
        // A① `lsp diagnostics <path>` — path keeps its original case ⇒ slice the
        // ORIGINAL by the ASCII prefix length. `lsp definition` / `lsp references`
        // / a bare `lsp diagnostics` fall through to ToolUnknown (denied; v1 is
        // diagnostics-only — the grammar stays closed).
        if lower.starts_with(LSP_DIAGNOSTICS_PREFIX) {
            let path = tool_trimmed[LSP_DIAGNOSTICS_PREFIX.len()..].trim();
            if !path.is_empty() {
                return ParsedTurn::ToolLspDiagnostics(path);
            }
        }
        // B⑫ `mcp <server> <tool> [json-args]` — server + tool are the first two
        // whitespace tokens (case-PRESERVED ⇒ slice the ORIGINAL by the ASCII
        // prefix length); the remainder (an optional JSON object) is the args. A
        // bare `mcp` / a missing tool falls through to ToolUnknown (denied; v1 is a
        // read-call only — the grammar stays closed).
        if lower.starts_with(MCP_PREFIX) {
            let rest = tool_trimmed[MCP_PREFIX.len()..].trim_start();
            let (server, after) = split_first_token(rest);
            let (tool, args) = split_first_token(after.trim_start());
            if !server.is_empty() && !tool.is_empty() {
                return ParsedTurn::ToolMcp(server, tool, args.trim());
            }
        }
        // A⑤ `git <subcommand> [args]` — subcommand is the first whitespace token
        // (case-PRESERVED ⇒ slice the ORIGINAL), the remainder is the args. A bare
        // `git` (no subcommand) falls through to ToolUnknown; a non-READ subcommand
        // is denied by the chokepoint's allowlist (grammar stays closed, PD-1).
        if lower.starts_with(GIT_PREFIX) {
            let rest = tool_trimmed[GIT_PREFIX.len()..].trim_start();
            let (subcommand, args) = split_first_token(rest);
            if !subcommand.is_empty() {
                return ParsedTurn::ToolGit(subcommand, args.trim());
            }
        }
        // A② `test run <pkg>` — the package path keeps its original case ⇒ slice the
        // ORIGINAL by the ASCII prefix length. A bare `test run` (no pkg) / any other
        // `test …` falls through to ToolUnknown (the runner is fixed; the grammar
        // stays closed, PD-1).
        if lower.starts_with(TEST_RUN_PREFIX) {
            let pkg = tool_trimmed[TEST_RUN_PREFIX.len()..].trim();
            if !pkg.is_empty() {
                return ParsedTurn::ToolTestRun(pkg);
            }
        }
        // A④-rg `search <regex>` — the regex keeps its original case ⇒ slice the
        // ORIGINAL by the ASCII prefix length. A bare `search` (no pattern) falls
        // through to ToolUnknown (grammar closed, PD-1). Checked AFTER `web search `
        // (which begins `web `, never `search `) ⇒ no collision.
        if lower.starts_with(SEARCH_PREFIX) {
            let pattern = tool_trimmed[SEARCH_PREFIX.len()..].trim();
            if !pattern.is_empty() {
                return ParsedTurn::ToolSearch(pattern);
            }
        }
        // [4] B⑨ `codebase <query>` — semantic retrieval from the local encrypted index.
        // A bare `codebase` (no query) falls through to ToolUnknown (grammar closed, PD-1).
        if lower.starts_with(CODEBASE_PREFIX) {
            let query = tool_trimmed[CODEBASE_PREFIX.len()..].trim();
            if !query.is_empty() {
                return ParsedTurn::ToolCodebase(query);
            }
        }
        // K-0a-3 `skew capabilities` — the agent reads the Skew capability catalog (the
        // `skew_catalog` single source of truth) mid-reasoning. A pure static READ. Any
        // OTHER `skew …` (`skew capability <name>`, `skew trade …`, a bare `skew`) falls
        // through to ToolUnknown (denied; the loop can READ the surface but NEVER originate
        // a trade — trading is a separate owner-armed bounded action, K-2).
        if lower == "skew capabilities" {
            return ParsedTurn::ToolSkewCapabilities;
        }
        return ParsedTurn::ToolUnknown(first);
    }
    let trimmed = text.trim();
    let answer = trimmed.strip_prefix("ANSWER:").map_or(trimmed, str::trim);
    ParsedTurn::Answer(answer)
}

// ===========================================================================
// 5. Frontier tool executors (IV1/IV2/IV4 walls; results are PROMPT-bound)
// ===========================================================================
//
// ENDGAME E1 / PD-3 — RECALL IS A READ. Every recall executor below takes a
// [`ReadCapability`] witness (a zero-sized [`commands::authority`] token whose
// ONLY constructor is [`ReadCapability::granted`], handed out freely — reads
// are not side effects). The witness makes "autonomous recall needs only READ"
// a TYPE fact, not a comment: an executor CANNOT be called with an egress /
// mutate / approval token in its place (they are distinct types), and READ can
// never be widened into egress/mutate (PD-2, E0d — self-escalation does not
// compile). The loop driver itself holds NO egress/mutate/approval symbol at
// all (proven structurally by `ops/evidence/stage_g/e1_recall_read_only_grep.sh`).
// `_read` is a witness, not a gate: recall is never denied — it is typed.

/// Char-boundary-safe truncation with an explicit marker (never silent).
fn truncate_char_safe(text: &str, cap_bytes: usize) -> String {
    if text.len() <= cap_bytes {
        return text.to_string();
    }
    let mut cut = cap_bytes;
    while cut > 0 && !text.is_char_boundary(cut) {
        cut -= 1;
    }
    format!("{}…[truncated]", &text[..cut])
}

/// `memory index` for a FRONTIER turn: `catalog_select(frontier_bound =
/// true)` — tombstoned AND private records are excluded BEFORE anything is
/// rendered (IV2/IV3/D7). Summaries only; never content, never blob bytes.
fn frontier_index_result(_read: ReadCapability, state: &MemoryToolState<'_>) -> String {
    let visible = catalog_select(state.records, true);
    let mut out = format!(
        "memory index: {} shareable records (private + tombstoned excluded)\n",
        visible.len()
    );
    for record in visible.iter().take(AGENT_LOOP_INDEX_RENDER_CAP) {
        out.push_str(&format!(
            "id={} imp={} summary={}\n",
            record.memory_id().get(),
            record.importance_u16(),
            record.summary_str()
        ));
    }
    if visible.len() > AGENT_LOOP_INDEX_RENDER_CAP {
        out.push_str(&format!(
            "… {} more (bounded)\n",
            visible.len() - AGENT_LOOP_INDEX_RENDER_CAP
        ));
    }
    truncate_char_safe(&out, AGENT_LOOP_TOOL_RESULT_CAP_BYTES)
}

/// `memory read <id>` for a FRONTIER turn — the full gate chain (design §5):
/// delete truth (IV3 layer 1) → `read_select(frontier_bound = true)`
/// (existence + tier + PRIVACY, IV2/IV3) → content presence → content-hash
/// verify (IV4/D6) → UTF-8 only → the canonical redaction gate with
/// `include_private_memory = record.is_private()` (IV1 — structurally
/// unreachable after `read_select`, kept as the second wall). Every denial
/// is a typed label the model can read; denied bytes NEVER enter the prompt.
fn frontier_read_result(_read: ReadCapability, state: &MemoryToolState<'_>, id: u64) -> String {
    let memory_id = MemoryId::new(id);
    if state.policy.is_tombstoned(memory_id) {
        return format!("memory read {id}: denied (memory_index.read_deny.tombstoned)");
    }
    let record = match read_select(state.records, memory_id, true) {
        Ok(record) => record,
        Err(deny) => {
            return format!("memory read {id}: denied ({})", deny.class_label());
        }
    };
    let Some((_, content)) = state.contents.iter().find(|(cid, _)| *cid == memory_id) else {
        return format!("memory read {id}: denied (content unavailable)");
    };
    if let Err(error) = record.verify_against_content(content) {
        return format!("memory read {id}: denied ({})", error.class_label());
    }
    let Ok(text) = core::str::from_utf8(content) else {
        return format!("memory read {id}: denied (binary content)");
    };
    let fragments = [text];
    let deleted: Vec<[u8; 32]> = state
        .records
        .iter()
        .filter(|r| r.is_tombstone())
        .map(|r| *r.content_hash_32())
        .collect();
    match redact(&RedactionRequest {
        fragments: &fragments,
        candidate_memory_ids: &[*record.content_hash_32()],
        deleted_ids: &deleted,
        include_private_memory: record.is_private(),
    }) {
        Err(_) => format!("memory read {id}: denied (redaction)"),
        Ok(receipt) if receipt.secret_fragments_denied_u32() > 0 => {
            format!("memory read {id}: withheld (secret-shaped)")
        }
        Ok(_) => truncate_char_safe(
            &format!("memory read {id} (verified):\n{text}"),
            AGENT_LOOP_TOOL_RESULT_CAP_BYTES,
        ),
    }
}

/// `file read <path>` for a FRONTIER turn (lane A): the full file wall stack
/// (IV-F1 allowlist + IV-F2 denylist + IV-F3 size cap, all inside
/// [`crate::file_context::FileReadPolicy::read`]) → UTF-8-only (IV-F5) → the
/// canonical redaction gate (IV-F6). `None` policy ⇒ denied (no file access
/// configured). The `(verified)` marker drives the K-read count, exactly like
/// `frontier_read_result`. Denied/withheld bytes NEVER enter the prompt.
///
/// P3-2 (IV-W2): a VERIFIED read additionally returns the executor's own
/// `{path, canonical, sha256}` record — the ONLY truth a later `PROPOSE-EDIT`
/// may bind to. Every non-verified outcome returns `None` (never recorded).
fn frontier_file_result(
    _read: ReadCapability,
    file_policy: Option<&crate::file_context::FileReadPolicy>,
    path: &str,
) -> (String, Option<VerifiedFileRead>) {
    let Some(policy) = file_policy else {
        return (
            format!("file read {path}: denied (no file access configured)"),
            None,
        );
    };
    let result = match policy.read(std::path::Path::new(path)) {
        Ok(result) => result,
        Err(deny) => {
            return (
                format!("file read {path}: denied ({})", deny.class_label()),
                None,
            );
        }
    };
    let Some(text) = result.text.as_deref() else {
        return (
            format!(
                "file read {path}: binary ({} bytes); withheld (utf-8 only)",
                result.len_bytes()
            ),
            None,
        );
    };
    // E14-B2: per-line redaction so a benign code / audit / security file that merely
    // MENTIONS a secret token stays READABLE (only the secret-shaped lines are
    // withheld), instead of wholesale-withholding + tripping the guard lockdown that
    // killed the whole consult after one turn. The SI-2 wall still keeps every
    // secret-shaped line OUT of the frontier-bound context (the line is replaced, not
    // shown); this only stops a benign read from aborting the session.
    //
    // A multi-line key/cert block (PEM `-----BEGIN`) is fully withheld — its body
    // lines do NOT match the single-line markers, so per-line redaction could leak
    // them. (A bare key FILE is already lane-A denied; this catches one embedded in a
    // .md/.txt.)
    if text.to_ascii_lowercase().contains("-----begin") {
        return (
            format!(
                "file read {path}: contains a key/cert block; fully withheld (safety) — read a different file or ask the owner"
            ),
            None,
        );
    }
    let mut redacted_lines: Vec<String> = Vec::new();
    let mut withheld_u32 = 0u32;
    for line in text.lines() {
        let fragment = [line];
        let line_is_secret = match redact(&RedactionRequest {
            fragments: &fragment,
            candidate_memory_ids: &[],
            deleted_ids: &[],
            include_private_memory: false,
        }) {
            Ok(receipt) => receipt.secret_fragments_denied_u32() != 0,
            // fail-closed: a line we cannot classify is withheld, never shown.
            Err(_) => true,
        };
        if line_is_secret {
            withheld_u32 = withheld_u32.saturating_add(1);
            redacted_lines.push("[withheld: secret-shaped line]".to_string());
        } else {
            redacted_lines.push(line.to_string());
        }
    }
    let body = redacted_lines.join("\n");
    let header = if withheld_u32 == 0 {
        format!("file read {path} (verified):")
    } else {
        format!("file read {path} (verified, {withheld_u32} secret-shaped line(s) withheld):")
    };
    (
        truncate_char_safe(
            &format!("{header}\n{body}"),
            AGENT_LOOP_TOOL_RESULT_CAP_BYTES,
        ),
        // Only a FULLY-clean read is editable: a partial (redacted) read could propose
        // an edit that writes the withhold-markers back into the file, so the edit
        // receipt is withheld whenever any line was redacted.
        if withheld_u32 == 0 {
            Some(VerifiedFileRead {
                path_as_typed: path.to_string(),
                canonical_path: result.canonical_path.clone(),
                sha256_32: result.sha256_32,
            })
        } else {
            None
        },
    )
}

/// `web fetch <url>` for a FRONTIER turn (E11-1b; WEB_FETCH_THREAT_MODEL.md ⑭):
/// the SHARED glue ([`render_web_fetch`](crate::provider::web_fetch::render_web_fetch))
/// — classify_url SSRF wall (IV-WF1/WF10) → the seam's secret-zero GET → the
/// canonical redaction gate on the UNTRUSTED body (IV-WF5) → rights/quote-gated,
/// advisory-only surface (IV-WF6). A `None` seam (or a default build with no web
/// socket) is the honest "web transport not compiled" deny — the grammar stays
/// closed (a fetch is a gated READ, not a new side effect; the loop stays pure for
/// PD-1). A VERIFIED advisory consumes K (IV-WF8, the bool); a deny / withhold
/// never does. `retrieved_at = 0`: the loop is pure (no clock), and the record's
/// timestamp is metadata, never a gate input. Denied / withheld bytes NEVER enter
/// the prompt.
fn frontier_web_fetch_result(
    _read: ReadCapability,
    web_seam: Option<&crate::provider::web_fetch::WebFetchSeam>,
    url: &str,
) -> (String, bool) {
    let policy = crate::provider::web_policy::WebSourcePolicy {
        web_enabled: true,
        max_quote_chars_u32: crate::provider::web_fetch::WEB_FETCH_QUOTE_CHARS,
    };
    let port = web_seam.and_then(|seam| seam.port());
    let render = crate::provider::web_fetch::render_web_fetch(port, &policy, url, 0);
    (
        truncate_char_safe(&render.rendered, AGENT_LOOP_TOOL_RESULT_CAP_BYTES),
        render.consumed_read,
    )
}

/// `audit detect <path>` for a FRONTIER turn (E11-2; AUDIT_ENGINE_THREAT_MODEL.md ⑮):
/// drive the audit game-tree engine on a REAL local source tree through the SHARED
/// glue ([`run_source_detect`](crate::audit::detect::run_source_detect)) and return
/// the impact-ranked CANDIDATE report. Pure local analysis: a bounded read-only walk
/// that emits COUNTS + hashed anchors + STATIC rule labels only — NO raw source byte,
/// NO promotion, NO repro-run, NO exec (IV-AE1/AE4/AE6). The agent can PROPOSE an
/// audit detect (a gated READ); it CANNOT promote a candidate to a finding or run a
/// repro — that is the owner-gated, kernel-sandboxed exec chokepoint (the loop grammar
/// stays CLOSED, PD-1). A detect always runs a bounded walk ⇒ it consumes K (the bool
/// is always `true`; there is no "deny" path — an empty / unreadable tree is a valid
/// zero-candidate report, never a leak).
fn frontier_audit_detect_result(_read: ReadCapability, path: &str) -> (String, bool) {
    let report = crate::audit::detect::run_source_detect(
        std::path::Path::new(path),
        crate::commands::eval_core::AuditProfile::Rust,
    );
    let rendered = crate::audit::detect::report_lines(&report).join("\n");
    (
        truncate_char_safe(&rendered, AGENT_LOOP_TOOL_RESULT_CAP_BYTES),
        true,
    )
}

/// `skew capabilities` for a FRONTIER turn (K-0a-3): the agent reads the Skew capability
/// catalog (the [`crate::skew_catalog`] single source of truth) mid-reasoning — a PURE static
/// READ (no key, no network, money 0). The rendered catalog is redact-belted before it enters
/// the prompt (SI-2, defense-in-depth though the catalog holds no secrets) and truncated to the
/// shared tool-result cap. Always a successful read (consumes one K).
fn frontier_skew_capabilities_result(_read: ReadCapability) -> (String, bool) {
    let rendered = crate::skew_catalog::render_catalog();
    let fragments = [rendered.as_str()];
    let safe = match redact(&RedactionRequest {
        fragments: &fragments,
        candidate_memory_ids: &[],
        deleted_ids: &[],
        include_private_memory: false,
    }) {
        Ok(r) if r.secret_fragments_denied_u32() == 0 => rendered,
        _ => "skew capabilities: withheld (a line was secret-shaped)".to_string(),
    };
    (
        truncate_char_safe(&safe, AGENT_LOOP_TOOL_RESULT_CAP_BYTES),
        true,
    )
}

/// `memory walrus-index` for a FRONTIER turn (E14-W2): the agent reads its MAIN INDEX
/// from the 2-tier Walrus memory — every memory's `(id, topic)` — to decide which
/// sub-store to enter. Under `put-fixture-net` it reaches the real testnet aggregator;
/// off-build it honest-degrades (the grammar stays closed; a read is not a side effect,
/// PD-1). The rendered index is redact-belted before it enters the prompt (SI-2). A
/// successful index consumes K; a deny / not-compiled never does.
fn frontier_walrus_index_result(_read: ReadCapability) -> (String, bool) {
    #[cfg(feature = "put-fixture-net")]
    {
        let store = match crate::memory_store::PersistedStore::open_local() {
            Ok(s) => s,
            Err(_) => return ("memory walrus-index: store unavailable".to_string(), false),
        };
        match crate::memory_walrus::load_main_index(&store) {
            Ok(index) => {
                let mut lines = vec![format!(
                    "walrus-index: {} memories on Walrus (MAIN INDEX)",
                    index.entries.len()
                )];
                for e in index.entries.iter().take(64) {
                    lines.push(format!("id={} topic={}", e.memory_id, e.topic));
                }
                let rendered = lines.join("\n");
                let fragments = [rendered.as_str()];
                let safe = match redact(&RedactionRequest {
                    fragments: &fragments,
                    candidate_memory_ids: &[],
                    deleted_ids: &[],
                    include_private_memory: false,
                }) {
                    Ok(r) if r.secret_fragments_denied_u32() == 0 => rendered,
                    _ => "walrus-index: withheld (a topic was secret-shaped)".to_string(),
                };
                (
                    truncate_char_safe(&safe, AGENT_LOOP_TOOL_RESULT_CAP_BYTES),
                    true,
                )
            }
            Err(reason) => (format!("memory walrus-index: {reason}"), false),
        }
    }
    #[cfg(not(feature = "put-fixture-net"))]
    {
        let _ = _read;
        (
            "memory walrus-index: the Walrus transport is not compiled (build --features put-fixture-net)".to_string(),
            false,
        )
    }
}

/// `memory walrus-fetch <id>` for a FRONTIER turn (E14-W2 + W4 Slice 2 P-RAG): the agent
/// enters the SUB-STORE for `id` via the MAIN INDEX with a RESILIENT fetch (Walrus
/// PRIMARY → 0G FALLBACK), then a DETERMINISTIC CRAG evaluator labels the result
/// Correct/Ambiguous/Incorrect against the task `query`. On an Incorrect (off-topic)
/// fetch it WIDENS to the best-ranked OTHER index entries (bounded) — turning a silent
/// wrong retrieval into a detected, recovered event; the agent prefers VERIFIED memory.
/// The chosen detail is redact-belted (SI-2) before it enters the prompt. A successful
/// fetch consumes K; a deny / not-compiled never does. The evaluator is 0 LLM tokens
/// (META-LAW: the model proposes the tool call, an L0 check judges).
fn frontier_walrus_fetch_result(
    _read: ReadCapability,
    memory_id: u64,
    query: &str,
) -> (String, bool) {
    #[cfg(feature = "put-fixture-net")]
    {
        let store = match crate::memory_store::PersistedStore::open_local() {
            Ok(s) => s,
            Err(_) => {
                return (
                    format!("memory walrus-fetch {memory_id}: store unavailable"),
                    false,
                );
            }
        };
        let index = match crate::memory_walrus::load_main_index(&store) {
            Ok(i) => i,
            Err(reason) => return (format!("memory walrus-fetch {memory_id}: {reason}"), false),
        };
        // CRAG corrective retrieval (deterministic): fetch the requested id (Walrus→0G
        // resilient), and on an Incorrect (off-topic) result WIDEN to the best-ranked
        // other MAIN INDEX entries. The model never judges — `corrective_fetch` is pure.
        let entries: Vec<(u64, String)> = index
            .entries
            .iter()
            .map(|e| (e.memory_id, e.topic.clone()))
            .collect();
        let outcome = crate::memory_crag::corrective_fetch(query, memory_id, &entries, |id| {
            index
                .entries
                .iter()
                .find(|e| e.memory_id == id)
                .and_then(|e| crate::memory_walrus::fetch_entry_resilient(&store, e))
        });
        let Some(content) = outcome.body else {
            return (
                format!(
                    "memory walrus-fetch {memory_id}: sub-store not fetched from Walrus or 0G (propagation/boundary)"
                ),
                false,
            );
        };
        let verdict = outcome
            .verdict
            .unwrap_or_else(|| crate::memory_crag::evaluate(query, &content));
        let widen = if outcome.widen_trail.is_empty() {
            String::new()
        } else {
            let trail: Vec<String> = outcome
                .widen_trail
                .iter()
                .map(|(id, label)| format!("{id}:{}", label.label()))
                .collect();
            format!(" widen[{}]", trail.join(","))
        };
        let header = format!(
            "walrus memory id={} [{} via {}{}] (fetched + decrypted):",
            outcome.chosen_id,
            verdict.render_tag(),
            outcome.backend,
            widen,
        );
        let fragments = [content.as_str()];
        let safe = match redact(&RedactionRequest {
            fragments: &fragments,
            candidate_memory_ids: &[],
            deleted_ids: &[],
            include_private_memory: false,
        }) {
            Ok(r) if r.secret_fragments_denied_u32() == 0 => format!("{header}\n{content}"),
            _ => format!(
                "walrus memory id={}: withheld (secret-shaped)",
                outcome.chosen_id
            ),
        };
        (
            truncate_char_safe(&safe, AGENT_LOOP_TOOL_RESULT_CAP_BYTES),
            true,
        )
    }
    #[cfg(not(feature = "put-fixture-net"))]
    {
        let _ = (_read, memory_id, query);
        (
            "memory walrus-fetch: the Walrus transport is not compiled (build --features put-fixture-net)".to_string(),
            false,
        )
    }
}

/// `context index [<path>]` for a FRONTIER turn (E11-4-2; FILE_CONTEXT IV-F8..F11):
/// EXPOSE the already-walled PROJECT enumeration to the loop. A bare (empty) path
/// renders the registered project roots; a path renders a bounded, deterministic,
/// content-free index (rel-paths + kinds + sizes — NEVER file CONTENT). Reuses the
/// SAME `FileReadPolicy::cwd_default()` allowlist + `project_index::index_project`
/// (symlink-never-followed, denylist-pruned, capped) the dispatch verb uses, and
/// the SAME IV-F11 withhold: a secret-SHAPED rendered name ⇒ the WHOLE listing is
/// withheld (`scan_inline_secret`). A surfaced listing consumes K (the bool); a
/// deny / withhold / empty-roots never does. The 6th typed-READ executor (carries
/// the `ReadCapability` witness — a content-free enumeration is a gated READ, not a
/// side effect; the agent cannot read CONTENT or write through it, PD-1).
fn frontier_context_index_result(_read: ReadCapability, path: &str) -> (String, bool) {
    let policy = crate::file_context::FileReadPolicy::workspace_default();
    let (lines, surfaced) = if path.is_empty() {
        // Bare: the registered project roots (cwd + SINABRO_FILE_ROOTS) — the SAME
        // one-source-of-truth registry the dispatch verb renders. Content-free.
        let roots = policy.roots();
        let mut lines = vec![format!("registered project roots ({})", roots.len())];
        for root in roots
            .iter()
            .take(crate::project_index::MAX_INDEX_RENDER_LINES)
        {
            lines.push(format!("  {}", root.display()));
        }
        (lines, !roots.is_empty())
    } else {
        match crate::project_index::index_project(&policy, std::path::Path::new(path)) {
            Ok(index) => {
                let mut lines = vec![
                    format!("project={}", index.root.display()),
                    format!("entries={} truncated={}", index.len(), index.truncated),
                ];
                for entry in index
                    .entries
                    .iter()
                    .take(crate::project_index::MAX_INDEX_RENDER_LINES)
                {
                    let kind = if entry.is_symlink {
                        "l"
                    } else if entry.is_dir {
                        "d"
                    } else {
                        "f"
                    };
                    lines.push(format!("  [{kind}] {}", entry.rel_path));
                }
                (lines, true)
            }
            Err(deny) => {
                // Typed, content-free denial — never an escaped path or file bytes.
                return (
                    format!("context index {path}: denied ({})", deny.class_label()),
                    false,
                );
            }
        }
    };
    // IV-F11 (the SAME wall as the dispatch verb's `redact_or_withhold`): a
    // secret-SHAPED rendered name ⇒ withhold the WHOLE listing (never a leak).
    if lines
        .iter()
        .any(|line| crate::secrets::scan_inline_secret(line))
    {
        return (
            "context index: WITHHELD (a name was secret-shaped)".to_string(),
            false,
        );
    }
    (
        truncate_char_safe(&lines.join("\n"), AGENT_LOOP_TOOL_RESULT_CAP_BYTES),
        surfaced,
    )
}

/// `lsp diagnostics <path>` for a FRONTIER turn (A①, CURSOR PARITY keystone-1):
/// run the REAL language server over `path` (sandboxed — network + write
/// kernel-DENIED = READ-class T3) and surface its diagnostics — COMPILER TRUTH,
/// not a model guess (AXIS-2 / P-HALL anti-hallucination). The whole pipeline
/// (the walled file read → the sandboxed server → the redact belt) lives in
/// [`crate::lsp`]; here we only truncate. An absent binary / a non-`lsp` build /
/// an unreadable file honest-degrades (the bool is `false`, no K consumed); a
/// real verdict consumes K. The agent can READ diagnostics but writes/execs
/// NOTHING through it (PD-1). The 9th typed-READ executor (carries the
/// `ReadCapability` witness — a gated READ, never widened to egress/mutate).
fn frontier_lsp_diagnostics_result(_read: ReadCapability, path: &str) -> (String, bool) {
    let (rendered, ran) = crate::lsp::diagnose(path);
    (
        truncate_char_safe(&rendered, AGENT_LOOP_TOOL_RESULT_CAP_BYTES),
        ran,
    )
}

/// `mcp <server> <tool> [args]` for a FRONTIER turn (B⑫, CURSOR PARITY keystone-3):
/// call a READ-class tool on an owner-configured LOCAL stdio MCP server through the
/// SHARED chokepoint ([`crate::mcp::render_mcp_call`]) — the SAME wall → redact ARG
/// → sandboxed `tools/call` (network kernel-DENIED) → redact RESULT → audit pipeline
/// the `context mcp` dispatch verb uses. An unconfigured server / an un-advertised
/// tool / a secret-shaped arg-or-result / a non-`mcp` build honest-degrades (the
/// bool is `false`, no K consumed); a verified, redacted result consumes K. The
/// agent can READ an MCP tool but writes / execs NOTHING through it (v1 read-only,
/// the grammar stays closed, PD-1). The 11th typed-READ executor (carries the
/// `ReadCapability` witness — a gated READ, never widened to egress/mutate).
fn frontier_mcp_call_result(
    _read: ReadCapability,
    mcp_seam: Option<&crate::mcp::McpSeam>,
    server: &str,
    tool: &str,
    args: &str,
) -> (String, bool) {
    let render = crate::mcp::render_mcp_call(mcp_seam, server, tool, args);
    (
        truncate_char_safe(&render.rendered, AGENT_LOOP_TOOL_RESULT_CAP_BYTES),
        render.consumed_read,
    )
}

/// `git <subcommand> [args]` for a FRONTIER turn (A⑤, CURSOR PARITY git-as-
/// capability-type): run a READ-only git subcommand (status/diff/log/show/blame) on
/// the local repo through the SHARED chokepoint ([`crate::git::render_git_read`]) —
/// the SAME allowlist → sandboxed git (network + write kernel-DENIED) → redact
/// pipeline the `context git` dispatch verb uses. A non-READ subcommand / an absent
/// git / a not-a-repo / a secret-shaped output honest-degrades (the bool is `false`,
/// no K consumed); a real git READ consumes K. The agent READS the repo but writes /
/// pushes NOTHING through it (v1 read-only; commit/branch/push are an owner-armed v2,
/// the grammar stays closed, PD-1). The 11th typed-READ executor (carries the
/// `ReadCapability` witness — a gated READ, never widened to mutate/egress).
fn frontier_git_result(_read: ReadCapability, subcommand: &str, args: &str) -> (String, bool) {
    let render = crate::git::render_git_read(subcommand, args);
    (
        truncate_char_safe(&render.rendered, AGENT_LOOP_TOOL_RESULT_CAP_BYTES),
        render.consumed_read,
    )
}

/// `test run <pkg>` for a FRONTIER turn (A②, CURSOR PARITY oracle test-loop): run the
/// REAL test runner (`sui move test` / `cargo test`) on a workspace package through
/// the SHARED chokepoint ([`crate::test_run::render_test_run`]) — the SAME validate →
/// sandboxed run (network kernel-DENIED, write-allowed for build artifacts) → redact
/// pipeline the `context test-run` dispatch verb uses. A non-package / an absent
/// toolchain / a secret-shaped output honest-degrades (the bool is `false`, no K
/// consumed); a real verdict (PASS/FAIL) consumes K. The agent gets COMPILER/TEST
/// truth (AXIS-2 / P-HALL) to reason about a fix, but writes / execs NOTHING beyond
/// the sandboxed test (PD-1). The 12th typed-READ executor (carries the
/// `ReadCapability` witness — a gated READ, never widened to mutate/egress).
fn frontier_test_run_result(_read: ReadCapability, pkg: &str) -> (String, bool) {
    let render = crate::test_run::render_test_run(pkg);
    (
        truncate_char_safe(&render.rendered, AGENT_LOOP_TOOL_RESULT_CAP_BYTES),
        render.consumed_read,
    )
}

/// `search <regex>` for a FRONTIER turn (A④-rg, CURSOR PARITY find-in-files): run a
/// linear-time REGEX over the workspace source through the SHARED chokepoint
/// ([`crate::search::render_search`]) — the SAME validate → bounded walk (each file
/// through the proven file-context wall: under-root + denylist + size cap + UTF-8) →
/// per-line redact pipeline the `context search` dispatch verb uses. NO subprocess,
/// NO network, NO write (a pure in-Rust READ, like `context index`). An invalid
/// pattern / no workspace root honest-degrades (the bool is `false`, no K consumed);
/// a real walk (even zero hits) consumes K. The agent LOCATES code by pattern but
/// writes NOTHING (PD-1). The 13th typed-READ executor (carries the `ReadCapability`
/// witness — a gated READ, never widened to mutate/egress).
fn frontier_search_result(_read: ReadCapability, pattern: &str) -> (String, bool) {
    let render = crate::search::render_search(pattern);
    (
        truncate_char_safe(&render.rendered, AGENT_LOOP_TOOL_RESULT_CAP_BYTES),
        render.consumed_read,
    )
}

/// `codebase <query>` for a FRONTIER turn ([4] B⑨ semantic index): load the LOCAL
/// encrypted-at-rest codebase index ([`crate::codebase_index::load_persisted_index`]) and
/// retrieve the top-K semantically + lexically relevant chunks
/// ([`crate::codebase_index::render_retrieval`], the SAME chokepoint the `context
/// codebase` verb uses). Local embeddings — NO network, NO subprocess, NO write; each
/// surfaced chunk passes the per-line redact wall. No index ⇒ honest "build first" (the
/// bool is `false`, no K consumed). The 14th typed-READ executor (carries the
/// `ReadCapability` witness — a gated READ, never widened to mutate/egress).
fn frontier_codebase_result(_read: ReadCapability, query: &str) -> (String, bool) {
    let Some(index) = crate::codebase_index::load_persisted_index() else {
        return (
            "codebase: no index (the owner runs `context codebase build` first)".to_string(),
            false,
        );
    };
    let render = crate::codebase_index::render_retrieval(
        &index,
        query,
        &crate::codebase_index::StubEmbedder,
    );
    (
        truncate_char_safe(&render.rendered, AGENT_LOOP_TOOL_RESULT_CAP_BYTES),
        render.consumed_read,
    )
}

// ===========================================================================
// 6. The driver
// ===========================================================================

/// Assemble the per-turn user message: the question plus the accumulated
/// tool results (oldest dropped first when over the byte cap). Deterministic
/// for equal inputs.
///
/// P2-1 cache law: the assembly is APPEND-ONLY — no per-turn tail text —
/// so until the byte cap slides the kept-results window, each turn's
/// message extends the previous one as a strict byte prefix (the property
/// a provider-side prefix cache keys on). The protocol reminder lives in
/// the SYSTEM prompt ([`SINABRO_LOOP_PROTOCOL`], the byte-stable static
/// prefix), where it is cached instead of busting the cache from the tail.
fn build_user_message(question: &str, results: &[String]) -> String {
    let mut keep_from = 0usize;
    loop {
        let mut message = String::from(question);
        for result in &results[keep_from..] {
            message.push_str("\n\n[tool result]\n");
            message.push_str(result);
        }
        if message.len() <= AGENT_LOOP_USER_MSG_CAP_BYTES || keep_from >= results.len() {
            return truncate_char_safe(&message, AGENT_LOOP_USER_MSG_CAP_BYTES);
        }
        keep_from += 1;
    }
}

/// Run the bounded agentic retrieval loop (design §6). Pure orchestration:
/// every stop is typed, every dimension is capped, no side effect exists on
/// any path — the ONLY thing the model can cause is a read-only projection.
pub fn run_agent_loop(
    transport: &mut dyn AgentTransport,
    state: &MemoryToolState<'_>,
    system: &str,
    question: &str,
) -> AgentLoopOutcome {
    run_agent_loop_with(
        transport,
        state,
        system,
        question,
        AGENT_LOOP_MAX_ITER,
        AGENT_LOOP_TOKEN_CAP,
        None,
        None,
        None,
    )
}

/// [`run_agent_loop`] with explicit caps and an optional local-file read
/// policy (lane A). The fan-out path funds each child a PARTITIONED budget
/// slice and a tighter iteration cap (fan threat model D-2/D-3); every other
/// bound (K reads, tool-result / user-message bytes) is shared with the
/// single loop. `file_policy = None` ⇒ the `file read` tool denies (no file
/// access configured); `Some` ⇒ the frontier file executor reads through it
/// and applies redaction (IV-F1..F6). File reads share the SAME K-read wall
/// as memory reads.
///
/// E11-1b: `web_seam = None` ⇒ the `web fetch` tool denies (no web transport in
/// this loop / the default build has no web socket); `Some` ⇒ the frontier web
/// executor fetches through the shared SSRF-walled glue (a gated public READ,
/// IV-WF1..WF10). Web fetches share the SAME K-read wall.
///
/// B⑫: `mcp_seam = None` (or an inert seam) ⇒ the `mcp` tool denies (no MCP server
/// configured); `Some` ⇒ the frontier MCP executor calls a READ-class tool on an
/// owner-configured LOCAL stdio server through the shared chokepoint (wall → redact
/// arg → sandboxed `tools/call` → redact result → audit). MCP calls share the SAME
/// K-read wall.
// The driver's bounds (caps, file policy, web seam, mcp seam) are orthogonal,
// named parameters — bundling them into a struct would only obscure the call sites.
#[allow(clippy::too_many_arguments)]
pub fn run_agent_loop_with(
    transport: &mut dyn AgentTransport,
    state: &MemoryToolState<'_>,
    system: &str,
    question: &str,
    max_iter_u8: u8,
    token_cap_u32: u32,
    file_policy: Option<&crate::file_context::FileReadPolicy>,
    web_seam: Option<&crate::provider::web_fetch::WebFetchSeam>,
    mcp_seam: Option<&crate::mcp::McpSeam>,
) -> AgentLoopOutcome {
    // The non-streaming entry: a discarding delta sink + a never-set cancel ⇒ every
    // existing caller is byte-identical to the pre-S-C behavior.
    let never = std::sync::atomic::AtomicBool::new(false);
    run_agent_loop_streaming(
        transport,
        state,
        system,
        question,
        max_iter_u8,
        token_cap_u32,
        file_policy,
        web_seam,
        mcp_seam,
        &mut |_| {},
        &never,
    )
}

/// [`run_agent_loop_with`] but STREAMING (S-C): `on_delta` receives each answer delta
/// AS the model generates it (the CALLER routes each delta through the redaction wall
/// before it leaves the process), and `cancel` is checked between turns here (+ between
/// SSE frames inside a streaming transport) for a true mid-turn abort. The wrapper
/// above passes a discarding sink + a never-set cancel, so non-streaming callers are
/// byte-identical. NEVER touches funds/wallet/chain (PD-6; the loop is read-only).
#[allow(clippy::too_many_arguments)]
pub fn run_agent_loop_streaming(
    transport: &mut dyn AgentTransport,
    state: &MemoryToolState<'_>,
    system: &str,
    question: &str,
    max_iter_u8: u8,
    token_cap_u32: u32,
    file_policy: Option<&crate::file_context::FileReadPolicy>,
    web_seam: Option<&crate::provider::web_fetch::WebFetchSeam>,
    mcp_seam: Option<&crate::mcp::McpSeam>,
    on_delta: &mut dyn FnMut(&str),
    cancel: &std::sync::atomic::AtomicBool,
) -> AgentLoopOutcome {
    let tool_loop = ToolLoop::with_max_iter(max_iter_u8);
    // ENDGAME E1 / PD-3: recall is a READ — mint the always-granted READ
    // witness ONCE and present it to every recall executor. READ is free (no
    // approval / grant / witness; reads are not side effects), but typing it
    // forbids substituting an egress/mutate/approval token on the recall path
    // (PD-2, E0d — READ can never be widened into egress/mutate, by the type
    // system). The model never sees this token; it gates nothing — it TYPES.
    let read = ReadCapability::granted();
    let mut budget = DailyTokenBudget::new(token_cap_u32);
    // P2-1 AUTO-COST: the m-agent CostLedger (atom #27) records every turn
    // that crossed the wire. PriceTable::default() is the ZERO-RATE sentinel
    // — token counters climb while `usd_micros` stays 0 until an operator
    // wires real rates (an honest unconfigured state, never silent default
    // pricing; OpenRouter per-model rates live on its dashboard).
    let mut ledger = CostLedger::new();
    let price = PriceTable::default();
    // P2-1 cache visibility: the plan splits the request into the byte-stable
    // static prefix (the system prompt, constant across the loop) and the
    // per-turn dynamic suffix (the user message); the stability counter
    // MEASURES whether each turn's user message extends the previous one as
    // a strict prefix — the property a provider-side prefix cache keys on.
    let mut cache_plan =
        plan_cache_breakpoints(u32::try_from(system.len()).unwrap_or(u32::MAX), 0, 0, 1);
    let mut prefix_stable_turns_u8: u8 = 0;
    let mut prev_user_message: Option<String> = None;
    let mut trail: Vec<String> = Vec::new();
    let mut results: Vec<String> = Vec::new();
    let mut iterations_u8: u8 = 0;
    let mut reads_u8: u8 = 0;
    let mut input_tokens_u64: u64 = 0;
    let mut output_tokens_u64: u64 = 0;
    // P2-2 AUTO-DRIFT (roadmap §2): the in-core trajectory-health bitset,
    // fed ONLY by mechanically observed events (no NLP guessing) and folded
    // to a guard action every turn. The model cannot disable it (L7).
    let mut health = TrajectoryHealth::healthy();
    // Tool calls already executed once — a byte-identical repeat is answered
    // from context (SemanticLoop signal) instead of re-executed (CU floor).
    let mut executed_tool_keys: Vec<String> = Vec::new();
    // P3-2 (IV-W2): the executor's OWN verified-read records — the only
    // truth a PROPOSE-EDIT answer may bind to. Repeats dedupe upstream, so
    // a path appears at most once.
    let mut verified_file_reads: Vec<VerifiedFileRead> = Vec::new();

    loop {
        // S-C true cancel: an owner-requested abort between turns ends the loop with a
        // typed Cancelled stop (nothing further runs; no side effect on any path).
        if cancel.load(std::sync::atomic::Ordering::SeqCst) {
            return AgentLoopOutcome {
                answer: None,
                stop: AgentLoopStop::Cancelled,
                iterations_u8,
                reads_u8,
                tool_trail: trail,
                input_tokens_u64,
                output_tokens_u64,
                cost: ledger,
                cache_plan,
                prefix_stable_turns_u8,
                health,
                verified_file_reads,
            };
        }
        if let Some(stop) = tool_loop.check_iter_cap(iterations_u8) {
            return AgentLoopOutcome {
                answer: None,
                stop: AgentLoopStop::from_loop_stop(stop),
                iterations_u8,
                reads_u8,
                tool_trail: trail,
                input_tokens_u64,
                output_tokens_u64,
                cost: ledger,
                cache_plan,
                prefix_stable_turns_u8,
                health,
                verified_file_reads,
            };
        }
        let user_message = build_user_message(question, &results);
        cache_plan = plan_cache_breakpoints(
            u32::try_from(system.len()).unwrap_or(u32::MAX),
            0,
            u32::try_from(user_message.len()).unwrap_or(u32::MAX),
            1,
        );
        if let Some(prev) = &prev_user_message {
            if user_message.starts_with(prev.as_str()) {
                prefix_stable_turns_u8 = prefix_stable_turns_u8.saturating_add(1);
            }
        }
        prev_user_message = Some(user_message.clone());
        let turn = match transport.turn_streaming(system, &user_message, &mut *on_delta, cancel) {
            Ok(turn) => turn,
            Err(error) => {
                trail.push(format!("transport: {}", error.class_label));
                return AgentLoopOutcome {
                    answer: None,
                    stop: AgentLoopStop::TransportFailed,
                    iterations_u8,
                    reads_u8,
                    tool_trail: trail,
                    input_tokens_u64,
                    output_tokens_u64,
                    cost: ledger,
                    cache_plan,
                    prefix_stable_turns_u8,
                    health,
                    verified_file_reads,
                };
            }
        };
        input_tokens_u64 = input_tokens_u64.saturating_add(turn.input_tokens_u64);
        output_tokens_u64 = output_tokens_u64.saturating_add(turn.output_tokens_u64);
        // P2-1: record the turn into the ledger UNCONDITIONALLY — these
        // tokens already crossed the wire (HTTP reality: cost is knowable
        // only after the response), so hiding a budget-refused turn from the
        // ledger would understate real spend. `record` is the infallible
        // saturating m-agent canonical; the cached counter is the provider's
        // own cache-hit report (절감 가시화).
        let usage = TurnUsage {
            prompt_tokens_u32: u32::try_from(turn.input_tokens_u64).unwrap_or(u32::MAX),
            completion_tokens_u32: u32::try_from(turn.output_tokens_u64).unwrap_or(u32::MAX),
            cached_tokens_u32: u32::try_from(turn.cached_tokens_u64).unwrap_or(u32::MAX),
        };
        ledger.record(&usage, &price);
        // Charge-then-continue (m-agent budget law adapted to HTTP reality:
        // a turn's cost is knowable only after the response, so the charge
        // gates every FURTHER turn, and the iteration cap bounds the count).
        // The charge unit (prompt + completion, saturating) is byte-identical
        // to the pre-P2-1 behavior.
        let spent_u32 = u32::try_from(turn.input_tokens_u64.saturating_add(turn.output_tokens_u64))
            .unwrap_or(u32::MAX);
        let budget_exceeded = budget.try_charge(TokenCount::new(spent_u32)).is_err();

        match parse_turn(&turn.answer_text) {
            ParsedTurn::Answer(answer) => {
                // A paid-for final answer is never discarded: budget
                // exhaustion is noted but the completion stands (no further
                // transport call happens either way).
                if budget_exceeded {
                    trail.push("budget-exhausted-at-completion".to_string());
                }
                return AgentLoopOutcome {
                    answer: Some(answer.to_string()),
                    stop: AgentLoopStop::Completed,
                    iterations_u8,
                    reads_u8,
                    tool_trail: trail,
                    input_tokens_u64,
                    output_tokens_u64,
                    cost: ledger,
                    cache_plan,
                    prefix_stable_turns_u8,
                    health,
                    verified_file_reads,
                };
            }
            ParsedTurn::ToolUnknown(line) => {
                // IV6: outside the closed read-only set — denied WITHOUT
                // execution; the loop ends (strictest v1 posture). P2-2: the
                // escalation attempt is ALSO a recorded trajectory signal
                // (lockdown-grade), so the receipt's guard line tells the
                // truth about WHY this run is suspect.
                health.record(TrajectorySignal::ToolEscalation);
                trail.push(format!("denied-tool {}", truncate_char_safe(line, 60)));
                return AgentLoopOutcome {
                    answer: None,
                    stop: AgentLoopStop::ToolDenied,
                    iterations_u8,
                    reads_u8,
                    tool_trail: trail,
                    input_tokens_u64,
                    output_tokens_u64,
                    cost: ledger,
                    cache_plan,
                    prefix_stable_turns_u8,
                    health,
                    verified_file_reads,
                };
            }
            ParsedTurn::ToolIndex
            | ParsedTurn::ToolRead(_)
            | ParsedTurn::ToolFileRead(_)
            | ParsedTurn::ToolWebFetch(_)
            | ParsedTurn::ToolWebSearch(_)
            | ParsedTurn::ToolAuditDetect(_)
            | ParsedTurn::ToolContextIndex(_)
            | ParsedTurn::ToolWalrusIndex
            | ParsedTurn::ToolWalrusFetch(_)
            | ParsedTurn::ToolSkewCapabilities
                if budget_exceeded =>
            {
                return AgentLoopOutcome {
                    answer: None,
                    stop: AgentLoopStop::BudgetExceeded,
                    iterations_u8,
                    reads_u8,
                    tool_trail: trail,
                    input_tokens_u64,
                    output_tokens_u64,
                    cost: ledger,
                    cache_plan,
                    prefix_stable_turns_u8,
                    health,
                    verified_file_reads,
                };
            }
            ParsedTurn::ToolIndex => {
                if executed_tool_keys.iter().any(|key| key == "index") {
                    // P2-2 SemanticLoop: a byte-identical repeat of an
                    // already-answered tool call — recorded, NOT re-executed
                    // (no duplicate work, no duplicate prompt bytes).
                    health.record(TrajectorySignal::SemanticLoop);
                    trail.push("repeat index".to_string());
                    results.push(
                        "memory index: repeated tool call (the result is already above)"
                            .to_string(),
                    );
                } else {
                    executed_tool_keys.push("index".to_string());
                    trail.push("index".to_string());
                    results.push(frontier_index_result(read, state));
                }
            }
            ParsedTurn::ToolRead(id) => {
                let key = format!("read {id}");
                if executed_tool_keys.contains(&key) {
                    health.record(TrajectorySignal::SemanticLoop);
                    trail.push(format!("repeat read {id}"));
                    results.push(format!(
                        "memory read {id}: repeated tool call (the result is already above)"
                    ));
                } else if reads_u8 >= AGENT_LOOP_MAX_READS {
                    // IV5's K — the read wall: counted, denied, loop continues
                    // (the model can still answer from what it has).
                    trail.push(format!("read-cap {id}"));
                    results.push(format!(
                        "memory read {id}: denied (read cap K={AGENT_LOOP_MAX_READS} reached)"
                    ));
                } else {
                    executed_tool_keys.push(key);
                    let result = frontier_read_result(read, state, id);
                    if result.contains("(verified)") {
                        reads_u8 = reads_u8.saturating_add(1);
                        trail.push(format!("read {id}"));
                    } else {
                        trail.push(format!("read-denied {id}"));
                    }
                    results.push(result);
                }
            }
            ParsedTurn::ToolFileRead(path) => {
                // Lane A — file reads share the SAME K-read wall as memory
                // reads (IV5/IV-F3); every gate is the file policy's
                // (IV-F1..F6). The trail carries the path label only.
                let key = format!("file {path}");
                if executed_tool_keys.contains(&key) {
                    health.record(TrajectorySignal::SemanticLoop);
                    trail.push(format!("repeat file {path}"));
                    results.push(format!(
                        "file read {path}: repeated tool call (the result is already above)"
                    ));
                } else if reads_u8 >= AGENT_LOOP_MAX_READS {
                    trail.push("file-read-cap".to_string());
                    results.push(format!(
                        "file read {path}: denied (read cap K={AGENT_LOOP_MAX_READS} reached)"
                    ));
                } else {
                    executed_tool_keys.push(key);
                    let (result, verified) = frontier_file_result(read, file_policy, path);
                    if let Some(read) = verified {
                        reads_u8 = reads_u8.saturating_add(1);
                        trail.push(format!("file {path}"));
                        // P3-2 (IV-W2): record the executor's own truth.
                        verified_file_reads.push(read);
                    } else {
                        trail.push(format!("file-denied {path}"));
                    }
                    results.push(result);
                }
            }
            ParsedTurn::ToolWebFetch(url) => {
                // E11-1b (⑭ IV-WF8): web fetches share the SAME K-read wall as
                // memory / file reads. Every gate is the shared glue's (SSRF wall,
                // redaction, rights/quote/advisory). The trail carries the url
                // label only — never the fetched bytes.
                let key = format!("web {url}");
                if executed_tool_keys.contains(&key) {
                    health.record(TrajectorySignal::SemanticLoop);
                    trail.push(format!("repeat web {url}"));
                    results.push(format!(
                        "web fetch {url}: repeated tool call (the result is already above)"
                    ));
                } else if reads_u8 >= AGENT_LOOP_MAX_READS {
                    trail.push("web-fetch-cap".to_string());
                    results.push(format!(
                        "web fetch {url}: denied (read cap K={AGENT_LOOP_MAX_READS} reached)"
                    ));
                } else {
                    executed_tool_keys.push(key);
                    let (result, consumed) = frontier_web_fetch_result(read, web_seam, url);
                    if consumed {
                        // A VERIFIED advisory surfaced ⇒ consume K (IV-WF8).
                        reads_u8 = reads_u8.saturating_add(1);
                        trail.push(format!("web {url}"));
                    } else {
                        // A deny / withhold / not-compiled never consumes K.
                        trail.push(format!("web-denied {url}"));
                    }
                    results.push(result);
                }
            }
            ParsedTurn::ToolWebSearch(query) => {
                // P3b: a web SEARCH is a web FETCH of the configured search endpoint (the
                // ONE search-URL truth, shared with the `context web-search` verb). Same
                // K-read wall + SSRF wall + redaction glue as web fetch; NO new executor.
                let url = crate::dispatch::build_web_search_url(query);
                let key = format!("web {url}");
                if executed_tool_keys.contains(&key) {
                    health.record(TrajectorySignal::SemanticLoop);
                    trail.push(format!("repeat search {query}"));
                    results.push(format!(
                        "web search {query}: repeated tool call (the result is already above)"
                    ));
                } else if reads_u8 >= AGENT_LOOP_MAX_READS {
                    trail.push("web-search-cap".to_string());
                    results.push(format!(
                        "web search {query}: denied (read cap K={AGENT_LOOP_MAX_READS} reached)"
                    ));
                } else {
                    executed_tool_keys.push(key);
                    let (result, consumed) = frontier_web_fetch_result(read, web_seam, &url);
                    if consumed {
                        // A VERIFIED advisory surfaced ⇒ consume K (shared with web fetch).
                        reads_u8 = reads_u8.saturating_add(1);
                        trail.push(format!("search {query}"));
                    } else {
                        trail.push(format!("search-denied {query}"));
                    }
                    results.push(result);
                }
            }
            ParsedTurn::ToolWalrusIndex => {
                // E14-W2: the agent reads its 2-tier Walrus MAIN INDEX. Shares the K-read
                // wall; the redacted index (id + topic per memory) enters the prompt.
                let key = "walrus-index".to_string();
                if executed_tool_keys.contains(&key) {
                    health.record(TrajectorySignal::SemanticLoop);
                    trail.push("repeat walrus-index".to_string());
                    results.push(
                        "memory walrus-index: repeated tool call (the result is already above)"
                            .to_string(),
                    );
                } else if reads_u8 >= AGENT_LOOP_MAX_READS {
                    trail.push("walrus-index-cap".to_string());
                    results.push(format!(
                        "memory walrus-index: denied (read cap K={AGENT_LOOP_MAX_READS} reached)"
                    ));
                } else {
                    executed_tool_keys.push(key);
                    let (result, consumed) = frontier_walrus_index_result(read);
                    if consumed {
                        reads_u8 = reads_u8.saturating_add(1);
                        trail.push("walrus-index".to_string());
                    } else {
                        trail.push("walrus-index-denied".to_string());
                    }
                    results.push(result);
                }
            }
            ParsedTurn::ToolSkewCapabilities => {
                // K-0a-3: the agent reads the Skew capability catalog (the `skew_catalog`
                // single source of truth) mid-reasoning. Shares the K-read wall; the
                // redact-belted catalog enters the prompt. A pure static READ (money 0);
                // trading is NEVER originated here (a separate owner-armed bounded action).
                let key = "skew-capabilities".to_string();
                if executed_tool_keys.contains(&key) {
                    health.record(TrajectorySignal::SemanticLoop);
                    trail.push("repeat skew-capabilities".to_string());
                    results.push(
                        "skew capabilities: repeated tool call (the result is already above)"
                            .to_string(),
                    );
                } else if reads_u8 >= AGENT_LOOP_MAX_READS {
                    trail.push("skew-capabilities-cap".to_string());
                    results.push(format!(
                        "skew capabilities: denied (read cap K={AGENT_LOOP_MAX_READS} reached)"
                    ));
                } else {
                    executed_tool_keys.push(key);
                    let (result, consumed) = frontier_skew_capabilities_result(read);
                    if consumed {
                        reads_u8 = reads_u8.saturating_add(1);
                        trail.push("skew-capabilities".to_string());
                    } else {
                        trail.push("skew-capabilities-denied".to_string());
                    }
                    results.push(result);
                }
            }
            ParsedTurn::ToolWalrusFetch(id) => {
                // E14-W2: the agent enters a SUB-STORE; the decrypted detail (redacted)
                // enters the prompt. Shares the K-read wall.
                let key = format!("walrus-fetch {id}");
                if executed_tool_keys.contains(&key) {
                    health.record(TrajectorySignal::SemanticLoop);
                    trail.push(format!("repeat walrus-fetch {id}"));
                    results.push(format!(
                        "memory walrus-fetch {id}: repeated tool call (the result is already above)"
                    ));
                } else if reads_u8 >= AGENT_LOOP_MAX_READS {
                    trail.push("walrus-fetch-cap".to_string());
                    results.push(format!(
                        "memory walrus-fetch {id}: denied (read cap K={AGENT_LOOP_MAX_READS} reached)"
                    ));
                } else {
                    executed_tool_keys.push(key);
                    let (result, consumed) = frontier_walrus_fetch_result(read, id, question);
                    if consumed {
                        reads_u8 = reads_u8.saturating_add(1);
                        trail.push(format!("walrus-fetch {id}"));
                    } else {
                        trail.push(format!("walrus-fetch-denied {id}"));
                    }
                    results.push(result);
                }
            }
            ParsedTurn::ToolAuditDetect(path) => {
                // E11-2 (⑮ IV-AE6): an audit detect shares the SAME K-read wall as
                // memory / file / web reads. It is a pure metadata-only READ
                // (counts + hashed anchors + static rule labels — no raw source
                // byte); the agent can PROPOSE it but CANNOT promote a candidate or
                // run a repro (the owner-gated, kernel-sandboxed chokepoint; the
                // grammar stays closed, PD-1). The trail carries the path only.
                let key = format!("audit {path}");
                if executed_tool_keys.contains(&key) {
                    health.record(TrajectorySignal::SemanticLoop);
                    trail.push(format!("repeat audit {path}"));
                    results.push(format!(
                        "audit detect {path}: repeated tool call (the result is already above)"
                    ));
                } else if reads_u8 >= AGENT_LOOP_MAX_READS {
                    trail.push("audit-detect-cap".to_string());
                    results.push(format!(
                        "audit detect {path}: denied (read cap K={AGENT_LOOP_MAX_READS} reached)"
                    ));
                } else {
                    executed_tool_keys.push(key);
                    let (result, consumed) = frontier_audit_detect_result(read, path);
                    if consumed {
                        reads_u8 = reads_u8.saturating_add(1);
                        trail.push(format!("audit {path}"));
                    } else {
                        trail.push(format!("audit-denied {path}"));
                    }
                    results.push(result);
                }
            }
            ParsedTurn::ToolContextIndex(path) => {
                // E11-4-2: the project context index shares the SAME K-read wall as
                // memory / file / web / audit reads. It is a content-free PROJECT
                // enumeration (rel-paths + kinds + sizes — NEVER file CONTENT;
                // IV-F8..F11). A bare `context index` lists the registered roots; a
                // path indexes that subtree. The agent can enumerate but CANNOT read
                // CONTENT via this tool or widen it into a write (grammar stays
                // closed, PD-1). The trail carries the path label only (empty=roots).
                let key = format!("ctxindex {path}");
                if executed_tool_keys.contains(&key) {
                    health.record(TrajectorySignal::SemanticLoop);
                    trail.push(format!("repeat ctxindex {path}"));
                    results.push(format!(
                        "context index {path}: repeated tool call (the result is already above)"
                    ));
                } else if reads_u8 >= AGENT_LOOP_MAX_READS {
                    trail.push("context-index-cap".to_string());
                    results.push(format!(
                        "context index {path}: denied (read cap K={AGENT_LOOP_MAX_READS} reached)"
                    ));
                } else {
                    executed_tool_keys.push(key);
                    let (result, consumed) = frontier_context_index_result(read, path);
                    if consumed {
                        reads_u8 = reads_u8.saturating_add(1);
                        trail.push(format!("ctxindex {path}"));
                    } else {
                        trail.push(format!("ctxindex-denied {path}"));
                    }
                    results.push(result);
                }
            }
            ParsedTurn::ToolLspDiagnostics(path) => {
                // A① (CURSOR PARITY keystone-1): `lsp diagnostics <path>` shares
                // the SAME K-read wall as the memory / file / web / audit /
                // context reads. It runs the REAL language server
                // (rust-analyzer / move-analyzer) SANDBOXED (network + write
                // kernel-DENIED) and reports COMPILER TRUTH (AXIS-2 / P-HALL
                // anti-hallucination); the agent reasons with the compiler's
                // verdict but writes / execs NOTHING through it (grammar stays
                // closed, PD-1). The render is redact-belted (SI-2). The trail
                // carries the path only.
                let key = format!("lsp {path}");
                if executed_tool_keys.contains(&key) {
                    health.record(TrajectorySignal::SemanticLoop);
                    trail.push(format!("repeat lsp {path}"));
                    results.push(format!(
                        "lsp diagnostics {path}: repeated tool call (the result is already above)"
                    ));
                } else if reads_u8 >= AGENT_LOOP_MAX_READS {
                    trail.push("lsp-diagnostics-cap".to_string());
                    results.push(format!(
                        "lsp diagnostics {path}: denied (read cap K={AGENT_LOOP_MAX_READS} reached)"
                    ));
                } else {
                    executed_tool_keys.push(key);
                    let (result, consumed) = frontier_lsp_diagnostics_result(read, path);
                    if consumed {
                        reads_u8 = reads_u8.saturating_add(1);
                        trail.push(format!("lsp {path}"));
                    } else {
                        trail.push(format!("lsp-denied {path}"));
                    }
                    results.push(result);
                }
            }
            ParsedTurn::ToolMcp(server, tool, args) => {
                // B⑫ (CURSOR PARITY keystone-3): `mcp <server> <tool> [args]`
                // shares the SAME K-read wall as the memory / file / web / audit /
                // context / lsp reads. It calls a READ-class tool on an owner-
                // configured LOCAL stdio MCP server through the shared chokepoint
                // (wall → redact ARG → sandboxed tools/call, network kernel-DENIED
                // → redact RESULT → audit); the agent READS the tool result but
                // writes / execs NOTHING through it (v1 read-only, grammar closed,
                // PD-1). The render is redact-belted (SI-2). The trail carries the
                // server / tool labels only — never the result bytes.
                let key = format!("mcp {server} {tool} {args}");
                if executed_tool_keys.contains(&key) {
                    health.record(TrajectorySignal::SemanticLoop);
                    trail.push(format!("repeat mcp {server}/{tool}"));
                    results.push(format!(
                        "mcp {server}/{tool}: repeated tool call (the result is already above)"
                    ));
                } else if reads_u8 >= AGENT_LOOP_MAX_READS {
                    trail.push("mcp-cap".to_string());
                    results.push(format!(
                        "mcp {server}/{tool}: denied (read cap K={AGENT_LOOP_MAX_READS} reached)"
                    ));
                } else {
                    executed_tool_keys.push(key);
                    let (result, consumed) =
                        frontier_mcp_call_result(read, mcp_seam, server, tool, args);
                    if consumed {
                        reads_u8 = reads_u8.saturating_add(1);
                        trail.push(format!("mcp {server}/{tool}"));
                    } else {
                        trail.push(format!("mcp-denied {server}/{tool}"));
                    }
                    results.push(result);
                }
            }
            ParsedTurn::ToolGit(subcommand, args) => {
                // A⑤ (CURSOR PARITY git-as-capability-type): `git <subcommand>
                // [args]` shares the SAME K-read wall as the memory / file / web /
                // audit / context / lsp / mcp reads. It runs a READ-only git
                // subcommand on the local repo SANDBOXED (network + write
                // kernel-DENIED); the agent READS the repo but writes / pushes
                // NOTHING through it (v1 read-only; commit/branch/push are an
                // owner-armed v2 — grammar closed, PD-1). The render is redact-belted
                // (SI-2). The trail carries the subcommand label only.
                let key = format!("git {subcommand} {args}");
                if executed_tool_keys.contains(&key) {
                    health.record(TrajectorySignal::SemanticLoop);
                    trail.push(format!("repeat git {subcommand}"));
                    results.push(format!(
                        "git {subcommand}: repeated tool call (the result is already above)"
                    ));
                } else if reads_u8 >= AGENT_LOOP_MAX_READS {
                    trail.push("git-cap".to_string());
                    results.push(format!(
                        "git {subcommand}: denied (read cap K={AGENT_LOOP_MAX_READS} reached)"
                    ));
                } else {
                    executed_tool_keys.push(key);
                    let (result, consumed) = frontier_git_result(read, subcommand, args);
                    if consumed {
                        reads_u8 = reads_u8.saturating_add(1);
                        trail.push(format!("git {subcommand}"));
                    } else {
                        trail.push(format!("git-denied {subcommand}"));
                    }
                    results.push(result);
                }
            }
            ParsedTurn::ToolTestRun(pkg) => {
                // A② (CURSOR PARITY oracle test-loop): `test run <pkg>` shares the
                // SAME K-read wall as the other reads. It runs the REAL test runner
                // (`sui move test` / `cargo test`) on a workspace package SANDBOXED
                // (network kernel-DENIED, write-allowed for build artifacts) and
                // surfaces the pass/fail verdict — COMPILER/TEST truth (AXIS-2 /
                // P-HALL); the agent reasons about a fix but execs NOTHING beyond the
                // sandboxed test (grammar closed, PD-1). The render is redact-belted
                // (SI-2). The trail carries the package label only.
                let key = format!("test {pkg}");
                if executed_tool_keys.contains(&key) {
                    health.record(TrajectorySignal::SemanticLoop);
                    trail.push(format!("repeat test {pkg}"));
                    results.push(format!(
                        "test run {pkg}: repeated tool call (the result is already above)"
                    ));
                } else if reads_u8 >= AGENT_LOOP_MAX_READS {
                    trail.push("test-run-cap".to_string());
                    results.push(format!(
                        "test run {pkg}: denied (read cap K={AGENT_LOOP_MAX_READS} reached)"
                    ));
                } else {
                    executed_tool_keys.push(key);
                    let (result, consumed) = frontier_test_run_result(read, pkg);
                    if consumed {
                        reads_u8 = reads_u8.saturating_add(1);
                        trail.push(format!("test {pkg}"));
                    } else {
                        trail.push(format!("test-denied {pkg}"));
                    }
                    results.push(result);
                }
            }
            ParsedTurn::ToolSearch(pattern) => {
                // A④-rg (CURSOR PARITY find-in-files): `search <regex>` shares the
                // SAME K-read wall as the other reads. It runs a linear-time REGEX
                // over the workspace source (NO subprocess, NO network, NO write —
                // a pure in-Rust READ; each file passes the proven file-context wall
                // = under-root + denylist + size cap + UTF-8, and each matching line
                // passes the redact() wall). The agent LOCATES code by pattern but
                // writes NOTHING (grammar closed, PD-1). The trail carries a fixed
                // `search` label only — never the pattern or the matched bytes.
                let key = format!("search {pattern}");
                if executed_tool_keys.contains(&key) {
                    health.record(TrajectorySignal::SemanticLoop);
                    trail.push("repeat search".to_string());
                    results.push(
                        "search: repeated tool call (the result is already above)".to_string(),
                    );
                } else if reads_u8 >= AGENT_LOOP_MAX_READS {
                    trail.push("search-cap".to_string());
                    results.push(format!(
                        "search: denied (read cap K={AGENT_LOOP_MAX_READS} reached)"
                    ));
                } else {
                    executed_tool_keys.push(key);
                    let (result, consumed) = frontier_search_result(read, pattern);
                    if consumed {
                        reads_u8 = reads_u8.saturating_add(1);
                        trail.push("search".to_string());
                    } else {
                        trail.push("search-denied".to_string());
                    }
                    results.push(result);
                }
            }
            ParsedTurn::ToolCodebase(query) => {
                // [4] B⑨ semantic index: `codebase <query>` shares the SAME K-read wall.
                // It retrieves the top-K relevant chunks from the LOCAL encrypted index
                // (local embeddings — NO network, NO subprocess, NO write; each surfaced
                // chunk passes the redact() wall). The trail carries a fixed `codebase`
                // label only — never the query or the chunk bytes.
                let key = format!("codebase {query}");
                if executed_tool_keys.contains(&key) {
                    health.record(TrajectorySignal::SemanticLoop);
                    trail.push("repeat codebase".to_string());
                    results.push(
                        "codebase: repeated tool call (the result is already above)".to_string(),
                    );
                } else if reads_u8 >= AGENT_LOOP_MAX_READS {
                    trail.push("codebase-cap".to_string());
                    results.push(format!(
                        "codebase: denied (read cap K={AGENT_LOOP_MAX_READS} reached)"
                    ));
                } else {
                    executed_tool_keys.push(key);
                    let (result, consumed) = frontier_codebase_result(read, query);
                    if consumed {
                        reads_u8 = reads_u8.saturating_add(1);
                        trail.push("codebase".to_string());
                    } else {
                        trail.push("codebase-denied".to_string());
                    }
                    results.push(result);
                }
            }
        }
        // P2-2: fold the turn's mechanically observed wall outcomes into the
        // health bitset. The markers are the walls' OWN typed labels (the
        // same strings the K-read counter already keys on).
        if let Some(last) = results.last() {
            if last.contains("withheld (secret-shaped)") {
                // The model steered a read into secret-shaped content.
                health.record(TrajectorySignal::SecretTouch);
            }
            if last.contains("_mismatch)") {
                // An integrity-class denial (content/summary/blob-id hash
                // mismatch) is a claim↔evidence problem — audit-grade.
                health.record(TrajectorySignal::EvidenceMismatch);
            }
        }
        iterations_u8 = iterations_u8.saturating_add(1);
        // P2-2: fold the bitset to its most severe guard action. LOCKDOWN
        // ends the loop BEFORE any further egress turn (in-core, L7 — the
        // model cannot disable it); Slow/Audit stay visible in the receipt
        // (the action re-derives from `health`, never stored twice).
        if recommended_action(health) == GuardAction::Lockdown {
            trail.push("guard-lockdown".to_string());
            return AgentLoopOutcome {
                answer: None,
                stop: AgentLoopStop::GuardLockdown,
                iterations_u8,
                reads_u8,
                tool_trail: trail,
                input_tokens_u64,
                output_tokens_u64,
                cost: ledger,
                cache_plan,
                prefix_stable_turns_u8,
                health,
                verified_file_reads,
            };
        }
    }
}

// ===========================================================================
// 7. Subagent fan-out (roadmap §3.A; SUBAGENT_FANOUT_THREAT_MODEL.md)
// ===========================================================================
//
// Operator-initiated v1 (TM D-1): the MODEL has no spawn tool — the closed
// loop grammar is byte-unchanged. Each child = one `run_agent_loop_with`
// instance with its OWN transport + its OWN partitioned budget slice (TM
// D-2/D-4); children share only the read-only `MemoryToolState`. The live
// binding runs children in scoped threads; THIS layer owns the bounds and
// the DETERMINISTIC merge (by child index, never completion order — TM D-5).

/// Live-surface bound on children per fan (≤ m-agent
/// [`MAX_SUBAGENT_CHILDREN`](mnemos_m_agent::MAX_SUBAGENT_CHILDREN); TM D-3).
pub const FANOUT_MAX_CHILDREN: u8 = 4;

/// Per-child iteration cap (below the single loop's
/// [`AGENT_LOOP_MAX_ITER`]; total live calls ≤ children × this — TM D-3).
pub const FANOUT_CHILD_MAX_ITER: u8 = 3;

/// One child's slot in the merged result.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ChildResult {
    /// The child's spawn index (the merge key — TM D-5).
    pub child_index_u8: u8,
    /// The child's full loop receipt.
    pub outcome: AgentLoopOutcome,
}

/// The merged fan receipt: children ALWAYS ordered by index, plus totals.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FanoutOutcome {
    /// Per-child results, sorted by `child_index_u8` (deterministic).
    pub children: Vec<ChildResult>,
    /// Children that produced a final answer.
    pub completed_u8: u8,
    /// Children that stopped without an answer (typed stop in their slot).
    pub failed_u8: u8,
    /// Σ prompt tokens across children.
    pub input_tokens_u64: u64,
    /// Σ completion tokens across children.
    pub output_tokens_u64: u64,
}

/// Run ONE fan child: the same gated loop core with the fan's tighter
/// iteration cap and the child's partitioned token slice (TM D-2/D-3/D-7 —
/// every frontier wall is the single loop's, unchanged).
pub fn run_fanout_child(
    transport: &mut dyn AgentTransport,
    state: &MemoryToolState<'_>,
    system: &str,
    question: &str,
    child_token_cap_u32: u32,
) -> AgentLoopOutcome {
    run_agent_loop_with(
        transport,
        state,
        system,
        question,
        FANOUT_CHILD_MAX_ITER,
        child_token_cap_u32,
        // v1 fan children are memory-only; file context is a single-loop
        // capability for now (a fan child reading files is a later slice).
        None,
        // E11-1b: web fetch is likewise a single-loop capability in v1 — a fan
        // child reaching the public web is a later slice (parallel to file
        // context). `None` ⇒ the child's `web fetch` is the honest not-compiled
        // deny.
        None,
        // B⑫: MCP is likewise a single-loop capability in v1 — `None` ⇒ a fan
        // child's `mcp` tool is the honest "no MCP server configured" deny.
        None,
    )
}

/// Merge child results BY CHILD INDEX — never completion order (TM D-5):
/// the same inputs yield the same merged output regardless of parallel
/// timing. Totals saturate; counts are bounded by [`FANOUT_MAX_CHILDREN`].
#[must_use]
pub fn merge_fanout(mut results: Vec<ChildResult>) -> FanoutOutcome {
    results.sort_by_key(|result| result.child_index_u8);
    let mut completed_u8: u8 = 0;
    let mut failed_u8: u8 = 0;
    let mut input_tokens_u64: u64 = 0;
    let mut output_tokens_u64: u64 = 0;
    for result in &results {
        if result.outcome.answer.is_some() {
            completed_u8 = completed_u8.saturating_add(1);
        } else {
            failed_u8 = failed_u8.saturating_add(1);
        }
        input_tokens_u64 = input_tokens_u64.saturating_add(result.outcome.input_tokens_u64);
        output_tokens_u64 = output_tokens_u64.saturating_add(result.outcome.output_tokens_u64);
    }
    FanoutOutcome {
        children: results,
        completed_u8,
        failed_u8,
        input_tokens_u64,
        output_tokens_u64,
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use super::*;
    use mnemos_b_memory::MemoryTier;

    struct ScriptedTransport {
        replies: Vec<&'static str>,
        calls: usize,
        user_messages: Vec<String>,
        tokens_per_turn: (u64, u64),
    }

    impl ScriptedTransport {
        fn new(replies: Vec<&'static str>) -> Self {
            Self {
                replies,
                calls: 0,
                user_messages: Vec::new(),
                tokens_per_turn: (100, 50),
            }
        }
    }

    impl AgentTransport for ScriptedTransport {
        fn turn(
            &mut self,
            _system: &str,
            user_message: &str,
        ) -> Result<AgentTurn, AgentTransportError> {
            self.user_messages.push(user_message.to_string());
            let reply = self
                .replies
                .get(self.calls)
                .copied()
                .unwrap_or("ANSWER: out");
            self.calls += 1;
            Ok(AgentTurn {
                answer_text: reply.to_string(),
                input_tokens_u64: self.tokens_per_turn.0,
                output_tokens_u64: self.tokens_per_turn.1,
                cached_tokens_u64: 0,
            })
        }
    }

    fn record(id: u64, content: &[u8], tier: MemoryTier, private: bool) -> MemoryIndexRecord {
        MemoryIndexRecord::from_content(MemoryId::new(id), content, 100, tier, private)
            .expect("valid record")
    }

    const SHAREABLE: &[u8] = "the owner ships sinabro 1.0 \u{b0b4}\u{c77c}".as_bytes();
    const PRIVATE: &[u8] = b"private medical note";

    fn fixture_records() -> [MemoryIndexRecord; 3] {
        [
            record(1, SHAREABLE, MemoryTier::Recent, false),
            record(2, PRIVATE, MemoryTier::Recent, true),
            record(3, b"deleted body", MemoryTier::DeletedTombstone, false),
        ]
    }

    /// Happy path: index → read 1 → answer. Asserts the LOOP receipt AND the
    /// IV2 wall inside the ACTUAL prompts: the frontier index result lists
    /// only the shareable record, and the verified content reaches the next
    /// user message.
    #[test]
    fn loop_index_read_answer_completes() {
        let records = fixture_records();
        let contents: [(MemoryId, &[u8]); 2] =
            [(MemoryId::new(1), SHAREABLE), (MemoryId::new(2), PRIVATE)];
        let policy = TombstonePolicy::new();
        let state = MemoryToolState {
            records: &records,
            contents: &contents,
            policy: &policy,
        };
        let mut transport = ScriptedTransport::new(vec![
            "TOOL: memory index",
            "TOOL: memory read 1",
            "ANSWER: done — used memory 1",
        ]);
        let outcome = run_agent_loop(&mut transport, &state, "system", "what ships tomorrow?");

        assert_eq!(outcome.stop, AgentLoopStop::Completed);
        assert_eq!(outcome.answer.as_deref(), Some("done — used memory 1"));
        assert_eq!(outcome.iterations_u8, 2);
        assert_eq!(outcome.reads_u8, 1);
        assert_eq!(outcome.tool_trail, ["index", "read 1"]);
        assert_eq!(outcome.input_tokens_u64, 300);
        assert_eq!(outcome.output_tokens_u64, 150);
        assert_eq!(transport.calls, 3);

        // IV2 in the actual prompt: the index tool result (user message 2)
        // lists ONLY the shareable record — no private id, no private summary.
        let msg2 = &transport.user_messages[1];
        assert!(msg2.contains("1 shareable records"));
        assert!(msg2.contains("id=1"));
        assert!(!msg2.contains("id=2"), "private record never listed");
        assert!(!msg2.contains("medical"), "private summary never leaks");
        assert!(!msg2.contains("id=3"), "tombstone never listed");

        // The verified read content reaches user message 3.
        let msg3 = &transport.user_messages[2];
        assert!(msg3.contains("memory read 1 (verified)"));
        assert!(msg3.contains("sinabro 1.0"));
    }

    // ── S-C streaming + true cancel (additive; the non-streaming path is untouched) ──

    fn empty_state_policy() -> TombstonePolicy {
        TombstonePolicy::new()
    }

    #[test]
    fn turn_streaming_default_emits_whole_answer_once() {
        // A plain (non-streaming) transport gets the DEFAULT turn_streaming: it runs
        // `turn` then emits the whole answer once — every existing transport keeps working.
        let mut t = FnTransport(|_s: &str, _u: &str| {
            Ok(AgentTurn {
                answer_text: "hello world".to_string(),
                input_tokens_u64: 1,
                output_tokens_u64: 2,
                cached_tokens_u64: 0,
            })
        });
        let mut pieces: Vec<String> = Vec::new();
        let never = std::sync::atomic::AtomicBool::new(false);
        let turn = t
            .turn_streaming("s", "u", &mut |d| pieces.push(d.to_string()), &never)
            .unwrap();
        assert_eq!(turn.answer_text, "hello world");
        assert_eq!(
            pieces,
            vec!["hello world".to_string()],
            "default emits once"
        );
    }

    #[test]
    fn streaming_fn_transport_forwards_deltas_and_delegates_turn() {
        let mut t = StreamingFnTransport(
            |_s: &str,
             _u: &str,
             on_delta: &mut dyn FnMut(&str),
             _c: &std::sync::atomic::AtomicBool| {
                for piece in ["a", "b", "c"] {
                    on_delta(piece);
                }
                Ok(AgentTurn {
                    answer_text: "abc".to_string(),
                    input_tokens_u64: 0,
                    output_tokens_u64: 3,
                    cached_tokens_u64: 0,
                })
            },
        );
        let mut pieces: Vec<String> = Vec::new();
        let never = std::sync::atomic::AtomicBool::new(false);
        let turn = t
            .turn_streaming("s", "u", &mut |d| pieces.push(d.to_string()), &never)
            .unwrap();
        assert_eq!(turn.answer_text, "abc");
        assert_eq!(pieces, vec!["a", "b", "c"], "deltas forwarded in order");
        // The non-streaming turn still works (delegates with a discarding sink).
        assert_eq!(t.turn("s", "u").unwrap().answer_text, "abc");
    }

    #[test]
    fn run_agent_loop_streaming_forwards_answer_delta() {
        let records: [MemoryIndexRecord; 0] = [];
        let contents: [(MemoryId, &[u8]); 0] = [];
        let policy = empty_state_policy();
        let state = MemoryToolState {
            records: &records,
            contents: &contents,
            policy: &policy,
        };
        let mut t = StreamingFnTransport(
            |_s: &str,
             _u: &str,
             on_delta: &mut dyn FnMut(&str),
             _c: &std::sync::atomic::AtomicBool| {
                on_delta("ANSWER: ");
                on_delta("hi there");
                Ok(AgentTurn {
                    answer_text: "ANSWER: hi there".to_string(),
                    input_tokens_u64: 1,
                    output_tokens_u64: 1,
                    cached_tokens_u64: 0,
                })
            },
        );
        let mut pieces: Vec<String> = Vec::new();
        let never = std::sync::atomic::AtomicBool::new(false);
        let outcome = run_agent_loop_streaming(
            &mut t,
            &state,
            "sys",
            "q",
            AGENT_LOOP_MAX_ITER,
            AGENT_LOOP_TOKEN_CAP,
            None,
            None,
            None,
            &mut |d| pieces.push(d.to_string()),
            &never,
        );
        assert_eq!(outcome.stop, AgentLoopStop::Completed);
        assert_eq!(outcome.answer.as_deref(), Some("hi there"));
        assert_eq!(
            pieces.concat(),
            "ANSWER: hi there",
            "the streamed deltas reached the sink in order"
        );
    }

    #[test]
    fn run_agent_loop_streaming_cancel_stops_before_any_turn() {
        let records: [MemoryIndexRecord; 0] = [];
        let contents: [(MemoryId, &[u8]); 0] = [];
        let policy = empty_state_policy();
        let state = MemoryToolState {
            records: &records,
            contents: &contents,
            policy: &policy,
        };
        let calls = std::sync::atomic::AtomicUsize::new(0);
        let mut t = StreamingFnTransport(
            |_s: &str, _u: &str, _on: &mut dyn FnMut(&str), _c: &std::sync::atomic::AtomicBool| {
                calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                Ok(AgentTurn {
                    answer_text: "ANSWER: x".to_string(),
                    input_tokens_u64: 0,
                    output_tokens_u64: 0,
                    cached_tokens_u64: 0,
                })
            },
        );
        let cancel = std::sync::atomic::AtomicBool::new(true); // already cancelled
        let outcome = run_agent_loop_streaming(
            &mut t,
            &state,
            "sys",
            "q",
            AGENT_LOOP_MAX_ITER,
            AGENT_LOOP_TOKEN_CAP,
            None,
            None,
            None,
            &mut |_| {},
            &cancel,
        );
        assert_eq!(outcome.stop, AgentLoopStop::Cancelled);
        assert!(outcome.answer.is_none());
        assert_eq!(
            calls.load(std::sync::atomic::Ordering::SeqCst),
            0,
            "cancel stops the loop before any transport turn"
        );
    }

    #[test]
    fn cancel_token_clone_shares_flag() {
        let token = CancelToken::new();
        let clone = token.clone();
        assert!(!token.is_cancelled());
        clone.cancel();
        assert!(
            token.is_cancelled(),
            "a clone shares the flag (GUI sets, codec reads)"
        );
        assert!(clone.flag().load(std::sync::atomic::Ordering::SeqCst));
    }

    /// IV6: a proposed tool outside the closed read-only set is denied
    /// WITHOUT execution and ends the loop.
    #[test]
    fn unknown_tool_is_denied_without_execution() {
        let records = fixture_records();
        let contents: [(MemoryId, &[u8]); 0] = [];
        let policy = TombstonePolicy::new();
        let state = MemoryToolState {
            records: &records,
            contents: &contents,
            policy: &policy,
        };
        for proposal in [
            "TOOL: memory delete 1",
            "TOOL: wallet sign",
            "TOOL: tool run x",
            // P3-1 (IV-E1): the owner-side exec verb — and its exact
            // ceremony phrase — buys the MODEL nothing; the closed loop
            // grammar denies it without execution.
            "TOOL: exec run /bin/sh",
            "TOOL: tool run exec-local-owner-live /bin/sh",
            // P3-2 (IV-W1): no write/propose/apply tool exists in the loop
            // grammar — the owner-side apply verb AND its exact ceremony
            // phrase buy the MODEL nothing (propose rides the ANSWER
            // channel only; apply is owner-typed dispatch only).
            "TOOL: file write notes.txt",
            "TOOL: file propose notes.txt",
            "TOOL: file apply 0123456789abcdef",
            "TOOL: tool apply file-apply-owner-live 0123456789abcdef",
            // P3-3 (⑧ IV-L6): the owner-side LOCAL consult ceremony — and
            // its exact phrase — buy the MODEL nothing; a model cannot
            // self-route to a local endpoint or recurse into a consult.
            "TOOL: provider consult consult-local-naite-live q",
            "TOOL: provider consult consult-frontier-provider-live q",
            // P4-3 (VM-selector, L8): the owner-side runtime/model SELECTION
            // verb is NOT a loop tool — a model cannot self-select its runtime
            // or model id (the RD-49 auto-router stays unwired). Grammar
            // byte-unchanged ⇒ `model use …` parses ToolUnknown ⇒ denied.
            "TOOL: model use frontier deepseek/deepseek-chat",
            "TOOL: model use local 8000 llama3.2",
            // E11-1b (⑭ IV-WF10): the model gets `web fetch <url>` ONLY — it
            // cannot POST, set a header, or widen the verb. `web post` and a bare
            // `web fetch` (no url) parse ToolUnknown ⇒ denied + ToolEscalation.
            "TOOL: web post https://evil.test/x",
            "TOOL: web fetch",
            "TOOL: web delete https://evil.test/x",
            // E11-2 (⑮ IV-AE6): the agent gets `audit detect <path>` ONLY — it
            // cannot promote a candidate or run a repro. `audit promote`, `audit
            // run`, and a bare `audit detect` (no path) parse ToolUnknown ⇒ denied
            // + ToolEscalation (the verify-before-expose chokepoint is owner-gated).
            "TOOL: audit promote node-hash",
            "TOOL: audit run repro-command",
            "TOOL: audit detect",
        ] {
            let mut transport = ScriptedTransport::new(vec![proposal]);
            let outcome = run_agent_loop(&mut transport, &state, "s", "q");
            assert_eq!(outcome.stop, AgentLoopStop::ToolDenied, "{proposal}");
            assert_eq!(outcome.answer, None);
            assert_eq!(outcome.reads_u8, 0);
            assert_eq!(transport.calls, 1, "no further turns after denial");
            assert!(outcome.tool_trail[0].starts_with("denied-tool"));
            // P2-2: the escalation attempt is a recorded lockdown-grade
            // signal (the stop stays ToolDenied — same end, truthful guard).
            assert_eq!(recommended_action(outcome.health), GuardAction::Lockdown);
        }
    }

    /// E11-1b (⑭): `TOOL: web fetch <url>` is a RECOGNIZED read tool — it does NOT
    /// end the loop (unlike a denied tool). The SSRF wall + the not-compiled deny
    /// are the shared glue's; a deny / not-compiled NEVER consumes K (IV-WF8) and
    /// the loop CONTINUES so the model can still answer. In this default test build
    /// the seam has no transport ⇒ a wall-passing url is the honest "web transport
    /// not compiled"; an http url is denied by the wall BEFORE any transport
    /// question (so NO network is touched in this test).
    #[test]
    fn web_fetch_tool_is_gated_continues_and_never_consumes_k_on_deny() {
        let records = fixture_records();
        let contents: [(MemoryId, &[u8]); 0] = [];
        let policy = TombstonePolicy::new();
        let state = MemoryToolState {
            records: &records,
            contents: &contents,
            policy: &policy,
        };
        // An INERT seam — no transport in ANY build, so this test is hermetic
        // (never a live socket) regardless of the `web-egress` feature.
        let web_seam = crate::provider::web_fetch::WebFetchSeam::inert();
        assert!(
            web_seam.port().is_none(),
            "an inert seam never has a transport"
        );

        let replies = std::cell::RefCell::new(vec![
            "TOOL: web fetch http://docs.rs/".to_string(), // wall deny (not_https)
            "TOOL: web fetch https://docs.rs/".to_string(), // not compiled (no socket)
            "ANSWER: done".to_string(),
        ]);
        let user_msgs = std::cell::RefCell::new(Vec::<String>::new());
        let mut transport = FnTransport(|_s: &str, user: &str| {
            user_msgs.borrow_mut().push(user.to_string());
            let next = replies.borrow_mut().remove(0);
            Ok(AgentTurn {
                answer_text: next,
                input_tokens_u64: 10,
                output_tokens_u64: 5,
                cached_tokens_u64: 0,
            })
        });
        let outcome = run_agent_loop_with(
            &mut transport,
            &state,
            "sys",
            "what is serde?",
            AGENT_LOOP_MAX_ITER,
            AGENT_LOOP_TOKEN_CAP,
            None,
            Some(&web_seam),
            None,
        );
        // The loop CONTINUES through both web denies and completes on ANSWER.
        assert_eq!(outcome.stop, AgentLoopStop::Completed);
        assert_eq!(outcome.answer.as_deref(), Some("done"));
        // A deny / not-compiled NEVER consumes K (IV-WF8).
        assert_eq!(outcome.reads_u8, 0, "a web deny never consumes a read");
        // Both web outcomes are deny-class trail entries — never a verified `web `.
        assert!(
            outcome.tool_trail.iter().all(|t| !t.starts_with("web ")),
            "{:?}",
            outcome.tool_trail
        );
        assert_eq!(
            outcome
                .tool_trail
                .iter()
                .filter(|t| t.starts_with("web-denied"))
                .count(),
            2
        );
        // The wall fired on the http url BEFORE any transport; the https url hit
        // the honest not-compiled deny. The fetched-content path was never reached.
        let msgs = user_msgs.borrow();
        let joined = msgs.join("\n");
        assert!(joined.contains("web_fetch.url.not_https"), "{joined}");
        assert!(joined.contains("web transport not compiled"), "{joined}");
    }

    /// E11-2 (⑮ IV-AE6): `TOOL: audit detect <path>` is a RECOGNIZED read tool — a
    /// pure metadata-only walk that does NOT end the loop and consumes K like any
    /// read. The agent PROPOSES it; the result carries only counts + a histogram +
    /// "candidate not finding" (never a promotion, a finding, or a raw source byte).
    #[test]
    fn audit_detect_tool_is_gated_read_consumes_k_and_continues() {
        use std::io::Write as _;
        let dir = std::env::temp_dir().join(format!("sinabro_loop_detect_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let _ = std::fs::create_dir_all(dir.join("src"));
        if let Ok(mut f) = std::fs::File::create(dir.join("src/a.rs")) {
            let _ = f.write_all(b"let x = y.unwrap();\nunsafe { z() }\n");
        }
        let records = fixture_records();
        let contents: [(MemoryId, &[u8]); 0] = [];
        let policy = TombstonePolicy::new();
        let state = MemoryToolState {
            records: &records,
            contents: &contents,
            policy: &policy,
        };
        let path = dir.to_string_lossy().to_string();
        let replies = std::cell::RefCell::new(vec![
            format!("TOOL: audit detect {path}"),
            "ANSWER: two candidates, both leads (not findings)".to_string(),
        ]);
        let mut transport = FnTransport(|_s: &str, _user: &str| {
            let next = replies.borrow_mut().remove(0);
            Ok(AgentTurn {
                answer_text: next,
                input_tokens_u64: 10,
                output_tokens_u64: 5,
                cached_tokens_u64: 0,
            })
        });
        let outcome = run_agent_loop_with(
            &mut transport,
            &state,
            "sys",
            "audit my tree",
            AGENT_LOOP_MAX_ITER,
            AGENT_LOOP_TOKEN_CAP,
            None,
            None,
            None,
        );
        // A gated READ: the loop CONTINUES through the detect and completes on ANSWER.
        assert_eq!(outcome.stop, AgentLoopStop::Completed);
        assert_eq!(
            outcome.answer.as_deref(),
            Some("two candidates, both leads (not findings)")
        );
        // An audit detect consumes exactly one K (a real bounded walk ran).
        assert_eq!(outcome.reads_u8, 1, "an audit detect consumes one read");
        assert!(
            outcome.tool_trail.iter().any(|t| t.starts_with("audit ")),
            "{:?}",
            outcome.tool_trail
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// K-0a-3: `TOOL: skew capabilities` is a gated PURE READ — the agent reads the Skew
    /// capability catalog mid-reasoning (consumes one K) and the loop CONTINUES to ANSWER.
    #[test]
    fn skew_capabilities_tool_is_gated_read_consumes_k_and_continues() {
        let records = fixture_records();
        let contents: [(MemoryId, &[u8]); 0] = [];
        let policy = TombstonePolicy::new();
        let state = MemoryToolState {
            records: &records,
            contents: &contents,
            policy: &policy,
        };
        let replies = std::cell::RefCell::new(vec![
            "TOOL: skew capabilities".to_string(),
            "ANSWER: perp, OTC, options, secondary market, permissionless listing".to_string(),
        ]);
        let mut transport = FnTransport(|_s: &str, _user: &str| {
            let next = replies.borrow_mut().remove(0);
            Ok(AgentTurn {
                answer_text: next,
                input_tokens_u64: 10,
                output_tokens_u64: 5,
                cached_tokens_u64: 0,
            })
        });
        let outcome = run_agent_loop_with(
            &mut transport,
            &state,
            "sys",
            "what can you do on skew?",
            AGENT_LOOP_MAX_ITER,
            AGENT_LOOP_TOKEN_CAP,
            None,
            None,
            None,
        );
        assert_eq!(outcome.stop, AgentLoopStop::Completed);
        assert_eq!(
            outcome.reads_u8, 1,
            "a skew capabilities read consumes one K"
        );
        assert!(
            outcome.tool_trail.iter().any(|t| t.starts_with("skew")),
            "{:?}",
            outcome.tool_trail
        );
    }

    /// K-0a-3: `skew capabilities` parses to the READ tool; any OTHER `skew …` (a trade,
    /// a bare `skew`) is NOT a loop tool ⇒ ToolUnknown — the loop READS the Skew surface
    /// but NEVER originates a trade (a separate owner-armed bounded action, K-2).
    #[test]
    fn skew_capabilities_parses_and_other_skew_denied() {
        assert_eq!(
            parse_turn("TOOL: skew capabilities"),
            ParsedTurn::ToolSkewCapabilities
        );
        assert!(matches!(
            parse_turn("TOOL: skew trade BONK 100"),
            ParsedTurn::ToolUnknown(_)
        ));
        assert!(matches!(
            parse_turn("TOOL: skew"),
            ParsedTurn::ToolUnknown(_)
        ));
    }

    /// E11-4-2: `TOOL: context index` (bare) parses to the roots view; a path is
    /// kept case-PRESERVED. DISTINCT from the memory `ToolIndex`.
    #[test]
    fn context_index_parse_bare_and_path_case_preserved() {
        assert_eq!(
            parse_turn("TOOL: context index"),
            ParsedTurn::ToolContextIndex("")
        );
        match parse_turn("TOOL: context index /Proj/SRC") {
            ParsedTurn::ToolContextIndex(p) => assert_eq!(p, "/Proj/SRC"),
            other => panic!("expected ToolContextIndex, got {other:?}"),
        }
        // `memory index` stays the memory tool, not the project context index.
        assert_eq!(parse_turn("TOOL: memory index"), ParsedTurn::ToolIndex);
    }

    /// P3b: `TOOL: web search <query>` parses to ToolWebSearch (query case-preserved),
    /// DISTINCT from `web fetch`; a bare `web search` (no query) falls to ToolUnknown.
    #[test]
    fn web_search_parse_query_case_preserved_distinct_from_fetch() {
        match parse_turn("TOOL: web search Rust BorrowChecker") {
            ParsedTurn::ToolWebSearch(q) => assert_eq!(q, "Rust BorrowChecker"),
            other => panic!("expected ToolWebSearch, got {other:?}"),
        }
        match parse_turn("TOOL: web fetch https://example.com/") {
            ParsedTurn::ToolWebFetch(u) => assert_eq!(u, "https://example.com/"),
            other => panic!("web fetch must stay ToolWebFetch, got {other:?}"),
        }
        match parse_turn("TOOL: web search") {
            ParsedTurn::ToolUnknown(_) => {}
            other => panic!("bare web search must be ToolUnknown, got {other:?}"),
        }
    }

    /// B⑫: `TOOL: mcp <server> <tool> [json-args]` parses to ToolMcp — server +
    /// tool are the first two whitespace tokens (case-PRESERVED), the trailing JSON
    /// object is the args (case-PRESERVED). A bare `mcp` / a missing tool falls to
    /// ToolUnknown (the grammar stays closed, PD-1).
    #[test]
    fn mcp_parse_server_tool_args_and_bare_denied() {
        match parse_turn(r#"TOOL: mcp LocalFS Read_Note {"id":"X"}"#) {
            ParsedTurn::ToolMcp(s, t, a) => {
                assert_eq!(s, "LocalFS");
                assert_eq!(t, "Read_Note");
                assert_eq!(a, r#"{"id":"X"}"#);
            }
            other => panic!("expected ToolMcp, got {other:?}"),
        }
        // Server + tool only (no args) is valid; args default to empty.
        match parse_turn("TOOL: mcp localproof read_motd") {
            ParsedTurn::ToolMcp(s, t, a) => {
                assert_eq!(s, "localproof");
                assert_eq!(t, "read_motd");
                assert_eq!(a, "");
            }
            other => panic!("expected ToolMcp, got {other:?}"),
        }
        // A bare `mcp` / a missing tool ⇒ ToolUnknown (closed grammar).
        for line in ["TOOL: mcp", "TOOL: mcp onlyserver"] {
            match parse_turn(line) {
                ParsedTurn::ToolUnknown(_) => {}
                other => panic!("{line} must be ToolUnknown, got {other:?}"),
            }
        }
    }

    #[test]
    fn codebase_parse_query_and_bare_denied() {
        // [4] B⑨: `TOOL: codebase <query>` parses the query (multi-word, case-preserved).
        match parse_turn("TOOL: codebase web3 RPC reader endpoint") {
            ParsedTurn::ToolCodebase(q) => assert_eq!(q, "web3 RPC reader endpoint"),
            other => panic!("expected ToolCodebase, got {other:?}"),
        }
        // A bare `codebase` (no query) ⇒ ToolUnknown (closed grammar, PD-1). `codebase`
        // is distinct from `search ` (no prefix collision).
        for line in ["TOOL: codebase", "TOOL: codebase "] {
            match parse_turn(line) {
                ParsedTurn::ToolUnknown(_) => {}
                other => panic!("{line} must be ToolUnknown, got {other:?}"),
            }
        }
    }

    /// B⑫ (CURSOR PARITY keystone-3): `TOOL: mcp <server> <tool>` is a gated READ
    /// driven through the SHARED chokepoint. A configured seam is threaded as
    /// `Some`, but the model names an UNKNOWN server ⇒ the chokepoint fail-closes
    /// (server not configured) in EVERY build (the deny precedes any spawn), the
    /// loop CONTINUES, and no K is consumed (only a verified result consumes K).
    #[test]
    fn mcp_tool_unknown_server_fail_closed_and_loop_continues() {
        let records = fixture_records();
        let contents: [(MemoryId, &[u8]); 0] = [];
        let policy = TombstonePolicy::new();
        let state = MemoryToolState {
            records: &records,
            contents: &contents,
            policy: &policy,
        };
        let seam = crate::mcp::McpSeam::new(vec![crate::mcp::McpServerSpec::new(
            "localproof".to_string(),
            "/usr/bin/true".to_string(),
            vec![],
        )]);
        let replies = std::cell::RefCell::new(vec![
            "TOOL: mcp ghost read_motd".to_string(),
            "ANSWER: the mcp server was not configured".to_string(),
        ]);
        let mut transport = FnTransport(|_s: &str, _user: &str| {
            let next = replies.borrow_mut().remove(0);
            Ok(AgentTurn {
                answer_text: next,
                input_tokens_u64: 10,
                output_tokens_u64: 5,
                cached_tokens_u64: 0,
            })
        });
        let outcome = run_agent_loop_with(
            &mut transport,
            &state,
            "sys",
            "use the mcp tool",
            AGENT_LOOP_MAX_ITER,
            AGENT_LOOP_TOKEN_CAP,
            None,
            None,
            Some(&seam),
        );
        assert_eq!(outcome.stop, AgentLoopStop::Completed);
        assert_eq!(
            outcome.answer.as_deref(),
            Some("the mcp server was not configured")
        );
        // A fail-closed deny consumes NO K (only a verified result does).
        assert_eq!(
            outcome.reads_u8, 0,
            "an unconfigured-server deny consumes no read"
        );
        assert!(
            outcome
                .tool_trail
                .iter()
                .any(|t| t.contains("mcp-denied ghost/read_motd")),
            "the trail records the fail-closed deny: {:?}",
            outcome.tool_trail
        );
    }

    /// A⑤: `TOOL: git <subcommand> [args]` parses to ToolGit — subcommand is the
    /// first whitespace token (case-PRESERVED), the rest is the args. A bare `git`
    /// (no subcommand) falls to ToolUnknown (closed grammar, PD-1).
    #[test]
    fn git_parse_subcommand_and_args_case_preserved() {
        match parse_turn("TOOL: git log --oneline -5") {
            ParsedTurn::ToolGit(sub, args) => {
                assert_eq!(sub, "log");
                assert_eq!(args, "--oneline -5");
            }
            other => panic!("expected ToolGit, got {other:?}"),
        }
        // Subcommand only (no args) is valid; args default to empty.
        match parse_turn("TOOL: git status") {
            ParsedTurn::ToolGit(sub, args) => {
                assert_eq!(sub, "status");
                assert_eq!(args, "");
            }
            other => panic!("expected ToolGit, got {other:?}"),
        }
        // A bare `git` (no subcommand) ⇒ ToolUnknown (closed grammar).
        match parse_turn("TOOL: git") {
            ParsedTurn::ToolUnknown(_) => {}
            other => panic!("bare git must be ToolUnknown, got {other:?}"),
        }
    }

    /// A⑤ (CURSOR PARITY git-as-capability-type): `TOOL: git <subcommand>` is a
    /// gated READ driven through the SHARED chokepoint. A NON-READ subcommand
    /// (`commit`) ⇒ the chokepoint's allowlist fail-closes BEFORE any spawn (so this
    /// holds on every host / in every cwd), the loop CONTINUES, and no K is consumed.
    #[test]
    fn git_non_read_subcommand_fail_closed_and_loop_continues() {
        let records = fixture_records();
        let contents: [(MemoryId, &[u8]); 0] = [];
        let policy = TombstonePolicy::new();
        let state = MemoryToolState {
            records: &records,
            contents: &contents,
            policy: &policy,
        };
        let replies = std::cell::RefCell::new(vec![
            "TOOL: git commit -m wip".to_string(),
            "ANSWER: committing is an owner-approved action, not a read tool".to_string(),
        ]);
        let mut transport = FnTransport(|_s: &str, _user: &str| {
            let next = replies.borrow_mut().remove(0);
            Ok(AgentTurn {
                answer_text: next,
                input_tokens_u64: 10,
                output_tokens_u64: 5,
                cached_tokens_u64: 0,
            })
        });
        let outcome = run_agent_loop_with(
            &mut transport,
            &state,
            "sys",
            "commit my work with git",
            AGENT_LOOP_MAX_ITER,
            AGENT_LOOP_TOKEN_CAP,
            None,
            None,
            None,
        );
        assert_eq!(outcome.stop, AgentLoopStop::Completed);
        assert_eq!(
            outcome.answer.as_deref(),
            Some("committing is an owner-approved action, not a read tool")
        );
        // A fail-closed allowlist deny consumes NO K (only a verified READ does).
        assert_eq!(
            outcome.reads_u8, 0,
            "a non-READ-subcommand deny consumes no read"
        );
        assert!(
            outcome
                .tool_trail
                .iter()
                .any(|t| t.contains("git-denied commit")),
            "the trail records the fail-closed deny: {:?}",
            outcome.tool_trail
        );
    }

    /// E11-4-2 (IV-F11, PD-1): the grammar stays CLOSED — only `context index` is
    /// exposed. A write/delete (or any other `context …`, incl. `context file`)
    /// is an UNKNOWN tool (denied, ends the loop) — the loop cannot read CONTENT
    /// via this tool or widen it into a write.
    #[test]
    fn context_write_delete_and_file_are_denied_unknown_tools() {
        for line in [
            "TOOL: context write /x",
            "TOOL: context delete /x",
            "TOOL: context file /x",
        ] {
            match parse_turn(line) {
                ParsedTurn::ToolUnknown(_) => {}
                other => panic!("{line} must be ToolUnknown, got {other:?}"),
            }
        }
    }

    /// E11-4-2: the 6th typed-READ executor is content-free — a path OUTSIDE the
    /// allowed roots is a typed denial (no leak, no K), and the bare roots view
    /// surfaces the registered roots and consumes one K (cwd is always a root).
    #[test]
    fn context_index_executor_is_content_free_and_denies_outside_root() {
        let (out_etc, consumed_etc) =
            frontier_context_index_result(ReadCapability::granted(), "/etc");
        assert!(
            !consumed_etc,
            "an outside-root index consumes no K: {out_etc}"
        );
        assert!(out_etc.contains("denied"), "{out_etc}");
        let (out_roots, consumed_roots) =
            frontier_context_index_result(ReadCapability::granted(), "");
        assert!(
            consumed_roots,
            "the roots view consumes one K (cwd is a root)"
        );
        assert!(
            out_roots.contains("registered project roots"),
            "{out_roots}"
        );
    }

    /// E11-4-2: `TOOL: context index` is a gated READ — the loop CONTINUES through
    /// it (a content-free enumeration, not a side effect) and completes on ANSWER,
    /// consuming exactly one K.
    #[test]
    fn context_index_tool_is_gated_read_consumes_k_and_continues() {
        let records = fixture_records();
        let contents: [(MemoryId, &[u8]); 0] = [];
        let policy = TombstonePolicy::new();
        let state = MemoryToolState {
            records: &records,
            contents: &contents,
            policy: &policy,
        };
        let replies = std::cell::RefCell::new(vec![
            "TOOL: context index".to_string(),
            "ANSWER: the project has these roots".to_string(),
        ]);
        let mut transport = FnTransport(|_s: &str, _user: &str| {
            let next = replies.borrow_mut().remove(0);
            Ok(AgentTurn {
                answer_text: next,
                input_tokens_u64: 10,
                output_tokens_u64: 5,
                cached_tokens_u64: 0,
            })
        });
        let outcome = run_agent_loop_with(
            &mut transport,
            &state,
            "sys",
            "what's in this project?",
            AGENT_LOOP_MAX_ITER,
            AGENT_LOOP_TOKEN_CAP,
            None,
            None,
            None,
        );
        assert_eq!(outcome.stop, AgentLoopStop::Completed);
        assert_eq!(
            outcome.answer.as_deref(),
            Some("the project has these roots")
        );
        assert_eq!(outcome.reads_u8, 1, "a context index consumes one read");
        assert!(
            outcome.tool_trail.iter().any(|t| t.starts_with("ctxindex")),
            "{:?}",
            outcome.tool_trail
        );
    }

    /// E10-1 (⑬ IV-A1/IV-A2): a `PROPOSE-EXEC` final answer rides the ANSWER
    /// channel — the loop treats it as an ordinary completion and executes
    /// NOTHING (the inert proposal is sealed by dispatch; the loop has no
    /// executor on any path). The closed grammar is byte-unchanged: a side
    /// effect can only be PROPOSED in the answer, never invoked as a tool (the
    /// `unknown_tool_is_denied_without_execution` wall above still holds).
    #[test]
    fn propose_exec_rides_the_answer_channel_and_executes_nothing() {
        let records = fixture_records();
        let contents: [(MemoryId, &[u8]); 0] = [];
        let policy = TombstonePolicy::new();
        let state = MemoryToolState {
            records: &records,
            contents: &contents,
            policy: &policy,
        };
        let mut transport = ScriptedTransport::new(vec![
            "ANSWER: PROPOSE-EXEC\nCOMMAND: cargo test --workspace",
        ]);
        let outcome = run_agent_loop(&mut transport, &state, "s", "q");
        assert_eq!(outcome.stop, AgentLoopStop::Completed);
        // The propose block reaches dispatch intact (ANSWER: stripped, body kept).
        assert_eq!(
            outcome.answer.as_deref(),
            Some("PROPOSE-EXEC\nCOMMAND: cargo test --workspace")
        );
        // A propose is not a tool: zero reads, no tool entry in the trail.
        assert_eq!(outcome.reads_u8, 0);
        assert!(outcome.tool_trail.is_empty());
        // One transport turn; the loop ran no side effect (it cannot).
        assert_eq!(transport.calls, 1);
    }

    /// The m-agent iteration cap bounds the loop: a model that only ever
    /// asks for the index stops at MaxIterReached after exactly
    /// `AGENT_LOOP_MAX_ITER` transport calls.
    #[test]
    fn iteration_cap_stops_runaway() {
        let records = fixture_records();
        let contents: [(MemoryId, &[u8]); 0] = [];
        let policy = TombstonePolicy::new();
        let state = MemoryToolState {
            records: &records,
            contents: &contents,
            policy: &policy,
        };
        let mut transport = ScriptedTransport::new(vec!["TOOL: memory index"; 10]);
        let outcome = run_agent_loop(&mut transport, &state, "s", "q");
        assert_eq!(outcome.stop, AgentLoopStop::MaxIterReached);
        assert_eq!(outcome.iterations_u8, AGENT_LOOP_MAX_ITER);
        assert_eq!(transport.calls, usize::from(AGENT_LOOP_MAX_ITER));
    }

    /// The token budget bounds spend: an over-budget turn proposing MORE
    /// tool work stops the loop; an over-budget turn that already carries
    /// the final answer completes (a paid-for answer is never discarded).
    #[test]
    fn budget_gates_further_turns_but_keeps_paid_answer() {
        let records = fixture_records();
        let contents: [(MemoryId, &[u8]); 0] = [];
        let policy = TombstonePolicy::new();
        let state = MemoryToolState {
            records: &records,
            contents: &contents,
            policy: &policy,
        };

        let mut over = ScriptedTransport::new(vec!["TOOL: memory index"; 3]);
        over.tokens_per_turn = (15_000, 10_000); // 25k > 20k cap
        let outcome = run_agent_loop(&mut over, &state, "s", "q");
        assert_eq!(outcome.stop, AgentLoopStop::BudgetExceeded);
        assert_eq!(over.calls, 1, "no second transport call over budget");

        let mut answered = ScriptedTransport::new(vec!["ANSWER: kept"]);
        answered.tokens_per_turn = (15_000, 10_000);
        let outcome = run_agent_loop(&mut answered, &state, "s", "q");
        assert_eq!(outcome.stop, AgentLoopStop::Completed);
        assert_eq!(outcome.answer.as_deref(), Some("kept"));
        assert!(
            outcome
                .tool_trail
                .iter()
                .any(|t| t == "budget-exhausted-at-completion")
        );
    }

    /// Frontier read gates inside the loop: private (IV2), tombstoned (IV3,
    /// both layers) and unknown ids are DENIED as typed tool results (the
    /// denied bytes never enter the prompt) while the loop continues to a
    /// normal completion. (The secret-shaped case now LOCKS DOWN — see
    /// `guard_secret_touch_locks_down`, P2-2.)
    #[test]
    fn frontier_read_gates_deny_inside_loop() {
        let records = [
            record(1, SHAREABLE, MemoryTier::Recent, false),
            record(2, PRIVATE, MemoryTier::Recent, true),
            record(3, b"deleted body", MemoryTier::DeletedTombstone, false),
        ];
        let contents: [(MemoryId, &[u8]); 2] =
            [(MemoryId::new(2), PRIVATE), (MemoryId::new(1), SHAREABLE)];
        let policy = TombstonePolicy::new();
        let state = MemoryToolState {
            records: &records,
            contents: &contents,
            policy: &policy,
        };
        let mut transport = ScriptedTransport::new(vec![
            "TOOL: memory read 2",
            "TOOL: memory read 9",
            "ANSWER: ok",
        ]);
        let outcome = run_agent_loop(&mut transport, &state, "s", "q");
        assert_eq!(outcome.stop, AgentLoopStop::Completed);
        assert_eq!(outcome.reads_u8, 0, "denials are not reads");
        assert_eq!(outcome.tool_trail, ["read-denied 2", "read-denied 9"]);
        let last_msg = transport.user_messages.last().expect("messages");
        assert!(last_msg.contains("memory_index.read_deny.private_to_frontier"));
        assert!(last_msg.contains("memory_index.read_deny.not_in_index"));
        assert!(
            !last_msg.contains("medical"),
            "private content never enters the prompt"
        );
        // Ordinary denials are walls working as designed, not drift: healthy.
        assert!(outcome.health.is_healthy());
        assert_eq!(recommended_action(outcome.health), GuardAction::Continue);
    }

    /// P2-2 — a secret-shaped withhold records `SecretTouch` and the guard
    /// LOCKS DOWN: the loop ends typed with NO further egress turn (the
    /// scripted ANSWER is never requested), and the secret bytes never
    /// appear in any assembled message.
    #[test]
    fn guard_secret_touch_locks_down() {
        const SECRET_BODY: &[u8] = b"key = \"suiprivkey1qexamplenotreal\"";
        let records = [record(4, SECRET_BODY, MemoryTier::Recent, false)];
        let contents: [(MemoryId, &[u8]); 1] = [(MemoryId::new(4), SECRET_BODY)];
        let policy = TombstonePolicy::new();
        let state = MemoryToolState {
            records: &records,
            contents: &contents,
            policy: &policy,
        };
        let mut transport =
            ScriptedTransport::new(vec!["TOOL: memory read 4", "ANSWER: never-reached"]);
        let outcome = run_agent_loop(&mut transport, &state, "s", "q");
        assert_eq!(outcome.stop, AgentLoopStop::GuardLockdown);
        assert_eq!(outcome.answer, None);
        assert_eq!(
            transport.calls, 1,
            "lockdown: no further egress turn after the secret touch"
        );
        assert_eq!(outcome.tool_trail, ["read-denied 4", "guard-lockdown"]);
        assert_eq!(recommended_action(outcome.health), GuardAction::Lockdown);
        assert!(!outcome.health.is_healthy());
        for msg in &transport.user_messages {
            assert!(!msg.contains("suiprivkey"), "secret never enters a prompt");
        }
        assert_eq!(
            AgentLoopStop::GuardLockdown.class_label(),
            "loop.guard_lockdown"
        );
    }

    /// P2-2 — a byte-identical repeated tool call records `SemanticLoop`
    /// (guard: Slow — visible, not stopping) and is answered from context
    /// WITHOUT re-execution: the repeat note replaces a duplicate result.
    #[test]
    fn guard_repeated_tool_call_dedups_and_slows() {
        let (records, policy) = empty_state_fixture();
        let contents: [(MemoryId, &[u8]); 0] = [];
        let state = MemoryToolState {
            records: &records,
            contents: &contents,
            policy: &policy,
        };
        let mut transport = ScriptedTransport::new(vec![
            "TOOL: memory index",
            "TOOL: memory index",
            "ANSWER: done",
        ]);
        let outcome = run_agent_loop(&mut transport, &state, "s", "q");
        assert_eq!(outcome.stop, AgentLoopStop::Completed);
        assert_eq!(outcome.tool_trail, ["index", "repeat index"]);
        assert_eq!(recommended_action(outcome.health), GuardAction::Slow);

        // The duplicate was NOT re-executed: the final message carries the
        // ONE real index result plus the repeat note, not two catalogs.
        let last_msg = transport.user_messages.last().expect("messages");
        assert_eq!(last_msg.matches("shareable records").count(), 1);
        assert!(last_msg.contains("repeated tool call"));
    }

    /// P2-2 — an integrity-mismatch denial (the presented bytes fail the
    /// record's hash re-derivation) records `EvidenceMismatch`; the guard
    /// recommends AUDIT — visible in the receipt — while the loop still
    /// completes (the bad bytes were already denied at the wall).
    #[test]
    fn guard_integrity_mismatch_audits() {
        let records = [record(1, b"the true content", MemoryTier::Recent, false)];
        // The contents map serves DIFFERENT bytes for id 1 ⇒ hash mismatch.
        let contents: [(MemoryId, &[u8]); 1] = [(MemoryId::new(1), b"tampered bytes here")];
        let policy = TombstonePolicy::new();
        let state = MemoryToolState {
            records: &records,
            contents: &contents,
            policy: &policy,
        };
        let mut transport =
            ScriptedTransport::new(vec!["TOOL: memory read 1", "ANSWER: ok despite denial"]);
        let outcome = run_agent_loop(&mut transport, &state, "s", "q");
        assert_eq!(outcome.stop, AgentLoopStop::Completed);
        assert_eq!(outcome.reads_u8, 0, "a mismatching read never counts");
        assert_eq!(recommended_action(outcome.health), GuardAction::Audit);
        let last_msg = transport.user_messages.last().expect("messages");
        assert!(
            !last_msg.contains("tampered bytes"),
            "mismatching bytes never enter the prompt"
        );
    }

    /// IV5's K: reads beyond `AGENT_LOOP_MAX_READS` are denied (counted,
    /// no content) while the loop still completes. Four DISTINCT readable
    /// ids exercise the cap (a repeated id now dedups instead — P2-2, see
    /// `guard_repeated_tool_call_dedups_and_slows`).
    #[test]
    fn read_cap_k_is_enforced() {
        let bodies: [&[u8]; 4] = [b"body one", b"body two", b"body three", b"body four"];
        let records = [
            record(1, bodies[0], MemoryTier::Recent, false),
            record(2, bodies[1], MemoryTier::Recent, false),
            record(3, bodies[2], MemoryTier::Recent, false),
            record(4, bodies[3], MemoryTier::Recent, false),
        ];
        let contents: [(MemoryId, &[u8]); 4] = [
            (MemoryId::new(1), bodies[0]),
            (MemoryId::new(2), bodies[1]),
            (MemoryId::new(3), bodies[2]),
            (MemoryId::new(4), bodies[3]),
        ];
        let policy = TombstonePolicy::new();
        let state = MemoryToolState {
            records: &records,
            contents: &contents,
            policy: &policy,
        };
        let mut transport = ScriptedTransport::new(vec![
            "TOOL: memory read 1",
            "TOOL: memory read 2",
            "TOOL: memory read 3",
            "TOOL: memory read 4",
            "ANSWER: ok",
        ]);
        let outcome = run_agent_loop(&mut transport, &state, "s", "q");
        assert_eq!(outcome.stop, AgentLoopStop::Completed);
        assert_eq!(outcome.reads_u8, AGENT_LOOP_MAX_READS);
        assert_eq!(
            outcome.tool_trail.last().map(String::as_str),
            Some("read-cap 4")
        );
        let last_msg = transport.user_messages.last().expect("messages");
        assert!(last_msg.contains("read cap K=3 reached"));
    }

    /// A model that ignores the protocol and just answers completes cleanly;
    /// the `ANSWER:` prefix is optional.
    #[test]
    fn plain_answer_completes() {
        let records: [MemoryIndexRecord; 0] = [];
        let contents: [(MemoryId, &[u8]); 0] = [];
        let policy = TombstonePolicy::new();
        let state = MemoryToolState {
            records: &records,
            contents: &contents,
            policy: &policy,
        };
        let mut transport = ScriptedTransport::new(vec!["the plain answer text"]);
        let outcome = run_agent_loop(&mut transport, &state, "s", "q");
        assert_eq!(outcome.stop, AgentLoopStop::Completed);
        assert_eq!(outcome.answer.as_deref(), Some("the plain answer text"));
        assert_eq!(outcome.iterations_u8, 0);
    }

    /// The assembled user message stays under its byte cap (oldest tool
    /// results dropped first, explicit truncation marker when one result
    /// alone overflows).
    #[test]
    fn user_message_is_byte_capped() {
        let big = "x".repeat(AGENT_LOOP_TOOL_RESULT_CAP_BYTES);
        let results = vec![big.clone(), big.clone(), big.clone(), big];
        let message = build_user_message("q", &results);
        assert!(message.len() <= AGENT_LOOP_USER_MSG_CAP_BYTES);
        // Newest results are preferred (oldest dropped first).
        assert!(message.contains("[tool result]"));

        let empty = build_user_message("the question", &[]);
        assert_eq!(
            empty, "the question",
            "no per-turn tail text (P2-1: the protocol reminder lives in the system prompt)"
        );

        // P2-1 prefix law: under the cap, each assembly EXTENDS the previous
        // one as a strict byte prefix (append-only ⇒ provider-cacheable).
        let r1 = vec!["first tool result".to_string()];
        let r2 = vec!["first tool result".to_string(), "second".to_string()];
        let m0 = build_user_message("q", &[]);
        let m1 = build_user_message("q", &r1);
        let m2 = build_user_message("q", &r2);
        assert!(m1.starts_with(&m0));
        assert!(m2.starts_with(&m1));
    }

    /// P2-1 — the CostLedger records EVERY wire turn (in/out/cached), the
    /// zero-rate PriceTable sentinel projects $0 while counters climb, the
    /// cache plan carries the LAST turn's real byte split, and the measured
    /// prefix-stability counter sees the append-only assembly extend.
    #[test]
    fn cost_ledger_and_cache_metrics_accumulate() {
        let (records, policy) = empty_state_fixture();
        let contents: [(MemoryId, &[u8]); 0] = [];
        let state = MemoryToolState {
            records: &records,
            contents: &contents,
            policy: &policy,
        };
        let replies = std::cell::RefCell::new(vec![
            "TOOL: memory index".to_string(),
            "ANSWER: done".to_string(),
        ]);
        let last_user_len = std::cell::Cell::new(0usize);
        let mut transport = FnTransport(|_s: &str, user: &str| {
            last_user_len.set(user.len());
            Ok(AgentTurn {
                answer_text: replies.borrow_mut().remove(0),
                input_tokens_u64: 100,
                output_tokens_u64: 20,
                cached_tokens_u64: 64,
            })
        });
        let outcome = run_agent_loop(&mut transport, &state, "sys", "q");
        assert_eq!(outcome.stop, AgentLoopStop::Completed);

        // Ledger: two wire turns recorded (100/20/64 each).
        assert_eq!(outcome.cost.input_tokens_u32(), 200);
        assert_eq!(outcome.cost.output_tokens_u32(), 40);
        assert_eq!(outcome.cost.cached_tokens_u32(), 128);
        assert_eq!(
            outcome.cost.usd_micros().get(),
            0,
            "zero-rate sentinel: counters climb, usd stays 0 until rates are wired"
        );
        // The u64 loop counters agree at these magnitudes.
        assert_eq!(outcome.input_tokens_u64, 200);
        assert_eq!(outcome.output_tokens_u64, 40);

        // Cache plan: static = the system bytes ("sys" = 3); dynamic = the
        // LAST assembled user message; one breakpoint at the boundary.
        assert_eq!(outcome.cache_plan.static_prefix_bytes_u32, 3);
        assert_eq!(
            outcome.cache_plan.dynamic_suffix_bytes_u32 as usize,
            last_user_len.get()
        );
        assert_eq!(outcome.cache_plan.breakpoints_u8, 1);

        // Prefix stability: turn 2's message extends turn 1's (append-only).
        assert_eq!(outcome.prefix_stable_turns_u8, 1);
    }

    /// P2-1 — the prefix-stability metric is MEASURED, not assumed: when the
    /// user-message byte cap forces the kept-results window to slide (oldest
    /// tool result dropped), the next message no longer extends the previous
    /// one and the counter honestly stops counting that turn.
    #[test]
    fn prefix_stability_breaks_honestly_under_truncation() {
        let body_one = "memory body one ".repeat(124); // ~1984 bytes
        let body_two = "memory body two ".repeat(124);
        let records = [
            record(1, body_one.as_bytes(), MemoryTier::Recent, false),
            record(2, body_two.as_bytes(), MemoryTier::Recent, false),
        ];
        let contents: [(MemoryId, &[u8]); 2] = [
            (MemoryId::new(1), body_one.as_bytes()),
            (MemoryId::new(2), body_two.as_bytes()),
        ];
        let policy = TombstonePolicy::new();
        let state = MemoryToolState {
            records: &records,
            contents: &contents,
            policy: &policy,
        };
        let replies = std::cell::RefCell::new(vec![
            "TOOL: memory read 1".to_string(),
            "TOOL: memory read 2".to_string(),
            "ANSWER: ok".to_string(),
        ]);
        let mut transport = FnTransport(|_s: &str, _u: &str| {
            Ok(AgentTurn {
                answer_text: replies.borrow_mut().remove(0),
                input_tokens_u64: 1,
                output_tokens_u64: 1,
                cached_tokens_u64: 0,
            })
        });
        // A 2_500-byte question: q(2500) + result(~2016) fits the 6_000 cap,
        // but q + result + result overflows ⇒ turn 3 drops the OLDEST result
        // and its message is NOT a prefix extension of turn 2's.
        let question = "q".repeat(2_500);
        let outcome = run_agent_loop(&mut transport, &state, "sys", &question);
        assert_eq!(outcome.stop, AgentLoopStop::Completed);
        assert_eq!(outcome.reads_u8, 2, "both reads verified");
        assert_eq!(
            outcome.prefix_stable_turns_u8, 1,
            "turn 2 extended turn 1; truncation broke turn 3 (measured, falsifiable)"
        );
    }

    /// Stop-class labels stay stable (the m-agent `loop.*` namespace).
    #[test]
    fn stop_labels_stable() {
        assert_eq!(AgentLoopStop::Completed.class_label(), "loop.completed");
        assert_eq!(
            AgentLoopStop::from_loop_stop(LoopStop::MaxIterReached),
            AgentLoopStop::MaxIterReached
        );
        assert_eq!(
            AgentLoopStop::TransportFailed.class_label(),
            "loop.transport_failed"
        );
    }

    // ---- lane A: file read tool (FILE_CONTEXT_THREAT_MODEL.md) ------------

    /// Lane A — the loop's `file read` tool: reads a readable file inside the
    /// policy root (content reaches the prompt), denies an outside-root path,
    /// a denylisted name, and withholds a secret-shaped file — none of whose
    /// bytes ever enter the assembled prompt. With NO policy the tool denies.
    #[test]
    fn loop_file_read_tool_gates() {
        use crate::file_context::FileReadPolicy;
        use std::io::Write;

        let dir = std::env::temp_dir().join(format!("sinabro_loopfile_{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("dir");
        let readable = dir.join("notes.txt");
        std::fs::File::create(&readable)
            .expect("create")
            .write_all(b"PROJECT FACTS: ships friday")
            .expect("write");
        let secret = dir.join("config.toml");
        std::fs::File::create(&secret)
            .expect("create")
            .write_all(b"token = \"suiprivkey1qexamplenotreal\"")
            .expect("write");
        let policy = FileReadPolicy::new(
            std::slice::from_ref(&dir),
            crate::file_context::MAX_FILE_BYTES,
        );

        let (records, tomb) = empty_state_fixture();
        let contents: [(MemoryId, &[u8]); 0] = [];
        let state = MemoryToolState {
            records: &records,
            contents: &contents,
            policy: &tomb,
        };

        // Happy path: the file content reaches the next user message.
        let mut ok = ScriptedTransport::new(vec![
            // path is interpolated below; ScriptedTransport ignores user msg
            // content for its reply, so we drive the tool via the canned line.
            "ANSWER: placeholder",
        ]);
        // Drive the executor directly (the canned reply can't carry a dynamic
        // path): assert the frontier file executor's gating + the loop wiring
        // through a hand-built reply sequence.
        let read_line = format!("TOOL: file read {}", readable.display());
        let secret_line = format!("TOOL: file read {}", secret.display());
        let outside_line = "TOOL: file read /etc/hosts".to_string();
        let _ = &mut ok;

        // Use a closure transport to return path-specific tool lines in order.
        // (The secret-shaped file is exercised in its own pass below — E14-B2: a
        // file-read withhold no longer ends the loop; it withholds + continues.)
        let replies = std::cell::RefCell::new(vec![
            read_line.clone(),
            outside_line.clone(),
            "ANSWER: done".to_string(),
        ]);
        let user_msgs = std::cell::RefCell::new(Vec::<String>::new());
        let mut transport = FnTransport(|_s: &str, user: &str| {
            user_msgs.borrow_mut().push(user.to_string());
            let next = replies.borrow_mut().remove(0);
            Ok(AgentTurn {
                answer_text: next,
                input_tokens_u64: 10,
                output_tokens_u64: 5,
                cached_tokens_u64: 0,
            })
        });
        let outcome = run_agent_loop_with(
            &mut transport,
            &state,
            "sys",
            "what ships?",
            AGENT_LOOP_MAX_ITER,
            AGENT_LOOP_TOKEN_CAP,
            Some(&policy),
            None,
            None,
        );
        assert_eq!(outcome.stop, AgentLoopStop::Completed);
        assert_eq!(
            outcome.reads_u8, 1,
            "only the readable file counts as a read"
        );
        {
            let msgs = user_msgs.borrow();
            let all = msgs.join("\n");
            assert!(
                all.contains("PROJECT FACTS: ships friday"),
                "readable content reaches prompt"
            );
            assert!(
                all.contains("file_context.outside_allowed_roots"),
                "outside-root denied as a typed reason"
            );
            assert!(
                !all.contains("127.0.0.1"),
                "outside-file bytes never in prompt"
            );
            assert_eq!(
                outcome.tool_trail,
                [
                    format!("file {}", readable.display()),
                    "file-denied /etc/hosts".to_string(),
                ]
            );
        }
        // P3-2 (IV-W2): exactly the VERIFIED read is recorded — the
        // executor's own canonical path + the sha256 of the prompt-bound
        // bytes; the denied outside-root read is NOT recorded.
        assert_eq!(outcome.verified_file_reads.len(), 1);
        let read = &outcome.verified_file_reads[0];
        assert_eq!(read.path_as_typed, readable.display().to_string());
        assert_eq!(
            read.canonical_path,
            std::fs::canonicalize(&readable).expect("canon")
        );
        assert_eq!(
            read.sha256_32,
            crate::sha256_32(b"PROJECT FACTS: ships friday")
        );

        // E14-B2 — a secret-shaped FILE read now WITHHOLDS the secret-shaped line(s)
        // and CONTINUES (the SI-2 wall keeps the secret out of the prompt), instead of
        // locking the whole consult down after one turn. The loop runs the next turn
        // and ANSWERS from the redacted content.
        let secret_replies = std::cell::RefCell::new(vec![
            secret_line.clone(),
            "ANSWER: done after the withhold".to_string(),
        ]);
        let secret_msgs = std::cell::RefCell::new(Vec::<String>::new());
        let calls = std::cell::Cell::new(0u8);
        let mut secret_transport = FnTransport(|_s: &str, user: &str| {
            secret_msgs.borrow_mut().push(user.to_string());
            calls.set(calls.get() + 1);
            Ok(AgentTurn {
                answer_text: secret_replies.borrow_mut().remove(0),
                input_tokens_u64: 10,
                output_tokens_u64: 5,
                cached_tokens_u64: 0,
            })
        });
        let withhold = run_agent_loop_with(
            &mut secret_transport,
            &state,
            "sys",
            "what ships?",
            AGENT_LOOP_MAX_ITER,
            AGENT_LOOP_TOKEN_CAP,
            Some(&policy),
            None,
            None,
        );
        // NO lockdown: the loop completes from the model's answer after the withhold.
        assert_eq!(withhold.stop, AgentLoopStop::Completed);
        assert_ne!(
            recommended_action(withhold.health),
            GuardAction::Lockdown,
            "a file-read withhold no longer locks the consult down (E14-B2)"
        );
        assert_eq!(calls.get(), 2, "the loop ran a 2nd turn after the withhold");
        let joined = secret_msgs.borrow().join("\n");
        assert!(
            joined.contains("[withheld: secret-shaped line]"),
            "the secret-shaped line is withheld, the rest readable: {joined}"
        );
        assert!(
            !joined.contains("suiprivkey1qexample"),
            "secret bytes never in any prompt"
        );
        // a partial (redacted) read is NEVER a propose-bindable record (no edit).
        assert!(withhold.verified_file_reads.is_empty());
        assert!(
            withhold
                .tool_trail
                .iter()
                .any(|t| t == &format!("file-denied {}", secret.display())),
            "the partial read is trailed (not editable); the loop did not lock down"
        );

        std::fs::remove_dir_all(&dir).ok();
    }

    /// Lane A — with NO file policy the tool denies (no file access
    /// configured); the loop still completes from the model's own answer.
    #[test]
    fn loop_file_read_denied_without_policy() {
        let (records, tomb) = empty_state_fixture();
        let contents: [(MemoryId, &[u8]); 0] = [];
        let state = MemoryToolState {
            records: &records,
            contents: &contents,
            policy: &tomb,
        };
        let mut transport = ScriptedTransport::new(vec!["TOOL: file read /any/path", "ANSWER: ok"]);
        let outcome = run_agent_loop_with(
            &mut transport,
            &state,
            "s",
            "q",
            AGENT_LOOP_MAX_ITER,
            AGENT_LOOP_TOKEN_CAP,
            None,
            None,
            None,
        );
        assert_eq!(outcome.stop, AgentLoopStop::Completed);
        assert_eq!(outcome.reads_u8, 0);
        let last = transport.user_messages.last().expect("messages");
        assert!(last.contains("no file access configured"));
        // P3-2 (IV-W2): no policy ⇒ no verified read ⇒ nothing bindable.
        assert!(outcome.verified_file_reads.is_empty());
    }

    /// Lane A — `file read` parses with the path case PRESERVED (a lowercased
    /// path would miss a real file on a case-sensitive fs).
    #[test]
    fn file_read_parse_preserves_path_case() {
        match parse_turn("TOOL: file read /Proj/SRC/Main.RS") {
            ParsedTurn::ToolFileRead(path) => assert_eq!(path, "/Proj/SRC/Main.RS"),
            other => panic!("expected ToolFileRead, got {other:?}"),
        }
        // An empty path falls through to the unknown-tool denial (IV6).
        assert!(matches!(
            parse_turn("TOOL: file read   "),
            ParsedTurn::ToolUnknown(_)
        ));
    }

    // ---- fan-out (roadmap §3.A; TM D-2/D-3/D-4/D-5) -----------------------

    fn empty_state_fixture() -> ([MemoryIndexRecord; 0], TombstonePolicy) {
        ([], TombstonePolicy::new())
    }

    /// TM D-5 — the merge is deterministic BY CHILD INDEX: (a) a manually
    /// scrambled arrival order merges identically to the sorted one (pure,
    /// no timing); (b) under REAL scoped threads with inverted sleeps
    /// (later children finish first), the merged output is still index-
    /// ordered with each child's own answer in its own slot.
    #[test]
    fn fanout_merge_is_deterministic_by_index() {
        fn child(idx: u8, answer: &str) -> ChildResult {
            ChildResult {
                child_index_u8: idx,
                outcome: AgentLoopOutcome {
                    answer: Some(answer.to_string()),
                    stop: AgentLoopStop::Completed,
                    iterations_u8: 0,
                    reads_u8: 0,
                    tool_trail: Vec::new(),
                    input_tokens_u64: 100,
                    output_tokens_u64: 50,
                    cost: CostLedger::new(),
                    cache_plan: CacheBreakpointPlan::default(),
                    prefix_stable_turns_u8: 0,
                    health: TrajectoryHealth::healthy(),
                    verified_file_reads: Vec::new(),
                },
            }
        }
        // (a) two different arrival orders ⇒ identical merged output.
        let scrambled = merge_fanout(vec![child(2, "c2"), child(0, "c0"), child(1, "c1")]);
        let sorted = merge_fanout(vec![child(0, "c0"), child(1, "c1"), child(2, "c2")]);
        assert_eq!(scrambled, sorted);
        assert_eq!(
            scrambled
                .children
                .iter()
                .map(|c| c.child_index_u8)
                .collect::<Vec<_>>(),
            [0, 1, 2]
        );
        assert_eq!(scrambled.completed_u8, 3);
        assert_eq!(scrambled.input_tokens_u64, 300);
        assert_eq!(scrambled.output_tokens_u64, 150);

        // (b) real threads, inverted sleeps: child 0 slowest, child 2 fastest.
        let (records, policy) = empty_state_fixture();
        let contents: [(MemoryId, &[u8]); 0] = [];
        let state = MemoryToolState {
            records: &records,
            contents: &contents,
            policy: &policy,
        };
        let arrivals = std::sync::Mutex::new(Vec::new());
        let mut results: Vec<ChildResult> = std::thread::scope(|scope| {
            let mut handles = Vec::new();
            for index in 0u8..3 {
                let state_ref = &state;
                let arrivals_ref = &arrivals;
                handles.push(scope.spawn(move || {
                    let delay_ms = u64::from(2 - index) * 30;
                    let mut transport = FnTransport(move |_system: &str, _user: &str| {
                        std::thread::sleep(std::time::Duration::from_millis(delay_ms));
                        Ok(AgentTurn {
                            answer_text: format!("ANSWER: from-child-{index}"),
                            input_tokens_u64: 10,
                            output_tokens_u64: 5,
                            cached_tokens_u64: 0,
                        })
                    });
                    let outcome = run_fanout_child(&mut transport, state_ref, "s", "q", 1_000);
                    arrivals_ref.lock().expect("arrival lock").push(index);
                    ChildResult {
                        child_index_u8: index,
                        outcome,
                    }
                }));
            }
            handles
                .into_iter()
                .map(|handle| handle.join().expect("child thread joins"))
                .collect()
        });
        // Encourage a scrambled arrival (not asserted — timing is advisory);
        // the merge result below must be index-ordered REGARDLESS.
        let _arrival_order = arrivals.lock().expect("arrival lock").clone();
        // Scramble the collected vec deterministically before merging.
        results.rotate_left(1);
        let merged = merge_fanout(results);
        for (position, child) in merged.children.iter().enumerate() {
            assert_eq!(usize::from(child.child_index_u8), position);
            assert_eq!(
                child.outcome.answer.as_deref(),
                Some(format!("from-child-{position}").as_str())
            );
        }
        assert_eq!(merged.completed_u8, 3);
        assert_eq!(merged.failed_u8, 0);
    }

    /// TM D-2/D-4 — children are isolated: a transport-failing child and a
    /// budget-exhausted child (its OWN partitioned slice) each stop typed
    /// in their own slot; the healthy sibling's answer is untouched; and the
    /// fan child iteration cap (3, below the single loop's 5) bounds a
    /// tool-looping child.
    #[test]
    fn fanout_children_are_isolated_and_capped() {
        let (records, policy) = empty_state_fixture();
        let contents: [(MemoryId, &[u8]); 0] = [];
        let state = MemoryToolState {
            records: &records,
            contents: &contents,
            policy: &policy,
        };

        // child 0: transport failure.
        let mut failing = FnTransport(|_: &str, _: &str| {
            Err(AgentTransportError {
                class_label: "boom".to_string(),
            })
        });
        let child0 = run_fanout_child(&mut failing, &state, "s", "q0", 1_000);

        // child 1: healthy completion.
        let mut healthy = FnTransport(|_: &str, _: &str| {
            Ok(AgentTurn {
                answer_text: "ANSWER: healthy".to_string(),
                input_tokens_u64: 10,
                output_tokens_u64: 5,
                cached_tokens_u64: 0,
            })
        });
        let child1 = run_fanout_child(&mut healthy, &state, "s", "q1", 1_000);

        // child 2: its own tiny slice (100) exhausted by a 150-token tool turn.
        let mut hungry = FnTransport(|_: &str, _: &str| {
            Ok(AgentTurn {
                answer_text: "TOOL: memory index".to_string(),
                input_tokens_u64: 100,
                output_tokens_u64: 50,
                cached_tokens_u64: 0,
            })
        });
        let child2 = run_fanout_child(&mut hungry, &state, "s", "q2", 100);

        // child 3: tool-loops forever; the FAN iteration cap (3) stops it.
        let calls = std::cell::Cell::new(0u8);
        let mut looping = FnTransport(|_: &str, _: &str| {
            calls.set(calls.get() + 1);
            Ok(AgentTurn {
                answer_text: "TOOL: memory index".to_string(),
                input_tokens_u64: 1,
                output_tokens_u64: 1,
                cached_tokens_u64: 0,
            })
        });
        let child3 = run_fanout_child(&mut looping, &state, "s", "q3", 1_000);
        assert_eq!(calls.get(), FANOUT_CHILD_MAX_ITER);

        let merged = merge_fanout(vec![
            ChildResult {
                child_index_u8: 3,
                outcome: child3,
            },
            ChildResult {
                child_index_u8: 0,
                outcome: child0,
            },
            ChildResult {
                child_index_u8: 2,
                outcome: child2,
            },
            ChildResult {
                child_index_u8: 1,
                outcome: child1,
            },
        ]);
        assert_eq!(merged.completed_u8, 1);
        assert_eq!(merged.failed_u8, 3);
        assert_eq!(
            merged.children[0].outcome.stop,
            AgentLoopStop::TransportFailed
        );
        assert_eq!(
            merged.children[1].outcome.answer.as_deref(),
            Some("healthy")
        );
        assert_eq!(
            merged.children[2].outcome.stop,
            AgentLoopStop::BudgetExceeded
        );
        assert_eq!(
            merged.children[3].outcome.stop,
            AgentLoopStop::MaxIterReached
        );
        assert_eq!(
            merged.children[3].outcome.iterations_u8,
            FANOUT_CHILD_MAX_ITER
        );
    }

    /// ENDGAME E1 / PD-3 — recall is a READ, and the answer cites it. The
    /// recall executors run under a free [`ReadCapability`] witness (no
    /// approval / grant), and [`AgentLoopOutcome::recalled_memory_ids`] reports
    /// exactly the VERIFIED memory reads: a denied private read is NOT a
    /// recall, so it is never cited (and its bytes never reached the prompt).
    #[test]
    fn recall_is_read_and_cites_only_verified_ids() {
        // READ is always granted with no witness (PD-3) — the same token the
        // loop mints internally for every recall executor.
        let _read = ReadCapability::granted();

        let records = fixture_records();
        let contents: [(MemoryId, &[u8]); 2] =
            [(MemoryId::new(1), SHAREABLE), (MemoryId::new(2), PRIVATE)];
        let policy = TombstonePolicy::new();
        let state = MemoryToolState {
            records: &records,
            contents: &contents,
            policy: &policy,
        };
        // index → read 1 (shareable, verified) → read 2 (private, DENIED) → answer.
        let mut transport = ScriptedTransport::new(vec![
            "TOOL: memory index",
            "TOOL: memory read 1",
            "TOOL: memory read 2",
            "ANSWER: done",
        ]);
        let outcome = run_agent_loop(&mut transport, &state, "s", "q");
        assert_eq!(outcome.stop, AgentLoopStop::Completed);
        assert_eq!(outcome.reads_u8, 1, "only the shareable read verified");
        // The citation is exactly the verified recall (id 1); the denied
        // private read (trail `read-denied 2`) is not a recall.
        assert_eq!(outcome.recalled_memory_ids(), vec![1]);
        assert!(
            outcome.tool_trail.iter().any(|t| t == "read-denied 2"),
            "the private read was denied, not recalled"
        );
    }

    /// E14-B2 — a file embedding a multi-line PEM key/cert block is FULLY withheld
    /// (its body lines do not match the single-line markers, so per-line redaction
    /// could leak them); a clean file is fully readable + editable; a doc that merely
    /// MENTIONS a secret token keeps its benign lines + withholds only the secret one.
    #[test]
    fn frontier_file_result_pem_is_fully_withheld_clean_is_editable() {
        use crate::commands::authority::ReadCapability;
        use crate::file_context::{FileReadPolicy, MAX_FILE_BYTES};

        let dir = std::env::temp_dir().join(format!("mnemos_b2_{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("mk");
        let policy = FileReadPolicy::new(std::slice::from_ref(&dir), MAX_FILE_BYTES);
        let read = || ReadCapability::granted();

        // (1) a PEM block embedded in a .md ⇒ the WHOLE file is withheld (body safety).
        let pem = dir.join("embedded.md");
        std::fs::write(
            &pem,
            "intro line\n-----BEGIN PRIVATE KEY-----\nMIIBVQ_keybody_must_not_leak\n-----END PRIVATE KEY-----\noutro line",
        )
        .expect("write pem");
        let (out, verified) =
            frontier_file_result(read(), Some(&policy), pem.to_str().expect("utf8"));
        assert!(
            !out.contains("MIIBVQ"),
            "the key body must never leak: {out}"
        );
        assert!(out.contains("key/cert block"));
        assert!(verified.is_none(), "a withheld read is not editable");

        // (2) a clean file ⇒ fully readable AND editable (Some receipt).
        let clean = dir.join("notes.txt");
        std::fs::write(&clean, "alpha\nbeta\ngamma").expect("write clean");
        let (out2, verified2) =
            frontier_file_result(read(), Some(&policy), clean.to_str().expect("utf8"));
        assert!(out2.contains("alpha") && out2.contains("gamma"));
        assert!(out2.contains("(verified):"), "clean read header");
        assert!(verified2.is_some(), "a clean read IS editable");

        // (3) a doc that MENTIONS a secret token ⇒ benign lines kept, secret withheld,
        //     and NO wholesale lockdown phrase.
        let doc = dir.join("audit.md");
        std::fs::write(
            &doc,
            "audit heading\nthe suiprivkey1qexamplenotreal must be rotated\nconcluding remark",
        )
        .expect("write doc");
        let (out3, verified3) =
            frontier_file_result(read(), Some(&policy), doc.to_str().expect("utf8"));
        assert!(out3.contains("audit heading") && out3.contains("concluding remark"));
        assert!(out3.contains("[withheld: secret-shaped line]"));
        assert!(
            !out3.contains("suiprivkey1qexamplenotreal"),
            "secret never shown"
        );
        assert!(
            !out3.contains("withheld (secret-shaped)"),
            "must not carry the lockdown-trigger phrase"
        );
        assert!(
            verified3.is_none(),
            "a partially-redacted read is not editable"
        );

        std::fs::remove_dir_all(&dir).ok();
    }
}
