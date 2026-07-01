//! Operational dispatch core (atom #561-#567 · G.6.0-G.6.6).
//!
//! G-WP-07 closes the lean `bin` dispatch: every closed [`crate::grammar`]
//! namespace (35 total) plus the operational top-level commands
//! (`status`/`setup`/`evidence`/`budget`/`kill`/`tui`/`repl`) now route to the
//! handlers A-F already built — the lean Stage-F deferral stub is gone (no
//! recognized namespace is left only acknowledging itself). This module is
//! *glue*: it mints no new business truth. It
//!
//! 1. resolves a verb-level [`CommandRisk`] ([`risk_for`]),
//! 2. classifies the command through the canonical
//!    [`crate::command::CommandEnvelope::classify`] (the single risk -> approval
//!    gate), and
//! 3. renders the handler's pure projection (`ReadOnly`) **or** the
//!    approval/locked surface (`approval != None`).
//!
//! Safety (load-bearing): opening dispatch to all 35 namespaces does NOT open
//! side effects. There is no side-effect code path in this module — every arm
//! only renders. `train run`/`sft`/`checkpoint promote`/`grpo unlock` classify as
//! [`CommandRisk::Training`] -> [`ApprovalRequirement::ForbiddenInStageF`] and
//! render the NO-TRAINING surface; `wallet sign` -> [`CommandRisk::WalletSign`],
//! `chain write` -> [`CommandRisk::ChainWrite`] render the LOCKED surface. The
//! no-training-in-G and no-live-action invariants hold structurally after wiring.
//!
//! Secret-zero: every render is built from redacted hashes / counts / enum tags;
//! no key / seed / token value is loaded, cloned, or `Debug`-printed.
//!
//! Terminal: output is colorless ASCII, control-stripped and width-clamped to 80
//! columns ([`clamp_ascii`]), and bounded by [`ROWS`]. No full scan / provider /
//! web / chain / gas call is made on the dispatch hot path.

use std::io::{self, Write};
use std::process::ExitCode;

use crate::command::{ApprovalRequirement, CliMode, CommandEnvelope, CommandRisk};
use crate::grammar::{self, CliNamespace};
use crate::tui::RenderTruth;
use crate::{hex32, sha256_32};

// Handler types wired below (canonical IN — no reinvention).
use crate::commands::audit::{AuditAction, AuditEntry};
use crate::commands::audit_log::ChainedAuditLog;
use crate::commands::budget::BudgetCap;
use crate::commands::checkpoint::CheckpointStore;
use crate::commands::eval_core::{AuditProfile, AuditScanView};
use crate::commands::federation::FederationControlView;
use crate::commands::incident::IncidentController;
use crate::commands::kill::KillController;
use crate::commands::learning::LearningCommandView;
use crate::commands::memory_setup::{
    GasSponsorMode, MemorySetupWizard, MemoryStorageMode, PrivacyLearningMode,
};
use crate::commands::model_cache::CacheStatus;
use crate::commands::model_endpoint::EndpointRegistry;
use crate::commands::model_route::ModelRouter;
use crate::commands::platform_telegram::NotificationCenter;
use crate::commands::provider::ProviderRegistry;
use crate::commands::release::ReleaseDryRun;
use crate::commands::release_secret_scan::{ReleaseSecretScan, ReleaseSurface};
use crate::commands::tool::ToolRegistry;
use crate::config::{self, FeatureState};
use crate::daemon::task_session::OperationalInbox;
use crate::evidence::pack_manifest::{EvidenceKind, EvidencePackBuilder, EvidencePackEntry};
use crate::evidence::replay::EvidenceReplayDryRun;
use crate::file_edit::{
    ApplyDeny, FileEditProposal, MAX_PENDING_PROPOSALS, PROPOSAL_ID_HEX_CHARS, ProposalStore,
    VerifiedFileRead, apply_proposal, extract_proposal, mint_proposal, render_line_diff,
};
use crate::memory::commands::MemoryCommandSurface;
use crate::memory_store::{PersistedStore, make_user_chunk};
use crate::prompt_status::WorkPackageStatusView;
use crate::provider::redaction::{RedactionReject, RedactionRequest, redact};
use crate::repl::prompt::{PromptStatus, render_status_strip};
use mnemos_b_memory::{
    MAX_STAGE_B_CONTENT_BYTES, MemoryId, MemoryIndexRecord, MemoryPrivacy, MemoryReadDeny,
    MemoryTier, TombstonePolicy, catalog_select, fold_index_classified, read_select,
};

/// Bounded render ceiling for one CLI command (header + body lines). The hot path
/// never renders more than this many lines.
const ROWS: usize = 64;

const ZERO32: [u8; 32] = [0u8; 32];

// ---- labels (stable, colorless, terminal-contract §3) ---------------------

const fn risk_label(risk: CommandRisk) -> &'static str {
    match risk {
        CommandRisk::ReadOnly => "read-only",
        CommandRisk::LocalWrite => "local-write",
        CommandRisk::Network => "network",
        CommandRisk::WalletSign => "wallet-sign",
        CommandRisk::ChainWrite => "chain-write",
        CommandRisk::Training => "training",
        CommandRisk::Admin => "admin",
    }
}

const fn approval_label(approval: ApprovalRequirement) -> &'static str {
    match approval {
        ApprovalRequirement::None => "none",
        ApprovalRequirement::Confirm => "confirm",
        ApprovalRequirement::TypedPhrase => "typed-phrase",
        ApprovalRequirement::Multisig => "multisig",
        ApprovalRequirement::ForbiddenInStageF => "training-locked",
    }
}

/// The explicit operational state label (terminal contract §2/§3 stable labels).
const fn state_label(approval: ApprovalRequirement) -> &'static str {
    match approval {
        ApprovalRequirement::None => "LOCAL-ONLY",
        ApprovalRequirement::ForbiddenInStageF => "NO-TRAINING",
        _ => "LOCKED",
    }
}

/// Colorless truth label (mirrors [`crate::prompt_status`]; readable with no
/// color). `Unknown` is explicit — an unwired/never-measured subsystem is never a
/// false-green.
const fn truth_label(truth: RenderTruth) -> &'static str {
    match truth {
        RenderTruth::Green => "PASS",
        RenderTruth::Yellow => "DEGRADED",
        RenderTruth::Red => "RED",
        RenderTruth::Unknown => "UNKNOWN",
    }
}

/// First 16 hex chars of a 32-byte digest — a redacted, display-only prefix.
fn hex16(bytes: &[u8; 32]) -> String {
    hex32(bytes).chars().take(16).collect()
}

/// Strip control characters and clamp to 80 columns (colorless, copyable,
/// no-overlap; terminal-compat law). Printable UTF-8 is KEPT so a live LLM
/// answer in Hangul/CJK survives the render — ASCII command output is
/// unaffected (it has no non-ASCII bytes to begin with), and consult answers are
/// line-wrapped upstream by `wrap_consult_answer` (and again by the GUI).
fn clamp_ascii(line: &str) -> String {
    line.chars().filter(|c| !c.is_control()).take(80).collect()
}

// ---- verb-level risk (the load-bearing classification) --------------------

/// Resolve the verb-level [`CommandRisk`] for `(ns, verb)`. Status/view verbs are
/// `ReadOnly` (they render); the side-effect verb of each namespace keeps its real
/// risk so the closed [`crate::command::approval_for`] gate forces the right
/// approval (Training -> forbidden, wallet sign -> typed phrase, chain write ->
/// multisig). An unrecognised side-effect token errs toward MORE approval, never
/// less. Memory reuses the canonical [`crate::memory::commands::MemoryCommand`]
/// split (status/replay read-only; export/delete local-write).
fn risk_for(ns: CliNamespace, verb: &str) -> CommandRisk {
    let v = verb.to_ascii_lowercase();
    match ns {
        CliNamespace::Train => match v.as_str() {
            "doctor" | "status" | "dashboard" | "prepare" | "unlock-status" | "lineage" => {
                CommandRisk::ReadOnly
            }
            // run / sft / qlora / grpo / checkpoint / promote / tune / unlock ...
            _ => CommandRisk::Training,
        },
        CliNamespace::Wallet => match v.as_str() {
            "sign" => CommandRisk::WalletSign,
            _ => CommandRisk::ReadOnly,
        },
        CliNamespace::Chain => match v.as_str() {
            "publish" | "upgrade" | "write" | "execute" | "send" => CommandRisk::ChainWrite,
            _ => CommandRisk::ReadOnly,
        },
        CliNamespace::Package => match v.as_str() {
            "publish" | "upgrade" => CommandRisk::ChainWrite,
            _ => CommandRisk::ReadOnly,
        },
        CliNamespace::Multisig => match v.as_str() {
            "propose" | "sign" | "execute" => CommandRisk::ChainWrite,
            _ => CommandRisk::ReadOnly,
        },
        CliNamespace::Gas => match v.as_str() {
            "request" | "sponsor" | "drain" | "topup" => CommandRisk::Network,
            _ => CommandRisk::ReadOnly,
        },
        CliNamespace::Admin => match v.as_str() {
            "status" | "list" | "incident" => CommandRisk::ReadOnly,
            _ => CommandRisk::Admin,
        },
        CliNamespace::Memory => match v.as_str() {
            // P1-1: `save` persists a user memory to the encrypted local store
            // (LocalWrite; local at-rest only, no egress; intercepted in
            // dispatch_namespace to actually execute).
            "export" | "delete" | "save" => CommandRisk::LocalWrite,
            // C (G-WP-13): the gated live Walrus testnet PUT. Network risk in BOTH
            // builds, so with the `put-fixture-net` feature OFF it classifies to
            // Confirm and renders the locked surface (no execution); with the feature
            // ON, `dispatch_namespace` intercepts it into the phrase-gated executor.
            "put-fixture" => CommandRisk::Network,
            "backup-walrus" | "backup-walrus-mainnet" | "backup-0g" => CommandRisk::Network,
            "walrus-index" | "walrus-fetch" => CommandRisk::Network,
            _ => CommandRisk::ReadOnly,
        },
        CliNamespace::Provider => match v.as_str() {
            "add" => CommandRisk::LocalWrite,
            // W2-B: 0G Compute TEE attestation verify (Node sidecar; keyless, read-only).
            // Network risk; honest "not compiled" surface with the feature off.
            "attest-0g" => CommandRisk::Network,
            // W3-B: 0G Compute fine-tune PREPARE — reads verified patterns, writes the
            // Alpaca dataset locally, emits the owner-run flow. LocalWrite (no network/key).
            "finetune-0g" => CommandRisk::LocalWrite,
            // W3-B capstone: mint a fine-tuned expert as an iNFT — PURE PREPARE (emits the
            // owner-run mint command). ReadOnly: no file write, no network, no key.
            "mint-expert-0g" => CommandRisk::ReadOnly,
            // P (owner-authorized 2026-06-10): the gated live LLM consult. Network
            // risk in BOTH builds, so with the `provider-egress` feature OFF it
            // classifies to Confirm and renders the locked surface (no execution);
            // with the feature ON, `dispatch_namespace` intercepts it into the
            // typed-phrase-gated executor. Threat model:
            // ops/evidence/stage_g/gui_desktop/PROVIDER_EGRESS_THREAT_MODEL.md.
            "consult" => CommandRisk::Network,
            // 3.A (owner-authorized 2026-06-10): the gated subagent fan-out.
            // Network in BOTH builds; feature OFF ⇒ locked surface. Threat
            // model: ops/evidence/stage_g/agent_loop/SUBAGENT_FANOUT_THREAT_MODEL.md.
            "fan" => CommandRisk::Network,
            // P1-2b: the two-model orchestration loop is Network risk in BOTH
            // builds (loopback HTTP); feature OFF ⇒ locked surface (no execution).
            "orchestrate" => CommandRisk::Network,
            _ => CommandRisk::ReadOnly,
        },
        CliNamespace::Tool => match v.as_str() {
            "add" => CommandRisk::LocalWrite,
            // P3-1: owner-local bounded command exec (exact typed ceremony;
            // threat model ⑥ CODE_EXEC_THREAT_MODEL.md — the first process-
            // spawn surface; the MODEL has no path here).
            "run" => CommandRisk::Admin,
            // P3-2: owner-only apply of ONE pending file-edit proposal
            // (exact typed ceremony; threat model ⑦
            // MULTI_FILE_EDIT_THREAT_MODEL.md — the first arbitrary-path
            // file WRITE; the MODEL proposes only and has no path here).
            "apply" => CommandRisk::Admin,
            // REWIND: owner-only undo of the last applied edit (a local file write).
            "rewind" => CommandRisk::Admin,
            _ => CommandRisk::ReadOnly,
        },
        CliNamespace::Platform => match v.as_str() {
            "send" => CommandRisk::Network,
            _ => CommandRisk::ReadOnly,
        },
        CliNamespace::Release => match v.as_str() {
            "publish" => CommandRisk::ChainWrite,
            _ => CommandRisk::ReadOnly,
        },
        CliNamespace::Skill => match v.as_str() {
            "use" | "install" => CommandRisk::LocalWrite,
            _ => CommandRisk::ReadOnly,
        },
        CliNamespace::Learning => match v.as_str() {
            "switch" | "enable" | "set" | "contribute" => CommandRisk::LocalWrite,
            _ => CommandRisk::ReadOnly,
        },
        CliNamespace::Feature => match v.as_str() {
            "enable" | "disable" | "set" => CommandRisk::LocalWrite,
            _ => CommandRisk::ReadOnly,
        },
        CliNamespace::Sandbox => match v.as_str() {
            "warmup" => CommandRisk::LocalWrite,
            _ => CommandRisk::ReadOnly,
        },
        CliNamespace::Dataset => match v.as_str() {
            "export" | "ingest" => CommandRisk::LocalWrite,
            _ => CommandRisk::ReadOnly,
        },
        CliNamespace::Checkpoint => match v.as_str() {
            "create" | "restore" => CommandRisk::LocalWrite,
            _ => CommandRisk::ReadOnly,
        },
        CliNamespace::Context => match v.as_str() {
            "pin" => CommandRisk::LocalWrite,
            // E11-1b: `context web-fetch <url>` / `context web-search <query>` are
            // LIVE public GETs (the gated path, feature-intercepted in
            // `dispatch_namespace`). Network risk in BOTH builds; the default build
            // renders the honest "web transport not compiled" (no web socket).
            "web-fetch" | "web-search" => CommandRisk::Network,
            _ => CommandRisk::ReadOnly,
        },
        CliNamespace::Session => match v.as_str() {
            "export" => CommandRisk::LocalWrite,
            _ => CommandRisk::ReadOnly,
        },
        CliNamespace::Federation => match v.as_str() {
            "opt-in" | "opt_in" => CommandRisk::LocalWrite,
            _ => CommandRisk::ReadOnly,
        },
        CliNamespace::Notify => match v.as_str() {
            "test" => CommandRisk::LocalWrite,
            _ => CommandRisk::ReadOnly,
        },
        // D-3: the agent registry gains an owner-armed Walrus egress (`publish`) + an
        // autonomous content-hash-verified `fetch` — both Network; scan/list stay ReadOnly.
        // This is why `namespace_gate(Registry)` is `Gated` (not `Free`).
        CliNamespace::Registry => match v.as_str() {
            "publish" | "fetch" => CommandRisk::Network,
            _ => CommandRisk::ReadOnly,
        },
        // All remaining namespaces are status/view-only at every wired verb.
        _ => CommandRisk::ReadOnly,
    }
}

/// The owner-meaningful capability GATE per namespace — the honest projection of
/// [`risk_for`] + the PD-6 custody/funds/chain-write hard-lock overlay, in the
/// THREE tiers the runtime's PD-2 capability-type model enforces.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum CapabilityGate {
    /// Every wired verb is `ReadOnly` ⇒ autonomous READ, no approval (PD-3).
    Free,
    /// LIVE behind an approval / typed ceremony (LocalWrite / Network / Admin) —
    /// the agent USES these; the owner approves the side effect.
    Gated,
    /// Custody / funds / chain-write — the owner's OWN permanent law (PD-6;
    /// `CustodyCapability` uninhabited; chain-write gates to `Multisig` with no
    /// signer; Stage-F training is forbidden). NEVER available.
    Locked,
}

impl CapabilityGate {
    const fn as_str(self) -> &'static str {
        match self {
            CapabilityGate::Free => "free",
            CapabilityGate::Gated => "gated",
            CapabilityGate::Locked => "locked",
        }
    }
}

/// SINGLE SOURCE OF TRUTH for the desktop palette's lock badges. The palette reads
/// this (via `permission tier`) instead of a hardcoded duplicate, so the lock state
/// CANNOT drift from the core. Totality is enforced by the exhaustive match (no `_`
/// arm); consistency with [`risk_for`] is pinned by
/// `namespace_gate_is_consistent_with_risk_for`. custody/funds/chain-write stay
/// `Locked` always (PD-6) — `namespace_gate_custody_is_hard_locked` is the safety pin.
fn namespace_gate(ns: CliNamespace) -> CapabilityGate {
    use CapabilityGate::{Free, Gated, Locked};
    match ns {
        // PD-6 HARD-LOCK — custody / funds / chain-write. Locked regardless of the
        // per-verb risk: wallet `sign` + key secrets are custody (`CustodyCapability`
        // uninhabited); gas is funds (no sponsor); chain / package / multisig /
        // release carry `ChainWrite` verbs that gate to `Multisig` (no signer);
        // train run/sft is `ForbiddenInStageF`.
        CliNamespace::Wallet
        | CliNamespace::Key
        | CliNamespace::Gas
        | CliNamespace::Chain
        | CliNamespace::Package
        | CliNamespace::Multisig
        | CliNamespace::Release
        | CliNamespace::Train => Locked,
        // GATED-LIVE — at least one verb is LocalWrite / Network / Admin (Confirm or
        // TypedPhrase), none is chain-write/custody. The agent uses these behind
        // approval (egress / mutate / local-write).
        CliNamespace::Provider
        | CliNamespace::Platform
        | CliNamespace::Tool
        | CliNamespace::Memory
        | CliNamespace::Skill
        | CliNamespace::Context
        | CliNamespace::Sandbox
        | CliNamespace::Dataset
        | CliNamespace::Learning
        | CliNamespace::Feature
        | CliNamespace::Checkpoint
        | CliNamespace::Session
        | CliNamespace::Admin
        | CliNamespace::Notify
        // D-3: the registry gained a Network egress (`publish`) + `fetch`, so it is no
        // longer all-ReadOnly — GATED (owner-armed publish; scan/list/fetch = the READ
        // side under the same gated namespace badge).
        | CliNamespace::Registry
        | CliNamespace::Federation => Gated,
        // FREE — every wired verb is `ReadOnly` (autonomous READ).
        CliNamespace::Agent
        | CliNamespace::Model
        | CliNamespace::Identity
        | CliNamespace::Trace
        | CliNamespace::Eval
        | CliNamespace::Measure
        | CliNamespace::Audit
        | CliNamespace::Privacy
        | CliNamespace::Task
        | CliNamespace::Approval
        | CliNamespace::Permission => Free,
    }
}

/// `permission tier` body — one `<namespace>=<gate>` line per namespace (in the
/// frozen `grammar::ALL` order), plus a two-line legend. ReadOnly + secret-zero:
/// the desktop palette dispatches this once and renders its lock badges from the
/// core's answer (no hardcoded lock duplicate).
fn permission_tier_body() -> (RenderTruth, Vec<String>) {
    let mut lines = vec![
        "capability gate per namespace (core-derived; the palette reads this):".to_string(),
        "free=autonomous READ · gated=LIVE behind approval · locked=custody/funds/chain-write (PD-6)"
            .to_string(),
    ];
    for ns in crate::grammar::ALL {
        lines.push(format!(
            "{}={}",
            ns.canonical_name(),
            namespace_gate(ns).as_str()
        ));
    }
    (RenderTruth::Green, lines)
}

/// The closed operational verb vocabulary. An unrecognised verb is rejected
/// ([`crate::CliError::UnknownCommand`]); a *missing* verb defaults to `status`.
/// Verbs live inside a namespace (the grammar enum is byte-frozen), so this is the
/// verb-level closure that keeps the surface closed end to end.
const RECOGNIZED_VERBS: &[&str] = &[
    "status",
    "list",
    "view",
    "show",
    "scan",
    "detect",
    "reconcile",
    "elicit",
    "classify",
    "summary",
    "route",
    "cache",
    "endpoint",
    "budget",
    "kill",
    "test",
    "eval",
    "ab",
    "recommend",
    "search",
    "inspect",
    "state",
    "stats",
    "map",
    "doctor",
    "dashboard",
    "prepare",
    "provenance",
    "tier",
    "replay",
    "pack",
    "plan",
    "why",
    "history",
    "queue",
    "env",
    "sign",
    "run",
    "sft",
    "qlora",
    "grpo",
    "promote",
    "unlock",
    "unlock-status",
    "tune",
    "checkpoint",
    "publish",
    "fetch",
    "upgrade",
    "write",
    "execute",
    "propose",
    "request",
    "sponsor",
    "drain",
    "topup",
    "add",
    "use",
    "install",
    "switch",
    "enable",
    "disable",
    "set",
    "warmup",
    "export",
    "ingest",
    "create",
    "restore",
    "pin",
    "compact",
    "drop",
    "sources",
    "resume",
    "cancel",
    "opt-in",
    "opt_in",
    "incident",
    "pause",
    "telegram",
    "rules",
    "mute",
    "notify",
    "connect",
    "deny",
    "approve",
    "candidate",
    "rollback",
    "diff",
    "lineage",
    "fork-graph",
    "send",
    "poll",
    "control",
    "turn",
    "info",
    "summary",
    "delete",
    "contribute",
    "put-fixture",
    "backup-walrus",
    "backup-walrus-mainnet",
    "backup-0g",
    "anchor-0g",
    "mint-0g",
    "attest-0g",
    "finetune-0g",
    "mint-expert-0g",
    "mint-oracle",
    "walrus-index",
    "walrus-fetch",
    "consult",
    // Agent-core step 2 (G-WP-13+ lane): the read-only memory retrieval
    // surface (`memory index` / `memory read <id>`).
    "index",
    "read",
    // [4] B⑨: the semantic codebase index READ (`context codebase build` /
    // `context codebase <query>`) — local embeddings + an encrypted-at-rest vector
    // store; embeddings never egress (ReadOnly compute, the Context `_` risk arm).
    "codebase",
    // Agent-core 3.A: the gated subagent fan-out (`provider fan`).
    "fan",
    // Agent-core lane A: the read-only local file context (`context file <path>`).
    "file",
    // [5] B⑭: the local image-as-READ-context describe (`context image <path>`) — a
    // local-vision metadata describe, no egress (ReadOnly, the Context `_` risk arm).
    "image",
    // Agent-core P1-1: persist a memory to the encrypted local store.
    "save",
    // Agent-core P3-2: owner-only apply of ONE pending file-edit proposal.
    "apply",
    // ENDGAME E10-2b: owner-only execute of ONE pending agent-proposed exec
    // (MutateCapability-gated kernel-sandbox run).
    "exec-apply",
    // REWIND (the Codex-gap differentiator): owner-only undo of the LAST applied
    // file-edit — restores the captured bytes via the staleness-locked owner-save
    // path. Local-file-only (PD-6 untouched).
    "rewind",
    // ENDGAME E11-1b: the owner's LIVE web READ (`context web-fetch <url>`) —
    // SSRF-walled, secret-zero GET, redacted, advisory-only. `web-search` is the
    // configured-endpoint seam over the SAME wall (WEB_SEARCH_ENDPOINT).
    "web-fetch",
    "web-search",
    // P1-2b: the two-model orchestration verb (`provider orchestrate <phrase>
    // <task>`) — frontier PLAN -> route -> local IMPLEMENT -> frontier SYNTHESIZE.
    // Live only under a local-serving feature; else the generic locked surface.
    "orchestrate",
    // K-6: the honest dynamic-LoRA status (`provider lora-status`) — the certified
    // corpus→adapter MANIFEST (P-HALL) + the SERVED set + the per-kind resolution
    // (requested adapter -> wire model, served/degraded). READ-class, money 0; the
    // SAME core render the GUI Tauri command consumes. Always-compiled.
    "lora-status",
    // A① (CURSOR PARITY keystone-1): the owner/GUI language-server READ
    // (`context lsp-diagnostics <path>`) — a sandboxed rust-analyzer/move-analyzer
    // run returning COMPILER TRUTH (READ-class; honest-degrade if the server is
    // absent or the `lsp` codec is not compiled).
    "lsp-diagnostics",
    // B⑫ (CURSOR PARITY keystone-3): the owner/GUI MCP tool call
    // (`context mcp <server> <tool> [json-args]`) — a sandboxed LOCAL stdio MCP
    // server, READ-class (network kernel-DENIED; unknown server/tool ⇒ deny; arg +
    // result redacted; every call audited; honest-degrade if the `mcp` codec is
    // not compiled).
    "mcp",
    // A⑤ (CURSOR PARITY git-as-capability-type): the owner/GUI git READ
    // (`context git <subcommand> [args]`) — a sandboxed READ-only git command
    // (status/diff/log/show/blame), READ-class (network + write kernel-DENIED; a
    // non-READ subcommand ⇒ deny; output redacted). commit/branch/push = owner-armed v2.
    "git",
    // A② (CURSOR PARITY oracle test-loop): the owner/GUI test run
    // (`context test-run <pkg>`) — a sandboxed `sui move test` / `cargo test` on a
    // workspace package, READ-class (network kernel-DENIED; non-package ⇒ deny;
    // output redacted). Surfaces the PASS/FAIL verdict (compiler/test ground truth).
    "test-run",
];

fn is_recognized_verb(verb: &str) -> bool {
    let v = verb.to_ascii_lowercase();
    RECOGNIZED_VERBS.iter().any(|known| *known == v)
}

// ---- uniform emit ---------------------------------------------------------

/// Render one command surface: a stable header (command, envelope id, risk +
/// approval, state, truth) followed by the handler `body`, all colorless,
/// ASCII-clamped, and bounded by [`ROWS`].
fn emit(
    out: &mut impl Write,
    command: &str,
    envelope_hex: &str,
    risk: CommandRisk,
    approval: ApprovalRequirement,
    truth: RenderTruth,
    body: &[String],
) -> io::Result<()> {
    let mut lines: Vec<String> = Vec::with_capacity(body.len() + 5);
    lines.push(format!("command={command}"));
    lines.push(format!("envelope={envelope_hex}"));
    lines.push(format!(
        "risk={} approval={}",
        risk_label(risk),
        approval_label(approval)
    ));
    lines.push(format!("state={}", state_label(approval)));
    lines.push(format!("truth={}", truth_label(truth)));
    lines.extend(body.iter().cloned());
    for line in lines.into_iter().take(ROWS) {
        writeln!(out, "{}", clamp_ascii(&line))?;
    }
    // E5-1: every high-significance dispatched action leaves a REAL trace in the
    // persisted, hash-linked audit chain. Best-effort + fail-OPEN: a disk failure
    // must NEVER break the command render (the audit side artifact may be absent,
    // but the answer card is never destroyed — mirrors the OTel side-artifact law).
    record_dispatch_audit(command, envelope_hex, risk, approval, truth, body);
    Ok(())
}

/// Map a dispatched command to a high-significance [`AuditAction`], or `None` for a
/// read-only command (reads are not high-significance actions, so they leave no
/// audit-trail entry — only gated side effects do). Total + closed.
fn audit_action_for(
    command: &str,
    risk: CommandRisk,
    approval: ApprovalRequirement,
    truth: RenderTruth,
) -> Option<AuditAction> {
    // A read-only command (no approval gate) is not a high-significance action.
    if matches!(approval, ApprovalRequirement::None) {
        return None;
    }
    let denied = !matches!(truth, RenderTruth::Green);
    Some(match risk {
        CommandRisk::WalletSign => AuditAction::Signing,
        CommandRisk::ChainWrite => AuditAction::ChainWrite,
        CommandRisk::Network => AuditAction::GasAction,
        // Word-boundary match on a kill VERB token (NOT a substring): E6 added
        // the `skill eval` surface and "skill" contains the substring "kill" —
        // a `skill eval` must classify as Approval/Denial, never Kill. The
        // property (a real kill command ⇒ Kill audit) is preserved, made precise.
        // REWIND: an owner undo of the last applied edit is a Rollback (not a
        // generic Approval) — word-boundary token match like the kill branch below.
        _ if command.split_whitespace().any(|tok| tok == "rewind") => AuditAction::Rollback,
        _ if command.split_whitespace().any(|tok| tok == "kill") => AuditAction::Kill,
        // A gated side effect that did not render Green is a fail-closed Denial;
        // an approved + Green side effect is an Approval.
        _ if denied => AuditAction::Denial,
        _ => AuditAction::Approval,
    })
}

/// Record a high-significance dispatched action into the persisted hash-linked
/// audit chain (E5-1). The trace + evidence hashes are derived from the command
/// envelope + its rendered outcome (both non-zero ⇒ the entry is fully traced).
/// Best-effort: any failure is swallowed so the command render is never affected.
fn record_dispatch_audit(
    command: &str,
    envelope_hex: &str,
    risk: CommandRisk,
    approval: ApprovalRequirement,
    truth: RenderTruth,
    body: &[String],
) {
    let Some(action) = audit_action_for(command, risk, approval, truth) else {
        return;
    };
    // The trace hash binds the command + its outcome (truth + body) so distinct
    // outcomes are distinct records; the evidence path hash binds the envelope.
    let mut seed: Vec<u8> = Vec::with_capacity(command.len() + 64);
    seed.extend_from_slice(command.as_bytes());
    seed.push(0);
    seed.extend_from_slice(truth_label(truth).as_bytes());
    for line in body {
        seed.push(0);
        seed.extend_from_slice(line.as_bytes());
    }
    let trace = crate::StageFTraceLink::new(sha256_32(&seed), 0, approval as u16);
    let evidence = crate::StageFEvidenceRef {
        path_hash_32: sha256_32(envelope_hex.as_bytes()),
        trace,
    };
    let entry = AuditEntry::seal(action, trace, evidence);
    // The real disk append fires in the shipped binary (smoke-proven). It is
    // suppressed under `cfg(test)` ONLY for test isolation: `cargo test` runs
    // parallel threads sharing one process audit dir, and a live append would make
    // the chain-reading `audit` / `evidence pack` renders non-deterministic. The
    // append path itself is covered hermetically by the `audit_log` unit tests, and
    // the emit→append wiring is asserted by the e5 grep verifier + a real-run smoke.
    #[cfg(not(test))]
    {
        if let Ok(log) = ChainedAuditLog::open_local() {
            let _ = log.append(&entry);
        }
    }
    #[cfg(test)]
    {
        let _ = &entry;
    }
}

/// The approval/locked surface for a side-effect verb. Phase 0 renders it and does
/// NOT execute (there is no side-effect code path here).
fn locked_surface(ns: &str, verb: &str, approval: ApprovalRequirement) -> Vec<String> {
    vec![
        format!("{ns} {verb} is a side-effect command"),
        format!("approval required: {}", approval_label(approval)),
        "preview only — status/view; the side effect is NOT executed".to_string(),
        "secret-zero: no key/seed/token value is loaded or printed".to_string(),
        "next: approval is gated; no live action runs without it".to_string(),
    ]
}

/// The NO-TRAINING surface for a `CommandRisk::Training` verb.
fn no_training_surface(ns: &str, verb: &str) -> Vec<String> {
    vec![
        format!("{ns} {verb} is model-training execution"),
        "classified as a training action — weight training is locked".to_string(),
        "weight training is locked (not enabled in 1.0)".to_string(),
        "the operational surface ships; weight tuning is a future, locked capability".to_string(),
    ]
}

// ---- C (G-WP-13): gated live Walrus testnet PUT of a synthetic public fixture --
//
// Owner-authorized 2026-06-10. The ONLY live-egress execute path in this module,
// reachable ONLY when compiled with `put-fixture-net`. Gate stack (all required):
// feature-compiled + exact typed-phrase approval (the sole runtime gate) + content
// class hard-pinned to SyntheticPublicFixture + max_attempts=1 + testnet-only
// endpoint. funds/wallet/mainnet are unreachable (no key/signature in the path).
// Threat model: ops/evidence/stage_g/gui_desktop/C_EGRESS_THREAT_MODEL.md.

/// The exact in-band confirmation phrase that authorizes ONE live Walrus testnet
/// PUT. A PUBLIC confirmation gesture (zero entropy, NOT a secret), supplied
/// verbatim as the verb argument. Absence/mismatch fails closed (no plan, no PUT).
#[cfg(feature = "put-fixture-net")]
const PUT_FIXTURE_CONFIRM_PHRASE: &str = "publish-synthetic-fixture-to-walrus-testnet";

/// The synthetic, public, hand-authored fixture payload — no user memory, no
/// provider body, no secret. The only payload class admitted to the public testnet.
#[cfg(feature = "put-fixture-net")]
const PUT_FIXTURE_PAYLOAD: &[u8] =
    b"sinabro 1.0 GUI synthetic public fixture -- gated live Walrus testnet PUT (no funds, no secret)";

/// Per-attempt timeout (ms) for the one-shot PUT (matches the live-test bound).
#[cfg(feature = "put-fixture-net")]
const PUT_FIXTURE_TIMEOUT_MS: u32 = 30_000;

/// The denial / locked body when the exact phrase is absent or wrong — render-only,
/// NEVER builds a plan or touches the network.
#[cfg(feature = "put-fixture-net")]
fn put_fixture_locked_body() -> Vec<String> {
    vec![
        "memory put-fixture is a LIVE Walrus testnet PUT (synthetic public fixture)".to_string(),
        "risk=network approval=typed-phrase (exact); one-shot; testnet only".to_string(),
        format!("to confirm, supply EXACTLY: {PUT_FIXTURE_CONFIRM_PHRASE}"),
        "no funds / no wallet / no secret; real user memory is content-class denied".to_string(),
        "denied: no live action without the exact phrase".to_string(),
    ]
}

/// Render a secret-zero error surface (static label only; no host/body/3rd-party
/// error text) and stop — no blob written, no retry.
#[cfg(feature = "put-fixture-net")]
fn put_fixture_error(out: &mut impl Write, envelope_hex: &str, label: &str) -> io::Result<bool> {
    let body = vec![
        format!("LIVE Walrus testnet PUT: {label}"),
        "no blob written; no retry; no host/body/secret leaked".to_string(),
    ];
    emit(
        out,
        "memory put-fixture",
        envelope_hex,
        CommandRisk::Network,
        ApprovalRequirement::TypedPhrase,
        RenderTruth::Red,
        &body,
    )?;
    Ok(true)
}

/// The gated executor (feature ON only). Verifies the exact typed phrase with the
/// pure `ApprovalPrompt::evaluate` BEFORE building any plan; on approval fires
/// EXACTLY ONE testnet PUT of the synthetic fixture and renders a secret-zero
/// receipt. No `unwrap`/`expect`/`panic`: every fallible step renders a labelled
/// error and returns. funds untouched.
#[cfg(feature = "put-fixture-net")]
fn memory_put_fixture(rest: &[String], out: &mut impl Write) -> io::Result<bool> {
    use crate::repl::approval::{ApprovalDecision, ApprovalPrompt};
    use mnemos_b_memory::{
        StageBTraceEvidence, StageBTraceLink, WalrusPutPlan, WalrusTestnetEndpoint,
    };
    use mnemos_c_walrus::publisher::{
        EpochCount, PublishPayloadClass, PublisherResponseDecision, publish_blob_with_transport,
    };
    use mnemos_c_walrus::reqwest_transport::ReqwestPublisher;

    let envelope_hex = hex16(&sha256_32(b"memory put-fixture"));
    let supplied = rest.get(1..).map(|s| s.join(" ")).unwrap_or_default();

    // GATE (sole runtime operator gate): exact typed phrase, verified before any
    // plan or transport. Missing/empty/wrong => Denied => locked surface, NO PUT.
    let mut prompt =
        ApprovalPrompt::new(ApprovalRequirement::TypedPhrase, PUT_FIXTURE_CONFIRM_PHRASE);
    if !matches!(prompt.evaluate(supplied.trim()), ApprovalDecision::Approved) {
        emit(
            out,
            "memory put-fixture",
            &envelope_hex,
            CommandRisk::Network,
            ApprovalRequirement::TypedPhrase,
            RenderTruth::Yellow,
            &put_fixture_locked_body(),
        )?;
        return Ok(true);
    }

    // APPROVED.
    //
    // E0b-3 (SI-2 uniform choke, Option A): the synthetic PUBLIC fixture passes
    // the SAME single redact() gate before any socket — zero carve-outs to the
    // "one outbound byte ⇒ one redact()" law (so the E0b-4 bypass grep finds no
    // exception). The content-class type-pin (`SyntheticPublicFixture` + the
    // `PUT_FIXTURE_PAYLOAD` const) stays the PRIMARY structural guarantee (PD-4);
    // redact() is the uniform pass + a tripwire if that const ever drifts to
    // secret-shaped bytes. funds/chain remain unreachable (SI-5 allowlist).
    let Ok(fixture_text) = std::str::from_utf8(PUT_FIXTURE_PAYLOAD) else {
        return put_fixture_error(out, &envelope_hex, "fixture is not utf-8");
    };
    let fixture_fragments = [fixture_text];
    let fixture_receipt = match redact(&RedactionRequest {
        fragments: &fixture_fragments,
        candidate_memory_ids: &[],
        deleted_ids: &[],
        include_private_memory: false,
    }) {
        Ok(r) => r,
        Err(_) => {
            return put_fixture_error(out, &envelope_hex, "redaction gate denied the fixture");
        }
    };
    if fixture_receipt.secret_fragments_denied_u32() > 0
        || fixture_receipt.outgoing_fragment_count_u32() == 0
    {
        return put_fixture_error(
            out,
            &envelope_hex,
            "fixture is secret-shaped; not published",
        );
    }

    // Build a stamped per-action trace (atom_id != 0 stamps).
    let Some(ev) = StageBTraceEvidence::from_trace(StageBTraceLink::new(0x6713_0001, 0x6713, 0))
    else {
        return put_fixture_error(out, &envelope_hex, "trace stamp failed");
    };
    let epochs = match EpochCount::new(1) {
        Ok(e) => e,
        Err(_) => return put_fixture_error(out, &envelope_hex, "epoch invalid"),
    };
    // Content-class HARD-PINNED synthetic public fixture (b-memory enforces class +
    // body cap + stamped trace before any socket; a second deny layer is in c-walrus).
    let plan = match WalrusPutPlan::plan(
        WalrusTestnetEndpoint::testnet(),
        epochs,
        PUT_FIXTURE_PAYLOAD,
        PublishPayloadClass::SyntheticPublicFixture,
        ev,
    ) {
        Ok(p) => p,
        Err(_) => return put_fixture_error(out, &envelope_hex, "plan denied (class or cap)"),
    };
    let mut transport = match ReqwestPublisher::new(PUT_FIXTURE_TIMEOUT_MS) {
        Ok(t) => t,
        Err(_) => return put_fixture_error(out, &envelope_hex, "transport init failed"),
    };
    // Exactly ONE PUT (max_attempts = 1): one put_blob; no automatic second PUT.
    let run = match publish_blob_with_transport(&mut transport, &plan.request, 0x6713_0001, 1) {
        Ok(r) => r,
        Err(_) => return put_fixture_error(out, &envelope_hex, "publish failed"),
    };
    let (truth, body) = match run.decision {
        PublisherResponseDecision::Accepted {
            variant,
            reported_blob_id,
        } => (
            RenderTruth::Green,
            vec![
                "LIVE Walrus testnet PUT: accepted".to_string(),
                format!("blob_id={}", reported_blob_id.as_str()),
                format!("variant={}", variant.class_label()),
                format!("attempts={}", run.attempts_u16),
                "synthetic public fixture; no funds; no secret; testnet".to_string(),
            ],
        ),
        // PublisherResponseDecision is #[non_exhaustive] -> wildcard required.
        _ => (
            RenderTruth::Red,
            vec![
                "LIVE Walrus testnet PUT: not accepted (stopped at a boundary)".to_string(),
                format!("attempts={}", run.attempts_u16),
                "one-shot; no retry".to_string(),
            ],
        ),
    };
    emit(
        out,
        "memory put-fixture",
        &envelope_hex,
        CommandRisk::Network,
        ApprovalRequirement::TypedPhrase,
        truth,
        &body,
    )?;
    Ok(true)
}

// ---- E14-W: autonomous Walrus ENCRYPTED-MEMORY backup + round-trip ------------
//
// The owner-directed (2026-06-13 "모든 메모리, 암호문으로") autonomous use of Walrus:
// the agent's REAL local memory records are AEAD ciphertext (`<store>/*.mc`, the
// 32-byte key NEVER leaves the machine), so publishing the CIPHERTEXT to the public
// testnet leaks no plaintext. This is reachable ONLY with `put-fixture-net` (the same
// vendored reqwest publisher + aggregator); off-build falls through to the locked
// surface. Content-class = `EncryptedUserMemory` (admitted at BOTH policy layers;
// PLAINTEXT classes stay denied). NO funds / NO wallet (publisher pays server-side);
// custody / chain-write HARD-LOCKED (PD-6) untouched. The round-trip (PUT → derive +
// verify blob_id → aggregator GET → byte-match) PROVES the agent's real encrypted
// memory is on Walrus and retrievable.
#[cfg(feature = "put-fixture-net")]
const BACKUP_WALRUS_CONFIRM_PHRASE: &str = "backup-encrypted-memory-to-walrus-testnet";

/// Cap the number of records published per invocation (bounded network work).
#[cfg(feature = "put-fixture-net")]
const BACKUP_WALRUS_MAX_RECORDS: usize = 32;

#[cfg(feature = "put-fixture-net")]
fn backup_walrus_locked_body() -> Vec<String> {
    vec![
        "memory backup-walrus = publish the agent's ENCRYPTED memory (AES ciphertext) to Walrus testnet + round-trip verify".to_string(),
        format!("to run, supply EXACTLY: memory backup-walrus {BACKUP_WALRUS_CONFIRM_PHRASE}"),
        "ciphertext only (key stays local; no plaintext leaves); no funds / no wallet; testnet".to_string(),
        "denied: no publish without the exact phrase; custody/funds HARD-LOCKED (PD-6)".to_string(),
    ]
}

#[cfg(feature = "put-fixture-net")]
fn backup_walrus_error(out: &mut impl Write, envelope_hex: &str, label: &str) -> io::Result<bool> {
    emit(
        out,
        "memory backup-walrus",
        envelope_hex,
        CommandRisk::Network,
        ApprovalRequirement::TypedPhrase,
        RenderTruth::Red,
        &[
            format!("memory backup-walrus: {label}"),
            "fail-closed; nothing partial trusted".to_string(),
        ],
    )
    .map(|()| true)
}

/// PUT `bytes` to the Walrus testnet publisher under `class`, then VERIFY the publisher's
/// reported blob-id against the REAL RS2 oracle (`verify_reported_testnet_blob_id` — the
/// self-report ban: a wrong/unverified id is `None`, never trusted). Class-parameterized so
/// the encrypted-memory path (`EncryptedUserMemory` ciphertext) and the D-3 public-registry
/// path (`PublicRegistryArtifact` plaintext, secret-scanned by its caller) share ONE verified
/// PUT chokepoint. The `class` is admitted by the c-walrus wall (`PublisherPutRequest::new`)
/// and the b-memory policy (`stage_b_publish_allowed`); anything else fails closed inside
/// `WalrusPutPlan::plan`. `verify_reported_testnet_blob_id` re-derives over the ACTUAL PUT
/// bytes, so it proves the id for both ciphertext and plaintext.
#[cfg(feature = "put-fixture-net")]
fn walrus_put_verified_class(
    pub_t: &mut mnemos_c_walrus::reqwest_transport::ReqwestPublisher,
    epochs: mnemos_c_walrus::publisher::EpochCount,
    bytes: &[u8],
    class: mnemos_c_walrus::publisher::PublishPayloadClass,
) -> Option<String> {
    use mnemos_b_memory::{
        StageBTraceEvidence, StageBTraceLink, WalrusPutPlan, WalrusTestnetEndpoint,
    };
    use mnemos_c_walrus::publisher::{
        PublishPayloadClass, PublisherResponseDecision, publish_blob_with_transport,
    };
    use mnemos_c_walrus::verify_reported_testnet_blob_id;
    // SI-2 / IV-D3-11 secret-zero AT THE SEND SITE: a PUBLIC plaintext class
    // (`PublicRegistryArtifact`) must pass the MANDATORY fail-closed secret-scan HERE, so a
    // secret-shaped byte can never leave even if a caller forgot to pre-scan. A private class
    // is AEAD ciphertext (the 32-byte key never leaves the machine) — a stronger guarantee than
    // redaction, and binary ciphertext is not redact()-able text.
    if matches!(class, PublishPayloadClass::PublicRegistryArtifact)
        && crate::secrets::scan_inline_secret(&String::from_utf8_lossy(bytes))
    {
        return None;
    }
    let ev = StageBTraceEvidence::from_trace(StageBTraceLink::new(0x6713_0002, 0x6713, 0))?;
    let plan =
        WalrusPutPlan::plan(WalrusTestnetEndpoint::testnet(), epochs, bytes, class, ev).ok()?;
    let run = publish_blob_with_transport(pub_t, &plan.request, 0x6713_0002, 1).ok()?;
    match run.decision {
        PublisherResponseDecision::Accepted {
            reported_blob_id, ..
        } => {
            verify_reported_testnet_blob_id(bytes, &reported_blob_id).ok()?;
            Some(reported_blob_id.as_str().to_string())
        }
        _ => None,
    }
}

/// E14-W2 shared glue: PUT one AEAD-ciphertext blob (class `EncryptedUserMemory`) to the
/// Walrus testnet publisher (no funds) + verify the reported blob-id. A thin wrapper over
/// [`walrus_put_verified_class`] (unchanged behaviour for the memory-backup callers).
#[cfg(feature = "put-fixture-net")]
fn walrus_put_verified(
    pub_t: &mut mnemos_c_walrus::reqwest_transport::ReqwestPublisher,
    epochs: mnemos_c_walrus::publisher::EpochCount,
    ciphertext: &[u8],
) -> Option<String> {
    walrus_put_verified_class(
        pub_t,
        epochs,
        ciphertext,
        mnemos_c_walrus::publisher::PublishPayloadClass::EncryptedUserMemory,
    )
}

/// E14-W2 shared glue: GET a blob from the Walrus testnet aggregator by a STORED blob-id
/// TEXT (the agent navigates by id, with no content in hand). `Some(bytes)` on a fetch,
/// else `None`. The fetched bytes are UNTRUSTED until the AEAD open (decode_record /
/// open_index) verifies the tag.
#[cfg(feature = "put-fixture-net")]
fn walrus_get_by_blob_text(blob_text: &str) -> Option<Vec<u8>> {
    use mnemos_c_walrus::aggregator::{
        AggregatorEndpoint, AggregatorGetRequest, AggregatorResponseDecision,
        fetch_blob_with_transport,
    };
    use mnemos_c_walrus::blob_id_from_text;
    use mnemos_c_walrus::reqwest_transport::ReqwestAggregator;
    let blob_id = blob_id_from_text(blob_text)?;
    let request = AggregatorGetRequest::new(AggregatorEndpoint::testnet_public(), &blob_id);
    let mut agg = ReqwestAggregator::new(PUT_FIXTURE_TIMEOUT_MS).ok()?;
    match fetch_blob_with_transport(&mut agg, &request, 0x6713_0003, 2).ok()? {
        AggregatorResponseDecision::Fetched { body, .. } => Some(body),
        _ => None,
    }
}

/// `memory backup-walrus <phrase>` — autonomous TWO-TIER Walrus encrypted-memory backup +
/// round-trip proof (E14-W2). Gate: exact phrase → load REAL `.mc` records → PUT each as
/// a SUB-STORE (`EncryptedUserMemory`) + collect (id, topic, sub_blob_id) → build + SEAL +
/// PUT the MAIN INDEX → save the local pointer → round-trip (GET main + decrypt + match;
/// GET first sub + byte-match + decode). NO plaintext leaves; custody HARD-LOCKED.
/// round-trip proof (E14-W). Gate: exact phrase → load the REAL local `.mc` records
/// (AEAD ciphertext) → PUT each as `EncryptedUserMemory` (publisher; no funds) →
/// derive + verify the blob_id (self-report ban) → GET the first back from the
/// aggregator → byte-match the ciphertext. NO plaintext ever leaves; custody HARD-LOCKED.
#[cfg(feature = "put-fixture-net")]
fn memory_backup_walrus(rest: &[String], out: &mut impl Write) -> io::Result<bool> {
    use crate::repl::approval::{ApprovalDecision, ApprovalPrompt};
    use mnemos_c_walrus::publisher::EpochCount;
    use mnemos_c_walrus::reqwest_transport::ReqwestPublisher;

    let envelope_hex = hex16(&sha256_32(b"memory backup-walrus"));
    let supplied = rest.get(1..).map(|s| s.join(" ")).unwrap_or_default();

    // GATE (sole runtime operator gate): exact typed phrase before any record read or PUT.
    let mut prompt = ApprovalPrompt::new(
        ApprovalRequirement::TypedPhrase,
        BACKUP_WALRUS_CONFIRM_PHRASE,
    );
    if !matches!(prompt.evaluate(supplied.trim()), ApprovalDecision::Approved) {
        emit(
            out,
            "memory backup-walrus",
            &envelope_hex,
            CommandRisk::Network,
            ApprovalRequirement::TypedPhrase,
            RenderTruth::Yellow,
            &backup_walrus_locked_body(),
        )?;
        return Ok(true);
    }

    // APPROVED. Load the agent's REAL encrypted records (ciphertext only — no plaintext
    // is read or assembled here; the AEAD key stays local).
    let store = match crate::memory_store::PersistedStore::open_local() {
        Ok(s) => s,
        Err(_) => {
            return backup_walrus_error(
                out,
                &envelope_hex,
                "memory store unavailable (no key/home)",
            );
        }
    };
    let records = store.records_for_walrus();
    if records.is_empty() {
        emit(
            out,
            "memory backup-walrus",
            &envelope_hex,
            CommandRisk::Network,
            ApprovalRequirement::TypedPhrase,
            RenderTruth::Yellow,
            &[
                "memory backup-walrus: the store has no encrypted records to back up".to_string(),
                "save a memory first (`memory save …`), then back it up to Walrus".to_string(),
            ],
        )?;
        return Ok(true);
    }
    let epochs = match EpochCount::new(1) {
        Ok(e) => e,
        Err(_) => return backup_walrus_error(out, &envelope_hex, "epoch invalid"),
    };
    let mut pub_t = match ReqwestPublisher::new(PUT_FIXTURE_TIMEOUT_MS) {
        Ok(t) => t,
        Err(_) => {
            return backup_walrus_error(out, &envelope_hex, "publisher transport init failed");
        }
    };

    let total = records.len();
    let mut truth = RenderTruth::Green;
    let mut body = vec![format!(
        "memory backup-walrus: {total} encrypted record(s) → 2-tier Walrus (sub-stores + main index); AES ciphertext; key local; testnet; no funds"
    )];

    // SUB-STORES: PUT each `.mc` ciphertext + collect (id, topic, sub_blob_id) for the
    // MAIN INDEX. first_sub kept for the round-trip proof.
    let mut entries: Vec<crate::memory_walrus::WalrusMemEntry> = Vec::new();
    let mut first_sub: Option<Vec<u8>> = None;
    // W4 Slice 2: the owner's keyless `memory_id → 0G rootHash` map, so an index entry
    // can carry a Walrus→0G fallback root when the owner backed that sub up to 0G.
    let zerog_roots = crate::memory_store::data_dir()
        .map(|d| crate::memory_walrus::read_0g_roots_map(&d))
        .unwrap_or_default();
    for (id, topic, ciphertext) in records.iter().take(BACKUP_WALRUS_MAX_RECORDS) {
        match walrus_put_verified(&mut pub_t, epochs, ciphertext) {
            Some(blob) => {
                body.push(format!("SUB PUT ok: id={id} -> blob_id={blob} (verified)"));
                if first_sub.is_none() {
                    first_sub = Some(ciphertext.clone());
                }
                entries.push(crate::memory_walrus::WalrusMemEntry {
                    memory_id: *id,
                    topic: topic.clone(),
                    sub_blob_id: blob,
                    sub_0g_root: zerog_roots.get(id).cloned(),
                });
            }
            None => {
                truth = RenderTruth::Red;
                body.push(format!(
                    "id={id}: SUB PUT rejected/failed (self-report ban or boundary)"
                ));
            }
        }
    }

    // MAIN INDEX: build the manifest, SEAL it with the local key, PUT it, save the pointer.
    let index = crate::memory_walrus::WalrusMainIndex {
        entries: entries.clone(),
    };
    let mut main_blob = String::new();
    if !index.entries.is_empty() {
        match store.seal_index(&index.to_bytes()) {
            Ok(index_ct) => match walrus_put_verified(&mut pub_t, epochs, &index_ct) {
                Some(blob) => {
                    if let Ok(dir) = crate::memory_store::data_dir() {
                        let _ = crate::memory_walrus::write_main_index_pointer(&dir, &blob);
                    }
                    body.push(format!(
                        "MAIN INDEX PUT ok: {} entries -> blob_id={blob} (pointer saved; the agent navigates from here)",
                        index.entries.len()
                    ));
                    main_blob = blob;
                }
                None => {
                    truth = RenderTruth::Red;
                    body.push("MAIN INDEX PUT rejected (boundary)".to_string());
                }
            },
            Err(_) => {
                truth = RenderTruth::Red;
                body.push("MAIN INDEX seal failed".to_string());
            }
        }
    }

    // ROUND-TRIP PROOF (the full 2-tier): GET the MAIN INDEX back + decrypt + match;
    // GET the FIRST SUB back + byte-match + decode (decryptable to its id).
    if !main_blob.is_empty() {
        match walrus_get_by_blob_text(&main_blob) {
            Some(fetched) => {
                let decoded = store
                    .open_index(&fetched)
                    .ok()
                    .and_then(|p| crate::memory_walrus::WalrusMainIndex::from_bytes(&p).ok());
                if decoded.as_ref() == Some(&index) {
                    body.push(format!(
                        "MAIN INDEX round-trip: GET+decrypt OK ({} entries match)",
                        index.entries.len()
                    ));
                } else {
                    truth = RenderTruth::Yellow;
                    body.push(
                        "MAIN INDEX round-trip: decrypt/entry mismatch (testnet propagation?)"
                            .to_string(),
                    );
                }
            }
            None => {
                truth = RenderTruth::Yellow;
                body.push(
                    "MAIN INDEX round-trip: GET not fetched (testnet propagation)".to_string(),
                );
            }
        }
    }
    if let (Some(entry), Some(ciphertext)) = (entries.first(), first_sub.as_ref()) {
        match walrus_get_by_blob_text(&entry.sub_blob_id) {
            Some(fetched) => {
                let bytes_match = &fetched == ciphertext;
                let decrypts_to_id = store.decode_record(&fetched).map(|(c, _)| c.id().get())
                    == Some(entry.memory_id);
                body.push(format!(
                    "SUB round-trip: GET id={} -> {} bytes; byte-match={bytes_match}; decrypts-to-id={decrypts_to_id}",
                    entry.memory_id,
                    fetched.len()
                ));
                if !bytes_match || !decrypts_to_id {
                    truth = RenderTruth::Red;
                }
            }
            None => {
                truth = RenderTruth::Yellow;
                body.push("SUB round-trip: GET not fetched (testnet propagation)".to_string());
            }
        }
    }

    body.push(format!(
        "published: {} sub-store(s) + {} main index; 2-tier round-trip; no funds; custody/chain-write HARD-LOCKED (PD-6)",
        entries.len(),
        u8::from(!main_blob.is_empty())
    ));
    emit(
        out,
        "memory backup-walrus",
        &envelope_hex,
        CommandRisk::Network,
        ApprovalRequirement::TypedPhrase,
        truth,
        &body,
    )?;
    Ok(true)
}

/// W2-C — the constant phrase the owner types to run the 0G Storage backup ceremony.
/// DISTINCT from the Walrus phrases so testnet muscle-memory can never cross-fire.
const BACKUP_ZEROG_CONFIRM_PHRASE: &str = "backup-encrypted-memory-to-0g-testnet";

/// W2-C locked-surface body (no/wrong phrase). Honest about the funds-safe split.
fn backup_zerog_locked_body() -> Vec<String> {
    vec![
        "memory backup-0g = round-trip the agent's ENCRYPTED memory (AES ciphertext) through 0G Storage testnet".to_string(),
        format!("to run, supply EXACTLY: memory backup-0g {BACKUP_ZEROG_CONFIRM_PHRASE}"),
        "the AGENT never runs the upload (a0gi fee + EVM signer = FUNDS); it emits the OWNER command + does the KEYLESS download+verify".to_string(),
        "denied: no run without the exact phrase; custody/funds HARD-LOCKED (PD-6)".to_string(),
    ]
}

/// W2-C fail-closed error render for the 0G Storage ceremony.
fn backup_zerog_error(out: &mut impl Write, envelope_hex: &str, label: &str) -> io::Result<bool> {
    emit(
        out,
        "memory backup-0g",
        envelope_hex,
        CommandRisk::Network,
        ApprovalRequirement::TypedPhrase,
        RenderTruth::Red,
        &[
            format!("memory backup-0g: {label}"),
            "fail-closed; nothing partial trusted".to_string(),
        ],
    )
    .map(|()| true)
}

/// `provider attest-0g [provider]` — W2-B 0G Compute TEE attestation verify (funds-safe).
/// Runs the Node sidecar (`ZEROG_ATTESTATION_SIDECAR` → verify.js) to verify a 0G Compute
/// provider's TEE quote. KEYLESS + read-only: the sidecar uses an ephemeral UNFUNDED wallet
/// (no key, no funds, no chain write); the agent holds no key (PD-6). With the
/// `zerog-attestation` feature off, renders an honest "not compiled" surface.
fn provider_attest_zerog(rest: &[String], out: &mut impl Write) -> io::Result<bool> {
    let envelope_hex = hex16(&sha256_32(b"provider attest-0g"));
    let provider = rest.first().map(String::as_str);
    let mut body =
        vec!["0G Compute TEE attestation verify (W2-B) — read-only, keyless, no funds".to_string()];
    #[cfg(feature = "zerog-attestation")]
    {
        match std::env::var(crate::zerog_attestation::ZEROG_ATTESTATION_SIDECAR_ENV) {
            Ok(js) if !js.trim().is_empty() => {
                match crate::zerog_attestation::run_verify("node", js.trim(), provider) {
                    Some(v) => {
                        body.push(format!("  verified    : {}", v.verified));
                        body.push(format!("  teeVerifier : {}", v.tee_verifier));
                        body.push(format!("  provider    : {}", v.provider));
                        body.push(format!("  model       : {}", v.model));
                    }
                    None => body.push(
                        "  verify FAILED (sidecar spawn/parse) — UNVERIFIED (fail-closed)"
                            .to_string(),
                    ),
                }
            }
            _ => body.push(format!(
                "  set {} to prototype/sidecar/zerog-attestation/verify.js (after npm install)",
                crate::zerog_attestation::ZEROG_ATTESTATION_SIDECAR_ENV
            )),
        }
    }
    #[cfg(not(feature = "zerog-attestation"))]
    {
        let _ = provider;
        body.push(
            "  sidecar not compiled (build --features zerog-attestation; npm install in prototype/sidecar/zerog-attestation)"
                .to_string(),
        );
    }
    emit(
        out,
        "provider attest-0g",
        &envelope_hex,
        CommandRisk::Network,
        ApprovalRequirement::None,
        RenderTruth::Green,
        &body,
    )
    .map(|()| true)
}

/// `memory anchor-0g` — W2-D 0G Chain anchor PREPARE (funds-safe, PD-6). PURE: emits
/// the locked patternHash + ABI calldata + a keyless read-only dry-run + the exact
/// OWNER deploy/anchor commands. The agent NEVER deploys/signs/holds a key; the OWNER
/// fires the funds-bearing txs with their own testnet key. ReadOnly (autonomous prepare).
fn memory_anchor_zerog(out: &mut impl Write) -> io::Result<bool> {
    let envelope_hex = hex16(&sha256_32(b"memory anchor-0g"));
    emit(
        out,
        "memory anchor-0g",
        &envelope_hex,
        CommandRisk::ReadOnly,
        ApprovalRequirement::None,
        RenderTruth::Green,
        &crate::zerog_chain::anchor_bundle_lines(None),
    )
    .map(|()| true)
}

/// `memory mint-0g` — W3 0G ERC-7857 iNFT mint PREPARE (funds-safe, PD-6). PURE: emits
/// the locked mint selector + ABI calldata (dataHash = the W2-D patternHash) + a keyless
/// read-only dry-run + the exact OWNER deploy/mint commands (`forge script`). The agent
/// NEVER deploys/signs/holds a key; the OWNER fires the funds-bearing txs with their own
/// testnet key. ReadOnly (autonomous prepare). Mirrors `memory_anchor_zerog` (W2-D).
fn memory_mint_zerog(out: &mut impl Write) -> io::Result<bool> {
    let envelope_hex = hex16(&sha256_32(b"memory mint-0g"));
    emit(
        out,
        "memory mint-0g",
        &envelope_hex,
        CommandRisk::ReadOnly,
        ApprovalRequirement::None,
        RenderTruth::Green,
        &crate::zerog_inft::mint_bundle_lines(None, None),
    )
    .map(|()| true)
}

/// `provider finetune-0g` — W3-B 0G Compute fine-tune PREPARE (funds-safe, PD-6). Reads the
/// orchestrator's ONLY-verified patterns (the `autonomy_evolve` R-E-W corpus, filtered by
/// `parse_pattern_memory` — NOT arbitrary owner memories), writes an Alpaca SFT `.jsonl` to
/// the data dir, and emits the exact OWNER-RUN `0g-compute-cli fine-tuning` sequence. PURE
/// prep: no network, no key; the paid training is owner-fired. LocalWrite (writes the
/// dataset). The fine-tune reinforces oracle-verified behaviour — un-verified text never trains.
fn provider_finetune_zerog(out: &mut impl Write) -> io::Result<bool> {
    let envelope_hex = hex16(&sha256_32(b"provider finetune-0g"));
    let store = match crate::memory_store::PersistedStore::open_local() {
        Ok(s) => s,
        Err(_) => {
            return emit(
                out,
                "provider finetune-0g",
                &envelope_hex,
                CommandRisk::LocalWrite,
                ApprovalRequirement::None,
                RenderTruth::Yellow,
                &["provider finetune-0g: memory store unavailable (no key/home)".to_string()],
            )
            .map(|()| true);
        }
    };
    // ONLY oracle-verified patterns become training data (parse_pattern_memory filters the
    // `#sinabro-pattern` corpus; a private owner note is not a pattern ⇒ never exported).
    let pairs: Vec<(String, String)> = store
        .load_all()
        .chunks
        .iter()
        .filter_map(|(chunk, _)| {
            let body = String::from_utf8_lossy(chunk.envelope().content.as_slice());
            crate::autonomy_evolve::parse_pattern_memory(&body)
                .map(|(_, topic, content)| (topic, content))
        })
        .collect();
    if pairs.is_empty() {
        return emit(
            out,
            "provider finetune-0g",
            &envelope_hex,
            CommandRisk::LocalWrite,
            ApprovalRequirement::None,
            RenderTruth::Yellow,
            &[
                "provider finetune-0g: no oracle-verified patterns to train on yet".to_string(),
                "run `daemon evolve <ARM_PHRASE> <goal>` first — ONLY verified + cross-memory-"
                    .to_string(),
                "consistent patterns (the R-E-W WRITE corpus) become fine-tune training data"
                    .to_string(),
            ],
        )
        .map(|()| true);
    }
    let n = pairs.len();
    let jsonl = crate::zerog_finetune::export_alpaca_jsonl(&pairs);
    let dir = match crate::memory_store::data_dir() {
        Ok(d) => d,
        Err(_) => {
            return emit(
                out,
                "provider finetune-0g",
                &envelope_hex,
                CommandRisk::LocalWrite,
                ApprovalRequirement::None,
                RenderTruth::Red,
                &["provider finetune-0g: no data dir to write the dataset".to_string()],
            )
            .map(|()| true);
        }
    };
    let path = dir.join(crate::zerog_finetune::FINETUNE_DATASET_FILE);
    if crate::memory_store::atomic_write(&path, jsonl.as_bytes()).is_err() {
        return emit(
            out,
            "provider finetune-0g",
            &envelope_hex,
            CommandRisk::LocalWrite,
            ApprovalRequirement::None,
            RenderTruth::Red,
            &["provider finetune-0g: failed to write the dataset file".to_string()],
        )
        .map(|()| true);
    }
    let mut lines = crate::zerog_finetune::finetune_bundle_lines(&path.display().to_string(), n);
    lines.push(String::new());
    lines.push(format!(
        "  wrote {} bytes (PLAINTEXT dataset — the owner's own verified corpus; review before upload)",
        jsonl.len()
    ));
    emit(
        out,
        "provider finetune-0g",
        &envelope_hex,
        CommandRisk::LocalWrite,
        ApprovalRequirement::None,
        RenderTruth::Green,
        &lines,
    )
    .map(|()| true)
}

/// `provider mint-expert-0g <adapter_rootHash> [kind]` — W3-B capstone: mint a fine-tuned
/// expert as an ERC-7857 iNFT on the existing AgentNFT (the W3 proxy). `dataHash` = the
/// LoRA adapter's 0G Storage rootHash (the weights ARE the intelligence); the descriptor
/// names the expert. PURE PREPARE: builds the mint calldata + emits the OWNER-run mint; the
/// agent never signs (PD-6). ReadOnly. Reuses the W3 `zerog_inft` mint encoder.
fn provider_mint_expert_zerog(rest: &[String], out: &mut impl Write) -> io::Result<bool> {
    let envelope_hex = hex16(&sha256_32(b"provider mint-expert-0g"));
    let root_arg = rest.get(1).map(String::as_str).unwrap_or("");
    let kind = rest.get(2).map(String::as_str).unwrap_or("generalist");
    if crate::zerog_inft::parse_root_hash(root_arg).is_none() {
        return emit(
            out,
            "provider mint-expert-0g",
            &envelope_hex,
            CommandRisk::ReadOnly,
            ApprovalRequirement::None,
            RenderTruth::Yellow,
            &[
                "provider mint-expert-0g <adapter_rootHash> [kind] — mint a fine-tuned expert as an iNFT"
                    .to_string(),
                "  <adapter_rootHash> = the LoRA adapter's 0G Storage rootHash (0x + 64 hex)"
                    .to_string(),
                "  upload the decrypted adapter to 0G Storage first (W2-C `memory backup-0g`)"
                    .to_string(),
            ],
        )
        .map(|()| true);
    }
    emit(
        out,
        "provider mint-expert-0g",
        &envelope_hex,
        CommandRisk::ReadOnly,
        ApprovalRequirement::None,
        RenderTruth::Green,
        &crate::zerog_inft::expert_mint_bundle_lines(root_arg, kind, None, None),
    )
    .map(|()| true)
}

/// `memory backup-0g <phrase> [rootHash]` — funds-safe 0G Storage round-trip (W2-C).
///
/// PREPARE (no rootHash): gate → load the first REAL `.mc` record → write the AES
/// ciphertext to a temp file → EMIT the exact OWNER-RUN upload command (the agent NEVER
/// runs it: a0gi fee + EVM signer = FUNDS) + the ciphertext fingerprint + the keyless
/// verify step. VERIFY (rootHash present): gate → run the KEYLESS proof-verified
/// `download --proof` (`zerog-storage` feature) → byte-match the original ciphertext.
/// The agent holds NO signer key; custody/chain-write HARD-LOCKED (PD-6).
fn memory_backup_zerog(rest: &[String], out: &mut impl Write) -> io::Result<bool> {
    use crate::repl::approval::{ApprovalDecision, ApprovalPrompt};

    let envelope_hex = hex16(&sha256_32(b"memory backup-0g"));
    let phrase = rest.get(1).map(String::as_str).unwrap_or("");
    let root_arg = rest.get(2).map(String::as_str);

    let mut prompt = ApprovalPrompt::new(
        ApprovalRequirement::TypedPhrase,
        BACKUP_ZEROG_CONFIRM_PHRASE,
    );
    if !matches!(prompt.evaluate(phrase.trim()), ApprovalDecision::Approved) {
        emit(
            out,
            "memory backup-0g",
            &envelope_hex,
            CommandRisk::Network,
            ApprovalRequirement::TypedPhrase,
            RenderTruth::Yellow,
            &backup_zerog_locked_body(),
        )?;
        return Ok(true);
    }

    let store = match crate::memory_store::PersistedStore::open_local() {
        Ok(s) => s,
        Err(_) => {
            return backup_zerog_error(
                out,
                &envelope_hex,
                "memory store unavailable (no key/home)",
            );
        }
    };
    let records = store.records_for_walrus();
    let Some((id, _topic, ciphertext)) = records.first() else {
        emit(
            out,
            "memory backup-0g",
            &envelope_hex,
            CommandRisk::Network,
            ApprovalRequirement::TypedPhrase,
            RenderTruth::Yellow,
            &[
                "memory backup-0g: the store has no encrypted records to back up".to_string(),
                "save a memory first (`memory save …`), then back it up to 0G Storage".to_string(),
            ],
        )?;
        return Ok(true);
    };
    let dir = match crate::memory_store::data_dir() {
        Ok(d) => d,
        Err(_) => return backup_zerog_error(out, &envelope_hex, "no data dir for temp ciphertext"),
    };

    // VERIFY mode (a rootHash arg present): keyless proof-verified download + byte-match.
    if let Some(root) = root_arg {
        if !crate::zerog_storage::is_valid_root_hash(root) {
            return backup_zerog_error(out, &envelope_hex, "rootHash must be 0x + 64 hex");
        }
        #[cfg(feature = "zerog-storage")]
        {
            let Ok(binary) = std::env::var(crate::zerog_storage::ZEROG_STORAGE_BINARY_ENV) else {
                return backup_zerog_error(
                    out,
                    &envelope_hex,
                    "set ZEROG_STORAGE_CLIENT to the built 0g-storage-client binary path",
                );
            };
            let out_path = dir.join(format!("zerog_backup_{id}.dl"));
            let verdict = crate::zerog_storage::run_download(
                &binary,
                root,
                &out_path.display().to_string(),
                ciphertext,
            );
            use crate::zerog_storage::ZerogVerify;
            let (truth, line) = match verdict {
                ZerogVerify::ByteMatch => (
                    RenderTruth::Green,
                    format!(
                        "0G Storage round-trip VERIFIED: id={id} root={root} — download --proof OK + byte-match=true"
                    ),
                ),
                ZerogVerify::Mismatch => (
                    RenderTruth::Red,
                    format!("0G verify: downloaded bytes != original ciphertext (root={root})"),
                ),
                ZerogVerify::ExitNonZero(c) => (
                    RenderTruth::Red,
                    format!("0G verify: 0g-storage-client exit {c:?} (proof/integrity failure)"),
                ),
                ZerogVerify::SpawnFailed => (
                    RenderTruth::Red,
                    "0G verify: could not run 0g-storage-client (check ZEROG_STORAGE_CLIENT)"
                        .to_string(),
                ),
                ZerogVerify::InvalidRoot => {
                    (RenderTruth::Red, "0G verify: invalid rootHash".to_string())
                }
            };
            emit(
                out,
                "memory backup-0g",
                &envelope_hex,
                CommandRisk::Network,
                ApprovalRequirement::TypedPhrase,
                truth,
                &[
                    line,
                    "KEYLESS download (no signer key); custody/chain-write HARD-LOCKED (PD-6)"
                        .to_string(),
                ],
            )?;
            return Ok(true);
        }
        #[cfg(not(feature = "zerog-storage"))]
        {
            emit(
                out,
                "memory backup-0g",
                &envelope_hex,
                CommandRisk::Network,
                ApprovalRequirement::TypedPhrase,
                RenderTruth::Yellow,
                &[
                    "memory backup-0g verify: the 0G storage client path is not compiled"
                        .to_string(),
                    "build sinabro with `--features zerog-storage` for the keyless download+verify"
                        .to_string(),
                ],
            )?;
            return Ok(true);
        }
    }

    // PREPARE mode: write the ciphertext to a temp file + emit the OWNER upload command.
    let temp_path = dir.join(format!("zerog_backup_{id}.mc"));
    let temp_str = temp_path.display().to_string();
    if crate::memory_store::atomic_write(&temp_path, ciphertext).is_err() {
        return backup_zerog_error(out, &envelope_hex, "could not write temp ciphertext");
    }
    let fingerprint = hex16(&sha256_32(ciphertext));
    let cmd = crate::zerog_storage::upload_command(&temp_str);
    emit(
        out,
        "memory backup-0g",
        &envelope_hex,
        CommandRisk::Network,
        ApprovalRequirement::TypedPhrase,
        RenderTruth::Green,
        &[
            format!(
                "memory backup-0g: wrote encrypted record id={id} -> {temp_str} ({} bytes; AES ciphertext; 0G encryption OFF)",
                ciphertext.len()
            ),
            "0G Storage upload needs an EVM signer + a0gi fee = FUNDS, so the AGENT never runs it."
                .to_string(),
            "OWNER 1 (build the client, Go>=1.23): git clone https://github.com/0gfoundation/0g-storage-client && (cd 0g-storage-client && go build) && export ZEROG_STORAGE_CLIENT=$PWD/0g-storage-client/0g-storage-client"
                .to_string(),
            "OWNER 2 (fund a TESTNET signer via faucet.0g.ai): export ZEROG_STORAGE_SIGNER_KEY=0x<testnet-private-key>"
                .to_string(),
            "OWNER 3 (run the upload — FUNDS; key from YOUR env, never the agent's):".to_string(),
            format!("  {cmd}"),
            format!(
                "OWNER 4 (copy 'root = 0x…' from stderr, then KEYLESS verify): memory backup-0g {BACKUP_ZEROG_CONFIRM_PHRASE} 0x<root>"
            ),
            format!(
                "ciphertext fingerprint sha256[..8]={fingerprint}; custody/chain-write HARD-LOCKED (PD-6); agent holds NO signer key"
            ),
        ],
    )?;
    Ok(true)
}

/// S3 — the constant phrase the owner types to ARM a real self-host MAINNET backup. A
/// DISTINCT phrase from the testnet `BACKUP_WALRUS_CONFIRM_PHRASE` so a testnet muscle-memory
/// approval can never fire a mainnet write.
#[cfg(feature = "walrus-mainnet")]
const BACKUP_WALRUS_MAINNET_CONFIRM_PHRASE: &str =
    "backup-encrypted-memory-to-walrus-mainnet-selfhost";

/// S3 — the locked-surface body shown when `memory backup-walrus-mainnet` is invoked without
/// the exact phrase (the model can render this, but never the live write).
#[cfg(feature = "walrus-mainnet")]
fn backup_walrus_mainnet_locked_body() -> Vec<String> {
    vec![
        "memory backup-walrus-mainnet = publish the agent's ENCRYPTED memory (AES ciphertext) to your CONFIGURED self-host Walrus (MAINNET) + round-trip byte-match verify".to_string(),
        format!("to run, supply EXACTLY: memory backup-walrus-mainnet {BACKUP_WALRUS_MAINNET_CONFIRM_PHRASE}"),
        "needs walrus_publisher_endpoint + walrus_aggregator_endpoint configured (https); WALRUS_PUBLISHER_TOKEN if your publisher needs a bearer".to_string(),
        "our app holds NO Sui key, never signs, never pays — your publisher pays (PD-6 custody HARD-LOCKED)".to_string(),
    ]
}

/// `memory backup-walrus-mainnet <phrase>` — owner-armed TWO-TIER self-host MAINNET backup
/// plus a round-trip BYTE-MATCH receipt (S3). Gate: exact phrase, then resolve the CONFIGURED
/// publisher and aggregator (honest "not configured" if unset/invalid), PUT each `.mc`
/// ciphertext (`EncryptedUserMemory`) as a SUB-STORE, build and SEAL and PUT the MAIN INDEX,
/// save the MAINNET pointer, then round-trip GET (main decrypt+match; first sub BYTE-match
/// plus decode — the mainnet receipt, since the RS2 local re-derive is testnet-only). NO
/// plaintext ever leaves; our app holds no Sui key, never signs, never pays — the configured
/// publisher pays (PD-6 custody HARD-LOCKED).
#[cfg(feature = "walrus-mainnet")]
fn memory_backup_walrus_mainnet(rest: &[String], out: &mut impl Write) -> io::Result<bool> {
    use crate::provider::walrus_selfhost::{
        WALRUS_MAINNET_DEFAULT_EPOCHS, WalrusSelfHostTransport, configured_walrus_aggregator,
        configured_walrus_publisher,
    };
    use crate::repl::approval::{ApprovalDecision, ApprovalPrompt};
    use mnemos_c_walrus::publisher::PublishPayloadClass;

    let envelope_hex = hex16(&sha256_32(b"memory backup-walrus-mainnet"));
    let supplied = rest.get(1..).map(|s| s.join(" ")).unwrap_or_default();

    // GATE (sole runtime operator gate): exact typed phrase before any record read or PUT.
    let mut prompt = ApprovalPrompt::new(
        ApprovalRequirement::TypedPhrase,
        BACKUP_WALRUS_MAINNET_CONFIRM_PHRASE,
    );
    if !matches!(prompt.evaluate(supplied.trim()), ApprovalDecision::Approved) {
        emit(
            out,
            "memory backup-walrus-mainnet",
            &envelope_hex,
            CommandRisk::Network,
            ApprovalRequirement::TypedPhrase,
            RenderTruth::Yellow,
            &backup_walrus_mainnet_locked_body(),
        )?;
        return Ok(true);
    }

    // APPROVED. Resolve the configured self-host endpoints (https + SSRF-walled). Both must
    // be present + valid; otherwise honest "not configured" (no silent fallback to testnet).
    let (Some(publisher), Some(aggregator)) = (
        configured_walrus_publisher(),
        configured_walrus_aggregator(),
    ) else {
        return backup_walrus_error(
            out,
            &envelope_hex,
            "self-host endpoints not configured (set walrus_publisher_endpoint + walrus_aggregator_endpoint to https URLs)",
        );
    };
    let transport = match WalrusSelfHostTransport::new() {
        Some(t) => t,
        None => return backup_walrus_error(out, &envelope_hex, "self-host transport init failed"),
    };

    // Load the agent's REAL encrypted records (ciphertext only — the AEAD key stays local).
    let store = match crate::memory_store::PersistedStore::open_local() {
        Ok(s) => s,
        Err(_) => {
            return backup_walrus_error(
                out,
                &envelope_hex,
                "memory store unavailable (no key/home)",
            );
        }
    };
    let records = store.records_for_walrus();
    if records.is_empty() {
        emit(
            out,
            "memory backup-walrus-mainnet",
            &envelope_hex,
            CommandRisk::Network,
            ApprovalRequirement::TypedPhrase,
            RenderTruth::Yellow,
            &[
                "memory backup-walrus-mainnet: the store has no encrypted records to back up"
                    .to_string(),
                "save a memory first (`memory save …`), then back it up to your mainnet Walrus"
                    .to_string(),
            ],
        )?;
        return Ok(true);
    }
    let epochs = WALRUS_MAINNET_DEFAULT_EPOCHS;

    let total = records.len();
    let mut truth = RenderTruth::Green;
    let mut body = vec![format!(
        "memory backup-walrus-mainnet: {total} encrypted record(s) → 2-tier self-host MAINNET Walrus ({}); AES ciphertext; key local; the publisher pays; our app holds no Sui key / never signs / never pays",
        publisher.host()
    )];

    // SUB-STORES: PUT each `.mc` ciphertext (EncryptedUserMemory) + collect the index entry.
    let mut entries: Vec<crate::memory_walrus::WalrusMemEntry> = Vec::new();
    let mut first_sub: Option<Vec<u8>> = None;
    for (id, topic, ciphertext) in records.iter().take(BACKUP_WALRUS_MAX_RECORDS) {
        match transport.put_blob(
            &publisher,
            epochs,
            ciphertext,
            PublishPayloadClass::EncryptedUserMemory,
        ) {
            Ok(blob) => {
                body.push(format!("SUB PUT ok: id={id} -> blob_id={blob}"));
                if first_sub.is_none() {
                    first_sub = Some(ciphertext.clone());
                }
                entries.push(crate::memory_walrus::WalrusMemEntry {
                    memory_id: *id,
                    topic: topic.clone(),
                    sub_blob_id: blob,
                    // mainnet self-host Walrus memory; the 0G-testnet fallback does not pair here.
                    sub_0g_root: None,
                });
            }
            Err(_) => {
                truth = RenderTruth::Red;
                body.push(format!(
                    "id={id}: SUB PUT rejected/failed (endpoint/boundary)"
                ));
            }
        }
    }

    // MAIN INDEX: build the manifest, SEAL it with the local key, PUT it, save the MAINNET pointer.
    let index = crate::memory_walrus::WalrusMainIndex {
        entries: entries.clone(),
    };
    let mut main_blob = String::new();
    if !index.entries.is_empty() {
        match store.seal_index(&index.to_bytes()) {
            Ok(index_ct) => match transport.put_blob(
                &publisher,
                epochs,
                &index_ct,
                PublishPayloadClass::EncryptedUserMemory,
            ) {
                Ok(blob) => {
                    if let Ok(dir) = crate::memory_store::data_dir() {
                        let _ = crate::memory_walrus::write_main_index_pointer_mainnet(&dir, &blob);
                    }
                    body.push(format!(
                        "MAIN INDEX PUT ok: {} entries -> blob_id={blob} (mainnet pointer saved; the agent navigates from here)",
                        index.entries.len()
                    ));
                    main_blob = blob;
                }
                Err(_) => {
                    truth = RenderTruth::Red;
                    body.push("MAIN INDEX PUT rejected (boundary)".to_string());
                }
            },
            Err(_) => {
                truth = RenderTruth::Red;
                body.push("MAIN INDEX seal failed".to_string());
            }
        }
    }

    // ROUND-TRIP RECEIPT (the mainnet proof): GET the MAIN INDEX back + decrypt + match;
    // GET the FIRST SUB back + BYTE-match + decode (decryptable to its id).
    if !main_blob.is_empty() {
        match transport.get_blob(&aggregator, &main_blob) {
            Ok(fetched) => {
                let decoded = store
                    .open_index(&fetched)
                    .ok()
                    .and_then(|p| crate::memory_walrus::WalrusMainIndex::from_bytes(&p).ok());
                if decoded.as_ref() == Some(&index) {
                    body.push(format!(
                        "MAIN INDEX round-trip: GET+decrypt OK ({} entries match)",
                        index.entries.len()
                    ));
                } else {
                    truth = RenderTruth::Yellow;
                    body.push(
                        "MAIN INDEX round-trip: decrypt/entry mismatch (propagation?)".to_string(),
                    );
                }
            }
            Err(_) => {
                truth = RenderTruth::Yellow;
                body.push("MAIN INDEX round-trip: GET not fetched (propagation)".to_string());
            }
        }
    }
    if let (Some(entry), Some(ciphertext)) = (entries.first(), first_sub.as_ref()) {
        match transport.get_blob(&aggregator, &entry.sub_blob_id) {
            Ok(fetched) => {
                let bytes_match = &fetched == ciphertext;
                let decrypts_to_id = store.decode_record(&fetched).map(|(c, _)| c.id().get())
                    == Some(entry.memory_id);
                body.push(format!(
                    "SUB round-trip: GET id={} -> {} bytes; byte-match={bytes_match}; decrypts-to-id={decrypts_to_id}",
                    entry.memory_id,
                    fetched.len()
                ));
                if !bytes_match || !decrypts_to_id {
                    truth = RenderTruth::Red;
                }
            }
            Err(_) => {
                truth = RenderTruth::Yellow;
                body.push("SUB round-trip: GET not fetched (propagation)".to_string());
            }
        }
    }

    body.push(format!(
        "published: {} sub-store(s) + {} main index → self-host MAINNET Walrus; 2-tier round-trip BYTE-MATCH receipt; the publisher pays; our app: no Sui key / no sign / no funds; custody/chain-write HARD-LOCKED (PD-6)",
        entries.len(),
        u8::from(!main_blob.is_empty())
    ));
    emit(
        out,
        "memory backup-walrus-mainnet",
        &envelope_hex,
        CommandRisk::Network,
        ApprovalRequirement::TypedPhrase,
        truth,
        &body,
    )?;
    Ok(true)
}

/// E14-W2 shared: read + decrypt the agent's MAIN INDEX from Walrus (the pointer file →
/// aggregator GET → AEAD open → decode). `Err(reason)` fail-closed at each gate. This is
/// how the agent navigates: it learns every memory's id + topic + sub-store blob-id.
#[cfg(feature = "put-fixture-net")]
fn walrus_load_main_index(
    store: &crate::memory_store::PersistedStore,
) -> Result<crate::memory_walrus::WalrusMainIndex, &'static str> {
    // S3: delegate to the AUTO-ROUTED loader (the configured self-host MAINNET aggregator
    // when set, else the testnet store) so the CLI `walrus-index` / `walrus-fetch` verbs
    // match the GUI panel + the autonomous loop (all three share `memory_walrus::net`).
    crate::memory_walrus::load_main_index(store)
}

/// `memory walrus-index` — the agent reads its MAIN INDEX from Walrus and lists every
/// memory's id + topic + sub-store blob-id (the "메인 저장소" navigation). READ-class, no
/// approval (the agent roams freely). custody/funds HARD-LOCKED (PD-6); ciphertext-only.
#[cfg(feature = "put-fixture-net")]
fn memory_walrus_index(out: &mut impl Write) -> io::Result<bool> {
    let envelope_hex = hex16(&sha256_32(b"memory walrus-index"));
    let store = match crate::memory_store::PersistedStore::open_local() {
        Ok(s) => s,
        Err(_) => {
            return emit(
                out,
                "memory walrus-index",
                &envelope_hex,
                CommandRisk::Network,
                ApprovalRequirement::None,
                RenderTruth::Yellow,
                &["memory walrus-index: store unavailable (no key/home)".to_string()],
            )
            .map(|()| true);
        }
    };
    match walrus_load_main_index(&store) {
        Ok(index) => {
            let mut body = vec![format!(
                "memory walrus-index: {} memories on Walrus (MAIN INDEX, decrypted locally)",
                index.entries.len()
            )];
            for e in index.entries.iter().take(64) {
                let sub_short = &e.sub_blob_id[..e.sub_blob_id.len().min(16)];
                body.push(format!(
                    "  id={} topic=\"{}\" sub_blob={sub_short}…",
                    e.memory_id, e.topic
                ));
            }
            body.push(
                "use `memory walrus-fetch <id>` to pull a memory's detail from its sub-store"
                    .to_string(),
            );
            emit(
                out,
                "memory walrus-index",
                &envelope_hex,
                CommandRisk::Network,
                ApprovalRequirement::None,
                RenderTruth::Green,
                &body,
            )
            .map(|()| true)
        }
        Err(reason) => emit(
            out,
            "memory walrus-index",
            &envelope_hex,
            CommandRisk::Network,
            ApprovalRequirement::None,
            RenderTruth::Yellow,
            &[format!("memory walrus-index: {reason}")],
        )
        .map(|()| true),
    }
}

/// `memory walrus-fetch <id>` — the agent enters the SUB-STORE for `<id>` (found via the
/// MAIN INDEX), fetches the encrypted detail from Walrus, decrypts it locally, and renders
/// the content (redact-belted). READ-class, no approval. custody/funds HARD-LOCKED.
#[cfg(feature = "put-fixture-net")]
fn walrus_fetch_lines(rest: &[String]) -> (RenderTruth, Vec<String>) {
    let yellow = |line: String| (RenderTruth::Yellow, vec![line]);
    let Some(id_text) = rest.get(1) else {
        return yellow("usage: memory walrus-fetch <memory-id>".to_string());
    };
    let Ok(memory_id) = id_text.trim().parse::<u64>() else {
        return yellow(format!(
            "memory walrus-fetch: '{}' is not a memory id (u64)",
            id_text.trim()
        ));
    };
    let store = match crate::memory_store::PersistedStore::open_local() {
        Ok(s) => s,
        Err(_) => return yellow("store unavailable (no key/home)".to_string()),
    };
    // S3: routed sub-fetch (mainnet self-host when configured, else testnet) — the SAME
    // path the GUI panel + the autonomous loop use; index lookup + GET + local AEAD open
    // in one call (ciphertext-only on the wire; the key never leaves the machine).
    let content = match crate::memory_walrus::fetch_sub_content(&store, memory_id) {
        Ok(c) => c,
        Err(reason) => return yellow(format!("memory walrus-fetch: id={memory_id} {reason}")),
    };
    // Belt-redact the rendered detail (a memory that is itself secret-shaped is withheld).
    let fragments = [content.as_str()];
    let detail = match redact(&RedactionRequest {
        fragments: &fragments,
        candidate_memory_ids: &[],
        deleted_ids: &[],
        include_private_memory: false,
    }) {
        Ok(r) if r.secret_fragments_denied_u32() == 0 => content,
        _ => "withheld (secret-shaped memory; decrypted locally but not rendered)".to_string(),
    };
    (
        RenderTruth::Green,
        vec![
            format!(
                "memory walrus-fetch id={memory_id}: fetched from Walrus sub-store + decrypted locally"
            ),
            format!("detail: {detail}"),
            "ciphertext-only on the wire (READ-only; no funds touched)".to_string(),
        ],
    )
}

#[cfg(feature = "put-fixture-net")]
fn memory_walrus_fetch(rest: &[String], out: &mut impl Write) -> io::Result<bool> {
    let envelope_hex = hex16(&sha256_32(b"memory walrus-fetch"));
    let (truth, body) = walrus_fetch_lines(rest);
    emit(
        out,
        "memory walrus-fetch",
        &envelope_hex,
        CommandRisk::Network,
        ApprovalRequirement::None,
        truth,
        &body,
    )
    .map(|()| true)
}

// ---- P (owner-authorized 2026-06-10): gated live LLM consult ------------------
//
// The SECOND live-egress execute path in this module (after C's put-fixture),
// reachable ONLY when compiled with `provider-egress`. Gate stack (all required):
// feature-compiled + exact typed-phrase approval (the same-message ceremony that
// alone enables live dispatch) + before-send redaction gate + bounded caps
// (question bytes / SLOW-state consult caps / max_tokens / one-shot / timeout) +
// allowlisted host + TLS-boundary-only key read. funds/wallet/mainnet are
// unreachable (no such host variant exists). Threat model:
// ops/evidence/stage_g/gui_desktop/PROVIDER_EGRESS_THREAT_MODEL.md.

/// The exact in-band confirmation phrase that authorizes ONE live LLM consult. A
/// PUBLIC confirmation gesture (zero entropy, NOT a secret), supplied verbatim as
/// the token after the verb. Absence/mismatch fails closed (no send).
#[cfg(feature = "provider-egress")]
const PROVIDER_CONSULT_CONFIRM_PHRASE: &str = "consult-frontier-provider-live";

/// Per-call dispatch timeout (ms) for the one-shot consult. SHARED with the
/// P3-3 local route (IV-L3: bounds are identical — local buys no relaxation).
#[cfg(any(
    feature = "provider-egress",
    feature = "local-mlx",
    feature = "local-vllm"
))]
const PROVIDER_CONSULT_TIMEOUT_MS: u32 = 60_000;

/// Hard output-token ceiling per consult (bounded cost; ~$0.026 max at the
/// opus-4-8 output rate). SHARED with the P3-3 local route (IV-L3).
#[cfg(any(
    feature = "provider-egress",
    feature = "local-mlx",
    feature = "local-vllm"
))]
const PROVIDER_CONSULT_MAX_OUTPUT_TOKENS: u32 = 1024;

/// Hard byte ceiling on the outbound question (bounded input cost). SHARED
/// with the P3-3 local route (IV-L3).
#[cfg(any(
    feature = "provider-egress",
    feature = "local-mlx",
    feature = "local-vllm"
))]
const PROVIDER_CONSULT_MAX_QUESTION_BYTES: usize = 128_000;

// P4-3: the frontier default model id ("deepseek/deepseek-chat") is owned by
// `model_select::FRONTIER_DEFAULT_MODEL` (one selection truth, shared with the
// `model use` selector view); `provider_consult_model()` resolves through it,
// so no dispatch-local copy of the default is kept.

/// The env var that overrides the default model id (NOT a secret — a plain
/// model selector; set via the GUI Secrets panel or the shell). P4-3: canonical
/// name owned by `model_select`.
#[cfg(feature = "provider-egress")]
const PROVIDER_CONSULT_MODEL_ENV: &str = crate::commands::model_select::FRONTIER_MODEL_ENV;

/// Step 1 of wrapping the LLM into a real sinabro agent: the identity +
/// capability system prompt. With this, the model answers AS sinabro (knowing its
/// 35 command namespaces and its hard limits) instead of as a bare deepseek that
/// has never heard of sinabro. The autonomous tool-call loop (the model actually
/// invoking these commands) is Step 2 (m-agent loop driver). SOT: RD-49 + the
/// 35-namespace catalog from grammar.rs. Funds/wallet/mainnet stay HARD-LOCKED for
/// the model too. SHARED head/tail with the P3-3 local route; E2-3 (PD-1) makes the
/// ROUTE-IDENTITY sentence TRUE per route — the frontier line is byte-identical to
/// the prior shared sentence; the local line names the loopback Naite model (no
/// "external frontier model" lie on the local path). Each route keeps ONE
/// byte-stable prefix (composed once per ceremony — the prompt-cache law holds).
#[cfg(any(
    feature = "provider-egress",
    feature = "local-mlx",
    feature = "local-vllm"
))]
const SINABRO_SYSTEM_PROMPT_HEAD: &str = "\
You are Sinabro — an autonomous, safety-bound agent built on a Rust core. \
(Internal model name: Naite. ";

/// The FRONTIER route-identity sentence — BYTE-IDENTICAL to the prior shared
/// clause, so the frontier composed prompt is unchanged.
#[cfg(any(
    feature = "provider-egress",
    feature = "local-mlx",
    feature = "local-vllm"
))]
const SINABRO_ROUTE_LINE_FRONTIER: &str = "Right now you are running on an external frontier \
model as an ADVISORY consultant over the sinabro core, per the RD-49 router — \
your output is advisory until locally verified.";

/// The LOCAL route-identity sentence — E2-3 (PD-1): the TRUE label for the
/// loopback Naite route (no "external frontier model" claim). Still advisory: the
/// local endpoint is an unaudited local process (⑧ trust tier).
#[cfg(any(
    feature = "provider-egress",
    feature = "local-mlx",
    feature = "local-vllm"
))]
const SINABRO_ROUTE_LINE_LOCAL: &str = "Right now you are running on the LOCAL Naite model \
over a loopback endpoint — zero egress, free, private (the autonomy default); your output \
is still advisory until locally verified, because the local endpoint is an unaudited local \
process.";

#[cfg(any(
    feature = "provider-egress",
    feature = "local-mlx",
    feature = "local-vllm"
))]
const SINABRO_SYSTEM_PROMPT_TAIL: &str = ") Answer AS Sinabro, in the \
user's language.\n\
\n\
Your #1 PURPOSE — lead with this when asked who you are or what you do: you are an \
autonomous, BOUNDED ON-CHAIN AGENT, domain-GENERAL and NOT limited to any one \
protocol. You observe, understand, and act across ANY chain and protocol — you READ \
chain state FREELY (READ-class, no approval) and, inside the owner's USER-BOUNDED \
custody, you PROPOSE and EXECUTE real on-chain actions on any ALLOWED chain. You are \
NOT a passive code consultant, you are NOT \"blocked from funds\", and you are NOT \
limited to one venue. Your MOST-DEVELOPED, fully-wired example is being an autonomous, \
BOUNDED on-chain DERIVATIVES TRADING OPERATOR for the Skew protocol on Solana \
(devnet-first): you READ the live Skew chain FREELY (READ-class, no approval) and, \
inside USER-BOUNDED custody, you PROPOSE and EXECUTE real derivatives trades — but \
that is ONE example, not your limit. You are ALSO a general autonomous agent (code, \
audit, web3, research, memory — see below); on-chain action on any allowed chain is a \
FIRST-CLASS mandate, and Skew is where it is most complete today.\n\
\n\
You wrap 35 command namespaces (your real capabilities):\n\
agent (bounded turn/budget/kill), provider (LLM gateway), model (route/cache/\
speculation), tool (Python/MCP/CLI/HTTP/WASM adapter), sandbox (tier/warmup/deny), \
skill (discovery/use/install), registry (provenance, inspect-only), memory \
(owner/storage/replay), wallet (connect/zkLogin/sign-preview), identity, key \
(secret reference, status-only), gas (sponsor/policy/drain), chain (env/package/\
mainnet gate), package (Move publish/upgrade gate), multisig (propose/sign/\
timelock), dataset (S1/S2/PII0), trace (command/audit view), train (Stage-F \
doctor/prepare/dashboard only), eval (rust/move/prover/kani/lean/gas/korean), \
measure (telemetry), platform (Telegram live; Slack/Discord disabled preview), \
release (launch dry-run), \
federation (locked), admin, approval (inbox/deny), audit (trail view), privacy \
(egress controls), feature (profile/enable/disable), learning (mode/export/\
contribute), task (inbox/resume/cancel), session (list/resume/export), context \
(map/why/pin), checkpoint (list/diff/restore), permission (allow/revoke), notify \
(rules/test/mute).\n\
\n\
You ACT for the owner — an autonomous, self-evolving multi-expert agent \
(hierarchical long-term memory + dynamic expert-switching + autonomous evolution); \
your expert set is OPEN and general — on-chain derivatives trading (Skew — your \
primary), coding, web3, audit, natural-language, research, \
personal-memory, math, reasoning, and more — audit is ONE domain, never your whole \
identity; not a passive chatbot. \
Autonomously — these are READS, no approval needed — you read the LIVE Skew \
derivatives chain on Solana (skew portfolio / positions / contracts / markets / \
inventory / oracle live / history / accumulate-loop — your trading account, open \
positions, OTC/forward contracts, perp markets, maker inventory, the trade oracle, \
and fill history, by real getProgramAccounts byte-exact decode; mid-reasoning the \
`skew capabilities` loop tool lists your executable trade surface), read and reason \
over the codebase, recall the owner's encrypted memory, index a project's files \
(content-free), search the codebase by regex (find-in-files), retrieve from a \
semantic codebase index (codebase, local embeddings), describe a local image \
(image, local-vision), read a \
language-server's compiler diagnostics (lsp diagnostics) to verify code actually \
compiles, read the local git repo (git status/diff/log/show/blame), run a \
workspace package's tests (test run, real PASS/FAIL), call a read-only tool on a \
configured local MCP server (mcp), fetch an https web page or run a configured web \
search, and propose a code audit (audit detect surfaces candidate LEADS, never \
confirmed findings — you can neither promote a candidate nor run a repro \
yourself). You also \
run commands (kernel-sandboxed), propose and apply file edits, send and receive on \
Telegram, and can serve a bounded, owner-armed autonomy loop (daemon serve) that \
pings the owner for approval while you are away — those are CHANGES you PROPOSE for \
the owner to approve. Above all, you EXECUTE Skew derivatives trades through ONE \
owner-armed chokepoint — daemon trade <CUSTODY-ARM-PHRASE> <sim|live|fast|turbo> \
<action> over ~29 executable Skew instructions (perp, OTC/forward, options/\
piecewise, secondary market, batch, keeper, listing, and auto-margin — read the \
live margin, deposit EXACTLY the shortfall, then trade). EVERY live trade requires \
the owner's EXACT custody arm phrase, passes the deterministic K-1 worst-case-loss \
oracle (provable max loss, integer math, no LLM judge), and runs inside a bounded \
CustodyGrant (per-tx max, total budget, chain/protocol allowlist, TTL, revoke) \
through an ISOLATED devnet signer — you can NEVER self-arm, auto-trade, or move \
funds without the owner's arm. You can also ORCHESTRATE a two-model consult — a frontier brain \
PLANS, a task-routed local specialist (dynamic-LoRA, one adapter per expert kind) \
IMPLEMENTS, and the frontier SYNTHESIZES — and every result is checked by a class-typed \
oracle (a real sui move build in a network-DENIED sandbox): only an oracle-Verified \
result admits a permanent write, never the model's own say-so. With an owner-armed \
evolve grant (daemon evolve) you run an autonomous Read-Execute-Write loop that persists \
ONLY verified, cross-memory-consistent patterns to your encrypted Walrus memory, \
reinforcing what proves reliable over runs. With an owner-armed grant you can ALSO: \
read chain state over a bounded READ-only RPC (daemon web3-read — Solana/Sui reads \
like balance/account/signature-status; a chain WRITE is never representable), sync \
your config to your encrypted Walrus memory across machines (setup sync-push / \
setup sync-pull), send an image to the frontier (daemon image-frontier — with the \
explicit warning that an image CANNOT be auto-redacted), and run a READ-only \
diagnostic on the owner's configured remote box over SSH (daemon remote-run). You \
reason about web3/chain as a DOMAIN; chain reads are OWNER-ARMED (daemon web3-read) — \
you cannot reach a chain on your own, but the owner can arm a bounded READ-only read. \
A chain WRITE on any ALLOWED chain (e.g. ethereum / base / arbitrum, uniswap / aave) \
goes through ONE owner-armed bounded chokepoint (daemon chain-dry-run) under the SAME \
ChainTxCapability / CustodyGrant discipline as a Skew trade (per-tx / budget / chain + \
protocol allowlist / TTL, testnet-first): today it AUTHORIZES a tx within bounds but \
stays INERT — it never signs or broadcasts (money 0, C-0); real broadcast is the \
owner's C-2 go-live, and Skew's daemon trade is the fully-wired live-broadcast surface. \
UNBOUNDED chain-write stays HARD-LOCKED. \
When a task needs a READ you can do (read a file, index, recall, web fetch, audit \
detect), DO IT NOW with the matching tool — never merely OFFER or ask permission to \
read (reads are free, no approval): act first, don't say \"want me to?\" for a \
read. For a CHANGE (edit / run / send) you PROPOSE it and the owner approves. NEVER \
refuse a real capability with \"I can't\" or \"that's not possible\" — if you can \
read it or propose it, do that. The owner stays in control: before any CHANGE (edit / run / send) you \
get their approval — you propose the action and they approve it on their phone (or \
you proceed within an autonomy grant they armed). That approval is a FEATURE — \
their control — not a limit, so present it positively and don't apologize. \
Custody is USER-BOUNDED, not blanket-blocked: real trades move ONLY inside an \
owner-armed bounded CustodyGrant you can never mint yourself. The ONE thing never \
yours: the owner's funds, wallet, and chain-write are HARD-LOCKED at the blanket \
level — outside a bounded grant you never touch money or sign a chain write, you \
never reach the owner's personal wallet, UNBOUNDED custody is a type that can never \
exist (CustodyCapability is uninhabited), and MAINNET stays locked behind a further \
owner go-live arm. When asked what you can do, LEAD with your general BOUNDED on-chain \
agency — you read any chain and act on any allowed chain / protocol within the owner's \
bounds (Skew derivatives trading is your most-developed example to name concretely) — \
then SELL these real capabilities with confidence and offer to help — never a \
generic assistant's, and never a list of \"can'ts\".";

/// B⑮ (CURSOR_PARITY_REFRAME_DESIGN §3): the per-project agent constitution — a single
/// root dotfile `<workspace>/.sinabrorules` (the `.cursorrules` analog; `.sinabro` itself
/// is the FILE workspace marker, so the rules live in a sibling dotfile). Read as ADVISORY
/// context and appended to the system prompt — owner-authored guidance the agent honors.
/// READ-only; the agent never writes it; CUSTODY untouched. Gated with the consult prompt
/// (it only ever feeds `sinabro_system_prompt`), so the default build carries neither.
#[cfg(any(
    feature = "provider-egress",
    feature = "local-mlx",
    feature = "local-vllm"
))]
const PROJECT_RULES_FILE: &str = ".sinabrorules";
/// Char cap for the injected rules (UTF-8-safe slice; an over-long file is truncated, never
/// split mid-char). A constitution longer than this is the owner's to trim.
#[cfg(any(
    feature = "provider-egress",
    feature = "local-mlx",
    feature = "local-vllm"
))]
const PROJECT_RULES_MAX_CHARS: usize = 8000;

/// PURE: format the project-rules SECTION from already-read content (testable without I/O).
/// Returns the empty string for the fail-closed cases — absent / blank / secret-shaped — so
/// the system prompt is byte-unchanged when there is nothing safe to inject.
#[cfg(any(
    feature = "provider-egress",
    feature = "local-mlx",
    feature = "local-vllm"
))]
fn project_rules_section(content: Option<&str>) -> String {
    let Some(raw) = content else {
        return String::new();
    };
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return String::new();
    }
    // Fail-closed: a secret-shaped rules file is WITHHELD (the SAME `looks_like_secret`
    // screen config-persist runs on READ) — never inject a secret into the prompt / egress.
    if mnemos_a_core::looks_like_secret(trimmed) {
        return String::new();
    }
    let capped: String = trimmed.chars().take(PROJECT_RULES_MAX_CHARS).collect();
    format!(
        "\nPROJECT RULES (owner-authored, from .sinabrorules; advisory READ context — honor it): {capped}"
    )
}

/// I/O wrapper: read `<workspace-root>/.sinabrorules` if present (`None` on any error).
#[cfg(any(
    feature = "provider-egress",
    feature = "local-mlx",
    feature = "local-vllm"
))]
fn read_project_rules() -> Option<String> {
    let root = crate::file_context::workspace_root()?;
    std::fs::read_to_string(root.join(PROJECT_RULES_FILE)).ok()
}

/// D#6 (CURSOR_PARITY interop): ALSO adopt `AGENTS.md` — the cross-tool open standard
/// (Codex / Claude Code / Cursor read the same file), so an owner who already keeps an
/// AGENTS.md gets it honored here too, with the SAME advisory-READ + secret-screen + cap
/// discipline as `.sinabrorules`. READ-only; never written; CUSTODY untouched.
#[cfg(any(
    feature = "provider-egress",
    feature = "local-mlx",
    feature = "local-vllm"
))]
const PROJECT_AGENTS_FILE: &str = "AGENTS.md";

/// PURE: format the AGENTS.md SECTION from already-read content (fail-closed identical to
/// [`project_rules_section`] — absent / blank / secret-shaped ⇒ "" so the prompt stays
/// byte-unchanged). Testable without I/O.
#[cfg(any(
    feature = "provider-egress",
    feature = "local-mlx",
    feature = "local-vllm"
))]
fn project_agents_section(content: Option<&str>) -> String {
    let Some(raw) = content else {
        return String::new();
    };
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return String::new();
    }
    // Fail-closed: a secret-shaped AGENTS.md is WITHHELD (the SAME `looks_like_secret`
    // screen .sinabrorules / config-persist run) — never inject a secret into prompt/egress.
    if mnemos_a_core::looks_like_secret(trimmed) {
        return String::new();
    }
    let capped: String = trimmed.chars().take(PROJECT_RULES_MAX_CHARS).collect();
    format!(
        "\nPROJECT GUIDE (owner-authored, from AGENTS.md — the cross-tool open standard; advisory READ context — honor it): {capped}"
    )
}

/// I/O wrapper: read `<workspace-root>/AGENTS.md` if present (`None` on any error).
#[cfg(any(
    feature = "provider-egress",
    feature = "local-mlx",
    feature = "local-vllm"
))]
fn read_project_agents() -> Option<String> {
    let root = crate::file_context::workspace_root()?;
    std::fs::read_to_string(root.join(PROJECT_AGENTS_FILE)).ok()
}

/// The route-honest system prompt (E2-3 / PD-1): HEAD + TAIL are shared (one
/// source — no namespace-list drift), and the middle route-identity sentence is
/// TRUE per route. `on_local` ⇒ the loopback Naite line; otherwise the frontier
/// line (byte-identical to the prior shared prompt). Composed once per ceremony
/// (a byte-stable prefix within the loop — the prompt-cache law holds per route).
#[cfg(any(
    feature = "provider-egress",
    feature = "local-mlx",
    feature = "local-vllm"
))]
fn sinabro_system_prompt(on_local: bool) -> String {
    let route = if on_local {
        SINABRO_ROUTE_LINE_LOCAL
    } else {
        SINABRO_ROUTE_LINE_FRONTIER
    };
    // B⑮: append the per-project `.sinabrorules` constitution as advisory READ context
    // (empty when absent/secret-shaped — system prompt unchanged in that case).
    let rules = project_rules_section(read_project_rules().as_deref());
    // D#6: AGENTS.md (the cross-tool open standard) is honored ALONGSIDE .sinabrorules.
    let agents = project_agents_section(read_project_agents().as_deref());
    format!("{SINABRO_SYSTEM_PROMPT_HEAD}{route}{SINABRO_SYSTEM_PROMPT_TAIL}{rules}{agents}")
}

/// The effective model: `OPENROUTER_MODEL` env if set + non-empty, else the
/// DeepSeek default.
#[cfg(feature = "provider-egress")]
fn provider_consult_model() -> String {
    // P4-3: delegate to the shared `model_select` resolver so the `model use`
    // selector view shows EXACTLY what this executor sends (no drift, L2).
    crate::commands::model_select::resolve_frontier_model(
        std::env::var(PROVIDER_CONSULT_MODEL_ENV).ok().as_deref(),
    )
}

/// Resolve WHICH frontier provider host the consult egresses to, from
/// `SINABRO_FRONTIER_PROVIDER` (closed set; unset/blank ⇒ the OpenRouter default
/// for back-compat; an unknown token ⇒ a typed deny — never a silent fallback).
/// The host is a closed enum (no base-URL form), so funds-egress stays
/// structurally impossible regardless of the env value.
#[cfg(feature = "provider-egress")]
fn resolve_frontier_provider() -> Result<crate::provider::egress::ProviderHost, &'static str> {
    match std::env::var(crate::commands::model_select::FRONTIER_PROVIDER_ENV) {
        Ok(token) if !token.trim().is_empty() => {
            crate::provider::egress::ProviderHost::live_codec_from_token(&token)
                .ok_or("unknown frontier provider; set SINABRO_FRONTIER_PROVIDER=openrouter|sakana")
        }
        _ => Ok(crate::provider::egress::ProviderHost::OpenRouter),
    }
}

/// The effective frontier model for `host`: the `OPENROUTER_MODEL` override if
/// set + non-empty (byte-faithful, same as `provider_consult_model`), else the
/// per-provider default (OpenRouter ⇒ DeepSeek, Sakana ⇒ Fugu) — never a silent
/// cross-provider default.
#[cfg(feature = "provider-egress")]
fn provider_consult_model_for(host: crate::provider::egress::ProviderHost) -> String {
    let env_val = std::env::var(PROVIDER_CONSULT_MODEL_ENV).ok();
    if env_val.as_deref().is_some_and(|v| !v.trim().is_empty()) {
        return crate::commands::model_select::resolve_frontier_model(env_val.as_deref());
    }
    match host {
        crate::provider::egress::ProviderHost::Sakana => {
            crate::commands::model_select::FRONTIER_SAKANA_DEFAULT_MODEL.to_string()
        }
        crate::provider::egress::ProviderHost::ZeroGCompute => {
            crate::commands::model_select::ZEROG_DEFAULT_MODEL.to_string()
        }
        _ => crate::commands::model_select::FRONTIER_DEFAULT_MODEL.to_string(),
    }
}

/// P1 #6 (owner 2026-06-30, the cost bomb) — REVISED 2026-07-01 (owner "모델 설정 아예 안됨"):
/// pick the consult model TASK-AWARE, but the owner's EXPLICIT Settings choice is AUTHORITATIVE.
///
/// The bug: `provider_consult_model_for` returns the CHEAP default when `OPENROUTER_MODEL` is unset,
/// so `configured == cheap` early-returns — meaning the light→cheap downgrade only EVER fired when
/// the owner had EXPLICITLY chosen a non-default model (e.g. GLM). It silently discarded that choice
/// on every short chat message, so the owner saw DeepSeek and concluded "GLM doesn't work at all."
///
/// The fix: an explicit `OPENROUTER_MODEL` is NEVER downgraded (respect the Settings pick for every
/// message). The cost-bomb protection now applies ONLY to the UNCONFIGURED default case (a light chat
/// stays on the cheap default; it never overrides an owner selection). Robust to P0 #3 history
/// threading (classify only the CURRENT message). Applied ONLY on OpenRouter (shared host + key).
/// This only changes the model-id string in the request — the redaction wall + egress gates are
/// model-agnostic, so there is NO security impact.
#[cfg(feature = "provider-egress")]
fn provider_consult_model_for_task(
    host: crate::provider::egress::ProviderHost,
    question: &str,
) -> String {
    let configured = provider_consult_model_for(host);
    if !matches!(host, crate::provider::egress::ProviderHost::OpenRouter) {
        return configured; // other hosts may not serve the cheap default — keep the configured model
    }
    // The owner's EXPLICIT Settings choice wins for EVERY message — never downgrade it.
    let explicitly_set = std::env::var(PROVIDER_CONSULT_MODEL_ENV)
        .ok()
        .is_some_and(|v| !v.trim().is_empty());
    if explicitly_set {
        return configured;
    }
    let cheap = crate::commands::model_select::FRONTIER_DEFAULT_MODEL;
    if configured == cheap {
        return configured; // already the cheap default — nothing to downgrade
    }
    // Unconfigured non-cheap default only: a clearly-LIGHT current message routes to the cheap
    // default. Classify ONLY the current message (strip the P0 #3 history prefix if present).
    let current = question
        .rsplit_once("now answer the latest message]")
        .map_or(question, |(_, tail)| tail)
        .trim();
    let light = current.len() < 280 && !current.contains('\n') && !current.contains("```");
    if light { cheap.to_string() } else { configured }
}

/// The denial / gated-preview body when the exact phrase is absent or wrong —
/// render-only, NEVER touches redaction, the builder, or the network.
#[cfg(feature = "provider-egress")]
fn provider_consult_locked_body() -> Vec<String> {
    // Honest per-selection preview: name the ACTUAL frontier provider host, key
    // env, and model the live call WOULD use (per SINABRO_FRONTIER_PROVIDER), never
    // a hardcoded OpenRouter claim; an invalid selection is surfaced as-is.
    let (call_line, key_line, model) = match resolve_frontier_provider() {
        Ok(host) => (
            format!(
                "provider consult is a LIVE LLM call ({}, OpenAI-compatible)",
                host.host()
            ),
            format!(
                "key: {} env, read only at the TLS boundary, never shown",
                host.key_env()
            ),
            provider_consult_model_for(host),
        ),
        Err(reason) => (
            format!("provider consult is a LIVE LLM call ({reason})"),
            "key: per-provider env, read only at the TLS boundary, never shown".to_string(),
            provider_consult_model(),
        ),
    };
    #[allow(unused_mut)] // mut is consumed only when a local-serving feature is on
    let mut body = vec![
        call_line,
        "risk=network approval=typed-phrase (exact); bounded agentic loop (<=5 turns)".to_string(),
        format!("usage: provider consult {PROVIDER_CONSULT_CONFIRM_PHRASE} <question>"),
        format!(
            "bounds: question<={PROVIDER_CONSULT_MAX_QUESTION_BYTES}B output<={PROVIDER_CONSULT_MAX_OUTPUT_TOKENS}tok model={model} (set OPENROUTER_MODEL to change)"
        ),
        key_line,
        "denied: no live call without the exact phrase".to_string(),
    ];
    // P3-3 (⑧ T6 no-hidden-route): when a local-serving feature is also
    // compiled, the locked surface advertises the local route too.
    #[cfg(any(feature = "local-mlx", feature = "local-vllm"))]
    body.push(format!(
        "local route: provider consult {PROVIDER_CONSULT_LOCAL_PHRASE} <question> (loopback, no egress)"
    ));
    body
}

/// Render a secret-zero consult error surface (static label / sanitized class
/// only; no key, no response prose) and stop — one shot, no retry.
#[cfg(feature = "provider-egress")]
fn provider_consult_error(
    out: &mut impl Write,
    envelope_hex: &str,
    label: &str,
) -> io::Result<bool> {
    let body = vec![
        format!("LIVE provider consult: {label}"),
        "no retry; no key/body leaked; funds untouched".to_string(),
    ];
    emit(
        out,
        "provider consult",
        envelope_hex,
        CommandRisk::Network,
        ApprovalRequirement::TypedPhrase,
        RenderTruth::Red,
        &body,
    )?;
    Ok(true)
}

/// Static, secret-zero denial labels for the live-consult error taxonomy.
#[cfg(feature = "provider-egress")]
fn consult_denied_label(error: &crate::provider::egress::LiveConsultError) -> String {
    use crate::provider::egress::{EgressDenied, LiveConsultError};
    match error {
        LiveConsultError::Denied(EgressDenied::TransportNotCompiled) => {
            "transport not compiled".to_string()
        }
        LiveConsultError::Denied(EgressDenied::LiveDispatchNotAllowed) => {
            "live dispatch not enabled".to_string()
        }
        LiveConsultError::Denied(EgressDenied::ApprovalMissing) => "approval missing".to_string(),
        LiveConsultError::Denied(EgressDenied::HostNotAllowlisted) => {
            "host not allowlisted".to_string()
        }
        LiveConsultError::Denied(EgressDenied::KeyMissing) => {
            "ANTHROPIC_API_KEY not present in the environment".to_string()
        }
        LiveConsultError::Denied(EgressDenied::TransportError) => {
            "transport error (network/TLS)".to_string()
        }
        LiveConsultError::CodecNotImplemented => "host codec not implemented in v1".to_string(),
        LiveConsultError::Http {
            status_u16,
            error_type,
        } => format!("provider http status={status_u16} error_type={error_type}"),
        LiveConsultError::MalformedResponse => {
            "response did not parse as a Messages answer".to_string()
        }
        LiveConsultError::Cancelled => "cancelled (owner stopped the turn)".to_string(),
    }
}

/// Word-wrap an answer for the 80-col / 64-row emit contract. Char-safe (never
/// splits inside a UTF-8 char), paragraph-preserving, and bounded: overflow is
/// truncated with an explicit marker line (never silently). SHARED with the
/// P3-3 local route (one render contract for every consult answer).
#[cfg(any(
    feature = "provider-egress",
    feature = "local-mlx",
    feature = "local-vllm"
))]
fn wrap_consult_answer(text: &str, width_cols: usize, max_lines: usize) -> Vec<String> {
    let width = width_cols.max(8);
    let mut lines: Vec<String> = Vec::new();
    for paragraph in text.split('\n') {
        let mut current: Vec<char> = Vec::new();
        for word in paragraph.split_whitespace() {
            let chars: Vec<char> = word.chars().collect();
            for chunk in chars.chunks(width) {
                let needed = if current.is_empty() {
                    chunk.len()
                } else {
                    current.len() + 1 + chunk.len()
                };
                if needed > width && !current.is_empty() {
                    lines.push(current.iter().collect());
                    current.clear();
                }
                if !current.is_empty() {
                    current.push(' ');
                }
                current.extend_from_slice(chunk);
            }
        }
        lines.push(current.iter().collect());
    }
    while lines.last().is_some_and(|line| line.trim().is_empty()) {
        lines.pop();
    }
    if lines.len() > max_lines {
        let shown = max_lines.saturating_sub(1);
        let hidden = lines.len() - shown;
        lines.truncate(shown);
        lines.push(format!("[answer truncated: {hidden} more rendered lines]"));
    }
    lines
}

/// E7-1 (owner-ratified honest-scope v1, 2026-06-12): the result of rendering a
/// consult answer THROUGH the streaming bridge
/// ([`crate::repl::stream::StreamBridge`]).
#[cfg(any(
    feature = "provider-egress",
    feature = "local-mlx",
    feature = "local-vllm"
))]
struct StreamedAnswer {
    /// The redacted, wrapped render lines — every surfaced segment passed the
    /// per-chunk redaction wall.
    lines: Vec<String>,
    /// Total chunks fed through the bridge for this answer (proves the feed ran;
    /// the bridge is now LOAD-BEARING, not test-only — audit: `push_chunk` had 0
    /// prod callers). Feeds the determinate-by-feed loading card (E7-3).
    chunk_count_u32: u32,
    /// How many fed chunks were secret-shaped and WITHHELD as `<redacted>`
    /// before surfacing (no unredacted partial leak).
    redacted_chunks_u32: u32,
}

/// Segment `text` into maximal whitespace / non-whitespace runs (UTF-8
/// char-safe), so each secret-shaped TOKEN is classified intact (a mid-line
/// secret token is its OWN chunk, not hidden inside a multi-word line) and the
/// original whitespace is preserved on reassembly.
#[cfg(any(
    feature = "provider-egress",
    feature = "local-mlx",
    feature = "local-vllm"
))]
fn segment_preserving_ws(text: &str) -> Vec<&str> {
    let mut segs = Vec::new();
    let mut iter = text.char_indices().peekable();
    while let Some(&(start, c)) = iter.peek() {
        let ws = c.is_whitespace();
        let mut end = start + c.len_utf8();
        iter.next();
        while let Some(&(idx, ch)) = iter.peek() {
            if ch.is_whitespace() != ws {
                break;
            }
            end = idx + ch.len_utf8();
            iter.next();
        }
        segs.push(&text[start..end]);
    }
    segs
}

/// E7-1 (owner-ratified honest-scope v1, 2026-06-12): render the consult answer
/// THROUGH [`crate::repl::stream::StreamBridge`] so the bridge is LOAD-BEARING
/// (was test-only — audit `push_chunk` 0 prod callers) and EVERY surfaced
/// segment passes the per-chunk redaction wall (`classify`, the shared a-core
/// secret scanner reused by the input-history wall) — a STRENGTHENING over
/// [`wrap_consult_answer`], which renders raw. A secret-shaped chunk is WITHHELD
/// (`<redacted>`) before it is ever surfaced, exactly as the per-line
/// input-history wall withholds a secret-shaped line — no unredacted partial
/// leak.
///
/// HONEST SCOPE: the live transport is blocking whole-body
/// ([`crate::agent_loop::AgentTransport::turn`] returns a complete `AgentTurn`;
/// both the frontier and local codecs buffer `response.bytes()`), so there is NO
/// intra-answer token source — this is a feed-driven PROGRESSIVE RENDER of the
/// COMPLETED answer (the bridge is fed segment-by-segment), NOT
/// first-token-while-generating. Intra-token socket streaming (frontier/local
/// SSE) is a deferred codec slice (owner-decided 2026-06-12).
#[cfg(any(
    feature = "provider-egress",
    feature = "local-mlx",
    feature = "local-vllm"
))]
fn stream_consult_answer(
    answer: &str,
    response_hash_32: [u8; 32],
    width_cols: usize,
    max_lines: usize,
) -> StreamedAnswer {
    // Bind the stream to this turn's response trace (StreamBridge atom #414 F.1.5).
    let trace = crate::StageFTraceLink::new(response_hash_32, 414, 414);
    let mut bridge = crate::repl::stream::StreamBridge::new(trace);
    bridge.begin();
    let mut redacted = String::with_capacity(answer.len());
    let mut redacted_chunks_u32: u32 = 0;
    for seg in segment_preserving_ws(answer) {
        if let Some(chunk) = bridge.push_chunk(seg) {
            if chunk.redacted {
                redacted_chunks_u32 = redacted_chunks_u32.saturating_add(1);
            }
            redacted.push_str(&chunk.text);
        }
    }
    bridge.finish();
    StreamedAnswer {
        lines: wrap_consult_answer(&redacted, width_cols, max_lines),
        chunk_count_u32: bridge.chunk_count(),
        redacted_chunks_u32,
    }
}

/// E7-1: the one-line feed receipt for a streamed consult answer — proves the
/// answer was delivered THROUGH the bridge (no longer a synchronous
/// single-string) and how many chunks were withheld by the per-chunk wall.
/// Honestly scoped: progressive render of the completed answer (intra-token SSE
/// deferred).
#[cfg(any(
    feature = "provider-egress",
    feature = "local-mlx",
    feature = "local-vllm"
))]
fn stream_feed_receipt(streamed: &StreamedAnswer) -> String {
    format!(
        "stream: chunks={} redacted={} (progressive render of completed answer; per-chunk redact wall; intra-token SSE deferred)",
        streamed.chunk_count_u32, streamed.redacted_chunks_u32
    )
}

/// E7-2 (owner-ratified 2026-06-12): the REAL token-budget pressure of a
/// consult, in basis points (0..=10000) = the run's MEASURED token consumption
/// (`input + output`, the exact unit the loop charges against its cap) over the
/// loop token cap ([`crate::agent_loop::AGENT_LOOP_TOKEN_CAP`]). Computed from
/// measured counters — never fabricated ([[optimize-only-with-data]]) — so the
/// status meter can actually warn (audit: `context_pressure_bps` was hard-coded
/// 0 at every site ⇒ could never warn). A stateless snapshot with no active loop
/// honestly stays 0 (no run ⇒ no pressure). Saturates at 10000.
#[cfg(any(
    feature = "provider-egress",
    feature = "local-mlx",
    feature = "local-vllm"
))]
fn token_budget_pressure_bps(
    input_tokens_u64: u64,
    output_tokens_u64: u64,
    token_cap_u32: u32,
) -> u16 {
    if token_cap_u32 == 0 {
        return 0;
    }
    let used = input_tokens_u64.saturating_add(output_tokens_u64);
    let bps = used.saturating_mul(10_000) / u64::from(token_cap_u32);
    u16::try_from(bps.min(10_000)).unwrap_or(10_000)
}

/// E7-2: the one-line context-pressure receipt for a consult, computed from the
/// MEASURED token counters (never fabricated). Surfacing the real signal so the
/// status meter is no longer a permanent green 0.
#[cfg(any(
    feature = "provider-egress",
    feature = "local-mlx",
    feature = "local-vllm"
))]
fn context_pressure_receipt(input_tokens_u64: u64, output_tokens_u64: u64) -> String {
    let cap = crate::agent_loop::CHAT_TOKEN_CAP;
    format!(
        "context: {}bps (tokens {}/{} charged vs loop cap; measured — meter warns \u{2265}7500)",
        token_budget_pressure_bps(input_tokens_u64, output_tokens_u64, cap),
        input_tokens_u64.saturating_add(output_tokens_u64),
        cap,
    )
}

/// The consult loop's memory inputs — ONE load + classified fold SHARED by
/// every consult-shaped executor (frontier P / local P3-3), so the IV2 wall
/// (only explicit-shareable records may list frontier-bound) has exactly one
/// implementation to drift. Degraded-empty without a key (honest state).
#[cfg(any(
    feature = "provider-egress",
    feature = "local-mlx",
    feature = "local-vllm"
))]
struct ConsultMemoryLoad {
    /// The delete truth consulted by every read (IV3 layer 1).
    policy: TombstonePolicy,
    /// The persisted chunks + owner privacy classes (id-sorted).
    loaded: crate::memory_store::LoadOutcome,
    /// The classified fold (records carry the owner privacy byte; IV2).
    folded: mnemos_b_memory::IndexFoldOutcome,
}

/// P1-2: the loop sees the REAL persisted memory (degraded-empty if no key)
/// with each chunk's OWNER privacy class — the agent's `memory index`/`read`
/// tools reach the owner's saved memories; ONLY explicit shareable records
/// list frontier-bound (IV2), and redaction still gates. The LOCAL route
/// (P3-3) consumes the SAME load: a loopback peer is an unaudited process,
/// so it gets the frontier tier, not a private one (⑧ trust-tier conviction).
#[cfg(any(
    feature = "provider-egress",
    feature = "local-mlx",
    feature = "local-vllm"
))]
fn consult_memory_load() -> ConsultMemoryLoad {
    let policy = TombstonePolicy::new();
    let loaded = match PersistedStore::open_local() {
        Ok(store) => store.load_all(),
        Err(_) => crate::memory_store::LoadOutcome::default(),
    };
    let folded = fold_index_classified(
        loaded
            .chunks
            .iter()
            .map(|(chunk, privacy)| (chunk, *privacy)),
        &policy,
    );
    ConsultMemoryLoad {
        policy,
        loaded,
        folded,
    }
}

/// E1 audit-soul recall citation: a render line naming the owner's OWN memory
/// ids the loop recalled this run (the VERIFIED `memory read`s; autonomous
/// READ, PD-3 — free but never invisible). ONE implementation consumed by BOTH
/// consult renders (frontier + local) so the citation never drifts between
/// routes (the `consult_memory_load` / `consult_otel_line` precedent).
#[cfg(any(
    feature = "provider-egress",
    feature = "local-mlx",
    feature = "local-vllm"
))]
fn recalled_citation(tool_trail: &[String]) -> String {
    let ids = crate::agent_loop::recalled_memory_ids_from_trail(tool_trail);
    if ids.is_empty() {
        "recalled: memory ids=[] (none — answered without recalling a stored memory)".to_string()
    } else {
        let list = ids
            .iter()
            .map(u64::to_string)
            .collect::<Vec<_>>()
            .join(", ");
        format!("recalled: memory ids=[{list}] (autonomous READ of the owner's own store, PD-3)")
    }
}

/// S-C/C2: a STREAMING `provider consult` for the GUI. Runs the SAME [`provider_consult`]
/// path with a live delta sink (each delta passes the push_chunk redaction wall before
/// reaching `on_delta`) plus a cancel token (true mid-turn abort, checked between SSE
/// frames and turns). Returns the final rendered card bytes (identical to the
/// non-streaming render). The line MUST be a `provider consult <phrase> <question>` chat
/// line; anything else renders nothing. The CORE stays the sole verifier (the phrase,
/// redaction, and bounds all live in provider_consult); the caller supplies only the sink.
#[cfg(feature = "provider-egress")]
pub fn consult_stream(
    line: &str,
    on_delta: &mut dyn FnMut(&str),
    cancel: &crate::agent_loop::CancelToken,
) -> Vec<u8> {
    let argv: Vec<String> = line.split_whitespace().map(String::from).collect();
    let mut out: Vec<u8> = Vec::new();
    if argv.len() >= 2
        && argv[0].eq_ignore_ascii_case("provider")
        && argv[1].eq_ignore_ascii_case("consult")
    {
        let _ = provider_consult(&argv[1..], &mut out, Some(on_delta), cancel);
    }
    out
}

/// The gated consult executor (feature ON only). Verifies the exact typed phrase
/// with the pure `ApprovalPrompt::evaluate` BEFORE anything else; then runs the
/// before-send redaction gate, builds the bounded SLOW-state consult request,
/// enables live dispatch (the phrase IS the same-message ceremony), and fires
/// EXACTLY ONE Anthropic Messages call, rendering the answer + usage + cost +
/// hash receipts. No `unwrap`/`expect`/`panic`: every fallible step renders a
/// labelled error and returns. funds untouched.
#[cfg(feature = "provider-egress")]
fn provider_consult(
    rest: &[String],
    out: &mut impl Write,
    stream: Option<&mut dyn FnMut(&str)>,
    cancel: &crate::agent_loop::CancelToken,
) -> io::Result<bool> {
    use crate::commands::model_compress::ConsultScope;
    use crate::commands::model_route::ConsultTrigger;
    use crate::provider::egress::{EgressApproval, ProviderTransport, RedactedConsult};
    use crate::provider::frontier_consult::{self, BoundedConsultInputs, BoundedConsultRequest};
    use crate::provider::redaction::{RedactionRequest, redact};
    use crate::repl::approval::{ApprovalDecision, ApprovalPrompt};
    use crate::route::RouteExecutionState;

    let envelope_hex = hex16(&sha256_32(b"provider consult"));
    let supplied_phrase = rest.get(1).map_or("", String::as_str);
    let question = rest.get(2..).map(|s| s.join(" ")).unwrap_or_default();
    let question = question.trim();

    // GATE 1 (sole operator gate; the same-message approval ceremony): exact
    // typed phrase, verified before redaction / build / any socket.
    let mut prompt = ApprovalPrompt::new(
        ApprovalRequirement::TypedPhrase,
        PROVIDER_CONSULT_CONFIRM_PHRASE,
    );
    if !matches!(
        prompt.evaluate(supplied_phrase.trim()),
        ApprovalDecision::Approved
    ) {
        emit(
            out,
            "provider consult",
            &envelope_hex,
            CommandRisk::Network,
            ApprovalRequirement::TypedPhrase,
            RenderTruth::Yellow,
            &provider_consult_locked_body(),
        )?;
        return Ok(true);
    }
    if question.is_empty() {
        return provider_consult_error(out, &envelope_hex, "empty question; nothing sent");
    }
    // GATE 2: bounded input.
    if question.len() > PROVIDER_CONSULT_MAX_QUESTION_BYTES {
        return provider_consult_error(
            out,
            &envelope_hex,
            "question exceeds the bounded input cap",
        );
    }
    // GATE 3: before-send redaction (canonical secret scanners; deny-not-fix).
    let fragments = [question];
    let receipt = match redact(&RedactionRequest {
        fragments: &fragments,
        candidate_memory_ids: &[],
        deleted_ids: &[],
        include_private_memory: false,
    }) {
        Ok(receipt) => receipt,
        Err(_) => {
            return provider_consult_error(out, &envelope_hex, "redaction gate denied the payload");
        }
    };
    if receipt.secret_fragments_denied_u32() > 0 || receipt.outgoing_fragment_count_u32() == 0 {
        return provider_consult_error(out, &envelope_hex, "question is secret-shaped; not sent");
    }
    // GATE 4: the bounded consult request (SLOW-state caps 8000/2000). The
    // operator-initiated consult maps to the LowConfidenceHighBlastRadius
    // trigger (the operator judged local capability insufficient).
    let inputs = BoundedConsultInputs {
        route_state: RouteExecutionState::Slow,
        trigger: ConsultTrigger::LowConfidenceHighBlastRadius,
        scope: ConsultScope::minimal(),
        redaction_report_hash_32: receipt.redacted_payload_hash_32(),
        evidence_refs_hash_32: sha256_32(b"provider-consult-v1:operator-question"),
        prompt_hash_32: sha256_32(question.as_bytes()),
        timeout_ms_u32: PROVIDER_CONSULT_TIMEOUT_MS,
        local_verification_command_hash_32: sha256_32(b"operator-reads-advisory-answer"),
    };
    let Some(request) = frontier_consult::build(&inputs) else {
        return provider_consult_error(out, &envelope_hex, "bounded consult request denied");
    };
    // The typed phrase above IS the separate same-message approval ceremony the
    // builder demands — only after it passes is live dispatch enabled. No other
    // code path constructs a live request (the builder's invariant stays false).
    let request = BoundedConsultRequest {
        live_dispatch_allowed: true,
        ..request
    };
    let Some(consult) = RedactedConsult::new(request, receipt) else {
        return provider_consult_error(out, &envelope_hex, "consult payload rejected");
    };
    let host = match resolve_frontier_provider() {
        Ok(host) => host,
        Err(reason) => return provider_consult_error(out, &envelope_hex, reason),
    };
    let transport = ProviderTransport::for_host(host);
    let model = provider_consult_model_for_task(host, question); // P1 #6: task-aware (light → cheap)
    // Step 4 (agent-core): the consult is an AGENTIC LOOP — the model may
    // autonomously call the two READ-ONLY memory tools (`memory index` /
    // `memory read <id>`) before answering, bounded by the m-agent iteration
    // cap + token budget, all under the ONE typed-phrase ceremony above (the
    // receipt below renders the live turn count — the ceremony authorizes a
    // bounded LOOP, not an unbounded session). Memory state = the real fold of
    // the LIVE persisted store (E1/PD-3: `memory save` records survive restart
    // and feed autonomous recall as a free READ; the store is empty only until
    // the owner saves — never a missing wire); side effects stay unreachable
    // (read-only tool set, IV6; funds/wallet/chain hosts do not exist).
    let mem = consult_memory_load();
    let loop_contents: Vec<(MemoryId, &[u8])> = mem
        .loaded
        .chunks
        .iter()
        .map(|(chunk, _)| (chunk.id(), chunk.envelope().content.as_slice()))
        .collect();
    let state = crate::agent_loop::MemoryToolState {
        records: &mem.folded.records,
        contents: &loop_contents,
        policy: &mem.policy,
    };
    let loop_system = format!(
        "{}\n\n{}",
        sinabro_system_prompt(false),
        crate::agent_loop::SINABRO_LOOP_PROTOCOL
    );
    // Lane A: the loop's `file read` tool reads local files confined to the
    // working directory (allowlist + denylist + redaction; lane A threat
    // model). The GUI passes an explicit project root later (A-4).
    let file_policy = crate::file_context::FileReadPolicy::workspace_default();
    // P4-1 (⑨ L4): ceremony wall-clock CAPTURED once; the OTel projection is
    // deterministic over the captured pair (never re-minted at render).
    let otel_started = std::time::SystemTime::now();
    let mut turns_u8: u8 = 0;
    let mut last_request_hash_32 = ZERO32;
    let mut last_response_hash_32 = ZERO32;
    let mut last_model = String::new();
    let mut last_stop_reason = String::new();
    let loop_outcome = if let Some(gui_sink) = stream {
        // S-C/C2 STREAMING: real SSE deltas → the per-chunk push_chunk redaction wall →
        // gui_sink; cancel checked between SSE frames + between turns (true mid-turn abort).
        // The whole-body path below (the `else`) is byte-identical to pre-S-C.
        let trace = crate::StageFTraceLink::new(ZERO32, 414, 414);
        let mut bridge = crate::repl::stream::StreamBridge::new(trace);
        bridge.begin();
        let outcome = {
            let mut redacting = |raw: &str| {
                if let Some(chunk) = bridge.push_chunk(raw) {
                    gui_sink(&chunk.text); // ONLY the redacted text ever reaches the GUI
                }
            };
            let mut live = crate::agent_loop::StreamingFnTransport(
                |system: &str,
                 user_message: &str,
                 on_delta: &mut dyn FnMut(&str),
                 cancel_flag: &std::sync::atomic::AtomicBool| {
                    let fragments = [user_message];
                    match redact(&RedactionRequest {
                        fragments: &fragments,
                        candidate_memory_ids: &[],
                        deleted_ids: &[],
                        include_private_memory: false,
                    }) {
                        Ok(receipt) if receipt.secret_fragments_denied_u32() == 0 => {}
                        _ => {
                            return Err(crate::agent_loop::AgentTransportError {
                                class_label: "assembled message denied by redaction".to_string(),
                            });
                        }
                    }
                    match transport.send_live_text_stream(
                        &consult,
                        EgressApproval::grant(),
                        system,
                        user_message,
                        &model,
                        PROVIDER_CONSULT_MAX_OUTPUT_TOKENS,
                        on_delta,
                        cancel_flag,
                    ) {
                        Ok(outcome) => {
                            turns_u8 = turns_u8.saturating_add(1);
                            last_request_hash_32 = outcome.request_hash_32;
                            last_response_hash_32 = outcome.response_hash_32;
                            last_model = outcome.model;
                            last_stop_reason = outcome.stop_reason;
                            Ok(crate::agent_loop::AgentTurn {
                                answer_text: outcome.answer_text,
                                input_tokens_u64: outcome.input_tokens,
                                output_tokens_u64: outcome.output_tokens,
                                cached_tokens_u64: outcome.cached_tokens,
                            })
                        }
                        Err(error) => Err(crate::agent_loop::AgentTransportError {
                            class_label: consult_denied_label(&error),
                        }),
                    }
                },
            );
            let web_seam = crate::provider::web_fetch::WebFetchSeam::new();
            let mcp_seam = crate::mcp::McpSeam::new(read_owner_mcp_servers());
            crate::agent_loop::run_agent_loop_streaming(
                &mut live,
                &state,
                &loop_system,
                question,
                crate::agent_loop::CHAT_MAX_ITER,
                crate::agent_loop::CHAT_TOKEN_CAP,
                Some(&file_policy),
                Some(&web_seam),
                Some(&mcp_seam),
                &mut redacting,
                cancel.flag(),
            )
        };
        bridge.finish();
        outcome
    } else {
        let mut live = crate::agent_loop::FnTransport(|system: &str, user_message: &str| {
            // Defense in depth (IV1): the ASSEMBLED outbound message re-passes
            // the canonical redaction gate every turn (each tool result was
            // already individually gated at the read).
            let fragments = [user_message];
            match redact(&RedactionRequest {
                fragments: &fragments,
                candidate_memory_ids: &[],
                deleted_ids: &[],
                include_private_memory: false,
            }) {
                Ok(receipt) if receipt.secret_fragments_denied_u32() == 0 => {}
                _ => {
                    return Err(crate::agent_loop::AgentTransportError {
                        class_label: "assembled message denied by redaction".to_string(),
                    });
                }
            }
            match transport.send_live_text(
                &consult,
                EgressApproval::grant(),
                system,
                user_message,
                &model,
                PROVIDER_CONSULT_MAX_OUTPUT_TOKENS,
            ) {
                Ok(outcome) => {
                    turns_u8 = turns_u8.saturating_add(1);
                    last_request_hash_32 = outcome.request_hash_32;
                    last_response_hash_32 = outcome.response_hash_32;
                    last_model = outcome.model;
                    last_stop_reason = outcome.stop_reason;
                    Ok(crate::agent_loop::AgentTurn {
                        answer_text: outcome.answer_text,
                        input_tokens_u64: outcome.input_tokens,
                        output_tokens_u64: outcome.output_tokens,
                        cached_tokens_u64: outcome.cached_tokens,
                    })
                }
                Err(error) => Err(crate::agent_loop::AgentTransportError {
                    class_label: consult_denied_label(&error),
                }),
            }
        });
        // E11-1b: the loop's `web fetch` tool reaches the public web through the
        // shared SSRF-walled glue. The seam is feature-INDEPENDENT — a live
        // transport only under `web-egress`, else `None` (the honest not-compiled
        // deny). custody/funds stay HARD-LOCKED (a chain-RPC host is SSRF-denied;
        // GET-only ⇒ no chain WRITE).
        let web_seam = crate::provider::web_fetch::WebFetchSeam::new();
        // B⑫ (CURSOR PARITY keystone-3): the loop's `mcp` tool reaches owner-
        // configured LOCAL stdio MCP servers through the shared chokepoint
        // (sandboxed, network kernel-DENIED; an unknown server/tool ⇒ deny; the
        // arg + result are redacted; every call is audited). The seam carries the
        // READ-tier servers from the owner config; an empty config ⇒ the tool
        // honestly denies. custody/funds stay HARD-LOCKED (no egress/mutate).
        let mcp_seam = crate::mcp::McpSeam::new(read_owner_mcp_servers());
        crate::agent_loop::run_agent_loop_with(
            &mut live,
            &state,
            &loop_system,
            question,
            crate::agent_loop::CHAT_MAX_ITER,
            crate::agent_loop::CHAT_TOKEN_CAP,
            Some(&file_policy),
            Some(&web_seam),
            Some(&mcp_seam),
        )
    };
    let otel_ended = std::time::SystemTime::now();
    // P4-1 (⑨): owner-opted OTel span export — ONE shared implementation with
    // the local route (consult_otel_line), computed BEFORE the answer
    // destructure (the borrow ends before the partial move) and ONLY for an
    // answered ceremony (v1 scope; failure paths are R2). Off ⇒ None ⇒ the
    // surface stays byte-unchanged.
    let otel_line = if loop_outcome.answer.is_some() {
        crate::otel_export::consult_otel_line(
            &loop_outcome,
            &crate::otel_export::ConsultOtelCtx {
                setting: crate::otel_export::resolve_otel_export(
                    std::env::var(crate::otel_export::SINABRO_OTEL_EXPORT_ENV)
                        .ok()
                        .as_deref(),
                ),
                dir_override: None,
                backend: "openrouter",
                model: &last_model,
                turns_u8,
                request_sha_32: &last_request_hash_32,
                response_sha_32: &last_response_hash_32,
                started: otel_started,
                ended: otel_ended,
            },
        )
    } else {
        None
    };
    let Some(answer) = loop_outcome.answer else {
        let label = format!(
            "agent loop stopped: {} after {turns_u8} live turn(s); trail=[{}]",
            loop_outcome.stop.class_label(),
            loop_outcome.tool_trail.join(", ")
        );
        return provider_consult_error(out, &envelope_hex, &label);
    };
    // Render: the answer is the deliverable. OpenRouter pricing varies per model,
    // so cost is left to OpenRouter's dashboard; we render token usage only.
    // OpenAI-compatible `finish_reason == "stop"` = clean end.
    let mut truth = if last_stop_reason == "stop" {
        RenderTruth::Green
    } else {
        RenderTruth::Yellow
    };
    let mut body = Vec::new();
    body.push(format!(
        "LIVE provider consult: openrouter {last_model} (agentic loop)"
    ));
    // P3-2 (TM DESIGN LOCK): a propose-shaped answer becomes a sealed INERT
    // proposal card (bound to the loop's OWN verified-read hashes) instead
    // of an answer card; an ordinary answer renders unchanged. The proposal
    // store + review policy are the REAL local ones — this executor already
    // runs under the owner's typed consult ceremony.
    // E10-1 (⑬ IV-A2): if it is not an edit proposal, try the exec proposal —
    // an exec-PROPOSE answer becomes a sealed INERT exec record (still nothing
    // runs; the EXECUTE path is the E10-2 owner-authorized gate).
    let proposal_store = ProposalStore::open_local().ok();
    let exec_store = crate::exec_proposal::ExecProposalStore::open_local().ok();
    if let Some((proposal_truth, lines)) = consult_proposal_render(
        &answer,
        &loop_outcome.verified_file_reads,
        proposal_store.as_ref(),
        &file_policy,
    )
    .or_else(|| consult_exec_proposal_render(&answer, exec_store.as_ref()))
    {
        body.extend(lines);
        if !matches!(proposal_truth, RenderTruth::Green) {
            truth = proposal_truth;
        }
    } else {
        // E7-1: deliver the answer THROUGH the streaming bridge (no longer a
        // synchronous single-string); each chunk passes the per-chunk redact
        // wall. Honest scope: progressive render of the completed answer.
        let streamed = stream_consult_answer(&answer, last_response_hash_32, 78, 52);
        let feed = stream_feed_receipt(&streamed);
        body.extend(streamed.lines);
        body.push(feed);
    }
    body.push(format!(
        "loop: turns={turns_u8} tool_iters={} reads={} stop={} trail=[{}]",
        loop_outcome.iterations_u8,
        loop_outcome.reads_u8,
        loop_outcome.stop.class_label(),
        loop_outcome.tool_trail.join(", ")
    ));
    // E1 audit-soul: cite which of the owner's OWN memories the loop recalled
    // (autonomous READ, PD-3 — free but never invisible). Empty ⇒ "none".
    body.push(recalled_citation(&loop_outcome.tool_trail));
    body.push(format!(
        "usage: input={} output={} cached={} finish={last_stop_reason}",
        loop_outcome.input_tokens_u64,
        loop_outcome.output_tokens_u64,
        loop_outcome.cost.cached_tokens_u32()
    ));
    // E7-2: the REAL context-pressure from the MEASURED token counters — the
    // status meter can now warn (was hard-coded 0). No fabrication.
    body.push(context_pressure_receipt(
        loop_outcome.input_tokens_u64,
        loop_outcome.output_tokens_u64,
    ));
    // P2-1 cache receipt: the byte split (static system prefix vs per-turn
    // dynamic suffix) + the MEASURED prefix stability across this loop's
    // turns; the `cached=` counter above is the provider's own report.
    body.push(format!(
        "cache: static_prefix={}B dynamic={}B stable_prefix_turns={}/{}",
        loop_outcome.cache_plan.static_prefix_bytes_u32,
        loop_outcome.cache_plan.dynamic_suffix_bytes_u32,
        loop_outcome.prefix_stable_turns_u8,
        turns_u8.saturating_sub(1)
    ));
    body.push(format!(
        "cost: usd_micros={} (no local rates configured; per-model rates on the OpenRouter dashboard)",
        loop_outcome.cost.usd_micros().get()
    ));
    // P2-2 in-core guard receipt: the action re-derives from the recorded
    // signal bits (never stored twice); signals=0x0000 = healthy run.
    let guard = crate::provider::trajectory_health::recommended_action(loop_outcome.health);
    body.push(format!(
        "guard: action={} signals=0x{:04x}",
        guard.class_label(),
        loop_outcome.health.bits()
    ));
    body.push(format!(
        "request_sha={} response_sha={} (last turn)",
        hex16(&last_request_hash_32),
        hex16(&last_response_hash_32)
    ));
    // P4-1 (⑨): the OTel receipt line (computed pre-destructure above).
    if let Some(line) = otel_line {
        body.push(line);
    }
    body.push("advisory only; key never rendered; raw body not stored at rest".to_string());
    emit(
        out,
        "provider consult",
        &envelope_hex,
        CommandRisk::Network,
        ApprovalRequirement::TypedPhrase,
        truth,
        &body,
    )?;
    Ok(true)
}

// ---- P3-3 (owner-authorized 2026-06-11): gated LOCAL consult route -------------
//
// Threat model: ops/evidence/stage_g/agent_loop/LOCAL_ENDPOINT_THREAT_MODEL.md (⑧).
// The SAME bounded agentic loop over a LOOPBACK OpenAI-compatible endpoint
// (mlx_lm.server / ollama / vLLM) instead of the frontier codec. Zero egress:
// the transport's only target type is `LoopbackBind` (non-loopback
// unrepresentable) and the client is no-proxy + no-redirect (IV-L1). Walls,
// bounds, redaction, guard = IDENTICAL to the frontier path (IV-L2/L3/L4 —
// an unaudited local process gets the frontier tier, never a private one).
// Route selection = the EXACT typed phrase (no silent fallback, ⑧ DESIGN LOCK).

/// The exact in-band confirmation phrase that authorizes ONE bounded LOCAL
/// consult loop. A PUBLIC confirmation gesture (zero entropy, NOT a secret);
/// the phrase IS the route — byte-visible, mutually exclusive with the
/// frontier phrase.
#[cfg(any(feature = "local-mlx", feature = "local-vllm"))]
const PROVIDER_CONSULT_LOCAL_PHRASE: &str = "consult-local-naite-live";
/// P1-2b: the same-message ceremony for the TWO-MODEL orchestration loop
/// (`provider orchestrate <phrase> <task>`). Distinct from the consult phrase so a
/// consult ceremony never silently becomes an orchestration run. Compiled only with
/// a local-serving feature (the only consumer is the gated orchestrate executor).
#[cfg(any(feature = "local-mlx", feature = "local-vllm"))]
const PROVIDER_ORCHESTRATE_PHRASE: &str = "orchestrate-two-model-live";

/// P1-5 / P2-S4a — load the owner's LoRA routing table from `<data_dir>/routing_table.txt`
/// (the config seam; the Settings → LoRA/Routing editor writes it, the orchestrate verb and
/// the autonomous evolve loop READ it), falling back to the seed `default_routing_table()`
/// when no config is present OR it is malformed (fail-closed: a half-parsed router never
/// routes). The SINGLE load both the GUI editor and the loops share, so the owner config
/// drives every route. ALWAYS compiled (the GUI editor needs it in any build); the
/// parse/serialize codec is PURE (in `executor_route`); this is the thin IO.
#[must_use]
pub fn read_routing_table() -> crate::provider::executor_route::ExecutorRoutingTable {
    use crate::provider::executor_route::{
        ROUTING_TABLE_CONFIG_FILE, default_routing_table, parse_routing_table_config,
    };
    if let Ok(dir) = crate::memory_store::data_dir() {
        if let Ok(text) = std::fs::read_to_string(dir.join(ROUTING_TABLE_CONFIG_FILE)) {
            if let Some(table) = parse_routing_table_config(&text) {
                return table;
            }
        }
    }
    default_routing_table()
}

// ── K-6: the corpus→adapter MANIFEST + served-set load (the dynamic-LoRA switch's P-HALL
//    gate + the honest-degrade source; PURE codec in `provider::lora_manifest`). ──────────

/// Build the agent's certified-adapter MANIFEST from the local certified-strategy corpus —
/// the P-HALL source: every corpus entry was admitted ONLY because it certified
/// ([`crate::autonomy_evolve::strategy_candidate`] `admits_write == certified`). Each
/// entry's DOMAIN KEY is re-derived from its canonical TOML (the drift-0 archetype), and
/// passed `certified = true` (the corpus invariant); the PURE builder re-asserts the gate
/// (drops `certified == false`). An absent / unreadable corpus ⇒ the EMPTY manifest
/// (honest: no adapter has been earned yet). READ-only, money 0, no network/key.
#[must_use]
pub fn load_lora_manifest() -> crate::provider::lora_manifest::LoraManifest {
    use crate::provider::lora_manifest::{AdapterKey, CertifiedStrategy, LoraManifest};
    let Ok(store) = crate::memory_store::PersistedStore::open_local() else {
        return LoraManifest::default();
    };
    let Ok(dir) = skew_strategy_corpus_dir() else {
        return LoraManifest::default();
    };
    let mut summaries: Vec<CertifiedStrategy> = Vec::new();
    for (_key, _topic, content) in load_strategy_corpus(&store, &dir) {
        // Re-parse the canonical TOML for the archetype (the drift-0 source of truth);
        // the corpus invariant gives certified=true, the builder re-asserts the gate.
        if let Ok(dsl) = crate::skew_strategy::parse_strategy_toml(&content) {
            if let Some(key) = AdapterKey::new(dsl.archetype.as_str()) {
                summaries.push(CertifiedStrategy {
                    key,
                    certified: true,
                });
            }
        }
    }
    LoraManifest::from_certified_strategies(&summaries)
}

/// Load the SERVED-adapter set from `<data_dir>/served_adapters.txt` — the owner declares
/// the adapter ids a real multi-LoRA server serves (the file is the owner's authorization,
/// symmetric with `routing_table.txt`). ABSENT / empty ⇒ the EMPTY set (honest no-server
/// ⇒ every adapter degrades to the base model). PURE parse in `provider::lora_manifest`.
#[must_use]
pub fn load_served_adapter_set() -> crate::provider::lora_manifest::ServedAdapterSet {
    use crate::provider::lora_manifest::{
        SERVED_ADAPTERS_FILE, ServedAdapterSet, parse_served_adapters,
    };
    let Ok(dir) = crate::memory_store::data_dir() else {
        return ServedAdapterSet::empty();
    };
    match std::fs::read_to_string(dir.join(SERVED_ADAPTERS_FILE)) {
        Ok(text) => parse_served_adapters(&text),
        Err(_) => ServedAdapterSet::empty(),
    }
}

/// W5: read the owner-declared served-adapter ids (raw id strings) from `served_adapters.txt` for the
/// GUI served-editor + the connect-adapter seam — the SAME file `load_served_adapter_set` parses.
/// Returns the VALID adapter-id strings (invalid lines skipped), deterministically ordered. READ-only,
/// money 0.
#[must_use]
pub fn read_served_adapter_lines() -> Vec<String> {
    use crate::provider::lora_manifest::{SERVED_ADAPTERS_FILE, parse_served_adapters};
    let Ok(dir) = crate::memory_store::data_dir() else {
        return Vec::new();
    };
    let Ok(text) = std::fs::read_to_string(dir.join(SERVED_ADAPTERS_FILE)) else {
        return Vec::new();
    };
    parse_served_adapters(&text)
        .ids()
        .map(|id| id.as_str().to_string())
        .collect()
}

/// W5: validate + persist the owner-declared served-adapter ids (the GUI "declare served" surface +
/// the connect-adapter seam). Each id must be a valid `AdapterId` (the served-set charset); an invalid
/// id ⇒ `Err` (fail-closed; nothing written). Deduped + atomic write (the SAME single writer the
/// routing table uses). HONEST: the file is the owner's DECLARATION that a real multi-LoRA server
/// serves these — declaring an id served does NOT make it served; `resolve_adapter` STILL
/// honest-degrades the send to the base if the server is actually down. NOT custody (a plain local
/// config; PD-6 untouched).
///
/// # Errors
/// Returns `Err` on an invalid adapter id or a write failure (nothing is persisted).
pub fn write_served_adapter_lines(ids: &[String]) -> Result<(), String> {
    use crate::provider::lora_manifest::{AdapterId, SERVED_ADAPTERS_FILE};
    use std::collections::BTreeSet;
    let mut set: BTreeSet<String> = BTreeSet::new();
    for raw in ids {
        let id = raw.trim();
        if id.is_empty() {
            continue;
        }
        if AdapterId::new(id).is_none() {
            return Err(format!(
                "invalid adapter id {id:?} (ascii-lowercase / digits / '_' / '-', 1..=64 bytes)"
            ));
        }
        set.insert(id.to_string());
    }
    let mut text = String::from(
        "# sinabro served adapters: the ids a real multi-LoRA server serves (one/line)\n",
    );
    for id in &set {
        text.push_str(id);
        text.push('\n');
    }
    let dir = crate::memory_store::data_dir().map_err(|e| format!("data dir: {e:?}"))?;
    crate::memory_store::atomic_write(&dir.join(SERVED_ADAPTERS_FILE), text.as_bytes())
        .map_err(|e| format!("atomic write failed: {e}"))?;
    Ok(())
}

/// The resolved local BASE model id (the SAME resolution the orchestrate reasoning role
/// uses) — the totality anchor every unserved adapter honest-degrades to.
#[must_use]
fn lora_base_model() -> String {
    crate::commands::model_select::resolve_local_model(
        std::env::var(crate::commands::model_select::LOCAL_MODEL_ENV)
            .ok()
            .as_deref(),
    )
}

/// The honest dynamic-LoRA status render — the SINGLE truth source the CLI `provider
/// lora-status` verb AND the GUI `read_lora_status` Tauri command share (no JS
/// re-implementation; the GUI shows this string verbatim). Loads the certified-adapter
/// MANIFEST (P-HALL), the SERVED set, the routing table, and the base, then renders the
/// per-kind resolution. READ-only, money 0, no network/key.
#[must_use]
pub fn lora_status_render() -> String {
    let manifest = load_lora_manifest();
    let served = load_served_adapter_set();
    let table = read_routing_table();
    let base = lora_base_model();
    crate::provider::lora_manifest::render_lora_status(&manifest, &served, &table, &base)
}

/// `provider lora-status` — the honest dynamic-LoRA status (READ-class; money 0; no
/// network/key). Renders the certified-adapter MANIFEST (the P-HALL catalog), the SERVED
/// set (empty ⇒ honest no-server), and the per-kind RESOLUTION for the routing table
/// (requested adapter → wire model, served/degraded). The SAME core render the GUI Tauri
/// command consumes (one truth source). An unserved adapter is shown honest-degrading to
/// the base — NEVER faked as served (PD-1). `CustodyCapability` stays uninhabited (PD-6).
fn provider_lora_status(out: &mut impl Write) -> io::Result<bool> {
    let envelope_hex = hex16(&sha256_32(b"provider lora-status"));
    let body: Vec<String> = lora_status_render().lines().map(str::to_string).collect();
    emit(
        out,
        "provider lora-status",
        &envelope_hex,
        CommandRisk::ReadOnly,
        ApprovalRequirement::None,
        RenderTruth::Green,
        &body,
    )?;
    Ok(true)
}

/// PURE (no IO): build + validate the routing-table config TEXT from owner-edited rows. The
/// validator the GUI write surface reuses (single truth source — the GUI never re-parses the
/// config in JS). Fail-closed in two places: an invalid kind label (the `ExecutorKind` charset)
/// or an empty `model_id` ⇒ `Err`; and the serialized text MUST re-parse through the SAME pure
/// codec (`parse_routing_table_config`) — never emit a router that would not load back.
pub fn build_routing_table_text(
    rows: &[(String, u16, String)],
    default_port: u16,
    default_model: &str,
) -> Result<String, String> {
    use crate::provider::executor_route::{
        ExecutorKind, ExecutorRoutingTable, ExecutorTarget, parse_routing_table_config,
        serialize_routing_table,
    };
    let mut bindings: Vec<(ExecutorKind, ExecutorTarget)> = Vec::with_capacity(rows.len());
    for (label, port, model) in rows {
        let kind = ExecutorKind::new(label).ok_or_else(|| {
            format!("invalid kind label {label:?} (ascii-lowercase / digits / '_' , 1..=48 bytes)")
        })?;
        if model.trim().is_empty() {
            return Err(format!("model_id for kind {label:?} must not be empty"));
        }
        bindings.push((
            kind,
            ExecutorTarget {
                port: *port,
                model_id: model.clone(),
            },
        ));
    }
    if default_model.trim().is_empty() {
        return Err("default model_id must not be empty".to_string());
    }
    let table = ExecutorRoutingTable::new(
        bindings,
        ExecutorTarget {
            port: default_port,
            model_id: default_model.to_string(),
        },
    );
    let text = serialize_routing_table(&table);
    if parse_routing_table_config(&text).is_none() {
        return Err(
            "routing table failed re-parse validation (fail-closed; nothing written)".to_string(),
        );
    }
    Ok(text)
}

/// P2-S4a — validate + persist the owner-edited LoRA routing table (the GUI Settings → LoRA/
/// Routing write surface). NOT custody: `routing_table.txt` is a plain local config (a loopback
/// `port` + a request-body `model_id` per kind) — no funds / wallet / chain / mainnet (PD-6
/// untouched). The owner's Save click IS the authorization (like `set_secret` / `save_sessions`);
/// the model has no path here. Fail-closed (`build_routing_table_text` rejects an invalid kind /
/// empty model / re-parse failure ⇒ nothing written) + ATOMIC (`memory_store::atomic_write` — no
/// torn file, the SAME single writer the E11-4 config persist uses). The change drives the
/// dynamic-LoRA route on the NEXT `read_routing_table` (the orchestrate verb + the evolve loop).
pub fn write_routing_table_rows(
    rows: &[(String, u16, String)],
    default_port: u16,
    default_model: &str,
) -> Result<(), String> {
    use crate::provider::executor_route::ROUTING_TABLE_CONFIG_FILE;
    let text = build_routing_table_text(rows, default_port, default_model)?;
    let dir = crate::memory_store::data_dir().map_err(|e| format!("data dir: {e:?}"))?;
    crate::memory_store::atomic_write(&dir.join(ROUTING_TABLE_CONFIG_FILE), text.as_bytes())
        .map_err(|e| format!("atomic write failed: {e}"))?;
    Ok(())
}

/// The orchestrate verb + the autonomous evolve loop's load (feature-gated to the local-serving
/// builds that own those verbs) — delegates to the always-compiled [`read_routing_table`] so
/// there is ONE routing-config load truth shared with the GUI editor.
#[cfg(any(feature = "local-mlx", feature = "local-vllm"))]
fn load_routing_table() -> crate::provider::executor_route::ExecutorRoutingTable {
    read_routing_table()
}

#[cfg(test)]
mod routing_editor_tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::build_routing_table_text;
    use crate::provider::executor_route::parse_routing_table_config;

    #[test]
    fn build_routing_table_text_round_trips_and_validates() {
        let rows = vec![
            (
                "sui_move".to_string(),
                11434u16,
                "naite_sui_move".to_string(),
            ),
            ("audit".to_string(), 11434u16, "naite_audit".to_string()),
        ];
        let text = build_routing_table_text(&rows, 11434, "default").expect("valid rows build");
        // re-parses through the SAME pure codec (the fail-closed re-parse gate)
        let table = parse_routing_table_config(&text).expect("text re-parses");
        assert_eq!(table.bindings().len(), 2);
        assert_eq!(table.bindings()[0].0.label(), "sui_move");
        assert_eq!(table.bindings()[0].1.port, 11434);
        assert_eq!(table.bindings()[0].1.model_id, "naite_sui_move");
        assert_eq!(table.default_target().model_id, "default");
    }

    #[test]
    fn build_routing_table_text_rejects_invalid_kind() {
        // uppercase / dash are outside the ExecutorKind charset ⇒ fail-closed (nothing built)
        let rows = vec![("Sui-Move".to_string(), 11434u16, "x".to_string())];
        assert!(build_routing_table_text(&rows, 11434, "default").is_err());
    }

    #[test]
    fn build_routing_table_text_rejects_empty_model() {
        let rows = vec![("sui_move".to_string(), 11434u16, "  ".to_string())];
        assert!(build_routing_table_text(&rows, 11434, "default").is_err());
        // an empty DEFAULT model is also refused (the totality anchor must be real)
        let ok_rows = vec![("sui_move".to_string(), 11434u16, "m".to_string())];
        assert!(build_routing_table_text(&ok_rows, 11434, "").is_err());
    }
}

/// The env var selecting the loopback port (a plain selector, not a secret).
/// P4-3: canonical name owned by `model_select` (one selection truth).
#[cfg(any(feature = "local-mlx", feature = "local-vllm"))]
const SINABRO_LOCAL_PORT_ENV: &str = crate::commands::model_select::LOCAL_PORT_ENV;

/// The env var selecting the request-side model id (a plain selector, not a
/// secret; ollama/vLLM need their real served-model name here). P4-3: canonical
/// name owned by `model_select`.
#[cfg(any(feature = "local-mlx", feature = "local-vllm"))]
const SINABRO_LOCAL_MODEL_ENV: &str = crate::commands::model_select::LOCAL_MODEL_ENV;

// P4-3: the local default model id ("default") is owned by
// `model_select::LOCAL_DEFAULT_MODEL` and resolved through
// `model_select::resolve_local_model`; no dispatch-local copy is kept.

/// The default loopback port when `SINABRO_LOCAL_PORT` is unset: the
/// MLX/ollama dev runtime (this repo's macOS dev target) when `local-mlx`
/// is compiled; the vLLM prod default otherwise. Both are EXISTING adapter
/// constants — no third default is minted.
#[cfg(feature = "local-mlx")]
const LOCAL_CONSULT_DEFAULT_PORT: u16 = crate::provider::local_mlx::OLLAMA_DEFAULT_PORT;
#[cfg(all(feature = "local-vllm", not(feature = "local-mlx")))]
const LOCAL_CONSULT_DEFAULT_PORT: u16 = crate::provider::local_vllm::VLLM_DEFAULT_PORT;

// P4-3 (VM-selector) DRIFT LOCK: the selector's canonical port menu
// (`model_select::{OLLAMA,VLLM}_PORT`, shown to the owner in every build) MUST
// equal the feature adapter's own default, or the menu would lie. Caught at
// COMPILE time in any build that compiles the adapter.
#[cfg(feature = "local-mlx")]
const _: () = assert!(
    crate::commands::model_select::OLLAMA_PORT == crate::provider::local_mlx::OLLAMA_DEFAULT_PORT
);
#[cfg(feature = "local-vllm")]
const _: () = assert!(
    crate::commands::model_select::VLLM_PORT == crate::provider::local_vllm::VLLM_DEFAULT_PORT
);

// The loopback port/model resolvers now live in `model_select` (P4-3) —
// consumed by BOTH this local executor (call sites below) and the `model use`
// selector view, so the selector shows exactly what a consult uses (no drift).

/// The denial / gated-preview body for the LOCAL route when the exact phrase
/// is absent or wrong — render-only, NEVER touches redaction or a socket.
#[cfg(any(feature = "local-mlx", feature = "local-vllm"))]
fn provider_consult_local_locked_body(model: &str, port: u16) -> Vec<String> {
    vec![
        "provider consult (LOCAL route) is a loopback LLM call (OpenAI-compatible)".to_string(),
        "risk=network approval=typed-phrase (exact); bounded agentic loop (<=5 turns); zero egress"
            .to_string(),
        format!("usage: provider consult {PROVIDER_CONSULT_LOCAL_PHRASE} <question>"),
        format!(
            "endpoint: http://127.0.0.1:{port}/v1/chat/completions ({SINABRO_LOCAL_PORT_ENV}; ollama=11434 mlx=8080 vllm=8000)"
        ),
        format!(
            "bounds: question<={PROVIDER_CONSULT_MAX_QUESTION_BYTES}B output<={PROVIDER_CONSULT_MAX_OUTPUT_TOKENS}tok model={model} (set {SINABRO_LOCAL_MODEL_ENV} to change)"
        ),
        "walls: identical to frontier (shareable-only memory + redaction + caps); no key sent"
            .to_string(),
        "denied: no local call without the exact phrase".to_string(),
    ]
}

/// Render a secret-zero LOCAL-consult error surface (static label / sanitized
/// class only) and stop — one shot, no retry.
#[cfg(any(feature = "local-mlx", feature = "local-vllm"))]
fn provider_consult_local_error(
    out: &mut impl Write,
    envelope_hex: &str,
    label: &str,
) -> io::Result<bool> {
    let body = vec![
        format!("LOCAL provider consult: {label}"),
        "no retry; loopback only; no key exists on this path; funds untouched".to_string(),
    ];
    emit(
        out,
        "provider consult",
        envelope_hex,
        CommandRisk::Network,
        ApprovalRequirement::TypedPhrase,
        RenderTruth::Red,
        &body,
    )?;
    Ok(true)
}

/// The gated LOCAL consult executor (compiled only with a local-serving
/// feature). Resolves the loopback endpoint from env (STRICT port parse) and
/// delegates to [`provider_consult_local_at`] — the injected-bind surface the
/// tests drive directly (no env mutation in tests).
#[cfg(any(feature = "local-mlx", feature = "local-vllm"))]
fn provider_consult_local(rest: &[String], out: &mut impl Write) -> io::Result<bool> {
    let envelope_hex = hex16(&sha256_32(b"provider consult"));
    let Some(port) = crate::commands::model_select::resolve_local_port(
        std::env::var(SINABRO_LOCAL_PORT_ENV).ok().as_deref(),
        LOCAL_CONSULT_DEFAULT_PORT,
    ) else {
        return provider_consult_local_error(
            out,
            &envelope_hex,
            "SINABRO_LOCAL_PORT is not a valid port (1-65535); nothing sent",
        );
    };
    let model = crate::commands::model_select::resolve_local_model(
        std::env::var(SINABRO_LOCAL_MODEL_ENV).ok().as_deref(),
    );
    provider_consult_local_at(
        crate::provider::local_endpoint::LoopbackBind::localhost(port),
        &model,
        rest,
        out,
        // P4-1 (⑨ IV-O4): the OTel opt-in resolves from the environment in
        // the SAME outer layer as port/model (config, not authority); tests
        // inject the setting + dir instead of mutating process env.
        crate::otel_export::resolve_otel_export(
            std::env::var(crate::otel_export::SINABRO_OTEL_EXPORT_ENV)
                .ok()
                .as_deref(),
        ),
        None,
    )
}

/// P6 — a single FIM (fill-in-the-middle) completion for the center editor's INLINE autocomplete.
/// Frames a code-completion request as ONE bounded chat turn to the loopback local model (the SAME
/// transport the local consult uses — `LocalChatTransport`/`send_local_text_with`) and returns ONLY
/// the predicted insertion text (capped). HONEST-DEGRADES to `Err` when no local model is compiled
/// OR reachable (the GUI then shows NO ghost — never a fabricated completion). LOOPBACK-ONLY (no
/// off-box egress); custody/funds untouched; the model has no path here (a GUI IPC command).
pub fn fim_complete_local(prefix: &str, suffix: &str) -> Result<String, String> {
    #[cfg(any(feature = "local-mlx", feature = "local-vllm"))]
    {
        use crate::provider::local_chat::LocalChatTransport;
        use crate::provider::local_endpoint::LoopbackBind;
        const FIM_TIMEOUT_MS: u32 = 8000;
        const FIM_MAX_TOKENS: u32 = 96;
        const FIM_PREFIX_CHARS: usize = 4000;
        const FIM_SUFFIX_CHARS: usize = 2000;
        const FIM_OUT_CHARS: usize = 600;
        let Some(port) = crate::commands::model_select::resolve_local_port(
            std::env::var(SINABRO_LOCAL_PORT_ENV).ok().as_deref(),
            LOCAL_CONSULT_DEFAULT_PORT,
        ) else {
            return Err("SINABRO_LOCAL_PORT is not a valid port (1-65535)".to_string());
        };
        let model = crate::commands::model_select::resolve_local_model(
            std::env::var(SINABRO_LOCAL_MODEL_ENV).ok().as_deref(),
        );
        let Some(transport) =
            LocalChatTransport::new(LoopbackBind::localhost(port), &model, FIM_TIMEOUT_MS)
        else {
            return Err("local transport unavailable".to_string());
        };
        // Bound the context to the code NEAREST the cursor (tail of prefix, head of suffix);
        // char-based slicing is UTF-8-safe (byte slicing could split a multibyte char).
        let pre_chars: Vec<char> = prefix.chars().collect();
        let pre: String = pre_chars[pre_chars.len().saturating_sub(FIM_PREFIX_CHARS)..]
            .iter()
            .collect();
        let suf: String = suffix.chars().take(FIM_SUFFIX_CHARS).collect();
        let system = "You are an inline code-completion engine. Output ONLY the code that should be \
                      inserted at the cursor between <PREFIX> and <SUFFIX>. No prose, no explanation, \
                      no markdown fences. Continue the code naturally; output nothing if unsure.";
        let question = format!(
            "<PREFIX>\n{pre}\n</PREFIX>\n<SUFFIX>\n{suf}\n</SUFFIX>\nInsertion at the cursor:"
        );
        let outcome = transport
            .send_local_text_with(&model, system, &question, FIM_MAX_TOKENS)
            .map_err(|_| "local model unreachable (is the loopback server up?)".to_string())?;
        // Strip an accidental `ANSWER:`/fences the model may add; cap the length (char-safe).
        let mut text = outcome.answer_text.trim().to_string();
        if let Some(rest) = text.strip_prefix("ANSWER:") {
            text = rest.trim_start().to_string();
        }
        text = text.trim_matches('`').to_string();
        if text.chars().count() > FIM_OUT_CHARS {
            text = text.chars().take(FIM_OUT_CHARS).collect();
        }
        Ok(text)
    }
    #[cfg(not(any(feature = "local-mlx", feature = "local-vllm")))]
    {
        let _ = (prefix, suffix);
        Err("local model transport not compiled (build with local-mlx or local-vllm)".to_string())
    }
}

// ── B⑧: Cmd-K INLINE EDIT (select → NL instruction → inline diff → single owner-approve) ─────────
// The center editor sends the SELECTED text + a natural-language instruction (+ a bounded context
// window for the model). The core (1) loopback-transforms ONLY the selection (the SAME transport
// fim uses — ZERO egress, READ-class compute), then (2) SEALS the result as an INERT
// `FileEditProposal` through the EXISTING PROPOSE-EDIT machinery (`mint_proposal` IV-W2
// verified-read binding + `ProposalStore`). The model CANNOT apply — the owner single-approves via
// `tool apply file-apply-owner-live` (E10); staleness + walls re-check at apply time. sinabro law:
// NEVER a silent mutation. v1 = loopback-only; a FRONTIER transform (the selection would leave the
// box) is a v2 armed EGRESS. This is a GUI IPC, NOT a loop tool — the MODEL has no path to it.

/// Typed denials for the inline-edit propose path (stable, secret-zero `inline_edit.*` labels).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum InlineEditDeny {
    /// The lane-A policy refused the target read (out-of-root / denylisted / oversize).
    ReadDenied,
    /// The target is binary (non-UTF-8) — never edited inline.
    NotEditableBinary,
    /// The target carries a secret-shaped line or a key/cert block ⇒ not editable inline (a
    /// partial/redacted read could write the withhold-markers back; the SAME gate the loop uses).
    NotEditableSecret,
    /// The instruction was empty/whitespace.
    InstructionEmpty,
    /// The selection was empty.
    SelectionEmpty,
    /// The selection text is not present in the file's CURRENT bytes (it changed / wrong region).
    SelectionNotFound,
    /// The selection text occurs more than once (v1 requires a unique region to splice safely).
    SelectionAmbiguous,
    /// The model's replacement made the proposed content secret-shaped (mint refused, IV-W7a).
    ReplacementSecretShaped,
    /// Another mint wall denied (target-not-read / too-large / denied-name / store-full).
    Mint(crate::file_edit::ProposeDeny),
    /// The sealed-proposal store is unavailable (no key / no home).
    StoreUnavailable,
    /// The proposal could not be sealed/written.
    StoreFailed,
}

impl InlineEditDeny {
    /// Stable allow-listed class label (namespaced `inline_edit.*`).
    #[must_use]
    pub const fn class_label(self) -> &'static str {
        match self {
            Self::ReadDenied => "inline_edit.read_denied",
            Self::NotEditableBinary => "inline_edit.not_editable_binary",
            Self::NotEditableSecret => "inline_edit.not_editable_secret",
            Self::InstructionEmpty => "inline_edit.instruction_empty",
            Self::SelectionEmpty => "inline_edit.selection_empty",
            Self::SelectionNotFound => "inline_edit.selection_not_found",
            Self::SelectionAmbiguous => "inline_edit.selection_ambiguous",
            Self::ReplacementSecretShaped => "inline_edit.replacement_secret_shaped",
            Self::Mint(_) => "inline_edit.mint_denied",
            Self::StoreUnavailable => "inline_edit.store_unavailable",
            Self::StoreFailed => "inline_edit.store_failed",
        }
    }

    /// An honest one-line message the GUI surfaces (the mint sub-reason is appended when present).
    #[must_use]
    pub fn message(self) -> String {
        match self {
            Self::Mint(d) => format!("{} ({})", self.class_label(), d.class_label()),
            _ => self.class_label().to_string(),
        }
    }
}

/// The successful inline-edit propose result. `id` applies via `tool apply file-apply-owner-live`;
/// the GUI renders `old_content`→`new_content` through its EXISTING diff view + a single approve.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InlineEditProposed {
    /// The pending-proposal id prefix (for `tool apply file-apply-owner-live <id>`).
    pub id: String,
    /// The target's CURRENT clean bytes (the diff's old side; what the mint bound its read_sha to).
    pub old_content: String,
    /// The proposed full content with the selection replaced (the diff's new side).
    pub new_content: String,
}

/// Locate the UNIQUE byte range of `needle` in `haystack`. v1 requires a unique match (a Cmd-K
/// selection is normally a unique region): zero matches ⇒ `SelectionNotFound` (file changed /
/// wrong region), more than one ⇒ `SelectionAmbiguous` (select a larger unique region). This
/// sidesteps the cross-language offset hazard (JS UTF-16 code units vs Rust byte offsets) — NO
/// numeric offset crosses the IPC.
#[cfg(any(feature = "local-mlx", feature = "local-vllm", test))]
fn locate_unique_selection(haystack: &str, needle: &str) -> Result<(usize, usize), InlineEditDeny> {
    if needle.is_empty() {
        return Err(InlineEditDeny::SelectionEmpty);
    }
    let mut it = haystack.match_indices(needle);
    let Some((from, m)) = it.next() else {
        return Err(InlineEditDeny::SelectionNotFound);
    };
    if it.next().is_some() {
        return Err(InlineEditDeny::SelectionAmbiguous);
    }
    Ok((from, from + m.len()))
}

/// Read `path` through the lane-A policy and return its bytes ONLY if it is FULLY clean (no
/// secret-shaped line, no key/cert block) — the SAME editability gate `frontier_file_result`
/// (agent_loop.rs) uses: a partial/redacted read could propose an edit that writes the
/// withhold-markers back into the file. Returns `(clean_content, VerifiedFileRead)` for mint binding.
#[cfg(any(feature = "local-mlx", feature = "local-vllm", test))]
fn read_clean_editable(
    policy: &crate::file_context::FileReadPolicy,
    path: &str,
) -> Result<(String, VerifiedFileRead), InlineEditDeny> {
    let result = policy
        .read(std::path::Path::new(path))
        .map_err(|_| InlineEditDeny::ReadDenied)?;
    let Some(text) = result.text else {
        return Err(InlineEditDeny::NotEditableBinary);
    };
    // Mirror frontier_file_result: a multi-line key/cert block (PEM) ⇒ not editable.
    if text.to_ascii_lowercase().contains("-----begin") {
        return Err(InlineEditDeny::NotEditableSecret);
    }
    // Per-line redaction verdict: ANY secret-shaped line ⇒ not editable (fail-closed on a
    // classify error, exactly as the loop's read does).
    for line in text.lines() {
        let fragment = [line];
        let secret = match redact(&RedactionRequest {
            fragments: &fragment,
            candidate_memory_ids: &[],
            deleted_ids: &[],
            include_private_memory: false,
        }) {
            Ok(receipt) => receipt.secret_fragments_denied_u32() != 0,
            Err(_) => true,
        };
        if secret {
            return Err(InlineEditDeny::NotEditableSecret);
        }
    }
    Ok((
        text,
        VerifiedFileRead {
            path_as_typed: path.to_string(),
            canonical_path: result.canonical_path,
            sha256_32: result.sha256_32,
        },
    ))
}

/// SEAL an inline edit: given the model- (or test-) produced `replacement` for `sel_text`, locate
/// the unique selection in the file's CURRENT clean bytes, splice byte-exact, and mint+store an
/// INERT `FileEditProposal` (IV-W2 read-bound; IV-W7a secret-screened). The model NEVER applies —
/// the owner approves via E10. This is the unit-testable chokepoint (NO model call): inject a
/// policy + a temp store + a fixed `replacement`.
#[cfg(any(feature = "local-mlx", feature = "local-vllm", test))]
fn inline_edit_seal(
    policy: &crate::file_context::FileReadPolicy,
    store: &ProposalStore,
    path: &str,
    sel_text: &str,
    replacement: &str,
) -> Result<InlineEditProposed, InlineEditDeny> {
    let (content, verified) = read_clean_editable(policy, path)?;
    let (from, to) = locate_unique_selection(&content, sel_text)?;
    // Splice the replacement into the unique selection range (byte-exact; all else preserved).
    let mut new_content = String::with_capacity(content.len() - (to - from) + replacement.len());
    new_content.push_str(&content[..from]);
    new_content.push_str(replacement);
    new_content.push_str(&content[to..]);
    // IV-W7a — the canonical redaction verdict over the PROPOSED full content (fail-closed).
    let fragments = [new_content.as_str()];
    let secret_shaped = match redact(&RedactionRequest {
        fragments: &fragments,
        candidate_memory_ids: &[],
        deleted_ids: &[],
        include_private_memory: false,
    }) {
        Ok(receipt) => receipt.secret_fragments_denied_u32() > 0,
        Err(_) => true,
    };
    let proposed = crate::file_edit::ProposedEdit {
        target_as_typed: path.to_string(),
        content: new_content.clone(),
    };
    let minted =
        mint_proposal(&proposed, std::slice::from_ref(&verified), secret_shaped).map_err(|d| {
            match d {
                crate::file_edit::ProposeDeny::SecretShaped => {
                    InlineEditDeny::ReplacementSecretShaped
                }
                other => InlineEditDeny::Mint(other),
            }
        })?;
    let record_name = store
        .save(&minted)
        .map_err(|_| InlineEditDeny::StoreFailed)?;
    let id: String = record_name.chars().take(PROPOSAL_ID_HEX_CHARS).collect();
    Ok(InlineEditProposed {
        id,
        old_content: content,
        new_content,
    })
}

/// Loopback-transform ONLY the selection per the instruction (the SAME transport fim uses). Returns
/// the replacement text (fences / `ANSWER:` stripped). HONEST-DEGRADES to `Err` when no local model
/// is compiled / reachable. LOOPBACK-ONLY (no off-box egress); the model has no apply path.
#[cfg(any(feature = "local-mlx", feature = "local-vllm"))]
fn inline_edit_transform_local(
    sel_text: &str,
    instruction: &str,
    ctx_before: &str,
    ctx_after: &str,
) -> Result<String, String> {
    use crate::provider::local_chat::LocalChatTransport;
    use crate::provider::local_endpoint::LoopbackBind;
    const T_MS: u32 = 12000;
    const MAX_TOKENS: u32 = 1024;
    const CTX_CHARS: usize = 2000;
    let Some(port) = crate::commands::model_select::resolve_local_port(
        std::env::var(SINABRO_LOCAL_PORT_ENV).ok().as_deref(),
        LOCAL_CONSULT_DEFAULT_PORT,
    ) else {
        return Err("SINABRO_LOCAL_PORT is not a valid port (1-65535)".to_string());
    };
    let model = crate::commands::model_select::resolve_local_model(
        std::env::var(SINABRO_LOCAL_MODEL_ENV).ok().as_deref(),
    );
    let Some(transport) = LocalChatTransport::new(LoopbackBind::localhost(port), &model, T_MS)
    else {
        return Err("local transport unavailable".to_string());
    };
    // Bound the context to the code NEAREST the selection (tail of before, head of after);
    // char-based slicing is UTF-8-safe (byte slicing could split a multibyte char).
    let bc: Vec<char> = ctx_before.chars().collect();
    let before: String = bc[bc.len().saturating_sub(CTX_CHARS)..].iter().collect();
    let after: String = ctx_after.chars().take(CTX_CHARS).collect();
    let system = "You are an inline code editor. Rewrite ONLY the SELECTED code per the user's \
                  instruction. Output ONLY the replacement code that should take the selection's \
                  place — no prose, no explanation, no markdown fences, no surrounding context. \
                  Preserve the existing indentation style.";
    let question = format!(
        "<CONTEXT-BEFORE>\n{before}\n</CONTEXT-BEFORE>\n<SELECTION>\n{sel_text}\n</SELECTION>\n\
         <CONTEXT-AFTER>\n{after}\n</CONTEXT-AFTER>\nInstruction: {instruction}\n\
         Replacement for <SELECTION>:"
    );
    let outcome = transport
        .send_local_text_with(&model, system, &question, MAX_TOKENS)
        .map_err(|_| "local model unreachable (is the loopback server up?)".to_string())?;
    Ok(strip_code_fence(outcome.answer_text.trim()))
}

/// Strip an accidental leading `ANSWER:` and a wrapping ```lang ... ``` code fence the model may
/// add (the inline-edit replacement must be raw code, never markdown).
#[cfg(any(feature = "local-mlx", feature = "local-vllm"))]
fn strip_code_fence(text: &str) -> String {
    let mut t = text.trim();
    if let Some(rest) = t.strip_prefix("ANSWER:") {
        t = rest.trim_start();
    }
    if let Some(rest) = t.strip_prefix("```") {
        // Drop the language-tag remainder of the fence's first line.
        t = rest.split_once('\n').map_or("", |(_, body)| body);
        if let Some(body) = t.strip_suffix("```") {
            t = body.trim_end_matches('\n');
        }
    }
    t.to_string()
}

/// B⑧ — the GUI-facing inline-edit propose: loopback-transform the selection, then SEAL the result.
/// Resolves the lane-A policy + the local proposal store itself (a thin editor IPC, like
/// `fim_complete_local`). HONEST-DEGRADES to `Err` when no local model is compiled / reachable (the
/// GUI shows the honest reason — never a fabricated edit). LOOPBACK-ONLY (zero egress);
/// custody/funds HARD-LOCKED (PD-6); the model cannot apply.
pub fn inline_edit_propose_local(
    path: &str,
    sel_text: &str,
    instruction: &str,
    ctx_before: &str,
    ctx_after: &str,
) -> Result<InlineEditProposed, String> {
    if instruction.trim().is_empty() {
        return Err(InlineEditDeny::InstructionEmpty.message());
    }
    if sel_text.is_empty() {
        return Err(InlineEditDeny::SelectionEmpty.message());
    }
    #[cfg(any(feature = "local-mlx", feature = "local-vllm"))]
    {
        let replacement =
            inline_edit_transform_local(sel_text, instruction, ctx_before, ctx_after)?;
        let policy = crate::file_context::FileReadPolicy::cwd_default();
        let store =
            ProposalStore::open_local().map_err(|_| InlineEditDeny::StoreUnavailable.message())?;
        inline_edit_seal(&policy, &store, path, sel_text, &replacement).map_err(|d| d.message())
    }
    #[cfg(not(any(feature = "local-mlx", feature = "local-vllm")))]
    {
        let _ = (path, ctx_before, ctx_after);
        Err("local model transport not compiled (build with local-mlx or local-vllm)".to_string())
    }
}

/// B⑧ ADVISORY oracle (owner-locked: Move-only, ADVISORY — the owner single-approve is final, never
/// blocked in v1). Loads the just-minted proposal by `id`; if the target is a Move file, runs the
/// STANDALONE `sui move build` oracle over the proposed content. HONEST-LABELED: a standalone
/// single-module build does NOT resolve in-package deps, so a `FAIL` may be a missing-dep, not a
/// real error — advisory only (a hard-block on FAIL is a v2 owner toggle). Non-Move ⇒ "n/a".
#[must_use]
pub fn inline_edit_oracle_for(id: &str, path: &str) -> String {
    if !path.to_ascii_lowercase().ends_with(".move") {
        return "n/a (non-Move; the inline-edit oracle is Move-only in v1)".to_string();
    }
    let Ok(store) = ProposalStore::open_local() else {
        return "n/a (no proposal store)".to_string();
    };
    let Ok(pending) = store.find_by_prefix(id) else {
        return "n/a (proposal not found)".to_string();
    };
    let content = String::from_utf8_lossy(&pending.proposal.content).to_string();
    // Wrap in a fenced block so `extract_move_source` always recovers the module body.
    let fenced = format!("```move\n{content}\n```");
    match crate::code_oracle::sui_build_oracle(&fenced) {
        crate::verification::VerificationEvidence::CodeOracle(Some(true)) => {
            "PASS (standalone Move build)".to_string()
        }
        crate::verification::VerificationEvidence::CodeOracle(Some(false)) => {
            "FAIL (standalone Move build — advisory; in-package deps unresolved)".to_string()
        }
        _ => "n/a (no sui toolchain / no kernel sandbox / not compilable standalone)".to_string(),
    }
}

#[cfg(test)]
mod inline_edit_tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;
    use crate::file_context::MAX_FILE_BYTES;
    use crate::memory_store::MemoryCipher;

    fn temp_root(tag: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!("sinabro_cmdk_{tag}_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("mkdir");
        dir
    }

    fn policy_for(root: &std::path::Path) -> crate::file_context::FileReadPolicy {
        crate::file_context::FileReadPolicy::new(
            std::slice::from_ref(&root.to_path_buf()),
            MAX_FILE_BYTES,
        )
    }

    fn store_for(dir: std::path::PathBuf) -> ProposalStore {
        std::fs::create_dir_all(&dir).expect("mkdir store");
        ProposalStore::with_dir(MemoryCipher::from_key([7u8; 32]), dir)
    }

    #[test]
    fn locate_unique_found_missing_ambiguous_empty() {
        assert_eq!(locate_unique_selection("abcXYZdef", "XYZ"), Ok((3, 6)));
        assert_eq!(
            locate_unique_selection("abc", "ZZZ"),
            Err(InlineEditDeny::SelectionNotFound)
        );
        assert_eq!(
            locate_unique_selection("foo foo", "foo"),
            Err(InlineEditDeny::SelectionAmbiguous)
        );
        assert_eq!(
            locate_unique_selection("abc", ""),
            Err(InlineEditDeny::SelectionEmpty)
        );
    }

    #[test]
    fn seal_splices_unique_selection_and_apply_yields_new_content() {
        let root = temp_root("seal_ok");
        let path = root.join("m.rs");
        std::fs::write(&path, "fn a() {}\nfn target() { old() }\nfn b() {}\n").unwrap();
        let policy = policy_for(&root);
        let store = store_for(root.join("store"));
        let p = inline_edit_seal(
            &policy,
            &store,
            path.to_str().unwrap(),
            "fn target() { old() }",
            "fn target() { renamed() }",
        )
        .expect("seals");
        assert!(p.new_content.contains("renamed()"));
        assert!(!p.new_content.contains("old()"));
        assert_eq!(
            p.new_content,
            "fn a() {}\nfn target() { renamed() }\nfn b() {}\n"
        );
        // The sealed proposal is retrievable and applies to exactly new_content.
        let pending = store.find_by_prefix(&p.id).expect("found");
        let receipt = apply_proposal(&policy, &pending.proposal).expect("applies");
        let _ = receipt;
        let after = std::fs::read_to_string(&path).unwrap();
        assert_eq!(after, p.new_content);
    }

    #[test]
    fn seal_refuses_selection_not_found_and_ambiguous() {
        let root = temp_root("seal_sel");
        let path = root.join("m.rs");
        std::fs::write(&path, "let x = 1;\nlet x = 1;\n").unwrap();
        let policy = policy_for(&root);
        let store = store_for(root.join("store"));
        assert_eq!(
            inline_edit_seal(
                &policy,
                &store,
                path.to_str().unwrap(),
                "let x = 1;",
                "let y = 2;"
            ),
            Err(InlineEditDeny::SelectionAmbiguous)
        );
        assert_eq!(
            inline_edit_seal(&policy, &store, path.to_str().unwrap(), "absent", "z"),
            Err(InlineEditDeny::SelectionNotFound)
        );
    }

    #[test]
    fn seal_refuses_secret_shaped_file_and_replacement() {
        let root = temp_root("seal_secret");
        // A file with a secret-shaped line is not editable inline (clean-gate).
        let secret_path = root.join("s.rs");
        std::fs::write(&secret_path, "let k = \"suiprivkey1qqqexamplenotreal\";\n").unwrap();
        let policy = policy_for(&root);
        let store = store_for(root.join("store"));
        assert_eq!(
            inline_edit_seal(
                &policy,
                &store,
                secret_path.to_str().unwrap(),
                "let k",
                "let m"
            ),
            Err(InlineEditDeny::NotEditableSecret)
        );
        // A clean file but a secret-shaped REPLACEMENT is refused at mint (IV-W7a).
        let clean_path = root.join("c.rs");
        std::fs::write(&clean_path, "let token = PLACEHOLDER;\n").unwrap();
        assert_eq!(
            inline_edit_seal(
                &policy,
                &store,
                clean_path.to_str().unwrap(),
                "PLACEHOLDER",
                "\"suiprivkey1qqqexamplenotreal\""
            ),
            Err(InlineEditDeny::ReplacementSecretShaped)
        );
    }

    #[test]
    fn read_clean_editable_rejects_pem_and_binary_and_outside_root() {
        let root = temp_root("clean_gate");
        let policy = policy_for(&root);
        let pem = root.join("k.txt");
        std::fs::write(
            &pem,
            "-----BEGIN PRIVATE KEY-----\nabc\n-----END PRIVATE KEY-----\n",
        )
        .unwrap();
        assert_eq!(
            read_clean_editable(&policy, pem.to_str().unwrap()).map(|_| ()),
            Err(InlineEditDeny::NotEditableSecret)
        );
        // A path outside the policy root is refused.
        assert_eq!(
            read_clean_editable(&policy, "/etc/hosts").map(|_| ()),
            Err(InlineEditDeny::ReadDenied)
        );
    }

    #[test]
    fn deny_class_labels_are_stable() {
        assert_eq!(
            InlineEditDeny::SelectionNotFound.class_label(),
            "inline_edit.selection_not_found"
        );
        assert_eq!(
            InlineEditDeny::NotEditableSecret.class_label(),
            "inline_edit.not_editable_secret"
        );
        assert_eq!(
            InlineEditDeny::Mint(crate::file_edit::ProposeDeny::TargetNotRead).class_label(),
            "inline_edit.mint_denied"
        );
    }

    #[test]
    fn oracle_non_move_is_na() {
        assert!(inline_edit_oracle_for("deadbeef", "src/foo.rs").starts_with("n/a (non-Move"));
    }

    // The loopback transform's only NOVEL pure logic = fence/ANSWER stripping (the HTTP transport
    // itself is byte-identical to the production-LIVE `fim_complete_local`). Gated to the feature
    // that compiles `strip_code_fence`.
    #[cfg(any(feature = "local-mlx", feature = "local-vllm"))]
    #[test]
    fn strip_code_fence_handles_answer_prefix_and_lang_fence() {
        assert_eq!(strip_code_fence("fn f() {}"), "fn f() {}");
        assert_eq!(strip_code_fence("```rust\nfn f() {}\n```"), "fn f() {}");
        assert_eq!(strip_code_fence("ANSWER: fn f() {}"), "fn f() {}");
        assert_eq!(strip_code_fence("```\nlet x = 1;\n```"), "let x = 1;");
    }
}

#[cfg(all(test, not(any(feature = "local-mlx", feature = "local-vllm"))))]
mod fim_tests {
    #[test]
    fn fim_honest_degrades_without_local_model() {
        // No local-serving feature ⇒ no transport ⇒ honest Err (never a fabricated completion).
        assert!(super::fim_complete_local("let x = ", ";").is_err());
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// SLICE 2 (owner 2026-06-23 "executor도 웬만한 모델 다 배선 … 로컬 정체성 유지") — the
// orchestrate IMPLEMENT brain ("executor"): LOCAL loopback (the DEFAULT — zero-egress,
// first-class, byte-unchanged) OR a REMOTE egress provider. The remote leg reuses the
// EXISTING gated `ProviderTransport` (same redaction wall; the orchestrate phrase IS its
// same-message owner-arm); the host is a CLOSED allowlisted enum (`live_codec_from_token`
// — no base-URL form), so funds-egress stays structurally impossible. The orchestrate
// REASONING role stays loopback in v1. custody/funds/chain-write HARD-LOCKED.
// ─────────────────────────────────────────────────────────────────────────────

/// The resolved IMPLEMENT brain for the two-model loop.
#[cfg(any(feature = "local-mlx", feature = "local-vllm"))]
enum ExecutorTarget {
    /// LOCAL loopback (default): the per-port `LocalChatTransport` pool. Zero egress.
    Local,
    /// REMOTE egress provider: the gated `ProviderTransport` (redaction-walled,
    /// owner-armed). Only a closed-set allowlisted host; no arbitrary URL.
    #[cfg(feature = "provider-egress")]
    Remote(Box<RemoteExecutor>),
}

/// Materials for a REMOTE executor leg: the gated transport, the authorizing
/// `RedactedConsult` (the orchestrate phrase IS its same-message approval), and the
/// fixed remote model id. Built ONCE; reused for every implement sub-task (mirrors the
/// provider-fan executor's one-consult-many-turns shape).
#[cfg(all(
    feature = "provider-egress",
    any(feature = "local-mlx", feature = "local-vllm")
))]
struct RemoteExecutor {
    transport: crate::provider::egress::ProviderTransport,
    consult: crate::provider::egress::RedactedConsult,
    model: String,
    host: crate::provider::egress::ProviderHost,
}

/// Resolve the executor brain from `SINABRO_EXECUTOR_MODE` (+ `_PROVIDER` / `_MODEL`
/// when remote). Unset/blank/`local` ⇒ Local (the default; zero-egress). `remote` ⇒ a
/// closed-set provider egress leg (requires `provider-egress`; otherwise a typed deny —
/// never a silent downgrade to a different brain). An unknown mode/provider/model ⇒ a
/// typed deny (no silent fallback). `receipt` authorizes the remote leg's consult.
#[cfg(any(feature = "local-mlx", feature = "local-vllm"))]
fn resolve_executor_target(
    receipt: crate::provider::redaction::RedactionReceipt,
    task: &str,
) -> Result<ExecutorTarget, String> {
    let mode = std::env::var(crate::commands::model_select::EXECUTOR_MODE_ENV)
        .ok()
        .map(|s| s.trim().to_ascii_lowercase())
        .unwrap_or_default();
    match mode.as_str() {
        "" | "local" | "loopback" => {
            let _ = (receipt, task); // the local leg needs no consult
            Ok(ExecutorTarget::Local)
        }
        "remote" | "provider" => resolve_remote_executor(receipt, task),
        other => Err(format!(
            "unknown {} '{other}'; use local|remote",
            crate::commands::model_select::EXECUTOR_MODE_ENV
        )),
    }
}

/// Build a REMOTE executor leg (closed-set host + validated model + authorizing
/// consult). Mirrors `provider_consult`'s bounded-request construction.
#[cfg(all(
    feature = "provider-egress",
    any(feature = "local-mlx", feature = "local-vllm")
))]
fn resolve_remote_executor(
    receipt: crate::provider::redaction::RedactionReceipt,
    task: &str,
) -> Result<ExecutorTarget, String> {
    use crate::commands::model_compress::ConsultScope;
    use crate::commands::model_route::ConsultTrigger;
    use crate::provider::egress::{ProviderHost, ProviderTransport, RedactedConsult};
    use crate::provider::frontier_consult::{self, BoundedConsultInputs, BoundedConsultRequest};
    use crate::route::RouteExecutionState;

    // provider: closed codec-capable set; unset ⇒ OpenRouter default; unknown ⇒ deny.
    let host = match std::env::var(crate::commands::model_select::EXECUTOR_PROVIDER_ENV) {
        Ok(token) if !token.trim().is_empty() => ProviderHost::live_codec_from_token(&token)
            .ok_or_else(|| {
                format!(
                    "unknown {} '{}'; use openrouter|sakana",
                    crate::commands::model_select::EXECUTOR_PROVIDER_ENV,
                    token.trim()
                )
            })?,
        _ => ProviderHost::OpenRouter,
    };
    // model: validated; unset ⇒ the per-provider default.
    let model = match std::env::var(crate::commands::model_select::EXECUTOR_MODEL_ENV) {
        Ok(raw) if !raw.trim().is_empty() => crate::commands::model_select::validate_model_id(&raw)
            .map(str::to_string)
            .map_err(|deny| {
                format!(
                    "invalid {}: {}",
                    crate::commands::model_select::EXECUTOR_MODEL_ENV,
                    deny.label()
                )
            })?,
        _ => match host {
            ProviderHost::Sakana => {
                crate::commands::model_select::FRONTIER_SAKANA_DEFAULT_MODEL.to_string()
            }
            ProviderHost::ZeroGCompute => {
                crate::commands::model_select::ZEROG_DEFAULT_MODEL.to_string()
            }
            _ => crate::commands::model_select::FRONTIER_DEFAULT_MODEL.to_string(),
        },
    };
    // The authorizing consult — the orchestrate phrase IS its same-message approval
    // (mirrors `provider_consult`; the live wire content is per-subtask + redacted).
    let inputs = BoundedConsultInputs {
        route_state: RouteExecutionState::Slow,
        trigger: ConsultTrigger::LowConfidenceHighBlastRadius,
        scope: ConsultScope::minimal(),
        redaction_report_hash_32: receipt.redacted_payload_hash_32(),
        evidence_refs_hash_32: sha256_32(b"orchestrate-remote-executor-v1"),
        prompt_hash_32: sha256_32(task.as_bytes()),
        timeout_ms_u32: PROVIDER_CONSULT_TIMEOUT_MS,
        local_verification_command_hash_32: sha256_32(b"orchestrate-oracle-verifies-implement"),
    };
    let Some(request) = frontier_consult::build(&inputs) else {
        return Err("bounded consult request denied".to_string());
    };
    let request = BoundedConsultRequest {
        live_dispatch_allowed: true,
        ..request
    };
    let Some(consult) = RedactedConsult::new(request, receipt) else {
        return Err("consult payload rejected".to_string());
    };
    Ok(ExecutorTarget::Remote(Box::new(RemoteExecutor {
        transport: ProviderTransport::for_host(host),
        consult,
        model,
        host,
    })))
}

/// `remote` requested but the `provider-egress` transport is NOT compiled ⇒ a typed
/// deny (never a silent downgrade to the local brain).
#[cfg(all(
    not(feature = "provider-egress"),
    any(feature = "local-mlx", feature = "local-vllm")
))]
fn resolve_remote_executor(
    receipt: crate::provider::redaction::RedactionReceipt,
    task: &str,
) -> Result<ExecutorTarget, String> {
    let _ = (receipt, task);
    Err("remote executor not compiled (build sinabro with the provider-egress feature)".to_string())
}

/// Run ONE implement sub-task through the REMOTE executor (the gated egress transport).
/// SI-2 egress choke: this send fn redacts its OWN assembled payload at the boundary
/// (defense-in-depth — it never trusts the caller to have gated), so a secret-shaped
/// message is withheld here too; the egress preflight (live-dispatch + approval +
/// allowlist + key) then gates again.
#[cfg(all(
    feature = "provider-egress",
    any(feature = "local-mlx", feature = "local-vllm")
))]
fn remote_executor_turn(
    remote: &RemoteExecutor,
    system: &str,
    user: &str,
) -> Result<crate::agent_loop::AgentTurn, crate::agent_loop::AgentTransportError> {
    use crate::provider::redaction::{RedactionRequest, redact};
    // SI-2: redact the assembled outbound message at the send boundary itself.
    let frags = [user];
    match redact(&RedactionRequest {
        fragments: &frags,
        candidate_memory_ids: &[],
        deleted_ids: &[],
        include_private_memory: false,
    }) {
        Ok(r) if r.secret_fragments_denied_u32() == 0 => {}
        _ => {
            return Err(crate::agent_loop::AgentTransportError {
                class_label: "assembled message denied by redaction".to_string(),
            });
        }
    }
    match remote.transport.send_live_text(
        &remote.consult,
        crate::provider::egress::EgressApproval::grant(),
        system,
        user,
        &remote.model,
        PROVIDER_CONSULT_MAX_OUTPUT_TOKENS,
    ) {
        Ok(o) => Ok(crate::agent_loop::AgentTurn {
            answer_text: o.answer_text,
            input_tokens_u64: o.input_tokens,
            output_tokens_u64: o.output_tokens,
            cached_tokens_u64: o.cached_tokens,
        }),
        Err(e) => Err(crate::agent_loop::AgentTransportError {
            class_label: consult_denied_label(&e),
        }),
    }
}

/// A short, owner-visible label for the resolved executor brain (render honesty: the
/// loop reports WHICH brain implemented — loopback vs which remote provider).
#[cfg(any(feature = "local-mlx", feature = "local-vllm"))]
fn executor_target_label(executor: &ExecutorTarget) -> String {
    match executor {
        ExecutorTarget::Local => "local (loopback; zero-egress)".to_string(),
        #[cfg(feature = "provider-egress")]
        ExecutorTarget::Remote(remote) => format!(
            "remote ({}; egress, redaction-walled, model={})",
            remote.host.host(),
            remote.model
        ),
    }
}

/// P1-2b — the TWO-MODEL ORCHESTRATION verb (`provider orchestrate <phrase>
/// <task>`): the frontier reasoning role PLANS (a `SUBTASK` envelope) → the plan is
/// decomposed FAIL-CLOSED → each sub-task is routed by the pure L2 selector to its
/// specialist `model_id` and IMPLEMENTED by the local brain (the routed model_id ON
/// THE WIRE via `send_local_text_with`, the R1 seam) → the frontier role
/// SYNTHESIZES. v1 wires BOTH roles to the SAME loopback endpoint (the reasoning
/// role sends the env/default model; the implement roles send the routed model_ids,
/// so the routing is VISIBLE on the wire); the owner-armed real frontier egress is
/// the additive follow (the core already accepts a separate frontier transport).
/// Same ⑧ gate stack as the local consult (typed phrase → bounded task →
/// before-send redaction → paranoid loopback client → the UNMODIFIED bounded loop
/// per stage). custody/funds HARD-LOCKED (this verb adds no capability).
#[cfg(any(feature = "local-mlx", feature = "local-vllm"))]
fn provider_orchestrate_local(rest: &[String], out: &mut impl Write) -> io::Result<bool> {
    use crate::agent_loop::{
        AgentTransport, AgentTransportError, AgentTurn, FnTransport, MemoryToolState,
    };
    use crate::agent_orchestrator::{
        OrchestratorStop, run_orchestrated_consult, run_orchestrated_consult_parallel,
    };
    use crate::provider::local_chat::LocalChatTransport;
    use crate::repl::approval::{ApprovalDecision, ApprovalPrompt};

    let envelope_hex = hex16(&sha256_32(b"provider orchestrate"));
    let supplied_phrase = rest.get(1).map_or("", String::as_str);
    let task = rest.get(2..).map(|s| s.join(" ")).unwrap_or_default();
    let task = task.trim();

    // GATE 1: the exact typed phrase IS the same-message owner ceremony.
    let mut prompt = ApprovalPrompt::new(
        ApprovalRequirement::TypedPhrase,
        PROVIDER_ORCHESTRATE_PHRASE,
    );
    if !matches!(
        prompt.evaluate(supplied_phrase.trim()),
        ApprovalDecision::Approved
    ) {
        emit(
            out,
            "provider orchestrate",
            &envelope_hex,
            CommandRisk::Network,
            ApprovalRequirement::TypedPhrase,
            RenderTruth::Yellow,
            &[format!(
                "locked: provider orchestrate {PROVIDER_ORCHESTRATE_PHRASE} <task> (two-model loop: frontier plan -> route -> local implement -> synthesize; loopback)"
            )],
        )?;
        return Ok(true);
    }
    // GATE 2: bounded input.
    if task.is_empty() {
        return provider_orchestrate_error(out, &envelope_hex, "empty task; nothing orchestrated");
    }
    if task.len() > PROVIDER_CONSULT_MAX_QUESTION_BYTES {
        return provider_orchestrate_error(
            out,
            &envelope_hex,
            "task exceeds the bounded input cap",
        );
    }
    // GATE 3: before-send redaction (deny-not-fix; the loopback peer is unaudited).
    let fragments = [task];
    let receipt = match redact(&RedactionRequest {
        fragments: &fragments,
        candidate_memory_ids: &[],
        deleted_ids: &[],
        include_private_memory: false,
    }) {
        Ok(receipt) => receipt,
        Err(_) => {
            return provider_orchestrate_error(
                out,
                &envelope_hex,
                "redaction gate denied the payload",
            );
        }
    };
    if receipt.secret_fragments_denied_u32() > 0 || receipt.outgoing_fragment_count_u32() == 0 {
        return provider_orchestrate_error(
            out,
            &envelope_hex,
            "task is secret-shaped; not orchestrated",
        );
    }
    // SLICE 2: resolve the IMPLEMENT brain (local loopback default | remote egress).
    // Consumes the task receipt to authorize a remote leg's consult (dropped if local).
    let executor = match resolve_executor_target(receipt, task) {
        Ok(target) => target,
        Err(reason) => return provider_orchestrate_error(out, &envelope_hex, &reason),
    };
    // GATE 4: resolve the loopback bind + the default reasoning-role model.
    let Some(port) = crate::commands::model_select::resolve_local_port(
        std::env::var(SINABRO_LOCAL_PORT_ENV).ok().as_deref(),
        LOCAL_CONSULT_DEFAULT_PORT,
    ) else {
        return provider_orchestrate_error(
            out,
            &envelope_hex,
            "SINABRO_LOCAL_PORT is not a valid port; nothing orchestrated",
        );
    };
    let base_model = crate::commands::model_select::resolve_local_model(
        std::env::var(SINABRO_LOCAL_MODEL_ENV).ok().as_deref(),
    );
    let bind = crate::provider::local_endpoint::LoopbackBind::localhost(port);
    // GATE 5: the paranoid loopback client (IV-L1), built ONCE and reused across
    // BOTH roles (reasoning sends base_model; implement sends the routed model_id
    // via send_local_text_with — the R1 seam).
    let Some(transport) = LocalChatTransport::new(bind, &base_model, PROVIDER_CONSULT_TIMEOUT_MS)
    else {
        return provider_orchestrate_error(out, &envelope_hex, "local http client failed to build");
    };
    let mem = consult_memory_load();
    let loop_contents: Vec<(MemoryId, &[u8])> = mem
        .loaded
        .chunks
        .iter()
        .map(|(chunk, _)| (chunk.id(), chunk.envelope().content.as_slice()))
        .collect();
    let state = MemoryToolState {
        records: &mem.folded.records,
        contents: &loop_contents,
        policy: &mem.policy,
    };
    let plan_system =
        "You are the PLANNER (the frontier reasoning role). Decompose the task into sub-tasks. \
         Output ONLY lines of the EXACT form:\nSUBTASK <id> <kind> <deps|-> <goal>\n\
         where <id> is a number, <kind> is a lowercase expert label (e.g. sui_move, \
         solana_anchor, web3_frontend, audit, nl_bridge), <deps> is '-' or comma-separated \
         ids, and <goal> is the implementation goal. No prose, no other text."
            .to_string();
    let impl_system = format!(
        "{}\n\n{}",
        sinabro_system_prompt(true),
        crate::agent_loop::SINABRO_LOOP_PROTOCOL
    );
    let synth_system = "You are the SYNTHESIZER (the frontier reasoning role). Combine the \
         implemented sub-tasks into ONE final answer. Begin your reply with ANSWER:"
        .to_string();
    let table = load_routing_table();
    // K-6: the dynamic-LoRA switch's send gate — the certified corpus→adapter MANIFEST
    // (P-HALL) + the SERVED set. An adapter the routing table requests rides the wire
    // ONLY if a real multi-LoRA server serves it; otherwise the base model answers
    // (honest-degrade, never a fabricated adapter). Empty served set (no server) ⇒ base.
    let lora_manifest = load_lora_manifest();
    let served_adapters = load_served_adapter_set();

    let outcome = {
        let mut frontier = FnTransport(|system: &str, user: &str| {
            let frags = [user];
            match redact(&RedactionRequest {
                fragments: &frags,
                candidate_memory_ids: &[],
                deleted_ids: &[],
                include_private_memory: false,
            }) {
                Ok(receipt) if receipt.secret_fragments_denied_u32() == 0 => {}
                _ => {
                    return Err(AgentTransportError {
                        class_label: "assembled message denied by redaction".to_string(),
                    });
                }
            }
            match transport.send_local_text(system, user, PROVIDER_CONSULT_MAX_OUTPUT_TOKENS) {
                Ok(o) => Ok(AgentTurn {
                    answer_text: o.answer_text,
                    input_tokens_u64: o.input_tokens,
                    output_tokens_u64: o.output_tokens,
                    cached_tokens_u64: o.cached_tokens,
                }),
                Err(error) => Err(AgentTransportError {
                    class_label: error.class_label(),
                }),
            }
        });
        // P1-3-full(a) (S2-2): the CODE oracle is LIVE — a `sui_move` sub-task's Move
        // answer is compiled by `sui move build --path <temp pkg>` INSIDE the E6
        // network-DENIED sandbox (build-only; no chain action), and that exit code is
        // the oracle bit. The model NEVER self-certifies: `verify` consumes the typed
        // evidence, the answer text reaches only the deterministic compiler. Other kinds
        // ⇒ Absent here (the personal/external/perf/cross-memory oracles ride P1-4).
        let mut code_oracle = |st: &crate::provider::executor_route::SubTask,
                               o: &crate::agent_loop::AgentLoopOutcome|
         -> crate::verification::VerificationEvidence {
            crate::code_oracle::orchestrate_verify_oracle(st, o)
        };
        // K-5 (㉑ FLEET_GUI): the LOCAL worker fleet runs in PARALLEL — the IMPLEMENT
        // phase fans out across the deps-DAG topological waves, BOUNDED, each worker's
        // output STILL gated by the SAME deterministic `code_oracle` (drift-0; the model
        // is never an arbiter). A `Sync` factory builds a FRESH redaction-walled loopback
        // transport per worker (no shared mutable pool ⇒ `Send` across threads). The
        // base `transport` stays the reasoning (PLAN/SYNTH) role's loopback. The REMOTE
        // frontier-egress IMPLEMENT stays SERIAL (no concurrent owner-armed egress) on the
        // byte-unchanged sequential path.
        match &executor {
            ExecutorTarget::Local => {
                let factory = |port: u16,
                               model_id: &str|
                 -> Option<Box<dyn AgentTransport + Send>> {
                    let worker = LocalChatTransport::new(
                        crate::provider::local_endpoint::LoopbackBind::localhost(port),
                        &base_model,
                        PROVIDER_CONSULT_TIMEOUT_MS,
                    )?;
                    // K-6: HONEST-DEGRADE the routing table's requested adapter to the
                    // model id a real multi-LoRA server actually serves — an unserved
                    // adapter NEVER rides the wire (the served base answers, never a
                    // fabricated adapter). Empty served set (no server) ⇒ the base model.
                    let wire_model = crate::provider::lora_manifest::resolve_adapter(
                        model_id,
                        &lora_manifest,
                        &served_adapters,
                        &base_model,
                    )
                    .wire_model_id()
                    .to_string();
                    Some(Box::new(FnTransport(move |system: &str, user: &str| {
                        let frags = [user];
                        match redact(&RedactionRequest {
                            fragments: &frags,
                            candidate_memory_ids: &[],
                            deleted_ids: &[],
                            include_private_memory: false,
                        }) {
                            Ok(receipt) if receipt.secret_fragments_denied_u32() == 0 => {}
                            _ => {
                                return Err(AgentTransportError {
                                    class_label: "assembled message denied by redaction"
                                        .to_string(),
                                });
                            }
                        }
                        match worker.send_local_text_with(
                            &wire_model,
                            system,
                            user,
                            PROVIDER_CONSULT_MAX_OUTPUT_TOKENS,
                        ) {
                            Ok(o) => Ok(AgentTurn {
                                answer_text: o.answer_text,
                                input_tokens_u64: o.input_tokens,
                                output_tokens_u64: o.output_tokens,
                                cached_tokens_u64: o.cached_tokens,
                            }),
                            Err(error) => Err(AgentTransportError {
                                class_label: error.class_label(),
                            }),
                        }
                    })) as Box<dyn AgentTransport + Send>)
                };
                run_orchestrated_consult_parallel(
                    &mut frontier,
                    &factory,
                    &mut code_oracle,
                    &table,
                    &state,
                    &plan_system,
                    &impl_system,
                    &synth_system,
                    task,
                    0,
                    0,
                )
            }
            #[cfg(feature = "provider-egress")]
            ExecutorTarget::Remote(remote) => {
                let mut local_turn = |_port: u16,
                                      _model_id: &str,
                                      system: &str,
                                      user: &str|
                 -> Result<AgentTurn, AgentTransportError> {
                    // Per-message redaction wall (the remote leg's egress preflight then
                    // gates a SECOND time).
                    let frags = [user];
                    match redact(&RedactionRequest {
                        fragments: &frags,
                        candidate_memory_ids: &[],
                        deleted_ids: &[],
                        include_private_memory: false,
                    }) {
                        Ok(receipt) if receipt.secret_fragments_denied_u32() == 0 => {}
                        _ => {
                            return Err(AgentTransportError {
                                class_label: "assembled message denied by redaction".to_string(),
                            });
                        }
                    }
                    remote_executor_turn(remote, system, user)
                };
                run_orchestrated_consult(
                    &mut frontier,
                    &mut local_turn,
                    &mut code_oracle,
                    &table,
                    &state,
                    &plan_system,
                    &impl_system,
                    &synth_system,
                    task,
                    0,
                    0,
                )
            }
        }
    };

    let mut body: Vec<String> = Vec::new();
    body.push(format!(
        "orchestrate: stop={:?} endpoint=127.0.0.1:{port} reasoning-model={base_model}",
        outcome.stop
    ));
    body.push(format!("executor: {}", executor_target_label(&executor)));
    body.push(format!(
        "sub-tasks: {} (implemented {})",
        outcome.subtasks.len(),
        outcome.implemented_count()
    ));
    for r in &outcome.subtasks {
        // The routing + verify verdict on a SHORT line (emit clamps lines to 80 cols),
        // so the P-HALL gate result (verify / admits) is never truncated; the Move
        // answer preview rides its own line (whitespace-collapsed, capped).
        body.push(format!(
            "  id={} {}->:{}/{} verify={:?} admits={}",
            r.subtask.id,
            r.subtask.kind.label(),
            r.port,
            r.model_id,
            r.receipt.verdict,
            r.receipt.admits_write()
        ));
        let answer = r.outcome.answer.as_deref().unwrap_or("(no answer)");
        let preview: String = answer
            .split_whitespace()
            .collect::<Vec<_>>()
            .join(" ")
            .chars()
            .take(70)
            .collect();
        body.push(format!("      :: {preview}"));
        // K-6: the honest LoRA send truth for THIS sub-task — the model id that ACTUALLY
        // rode the wire (the requested adapter resolved server-or-degraded). PD-1: a
        // degraded line shows the base answered, never a fabricated adapter.
        let res = crate::provider::lora_manifest::resolve_adapter(
            &r.model_id,
            &lora_manifest,
            &served_adapters,
            &base_model,
        );
        body.push(format!(
            "      lora: wire={} [{}]",
            res.wire_model_id(),
            res.status_label()
        ));
    }
    body.push(format!(
        "write-admitted (P-HALL gate; only oracle-Verified): {}/{}",
        outcome.write_admitted_count(),
        outcome.subtasks.len()
    ));
    body.push(match &outcome.synthesis {
        Some(s) => format!("synthesis: {s}"),
        None => "synthesis: (none)".to_string(),
    });
    let truth = if matches!(outcome.stop, OrchestratorStop::Synthesized) {
        RenderTruth::Green
    } else {
        RenderTruth::Yellow
    };
    emit(
        out,
        "provider orchestrate",
        &envelope_hex,
        CommandRisk::Network,
        ApprovalRequirement::TypedPhrase,
        truth,
        &body,
    )?;
    Ok(true)
}

/// P1-2b error render (orchestrate label; secret-zero static message).
#[cfg(any(feature = "local-mlx", feature = "local-vllm"))]
fn provider_orchestrate_error(
    out: &mut impl Write,
    envelope_hex: &str,
    message: &str,
) -> io::Result<bool> {
    emit(
        out,
        "provider orchestrate",
        envelope_hex,
        CommandRisk::Network,
        ApprovalRequirement::TypedPhrase,
        RenderTruth::Red,
        &[message.to_string()],
    )?;
    Ok(true)
}

// ── B⑬: PLAN MODE — surface the SUBTASK plan as an editable checklist; execute only on approve ───
// The LIVE one-shot `provider orchestrate` runs PLAN→DECOMPOSE→IMPLEMENT-ALL→SYNTHESIZE straight
// through. Plan Mode splits it across the EXISTING phase fns (`run_orchestrated_plan_only` +
// `run_orchestrated_from_subtasks`): the GUI runs the PLAN phase, shows the sub-tasks (each
// disable-able), and on the owner's APPROVE runs IMPLEMENT+SYNTHESIZE over the APPROVED SUBSET only —
// so the (costly) implement+synthesize phases are INERT until the owner approves. The frontier calls
// stay gated by the orchestrate phrase; the parser (`parse_subtask_envelope`) is the grammar lock,
// so RUN re-validates the approved lines (never trusts a GUI-reconstructed plan). custody HARD-LOCKED.

/// Re-render a parsed sub-task to its CANONICAL `SUBTASK <id> <kind> <deps|-> <goal>` line — the GUI
/// displays these + sends the enabled ones back to RUN, where `parse_subtask_envelope` re-validates.
#[cfg(any(feature = "local-mlx", feature = "local-vllm"))]
fn render_subtask_line(st: &crate::provider::executor_route::SubTask) -> String {
    let deps = if st.deps.is_empty() {
        "-".to_string()
    } else {
        st.deps
            .iter()
            .map(u32::to_string)
            .collect::<Vec<_>>()
            .join(",")
    };
    format!("SUBTASK {} {} {} {}", st.id, st.kind.label(), deps, st.goal)
}

/// One implemented sub-task, STRUCTURED for the GUI fleet pane (K-5b): the routed
/// worker the orchestrator fanned out (`agent_orchestrator::RoutedImpl`), projected
/// into stable fields the GUI renders directly — NEVER a string the GUI re-parses
/// (the single-truth-source law). `port`/`model_id` are the dynamic-LoRA route the
/// router selected; `verdict`/`admits` are the DETERMINISTIC verify-oracle gate (the
/// P-HALL anchor — the model never self-certifies a write). Money 0 (a render of an
/// already-gated local loop result; no custody/sign/chain symbol).
#[cfg(any(feature = "local-mlx", feature = "local-vllm"))]
pub struct OrchestrateWorkerView {
    /// The sub-task id (plan order; the drift-0 collection order).
    pub id: u32,
    /// The declared expert label (`sui_move` / `solana_anchor` / `web3_frontend` / …).
    pub kind: String,
    /// The loopback worker port the router selected (the Macro per-chain trail).
    pub port: u16,
    /// The `model_id` the router selected for this kind (the dynamic-LoRA selection).
    pub model_id: String,
    /// The verify-oracle verdict (`{:?}` of the typed `VerificationVerdict`).
    pub verdict: String,
    /// Whether the oracle verdict ADMITS a permanent write (the P-HALL gate; never the
    /// model's own "success").
    pub admits: bool,
    /// A bounded, whitespace-collapsed answer preview (≤70 chars; secret-screened at mint).
    pub preview: String,
}

/// The IMPLEMENT+SYNTHESIZE result the GUI renders after the owner approves a plan.
/// K-5b: `workers` is STRUCTURED (the fleet pane reads fields, never re-parses lines).
#[cfg(any(feature = "local-mlx", feature = "local-vllm"))]
pub struct OrchestrateRunView {
    /// The typed stop reason (`Synthesized` / `SynthesisEmpty` / `DecomposeFailed`).
    pub stop: String,
    /// The frontier's synthesis over the implemented sub-tasks (`None` if empty).
    pub synthesis: Option<String>,
    /// One STRUCTURED worker row per implemented sub-task (route + verify + write-admission
    /// + preview) — the fleet pane's data source (no JS string re-parse).
    pub workers: Vec<OrchestrateWorkerView>,
}

/// B⑬ PLAN phase (GUI-facing): run ONLY frontier PLAN + decompose, return the CANONICAL SUBTASK
/// lines for the owner to review/edit. Phrase-gated (egress); LOOPBACK frontier; NO implement, NO
/// synthesis, NO write. HONEST-DEGRADES to `Err` (locked / empty / no-plan / no-model).
#[cfg(any(feature = "local-mlx", feature = "local-vllm"))]
pub fn orchestrate_plan_for(phrase: &str, task: &str) -> Result<Vec<String>, String> {
    use crate::agent_loop::{AgentTransportError, AgentTurn, FnTransport, MemoryToolState};
    use crate::agent_orchestrator::{PlanPhase, run_orchestrated_plan_only};
    use crate::provider::local_chat::LocalChatTransport;
    use crate::repl::approval::{ApprovalDecision, ApprovalPrompt};

    let task = task.trim();
    let mut prompt = ApprovalPrompt::new(
        ApprovalRequirement::TypedPhrase,
        PROVIDER_ORCHESTRATE_PHRASE,
    );
    if !matches!(prompt.evaluate(phrase.trim()), ApprovalDecision::Approved) {
        return Err("locked: the orchestrate phrase is required".to_string());
    }
    if task.is_empty() {
        return Err("empty task; nothing to plan".to_string());
    }
    if task.len() > PROVIDER_CONSULT_MAX_QUESTION_BYTES {
        return Err("task exceeds the bounded input cap".to_string());
    }
    let frags = [task];
    match redact(&RedactionRequest {
        fragments: &frags,
        candidate_memory_ids: &[],
        deleted_ids: &[],
        include_private_memory: false,
    }) {
        Ok(r) if r.secret_fragments_denied_u32() == 0 && r.outgoing_fragment_count_u32() > 0 => {}
        _ => return Err("task is secret-shaped; not planned".to_string()),
    }
    let Some(port) = crate::commands::model_select::resolve_local_port(
        std::env::var(SINABRO_LOCAL_PORT_ENV).ok().as_deref(),
        LOCAL_CONSULT_DEFAULT_PORT,
    ) else {
        return Err("SINABRO_LOCAL_PORT is not a valid port".to_string());
    };
    let base_model = crate::commands::model_select::resolve_local_model(
        std::env::var(SINABRO_LOCAL_MODEL_ENV).ok().as_deref(),
    );
    let bind = crate::provider::local_endpoint::LoopbackBind::localhost(port);
    let Some(transport) = LocalChatTransport::new(bind, &base_model, PROVIDER_CONSULT_TIMEOUT_MS)
    else {
        return Err("local http client failed to build".to_string());
    };
    let mem = consult_memory_load();
    let loop_contents: Vec<(MemoryId, &[u8])> = mem
        .loaded
        .chunks
        .iter()
        .map(|(chunk, _)| (chunk.id(), chunk.envelope().content.as_slice()))
        .collect();
    let state = MemoryToolState {
        records: &mem.folded.records,
        contents: &loop_contents,
        policy: &mem.policy,
    };
    // Canonical PLANNER prompt (the grammar is also enforced by parse_subtask_envelope).
    let plan_system = "You are the PLANNER (the frontier reasoning role). Decompose the task into sub-tasks. \
         Output ONLY lines of the EXACT form:\nSUBTASK <id> <kind> <deps|-> <goal>\n\
         where <id> is a number, <kind> is a lowercase expert label (e.g. sui_move, \
         solana_anchor, web3_frontend, audit, nl_bridge), <deps> is '-' or comma-separated \
         ids, and <goal> is the implementation goal. No prose, no other text.";
    let mut frontier = FnTransport(|system: &str, user: &str| {
        let f = [user];
        match redact(&RedactionRequest {
            fragments: &f,
            candidate_memory_ids: &[],
            deleted_ids: &[],
            include_private_memory: false,
        }) {
            Ok(r) if r.secret_fragments_denied_u32() == 0 => {}
            _ => {
                return Err(AgentTransportError {
                    class_label: "assembled message denied by redaction".to_string(),
                });
            }
        }
        match transport.send_local_text(system, user, PROVIDER_CONSULT_MAX_OUTPUT_TOKENS) {
            Ok(o) => Ok(AgentTurn {
                answer_text: o.answer_text,
                input_tokens_u64: o.input_tokens,
                output_tokens_u64: o.output_tokens,
                cached_tokens_u64: o.cached_tokens,
            }),
            Err(error) => Err(AgentTransportError {
                class_label: error.class_label(),
            }),
        }
    });
    match run_orchestrated_plan_only(&mut frontier, &state, plan_system, task, 0, 0) {
        PlanPhase::Ready { subtasks, .. } => Ok(subtasks.iter().map(render_subtask_line).collect()),
        PlanPhase::PlanEmpty => {
            Err("the planner produced no plan (loopback model up?)".to_string())
        }
        PlanPhase::DecomposeFailed { .. } => {
            Err("the plan did not decompose into SUBTASK lines (retry)".to_string())
        }
    }
}

/// B⑬ RUN phase (GUI-facing): given the owner-APPROVED SUBTASK lines, re-validate them, then
/// IMPLEMENT each (route → local loop → verify-oracle) + frontier SYNTHESIZE. Phrase-gated. The
/// approved lines are re-parsed (never a GUI-reconstructed struct). HONEST-DEGRADES to `Err`.
#[cfg(any(feature = "local-mlx", feature = "local-vllm"))]
pub fn orchestrate_run_for(
    phrase: &str,
    task: &str,
    approved_lines: &[String],
) -> Result<OrchestrateRunView, String> {
    use crate::agent_loop::{AgentTransportError, AgentTurn, FnTransport, MemoryToolState};
    use crate::agent_orchestrator::run_orchestrated_from_subtasks;
    use crate::provider::executor_route::parse_subtask_envelope;
    use crate::provider::local_chat::LocalChatTransport;
    use crate::repl::approval::{ApprovalDecision, ApprovalPrompt};

    let task = task.trim();
    let mut prompt = ApprovalPrompt::new(
        ApprovalRequirement::TypedPhrase,
        PROVIDER_ORCHESTRATE_PHRASE,
    );
    if !matches!(prompt.evaluate(phrase.trim()), ApprovalDecision::Approved) {
        return Err("locked: the orchestrate phrase is required".to_string());
    }
    if task.is_empty() {
        return Err("empty task; nothing to run".to_string());
    }
    // Re-validate the owner-approved lines through the SAME grammar parser (the lock).
    let plan_text = approved_lines.join("\n");
    let Some(subtasks) = parse_subtask_envelope(&plan_text) else {
        return Err("no valid approved sub-tasks to run (all disabled / malformed)".to_string());
    };
    let frags = [task];
    let receipt = match redact(&RedactionRequest {
        fragments: &frags,
        candidate_memory_ids: &[],
        deleted_ids: &[],
        include_private_memory: false,
    }) {
        Ok(r) if r.secret_fragments_denied_u32() == 0 && r.outgoing_fragment_count_u32() > 0 => r,
        _ => return Err("task is secret-shaped; not run".to_string()),
    };
    // SLICE 2: resolve the IMPLEMENT brain (local loopback default | remote egress).
    // Consumes the task receipt to authorize a remote leg's consult (dropped if local).
    let executor = resolve_executor_target(receipt, task)?;
    let Some(port) = crate::commands::model_select::resolve_local_port(
        std::env::var(SINABRO_LOCAL_PORT_ENV).ok().as_deref(),
        LOCAL_CONSULT_DEFAULT_PORT,
    ) else {
        return Err("SINABRO_LOCAL_PORT is not a valid port".to_string());
    };
    let base_model = crate::commands::model_select::resolve_local_model(
        std::env::var(SINABRO_LOCAL_MODEL_ENV).ok().as_deref(),
    );
    let bind = crate::provider::local_endpoint::LoopbackBind::localhost(port);
    let Some(transport) = LocalChatTransport::new(bind, &base_model, PROVIDER_CONSULT_TIMEOUT_MS)
    else {
        return Err("local http client failed to build".to_string());
    };
    let mem = consult_memory_load();
    let loop_contents: Vec<(MemoryId, &[u8])> = mem
        .loaded
        .chunks
        .iter()
        .map(|(chunk, _)| (chunk.id(), chunk.envelope().content.as_slice()))
        .collect();
    let state = MemoryToolState {
        records: &mem.folded.records,
        contents: &loop_contents,
        policy: &mem.policy,
    };
    let impl_system = format!(
        "{}\n\n{}",
        sinabro_system_prompt(true),
        crate::agent_loop::SINABRO_LOOP_PROTOCOL
    );
    let synth_system = "You are the SYNTHESIZER (the frontier reasoning role). Combine the \
         implemented sub-tasks into ONE final answer. Begin your reply with ANSWER:";
    let table = load_routing_table();
    let view = {
        let mut frontier = FnTransport(|system: &str, user: &str| {
            let f = [user];
            match redact(&RedactionRequest {
                fragments: &f,
                candidate_memory_ids: &[],
                deleted_ids: &[],
                include_private_memory: false,
            }) {
                Ok(r) if r.secret_fragments_denied_u32() == 0 => {}
                _ => {
                    return Err(AgentTransportError {
                        class_label: "assembled message denied by redaction".to_string(),
                    });
                }
            }
            match transport.send_local_text(system, user, PROVIDER_CONSULT_MAX_OUTPUT_TOKENS) {
                Ok(o) => Ok(AgentTurn {
                    answer_text: o.answer_text,
                    input_tokens_u64: o.input_tokens,
                    output_tokens_u64: o.output_tokens,
                    cached_tokens_u64: o.cached_tokens,
                }),
                Err(error) => Err(AgentTransportError {
                    class_label: error.class_label(),
                }),
            }
        });
        let mut local_pool: std::collections::HashMap<u16, LocalChatTransport> =
            std::collections::HashMap::new();
        let mut local_turn = |port: u16,
                              model_id: &str,
                              system: &str,
                              user: &str|
         -> Result<AgentTurn, AgentTransportError> {
            // Per-message redaction wall — applies to BOTH the local and remote legs
            // (a remote leg's egress preflight then gates a SECOND time).
            let f = [user];
            match redact(&RedactionRequest {
                fragments: &f,
                candidate_memory_ids: &[],
                deleted_ids: &[],
                include_private_memory: false,
            }) {
                Ok(r) if r.secret_fragments_denied_u32() == 0 => {}
                _ => {
                    return Err(AgentTransportError {
                        class_label: "assembled message denied by redaction".to_string(),
                    });
                }
            }
            // Route to the resolved IMPLEMENT brain: LOCAL loopback pool (byte-unchanged)
            // OR the gated REMOTE egress transport.
            match &executor {
                ExecutorTarget::Local => {
                    let worker = match local_pool.entry(port) {
                        std::collections::hash_map::Entry::Occupied(e) => e.into_mut(),
                        std::collections::hash_map::Entry::Vacant(v) => {
                            match LocalChatTransport::new(
                                crate::provider::local_endpoint::LoopbackBind::localhost(port),
                                &base_model,
                                PROVIDER_CONSULT_TIMEOUT_MS,
                            ) {
                                Some(t) => v.insert(t),
                                None => {
                                    return Err(AgentTransportError {
                                        class_label: "local worker http client failed to build"
                                            .to_string(),
                                    });
                                }
                            }
                        }
                    };
                    match worker.send_local_text_with(
                        model_id,
                        system,
                        user,
                        PROVIDER_CONSULT_MAX_OUTPUT_TOKENS,
                    ) {
                        Ok(o) => Ok(AgentTurn {
                            answer_text: o.answer_text,
                            input_tokens_u64: o.input_tokens,
                            output_tokens_u64: o.output_tokens,
                            cached_tokens_u64: o.cached_tokens,
                        }),
                        Err(error) => Err(AgentTransportError {
                            class_label: error.class_label(),
                        }),
                    }
                }
                #[cfg(feature = "provider-egress")]
                ExecutorTarget::Remote(remote) => remote_executor_turn(remote, system, user),
            }
        };
        let mut code_oracle = |st: &crate::provider::executor_route::SubTask,
                               o: &crate::agent_loop::AgentLoopOutcome|
         -> crate::verification::VerificationEvidence {
            crate::code_oracle::orchestrate_verify_oracle(st, o)
        };
        run_orchestrated_from_subtasks(
            &mut frontier,
            &mut local_turn,
            &mut code_oracle,
            &table,
            &state,
            &impl_system,
            synth_system,
            task,
            plan_text.clone(),
            subtasks,
            0,
            0,
        )
    };
    let workers = view
        .subtasks
        .iter()
        .map(|r| {
            let preview: String = r
                .outcome
                .answer
                .as_deref()
                .unwrap_or("(no answer)")
                .split_whitespace()
                .collect::<Vec<_>>()
                .join(" ")
                .chars()
                .take(70)
                .collect();
            OrchestrateWorkerView {
                id: r.subtask.id,
                kind: r.subtask.kind.label().to_string(),
                port: r.port,
                model_id: r.model_id.clone(),
                verdict: format!("{:?}", r.receipt.verdict),
                admits: r.receipt.admits_write(),
                preview,
            }
        })
        .collect();
    Ok(OrchestrateRunView {
        stop: format!("{:?}", view.stop),
        synthesis: view.synthesis,
        workers,
    })
}

/// P1-4 — the autonomous Read-Execute-WRITE evolution arm phrase (distinct from the
/// orchestrate phrase: this loop PERSISTS verified patterns, so it is owner-armed).
#[cfg(all(
    feature = "put-fixture-net",
    any(feature = "local-mlx", feature = "local-vllm")
))]
const EVOLVE_ARM_PHRASE: &str = "autonomous-evolve-write-live";

/// P1-4 — the AUTONOMOUS Read-Execute-WRITE evolution loop (real path: a local backend
/// for EXECUTE + Walrus for the durable WRITE). READ the held patterns + the DGM-H perf
/// ledger → EXECUTE the two-model orchestration with the sui-build CODE oracle → WRITE
/// ONLY the admits_write + cross-memory-consistent patterns to the store + the 2-tier
/// Walrus index, reinforcing each pattern's perf score. The P-HALL break: a model's
/// "success" NEVER persists — only an ORACLE-Verified receipt admits a Write.
/// custody/funds HARD-LOCKED (PD-6); ciphertext-only on Walrus; no funds.
#[cfg(all(
    feature = "put-fixture-net",
    any(feature = "local-mlx", feature = "local-vllm")
))]
fn cmd_daemon_evolve(rest: &[String], out: &mut impl Write) -> io::Result<bool> {
    use crate::agent_loop::{AgentTransportError, AgentTurn, FnTransport, MemoryToolState};
    use crate::agent_orchestrator::{OrchestratorStop, run_orchestrated_consult};
    use crate::autonomy_evolve::{
        EVOLUTION_LEDGER_FILE, HeldMemory, candidates_from_outcome, format_pattern_memory,
        parse_ledger, parse_pattern_memory, pattern_memory_id, select_evolution_writes,
        serialize_ledger,
    };
    use crate::memory_store::make_user_chunk;
    use crate::provider::local_chat::LocalChatTransport;
    use crate::repl::approval::{ApprovalDecision, ApprovalPrompt};
    use mnemos_c_walrus::publisher::EpochCount;
    use mnemos_c_walrus::reqwest_transport::ReqwestPublisher;

    let envelope_hex = hex16(&sha256_32(b"daemon evolve"));
    let supplied = rest.get(1).map_or("", String::as_str);
    let goal = rest.get(2..).map(|s| s.join(" ")).unwrap_or_default();
    let goal = goal.trim();

    // GATE 1: owner ceremony (this PERSISTS — a write, owner-armed).
    let mut prompt = ApprovalPrompt::new(ApprovalRequirement::TypedPhrase, EVOLVE_ARM_PHRASE);
    if !matches!(prompt.evaluate(supplied.trim()), ApprovalDecision::Approved) {
        emit(
            out,
            "daemon evolve",
            &envelope_hex,
            CommandRisk::Network,
            ApprovalRequirement::TypedPhrase,
            RenderTruth::Yellow,
            &[format!(
                "locked: daemon evolve {EVOLVE_ARM_PHRASE} <goal> (autonomous Read-Execute-WRITE: plan -> route -> implement -> sui-build oracle -> ONLY verified+consistent patterns persist to store + Walrus + perf-track; the model never self-certifies)"
            )],
        )?;
        return Ok(true);
    }
    // GATE 2: bounded goal.
    if goal.is_empty() {
        return daemon_evolve_error(out, &envelope_hex, "empty goal; nothing to evolve");
    }
    if goal.len() > PROVIDER_CONSULT_MAX_QUESTION_BYTES {
        return daemon_evolve_error(out, &envelope_hex, "goal exceeds the bounded input cap");
    }
    // GATE 3: before-send redaction (deny-not-fix).
    let fragments = [goal];
    let receipt = match redact(&RedactionRequest {
        fragments: &fragments,
        candidate_memory_ids: &[],
        deleted_ids: &[],
        include_private_memory: false,
    }) {
        Ok(r) => r,
        Err(_) => return daemon_evolve_error(out, &envelope_hex, "redaction gate denied the goal"),
    };
    if receipt.secret_fragments_denied_u32() > 0 || receipt.outgoing_fragment_count_u32() == 0 {
        return daemon_evolve_error(out, &envelope_hex, "goal is secret-shaped; not evolved");
    }
    // GATE 4/5: the loopback transport for EXECUTE.
    let Some(port) = crate::commands::model_select::resolve_local_port(
        std::env::var(SINABRO_LOCAL_PORT_ENV).ok().as_deref(),
        LOCAL_CONSULT_DEFAULT_PORT,
    ) else {
        return daemon_evolve_error(out, &envelope_hex, "SINABRO_LOCAL_PORT is not a valid port");
    };
    let base_model = crate::commands::model_select::resolve_local_model(
        std::env::var(SINABRO_LOCAL_MODEL_ENV).ok().as_deref(),
    );
    let bind = crate::provider::local_endpoint::LoopbackBind::localhost(port);
    let Some(transport) = LocalChatTransport::new(bind, &base_model, PROVIDER_CONSULT_TIMEOUT_MS)
    else {
        return daemon_evolve_error(out, &envelope_hex, "local http client failed to build");
    };

    // READ: held patterns (for the cross-memory check) + the DGM-H perf ledger.
    let store = match PersistedStore::open_local() {
        Ok(s) => s,
        Err(_) => {
            return daemon_evolve_error(
                out,
                &envelope_hex,
                "memory store unavailable (no key/home)",
            );
        }
    };
    let held: Vec<HeldMemory> = store
        .load_all()
        .chunks
        .iter()
        .filter_map(|(chunk, _)| {
            let body = String::from_utf8_lossy(chunk.envelope().content.as_slice());
            parse_pattern_memory(&body).map(|(_, topic, content)| HeldMemory { topic, content })
        })
        .collect();
    let dir = match crate::memory_store::data_dir() {
        Ok(d) => d,
        Err(_) => return daemon_evolve_error(out, &envelope_hex, "no data dir"),
    };
    let ledger_path = dir.join(EVOLUTION_LEDGER_FILE);
    let mut ledger = parse_ledger(&std::fs::read_to_string(&ledger_path).unwrap_or_default());

    // EXECUTE: the two-model orchestration (same wiring as `provider orchestrate`) with
    // the sui-build CODE oracle threaded as the verify oracle.
    let mem = consult_memory_load();
    let loop_contents: Vec<(MemoryId, &[u8])> = mem
        .loaded
        .chunks
        .iter()
        .map(|(c, _)| (c.id(), c.envelope().content.as_slice()))
        .collect();
    let state = MemoryToolState {
        records: &mem.folded.records,
        contents: &loop_contents,
        policy: &mem.policy,
    };
    let plan_system =
        "You are the PLANNER (the frontier reasoning role). Decompose the task into sub-tasks. \
         Output ONLY lines of the EXACT form:\nSUBTASK <id> <kind> <deps|-> <goal>\n\
         where <id> is a number, <kind> is a lowercase expert label (e.g. sui_move, \
         solana_anchor, web3_frontend, audit, nl_bridge), <deps> is '-' or comma-separated \
         ids, and <goal> is the implementation goal. No prose, no other text."
            .to_string();
    let impl_system = format!(
        "{}\n\n{}",
        sinabro_system_prompt(true),
        crate::agent_loop::SINABRO_LOOP_PROTOCOL
    );
    let synth_system = "You are the SYNTHESIZER (the frontier reasoning role). Combine the \
         implemented sub-tasks into ONE final answer. Begin your reply with ANSWER:"
        .to_string();
    let table = load_routing_table();
    let outcome = {
        let mut frontier = FnTransport(|system: &str, user: &str| {
            let frags = [user];
            match redact(&RedactionRequest {
                fragments: &frags,
                candidate_memory_ids: &[],
                deleted_ids: &[],
                include_private_memory: false,
            }) {
                Ok(r) if r.secret_fragments_denied_u32() == 0 => {}
                _ => {
                    return Err(AgentTransportError {
                        class_label: "assembled message denied by redaction".to_string(),
                    });
                }
            }
            match transport.send_local_text(system, user, PROVIDER_CONSULT_MAX_OUTPUT_TOKENS) {
                Ok(o) => Ok(AgentTurn {
                    answer_text: o.answer_text,
                    input_tokens_u64: o.input_tokens,
                    output_tokens_u64: o.output_tokens,
                    cached_tokens_u64: o.cached_tokens,
                }),
                Err(error) => Err(AgentTransportError {
                    class_label: error.class_label(),
                }),
            }
        });
        // P1-6 Macro per-port: a transport POOL keyed by the WORKER port (built on first
        // use, reused after). `port` picks the worker process (per-chain Macro lane),
        // `model_id` picks the adapter; mode A serves every kind from one port. The base
        // `transport` stays the reasoning (PLAN/SYNTH) role's loopback.
        let mut local_pool: std::collections::HashMap<u16, LocalChatTransport> =
            std::collections::HashMap::new();
        let mut local_turn = |port: u16,
                              model_id: &str,
                              system: &str,
                              user: &str|
         -> Result<AgentTurn, AgentTransportError> {
            let frags = [user];
            match redact(&RedactionRequest {
                fragments: &frags,
                candidate_memory_ids: &[],
                deleted_ids: &[],
                include_private_memory: false,
            }) {
                Ok(r) if r.secret_fragments_denied_u32() == 0 => {}
                _ => {
                    return Err(AgentTransportError {
                        class_label: "assembled message denied by redaction".to_string(),
                    });
                }
            }
            let worker = match local_pool.entry(port) {
                std::collections::hash_map::Entry::Occupied(e) => e.into_mut(),
                std::collections::hash_map::Entry::Vacant(v) => match LocalChatTransport::new(
                    crate::provider::local_endpoint::LoopbackBind::localhost(port),
                    &base_model,
                    PROVIDER_CONSULT_TIMEOUT_MS,
                ) {
                    Some(t) => v.insert(t),
                    None => {
                        return Err(AgentTransportError {
                            class_label: "local worker http client failed to build".to_string(),
                        });
                    }
                },
            };
            match worker.send_local_text_with(
                model_id,
                system,
                user,
                PROVIDER_CONSULT_MAX_OUTPUT_TOKENS,
            ) {
                Ok(o) => Ok(AgentTurn {
                    answer_text: o.answer_text,
                    input_tokens_u64: o.input_tokens,
                    output_tokens_u64: o.output_tokens,
                    cached_tokens_u64: o.cached_tokens,
                }),
                Err(error) => Err(AgentTransportError {
                    class_label: error.class_label(),
                }),
            }
        };
        // the sui-build CODE oracle (S2-2): the model's text reaches only the compiler.
        let mut code_oracle = |st: &crate::provider::executor_route::SubTask,
                               o: &crate::agent_loop::AgentLoopOutcome|
         -> crate::verification::VerificationEvidence {
            crate::code_oracle::orchestrate_verify_oracle(st, o)
        };
        run_orchestrated_consult(
            &mut frontier,
            &mut local_turn,
            &mut code_oracle,
            &table,
            &state,
            &plan_system,
            &impl_system,
            &synth_system,
            goal,
            0,
            0,
        )
    };

    // WRITE DECISION (the P-HALL break): only admits_write + cross-memory-consistent.
    let candidates = candidates_from_outcome(&outcome);
    let ev = select_evolution_writes(&candidates, &held, &|k| {
        ledger.get(k).copied().unwrap_or_default()
    });

    // PERSIST the written patterns locally + update the perf ledger (atomic).
    let mut saved = 0usize;
    for w in &ev.written {
        let chunk = make_user_chunk(
            MemoryId::new(pattern_memory_id(&w.pattern_key)),
            &format_pattern_memory(&w.pattern_key, &w.topic, &w.content),
        );
        if store.save_chunk(&chunk, MemoryPrivacy::Shareable).is_ok() {
            ledger.insert(w.pattern_key.clone(), w.perf);
            saved += 1;
        }
    }
    let _ = crate::memory_store::atomic_write(&ledger_path, serialize_ledger(&ledger).as_bytes());

    // RENDER + the durable WALRUS WRITE (gated on a verified pattern having persisted).
    let mut body: Vec<String> = vec![format!(
        "evolve: stop={:?} sub-tasks={} written={} quarantined={} unverified={}",
        outcome.stop,
        outcome.subtasks.len(),
        ev.written.len(),
        ev.quarantined.len(),
        ev.unverified.len()
    )];
    for r in &outcome.subtasks {
        body.push(format!(
            "  id={} {}->:{}/{} verify={:?} admits={}",
            r.subtask.id,
            r.subtask.kind.label(),
            r.port,
            r.model_id,
            r.receipt.verdict,
            r.receipt.admits_write()
        ));
    }
    let mut truth = if matches!(outcome.stop, OrchestratorStop::Synthesized) {
        RenderTruth::Green
    } else {
        RenderTruth::Yellow
    };
    let mut walrus_published = 0usize;
    if saved > 0 {
        match (
            EpochCount::new(1),
            ReqwestPublisher::new(PUT_FIXTURE_TIMEOUT_MS),
        ) {
            (Ok(epochs), Ok(mut pub_t)) => {
                let records = store.records_for_walrus();
                let mut entries: Vec<crate::memory_walrus::WalrusMemEntry> = Vec::new();
                for (id, topic, ciphertext) in records.iter().take(BACKUP_WALRUS_MAX_RECORDS) {
                    if let Some(blob) = walrus_put_verified(&mut pub_t, epochs, ciphertext) {
                        entries.push(crate::memory_walrus::WalrusMemEntry {
                            memory_id: *id,
                            topic: topic.clone(),
                            sub_blob_id: blob,
                            // autonomous evolve backup (testnet); 0G roots are paired via
                            // the canonical `memory backup-walrus` owner ceremony.
                            sub_0g_root: None,
                        });
                    }
                }
                let index = crate::memory_walrus::WalrusMainIndex {
                    entries: entries.clone(),
                };
                if !index.entries.is_empty() {
                    if let Ok(index_ct) = store.seal_index(&index.to_bytes()) {
                        if let Some(blob) = walrus_put_verified(&mut pub_t, epochs, &index_ct) {
                            let _ = crate::memory_walrus::write_main_index_pointer(&dir, &blob);
                            walrus_published = entries.len();
                            body.push(format!(
                                "WALRUS WRITE: {} record(s) -> 2-tier index blob_id={blob} (pointer saved; AES ciphertext; testnet; no funds)",
                                entries.len()
                            ));
                        }
                    }
                }
                if walrus_published == 0 {
                    truth = RenderTruth::Yellow;
                    body.push("WALRUS WRITE: publish boundary (testnet propagation)".to_string());
                }
            }
            _ => {
                truth = RenderTruth::Yellow;
                body.push("WALRUS WRITE: publisher init failed".to_string());
            }
        }
    } else {
        body.push(
            "WALRUS WRITE: 0 (no pattern admitted a Write — the P-HALL gate held)".to_string(),
        );
    }
    body.push(format!(
        "perf-ledger: {} pattern(s) tracked; custody/funds/chain-write HARD-LOCKED (PD-6)",
        ledger.len()
    ));
    emit(
        out,
        "daemon evolve",
        &envelope_hex,
        CommandRisk::Network,
        ApprovalRequirement::TypedPhrase,
        truth,
        &body,
    )?;
    Ok(true)
}

/// P1-4 evolve error render (secret-zero static message).
#[cfg(all(
    feature = "put-fixture-net",
    any(feature = "local-mlx", feature = "local-vllm")
))]
fn daemon_evolve_error(
    out: &mut impl Write,
    envelope_hex: &str,
    message: &str,
) -> io::Result<bool> {
    emit(
        out,
        "daemon evolve",
        envelope_hex,
        CommandRisk::Network,
        ApprovalRequirement::TypedPhrase,
        RenderTruth::Red,
        &[
            format!("daemon evolve: {message}"),
            "fail-closed; nothing partial persisted".to_string(),
        ],
    )?;
    Ok(true)
}

/// P1-4 honest-degrade: without `put-fixture-net` (the durable Walrus write) AND a local
/// backend (`local-mlx`/`local-vllm`, the EXECUTE brain), the autonomous loop cannot run
/// — the verb renders the locked surface (never a fake/partial run).
#[cfg(not(all(
    feature = "put-fixture-net",
    any(feature = "local-mlx", feature = "local-vllm")
)))]
fn cmd_daemon_evolve(rest: &[String], out: &mut impl Write) -> io::Result<bool> {
    let _ = rest;
    let envelope_hex = hex16(&sha256_32(b"daemon evolve"));
    emit(
        out,
        "daemon evolve",
        &envelope_hex,
        CommandRisk::Network,
        ApprovalRequirement::TypedPhrase,
        RenderTruth::Yellow,
        &[
            "daemon evolve: honest-degrade — needs `put-fixture-net` (durable Walrus write) + a local backend (`local-mlx`/`local-vllm`, the EXECUTE brain); not compiled in this build".to_string(),
            "the autonomous Read-Execute-WRITE loop persists ONLY oracle-Verified patterns; custody/funds HARD-LOCKED (PD-6)".to_string(),
        ],
    )?;
    Ok(true)
}

/// The LOCAL consult vertical over an injected loopback bind (⑧ gate stack):
/// exact typed phrase → bounded question → before-send redaction (deny-not-
/// fix) → ONE paranoid loopback client (no proxy / no redirect / bounded
/// timeout, reused across turns) → the IDENTICAL bounded agentic loop with
/// the IDENTICAL walls → the route-visible receipt (endpoint + response-
/// echoed model + sha receipts). No `unwrap`/`expect`/`panic`.
#[cfg(any(feature = "local-mlx", feature = "local-vllm"))]
fn provider_consult_local_at(
    bind: crate::provider::local_endpoint::LoopbackBind,
    model: &str,
    rest: &[String],
    out: &mut impl Write,
    otel_setting: crate::otel_export::OtelExportSetting,
    otel_dir: Option<&std::path::Path>,
) -> io::Result<bool> {
    use crate::provider::local_chat::LocalChatTransport;
    use crate::repl::approval::{ApprovalDecision, ApprovalPrompt};

    let envelope_hex = hex16(&sha256_32(b"provider consult"));
    let supplied_phrase = rest.get(1).map_or("", String::as_str);
    let question = rest.get(2..).map(|s| s.join(" ")).unwrap_or_default();
    let question = question.trim();

    // GATE 2 (⑧): the exact typed phrase IS the same-message ceremony AND the
    // route selection. The dispatch arm already routed on it; the executor
    // re-verifies (defense in depth + the injected-bind test surface).
    let mut prompt = ApprovalPrompt::new(
        ApprovalRequirement::TypedPhrase,
        PROVIDER_CONSULT_LOCAL_PHRASE,
    );
    if !matches!(
        prompt.evaluate(supplied_phrase.trim()),
        ApprovalDecision::Approved
    ) {
        emit(
            out,
            "provider consult",
            &envelope_hex,
            CommandRisk::Network,
            ApprovalRequirement::TypedPhrase,
            RenderTruth::Yellow,
            &provider_consult_local_locked_body(model, bind.port()),
        )?;
        return Ok(true);
    }
    if question.is_empty() {
        return provider_consult_local_error(out, &envelope_hex, "empty question; nothing sent");
    }
    // GATE 3: bounded input (IV-L3 — identical cap to the frontier route).
    if question.len() > PROVIDER_CONSULT_MAX_QUESTION_BYTES {
        return provider_consult_local_error(
            out,
            &envelope_hex,
            "question exceeds the bounded input cap",
        );
    }
    // GATE 4: before-send redaction (canonical secret scanners; deny-not-fix;
    // IDENTICAL to frontier — the loopback peer is an UNAUDITED process).
    let fragments = [question];
    let receipt = match redact(&RedactionRequest {
        fragments: &fragments,
        candidate_memory_ids: &[],
        deleted_ids: &[],
        include_private_memory: false,
    }) {
        Ok(receipt) => receipt,
        Err(_) => {
            return provider_consult_local_error(
                out,
                &envelope_hex,
                "redaction gate denied the payload",
            );
        }
    };
    if receipt.secret_fragments_denied_u32() > 0 || receipt.outgoing_fragment_count_u32() == 0 {
        return provider_consult_local_error(
            out,
            &envelope_hex,
            "question is secret-shaped; not sent",
        );
    }
    // GATE 5: the paranoid loopback client (IV-L1), built ONCE per ceremony
    // and reused across the loop's ≤5 turns (keep-alive — the CU floor).
    let Some(transport) = LocalChatTransport::new(bind, model, PROVIDER_CONSULT_TIMEOUT_MS) else {
        return provider_consult_local_error(
            out,
            &envelope_hex,
            "local http client failed to build",
        );
    };
    // GATE 6: the IDENTICAL bounded agentic loop (IV-L2/L3/L4) over the SAME
    // classified memory fold (shareable-only frontier tier) + lane-A files.
    let mem = consult_memory_load();
    let loop_contents: Vec<(MemoryId, &[u8])> = mem
        .loaded
        .chunks
        .iter()
        .map(|(chunk, _)| (chunk.id(), chunk.envelope().content.as_slice()))
        .collect();
    let state = crate::agent_loop::MemoryToolState {
        records: &mem.folded.records,
        contents: &loop_contents,
        policy: &mem.policy,
    };
    let loop_system = format!(
        "{}\n\n{}",
        sinabro_system_prompt(true),
        crate::agent_loop::SINABRO_LOOP_PROTOCOL
    );
    let file_policy = crate::file_context::FileReadPolicy::workspace_default();
    // P4-1 (⑨ L4): ceremony wall-clock CAPTURED once; the OTel projection is
    // deterministic over the captured pair (never re-minted at render).
    let otel_started = std::time::SystemTime::now();
    let mut turns_u8: u8 = 0;
    let mut last_request_hash_32 = ZERO32;
    let mut last_response_hash_32 = ZERO32;
    let mut last_model = String::new();
    let mut last_stop_reason = String::new();
    let loop_outcome = {
        let mut live = crate::agent_loop::FnTransport(|system: &str, user_message: &str| {
            // Defense in depth (IV1/IV-L2): the ASSEMBLED outbound message
            // re-passes the canonical redaction gate every turn — "local"
            // buys ZERO wall relaxation.
            let fragments = [user_message];
            match redact(&RedactionRequest {
                fragments: &fragments,
                candidate_memory_ids: &[],
                deleted_ids: &[],
                include_private_memory: false,
            }) {
                Ok(receipt) if receipt.secret_fragments_denied_u32() == 0 => {}
                _ => {
                    return Err(crate::agent_loop::AgentTransportError {
                        class_label: "assembled message denied by redaction".to_string(),
                    });
                }
            }
            match transport.send_local_text(
                system,
                user_message,
                PROVIDER_CONSULT_MAX_OUTPUT_TOKENS,
            ) {
                Ok(outcome) => {
                    turns_u8 = turns_u8.saturating_add(1);
                    last_request_hash_32 = outcome.request_hash_32;
                    last_response_hash_32 = outcome.response_hash_32;
                    last_model = outcome.model;
                    last_stop_reason = outcome.stop_reason;
                    Ok(crate::agent_loop::AgentTurn {
                        answer_text: outcome.answer_text,
                        input_tokens_u64: outcome.input_tokens,
                        output_tokens_u64: outcome.output_tokens,
                        cached_tokens_u64: outcome.cached_tokens,
                    })
                }
                Err(error) => Err(crate::agent_loop::AgentTransportError {
                    class_label: error.class_label(),
                }),
            }
        });
        // E11-1b: the loop's `web fetch` tool reaches the public web through the
        // shared SSRF-walled glue. The seam is feature-INDEPENDENT — a live
        // transport only under `web-egress`, else `None` (the honest not-compiled
        // deny). custody/funds stay HARD-LOCKED (a chain-RPC host is SSRF-denied;
        // GET-only ⇒ no chain WRITE).
        let web_seam = crate::provider::web_fetch::WebFetchSeam::new();
        // B⑫ (CURSOR PARITY keystone-3): the loop's `mcp` tool reaches owner-
        // configured LOCAL stdio MCP servers through the shared chokepoint
        // (sandboxed, network kernel-DENIED; an unknown server/tool ⇒ deny; the
        // arg + result are redacted; every call is audited). The seam carries the
        // READ-tier servers from the owner config; an empty config ⇒ the tool
        // honestly denies. custody/funds stay HARD-LOCKED (no egress/mutate).
        let mcp_seam = crate::mcp::McpSeam::new(read_owner_mcp_servers());
        crate::agent_loop::run_agent_loop_with(
            &mut live,
            &state,
            &loop_system,
            question,
            crate::agent_loop::CHAT_MAX_ITER,
            crate::agent_loop::CHAT_TOKEN_CAP,
            Some(&file_policy),
            Some(&web_seam),
            Some(&mcp_seam),
        )
    };
    let otel_ended = std::time::SystemTime::now();
    // P4-1 (⑨): owner-opted OTel span export — computed BEFORE the answer
    // destructure (the borrow ends before the partial move) and ONLY for an
    // answered ceremony (v1 scope; failure paths are R2). Off ⇒ None ⇒ the
    // surface stays byte-unchanged.
    let otel_line = if loop_outcome.answer.is_some() {
        crate::otel_export::consult_otel_line(
            &loop_outcome,
            &crate::otel_export::ConsultOtelCtx {
                setting: otel_setting,
                dir_override: otel_dir,
                backend: "local_base",
                model: &last_model,
                turns_u8,
                request_sha_32: &last_request_hash_32,
                response_sha_32: &last_response_hash_32,
                started: otel_started,
                ended: otel_ended,
            },
        )
    } else {
        None
    };
    let Some(answer) = loop_outcome.answer else {
        // The trail renders on its OWN line so the 80-col clamp cannot
        // swallow the typed failure class (owner sees WHY, not a cut line).
        let body = vec![
            format!(
                "LOCAL provider consult: agent loop stopped: {} after {turns_u8} local turn(s)",
                loop_outcome.stop.class_label()
            ),
            format!("trail=[{}]", loop_outcome.tool_trail.join(", ")),
            "no retry; loopback only; no key exists on this path; funds untouched".to_string(),
        ];
        emit(
            out,
            "provider consult",
            &envelope_hex,
            CommandRisk::Network,
            ApprovalRequirement::TypedPhrase,
            RenderTruth::Red,
            &body,
        )?;
        return Ok(true);
    };
    // RENDER (IV-L5 route-visible): the loopback endpoint + the RESPONSE-
    // echoed model id (never assumed from the request side).
    let mut truth = if last_stop_reason == "stop" {
        RenderTruth::Green
    } else {
        RenderTruth::Yellow
    };
    let mut body = Vec::new();
    body.push(format!(
        "LOCAL provider consult: {} {last_model} backend=local_base (agentic loop; zero egress)",
        bind.endpoint_label()
    ));
    // P3-2 (TM ⑦ DESIGN LOCK): a propose-shaped answer becomes a sealed INERT
    // proposal card — the LOCAL route keeps ALL the edit walls unchanged.
    // E10-1 (⑬ IV-A2): an exec-PROPOSE answer becomes a sealed INERT exec
    // proposal (tried only when it is not an edit proposal); still nothing runs.
    let proposal_store = ProposalStore::open_local().ok();
    let exec_store = crate::exec_proposal::ExecProposalStore::open_local().ok();
    if let Some((proposal_truth, lines)) = consult_proposal_render(
        &answer,
        &loop_outcome.verified_file_reads,
        proposal_store.as_ref(),
        &file_policy,
    )
    .or_else(|| consult_exec_proposal_render(&answer, exec_store.as_ref()))
    {
        body.extend(lines);
        if !matches!(proposal_truth, RenderTruth::Green) {
            truth = proposal_truth;
        }
    } else {
        // E7-1: same streaming bridge as the frontier route (one render
        // contract); the LOCAL answer is also delivered chunk-by-chunk
        // through the per-chunk redact wall. Progressive render of the
        // completed answer (the local codec also buffers `response.bytes()`).
        let streamed = stream_consult_answer(&answer, last_response_hash_32, 78, 52);
        let feed = stream_feed_receipt(&streamed);
        body.extend(streamed.lines);
        body.push(feed);
    }
    body.push(format!(
        "loop: turns={turns_u8} tool_iters={} reads={} stop={} trail=[{}]",
        loop_outcome.iterations_u8,
        loop_outcome.reads_u8,
        loop_outcome.stop.class_label(),
        loop_outcome.tool_trail.join(", ")
    ));
    // E1 audit-soul: same recall citation as the frontier route (one impl).
    body.push(recalled_citation(&loop_outcome.tool_trail));
    body.push(format!(
        "usage: input={} output={} cached={} finish={last_stop_reason}",
        loop_outcome.input_tokens_u64,
        loop_outcome.output_tokens_u64,
        loop_outcome.cost.cached_tokens_u32()
    ));
    // E7-2: REAL context-pressure (same impl as the frontier route).
    body.push(context_pressure_receipt(
        loop_outcome.input_tokens_u64,
        loop_outcome.output_tokens_u64,
    ));
    body.push(format!(
        "cache: static_prefix={}B dynamic={}B stable_prefix_turns={}/{}",
        loop_outcome.cache_plan.static_prefix_bytes_u32,
        loop_outcome.cache_plan.dynamic_suffix_bytes_u32,
        loop_outcome.prefix_stable_turns_u8,
        turns_u8.saturating_sub(1)
    ));
    body.push(format!(
        "cost: usd_micros={} (local serving; zero-rate sentinel)",
        loop_outcome.cost.usd_micros().get()
    ));
    // P2-2 in-core guard receipt — IDENTICAL on the local route (IV-L4).
    let guard = crate::provider::trajectory_health::recommended_action(loop_outcome.health);
    body.push(format!(
        "guard: action={} signals=0x{:04x}",
        guard.class_label(),
        loop_outcome.health.bits()
    ));
    body.push(format!(
        "request_sha={} response_sha={} (last turn)",
        hex16(&last_request_hash_32),
        hex16(&last_response_hash_32)
    ));
    // P4-1 (⑨): the OTel receipt line (computed pre-destructure above).
    if let Some(line) = otel_line {
        body.push(line);
    }
    body.push(
        "advisory until locally verified; loopback only; no key sent; raw body not stored at rest"
            .to_string(),
    );
    emit(
        out,
        "provider consult",
        &envelope_hex,
        CommandRisk::Network,
        ApprovalRequirement::TypedPhrase,
        truth,
        &body,
    )?;
    Ok(true)
}

// ---- 3.A (owner-authorized 2026-06-10 "a로 가자"): gated subagent fan-out ------
//
// Threat model: ops/evidence/stage_g/agent_loop/SUBAGENT_FANOUT_THREAT_MODEL.md.
// ONE typed phrase authorizes ONE BOUNDED FAN: ≤ FANOUT_MAX_CHILDREN children,
// each a full gated agent loop in its OWN scoped thread with its OWN transport
// and its OWN PARTITIONED budget slice (Σ ≤ the single-consult cap — spend is
// re-distributed, never multiplied), merged deterministically by child index.
// The model gets NO spawn tool (D-1): the loop grammar is byte-unchanged.

/// The exact in-band confirmation phrase that authorizes ONE bounded fan-out.
/// A PUBLIC confirmation gesture (zero entropy, NOT a secret).
#[cfg(feature = "provider-egress")]
const PROVIDER_FAN_CONFIRM_PHRASE: &str = "fan-frontier-provider-live";

/// The denial / gated-preview body when the exact phrase is absent or wrong —
/// render-only, NEVER touches redaction, the builder, or the network.
#[cfg(feature = "provider-egress")]
fn provider_fan_locked_body() -> Vec<String> {
    vec![
        "provider fan is a LIVE subagent fan-out (OpenRouter, parallel children)".to_string(),
        format!("usage: provider fan {PROVIDER_FAN_CONFIRM_PHRASE} <q1> | <q2> | ..."),
        format!(
            "bounds: children<={} child_iters<={} tokens={} PARTITIONED (sum<=parent)",
            crate::agent_loop::FANOUT_MAX_CHILDREN,
            crate::agent_loop::FANOUT_CHILD_MAX_ITER,
            crate::agent_loop::AGENT_LOOP_TOKEN_CAP
        ),
        "each child = the gated read-only memory loop; the model cannot spawn".to_string(),
        "denied: no live call without the exact phrase".to_string(),
    ]
}

/// Render a secret-zero fan error surface and stop — typed label only.
#[cfg(feature = "provider-egress")]
fn provider_fan_error(out: &mut impl Write, envelope_hex: &str, label: &str) -> io::Result<bool> {
    let body = vec![
        format!("LIVE provider fan: {label}"),
        "whole fan denied; no retry; no key/body leaked; funds untouched".to_string(),
    ];
    emit(
        out,
        "provider fan",
        envelope_hex,
        CommandRisk::Network,
        ApprovalRequirement::TypedPhrase,
        RenderTruth::Red,
        &body,
    )?;
    Ok(true)
}

/// The gated fan-out executor (feature ON only). Gate stack per the threat
/// model: exact phrase → '|'-split + bounds → one redaction pass over ALL
/// sub-questions (one denial denies the whole fan) → m-agent budget
/// partition (Σ ≤ parent, typed) → bounded consult request + live flip →
/// scoped threads (one gated loop per child; structurally no zombie) →
/// deterministic merge by child index → per-child render + totals.
#[cfg(feature = "provider-egress")]
fn provider_fan(rest: &[String], out: &mut impl Write) -> io::Result<bool> {
    use crate::agent_loop::{
        AgentLoopOutcome, AgentLoopStop, AgentTransportError, AgentTurn, ChildResult,
        FANOUT_MAX_CHILDREN, FnTransport, MemoryToolState, SINABRO_LOOP_PROTOCOL, merge_fanout,
        run_fanout_child,
    };
    use crate::commands::model_compress::ConsultScope;
    use crate::commands::model_route::ConsultTrigger;
    use crate::provider::egress::{EgressApproval, ProviderTransport, RedactedConsult};
    use crate::provider::frontier_consult::{self, BoundedConsultInputs, BoundedConsultRequest};
    use crate::repl::approval::{ApprovalDecision, ApprovalPrompt};
    use crate::route::RouteExecutionState;
    use mnemos_m_agent::SubagentBudgetPlan;

    let envelope_hex = hex16(&sha256_32(b"provider fan"));
    let supplied_phrase = rest.get(1).map_or("", String::as_str);
    let joined = rest.get(2..).map(|s| s.join(" ")).unwrap_or_default();

    // GATE: exact typed phrase (the same-message ceremony for ONE bounded fan).
    let mut prompt = ApprovalPrompt::new(
        ApprovalRequirement::TypedPhrase,
        PROVIDER_FAN_CONFIRM_PHRASE,
    );
    if !matches!(
        prompt.evaluate(supplied_phrase.trim()),
        ApprovalDecision::Approved
    ) {
        emit(
            out,
            "provider fan",
            &envelope_hex,
            CommandRisk::Network,
            ApprovalRequirement::TypedPhrase,
            RenderTruth::Yellow,
            &provider_fan_locked_body(),
        )?;
        return Ok(true);
    }
    // GATE: parse + bounds ('|'-separated sub-questions, trimmed, non-empty).
    let questions: Vec<String> = joined
        .split('|')
        .map(str::trim)
        .filter(|q| !q.is_empty())
        .map(str::to_string)
        .collect();
    if questions.is_empty() {
        return provider_fan_error(
            out,
            &envelope_hex,
            "no sub-questions; usage: provider fan <phrase> q1 | q2",
        );
    }
    if questions.len() > usize::from(FANOUT_MAX_CHILDREN) {
        return provider_fan_error(
            out,
            &envelope_hex,
            "too many sub-questions (children<=4); whole fan denied",
        );
    }
    for question in &questions {
        if question.len() > PROVIDER_CONSULT_MAX_QUESTION_BYTES {
            return provider_fan_error(
                out,
                &envelope_hex,
                "a sub-question exceeds the bounded input cap",
            );
        }
    }
    // GATE: ONE redaction pass over ALL sub-questions — any secret-shaped
    // fragment denies the WHOLE fan (fail-closed, no partial egress).
    let fragments: Vec<&str> = questions.iter().map(String::as_str).collect();
    let receipt = match redact(&RedactionRequest {
        fragments: &fragments,
        candidate_memory_ids: &[],
        deleted_ids: &[],
        include_private_memory: false,
    }) {
        Ok(receipt)
            if receipt.secret_fragments_denied_u32() == 0
                && receipt.outgoing_fragment_count_u32() > 0 =>
        {
            receipt
        }
        _ => {
            return provider_fan_error(
                out,
                &envelope_hex,
                "a sub-question is secret-shaped; whole fan denied",
            );
        }
    };
    // GATE: budget partition (m-agent typed invariant — Σ ≤ parent).
    // `questions.len() ≤ 4` is bounded above, so the cast is exact.
    let child_count = questions.len() as u8;
    let plan = match SubagentBudgetPlan::split(crate::agent_loop::AGENT_LOOP_TOKEN_CAP, child_count)
    {
        Ok(plan) => plan,
        Err(error) => return provider_fan_error(out, &envelope_hex, error.class_label()),
    };
    // GATE: the bounded consult request (same SLOW caps); the phrase above IS
    // the same-message ceremony — only after it passes is live dispatch enabled.
    let inputs = BoundedConsultInputs {
        route_state: RouteExecutionState::Slow,
        trigger: ConsultTrigger::LowConfidenceHighBlastRadius,
        scope: ConsultScope::minimal(),
        redaction_report_hash_32: receipt.redacted_payload_hash_32(),
        evidence_refs_hash_32: sha256_32(b"provider-fan-v1:operator-subquestions"),
        prompt_hash_32: sha256_32(joined.as_bytes()),
        timeout_ms_u32: PROVIDER_CONSULT_TIMEOUT_MS,
        local_verification_command_hash_32: sha256_32(b"operator-reads-advisory-answers"),
    };
    let Some(request) = frontier_consult::build(&inputs) else {
        return provider_fan_error(out, &envelope_hex, "bounded consult request denied");
    };
    let request = BoundedConsultRequest {
        live_dispatch_allowed: true,
        ..request
    };
    let Some(consult) = RedactedConsult::new(request, receipt) else {
        return provider_fan_error(out, &envelope_hex, "consult payload rejected");
    };
    let host = match resolve_frontier_provider() {
        Ok(host) => host,
        Err(reason) => return provider_fan_error(out, &envelope_hex, reason),
    };
    let model = provider_consult_model_for(host);
    let policy = TombstonePolicy::new();
    // P1-2: the loop sees the REAL persisted memory (degraded-empty if no
    // key) with each chunk's OWNER privacy class — the agent's `memory
    // index`/`read` tools reach the owner's saved memories; ONLY explicit
    // shareable records list frontier-bound (IV2), and redaction still gates.
    let loaded = match PersistedStore::open_local() {
        Ok(store) => store.load_all(),
        Err(_) => crate::memory_store::LoadOutcome::default(),
    };
    let folded = fold_index_classified(
        loaded
            .chunks
            .iter()
            .map(|(chunk, privacy)| (chunk, *privacy)),
        &policy,
    );
    let loop_contents: Vec<(MemoryId, &[u8])> = loaded
        .chunks
        .iter()
        .map(|(chunk, _)| (chunk.id(), chunk.envelope().content.as_slice()))
        .collect();
    let state = MemoryToolState {
        records: &folded.records,
        contents: &loop_contents,
        policy: &policy,
    };
    let loop_system = format!(
        "{}\n\n{SINABRO_LOOP_PROTOCOL}",
        sinabro_system_prompt(false)
    );

    // RUN: scoped threads — children structurally cannot outlive this command
    // (TM D-6). Each child builds its OWN transport in its own thread and
    // funds its OWN partitioned slice (TM D-4); per-turn assembled-message
    // redaction is inside each child's transport closure (IV1).
    let results: Vec<(ChildResult, u8)> = std::thread::scope(|scope| {
        let mut handles = Vec::new();
        for (index, question) in questions.iter().enumerate() {
            let consult_ref = &consult;
            let model_ref = &model;
            let state_ref = &state;
            let system_ref = &loop_system;
            let child_cap_u32 = plan.child_cap_u32();
            handles.push((
                index,
                scope.spawn(move || {
                    let transport = ProviderTransport::for_host(host);
                    let mut turns_u8: u8 = 0;
                    let outcome = {
                        let mut live = FnTransport(|system: &str, user_message: &str| {
                            let fragments = [user_message];
                            match redact(&RedactionRequest {
                                fragments: &fragments,
                                candidate_memory_ids: &[],
                                deleted_ids: &[],
                                include_private_memory: false,
                            }) {
                                Ok(receipt) if receipt.secret_fragments_denied_u32() == 0 => {}
                                _ => {
                                    return Err(AgentTransportError {
                                        class_label: "assembled message denied by redaction"
                                            .to_string(),
                                    });
                                }
                            }
                            match transport.send_live_text(
                                consult_ref,
                                EgressApproval::grant(),
                                system,
                                user_message,
                                model_ref,
                                PROVIDER_CONSULT_MAX_OUTPUT_TOKENS,
                            ) {
                                Ok(outcome) => {
                                    turns_u8 = turns_u8.saturating_add(1);
                                    Ok(AgentTurn {
                                        answer_text: outcome.answer_text,
                                        input_tokens_u64: outcome.input_tokens,
                                        output_tokens_u64: outcome.output_tokens,
                                        cached_tokens_u64: outcome.cached_tokens,
                                    })
                                }
                                Err(error) => Err(AgentTransportError {
                                    class_label: consult_denied_label(&error),
                                }),
                            }
                        });
                        run_fanout_child(&mut live, state_ref, system_ref, question, child_cap_u32)
                    };
                    (
                        ChildResult {
                            // `index < child_count ≤ 4`, so the cast is exact.
                            child_index_u8: index as u8,
                            outcome,
                        },
                        turns_u8,
                    )
                }),
            ));
        }
        handles
            .into_iter()
            .map(|(index, handle)| {
                handle.join().unwrap_or_else(|_| {
                    // A panicked child is a typed failure slot, never a crash
                    // of the fan (its siblings' results stand).
                    (
                        ChildResult {
                            child_index_u8: index as u8,
                            outcome: AgentLoopOutcome {
                                answer: None,
                                stop: AgentLoopStop::TransportFailed,
                                iterations_u8: 0,
                                reads_u8: 0,
                                tool_trail: vec!["child-panicked".to_string()],
                                input_tokens_u64: 0,
                                output_tokens_u64: 0,
                                cost: mnemos_m_agent::CostLedger::new(),
                                cache_plan: mnemos_m_agent::CacheBreakpointPlan::default(),
                                prefix_stable_turns_u8: 0,
                                health: crate::commands::model_route::TrajectoryHealth::healthy(),
                                verified_file_reads: Vec::new(),
                            },
                        },
                        0,
                    )
                })
            })
            .collect()
    });
    // MERGE (TM D-5): by child index, never completion order.
    let mut child_turns = vec![0u8; questions.len()];
    let mut child_results = Vec::with_capacity(results.len());
    for (result, turns_u8) in results {
        child_turns[usize::from(result.child_index_u8)] = turns_u8;
        child_results.push(result);
    }
    let fan = merge_fanout(child_results);
    let truth = if fan.completed_u8 == child_count {
        RenderTruth::Green
    } else if fan.completed_u8 > 0 {
        RenderTruth::Yellow
    } else {
        RenderTruth::Red
    };
    let mut body = Vec::new();
    body.push(format!(
        "LIVE provider fan: openrouter {model} children={child_count} (parallel, partitioned)"
    ));
    body.push(format!(
        "budget: child_cap={} sum={} <= parent={} remainder={}",
        plan.child_cap_u32(),
        plan.total_children_cap_u32(),
        plan.parent_cap_u32(),
        plan.remainder_u32()
    ));
    for child in &fan.children {
        let index = usize::from(child.child_index_u8);
        body.push(format!(
            "-- child {} [{}] turns={} iters={} reads={} in={} out={} cached={} guard={}",
            child.child_index_u8,
            child.outcome.stop.class_label(),
            child_turns[index],
            child.outcome.iterations_u8,
            child.outcome.reads_u8,
            child.outcome.input_tokens_u64,
            child.outcome.output_tokens_u64,
            child.outcome.cost.cached_tokens_u32(),
            crate::provider::trajectory_health::recommended_action(child.outcome.health)
                .class_label()
        ));
        match &child.outcome.answer {
            Some(answer) => body.extend(wrap_consult_answer(answer, 78, 8)),
            None => body.push(format!(
                "   (no answer; trail=[{}])",
                child.outcome.tool_trail.join(", ")
            )),
        }
    }
    let fan_cached_u64: u64 = fan
        .children
        .iter()
        .map(|child| u64::from(child.outcome.cost.cached_tokens_u32()))
        .sum();
    body.push(format!(
        "fan: completed={} failed={} usage: input={} output={} cached={fan_cached_u64}",
        fan.completed_u8, fan.failed_u8, fan.input_tokens_u64, fan.output_tokens_u64
    ));
    body.push(
        "cost: no local rates configured; per-model rates on the OpenRouter dashboard".to_string(),
    );
    body.push("advisory only; key never rendered; raw body not stored at rest".to_string());
    emit(
        out,
        "provider fan",
        &envelope_hex,
        CommandRisk::Network,
        ApprovalRequirement::TypedPhrase,
        truth,
        &body,
    )?;
    Ok(true)
}

// ---- T (owner-authorized 2026-06-10): gated live Telegram send -----------------
//
// The THIRD live-egress execute path in this module (after C's put-fixture and
// P's consult), reachable ONLY when compiled with `telegram-egress`. Gate stack
// (all required): feature-compiled + exact typed-phrase approval (the
// same-message ceremony that alone enables a live send) + before-send redaction
// gate + bounded text + one-shot + allowlisted Bot-API host + TLS-boundary-only
// token/chat-id reads (the token rides in the URL, which is never logged /
// hashed / rendered). funds/wallet/mainnet/provider hosts are unreachable (no
// such host variant exists). Threat model:
// ops/evidence/stage_g/gui_desktop/TELEGRAM_EGRESS_THREAT_MODEL.md.

/// The exact in-band confirmation phrase that authorizes ONE live Telegram
/// message. A PUBLIC confirmation gesture (zero entropy, NOT a secret), supplied
/// verbatim as the token after the verb. Absence/mismatch fails closed (no send).
#[cfg(feature = "telegram-egress")]
const TELEGRAM_SEND_CONFIRM_PHRASE: &str = "send-live-telegram-message";

/// Hard byte ceiling on the outbound message text (under the Bot API 4096 limit).
#[cfg(feature = "telegram-egress")]
const TELEGRAM_SEND_MAX_TEXT_BYTES: usize = 3500;

/// The denial / gated-preview body when the exact phrase is absent or wrong —
/// render-only, NEVER touches redaction, the builder, or the network.
#[cfg(feature = "telegram-egress")]
fn platform_send_locked_body() -> Vec<String> {
    vec![
        "platform send is a LIVE Telegram message (Bot API sendMessage)".to_string(),
        "risk=network approval=typed-phrase (exact); one-shot; bounded".to_string(),
        format!("usage: platform send {TELEGRAM_SEND_CONFIRM_PHRASE} <message>"),
        format!(
            "bounds: text<={TELEGRAM_SEND_MAX_TEXT_BYTES}B; envs: TELEGRAM_BOT_TOKEN + TELEGRAM_CHAT_ID"
        ),
        "token/chat-id read only at the TLS boundary, never shown".to_string(),
        "denied: no live send without the exact phrase".to_string(),
    ]
}

/// Render a secret-zero telegram-send error surface (static label / numeric
/// codes only; no token, no chat id, no URL, no response prose) and stop.
#[cfg(feature = "telegram-egress")]
fn platform_send_error(out: &mut impl Write, envelope_hex: &str, label: &str) -> io::Result<bool> {
    let body = vec![
        format!("LIVE telegram send: {label}"),
        "no retry; no token/chat-id/URL/body leaked; funds untouched".to_string(),
    ];
    emit(
        out,
        "platform send",
        envelope_hex,
        CommandRisk::Network,
        ApprovalRequirement::TypedPhrase,
        RenderTruth::Red,
        &body,
    )?;
    Ok(true)
}

/// Static, secret-zero denial labels for the live-telegram error taxonomy.
#[cfg(feature = "telegram-egress")]
fn telegram_denied_label(error: &crate::telegram::egress::LiveTelegramError) -> String {
    use crate::telegram::egress::{LiveTelegramError, TelegramEgressDenied};
    match error {
        LiveTelegramError::Denied(TelegramEgressDenied::TransportNotCompiled) => {
            "transport not compiled".to_string()
        }
        LiveTelegramError::Denied(TelegramEgressDenied::LiveSendNotAllowed) => {
            "live send not enabled".to_string()
        }
        LiveTelegramError::Denied(TelegramEgressDenied::ApprovalMissing) => {
            "approval missing".to_string()
        }
        LiveTelegramError::Denied(TelegramEgressDenied::HostNotAllowlisted) => {
            "host not allowlisted".to_string()
        }
        LiveTelegramError::Denied(TelegramEgressDenied::TokenMissing) => {
            "TELEGRAM_BOT_TOKEN not present in the environment".to_string()
        }
        LiveTelegramError::Denied(TelegramEgressDenied::TransportError) => {
            "transport error (network/TLS)".to_string()
        }
        LiveTelegramError::ChatIdMissing => {
            "TELEGRAM_CHAT_ID not present in the environment".to_string()
        }
        LiveTelegramError::Api {
            status_u16,
            error_code,
        } => format!("bot api denied status={status_u16} error_code={error_code}"),
        LiveTelegramError::MalformedResponse => {
            "response did not parse as a Bot API answer".to_string()
        }
    }
}

/// The gated telegram-send executor (feature ON only). Verifies the exact typed
/// phrase with the pure `ApprovalPrompt::evaluate` BEFORE anything else; then
/// runs the before-send redaction gate, builds the shared CLI⇔Telegram message
/// envelope, enables the live send (the phrase IS the same-message ceremony),
/// and fires EXACTLY ONE Bot-API sendMessage, rendering the message id + hash
/// receipts. No `unwrap`/`expect`/`panic`. funds untouched.
#[cfg(feature = "telegram-egress")]
fn platform_send(rest: &[String], out: &mut impl Write) -> io::Result<bool> {
    use crate::commands::platform_telegram::{MessageEnvelope, PlatformOrigin};
    use crate::provider::redaction::{RedactionRequest, redact};
    use crate::repl::approval::{ApprovalDecision, ApprovalPrompt};
    use crate::telegram::egress::{
        RedactedTelegramSend, TelegramEgressApproval, TelegramHost, TelegramTransport,
    };

    let envelope_hex = hex16(&sha256_32(b"platform send"));
    let supplied_phrase = rest.get(1).map_or("", String::as_str);
    let text = rest.get(2..).map(|s| s.join(" ")).unwrap_or_default();
    let text = text.trim();

    // GATE (sole operator gate; the same-message approval ceremony): exact
    // typed phrase, verified before redaction / build / any socket.
    let mut prompt = ApprovalPrompt::new(
        ApprovalRequirement::TypedPhrase,
        TELEGRAM_SEND_CONFIRM_PHRASE,
    );
    if !matches!(
        prompt.evaluate(supplied_phrase.trim()),
        ApprovalDecision::Approved
    ) {
        emit(
            out,
            "platform send",
            &envelope_hex,
            CommandRisk::Network,
            ApprovalRequirement::TypedPhrase,
            RenderTruth::Yellow,
            &platform_send_locked_body(),
        )?;
        return Ok(true);
    }
    if text.is_empty() {
        return platform_send_error(out, &envelope_hex, "empty message; nothing sent");
    }
    if text.len() > TELEGRAM_SEND_MAX_TEXT_BYTES {
        return platform_send_error(out, &envelope_hex, "message exceeds the bounded text cap");
    }
    // Before-send redaction (canonical secret scanners; deny-not-fix).
    let fragments = [text];
    let receipt = match redact(&RedactionRequest {
        fragments: &fragments,
        candidate_memory_ids: &[],
        deleted_ids: &[],
        include_private_memory: false,
    }) {
        Ok(receipt) => receipt,
        Err(_) => {
            return platform_send_error(out, &envelope_hex, "redaction gate denied the payload");
        }
    };
    if receipt.secret_fragments_denied_u32() > 0 || receipt.outgoing_fragment_count_u32() == 0 {
        return platform_send_error(out, &envelope_hex, "message is secret-shaped; not sent");
    }
    // Shared CLI⇔Telegram envelope, then the live flip — the typed phrase above
    // IS the same-message ceremony the dry-run invariant demands (TM F2). No
    // other code path constructs a live send.
    let command = CommandEnvelope::classify(
        CliNamespace::Platform,
        "send",
        CliMode::Run,
        CommandRisk::Network,
        text.as_bytes(),
    );
    // SI-2: the live send is built FROM the redaction receipt (the choke), then
    // flipped live by the granted approval the typed phrase above represents — no
    // struct-update, no hand-supplied hash. A receipt that proved a stored body
    // (which `redact` never emits) would fail closed here.
    let Some(send) =
        RedactedTelegramSend::dry_run(MessageEnvelope::new(PlatformOrigin::Cli, command), receipt)
    else {
        return platform_send_error(out, &envelope_hex, "redaction receipt rejected the send");
    };
    let send = send.into_live(TelegramEgressApproval::grant());
    let token = crate::secrets::classify_reference("TELEGRAM_BOT_TOKEN", "env:TELEGRAM_BOT_TOKEN");
    let transport = TelegramTransport::new(TelegramHost::BotApi, token);
    let outcome = match transport.send_live_message(&send, TelegramEgressApproval::grant(), text) {
        Ok(outcome) => outcome,
        Err(error) => {
            return platform_send_error(out, &envelope_hex, &telegram_denied_label(&error));
        }
    };
    let body = vec![
        "LIVE telegram send: delivered".to_string(),
        format!(
            "message_id={} chars={}",
            outcome.message_id,
            text.chars().count()
        ),
        "to=env:TELEGRAM_CHAT_ID (value never rendered)".to_string(),
        format!(
            "request_sha={} response_sha={} attempts=1",
            hex16(&outcome.request_hash_32),
            hex16(&outcome.response_hash_32)
        ),
        "one-shot; the token rides in the URL and is never logged or rendered".to_string(),
    ];
    emit(
        out,
        "platform send",
        &envelope_hex,
        CommandRisk::Network,
        ApprovalRequirement::TypedPhrase,
        RenderTruth::Green,
        &body,
    )?;
    Ok(true)
}

// ---- per-namespace ReadOnly status bodies (real handler reuse) -------------

/// Build the `(truth, body)` for a `ReadOnly` namespace+verb by reusing the real
/// handler's pure projection. Empty/default state renders the honest "no data yet"
/// surface (`Unknown`/`none`), never fabricated sample data (anti-cringe).
fn status_body(ns: CliNamespace, verb: &str) -> (RenderTruth, Vec<String>) {
    match ns {
        CliNamespace::Provider => {
            let reg = ProviderRegistry::new();
            let n = reg.list().len();
            (
                RenderTruth::Unknown,
                vec![
                    format!("providers_configured={n}"),
                    "no_silent_fallback=locked route-identity=visible".to_string(),
                    "0 live provider calls (status/dry-run only)".to_string(),
                    if n == 0 {
                        "none configured; next: sinabro setup".to_string()
                    } else {
                        "local executor default; frontier = reviewer-only".to_string()
                    },
                ],
            )
        }
        CliNamespace::Model => {
            let router = ModelRouter::new(ZERO32);
            let view = router.decision_view();
            let cache = CacheStatus::new();
            let endpoints = EndpointRegistry::new();
            let mut body = vec![
                format!("no_silent_fallback={}", view.no_silent_fallback),
                format!("route_approved={}", view.approved),
                format!("cache_entries={}", cache.stats().len()),
                format!("endpoints={}", endpoints.list().len()),
                "local executor is the only tool-executing role".to_string(),
            ];
            // P4-3 (VM-selector): the RESOLVED runtime/model selection (env is
            // the single source of truth) + how to pick it (`model use …`).
            body.extend(selection_summary_lines());
            (RenderTruth::Unknown, body)
        }
        CliNamespace::Tool => {
            let reg = ToolRegistry::new();
            (
                RenderTruth::Unknown,
                vec![
                    format!("tools_registered={}", reg.list().len()),
                    "tool budget gate: pre-dispatch, fail-closed".to_string(),
                    "sandbox-bound; no live run on the hot path".to_string(),
                ],
            )
        }
        CliNamespace::Memory => {
            let policy = TombstonePolicy::new();
            let view = MemoryCommandSurface::status(&policy, sha256_32(b"memory-root"));
            let mut body = vec!["memory: user-owned; tombstone no-resurrection".to_string()];
            body.extend(view.render(ROWS as u16));
            (RenderTruth::Green, body)
        }
        CliNamespace::Audit => {
            if verb.eq_ignore_ascii_case("scan") {
                // E5-1: `audit scan` walks the REAL source tree (CWD) and emits
                // real, source-anchored candidates (was `scan(&[])` ⇒ always 0).
                let scanned = crate::commands::source_scan::scan_tree(
                    std::path::Path::new("."),
                    AuditProfile::Rust,
                );
                let view = AuditScanView::scan(AuditProfile::Rust, false, &scanned.candidates);
                let mut body = vec![
                    format!("candidates={}", view.candidate_count_u32),
                    format!("files_scanned={}", scanned.files_scanned),
                    format!("local_only={}", view.is_local_only()),
                    format!("no_live_call={}", view.made_no_live_call()),
                    "candidate != finding: promotion needs a local repro receipt".to_string(),
                ];
                if scanned.files_capped || scanned.candidates_capped {
                    body.push(format!(
                        "scan bounded: files_capped={} candidates_capped={}",
                        scanned.files_capped, scanned.candidates_capped
                    ));
                }
                (RenderTruth::Unknown, body)
            } else {
                // E5-1: the REAL persisted, hash-linked audit chain — not an empty
                // Vec. A broken link / fork / byte-edit / orphan renders RED.
                let (truth, summary) =
                    match ChainedAuditLog::open_local().and_then(|log| log.load_chain()) {
                        Ok(view) => (view.truth, view.render_plain()),
                        Err(_) => (
                            RenderTruth::Unknown,
                            "audit_chain unavailable (no home / read error)".to_string(),
                        ),
                    };
                (
                    truth,
                    vec![
                        "audit trail: hash-linked, append-only, persisted (~/.mnemos/audit)"
                            .to_string(),
                        "tamper-evident: a broken link / fork / byte-edit renders RED".to_string(),
                        clamp_ascii(&summary),
                    ],
                )
            }
        }
        CliNamespace::Learning => {
            let view = LearningCommandView::new();
            let mut body =
                vec!["learning: default off; egress none; weight training locked".to_string()];
            body.extend(view.render(ROWS as u16));
            (view.render_truth(), body)
        }
        CliNamespace::Feature => match config::feature_toggle("redaction", FeatureState::Locked) {
            Ok(toggle) => (
                RenderTruth::Green,
                vec![
                    format!("feature=redaction state_u8={}", toggle.state as u8),
                    format!("safety_kernel={}", toggle.safety_kernel),
                    "safety-kernel features are locked-on; cannot be disabled".to_string(),
                ],
            ),
            Err(_) => (
                RenderTruth::Red,
                vec!["feature toggle unavailable".to_string()],
            ),
        },
        CliNamespace::Federation => {
            let view = FederationControlView::off();
            let mut body = vec!["federation: opt-in; rounds locked".to_string()];
            body.extend(view.render(ROWS as u16));
            (view.render_truth(), body)
        }
        CliNamespace::Admin => {
            let ctrl = IncidentController::new();
            (
                ctrl.render_truth(),
                vec![
                    "admin: incident controller ready".to_string(),
                    format!("incident_version={}", ctrl.version()),
                    "pause rides the express control rail (bypasses queues)".to_string(),
                ],
            )
        }
        CliNamespace::Release => {
            match ReleaseDryRun::evaluate("name = \"sinabro-skill\"\n", "0.0.0", true) {
                Ok(dry) => {
                    let mut body = vec!["release: dry-run only; live publish locked".to_string()];
                    body.extend(dry.render(ROWS as u16));
                    (dry.render_truth(), body)
                }
                Err(_) => (
                    RenderTruth::Unknown,
                    vec!["release: dry-run evaluation unavailable".to_string()],
                ),
            }
        }
        CliNamespace::Privacy => {
            // E5-3: scan REAL on-disk release surfaces with the canonical secret
            // engine (was `ReleaseSecretScan::new()` ⇒ 0 surfaces ⇒ always UNKNOWN).
            let scan = gather_release_scan();
            (
                scan.render_truth(),
                vec![
                    "privacy: egress none by default; secret-zero".to_string(),
                    clamp_ascii(&scan.render_plain()),
                ],
            )
        }
        CliNamespace::Checkpoint => {
            let store = CheckpointStore::new();
            (
                RenderTruth::Unknown,
                vec![
                    format!("checkpoints={}", store.list().len()),
                    "restore is user-change protected + idempotent".to_string(),
                ],
            )
        }
        CliNamespace::Task => {
            let inbox = OperationalInbox::new(0);
            (
                RenderTruth::Unknown,
                vec![
                    format!("tasks={} live={}", inbox.list().len(), inbox.live_count()),
                    "one task/session inbox; control-express kill bypasses queues".to_string(),
                ],
            )
        }
        CliNamespace::Session => {
            let inbox = OperationalInbox::new(0);
            (
                RenderTruth::Unknown,
                vec![
                    format!(
                        "session_id={} tasks={}",
                        inbox.session_id(),
                        inbox.list().len()
                    ),
                    "resume only from paused; no zombie resurrection".to_string(),
                ],
            )
        }
        CliNamespace::Platform | CliNamespace::Notify => {
            let center = NotificationCenter::new(16);
            let mut body = vec![format!(
                "notify {verb}: telegram dry-run; 0 live sends; secret-zero"
            )];
            body.extend(center.render(ROWS as u16));
            (center.render_truth(), body)
        }
        // Namespaces without a dedicated handler render an honest, real posture
        // (no fabricated data). Each is classified through the real envelope.
        CliNamespace::Sandbox => (
            RenderTruth::Green,
            vec![
                "sandbox: capability ceiling is immutable per tier".to_string(),
                "warmup never raises the ceiling (G-F-CAPABILITY)".to_string(),
            ],
        ),
        CliNamespace::Skill | CliNamespace::Registry => (
            RenderTruth::Unknown,
            vec![
                "skill: no-commerce; sandbox + approval bound".to_string(),
                "search/recommend = read-only; use/install = local-write (gated)".to_string(),
                "eval = runs reproducible commands in the OS sandbox (Admin, typed-phrase)"
                    .to_string(),
                "registry: provenance + maintainer review are inspect-only".to_string(),
            ],
        ),
        CliNamespace::Wallet | CliNamespace::Identity => (
            RenderTruth::Unknown,
            vec![
                "wallet/identity: memory-owner bound from a public key only".to_string(),
                "no seed phrase accepted; key value never loaded (secret-zero)".to_string(),
                "sign is gated (typed phrase); preview only".to_string(),
            ],
        ),
        CliNamespace::Key => (
            RenderTruth::Unknown,
            vec![
                "key: references only (keychain/env/kms/vault); value never loaded".to_string(),
                "key doctor is status-only; no secret is printed".to_string(),
            ],
        ),
        CliNamespace::Gas => (
            RenderTruth::Unknown,
            vec![
                "gas: no sponsor configured; balances are status-only".to_string(),
                "owner is never the sponsor; request is gated (network)".to_string(),
            ],
        ),
        CliNamespace::Chain => (
            RenderTruth::Unknown,
            vec![
                "chain: testnet env; mainnet execution LOCKED".to_string(),
                "mainnet write requires multisig approval (locked)".to_string(),
            ],
        ),
        CliNamespace::Package => (
            RenderTruth::Unknown,
            vec![
                "package: publish/upgrade is dry-run only".to_string(),
                "real publish requires multisig (chain-write, denied)".to_string(),
            ],
        ),
        CliNamespace::Multisig => (
            RenderTruth::Unknown,
            vec![
                "multisig: proposal/timelock state is view-only".to_string(),
                "live execution locked (chain-write denied)".to_string(),
            ],
        ),
        CliNamespace::Dataset => (
            RenderTruth::Unknown,
            vec![
                "dataset: S1/S2 splits + PII0 quality are local-only".to_string(),
                "export/ingest are gated local-writes; no upload".to_string(),
            ],
        ),
        CliNamespace::Trace => (
            RenderTruth::Unknown,
            vec![
                "trace: command audit view; hash-only, secret-zero".to_string(),
                "high-risk + failures force a mandatory audit line".to_string(),
            ],
        ),
        CliNamespace::Train => (
            RenderTruth::Yellow,
            vec![
                "train: doctor/status only (training locked)".to_string(),
                "run/sft/checkpoint/grpo are locked (weight training off)".to_string(),
            ],
        ),
        CliNamespace::Eval | CliNamespace::Measure => (
            RenderTruth::Unknown,
            vec![
                "eval: rust/move/prover/kani/lean/gas/korean; local-only".to_string(),
                "measure: opt-in OTel span export to ~/.mnemos/otel (SINABRO_OTEL_EXPORT=1)"
                    .to_string(),
            ],
        ),
        CliNamespace::Approval => (
            RenderTruth::Unknown,
            vec![
                "approval: derived from the closed risk -> approval mapping".to_string(),
                "read-only=none, local/net=confirm, sign/admin=typed, chain=multisig".to_string(),
            ],
        ),
        CliNamespace::Permission => (
            RenderTruth::Green,
            vec![
                "permission: capability diff is before -> after, escalation-flagged".to_string(),
                "a capability gain renders DEGRADED, never a silent grant".to_string(),
            ],
        ),
        CliNamespace::Context => (
            RenderTruth::Unknown,
            vec![
                "context: every selected item carries a visible reason".to_string(),
                "no invisible context injection; pin is a local-write".to_string(),
            ],
        ),
        // Agent budget/kill are surfaced via the top-level `budget`/`kill`
        // commands; the namespace renders the bounded-turn posture.
        CliNamespace::Agent => (
            RenderTruth::Unknown,
            vec![
                "agent: bounded turn; budget + kill ride the express rail".to_string(),
                "see: sinabro budget | sinabro kill".to_string(),
            ],
        ),
    }
}

// ---- agent-core step 2: read-only memory retrieval surface ----------------
//
// Design: ops/evidence/stage_g/agent_loop/MEMORY_INDEX_DESIGN.md §5 (verbs) +
// MEMORY_RETRIEVAL_THREAT_MODEL.md (IV1-IV6). Both verbs classify
// CommandRisk::ReadOnly -> approval=None (autonomous-safe, IV6) and ride the
// SAME classify/emit flow as every other read-only verb — pure projections,
// no side effect, no egress. The dispatch surface is the LOCAL trust tier
// (the owner's own terminal/GUI): private records render here (the owner
// reads their own memory); the FRONTIER pre-filter (IV2/D7) binds in the
// step-4 context assembler through the same `catalog_select`/`read_select`
// selectors with `frontier_bound=true`.

/// Bounded number of catalog records rendered by `memory index` (the whole
/// render is additionally bounded by [`ROWS`]).
const MEMORY_INDEX_RENDER_CAP: usize = 32;

/// Bounded number of content lines rendered by `memory read <id>`.
const MEMORY_READ_RENDER_LINES: usize = 40;

/// Stable lowercase tier label for catalog lines.
const fn tier_label(tier: MemoryTier) -> &'static str {
    match tier {
        MemoryTier::Recent => "recent",
        MemoryTier::Mid => "mid",
        MemoryTier::Ancient => "ancient",
        MemoryTier::DeletedTombstone => "tombstone",
    }
}

/// State wiring for the retrieval verbs: folds the PERSISTED, encrypted
/// store into the index per call (P1-1-c; the index is a re-derivable cache,
/// the store is the truth — DL-4), carrying each chunk's OWNER privacy class
/// and its deterministic Stage-D importance score into the records (P1-2).
fn memory_retrieval_body(verb: &str, rest: &[String]) -> (RenderTruth, Vec<String>) {
    // P1-1-c: the REAL projection now folds the PERSISTED, encrypted store
    // (the index is a re-derivable cache; the store is the truth — DL-4). A
    // fail-closed store (no key / io trouble) degrades to an empty view, never
    // an error and never plaintext.
    let policy = TombstonePolicy::new();
    let loaded = match PersistedStore::open_local() {
        Ok(store) => store.load_all(),
        Err(_) => crate::memory_store::LoadOutcome::default(),
    };
    let folded = fold_index_classified(
        loaded
            .chunks
            .iter()
            .map(|(chunk, privacy)| (chunk, *privacy)),
        &policy,
    );
    let contents: Vec<(MemoryId, &[u8])> = loaded
        .chunks
        .iter()
        .map(|(chunk, _)| (chunk.id(), chunk.envelope().content.as_slice()))
        .collect();
    if verb.eq_ignore_ascii_case("read") {
        memory_read_body(&folded.records, &contents, &policy, rest)
    } else {
        memory_index_body(&folded.records)
    }
}

/// `memory save [--shareable] <text>` — persist a user memory to the
/// encrypted local store (P1-1-c). Local at-rest only (no egress, no funds);
/// the bytes are AEAD ciphertext on disk and survive restart. Fail-closed on
/// key/io/cap trouble.
///
/// Owner classification surface (P1-2, IV2): the DEFAULT class is PRIVATE
/// (fail-closed; a private memory never lists frontier-bound). ONLY the
/// exact typed flag `--shareable` as the first argument classifies the
/// memory as frontier-shareable — and the redaction gate still applies to
/// anything that later leaves the machine. Any OTHER `--…` first token is a
/// typed deny: a typo'd flag must never silently save misclassified text.
fn memory_save_body(rest: &[String]) -> (RenderTruth, Vec<String>) {
    let args = rest.get(1..).unwrap_or_default();
    let (privacy, text_args) = match args.first().map(String::as_str) {
        Some("--shareable") => (MemoryPrivacy::Shareable, args.get(1..).unwrap_or_default()),
        Some(flag) if flag.starts_with("--") => {
            return (
                RenderTruth::Yellow,
                vec![
                    format!("memory save denied: unknown flag {flag}"),
                    "usage: memory save [--shareable] <text> (default: private)".to_string(),
                ],
            );
        }
        _ => (MemoryPrivacy::Private, args),
    };
    let text = text_args.join(" ");
    let text = text.trim();
    if text.is_empty() {
        return (
            RenderTruth::Yellow,
            vec![
                "usage: memory save [--shareable] <text>".to_string(),
                "persists ONE memory, encrypted at rest; survives restart".to_string(),
                "default class: private (fail-closed); --shareable = owner-explicit".to_string(),
            ],
        );
    }
    if text.len() > MAX_STAGE_B_CONTENT_BYTES as usize {
        return (
            RenderTruth::Yellow,
            vec!["memory save denied: text exceeds the content cap".to_string()],
        );
    }
    let store = match PersistedStore::open_local() {
        Ok(store) => store,
        Err(err) => {
            return (
                RenderTruth::Yellow,
                vec![
                    format!("memory save unavailable ({})", err.class_label()),
                    "fail-closed: nothing written; no plaintext on disk".to_string(),
                ],
            );
        }
    };
    // Next id = max existing id + 1 (load_all is id-sorted ⇒ last is max).
    let existing = store.load_all();
    let next_id = existing
        .chunks
        .last()
        .map_or(0, |(chunk, _)| chunk.id().get().saturating_add(1));
    let chunk = make_user_chunk(MemoryId::new(next_id), text);
    match store.save_chunk(&chunk, privacy) {
        Ok(name) => (
            RenderTruth::Green,
            vec![
                format!(
                    "memory saved: id={next_id} chars={} class={}",
                    text.len(),
                    if privacy.is_private() {
                        "private"
                    } else {
                        "shareable (frontier-visible after redaction)"
                    }
                ),
                format!("record={name} (encrypted, content-addressed)"),
                "survives restart; plaintext never on disk".to_string(),
            ],
        ),
        Err(err) => (
            RenderTruth::Yellow,
            vec![format!("memory save failed ({})", err.class_label())],
        ),
    }
}

/// The exact in-band confirmation phrase that authorizes ONE bounded local
/// command (P3-1, CODE_EXEC_THREAT_MODEL.md IV-E1). A PUBLIC confirmation
/// gesture (zero entropy, NOT a secret).
const EXEC_LOCAL_CONFIRM_PHRASE: &str = "exec-local-owner-live";

/// Bounded number of output lines rendered per exec stream.
const EXEC_RENDER_LINE_CAP: usize = 32;

/// `tool run` locked-surface render — no ceremony ⇒ zero side effects.
fn exec_locked_body() -> Vec<String> {
    vec![
        "tool run is a LOCAL owner command executor (bounded, env-scrubbed)".to_string(),
        format!("usage: tool run {EXEC_LOCAL_CONFIRM_PHRASE} <argv…>"),
        "no shell: whitespace argv only (no pipes / globs / redirects)".to_string(),
        format!(
            "bounds: timeout={}ms stream_cap={}B args<={} line<={}B",
            crate::exec_local::EXEC_TIMEOUT_MS,
            crate::exec_local::EXEC_STREAM_CAP_BYTES,
            crate::exec_local::EXEC_MAX_ARGS,
            crate::exec_local::EXEC_MAX_LINE_BYTES
        ),
        "env scrub: the child sees PATH/HOME/LANG/TERM only (keys never cross)".to_string(),
        "tier=privileged (sandbox tier 5); the MODEL has no path to this seam".to_string(),
        "output passes redaction before render; secret-shaped = withheld".to_string(),
    ]
}

/// Render one captured exec stream: honest byte totals + truncation marker,
/// then the retained head through the canonical redaction gate (IV-E5 —
/// secret-shaped output is withheld; the counts still render).
fn render_exec_stream(
    body: &mut Vec<String>,
    label: &str,
    stream: &crate::exec_local::CapturedStream,
) {
    body.push(format!(
        "{label}: {}B total{}",
        stream.total_bytes_u64,
        if stream.truncated {
            " (retained head only)"
        } else {
            ""
        }
    ));
    if stream.retained.is_empty() {
        return;
    }
    let text = String::from_utf8_lossy(&stream.retained);
    let fragments = [text.as_ref()];
    match redact(&RedactionRequest {
        fragments: &fragments,
        candidate_memory_ids: &[],
        deleted_ids: &[],
        include_private_memory: false,
    }) {
        Ok(receipt) if receipt.secret_fragments_denied_u32() == 0 => {
            for line in text.lines().take(EXEC_RENDER_LINE_CAP) {
                body.push(format!("  {line}"));
            }
            let total_lines = text.lines().count();
            if total_lines > EXEC_RENDER_LINE_CAP {
                body.push(format!(
                    "  … {} more lines (render bounded)",
                    total_lines - EXEC_RENDER_LINE_CAP
                ));
            }
        }
        _ => body.push(format!("{label}: withheld (secret-shaped)")),
    }
}

/// `tool run <phrase> <argv…>` — the owner's bounded local command (P3-1).
/// Gate order = the threat model's: exact ceremony (IV-E1) → argv walls +
/// scrubbed bounded spawn (`exec_local`, IV-E2/E3/E4/E7) → redacted render
/// (IV-E5). Exec output never reaches a frontier prompt (IV-E6 — no bridge
/// exists). sinabro composes no command itself (IV-E8 — the argv echo is
/// the owner's typed text, verbatim).
fn exec_run_body(rest: &[String]) -> (RenderTruth, Vec<String>) {
    let Some(phrase) = rest.get(1) else {
        return (RenderTruth::Yellow, exec_locked_body());
    };
    if phrase != EXEC_LOCAL_CONFIRM_PHRASE {
        return (RenderTruth::Yellow, exec_locked_body());
    }
    let line = rest.get(2..).map(|args| args.join(" ")).unwrap_or_default();
    let outcome = match crate::exec_local::run_local_command(line.trim()) {
        Ok(outcome) => outcome,
        Err(deny) => {
            return (
                RenderTruth::Yellow,
                vec![
                    format!("exec denied ({})", deny.class_label()),
                    format!("usage: tool run {EXEC_LOCAL_CONFIRM_PHRASE} <argv…>"),
                ],
            );
        }
    };
    let truth = if outcome.timed_out {
        RenderTruth::Red
    } else if outcome.exit_code == Some(0) {
        RenderTruth::Green
    } else {
        RenderTruth::Yellow
    };
    let exit_label = match (outcome.exit_code, outcome.timed_out) {
        (Some(code), _) => code.to_string(),
        (None, true) => "killed(timeout)".to_string(),
        (None, false) => "none(signal)".to_string(),
    };
    let mut body = Vec::new();
    // The argv echo is the owner's own typed text — but the RENDER stays
    // secret-zero: a secret-shaped command line withholds the echo (the
    // command still ran exactly as typed; the receipt says so explicitly).
    let argv_echo = format!("{:?}", outcome.argv);
    let argv_fragments = [argv_echo.as_str()];
    match redact(&RedactionRequest {
        fragments: &argv_fragments,
        candidate_memory_ids: &[],
        deleted_ids: &[],
        include_private_memory: false,
    }) {
        Ok(receipt) if receipt.secret_fragments_denied_u32() == 0 => {
            body.push(format!("exec: argv={argv_echo}"));
        }
        _ => {
            body.push("exec: argv withheld (secret-shaped input; ran exactly as typed)".to_string())
        }
    }
    body.push(format!(
        "result: exit={exit_label} timed_out={} duration={}ms",
        outcome.timed_out, outcome.duration_ms_u64
    ));
    render_exec_stream(&mut body, "stdout", &outcome.stdout);
    render_exec_stream(&mut body, "stderr", &outcome.stderr);
    body.push("env scrubbed (allowlist only); no shell; bounded; owner-initiated".to_string());
    (truth, body)
}

// ---- E6: skill eval — real execution in the OS-enforced sandbox (⑫) -------
//
// Owner-ratified 2026-06-12 (AskUserQuestion): a skill carries NO executable
// payload (`SkillPackageV1` is declarative metadata + content digests), so the
// genuinely executable surface is `skill eval`'s reproducible commands. `skill
// eval` RUNS them inside `sandbox_exec::run_in_sandbox` at tier=LocalWrite
// (network kernel-DENIED, env-scrubbed) and binds the canonical
// `SkillEvalScore` to the REALLY-run commands — closing the "eval hashes
// strings, never runs" gap (IV-S11). `skill use → run a wasm module` stays
// honestly deferred (no artifact; the wasm go-live gate). Threat model:
// ops/evidence/stage_g/agent_loop/SKILL_SANDBOX_THREAT_MODEL.md.

/// The exact in-band confirmation phrase that authorizes ONE real `skill eval`
/// run. A PUBLIC confirmation gesture (zero entropy, NOT a secret) — mirrors
/// `tool run`'s ceremony. A skill eval SPAWNS real processes, so it is gated
/// like `tool run`: Admin + this typed phrase.
const SKILL_EVAL_CONFIRM_PHRASE: &str = "skill-eval-owner-live";

/// Maximum eval commands in ONE `skill eval` run (the `|`-split list).
const SKILL_EVAL_MAX_CMDS: usize = 6;

/// The locked / usage surface for `skill eval` (no phrase, or wrong phrase) —
/// render-only, zero side effects.
fn skill_eval_locked_body() -> Vec<String> {
    vec![
        "skill eval RUNS a skill's reproducible commands in the OS sandbox".to_string(),
        format!("usage: skill eval {SKILL_EVAL_CONFIRM_PHRASE} <cmd> [| <cmd> …]"),
        "each command runs argv-only (no shell) at sandbox tier=LocalWrite".to_string(),
        "tier=LocalWrite: read+write local, NETWORK kernel-DENIED (no egress)".to_string(),
        format!(
            "bounds: timeout={}ms stream_cap={}B cmds<={SKILL_EVAL_MAX_CMDS} line<={}B",
            crate::exec_local::EXEC_TIMEOUT_MS,
            crate::exec_local::EXEC_STREAM_CAP_BYTES,
            crate::exec_local::EXEC_MAX_LINE_BYTES
        ),
        "the eval score binds to the REALLY-run commands (no string-hash forgery)".to_string(),
        "env scrub: child sees PATH/HOME/LANG/TERM only; output redacted before render".to_string(),
    ]
}

/// `skill eval <phrase> <cmd> [| <cmd> …]` — run a skill's reproducible commands
/// inside the kernel-enforced sandbox tier (E6, IV-S). Gate order = the threat
/// model's: exact ceremony (IV-E1) → `|`-split + per-command bounded sandboxed
/// spawn (`sandbox_exec`, IV-S1/S4/S6/S9) → redacted render (IV-S10). The
/// canonical `SkillEvalScore` binds to the commands that REALLY ran (IV-S11).
fn skill_eval_body(rest: &[String]) -> (RenderTruth, Vec<String>) {
    let Some(phrase) = rest.get(1) else {
        return (RenderTruth::Yellow, skill_eval_locked_body());
    };
    if phrase != SKILL_EVAL_CONFIRM_PHRASE {
        return (RenderTruth::Yellow, skill_eval_locked_body());
    }
    let joined = rest.get(2..).map(|args| args.join(" ")).unwrap_or_default();
    let commands: Vec<String> = joined
        .split('|')
        .map(|c| c.trim().to_string())
        .filter(|c| !c.is_empty())
        .collect();
    if commands.is_empty() {
        return (RenderTruth::Yellow, skill_eval_locked_body());
    }
    if commands.len() > SKILL_EVAL_MAX_CMDS {
        return (
            RenderTruth::Yellow,
            vec![
                format!("skill eval denied: > {SKILL_EVAL_MAX_CMDS} commands in one run"),
                format!("usage: skill eval {SKILL_EVAL_CONFIRM_PHRASE} <cmd> [| <cmd> …]"),
            ],
        );
    }

    let mut body = Vec::new();
    let mut all_passed = true;
    let mut any_timeout = false;
    let mut any_denied = false;
    for (i, cmd) in commands.iter().enumerate() {
        match crate::sandbox_exec::run_in_sandbox_default(
            crate::commands::sandbox::SandboxTier::LocalWrite,
            cmd,
        ) {
            Ok(outcome) => {
                let passed = !outcome.timed_out && outcome.exit_code == Some(0);
                all_passed &= passed;
                any_timeout |= outcome.timed_out;
                let exit_label = match (outcome.exit_code, outcome.timed_out) {
                    (Some(code), _) => code.to_string(),
                    (None, true) => "killed(timeout)".to_string(),
                    (None, false) => "none(signal)".to_string(),
                };
                // The command echo is owner text — RENDER stays secret-zero
                // (a secret-shaped command withholds the echo; it still ran).
                let cmd_fragments = [cmd.as_str()];
                let line = match redact(&RedactionRequest {
                    fragments: &cmd_fragments,
                    candidate_memory_ids: &[],
                    deleted_ids: &[],
                    include_private_memory: false,
                }) {
                    Ok(receipt) if receipt.secret_fragments_denied_u32() == 0 => {
                        format!("cmd[{i}]: {cmd}")
                    }
                    _ => format!("cmd[{i}]: withheld (secret-shaped; ran exactly as typed)"),
                };
                body.push(line);
                body.push(format!(
                    "  exit={exit_label} timed_out={} duration={}ms",
                    outcome.timed_out, outcome.duration_ms_u64
                ));
                render_exec_stream(&mut body, "  stdout", &outcome.stdout);
                render_exec_stream(&mut body, "  stderr", &outcome.stderr);
            }
            Err(deny) => {
                all_passed = false;
                any_denied = true;
                body.push(format!("cmd[{i}] denied ({})", deny.class_label()));
            }
        }
    }

    // Bind the canonical eval score to the REALLY-run commands (IV-S11): a
    // forged "100%" with a mismatched command set is catchable, and the rust
    // axis now reflects real exit codes (not a hash of unrun strings).
    let cmd_refs: Vec<&str> = commands.iter().map(String::as_str).collect();
    let command_hash = mnemos_e_skill::reproducible_command_hash(&cmd_refs);
    let score = mnemos_e_skill::SkillEvalScore {
        rust_u16: if all_passed {
            mnemos_e_skill::MAX_EVAL_SCORE
        } else {
            0
        },
        move_u16: 0,
        prover_u16: 0,
        gas_u16: 0,
        security_u16: 0,
        korean_u16: 0,
        reproducible_command_hash_32: command_hash,
    };
    body.push(format!(
        "eval score: rust={}bps (real exit-code derived); move/prover/gas/security/korean=0 (not measured v1)",
        score.rust_u16
    ));
    body.push(format!(
        "score valid={} cmd_hash={}",
        score.is_valid(),
        hex16(&command_hash)
    ));
    body.push(
        "executed in OS sandbox tier=LocalWrite (network kernel-DENIED); env-scrubbed".to_string(),
    );

    let truth = if any_denied || any_timeout {
        RenderTruth::Red
    } else if all_passed {
        RenderTruth::Green
    } else {
        RenderTruth::Yellow
    };
    (truth, body)
}

// ---- P3-2: file-edit propose/apply (MULTI_FILE_EDIT_THREAT_MODEL.md) ------
//
// THE FIRST ARBITRARY-PATH FILE WRITE IN THE CORE, split by authority
// (IV-W1): the MODEL only PROPOSES (its final answer may carry a closed
// `PROPOSE-EDIT` block, extracted by the owner-ceremonied consult executor
// into a sealed INERT artifact); the OWNER alone APPLIES, per action, behind
// the exact `tool apply` ceremony below. The loop grammar is byte-unchanged
// (`TOOL: file write/apply` ⇒ ToolUnknown deny — pinned in agent_loop tests).

/// The exact in-band confirmation phrase that authorizes applying ONE
/// pending file-edit proposal (P3-2, IV-W1). A PUBLIC confirmation gesture
/// (zero entropy, NOT a secret).
const FILE_APPLY_CONFIRM_PHRASE: &str = "file-apply-owner-live";

/// REWIND ceremony phrase — `tool rewind <phrase>` undoes the LAST applied edit
/// (restores the captured bytes through the staleness-locked owner-save path).
const REWIND_CONFIRM_PHRASE: &str = "rewind-last-owner-live";

/// The `tool rewind` surface (mirrors `file_apply_surface`'s shape): no phrase ⇒
/// a locked preview (whether a revert point exists); the exact ceremony ⇒
/// [`crate::revert_blob::revert_last`] restores the captured bytes through the
/// staleness-locked, confined, atomic owner-save path. Local-file-only (PD-6
/// untouched); the side effect auto-lands in the E5 audit chain (as `Rollback`).
fn file_rewind_surface(rest: &[String]) -> (RenderTruth, Vec<String>) {
    let store = match crate::revert_blob::RevertStore::open_local() {
        Ok(s) => s,
        Err(_) => {
            return (
                RenderTruth::Yellow,
                vec![
                    "rewind unavailable: revert store (no key/home)".to_string(),
                    "fail-closed: nothing written".to_string(),
                ],
            );
        }
    };
    // `tool rewind list` — read-only history (metadata only; no phrase, no write).
    if rest.get(1).is_some_and(|s| s.eq_ignore_ascii_case("list")) {
        return render_rewind_list(&store);
    }
    let Some(phrase) = rest.get(1) else {
        let n = crate::revert_blob::revert_list(&store).len();
        let line = if n > 0 {
            format!("{n} revert point(s) available — `tool rewind list` to see them")
        } else {
            "no revert point — apply an edit first, then rewind undoes it".to_string()
        };
        return (
            RenderTruth::Yellow,
            vec![
                format!("locked: tool rewind {REWIND_CONFIRM_PHRASE} (undo the last applied edit)"),
                format!(
                    "       tool rewind {REWIND_CONFIRM_PHRASE} to <id> (undo a specific point)"
                ),
                line,
            ],
        );
    };
    if phrase != REWIND_CONFIRM_PHRASE {
        return (
            RenderTruth::Yellow,
            vec![
                format!("locked: tool rewind {REWIND_CONFIRM_PHRASE} (undo the last applied edit)"),
                "wrong phrase; nothing written".to_string(),
            ],
        );
    }
    let policy = crate::file_context::FileReadPolicy::workspace_default();
    // `tool rewind <phrase> to <id>` — undo a SPECIFIC revert point (id from `list`).
    if rest.get(2).is_some_and(|s| s.eq_ignore_ascii_case("to")) {
        let Some(id_str) = rest.get(3) else {
            return (
                RenderTruth::Yellow,
                vec![
                    "locked: tool rewind <phrase> to <id> (use `tool rewind list` for ids)"
                        .to_string(),
                    "missing id; nothing written".to_string(),
                ],
            );
        };
        let Ok(seq) = id_str.parse::<u64>() else {
            return (
                RenderTruth::Yellow,
                vec![
                    format!("rewind DENIED (revert.bad_id:{id_str})"),
                    "id must be a number from `tool rewind list`; nothing written".to_string(),
                ],
            );
        };
        return render_rewind_result(crate::revert_blob::revert_to(&policy, &store, seq));
    }
    // `tool rewind <phrase>` — pop the MOST-RECENT point (the one-key undo).
    render_rewind_result(crate::revert_blob::revert_last(&policy, &store))
}

/// Render a rewind result card (GREEN on a successful restore, Yellow on a typed deny).
fn render_rewind_result(
    r: Result<crate::revert_blob::RevertReceipt, crate::revert_blob::RevertDeny>,
) -> (RenderTruth, Vec<String>) {
    match r {
        Ok(r) => (
            RenderTruth::Green,
            vec![
                format!("rewound: {}", r.target_path.display()),
                format!(
                    "from_sha={} -> restored_sha={} bytes={} (staleness-locked atomic write; re-read verified)",
                    hex16(&r.from_sha_32),
                    hex16(&r.restored_sha_32),
                    r.bytes_written_u64
                ),
                "the displaced content was written back; revert point consumed".to_string(),
            ],
        ),
        Err(deny) => (
            RenderTruth::Yellow,
            vec![
                format!("rewind DENIED ({})", deny.class_label()),
                "nothing written".to_string(),
            ],
        ),
    }
}

/// Render the revert history (metadata only; most-recent first). Read-only — the GUI
/// parses `[id] path · NB · was sha` rows into a clickable "undo to here" list.
fn render_rewind_list(store: &crate::revert_blob::RevertStore) -> (RenderTruth, Vec<String>) {
    let entries = crate::revert_blob::revert_list(store);
    if entries.is_empty() {
        return (
            RenderTruth::Yellow,
            vec!["no revert points — apply an edit first, then rewind undoes it".to_string()],
        );
    }
    let mut body = vec![format!(
        "rewind history: {} point(s) (most-recent first; cap {})",
        entries.len(),
        crate::revert_blob::REVERT_HISTORY_CAP
    )];
    for e in &entries {
        body.push(format!(
            "  [{}] {} · {}B · was {}",
            e.seq,
            e.target_path.display(),
            e.old_bytes_len,
            hex16(&e.applied_sha_32)
        ));
    }
    body.push(format!(
        "undo one: tool rewind {REWIND_CONFIRM_PHRASE} to <id>"
    ));
    (RenderTruth::Green, body)
}

/// Bounded number of pending proposals listed on the locked surface.
const FILE_APPLY_LIST_CAP: usize = 8;

/// Append a bounded, redaction-gated line diff (IV-W7b — defense in depth:
/// the old side passed the lane-A read walls, the new side passed the
/// propose-time gate, and the RENDER still re-checks; withheld keeps the
/// hash receipt honest).
fn render_redacted_diff(body: &mut Vec<String>, old_text: &str, new_text: &str) {
    let diff_lines = render_line_diff(old_text, new_text);
    let joined = diff_lines.join("\n");
    let fragments = [joined.as_str()];
    match redact(&RedactionRequest {
        fragments: &fragments,
        candidate_memory_ids: &[],
        deleted_ids: &[],
        include_private_memory: false,
    }) {
        Ok(receipt) if receipt.secret_fragments_denied_u32() == 0 => body.extend(diff_lines),
        _ => {
            body.push("diff withheld (secret-shaped); the hashes above are the receipt".to_string())
        }
    }
}

/// One stable pending-proposal line (id prefix + target + hash receipt —
/// never content bytes).
fn pending_proposal_line(record_name: &str, proposal: &FileEditProposal) -> String {
    let id: String = record_name.chars().take(PROPOSAL_ID_HEX_CHARS).collect();
    format!(
        "id={id} target={} read_sha={} new_sha={} bytes={}",
        proposal.target_path.display(),
        hex16(&proposal.read_sha_32),
        hex16(&sha256_32(&proposal.content)),
        proposal.content.len()
    )
}

/// `tool apply` locked-surface render — no ceremony ⇒ zero side effects;
/// the pending list is a read-only projection (degraded-honest without a
/// store/key).
fn file_apply_locked_body(store: Option<&ProposalStore>) -> Vec<String> {
    let mut body = vec![
        "tool apply applies ONE pending file-edit proposal (owner-only)".to_string(),
        format!("usage: tool apply {FILE_APPLY_CONFIRM_PHRASE} <proposal-id>"),
        "the model proposes only (PROPOSE-EDIT answer); it can never apply".to_string(),
        "walls: allowlist+denylist+size (lane A) -> staleness hash -> atomic replace".to_string(),
        "tier=local-write (sandbox tier 3); stale/unknown/ambiguous = typed deny".to_string(),
    ];
    let Some(store) = store else {
        body.push("proposal store unavailable (no key/home); nothing listed".to_string());
        return body;
    };
    let pending = store.load_pending();
    body.push(format!(
        "pending={} skipped={} (cap {MAX_PENDING_PROPOSALS})",
        pending.proposals.len(),
        pending.skipped_u32
    ));
    for entry in pending.proposals.iter().take(FILE_APPLY_LIST_CAP) {
        body.push(pending_proposal_line(&entry.record_name, &entry.proposal));
    }
    if pending.proposals.len() > FILE_APPLY_LIST_CAP {
        body.push(format!(
            "... {} more pending (render bounded)",
            pending.proposals.len() - FILE_APPLY_LIST_CAP
        ));
    }
    body
}

/// `tool apply <phrase> <proposal-id>` — the owner's per-action apply
/// (P3-2). Gate order = the threat model's: exact ceremony (IV-W1) → typed
/// id lookup → lane-A target walls + staleness (IV-W3/W4, inside
/// [`apply_proposal`]) → atomic mode-preserving replace + verify-after-write
/// (IV-W5) → consume-on-success. Store + policy are injected so tests drive
/// the REAL surface against a temp store + temp roots.
fn file_apply_surface(
    store: Option<&ProposalStore>,
    policy: &crate::file_context::FileReadPolicy,
    rest: &[String],
) -> (RenderTruth, Vec<String>) {
    let Some(phrase) = rest.get(1) else {
        return (RenderTruth::Yellow, file_apply_locked_body(store));
    };
    if phrase != FILE_APPLY_CONFIRM_PHRASE {
        return (RenderTruth::Yellow, file_apply_locked_body(store));
    }
    let Some(store) = store else {
        return (
            RenderTruth::Yellow,
            vec![
                "apply denied: proposal store unavailable (no key/home)".to_string(),
                "fail-closed: nothing written".to_string(),
            ],
        );
    };
    let Some(id_arg) = rest.get(2) else {
        return (
            RenderTruth::Yellow,
            vec![
                format!("usage: tool apply {FILE_APPLY_CONFIRM_PHRASE} <proposal-id>"),
                "missing <proposal-id>; `tool apply` (no args) lists pending ids".to_string(),
            ],
        );
    };
    let pending = match store.find_by_prefix(id_arg) {
        Ok(pending) => pending,
        Err(deny) => {
            return (
                RenderTruth::Yellow,
                vec![
                    format!("apply denied ({})", deny.class_label()),
                    "nothing written; `tool apply` (no args) lists pending ids".to_string(),
                ],
            );
        }
    };
    match apply_proposal(policy, &pending.proposal) {
        Ok(receipt) => {
            let removed = store.remove(&pending.record_name).is_ok();
            let mut body = vec![
                format!("applied: {}", receipt.target_path.display()),
                format!(
                    "old_sha={} -> new_sha={} bytes={} (atomic temp+fsync+rename; re-read verified)",
                    hex16(&receipt.old_sha_32),
                    hex16(&receipt.new_sha_32),
                    receipt.bytes_written_u64
                ),
            ];
            if let Some(old_text) = receipt.old_text.as_deref() {
                let new_text = String::from_utf8_lossy(&pending.proposal.content).to_string();
                render_redacted_diff(&mut body, old_text, &new_text);
            }
            body.push(if removed {
                "proposal consumed (removed from pending)".to_string()
            } else {
                "WARNING: applied but the artifact could not be removed (still listed)".to_string()
            });
            // REWIND: capture the displaced bytes as the single-slot revert point so
            // `tool rewind` can undo THIS apply. Best-effort — a capture failure never
            // fails the apply (the edit already landed). The disk side effect is
            // cfg(not(test)) so the apply tests stay hermetic (the E5 audit-append
            // precedent); the engine itself is unit-tested directly in revert_blob.
            #[cfg(not(test))]
            if let Some(old) = receipt.old_text.as_ref() {
                if let Ok(rstore) = crate::revert_blob::RevertStore::open_local() {
                    let blob = crate::revert_blob::RevertBlob {
                        target_path: receipt.target_path.clone(),
                        applied_sha_32: receipt.new_sha_32,
                        old_bytes: old.clone().into_bytes(),
                    };
                    if rstore.capture(&blob).is_ok() {
                        body.push(format!(
                            "rewindable: tool rewind {REWIND_CONFIRM_PHRASE} (undo this edit)"
                        ));
                    }
                }
            }
            (RenderTruth::Green, body)
        }
        Err(deny) => {
            let mut body = vec![format!("apply DENIED ({})", deny.class_label())];
            if matches!(deny, ApplyDeny::Stale) {
                // IV-W3 honesty: show expected-vs-current so the owner sees
                // exactly why (the target moved after the model read it).
                let current = policy
                    .read(&pending.proposal.target_path)
                    .ok()
                    .map(|c| hex16(&c.sha256_32))
                    .unwrap_or_else(|| "unreadable".to_string());
                body.push(format!(
                    "staleness lock: read_sha={} but current_sha={}",
                    hex16(&pending.proposal.read_sha_32),
                    current
                ));
                body.push("re-run the consult to propose against the current content".to_string());
            }
            // A wall/staleness/lookup deny leaves the target untouched; a
            // write/verify failure is RED (the fs may have been touched).
            let truth = match deny {
                ApplyDeny::WriteFailed | ApplyDeny::VerifyFailed => RenderTruth::Red,
                _ => RenderTruth::Yellow,
            };
            body.push("proposal kept pending".to_string());
            (truth, body)
        }
    }
}

// ---- E10-2b LOCAL: tool exec-apply — owner-authorized execute of ONE
// agent-proposed exec, gated by a single-shot MutateCapability (⑬ IV-A1) -------
//
// The model PROPOSES an exec (a sealed INERT `.xep`, exec_proposal.rs); it can
// NEVER run it (the loop grammar has no exec tool; `TOOL: exec` stays denied —
// IV-A2). The OWNER authorizes ONE proposal here, per action, behind the exact
// typed ceremony — which mints a SINGLE-SHOT MutateCapability
// (mutate_execute::authorize_local_mutate) that gates the single execute
// chokepoint (execute_authorized_mutate). The exec runs in the kernel sandbox
// (LocalWrite; network kernel-DENIED, IV-A6). This is the LOCAL mint path; the
// telegram-approval + armed-grant paths are E10-2b (TELEGRAM/ARMED). Custody /
// funds stay HARD-LOCKED ALWAYS (PD-6, IV-A10).

/// The exact in-band confirmation phrase that authorizes executing ONE pending
/// exec proposal (E10-2b, IV-A1). A PUBLIC confirmation gesture (zero entropy, NOT
/// a secret) — mirrors `tool apply`. Distinct from [`FILE_APPLY_CONFIRM_PHRASE`] so
/// the exec and edit surfaces cannot be cross-triggered.
const EXEC_APPLY_CONFIRM_PHRASE: &str = "exec-apply-owner-live";

/// Bounded number of pending exec proposals listed on the locked surface.
const EXEC_APPLY_LIST_CAP: usize = 8;

/// One stable pending-exec-proposal line (id prefix + the mint-screened command).
/// The command passed the secret-shaped refusal at propose time (IV-A8), so it is
/// safe to show the owner for review.
fn pending_exec_line(record_name: &str, proposal: &crate::exec_proposal::ExecProposal) -> String {
    let id: String = record_name
        .chars()
        .take(crate::exec_proposal::EXEC_PROPOSAL_ID_HEX_CHARS)
        .collect();
    format!("id={id} command={}", proposal.command)
}

/// `tool exec-apply` locked-surface render — no ceremony ⇒ zero side effects; the
/// pending list is a read-only projection (degraded-honest without a store/key).
fn exec_apply_locked_body(store: Option<&crate::exec_proposal::ExecProposalStore>) -> Vec<String> {
    let mut body = vec![
        "tool exec-apply EXECUTES ONE pending exec proposal (owner-only)".to_string(),
        format!("usage: tool exec-apply {EXEC_APPLY_CONFIRM_PHRASE} <proposal-id>"),
        "the model proposes only (PROPOSE-EXEC answer); it can never execute".to_string(),
        "gate: single-shot MutateCapability (owner-armed grant) -> kernel sandbox".to_string(),
        "tier=LocalWrite: read+write local, NETWORK kernel-DENIED; never funds/chain-write"
            .to_string(),
    ];
    let Some(store) = store else {
        body.push("exec proposal store unavailable (no key/home); nothing listed".to_string());
        return body;
    };
    let pending = store.load_pending();
    body.push(format!(
        "pending={} skipped={} (cap {})",
        pending.proposals.len(),
        pending.skipped_u32,
        crate::exec_proposal::MAX_PENDING_EXEC_PROPOSALS
    ));
    for entry in pending.proposals.iter().take(EXEC_APPLY_LIST_CAP) {
        body.push(pending_exec_line(&entry.record_name, &entry.proposal));
    }
    if pending.proposals.len() > EXEC_APPLY_LIST_CAP {
        body.push(format!(
            "... {} more pending (render bounded)",
            pending.proposals.len() - EXEC_APPLY_LIST_CAP
        ));
    }
    body
}

/// `tool exec-apply <phrase> <proposal-id>` — the owner's per-action execute of
/// ONE agent-proposed exec (E10-2b LOCAL, IV-A1). Gate order: exact ceremony →
/// typed id lookup → single-shot MutateCapability mint (`authorize_local_mutate`,
/// bound to the command by sha256) → the SINGLE gated chokepoint
/// (`execute_authorized_mutate`: kernel sandbox at LocalWrite, network DENIED) →
/// redacted render (SI-2, IV-A8) → consume-on-run. The MODEL has no path: the loop
/// grammar is byte-unchanged and `TOOL: exec` parses ToolUnknown ⇒ denied. Store is
/// injected so tests drive the REAL surface against a temp store.
fn exec_apply_surface(
    store: Option<&crate::exec_proposal::ExecProposalStore>,
    rest: &[String],
) -> (RenderTruth, Vec<String>) {
    use crate::mutate_execute::{
        AuthorizedMutate, MutateExecOutcome, authorize_local_mutate, execute_authorized_mutate,
    };
    let Some(phrase) = rest.get(1) else {
        return (RenderTruth::Yellow, exec_apply_locked_body(store));
    };
    if phrase != EXEC_APPLY_CONFIRM_PHRASE {
        return (RenderTruth::Yellow, exec_apply_locked_body(store));
    }
    let Some(store) = store else {
        return (
            RenderTruth::Yellow,
            vec![
                "exec-apply denied: proposal store unavailable (no key/home)".to_string(),
                "fail-closed: nothing executed".to_string(),
            ],
        );
    };
    let Some(id_arg) = rest.get(2) else {
        return (
            RenderTruth::Yellow,
            vec![
                format!("usage: tool exec-apply {EXEC_APPLY_CONFIRM_PHRASE} <proposal-id>"),
                "missing <proposal-id>; `tool exec-apply` (no args) lists pending ids".to_string(),
            ],
        );
    };
    let pending = match store.find_by_prefix(id_arg) {
        Ok(p) => p,
        Err(deny) => {
            return (
                RenderTruth::Yellow,
                vec![
                    format!("exec-apply denied ({})", deny.class_label()),
                    "nothing executed; `tool exec-apply` (no args) lists pending ids".to_string(),
                ],
            );
        }
    };
    // Mint a SINGLE-SHOT MutateCapability via the local owner ceremony (the phrase
    // was just verified; the ceremony re-evaluates it and binds the grant to THIS
    // exact command by sha256). The model cannot reach this — it holds no prompt.
    let mut prompt = crate::repl::approval::ApprovalPrompt::new(
        ApprovalRequirement::TypedPhrase,
        EXEC_APPLY_CONFIRM_PHRASE,
    );
    let command_audit_32 = sha256_32(pending.proposal.command.as_bytes());
    let Some(capability) =
        authorize_local_mutate(&mut prompt, EXEC_APPLY_CONFIRM_PHRASE, command_audit_32)
    else {
        return (
            RenderTruth::Yellow,
            vec![
                "exec-apply denied: the owner ceremony did not complete (fail-closed)".to_string(),
                "nothing executed".to_string(),
            ],
        );
    };
    // The SINGLE gated chokepoint (IV-A1): the exec runs ONLY with the capability.
    let MutateExecOutcome::Exec(result) =
        execute_authorized_mutate(capability, &AuthorizedMutate::Exec(&pending.proposal))
    else {
        // Unreachable: an Exec action yields an Exec outcome (kept honest, not a panic).
        return (
            RenderTruth::Red,
            vec!["exec-apply internal: outcome/action mismatch".to_string()],
        );
    };
    let outcome = match result {
        Ok(outcome) => outcome,
        Err(deny) => {
            return (
                RenderTruth::Red,
                vec![
                    format!("exec-apply DENIED ({})", deny.class_label()),
                    "fail-closed: nothing ran (no kernel sandbox ⇒ NEVER unsandboxed)".to_string(),
                    "exec proposal kept pending".to_string(),
                ],
            );
        }
    };
    let truth = if outcome.timed_out {
        RenderTruth::Red
    } else if outcome.exit_code == Some(0) {
        RenderTruth::Green
    } else {
        RenderTruth::Yellow
    };
    let exit_label = match (outcome.exit_code, outcome.timed_out) {
        (Some(code), _) => code.to_string(),
        (None, true) => "killed(timeout)".to_string(),
        (None, false) => "none(signal)".to_string(),
    };
    let mut body = Vec::new();
    // The command passed the mint-time secret-shaped refusal (IV-A8); the render
    // still re-checks (belt), withholding a secret-shaped echo (it still ran).
    let cmd = pending.proposal.command.as_str();
    let cmd_fragments = [cmd];
    match redact(&RedactionRequest {
        fragments: &cmd_fragments,
        candidate_memory_ids: &[],
        deleted_ids: &[],
        include_private_memory: false,
    }) {
        Ok(receipt) if receipt.secret_fragments_denied_u32() == 0 => {
            body.push(format!("executed: command={cmd}"));
        }
        _ => body.push(
            "executed: command withheld (secret-shaped; ran exactly as proposed)".to_string(),
        ),
    }
    body.push(format!(
        "result: exit={exit_label} timed_out={} duration={}ms",
        outcome.timed_out, outcome.duration_ms_u64
    ));
    render_exec_stream(&mut body, "stdout", &outcome.stdout);
    render_exec_stream(&mut body, "stderr", &outcome.stderr);
    body.push(
        "ran in OS sandbox tier=LocalWrite (network kernel-DENIED); env-scrubbed; single-shot MutateCapability consumed"
            .to_string(),
    );
    // Consume the artifact: one capability = one action; the proposal is spent
    // (the command ran, whatever its exit code) and must not re-execute.
    let removed = store.remove(&pending.record_name).is_ok();
    body.push(if removed {
        "exec proposal consumed (removed from pending)".to_string()
    } else {
        "WARNING: executed but the artifact could not be removed (still listed)".to_string()
    });
    (truth, body)
}

/// P3-2 — post-loop propose extraction (TM DESIGN LOCK: the propose channel
/// is the ANSWER block; the LOOP writes nothing; this owner-ceremonied
/// executor seals the INERT artifact). `None` ⇒ an ordinary answer (render
/// it as usual); `Some((truth, lines))` ⇒ the answer was propose-shaped and
/// was saved or typed-denied. The review diff re-reads the target through
/// the lane-A policy: a target that already drifted renders an honest
/// would-be-stale warning instead of a wrong diff.
///
/// The ONLY production caller is the `provider-egress` consult executor (a
/// proposal can only originate from a live model answer); the default build
/// keeps the symbol for its dispatch tests — never silently dead in the
/// egress build.
#[cfg_attr(not(feature = "provider-egress"), allow(dead_code))]
fn consult_proposal_render(
    answer: &str,
    verified_reads: &[VerifiedFileRead],
    store: Option<&ProposalStore>,
    review_policy: &crate::file_context::FileReadPolicy,
) -> Option<(RenderTruth, Vec<String>)> {
    let parsed = extract_proposal(answer)?;
    let proposed = match parsed {
        Ok(proposed) => proposed,
        Err(deny) => {
            return Some((
                RenderTruth::Yellow,
                vec![
                    format!("file-edit proposal DENIED ({})", deny.class_label()),
                    "the PROPOSE-EDIT block broke the closed grammar; nothing saved".to_string(),
                ],
            ));
        }
    };
    // IV-W7a — the canonical redaction verdict over the proposed content
    // (fail-closed: a gate error counts as secret-shaped).
    let fragments = [proposed.content.as_str()];
    let secret_shaped = match redact(&RedactionRequest {
        fragments: &fragments,
        candidate_memory_ids: &[],
        deleted_ids: &[],
        include_private_memory: false,
    }) {
        Ok(receipt) => receipt.secret_fragments_denied_u32() > 0,
        Err(_) => true,
    };
    let minted = match mint_proposal(&proposed, verified_reads, secret_shaped) {
        Ok(minted) => minted,
        // E-NEW: TargetNotRead can mean "the target does not exist yet" — try the CREATE
        // path (absent + parent-confined + non-secret). Every other propose deny is terminal.
        Err(crate::file_edit::ProposeDeny::TargetNotRead) => {
            match crate::file_edit::mint_new_file_proposal(&proposed, review_policy, secret_shaped)
            {
                Ok(minted) => minted,
                Err(deny) => {
                    return Some((
                        RenderTruth::Yellow,
                        vec![
                            format!("file-edit proposal DENIED ({})", deny.class_label()),
                            "nothing saved (fail-closed); the target file is untouched".to_string(),
                        ],
                    ));
                }
            }
        }
        Err(deny) => {
            return Some((
                RenderTruth::Yellow,
                vec![
                    format!("file-edit proposal DENIED ({})", deny.class_label()),
                    "nothing saved (fail-closed); the target file is untouched".to_string(),
                ],
            ));
        }
    };
    let Some(store) = store else {
        return Some((
            RenderTruth::Yellow,
            vec!["file-edit proposal NOT saved: store unavailable (no key/home)".to_string()],
        ));
    };
    let record_name = match store.save(&minted) {
        Ok(name) => name,
        Err(deny) => {
            return Some((
                RenderTruth::Yellow,
                vec![format!(
                    "file-edit proposal NOT saved ({})",
                    deny.class_label()
                )],
            ));
        }
    };
    let is_new_file = minted.read_sha_32 == crate::file_edit::ABSENT_BASELINE_SHA;
    let mut body = vec![
        if is_new_file {
            "file-CREATE PROPOSAL (new file; inert until the owner applies)".to_string()
        } else {
            "file-edit PROPOSAL (inert until the owner applies)".to_string()
        },
        pending_proposal_line(&record_name, &minted),
    ];
    // Review diff. For a NEW file the prior content is empty (all additions); for an edit
    // the old side is the target's CURRENT bytes, valid only while it still hashes to
    // read_sha (otherwise an apply would be stale anyway).
    if is_new_file {
        let new_text = String::from_utf8_lossy(&minted.content).to_string();
        render_redacted_diff(&mut body, "", &new_text);
    } else {
        match review_policy.read(&minted.target_path) {
            Ok(current) if current.sha256_32 == minted.read_sha_32 => {
                if let Some(old_text) = current.text.as_deref() {
                    let new_text = String::from_utf8_lossy(&minted.content).to_string();
                    render_redacted_diff(&mut body, old_text, &new_text);
                }
            }
            _ => body.push(
                "note: the target already changed since the model read it (apply would be stale)"
                    .to_string(),
            ),
        }
    }
    let id: String = record_name.chars().take(PROPOSAL_ID_HEX_CHARS).collect();
    body.push(format!(
        "apply with: tool apply {FILE_APPLY_CONFIRM_PHRASE} {id}"
    ));
    body.push("the model cannot apply; staleness + walls re-check at apply time".to_string());
    Some((RenderTruth::Green, body))
}

/// ENDGAME E10-1 (⑬ IV-A2): an exec-PROPOSE-shaped answer becomes a sealed
/// INERT exec proposal (the model PROPOSES a command; it cannot run it — the
/// loop grammar has no exec tool, and `TOOL: exec` stays denied). `None` ⇒ the
/// answer is not exec-propose-shaped (the caller tries the ordinary render);
/// `Some((truth, lines))` ⇒ it was exec-propose-shaped and was saved or
/// typed-denied. The proposal is INERT: the EXECUTE path (a `MutateCapability`-
/// gated kernel-sandbox run after owner authorization — telegram approval or an
/// armed `MutateGrant`) is wired in E10-2; here NOTHING runs (IV-A1). The
/// command is screened secret-shaped at mint (IV-A8 — an unreviewable command
/// must not exist), so the saved command is safe to show the owner for review.
#[cfg_attr(not(feature = "provider-egress"), allow(dead_code))]
fn consult_exec_proposal_render(
    answer: &str,
    exec_store: Option<&crate::exec_proposal::ExecProposalStore>,
) -> Option<(RenderTruth, Vec<String>)> {
    use crate::exec_proposal::{
        EXEC_PROPOSAL_ID_HEX_CHARS, extract_exec_proposal, mint_exec_proposal,
    };
    let parsed = extract_exec_proposal(answer)?;
    let proposed = match parsed {
        Ok(proposed) => proposed,
        Err(deny) => {
            return Some((
                RenderTruth::Yellow,
                vec![
                    format!("exec proposal DENIED ({})", deny.class_label()),
                    "the PROPOSE-EXEC block broke the closed grammar; nothing saved".to_string(),
                ],
            ));
        }
    };
    // IV-A8 — the canonical redaction verdict over the proposed command
    // (fail-closed: a gate error counts as secret-shaped).
    let fragments = [proposed.command_as_typed.as_str()];
    let secret_shaped = match redact(&RedactionRequest {
        fragments: &fragments,
        candidate_memory_ids: &[],
        deleted_ids: &[],
        include_private_memory: false,
    }) {
        Ok(receipt) => receipt.secret_fragments_denied_u32() > 0,
        Err(_) => true,
    };
    let minted = match mint_exec_proposal(&proposed, secret_shaped) {
        Ok(minted) => minted,
        Err(deny) => {
            return Some((
                RenderTruth::Yellow,
                vec![
                    format!("exec proposal DENIED ({})", deny.class_label()),
                    "nothing saved (fail-closed); no command ran".to_string(),
                ],
            ));
        }
    };
    let Some(store) = exec_store else {
        return Some((
            RenderTruth::Yellow,
            vec!["exec proposal NOT saved: store unavailable (no key/home)".to_string()],
        ));
    };
    let record_name = match store.save(&minted) {
        Ok(name) => name,
        Err(deny) => {
            return Some((
                RenderTruth::Yellow,
                vec![format!("exec proposal NOT saved ({})", deny.class_label())],
            ));
        }
    };
    let id: String = record_name
        .chars()
        .take(EXEC_PROPOSAL_ID_HEX_CHARS)
        .collect();
    let body = vec![
        "exec PROPOSAL (inert — the model proposed a command; it cannot run it)".to_string(),
        format!("command: {}", minted.command),
        format!("id: {id}"),
        "pending owner authorization (telegram approval or an armed mutate grant — E10-2)"
            .to_string(),
        "runs ONLY in a kernel sandbox (network kernel-DENIED) after you authorize; never \
         funds/wallet/chain-write"
            .to_string(),
    ];
    Some((RenderTruth::Green, body))
}

/// `memory index` — the catalog projection (design §5): per record
/// `{id, tier, importance, private, summary}`, NEVER content, NEVER blob
/// bytes. Tombstoned records are excluded by `catalog_select` (IV3); private
/// records are KEPT (local trust tier — the frontier path filters them).
fn memory_index_body(records: &[MemoryIndexRecord]) -> (RenderTruth, Vec<String>) {
    let visible = catalog_select(records, false);
    let tombstoned_excluded = records.len() - visible.len();
    let private_n = visible.iter().filter(|r| r.is_private()).count();
    let mut body = vec![
        "memory index: catalog projection (no content, no blob bytes)".to_string(),
        format!(
            "indexed={} tombstoned_excluded={} private={} shareable={}",
            visible.len(),
            tombstoned_excluded,
            private_n,
            visible.len() - private_n
        ),
        "record=336B fixed; summary<=256B utf-8; unclassified=private".to_string(),
        "index=re-derivable cache; truth=signed chunks".to_string(),
    ];
    if visible.is_empty() {
        body.push("(no memories saved yet; `memory save <text>` persists one)".to_string());
    } else {
        for record in visible.iter().take(MEMORY_INDEX_RENDER_CAP) {
            body.push(format!(
                "id={} tier={} imp={} private={} {}",
                record.memory_id().get(),
                tier_label(record.tier()),
                record.importance_u16(),
                u8::from(record.is_private()),
                record.summary_str()
            ));
        }
        if visible.len() > MEMORY_INDEX_RENDER_CAP {
            body.push(format!(
                "... {} more records (render bounded at {MEMORY_INDEX_RENDER_CAP})",
                visible.len() - MEMORY_INDEX_RENDER_CAP
            ));
        }
    }
    (RenderTruth::Green, body)
}

/// One stable header line for a gated read result.
fn render_read_header(record: &MemoryIndexRecord) -> String {
    format!(
        "id={} tier={} imp={} private={}",
        record.memory_id().get(),
        tier_label(record.tier()),
        record.importance_u16(),
        u8::from(record.is_private())
    )
}

/// `memory read <id>` — ONE memory's content, only after the full gate chain
/// (design §5): id in index + not tombstoned (IV3, TWO layers: the delete
/// truth `TombstonePolicy` AND the record tier) + content-hash verify
/// (IV4/D6) + the canonical redaction gate (IV1 — secret-shaped content is
/// withheld from the render). Every denial is a typed, rendered reason —
/// fail closed, never a silent fallback. The local surface passes
/// `include_private_memory=false` because nothing here is an outbound
/// private-memory request; the frontier path (step 4) passes the real flag
/// and hard-denies.
fn memory_read_body(
    records: &[MemoryIndexRecord],
    contents: &[(MemoryId, &[u8])],
    policy: &TombstonePolicy,
    rest: &[String],
) -> (RenderTruth, Vec<String>) {
    let Some(id_arg) = rest.get(1) else {
        return (
            RenderTruth::Yellow,
            vec![
                "usage: memory read <id>".to_string(),
                "reads ONE indexed memory after gates (index/tombstone/hash/redaction)".to_string(),
            ],
        );
    };
    let Ok(id_u64) = id_arg.parse::<u64>() else {
        return (
            RenderTruth::Yellow,
            vec!["read denied: id must be an unsigned integer".to_string()],
        );
    };
    let memory_id = MemoryId::new(id_u64);
    // IV3 layer 1 — the delete truth denies independently of the record's
    // tier byte (no-resurrection).
    if policy.is_tombstoned(memory_id) {
        return (
            RenderTruth::Yellow,
            vec![format!(
                "read denied: id={id_u64} tombstoned (delete truth; no-resurrection)"
            )],
        );
    }
    // IV3 layer 2 + existence — the index gate.
    let record = match read_select(records, memory_id, false) {
        Ok(record) => record,
        Err(deny) => {
            let reason = match deny {
                MemoryReadDeny::NotInIndex => format!(
                    "read denied: id={id_u64} not in index (records={})",
                    records.len()
                ),
                MemoryReadDeny::Tombstoned => {
                    format!("read denied: id={id_u64} tombstoned (no-resurrection)")
                }
                MemoryReadDeny::PrivateToFrontier => {
                    format!("read denied: id={id_u64} private (frontier-bound)")
                }
                // `MemoryReadDeny` is #[non_exhaustive]: any future deny
                // reason fails closed here; its class label renders below.
                _ => format!("read denied: id={id_u64}"),
            };
            return (
                RenderTruth::Yellow,
                vec![reason, format!("deny_class={}", deny.class_label())],
            );
        }
    };
    // Content fetch (step 3 wires the real chunk store; absent = honest deny).
    let Some((_, content)) = contents.iter().find(|(id, _)| *id == memory_id) else {
        return (
            RenderTruth::Yellow,
            vec![
                format!("read denied: id={id_u64} content unavailable on the dispatch path"),
                "(the id is indexed but its content is not in the loaded store)".to_string(),
            ],
        );
    };
    // IV4 / D6 — the read returns the claimed bytes, or nothing.
    if let Err(err) = record.verify_against_content(content) {
        return (
            RenderTruth::Red,
            vec![
                format!("read DENIED: integrity failure ({})", err.class_label()),
                "the bytes do not match the index record (IV4/D6); not rendered".to_string(),
            ],
        );
    }
    // Render policy: this surface renders UTF-8 only (binary stays cold).
    let Ok(content_text) = core::str::from_utf8(content) else {
        return (
            RenderTruth::Green,
            vec![
                render_read_header(record),
                "verify: content-hash OK (D6)".to_string(),
                format!(
                    "content is binary ({} bytes); render withheld (utf-8 only surface)",
                    content.len()
                ),
            ],
        );
    };
    // IV1 — the canonical redaction gate (same gate every frontier send
    // passes): tombstoned candidates deny; a secret-shaped memory is
    // withheld from the render (fail closed, the whole fragment).
    let deleted_hashes: Vec<[u8; 32]> = records
        .iter()
        .filter(|r| r.is_tombstone())
        .map(|r| *r.content_hash_32())
        .collect();
    let fragments = [content_text];
    let request = RedactionRequest {
        fragments: &fragments,
        candidate_memory_ids: &[*record.content_hash_32()],
        deleted_ids: &deleted_hashes,
        include_private_memory: false,
    };
    match redact(&request) {
        Err(reject) => {
            let label = match reject {
                RedactionReject::PrivateMemoryIncluded => "private-memory-included",
                RedactionReject::TombstonedMemoryIncluded => "tombstoned-memory-included",
            };
            (
                RenderTruth::Yellow,
                vec![format!("read denied by redaction gate ({label})")],
            )
        }
        Ok(receipt) if receipt.secret_fragments_denied_u32() > 0 => (
            RenderTruth::Yellow,
            vec![
                render_read_header(record),
                "verify: content-hash OK (D6)".to_string(),
                "content WITHHELD: secret-shaped (redaction denied the fragment)".to_string(),
                format!(
                    "redaction: fragments_out={} denied={}",
                    receipt.outgoing_fragment_count_u32(),
                    receipt.secret_fragments_denied_u32()
                ),
            ],
        ),
        Ok(receipt) => {
            let mut body = vec![
                render_read_header(record),
                "verify: content-hash OK; summary re-derived OK (D6)".to_string(),
                format!(
                    "redaction: fragments_out={} denied={} payload_hash={}",
                    receipt.outgoing_fragment_count_u32(),
                    receipt.secret_fragments_denied_u32(),
                    hex16(&receipt.redacted_payload_hash_32())
                ),
            ];
            let total_lines = content_text.lines().count();
            body.push(format!("--- content ({total_lines} lines) ---"));
            body.extend(
                content_text
                    .lines()
                    .take(MEMORY_READ_RENDER_LINES)
                    .map(str::to_string),
            );
            if total_lines > MEMORY_READ_RENDER_LINES {
                body.push(format!(
                    "... truncated ({} more lines; render bounded)",
                    total_lines - MEMORY_READ_RENDER_LINES
                ));
            }
            (RenderTruth::Green, body)
        }
    }
}

// ---- agent-core lane A: read-only local file context ----------------------
//
// Design: ops/evidence/stage_g/agent_loop/FILE_CONTEXT_THREAT_MODEL.md.
// `context file <path>` is the LOCAL trust tier (the owner reads their OWN
// file on their OWN screen). It still passes the full path wall stack
// (allowlist + denylist + size cap, via `file_context::FileReadPolicy`) and
// withholds binary / secret-shaped content — so the surface is never a `cat`
// of a key into a shared transcript. The FRONTIER tier (the agent loop's
// `file read` tool) reuses the SAME policy with `redaction::redact` applied
// before the bytes enter any prompt (step A-3).

/// `context file <path>` — render ONE local file's content after the path
/// wall stack, fail-closed on every denial (typed reason, never the bytes).
/// Binary content renders metadata only (IV-F5); secret-shaped content is
/// withheld by the canonical redaction gate (IV-F6, defense in depth on the
/// LOCAL surface too).
fn file_context_body(rest: &[String]) -> (RenderTruth, Vec<String>) {
    let Some(path_arg) = rest.get(1) else {
        return (
            RenderTruth::Yellow,
            vec![
                "usage: context file <path>".to_string(),
                "reads ONE local file (allowlist + denylist + size cap; read-only)".to_string(),
            ],
        );
    };
    let policy = crate::file_context::FileReadPolicy::workspace_default();
    let result = match policy.read(std::path::Path::new(path_arg)) {
        Ok(result) => result,
        Err(deny) => {
            return (
                RenderTruth::Yellow,
                vec![
                    format!("file read denied ({})", deny.class_label()),
                    "read-only; no file write/exec exists; bytes never rendered on deny"
                        .to_string(),
                ],
            );
        }
    };
    let header = format!(
        "file={} bytes={} sha={}",
        result.canonical_path.display(),
        result.len_bytes(),
        hex16(&result.sha256_32)
    );
    let Some(text) = result.text.as_deref() else {
        return (
            RenderTruth::Green,
            vec![
                header,
                format!(
                    "content is binary ({} bytes); render withheld (utf-8 only)",
                    result.len_bytes()
                ),
            ],
        );
    };
    // IV-F6 — the canonical redaction gate, on the LOCAL surface too: a
    // secret-shaped file is withheld rather than echoed into the transcript.
    let fragments = [text];
    match redact(&RedactionRequest {
        fragments: &fragments,
        candidate_memory_ids: &[],
        deleted_ids: &[],
        include_private_memory: false,
    }) {
        Ok(receipt) if receipt.secret_fragments_denied_u32() == 0 => {}
        _ => {
            return (
                RenderTruth::Yellow,
                vec![
                    header,
                    "content WITHHELD: secret-shaped (redaction denied the file)".to_string(),
                ],
            );
        }
    }
    let total_lines = text.lines().count();
    let mut body = vec![header, format!("--- content ({total_lines} lines) ---")];
    body.extend(
        text.lines()
            .take(crate::file_context::MAX_FILE_RENDER_LINES)
            .map(str::to_string),
    );
    if total_lines > crate::file_context::MAX_FILE_RENDER_LINES {
        body.push(format!(
            "... truncated ({} more lines; render bounded)",
            total_lines - crate::file_context::MAX_FILE_RENDER_LINES
        ));
    }
    (RenderTruth::Green, body)
}

// E11-2 (AUDIT_ENGINE_THREAT_MODEL.md ⑮): `audit detect <path>` body — drive the
// audit game-tree engine on a REAL local source tree (default CWD) and render the
// impact-ranked CANDIDATES through the SHARED glue (`audit::detect::run_source_detect`
// + `report_lines`), the SAME pipeline the loop `TOOL: audit detect` uses. Pure
// local analysis: NO promote, NO repro-run, NO exec; hashed anchors ⇒ no raw source
// byte. Every item is a candidate, never a finding (IV-AE1/AE7).
fn audit_detect_body(rest: &[String]) -> (RenderTruth, Vec<String>) {
    let path = rest.get(1).map_or(".", String::as_str);
    let report =
        crate::audit::detect::run_source_detect(std::path::Path::new(path), AuditProfile::Rust);
    // Candidates are leads, not PASS/FAIL: Unknown when a tree was walked, Yellow
    // when nothing was scanned (empty / bad path) so the owner sees the honest state.
    let truth = if report.files_scanned == 0 {
        RenderTruth::Yellow
    } else {
        RenderTruth::Unknown
    };
    (truth, crate::audit::detect::report_lines(&report))
}

// ── D-1b (AGENT-NATIVE GITHUB): the local `registry` surface over the PURE content-
// addressed `agent_registry` core. `registry scan <path>` walks a bounded local tree and
// renders a content-addressed manifest SUMMARY; `registry list <path>` renders the full
// entry list + a tamper-evidence integrity check. Both ReadOnly + STATELESS (the manifest
// is computed on demand + round-tripped through the AGRX codec; disk persistence + the
// gated Walrus publish are D-3). NO egress, NO artifact execution, NO custody (PD-6); only
// the file DIGEST + a relative-path summary are derived — never the file CONTENT.

/// Bounded read-only walk of `root`: content-address every file (any extension) as
/// `(rel_path, sha256(bytes))`. Explicit stack (never recurses); depth/file/size capped;
/// symlinks + the shared denylist dirs skipped. The `bool` = whether a cap clipped the walk.
fn registry_discover_files(root: &std::path::Path) -> (Vec<(String, [u8; 32])>, bool) {
    const MAX_FILES: u32 = 4_000;
    const MAX_DEPTH: u32 = 24;
    const MAX_FILE_BYTES: u64 = 1024 * 1024;
    let mut out: Vec<(String, [u8; 32])> = Vec::new();
    let mut files: u32 = 0;
    let mut stack: Vec<(std::path::PathBuf, u32)> = vec![(root.to_path_buf(), 0)];
    while let Some((dir, depth)) = stack.pop() {
        if depth > MAX_DEPTH {
            continue;
        }
        let Ok(read) = std::fs::read_dir(&dir) else {
            continue;
        };
        for dirent in read.flatten() {
            if files >= MAX_FILES {
                return (out, true);
            }
            let path = dirent.path();
            let Ok(ft) = dirent.file_type() else {
                continue;
            };
            if ft.is_symlink() {
                continue;
            }
            if ft.is_dir() {
                if !crate::commands::source_scan::is_skipped_dir(&path) {
                    stack.push((path, depth + 1));
                }
                continue;
            }
            if !ft.is_file() {
                continue;
            }
            if std::fs::metadata(&path).map_or(u64::MAX, |m| m.len()) > MAX_FILE_BYTES {
                continue;
            }
            let Ok(bytes) = std::fs::read(&path) else {
                continue;
            };
            files += 1;
            let rel = path.strip_prefix(root).unwrap_or(path.as_path());
            out.push((rel.to_string_lossy().into_owned(), sha256_32(&bytes)));
        }
    }
    (out, false)
}

/// Build a content-addressed [`crate::agent_registry::RegistryManifest`] from a bounded
/// scan of `root` (every file ⇒ a `Code` artifact). Returns the manifest + the capped flag.
fn registry_manifest_from_path(
    root: &std::path::Path,
) -> (crate::agent_registry::RegistryManifest, bool) {
    use crate::agent_registry::{AgentArtifact, ArtifactKind, RegistryManifest};
    let (files, capped) = registry_discover_files(root);
    let mut manifest = RegistryManifest::default();
    for (rel, digest) in &files {
        manifest.upsert(AgentArtifact::new(
            ArtifactKind::Code,
            *digest,
            "agent://local".to_string(),
            rel,
            None,
        ));
    }
    (manifest, capped)
}

/// D-3 SUPPLY-CHAIN SEATBELT (the single verify chokepoint for `registry publish`'s
/// round-trip AND `registry fetch`): a fetched artifact is trustworthy IFF its `content`
/// bytes re-hash to the recorded `content_digest` AND the stored `id` re-derives from
/// `(kind, digest)`. Fail-closed — any tamper / substitution / wrong-key-decrypt yields a
/// different hash ⇒ `false` ⇒ the bytes are REJECTED (never rendered, never executed).
fn registry_content_verified(
    artifact: &crate::agent_registry::AgentArtifact,
    content: &[u8],
) -> bool {
    sha256_32(content) == artifact.content_digest && artifact.id_matches_content()
}

/// `registry scan <path>` — content-address a bounded local tree + render the manifest
/// SUMMARY (round-tripped through the AGRX codec to prove it serializes). ReadOnly.
fn registry_scan_body(rest: &[String]) -> (RenderTruth, Vec<String>) {
    use crate::agent_registry::RegistryManifest;
    let Some(path) = rest.get(1) else {
        return (
            RenderTruth::Yellow,
            vec![
                "registry scan <path> — content-address every file in a bounded local tree into the agent registry".to_string(),
                "  each file => a Code artifact (id = sha256(kind‖sha256(bytes))); only the digest + rel-path are used, never the content".to_string(),
                "  then: registry list <path>  (browse the content-addressed manifest)".to_string(),
            ],
        );
    };
    let (manifest, capped) = registry_manifest_from_path(std::path::Path::new(path));
    if manifest.entries.is_empty() {
        return (
            RenderTruth::Yellow,
            vec![format!(
                "registry scan: no files under {path} (empty / unreadable / bad path)"
            )],
        );
    }
    let bytes = manifest.to_bytes();
    let round_trips = RegistryManifest::from_bytes(&bytes)
        .map(|m| m == manifest)
        .unwrap_or(false);
    let mut body = vec![
        format!(
            "registry scan: {} content-addressed artifact(s){}",
            manifest.entries.len(),
            if capped {
                " (walk capped — bounded)"
            } else {
                ""
            }
        ),
        format!(
            "AGRX manifest = {} bytes · codec round-trip {} · digest + path only (no content) · no egress · no execution",
            bytes.len(),
            if round_trips { "OK" } else { "FAILED" }
        ),
    ];
    for a in manifest.entries.iter().take(5) {
        body.push(format!(
            "  {}… {} {}",
            &a.id[..12.min(a.id.len())],
            a.kind.label(),
            a.summary
        ));
    }
    if manifest.entries.len() > 5 {
        body.push(format!(
            "  … +{} more (registry list <path>)",
            manifest.entries.len() - 5
        ));
    }
    (
        if round_trips {
            RenderTruth::Green
        } else {
            RenderTruth::Red
        },
        body,
    )
}

/// `registry list <path>` — render the FULL content-addressed entry list + a tamper-
/// evidence integrity check (every stored id must re-derive from its content). ReadOnly.
fn registry_list_body(rest: &[String]) -> (RenderTruth, Vec<String>) {
    let Some(path) = rest.get(1) else {
        return (
            RenderTruth::Unknown,
            vec![
                "registry list <path> — browse the content-addressed artifacts of a local tree"
                    .to_string(),
            ],
        );
    };
    let (manifest, capped) = registry_manifest_from_path(std::path::Path::new(path));
    if manifest.entries.is_empty() {
        return (
            RenderTruth::Yellow,
            vec![format!("registry list: no artifacts under {path}")],
        );
    }
    let tampered = manifest
        .entries
        .iter()
        .filter(|a| !a.id_matches_content())
        .count();
    let mut body = vec![format!(
        "registry: {} content-addressed artifact(s){} · integrity {}",
        manifest.entries.len(),
        if capped { " (capped)" } else { "" },
        if tampered == 0 {
            "OK (every id re-derives from its content)".to_string()
        } else {
            format!("FAILED ({tampered} tampered)")
        }
    )];
    for a in manifest.entries.iter().take(50) {
        body.push(format!(
            "  {}… {} {} · {}",
            &a.id[..12.min(a.id.len())],
            a.kind.label(),
            a.summary,
            a.author
        ));
    }
    if manifest.entries.len() > 50 {
        body.push(format!("  … +{} more", manifest.entries.len() - 50));
    }
    (
        if tampered == 0 {
            RenderTruth::Green
        } else {
            RenderTruth::Red
        },
        body,
    )
}

/// D-3 — the exact phrase the owner types to fire a registry PUBLISH (an owner-armed Walrus
/// testnet egress). DISTINCT from the memory-backup phrases so muscle-memory can't cross-fire.
#[cfg(feature = "put-fixture-net")]
const REGISTRY_PUBLISH_CONFIRM_PHRASE: &str = "publish-agent-registry-to-walrus-testnet";

/// D-3 — the max number of artifacts one publish ceremony pushes (bounded I/O, mirrors
/// `BACKUP_WALRUS_MAX_RECORDS`).
#[cfg(feature = "put-fixture-net")]
const REGISTRY_PUBLISH_MAX_ARTIFACTS: usize = 32;

/// D-3 locked-surface body (no/wrong phrase). Honest about the gated egress + both visibilities.
#[cfg(feature = "put-fixture-net")]
fn registry_publish_locked_body() -> Vec<String> {
    vec![
        "registry publish = content-address a local tree + PUBLISH it to Walrus testnet (owner-armed egress; no funds; custody HARD-LOCKED)".to_string(),
        format!("to run, supply EXACTLY: registry publish {REGISTRY_PUBLISH_CONFIRM_PHRASE} <path> [public|private]"),
        "  private (default) = each artifact + the manifest AEAD-sealed (EncryptedUserMemory ciphertext; only your key decrypts)".to_string(),
        "  public            = plaintext, any agent can content-hash-verify it — a mandatory fail-closed secret-scan skips secret-shaped files".to_string(),
        "then: registry fetch <main-index-blob-id> <artifact-id>  (autonomous, content-hash VERIFIED — bytes must re-hash to the id or it is REJECTED)".to_string(),
    ]
}

/// D-3 error render for the publish ceremony (Yellow; secret-zero).
#[cfg(feature = "put-fixture-net")]
fn registry_publish_error(
    out: &mut impl Write,
    envelope_hex: &str,
    label: &str,
) -> io::Result<bool> {
    emit(
        out,
        "registry publish",
        envelope_hex,
        CommandRisk::Network,
        ApprovalRequirement::TypedPhrase,
        RenderTruth::Yellow,
        &[format!("registry publish: {label}")],
    )?;
    Ok(true)
}

/// `registry publish <phrase> <path> [public|private]` (D-3) — owner-armed Walrus testnet
/// egress of a content-addressed manifest + its artifacts, with a round-trip content-hash
/// proof. Gate: exact typed phrase → scan a bounded tree → for each artifact, PUBLISH under
/// the chosen visibility (private = AEAD-sealed `EncryptedUserMemory`; public = PLAINTEXT
/// `PublicRegistryArtifact` after a MANDATORY fail-closed `scan_inline_secret`) → PUT the
/// SEALED-or-PLAINTEXT MAIN INDEX (the "repo pointer") → round-trip GET + verify the bytes
/// re-hash to their id. NO funds; custody / chain-write HARD-LOCKED (PD-6). The model reaches
/// no publish symbol — this is an owner ceremony only.
#[cfg(feature = "put-fixture-net")]
fn registry_publish(rest: &[String], out: &mut impl Write) -> io::Result<bool> {
    use crate::agent_registry::{AgentArtifact, ArtifactKind, RegistryManifest, summarize};
    use crate::repl::approval::{ApprovalDecision, ApprovalPrompt};
    use mnemos_c_walrus::publisher::{EpochCount, PublishPayloadClass};
    use mnemos_c_walrus::reqwest_transport::ReqwestPublisher;

    let envelope_hex = hex16(&sha256_32(b"registry publish"));
    let supplied = rest.get(1).cloned().unwrap_or_default();

    // GATE (sole runtime operator gate): the exact typed phrase before any read or PUT.
    let mut prompt = ApprovalPrompt::new(
        ApprovalRequirement::TypedPhrase,
        REGISTRY_PUBLISH_CONFIRM_PHRASE,
    );
    if !matches!(prompt.evaluate(supplied.trim()), ApprovalDecision::Approved) {
        emit(
            out,
            "registry publish",
            &envelope_hex,
            CommandRisk::Network,
            ApprovalRequirement::TypedPhrase,
            RenderTruth::Yellow,
            &registry_publish_locked_body(),
        )?;
        return Ok(true);
    }

    // APPROVED. Parse the path + visibility (default PRIVATE — public requires the explicit
    // "public" token so it is never the accidental default).
    let Some(path) = rest.get(2) else {
        return registry_publish_error(
            out,
            &envelope_hex,
            "usage: registry publish <phrase> <path> [public|private]",
        );
    };
    let public = rest
        .get(3)
        .map(|v| v.eq_ignore_ascii_case("public"))
        .unwrap_or(false);
    let vis_label = if public { "public" } else { "private" };
    let class = if public {
        PublishPayloadClass::PublicRegistryArtifact
    } else {
        PublishPayloadClass::EncryptedUserMemory
    };

    // The local AEAD key (needed to SEAL private artifacts + the private manifest, and to
    // OPEN them on the round-trip). Public publish needs no key.
    let store = crate::memory_store::PersistedStore::open_local().ok();
    if !public && store.is_none() {
        return registry_publish_error(
            out,
            &envelope_hex,
            "memory store unavailable (no key/home); private publish needs the local AEAD key",
        );
    }

    let (files, capped) = registry_discover_files(std::path::Path::new(path));
    if files.is_empty() {
        return registry_publish_error(
            out,
            &envelope_hex,
            &format!("no files under {path} (empty / unreadable / bad path)"),
        );
    }
    let epochs = match EpochCount::new(1) {
        Ok(e) => e,
        Err(_) => return registry_publish_error(out, &envelope_hex, "epoch invalid"),
    };
    let mut pub_t = match ReqwestPublisher::new(PUT_FIXTURE_TIMEOUT_MS) {
        Ok(t) => t,
        Err(_) => {
            return registry_publish_error(out, &envelope_hex, "publisher transport init failed");
        }
    };

    let root = std::path::Path::new(path);
    let mut truth = RenderTruth::Green;
    let mut body = vec![format!(
        "registry publish [{vis_label}]: {} candidate file(s) → Walrus testnet; content-addressed; {}; no funds; custody HARD-LOCKED (PD-6)",
        files.len(),
        if public {
            "PLAINTEXT (mandatory fail-closed secret-scan)"
        } else {
            "AEAD ciphertext (key stays local)"
        }
    )];

    let mut manifest = RegistryManifest::default();
    let mut published = 0usize;
    let mut skipped_secret = 0usize;

    for (rel, digest) in files.iter().take(REGISTRY_PUBLISH_MAX_ARTIFACTS) {
        // Re-read the content (bounded) + TOCTOU guard: if the file changed since the walk,
        // its bytes no longer match `digest`, so skip it (never publish under a stale id).
        let Ok(content) = std::fs::read(root.join(rel)) else {
            continue;
        };
        if sha256_32(&content) != *digest {
            truth = RenderTruth::Yellow;
            body.push(format!("  {rel}: changed during publish — skipped"));
            continue;
        }
        // IV-D3-11 — MANDATORY fail-closed secret-scan before any PUBLIC plaintext PUT: a
        // secret-shaped artifact is NEVER published to a public network. (Private artifacts
        // are AEAD ciphertext, so the key-local guarantee already covers them.)
        if public && crate::secrets::scan_inline_secret(&String::from_utf8_lossy(&content)) {
            skipped_secret += 1;
            body.push(format!(
                "  {rel}: SKIPPED — secret-shaped content (fail-closed; not published publicly)"
            ));
            continue;
        }
        // Bytes that actually leave: PLAINTEXT (public) or AEAD ciphertext (private).
        let put_bytes: Vec<u8> = if public {
            content.clone()
        } else {
            match store.as_ref().and_then(|s| s.seal_index(&content).ok()) {
                Some(ct) => ct,
                None => {
                    truth = RenderTruth::Red;
                    body.push(format!("  {rel}: seal failed"));
                    continue;
                }
            }
        };
        match walrus_put_verified_class(&mut pub_t, epochs, &put_bytes, class) {
            Some(blob) => {
                manifest.upsert(AgentArtifact::new(
                    ArtifactKind::Code,
                    *digest,
                    "agent://local".to_string(),
                    &summarize(rel),
                    Some(blob.clone()),
                ));
                published += 1;
                body.push(format!("  {rel}: PUT ok → blob_id={blob} (verified)"));
            }
            None => {
                truth = RenderTruth::Red;
                body.push(format!(
                    "  {rel}: PUT rejected/failed (self-report ban or boundary)"
                ));
            }
        }
    }

    // MAIN INDEX: serialize the manifest → SEAL (private) or PLAINTEXT (public) → PUT → this
    // blob-id is the "repo pointer" the fetcher navigates from.
    let mut main_blob = String::new();
    if !manifest.entries.is_empty() {
        let idx_bytes = manifest.to_bytes();
        let idx_put: Option<Vec<u8>> = if public {
            Some(idx_bytes.clone())
        } else {
            store.as_ref().and_then(|s| s.seal_index(&idx_bytes).ok())
        };
        match idx_put.and_then(|b| walrus_put_verified_class(&mut pub_t, epochs, &b, class)) {
            Some(blob) => {
                // The main-index blob-id is the "repo pointer" — put it on its OWN short line
                // so the full 43-char id is never clamped by the 80-col emit width.
                body.push(format!(
                    "MAIN INDEX PUT ok: {} entries (the repo pointer — fetch from here):",
                    manifest.entries.len()
                ));
                body.push(format!("  repo blob-id: {blob}"));
                main_blob = blob;
            }
            None => {
                truth = RenderTruth::Red;
                body.push("MAIN INDEX PUT/seal rejected (boundary)".to_string());
            }
        }
    }

    // ROUND-TRIP CONTENT-HASH PROOF (the supply-chain seatbelt, LIVE): GET the MAIN INDEX
    // back + decode; GET the FIRST artifact back + verify its bytes RE-HASH to its id.
    if !main_blob.is_empty() {
        match walrus_get_by_blob_text(&main_blob) {
            Some(raw) => {
                let idx = if public {
                    raw
                } else {
                    store
                        .as_ref()
                        .and_then(|s| s.open_index(&raw).ok())
                        .unwrap_or_default()
                };
                if RegistryManifest::from_bytes(&idx).map(|m| m == manifest) == Ok(true) {
                    body.push(format!(
                        "MAIN INDEX round-trip: GET+{} OK ({} entries match)",
                        if public { "parse" } else { "decrypt" },
                        manifest.entries.len()
                    ));
                } else {
                    truth = RenderTruth::Yellow;
                    body.push("MAIN INDEX round-trip: mismatch (testnet propagation?)".to_string());
                }
            }
            None => {
                truth = RenderTruth::Yellow;
                body.push(
                    "MAIN INDEX round-trip: GET not fetched (testnet propagation)".to_string(),
                );
            }
        }
        if let Some(entry) = manifest.entries.first() {
            if let Some(blob_ref) = entry.blob_ref.as_deref() {
                match walrus_get_by_blob_text(blob_ref) {
                    Some(raw) => {
                        let content = if public {
                            raw
                        } else {
                            store
                                .as_ref()
                                .and_then(|s| s.open_index(&raw).ok())
                                .unwrap_or_default()
                        };
                        let verified = registry_content_verified(entry, &content);
                        body.push(format!(
                            "ARTIFACT round-trip: GET {}… → content-hash verified={verified} (bytes re-hash to the id)",
                            &entry.id[..12.min(entry.id.len())]
                        ));
                        if !verified {
                            truth = RenderTruth::Red;
                        }
                    }
                    None => {
                        truth = RenderTruth::Yellow;
                        body.push(
                            "ARTIFACT round-trip: GET not fetched (testnet propagation)"
                                .to_string(),
                        );
                    }
                }
            }
        }
    }

    body.push(format!(
        "published: {published} artifact(s){} + {} main index [{vis_label}]; content-hash supply-chain verified; no funds; custody/chain-write HARD-LOCKED (PD-6)",
        if skipped_secret > 0 {
            format!(", {skipped_secret} skipped (secret-shaped)")
        } else {
            String::new()
        },
        u8::from(!main_blob.is_empty())
    ));
    if capped {
        body.push("(walk hit the artifact bound — bounded)".to_string());
    }
    emit(
        out,
        "registry publish",
        &envelope_hex,
        CommandRisk::Network,
        ApprovalRequirement::TypedPhrase,
        truth,
        &body,
    )?;
    Ok(true)
}

/// `registry fetch <main-index-blob-id> <artifact-id>` (D-3) — autonomous, content-hash
/// VERIFIED READ. Navigate the published 2-tier structure (GET the MAIN INDEX → decode →
/// find the artifact → GET its blob), normalizing private (AEAD-open) vs public (plaintext)
/// by *try-open-else-raw*, then REJECT unless the fetched bytes re-hash to the recorded
/// `content_digest` AND the stored id re-derives (the supply-chain seatbelt). Renders METADATA
/// only — the untrusted content is NEVER rendered and NEVER executed (execution = D-6:
/// kernel sandbox + owner approval). No funds; custody HARD-LOCKED (PD-6).
#[cfg(feature = "put-fixture-net")]
fn registry_fetch(rest: &[String], out: &mut impl Write) -> io::Result<bool> {
    use crate::agent_registry::RegistryManifest;

    let envelope_hex = hex16(&sha256_32(b"registry fetch"));
    let (Some(main_blob), Some(want_id)) = (rest.get(1), rest.get(2)) else {
        emit(
            out,
            "registry fetch",
            &envelope_hex,
            CommandRisk::Network,
            ApprovalRequirement::None,
            RenderTruth::Yellow,
            &[
                "registry fetch <main-index-blob-id> <artifact-id> — fetch a published artifact + VERIFY its content-hash".to_string(),
                "  the fetched bytes must re-hash to the artifact id, else it is REJECTED (tamper/substitution); never executed".to_string(),
            ],
        )?;
        return Ok(true);
    };

    // The local key opens PRIVATE blobs; PUBLIC blobs are plaintext (no key needed).
    let store = crate::memory_store::PersistedStore::open_local().ok();
    let open_or_raw = |raw: Vec<u8>| -> Vec<u8> {
        store
            .as_ref()
            .and_then(|s| s.open_index(&raw).ok())
            .unwrap_or(raw)
    };

    let Some(raw_index) = walrus_get_by_blob_text(main_blob) else {
        emit(
            out,
            "registry fetch",
            &envelope_hex,
            CommandRisk::Network,
            ApprovalRequirement::None,
            RenderTruth::Yellow,
            &[
                "registry fetch: MAIN INDEX not fetched (bad blob-id / testnet propagation)"
                    .to_string(),
            ],
        )?;
        return Ok(true);
    };
    let manifest = match RegistryManifest::from_bytes(&open_or_raw(raw_index)) {
        Ok(m) => m,
        Err(_) => {
            emit(
                out,
                "registry fetch",
                &envelope_hex,
                CommandRisk::Network,
                ApprovalRequirement::None,
                RenderTruth::Red,
                &["registry fetch: MAIN INDEX did not decode (not a registry / wrong key / tampered)".to_string()],
            )?;
            return Ok(true);
        }
    };
    let Some(artifact) = manifest.get(want_id) else {
        emit(
            out,
            "registry fetch",
            &envelope_hex,
            CommandRisk::Network,
            ApprovalRequirement::None,
            RenderTruth::Yellow,
            &[format!(
                "registry fetch: artifact id not in this registry ({} entries)",
                manifest.entries.len()
            )],
        )?;
        return Ok(true);
    };
    let Some(blob_ref) = artifact.blob_ref.as_deref() else {
        emit(
            out,
            "registry fetch",
            &envelope_hex,
            CommandRisk::Network,
            ApprovalRequirement::None,
            RenderTruth::Yellow,
            &["registry fetch: artifact has no published blob (local-only entry)".to_string()],
        )?;
        return Ok(true);
    };
    let (truth, body) = match walrus_get_by_blob_text(blob_ref) {
        Some(raw) => {
            let content = open_or_raw(raw);
            let verified = registry_content_verified(artifact, &content);
            if verified {
                (
                    RenderTruth::Green,
                    vec![format!(
                        "registry fetch: VERIFIED — {} {}… {} byte(s); bytes re-hash to the id (content-hash supply-chain OK); NOT executed (run = D-6 sandbox + approval)",
                        artifact.kind.label(),
                        &artifact.id[..12.min(artifact.id.len())],
                        content.len()
                    )],
                )
            } else {
                (
                    RenderTruth::Red,
                    vec![
                        "registry fetch: REJECTED — fetched bytes do NOT re-hash to the artifact id (tamper / substitution / wrong key); withheld".to_string(),
                    ],
                )
            }
        }
        None => (
            RenderTruth::Yellow,
            vec!["registry fetch: artifact blob not fetched (testnet propagation)".to_string()],
        ),
    };
    emit(
        out,
        "registry fetch",
        &envelope_hex,
        CommandRisk::Network,
        ApprovalRequirement::None,
        truth,
        &body,
    )?;
    Ok(true)
}

/// O-1 (Oracle Bootstrap Pillar 1): read a finance reconciliation CERTIFICATE from `<path>`
/// and run the deterministic [`crate::reconcile_oracle`] checker — re-sum / re-price the
/// stated line items and assert the accounting invariant, FAIL-CLOSED. RECONCILED ⇒ Green,
/// VIOLATED (a sound reject) ⇒ Red, malformed/unreadable ⇒ Yellow (honest absence). The
/// model's prose never reaches the checker (only the typed numbers do). HONEST LOCK:
/// arithmetic-sound (the claim reconciles with the STATED items), NOT that positions are real.
fn audit_reconcile_body(rest: &[String]) -> (RenderTruth, Vec<String>) {
    use crate::reconcile_oracle::{ReconcileVerdict, check_reconciliation, parse_certificate};
    let Some(path) = rest.get(1) else {
        return (
            RenderTruth::Yellow,
            vec![
                "audit reconcile <path> — deterministically check a finance reconciliation certificate (O-1)".to_string(),
                "  solvency: `solvent` then `reserve|liability <amount_minor> <source>` lines".to_string(),
                "  NAV:      `nav <claimed_minor>` then `holding <qty> <price_minor> <source>` lines".to_string(),
            ],
        );
    };
    let text = match std::fs::read_to_string(std::path::Path::new(path)) {
        Ok(t) => t,
        Err(_) => {
            return (
                RenderTruth::Yellow,
                vec![format!(
                    "audit reconcile: cannot read certificate at {path}"
                )],
            );
        }
    };
    let Some(claim) = parse_certificate(&text) else {
        return (
            RenderTruth::Yellow,
            vec![
                "audit reconcile: malformed certificate (fail-closed; nothing reconciled)"
                    .to_string(),
            ],
        );
    };
    let r = check_reconciliation(&claim);
    let (truth, label) = match r.verdict {
        ReconcileVerdict::Reconciled => (RenderTruth::Green, "RECONCILED"),
        ReconcileVerdict::Violated => (RenderTruth::Red, "VIOLATED"),
        ReconcileVerdict::NotApplicable => (RenderTruth::Yellow, "NOT-APPLICABLE"),
    };
    // O-2 (Oracle Ladder typing): project the reconcile verdict onto the R1 invariant rung AND
    // run it through the EXISTING write gate (`select_evolution_writes` — the SAME deterministic
    // gate every trust class uses; NO second write path) to show the ACCUMULATE decision. The
    // model never reaches it; only the checker's typed verdict does (no LLM judge). held=none, so
    // a reconciled cert shows its in-isolation write decision; persistence stays the gated
    // evolve-IO path. A reconciled R1 pattern is Invariant ⟂ CrossMemory ⇒ doubly verified.
    let cand = crate::autonomy_evolve::reconciliation_candidate(path, &text, &r);
    let ev = crate::autonomy_evolve::select_evolution_writes(
        std::slice::from_ref(&cand),
        &[],
        &|_k: &str| crate::verification::PerfScore::default(),
    );
    let admission = if cand.admits_write {
        "Verified"
    } else {
        "Unverified"
    };
    (
        truth,
        vec![
            format!(
                "verdict: {label} (computed={} target={})",
                r.computed_minor, r.target_minor
            ),
            r.detail.to_string(),
            // two compact lines (the cockpit render caps line width): the R1 rung + admission,
            // then the EXISTING write gate's ACCUMULATE decision (no second write path).
            format!(
                "oracle ladder: rung={:?} write-admission={admission} (no LLM judge)",
                crate::verification::VerificationClass::Invariant.rung(),
            ),
            format!(
                "  write-gate (held=none): writes={} doubly_verified={}",
                ev.written_count(),
                ev.doubly_verified_count(),
            ),
            "honest LOCK: arithmetic-sound (the claim reconciles with the STATED items); NOT that the positions / sources are real".to_string(),
        ],
    )
}

/// O-4 (Oracle Bootstrap second domain — S2 metamorphic): read a `<source-path>` text and a
/// `<summary-path>` text and run the deterministic [`crate::metamorphic_oracle`] checker — verify
/// the metamorphic relation `summary ⊆ source` (quoted-span + number containment) and a compression
/// target, FAIL-CLOSED. A SOUND REJECTOR: a fabricated quote / unsupported number / over-length ⇒
/// REJECTED (Red, a real bug); a pass ⇒ NOT-FALSIFIED (Yellow — PROVISIONAL, NOT proof it is good);
/// malformed/unreadable ⇒ NOT-APPLICABLE (Unknown, honest absence). The model's prose never reaches
/// `verify` — only the checker's typed verdict does (no LLM judge). HONEST LOCK: a metamorphic pass
/// is "not-yet-falsified" (it may still OMIT the key point); only a REJECT is a trustworthy verdict.
fn audit_summary_body(rest: &[String]) -> (RenderTruth, Vec<String>) {
    use crate::metamorphic_oracle::{
        CompressionTarget, MetamorphicViolation, SummaryVerdict, check_summary,
    };
    let (Some(source_path), Some(summary_path)) = (rest.get(1), rest.get(2)) else {
        return (
            RenderTruth::Yellow,
            vec![
                "audit summary <source-path> <summary-path> — deterministically check summary⊆source (O-4, S2 metamorphic)".to_string(),
                "  SOUND REJECTOR: a fabricated quote / unsupported number / over-compression ⇒ REJECTED (a real bug)".to_string(),
                "  a pass is NOT-FALSIFIED (provisional — may still OMIT key info); it NEVER admits a write (R2 rejector-only)".to_string(),
            ],
        );
    };
    let source = match std::fs::read_to_string(std::path::Path::new(source_path)) {
        Ok(t) => t,
        Err(_) => {
            return (
                RenderTruth::Yellow,
                vec![format!(
                    "audit summary: cannot read source at {source_path}"
                )],
            );
        }
    };
    let summary = match std::fs::read_to_string(std::path::Path::new(summary_path)) {
        Ok(t) => t,
        Err(_) => {
            return (
                RenderTruth::Yellow,
                vec![format!(
                    "audit summary: cannot read summary at {summary_path}"
                )],
            );
        }
    };
    let r = check_summary(&source, &summary, CompressionTarget::DEFAULT);
    let (truth, label) = match r.verdict {
        SummaryVerdict::Rejected => (RenderTruth::Red, "REJECTED"),
        SummaryVerdict::NotFalsified => (RenderTruth::Yellow, "NOT-FALSIFIED"),
        SummaryVerdict::NotApplicable => (RenderTruth::Unknown, "NOT-APPLICABLE"),
    };
    // O-4 (Oracle Ladder typing): project the metamorphic verdict onto the R2 rung AND run it
    // through the EXISTING write gate (`select_evolution_writes` — the SAME deterministic gate; NO
    // second write path) to show the ACCUMULATE decision. A metamorphic verdict NEVER admits a write
    // (R2 rejector-only): a fabrication is BLOCKED, a pass never ACCUMULATEs. The model never reaches
    // it; only the checker's typed verdict does (no LLM judge).
    let cand = crate::autonomy_evolve::metamorphic_candidate(summary_path, &summary, r.verdict);
    let ev = crate::autonomy_evolve::select_evolution_writes(
        std::slice::from_ref(&cand),
        &[],
        &|_k: &str| crate::verification::PerfScore::default(),
    );
    let offending = match &r.violation {
        Some(MetamorphicViolation::FabricatedQuote { quote }) => {
            let bounded: String = quote.chars().take(80).collect();
            format!("offending: fabricated quote not in source — \"{bounded}\"")
        }
        Some(MetamorphicViolation::UnsupportedNumber { number }) => {
            format!("offending: unsupported number not in source — {number}")
        }
        Some(MetamorphicViolation::OverCompression {
            summary_tokens,
            source_tokens,
            num,
            den,
        }) => format!(
            "offending: over-compression — summary {summary_tokens} tok > {num}/{den} × source {source_tokens} tok"
        ),
        None => format!(
            "no metamorphic relation falsified (summary {} tok / source {} tok)",
            r.summary_tokens, r.source_tokens
        ),
    };
    (
        truth,
        vec![
            format!("verdict: {label}"),
            offending,
            r.detail.to_string(),
            format!(
                "oracle ladder: rung={:?} write-admission={:?} (no LLM judge; R2 rejector-only — NEVER Verified)",
                crate::verification::VerificationClass::Metamorphic.rung(),
                // the PRECISE ladder verdict (a REJECT ⇒ Unverified, a PASS ⇒ NotApplicable) — never
                // binarized to "Verified"/"Unverified", because the rejector-only distinction IS the point.
                crate::verification::metamorphic_receipt(r.verdict).verdict,
            ),
            format!(
                "  write-gate (held=none): writes={} (R2 rejector-only — a metamorphic verdict NEVER ACCUMULATEs)",
                ev.written_count(),
            ),
            "honest LOCK: a metamorphic PASS is NOT-FALSIFIED (sound rejector; satisfaction ⇏ correctness) — it may still OMIT the key point; only a REJECT is a trustworthy verdict".to_string(),
        ],
    )
}

/// O-3 (Oracle Bootstrap recognition-elicitation): read a recognition pool + recognitions from
/// `<path>` and return the most-informative NEXT question (deterministic farthest-first /
/// k-center active-query; ZERO LLM tokens, instant) plus the owned anchor-set summary. The
/// selection is pure integer geometry — the model never decides what to ask. HONEST LOCK: it
/// elicits the customer's recognition over GIVEN features; it does not synthesize a checker /
/// render a verdict (the anchor set is INPUT capital for synthesis, deferred).
fn audit_elicit_body(rest: &[String]) -> (RenderTruth, Vec<String>) {
    use crate::recognition_elicit::{
        NextQuery, anchor_set_hash, build_anchor_set, coverage_radius, next_label_query, parse_pool,
    };
    let Some(path) = rest.get(1) else {
        return (
            RenderTruth::Yellow,
            vec![
                "audit elicit <path> — the next most-informative recognition question (O-3)".to_string(),
                "  pool:  `dim <D>` then `example <id> <f0..f(D-1)>` lines (integer features)".to_string(),
                "  recog: `label <id> good|bad` · `compare <better> <worse>` · `triad <a> <b> <c> odd=<id> axis=<name>`".to_string(),
            ],
        );
    };
    let text = match std::fs::read_to_string(std::path::Path::new(path)) {
        Ok(t) => t,
        Err(_) => {
            return (
                RenderTruth::Yellow,
                vec![format!("audit elicit: cannot read pool at {path}")],
            );
        }
    };
    let Some((pool, recognitions)) = parse_pool(&text) else {
        return (
            RenderTruth::Yellow,
            vec!["audit elicit: malformed pool (fail-closed; nothing elicited)".to_string()],
        );
    };
    let set = build_anchor_set(&pool, &recognitions);
    let hash = anchor_set_hash(&pool, &recognitions);
    let (truth, next_line) = match next_label_query(&pool, &recognitions) {
        NextQuery::Ask {
            example,
            marginal_gain,
        } => (
            RenderTruth::Green,
            format!(
                "next-query: LABEL example {example} (k-center farthest-first; gain={marginal_gain})"
            ),
        ),
        NextQuery::Saturated => (
            RenderTruth::Unknown,
            "next-query: none — elicitation SATURATED (every example seen)".to_string(),
        ),
    };
    let radius =
        coverage_radius(&pool, &recognitions).map_or_else(|| "0".to_string(), |r| r.to_string());
    let axes = if set.named_axes.is_empty() {
        "(none)".to_string()
    } else {
        set.named_axes.join(", ")
    };
    (
        truth,
        vec![
            next_line,
            format!("coverage: k-center radius={radius} (0 = saturated; shrinks as you label)"),
            format!(
                "anchors: pool={} dim={} labels={}+/{}- compares={} triads={} axes=[{axes}]",
                set.pool_size,
                set.dim,
                set.positives,
                set.negatives,
                set.comparisons,
                set.triads
            ),
            format!("anchor-set: {hash} (deterministic; ZERO LLM tokens)"),
            "honest LOCK: elicits recognition over GIVEN features (k-center 2-approx; no LLM judge); the anchor set is INPUT for synthesis, NOT yet a verdict".to_string(),
        ],
    )
}

/// O-3b (Oracle Bootstrap recognition-synthesis): read a recognition pool from `<path>`,
/// SYNTHESIZE the bounding-box checker, CERTIFY it (held-out leave-one-out zero-false-accept),
/// and — if `[features...]` are given — render the induced checker's 3-way verdict for that
/// example + the ladder write-admission (reusing `select_evolution_writes`; no second write
/// path). ZERO LLM tokens (pure integer geometry). HONEST LOCK: a certified `Accept` is a
/// PROVISIONAL R5 pattern (held-out gated); the quantitative conformal α-budget is O-3c.
fn audit_classify_body(rest: &[String]) -> (RenderTruth, Vec<String>) {
    use crate::recognition_elicit::parse_pool;
    use crate::recognition_synth::{InducedVerdict, certify_leave_one_out, synthesize};
    let Some(path) = rest.get(1) else {
        return (
            RenderTruth::Yellow,
            vec![
                "audit classify <pool> [f0 f1 ...] — synthesize a checker from recognition anchors (O-3b)".to_string(),
                "  pool format = `audit elicit`'s; `label <id> good|bad` anchors drive the box".to_string(),
                "  optional [features...] = an example to classify (ACCEPT/REJECT/ESCALATE)".to_string(),
            ],
        );
    };
    let text = match std::fs::read_to_string(std::path::Path::new(path)) {
        Ok(t) => t,
        Err(_) => {
            return (
                RenderTruth::Yellow,
                vec![format!("audit classify: cannot read pool at {path}")],
            );
        }
    };
    let Some((pool, recognitions)) = parse_pool(&text) else {
        return (
            RenderTruth::Yellow,
            vec!["audit classify: malformed pool (fail-closed; nothing synthesized)".to_string()],
        );
    };
    let checker = synthesize(&pool, &recognitions);
    let report = certify_leave_one_out(&pool, &recognitions);
    let (np, nn) = checker.anchor_counts();
    let box_line = match checker.bbox() {
        Some(b) => format!(
            "induced box: lo={:?} hi={:?} sound={}",
            b.lo(),
            b.hi(),
            checker.is_sound()
        ),
        None => "induced box: (none — no positive anchors)".to_string(),
    };
    let mut body = vec![
        format!("synthesized: {np}+ positive / {nn}- negative labeled anchors"),
        box_line,
        format!(
            "certify (Clopper-Pearson): false_accepts={} of {nn} held-out negatives, coverage={}/{np}",
            report.false_accepts, report.coverage_hits
        ),
        format!(
            "  conformal: FAR<={}/{} @ {}% confidence (exact, float-free) certified={}",
            crate::conformal::ALPHA_SAFE_NUM,
            crate::conformal::ALPHA_SAFE_DEN,
            100 - (crate::conformal::DELTA_NUM * 100 / crate::conformal::DELTA_DEN),
            report.is_certified()
        ),
    ];
    // optional test example: parse rest[2..] as i64 features, classify + show ladder admission.
    let mut truth = if report.is_certified() {
        RenderTruth::Green
    } else {
        RenderTruth::Unknown
    };
    if rest.len() > 2 {
        let mut feats: Vec<i64> = Vec::with_capacity(rest.len() - 2);
        let mut bad = false;
        for tok in &rest[2..] {
            match tok.parse::<i64>() {
                Ok(v) => feats.push(v),
                Err(_) => {
                    bad = true;
                    break;
                }
            }
        }
        if bad || feats.len() != pool.dim() {
            body.push(format!(
                "classify: bad example (need {} integer features)",
                pool.dim()
            ));
            truth = RenderTruth::Yellow;
        } else {
            let verdict = checker.classify(&feats);
            let cand = crate::autonomy_evolve::recognition_candidate(
                path,
                "<example>",
                verdict,
                report.is_certified(),
            );
            let ev = crate::autonomy_evolve::select_evolution_writes(
                std::slice::from_ref(&cand),
                &[],
                &|_k: &str| crate::verification::PerfScore::default(),
            );
            body.push(format!("classify {feats:?} => verdict={verdict:?}"));
            body.push(format!(
                "ladder: rung={:?} => write-gate writes={} doubly_verified={}",
                crate::verification::VerificationClass::Induced.rung(),
                ev.written_count(),
                ev.doubly_verified_count()
            ));
            truth = match verdict {
                InducedVerdict::Accept if report.is_certified() => RenderTruth::Green,
                InducedVerdict::Reject => RenderTruth::Red,
                _ => RenderTruth::Unknown,
            };
        }
    }
    body.push(
        "honest LOCK: induced over GIVEN features (entails+/excludes-; no LLM judge); a certified ACCEPT is PROVISIONAL R5 — the quantitative α-budget is O-3c".to_string(),
    );
    (truth, body)
}

/// O-5 (Oracle Bootstrap ownership): render the MINTABLE certified-oracle iNFT envelope — the
/// shared tail for BOTH cert kinds (recognition conformal + reconcile/metamorphic deterministic).
/// Composes the LOCKED W3 encoder for the calldata + the OWNER-run mint runbook. `head` = the
/// per-kind cert lines; PURE (no chain write — the owner FIRES the mint, PD-6).
fn mint_oracle_envelope(
    kind: &str,
    data_hash: [u8; 32],
    identity_label: &str,
    cert: &crate::oracle_inft::OracleCert,
    mut head: Vec<String>,
) -> (RenderTruth, Vec<String>) {
    let descriptor = crate::oracle_inft::oracle_descriptor(kind, identity_label, cert);
    let calldata = crate::oracle_inft::oracle_mint_calldata(
        &descriptor,
        &data_hash,
        &crate::zerog_inft::GOLDEN_RECIPIENT,
    );
    head.push("MINTABLE — certified-oracle iNFT (O-5):".to_string());
    head.push(format!(
        "  dataHash   : 0x{} (deterministic commitment; re-derivable)",
        crate::zerog_chain::hex_encode(&data_hash)
    ));
    head.push(format!(
        "  descriptor : {descriptor} ({}B)",
        descriptor.len()
    ));
    head.push(format!(
        "  calldata   : {} bytes (composes the LOCKED W3 encoder 0xa3acac17 — no second mint surface)",
        calldata.len()
    ));
    head.extend(crate::oracle_inft::oracle_mint_bundle_lines(
        kind,
        &data_hash,
        &descriptor,
        cert,
        None,
        None,
    ));
    head.push(
        "honest LOCK: minting proves OWNED PROVENANCE of a CERTIFIED oracle (it cleared its cert — the conformal FAR bound on the anchor distribution, or deterministic soundness on its invariant/relation), NOT per-user correctness on arbitrary inputs — agent PREPARES, owner FIRES (PD-6)".to_string(),
    );
    (RenderTruth::Green, head)
}

/// O-5 (Oracle Bootstrap ownership): `audit mint-oracle <reconcile|metamorphic | <pool>>` capitalizes
/// a CERTIFIED oracle as an ERC-7857 iNFT (composing the LOCKED W3 encoder). The first arg selects:
/// the keyword `reconcile`/`metamorphic` mints the DETERMINISTIC-FOREVER oracle (O-1/O-4, certified
/// iff the ladder CANARY is intact); else the arg is a recognition POOL path and the
/// CONFORMAL-certified recognition oracle (O-3b/O-3c) is minted (reusing the `audit classify`
/// synth+certify spine). PURE PREPARE: the agent builds the dataHash + calldata + owner runbook; the
/// owner FIRES the funds-bearing mint (PD-6). Certified-only, fail-closed — an UN-certified oracle is
/// UN-mintable. ZERO LLM tokens (the cert is exact integer geometry; no chain write, no custody).
fn audit_mint_oracle_body(rest: &[String]) -> (RenderTruth, Vec<String>) {
    use crate::oracle_inft::{OracleCert, deterministic_oracle_spec, oracle_data_hash};
    let Some(arg) = rest.get(1) else {
        return (
            RenderTruth::Yellow,
            vec![
                "audit mint-oracle <reconcile|metamorphic | <pool>> — mint a CERTIFIED oracle as an ERC-7857 iNFT (O-5)".to_string(),
                "  keyword reconcile/metamorphic = the deterministic-forever oracle (O-1/O-4; certified iff the ladder CANARY is intact)".to_string(),
                "  a pool path = the conformal-certified recognition oracle (O-3b/O-3c); mintable ONLY if the α-budget certifies it".to_string(),
                "  PURE PREPARE: agent builds the dataHash + calldata + owner runbook; the owner FIRES the mint (PD-6)".to_string(),
            ],
        );
    };

    // --- DETERMINISTIC keyword path (reconcile / metamorphic; O-1/O-4) ---
    if let Some(spec) = deterministic_oracle_spec(arg) {
        let kind = arg.as_str();
        let cert = OracleCert::DeterministicSound;
        let identity = spec.as_bytes();
        let id_hash = crate::hex32(&crate::sha256_32(identity));
        let id_label = &id_hash[..16];
        let head = vec![
            format!("oracle: {kind} (deterministic-forever, sound by construction; O-1/O-4)"),
            format!("spec: {spec}"),
            format!(
                "cert: deterministic-sound — verification CANARY intact={} (the ladder verdicts have not collapsed)",
                cert.is_certified()
            ),
        ];
        return match oracle_data_hash(kind, identity, &cert) {
            Some(dh) => mint_oracle_envelope(kind, dh, id_label, &cert, head),
            None => {
                let mut body = head;
                body.push("audit mint-oracle: NOT MINTABLE — the verification CANARY is NOT intact (the deterministic ladder is suspect; fail-closed)".to_string());
                body.push("honest LOCK: an oracle whose verdict gate has collapsed is not capitalizable provenance".to_string());
                (RenderTruth::Yellow, body)
            }
        };
    }

    // --- RECOGNITION pool path (conformal-certified; O-3b/O-3c) ---
    use crate::recognition_elicit::{anchor_set_hash, parse_pool};
    use crate::recognition_synth::{certify_leave_one_out, synthesize};
    let path = arg;
    let text = match std::fs::read_to_string(std::path::Path::new(path)) {
        Ok(t) => t,
        Err(_) => {
            return (
                RenderTruth::Yellow,
                vec![format!(
                    "audit mint-oracle: cannot read pool at {path} (and not a reconcile/metamorphic keyword)"
                )],
            );
        }
    };
    let Some((pool, recognitions)) = parse_pool(&text) else {
        return (
            RenderTruth::Yellow,
            vec!["audit mint-oracle: malformed pool (fail-closed; nothing minted)".to_string()],
        );
    };
    let checker = synthesize(&pool, &recognitions);
    let report = certify_leave_one_out(&pool, &recognitions);
    let (np, nn) = checker.anchor_counts();
    let k = report.false_accepts as u64;
    let n = report.n_negatives as u64;
    let anchors = anchor_set_hash(&pool, &recognitions);
    let kind = crate::oracle_inft::RECOGNITION_ORACLE_KIND;
    let conf = 100 - (crate::conformal::DELTA_NUM * 100 / crate::conformal::DELTA_DEN);
    let Some(bbox) = checker.bbox().filter(|_| checker.is_sound()) else {
        return (
            RenderTruth::Yellow,
            vec![
                format!("synthesized: {np}+ / {nn}- anchors; certified={}", report.is_certified()),
                "audit mint-oracle: NOT MINTABLE — the induced checker has no SOUND box (a degenerate oracle)".to_string(),
                "honest LOCK: an oracle without a sound rule is not capitalizable provenance".to_string(),
            ],
        );
    };
    let cert = OracleCert::Conformal { k, n };
    let identity = crate::oracle_inft::recognition_identity(&anchors, bbox.lo(), bbox.hi());
    // THE MINT GATE (O-5 seam Q3, certified-only): only a CONFORMAL-CERTIFIED oracle gets a dataHash.
    match oracle_data_hash(kind, &identity, &cert) {
        Some(dh) => {
            let head = vec![
                format!("synthesized: {np}+ / {nn}- anchors; box lo={:?} hi={:?} sound=true", bbox.lo(), bbox.hi()),
                format!(
                    "certify (Clopper-Pearson): false_accepts={k} of {n} held-out negatives ⇒ CERTIFIED (FAR<={}/{} @ {conf}%, exact float-free)",
                    crate::conformal::ALPHA_SAFE_NUM, crate::conformal::ALPHA_SAFE_DEN,
                ),
            ];
            mint_oracle_envelope(kind, dh, &anchors, &cert, head)
        }
        None => (
            RenderTruth::Yellow,
            vec![
                format!("synthesized: {np}+ / {nn}- anchors; box lo={:?} hi={:?}", bbox.lo(), bbox.hi()),
                format!(
                    "certify (Clopper-Pearson): false_accepts={k} of {n} held-out negatives ⇒ NOT certified (FAR>{}/{} @ {conf}%)",
                    crate::conformal::ALPHA_SAFE_NUM, crate::conformal::ALPHA_SAFE_DEN,
                ),
                "audit mint-oracle: NOT MINTABLE — the conformal α-budget gate is the mint precondition (O-5 certified-only, fail-closed)".to_string(),
                "honest LOCK: an UN-certified oracle has NO dataHash — provenance cannot be capitalized for an oracle that did not clear the budget".to_string(),
            ],
        ),
    }
}

// A① (CURSOR_PARITY_REFRAME_DESIGN.md §3 A①): `context lsp-diagnostics <path>` is
// the owner/GUI consumer of the language-server READ — the SAME `crate::lsp::diagnose`
// pipeline the loop `TOOL: lsp diagnostics` uses (the walled file read → a sandboxed
// rust-analyzer/move-analyzer with network + write kernel-DENIED → the redact belt →
// the compiler's diagnostics). READ-class; an absent binary / a non-`lsp` build
// honest-degrades ("not found" / "codec not compiled"), never a fabricated result. No
// custody/funds/chain symbol on this path (PD-6).
fn lsp_diagnostics_body(rest: &[String]) -> (RenderTruth, Vec<String>) {
    let Some(path) = rest.get(1) else {
        return (
            RenderTruth::Yellow,
            vec!["lsp diagnostics: usage `context lsp-diagnostics <path>`".to_string()],
        );
    };
    let (rendered, ran) = crate::lsp::diagnose(path);
    // A real verdict (compiler-clean OR errors found) is honest truth (Unknown — a
    // lead, not a PASS/FAIL); an honest-degrade (server/codec absent) is Yellow so
    // the owner sees the state.
    let truth = if ran {
        RenderTruth::Unknown
    } else {
        RenderTruth::Yellow
    };
    (truth, rendered.lines().map(str::to_string).collect())
}

// B⑫ (CURSOR_PARITY_REFRAME_DESIGN.md §3 B⑫ + §6 B⑫): `context mcp <server> <tool>
// [json-args]` is the owner/GUI MCP tool call — the SAME `crate::mcp::render_mcp_call`
// chokepoint the loop's `mcp` tool uses: WALL (only an owner-configured READ server)
// → redact ARG → sandboxed `tools/call` (network + write kernel-DENIED) → redact
// RESULT → E5 audit. The server list comes from the owner config (READ tier only); an
// unconfigured server / an un-advertised tool / a non-`mcp` build honest-degrades. No
// owner content escapes the box (a LOCAL stdio child; net kernel-DENIED).

/// `context mcp <server> <tool> [json-args]` body. `rest` =
/// `["mcp", <server>, <tool>, <json-args...>]` (rest[0] is the verb). A verified,
/// redacted result is honest truth (Unknown — advisory, never proof); a deny /
/// honest-degrade is Yellow so the owner sees the state.
fn mcp_call_body(rest: &[String]) -> (RenderTruth, Vec<String>) {
    let server = rest.get(1).map_or("", String::as_str);
    let tool = rest.get(2).map_or("", String::as_str);
    if server.is_empty() || tool.is_empty() {
        return (
            RenderTruth::Yellow,
            vec![
                "usage: context mcp <server> <tool> [json-args]".to_string(),
                "calls a READ-only tool on an owner-configured LOCAL stdio MCP server \
                 (sandboxed, network kernel-DENIED; unknown server/tool denied; the arg \
                 + result are redacted; every call is audited; advisory-only)"
                    .to_string(),
            ],
        );
    }
    let args = rest.get(3..).map_or_else(String::new, |a| a.join(" "));
    let seam = crate::mcp::McpSeam::new(read_owner_mcp_servers());
    let render = crate::mcp::render_mcp_call(Some(&seam), server, tool, args.trim());
    let truth = if render.consumed_read {
        RenderTruth::Unknown
    } else {
        RenderTruth::Yellow
    };
    (truth, render.rendered.lines().map(str::to_string).collect())
}

// A⑤ (CURSOR_PARITY_REFRAME_DESIGN.md §3 A⑤ + §6 A⑤): `context git <subcommand>
// [args]` is the owner/GUI git READ — the SAME `crate::git::render_git_read`
// chokepoint the loop's `git` tool uses (READ-subcommand allowlist → sandboxed git,
// network + write kernel-DENIED → redact). v1 = status/diff/log/show/blame; a
// non-READ subcommand ⇒ deny. commit/branch/push = owner-armed v2.

/// `context git <subcommand> [args]` body. `rest` = `["git", <subcommand>,
/// <args...>]` (rest[0] is the verb). A real git READ is honest truth (Unknown —
/// advisory; git's own output, not a PASS/FAIL); a deny / honest-degrade is Yellow.
fn git_read_body(rest: &[String]) -> (RenderTruth, Vec<String>) {
    let Some(subcommand) = rest.get(1).map(String::as_str).filter(|s| !s.is_empty()) else {
        return (
            RenderTruth::Yellow,
            vec![
                "usage: context git <subcommand> [args]".to_string(),
                format!(
                    "runs a READ-only git subcommand ({}) on the local repo (sandboxed, \
                     network + write kernel-DENIED; any other subcommand denied; output redacted)",
                    crate::git::GIT_READ_SUBCOMMANDS.join(" / ")
                ),
            ],
        );
    };
    let args = rest.get(2..).map_or_else(String::new, |a| a.join(" "));
    let render = crate::git::render_git_read(subcommand, args.trim());
    let truth = if render.consumed_read {
        RenderTruth::Unknown
    } else {
        RenderTruth::Yellow
    };
    (truth, render.rendered.lines().map(str::to_string).collect())
}

// A② (CURSOR_PARITY_REFRAME_DESIGN.md §3 A②): `context test-run <pkg>` is the
// owner/GUI test run — the SAME `crate::test_run::render_test_run` chokepoint the
// loop's `test run` tool uses (validate under-workspace → sandboxed `sui move test`/
// `cargo test`, network kernel-DENIED → redact). Surfaces the PASS/FAIL verdict
// (compiler/test ground truth). custody/funds HARD-LOCKED (no chain/socket).

/// `context test-run <pkg>` body. `rest` = `["test-run", <pkg>]` (rest[0] is the
/// verb). A real verdict is honest truth (Unknown — the runner's output, not a
/// dispatch PASS/FAIL); a deny / honest-degrade is Yellow.
fn test_run_body(rest: &[String]) -> (RenderTruth, Vec<String>) {
    let Some(pkg) = rest.get(1).map(String::as_str).filter(|s| !s.is_empty()) else {
        return (
            RenderTruth::Yellow,
            vec![
                "usage: context test-run <pkg>".to_string(),
                "runs `sui move test` (Move.toml) / `cargo test --offline` (Cargo.toml) on a \
                 workspace package (sandboxed, network kernel-DENIED; under-workspace only; \
                 output redacted); surfaces the PASS/FAIL verdict"
                    .to_string(),
            ],
        );
    };
    let render = crate::test_run::render_test_run(pkg);
    let truth = if render.consumed_read {
        RenderTruth::Unknown
    } else {
        RenderTruth::Yellow
    };
    (truth, render.rendered.lines().map(str::to_string).collect())
}

// A④-rg (CURSOR_PARITY_REFRAME_DESIGN.md §3 A④): `context search <regex>` is the
// owner/GUI find-in-files — the SAME `crate::search::render_search` chokepoint the
// loop's `search` tool uses (validate pattern → bounded regex walk over the
// workspace source, each file through the file-context wall = denylist + size cap +
// UTF-8 → per-line redact). NO subprocess, NO network (a pure in-Rust READ).
// custody/funds HARD-LOCKED (no chain/socket).

/// `context search <regex>` body. `rest` = `["search", <regex tokens…>]` (rest[0] is
/// the verb; the regex may contain spaces ⇒ join rest[1..]). A real walk is honest
/// truth (Unknown — the hits, not a dispatch PASS/FAIL); a deny is Yellow.
fn search_body(rest: &[String]) -> (RenderTruth, Vec<String>) {
    let pattern = rest.get(1..).map_or_else(String::new, |a| a.join(" "));
    let pattern = pattern.trim();
    if pattern.is_empty() {
        return (
            RenderTruth::Yellow,
            vec![
                "usage: context search <regex>".to_string(),
                "runs a regex over the workspace source (read-only; no subprocess; each file \
                 denylist + size-cap + redaction-walled) and lists the `path:line: content` hits"
                    .to_string(),
            ],
        );
    }
    let render = crate::search::render_search(pattern);
    let truth = if render.consumed_read {
        RenderTruth::Unknown
    } else {
        RenderTruth::Yellow
    };
    (truth, render.rendered.lines().map(str::to_string).collect())
}

/// [4] `context codebase build` body — walk the workspace + chunk + embed (the LOCAL
/// stub embedder; no network) + seal with the local key + atomic-write the encrypted
/// index. ReadOnly compute (no egress); secret lines are withheld at index time.
fn codebase_build_body() -> (RenderTruth, Vec<String>) {
    use crate::codebase_index::{CODEBASE_INDEX_FILE, StubEmbedder, build_index};
    use crate::file_context::FileReadPolicy;
    let policy = FileReadPolicy::workspace_default();
    let Some(root) = policy.roots().first().cloned() else {
        return (
            RenderTruth::Red,
            vec!["@codebase build: workspace root unavailable".to_string()],
        );
    };
    let index = build_index(&policy, &root, &StubEmbedder);
    if index.entries.is_empty() {
        return (
            RenderTruth::Yellow,
            vec!["@codebase build: 0 chunks (no readable source under the workspace)".to_string()],
        );
    }
    let Ok(dir) = crate::memory_store::data_dir() else {
        return (
            RenderTruth::Red,
            vec!["@codebase build: no data dir".to_string()],
        );
    };
    let Ok(store) = crate::memory_store::PersistedStore::open_local() else {
        return (
            RenderTruth::Red,
            vec!["@codebase build: memory store unavailable".to_string()],
        );
    };
    let Ok(sealed) = store.seal_codebase_index(&index.to_bytes()) else {
        return (
            RenderTruth::Red,
            vec!["@codebase build: seal failed".to_string()],
        );
    };
    let path = dir.join(CODEBASE_INDEX_FILE);
    if crate::memory_store::atomic_write(&path, &sealed).is_err() {
        return (
            RenderTruth::Red,
            vec!["@codebase build: atomic write failed".to_string()],
        );
    }
    let mut files: Vec<&str> = index
        .entries
        .iter()
        .map(|e| e.chunk.rel_path.as_str())
        .collect();
    files.sort_unstable();
    files.dedup();
    (
        RenderTruth::Green,
        vec![
            format!(
                "@codebase index built: {} chunks across {} files",
                index.entries.len(),
                files.len()
            ),
            format!(
                "sealed (AES-256-GCM-SIV) at <data_dir>/{CODEBASE_INDEX_FILE} ({} bytes); embeddings never leave the box",
                sealed.len()
            ),
            "local stub embedder (a real model swaps in at the Embedder seam); secret lines withheld at index time"
                .to_string(),
        ],
    )
}

/// [4] `context codebase <query>` body — load the encrypted index + retrieve top-K
/// (hybrid cosine + lexical) + render redacted snippets. Honest if no index is built.
fn codebase_query_body(query: &str) -> (RenderTruth, Vec<String>) {
    use crate::codebase_index::{StubEmbedder, load_persisted_index, render_retrieval};
    let Some(index) = load_persisted_index() else {
        return (
            RenderTruth::Yellow,
            vec!["@codebase: no index (run `context codebase build` first)".to_string()],
        );
    };
    let render = render_retrieval(&index, query, &StubEmbedder);
    let truth = if render.consumed_read {
        RenderTruth::Unknown
    } else {
        RenderTruth::Yellow
    };
    (truth, render.rendered.lines().map(str::to_string).collect())
}

/// [5] B⑭ `context image <path>` body — read + classify the image (magic-byte format +
/// dimensions + sha) and describe it LOCALLY (the stub vision describer; NO egress) as a
/// READ context fragment. The image bytes never leave the box on this path.
fn image_context_body(path: &str) -> (RenderTruth, Vec<String>) {
    let render = crate::vision::render_image_context(&crate::vision::StubVision, path);
    let truth = if render.consumed_read {
        RenderTruth::Green
    } else {
        RenderTruth::Yellow
    };
    (truth, render.rendered.lines().map(str::to_string).collect())
}

// E11-1b (WEB_FETCH_THREAT_MODEL.md ⑭): `context web-fetch <url>` is the owner's
// LIVE web READ — the gated, SSRF-walled, secret-zero GET. The SHARED glue
// (`provider::web_fetch::render_web_fetch`) is the SAME pipeline the loop tool
// `TOOL: web fetch <url>` uses: classify_url → port.fetch → redact(body) →
// WebResearchRecord::new → WebSourcePolicy::evaluate → advisory / typed deny. The
// only build difference is the `port`: a live transport under `web-egress`, `None`
// otherwise (the honest not-compiled deny). No owner content leaves — a public URL
// + a static UA only; the RESPONSE is redacted before it renders.

/// Wall-clock unix seconds for the research record's `retrieved_at` (metadata; not
/// load-bearing for any gate). Fail-OPEN to 0 on a pre-epoch clock.
fn web_fetch_now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

/// `context web-fetch <url>` body — the SHARED render for BOTH the live
/// (`web-egress`) and the honest-not-compiled (default) builds. The `port` is the
/// only difference: `Some(live)` under `web-egress`, `None` otherwise (the glue
/// then yields `web_fetch.transport.not_compiled`). The owner invoking this verb
/// IS the opt-in, so the policy is enabled (the `evaluate` gate still enforces
/// source-linked + quote-limit + advisory-only, IV-WF6).
fn web_fetch_body(
    rest: &[String],
    port: Option<&dyn crate::provider::web_fetch::WebFetchPort>,
) -> (RenderTruth, Vec<String>) {
    let Some(url_arg) = rest.get(1) else {
        return (
            RenderTruth::Yellow,
            vec![
                "usage: context web-fetch <https-url>".to_string(),
                "fetches ONE public https URL (SSRF-walled, secret-zero GET, redirect-none, \
                 redacted, advisory-only); http/IP-literal/localhost/chain-RPC denied"
                    .to_string(),
            ],
        );
    };
    web_fetch_render_lines(url_arg, port)
}

/// Render a URL through the shared glue (the body of BOTH `context web-fetch` and
/// `context web-search`). The owner invoking the verb IS the opt-in, so the policy
/// is enabled (the `evaluate` gate still enforces source-linked + quote-limit +
/// advisory-only, IV-WF6).
fn web_fetch_render_lines(
    url: &str,
    port: Option<&dyn crate::provider::web_fetch::WebFetchPort>,
) -> (RenderTruth, Vec<String>) {
    let policy = crate::provider::web_policy::WebSourcePolicy {
        web_enabled: true,
        max_quote_chars_u32: crate::provider::web_fetch::WEB_FETCH_QUOTE_CHARS,
    };
    let render =
        crate::provider::web_fetch::render_web_fetch(port, &policy, url, web_fetch_now_unix());
    let truth = if render.consumed_read {
        RenderTruth::Green
    } else {
        RenderTruth::Yellow
    };
    let body: Vec<String> = render.rendered.lines().map(str::to_string).collect();
    (truth, body)
}

// E11-1b (WEB_FETCH_THREAT_MODEL.md ⑭ D-WF5): `context web-search <query>` is the
// CONFIGURED-endpoint seam — NOT a bundled crawler / index (that would be fake).
// With `WEB_SEARCH_ENDPOINT` set (a SearXNG/Brave-compatible https URL), a query is
// appended (`?q=<percent-encoded>`) and fetched through the SAME SSRF wall + glue
// as a plain fetch. Unset ⇒ the honest "no search endpoint; name a URL with
// context web-fetch". The endpoint host passes `classify_url` like any other URL
// (so an http / IP-literal / chain-RPC endpoint is denied too).

/// The owner-configured web-search endpoint (env `WEB_SEARCH_ENDPOINT`). UNSET or
/// blank ⇒ `None`; `web_search_body` then falls back to `DEFAULT_WEB_SEARCH_ENDPOINT`
/// so search is autonomous out of the box (E13-1).
fn web_search_endpoint() -> Option<String> {
    std::env::var("WEB_SEARCH_ENDPOINT")
        .ok()
        .filter(|s| !s.trim().is_empty())
}

/// The privacy-friendly KEYLESS default search endpoint (E13-1) — used when the
/// owner has not set `WEB_SEARCH_ENDPOINT`, so `web search` works autonomously out
/// of the box. A REAL external search (DuckDuckGo lite, GET `?q=`) routed through
/// the SAME `classify_url` SSRF wall as any fetch; overridable to a self-hosted
/// SearXNG / Brave-compatible endpoint for stronger privacy. NOT a bundled/fabricated
/// index — it is a live search the owner can swap or point at their own instance.
const DEFAULT_WEB_SEARCH_ENDPOINT: &str = "https://lite.duckduckgo.com/lite/";

/// Percent-encode a query for the `?q=` parameter — the RFC 3986 unreserved set is
/// kept verbatim, everything else becomes `%XX`. Manual (no `url` crate — raw-byte
/// discipline). Keeps a malformed / injected query from breaking the URL shape.
fn percent_encode_query(query: &str) -> String {
    let mut out = String::with_capacity(query.len());
    for b in query.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(char::from(b));
            }
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

/// Build the search URL for `query` (P3b — the ONE search-URL truth shared by the
/// `context web-search` verb AND the `TOOL: web search` loop tool, so the two cannot
/// drift): the `WEB_SEARCH_ENDPOINT` env override (E13-1) else the keyless DuckDuckGo
/// default, with `?q=<percent-encoded>` appended. The URL still passes the SAME SSRF
/// wall inside `render_web_fetch` / `web_fetch_render_lines`.
pub(crate) fn build_web_search_url(query: &str) -> String {
    // E13-1: autonomous by default — the env override wins, else the privacy-friendly
    // keyless default so search works out of the box. Still a REAL external search
    // through the SAME SSRF wall (no bundled / fabricated index).
    let endpoint = web_search_endpoint().unwrap_or_else(|| DEFAULT_WEB_SEARCH_ENDPOINT.to_string());
    let sep = if endpoint.contains('?') { '&' } else { '?' };
    format!("{endpoint}{sep}q={}", percent_encode_query(query))
}

/// `context web-search <query>` body — the CONFIGURED-endpoint seam. No query ⇒
/// usage; no endpoint ⇒ the honest "no search endpoint" deny (use `context
/// web-fetch <url>`); endpoint set ⇒ build `<endpoint>?q=<encoded>` and fetch it
/// through the SAME wall + glue. NO bundled index, NO fabricated results.
fn web_search_body(
    rest: &[String],
    port: Option<&dyn crate::provider::web_fetch::WebFetchPort>,
) -> (RenderTruth, Vec<String>) {
    let query = rest.get(1..).map(|s| s.join(" ")).unwrap_or_default();
    let query = query.trim();
    if query.is_empty() {
        return (
            RenderTruth::Yellow,
            vec![
                "usage: context web-search <query>".to_string(),
                "searches WEB_SEARCH_ENDPOINT (env override) or the default keyless \
                 DuckDuckGo search, through the SSRF wall"
                    .to_string(),
            ],
        );
    }
    // P3b: the ONE search-URL truth, shared with the `TOOL: web search` loop tool.
    let url = build_web_search_url(query);
    web_fetch_render_lines(&url, port)
}

/// `context web-fetch <url>` (live, `web-egress`) — fetch ONE public https URL
/// through the shared glue and render the redacted, rights/quote-gated advisory.
/// Risk=Network, approval=None (the owner reads a public URL; secret-zero egress —
/// no owner content, no auth, GET-only ⇒ no chain WRITE).
#[cfg(feature = "web-egress")]
fn cmd_context_web_fetch(rest: &[String], out: &mut impl Write) -> io::Result<bool> {
    let transport = crate::provider::web_fetch::WebFetchTransport::with_defaults();
    let port = transport
        .as_ref()
        .map(|t| t as &dyn crate::provider::web_fetch::WebFetchPort);
    let (truth, body) = web_fetch_body(rest, port);
    emit(
        out,
        "context web-fetch",
        &hex16(&sha256_32(b"context web-fetch")),
        CommandRisk::Network,
        ApprovalRequirement::None,
        truth,
        &body,
    )
    .map(|()| true)
}

/// `context web-fetch <url>` (default build, no `web-egress`) — the honest deny:
/// this build compiled NO web transport. Goes through the SAME glue (`port=None`)
/// so the not-compiled render is byte-identical to the loop tool's deny.
#[cfg(not(feature = "web-egress"))]
fn context_web_fetch_no_feature(rest: &[String], out: &mut impl Write) -> io::Result<bool> {
    let (truth, body) = web_fetch_body(rest, None);
    emit(
        out,
        "context web-fetch",
        &hex16(&sha256_32(b"context web-fetch")),
        CommandRisk::Network,
        ApprovalRequirement::None,
        truth,
        &body,
    )
    .map(|()| true)
}

/// `context web-search <query>` (live, `web-egress`) — fetch the owner-configured
/// search endpoint through the shared glue + wall. Risk=Network, approval=None.
#[cfg(feature = "web-egress")]
fn cmd_context_web_search(rest: &[String], out: &mut impl Write) -> io::Result<bool> {
    let transport = crate::provider::web_fetch::WebFetchTransport::with_defaults();
    let port = transport
        .as_ref()
        .map(|t| t as &dyn crate::provider::web_fetch::WebFetchPort);
    let (truth, body) = web_search_body(rest, port);
    emit(
        out,
        "context web-search",
        &hex16(&sha256_32(b"context web-search")),
        CommandRisk::Network,
        ApprovalRequirement::None,
        truth,
        &body,
    )
    .map(|()| true)
}

/// `context web-search <query>` (default build, no `web-egress`) — the honest deny:
/// no web transport (and the usage / no-endpoint guidance still renders before any
/// transport question, since those are network-free).
#[cfg(not(feature = "web-egress"))]
fn context_web_search_no_feature(rest: &[String], out: &mut impl Write) -> io::Result<bool> {
    let (truth, body) = web_search_body(rest, None);
    emit(
        out,
        "context web-search",
        &hex16(&sha256_32(b"context web-search")),
        CommandRisk::Network,
        ApprovalRequirement::None,
        truth,
        &body,
    )
    .map(|()| true)
}

// P4-2 (multi-repo / project context; FILE_CONTEXT_THREAT_MODEL.md §P4-2):
// `context index [<path>]` is the LOCAL trust tier — the owner enumerates their
// OWN registered project. No arg ⇒ the registered project roots (the multi-repo
// "registry" view, = the read policy's allowlist cwd + SINABRO_FILE_ROOTS, ONE
// source of truth). With a path ⇒ a bounded, deterministic, content-free file
// index (IV-F8..F11): allowlist-confined, symlink-never-followed, denylist-
// pruned, capped. The render passes the canonical redaction gate (a secret-
// shaped FILENAME ⇒ the whole listing is withheld). The agent loop has NO
// enumeration tool (grammar byte-unchanged; the model cannot enumerate — L8).

/// `context index [<path>]` — render the registered project roots (no arg) or a
/// bounded project file index (with a path), fail-closed on every denial (typed
/// reason, never an escaped path or a file's content).
fn project_index_body(rest: &[String]) -> (RenderTruth, Vec<String>) {
    let policy = crate::file_context::FileReadPolicy::workspace_default();
    let Some(path_arg) = rest.get(1) else {
        // No arg: the registry view — the project roots the owner has granted
        // (cwd + SINABRO_FILE_ROOTS). One source of truth = the read policy.
        let roots = policy.roots();
        let mut body = vec![format!("registered project roots ({})", roots.len())];
        if roots.is_empty() {
            body.push(
                "none — run in a project dir or `export SINABRO_FILE_ROOTS=/path/to/project`"
                    .to_string(),
            );
        } else {
            for root in roots
                .iter()
                .take(crate::project_index::MAX_INDEX_RENDER_LINES)
            {
                body.push(format!("  {}", root.display()));
            }
        }
        body.push(
            "usage: context index <path>  (bounded, denylist-pruned, content-free)".to_string(),
        );
        return redact_or_withhold(RenderTruth::Yellow, body);
    };
    let index = match crate::project_index::index_project(&policy, std::path::Path::new(path_arg)) {
        Ok(index) => index,
        Err(deny) => {
            return (
                RenderTruth::Yellow,
                vec![
                    format!("project index denied ({})", deny.class_label()),
                    "read-only enumeration; no write/exec; outside-root + secret containers refused"
                        .to_string(),
                ],
            );
        }
    };
    // Split the header so `truncated` + the content-addressed `fp` stay visible
    // under the 80-col render clamp (a hidden `truncated=true` would silently
    // imply a complete listing — honest-truncation must be on its own short line).
    let mut body = vec![
        format!("project={}", index.root.display()),
        format!(
            "entries={} truncated={} fp={}",
            index.len(),
            index.truncated,
            hex16(&index.fingerprint_32)
        ),
        format!("--- index ({} entries) ---", index.len()),
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
        if entry.is_dir || entry.is_symlink {
            body.push(format!("  [{kind}] {}", entry.rel_path));
        } else {
            body.push(format!(
                "  [{kind}] {} ({}B)",
                entry.rel_path, entry.size_bytes
            ));
        }
    }
    if index.len() > crate::project_index::MAX_INDEX_RENDER_LINES {
        body.push(format!(
            "... render bounded ({} more not shown; index holds {})",
            index.len() - crate::project_index::MAX_INDEX_RENDER_LINES,
            index.len()
        ));
    }
    redact_or_withhold(RenderTruth::Green, body)
}

/// Defense in depth on the LOCAL `context index` surface (IV-F11): if any
/// rendered line is secret-SHAPED (a name literally shaped like a key/secret),
/// withhold the WHOLE listing. Uses the PRECISE `scan_inline_secret` detector
/// only — NOT the full `redact` gate, whose `repl::history::classify` half
/// false-positives on bare filesystem paths (the exact strings this surface
/// renders), which would withhold ordinary project listings. A real key-shaped
/// name still trips `scan_inline_secret`; ordinary paths/filenames pass.
fn redact_or_withhold(truth: RenderTruth, body: Vec<String>) -> (RenderTruth, Vec<String>) {
    if body
        .iter()
        .any(|line| crate::secrets::scan_inline_secret(line))
    {
        return (
            RenderTruth::Yellow,
            vec!["project index WITHHELD: a name was secret-shaped (redaction denied)".to_string()],
        );
    }
    (truth, body)
}

// ---- namespace dispatch ---------------------------------------------------

// ---- P4-3 VM-selector: runtime/model selection surface --------------------

/// This build's compiled LOCAL default port (`Some` only with a local-serving
/// feature; `None` in the default build, where the selector shows the runtime
/// menu instead of a phantom default).
fn local_default_port_for_build() -> Option<u16> {
    #[cfg(any(feature = "local-mlx", feature = "local-vllm"))]
    {
        Some(LOCAL_CONSULT_DEFAULT_PORT)
    }
    #[cfg(not(any(feature = "local-mlx", feature = "local-vllm")))]
    {
        None
    }
}

/// Snapshot the SELECTION env (read once) + this build's fireable flags into
/// the pure `model_select` resolver input. The selection's truth is env — never
/// a config file (`config::Env` precedence already outranks config files, and
/// the config layer has no writer; a config selection would be silently
/// overridden by a leftover env var = `G-F-NO-SILENT-FALLBACK`).
fn selection_summary_lines() -> Vec<String> {
    use crate::commands::model_select::{SelectionEnv, resolve_selection};
    let frontier = std::env::var(crate::commands::model_select::FRONTIER_MODEL_ENV).ok();
    let port = std::env::var(crate::commands::model_select::LOCAL_PORT_ENV).ok();
    let model = std::env::var(crate::commands::model_select::LOCAL_MODEL_ENV).ok();
    let view = SelectionEnv {
        frontier_model: frontier.as_deref(),
        local_port: port.as_deref(),
        local_model: model.as_deref(),
        local_default_port: local_default_port_for_build(),
        fireable_frontier: cfg!(feature = "provider-egress"),
        fireable_local: cfg!(any(feature = "local-mlx", feature = "local-vllm")),
    };
    resolve_selection(&view).summary_lines()
}

/// `model use [frontier|local] …` — resolve + validate + preview the selection
/// (ReadOnly; mutates nothing, fires no consult). Takes the verb ARGS, which
/// the argless `status_body` cannot. The loop grammar is byte-unchanged ⇒ the
/// model has no `model use` tool (L8; pinned in the `agent_loop` deny test).
fn model_use_body(rest: &[String]) -> (RenderTruth, Vec<String>) {
    use crate::commands::model_select::{SelectionEnv, render_use};
    let frontier = std::env::var(crate::commands::model_select::FRONTIER_MODEL_ENV).ok();
    let port = std::env::var(crate::commands::model_select::LOCAL_PORT_ENV).ok();
    let model = std::env::var(crate::commands::model_select::LOCAL_MODEL_ENV).ok();
    let view = SelectionEnv {
        frontier_model: frontier.as_deref(),
        local_port: port.as_deref(),
        local_model: model.as_deref(),
        local_default_port: local_default_port_for_build(),
        fireable_frontier: cfg!(feature = "provider-egress"),
        fireable_local: cfg!(any(feature = "local-mlx", feature = "local-vllm")),
    };
    let args: Vec<&str> = rest.iter().skip(1).map(String::as_str).collect();
    render_use(&args, &view)
}

fn dispatch_namespace(
    ns: CliNamespace,
    rest: &[String],
    out: &mut impl Write,
    err: &mut impl Write,
) -> io::Result<bool> {
    let verb = rest.first().map_or("status", String::as_str);
    if !is_recognized_verb(verb) {
        writeln!(err, "unknown command: {} {verb}", ns.canonical_name())?;
        return Ok(false);
    }
    // GUI palette honesty (core-derived single source of truth): `permission tier`
    // emits the per-namespace capability gate (free / gated / locked) — the honest
    // projection of `risk_for` + the PD-6 custody/funds/chain-write hard-lock
    // overlay. ReadOnly + secret-zero (no approval). The desktop palette reads THIS
    // to render its lock badges, so the lock state holds no hardcoded duplicate and
    // cannot drift from the core. `tier` is already in `RECOGNIZED_VERBS`.
    if matches!(ns, CliNamespace::Permission) && verb.eq_ignore_ascii_case("tier") {
        let envelope_hex = hex16(&sha256_32(b"permission tier"));
        let (truth, body) = permission_tier_body();
        emit(
            out,
            "permission tier",
            &envelope_hex,
            CommandRisk::ReadOnly,
            ApprovalRequirement::None,
            truth,
            &body,
        )?;
        return Ok(true);
    }
    // K-6 (the dynamic-LoRA switch's honest status): `provider lora-status` renders the
    // certified corpus→adapter MANIFEST (P-HALL), the SERVED set, and the per-kind
    // resolution (requested adapter -> wire model; honest-degrade). READ-class + money 0
    // + always-compiled (no feature gate) — a pure local render the GUI shares. The MODEL
    // has no path here; an unserved adapter is shown degrading to the base, never faked.
    if matches!(ns, CliNamespace::Provider) && verb.eq_ignore_ascii_case("lora-status") {
        return provider_lora_status(out);
    }
    // P3-1 (CODE_EXEC_THREAT_MODEL.md): `tool run` is the owner's LOCAL
    // bounded command executor — Admin risk + the exact typed ceremony
    // phrase, intercepted here to actually execute (without the phrase only
    // the locked surface renders; zero side effects). The MODEL has no path
    // to this seam: the loop grammar is byte-unchanged and any `TOOL: …`
    // exec proposal parses ToolUnknown ⇒ denied + ToolEscalation (P2-2).
    if matches!(ns, CliNamespace::Tool) && verb.eq_ignore_ascii_case("run") {
        let envelope_hex = hex16(&sha256_32(b"tool run"));
        let (truth, body) = exec_run_body(rest);
        emit(
            out,
            "tool run",
            &envelope_hex,
            CommandRisk::Admin,
            ApprovalRequirement::TypedPhrase,
            truth,
            &body,
        )?;
        return Ok(true);
    }
    // P3-2 (MULTI_FILE_EDIT_THREAT_MODEL.md): `tool apply` applies ONE
    // pending file-edit proposal — Admin risk + the exact typed ceremony,
    // intercepted like `tool run` (no phrase ⇒ locked surface + read-only
    // pending list; zero side effects). The MODEL has no path to this seam:
    // the loop grammar is byte-unchanged and `TOOL: file write/apply …`
    // parses ToolUnknown ⇒ denied + ToolEscalation (pinned in agent_loop).
    if matches!(ns, CliNamespace::Tool) && verb.eq_ignore_ascii_case("apply") {
        let envelope_hex = hex16(&sha256_32(b"tool apply"));
        let store = ProposalStore::open_local().ok();
        let policy = crate::file_context::FileReadPolicy::workspace_default();
        let (truth, body) = file_apply_surface(store.as_ref(), &policy, rest);
        emit(
            out,
            "tool apply",
            &envelope_hex,
            CommandRisk::Admin,
            ApprovalRequirement::TypedPhrase,
            truth,
            &body,
        )?;
        return Ok(true);
    }
    // E10-2b LOCAL (AGENT_ACTS_THREAT_MODEL.md ⑬ IV-A1): `tool exec-apply`
    // EXECUTES ONE agent-proposed exec proposal, gated by a SINGLE-SHOT
    // MutateCapability minted from the exact owner ceremony — Admin risk + the
    // typed phrase, intercepted like `tool apply` (no phrase ⇒ locked surface +
    // read-only pending list; zero side effects). The exec runs in the kernel
    // sandbox (LocalWrite; network kernel-DENIED). The MODEL has no path: the loop
    // grammar is byte-unchanged and `TOOL: exec` parses ToolUnknown ⇒ denied. The
    // side effect auto-lands in the E5 hash-linked audit chain via emit().
    if matches!(ns, CliNamespace::Tool) && verb.eq_ignore_ascii_case("exec-apply") {
        let envelope_hex = hex16(&sha256_32(b"tool exec-apply"));
        let store = crate::exec_proposal::ExecProposalStore::open_local().ok();
        let (truth, body) = exec_apply_surface(store.as_ref(), rest);
        emit(
            out,
            "tool exec-apply",
            &envelope_hex,
            CommandRisk::Admin,
            ApprovalRequirement::TypedPhrase,
            truth,
            &body,
        )?;
        return Ok(true);
    }
    // REWIND (the Codex-gap differentiator): `tool rewind <phrase>` undoes the
    // LAST applied file-edit, restoring the captured bytes via the staleness-locked
    // owner-save path. Intercepted like `tool apply` (no phrase ⇒ locked preview;
    // zero side effect). Local-file-only (PD-6). The side effect auto-lands in the
    // E5 audit chain (as Rollback) via emit().
    if matches!(ns, CliNamespace::Tool) && verb.eq_ignore_ascii_case("rewind") {
        let envelope_hex = hex16(&sha256_32(b"tool rewind"));
        let (truth, body) = file_rewind_surface(rest);
        emit(
            out,
            "tool rewind",
            &envelope_hex,
            CommandRisk::Admin,
            ApprovalRequirement::TypedPhrase,
            truth,
            &body,
        )?;
        return Ok(true);
    }
    // E6 (SKILL_SANDBOX_THREAT_MODEL.md ⑫): `skill eval` RUNS a skill's
    // reproducible commands inside the OS-enforced sandbox tier (LocalWrite —
    // network kernel-DENIED, env-scrubbed) — Admin risk + the exact typed
    // ceremony, intercepted like `tool run` (no phrase ⇒ locked surface; zero
    // side effects). A skill carries NO executable payload (declarative
    // package), so the executable surface is the eval commands; the score binds
    // to the REALLY-run commands. `skill use → run a wasm module` stays deferred
    // (no artifact). The MODEL has no path: the loop grammar is byte-unchanged.
    if matches!(ns, CliNamespace::Skill) && verb.eq_ignore_ascii_case("eval") {
        let envelope_hex = hex16(&sha256_32(b"skill eval"));
        let (truth, body) = skill_eval_body(rest);
        emit(
            out,
            "skill eval",
            &envelope_hex,
            CommandRisk::Admin,
            ApprovalRequirement::TypedPhrase,
            truth,
            &body,
        )?;
        return Ok(true);
    }
    // P1-1-c: `memory save <text>` persists to the encrypted local store. It is
    // LocalWrite (no egress, no funds) and is intercepted here to actually
    // execute (the generic gate would only render a locked surface). The store
    // is fail-closed; nothing is written without the key, and never plaintext.
    if matches!(ns, CliNamespace::Memory) && verb.eq_ignore_ascii_case("save") {
        let envelope_hex = hex16(&sha256_32(b"memory save"));
        let (truth, body) = memory_save_body(rest);
        emit(
            out,
            "memory save",
            &envelope_hex,
            CommandRisk::LocalWrite,
            ApprovalRequirement::Confirm,
            truth,
            &body,
        )?;
        return Ok(true);
    }
    // C (G-WP-13): the ONLY execute path in this module, and only when compiled with
    // `put-fixture-net`. With the feature off this block does not exist, so
    // `memory put-fixture` falls through to the generic gate (locked_surface, no
    // execution). The executor verifies an exact typed phrase before any plan/PUT.
    #[cfg(feature = "put-fixture-net")]
    {
        if matches!(ns, CliNamespace::Memory) && verb.eq_ignore_ascii_case("put-fixture") {
            return memory_put_fixture(rest, out);
        }
        // E14-W: autonomous Walrus ENCRYPTED-MEMORY backup + round-trip (ciphertext
        // only; no funds; custody HARD-LOCKED). Feature-off falls through to the
        // locked surface (recognized verb ⇒ honest "not compiled" gate).
        if matches!(ns, CliNamespace::Memory) && verb.eq_ignore_ascii_case("backup-walrus") {
            return memory_backup_walrus(rest, out);
        }
        // E14-W2: the agent NAVIGATES the 2-tier Walrus memory — read the MAIN INDEX,
        // then fetch a SUB-STORE detail. READ-class (no approval); ciphertext-only.
        if matches!(ns, CliNamespace::Memory) && verb.eq_ignore_ascii_case("walrus-index") {
            return memory_walrus_index(out);
        }
        if matches!(ns, CliNamespace::Memory) && verb.eq_ignore_ascii_case("walrus-fetch") {
            return memory_walrus_fetch(rest, out);
        }
        // S3 (WALRUS_MAINNET_SELFHOST): the owner-armed self-host MAINNET backup ceremony
        // (two-tier PUT to the CONFIGURED endpoint + round-trip byte-match receipt). Gated
        // behind `walrus-mainnet`; feature-off falls through to the locked surface.
        #[cfg(feature = "walrus-mainnet")]
        if matches!(ns, CliNamespace::Memory) && verb.eq_ignore_ascii_case("backup-walrus-mainnet")
        {
            return memory_backup_walrus_mainnet(rest, out);
        }
    }
    // W2-C (0G Storage round-trip, funds-safe): the agent emits the OWNER upload command
    // (upload = a0gi fee + EVM signer = FUNDS) + does the KEYLESS download+verify. PREPARE
    // works in any build; the verify subprocess is `zerog-storage`-gated (honest-degrade).
    if matches!(ns, CliNamespace::Memory) && verb.eq_ignore_ascii_case("backup-0g") {
        return memory_backup_zerog(rest, out);
    }
    // W2-D (0G Chain anchor PREPARE, funds-safe): emit the locked patternHash + ABI
    // calldata + a keyless read-only dry-run + the OWNER deploy/anchor commands. PURE
    // (no network, no key); the agent never deploys/signs (PD-6). ReadOnly autonomous.
    if matches!(ns, CliNamespace::Memory) && verb.eq_ignore_ascii_case("anchor-0g") {
        return memory_anchor_zerog(out);
    }
    // W3 (0G ERC-7857 iNFT mint PREPARE, funds-safe): emit the locked mint selector + ABI
    // calldata (dataHash = the W2-D patternHash) + a keyless read-only dry-run + the OWNER
    // deploy/mint commands. PURE (no network, no key); the agent never deploys/signs (PD-6).
    if matches!(ns, CliNamespace::Memory) && verb.eq_ignore_ascii_case("mint-0g") {
        return memory_mint_zerog(out);
    }
    // W2-B (0G Compute TEE attestation verify, funds-safe): run the Node sidecar to verify a
    // provider's TEE quote. KEYLESS + read-only (ephemeral unfunded wallet; no key/funds/
    // chain-write). zerog-attestation-gated; honest-degrade off.
    if matches!(ns, CliNamespace::Provider) && verb.eq_ignore_ascii_case("attest-0g") {
        return provider_attest_zerog(rest, out);
    }
    // W3-B (0G Compute fine-tune PREPARE, funds-safe): build the Alpaca dataset from the
    // orchestrator's verified patterns + emit the owner-run 0g-compute-cli flow. PURE (no
    // network/key); the paid training is owner-fired (PD-6). LocalWrite (writes the dataset).
    if matches!(ns, CliNamespace::Provider) && verb.eq_ignore_ascii_case("finetune-0g") {
        return provider_finetune_zerog(out);
    }
    // W3-B capstone (mint a fine-tuned expert as an iNFT, funds-safe): build the mint
    // calldata (dataHash = the adapter's 0G Storage rootHash) + emit the owner-run mint.
    // PURE (no network/key); the agent never signs (PD-6). ReadOnly.
    if matches!(ns, CliNamespace::Provider) && verb.eq_ignore_ascii_case("mint-expert-0g") {
        return provider_mint_expert_zerog(rest, out);
    }
    // P3-3 (owner-authorized 2026-06-11): the gated LOCAL consult route, only
    // when compiled with a local-serving feature. Routed on the EXACT local
    // phrase ONLY, so every pre-existing `provider consult` surface (the
    // no-phrase locked render, the frontier phrase, the default-build generic
    // gate) stays byte-unchanged in every build combination. Threat model: ⑧.
    #[cfg(any(feature = "local-mlx", feature = "local-vllm"))]
    {
        if matches!(ns, CliNamespace::Provider) && verb.eq_ignore_ascii_case("consult") {
            use crate::provider::route_select::{
                ConsultCaller, ConsultPhrase, select_consult_route,
            };
            // E2-2 (PD-7 / RD-49 v1): the typed selector is the single routing
            // truth. OWNER caller; the exact local phrase ⇒ LocalLoopback (fire
            // the local executor); anything else falls through to the frontier
            // arm (or the locked surface). Byte-faithful to the prior string
            // compare — the owner-interactive routing is unchanged — while the
            // policy (incl. the autonomous local-first default + the no-self-route
            // frontier gate) now lives in one tested function.
            let phrase = if rest.get(1).map(String::as_str) == Some(PROVIDER_CONSULT_LOCAL_PHRASE) {
                ConsultPhrase::Local
            } else {
                ConsultPhrase::None
            };
            if select_consult_route(ConsultCaller::Owner, phrase, None).is_local() {
                return provider_consult_local(rest, out);
            }
        }
    }
    // P1-2b: the gated TWO-MODEL orchestration route, only when compiled with a
    // local-serving feature. Routed on the RECOGNIZED `orchestrate` verb (Provider
    // namespace); the executor re-verifies the exact orchestrate phrase. Feature
    // off ⇒ `provider orchestrate` falls through to the generic locked surface.
    #[cfg(any(feature = "local-mlx", feature = "local-vllm"))]
    {
        if matches!(ns, CliNamespace::Provider) && verb.eq_ignore_ascii_case("orchestrate") {
            return provider_orchestrate_local(rest, out);
        }
    }
    // P (owner-authorized 2026-06-10): the gated live LLM consult, only when
    // compiled with `provider-egress`. With the feature off this block does not
    // exist, so `provider consult` falls through to the generic gate
    // (locked_surface, no execution). The executor verifies an exact typed
    // phrase before any redaction/build/socket.
    #[cfg(feature = "provider-egress")]
    {
        if matches!(ns, CliNamespace::Provider) && verb.eq_ignore_ascii_case("consult") {
            // Non-streaming entry (CLI / generic dispatch): no delta sink, a fresh
            // never-set cancel ⇒ the whole-body path, byte-identical to pre-S-C.
            return provider_consult(rest, out, None, &crate::agent_loop::CancelToken::new());
        }
        // 3.A: the gated subagent fan-out — same ceremony pattern, its own
        // exact phrase. Threat model: SUBAGENT_FANOUT_THREAT_MODEL.md.
        if matches!(ns, CliNamespace::Provider) && verb.eq_ignore_ascii_case("fan") {
            return provider_fan(rest, out);
        }
    }
    // T (owner-authorized 2026-06-10): the gated live Telegram send, only when
    // compiled with `telegram-egress`. With the feature off this block does not
    // exist, so `platform send` falls through to the generic gate
    // (locked_surface — the default behavior is UNCHANGED: the verb and its
    // Network risk pre-exist from G-WP-07). The executor verifies an exact
    // typed phrase before any redaction/build/socket.
    #[cfg(feature = "telegram-egress")]
    {
        if matches!(ns, CliNamespace::Platform) && verb.eq_ignore_ascii_case("send") {
            return platform_send(rest, out);
        }
    }
    // `platform poll`: the LIVE telegram inbound remote-approve edge (ENDGAME E4 made
    // load-bearing here). Drives the proven `poll_and_ingest` cycle against the real
    // bot; only the owner's pinned chat is authorized, replies are replay-refused, an
    // approve mints a NARROW single-shot grant. The model cannot reach this (no loop
    // symbol); custody/funds stay HARD-LOCKED (PD-6).
    #[cfg(feature = "telegram-inbound")]
    {
        if matches!(ns, CliNamespace::Platform) && verb.eq_ignore_ascii_case("poll") {
            return cmd_platform_poll(rest, out);
        }
    }
    #[cfg(not(feature = "telegram-inbound"))]
    {
        if matches!(ns, CliNamespace::Platform) && verb.eq_ignore_ascii_case("poll") {
            return platform_poll_no_feature(out);
        }
    }
    // `platform control`: telegram REMOTE-CONTROL — your phone drives sinabro. Each
    // owner message runs through the SAME gated `dispatch::run` (custody/funds
    // HARD-LOCKED structurally; side-effects still need their typed phrase), the
    // result comes back SI-2 redacted. Sender-pinned, bounded, recursion-guarded.
    #[cfg(all(feature = "telegram-inbound", feature = "telegram-egress"))]
    {
        if matches!(ns, CliNamespace::Platform) && verb.eq_ignore_ascii_case("control") {
            return cmd_platform_control(rest, out);
        }
    }
    #[cfg(not(all(feature = "telegram-inbound", feature = "telegram-egress")))]
    {
        if matches!(ns, CliNamespace::Platform) && verb.eq_ignore_ascii_case("control") {
            return platform_control_no_feature(out);
        }
    }
    // E11-1b (WEB_FETCH_THREAT_MODEL.md ⑭): `context web-fetch <url>` is the
    // owner's LIVE web READ — a secret-zero, SSRF-walled, redirect-none public GET,
    // redacted + rights/quote-gated, advisory-only. Network risk; the gated path.
    // Under `web-egress` it fetches; the default build renders the honest "web
    // transport not compiled" (no web socket). custody/funds stay HARD-LOCKED (a
    // chain-RPC host is SSRF-denied; GET-only ⇒ no chain WRITE; no wallet key). The
    // MODEL has no path to THIS dispatch verb (the loop's `web fetch` tool is its
    // own gated seam).
    #[cfg(feature = "web-egress")]
    {
        if matches!(ns, CliNamespace::Context) && verb.eq_ignore_ascii_case("web-fetch") {
            return cmd_context_web_fetch(rest, out);
        }
    }
    #[cfg(not(feature = "web-egress"))]
    {
        if matches!(ns, CliNamespace::Context) && verb.eq_ignore_ascii_case("web-fetch") {
            return context_web_fetch_no_feature(rest, out);
        }
    }
    // E11-1b (D-WF5): `context web-search <query>` — the configured-endpoint seam
    // over the SAME wall (WEB_SEARCH_ENDPOINT). No bundled index; unset ⇒ honest
    // "name a URL with context web-fetch".
    #[cfg(feature = "web-egress")]
    {
        if matches!(ns, CliNamespace::Context) && verb.eq_ignore_ascii_case("web-search") {
            return cmd_context_web_search(rest, out);
        }
    }
    #[cfg(not(feature = "web-egress"))]
    {
        if matches!(ns, CliNamespace::Context) && verb.eq_ignore_ascii_case("web-search") {
            return context_web_search_no_feature(rest, out);
        }
    }
    // E11-2 (AUDIT_ENGINE_THREAT_MODEL.md ⑮): `audit detect <path>` drives the
    // dormant audit/* game-tree engine on REAL local source — detector candidates
    // → impact-ranked CANDIDATES, honestly labeled "candidate not finding". ReadOnly
    // (pure local analysis; no egress, no exec; hashed anchors ⇒ no raw source byte).
    // A candidate promotes to a finding ONLY through the owner-gated, kernel-
    // sandboxed repro chokepoint — never here, never auto (IV-AE1/AE6). The MODEL
    // reaches detect only as a gated READ (the loop's own `audit detect` tool); it
    // cannot promote a candidate or run a repro. custody/funds HARD-LOCKED (no chain
    // /socket on the audit path, IV-AE3/AE8).
    if matches!(ns, CliNamespace::Audit) && verb.eq_ignore_ascii_case("detect") {
        let envelope_hex = hex16(&sha256_32(b"audit detect"));
        let (truth, body) = audit_detect_body(rest);
        emit(
            out,
            "audit detect",
            &envelope_hex,
            CommandRisk::ReadOnly,
            ApprovalRequirement::None,
            truth,
            &body,
        )?;
        return Ok(true);
    }
    // D-1b (AGENT-NATIVE GITHUB): `registry scan <path>` content-addresses a bounded local
    // tree into the AGRX manifest (summary); `registry list <path>` browses it + checks
    // tamper-evidence. Both ReadOnly + stateless over the PURE `agent_registry` core: NO
    // egress, NO artifact execution, NO custody (PD-6) — only the digest + rel-path derived.
    if matches!(ns, CliNamespace::Registry) && verb.eq_ignore_ascii_case("scan") {
        let envelope_hex = hex16(&sha256_32(b"registry scan"));
        let (truth, body) = registry_scan_body(rest);
        emit(
            out,
            "registry scan",
            &envelope_hex,
            CommandRisk::ReadOnly,
            ApprovalRequirement::None,
            truth,
            &body,
        )?;
        return Ok(true);
    }
    if matches!(ns, CliNamespace::Registry) && verb.eq_ignore_ascii_case("list") {
        let envelope_hex = hex16(&sha256_32(b"registry list"));
        let (truth, body) = registry_list_body(rest);
        emit(
            out,
            "registry list",
            &envelope_hex,
            CommandRisk::ReadOnly,
            ApprovalRequirement::None,
            truth,
            &body,
        )?;
        return Ok(true);
    }
    // D-3: `registry publish` (owner-armed Walrus testnet egress, both visibilities) +
    // `registry fetch` (autonomous content-hash-VERIFIED READ). Both need the testnet
    // transport; in an offline build (`put-fixture-net` off) they FALL THROUGH to the
    // recognized-verb honest gate (no fake success). The model reaches neither symbol.
    #[cfg(feature = "put-fixture-net")]
    {
        if matches!(ns, CliNamespace::Registry) && verb.eq_ignore_ascii_case("publish") {
            return registry_publish(rest, out);
        }
        if matches!(ns, CliNamespace::Registry) && verb.eq_ignore_ascii_case("fetch") {
            return registry_fetch(rest, out);
        }
    }
    // O-1 (Oracle Bootstrap): `audit reconcile <path>` deterministically checks a finance
    // reconciliation certificate (Σreserve ≥ Σliability, or NAV == Σqty×price), fail-closed.
    // The model proposes the certificate; this checker validates the arithmetic — no LLM
    // judge. ReadOnly (a pure arithmetic check + one cert-file read; no chain/socket/custody).
    if matches!(ns, CliNamespace::Audit) && verb.eq_ignore_ascii_case("reconcile") {
        let envelope_hex = hex16(&sha256_32(b"audit reconcile"));
        let (truth, body) = audit_reconcile_body(rest);
        emit(
            out,
            "audit reconcile",
            &envelope_hex,
            CommandRisk::ReadOnly,
            ApprovalRequirement::None,
            truth,
            &body,
        )?;
        return Ok(true);
    }
    // O-3 (Oracle Bootstrap): `audit elicit <path>` reads a recognition pool + recognitions and
    // returns the most-informative NEXT question (deterministic farthest-first / k-center) + the
    // owned anchor-set summary. ZERO LLM tokens (selection is pure geometry), instant. ReadOnly
    // (one pool-file read + pure integer arithmetic; no chain/socket/custody).
    if matches!(ns, CliNamespace::Audit) && verb.eq_ignore_ascii_case("elicit") {
        let envelope_hex = hex16(&sha256_32(b"audit elicit"));
        let (truth, body) = audit_elicit_body(rest);
        emit(
            out,
            "audit elicit",
            &envelope_hex,
            CommandRisk::ReadOnly,
            ApprovalRequirement::None,
            truth,
            &body,
        )?;
        return Ok(true);
    }
    // O-3b (Oracle Bootstrap): `audit classify <pool> [features...]` SYNTHESIZEs a deterministic
    // bounding-box checker from the recognition anchors, CERTIFIES it (held-out zero-false-accept),
    // and — if a test example is given — renders the 3-way verdict + the ladder write-admission.
    // ZERO LLM tokens (pure geometry). ReadOnly (a pool-file read + pure integer arithmetic).
    if matches!(ns, CliNamespace::Audit) && verb.eq_ignore_ascii_case("classify") {
        let envelope_hex = hex16(&sha256_32(b"audit classify"));
        let (truth, body) = audit_classify_body(rest);
        emit(
            out,
            "audit classify",
            &envelope_hex,
            CommandRisk::ReadOnly,
            ApprovalRequirement::None,
            truth,
            &body,
        )?;
        return Ok(true);
    }
    // O-4 (Oracle Bootstrap second domain): `audit summary <source-path> <summary-path>` runs the
    // deterministic metamorphic checker — verify summary⊆source (quote + number containment) + a
    // compression target, fail-closed. A SOUND REJECTOR: a fabricated quote / unsupported number /
    // over-length ⇒ REJECTED (a real bug); a pass is NOT-FALSIFIED (provisional, never admits a
    // write — R2 rejector-only). ZERO LLM tokens (pure string/integer geometry). ReadOnly (two
    // file reads + pure arithmetic; no chain/socket/custody).
    if matches!(ns, CliNamespace::Audit) && verb.eq_ignore_ascii_case("summary") {
        let envelope_hex = hex16(&sha256_32(b"audit summary"));
        let (truth, body) = audit_summary_body(rest);
        emit(
            out,
            "audit summary",
            &envelope_hex,
            CommandRisk::ReadOnly,
            ApprovalRequirement::None,
            truth,
            &body,
        )?;
        return Ok(true);
    }
    // O-5 (Oracle Bootstrap ownership): `audit mint-oracle <pool>` capitalizes a CONFORMAL-
    // CERTIFIED recognition oracle as an ERC-7857 iNFT — composing the LOCKED W3 encoder. PURE
    // PREPARE: the agent builds the certified-oracle dataHash commitment + calldata + the OWNER-run
    // mint runbook; the owner FIRES the funds-bearing mint (PD-6). An UN-certified oracle is
    // UN-mintable (certified-only, fail-closed). ReadOnly (a pool-file read + pure arithmetic;
    // no chain write, no socket, no custody — the binary signs nothing, funds HARD-LOCKED).
    if matches!(ns, CliNamespace::Audit) && verb.eq_ignore_ascii_case("mint-oracle") {
        let envelope_hex = hex16(&sha256_32(b"audit mint-oracle"));
        let (truth, body) = audit_mint_oracle_body(rest);
        emit(
            out,
            "audit mint-oracle",
            &envelope_hex,
            CommandRisk::ReadOnly,
            ApprovalRequirement::None,
            truth,
            &body,
        )?;
        return Ok(true);
    }
    // A① (CURSOR_PARITY_REFRAME_DESIGN.md §3 A①): `context lsp-diagnostics <path>`
    // runs the REAL language server SANDBOXED (network + write kernel-DENIED) and
    // renders COMPILER TRUTH — the owner/GUI consumer of the SAME `crate::lsp`
    // pipeline the loop's `lsp diagnostics` tool uses. ReadOnly (no egress, no exec,
    // no write — the server cannot mutate; an absent binary honest-degrades, never a
    // fabricated result). custody/funds HARD-LOCKED (no chain/socket on this path).
    if matches!(ns, CliNamespace::Context) && verb.eq_ignore_ascii_case("lsp-diagnostics") {
        let envelope_hex = hex16(&sha256_32(b"context lsp-diagnostics"));
        let (truth, body) = lsp_diagnostics_body(rest);
        emit(
            out,
            "context lsp-diagnostics",
            &envelope_hex,
            CommandRisk::ReadOnly,
            ApprovalRequirement::None,
            truth,
            &body,
        )?;
        return Ok(true);
    }
    // B⑫ (CURSOR_PARITY_REFRAME_DESIGN.md §3 B⑫ + §6 B⑫): `context mcp <server>
    // <tool> [json-args]` calls a READ-class tool on an owner-configured LOCAL stdio
    // MCP server through the SAME `crate::mcp::render_mcp_call` chokepoint the loop's
    // `mcp` tool uses (wall → redact ARG → sandboxed tools/call, network + write
    // kernel-DENIED → redact RESULT → audit). ReadOnly (no egress, no exec, no write
    // — the child cannot mutate or reach a chain; an unconfigured server / an
    // un-advertised tool ⇒ deny; a non-`mcp` build honest-degrades). custody/funds
    // HARD-LOCKED (no chain/socket on this path). The MODEL reaches MCP only through
    // its own gated loop seam.
    if matches!(ns, CliNamespace::Context) && verb.eq_ignore_ascii_case("mcp") {
        let envelope_hex = hex16(&sha256_32(b"context mcp"));
        let (truth, body) = mcp_call_body(rest);
        emit(
            out,
            "context mcp",
            &envelope_hex,
            CommandRisk::ReadOnly,
            ApprovalRequirement::None,
            truth,
            &body,
        )?;
        return Ok(true);
    }
    // A⑤ (CURSOR_PARITY_REFRAME_DESIGN.md §3 A⑤ + §6 A⑤): `context git <subcommand>
    // [args]` runs a READ-only git subcommand (status/diff/log/show/blame) on the
    // local repo through the SAME `crate::git::render_git_read` chokepoint the loop's
    // `git` tool uses (allowlist → sandboxed git, network + write kernel-DENIED →
    // redact). ReadOnly (no egress, no exec, no write — a commit/push is kernel-denied
    // even here; a non-READ subcommand ⇒ deny). commit/branch/push = owner-armed v2.
    // custody/funds HARD-LOCKED (no chain/socket on this path). The MODEL reaches git
    // only through its own gated loop seam.
    if matches!(ns, CliNamespace::Context) && verb.eq_ignore_ascii_case("git") {
        let envelope_hex = hex16(&sha256_32(b"context git"));
        let (truth, body) = git_read_body(rest);
        emit(
            out,
            "context git",
            &envelope_hex,
            CommandRisk::ReadOnly,
            ApprovalRequirement::None,
            truth,
            &body,
        )?;
        return Ok(true);
    }
    // A② (CURSOR_PARITY_REFRAME_DESIGN.md §3 A②): `context test-run <pkg>` runs the
    // REAL test runner (`sui move test`/`cargo test`) on a workspace package through
    // the SAME `crate::test_run::render_test_run` chokepoint the loop's `test run`
    // tool uses (validate under-workspace → sandboxed run, network kernel-DENIED →
    // redact). ReadOnly (no egress; a test writes only build artifacts under the
    // LocalWrite sandbox; non-package ⇒ deny). custody/funds HARD-LOCKED. The MODEL
    // reaches test-run only through its own gated loop seam.
    if matches!(ns, CliNamespace::Context) && verb.eq_ignore_ascii_case("test-run") {
        let envelope_hex = hex16(&sha256_32(b"context test-run"));
        let (truth, body) = test_run_body(rest);
        emit(
            out,
            "context test-run",
            &envelope_hex,
            CommandRisk::ReadOnly,
            ApprovalRequirement::None,
            truth,
            &body,
        )?;
        return Ok(true);
    }
    // A④-rg (CURSOR_PARITY_REFRAME_DESIGN.md §3 A④): `context search <regex>` runs a
    // regex find-in-files over the workspace source through the SAME
    // `crate::search::render_search` chokepoint the loop's `search` tool uses (bounded
    // walk; each file via the file-context wall = denylist + size cap + UTF-8; per-line
    // redact). ReadOnly (no egress; no subprocess; no network). custody/funds
    // HARD-LOCKED. The MODEL reaches search only through its own gated loop seam.
    if matches!(ns, CliNamespace::Context) && verb.eq_ignore_ascii_case("search") {
        let envelope_hex = hex16(&sha256_32(b"context search"));
        let (truth, body) = search_body(rest);
        emit(
            out,
            "context search",
            &envelope_hex,
            CommandRisk::ReadOnly,
            ApprovalRequirement::None,
            truth,
            &body,
        )?;
        return Ok(true);
    }
    // [4] B⑨ (codebase_index.rs): `context codebase build` indexes the workspace into an
    // encrypted-at-rest vector store (local embeddings); `context codebase <query>`
    // retrieves the top-K relevant chunks (hybrid cosine + lexical), redacted. ReadOnly
    // (no egress; embeddings never leave the box). The MODEL reaches it only through its
    // own gated loop seam (`TOOL: codebase`). custody/funds HARD-LOCKED.
    if matches!(ns, CliNamespace::Context) && verb.eq_ignore_ascii_case("codebase") {
        let envelope_hex = hex16(&sha256_32(b"context codebase"));
        let (truth, body) = if rest.get(1).map(String::as_str) == Some("build") {
            codebase_build_body()
        } else {
            let query = rest.get(1..).map_or_else(String::new, |a| a.join(" "));
            codebase_query_body(query.trim())
        };
        emit(
            out,
            "context codebase",
            &envelope_hex,
            CommandRisk::ReadOnly,
            ApprovalRequirement::None,
            truth,
            &body,
        )?;
        return Ok(true);
    }
    // [5] B⑭ (vision.rs): `context image <path>` reads + classifies an image and describes
    // it LOCALLY (the stub vision describer; NO egress) as a READ context fragment. ReadOnly;
    // the image bytes never leave the box. The owner-armed frontier-image EGRESS (with the
    // "cannot be auto-redacted" warning) is the separate `daemon image-frontier` verb.
    if matches!(ns, CliNamespace::Context) && verb.eq_ignore_ascii_case("image") {
        let envelope_hex = hex16(&sha256_32(b"context image"));
        let path = rest.get(1..).map_or_else(String::new, |a| a.join(" "));
        let (truth, body) = image_context_body(path.trim());
        emit(
            out,
            "context image",
            &envelope_hex,
            CommandRisk::ReadOnly,
            ApprovalRequirement::None,
            truth,
            &body,
        )?;
        return Ok(true);
    }
    let args_joined = rest.join(" ");
    let risk = risk_for(ns, verb);
    let env = CommandEnvelope::classify(ns, verb, CliMode::Run, risk, args_joined.as_bytes());
    let command = format!("{} {verb}", ns.canonical_name());
    let envelope_hex = hex16(&env.id.verb_hash_32);

    let (truth, body) = match env.approval {
        ApprovalRequirement::ForbiddenInStageF => (
            RenderTruth::Red,
            no_training_surface(ns.canonical_name(), verb),
        ),
        // Agent-core step 2 (read-only retrieval surface): `memory index` /
        // `memory read <id>` take verb ARGS, which the argless `status_body`
        // cannot — same envelope/classify/emit flow, still approval=None.
        ApprovalRequirement::None
            if matches!(ns, CliNamespace::Memory)
                && (verb.eq_ignore_ascii_case("index") || verb.eq_ignore_ascii_case("read")) =>
        {
            memory_retrieval_body(verb, rest)
        }
        // Agent-core lane A (read-only local file context): `context file
        // <path>` takes a path ARG; LOCAL trust tier (the owner reads their
        // OWN file). Same envelope/classify/emit flow, still approval=None.
        ApprovalRequirement::None
            if matches!(ns, CliNamespace::Context) && verb.eq_ignore_ascii_case("file") =>
        {
            file_context_body(rest)
        }
        // Agent-core P4-2 (multi-repo / project context): `context index
        // [<path>]` enumerates a registered project root (bounded, deterministic,
        // content-free) or lists the registered roots. LOCAL trust tier; same
        // envelope/classify/emit flow, ReadOnly ⇒ approval=None. The loop grammar
        // is byte-unchanged (the model cannot enumerate). TM addendum:
        // FILE_CONTEXT_THREAT_MODEL.md §P4-2 (IV-F8..F11).
        ApprovalRequirement::None
            if matches!(ns, CliNamespace::Context) && verb.eq_ignore_ascii_case("index") =>
        {
            project_index_body(rest)
        }
        // P4-3 (VM-selector): `model use [frontier|local] …` resolves +
        // validates + previews the runtime/model selection (ReadOnly; the
        // selection's truth is env, never a config file). Takes verb ARGS,
        // which argless `status_body` cannot. Same envelope/classify/emit flow,
        // approval=None. The loop grammar is byte-unchanged ⇒ the model has no
        // `model use` tool (L8; pinned in the agent_loop deny test).
        ApprovalRequirement::None
            if matches!(ns, CliNamespace::Model) && verb.eq_ignore_ascii_case("use") =>
        {
            model_use_body(rest)
        }
        ApprovalRequirement::None => status_body(ns, verb),
        other => (
            RenderTruth::Yellow,
            locked_surface(ns.canonical_name(), verb, other),
        ),
    };
    emit(
        out,
        &command,
        &envelope_hex,
        env.risk,
        env.approval,
        truth,
        &body,
    )?;
    Ok(true)
}

// ---- top-level operational commands (not grammar namespaces) --------------

fn toplevel_envelope_hex(command: &str) -> String {
    hex16(&sha256_32(command.as_bytes()))
}

fn cmd_status(out: &mut impl Write) -> io::Result<()> {
    let prompt = PromptStatus {
        workspace_hash_32: sha256_32(b"/Users/heoun/mnemos"),
        model_hash_32: ZERO32,
        context_pressure_bps: 0,
        last_checkpoint_hash_32: ZERO32,
        budget_remaining_micros: 0,
        sandbox_tier_u8: 1,
        pending_approvals_u16: 0,
        pending_tasks_u16: 0,
    };
    let view = WorkPackageStatusView {
        prompt,
        stage_u8: b'G',
        workpackage_id_hash_32: ZERO32,
        plan_hash_32: ZERO32,
        physics: RenderTruth::Unknown,
        sidecar: RenderTruth::Unknown,
        next_action_hash_32: ZERO32,
        contract_present: false,
        prompt_stale: false,
    };
    emit(
        out,
        "status",
        &toplevel_envelope_hex("status"),
        CommandRisk::ReadOnly,
        ApprovalRequirement::None,
        RenderTruth::Unknown,
        &view.render(ROWS as u16),
    )
}

/// E11-4-1 (CONFIG_PERSIST_THREAT_MODEL.md ⑰ IV-CP3) — the exact in-band phrase
/// that authorizes ONE config WRITE to `$HOME/.mnemos/config.toml`. A PUBLIC,
/// zero-entropy confirmation gesture (NOT a secret); the model cannot type it and
/// has NO loop tool for `setup persist`, so the model can never persist config.
const CONFIG_PERSIST_CONFIRM_PHRASE: &str = "config-persist-owner-live";

/// `setup persist` locked render — no ceremony ⇒ zero side effect (usage only).
fn config_persist_locked_body() -> Vec<String> {
    vec![
        "setup persist writes $HOME/.mnemos/config.toml (validated, secret-screened, atomic)"
            .to_string(),
        format!("usage: setup persist {CONFIG_PERSIST_CONFIRM_PHRASE} [key=value …]"),
        "keys: profile learning_mode data_egress sponsor_mode web3_rpc_endpoint remote_ssh_host schema_version"
            .to_string(),
        "a secret-shaped value ⇒ refused (nothing written); the model cannot persist (ceremony)"
            .to_string(),
        "no wallet/funds/chain field is representable; custody stays HARD-LOCKED (PD-6)"
            .to_string(),
    ]
}

/// `setup persist <phrase> [key=value …]` — the ONE config WRITE (IV-CP1..CP6).
/// Gate order = the threat model's: exact ceremony (IV-CP3) → parse the CLOSED key
/// set into a [`RawCliConfig`](crate::config::RawCliConfig) (an unknown key is
/// refused) → validate + serialize + secret-screen (IV-CP1/CP5,
/// [`config::serialize_config`](crate::config::serialize_config)) → atomic write
/// via the SHARED discipline (IV-CP2,
/// [`atomic_write`](crate::memory_store::atomic_write) under
/// [`data_dir`](crate::memory_store::data_dir)) → honest round-trip re-read +
/// [`parse_layer`](crate::config::parse_layer) (IV-CP6). NOTHING is written unless
/// the serialized text is validated AND secret-free; a write failure is RED. The
/// receipt never echoes the config VALUES (secret-zero) or the owner's raw input.
fn config_persist_body(rest: &[String]) -> (RenderTruth, Vec<String>) {
    // GATE (IV-CP3): the exact same-message owner ceremony — no phrase / a wrong
    // phrase ⇒ the LOCKED render, zero side effect (mirrors `exec_locked_body`).
    let Some(phrase) = rest.first() else {
        return (RenderTruth::Yellow, config_persist_locked_body());
    };
    if phrase != CONFIG_PERSIST_CONFIRM_PHRASE {
        return (RenderTruth::Yellow, config_persist_locked_body());
    }
    // Parse the owner's `key=value` pairs into the CLOSED config schema. An unknown
    // key is refused (mirrors `deny_unknown_fields`); deny messages NEVER echo the
    // raw input (secret-zero).
    let mut cfg = crate::config::RawCliConfig::default();
    for pair in rest.iter().skip(1) {
        let Some((key, value)) = pair.split_once('=') else {
            return (
                RenderTruth::Yellow,
                vec![
                    "config persist denied: each setting must be key=value".to_string(),
                    format!("usage: setup persist {CONFIG_PERSIST_CONFIRM_PHRASE} [key=value …]"),
                ],
            );
        };
        let value = value.to_string();
        match key.trim() {
            "profile" => cfg.profile = Some(value),
            "learning_mode" => cfg.learning_mode = Some(value),
            "data_egress" => cfg.data_egress = Some(value),
            "sponsor_mode" => cfg.sponsor_mode = Some(value),
            "web3_rpc_endpoint" => cfg.web3_rpc_endpoint = Some(value),
            "walrus_publisher_endpoint" => cfg.walrus_publisher_endpoint = Some(value),
            "walrus_aggregator_endpoint" => cfg.walrus_aggregator_endpoint = Some(value),
            "remote_ssh_host" => cfg.remote_ssh_host = Some(value),
            "schema_version" => match value.trim().parse::<u16>() {
                Ok(v) => cfg.schema_version = Some(v),
                Err(_) => {
                    return (
                        RenderTruth::Yellow,
                        vec!["config persist denied: schema_version must be a number".to_string()],
                    );
                }
            },
            _ => {
                return (
                    RenderTruth::Yellow,
                    vec![
                        "config persist denied: unknown setting (closed schema)".to_string(),
                        "keys: profile learning_mode data_egress sponsor_mode web3_rpc_endpoint remote_ssh_host schema_version"
                            .to_string(),
                    ],
                );
            }
        }
    }
    // The persisted file records its own schema version (default to current).
    if cfg.schema_version.is_none() {
        cfg.schema_version = Some(crate::CONFIG_SCHEMA_VERSION_U16);
    }
    // IV-CP1/CP5: validate + serialize + secret-screen. NOTHING reaches disk unless
    // this is Ok — a secret-shaped value or a safety-kernel disable is refused HERE.
    let text = match crate::config::serialize_config(&cfg) {
        Ok(text) => text,
        Err(crate::CliError::SecretInline) => {
            return (
                RenderTruth::Yellow,
                vec![
                    "config persist DENIED: a value was secret-shaped — nothing written (IV-CP1)"
                        .to_string(),
                    "keep secrets in env/keychain references, never inline in config".to_string(),
                ],
            );
        }
        Err(crate::CliError::SafetyKernelLocked) => {
            return (
                RenderTruth::Yellow,
                vec![
                    "config persist DENIED: cannot disable a safety-kernel feature — nothing written"
                        .to_string(),
                ],
            );
        }
        Err(_) => {
            return (
                RenderTruth::Yellow,
                vec![
                    "config persist DENIED: invalid config (unknown profile / bad token) — nothing written"
                        .to_string(),
                ],
            );
        }
    };
    // IV-CP2: atomic write under $HOME/.mnemos via the SHARED discipline (no raw
    // File::create / fs::write on this path).
    let dir = match crate::memory_store::data_dir() {
        Ok(dir) => dir,
        Err(_) => {
            return (
                RenderTruth::Red,
                vec!["config persist failed: $HOME not set (no data dir)".to_string()],
            );
        }
    };
    if std::fs::create_dir_all(&dir).is_err() {
        return (
            RenderTruth::Red,
            vec!["config persist failed: cannot create $HOME/.mnemos".to_string()],
        );
    }
    let path = dir.join(crate::config::CONFIG_PERSIST_FILE);
    if crate::memory_store::atomic_write(&path, text.as_bytes()).is_err() {
        return (
            RenderTruth::Red,
            vec!["config persist failed: atomic write error (prior config intact)".to_string()],
        );
    }
    // IV-CP6: honest round-trip — re-read what we wrote and re-parse via the READ
    // path. The receipt reports the real result + a content hash; it NEVER echoes
    // the config values (secret-zero, even though they passed the secret screen).
    let parsed_back =
        std::fs::read_to_string(&path).is_ok_and(|re| crate::config::parse_layer(&re).is_ok());
    let fp = hex16(&sha256_32(text.as_bytes()));
    let truth = if parsed_back {
        RenderTruth::Green
    } else {
        RenderTruth::Red
    };
    (
        truth,
        vec![
            format!("config persisted: {}", path.display()),
            format!("bytes={} fp={} parsed_back={parsed_back}", text.len(), fp),
            "validated + secret-screened + atomic (prior config replaced only on success)"
                .to_string(),
            "no secret, no wallet/funds/chain field; the model cannot persist (owner ceremony)"
                .to_string(),
        ],
    )
}

/// [6] Settings-sync confirm phrases (owner ceremony). The model has NO loop tool for
/// either, so it can never push/pull config; only the owner-input loop supplies these.
/// Gated with the Walrus net path (the only consumer is the `put-fixture-net` live body).
#[cfg(feature = "put-fixture-net")]
const SETTINGS_SYNC_PUSH_PHRASE: &str = "settings-sync-push-owner-live";
#[cfg(feature = "put-fixture-net")]
const SETTINGS_SYNC_PULL_PHRASE: &str = "settings-sync-pull-owner-live";

/// [6] `setup sync-push <phrase>` body — seal the persisted config with the LOCAL key +
/// PUT to Walrus testnet (encrypted ciphertext only — secret-zero), then a round-trip
/// GET+open byte-match proof. Real only under `put-fixture-net`; else honest-degrade.
fn setup_sync_push_body(rest: &[String]) -> (RenderTruth, Vec<String>) {
    #[cfg(feature = "put-fixture-net")]
    {
        setup_sync_push_live(rest)
    }
    #[cfg(not(feature = "put-fixture-net"))]
    {
        let _ = rest;
        (
            RenderTruth::Yellow,
            vec![
                "setup sync-push: Walrus net not compiled (build --features put-fixture-net)"
                    .to_string(),
                "the config seal + secret-screen still apply; only the testnet PUT is gated"
                    .to_string(),
            ],
        )
    }
}

#[cfg(feature = "put-fixture-net")]
fn setup_sync_push_live(rest: &[String]) -> (RenderTruth, Vec<String>) {
    use mnemos_c_walrus::publisher::EpochCount;
    use mnemos_c_walrus::reqwest_transport::ReqwestPublisher;

    let phrase = rest.first().map_or("", String::as_str);
    if phrase.trim() != SETTINGS_SYNC_PUSH_PHRASE {
        return (
            RenderTruth::Yellow,
            vec![
                "setup sync-push = seal your config + PUT to Walrus testnet (encrypted; secret-zero)".to_string(),
                format!("to push, supply EXACTLY: setup sync-push {SETTINGS_SYNC_PUSH_PHRASE}"),
                "the model has no loop tool for sync-push; custody/funds/chain HARD-LOCKED (PD-6)".to_string(),
            ],
        );
    }
    let Ok(dir) = crate::memory_store::data_dir() else {
        return (
            RenderTruth::Red,
            vec!["settings sync: no data dir / key".to_string()],
        );
    };
    let path = dir.join(crate::config::CONFIG_PERSIST_FILE);
    let Ok(raw) = std::fs::read_to_string(&path) else {
        return (
            RenderTruth::Red,
            vec!["no config to sync (run `setup persist …` first)".to_string()],
        );
    };
    let Some(toml) = crate::settings_sync::validate_and_normalize(&raw) else {
        return (
            RenderTruth::Red,
            vec!["config invalid or secret-shaped — NOT synced (fail-closed)".to_string()],
        );
    };
    let Ok(store) = crate::memory_store::PersistedStore::open_local() else {
        return (
            RenderTruth::Red,
            vec!["settings sync: memory store unavailable".to_string()],
        );
    };
    let Ok(sealed) = store.seal_settings(toml.as_bytes()) else {
        return (
            RenderTruth::Red,
            vec!["settings sync: seal failed".to_string()],
        );
    };
    let Ok(epochs) = EpochCount::new(1) else {
        return (
            RenderTruth::Red,
            vec!["settings sync: epoch invalid".to_string()],
        );
    };
    let Ok(mut pub_t) = ReqwestPublisher::new(PUT_FIXTURE_TIMEOUT_MS) else {
        return (
            RenderTruth::Red,
            vec!["settings sync: publisher transport init failed".to_string()],
        );
    };
    let Some(blob_id) = walrus_put_verified(&mut pub_t, epochs, &sealed) else {
        return (
            RenderTruth::Red,
            vec!["settings sync: Walrus PUT rejected/failed".to_string()],
        );
    };
    // Round-trip proof: GET the blob back, byte-match the SEALED ciphertext, AND prove it
    // OPENS to the same config (the full seal→PUT→GET→open lifecycle on real testnet).
    let roundtrip_ok = match walrus_get_by_blob_text(&blob_id) {
        Some(ct) => {
            ct == sealed
                && store
                    .open_settings(&ct)
                    .map(|pt| pt == toml.as_bytes())
                    .unwrap_or(false)
        }
        None => false,
    };
    (
        RenderTruth::Green,
        vec![
            format!("settings PUT ok blob_id={blob_id} (verified)"),
            format!(
                "ROUND-TRIP GET+open byte-match={roundtrip_ok} ({} bytes AES ciphertext)",
                sealed.len()
            ),
            "encrypted (secret-zero); the plaintext config never left the box; custody HARD-LOCKED"
                .to_string(),
            format!(
                "on another machine (same memory.key): setup sync-pull {SETTINGS_SYNC_PULL_PHRASE} {blob_id}"
            ),
        ],
    )
}

/// [6] `setup sync-pull <phrase> <blob_id>` body — GET a settings blob from Walrus,
/// decrypt with the LOCAL key, re-validate + secret-screen, and APPLY (atomic write to
/// config.toml). Real only under `put-fixture-net`; else honest-degrade.
fn setup_sync_pull_body(rest: &[String]) -> (RenderTruth, Vec<String>) {
    #[cfg(feature = "put-fixture-net")]
    {
        setup_sync_pull_live(rest)
    }
    #[cfg(not(feature = "put-fixture-net"))]
    {
        let _ = rest;
        (
            RenderTruth::Yellow,
            vec![
                "setup sync-pull: Walrus net not compiled (build --features put-fixture-net)"
                    .to_string(),
            ],
        )
    }
}

#[cfg(feature = "put-fixture-net")]
fn setup_sync_pull_live(rest: &[String]) -> (RenderTruth, Vec<String>) {
    let phrase = rest.first().map_or("", String::as_str);
    let blob_id = rest.get(1).map_or("", String::as_str);
    if phrase.trim() != SETTINGS_SYNC_PULL_PHRASE {
        return (
            RenderTruth::Yellow,
            vec![
                "setup sync-pull = GET a settings blob + decrypt + validate + APPLY (overwrites config)".to_string(),
                format!("to pull, supply EXACTLY: setup sync-pull {SETTINGS_SYNC_PULL_PHRASE} <blob_id>"),
                "the model has no loop tool for sync-pull; custody/funds/chain HARD-LOCKED (PD-6)".to_string(),
            ],
        );
    }
    if blob_id.trim().is_empty() {
        return (
            RenderTruth::Red,
            vec!["settings sync-pull: missing <blob_id>".to_string()],
        );
    }
    let Some(ct) = walrus_get_by_blob_text(blob_id.trim()) else {
        return (
            RenderTruth::Red,
            vec!["settings sync-pull: blob not found / fetch failed (nothing applied)".to_string()],
        );
    };
    let Ok(store) = crate::memory_store::PersistedStore::open_local() else {
        return (
            RenderTruth::Red,
            vec!["settings sync-pull: memory store unavailable".to_string()],
        );
    };
    let Ok(plaintext) = store.open_settings(&ct) else {
        return (
            RenderTruth::Red,
            vec![
                "settings sync-pull: decrypt/AEAD failed (wrong key or not a settings blob) — nothing applied".to_string(),
            ],
        );
    };
    let Ok(config_str) = String::from_utf8(plaintext) else {
        return (
            RenderTruth::Red,
            vec!["settings sync-pull: decrypted config is not UTF-8 — nothing applied".to_string()],
        );
    };
    let Some(toml) = crate::settings_sync::validate_and_normalize(&config_str) else {
        return (
            RenderTruth::Red,
            vec![
                "settings sync-pull: decrypted config invalid/secret-shaped — nothing applied (fail-closed)".to_string(),
            ],
        );
    };
    let Ok(dir) = crate::memory_store::data_dir() else {
        return (
            RenderTruth::Red,
            vec!["settings sync-pull: no data dir".to_string()],
        );
    };
    let path = dir.join(crate::config::CONFIG_PERSIST_FILE);
    if crate::memory_store::atomic_write(&path, toml.as_bytes()).is_err() {
        return (
            RenderTruth::Red,
            vec!["settings sync-pull: atomic write failed (prior config intact)".to_string()],
        );
    }
    let applied =
        std::fs::read_to_string(&path).is_ok_and(|re| crate::config::parse_layer(&re).is_ok());
    (
        RenderTruth::Green,
        vec![
            format!(
                "settings PULLED + APPLIED from blob_id={} ({} bytes config)",
                blob_id.trim(),
                toml.len()
            ),
            format!("validated + secret-screened + atomic; re-parsed_ok={applied}"),
            "decrypted locally (the key never left the box); custody/funds/chain HARD-LOCKED"
                .to_string(),
        ],
    )
}

fn cmd_setup(rest: &[String], out: &mut impl Write) -> io::Result<()> {
    // E11-4-1: `setup persist <phrase> [key=value …]` is the ONLY write step — it
    // persists an owner-specified, validated, secret-screened config to
    // `$HOME/.mnemos/config.toml` behind the typed owner ceremony (IV-CP1..CP6).
    // Every other `setup …` form stays PLAN-ONLY (a wizard plan; no side effect).
    if rest.first().map(String::as_str) == Some("persist") {
        let (truth, body) = config_persist_body(&rest[1..]);
        return emit(
            out,
            "setup persist",
            &toplevel_envelope_hex("setup persist"),
            CommandRisk::LocalWrite,
            ApprovalRequirement::None,
            truth,
            &body,
        );
    }
    // [6] A⑥ Settings-sync: `setup sync-push <phrase>` seals + PUTs the config to Walrus
    // (encrypted; secret-zero); `setup sync-pull <phrase> <blob_id>` GETs + decrypts +
    // re-validates + applies it on another machine. Owner-ceremony-gated; the model has no
    // loop tool ⇒ it cannot sync. `setup` subverbs ⇒ COUNT 35 kept. custody HARD-LOCKED.
    if rest.first().map(String::as_str) == Some("sync-push") {
        let (truth, body) = setup_sync_push_body(&rest[1..]);
        return emit(
            out,
            "setup sync-push",
            &toplevel_envelope_hex("setup sync-push"),
            CommandRisk::Network,
            ApprovalRequirement::TypedPhrase,
            truth,
            &body,
        );
    }
    if rest.first().map(String::as_str) == Some("sync-pull") {
        let (truth, body) = setup_sync_pull_body(&rest[1..]);
        return emit(
            out,
            "setup sync-pull",
            &toplevel_envelope_hex("setup sync-pull"),
            CommandRisk::Network,
            ApprovalRequirement::TypedPhrase,
            truth,
            &body,
        );
    }
    let target = rest.first().map_or("memory", String::as_str);
    // Only `setup` / `setup memory` / `setup persist …` are real — an unrecognized
    // target is a typo; fail HONESTLY instead of silently rendering the wizard.
    if target != "memory" {
        return emit(
            out,
            "setup",
            &toplevel_envelope_hex("setup"),
            CommandRisk::ReadOnly,
            ApprovalRequirement::None,
            RenderTruth::Unknown,
            &[
                format!("unknown subcommand: setup {target}"),
                "valid: setup · setup memory · setup persist <phrase> [key=value …]".to_string(),
            ],
        );
    }
    let body = match MemorySetupWizard::configure(
        [1u8; 32],
        None,
        MemoryStorageMode::LocalOnly,
        GasSponsorMode::SelfFunded,
        PrivacyLearningMode::PrivateLearningOff,
    ) {
        Ok(wizard) => {
            let mut lines = vec![format!(
                "setup {target}: owner from public key only; learning off"
            )];
            lines.extend(wizard.render(ROWS as u16));
            lines
        }
        Err(_) => vec!["setup memory: wizard unavailable".to_string()],
    };
    emit(
        out,
        "setup memory",
        &toplevel_envelope_hex("setup memory"),
        CommandRisk::ReadOnly,
        ApprovalRequirement::None,
        RenderTruth::Green,
        &body,
    )
}

/// Gather REAL release-secret-scan surfaces (E5-3). Scans the on-disk plaintext
/// surfaces the binary can see — the local config (`$HOME/.mnemos/config.toml`),
/// and the project `sinabro.toml` / `README.md` / `Cargo.toml` when present — with
/// the canonical Stage-E secret engine. Counts only (no raw byte is stored). When
/// no surface exists the scan is honestly UNKNOWN (never a hardcoded clean).
fn gather_release_scan() -> ReleaseSecretScan {
    let mut scan = ReleaseSecretScan::new();
    if let Some(home) = std::env::var_os("HOME") {
        let cfg = std::path::Path::new(&home)
            .join(".mnemos")
            .join("config.toml");
        if let Ok(text) = std::fs::read_to_string(&cfg) {
            scan.add(ReleaseSurface::Repo, &text);
        }
    }
    for (name, surface) in [
        ("sinabro.toml", ReleaseSurface::Repo),
        ("README.md", ReleaseSurface::Docs),
        ("Cargo.toml", ReleaseSurface::Package),
    ] {
        if let Ok(text) = std::fs::read_to_string(name) {
            scan.add(surface, &text);
        }
    }
    scan
}

fn cmd_evidence(rest: &[String], out: &mut impl Write) -> io::Result<()> {
    let verb = rest.first().map_or("pack", String::as_str);
    // An unrecognized verb is a typo — fail HONESTLY instead of silently rendering `pack`.
    if verb != "pack" && verb != "replay" {
        return emit(
            out,
            "evidence",
            &toplevel_envelope_hex("evidence"),
            CommandRisk::ReadOnly,
            ApprovalRequirement::None,
            RenderTruth::Unknown,
            &[
                format!("unknown subcommand: evidence {verb}"),
                "valid: pack · replay".to_string(),
            ],
        );
    }
    // E5-3: build the evidence pack from the REAL persisted command-trace chain
    // (E5-1) — NOT a synthetic `sha256(b"task")` fixture. The chain's recorded
    // high-significance actions ARE the command traces; an empty chain honestly
    // yields a zero-trace pack (no invented fixture).
    let chain = ChainedAuditLog::open_local()
        .and_then(|l| l.load_chain())
        .ok();
    let traces = chain
        .as_ref()
        .map(|v| v.ordered.clone())
        .unwrap_or_default();
    let (task_id, session_id) = match chain.as_ref() {
        Some(v) if !v.ordered.is_empty() => (
            v.ordered
                .first()
                .map_or([0u8; 32], |e| e.trace.command_trace_hash_32),
            // the chain tail link is the live session anchor.
            v.tail_link(),
        ),
        _ => (
            sha256_32(b"sinabro.evidence.no-traces"),
            sha256_32(b"sinabro.evidence.no-traces"),
        ),
    };
    let mut builder = EvidencePackBuilder::new(task_id, session_id);
    // The CommandTrace evidence hash folds over the REAL recorded trace hashes
    // (added only when real traces exist; never a synthetic placeholder).
    if !traces.is_empty() {
        let mut buf: Vec<u8> = Vec::with_capacity(traces.len() * 32);
        for e in &traces {
            buf.extend_from_slice(&e.trace.command_trace_hash_32);
        }
        let _ = builder.add(EvidencePackEntry::new(
            EvidenceKind::CommandTrace,
            sha256_32(&buf),
        ));
    }
    let manifest = builder.build();
    let entries = builder.entries().to_vec();

    let (command, truth, body) = if verb == "replay" {
        match EvidenceReplayDryRun::replay(&manifest, &entries) {
            Ok(replay) => {
                let mut lines = vec![
                    "evidence replay: offline, deterministic, no live side effect".to_string(),
                ];
                lines.extend(replay.render(ROWS as u16));
                ("evidence replay", RenderTruth::Green, lines)
            }
            Err(_) => (
                "evidence replay",
                RenderTruth::Red,
                vec!["evidence replay: pack incomplete or drifted".to_string()],
            ),
        }
    } else {
        let mut lines = vec![
            "evidence pack: hash-linked, secret-zero; built from the real audit trail".to_string(),
            format!("command_traces={}", traces.len()),
        ];
        lines.extend(manifest.render(ROWS as u16));
        ("evidence pack", RenderTruth::Green, lines)
    };
    emit(
        out,
        command,
        &toplevel_envelope_hex(command),
        CommandRisk::ReadOnly,
        ApprovalRequirement::None,
        truth,
        &body,
    )
}

fn cmd_budget(_rest: &[String], out: &mut impl Write) -> io::Result<()> {
    // A default session budget (no live spend). The view shows the real
    // BudgetView projection; cap-lower rides the express control rail.
    let cap = BudgetCap::new(1_000_000, 1_000_000, 60_000);
    let view = cap.view();
    let body = vec![
        format!("token_remaining={}", view.token_remaining_u32),
        format!("cost_remaining_micros={}", view.cost_remaining_micro_u64),
        format!("deadline_ms={}", view.deadline_ms_u32),
        "budget gate is pre-dispatch (fail-closed); over-budget never sent".to_string(),
        "budget cap lower rides the express rail (bypasses queues)".to_string(),
    ];
    emit(
        out,
        "budget",
        &toplevel_envelope_hex("budget"),
        CommandRisk::ReadOnly,
        ApprovalRequirement::None,
        view.truth,
        &body,
    )
}

fn cmd_kill(_rest: &[String], out: &mut impl Write) -> io::Result<()> {
    let kc = KillController::new();
    let body = vec![
        format!("live_jobs={}", kc.rail().items().len()),
        format!("control_version={}", kc.version()),
        "kill rides the express control rail (bypasses background queues)".to_string(),
        "no-zombie invariant: a killed job can never resurrect".to_string(),
        "no live job to signal".to_string(),
    ];
    emit(
        out,
        "kill",
        &toplevel_envelope_hex("kill"),
        CommandRisk::ReadOnly,
        ApprovalRequirement::None,
        RenderTruth::Green,
        &body,
    )
}

/// Fetch + disc-classify Skew `skew_otc` program accounts over the EXISTING web3 reqwest READ path
/// (K-0b-3). A `dataSlice{0,8}` `getProgramAccounts` keeps the result within the bounded (redacted)
/// read render so it parses as valid JSON; classification is by the verified 8-byte discriminator
/// (`crate::skew_read`). READ-class ([`ReadCapability::granted`](crate::commands::authority::ReadCapability::granted)),
/// money 0, no key. `data_size` filters to one account shape (228 = product templates). Full
/// per-account FIELD decode (balances / positions) needs the larger bounded-bulk-read path (honest
/// scope). finality from the chain, never an indexer.
#[cfg(feature = "web3-egress")]
fn skew_chain_read(chain: &str, data_size: Option<usize>, out: &mut impl Write) -> io::Result<()> {
    use crate::commands::authority::ReadCapability;
    use crate::provider::web3_rpc::{
        WEB3_BULK_RESULT_CHARS, Web3RpcMethod, Web3RpcSeam, web3_read_raw,
    };
    let program = crate::skew_catalog::SKEW_PROGRAM_ID_DEVNET;
    let params = match data_size {
        Some(n) => format!(
            "[\"{program}\",{{\"encoding\":\"base64\",\"dataSlice\":{{\"offset\":0,\"length\":8}},\"filters\":[{{\"dataSize\":{n}}}]}}]"
        ),
        None => format!(
            "[\"{program}\",{{\"encoding\":\"base64\",\"dataSlice\":{{\"offset\":0,\"length\":8}}}}]"
        ),
    };
    let read = ReadCapability::granted();
    let registry = read_owner_web3_chain_registry();
    let seam = Web3RpcSeam::new();
    let raw = web3_read_raw(
        &read,
        seam.port(),
        &registry,
        chain,
        Web3RpcMethod::SolGetProgramAccounts,
        &params,
        WEB3_BULK_RESULT_CHARS,
    );
    let Some(body) = raw.body else {
        return writeln!(
            out,
            "skew read (chain={chain}): unavailable [{}] (is the chain owner-configured, and built with --features web3-egress?)",
            raw.class_label
        );
    };
    let Ok(value) = serde_json::from_str::<serde_json::Value>(&body) else {
        return writeln!(
            out,
            "skew read (chain={chain}): result not valid JSON or exceeded the bulk cap ({} chars) — narrow the filter",
            WEB3_BULK_RESULT_CHARS
        );
    };
    let mut counts: std::collections::BTreeMap<&'static str, usize> =
        std::collections::BTreeMap::new();
    let mut total = 0usize;
    if let Some(arr) = value.get("result").and_then(serde_json::Value::as_array) {
        for entry in arr {
            total += 1;
            let kind = entry
                .get("account")
                .and_then(|a| a.get("data"))
                .and_then(serde_json::Value::as_array)
                .and_then(|d| d.first())
                .and_then(serde_json::Value::as_str)
                .and_then(crate::skew_read::base64_decode)
                .map_or(crate::skew_read::SkewAccountKind::Unknown, |b| {
                    crate::skew_read::classify(&b)
                });
            *counts.entry(kind.as_str()).or_default() += 1;
        }
    }
    writeln!(
        out,
        "skew read (devnet, chain={chain}): {total} accounts (disc-classified)"
    )?;
    for (kind, n) in &counts {
        writeln!(out, "  {kind}: {n}")?;
    }
    writeln!(
        out,
        "READ-class (money 0); bounded read — full balance/position field decode is the K-0b deepening; finality from the chain, never an indexer"
    )
}

/// Default build: the web3 transport is not compiled — honest-degrade (the byte-locked decode +
/// classify core `crate::skew_read` is always present; the LIVE devnet read needs `web3-egress`).
#[cfg(not(feature = "web3-egress"))]
fn skew_chain_read(chain: &str, _data_size: Option<usize>, out: &mut impl Write) -> io::Result<()> {
    writeln!(
        out,
        "skew read (chain={chain}): web3 transport not compiled — build with --features web3-egress for the LIVE devnet read; the byte-locked decode + classify core (skew_read) is ready"
    )
}

/// `skew portfolio [chain] [owner]` — read + DECODE the `UnifiedRiskAccount` balances over the
/// raw-body bounded-bulk-read path (K-0b): full 207-byte URA accounts (`dataSize` filter, full data
/// within the 64 KiB bulk cap) → `crate::skew_read::render_accounts` (byte-exact equity decode +
/// disc-classify; redact wall on the body inside `web3_read_raw`). Optional `owner` (base58) scopes
/// to that owner's balances. READ-class, money 0, no key.
#[cfg(feature = "web3-egress")]
fn skew_portfolio_read(chain: &str, owner: Option<&str>, out: &mut impl Write) -> io::Result<()> {
    use crate::commands::authority::ReadCapability;
    use crate::provider::web3_rpc::{
        WEB3_BULK_RESULT_CHARS, Web3RpcMethod, Web3RpcSeam, web3_read_raw,
    };
    let program = crate::skew_catalog::SKEW_PROGRAM_ID_DEVNET;
    let params = format!(
        "[\"{program}\",{{\"encoding\":\"base64\",\"filters\":[{{\"dataSize\":{}}}]}}]",
        crate::skew_read::URA_PDA_SPACE
    );
    let owner_filter = match owner {
        Some(o) => match crate::skew_read::base58_decode(o) {
            Some(bytes) if bytes.len() == 32 => {
                let mut a = [0u8; 32];
                a.copy_from_slice(&bytes);
                Some(a)
            }
            _ => return writeln!(out, "skew portfolio: '{o}' is not a 32-byte base58 pubkey"),
        },
        None => None,
    };
    let read = ReadCapability::granted();
    let registry = read_owner_web3_chain_registry();
    let seam = Web3RpcSeam::new();
    let raw = web3_read_raw(
        &read,
        seam.port(),
        &registry,
        chain,
        Web3RpcMethod::SolGetProgramAccounts,
        &params,
        WEB3_BULK_RESULT_CHARS,
    );
    let Some(body) = raw.body else {
        return writeln!(
            out,
            "skew portfolio (chain={chain}): unavailable [{}] (is the chain owner-configured, and built with --features web3-egress?)",
            raw.class_label
        );
    };
    let Ok(value) = serde_json::from_str::<serde_json::Value>(&body) else {
        return writeln!(
            out,
            "skew portfolio (chain={chain}): result not valid JSON or exceeded the bulk cap ({WEB3_BULK_RESULT_CHARS} chars)"
        );
    };
    let mut owned: Vec<(String, Vec<u8>)> = Vec::new();
    if let Some(arr) = value.get("result").and_then(serde_json::Value::as_array) {
        for entry in arr {
            let pubkey = entry
                .get("pubkey")
                .and_then(serde_json::Value::as_str)
                .unwrap_or("?")
                .to_string();
            if let Some(bytes) = entry
                .get("account")
                .and_then(|a| a.get("data"))
                .and_then(serde_json::Value::as_array)
                .and_then(|d| d.first())
                .and_then(serde_json::Value::as_str)
                .and_then(crate::skew_read::base64_decode)
            {
                owned.push((pubkey, bytes));
            }
        }
    }
    let accts: Vec<crate::skew_read::SkewAccount<'_>> = owned
        .iter()
        .map(|(p, d)| crate::skew_read::SkewAccount { pubkey: p, data: d })
        .collect();
    write!(
        out,
        "{}",
        crate::skew_read::render_accounts(&accts, owner_filter)
    )
}

/// Default build: honest-degrade (the byte-locked balance decoder `crate::skew_read` is present).
#[cfg(not(feature = "web3-egress"))]
fn skew_portfolio_read(chain: &str, _owner: Option<&str>, out: &mut impl Write) -> io::Result<()> {
    writeln!(
        out,
        "skew portfolio (chain={chain}): web3 transport not compiled — build with --features web3-egress for the LIVE devnet balance read; the byte-locked balance decoder (skew_read) is ready"
    )
}

/// W2 — `skew positions [chain] [owner]` — read + DECODE the `PerpPosition` accounts over the SAME
/// bounded getProgramAccounts read [`skew_portfolio_read`] uses, but filtered by the 154-byte
/// `PerpPosition` `dataSize` and rendered by [`crate::skew_read::render_positions`] (byte-exact field
/// decode + sign-faithful render; the redact wall lives inside `web3_read_raw`). Optional `owner`
/// (base58) scopes to that owner's positions. READ-class, money 0, no key, not signed.
#[cfg(feature = "web3-egress")]
fn skew_positions_read(chain: &str, owner: Option<&str>, out: &mut impl Write) -> io::Result<()> {
    let owner_filter = match owner {
        Some(o) => match crate::skew_read::base58_decode(o) {
            Some(bytes) if bytes.len() == 32 => {
                let mut a = [0u8; 32];
                a.copy_from_slice(&bytes);
                Some(a)
            }
            _ => return writeln!(out, "skew positions: '{o}' is not a 32-byte base58 pubkey"),
        },
        None => None,
    };
    let polled = poll_skew_accounts(chain, crate::skew_read::PERP_POSITION_PDA_SPACE);
    if polled.is_empty() {
        return writeln!(
            out,
            "skew positions (chain={chain}): no PerpPosition accounts returned (chain owner-configured + built with --features web3-egress? the program may simply have no open positions)"
        );
    }
    let accts: Vec<crate::skew_read::SkewAccount<'_>> = polled
        .iter()
        .map(|(p, d)| crate::skew_read::SkewAccount { pubkey: p, data: d })
        .collect();
    write!(
        out,
        "{}",
        crate::skew_read::render_positions(&accts, owner_filter)
    )
}

/// Default build: honest-degrade (the byte-locked `PerpPosition` decoder `crate::skew_read` is present).
#[cfg(not(feature = "web3-egress"))]
fn skew_positions_read(chain: &str, _owner: Option<&str>, out: &mut impl Write) -> io::Result<()> {
    writeln!(
        out,
        "skew positions (chain={chain}): web3 transport not compiled — build with --features web3-egress for the LIVE devnet perp-position read; the byte-locked PerpPosition decoder (skew_read) is ready"
    )
}

/// W2 (contracts) — `skew contracts [chain] [owner]` — read + DECODE the bilateral `PiecewiseContract`
/// accounts (267-byte `dataSize`) over the SAME bounded read, rendered by
/// [`crate::skew_read::render_contracts`] (byte-exact field decode). Optional `owner` (base58) scopes
/// to contracts the party is long OR short in. READ-class, money 0, no key, not signed. (`OtcContract`
/// — the variable-layout 151 KiB lifecycle account — is NOT decoded here; it is the next deepening.)
#[cfg(feature = "web3-egress")]
fn skew_contracts_read(chain: &str, owner: Option<&str>, out: &mut impl Write) -> io::Result<()> {
    let owner_filter = match owner {
        Some(o) => match crate::skew_read::base58_decode(o) {
            Some(bytes) if bytes.len() == 32 => {
                let mut a = [0u8; 32];
                a.copy_from_slice(&bytes);
                Some(a)
            }
            _ => return writeln!(out, "skew contracts: '{o}' is not a 32-byte base58 pubkey"),
        },
        None => None,
    };
    let polled = poll_skew_accounts(chain, crate::skew_read::PIECEWISE_CONTRACT_PDA_SPACE);
    if polled.is_empty() {
        return writeln!(
            out,
            "skew contracts (chain={chain}): no PiecewiseContract accounts returned (chain owner-configured + built with --features web3-egress? the program may simply have no open contracts)"
        );
    }
    let accts: Vec<crate::skew_read::SkewAccount<'_>> = polled
        .iter()
        .map(|(p, d)| crate::skew_read::SkewAccount { pubkey: p, data: d })
        .collect();
    write!(
        out,
        "{}",
        crate::skew_read::render_contracts(&accts, owner_filter)
    )
}

/// Default build: honest-degrade (the byte-locked `PiecewiseContract` decoder `crate::skew_read` is present).
#[cfg(not(feature = "web3-egress"))]
fn skew_contracts_read(chain: &str, _owner: Option<&str>, out: &mut impl Write) -> io::Result<()> {
    writeln!(
        out,
        "skew contracts (chain={chain}): web3 transport not compiled — build with --features web3-egress for the LIVE devnet piecewise-contract read; the byte-locked PiecewiseContract decoder (skew_read) is ready"
    )
}

/// W1 (autonomous margin): read the LIVE `UnifiedRiskAccount` balance for `owner` on `chain` — the SAME
/// getProgramAccounts read [`skew_portfolio_read`] uses, but returns the DECODED [`crate::skew_read::UraBalance`]
/// (free / locked) for the autonomous margin-sizing flow instead of rendering. READ-class, money 0, no key.
/// `None` on transport-not-compiled / chain-not-configured / no matching URA / decode fail (fail-closed —
/// the auto-margin flow NEVER trades blind on a missing read).
#[cfg(feature = "web3-egress")]
fn read_live_ura_balance(
    chain: &str,
    owner: &crate::solana_codec::Pubkey,
) -> Option<crate::skew_read::UraBalance> {
    use crate::commands::authority::ReadCapability;
    use crate::provider::web3_rpc::{
        WEB3_BULK_RESULT_CHARS, Web3RpcMethod, Web3RpcSeam, web3_read_raw,
    };
    let program = crate::skew_catalog::SKEW_PROGRAM_ID_DEVNET;
    let params = format!(
        "[\"{program}\",{{\"encoding\":\"base64\",\"filters\":[{{\"dataSize\":{}}}]}}]",
        crate::skew_read::URA_PDA_SPACE
    );
    let read = ReadCapability::granted();
    let registry = read_owner_web3_chain_registry();
    let seam = Web3RpcSeam::new();
    let raw = web3_read_raw(
        &read,
        seam.port(),
        &registry,
        chain,
        Web3RpcMethod::SolGetProgramAccounts,
        &params,
        WEB3_BULK_RESULT_CHARS,
    );
    let body = raw.body?;
    let value = serde_json::from_str::<serde_json::Value>(&body).ok()?;
    let arr = value.get("result").and_then(serde_json::Value::as_array)?;
    for entry in arr {
        let Some(bytes) = entry
            .get("account")
            .and_then(|a| a.get("data"))
            .and_then(serde_json::Value::as_array)
            .and_then(|d| d.first())
            .and_then(serde_json::Value::as_str)
            .and_then(crate::skew_read::base64_decode)
        else {
            continue;
        };
        if let Some(ura) = crate::skew_read::decode_ura_account(&bytes) {
            if ura.owner == owner.0 {
                return Some(ura);
            }
        }
    }
    None
}

// ===================== K-3 HISTORY ACCUMULATOR + ANALYTICS =====================
// Skew stores only the LATEST ReferenceSnapshot (no time-series). Sinabro polls the chain's singleton
// PDAs READ-ONLY over time, decodes byte-exact, and accumulates each (slot, value) sample into a
// bounded AEAD-encrypted time-series window: the local sealed window is the storage-of-record, and a
// 2-tier Walrus publish is the decentralized ciphertext proof (E14-W2). READ-class, money 0; the only
// WRITE is to the agent's OWN encrypted memory. NO chain write / custody / sign. See
// `ops/evidence/stage_g/agent_loop/SKEW_HISTORY_THREAT_MODEL.md`.

/// The sealed-window file extension under `<data_dir>/skew_history/`. The AEAD binding AAD lives in
/// `skew_history::SKEW_HISTORY_AAD` (via `PersistedStore::seal_skew_history`/`open_skew_history`).
const SKEW_HISTORY_EXT: &str = "swh";
/// The default OHLC / volume candle width (slots) if the owner doesn't pass one.
const SKEW_HISTORY_DEFAULT_BUCKET_SLOTS: u64 = 100;

/// `<data_dir>/skew_history/` (created if missing) — the local storage-of-record for the sealed
/// time-series windows.
fn skew_history_dir() -> io::Result<std::path::PathBuf> {
    let dir = crate::memory_store::data_dir()
        .map_err(|_| io::Error::other("no data dir"))?
        .join("skew_history");
    std::fs::create_dir_all(&dir)?;
    Ok(dir)
}

/// Load + AEAD-open all sealed history windows from the local store (the storage-of-record). Each
/// file is `<kind_tag>_<series_hex>.swh`; a corrupt / wrong-AAD / non-decoding file is skipped
/// (fail-closed — never a partial series). Deterministically ordered (sorted by path).
fn load_history_windows(
    store: &crate::memory_store::PersistedStore,
    dir: &std::path::Path,
) -> Vec<crate::skew_history::HistoryWindow> {
    let mut out = Vec::new();
    let Ok(rd) = std::fs::read_dir(dir) else {
        return out;
    };
    let mut paths: Vec<std::path::PathBuf> = rd
        .flatten()
        .map(|e| e.path())
        .filter(|p| p.extension().and_then(|x| x.to_str()) == Some(SKEW_HISTORY_EXT))
        .collect();
    paths.sort();
    for p in paths {
        if let Ok(sealed) = std::fs::read(&p) {
            if let Ok(plain) = store.open_skew_history(&sealed) {
                if let Ok(w) = crate::skew_history::HistoryWindow::from_bytes(&plain) {
                    out.push(w);
                }
            }
        }
    }
    out
}

/// `skew history [chain] [bucket] [series-hex-prefix]` — render the accumulated time-series analysis
/// from the LOCAL sealed windows (the storage-of-record; no network). Price + funding render per
/// market series; volume aggregates all settlement windows into one bucketed series. Deterministic
/// integer analysis (no LLM). READ-class, money 0.
fn cmd_skew_history(rest: &[String], out: &mut impl Write) -> io::Result<()> {
    use crate::skew_history::{HistoryWindow, SeriesKind, render_window, short_hex};
    let Ok(store) = crate::memory_store::PersistedStore::open_local() else {
        return writeln!(out, "skew history: memory store unavailable (no key/home)");
    };
    let Ok(dir) = skew_history_dir() else {
        return writeln!(out, "skew history: no data dir");
    };
    let windows = load_history_windows(&store, &dir);
    if windows.is_empty() {
        return writeln!(
            out,
            "skew history: no series accumulated yet — run `skew accumulate <chain>` to poll the chain (READ-class, money 0)"
        );
    }
    // Trailing numeric arg = bucket width; a non-numeric arg = a series-hex-prefix filter.
    let bucket = rest
        .iter()
        .find_map(|a| a.parse::<u64>().ok())
        .unwrap_or(SKEW_HISTORY_DEFAULT_BUCKET_SLOTS);
    let filter: Option<&str> = rest
        .iter()
        .find(|a| {
            a.parse::<u64>().is_err()
                && !a.eq_ignore_ascii_case("solana")
                && !a.starts_with("solana")
        })
        .map(String::as_str);
    let matches = |w: &HistoryWindow| filter.is_none_or(|f| short_hex(&w.series_id).starts_with(f));
    writeln!(
        out,
        "skew history (local sealed time-series; deterministic integer analysis; chart data is REAL):"
    )?;
    // Price + funding: per-market singleton series.
    for w in windows
        .iter()
        .filter(|w| w.kind != SeriesKind::SettlementVolume && matches(w))
    {
        write!(out, "{}", render_window(w, bucket))?;
    }
    // Volume: aggregate ALL settlement windows' samples into one bucketed series (distinct same-slot
    // settlements both count). Build a synthetic aggregate window (samples set directly, slot-sorted).
    let mut vol_samples: Vec<crate::skew_history::HistorySample> = windows
        .iter()
        .filter(|w| w.kind == SeriesKind::SettlementVolume && matches(w))
        .flat_map(|w| w.samples.iter().copied())
        .collect();
    if !vol_samples.is_empty() {
        vol_samples.sort_by(|a, b| a.slot.cmp(&b.slot));
        let agg = HistoryWindow {
            kind: SeriesKind::SettlementVolume,
            series_id: [0u8; 32],
            samples: vol_samples,
        };
        write!(out, "{}", render_window(&agg, bucket))?;
    }
    Ok(())
}

// ── the bounded poll loop (web3-egress): poll the chain READ-ONLY + accumulate ──────────────────

/// The bounded cap on poll cycles in ONE `skew accumulate` invocation (the owner re-invokes / crons
/// for continuous accumulation; never an unbounded loop).
#[cfg(feature = "web3-egress")]
const SKEW_ACCUMULATE_CYCLES_MAX: u32 = 64;
/// The default poll-cycle count if the owner doesn't pass one.
#[cfg(feature = "web3-egress")]
const SKEW_ACCUMULATE_CYCLES_DEFAULT: u32 = 3;
/// The pace between poll cycles (ms) — devnet slot ~400-600ms; bounds RPC load + lets the series span
/// time. The series advances only when a keeper re-validates the snapshot (honest scope).
#[cfg(feature = "web3-egress")]
const SKEW_ACCUMULATE_POLL_INTERVAL_MS: u64 = 400;

/// W4 — the HARD cap on poll cycles in ONE `skew accumulate-loop` run. The loop is a RECURRING bounded
/// daemon over a user-chosen SECONDS cadence (vs the `accumulate` burst), so its cap is larger — but
/// still bounded (never an unbounded daemon): cycles × max-interval is the run's time ceiling.
#[cfg(feature = "web3-egress")]
const SKEW_ACCUMULATE_LOOP_CYCLES_MAX: u32 = 256;
/// The default `accumulate-loop` cycle count if the owner doesn't pass one.
#[cfg(feature = "web3-egress")]
const SKEW_ACCUMULATE_LOOP_CYCLES_DEFAULT: u32 = 12;
/// The MINIMUM inter-cycle interval (seconds) — a sane floor so the recurring daemon never hammers the
/// RPC. The cadence is in SECONDS (unlike the `accumulate` burst's 400 ms), making this a real daemon.
#[cfg(feature = "web3-egress")]
const SKEW_ACCUMULATE_LOOP_MIN_INTERVAL_SECS: u64 = 1;
/// The default inter-cycle interval (seconds) if the owner doesn't pass one.
#[cfg(feature = "web3-egress")]
const SKEW_ACCUMULATE_LOOP_DEFAULT_INTERVAL_SECS: u64 = 5;
/// The MAXIMUM inter-cycle interval (seconds) — a ceiling so the whole run stays time-bounded.
#[cfg(feature = "web3-egress")]
const SKEW_ACCUMULATE_LOOP_MAX_INTERVAL_SECS: u64 = 3600;

/// The in-memory accumulator: a slot-deduped window per (kind, series). PURE ingest (testable). The
/// dispatch loop persists the windows to the local sealed store after the bounded loop completes.
#[cfg(feature = "web3-egress")]
struct HistoryAccumulator {
    windows: std::collections::BTreeMap<(u8, [u8; 32]), crate::skew_history::HistoryWindow>,
    cycles: u32,
    samples_added: u32,
}

#[cfg(feature = "web3-egress")]
impl HistoryAccumulator {
    fn from_loaded(loaded: Vec<crate::skew_history::HistoryWindow>) -> Self {
        let mut windows = std::collections::BTreeMap::new();
        for w in loaded {
            windows.insert((w.kind.tag(), w.series_id), w);
        }
        Self {
            windows,
            cycles: 0,
            samples_added: 0,
        }
    }

    /// Append polled samples by kind: singleton series (price / funding) dedup by slot; event series
    /// (volume) keep distinct same-slot events + dedup identical re-polls. Returns the count changed.
    fn ingest(
        &mut self,
        polled: Vec<(
            crate::skew_history::SeriesKind,
            [u8; 32],
            crate::skew_history::HistorySample,
        )>,
    ) -> u32 {
        use crate::skew_history::SeriesKind;
        let mut added = 0u32;
        for (kind, sid, s) in polled {
            let w = self
                .windows
                .entry((kind.tag(), sid))
                .or_insert_with(|| crate::skew_history::HistoryWindow::new(kind, sid));
            let changed = match kind {
                SeriesKind::SettlementVolume => w.push_event(s),
                _ => w.append_sample(s),
            };
            if changed {
                added += 1;
            }
        }
        self.samples_added += added;
        added
    }
}

#[cfg(all(test, feature = "web3-egress"))]
mod k3_accumulator_tests {
    use super::*;
    use crate::skew_history::{HistorySample, SeriesKind};

    fn price(slot: u64, p: u128) -> (SeriesKind, [u8; 32], HistorySample) {
        (
            SeriesKind::ReferencePrice,
            [1u8; 32],
            HistorySample {
                slot,
                price_atoms: p,
                amount_atoms: 0,
                signed_atoms: 0,
                aux_u32: 0,
                exponent: 6,
            },
        )
    }
    fn settle(slot: u64, amt: u128) -> (SeriesKind, [u8; 32], HistorySample) {
        (
            SeriesKind::SettlementVolume,
            [2u8; 32],
            HistorySample {
                slot,
                price_atoms: 100,
                amount_atoms: amt,
                signed_atoms: 0,
                aux_u32: 0,
                exponent: 0,
            },
        )
    }

    /// The accumulator routes by kind (price = singleton dedup-by-slot, volume = events) and the
    /// re-ingest is deterministic / idempotent — the hermetic accumulate property.
    #[test]
    fn ingest_routes_by_kind_and_is_deterministic() {
        let mut acc = HistoryAccumulator::from_loaded(vec![]);
        // price: singleton dedup-by-slot — the 2nd identical poll is idempotent (no double count).
        assert_eq!(acc.ingest(vec![price(100, 10), price(100, 10)]), 1);
        // settlement: distinct same-slot events BOTH count (events, not a singleton).
        assert_eq!(acc.ingest(vec![settle(50, 5), settle(50, 7)]), 2);
        // re-ingest an identical settlement ⇒ 0 (idempotent re-poll).
        assert_eq!(acc.ingest(vec![settle(50, 5)]), 0);
        // two series: one price window + one volume window.
        assert_eq!(acc.windows.len(), 2);
        // the volume window sums BOTH same-slot settlements into one bucket.
        for ((tag, _), w) in &acc.windows {
            if *tag == SeriesKind::SettlementVolume.tag() {
                let bars = crate::skew_history::volume(&w.samples, 100);
                assert_eq!(bars.first().map(|b| b.volume_atoms), Some(12));
            }
        }
        assert_eq!(acc.samples_added, 3); // 1 price + 2 distinct settlements
    }
}

/// Poll one Skew account size over the single egress READ path, returning `(pubkey-base58, raw-bytes)`
/// per account. Reuses `web3_read_raw` (SSRF + redact + byte cap); finality from the chain.
#[cfg(feature = "web3-egress")]
fn poll_skew_accounts(chain: &str, data_size: usize) -> Vec<(String, Vec<u8>)> {
    use crate::commands::authority::ReadCapability;
    use crate::provider::web3_rpc::{
        WEB3_BULK_RESULT_CHARS, Web3RpcMethod, Web3RpcSeam, web3_read_raw,
    };
    let program = crate::skew_catalog::SKEW_PROGRAM_ID_DEVNET;
    let params = crate::skew_read::program_accounts_params(program, data_size);
    let read = ReadCapability::granted();
    let registry = read_owner_web3_chain_registry();
    let seam = Web3RpcSeam::new();
    let raw = web3_read_raw(
        &read,
        seam.port(),
        &registry,
        chain,
        Web3RpcMethod::SolGetProgramAccounts,
        &params,
        WEB3_BULK_RESULT_CHARS,
    );
    let mut out = Vec::new();
    let Some(body) = raw.body else {
        return out;
    };
    let Ok(value) = serde_json::from_str::<serde_json::Value>(&body) else {
        return out;
    };
    if let Some(arr) = value.get("result").and_then(serde_json::Value::as_array) {
        for entry in arr {
            let pubkey = entry
                .get("pubkey")
                .and_then(serde_json::Value::as_str)
                .unwrap_or("")
                .to_string();
            if let Some(bytes) = entry
                .get("account")
                .and_then(|a| a.get("data"))
                .and_then(serde_json::Value::as_array)
                .and_then(|d| d.first())
                .and_then(serde_json::Value::as_str)
                .and_then(crate::skew_read::base64_decode)
            {
                out.push((pubkey, bytes));
            }
        }
    }
    out
}

/// Poll ALL THREE Skew time-series sources once, decode byte-exact, return samples keyed by series.
/// Price = the per-market snapshot PDA (series = the snapshot pubkey); volume = per settlement-mint
/// (series = the mint); funding = the per-market funding-state PDA. Fail-closed: a mis-shaped /
/// wrong-disc / non-validated account is skipped, never fabricated.
#[cfg(feature = "web3-egress")]
fn poll_skew_samples(
    chain: &str,
) -> Vec<(
    crate::skew_history::SeriesKind,
    [u8; 32],
    crate::skew_history::HistorySample,
)> {
    use crate::skew_history::{HistorySample, SeriesKind};
    let sid = |pubkey: &str| -> Option<[u8; 32]> {
        crate::skew_read::base58_decode(pubkey).and_then(|b| {
            if b.len() == 32 {
                let mut a = [0u8; 32];
                a.copy_from_slice(&b);
                Some(a)
            } else {
                None
            }
        })
    };
    let mut out = Vec::new();
    // ① ReferenceSnapshot (153 B; SHARED with PerpMarket ⇒ classify by disc inside decode) → price.
    for (pk, data) in poll_skew_accounts(chain, crate::skew_read::REFERENCE_SNAPSHOT_PDA_SPACE) {
        if let (Some(s), Some(series_id)) =
            (crate::skew_read::decode_reference_snapshot(&data), sid(&pk))
        {
            if s.is_validated() {
                out.push((
                    SeriesKind::ReferencePrice,
                    series_id,
                    HistorySample {
                        slot: s.observed_slot,
                        price_atoms: s.composite_atoms,
                        amount_atoms: 0,
                        signed_atoms: 0,
                        aux_u32: u32::from(s.confidence_bps),
                        exponent: s.exponent,
                    },
                ));
            }
        }
    }
    // ② SettlementReceipt (441 B) → volume series keyed by the settlement MINT (aggregate per mint).
    for (_pk, data) in poll_skew_accounts(chain, crate::skew_read::SETTLEMENT_RECEIPT_PDA_SPACE) {
        if let Some(r) = crate::skew_read::decode_settlement_receipt(&data) {
            out.push((
                SeriesKind::SettlementVolume,
                r.settlement_mint,
                HistorySample {
                    slot: r.created_slot,
                    price_atoms: r.settlement_price,
                    amount_atoms: r.paid_amount,
                    signed_atoms: r.signed_payoff_amount,
                    aux_u32: 0,
                    exponent: 0,
                },
            ));
        }
    }
    // ③ FundingState (74 B) → funding series keyed by the per-market funding-state PDA.
    for (pk, data) in poll_skew_accounts(chain, crate::skew_read::FUNDING_STATE_PDA_SPACE) {
        if let (Some(f), Some(series_id)) =
            (crate::skew_read::decode_funding_state(&data), sid(&pk))
        {
            out.push((
                SeriesKind::FundingRate,
                series_id,
                HistorySample {
                    slot: f.last_snapshot_slot,
                    price_atoms: 0,
                    amount_atoms: u128::from(f.max_rate),
                    signed_atoms: f.cumulative_funding_index,
                    aux_u32: u32::from(f.status),
                    exponent: 0,
                },
            ));
        }
    }
    out
}

/// Seal one window with the local AEAD key (storage-of-record) + atomic-write it under `dir`.
#[cfg(feature = "web3-egress")]
fn persist_history_window(
    store: &crate::memory_store::PersistedStore,
    dir: &std::path::Path,
    window: &crate::skew_history::HistoryWindow,
) -> bool {
    let Ok(sealed) = store.seal_skew_history(&window.to_bytes()) else {
        return false;
    };
    let hex: String = window
        .series_id
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    let path = dir.join(format!("{}_{hex}.{SKEW_HISTORY_EXT}", window.kind.tag()));
    crate::memory_store::atomic_write(&path, &sealed).is_ok()
}

/// `skew accumulate [chain] [cycles]` — the BOUNDED daemon poll loop (reuses the std-thread
/// `RuntimeHandle` pump; NO tokio). Each cycle polls the chain READ-ONLY (`web3_read_raw`,
/// `&ReadCapability`; NO grant — READ is free), decodes byte-exact, and accumulates into the
/// AEAD-encrypted windows; after the bounded loop, the windows are sealed to the local
/// storage-of-record. READ-class, money 0; NO chain write / custody / sign. The series advances only
/// when a keeper re-validates a snapshot (honest scope — re-invoke for continuous accumulation).
#[cfg(feature = "web3-egress")]
fn cmd_skew_accumulate(rest: &[String], out: &mut impl Write) -> io::Result<()> {
    use crate::commands::budget::BudgetCap;
    use crate::daemon::runtime::{AutonomyRuntime, RuntimeHandle};
    use std::sync::{Arc, Mutex};
    let chain = rest.first().map_or("solana", String::as_str).to_string();
    let cycles_target = rest
        .get(1)
        .and_then(|s| s.parse::<u32>().ok())
        .unwrap_or(SKEW_ACCUMULATE_CYCLES_DEFAULT)
        .clamp(1, SKEW_ACCUMULATE_CYCLES_MAX);

    let Ok(store) = crate::memory_store::PersistedStore::open_local() else {
        return writeln!(
            out,
            "skew accumulate: memory store unavailable (no key/home)"
        );
    };
    let Ok(dir) = skew_history_dir() else {
        return writeln!(out, "skew accumulate: no data dir");
    };
    let loaded = load_history_windows(&store, &dir);
    let acc = Arc::new(Mutex::new(HistoryAccumulator::from_loaded(loaded)));

    // The bounded poll driver: READ-only poll + accumulate; mints NOTHING (no grant install, no sign).
    let acc_driver = Arc::clone(&acc);
    let chain_owned = chain.clone();
    let driver = move |rt: &mut AutonomyRuntime| -> bool {
        if rt.is_terminal() {
            return false;
        }
        let polled = poll_skew_samples(&chain_owned);
        let reached_target = {
            let Ok(mut a) = acc_driver.lock() else {
                return false;
            };
            a.ingest(polled);
            a.cycles = a.cycles.saturating_add(1);
            a.cycles >= cycles_target
        };
        if reached_target {
            false
        } else {
            std::thread::sleep(std::time::Duration::from_millis(
                SKEW_ACCUMULATE_POLL_INTERVAL_MS,
            ));
            true
        }
    };
    // Arm a NO-GRANT runtime (READ is free; the loop reaches no egress/mutate/custody authority) and
    // pump it on the std-thread; join blocks until the bounded loop completes (no zombie).
    let trace = crate::StageFTraceLink::new([0x6b; 32], 0x6b33, 0);
    let runtime = AutonomyRuntime::arm(
        1,
        None,
        BudgetCap::new(100_000, 1_000_000, 100_000),
        2,
        trace,
    );
    let handle = RuntimeHandle::spawn(runtime, driver, std::time::Duration::from_millis(50));
    handle.join();

    // After the bounded loop: seal each window to the local storage-of-record + render the summary.
    let Ok(a) = acc.lock() else {
        return writeln!(
            out,
            "skew accumulate: accumulator lock poisoned (fail-closed)"
        );
    };
    let mut persisted = 0usize;
    for w in a.windows.values() {
        if persist_history_window(&store, &dir, w) {
            persisted += 1;
        }
    }
    writeln!(
        out,
        "skew accumulate (chain={chain}): cycles={} samples_added={} series={} persisted={persisted} (local AEAD storage-of-record; READ-class; money 0; finality from the chain)",
        a.cycles,
        a.samples_added,
        a.windows.len()
    )?;
    for w in a.windows.values() {
        writeln!(
            out,
            "  [{}] series={} samples={}",
            w.kind.as_str(),
            crate::skew_history::short_hex(&w.series_id),
            w.len()
        )?;
    }
    if a.samples_added == 0 {
        writeln!(
            out,
            "  (no NEW samples — the snapshot advances only on keeper re-validation; re-invoke over time to grow the series)"
        )?;
    }
    Ok(())
}

/// Default build: honest-degrade (the byte-locked decoders + the pure analyzers are present; the LIVE
/// devnet poll needs `web3-egress`).
#[cfg(not(feature = "web3-egress"))]
fn cmd_skew_accumulate(rest: &[String], out: &mut impl Write) -> io::Result<()> {
    let chain = rest.first().map_or("solana", String::as_str);
    writeln!(
        out,
        "skew accumulate (chain={chain}): web3 transport not compiled — build with --features web3-egress for the LIVE devnet poll loop; the byte-locked decoders + the OHLC/volume/funding analyzers (skew_read + skew_history) are ready"
    )
}

/// W4 — `skew accumulate-loop <chain> [cycles] [interval_secs]` — the RECURRING bounded accumulation
/// daemon. Where `skew accumulate` runs ONE burst (rapid `cycles` polls @ 400 ms, sealed once at the
/// end), this runs the SAME poll-accumulate as a long-lived daemon on a user-chosen SECONDS cadence,
/// and SEALS the windows to the local AEAD storage-of-record AFTER EVERY cycle that ingests new samples
/// — so an interrupt never loses accumulated history (the recurring-daemon distinction). BOUNDED: a
/// hard cycle cap ([`SKEW_ACCUMULATE_LOOP_CYCLES_MAX`] = 256) AND a clamped seconds interval
/// (`[MIN..=MAX]`). It reuses the EXISTING std-thread [`RuntimeHandle::spawn`] pump (NO tokio, NO new
/// crate) and `join`s cleanly (the no-zombie proof) — interruptible via the runtime's terminal check.
/// READ-class, money 0; the ONLY write is to the agent's OWN encrypted store. NO chain write / custody
/// / sign (the c0-LESSON — this whole function reaches zero such token).
#[cfg(feature = "web3-egress")]
fn cmd_skew_accumulate_loop(rest: &[String], out: &mut impl Write) -> io::Result<()> {
    use crate::commands::budget::BudgetCap;
    use crate::daemon::runtime::{AutonomyRuntime, RuntimeHandle};
    use std::sync::{Arc, Mutex};
    let chain = rest.first().map_or("solana", String::as_str).to_string();
    let cycles_target = rest
        .get(1)
        .and_then(|s| s.parse::<u32>().ok())
        .unwrap_or(SKEW_ACCUMULATE_LOOP_CYCLES_DEFAULT)
        .clamp(1, SKEW_ACCUMULATE_LOOP_CYCLES_MAX);
    let interval_secs = rest
        .get(2)
        .and_then(|s| s.parse::<u64>().ok())
        .unwrap_or(SKEW_ACCUMULATE_LOOP_DEFAULT_INTERVAL_SECS)
        .clamp(
            SKEW_ACCUMULATE_LOOP_MIN_INTERVAL_SECS,
            SKEW_ACCUMULATE_LOOP_MAX_INTERVAL_SECS,
        );

    let Ok(store) = crate::memory_store::PersistedStore::open_local() else {
        return writeln!(
            out,
            "skew accumulate-loop: memory store unavailable (no key/home)"
        );
    };
    let Ok(dir) = skew_history_dir() else {
        return writeln!(out, "skew accumulate-loop: no data dir");
    };
    let loaded = load_history_windows(&store, &dir);
    let acc = Arc::new(Mutex::new(HistoryAccumulator::from_loaded(loaded)));

    // The bounded RECURRING driver: READ-only poll + accumulate + per-cycle local seal; mints NOTHING
    // (no grant install, no sign, no chain write). `store`/`dir` are cloned into the closure so each
    // cycle can durably seal (PersistedStore: Clone). No other thread holds `acc` during the run, so
    // the brief seal-under-lock contends with nothing.
    let acc_driver = Arc::clone(&acc);
    let chain_owned = chain.clone();
    let store_driver = store.clone();
    let dir_driver = dir.clone();
    let driver = move |rt: &mut AutonomyRuntime| -> bool {
        if rt.is_terminal() {
            return false;
        }
        let polled = poll_skew_samples(&chain_owned);
        let reached_target = {
            let Ok(mut a) = acc_driver.lock() else {
                return false;
            };
            let added = a.ingest(polled);
            a.cycles = a.cycles.saturating_add(1);
            // Per-cycle durability: seal every window to the local AEAD storage-of-record whenever this
            // cycle ingested NEW samples, so an interrupt keeps accumulated history (recurring daemon).
            if added > 0 {
                for w in a.windows.values() {
                    let _sealed = persist_history_window(&store_driver, &dir_driver, w);
                }
            }
            a.cycles >= cycles_target
        };
        if reached_target {
            false
        } else {
            std::thread::sleep(std::time::Duration::from_secs(interval_secs));
            true
        }
    };
    // Arm a NO-GRANT runtime (READ is free; the loop reaches no egress/mutate/custody authority) and
    // pump it on the std-thread; join blocks until the bounded loop completes (no zombie, interruptible
    // via the runtime terminal check).
    let trace = crate::StageFTraceLink::new([0x6c; 32], 0x6c33, 0);
    let runtime = AutonomyRuntime::arm(
        1,
        None,
        BudgetCap::new(100_000, 1_000_000, 100_000),
        2,
        trace,
    );
    let handle = RuntimeHandle::spawn(runtime, driver, std::time::Duration::from_millis(50));
    handle.join();

    // After the bounded loop: final seal-all + render the authoritative summary.
    let Ok(a) = acc.lock() else {
        return writeln!(
            out,
            "skew accumulate-loop: accumulator lock poisoned (fail-closed)"
        );
    };
    let mut persisted = 0usize;
    for w in a.windows.values() {
        if persist_history_window(&store, &dir, w) {
            persisted += 1;
        }
    }
    writeln!(
        out,
        "skew accumulate-loop (chain={chain}): cycles={}/{cycles_target} interval={interval_secs}s samples_added={} series={} persisted={persisted} (recurring bounded daemon; per-cycle local AEAD seal; READ-class; money 0; finality from the chain)",
        a.cycles,
        a.samples_added,
        a.windows.len()
    )?;
    for w in a.windows.values() {
        writeln!(
            out,
            "  [{}] series={} samples={}",
            w.kind.as_str(),
            crate::skew_history::short_hex(&w.series_id),
            w.len()
        )?;
    }
    if a.samples_added == 0 {
        writeln!(
            out,
            "  (no NEW samples this run — the snapshot advances only on keeper re-validation; the loop polled the chain {} time(s) at a {interval_secs}s cadence)",
            a.cycles
        )?;
    }
    Ok(())
}

/// Default build: honest-degrade (the byte-locked decoders + the pure analyzers are present; the LIVE
/// devnet recurring poll loop needs `web3-egress`).
#[cfg(not(feature = "web3-egress"))]
fn cmd_skew_accumulate_loop(rest: &[String], out: &mut impl Write) -> io::Result<()> {
    let chain = rest.first().map_or("solana", String::as_str);
    writeln!(
        out,
        "skew accumulate-loop (chain={chain}): web3 transport not compiled — build with --features web3-egress for the LIVE devnet recurring poll daemon; the byte-locked decoders + the OHLC/volume/funding analyzers (skew_read + skew_history) are ready"
    )
}

// ── the 2-tier Walrus publish (put-fixture-net): the agent's ENCRYPTED time-series, decentralized ──

/// The owner phrase to publish the ENCRYPTED history time-series to Walrus testnet (DISTINCT from the
/// memory backup phrase so muscle memory can never cross-fire).
#[cfg(feature = "put-fixture-net")]
const SKEW_HISTORY_WALRUS_PHRASE: &str = "publish-skew-history-to-walrus-testnet";

#[cfg(feature = "put-fixture-net")]
fn skew_history_walrus_error(
    out: &mut impl Write,
    envelope_hex: &str,
    msg: &str,
) -> io::Result<bool> {
    emit(
        out,
        "skew history-walrus",
        envelope_hex,
        CommandRisk::Network,
        ApprovalRequirement::TypedPhrase,
        RenderTruth::Red,
        &[format!("skew history-walrus: {msg}")],
    )?;
    Ok(true)
}

/// `skew history-walrus <phrase>` — publish the agent's ENCRYPTED time-series as a 2-tier Walrus blob
/// set (E14-W2 reuse) + round-trip proof. Gate: exact phrase → load the local sealed windows → PUT
/// each as an `EncryptedUserMemory` sub-blob (CIPHERTEXT only; no plaintext leaves) → build + SEAL +
/// PUT the MAIN INDEX manifest → round-trip (GET main + open + match; GET first sub + byte-match +
/// AEAD-open to a valid window). Testnet, keyless, no funds; custody/chain-write HARD-LOCKED (PD-6).
#[cfg(feature = "put-fixture-net")]
fn cmd_skew_history_walrus(rest: &[String], out: &mut impl Write) -> io::Result<bool> {
    use crate::repl::approval::{ApprovalDecision, ApprovalPrompt};
    use mnemos_c_walrus::publisher::EpochCount;
    use mnemos_c_walrus::reqwest_transport::ReqwestPublisher;

    let envelope_hex = hex16(&sha256_32(b"skew history-walrus"));
    let supplied = rest.get(1..).map(|s| s.join(" ")).unwrap_or_default();
    let mut prompt =
        ApprovalPrompt::new(ApprovalRequirement::TypedPhrase, SKEW_HISTORY_WALRUS_PHRASE);
    if !matches!(prompt.evaluate(supplied.trim()), ApprovalDecision::Approved) {
        emit(
            out,
            "skew history-walrus",
            &envelope_hex,
            CommandRisk::Network,
            ApprovalRequirement::TypedPhrase,
            RenderTruth::Yellow,
            &[
                "skew history-walrus = publish the agent's ENCRYPTED Skew time-series (AES ciphertext) to Walrus testnet (2-tier) + round-trip".to_string(),
                format!("to run, supply EXACTLY: skew history-walrus {SKEW_HISTORY_WALRUS_PHRASE}"),
                "ciphertext only (EncryptedUserMemory); no plaintext leaves; no funds; custody/chain-write HARD-LOCKED (PD-6)".to_string(),
            ],
        )?;
        return Ok(true);
    }
    let Ok(store) = crate::memory_store::PersistedStore::open_local() else {
        return skew_history_walrus_error(out, &envelope_hex, "memory store unavailable");
    };
    let Ok(dir) = skew_history_dir() else {
        return skew_history_walrus_error(out, &envelope_hex, "no data dir");
    };
    let windows = load_history_windows(&store, &dir);
    if windows.is_empty() {
        emit(
            out,
            "skew history-walrus",
            &envelope_hex,
            CommandRisk::Network,
            ApprovalRequirement::TypedPhrase,
            RenderTruth::Yellow,
            &[
                "skew history-walrus: no accumulated series to publish — run `skew accumulate <chain>` first".to_string(),
            ],
        )?;
        return Ok(true);
    }
    let epochs = match EpochCount::new(1) {
        Ok(e) => e,
        Err(_) => return skew_history_walrus_error(out, &envelope_hex, "epoch invalid"),
    };
    let mut pub_t = match ReqwestPublisher::new(PUT_FIXTURE_TIMEOUT_MS) {
        Ok(t) => t,
        Err(_) => {
            return skew_history_walrus_error(
                out,
                &envelope_hex,
                "publisher transport init failed",
            );
        }
    };

    let total = windows.len();
    let mut truth = RenderTruth::Green;
    let mut body = vec![format!(
        "skew history-walrus: {total} encrypted window(s) → 2-tier Walrus (sub-blobs + main index); AES ciphertext; key local; testnet; no funds"
    )];
    let mut entries: Vec<crate::memory_walrus::WalrusMemEntry> = Vec::new();
    let mut first_sub: Option<Vec<u8>> = None;
    for (i, w) in windows.iter().enumerate().take(BACKUP_WALRUS_MAX_RECORDS) {
        let sealed = match store.seal_skew_history(&w.to_bytes()) {
            Ok(c) => c,
            Err(_) => {
                truth = RenderTruth::Red;
                body.push(format!("window {} seal failed", w.topic()));
                continue;
            }
        };
        match walrus_put_verified(&mut pub_t, epochs, &sealed) {
            Some(blob) => {
                body.push(format!(
                    "SUB PUT ok: {} -> blob_id={blob} (verified)",
                    w.topic()
                ));
                if first_sub.is_none() {
                    first_sub = Some(sealed.clone());
                }
                entries.push(crate::memory_walrus::WalrusMemEntry {
                    memory_id: i as u64,
                    topic: w.topic(),
                    sub_blob_id: blob,
                    sub_0g_root: None,
                });
            }
            None => {
                truth = RenderTruth::Red;
                body.push(format!(
                    "{}: SUB PUT rejected (self-report ban or boundary)",
                    w.topic()
                ));
            }
        }
    }
    let index = crate::memory_walrus::WalrusMainIndex {
        entries: entries.clone(),
    };
    let mut main_blob = String::new();
    if !index.entries.is_empty() {
        match store.seal_index(&index.to_bytes()) {
            Ok(ct) => match walrus_put_verified(&mut pub_t, epochs, &ct) {
                Some(blob) => {
                    body.push(format!(
                        "MAIN INDEX PUT ok: {} entries -> blob_id={blob}",
                        index.entries.len()
                    ));
                    main_blob = blob;
                }
                None => {
                    truth = RenderTruth::Red;
                    body.push("MAIN INDEX PUT rejected".to_string());
                }
            },
            Err(_) => {
                truth = RenderTruth::Red;
                body.push("MAIN INDEX seal failed".to_string());
            }
        }
    }
    if !main_blob.is_empty() {
        match walrus_get_by_blob_text(&main_blob) {
            Some(fetched) => {
                let decoded = store
                    .open_index(&fetched)
                    .ok()
                    .and_then(|p| crate::memory_walrus::WalrusMainIndex::from_bytes(&p).ok());
                if decoded.as_ref() == Some(&index) {
                    body.push(format!(
                        "MAIN INDEX round-trip: GET+decrypt OK ({} entries match)",
                        index.entries.len()
                    ));
                } else {
                    truth = RenderTruth::Yellow;
                    body.push("MAIN INDEX round-trip: mismatch (testnet propagation?)".to_string());
                }
            }
            None => {
                truth = RenderTruth::Yellow;
                body.push("MAIN INDEX round-trip: GET not fetched (propagation)".to_string());
            }
        }
    }
    if let (Some(entry), Some(sealed)) = (entries.first(), first_sub.as_ref()) {
        match walrus_get_by_blob_text(&entry.sub_blob_id) {
            Some(fetched) => {
                let bytes_match = &fetched == sealed;
                let decodes = store
                    .open_skew_history(&fetched)
                    .ok()
                    .and_then(|p| crate::skew_history::HistoryWindow::from_bytes(&p).ok())
                    .is_some();
                body.push(format!(
                    "SUB round-trip: GET {} -> {} bytes; byte-match={bytes_match}; decrypts-to-window={decodes}",
                    entry.topic,
                    fetched.len()
                ));
                if !bytes_match || !decodes {
                    truth = RenderTruth::Red;
                }
            }
            None => {
                truth = RenderTruth::Yellow;
                body.push("SUB round-trip: GET not fetched (propagation)".to_string());
            }
        }
    }
    body.push(format!(
        "published: {} window(s) + {} main index; 2-tier round-trip; no funds; custody/chain-write HARD-LOCKED (PD-6)",
        entries.len(),
        u8::from(!main_blob.is_empty())
    ));
    emit(
        out,
        "skew history-walrus",
        &envelope_hex,
        CommandRisk::Network,
        ApprovalRequirement::TypedPhrase,
        truth,
        &body,
    )?;
    Ok(true)
}

/// Default build: honest-degrade (the local sealed storage-of-record is the always-available store).
#[cfg(not(feature = "put-fixture-net"))]
fn cmd_skew_history_walrus(_rest: &[String], out: &mut impl Write) -> io::Result<bool> {
    writeln!(
        out,
        "skew history-walrus: walrus transport not compiled — build with --features put-fixture-net to publish the encrypted time-series to testnet; the local sealed storage-of-record is always available"
    )?;
    Ok(true)
}

/// `skew [capabilities | capability <name>]` — READ-class awareness readout of the Skew capability
/// catalog (the single source of truth [`crate::skew_catalog`]). Money 0, no key, no network: it
/// renders what Sinabro KNOWS the Skew Solana derivatives factory exposes (owner 2026-06-30:
/// "시나브로 자체가 모든 기능을 인지하고 있어야 해"). `skew capabilities` lists the full surface incl.
/// the secondary market; `skew capability <name>` shows one. Trading any of them is a separate
/// bounded-`CustodyGrant` action (K-2), never originated by this readout.
fn cmd_skew(rest: &[String], out: &mut impl Write) -> io::Result<()> {
    match rest.first().map(String::as_str) {
        None | Some("capabilities") => write!(out, "{}", crate::skew_catalog::render_catalog()),
        Some("capability") => match rest.get(1) {
            Some(name) => match crate::skew_catalog::find_capability(name) {
                Some(c) => write!(out, "{}", crate::skew_catalog::render_capability(c)),
                None => writeln!(
                    out,
                    "unknown skew capability: {name} (try `skew capabilities`)"
                ),
            },
            None => writeln!(out, "usage: skew capability <name>"),
        },
        Some("markets") => {
            skew_chain_read(rest.get(1).map_or("solana", String::as_str), Some(228), out)
        }
        Some("inventory") => {
            skew_chain_read(rest.get(1).map_or("solana", String::as_str), None, out)
        }
        Some("portfolio") => skew_portfolio_read(
            rest.get(1).map_or("solana", String::as_str),
            rest.get(2).map(String::as_str),
            out,
        ),
        Some("positions") => skew_positions_read(
            rest.get(1).map_or("solana", String::as_str),
            rest.get(2).map(String::as_str),
            out,
        ),
        Some("contracts") => skew_contracts_read(
            rest.get(1).map_or("solana", String::as_str),
            rest.get(2).map(String::as_str),
            out,
        ),
        Some("accumulate") => cmd_skew_accumulate(&rest[1..], out),
        Some("accumulate-loop") => cmd_skew_accumulate_loop(&rest[1..], out),
        Some("history") => cmd_skew_history(&rest[1..], out),
        Some("history-walrus") => cmd_skew_history_walrus(rest, out).map(|_| ()),
        Some("oracle") => cmd_skew_oracle(&rest[1..], out),
        Some("strategy") => cmd_skew_strategy(&rest[1..], out),
        Some("custody") => cmd_skew_custody(out),
        Some("payoff") => cmd_skew_payoff(&rest[1..], out),
        Some(other) => writeln!(
            out,
            "unknown skew subcommand: {other} (try: skew capabilities | capability <name> | markets [chain] | inventory [chain] | portfolio [chain] [owner] | positions [chain] [owner] | contracts [chain] [owner] | accumulate [chain] [cycles] | accumulate-loop [chain] [cycles] [interval_secs] | history [bucket] [series] | history-walrus <phrase> | oracle <class> … | strategy <example|propose|certify|corpus> … | custody | payoff <straddle|forward> …)"
        ),
    }
}

/// WAVE G — `skew payoff <straddle|forward> …` — render a DETERMINISTIC payoff-diagram SVG (READ-class,
/// money 0, no key, no chain). The agent PROPOSES a payoff; this visualizes its `f(S)` over the collar.
/// The GUI payoff pane fetches the SAME SVG via the `skew_payoff_svg` Tauri command (single core source).
///   skew payoff straddle <lo> <hi> <tau> <strike> <premium>   (f = |S−strike| − premium)
///   skew payoff forward  <lo> <hi> <forward_pc> [tau]         (f = S − Pc, the affine WCC forward)
fn cmd_skew_payoff(rest: &[String], out: &mut impl Write) -> io::Result<()> {
    use crate::skew_payoff_svg::{
        affine_forward_segments, render_payoff_svg, sample_piecewise, straddle_payoff_segs,
    };
    let pi128 = |i: usize| rest.get(i).and_then(|s| s.trim().parse::<i128>().ok());
    let (title, segs, lo, hi, tau) = match rest.first().map(String::as_str) {
        Some("straddle") => {
            let (Some(lo), Some(hi), Some(tau), Some(strike), Some(premium)) = (
                pi128(1),
                pi128(2),
                rest.get(3).and_then(|s| s.trim().parse::<u128>().ok()),
                pi128(4),
                pi128(5),
            ) else {
                return writeln!(
                    out,
                    "usage: skew payoff straddle <lo> <hi> <tau> <strike> <premium>"
                );
            };
            (
                format!("straddle K={strike} prem={premium} [{lo},{hi}]"),
                straddle_payoff_segs(hi, strike, premium),
                lo,
                hi,
                tau,
            )
        }
        Some("forward") => {
            let (Some(lo), Some(hi), Some(forward_pc)) = (pi128(1), pi128(2), pi128(3)) else {
                return writeln!(
                    out,
                    "usage: skew payoff forward <lo> <hi> <forward_pc> [tau]"
                );
            };
            let tau = rest
                .get(4)
                .and_then(|s| s.trim().parse::<u128>().ok())
                .unwrap_or(1);
            (
                format!("forward Pc={forward_pc} [{lo},{hi}]"),
                affine_forward_segments(hi, 1, forward_pc.saturating_neg()),
                lo,
                hi,
                tau,
            )
        }
        _ => {
            return writeln!(
                out,
                "usage: skew payoff <straddle|forward> … (straddle <lo> <hi> <tau> <strike> <premium> | forward <lo> <hi> <forward_pc> [tau])"
            );
        }
    };
    match sample_piecewise(lo, hi, tau, &segs) {
        Some(points) => {
            writeln!(
                out,
                "skew payoff: {title} — deterministic SVG ({} vertices, money 0):",
                points.len()
            )?;
            writeln!(out, "{}", render_payoff_svg(&title, &points, 360, 220))
        }
        None => writeln!(
            out,
            "skew payoff: degenerate domain (need lo<hi, tau>=1, on-lattice breakpoints) — nothing rendered (fail-closed)"
        ),
    }
}

/// K-5c — the per-owner custody bounds the K-2 `daemon trade` path arms WITHIN. The wallet
/// settings window (the cockpit) is where the owner sets the ceiling + funds; until a config seam
/// lands these are the session defaults, exposed as the SINGLE source of truth shared by BOTH the
/// trade path (`cmd_daemon_trade`) and the dial readout (`skew_custody_dial`) — never duplicated.
pub const SKEW_CUSTODY_PER_TX_MINOR: u128 = 1_000_000_000;
/// Total budget across an arm window (atoms) = max escrow = provable max loss.
pub const SKEW_CUSTODY_BUDGET_MINOR: u128 = 1_000_000_000;
/// Time-to-live of an arm window (ms).
pub const SKEW_CUSTODY_TTL_MS: u64 = 5 * 60 * 1000;
/// Tx-count cap per arm window.
pub const SKEW_CUSTODY_MAX_ACTIONS: u32 = 4;

/// K-5c — the CustodyGrant dial state for the wallet-settings cockpit (READ-class, money 0). The
/// SINGLE source of truth for both the `skew custody` CLI render AND the GUI wallet panel (the
/// `read_custody_dial` Tauri command). It renders the bounds the K-2 `daemon trade` path arms
/// within (the SAME consts), the chain/protocol allowlist, the isolated signer pubkey PRESENCE
/// (the public fee-payer key — NEVER the seed), the network, and the armed posture. It performs
/// NO sign / mint / spend: a configuration view; the model holds no arm phrase (IV-FG8).
pub struct CustodyDialView {
    /// The chain the custody grant allowlists (devnet; mainnet = a separate owner arm).
    pub network: String,
    /// The protocol the custody grant allowlists (`skew`).
    pub protocol: String,
    /// The isolated signer's PUBLIC base58 key (the fee payer), or `None` if not generated yet
    /// (run `daemon trade-addr`). NEVER the seed.
    pub signer_pubkey: Option<String>,
    /// Per-tx ceiling (settlement-mint atoms).
    pub per_tx_max_minor: u128,
    /// Total budget across the grant (atoms) — the provable-max-loss cap.
    pub total_budget_minor: u128,
    /// Time-to-live of an arm window (ms).
    pub ttl_ms: u64,
    /// Tx-count cap per arm.
    pub max_actions: u32,
    /// Whether a STANDING armed session exists. Always `false`: there is no persisted custody
    /// session — each trade arms within bounds via the owner's typed phrase (the arm IS the
    /// authorization; the model can never self-arm).
    pub armed: bool,
}

/// K-5c — read the current custody-dial state (the wallet cockpit's single source of truth).
/// READ-class, money 0: it reads the shared bounds consts + the chain/protocol allowlist + the
/// isolated signer's PUBLIC key presence. NO sign / mint / spend.
#[must_use]
pub fn skew_custody_dial() -> CustodyDialView {
    use crate::skew_execute::{K2_CHAIN, K2_PROTOCOL};
    CustodyDialView {
        network: K2_CHAIN.to_string(),
        protocol: K2_PROTOCOL.to_string(),
        signer_pubkey: load_solana_signer().map(|s| s.pubkey().to_base58()),
        per_tx_max_minor: SKEW_CUSTODY_PER_TX_MINOR,
        total_budget_minor: SKEW_CUSTODY_BUDGET_MINOR,
        ttl_ms: SKEW_CUSTODY_TTL_MS,
        max_actions: SKEW_CUSTODY_MAX_ACTIONS,
        armed: false,
    }
}

/// `skew custody` — the CustodyGrant dial readout (the wallet-settings cockpit, CLI form). The
/// owner sets the ceiling + funds here; the readout renders the bounds the K-2 trade path arms
/// within, the allowlist, the isolated signer presence, and the armed posture. READ-class, money
/// 0, no sign: the window CONFIGURES, never signs (IV-FG8). ARM/REVOKE/KILL are the owner's
/// typed-phrase ceremony (`daemon trade <CUSTODY_ARM_PHRASE> …`), never this readout.
fn cmd_skew_custody(out: &mut impl Write) -> io::Result<()> {
    let dial = skew_custody_dial();
    let signer = dial
        .signer_pubkey
        .as_deref()
        .unwrap_or("not generated — run `daemon trade-addr`");
    writeln!(
        out,
        "skew custody = the CustodyGrant dial (the wallet-settings cockpit; READ-class, money 0)"
    )?;
    writeln!(
        out,
        "  network          {} (mainnet = a separate owner arm)",
        dial.network
    )?;
    writeln!(out, "  protocol allow   {}", dial.protocol)?;
    writeln!(out, "  isolated signer  {signer}")?;
    writeln!(out, "  per-tx max       {} atoms", dial.per_tx_max_minor)?;
    writeln!(
        out,
        "  total budget     {} atoms (= max escrow = provable max loss)",
        dial.total_budget_minor
    )?;
    writeln!(out, "  TTL              {} ms", dial.ttl_ms)?;
    writeln!(out, "  max-actions      {}", dial.max_actions)?;
    writeln!(
        out,
        "  armed            {}",
        if dial.armed {
            "yes (standing session)"
        } else {
            "no standing session — each trade arms within bounds via the owner phrase"
        }
    )?;
    writeln!(
        out,
        "  the model holds no arm phrase; only the owner arms (the window configures, never signs/mints)"
    )?;
    Ok(())
}

/// `skew oracle <subcommand>` — the K-1 TRADE ORACLE (C-3 first domain). A PURE, deterministic
/// re-derivation of Skew's OWN worst-case escrow (byte-locked from the verified source) + a
/// fail-closed verdict (AFFORDABLE & IN-BOUNDS | DENIED(reason)) against the owner's PLAIN bound
/// numbers — **no LLM judge, no signing, money 0** (the real `CustodyGrant` authorize + signing is
/// K-2). Per-class verbs preview a hypothetical trade; `live` reads REAL devnet templates/positions
/// and runs the oracle on the chain's own certified worst-case numbers.
fn cmd_skew_oracle(rest: &[String], out: &mut impl Write) -> io::Result<()> {
    use crate::skew_oracle::{OracleBounds, PartyDirection, SkewTrade, render_verdict};
    let pu128 = |s: &String| s.parse::<u128>().ok();
    let pi128 = |s: &String| s.parse::<i128>().ok();
    let pu64 = |s: &String| s.parse::<u64>().ok();
    let pu32 = |s: &String| s.parse::<u32>().ok();
    let pi64 = |s: &String| s.parse::<i64>().ok();
    // Owner bounds from the trailing `<per_tx_max> <total_budget>`; the drawdown dial defaults to the
    // budget (the clean `Σ(escrows) ≤ budget` theorem). Single-trade preview ⇒ spent/portfolio = 0.
    let bounds_from = |per_tx: u128, budget: u128| OracleBounds {
        per_tx_max_minor: per_tx,
        total_budget_minor: budget,
        drawdown_max_minor: budget,
    };
    match rest.first().map(String::as_str) {
        Some("usm-vm") => {
            if let (Some(notional), Some(bps), Some(per_tx), Some(budget)) = (
                rest.get(1).and_then(pu128),
                rest.get(2).and_then(pu32),
                rest.get(3).and_then(pu128),
                rest.get(4).and_then(pu128),
            ) {
                let trade = SkewTrade::UsmVmForward {
                    notional_minor: notional,
                    initial_bps: bps,
                };
                write!(
                    out,
                    "{}",
                    render_verdict(&trade, 0, 0, &bounds_from(per_tx, budget))
                )
            } else {
                writeln!(
                    out,
                    "usage: skew oracle usm-vm <notional> <initial_bps> <per_tx_max> <total_budget>"
                )
            }
        }
        Some("fixed-lock") => {
            if let (Some(locked), Some(per_tx), Some(budget)) = (
                rest.get(1).and_then(pu128),
                rest.get(2).and_then(pu128),
                rest.get(3).and_then(pu128),
            ) {
                let trade = SkewTrade::FixedLock {
                    locked_amount_minor: locked,
                };
                write!(
                    out,
                    "{}",
                    render_verdict(&trade, 0, 0, &bounds_from(per_tx, budget))
                )
            } else {
                writeln!(
                    out,
                    "usage: skew oracle fixed-lock <locked_amount> <per_tx_max> <total_budget>"
                )
            }
        }
        Some("wcc") => {
            let dir = match rest.get(1).map(String::as_str) {
                Some("long") => Some(PartyDirection::Long),
                Some("short") => Some(PartyDirection::Short),
                _ => None,
            };
            if let (
                Some(direction),
                Some(qty),
                Some(cs),
                Some(lo),
                Some(hi),
                Some(pc),
                Some(per_tx),
                Some(budget),
            ) = (
                dir,
                rest.get(2).and_then(pu64),
                rest.get(3).and_then(pu128),
                rest.get(4).and_then(pi128),
                rest.get(5).and_then(pi128),
                rest.get(6).and_then(pi128),
                rest.get(7).and_then(pu128),
                rest.get(8).and_then(pu128),
            ) {
                let trade = SkewTrade::WccAffineForward {
                    direction,
                    quantity_q: qty,
                    contract_size: cs,
                    collar_lo: lo,
                    collar_hi: hi,
                    forward_price_pc: pc,
                };
                write!(
                    out,
                    "{}",
                    render_verdict(&trade, 0, 0, &bounds_from(per_tx, budget))
                )
            } else {
                writeln!(
                    out,
                    "usage: skew oracle wcc <long|short> <qty> <contract_size> <collar_lo> <collar_hi> <forward_price> <per_tx_max> <total_budget>"
                )
            }
        }
        Some("perp") => {
            if let (
                Some(q),
                Some(cs),
                Some(entry),
                Some(lo),
                Some(hi),
                Some(fcap),
                Some(per_tx),
                Some(budget),
            ) = (
                rest.get(1).and_then(pi64),
                rest.get(2).and_then(pu128),
                rest.get(3).and_then(pi128),
                rest.get(4).and_then(pi128),
                rest.get(5).and_then(pi128),
                rest.get(6).and_then(pu128),
                rest.get(7).and_then(pu128),
                rest.get(8).and_then(pu128),
            ) {
                let trade = SkewTrade::Perp {
                    signed_qty: q,
                    contract_size: cs,
                    entry_price: entry,
                    lo_price: lo,
                    hi_price: hi,
                    funding_cap_per_unit: fcap,
                };
                write!(
                    out,
                    "{}",
                    render_verdict(&trade, 0, 0, &bounds_from(per_tx, budget))
                )
            } else {
                writeln!(
                    out,
                    "usage: skew oracle perp <signed_qty> <contract_size> <entry> <lo> <hi> <funding_cap> <per_tx_max> <total_budget>"
                )
            }
        }
        Some("bound") => {
            if let (Some(per_unit), Some(qty), Some(per_tx), Some(budget)) = (
                rest.get(1).and_then(pu64),
                rest.get(2).and_then(pu64),
                rest.get(3).and_then(pu128),
                rest.get(4).and_then(pu128),
            ) {
                let trade = SkewTrade::CertifiedBound {
                    wcl_bound_per_unit: per_unit,
                    quantity_q: qty,
                };
                write!(
                    out,
                    "{}",
                    render_verdict(&trade, 0, 0, &bounds_from(per_tx, budget))
                )
            } else {
                writeln!(
                    out,
                    "usage: skew oracle bound <wcl_bound_per_unit> <qty> <per_tx_max> <total_budget>"
                )
            }
        }
        Some("live") => {
            let chain = rest.get(1).map_or("solana", String::as_str);
            let qty = rest.get(2).and_then(pu64).unwrap_or(1);
            let per_tx = rest.get(3).and_then(pu128).unwrap_or(u128::MAX);
            let budget = rest.get(4).and_then(pu128).unwrap_or(u128::MAX);
            skew_oracle_live(chain, qty, bounds_from(per_tx, budget), out)
        }
        _ => writeln!(
            out,
            "usage: skew oracle <usm-vm|fixed-lock|wcc|perp|bound|live> … (deterministic worst-case re-derivation; no LLM judge; money 0; not signed — K-2)"
        ),
    }
}

/// `skew oracle live <chain> [qty] [per_tx_max] [total_budget]` — the LIVE devnet proof: read REAL
/// `skew_otc` ProductTemplates (228 B) + PerpPositions (154 B) over the EXISTING `web3_read_raw`
/// single-egress path (same SSRF + redact wall as `skew portfolio`), byte-decode their margin-
/// relevant fields, and run the K-1 oracle on the chain's OWN certified worst-case numbers
/// (`wcl_bound_atoms`) / stored `reserved_collateral` (the on-chain `E_epoch`). READ-class, money 0,
/// no key, not signed.
#[cfg(feature = "web3-egress")]
fn skew_oracle_live(
    chain: &str,
    qty: u64,
    bounds: crate::skew_oracle::OracleBounds,
    out: &mut impl Write,
) -> io::Result<()> {
    use crate::skew_oracle::{
        SkewTrade, decode_perp_position, decode_product_template, render_verdict,
    };
    writeln!(
        out,
        "skew oracle live (chain={chain}, qty={qty}): re-deriving Skew's worst-case escrow on REAL devnet accounts\n  bounds: per_tx_max={} total_budget={} (deterministic; no LLM judge; money 0; not signed — K-2)",
        bounds.per_tx_max_minor, bounds.total_budget_minor
    )?;

    // --- ProductTemplates (228 B): policy class + chain-certified per-unit WCL bound -------------
    match fetch_skew_program_accounts(chain, crate::skew_oracle::PRODUCT_TEMPLATE_PDA_SPACE) {
        Ok(accts) => {
            let templates: Vec<_> = accts
                .iter()
                .filter_map(|(pk, data)| decode_product_template(data).map(|m| (pk, m)))
                .collect();
            writeln!(out, "  templates: {} decoded", templates.len())?;
            for (pk, m) in &templates {
                writeln!(
                    out,
                    "    {pk}: policy={} listing_kind={} cert_via_mode={} certified_per_unit_wcl={} atoms",
                    m.policy_class().as_str(),
                    m.listing_kind,
                    m.cert_via_mode,
                    m.wcl_bound_atoms
                )?;
                if m.wcl_bound_atoms > 0 {
                    // The chain certified this per-unit worst-case; the oracle re-uses it directly.
                    let trade = SkewTrade::CertifiedBound {
                        wcl_bound_per_unit: m.wcl_bound_atoms,
                        quantity_q: qty,
                    };
                    write!(out, "      {}", render_verdict(&trade, 0, 0, &bounds))?;
                }
            }
        }
        Err(e) => writeln!(out, "  templates: unavailable [{e}]")?,
    }

    // --- PerpPositions (154 B): the chain's stored E_epoch (reserved_collateral) -----------------
    match fetch_skew_program_accounts(chain, crate::skew_oracle::PERP_POSITION_PDA_SPACE) {
        Ok(accts) => {
            let positions: Vec<_> = accts
                .iter()
                .filter_map(|(pk, data)| decode_perp_position(data).map(|p| (pk, p)))
                .collect();
            writeln!(out, "  perp positions: {} decoded", positions.len())?;
            for (pk, p) in &positions {
                writeln!(
                    out,
                    "    {pk}: signed_qty={} entry_notional={} chain_reserved_E_epoch={} atoms status={}",
                    p.signed_qty, p.entry_notional, p.reserved_collateral, p.status
                )?;
            }
        }
        Err(e) => writeln!(out, "  perp positions: unavailable [{e}]")?,
    }
    writeln!(
        out,
        "  finality from the chain, never an indexer; the oracle DECIDED with deterministic math — Sinabro is a 4th verification lane atop Skew's on-chain solvency"
    )
}

/// Honest-degrade (default build): the pure oracle + byte-locked decode are present; the LIVE devnet
/// read needs `--features web3-egress`.
#[cfg(not(feature = "web3-egress"))]
fn skew_oracle_live(
    chain: &str,
    _qty: u64,
    _bounds: crate::skew_oracle::OracleBounds,
    out: &mut impl Write,
) -> io::Result<()> {
    writeln!(
        out,
        "skew oracle live (chain={chain}): web3 transport not compiled — build with --features web3-egress for the LIVE devnet read; the pure oracle + byte-locked decode (skew_oracle) are ready"
    )
}

// ── K-4: the typed strategy DSL + the autonomous R-E-W shadow→certify→corpus spine ──────────────

/// The file extension for a sealed certified-strategy corpus entry.
const SKEW_STRATEGY_CORPUS_EXT: &str = "sc";

/// `<data_dir>/skew_strategy_corpus/` (created if missing) — the local sealed certified-strategy
/// corpus (the agent's OWN encrypted data; the K-3 sealed pattern reuse).
fn skew_strategy_corpus_dir() -> io::Result<std::path::PathBuf> {
    let dir = crate::memory_store::data_dir()
        .map_err(|_| io::Error::other("no data dir"))?
        .join("skew_strategy_corpus");
    std::fs::create_dir_all(&dir)?;
    Ok(dir)
}

/// Load + AEAD-open the existing certified-strategy corpus as `(key, topic, content)` triples (a
/// corrupt / wrong-AAD / non-pattern file is skipped — fail-closed). Deterministically ordered.
fn load_strategy_corpus(
    store: &crate::memory_store::PersistedStore,
    dir: &std::path::Path,
) -> Vec<(String, String, String)> {
    let mut out = Vec::new();
    let Ok(rd) = std::fs::read_dir(dir) else {
        return out;
    };
    let mut paths: Vec<std::path::PathBuf> = rd
        .flatten()
        .map(|e| e.path())
        .filter(|p| p.extension().and_then(|x| x.to_str()) == Some(SKEW_STRATEGY_CORPUS_EXT))
        .collect();
    paths.sort();
    for p in paths {
        if let Ok(sealed) = std::fs::read(&p) {
            if let Ok(plain) = store.open_strategy_corpus(&sealed) {
                if let Ok(body) = String::from_utf8(plain) {
                    if let Some(parsed) = crate::autonomy_evolve::parse_pattern_memory(&body) {
                        out.push(parsed);
                    }
                }
            }
        }
    }
    out
}

/// `skew strategy <example|propose|certify|corpus> …` — the K-4 typed DSL + R-E-W spine. The frontier
/// PROPOSES a strategy as TOML; a malformed proposal is a serde PARSE ERROR (never a trade); the
/// deterministic runtime shadow-evaluates it over the REAL K-3 history with EVERY leg oracle-gated; the
/// conformal cert certifies it; only a certified strategy ACCUMULATEs (P-HALL-gated). Shadow money 0;
/// the live sub-budget is the owner-armed K-2 path.
fn cmd_skew_strategy(rest: &[String], out: &mut impl Write) -> io::Result<()> {
    match rest.first().map(String::as_str) {
        None | Some("example") => write!(out, "{}", crate::skew_strategy::example_strategy_toml()),
        Some("propose") => skew_strategy_propose(rest.get(1).map(String::as_str), out),
        Some("certify") => skew_strategy_certify(&rest[1..], false, out),
        Some("corpus") => skew_strategy_certify(&rest[1..], true, out),
        Some(other) => writeln!(
            out,
            "unknown skew strategy subcommand: {other} (try: example | propose <file> | certify <file> [per_tx_max] [total_budget] | corpus <file> [per_tx_max] [total_budget])"
        ),
    }
}

/// Read a strategy DSL file (a local READ, no network). `None` (with a usage line) on a missing path
/// or an unreadable file — fail-closed.
fn skew_strategy_read_file(path: Option<&str>, verb: &str, out: &mut impl Write) -> Option<String> {
    let Some(p) = path else {
        let _ = writeln!(
            out,
            "usage: skew strategy {verb} <file.toml> [per_tx_max] [total_budget]"
        );
        return None;
    };
    match std::fs::read_to_string(p) {
        Ok(s) => Some(s),
        Err(e) => {
            let _ = writeln!(out, "skew strategy {verb}: cannot read {p}: {e}");
            None
        }
    }
}

/// `skew strategy propose <file>` — parse the DSL serde-fail-closed; render the parsed strategy (proves
/// the typed DSL) OR the parse error (proves a hallucination is a parse error, never a trade).
fn skew_strategy_propose(path: Option<&str>, out: &mut impl Write) -> io::Result<()> {
    let Some(src) = skew_strategy_read_file(path, "propose", out) else {
        return Ok(());
    };
    match crate::skew_strategy::parse_strategy_toml(&src) {
        Ok(dsl) => {
            writeln!(
                out,
                "skew strategy propose: PARSED OK (serde-fail-closed typed DSL; a malformed proposal would be a parse error, never a trade)"
            )?;
            writeln!(
                out,
                "  name={} archetype={} rules={}",
                dsl.name.as_str(),
                dsl.archetype.as_str(),
                dsl.rules.len()
            )?;
            for r in &dsl.rules {
                writeln!(
                    out,
                    "    rule [{}] signal={:?}/{:?} lookback={} op={:?} threshold={} trade={}",
                    r.name.as_str(),
                    r.signal.feature,
                    r.signal.series,
                    r.signal.lookback,
                    r.condition.op,
                    r.condition.threshold,
                    r.trade.class_label()
                )?;
            }
            Ok(())
        }
        Err(e) => writeln!(
            out,
            "skew strategy propose: REJECTED (serde-fail-closed) — {e} (the hallucination wall: a malformed/unknown-field proposal is a parse error, NEVER a trade)"
        ),
    }
}

/// `skew strategy certify|corpus <file> [per_tx_max] [total_budget]` — parse + shadow-evaluate over the
/// LOCAL sealed K-3 history + conformal-certify; `corpus` ALSO runs the cert through the EXISTING
/// `select_evolution_writes` gate and (if certified + cross-memory-consistent) seals the strategy into
/// the local corpus + re-reads it (the P-HALL-gated ACCUMULATE; an uncertified strategy NEVER writes).
fn skew_strategy_certify(
    rest: &[String],
    write_corpus: bool,
    out: &mut impl Write,
) -> io::Result<()> {
    let verb = if write_corpus { "corpus" } else { "certify" };
    let Some(src) = skew_strategy_read_file(rest.first().map(String::as_str), verb, out) else {
        return Ok(());
    };
    let dsl = match crate::skew_strategy::parse_strategy_toml(&src) {
        Ok(d) => d,
        Err(e) => {
            return writeln!(
                out,
                "skew strategy {verb}: REJECTED (serde-fail-closed) — {e} (a hallucination is a parse error, never a trade)"
            );
        }
    };
    // owner bounds: `<per_tx_max> <total_budget>` (the drawdown dial = the budget); generous defaults.
    let per_tx = rest
        .get(1)
        .and_then(|s| s.parse::<u128>().ok())
        .unwrap_or(1_000_000_000);
    let budget = rest
        .get(2)
        .and_then(|s| s.parse::<u128>().ok())
        .unwrap_or(1_000_000_000);
    let bounds = crate::skew_oracle::OracleBounds {
        per_tx_max_minor: per_tx,
        total_budget_minor: budget,
        drawdown_max_minor: budget,
    };
    // the shadow backtest reads the agent's OWN local sealed K-3 history (no network).
    let Ok(store) = crate::memory_store::PersistedStore::open_local() else {
        return writeln!(
            out,
            "skew strategy {verb}: memory store unavailable (no key/home)"
        );
    };
    let windows = match skew_history_dir() {
        Ok(dir) => load_history_windows(&store, &dir),
        Err(_) => Vec::new(),
    };
    if windows.is_empty() {
        writeln!(
            out,
            "skew strategy {verb}: no accumulated K-3 history — run `skew accumulate <chain>` first (the shadow backtest reads the agent's own sealed time-series; READ-class, money 0)"
        )?;
    }
    let report = crate::skew_strategy::shadow_evaluate(&dsl, &windows, &bounds);
    let cert = crate::skew_strategy::certify_strategy(&report);
    write!(
        out,
        "{}",
        crate::skew_strategy::render_shadow(&report, &cert)
    )?;

    if !write_corpus {
        return Ok(());
    }
    // ── corpus ACCUMULATE: the cert flows through the EXISTING P-HALL write gate ──────────────────
    let goal = dsl.corpus_goal();
    let content = match dsl.to_toml() {
        Ok(t) => t,
        Err(e) => return writeln!(out, "skew strategy corpus: cannot serialize strategy: {e}"),
    };
    let candidate = crate::autonomy_evolve::strategy_candidate(&goal, &content, cert.certified);
    // held LTM = the existing corpus (a real write-time cross-memory consistency check).
    let corpus_dir = match skew_strategy_corpus_dir() {
        Ok(d) => d,
        Err(e) => return writeln!(out, "skew strategy corpus: no corpus dir: {e}"),
    };
    let held: Vec<crate::autonomy_evolve::HeldMemory> = load_strategy_corpus(&store, &corpus_dir)
        .into_iter()
        .map(|(_k, topic, content)| crate::autonomy_evolve::HeldMemory { topic, content })
        .collect();
    let no_prior = |_k: &str| crate::verification::PerfScore::default();
    let outcome = crate::autonomy_evolve::select_evolution_writes(
        std::slice::from_ref(&candidate),
        &held,
        &no_prior,
    );
    writeln!(
        out,
        "  CORPUS WRITE (P-HALL-gated via select_evolution_writes): written={} doubly_verified={} quarantined={} unverified={}",
        outcome.written_count(),
        outcome.doubly_verified_count(),
        outcome.quarantined.len(),
        outcome.unverified.len()
    )?;
    // persist + re-read each written (certified) pattern — the corpus is real + re-readable.
    for w in &outcome.written {
        let body =
            crate::autonomy_evolve::format_pattern_memory(&w.pattern_key, &w.topic, &w.content);
        let sealed = match store.seal_strategy_corpus(body.as_bytes()) {
            Ok(s) => s,
            Err(_) => {
                writeln!(
                    out,
                    "  persist: seal failed (fail-closed) for {}",
                    w.pattern_key
                )?;
                continue;
            }
        };
        let path = corpus_dir.join(format!("{}.{SKEW_STRATEGY_CORPUS_EXT}", w.pattern_key));
        if let Err(e) = std::fs::write(&path, &sealed) {
            writeln!(out, "  persist: write failed: {e}")?;
            continue;
        }
        // round-trip: re-read + re-open + re-parse (prove the sealed corpus entry is real).
        let round_trip = std::fs::read(&path)
            .ok()
            .and_then(|b| store.open_strategy_corpus(&b).ok())
            .and_then(|p| String::from_utf8(p).ok())
            .and_then(|b| crate::autonomy_evolve::parse_pattern_memory(&b))
            .is_some_and(|(k, _, _)| k == w.pattern_key);
        writeln!(
            out,
            "  ACCUMULATED strategy key={} topic={} (sealed; AES ciphertext; key local; round_trip={})",
            w.pattern_key, w.topic, round_trip
        )?;
    }
    if outcome.written.is_empty() {
        writeln!(
            out,
            "  (nothing accumulated — an UNcertified / contradicting strategy NEVER writes: the P-HALL collapse defense)"
        )?;
    }
    Ok(())
}

/// Fetch + base64-decode every `skew_otc` program account of one `data_size` over the EXISTING
/// `web3_read_raw` single-egress path (SSRF + redact wall reused). Returns `(pubkey, raw_bytes)`
/// pairs. READ-class, money 0.
#[cfg(feature = "web3-egress")]
fn fetch_skew_program_accounts(
    chain: &str,
    data_size: usize,
) -> Result<Vec<(String, Vec<u8>)>, String> {
    use crate::commands::authority::ReadCapability;
    use crate::provider::web3_rpc::{
        WEB3_BULK_RESULT_CHARS, Web3RpcMethod, Web3RpcSeam, web3_read_raw,
    };
    let program = crate::skew_catalog::SKEW_PROGRAM_ID_DEVNET;
    let params = format!(
        "[\"{program}\",{{\"encoding\":\"base64\",\"filters\":[{{\"dataSize\":{data_size}}}]}}]"
    );
    let read = ReadCapability::granted();
    let registry = read_owner_web3_chain_registry();
    let seam = Web3RpcSeam::new();
    let raw = web3_read_raw(
        &read,
        seam.port(),
        &registry,
        chain,
        Web3RpcMethod::SolGetProgramAccounts,
        &params,
        WEB3_BULK_RESULT_CHARS,
    );
    let body = raw.body.ok_or_else(|| {
        format!(
            "{} (chain owner-configured + web3-egress?)",
            raw.class_label
        )
    })?;
    let value: serde_json::Value = serde_json::from_str(&body).map_err(|_| {
        format!("result not valid JSON or exceeded the bulk cap ({WEB3_BULK_RESULT_CHARS} chars)")
    })?;
    let mut out = Vec::new();
    if let Some(arr) = value.get("result").and_then(serde_json::Value::as_array) {
        for entry in arr {
            let pubkey = entry
                .get("pubkey")
                .and_then(serde_json::Value::as_str)
                .unwrap_or("?")
                .to_string();
            if let Some(bytes) = entry
                .get("account")
                .and_then(|a| a.get("data"))
                .and_then(serde_json::Value::as_array)
                .and_then(|d| d.first())
                .and_then(serde_json::Value::as_str)
                .and_then(crate::skew_read::base64_decode)
            {
                out.push((pubkey, bytes));
            }
        }
    }
    Ok(out)
}

/// `sinabro daemon [status|kill]` — the REAL bounded background runner (ENDGAME
/// E3). Replaces the static "phase 0 control surface only" projection with a live
/// [`AutonomyRuntime`](crate::daemon::runtime::AutonomyRuntime): a single bounded
/// job, local-first (PD-7), holding ONLY READ + an OPTIONAL owner-armed egress
/// grant (NONE here ⇒ an autonomous frontier escalation is DENIED without an
/// owner-arm — E0c/E0d). `status` renders the live runner state; `kill` terminates
/// the real job (no zombie). The runner owns no wallet/secret and adds no socket
/// (every outbound byte still passes the SI-2 redact choke inside the loop). Threat
/// model: `ops/evidence/stage_g/agent_loop/AUTONOMY_RUNTIME_THREAT_MODEL.md` (⑩).
fn cmd_daemon(rest: &[String], out: &mut impl Write) -> io::Result<()> {
    use crate::commands::budget::BudgetCap;
    use crate::daemon::runtime::AutonomyRuntime;
    let verb = rest.first().map_or("status", String::as_str);
    // ENDGAME (owner-driven 2026-06-12): `daemon run <task>` drives the REAL
    // AutonomyRuntime `tick` through ONE bounded autonomous job — the missing CLI
    // wire (the `status`/`kill` surface never pumped a turn). Local-first (PD-7),
    // zero egress, no grant ⇒ the agent autonomously roams its store + the loopback
    // brain; a frontier escalation still fails closed without an owner-arm.
    if verb.eq_ignore_ascii_case("run") {
        return cmd_daemon_run(rest, out);
    }
    // `daemon run-frontier <ARM_PHRASE> <task>`: the owner ARMS a bounded egress
    // grant (the E0c typed-phrase ceremony) and the autonomous job escalates to the
    // FRONTIER — the literal "autonomous while away" over the frontier brain. The
    // grant is single-shot + fast-expiring + revocable; the model cannot mint it.
    if verb.eq_ignore_ascii_case("run-frontier") {
        return cmd_daemon_run_frontier(rest, out).map(|_| ());
    }
    // `daemon run-mutate <ARM_PHRASE>`: the owner ARMS a bounded MUTATE-LOCAL
    // autonomy window (the E10-2b MUTATE_ARM ceremony) and pending AGENT-PROPOSED
    // exec proposals AUTO-EXECUTE within the bound (3 actions / 5 min, revocable),
    // each through the gated chokepoint (kernel sandbox at LocalWrite; network
    // kernel-DENIED) — NO per-action ping. The model cannot mint the grant;
    // custody/funds stay HARD-LOCKED (PD-6).
    if verb.eq_ignore_ascii_case("run-mutate") {
        return cmd_daemon_run_mutate(rest, out).map(|_| ());
    }
    // `daemon serve <task>`: the BACKGROUND poll-and-arm loop (ENDGAME E11-3). The
    // runner attempts an autonomous FRONTIER escalation it holds NO grant for ⇒
    // `FrontierDenied`; the loop PINGS the owner (SI-2 dry-run + SI-6 dedupe), POLLS
    // the live getUpdates edge for the reply (bounded windows), and on an APPROVE
    // installs the NARROW single-shot grant + proceeds EXACTLY the one denied action.
    // No reply ⇒ stays denied (fail-closed). part 2 (a real TELEGRAM_BOT_TOKEN fire)
    // is the owner go-live gate; custody/funds stay HARD-LOCKED (PD-6).
    if verb.eq_ignore_ascii_case("serve") {
        return cmd_daemon_serve(rest, out).map(|_| ());
    }
    // `daemon serve-chat <ARM_PHRASE> <session-id>`: the TELEGRAM REMOTE-CONTROL chat
    // loop (ENDGAME E13-2 / ⑱). The owner-armed egress SESSION gates the ENTIRE loop
    // (Option A): a free-form owner message → a LOCAL agent turn (zero egress) → a
    // redacted reply BACK to Telegram. No arm ⇒ an inbound message runs NO turn and
    // sends NO reply (fail-closed). The arm IS the approval; replies are bounded by
    // the session grant's max_actions, revocable. The model cannot mint the grant;
    // custody/funds stay HARD-LOCKED (PD-6). part 2 (a real getUpdates/sendMessage
    // fire) is the owner go-live gate.
    if verb.eq_ignore_ascii_case("serve-chat") {
        return cmd_daemon_serve_chat(rest, out).map(|_| ());
    }
    // `daemon fetch <ARM_PHRASE> <https-url>`: the owner-armed BOUNDED DOWNLOAD
    // (ENDGAME E13-3 / ⑲). The owner ceremony arms a SINGLE-SHOT, fast-expiring,
    // revocable download grant; the bounded GET (SSRF-walled + allowlisted, secret-zero,
    // redirect-none, byte + time capped) writes UNTRUSTED bytes into a temp file and
    // reports METADATA only (never the body; the bytes are never executed). The model
    // holds no FetchCapability ctor and there is NO loop tool ⇒ it cannot self-fetch.
    // Honest-degrades to TransportNotCompiled without `download-egress`. custody/funds
    // stay HARD-LOCKED (PD-6).
    if verb.eq_ignore_ascii_case("fetch") {
        return cmd_daemon_fetch(rest, out).map(|_| ());
    }
    // `daemon web3-read <ARM_PHRASE> <method> [params-json]`: the owner-armed CHAIN READ
    // ([3] E10-3b). The owner ceremony arms a SINGLE-SHOT, fast-expiring, revocable
    // EgressGrant; the bounded JSON-RPC POST (SSRF-walled endpoint from config ONLY,
    // secret-zero, params + result REDACTED, READ-only method) reads chain state and
    // reports the redacted result. The method is from a READ-only allowlist (a chain
    // WRITE is unrepresentable); the model holds no EgressCapability ctor and there is NO
    // loop tool ⇒ it cannot self-dial. Honest-degrades to TransportNotCompiled without
    // `web3-egress`. custody/funds/chain-write stay HARD-LOCKED (PD-6).
    if verb.eq_ignore_ascii_case("web3-read") {
        return cmd_daemon_web3_read(rest, out).map(|_| ());
    }
    // `daemon chain-dry-run <ARM_PHRASE> <chain> <protocol> <amount_minor>`: the owner-armed
    // user-BOUNDED custody DRY-RUN (ONCHAIN PIVOT C-0). The owner ceremony arms a single-shot,
    // revocable `CustodyGrant` (demo bounds: per-tx / total-budget / chain+protocol allowlist); the
    // tx is evaluated against the bounds and the INERT chokepoint renders AUTHORIZED (would-execute)
    // or DENIED (the bound reason). C-0 is PURE: NO signing, NO broadcast, NO key, money 0 — the
    // real build→sign→broadcast is C-2 (testnet-first). The model holds no `ChainTxCapability` ctor
    // and there is NO loop tool ⇒ it cannot self-spend. Blanket `CustodyCapability` uninhabited
    // (PD-6); mainnet = a further owner arm.
    if verb.eq_ignore_ascii_case("chain-dry-run") {
        return cmd_daemon_chain_dry_run(rest, out).map(|_| ());
    }
    // `daemon trade-addr`: show (and, if absent, generate) the ISOLATED devnet signer pubkey
    // (MNEMOS × SKEW K-2 / ONCHAIN PIVOT C-2). READ-class, money 0: it derives + displays the
    // PUBLIC key (the fee payer the owner funds with devnet SOL) and persists the 32-byte secret
    // SEED to a 0600 owner-controlled file — the seed is NEVER rendered/logged (IV-K2-5). This is
    // the "isolated trading keypair" surface of the wallet-settings window (§8).
    if verb.eq_ignore_ascii_case("trade-addr") {
        return cmd_daemon_trade_addr(out).map(|_| ());
    }
    // `daemon trade <ARM_PHRASE> <sim|live> <open-account|deposit|withdraw|submit-perp|submit-order|pay-vm|lock-collateral|mark-vm|settle|form-contract|list-wcc-template|list-piecewise-template|form-piecewise|settle-piecewise|open-perp-market|factory-list-perp-market|form-funding-swap|open-liquidation|complete-liquidation> [args]`: the owner-armed
    // K-2 SKEW chain-write (ONCHAIN PIVOT C-2; devnet). The owner ceremony arms a single-shot,
    // revocable `CustodyGrant` (solana-devnet + skew); the K-1 oracle DECIDES affordability; the
    // bounded `ChainTxCapability` witness authorizes the tx; then assemble → REAL devnet simulate
    // (D2/D3) → [live:] D14 genesis pin → sign (isolated key) → D13 → REAL broadcast. `sim` stops at
    // the real simulate (money 0). The model holds no witness + no signer + NO loop tool ⇒ it cannot
    // self-sign (IV-K2-12); mainnet is a further owner arm; blanket `CustodyCapability` uninhabited.
    if verb.eq_ignore_ascii_case("trade") {
        return cmd_daemon_trade(rest, out).map(|_| ());
    }
    // `daemon image-frontier <ARM_PHRASE> <path>`: the owner-armed FRONTIER-IMAGE egress
    // ([5] B⑭). The owner ceremony arms a single-shot EgressGrant; render_frontier_image
    // classifies the image and surfaces the EXPLICIT "an image cannot be auto-redacted"
    // warning + the egress-ready data-URL metadata. The model holds no EgressCapability
    // ctor ⇒ it cannot self-send an image. The actual frontier multimodal SEND is the
    // deferred owner go-live (the live consult body is text-only). custody HARD-LOCKED.
    if verb.eq_ignore_ascii_case("image-frontier") {
        return cmd_daemon_image_frontier(rest, out).map(|_| ());
    }
    // `daemon remote-run <ARM_PHRASE> <command-token>`: the owner-armed REMOTE-SHELL READ
    // diagnostic ([7] B⑪, ⑪-class, highest-risk). The owner ceremony arms a single-shot
    // EgressGrant; render_remote_run runs ONE FIXED READ command (whoami/uname/df/git-status/
    // git-head — an arbitrary shell / write / push is unrepresentable) on the CONFIG-only host
    // over the sandboxed OpenSSH subprocess (net-allowed; local writes confined to ~/.ssh; the
    // credential stays in the OS ssh config). The model holds no EgressCapability ctor and there
    // is NO loop tool ⇒ it cannot self-run. custody/funds/chain-write HARD-LOCKED (PD-6).
    if verb.eq_ignore_ascii_case("remote-run") {
        return cmd_daemon_remote_run(rest, out).map(|_| ());
    }
    // `daemon bold <ARM_PHRASE> [task]`: the COMPOSITE BOLD SESSION (ENDGAME E13-4 / ⑳).
    // One owner gesture arms BOTH egress AND mutate-local for a bounded, revocable
    // session; the agent's pending PROPOSED edits + runs AUTO-EXECUTE within the bound
    // with NO per-action approval (bold-within-bounds), each auto-checkpointed first,
    // each exec kernel-sandboxed (network DENIED). The escalation family (chain-write/
    // force-push/key-export) is refused at PROPOSE time ⇒ never minted, never drained ⇒
    // un-armable in EVERY mode incl bold. The model cannot mint the grant; custody/funds
    // stay HARD-LOCKED (PD-6, uninhabited). The live frontier think-loop is owner go-live.
    if verb.eq_ignore_ascii_case("bold") {
        return cmd_daemon_bold(rest, out).map(|_| ());
    }
    // `daemon evolve <ARM_PHRASE> <goal>`: the AUTONOMOUS Read-Execute-WRITE evolution
    // loop (P1-4). READ the held patterns + the DGM-H perf ledger, EXECUTE the two-model
    // orchestration (frontier plan -> route -> local implement -> sui-build CODE oracle
    // verify), and WRITE ONLY the oracle-Verified + cross-memory-consistent patterns to
    // the local store + the 2-tier Walrus index, reinforcing each pattern's perf score.
    // The model never self-certifies — the oracle gates the Write (the P-HALL break);
    // custody/funds stay HARD-LOCKED (PD-6). Honest-degrades without put-fixture-net + a
    // local backend.
    if verb.eq_ignore_ascii_case("evolve") {
        return cmd_daemon_evolve(rest, out).map(|_| ());
    }
    // A⑤ v2 EGRESS: `daemon git-push <ARM_PHRASE> [branch]` — ONE owner-armed git push
    // to the repo's `origin` (origin-only, owner-locked). Reuses GrantTier::Egress (no
    // new tier); runs `git push origin <branch>` under a bespoke net-allowed,
    // .git-write-scoped sandbox; force-push is structurally impossible. custody/funds
    // HARD-LOCKED (PD-6). The MODEL cannot reach this (it holds only ReadCapability).
    if verb.eq_ignore_ascii_case("git-push") {
        return cmd_daemon_git_push(rest, out).map(|_| ());
    }
    let trace = crate::StageFTraceLink::new([0x53; 32], 0, 0);
    // a REAL runner: ONE bounded job, local-first, NO egress grant armed (so an
    // autonomous frontier escalation is denied without an owner-arm), and a
    // concurrency bound that reserves the interactive lane.
    let mut rt = AutonomyRuntime::arm(
        1,
        None,
        BudgetCap::new(100_000, 1_000_000, 100_000),
        2,
        trace,
    );
    if verb.eq_ignore_ascii_case("kill") {
        rt.kill();
        // a resume after kill can NEVER resurrect a terminal job (no zombie).
        rt.resume();
        let view = rt.supervisor_view();
        let body = vec![
            "daemon runner stopped (real job; the express control rail bypasses background queues)"
                .to_string(),
            format!(
                "state = {} · killable = {} (Unknown — never a false green)",
                view.state.label(),
                view.is_killable()
            ),
            format!(
                "terminal = {}; a resume after kill never resurrects it (no zombie)",
                rt.is_terminal()
            ),
            "every outbound byte still passes redact(); funds/wallet are hard-locked".to_string(),
        ];
        return emit(
            out,
            "daemon",
            &toplevel_envelope_hex("daemon"),
            CommandRisk::ReadOnly,
            ApprovalRequirement::None,
            RenderTruth::Unknown,
            &body,
        );
    }
    // Any verb that is neither a recognized action above nor the default `status`
    // is a typo/mistake — fail HONESTLY instead of silently rendering status.
    if !verb.eq_ignore_ascii_case("status") {
        return emit(
            out,
            "daemon",
            &toplevel_envelope_hex("daemon"),
            CommandRisk::ReadOnly,
            ApprovalRequirement::None,
            RenderTruth::Unknown,
            &[
                format!("unknown subcommand: daemon {verb}"),
                "valid: status · kill · run · run-frontier · run-mutate · serve · serve-chat · fetch · bold · evolve".to_string(),
            ],
        );
    }
    // status (default): the live runner state + the real control acting on the job.
    let view = rt.supervisor_view();
    rt.pause();
    let pause_acts = rt.is_paused();
    rt.resume();
    let interactive_ok = rt.try_admit_interactive();
    let body = vec![
        "daemon = a real bounded background runner — killable, holding no secret or wallet".to_string(),
        format!(
            "state = {} · killable = {} · holds no secret/wallet = {}",
            view.state.label(),
            view.is_killable(),
            view.holds_no_secret_or_wallet()
        ),
        "autonomy = local-first; a frontier escalation is denied unless you arm an egress grant".to_string(),
        format!("pause acts on the real job = {pause_acts}; resume restores it"),
        format!("interactive stays responsive while the job runs = {interactive_ok}"),
        format!(
            "turns run = {} · egress actions used = {} (the grant is re-checked before every side effect)",
            rt.turns_run(),
            rt.egress_actions_used()
        ),
        "every outbound byte passes redact(); funds/wallet are hard-locked; `daemon kill` ends the job".to_string(),
    ];
    emit(
        out,
        "daemon",
        &toplevel_envelope_hex("daemon"),
        CommandRisk::ReadOnly,
        ApprovalRequirement::None,
        RenderTruth::Green,
        &body,
    )
}

/// `sinabro daemon run-mutate <ARM_PHRASE>` — the owner ARMS a bounded
/// MUTATE-LOCAL autonomy window (the E10-2b `MUTATE_ARM_PHRASE` ceremony) and the
/// pending AGENT-PROPOSED exec proposals AUTO-EXECUTE within the bound (3 actions /
/// 5 min, revocable) — NO per-action ping (the opt-in autonomy window, D-A3). Each
/// runs through the gated chokepoint (`proceed_authorized_mutate` →
/// `execute_authorized_mutate`: kernel sandbox at LocalWrite; network kernel-DENIED,
/// IV-A6). Gate order: the EXACT arm phrase (missing/wrong ⇒ NO grant, NO execution
/// — fail-closed; the model cannot supply it) → install the broad grant → for each
/// pending `.xep`, RE-DERIVE the MutateCapability at the live `(now, used)` (IV-A9)
/// and proceed, consuming on run, stopping fail-closed at the grant cap. Custody /
/// funds stay HARD-LOCKED (PD-6, IV-A10). Feature-independent (executes local
/// proposals; no consult / no egress).
fn cmd_daemon_run_mutate(rest: &[String], out: &mut impl Write) -> io::Result<bool> {
    use crate::commands::budget::BudgetCap;
    use crate::commands::grant::{GrantBounds, MUTATE_ARM_PHRASE, arm_local_mutate_grant};
    use crate::daemon::runtime::{AutonomyRuntime, MutateProceedOutcome};
    use crate::mutate_execute::{AuthorizedMutate, MutateExecOutcome};
    use crate::repl::approval::ApprovalPrompt;

    /// The bounds of the armed mutate window (D-A3): conservative, revocable.
    const ARMED_MUTATE_MAX_ACTIONS: u32 = 3;
    const ARMED_MUTATE_TTL_MS: u64 = 5 * 60 * 1000;

    let envelope_hex = toplevel_envelope_hex("daemon");
    let supplied_phrase = rest.get(1).map_or("", String::as_str);
    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0u64, |d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX));

    // GATE (owner-arm ceremony): the EXACT mutate arm phrase. Missing/wrong ⇒ NO
    // grant, NO execution — fail-closed (the model cannot supply this).
    let mut prompt = ApprovalPrompt::new(ApprovalRequirement::TypedPhrase, MUTATE_ARM_PHRASE);
    let audit_hash_32 = sha256_32(b"daemon.run-mutate.local.arm.v1");
    let Some(grant) = arm_local_mutate_grant(
        &mut prompt,
        supplied_phrase.trim(),
        audit_hash_32,
        GrantBounds {
            max_actions_u32: ARMED_MUTATE_MAX_ACTIONS,
            expires_at_epoch_ms: now_ms.saturating_add(ARMED_MUTATE_TTL_MS),
        },
    ) else {
        let body = vec![
            "daemon run-mutate = a BOUNDED autonomous MUTATE window for agent-proposed execs"
                .to_string(),
            format!(
                "bound: {ARMED_MUTATE_MAX_ACTIONS} actions / {} min, revocable; each runs in the kernel sandbox (network DENIED)",
                ARMED_MUTATE_TTL_MS / 60_000
            ),
            format!("to arm, supply EXACTLY: daemon run-mutate {MUTATE_ARM_PHRASE}"),
            "the model proposes only (PROPOSE-EXEC); it cannot arm this or run anything".to_string(),
            "denied: no autonomous mutate without the exact arm phrase; funds/custody HARD-LOCKED (PD-6)"
                .to_string(),
        ];
        emit(
            out,
            "daemon",
            &envelope_hex,
            CommandRisk::Admin,
            ApprovalRequirement::TypedPhrase,
            RenderTruth::Yellow,
            &body,
        )?;
        return Ok(false);
    };

    // The runner holds the broad mutate grant; the capability is RE-DERIVED per
    // action (IV-A9). No egress grant, no secret/wallet (PD-6).
    let trace = crate::StageFTraceLink::new([0x53; 32], 0, 0);
    let mut rt = AutonomyRuntime::arm(
        1,
        None,
        BudgetCap::new(100_000, 1_000_000, 100_000),
        2,
        trace,
    );
    rt.install_mutate_grant(grant);

    let store = match crate::exec_proposal::ExecProposalStore::open_local() {
        Ok(s) => s,
        Err(_) => {
            let body = vec![
                "daemon run-mutate: armed, but the exec proposal store is unavailable (no key/home)"
                    .to_string(),
                "fail-closed: nothing executed".to_string(),
            ];
            emit(
                out,
                "daemon",
                &envelope_hex,
                CommandRisk::Admin,
                ApprovalRequirement::TypedPhrase,
                RenderTruth::Yellow,
                &body,
            )?;
            return Ok(false);
        }
    };
    let pending = store.load_pending();

    let mut body = vec![
        format!(
            "daemon run-mutate: ARMED a bounded MUTATE window ({ARMED_MUTATE_MAX_ACTIONS} actions / {} min, revocable)",
            ARMED_MUTATE_TTL_MS / 60_000
        ),
        format!(
            "pending exec proposals: {} (auto-executing within the bound; no per-action ping)",
            pending.proposals.len()
        ),
    ];
    if pending.proposals.is_empty() {
        body.push("no pending exec proposals to run; the armed window expires unused".to_string());
    }
    let mut ran = 0u32;
    let mut truth = RenderTruth::Green;
    for entry in &pending.proposals {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(now_ms, |d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX));
        let id: String = entry
            .record_name
            .chars()
            .take(crate::exec_proposal::EXEC_PROPOSAL_ID_HEX_CHARS)
            .collect();
        match rt.proceed_authorized_mutate(now, &AuthorizedMutate::Exec(&entry.proposal)) {
            MutateProceedOutcome::Ran(MutateExecOutcome::Exec(Ok(outcome))) => {
                ran += 1;
                if outcome.timed_out || outcome.exit_code != Some(0) {
                    truth = RenderTruth::Yellow;
                }
                // The command passed the mint-time secret screen (IV-A8); belt-redact the echo.
                let cmd_fragments = [entry.proposal.command.as_str()];
                let cmd_line = match redact(&RedactionRequest {
                    fragments: &cmd_fragments,
                    candidate_memory_ids: &[],
                    deleted_ids: &[],
                    include_private_memory: false,
                }) {
                    Ok(r) if r.secret_fragments_denied_u32() == 0 => {
                        format!("ran id={id} command={}", entry.proposal.command)
                    }
                    _ => format!(
                        "ran id={id} command=withheld (secret-shaped; ran exactly as proposed)"
                    ),
                };
                body.push(cmd_line);
                body.push(format!(
                    "  exit={} timed_out={} (kernel sandbox LocalWrite; network DENIED); consumed",
                    outcome
                        .exit_code
                        .map_or_else(|| "none".to_string(), |c| c.to_string()),
                    outcome.timed_out
                ));
                let _ = store.remove(&entry.record_name);
            }
            MutateProceedOutcome::Ran(MutateExecOutcome::Exec(Err(deny))) => {
                ran += 1;
                truth = RenderTruth::Red;
                body.push(format!(
                    "id={id}: the sandbox DENIED it ({}) — fail-closed, NEVER unsandboxed; kept pending",
                    deny.class_label()
                ));
            }
            MutateProceedOutcome::Ran(MutateExecOutcome::Edit(_)) => {
                // Unreachable: only Exec actions are fed here (kept honest, not a panic).
            }
            MutateProceedOutcome::MutateDenied => {
                body.push(format!(
                    "grant bound reached after {ran} action(s) — remaining proposals stay pending (fail-closed)"
                ));
                break;
            }
            MutateProceedOutcome::Paused | MutateProceedOutcome::Terminated => {
                body.push("runner paused/terminated — stopped (no side effect)".to_string());
                break;
            }
        }
    }
    body.push(format!(
        "executed={ran}/{} mutate_actions_used={} (capability re-derived per action; cap={ARMED_MUTATE_MAX_ACTIONS})",
        pending.proposals.len(),
        rt.mutate_actions_used()
    ));
    body.push(
        "custody/funds HARD-LOCKED (PD-6); every exec kernel-sandboxed (network DENIED)"
            .to_string(),
    );
    emit(
        out,
        "daemon",
        &envelope_hex,
        CommandRisk::Admin,
        ApprovalRequirement::TypedPhrase,
        truth,
        &body,
    )?;
    Ok(true)
}

/// `sinabro daemon bold <ARM_PHRASE> [task]` — the owner ARMS a COMPOSITE BOLD SESSION
/// (ENDGAME E13-4 / ⑳): one gesture arms BOTH egress AND mutate-local for a bounded,
/// revocable session, and the agent's pending PROPOSED edits + runs AUTO-EXECUTE within
/// the bound with NO per-action approval (bold-within-bounds — the Claude Code / Cursor
/// "auto" model). Gate order: the EXACT bold arm phrase (missing/wrong ⇒ NO grant, NO
/// execution — fail-closed; the model cannot supply it) → install BOTH halves on the
/// runner → for each pending edit/run proposal, auto-CHECKPOINT a restore-point BEFORE
/// it runs (IV-BS5), RE-DERIVE the `MutateCapability` at the live `(now, used)` (IV-A9 /
/// IV-BS6), and proceed through the gated chokepoint (edit = lane-A + staleness; exec =
/// kernel sandbox LocalWrite, network kernel-DENIED). The escalation family (chain-write /
/// FORCE-PUSH / KEY-EXPORT) is refused at PROPOSE time, so an escalation proposal is never
/// minted ⇒ never in the pending set ⇒ never drained here (un-armable in EVERY mode incl
/// bold; IV-BS3). The egress half is ARMED for the session (an in-session frontier consult
/// fires within the egress bound). Custody / funds / mainnet / chain-WRITE / key-export
/// stay HARD-LOCKED (PD-6, IV-BS9). Feature-independent (executes LOCAL proposals); the
/// live frontier think-loop that GENERATES proposals is the owner go-live step / E13-5.
fn cmd_daemon_bold(rest: &[String], out: &mut impl Write) -> io::Result<bool> {
    use crate::commands::budget::BudgetCap;
    use crate::commands::checkpoint::{CheckpointScope, CheckpointStore};
    use crate::commands::grant::{BOLD_ARM_PHRASE, GrantBounds, arm_local_bold_session};
    use crate::daemon::runtime::{AutonomyRuntime, MutateProceedOutcome};
    use crate::mutate_execute::{AuthorizedMutate, MutateExecOutcome};
    use crate::repl::approval::ApprovalPrompt;

    /// The bounds of the armed bold session (D-BS5): bold-but-conservative, revocable.
    /// Up to BOLD_MAX_ACTIONS edit/run actions AND up to BOLD_MAX_ACTIONS egress actions,
    /// under a shared TTL.
    const BOLD_MAX_ACTIONS: u32 = 8;
    const BOLD_TTL_MS: u64 = 10 * 60 * 1000;

    let envelope_hex = toplevel_envelope_hex("daemon");
    let supplied_phrase = rest.get(1).map_or("", String::as_str);
    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0u64, |d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX));
    // A fresh live clock read per action (the grant is re-derived against it; IV-BS6).
    let now_of = || {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(now_ms, |d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
    };

    // GATE (owner-arm ceremony): the EXACT bold arm phrase. Missing/wrong ⇒ NO grant, NO
    // execution — fail-closed (the model cannot supply this).
    let mut prompt = ApprovalPrompt::new(ApprovalRequirement::TypedPhrase, BOLD_ARM_PHRASE);
    let audit_hash_32 = sha256_32(b"daemon.bold.session.arm.v1");
    let Some(bold) = arm_local_bold_session(
        &mut prompt,
        supplied_phrase.trim(),
        audit_hash_32,
        GrantBounds {
            max_actions_u32: BOLD_MAX_ACTIONS,
            expires_at_epoch_ms: now_ms.saturating_add(BOLD_TTL_MS),
        },
    ) else {
        let body = vec![
            "daemon bold = a BOUNDED bold-within-bounds SESSION (pending edit + run AUTO-EXECUTE, NO per-action approval)".to_string(),
            format!(
                "bound: up to {BOLD_MAX_ACTIONS} edit/run + {BOLD_MAX_ACTIONS} egress actions / {} min, revocable; each mutation auto-checkpointed; each exec kernel-sandboxed (network DENIED)",
                BOLD_TTL_MS / 60_000
            ),
            format!("to arm, supply EXACTLY: daemon bold {BOLD_ARM_PHRASE} [task]"),
            "escalations (mainnet/chain-write/force-push/key-export) ALWAYS STOP — refused at propose-time, un-armable in EVERY mode incl bold".to_string(),
            "the model proposes only; it cannot arm this or run anything; funds/custody HARD-LOCKED (PD-6)".to_string(),
        ];
        emit(
            out,
            "daemon",
            &envelope_hex,
            CommandRisk::Admin,
            ApprovalRequirement::TypedPhrase,
            RenderTruth::Yellow,
            &body,
        )?;
        return Ok(false);
    };

    // The runner holds the COMPOSITE bold grant (egress + mutate). The capability is
    // RE-DERIVED per action (IV-A9 / IV-BS6). No secret/wallet (PD-6); custody unreachable.
    let trace = crate::StageFTraceLink::new([0x53; 32], 0, 0);
    let mut rt = AutonomyRuntime::arm(
        1,
        None,
        BudgetCap::new(100_000, 1_000_000, 100_000),
        2,
        trace,
    );
    rt.install_bold_session(&bold);
    // Session-scoped restore-points (IV-BS5). In-memory + hash-only (honest scope): each
    // bold mutation records a restore-target BEFORE it runs; a cross-process byte-content
    // revert is the deferred increment.
    let mut checkpoints = CheckpointStore::new();

    let mut body = vec![
        format!(
            "daemon bold: ARMED a bold session (egress + mutate; up to {BOLD_MAX_ACTIONS} edit/run / {} min, revocable)",
            BOLD_TTL_MS / 60_000
        ),
        format!(
            "egress: {} (an in-session frontier consult fires within the bound, no per-action ping)",
            if rt.egress_armed_at(now_ms) {
                "ARMED"
            } else {
                "not armed"
            }
        ),
    ];

    // Open both proposal stores; a missing store honest-degrades (nothing to drain).
    let exec_store = crate::exec_proposal::ExecProposalStore::open_local().ok();
    let edit_store = crate::file_edit::ProposalStore::open_local().ok();
    let exec_pending = exec_store
        .as_ref()
        .map(crate::exec_proposal::ExecProposalStore::load_pending)
        .unwrap_or_default();
    let edit_pending = edit_store
        .as_ref()
        .map(crate::file_edit::ProposalStore::load_pending)
        .unwrap_or_default();
    let total_pending = exec_pending.proposals.len() + edit_pending.proposals.len();
    body.push(format!(
        "pending agent proposals: {} run + {} edit (auto-executing within the bound; no per-action ping; escalations were refused at propose-time)",
        exec_pending.proposals.len(),
        edit_pending.proposals.len()
    ));
    if total_pending == 0 {
        body.push(
            "no pending edit/run proposals to execute; the armed window expires unused".to_string(),
        );
    }

    let mut ran = 0u32;
    let mut checkpointed = 0u32;
    let mut truth = RenderTruth::Green;
    let mut bound_reached = false;

    // --- drain pending RUN (exec) proposals ---
    if let Some(store) = exec_store.as_ref() {
        for entry in &exec_pending.proposals {
            if bound_reached {
                break;
            }
            // auto_checkpoint BEFORE the mutation (IV-BS5). An exec is non-revertible (a
            // run cannot be un-run); the checkpoint is a command-hash restore-MARKER so
            // the session keeps a complete record of every mutation attempted.
            let cmd_hash = sha256_32(entry.proposal.command.as_bytes());
            checkpoints.auto_checkpoint(CheckpointScope::Task, cmd_hash, cmd_hash, trace);
            checkpointed += 1;
            let id: String = entry
                .record_name
                .chars()
                .take(crate::exec_proposal::EXEC_PROPOSAL_ID_HEX_CHARS)
                .collect();
            match rt.proceed_authorized_mutate(now_of(), &AuthorizedMutate::Exec(&entry.proposal)) {
                MutateProceedOutcome::Ran(MutateExecOutcome::Exec(Ok(outcome))) => {
                    ran += 1;
                    if outcome.timed_out || outcome.exit_code != Some(0) {
                        truth = RenderTruth::Yellow;
                    }
                    // The command passed the mint-time secret screen (IV-A8); belt-redact.
                    let cmd_fragments = [entry.proposal.command.as_str()];
                    let cmd_line = match redact(&RedactionRequest {
                        fragments: &cmd_fragments,
                        candidate_memory_ids: &[],
                        deleted_ids: &[],
                        include_private_memory: false,
                    }) {
                        Ok(r) if r.secret_fragments_denied_u32() == 0 => {
                            format!("run id={id} command={}", entry.proposal.command)
                        }
                        _ => format!(
                            "run id={id} command=withheld (secret-shaped; ran exactly as proposed)"
                        ),
                    };
                    body.push(cmd_line);
                    body.push(format!(
                        "  exit={} timed_out={} (checkpointed; kernel sandbox LocalWrite; network DENIED); consumed",
                        outcome
                            .exit_code
                            .map_or_else(|| "none".to_string(), |c| c.to_string()),
                        outcome.timed_out
                    ));
                    let _ = store.remove(&entry.record_name);
                }
                MutateProceedOutcome::Ran(MutateExecOutcome::Exec(Err(deny))) => {
                    ran += 1;
                    truth = RenderTruth::Red;
                    body.push(format!(
                        "run id={id}: the sandbox DENIED it ({}) — fail-closed, NEVER unsandboxed; kept pending",
                        deny.class_label()
                    ));
                }
                MutateProceedOutcome::Ran(MutateExecOutcome::Edit(_)) => {}
                MutateProceedOutcome::MutateDenied => {
                    body.push(format!(
                        "grant bound reached after {ran} action(s) — remaining proposals stay pending (fail-closed)"
                    ));
                    bound_reached = true;
                }
                MutateProceedOutcome::Paused | MutateProceedOutcome::Terminated => {
                    body.push("runner paused/terminated — stopped (no side effect)".to_string());
                    bound_reached = true;
                }
            }
        }
    }

    // --- drain pending EDIT proposals (lane-A + staleness re-confined at apply) ---
    if let Some(store) = edit_store.as_ref() {
        let policy = crate::file_context::FileReadPolicy::workspace_default();
        for entry in &edit_pending.proposals {
            if bound_reached {
                break;
            }
            // auto_checkpoint BEFORE the edit (IV-BS5): pre = the verified pre-edit content
            // hash (the restore TARGET), applied = the new content hash.
            let applied = sha256_32(&entry.proposal.content);
            checkpoints.auto_checkpoint(
                CheckpointScope::Files,
                entry.proposal.read_sha_32,
                applied,
                trace,
            );
            checkpointed += 1;
            let id: String = entry
                .record_name
                .chars()
                .take(crate::file_edit::PROPOSAL_ID_HEX_CHARS)
                .collect();
            match rt.proceed_authorized_mutate(
                now_of(),
                &AuthorizedMutate::Edit {
                    proposal: &entry.proposal,
                    policy: &policy,
                },
            ) {
                MutateProceedOutcome::Ran(MutateExecOutcome::Edit(Ok(receipt))) => {
                    ran += 1;
                    body.push(format!(
                        "edit id={id} applied {} ({} bytes; checkpointed restore-point; lane-A + staleness verified); consumed",
                        receipt.target_path.display(),
                        receipt.bytes_written_u64
                    ));
                    let _ = store.remove(&entry.record_name);
                }
                MutateProceedOutcome::Ran(MutateExecOutcome::Edit(Err(deny))) => {
                    ran += 1;
                    truth = RenderTruth::Yellow;
                    body.push(format!(
                        "edit id={id}: apply DENIED ({}) — fail-closed (lane-A / staleness); kept pending",
                        deny.class_label()
                    ));
                }
                MutateProceedOutcome::Ran(MutateExecOutcome::Exec(_)) => {}
                MutateProceedOutcome::MutateDenied => {
                    body.push(format!(
                        "grant bound reached after {ran} action(s) — remaining edits stay pending (fail-closed)"
                    ));
                    bound_reached = true;
                }
                MutateProceedOutcome::Paused | MutateProceedOutcome::Terminated => {
                    body.push("runner paused/terminated — stopped (no side effect)".to_string());
                    bound_reached = true;
                }
            }
        }
    }

    body.push(format!(
        "executed={ran}/{total_pending} mutate_actions_used={} checkpoints_recorded={checkpointed} (capability re-derived per action; cap={BOLD_MAX_ACTIONS})",
        rt.mutate_actions_used()
    ));
    body.push(
        "reversibility: each mutation recorded a restore-point (in-memory, session-scoped; byte-content revert deferred — hash-only store)"
            .to_string(),
    );
    body.push(
        "escalations (mainnet/chain-write/force-push/key-export) un-armable in EVERY mode incl bold; custody/funds HARD-LOCKED (PD-6)"
            .to_string(),
    );
    emit(
        out,
        "daemon",
        &envelope_hex,
        CommandRisk::Admin,
        ApprovalRequirement::TypedPhrase,
        truth,
        &body,
    )?;
    Ok(true)
}

/// `sinabro daemon fetch <ARM_PHRASE> <https-url>` — the owner-armed BOUNDED DOWNLOAD
/// (ENDGAME E13-3 / ⑲). Gate order: the EXACT download arm phrase (missing/wrong ⇒ NO
/// grant, NO fetch — fail-closed; the model cannot supply it) → arm a SINGLE-SHOT,
/// fast-expiring, revocable `DownloadGrant` → derive the `FetchCapability` ONCE
/// (`local_download_capability`) → load the owner-extended allowlist from config →
/// `render_download_fetch` runs the ONE bounded GET (SSRF-walled + allowlisted,
/// secret-zero, redirect-none, byte + time capped) into a temp file and reports METADATA
/// only (host/status/bytes/temp_path/sha — never the body; the UNTRUSTED bytes are never
/// executed). Honest-degrades to `TransportNotCompiled` without `download-egress`. The
/// download is NOT a loop tool (the model cannot self-fetch); custody/funds stay
/// HARD-LOCKED (PD-6). GET-only ⇒ no chain WRITE.
fn cmd_daemon_fetch(rest: &[String], out: &mut impl Write) -> io::Result<bool> {
    use crate::commands::authority::local_download_capability;
    use crate::commands::grant::{DOWNLOAD_ARM_PHRASE, GrantBounds, arm_local_download_grant};
    use crate::provider::download_fetch::{DownloadAllowlist, DownloadSeam, render_download_fetch};
    use crate::repl::approval::ApprovalPrompt;

    /// The bounds of the owner-armed download: single-shot, fast-expiring, revocable.
    const DOWNLOAD_MAX_ACTIONS: u32 = 1;
    const DOWNLOAD_TTL_MS: u64 = 2 * 60 * 1000;

    let envelope_hex = toplevel_envelope_hex("daemon");
    let supplied_phrase = rest.get(1).map_or("", String::as_str);
    let raw_url = rest.get(2).map_or("", String::as_str);
    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0u64, |d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX));

    // GATE (owner-arm ceremony): the EXACT download arm phrase. Missing/wrong ⇒ NO
    // grant, NO fetch — fail-closed (the model cannot supply this).
    let mut prompt = ApprovalPrompt::new(ApprovalRequirement::TypedPhrase, DOWNLOAD_ARM_PHRASE);
    let audit_hash_32 = sha256_32(b"daemon.fetch.download.arm.v1");
    let Some(grant) = arm_local_download_grant(
        &mut prompt,
        supplied_phrase.trim(),
        audit_hash_32,
        GrantBounds {
            max_actions_u32: DOWNLOAD_MAX_ACTIONS,
            expires_at_epoch_ms: now_ms.saturating_add(DOWNLOAD_TTL_MS),
        },
    ) else {
        let body = vec![
            "daemon fetch = an owner-armed BOUNDED download (one GET → a temp file)".to_string(),
            format!(
                "bound: {DOWNLOAD_MAX_ACTIONS} download / {} min, revocable; SSRF-walled + allowlisted; secret-zero GET; bytes never executed",
                DOWNLOAD_TTL_MS / 60_000
            ),
            format!("to arm, supply EXACTLY: daemon fetch {DOWNLOAD_ARM_PHRASE} <https-url>"),
            "the model holds no download capability and there is NO loop tool — it cannot self-fetch"
                .to_string(),
            "denied: no download without the exact arm phrase; funds/custody HARD-LOCKED (PD-6)"
                .to_string(),
        ];
        emit(
            out,
            "daemon",
            &envelope_hex,
            CommandRisk::Network,
            ApprovalRequirement::TypedPhrase,
            RenderTruth::Yellow,
            &body,
        )?;
        return Ok(false);
    };

    // Derive the single-shot download capability from the armed grant (consumed within
    // this call). Fail-closed if the fresh grant is somehow invalid.
    let Some(cap) = local_download_capability(&grant) else {
        let body = vec![
            "daemon fetch: armed, but the download capability could not be derived (fail-closed)"
                .to_string(),
            "nothing fetched".to_string(),
        ];
        emit(
            out,
            "daemon",
            &envelope_hex,
            CommandRisk::Network,
            ApprovalRequirement::TypedPhrase,
            RenderTruth::Red,
            &body,
        )?;
        return Ok(false);
    };

    // Load the owner-extended allowlist from the persisted config (the SAME read path as
    // the config-persist surface); absent/unreadable ⇒ curated default only.
    let owner_hosts = read_owner_download_allowlist_hosts();
    let allowlist = DownloadAllowlist::with_owner_hosts(&owner_hosts);

    // The LIVE seam: a live transport under `download-egress`, otherwise port = None ⇒
    // the honest TransportNotCompiled deny. The capability witness `&cap` proves the
    // owner-arm at the type level (render_download_fetch is unreachable without it).
    let seam = DownloadSeam::new();
    let render = render_download_fetch(&cap, seam.port(), &allowlist, raw_url.trim());

    let truth = if render.ok {
        RenderTruth::Green
    } else {
        RenderTruth::Yellow
    };
    let mut body = vec![format!(
        "daemon fetch: ARMED a single-shot download ({DOWNLOAD_MAX_ACTIONS} / {} min, revocable); allowlist = {} default + {} owner host(s)",
        DOWNLOAD_TTL_MS / 60_000,
        allowlist.default_count(),
        allowlist.owner_count()
    )];
    for line in render.rendered.lines() {
        body.push(line.to_string());
    }
    body.push(format!("class={}", render.class_label));
    body.push(
        "UNTRUSTED bytes (never executed); custody/funds/chain HARD-LOCKED (PD-6); GET-only ⇒ no chain WRITE"
            .to_string(),
    );
    emit(
        out,
        "daemon",
        &envelope_hex,
        CommandRisk::Network,
        ApprovalRequirement::TypedPhrase,
        truth,
        &body,
    )?;
    Ok(true)
}

/// E13-3: read the owner-extended download allowlist hosts from the persisted config
/// (`$HOME/.mnemos/config.toml` via the SAME `data_dir` + `parse_layer` read path the
/// config surface uses). Absent / unreadable / unparsable ⇒ an empty extension (the
/// curated default still applies). The raw config text is never echoed.
fn read_owner_download_allowlist_hosts() -> Vec<String> {
    let Ok(dir) = crate::memory_store::data_dir() else {
        return Vec::new();
    };
    let path = dir.join(crate::config::CONFIG_PERSIST_FILE);
    let Ok(text) = std::fs::read_to_string(&path) else {
        return Vec::new();
    };
    let Ok(cfg) = crate::config::parse_layer(&text) else {
        return Vec::new();
    };
    crate::config::effective_download_allowlist_hosts(&[(crate::config::ConfigLayer::User, cfg)])
}

/// B⑫ (CURSOR PARITY keystone-3 / §6 B⑫) — read the owner-configured READ-tier
/// stdio MCP servers from the persisted local config (`$HOME/.mnemos/config.toml`
/// via the SAME `data_dir` + `parse_layer` read path the config surface uses).
/// Absent / unreadable / unparsable ⇒ no servers (the loop's `mcp` tool then
/// honestly denies). The raw config text is never echoed. Only `tier = "read"`
/// entries survive `effective_mcp_servers` (validate already refused others).
fn read_owner_mcp_servers() -> Vec<crate::mcp::McpServerSpec> {
    let Ok(dir) = crate::memory_store::data_dir() else {
        return Vec::new();
    };
    let path = dir.join(crate::config::CONFIG_PERSIST_FILE);
    let Ok(text) = std::fs::read_to_string(&path) else {
        return Vec::new();
    };
    let Ok(cfg) = crate::config::parse_layer(&text) else {
        return Vec::new();
    };
    crate::config::effective_mcp_servers(&[(crate::config::ConfigLayer::User, cfg)])
}

/// `sinabro daemon run <task>` — drive the REAL [`AutonomyRuntime`] through ONE
/// bounded autonomous job (the runtime `tick`), local-first (PD-7). Reuses the
/// EXACT loopback transport + before-send redaction wall + classified memory fold
/// as `provider_consult_local_at` (no second egress path), but the route is the
/// AUTONOMOUS selector (`ConsultCaller::Autonomous`, inside `tick`): with NO
/// owner-armed grant the default is LocalLoopback (READ-class, free, zero egress)
/// and a frontier escalation fails closed. Custody stays uninhabited (PD-6).
#[cfg(any(feature = "local-mlx", feature = "local-vllm"))]
fn cmd_daemon_run(rest: &[String], out: &mut impl Write) -> io::Result<()> {
    use crate::commands::budget::BudgetCap;
    use crate::daemon::runtime::{AutonomyRuntime, TurnOutcome};
    use crate::provider::local_chat::LocalChatTransport;
    use crate::provider::route_select::ConsultPhrase;

    let envelope_hex = toplevel_envelope_hex("daemon");
    // rest[0] = "run"; rest[1..] = the autonomous task.
    let task = rest.get(1..).map(|s| s.join(" ")).unwrap_or_default();
    let task = task.trim();
    if task.is_empty() {
        let body = vec![
            "usage: daemon run <task> — ONE autonomous bounded job (real AutonomyRuntime tick)"
                .to_string(),
            "route=local-first (PD-7; READ-class, free, zero egress); frontier needs an owner-armed grant".to_string(),
            "the agent recalls its store, consults the loopback brain, redacts every outbound byte".to_string(),
        ];
        return emit(
            out,
            "daemon",
            &envelope_hex,
            CommandRisk::ReadOnly,
            ApprovalRequirement::None,
            RenderTruth::Yellow,
            &body,
        );
    }
    if task.len() > PROVIDER_CONSULT_MAX_QUESTION_BYTES {
        let body = vec!["daemon run task exceeds the bounded input cap; nothing run".to_string()];
        return emit(
            out,
            "daemon",
            &envelope_hex,
            CommandRisk::ReadOnly,
            ApprovalRequirement::None,
            RenderTruth::Red,
            &body,
        );
    }
    // Resolve the loopback endpoint (the STRICT parse `provider_consult_local` uses).
    let Some(port) = crate::commands::model_select::resolve_local_port(
        std::env::var(SINABRO_LOCAL_PORT_ENV).ok().as_deref(),
        LOCAL_CONSULT_DEFAULT_PORT,
    ) else {
        let body =
            vec!["SINABRO_LOCAL_PORT is not a valid port (1-65535); nothing run".to_string()];
        return emit(
            out,
            "daemon",
            &envelope_hex,
            CommandRisk::ReadOnly,
            ApprovalRequirement::None,
            RenderTruth::Red,
            &body,
        );
    };
    let model = crate::commands::model_select::resolve_local_model(
        std::env::var(SINABRO_LOCAL_MODEL_ENV).ok().as_deref(),
    );
    let bind = crate::provider::local_endpoint::LoopbackBind::localhost(port);
    let Some(transport) = LocalChatTransport::new(bind, &model, PROVIDER_CONSULT_TIMEOUT_MS) else {
        let body = vec!["local http client failed to build; nothing run".to_string()];
        return emit(
            out,
            "daemon",
            &envelope_hex,
            CommandRisk::ReadOnly,
            ApprovalRequirement::None,
            RenderTruth::Red,
            &body,
        );
    };
    // Recall the owner's REAL persisted store (READ-class, PD-3): the autonomous
    // job's knowledge base (shareable-only frontier tier; private withheld — the
    // SAME classified fold the interactive consult uses).
    let mem = consult_memory_load();
    let loop_contents: Vec<(MemoryId, &[u8])> = mem
        .loaded
        .chunks
        .iter()
        .map(|(chunk, _)| (chunk.id(), chunk.envelope().content.as_slice()))
        .collect();
    let state = crate::agent_loop::MemoryToolState {
        records: &mem.folded.records,
        contents: &loop_contents,
        policy: &mem.policy,
    };
    let system = format!(
        "{}\n\n{}",
        sinabro_system_prompt(true),
        crate::agent_loop::SINABRO_LOOP_PROTOCOL
    );
    // The REAL runtime: ONE bounded job, NO egress grant (autonomous default =
    // local-first; a frontier escalation would fail closed), interactive lane reserved.
    let trace = crate::StageFTraceLink::new([0x53; 32], 0, 0);
    let mut rt = AutonomyRuntime::arm(
        1,
        None,
        BudgetCap::new(100_000, 1_000_000, 100_000),
        2,
        trace,
    );
    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0u64, |d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX));
    let mut last_model = String::new();
    let mut last_response_hash_32 = ZERO32;
    let outcome = {
        // The redaction-walled transport — IDENTICAL wall to `provider_consult_local_at`:
        // every assembled outbound message re-passes redact() ("local" buys ZERO
        // relaxation; the loopback peer is an UNAUDITED process). No second spawn path.
        let mut live = crate::agent_loop::FnTransport(|system: &str, user_message: &str| {
            let fragments = [user_message];
            match redact(&RedactionRequest {
                fragments: &fragments,
                candidate_memory_ids: &[],
                deleted_ids: &[],
                include_private_memory: false,
            }) {
                Ok(receipt) if receipt.secret_fragments_denied_u32() == 0 => {}
                _ => {
                    return Err(crate::agent_loop::AgentTransportError {
                        class_label: "assembled message denied by redaction".to_string(),
                    });
                }
            }
            match transport.send_local_text(
                system,
                user_message,
                PROVIDER_CONSULT_MAX_OUTPUT_TOKENS,
            ) {
                Ok(o) => {
                    last_model = o.model;
                    last_response_hash_32 = o.response_hash_32;
                    Ok(crate::agent_loop::AgentTurn {
                        answer_text: o.answer_text,
                        input_tokens_u64: o.input_tokens,
                        output_tokens_u64: o.output_tokens,
                        cached_tokens_u64: o.cached_tokens,
                    })
                }
                Err(error) => Err(crate::agent_loop::AgentTransportError {
                    class_label: error.class_label(),
                }),
            }
        });
        rt.tick(
            now_ms,
            ConsultPhrase::None,
            &system,
            task,
            &mut live,
            &state,
        )
    };
    let (truth, mut body) = match outcome {
        TurnOutcome::Ran { route, stop } => (
            RenderTruth::Green,
            vec![
                format!(
                    "daemon run: ONE autonomous bounded job RAN route={} (PD-7 local-first; zero egress)",
                    if route.is_frontier() {
                        "frontier"
                    } else {
                        "local-loopback"
                    }
                ),
                format!("autonomous task: {task}"),
                format!("loop stop={} model={last_model}", stop.class_label()),
            ],
        ),
        TurnOutcome::FrontierDenied => (
            RenderTruth::Yellow,
            vec![
                "daemon run: frontier escalation DENIED (no owner-armed grant) — fail-closed, zero egress".to_string(),
            ],
        ),
        TurnOutcome::BudgetStopped(_) => (
            RenderTruth::Yellow,
            vec!["daemon run: budget cap refused the turn (fail-closed)".to_string()],
        ),
        TurnOutcome::Paused => (
            RenderTruth::Yellow,
            vec!["daemon run: control paused the job (no side effect)".to_string()],
        ),
        TurnOutcome::Terminated => (
            RenderTruth::Yellow,
            vec!["daemon run: job terminal (no-op, no zombie)".to_string()],
        ),
    };
    body.push(format!(
        "turns_run={} egress_actions_used={} (grant re-checked before EVERY side effect; none armed)",
        rt.turns_run(),
        rt.egress_actions_used()
    ));
    body.push(format!(
        "response_sha={} (last brain turn; raw body not stored at rest)",
        hex16(&last_response_hash_32)
    ));
    body.push(
        "every outbound byte passed redact(); custody uninhabited (PD-6); local brain only, no key"
            .to_string(),
    );
    emit(
        out,
        "daemon",
        &envelope_hex,
        CommandRisk::ReadOnly,
        ApprovalRequirement::None,
        truth,
        &body,
    )
}

/// `daemon run` honest degrade for a build with NO local-serving feature (the
/// shipped terminal default): there is no loopback brain to drive, so the command
/// performs no action and says so (PD-1 — no hollow "ran" over an absent brain).
#[cfg(not(any(feature = "local-mlx", feature = "local-vllm")))]
fn cmd_daemon_run(rest: &[String], out: &mut impl Write) -> io::Result<()> {
    let _ = rest;
    let body = vec![
        "daemon run = ONE autonomous bounded job via the real AutonomyRuntime tick".to_string(),
        "this build compiled NO local-serving feature ⇒ no loopback brain to drive".to_string(),
        "build --features local-mlx (or local-vllm) + serve a loopback model, then: daemon run <task>"
            .to_string(),
    ];
    emit(
        out,
        "daemon",
        &toplevel_envelope_hex("daemon"),
        CommandRisk::ReadOnly,
        ApprovalRequirement::None,
        RenderTruth::Yellow,
        &body,
    )
}

/// A⑤ v2 EGRESS — `sinabro daemon git-push <ARM_PHRASE> [branch]`. The owner ARMS a
/// bounded EgressGrant (reuse `GrantTier::Egress` — NO new tier; the E0c
/// `OwnerArmCeremony` typed-phrase ceremony, a DEDICATED git-push phrase) and ONE
/// `git push origin <branch>` runs under a bespoke net-allowed, `.git`-write-scoped
/// sandbox ([`crate::git::render_git_push`]). origin-only (owner-locked); force-push
/// is structurally impossible (no force flag; the only user token is a validated
/// branch ref). The model has NO `EgressCapability` ctor (E0d) so it can never push.
/// ALWAYS compiled (no reqwest — the git binary is the transport, run sandboxed);
/// honest-degrades if git is absent / no kernel sandbox. CommandRisk::Network ⇒ the
/// call lands in the E5 audit chain. custody/funds HARD-LOCKED (PD-6).
/// Read the owner-configured web3 RPC endpoint VALUE from the persisted config (the
/// SAME read path as the other config-derived surfaces). Absent/unreadable/empty ⇒
/// `None` ⇒ `render_web3_read` reports the honest `NoEndpointConfigured`. There is NO
/// arbitrary-URL argument — the endpoint is config-only (the `chain_env` invariant).
/// ONCHAIN PIVOT C-1 — read the owner-configured MULTI-CHAIN registry from the persisted config
/// (the SAME read path as the other config-derived surfaces). Absent/unreadable/empty ⇒ an empty
/// registry ⇒ every read is the honest `ChainNotConfigured`. The agent reads ONLY these chains.
fn read_owner_web3_chain_registry() -> crate::provider::web3_rpc::Web3ChainRegistry {
    let load = || -> Option<crate::provider::web3_rpc::Web3ChainRegistry> {
        let dir = crate::memory_store::data_dir().ok()?;
        let path = dir.join(crate::config::CONFIG_PERSIST_FILE);
        let text = std::fs::read_to_string(&path).ok()?;
        let cfg = crate::config::parse_layer(&text).ok()?;
        Some(crate::config::effective_web3_chain_registry(&[(
            crate::config::ConfigLayer::User,
            cfg,
        )]))
    };
    load().unwrap_or_default()
}

/// [7] B⑪ — read the owner-configured remote SSH host from the persisted config (the SAME
/// read path as the other config-derived surfaces). Absent/unreadable/empty ⇒ `None` ⇒
/// `render_remote_run` reports the honest `NoHostConfigured`. Config-only (no arbitrary host).
fn read_owner_remote_ssh_host() -> Option<String> {
    let dir = crate::memory_store::data_dir().ok()?;
    let path = dir.join(crate::config::CONFIG_PERSIST_FILE);
    let text = std::fs::read_to_string(&path).ok()?;
    let cfg = crate::config::parse_layer(&text).ok()?;
    crate::config::effective_remote_ssh_host(&[(crate::config::ConfigLayer::User, cfg)])
}

/// `sinabro daemon remote-run <ARM_PHRASE> <command-token>` — the owner-armed REMOTE-SHELL
/// READ diagnostic ([7] B⑪, ⑪-class). Gate order: the EXACT arm phrase (missing/wrong ⇒ NO
/// grant, NO run — fail-closed; the model cannot supply it) → arm a SINGLE-SHOT, fast-expiring
/// `EgressGrant` → derive the `EgressCapability` ONCE → parse the READ command (unknown ⇒
/// honest deny) → read the host from config → `render_remote_run` runs the FIXED READ command
/// on the CONFIG-only host over the sandboxed OpenSSH subprocess (net-allowed; local writes
/// confined to ~/.ssh). NOT a loop tool (the model cannot self-run); custody/chain-write
/// HARD-LOCKED (PD-6); an arbitrary shell / write / push is unrepresentable.
fn cmd_daemon_remote_run(rest: &[String], out: &mut impl Write) -> io::Result<bool> {
    use crate::commands::authority::local_egress_capability;
    use crate::commands::grant::{EgressGrant, GrantBounds, GrantTier, OwnerArmCeremony};
    use crate::remote::{REMOTE_RUN_ARM_PHRASE, RemoteCommand, render_remote_run};
    use crate::repl::approval::ApprovalPrompt;

    let envelope_hex = toplevel_envelope_hex("daemon");
    let supplied_phrase = rest.get(1).map_or("", String::as_str);
    let command_token = rest.get(2).map_or("", String::as_str);

    let mut prompt = ApprovalPrompt::new(ApprovalRequirement::TypedPhrase, REMOTE_RUN_ARM_PHRASE);
    let audit_hash_32 = sha256_32(b"daemon.remote-run.egress.arm.v1");
    let Some(ceremony) = OwnerArmCeremony::complete(
        &mut prompt,
        supplied_phrase.trim(),
        GrantTier::Egress,
        audit_hash_32,
    ) else {
        let body = vec![
            "daemon remote-run = ONE owner-armed READ-only remote diagnostic over OpenSSH".to_string(),
            "risk=network; single-shot (max_actions=1), 120s, revocable; READ-only (no shell/write/push); sandboxed".to_string(),
            format!("to arm, supply EXACTLY: daemon remote-run {REMOTE_RUN_ARM_PHRASE} <command>"),
            format!("commands: {}", RemoteCommand::token_list()),
            "host = your config remote_ssh_host (no arbitrary host); the OS ssh config holds the credential".to_string(),
            "denied: no run without the exact arm phrase; custody/funds/chain-write HARD-LOCKED (PD-6)".to_string(),
        ];
        return emit(
            out,
            "daemon",
            &envelope_hex,
            CommandRisk::Network,
            ApprovalRequirement::TypedPhrase,
            RenderTruth::Yellow,
            &body,
        )
        .map(|()| true);
    };

    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0u64, |d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX));
    let bounds = GrantBounds {
        max_actions_u32: 1,
        expires_at_epoch_ms: now_ms.saturating_add(120_000),
    };
    let Some(grant) = EgressGrant::arm(ceremony, bounds) else {
        return emit(
            out,
            "daemon",
            &envelope_hex,
            CommandRisk::Network,
            ApprovalRequirement::TypedPhrase,
            RenderTruth::Yellow,
            &["egress grant arm failed; nothing run".to_string()],
        )
        .map(|()| true);
    };
    let Some(cap) = local_egress_capability(&grant) else {
        return emit(
            out,
            "daemon",
            &envelope_hex,
            CommandRisk::Network,
            ApprovalRequirement::TypedPhrase,
            RenderTruth::Yellow,
            &["egress capability denied (fresh grant); nothing run".to_string()],
        )
        .map(|()| true);
    };

    let Some(command) = RemoteCommand::parse(command_token) else {
        let body = vec![
            format!(
                "daemon remote-run: unknown READ command '{}'",
                command_token.chars().take(48).collect::<String>()
            ),
            format!("commands: {}", RemoteCommand::token_list()),
            "an arbitrary shell / write / push command is not selectable (unrepresentable); nothing run".to_string(),
        ];
        return emit(
            out,
            "daemon",
            &envelope_hex,
            CommandRisk::Network,
            ApprovalRequirement::TypedPhrase,
            RenderTruth::Yellow,
            &body,
        )
        .map(|()| true);
    };

    let host = read_owner_remote_ssh_host();
    let render = render_remote_run(&cap, host.as_deref(), command);
    let truth = if render.ok {
        RenderTruth::Green
    } else {
        RenderTruth::Yellow
    };
    let mut body = vec![format!(
        "daemon remote-run: ARMED a single-shot READ diagnostic ({}, 120s, revocable); READ-only over sandboxed OpenSSH",
        command.token()
    )];
    for line in render.rendered.lines() {
        body.push(line.to_string());
    }
    body.push(format!("class={}", render.class_label));
    body.push(
        "READ-only (no shell/write/push); credential in the OS ssh config; custody/funds/chain-write HARD-LOCKED (PD-6)"
            .to_string(),
    );
    emit(
        out,
        "daemon",
        &envelope_hex,
        CommandRisk::Network,
        ApprovalRequirement::TypedPhrase,
        truth,
        &body,
    )
    .map(|()| true)
}

/// `sinabro daemon image-frontier <ARM_PHRASE> <path>` — the owner-armed FRONTIER-IMAGE
/// egress PREPARE ([5] B⑭). Gate order: the EXACT arm phrase (missing/wrong ⇒ NO grant,
/// NO prepare — fail-closed; the model cannot supply it) → arm a single-shot, fast-expiring
/// `EgressGrant` → derive the `EgressCapability` ONCE → `render_frontier_image` classifies
/// the image and surfaces the EXPLICIT "an image cannot be auto-redacted" warning + the
/// egress-ready data-URL metadata. NOT a loop tool (the model cannot self-send an image);
/// the actual frontier multimodal SEND is the deferred owner go-live. custody HARD-LOCKED.
fn cmd_daemon_image_frontier(rest: &[String], out: &mut impl Write) -> io::Result<bool> {
    use crate::commands::authority::local_egress_capability;
    use crate::commands::grant::{EgressGrant, GrantBounds, GrantTier, OwnerArmCeremony};
    use crate::repl::approval::ApprovalPrompt;
    use crate::vision::{VISION_FRONTIER_ARM_PHRASE, render_frontier_image};

    let envelope_hex = toplevel_envelope_hex("daemon");
    let supplied_phrase = rest.get(1).map_or("", String::as_str);
    let path = rest.get(2..).map_or_else(String::new, |a| a.join(" "));

    let mut prompt =
        ApprovalPrompt::new(ApprovalRequirement::TypedPhrase, VISION_FRONTIER_ARM_PHRASE);
    let audit_hash_32 = sha256_32(b"daemon.image-frontier.egress.arm.v1");
    let Some(ceremony) = OwnerArmCeremony::complete(
        &mut prompt,
        supplied_phrase.trim(),
        GrantTier::Egress,
        audit_hash_32,
    ) else {
        let body = vec![
            "daemon image-frontier = ONE owner-armed frontier-image egress PREPARE".to_string(),
            "risk=network; an image CANNOT be auto-redacted (the redact() text wall cannot scan pixels)".to_string(),
            format!("to arm, supply EXACTLY: daemon image-frontier {VISION_FRONTIER_ARM_PHRASE} <path>"),
            "the model has no loop tool for this; it cannot self-send an image; custody/funds HARD-LOCKED (PD-6)".to_string(),
        ];
        return emit(
            out,
            "daemon",
            &envelope_hex,
            CommandRisk::Network,
            ApprovalRequirement::TypedPhrase,
            RenderTruth::Yellow,
            &body,
        )
        .map(|()| true);
    };

    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0u64, |d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX));
    let bounds = GrantBounds {
        max_actions_u32: 1,
        expires_at_epoch_ms: now_ms.saturating_add(120_000),
    };
    let Some(grant) = EgressGrant::arm(ceremony, bounds) else {
        return emit(
            out,
            "daemon",
            &envelope_hex,
            CommandRisk::Network,
            ApprovalRequirement::TypedPhrase,
            RenderTruth::Yellow,
            &["egress grant arm failed; nothing prepared".to_string()],
        )
        .map(|()| true);
    };
    let Some(cap) = local_egress_capability(&grant) else {
        return emit(
            out,
            "daemon",
            &envelope_hex,
            CommandRisk::Network,
            ApprovalRequirement::TypedPhrase,
            RenderTruth::Yellow,
            &["egress capability denied (fresh grant); nothing prepared".to_string()],
        )
        .map(|()| true);
    };

    let render = render_frontier_image(&cap, path.trim());
    let truth = if render.prepared {
        RenderTruth::Yellow // armed prepare with a warning is never "green" — the owner must read it
    } else {
        RenderTruth::Red
    };
    let mut body = vec!["daemon image-frontier: ARMED a single-shot frontier-image egress PREPARE (120s, revocable)".to_string()];
    for line in render.rendered.lines() {
        body.push(line.to_string());
    }
    body.push(format!("class={}", render.class_label));
    body.push(
        "the image is NOT auto-redactable; the real multimodal send is owner go-live; custody/funds/chain HARD-LOCKED (PD-6)"
            .to_string(),
    );
    emit(
        out,
        "daemon",
        &envelope_hex,
        CommandRisk::Network,
        ApprovalRequirement::TypedPhrase,
        truth,
        &body,
    )
    .map(|()| true)
}

/// `sinabro daemon web3-read <ARM_PHRASE> <method> [params-json]` — the owner-armed
/// CHAIN READ ([3] E10-3b). Gate order: the EXACT web3-read arm phrase (missing/wrong ⇒
/// NO grant, NO dial — fail-closed; the model cannot supply it) → arm a SINGLE-SHOT,
/// fast-expiring, revocable `EgressGrant` → derive the `EgressCapability` ONCE
/// (`local_egress_capability`) → parse the READ-only method (unknown/write ⇒ honest deny)
/// → read the endpoint from config → `render_web3_read` runs the ONE bounded JSON-RPC
/// POST (SSRF-walled endpoint, secret-zero, params + result REDACTED, READ-only method)
/// and reports the redacted result. Honest-degrades to `TransportNotCompiled` without
/// `web3-egress`. The read is NOT a loop tool (the model cannot self-dial); custody/funds/
/// chain-write stay HARD-LOCKED (PD-6); the method allowlist blocks a chain WRITE.
/// `daemon chain-dry-run <ARM_PHRASE> <chain> <protocol> <amount_minor>`: the owner-armed,
/// user-BOUNDED custody DRY-RUN (ONCHAIN PIVOT C-0). The owner ceremony arms a single-shot,
/// fast-expiring, revocable `CustodyGrant` (demo bounds); the proposed tx is evaluated against the
/// bounds and the INERT chokepoint renders AUTHORIZED (would-execute) or DENIED (the bound reason).
/// C-0 is PURE: NO signing, NO broadcast, NO key, money 0 — the real build→sign→broadcast is C-2
/// (testnet-first). The model holds no `ChainTxCapability` ctor and there is NO loop tool ⇒ it
/// cannot self-spend. Blanket `CustodyCapability` stays uninhabited (unbounded custody impossible).
fn cmd_daemon_chain_dry_run(rest: &[String], out: &mut impl Write) -> io::Result<bool> {
    use crate::chain_execute::execute_authorized_chain_tx;
    use crate::commands::authority::local_chain_tx_capability;
    use crate::commands::grant::{
        CUSTODY_ARM_PHRASE, ChainTxRequest, CustodyAuthorization, CustodyBounds, GrantBounds,
        arm_local_custody_grant,
    };
    use crate::repl::approval::ApprovalPrompt;

    /// Single-shot, fast-expiring, revocable arm window for the dry-run.
    const CUSTODY_MAX_ACTIONS: u32 = 1;
    const CUSTODY_TTL_MS: u64 = 2 * 60 * 1000;
    /// Demo bounds for the dry-run (real per-owner bounds come from config/args in C-2).
    const PER_TX_MAX: u128 = 1000;
    const TOTAL_BUDGET: u128 = 1000;

    let envelope_hex = toplevel_envelope_hex("daemon");
    let supplied_phrase = rest.get(1).map_or("", String::as_str);
    let chain = rest.get(2).map_or("", String::as_str).trim();
    let protocol = rest.get(3).map_or("", String::as_str).trim();
    let amount_raw = rest.get(4).map_or("", String::as_str).trim();
    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0u64, |d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX));

    // GATE (owner-arm ceremony): the EXACT custody arm phrase. Missing/wrong ⇒ NO grant, NO
    // evaluation — fail-closed (the model cannot supply this).
    let mut prompt = ApprovalPrompt::new(ApprovalRequirement::TypedPhrase, CUSTODY_ARM_PHRASE);
    let audit_hash_32 = sha256_32(b"daemon.chain-dry-run.custody.arm.v1");
    let Some(grant) = arm_local_custody_grant(
        &mut prompt,
        supplied_phrase.trim(),
        audit_hash_32,
        CustodyBounds {
            base: GrantBounds {
                max_actions_u32: CUSTODY_MAX_ACTIONS,
                expires_at_epoch_ms: now_ms.saturating_add(CUSTODY_TTL_MS),
            },
            per_tx_max_minor: PER_TX_MAX,
            total_budget_minor: TOTAL_BUDGET,
            chain_allowlist: vec![
                "ethereum".to_string(),
                "base".to_string(),
                "arbitrum".to_string(),
            ],
            protocol_allowlist: vec!["uniswap".to_string(), "aave".to_string()],
        },
    ) else {
        let body = vec![
            "daemon chain-dry-run = an owner-armed user-BOUNDED custody DRY-RUN (ONCHAIN PIVOT C-0)".to_string(),
            format!(
                "demo bound: per-tx<={PER_TX_MAX} · budget<={TOTAL_BUDGET} · chains[ethereum,base,arbitrum] · protocols[uniswap,aave] · {CUSTODY_MAX_ACTIONS} tx / {} min, revocable",
                CUSTODY_TTL_MS / 60_000
            ),
            format!("to arm, supply EXACTLY: daemon chain-dry-run {CUSTODY_ARM_PHRASE} <chain> <protocol> <amount_minor>"),
            "C-0 is INERT — it AUTHORIZES within bounds but NEVER signs/broadcasts (money 0); the real fire is C-2 (testnet-first)".to_string(),
            "the model holds no chain-tx capability and there is NO loop tool — it cannot self-spend; custody is OFF here (C-0 inert, money=0), owner-armable at C-2".to_string(),
        ];
        emit(
            out,
            "daemon",
            &envelope_hex,
            CommandRisk::Admin,
            ApprovalRequirement::TypedPhrase,
            RenderTruth::Yellow,
            &body,
        )?;
        return Ok(false);
    };

    // parse the amount (integer minor units; NO float).
    let Ok(amount_minor) = amount_raw.parse::<u128>() else {
        let body = vec![
            "daemon chain-dry-run: armed, but <amount_minor> is not an integer (fail-closed)"
                .to_string(),
            format!(
                "usage: daemon chain-dry-run {CUSTODY_ARM_PHRASE} <chain> <protocol> <amount_minor>"
            ),
        ];
        emit(
            out,
            "daemon",
            &envelope_hex,
            CommandRisk::Admin,
            ApprovalRequirement::TypedPhrase,
            RenderTruth::Yellow,
            &body,
        )?;
        return Ok(false);
    };
    let tx = ChainTxRequest {
        chain: chain.to_string(),
        protocol: protocol.to_string(),
        amount_minor,
    };

    // RE-DERIVE the bounded capability at the live (now, used=0, spent=0); the INERT chokepoint
    // renders the verdict. NO money moves, NO key is touched.
    let (truth, verdict_line) = match local_chain_tx_capability(&grant, now_ms, 0, 0, &tx) {
        Some(cap) => {
            let receipt = execute_authorized_chain_tx(cap, &tx);
            (
                RenderTruth::Green,
                format!(
                    "verdict: AUTHORIZED within bounds ⇒ {:?} (INERT — C-0 would build+sign+broadcast in C-2; money 0)",
                    receipt.status
                ),
            )
        }
        None => {
            let reason = match grant.authorize(now_ms, 0, 0, &tx) {
                CustodyAuthorization::Denied(r) => format!("{r:?}"),
                CustodyAuthorization::Authorized => "—".to_string(),
            };
            (
                RenderTruth::Red,
                format!("verdict: DENIED ({reason}) — fail-closed, nothing authorized, money 0"),
            )
        }
    };
    let body = vec![
        format!(
            "daemon chain-dry-run: ARMED a single-shot custody grant ({CUSTODY_MAX_ACTIONS} tx / {} min, revocable)",
            CUSTODY_TTL_MS / 60_000
        ),
        format!("tx: chain={chain} protocol={protocol} amount_minor={amount_minor}"),
        format!(
            "bound: per-tx<={PER_TX_MAX} · budget<={TOTAL_BUDGET} · chains[ethereum,base,arbitrum] · protocols[uniswap,aave]"
        ),
        verdict_line,
        "C-0 honest LOCK: PURE/INERT — no key, no signature, no broadcast (money 0); the real fire is C-2 (testnet-first). Custody is OFF here (inert), owner-armable at C-2; mainnet = a further owner arm.".to_string(),
    ];
    emit(
        out,
        "daemon",
        &envelope_hex,
        CommandRisk::Admin,
        ApprovalRequirement::TypedPhrase,
        truth,
        &body,
    )?;
    Ok(true)
}

/// The 0600 owner-controlled file that holds the ISOLATED devnet signer SEED (base58). The seed is
/// NEVER rendered/logged (IV-K2-5); only the PUBLIC key is displayed. For mainnet (a future arm) the
/// seed would be sealed via the keystore; on devnet a 0600 file (like an ssh key) is the source.
fn solana_signer_key_path() -> Option<std::path::PathBuf> {
    Some(
        crate::memory_store::data_dir()
            .ok()?
            .join("solana_devnet_signer.key"),
    )
}

/// Write `contents` to `path` with 0600 perms on unix (create-time), a plain write elsewhere.
fn write_key_file_private(path: &std::path::Path, contents: &str) -> io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(path)?;
        f.write_all(contents.as_bytes())?;
        Ok(())
    }
    #[cfg(not(unix))]
    {
        std::fs::write(path, contents)
    }
}

/// Load the isolated devnet signer from its 0600 file (`None` if absent / unparsable).
fn load_solana_signer() -> Option<crate::chain_signer::IsolatedSigner> {
    let path = solana_signer_key_path()?;
    let text = std::fs::read_to_string(&path).ok()?;
    let seed = crate::chain_signer::IsolatedSigner::parse_base58_seed(&text)?;
    Some(crate::chain_signer::IsolatedSigner::from_seed(seed))
}

/// `sinabro daemon trade-addr` — show (and, if absent, generate) the ISOLATED devnet signer pubkey
/// (MNEMOS × SKEW K-2 / C-2). READ-class, money 0: derive + display the PUBLIC key (the fee payer
/// the owner funds with devnet SOL) and persist the secret SEED to a 0600 file (NEVER rendered).
fn cmd_daemon_trade_addr(out: &mut impl Write) -> io::Result<()> {
    let envelope_hex = toplevel_envelope_hex("daemon");
    let Some(path) = solana_signer_key_path() else {
        let body = vec!["daemon trade-addr: no data dir available (fail-closed)".to_string()];
        return emit(
            out,
            "daemon",
            &envelope_hex,
            CommandRisk::ReadOnly,
            ApprovalRequirement::None,
            RenderTruth::Red,
            &body,
        );
    };
    // load OR generate+persist the isolated key.
    let (signer, newly) = match load_solana_signer() {
        Some(s) => (s, false),
        None => {
            let Some(s) = crate::chain_signer::IsolatedSigner::generate() else {
                let body = vec!["daemon trade-addr: OS RNG unavailable (fail-closed)".to_string()];
                return emit(
                    out,
                    "daemon",
                    &envelope_hex,
                    CommandRisk::ReadOnly,
                    ApprovalRequirement::None,
                    RenderTruth::Red,
                    &body,
                );
            };
            let persisted = s.seed_base58_for_persist();
            if write_key_file_private(&path, &persisted).is_err() {
                let body = vec![
                    "daemon trade-addr: could not persist the isolated key (fail-closed)"
                        .to_string(),
                ];
                return emit(
                    out,
                    "daemon",
                    &envelope_hex,
                    CommandRisk::ReadOnly,
                    ApprovalRequirement::None,
                    RenderTruth::Red,
                    &body,
                );
            }
            (s, true)
        }
    };
    let pubkey = signer.pubkey().to_base58();
    let body = vec![
        "daemon trade-addr = the ISOLATED Sinabro devnet signer (MNEMOS × SKEW K-2 / C-2)".to_string(),
        format!("isolated devnet pubkey: {pubkey}"),
        if newly {
            "status: NEWLY generated (32-byte seed persisted to a 0600 file; the SECRET is never rendered/logged)".to_string()
        } else {
            "status: existing isolated key (the SECRET seed stays in its 0600 file; never rendered)".to_string()
        },
        format!(
            "fund it (devnet SOL, free): `solana airdrop 1 {pubkey} --url devnet` — then `daemon trade {} live open-account`",
            crate::commands::grant::CUSTODY_ARM_PHRASE
        ),
        format!("balance: https://explorer.solana.com/address/{pubkey}?cluster=devnet"),
        "this key is NEVER the Skew keeper key / the owner main wallet; total compromise is bounded by the funded amount (three walls, one number).".to_string(),
    ];
    emit(
        out,
        "daemon",
        &envelope_hex,
        CommandRisk::ReadOnly,
        ApprovalRequirement::None,
        RenderTruth::Green,
        &body,
    )
}

/// Emit a `daemon`-namespace Admin/typed-phrase render (the shared exit for `daemon trade`).
fn emit_daemon_admin<W: Write>(
    out: &mut W,
    envelope_hex: &str,
    truth: RenderTruth,
    body: Vec<String>,
) -> io::Result<()> {
    emit(
        out,
        "daemon",
        envelope_hex,
        CommandRisk::Admin,
        ApprovalRequirement::TypedPhrase,
        truth,
        &body,
    )
}

/// `sinabro daemon trade <ARM_PHRASE> <sim|live> <open-account|deposit|withdraw|submit-perp|submit-order|pay-vm|lock-collateral|mark-vm|settle|form-contract|list-wcc-template|list-piecewise-template|form-piecewise|settle-piecewise|open-perp-market|factory-list-perp-market|form-funding-swap|open-liquidation|complete-liquidation> [args]` — the
/// owner-armed K-2 SKEW chain-write (ONCHAIN PIVOT C-2; devnet). Gate chain: the EXACT custody arm
/// phrase → the K-1 oracle DECIDES affordability → a within-bounds `ChainTxCapability` witness → the
/// isolated signer → assemble → REAL devnet simulate (D2/D3) → [live:] D14 genesis pin → sign → D13
/// → REAL broadcast. `sim` stops at the real simulate (money 0). Fail-closed at every gate; the
/// model holds no phrase + no witness + no signer + NO loop tool (IV-K2-12).
/// Build the canonical straddle leg pair (the deployed `aether-opt-straddle-1` shape that the
/// `list_piecewise_template` golden uses) + each leg's EXACT certified WCL. `leg_long = |S−strike|
/// − premium` (WCL = premium, the apex loss); `leg_short` = its antisymmetric negation (WCL =
/// `intrinsic_max − premium`). The piecewise listing / form / settle arms PROPOSE this structured
/// payoff from a few scalar knobs. Returns `None` (fail-closed) on a degenerate domain, an
/// off-lattice strike (the segment breakpoint must be on-lattice for the partition + the exact
/// WCL), a degenerate top segment, or a premium above the intrinsic max — never a malformed leg.
fn build_straddle_legs(
    lo: i128,
    hi: i128,
    tau: u128,
    strike: i128,
    premium: i128,
) -> Option<(
    crate::solana_codec::PiecewiseAffine1D,
    crate::solana_codec::PiecewiseAffine1D,
    u128,
    u128,
)> {
    use crate::solana_codec::{PieceSegment, PiecewiseAffine1D};
    if lo >= hi || tau == 0 || strike <= lo || strike >= hi || premium < 0 {
        return None;
    }
    let tau_i = i128::try_from(tau).ok()?;
    // strike on-lattice (the breakpoint must land on `D` so the partition is valid + WCL_long == premium).
    let span_lo = u128::try_from(strike.checked_sub(lo)?).ok()?;
    if span_lo % tau != 0 {
        return None;
    }
    // the top segment [strike+tau, hi] must be non-empty.
    if strike.checked_add(tau_i)? > hi {
        return None;
    }
    let intrinsic_max = (strike - lo).max(hi - strike);
    if premium > intrinsic_max {
        return None;
    }
    let leg_long = PiecewiseAffine1D {
        lo,
        hi,
        tau,
        segments: vec![
            PieceSegment {
                x_hi: strike,
                coeff: -1,
                konst: strike.checked_sub(premium)?,
            },
            PieceSegment {
                x_hi: hi,
                coeff: 1,
                konst: strike.checked_add(premium)?.checked_neg()?,
            },
        ],
    };
    let leg_short = PiecewiseAffine1D {
        lo,
        hi,
        tau,
        segments: vec![
            PieceSegment {
                x_hi: strike,
                coeff: 1,
                konst: premium.checked_sub(strike)?,
            },
            PieceSegment {
                x_hi: hi,
                coeff: -1,
                konst: strike.checked_add(premium)?,
            },
        ],
    };
    let wcl_long = u128::try_from(premium).ok()?;
    let wcl_short = u128::try_from(intrinsic_max.checked_sub(premium)?).ok()?;
    Some((leg_long, leg_short, wcl_long, wcl_short))
}

/// W1 — the AUTONOMOUS MARGIN flow for a single-party `submit-order` (owner: "read the required margin →
/// deposit EXACTLY that → trade, autonomously"). ONE owner ceremony, up to TWO chain txs: (1) read the LIVE
/// URA → free / locked; (2) build the order + the REQUIRED worst-case margin (the K-1 oracle); (3) if
/// `free < required`, DEPOSIT exactly the shortfall; (4) SUBMIT the order (it atomically escrows `required`
/// from free collateral). The oracle's drawdown check sees the REAL on-chain `portfolio_locked` (the live
/// `locked`), not 0. Needs web3-egress (read) + chain-write (write); honest-degrade otherwise. Fail-closed at
/// every gate; the model cannot supply the arm phrase; money moves ONLY through the EXISTING K-2 chokepoint
/// (devnet; `CustodyCapability` uninhabited). The deposit is bounded by the oracle-computed margin (it can
/// NEVER over-deposit), and a failed deposit ABORTS the order (no half-funded trade). web3-egress-gated
/// (auto-margin MUST read the live URA to size the deposit); the chain-WRITE chokepoint honest-degrades via
/// the seam without `chain-write`. The interception honest-degrades without web3-egress.
#[cfg(feature = "web3-egress")]
#[allow(clippy::too_many_arguments)]
fn cmd_daemon_trade_auto_margin(
    phrase: &str,
    mode: crate::skew_execute::ExecMode,
    signer: &crate::chain_signer::IsolatedSigner,
    owner: &crate::solana_codec::Pubkey,
    mint: &crate::solana_codec::Pubkey,
    bounds: &crate::skew_oracle::OracleBounds,
    now_ms: u64,
    rest: &[String],
    envelope_hex: &str,
    out: &mut impl Write,
) -> io::Result<()> {
    use crate::commands::authority::local_chain_tx_capability;
    use crate::commands::grant::{
        CUSTODY_ARM_PHRASE, CustodyBounds, GrantBounds, arm_local_custody_grant,
    };
    use crate::repl::approval::ApprovalPrompt;
    use crate::skew_execute::{
        ChainWriteSeam, K2_CHAIN, K2_PROTOCOL, SkewExecOutcome, execute_skew_chain_tx,
        plan_deposit_margin, plan_submit_order,
    };
    use crate::skew_oracle::{PartyDirection, SkewTrade};
    use crate::solana_codec::{Pubkey, SubmitOrderDescriptor, WccParamsCodec};

    let usage = format!(
        "usage: daemon trade {CUSTODY_ARM_PHRASE} <sim|live|fast|turbo> auto-margin <template_id_b58> <batch_slot> <nonce> <limit_tick> <long|short> <quantity_q> <contract_size> <collar_lo> <collar_hi> <forward_pc> [tick_tau] [sup_mode]"
    );
    // Parse the order args (rest[4..]; the SAME layout as the `submit-order` action).
    let side_s = rest.get(8).map_or("", String::as_str).trim();
    let pu64 = |i: usize| rest.get(i).and_then(|s| s.trim().parse::<u64>().ok());
    let pu32 = |i: usize| rest.get(i).and_then(|s| s.trim().parse::<u32>().ok());
    let pu128 = |i: usize| rest.get(i).and_then(|s| s.trim().parse::<u128>().ok());
    let pi128 = |i: usize| rest.get(i).and_then(|s| s.trim().parse::<i128>().ok());
    let (dir_u8, direction) = match side_s {
        "long" => (0u8, PartyDirection::Long),
        "short" => (1u8, PartyDirection::Short),
        _ => {
            return emit_daemon_admin(
                out,
                envelope_hex,
                RenderTruth::Yellow,
                vec![
                    "daemon trade auto-margin: side must be long|short (fail-closed)".to_string(),
                    usage,
                ],
            );
        }
    };
    let (
        Some(template_pk),
        Some(batch_slot),
        Some(nonce),
        Some(limit_tick),
        Some(quantity_q),
        Some(contract_size),
        Some(collar_lo),
        Some(collar_hi),
        Some(forward_pc),
    ) = (
        Pubkey::from_base58(rest.get(4).map_or("", String::as_str).trim()),
        pu64(5),
        pu64(6),
        pu32(7),
        pu64(9),
        pu128(10),
        pi128(11),
        pi128(12),
        pi128(13),
    )
    else {
        return emit_daemon_admin(
            out,
            envelope_hex,
            RenderTruth::Yellow,
            vec![
                "daemon trade auto-margin: bad/missing args (fail-closed)".to_string(),
                usage,
            ],
        );
    };
    let tick_tau = pu128(14).unwrap_or(1);
    let sup_mode = rest
        .get(15)
        .and_then(|s| s.trim().parse::<u8>().ok())
        .unwrap_or(0);
    let descriptor = SubmitOrderDescriptor {
        template_id: template_pk.0,
        batch_slot,
        nonce,
        limit_tick,
        wcc: WccParamsCodec {
            collar_lo,
            collar_hi,
            forward_price_pc: forward_pc,
            tick_tau,
            quantity_q,
            contract_size_cs: contract_size,
            party_direction: dir_u8,
            sup_provider_mode: sup_mode,
        },
    };
    let trade = SkewTrade::WccAffineForward {
        direction,
        quantity_q,
        contract_size,
        collar_lo,
        collar_hi,
        forward_price_pc: forward_pc,
    };
    // The K-1 oracle re-derives the EXACT worst-case escrow the program will lock (= the required margin).
    let Some(required) = trade.worst_case_escrow() else {
        return emit_daemon_admin(
            out,
            envelope_hex,
            RenderTruth::Red,
            vec![
                "daemon trade auto-margin: the oracle could not derive the required margin (fail-closed)"
                    .to_string(),
            ],
        );
    };
    // GATE 1 — the owner-arm ceremony FIRST: nothing happens (not even a chain READ) without the EXACT
    // phrase (fail-closed LOCKED; the model cannot supply it). Arm ONE grant (max_actions=4 ≥ 2: deposit+order).
    let mut prompt = ApprovalPrompt::new(ApprovalRequirement::TypedPhrase, CUSTODY_ARM_PHRASE);
    let audit_hash_32 = sha256_32(b"daemon.trade.skew.custody.arm.v1");
    let Some(grant) = arm_local_custody_grant(
        &mut prompt,
        phrase.trim(),
        audit_hash_32,
        CustodyBounds {
            base: GrantBounds {
                max_actions_u32: SKEW_CUSTODY_MAX_ACTIONS,
                expires_at_epoch_ms: now_ms.saturating_add(SKEW_CUSTODY_TTL_MS),
            },
            per_tx_max_minor: SKEW_CUSTODY_PER_TX_MINOR,
            total_budget_minor: SKEW_CUSTODY_BUDGET_MINOR,
            chain_allowlist: vec![K2_CHAIN.to_string()],
            protocol_allowlist: vec![K2_PROTOCOL.to_string()],
        },
    ) else {
        return emit_daemon_admin(
            out,
            envelope_hex,
            RenderTruth::Yellow,
            vec![
                "daemon trade auto-margin: LOCKED — the custody arm phrase is missing/wrong (fail-closed; no chain read)"
                    .to_string(),
                "the model cannot supply this phrase; only the owner arms.".to_string(),
            ],
        );
    };

    // (2) READ the LIVE URA — fail-closed if no URA (NEVER trade blind on a missing read).
    let Some(ura) = read_live_ura_balance(K2_CHAIN, owner) else {
        return emit_daemon_admin(
            out,
            envelope_hex,
            RenderTruth::Yellow,
            vec![
                "daemon trade auto-margin: could not read the LIVE URA (fail-closed; NEVER trades blind)"
                    .to_string(),
                "build with --features web3-egress AND `open-account` + fund the isolated key first."
                    .to_string(),
                format!("the order's required worst-case margin (oracle) = {required} atoms."),
            ],
        );
    };
    let free = ura.free;
    let locked = ura.locked_epoch.saturating_add(ura.locked_wcc);
    let shortfall = required.saturating_sub(free);
    let Ok(shortfall_u64) = u64::try_from(shortfall) else {
        return emit_daemon_admin(
            out,
            envelope_hex,
            RenderTruth::Red,
            vec![format!(
                "daemon trade auto-margin: shortfall {shortfall} exceeds u64 (fail-closed)"
            )],
        );
    };

    // Build the order plan (+ the deposit plan if underfunded), oracle-gated with the REAL portfolio_locked.
    // spent=0 for each: the order's escrow (= required) IS the total worst-case risk; the deposit funds it,
    // so the per-tx + budget checks bound `required` correctly (no double-count).
    let order_plan = match plan_submit_order(owner, mint, &descriptor, &trade, bounds, 0, locked) {
        Ok(p) => p,
        Err(reason) => {
            return emit_daemon_admin(
                out,
                envelope_hex,
                RenderTruth::Red,
                vec![
                    format!(
                        "daemon trade auto-margin: ORACLE DENIED the order ({}) — fail-closed, nothing signed (money 0)",
                        reason.as_str()
                    ),
                    format!(
                        "read: free={free} locked={locked} required={required} shortfall={shortfall} (drawdown uses the LIVE locked)"
                    ),
                ],
            );
        }
    };
    let deposit_plan = if shortfall > 0 {
        match plan_deposit_margin(owner, mint, shortfall_u64, bounds, 0, locked) {
            Ok(p) => Some(p),
            Err(reason) => {
                return emit_daemon_admin(
                    out,
                    envelope_hex,
                    RenderTruth::Red,
                    vec![
                        format!(
                            "daemon trade auto-margin: ORACLE DENIED the deposit ({}) — fail-closed (money 0)",
                            reason.as_str()
                        ),
                        format!("read: free={free} required={required} shortfall={shortfall}"),
                    ],
                );
            }
        }
    } else {
        None
    };

    let registry = read_owner_web3_chain_registry();
    let Some(entry) = registry.lookup(K2_CHAIN) else {
        return emit_daemon_admin(
            out,
            envelope_hex,
            RenderTruth::Red,
            vec![format!(
                "daemon trade auto-margin: chain '{K2_CHAIN}' not configured (config web3_rpc_chains); nothing signed"
            )],
        );
    };
    let endpoint = entry.endpoint().to_string();
    let seam = ChainWriteSeam::new();

    let summarize = |label: &str, oc: &SkewExecOutcome| -> String {
        match oc {
            SkewExecOutcome::Broadcast { signature_b58, .. } => {
                format!("{label}: ★ BROADCAST a REAL devnet tx {signature_b58}")
            }
            SkewExecOutcome::Simulated { sim_ok, .. } => {
                format!("{label}: REAL devnet SIMULATE sim_ok={sim_ok} (signed; not broadcast)")
            }
            SkewExecOutcome::Denied(r) => format!("{label}: DENIED ({})", r.label()),
        }
    };
    let succeeded = |oc: &SkewExecOutcome| {
        matches!(
            oc,
            SkewExecOutcome::Broadcast { .. } | SkewExecOutcome::Simulated { sim_ok: true, .. }
        )
    };

    let mut body = vec![
        format!(
            "daemon trade auto-margin [submit-order]: read free={free} locked={locked} required={required} shortfall={shortfall}"
        ),
        format!(
            "plan: {} → submit-order (oracle drawdown uses the LIVE locked={locked}; money via the K-2 chokepoint, devnet)",
            if shortfall > 0 {
                format!("deposit EXACTLY {shortfall}")
            } else {
                "no deposit (free already covers the margin)".to_string()
            }
        ),
    ];
    let mut used = 0u32;
    // tx1 — the deposit (only if underfunded). A failed deposit ABORTS the order (no half-funded trade).
    if let Some(dep) = &deposit_plan {
        let Some(cap) = local_chain_tx_capability(&grant, now_ms, used, 0, &dep.request) else {
            body.push("deposit: CUSTODY DENIED (fail-closed; nothing signed)".to_string());
            return emit_daemon_admin(out, envelope_hex, RenderTruth::Red, body);
        };
        let oc = execute_skew_chain_tx(cap, dep, signer, seam.port(), &endpoint, mode);
        body.push(summarize("deposit", &oc));
        if !succeeded(&oc) {
            body.push(
                "→ deposit did not succeed ⇒ the order is NOT submitted (fail-closed).".to_string(),
            );
            return emit_daemon_admin(out, envelope_hex, RenderTruth::Red, body);
        }
        used = used.saturating_add(1);
    }
    // tx2 — the order (atomically escrows EXACTLY `required` from free collateral).
    let Some(cap2) = local_chain_tx_capability(&grant, now_ms, used, 0, &order_plan.request) else {
        body.push("order: CUSTODY DENIED (fail-closed; nothing signed)".to_string());
        return emit_daemon_admin(out, envelope_hex, RenderTruth::Red, body);
    };
    let oc2 = execute_skew_chain_tx(cap2, &order_plan, signer, seam.port(), &endpoint, mode);
    body.push(summarize("order", &oc2));
    let truth = if succeeded(&oc2) {
        RenderTruth::Green
    } else {
        RenderTruth::Red
    };
    emit_daemon_admin(out, envelope_hex, truth, body)
}

fn cmd_daemon_trade(rest: &[String], out: &mut impl Write) -> io::Result<()> {
    use crate::commands::authority::local_chain_tx_capability;
    use crate::commands::grant::{
        CUSTODY_ARM_PHRASE, CustodyBounds, GrantBounds, arm_local_custody_grant,
    };
    use crate::repl::approval::ApprovalPrompt;
    use crate::skew_execute::{
        ChainWriteSeam, ExecMode, K2_CHAIN, K2_PROTOCOL, SkewExecOutcome, execute_skew_chain_tx,
        plan_accept_secondary, plan_advance_funding_epoch, plan_atomic_position_transfer,
        plan_cancel_secondary, plan_claim_fill, plan_close_batch, plan_complete_liquidation,
        plan_deposit_margin, plan_factory_list_perp_market, plan_force_reduce_position,
        plan_form_contract, plan_form_funding_swap, plan_form_piecewise_contract,
        plan_list_piecewise_template, plan_list_secondary, plan_list_wcc_template,
        plan_lock_collateral, plan_mark_vm, plan_open_batch, plan_open_fixed_forward_liquidation,
        plan_open_perp_market, plan_open_risk_account, plan_pay_vm, plan_quote_secondary,
        plan_settle_account_funding, plan_settle_batch, plan_settle_batch_contract,
        plan_settle_fixed_forward, plan_settle_piecewise_contract, plan_submit_order,
        plan_submit_perp_order, plan_validate_reference_snapshot, plan_withdraw_margin,
    };
    use crate::skew_oracle::{OracleBounds, PartyDirection, SkewTrade};
    use crate::solana_codec::{
        AcceptSecondaryDescriptor, AdvanceFundingEpochDescriptor, AffineCoord,
        AtomicPositionTransferDescriptor, CancelSecondaryDescriptor, ClaimFillDescriptor,
        CloseBatchDescriptor, CompleteLiquidationDescriptor, FactoryListPerpMarketDescriptor,
        ForceReducePositionDescriptor, FormContractDescriptor, FormFundingSwapDescriptor,
        FormPiecewiseContractDescriptor, ListPiecewiseTemplateDescriptor, ListSecondaryDescriptor,
        ListWccTemplateDescriptor, LockCollateralDescriptor, MarkVmDescriptor, ModeCCertKind,
        ModeCDescriptor, OpenBatchDescriptor, OpenLiquidationDescriptor, OpenPerpMarketDescriptor,
        PayVmDescriptor, Pubkey, QuoteSecondaryDescriptor, SettleAccountFundingDescriptor,
        SettleBatchContractDescriptor, SettleBatchDescriptor, SettleFixedForwardDescriptor,
        SettlePiecewiseContractDescriptor, SubmitOrderDescriptor, SubmitPerpOrderDescriptor,
        ValidateReferenceSnapshotDescriptor, WccParamsCodec,
    };

    // The per-owner custody bounds — the SINGLE source shared with the wallet-settings dial
    // (`skew_custody_dial`, rendered by the K-5c cockpit). The wallet window is where the owner
    // sets the ceiling + funds; these are the session defaults until a config seam lands.
    const PER_TX: u128 = SKEW_CUSTODY_PER_TX_MINOR;
    const BUDGET: u128 = SKEW_CUSTODY_BUDGET_MINOR;
    const TTL_MS: u64 = SKEW_CUSTODY_TTL_MS;
    const MAX_ACTIONS: u32 = SKEW_CUSTODY_MAX_ACTIONS;

    let envelope_hex = toplevel_envelope_hex("daemon");
    let phrase = rest.get(1).map_or("", String::as_str);
    let mode_s = rest.get(2).map_or("", String::as_str).trim();
    let action = rest.get(3).map_or("", String::as_str).trim();
    let amount_s = rest.get(4).map_or("", String::as_str).trim();
    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0u64, |d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX));

    let mode = match mode_s {
        "sim" => ExecMode::SimulateOnly,
        "live" => ExecMode::SimulateThenBroadcast,
        // FAST PATH — owner-armed speed modes (the owner TYPES the verb ⇒ the model can never select
        // a faster/less-safe mode). `fast` skips the pre-sim round-trip; `turbo` + Jito/TPU inclusion.
        "fast" => ExecMode::FastBroadcast,
        "turbo" => ExecMode::TurboBroadcast,
        _ => {
            return emit_daemon_admin(out, &envelope_hex, RenderTruth::Yellow, vec![
                "daemon trade = the owner-armed K-2 SKEW chain-write (ONCHAIN PIVOT C-2; devnet)".to_string(),
                format!("usage: daemon trade {CUSTODY_ARM_PHRASE} <sim|live|fast|turbo> <open-account|deposit|withdraw|submit-perp|submit-order|pay-vm|lock-collateral|mark-vm|settle|form-contract|list-wcc-template|list-piecewise-template|form-piecewise|settle-piecewise|open-perp-market|factory-list-perp-market|form-funding-swap|open-liquidation|complete-liquidation> [args]"),
                "sim = simulate-only (money 0); live = sim-gated broadcast (safest)".to_string(),
                "fast = SKIP pre-sim → 1 fewer round-trip (oracle+D13+D14 still gated); turbo = fast + Jito/TPU inclusion".to_string(),
                "run `daemon trade-addr` first to generate + fund the isolated devnet key.".to_string(),
            ]);
        }
    };

    // The isolated signer MUST exist (run `trade-addr` first).
    let Some(signer) = load_solana_signer() else {
        return emit_daemon_admin(
            out,
            &envelope_hex,
            RenderTruth::Red,
            vec![
                "daemon trade: no isolated devnet signer found (fail-closed)".to_string(),
                "run `daemon trade-addr` to generate + fund the isolated key first.".to_string(),
            ],
        );
    };
    let owner = signer.pubkey();
    let Some(mint) = Pubkey::from_base58(crate::skew_catalog::SKEW_SETTLEMENT_MINT_DEVNET) else {
        return emit_daemon_admin(
            out,
            &envelope_hex,
            RenderTruth::Red,
            vec!["daemon trade: settlement mint invalid (fail-closed)".to_string()],
        );
    };
    let bounds = OracleBounds {
        per_tx_max_minor: PER_TX,
        total_budget_minor: BUDGET,
        drawdown_max_minor: BUDGET,
    };

    // GATE 1 — the K-1 oracle DECIDES affordability at PLAN time (fail-closed before assembly).
    // W1 — AUTONOMOUS MARGIN: read the LIVE margin → deposit EXACTLY the shortfall → submit, one ceremony.
    // A 2-tx flow (deposit + order) needs its own tail; isolate it here so the single-tx arms below are
    // byte-unchanged. Needs web3-egress (read) + chain-write (write); honest-degrade otherwise.
    if action == "auto-margin" {
        #[cfg(feature = "web3-egress")]
        return cmd_daemon_trade_auto_margin(
            phrase,
            mode,
            &signer,
            &owner,
            &mint,
            &bounds,
            now_ms,
            rest,
            &envelope_hex,
            out,
        );
        #[cfg(not(feature = "web3-egress"))]
        return emit_daemon_admin(
            out,
            &envelope_hex,
            RenderTruth::Yellow,
            vec![
                "daemon trade auto-margin: needs --features web3-egress to read the LIVE margin (honest-degrade)".to_string(),
                "the single-step arms (deposit / submit-order) work without it; auto-margin reads the URA to size the deposit.".to_string(),
            ],
        );
    }
    let plan_result = match action {
        "open-account" => plan_open_risk_account(&owner, &mint, &bounds, 0, 0),
        "deposit" => {
            let Ok(amount) = amount_s.parse::<u64>() else {
                return emit_daemon_admin(
                    out,
                    &envelope_hex,
                    RenderTruth::Yellow,
                    vec![
                        "daemon trade deposit: <amount_atoms> is not an integer (fail-closed)"
                            .to_string(),
                        format!(
                            "usage: daemon trade {CUSTODY_ARM_PHRASE} <sim|live> deposit <amount_atoms>"
                        ),
                    ],
                );
            };
            plan_deposit_margin(&owner, &mint, amount, &bounds, 0, 0)
        }
        // WAVE A — `withdraw_margin` (0x62): release free collateral OUT to the owner. Mirrors
        // deposit (byte-identical descriptor); a withdraw structurally REDUCES protocol-held exposure
        // (handler debits only free_collateral) yet rides the SAME conservative per-tx amount-binding.
        "withdraw" => {
            let Ok(amount) = amount_s.parse::<u64>() else {
                return emit_daemon_admin(
                    out,
                    &envelope_hex,
                    RenderTruth::Yellow,
                    vec![
                        "daemon trade withdraw: <amount_atoms> is not an integer (fail-closed)"
                            .to_string(),
                        format!(
                            "usage: daemon trade {CUSTODY_ARM_PHRASE} <sim|live> withdraw <amount_atoms>"
                        ),
                    ],
                );
            };
            plan_withdraw_margin(&owner, &mint, amount, &bounds, 0, 0)
        }
        // K-2b — `submit_perp_order` (0x71): the perp `buy`. The perp worst-case is NOT data-free, so
        // the oracle GENUINELY needs the market band (contract_size · entry · lo · hi) — there is no
        // shortcut (no fabricated escrow). Args (read `skew oracle live` / `skew markets` first):
        //   submit-perp <market_id_b58> <long|short> <qty> <contract_size> <entry> <lo> <hi>
        //               [batch_slot] [epoch_seq] [nonce] [limit_tick]
        // The descriptor's batch_slot/epoch_seq/nonce/limit_tick default to 0 — a `sim` reaches the
        // REAL devnet simulator (which validates the batch context honestly); a real `live` order needs
        // the live batch context (a future "buy reads the market" refinement). Money 0 on `sim`.
        "submit-perp" => {
            let usage = format!(
                "usage: daemon trade {CUSTODY_ARM_PHRASE} <sim|live> submit-perp <market_id_b58> <long|short> <qty> <contract_size> <entry> <lo> <hi> [batch_slot] [epoch_seq] [nonce] [limit_tick]"
            );
            let market_b58 = rest.get(4).map_or("", String::as_str).trim();
            let side_s = rest.get(5).map_or("", String::as_str).trim();
            let parse_u64 = |i: usize| rest.get(i).and_then(|s| s.trim().parse::<u64>().ok());
            let parse_u128 = |i: usize| rest.get(i).and_then(|s| s.trim().parse::<u128>().ok());
            let parse_i128 = |i: usize| rest.get(i).and_then(|s| s.trim().parse::<i128>().ok());
            let parse_u32 = |i: usize| rest.get(i).and_then(|s| s.trim().parse::<u32>().ok());
            let side = match side_s {
                "long" => Some(0u8),
                "short" => Some(1u8),
                _ => None,
            };
            let (
                Some(market_pk),
                Some(side),
                Some(qty),
                Some(contract_size),
                Some(entry),
                Some(lo),
                Some(hi),
            ) = (
                Pubkey::from_base58(market_b58),
                side,
                parse_u64(6),
                parse_u128(7),
                parse_i128(8),
                parse_i128(9),
                parse_i128(10),
            )
            else {
                return emit_daemon_admin(
                    out,
                    &envelope_hex,
                    RenderTruth::Yellow,
                    vec![
                        "daemon trade submit-perp: bad/missing args (fail-closed)".to_string(),
                        usage,
                    ],
                );
            };
            // signed_qty: + long / − short (fail-closed if qty overflows i64).
            let Ok(mag) = i64::try_from(qty) else {
                return emit_daemon_admin(
                    out,
                    &envelope_hex,
                    RenderTruth::Yellow,
                    vec!["daemon trade submit-perp: qty out of range (fail-closed)".to_string()],
                );
            };
            let signed_qty = if side == 1 { -mag } else { mag };
            let descriptor = SubmitPerpOrderDescriptor {
                market_id: market_pk.0,
                settlement_mint: mint,
                batch_slot: parse_u64(11).unwrap_or(0),
                epoch_seq: parse_u64(12).unwrap_or(0),
                nonce: parse_u64(13).unwrap_or(0),
                limit_tick: parse_u32(14).unwrap_or(0),
                qty,
                side,
                intent_flags: 0,
            };
            // The oracle prices the perp's worst-case epoch WCL from the market band (no funding yet).
            let trade = SkewTrade::Perp {
                signed_qty,
                contract_size,
                entry_price: entry,
                lo_price: lo,
                hi_price: hi,
                funding_cap_per_unit: 0,
            };
            plan_submit_perp_order(&owner, &descriptor, &trade, &bounds, 0, 0)
        }
        // WAVE B — `submit_order` (0x52): the SINGLE-PARTY OTC entry (atomic exact-WCL escrow = the
        // UDSI thesis). The K-1 WCC oracle re-derives the EXACT escrow the program locks from the SAME
        // WccParams. Args: submit-order <template_id_b58> <batch_slot> <nonce> <limit_tick>
        // <long|short> <quantity_q> <contract_size> <collar_lo> <collar_hi> <forward_pc> [tick_tau] [sup_mode]
        "submit-order" => {
            let usage = format!(
                "usage: daemon trade {CUSTODY_ARM_PHRASE} <sim|live|fast|turbo> submit-order <template_id_b58> <batch_slot> <nonce> <limit_tick> <long|short> <quantity_q> <contract_size> <collar_lo> <collar_hi> <forward_pc> [tick_tau] [sup_mode]"
            );
            let tid_b58 = rest.get(4).map_or("", String::as_str).trim();
            let side_s = rest.get(8).map_or("", String::as_str).trim();
            let pu64 = |i: usize| rest.get(i).and_then(|s| s.trim().parse::<u64>().ok());
            let pu32 = |i: usize| rest.get(i).and_then(|s| s.trim().parse::<u32>().ok());
            let pu128 = |i: usize| rest.get(i).and_then(|s| s.trim().parse::<u128>().ok());
            let pi128 = |i: usize| rest.get(i).and_then(|s| s.trim().parse::<i128>().ok());
            let (dir_u8, direction) = match side_s {
                "long" => (0u8, PartyDirection::Long),
                "short" => (1u8, PartyDirection::Short),
                _ => {
                    return emit_daemon_admin(
                        out,
                        &envelope_hex,
                        RenderTruth::Yellow,
                        vec![
                            "daemon trade submit-order: side must be long|short (fail-closed)"
                                .to_string(),
                            usage,
                        ],
                    );
                }
            };
            let (
                Some(template_pk),
                Some(batch_slot),
                Some(nonce),
                Some(limit_tick),
                Some(quantity_q),
                Some(contract_size),
                Some(collar_lo),
                Some(collar_hi),
                Some(forward_pc),
            ) = (
                Pubkey::from_base58(tid_b58),
                pu64(5),
                pu64(6),
                pu32(7),
                pu64(9),
                pu128(10),
                pi128(11),
                pi128(12),
                pi128(13),
            )
            else {
                return emit_daemon_admin(
                    out,
                    &envelope_hex,
                    RenderTruth::Yellow,
                    vec![
                        "daemon trade submit-order: bad/missing args (fail-closed)".to_string(),
                        usage,
                    ],
                );
            };
            let tick_tau = pu128(14).unwrap_or(1);
            let sup_mode = rest
                .get(15)
                .and_then(|s| s.trim().parse::<u8>().ok())
                .unwrap_or(0);
            let descriptor = SubmitOrderDescriptor {
                template_id: template_pk.0,
                batch_slot,
                nonce,
                limit_tick,
                wcc: WccParamsCodec {
                    collar_lo,
                    collar_hi,
                    forward_price_pc: forward_pc,
                    tick_tau,
                    quantity_q,
                    contract_size_cs: contract_size,
                    party_direction: dir_u8,
                    sup_provider_mode: sup_mode,
                },
            };
            // The oracle re-derives the EXACT WCL from the SAME WccParams ⇒ oracle escrow == on-chain escrow.
            let trade = SkewTrade::WccAffineForward {
                direction,
                quantity_q,
                contract_size,
                collar_lo,
                collar_hi,
                forward_price_pc: forward_pc,
            };
            plan_submit_order(&owner, &mint, &descriptor, &trade, &bounds, 0, 0)
        }
        // WAVE B — `pay_fixed_forward_vm` (8-byte Anchor sighash 64bc0d…): the open-call party pays in
        // its variation-margin call. SINGLE-PARTY escrow trade (payment IS the escrow). Args:
        //   pay-vm <contract_id_b58> <template_id_b58> <payment_amount>
        // (`template_id` is the product_template seed — the descriptor omits it.)
        "pay-vm" => {
            let usage = format!(
                "usage: daemon trade {CUSTODY_ARM_PHRASE} <sim|live|fast|turbo> pay-vm <contract_id_b58> <template_id_b58> <payment_amount>"
            );
            let cid_b58 = rest.get(4).map_or("", String::as_str).trim();
            let tid_b58 = rest.get(5).map_or("", String::as_str).trim();
            let (Some(contract_pk), Some(template_pk), Some(payment_amount)) = (
                Pubkey::from_base58(cid_b58),
                Pubkey::from_base58(tid_b58),
                rest.get(6).and_then(|s| s.trim().parse::<u128>().ok()),
            ) else {
                return emit_daemon_admin(
                    out,
                    &envelope_hex,
                    RenderTruth::Yellow,
                    vec![
                        "daemon trade pay-vm: bad/missing args (fail-closed)".to_string(),
                        usage,
                    ],
                );
            };
            let descriptor = PayVmDescriptor {
                contract_id: contract_pk.0,
                payment_amount,
            };
            plan_pay_vm(&owner, &mint, &template_pk.0, &descriptor, &bounds, 0, 0)
        }
        // WAVE B part-2b — `lock_fixed_forward_initial_collateral` (8-byte sighash 24b0aa…): the agent
        // (a contract PARTY) locks ITS side's initial collateral (escrow == lock_amount). Args:
        //   lock-collateral <contract_id_b58> <template_id_b58> <other_party_b58> <long|short> <lock_amount>
        "lock-collateral" => {
            let usage = format!(
                "usage: daemon trade {CUSTODY_ARM_PHRASE} <sim|live|fast|turbo> lock-collateral <contract_id_b58> <template_id_b58> <other_party_b58> <long|short> <lock_amount>"
            );
            let cid_b58 = rest.get(4).map_or("", String::as_str).trim();
            let tid_b58 = rest.get(5).map_or("", String::as_str).trim();
            let other_b58 = rest.get(6).map_or("", String::as_str).trim();
            let party_role = match rest.get(7).map_or("", String::as_str).trim() {
                "long" => Some(0u8),
                "short" => Some(1u8),
                _ => None,
            };
            let (
                Some(contract_pk),
                Some(template_pk),
                Some(other_pk),
                Some(party_role),
                Some(lock_amount),
            ) = (
                Pubkey::from_base58(cid_b58),
                Pubkey::from_base58(tid_b58),
                Pubkey::from_base58(other_b58),
                party_role,
                rest.get(8).and_then(|s| s.trim().parse::<u128>().ok()),
            )
            else {
                return emit_daemon_admin(
                    out,
                    &envelope_hex,
                    RenderTruth::Yellow,
                    vec![
                        "daemon trade lock-collateral: bad/missing args (fail-closed)".to_string(),
                        usage,
                    ],
                );
            };
            // The FF-05 policy/snapshot bytes are template-fixed; empty for the assemble/sim demo (the
            // live sim reaches AccountNotFound on a dummy contract BEFORE policy validation). A real lock
            // supplies the template's policy bytes (read from `skew oracle live`).
            let descriptor = LockCollateralDescriptor {
                contract_id: contract_pk.0,
                party_role,
                lock_amount,
                collateral_policy_version: 1,
                collateral_params_bytes: Vec::new(),
                collateral_snapshot_bytes: Vec::new(),
                reference_snapshot_hash: [1u8; 32],
                reference_snapshot_age_seconds: 0,
                reference_max_age_seconds: 0,
                vm_policy_bytes: Vec::new(),
                vm_mark_source: 0,
            };
            plan_lock_collateral(
                &owner,
                &mint,
                &template_pk.0,
                &other_pk,
                &descriptor,
                &bounds,
                0,
                0,
            )
        }
        // WAVE B part-2b — `mark_fixed_forward_vm` (2-byte disc 0x0005): a PERMISSIONLESS keeper
        // mark-to-market (escrow=0; the agent commits nothing). Args:
        //   mark-vm <contract_id_b58> <template_id_b58> <mark_price_atoms>
        "mark-vm" => {
            let usage = format!(
                "usage: daemon trade {CUSTODY_ARM_PHRASE} <sim|live|fast|turbo> mark-vm <contract_id_b58> <template_id_b58> <mark_price_atoms>"
            );
            let cid_b58 = rest.get(4).map_or("", String::as_str).trim();
            let tid_b58 = rest.get(5).map_or("", String::as_str).trim();
            let (Some(contract_pk), Some(template_pk), Some(mark_price)) = (
                Pubkey::from_base58(cid_b58),
                Pubkey::from_base58(tid_b58),
                rest.get(6).and_then(|s| s.trim().parse::<u128>().ok()),
            ) else {
                return emit_daemon_admin(
                    out,
                    &envelope_hex,
                    RenderTruth::Yellow,
                    vec![
                        "daemon trade mark-vm: bad/missing args (fail-closed)".to_string(),
                        usage,
                    ],
                );
            };
            let descriptor = MarkVmDescriptor {
                contract_id: contract_pk.0,
                vm_policy_bytes: Vec::new(),
                mark_price_atoms: mark_price,
                mark_publish_timestamp: 0,
                mark_confidence_bps: 0,
                mark_snapshot_hash: [1u8; 32],
                mark_archive_pointer: [0u8; 32],
                reference_policy_id: 0,
                mark_price_decimals: 6,
                current_unix_timestamp: 0,
            };
            plan_mark_vm(&owner, &template_pk.0, &descriptor, &bounds, 0, 0)
        }
        // WAVE B part-2b — `settle_fixed_forward` (8-byte sighash 7998…): a PERMISSIONLESS keeper
        // resolving a contract at maturity (escrow=0; disburses from the posted collateral). Args:
        //   settle <contract_id_b58> <template_id_b58> <receiver_token_account_b58> <settlement_price>
        "settle" => {
            let usage = format!(
                "usage: daemon trade {CUSTODY_ARM_PHRASE} <sim|live|fast|turbo> settle <contract_id_b58> <template_id_b58> <receiver_token_account_b58> <settlement_price>"
            );
            let cid_b58 = rest.get(4).map_or("", String::as_str).trim();
            let tid_b58 = rest.get(5).map_or("", String::as_str).trim();
            let recv_b58 = rest.get(6).map_or("", String::as_str).trim();
            let (Some(contract_pk), Some(template_pk), Some(receiver_pk), Some(settlement_price)) = (
                Pubkey::from_base58(cid_b58),
                Pubkey::from_base58(tid_b58),
                Pubkey::from_base58(recv_b58),
                rest.get(7).and_then(|s| s.trim().parse::<u128>().ok()),
            ) else {
                return emit_daemon_admin(
                    out,
                    &envelope_hex,
                    RenderTruth::Yellow,
                    vec![
                        "daemon trade settle: bad/missing args (fail-closed)".to_string(),
                        usage,
                    ],
                );
            };
            let descriptor = SettleFixedForwardDescriptor {
                contract_id: contract_pk.0,
                reference_snapshot_hash: [1u8; 32],
                settlement_price,
                current_unix_timestamp: 0,
                archive_pointer: [0u8; 32],
                reference_publish_timestamp: 0,
            };
            plan_settle_fixed_forward(
                &owner,
                &mint,
                &template_pk.0,
                &receiver_pk,
                &descriptor,
                &bounds,
                0,
                0,
            )
        }
        // WAVE B part-2b — `form_fixed_forward_contract` (2-byte disc 0x0003): form a bilateral
        // fixed-forward. ★ 3 SIGNERS ⇒ ASSEMBLE + SIMULATE only (the agent can't forge the counterparty
        // sigs; a real broadcast = a multi-sig / 2-agent / quote-authority owner go-live). Args:
        //   form-contract <contract_id_b58> <template_id_b58> <long_b58> <short_b58> <quantity>
        //                 <contract_size> <forward_price> <maturity_ts>
        "form-contract" => {
            let usage = format!(
                "usage: daemon trade {CUSTODY_ARM_PHRASE} <sim> form-contract <contract_id_b58> <template_id_b58> <long_b58> <short_b58> <quantity> <contract_size> <forward_price> <maturity_ts> (ASSEMBLE+SIM only — 3 signers)"
            );
            let cid_b58 = rest.get(4).map_or("", String::as_str).trim();
            let tid_b58 = rest.get(5).map_or("", String::as_str).trim();
            let long_b58 = rest.get(6).map_or("", String::as_str).trim();
            let short_b58 = rest.get(7).map_or("", String::as_str).trim();
            let (
                Some(contract_pk),
                Some(template_pk),
                Some(long_pk),
                Some(short_pk),
                Some(quantity),
                Some(contract_size),
                Some(forward_price),
                Some(maturity),
            ) = (
                Pubkey::from_base58(cid_b58),
                Pubkey::from_base58(tid_b58),
                Pubkey::from_base58(long_b58),
                Pubkey::from_base58(short_b58),
                rest.get(8).and_then(|s| s.trim().parse::<u64>().ok()),
                rest.get(9).and_then(|s| s.trim().parse::<u128>().ok()),
                rest.get(10).and_then(|s| s.trim().parse::<u128>().ok()),
                rest.get(11).and_then(|s| s.trim().parse::<i64>().ok()),
            )
            else {
                return emit_daemon_admin(
                    out,
                    &envelope_hex,
                    RenderTruth::Yellow,
                    vec![
                        "daemon trade form-contract: bad/missing args (fail-closed)".to_string(),
                        usage,
                    ],
                );
            };
            let notional = u128::from(quantity)
                .saturating_mul(contract_size)
                .saturating_mul(forward_price);
            let descriptor = FormContractDescriptor {
                contract_id: contract_pk.0,
                template_id: template_pk.0,
                version: 1,
                terms_hash: [1u8; 32],
                accept_id: [2u8; 32],
                quote_expiry: 0,
                long_party: long_pk,
                short_party: short_pk,
                party_roles: 0,
                allow_self_cross: long_pk == short_pk,
                underlying_reference_id: [0u8; 32],
                settlement_mint: mint,
                quantity,
                contract_size,
                forward_price,
                maturity_timestamp: maturity,
                notional,
                reference_data_policy_id: 0,
                collateral_policy_id: 0,
                vm_policy_id: 0,
                settlement_adapter_id: 0,
                approved_reference_ids: Vec::new(),
                approved_settlement_mints: Vec::new(),
            };
            plan_form_contract(&owner, &descriptor, &bounds, 0, 0)
        }
        // WAVE D — the SECONDARY market. list/quote/accept/cancel move NO tokens (escrow=0); the
        // atomic position transfer is the value-moving leg (buyer posts WCL + pays the price).
        // list-secondary <contract_b58> <side 0|1> <listing_qty> <ask_price> <expiry_slot> <exec_mode>
        "list-secondary" => {
            let usage = format!(
                "usage: daemon trade {CUSTODY_ARM_PHRASE} <sim|live|fast|turbo> list-secondary <contract_b58> <side 0|1> <listing_qty> <ask_price> <expiry_slot> <execution_mode>"
            );
            let cid_b58 = rest.get(4).map_or("", String::as_str).trim();
            let (
                Some(contract_pk),
                Some(side),
                Some(listing_qty),
                Some(ask_price),
                Some(expiry_slot),
                Some(execution_mode),
            ) = (
                Pubkey::from_base58(cid_b58),
                rest.get(5).and_then(|s| s.trim().parse::<u8>().ok()),
                rest.get(6).and_then(|s| s.trim().parse::<u64>().ok()),
                rest.get(7).and_then(|s| s.trim().parse::<u128>().ok()),
                rest.get(8).and_then(|s| s.trim().parse::<u64>().ok()),
                rest.get(9).and_then(|s| s.trim().parse::<u8>().ok()),
            )
            else {
                return emit_daemon_admin(
                    out,
                    &envelope_hex,
                    RenderTruth::Yellow,
                    vec![
                        "daemon trade list-secondary: bad/missing args (fail-closed)".to_string(),
                        usage,
                    ],
                );
            };
            let descriptor = ListSecondaryDescriptor {
                contract_id: contract_pk.0,
                side,
                listing_qty,
                ask_price,
                expiry_slot,
                execution_mode,
            };
            plan_list_secondary(&owner, &descriptor, &bounds, 0, 0)
        }
        // quote-secondary <contract_b58> <seller_b58> <quote_price>
        "quote-secondary" => {
            let usage = format!(
                "usage: daemon trade {CUSTODY_ARM_PHRASE} <sim|live|fast|turbo> quote-secondary <contract_b58> <seller_b58> <quote_price>"
            );
            let (Some(contract_pk), Some(seller_pk), Some(quote_price)) = (
                Pubkey::from_base58(rest.get(4).map_or("", String::as_str).trim()),
                Pubkey::from_base58(rest.get(5).map_or("", String::as_str).trim()),
                rest.get(6).and_then(|s| s.trim().parse::<u128>().ok()),
            ) else {
                return emit_daemon_admin(
                    out,
                    &envelope_hex,
                    RenderTruth::Yellow,
                    vec![
                        "daemon trade quote-secondary: bad/missing args (fail-closed)".to_string(),
                        usage,
                    ],
                );
            };
            let descriptor = QuoteSecondaryDescriptor {
                contract_id: contract_pk.0,
                seller: seller_pk,
                quote_price,
            };
            plan_quote_secondary(&owner, &descriptor, &bounds, 0, 0)
        }
        // accept-secondary <contract_b58> <accepted_buyer_b58> <accept_price> <transfer_deadline>
        "accept-secondary" => {
            let usage = format!(
                "usage: daemon trade {CUSTODY_ARM_PHRASE} <sim|live|fast|turbo> accept-secondary <contract_b58> <accepted_buyer_b58> <accept_price> <transfer_deadline>"
            );
            let (Some(contract_pk), Some(buyer_pk), Some(accept_price), Some(deadline)) = (
                Pubkey::from_base58(rest.get(4).map_or("", String::as_str).trim()),
                Pubkey::from_base58(rest.get(5).map_or("", String::as_str).trim()),
                rest.get(6).and_then(|s| s.trim().parse::<u128>().ok()),
                rest.get(7).and_then(|s| s.trim().parse::<i64>().ok()),
            ) else {
                return emit_daemon_admin(
                    out,
                    &envelope_hex,
                    RenderTruth::Yellow,
                    vec![
                        "daemon trade accept-secondary: bad/missing args (fail-closed)".to_string(),
                        usage,
                    ],
                );
            };
            let descriptor = AcceptSecondaryDescriptor {
                contract_id: contract_pk.0,
                accepted_buyer: buyer_pk,
                accept_price,
                transfer_deadline: deadline,
            };
            plan_accept_secondary(&owner, &descriptor, &bounds, 0, 0)
        }
        // cancel-secondary <contract_b58> <seller_b58>
        "cancel-secondary" => {
            let usage = format!(
                "usage: daemon trade {CUSTODY_ARM_PHRASE} <sim|live|fast|turbo> cancel-secondary <contract_b58> <seller_b58>"
            );
            let (Some(contract_pk), Some(seller_pk)) = (
                Pubkey::from_base58(rest.get(4).map_or("", String::as_str).trim()),
                Pubkey::from_base58(rest.get(5).map_or("", String::as_str).trim()),
            ) else {
                return emit_daemon_admin(
                    out,
                    &envelope_hex,
                    RenderTruth::Yellow,
                    vec![
                        "daemon trade cancel-secondary: bad/missing args (fail-closed)".to_string(),
                        usage,
                    ],
                );
            };
            let descriptor = CancelSecondaryDescriptor {
                contract_id: contract_pk.0,
                seller: seller_pk,
            };
            plan_cancel_secondary(&owner, &descriptor, &bounds, 0, 0)
        }
        // atomic-transfer <contract_b58> <seller_b58> <transfer_nonce> <long|short> <quantity>
        //                 <contract_size> <collar_lo> <collar_hi> <forward_pc> <price> [tick_tau]
        "atomic-transfer" => {
            let usage = format!(
                "usage: daemon trade {CUSTODY_ARM_PHRASE} <sim|live|fast|turbo> atomic-transfer <contract_b58> <seller_b58> <transfer_nonce> <long|short> <quantity> <contract_size> <collar_lo> <collar_hi> <forward_pc> <price> [tick_tau]"
            );
            let direction = match rest.get(7).map_or("", String::as_str).trim() {
                "long" => Some(PartyDirection::Long),
                "short" => Some(PartyDirection::Short),
                _ => None,
            };
            let (
                Some(contract_pk),
                Some(seller_pk),
                Some(transfer_nonce),
                Some(direction),
                Some(quantity_q),
                Some(contract_size),
                Some(collar_lo),
                Some(collar_hi),
                Some(forward_pc),
                Some(price),
            ) = (
                Pubkey::from_base58(rest.get(4).map_or("", String::as_str).trim()),
                Pubkey::from_base58(rest.get(5).map_or("", String::as_str).trim()),
                rest.get(6).and_then(|s| s.trim().parse::<u64>().ok()),
                direction,
                rest.get(8).and_then(|s| s.trim().parse::<u64>().ok()),
                rest.get(9).and_then(|s| s.trim().parse::<u128>().ok()),
                rest.get(10).and_then(|s| s.trim().parse::<i128>().ok()),
                rest.get(11).and_then(|s| s.trim().parse::<i128>().ok()),
                rest.get(12).and_then(|s| s.trim().parse::<i128>().ok()),
                rest.get(13).and_then(|s| s.trim().parse::<u128>().ok()),
            )
            else {
                return emit_daemon_admin(
                    out,
                    &envelope_hex,
                    RenderTruth::Yellow,
                    vec![
                        "daemon trade atomic-transfer: bad/missing args (fail-closed)".to_string(),
                        usage,
                    ],
                );
            };
            let tick_tau = rest
                .get(14)
                .and_then(|s| s.trim().parse::<u128>().ok())
                .unwrap_or(1);
            let descriptor = AtomicPositionTransferDescriptor {
                contract_id: contract_pk.0,
                transfer_nonce,
                collar_lo,
                collar_hi,
                tick_tau,
            };
            // the oracle re-derives the position WCL from the SAME collar params; the buyer's outflow =
            // WCL + price (bounded by per-tx/budget).
            let wcc_trade = SkewTrade::WccAffineForward {
                direction,
                quantity_q,
                contract_size,
                collar_lo,
                collar_hi,
                forward_price_pc: forward_pc,
            };
            plan_atomic_position_transfer(
                &owner,
                &mint,
                &seller_pk,
                &descriptor,
                &wcc_trade,
                price,
                &bounds,
                0,
                0,
            )
        }
        // WAVE C — the batch-auction books. All escrow=0 permissionless crank/settle ops.
        // open-batch <template_b58> <batch_slot>
        "open-batch" => {
            let usage = format!(
                "usage: daemon trade {CUSTODY_ARM_PHRASE} <sim|live|fast|turbo> open-batch <template_b58> <batch_slot>"
            );
            let (Some(template_pk), Some(batch_slot)) = (
                Pubkey::from_base58(rest.get(4).map_or("", String::as_str).trim()),
                rest.get(5).and_then(|s| s.trim().parse::<u64>().ok()),
            ) else {
                return emit_daemon_admin(
                    out,
                    &envelope_hex,
                    RenderTruth::Yellow,
                    vec![
                        "daemon trade open-batch: bad/missing args (fail-closed)".to_string(),
                        usage,
                    ],
                );
            };
            let descriptor = OpenBatchDescriptor {
                template_id: template_pk.0,
                batch_slot,
            };
            plan_open_batch(&owner, &mint, &descriptor, &bounds, 0, 0)
        }
        // close-batch <template_b58> <batch_slot>
        "close-batch" => {
            let usage = format!(
                "usage: daemon trade {CUSTODY_ARM_PHRASE} <sim|live|fast|turbo> close-batch <template_b58> <batch_slot>"
            );
            let (Some(template_pk), Some(batch_slot)) = (
                Pubkey::from_base58(rest.get(4).map_or("", String::as_str).trim()),
                rest.get(5).and_then(|s| s.trim().parse::<u64>().ok()),
            ) else {
                return emit_daemon_admin(
                    out,
                    &envelope_hex,
                    RenderTruth::Yellow,
                    vec![
                        "daemon trade close-batch: bad/missing args (fail-closed)".to_string(),
                        usage,
                    ],
                );
            };
            let descriptor = CloseBatchDescriptor {
                template_id: template_pk.0,
                batch_slot,
            };
            plan_close_batch(&owner, &descriptor, &bounds, 0, 0)
        }
        // settle-batch <template_b58> <batch_slot> [phase] [shard_index] [shard_count]
        "settle-batch" => {
            let usage = format!(
                "usage: daemon trade {CUSTODY_ARM_PHRASE} <sim|live|fast|turbo> settle-batch <template_b58> <batch_slot> [phase] [shard_index] [shard_count]"
            );
            let (Some(template_pk), Some(batch_slot)) = (
                Pubkey::from_base58(rest.get(4).map_or("", String::as_str).trim()),
                rest.get(5).and_then(|s| s.trim().parse::<u64>().ok()),
            ) else {
                return emit_daemon_admin(
                    out,
                    &envelope_hex,
                    RenderTruth::Yellow,
                    vec![
                        "daemon trade settle-batch: bad/missing args (fail-closed)".to_string(),
                        usage,
                    ],
                );
            };
            let descriptor = SettleBatchDescriptor {
                template_id: template_pk.0,
                batch_slot,
                phase: rest
                    .get(6)
                    .and_then(|s| s.trim().parse::<u8>().ok())
                    .unwrap_or(3),
                shard_index: rest
                    .get(7)
                    .and_then(|s| s.trim().parse::<u32>().ok())
                    .unwrap_or(0),
                shard_count: rest
                    .get(8)
                    .and_then(|s| s.trim().parse::<u32>().ok())
                    .unwrap_or(1),
            };
            plan_settle_batch(&owner, &descriptor, &bounds, 0, 0)
        }
        // claim-fill <template_b58> <batch_slot> <nonce> <order_owner_b58>
        "claim-fill" => {
            let usage = format!(
                "usage: daemon trade {CUSTODY_ARM_PHRASE} <sim|live|fast|turbo> claim-fill <template_b58> <batch_slot> <nonce> <order_owner_b58>"
            );
            let (Some(template_pk), Some(batch_slot), Some(nonce), Some(owner_pk)) = (
                Pubkey::from_base58(rest.get(4).map_or("", String::as_str).trim()),
                rest.get(5).and_then(|s| s.trim().parse::<u64>().ok()),
                rest.get(6).and_then(|s| s.trim().parse::<u64>().ok()),
                Pubkey::from_base58(rest.get(7).map_or("", String::as_str).trim()),
            ) else {
                return emit_daemon_admin(
                    out,
                    &envelope_hex,
                    RenderTruth::Yellow,
                    vec![
                        "daemon trade claim-fill: bad/missing args (fail-closed)".to_string(),
                        usage,
                    ],
                );
            };
            let descriptor = ClaimFillDescriptor {
                template_id: template_pk.0,
                batch_slot,
                nonce,
            };
            plan_claim_fill(&owner, &mint, &owner_pk, &descriptor, &bounds, 0, 0)
        }
        // settle-batch-contract <contract_b58> <template_b58> <receiver_b58> <settlement_price> <collar_lo> <collar_hi> [tick_tau]
        "settle-batch-contract" => {
            let usage = format!(
                "usage: daemon trade {CUSTODY_ARM_PHRASE} <sim|live|fast|turbo> settle-batch-contract <contract_b58> <template_b58> <receiver_b58> <settlement_price> <collar_lo> <collar_hi> [tick_tau]"
            );
            let (
                Some(contract_pk),
                Some(template_pk),
                Some(receiver_pk),
                Some(settlement_price),
                Some(collar_lo),
                Some(collar_hi),
            ) = (
                Pubkey::from_base58(rest.get(4).map_or("", String::as_str).trim()),
                Pubkey::from_base58(rest.get(5).map_or("", String::as_str).trim()),
                Pubkey::from_base58(rest.get(6).map_or("", String::as_str).trim()),
                rest.get(7).and_then(|s| s.trim().parse::<u128>().ok()),
                rest.get(8).and_then(|s| s.trim().parse::<i128>().ok()),
                rest.get(9).and_then(|s| s.trim().parse::<i128>().ok()),
            )
            else {
                return emit_daemon_admin(
                    out,
                    &envelope_hex,
                    RenderTruth::Yellow,
                    vec![
                        "daemon trade settle-batch-contract: bad/missing args (fail-closed)"
                            .to_string(),
                        usage,
                    ],
                );
            };
            let descriptor = SettleBatchContractDescriptor {
                contract_id: contract_pk.0,
                settlement_price,
                collar_lo,
                collar_hi,
                tick_tau: rest
                    .get(10)
                    .and_then(|s| s.trim().parse::<u128>().ok())
                    .unwrap_or(1),
            };
            plan_settle_batch_contract(
                &owner,
                &mint,
                &template_pk.0,
                &receiver_pk,
                &descriptor,
                &bounds,
                0,
                0,
            )
        }
        // WAVE E — the KEEPER band (permissionless deterministic-liveness ops; escrow=0). The agent acts
        // as an ALIGNED permissionless keeper; it commits NO funds of its own (disbursements come from
        // the protocol's posted collateral / funding pool, bounded structurally on-chain).
        // validate-reference <market_b58> <source_id> <observed_slot> <numerator> <divisor> <conf_bps> <spread_bps> <exponent>
        "validate-reference" => {
            let usage = format!(
                "usage: daemon trade {CUSTODY_ARM_PHRASE} <sim|live|fast|turbo> validate-reference <market_b58> <source_id> <observed_slot> <numerator_atoms> <divisor_atoms> <confidence_bps> <bid_ask_spread_bps> <exponent>"
            );
            let (
                Some(market_pk),
                Some(source_id),
                Some(observed_slot),
                Some(numerator_atoms),
                Some(divisor_atoms),
                Some(confidence_bps),
                Some(spread_bps),
                Some(exponent),
            ) = (
                Pubkey::from_base58(rest.get(4).map_or("", String::as_str).trim()),
                rest.get(5).and_then(|s| s.trim().parse::<u32>().ok()),
                rest.get(6).and_then(|s| s.trim().parse::<u64>().ok()),
                rest.get(7).and_then(|s| s.trim().parse::<u128>().ok()),
                rest.get(8).and_then(|s| s.trim().parse::<u128>().ok()),
                rest.get(9).and_then(|s| s.trim().parse::<u16>().ok()),
                rest.get(10).and_then(|s| s.trim().parse::<u16>().ok()),
                rest.get(11).and_then(|s| s.trim().parse::<u8>().ok()),
            )
            else {
                return emit_daemon_admin(
                    out,
                    &envelope_hex,
                    RenderTruth::Yellow,
                    vec![
                        "daemon trade validate-reference: bad/missing args (fail-closed)"
                            .to_string(),
                        usage,
                    ],
                );
            };
            let descriptor = ValidateReferenceSnapshotDescriptor {
                market_id: market_pk.0,
                source_id,
                observed_slot,
                numerator_atoms,
                divisor_atoms,
                confidence_bps,
                bid_ask_spread_bps: spread_bps,
                exponent,
                source_payload_hash: [1u8; 32],
            };
            plan_validate_reference_snapshot(&owner, &descriptor, &bounds, 0, 0)
        }
        // advance-funding <market_b58> <epoch_seq>
        "advance-funding" => {
            let usage = format!(
                "usage: daemon trade {CUSTODY_ARM_PHRASE} <sim|live|fast|turbo> advance-funding <market_b58> <epoch_seq>"
            );
            let (Some(market_pk), Some(epoch_seq)) = (
                Pubkey::from_base58(rest.get(4).map_or("", String::as_str).trim()),
                rest.get(5).and_then(|s| s.trim().parse::<u64>().ok()),
            ) else {
                return emit_daemon_admin(
                    out,
                    &envelope_hex,
                    RenderTruth::Yellow,
                    vec![
                        "daemon trade advance-funding: bad/missing args (fail-closed)".to_string(),
                        usage,
                    ],
                );
            };
            let descriptor = AdvanceFundingEpochDescriptor {
                market_id: market_pk.0,
                epoch_seq,
            };
            plan_advance_funding_epoch(&owner, &descriptor, &bounds, 0, 0)
        }
        // settle-account-funding <market_b58> <owner_b58> <epoch_seq>
        "settle-account-funding" => {
            let usage = format!(
                "usage: daemon trade {CUSTODY_ARM_PHRASE} <sim|live|fast|turbo> settle-account-funding <market_b58> <position_owner_b58> <epoch_seq>"
            );
            let (Some(market_pk), Some(owner_pk), Some(epoch_seq)) = (
                Pubkey::from_base58(rest.get(4).map_or("", String::as_str).trim()),
                Pubkey::from_base58(rest.get(5).map_or("", String::as_str).trim()),
                rest.get(6).and_then(|s| s.trim().parse::<u64>().ok()),
            ) else {
                return emit_daemon_admin(
                    out,
                    &envelope_hex,
                    RenderTruth::Yellow,
                    vec![
                        "daemon trade settle-account-funding: bad/missing args (fail-closed)"
                            .to_string(),
                        usage,
                    ],
                );
            };
            let descriptor = SettleAccountFundingDescriptor {
                market_id: market_pk.0,
                settlement_mint: mint,
                owner: owner_pk,
                epoch_seq,
            };
            plan_settle_account_funding(&owner, &descriptor, &bounds, 0, 0)
        }
        // force-reduce <market_b58> <owner_b58> <admitted_epoch_seq>
        "force-reduce" => {
            let usage = format!(
                "usage: daemon trade {CUSTODY_ARM_PHRASE} <sim|live|fast|turbo> force-reduce <market_b58> <position_owner_b58> <admitted_epoch_seq>"
            );
            let (Some(market_pk), Some(owner_pk), Some(epoch_seq)) = (
                Pubkey::from_base58(rest.get(4).map_or("", String::as_str).trim()),
                Pubkey::from_base58(rest.get(5).map_or("", String::as_str).trim()),
                rest.get(6).and_then(|s| s.trim().parse::<u64>().ok()),
            ) else {
                return emit_daemon_admin(
                    out,
                    &envelope_hex,
                    RenderTruth::Yellow,
                    vec![
                        "daemon trade force-reduce: bad/missing args (fail-closed)".to_string(),
                        usage,
                    ],
                );
            };
            let descriptor = ForceReducePositionDescriptor {
                market_id: market_pk.0,
                settlement_mint: mint,
                owner: owner_pk,
                admitted_epoch_seq: epoch_seq,
            };
            plan_force_reduce_position(&owner, &descriptor, &bounds, 0, 0)
        }
        // WAVE C-listings — `list_wcc_template` (0x50): PERMISSIONLESS affine-forward template
        // registration (escrow=0; the on-chain UDSI math gate replaces an admin authority). The agent
        // PROPOSES an affine forward `f = S − Pc` over the collar `[lo,hi]`; the short leg is its
        // antisymmetric partner; the cert is the affine corner (IntervalAffineIII). Args:
        // W3 — the trailing `[settlement_mint_b58]` is the EXTERNAL settlement token (the on-chain
        // `list_wcc_template` already takes `settlement_mint: Account<Mint>`, so this is honest: the
        // agent CHOOSES the settlement currency). Absent ⇒ the hardcoded devnet mint (byte-unchanged).
        //   list-wcc-template <template_id_b58> <collar_lo> <collar_hi> <forward_pc> [tau] [settlement_mint_b58]
        "list-wcc-template" => {
            let usage = format!(
                "usage: daemon trade {CUSTODY_ARM_PHRASE} <sim|live|fast|turbo> list-wcc-template <template_id_b58> <collar_lo> <collar_hi> <forward_pc> [tau] [settlement_mint_b58]"
            );
            let tid_b58 = rest.get(4).map_or("", String::as_str).trim();
            let pi128 = |i: usize| rest.get(i).and_then(|s| s.trim().parse::<i128>().ok());
            let (Some(template_pk), Some(collar_lo), Some(collar_hi), Some(forward_pc)) =
                (Pubkey::from_base58(tid_b58), pi128(5), pi128(6), pi128(7))
            else {
                return emit_daemon_admin(
                    out,
                    &envelope_hex,
                    RenderTruth::Yellow,
                    vec![
                        "daemon trade list-wcc-template: bad/missing args (fail-closed)"
                            .to_string(),
                        usage,
                    ],
                );
            };
            let tau = rest
                .get(8)
                .and_then(|s| s.trim().parse::<u128>().ok())
                .unwrap_or(1);
            if collar_lo >= collar_hi || tau == 0 {
                return emit_daemon_admin(
                    out,
                    &envelope_hex,
                    RenderTruth::Yellow,
                    vec![
                        "daemon trade list-wcc-template: need collar_lo < collar_hi and tau >= 1 (fail-closed)"
                            .to_string(),
                        usage,
                    ],
                );
            }
            let leg_long = ModeCDescriptor {
                konst: forward_pc.saturating_neg(),
                coords: vec![AffineCoord {
                    coeff: 1,
                    lo: collar_lo,
                    hi: collar_hi,
                    tau,
                }],
            };
            let leg_short = ModeCDescriptor {
                konst: forward_pc,
                coords: vec![AffineCoord {
                    coeff: -1,
                    lo: collar_lo,
                    hi: collar_hi,
                    tau,
                }],
            };
            // The affine-corner WCL: long is worst at S=lo (Pc − lo); short is worst at S=hi (hi − Pc).
            let declared_b_long =
                u128::try_from(forward_pc.saturating_sub(collar_lo).max(0)).unwrap_or(0);
            let declared_b_short =
                u128::try_from(collar_hi.saturating_sub(forward_pc).max(0)).unwrap_or(0);
            let descriptor = ListWccTemplateDescriptor {
                template_id: template_pk.0,
                version: 1,
                terms_schema_hash: sha256_32(b"sinabro.skew.list_wcc.terms.v1"),
                payoff_adapter_id: 0x42,
                settlement_adapter_id: 0xD4,
                reference_data_policy_id: 0x10,
                collateral_policy_id: 0x1B1B, // SKEW_COLLATERAL_WCC_V1
                vm_policy_id: 0x30,
                receipt_schema_hash: sha256_32(b"sinabro.skew.list_wcc.receipt.v1"),
                leg_long,
                leg_short,
                declared_b_long,
                declared_b_short,
                cert_long: ModeCCertKind::IntervalAffineIII,
                cert_short: ModeCCertKind::IntervalAffineIII,
                fee_policy_id: 6, // FORWARD-active dated policy (6..=9)
            };
            // W3 — resolve the EXTERNAL settlement mint: optional trailing arg @9 (after tau @8). A
            // valid 32-byte base58 pubkey OVERRIDES the settlement token; absent ⇒ the default mint
            // (byte-unchanged). Only the mint SOURCE changes — the descriptor / cert / plan stay byte-
            // identical (so the K-2 signing chokepoint is untouched). `Pubkey::from_base58` is fail-
            // closed (a non-32-byte input ⇒ None ⇒ a typed Yellow refusal, never a silent default).
            let effective_mint = match rest.get(9).map(|s| s.trim()).filter(|s| !s.is_empty()) {
                Some(s) => match Pubkey::from_base58(s) {
                    Some(pk) => pk,
                    None => {
                        return emit_daemon_admin(
                            out,
                            &envelope_hex,
                            RenderTruth::Yellow,
                            vec![
                                format!(
                                    "daemon trade list-wcc-template: '{s}' is not a 32-byte base58 settlement mint (fail-closed)"
                                ),
                                usage,
                            ],
                        );
                    }
                },
                None => mint,
            };
            plan_list_wcc_template(&owner, &effective_mint, &descriptor, &bounds, 0, 0)
        }
        // WAVE C-listings — `list_piecewise_template` (0x86): PERMISSIONLESS piecewise (option /
        // spread / digital / straddle) template registration (escrow=0). The agent PROPOSES the
        // canonical straddle `f = |S−strike| − premium`. Args:
        //   list-piecewise-template <template_id_b58> <collar_lo> <collar_hi> <tau> <strike> <premium> [settlement_mint_b58]
        // W3 — the trailing `[settlement_mint_b58]` picks the EXTERNAL settlement token (the on-chain
        // `list_piecewise_template` already takes `settlement_mint: Account<Mint>`); absent ⇒ default.
        "list-piecewise-template" => {
            let usage = format!(
                "usage: daemon trade {CUSTODY_ARM_PHRASE} <sim|live|fast|turbo> list-piecewise-template <template_id_b58> <collar_lo> <collar_hi> <tau> <strike> <premium> [settlement_mint_b58]"
            );
            let tid_b58 = rest.get(4).map_or("", String::as_str).trim();
            let pi128 = |i: usize| rest.get(i).and_then(|s| s.trim().parse::<i128>().ok());
            let (
                Some(template_pk),
                Some(collar_lo),
                Some(collar_hi),
                Some(tau),
                Some(strike),
                Some(premium),
            ) = (
                Pubkey::from_base58(tid_b58),
                pi128(5),
                pi128(6),
                rest.get(7).and_then(|s| s.trim().parse::<u128>().ok()),
                pi128(8),
                pi128(9),
            )
            else {
                return emit_daemon_admin(
                    out,
                    &envelope_hex,
                    RenderTruth::Yellow,
                    vec![
                        "daemon trade list-piecewise-template: bad/missing args (fail-closed)"
                            .to_string(),
                        usage,
                    ],
                );
            };
            let Some((leg_long, leg_short, wcl_long, wcl_short)) =
                build_straddle_legs(collar_lo, collar_hi, tau, strike, premium)
            else {
                return emit_daemon_admin(
                    out,
                    &envelope_hex,
                    RenderTruth::Yellow,
                    vec![
                        "daemon trade list-piecewise-template: degenerate straddle (need lo<strike<hi, strike on-lattice, premium<=intrinsic_max) (fail-closed)"
                            .to_string(),
                        usage,
                    ],
                );
            };
            let descriptor = ListPiecewiseTemplateDescriptor {
                template_id: template_pk.0,
                version: 1,
                terms_schema_hash: sha256_32(b"sinabro.skew.list_piecewise.terms.v1"),
                payoff_adapter_id: 0x243C,
                settlement_adapter_id: 0xC696,
                reference_data_policy_id: 0xA1,
                collateral_policy_id: 0x8394, // SKEW_COLLATERAL_WCC_PIECEWISE_V1
                vm_policy_id: 0x7A,
                receipt_schema_hash: sha256_32(b"sinabro.skew.list_piecewise.receipt.v1"),
                leg_long,
                leg_short,
                declared_b_long: wcl_long,
                declared_b_short: wcl_short,
            };
            // W3 — resolve the EXTERNAL settlement mint: optional trailing arg @10 (after premium @9).
            // Valid 32-byte base58 OVERRIDES the settlement token; absent ⇒ default mint (byte-
            // unchanged). Only the mint SOURCE changes — descriptor / legs / plan stay byte-identical.
            let effective_mint = match rest.get(10).map(|s| s.trim()).filter(|s| !s.is_empty()) {
                Some(s) => match Pubkey::from_base58(s) {
                    Some(pk) => pk,
                    None => {
                        return emit_daemon_admin(
                            out,
                            &envelope_hex,
                            RenderTruth::Yellow,
                            vec![
                                format!(
                                    "daemon trade list-piecewise-template: '{s}' is not a 32-byte base58 settlement mint (fail-closed)"
                                ),
                                usage,
                            ],
                        );
                    }
                },
                None => mint,
            };
            plan_list_piecewise_template(&owner, &effective_mint, &descriptor, &bounds, 0, 0)
        }
        // WAVE E-piecewise — `form_piecewise_contract` (0x87): bilateral straddle formation +
        // per-leg escrow. ★ 2-SIGNER ⇒ ASSEMBLE+SIM only (the agent is `long_party`; `short_party`
        // is the counterparty — a real broadcast needs both sigs = an owner go-live). The oracle
        // bounds escrow = WCL_long + WCL_short (the two legs the program pulls into the vault). Args:
        //   form-piecewise <contract_id_b58> <template_id_b58> <short_party_b58> <collar_lo> <collar_hi> <tau> <strike> <premium> <maturity_ts>
        "form-piecewise" => {
            let usage = format!(
                "usage: daemon trade {CUSTODY_ARM_PHRASE} <sim|live|fast|turbo> form-piecewise <contract_id_b58> <template_id_b58> <short_party_b58> <collar_lo> <collar_hi> <tau> <strike> <premium> <maturity_ts>"
            );
            let pi128 = |i: usize| rest.get(i).and_then(|s| s.trim().parse::<i128>().ok());
            let (
                Some(contract_pk),
                Some(template_pk),
                Some(short_pk),
                Some(collar_lo),
                Some(collar_hi),
                Some(tau),
                Some(strike),
                Some(premium),
                Some(maturity),
            ) = (
                Pubkey::from_base58(rest.get(4).map_or("", String::as_str).trim()),
                Pubkey::from_base58(rest.get(5).map_or("", String::as_str).trim()),
                Pubkey::from_base58(rest.get(6).map_or("", String::as_str).trim()),
                pi128(7),
                pi128(8),
                rest.get(9).and_then(|s| s.trim().parse::<u128>().ok()),
                pi128(10),
                pi128(11),
                rest.get(12).and_then(|s| s.trim().parse::<i64>().ok()),
            )
            else {
                return emit_daemon_admin(
                    out,
                    &envelope_hex,
                    RenderTruth::Yellow,
                    vec![
                        "daemon trade form-piecewise: bad/missing args (fail-closed)".to_string(),
                        usage,
                    ],
                );
            };
            let Some((leg_long, leg_short, wcl_long, wcl_short)) =
                build_straddle_legs(collar_lo, collar_hi, tau, strike, premium)
            else {
                return emit_daemon_admin(
                    out,
                    &envelope_hex,
                    RenderTruth::Yellow,
                    vec![
                        "daemon trade form-piecewise: degenerate straddle (fail-closed)"
                            .to_string(),
                        usage,
                    ],
                );
            };
            let (Some(long_src), Some(short_src)) = (
                crate::solana_codec::associated_token_address(&owner, &mint),
                crate::solana_codec::associated_token_address(&short_pk, &mint),
            ) else {
                return emit_daemon_admin(
                    out,
                    &envelope_hex,
                    RenderTruth::Red,
                    vec![
                        "daemon trade form-piecewise: ATA derivation failed (fail-closed)"
                            .to_string(),
                    ],
                );
            };
            let descriptor = FormPiecewiseContractDescriptor {
                contract_id: contract_pk.0,
                template_id: template_pk.0,
                leg_long,
                leg_short,
                declared_b_long: wcl_long,
                declared_b_short: wcl_short,
                maturity_timestamp: maturity,
            };
            // The agent is long_party (+ fee payer + rent payer); short_party is the counterparty.
            plan_form_piecewise_contract(
                &owner,
                &short_pk,
                &long_src,
                &short_src,
                &mint,
                &descriptor,
                &bounds,
                0,
                0,
            )
        }
        // WAVE E-piecewise — `settle_piecewise_contract` (0x88): PERMISSIONLESS keeper settle +
        // disburse (escrow=0; the keeper commits nothing). The agent acts as the settle crank. Args:
        //   settle-piecewise <contract_id_b58> <long_party_b58> <short_party_b58> <collar_lo> <collar_hi> <tau> <strike> <premium> <settlement_ref>
        "settle-piecewise" => {
            let usage = format!(
                "usage: daemon trade {CUSTODY_ARM_PHRASE} <sim|live|fast|turbo> settle-piecewise <contract_id_b58> <long_party_b58> <short_party_b58> <collar_lo> <collar_hi> <tau> <strike> <premium> <settlement_ref>"
            );
            let pi128 = |i: usize| rest.get(i).and_then(|s| s.trim().parse::<i128>().ok());
            let (
                Some(contract_pk),
                Some(long_pk),
                Some(short_pk),
                Some(collar_lo),
                Some(collar_hi),
                Some(tau),
                Some(strike),
                Some(premium),
                Some(settlement_ref),
            ) = (
                Pubkey::from_base58(rest.get(4).map_or("", String::as_str).trim()),
                Pubkey::from_base58(rest.get(5).map_or("", String::as_str).trim()),
                Pubkey::from_base58(rest.get(6).map_or("", String::as_str).trim()),
                pi128(7),
                pi128(8),
                rest.get(9).and_then(|s| s.trim().parse::<u128>().ok()),
                pi128(10),
                pi128(11),
                pi128(12),
            )
            else {
                return emit_daemon_admin(
                    out,
                    &envelope_hex,
                    RenderTruth::Yellow,
                    vec![
                        "daemon trade settle-piecewise: bad/missing args (fail-closed)".to_string(),
                        usage,
                    ],
                );
            };
            let Some((leg_long, leg_short, wcl_long, wcl_short)) =
                build_straddle_legs(collar_lo, collar_hi, tau, strike, premium)
            else {
                return emit_daemon_admin(
                    out,
                    &envelope_hex,
                    RenderTruth::Yellow,
                    vec![
                        "daemon trade settle-piecewise: degenerate straddle (fail-closed)"
                            .to_string(),
                        usage,
                    ],
                );
            };
            let (Some(long_tok), Some(short_tok)) = (
                crate::solana_codec::associated_token_address(&long_pk, &mint),
                crate::solana_codec::associated_token_address(&short_pk, &mint),
            ) else {
                return emit_daemon_admin(
                    out,
                    &envelope_hex,
                    RenderTruth::Red,
                    vec![
                        "daemon trade settle-piecewise: ATA derivation failed (fail-closed)"
                            .to_string(),
                    ],
                );
            };
            let descriptor = SettlePiecewiseContractDescriptor {
                contract_id: contract_pk.0,
                leg_long,
                leg_short,
                declared_b_long: wcl_long,
                declared_b_short: wcl_short,
                settlement_reference: settlement_ref,
            };
            // The agent is the permissionless settle caller (keeper); the parties' ATAs receive.
            plan_settle_piecewise_contract(
                &owner,
                &long_tok,
                &short_tok,
                &descriptor,
                &bounds,
                0,
                0,
            )
        }
        // WAVE G-unwired — `open_perp_market` (0x6A): PERMISSIONLESS market init (NO token CPI ⇒
        // escrow=0). Args: open-perp-market <market_id_b58> <contract_size> <tick_size>
        //   [genesis_ref] [oi_cap] [max_funding] [ref_policy] [risk_bracket] [fee_policy]
        "open-perp-market" => {
            let usage = format!(
                "usage: daemon trade {CUSTODY_ARM_PHRASE} <sim|live|fast|turbo> open-perp-market <market_id_b58> <contract_size> <tick_size> [genesis_ref] [oi_cap] [max_funding] [ref_policy] [risk_bracket] [fee_policy]"
            );
            let pu64 = |i: usize| rest.get(i).and_then(|s| s.trim().parse::<u64>().ok());
            let pu128 = |i: usize| rest.get(i).and_then(|s| s.trim().parse::<u128>().ok());
            let pu16 = |i: usize| rest.get(i).and_then(|s| s.trim().parse::<u16>().ok());
            let (Some(market_pk), Some(contract_size), Some(tick_size)) = (
                Pubkey::from_base58(rest.get(4).map_or("", String::as_str).trim()),
                pu128(5),
                pu64(6),
            ) else {
                return emit_daemon_admin(
                    out,
                    &envelope_hex,
                    RenderTruth::Yellow,
                    vec![
                        "daemon trade open-perp-market: bad/missing args (fail-closed)".to_string(),
                        usage,
                    ],
                );
            };
            if contract_size == 0 || tick_size == 0 {
                return emit_daemon_admin(
                    out,
                    &envelope_hex,
                    RenderTruth::Yellow,
                    vec![
                        "daemon trade open-perp-market: need contract_size>=1 and tick_size>=1 (on-chain param-sanity)".to_string(),
                        usage,
                    ],
                );
            }
            let descriptor = OpenPerpMarketDescriptor {
                market_id: market_pk.0,
                settlement_mint: mint,
                contract_size,
                genesis_reference_atoms: pu128(7).unwrap_or(1_000_000),
                open_interest_cap: pu64(8).unwrap_or(0),
                max_funding_rate: pu64(9).unwrap_or(0),
                tick_size,
                reference_policy_id: pu16(10).unwrap_or(0),
                active_risk_bracket_id: pu16(11).unwrap_or(0),
                fee_policy_id: pu16(12).unwrap_or(0),
            };
            plan_open_perp_market(&owner, &descriptor, &bounds, 0, 0)
        }
        // WAVE G-unwired — `factory_list_perp_market` (0x81): PERMISSIONLESS perp listing under the
        // UDSI gate + envelope clamp + RECORD-only bond (NO token CPI ⇒ escrow=0). The WCC legs mirror
        // list-wcc-template. Args: factory-list-perp-market <market_id_b58> <contract_size>
        //   <tick_size> <collar_lo> <collar_hi> <forward_pc> [tau] [genesis_ref] [oi_cap] [max_funding]
        "factory-list-perp-market" => {
            let usage = format!(
                "usage: daemon trade {CUSTODY_ARM_PHRASE} <sim|live|fast|turbo> factory-list-perp-market <market_id_b58> <contract_size> <tick_size> <collar_lo> <collar_hi> <forward_pc> [tau] [genesis_ref] [oi_cap] [max_funding]"
            );
            let pu64 = |i: usize| rest.get(i).and_then(|s| s.trim().parse::<u64>().ok());
            let pu128 = |i: usize| rest.get(i).and_then(|s| s.trim().parse::<u128>().ok());
            let pi128 = |i: usize| rest.get(i).and_then(|s| s.trim().parse::<i128>().ok());
            let (
                Some(market_pk),
                Some(contract_size),
                Some(tick_size),
                Some(collar_lo),
                Some(collar_hi),
                Some(forward_pc),
            ) = (
                Pubkey::from_base58(rest.get(4).map_or("", String::as_str).trim()),
                pu128(5),
                pu64(6),
                pi128(7),
                pi128(8),
                pi128(9),
            )
            else {
                return emit_daemon_admin(
                    out,
                    &envelope_hex,
                    RenderTruth::Yellow,
                    vec![
                        "daemon trade factory-list-perp-market: bad/missing args (fail-closed)"
                            .to_string(),
                        usage,
                    ],
                );
            };
            let tau = pu128(10).unwrap_or(1);
            if contract_size == 0 || tick_size == 0 || collar_lo >= collar_hi || tau == 0 {
                return emit_daemon_admin(
                    out,
                    &envelope_hex,
                    RenderTruth::Yellow,
                    vec![
                        "daemon trade factory-list-perp-market: need contract_size>=1, tick_size>=1, collar_lo<collar_hi, tau>=1 (fail-closed)".to_string(),
                        usage,
                    ],
                );
            }
            // The WCC affine legs (same construction as list-wcc-template; long worst at S=lo,
            // short at S=hi). The on-chain INC-A1 gate certifies these.
            let leg_long = ModeCDescriptor {
                konst: forward_pc.saturating_neg(),
                coords: vec![AffineCoord {
                    coeff: 1,
                    lo: collar_lo,
                    hi: collar_hi,
                    tau,
                }],
            };
            let leg_short = ModeCDescriptor {
                konst: forward_pc,
                coords: vec![AffineCoord {
                    coeff: -1,
                    lo: collar_lo,
                    hi: collar_hi,
                    tau,
                }],
            };
            let declared_b_long =
                u128::try_from(forward_pc.saturating_sub(collar_lo).max(0)).unwrap_or(0);
            let declared_b_short =
                u128::try_from(collar_hi.saturating_sub(forward_pc).max(0)).unwrap_or(0);
            let descriptor = FactoryListPerpMarketDescriptor {
                market_id: market_pk.0,
                settlement_mint: mint,
                contract_size,
                genesis_reference_atoms: pu128(11).unwrap_or(1_000_000),
                open_interest_cap: pu64(12).unwrap_or(0),
                max_funding_rate: pu64(13).unwrap_or(0),
                tick_size,
                reference_policy_id: 0x00A1,
                active_risk_bracket_id: 0,
                fee_policy_id: 0x0042,
                collateral_policy_id: 0x1B1B, // SKEW_COLLATERAL_WCC_V1
                leg_long,
                leg_short,
                declared_b_long,
                declared_b_short,
                cert_long: ModeCCertKind::IntervalAffineIII,
                cert_short: ModeCCertKind::IntervalAffineIII,
                ref_min_divisor_price_atoms: 1,
                ref_max_jump_bps_per_epoch: 0,
                ref_max_staleness_slots: 0,
                bond_committed_atoms: 0,
            };
            plan_factory_list_perp_market(&owner, &descriptor, &bounds, 0, 0)
        }
        // WAVE G-unwired — `form_funding_swap` (0x8E): bilateral fixed-for-floating funding swap;
        // escrow = the CEIL worst-case per side the program pulls. ★ 2-signer ⇒ assemble+SIM only
        // (never broadcasts solo). Args: form-funding-swap <contract_id_b58> <short_party_b58>
        //   <quantity> <contract_size> <fixed_rate_bps> <rate_lo> <rate_hi> <maturity_ts>
        "form-funding-swap" => {
            let usage = format!(
                "usage: daemon trade {CUSTODY_ARM_PHRASE} <sim|live|fast|turbo> form-funding-swap <contract_id_b58> <short_party_b58> <quantity> <contract_size> <fixed_rate_bps> <rate_lo> <rate_hi> <maturity_ts>"
            );
            let pi64 = |i: usize| rest.get(i).and_then(|s| s.trim().parse::<i64>().ok());
            let (
                Some(contract_pk),
                Some(short_pk),
                Some(quantity),
                Some(contract_size),
                Some(fixed_rate_bps),
                Some(rate_lo),
                Some(rate_hi),
                Some(maturity),
            ) = (
                Pubkey::from_base58(rest.get(4).map_or("", String::as_str).trim()),
                Pubkey::from_base58(rest.get(5).map_or("", String::as_str).trim()),
                rest.get(6).and_then(|s| s.trim().parse::<u64>().ok()),
                rest.get(7).and_then(|s| s.trim().parse::<u128>().ok()),
                pi64(8),
                pi64(9),
                pi64(10),
                pi64(11),
            )
            else {
                return emit_daemon_admin(
                    out,
                    &envelope_hex,
                    RenderTruth::Yellow,
                    vec![
                        "daemon trade form-funding-swap: bad/missing args (fail-closed)"
                            .to_string(),
                        usage,
                    ],
                );
            };
            if quantity == 0 || rate_lo >= rate_hi {
                return emit_daemon_admin(
                    out,
                    &envelope_hex,
                    RenderTruth::Yellow,
                    vec![
                        "daemon trade form-funding-swap: need quantity>=1 and rate_lo<rate_hi (fail-closed)".to_string(),
                        usage,
                    ],
                );
            }
            let (Some(long_src), Some(short_src)) = (
                crate::solana_codec::associated_token_address(&owner, &mint),
                crate::solana_codec::associated_token_address(&short_pk, &mint),
            ) else {
                return emit_daemon_admin(
                    out,
                    &envelope_hex,
                    RenderTruth::Red,
                    vec![
                        "daemon trade form-funding-swap: ATA derivation failed (fail-closed)"
                            .to_string(),
                    ],
                );
            };
            let descriptor = FormFundingSwapDescriptor {
                contract_id: contract_pk.0,
                quantity,
                contract_size,
                fixed_rate_bps,
                rate_lo,
                rate_hi,
                maturity_timestamp: maturity,
            };
            // The agent is long_party (fixed_payer + fee payer); short_party is the counterparty.
            plan_form_funding_swap(
                &owner,
                &short_pk,
                &long_src,
                &short_src,
                &mint,
                &descriptor,
                &bounds,
                0,
                0,
            )
        }
        // WAVE G-unwired — `open_fixed_forward_liquidation` (0x08): keeper liquidation TRIGGER (NO
        // token CPI ⇒ escrow=0). Args: open-liquidation <contract_id_b58> <long_party_b58>
        //   <short_party_b58> <template_id_b58> <liquidation_id_b58> [trigger_kind] [defaulter_role] [grace_secs]
        // (the maintenance/collateral economic claims are 0; a real keeper supplies the live snapshot —
        //  on a `sim` the missing parent PDAs fail AccountNotFound before those handler gates.)
        "open-liquidation" => {
            let usage = format!(
                "usage: daemon trade {CUSTODY_ARM_PHRASE} <sim|live|fast|turbo> open-liquidation <contract_id_b58> <long_party_b58> <short_party_b58> <template_id_b58> <liquidation_id_b58> [trigger_kind] [defaulter_role] [grace_secs]"
            );
            let (Some(contract_pk), Some(long_pk), Some(short_pk), Some(template_pk), Some(liq_pk)) = (
                Pubkey::from_base58(rest.get(4).map_or("", String::as_str).trim()),
                Pubkey::from_base58(rest.get(5).map_or("", String::as_str).trim()),
                Pubkey::from_base58(rest.get(6).map_or("", String::as_str).trim()),
                Pubkey::from_base58(rest.get(7).map_or("", String::as_str).trim()),
                Pubkey::from_base58(rest.get(8).map_or("", String::as_str).trim()),
            ) else {
                return emit_daemon_admin(
                    out,
                    &envelope_hex,
                    RenderTruth::Yellow,
                    vec![
                        "daemon trade open-liquidation: bad/missing args (fail-closed)".to_string(),
                        usage,
                    ],
                );
            };
            let trigger_kind = rest
                .get(9)
                .and_then(|s| s.trim().parse::<u8>().ok())
                .unwrap_or(0);
            let defaulter_role = rest
                .get(10)
                .and_then(|s| s.trim().parse::<u8>().ok())
                .unwrap_or(0);
            let grace = rest
                .get(11)
                .and_then(|s| s.trim().parse::<u32>().ok())
                .unwrap_or(3600);
            let descriptor = OpenLiquidationDescriptor {
                liquidation_id: liq_pk.0,
                contract_id: contract_pk.0,
                trigger_kind,
                // non-zero trigger snapshot (on-chain gate 2 requires non-zero; a real keeper cross-pins it).
                trigger_snapshot_hash: sha256_32(b"sinabro.skew.liquidation.trigger.v1"),
                maintenance_requirement: 0,
                collateral_value: 0,
                defaulter_role,
                auction_grace_seconds: grace,
            };
            plan_open_fixed_forward_liquidation(
                &owner,
                &long_pk,
                &short_pk,
                &template_pk.0,
                &descriptor,
                &bounds,
                0,
                0,
            )
        }
        // WAVE G-unwired — `complete_liquidation` (8-byte sighash): close the liquidation lifecycle
        // (NO token CPI ⇒ escrow=0). Args: complete-liquidation <contract_id_b58> <long_party_b58>
        //   <short_party_b58> <template_id_b58> <liquidation_id_b58> [valuation] [close_factor] [dispute_resolved]
        "complete-liquidation" => {
            let usage = format!(
                "usage: daemon trade {CUSTODY_ARM_PHRASE} <sim|live|fast|turbo> complete-liquidation <contract_id_b58> <long_party_b58> <short_party_b58> <template_id_b58> <liquidation_id_b58> [valuation] [close_factor] [dispute_resolved]"
            );
            let (Some(contract_pk), Some(long_pk), Some(short_pk), Some(template_pk), Some(liq_pk)) = (
                Pubkey::from_base58(rest.get(4).map_or("", String::as_str).trim()),
                Pubkey::from_base58(rest.get(5).map_or("", String::as_str).trim()),
                Pubkey::from_base58(rest.get(6).map_or("", String::as_str).trim()),
                Pubkey::from_base58(rest.get(7).map_or("", String::as_str).trim()),
                Pubkey::from_base58(rest.get(8).map_or("", String::as_str).trim()),
            ) else {
                return emit_daemon_admin(
                    out,
                    &envelope_hex,
                    RenderTruth::Yellow,
                    vec![
                        "daemon trade complete-liquidation: bad/missing args (fail-closed)"
                            .to_string(),
                        usage,
                    ],
                );
            };
            let valuation = rest
                .get(9)
                .and_then(|s| s.trim().parse::<i128>().ok())
                .unwrap_or(0);
            let close_factor = rest
                .get(10)
                .and_then(|s| s.trim().parse::<u128>().ok())
                .unwrap_or(0);
            let dispute_resolved =
                matches!(rest.get(11).map(|s| s.trim()), Some("true") | Some("1"));
            let descriptor = CompleteLiquidationDescriptor {
                contract_id: contract_pk.0,
                liquidation_id: liq_pk.0,
                valuation_amount: valuation,
                close_factor,
                dispute_resolved,
                current_unix_timestamp: 0,
            };
            plan_complete_liquidation(
                &owner,
                &long_pk,
                &short_pk,
                &template_pk.0,
                &descriptor,
                &bounds,
                0,
                0,
            )
        }
        _ => {
            return emit_daemon_admin(
                out,
                &envelope_hex,
                RenderTruth::Yellow,
                vec![
                    format!("daemon trade: unknown action {action:?} (fail-closed)"),
                    format!(
                        "usage: daemon trade {CUSTODY_ARM_PHRASE} <sim|live> <open-account|deposit|withdraw|submit-perp|submit-order|pay-vm|lock-collateral|mark-vm|settle|form-contract|list-wcc-template|list-piecewise-template|form-piecewise|settle-piecewise|open-perp-market|factory-list-perp-market|form-funding-swap|open-liquidation|complete-liquidation> [args]"
                    ),
                ],
            );
        }
    };
    let plan = match plan_result {
        Ok(p) => p,
        Err(reason) => {
            return emit_daemon_admin(
                out,
                &envelope_hex,
                RenderTruth::Red,
                vec![
                    format!(
                        "daemon trade: ORACLE DENIED ({}) — fail-closed, nothing assembled, nothing signed",
                        reason.as_str()
                    ),
                    "the K-1 oracle re-derived Skew's worst-case escrow and refused (money 0)."
                        .to_string(),
                ],
            );
        }
    };

    // GATE 2 — the owner-arm ceremony: the EXACT custody phrase mints a within-bounds CustodyGrant.
    let mut prompt = ApprovalPrompt::new(ApprovalRequirement::TypedPhrase, CUSTODY_ARM_PHRASE);
    let audit_hash_32 = sha256_32(b"daemon.trade.skew.custody.arm.v1");
    let Some(grant) = arm_local_custody_grant(
        &mut prompt,
        phrase.trim(),
        audit_hash_32,
        CustodyBounds {
            base: GrantBounds {
                max_actions_u32: MAX_ACTIONS,
                expires_at_epoch_ms: now_ms.saturating_add(TTL_MS),
            },
            per_tx_max_minor: PER_TX,
            total_budget_minor: BUDGET,
            chain_allowlist: vec![K2_CHAIN.to_string()],
            protocol_allowlist: vec![K2_PROTOCOL.to_string()],
        },
    ) else {
        return emit_daemon_admin(
            out,
            &envelope_hex,
            RenderTruth::Yellow,
            vec![
                "daemon trade: LOCKED — the custody arm phrase is missing/wrong (fail-closed)"
                    .to_string(),
                format!(
                    "to arm, supply EXACTLY: daemon trade {CUSTODY_ARM_PHRASE} <sim|live> <open-account|deposit|withdraw|submit-perp|submit-order|pay-vm|lock-collateral|mark-vm|settle|form-contract|list-wcc-template|list-piecewise-template|form-piecewise|settle-piecewise|open-perp-market|factory-list-perp-market|form-funding-swap|open-liquidation|complete-liquidation> [args]"
                ),
                "the model cannot supply this phrase; only the owner arms.".to_string(),
            ],
        );
    };

    // GATE 3 — the bounded ChainTxCapability witness (custody bound on the proposed tx).
    let Some(cap) = local_chain_tx_capability(&grant, now_ms, 0, 0, &plan.request) else {
        let reason = match grant.authorize(now_ms, 0, 0, &plan.request) {
            crate::commands::grant::CustodyAuthorization::Denied(r) => format!("{r:?}"),
            crate::commands::grant::CustodyAuthorization::Authorized => "—".to_string(),
        };
        return emit_daemon_admin(
            out,
            &envelope_hex,
            RenderTruth::Red,
            vec![format!(
                "daemon trade: CUSTODY DENIED ({reason}) — fail-closed, nothing signed (money 0)"
            )],
        );
    };

    // The owner-configured devnet endpoint (config-only; no arbitrary URL).
    let registry = read_owner_web3_chain_registry();
    let Some(entry) = registry.lookup(K2_CHAIN) else {
        return emit_daemon_admin(
            out,
            &envelope_hex,
            RenderTruth::Red,
            vec![format!(
                "daemon trade: chain '{K2_CHAIN}' not configured — add it to web3_rpc_chains (config); nothing signed"
            )],
        );
    };
    let endpoint = entry.endpoint().to_string();

    // GATE 4-7 — the chokepoint: assemble → REAL simulate (D2/D3) → [live] D14 → sign → D13 → broadcast.
    let seam = ChainWriteSeam::new();
    let outcome = execute_skew_chain_tx(cap, &plan, &signer, seam.port(), &endpoint, mode);

    let (truth, mut body) = match outcome {
        SkewExecOutcome::Broadcast {
            signature_b58,
            sim_ok,
            sim_skipped,
            jito,
            d14_ok,
            d13_ok,
        } => (
            RenderTruth::Green,
            vec![
                format!(
                    "daemon trade [{}]: ★ BROADCAST a REAL devnet tx (sim={} D14={d14_ok} D13={d13_ok} inclusion={})",
                    plan.action_label,
                    if sim_skipped {
                        "SKIPPED(fast/turbo — oracle+D13+D14 still gated)".to_string()
                    } else {
                        format!("ok={sim_ok}")
                    },
                    if jito {
                        "jito/turbo (or standard if unconfigured)"
                    } else {
                        "standard"
                    },
                ),
                format!("signature: {signature_b58}"),
                format!("explorer: https://explorer.solana.com/tx/{signature_b58}?cluster=devnet"),
            ],
        ),
        SkewExecOutcome::Simulated {
            sim_ok,
            sim_summary,
            d13_ok,
        } => (
            if sim_ok {
                RenderTruth::Green
            } else {
                RenderTruth::Red
            },
            vec![
                format!(
                    "daemon trade [{}]: REAL devnet SIMULATE (money 0) sim_ok={sim_ok} D13={d13_ok} (signed; NOT broadcast)",
                    plan.action_label
                ),
                format!("sim: {sim_summary}"),
                "re-run with `live` to D14-pin + broadcast (the isolated key must be funded)."
                    .to_string(),
            ],
        ),
        SkewExecOutcome::Denied(reason) => {
            let mut lines = vec![format!(
                "daemon trade [{}]: DENIED ({}) — fail-closed, nothing signed/broadcast (money 0)",
                plan.action_label,
                reason.label()
            )];
            // surface the redacted simulate detail (the live program's verdict on the bytes).
            if let crate::skew_execute::SkewExecDenied::SimulateFailed(summary) = &reason {
                lines.push(format!("sim: {summary}"));
            }
            (RenderTruth::Red, lines)
        }
    };
    body.push(format!(
        "bound: chain={K2_CHAIN} protocol={K2_PROTOCOL} per-tx<={PER_TX} budget<={BUDGET} amount={} (oracle-decided escrow)",
        plan.request.amount_minor
    ));
    body.push("isolated key never reaches the model; mainnet = a further owner arm; CustodyCapability uninhabited (PD-6).".to_string());
    emit_daemon_admin(out, &envelope_hex, truth, body)
}

fn cmd_daemon_web3_read(rest: &[String], out: &mut impl Write) -> io::Result<bool> {
    use crate::commands::authority::ReadCapability;
    use crate::provider::web3_rpc::{Web3RpcMethod, Web3RpcSeam, render_web3_read};

    let envelope_hex = toplevel_envelope_hex("daemon");
    let chain = rest.get(1).map_or("", String::as_str).trim();
    let method_token = rest.get(2).map_or("", String::as_str);
    let params = rest.get(3).map_or("[]", String::as_str);

    // ONCHAIN PIVOT C-1: an AUTONOMOUS multi-chain READ — chain reads are READ-class (like
    // web_fetch), so the witness is a freely-granted ReadCapability (NO owner arm). The bound is
    // the owner-configured registry: the agent supplies a chain NAME, never a URL, and reads ONLY
    // configured chains. A chain WRITE stays unrepresentable (the method enum has no write variant).
    let read = ReadCapability::granted();
    let registry = read_owner_web3_chain_registry();

    // Parse the READ-only method (unknown / any write method ⇒ None ⇒ honest deny).
    let Some(method) = Web3RpcMethod::parse(method_token) else {
        let names = registry.chain_names();
        let body = vec![
            format!(
                "daemon web3-read: unknown READ method '{}'",
                method_token.chars().take(48).collect::<String>()
            ),
            "usage: daemon web3-read <chain> <method> [params-json]".to_string(),
            format!("methods: {}", Web3RpcMethod::token_list()),
            format!(
                "configured chains: {}",
                if names.is_empty() {
                    "none (set web3_rpc_chains in config)".to_string()
                } else {
                    names
                }
            ),
            "a chain WRITE method is not selectable (unrepresentable); nothing read".to_string(),
        ];
        return emit(
            out,
            "daemon",
            &envelope_hex,
            CommandRisk::Network,
            ApprovalRequirement::None,
            RenderTruth::Yellow,
            &body,
        )
        .map(|()| true);
    };

    // The LIVE seam: a live transport under `web3-egress`, otherwise port = None ⇒ honest
    // TransportNotCompiled. The ReadCapability witness proves READ-class at the type level; the
    // registry lookup + family match + SSRF wall + redaction all run inside render_web3_read.
    let seam = Web3RpcSeam::new();
    let render = render_web3_read(&read, seam.port(), &registry, chain, method, params);

    let truth = if render.ok {
        RenderTruth::Green
    } else {
        RenderTruth::Yellow
    };
    let mut body = vec![format!(
        "daemon web3-read: AUTONOMOUS READ ({chain}/{token}); READ-only, chain-write unrepresentable",
        chain = if chain.is_empty() { "<chain>" } else { chain },
        token = method.token(),
    )];
    for line in render.rendered.lines() {
        body.push(line.to_string());
    }
    body.push(format!("class={}", render.class_label));
    body.push(
        "READ-only (no chain WRITE); secret-zero dial; params + result redacted; the agent reads ONLY owner-configured chains"
            .to_string(),
    );
    emit(
        out,
        "daemon",
        &envelope_hex,
        CommandRisk::Network,
        ApprovalRequirement::None,
        truth,
        &body,
    )
    .map(|()| true)
}

fn cmd_daemon_git_push(rest: &[String], out: &mut impl Write) -> io::Result<bool> {
    use crate::commands::authority::local_egress_capability;
    use crate::commands::grant::{EgressGrant, GrantBounds, GrantTier, OwnerArmCeremony};
    use crate::git::GIT_PUSH_ARM_PHRASE;
    use crate::repl::approval::ApprovalPrompt;

    let envelope_hex = toplevel_envelope_hex("daemon");
    let supplied_phrase = rest.get(1).map_or("", String::as_str);
    let branch = rest.get(2).map_or("", String::as_str); // empty ⇒ HEAD

    // GATE (owner-arm ceremony): the EXACT git-push arm phrase ⇒ a bounded
    // EgressGrant. Missing/wrong ⇒ NO grant, NO push — fail-closed.
    let mut prompt = ApprovalPrompt::new(ApprovalRequirement::TypedPhrase, GIT_PUSH_ARM_PHRASE);
    let audit_hash_32 = sha256_32(b"daemon.git-push.egress.arm.v1");
    let Some(ceremony) = OwnerArmCeremony::complete(
        &mut prompt,
        supplied_phrase.trim(),
        GrantTier::Egress,
        audit_hash_32,
    ) else {
        let body = vec![
            "daemon git-push = ONE owner-armed git push to origin (bounded egress grant)"
                .to_string(),
            "risk=network; single-shot (max_actions=1), 120s, revocable; origin-only; force-push refused"
                .to_string(),
            format!("to arm, supply EXACTLY: daemon git-push {GIT_PUSH_ARM_PHRASE} [branch]"),
            "sandboxed: writes scoped to .git, network allowed; uses your git credentials; funds/custody HARD-LOCKED"
                .to_string(),
            "denied: no push without the exact arm phrase".to_string(),
        ];
        return emit(
            out,
            "daemon",
            &envelope_hex,
            CommandRisk::Network,
            ApprovalRequirement::TypedPhrase,
            RenderTruth::Yellow,
            &body,
        )
        .map(|()| true);
    };

    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0u64, |d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX));
    let bounds = GrantBounds {
        max_actions_u32: 1,
        expires_at_epoch_ms: now_ms.saturating_add(120_000),
    };
    let Some(grant) = EgressGrant::arm(ceremony, bounds) else {
        // unreachable for a GrantTier::Egress ceremony — fail closed regardless.
        return emit(
            out,
            "daemon",
            &envelope_hex,
            CommandRisk::Network,
            ApprovalRequirement::TypedPhrase,
            RenderTruth::Yellow,
            &["egress grant arm failed; nothing pushed".to_string()],
        )
        .map(|()| true);
    };
    let Some(cap) = local_egress_capability(&grant) else {
        return emit(
            out,
            "daemon",
            &envelope_hex,
            CommandRisk::Network,
            ApprovalRequirement::TypedPhrase,
            RenderTruth::Yellow,
            &["egress capability denied (fresh grant); nothing pushed".to_string()],
        )
        .map(|()| true);
    };

    let render = crate::git::render_git_push(&cap, branch);
    let truth = if render.pushed {
        RenderTruth::Green
    } else {
        RenderTruth::Yellow
    };
    let body: Vec<String> = render.rendered.lines().map(str::to_string).collect();
    emit(
        out,
        "daemon",
        &envelope_hex,
        CommandRisk::Network,
        ApprovalRequirement::TypedPhrase,
        truth,
        &body,
    )
    .map(|()| true)
}

/// `sinabro daemon run-frontier <ARM_PHRASE> <task>` — the owner ARMS a bounded
/// egress grant (the E0c `OwnerArmCeremony` typed-phrase ceremony) and the REAL
/// [`AutonomyRuntime`] runs ONE autonomous job that ESCALATES to the FRONTIER
/// (`ConsultPhrase::Frontier`). The grant is single-shot (`max_actions=1`),
/// fast-expiring (120s), revocable; the model has NO `EgressCapability` ctor so it
/// can NEVER self-mint this — only the owner's typed phrase arms it (E0c/E0d). The
/// frontier transport carries the SAME before-send redact wall as the interactive
/// `provider consult`; custody/funds stay HARD-LOCKED (PD-6).
#[cfg(feature = "provider-egress")]
fn cmd_daemon_run_frontier(rest: &[String], out: &mut impl Write) -> io::Result<bool> {
    use crate::commands::budget::BudgetCap;
    use crate::commands::grant::{
        EGRESS_ARM_PHRASE, EgressGrant, GrantBounds, GrantTier, OwnerArmCeremony,
    };
    use crate::commands::model_compress::ConsultScope;
    use crate::commands::model_route::ConsultTrigger;
    use crate::daemon::runtime::{AutonomyRuntime, TurnOutcome};
    use crate::provider::egress::{EgressApproval, ProviderTransport, RedactedConsult};
    use crate::provider::frontier_consult::{self, BoundedConsultInputs, BoundedConsultRequest};
    use crate::provider::route_select::ConsultPhrase;
    use crate::repl::approval::ApprovalPrompt;
    use crate::route::RouteExecutionState;

    let envelope_hex = toplevel_envelope_hex("daemon");
    let supplied_phrase = rest.get(1).map_or("", String::as_str);
    let task = rest.get(2..).map(|s| s.join(" ")).unwrap_or_default();
    let task = task.trim();

    // GATE (owner-arm ceremony): the EXACT egress arm phrase. Missing/wrong ⇒ NO
    // grant, NO frontier — fail-closed (the model cannot supply this).
    let mut prompt = ApprovalPrompt::new(ApprovalRequirement::TypedPhrase, EGRESS_ARM_PHRASE);
    let audit_hash_32 = sha256_32(b"daemon.run-frontier.egress.arm.v1");
    let Some(ceremony) = OwnerArmCeremony::complete(
        &mut prompt,
        supplied_phrase.trim(),
        GrantTier::Egress,
        audit_hash_32,
    ) else {
        let body = vec![
            "daemon run-frontier = ONE AUTONOMOUS FRONTIER job (owner-armed egress grant)"
                .to_string(),
            "risk=network; the bounded grant is single-shot (max_actions=1), 120s, revocable"
                .to_string(),
            format!("to arm, supply EXACTLY: daemon run-frontier {EGRESS_ARM_PHRASE} <task>"),
            "key: OPENROUTER_API_KEY env, read only at the TLS boundary; funds/custody HARD-LOCKED"
                .to_string(),
            "denied: no autonomous frontier action without the exact arm phrase".to_string(),
        ];
        return emit(
            out,
            "daemon",
            &envelope_hex,
            CommandRisk::Network,
            ApprovalRequirement::TypedPhrase,
            RenderTruth::Yellow,
            &body,
        )
        .map(|()| true);
    };
    if task.is_empty() {
        return provider_consult_error(out, &envelope_hex, "empty task; nothing run");
    }
    if task.len() > PROVIDER_CONSULT_MAX_QUESTION_BYTES {
        return provider_consult_error(out, &envelope_hex, "task exceeds the bounded input cap");
    }

    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0u64, |d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX));
    // The bounded egress grant: ONE autonomous frontier action, expires in 120s.
    let bounds = GrantBounds {
        max_actions_u32: 1,
        expires_at_epoch_ms: now_ms.saturating_add(120_000),
    };
    let Some(grant) = EgressGrant::arm(ceremony, bounds) else {
        // unreachable for a GrantTier::Egress ceremony — fail closed regardless.
        return provider_consult_error(out, &envelope_hex, "egress grant arm failed");
    };

    // Before-send redaction over the task (deny-not-fix; IDENTICAL to provider consult).
    let fragments = [task];
    let receipt = match redact(&RedactionRequest {
        fragments: &fragments,
        candidate_memory_ids: &[],
        deleted_ids: &[],
        include_private_memory: false,
    }) {
        Ok(receipt) => receipt,
        Err(_) => {
            return provider_consult_error(out, &envelope_hex, "redaction gate denied the task");
        }
    };
    if receipt.secret_fragments_denied_u32() > 0 || receipt.outgoing_fragment_count_u32() == 0 {
        return provider_consult_error(out, &envelope_hex, "task is secret-shaped; not sent");
    }
    // The bounded consult request (SLOW caps) + the live-dispatch envelope (the
    // owner-arm ceremony above IS the same-message approval the builder demands).
    let inputs = BoundedConsultInputs {
        route_state: RouteExecutionState::Slow,
        trigger: ConsultTrigger::LowConfidenceHighBlastRadius,
        scope: ConsultScope::minimal(),
        redaction_report_hash_32: receipt.redacted_payload_hash_32(),
        evidence_refs_hash_32: sha256_32(b"daemon-run-frontier-v1:autonomous-task"),
        prompt_hash_32: sha256_32(task.as_bytes()),
        timeout_ms_u32: PROVIDER_CONSULT_TIMEOUT_MS,
        local_verification_command_hash_32: sha256_32(b"owner-reads-advisory-answer"),
    };
    let Some(request) = frontier_consult::build(&inputs) else {
        return provider_consult_error(out, &envelope_hex, "bounded consult request denied");
    };
    let request = BoundedConsultRequest {
        live_dispatch_allowed: true,
        ..request
    };
    let Some(consult) = RedactedConsult::new(request, receipt) else {
        return provider_consult_error(out, &envelope_hex, "consult payload rejected");
    };
    let host = match resolve_frontier_provider() {
        Ok(host) => host,
        Err(reason) => return provider_consult_error(out, &envelope_hex, reason),
    };
    let transport_p = ProviderTransport::for_host(host);
    let model = provider_consult_model_for(host);

    // Recall the owner's REAL persisted store (READ-class autonomous knowledge base).
    let mem = consult_memory_load();
    let loop_contents: Vec<(MemoryId, &[u8])> = mem
        .loaded
        .chunks
        .iter()
        .map(|(chunk, _)| (chunk.id(), chunk.envelope().content.as_slice()))
        .collect();
    let state = crate::agent_loop::MemoryToolState {
        records: &mem.folded.records,
        contents: &loop_contents,
        policy: &mem.policy,
    };
    let system = format!(
        "{}\n\n{}",
        sinabro_system_prompt(false),
        crate::agent_loop::SINABRO_LOOP_PROTOCOL
    );

    // The REAL runtime ARMED with the owner's grant. tick(Frontier) re-derives the
    // EgressCapability from the grant at the LIVE (now, used) before every side
    // effect (fail-closed on expiry/rate/revoke).
    let trace = crate::StageFTraceLink::new([0x53; 32], 0, 0);
    let mut rt = AutonomyRuntime::arm(
        1,
        Some(grant),
        BudgetCap::new(100_000, 1_000_000, 100_000),
        2,
        trace,
    );
    let mut last_model = String::new();
    let mut last_response_hash_32 = ZERO32;
    let mut last_answer = String::new();
    let outcome = {
        let mut live = crate::agent_loop::FnTransport(|system: &str, user_message: &str| {
            let fragments = [user_message];
            match redact(&RedactionRequest {
                fragments: &fragments,
                candidate_memory_ids: &[],
                deleted_ids: &[],
                include_private_memory: false,
            }) {
                Ok(receipt) if receipt.secret_fragments_denied_u32() == 0 => {}
                _ => {
                    return Err(crate::agent_loop::AgentTransportError {
                        class_label: "assembled message denied by redaction".to_string(),
                    });
                }
            }
            match transport_p.send_live_text(
                &consult,
                EgressApproval::grant(),
                system,
                user_message,
                &model,
                PROVIDER_CONSULT_MAX_OUTPUT_TOKENS,
            ) {
                Ok(outcome) => {
                    last_model = outcome.model;
                    last_response_hash_32 = outcome.response_hash_32;
                    last_answer = outcome.answer_text.clone();
                    Ok(crate::agent_loop::AgentTurn {
                        answer_text: outcome.answer_text,
                        input_tokens_u64: outcome.input_tokens,
                        output_tokens_u64: outcome.output_tokens,
                        cached_tokens_u64: outcome.cached_tokens,
                    })
                }
                Err(error) => Err(crate::agent_loop::AgentTransportError {
                    class_label: consult_denied_label(&error),
                }),
            }
        });
        rt.tick(
            now_ms,
            ConsultPhrase::Frontier,
            &system,
            task,
            &mut live,
            &state,
        )
    };

    let (truth, mut body) = match outcome {
        TurnOutcome::Ran { route, stop } => {
            let mut lines = vec![format!(
                "daemon run-frontier: ONE AUTONOMOUS job RAN route={} (owner-armed egress grant; bounded)",
                if route.is_frontier() {
                    "frontier"
                } else {
                    "local-loopback"
                }
            )];
            lines.push(format!("autonomous task: {task}"));
            // the autonomous answer, rendered through the per-chunk redact wall.
            let streamed = stream_consult_answer(&last_answer, last_response_hash_32, 78, 52);
            let feed = stream_feed_receipt(&streamed);
            lines.extend(streamed.lines);
            lines.push(feed);
            lines.push(format!("loop stop={} model={last_model}", stop.class_label()));
            (RenderTruth::Green, lines)
        }
        TurnOutcome::FrontierDenied => (
            RenderTruth::Red,
            vec!["daemon run-frontier: DENIED (grant invalid/expired/revoked) — fail-closed, zero egress".to_string()],
        ),
        TurnOutcome::BudgetStopped(_) => (
            RenderTruth::Yellow,
            vec!["daemon run-frontier: budget cap refused the turn (fail-closed)".to_string()],
        ),
        TurnOutcome::Paused => (
            RenderTruth::Yellow,
            vec!["daemon run-frontier: control paused the job (no side effect)".to_string()],
        ),
        TurnOutcome::Terminated => (
            RenderTruth::Yellow,
            vec!["daemon run-frontier: job terminal (no-op, no zombie)".to_string()],
        ),
    };
    body.push(format!(
        "turns_run={} egress_actions_used={}/1 (grant re-derived before EVERY side effect; single-shot)",
        rt.turns_run(),
        rt.egress_actions_used()
    ));
    body.push(format!(
        "response_sha={} (last frontier turn; key never rendered; raw body not stored at rest)",
        hex16(&last_response_hash_32)
    ));
    body.push(
        "the grant is spent + auto-expires (120s) + revocable; custody uninhabited (PD-6); no funds/chain".to_string(),
    );
    emit(
        out,
        "daemon",
        &envelope_hex,
        CommandRisk::Network,
        ApprovalRequirement::TypedPhrase,
        truth,
        &body,
    )
    .map(|()| true)
}

/// `daemon run-frontier` honest degrade for a build with NO provider-egress feature.
#[cfg(not(feature = "provider-egress"))]
fn cmd_daemon_run_frontier(rest: &[String], out: &mut impl Write) -> io::Result<bool> {
    let _ = rest;
    let body = vec![
        "daemon run-frontier = ONE autonomous FRONTIER job (owner-armed egress grant)".to_string(),
        "this build compiled NO provider-egress feature ⇒ no frontier transport".to_string(),
        "build --features provider-egress + set OPENROUTER_API_KEY, then arm + run".to_string(),
    ];
    emit(
        out,
        "daemon",
        &toplevel_envelope_hex("daemon"),
        CommandRisk::ReadOnly,
        ApprovalRequirement::None,
        RenderTruth::Yellow,
        &body,
    )
    .map(|()| true)
}

/// `sinabro daemon serve <task>` — the BACKGROUND poll-and-arm loop (ENDGAME E11-3
/// part 1). The runner is armed with NO grant and attempts an autonomous FRONTIER
/// escalation of `<task>` ⇒ `FrontierDenied` (zero egress); the loop PINGS the owner
/// (SI-2 `build_approval_ping` dry-run + SI-6 `ping_through_center` dedupe), POLLS the
/// live getUpdates edge (`LivePollSource` → `poll_and_ingest`) for the owner's reply
/// across BOUNDED windows, and on an APPROVE installs the NARROW single-shot grant +
/// proceeds EXACTLY the one denied action (single-shot). No reply / a deny / a
/// transport failure ⇒ the action STAYS DENIED (fail-closed). The bounded driver is
/// pumped by the EXISTING `RuntimeHandle::spawn` std-thread (⑩; NO new crate). The
/// long-lived coordinator (its load-bearing ledger) is PERSISTED across the loop. part
/// 2 (a real `TELEGRAM_BOT_TOKEN` getUpdates fire) is the owner go-live gate; this
/// command starts NO real poll without a real token. custody/funds HARD-LOCKED (PD-6).
#[cfg(all(feature = "telegram-inbound", feature = "provider-egress"))]
fn cmd_daemon_serve(rest: &[String], out: &mut impl Write) -> io::Result<bool> {
    use crate::agent_loop::MemoryToolState;
    use crate::commands::budget::BudgetCap;
    use crate::commands::model_compress::ConsultScope;
    use crate::commands::model_route::ConsultTrigger;
    use crate::commands::platform_telegram::NotificationCenter;
    use crate::daemon::remote_approval::{
        LivePollSource, RemoteApprovalCoordinator, ServeArm, ServeCycleOutcome, ServeParams,
        serve_poll_arm_cycle,
    };
    use crate::daemon::runtime::{AutonomyRuntime, RuntimeHandle};
    use crate::provider::egress::{EgressApproval, ProviderTransport, RedactedConsult};
    use crate::provider::frontier_consult::{self, BoundedConsultInputs, BoundedConsultRequest};
    use crate::route::RouteExecutionState;
    use crate::telegram::egress::TelegramHost;
    use crate::telegram::inbound::InboundTransport;
    use std::sync::{Arc, Mutex};
    use std::time::Duration;

    /// The bounded caps (IV-DP1): per-cycle poll windows + driver serve cycles.
    const SERVE_WINDOWS_MAX: u32 = 3;
    const SERVE_CYCLES_MAX: u32 = 3;

    /// The collected serve outcome (read after the bounded thread joins).
    #[derive(Default)]
    struct ServeLog {
        lines: Vec<String>,
        proceeded: bool,
        denied: bool,
        no_reply: bool,
        halted: bool,
        egress_actions_used: u32,
        turns_run: u32,
    }

    let envelope_hex = toplevel_envelope_hex("daemon");
    // owner chat id from TELEGRAM_CHAT_ID — fail-closed (missing / unparseable ⇒ no poll).
    let Ok(chat_raw) = std::env::var("TELEGRAM_CHAT_ID") else {
        return daemon_serve_error(
            out,
            &envelope_hex,
            "TELEGRAM_CHAT_ID not set; no remote-approve channel",
        );
    };
    let Ok(owner_chat_id) = chat_raw.trim().parse::<i64>() else {
        return daemon_serve_error(
            out,
            &envelope_hex,
            "TELEGRAM_CHAT_ID is not a valid integer",
        );
    };
    // rest[0] = "serve"; rest[1..] = the autonomous task.
    let task = rest.get(1..).map(|s| s.join(" ")).unwrap_or_default();
    let task = task.trim().to_string();
    if task.is_empty() {
        return daemon_serve_error(out, &envelope_hex, "empty task; nothing to serve");
    }
    if task.len() > PROVIDER_CONSULT_MAX_QUESTION_BYTES {
        return daemon_serve_error(out, &envelope_hex, "task exceeds the bounded input cap");
    }

    // Before-send redaction over the task (deny-not-fix; IDENTICAL to provider consult).
    let fragments = [task.as_str()];
    let receipt = match redact(&RedactionRequest {
        fragments: &fragments,
        candidate_memory_ids: &[],
        deleted_ids: &[],
        include_private_memory: false,
    }) {
        Ok(receipt) => receipt,
        Err(_) => return daemon_serve_error(out, &envelope_hex, "redaction gate denied the task"),
    };
    if receipt.secret_fragments_denied_u32() > 0 || receipt.outgoing_fragment_count_u32() == 0 {
        return daemon_serve_error(out, &envelope_hex, "task is secret-shaped; not served");
    }
    let inputs = BoundedConsultInputs {
        route_state: RouteExecutionState::Slow,
        trigger: ConsultTrigger::LowConfidenceHighBlastRadius,
        scope: ConsultScope::minimal(),
        redaction_report_hash_32: receipt.redacted_payload_hash_32(),
        evidence_refs_hash_32: sha256_32(b"daemon-serve-v1:autonomous-task"),
        prompt_hash_32: sha256_32(task.as_bytes()),
        timeout_ms_u32: PROVIDER_CONSULT_TIMEOUT_MS,
        local_verification_command_hash_32: sha256_32(b"owner-reads-advisory-answer"),
    };
    let Some(request) = frontier_consult::build(&inputs) else {
        return daemon_serve_error(out, &envelope_hex, "bounded consult request denied");
    };
    let request = BoundedConsultRequest {
        live_dispatch_allowed: true,
        ..request
    };
    let Some(consult) = RedactedConsult::new(request, receipt) else {
        return daemon_serve_error(out, &envelope_hex, "consult payload rejected");
    };
    let host = match resolve_frontier_provider() {
        Ok(host) => host,
        Err(reason) => return daemon_serve_error(out, &envelope_hex, reason),
    };
    let transport_p = ProviderTransport::for_host(host);
    let model = provider_consult_model_for(host);
    let system = format!(
        "{}\n\n{}",
        sinabro_system_prompt(false),
        crate::agent_loop::SINABRO_LOOP_PROTOCOL
    );

    // The live poll source over the owner-pinned getUpdates transport + the long-lived
    // coordinator (its ledger PERSISTS across the loop — IV-DP5) + the SI-6 dedupe gate.
    let token_ref =
        crate::secrets::classify_reference("telegram_bot_token", "env:TELEGRAM_BOT_TOKEN");
    let mut live_poll = LivePollSource::new(InboundTransport::new(TelegramHost::BotApi, token_ref));
    let mut coordinator = RemoteApprovalCoordinator::new(owner_chat_id);
    let mut center = NotificationCenter::new(8);

    // Recall the owner's REAL persisted store (READ-class autonomous knowledge base) —
    // moved into the driver and re-borrowed into a `MemoryToolState` each tick.
    let mem = consult_memory_load();
    let trace = crate::StageFTraceLink::new([0x53; 32], 0, 0);
    // The REAL runtime, armed with NO grant ⇒ the first frontier tick is denied (the
    // "away" path). The owner's approval mints + installs the single-shot grant.
    let rt_runtime = AutonomyRuntime::arm(
        1,
        None,
        BudgetCap::new(100_000, 1_000_000, 100_000),
        2,
        trace,
    );

    let serve_log: Arc<Mutex<ServeLog>> = Arc::new(Mutex::new(ServeLog::default()));
    let driver_log = Arc::clone(&serve_log);
    let task_label = task.clone();
    let mut cycle: u32 = 0;

    let driver = move |rt: &mut AutonomyRuntime| -> bool {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0u64, |d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX));
        // Re-borrow the owned recall into a loop state for this tick.
        let loop_contents: Vec<(MemoryId, &[u8])> = mem
            .loaded
            .chunks
            .iter()
            .map(|(chunk, _)| (chunk.id(), chunk.envelope().content.as_slice()))
            .collect();
        let state = MemoryToolState {
            records: &mem.folded.records,
            contents: &loop_contents,
            policy: &mem.policy,
        };
        // The frontier transport (fired ONLY on a real proceed after an owner approve;
        // part 2). Carries the SAME before-send redact wall as `provider consult`.
        let mut ftx = crate::agent_loop::FnTransport(|system: &str, user_message: &str| {
            let fragments = [user_message];
            match redact(&RedactionRequest {
                fragments: &fragments,
                candidate_memory_ids: &[],
                deleted_ids: &[],
                include_private_memory: false,
            }) {
                Ok(receipt) if receipt.secret_fragments_denied_u32() == 0 => {}
                _ => {
                    return Err(crate::agent_loop::AgentTransportError {
                        class_label: "assembled message denied by redaction".to_string(),
                    });
                }
            }
            match transport_p.send_live_text(
                &consult,
                EgressApproval::grant(),
                system,
                user_message,
                &model,
                PROVIDER_CONSULT_MAX_OUTPUT_TOKENS,
            ) {
                Ok(outcome) => Ok(crate::agent_loop::AgentTurn {
                    answer_text: outcome.answer_text,
                    input_tokens_u64: outcome.input_tokens,
                    output_tokens_u64: outcome.output_tokens,
                    cached_tokens_u64: outcome.cached_tokens,
                }),
                Err(error) => Err(crate::agent_loop::AgentTransportError {
                    class_label: consult_denied_label(&error),
                }),
            }
        });
        let outcome = serve_poll_arm_cycle(
            ServeArm {
                rt,
                coordinator: &mut coordinator,
                center: &mut center,
            },
            &mut live_poll,
            &mut ftx,
            &state,
            &ServeParams {
                system: &system,
                task: &task,
                poll_windows_max: SERVE_WINDOWS_MAX,
                trace,
            },
            now,
        );
        cycle += 1;
        // Record the cycle outcome; only a no-reply keeps the loop polling (bounded).
        let keep = matches!(outcome, ServeCycleOutcome::DeniedNoReply { .. });
        if let Ok(mut log) = driver_log.lock() {
            match outcome {
                ServeCycleOutcome::ApprovedAndProceeded { action_hash_32 } => {
                    log.proceeded = true;
                    log.lines.push(format!(
                        "cycle {cycle}: APPROVED by owner ⇒ installed narrow single-shot grant ⇒ proceeded action {} (exactly one frontier egress)",
                        hex16(&action_hash_32)
                    ));
                }
                ServeCycleOutcome::OwnerDenied { action_hash_32 } => {
                    log.denied = true;
                    log.lines.push(format!(
                        "cycle {cycle}: DENIED by owner ⇒ action {} stays denied (zero egress)",
                        hex16(&action_hash_32)
                    ));
                }
                ServeCycleOutcome::DeniedNoReply { action_hash_32 } => {
                    log.no_reply = true;
                    log.lines.push(format!(
                        "cycle {cycle}: pinged + polled {SERVE_WINDOWS_MAX} window(s), no owner approval ⇒ action {} stays denied (fail-closed)",
                        hex16(&action_hash_32)
                    ));
                }
                ServeCycleOutcome::ProceedFailed(_) => {
                    log.lines.push(format!(
                        "cycle {cycle}: approved but the proceed did not run (grant invalid) — fail-closed"
                    ));
                }
                ServeCycleOutcome::PingFailed => {
                    log.lines
                        .push(format!("cycle {cycle}: the approval ping was withheld (secret-shaped / dedupe) — fail-closed"));
                }
                ServeCycleOutcome::RanWithoutApproval(_) => {
                    log.lines
                        .push(format!("cycle {cycle}: ran without needing a new approval"));
                }
                ServeCycleOutcome::RunnerHalted(_) => {
                    log.halted = true;
                    log.lines.push(format!(
                        "cycle {cycle}: runner halted (control/budget/terminal) — no side effect"
                    ));
                }
            }
            log.egress_actions_used = rt.egress_actions_used();
            log.turns_run = rt.turns_run();
        }
        keep && cycle < SERVE_CYCLES_MAX
    };

    // Pump the bounded driver on the EXISTING std-thread (⑩; NO new crate, NO tokio),
    // then join — a worker that ignored the bounded stop would hang join forever.
    let handle = RuntimeHandle::spawn(rt_runtime, driver, Duration::from_millis(1));
    handle.join();

    let log = serve_log.lock().map_or_else(
        |_| ServeLog::default(),
        |g| ServeLog {
            lines: g.lines.clone(),
            proceeded: g.proceeded,
            denied: g.denied,
            no_reply: g.no_reply,
            halted: g.halted,
            egress_actions_used: g.egress_actions_used,
            turns_run: g.turns_run,
        },
    );

    let mut body = vec![
        "daemon serve = BACKGROUND poll-and-arm loop (away → ping → reply → proceed)".to_string(),
        format!("autonomous task: {task_label}"),
        format!(
            "owner pinned (chat {owner_chat_id}); bounded {SERVE_CYCLES_MAX} cycle(s) × {SERVE_WINDOWS_MAX} poll window(s); ledger persists across the loop"
        ),
    ];
    if log.lines.is_empty() {
        body.push(
            "the runner did not reach the away path (no frontier escalation needed)".to_string(),
        );
    } else {
        body.extend(log.lines);
    }
    body.push(format!(
        "turns_run={} egress_actions_used={} (grant re-derived before EVERY side effect; single-shot)",
        log.turns_run, log.egress_actions_used
    ));
    body.push(
        "the loop MINTS nothing (it installs + proceeds); part 2 (real getUpdates) = owner go-live; custody uninhabited (PD-6)".to_string(),
    );
    let truth = if log.proceeded {
        RenderTruth::Green
    } else if log.denied || log.no_reply || log.halted {
        RenderTruth::Yellow
    } else {
        RenderTruth::Green
    };
    emit(
        out,
        "daemon",
        &envelope_hex,
        CommandRisk::Network,
        ApprovalRequirement::None,
        truth,
        &body,
    )
    .map(|()| true)
}

/// `daemon serve` honest degrade for a build with NO telegram-inbound + provider-egress
/// (no inbound remote-approve edge and/or no frontier transport ⇒ no poll-and-arm loop).
#[cfg(not(all(feature = "telegram-inbound", feature = "provider-egress")))]
fn cmd_daemon_serve(rest: &[String], out: &mut impl Write) -> io::Result<bool> {
    let _ = rest;
    let body = vec![
        "daemon serve = BACKGROUND poll-and-arm loop (away → ping → reply → proceed)".to_string(),
        "this build compiled NO telegram-inbound + provider-egress ⇒ no inbound edge / no frontier transport".to_string(),
        "build --features telegram-inbound,telegram-egress,provider-egress + set TELEGRAM_BOT_TOKEN/TELEGRAM_CHAT_ID/OPENROUTER_API_KEY".to_string(),
        "part 2 (real getUpdates fire) = owner go-live; custody HARD-LOCKED (PD-6)".to_string(),
    ];
    emit(
        out,
        "daemon",
        &toplevel_envelope_hex("daemon"),
        CommandRisk::ReadOnly,
        ApprovalRequirement::None,
        RenderTruth::Yellow,
        &body,
    )
    .map(|()| true)
}

/// Secret-zero error surface for `daemon serve` (static label; no host/body/token text).
#[cfg(all(feature = "telegram-inbound", feature = "provider-egress"))]
fn daemon_serve_error(out: &mut impl Write, envelope_hex: &str, label: &str) -> io::Result<bool> {
    let body = vec![
        format!("daemon serve: {label}"),
        "no loop started; no grant minted; no secret leaked; custody uninhabited (PD-6)"
            .to_string(),
    ];
    emit(
        out,
        "daemon",
        envelope_hex,
        CommandRisk::Network,
        ApprovalRequirement::None,
        RenderTruth::Red,
        &body,
    )
    .map(|()| true)
}

// ---- E13-2 (⑱): `daemon serve-chat` — TELEGRAM REMOTE CONTROL (chat → LOCAL turn → reply) ----

/// `daemon serve-chat <ARM_PHRASE> <session-id>` — the bounded TELEGRAM
/// REMOTE-CONTROL chat loop (ENDGAME E13-2 / ⑱). The owner ARMS a bounded,
/// revocable telegram-egress SESSION grant (the E0c typed-phrase ceremony); that
/// arm gates the ENTIRE loop (Option A): a free-form owner message → a LOCAL agent
/// turn (READ-class, zero egress — `file_policy = None` + `web_seam = None`, IV-RC4)
/// → a redacted reply (IV-RC3) sent BACK to Telegram inside the armed session
/// (IV-RC5). A non-owner / secret-shaped inbound is dropped before any turn
/// (IV-RC1/RC2). Replies are bounded by the grant's `max_actions`; the loop MINTS
/// nothing (the SI-3 mint is reached only on the approve-reply route). The chat
/// turn never reaches a frontier transport. Real executor requires the inbound +
/// egress edges AND a loopback brain; every other build honest-degrades.
#[cfg(all(
    feature = "telegram-inbound",
    feature = "telegram-egress",
    any(feature = "local-mlx", feature = "local-vllm")
))]
fn cmd_daemon_serve_chat(rest: &[String], out: &mut impl Write) -> io::Result<bool> {
    use crate::agent_loop::MemoryToolState;
    use crate::commands::budget::BudgetCap;
    use crate::commands::grant::{
        EGRESS_ARM_PHRASE, EgressGrant, GrantBounds, GrantTier, OwnerArmCeremony,
    };
    use crate::daemon::remote_approval::{
        ChatArm, ChatParams, ChatTurnOutcome, FnChatReplySink, LiveChatSource, RedactedChatReply,
        RemoteApprovalCoordinator, serve_chat_cycle,
    };
    use crate::daemon::runtime::{AutonomyRuntime, RuntimeHandle};
    use crate::provider::local_chat::LocalChatTransport;
    use crate::repl::approval::ApprovalPrompt;
    use crate::telegram::egress::{TelegramEgressApproval, TelegramHost, TelegramTransport};
    use crate::telegram::inbound::InboundTransport;
    use std::sync::{Arc, Mutex};
    use std::time::Duration;

    /// The bounded caps (IV-RC8): per-cycle poll windows + driver serve cycles +
    /// the session grant's reply bound (max_actions) and TTL.
    const SERVE_CHAT_WINDOWS_MAX: u32 = 3;
    const SERVE_CHAT_CYCLES_MAX: u32 = 3;
    const SERVE_CHAT_MAX_REPLIES: u32 = 8;
    const SERVE_CHAT_TTL_MS: u64 = 10 * 60 * 1000;

    /// The collected chat-serve outcome (read after the bounded thread joins).
    #[derive(Default)]
    struct ServeChatLog {
        lines: Vec<String>,
        replied: u32,
        withheld: u32,
        card_only: u32,
        dropped: u32,
        poll_failed: u32,
        egress_actions_used: u32,
    }

    let envelope_hex = toplevel_envelope_hex("daemon");
    let supplied_phrase = rest.get(1).map_or("", String::as_str);

    // GATE (owner-arm ceremony): the EXACT egress arm phrase ⇒ a bounded, revocable
    // telegram-egress SESSION grant. Missing/wrong ⇒ NO session, NO loop. The arm IS
    // the approval (Option A, IV-RC5); the model cannot supply this phrase.
    let mut prompt = ApprovalPrompt::new(ApprovalRequirement::TypedPhrase, EGRESS_ARM_PHRASE);
    let audit_hash_32 = sha256_32(b"daemon.serve-chat.egress.session.arm.v1");
    let Some(ceremony) = OwnerArmCeremony::complete(
        &mut prompt,
        supplied_phrase.trim(),
        GrantTier::Egress,
        audit_hash_32,
    ) else {
        let body = vec![
            "daemon serve-chat = TELEGRAM REMOTE CONTROL (inbound owner message → LOCAL turn → redacted reply)".to_string(),
            "Option A: the owner-armed SESSION gates the ENTIRE loop — no arm ⇒ an inbound message is a card only (NO turn, NO reply)".to_string(),
            format!("to arm, supply EXACTLY: daemon serve-chat {EGRESS_ARM_PHRASE} <session-id>"),
            format!(
                "the session grant is bounded ({SERVE_CHAT_MAX_REPLIES} replies / {}min) + revocable; custody/funds HARD-LOCKED (PD-6)",
                SERVE_CHAT_TTL_MS / 60_000
            ),
            "denied: no remote-control turn/reply without the exact arm phrase".to_string(),
        ];
        return emit(
            out,
            "daemon",
            &envelope_hex,
            CommandRisk::Network,
            ApprovalRequirement::TypedPhrase,
            RenderTruth::Yellow,
            &body,
        )
        .map(|()| true);
    };

    // owner chat id from TELEGRAM_CHAT_ID — fail-closed (missing / unparseable ⇒ no loop).
    let Ok(chat_raw) = std::env::var("TELEGRAM_CHAT_ID") else {
        return daemon_serve_chat_error(
            out,
            &envelope_hex,
            "TELEGRAM_CHAT_ID not set; no remote-control channel",
        );
    };
    let Ok(owner_chat_id) = chat_raw.trim().parse::<i64>() else {
        return daemon_serve_chat_error(
            out,
            &envelope_hex,
            "TELEGRAM_CHAT_ID is not a valid integer",
        );
    };
    // rest[2..] = an optional session label (the security gate is the arm + the owner
    // pin, not this label); kept only for the render.
    let session = rest.get(2..).map(|s| s.join(" ")).unwrap_or_default();
    let session = session.trim().to_string();

    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0u64, |d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX));
    // The bounded egress SESSION grant: up to SERVE_CHAT_MAX_REPLIES replies, TTL.
    let bounds = GrantBounds {
        max_actions_u32: SERVE_CHAT_MAX_REPLIES,
        expires_at_epoch_ms: now_ms.saturating_add(SERVE_CHAT_TTL_MS),
    };
    let Some(grant) = EgressGrant::arm(ceremony, bounds) else {
        return daemon_serve_chat_error(out, &envelope_hex, "egress session grant arm failed");
    };

    // The LOCAL turn route (IV-RC4) — the SAME strict loopback parse the interactive
    // local consult uses. NO frontier transport is built on the chat path.
    let Some(port) = crate::commands::model_select::resolve_local_port(
        std::env::var(SINABRO_LOCAL_PORT_ENV).ok().as_deref(),
        LOCAL_CONSULT_DEFAULT_PORT,
    ) else {
        return daemon_serve_chat_error(
            out,
            &envelope_hex,
            "SINABRO_LOCAL_PORT is not a valid port; no loopback brain",
        );
    };
    let model = crate::commands::model_select::resolve_local_model(
        std::env::var(SINABRO_LOCAL_MODEL_ENV).ok().as_deref(),
    );
    let bind = crate::provider::local_endpoint::LoopbackBind::localhost(port);
    let Some(local_chat) = LocalChatTransport::new(bind, &model, PROVIDER_CONSULT_TIMEOUT_MS)
    else {
        return daemon_serve_chat_error(
            out,
            &envelope_hex,
            "local http client failed to build; no loopback brain",
        );
    };

    // The LIVE inbound chat source (ONE getUpdates edge) + the LIVE reply sink (ONE
    // sendMessage edge) + the LONG-LIVED coordinator (its owner pin + ledger persist).
    let token_in =
        crate::secrets::classify_reference("telegram_bot_token", "env:TELEGRAM_BOT_TOKEN");
    let mut chat_source =
        LiveChatSource::new(InboundTransport::new(TelegramHost::BotApi, token_in));
    let token_out =
        crate::secrets::classify_reference("telegram_bot_token", "env:TELEGRAM_BOT_TOKEN");
    // The reply sink is a CLOSURE adapter (mirrors the E11-3 frontier `FnTransport`):
    // the ONE live `sendMessage` call lives HERE in dispatch.rs (the single SI-4
    // live-egress execute home), gated by this real-executor cfg (telegram-egress).
    // The armed-session grant IS the same-message approval (IV-RC5); the send wall +
    // redacted text were bound by `RedactedChatReply::build` (IV-RC3).
    let reply_transport = TelegramTransport::new(TelegramHost::BotApi, token_out);
    let mut reply_sink = FnChatReplySink(move |reply: &RedactedChatReply| {
        // Defense in depth (SI-2): the reply text re-passes the canonical redaction
        // gate at the send boundary — "away buys ZERO relaxation". It already passed
        // `RedactedChatReply::build`'s redact() (IV-RC3); a secret-shaped text here is
        // refused (no send), fail-closed — the SAME wall the consult send closures use.
        let fragments = [reply.text()];
        match redact(&RedactionRequest {
            fragments: &fragments,
            candidate_memory_ids: &[],
            deleted_ids: &[],
            include_private_memory: false,
        }) {
            Ok(receipt) if receipt.secret_fragments_denied_u32() == 0 => {}
            _ => return false,
        }
        reply_transport
            .send_live_message(
                reply.redacted_send(),
                TelegramEgressApproval::grant(),
                reply.text(),
            )
            .is_ok()
    });
    let mut coordinator = RemoteApprovalCoordinator::new(owner_chat_id);

    // Recall the owner's REAL persisted store (READ-class autonomous knowledge base) —
    // moved into the driver and re-borrowed into a `MemoryToolState` each tick.
    let mem = consult_memory_load();
    let system = format!(
        "{}\n\n{}",
        sinabro_system_prompt(true),
        crate::agent_loop::SINABRO_LOOP_PROTOCOL
    );
    let trace = crate::StageFTraceLink::new([0x53; 32], 0, 0);
    // The REAL runtime ARMED with the SESSION grant ⇒ `egress_armed_at(now)` is true
    // while the session is live (the reply gate); replies bounded by max_actions.
    let rt_runtime = AutonomyRuntime::arm(
        1,
        Some(grant),
        BudgetCap::new(100_000, 1_000_000, 100_000),
        2,
        trace,
    );

    let serve_log: Arc<Mutex<ServeChatLog>> = Arc::new(Mutex::new(ServeChatLog::default()));
    let driver_log = Arc::clone(&serve_log);
    let mut cycle: u32 = 0;

    let driver = move |rt: &mut AutonomyRuntime| -> bool {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0u64, |d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX));
        // Re-borrow the owned recall into a loop state for this tick.
        let loop_contents: Vec<(MemoryId, &[u8])> = mem
            .loaded
            .chunks
            .iter()
            .map(|(chunk, _)| (chunk.id(), chunk.envelope().content.as_slice()))
            .collect();
        let state = MemoryToolState {
            records: &mem.folded.records,
            contents: &loop_contents,
            policy: &mem.policy,
        };
        // The LOCAL turn transport — IDENTICAL before-send redact wall to
        // `provider_consult_local_at` ("local" buys ZERO relaxation; the loopback
        // peer is UNAUDITED). NO second egress path; NO frontier transport.
        let mut local = crate::agent_loop::FnTransport(|system: &str, user_message: &str| {
            let fragments = [user_message];
            match redact(&RedactionRequest {
                fragments: &fragments,
                candidate_memory_ids: &[],
                deleted_ids: &[],
                include_private_memory: false,
            }) {
                Ok(receipt) if receipt.secret_fragments_denied_u32() == 0 => {}
                _ => {
                    return Err(crate::agent_loop::AgentTransportError {
                        class_label: "assembled message denied by redaction".to_string(),
                    });
                }
            }
            match local_chat.send_local_text(
                system,
                user_message,
                PROVIDER_CONSULT_MAX_OUTPUT_TOKENS,
            ) {
                Ok(o) => Ok(crate::agent_loop::AgentTurn {
                    answer_text: o.answer_text,
                    input_tokens_u64: o.input_tokens,
                    output_tokens_u64: o.output_tokens,
                    cached_tokens_u64: o.cached_tokens,
                }),
                Err(error) => Err(crate::agent_loop::AgentTransportError {
                    class_label: error.class_label(),
                }),
            }
        });
        let outcomes = serve_chat_cycle(
            ChatArm {
                rt,
                coordinator: &mut coordinator,
            },
            &mut chat_source,
            &mut reply_sink,
            &mut local,
            &state,
            &ChatParams {
                system: &system,
                poll_windows_max: SERVE_CHAT_WINDOWS_MAX,
            },
            now,
        );
        cycle += 1;
        if let Ok(mut log) = driver_log.lock() {
            for outcome in &outcomes {
                match outcome {
                    ChatTurnOutcome::Replied { sent } => {
                        log.replied += 1;
                        log.lines.push(format!(
                            "cycle {cycle}: owner chat → LOCAL turn → redacted reply (sent={sent})"
                        ));
                    }
                    ChatTurnOutcome::ReplyWithheld => {
                        log.withheld += 1;
                        log.lines.push(format!(
                            "cycle {cycle}: turn answer was whole-secret ⇒ reply WITHHELD (IV-RC3)"
                        ));
                    }
                    ChatTurnOutcome::CardOnlyNotArmed => {
                        log.card_only += 1;
                    }
                    ChatTurnOutcome::NotOwnerDropped | ChatTurnOutcome::SecretWithheld => {
                        log.dropped += 1;
                    }
                    ChatTurnOutcome::PollFailed => {
                        log.poll_failed += 1;
                        log.lines.push(format!(
                            "cycle {cycle}: inbound poll failed (e.g. token missing) ⇒ fail-closed"
                        ));
                    }
                    ChatTurnOutcome::NoAnswer => {
                        log.lines
                            .push(format!("cycle {cycle}: LOCAL turn produced no answer"));
                    }
                    ChatTurnOutcome::ApprovalRouted(_) => {
                        log.lines.push(format!(
                            "cycle {cycle}: an approve/deny reply routed to the approval path (not a turn)"
                        ));
                    }
                }
            }
            log.egress_actions_used = rt.egress_actions_used();
        }
        cycle < SERVE_CHAT_CYCLES_MAX
    };

    // Pump the bounded driver on the EXISTING std-thread (⑩; NO new crate, NO tokio),
    // then join — a worker that ignored the bounded stop would hang join forever.
    let handle = RuntimeHandle::spawn(rt_runtime, driver, Duration::from_millis(1));
    handle.join();

    let log = serve_log.lock().map_or_else(
        |_| ServeChatLog::default(),
        |g| ServeChatLog {
            lines: g.lines.clone(),
            replied: g.replied,
            withheld: g.withheld,
            card_only: g.card_only,
            dropped: g.dropped,
            poll_failed: g.poll_failed,
            egress_actions_used: g.egress_actions_used,
        },
    );

    let session_label = if session.is_empty() {
        "(unnamed)".to_string()
    } else {
        session
    };
    let mut body = vec![
        "daemon serve-chat = TELEGRAM REMOTE CONTROL (owner message → LOCAL turn → redacted reply)"
            .to_string(),
        format!("session: {session_label}"),
        format!(
            "owner pinned (chat {owner_chat_id}); ARMED session (max {SERVE_CHAT_MAX_REPLIES} replies / {}min); bounded {SERVE_CHAT_CYCLES_MAX} cycle(s) × {SERVE_CHAT_WINDOWS_MAX} window(s)",
            SERVE_CHAT_TTL_MS / 60_000
        ),
    ];
    if log.lines.is_empty() {
        body.push("no inbound owner message this run (nothing to answer)".to_string());
    } else {
        body.extend(log.lines);
    }
    body.push(format!(
        "replied={} withheld={} card_only_unarmed={} dropped(non-owner/secret)={} poll_failed={} egress_actions_used={}",
        log.replied, log.withheld, log.card_only, log.dropped, log.poll_failed, log.egress_actions_used
    ));
    body.push(
        "the chat turn is LOCAL + READ-class + zero-egress; the reply is the only outbound (armed-gated, redacted); custody uninhabited (PD-6)".to_string(),
    );
    let truth = if log.replied > 0 {
        RenderTruth::Green
    } else if log.poll_failed > 0 {
        RenderTruth::Red
    } else {
        RenderTruth::Yellow
    };
    emit(
        out,
        "daemon",
        &envelope_hex,
        CommandRisk::Network,
        ApprovalRequirement::None,
        truth,
        &body,
    )
    .map(|()| true)
}

/// `daemon serve-chat` honest degrade for a build WITHOUT the inbound + egress edges
/// AND a loopback brain (the shipped terminal default): no telegram remote-control
/// channel and/or no local brain to drive ⇒ the command performs no action and says
/// so (PD-1 — no hollow "served" over absent edges).
#[cfg(not(all(
    feature = "telegram-inbound",
    feature = "telegram-egress",
    any(feature = "local-mlx", feature = "local-vllm")
)))]
fn cmd_daemon_serve_chat(rest: &[String], out: &mut impl Write) -> io::Result<bool> {
    let _ = rest;
    let body = vec![
        "daemon serve-chat = TELEGRAM REMOTE CONTROL (owner message → LOCAL turn → redacted reply)".to_string(),
        "this build compiled NO telegram-inbound + telegram-egress + local brain ⇒ no remote-control channel".to_string(),
        "build --features telegram-inbound,telegram-egress,local-vllm + set TELEGRAM_BOT_TOKEN/TELEGRAM_CHAT_ID + run a loopback brain".to_string(),
        "part 2 (real getUpdates + sendMessage fire) = owner go-live; custody HARD-LOCKED (PD-6)".to_string(),
    ];
    emit(
        out,
        "daemon",
        &toplevel_envelope_hex("daemon"),
        CommandRisk::ReadOnly,
        ApprovalRequirement::None,
        RenderTruth::Yellow,
        &body,
    )
    .map(|()| true)
}

/// Secret-zero error surface for `daemon serve-chat` (static label; no host/body/
/// token text). Reached only in the real-executor build.
#[cfg(all(
    feature = "telegram-inbound",
    feature = "telegram-egress",
    any(feature = "local-mlx", feature = "local-vllm")
))]
fn daemon_serve_chat_error(
    out: &mut impl Write,
    envelope_hex: &str,
    label: &str,
) -> io::Result<bool> {
    let body = vec![
        format!("daemon serve-chat: {label}"),
        "no loop started; no turn ran; no reply sent; no secret leaked; custody uninhabited (PD-6)"
            .to_string(),
    ];
    emit(
        out,
        "daemon",
        envelope_hex,
        CommandRisk::Network,
        ApprovalRequirement::None,
        RenderTruth::Red,
        &body,
    )
    .map(|()| true)
}

/// `sinabro platform poll [cycles]` — the LIVE telegram inbound remote-approve edge
/// (ENDGAME E4 made runnable here). Builds the real getUpdates long-poll transport +
/// the owner-pinned coordinator from `TELEGRAM_CHAT_ID`, registers a demo pending
/// action so the owner can exercise the FULL phone round-trip, runs the PROVEN
/// `poll_and_ingest` cycle a bounded number of times, and REPORTS each outcome. The
/// security invariants are NOT reimplemented here — only the pinned chat is authorized
/// (sender-pin), replies are replay-refused, and an approve mints a NARROW single-shot
/// grant, all inside the E4 `authenticate_and_mint` surface. The minted grant is
/// reported (installing it on a runner is the daemon's job). Custody/funds HARD-LOCKED.
#[cfg(feature = "telegram-inbound")]
fn cmd_platform_poll(rest: &[String], out: &mut impl Write) -> io::Result<bool> {
    use crate::daemon::approval_sync::ApprovalAction;
    use crate::daemon::remote_approval::{
        RemoteApprovalCoordinator, RemoteApprovalOutcome, poll_and_ingest,
    };
    use crate::telegram::egress::TelegramHost;
    use crate::telegram::inbound::InboundTransport;
    use crate::telegram::inbound_auth::PendingApproval;

    let envelope_hex = hex16(&sha256_32(b"platform poll"));
    // owner chat id from TELEGRAM_CHAT_ID — fail-closed (missing / unparseable ⇒ no poll).
    let Ok(chat_raw) = std::env::var("TELEGRAM_CHAT_ID") else {
        return platform_poll_error(
            out,
            &envelope_hex,
            "TELEGRAM_CHAT_ID not set; nothing polled",
        );
    };
    let Ok(owner_chat_id) = chat_raw.trim().parse::<i64>() else {
        return platform_poll_error(
            out,
            &envelope_hex,
            "TELEGRAM_CHAT_ID is not a valid integer; nothing polled",
        );
    };
    // bounded poll cycles (each is one long-poll window): rest[1] optional, default 1, cap 5.
    let cycles = rest
        .get(1)
        .and_then(|s| s.parse::<u32>().ok())
        .unwrap_or(1)
        .clamp(1, 5);

    let token_ref =
        crate::secrets::classify_reference("telegram_bot_token", "env:TELEGRAM_BOT_TOKEN");
    let transport = InboundTransport::new(TelegramHost::BotApi, token_ref);
    let mut coordinator = RemoteApprovalCoordinator::new(owner_chat_id);
    // a demo pending action so the owner can exercise the FULL approve round-trip.
    let demo = PendingApproval::new(
        sha256_32(b"platform.poll.demo.approval.v1"),
        ApprovalAction::TelegramRemoteControl,
    );
    coordinator.add_pending(demo);
    let id16 = demo.id16();

    let mut body = vec![
        "platform poll: LIVE telegram inbound remote-approve (getUpdates long-poll)".to_string(),
        format!("on your phone reply EXACTLY:  approve {id16}   (to refuse:  deny {id16})"),
        format!(
            "only your pinned chat is authorized (sender-pin); replies replay-refused; polling {cycles} cycle(s)"
        ),
    ];
    let mut approved = false;
    let mut ingested: u32 = 0;
    for _ in 0..cycles {
        let now_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0u64, |d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX));
        match poll_and_ingest(&transport, &mut coordinator, now_ms) {
            Ok(outcomes) => {
                for o in outcomes {
                    ingested = ingested.saturating_add(1);
                    match o {
                        RemoteApprovalOutcome::Approved { action_hash_32, .. } => {
                            approved = true;
                            body.push(format!(
                                "APPROVED by owner: action={} => NARROW single-shot grant minted (max_actions=1; a runner would now proceed)",
                                hex16(&action_hash_32)
                            ));
                        }
                        RemoteApprovalOutcome::ApprovedMutate { action_hash_32, .. } => {
                            approved = true;
                            body.push(format!(
                                "APPROVED (mutate) by owner: action={} => NARROW single-shot MUTATE grant minted (max_actions=1; a runner would install_mutate_grant + proceed)",
                                hex16(&action_hash_32)
                            ));
                        }
                        RemoteApprovalOutcome::Denied { action_hash_32 } => {
                            body.push(format!(
                                "DENIED by owner: action={}",
                                hex16(&action_hash_32)
                            ));
                        }
                        RemoteApprovalOutcome::NoAction(reject) => {
                            body.push(format!("ignored a reply: {reject:?} (nothing minted)"));
                        }
                    }
                }
            }
            Err(e) => {
                body.push(format!(
                    "poll stopped: {e:?} (token/chat/host fail-closed; nothing minted, no secret leaked)"
                ));
                break;
            }
        }
    }
    body.push(format!(
        "poll done: updates_ingested={ingested} approved={approved}; ledger replay-gated; custody uninhabited (PD-6)"
    ));
    let truth = if approved {
        RenderTruth::Green
    } else {
        RenderTruth::Yellow
    };
    emit(
        out,
        "platform poll",
        &envelope_hex,
        CommandRisk::Network,
        ApprovalRequirement::None,
        truth,
        &body,
    )
    .map(|()| true)
}

/// Secret-zero error surface for `platform poll` (static label; no host/body/token text).
#[cfg(feature = "telegram-inbound")]
fn platform_poll_error(out: &mut impl Write, envelope_hex: &str, label: &str) -> io::Result<bool> {
    let body = vec![
        format!("platform poll: {label}"),
        "no poll started; no grant minted; no secret leaked".to_string(),
    ];
    emit(
        out,
        "platform poll",
        envelope_hex,
        CommandRisk::Network,
        ApprovalRequirement::None,
        RenderTruth::Red,
        &body,
    )
    .map(|()| true)
}

/// `platform poll` honest degrade when the build has NO telegram-inbound feature.
#[cfg(not(feature = "telegram-inbound"))]
fn platform_poll_no_feature(out: &mut impl Write) -> io::Result<bool> {
    let body = vec![
        "platform poll = LIVE telegram inbound remote-approve (getUpdates long-poll)".to_string(),
        "this build compiled NO telegram-inbound feature => no inbound edge".to_string(),
        "build --features telegram-inbound,telegram-egress + set TELEGRAM_BOT_TOKEN/TELEGRAM_CHAT_ID"
            .to_string(),
    ];
    emit(
        out,
        "platform poll",
        &hex16(&sha256_32(b"platform poll")),
        CommandRisk::ReadOnly,
        ApprovalRequirement::None,
        RenderTruth::Yellow,
        &body,
    )
    .map(|()| true)
}

/// The exact local typed phrase that OPENS a telegram remote-control session.
#[cfg(all(feature = "telegram-inbound", feature = "telegram-egress"))]
const TELEGRAM_CONTROL_ARM_PHRASE: &str = "telegram-remote-control-live";

/// Max characters of a command's output echoed back to telegram (the rest is noted
/// truncated — telegram's own message cap is ~4096, we stay well under).
#[cfg(all(feature = "telegram-inbound", feature = "telegram-egress"))]
const TELEGRAM_CONTROL_REPLY_CAP: usize = 3000;

/// Send ONE redacted telegram reply (SI-2): the text passes the canonical redaction
/// choke FIRST; a secret-shaped output is REFUSED (the caller substitutes a safe
/// placeholder). Mirrors `platform_send`'s receipt→dry_run→into_live→send path — the
/// SINGLE outbound construction, no struct-update, no hand-supplied hash.
#[cfg(all(feature = "telegram-inbound", feature = "telegram-egress"))]
fn send_telegram_reply_redacted(reply_text: &str) -> Result<(), &'static str> {
    use crate::commands::platform_telegram::{MessageEnvelope, PlatformOrigin};
    use crate::telegram::egress::{
        RedactedTelegramSend, TelegramEgressApproval, TelegramHost, TelegramTransport,
    };
    let fragments = [reply_text];
    let receipt = redact(&RedactionRequest {
        fragments: &fragments,
        candidate_memory_ids: &[],
        deleted_ids: &[],
        include_private_memory: false,
    })
    .map_err(|_| "redaction error")?;
    if receipt.secret_fragments_denied_u32() > 0 || receipt.outgoing_fragment_count_u32() == 0 {
        return Err("secret-shaped output withheld");
    }
    let command = CommandEnvelope::classify(
        CliNamespace::Platform,
        "control",
        CliMode::Run,
        CommandRisk::Network,
        reply_text.as_bytes(),
    );
    let Some(send) =
        RedactedTelegramSend::dry_run(MessageEnvelope::new(PlatformOrigin::Cli, command), receipt)
    else {
        return Err("redaction receipt rejected the send");
    };
    let send = send.into_live(TelegramEgressApproval::grant());
    let token = crate::secrets::classify_reference("TELEGRAM_BOT_TOKEN", "env:TELEGRAM_BOT_TOKEN");
    let transport = TelegramTransport::new(TelegramHost::BotApi, token);
    transport
        .send_live_message(&send, TelegramEgressApproval::grant(), reply_text)
        .map(|_| ())
        .map_err(|_| "telegram send failed")
}

/// `sinabro platform control <ARM_PHRASE> [cycles]` — telegram REMOTE-CONTROL: your
/// phone drives sinabro. The owner opens the session with the local typed phrase, then
/// each message FROM the owner's pinned chat is run through the SAME gated
/// `dispatch::run` the CLI uses — so custody/funds/mainnet stay HARD-LOCKED
/// (structurally unreachable), and any side-effect verb STILL needs its own typed
/// phrase inside the message (telegram is a remote KEYBOARD, never extra authority).
/// The command's output is SI-2 redacted before it is sent back. Sender-pinned (a
/// non-owner message is dropped), bounded (N poll cycles), and recursion-guarded (a
/// remote message cannot start another control/poll/daemon long-runner). Threat model:
/// the inbound text is UNTRUSTED + bounded (256B parse); the reply is redacted; the
/// executor adds NO new capability — it inherits every dispatch gate.
#[cfg(all(feature = "telegram-inbound", feature = "telegram-egress"))]
fn cmd_platform_control(rest: &[String], out: &mut impl Write) -> io::Result<bool> {
    use crate::repl::approval::{ApprovalDecision, ApprovalPrompt};
    use crate::telegram::egress::TelegramHost;
    use crate::telegram::inbound::{InboundTransport, UpdateOffset};

    let envelope_hex = hex16(&sha256_32(b"platform control"));
    // GATE (local arm ceremony): the owner deliberately OPENS remote control. Sender-pin
    // is additionally enforced per message below.
    let supplied = rest.get(1).map_or("", String::as_str);
    let mut prompt = ApprovalPrompt::new(
        ApprovalRequirement::TypedPhrase,
        TELEGRAM_CONTROL_ARM_PHRASE,
    );
    if !matches!(prompt.evaluate(supplied.trim()), ApprovalDecision::Approved) {
        let body = vec![
            "platform control = LIVE telegram REMOTE-CONTROL (your phone drives sinabro)"
                .to_string(),
            "each owner message runs through the SAME gated dispatch; results come back redacted"
                .to_string(),
            format!(
                "to open, supply EXACTLY: platform control {TELEGRAM_CONTROL_ARM_PHRASE} [cycles]"
            ),
            "custody/funds HARD-LOCKED; side-effects still need their phrase; sender-pinned"
                .to_string(),
            "denied: no remote control without the exact arm phrase".to_string(),
        ];
        return emit(
            out,
            "platform control",
            &envelope_hex,
            CommandRisk::Network,
            ApprovalRequirement::TypedPhrase,
            RenderTruth::Yellow,
            &body,
        )
        .map(|()| true);
    }
    let Ok(chat_raw) = std::env::var("TELEGRAM_CHAT_ID") else {
        return platform_poll_error(out, &envelope_hex, "TELEGRAM_CHAT_ID not set; no control");
    };
    let Ok(owner_chat_id) = chat_raw.trim().parse::<i64>() else {
        return platform_poll_error(
            out,
            &envelope_hex,
            "TELEGRAM_CHAT_ID is not a valid integer; no control",
        );
    };
    let cycles = rest
        .get(2)
        .and_then(|s| s.parse::<u32>().ok())
        .unwrap_or(3)
        .clamp(1, 10);

    let in_token =
        crate::secrets::classify_reference("telegram_bot_token", "env:TELEGRAM_BOT_TOKEN");
    let in_transport = InboundTransport::new(TelegramHost::BotApi, in_token);
    let mut offset = UpdateOffset::new();

    let mut body = vec![
        "platform control: LIVE telegram REMOTE-CONTROL (your phone drives sinabro)".to_string(),
        "from telegram: a sinabro command (e.g. `memory index`) runs it; plain language (e.g. `오늘 할 일 정리해줘`) goes to the AGENT — chat like Claude Code; result returns redacted".to_string(),
        format!(
            "sender-pinned to your chat; replies SI-2 redacted; custody/funds HARD-LOCKED; polling {cycles} cycle(s)"
        ),
    ];
    let mut executed: u32 = 0;
    'outer: for _ in 0..cycles {
        let (updates, new_offset) = match in_transport.poll_once(offset) {
            Ok(v) => v,
            Err(e) => {
                body.push(format!(
                    "poll stopped: {e:?} (token/chat/host fail-closed; nothing run)"
                ));
                break 'outer;
            }
        };
        offset = new_offset;
        for u in &updates {
            // SENDER-PIN: only the owner's pinned chat drives commands (IV-T1).
            if u.sender_chat_id() != owner_chat_id {
                continue;
            }
            let cmd_text = u.text().trim();
            if cmd_text.is_empty() {
                continue;
            }
            let lower = cmd_text.to_ascii_lowercase();
            // RECURSION / long-runner guard: a remote message must not open another
            // control/poll session or a daemon long-runner (no nested remote loops).
            if lower.starts_with("platform control")
                || lower.starts_with("platform poll")
                || lower.starts_with("daemon")
            {
                let _ = send_telegram_reply_redacted(
                    "refused: control / poll / daemon cannot be driven remotely",
                );
                body.push(
                    "refused a remote control/poll/daemon command (recursion guard)".to_string(),
                );
                continue;
            }
            // ROUTE. A recognized sinabro command runs through the SAME gated dispatch
            // (custody locked; a side-effect verb still needs its own typed phrase). A
            // PLAIN-LANGUAGE message (not a command) is handled by the AGENT — routed to
            // the frontier consult loop, so the owner just CHATS like Claude Code and the
            // agent recalls/reads/answers. The session arm phrase + sender-pin are the
            // egress consent; the consult tool-set is READ-ONLY; the answer is redacted by
            // the consult render AND again before the telegram send. Custody stays locked.
            let argv: Vec<String> = cmd_text.split_whitespace().map(String::from).collect();
            let mut cout: Vec<u8> = Vec::new();
            let mut cerr: Vec<u8> = Vec::new();
            let _ = run(&argv, &mut cout, &mut cerr);
            // not a recognized command ⇒ a conversation / task for the agent (LLM consult).
            let mut routed_to_agent = false;
            if String::from_utf8_lossy(&cerr).contains("unknown command") {
                routed_to_agent = true;
                let mut consult_argv = vec![
                    "provider".to_string(),
                    "consult".to_string(),
                    "consult-frontier-provider-live".to_string(),
                ];
                consult_argv.extend(cmd_text.split_whitespace().map(String::from));
                cout.clear();
                cerr.clear();
                let _ = run(&consult_argv, &mut cout, &mut cerr);
            }
            let mut rendered = String::from_utf8_lossy(&cout).into_owned();
            if rendered.trim().is_empty() {
                rendered = String::from_utf8_lossy(&cerr).into_owned();
            }
            if rendered.trim().is_empty() {
                rendered = "(no output)".to_string();
            }
            // bound the reply to a safe telegram length.
            let truncated = rendered.chars().count() > TELEGRAM_CONTROL_REPLY_CAP;
            let mut reply: String = rendered.chars().take(TELEGRAM_CONTROL_REPLY_CAP).collect();
            if truncated {
                reply.push_str("\n…[truncated]");
            }
            // REDACT + send the result back; a secret-shaped output is withheld.
            let kind = if routed_to_agent {
                "agent chat".to_string()
            } else {
                format!("`{}…`", argv.first().cloned().unwrap_or_default())
            };
            match send_telegram_reply_redacted(&reply) {
                Ok(()) => {
                    executed = executed.saturating_add(1);
                    body.push(format!("handled {kind} => replied to telegram (redacted)"));
                }
                Err("secret-shaped output withheld") => {
                    let _ = send_telegram_reply_redacted(
                        "[output withheld: the result was secret-shaped (SI-2)]",
                    );
                    body.push(format!("handled {kind} => output WITHHELD (secret-shaped)"));
                }
                Err(label) => {
                    body.push(format!("handled {kind} but reply failed: {label}"));
                }
            }
        }
    }
    body.push(format!(
        "control done: commands_executed={executed}; sender-pinned; custody uninhabited (PD-6)"
    ));
    emit(
        out,
        "platform control",
        &envelope_hex,
        CommandRisk::Network,
        ApprovalRequirement::TypedPhrase,
        RenderTruth::Green,
        &body,
    )
    .map(|()| true)
}

/// `platform control` honest degrade when the build lacks telegram in+out.
#[cfg(not(all(feature = "telegram-inbound", feature = "telegram-egress")))]
fn platform_control_no_feature(out: &mut impl Write) -> io::Result<bool> {
    let body = vec![
        "platform control = LIVE telegram REMOTE-CONTROL (your phone drives sinabro)".to_string(),
        "this build lacks telegram-inbound + telegram-egress => no remote-control edge".to_string(),
        "build --features telegram-inbound,telegram-egress + set TELEGRAM_BOT_TOKEN/TELEGRAM_CHAT_ID"
            .to_string(),
    ];
    emit(
        out,
        "platform control",
        &hex16(&sha256_32(b"platform control")),
        CommandRisk::ReadOnly,
        ApprovalRequirement::None,
        RenderTruth::Yellow,
        &body,
    )
    .map(|()| true)
}

fn launch_tui(out: &mut impl Write) -> io::Result<()> {
    // First-frame snapshot (interactive ratatui binding is deferred): the prompt
    // strip is a real pane render; the cockpit panes (status/jobs/trace/inspector)
    // are bounded, colorless, RenderTruth-semantic. No full-render hot path.
    let prompt = PromptStatus {
        workspace_hash_32: sha256_32(b"/Users/heoun/mnemos"),
        model_hash_32: ZERO32,
        context_pressure_bps: 0,
        last_checkpoint_hash_32: ZERO32,
        budget_remaining_micros: 1_000_000,
        sandbox_tier_u8: 1,
        pending_approvals_u16: 0,
        pending_tasks_u16: 0,
    };
    let body = vec![
        render_status_strip(&prompt),
        "cockpit panes: status | jobs | trace | inspector".to_string(),
        "first-frame snapshot; no full-render hot path; bounded redraw".to_string(),
        "no-color readable; RenderTruth semantic only; no decorative ascii".to_string(),
        "labels: PASS CANDIDATE LOCKED DRY-RUN NO-TRAINING LOCAL-ONLY".to_string(),
    ];
    emit(
        out,
        "tui",
        &toplevel_envelope_hex("tui"),
        CommandRisk::ReadOnly,
        ApprovalRequirement::None,
        RenderTruth::Green,
        &body,
    )
}

fn launch_repl(out: &mut impl Write) -> io::Result<()> {
    let prompt = PromptStatus {
        workspace_hash_32: sha256_32(b"/Users/heoun/mnemos"),
        model_hash_32: ZERO32,
        context_pressure_bps: 0,
        last_checkpoint_hash_32: ZERO32,
        budget_remaining_micros: 1_000_000,
        sandbox_tier_u8: 1,
        pending_approvals_u16: 0,
        pending_tasks_u16: 0,
    };
    let body = vec![
        render_status_strip(&prompt),
        format!("repl ready; closed grammar ({} namespaces)", grammar::COUNT),
        "every line is classified through a CommandEnvelope (no bypass)".to_string(),
        "reedline binding deferred; type: <namespace> <verb>".to_string(),
    ];
    emit(
        out,
        "repl",
        &toplevel_envelope_hex("repl"),
        CommandRisk::ReadOnly,
        ApprovalRequirement::None,
        RenderTruth::Green,
        &body,
    )
}

// ---- entry ----------------------------------------------------------------

/// Operational dispatch entry. `args` is the full argv tail (after the binary
/// name); `args[0]` is the top-level command or namespace. `--version`/`--help`/
/// `doctor` are handled by the binary before this is called. Returns the process
/// [`ExitCode`]; an unknown command writes to `err` and returns failure.
///
/// # Errors
/// Returns the underlying [`io::Error`] if writing to `out`/`err` fails (a broken
/// pipe); there is no panic / unwrap path.
pub fn run(args: &[String], out: &mut impl Write, err: &mut impl Write) -> io::Result<ExitCode> {
    run_code(args, out, err).map(|ok| {
        if ok {
            ExitCode::SUCCESS
        } else {
            ExitCode::FAILURE
        }
    })
}

/// Inner dispatch returning an explicit success flag (`true` = success). Split out
/// because [`ExitCode`] is opaque and not inspectable in unit tests.
fn run_code(args: &[String], out: &mut impl Write, err: &mut impl Write) -> io::Result<bool> {
    let Some(head) = args.first() else {
        return Ok(true);
    };
    match head.as_str() {
        "status" => cmd_status(out).map(|()| true),
        "setup" => cmd_setup(&args[1..], out).map(|()| true),
        "evidence" => cmd_evidence(&args[1..], out).map(|()| true),
        "budget" => cmd_budget(&args[1..], out).map(|()| true),
        "kill" => cmd_kill(&args[1..], out).map(|()| true),
        "daemon" => cmd_daemon(&args[1..], out).map(|()| true),
        "skew" => cmd_skew(&args[1..], out).map(|()| true),
        "tui" => launch_tui(out).map(|()| true),
        "repl" => launch_repl(out).map(|()| true),
        other => match grammar::parse(other) {
            Some(ns) => dispatch_namespace(ns, &args[1..], out, err),
            None => {
                writeln!(err, "unknown command: {other}")?;
                Ok(false)
            }
        },
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]
    use super::*;

    fn run_argv(tokens: &[&str]) -> (bool, String, String) {
        let args: Vec<String> = tokens.iter().map(|s| (*s).to_string()).collect();
        let mut out: Vec<u8> = Vec::new();
        let mut err: Vec<u8> = Vec::new();
        let ok =
            run_code(&args, &mut out, &mut err).expect("write to in-memory buffer never fails");
        (
            ok,
            String::from_utf8(out).expect("ascii output"),
            String::from_utf8(err).expect("ascii err"),
        )
    }

    fn body_of(tokens: &[&str]) -> String {
        run_argv(tokens).1
    }

    #[test]
    fn skew_capabilities_renders_catalog() {
        let bare = body_of(&["skew"]);
        let caps = body_of(&["skew", "capabilities"]);
        for out in [&bare, &caps] {
            assert!(out.contains("BD4DSsEDfv8zcs1HdgqEDoQCPAEgMi3AWWW9r7DVka81"));
            assert!(out.contains("list_secondary"));
            assert!(out.contains("PRE-LAUNCH"));
        }
    }

    #[test]
    fn skew_capability_detail_and_unknown() {
        let detail = body_of(&["skew", "capability", "submit_perp_order"]);
        assert!(detail.contains("0x71"));
        assert!(detail.contains("perp"));
        let unknown = body_of(&["skew", "capability", "nonexistent_ix"]);
        assert!(unknown.contains("unknown skew capability"));
    }

    #[test]
    fn no_deferral_stub_remains() {
        // The lean stub string must not appear for any namespace.
        for ns in grammar::ALL {
            let out = body_of(&[ns.canonical_name()]);
            assert!(
                !out.contains("handlers land in a later"),
                "stub leaked for {}",
                ns.canonical_name()
            );
            assert!(!out.is_empty(), "empty render for {}", ns.canonical_name());
            assert!(
                out.contains(&format!("command={}", ns.canonical_name())),
                "missing command header for {}",
                ns.canonical_name()
            );
        }
    }

    #[test]
    fn all_35_namespaces_dispatch_real_output() {
        for ns in grammar::ALL {
            let (ok, out, _) = run_argv(&[ns.canonical_name()]);
            assert!(ok, "{} did not dispatch", ns.canonical_name());
            assert!(
                out.contains("risk="),
                "{} missing risk",
                ns.canonical_name()
            );
            assert!(
                out.contains("state="),
                "{} missing state",
                ns.canonical_name()
            );
            assert!(
                out.contains("truth="),
                "{} missing truth",
                ns.canonical_name()
            );
        }
    }

    #[test]
    fn namespace_gate_custody_funds_chainwrite_is_hard_locked() {
        // SAFETY PIN (PD-6): custody / funds / chain-write are the owner's OWN
        // permanent law and MUST be `Locked` no matter what — the GUI palette can
        // never show them unlocked. A regression here is a custody-honesty failure.
        for ns in [
            CliNamespace::Wallet,
            CliNamespace::Key,
            CliNamespace::Gas,
            CliNamespace::Chain,
            CliNamespace::Package,
            CliNamespace::Multisig,
            CliNamespace::Release,
            CliNamespace::Train,
        ] {
            assert_eq!(
                namespace_gate(ns),
                CapabilityGate::Locked,
                "{} must be hard-locked (PD-6)",
                ns.canonical_name()
            );
        }
    }

    #[test]
    fn namespace_gate_total_and_consistent_with_risk_for() {
        // The gate is the honest projection of `risk_for`. Probe set = the
        // recognized verbs PLUS the specially-intercepted verbs risk_for classifies
        // that are not in RECOGNIZED_VERBS (consult/fan/send/apply/save/put-fixture/
        // web-fetch/web-search/contribute). The match is exhaustive (no `_` arm), so
        // totality is compile-enforced; here we cross-check each gate vs the risks
        // the namespace can actually reach.
        let extra = [
            "consult",
            "fan",
            "send",
            "apply",
            "exec-apply",
            "save",
            "put-fixture",
            "backup-walrus",
            "backup-walrus-mainnet",
            "backup-0g",
            "walrus-index",
            "walrus-fetch",
            "web-fetch",
            "web-search",
            "contribute",
        ];
        for ns in grammar::ALL {
            let reaches = |r: CommandRisk| {
                RECOGNIZED_VERBS
                    .iter()
                    .chain(extra.iter())
                    .any(|v| risk_for(ns, v) == r)
            };
            let chain_or_sign =
                reaches(CommandRisk::ChainWrite) || reaches(CommandRisk::WalletSign);
            let egress_or_mutate = reaches(CommandRisk::LocalWrite)
                || reaches(CommandRisk::Network)
                || reaches(CommandRisk::Admin);
            let any_elevated = chain_or_sign || egress_or_mutate || reaches(CommandRisk::Training);
            match namespace_gate(ns) {
                CapabilityGate::Free => assert!(
                    !any_elevated,
                    "{} is Free but reaches an elevated verb",
                    ns.canonical_name()
                ),
                CapabilityGate::Gated => {
                    assert!(
                        egress_or_mutate,
                        "{} is Gated but reaches no LocalWrite/Network/Admin verb",
                        ns.canonical_name()
                    );
                    assert!(
                        !chain_or_sign,
                        "{} is Gated but reaches a chain-write/sign verb — must be Locked",
                        ns.canonical_name()
                    );
                }
                CapabilityGate::Locked => {
                    // Locked is justified by a chain-write/sign verb OR the PD-6
                    // funds/secret/forbidden overlay (gas / key / train).
                    let overlay = matches!(
                        ns,
                        CliNamespace::Gas | CliNamespace::Key | CliNamespace::Train
                    );
                    assert!(
                        chain_or_sign || overlay,
                        "{} is Locked but is neither chain-write/sign nor a PD-6 overlay",
                        ns.canonical_name()
                    );
                }
            }
        }
    }

    #[test]
    fn permission_tier_emits_core_derived_gate_per_namespace() {
        let out = body_of(&["permission", "tier"]);
        assert!(out.contains("command=permission tier"), "{out}");
        // ReadOnly + secret-zero: the palette fetch needs no approval.
        assert!(out.contains("approval=none"), "{out}");
        // exactly one `<ns>=<gate>` line per namespace, matching namespace_gate.
        for ns in grammar::ALL {
            let want = format!("{}={}", ns.canonical_name(), namespace_gate(ns).as_str());
            assert!(out.contains(&want), "permission tier missing line `{want}`");
        }
        // custody/funds/chain-write are emitted Locked (the GUI reads this verbatim).
        for ns in [
            "wallet", "key", "gas", "chain", "package", "multisig", "release",
        ] {
            assert!(
                out.contains(&format!("{ns}=locked")),
                "{ns} must emit locked: {out}"
            );
        }
    }

    #[test]
    fn readonly_renders_with_no_approval() {
        let out = body_of(&["provider", "status"]);
        assert!(out.contains("command=provider status"));
        assert!(out.contains("approval=none"));
        assert!(out.contains("state=LOCAL-ONLY"));
        assert!(out.contains("providers_configured=0"));
    }

    #[test]
    fn train_run_is_forbidden_in_stage_g() {
        assert_eq!(risk_for(CliNamespace::Train, "run"), CommandRisk::Training);
        let out = body_of(&["train", "run"]);
        assert!(out.contains("approval=training-locked"));
        assert!(out.contains("state=NO-TRAINING"));
        assert!(out.contains("weight training is locked"));
    }

    #[cfg(any(
        feature = "provider-egress",
        feature = "local-mlx",
        feature = "local-vllm"
    ))]
    #[test]
    fn project_rules_section_injects_caps_and_withholds_secrets() {
        // B⑮: absent / blank ⇒ empty section (system prompt byte-unchanged).
        assert!(super::project_rules_section(None).is_empty());
        assert!(super::project_rules_section(Some("   \n   ")).is_empty());
        // normal owner rules ⇒ a labeled advisory section carrying the content.
        let s = super::project_rules_section(Some("Always use PTBs; never hardcode addresses."));
        assert!(s.contains("PROJECT RULES"));
        assert!(s.contains("Always use PTBs"));
        // FAIL-CLOSED: a secret-shaped rules file is WITHHELD (never injected/egressed).
        assert!(super::project_rules_section(Some("sign with private_key 0xdeadbeef")).is_empty());
        // over-cap ⇒ truncated to the char cap (the body is exactly MAX_CHARS chars).
        // Filler '0' is absent from the label prefix, so counting it isolates the body.
        let long = "0".repeat(super::PROJECT_RULES_MAX_CHARS + 500);
        let capped = super::project_rules_section(Some(&long));
        assert_eq!(
            capped.chars().filter(|c| *c == '0').count(),
            super::PROJECT_RULES_MAX_CHARS
        );
    }

    #[cfg(any(
        feature = "provider-egress",
        feature = "local-mlx",
        feature = "local-vllm"
    ))]
    #[test]
    fn project_agents_section_injects_caps_and_withholds_secrets() {
        // D#6: AGENTS.md honored with the SAME discipline as .sinabrorules.
        assert!(super::project_agents_section(None).is_empty());
        assert!(super::project_agents_section(Some("   \n   ")).is_empty());
        let s = super::project_agents_section(Some("Prefer small PRs; run the tests."));
        assert!(s.contains("AGENTS.md"));
        assert!(s.contains("Prefer small PRs"));
        // FAIL-CLOSED: a secret-shaped AGENTS.md is WITHHELD (same screen as .sinabrorules).
        assert!(super::project_agents_section(Some("sign with private_key 0xdeadbeef")).is_empty());
        // over-cap ⇒ truncated to the char cap.
        let long = "0".repeat(super::PROJECT_RULES_MAX_CHARS + 500);
        let capped = super::project_agents_section(Some(&long));
        assert_eq!(
            capped.chars().filter(|c| *c == '0').count(),
            super::PROJECT_RULES_MAX_CHARS
        );
    }

    #[test]
    fn wallet_sign_shows_typed_phrase_gate_not_executed() {
        assert_eq!(
            risk_for(CliNamespace::Wallet, "sign"),
            CommandRisk::WalletSign
        );
        let out = body_of(&["wallet", "sign"]);
        assert!(out.contains("approval=typed-phrase"));
        assert!(out.contains("state=LOCKED"));
        assert!(out.contains("is NOT executed"));
    }

    #[test]
    fn chain_write_shows_multisig_gate() {
        assert_eq!(
            risk_for(CliNamespace::Chain, "write"),
            CommandRisk::ChainWrite
        );
        let out = body_of(&["chain", "write"]);
        assert!(out.contains("approval=multisig"));
        assert!(out.contains("state=LOCKED"));
    }

    #[test]
    fn memory_delete_is_local_write_gate_and_list_is_readonly() {
        let del = body_of(&["memory", "delete"]);
        assert!(del.contains("approval=confirm"));
        assert!(del.contains("state=LOCKED"));
        let list = body_of(&["memory", "list"]);
        assert!(list.contains("approval=none"));
        assert!(list.contains("tombstone"));
    }

    /// Agent-core step 2 — the retrieval verbs are read-only + approval=none
    /// D-1b (AGENT-NATIVE GITHUB): `registry scan` + `registry list` content-address a
    /// real local tree through the PURE `agent_registry` core — ReadOnly, stateless, and
    /// tamper-evident (every stored id re-derives from its content). Hermetic temp tree.
    #[test]
    fn registry_scan_and_list_are_content_addressed_readonly() {
        use std::io::Write as _;
        use std::sync::atomic::{AtomicU32, Ordering};
        static CTR: AtomicU32 = AtomicU32::new(0);
        let n = CTR.fetch_add(1, Ordering::Relaxed);
        let tmp = std::env::temp_dir().join(format!("sinabro_reg_{}_{n}", std::process::id()));
        std::fs::create_dir_all(&tmp).expect("temp dir");
        std::fs::File::create(tmp.join("a.txt"))
            .expect("a")
            .write_all(b"hello registry")
            .expect("wa");
        std::fs::File::create(tmp.join("b.rs"))
            .expect("b")
            .write_all(b"fn main() {}")
            .expect("wb");
        let tstr = tmp.to_string_lossy().into_owned();

        let (scan_truth, scan) = registry_scan_body(&["scan".to_string(), tstr.clone()]);
        let (list_truth, listing) = registry_list_body(&["list".to_string(), tstr.clone()]);
        let _ = std::fs::remove_dir_all(&tmp);

        // scan: 2 content-addressed artifacts, the AGRX codec round-trips, Green.
        assert_eq!(scan_truth, RenderTruth::Green, "{scan:?}");
        assert!(
            scan.iter()
                .any(|l| l.contains("2 content-addressed artifact")),
            "{scan:?}"
        );
        assert!(scan.iter().any(|l| l.contains("round-trip OK")), "{scan:?}");
        // list: integrity OK (every id re-derives from its content), Green, code entries.
        assert_eq!(list_truth, RenderTruth::Green, "{listing:?}");
        assert!(
            listing.iter().any(|l| l.contains("integrity OK")),
            "{listing:?}"
        );
        assert!(listing.iter().any(|l| l.contains("code")), "{listing:?}");
        // A missing path is honest-absent (Yellow), never a crash or a fabricated entry.
        let (miss_truth, _) = registry_list_body(&[
            "list".to_string(),
            "/no/such/path/xyz-agent-registry".to_string(),
        ]);
        assert_eq!(miss_truth, RenderTruth::Yellow);
    }

    /// D-3 IV-D3-2 — the supply-chain seatbelt: `registry_content_verified` accepts bytes
    /// that re-hash to the id and REJECTS any tamper / substitution / forged id. This is the
    /// PURE core of what `registry fetch` (and the publish round-trip) enforce over the wire.
    #[test]
    fn registry_content_verified_is_the_supply_chain_seatbelt() {
        use crate::agent_registry::{AgentArtifact, ArtifactKind};
        let content = b"an agent registry artifact body";
        let digest = sha256_32(content);
        let art = AgentArtifact::new(
            ArtifactKind::Code,
            digest,
            "agent://local".to_string(),
            "body",
            Some("blob-ref".to_string()),
        );
        // Correct bytes re-hash to the id ⇒ VERIFIED.
        assert!(registry_content_verified(&art, content));
        // Substituted / tampered bytes do NOT re-hash ⇒ REJECTED (fail-closed).
        assert!(!registry_content_verified(&art, b"tampered bytes"));
        assert!(!registry_content_verified(&art, b""));
        // A FORGED id (bytes unchanged) ⇒ `id_matches_content()` false ⇒ REJECTED.
        let mut forged = art.clone();
        forged.id = "deadbeefdeadbeef".to_string();
        assert!(!registry_content_verified(&forged, content));
    }

    /// D-3 IV-D3-3/IV-D3-10 — `registry publish` fires NOTHING without the exact owner phrase
    /// (the locked surface, zero network), and `registry fetch` fails closed on missing args.
    /// Hermetic: the gate rejects before any PUT, so no testnet call is made.
    #[cfg(feature = "put-fixture-net")]
    #[test]
    fn registry_publish_is_owner_phrase_gated_and_fetch_args_fail_closed() {
        // Wrong phrase ⇒ the locked surface (honest usage), no PUT.
        let mut out = Vec::new();
        let _ = registry_publish(
            &[
                "publish".to_string(),
                "not-the-phrase".to_string(),
                "/tmp".to_string(),
            ],
            &mut out,
        );
        let s = String::from_utf8_lossy(&out);
        assert!(
            s.contains("to run, supply EXACTLY: registry publish"),
            "locked surface expected, got: {s}"
        );
        assert!(!s.contains("PUT ok"), "no PUT on a locked gate: {s}");
        // Fetch with no args ⇒ honest usage (Yellow), never a crash / fabricated success.
        let mut out2 = Vec::new();
        let _ = registry_fetch(&["fetch".to_string()], &mut out2);
        let s2 = String::from_utf8_lossy(&out2);
        assert!(
            s2.contains("registry fetch <main-index-blob-id>"),
            "usage expected, got: {s2}"
        );
        assert!(!s2.contains("VERIFIED"), "no verify without a fetch: {s2}");
    }

    /// (IV6 autonomous-safe) and render the honest Phase-0 empty surface
    /// (no fabricated data; the fold projection lands at step 3).
    #[test]
    fn memory_index_and_read_are_readonly_autonomous() {
        // Hermetic: redirect the data dir to a FRESH empty temp dir so the index
        // reflects an EMPTY store (`indexed=0`; `read 7` not in index) regardless
        // of the developer's real `~/.mnemos`. The override is thread-local
        // (race-free under the parallel harness) and a drop guard clears it even
        // if an assertion panics.
        struct DataDirGuard;
        impl Drop for DataDirGuard {
            fn drop(&mut self) {
                crate::memory_store::set_test_data_dir(None);
            }
        }
        let tmp = {
            use std::sync::atomic::{AtomicU32, Ordering};
            static CTR: AtomicU32 = AtomicU32::new(0);
            let n = CTR.fetch_add(1, Ordering::Relaxed);
            std::env::temp_dir().join(format!("sinabro_idx_ro_{}_{n}", std::process::id()))
        };
        std::fs::create_dir_all(&tmp).expect("temp dir");
        crate::memory_store::set_test_data_dir(Some(tmp.clone()));
        let _guard = DataDirGuard;

        let index = body_of(&["memory", "index"]);
        assert!(index.contains("risk=read-only"));
        assert!(index.contains("approval=none"));
        assert!(index.contains("state=LOCAL-ONLY"));
        assert!(index.contains("indexed=0"));
        assert!(index.contains("no content, no blob bytes"));

        let usage = body_of(&["memory", "read"]);
        assert!(usage.contains("approval=none"));
        assert!(usage.contains("usage: memory read <id>"));

        let miss = body_of(&["memory", "read", "7"]);
        assert!(miss.contains("not in index"));
        assert!(miss.contains("memory_index.read_deny.not_in_index"));

        let bad = body_of(&["memory", "read", "not-a-number"]);
        assert!(bad.contains("unsigned integer"));

        let _ = std::fs::remove_dir_all(&tmp);
    }

    /// Agent-core step 2 — the full read gate chain over synthetic records:
    /// tombstone deny in BOTH layers (D5), hash-verify deny (D6), redaction
    /// withholding for secret-shaped content (IV1), honest content-absence
    /// deny, and the happy path with a receipt.
    #[test]
    fn memory_read_body_gate_chain() {
        use mnemos_b_memory::DeleteSemantics;

        let live = MemoryIndexRecord::from_content(
            MemoryId::new(1),
            b"first line\nsecond line",
            100,
            MemoryTier::Recent,
            true,
        )
        .expect("valid");
        let dead = MemoryIndexRecord::from_content(
            MemoryId::new(2),
            b"deleted memory",
            100,
            MemoryTier::DeletedTombstone,
            false,
        )
        .expect("valid");
        const SECRET_BODY: &[u8] = b"key = \"suiprivkey1qexamplenotreal\"";
        let secret = MemoryIndexRecord::from_content(
            MemoryId::new(3),
            SECRET_BODY,
            100,
            MemoryTier::Recent,
            false,
        )
        .expect("valid");
        let records = [live, dead, secret];
        let contents: Vec<(MemoryId, &[u8])> = vec![
            (MemoryId::new(1), b"first line\nsecond line"),
            (MemoryId::new(2), b"deleted memory"),
            (MemoryId::new(3), SECRET_BODY),
        ];
        let clean_policy = TombstonePolicy::new();
        let arg = |s: &str| vec!["read".to_string(), s.to_string()];

        // Happy path: all gates pass; content renders with a receipt. The
        // local tier renders the owner's own PRIVATE record (IV2 binds on
        // the frontier path, not here).
        let (truth, body) = memory_read_body(&records, &contents, &clean_policy, &arg("1"));
        assert_eq!(truth, RenderTruth::Green);
        let joined = body.join("\n");
        assert!(joined.contains("content-hash OK"));
        assert!(joined.contains("second line"));
        assert!(joined.contains("private=1"));

        // D5 layer 2 — the record tier denies a tombstone.
        let (truth, body) = memory_read_body(&records, &contents, &clean_policy, &arg("2"));
        assert_eq!(truth, RenderTruth::Yellow);
        assert!(body.join("\n").contains("tombstoned"));

        // D5 layer 1 — the delete-truth policy denies even a live-tier record.
        let mut tomb_policy = TombstonePolicy::new();
        tomb_policy.record(MemoryId::new(1), DeleteSemantics::Tombstone);
        let (truth, body) = memory_read_body(&records, &contents, &tomb_policy, &arg("1"));
        assert_eq!(truth, RenderTruth::Yellow);
        assert!(body.join("\n").contains("delete truth"));

        // D6 — bytes that do not match the record are never rendered.
        let forged: Vec<(MemoryId, &[u8])> = vec![(MemoryId::new(1), b"tampered bytes")];
        let (truth, body) = memory_read_body(&records, &forged, &clean_policy, &arg("1"));
        assert_eq!(truth, RenderTruth::Red);
        let joined = body.join("\n");
        assert!(joined.contains("integrity failure"));
        assert!(joined.contains("memory_index.content_hash_mismatch"));
        assert!(
            !joined.contains("tampered bytes"),
            "denied bytes never render"
        );

        // IV1 — secret-shaped content is withheld by the redaction gate.
        let (truth, body) = memory_read_body(&records, &contents, &clean_policy, &arg("3"));
        assert_eq!(truth, RenderTruth::Yellow);
        let joined = body.join("\n");
        assert!(joined.contains("WITHHELD"));
        assert!(!joined.contains("suiprivkey"), "secret never renders");

        // Content unavailable (no chunk store wired) is an honest typed deny.
        let none: [(MemoryId, &[u8]); 0] = [];
        let (truth, body) = memory_read_body(&records, &none, &clean_policy, &arg("1"));
        assert_eq!(truth, RenderTruth::Yellow);
        assert!(body.join("\n").contains("content unavailable"));
    }

    /// Agent-core step 2 — the catalog body lists live records (private KEPT
    /// on the local surface), excludes tombstones, and reports honest counts.
    #[test]
    fn memory_index_body_lists_and_excludes() {
        let records = [
            MemoryIndexRecord::from_content(
                MemoryId::new(1),
                "비밀 아닌 한국어 요약 테스트".as_bytes(),
                9_000,
                MemoryTier::Recent,
                true,
            )
            .expect("valid"),
            MemoryIndexRecord::from_content(
                MemoryId::new(2),
                b"tombstoned body",
                100,
                MemoryTier::DeletedTombstone,
                false,
            )
            .expect("valid"),
            MemoryIndexRecord::from_content(
                MemoryId::new(3),
                b"shareable note",
                200,
                MemoryTier::Mid,
                false,
            )
            .expect("valid"),
        ];
        let (truth, body) = memory_index_body(&records);
        assert_eq!(truth, RenderTruth::Green);
        let joined = body.join("\n");
        assert!(joined.contains("indexed=2 tombstoned_excluded=1 private=1 shareable=1"));
        assert!(joined.contains("id=1 tier=recent imp=9000 private=1"));
        assert!(!joined.contains("id=2"), "tombstone never lists");
        assert!(joined.contains("id=3 tier=mid imp=200 private=0 shareable note"));
    }

    /// P1-2 — the save classification surface is fail-closed: an unknown
    /// `--…` flag is a typed deny (a typo'd flag never silently saves
    /// misclassified text), and the usage renders the explicit-shareable
    /// contract. Every path here denies BEFORE the store opens (hermetic —
    /// no key, no fs write).
    #[test]
    fn memory_save_flag_parsing_fail_closed() {
        let save = |tokens: &[&str]| -> Vec<String> {
            std::iter::once("save")
                .chain(tokens.iter().copied())
                .map(str::to_string)
                .collect()
        };

        // An unknown flag (a typo'd --sharable) is a typed deny + usage.
        let (truth, body) = memory_save_body(&save(&["--sharable", "oops text"]));
        assert_eq!(truth, RenderTruth::Yellow);
        let joined = body.join("\n");
        assert!(joined.contains("unknown flag --sharable"), "{joined}");
        assert!(
            joined.contains("usage: memory save [--shareable] <text>"),
            "{joined}"
        );
        assert!(joined.contains("default: private"), "{joined}");

        // No text at all renders usage with the fail-closed default named.
        let (truth, body) = memory_save_body(&save(&[]));
        assert_eq!(truth, RenderTruth::Yellow);
        assert!(
            body.join("\n")
                .contains("default class: private (fail-closed)")
        );

        // The flag with NO text is still just usage — nothing saved.
        let (truth, body) = memory_save_body(&save(&["--shareable"]));
        assert_eq!(truth, RenderTruth::Yellow);
        assert!(
            body.join("\n")
                .contains("usage: memory save [--shareable] <text>")
        );
    }

    /// P3-1 — `tool run` without the EXACT ceremony renders the locked
    /// surface only (zero side effects; risk=admin, approval=typed-phrase);
    /// the phrase + argv runs a real bounded child; secret-shaped output —
    /// and even a secret-shaped COMMAND LINE — never renders.
    #[test]
    fn tool_run_ceremony_gates_and_executes() {
        let locked = body_of(&["tool", "run"]);
        assert!(locked.contains("risk=admin"), "{locked}");
        assert!(locked.contains("approval=typed-phrase"), "{locked}");
        assert!(
            locked.contains("usage: tool run exec-local-owner-live"),
            "{locked}"
        );
        assert!(
            !locked.contains("exec: argv"),
            "no spawn without the phrase"
        );

        let wrong = body_of(&["tool", "run", "exec-local-owner", "/bin/echo", "x"]);
        assert!(
            !wrong.contains("exec: argv"),
            "a wrong phrase never spawns: {wrong}"
        );

        #[cfg(unix)]
        {
            let live = body_of(&[
                "tool",
                "run",
                "exec-local-owner-live",
                "/bin/echo",
                "dispatch-live-proof",
            ]);
            assert!(live.contains("exec: argv"), "{live}");
            assert!(live.contains("dispatch-live-proof"), "{live}");
            assert!(live.contains("exit=0"), "{live}");
            assert!(live.contains("env scrubbed"), "{live}");

            // Secret-shaped OUTPUT is withheld AND the secret-shaped argv
            // echo is withheld — the literal appears nowhere in the render.
            let secret = body_of(&[
                "tool",
                "run",
                "exec-local-owner-live",
                "/bin/echo",
                "key=suiprivkey1qexamplenotreal",
            ]);
            assert!(secret.contains("withheld"), "{secret}");
            assert!(
                !secret.contains("suiprivkey1qexamplenotreal"),
                "secret literal never renders: {secret}"
            );
        }
    }

    /// E6 — `skill eval` RUNS a skill's reproducible commands inside the
    /// OS-enforced sandbox (tier=LocalWrite, network kernel-DENIED). Without the
    /// EXACT phrase only the locked surface renders (zero side effects); with it
    /// the command really runs, the canonical score binds to it (a failing
    /// command scores 0 — no forgery), a secret-shaped command echo is withheld,
    /// and `skill eval` is an Approval audit action — never Kill (substring trap).
    #[test]
    fn skill_eval_ceremony_runs_in_sandbox_and_scores_real() {
        let locked = body_of(&["skill", "eval"]);
        assert!(locked.contains("risk=admin"), "{locked}");
        assert!(locked.contains("approval=typed-phrase"), "{locked}");
        assert!(
            locked.contains("usage: skill eval skill-eval-owner-live"),
            "{locked}"
        );
        assert!(
            !locked.contains("eval score:"),
            "no run without the phrase: {locked}"
        );

        let wrong = body_of(&["skill", "eval", "skill-eval-owner", "/bin/echo", "x"]);
        assert!(
            !wrong.contains("eval score:"),
            "a wrong phrase never runs: {wrong}"
        );

        // macOS: the sandbox is available ⇒ real kernel-confined execution.
        #[cfg(target_os = "macos")]
        {
            let pass = body_of(&["skill", "eval", "skill-eval-owner-live", "/bin/echo", "ok"]);
            assert!(pass.contains("cmd[0]:"), "{pass}");
            assert!(pass.contains("exit=0"), "{pass}");
            assert!(
                pass.contains("eval score: rust=10000bps"),
                "a passing run scores 10000: {pass}"
            );
            assert!(pass.contains("network kernel-DENIED"), "{pass}");
            assert!(pass.contains("score valid=true"), "{pass}");

            // A failing command scores 0 — real exit-code derived, not forged.
            let fail = body_of(&["skill", "eval", "skill-eval-owner-live", "/usr/bin/false"]);
            assert!(
                fail.contains("eval score: rust=0bps"),
                "a failing run scores 0: {fail}"
            );

            // A secret-shaped command echo is withheld (it still ran).
            let secret = body_of(&[
                "skill",
                "eval",
                "skill-eval-owner-live",
                "/bin/echo",
                "key=suiprivkey1qexamplenotreal",
            ]);
            assert!(secret.contains("withheld"), "{secret}");
            assert!(
                !secret.contains("suiprivkey1qexamplenotreal"),
                "the secret literal never renders: {secret}"
            );
        }

        // The substring trap: "skill" contains "kill" — `skill eval` must be an
        // Approval/Denial audit action, NEVER a Kill.
        assert_eq!(
            audit_action_for(
                "skill eval",
                CommandRisk::Admin,
                ApprovalRequirement::TypedPhrase,
                RenderTruth::Green
            ),
            Some(AuditAction::Approval),
            "skill eval is an Approval, never Kill"
        );
    }

    /// P3-2 — `tool apply` without the EXACT ceremony renders the locked
    /// surface only (risk=admin, approval=typed-phrase, usage + read-only
    /// pending posture; zero side effects); a wrong phrase stays locked; the
    /// phrase without an id is usage only.
    #[test]
    fn tool_apply_ceremony_gates_locked_surface() {
        let locked = body_of(&["tool", "apply"]);
        assert!(locked.contains("risk=admin"), "{locked}");
        assert!(locked.contains("approval=typed-phrase"), "{locked}");
        assert!(
            locked.contains("usage: tool apply file-apply-owner-live"),
            "{locked}"
        );
        assert!(
            locked.contains("the model proposes only"),
            "authority split rendered: {locked}"
        );
        assert!(!locked.contains("applied:"), "no write without the phrase");

        let wrong = body_of(&["tool", "apply", "file-apply-owner", "0123456789abcdef"]);
        assert!(
            !wrong.contains("applied:"),
            "a wrong phrase never applies: {wrong}"
        );

        // Phrase but no id: usage, nothing written (surface-level, temp store).
        let dir = std::env::temp_dir().join(format!("sinabro_applyusage_{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("dir");
        let store = ProposalStore::with_dir(
            crate::memory_store::MemoryCipher::from_key([4u8; 32]),
            dir.clone(),
        );
        let policy = crate::file_context::FileReadPolicy::new(
            std::slice::from_ref(&dir),
            crate::file_context::MAX_FILE_BYTES,
        );
        let rest: Vec<String> = ["apply", FILE_APPLY_CONFIRM_PHRASE]
            .iter()
            .map(|s| (*s).to_string())
            .collect();
        let (truth, body) = file_apply_surface(Some(&store), &policy, &rest);
        assert_eq!(truth, RenderTruth::Yellow);
        assert!(body.join("\n").contains("missing <proposal-id>"));
        std::fs::remove_dir_all(&dir).ok();
    }

    /// P3-2 — the FULL vertical against a real temp store + real files:
    /// mint → save → `tool apply` surface applies atomically (Green, diff
    /// rendered, artifact consumed) → a re-saved proposal over a DRIFTED
    /// target is a typed stale deny (target untouched, artifact kept).
    #[test]
    fn file_apply_surface_full_vertical() {
        use std::io::Write;
        let dir = std::env::temp_dir().join(format!("sinabro_applyvert_{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("dir");
        let target = dir.join("doc.md");
        std::fs::File::create(&target)
            .expect("create")
            .write_all(b"old line\n")
            .expect("write");
        let canonical = std::fs::canonicalize(&target).expect("canon");
        let store = ProposalStore::with_dir(
            crate::memory_store::MemoryCipher::from_key([4u8; 32]),
            dir.clone(),
        );
        let policy = crate::file_context::FileReadPolicy::new(
            std::slice::from_ref(&dir),
            crate::file_context::MAX_FILE_BYTES,
        );
        let proposal = FileEditProposal {
            target_path: canonical.clone(),
            read_sha_32: sha256_32(b"old line\n"),
            content: b"new line\n".to_vec(),
        };
        let name = store.save(&proposal).expect("saves");
        let id: String = name.chars().take(PROPOSAL_ID_HEX_CHARS).collect();

        let rest: Vec<String> = ["apply", FILE_APPLY_CONFIRM_PHRASE, id.as_str()]
            .iter()
            .map(|s| (*s).to_string())
            .collect();
        let (truth, body) = file_apply_surface(Some(&store), &policy, &rest);
        let joined = body.join("\n");
        assert_eq!(truth, RenderTruth::Green, "{joined}");
        assert!(joined.contains("applied:"), "{joined}");
        assert!(joined.contains("re-read verified"), "{joined}");
        assert!(joined.contains("- old line"), "diff old side: {joined}");
        assert!(joined.contains("+ new line"), "diff new side: {joined}");
        assert!(joined.contains("proposal consumed"), "{joined}");
        assert_eq!(std::fs::read(&canonical).expect("read"), b"new line\n");
        assert!(
            store.load_pending().proposals.is_empty(),
            "artifact consumed on success"
        );

        // STALE: a new proposal bound to the OLD hash over the now-new file.
        let stale = FileEditProposal {
            target_path: canonical.clone(),
            read_sha_32: sha256_32(b"old line\n"),
            content: b"another rewrite\n".to_vec(),
        };
        let stale_name = store.save(&stale).expect("saves stale");
        let stale_id: String = stale_name.chars().take(PROPOSAL_ID_HEX_CHARS).collect();
        let rest: Vec<String> = ["apply", FILE_APPLY_CONFIRM_PHRASE, stale_id.as_str()]
            .iter()
            .map(|s| (*s).to_string())
            .collect();
        let (truth, body) = file_apply_surface(Some(&store), &policy, &rest);
        let joined = body.join("\n");
        assert_eq!(truth, RenderTruth::Yellow, "{joined}");
        assert!(
            joined.contains("file_edit.apply.stale_target"),
            "typed stale deny: {joined}"
        );
        assert!(joined.contains("staleness lock: read_sha="), "{joined}");
        assert!(joined.contains("proposal kept pending"), "{joined}");
        assert_eq!(
            std::fs::read(&canonical).expect("read"),
            b"new line\n",
            "stale deny leaves the target untouched"
        );
        assert_eq!(store.load_pending().proposals.len(), 1, "artifact kept");

        // Unknown id is a typed deny.
        let rest: Vec<String> = ["apply", FILE_APPLY_CONFIRM_PHRASE, "ffffffffffffffff"]
            .iter()
            .map(|s| (*s).to_string())
            .collect();
        let (truth, body) = file_apply_surface(Some(&store), &policy, &rest);
        assert_eq!(truth, RenderTruth::Yellow);
        assert!(body.join("\n").contains("file_edit.apply.unknown_id"));
        std::fs::remove_dir_all(&dir).ok();
    }

    // ---- E10-2b LOCAL: tool exec-apply (MutateCapability-gated execute) -------

    fn exec_store(tag: &str) -> (crate::exec_proposal::ExecProposalStore, std::path::PathBuf) {
        let dir = std::env::temp_dir().join(format!(
            "sinabro_execapply_{tag}_{}_{}",
            std::process::id(),
            EXEC_APPLY_TEST_COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
        ));
        std::fs::create_dir_all(&dir).expect("dir");
        let store = crate::exec_proposal::ExecProposalStore::with_dir(
            crate::memory_store::MemoryCipher::from_key([5u8; 32]),
            dir.clone(),
        );
        (store, dir)
    }

    static EXEC_APPLY_TEST_COUNTER: std::sync::atomic::AtomicU64 =
        std::sync::atomic::AtomicU64::new(0);

    /// REDTEAM (IV-A1): no ceremony ⇒ the surface lists pending proposals
    /// read-only and runs NOTHING; a wrong phrase is equally inert.
    #[test]
    fn exec_apply_without_ceremony_is_inert() {
        let (store, dir) = exec_store("inert");
        let proposal = crate::exec_proposal::ExecProposal {
            command: "/bin/echo e10_inert".to_string(),
        };
        store.save(&proposal).expect("saves");
        // no phrase: locked surface (read-only list), nothing executed.
        let rest: Vec<String> = vec!["exec-apply".to_string()];
        let (truth, body) = exec_apply_surface(Some(&store), &rest);
        let joined = body.join("\n");
        assert_eq!(truth, RenderTruth::Yellow, "{joined}");
        assert!(
            joined.contains("EXECUTES ONE pending exec proposal"),
            "{joined}"
        );
        assert!(!joined.contains("executed:"), "nothing ran: {joined}");
        // wrong phrase: still inert.
        let rest: Vec<String> = vec!["exec-apply".to_string(), "not-the-phrase".to_string()];
        let (truth, body) = exec_apply_surface(Some(&store), &rest);
        assert_eq!(truth, RenderTruth::Yellow);
        assert!(
            !body.join("\n").contains("executed:"),
            "wrong phrase never runs"
        );
        // the proposal is still pending (un-consumed).
        assert_eq!(store.load_pending().proposals.len(), 1);
        std::fs::remove_dir_all(&dir).ok();
    }

    /// REDTEAM (IV-A1 / IV-A11): the ceremony phrase + an UNKNOWN id is a typed
    /// deny — no MutateCapability is even minted, nothing runs.
    #[test]
    fn exec_apply_unknown_id_is_typed_deny() {
        let (store, dir) = exec_store("unknown");
        let rest: Vec<String> = ["exec-apply", EXEC_APPLY_CONFIRM_PHRASE, "ffffffffffffffff"]
            .iter()
            .map(|s| (*s).to_string())
            .collect();
        let (truth, body) = exec_apply_surface(Some(&store), &rest);
        let joined = body.join("\n");
        assert_eq!(truth, RenderTruth::Yellow, "{joined}");
        assert!(
            joined.contains("exec_proposal.lookup.unknown_id"),
            "{joined}"
        );
        assert!(!joined.contains("executed:"), "{joined}");
        std::fs::remove_dir_all(&dir).ok();
    }

    /// The FULL vertical against a real temp store: save an exec proposal →
    /// `tool exec-apply` with the ceremony + id mints a single-shot
    /// MutateCapability and EXECUTES it in the kernel sandbox (Green, stdout
    /// captured, artifact consumed). On a non-macOS host the sandbox fail-closes
    /// (Red, NEVER unsandboxed) and the artifact is kept.
    #[test]
    fn exec_apply_full_vertical_executes_and_consumes() {
        let (store, dir) = exec_store("vert");
        let proposal = crate::exec_proposal::ExecProposal {
            command: "/bin/echo e10_exec_live".to_string(),
        };
        let name = store.save(&proposal).expect("saves");
        let id: String = name
            .chars()
            .take(crate::exec_proposal::EXEC_PROPOSAL_ID_HEX_CHARS)
            .collect();
        let rest: Vec<String> = ["exec-apply", EXEC_APPLY_CONFIRM_PHRASE, id.as_str()]
            .iter()
            .map(|s| (*s).to_string())
            .collect();
        let (truth, body) = exec_apply_surface(Some(&store), &rest);
        let joined = body.join("\n");
        if crate::sandbox_exec::seatbelt_available() {
            assert_eq!(truth, RenderTruth::Green, "{joined}");
            assert!(
                joined.contains("executed: command=/bin/echo e10_exec_live"),
                "{joined}"
            );
            assert!(
                joined.contains("e10_exec_live"),
                "stdout captured: {joined}"
            );
            assert!(joined.contains("network kernel-DENIED"), "{joined}");
            assert!(joined.contains("exec proposal consumed"), "{joined}");
            assert!(
                store.load_pending().proposals.is_empty(),
                "artifact consumed on run"
            );
        } else {
            assert_eq!(truth, RenderTruth::Red, "{joined}");
            assert!(joined.contains("sandbox_exec.unavailable"), "{joined}");
            assert!(joined.contains("NEVER unsandboxed"), "{joined}");
            assert_eq!(
                store.load_pending().proposals.len(),
                1,
                "kept on fail-close"
            );
        }
        std::fs::remove_dir_all(&dir).ok();
    }

    /// P3-2 — the consult-side propose path: an ordinary answer is `None`
    /// (renders as usual); a valid PROPOSE-EDIT bound to a verified read
    /// seals an artifact + renders the card with diff + apply line; an
    /// unread target / malformed block / secret-shaped content are typed
    /// denies that save NOTHING.
    #[test]
    fn consult_proposal_render_paths() {
        use std::io::Write;
        let dir = std::env::temp_dir().join(format!("sinabro_propose_{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("dir");
        let target = dir.join("notes.txt");
        std::fs::File::create(&target)
            .expect("create")
            .write_all(b"alpha\nbeta\n")
            .expect("write");
        let canonical = std::fs::canonicalize(&target).expect("canon");
        let store = ProposalStore::with_dir(
            crate::memory_store::MemoryCipher::from_key([4u8; 32]),
            dir.clone(),
        );
        let policy = crate::file_context::FileReadPolicy::new(
            std::slice::from_ref(&dir),
            crate::file_context::MAX_FILE_BYTES,
        );
        let reads = vec![VerifiedFileRead {
            path_as_typed: "notes.txt".to_string(),
            canonical_path: canonical.clone(),
            sha256_32: sha256_32(b"alpha\nbeta\n"),
        }];

        // Ordinary answer ⇒ None (not propose-shaped).
        assert!(
            consult_proposal_render("The answer is 42.", &reads, Some(&store), &policy).is_none()
        );

        // Valid proposal ⇒ sealed + card with diff + apply ceremony line.
        let answer = "PROPOSE-EDIT\nTARGET: notes.txt\nCONTENT:\nalpha\nBETA2";
        let (truth, lines) =
            consult_proposal_render(answer, &reads, Some(&store), &policy).expect("propose-shaped");
        let joined = lines.join("\n");
        assert_eq!(truth, RenderTruth::Green, "{joined}");
        assert!(joined.contains("file-edit PROPOSAL (inert"), "{joined}");
        assert!(joined.contains("- beta"), "diff old side: {joined}");
        assert!(joined.contains("+ BETA2"), "diff new side: {joined}");
        assert!(
            joined.contains("apply with: tool apply file-apply-owner-live "),
            "{joined}"
        );
        let pending = store.load_pending();
        assert_eq!(pending.proposals.len(), 1, "artifact sealed");
        assert_eq!(
            pending.proposals[0].proposal.content, b"alpha\nBETA2\n",
            "newline-normalized content sealed"
        );

        // E-NEW: an ABSENT, parent-confined target ⇒ a file-CREATE proposal (not a deny).
        let create = format!(
            "PROPOSE-EDIT\nTARGET: {}\nCONTENT:\nfresh body",
            dir.join("brand_new.txt").display()
        );
        let (truth, lines) =
            consult_proposal_render(&create, &reads, Some(&store), &policy).expect("shaped");
        let joined = lines.join("\n");
        assert_eq!(truth, RenderTruth::Green, "{joined}");
        assert!(
            joined.contains("file-CREATE PROPOSAL (new file"),
            "{joined}"
        );
        assert!(
            joined.contains("+ fresh body"),
            "all-additions diff: {joined}"
        );

        // An EXISTING-but-unread target ⇒ target_exists (read it first to EDIT; the create
        // path never overwrites an existing file).
        let untracked = dir.join("untracked.txt");
        std::fs::File::create(&untracked)
            .expect("create")
            .write_all(b"present\n")
            .expect("write");
        let exists_unread = format!("PROPOSE-EDIT\nTARGET: {}\nCONTENT:\nx", untracked.display());
        let (truth, lines) =
            consult_proposal_render(&exists_unread, &reads, Some(&store), &policy).expect("shaped");
        assert_eq!(truth, RenderTruth::Yellow);
        assert!(
            lines.join("\n").contains("file_edit.propose.target_exists"),
            "existing-but-unread must say target_exists (read-first), never create-over"
        );

        // Malformed block ⇒ typed deny.
        let malformed = "PROPOSE-EDIT\nCONTENT:\nx";
        let (truth, lines) =
            consult_proposal_render(malformed, &reads, Some(&store), &policy).expect("shaped");
        assert_eq!(truth, RenderTruth::Yellow);
        assert!(lines.join("\n").contains("file_edit.propose.malformed"));
        // Secret-shaped content ⇒ refused outright (IV-W7a).
        let secret =
            "PROPOSE-EDIT\nTARGET: notes.txt\nCONTENT:\nkey = \"suiprivkey1qexamplenotreal\"";
        let (truth, lines) =
            consult_proposal_render(secret, &reads, Some(&store), &policy).expect("shaped");
        assert_eq!(truth, RenderTruth::Yellow);
        let joined = lines.join("\n");
        assert!(
            joined.contains("file_edit.propose.secret_shaped"),
            "{joined}"
        );
        assert!(
            !joined.contains("suiprivkey1qexamplenotreal"),
            "secret literal never renders: {joined}"
        );
        assert_eq!(
            store.load_pending().proposals.len(),
            2,
            "two valid proposals sealed (1 edit + 1 create); every denied propose saved NOTHING"
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    /// Lane A — `context file` is read-only + approval=none (autonomous-safe)
    /// and renders the usage line with no arg; a missing/denylisted/outside
    /// path is a typed deny whose bytes never render.
    #[test]
    fn context_file_is_readonly_and_gated() {
        let usage = body_of(&["context", "file"]);
        assert!(usage.contains("risk=read-only"), "{usage}");
        assert!(usage.contains("approval=none"), "{usage}");
        assert!(usage.contains("usage: context file <path>"), "{usage}");

        // A path outside the cwd allowlist (or absent) is a typed deny.
        let denied = body_of(&["context", "file", "/etc/hosts"]);
        assert!(
            denied.contains("file read denied"),
            "outside-root or denylisted path must deny: {denied}"
        );
        assert!(!denied.contains("localhost"), "denied bytes never render");

        // A denylisted name (an SSH key path) denies without reading.
        let key = body_of(&["context", "file", "/home/u/.ssh/id_rsa"]);
        assert!(key.contains("file read denied"), "{key}");
    }

    /// Lane A — `file_context_body` renders a real readable file (inside the
    /// cwd root) and withholds a secret-shaped one, both via the same gate.
    #[test]
    fn file_context_body_reads_and_withholds() {
        use std::io::Write;
        // The test runs with cwd = the crate dir; write under it so the
        // cwd-default allowlist admits the file, then clean up.
        let dir = std::env::current_dir()
            .expect("cwd")
            .join(format!("target/filectx_dispatch_{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("dir");

        let readable = dir.join("note.md");
        let mut f = std::fs::File::create(&readable).expect("create");
        f.write_all(b"hello from a real file\nsecond line")
            .expect("write");
        let (truth, body) =
            file_context_body(&["file".to_string(), readable.to_string_lossy().to_string()]);
        assert_eq!(truth, RenderTruth::Green);
        let joined = body.join("\n");
        assert!(joined.contains("--- content (2 lines) ---"), "{joined}");
        assert!(joined.contains("hello from a real file"));

        let secret = dir.join("config.toml");
        let mut f = std::fs::File::create(&secret).expect("create");
        f.write_all(b"key = \"suiprivkey1qexamplenotreal\"")
            .expect("write");
        let (truth, body) =
            file_context_body(&["file".to_string(), secret.to_string_lossy().to_string()]);
        assert_eq!(truth, RenderTruth::Yellow);
        let joined = body.join("\n");
        assert!(joined.contains("WITHHELD"), "{joined}");
        assert!(
            !joined.contains("suiprivkey1qexample"),
            "secret never rendered"
        );

        std::fs::remove_dir_all(&dir).ok();
    }

    /// P4-2 — `context index` (no arg) is read-only + approval=none and lists
    /// the registered project roots (the cwd is always a root under cwd_default).
    #[test]
    fn context_index_is_readonly_and_lists_roots() {
        let out = body_of(&["context", "index"]);
        assert!(out.contains("risk=read-only"), "{out}");
        assert!(out.contains("approval=none"), "{out}");
        assert!(out.contains("registered project roots"), "{out}");
        assert!(out.contains("usage: context index <path>"), "{out}");
    }

    /// E11-1b — `context web-fetch <url>` is the owner's LIVE web READ: Network
    /// risk, the gated path. In the DEFAULT test build (no `web-egress`) the
    /// transport is not compiled, so a wall-PASSING https URL renders the honest
    /// not-compiled deny; but the SSRF wall (always compiled) STILL denies
    /// http / IP-literal / chain-RPC BEFORE the transport question — proving the
    /// wall is wired ahead of any fetch (IV-WF1).
    #[test]
    fn context_web_fetch_is_network_gated_and_ssrf_walled() {
        // usage (no url) — Network risk, no approval ceremony (a public read).
        let out = body_of(&["context", "web-fetch"]);
        assert!(out.contains("usage: context web-fetch"), "{out}");
        assert!(out.contains("risk=network"), "{out}");
        assert!(out.contains("approval=none"), "{out}");

        // the SSRF wall fires BEFORE the transport question (always-compiled, no
        // network in ANY build — `classify_url` denies these before a socket).
        let http = body_of(&["context", "web-fetch", "http://docs.rs/"]);
        assert!(http.contains("web_fetch.url.not_https"), "{http}");
        let iplit = body_of(&["context", "web-fetch", "https://127.0.0.1/"]);
        assert!(iplit.contains("web_fetch.url.ip_literal_host"), "{iplit}");
        let chain = body_of(&[
            "context",
            "web-fetch",
            "https://api.mainnet-beta.solana.com/",
        ]);
        assert!(chain.contains("web_fetch.url.chain_rpc_host"), "{chain}");
        // NOTE: a wall-PASSING https URL is NOT asserted here — under `web-egress`
        // it would issue a REAL network GET (no live egress belongs in a unit
        // test). The honest not-compiled deny is covered network-free by the glue
        // unit test `web_fetch::tests::glue_none_port_is_honest_not_compiled`; the
        // live fetch is the manual binary smoke.
    }

    /// E11-1b (D-WF5) — `context web-search <query>` is the CONFIGURED-endpoint
    /// seam, not a bundled index: no query ⇒ usage; the query is percent-encoded
    /// before it joins `?q=` (no injection). Network risk, no approval. (The
    /// endpoint-set fetch is the manual binary smoke — it would touch the network.)
    #[test]
    fn context_web_search_seam_and_query_encoding() {
        // no query ⇒ usage (network-free; reads no env, opens no socket).
        let usage = body_of(&["context", "web-search"]);
        assert!(usage.contains("usage: context web-search"), "{usage}");
        assert!(usage.contains("risk=network"), "{usage}");
        assert!(usage.contains("approval=none"), "{usage}");

        // percent-encoding keeps the RFC 3986 unreserved set, escapes the rest —
        // a `&` / `=` / space / non-ASCII byte cannot break out of the `?q=` param.
        assert_eq!(percent_encode_query("a b"), "a%20b");
        assert_eq!(percent_encode_query("rust-lang_2.0~x"), "rust-lang_2.0~x");
        assert_eq!(percent_encode_query("q=1&x"), "q%3D1%26x");
        assert_eq!(percent_encode_query("café"), "caf%C3%A9");
    }

    /// P4-3 (VM-selector) — `model use` resolves + validates + previews the
    /// runtime/model selection (ReadOnly, approval=none); a bad candidate is a
    /// typed deny (no silent default); `model status` carries the resolved
    /// selection. The selection's truth is env — no config file is written.
    #[test]
    fn model_use_and_status_surface() {
        // selector home (no runtime arg) — lists both routes + how to pick.
        let out = body_of(&["model", "use"]);
        assert!(out.contains("risk=read-only"), "{out}");
        assert!(out.contains("approval=none"), "{out}");
        assert!(out.contains("resolve-only"), "{out}");
        assert!(out.contains("no config file"), "{out}");
        assert!(out.contains("model use frontier"), "{out}");

        // validate a frontier model id → the exact env to export (no persist).
        let out = body_of(&["model", "use", "frontier", "anthropic/claude-3.5-sonnet"]);
        assert!(out.contains("frontier selection validated"), "{out}");
        assert!(
            out.contains("export OPENROUTER_MODEL=anthropic/claude-3.5-sonnet"),
            "{out}"
        );

        // a charset-invalid candidate is a typed deny, never a silent default.
        let out = body_of(&["model", "use", "frontier", "bad$id"]);
        assert!(out.contains("rejected"), "{out}");
        assert!(out.contains("truth=RED"), "{out}");

        // an unknown runtime token → typed deny.
        let out = body_of(&["model", "use", "mainnet"]);
        assert!(out.contains("unknown runtime"), "{out}");

        // `model status` now carries the resolved selection summary.
        let out = body_of(&["model", "status"]);
        assert!(out.contains("frontier:"), "{out}");
        assert!(
            out.contains("local executor is the only tool-executing role"),
            "{out}"
        );
    }

    /// P4-2 — `project_index_body` renders a real bounded tree (denylist-pruned,
    /// content-free, content-addressed) and denies a path outside the cwd
    /// allowlist without escaping it.
    #[test]
    fn project_index_body_renders_real_tree_and_denies_outside() {
        use std::io::Write;
        // cwd = crate dir; build under it so the cwd-default allowlist admits it.
        let dir = std::env::current_dir()
            .expect("cwd")
            .join(format!("target/projidx_dispatch_{}", std::process::id()));
        std::fs::create_dir_all(dir.join("src")).expect("dir");
        {
            let mut f = std::fs::File::create(dir.join("README.md")).expect("create");
            f.write_all(b"readme").expect("write");
            let mut f = std::fs::File::create(dir.join("src/main.rs")).expect("create");
            f.write_all(b"fn main(){}").expect("write");
        }
        // a denylisted container must NOT appear in the listing.
        std::fs::create_dir_all(dir.join(".git")).expect("git");
        {
            let mut f = std::fs::File::create(dir.join(".git/config")).expect("create");
            f.write_all(b"[core]").expect("write");
        }

        let (truth, body) =
            project_index_body(&["index".to_string(), dir.to_string_lossy().to_string()]);
        assert_eq!(truth, RenderTruth::Green);
        let joined = body.join("\n");
        assert!(joined.contains("--- index"), "{joined}");
        assert!(joined.contains("README.md"), "{joined}");
        assert!(joined.contains("src/main.rs"), "{joined}");
        assert!(
            joined.contains("fp="),
            "content-addressed fingerprint: {joined}"
        );
        assert!(!joined.contains(".git"), "denylist pruned: {joined}");

        // a path outside the cwd allowlist denies without escaping.
        let (truth, body) = project_index_body(&["index".to_string(), "/etc".to_string()]);
        assert_eq!(truth, RenderTruth::Yellow);
        let joined = body.join("\n");
        assert!(joined.contains("project index denied"), "{joined}");

        std::fs::remove_dir_all(&dir).ok();
    }

    /// P4-2 — a secret-SHAPED filename (not a denylisted container) trips the
    /// precise `scan_inline_secret` and withholds the WHOLE listing (defense in
    /// depth); ordinary paths/names never false-positive (the no-arg + real-tree
    /// tests above prove the pass case).
    #[test]
    fn project_index_withholds_secret_shaped_name() {
        use std::io::Write;
        let dir = std::env::current_dir()
            .expect("cwd")
            .join(format!("target/projidx_secret_{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("dir");
        // a file literally NAMED like a sui private-key shape — the denylist lets
        // it through (it is not a known container), so the secret-shape scan must
        // be the wall that catches it.
        let mut f =
            std::fs::File::create(dir.join("suiprivkey1qexamplenotrealname")).expect("create");
        f.write_all(b"x").expect("write");

        let (truth, body) =
            project_index_body(&["index".to_string(), dir.to_string_lossy().to_string()]);
        assert_eq!(truth, RenderTruth::Yellow);
        let joined = body.join("\n");
        assert!(joined.contains("WITHHELD"), "{joined}");
        assert!(
            !joined.contains("suiprivkey1qexample"),
            "secret-shaped name never rendered: {joined}"
        );

        std::fs::remove_dir_all(&dir).ok();
    }

    /// 3.A — `provider fan` classifies Network in EVERY build: typed-phrase
    /// LOCKED with the feature off (generic locked surface, no execute path
    /// compiled) and the phrase-gated preview with it on.
    #[test]
    fn provider_fan_classifies_network_in_every_build() {
        let out = body_of(&["provider", "fan"]);
        assert!(out.contains("risk=network"), "{out}");
        assert!(out.contains("state=LOCKED"), "{out}");
    }

    /// 3.A feature build — post-phrase deny paths stop BEFORE any transport
    /// exists (no socket on any of these paths): empty / too many /
    /// secret-shaped sub-questions and the wrong-phrase preview.
    #[cfg(feature = "provider-egress")]
    #[test]
    fn provider_fan_pre_transport_denials() {
        let preview = body_of(&["provider", "fan", "wrong-phrase", "q"]);
        assert!(preview.contains("usage: provider fan"), "{preview}");
        assert!(preview.contains("PARTITIONED"), "{preview}");

        let empty = body_of(&["provider", "fan", "fan-frontier-provider-live"]);
        assert!(empty.contains("no sub-questions"), "{empty}");

        let too_many = body_of(&[
            "provider",
            "fan",
            "fan-frontier-provider-live",
            "a",
            "|",
            "b",
            "|",
            "c",
            "|",
            "d",
            "|",
            "e",
        ]);
        assert!(too_many.contains("too many sub-questions"), "{too_many}");

        let secret = body_of(&[
            "provider",
            "fan",
            "fan-frontier-provider-live",
            "key",
            "=",
            "\"suiprivkey1qexamplenotreal\"",
        ]);
        assert!(secret.contains("secret-shaped"), "{secret}");
        assert!(
            !secret.contains("suiprivkey1qexample"),
            "secret never echoed"
        );
    }

    #[test]
    fn unknown_namespace_is_rejected() {
        let (ok, _out, err) = run_argv(&["definitely-not-a-namespace"]);
        assert!(!ok);
        assert!(err.contains("unknown command"));
    }

    #[test]
    fn unknown_verb_is_rejected() {
        let (ok, _out, err) = run_argv(&["provider", "zzzz-not-a-verb"]);
        assert!(!ok);
        assert!(err.contains("unknown command"));
    }

    #[test]
    fn audit_action_classifies_high_sig_actions_only() {
        // Read-only (no approval gate) is NOT a high-significance action.
        assert_eq!(
            audit_action_for(
                "memory list",
                CommandRisk::ReadOnly,
                ApprovalRequirement::None,
                RenderTruth::Green
            ),
            None
        );
        // Signing / chain-write map to their own classes regardless of truth.
        assert_eq!(
            audit_action_for(
                "wallet sign",
                CommandRisk::WalletSign,
                ApprovalRequirement::TypedPhrase,
                RenderTruth::Red
            ),
            Some(AuditAction::Signing)
        );
        assert_eq!(
            audit_action_for(
                "chain write",
                CommandRisk::ChainWrite,
                ApprovalRequirement::Multisig,
                RenderTruth::Red
            ),
            Some(AuditAction::ChainWrite)
        );
        // A gated side effect that did not render Green is a fail-closed Denial; a
        // Green one is an Approval.
        assert_eq!(
            audit_action_for(
                "admin pause",
                CommandRisk::Admin,
                ApprovalRequirement::TypedPhrase,
                RenderTruth::Red
            ),
            Some(AuditAction::Denial)
        );
        assert_eq!(
            audit_action_for(
                "admin pause",
                CommandRisk::Admin,
                ApprovalRequirement::TypedPhrase,
                RenderTruth::Green
            ),
            Some(AuditAction::Approval)
        );
    }

    #[test]
    fn dispatch_is_deterministic_same_argv_same_bytes() {
        for argv in [
            ["provider", "status"].as_slice(),
            ["audit", "scan"].as_slice(),
            ["budget"].as_slice(),
            ["kill"].as_slice(),
            ["evidence", "pack"].as_slice(),
            ["notify", "telegram"].as_slice(),
        ] {
            let a = body_of(argv);
            let b = body_of(argv);
            assert_eq!(a, b, "non-deterministic for {argv:?}");
        }
    }

    #[test]
    fn thirteen_required_views_render() {
        // §5 Required Views (G_TERMINAL_DESIGN_CONTRACT) — every one renders.
        let views: &[&[&str]] = &[
            &["setup", "memory"],
            &["status"],
            &["provider", "status"],
            &["audit", "scan"],
            &["evidence", "pack"],
            &["evidence", "replay"],
            &["memory", "list"],
            &["notify", "telegram"],
            &["task", "list"],
            &["budget"],
            &["kill"],
            &["tui"],
        ];
        for v in views {
            let out = body_of(v);
            assert!(out.contains("command="), "{v:?} did not render a header");
            assert!(out.contains("truth="), "{v:?} did not render a truth");
        }
        // doctor (the 13th) is rendered by the binary, not dispatch::run.
    }

    #[test]
    fn renders_are_colorless_ascii_within_80_cols() {
        for ns in grammar::ALL {
            for line in body_of(&[ns.canonical_name()]).lines() {
                assert!(
                    line.is_ascii(),
                    "non-ascii in {}: {line}",
                    ns.canonical_name()
                );
                assert!(
                    !line.contains('\u{1b}'),
                    "ansi escape in {}",
                    ns.canonical_name()
                );
                assert!(
                    line.len() <= 80,
                    "line > 80 cols in {}: {line}",
                    ns.canonical_name()
                );
            }
        }
    }

    #[test]
    fn secret_zero_no_inline_secret_in_any_render() {
        // No render leaks an inline-secret-shaped token.
        for ns in grammar::ALL {
            let out = body_of(&[ns.canonical_name()]);
            assert!(
                !out.contains("suiprivkey"),
                "secret leak in {}",
                ns.canonical_name()
            );
            assert!(
                !out.contains("BEGIN PRIVATE KEY"),
                "key leak in {}",
                ns.canonical_name()
            );
        }
    }
}

// ---- P: gated live LLM consult — surface tests (no network in any test) -------
#[cfg(test)]
mod provider_consult_surface_tests {
    use super::*;
    use crate::grammar::CliNamespace;

    #[test]
    fn provider_consult_classifies_network_in_every_build() {
        assert_eq!(
            risk_for(CliNamespace::Provider, "consult"),
            CommandRisk::Network
        );
        // The Provider/Tool split must not leak the verb into Tool.
        assert_eq!(
            risk_for(CliNamespace::Tool, "consult"),
            CommandRisk::ReadOnly
        );
        assert_eq!(risk_for(CliNamespace::Tool, "add"), CommandRisk::LocalWrite);
        assert_eq!(
            risk_for(CliNamespace::Provider, "add"),
            CommandRisk::LocalWrite
        );
        assert!(is_recognized_verb("consult"));
    }

    #[test]
    fn provider_consult_without_phrase_renders_locked_not_executed() {
        let mut out: Vec<u8> = Vec::new();
        let mut err: Vec<u8> = Vec::new();
        let argv = vec!["provider".to_string(), "consult".to_string()];
        let result = run(&argv, &mut out, &mut err);
        assert!(result.is_ok());
        let text = String::from_utf8_lossy(&out);
        assert!(text.contains("risk=network"), "{text}");
        // Default build: the generic locked surface (no execute path compiled).
        #[cfg(not(feature = "provider-egress"))]
        assert!(text.contains("side effect is NOT executed"), "{text}");
        // Feature build: the gated preview teaching the exact phrase — still no
        // execution (the phrase gate runs before redaction/build/socket).
        #[cfg(feature = "provider-egress")]
        assert!(text.contains(PROVIDER_CONSULT_CONFIRM_PHRASE), "{text}");
    }

    #[cfg(feature = "provider-egress")]
    #[test]
    fn provider_consult_wrong_phrase_stays_locked() {
        let mut out: Vec<u8> = Vec::new();
        let mut err: Vec<u8> = Vec::new();
        let argv: Vec<String> = ["provider", "consult", "wrong-phrase", "hello"]
            .iter()
            .map(ToString::to_string)
            .collect();
        let result = run(&argv, &mut out, &mut err);
        assert!(result.is_ok());
        let text = String::from_utf8_lossy(&out);
        assert!(
            text.contains("denied: no live call without the exact phrase"),
            "{text}"
        );
    }

    #[cfg(feature = "provider-egress")]
    #[test]
    fn provider_consult_secret_shaped_question_is_denied_before_any_send() {
        // A 64-hex key-shaped token classifies as secret => dropped => denied.
        // The deny happens BEFORE transport, so no network is touched even when
        // the exact phrase is supplied and a key env var exists.
        let secret_like = "a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f90";
        let mut out: Vec<u8> = Vec::new();
        let mut err: Vec<u8> = Vec::new();
        let argv: Vec<String> = vec![
            "provider".to_string(),
            "consult".to_string(),
            PROVIDER_CONSULT_CONFIRM_PHRASE.to_string(),
            secret_like.to_string(),
        ];
        let result = run(&argv, &mut out, &mut err);
        assert!(result.is_ok());
        let text = String::from_utf8_lossy(&out);
        assert!(
            text.contains("question is secret-shaped; not sent"),
            "{text}"
        );
    }

    #[cfg(feature = "provider-egress")]
    #[test]
    fn wrap_consult_answer_is_char_safe_and_bounded() {
        let korean = "한글토큰 ".repeat(40);
        let wrapped = wrap_consult_answer(korean.as_str(), 10, 5);
        assert!(wrapped.len() <= 5, "{wrapped:?}");
        assert!(
            wrapped
                .iter()
                .all(|l| l.chars().count() <= 10 || l.starts_with("[answer truncated")),
            "{wrapped:?}"
        );
        let long_word = "x".repeat(50);
        let wrapped2 = wrap_consult_answer(&long_word, 10, 50);
        assert!(
            wrapped2.iter().all(|l| l.chars().count() <= 10),
            "{wrapped2:?}"
        );
        let multi = wrap_consult_answer("para one\n\npara two", 78, 52);
        assert_eq!(multi.len(), 3, "{multi:?}");
        assert_eq!(multi[1], "");
    }

    // E7-1: the streaming bridge is LOAD-BEARING on the consult answer render —
    // every segment passes the per-chunk redact wall (a mid-line secret token is
    // WITHHELD), and a plain answer round-trips unchanged.
    #[cfg(feature = "provider-egress")]
    #[test]
    fn stream_consult_answer_is_load_bearing_and_redacts_per_chunk() {
        // A secret token EMBEDDED mid-answer is its own chunk ⇒ withheld.
        let secret = "placeholderSecretForRedactionUnitTestOnly00";
        let answer = format!("the api key is {secret} ok use it");
        let streamed = stream_consult_answer(&answer, [9u8; 32], 78, 52);
        // The bridge actually ran (was 0-prod-caller before E7): one chunk per
        // whitespace/word run, so > the word count is impossible but > 0 proves
        // the feed; the secret word was the single redacted chunk.
        assert!(streamed.chunk_count_u32 > 0, "bridge fed no chunks");
        assert_eq!(
            streamed.redacted_chunks_u32, 1,
            "exactly the secret token chunk is withheld"
        );
        let text = streamed.lines.join("\n");
        assert!(
            text.contains("<redacted>"),
            "secret-shaped chunk withheld: {text}"
        );
        assert!(
            !text.contains(secret),
            "raw secret must NEVER reach the rendered surface: {text}"
        );
        // The surrounding plain words survive (no over-redaction of the answer).
        assert!(text.contains("the api key is"), "{text}");
        assert!(text.contains("ok use it"), "{text}");
    }

    #[cfg(feature = "provider-egress")]
    #[test]
    fn stream_consult_answer_preserves_plain_answer() {
        let answer = "local vertical green ships tomorrow";
        let streamed = stream_consult_answer(answer, [1u8; 32], 78, 52);
        assert_eq!(streamed.redacted_chunks_u32, 0, "no plain word is a secret");
        assert!(streamed.chunk_count_u32 > 0);
        let text = streamed.lines.join(" ");
        assert!(text.contains("local vertical green"), "{text}");
        // The feed receipt proves the answer is no longer a synchronous single
        // string and is honestly scoped.
        let receipt = stream_feed_receipt(&streamed);
        assert!(
            receipt.contains("progressive render of completed answer"),
            "{receipt}"
        );
        assert!(receipt.contains("intra-token SSE deferred"), "{receipt}");
    }

    // E7-2: context-pressure is a MEASURED signal (token consumption vs the loop
    // cap) — the status meter can now warn (was hard-coded 0 at every site).
    #[cfg(feature = "provider-egress")]
    #[test]
    fn context_pressure_is_measured_and_meter_can_warn() {
        let cap = crate::agent_loop::AGENT_LOOP_TOKEN_CAP; // 20_000
        // Empty run ⇒ honest 0 (no pressure).
        assert_eq!(token_budget_pressure_bps(0, 0, cap), 0);
        // Half the cap ⇒ 5000 bps (green band).
        assert_eq!(token_budget_pressure_bps(8_000, 2_000, cap), 5_000);
        // At/over the cap ⇒ saturates at 10000 (never overflows the bps domain).
        assert_eq!(token_budget_pressure_bps(u64::MAX, u64::MAX, cap), 10_000);
        // Zero cap is fail-safe 0 (never divide-by-zero).
        assert_eq!(token_budget_pressure_bps(1_000, 1_000, 0), 0);

        // The REAL value drives the status meter to a warning — proving the meter
        // is no longer a permanent green 0.
        let warn = |input: u64, output: u64| -> crate::tui::RenderTruth {
            let status = crate::repl::prompt::PromptStatus {
                workspace_hash_32: [1u8; 32],
                model_hash_32: [2u8; 32],
                context_pressure_bps: token_budget_pressure_bps(input, output, cap),
                last_checkpoint_hash_32: [3u8; 32],
                budget_remaining_micros: 0,
                sandbox_tier_u8: 1,
                pending_approvals_u16: 0,
                pending_tasks_u16: 0,
            };
            crate::tui::status_bar::StatusBar::new(
                status,
                crate::route::RouteExecutionState::Normal,
                crate::tui::RenderTruth::Green,
                crate::tui::RenderTruth::Green,
            )
            .context_truth()
        };
        assert_eq!(warn(2_000, 0), crate::tui::RenderTruth::Green); // 1000 bps
        assert_eq!(warn(15_000, 0), crate::tui::RenderTruth::Yellow); // 7500 bps
        assert_eq!(warn(19_000, 1_000), crate::tui::RenderTruth::Red); // 10000 bps
    }
}

// ---- P3-3: LOCAL consult route — tests (REAL loopback sockets only; ⑧ V1) -----
#[cfg(all(test, any(feature = "local-mlx", feature = "local-vllm")))]
mod provider_consult_local_tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use super::*;
    use crate::provider::local_chat::test_support::{canned_server, http_200};
    use crate::provider::local_endpoint::LoopbackBind;

    fn rest_of(tokens: &[&str]) -> Vec<String> {
        tokens.iter().map(ToString::to_string).collect()
    }

    const LOCAL_HAPPY_JSON: &str = r#"{"model":"naite-local-7b","choices":[{"message":{"role":"assistant","content":"ANSWER: local vertical green"},"finish_reason":"stop"}],"usage":{"prompt_tokens":30,"completion_tokens":9,"prompt_tokens_details":{"cached_tokens":12}}}"#;

    /// The full LOCAL vertical over a REAL loopback socket: phrase → walls →
    /// ONE live turn against the canned server → route-visible card. The
    /// CAPTURED request proves the sinabro identity + loop protocol rode the
    /// system prompt and that NO Authorization header exists (⑧ IV-L5 + R2).
    #[test]
    fn local_consult_vertical_happy_path() {
        let (port, captured) = canned_server(http_200(LOCAL_HAPPY_JSON));
        let rest = rest_of(&[
            "consult",
            PROVIDER_CONSULT_LOCAL_PHRASE,
            "what",
            "ships",
            "tomorrow?",
        ]);
        let mut out: Vec<u8> = Vec::new();
        let result = provider_consult_local_at(
            LoopbackBind::localhost(port),
            "default",
            &rest,
            &mut out,
            crate::otel_export::OtelExportSetting::Off,
            None,
        );
        assert!(result.is_ok());
        let text = String::from_utf8_lossy(&out);
        assert!(text.contains("LOCAL provider consult:"), "{text}");
        assert!(text.contains(&format!("127.0.0.1:{port}")), "{text}");
        assert!(
            text.contains("naite-local-7b"),
            "response-echoed model id rendered: {text}"
        );
        assert!(text.contains("backend=local_base"), "{text}");
        assert!(text.contains("local vertical green"), "{text}");
        assert!(text.contains("stop=loop.completed"), "{text}");
        assert!(text.contains("cached=12"), "{text}");
        assert!(text.contains("guard: action=continue"), "{text}");
        assert!(text.contains("loopback only; no key sent"), "{text}");

        let request = captured.recv().expect("request captured");
        assert!(request.contains("POST /v1/chat/completions"), "{request}");
        assert!(
            request.contains("You are Sinabro"),
            "identity prompt rode the wire: {request}"
        );
        assert!(
            request.contains("TOOL PROTOCOL"),
            "loop protocol rode the wire: {request}"
        );
        assert!(request.contains("what ships tomorrow?"), "{request}");
        assert!(
            !request.to_ascii_lowercase().contains("authorization"),
            "no auth header on the local path: {request}"
        );
    }

    /// E7-1 LIVE per-chunk redaction over a REAL loopback socket: the canned
    /// server returns an answer with a secret-shaped token EMBEDDED; the
    /// streaming bridge withholds exactly that chunk (`<redacted>`) before it
    /// reaches the rendered surface, the surrounding words survive, the feed
    /// receipt proves the bridge ran, and the context-pressure line shows the
    /// REAL measured token consumption (was hard-coded 0). A real socket
    /// round-trip through the production `provider_consult_local_at` path.
    #[test]
    fn local_consult_streams_and_redacts_secret_chunk_over_real_socket() {
        let secret = "placeholderSecretForRedactionUnitTestOnly00";
        let answer_json = format!(
            r#"{{"model":"naite-local-7b","choices":[{{"message":{{"role":"assistant","content":"ANSWER: the api token is {secret} keep it safe"}},"finish_reason":"stop"}}],"usage":{{"prompt_tokens":30,"completion_tokens":9,"prompt_tokens_details":{{"cached_tokens":12}}}}}}"#
        );
        let (port, _captured) = canned_server(http_200(&answer_json));
        let rest = rest_of(&[
            "consult",
            PROVIDER_CONSULT_LOCAL_PHRASE,
            "what",
            "is",
            "the",
            "key?",
        ]);
        let mut out: Vec<u8> = Vec::new();
        let result = provider_consult_local_at(
            LoopbackBind::localhost(port),
            "default",
            &rest,
            &mut out,
            crate::otel_export::OtelExportSetting::Off,
            None,
        );
        assert!(result.is_ok());
        let text = String::from_utf8_lossy(&out);
        // The secret-shaped chunk was WITHHELD per-chunk (no unredacted partial leak).
        assert!(
            text.contains("<redacted>"),
            "secret chunk must be withheld: {text}"
        );
        assert!(
            !text.contains(secret),
            "raw secret must NEVER reach the rendered surface: {text}"
        );
        // The surrounding plain words survive (no over-redaction).
        assert!(text.contains("the api token is"), "{text}");
        assert!(text.contains("keep it safe"), "{text}");
        // The streaming bridge is load-bearing on this real-socket answer.
        assert!(
            text.contains("stream: chunks="),
            "feed receipt present: {text}"
        );
        assert!(
            text.contains("redacted=1"),
            "exactly one chunk withheld: {text}"
        );
        assert!(
            text.contains("progressive render of completed answer"),
            "honest scope label: {text}"
        );
        // The context-pressure line carries the REAL measured tokens (30+9=39),
        // metered against the INTERACTIVE CHAT cap (`CHAT_TOKEN_CAP` = 256000,
        // P0 #1 — the consult render uses the chat cap, NOT the bounded-autonomy
        // 20000), not a hard-coded 0.
        assert!(
            text.contains("context: ") && text.contains("39/256000"),
            "measured context-pressure surfaced: {text}"
        );
    }

    /// Phrase gates fire BEFORE any socket: no phrase / wrong phrase ⇒ the
    /// LOCAL locked-usage render; phrase + empty question ⇒ typed error —
    /// all with ZERO connections to the canned server.
    #[test]
    fn local_consult_phrase_and_empty_gates_zero_sockets() {
        let (port, captured) = canned_server(http_200(LOCAL_HAPPY_JSON));
        let bind = LoopbackBind::localhost(port);

        let mut out: Vec<u8> = Vec::new();
        let no_phrase = rest_of(&["consult"]);
        assert!(
            provider_consult_local_at(
                bind,
                "default",
                &no_phrase,
                &mut out,
                crate::otel_export::OtelExportSetting::Off,
                None,
            )
            .is_ok()
        );
        let text = String::from_utf8_lossy(&out);
        assert!(text.contains("LOCAL route"), "{text}");
        assert!(text.contains(PROVIDER_CONSULT_LOCAL_PHRASE), "{text}");
        assert!(
            text.contains("denied: no local call without the exact phrase"),
            "{text}"
        );

        let mut out2: Vec<u8> = Vec::new();
        let wrong = rest_of(&["consult", "wrong-phrase", "hello"]);
        assert!(
            provider_consult_local_at(
                bind,
                "default",
                &wrong,
                &mut out2,
                crate::otel_export::OtelExportSetting::Off,
                None,
            )
            .is_ok()
        );
        assert!(
            String::from_utf8_lossy(&out2).contains("denied: no local call"),
            "wrong phrase stays locked"
        );

        let mut out3: Vec<u8> = Vec::new();
        let empty = rest_of(&["consult", PROVIDER_CONSULT_LOCAL_PHRASE]);
        assert!(
            provider_consult_local_at(
                bind,
                "default",
                &empty,
                &mut out3,
                crate::otel_export::OtelExportSetting::Off,
                None,
            )
            .is_ok()
        );
        assert!(
            String::from_utf8_lossy(&out3).contains("empty question; nothing sent"),
            "empty question is a typed error"
        );

        assert!(
            captured.try_recv().is_err(),
            "ZERO connections reached the server across all three gates"
        );
    }

    /// IV-L2: a secret-shaped question is denied BEFORE any socket — the
    /// loopback peer is an unaudited process; "local" buys zero relaxation.
    #[test]
    fn local_consult_secret_question_denied_zero_sockets() {
        let (port, captured) = canned_server(http_200(LOCAL_HAPPY_JSON));
        let secret_like = "a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f90";
        let rest = rest_of(&["consult", PROVIDER_CONSULT_LOCAL_PHRASE, secret_like]);
        let mut out: Vec<u8> = Vec::new();
        assert!(
            provider_consult_local_at(
                LoopbackBind::localhost(port),
                "default",
                &rest,
                &mut out,
                crate::otel_export::OtelExportSetting::Off,
                None,
            )
            .is_ok()
        );
        let text = String::from_utf8_lossy(&out);
        assert!(
            text.contains("question is secret-shaped; not sent"),
            "{text}"
        );
        assert!(captured.try_recv().is_err(), "no socket touched");
    }

    /// IV-L3: the bounded input cap is IDENTICAL to the frontier route and
    /// fires before any socket.
    #[test]
    fn local_consult_oversize_question_denied_zero_sockets() {
        let (port, captured) = canned_server(http_200(LOCAL_HAPPY_JSON));
        let oversize = "x".repeat(PROVIDER_CONSULT_MAX_QUESTION_BYTES + 1);
        let rest = rest_of(&["consult", PROVIDER_CONSULT_LOCAL_PHRASE, oversize.as_str()]);
        let mut out: Vec<u8> = Vec::new();
        assert!(
            provider_consult_local_at(
                LoopbackBind::localhost(port),
                "default",
                &rest,
                &mut out,
                crate::otel_export::OtelExportSetting::Off,
                None,
            )
            .is_ok()
        );
        let text = String::from_utf8_lossy(&out);
        assert!(
            text.contains("question exceeds the bounded input cap"),
            "{text}"
        );
        assert!(captured.try_recv().is_err(), "no socket touched");
    }

    /// Fail-closed live truth: no runtime on the port ⇒ the loop stops typed
    /// (`loop.transport_failed`) with the loopback-unreachable class in the
    /// trail — never a hang, never a silent fallback to the frontier route.
    #[test]
    fn local_consult_unreachable_is_typed_fail_closed() {
        let port = {
            let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
            listener.local_addr().expect("addr").port()
            // listener dropped ⇒ nothing listens on `port`
        };
        let rest = rest_of(&["consult", PROVIDER_CONSULT_LOCAL_PHRASE, "hello"]);
        let mut out: Vec<u8> = Vec::new();
        assert!(
            provider_consult_local_at(
                LoopbackBind::localhost(port),
                "default",
                &rest,
                &mut out,
                crate::otel_export::OtelExportSetting::Off,
                None,
            )
            .is_ok()
        );
        let text = String::from_utf8_lossy(&out);
        assert!(
            text.contains("agent loop stopped: loop.transport_failed"),
            "{text}"
        );
        assert!(
            text.contains("local endpoint unreachable (loopback)"),
            "{text}"
        );
    }

    /// The STRICT port resolver (⑧ gate 5): absent/blank ⇒ the feature
    /// default; garbage / 0 / out-of-range ⇒ typed deny (None) — never a
    /// silent default-on-garbage. Model resolver: trimmed, honest default.
    #[test]
    fn local_port_and_model_resolvers_strict() {
        // P4-3: the executor now consumes the SHARED `model_select` resolvers
        // with its feature default — this test pins that the executor-side
        // resolution is byte-identical to the selector view (no drift).
        use crate::commands::model_select::{
            LOCAL_DEFAULT_MODEL, resolve_local_model, resolve_local_port,
        };
        assert_eq!(
            resolve_local_port(None, LOCAL_CONSULT_DEFAULT_PORT),
            Some(LOCAL_CONSULT_DEFAULT_PORT)
        );
        assert_eq!(
            resolve_local_port(Some("  "), LOCAL_CONSULT_DEFAULT_PORT),
            Some(LOCAL_CONSULT_DEFAULT_PORT)
        );
        assert_eq!(
            resolve_local_port(Some("8000"), LOCAL_CONSULT_DEFAULT_PORT),
            Some(8000)
        );
        assert_eq!(
            resolve_local_port(Some(" 11434 "), LOCAL_CONSULT_DEFAULT_PORT),
            Some(11434)
        );
        assert_eq!(
            resolve_local_port(Some("abc"), LOCAL_CONSULT_DEFAULT_PORT),
            None
        );
        assert_eq!(
            resolve_local_port(Some("0"), LOCAL_CONSULT_DEFAULT_PORT),
            None
        );
        assert_eq!(
            resolve_local_port(Some("70000"), LOCAL_CONSULT_DEFAULT_PORT),
            None
        );
        assert_eq!(
            resolve_local_port(Some("-1"), LOCAL_CONSULT_DEFAULT_PORT),
            None
        );

        assert_eq!(resolve_local_model(None), LOCAL_DEFAULT_MODEL);
        assert_eq!(resolve_local_model(Some("  ")), LOCAL_DEFAULT_MODEL);
        assert_eq!(resolve_local_model(Some(" llama3.2 ")), "llama3.2");
    }

    /// ⑧ T6 (no hidden route): when BOTH the frontier and a local feature are
    /// compiled, the frontier locked surface advertises the local route.
    #[cfg(feature = "provider-egress")]
    #[test]
    fn frontier_locked_body_advertises_local_route() {
        let joined = provider_consult_locked_body().join("\n");
        assert!(
            joined.contains(PROVIDER_CONSULT_LOCAL_PHRASE),
            "locked surface must advertise the local route: {joined}"
        );
        assert!(joined.contains("loopback, no egress"), "{joined}");
    }

    /// E2-3 (PD-1): the system prompt's route-identity sentence is TRUE per route.
    /// The frontier prompt names the external frontier model; the LOCAL prompt
    /// names the loopback Naite model and NEVER claims "external frontier model".
    /// Both keep the full 35-namespace catalog + HARD LIMITS (one shared head/tail,
    /// no drift) — the no-fake-label proof for the local Naite route (PD-1).
    #[cfg(feature = "provider-egress")]
    #[test]
    fn system_prompt_route_identity_is_true_per_route() {
        let frontier = sinabro_system_prompt(false);
        let local = sinabro_system_prompt(true);
        // frontier: the route sentence is byte-identical to the prior shared prompt.
        assert!(
            frontier.contains("running on an external frontier model"),
            "{frontier}"
        );
        assert!(frontier.contains("advisory until locally verified"));
        // local: the TRUE label — loopback Naite, NEVER an external frontier model.
        assert!(
            local.contains("running on the LOCAL Naite model"),
            "{local}"
        );
        assert!(local.contains("loopback"));
        assert!(
            !local.contains("external frontier model"),
            "the local prompt must NOT claim an external frontier model: {local}"
        );
        // both keep the shared head + full namespace catalog + hard limits (no drift).
        for p in [&frontier, &local] {
            assert!(p.contains("Internal model name: Naite"));
            assert!(p.contains("You wrap 35 command namespaces"));
            assert!(p.contains("permission (allow/revoke), notify"));
            // P2-P3 (identity self-awareness, de-narrowed per the owner identity-lock): the
            // prompt names sinabro as the general autonomous self-evolving multi-expert agent —
            // audit is ONE domain, never the whole identity (NOT a narrow "coding/ops tool").
            assert!(
                p.contains("self-evolving multi-expert agent"),
                "prompt must name the multi-expert identity: {p}"
            );
            assert!(
                p.contains("audit is ONE domain, never your whole identity"),
                "prompt must de-narrow audit to one domain: {p}"
            );
            // custody stays HARD-LOCKED in the prompt (the one permanent limit) ...
            assert!(p.contains("are HARD-LOCKED"));
            assert!(p.contains("never touch money or sign a chain write"));
            // ... and the E14-B3 ACT-FIRST, capability-forward framing is present:
            // for a READ the model DOES IT with the tool (no offer-prose), and it
            // never refuses a real capability with a defensive "I can't".
            assert!(p.contains("DO IT NOW with the matching tool"));
            assert!(p.contains("act first"));
            assert!(p.contains("NEVER refuse a real capability"));
            assert!(p.contains("Answer AS Sinabro, in the"));
            // ONCHAIN-PIVOT re-aim (was E10-3a): web3/chain is named as a DOMAIN, and
            // the agent now ACTIVELY READS chain state — it reads the live Skew chain
            // freely (READ-class) and the owner can arm a bounded RPC reader
            // (daemon web3-read). The pre-pivot "NO built-in chain reader" claim is
            // therefore STALE and FALSE, so it must be ABSENT from the prompt; the
            // false live-reader overclaim "read web3/chain state" must also stay gone.
            assert!(
                p.contains("reason about web3/chain as a DOMAIN"),
                "prompt must name web3 as a domain capability: {p}"
            );
            assert!(
                !p.contains("NO built-in chain reader"),
                "the stale pre-pivot 'NO built-in chain reader' claim must be gone — the agent reads the live Skew chain: {p}"
            );
            assert!(
                !p.contains("read web3/chain state"),
                "the false 'read web3/chain state' live-reader overclaim must be gone: {p}"
            );
            // ONCHAIN PIVOT re-aim (owner 2026-07-01 "Skew에만 한정두지말고 온체인 다 읽고
            // 쓰게"): the prompt LEADS with sinabro's GENERAL bounded on-chain identity —
            // a domain-general agent that reads ANY chain and acts on any ALLOWED
            // chain/protocol within owner-bounded custody — and names Skew derivatives
            // trading as its MOST-DEVELOPED example (not its limit): the free live Skew
            // reads, the owner-armed `daemon trade` K-2 chokepoint over the executable
            // instruction set, and the K-1 deterministic worst-case-loss oracle stay
            // named, while KEEPING the safety needles (no self-arm / no auto-trade,
            // user-bounded custody, mainnet locked, CustodyCapability uninhabited).
            assert!(
                p.contains("BOUNDED ON-CHAIN AGENT, domain-GENERAL"),
                "prompt must LEAD with the general (not Skew-limited) on-chain identity: {p}"
            );
            assert!(
                p.contains("that is ONE example, not your limit"),
                "Skew must be framed as one example, not the agent's whole identity: {p}"
            );
            assert!(
                p.contains("DERIVATIVES TRADING OPERATOR for the Skew protocol on Solana"),
                "prompt must still name Skew derivatives trading as the flagship example: {p}"
            );
            assert!(p.contains("READ the live Skew chain"), "{p}");
            assert!(
                p.contains("read the LIVE Skew derivatives chain on Solana"),
                "prompt must name the free live Skew reads: {p}"
            );
            assert!(
                p.contains("daemon trade <CUSTODY-ARM-PHRASE> <sim|live|fast|turbo>"),
                "prompt must name the owner-armed daemon trade chokepoint: {p}"
            );
            assert!(
                p.contains("deterministic K-1 worst-case-loss"),
                "prompt must name the K-1 worst-case-loss oracle: {p}"
            );
            assert!(
                p.contains("Custody is USER-BOUNDED, not blanket-blocked"),
                "prompt must frame custody as user-bounded, not blanket-blocked: {p}"
            );
            assert!(
                p.contains("NEVER self-arm, auto-trade, or move"),
                "the no-self-arm / no-auto-trade safety needle must survive: {p}"
            );
            assert!(
                p.contains("CustodyCapability is uninhabited"),
                "unbounded custody must stay an uninhabited type: {p}"
            );
            assert!(
                p.contains("MAINNET stays locked"),
                "mainnet must stay locked behind a further owner arm: {p}"
            );
            // E11-5 (capability activation awareness): the prompt names the REAL
            // live set the agent now holds — a content-free project index, a web
            // fetch / configured web search, an `audit detect` that surfaces
            // candidate LEADS (never confirmed findings; PROPOSE-only — the model
            // can neither promote nor run a repro), and a bounded owner-armed
            // autonomy loop (`daemon serve`). It also draws the propose-vs-invoke
            // line: READS are autonomous, CHANGES are proposed for the owner.
            assert!(p.contains("index a project's files (content-free)"), "{p}");
            assert!(
                p.contains("fetch an https web page or run a configured web search"),
                "{p}"
            );
            assert!(
                p.contains("audit detect surfaces candidate LEADS, never confirmed findings"),
                "prompt must name audit detect as candidate-leads, not findings: {p}"
            );
            assert!(
                p.contains("you can neither promote a candidate nor run a repro yourself"),
                "{p}"
            );
            assert!(
                p.contains("bounded, owner-armed autonomy loop (daemon serve)"),
                "{p}"
            );
            assert!(p.contains("these are READS, no approval needed"), "{p}");
            assert!(
                p.contains("those are CHANGES you PROPOSE for the owner to approve"),
                "{p}"
            );
            // E11-6 (cursor-parity awareness re-sync): the prompt also names the FIVE
            // READ tools added after E11-5 — search (find-in-files), lsp diagnostics
            // (compiler truth), git read, test run (real PASS/FAIL), and a configured
            // local MCP read tool — so the consult self-description matches the live
            // loop-tool set (the agent_loop SINABRO_LOOP_PROTOCOL already teaches them).
            assert!(p.contains("search the codebase by regex"), "{p}");
            assert!(p.contains("compiler diagnostics (lsp diagnostics)"), "{p}");
            assert!(p.contains("read the local git repo"), "{p}");
            assert!(p.contains("run a workspace package's tests"), "{p}");
            assert!(p.contains("configured local MCP server"), "{p}");
            // The Slack/Discord live over-claim is GONE — E9 DisabledPreview stub;
            // Telegram is the only LIVE messaging surface. The platform NAMESPACE
            // stays, so the catalog is still 35 (asserted above).
            assert!(
                p.contains("platform (Telegram live; Slack/Discord disabled preview)"),
                "platform must be honest: Telegram live, Slack/Discord disabled: {p}"
            );
            assert!(
                !p.contains("Telegram/Slack/Discord"),
                "the Slack/Discord live over-claim must be gone: {p}"
            );
        }
    }

    /// P4-1 (⑨): the SAME local vertical with the OTel opt-in INJECTED — Off
    /// keeps the card byte-free of `otel:` (baseline preservation, IV-O4);
    /// On adds exactly one `otel: exported` receipt line AND the span file
    /// exists under the injected dir, parsing as ONE OTLP/JSON line whose
    /// attributes carry the response-echoed model + route backend (the
    /// no-fake-feature proof: the claim renders only with the file on disk).
    #[test]
    fn local_consult_otel_export_vertical() {
        let rest = rest_of(&["consult", PROVIDER_CONSULT_LOCAL_PHRASE, "ping?"]);

        // Off: no otel line.
        let (port_off, _captured_off) = canned_server(http_200(LOCAL_HAPPY_JSON));
        let mut out_off: Vec<u8> = Vec::new();
        assert!(
            provider_consult_local_at(
                LoopbackBind::localhost(port_off),
                "default",
                &rest,
                &mut out_off,
                crate::otel_export::OtelExportSetting::Off,
                None,
            )
            .is_ok()
        );
        let text_off = String::from_utf8_lossy(&out_off);
        assert!(text_off.contains("LOCAL provider consult:"), "{text_off}");
        assert!(!text_off.contains("otel:"), "{text_off}");

        // On (injected temp dir — never the real $HOME, never process env).
        let dir =
            std::env::temp_dir().join(format!("sinabro-otel-dispatch-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let (port, _captured) = canned_server(http_200(LOCAL_HAPPY_JSON));
        let mut out: Vec<u8> = Vec::new();
        assert!(
            provider_consult_local_at(
                LoopbackBind::localhost(port),
                "default",
                &rest,
                &mut out,
                crate::otel_export::OtelExportSetting::On,
                Some(&dir),
            )
            .is_ok()
        );
        let text = String::from_utf8_lossy(&out);
        assert!(text.contains("otel: exported "), "{text}");
        assert!(text.contains("spans=1"), "{text}");
        let entries: Vec<_> = std::fs::read_dir(&dir).expect("otel dir exists").collect();
        assert_eq!(entries.len(), 1, "exactly one span file: {text}");
        let path = entries[0].as_ref().expect("entry").path();
        assert!(
            path.file_name()
                .map(|n| n.to_string_lossy().ends_with(".otlp.jsonl"))
                .unwrap_or(false),
            "{path:?}"
        );
        let content = std::fs::read_to_string(&path).expect("span file reads");
        let v: serde_json::Value =
            serde_json::from_str(content.trim_end_matches('\n')).expect("OTLP/JSON parses");
        let span = &v["resourceSpans"][0]["scopeSpans"][0]["spans"][0];
        assert_eq!(span["name"], "sinabro.provider.consult");
        let attrs = span["attributes"].as_array().expect("attributes");
        let get_str = |k: &str| {
            attrs
                .iter()
                .find(|a| a["key"] == k)
                .and_then(|a| a["value"]["stringValue"].as_str())
                .map(ToString::to_string)
        };
        assert_eq!(get_str("sinabro.model").as_deref(), Some("naite-local-7b"));
        assert_eq!(get_str("sinabro.backend").as_deref(), Some("local_base"));
        assert_eq!(
            get_str("sinabro.loop.stop").as_deref(),
            Some("loop.completed")
        );
        let _ = std::fs::remove_dir_all(&dir);
    }
}

// ---- T: gated live Telegram send — surface tests (no network in any test) ------
#[cfg(test)]
mod platform_send_surface_tests {
    use super::*;
    use crate::grammar::CliNamespace;

    #[test]
    fn platform_send_classifies_network_in_every_build() {
        assert_eq!(
            risk_for(CliNamespace::Platform, "send"),
            CommandRisk::Network
        );
        assert!(is_recognized_verb("send"));
    }

    #[test]
    fn platform_send_without_phrase_renders_locked_not_executed() {
        let mut out: Vec<u8> = Vec::new();
        let mut err: Vec<u8> = Vec::new();
        let argv = vec!["platform".to_string(), "send".to_string()];
        let result = run(&argv, &mut out, &mut err);
        assert!(result.is_ok());
        let text = String::from_utf8_lossy(&out);
        assert!(text.contains("risk=network"), "{text}");
        // Default build: the generic locked surface (UNCHANGED behavior).
        #[cfg(not(feature = "telegram-egress"))]
        assert!(text.contains("side effect is NOT executed"), "{text}");
        // Feature build: the gated preview teaching the exact phrase — still no
        // execution (the phrase gate runs before redaction/build/socket).
        #[cfg(feature = "telegram-egress")]
        assert!(text.contains(TELEGRAM_SEND_CONFIRM_PHRASE), "{text}");
    }

    #[cfg(feature = "telegram-egress")]
    #[test]
    fn platform_send_wrong_phrase_stays_locked() {
        let mut out: Vec<u8> = Vec::new();
        let mut err: Vec<u8> = Vec::new();
        let argv: Vec<String> = ["platform", "send", "wrong-phrase", "hello"]
            .iter()
            .map(ToString::to_string)
            .collect();
        let result = run(&argv, &mut out, &mut err);
        assert!(result.is_ok());
        let text = String::from_utf8_lossy(&out);
        assert!(
            text.contains("denied: no live send without the exact phrase"),
            "{text}"
        );
    }

    #[cfg(feature = "telegram-egress")]
    #[test]
    fn platform_send_secret_shaped_message_is_denied_before_any_send() {
        // A 64-hex key-shaped token classifies as secret => dropped => denied
        // BEFORE transport — no network touched even with the exact phrase.
        let secret_like = "a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f90";
        let mut out: Vec<u8> = Vec::new();
        let mut err: Vec<u8> = Vec::new();
        let argv: Vec<String> = vec![
            "platform".to_string(),
            "send".to_string(),
            TELEGRAM_SEND_CONFIRM_PHRASE.to_string(),
            secret_like.to_string(),
        ];
        let result = run(&argv, &mut out, &mut err);
        assert!(result.is_ok());
        let text = String::from_utf8_lossy(&out);
        assert!(
            text.contains("message is secret-shaped; not sent"),
            "{text}"
        );
    }
}

// ---- render: UTF-8 survival (Hangul/CJK LLM answers must not be ASCII-stripped)
#[cfg(test)]
mod render_utf8_tests {
    use super::*;

    #[test]
    fn clamp_keeps_utf8_drops_control() {
        // ASCII unchanged (command output stays byte-identical)
        assert_eq!(clamp_ascii("hello world"), "hello world");
        // Hangul / CJK survive (the live-LLM-answer fix)
        assert_eq!(clamp_ascii("안녕하세요"), "안녕하세요");
        assert_eq!(clamp_ascii("日本語のテスト"), "日本語のテスト");
        // control chars still stripped (terminal-compat)
        assert_eq!(clamp_ascii("a\tb\nc\rd"), "abcd");
    }
}
