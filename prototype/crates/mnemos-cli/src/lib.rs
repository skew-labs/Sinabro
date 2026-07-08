//! `sinabro` — the Mnemos / Sinabro CLI Cockpit.
//!
//! This crate turns the memory / evidence / policy / data-rights core into a
//! CLI-first product surface. This crate is a *surface*: it reads and drives
//! the canonical core truth and never reinvents it. Every user action compiles to a
//! typed [`command::CommandEnvelope`] guarded by a [`command::CommandRisk`] and
//! an [`command::ApprovalRequirement`]; the safety kernel is non-disableable;
//! learning and data egress default to off.
//!
//! Crate-home note: the directory is `crates/mnemos-cli`
//! but the package is `sinabro` because the legacy `bin/mnemos-cli` already owns
//! the package name `mnemos-cli`. `sinabro` is the public binary; `mnemos` is the
//! legacy alias.
//!
//! Reuse (interface-only, no business truth copied): the secret/redaction
//! conventions come from `mnemos-a-core` ([`mnemos_a_core::looks_like_secret`],
//! [`mnemos_a_core::redact_for_log`]); the error shape mirrors
//! [`mnemos_a_core::MnemosError`] (no `anyhow`, `Display` is a fixed label, no
//! secret/raw input ever embedded).
// `deny` (not `forbid`) so the single isolated `tui::raw` module can re-allow
// `unsafe` for its two libc `termios` FFI calls (the only allowed unsafe in the
// crate); every other module in the crate stays unsafe-denied.
#![deny(unsafe_code)]
#![deny(missing_docs)]
// Test code may use `unwrap`/`expect`/`panic!` (a failed assertion SHOULD panic). The
// `-D clippy::unwrap_used` etc. denials are for the PROD surface only (verified clean via
// `cargo clippy -p sinabro --lib`); this crate-wide `cfg_attr(test, …)` makes that policy
// explicit + consistent (several recent test modules — web_fetch / download_fetch / runtime /
// memory_walrus / telegram — used unwrap/expect without a per-module `#![allow]`, which the
// `--all-targets` clippy flags on a fresh relint). PROD `unwrap_used` denial is UNCHANGED.
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used, clippy::panic))]

pub mod agent_loop;
// The two-model orchestration
// loop — frontier PLAN -> decompose -> per-sub-task route + local IMPLEMENT ->
// frontier SYNTHESIZE. A NEW caller chaining the UNMODIFIED run_agent_loop_with;
// L1 of the three-layer separation.
pub mod agent_orchestrator;
// The agent-native GitHub: the PURE
// content-addressed artifact registry core — a git-object analog (skills / adapters /
// strategies / memories / code / oracles addressed by content hash) + the AGRX manifest
// codec. NO egress / NO execution here; later slices add the AI-native wire protocol, the
// gated Walrus publish/fetch, the loop tool, the GUI, and the sandboxed fetch-then-propose.
pub mod agent_registry;
pub mod audit;
pub mod command;
pub mod commands;
pub mod completion;
pub mod config;
pub mod conformal;
// Mycel: the CONTENT STORE adapter — the agent-registry's storage behind a
// swappable, content-addressed backend (default = non-chain LocalCasStore; Walrus/S3 are
// feature-gated adapters). Backend independence is safe because the registry's
// content-hash seatbelt re-hashes content→artifact_id, not the storage cid.
pub mod content_store;
// Mycel: the S3 content-store adapter (feature `s3`) — S3-compatible backend over
// reqwest + a HAND-ROLLED SigV4 (no AWS SDK, no hmac crate; HMAC-SHA256 on sha2). Locked
// byte-exact to the AWS get-vanilla vector. Backend-independence is safe by the same content-hash re-hashing.
pub mod daemon;
// Nous IR: the definition-unit node identity codec — one function/type = one
// node, cid derived from CONTENT (P-LOCK-2: the name is data, not identity). PURE
// codec lane (no network, no custody surface).
pub mod defn_node;
pub mod dispatch;
pub mod doctor;
pub mod evidence;
pub mod exec_local;
pub mod exec_proposal;
pub mod file_context;
pub mod file_edit;
#[cfg(feature = "s3")]
pub mod s3_store;
// REWIND (the differentiator Codex lacks): a content-capturing "last applied
// edit" revert point that restores the displaced bytes through the SAME
// owner_save_file staleness-locked atomic path. Local-file-only; custody untouched.
pub mod git;
pub mod grammar;
// Nous IR: the first-language definition-unit ingest — TypeScript, with
// CONSERVATIVE sound-first syntactic normalization
// (whitespace/comments/ASI-safe newlines/own-name/alpha). Fail-closed lexer; the
// only fs touch is the walled render path.
pub mod ingest_ts;
// IDENTITY (cross-agent reputation unlock): a hand-rolled Lamport one-time signature
// on sha256 — turns the author DATA stub into a forgery-resistant CRYPTOGRAPHIC
// identity (identity_id = sha256(domain ‖ pubkey); sign/verify an attestation). NOT
// custody: hash-based, no curve/wallet/chain/funds symbol.
pub mod identity;
// Nous IR: the INTENT SPEC — a change's "why" as SEVEN machine-queryable
// fields (goal/preconditions/invariants/considered-alternatives/uncertainty/
// evidence/provenance), content-addressed; prose is a one-way render
// of the structure (never parsed back). PURE codec; the ledger Intent op's real content.
pub mod intent_spec;
// Nous IR: the LEDGER — append-only hash-linked op log (pin/name-bind/proof/
// intent) + the P-LOCK-3 capability-witness PIN that promotes the morphism advisory
// verdict into REAL composition (judge gates INSIDE compose; escalated pairs cannot
// compose, structurally). Effect-first write ordering = false-audit-impossible.
pub mod ledger;
pub mod lsp;
pub mod mcp;
pub mod memory;
pub mod memory_crag;
pub mod memory_store;
pub mod memory_walrus;
pub mod metamorphic_oracle;
// Nous IR: the TYPED MORPHISM + deterministic commute/conflict JUDGE —
// change = before/after node-sets + predicates + invariants + ns effects, all
// content-addressed (P-LOCK-3); "conflict" = predicate/effect incompatibility over
// the (nodes, names) world, NOT textual overlap; escalate-by-default (P-LOCK-4,
// zero false merge = the kill gate). FULLY PURE; v0 verdict is advisory (no apply
// surface — the ledger seam).
pub mod morphism;
// Nous IR: the NAMESPACE — name↔cid mappings as versioned first-class data
// (append-only Bind/Unbind event log, deterministic fold, aliases; a rename is
// mapping events ONLY — the node is untouched by construction). Fail-closed NSPX
// codec; persistence via the shared atomic_write; authority model = honest v1 stub.
pub mod namespace;
// Nous IR: the REDACTION PROTOCOL — satisfy "delete my data / remove this
// secret" WITHOUT breaking the append-only chain: overwrite the ContentStore blob
// with a tombstone + record the cid/reason-class in the RDXN registry (the LEDGER is
// byte-unchanged; the chain hashes ops, not content). classify_fetch distinguishes
// redacted / tampered / present / absent.
pub mod recognition_elicit;
pub mod recognition_synth;
pub mod reconcile_oracle;
pub mod redaction;
// The loop-tool glue for the pinned agent registry —
// pointer file + prefix resolution (PURE) + the `put-fixture-net`-gated verified
// fetch. The trust anchor (the pointer) is owner-written only; every fetch passes
// the content-hash seatbelt.
pub mod registry_loop;
pub mod revert_blob;
pub mod zerog_attestation;
pub mod zerog_chain;
pub mod zerog_finetune;
pub mod zerog_inft;
pub mod zerog_storage;
// AGENT ACTS: the single gated EXECUTE chokepoint for
// agent-proposed side effects — `execute_authorized_mutate` requires a
// MutateCapability witness, so no exec/edit runs without owner authority.
pub mod mutate_execute;
// The single gated chokepoint for an owner-BOUNDED on-chain tx —
// `execute_authorized_chain_tx` requires a `ChainTxCapability` witness (minted ONLY from a
// VALID owner-armed `CustodyGrant` + a within-bounds tx). It is INERT (no sign/broadcast,
// money 0); a later slice adds the isolated signer + RPC. Blanket `CustodyCapability` stays uninhabited.
pub mod chain_execute;
pub mod chain_signer;
pub mod skew_execute;
// Oracle Bootstrap: capitalize a CERTIFIED oracle as an ERC-7857 iNFT —
// composes the LOCKED `zerog_inft` encoder; the dataHash is a deterministic certified-oracle
// commitment, FAIL-CLOSED on a TYPED cert (recognition = the conformal α-budget; reconcile/
// metamorphic = deterministic-sound, canary-gated). PURE PREPARE; custody/funds HARD-LOCKED
// (the binary signs nothing — the owner FIRES the mint).
pub mod oracle_inft;
// OTel trace export — the thin OTLP/JSON
// projection over the consult receipt truth. cfg-gated to the ONLY features
// whose executors can call it (the default build compiles ZERO
// exporter code, so the default surface is byte-identical structurally).
#[cfg(any(
    feature = "provider-egress",
    feature = "local-mlx",
    feature = "local-vllm"
))]
pub mod otel_export;
// Multi-repo / project context — a bounded,
// deterministic, content-free recursive file index over the registered
// (allowlisted) project roots. Reuses lane A's `FileReadPolicy` allowlist +
// `denied_token` denylist; adds enumeration bounds (the FIRST recursive
// enumeration of an arbitrary user project tree). LOCAL/owner tier (the
// loop grammar is byte-unchanged — the model cannot enumerate).
pub mod project_index;
// Nous IR: the PROOF CACHE — verification memoized by (input-closure cid,
// procedure); a re-verification of identical bytes is a LOOKUP (recomputation 0).
// v1 procedure = the PURE ingest (deterministic by construction); computed runs
// emit the `Proof` op (typed Proof-only append). Cache-trust hardening is a later slice.
pub mod prompt_status;
pub mod proof_cache;
// Nous IR: PROOF AUDIT — random re-verification (seed-late-bound, reproducible)
// + signer reputation (RPUX counters, derived standing, heavy-slash). A poisoned
// receipt is re-run from its CAS closure; a mismatch slashes the claimant and records
// an `Audit` op.
pub mod proof_audit;
pub mod provider;
// Owner-box / remote-shell lane (highest-risk): an owner-armed,
// READ-only-allowlisted, config-only-host, sandboxed OpenSSH-subprocess remote diagnostic.
// custody HARD-LOCKED; the credential stays in the OS ssh config (never enters sinabro).
pub mod remote;
pub mod repl;
pub mod route;
pub mod sandbox_exec;
pub mod search;
pub mod secrets;
pub mod settings_sync;
pub mod setup;
pub mod skew_catalog;
pub mod skew_history;
pub mod skew_oracle;
pub mod skew_payoff_svg;
pub mod skew_read;
pub mod skew_strategy;
pub mod skill;
pub mod solana_codec;
pub mod telegram;
pub mod test_run;
pub mod tool;
pub mod trace;
pub mod tui;
pub mod ui;
// The autonomous Read-Execute-WRITE evolution loop's
// DETERMINISTIC write-decision core — a verified pattern persists ONLY if its oracle
// receipt admits_write AND it is cross-memory consistent with the held LTM; each write
// carries a DGM-H perf-tracking score (reinforced on verified-good). Pure, 0 IO, 0 tokens.
pub mod autonomy_evolve;
// The CODE-class oracle — the one impure companion
// to the pure `verification` ladder. Extracts Move from the local answer, materializes a
// temp Sui package, and runs `sui move build` in the network-DENIED sandbox; the exit
// Semantic codebase index — local embeddings (pluggable seam) + an encrypted-at-rest
// vector store + hybrid cosine/lexical retrieval; @codebase READ; embeddings never egress.
pub mod codebase_index;
// code is the oracle bit fed to verify(Code, ..). Build-only (no chain action). 0 tokens.
pub mod code_oracle;
// The Typed-Write-Admission TRUST-TIER ladder — the
// anti-hallucination anchor. Maps a sub-task's expert kind to one of five verification classes
// (Code / PersonalOwner / ExternalFact / ModelInference / CrossMemory), then to a
// class-typed ORACLE (compiler bit / owner provenance / independent corroboration /
// DGM-H perf-tracking / contradiction-detection) that produces a typed receipt; only a
// Verified receipt admits a permanent Write. Compiler is ONE class, NOT universal.
// classify is total (unknown kind ⇒ ModelInference, lowest-trust fail-safe). The
// model's TEXT is never an input (no self-certification). Pure, no IO, 0 tokens.
pub mod verification;
// Multimodal / image input — local-vision-first: an image as a READ context
// fragment (local describe seam, no egress) + an owner-armed frontier-image EGRESS path
// with the explicit "an image cannot be auto-redacted" warning. custody HARD-LOCKED.
pub mod vision;

use sha2::{Digest, Sha256};

/// Grammar version stamped into every [`command::CommandId`]; bumped only when
/// the closed command surface changes shape (snapshot-gated).
pub const GRAMMAR_VERSION_U16: u16 = 1;

/// CLI config schema version (see [`config::CliConfigDigest`]).
pub const CONFIG_SCHEMA_VERSION_U16: u16 = 1;

/// Compute a SHA-256 digest of `bytes` as a fixed 32-byte array.
#[must_use]
pub fn sha256_32(bytes: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hasher.finalize().into()
}

/// Lower-case hex encoding of a 32-byte digest (64 chars). Hand-rolled to avoid
/// an extra dependency (matches the `hex32_encode` convention).
#[must_use]
pub fn hex32(bytes: &[u8; 32]) -> String {
    const LUT: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(64);
    for &b in bytes {
        out.push(LUT[(b >> 4) as usize] as char);
        out.push(LUT[(b & 0x0f) as usize] as char);
    }
    out
}

// ---- Handoff + trace ------------------------------------------------------

/// The predecessor plan/DoD + command-grammar hash lock proving this crate starts on
/// a closed, evidence-backed predecessor set.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StageFHandoffDigest {
    /// SHA-256 of the Phase 0 / Stage A plan.
    pub atom_plan_a_hash_32: [u8; 32],
    /// SHA-256 of the Stage B plan.
    pub stage_b_plan_hash_32: [u8; 32],
    /// SHA-256 of the Stage C plan.
    pub stage_c_plan_hash_32: [u8; 32],
    /// SHA-256 of the Stage D plan.
    pub stage_d_plan_hash_32: [u8; 32],
    /// SHA-256 of the Stage E plan.
    pub stage_e_plan_hash_32: [u8; 32],
    /// SHA-256 of the Stage E Definition-of-Done evidence bundle.
    pub stage_e_dod_hash_32: [u8; 32],
    /// SHA-256 of the closed Stage F command grammar surface.
    pub command_grammar_hash_32: [u8; 32],
}

/// Links a command trace to its Stage F atom + gate id.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StageFTraceLink {
    /// SHA-256 of the command trace record this link points at.
    pub command_trace_hash_32: [u8; 32],
    /// Stage F atom id.
    pub stage_f_atom_u16: u16,
    /// Gate id that governs the atom.
    pub gate_id_u16: u16,
}

impl StageFTraceLink {
    /// Construct a trace link.
    #[must_use]
    pub const fn new(
        command_trace_hash_32: [u8; 32],
        stage_f_atom_u16: u16,
        gate_id_u16: u16,
    ) -> Self {
        Self {
            command_trace_hash_32,
            stage_f_atom_u16,
            gate_id_u16,
        }
    }
}

/// A hashed evidence path bound to a trace link.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StageFEvidenceRef {
    /// SHA-256 of the evidence path.
    pub path_hash_32: [u8; 32],
    /// The trace link the evidence belongs to.
    pub trace: StageFTraceLink,
}

// ---- handoff lock ---------------------------------------------------------

/// Read-only projection of the Stage G unlock truth the handoff lock checks.
/// Mirrors the three lock booleans of the on-disk
/// `datasets/stage_e/stage_g_unlock.json` (E DoD). This is a CLI *view* of E's
/// `StageGUnlockPacket`, not a reinvention of it — Stage F never flips these.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StageGUnlockView {
    /// Whether the SFT smoke is unlocked (must be `false` in Stage F).
    pub sft_smoke_ready: bool,
    /// Whether GRPO is locked (must be `true`).
    pub grpo_locked: bool,
    /// Whether self-evolution promotion is locked (must be `true`).
    pub self_evolution_promotion_locked: bool,
}

/// Why an A–E handoff lock check rejected.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HandoffReject {
    /// One or more A–E predecessor evidence inputs were empty.
    MissingPredecessorEvidence,
    /// E reported `grpo_locked = false` — train must stay locked in Stage F.
    GrpoUnlocked,
    /// E reported self-evolution promotion unlocked.
    SelfEvolutionUnlocked,
    /// Stage F must not observe SFT smoke unlocked.
    SftSmokeUnlockedTooEarly,
}

/// Raw bytes of the A–E predecessor artifacts + the Stage F command-grammar
/// surface, bundled so the handoff verifier takes a single input value.
#[derive(Clone, Copy, Debug)]
pub struct HandoffInputs<'a> {
    /// Phase 0 / Stage A plan bytes.
    pub atom_plan_a: &'a [u8],
    /// Stage B plan bytes.
    pub stage_b_plan: &'a [u8],
    /// Stage C plan bytes.
    pub stage_c_plan: &'a [u8],
    /// Stage D plan bytes.
    pub stage_d_plan: &'a [u8],
    /// Stage E plan bytes.
    pub stage_e_plan: &'a [u8],
    /// Stage E DoD bundle bytes.
    pub stage_e_dod: &'a [u8],
    /// Stage F command-grammar surface bytes.
    pub command_grammar: &'a [u8],
}

/// Verify the A–E handoff lock and, on success, return the [`StageFHandoffDigest`].
///
/// The lock fails closed if any predecessor input is empty or if the Stage G
/// unlock view shows training / self-evolution unlocked.
pub fn verify_handoff(
    inputs: &HandoffInputs<'_>,
    unlock: StageGUnlockView,
) -> Result<StageFHandoffDigest, HandoffReject> {
    let parts = [
        inputs.atom_plan_a,
        inputs.stage_b_plan,
        inputs.stage_c_plan,
        inputs.stage_d_plan,
        inputs.stage_e_plan,
        inputs.stage_e_dod,
        inputs.command_grammar,
    ];
    for part in parts {
        if part.is_empty() {
            return Err(HandoffReject::MissingPredecessorEvidence);
        }
    }
    if !unlock.grpo_locked {
        return Err(HandoffReject::GrpoUnlocked);
    }
    if !unlock.self_evolution_promotion_locked {
        return Err(HandoffReject::SelfEvolutionUnlocked);
    }
    if unlock.sft_smoke_ready {
        return Err(HandoffReject::SftSmokeUnlockedTooEarly);
    }
    Ok(StageFHandoffDigest {
        atom_plan_a_hash_32: sha256_32(inputs.atom_plan_a),
        stage_b_plan_hash_32: sha256_32(inputs.stage_b_plan),
        stage_c_plan_hash_32: sha256_32(inputs.stage_c_plan),
        stage_d_plan_hash_32: sha256_32(inputs.stage_d_plan),
        stage_e_plan_hash_32: sha256_32(inputs.stage_e_plan),
        stage_e_dod_hash_32: sha256_32(inputs.stage_e_dod),
        command_grammar_hash_32: sha256_32(inputs.command_grammar),
    })
}

// ---- crate error ----------------------------------------------------------

/// Typed CLI error. Mirrors the a-core convention: no `anyhow`/`eyre`, no panic,
/// and the `Display` text is a fixed label that never embeds a secret or raw
/// input.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum CliError {
    /// An unknown / non-closed command verb was supplied.
    #[error("unknown command")]
    UnknownCommand,
    /// A config layer failed to parse or violated a hard policy.
    #[error("invalid config")]
    InvalidConfig,
    /// A safety-kernel feature was asked to be disabled (forbidden in any profile).
    #[error("safety kernel cannot be disabled")]
    SafetyKernelLocked,
    /// A command that is forbidden in Stage F (e.g. train execution) was issued.
    #[error("command forbidden in stage F")]
    ForbiddenInStageF,
    /// A secret-shaped value was found inline where only a reference is allowed.
    #[error("secret must be a reference, not inline")]
    SecretInline,
}

/// Crate result alias.
pub type CliResult<T> = core::result::Result<T, CliError>;

#[cfg(test)]
mod tests {
    use super::*;

    fn unlock_ok() -> StageGUnlockView {
        StageGUnlockView {
            sft_smoke_ready: false,
            grpo_locked: true,
            self_evolution_promotion_locked: true,
        }
    }

    fn sample_inputs() -> HandoffInputs<'static> {
        HandoffInputs {
            atom_plan_a: b"a",
            stage_b_plan: b"b",
            stage_c_plan: b"c",
            stage_d_plan: b"d",
            stage_e_plan: b"e",
            stage_e_dod: b"dod",
            command_grammar: b"grammar",
        }
    }

    #[test]
    fn hex32_is_64_lowercase_chars() {
        let d = sha256_32(b"sinabro");
        let h = hex32(&d);
        assert_eq!(h.len(), 64);
        assert!(
            h.chars()
                .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase())
        );
    }

    #[test]
    fn handoff_ok_when_all_present_and_locked() {
        let r = verify_handoff(&sample_inputs(), unlock_ok());
        assert!(r.is_ok());
    }

    #[test]
    fn handoff_rejects_missing_predecessor_evidence() {
        let mut i = sample_inputs();
        i.stage_b_plan = b"";
        let r = verify_handoff(&i, unlock_ok());
        assert_eq!(r, Err(HandoffReject::MissingPredecessorEvidence));
    }

    #[test]
    fn handoff_rejects_grpo_unlocked() {
        let mut u = unlock_ok();
        u.grpo_locked = false;
        let r = verify_handoff(&sample_inputs(), u);
        assert_eq!(r, Err(HandoffReject::GrpoUnlocked));
    }

    #[test]
    fn handoff_rejects_sft_smoke_unlocked_too_early() {
        let mut u = unlock_ok();
        u.sft_smoke_ready = true;
        let r = verify_handoff(&sample_inputs(), u);
        assert_eq!(r, Err(HandoffReject::SftSmokeUnlockedTooEarly));
    }
}
