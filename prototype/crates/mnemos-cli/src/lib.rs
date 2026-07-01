//! `sinabro` — the Mnemos / Sinabro CLI Cockpit (Stage F, F-WP-01 #401-#410).
//!
//! Stage F turns the A–E memory / evidence / policy / data-rights core into a
//! CLI-first product surface. This crate is a *surface*: it reads and drives
//! A–E canonical truth and never reinvents it. Every user action compiles to a
//! typed [`command::CommandEnvelope`] guarded by a [`command::CommandRisk`] and
//! an [`command::ApprovalRequirement`]; the safety kernel is non-disableable;
//! learning and data egress default to off.
//!
//! Crate-home note (#402): the directory is the plan-mandated `crates/mnemos-cli`
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
// `unsafe` for its two libc `termios` FFI calls (atom #570 "the only allowed
// unsafe"); every other module in the crate stays unsafe-denied.
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
// P1-2 (owner brief 2026-06-13, orchestrator spine): the two-model orchestration
// loop — frontier PLAN -> decompose -> per-sub-task route + local IMPLEMENT ->
// frontier SYNTHESIZE. A NEW caller chaining the UNMODIFIED run_agent_loop_with;
// L1 of the three-layer separation. Plan: P1_ORCHESTRATOR_PLAN.md.
pub mod agent_orchestrator;
// D-1 (AGENT-NATIVE GITHUB, owner 2026-07-01 "우리 에이전트만의 깃허브"): the PURE
// content-addressed artifact registry core — a git-object analog (skills / adapters /
// strategies / memories / code / oracles addressed by content hash) + the AGRX manifest
// codec. NO egress / NO execution here; D-2..D-6 add the AI-native wire protocol, the
// gated Walrus publish/fetch, the loop tool, the GUI, and the sandboxed fetch-then-propose.
pub mod agent_registry;
pub mod audit;
pub mod command;
pub mod commands;
pub mod completion;
pub mod config;
pub mod conformal;
pub mod daemon;
pub mod dispatch;
pub mod doctor;
pub mod evidence;
pub mod exec_local;
pub mod exec_proposal;
pub mod file_context;
pub mod file_edit;
// REWIND (the differentiator Codex lacks): a content-capturing "last applied
// edit" revert point that restores the displaced bytes through the SAME
// owner_save_file staleness-locked atomic path. Local-file-only; PD-6 untouched.
pub mod git;
pub mod grammar;
pub mod lsp;
pub mod mcp;
pub mod memory;
pub mod memory_crag;
pub mod memory_store;
pub mod memory_walrus;
pub mod metamorphic_oracle;
pub mod recognition_elicit;
pub mod recognition_synth;
pub mod reconcile_oracle;
pub mod revert_blob;
pub mod zerog_attestation;
pub mod zerog_chain;
pub mod zerog_finetune;
pub mod zerog_inft;
pub mod zerog_storage;
// ENDGAME E10-2a (⑬ AGENT ACTS): the single gated EXECUTE chokepoint for
// agent-proposed side effects — `execute_authorized_mutate` requires a
// MutateCapability witness (IV-A1), so no exec/edit runs without owner authority.
pub mod mutate_execute;
// ONCHAIN PIVOT C-0: the single gated chokepoint for an owner-BOUNDED on-chain tx —
// `execute_authorized_chain_tx` requires a `ChainTxCapability` witness (minted ONLY from a
// VALID owner-armed `CustodyGrant` + a within-bounds tx). C-0 is INERT (no sign/broadcast,
// money 0); C-2 adds the isolated signer + RPC. Blanket `CustodyCapability` stays uninhabited.
pub mod chain_execute;
pub mod chain_signer;
pub mod skew_execute;
// O-5 (Oracle Bootstrap §6.9 + §6.6): capitalize a CERTIFIED oracle as an ERC-7857 iNFT —
// composes the LOCKED `zerog_inft` encoder; the dataHash is a deterministic certified-oracle
// commitment, FAIL-CLOSED on a TYPED cert (recognition = the conformal α-budget O-3c; reconcile/
// metamorphic = deterministic-sound, canary-gated). PURE PREPARE; custody/funds HARD-LOCKED
// (the binary signs nothing — the owner FIRES the mint).
pub mod oracle_inft;
// P4-1 (owner-authorized 2026-06-11): OTel trace export — the thin OTLP/JSON
// projection over the consult receipt truth. cfg-gated to the ONLY features
// whose executors can call it (⑨ IV-O5: the default build compiles ZERO
// exporter code, so the default surface is byte-identical structurally).
// Threat model: ops/evidence/stage_g/agent_loop/OTEL_EXPORT_THREAT_MODEL.md.
#[cfg(any(
    feature = "provider-egress",
    feature = "local-mlx",
    feature = "local-vllm"
))]
pub mod otel_export;
// P4-2 (owner-authorized 2026-06-11): multi-repo / project context — a bounded,
// deterministic, content-free recursive file index over the registered
// (allowlisted) project roots. Reuses lane A's `FileReadPolicy` allowlist +
// `denied_token` denylist; adds enumeration bounds (the FIRST recursive
// enumeration of an arbitrary user project tree). LOCAL/owner tier in VS-1 (the
// loop grammar is byte-unchanged — the model cannot enumerate). Threat model
// addendum: FILE_CONTEXT_THREAT_MODEL.md §P4-2 (IV-F8..F11).
pub mod project_index;
pub mod prompt_status;
pub mod provider;
// [7] B⑪ owner-box / remote-shell lane (⑪-class, highest-risk): an owner-armed,
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
// P1-4 (orchestrator spine): the autonomous Read-Execute-WRITE evolution loop's
// DETERMINISTIC write-decision core — a verified pattern persists ONLY if its oracle
// receipt admits_write AND it is cross-memory consistent with the held LTM; each write
// carries a DGM-H perf-tracking score (reinforced on verified-good). Pure, 0 IO, 0 tokens.
pub mod autonomy_evolve;
// P1-3-full(a) (orchestrator spine): the CODE-class oracle — the one impure companion
// to the pure `verification` ladder. Extracts Move from the local answer, materializes a
// temp Sui package, and runs `sui move build` in the E6 network-DENIED sandbox; the exit
// [4] B⑨ semantic codebase index — local embeddings (pluggable seam) + an encrypted-at-rest
// vector store + hybrid cosine/lexical retrieval; @codebase READ; embeddings never egress.
pub mod codebase_index;
// code is the oracle bit fed to verify(Code, ..). Build-only (no chain action). 0 tokens.
pub mod code_oracle;
// P1-3 (full; orchestrator spine): the Typed-Write-Admission TRUST-TIER ladder — the
// P-HALL anchor. Maps a sub-task's expert kind to one of five verification classes
// (Code / PersonalOwner / ExternalFact / ModelInference / CrossMemory), then to a
// class-typed ORACLE (compiler bit / owner provenance / independent corroboration /
// DGM-H perf-tracking / contradiction-detection) that produces a typed receipt; only a
// Verified receipt admits a permanent Write. Compiler is ONE class, NOT universal.
// classify is total (unknown kind ⇒ ModelInference, lowest-trust fail-safe). The
// model's TEXT is never an input (no self-certification). Pure, no IO, 0 tokens.
// Plan: P1_ORCHESTRATOR_PLAN.md.
pub mod verification;
// [5] B⑭ multimodal / image input — local-vision-first: an image as a READ context
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
/// an extra dependency (matches the Stage E `hex32_encode` convention).
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

// ---- §4.0 Handoff + trace -------------------------------------------------

/// §4.0 — the A–E plan/DoD + command-grammar hash lock proving Stage F starts on
/// a closed, evidence-backed predecessor set (atom #401 F.0.0 handoff lock).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StageFHandoffDigest {
    /// SHA-256 of the Phase 0 / Stage A atom plan.
    pub atom_plan_a_hash_32: [u8; 32],
    /// SHA-256 of the Stage B atom plan.
    pub stage_b_plan_hash_32: [u8; 32],
    /// SHA-256 of the Stage C atom plan.
    pub stage_c_plan_hash_32: [u8; 32],
    /// SHA-256 of the Stage D atom plan.
    pub stage_d_plan_hash_32: [u8; 32],
    /// SHA-256 of the Stage E atom plan.
    pub stage_e_plan_hash_32: [u8; 32],
    /// SHA-256 of the Stage E Definition-of-Done evidence bundle.
    pub stage_e_dod_hash_32: [u8; 32],
    /// SHA-256 of the closed Stage F command grammar surface.
    pub command_grammar_hash_32: [u8; 32],
}

/// §4.0 — links a command trace to its Stage F atom + gate id.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StageFTraceLink {
    /// SHA-256 of the command trace record this link points at.
    pub command_trace_hash_32: [u8; 32],
    /// Stage F atom id (#401..#480).
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

/// §4.0 — a hashed evidence path bound to a trace link.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StageFEvidenceRef {
    /// SHA-256 of the evidence path.
    pub path_hash_32: [u8; 32],
    /// The trace link the evidence belongs to.
    pub trace: StageFTraceLink,
}

// ---- handoff lock (atom #401) ---------------------------------------------

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

/// Why an A–E handoff lock check rejected (atom #401 test list).
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
    /// Phase 0 / Stage A atom plan bytes.
    pub atom_plan_a: &'a [u8],
    /// Stage B atom plan bytes.
    pub stage_b_plan: &'a [u8],
    /// Stage C atom plan bytes.
    pub stage_c_plan: &'a [u8],
    /// Stage D atom plan bytes.
    pub stage_d_plan: &'a [u8],
    /// Stage E atom plan bytes.
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
