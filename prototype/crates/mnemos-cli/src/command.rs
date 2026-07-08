//! Command model.
//!
//! Every user action — from CLI, REPL, TUI, or a remote platform — compiles to a
//! [`CommandEnvelope`] carrying a [`CommandRisk`] and a derived
//! [`ApprovalRequirement`]. The risk→approval mapping is total and closed:
//! training risk is always [`ApprovalRequirement::ForbiddenInStageF`]; chain
//! writes need multisig; wallet signing + admin need a typed phrase; network +
//! local writes need a confirm; read-only needs nothing. This single envelope is
//! shared by all surfaces so Telegram/mobile/API cannot diverge from the CLI.

use crate::grammar::CliNamespace;
use crate::{GRAMMAR_VERSION_U16, StageFEvidenceRef};

/// Top-level CLI mode.
#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CliMode {
    /// Interactive REPL (default entry).
    Repl = 1,
    /// Full-screen TUI cockpit.
    Tui = 2,
    /// Non-interactive run for CI / automation.
    Run = 3,
    /// First-run / health doctor.
    Doctor = 4,
    /// Administrative surface.
    Admin = 5,
}

/// Risk class of a command; drives the approval requirement.
#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CommandRisk {
    /// Pure read; no mutation, no egress.
    ReadOnly = 1,
    /// Local filesystem / config mutation.
    LocalWrite = 2,
    /// Network egress.
    Network = 3,
    /// Wallet signing.
    WalletSign = 4,
    /// On-chain write.
    ChainWrite = 5,
    /// Model training execution.
    Training = 6,
    /// Administrative action.
    Admin = 7,
}

/// Approval gate a command must pass before any side effect.
#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ApprovalRequirement {
    /// No approval (read-only).
    None = 1,
    /// Single confirm.
    Confirm = 2,
    /// Typed phrase required (destructive / signing / admin).
    TypedPhrase = 3,
    /// Multisig required (chain write).
    Multisig = 4,
    /// Forbidden entirely (e.g. train execution).
    ForbiddenInStageF = 5,
}

/// Identity of a command: closed namespace + verb hash + grammar version.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CommandId {
    /// Closed command namespace.
    pub namespace: CliNamespace,
    /// SHA-256 of the canonical verb string.
    pub verb_hash_32: [u8; 32],
    /// Grammar version this id was minted under.
    pub grammar_version_u16: u16,
}

/// A fully classified command ready for dispatch.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CommandEnvelope {
    /// Command identity.
    pub id: CommandId,
    /// CLI mode the command runs in.
    pub mode: CliMode,
    /// Risk class.
    pub risk: CommandRisk,
    /// Approval gate (derived from `risk`).
    pub approval: ApprovalRequirement,
    /// SHA-256 of the (redacted) argument vector.
    pub args_hash_32: [u8; 32],
}

/// The trace record every executed command emits.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CommandTraceRecord {
    /// The classified command.
    pub envelope: CommandEnvelope,
    /// Process exit code.
    pub exit_code_i32: i32,
    /// Evidence reference.
    pub evidence: StageFEvidenceRef,
    /// SHA-256 of the redacted command output.
    pub redacted_output_hash_32: [u8; 32],
}

/// The closed, total risk→approval mapping. Training is always forbidden;
/// this is the single place that decision is made.
#[must_use]
pub const fn approval_for(risk: CommandRisk) -> ApprovalRequirement {
    match risk {
        CommandRisk::ReadOnly => ApprovalRequirement::None,
        CommandRisk::LocalWrite | CommandRisk::Network => ApprovalRequirement::Confirm,
        CommandRisk::WalletSign | CommandRisk::Admin => ApprovalRequirement::TypedPhrase,
        CommandRisk::ChainWrite => ApprovalRequirement::Multisig,
        CommandRisk::Training => ApprovalRequirement::ForbiddenInStageF,
    }
}

impl CommandId {
    /// Mint a command id for a namespace + canonical verb.
    #[must_use]
    pub fn new(namespace: CliNamespace, verb: &str) -> Self {
        Self {
            namespace,
            verb_hash_32: crate::sha256_32(verb.as_bytes()),
            grammar_version_u16: GRAMMAR_VERSION_U16,
        }
    }
}

impl CommandEnvelope {
    /// Build an envelope, deriving the approval from the risk via the closed
    /// [`approval_for`] mapping. There is no other way to construct an approval.
    #[must_use]
    pub fn classify(
        namespace: CliNamespace,
        verb: &str,
        mode: CliMode,
        risk: CommandRisk,
        args: &[u8],
    ) -> Self {
        Self {
            id: CommandId::new(namespace, verb),
            mode,
            risk,
            approval: approval_for(risk),
            args_hash_32: crate::sha256_32(args),
        }
    }

    /// Whether this command is forbidden entirely (train execution).
    #[must_use]
    pub const fn is_forbidden_in_stage_f(&self) -> bool {
        matches!(self.approval, ApprovalRequirement::ForbiddenInStageF)
    }

    /// Whether this command may run with no approval prompt (read-only).
    #[must_use]
    pub const fn needs_no_approval(&self) -> bool {
        matches!(self.approval, ApprovalRequirement::None)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn read_only_needs_no_approval() {
        let e = CommandEnvelope::classify(
            CliNamespace::Trace,
            "list",
            CliMode::Run,
            CommandRisk::ReadOnly,
            b"",
        );
        assert_eq!(e.approval, ApprovalRequirement::None);
        assert!(e.needs_no_approval());
        assert!(!e.is_forbidden_in_stage_f());
    }

    #[test]
    fn training_is_forbidden_in_stage_f() {
        let e = CommandEnvelope::classify(
            CliNamespace::Train,
            "run",
            CliMode::Run,
            CommandRisk::Training,
            b"",
        );
        assert!(e.is_forbidden_in_stage_f());
    }

    #[test]
    fn side_effects_require_approval() {
        for (risk, expect) in [
            (CommandRisk::LocalWrite, ApprovalRequirement::Confirm),
            (CommandRisk::Network, ApprovalRequirement::Confirm),
            (CommandRisk::WalletSign, ApprovalRequirement::TypedPhrase),
            (CommandRisk::Admin, ApprovalRequirement::TypedPhrase),
            (CommandRisk::ChainWrite, ApprovalRequirement::Multisig),
        ] {
            assert_eq!(approval_for(risk), expect);
            assert_ne!(expect, ApprovalRequirement::None);
        }
    }

    #[test]
    fn risk_matrix_is_total_and_closed() {
        // Every risk maps to exactly one approval; no risk silently maps to None
        // except ReadOnly.
        for risk in [
            CommandRisk::ReadOnly,
            CommandRisk::LocalWrite,
            CommandRisk::Network,
            CommandRisk::WalletSign,
            CommandRisk::ChainWrite,
            CommandRisk::Training,
            CommandRisk::Admin,
        ] {
            let a = approval_for(risk);
            if matches!(risk, CommandRisk::ReadOnly) {
                assert_eq!(a, ApprovalRequirement::None);
            } else {
                assert_ne!(a, ApprovalRequirement::None);
            }
        }
    }
}
