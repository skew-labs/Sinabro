//! REPL shell boundary.
//!
//! The REPL is a *thin shell* around [`crate::command::CommandEnvelope`]: every
//! input line is parsed through the closed [`crate::grammar`] and turned into an
//! envelope (carrying risk + approval) — there is no command-bypass path that
//! would let a line cause a side effect without an envelope. This dispatch engine
//! is the canonical surface and is fully testable via injected input lines (no
//! terminal required).
//!
//! On a real TTY the interactive surface is a `reedline` chat loop ([`chat`])
//! preceded by a one-shot `ratatui` [`splash`]; the hand-rolled
//! raw-mode line editor it replaced has been retired. Every non-TTY / piped /
//! checker / test path stays on the byte-unchanged cooked loop in [`run`].

pub mod approval;
pub mod chat;
pub mod complete;
pub mod history;
pub mod latency;
pub mod palette;
pub mod prompt;
pub mod run;
pub mod splash;
pub mod stream;

use crate::command::{CliMode, CommandEnvelope, CommandRisk};
use crate::grammar::{self, CliNamespace};

/// The outcome of feeding one event to the REPL engine.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReplOutcome {
    /// Blank line; nothing to do.
    Empty,
    /// End-of-file (Ctrl-D); exit the loop.
    Eof,
    /// Interrupt (Ctrl-C); cancel the current line.
    Cancelled,
    /// The first token did not resolve to a closed namespace.
    Unknown,
    /// A classified command ready for the dispatcher (carries risk + approval).
    Dispatch(CommandEnvelope),
}

/// A thin REPL engine. Holds only the active [`CliMode`]; all command meaning
/// comes from the shared grammar + command model.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ReplEngine {
    mode: CliMode,
}

impl Default for ReplEngine {
    fn default() -> Self {
        Self {
            mode: CliMode::Repl,
        }
    }
}

/// Conservative line-level risk for a namespace at the REPL boundary. Verb-level
/// refinement happens in each namespace's handler; the
/// boundary errs toward *more* approval, never less.
const fn boundary_risk(ns: CliNamespace) -> CommandRisk {
    match ns {
        CliNamespace::Train => CommandRisk::Training,
        CliNamespace::Wallet => CommandRisk::WalletSign,
        CliNamespace::Chain | CliNamespace::Package | CliNamespace::Multisig => {
            CommandRisk::ChainWrite
        }
        CliNamespace::Admin => CommandRisk::Admin,
        CliNamespace::Provider
        | CliNamespace::Tool
        | CliNamespace::Gas
        | CliNamespace::Platform
        | CliNamespace::Release => CommandRisk::Network,
        _ => CommandRisk::ReadOnly,
    }
}

impl ReplEngine {
    /// Create a REPL engine in [`CliMode::Repl`].
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Handle one input line. Empty -> [`ReplOutcome::Empty`]; unknown first
    /// token -> [`ReplOutcome::Unknown`]; otherwise a classified
    /// [`ReplOutcome::Dispatch`]. No line ever bypasses the envelope.
    #[must_use]
    pub fn handle_line(&self, line: &str) -> ReplOutcome {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            return ReplOutcome::Empty;
        }
        let mut tokens = trimmed.split_whitespace();
        let head = tokens.next().unwrap_or_default();
        let Some(ns) = grammar::parse(head) else {
            return ReplOutcome::Unknown;
        };
        let verb = tokens.next().unwrap_or("status");
        let envelope =
            CommandEnvelope::classify(ns, verb, self.mode, boundary_risk(ns), trimmed.as_bytes());
        ReplOutcome::Dispatch(envelope)
    }

    /// Handle an end-of-file event.
    #[must_use]
    pub const fn handle_eof(&self) -> ReplOutcome {
        ReplOutcome::Eof
    }

    /// Handle an interrupt (Ctrl-C) event.
    #[must_use]
    pub const fn handle_interrupt(&self) -> ReplOutcome {
        ReplOutcome::Cancelled
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::command::ApprovalRequirement;

    #[test]
    fn empty_line_is_empty() {
        assert_eq!(ReplEngine::new().handle_line("   "), ReplOutcome::Empty);
    }

    #[test]
    fn eof_and_interrupt_are_distinct() {
        let e = ReplEngine::new();
        assert_eq!(e.handle_eof(), ReplOutcome::Eof);
        assert_eq!(e.handle_interrupt(), ReplOutcome::Cancelled);
    }

    #[test]
    fn unknown_first_token_is_unknown() {
        assert_eq!(
            ReplEngine::new().handle_line("buy a-skill"),
            ReplOutcome::Unknown
        );
    }

    #[test]
    fn known_command_dispatches_through_envelope() {
        assert!(matches!(
            ReplEngine::new().handle_line("trace list"),
            ReplOutcome::Dispatch(env)
                if env.risk == CommandRisk::ReadOnly && env.approval == ApprovalRequirement::None
        ));
    }

    #[test]
    fn train_dispatch_is_forbidden_in_stage_f() {
        assert!(matches!(
            ReplEngine::new().handle_line("train run"),
            ReplOutcome::Dispatch(env) if env.is_forbidden_in_stage_f()
        ));
    }

    #[test]
    fn side_effecting_namespaces_require_approval() {
        for line in ["wallet sign", "chain publish"] {
            assert!(
                matches!(
                    ReplEngine::new().handle_line(line),
                    ReplOutcome::Dispatch(env) if env.approval != ApprovalRequirement::None
                ),
                "{line} must need approval"
            );
        }
    }
}
