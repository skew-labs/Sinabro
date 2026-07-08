//! Cockpit approval modal — the *TUI approval state*.
//!
//! A high-risk approval modal must display the exact command, the capability
//! diff, the cost / gas impact, the rollback path, and the trace id — never a
//! bare "approve?" button. This is enforced structurally: a high-risk modal
//! missing any mandatory field is *invalid* and can only deny
//! ([`ApprovalModal::decide`] returns a [`DeniedAudit`]), so an under-specified
//! approval can never be granted.
//!
//! It reuses the closed [`CommandEnvelope`] risk→approval mapping (`command.rs`)
//! and the fail-closed [`ApprovalPrompt`] (`repl/approval.rs`); it performs no
//! wallet / chain / network / payment action itself — it only projects state and
//! routes the typed decision.

use crate::StageFTraceLink;
use crate::command::{CommandEnvelope, CommandRisk};
use crate::repl::approval::{ApprovalDecision, ApprovalPrompt};

const ZERO32: [u8; 32] = [0u8; 32];

/// Why an approval was denied (the denied-audit reason).
#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DenyReason {
    /// A high-risk modal was missing a mandatory display field.
    MissingRequiredField = 1,
    /// The command is forbidden (e.g. train execution).
    ForbiddenInStageF = 2,
    /// The typed phrase / confirm response did not satisfy the prompt.
    ResponseRejected = 3,
    /// A timeout (a timeout is always a denial).
    Timeout = 4,
}

/// An audit record produced whenever an approval is denied. Carries the command
/// identity + risk + reason so the denial is traceable; never the raw response.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DeniedAudit {
    /// SHA-256 of the canonical verb of the denied command.
    pub command_verb_hash_32: [u8; 32],
    /// Risk class of the denied command.
    pub risk: CommandRisk,
    /// Why it was denied.
    pub reason: DenyReason,
    /// Trace link binding the denial to its atom + gate.
    pub trace: StageFTraceLink,
}

/// The outcome of an approval decision.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ApprovalOutcome {
    /// The action is approved.
    Approved,
    /// The action is denied, with an audit record.
    Denied(DeniedAudit),
}

impl ApprovalOutcome {
    /// Whether the outcome approves the action.
    #[must_use]
    pub const fn is_approved(&self) -> bool {
        matches!(self, Self::Approved)
    }
}

/// The approval modal: the displayed approval state plus the typed
/// decision gate.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ApprovalModal {
    envelope: CommandEnvelope,
    capability_diff_hash_32: [u8; 32],
    gas_impact_micros_u64: u64,
    rollback_hash_32: [u8; 32],
    trace: StageFTraceLink,
    prompt: ApprovalPrompt,
}

impl ApprovalModal {
    /// Build a modal for `envelope`, displaying the capability diff, the
    /// cost/gas impact, the rollback path, and the trace id. `expected_phrase`
    /// is the exact phrase required for a typed-phrase / multisig approval.
    #[must_use]
    pub fn new(
        envelope: CommandEnvelope,
        capability_diff_hash_32: [u8; 32],
        gas_impact_micros_u64: u64,
        rollback_hash_32: [u8; 32],
        trace: StageFTraceLink,
        expected_phrase: impl Into<String>,
    ) -> Self {
        let prompt = ApprovalPrompt::new(envelope.approval, expected_phrase);
        Self {
            envelope,
            capability_diff_hash_32,
            gas_impact_micros_u64,
            rollback_hash_32,
            trace,
            prompt,
        }
    }

    /// The classified command being approved.
    #[must_use]
    pub const fn envelope(&self) -> CommandEnvelope {
        self.envelope
    }

    /// Whether this command is high-risk (needs a typed phrase or multisig).
    #[must_use]
    pub const fn is_high_risk(&self) -> bool {
        matches!(
            self.envelope.risk,
            CommandRisk::WalletSign | CommandRisk::ChainWrite | CommandRisk::Admin
        )
    }

    /// Whether every mandatory display field is present. A high-risk modal must
    /// carry a capability diff, a rollback path, and a non-empty trace id; any
    /// modal must carry a trace id. Missing ⇒ invalid (can only deny).
    #[must_use]
    pub fn has_required_fields(&self) -> bool {
        let trace_ok =
            self.trace.command_trace_hash_32 != ZERO32 && self.trace.stage_f_atom_u16 != 0;
        if self.is_high_risk() {
            trace_ok && self.capability_diff_hash_32 != ZERO32 && self.rollback_hash_32 != ZERO32
        } else {
            trace_ok
        }
    }

    fn audit(&self, reason: DenyReason) -> DeniedAudit {
        DeniedAudit {
            command_verb_hash_32: self.envelope.id.verb_hash_32,
            risk: self.envelope.risk,
            reason,
            trace: self.trace,
        }
    }

    /// Evaluate a typed response. Fail-closed precedence:
    /// forbidden ⇒ deny; missing mandatory field ⇒ deny; otherwise
    /// route to the [`ApprovalPrompt`]. A denial always yields a [`DeniedAudit`].
    pub fn decide(&mut self, response: &str) -> ApprovalOutcome {
        if self.envelope.is_forbidden_in_stage_f() {
            return ApprovalOutcome::Denied(self.audit(DenyReason::ForbiddenInStageF));
        }
        if !self.has_required_fields() {
            return ApprovalOutcome::Denied(self.audit(DenyReason::MissingRequiredField));
        }
        match self.prompt.evaluate(response) {
            ApprovalDecision::Approved => ApprovalOutcome::Approved,
            ApprovalDecision::Denied => {
                ApprovalOutcome::Denied(self.audit(DenyReason::ResponseRejected))
            }
        }
    }

    /// A timeout is always a denial (and produces an audit).
    #[must_use]
    pub fn on_timeout(&self) -> ApprovalOutcome {
        ApprovalOutcome::Denied(self.audit(DenyReason::Timeout))
    }

    /// Render the modal as bounded, colorless text lines. Surfaces the command
    /// id, risk, approval requirement, capability diff, cost/gas impact,
    /// rollback path, and trace id. Returns a `field_present=false` marker for a
    /// missing mandatory field rather than hiding it.
    #[must_use]
    pub fn render(&self, rows: u16) -> Vec<String> {
        let lines = vec![
            format!(
                "command: {} risk={:?}",
                hex8(&self.envelope.id.verb_hash_32),
                self.envelope.risk
            ),
            format!("approval: {:?}", self.envelope.approval),
            format!(
                "capability_diff: {} present={}",
                hex8(&self.capability_diff_hash_32),
                self.capability_diff_hash_32 != ZERO32
            ),
            format!("gas_impact_micros: {}", self.gas_impact_micros_u64),
            format!(
                "rollback_path: {} present={}",
                hex8(&self.rollback_hash_32),
                self.rollback_hash_32 != ZERO32
            ),
            format!(
                "trace: atom={} gate={} id={}",
                self.trace.stage_f_atom_u16,
                self.trace.gate_id_u16,
                hex8(&self.trace.command_trace_hash_32)
            ),
            format!("fields_complete={}", self.has_required_fields()),
        ];
        lines.into_iter().take(rows as usize).collect()
    }
}

/// First 8 hex chars of a 32-byte hash.
fn hex8(bytes: &[u8; 32]) -> String {
    crate::hex32(bytes)[..8].to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::command::CliMode;
    use crate::grammar::CliNamespace;

    fn trace() -> StageFTraceLink {
        StageFTraceLink::new([9u8; 32], 424, 1)
    }

    fn install_modal() -> ApprovalModal {
        // skill install -> LocalWrite -> Confirm
        let env = CommandEnvelope::classify(
            CliNamespace::Skill,
            "install",
            CliMode::Tui,
            CommandRisk::LocalWrite,
            b"weather-now",
        );
        ApprovalModal::new(env, [1u8; 32], 0, [2u8; 32], trace(), "")
    }

    fn wallet_modal(cap: [u8; 32], rollback: [u8; 32]) -> ApprovalModal {
        let env = CommandEnvelope::classify(
            CliNamespace::Wallet,
            "sign",
            CliMode::Tui,
            CommandRisk::WalletSign,
            b"preview",
        );
        ApprovalModal::new(env, cap, 1500, rollback, trace(), "I APPROVE WALLET SIGN")
    }

    fn chain_modal() -> ApprovalModal {
        let env = CommandEnvelope::classify(
            CliNamespace::Chain,
            "publish",
            CliMode::Tui,
            CommandRisk::ChainWrite,
            b"pkg",
        );
        ApprovalModal::new(env, [3u8; 32], 9000, [4u8; 32], trace(), "MULTISIG CONFIRM")
    }

    #[test]
    fn install_approval_confirm_path() {
        let mut m = install_modal();
        assert!(!m.is_high_risk());
        assert!(!m.decide("no").is_approved());
        assert!(m.decide("yes").is_approved());
    }

    #[test]
    fn wallet_sign_requires_exact_typed_phrase() {
        let mut m = wallet_modal([1u8; 32], [2u8; 32]);
        assert!(m.is_high_risk());
        // bare enter never approves
        assert!(!m.decide("").is_approved());
        // wrong phrase denies
        assert!(!m.decide("approve").is_approved());
        // exact phrase approves
        assert!(m.decide("I APPROVE WALLET SIGN").is_approved());
    }

    #[test]
    fn chain_write_multisig_path() {
        let mut m = chain_modal();
        assert!(!m.decide("nope").is_approved());
        assert!(m.decide("MULTISIG CONFIRM").is_approved());
    }

    #[test]
    fn high_risk_missing_capability_diff_can_only_deny() {
        // capability diff zeroed -> invalid high-risk modal -> deny w/ audit
        let mut m = wallet_modal(ZERO32, [2u8; 32]);
        assert!(!m.has_required_fields());
        let out = m.decide("I APPROVE WALLET SIGN");
        assert!(
            !out.is_approved(),
            "an under-specified high-risk modal must deny"
        );
        if let ApprovalOutcome::Denied(audit) = out {
            assert_eq!(audit.reason, DenyReason::MissingRequiredField);
            assert_eq!(audit.risk, CommandRisk::WalletSign);
        }
    }

    #[test]
    fn denied_audit_carries_command_and_trace() {
        let mut m = wallet_modal([1u8; 32], [2u8; 32]);
        let out = m.decide("wrong phrase");
        assert!(!out.is_approved());
        if let ApprovalOutcome::Denied(audit) = out {
            assert_eq!(audit.reason, DenyReason::ResponseRejected);
            assert_eq!(audit.trace.stage_f_atom_u16, 424);
            assert_ne!(audit.command_verb_hash_32, [0u8; 32]);
        }
    }

    #[test]
    fn timeout_denies_with_audit() {
        let m = wallet_modal([1u8; 32], [2u8; 32]);
        let out = m.on_timeout();
        assert!(!out.is_approved());
        if let ApprovalOutcome::Denied(audit) = out {
            assert_eq!(audit.reason, DenyReason::Timeout);
        }
    }

    #[test]
    fn render_surfaces_all_mandatory_fields() {
        let m = wallet_modal([1u8; 32], [2u8; 32]);
        let text = m.render(16).join("\n");
        assert!(text.contains("capability_diff"));
        assert!(text.contains("gas_impact_micros"));
        assert!(text.contains("rollback_path"));
        assert!(text.contains("trace"));
        assert!(text.contains("fields_complete=true"));
    }
}
