//! §4.1 slash command palette (atom #411 F.1.2).
//!
//! A leading-`/` palette is a *convenience surface* over the closed grammar: a
//! slash token resolves to exactly one [`CliNamespace`] + verb and compiles to
//! the same [`CommandEnvelope`] (same command identity + risk + approval) as the
//! bare clap/grammar form. There are no shadow command semantics — every entry
//! routes to a real namespace, and an unknown slash is rejected.
//!
//! A handful of convenience slashes have no dedicated namespace and resolve to
//! the namespace that owns their surface (documented in [`SLASH_TABLE`]):
//! `/plan`,`/kill`,`/doctor` → `agent`; `/use` → `skill`; `/web` → `tool`;
//! `/evidence` → `audit`; `/approve` → `approval`.

use super::boundary_risk;
use crate::command::{CliMode, CommandEnvelope};
use crate::grammar::CliNamespace;

/// The closed slash table: `(slash_key, namespace, default_verb)`. The key omits
/// the leading `/`. Every namespace here is a member of
/// [`crate::grammar::ALL`]; the palette can never introduce a command outside
/// the closed surface.
pub const SLASH_TABLE: &[(&str, CliNamespace, &str)] = &[
    ("plan", CliNamespace::Agent, "plan"),
    ("task", CliNamespace::Task, "status"),
    ("session", CliNamespace::Session, "status"),
    ("context", CliNamespace::Context, "status"),
    ("checkpoint", CliNamespace::Checkpoint, "status"),
    ("permissions", CliNamespace::Permission, "status"),
    ("skill", CliNamespace::Skill, "status"),
    ("registry", CliNamespace::Registry, "status"),
    ("use", CliNamespace::Skill, "use"),
    ("memory", CliNamespace::Memory, "status"),
    ("tool", CliNamespace::Tool, "status"),
    ("web", CliNamespace::Tool, "web"),
    ("provider", CliNamespace::Provider, "status"),
    ("wallet", CliNamespace::Wallet, "status"),
    ("gas", CliNamespace::Gas, "status"),
    ("chain", CliNamespace::Chain, "status"),
    ("dataset", CliNamespace::Dataset, "status"),
    ("evidence", CliNamespace::Audit, "evidence"),
    ("learning", CliNamespace::Learning, "status"),
    ("features", CliNamespace::Feature, "status"),
    ("privacy", CliNamespace::Privacy, "status"),
    ("train", CliNamespace::Train, "status"),
    ("eval", CliNamespace::Eval, "status"),
    ("measure", CliNamespace::Measure, "status"),
    ("notify", CliNamespace::Notify, "status"),
    ("doctor", CliNamespace::Agent, "doctor"),
    ("approve", CliNamespace::Approval, "approve"),
    ("kill", CliNamespace::Agent, "kill"),
];

/// Look up a slash key (without the leading `/`) in the closed table.
#[must_use]
pub fn lookup(slash_key: &str) -> Option<(CliNamespace, &'static str)> {
    let lowered = slash_key.trim().to_ascii_lowercase();
    for (key, ns, verb) in SLASH_TABLE {
        if *key == lowered {
            return Some((*ns, *verb));
        }
    }
    None
}

/// Resolve a palette line (must start with `/`) into a [`CommandEnvelope`] in the
/// given [`CliMode`]. Returns `None` if the line is not a slash line or the slash
/// key is unknown (unknown-slash reject). The envelope is built through the same
/// [`CommandEnvelope::classify`] + [`super::boundary_risk`] path the bare REPL
/// uses, so a slash form is never a shadow command.
#[must_use]
pub fn resolve(line: &str, mode: CliMode) -> Option<CommandEnvelope> {
    let trimmed = line.trim();
    let rest = trimmed.strip_prefix('/')?;
    let mut tokens = rest.split_whitespace();
    let key = tokens.next().unwrap_or_default();
    let (ns, default_verb) = lookup(key)?;
    let verb = tokens.next().unwrap_or(default_verb);
    Some(CommandEnvelope::classify(
        ns,
        verb,
        mode,
        boundary_risk(ns),
        trimmed.as_bytes(),
    ))
}

/// The full slash completion list, each with its leading `/`, in table order.
#[must_use]
pub fn slash_completions() -> Vec<String> {
    SLASH_TABLE
        .iter()
        .map(|(key, _, _)| format!("/{key}"))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::command::{ApprovalRequirement, CommandRisk};
    use crate::repl::{ReplEngine, ReplOutcome};

    #[test]
    fn slash_resolves_to_its_namespace() {
        let resolved = resolve("/skill", CliMode::Repl);
        assert!(resolved.is_some(), "known slash must resolve");
        if let Some(e) = resolved {
            assert_eq!(e.id.namespace, CliNamespace::Skill);
            assert_eq!(e.risk, CommandRisk::ReadOnly);
            assert_eq!(e.approval, ApprovalRequirement::None);
        }
    }

    #[test]
    fn slash_is_envelope_equivalent_to_bare_command() {
        // `/skill` and bare `skill` must produce the same command identity + risk
        // + approval (no shadow semantics). Only the raw args hash may differ.
        let slash = resolve("/skill", CliMode::Repl);
        let bare_outcome = ReplEngine::new().handle_line("skill");
        assert!(slash.is_some(), "known slash must resolve");
        assert!(
            matches!(bare_outcome, ReplOutcome::Dispatch(_)),
            "bare skill must dispatch"
        );
        if let (Some(slash), ReplOutcome::Dispatch(bare)) = (slash, bare_outcome) {
            assert_eq!(slash.id.namespace, bare.id.namespace);
            assert_eq!(slash.id.verb_hash_32, bare.id.verb_hash_32);
            assert_eq!(slash.risk, bare.risk);
            assert_eq!(slash.approval, bare.approval);
        }
    }

    #[test]
    fn destructive_slash_keeps_its_risk() {
        let wallet = resolve("/wallet sign", CliMode::Repl);
        assert!(wallet.is_some(), "wallet slash resolves");
        if let Some(w) = wallet {
            assert_eq!(w.risk, CommandRisk::WalletSign);
            assert_eq!(w.approval, ApprovalRequirement::TypedPhrase);
        }
        let train = resolve("/train run", CliMode::Repl);
        assert!(train.is_some(), "train slash resolves");
        if let Some(t) = train {
            assert!(t.is_forbidden_in_stage_f());
        }
    }

    #[test]
    fn convenience_slashes_route_to_owning_namespace() {
        assert_eq!(lookup("web"), Some((CliNamespace::Tool, "web")));
        assert_eq!(lookup("use"), Some((CliNamespace::Skill, "use")));
        assert_eq!(lookup("kill"), Some((CliNamespace::Agent, "kill")));
        assert_eq!(lookup("evidence"), Some((CliNamespace::Audit, "evidence")));
    }

    #[test]
    fn unknown_slash_is_rejected() {
        assert!(resolve("/buy", CliMode::Repl).is_none());
        assert!(resolve("/definitely-not", CliMode::Repl).is_none());
        // a non-slash line is not a palette line
        assert!(resolve("skill", CliMode::Repl).is_none());
    }

    #[test]
    fn completion_list_covers_table_and_is_slash_prefixed() {
        let list = slash_completions();
        assert_eq!(list.len(), SLASH_TABLE.len());
        assert!(list.iter().all(|s| s.starts_with('/')));
        assert!(list.contains(&"/skill".to_string()));
    }

    #[test]
    fn every_table_namespace_is_in_the_closed_set() {
        for (_, ns, _) in SLASH_TABLE {
            assert!(crate::grammar::ALL.contains(ns));
        }
    }
}
