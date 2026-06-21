//! §4.1 closed command grammar (atom #403 F.0.2).
//!
//! The CLI command surface is a *closed* set of namespaces — a hidden
//! side-effect command is impossible because there is no open dispatch path. The
//! surface is a `repr(u8)` enum + a total parser + a small alias map, and it is
//! snapshot-tested. A hand-rolled closed enum is stricter than a derive-macro CLI
//! parser, keeps the crate offline/dependency-minimal, and matches the existing
//! `bin/mnemos-cli` convention.

use crate::sha256_32;

/// §4.1 — the closed set of CLI command namespaces (master §2.6, 35 total).
#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum CliNamespace {
    /// `agent` — bounded turn / budget / kill.
    Agent = 1,
    /// `provider` — LLM provider gateway.
    Provider = 2,
    /// `model` — model route / cache / speculation.
    Model = 3,
    /// `tool` — tool adapter (Python/MCP/CLI/HTTP/WASM).
    Tool = 4,
    /// `sandbox` — sandbox tier inspect/warmup/deny.
    Sandbox = 5,
    /// `skill` — skill discovery / use / install.
    Skill = 6,
    /// `registry` — skill registry / provenance.
    Registry = 7,
    /// `memory` — owner / storage / replay controls.
    Memory = 8,
    /// `wallet` — connect / zkLogin / sign preview.
    Wallet = 9,
    /// `identity` — memory-owner identity.
    Identity = 10,
    /// `key` — secret reference / key doctor (status-only).
    Key = 11,
    /// `gas` — sponsor mode / policy / drain dashboard.
    Gas = 12,
    /// `chain` — env / package / mainnet gate.
    Chain = 13,
    /// `package` — Move package publish/upgrade gate.
    Package = 14,
    /// `multisig` — multisig propose / sign / timelock.
    Multisig = 15,
    /// `dataset` — S1/S2 / PII0 dataset controls.
    Dataset = 16,
    /// `trace` — command trace / audit view.
    Trace = 17,
    /// `train` — Stage F: doctor/prepare/dashboard/unlock-status only.
    Train = 18,
    /// `eval` — rust/move/prover/kani/lean/gas/korean eval.
    Eval = 19,
    /// `measure` — measurement telemetry (opt-in).
    Measure = 20,
    /// `platform` — Telegram/Slack/Discord controls.
    Platform = 21,
    /// `release` — launchable package dry-run.
    Release = 22,
    /// `federation` — opt-in federation (locked).
    Federation = 23,
    /// `admin` — administrative surface.
    Admin = 24,
    /// `approval` — approval inbox / deny.
    Approval = 25,
    /// `audit` — audit trail view.
    Audit = 26,
    /// `privacy` — privacy status / egress controls.
    Privacy = 27,
    /// `feature` — feature profile / enable / disable.
    Feature = 28,
    /// `learning` — learning mode / export / contribute / revoke.
    Learning = 29,
    /// `task` — task inbox / resume / cancel.
    Task = 30,
    /// `session` — session list / resume / export.
    Session = 31,
    /// `context` — context map / status / why / pin.
    Context = 32,
    /// `checkpoint` — checkpoint list / diff / restore.
    Checkpoint = 33,
    /// `permission` — permission status / allow / revoke.
    Permission = 34,
    /// `notify` — notification rules / test / mute.
    Notify = 35,
}

/// The number of namespaces in the closed surface.
pub const COUNT: usize = 35;

/// Every namespace, in discriminant order. Used by completion + coverage tests.
pub const ALL: [CliNamespace; COUNT] = [
    CliNamespace::Agent,
    CliNamespace::Provider,
    CliNamespace::Model,
    CliNamespace::Tool,
    CliNamespace::Sandbox,
    CliNamespace::Skill,
    CliNamespace::Registry,
    CliNamespace::Memory,
    CliNamespace::Wallet,
    CliNamespace::Identity,
    CliNamespace::Key,
    CliNamespace::Gas,
    CliNamespace::Chain,
    CliNamespace::Package,
    CliNamespace::Multisig,
    CliNamespace::Dataset,
    CliNamespace::Trace,
    CliNamespace::Train,
    CliNamespace::Eval,
    CliNamespace::Measure,
    CliNamespace::Platform,
    CliNamespace::Release,
    CliNamespace::Federation,
    CliNamespace::Admin,
    CliNamespace::Approval,
    CliNamespace::Audit,
    CliNamespace::Privacy,
    CliNamespace::Feature,
    CliNamespace::Learning,
    CliNamespace::Task,
    CliNamespace::Session,
    CliNamespace::Context,
    CliNamespace::Checkpoint,
    CliNamespace::Permission,
    CliNamespace::Notify,
];

impl CliNamespace {
    /// The single canonical (lower-case) name of this namespace.
    #[must_use]
    pub const fn canonical_name(self) -> &'static str {
        match self {
            Self::Agent => "agent",
            Self::Provider => "provider",
            Self::Model => "model",
            Self::Tool => "tool",
            Self::Sandbox => "sandbox",
            Self::Skill => "skill",
            Self::Registry => "registry",
            Self::Memory => "memory",
            Self::Wallet => "wallet",
            Self::Identity => "identity",
            Self::Key => "key",
            Self::Gas => "gas",
            Self::Chain => "chain",
            Self::Package => "package",
            Self::Multisig => "multisig",
            Self::Dataset => "dataset",
            Self::Trace => "trace",
            Self::Train => "train",
            Self::Eval => "eval",
            Self::Measure => "measure",
            Self::Platform => "platform",
            Self::Release => "release",
            Self::Federation => "federation",
            Self::Admin => "admin",
            Self::Approval => "approval",
            Self::Audit => "audit",
            Self::Privacy => "privacy",
            Self::Feature => "feature",
            Self::Learning => "learning",
            Self::Task => "task",
            Self::Session => "session",
            Self::Context => "context",
            Self::Checkpoint => "checkpoint",
            Self::Permission => "permission",
            Self::Notify => "notify",
        }
    }
}

/// The closed alias table: `(alias, canonical namespace)`. Aliases are a
/// convenience only and resolve to exactly the same namespace; no alias can
/// introduce a command outside [`ALL`].
pub const ALIASES: &[(&str, CliNamespace)] = &[
    ("skills", CliNamespace::Skill),
    ("providers", CliNamespace::Provider),
    ("models", CliNamespace::Model),
    ("tools", CliNamespace::Tool),
    ("mem", CliNamespace::Memory),
    ("identities", CliNamespace::Identity),
    ("keys", CliNamespace::Key),
    ("pkg", CliNamespace::Package),
    ("msig", CliNamespace::Multisig),
    ("datasets", CliNamespace::Dataset),
    ("traces", CliNamespace::Trace),
    ("evals", CliNamespace::Eval),
    ("platforms", CliNamespace::Platform),
    ("fed", CliNamespace::Federation),
    ("approvals", CliNamespace::Approval),
    ("feat", CliNamespace::Feature),
    ("features", CliNamespace::Feature),
    ("tasks", CliNamespace::Task),
    ("sess", CliNamespace::Session),
    ("sessions", CliNamespace::Session),
    ("ctx", CliNamespace::Context),
    ("ckpt", CliNamespace::Checkpoint),
    ("perm", CliNamespace::Permission),
    ("permissions", CliNamespace::Permission),
    ("notifications", CliNamespace::Notify),
];

/// Parse a token into a namespace. The match is closed: an unknown token returns
/// `None` (the caller surfaces [`crate::CliError::UnknownCommand`]). Matching is
/// case-insensitive on the canonical names and the alias table.
#[must_use]
pub fn parse(token: &str) -> Option<CliNamespace> {
    let lowered = token.trim().to_ascii_lowercase();
    for ns in ALL {
        if ns.canonical_name() == lowered {
            return Some(ns);
        }
    }
    for (alias, ns) in ALIASES {
        if *alias == lowered {
            return Some(*ns);
        }
    }
    None
}

/// The stable hash of the closed command surface: SHA-256 over the canonical
/// names joined by `\n` in discriminant order. Documentation (`docs/cli/*`) and
/// shell completion embed this; a drift means the doc no longer matches grammar.
#[must_use]
pub fn grammar_hash() -> [u8; 32] {
    let mut surface = String::new();
    for ns in ALL {
        surface.push_str(ns.canonical_name());
        surface.push('\n');
    }
    sha256_32(surface.as_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn all_has_35_and_matches_count() {
        assert_eq!(ALL.len(), COUNT);
        assert_eq!(COUNT, 35);
    }

    #[test]
    fn discriminants_are_dense_1_to_35() {
        for (i, ns) in ALL.iter().enumerate() {
            assert_eq!(*ns as u8, (i as u8) + 1);
        }
    }

    #[test]
    fn canonical_names_are_unique() {
        let mut names: Vec<&str> = ALL.iter().map(|n| n.canonical_name()).collect();
        names.sort_unstable();
        let before = names.len();
        names.dedup();
        assert_eq!(before, names.len(), "duplicate canonical name");
    }

    #[test]
    fn every_canonical_name_parses_back() {
        for ns in ALL {
            assert_eq!(parse(ns.canonical_name()), Some(ns));
        }
    }

    #[test]
    fn parse_is_case_insensitive() {
        assert_eq!(parse("AGENT"), Some(CliNamespace::Agent));
        assert_eq!(parse("  Skill  "), Some(CliNamespace::Skill));
    }

    #[test]
    fn unknown_command_is_rejected() {
        assert_eq!(parse("definitely-not-a-namespace"), None);
        assert_eq!(parse("buy"), None);
        assert_eq!(parse("checkout"), None);
    }

    #[test]
    fn aliases_resolve_into_closed_set() {
        for (alias, ns) in ALIASES {
            assert_eq!(parse(alias), Some(*ns));
            assert!(ALL.contains(ns));
        }
    }

    #[test]
    fn grammar_hash_is_stable_and_32_bytes() {
        assert_eq!(grammar_hash(), grammar_hash());
        assert_eq!(grammar_hash().len(), 32);
    }
}
