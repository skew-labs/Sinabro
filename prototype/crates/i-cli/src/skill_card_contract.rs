//! `mnemos-i-cli::skill_card_contract` — the CLI-first card data contract.
//!
//! Stage D defines a **CLI-first** skill surface: every command can be initiated
//! from the CLI or by an agent recommendation, and later UI/TUI can polish the
//! presentation but can never route the main flow through a web market. This
//! module pins, per command, the card fields a CLI / agent must surface
//! ([`SkillCliCommand::required_card_fields`]) and which commands require an
//! explicit user confirmation ([`SkillCliCommand::requires_user_confirmation`]).
//!
//! No-commerce: none of the twelve commands is a
//! buy/sell/payment/checkout/refund command — [`SkillCliCommand::is_commerce`]
//! is always `false`, and no required field names a price or payment.
//!
//! Reuses the catalog card types from `mnemos-e-skill` (the single new
//! `i-cli -> mnemos-e-skill` crate edge); it mints no new card type and no
//! checkout/payment surface.

#![deny(missing_docs)]

use mnemos_e_skill::SkillCardSummary;

/// The twelve Stage-D skill CLI commands (the only entry points; no web-market
/// checkout route exists).
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum SkillCliCommand {
    /// List skills matching a query.
    Search,
    /// Load the full detail card for one skill.
    Inspect,
    /// Ask the agent for ranked candidates (advisory only).
    Recommend,
    /// Run a skill on redacted fixtures (try-before-use).
    Use,
    /// Install a verified skill (requires confirmation).
    Install,
    /// Enable an installed skill.
    Enable,
    /// Disable an installed skill.
    Disable,
    /// Update an installed skill to a new verified package.
    Update,
    /// Remove an installed skill (requires confirmation).
    Remove,
    /// Fork a skill into a new provenance lineage.
    Fork,
    /// Publish a signed package to the (offline) registry.
    Publish,
    /// Run a skill's eval suite.
    Eval,
}

impl SkillCliCommand {
    /// All twelve commands, in canonical order.
    #[must_use]
    pub const fn all() -> [SkillCliCommand; 12] {
        [
            Self::Search,
            Self::Inspect,
            Self::Recommend,
            Self::Use,
            Self::Install,
            Self::Enable,
            Self::Disable,
            Self::Update,
            Self::Remove,
            Self::Fork,
            Self::Publish,
            Self::Eval,
        ]
    }

    /// The CLI verb for this command.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Search => "search",
            Self::Inspect => "inspect",
            Self::Recommend => "recommend",
            Self::Use => "use",
            Self::Install => "install",
            Self::Enable => "enable",
            Self::Disable => "disable",
            Self::Update => "update",
            Self::Remove => "remove",
            Self::Fork => "fork",
            Self::Publish => "publish",
            Self::Eval => "eval",
        }
    }

    /// Whether this command needs an explicit user confirmation before it runs.
    /// `use` / `install` / `remove` mutate local state and always require it.
    #[must_use]
    pub const fn requires_user_confirmation(self) -> bool {
        matches!(self, Self::Use | Self::Install | Self::Remove)
    }

    /// Always `false`: no command is a commerce / payment / checkout action.
    #[must_use]
    pub const fn is_commerce(self) -> bool {
        false
    }

    /// The card fields a CLI / agent must surface for this command. Every
    /// surfacing command includes the capability diff or permission preview so
    /// the permission delta is never hidden.
    #[must_use]
    pub const fn required_card_fields(self) -> &'static [&'static str] {
        match self {
            Self::Search => &[
                "skill",
                "name_hash",
                "verified_installs",
                "eval",
                "security",
                "compatibility",
                "capability_class",
                "capability_diff",
            ],
            Self::Inspect => &[
                "skill",
                "eval",
                "security",
                "compatibility",
                "capability_diff",
                "reproducible_command_hash",
                "malicious_fixture_pass",
                "audit_state",
                "provenance",
            ],
            Self::Recommend => &[
                "skill",
                "rank",
                "permission_preview",
                "requires_user_confirm",
                "rationale_hash",
            ],
            Self::Use => &[
                "skill",
                "capability_diff",
                "permission_preview",
                "user_confirmation",
            ],
            Self::Install => &[
                "skill",
                "package",
                "capability_diff",
                "permission_preview",
                "install_preconditions",
                "user_confirmation",
            ],
            Self::Enable => &["skill", "install_state", "user_confirmation"],
            Self::Disable => &["skill", "install_state"],
            Self::Update => &["skill", "package", "capability_diff", "user_confirmation"],
            Self::Remove => &["skill", "install_state", "user_confirmation"],
            Self::Fork => &["skill", "parent_package", "provenance"],
            Self::Publish => &[
                "skill",
                "package",
                "signature",
                "supply_chain",
                "no_commerce",
            ],
            Self::Eval => &["skill", "eval", "reproducible_command_hash", "tests_digest"],
        }
    }
}

/// A CLI card contract instance: a command paired with the listing card it
/// renders.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SkillCardContract {
    /// The command this card is rendered for.
    pub command: SkillCliCommand,
    /// The lightweight listing card.
    pub card: SkillCardSummary,
}

impl SkillCardContract {
    /// Pair a command with a card.
    #[must_use]
    pub const fn new(command: SkillCliCommand, card: SkillCardSummary) -> Self {
        Self { command, card }
    }

    /// A single-line JSON snapshot of the card for CLI / agent consumption.
    /// Carries only counts and class labels — never a price or payment field.
    #[must_use]
    pub fn to_jsonl(&self) -> String {
        format!(
            "{{\"schema\":\"mnemos.d.cli_card_contract.v1\",\"command\":\"{cmd}\",\"requires_confirmation\":{conf},\"is_commerce\":{commerce},\"skill\":{skill},\"verified_installs\":{vi},\"security\":{sec},\"compatibility\":{compat},\"capability_class\":\"{cc}\",\"high_risk\":{hr},\"eval_warning\":{ew}}}",
            cmd = self.command.as_str(),
            conf = self.command.requires_user_confirmation(),
            commerce = self.command.is_commerce(),
            skill = self.card.skill.0,
            vi = self.card.verified_installs_u64,
            sec = self.card.security as u8,
            compat = self.card.compatibility as u8,
            cc = self.card.capability_class.class_label(),
            hr = self.card.high_risk,
            ew = self.card.eval_warning,
        )
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use mnemos_e_skill::{HostEnvironment, MnemosVersion, SkillCatalogIndexEntry};

    fn card() -> SkillCardSummary {
        let toml = mnemos_e_skill::verify::sample_valid_package_toml();
        let host = HostEnvironment {
            mnemos_version: MnemosVersion::new(0, 2, 0),
            chain_env_hash_32: [0xC0; 32],
            os_gpu_hash_32: [0x05; 32],
            toolchain_hash_32: [0x70; 32],
            model_provider_hash_32: [0x30; 32],
        };
        let entry =
            SkillCatalogIndexEntry::from_package_toml(&toml, &host, [0x99; 32], 50, 7, 3).unwrap();
        SkillCardSummary::from_index_entry(&entry)
    }

    const FORBIDDEN: &[&str] = &[
        "price", "payment", "buy", "sell", "fee", "unlock", "checkout", "refund", "revenue",
        "royalty", "cost", "paywall",
    ];

    #[test]
    fn card_json_snapshot() {
        let contract = SkillCardContract::new(SkillCliCommand::Search, card());
        let line = contract.to_jsonl();
        assert!(line.contains("\"command\":\"search\""));
        assert!(line.contains("\"verified_installs\":7"));
        assert!(line.contains("\"is_commerce\":false"));
        // exactly one line.
        assert_eq!(line.lines().count(), 1);
    }

    #[test]
    fn search_list_fields() {
        let fields = SkillCliCommand::Search.required_card_fields();
        assert!(fields.contains(&"security"));
        assert!(fields.contains(&"capability_diff"));
    }

    #[test]
    fn inspect_fields() {
        assert!(
            SkillCliCommand::Inspect
                .required_card_fields()
                .contains(&"provenance")
        );
    }

    #[test]
    fn recommend_list() {
        assert!(
            SkillCliCommand::Recommend
                .required_card_fields()
                .contains(&"permission_preview")
        );
    }

    #[test]
    fn use_confirmation_contract() {
        assert!(SkillCliCommand::Use.requires_user_confirmation());
    }

    #[test]
    fn install_receipt_gate() {
        let fields = SkillCliCommand::Install.required_card_fields();
        assert!(fields.contains(&"install_preconditions"));
        assert!(SkillCliCommand::Install.requires_user_confirmation());
    }

    #[test]
    fn enable_disable_update_remove_rows() {
        for cmd in [
            SkillCliCommand::Enable,
            SkillCliCommand::Disable,
            SkillCliCommand::Update,
            SkillCliCommand::Remove,
        ] {
            assert!(!cmd.required_card_fields().is_empty());
        }
        assert!(SkillCliCommand::Remove.requires_user_confirmation());
        assert!(!SkillCliCommand::Disable.requires_user_confirmation());
    }

    #[test]
    fn no_commerce_in_any_command() {
        for cmd in SkillCliCommand::all() {
            assert!(!cmd.is_commerce());
            assert!(!FORBIDDEN.contains(&cmd.as_str()));
            for field in cmd.required_card_fields() {
                for bad in FORBIDDEN {
                    assert!(
                        !field.contains(bad),
                        "field {field} contains commerce token {bad}"
                    );
                }
            }
        }
    }
}
