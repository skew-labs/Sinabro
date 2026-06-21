//! Completion + help + cheat-sheet snapshot artifacts (atom #407 F.0.6).
//!
//! Shell completion is generated from the *closed* grammar, so it can never
//! expose a forbidden hidden command. Documentation embeds the grammar hash, so a
//! drift between the docs and the command surface is detectable. The cheat sheet
//! compresses the surface into memorable verbs (documentation labels only — no
//! live wallet/gas/provider action).

use crate::grammar::{ALL, grammar_hash};
use crate::hex32;

/// Space-separated list of every canonical namespace (for completion scripts).
#[must_use]
pub fn namespace_word_list() -> String {
    let mut names: Vec<&str> = ALL.iter().map(|n| n.canonical_name()).collect();
    names.sort_unstable();
    names.join(" ")
}

/// Bash completion script for the `sinabro` binary (closed namespace set).
#[must_use]
pub fn bash_completion() -> String {
    format!(
        "# sinabro bash completion (grammar {hash})\n\
         _sinabro() {{\n\
         \x20 local words=\"{words}\"\n\
         \x20 COMPREPLY=( $(compgen -W \"$words\" -- \"${{COMP_WORDS[COMP_CWORD]}}\") )\n\
         }}\n\
         complete -F _sinabro sinabro mnemos\n",
        hash = hex32(&grammar_hash()),
        words = namespace_word_list(),
    )
}

/// Zsh completion script for the `sinabro` binary.
#[must_use]
pub fn zsh_completion() -> String {
    format!(
        "#compdef sinabro mnemos\n# grammar {hash}\n_arguments '1:namespace:({words})'\n",
        hash = hex32(&grammar_hash()),
        words = namespace_word_list(),
    )
}

/// Fish completion script for the `sinabro` binary.
#[must_use]
pub fn fish_completion() -> String {
    let mut out = format!(
        "# sinabro fish completion (grammar {})\n",
        hex32(&grammar_hash())
    );
    for ns in ALL {
        out.push_str(&format!(
            "complete -c sinabro -n __fish_use_subcommand -a {} \n",
            ns.canonical_name()
        ));
    }
    out
}

/// The memorable cheat-sheet verbs (documentation labels only).
pub const CHEAT_SHEET_VERBS: &[&str] = &[
    "doctor",
    "setup",
    "plan",
    "run",
    "tui",
    "task",
    "session",
    "context",
    "checkpoint",
    "permissions",
    "skill",
    "registry",
    "web",
    "provider",
    "gas",
    "wallet",
    "eval",
    "measure",
    "notify",
    "features",
    "privacy",
    "learning",
    "kill",
];

/// Render the CLI cheat sheet (markdown). Embeds the grammar hash so the doc can
/// be drift-checked against the command surface.
#[must_use]
pub fn cheat_sheet() -> String {
    let mut out = String::from("# Sinabro CLI cheat sheet\n\n");
    out.push_str(&format!("grammar: `{}`\n\n", hex32(&grammar_hash())));
    out.push_str("Memorable verbs:\n\n");
    for verb in CHEAT_SHEET_VERBS {
        out.push_str(&format!("- `sinabro {verb}`\n"));
    }
    out
}

/// Hex of the grammar hash that docs/completion embed.
#[must_use]
pub fn docs_grammar_hash_hex() -> String {
    hex32(&grammar_hash())
}

/// Whether the generated completion excludes all forbidden commerce verbs (there
/// is no closed namespace for them, so they can never appear).
#[must_use]
pub fn completion_excludes_forbidden() -> bool {
    let surface = format!(
        "{} {} {}",
        bash_completion(),
        zsh_completion(),
        fish_completion()
    );
    !["buy", "checkout", "refund", "revenue", "payment", "royalty"]
        .iter()
        .any(|forbidden| {
            // word-boundary-ish check: forbidden verb as a standalone token.
            surface
                .split(|c: char| !c.is_ascii_alphanumeric())
                .any(|tok| tok == *forbidden)
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn completion_lists_every_namespace() {
        let words = namespace_word_list();
        for ns in ALL {
            assert!(
                words.contains(ns.canonical_name()),
                "missing {}",
                ns.canonical_name()
            );
        }
    }

    #[test]
    fn completion_excludes_forbidden_commerce_verbs() {
        assert!(completion_excludes_forbidden());
    }

    #[test]
    fn cheat_sheet_has_verbs_and_grammar_hash() {
        let sheet = cheat_sheet();
        for verb in CHEAT_SHEET_VERBS {
            assert!(sheet.contains(verb), "cheat sheet missing {verb}");
        }
        assert!(sheet.contains(&docs_grammar_hash_hex()));
    }

    #[test]
    fn grammar_hash_hex_is_64_chars() {
        assert_eq!(docs_grammar_hash_hex().len(), 64);
    }

    #[test]
    fn grammar_hash_matches_docs_cross_language_lock() {
        // Cross-language lock: this value is the sha256 of the 35 canonical names
        // (discriminant order, each + "\n"), computed independently in Python and
        // embedded verbatim in docs/cli/cheat-sheet.md + docs/cli/commands.md +
        // ops/evidence/stage_f/handoff.md. A drift here means docs are stale.
        assert_eq!(
            docs_grammar_hash_hex(),
            "88837cd009b8e6492b1a53c2a0b1b807b2ae9f6c3e7d99de9d04923c5fd5e4ec"
        );
    }
}
