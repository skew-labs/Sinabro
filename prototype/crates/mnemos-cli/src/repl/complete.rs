//! Context-aware completion provider (atom #413 F.1.4, completion half).
//!
//! Completion is computed from *cached local state only* — namespace names from
//! the closed grammar and injected skill-id hints from D's skill-index cached
//! view. Network-backed suggestions are marked `stale` and are still offered but
//! flagged; completion never performs I/O and never blocks typing. The context
//! map half of #413 lives in [`crate::commands::context`].

use crate::grammar::{self, CliNamespace};

/// A cached skill-id hint injected from D's skill index. `stale` marks a hint
/// whose backing index may be out of date; it is still offered, flagged, and
/// never refreshed on the hot path.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SkillIdHint {
    /// The skill id / name to complete.
    pub name: String,
    /// Whether the backing cache entry is stale.
    pub stale: bool,
}

impl SkillIdHint {
    /// A fresh hint.
    #[must_use]
    pub fn fresh(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            stale: false,
        }
    }

    /// A stale hint (offered but flagged).
    #[must_use]
    pub fn stale(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            stale: true,
        }
    }
}

/// The completion provider over cached local state.
#[derive(Clone, Debug, Default)]
pub struct Completer {
    skills: Vec<SkillIdHint>,
}

impl Completer {
    /// An empty completer (no skill hints).
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// A completer seeded with cached skill-id hints.
    #[must_use]
    pub fn with_skill_hints(skills: Vec<SkillIdHint>) -> Self {
        Self { skills }
    }

    /// Namespace completions for `prefix`, in discriminant order. Pure: a single
    /// pass over the 35-entry closed surface, no I/O.
    #[must_use]
    pub fn complete_namespace(prefix: &str) -> Vec<&'static str> {
        let lowered = prefix.trim().to_ascii_lowercase();
        grammar::ALL
            .iter()
            .map(|ns: &CliNamespace| ns.canonical_name())
            .filter(|name| name.starts_with(&lowered))
            .collect()
    }

    /// Cached skill-id completions for `prefix`. Includes stale hints (the caller
    /// renders the stale flag); never blocks.
    #[must_use]
    pub fn complete_skill(&self, prefix: &str) -> Vec<&SkillIdHint> {
        let lowered = prefix.trim().to_ascii_lowercase();
        self.skills
            .iter()
            .filter(|h| h.name.to_ascii_lowercase().starts_with(&lowered))
            .collect()
    }

    /// Whether any cached hint is stale (so the UI can show a stale marker).
    #[must_use]
    pub fn any_stale(&self) -> bool {
        self.skills.iter().any(|h| h.stale)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn namespace_completion_matches_prefix_in_order() {
        let m = Completer::complete_namespace("me");
        // discriminant order: memory(8) precedes measure(20)
        assert_eq!(m, vec!["memory", "measure"]);
    }

    #[test]
    fn namespace_completion_empty_prefix_is_all() {
        assert_eq!(Completer::complete_namespace("").len(), grammar::COUNT);
    }

    #[test]
    fn namespace_completion_unknown_prefix_is_empty() {
        assert!(Completer::complete_namespace("zzzz").is_empty());
    }

    #[test]
    fn skill_completion_from_cached_hints() {
        let c = Completer::with_skill_hints(vec![
            SkillIdHint::fresh("weather-now"),
            SkillIdHint::fresh("weather-history"),
            SkillIdHint::fresh("translate"),
        ]);
        let got: Vec<&str> = c
            .complete_skill("weather")
            .iter()
            .map(|h| h.name.as_str())
            .collect();
        assert_eq!(got, vec!["weather-now", "weather-history"]);
    }

    #[test]
    fn stale_hints_are_offered_and_flagged() {
        let c = Completer::with_skill_hints(vec![
            SkillIdHint::fresh("alpha"),
            SkillIdHint::stale("alpine"),
        ]);
        assert!(c.any_stale());
        let got = c.complete_skill("al");
        assert_eq!(got.len(), 2);
        assert!(got.iter().any(|h| h.stale));
    }

    #[test]
    fn fresh_only_completer_is_not_stale() {
        let c = Completer::with_skill_hints(vec![SkillIdHint::fresh("a")]);
        assert!(!c.any_stale());
    }
}
