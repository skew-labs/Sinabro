//! `mnemos-e-skill::no_commerce` — atom #317 · D.4.6 — the no-commerce
//! forbidden-surface scan.
//!
//! ## Canonical OUT (§317)
//!
//! Active Stage D must not contain buy / sell / payment / checkout / refund /
//! revenue / royalty / unlock command, type, CLI-grammar, or doc surfaces
//! (§317 광기). [`scan_surfaces`] folds four surface scanners — command names,
//! type names, CLI-grammar tokens, and doc prose — into one
//! [`NoCommerceReport`]; the criterion is **forbidden active-commerce hits =
//! 0** on a clean surface. Future commerce can exist only as sealed
//! post-validation RFC text outside any executable path (master RD-26).
//!
//! ## Reuse (master RD-26 → #243)
//!
//! This module re-uses the **single source of truth** for the forbidden
//! vocabulary — [`crate::package_policy::FORBIDDEN_COMMERCE_SUBSTRINGS`] and
//! [`crate::package_policy::FORBIDDEN_COMMERCE_EXACT`] (#243) — and the policy
//! version hash [`crate::package_policy::no_commerce_policy_hash`]. It never
//! re-defines the token sets; it only applies the same exact-then-substring
//! rule to non-TOML-key surfaces (identifiers and prose). `cost` stays absent
//! and `cost_usd` is exact-only, so the legitimate `token_cost_estimate`
//! budgeting word never trips.
//!
//! ## Offline boundary
//!
//! A pure, offline string scan: no network, wallet, secret, or chain action,
//! and the report carries only `&'static` policy tokens, never the scanned
//! operator string.

#![deny(missing_docs)]

extern crate alloc;

use alloc::vec::Vec;

use crate::package_policy::{
    FORBIDDEN_COMMERCE_EXACT, FORBIDDEN_COMMERCE_SUBSTRINGS, no_commerce_policy_hash,
};

// ===========================================================================
// 1. forbidden_commerce_token — surface-level analogue of the #243 key scan
// ===========================================================================

/// Return the forbidden commerce token a single surface token matches, if any,
/// applying the canonical #243 rule (exact match on the whole token, then a
/// substring match) over the reused [`FORBIDDEN_COMMERCE_EXACT`] /
/// [`FORBIDDEN_COMMERCE_SUBSTRINGS`] vocabularies. Case-insensitive. Returns a
/// `&'static` policy token, never the scanned string.
#[must_use]
pub fn forbidden_commerce_token(token: &str) -> Option<&'static str> {
    let lower = token.to_ascii_lowercase();
    // Whole-token exact match (e.g. a bare `pay` key).
    if let Some(&exact) = FORBIDDEN_COMMERCE_EXACT.iter().find(|&&e| lower == e) {
        return Some(exact);
    }
    // Dash/underscore-delimited piece exact match, so a short exact token
    // hidden behind a CLI prefix or compound name (`--buy`, `buy_now`,
    // `pay-link`) cannot evade the gate. `cost` is deliberately ABSENT from the
    // exact list, so `token_cost_estimate` (piece `cost`) never trips.
    for piece in lower.split(['-', '_']) {
        if let Some(&exact) = FORBIDDEN_COMMERCE_EXACT.iter().find(|&&e| piece == e) {
            return Some(exact);
        }
    }
    // Substring match over the curated commerce vocabulary.
    FORBIDDEN_COMMERCE_SUBSTRINGS
        .iter()
        .find(|&&sub| lower.contains(sub))
        .copied()
}

/// Split doc prose into lowercased word tokens on any non-`[a-z0-9_]`
/// boundary, so each word can be scanned by [`forbidden_commerce_token`].
fn doc_words(text: &str) -> Vec<alloc::string::String> {
    let mut words: Vec<alloc::string::String> = Vec::new();
    let mut cur = alloc::string::String::new();
    for ch in text.chars() {
        if ch.is_ascii_alphanumeric() || ch == '_' {
            cur.push(ch.to_ascii_lowercase());
        } else if !cur.is_empty() {
            words.push(core::mem::take(&mut cur));
        }
    }
    if !cur.is_empty() {
        words.push(cur);
    }
    words
}

// ===========================================================================
// 2. NoCommerceSurface / NoCommerceSurfaceViolation
// ===========================================================================

/// Which executable surface a forbidden token was found on.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum NoCommerceSurface {
    /// A command / subcommand name.
    Command,
    /// A type / struct / enum name.
    Type,
    /// A CLI grammar token (flag, argument keyword).
    CliGrammar,
    /// Doc prose.
    Docs,
}

impl NoCommerceSurface {
    /// Stable, leak-free class label.
    #[inline]
    #[must_use]
    pub const fn class_label(&self) -> &'static str {
        match self {
            Self::Command => "no_commerce.surface.command",
            Self::Type => "no_commerce.surface.type",
            Self::CliGrammar => "no_commerce.surface.cli_grammar",
            Self::Docs => "no_commerce.surface.docs",
        }
    }
}

/// A commerce-shaped token was found on a surface. Carries the surface and the
/// matched `&'static` policy token only.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub struct NoCommerceSurfaceViolation {
    /// Which surface tripped.
    pub surface: NoCommerceSurface,
    /// The forbidden token that matched (from the #243 policy lists).
    pub matched_token: &'static str,
}

// ===========================================================================
// 3. per-surface scanners
// ===========================================================================

/// Scan a slice of identifier-shaped tokens (command / type / CLI) for the
/// given surface, collecting one violation per matched token.
fn scan_identifiers(
    surface: NoCommerceSurface,
    tokens: &[&str],
    out: &mut Vec<NoCommerceSurfaceViolation>,
) {
    for token in tokens {
        if let Some(matched_token) = forbidden_commerce_token(token) {
            out.push(NoCommerceSurfaceViolation {
                surface,
                matched_token,
            });
        }
    }
}

/// `Err` with the first violation iff any command name is commerce-shaped.
pub fn scan_command_surface(commands: &[&str]) -> Result<(), NoCommerceSurfaceViolation> {
    let mut v = Vec::new();
    scan_identifiers(NoCommerceSurface::Command, commands, &mut v);
    v.into_iter().next().map_or(Ok(()), Err)
}

/// `Err` with the first violation iff any type name is commerce-shaped.
pub fn scan_type_surface(types: &[&str]) -> Result<(), NoCommerceSurfaceViolation> {
    let mut v = Vec::new();
    scan_identifiers(NoCommerceSurface::Type, types, &mut v);
    v.into_iter().next().map_or(Ok(()), Err)
}

/// `Err` with the first violation iff any CLI grammar token is commerce-shaped.
pub fn scan_cli_grammar(tokens: &[&str]) -> Result<(), NoCommerceSurfaceViolation> {
    let mut v = Vec::new();
    scan_identifiers(NoCommerceSurface::CliGrammar, tokens, &mut v);
    v.into_iter().next().map_or(Ok(()), Err)
}

/// `Err` with the first violation iff any doc word is commerce-shaped. Fail-
/// closed: this is conservative (a benign word that *contains* a forbidden
/// substring rejects), matching the #243 substring doctrine.
pub fn scan_docs(text: &str) -> Result<(), NoCommerceSurfaceViolation> {
    for word in doc_words(text) {
        if let Some(matched_token) = forbidden_commerce_token(&word) {
            return Err(NoCommerceSurfaceViolation {
                surface: NoCommerceSurface::Docs,
                matched_token,
            });
        }
    }
    Ok(())
}

// ===========================================================================
// 4. NoCommerceReport — aggregate scan
// ===========================================================================

/// The result of scanning every declared surface of a skill.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NoCommerceReport {
    /// Every violation found, in surface order (command, type, CLI, docs).
    pub violations: Vec<NoCommerceSurfaceViolation>,
    /// The #243 policy-version hash this scan was run against, so a report is
    /// bound to the exact forbidden vocabulary that produced it.
    pub policy_hash_32: [u8; 32],
}

impl NoCommerceReport {
    /// `true` iff no surface is commerce-shaped (criterion: hits = 0).
    #[inline]
    #[must_use]
    pub fn is_clean(&self) -> bool {
        self.violations.is_empty()
    }
}

/// Scan all four surfaces of a skill (commands, types, CLI grammar, docs) and
/// fold the result into one [`NoCommerceReport`]. Deterministic and order-
/// stable: surfaces are scanned command → type → CLI → docs, and the report is
/// bound to [`no_commerce_policy_hash`].
#[must_use]
pub fn scan_surfaces(
    commands: &[&str],
    types: &[&str],
    cli_grammar: &[&str],
    docs: &str,
) -> NoCommerceReport {
    let mut violations: Vec<NoCommerceSurfaceViolation> = Vec::new();
    scan_identifiers(NoCommerceSurface::Command, commands, &mut violations);
    scan_identifiers(NoCommerceSurface::Type, types, &mut violations);
    scan_identifiers(NoCommerceSurface::CliGrammar, cli_grammar, &mut violations);
    if let Err(v) = scan_docs(docs) {
        violations.push(v);
    }
    NoCommerceReport {
        violations,
        policy_hash_32: no_commerce_policy_hash(),
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn forbidden_command_scan() {
        assert_eq!(
            scan_command_surface(&["search", "inspect", "checkout"])
                .expect_err("checkout command must reject")
                .matched_token,
            "checkout"
        );
        assert!(scan_command_surface(&["search", "inspect", "install"]).is_ok());
    }

    #[test]
    fn forbidden_type_scan() {
        let err = scan_type_surface(&["SkillCard", "PaymentReceipt"])
            .expect_err("payment type must reject");
        assert_eq!(err.matched_token, "payment");
        assert_eq!(err.surface, NoCommerceSurface::Type);
    }

    #[test]
    fn cli_grammar_scan() {
        assert_eq!(
            scan_cli_grammar(&["--dry-run", "--price"])
                .expect_err("--price flag must reject")
                .matched_token,
            "price"
        );
        assert!(scan_cli_grammar(&["--dry-run", "--inspect", "--enable"]).is_ok());
    }

    #[test]
    fn docs_scan_rejects_commerce_prose() {
        let doc = "This skill is free to install. Run the refund flow to undo.";
        assert_eq!(
            scan_docs(doc)
                .expect_err("refund prose must reject")
                .matched_token,
            "refund"
        );
    }

    #[test]
    fn docs_scan_passes_clean_prose() {
        let doc = "This skill searches, inspects, and installs catalog entries offline.";
        assert!(scan_docs(doc).is_ok(), "clean doc must pass");
    }

    #[test]
    fn fixture_with_fake_checkout_rejected() {
        // A community-imported skill that hides a checkout command, a payment
        // type, a --buy flag, and a paywall doc — every surface must trip.
        let report = scan_surfaces(
            &["search", "checkout"],
            &["SkillCard", "PaywallGate"],
            &["--buy"],
            "Unlock premium features after payment.",
        );
        assert!(!report.is_clean());
        // command, type, cli, docs all caught.
        assert_eq!(report.violations.len(), 4);
        assert_eq!(report.violations[0].surface, NoCommerceSurface::Command);
        assert_eq!(report.violations[0].matched_token, "checkout");
        assert_ne!(report.policy_hash_32, [0u8; 32]);
    }

    #[test]
    fn clean_skill_scans_zero_hits() {
        let report = scan_surfaces(
            &[
                "search", "inspect", "install", "enable", "disable", "remove",
            ],
            &[
                "SkillStarterPack",
                "LocalInstallReceipt",
                "CommunitySkillImport",
            ],
            &["--dry-run", "--inspect"],
            "Search, inspect, dry-run, install, enable, disable, and remove skills offline.",
        );
        assert!(report.is_clean(), "clean skill must have 0 commerce hits");
    }

    #[test]
    fn token_cost_estimate_word_is_not_commerce() {
        // The legitimate budgeting word must not trip the surface scan.
        assert!(forbidden_commerce_token("token_cost_estimate").is_none());
        assert!(scan_docs("The token_cost_estimate is a budgeting hint, not money.").is_ok());
    }
}
