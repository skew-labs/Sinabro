//! `mnemos-e-skill::author_check` — the skill author checklist contract.
//!
//! ## Overview
//!
//! A simple, ordered authoring path: `manifest -> fixtures -> eval
//! command -> capability declaration -> provenance signature -> local dry-run`.
//! [`AuthorChecklist`] tracks the six [`AuthorStep`]s; a submission is publish-
//! ready only when [`AuthorChecklist::is_complete`]. Docs are part of the gate,
//! not an afterthought — the author guide uses the
//! same canonical example fixture
//! ([`crate::verify::sample_valid_package_toml`]) that
//! [`evaluate_submission`] validates, so the guide example always passes the
//! local dry-run.
//!
//! ## Reuse
//!
//! The manifest step reuses [`parse_package`] and
//! [`scan_no_commerce`]; the capability step reuses the
//! [`CapabilityDiff`] consistency check and rejects a declaration that drifts
//! from the actual diff. The checklist output shape mirrors the CLI card
//! data contract (one row per step) without importing the `i-cli` crate (which
//! depends on `e-skill`) — no dependency inversion.
//!
//! ## Offline boundary
//!
//! Pure, offline validation: no network, wallet, secret, or chain action.

#![deny(missing_docs)]

extern crate alloc;

use crate::capability_diff::CapabilityDiff;
use crate::package_policy::scan_no_commerce;
use crate::package_toml::parse_package;

// ===========================================================================
// 1. AuthorStep — the six ordered authoring steps
// ===========================================================================

/// One step of the author checklist, in the canonical order an author follows.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
#[repr(u8)]
pub enum AuthorStep {
    /// Manifest parses against the canonical schema and is no-commerce.
    ManifestSchema = 1,
    /// Test fixtures are present.
    Fixtures = 2,
    /// A reproducible eval command/score is present.
    EvalCommand = 3,
    /// The declared capabilities match the actual capability diff.
    CapabilityDeclaration = 4,
    /// The package carries a provenance author signature.
    ProvenanceSignature = 5,
    /// A local try-before-use dry-run passed.
    LocalDryRun = 6,
}

impl AuthorStep {
    /// Stable, leak-free step label.
    #[inline]
    #[must_use]
    pub const fn label(&self) -> &'static str {
        match self {
            Self::ManifestSchema => "author.manifest_schema",
            Self::Fixtures => "author.fixtures",
            Self::EvalCommand => "author.eval_command",
            Self::CapabilityDeclaration => "author.capability_declaration",
            Self::ProvenanceSignature => "author.provenance_signature",
            Self::LocalDryRun => "author.local_dry_run",
        }
    }
}

// ===========================================================================
// 2. AuthorCheckError
// ===========================================================================

/// Why an individual author check failed.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum AuthorCheckError {
    /// The manifest TOML failed to parse against the canonical schema.
    ManifestParse,
    /// The manifest carries a commerce-shaped field.
    NoCommerce,
    /// The declared capabilities do not match the actual capability diff, or
    /// the diff is itself inconsistent.
    CapabilityDrift,
}

impl AuthorCheckError {
    /// Stable, leak-free class label.
    #[inline]
    #[must_use]
    pub const fn class_label(&self) -> &'static str {
        match self {
            Self::ManifestParse => "author.manifest_parse",
            Self::NoCommerce => "author.no_commerce",
            Self::CapabilityDrift => "author.capability_drift",
        }
    }
}

// ===========================================================================
// 3. individual checks (reuse #248 / #243 / #244)
// ===========================================================================

/// Check the manifest step: it must parse against the canonical schema
/// AND be free of commerce-shaped fields.
pub fn check_manifest_schema(manifest_toml: &str) -> Result<(), AuthorCheckError> {
    parse_package(manifest_toml).map_err(|_| AuthorCheckError::ManifestParse)?;
    scan_no_commerce(manifest_toml).map_err(|_| AuthorCheckError::NoCommerce)?;
    Ok(())
}

/// Check the capability-declaration step: the author's `declared_added_mask_u64`
/// must equal the actual diff's `added_mask_u64`, and the diff must be
/// self-consistent (no hidden permission). A mismatch is a docs/code
/// drift and rejects.
pub fn check_capability_declaration(
    declared_added_mask_u64: u64,
    diff: &CapabilityDiff,
) -> Result<(), AuthorCheckError> {
    if !diff.is_consistent() || declared_added_mask_u64 != diff.added_mask_u64 {
        return Err(AuthorCheckError::CapabilityDrift);
    }
    Ok(())
}

// ===========================================================================
// 4. AuthorChecklist — the six-step report
// ===========================================================================

/// The result of running the author checklist over a submission. Each field is
/// one [`AuthorStep`] verdict; [`Self::is_complete`] is publish-readiness.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub struct AuthorChecklist {
    /// Manifest parses + no-commerce.
    pub manifest_ok: bool,
    /// Test fixtures present.
    pub fixtures_ok: bool,
    /// Reproducible eval command/score present.
    pub eval_command_ok: bool,
    /// Declared capabilities match the actual diff.
    pub capability_declared_ok: bool,
    /// Provenance author signature present.
    pub provenance_signed_ok: bool,
    /// Local try-before-use dry-run passed.
    pub dry_run_ok: bool,
}

impl AuthorChecklist {
    /// `true` iff every step passed — the submission is publish-ready.
    #[inline]
    #[must_use]
    pub const fn is_complete(&self) -> bool {
        self.manifest_ok
            && self.fixtures_ok
            && self.eval_command_ok
            && self.capability_declared_ok
            && self.provenance_signed_ok
            && self.dry_run_ok
    }

    /// The first incomplete step in canonical order, if any — the next thing the
    /// author must fix.
    #[must_use]
    pub const fn first_missing(&self) -> Option<AuthorStep> {
        if !self.manifest_ok {
            Some(AuthorStep::ManifestSchema)
        } else if !self.fixtures_ok {
            Some(AuthorStep::Fixtures)
        } else if !self.eval_command_ok {
            Some(AuthorStep::EvalCommand)
        } else if !self.capability_declared_ok {
            Some(AuthorStep::CapabilityDeclaration)
        } else if !self.provenance_signed_ok {
            Some(AuthorStep::ProvenanceSignature)
        } else if !self.dry_run_ok {
            Some(AuthorStep::LocalDryRun)
        } else {
            None
        }
    }
}

/// Run the full author checklist over a submission. The manifest and capability
/// steps are validated here (reusing the manifest, no-commerce, and capability
/// checks); the remaining steps (fixtures, eval, provenance signature, dry-run)
/// are supplied as upstream gate verdicts.
#[must_use]
pub fn evaluate_submission(
    manifest_toml: &str,
    fixtures_present: bool,
    eval_present: bool,
    declared_added_mask_u64: u64,
    capability_diff: &CapabilityDiff,
    provenance_signed: bool,
    dry_run_passed: bool,
) -> AuthorChecklist {
    AuthorChecklist {
        manifest_ok: check_manifest_schema(manifest_toml).is_ok(),
        fixtures_ok: fixtures_present,
        eval_command_ok: eval_present,
        capability_declared_ok: check_capability_declaration(
            declared_added_mask_u64,
            capability_diff,
        )
        .is_ok(),
        provenance_signed_ok: provenance_signed,
        dry_run_ok: dry_run_passed,
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use crate::capability_diff::SkillRuntimePermission;
    use crate::verify::sample_valid_package_toml;
    use alloc::vec::Vec;

    fn diff() -> CapabilityDiff {
        // A read-only memory capability — consistent by construction.
        CapabilityDiff::new(SkillRuntimePermission::MemoryRead.mask_bit(), 0, Vec::new())
    }

    #[test]
    fn guide_example_parses_and_passes_dry_run() {
        // The doc/guide fixture is the canonical sample — it must parse
        // and pass the manifest step (the local dry-run criterion).
        let toml = sample_valid_package_toml();
        assert!(parse_package(&toml).is_ok(), "guide example must parse");
        assert!(
            check_manifest_schema(&toml).is_ok(),
            "guide example must pass"
        );
    }

    #[test]
    fn minimal_skill_fixture_is_complete() {
        let d = diff();
        let checklist = evaluate_submission(
            &sample_valid_package_toml(),
            true,
            true,
            d.added_mask_u64,
            &d,
            true,
            true,
        );
        assert!(checklist.is_complete());
        assert_eq!(checklist.first_missing(), None);
    }

    #[test]
    fn bad_manifest_examples_reject() {
        // Malformed TOML.
        assert_eq!(
            check_manifest_schema("this is = = not toml").unwrap_err(),
            AuthorCheckError::ManifestParse
        );
        // An unknown commerce-shaped manifest key fails the deny_unknown_fields
        // parse before the no-commerce scan; either way it is rejected.
        assert!(check_manifest_schema("[manifest]\nid = 1\nprice = 100\n").is_err());
        // Positive control: the canonical sample passes.
        assert!(check_manifest_schema(&sample_valid_package_toml()).is_ok());
    }

    #[test]
    fn capability_docs_drift_rejected() {
        let d = diff();
        // Declared mask differs from the actual diff -> drift.
        assert_eq!(
            check_capability_declaration(0xFF, &d).unwrap_err(),
            AuthorCheckError::CapabilityDrift
        );
        // A tampered (inconsistent) diff -> drift even if the mask matches.
        let mut tampered = diff();
        tampered.human_digest_32 = [0u8; 32];
        assert_eq!(
            check_capability_declaration(tampered.added_mask_u64, &tampered).unwrap_err(),
            AuthorCheckError::CapabilityDrift
        );
        // Matching declaration on a consistent diff passes.
        assert!(check_capability_declaration(d.added_mask_u64, &d).is_ok());
    }

    #[test]
    fn first_missing_reports_earliest_gap() {
        let d = diff();
        let checklist = evaluate_submission(
            &sample_valid_package_toml(),
            true,
            false, // eval missing
            d.added_mask_u64,
            &d,
            true,
            true,
        );
        assert!(!checklist.is_complete());
        assert_eq!(checklist.first_missing(), Some(AuthorStep::EvalCommand));
    }
}
