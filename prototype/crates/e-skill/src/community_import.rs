//! `mnemos-e-skill::community_import` — atom #312 · D.4.1 — the external/
//! community skill import flow.
//!
//! ## Canonical OUT (§4.5 — ATOM_PLAN line 351, 364-370)
//!
//! - [`CommunitySkillDecision`] — §4.5 `{ Pending=1, Accepted=2,
//!   Quarantined=3, Rejected=4 }`.
//! - [`CommunitySkillImport`] — §4.5 `{ source_hash_32, package, decision,
//!   review_hash_32, no_commerce_scan_hash_32 }`.
//!
//! ## Dry-run-first flow (reuse #242-#255)
//!
//! An external import is **dry-run first** (§312 광기): the package is parsed,
//! its signature/provenance checked (#246 / #247), the malicious-fixture suite
//! run (#250), the capability diff checked for hidden permissions (#244
//! [`CapabilityDiff::is_consistent`]), the eval command presence checked
//! (#245), and the no-commerce scan run (#243
//! [`scan_no_commerce`]). [`decide_import`] folds these gate results into one
//! [`CommunitySkillDecision`]. Import is a *decision*, not an enable: the
//! decision enum has no executable state, so an import **can never auto-enable
//! execution** — enabling stays the local install state machine (#316) gated by
//! a signed install receipt (#315).
//!
//! ## Determinism + offline boundary
//!
//! [`decide_import`] is a pure function of the six gate booleans (§312
//! criterion — *import report is deterministic*). No network, wallet, secret,
//! or chain action; the report carries hashes, never the imported source bytes.

#![deny(missing_docs)]

extern crate alloc;

use crate::capability_diff::CapabilityDiff;
use crate::package::{SkillPackageDigest32, blake2b_256};
use crate::package_policy::{no_commerce_policy_hash, scan_no_commerce};

/// Domain tag binding the no-commerce scan outcome into the import record.
const DOMAIN_IMPORT_NO_COMMERCE: &[u8] = b"mnemos.d.community_import_no_commerce.v1";

// ===========================================================================
// 1. CommunitySkillDecision — §4.5
// ===========================================================================

/// The decision of a community import dry-run (§4.5).
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
#[repr(u8)]
pub enum CommunitySkillDecision {
    /// Imported and parsed, but a soft gate (missing eval) is unmet — held for
    /// review, never auto-enabled.
    Pending = 1,
    /// Every gate passed — eligible for the review queue / catalog.
    Accepted = 2,
    /// A suspicious gate failed (malicious fixture) — quarantined for a
    /// maintainer, never executable.
    Quarantined = 3,
    /// A hard gate failed (unsigned, bad provenance, hidden permission, or a
    /// commerce surface) — refused outright.
    Rejected = 4,
}

impl CommunitySkillDecision {
    /// Stable, leak-free class label.
    #[inline]
    #[must_use]
    pub const fn class_label(&self) -> &'static str {
        match self {
            Self::Pending => "community_import.pending",
            Self::Accepted => "community_import.accepted",
            Self::Quarantined => "community_import.quarantined",
            Self::Rejected => "community_import.rejected",
        }
    }

    /// `true` iff this decision admits the skill into the catalog/review surface
    /// (only `Accepted`). NEVER implies execution — enable is gated elsewhere.
    #[inline]
    #[must_use]
    pub const fn is_accepted(&self) -> bool {
        matches!(self, Self::Accepted)
    }
}

// ===========================================================================
// 2. CommunityImportEvidence — the dry-run gate results
// ===========================================================================

/// The dry-run gate results for an external skill import. Each field is the
/// output of an existing D-WP-01A/02 gate (#242-#255); this module never
/// re-runs those gates, it folds their verdicts.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub struct CommunityImportEvidence {
    /// The package carried an author signature (#247).
    pub signature_present: bool,
    /// The provenance chain validated (#246).
    pub provenance_ok: bool,
    /// The capability diff is consistent — no hidden permission (#244).
    pub capability_consistent: bool,
    /// The malicious-fixture suite passed (#250).
    pub malicious_fixture_clean: bool,
    /// An eval command/score is present (#245).
    pub eval_present: bool,
    /// The no-commerce scan passed (#243).
    pub no_commerce_clean: bool,
}

impl CommunityImportEvidence {
    /// Build evidence, deriving `capability_consistent` from the #244 diff and
    /// `no_commerce_clean` from the #243 scan of the imported manifest TOML, so
    /// the canonical gates are actually consumed (not re-implemented).
    #[must_use]
    pub fn from_gates(
        signature_present: bool,
        provenance_ok: bool,
        malicious_fixture_clean: bool,
        eval_present: bool,
        capability_diff: &CapabilityDiff,
        manifest_toml: &str,
    ) -> Self {
        Self {
            signature_present,
            provenance_ok,
            capability_consistent: capability_diff.is_consistent(),
            malicious_fixture_clean,
            eval_present,
            no_commerce_clean: scan_no_commerce(manifest_toml).is_ok(),
        }
    }
}

// ===========================================================================
// 3. decide_import — the deterministic gate fold
// ===========================================================================

/// Fold the dry-run gate results into a [`CommunitySkillDecision`]. A pure
/// function of the six booleans: a hard-gate failure (unsigned / bad provenance
/// / hidden permission / commerce surface) is [`Rejected`](CommunitySkillDecision::Rejected);
/// otherwise a dirty malicious fixture is
/// [`Quarantined`](CommunitySkillDecision::Quarantined); otherwise a missing
/// eval is [`Pending`](CommunitySkillDecision::Pending); otherwise
/// [`Accepted`](CommunitySkillDecision::Accepted).
#[must_use]
pub fn decide_import(e: &CommunityImportEvidence) -> CommunitySkillDecision {
    if !e.signature_present || !e.provenance_ok || !e.capability_consistent || !e.no_commerce_clean
    {
        CommunitySkillDecision::Rejected
    } else if !e.malicious_fixture_clean {
        CommunitySkillDecision::Quarantined
    } else if !e.eval_present {
        CommunitySkillDecision::Pending
    } else {
        CommunitySkillDecision::Accepted
    }
}

// ===========================================================================
// 4. CommunitySkillImport — §4.5 record
// ===========================================================================

/// The record of an external import dry-run (§4.5).
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub struct CommunitySkillImport {
    /// Hash of the import source (URL / bundle bytes) — never the raw source.
    pub source_hash_32: [u8; 32],
    /// The imported package's content digest.
    pub package: SkillPackageDigest32,
    /// The folded import decision.
    pub decision: CommunitySkillDecision,
    /// Hash of the human/maintainer review note (zero until reviewed).
    pub review_hash_32: [u8; 32],
    /// Hash binding the no-commerce scan outcome to the #243 policy version.
    pub no_commerce_scan_hash_32: [u8; 32],
}

impl CommunitySkillImport {
    /// Evaluate an import: fold the evidence into a decision and bind the
    /// no-commerce scan outcome to the #243 policy version. Deterministic for a
    /// fixed `(source, package, evidence, review)`.
    #[must_use]
    pub fn evaluate(
        source_hash_32: [u8; 32],
        package: SkillPackageDigest32,
        evidence: &CommunityImportEvidence,
        review_hash_32: [u8; 32],
    ) -> Self {
        let decision = decide_import(evidence);
        let no_commerce_scan_hash_32 = no_commerce_scan_hash(evidence.no_commerce_clean);
        Self {
            source_hash_32,
            package,
            decision,
            review_hash_32,
            no_commerce_scan_hash_32,
        }
    }
}

/// Bind the no-commerce scan outcome (clean/dirty) to the #243 policy-version
/// hash, so a stored import record proves which forbidden vocabulary it was
/// scanned against.
#[must_use]
fn no_commerce_scan_hash(clean: bool) -> [u8; 32] {
    let policy = no_commerce_policy_hash();
    blake2b_256(&[DOMAIN_IMPORT_NO_COMMERCE, &policy, &[u8::from(clean)]])
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use alloc::vec::Vec;

    fn good_evidence() -> CommunityImportEvidence {
        CommunityImportEvidence {
            signature_present: true,
            provenance_ok: true,
            capability_consistent: true,
            malicious_fixture_clean: true,
            eval_present: true,
            no_commerce_clean: true,
        }
    }

    fn pkg() -> SkillPackageDigest32 {
        SkillPackageDigest32::new([0x31; 32])
    }

    #[test]
    fn valid_import_accepted() {
        let imp = CommunitySkillImport::evaluate([0x01; 32], pkg(), &good_evidence(), [0u8; 32]);
        assert_eq!(imp.decision, CommunitySkillDecision::Accepted);
        assert!(imp.decision.is_accepted());
        assert_ne!(imp.no_commerce_scan_hash_32, [0u8; 32]);
    }

    #[test]
    fn unsigned_rejected() {
        let mut e = good_evidence();
        e.signature_present = false;
        assert_eq!(decide_import(&e), CommunitySkillDecision::Rejected);
    }

    #[test]
    fn hidden_permission_rejected_via_real_diff() {
        // A capability diff whose digest no longer matches its mask is hiding a
        // permission; `from_gates` must surface it as inconsistent -> Rejected.
        let mut diff = CapabilityDiff::new(0b11, 0, Vec::new());
        diff.human_digest_32 = [0u8; 32]; // tamper -> inconsistent
        assert!(!diff.is_consistent());
        let e =
            CommunityImportEvidence::from_gates(true, true, true, true, &diff, "name = \"ok\"\n");
        assert!(!e.capability_consistent);
        assert_eq!(decide_import(&e), CommunitySkillDecision::Rejected);
    }

    #[test]
    fn missing_eval_warns_pending() {
        let mut e = good_evidence();
        e.eval_present = false;
        assert_eq!(decide_import(&e), CommunitySkillDecision::Pending);
    }

    #[test]
    fn malicious_fixture_quarantined() {
        let mut e = good_evidence();
        e.malicious_fixture_clean = false;
        // Not auto-rejected, but never accepted/executable.
        assert_eq!(decide_import(&e), CommunitySkillDecision::Quarantined);
        assert!(!decide_import(&e).is_accepted());
    }

    #[test]
    fn no_commerce_violation_rejected_via_scan() {
        // A manifest with a checkout key fails the #243 scan inside `from_gates`.
        let diff = CapabilityDiff::new(0, 0, Vec::new());
        let e = CommunityImportEvidence::from_gates(
            true,
            true,
            true,
            true,
            &diff,
            "name = \"x\"\ncheckout_url = \"https://pay\"\n",
        );
        assert!(!e.no_commerce_clean);
        assert_eq!(decide_import(&e), CommunitySkillDecision::Rejected);
    }

    #[test]
    fn import_is_deterministic() {
        let a = CommunitySkillImport::evaluate([0x01; 32], pkg(), &good_evidence(), [0u8; 32]);
        let b = CommunitySkillImport::evaluate([0x01; 32], pkg(), &good_evidence(), [0u8; 32]);
        assert_eq!(a, b);
    }
}
