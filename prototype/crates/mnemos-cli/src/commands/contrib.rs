//! `sinabro contrib` — contributor local dry-run (atom #464 · F.7.5 contributor
//! dry-run).
//!
//! Lets an external contributor validate a skill / package **locally** before
//! submitting it: it scans the candidate for baked secrets, requires a complete
//! author checklist, and requires the community-import dry-run to have been
//! Accepted (every Stage D security gate passed). It is the community-integration
//! seed before a hackathon — **not** a paid marketplace
//! ([`ContribDryRun::is_commerce`] is always `false`) — and it performs **no live
//! action**: there is no network, no upload, and no on-chain write
//! ([`ContribDryRun::try_contribute_live`] always refuses).
//!
//! Reuse (no reinvention): the checklist is the canonical Stage D
//! [`mnemos_e_skill::author_check::AuthorChecklist`] (#313); the import decision
//! is the canonical [`mnemos_e_skill::community_import::CommunitySkillImport`]
//! (#312); the secret scan is the Stage E
//! [`mnemos_l_dataset::privacy_scanner::scan_str`]. The verdict is the cockpit
//! [`crate::tui::RenderTruth`].
//!
//! # Secret custody proof (physics warning #464 resolution)
//!
//! The candidate bytes are read only to hand them to `scan_str`, which returns
//! **counts only, never a raw secret byte**. This module stores only those
//! counts ([`ContribDryRun`] holds no candidate text); it never `Debug`/`Clone`s
//! or renders a scanned value, and exposes no network / wallet / key API. A
//! non-clean scan fails closed with [`ContribReject::SecretFound`] (the
//! "no secrets" + "no network mode" criteria).

use crate::tui::RenderTruth;
use mnemos_e_skill::author_check::{AuthorChecklist, AuthorStep};
use mnemos_e_skill::community_import::{CommunitySkillDecision, CommunitySkillImport};
use mnemos_e_skill::package::SkillPackageDigest32;
use mnemos_l_dataset::privacy_scanner::scan_str;

/// Why a contributor dry-run refused (fail-closed).
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum ContribReject {
    /// The candidate carries a baked secret (secret / encoded hit). A
    /// contribution can never embed a secret, and none ever leaves locally.
    #[error("secret found in contribution candidate")]
    SecretFound,
    /// The author checklist is incomplete; the wrapped step is the first gap.
    #[error("incomplete author checklist")]
    IncompleteChecklist(AuthorStep),
    /// The community-import dry-run did not Accept the package (a Stage D
    /// security gate failed); the wrapped decision says which class.
    #[error("import not accepted")]
    ImportNotAccepted(CommunitySkillDecision),
    /// A live contribution (upload / on-chain write) was attempted. Forbidden in
    /// Stage F.
    #[error("live contribution forbidden in stage F")]
    LiveContributionForbiddenInStageF,
}

/// A passed contributor dry-run. Constructing one means: the secret scan was
/// clean, the author checklist was complete, and the import was Accepted. Holds
/// only scan counts (never candidate bytes) and can never go live.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ContribDryRun {
    package: SkillPackageDigest32,
    pii_hits: u32,
    secret_hits: u32,
    encoded_hits: u32,
}

impl ContribDryRun {
    /// Validate a contribution candidate locally. Fails closed in priority order:
    /// a baked secret (scan not clean) rejects first, then an incomplete author
    /// checklist, then a non-Accepted import. On success the candidate is clean
    /// by construction.
    pub fn evaluate(
        checklist: &AuthorChecklist,
        import: &CommunitySkillImport,
        candidate_text: &str,
    ) -> Result<Self, ContribReject> {
        // 1) Secret scan first — a secret never survives the dry-run.
        let scan = scan_str(candidate_text);
        if scan.secret_hits_u32 > 0 || scan.encoded_hits_u32 > 0 {
            return Err(ContribReject::SecretFound);
        }
        // 2) The author checklist must be complete.
        if let Some(step) = checklist.first_missing() {
            return Err(ContribReject::IncompleteChecklist(step));
        }
        // 3) The community-import dry-run must have Accepted (all D gates passed).
        if !import.decision.is_accepted() {
            return Err(ContribReject::ImportNotAccepted(import.decision));
        }
        Ok(Self {
            package: import.package,
            pii_hits: scan.pii_hits_u32,
            secret_hits: scan.secret_hits_u32,
            encoded_hits: scan.encoded_hits_u32,
        })
    }

    /// The validated package digest.
    #[must_use]
    pub const fn package(&self) -> SkillPackageDigest32 {
        self.package
    }

    /// Always `false`: a contributor dry-run is not a paid marketplace.
    #[must_use]
    pub const fn is_commerce(&self) -> bool {
        false
    }

    /// Always `true`: the dry-run is local-only.
    #[must_use]
    pub const fn is_local_only(&self) -> bool {
        true
    }

    /// Always `true`: no live network / chain call was made.
    #[must_use]
    pub const fn made_no_live_call(&self) -> bool {
        true
    }

    /// Attempt a live contribution (upload / on-chain). Always refuses in Stage F.
    pub const fn try_contribute_live(&self) -> Result<(), ContribReject> {
        Err(ContribReject::LiveContributionForbiddenInStageF)
    }

    /// The render truth. A constructed dry-run is clean and renders `Green`; the
    /// live contribution step is never executed.
    #[must_use]
    pub const fn render_truth(&self) -> RenderTruth {
        if self.secret_hits == 0 && self.encoded_hits == 0 {
            RenderTruth::Green
        } else {
            RenderTruth::Red
        }
    }

    /// Redacted, colorless dry-run lines bounded by `rows`. Only scan counts are
    /// shown — never a scanned value.
    #[must_use]
    pub fn render(&self, rows: u16) -> Vec<String> {
        let lines = vec![
            format!("is_commerce={}", self.is_commerce()),
            format!("local_only={}", self.is_local_only()),
            format!("no_live_call={}", self.made_no_live_call()),
            format!("secret_hits={}", self.secret_hits),
            format!("encoded_hits={}", self.encoded_hits),
            format!("pii_hits={}", self.pii_hits),
            format!("truth_u8={}", self.render_truth() as u8),
        ];
        lines.into_iter().take(rows as usize).collect()
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    #![allow(clippy::expect_used)]
    #![allow(clippy::panic)]

    use super::*;
    use mnemos_e_skill::community_import::CommunityImportEvidence;

    /// A clean candidate manifest, shaped like the skill author guide example.
    const AUTHOR_GUIDE_FIXTURE: &str =
        "name = \"hello-skill\"\ndescription = \"a first skill\"\neval_command = \"cargo test\"\n";

    /// A clean candidate shaped like the self-host gas guide example.
    const SELF_HOST_GAS_FIXTURE: &str =
        "name = \"gas-helper\"\ngas_mode = \"self_hosted\"\nendpoint = \"http://localhost:9000\"\n";

    fn complete_checklist() -> AuthorChecklist {
        AuthorChecklist {
            manifest_ok: true,
            fixtures_ok: true,
            eval_command_ok: true,
            capability_declared_ok: true,
            provenance_signed_ok: true,
            dry_run_ok: true,
        }
    }

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

    fn accepted_import(tag: u8) -> CommunitySkillImport {
        CommunitySkillImport::evaluate(
            [tag; 32],
            SkillPackageDigest32::new([tag; 32]),
            &good_evidence(),
            [0u8; 32],
        )
    }

    #[test]
    fn dry_run_passes_on_clean_complete_accepted() {
        let r = ContribDryRun::evaluate(
            &complete_checklist(),
            &accepted_import(0x10),
            AUTHOR_GUIDE_FIXTURE,
        )
        .unwrap();
        assert!(!r.is_commerce());
        assert!(r.is_local_only());
        assert_eq!(r.render_truth(), RenderTruth::Green);
    }

    #[test]
    fn dry_run_fails_when_import_not_accepted() {
        // A malicious-fixture-dirty import is Quarantined, never Accepted.
        let mut e = good_evidence();
        e.malicious_fixture_clean = false;
        let import = CommunitySkillImport::evaluate(
            [0x20; 32],
            SkillPackageDigest32::new([0x20; 32]),
            &e,
            [0u8; 32],
        );
        let r = ContribDryRun::evaluate(&complete_checklist(), &import, AUTHOR_GUIDE_FIXTURE);
        assert_eq!(
            r,
            Err(ContribReject::ImportNotAccepted(
                CommunitySkillDecision::Quarantined
            ))
        );
    }

    #[test]
    fn missing_metadata_reports_first_gap() {
        let mut checklist = complete_checklist();
        checklist.manifest_ok = false; // missing manifest metadata
        let r = ContribDryRun::evaluate(&checklist, &accepted_import(0x30), AUTHOR_GUIDE_FIXTURE);
        assert_eq!(
            r,
            Err(ContribReject::IncompleteChecklist(
                AuthorStep::ManifestSchema
            ))
        );
    }

    #[test]
    fn secret_scan_rejects_baked_secret() {
        let dirty = "name = \"x\"\nwallet_secret = \"sk_live_DEADBEEF0123456789\"\n";
        let r = ContribDryRun::evaluate(&complete_checklist(), &accepted_import(0x40), dirty);
        assert_eq!(r, Err(ContribReject::SecretFound));
    }

    #[test]
    fn no_network_mode_and_live_contribution_forbidden() {
        let r = ContribDryRun::evaluate(
            &complete_checklist(),
            &accepted_import(0x50),
            AUTHOR_GUIDE_FIXTURE,
        )
        .unwrap();
        assert!(r.made_no_live_call());
        assert_eq!(
            r.try_contribute_live(),
            Err(ContribReject::LiveContributionForbiddenInStageF)
        );
    }

    #[test]
    fn skill_author_guide_fixture_passes() {
        let r = ContribDryRun::evaluate(
            &complete_checklist(),
            &accepted_import(0x60),
            AUTHOR_GUIDE_FIXTURE,
        );
        assert!(r.is_ok(), "the author guide example must pass the dry-run");
    }

    #[test]
    fn self_host_gas_guide_fixture_passes() {
        let r = ContribDryRun::evaluate(
            &complete_checklist(),
            &accepted_import(0x70),
            SELF_HOST_GAS_FIXTURE,
        );
        assert!(r.is_ok(), "the self-host gas guide example must pass");
    }

    #[test]
    fn render_is_bounded_and_no_commerce() {
        let r = ContribDryRun::evaluate(
            &complete_checklist(),
            &accepted_import(0x80),
            AUTHOR_GUIDE_FIXTURE,
        )
        .unwrap();
        assert!(r.render(2).len() <= 2);
        const COMMERCE: &[&str] = &["price", "buy", "sell", "checkout", "refund", "$"];
        for line in r.render(64) {
            for t in COMMERCE {
                assert!(!line.contains(*t), "commerce token {t} leaked: {line}");
            }
        }
    }
}
