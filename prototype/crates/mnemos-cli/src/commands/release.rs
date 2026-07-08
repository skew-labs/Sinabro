//! `sinabro release` — launchable package dry-run.
//!
//! A local, offline **dry-run** of a release: it parses the version metadata,
//! scans the would-be-packaged bytes for *baked secrets*, and folds an install
//! smoke result — but it never actually publishes a public release
//! ([`ReleaseDryRun::try_publish`] always refuses with
//! [`ReleaseReject::LiveReleaseForbiddenInStageF`]).
//!
//! Reuse: the baked-secret scan is the canonical
//! [`mnemos_l_dataset::privacy_scanner::scan_str`] returning a [`ScanReport`];
//! this module re-runs no redaction logic of its own. The red/yellow/green
//! verdict is the cockpit [`crate::tui::RenderTruth`].
//!
//! # Secret custody proof
//!
//! The dry-run reads candidate bytes only to hand them to `scan_str`, which
//! returns **counts and a decision, never a raw secret byte** (`ScanReport` is
//! `Copy` + `Debug`-scalars-only). This module stores
//! only those counts ([`ReleaseDryRun`] holds no package text); it never
//! `Debug`/`Clone`s or renders a scanned value, and exposes no
//! network / wallet / key API. A non-clean scan fails closed
//! ([`ReleaseReject::BakedSecretFound`]) — a secret can never ride a release.

use crate::tui::RenderTruth;
use mnemos_l_dataset::privacy_scanner::{ScanReport, scan_str};

/// Parsed `major.minor.patch` release version metadata.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ReleaseVersion {
    /// Major version.
    pub major: u16,
    /// Minor version.
    pub minor: u16,
    /// Patch version.
    pub patch: u16,
}

impl ReleaseVersion {
    /// Parse a `"x.y.z"` triplet. Returns `None` for any shape other than three
    /// dot-separated `u16` components (so empty / malformed metadata is caught).
    #[must_use]
    pub fn parse(s: &str) -> Option<Self> {
        let mut it = s.split('.');
        let major = it.next()?.parse::<u16>().ok()?;
        let minor = it.next()?.parse::<u16>().ok()?;
        let patch = it.next()?.parse::<u16>().ok()?;
        if it.next().is_some() {
            return None; // more than three components
        }
        Some(Self {
            major,
            minor,
            patch,
        })
    }

    /// Render the version back to its `"x.y.z"` form.
    #[must_use]
    pub fn render(&self) -> String {
        format!("{}.{}.{}", self.major, self.minor, self.patch)
    }
}

/// Why a release dry-run refused (fail-closed).
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum ReleaseReject {
    /// The version metadata was missing or malformed.
    #[error("missing or malformed version metadata")]
    MissingVersion,
    /// The packaged bytes carry a baked secret (secret / encoded hit) — a
    /// release can never embed a secret.
    #[error("baked secret found in release candidate")]
    BakedSecretFound,
    /// The install smoke test did not pass.
    #[error("install smoke failed")]
    InstallSmokeFailed,
    /// A live publish was attempted; this surface never publishes a public release.
    #[error("live release forbidden in stage F")]
    LiveReleaseForbiddenInStageF,
}

/// A passed release dry-run. Constructing one means: version parsed, the
/// baked-secret scan was clean, and the install smoke passed. It holds only
/// scan *counts* (never package bytes) and can never publish.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ReleaseDryRun {
    version: ReleaseVersion,
    pii_hits: u32,
    secret_hits: u32,
    encoded_hits: u32,
    install_smoke_ok: bool,
}

impl ReleaseDryRun {
    /// Run a release dry-run over the candidate `package_text`, the `version_str`
    /// metadata, and an upstream `install_smoke_ok` verdict.
    ///
    /// Fails closed: a malformed version rejects, a non-clean baked-secret scan
    /// rejects with [`ReleaseReject::BakedSecretFound`] (only the counts survive),
    /// and a failed install smoke rejects. On success the dry-run is clean by
    /// construction (`secret_hits == 0 && encoded_hits == 0`).
    pub fn evaluate(
        package_text: &str,
        version_str: &str,
        install_smoke_ok: bool,
    ) -> Result<Self, ReleaseReject> {
        let version = ReleaseVersion::parse(version_str).ok_or(ReleaseReject::MissingVersion)?;
        let scan: ScanReport = scan_str(package_text);
        // A baked secret (hard-secret or encoded hit) can never ride a release.
        if scan.secret_hits_u32 > 0 || scan.encoded_hits_u32 > 0 {
            return Err(ReleaseReject::BakedSecretFound);
        }
        if !install_smoke_ok {
            return Err(ReleaseReject::InstallSmokeFailed);
        }
        Ok(Self {
            version,
            pii_hits: scan.pii_hits_u32,
            secret_hits: scan.secret_hits_u32,
            encoded_hits: scan.encoded_hits_u32,
            install_smoke_ok,
        })
    }

    /// The parsed version metadata.
    #[must_use]
    pub const fn version(&self) -> ReleaseVersion {
        self.version
    }

    /// Always `true`: the release is dry-run only.
    #[must_use]
    pub const fn is_dry_run(&self) -> bool {
        true
    }

    /// Always `false`: it never publishes a public release.
    #[must_use]
    pub const fn published(&self) -> bool {
        false
    }

    /// Attempt to publish for real. Always refuses — there is no code
    /// path from this module to a live release.
    pub const fn try_publish(&self) -> Result<(), ReleaseReject> {
        Err(ReleaseReject::LiveReleaseForbiddenInStageF)
    }

    /// The render truth. A constructed dry-run is clean (no baked secret, smoke
    /// passed) and renders `Green`; the publish step is never executed (so it can
    /// never be falsely green).
    #[must_use]
    pub const fn render_truth(&self) -> RenderTruth {
        if self.secret_hits == 0 && self.encoded_hits == 0 && self.install_smoke_ok {
            RenderTruth::Green
        } else {
            RenderTruth::Red
        }
    }

    /// Redacted, colorless dry-run status lines bounded by `rows`. Only scan
    /// counts and the version are shown — never a scanned value.
    #[must_use]
    pub fn render(&self, rows: u16) -> Vec<String> {
        let lines = vec![
            format!("version={}", self.version.render()),
            format!("is_dry_run={}", self.is_dry_run()),
            format!("published={}", self.published()),
            format!("secret_hits={}", self.secret_hits),
            format!("encoded_hits={}", self.encoded_hits),
            format!("pii_hits={}", self.pii_hits),
            format!("install_smoke_ok={}", self.install_smoke_ok),
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

    const CLEAN_PACKAGE: &str = "name = \"sinabro-skill\"\ndescription = \"a demo skill\"\n";

    #[test]
    fn package_dry_run_passes_on_clean_candidate() {
        let r = ReleaseDryRun::evaluate(CLEAN_PACKAGE, "1.2.3", true).unwrap();
        assert!(r.is_dry_run());
        assert!(!r.published());
        assert_eq!(r.version(), ReleaseVersion::new_for_test(1, 2, 3));
        assert_eq!(r.render_truth(), RenderTruth::Green);
    }

    #[test]
    fn install_smoke_failure_rejects() {
        let r = ReleaseDryRun::evaluate(CLEAN_PACKAGE, "0.1.0", false);
        assert_eq!(r, Err(ReleaseReject::InstallSmokeFailed));
    }

    #[test]
    fn baked_secret_scan_rejects_release() {
        // A provider/live key baked into the candidate is caught by the canonical
        // scanner and the release is refused — secret never embedded.
        let dirty = "name = \"x\"\nprovider_api_key = \"sk_live_ABCDEF0123456789\"\n";
        let r = ReleaseDryRun::evaluate(dirty, "1.0.0", true);
        assert_eq!(r, Err(ReleaseReject::BakedSecretFound));
    }

    #[test]
    fn version_metadata_must_be_well_formed() {
        assert_eq!(
            ReleaseDryRun::evaluate(CLEAN_PACKAGE, "", true),
            Err(ReleaseReject::MissingVersion)
        );
        assert_eq!(
            ReleaseDryRun::evaluate(CLEAN_PACKAGE, "1.2", true),
            Err(ReleaseReject::MissingVersion)
        );
        assert_eq!(
            ReleaseDryRun::evaluate(CLEAN_PACKAGE, "1.2.3.4", true),
            Err(ReleaseReject::MissingVersion)
        );
        assert!(ReleaseVersion::parse("10.20.30").is_some());
    }

    #[test]
    fn live_publish_is_forbidden_in_stage_f() {
        let r = ReleaseDryRun::evaluate(CLEAN_PACKAGE, "1.0.0", true).unwrap();
        assert_eq!(
            r.try_publish(),
            Err(ReleaseReject::LiveReleaseForbiddenInStageF)
        );
        assert!(!r.published());
    }

    #[test]
    fn render_is_bounded_and_no_commerce() {
        let r = ReleaseDryRun::evaluate(CLEAN_PACKAGE, "2.0.1", true).unwrap();
        assert!(r.render(2).len() <= 2);
        assert!(r.render(64).len() <= 8);
        const COMMERCE: &[&str] = &["price", "buy", "sell", "checkout", "refund", "$"];
        for line in r.render(64) {
            for t in COMMERCE {
                assert!(!line.contains(*t), "commerce token {t} leaked: {line}");
            }
        }
    }

    // Test-only constructor mirror so the version assertion does not reach into
    // private fields through a public ctor that production code does not need.
    impl ReleaseVersion {
        fn new_for_test(major: u16, minor: u16, patch: u16) -> Self {
            Self {
                major,
                minor,
                patch,
            }
        }
    }
}
