//! Open-source release secret-baking scan (atom #477 · F.8.10).
//!
//! # Custody / live-boundary proof (physics #477 resolution)
//!
//! Before the open-source client ships, every release surface — repo, image,
//! docs, examples, git history, command trace, and the packaged artifact — is
//! scanned so a sponsor key (or any wallet / provider / commerce secret) cannot
//! appear anywhere. The scan is a **pure function over in-memory candidate
//! bytes**: it reuses the canonical Stage E
//! [`mnemos_l_dataset::privacy_scanner::scan_str`], which performs no network /
//! wallet / process / filesystem-write call (no such API exists in this module
//! either). Its output ([`SurfaceScan`]) carries **only counts** — never a raw
//! secret byte ([`ScanReport`] is `Copy` over scalars) — and the gate is
//! **fail-closed**: a single hard-secret or encoded-secret hit on any surface
//! rejects the release. No secret value is ever loaded, so there is nothing to
//! `Debug` / `Clone`. `live_action_allowed = false`.
//!
//! Reuse (no reinvention): the scanner + counts report are the canonical Stage E
//! `privacy_scanner`; the verdict is the shared [`crate::tui::RenderTruth`].

use mnemos_l_dataset::privacy_scanner::{ScanReport, scan_str};

use crate::tui::RenderTruth;

/// The release surfaces that must all be secret-clean before ship (atom #477).
#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReleaseSurface {
    /// Source repository tree.
    Repo = 1,
    /// Container / binary image.
    Image = 2,
    /// Documentation.
    Docs = 3,
    /// Examples / fixtures.
    Examples = 4,
    /// Git / commit history.
    History = 5,
    /// Command trace sidecar.
    Trace = 6,
    /// The packaged release artifact.
    Package = 7,
}

impl ReleaseSurface {
    /// The stable `u8` discriminant.
    #[must_use]
    pub const fn as_u8(self) -> u8 {
        self as u8
    }

    /// A stable lower-case ASCII label (colorless terminals rely on the word).
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Repo => "repo",
            Self::Image => "image",
            Self::Docs => "docs",
            Self::Examples => "examples",
            Self::History => "history",
            Self::Trace => "trace",
            Self::Package => "package",
        }
    }

    /// Every release surface, in discriminant order.
    #[must_use]
    pub const fn all() -> [ReleaseSurface; 7] {
        [
            Self::Repo,
            Self::Image,
            Self::Docs,
            Self::Examples,
            Self::History,
            Self::Trace,
            Self::Package,
        ]
    }
}

/// A counts-only scan of one release surface (no raw secret bytes).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SurfaceScan {
    /// The scanned surface.
    pub surface: ReleaseSurface,
    /// The counts-only privacy report.
    pub report: ScanReport,
}

impl SurfaceScan {
    /// Scan a surface's candidate text, keeping only counts.
    #[must_use]
    pub fn scan(surface: ReleaseSurface, candidate: &str) -> Self {
        Self {
            surface,
            report: scan_str(candidate),
        }
    }

    /// Whether this surface is free of hard-secret and encoded-secret hits.
    #[must_use]
    pub const fn is_secret_free(&self) -> bool {
        self.report.secret_hits_u32 == 0 && self.report.encoded_hits_u32 == 0
    }
}

/// Why a release secret scan failed (fail-closed) — a secret can never ride a
/// release. Only the *kind* of hit is surfaced, never the secret itself.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum ReleaseSecretReject {
    /// A hard secret (sponsor / wallet / provider / commerce key) was found.
    #[error("baked secret found on a release surface")]
    BakedSecretFound,
    /// An encoded secret (base64 / hex / gzip / zip) was found.
    #[error("encoded secret found on a release surface")]
    EncodedSecretFound,
}

/// The whole-release secret scan: the per-surface counts plus the fail-closed
/// verdict.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ReleaseSecretScan {
    scans: Vec<SurfaceScan>,
}

impl ReleaseSecretScan {
    /// An empty scan.
    #[must_use]
    pub fn new() -> Self {
        Self { scans: Vec::new() }
    }

    /// Scan and record one surface.
    pub fn add(&mut self, surface: ReleaseSurface, candidate: &str) {
        self.scans.push(SurfaceScan::scan(surface, candidate));
    }

    /// The per-surface scans.
    #[must_use]
    pub fn scans(&self) -> &[SurfaceScan] {
        &self.scans
    }

    /// The number of surfaces scanned.
    #[must_use]
    pub fn len(&self) -> usize {
        self.scans.len()
    }

    /// Whether nothing has been scanned yet.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.scans.is_empty()
    }

    /// Total hard-secret hits across every surface.
    #[must_use]
    pub fn total_secret_hits(&self) -> u32 {
        self.scans.iter().map(|s| s.report.secret_hits_u32).sum()
    }

    /// Total encoded-secret hits across every surface.
    #[must_use]
    pub fn total_encoded_hits(&self) -> u32 {
        self.scans.iter().map(|s| s.report.encoded_hits_u32).sum()
    }

    /// Total redactable-PII hits across every surface.
    #[must_use]
    pub fn total_pii_hits(&self) -> u32 {
        self.scans.iter().map(|s| s.report.pii_hits_u32).sum()
    }

    /// Whether every scanned surface is secret-free (the ship criterion:
    /// secret hits == 0).
    #[must_use]
    pub fn is_clean(&self) -> bool {
        self.total_secret_hits() == 0 && self.total_encoded_hits() == 0
    }

    /// No-false-green verdict: Red on any secret / encoded hit; Unknown when
    /// nothing has been scanned (never measured); else Green.
    #[must_use]
    pub fn render_truth(&self) -> RenderTruth {
        if self.scans.is_empty() {
            RenderTruth::Unknown
        } else if self.is_clean() {
            RenderTruth::Green
        } else {
            RenderTruth::Red
        }
    }

    /// Fail-closed gate: reject the release if any surface carries a hard or an
    /// encoded secret. The error distinguishes the two so the operator knows what
    /// to scrub; only counts are ever surfaced.
    pub fn gate(&self) -> Result<(), ReleaseSecretReject> {
        if self.total_secret_hits() > 0 {
            return Err(ReleaseSecretReject::BakedSecretFound);
        }
        if self.total_encoded_hits() > 0 {
            return Err(ReleaseSecretReject::EncodedSecretFound);
        }
        Ok(())
    }

    /// A bounded, colorless, ASCII one-line summary (no raw secret bytes).
    #[must_use]
    pub fn render_plain(&self) -> String {
        format!(
            "release_scan surfaces={} secret_hits={} encoded_hits={} pii_hits={} clean={}",
            self.len(),
            self.total_secret_hits(),
            self.total_encoded_hits(),
            self.total_pii_hits(),
            self.is_clean(),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fake_sponsor_key_fixture_rejects() {
        let mut scan = ReleaseSecretScan::new();
        scan.add(ReleaseSurface::Repo, "sponsor_key: 0xFAKEdeadbeef0123");
        assert!(scan.total_secret_hits() >= 1);
        assert_eq!(scan.gate(), Err(ReleaseSecretReject::BakedSecretFound));
        assert_eq!(scan.render_truth(), RenderTruth::Red);
        assert!(!scan.is_clean());
    }

    #[test]
    fn provider_key_fixture_rejects() {
        let mut scan = ReleaseSecretScan::new();
        scan.add(
            ReleaseSurface::Package,
            "provider_api_key=sk_test_fakefakefake",
        );
        assert!(scan.total_secret_hits() >= 1);
        assert_eq!(scan.gate(), Err(ReleaseSecretReject::BakedSecretFound));
    }

    #[test]
    fn wallet_secret_fixture_rejects() {
        let mut scan = ReleaseSecretScan::new();
        scan.add(
            ReleaseSurface::History,
            "leftover wallet_secret in an old commit",
        );
        assert!(scan.total_secret_hits() >= 1);
        assert_eq!(scan.gate(), Err(ReleaseSecretReject::BakedSecretFound));
    }

    #[test]
    fn encoded_secret_fixture_rejects() {
        let mut scan = ReleaseSecretScan::new();
        // A long high-entropy base64 run (mixed case + digits) with no hard marker
        // -> encoded hit only, so the gate distinguishes it.
        scan.add(
            ReleaseSurface::Image,
            "blob Zm9vYmFyQUJDMTIzZm9vYmFyQUJDMTIzZm9vYmFyQUJD12345 end",
        );
        assert_eq!(scan.total_secret_hits(), 0);
        assert!(scan.total_encoded_hits() >= 1);
        assert_eq!(scan.gate(), Err(ReleaseSecretReject::EncodedSecretFound));
        assert_eq!(scan.render_truth(), RenderTruth::Red);
    }

    #[test]
    fn clean_release_passes_with_zero_secret_hits() {
        let mut scan = ReleaseSecretScan::new();
        scan.add(ReleaseSurface::Repo, "fn main() { greet(); }\n");
        scan.add(
            ReleaseSurface::Docs,
            "# Sinabro\nA local-first CLI cockpit.\n",
        );
        scan.add(
            ReleaseSurface::Trace,
            "trace risk=1 exit=0 out_hash=08574d725cb3fe2cbd12e939779ecce227e3f2bc8670f17e6fdca72c1ccec009\n",
        );
        assert_eq!(scan.total_secret_hits(), 0);
        assert_eq!(scan.total_encoded_hits(), 0);
        assert!(scan.is_clean());
        assert!(scan.gate().is_ok());
        assert_eq!(scan.render_truth(), RenderTruth::Green);
    }

    #[test]
    fn empty_scan_is_unknown_not_green() {
        let scan = ReleaseSecretScan::new();
        assert!(scan.is_empty());
        assert_eq!(scan.render_truth(), RenderTruth::Unknown);
        assert!(!scan.render_truth().is_healthy());
    }

    #[test]
    fn render_plain_is_colorless_ascii() {
        let mut scan = ReleaseSecretScan::new();
        scan.add(ReleaseSurface::Docs, "clean readme\n");
        let line = scan.render_plain();
        assert!(line.is_ascii());
        assert!(!line.contains('\u{1b}'));
        assert!(line.contains("clean=true"));
    }

    #[test]
    fn all_seven_surfaces_enumerated() {
        assert_eq!(ReleaseSurface::all().len(), 7);
        assert_eq!(ReleaseSurface::Repo.label(), "repo");
        assert_eq!(ReleaseSurface::Package.as_u8(), 7);
    }
}
