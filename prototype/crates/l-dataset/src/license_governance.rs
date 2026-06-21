//! Dataset license / provenance governance (atom #383 · E.2.12).
//!
//! Internal A-D traces are allowed (their provenance is the build itself). An
//! external source must carry a known, compatible license **and** provenance; an
//! unknown or incompatible license, or a private/proprietary repo, is
//! **quarantined** (never exported, never reward) until resolved. Reuses the
//! provenance chain (#369): a sample whose license is unknown is quarantined by
//! construction, so license participates in the export decision, not just the
//! file path.
use crate::diet_kind::AtomDietKey;
use crate::provenance::ProvenanceChain;

/// A classified dataset license.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
#[repr(u8)]
pub enum LicenseClass {
    /// A first-party A-D build trace (self-evidenced provenance).
    InternalAToD = 1,
    /// MIT.
    Mit = 2,
    /// Apache-2.0.
    Apache2 = 3,
    /// A BSD family license.
    Bsd = 4,
    /// Unknown / unrecognized license.
    Unknown = 5,
    /// A private / proprietary / confidential repo.
    PrivateRepo = 6,
}

impl LicenseClass {
    /// Numeric discriminant (`1..=6`).
    pub const fn as_u8(self) -> u8 {
        self as u8
    }

    /// Classify a license tag fail-closed: anything unrecognized is `Unknown`.
    pub fn classify(tag: &str) -> Self {
        let t = tag.trim().to_ascii_lowercase();
        if t.contains("internal") || t.contains("a-d") || t.contains("first-party") {
            Self::InternalAToD
        } else if t.contains("private") || t.contains("proprietary") || t.contains("confidential") {
            Self::PrivateRepo
        } else if t.contains("mit") {
            Self::Mit
        } else if t.contains("apache") {
            Self::Apache2
        } else if t.contains("bsd") {
            Self::Bsd
        } else {
            Self::Unknown
        }
    }

    /// Whether sources under this license *class* may be exported (still subject
    /// to provenance for external classes).
    pub const fn class_exportable(self) -> bool {
        matches!(
            self,
            Self::InternalAToD | Self::Mit | Self::Apache2 | Self::Bsd
        )
    }
}

/// The governance decision for one source.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub struct LicenseDecision {
    /// The source atom.
    pub key: AtomDietKey,
    /// The classified license.
    pub class: LicenseClass,
    /// Whether the provenance chain reports a known license.
    pub license_known: bool,
    /// Whether this source may be exported.
    pub exportable: bool,
    /// Whether this source is quarantined (never exported / reward).
    pub quarantined: bool,
}

/// Govern a source's export decision. Internal A-D traces are always exportable;
/// MIT/Apache/BSD export only with provenance (a known license); unknown and
/// private/proprietary sources are quarantined.
pub fn govern(
    key: AtomDietKey,
    license_tag: &str,
    provenance: &ProvenanceChain,
) -> LicenseDecision {
    let class = LicenseClass::classify(license_tag);
    let exportable = match class {
        LicenseClass::InternalAToD => true,
        LicenseClass::Mit | LicenseClass::Apache2 | LicenseClass::Bsd => provenance.license_known,
        LicenseClass::Unknown | LicenseClass::PrivateRepo => false,
    };
    LicenseDecision {
        key,
        class,
        license_known: provenance.license_known,
        exportable,
        quarantined: !exportable,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::diet_kind::DietSourceStage;

    fn key() -> AtomDietKey {
        AtomDietKey::new(DietSourceStage::StageD, 383)
    }

    fn chain(license_known: bool) -> ProvenanceChain {
        ProvenanceChain::new(key(), [1u8; 32], [2u8; 32], license_known)
    }

    #[test]
    fn internal_source_is_exportable_without_external_license() {
        let d = govern(key(), "internal A-D trace", &chain(false));
        assert_eq!(d.class, LicenseClass::InternalAToD);
        assert!(d.exportable);
        assert!(!d.quarantined);
    }

    #[test]
    fn mit_and_apache_and_bsd_with_provenance_export() {
        assert!(govern(key(), "MIT", &chain(true)).exportable);
        assert!(govern(key(), "Apache-2.0", &chain(true)).exportable);
        assert_eq!(
            govern(key(), "BSD-3-Clause", &chain(true)).class,
            LicenseClass::Bsd
        );
    }

    #[test]
    fn mit_without_provenance_quarantines() {
        let d = govern(key(), "MIT", &chain(false));
        assert_eq!(d.class, LicenseClass::Mit);
        assert!(!d.exportable);
        assert!(d.quarantined);
    }

    #[test]
    fn unknown_license_quarantines() {
        let d = govern(key(), "weird-custom-license", &chain(true));
        assert_eq!(d.class, LicenseClass::Unknown);
        assert!(d.quarantined);
    }

    #[test]
    fn private_repo_quarantines() {
        let d = govern(key(), "proprietary/confidential", &chain(true));
        assert_eq!(d.class, LicenseClass::PrivateRepo);
        assert!(d.quarantined);
    }
}
