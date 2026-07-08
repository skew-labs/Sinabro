//! `mnemos-e-skill::catalog_index` — the catalog index entry.
//!
//! A [`SkillCatalogIndexEntry`] is a **denormalized, search-facing view** of an
//! already-signed, already-verified package. It folds together the
//! signed package digest, the eval / security state, the
//! evaluated compatibility decision, the capability diff, and the
//! content-addressed provenance, plus three weak/strong popularity
//! counters.
//!
//! The core invariant: a catalog entry is **never** the source of executable
//! permission truth ([`SkillCatalogIndexEntry::is_permission_truth_source`] is
//! always `false`). Use / install still flow through the signed package,
//! capability approval, dry-run, and the install plan — the index only
//! makes a verified package *discoverable*, it can never *authorize* one. An
//! install receipt is likewise never inferred from a catalog entry: the entry
//! carries no [`crate::install_state::InstallState`] field at all.

#![deny(missing_docs)]

extern crate alloc;

use crate::capability_diff::CapabilityDiff;
use crate::compat::{CompatibilityDecision, HostEnvironment};
use crate::eval::SkillEvalScore;
use crate::manifest::SkillId;
use crate::package::{SkillPackageDigest32, SkillSecurityState};
use crate::provenance::ProvenanceNode;
use crate::verify::{VerifiedPackage, verify_skill_package};

/// Domain tag for the stable catalog-index digest. Distinct per the
/// `mnemos.d.<area>.v1` scheme so a catalog digest can never collide with a
/// package / signature / compat digest.
const DOMAIN_CATALOG_INDEX: &[u8] = b"mnemos.d.catalog_index.v1";

/// Reason a catalog index entry could not be built from raw package bytes.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum CatalogIndexError {
    /// The package bytes failed [`verify_skill_package`] (bad schema, missing /
    /// tampered signature, hidden permission, incomplete supply chain, ...). A
    /// catalog entry is only a denormalized view of an *already-verified*
    /// package, never a way to admit an unverified one.
    Unverified,
}

impl CatalogIndexError {
    /// Stable, leak-free class label (mirrors the `class_label` convention on
    /// [`crate::verify::VerifyError`] / [`crate::package::SkillSecurityState`]).
    #[must_use]
    pub const fn class_label(&self) -> &'static str {
        match self {
            Self::Unverified => "catalog_index.unverified",
        }
    }
}

/// A denormalized, search-facing view of one verified skill package.
///
/// Built only from a [`VerifiedPackage`] (so a never-verified package can never
/// produce one) plus an off-band `name_hash_32` (the manifest drops the name to
/// a length, so the original name is hashed by the indexer) and three counters
/// the indexer maintains from the registry event stream (#287).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SkillCatalogIndexEntry {
    /// The skill id (newtype over `u16`).
    pub skill: SkillId,
    /// The signed package content digest this entry denormalizes.
    pub package: SkillPackageDigest32,
    /// Hash of the human-facing skill name (the manifest itself never retains
    /// the name string, only its byte length).
    pub name_hash_32: [u8; 32],
    /// Download count — a *weak* popularity signal (a download is not an
    /// install; see [`crate::catalog_counters`]).
    pub downloads_u64: u64,
    /// Verified-install count — a *strong* signal requiring install / eval /
    /// active-trace evidence and excluding revoked installs.
    pub verified_installs_u64: u64,
    /// Active-user count (installs currently in an active-trace state).
    pub active_users_u64: u64,
    /// Eval score (six axes), carried verbatim from the verified package.
    pub eval: SkillEvalScore,
    /// Security state (Unknown ceiling until a sandbox / audit pass raises it).
    pub security: SkillSecurityState,
    /// The compatibility *decision* this entry was indexed under, evaluated
    /// against the indexer's reference host environment.
    pub compatibility: CompatibilityDecision,
    /// The capability diff shown before any use / dry-run / install — present
    /// (not optional) so a card can never hide the permission delta.
    pub capability_diff: CapabilityDiff,
    /// Content-addressed provenance node (single parent or root).
    pub provenance: ProvenanceNode,
}

impl SkillCatalogIndexEntry {
    /// Denormalize an already-[`VerifiedPackage`] into an index entry, baking in
    /// the compatibility decision for the indexer's reference `host`.
    #[must_use]
    pub fn from_verified_package(
        verified: &VerifiedPackage,
        host: &HostEnvironment,
        name_hash_32: [u8; 32],
        downloads_u64: u64,
        verified_installs_u64: u64,
        active_users_u64: u64,
    ) -> Self {
        Self {
            skill: verified.package.skill_id(),
            package: verified.digest,
            name_hash_32,
            downloads_u64,
            verified_installs_u64,
            active_users_u64,
            eval: verified.package.eval,
            security: verified.security,
            compatibility: verified.evaluate_compatibility(host),
            capability_diff: verified.package.capability_diff.clone(),
            provenance: verified.package.provenance,
        }
    }

    /// Build an entry directly from canonical package TOML by running the full
    /// verifier first. A missing or tampered signature surfaces as
    /// [`crate::verify::VerifyError::Signature`] and is collapsed to
    /// [`CatalogIndexError::Unverified`]: the catalog never admits an unverified
    /// package.
    pub fn from_package_toml(
        package_toml: &str,
        host: &HostEnvironment,
        name_hash_32: [u8; 32],
        downloads_u64: u64,
        verified_installs_u64: u64,
        active_users_u64: u64,
    ) -> Result<Self, CatalogIndexError> {
        let verified =
            verify_skill_package(package_toml).map_err(|_| CatalogIndexError::Unverified)?;
        Ok(Self::from_verified_package(
            &verified,
            host,
            name_hash_32,
            downloads_u64,
            verified_installs_u64,
            active_users_u64,
        ))
    }

    /// Return a copy of this entry with its three counters replaced by the
    /// values an event-stream fold ([`crate::catalog_counters`])
    /// produced. The identity (skill / package / eval / security / compat /
    /// capability / provenance) is untouched.
    #[must_use]
    pub fn with_counters(
        mut self,
        downloads_u64: u64,
        verified_installs_u64: u64,
        active_users_u64: u64,
    ) -> Self {
        self.downloads_u64 = downloads_u64;
        self.verified_installs_u64 = verified_installs_u64;
        self.active_users_u64 = active_users_u64;
        self
    }

    /// Stable content digest over the full entry (identity + counters). The same
    /// inputs always hash to the same value; changing any counter or identity
    /// field changes the digest. All parts are fixed-width, so the no-separator
    /// `blake2b_256` framing is unambiguous.
    #[must_use]
    pub fn index_digest(&self) -> [u8; 32] {
        let skill = self.skill.0.to_le_bytes();
        let downloads = self.downloads_u64.to_le_bytes();
        let verified = self.verified_installs_u64.to_le_bytes();
        let active = self.active_users_u64.to_le_bytes();
        let mut axes = [0u8; 12];
        let a = self.eval.axes();
        let mut i = 0;
        while i < 6 {
            let le = a[i].to_le_bytes();
            axes[i * 2] = le[0];
            axes[i * 2 + 1] = le[1];
            i += 1;
        }
        let security = [self.security as u8];
        let compat = [self.compatibility as u8];
        let provenance = self.provenance.digest_32();
        crate::package::blake2b_256(&[
            DOMAIN_CATALOG_INDEX,
            &skill,
            self.package.as_bytes(),
            &self.name_hash_32,
            &downloads,
            &verified,
            &active,
            &axes,
            &security,
            &compat,
            self.capability_diff.human_digest_32(),
            &provenance,
        ])
    }

    /// Always `false`: a catalog entry is a discovery view, never the source of
    /// executable permission truth. Use / install authority lives in the signed
    /// package + capability approval + dry-run + the install plan.
    #[must_use]
    pub const fn is_permission_truth_source(&self) -> bool {
        false
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use crate::compat::MnemosVersion;
    use crate::package_toml::to_hex;
    use crate::verify::sample_valid_package_toml;

    fn host() -> HostEnvironment {
        HostEnvironment {
            mnemos_version: MnemosVersion::new(0, 2, 0),
            chain_env_hash_32: [0xC0; 32],
            os_gpu_hash_32: [0x05; 32],
            toolchain_hash_32: [0x70; 32],
            model_provider_hash_32: [0x30; 32],
        }
    }

    #[test]
    fn entry_from_package() {
        let toml = sample_valid_package_toml();
        let entry = SkillCatalogIndexEntry::from_package_toml(&toml, &host(), [0x99; 32], 12, 4, 2)
            .expect("valid package must index");
        assert_eq!(entry.skill.0, 42);
        assert_eq!(entry.downloads_u64, 12);
        assert_eq!(entry.verified_installs_u64, 4);
        assert_eq!(entry.active_users_u64, 2);
        assert_eq!(entry.security, SkillSecurityState::Unknown);
    }

    #[test]
    fn entry_from_event_stream() {
        let toml = sample_valid_package_toml();
        let base = SkillCatalogIndexEntry::from_package_toml(&toml, &host(), [0x99; 32], 0, 0, 0)
            .expect("valid package must index");
        // An event-stream fold updates only the counters; identity is stable.
        let folded = base.clone().with_counters(100, 5, 3);
        assert_eq!(folded.downloads_u64, 100);
        assert_eq!(folded.verified_installs_u64, 5);
        assert_eq!(folded.active_users_u64, 3);
        assert_eq!(folded.skill, base.skill);
        assert_eq!(folded.package, base.package);
    }

    #[test]
    fn missing_signature_reject() {
        let toml = sample_valid_package_toml();
        // Mutate the tests_digest in the TOML — this breaks the content digest,
        // so the bound signature no longer verifies (VerifyError::Signature).
        let tampered = toml.replace(&to_hex(&[0x7E; 32]), &to_hex(&[0x7D; 32]));
        assert_ne!(tampered, toml);
        assert_eq!(
            SkillCatalogIndexEntry::from_package_toml(&tampered, &host(), [0x99; 32], 0, 0, 0),
            Err(CatalogIndexError::Unverified),
        );
    }

    #[test]
    fn install_receipt_not_inferred() {
        let toml = sample_valid_package_toml();
        // High downloads but zero verified installs: downloads never imply an
        // install, and the entry carries no install-state / receipt field.
        let entry =
            SkillCatalogIndexEntry::from_package_toml(&toml, &host(), [0x99; 32], 1000, 0, 0)
                .expect("valid package must index");
        assert_eq!(entry.verified_installs_u64, 0);
        assert_eq!(entry.active_users_u64, 0);
        assert!(!entry.is_permission_truth_source());
    }

    #[test]
    fn index_digest_stable() {
        let toml = sample_valid_package_toml();
        let a = SkillCatalogIndexEntry::from_package_toml(&toml, &host(), [0x99; 32], 10, 2, 1)
            .expect("index");
        let b = SkillCatalogIndexEntry::from_package_toml(&toml, &host(), [0x99; 32], 10, 2, 1)
            .expect("index");
        assert_eq!(a.index_digest(), b.index_digest());
        let changed = a.clone().with_counters(11, 2, 1);
        assert_ne!(a.index_digest(), changed.index_digest());
    }
}
