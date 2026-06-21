//! `mnemos-e-skill::package` — atom #242 · D.0.1 — `SkillPackageV1`
//! wrapper over the A `SkillManifest`, plus the supporting content-digest
//! spine shared across the D-WP-01A signed-package surface.
//!
//! ## Canonical OUT (§4.1 — ATOM_PLAN line 207-224)
//!
//! - [`SkillPackageV1`] — the signed-package aggregate. It **wraps** the
//!   A [`SkillManifest`] (atom #39 · E.0.1) verbatim; it does NOT replace
//!   it and never re-parses the base manifest fields. [`load_manifest`]
//!   stays the only parser for the base manifest (§1 reuse invariant).
//! - [`SkillPackageDigest32`] — `#[repr(transparent)]` 32-byte content
//!   address of a package (Blake2b-256 of the canonical content preimage,
//!   signature excluded). Two packages with byte-identical content map to
//!   one digest; any field change moves the digest.
//! - [`SkillSecurityState`] — §4.1 5-variant `#[repr(u8)]` trust-state
//!   label `{Unknown=1, SandboxPass=2, AuditPass=3, Quarantined=4,
//!   Revoked=5}`. A bare signature never grants `AuditPass`/`SandboxPass`;
//!   those require the WASM-sandbox / audit WPs (#256+). Stage D
//!   D-WP-01A only ever derives `Unknown` for a freshly-verified package.
//! - [`SkillSupplyChainReceipt`] — §4.1 supply-chain evidence: SBOM hash,
//!   reproducible-build hash, dependency-lock hash, deny-audit hash,
//!   license hash, and the `build_script_network_denied` flag. A signed
//!   package is **not** trusted unless this receipt is present and the
//!   build-script network flag is denied.
//!
//! ## Content-digest spine
//!
//! [`blake2b_256`] is the one crate-internal Blake2b-256 helper consumed
//! by every `*_digest_32` derivation in this crate (matching the k-devex
//! `stage_c_ceremony::transcript_hash` preimage/finalize pattern). Each
//! digestable type contributes a fixed-layout 32-byte sub-digest under a
//! distinct domain tag so a value in one position can never alias a value
//! in another (cross-language schema-lock discipline, codification #1).
//!
//! ## No-commerce + offline boundary
//!
//! Nothing in this module carries a price, checkout, revenue, royalty, or
//! payment field (G-D-NO-COMMERCE). The signature is verified **offline**
//! and exports no secret (G-D-SIGNATURE); see [`crate::signature`].

#![deny(missing_docs)]

extern crate alloc;

use alloc::vec::Vec;

use blake2::{Blake2b, Digest, digest::consts::U32};

use crate::capability_diff::CapabilityDiff;
use crate::eval::SkillEvalScore;
use crate::manifest::{SkillId, SkillManifest};
use crate::provenance::ProvenanceNode;
use crate::signature::SkillPackageSignature;

// ===========================================================================
// 1. Domain tags — one per digestable position (schema-lock discipline)
// ===========================================================================

/// Domain tag for the package-level content digest ([`SkillPackageV1::content_digest`]).
pub(crate) const DOMAIN_PACKAGE: &[u8] = b"mnemos.d.skill_package.v1";
/// Domain tag for the manifest sub-digest folded into the package digest.
pub(crate) const DOMAIN_MANIFEST: &[u8] = b"mnemos.d.skill_manifest.v1";
/// Domain tag for the supply-chain receipt sub-digest.
pub(crate) const DOMAIN_SUPPLY_CHAIN: &[u8] = b"mnemos.d.supply_chain.v1";

// ===========================================================================
// 2. blake2b_256 — the one crate-internal content-hash helper
// ===========================================================================

/// Blake2b-256 over the concatenation of `parts`, returned as a fixed
/// 32-byte array. This mirrors the k-devex `stage_c_ceremony::transcript_hash`
/// pattern (`Blake2b::<U32>::new(); update(preimage); finalize().into()`) and
/// is the single hashing surface for every `*_digest_32` field in this crate.
///
/// # Caller framing contract (no inter-part length framing here)
///
/// This helper concatenates `parts` with NO separators, so the caller MUST
/// make the concatenation unambiguous to avoid a boundary-shifting collision
/// (`["ab","c"]` vs `["a","bc"]`). Every caller in this crate satisfies this
/// by construction in one of two ways:
/// 1. `parts[0]` is a fixed, compile-time-constant domain tag (distinct per
///    digest position) AND every remaining part is a FIXED-WIDTH 32-byte
///    array (e.g. [`SkillPackageV1::content_digest`], [`SkillPackageSignature::bind`]).
///    Fixed widths ⇒ the byte split is unique. The constant domain tag also
///    never collides across positions because each position uses a distinct
///    constant.
/// 2. `parts[0]` is a fixed domain tag and `parts[1]` is a single buffer that
///    is ITSELF length-prefixed internally (counts + per-element lengths) —
///    e.g. [`crate::capability_diff::CapabilityDiff`], [`crate::eval`],
///    [`crate::bundle::BundleLayout::artifact_digest_tree`].
///
/// A future caller mixing variable-width parts without internal framing would
/// break this invariant — keep new callers in one of the two shapes above.
#[must_use]
pub(crate) fn blake2b_256(parts: &[&[u8]]) -> [u8; 32] {
    let mut h = Blake2b::<U32>::new();
    for part in parts {
        h.update(part);
    }
    h.finalize().into()
}

/// Fixed-layout binary preimage of an A [`SkillManifest`]. The name string
/// is never present (the manifest only retains `name_len_u8`), so this
/// preimage is operator-name-free by construction. Little-endian for every
/// multi-byte integer; tool ids in declaration order.
#[must_use]
fn manifest_digest(manifest: &SkillManifest) -> [u8; 32] {
    let mut buf: Vec<u8> = Vec::new();
    buf.extend_from_slice(&manifest.id().0.to_le_bytes());
    buf.push(manifest.name_len_u8());
    buf.extend_from_slice(&manifest.version_u32().to_le_bytes());
    buf.extend_from_slice(&manifest.token_cost_estimate_u32().to_le_bytes());
    buf.extend_from_slice(&(manifest.tool_ids().len() as u32).to_le_bytes());
    for tool in manifest.tool_ids() {
        buf.extend_from_slice(&tool.0.to_le_bytes());
    }
    blake2b_256(&[DOMAIN_MANIFEST, &buf])
}

// ===========================================================================
// 3. SkillPackageDigest32 — 32-byte package content address
// ===========================================================================

/// 32-byte content address of a [`SkillPackageV1`]. `#[repr(transparent)]`
/// over `[u8; 32]` ⇒ `size_of::<SkillPackageDigest32>() == 32` byte-exact.
/// Equality / hashing are byte-equal on the array.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
#[repr(transparent)]
pub struct SkillPackageDigest32([u8; 32]);

impl SkillPackageDigest32 {
    /// Wrap 32 raw bytes as a package digest (used by the verifier and by
    /// fixtures; the canonical derivation is [`SkillPackageV1::content_digest`]).
    #[inline]
    #[must_use]
    pub const fn new(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Borrow the underlying 32-byte array.
    #[inline]
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

// ===========================================================================
// 4. SkillSecurityState — §4.1 5-variant trust-state label
// ===========================================================================

/// Security trust-state of a skill package (§4.1). `#[repr(u8)]` 1-byte
/// discriminant. The 5-variant set is pinned by §4.1 (no `#[non_exhaustive]`
/// — the variant set IS the spec). A bare author signature only ever yields
/// [`Self::Unknown`] here — `SandboxPass` / `AuditPass` require the
/// WASM-sandbox (#256+) and audit surfaces, and `Quarantined` / `Revoked`
/// are registry decisions.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
#[repr(u8)]
pub enum SkillSecurityState {
    /// No sandbox / audit evidence yet — the default for a freshly
    /// verified package in D-WP-01A.
    Unknown = 1,
    /// Passed the WASM Tier-2 sandbox dry-run (assigned by a later WP).
    SandboxPass = 2,
    /// Passed an external security audit (assigned by a later WP).
    AuditPass = 3,
    /// Held in quarantine — visible but not installable/usable.
    Quarantined = 4,
    /// Revoked — must not execute even if previously installed.
    Revoked = 5,
}

impl SkillSecurityState {
    /// Stable class label namespaced under `skill_security.*`.
    #[inline]
    #[must_use]
    pub const fn class_label(&self) -> &'static str {
        match self {
            Self::Unknown => "skill_security.unknown",
            Self::SandboxPass => "skill_security.sandbox_pass",
            Self::AuditPass => "skill_security.audit_pass",
            Self::Quarantined => "skill_security.quarantined",
            Self::Revoked => "skill_security.revoked",
        }
    }

    /// `true` iff a package in this state may be installed/enabled. Only
    /// `Quarantined` / `Revoked` are hard-blocked here; trust *promotion*
    /// (granting `SandboxPass`/`AuditPass`) is a later-WP concern.
    #[inline]
    #[must_use]
    pub const fn is_installable(&self) -> bool {
        !matches!(self, Self::Quarantined | Self::Revoked)
    }
}

// ===========================================================================
// 5. SkillSupplyChainReceipt — §4.1 supply-chain evidence
// ===========================================================================

/// Supply-chain evidence bound into a signed package (§4.1). Every hash is
/// a 32-byte content address of the corresponding artifact; an all-zero
/// hash is treated as "absent" by the verifier (G-D-SKILL-SUPPLY-CHAIN).
/// `build_script_network_denied` must be `true` — a package whose build
/// script may reach the network is rejected before catalog index.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub struct SkillSupplyChainReceipt {
    /// Blake2b-256 of the package SBOM.
    pub sbom_hash_32: [u8; 32],
    /// Blake2b-256 of the reproducible-build receipt.
    pub reproducible_build_hash_32: [u8; 32],
    /// Blake2b-256 of the dependency lock (e.g. `Cargo.lock`).
    pub dependency_lock_hash_32: [u8; 32],
    /// Blake2b-256 of the deny/advisory audit record.
    pub deny_audit_hash_32: [u8; 32],
    /// Blake2b-256 of the license manifest.
    pub license_hash_32: [u8; 32],
    /// `true` iff the package build script is proven to make no network
    /// egress. Required to be `true` for a trusted package.
    pub build_script_network_denied: bool,
}

impl SkillSupplyChainReceipt {
    /// `true` iff every supply-chain hash is non-zero AND the build-script
    /// network flag is denied. A package failing this is not catalog-visible.
    #[must_use]
    pub fn is_complete(&self) -> bool {
        self.build_script_network_denied
            && self.sbom_hash_32 != [0u8; 32]
            && self.reproducible_build_hash_32 != [0u8; 32]
            && self.dependency_lock_hash_32 != [0u8; 32]
            && self.deny_audit_hash_32 != [0u8; 32]
            && self.license_hash_32 != [0u8; 32]
    }

    /// 32-byte sub-digest of this receipt, folded into the package digest.
    #[must_use]
    pub(crate) fn digest_32(&self) -> [u8; 32] {
        blake2b_256(&[
            DOMAIN_SUPPLY_CHAIN,
            &self.sbom_hash_32,
            &self.reproducible_build_hash_32,
            &self.dependency_lock_hash_32,
            &self.deny_audit_hash_32,
            &self.license_hash_32,
            &[self.build_script_network_denied as u8],
        ])
    }
}

// ===========================================================================
// 6. SkillPackageV1 — the signed-package aggregate (§4.1 line 207-216)
// ===========================================================================

/// Signed skill package (§4.1). Wraps the A [`SkillManifest`] and binds the
/// capability diff, eval score, provenance node, supply-chain receipt, the
/// tests + artifact digests, and the author signature. The struct shape is
/// exactly §4.1 line 207-216 — 8 fields, no commerce field, no replacement
/// of the base manifest.
///
/// The signature covers the package content digest
/// ([`Self::content_digest`]), which additionally binds the no-commerce
/// policy hash and the compatibility digest (neither of which is a struct
/// field — both are external bindings supplied by the verifier so the
/// struct stays byte-exact to §4.1 while honouring the atom #247 coverage
/// list).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SkillPackageV1 {
    /// Reused A manifest (built only via [`load_manifest`]); never replaced.
    pub manifest: SkillManifest,
    /// Permission diff shown before use/install.
    pub capability_diff: CapabilityDiff,
    /// Reproducible-command-linked eval score.
    pub eval: SkillEvalScore,
    /// Single-parent content-addressed provenance node.
    pub provenance: ProvenanceNode,
    /// SBOM / reproducible-build / dependency / deny / license evidence.
    pub supply_chain: SkillSupplyChainReceipt,
    /// 32-byte digest of the skill test corpus.
    pub tests_digest_32: [u8; 32],
    /// 32-byte digest of the skill artifact tree (bundle root).
    pub artifact_digest_32: [u8; 32],
    /// Author signature over [`Self::content_digest`].
    pub signature: SkillPackageSignature,
}

impl SkillPackageV1 {
    /// Canonical content digest of this package: Blake2b-256 over the
    /// fixed-layout fold of the manifest digest, the capability-diff human
    /// digest, the eval digest, the provenance digest, the supply-chain
    /// digest, the tests + artifact digests, the `no_commerce_policy_hash`,
    /// and the `compat_digest`. The signature itself is excluded (it signs
    /// this digest).
    ///
    /// `no_commerce_policy_hash` and `compat_digest` are passed in by the
    /// verifier ([`crate::verify`]) rather than stored on the struct, so
    /// `SkillPackageV1` stays exactly the §4.1 8-field shape while the
    /// signature still covers compatibility + the no-commerce policy
    /// (atom #247 coverage list).
    #[must_use]
    pub fn content_digest(
        &self,
        no_commerce_policy_hash: [u8; 32],
        compat_digest: [u8; 32],
    ) -> SkillPackageDigest32 {
        let manifest = manifest_digest(&self.manifest);
        let eval = self.eval.digest_32();
        let provenance = self.provenance.digest_32();
        let supply = self.supply_chain.digest_32();
        let digest = blake2b_256(&[
            DOMAIN_PACKAGE,
            &manifest,
            self.capability_diff.human_digest_32(),
            &eval,
            &provenance,
            &supply,
            &self.tests_digest_32,
            &self.artifact_digest_32,
            &no_commerce_policy_hash,
            &compat_digest,
        ]);
        SkillPackageDigest32::new(digest)
    }

    /// The skill id (read through to the wrapped manifest — never a second
    /// source of truth).
    #[inline]
    #[must_use]
    pub const fn skill_id(&self) -> SkillId {
        self.manifest.id()
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use crate::manifest::load_manifest;
    use mnemos_m_agent::tool_schema::ToolId;

    /// A canonical valid manifest fixture, reused across the package tests.
    /// Built only via [`load_manifest`] — there is no other constructor.
    pub(crate) fn fixture_manifest() -> SkillManifest {
        load_manifest(
            "id = 42\nname = \"echo\"\nversion = 1\ntool_ids = [1, 2, 3]\ntoken_cost_estimate = 250\n",
        )
        .expect("fixture manifest must parse")
    }

    #[test]
    fn package_digest_is_32_bytes() {
        assert_eq!(core::mem::size_of::<SkillPackageDigest32>(), 32);
    }

    #[test]
    fn a_manifest_fixture_loads_unchanged_through_wrapper() {
        // §242 test: the wrapped A manifest is byte-identical to a
        // freshly-loaded one — the wrapper never re-parses or mutates it.
        let m1 = fixture_manifest();
        let m2 = fixture_manifest();
        assert_eq!(m1, m2);
        assert_eq!(m1.id(), SkillId(42));
        assert_eq!(m1.tool_ids(), &[ToolId(1), ToolId(2), ToolId(3)]);
    }

    #[test]
    fn manifest_digest_is_name_free_and_stable() {
        let m = fixture_manifest();
        let d1 = manifest_digest(&m);
        let d2 = manifest_digest(&m);
        assert_eq!(d1, d2, "manifest digest must be deterministic");
        // A different manifest moves the digest.
        let other = load_manifest(
            "id = 43\nname = \"echo\"\nversion = 1\ntool_ids = [1, 2, 3]\ntoken_cost_estimate = 250\n",
        )
        .expect("other manifest");
        assert_ne!(manifest_digest(&other), d1, "id change must move digest");
    }

    #[test]
    fn security_state_quarantine_and_revoke_block_install() {
        assert!(SkillSecurityState::Unknown.is_installable());
        assert!(SkillSecurityState::SandboxPass.is_installable());
        assert!(SkillSecurityState::AuditPass.is_installable());
        assert!(!SkillSecurityState::Quarantined.is_installable());
        assert!(!SkillSecurityState::Revoked.is_installable());
        assert_eq!(SkillSecurityState::Unknown as u8, 1);
        assert_eq!(SkillSecurityState::Revoked as u8, 5);
    }

    #[test]
    fn supply_chain_receipt_requires_all_hashes_and_network_denied() {
        let complete = SkillSupplyChainReceipt {
            sbom_hash_32: [1u8; 32],
            reproducible_build_hash_32: [2u8; 32],
            dependency_lock_hash_32: [3u8; 32],
            deny_audit_hash_32: [4u8; 32],
            license_hash_32: [5u8; 32],
            build_script_network_denied: true,
        };
        assert!(complete.is_complete());

        // Missing one hash → incomplete.
        let mut missing = complete;
        missing.sbom_hash_32 = [0u8; 32];
        assert!(!missing.is_complete());

        // Network not denied → incomplete even with all hashes.
        let mut networked = complete;
        networked.build_script_network_denied = false;
        assert!(!networked.is_complete());

        // Sub-digest is deterministic + sensitive to the network flag.
        assert_eq!(complete.digest_32(), complete.digest_32());
        assert_ne!(complete.digest_32(), networked.digest_32());
    }
}
