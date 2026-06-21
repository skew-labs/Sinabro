//! `mnemos-e-skill::verify` — atom #252 · D.0.11 — the package verifier API.
//!
//! ## Canonical OUT (§252)
//!
//! [`verify_skill_package`] takes the canonical package bytes and returns a
//! typed [`SkillPackageV1`] + its [`SkillPackageDigest32`] **only after**
//! every precheck passes (§252 광기): schema, no-commerce, manifest,
//! capability diff, eval, provenance, supply-chain receipt, compatibility,
//! content digest, and author signature. Any failure returns a stable
//! [`VerifyError`] (the error taxonomy) — never a panic.
//!
//! The base manifest is parsed **only** by [`load_manifest`] (the §242
//! invariant): the verifier re-serializes the `[manifest]` section and
//! hands it to `load_manifest`, never re-implementing manifest parsing.
//!
//! Verification is offline and allocation-bounded for small metadata — the
//! §254 bench enforces the p95 budget.

#![deny(missing_docs)]

use mnemos_c_walrus::codec::SignatureBytes;
use mnemos_d_move::types::SuiAddress;
use mnemos_m_agent::tool_schema::ToolId;

use crate::capability_diff::CapabilityDiff;
use crate::compat::{HostEnvironment, MnemosVersion, SkillCompatibility, VersionReq};
use crate::eval::SkillEvalScore;
use crate::manifest::load_manifest;
use crate::package::{
    SkillPackageDigest32, SkillPackageV1, SkillSecurityState, SkillSupplyChainReceipt,
};
use crate::package_policy::{no_commerce_policy_hash, scan_no_commerce};
use crate::package_toml::{
    PackageTomlError, RawPackage, hex_to_array, parse_package, parse_version,
};
use crate::provenance::ProvenanceNode;
use crate::signature::SkillPackageSignature;

/// Maximum package-metadata byte length the verifier accepts (§254 "max
/// metadata size"). A package whose canonical TOML exceeds this is rejected
/// before any parsing work, bounding verify cost so search/ranking can call
/// it repeatedly without a DoS surface. 64 KiB is generous for metadata
/// (the bundle artifacts themselves are referenced by hash, not inlined).
pub const MAX_PACKAGE_METADATA_BYTES: usize = 64 * 1024;

// ===========================================================================
// 1. VerifyError — the §252 error taxonomy
// ===========================================================================

/// Why [`verify_skill_package`] rejected a package. Payload-light + `Copy`
/// so a canary in the input cannot escape via the error channel.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
#[non_exhaustive]
pub enum VerifyError {
    /// The package metadata exceeds [`MAX_PACKAGE_METADATA_BYTES`].
    TooLarge,
    /// TOML schema failure (unknown key, duplicate, parse error).
    Schema,
    /// A hex / version field was malformed.
    Encoding,
    /// The package carries a commerce-shaped field (G-D-NO-COMMERCE).
    Commerce,
    /// The wrapped manifest failed `load_manifest` validation.
    Manifest,
    /// The capability diff declares a tool the manifest did not.
    CapabilityToolMismatch,
    /// The capability diff is internally inconsistent (hidden permission).
    CapabilityHidden,
    /// The eval score is invalid (axis > 10_000 or zero command hash).
    EvalInvalid,
    /// The provenance node is malformed (missing author, self-parent, …).
    ProvenanceInvalid,
    /// The supply-chain receipt is incomplete (zero hash or networked build).
    SupplyChainIncomplete,
    /// The package security state is not installable (quarantined/revoked).
    TrustBoundary,
    /// The author signature does not bind the content digest.
    Signature,
}

impl VerifyError {
    /// Stable class label namespaced under `verify.*`.
    #[inline]
    #[must_use]
    pub const fn class_label(&self) -> &'static str {
        match self {
            Self::TooLarge => "verify.too_large",
            Self::Schema => "verify.schema",
            Self::Encoding => "verify.encoding",
            Self::Commerce => "verify.commerce",
            Self::Manifest => "verify.manifest",
            Self::CapabilityToolMismatch => "verify.capability_tool_mismatch",
            Self::CapabilityHidden => "verify.capability_hidden",
            Self::EvalInvalid => "verify.eval_invalid",
            Self::ProvenanceInvalid => "verify.provenance_invalid",
            Self::SupplyChainIncomplete => "verify.supply_chain_incomplete",
            Self::TrustBoundary => "verify.trust_boundary",
            Self::Signature => "verify.signature",
        }
    }
}

impl From<PackageTomlError> for VerifyError {
    fn from(e: PackageTomlError) -> Self {
        match e {
            PackageTomlError::Toml | PackageTomlError::Serialize => Self::Schema,
            PackageTomlError::Hex | PackageTomlError::Version => Self::Encoding,
        }
    }
}

// ===========================================================================
// 2. VerifiedPackage — the typed verifier output
// ===========================================================================

/// A package that has passed every [`verify_skill_package`] precheck. Holds
/// the §252 canonical outputs (`package` + `digest`) plus the parsed
/// compatibility constraint and the derived security state used by the
/// trust-boundary precheck.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerifiedPackage {
    /// The typed signed package (§4.1).
    pub package: SkillPackageV1,
    /// The canonical content address of the package.
    pub digest: SkillPackageDigest32,
    /// The parsed compatibility constraint (bound into `digest`).
    pub compatibility: SkillCompatibility,
    /// Derived security state — `Unknown` for a freshly verified package
    /// (sandbox/audit promotion is a later WP).
    pub security: SkillSecurityState,
}

impl VerifiedPackage {
    /// Evaluate this package's compatibility against a concrete host.
    #[must_use]
    pub fn evaluate_compatibility(
        &self,
        host: &HostEnvironment,
    ) -> crate::compat::CompatibilityDecision {
        self.compatibility.evaluate(host)
    }
}

// ===========================================================================
// 3. verify_skill_package — the §252 entry point
// ===========================================================================

/// Verify a canonical package TOML and return the typed package + digest.
/// See the module docs for the precheck order. Offline + panic-free.
pub fn verify_skill_package(package_bytes: &str) -> Result<VerifiedPackage, VerifyError> {
    // (0) size budget: reject oversized metadata before any work (§254).
    if package_bytes.len() > MAX_PACKAGE_METADATA_BYTES {
        return Err(VerifyError::TooLarge);
    }

    // (1) schema: parse + unknown/duplicate-key reject (CRLF-normalized).
    let raw: RawPackage = parse_package(package_bytes)?;

    // (2) no-commerce: scan the ORIGINAL bytes (catches commerce keys even
    //     inside the [extensions] escape hatch).
    if scan_no_commerce(package_bytes).is_err() {
        return Err(VerifyError::Commerce);
    }

    // (3) manifest: `load_manifest` is the only parser — re-serialize JUST
    //     the [manifest] section and feed it through, so Stage D never
    //     re-implements base-manifest parsing (§242 invariant).
    let manifest_section_toml = toml::to_string(&raw.manifest).map_err(|_| VerifyError::Schema)?;
    let manifest = load_manifest(&manifest_section_toml).map_err(|_| VerifyError::Manifest)?;

    // (4) capability diff: derive (a_capabilities + human_digest are NOT
    //     author-supplied, so a hidden permission is unencodable).
    let diff_tool_ids: Vec<ToolId> = raw
        .capability_diff
        .tool_ids
        .iter()
        .map(|&t| ToolId(t))
        .collect();
    // Every diff tool must be declared by the manifest.
    for tool in &diff_tool_ids {
        if !manifest.tool_ids().contains(tool) {
            return Err(VerifyError::CapabilityToolMismatch);
        }
    }
    // The canonical TOML stores only the masks + tool ids; `CapabilityDiff::new`
    // DERIVES `a_capabilities` and `human_digest_32`, so a hidden permission
    // is unrepresentable here (prevention, not detection). The consistency
    // check below is therefore structurally always-true for this construction
    // path — it is kept as defense-in-depth for any future path that builds a
    // `CapabilityDiff` from untrusted fields rather than via `new`.
    let capability_diff = CapabilityDiff::new(
        raw.capability_diff.added_mask,
        raw.capability_diff.removed_mask,
        diff_tool_ids,
    );
    if !capability_diff.is_consistent() {
        return Err(VerifyError::CapabilityHidden);
    }

    // (5) eval.
    let eval = SkillEvalScore {
        rust_u16: raw.eval.rust,
        move_u16: raw.eval.move_axis,
        prover_u16: raw.eval.prover,
        gas_u16: raw.eval.gas,
        security_u16: raw.eval.security,
        korean_u16: raw.eval.korean,
        reproducible_command_hash_32: hex_to_array::<32>(&raw.eval.reproducible_command_hash)?,
    };
    if !eval.is_valid() {
        return Err(VerifyError::EvalInvalid);
    }

    // (6) provenance.
    let parent = match &raw.provenance.parent {
        Some(hex) => Some(SkillPackageDigest32::new(hex_to_array::<32>(hex)?)),
        None => None,
    };
    let provenance = ProvenanceNode {
        skill: manifest.id(),
        package: SkillPackageDigest32::new(hex_to_array::<32>(&raw.provenance.package)?),
        parent,
        author: SuiAddress::new(hex_to_array::<32>(&raw.provenance.author)?),
        provenance_depth_u16: raw.provenance.depth,
    };
    if !provenance.is_well_formed() {
        return Err(VerifyError::ProvenanceInvalid);
    }

    // (7) supply-chain.
    let supply_chain = SkillSupplyChainReceipt {
        sbom_hash_32: hex_to_array::<32>(&raw.supply_chain.sbom_hash)?,
        reproducible_build_hash_32: hex_to_array::<32>(&raw.supply_chain.reproducible_build_hash)?,
        dependency_lock_hash_32: hex_to_array::<32>(&raw.supply_chain.dependency_lock_hash)?,
        deny_audit_hash_32: hex_to_array::<32>(&raw.supply_chain.deny_audit_hash)?,
        license_hash_32: hex_to_array::<32>(&raw.supply_chain.license_hash)?,
        build_script_network_denied: raw.supply_chain.build_script_network_denied,
    };
    if !supply_chain.is_complete() {
        return Err(VerifyError::SupplyChainIncomplete);
    }

    // (8) compatibility (bound into the content digest).
    let compatibility = SkillCompatibility {
        version_req: VersionReq {
            min: {
                let (a, b, c) = parse_version(&raw.compatibility.version_min)?;
                MnemosVersion::new(a, b, c)
            },
            max: {
                let (a, b, c) = parse_version(&raw.compatibility.version_max)?;
                MnemosVersion::new(a, b, c)
            },
        },
        chain_env_hash_32: hex_to_array::<32>(&raw.compatibility.chain_env_hash)?,
        os_gpu_hash_32: hex_to_array::<32>(&raw.compatibility.os_gpu_hash)?,
        toolchain_hash_32: hex_to_array::<32>(&raw.compatibility.toolchain_hash)?,
        model_provider_hash_32: hex_to_array::<32>(&raw.compatibility.model_provider_hash)?,
    };
    // Reject a malformed inverted range (min > max) fail-closed — such a
    // range is unsatisfiable for every version and should never ship.
    if compatibility.version_req.min > compatibility.version_req.max {
        return Err(VerifyError::Encoding);
    }

    // (9) digests + signature bytes.
    let tests_digest_32 = hex_to_array::<32>(&raw.digests.tests_digest)?;
    let artifact_digest_32 = hex_to_array::<32>(&raw.digests.artifact_digest)?;
    let signature =
        SkillPackageSignature::new(SignatureBytes(hex_to_array::<64>(&raw.signature.bytes)?));

    let package = SkillPackageV1 {
        manifest,
        capability_diff,
        eval,
        provenance,
        supply_chain,
        tests_digest_32,
        artifact_digest_32,
        signature,
    };

    // (10) content digest binds compatibility + no-commerce policy.
    let digest = package.content_digest(no_commerce_policy_hash(), compatibility.digest_32());

    // (11) trust-boundary precheck: a freshly verified package is Unknown
    //      (no sandbox/audit yet); Unknown is installable. A bare signature
    //      never promotes to SandboxPass/AuditPass.
    let security = SkillSecurityState::Unknown;
    if !security.is_installable() {
        return Err(VerifyError::TrustBoundary);
    }

    // (12) author signature over the content digest (offline).
    if !package.signature.verify(package.provenance.author, digest) {
        return Err(VerifyError::Signature);
    }

    Ok(VerifiedPackage {
        package,
        digest,
        compatibility,
        security,
    })
}

/// Build a canonical, signed, **valid** package TOML. Shared by the unit
/// tests, the malicious-fixture tests (#250), the property corpus (#253),
/// and the verify bench (#254) so all four exercise one source-of-truth
/// fixture (no drift). The signature is computed AFTER the content digest,
/// so the result is a genuinely valid package, not a hand-faked one.
#[doc(hidden)]
#[must_use]
pub fn sample_valid_package_toml() -> String {
    sample_valid_package_toml_impl()
}

#[allow(clippy::expect_used)]
fn sample_valid_package_toml_impl() -> String {
    use crate::package_toml::to_hex;
    // Build the typed package first, derive the digest + signature, then
    // render the canonical TOML with the real signature bytes.
    let manifest = load_manifest(
        "id = 42\nname = \"echo\"\nversion = 1\ntool_ids = [1, 2, 3]\ntoken_cost_estimate = 250\n",
    )
    .expect("manifest");
    let diff = CapabilityDiff::new(
        crate::capability_diff::SkillRuntimePermission::MemoryRead.mask_bit(),
        0,
        vec![ToolId(1)],
    );
    let eval = SkillEvalScore {
        rust_u16: 9_800,
        move_u16: 10_000,
        prover_u16: 10_000,
        gas_u16: 9_500,
        security_u16: 10_000,
        korean_u16: 9_000,
        reproducible_command_hash_32: crate::eval::reproducible_command_hash(&["cargo test"]),
    };
    let author = SuiAddress::new([0x11; 32]);
    let provenance = ProvenanceNode {
        skill: manifest.id(),
        package: SkillPackageDigest32::new([0xA0; 32]),
        parent: None,
        author,
        provenance_depth_u16: 0,
    };
    let supply_chain = SkillSupplyChainReceipt {
        sbom_hash_32: [1; 32],
        reproducible_build_hash_32: [2; 32],
        dependency_lock_hash_32: [3; 32],
        deny_audit_hash_32: [4; 32],
        license_hash_32: [5; 32],
        build_script_network_denied: true,
    };
    let compatibility = SkillCompatibility {
        version_req: VersionReq {
            min: MnemosVersion::new(0, 1, 0),
            max: MnemosVersion::new(0, 3, 0),
        },
        chain_env_hash_32: [0xC0; 32],
        os_gpu_hash_32: [0x05; 32],
        toolchain_hash_32: [0x70; 32],
        model_provider_hash_32: [0x30; 32],
    };
    let tests_digest_32 = [0x7E; 32];
    let artifact_digest_32 = [0xAF; 32];
    let unsigned = SkillPackageV1 {
        manifest,
        capability_diff: diff,
        eval,
        provenance,
        supply_chain,
        tests_digest_32,
        artifact_digest_32,
        signature: SkillPackageSignature::new(SignatureBytes([0u8; 64])),
    };
    let digest = unsigned.content_digest(no_commerce_policy_hash(), compatibility.digest_32());
    let sig = SkillPackageSignature::bind(author, digest);
    let sig_hex = to_hex(sig.as_signature_bytes().as_bytes());

    let h = |b: &[u8; 32]| to_hex(b);
    format!(
        "[manifest]\nid = 42\nname = \"echo\"\nversion = 1\ntool_ids = [1, 2, 3]\ntoken_cost_estimate = 250\n\n\
             [capability_diff]\nadded_mask = {added}\nremoved_mask = 0\ntool_ids = [1]\n\n\
             [eval]\nrust = 9800\nmove = 10000\nprover = 10000\ngas = 9500\nsecurity = 10000\nkorean = 9000\nreproducible_command_hash = \"{rch}\"\n\n\
             [provenance]\nskill = 42\npackage = \"{pkg}\"\nauthor = \"{author}\"\ndepth = 0\n\n\
             [supply_chain]\nsbom_hash = \"{sbom}\"\nreproducible_build_hash = \"{rbh}\"\ndependency_lock_hash = \"{dlh}\"\ndeny_audit_hash = \"{dah}\"\nlicense_hash = \"{lh}\"\nbuild_script_network_denied = true\n\n\
             [compatibility]\nversion_min = \"0.1.0\"\nversion_max = \"0.3.0\"\nchain_env_hash = \"{ceh}\"\nos_gpu_hash = \"{ogh}\"\ntoolchain_hash = \"{tch}\"\nmodel_provider_hash = \"{mph}\"\n\n\
             [digests]\ntests_digest = \"{td}\"\nartifact_digest = \"{ad}\"\n\n\
             [signature]\nbytes = \"{sig_hex}\"\n",
        added = crate::capability_diff::SkillRuntimePermission::MemoryRead.mask_bit(),
        rch = h(&crate::eval::reproducible_command_hash(&["cargo test"])),
        pkg = h(&[0xA0; 32]),
        author = h(&[0x11; 32]),
        sbom = h(&[1; 32]),
        rbh = h(&[2; 32]),
        dlh = h(&[3; 32]),
        dah = h(&[4; 32]),
        lh = h(&[5; 32]),
        ceh = h(&[0xC0; 32]),
        ogh = h(&[0x05; 32]),
        tch = h(&[0x70; 32]),
        mph = h(&[0x30; 32]),
        td = h(&[0x7E; 32]),
        ad = h(&[0xAF; 32]),
    )
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use crate::package_toml::to_hex;

    fn signed_fixture() -> String {
        sample_valid_package_toml()
    }

    #[test]
    fn valid_package_verifies() {
        let bytes = signed_fixture();
        let verified = verify_skill_package(&bytes).expect("valid package must verify");
        assert_eq!(verified.package.skill_id().0, 42);
        assert_eq!(verified.security, SkillSecurityState::Unknown);
    }

    #[test]
    fn tampered_signature_rejected() {
        let bytes = signed_fixture();
        // Flip the package digest by mutating the tests_digest in the TOML.
        let tampered = bytes.replace(&to_hex(&[0x7E; 32]), &to_hex(&[0x7D; 32]));
        assert_ne!(tampered, bytes);
        assert_eq!(
            verify_skill_package(&tampered),
            Err(VerifyError::Signature),
            "content mutation must break the signature"
        );
    }

    #[test]
    fn commerce_field_rejected() {
        let bytes = format!("{}\n[extensions]\nprice = 100\n", signed_fixture());
        assert_eq!(verify_skill_package(&bytes), Err(VerifyError::Commerce));
    }

    #[test]
    fn unknown_section_rejected_as_schema() {
        let bytes = format!("{}\n[mystery]\nx = 1\n", signed_fixture());
        assert_eq!(verify_skill_package(&bytes), Err(VerifyError::Schema));
    }

    #[test]
    fn incomplete_supply_chain_rejected() {
        let bytes = signed_fixture().replace(
            "build_script_network_denied = true",
            "build_script_network_denied = false",
        );
        assert_eq!(
            verify_skill_package(&bytes),
            Err(VerifyError::SupplyChainIncomplete)
        );
    }

    #[test]
    fn capability_tool_not_in_manifest_rejected() {
        // Manifest declares tools [1,2,3]; claim tool 2 is fine, but inject
        // a diff tool 3 that is declared → still fine. Use an undeclared
        // path by editing the manifest to drop tool 1 while the diff keeps it.
        let bytes = signed_fixture().replace("tool_ids = [1, 2, 3]", "tool_ids = [2, 3]");
        // The signature no longer matches (manifest changed) — but the tool
        // mismatch is checked BEFORE the signature, so we get the mismatch.
        assert_eq!(
            verify_skill_package(&bytes),
            Err(VerifyError::CapabilityToolMismatch)
        );
    }

    #[test]
    fn eval_over_cap_rejected() {
        let bytes = signed_fixture().replace("rust = 9800", "rust = 10001");
        assert_eq!(verify_skill_package(&bytes), Err(VerifyError::EvalInvalid));
    }

    #[test]
    fn inverted_version_range_rejected() {
        // version_min > version_max is unsatisfiable — reject fail-closed.
        let bytes = signed_fixture().replace("version_min = \"0.1.0\"", "version_min = \"9.9.9\"");
        assert_eq!(verify_skill_package(&bytes), Err(VerifyError::Encoding));
    }

    #[test]
    fn oversized_metadata_rejected() {
        // A valid package padded past the size budget inside the extensions
        // table is rejected before parsing.
        let mut bytes = signed_fixture();
        bytes.push_str("\n[extensions]\nx_pad = \"");
        bytes.push_str(&"a".repeat(MAX_PACKAGE_METADATA_BYTES));
        bytes.push_str("\"\n");
        assert!(bytes.len() > MAX_PACKAGE_METADATA_BYTES);
        assert_eq!(verify_skill_package(&bytes), Err(VerifyError::TooLarge));
    }

    #[test]
    fn error_taxonomy_labels_are_namespaced() {
        assert_eq!(VerifyError::Schema.class_label(), "verify.schema");
        assert_eq!(VerifyError::Signature.class_label(), "verify.signature");
        assert_eq!(VerifyError::Commerce.class_label(), "verify.commerce");
        assert_eq!(VerifyError::TooLarge.class_label(), "verify.too_large");
    }
}
