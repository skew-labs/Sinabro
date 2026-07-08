//! `mnemos-e-skill::package_toml` — the canonical TOML
//! schema for [`crate::package::SkillPackageV1`].
//!
//! ## Canonical output types
//!
//! - [`RawPackage`] — the deserialization DTO for the package TOML. Every
//!   section uses `#[serde(deny_unknown_fields)]`, so an unknown production
//!   key rejects at parse time — UNLESS it lives in the explicit
//!   `[extensions]` table (the "extension-prefixed" escape hatch).
//! - [`parse_package`] — CRLF-normalizing parser. `\r\n` is collapsed to
//!   `\n` before parsing, so CRLF and LF inputs produce identical results
//!   (verified by test). Duplicate keys reject (the `toml` parser
//!   errors natively).
//! - [`to_canonical_toml`] — re-serialize a parsed package into the
//!   canonical normal form (fixed section + key order). Re-parsing the
//!   canonical bytes yields the same DTO, and re-serializing yields the
//!   same bytes — so semantically-identical package text has exactly one
//!   canonical encoding (the round-trip criterion).
//!
//! Hex fields are fixed-width lowercase (`[u8; 32]` ⇒ 64 hex chars,
//! `[u8; 64]` ⇒ 128 hex chars); a wrong-width or non-hex value rejects.

#![deny(missing_docs)]

extern crate alloc;

use alloc::string::String;
use alloc::vec::Vec;

use serde::{Deserialize, Serialize};

// ===========================================================================
// 1. PackageTomlError — payload-less parse failure channel
// ===========================================================================

/// Failure modes for [`parse_package`] / [`to_canonical_toml`]. Payload-less
/// so a canary in the input cannot escape through this channel (the
/// `ManifestError` precedent).
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
#[non_exhaustive]
pub enum PackageTomlError {
    /// TOML parse failure, duplicate key, or unknown non-extension field.
    Toml,
    /// A hex field is the wrong width or contains a non-hex character.
    Hex,
    /// A version string is not `major.minor.patch` with `u16` components.
    Version,
    /// Canonical re-serialization failed (should not happen for a parsed
    /// DTO; surfaced rather than panicking).
    Serialize,
}

impl PackageTomlError {
    /// Stable class label namespaced under `package_toml.*`.
    #[inline]
    #[must_use]
    pub const fn class_label(&self) -> &'static str {
        match self {
            Self::Toml => "package_toml.toml",
            Self::Hex => "package_toml.hex",
            Self::Version => "package_toml.version",
            Self::Serialize => "package_toml.serialize",
        }
    }
}

// ===========================================================================
// 2. Hex helpers (fixed width, lowercase, no external crate)
// ===========================================================================

/// Encode bytes as a lowercase hex string.
#[must_use]
pub fn to_hex(bytes: &[u8]) -> String {
    const LUT: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        out.push(LUT[(b >> 4) as usize] as char);
        out.push(LUT[(b & 0x0f) as usize] as char);
    }
    out
}

/// Decode exactly `N` bytes from a lowercase/uppercase hex string. Returns
/// [`PackageTomlError::Hex`] on a wrong-width or non-hex input.
pub fn hex_to_array<const N: usize>(s: &str) -> Result<[u8; N], PackageTomlError> {
    let bytes = s.as_bytes();
    if bytes.len() != N * 2 {
        return Err(PackageTomlError::Hex);
    }
    let mut out = [0u8; N];
    let mut i = 0;
    while i < N {
        let hi = hex_nibble(bytes[i * 2])?;
        let lo = hex_nibble(bytes[i * 2 + 1])?;
        out[i] = (hi << 4) | lo;
        i += 1;
    }
    Ok(out)
}

fn hex_nibble(c: u8) -> Result<u8, PackageTomlError> {
    match c {
        b'0'..=b'9' => Ok(c - b'0'),
        b'a'..=b'f' => Ok(c - b'a' + 10),
        b'A'..=b'F' => Ok(c - b'A' + 10),
        _ => Err(PackageTomlError::Hex),
    }
}

/// Parse a `major.minor.patch` version into a `(u16, u16, u16)` triple.
pub fn parse_version(s: &str) -> Result<(u16, u16, u16), PackageTomlError> {
    let mut parts = s.split('.');
    let major = parts.next().ok_or(PackageTomlError::Version)?;
    let minor = parts.next().ok_or(PackageTomlError::Version)?;
    let patch = parts.next().ok_or(PackageTomlError::Version)?;
    if parts.next().is_some() {
        return Err(PackageTomlError::Version);
    }
    let major = major
        .parse::<u16>()
        .map_err(|_| PackageTomlError::Version)?;
    let minor = minor
        .parse::<u16>()
        .map_err(|_| PackageTomlError::Version)?;
    let patch = patch
        .parse::<u16>()
        .map_err(|_| PackageTomlError::Version)?;
    Ok((major, minor, patch))
}

/// Render a `(u16, u16, u16)` version triple as `major.minor.patch`.
#[must_use]
pub fn render_version(v: (u16, u16, u16)) -> String {
    let mut s = String::new();
    s.push_str(itoa_u16(v.0).as_str());
    s.push('.');
    s.push_str(itoa_u16(v.1).as_str());
    s.push('.');
    s.push_str(itoa_u16(v.2).as_str());
    s
}

fn itoa_u16(mut n: u16) -> String {
    if n == 0 {
        return String::from("0");
    }
    let mut digits: Vec<u8> = Vec::new();
    while n > 0 {
        digits.push(b'0' + (n % 10) as u8);
        n /= 10;
    }
    digits.reverse();
    // digits is ASCII by construction.
    String::from_utf8(digits).unwrap_or_default()
}

// ===========================================================================
// 3. RawPackage DTO (deny_unknown_fields per section; [extensions] escape)
// ===========================================================================

/// Manifest section of the package TOML (fields mirror the A manifest).
///
/// This DTO intentionally duplicates the field set of the private
/// `manifest::RawManifest` (which is not exported). Drift between the two is
/// NOT silent: `verify::verify_skill_package` re-serializes this section and
/// feeds it to the canonical [`crate::manifest::load_manifest`], whose own
/// `#[serde(deny_unknown_fields)]` rejects at runtime if the field sets ever
/// diverge — so `load_manifest` stays the single source of truth for
/// base-manifest parsing (a documented invariant) and any drift fails a test, not a
/// user.
#[derive(Clone, Debug, Deserialize, Serialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct RawManifestSection {
    /// Skill id.
    pub id: u16,
    /// Operator name (measured into `name_len_u8` by `load_manifest`).
    pub name: String,
    /// Manifest version (non-zero).
    pub version: u32,
    /// Declared tool ids.
    pub tool_ids: Vec<u16>,
    /// Operator-declared token-cost estimate.
    pub token_cost_estimate: u32,
}

/// Capability-diff section. `a_capabilities` and `human_digest` are DERIVED
/// (not stored) so the canonical form has exactly one shape per mask.
#[derive(Clone, Debug, Deserialize, Serialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct RawCapabilityDiff {
    /// Added permission mask.
    pub added_mask: u64,
    /// Removed permission mask.
    pub removed_mask: u64,
    /// Declared tool ids surfaced in the diff.
    pub tool_ids: Vec<u16>,
}

/// Eval section (six axes + reproducible command hash hex).
#[derive(Clone, Debug, Deserialize, Serialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct RawEval {
    /// Rust axis.
    pub rust: u16,
    /// Move axis (`move` is a Rust keyword → field renamed).
    #[serde(rename = "move")]
    pub move_axis: u16,
    /// Prover axis.
    pub prover: u16,
    /// Gas axis.
    pub gas: u16,
    /// Security axis.
    pub security: u16,
    /// Korean axis.
    pub korean: u16,
    /// Reproducible-command hash (64 hex chars).
    pub reproducible_command_hash: String,
}

/// Provenance section.
#[derive(Clone, Debug, Deserialize, Serialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct RawProvenance {
    /// Skill id.
    pub skill: u16,
    /// This package digest (64 hex chars).
    pub package: String,
    /// Parent package digest (64 hex chars), omitted for a root.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub parent: Option<String>,
    /// Author address (64 hex chars).
    pub author: String,
    /// Provenance depth.
    pub depth: u16,
}

/// Supply-chain section.
#[derive(Clone, Debug, Deserialize, Serialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct RawSupplyChain {
    /// SBOM hash (64 hex chars).
    pub sbom_hash: String,
    /// Reproducible-build hash (64 hex chars).
    pub reproducible_build_hash: String,
    /// Dependency-lock hash (64 hex chars).
    pub dependency_lock_hash: String,
    /// Deny-audit hash (64 hex chars).
    pub deny_audit_hash: String,
    /// License hash (64 hex chars).
    pub license_hash: String,
    /// Build-script network-denied flag (must be `true` to be trusted).
    pub build_script_network_denied: bool,
}

/// Compatibility section.
#[derive(Clone, Debug, Deserialize, Serialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct RawCompat {
    /// Minimum Mnemos version (`major.minor.patch`).
    pub version_min: String,
    /// Maximum Mnemos version (`major.minor.patch`).
    pub version_max: String,
    /// Chain-env hash (64 hex chars).
    pub chain_env_hash: String,
    /// OS/GPU hash (64 hex chars).
    pub os_gpu_hash: String,
    /// Toolchain hash (64 hex chars).
    pub toolchain_hash: String,
    /// Model/provider hash (64 hex chars).
    pub model_provider_hash: String,
}

/// Digests section (tests + artifact trees).
#[derive(Clone, Debug, Deserialize, Serialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct RawDigests {
    /// Tests-corpus digest (64 hex chars).
    pub tests_digest: String,
    /// Artifact-tree digest (64 hex chars).
    pub artifact_digest: String,
}

/// Signature section.
#[derive(Clone, Debug, Deserialize, Serialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct RawSignature {
    /// Signature bytes (128 hex chars = 64 bytes).
    pub bytes: String,
}

/// The full package DTO. Top-level `#[serde(deny_unknown_fields)]` rejects
/// any unknown section EXCEPT `[extensions]`, the explicit escape hatch.
///
/// `Eq` is intentionally NOT derived: the `extensions` table
/// (`toml::Table`) implements only `PartialEq` (TOML floats are not `Eq`),
/// so `RawPackage` is `PartialEq`-only. The verifier projects this DTO into
/// fully-`Eq` typed structs before any equality is needed downstream.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct RawPackage {
    /// Manifest section.
    pub manifest: RawManifestSection,
    /// Capability-diff section.
    pub capability_diff: RawCapabilityDiff,
    /// Eval section.
    pub eval: RawEval,
    /// Provenance section.
    pub provenance: RawProvenance,
    /// Supply-chain section.
    pub supply_chain: RawSupplyChain,
    /// Compatibility section.
    pub compatibility: RawCompat,
    /// Digests section.
    pub digests: RawDigests,
    /// Signature section.
    pub signature: RawSignature,
    /// Free-form extension table — the ONLY place unknown keys are allowed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub extensions: Option<toml::Table>,
}

// ===========================================================================
// 4. parse_package / to_canonical_toml
// ===========================================================================

/// Parse a package TOML into a [`RawPackage`]. CRLF is normalized to LF
/// first so CRLF and LF inputs are byte-identical to the parser.
pub fn parse_package(text: &str) -> Result<RawPackage, PackageTomlError> {
    let normalized = text.replace("\r\n", "\n");
    toml::from_str(&normalized).map_err(|_| PackageTomlError::Toml)
}

/// Re-serialize a [`RawPackage`] into the canonical normal form. The `toml`
/// serializer emits fields in declaration order, giving a deterministic
/// encoding; re-parsing it yields the same DTO (round-trip stable).
pub fn to_canonical_toml(package: &RawPackage) -> Result<String, PackageTomlError> {
    toml::to_string(package).map_err(|_| PackageTomlError::Serialize)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    fn canonical_fixture() -> String {
        let h32 = "11".repeat(32); // 64 hex chars
        let sig = "22".repeat(64); // 128 hex chars
        format!(
            "[manifest]\n\
             id = 42\n\
             name = \"echo\"\n\
             version = 1\n\
             tool_ids = [1, 2, 3]\n\
             token_cost_estimate = 250\n\n\
             [capability_diff]\n\
             added_mask = 64\n\
             removed_mask = 0\n\
             tool_ids = [1]\n\n\
             [eval]\n\
             rust = 9800\n\
             move = 10000\n\
             prover = 10000\n\
             gas = 9500\n\
             security = 10000\n\
             korean = 9000\n\
             reproducible_command_hash = \"{h32}\"\n\n\
             [provenance]\n\
             skill = 42\n\
             package = \"{h32}\"\n\
             author = \"{h32}\"\n\
             depth = 0\n\n\
             [supply_chain]\n\
             sbom_hash = \"{h32}\"\n\
             reproducible_build_hash = \"{h32}\"\n\
             dependency_lock_hash = \"{h32}\"\n\
             deny_audit_hash = \"{h32}\"\n\
             license_hash = \"{h32}\"\n\
             build_script_network_denied = true\n\n\
             [compatibility]\n\
             version_min = \"0.1.0\"\n\
             version_max = \"0.3.0\"\n\
             chain_env_hash = \"{h32}\"\n\
             os_gpu_hash = \"{h32}\"\n\
             toolchain_hash = \"{h32}\"\n\
             model_provider_hash = \"{h32}\"\n\n\
             [digests]\n\
             tests_digest = \"{h32}\"\n\
             artifact_digest = \"{h32}\"\n\n\
             [signature]\n\
             bytes = \"{sig}\"\n"
        )
    }

    #[test]
    fn round_trip_is_canonical() {
        let text = canonical_fixture();
        let p1 = parse_package(&text).expect("fixture parses");
        let canon = to_canonical_toml(&p1).expect("serialize");
        let p2 = parse_package(&canon).expect("canon re-parses");
        assert_eq!(p1, p2, "round-trip must be DTO-stable");
        // Re-serializing the canonical form is byte-identical (normal form).
        let canon2 = to_canonical_toml(&p2).expect("serialize 2");
        assert_eq!(canon, canon2, "canonical bytes must be a fixed point");
    }

    #[test]
    fn crlf_and_lf_are_stable() {
        let lf = canonical_fixture();
        let crlf = lf.replace('\n', "\r\n");
        let p_lf = parse_package(&lf).expect("lf");
        let p_crlf = parse_package(&crlf).expect("crlf");
        assert_eq!(p_lf, p_crlf, "CRLF and LF must parse identically");
    }

    #[test]
    fn unknown_prod_key_rejected() {
        let text = canonical_fixture().replace("[manifest]\n", "[manifest]\nsmuggled = \"evil\"\n");
        assert_eq!(parse_package(&text), Err(PackageTomlError::Toml));
    }

    #[test]
    fn extension_table_allowed() {
        let text = format!("{}\n[extensions]\nx_note = \"hi\"\n", canonical_fixture());
        let p = parse_package(&text).expect("extensions allowed");
        assert!(p.extensions.is_some());
    }

    #[test]
    fn duplicate_key_rejected() {
        let text = canonical_fixture().replace("id = 42\n", "id = 42\nid = 43\n");
        assert_eq!(parse_package(&text), Err(PackageTomlError::Toml));
    }

    #[test]
    fn hex_helpers_round_trip_and_reject() {
        let bytes = [0xAB, 0xCD, 0xEF, 0x01];
        assert_eq!(to_hex(&bytes), "abcdef01");
        assert_eq!(hex_to_array::<4>("abcdef01"), Ok(bytes));
        // Wrong width.
        assert_eq!(hex_to_array::<4>("abcd"), Err(PackageTomlError::Hex));
        // Non-hex char.
        assert_eq!(hex_to_array::<4>("abcdefgg"), Err(PackageTomlError::Hex));
    }

    #[test]
    fn version_round_trips() {
        assert_eq!(parse_version("0.3.12"), Ok((0, 3, 12)));
        assert_eq!(render_version((0, 3, 12)), "0.3.12");
        assert_eq!(parse_version("1.2"), Err(PackageTomlError::Version));
        assert_eq!(parse_version("1.2.3.4"), Err(PackageTomlError::Version));
        assert_eq!(parse_version("a.b.c"), Err(PackageTomlError::Version));
    }
}
