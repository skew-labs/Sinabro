//! `mnemos-e-skill::compat` — atom #251 · D.0.10 — the compatibility
//! constraint model.
//!
//! ## Canonical OUT (§251, discriminants from §4.4 line 303)
//!
//! - [`CompatibilityDecision`] — §4.4 `{Compatible=1, Warn=2,
//!   Incompatible=3, Unknown=4}`.
//! - [`MnemosVersion`] / [`VersionReq`] — a `major.minor.patch` triple and
//!   an inclusive range, the minimal semver surface (no external crate).
//! - [`SkillCompatibility`] — the constraint a skill places on its host:
//!   a Mnemos version range, a chain-env hash (C `StageCChainEnv` via hash,
//!   §1 reuse), an OS/GPU hash, a toolchain hash, and a model/provider hash.
//! - [`HostEnvironment`] — the concrete host the skill is evaluated against.
//!
//! ## Decision rules (§251 광기)
//!
//! Incompatible skills are **visible but not installable** without explicit
//! override evidence — EXCEPT an unsafe **chain-env mismatch**, which is
//! never overrideable. [`SkillCompatibility::installable`] encodes this:
//! a chain-env mismatch can never be overridden; every other incompatibility
//! can be installed only with `override_evidence == true` (audited).

#![deny(missing_docs)]

extern crate alloc;

use alloc::vec::Vec;

use crate::package::blake2b_256;

/// Domain tag for the compatibility fold digest.
pub(crate) const DOMAIN_COMPAT: &[u8] = b"mnemos.d.compat.v1";

// ===========================================================================
// 1. CompatibilityDecision — §4.4 4-variant decision
// ===========================================================================

/// Compatibility decision for a skill against a host (§4.4). The 4-variant
/// set is pinned by §4.4 (no `#[non_exhaustive]`).
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
#[repr(u8)]
pub enum CompatibilityDecision {
    /// Every constraint is satisfied.
    Compatible = 1,
    /// A non-fatal constraint (OS/GPU, toolchain, model) mismatches —
    /// installable, but the operator should be warned.
    Warn = 2,
    /// A fatal constraint (chain env or version range) mismatches.
    Incompatible = 3,
    /// At least one host field is unknown (all-zero hash); the decision
    /// cannot be made without more host evidence.
    Unknown = 4,
}

// ===========================================================================
// 2. MnemosVersion / VersionReq — minimal semver surface
// ===========================================================================

/// A `major.minor.patch` version triple. Lexicographic ordering on the
/// three components.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash, PartialOrd, Ord)]
pub struct MnemosVersion {
    /// Major component.
    pub major_u16: u16,
    /// Minor component.
    pub minor_u16: u16,
    /// Patch component.
    pub patch_u16: u16,
}

impl MnemosVersion {
    /// Construct a version triple.
    #[inline]
    #[must_use]
    pub const fn new(major_u16: u16, minor_u16: u16, patch_u16: u16) -> Self {
        Self {
            major_u16,
            minor_u16,
            patch_u16,
        }
    }
}

/// An inclusive version range `[min, max]`.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub struct VersionReq {
    /// Inclusive lower bound.
    pub min: MnemosVersion,
    /// Inclusive upper bound.
    pub max: MnemosVersion,
}

impl VersionReq {
    /// `true` iff `v` is within `[min, max]` inclusive.
    #[inline]
    #[must_use]
    pub fn contains(&self, v: MnemosVersion) -> bool {
        self.min <= v && v <= self.max
    }
}

// ===========================================================================
// 3. SkillCompatibility / HostEnvironment
// ===========================================================================

/// The compatibility constraint a skill places on its host (§251).
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub struct SkillCompatibility {
    /// Required Mnemos version range.
    pub version_req: VersionReq,
    /// Required chain-env hash (C `StageCChainEnv` via hash). A mismatch is
    /// unsafe and never overrideable.
    pub chain_env_hash_32: [u8; 32],
    /// Required OS/GPU profile hash (non-fatal mismatch).
    pub os_gpu_hash_32: [u8; 32],
    /// Required toolchain hash (non-fatal mismatch).
    pub toolchain_hash_32: [u8; 32],
    /// Required model/provider hash (non-fatal mismatch).
    pub model_provider_hash_32: [u8; 32],
}

/// The concrete host a skill is evaluated against.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub struct HostEnvironment {
    /// Host Mnemos version.
    pub mnemos_version: MnemosVersion,
    /// Host chain-env hash (all-zero ⇒ unknown).
    pub chain_env_hash_32: [u8; 32],
    /// Host OS/GPU hash (all-zero ⇒ unknown).
    pub os_gpu_hash_32: [u8; 32],
    /// Host toolchain hash (all-zero ⇒ unknown).
    pub toolchain_hash_32: [u8; 32],
    /// Host model/provider hash (all-zero ⇒ unknown).
    pub model_provider_hash_32: [u8; 32],
}

impl SkillCompatibility {
    /// Deterministic compatibility decision against `host` (§251 criterion).
    #[must_use]
    pub fn evaluate(&self, host: &HostEnvironment) -> CompatibilityDecision {
        // Unknown if any required host field is all-zero (not yet probed).
        if host.chain_env_hash_32 == [0u8; 32]
            || host.os_gpu_hash_32 == [0u8; 32]
            || host.toolchain_hash_32 == [0u8; 32]
            || host.model_provider_hash_32 == [0u8; 32]
        {
            return CompatibilityDecision::Unknown;
        }
        // Fatal: chain-env mismatch (unsafe) or version out of range.
        if host.chain_env_hash_32 != self.chain_env_hash_32 {
            return CompatibilityDecision::Incompatible;
        }
        if !self.version_req.contains(host.mnemos_version) {
            return CompatibilityDecision::Incompatible;
        }
        // Non-fatal: OS/GPU, toolchain, model/provider.
        if host.os_gpu_hash_32 != self.os_gpu_hash_32
            || host.toolchain_hash_32 != self.toolchain_hash_32
            || host.model_provider_hash_32 != self.model_provider_hash_32
        {
            return CompatibilityDecision::Warn;
        }
        CompatibilityDecision::Compatible
    }

    /// `true` iff the chain-env constraint is satisfied. A chain-env
    /// mismatch is unsafe and can never be overridden.
    #[inline]
    #[must_use]
    pub fn chain_env_compatible(&self, host: &HostEnvironment) -> bool {
        host.chain_env_hash_32 != [0u8; 32] && host.chain_env_hash_32 == self.chain_env_hash_32
    }

    /// Whether a skill may be installed/enabled on `host`. A
    /// chain-env mismatch is never installable (override ignored). Every
    /// other incompatibility (`Incompatible` via version, or `Unknown`) is
    /// installable only with audited `override_evidence`. `Compatible` and
    /// `Warn` are installable without override.
    #[must_use]
    pub fn installable(&self, host: &HostEnvironment, override_evidence: bool) -> bool {
        if !self.chain_env_compatible(host) {
            return false; // unsafe chain-env mismatch: never overrideable.
        }
        match self.evaluate(host) {
            CompatibilityDecision::Compatible | CompatibilityDecision::Warn => true,
            CompatibilityDecision::Incompatible | CompatibilityDecision::Unknown => {
                override_evidence
            }
        }
    }

    /// 32-byte fold digest, bound into the package content digest so the
    /// signature covers compatibility (atom #247 coverage list).
    #[must_use]
    pub fn digest_32(&self) -> [u8; 32] {
        let mut buf: Vec<u8> = Vec::new();
        buf.extend_from_slice(&self.version_req.min.major_u16.to_le_bytes());
        buf.extend_from_slice(&self.version_req.min.minor_u16.to_le_bytes());
        buf.extend_from_slice(&self.version_req.min.patch_u16.to_le_bytes());
        buf.extend_from_slice(&self.version_req.max.major_u16.to_le_bytes());
        buf.extend_from_slice(&self.version_req.max.minor_u16.to_le_bytes());
        buf.extend_from_slice(&self.version_req.max.patch_u16.to_le_bytes());
        buf.extend_from_slice(&self.chain_env_hash_32);
        buf.extend_from_slice(&self.os_gpu_hash_32);
        buf.extend_from_slice(&self.toolchain_hash_32);
        buf.extend_from_slice(&self.model_provider_hash_32);
        blake2b_256(&[DOMAIN_COMPAT, &buf])
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    fn compat() -> SkillCompatibility {
        SkillCompatibility {
            version_req: VersionReq {
                min: MnemosVersion::new(0, 1, 0),
                max: MnemosVersion::new(0, 3, 0),
            },
            chain_env_hash_32: [0xC0; 32],
            os_gpu_hash_32: [0x05; 32],
            toolchain_hash_32: [0x70; 32],
            model_provider_hash_32: [0x30; 32],
        }
    }

    fn matching_host() -> HostEnvironment {
        HostEnvironment {
            mnemos_version: MnemosVersion::new(0, 2, 0),
            chain_env_hash_32: [0xC0; 32],
            os_gpu_hash_32: [0x05; 32],
            toolchain_hash_32: [0x70; 32],
            model_provider_hash_32: [0x30; 32],
        }
    }

    #[test]
    fn exact_match_is_compatible_and_installable() {
        let c = compat();
        let h = matching_host();
        assert_eq!(c.evaluate(&h), CompatibilityDecision::Compatible);
        assert!(c.installable(&h, false));
    }

    #[test]
    fn semver_range_boundaries() {
        let c = compat();
        let mut h = matching_host();
        h.mnemos_version = MnemosVersion::new(0, 1, 0); // min inclusive
        assert_eq!(c.evaluate(&h), CompatibilityDecision::Compatible);
        h.mnemos_version = MnemosVersion::new(0, 3, 0); // max inclusive
        assert_eq!(c.evaluate(&h), CompatibilityDecision::Compatible);
        h.mnemos_version = MnemosVersion::new(0, 4, 0); // above max
        assert_eq!(c.evaluate(&h), CompatibilityDecision::Incompatible);
        // version-incompatible can be overridden (not a chain mismatch).
        assert!(c.installable(&h, true));
        assert!(!c.installable(&h, false));
    }

    #[test]
    fn chain_env_mismatch_is_never_overrideable() {
        let c = compat();
        let mut h = matching_host();
        h.chain_env_hash_32 = [0xFF; 32]; // wrong chain env
        assert_eq!(c.evaluate(&h), CompatibilityDecision::Incompatible);
        assert!(
            !c.installable(&h, true),
            "chain mismatch must never override"
        );
        assert!(!c.installable(&h, false));
    }

    #[test]
    fn missing_toolchain_is_warn_and_installable() {
        let c = compat();
        let mut h = matching_host();
        h.toolchain_hash_32 = [0x99; 32]; // different toolchain (present)
        assert_eq!(c.evaluate(&h), CompatibilityDecision::Warn);
        assert!(c.installable(&h, false));
    }

    #[test]
    fn unknown_host_field_is_unknown() {
        let c = compat();
        let mut h = matching_host();
        h.os_gpu_hash_32 = [0u8; 32]; // unprobed
        assert_eq!(c.evaluate(&h), CompatibilityDecision::Unknown);
        // Unknown chain env → not chain_env_compatible → never installable.
        let mut h2 = matching_host();
        h2.chain_env_hash_32 = [0u8; 32];
        assert!(!c.installable(&h2, true));
    }

    #[test]
    fn override_audit_path_is_deterministic() {
        let c = compat();
        let mut h = matching_host();
        h.mnemos_version = MnemosVersion::new(1, 0, 0);
        // Deterministic: same inputs, same decision.
        assert_eq!(c.evaluate(&h), c.evaluate(&h));
        assert_eq!(c.evaluate(&h), CompatibilityDecision::Incompatible);
        assert!(c.installable(&h, true));
    }

    #[test]
    fn compat_digest_stable_and_sensitive() {
        let c = compat();
        assert_eq!(c.digest_32(), c.digest_32());
        let mut c2 = c;
        c2.chain_env_hash_32 = [0xC1; 32];
        assert_ne!(c.digest_32(), c2.digest_32());
    }
}
