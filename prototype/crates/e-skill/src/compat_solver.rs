//! `mnemos-e-skill::compat_solver` — the compatibility
//! solver over single skills and skill **bundles**.
//!
//! Reuses the [`SkillCompatibility`] constraint model (its `evaluate` /
//! `installable` already encode the "unsafe chain-env mismatch is never
//! overrideable" rule) and lifts it to a *set*: a bundle is solved as a whole,
//! and one unsafe member blocks the entire bundle ([`solve_bundle`] takes the
//! worst member decision; [`bundle_installable`] requires *every* member to be
//! installable). The toolchain dimension ([`ToolId`]) is folded in by
//! [`solve_with_tools`]: a skill that needs a tool the host does not provide is
//! [`CompatibilityDecision::Incompatible`].
//!
//! The `SkillStarterPack` *type* (a named, hash-bound bundle) is owned by
//! the starter-pack module (`starter_pack.rs`); this solver operates
//! over a plain `&[SkillCompatibility]` set so it can be reused by both the
//! catalog and the starter-pack cluster without minting that type
//! here.

#![deny(missing_docs)]

use mnemos_m_agent::tool_schema::ToolId;

use crate::compat::{CompatibilityDecision, HostEnvironment, SkillCompatibility};

/// Severity rank for aggregating decisions across a bundle. Higher is worse, so
/// `Incompatible` dominates `Unknown` dominates `Warn` dominates `Compatible`.
const fn severity(decision: CompatibilityDecision) -> u8 {
    match decision {
        CompatibilityDecision::Compatible => 0,
        CompatibilityDecision::Warn => 1,
        CompatibilityDecision::Unknown => 2,
        CompatibilityDecision::Incompatible => 3,
    }
}

/// The worse (higher-severity) of two decisions.
const fn worse(a: CompatibilityDecision, b: CompatibilityDecision) -> CompatibilityDecision {
    if severity(a) >= severity(b) { a } else { b }
}

/// Solve a single skill's compatibility against `host`. Pure and
/// deterministic: same inputs always yield the same decision.
#[must_use]
pub fn solve_single(skill: &SkillCompatibility, host: &HostEnvironment) -> CompatibilityDecision {
    skill.evaluate(host)
}

/// Solve a **bundle** as a set: the decision is the worst member decision, so
/// one unsafe member (chain-env mismatch, version out of range, unknown host
/// field) blocks the whole bundle. An empty bundle is `Unknown`.
#[must_use]
pub fn solve_bundle(
    members: &[SkillCompatibility],
    host: &HostEnvironment,
) -> CompatibilityDecision {
    if members.is_empty() {
        return CompatibilityDecision::Unknown;
    }
    let mut decision = CompatibilityDecision::Compatible;
    for member in members {
        decision = worse(decision, member.evaluate(host));
    }
    decision
}

/// Whether an entire bundle may be installed. Requires a non-empty bundle in
/// which **every** member is installable on `host`. A single member with an
/// unsafe chain-env mismatch makes the bundle non-installable regardless of
/// `override_evidence` (the mismatch is never overrideable).
#[must_use]
pub fn bundle_installable(
    members: &[SkillCompatibility],
    host: &HostEnvironment,
    override_evidence: bool,
) -> bool {
    !members.is_empty()
        && members
            .iter()
            .all(|m| m.installable(host, override_evidence))
}

/// Whether every required tool id is present in the host's available set
/// (A `ToolId`). Empty `required` is trivially supported.
#[must_use]
pub fn tools_supported(required: &[ToolId], available: &[ToolId]) -> bool {
    required.iter().all(|r| available.contains(r))
}

/// Solve a skill's compatibility while also requiring its tool dependencies. A
/// missing tool is a hard [`CompatibilityDecision::Incompatible`]; otherwise the
/// base decision stands.
#[must_use]
pub fn solve_with_tools(
    skill: &SkillCompatibility,
    host: &HostEnvironment,
    required_tools: &[ToolId],
    available_tools: &[ToolId],
) -> CompatibilityDecision {
    if !tools_supported(required_tools, available_tools) {
        return CompatibilityDecision::Incompatible;
    }
    skill.evaluate(host)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use crate::compat::{MnemosVersion, VersionReq};

    fn skill(chain: u8) -> SkillCompatibility {
        SkillCompatibility {
            version_req: VersionReq {
                min: MnemosVersion::new(0, 1, 0),
                max: MnemosVersion::new(0, 3, 0),
            },
            chain_env_hash_32: [chain; 32],
            os_gpu_hash_32: [0x05; 32],
            toolchain_hash_32: [0x70; 32],
            model_provider_hash_32: [0x30; 32],
        }
    }

    fn host(chain: u8, os: u8, version: MnemosVersion) -> HostEnvironment {
        HostEnvironment {
            mnemos_version: version,
            chain_env_hash_32: [chain; 32],
            os_gpu_hash_32: [os; 32],
            toolchain_hash_32: [0x70; 32],
            model_provider_hash_32: [0x30; 32],
        }
    }

    #[test]
    fn compatible() {
        assert_eq!(
            solve_single(&skill(0xC0), &host(0xC0, 0x05, MnemosVersion::new(0, 2, 0))),
            CompatibilityDecision::Compatible
        );
    }

    #[test]
    fn warn() {
        // OS/GPU mismatch is non-fatal -> Warn.
        assert_eq!(
            solve_single(&skill(0xC0), &host(0xC0, 0xEE, MnemosVersion::new(0, 2, 0))),
            CompatibilityDecision::Warn
        );
    }

    #[test]
    fn incompatible() {
        // Chain-env mismatch is fatal -> Incompatible.
        assert_eq!(
            solve_single(&skill(0xC0), &host(0xFF, 0x05, MnemosVersion::new(0, 2, 0))),
            CompatibilityDecision::Incompatible
        );
    }

    #[test]
    fn unknown() {
        // All-zero host chain-env field -> Unknown.
        let h = HostEnvironment {
            mnemos_version: MnemosVersion::new(0, 2, 0),
            chain_env_hash_32: [0u8; 32],
            os_gpu_hash_32: [0x05; 32],
            toolchain_hash_32: [0x70; 32],
            model_provider_hash_32: [0x30; 32],
        };
        assert_eq!(
            solve_single(&skill(0xC0), &h),
            CompatibilityDecision::Unknown
        );
    }

    #[test]
    fn overrideable_vs_non_overrideable() {
        // Version-out-of-range with a matching chain-env is Incompatible but
        // overrideable.
        let s = skill(0xC0);
        let version_bad = host(0xC0, 0x05, MnemosVersion::new(5, 0, 0));
        assert!(!bundle_installable(&[s], &version_bad, false));
        assert!(bundle_installable(&[s], &version_bad, true));
        // A chain-env mismatch is never overrideable.
        let chain_bad = host(0xFF, 0x05, MnemosVersion::new(0, 2, 0));
        assert!(!bundle_installable(&[s], &chain_bad, true));
    }

    #[test]
    fn bundle_member_conflict() {
        let good = skill(0xC0);
        let chain_bad = skill(0xAB); // mismatches the 0xC0 host below
        let h = host(0xC0, 0x05, MnemosVersion::new(0, 2, 0));
        // One unsafe member blocks the whole bundle.
        assert_eq!(
            solve_bundle(&[good, chain_bad], &h),
            CompatibilityDecision::Incompatible
        );
        assert!(!bundle_installable(&[good, chain_bad], &h, true));
        // The good skill alone is fine.
        assert!(bundle_installable(&[good], &h, false));
    }

    #[test]
    fn deterministic_same_inputs_same_decision() {
        let s = skill(0xC0);
        let h = host(0xC0, 0x05, MnemosVersion::new(0, 2, 0));
        assert_eq!(solve_single(&s, &h), solve_single(&s, &h));
    }

    #[test]
    fn missing_tool_is_incompatible() {
        let s = skill(0xC0);
        let h = host(0xC0, 0x05, MnemosVersion::new(0, 2, 0));
        assert_eq!(
            solve_with_tools(&s, &h, &[ToolId(3)], &[ToolId(1), ToolId(2)]),
            CompatibilityDecision::Incompatible
        );
        assert_eq!(
            solve_with_tools(&s, &h, &[ToolId(1)], &[ToolId(1), ToolId(2)]),
            CompatibilityDecision::Compatible
        );
    }
}
