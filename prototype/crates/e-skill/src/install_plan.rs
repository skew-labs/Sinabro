//! `mnemos-e-skill::install_plan` — atom #271 · D.1.15 — the user-approved
//! install plan.
//!
//! An [`InstallPlan`] can be *computed* from catalog metadata, but executing it
//! requires every precondition in [`InstallPreconditions`] to hold AND the
//! observed package digest to match the plan's package (no digest drift):
//! package verification (#252), compatibility (#251), capability approval (#270
//! / #244), dry-run evidence (#266 / #267), and explicit user confirmation. A
//! plan with any precondition unmet — or a drifted digest — is
//! [`InstallDecision::Blocked`].

#![deny(missing_docs)]

use crate::manifest::SkillId;
use crate::package::SkillPackageDigest32;
use crate::wasm_tier2::module_id::WasmTier2ModuleId;

/// Preconditions an install must satisfy before it may execute. Each is supplied
/// by an upstream gate; the install plan does not compute them, it requires
/// them.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub struct InstallPreconditions {
    /// `verify_skill_package` (#252) returned a verified package.
    pub package_verified: bool,
    /// The compatibility check (#251) passed for the host environment.
    pub compatibility_pass: bool,
    /// The capability diff (#244 / #270) was shown and approved.
    pub capability_approved: bool,
    /// A try-before-use dry-run (#266 / #267) passed.
    pub dry_run_passed: bool,
    /// The user explicitly confirmed the install.
    pub user_confirmed: bool,
}

impl InstallPreconditions {
    /// All preconditions met — convenience for callers / tests that then flip a
    /// single field to assert a specific block reason.
    #[inline]
    #[must_use]
    pub const fn all_met() -> Self {
        Self {
            package_verified: true,
            compatibility_pass: true,
            capability_approved: true,
            dry_run_passed: true,
            user_confirmed: true,
        }
    }
}

/// Why an install plan was blocked.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum InstallBlockReason {
    /// The observed package digest does not match the plan's package.
    DigestDrift,
    /// The package was not verified.
    PackageUnverified,
    /// The package is incompatible with the host.
    Incompatible,
    /// The capability diff was not approved.
    CapabilityNotApproved,
    /// No passing dry-run evidence.
    DryRunMissing,
    /// The user did not confirm.
    UserNotConfirmed,
}

/// The decision of evaluating an install plan.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum InstallDecision {
    /// Every precondition held and the digest matched — install may proceed.
    Proceed,
    /// Install is blocked for the given reason.
    Blocked(InstallBlockReason),
}

/// An install plan, scoped to an exact package digest and module id.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct InstallPlan {
    /// The skill being installed.
    pub skill: SkillId,
    /// The exact package digest the plan was computed for.
    pub package: SkillPackageDigest32,
    /// The module id to be installed.
    pub module: WasmTier2ModuleId,
}

impl InstallPlan {
    /// Construct an install plan.
    #[inline]
    #[must_use]
    pub const fn new(
        skill: SkillId,
        package: SkillPackageDigest32,
        module: WasmTier2ModuleId,
    ) -> Self {
        Self {
            skill,
            package,
            module,
        }
    }

    /// Evaluate whether the install may proceed. The `observed_digest_32` must
    /// equal the plan's package digest (no drift), then every precondition is
    /// checked in a fixed order; the first failure is the block reason.
    #[must_use]
    pub fn evaluate(
        &self,
        pre: &InstallPreconditions,
        observed_digest_32: &[u8; 32],
    ) -> InstallDecision {
        if observed_digest_32 != self.package.as_bytes() {
            return InstallDecision::Blocked(InstallBlockReason::DigestDrift);
        }
        if !pre.package_verified {
            return InstallDecision::Blocked(InstallBlockReason::PackageUnverified);
        }
        if !pre.compatibility_pass {
            return InstallDecision::Blocked(InstallBlockReason::Incompatible);
        }
        if !pre.capability_approved {
            return InstallDecision::Blocked(InstallBlockReason::CapabilityNotApproved);
        }
        if !pre.dry_run_passed {
            return InstallDecision::Blocked(InstallBlockReason::DryRunMissing);
        }
        if !pre.user_confirmed {
            return InstallDecision::Blocked(InstallBlockReason::UserNotConfirmed);
        }
        InstallDecision::Proceed
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn plan() -> InstallPlan {
        InstallPlan::new(
            SkillId(9),
            SkillPackageDigest32::new([0x44; 32]),
            WasmTier2ModuleId::from_bytes([0x55; 32]),
        )
    }

    #[test]
    fn verified_install_accepted() {
        let p = plan();
        assert_eq!(
            p.evaluate(&InstallPreconditions::all_met(), &[0x44; 32]),
            InstallDecision::Proceed
        );
    }

    #[test]
    fn digest_drift_denied() {
        let p = plan();
        assert_eq!(
            p.evaluate(&InstallPreconditions::all_met(), &[0x99; 32]),
            InstallDecision::Blocked(InstallBlockReason::DigestDrift)
        );
    }

    #[test]
    fn plan_without_dry_run_denied() {
        let p = plan();
        let mut pre = InstallPreconditions::all_met();
        pre.dry_run_passed = false;
        assert_eq!(
            p.evaluate(&pre, &[0x44; 32]),
            InstallDecision::Blocked(InstallBlockReason::DryRunMissing)
        );
    }

    #[test]
    fn plan_without_capability_approval_denied() {
        let p = plan();
        let mut pre = InstallPreconditions::all_met();
        pre.capability_approved = false;
        assert_eq!(
            p.evaluate(&pre, &[0x44; 32]),
            InstallDecision::Blocked(InstallBlockReason::CapabilityNotApproved)
        );
    }

    #[test]
    fn plan_without_user_confirmation_denied() {
        let p = plan();
        let mut pre = InstallPreconditions::all_met();
        pre.user_confirmed = false;
        assert_eq!(
            p.evaluate(&pre, &[0x44; 32]),
            InstallDecision::Blocked(InstallBlockReason::UserNotConfirmed)
        );
    }
}
