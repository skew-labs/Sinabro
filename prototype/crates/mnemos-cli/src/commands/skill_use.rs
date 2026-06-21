//! Skill use / install launch flow (atom #439 · F.4.4): `sinabro skill use|install`.
//!
//! A use or install proceeds only after the full gate chain: the permission diff
//! is shown ([`PermissionPreview`] + [`gate_action`]), the package is verified,
//! the host is compatible, a try-before-use dry-run passed, and the user has
//! explicitly confirmed. Only then is a [`LocalInstallReceipt`] minted (via the
//! canonical [`mint_receipt`] over the [`InstallPlan`] / [`InstallPreconditions`]
//! decision). It never opens a hosted checkout.
//!
//! `G-F-NO-COMMERCE`: [`SkillUseLaunch::is_commerce`] is always `false`, the
//! rendered lines carry no price/payment token, and there is no method that could
//! open a checkout. `G-F-SKILL-REGISTRY`: confirmation-required / dry-run /
//! receipt / cancel are all covered.
//!
//! Reuse (no reinvention): the dry-run is the canonical
//! [`run_try_before_use`]; the gate decision is the canonical [`InstallPlan`] +
//! [`mint_receipt`]; the permission preview, compatibility gate, and risk →
//! approval mapping are all canonical. This module orchestrates them into one CLI
//! launch flow and performs no live action (offline; receipts are
//! [`LocalInstallReceipt`] values, never an on-chain write).

use crate::command::{ApprovalRequirement, CommandRisk, approval_for};
use mnemos_a_core::StageDTraceLink;
use mnemos_e_skill::{
    CapabilityDiff, CompatibilityDecision, InstallBlockReason, InstallPlan, InstallPreconditions,
    LocalInstallReceipt, LocalReceiptKind, PermissionPreview, PreviewGate, ReceiptError, SkillId,
    SkillPackageDigest32, TryBeforeUseFixture, TryBeforeUseRun, WasmSandboxDecision,
    WasmTier2ModuleId, compatibility_admits_install, gate_action, mint_receipt, run_try_before_use,
};

/// Why a use / install launch was refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SkillUseReject {
    /// The capability diff was missing or inconsistent (a hidden permission) —
    /// there is no permission-free path to use / install.
    PermissionDiffHidden,
    /// The install plan was blocked; carries the exact precondition reason
    /// (unverified / incompatible / capability-not-approved / dry-run-missing /
    /// user-not-confirmed / digest-drift).
    Blocked(InstallBlockReason),
    /// The package is revoked — never usable, even with every other gate green.
    Revoked,
}

/// First 8 hex chars of a 32-byte hash, for a compact, redaction-safe display id.
fn hex8(bytes: &[u8; 32]) -> String {
    crate::hex32(bytes)[..8].to_string()
}

/// The CLI use / install launch flow for one skill. Pure orchestration over the
/// canonical Stage D gate chain; holds the gathered evidence and the explicit
/// confirmation, and mints a receipt only when every precondition holds.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SkillUseLaunch {
    skill: SkillId,
    package: SkillPackageDigest32,
    module: WasmTier2ModuleId,
    capability_approval_hash_32: [u8; 32],
    permission_preview: PermissionPreview,
    permission_gate: PreviewGate,
    dry_run: Option<TryBeforeUseRun>,
    package_verified: bool,
    compatibility: CompatibilityDecision,
    confirmed: bool,
    risk: CommandRisk,
}

impl SkillUseLaunch {
    /// Open a launch flow for a skill, showing its `capability_diff` permission
    /// preview. The diff is gated immediately: a missing / inconsistent diff makes
    /// the launch un-proceedable. Starts un-verified, incompatible-unknown,
    /// dry-run-absent, and unconfirmed.
    #[must_use]
    pub fn open(
        skill: SkillId,
        package: SkillPackageDigest32,
        module: WasmTier2ModuleId,
        capability_diff: &CapabilityDiff,
    ) -> Self {
        Self {
            skill,
            package,
            module,
            capability_approval_hash_32: *capability_diff.human_digest_32(),
            permission_preview: PermissionPreview::from_diff(capability_diff),
            permission_gate: gate_action(Some(capability_diff)),
            dry_run: None,
            package_verified: false,
            compatibility: CompatibilityDecision::Unknown,
            confirmed: false,
            // A local install mutates local state -> LocalWrite -> Confirm.
            risk: CommandRisk::LocalWrite,
        }
    }

    /// Record the upstream package-verification result (#252).
    pub const fn set_package_verified(&mut self, verified: bool) {
        self.package_verified = verified;
    }

    /// Record the host compatibility decision (#251).
    pub const fn set_compatibility(&mut self, decision: CompatibilityDecision) {
        self.compatibility = decision;
    }

    /// Run a try-before-use dry-run over `fixture`, recording the canonical
    /// result. An ineligible fixture (raw workspace slice, or an unapproved
    /// redacted slice) yields a denied dry-run.
    pub fn run_dry_run(&mut self, fixture: &TryBeforeUseFixture, trace: StageDTraceLink) {
        self.dry_run = Some(run_try_before_use(
            self.skill,
            self.package,
            self.module,
            fixture,
            trace,
        ));
    }

    /// Record an explicit user confirmation.
    pub const fn confirm(&mut self) {
        self.confirmed = true;
    }

    /// Cancel the launch: clears the confirmation so it can no longer proceed.
    pub const fn cancel(&mut self) {
        self.confirmed = false;
    }

    /// The permission diff preview shown to the user.
    #[must_use]
    pub const fn permission_preview(&self) -> &PermissionPreview {
        &self.permission_preview
    }

    /// The recorded dry-run result, if one was run.
    #[must_use]
    pub const fn dry_run(&self) -> Option<TryBeforeUseRun> {
        self.dry_run
    }

    /// Whether a dry-run was run AND its sandbox decision allowed the trial.
    #[must_use]
    pub fn dry_run_passed(&self) -> bool {
        self.dry_run
            .is_some_and(|run| run.decision == WasmSandboxDecision::Allow)
    }

    /// Always `false`: this flow is never a commerce / checkout surface.
    #[must_use]
    pub const fn is_commerce(&self) -> bool {
        false
    }

    /// The approval requirement for this action, via the canonical risk mapping.
    #[must_use]
    pub const fn approval_requirement(&self) -> ApprovalRequirement {
        approval_for(self.risk)
    }

    /// The install preconditions gathered so far, projected for the canonical
    /// [`InstallPlan::evaluate`]: package verification, compatibility (mapped via
    /// [`compatibility_admits_install`]), capability approval (a consistent diff
    /// gate), dry-run evidence, and explicit confirmation.
    #[must_use]
    pub fn preconditions(&self) -> InstallPreconditions {
        InstallPreconditions {
            package_verified: self.package_verified,
            compatibility_pass: compatibility_admits_install(self.compatibility),
            capability_approved: matches!(self.permission_gate, PreviewGate::Allowed),
            dry_run_passed: self.dry_run_passed(),
            user_confirmed: self.confirmed,
        }
    }

    /// A cheap pre-check of whether the launch can proceed: a consistent
    /// permission diff and every precondition met. The authoritative gate is
    /// [`Self::launch`].
    #[must_use]
    pub fn can_launch(&self) -> bool {
        if !matches!(self.permission_gate, PreviewGate::Allowed) {
            return false;
        }
        let pre = self.preconditions();
        pre.package_verified
            && pre.compatibility_pass
            && pre.capability_approved
            && pre.dry_run_passed
            && pre.user_confirmed
    }

    /// Launch the use / install: refuses a hidden permission diff first, then mints
    /// a [`LocalInstallReceipt`] via the canonical [`mint_receipt`] (which refuses
    /// a revoked package and evaluates the [`InstallPlan`]). A `Use` receipt
    /// records a trial (non-executable); an `Install` receipt is executable. No
    /// hosted checkout is ever opened.
    pub fn launch(
        &self,
        kind: LocalReceiptKind,
        package_revoked: bool,
        user: mnemos_e_skill::SuiAddress,
        trace: StageDTraceLink,
    ) -> Result<LocalInstallReceipt, SkillUseReject> {
        if !matches!(self.permission_gate, PreviewGate::Allowed) {
            return Err(SkillUseReject::PermissionDiffHidden);
        }
        let plan = InstallPlan::new(self.skill, self.package, self.module);
        let pre = self.preconditions();
        match mint_receipt(
            kind,
            &plan,
            &pre,
            self.package.as_bytes(),
            package_revoked,
            user,
            self.capability_approval_hash_32,
            trace,
        ) {
            Ok(receipt) => Ok(receipt),
            Err(ReceiptError::Revoked) => Err(SkillUseReject::Revoked),
            Err(ReceiptError::Blocked(reason)) => Err(SkillUseReject::Blocked(reason)),
        }
    }

    /// Render the launch as bounded, colorless text lines. Surfaces the permission
    /// preview, the gate chain, and the confirmation state — never a price /
    /// checkout field.
    #[must_use]
    pub fn render(&self, rows: u16) -> Vec<String> {
        let lines = vec![
            format!("permission_high_risk={}", self.permission_preview.high_risk),
            format!("permission_added={}", self.permission_preview.added.len()),
            format!(
                "permission_gate={}",
                match self.permission_gate {
                    PreviewGate::Allowed => "allowed",
                    PreviewGate::Blocked => "blocked",
                }
            ),
            format!(
                "capability_approval={}",
                hex8(&self.capability_approval_hash_32)
            ),
            format!("package_verified={}", self.package_verified),
            format!(
                "compatibility_admits={}",
                compatibility_admits_install(self.compatibility)
            ),
            format!("dry_run_passed={}", self.dry_run_passed()),
            format!("confirmed={}", self.confirmed),
            format!("can_launch={}", self.can_launch()),
        ];
        lines.into_iter().take(rows as usize).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mnemos_a_core::{StageBTraceLink, StageCTraceLink, StageDTraceLink};
    use mnemos_e_skill::{
        CapabilityDiff, CompatibilityDecision, FixtureSource, InstallBlockReason, LocalReceiptKind,
        SkillId, SkillPackageDigest32, SkillRuntimePermission, SuiAddress, TryBeforeUseFixture,
        WasmTier2ModuleId,
    };

    fn trace() -> StageDTraceLink {
        let b = StageBTraceLink::new(0xF439_0001, 439, 0);
        let c = StageCTraceLink::new(b, 240, 9);
        StageDTraceLink::new(c, 439, 1)
    }

    fn honest_diff() -> CapabilityDiff {
        CapabilityDiff::new(SkillRuntimePermission::MemoryRead.mask_bit(), 0, Vec::new())
    }

    fn launch(diff: &CapabilityDiff) -> SkillUseLaunch {
        SkillUseLaunch::open(
            SkillId(7),
            SkillPackageDigest32::new([0x44; 32]),
            WasmTier2ModuleId::from_bytes([0x55; 32]),
            diff,
        )
    }

    fn fixture(source: FixtureSource) -> TryBeforeUseFixture {
        TryBeforeUseFixture {
            fixture_hash_32: [0x11; 32],
            source,
            redaction_token_32: [0u8; 32],
        }
    }

    fn user() -> SuiAddress {
        SuiAddress::new([0xAB; 32])
    }

    fn ready() -> SkillUseLaunch {
        let diff = honest_diff();
        let mut l = launch(&diff);
        l.set_package_verified(true);
        l.set_compatibility(CompatibilityDecision::Compatible);
        l.run_dry_run(&fixture(FixtureSource::Sample), trace());
        l.confirm();
        l
    }

    #[test]
    fn confirmation_required() {
        let diff = honest_diff();
        let mut l = launch(&diff);
        l.set_package_verified(true);
        l.set_compatibility(CompatibilityDecision::Compatible);
        l.run_dry_run(&fixture(FixtureSource::Sample), trace());
        // no confirm
        assert!(!l.can_launch());
        let r = l.launch(LocalReceiptKind::Install, false, user(), trace());
        assert_eq!(
            r,
            Err(SkillUseReject::Blocked(
                InstallBlockReason::UserNotConfirmed
            ))
        );
    }

    #[test]
    fn dry_run_launched() {
        // A raw-workspace fixture is ineligible -> dry-run denied -> blocked.
        let diff = honest_diff();
        let mut l = launch(&diff);
        l.set_package_verified(true);
        l.set_compatibility(CompatibilityDecision::Compatible);
        l.run_dry_run(&fixture(FixtureSource::RawWorkspace), trace());
        assert!(!l.dry_run_passed());
        l.confirm();
        let r = l.launch(LocalReceiptKind::Install, false, user(), trace());
        assert_eq!(
            r,
            Err(SkillUseReject::Blocked(InstallBlockReason::DryRunMissing))
        );
        // A bundled sample fixture is eligible -> dry-run passes.
        let mut l2 = launch(&diff);
        l2.run_dry_run(&fixture(FixtureSource::Sample), trace());
        assert!(l2.dry_run_passed());
    }

    #[test]
    fn install_receipt_created() {
        let l = ready();
        let r = l.launch(LocalReceiptKind::Install, false, user(), trace());
        assert!(r.is_ok());
        if let Ok(receipt) = r {
            assert!(receipt.is_executable());
            assert_eq!(receipt.skill.0, 7);
        }
    }

    #[test]
    fn use_receipt_is_a_trial_not_executable() {
        let l = ready();
        let r = l.launch(LocalReceiptKind::Use, false, user(), trace());
        assert!(r.is_ok());
        if let Ok(receipt) = r {
            assert!(
                !receipt.is_executable(),
                "a use/trial receipt is not executable"
            );
        }
    }

    #[test]
    fn cancel_aborts() {
        let mut l = ready();
        l.cancel();
        assert!(!l.can_launch());
        let r = l.launch(LocalReceiptKind::Install, false, user(), trace());
        assert_eq!(
            r,
            Err(SkillUseReject::Blocked(
                InstallBlockReason::UserNotConfirmed
            ))
        );
    }

    #[test]
    fn hidden_permission_blocks() {
        // Smuggle a Wallet permission into the mask without updating the digest.
        let mut bad =
            CapabilityDiff::new(SkillRuntimePermission::MemoryRead.mask_bit(), 0, Vec::new());
        bad.added_mask_u64 |= SkillRuntimePermission::Wallet.mask_bit();
        let mut l = launch(&bad);
        l.set_package_verified(true);
        l.set_compatibility(CompatibilityDecision::Compatible);
        l.run_dry_run(&fixture(FixtureSource::Sample), trace());
        l.confirm();
        let r = l.launch(LocalReceiptKind::Install, false, user(), trace());
        assert_eq!(r, Err(SkillUseReject::PermissionDiffHidden));
    }

    #[test]
    fn revoked_package_blocks() {
        let l = ready();
        let r = l.launch(LocalReceiptKind::Install, true, user(), trace());
        assert_eq!(r, Err(SkillUseReject::Revoked));
    }

    #[test]
    fn no_commerce_scan() {
        let l = ready();
        assert!(!l.is_commerce());
        const FORBIDDEN: &[&str] = &[
            "price", "pay", "buy", "sell", "checkout", "refund", "fee", "cost", "$",
        ];
        for line in l.render(32) {
            for bad in FORBIDDEN {
                assert!(
                    !line.contains(bad),
                    "commerce token {bad} in render: {line}"
                );
            }
        }
        // The canonical surface scanner confirms the command/type/cli/doc surface
        // carries no active commerce token.
        let report = mnemos_e_skill::scan_surfaces(
            &["skill", "search", "inspect", "use", "install", "cancel"],
            &["SkillUseLaunch", "SkillUseReject"],
            &["--dry-run", "--confirm", "--inspect"],
            "Search, inspect, dry-run, confirm, and install skills offline.",
        );
        assert!(report.is_clean(), "no-commerce surface scan must be clean");
    }
}
