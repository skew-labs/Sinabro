//! Skill package lifecycle commands:
//! `sinabro skill package install|fork|publish|revoke|eval`.
//!
//! A package lifecycle flow over an already-[`verify_skill_package`]-verified
//! skill package. Every install / publish step is gated by the canonical Stage D
//! and g-wallet trust surface: the capability diff must be consistent
//! (`G-F-CAPABILITY`), the supply-chain receipt complete (SBOM / reproducible
//! build / dependency lock / deny audit / license), a non-expired
//! [`SafetyKernelAttestation`] present (`G-F-SAFETY-ATTESTATION` — the "trust
//! receipt"), the malicious-fixture gate clean (the canonical [`decide_import`]
//! fold — `G-F-SKILL-QUARANTINE`), and the security state installable. A revoked
//! package can never run again ([`LocalSkillState::is_executable`]).
//!
//! `G-F-NO-COMMERCE`: [`SkillPackageFlow::is_commerce`] is always `false`; there
//! is no publish-for-money / checkout path — `publish` is a local DRY-RUN that
//! folds the gate evidence into a decision and never uploads, signs, or charges.
//!
//! Reuse (no reinvention): verification is the canonical [`verify_skill_package`];
//! the package digest / supply-chain / security state / eval / provenance are the
//! Stage D [`VerifiedPackage`] surface; the malicious-fixture + soft-gate fold is
//! the canonical [`decide_import`]; the revoke is the canonical [`apply_rollback`];
//! the safety-kernel attestation + official-trust verdict are the canonical
//! g-wallet types. This module orchestrates them into one CLI lifecycle and
//! performs no live action (offline; no upload / wallet / chain / gas).

use crate::command::{ApprovalRequirement, CommandRisk, approval_for};
use mnemos_e_skill::{
    CapabilityDiff, CommunityImportEvidence, CommunitySkillDecision, LocalSkillState,
    ProvenanceNode, RollbackOp, SkillEvalScore, SkillId, SkillPackageDigest32, SkillSecurityState,
    SkillSupplyChainReceipt, SuiAddress, VerifiedPackage, VerifyError, apply_rollback,
    decide_import, verify_skill_package,
};
use mnemos_g_wallet::{OfficialTrustDecision, SafetyKernelAttestation};

/// Why a package lifecycle step was refused. Every variant maps to one canonical
/// gate so a red-team can target the exact failed boundary.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SkillPackageReject {
    /// The package bytes failed the canonical [`verify_skill_package`].
    Unverified(VerifyError),
    /// The capability diff is inconsistent — a hidden permission (`G-F-CAPABILITY`).
    HiddenPermission,
    /// The supply-chain receipt is incomplete: a zero SBOM / reproducible-build /
    /// dependency-lock / deny-audit / license hash, or a networked build script.
    SupplyChainIncomplete,
    /// No safety-kernel attestation was presented — the trust receipt is absent
    /// (`G-F-SAFETY-ATTESTATION`).
    AttestationMissing,
    /// The safety-kernel attestation has expired at the evaluation epoch.
    AttestationExpired,
    /// The malicious-fixture gate quarantined the package (`G-F-SKILL-QUARANTINE`).
    MaliciousFixtureDirty,
    /// The package security state is not installable (quarantined / revoked).
    NotInstallable,
    /// The provenance node / chain is malformed (folded by [`decide_import`]).
    ProvenanceInvalid,
    /// The eval score is invalid (an axis over the cap or a zero command hash).
    EvalInvalid,
    /// A fork-preview produced a malformed provenance node (self-parent, depth
    /// over bound, or a zero author).
    ForkNodeMalformed,
}

/// First 8 hex chars of a 32-byte hash, for a compact, redaction-safe display id.
fn hex8(bytes: &[u8; 32]) -> String {
    crate::hex32(bytes)[..8].to_string()
}

/// A short, colorless label for an official-trust verdict.
const fn trust_label(trust: OfficialTrustDecision) -> &'static str {
    match trust {
        OfficialTrustDecision::OfficialTrusted => "trusted",
        OfficialTrustDecision::LocalOnly => "local",
        OfficialTrustDecision::SelfHostedOnly => "self-hosted",
        OfficialTrustDecision::Quarantined => "quarantined",
        OfficialTrustDecision::Revoked => "revoked",
    }
}

/// The "trust receipt": minted only when every hard gate passes (consistent
/// capability diff, installable security state, complete supply chain, a valid
/// safety-kernel attestation, and a clean malicious-fixture fold). Its absence
/// is itself the deny signal — there is no install / publish without it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SkillPackageTrustReceipt {
    /// The package the receipt attests.
    pub package: SkillPackageDigest32,
    /// The package security / audit state at receipt time.
    pub security: SkillSecurityState,
    /// The official-trust verdict.
    pub trust: OfficialTrustDecision,
    /// The build id the safety-kernel attestation covers.
    pub attestation_build_id_u64: u64,
    /// The capability-diff human digest the receipt is bound to.
    pub capability_digest_32: [u8; 32],
}

/// The local dry-run publish decision. NO upload / sign / charge happens — this
/// is a projection of the gate evidence into a [`CommunitySkillDecision`] plus
/// the supply-chain / attestation flags and a single `publishable` verdict.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SkillPackagePublishDecision {
    /// The package the dry-run was evaluated for.
    pub package: SkillPackageDigest32,
    /// The folded malicious-fixture / soft-gate decision.
    pub decision: CommunitySkillDecision,
    /// Whether the supply-chain receipt is complete.
    pub supply_chain_complete: bool,
    /// Whether a non-expired safety-kernel attestation is present.
    pub attestation_valid: bool,
    /// Whether the package would be publishable (all gates green). Dry-run only.
    pub publishable: bool,
}

/// A local install receipt (non-live: a recorded local lifecycle state, never an
/// on-chain write).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SkillPackageInstallReceipt {
    /// The installed package.
    pub package: SkillPackageDigest32,
    /// The local lifecycle state after install (`Installed`).
    pub state: LocalSkillState,
}

/// A revocation record. After a revoke the package is terminal and never
/// executable again.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SkillPackageRevocation {
    /// The revoked package.
    pub package: SkillPackageDigest32,
    /// The local lifecycle state after revoke (`Revoked`).
    pub state: LocalSkillState,
    /// Whether the package can execute after the revoke (always `false`).
    pub executable: bool,
}

/// The CLI package lifecycle flow for one verified skill package. Pure
/// orchestration over the canonical Stage D + g-wallet trust surface; holds the
/// gathered gate evidence and the current local lifecycle state.
#[derive(Clone, Debug)]
pub struct SkillPackageFlow {
    skill: SkillId,
    package: SkillPackageDigest32,
    provenance: ProvenanceNode,
    supply_chain: SkillSupplyChainReceipt,
    security: SkillSecurityState,
    eval: SkillEvalScore,
    capability_consistent: bool,
    capability_digest_32: [u8; 32],
    malicious_fixture_clean: bool,
    attestation: Option<SafetyKernelAttestation>,
    trust: OfficialTrustDecision,
    state: LocalSkillState,
    risk: CommandRisk,
}

impl SkillPackageFlow {
    /// Open a lifecycle flow from the canonical package components. The package is
    /// assumed already-[`verify_skill_package`]-verified (signature bound,
    /// no-commerce clean); the lifecycle re-folds the runtime registry gates
    /// (supply-chain completeness, malicious fixture, attestation, capability
    /// consistency, security state). Starts in [`LocalSkillState::Available`].
    #[must_use]
    #[allow(clippy::too_many_arguments)]
    pub fn open(
        skill: SkillId,
        package: SkillPackageDigest32,
        provenance: ProvenanceNode,
        supply_chain: SkillSupplyChainReceipt,
        security: SkillSecurityState,
        eval: SkillEvalScore,
        capability_diff: &CapabilityDiff,
        malicious_fixture_clean: bool,
        attestation: Option<SafetyKernelAttestation>,
        trust: OfficialTrustDecision,
    ) -> Self {
        Self {
            skill,
            package,
            provenance,
            supply_chain,
            security,
            eval,
            capability_consistent: capability_diff.is_consistent(),
            capability_digest_32: *capability_diff.human_digest_32(),
            malicious_fixture_clean,
            attestation,
            trust,
            // A freshly opened verified package starts Available; install moves it
            // to Installed and revoke moves it to Revoked.
            state: LocalSkillState::Available,
            // Install / revoke mutate local state -> LocalWrite -> Confirm.
            risk: CommandRisk::LocalWrite,
        }
    }

    /// Open a flow from an already-[`VerifiedPackage`], extracting the canonical
    /// components (digest, provenance, supply chain, security, eval, capability
    /// diff) so the verifier is the single source of truth — never re-decoded.
    #[must_use]
    pub fn from_verified_package(
        verified: &VerifiedPackage,
        malicious_fixture_clean: bool,
        attestation: Option<SafetyKernelAttestation>,
        trust: OfficialTrustDecision,
    ) -> Self {
        Self::open(
            verified.package.skill_id(),
            verified.digest,
            verified.package.provenance,
            verified.package.supply_chain,
            verified.security,
            verified.package.eval,
            &verified.package.capability_diff,
            malicious_fixture_clean,
            attestation,
            trust,
        )
    }

    /// Open a flow directly from canonical package TOML by running the full
    /// [`verify_skill_package`] first. A bad schema / tampered signature / hidden
    /// permission / incomplete supply chain surfaces as
    /// [`SkillPackageReject::Unverified`] — the lifecycle never admits an
    /// unverified package.
    pub fn from_toml(
        package_toml: &str,
        malicious_fixture_clean: bool,
        attestation: Option<SafetyKernelAttestation>,
        trust: OfficialTrustDecision,
    ) -> Result<Self, SkillPackageReject> {
        let verified =
            verify_skill_package(package_toml).map_err(SkillPackageReject::Unverified)?;
        Ok(Self::from_verified_package(
            &verified,
            malicious_fixture_clean,
            attestation,
            trust,
        ))
    }

    /// The current local lifecycle state.
    #[must_use]
    pub const fn state(&self) -> LocalSkillState {
        self.state
    }

    /// The official-trust verdict for this package.
    #[must_use]
    pub const fn trust(&self) -> OfficialTrustDecision {
        self.trust
    }

    /// Always `false`: a package lifecycle is never a commerce / checkout surface.
    #[must_use]
    pub const fn is_commerce(&self) -> bool {
        false
    }

    /// The approval requirement for a mutating step, via the canonical mapping.
    #[must_use]
    pub const fn approval_requirement(&self) -> ApprovalRequirement {
        approval_for(self.risk)
    }

    /// Whether the package may execute now: an installable security state AND an
    /// executable lifecycle state. A quarantined / revoked package is never
    /// runnable, and a revoked package stays non-runnable forever.
    #[must_use]
    pub fn is_runnable(&self) -> bool {
        self.security.is_installable() && self.state.is_executable()
    }

    /// Fold the canonical import gates for this package. `signature_present` and
    /// `no_commerce_clean` are invariants of an already-verified package; the
    /// other four are re-checked runtime gates.
    fn import_evidence(&self) -> CommunityImportEvidence {
        CommunityImportEvidence {
            signature_present: true,
            provenance_ok: self.provenance.is_well_formed(),
            capability_consistent: self.capability_consistent,
            malicious_fixture_clean: self.malicious_fixture_clean,
            eval_present: self.eval.is_valid(),
            no_commerce_clean: true,
        }
    }

    /// The central trust gate. On success, mints a [`SkillPackageTrustReceipt`];
    /// each failure maps to the exact canonical gate that refused.
    pub fn trust_receipt(
        &self,
        now_epoch_u64: u64,
    ) -> Result<SkillPackageTrustReceipt, SkillPackageReject> {
        if !self.capability_consistent {
            return Err(SkillPackageReject::HiddenPermission);
        }
        if !self.security.is_installable() {
            return Err(SkillPackageReject::NotInstallable);
        }
        if !self.supply_chain.is_complete() {
            return Err(SkillPackageReject::SupplyChainIncomplete);
        }
        let attestation = self
            .attestation
            .ok_or(SkillPackageReject::AttestationMissing)?;
        if !attestation.is_valid_at(now_epoch_u64) {
            return Err(SkillPackageReject::AttestationExpired);
        }
        match decide_import(&self.import_evidence()) {
            CommunitySkillDecision::Accepted => Ok(SkillPackageTrustReceipt {
                package: self.package,
                security: self.security,
                trust: self.trust,
                attestation_build_id_u64: attestation.build.build_id_u64,
                capability_digest_32: self.capability_digest_32,
            }),
            CommunitySkillDecision::Quarantined => Err(SkillPackageReject::MaliciousFixtureDirty),
            CommunitySkillDecision::Pending => Err(SkillPackageReject::EvalInvalid),
            CommunitySkillDecision::Rejected => Err(SkillPackageReject::ProvenanceInvalid),
        }
    }

    /// Install the package: refuses unless the full trust gate passes, then moves
    /// the local state to [`LocalSkillState::Installed`]. No live action.
    pub fn install(
        &mut self,
        now_epoch_u64: u64,
    ) -> Result<SkillPackageInstallReceipt, SkillPackageReject> {
        let _receipt = self.trust_receipt(now_epoch_u64)?;
        self.state = LocalSkillState::Installed;
        Ok(SkillPackageInstallReceipt {
            package: self.package,
            state: self.state,
        })
    }

    /// Preview a fork of this package as a child [`ProvenanceNode`] (parent = this
    /// package digest, depth + 1). Refuses a malformed child (self-parent, depth
    /// over the bound, or a zero author). A pure preview — nothing is published.
    pub fn fork_preview(
        &self,
        child_package: SkillPackageDigest32,
        forker: SuiAddress,
    ) -> Result<ProvenanceNode, SkillPackageReject> {
        let child = ProvenanceNode {
            skill: self.skill,
            package: child_package,
            parent: Some(self.package),
            author: forker,
            provenance_depth_u16: self.provenance.provenance_depth_u16.saturating_add(1),
        };
        if child.is_well_formed() {
            Ok(child)
        } else {
            Err(SkillPackageReject::ForkNodeMalformed)
        }
    }

    /// Dry-run a publish: fold the gate evidence into a decision without any live
    /// upload / sign / charge. `publishable` is the verdict; a dirty malicious
    /// fixture, incomplete supply chain, expired attestation, or non-installable
    /// state all make it `false`.
    #[must_use]
    pub fn publish_dry_run(&self, now_epoch_u64: u64) -> SkillPackagePublishDecision {
        let attestation_valid = self
            .attestation
            .is_some_and(|attestation| attestation.is_valid_at(now_epoch_u64));
        let supply_chain_complete = self.supply_chain.is_complete();
        let decision = decide_import(&self.import_evidence());
        let publishable = decision == CommunitySkillDecision::Accepted
            && supply_chain_complete
            && attestation_valid
            && self.security.is_installable();
        SkillPackagePublishDecision {
            package: self.package,
            decision,
            supply_chain_complete,
            attestation_valid,
            publishable,
        }
    }

    /// Revoke the package via the canonical [`apply_rollback`]. Terminal and
    /// idempotent: the local state becomes [`LocalSkillState::Revoked`], the
    /// security state becomes [`SkillSecurityState::Revoked`], and the package can
    /// never execute again.
    pub fn revoke(&mut self) -> SkillPackageRevocation {
        self.state = apply_rollback(self.state, RollbackOp::Quarantine);
        self.security = SkillSecurityState::Revoked;
        SkillPackageRevocation {
            package: self.package,
            state: self.state,
            executable: self.state.is_executable(),
        }
    }

    /// Evaluate the package by routing to the existing Stage D eval harness: the
    /// canonical [`SkillEvalScore`] validity gate (axis-capped, bound to a
    /// reproducible command hash). Returns the score on success.
    pub fn eval(&self) -> Result<SkillEvalScore, SkillPackageReject> {
        if self.eval.is_valid() {
            Ok(self.eval)
        } else {
            Err(SkillPackageReject::EvalInvalid)
        }
    }

    /// Render the flow as bounded, colorless text lines. Surfaces the gate
    /// evidence and lifecycle state — never a price / checkout field.
    #[must_use]
    pub fn render(&self, rows: u16) -> Vec<String> {
        let lines = vec![
            format!("skill={}", self.skill.0),
            format!("package={}", hex8(self.package.as_bytes())),
            format!("security={}", self.security.class_label()),
            format!("supply_chain_complete={}", self.supply_chain.is_complete()),
            format!("malicious_fixture_clean={}", self.malicious_fixture_clean),
            format!("capability_consistent={}", self.capability_consistent),
            format!("attestation_present={}", self.attestation.is_some()),
            format!("trust={}", trust_label(self.trust)),
            format!("state_executable={}", self.state.is_executable()),
            format!("runnable={}", self.is_runnable()),
        ];
        lines.into_iter().take(rows as usize).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mnemos_e_skill::{CapabilityDiff, SkillRuntimePermission, reproducible_command_hash};
    use mnemos_g_wallet::SafetyKernelBuildRef;

    const NOW: u64 = 10;

    fn digest(b: u8) -> SkillPackageDigest32 {
        SkillPackageDigest32::new([b; 32])
    }
    fn addr(b: u8) -> SuiAddress {
        SuiAddress::new([b; 32])
    }

    fn root_provenance() -> ProvenanceNode {
        ProvenanceNode {
            skill: SkillId(7),
            package: digest(0xA0),
            parent: None,
            author: addr(0x11),
            provenance_depth_u16: 0,
        }
    }

    fn complete_supply_chain() -> SkillSupplyChainReceipt {
        SkillSupplyChainReceipt {
            sbom_hash_32: [1; 32],
            reproducible_build_hash_32: [2; 32],
            dependency_lock_hash_32: [3; 32],
            deny_audit_hash_32: [4; 32],
            license_hash_32: [5; 32],
            build_script_network_denied: true,
        }
    }

    fn valid_eval() -> SkillEvalScore {
        SkillEvalScore {
            rust_u16: 9000,
            move_u16: 9000,
            prover_u16: 8000,
            gas_u16: 8000,
            security_u16: 9000,
            korean_u16: 9000,
            reproducible_command_hash_32: reproducible_command_hash(&["cargo test"]),
        }
    }

    fn honest_diff() -> CapabilityDiff {
        CapabilityDiff::new(SkillRuntimePermission::MemoryRead.mask_bit(), 0, Vec::new())
    }

    fn valid_attestation() -> SafetyKernelAttestation {
        SafetyKernelAttestation {
            build: SafetyKernelBuildRef {
                build_id_u64: 441,
                release_hash_32: [0x9; 32],
            },
            sbom_hash_32: [1; 32],
            reproducible_build_hash_32: [2; 32],
            sandbox_policy_hash_32: [3; 32],
            evidence_schema_hash_32: [4; 32],
            expires_epoch_u64: 100,
        }
    }

    fn flow(
        security: SkillSecurityState,
        malicious_clean: bool,
        attestation: Option<SafetyKernelAttestation>,
        supply: SkillSupplyChainReceipt,
        diff: &CapabilityDiff,
    ) -> SkillPackageFlow {
        SkillPackageFlow::open(
            SkillId(7),
            digest(0xA0),
            root_provenance(),
            supply,
            security,
            valid_eval(),
            diff,
            malicious_clean,
            attestation,
            OfficialTrustDecision::OfficialTrusted,
        )
    }

    fn ready() -> SkillPackageFlow {
        let diff = honest_diff();
        flow(
            SkillSecurityState::AuditPass,
            true,
            Some(valid_attestation()),
            complete_supply_chain(),
            &diff,
        )
    }

    #[test]
    fn install_succeeds_for_clean_package() {
        let mut f = ready();
        let r = f.install(NOW);
        assert!(r.is_ok());
        if let Ok(receipt) = r {
            assert_eq!(receipt.state, LocalSkillState::Installed);
        }
        assert!(f.is_runnable());
    }

    #[test]
    fn fork_preview_builds_well_formed_child() {
        let f = ready();
        let child = f.fork_preview(digest(0xB0), addr(0x22));
        assert!(child.is_ok());
        if let Ok(node) = child {
            assert_eq!(node.parent, Some(digest(0xA0)));
            assert_eq!(node.provenance_depth_u16, 1);
            assert!(node.is_well_formed());
        }
        // A self-parent fork (child digest == parent digest) is a 1-cycle.
        assert_eq!(
            f.fork_preview(digest(0xA0), addr(0x22)),
            Err(SkillPackageReject::ForkNodeMalformed)
        );
    }

    #[test]
    fn publish_dry_run_is_local_and_accepts_clean() {
        let f = ready();
        let d = f.publish_dry_run(NOW);
        assert_eq!(d.decision, CommunitySkillDecision::Accepted);
        assert!(d.publishable);
        assert!(d.supply_chain_complete);
        assert!(d.attestation_valid);
        // A dry-run must not mutate the lifecycle state (no upload, no install).
        assert_eq!(f.state(), LocalSkillState::Available);
    }

    #[test]
    fn revoke_makes_package_non_runnable_forever() {
        let mut f = ready();
        assert!(f.install(NOW).is_ok());
        assert!(f.is_runnable());
        let rev = f.revoke();
        assert_eq!(rev.state, LocalSkillState::Revoked);
        assert!(!rev.executable);
        assert!(!f.is_runnable(), "a revoked package can never run again");
    }

    #[test]
    fn eval_routes_to_harness_and_validates() {
        let f = ready();
        assert!(f.eval().is_ok());
        // An invalid eval (zero reproducible-command hash) is rejected.
        let mut bad_eval = valid_eval();
        bad_eval.reproducible_command_hash_32 = [0u8; 32];
        let diff = honest_diff();
        let f2 = SkillPackageFlow::open(
            SkillId(7),
            digest(0xA0),
            root_provenance(),
            complete_supply_chain(),
            SkillSecurityState::AuditPass,
            bad_eval,
            &diff,
            true,
            Some(valid_attestation()),
            OfficialTrustDecision::OfficialTrusted,
        );
        assert_eq!(f2.eval(), Err(SkillPackageReject::EvalInvalid));
    }

    #[test]
    fn malicious_fixture_denies_install_and_publish() {
        let diff = honest_diff();
        let mut f = flow(
            SkillSecurityState::AuditPass,
            false,
            Some(valid_attestation()),
            complete_supply_chain(),
            &diff,
        );
        assert_eq!(
            f.install(NOW),
            Err(SkillPackageReject::MaliciousFixtureDirty)
        );
        let d = f.publish_dry_run(NOW);
        assert_eq!(d.decision, CommunitySkillDecision::Quarantined);
        assert!(!d.publishable);
    }

    #[test]
    fn sbom_missing_blocks_install() {
        let mut supply = complete_supply_chain();
        supply.sbom_hash_32 = [0u8; 32];
        let diff = honest_diff();
        let mut f = flow(
            SkillSecurityState::AuditPass,
            true,
            Some(valid_attestation()),
            supply,
            &diff,
        );
        assert_eq!(
            f.install(NOW),
            Err(SkillPackageReject::SupplyChainIncomplete)
        );
    }

    #[test]
    fn reproducible_build_missing_blocks_install() {
        let mut supply = complete_supply_chain();
        supply.reproducible_build_hash_32 = [0u8; 32];
        let diff = honest_diff();
        let mut f = flow(
            SkillSecurityState::AuditPass,
            true,
            Some(valid_attestation()),
            supply,
            &diff,
        );
        assert_eq!(
            f.install(NOW),
            Err(SkillPackageReject::SupplyChainIncomplete)
        );
    }

    #[test]
    fn trust_receipt_absent_blocks_install() {
        let diff = honest_diff();
        let mut f = flow(
            SkillSecurityState::AuditPass,
            true,
            None,
            complete_supply_chain(),
            &diff,
        );
        assert_eq!(f.install(NOW), Err(SkillPackageReject::AttestationMissing));
    }

    #[test]
    fn attestation_expired_blocks_install() {
        let diff = honest_diff();
        let mut f = flow(
            SkillSecurityState::AuditPass,
            true,
            Some(valid_attestation()),
            complete_supply_chain(),
            &diff,
        );
        // The attestation expires at epoch 100; evaluating at 200 is expired.
        assert_eq!(f.install(200), Err(SkillPackageReject::AttestationExpired));
    }

    #[test]
    fn quarantined_security_denies_install_and_run() {
        let diff = honest_diff();
        let mut f = flow(
            SkillSecurityState::Quarantined,
            true,
            Some(valid_attestation()),
            complete_supply_chain(),
            &diff,
        );
        assert_eq!(f.install(NOW), Err(SkillPackageReject::NotInstallable));
        assert!(!f.is_runnable());
    }

    #[test]
    fn hidden_permission_blocks_install() {
        // Tamper the diff digest so it no longer matches its mask -> inconsistent.
        let mut bad = honest_diff();
        bad.human_digest_32 = [0u8; 32];
        let mut f = flow(
            SkillSecurityState::AuditPass,
            true,
            Some(valid_attestation()),
            complete_supply_chain(),
            &bad,
        );
        assert_eq!(f.install(NOW), Err(SkillPackageReject::HiddenPermission));
    }

    #[test]
    fn from_toml_rejects_unverified() {
        let r = SkillPackageFlow::from_toml(
            "this is not a valid package",
            true,
            Some(valid_attestation()),
            OfficialTrustDecision::OfficialTrusted,
        );
        assert!(matches!(r, Err(SkillPackageReject::Unverified(_))));
    }

    #[test]
    fn approval_is_confirm_for_local_write() {
        assert_eq!(ready().approval_requirement(), ApprovalRequirement::Confirm);
    }

    #[test]
    fn no_commerce_scan() {
        let f = ready();
        assert!(!f.is_commerce());
        const FORBIDDEN: &[&str] = &[
            "price", "pay", "buy", "sell", "checkout", "refund", "fee", "cost", "$",
        ];
        for line in f.render(32) {
            for bad in FORBIDDEN {
                assert!(
                    !line.contains(bad),
                    "commerce token {bad} in render: {line}"
                );
            }
        }
        let report = mnemos_e_skill::scan_surfaces(
            &[
                "skill", "package", "install", "fork", "publish", "revoke", "eval",
            ],
            &[
                "SkillPackageFlow",
                "SkillPackageReject",
                "SkillPackageTrustReceipt",
                "SkillPackagePublishDecision",
            ],
            &["--dry-run", "--now-epoch", "--forker"],
            "Install, fork-preview, publish dry-run, revoke, and eval skill packages offline.",
        );
        assert!(report.is_clean(), "no-commerce surface scan must be clean");
    }
}
