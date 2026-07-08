//! `mnemos-e-skill::install_receipt` — the local
//! use/install receipt.
//!
//! ## Overview
//!
//! - [`LocalInstallReceiptId`] — `#[repr(transparent)]` 32-byte content
//!   address of a receipt, derived from `(skill, package, user, state,
//!   capability_approval_hash)`. Deterministic: the same mint inputs always
//!   produce the same id (receipt replay is deterministic).
//! - [`LocalInstallReceipt`] — `{ id, skill, package, user, state,
//!   capability_approval_hash_32, trace }`. A receipt is the **local** record
//!   that a use/install flow completed; it is NOT a payment license and carries
//!   no price/payment field (no-commerce).
//!
//! ## Authority
//!
//! A receipt is minted only when [`crate::install_plan::InstallPlan::evaluate`]
//! returns [`InstallDecision::Proceed`] — i.e. the signed package was
//! verified, the host is compatible
//! ([`crate::compat::CompatibilityDecision`] via
//! [`compatibility_admits_install`]), the capability diff was
//! shown and approved (its `human_digest_32` is bound as
//! `capability_approval_hash_32`), a sandbox dry-run passed, and the user
//! confirmed. A revoked package is refused before any of that
//! ([`ReceiptError::Revoked`]) — a local receipt can never re-animate a revoked
//! package. The receipt state is a reused [`crate::rollback::LocalSkillState`],
//! never a freshly-minted lifecycle enum.
//!
//! ## Offline boundary
//!
//! Minting is a pure, offline derivation: the `user` is a typed
//! [`SuiAddress`] value (no signing), the `trace` is an offline evidence link,
//! and no network / wallet / secret / chain action occurs.

#![deny(missing_docs)]

extern crate alloc;

use alloc::vec::Vec;

use mnemos_a_core::StageDTraceLink;
use mnemos_d_move::types::SuiAddress;

use crate::compat::CompatibilityDecision;
use crate::install_plan::{InstallBlockReason, InstallDecision, InstallPlan, InstallPreconditions};
use crate::manifest::SkillId;
use crate::package::{SkillPackageDigest32, blake2b_256};
use crate::rollback::LocalSkillState;

/// Domain tag for the local-install-receipt id derivation.
const DOMAIN_LOCAL_RECEIPT: &[u8] = b"mnemos.d.local_install_receipt.v1";

// ===========================================================================
// 1. LocalReceiptKind — a use vs an install
// ===========================================================================

/// Whether a receipt records a try/use or a full install.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum LocalReceiptKind {
    /// A try-before-use run that passed — records use, leaves the skill in
    /// [`LocalSkillState::DryRunPassed`] (not installed).
    Use,
    /// A full install — records install, leaves the skill in
    /// [`LocalSkillState::Installed`].
    Install,
}

impl LocalReceiptKind {
    /// The local state this receipt kind records.
    #[inline]
    #[must_use]
    const fn recorded_state(self) -> LocalSkillState {
        match self {
            Self::Use => LocalSkillState::DryRunPassed,
            Self::Install => LocalSkillState::Installed,
        }
    }
}

// ===========================================================================
// 2. ReceiptError — why a receipt could not be minted
// ===========================================================================

/// Why [`mint_receipt`] refused to mint a receipt.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReceiptError {
    /// The install plan was blocked. Carries the exact block reason so
    /// "missing approval" / "dry-run fail" are distinguishable.
    Blocked(InstallBlockReason),
    /// The package is revoked — never mintable, even with every other gate
    /// green.
    Revoked,
}

// ===========================================================================
// 3. compatibility gate (reuse CompatibilityDecision)
// ===========================================================================

/// Map a compatibility decision to the install precondition: only
/// [`CompatibilityDecision::Compatible`] and [`CompatibilityDecision::Warn`]
/// admit install; [`CompatibilityDecision::Incompatible`] and
/// [`CompatibilityDecision::Unknown`] do not. Callers derive
/// [`InstallPreconditions::compatibility_pass`] from this.
#[inline]
#[must_use]
pub const fn compatibility_admits_install(decision: CompatibilityDecision) -> bool {
    matches!(
        decision,
        CompatibilityDecision::Compatible | CompatibilityDecision::Warn
    )
}

// ===========================================================================
// 4. LocalInstallReceiptId — deterministic receipt content address
// ===========================================================================

/// 32-byte content address of a [`LocalInstallReceipt`]. `#[repr(transparent)]`
/// over `[u8; 32]`.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
#[repr(transparent)]
pub struct LocalInstallReceiptId([u8; 32]);

impl LocalInstallReceiptId {
    /// Wrap 32 raw bytes as a receipt id.
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

    /// Derive the receipt id from its content fields. Fixed-width, count-free
    /// preimage under a distinct domain tag, so the no-separator `blake2b_256`
    /// framing is unambiguous and the id is replay-deterministic.
    #[must_use]
    fn derive(
        skill: SkillId,
        package: &SkillPackageDigest32,
        user: &SuiAddress,
        state: LocalSkillState,
        capability_approval_hash_32: &[u8; 32],
    ) -> Self {
        let mut buf: Vec<u8> = Vec::with_capacity(2 + 32 + 32 + 1 + 32);
        buf.extend_from_slice(&skill.0.to_le_bytes());
        buf.extend_from_slice(package.as_bytes());
        buf.extend_from_slice(user.as_bytes());
        buf.push(state as u8);
        buf.extend_from_slice(capability_approval_hash_32);
        Self(blake2b_256(&[DOMAIN_LOCAL_RECEIPT, &buf]))
    }
}

// ===========================================================================
// 5. LocalInstallReceipt
// ===========================================================================

/// The local record that a use/install flow completed. Minted only on
/// [`InstallDecision::Proceed`]; never a payment license.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub struct LocalInstallReceipt {
    /// Deterministic content address of this receipt.
    pub id: LocalInstallReceiptId,
    /// The skill the receipt is for.
    pub skill: SkillId,
    /// The exact package digest that was used/installed.
    pub package: SkillPackageDigest32,
    /// The local user/account the receipt belongs to.
    pub user: SuiAddress,
    /// The local lifecycle state recorded (reused from `rollback`).
    pub state: LocalSkillState,
    /// The approved capability-diff display digest — binds the
    /// receipt to the exact permissions the user approved.
    pub capability_approval_hash_32: [u8; 32],
    /// Offline Stage D trace link for the evidence trail.
    pub trace: StageDTraceLink,
}

impl LocalInstallReceipt {
    /// `true` iff the recorded state is runtime-executable (Installed/Enabled).
    /// A `Use` (DryRunPassed) receipt is NOT executable — it records a trial,
    /// not an install.
    #[inline]
    #[must_use]
    pub const fn is_executable(&self) -> bool {
        self.state.is_executable()
    }
}

/// Mint a local use/install receipt. The flow is:
/// 1. A revoked package is refused first ([`ReceiptError::Revoked`]).
/// 2. The [`InstallPlan`] is evaluated against `pre` and `observed_digest_32`;
///    a block (missing approval, failed dry-run, digest drift, …) returns
///    [`ReceiptError::Blocked`] with the exact reason.
/// 3. On [`InstallDecision::Proceed`] a deterministic receipt is minted in the
///    state for `kind`.
///
/// `capability_approval_hash_32` is the approved capability diff's
/// `human_digest_32`; `user`/`trace` are offline typed values.
///
/// The eight inputs are each a distinct, non-defaultable authority fact (kind,
/// plan, preconditions, observed digest, revocation, user, approval hash,
/// trace); grouping them would only hide the receipt's required provenance, so
/// the arity is intentional.
#[allow(clippy::too_many_arguments)]
pub fn mint_receipt(
    kind: LocalReceiptKind,
    plan: &InstallPlan,
    pre: &InstallPreconditions,
    observed_digest_32: &[u8; 32],
    package_revoked: bool,
    user: SuiAddress,
    capability_approval_hash_32: [u8; 32],
    trace: StageDTraceLink,
) -> Result<LocalInstallReceipt, ReceiptError> {
    if package_revoked {
        return Err(ReceiptError::Revoked);
    }
    match plan.evaluate(pre, observed_digest_32) {
        InstallDecision::Blocked(reason) => Err(ReceiptError::Blocked(reason)),
        InstallDecision::Proceed => {
            let state = kind.recorded_state();
            let id = LocalInstallReceiptId::derive(
                plan.skill,
                &plan.package,
                &user,
                state,
                &capability_approval_hash_32,
            );
            Ok(LocalInstallReceipt {
                id,
                skill: plan.skill,
                package: plan.package,
                user,
                state,
                capability_approval_hash_32,
                trace,
            })
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use crate::wasm_tier2::module_id::WasmTier2ModuleId;
    use mnemos_a_core::{StageBTraceLink, StageCTraceLink};

    fn link() -> StageDTraceLink {
        let b = StageBTraceLink::new(0xD315_0001, 315, 0);
        let c = StageCTraceLink::new(b, 240, 9);
        StageDTraceLink::new(c, 315, 1)
    }

    fn plan() -> InstallPlan {
        InstallPlan::new(
            SkillId(7),
            SkillPackageDigest32::new([0x44; 32]),
            WasmTier2ModuleId::from_bytes([0x55; 32]),
        )
    }

    fn user() -> SuiAddress {
        SuiAddress::new([0xAB; 32])
    }

    #[test]
    fn use_receipt_minted_on_proceed() {
        let r = mint_receipt(
            LocalReceiptKind::Use,
            &plan(),
            &InstallPreconditions::all_met(),
            &[0x44; 32],
            false,
            user(),
            [0x77; 32],
            link(),
        )
        .expect("use receipt must mint");
        assert_eq!(r.state, LocalSkillState::DryRunPassed);
        assert!(!r.is_executable(), "a use/trial receipt is not executable");
        assert_eq!(r.skill, SkillId(7));
    }

    #[test]
    fn install_receipt_minted_on_proceed() {
        let r = mint_receipt(
            LocalReceiptKind::Install,
            &plan(),
            &InstallPreconditions::all_met(),
            &[0x44; 32],
            false,
            user(),
            [0x77; 32],
            link(),
        )
        .expect("install receipt must mint");
        assert_eq!(r.state, LocalSkillState::Installed);
        assert!(r.is_executable());
    }

    #[test]
    fn missing_approval_rejected() {
        let mut pre = InstallPreconditions::all_met();
        pre.capability_approved = false;
        let err = mint_receipt(
            LocalReceiptKind::Install,
            &plan(),
            &pre,
            &[0x44; 32],
            false,
            user(),
            [0x77; 32],
            link(),
        )
        .expect_err("missing capability approval must reject");
        assert_eq!(
            err,
            ReceiptError::Blocked(InstallBlockReason::CapabilityNotApproved)
        );
    }

    #[test]
    fn dry_run_fail_rejected() {
        let mut pre = InstallPreconditions::all_met();
        pre.dry_run_passed = false;
        let err = mint_receipt(
            LocalReceiptKind::Use,
            &plan(),
            &pre,
            &[0x44; 32],
            false,
            user(),
            [0x77; 32],
            link(),
        )
        .expect_err("failed dry-run must reject");
        assert_eq!(
            err,
            ReceiptError::Blocked(InstallBlockReason::DryRunMissing)
        );
    }

    #[test]
    fn revoked_package_rejected_even_when_all_met() {
        let err = mint_receipt(
            LocalReceiptKind::Install,
            &plan(),
            &InstallPreconditions::all_met(),
            &[0x44; 32],
            true, // revoked
            user(),
            [0x77; 32],
            link(),
        )
        .expect_err("revoked package must reject");
        assert_eq!(err, ReceiptError::Revoked);
    }

    #[test]
    fn receipt_replay_deterministic() {
        let mk = || {
            mint_receipt(
                LocalReceiptKind::Install,
                &plan(),
                &InstallPreconditions::all_met(),
                &[0x44; 32],
                false,
                user(),
                [0x77; 32],
                link(),
            )
            .expect("mint")
        };
        let a = mk();
        let b = mk();
        assert_eq!(a.id, b.id, "same inputs must replay the same receipt id");
        assert_eq!(a, b);
        assert_ne!(a.id.as_bytes(), &[0u8; 32]);
    }

    #[test]
    fn compatibility_gate_admits_only_compatible_or_warn() {
        assert!(compatibility_admits_install(
            CompatibilityDecision::Compatible
        ));
        assert!(compatibility_admits_install(CompatibilityDecision::Warn));
        assert!(!compatibility_admits_install(
            CompatibilityDecision::Incompatible
        ));
        assert!(!compatibility_admits_install(
            CompatibilityDecision::Unknown
        ));
    }
}
