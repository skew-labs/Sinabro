//! PTB dry-run builders for the skill-registry actions.
//!
//! The dry-run path is SEPARATE from any execute path: these builders mutate no
//! state, sign nothing, touch no wallet, and read no secret. Each builder emits
//! an effect-shape ([`mnemos_d_move::stage_c_effect_delta::EffectDelta`]) so a
//! Gas Station can reason about the call, and is gated by the
//! [`GasStationPolicy`] (package binding + gas cap + wildcard reject).
//!
//! Sponsorship is LIMITED by the policy and NO new sponsorable function is
//! minted here, so skill payment and gas sponsorship never share a ledger
//! (no-commerce). The action set is a closed enum — an arbitrary transfer or
//! opaque call is unrepresentable, and a wildcard policy is rejected. Offline /
//! read-only / status-only; mainnet locked.

use mnemos_d_move::stage_c_effect_delta::EffectDelta;
use mnemos_d_move::types::{GasBudgetMist, ObjectId};
use mnemos_g_wallet::stage_c_gas_policy::{GasStationPolicy, GasStationRejectReason};

/// The dry-run-able skill-registry actions — one per state-changing Move entry.
/// This enum is closed: an arbitrary transfer / opaque call cannot be expressed.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
#[repr(u8)]
pub enum SkillPtbAction {
    /// `skill_registry::publish_skill`.
    Publish = 1,
    /// `skill_registry::fork_skill`.
    Fork = 2,
    /// `skill_registry::update_skill_metadata`.
    UpdateMetadata = 3,
    /// `install_receipt::record_install`.
    RecordInstall = 4,
    /// `install_receipt::enable_install`.
    EnableInstall = 5,
    /// `install_receipt::disable_install`.
    DisableInstall = 6,
    /// `install_receipt::remove_install`.
    RemoveInstall = 7,
    /// `install_receipt::revoke_install`.
    RevokeInstall = 8,
}

impl SkillPtbAction {
    /// The raw discriminant byte.
    #[inline]
    #[must_use]
    pub const fn as_u8(self) -> u8 {
        self as u8
    }

    /// All eight actions, in discriminant order.
    #[inline]
    #[must_use]
    pub const fn all() -> [Self; 8] {
        [
            Self::Publish,
            Self::Fork,
            Self::UpdateMetadata,
            Self::RecordInstall,
            Self::EnableInstall,
            Self::DisableInstall,
            Self::RemoveInstall,
            Self::RevokeInstall,
        ]
    }

    /// The Move module that owns the entry.
    #[inline]
    #[must_use]
    pub const fn move_module(self) -> &'static str {
        match self {
            Self::Publish | Self::Fork | Self::UpdateMetadata => "skill_registry",
            Self::RecordInstall
            | Self::EnableInstall
            | Self::DisableInstall
            | Self::RemoveInstall
            | Self::RevokeInstall => "install_receipt",
        }
    }

    /// The Move entry-function name.
    #[inline]
    #[must_use]
    pub const fn move_function(self) -> &'static str {
        match self {
            Self::Publish => "publish_skill",
            Self::Fork => "fork_skill",
            Self::UpdateMetadata => "update_skill_metadata",
            Self::RecordInstall => "record_install",
            Self::EnableInstall => "enable_install",
            Self::DisableInstall => "disable_install",
            Self::RemoveInstall => "remove_install",
            Self::RevokeInstall => "revoke_install",
        }
    }
}

/// A non-mutating dry-run plan for one skill-registry action. Carries the BCS
/// args, the gas budget, and the expected effect shape. No signing material, no
/// secret, no payment field.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SkillPtbDryRun {
    /// The action being dry-run.
    pub action: SkillPtbAction,
    /// The skill-registry package object id.
    pub package_id: ObjectId,
    /// The BCS-encoded call arguments (see [`crate::chain_bindings`]).
    pub args_bcs: Vec<u8>,
    /// The gas budget for the dry-run.
    pub gas: GasBudgetMist,
    /// The expected object / event / storage effect shape.
    pub effect: EffectDelta,
}

impl SkillPtbDryRun {
    /// A one-line effect-shape JSONL record for Gas Station policy evidence.
    /// Carries only structural counts — never a secret, key, or payment field.
    #[must_use]
    pub fn effect_jsonl(&self) -> String {
        let e = &self.effect;
        format!(
            "{{\"action\":{},\"module\":\"{}\",\"function\":\"{}\",\"args_bcs_len\":{},\"gas_mist\":{},\"object_writes\":{},\"event_count\":{},\"event_bytes\":{},\"net_storage_mist\":{}}}",
            self.action.as_u8(),
            self.action.move_module(),
            self.action.move_function(),
            self.args_bcs.len(),
            self.gas.get(),
            e.object_writes_u16,
            e.event_count_u16,
            e.event_bytes_u32,
            e.net_storage_mist(),
        )
    }
}

/// The expected effect shape of a state-changing skill action: one object write
/// (the shared registry or the receipt) and exactly one event. Pure; runs nothing.
#[must_use]
fn effect_for(event_bytes: u32) -> EffectDelta {
    EffectDelta {
        object_writes_u16: 1,
        event_count_u16: 1,
        event_bytes_u32: event_bytes,
        storage_cost_mist_u64: 0,
        storage_rebate_mist_u64: 0,
    }
}

/// Build a dry-run plan for `action`, gated by the C Gas Station policy: the
/// wildcard-allowlist check, the package binding, and the per-tx gas cap. Returns
/// the policy reject reason on denial. This mutates NO state and signs NOTHING.
///
/// # Errors
/// Returns [`GasStationRejectReason`] when the policy rejects the wildcard mask,
/// the presented package, or the gas budget.
pub fn build_dry_run(
    action: SkillPtbAction,
    package_id: ObjectId,
    args_bcs: Vec<u8>,
    gas: GasBudgetMist,
    event_bytes: u32,
    policy: &GasStationPolicy,
) -> Result<SkillPtbDryRun, GasStationRejectReason> {
    policy.reject_if_wildcard()?;
    policy.check_package(package_id)?;
    policy.check_gas_budget(gas)?;
    Ok(SkillPtbDryRun {
        action,
        package_id,
        args_bcs,
        gas,
        effect: effect_for(event_bytes),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use mnemos_g_wallet::stage_c_gas_policy::GasSponsorMode;

    fn pkg() -> ObjectId {
        ObjectId::new([0x5Au8; 32])
    }

    fn other_pkg() -> ObjectId {
        ObjectId::new([0x6Bu8; 32])
    }

    fn policy_for(p: ObjectId, allowed_mask_u16: u16) -> GasStationPolicy {
        GasStationPolicy {
            mode: GasSponsorMode::SelfHosted,
            package: p,
            max_gas_per_tx: GasBudgetMist::new(1_000_000),
            max_txs_per_epoch_u32: 100,
            max_storage_bytes_u32: 100_000,
            allowed_mask_u16,
            update_semantics_via_add_chunk: false,
            require_official_safety_kernel: false,
        }
    }

    #[test]
    fn each_action_dry_run_ok() {
        let policy = policy_for(pkg(), GasStationPolicy::INITIAL_ALLOWED_MASK);
        let actions = SkillPtbAction::all();
        let mut i = 0usize;
        while i < actions.len() {
            let dr = build_dry_run(
                actions[i],
                pkg(),
                vec![1, 2, 3],
                GasBudgetMist::new(10_000),
                64,
                &policy,
            );
            assert!(dr.is_ok());
            if let Ok(plan) = dr {
                assert_eq!(plan.effect.event_count_u16, 1);
                assert_eq!(plan.effect.object_writes_u16, 1);
                assert_eq!(plan.action, actions[i]);
            }
            i += 1;
        }
    }

    #[test]
    fn wrong_package_rejected() {
        let policy = policy_for(pkg(), GasStationPolicy::INITIAL_ALLOWED_MASK);
        let dr = build_dry_run(
            SkillPtbAction::Publish,
            other_pkg(),
            vec![],
            GasBudgetMist::new(10_000),
            64,
            &policy,
        );
        assert_eq!(dr, Err(GasStationRejectReason::PackageFunction));
    }

    #[test]
    fn over_budget_rejected() {
        let policy = policy_for(pkg(), GasStationPolicy::INITIAL_ALLOWED_MASK);
        let dr = build_dry_run(
            SkillPtbAction::Publish,
            pkg(),
            vec![],
            GasBudgetMist::new(9_999_999),
            64,
            &policy,
        );
        assert_eq!(dr, Err(GasStationRejectReason::Budget));
    }

    #[test]
    fn wildcard_policy_rejected() {
        // a wildcard/arbitrary allowlist (reserved bits set) is denied before any call.
        let policy = policy_for(pkg(), 0xFFFF);
        let dr = build_dry_run(
            SkillPtbAction::Publish,
            pkg(),
            vec![],
            GasBudgetMist::new(10_000),
            64,
            &policy,
        );
        assert_eq!(dr, Err(GasStationRejectReason::Wildcard));
    }

    #[test]
    fn effect_jsonl_has_no_secret_field() {
        let policy = policy_for(pkg(), GasStationPolicy::INITIAL_ALLOWED_MASK);
        let dr = build_dry_run(
            SkillPtbAction::RecordInstall,
            pkg(),
            vec![0; 10],
            GasBudgetMist::new(10_000),
            100,
            &policy,
        );
        assert!(dr.is_ok());
        if let Ok(plan) = dr {
            let line = plan.effect_jsonl();
            assert!(line.contains("\"function\":\"record_install\""));
            assert!(line.contains("\"event_count\":1"));
            assert!(!line.contains("secret"));
            assert!(!line.contains("key"));
            assert!(!line.contains("price"));
        }
    }

    #[test]
    fn action_metadata() {
        assert_eq!(SkillPtbAction::Publish.move_module(), "skill_registry");
        assert_eq!(
            SkillPtbAction::RecordInstall.move_module(),
            "install_receipt"
        );
        assert_eq!(
            SkillPtbAction::RevokeInstall.move_function(),
            "revoke_install"
        );
        assert_eq!(SkillPtbAction::all().len(), 8);
    }
}
