//! `mnemos-e-skill::catalog_card` — atoms #298 / #299 / #301 · D.3.2–D.3.5 —
//! progressive-disclosure catalog cards.
//!
//! Progressive disclosure (#298): the first listing shows only a lightweight
//! [`SkillCardSummary`] — name hash, verified installs, eval, security,
//! compatibility, and a high-level [`CapabilityClass`]. The full manifest /
//! WASM / docs and the eval / security / provenance detail (#299,
//! [`SkillCardDetail`]) load only on an explicit `inspect`.
//!
//! Permission-diff-first (#301): every card *requires* a [`CapabilityDiff`]
//! (`capability_diff` is not optional), so a card can never hide a permission
//! delta, and [`order_cards_permission_first`] surfaces high-risk cards before
//! the use / install CTA. No-commerce (#298, reuses #243): a card carries only
//! counts, never a price / payment field — [`SkillCardSummary::to_contract_string`]
//! passes [`crate::package_policy::scan_no_commerce`].

#![deny(missing_docs)]

extern crate alloc;

use alloc::string::String;

use crate::capability_diff::{CapabilityDiff, SkillRuntimePermission};
use crate::catalog_index::SkillCatalogIndexEntry;
use crate::compat::CompatibilityDecision;
use crate::eval::SkillEvalScore;
use crate::manifest::SkillId;
use crate::package::SkillSecurityState;
use crate::permission_preview::{self, PermissionPreview, PreviewGate, gate_action};
use crate::provenance::ProvenanceNode;

/// A coarse, listing-safe summary of a skill's capability footprint. The
/// highest-risk class present wins, so a wallet/secret skill can never be shown
/// as merely read-only.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum CapabilityClass {
    /// No write/network/wallet/secret capability added (reads only).
    ReadOnly,
    /// Adds memory-write capability.
    MemoryWrite,
    /// Adds host file-write capability.
    FileWrite,
    /// Adds network and/or chain capability.
    NetworkOrChain,
    /// Adds wallet and/or secret capability — the highest-risk class.
    WalletOrSecret,
}

impl CapabilityClass {
    /// Derive the high-level class from a capability diff's added-permission
    /// mask. The order is risk-descending so the riskiest present class wins.
    #[must_use]
    pub fn from_added_mask(added_mask_u64: u64) -> Self {
        let has = |p: SkillRuntimePermission| added_mask_u64 & p.mask_bit() != 0;
        if has(SkillRuntimePermission::Wallet) || has(SkillRuntimePermission::Secret) {
            Self::WalletOrSecret
        } else if has(SkillRuntimePermission::Network) || has(SkillRuntimePermission::Chain) {
            Self::NetworkOrChain
        } else if has(SkillRuntimePermission::FileWrite) {
            Self::FileWrite
        } else if has(SkillRuntimePermission::MemoryWrite) {
            Self::MemoryWrite
        } else {
            Self::ReadOnly
        }
    }

    /// Stable, leak-free class label.
    #[must_use]
    pub const fn class_label(self) -> &'static str {
        match self {
            Self::ReadOnly => "capability_class.read_only",
            Self::MemoryWrite => "capability_class.memory_write",
            Self::FileWrite => "capability_class.file_write",
            Self::NetworkOrChain => "capability_class.network_or_chain",
            Self::WalletOrSecret => "capability_class.wallet_or_secret",
        }
    }
}

/// The lightweight catalog card shown in a first listing (#298). Cheap to build
/// and serialize; the heavy detail is deferred to [`SkillCardDetail`].
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SkillCardSummary {
    /// Skill id.
    pub skill: SkillId,
    /// Hash of the human-facing name (short-description proxy).
    pub name_hash_32: [u8; 32],
    /// Verified-install count (the strong signal shown in listings).
    pub verified_installs_u64: u64,
    /// Eval score.
    pub eval: SkillEvalScore,
    /// Security state.
    pub security: SkillSecurityState,
    /// Compatibility decision.
    pub compatibility: CompatibilityDecision,
    /// High-level capability class.
    pub capability_class: CapabilityClass,
    /// The full capability diff — required (#301), never optional, so a card
    /// can never hide the permission delta.
    pub capability_diff: CapabilityDiff,
    /// Whether any added permission is high-risk (#301).
    pub high_risk: bool,
    /// Whether the eval is missing / invalid (a listing warning, #298).
    pub eval_warning: bool,
}

impl SkillCardSummary {
    /// Build the lightweight summary from a catalog index entry (#298). Derives
    /// the capability class, the high-risk flag (via #270 permission preview),
    /// and the eval warning; clones the required capability diff.
    #[must_use]
    pub fn from_index_entry(entry: &SkillCatalogIndexEntry) -> Self {
        let preview = PermissionPreview::from_diff(&entry.capability_diff);
        Self {
            skill: entry.skill,
            name_hash_32: entry.name_hash_32,
            verified_installs_u64: entry.verified_installs_u64,
            eval: entry.eval,
            security: entry.security,
            compatibility: entry.compatibility,
            capability_class: CapabilityClass::from_added_mask(
                entry.capability_diff.added_mask_u64,
            ),
            capability_diff: entry.capability_diff.clone(),
            high_risk: preview.high_risk,
            eval_warning: !entry.eval.is_valid(),
        }
    }

    /// `true` iff a skill in this security state may be installed (Quarantined /
    /// Revoked are not installable). Quarantined cards still *display*, they
    /// just cannot be installed.
    #[must_use]
    pub const fn is_installable(&self) -> bool {
        self.security.is_installable()
    }

    /// A stable, CLI/agent-serializable rendering of the card (#298 criterion).
    /// Emits only non-commerce scalar keys, so the result passes
    /// [`crate::package_policy::scan_no_commerce`] (#243).
    #[must_use]
    pub fn to_contract_string(&self) -> String {
        alloc::format!(
            "skill = {skill}\nverified_installs = {vi}\nsecurity = {sec}\ncompatibility = {compat}\ncapability_class = \"{cc}\"\nhigh_risk = {hr}\neval_warning = {ew}\n",
            skill = self.skill.0,
            vi = self.verified_installs_u64,
            sec = self.security as u8,
            compat = self.compatibility as u8,
            cc = self.capability_class.class_label(),
            hr = self.high_risk,
            ew = self.eval_warning,
        )
    }
}

/// The full inspect-time detail loaded only on demand (#299). Exposes the eval
/// reproducible-command hash, the malicious-fixture result, the audit state,
/// and the provenance parent. There is no card without a security state.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SkillCardDetail {
    /// The lightweight summary this detail expands.
    pub summary: SkillCardSummary,
    /// Reproducible-command hash backing the eval score.
    pub reproducible_command_hash_32: [u8; 32],
    /// Whether the malicious-fixture suite passed for this skill (#274
    /// red-team evidence; `false` blocks install).
    pub malicious_fixture_pass: bool,
    /// The audit / security state (mirrors the summary's security state).
    pub audit_state: SkillSecurityState,
    /// Content-addressed provenance (single parent or root).
    pub provenance: ProvenanceNode,
}

impl SkillCardDetail {
    /// Lazily load the full card detail for an entry (#299). `malicious_fixture_pass`
    /// is the #274 red-team verdict for this skill.
    #[must_use]
    pub fn inspect(entry: &SkillCatalogIndexEntry, malicious_fixture_pass: bool) -> Self {
        Self {
            summary: SkillCardSummary::from_index_entry(entry),
            reproducible_command_hash_32: entry.eval.reproducible_command_hash_32,
            malicious_fixture_pass,
            audit_state: entry.security,
            provenance: entry.provenance,
        }
    }
}

/// Order a slice of cards so high-risk permission cards appear **first** (#301),
/// before any use / install CTA. Stable sort with a skill-id tie-break, using
/// the #270 permission-preview risk key, so popularity can never bury a
/// high-risk permission below the fold.
pub fn order_cards_permission_first(cards: &mut [SkillCardSummary]) {
    cards.sort_by(|a, b| {
        let ka = permission_preview::high_risk_first_key(&PermissionPreview::from_diff(
            &a.capability_diff,
        ));
        let kb = permission_preview::high_risk_first_key(&PermissionPreview::from_diff(
            &b.capability_diff,
        ));
        ka.cmp(&kb).then_with(|| a.skill.0.cmp(&b.skill.0))
    });
}

/// Gate a card's use / install CTA on the presence of a **consistent**
/// capability diff (#301, reuses #270 [`gate_action`]). A hidden (inconsistent)
/// diff blocks the CTA — there is no permission-free path to use / install.
#[must_use]
pub fn card_cta_gate(card: &SkillCardSummary) -> PreviewGate {
    gate_action(Some(&card.capability_diff))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use crate::compat::{HostEnvironment, MnemosVersion};
    use crate::package_policy::scan_no_commerce;
    use crate::verify::sample_valid_package_toml;
    use alloc::vec;

    fn host() -> HostEnvironment {
        HostEnvironment {
            mnemos_version: MnemosVersion::new(0, 2, 0),
            chain_env_hash_32: [0xC0; 32],
            os_gpu_hash_32: [0x05; 32],
            toolchain_hash_32: [0x70; 32],
            model_provider_hash_32: [0x30; 32],
        }
    }

    fn entry() -> SkillCatalogIndexEntry {
        let toml = sample_valid_package_toml();
        SkillCatalogIndexEntry::from_package_toml(&toml, &host(), [0x99; 32], 50, 7, 3)
            .expect("valid package must index")
    }

    #[test]
    fn lightweight_card() {
        let card = SkillCardSummary::from_index_entry(&entry());
        assert_eq!(card.skill.0, 42);
        assert_eq!(card.verified_installs_u64, 7);
        // sample skill adds only MemoryRead -> read-only class, not high risk.
        assert_eq!(card.capability_class, CapabilityClass::ReadOnly);
        assert!(!card.high_risk);
    }

    #[test]
    fn full_inspect_lazy_load() {
        let e = entry();
        let detail = SkillCardDetail::inspect(&e, true);
        assert_eq!(detail.summary.skill.0, 42);
        assert_eq!(
            detail.reproducible_command_hash_32,
            e.eval.reproducible_command_hash_32
        );
        assert!(detail.malicious_fixture_pass);
        assert_eq!(detail.provenance, e.provenance);
    }

    #[test]
    fn missing_eval_warning() {
        let mut e = entry();
        // Zero the reproducible-command hash -> eval becomes invalid.
        e.eval.reproducible_command_hash_32 = [0; 32];
        let card = SkillCardSummary::from_index_entry(&e);
        assert!(card.eval_warning);
    }

    #[test]
    fn no_payment_fields() {
        let card = SkillCardSummary::from_index_entry(&entry());
        // The serialized card contract carries no commerce field (#243).
        assert!(scan_no_commerce(&card.to_contract_string()).is_ok());
    }

    #[test]
    fn overflow_reject() {
        // u64::MAX verified installs must not panic when built or serialized.
        let card = SkillCardSummary::from_index_entry(&entry().with_counters(
            u64::MAX,
            u64::MAX,
            u64::MAX,
        ));
        assert_eq!(card.verified_installs_u64, u64::MAX);
        assert!(!card.to_contract_string().is_empty());
    }

    #[test]
    fn sandbox_pass_card() {
        let mut e = entry();
        e.security = SkillSecurityState::SandboxPass;
        let card = SkillCardSummary::from_index_entry(&e);
        assert_eq!(card.security, SkillSecurityState::SandboxPass);
        assert!(card.is_installable());
    }

    #[test]
    fn audit_pass_card() {
        let mut e = entry();
        e.security = SkillSecurityState::AuditPass;
        let detail = SkillCardDetail::inspect(&e, true);
        assert_eq!(detail.audit_state, SkillSecurityState::AuditPass);
    }

    #[test]
    fn quarantined_display() {
        let mut e = entry();
        e.security = SkillSecurityState::Quarantined;
        let card = SkillCardSummary::from_index_entry(&e);
        // Still displays, but is not installable.
        assert_eq!(card.security, SkillSecurityState::Quarantined);
        assert!(!card.is_installable());
    }

    #[test]
    fn card_ordering_high_risk_first() {
        let mut wallet = SkillCardSummary::from_index_entry(&entry());
        wallet.skill = SkillId(7);
        wallet.capability_diff =
            CapabilityDiff::new(SkillRuntimePermission::Wallet.mask_bit(), 0, vec![]);
        wallet.high_risk = true;
        let read = SkillCardSummary::from_index_entry(&entry());
        let mut cards = vec![read.clone(), wallet.clone()];
        order_cards_permission_first(&mut cards);
        // The wallet (high-risk) card sorts first.
        assert_eq!(cards[0].skill.0, 7);
    }

    #[test]
    fn no_hidden_diff_blocks_cta() {
        let mut card = SkillCardSummary::from_index_entry(&entry());
        // Inject a hidden permission: an added mask that the a-capabilities do
        // not reflect -> inconsistent diff.
        let mut tampered =
            CapabilityDiff::new(SkillRuntimePermission::MemoryRead.mask_bit(), 0, vec![]);
        tampered.added_mask_u64 |= SkillRuntimePermission::Wallet.mask_bit();
        card.capability_diff = tampered;
        assert_eq!(card_cta_gate(&card), PreviewGate::Blocked);
    }
}
