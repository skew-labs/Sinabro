//! skill / WASM / registry signal.
//!
//! A skill install/use is reward-relevant only when *all seven* trust facts
//! agree: a signed package, a capability diff, a sandbox dry-run, an
//! eval/security pass, recorded provenance, a user confirmation, and an install
//! receipt. Commerce-shaped data is reject/quarantine, never reward; a malicious
//! WASM verdict denies. Any missing fact defaults `false` (fail-closed).
//!
//! The skill evidence is a Stage D trust surface, not one of the 21 sidecar
//! kinds; [`DietFileKind::RedteamDecision`] is used only as the error-context tag
//! (a security/red-team-adjacent label), never as a claim about the file name.
use crate::diet_kind::{AtomDietKey, DietFileKind};
use crate::error::DietResult;
use crate::{as_object, opt_bool, parse_json};

const CARRIER: DietFileKind = DietFileKind::RedteamDecision;

/// skill / WASM / registry trust signal.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub struct SkillRegistrySignal {
    /// The source atom.
    pub key: AtomDietKey,
    /// The skill package was signed.
    pub signed_package: bool,
    /// A capability (permission) diff was recorded.
    pub capability_diff_present: bool,
    /// A sandbox dry-run was performed.
    pub sandbox_dry_run: bool,
    /// The eval/security check passed.
    pub eval_security_pass: bool,
    /// Provenance was recorded.
    pub provenance_present: bool,
    /// The user confirmed the install/use.
    pub user_confirmed: bool,
    /// An install receipt was recorded.
    pub install_receipt_present: bool,
    /// The evidence is commerce-shaped (reject/quarantine, never reward).
    pub commerce_shaped: bool,
    /// A malicious WASM verdict was recorded (deny).
    pub wasm_malicious_deny: bool,
    /// Reward precondition: all seven trust facts agree, no commerce, no
    /// malicious WASM.
    pub reward_eligible: bool,
}

/// Collect a [`SkillRegistrySignal`] from a skill trust-evidence JSON document.
pub fn collect(key: AtomDietKey, skill_json: &str) -> DietResult<SkillRegistrySignal> {
    let v = parse_json(CARRIER, skill_json)?;
    let obj = as_object(&v, CARRIER, "$root")?;
    let flag = |field: &str| opt_bool(obj, field).unwrap_or(false);

    let signed_package = flag("signed_package");
    let capability_diff_present = flag("capability_diff_present");
    let sandbox_dry_run = flag("sandbox_dry_run");
    let eval_security_pass = flag("eval_security_pass");
    let provenance_present = flag("provenance_present");
    let user_confirmed = flag("user_confirmed");
    let install_receipt_present = flag("install_receipt_present");
    let commerce_shaped = flag("commerce_shaped");
    let wasm_malicious_deny = flag("wasm_malicious_deny");

    let reward_eligible = signed_package
        && capability_diff_present
        && sandbox_dry_run
        && eval_security_pass
        && provenance_present
        && user_confirmed
        && install_receipt_present
        && !commerce_shaped
        && !wasm_malicious_deny;

    Ok(SkillRegistrySignal {
        key,
        signed_package,
        capability_diff_present,
        sandbox_dry_run,
        eval_security_pass,
        provenance_present,
        user_confirmed,
        install_receipt_present,
        commerce_shaped,
        wasm_malicious_deny,
        reward_eligible,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::diet_kind::DietSourceStage;

    fn key() -> AtomDietKey {
        AtomDietKey::new(DietSourceStage::StageD, 363)
    }

    const ALL_TRUE: &str = r#"{"signed_package":true,"capability_diff_present":true,"sandbox_dry_run":true,"eval_security_pass":true,"provenance_present":true,"user_confirmed":true,"install_receipt_present":true,"commerce_shaped":false,"wasm_malicious_deny":false}"#;

    #[test]
    fn install_receipt_fixture_is_reward_eligible() -> DietResult<()> {
        let s = collect(key(), ALL_TRUE)?;
        assert!(s.reward_eligible);
        Ok(())
    }

    #[test]
    fn commerce_shaped_is_quarantined() -> DietResult<()> {
        let doc = ALL_TRUE.replace("\"commerce_shaped\":false", "\"commerce_shaped\":true");
        let s = collect(key(), &doc)?;
        assert!(s.commerce_shaped);
        assert!(!s.reward_eligible);
        Ok(())
    }

    #[test]
    fn malicious_wasm_denies() -> DietResult<()> {
        let doc = ALL_TRUE.replace(
            "\"wasm_malicious_deny\":false",
            "\"wasm_malicious_deny\":true",
        );
        let s = collect(key(), &doc)?;
        assert!(s.wasm_malicious_deny);
        assert!(!s.reward_eligible);
        Ok(())
    }

    #[test]
    fn missing_capability_diff_is_no_reward() -> DietResult<()> {
        // capability_diff_present absent => defaults false => not eligible.
        let doc = r#"{"signed_package":true,"sandbox_dry_run":true,"eval_security_pass":true,"provenance_present":true,"user_confirmed":true,"install_receipt_present":true}"#;
        let s = collect(key(), doc)?;
        assert!(!s.capability_diff_present);
        assert!(!s.reward_eligible);
        Ok(())
    }
}
