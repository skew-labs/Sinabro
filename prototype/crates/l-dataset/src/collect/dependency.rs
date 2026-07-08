//! Dependency / security audit signal.
//!
//! A dependency advisory, a banned crate, a denied license, or an unknown source
//! can override an otherwise good compile/test reward. This collector lifts the
//! per-category clean flags from `deny_audit.json` into a reward
//! *override block*: any deny blocks reward regardless of how green the build is.
use crate::deny_audit;
use crate::diet_kind::AtomDietKey;
use crate::error::DietResult;

/// dependency / security audit signal derived from `deny_audit.json`.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub struct DependencySignal {
    /// The source atom.
    pub key: AtomDietKey,
    /// No security advisory hit.
    pub advisory_clean: bool,
    /// No banned crate.
    pub bans_clean: bool,
    /// No denied license.
    pub license_clean: bool,
    /// No unknown dependency source.
    pub sources_clean: bool,
    /// Any category recorded a deny.
    pub any_deny: bool,
    /// A denied license quarantines the sample (license risk is special-cased).
    pub license_quarantine: bool,
    /// Any deny blocks reward regardless of compile/test success.
    pub reward_override_block: bool,
}

/// Collect a [`DependencySignal`] from a `deny_audit.json` document.
pub fn collect(key: AtomDietKey, deny_audit_json: &str) -> DietResult<DependencySignal> {
    let d = deny_audit::parse(deny_audit_json)?;
    Ok(DependencySignal {
        key,
        advisory_clean: d.advisory_clean,
        bans_clean: d.bans_clean,
        license_clean: d.license_clean,
        sources_clean: d.sources_clean,
        any_deny: d.any_deny(),
        license_quarantine: !d.license_clean,
        reward_override_block: d.any_deny(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::diet_kind::DietSourceStage;

    fn key() -> AtomDietKey {
        AtomDietKey::new(DietSourceStage::StageD, 355)
    }

    #[test]
    fn clean_pass_does_not_block_reward() -> DietResult<()> {
        let doc = r#"{"advisories":[],"bans":[],"licenses_denied":[],"unknown_sources":[]}"#;
        let s = collect(key(), doc)?;
        assert!(!s.any_deny);
        assert!(!s.reward_override_block);
        assert!(!s.license_quarantine);
        Ok(())
    }

    #[test]
    fn advisory_is_no_reward() -> DietResult<()> {
        let s = collect(key(), r#"{"advisories":["RUSTSEC-2024-0001"]}"#)?;
        assert!(!s.advisory_clean);
        assert!(s.reward_override_block);
        Ok(())
    }

    #[test]
    fn banned_crate_denies_reward() -> DietResult<()> {
        let s = collect(key(), r#"{"bans":["openssl"]}"#)?;
        assert!(!s.bans_clean);
        assert!(s.reward_override_block);
        Ok(())
    }

    #[test]
    fn denied_license_quarantines() -> DietResult<()> {
        let s = collect(key(), r#"{"licenses_denied":["GPL-3.0"]}"#)?;
        assert!(!s.license_clean);
        assert!(s.license_quarantine);
        assert!(s.reward_override_block);
        Ok(())
    }
}
