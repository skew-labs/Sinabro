//! `deny_audit.json` parser → structured deny/pass labels.
//!
//! Dependency advisories, bans, licenses, and unknown sources become explicit
//! per-category clean/deny booleans. Each category reads either an array (clean
//! ⇔ empty) or a boolean flag; an absent category defaults clean (nothing
//! denied this atom).
use crate::diet_kind::DietFileKind;
use crate::error::{DietError, DietResult};
use crate::parse_json;
use serde_json::Value;

const KIND: DietFileKind = DietFileKind::DenyAudit;

/// Normalized cargo-deny categories.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub struct DenyAudit {
    /// No security advisory hit.
    pub advisory_clean: bool,
    /// No banned crate.
    pub bans_clean: bool,
    /// No denied license.
    pub license_clean: bool,
    /// No unknown dependency source.
    pub sources_clean: bool,
}

impl DenyAudit {
    /// Whether any category recorded a deny.
    pub const fn any_deny(&self) -> bool {
        !(self.advisory_clean && self.bans_clean && self.license_clean && self.sources_clean)
    }
}

fn category_clean(obj: &serde_json::Map<String, Value>, array_key: &str, bool_key: &str) -> bool {
    if let Some(arr) = obj.get(array_key).and_then(|v| v.as_array()) {
        return arr.is_empty();
    }
    if let Some(b) = obj.get(bool_key).and_then(|v| v.as_bool()) {
        return b;
    }
    true
}

/// Parse a `deny_audit.json` document into per-category clean flags.
pub fn parse(text: &str) -> DietResult<DenyAudit> {
    let v = parse_json(KIND, text)?;
    let obj = v.as_object().ok_or(DietError::UnexpectedType {
        kind: KIND,
        field: "$root",
    })?;
    Ok(DenyAudit {
        advisory_clean: category_clean(obj, "advisories", "advisory_surface_unchanged"),
        bans_clean: category_clean(obj, "bans", "bans_clean"),
        license_clean: category_clean(obj, "licenses_denied", "license_surface_unchanged"),
        sources_clean: category_clean(obj, "unknown_sources", "sources_clean"),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn clean_pass_has_no_deny() -> DietResult<()> {
        let d = parse(r#"{"advisories":[],"bans":[],"licenses_denied":[],"unknown_sources":[]}"#)?;
        assert!(!d.any_deny());
        Ok(())
    }

    #[test]
    fn advisory_hit_is_deny() -> DietResult<()> {
        let d = parse(r#"{"advisories":["RUSTSEC-2024-0001"]}"#)?;
        assert!(!d.advisory_clean);
        assert!(d.any_deny());
        Ok(())
    }

    #[test]
    fn banned_crate_is_deny() -> DietResult<()> {
        let d = parse(r#"{"bans":["openssl"]}"#)?;
        assert!(!d.bans_clean);
        Ok(())
    }

    #[test]
    fn license_deny_is_deny() -> DietResult<()> {
        let d = parse(r#"{"licenses_denied":["GPL-3.0"]}"#)?;
        assert!(!d.license_clean);
        Ok(())
    }

    #[test]
    fn unknown_source_is_deny() -> DietResult<()> {
        let d = parse(r#"{"unknown_sources":["git://example.invalid/x"]}"#)?;
        assert!(!d.sources_clean);
        Ok(())
    }

    #[test]
    fn boolean_flag_fallback_is_honored() -> DietResult<()> {
        let d = parse(r#"{"advisory_surface_unchanged":false}"#)?;
        assert!(!d.advisory_clean);
        Ok(())
    }
}
