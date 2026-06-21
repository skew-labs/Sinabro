//! Rust miri/fuzz/property deep signal (atom #353 · E.1.2).
//!
//! An `unsafe`/hot-path change is *not* reward-eligible unless deeper evidence
//! exists: an explicit `G-MIRI` pass (or a justified `N/A`), and no fuzz crash
//! or property counterexample. The presence of `unsafe` is read structurally
//! from the diff (#346 reuse); miri/fuzz/property verdicts are read from explicit
//! gate statuses, never from prose.
use crate::collect::gate_status;
use crate::diet_kind::AtomDietKey;
use crate::diff;
use crate::error::DietResult;
use crate::gate_results::{GateStatus, parse_gates};

/// Rust deep-verification signal (miri / fuzz / property).
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub struct RustDeepSignal {
    /// The source atom.
    pub key: AtomDietKey,
    /// Explicit `G-MIRI` status (`Unknown` when absent).
    pub miri: GateStatus,
    /// `G-FUZZ` reported an explicit fail (a crash was found).
    pub fuzz_crash: bool,
    /// `G-PROPERTY` reported an explicit fail (a counterexample was found).
    pub property_counterexample: bool,
    /// The diff added an `unsafe` block/fn (#346 structural detection).
    pub has_unsafe: bool,
    /// Deep evidence is sufficient: either no `unsafe`, or miri passed / is a
    /// justified `N/A`; and no fuzz crash and no property counterexample.
    pub deep_evidence_sufficient: bool,
}

/// Collect a [`RustDeepSignal`] from a `gate_results.json` document and an
/// optional `code_diff.patch`. A malformed patch is propagated (fail-closed).
pub fn collect(
    key: AtomDietKey,
    gate_results_json: &str,
    code_diff_patch: Option<&str>,
) -> DietResult<RustDeepSignal> {
    let gates = parse_gates(gate_results_json)?;
    let miri = gate_status(&gates, "G-MIRI");
    let fuzz_crash = matches!(gate_status(&gates, "G-FUZZ"), GateStatus::Fail);
    let property_counterexample = matches!(gate_status(&gates, "G-PROPERTY"), GateStatus::Fail);
    let has_unsafe = match code_diff_patch {
        Some(p) => diff::parse(p)?.has_unsafe,
        None => false,
    };
    let miri_ok = matches!(miri, GateStatus::Pass | GateStatus::NotApplicable);
    let deep_evidence_sufficient =
        (!has_unsafe || miri_ok) && !fuzz_crash && !property_counterexample;
    Ok(RustDeepSignal {
        key,
        miri,
        fuzz_crash,
        property_counterexample,
        has_unsafe,
        deep_evidence_sufficient,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::diet_kind::DietSourceStage;

    fn key() -> AtomDietKey {
        AtomDietKey::new(DietSourceStage::StageD, 353)
    }

    const UNSAFE_PATCH: &str = "--- a/x.rs\n+++ b/x.rs\n@@ -0,0 +1,1 @@\n+    unsafe { *p }\n";
    const SAFE_PATCH: &str = "--- a/x.rs\n+++ b/x.rs\n@@ -0,0 +1,1 @@\n+    let x = 1;\n";

    #[test]
    fn miri_pass_with_unsafe_is_sufficient() -> DietResult<()> {
        let gates = r#"{"gate_set":["G-MIRI"],"G-MIRI":{"status":"PASS"}}"#;
        let s = collect(key(), gates, Some(UNSAFE_PATCH))?;
        assert_eq!(s.miri, GateStatus::Pass);
        assert!(s.has_unsafe);
        assert!(s.deep_evidence_sufficient);
        Ok(())
    }

    #[test]
    fn miri_fail_with_unsafe_is_insufficient() -> DietResult<()> {
        let gates = r#"{"gate_set":["G-MIRI"],"G-MIRI":{"status":"FAIL"}}"#;
        let s = collect(key(), gates, Some(UNSAFE_PATCH))?;
        assert_eq!(s.miri, GateStatus::Fail);
        assert!(!s.deep_evidence_sufficient);
        Ok(())
    }

    #[test]
    fn fuzz_crash_blocks_even_safe_code() -> DietResult<()> {
        let gates = r#"{"gate_set":["G-FUZZ"],"G-FUZZ":{"status":"FAIL"}}"#;
        let s = collect(key(), gates, Some(SAFE_PATCH))?;
        assert!(s.fuzz_crash);
        assert!(!s.deep_evidence_sufficient);
        Ok(())
    }

    #[test]
    fn property_counterexample_blocks() -> DietResult<()> {
        let gates = r#"{"gate_set":["G-PROPERTY"],"G-PROPERTY":{"status":"FAIL"}}"#;
        let s = collect(key(), gates, None)?;
        assert!(s.property_counterexample);
        assert!(!s.deep_evidence_sufficient);
        Ok(())
    }

    #[test]
    fn justified_na_miri_with_unsafe_is_sufficient() -> DietResult<()> {
        // miri marked N/A (e.g. unsupported on this target) with a reason still
        // counts as justified evidence for an unsafe change.
        let gates = r#"{"gate_set":["G-MIRI"],"G-MIRI":{"status":"N/A_NOT_VERIFIED"}}"#;
        let s = collect(key(), gates, Some(UNSAFE_PATCH))?;
        assert_eq!(s.miri, GateStatus::NotApplicable);
        assert!(s.deep_evidence_sufficient);
        Ok(())
    }

    #[test]
    fn safe_code_without_miri_is_still_sufficient() -> DietResult<()> {
        let gates = r#"{"gate_set":[]}"#;
        let s = collect(key(), gates, Some(SAFE_PATCH))?;
        assert!(!s.has_unsafe);
        assert!(s.deep_evidence_sufficient);
        Ok(())
    }
}
