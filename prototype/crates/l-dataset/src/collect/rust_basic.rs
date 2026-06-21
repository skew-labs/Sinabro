//! Rust fmt/clippy/test basic signal (atom #352 · E.1.1, §4.4 `RustSignal`).
//!
//! fmt/clippy/test pass is read from the *explicit* gate status and parsed test
//! totals — never inferred from a prose summary. A gate that is missing or whose
//! status is unrecognized is not green (fail-closed). `miri_pass` mirrors an
//! explicit `G-MIRI` gate only (the deep miri/fuzz/property surface is atom
//! #353); `criterion_hash_32` is the perf anchor filled by atom #354 and is the
//! `"none"` sentinel here.
use crate::collect::gate_pass;
use crate::diet_kind::AtomDietKey;
use crate::error::DietResult;
use crate::gate_results::{parse_gates, parse_tests};

/// Rust basic signal (§4.4 `RustSignal`).
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub struct RustSignal {
    /// The source atom.
    pub key: AtomDietKey,
    /// `cargo fmt --all --check` (`G-FMT`) was an explicit pass.
    pub fmt_pass: bool,
    /// `cargo clippy … -D warnings` (`G-CLIPPY`) was an explicit pass.
    pub clippy_pass: bool,
    /// Parsed test totals showed `failed == 0` and `passed > 0`.
    pub tests_pass: bool,
    /// `G-MIRI` was an explicit pass (the deep miri surface is atom #353).
    pub miri_pass: bool,
    /// Perf anchor — `sha256("none")` until atom #354 fills it.
    pub criterion_hash_32: [u8; 32],
}

/// Collect a [`RustSignal`] from a `gate_results.json` document and an optional
/// `test_results.json` document. `tests_pass` requires explicit non-zero passed
/// and zero failed; an absent test file is not a pass.
pub fn collect(
    key: AtomDietKey,
    gate_results_json: &str,
    test_results_json: Option<&str>,
) -> DietResult<RustSignal> {
    let gates = parse_gates(gate_results_json)?;
    let tests_pass = match test_results_json {
        Some(t) => {
            let to = parse_tests(t)?;
            to.failed_u32 == 0 && to.passed_u32 > 0
        }
        None => false,
    };
    Ok(RustSignal {
        key,
        fmt_pass: gate_pass(&gates, "G-FMT"),
        clippy_pass: gate_pass(&gates, "G-CLIPPY"),
        tests_pass,
        miri_pass: gate_pass(&gates, "G-MIRI"),
        criterion_hash_32: crate::sha256(b"none"),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::diet_kind::DietSourceStage;

    fn key() -> AtomDietKey {
        AtomDietKey::new(DietSourceStage::StageD, 352)
    }

    #[test]
    fn fmt_pass_clippy_pass_tests_pass() -> DietResult<()> {
        let gates = r#"{"gate_set":["G-FMT","G-CLIPPY","G-TEST"],"G-FMT":{"status":"PASS"},"G-CLIPPY":{"status":"PASS"},"G-TEST":{"status":"PASS"}}"#;
        let tests = r#"{"summary":{"passed":144,"failed":0,"ignored":2}}"#;
        let s = collect(key(), gates, Some(tests))?;
        assert!(s.fmt_pass);
        assert!(s.clippy_pass);
        assert!(s.tests_pass);
        assert!(!s.miri_pass);
        assert_eq!(s.criterion_hash_32, crate::sha256(b"none"));
        Ok(())
    }

    #[test]
    fn clippy_warning_fail_is_not_pass() -> DietResult<()> {
        let gates = r#"{"gate_set":["G-FMT","G-CLIPPY"],"G-FMT":{"status":"PASS"},"G-CLIPPY":{"status":"FAIL"}}"#;
        let s = collect(key(), gates, None)?;
        assert!(s.fmt_pass);
        assert!(!s.clippy_pass);
        Ok(())
    }

    #[test]
    fn nextest_and_cargo_test_counts_drive_tests_pass() -> DietResult<()> {
        // failing tests => not a pass even when the count is non-zero.
        let gates = r#"{"gate_set":["G-FMT"],"G-FMT":{"status":"PASS"}}"#;
        let failing = collect(
            key(),
            gates,
            Some(r#"{"summary":{"passed":10,"failed":3}}"#),
        )?;
        assert!(!failing.tests_pass);
        // zero tests is not a pass.
        let zero = collect(key(), gates, Some(r#"{"summary":{"passed":0,"failed":0}}"#))?;
        assert!(!zero.tests_pass);
        Ok(())
    }

    #[test]
    fn false_pass_fixture_without_explicit_status_is_not_green() -> DietResult<()> {
        // G-FMT is listed but has no status object (prose-only "looks fine"):
        // the parser yields Unknown, so fmt_pass must be false.
        let gates = r#"{"gate_set":["G-FMT"],"note":"fmt looks fine"}"#;
        let s = collect(key(), gates, None)?;
        assert!(!s.fmt_pass);
        assert!(!s.tests_pass);
        Ok(())
    }

    #[test]
    fn missing_test_file_is_not_a_pass() -> DietResult<()> {
        let gates = r#"{"gate_set":["G-TEST"],"G-TEST":{"status":"PASS"}}"#;
        let s = collect(key(), gates, None)?;
        assert!(!s.tests_pass);
        Ok(())
    }
}
