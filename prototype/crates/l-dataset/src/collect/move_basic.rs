//! Move build/test signal.
//!
//! Move success is read from explicit `sui move build` / `sui move test` gate
//! status and parsed test totals — a package-hash mismatch surfaces upstream as
//! a failed build gate. `prover_pass` mirrors an explicit `G-MOVE-PROVER` gate
//! (the deep prover/spec surface lives in the prover collector); `gas_hash_32`
//! is the gas anchor filled by the gas collector and is the `"none"` sentinel
//! here.
use crate::collect::gate_pass;
use crate::diet_kind::AtomDietKey;
use crate::error::DietResult;
use crate::gate_results::{parse_gates, parse_tests};

/// Move build/test signal.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub struct MoveSignal {
    /// The source atom.
    pub key: AtomDietKey,
    /// `sui move build` (`G-MOVE-BUILD`) was an explicit pass.
    pub build_pass: bool,
    /// `sui move test` passed: explicit gate pass or parsed non-zero/zero-fail
    /// test totals (covers abort-code tests counted as passing).
    pub test_pass: bool,
    /// `G-MOVE-PROVER` was an explicit pass (deep prover surface is separate).
    pub prover_pass: bool,
    /// Gas anchor — `sha256("none")` until the gas collector fills it.
    pub gas_hash_32: [u8; 32],
}

/// Collect a [`MoveSignal`] from a `gate_results.json` document and an optional
/// `test_results.json` document.
pub fn collect(
    key: AtomDietKey,
    gate_results_json: &str,
    test_results_json: Option<&str>,
) -> DietResult<MoveSignal> {
    let gates = parse_gates(gate_results_json)?;
    let totals_pass = match test_results_json {
        Some(t) => {
            let to = parse_tests(t)?;
            to.failed_u32 == 0 && to.passed_u32 > 0
        }
        None => false,
    };
    Ok(MoveSignal {
        key,
        build_pass: gate_pass(&gates, "G-MOVE-BUILD"),
        test_pass: gate_pass(&gates, "G-MOVE-TEST") || totals_pass,
        prover_pass: gate_pass(&gates, "G-MOVE-PROVER"),
        gas_hash_32: crate::sha256(b"none"),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::diet_kind::DietSourceStage;

    fn key() -> AtomDietKey {
        AtomDietKey::new(DietSourceStage::StageC, 356)
    }

    #[test]
    fn build_and_test_pass() -> DietResult<()> {
        let gates = r#"{"gate_set":["G-MOVE-BUILD","G-MOVE-TEST"],"G-MOVE-BUILD":{"status":"PASS"},"G-MOVE-TEST":{"status":"PASS"}}"#;
        let s = collect(key(), gates, None)?;
        assert!(s.build_pass);
        assert!(s.test_pass);
        assert!(!s.prover_pass);
        Ok(())
    }

    #[test]
    fn build_fail_is_not_pass() -> DietResult<()> {
        // a package-hash mismatch shows up as a failed build gate.
        let gates = r#"{"gate_set":["G-MOVE-BUILD"],"G-MOVE-BUILD":{"status":"FAIL"}}"#;
        let s = collect(key(), gates, None)?;
        assert!(!s.build_pass);
        Ok(())
    }

    #[test]
    fn abort_code_test_counts_via_totals() -> DietResult<()> {
        let gates = r#"{"gate_set":["G-MOVE-BUILD"],"G-MOVE-BUILD":{"status":"PASS"}}"#;
        let tests = r#"{"summary":{"passed":12,"failed":0}}"#;
        let s = collect(key(), gates, Some(tests))?;
        assert!(s.test_pass);
        Ok(())
    }

    #[test]
    fn failing_totals_are_not_test_pass() -> DietResult<()> {
        let gates = r#"{"gate_set":[]}"#;
        let s = collect(key(), gates, Some(r#"{"summary":{"passed":4,"failed":1}}"#))?;
        assert!(!s.test_pass);
        Ok(())
    }
}
