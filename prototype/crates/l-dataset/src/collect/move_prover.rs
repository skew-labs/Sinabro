//! Move Prover / spec signal (atom #357 · E.1.6).
//!
//! A prover proof can reward invariant repair *only* when it is tied to an exact
//! package/spec hash — modelled here as the `G-MOVE-PROVER` gate carrying a
//! linked command hash. A prover pass without that linkage is not invariant-
//! reward-eligible. Sparse prover data (no/`N/A` prover) falls back to a plain
//! move-test-pass signal.
use crate::diet_kind::AtomDietKey;
use crate::error::DietResult;
use crate::gate_results::{GateStatus, parse_gates};

/// Move Prover / spec signal.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub struct MoveProverSignal {
    /// The source atom.
    pub key: AtomDietKey,
    /// Explicit `G-MOVE-PROVER` status (`Unknown` when absent).
    pub prover_status: GateStatus,
    /// The prover gate carried a linked command hash (spec/package linkage).
    pub spec_hash_linked: bool,
    /// Invariant repair is reward-eligible: prover passed *and* spec is linked.
    pub invariant_reward_eligible: bool,
    /// Sparse-prover fallback: prover absent/`N/A` but the move tests passed.
    pub sparse_fallback_test_pass: bool,
    /// Deterministic evidence anchor over the prover status and linkage.
    pub evidence_hash_32: [u8; 32],
}

/// Collect a [`MoveProverSignal`] from a `gate_results.json` document and the
/// move-test-pass fact (from [`super::move_basic`]).
pub fn collect(
    key: AtomDietKey,
    gate_results_json: &str,
    move_test_pass: bool,
) -> DietResult<MoveProverSignal> {
    let gates = parse_gates(gate_results_json)?;
    let id = crate::sha256(b"G-MOVE-PROVER");
    let outcome = gates.iter().find(|g| g.gate_id_hash_32 == id);
    let prover_status = outcome.map_or(GateStatus::Unknown, |g| g.status);
    let spec_hash_linked = outcome.is_some_and(|g| g.command_hash_32.is_some());

    let invariant_reward_eligible = matches!(prover_status, GateStatus::Pass) && spec_hash_linked;
    let sparse = matches!(
        prover_status,
        GateStatus::NotApplicable | GateStatus::NotRun | GateStatus::Unknown
    );
    let sparse_fallback_test_pass = sparse && move_test_pass;

    let buf = [
        prover_status.as_u8(),
        spec_hash_linked as u8,
        move_test_pass as u8,
    ];
    Ok(MoveProverSignal {
        key,
        prover_status,
        spec_hash_linked,
        invariant_reward_eligible,
        sparse_fallback_test_pass,
        evidence_hash_32: crate::sha256(&buf),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::diet_kind::DietSourceStage;

    fn key() -> AtomDietKey {
        AtomDietKey::new(DietSourceStage::StageC, 357)
    }

    #[test]
    fn prover_pass_with_spec_linkage_is_invariant_eligible() -> DietResult<()> {
        let gates = r#"{"gate_set":["G-MOVE-PROVER"],"G-MOVE-PROVER":{"status":"PASS","tool":"sui move prove --path pkg@abc"}}"#;
        let s = collect(key(), gates, true)?;
        assert_eq!(s.prover_status, GateStatus::Pass);
        assert!(s.spec_hash_linked);
        assert!(s.invariant_reward_eligible);
        Ok(())
    }

    #[test]
    fn prover_fail_is_not_eligible() -> DietResult<()> {
        let gates = r#"{"gate_set":["G-MOVE-PROVER"],"G-MOVE-PROVER":{"status":"FAIL","tool":"sui move prove"}}"#;
        let s = collect(key(), gates, true)?;
        assert!(!s.invariant_reward_eligible);
        Ok(())
    }

    #[test]
    fn prover_pass_without_spec_linkage_is_not_eligible() -> DietResult<()> {
        // status PASS but no `tool` => no command linkage => not invariant-eligible.
        let gates = r#"{"gate_set":["G-MOVE-PROVER"],"G-MOVE-PROVER":{"status":"PASS"}}"#;
        let s = collect(key(), gates, true)?;
        assert!(!s.spec_hash_linked);
        assert!(!s.invariant_reward_eligible);
        Ok(())
    }

    #[test]
    fn sparse_prover_falls_back_to_test_pass() -> DietResult<()> {
        let gates =
            r#"{"gate_set":["G-MOVE-PROVER"],"G-MOVE-PROVER":{"status":"N/A_NOT_VERIFIED"}}"#;
        let s = collect(key(), gates, true)?;
        assert_eq!(s.prover_status, GateStatus::NotApplicable);
        assert!(s.sparse_fallback_test_pass);
        assert!(!s.invariant_reward_eligible);
        Ok(())
    }
}
