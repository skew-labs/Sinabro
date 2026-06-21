//! Move gas trace signal (atom #358 · E.1.7).
//!
//! Gas reward requires a baseline, a chain environment (#339 reuse: a real Sui
//! descriptor), package-hash + dry-run/dev-inspect evidence (the `G-GAS` gate
//! carrying a linked command hash). A bare self-reported gas number — no command
//! evidence — is S2-only and never reward-eligible.
use crate::diet_kind::AtomDietKey;
use crate::env_lock;
use crate::error::DietResult;
use crate::gate_results::{GateOutcome, GateStatus, parse_gates};

/// Move gas trace signal.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub struct GasSignal {
    /// The source atom.
    pub key: AtomDietKey,
    /// A `G-GAS` gate was present with a real status (a baseline exists).
    pub baseline_present: bool,
    /// The chain environment is recorded (Sui descriptor is non-sentinel).
    pub chain_env_present: bool,
    /// The gas gate carried a linked command hash (package + dry-run linkage).
    pub package_hash_present: bool,
    /// Dry-run / dev-inspect evidence: gas gate pass/deferred with command link.
    pub dry_run_evidence: bool,
    /// No command-backed dry-run — any gas claim is self-report only (S2-only).
    pub self_report_only: bool,
    /// Reward precondition: baseline + chain env + package linkage + dry-run.
    pub reward_eligible: bool,
    /// Deterministic gas evidence anchor.
    pub gas_hash_32: [u8; 32],
}

fn find<'a>(gates: &'a [GateOutcome], name: &str) -> Option<&'a GateOutcome> {
    let id = crate::sha256(name.as_bytes());
    gates.iter().find(|g| g.gate_id_hash_32 == id)
}

/// Collect a [`GasSignal`] from a `gate_results.json` document and an optional
/// `env_lock.json` document.
pub fn collect(
    key: AtomDietKey,
    gate_results_json: &str,
    env_lock_json: Option<&str>,
) -> DietResult<GasSignal> {
    let gates = parse_gates(gate_results_json)?;
    let outcome = find(&gates, "G-GAS");
    let status = outcome.map_or(GateStatus::Unknown, |g| g.status);
    let cmd_linked = outcome.is_some_and(|g| g.command_hash_32.is_some());

    let baseline_present = !matches!(status, GateStatus::Unknown | GateStatus::NotRun);
    let dry_run_evidence = matches!(status, GateStatus::Pass | GateStatus::Deferred) && cmd_linked;
    let package_hash_present = cmd_linked;
    let self_report_only = !dry_run_evidence;

    let none = crate::sha256(b"none");
    let sui = match env_lock_json {
        Some(e) => env_lock::parse(e)?.sui_hash_32,
        None => none,
    };
    let chain_env_present = sui != none;
    let reward_eligible =
        baseline_present && chain_env_present && package_hash_present && dry_run_evidence;

    let cmd = match status_command_hash(outcome) {
        Some(h) => h,
        None => none,
    };
    let mut buf = Vec::with_capacity(65);
    buf.extend_from_slice(&sui);
    buf.extend_from_slice(&cmd);
    buf.push(status.as_u8());
    Ok(GasSignal {
        key,
        baseline_present,
        chain_env_present,
        package_hash_present,
        dry_run_evidence,
        self_report_only,
        reward_eligible,
        gas_hash_32: crate::sha256(&buf),
    })
}

fn status_command_hash(outcome: Option<&GateOutcome>) -> Option<[u8; 32]> {
    outcome.and_then(|g| g.command_hash_32)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::diet_kind::DietSourceStage;

    fn key() -> AtomDietKey {
        AtomDietKey::new(DietSourceStage::StageC, 358)
    }

    const ENV_SUI: &str = r#"{"tooling_available":{"sui":"present (1.72.1-homebrew)"}}"#;

    #[test]
    fn full_gas_evidence_is_reward_eligible() -> DietResult<()> {
        let gates = r#"{"gate_set":["G-GAS"],"G-GAS":{"status":"PASS","tool":"sui client dev-inspect pkg@abc::m::f"}}"#;
        let s = collect(key(), gates, Some(ENV_SUI))?;
        assert!(s.baseline_present);
        assert!(s.chain_env_present);
        assert!(s.package_hash_present);
        assert!(s.dry_run_evidence);
        assert!(!s.self_report_only);
        assert!(s.reward_eligible);
        Ok(())
    }

    #[test]
    fn gas_regression_fail_is_not_eligible() -> DietResult<()> {
        let gates =
            r#"{"gate_set":["G-GAS"],"G-GAS":{"status":"FAIL","tool":"sui client dev-inspect"}}"#;
        let s = collect(key(), gates, Some(ENV_SUI))?;
        assert!(!s.dry_run_evidence);
        assert!(!s.reward_eligible);
        Ok(())
    }

    #[test]
    fn no_baseline_is_not_eligible() -> DietResult<()> {
        let s = collect(key(), r#"{"gate_set":[]}"#, Some(ENV_SUI))?;
        assert!(!s.baseline_present);
        assert!(!s.reward_eligible);
        Ok(())
    }

    #[test]
    fn self_report_only_without_command_is_not_eligible() -> DietResult<()> {
        // a gas number reported but no dry-run command linkage.
        let gates = r#"{"gate_set":["G-GAS"],"G-GAS":{"status":"PASS"}}"#;
        let s = collect(key(), gates, Some(ENV_SUI))?;
        assert!(s.self_report_only);
        assert!(!s.package_hash_present);
        assert!(!s.reward_eligible);
        Ok(())
    }

    #[test]
    fn storage_rebate_deferred_with_command_is_dry_run() -> DietResult<()> {
        let gates = r#"{"gate_set":["G-GAS"],"G-GAS":{"status":"STRUCTURAL_PASS_MEASUREMENT_DEFERRED","tool":"sui client dry-run"}}"#;
        let s = collect(key(), gates, Some(ENV_SUI))?;
        assert!(s.dry_run_evidence);
        Ok(())
    }
}
