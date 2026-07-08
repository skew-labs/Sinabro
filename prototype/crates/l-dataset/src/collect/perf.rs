//! criterion / perf / allocation signal.
//!
//! Performance reward requires a *baseline* (a criterion/bench gate), an
//! *environment lock* (rust + deps descriptors must be real, not the
//! `"none"` sentinel), and a non-failing perf review axis. A missing
//! baseline means the sample is SFT-context only — never reward. An explicit
//! allocation regression (`G-ALLOC` fail) also blocks reward.
use crate::collect::gate_status;
use crate::diet_kind::AtomDietKey;
use crate::env_lock;
use crate::error::DietResult;
use crate::gate_results::{GateStatus, parse_gates};
use crate::review5::{self, AxisVerdict};

/// criterion / perf / allocation signal.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub struct PerfSignal {
    /// The source atom.
    pub key: AtomDietKey,
    /// A criterion/bench gate (`G-BENCH`) was present with a real status.
    pub baseline_present: bool,
    /// The environment was locked (rust + deps descriptors are non-sentinel).
    pub env_locked: bool,
    /// The 5-review perf axis verdict (`Unknown` when no review provided).
    pub perf_axis: AxisVerdict,
    /// `G-ALLOC` reported an explicit allocation regression.
    pub alloc_regressed: bool,
    /// Reward precondition: baseline + env lock + perf axis not failing + no
    /// allocation regression. Reward itself is still assigned downstream.
    pub reward_eligible: bool,
    /// Deterministic evidence anchor over the deps hash and the perf verdicts.
    pub evidence_hash_32: [u8; 32],
}

/// Collect a [`PerfSignal`] from a `gate_results.json` document plus optional
/// `env_lock.json` and `review_5pack.json` documents.
pub fn collect(
    key: AtomDietKey,
    gate_results_json: &str,
    env_lock_json: Option<&str>,
    review5_json: Option<&str>,
) -> DietResult<PerfSignal> {
    let gates = parse_gates(gate_results_json)?;
    let bench = gate_status(&gates, "G-BENCH");
    let baseline_present = !matches!(bench, GateStatus::Unknown | GateStatus::NotRun);
    let alloc_regressed = matches!(gate_status(&gates, "G-ALLOC"), GateStatus::Fail);

    let none = crate::sha256(b"none");
    let env = match env_lock_json {
        Some(e) => Some(env_lock::parse(e)?),
        None => None,
    };
    let env_locked = matches!(env, Some(e) if e.rust_hash_32 != none && e.deps_hash_32 != none);
    let deps = match env {
        Some(e) => e.deps_hash_32,
        None => none,
    };

    let perf_axis = match review5_json {
        Some(r) => review5::parse(r)?.perf,
        None => AxisVerdict::Unknown,
    };
    let perf_ok = matches!(perf_axis, AxisVerdict::Pass | AxisVerdict::PassWithDeferred);
    let reward_eligible = baseline_present && env_locked && perf_ok && !alloc_regressed;

    let mut buf = Vec::with_capacity(35);
    buf.extend_from_slice(&deps);
    buf.push(perf_axis.as_u8());
    buf.push(baseline_present as u8);
    buf.push(alloc_regressed as u8);
    Ok(PerfSignal {
        key,
        baseline_present,
        env_locked,
        perf_axis,
        alloc_regressed,
        reward_eligible,
        evidence_hash_32: crate::sha256(&buf),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::diet_kind::DietSourceStage;

    fn key() -> AtomDietKey {
        AtomDietKey::new(DietSourceStage::StageD, 354)
    }

    const ENV_GOOD: &str = r#"{"rust":{"rustc":"1.94.1"},"build_flags":"--locked --offline"}"#;

    fn review(perf: &str) -> String {
        format!(
            r#"{{"perf":{{"verdict":"{perf}"}},"security":{{"verdict":"PASS"}},"chain":{{"verdict":"PASS"}},"agent_token":{{"verdict":"PASS"}},"devex":{{"verdict":"PASS"}}}}"#
        )
    }

    #[test]
    fn latency_improvement_is_reward_eligible() -> DietResult<()> {
        let gates = r#"{"gate_set":["G-BENCH"],"G-BENCH":{"status":"PASS","tool":"cargo bench"}}"#;
        let s = collect(key(), gates, Some(ENV_GOOD), Some(&review("PASS")))?;
        assert!(s.baseline_present);
        assert!(s.env_locked);
        assert_eq!(s.perf_axis, AxisVerdict::Pass);
        assert!(s.reward_eligible);
        Ok(())
    }

    #[test]
    fn perf_regression_blocks_reward() -> DietResult<()> {
        let gates = r#"{"gate_set":["G-BENCH"],"G-BENCH":{"status":"PASS"}}"#;
        let s = collect(
            key(),
            gates,
            Some(ENV_GOOD),
            Some(&review("FAIL — regression")),
        )?;
        assert_eq!(s.perf_axis, AxisVerdict::Fail);
        assert!(!s.reward_eligible);
        Ok(())
    }

    #[test]
    fn alloc_regression_blocks_reward() -> DietResult<()> {
        let gates = r#"{"gate_set":["G-BENCH","G-ALLOC"],"G-BENCH":{"status":"PASS"},"G-ALLOC":{"status":"FAIL"}}"#;
        let s = collect(key(), gates, Some(ENV_GOOD), Some(&review("PASS")))?;
        assert!(s.alloc_regressed);
        assert!(!s.reward_eligible);
        Ok(())
    }

    #[test]
    fn missing_baseline_is_no_reward() -> DietResult<()> {
        let gates = r#"{"gate_set":[]}"#;
        let s = collect(key(), gates, Some(ENV_GOOD), Some(&review("PASS")))?;
        assert!(!s.baseline_present);
        assert!(!s.reward_eligible);
        Ok(())
    }

    #[test]
    fn missing_env_lock_blocks_reward() -> DietResult<()> {
        let gates = r#"{"gate_set":["G-BENCH"],"G-BENCH":{"status":"PASS"}}"#;
        let s = collect(key(), gates, None, Some(&review("PASS")))?;
        assert!(!s.env_locked);
        assert!(!s.reward_eligible);
        Ok(())
    }
}
