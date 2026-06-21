//! Walrus PUT/GET roundtrip signal (atom #361 · E.1.10).
//!
//! PUT/GET latency is *diagnostic only*. Integrity pass/fail is reward-relevant
//! only for a synthetic / public-safe payload: a private payload is quarantined
//! via the privacy report (#341 reuse), so a roundtrip over private data can
//! never earn reward even if it round-tripped perfectly.
use crate::collect::{gate_pass, gate_status};
use crate::diet_kind::AtomDietKey;
use crate::error::DietResult;
use crate::gate_results::{GateStatus, parse_gates};
use crate::privacy::{self, PrivacyDecision};

/// Walrus PUT/GET roundtrip signal.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub struct WalrusRoundtripSignal {
    /// The source atom.
    pub key: AtomDietKey,
    /// A `G-WALRUS-PUT` gate was present with a real status.
    pub put_present: bool,
    /// A `G-WALRUS-GET` gate was present with a real status.
    pub get_present: bool,
    /// Integrity passed and both PUT and GET were present.
    pub integrity_pass: bool,
    /// The payload was public-safe (privacy verdict `Pass`).
    pub public_safe_payload: bool,
    /// Reward precondition: integrity over a public-safe payload.
    pub reward_eligible: bool,
    /// Diagnostic round-trip latency in milliseconds (never reward).
    pub latency_ms_u64: u64,
    /// Deterministic evidence anchor.
    pub evidence_hash_32: [u8; 32],
}

/// Collect a [`WalrusRoundtripSignal`] from a `gate_results.json` document, an
/// optional `privacy_report.json`, and the measured round-trip latency.
pub fn collect(
    key: AtomDietKey,
    gate_results_json: &str,
    privacy_json: Option<&str>,
    latency_ms_u64: u64,
) -> DietResult<WalrusRoundtripSignal> {
    let gates = parse_gates(gate_results_json)?;
    let put_present = !matches!(
        gate_status(&gates, "G-WALRUS-PUT"),
        GateStatus::Unknown | GateStatus::NotRun
    );
    let get_present = !matches!(
        gate_status(&gates, "G-WALRUS-GET"),
        GateStatus::Unknown | GateStatus::NotRun
    );
    let integrity_pass = gate_pass(&gates, "G-WALRUS-INTEGRITY") && put_present && get_present;
    let public_safe_payload = match privacy_json {
        Some(p) => matches!(privacy::parse(key, p)?.decision, PrivacyDecision::Pass),
        None => false,
    };
    let reward_eligible = integrity_pass && public_safe_payload;

    let mut buf = Vec::with_capacity(12);
    buf.push(put_present as u8);
    buf.push(get_present as u8);
    buf.push(integrity_pass as u8);
    buf.push(public_safe_payload as u8);
    buf.extend_from_slice(&latency_ms_u64.to_le_bytes());
    Ok(WalrusRoundtripSignal {
        key,
        put_present,
        get_present,
        integrity_pass,
        public_safe_payload,
        reward_eligible,
        latency_ms_u64,
        evidence_hash_32: crate::sha256(&buf),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::diet_kind::DietSourceStage;

    fn key() -> AtomDietKey {
        AtomDietKey::new(DietSourceStage::StageB, 361)
    }

    const FULL_GATES: &str = r#"{"gate_set":["G-WALRUS-PUT","G-WALRUS-GET","G-WALRUS-INTEGRITY"],"G-WALRUS-PUT":{"status":"PASS"},"G-WALRUS-GET":{"status":"PASS"},"G-WALRUS-INTEGRITY":{"status":"PASS"}}"#;

    #[test]
    fn public_roundtrip_pass_is_reward_eligible() -> DietResult<()> {
        let privacy = r#"{"verdict":"PASS — synthetic payload","checks":{}}"#;
        let s = collect(key(), FULL_GATES, Some(privacy), 42)?;
        assert!(s.integrity_pass);
        assert!(s.public_safe_payload);
        assert!(s.reward_eligible);
        assert_eq!(s.latency_ms_u64, 42);
        Ok(())
    }

    #[test]
    fn missing_get_blocks_integrity() -> DietResult<()> {
        let gates = r#"{"gate_set":["G-WALRUS-PUT","G-WALRUS-INTEGRITY"],"G-WALRUS-PUT":{"status":"PASS"},"G-WALRUS-INTEGRITY":{"status":"PASS"}}"#;
        let s = collect(key(), gates, Some(r#"{"verdict":"PASS","checks":{}}"#), 10)?;
        assert!(!s.get_present);
        assert!(!s.integrity_pass);
        assert!(!s.reward_eligible);
        Ok(())
    }

    #[test]
    fn private_payload_is_quarantined() -> DietResult<()> {
        let privacy =
            r#"{"verdict":"REJECT — private payload","checks":{"raw_user_data":{"count":1}}}"#;
        let s = collect(key(), FULL_GATES, Some(privacy), 7)?;
        assert!(!s.public_safe_payload);
        assert!(!s.reward_eligible);
        Ok(())
    }

    #[test]
    fn latency_is_diagnostic_and_recorded() -> DietResult<()> {
        let s = collect(
            key(),
            FULL_GATES,
            Some(r#"{"verdict":"PASS","checks":{}}"#),
            1234,
        )?;
        assert_eq!(s.latency_ms_u64, 1234);
        Ok(())
    }
}
