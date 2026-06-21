//! Exploit reproduction + regression fixture collector (atom #373 · E.2.2).
//!
//! An exploit reproduction is high-value training data **only** when it is
//! paired with a fix and a passing regression — `repro ∧ fix ∧ regression-pass`
//! is S1-eligible. Exploit text with no fix is **quarantine / negative context
//! only** (never positive reward): a working exploit without a remedy teaches
//! the wrong lesson. The raw exploit payload is never stored; it is hashed, and
//! a secret-like payload (a leaked key inside the PoC) is flagged via the
//! canonical terminal scanner (#340 reuse) so an exploit PoC cannot smuggle a
//! live secret into the corpus — a flagged payload is never S1-eligible.
use crate::diet_kind::AtomDietKey;
use crate::security::source::SecuritySeverity;
use crate::terminal::looks_secret;

/// Exploit reproduction + regression fixture signal.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub struct ExploitReproSignal {
    /// The source atom.
    pub key: AtomDietKey,
    /// The exploit severity.
    pub severity: SecuritySeverity,
    /// A reproduction was present.
    pub has_repro: bool,
    /// A fix was present.
    pub has_fix: bool,
    /// The regression fixture passed after the fix.
    pub regression_pass: bool,
    /// The payload contained secret-like residue (must be redacted).
    pub payload_secret_flagged: bool,
    /// `sha256` of the exploit payload (the payload itself is never stored).
    pub payload_hash_32: [u8; 32],
    /// S1-eligible: repro ∧ fix ∧ regression-pass ∧ no secret residue.
    pub s1_eligible: bool,
    /// Quarantine-only: anything that is not S1-eligible.
    pub quarantine_only: bool,
}

/// Collect an [`ExploitReproSignal`]. The payload is hashed and scanned; only a
/// repro+fix+regression-pass with a clean payload is S1-eligible.
pub fn collect(
    key: AtomDietKey,
    severity: SecuritySeverity,
    has_repro: bool,
    has_fix: bool,
    regression_pass: bool,
    payload: &str,
) -> ExploitReproSignal {
    let payload_secret_flagged = looks_secret(payload);
    let s1_eligible = has_repro && has_fix && regression_pass && !payload_secret_flagged;
    ExploitReproSignal {
        key,
        severity,
        has_repro,
        has_fix,
        regression_pass,
        payload_secret_flagged,
        payload_hash_32: crate::sha256(payload.as_bytes()),
        s1_eligible,
        quarantine_only: !s1_eligible,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::diet_kind::DietSourceStage;

    fn key() -> AtomDietKey {
        AtomDietKey::new(DietSourceStage::StageD, 373)
    }

    #[test]
    fn repro_fix_regression_is_s1() {
        let s = collect(key(), SecuritySeverity::High, true, true, true, "safe poc");
        assert!(s.s1_eligible);
        assert!(!s.quarantine_only);
        assert!(!s.payload_secret_flagged);
    }

    #[test]
    fn repro_without_fix_is_quarantine_only() {
        let s = collect(key(), SecuritySeverity::Critical, true, false, false, "poc");
        assert!(!s.s1_eligible);
        assert!(s.quarantine_only);
    }

    #[test]
    fn regression_fail_is_quarantine_only() {
        let s = collect(key(), SecuritySeverity::High, true, true, false, "poc");
        assert!(!s.s1_eligible);
        assert!(s.quarantine_only);
    }

    #[test]
    fn secret_payload_is_flagged_and_not_s1() {
        let s = collect(
            key(),
            SecuritySeverity::High,
            true,
            true,
            true,
            "leak sk-live_ABCDEF0123456789",
        );
        assert!(s.payload_secret_flagged);
        assert!(!s.s1_eligible);
        assert!(s.quarantine_only);
    }

    #[test]
    fn payload_is_hashed_not_stored() {
        let s = collect(
            key(),
            SecuritySeverity::Low,
            true,
            false,
            false,
            "exploit text",
        );
        assert_eq!(s.payload_hash_32, crate::sha256(b"exploit text"));
    }
}
