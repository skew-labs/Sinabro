//! wallet / secret / key isolation signal (atom #362 · E.1.11).
//!
//! **Detection scanner.** Any secret leak turns the atom into a privacy *reject*
//! regardless of compile/test success. The terminal log is scanned with the
//! canonical redaction scanner (#340 reuse): a residue hit is recorded as a leak
//! *fact* (not propagated as a hard error), while a malformed log still fails.
//! The privacy report (#341 reuse) supplies the secret-class hit count. An absent
//! privacy report fails closed to `Reject`. This collector never *uses* a wallet,
//! key, or secret; it only detects their leakage.
use crate::diet_kind::AtomDietKey;
use crate::error::{DietError, DietResult};
use crate::privacy::{self, PrivacyDecision};
use crate::terminal::scan_terminal_str;

/// wallet / secret / key isolation signal.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub struct SecretIsolationSignal {
    /// The source atom.
    pub key: AtomDietKey,
    /// The terminal log scanned clean (no secret residue).
    pub terminal_clean: bool,
    /// The privacy report verdict.
    pub privacy_decision: PrivacyDecision,
    /// Secret-class hit count from the privacy report.
    pub secret_hits_u32: u32,
    /// A leak was detected (terminal residue or any secret-class hit).
    pub leak_detected: bool,
    /// The atom is a privacy reject (any leak, or a `Reject` verdict).
    pub privacy_reject: bool,
}

/// Collect a [`SecretIsolationSignal`] from an optional `terminal_redacted.jsonl`
/// and an optional `privacy_report.json`.
pub fn collect(
    key: AtomDietKey,
    terminal_redacted_jsonl: Option<&str>,
    privacy_json: Option<&str>,
) -> DietResult<SecretIsolationSignal> {
    let (terminal_clean, terminal_leak) = match terminal_redacted_jsonl {
        Some(t) => match scan_terminal_str(t) {
            Ok(_) => (true, false),
            Err(DietError::SecretResidue { .. }) => (false, true),
            Err(e) => return Err(e),
        },
        None => (true, false),
    };
    let (privacy_decision, secret_hits_u32) = match privacy_json {
        Some(p) => {
            let r = privacy::parse(key, p)?;
            (r.decision, r.secret_hits_u32)
        }
        None => (PrivacyDecision::Reject, 0),
    };
    let leak_detected = terminal_leak || secret_hits_u32 > 0;
    let privacy_reject = leak_detected || matches!(privacy_decision, PrivacyDecision::Reject);
    Ok(SecretIsolationSignal {
        key,
        terminal_clean,
        privacy_decision,
        secret_hits_u32,
        leak_detected,
        privacy_reject,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::diet_kind::DietSourceStage;

    fn key() -> AtomDietKey {
        AtomDietKey::new(DietSourceStage::Phase0, 362)
    }

    #[test]
    fn no_secret_passes() -> DietResult<()> {
        let terminal = r#"{"n":1,"line":"BUILD_EXIT=0","redaction":"none"}"#;
        let privacy = r#"{"verdict":"PASS — 0 secret","checks":{}}"#;
        let s = collect(key(), Some(terminal), Some(privacy))?;
        assert!(s.terminal_clean);
        assert!(!s.leak_detected);
        assert!(!s.privacy_reject);
        Ok(())
    }

    #[test]
    fn debug_printed_secret_leak_rejects() -> DietResult<()> {
        let terminal = r#"{"n":1,"line":"SealedKeypair { ct: \"sk-live_ABCDEF0123456789\" }","redaction":"none"}"#;
        let s = collect(
            key(),
            Some(terminal),
            Some(r#"{"verdict":"PASS","checks":{}}"#),
        )?;
        assert!(!s.terminal_clean);
        assert!(s.leak_detected);
        assert!(s.privacy_reject);
        Ok(())
    }

    #[test]
    fn env_token_leak_rejects() -> DietResult<()> {
        let terminal = r#"{"n":1,"line":"export GH=ghp_ABCDEFGHIJKLMNOP","redaction":"none"}"#;
        let s = collect(
            key(),
            Some(terminal),
            Some(r#"{"verdict":"PASS","checks":{}}"#),
        )?;
        assert!(s.leak_detected);
        assert!(s.privacy_reject);
        Ok(())
    }

    #[test]
    fn sponsor_key_hit_rejects() -> DietResult<()> {
        let privacy =
            r#"{"verdict":"REJECT — sponsor key","checks":{"sponsor_key_present":{"count":1}}}"#;
        let s = collect(key(), None, Some(privacy))?;
        assert_eq!(s.secret_hits_u32, 1);
        assert!(s.leak_detected);
        assert!(s.privacy_reject);
        Ok(())
    }

    #[test]
    fn redacted_clean_terminal_is_not_a_reject() -> DietResult<()> {
        let terminal = r#"{"n":1,"line":"token REDACTED","redaction":"redacted"}"#;
        let privacy = r#"{"verdict":"REDACTED — 1 masked","checks":{}}"#;
        let s = collect(key(), Some(terminal), Some(privacy))?;
        assert_eq!(s.privacy_decision, PrivacyDecision::Redacted);
        assert!(!s.leak_detected);
        assert!(!s.privacy_reject);
        Ok(())
    }

    #[test]
    fn absent_privacy_report_fails_closed() -> DietResult<()> {
        let s = collect(
            key(),
            Some(r#"{"n":1,"line":"ok","redaction":"none"}"#),
            None,
        )?;
        assert_eq!(s.privacy_decision, PrivacyDecision::Reject);
        assert!(s.privacy_reject);
        Ok(())
    }
}
