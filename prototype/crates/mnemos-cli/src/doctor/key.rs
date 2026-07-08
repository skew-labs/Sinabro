//! Status-only key doctor.
//!
//! No live key load, no network, no secret clone / `Debug`. Reports the presence
//! and location of declared secret references and whether any inline secret
//! leaked into scanned text (config / docs / history).

use crate::secrets::{SecretRefView, classify_reference, scan_inline_secret};

/// Result of a key-doctor audit.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KeyDoctorReport {
    /// Status-only views of each declared secret reference.
    pub refs: Vec<SecretRefView>,
    /// Count of scanned texts that contained an inline secret.
    pub inline_secret_hits: u32,
    /// `true` iff no inline secret was found.
    pub secret_zero: bool,
}

/// Audit declared `(name, reference)` pairs and scan `scanned_texts` for inline
/// secrets. The secret values are never loaded.
#[must_use]
pub fn audit_refs(declared: &[(&str, &str)], scanned_texts: &[&str]) -> KeyDoctorReport {
    let refs: Vec<SecretRefView> = declared
        .iter()
        .map(|(name, reference)| classify_reference(name, reference))
        .collect();
    let inline_secret_hits = scanned_texts
        .iter()
        .filter(|t| scan_inline_secret(t))
        .count() as u32;
    KeyDoctorReport {
        refs,
        inline_secret_hits,
        secret_zero: inline_secret_hits == 0,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::secrets::SecretLocation;

    #[test]
    fn clean_refs_report_secret_zero() {
        let r = audit_refs(
            &[
                ("provider", "env:ANTHROPIC_API_KEY"),
                ("anchor", "keychain:owner"),
            ],
            &[
                "learning_mode = \"off\"",
                "# docs: use env:ANTHROPIC_API_KEY",
            ],
        );
        assert!(r.secret_zero);
        assert_eq!(r.inline_secret_hits, 0);
        assert_eq!(r.refs.len(), 2);
        assert_eq!(r.refs[0].location, SecretLocation::EnvRef);
        assert!(r.refs.iter().all(|v| v.value_never_loaded));
    }

    #[test]
    fn inline_secret_breaks_secret_zero() {
        let r = audit_refs(&[], &["leaked = \"suiprivkey1qexamplenotreal\""]);
        assert!(!r.secret_zero);
        assert_eq!(r.inline_secret_hits, 1);
    }
}
