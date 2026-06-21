//! Reviewer identity privacy (atom #377 · E.2.6).
//!
//! A reviewer identity must be **stable enough for provenance but never raw
//! personal data**. The stable anchor is `sha256(normalized-handle)` — the same
//! reviewer always hashes to the same value (deterministic, collision-resistant)
//! — while emails, API tokens, and session ids are detected and **never
//! exported**: an identity that still contains an email / token / session marker
//! is a redaction reject ([`DietError::SecretResidue`]), not a "good enough"
//! mask. Only a clean handle yields a stable hash.
use crate::diet_kind::DietFileKind;
use crate::error::{DietError, DietResult};
use crate::terminal::looks_secret;

/// A stable, exportable reviewer identity anchor (hash of a clean handle).
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub struct ReviewerIdentity {
    /// `sha256` of the normalized (trimmed, lower-cased) reviewer handle.
    pub stable_hash_32: [u8; 32],
}

/// Whether a string is shaped like an email (`local@dotted.domain`).
fn looks_email(s: &str) -> bool {
    if let Some(at) = s.find('@') {
        let (local, rest) = s.split_at(at);
        let domain = &rest[1..];
        return !local.is_empty()
            && domain.contains('.')
            && !domain.starts_with('.')
            && !domain.ends_with('.')
            && !local.contains(char::is_whitespace)
            && !domain.contains(char::is_whitespace);
    }
    false
}

/// Whether a string carries a session-id marker.
fn looks_session_id(s: &str) -> bool {
    let l = s.to_ascii_lowercase();
    l.contains("jsessionid") || l.contains("session_id") || l.contains("sid=")
}

/// Build a stable reviewer identity. Email / token / session residue rejects —
/// a stable hash is only emitted for a clean handle (raw PII never exported).
pub fn reviewer_identity(raw: &str) -> DietResult<ReviewerIdentity> {
    if looks_email(raw) || looks_secret(raw) || looks_session_id(raw) {
        return Err(DietError::SecretResidue {
            kind: DietFileKind::HumanReview,
        });
    }
    Ok(ReviewerIdentity {
        stable_hash_32: crate::sha256(raw.trim().to_ascii_lowercase().as_bytes()),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stable_reviewer_hash_is_deterministic() -> DietResult<()> {
        let a = reviewer_identity("Owner")?;
        let b = reviewer_identity("owner")?; // normalized (trim + lower) ⇒ same anchor
        assert_eq!(a.stable_hash_32, b.stable_hash_32);
        assert_eq!(a.stable_hash_32, crate::sha256(b"owner"));
        Ok(())
    }

    #[test]
    fn email_is_redaction_reject() {
        assert!(matches!(
            reviewer_identity("alice@example.com"),
            Err(DietError::SecretResidue { .. })
        ));
    }

    #[test]
    fn token_is_redaction_reject() {
        assert!(matches!(
            reviewer_identity("ghp_ABCDEFGHIJKLMNOPqrstuvwx"),
            Err(DietError::SecretResidue { .. })
        ));
    }

    #[test]
    fn session_id_is_redaction_reject() {
        assert!(matches!(
            reviewer_identity("jsessionid=9A1B2C3D"),
            Err(DietError::SecretResidue { .. })
        ));
    }

    #[test]
    fn distinct_handles_do_not_collide() -> DietResult<()> {
        assert_ne!(
            reviewer_identity("alice")?.stable_hash_32,
            reviewer_identity("bob")?.stable_hash_32
        );
        Ok(())
    }
}
