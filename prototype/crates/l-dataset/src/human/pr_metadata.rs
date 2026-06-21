//! PR / source metadata collector (atom #375 · E.2.4).
//!
//! PR metadata preserves repo, commit, diff, reviewer, CI, and license as
//! `sha256` anchors — never the raw URL, token, or private body. A source with
//! **no license is quarantined** (never exported, never reward) until the
//! license is resolved. A private URL (one carrying userinfo credentials or a
//! token) is flagged redacted; only its hash survives — path is never
//! provenance, only the content hash is.
use crate::diet_kind::AtomDietKey;
use crate::terminal::looks_secret;

/// Whether a source is a local A-D trace or an external corpus.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
#[repr(u8)]
pub enum PrOrigin {
    /// A local A-D build trace (internal, trusted provenance).
    LocalAToD = 1,
    /// An external audit corpus (needs explicit provenance + license).
    ExternalAudit = 2,
}

impl PrOrigin {
    /// Numeric discriminant.
    pub const fn as_u8(self) -> u8 {
        self as u8
    }
}

/// Raw PR metadata fields (borrowed; hashed on construction, never retained raw).
#[derive(Clone, Copy, Debug)]
pub struct PrMetadataInput<'a> {
    /// Repository URL / identifier.
    pub repo: &'a str,
    /// Commit identifier.
    pub commit: &'a str,
    /// Diff identifier / content.
    pub diff: &'a str,
    /// Reviewer identifier.
    pub reviewer: &'a str,
    /// CI run identifier.
    pub ci: &'a str,
    /// License identifier (`None` ⇒ quarantine).
    pub license: Option<&'a str>,
}

/// Normalized PR / source metadata (all fields hashed).
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub struct PrMetadata {
    /// The source atom.
    pub key: AtomDietKey,
    /// Local-vs-external origin.
    pub origin: PrOrigin,
    /// `sha256` of the repo identifier.
    pub repo_hash_32: [u8; 32],
    /// `sha256` of the commit identifier.
    pub commit_hash_32: [u8; 32],
    /// `sha256` of the diff identifier.
    pub diff_hash_32: [u8; 32],
    /// `sha256` of the reviewer identifier.
    pub reviewer_hash_32: [u8; 32],
    /// `sha256` of the CI run identifier.
    pub ci_hash_32: [u8; 32],
    /// `sha256` of the license identifier (`"unknown"` when absent).
    pub license_hash_32: [u8; 32],
    /// Whether a non-empty license was present.
    pub license_known: bool,
    /// Whether the repo URL was a private URL (userinfo/token) and was redacted.
    pub private_url_redacted: bool,
    /// Quarantined (never exported / reward) — currently iff the license is unknown.
    pub quarantined: bool,
}

/// Whether a URL is private: it carries userinfo credentials (`scheme://x@host`)
/// or any secret-token marker.
fn is_private_url(u: &str) -> bool {
    if looks_secret(u) {
        return true;
    }
    if let Some(rest) = u.split("://").nth(1) {
        if let Some(authority) = rest.split('/').next() {
            return authority.contains('@');
        }
    }
    false
}

/// Build normalized PR metadata. Missing license ⇒ quarantine; private repo URL
/// ⇒ redaction flag. No raw URL/token is retained — only hashes.
pub fn new(key: AtomDietKey, origin: PrOrigin, input: &PrMetadataInput<'_>) -> PrMetadata {
    let license_known = input.license.is_some_and(|l| !l.trim().is_empty());
    PrMetadata {
        key,
        origin,
        repo_hash_32: crate::sha256(input.repo.as_bytes()),
        commit_hash_32: crate::sha256(input.commit.as_bytes()),
        diff_hash_32: crate::sha256(input.diff.as_bytes()),
        reviewer_hash_32: crate::sha256(input.reviewer.as_bytes()),
        ci_hash_32: crate::sha256(input.ci.as_bytes()),
        license_hash_32: crate::sha256(input.license.unwrap_or("unknown").as_bytes()),
        license_known,
        private_url_redacted: is_private_url(input.repo),
        quarantined: !license_known,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::diet_kind::DietSourceStage;

    fn key() -> AtomDietKey {
        AtomDietKey::new(DietSourceStage::StageD, 375)
    }

    fn input<'a>(repo: &'a str, license: Option<&'a str>) -> PrMetadataInput<'a> {
        PrMetadataInput {
            repo,
            commit: "abc123",
            diff: "diff-hash",
            reviewer: "owner",
            ci: "ci-run-1",
            license,
        }
    }

    #[test]
    fn local_pr_with_license_is_not_quarantined() {
        let m = new(
            key(),
            PrOrigin::LocalAToD,
            &input("https://github.com/org/repo", Some("MIT")),
        );
        assert!(m.license_known);
        assert!(!m.quarantined);
        assert!(!m.private_url_redacted);
        assert_eq!(m.origin, PrOrigin::LocalAToD);
    }

    #[test]
    fn external_audit_metadata_preserves_hashes() {
        let m = new(
            key(),
            PrOrigin::ExternalAudit,
            &input("https://audit.example/report", Some("Apache-2.0")),
        );
        assert_eq!(m.origin, PrOrigin::ExternalAudit);
        assert_eq!(
            m.repo_hash_32,
            crate::sha256(b"https://audit.example/report")
        );
    }

    #[test]
    fn missing_license_quarantines() {
        let m = new(key(), PrOrigin::ExternalAudit, &input("https://x/y", None));
        assert!(!m.license_known);
        assert!(m.quarantined);
    }

    #[test]
    fn private_url_is_redacted() {
        let m = new(
            key(),
            PrOrigin::ExternalAudit,
            &input(
                "https://user:ghp_ABCDEFGHIJKLMNOP@github.com/x/y",
                Some("MIT"),
            ),
        );
        assert!(m.private_url_redacted);
        // even redacted, only the hash is kept (no raw URL anywhere in the type).
        assert_eq!(
            m.repo_hash_32,
            crate::sha256(b"https://user:ghp_ABCDEFGHIJKLMNOP@github.com/x/y")
        );
    }
}
