//! Security corpus source schema (atom #371 · E.2.0).
//!
//! The security corpus has five **separate source classes** — exploit repros,
//! audit findings, deny-audit failures, 5-review failures, and red-team
//! decisions — so a high-value exploit-with-fix is never silently merged with a
//! narrative red-team note. Severity is parsed from a closed ladder; an unknown
//! source tag or severity *rejects* ([`DietError::UnknownSecuritySource`])
//! rather than being bucketed by guesswork. A source owns no raw payload: it
//! carries only its class, severity, and a `sha256` content anchor.
use crate::diet_kind::AtomDietKey;
use crate::error::{DietError, DietResult};

/// One of the five closed security source classes (§E.2 corpus).
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
#[repr(u8)]
pub enum SecuritySourceClass {
    /// An exploit reproduction (optionally with a fix + regression).
    ExploitRepro = 1,
    /// A normalized audit finding (severity + status).
    AuditFinding = 2,
    /// A deny-audit failure (a denied dangerous action).
    DenyFailure = 3,
    /// A 5-review axis failure.
    Review5Failure = 4,
    /// A red-team decision record.
    RedteamDecision = 5,
}

impl SecuritySourceClass {
    /// All five classes in discriminant order.
    pub const ALL: [SecuritySourceClass; 5] = [
        Self::ExploitRepro,
        Self::AuditFinding,
        Self::DenyFailure,
        Self::Review5Failure,
        Self::RedteamDecision,
    ];

    /// Numeric discriminant (`1..=5`).
    pub const fn as_u8(self) -> u8 {
        self as u8
    }

    /// Parse from a discriminant; `None` if not `1..=5`.
    pub const fn from_u8(v: u8) -> Option<Self> {
        match v {
            1 => Some(Self::ExploitRepro),
            2 => Some(Self::AuditFinding),
            3 => Some(Self::DenyFailure),
            4 => Some(Self::Review5Failure),
            5 => Some(Self::RedteamDecision),
            _ => None,
        }
    }

    /// Parse a source tag string, rejecting unknown tags fail-closed.
    pub fn from_tag(tag: &str) -> DietResult<Self> {
        let t = tag.trim().to_ascii_lowercase().replace([' ', '-'], "_");
        match t.as_str() {
            "exploit_repro" | "exploit" | "repro" => Ok(Self::ExploitRepro),
            "audit_finding" | "audit" | "finding" => Ok(Self::AuditFinding),
            "deny_failure" | "deny" | "deny_audit" => Ok(Self::DenyFailure),
            "review5_failure" | "review5" | "five_review" => Ok(Self::Review5Failure),
            "redteam_decision" | "redteam" | "red_team" => Ok(Self::RedteamDecision),
            _ => Err(DietError::UnknownSecuritySource),
        }
    }
}

/// Security severity ladder (closed). Unknown severities reject fail-closed.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
#[repr(u8)]
pub enum SecuritySeverity {
    /// Informational — no action required.
    Info = 1,
    /// Low severity.
    Low = 2,
    /// Medium severity.
    Medium = 3,
    /// High severity (blocks reward while open).
    High = 4,
    /// Critical severity (blocks reward while open).
    Critical = 5,
}

impl SecuritySeverity {
    /// Numeric discriminant (`1..=5`).
    pub const fn as_u8(self) -> u8 {
        self as u8
    }

    /// Parse from a discriminant; `None` if not `1..=5`.
    pub const fn from_u8(v: u8) -> Option<Self> {
        match v {
            1 => Some(Self::Info),
            2 => Some(Self::Low),
            3 => Some(Self::Medium),
            4 => Some(Self::High),
            5 => Some(Self::Critical),
            _ => None,
        }
    }

    /// Parse a severity string, rejecting unknown levels fail-closed.
    pub fn from_str_tag(s: &str) -> DietResult<Self> {
        match s.trim().to_ascii_lowercase().as_str() {
            "info" | "informational" | "none" => Ok(Self::Info),
            "low" => Ok(Self::Low),
            "medium" | "moderate" | "med" => Ok(Self::Medium),
            "high" => Ok(Self::High),
            "critical" | "crit" => Ok(Self::Critical),
            _ => Err(DietError::UnknownSecuritySource),
        }
    }

    /// Whether an *open* finding of this severity blocks reward (high/critical).
    pub const fn blocks_reward_when_open(self) -> bool {
        matches!(self, Self::High | Self::Critical)
    }
}

/// A security corpus source record: class + severity + content anchor, no raw payload.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub struct SecurityCorpusSource {
    /// The source atom.
    pub key: AtomDietKey,
    /// The source class.
    pub class: SecuritySourceClass,
    /// The severity.
    pub severity: SecuritySeverity,
    /// `sha256` of the source content (provenance anchor, never raw export).
    pub content_hash_32: [u8; 32],
}

impl SecurityCorpusSource {
    /// Build a security source record from a class tag, severity tag, and content.
    /// The content is hashed, never retained raw.
    pub fn new(
        key: AtomDietKey,
        class_tag: &str,
        severity_tag: &str,
        content: &str,
    ) -> DietResult<Self> {
        Ok(Self {
            key,
            class: SecuritySourceClass::from_tag(class_tag)?,
            severity: SecuritySeverity::from_str_tag(severity_tag)?,
            content_hash_32: crate::sha256(content.as_bytes()),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::diet_kind::DietSourceStage;

    fn key() -> AtomDietKey {
        AtomDietKey::new(DietSourceStage::StageD, 371)
    }

    #[test]
    fn all_source_classes_round_trip() {
        for c in SecuritySourceClass::ALL {
            assert_eq!(SecuritySourceClass::from_u8(c.as_u8()), Some(c));
        }
        assert_eq!(SecuritySourceClass::from_u8(0), None);
        assert_eq!(SecuritySourceClass::from_u8(6), None);
    }

    #[test]
    fn source_tags_parse() -> DietResult<()> {
        assert_eq!(
            SecuritySourceClass::from_tag("exploit repro")?,
            SecuritySourceClass::ExploitRepro
        );
        assert_eq!(
            SecuritySourceClass::from_tag("AUDIT")?,
            SecuritySourceClass::AuditFinding
        );
        assert_eq!(
            SecuritySourceClass::from_tag("deny-audit")?,
            SecuritySourceClass::DenyFailure
        );
        assert_eq!(
            SecuritySourceClass::from_tag("redteam")?,
            SecuritySourceClass::RedteamDecision
        );
        Ok(())
    }

    #[test]
    fn unknown_source_rejects() {
        assert!(matches!(
            SecuritySourceClass::from_tag("marketing"),
            Err(DietError::UnknownSecuritySource)
        ));
    }

    #[test]
    fn high_and_critical_severity_parse_and_block() -> DietResult<()> {
        assert_eq!(
            SecuritySeverity::from_str_tag("high")?,
            SecuritySeverity::High
        );
        assert_eq!(
            SecuritySeverity::from_str_tag("CRITICAL")?,
            SecuritySeverity::Critical
        );
        assert!(SecuritySeverity::High.blocks_reward_when_open());
        assert!(SecuritySeverity::Critical.blocks_reward_when_open());
        assert!(!SecuritySeverity::Medium.blocks_reward_when_open());
        Ok(())
    }

    #[test]
    fn unknown_severity_rejects() {
        assert!(matches!(
            SecuritySeverity::from_str_tag("apocalyptic"),
            Err(DietError::UnknownSecuritySource)
        ));
    }

    #[test]
    fn source_record_hashes_content() -> DietResult<()> {
        let s = SecurityCorpusSource::new(key(), "audit", "high", "finding body")?;
        assert_eq!(s.class, SecuritySourceClass::AuditFinding);
        assert_eq!(s.severity, SecuritySeverity::High);
        assert_eq!(s.content_hash_32, crate::sha256(b"finding body"));
        Ok(())
    }
}
