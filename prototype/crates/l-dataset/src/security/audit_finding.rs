//! Audit finding parser + `SecuritySignal` aggregate.
//!
//! A normalized audit finding carries a severity and a status
//! (open / fixed / accepted-risk / false-positive). A finding with **no backing
//! evidence rejects** ([`DietError::MissingEvidence`]) — a claimed critical with
//! nothing to reverify is not data. The reward rule is hard: an *open* high or
//! critical finding blocks reward for the atom and may enter SFT only as
//! negative context, never as a positive sample. The [`SecuritySignal`] is
//! the per-atom aggregate: open-high / open-critical counts plus the review-5
//! and deny-audit content anchors.
use crate::diet_kind::{AtomDietKey, DietFileKind};
use crate::error::{DietError, DietResult};
use crate::security::source::SecuritySeverity;
use crate::{as_object, opt_bool, parse_json, req_array, req_str};

/// Findings travel with the security review pack; errors are tagged with it.
const KIND: DietFileKind = DietFileKind::Review5Pack;

/// The lifecycle status of an audit finding.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
#[repr(u8)]
pub enum FindingStatus {
    /// Still open — counts against reward when high/critical.
    Open = 1,
    /// Fixed and (ideally) regression-covered.
    Fixed = 2,
    /// A risk explicitly accepted with a waiver.
    AcceptedRisk = 3,
    /// Triaged as a false positive.
    FalsePositive = 4,
}

impl FindingStatus {
    /// Numeric discriminant (`1..=4`).
    pub const fn as_u8(self) -> u8 {
        self as u8
    }

    /// Classify a status string. Unknown / unset all fail closed to `Open`
    /// (the worst case for the reward gate), never silently "resolved".
    pub fn from_tag(s: &str) -> Self {
        match s.trim().to_ascii_lowercase().as_str() {
            "fixed" | "resolved" | "closed" => Self::Fixed,
            "accepted" | "accepted_risk" | "accepted-risk" | "risk_accepted" => Self::AcceptedRisk,
            "false_positive" | "false-positive" | "falsepositive" | "fp" | "invalid" => {
                Self::FalsePositive
            }
            _ => Self::Open,
        }
    }
}

/// A normalized audit finding record.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub struct AuditFinding {
    /// The source atom.
    pub key: AtomDietKey,
    /// The finding severity.
    pub severity: SecuritySeverity,
    /// The finding status.
    pub status: FindingStatus,
    /// `sha256` of the finding id (provenance anchor).
    pub finding_hash_32: [u8; 32],
    /// Whether a backing evidence anchor was present (required to parse at all).
    pub evidence_present: bool,
}

impl AuditFinding {
    /// Whether this finding blocks reward: an open high/critical finding does.
    pub const fn blocks_reward(&self) -> bool {
        matches!(self.status, FindingStatus::Open) && self.severity.blocks_reward_when_open()
    }
}

/// The per-atom security aggregate.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub struct SecuritySignal {
    /// The source atom.
    pub key: AtomDietKey,
    /// `sha256` anchor of the 5-review pack.
    pub review5_hash_32: [u8; 32],
    /// `sha256` anchor of the deny-audit record.
    pub deny_hash_32: [u8; 32],
    /// Count of open high-severity findings.
    pub open_high_u32: u32,
    /// Count of open critical-severity findings.
    pub open_critical_u32: u32,
}

impl SecuritySignal {
    /// Whether the atom's security posture blocks reward (any open high/critical).
    pub const fn blocks_reward(&self) -> bool {
        self.open_high_u32 > 0 || self.open_critical_u32 > 0
    }
}

/// Parse a findings document (`{"findings":[{id,severity,status,evidence}]}`)
/// into normalized [`AuditFinding`] records. A finding without backing evidence
/// rejects; an unknown severity rejects.
pub fn parse_findings(key: AtomDietKey, findings_json: &str) -> DietResult<Vec<AuditFinding>> {
    let v = parse_json(KIND, findings_json)?;
    let obj = as_object(&v, KIND, "$root")?;
    let arr = req_array(obj, KIND, "findings")?;
    let mut out = Vec::with_capacity(arr.len());
    for f in arr {
        let co = as_object(f, KIND, "findings[]")?;
        let id = req_str(co, KIND, "id")?;
        let severity = SecuritySeverity::from_str_tag(req_str(co, KIND, "severity")?)?;
        let status =
            FindingStatus::from_tag(co.get("status").and_then(|x| x.as_str()).unwrap_or("open"));
        let evidence_present = co
            .get("evidence")
            .and_then(|x| x.as_str())
            .is_some_and(|s| !s.trim().is_empty())
            || co
                .get("evidence_hash")
                .and_then(|x| x.as_str())
                .is_some_and(|s| !s.trim().is_empty())
            || opt_bool(co, "evidence_present") == Some(true);
        if !evidence_present {
            return Err(DietError::MissingEvidence { kind: KIND });
        }
        out.push(AuditFinding {
            key,
            severity,
            status,
            finding_hash_32: crate::sha256(id.as_bytes()),
            evidence_present,
        });
    }
    Ok(out)
}

/// Aggregate a set of findings into the [`SecuritySignal`], folding in the
/// review-5 and deny-audit content anchors.
pub fn aggregate(
    key: AtomDietKey,
    findings: &[AuditFinding],
    review5_hash_32: [u8; 32],
    deny_hash_32: [u8; 32],
) -> SecuritySignal {
    let mut open_high = 0u32;
    let mut open_critical = 0u32;
    for f in findings {
        if matches!(f.status, FindingStatus::Open) {
            match f.severity {
                SecuritySeverity::High => open_high = open_high.saturating_add(1),
                SecuritySeverity::Critical => open_critical = open_critical.saturating_add(1),
                _ => {}
            }
        }
    }
    SecuritySignal {
        key,
        review5_hash_32,
        deny_hash_32,
        open_high_u32: open_high,
        open_critical_u32: open_critical,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::diet_kind::DietSourceStage;

    fn key() -> AtomDietKey {
        AtomDietKey::new(DietSourceStage::StageD, 372)
    }

    #[test]
    fn open_critical_blocks_reward() -> DietResult<()> {
        let doc = r#"{"findings":[{"id":"F1","severity":"critical","status":"open","evidence":"poc.rs:12"}]}"#;
        let f = parse_findings(key(), doc)?;
        assert_eq!(f.len(), 1);
        assert!(f[0].blocks_reward());
        let sig = aggregate(key(), &f, [1u8; 32], [2u8; 32]);
        assert_eq!(sig.open_critical_u32, 1);
        assert!(sig.blocks_reward());
        Ok(())
    }

    #[test]
    fn fixed_high_does_not_block() -> DietResult<()> {
        let doc = r#"{"findings":[{"id":"F2","severity":"high","status":"fixed","evidence":"fix.rs:1"}]}"#;
        let f = parse_findings(key(), doc)?;
        assert!(!f[0].blocks_reward());
        let sig = aggregate(key(), &f, [0u8; 32], [0u8; 32]);
        assert_eq!(sig.open_high_u32, 0);
        assert!(!sig.blocks_reward());
        Ok(())
    }

    #[test]
    fn accepted_risk_is_not_open() -> DietResult<()> {
        let doc = r#"{"findings":[{"id":"F3","severity":"high","status":"accepted_risk","evidence":"waiver"}]}"#;
        let f = parse_findings(key(), doc)?;
        assert_eq!(f[0].status, FindingStatus::AcceptedRisk);
        assert!(!f[0].blocks_reward());
        Ok(())
    }

    #[test]
    fn false_positive_is_not_open() -> DietResult<()> {
        let doc = r#"{"findings":[{"id":"F4","severity":"critical","status":"false_positive","evidence":"triage"}]}"#;
        let f = parse_findings(key(), doc)?;
        assert_eq!(f[0].status, FindingStatus::FalsePositive);
        assert!(!f[0].blocks_reward());
        Ok(())
    }

    #[test]
    fn missing_evidence_rejects() {
        let doc = r#"{"findings":[{"id":"F5","severity":"critical","status":"open"}]}"#;
        assert!(matches!(
            parse_findings(key(), doc),
            Err(DietError::MissingEvidence { .. })
        ));
    }

    #[test]
    fn unknown_severity_rejects() {
        let doc = r#"{"findings":[{"id":"F6","severity":"spicy","status":"open","evidence":"x"}]}"#;
        assert!(matches!(
            parse_findings(key(), doc),
            Err(DietError::UnknownSecuritySource)
        ));
    }

    #[test]
    fn status_unknown_fails_closed_to_open() {
        assert_eq!(FindingStatus::from_tag("wontfix"), FindingStatus::Open);
        assert_eq!(FindingStatus::from_tag(""), FindingStatus::Open);
    }
}
