//! `privacy_report.json` validator (atom #341 · E.0.10, §4.3 `PrivacyReport`).
//!
//! The report must agree with the scanners: a `Pass` verdict that still reports
//! any PII/secret hit is internally inconsistent and **rejects** (fail-closed).
//! An unknown verdict is treated as `Reject`. Hit counts are summed tolerantly
//! across a per-atom-variable `checks` set and split into PII vs secret buckets
//! by check name.
use crate::AtomDietKey;
use crate::diet_kind::DietFileKind;
use crate::error::{DietError, DietResult};
use crate::parse_json;
use serde_json::Value;

const KIND: DietFileKind = DietFileKind::PrivacyReport;

/// The privacy verdict for a sidecar (§4.3 `PrivacyDecision`).
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
#[repr(u8)]
pub enum PrivacyDecision {
    /// Clean: no PII/secret found.
    Pass = 1,
    /// Sensitive data was present but redacted.
    Redacted = 2,
    /// Sensitive data could not be cleared — the sample is rejected.
    Reject = 3,
}

impl PrivacyDecision {
    /// Numeric discriminant.
    pub const fn as_u8(self) -> u8 {
        self as u8
    }

    /// Parse from a discriminant; `None` if not `1..=3`.
    pub const fn from_u8(v: u8) -> Option<Self> {
        match v {
            1 => Some(Self::Pass),
            2 => Some(Self::Redacted),
            3 => Some(Self::Reject),
            _ => None,
        }
    }

    /// Classify a free-text `verdict` string, failing closed on anything
    /// unrecognized.
    pub fn from_verdict(verdict: &str) -> Self {
        let upper = verdict.trim().to_ascii_uppercase();
        if upper.starts_with("PASS") {
            Self::Pass
        } else if upper.contains("REDACT") {
            Self::Redacted
        } else {
            // REJECT / FAIL / anything unrecognized all fail closed.
            Self::Reject
        }
    }
}

/// A validated privacy report (§4.3 `PrivacyReport`).
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub struct PrivacyReport {
    /// The source atom this report belongs to.
    pub key: AtomDietKey,
    /// The privacy verdict.
    pub decision: PrivacyDecision,
    /// Sum of PII-class check hits.
    pub pii_hits_u32: u32,
    /// Sum of secret-class check hits.
    pub secret_hits_u32: u32,
    /// `sha256` of the redaction evidence (surface audit + terminal review).
    pub redaction_hash_32: [u8; 32],
}

fn is_secret_check(name: &str) -> bool {
    let n = name.to_ascii_lowercase();
    n.contains("secret")
        || n.contains("key")
        || n.contains("credential")
        || n.contains("canary")
        || n.contains("wallet")
        || n.contains("sponsor")
        || n.contains("commerce")
}

fn clamp_u32(v: u64) -> u32 {
    v.min(u32::MAX as u64) as u32
}

/// Parse and validate a `privacy_report.json` for atom `key`.
pub fn parse(key: AtomDietKey, text: &str) -> DietResult<PrivacyReport> {
    let v = parse_json(KIND, text)?;
    let obj = v.as_object().ok_or(DietError::UnexpectedType {
        kind: KIND,
        field: "$root",
    })?;
    let verdict = obj
        .get("verdict")
        .and_then(|x| x.as_str())
        .ok_or(DietError::MissingField {
            kind: KIND,
            field: "verdict",
        })?;
    let decision = PrivacyDecision::from_verdict(verdict);

    let mut pii = 0u64;
    let mut secret = 0u64;
    if let Some(Value::Object(checks)) = obj.get("checks") {
        for (name, body) in checks {
            let count = body
                .get("count")
                .and_then(serde_json::Value::as_u64)
                .unwrap_or(0);
            if is_secret_check(name) {
                secret = secret.saturating_add(count);
            } else {
                pii = pii.saturating_add(count);
            }
        }
    }

    let mut red = String::new();
    if let Some(s) = obj.get("surface_payload_audit") {
        red.push_str(&s.to_string());
    }
    if let Some(s) = obj
        .get("terminal_redaction_review")
        .and_then(|x| x.as_str())
    {
        red.push_str(s);
    }
    if red.is_empty() {
        red.push_str("none");
    }
    let redaction_hash_32 = crate::sha256(red.as_bytes());

    if matches!(decision, PrivacyDecision::Pass) && (pii + secret) > 0 {
        return Err(DietError::PrivacyInconsistent { kind: KIND });
    }

    Ok(PrivacyReport {
        key,
        decision,
        pii_hits_u32: clamp_u32(pii),
        secret_hits_u32: clamp_u32(secret),
        redaction_hash_32,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::diet_kind::DietSourceStage;

    fn key() -> AtomDietKey {
        AtomDietKey::new(DietSourceStage::Phase0, 16)
    }

    #[test]
    fn pass_zero_is_clean() -> DietResult<()> {
        let doc = r#"{"verdict":"PASS — 0 secret / 0 raw user data","checks":{"raw_secret_in_code":{"count":0},"provider_body_present":{"count":0}}}"#;
        let r = parse(key(), doc)?;
        assert_eq!(r.decision, PrivacyDecision::Pass);
        assert_eq!(r.pii_hits_u32, 0);
        assert_eq!(r.secret_hits_u32, 0);
        Ok(())
    }

    #[test]
    fn redacted_verdict_parses() -> DietResult<()> {
        let r = parse(
            key(),
            r#"{"verdict":"REDACTED — 2 tokens masked","checks":{}}"#,
        )?;
        assert_eq!(r.decision, PrivacyDecision::Redacted);
        Ok(())
    }

    #[test]
    fn reject_verdict_keeps_hits() -> DietResult<()> {
        let doc =
            r#"{"verdict":"REJECT — secret found","checks":{"wallet_secret_present":{"count":1}}}"#;
        let r = parse(key(), doc)?;
        assert_eq!(r.decision, PrivacyDecision::Reject);
        assert_eq!(r.secret_hits_u32, 1);
        Ok(())
    }

    #[test]
    fn pass_with_hits_is_inconsistent() {
        let doc = r#"{"verdict":"PASS","checks":{"private_memory_pointer":{"count":1}}}"#;
        assert!(matches!(
            parse(key(), doc),
            Err(DietError::PrivacyInconsistent {
                kind: DietFileKind::PrivacyReport
            })
        ));
    }

    #[test]
    fn commerce_shaped_secret_under_pass_rejects() {
        let doc = r#"{"verdict":"PASS — clean","checks":{"commerce_secret_present":{"count":1}}}"#;
        assert!(matches!(
            parse(key(), doc),
            Err(DietError::PrivacyInconsistent { .. })
        ));
    }

    #[test]
    fn unknown_verdict_fails_closed() -> DietResult<()> {
        let r = parse(key(), r#"{"verdict":"weird","checks":{}}"#)?;
        assert_eq!(r.decision, PrivacyDecision::Reject);
        Ok(())
    }

    #[test]
    fn missing_verdict_rejects() {
        assert!(matches!(
            parse(key(), r#"{"checks":{}}"#),
            Err(DietError::MissingField {
                kind: DietFileKind::PrivacyReport,
                field: "verdict"
            })
        ));
    }
}
