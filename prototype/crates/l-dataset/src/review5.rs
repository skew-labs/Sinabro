//! `review_5pack.json` parser.
//!
//! The 5-review is mandatory: all five axes must be present. A pass on one axis
//! cannot cancel a fail on another — `reward_blocked` is true if *any* axis
//! fails. A `Warning` verdict is preserved as its own state, not collapsed.
use crate::diet_kind::DietFileKind;
use crate::error::{DietError, DietResult};
use crate::{as_object, parse_json};

const KIND: DietFileKind = DietFileKind::Review5Pack;

/// One of the five mandatory review axes.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum ReviewAxis {
    /// Performance.
    Perf,
    /// Security.
    Security,
    /// On-chain correctness.
    Chain,
    /// Agent token economy.
    AgentToken,
    /// Developer experience.
    Devex,
}

impl ReviewAxis {
    /// All five axes in canonical order.
    pub const ALL: [ReviewAxis; 5] = [
        Self::Perf,
        Self::Security,
        Self::Chain,
        Self::AgentToken,
        Self::Devex,
    ];

    /// The JSON key for this axis.
    pub const fn json_key(self) -> &'static str {
        match self {
            Self::Perf => "perf",
            Self::Security => "security",
            Self::Chain => "chain",
            Self::AgentToken => "agent_token",
            Self::Devex => "devex",
        }
    }
}

/// Normalized per-axis verdict.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
#[repr(u8)]
pub enum AxisVerdict {
    /// Clean pass.
    Pass = 1,
    /// Pass with a measurement/finding deferred.
    PassWithDeferred = 2,
    /// A warning (preserved, not a pass).
    Warning = 3,
    /// A fail.
    Fail = 4,
    /// An unrecognized verdict (fail-closed downstream).
    Unknown = 5,
}

impl AxisVerdict {
    /// Numeric discriminant.
    pub const fn as_u8(self) -> u8 {
        self as u8
    }

    /// Classify a free-text axis verdict.
    pub fn classify(s: &str) -> Self {
        let u = s.trim().to_ascii_uppercase();
        if u.contains("FAIL") || u.contains("REJECT") {
            Self::Fail
        } else if u.starts_with("PASS") {
            if u.contains("DEFER") || u.contains("MEASUREMENT") {
                Self::PassWithDeferred
            } else {
                Self::Pass
            }
        } else if u.contains("WARN") {
            Self::Warning
        } else {
            Self::Unknown
        }
    }

    /// Whether this verdict is a fail.
    pub const fn is_fail(self) -> bool {
        matches!(self, Self::Fail)
    }
}

/// The five normalized axis verdicts.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub struct Review5 {
    /// Performance verdict.
    pub perf: AxisVerdict,
    /// Security verdict.
    pub security: AxisVerdict,
    /// Chain verdict.
    pub chain: AxisVerdict,
    /// Agent-token verdict.
    pub agent_token: AxisVerdict,
    /// Devex verdict.
    pub devex: AxisVerdict,
}

impl Review5 {
    /// The verdict for a given axis.
    pub const fn axis(&self, a: ReviewAxis) -> AxisVerdict {
        match a {
            ReviewAxis::Perf => self.perf,
            ReviewAxis::Security => self.security,
            ReviewAxis::Chain => self.chain,
            ReviewAxis::AgentToken => self.agent_token,
            ReviewAxis::Devex => self.devex,
        }
    }

    /// Whether any axis failed — a pass elsewhere cannot cancel it.
    pub fn any_fail(&self) -> bool {
        ReviewAxis::ALL.into_iter().any(|a| self.axis(a).is_fail())
    }

    /// A fail on any axis blocks reward.
    pub fn reward_blocked(&self) -> bool {
        self.any_fail()
    }
}

fn axis_verdict(
    root: &serde_json::Map<String, serde_json::Value>,
    axis: ReviewAxis,
) -> DietResult<AxisVerdict> {
    let key = axis.json_key();
    let obj = root
        .get(key)
        .and_then(|v| v.as_object())
        .ok_or(DietError::ReviewAxisMissing { axis: key })?;
    let verdict = obj
        .get("verdict")
        .and_then(|x| x.as_str())
        .ok_or(DietError::ReviewAxisMissing { axis: key })?;
    Ok(AxisVerdict::classify(verdict))
}

/// Parse and normalize a `review_5pack.json` document.
pub fn parse(text: &str) -> DietResult<Review5> {
    let v = parse_json(KIND, text)?;
    let obj = as_object(&v, KIND, "$root")?;
    Ok(Review5 {
        perf: axis_verdict(obj, ReviewAxis::Perf)?,
        security: axis_verdict(obj, ReviewAxis::Security)?,
        chain: axis_verdict(obj, ReviewAxis::Chain)?,
        agent_token: axis_verdict(obj, ReviewAxis::AgentToken)?,
        devex: axis_verdict(obj, ReviewAxis::Devex)?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn full(security: &str) -> String {
        format!(
            r#"{{"perf":{{"verdict":"PASS_WITH_MEASUREMENT_DEFERRED"}},"security":{{"verdict":"{security}"}},"chain":{{"verdict":"PASS"}},"agent_token":{{"verdict":"WARNING"}},"devex":{{"verdict":"PASS"}}}}"#
        )
    }

    #[test]
    fn five_axes_present_parses() -> DietResult<()> {
        let r = parse(&full("PASS"))?;
        assert_eq!(r.perf, AxisVerdict::PassWithDeferred);
        assert_eq!(r.agent_token, AxisVerdict::Warning);
        assert!(!r.reward_blocked());
        Ok(())
    }

    #[test]
    fn missing_axis_rejects() {
        let doc = r#"{"perf":{"verdict":"PASS"},"security":{"verdict":"PASS"},"chain":{"verdict":"PASS"},"agent_token":{"verdict":"PASS"}}"#;
        assert!(matches!(
            parse(doc),
            Err(DietError::ReviewAxisMissing { axis: "devex" })
        ));
    }

    #[test]
    fn fail_axis_blocks_reward() -> DietResult<()> {
        let r = parse(&full("FAIL — open critical"))?;
        assert_eq!(r.security, AxisVerdict::Fail);
        assert!(r.any_fail());
        assert!(r.reward_blocked());
        Ok(())
    }

    #[test]
    fn warning_axis_is_preserved() -> DietResult<()> {
        let r = parse(&full("PASS"))?;
        assert_eq!(r.agent_token, AxisVerdict::Warning);
        Ok(())
    }
}
