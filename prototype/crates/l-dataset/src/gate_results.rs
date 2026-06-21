//! `gate_results.json` + `test_results.json` parsers (atom #344 · E.0.13).
//!
//! A gate is green only when an explicit, hashed `status` says so — never
//! inferred from prose. Each gate's command (`tool`) is hashed for command
//! linkage. Note the classification order: `DEFERRED` is checked before any
//! `RED` test so `STRUCTURAL_PASS_MEASUREMENT_DEFERRED` is not misread as a fail
//! (its substring `…DEFER**RED**…`).
use crate::diet_kind::DietFileKind;
use crate::error::DietResult;
use crate::{as_object, opt_str, opt_u64, parse_json};

const GATE_KIND: DietFileKind = DietFileKind::GateResults;
const TEST_KIND: DietFileKind = DietFileKind::TestResults;

/// Explicit gate status.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
#[repr(u8)]
pub enum GateStatus {
    /// Green.
    Pass = 1,
    /// Red.
    Fail = 2,
    /// Not applicable to this atom.
    NotApplicable = 3,
    /// Not run this atom.
    NotRun = 4,
    /// Structurally green, a measurement deferred.
    Deferred = 5,
    /// Unrecognized / missing status (not green).
    Unknown = 6,
}

impl GateStatus {
    /// Numeric discriminant.
    pub const fn as_u8(self) -> u8 {
        self as u8
    }

    /// Classify a free-text gate status, fail-closed and DEFERRED-safe.
    pub fn classify(s: &str) -> Self {
        let u = s.trim().to_ascii_uppercase();
        if u.contains("FAIL") {
            Self::Fail
        } else if u.contains("DEFER") {
            Self::Deferred
        } else if u.starts_with("PASS") || u.contains("GREEN") {
            Self::Pass
        } else if u.starts_with("N/A") || u.contains("NOT_APPLICABLE") || u.contains("NOT_VERIFIED")
        {
            Self::NotApplicable
        } else if u.contains("NOT_RUN") || u.contains("NOTRUN") {
            Self::NotRun
        } else if u == "RED" {
            Self::Fail
        } else {
            Self::Unknown
        }
    }
}

/// One gate outcome, with optional command linkage.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub struct GateOutcome {
    /// `sha256` of the gate id.
    pub gate_id_hash_32: [u8; 32],
    /// The explicit status.
    pub status: GateStatus,
    /// `sha256` of the gate's command, when linked.
    pub command_hash_32: Option<[u8; 32]>,
}

/// Parse `gate_results.json` into per-gate outcomes. A gate listed in
/// `gate_set` but absent yields [`GateStatus::Unknown`] (never silently green).
pub fn parse_gates(text: &str) -> DietResult<Vec<GateOutcome>> {
    let v = parse_json(GATE_KIND, text)?;
    let obj = as_object(&v, GATE_KIND, "$root")?;
    let mut out = Vec::new();
    if let Some(set) = obj.get("gate_set").and_then(|x| x.as_array()) {
        for name_v in set {
            let Some(name) = name_v.as_str() else {
                continue;
            };
            let gate_id_hash_32 = crate::sha256(name.as_bytes());
            match obj.get(name).and_then(|g| g.as_object()) {
                Some(g) => out.push(GateOutcome {
                    gate_id_hash_32,
                    status: opt_str(g, "status").map_or(GateStatus::Unknown, GateStatus::classify),
                    command_hash_32: opt_str(g, "tool").map(|t| crate::sha256(t.as_bytes())),
                }),
                None => out.push(GateOutcome {
                    gate_id_hash_32,
                    status: GateStatus::Unknown,
                    command_hash_32: None,
                }),
            }
        }
    } else {
        for (name, g) in obj {
            if let Some(go) = g.as_object() {
                if let Some(status_str) = go.get("status").and_then(|s| s.as_str()) {
                    out.push(GateOutcome {
                        gate_id_hash_32: crate::sha256(name.as_bytes()),
                        status: GateStatus::classify(status_str),
                        command_hash_32: opt_str(go, "tool").map(|t| crate::sha256(t.as_bytes())),
                    });
                }
            }
        }
    }
    Ok(out)
}

/// Parsed test totals.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub struct TestOutcome {
    /// Tests passed.
    pub passed_u32: u32,
    /// Tests failed.
    pub failed_u32: u32,
    /// Tests ignored.
    pub ignored_u32: u32,
}

fn clamp(v: u64) -> u32 {
    v.min(u32::MAX as u64) as u32
}

/// Parse `test_results.json` totals from a `summary` object (or the root).
pub fn parse_tests(text: &str) -> DietResult<TestOutcome> {
    let v = parse_json(TEST_KIND, text)?;
    let obj = as_object(&v, TEST_KIND, "$root")?;
    let src = obj
        .get("summary")
        .and_then(|s| s.as_object())
        .unwrap_or(obj);
    Ok(TestOutcome {
        passed_u32: clamp(opt_u64(src, "passed").unwrap_or(0)),
        failed_u32: clamp(opt_u64(src, "failed").unwrap_or(0)),
        ignored_u32: clamp(opt_u64(src, "ignored").unwrap_or(0)),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn gate_pass_with_command_linkage() -> DietResult<()> {
        let doc =
            r#"{"gate_set":["G-FMT"],"G-FMT":{"status":"PASS","tool":"cargo fmt --all --check"}}"#;
        let g = parse_gates(doc)?;
        assert_eq!(g.len(), 1);
        assert_eq!(g[0].status, GateStatus::Pass);
        assert_eq!(
            g[0].command_hash_32,
            Some(crate::sha256(b"cargo fmt --all --check"))
        );
        Ok(())
    }

    #[test]
    fn gate_red_is_fail() -> DietResult<()> {
        let doc = r#"{"gate_set":["G-TEST"],"G-TEST":{"status":"FAIL"}}"#;
        assert_eq!(parse_gates(doc)?[0].status, GateStatus::Fail);
        Ok(())
    }

    #[test]
    fn deferred_is_not_misread_as_fail() {
        assert_eq!(
            GateStatus::classify("STRUCTURAL_PASS_MEASUREMENT_DEFERRED"),
            GateStatus::Deferred
        );
        assert_eq!(GateStatus::classify("RED"), GateStatus::Fail);
    }

    #[test]
    fn missing_gate_is_unknown_not_green() -> DietResult<()> {
        let doc = r#"{"gate_set":["G-MISSING"]}"#;
        let g = parse_gates(doc)?;
        assert_eq!(g[0].status, GateStatus::Unknown);
        assert_eq!(g[0].command_hash_32, None);
        Ok(())
    }

    #[test]
    fn test_results_pass_and_fail() -> DietResult<()> {
        let pass = parse_tests(r#"{"summary":{"passed":144,"failed":0,"ignored":2}}"#)?;
        assert_eq!(pass.passed_u32, 144);
        assert_eq!(pass.failed_u32, 0);
        let fail = parse_tests(r#"{"summary":{"passed":10,"failed":3}}"#)?;
        assert_eq!(fail.failed_u32, 3);
        Ok(())
    }
}
