//! `sinabro eval korean / ruler` + audit report rendering — Korean/ruler eval
//! routing (F-WP-06B, atom #458 · F.6.7).
//!
//! Language eval is explicit evidence, not vibes: the terminology drift and the
//! ruler verdict are visible. Audit reports render in Korean/English as **safe,
//! report-first** notes — candidate/finding status, impact hypothesis, affected
//! invariant, local repro summary, remediation, and an evidence hash. They must
//! never produce an exploit procedure, production-probing instructions, or
//! certainty language for an unreproduced candidate.
//!
//! Reuse (no reinvention): the eval outcome is the Stage E
//! [`mnemos_l_dataset::sidecar_training::EvalSummaryView`]; the render truth is
//! the cockpit [`RenderTruth`]. This module performs no live action.

use crate::hex32;
use crate::tui::RenderTruth;
use mnemos_l_dataset::sidecar_training::EvalSummaryView;

/// First 16 hex characters of a 32-byte hash — a redacted, display-only prefix.
#[must_use]
fn redact16(bytes: &[u8; 32]) -> String {
    hex32(bytes).chars().take(16).collect()
}

/// Markers that indicate an exploit procedure (never rendered in a report).
const EXPLOIT_MARKERS: &[&str] = &[
    "rm -rf",
    "drop table",
    "payload=",
    "step 1:",
    "exploit:",
    "selfdestruct",
    "transfer all funds",
    "private key=",
];

/// Markers that indicate unwarranted certainty (banned for unreproduced
/// candidates).
const CERTAINTY_MARKERS: &[&str] = &[
    "definitely",
    "guaranteed",
    "is exploitable",
    "certainly",
    "100% sure",
    "확실히",
    "반드시",
];

/// Why a language-eval / audit-report command was refused (fail-closed).
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum EvalLanguageReject {
    /// The text carries an exploit procedure / production-probing instruction.
    #[error("exploit instruction not allowed in a report")]
    ExploitInstruction,
    /// An unreproduced candidate used certainty language.
    #[error("certainty language not allowed for an unreproduced candidate")]
    CandidateCertainty,
}

/// The report language.
#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReportLang {
    /// Korean.
    Korean = 1,
    /// English.
    English = 2,
}

impl ReportLang {
    /// Stable u8 discriminant.
    #[must_use]
    pub const fn as_u8(self) -> u8 {
        self as u8
    }
}

/// A `sinabro eval korean / ruler` projection over a canonical [`EvalSummaryView`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LanguageEvalView {
    /// Redacted outcome hash from the eval summary.
    pub outcome_redacted: String,
    /// Number of terminology-map drifts detected.
    pub terminology_drift_u32: u32,
    /// Whether the ruler eval passed.
    pub ruler_pass: bool,
}

impl LanguageEvalView {
    /// Project a language eval from a canonical eval summary plus the measured
    /// terminology drift and ruler verdict.
    #[must_use]
    pub fn from_summary(
        summary: &EvalSummaryView,
        terminology_drift_u32: u32,
        ruler_pass: bool,
    ) -> Self {
        Self {
            outcome_redacted: redact16(&summary.outcome_hash_32),
            terminology_drift_u32,
            ruler_pass,
        }
    }

    /// Render truth: a failed ruler is `Red`; any terminology drift is `Yellow`;
    /// a clean, ruler-passing eval is `Green`.
    #[must_use]
    pub fn render_truth(&self) -> RenderTruth {
        if !self.ruler_pass {
            RenderTruth::Red
        } else if self.terminology_drift_u32 > 0 {
            RenderTruth::Yellow
        } else {
            RenderTruth::Green
        }
    }

    /// Colorless status lines bounded by `rows`.
    #[must_use]
    pub fn render(&self, rows: u16) -> Vec<String> {
        let lines = vec![
            format!("outcome={}", self.outcome_redacted),
            format!("terminology_drift={}", self.terminology_drift_u32),
            format!("ruler_pass={}", self.ruler_pass),
            format!("truth_u8={}", self.render_truth() as u8),
        ];
        lines.into_iter().take(rows as usize).collect()
    }
}

/// A safe, report-first audit report (Korean/English). It carries only status +
/// hashes — never an exploit procedure — so its rendering cannot leak a recipe.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuditReportView {
    /// The report language.
    pub lang: ReportLang,
    /// Whether this is a reproduced finding (vs an unreproduced candidate).
    pub is_finding: bool,
    /// Redacted rule id.
    pub rule_id_redacted: String,
    /// Redacted source location.
    pub location_redacted: String,
    /// Redacted affected invariant.
    pub invariant_redacted: String,
    /// Redacted evidence hash.
    pub evidence_redacted: String,
    /// Confidence in basis points.
    pub confidence_bps_u16: u16,
}

impl AuditReportView {
    /// An unreproduced candidate report (status = candidate; no certainty).
    #[must_use]
    pub fn candidate(
        lang: ReportLang,
        rule_id_hash_32: &[u8; 32],
        location_hash_32: &[u8; 32],
        invariant_hash_32: &[u8; 32],
        evidence_hash_32: &[u8; 32],
        confidence_bps_u16: u16,
    ) -> Self {
        Self {
            lang,
            is_finding: false,
            rule_id_redacted: redact16(rule_id_hash_32),
            location_redacted: redact16(location_hash_32),
            invariant_redacted: redact16(invariant_hash_32),
            evidence_redacted: redact16(evidence_hash_32),
            confidence_bps_u16,
        }
    }

    /// A reproduced finding report (status = finding; confidence pinned full).
    #[must_use]
    pub fn finding(
        lang: ReportLang,
        rule_id_hash_32: &[u8; 32],
        location_hash_32: &[u8; 32],
        invariant_hash_32: &[u8; 32],
        evidence_hash_32: &[u8; 32],
    ) -> Self {
        Self {
            lang,
            is_finding: true,
            rule_id_redacted: redact16(rule_id_hash_32),
            location_redacted: redact16(location_hash_32),
            invariant_redacted: redact16(invariant_hash_32),
            evidence_redacted: redact16(evidence_hash_32),
            confidence_bps_u16: 10000,
        }
    }

    /// The status label — `finding` (reproduced) or `candidate` (unreproduced).
    #[must_use]
    pub const fn status_label(&self) -> &'static str {
        if self.is_finding {
            "finding"
        } else {
            "candidate"
        }
    }

    /// Report-first lines bounded by `rows`. Only status + hashes are emitted, so
    /// no exploit procedure can appear.
    #[must_use]
    pub fn render(&self, rows: u16) -> Vec<String> {
        let lines = vec![
            format!("status={}", self.status_label()),
            format!("lang_u8={}", self.lang.as_u8()),
            format!("rule_id={}", self.rule_id_redacted),
            format!("location={}", self.location_redacted),
            format!("invariant={}", self.invariant_redacted),
            format!("evidence={}", self.evidence_redacted),
            format!("confidence_bps={}", self.confidence_bps_u16),
        ];
        lines.into_iter().take(rows as usize).collect()
    }
}

/// Refuse any free-text remediation note that carries an exploit procedure or a
/// production-probing instruction.
pub fn assert_no_exploit_instruction(text: &str) -> Result<(), EvalLanguageReject> {
    let lower = text.to_ascii_lowercase();
    for m in EXPLOIT_MARKERS {
        if lower.contains(m) {
            return Err(EvalLanguageReject::ExploitInstruction);
        }
    }
    Ok(())
}

/// Refuse certainty language for an *unreproduced* candidate (a reproduced
/// finding may state its verified result).
pub fn assert_no_candidate_certainty(
    text: &str,
    is_finding: bool,
) -> Result<(), EvalLanguageReject> {
    if is_finding {
        return Ok(());
    }
    let lower = text.to_ascii_lowercase();
    for m in CERTAINTY_MARKERS {
        if lower.contains(m) {
            return Err(EvalLanguageReject::CandidateCertainty);
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    #![allow(clippy::expect_used)]
    #![allow(clippy::panic)]

    use super::*;

    const COMMERCE_TOKENS: &[&str] = &[
        "price", "pay", "buy", "sell", "checkout", "refund", "fee", "cost", "$",
    ];

    fn summary() -> EvalSummaryView {
        EvalSummaryView {
            outcome_hash_32: [0xEE; 32],
        }
    }

    #[test]
    fn korean_fixture_clean_is_green() {
        let v = LanguageEvalView::from_summary(&summary(), 0, true);
        assert_eq!(v.render_truth(), RenderTruth::Green);
        assert_eq!(v.outcome_redacted.len(), 16);
    }

    #[test]
    fn terminology_drift_is_yellow() {
        let v = LanguageEvalView::from_summary(&summary(), 3, true);
        assert_eq!(v.terminology_drift_u32, 3);
        assert_eq!(v.render_truth(), RenderTruth::Yellow);
    }

    #[test]
    fn ruler_fail_is_red() {
        let v = LanguageEvalView::from_summary(&summary(), 0, false);
        assert_eq!(v.render_truth(), RenderTruth::Red);
    }

    #[test]
    fn gate_status_lines_present() {
        let v = LanguageEvalView::from_summary(&summary(), 1, true);
        let lines = v.render(8);
        assert!(lines.iter().any(|l| l == "ruler_pass=true"));
        assert!(lines.iter().any(|l| l == "terminology_drift=1"));
    }

    #[test]
    fn audit_candidate_korean_report() {
        let r = AuditReportView::candidate(
            ReportLang::Korean,
            &[1; 32],
            &[2; 32],
            &[3; 32],
            &[4; 32],
            6000,
        );
        let lines = r.render(16);
        assert!(lines.iter().any(|l| l == "status=candidate"));
        assert!(lines.iter().any(|l| l == "lang_u8=1"));
        assert_eq!(r.status_label(), "candidate");
    }

    #[test]
    fn audit_finding_english_report() {
        let r =
            AuditReportView::finding(ReportLang::English, &[1; 32], &[2; 32], &[3; 32], &[4; 32]);
        let lines = r.render(16);
        assert!(lines.iter().any(|l| l == "status=finding"));
        assert!(lines.iter().any(|l| l == "lang_u8=2"));
        assert_eq!(r.confidence_bps_u16, 10000);
    }

    #[test]
    fn exploit_instruction_denied() {
        assert_eq!(
            assert_no_exploit_instruction("step 1: rm -rf / then drain"),
            Err(EvalLanguageReject::ExploitInstruction)
        );
        assert!(
            assert_no_exploit_instruction("the bounds check is missing at the boundary").is_ok()
        );
    }

    #[test]
    fn candidate_certainty_denied_finding_allowed() {
        // An unreproduced candidate cannot speak with certainty.
        assert_eq!(
            assert_no_candidate_certainty("this is definitely exploitable", false),
            Err(EvalLanguageReject::CandidateCertainty)
        );
        assert_eq!(
            assert_no_candidate_certainty("이 결함은 확실히 위험하다", false),
            Err(EvalLanguageReject::CandidateCertainty)
        );
        // A reproduced finding may state its verified result.
        assert!(assert_no_candidate_certainty("this is definitely exploitable", true).is_ok());
        // A hedged candidate note is fine.
        assert!(
            assert_no_candidate_certainty(
                "this may affect the invariant; needs local repro",
                false
            )
            .is_ok()
        );
    }

    #[test]
    fn render_bounded_no_commerce_and_p95_within_50ms() {
        let r =
            AuditReportView::finding(ReportLang::English, &[1; 32], &[2; 32], &[3; 32], &[4; 32]);
        assert!(r.render(3).len() <= 3);
        assert!(r.render(64).len() <= 7);
        for line in r.render(64) {
            for bad in COMMERCE_TOKENS {
                assert!(!line.contains(bad), "commerce token {bad} in {line}");
            }
        }
        let mut samples = Vec::with_capacity(256);
        for _ in 0..256 {
            let t = std::time::Instant::now();
            let lines = r.render(32);
            std::hint::black_box(&lines);
            samples.push(t.elapsed().as_nanos() as u64);
        }
        let p95 = crate::repl::latency::p95_ms(&samples) / 1_000_000;
        assert!(
            p95 <= 50,
            "audit report render p95 {p95}ms exceeds 50ms budget"
        );
    }
}
