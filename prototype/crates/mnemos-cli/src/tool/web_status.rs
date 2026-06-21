//! Web-search tool surface status (atom #542 · G.4.11).
//!
//! A status projection over the Stage G web-source policy: web research is opt-in
//! (default off), source-linked, quote-limited, and never proof of code execution;
//! a high-stakes / security claim additionally needs local verification before a
//! web answer may be surfaced as advisory. The status holds no secret / private
//! memory — every field is a bool or a `u32` — so
//! [`WebToolStatus::holds_no_secret`] is the structural invariant `true`, and a
//! private-memory read is never a web input ([`WebToolStatus::private_memory_denied`]
//! is `true`) (`G-G-SECRET-ZERO`, `G-G-EVIDENCE-MANIFEST`). This module performs no
//! live action.
//!
//! Reuse (no reinvention): [`WebSourcePolicy`] / [`WebUseInputs`] / [`WebUseVerdict`]
//! from [`crate::provider::web_policy`]; the source record / source-less deny is the
//! Stage F [`crate::commands::tool`] (`WebResearchRecord` / `web_answer_allowed`).

use crate::provider::web_policy::{WebSourcePolicy, WebUseInputs, WebUseVerdict};

/// A status view of the web-search tool surface.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct WebToolStatus {
    /// Whether web research is enabled (default `false`, opt-in).
    pub web_enabled: bool,
    /// The maximum cited-quote length in characters.
    pub max_quote_chars_u32: u32,
    /// Invariant `false`: a web answer is never proof of code execution.
    pub is_execution_proof: bool,
    /// Invariant `true`: the status holds no secret / private memory.
    pub holds_no_secret: bool,
}

impl WebToolStatus {
    /// Project a status from a [`WebSourcePolicy`].
    #[must_use]
    pub const fn from_policy(policy: &WebSourcePolicy) -> Self {
        Self {
            web_enabled: policy.web_enabled,
            max_quote_chars_u32: policy.max_quote_chars_u32,
            is_execution_proof: WebSourcePolicy::is_code_execution_proof(),
            holds_no_secret: true,
        }
    }

    /// The default status: web research is disabled (opt-in).
    #[must_use]
    pub fn default_disabled() -> Self {
        Self::from_policy(&WebSourcePolicy::default())
    }

    /// Evaluate a web-answer use against this status's policy (reuse the canonical
    /// [`WebSourcePolicy::evaluate`]).
    #[must_use]
    pub fn evaluate(&self, inputs: &WebUseInputs<'_>) -> WebUseVerdict {
        WebSourcePolicy {
            web_enabled: self.web_enabled,
            max_quote_chars_u32: self.max_quote_chars_u32,
        }
        .evaluate(inputs)
    }

    /// Invariant `true`: a private-memory read is never a web-search input (web
    /// answers require a source-linked external record, never private memory).
    #[must_use]
    pub const fn private_memory_denied(&self) -> bool {
        true
    }

    /// Colorless status lines bounded by `rows`.
    #[must_use]
    pub fn render(&self, rows: u16) -> Vec<String> {
        let lines = vec![
            format!("web_enabled={}", self.web_enabled),
            format!("max_quote_chars={}", self.max_quote_chars_u32),
            format!("is_execution_proof={}", self.is_execution_proof),
            format!("private_memory_denied={}", self.private_memory_denied()),
            format!("holds_no_secret={}", self.holds_no_secret),
        ];
        lines.into_iter().take(rows as usize).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::commands::tool::{
        RightsDecision, WebFetchInputs, WebResearchPhase, WebResearchRecord,
    };

    fn grounded_record() -> Option<WebResearchRecord> {
        WebResearchRecord::new(&WebFetchInputs {
            phase: WebResearchPhase::Cite,
            source_url: "https://example.test/doc",
            retrieved_at_unix_u64: 1_700_000_000,
            fetch_body: "body bytes",
            raw_headers: "content-type: text/html",
            rights: RightsDecision::Allowed,
            citation_span: "a cited span",
        })
    }

    fn use_inputs<'a>(
        record: Option<&'a WebResearchRecord>,
        quote_len: u32,
        high_stakes: bool,
        local_verification_done: bool,
    ) -> WebUseInputs<'a> {
        WebUseInputs {
            record,
            quote_len_chars_u32: quote_len,
            high_stakes,
            local_verification_done,
        }
    }

    fn enabled() -> WebToolStatus {
        WebToolStatus::from_policy(&WebSourcePolicy {
            web_enabled: true,
            max_quote_chars_u32: 512,
        })
    }

    #[test]
    fn disabled_default() {
        let s = WebToolStatus::default_disabled();
        assert!(!s.web_enabled);
        let rec = grounded_record();
        assert!(rec.is_some());
        if let Some(rec) = rec {
            assert_eq!(
                s.evaluate(&use_inputs(Some(&rec), 10, false, false)),
                WebUseVerdict::DeniedWebDisabled
            );
        }
    }

    #[test]
    fn source_evidence_required() {
        let s = enabled();
        assert_eq!(
            s.evaluate(&use_inputs(None, 10, false, false)),
            WebUseVerdict::DeniedSourceless
        );
    }

    #[test]
    fn quote_limit() {
        let s = WebToolStatus::from_policy(&WebSourcePolicy {
            web_enabled: true,
            max_quote_chars_u32: 32,
        });
        let rec = grounded_record();
        assert!(rec.is_some());
        if let Some(rec) = rec {
            assert_eq!(
                s.evaluate(&use_inputs(Some(&rec), 1_000, false, false)),
                WebUseVerdict::DeniedQuoteTooLong
            );
        }
    }

    #[test]
    fn security_local_verify() {
        let s = enabled();
        let rec = grounded_record();
        assert!(rec.is_some());
        if let Some(rec) = rec {
            assert_eq!(
                s.evaluate(&use_inputs(Some(&rec), 10, true, false)),
                WebUseVerdict::DeniedHighStakesNeedsLocalVerify
            );
            assert_eq!(
                s.evaluate(&use_inputs(Some(&rec), 10, true, true)),
                WebUseVerdict::AllowedAdvisory
            );
        }
    }

    #[test]
    fn private_memory_deny_and_secret_zero() {
        let s = enabled();
        assert!(s.private_memory_denied());
        assert!(s.holds_no_secret);
        assert!(!s.is_execution_proof);
    }
}
