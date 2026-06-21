//! Operational web-research source policy (atom #502 · G.1.11).
//!
//! Stage F minted [`WebResearchRecord`] (source-url / fetch / citation hashes +
//! rights decision + browser-credential redaction proof) and
//! [`web_answer_allowed`] (a source-less or rights-denied answer is denied).
//! Stage G adds the *operational policy*: web research is **opt-in** (default
//! off), source-linked, quote-limited, redacted, and **never proof of code
//! execution**; a high-stakes / security claim additionally requires local
//! verification before the web answer may be surfaced as advisory.
//!
//! Reuse (no reinvention): [`WebResearchRecord`] / [`web_answer_allowed`] from
//! [`crate::commands::tool`].

use crate::commands::tool::{WebResearchRecord, web_answer_allowed};

/// The operational web-source policy (opt-in, quote-limited).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct WebSourcePolicy {
    /// Whether web research is enabled. Default `false` (opt-in).
    pub web_enabled: bool,
    /// The maximum cited-quote length in characters.
    pub max_quote_chars_u32: u32,
}

impl Default for WebSourcePolicy {
    fn default() -> Self {
        Self {
            web_enabled: false,
            max_quote_chars_u32: 512,
        }
    }
}

/// The verdict of evaluating a web-answer use against the policy.
#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WebUseVerdict {
    /// Denied: web research is not enabled (opt-in default off).
    DeniedWebDisabled = 1,
    /// Denied: the answer is source-less or its source is rights-denied.
    DeniedSourceless = 2,
    /// Denied: the cited quote exceeds the quote limit.
    DeniedQuoteTooLong = 3,
    /// Denied: a high-stakes claim without local verification.
    DeniedHighStakesNeedsLocalVerify = 4,
    /// Allowed as advisory only (never proof of code execution).
    AllowedAdvisory = 5,
}

impl WebUseVerdict {
    /// Whether the web answer may be surfaced (advisory only).
    #[must_use]
    pub const fn is_allowed(self) -> bool {
        matches!(self, Self::AllowedAdvisory)
    }
}

/// The inputs to a web-answer use decision.
#[derive(Clone, Copy, Debug)]
pub struct WebUseInputs<'a> {
    /// The web research record backing the answer (`None` = no source).
    pub record: Option<&'a WebResearchRecord>,
    /// The cited quote length in characters.
    pub quote_len_chars_u32: u32,
    /// Whether the claim is high-stakes / security-relevant.
    pub high_stakes: bool,
    /// Whether the claim was locally verified.
    pub local_verification_done: bool,
}

impl WebSourcePolicy {
    /// Evaluate whether a web answer may be surfaced. Order: web enabled, then a
    /// present source with citation (rights allowed), then quote within the
    /// limit, then high-stakes claims locally verified.
    #[must_use]
    pub fn evaluate(&self, inputs: &WebUseInputs<'_>) -> WebUseVerdict {
        if !self.web_enabled {
            return WebUseVerdict::DeniedWebDisabled;
        }
        if !web_answer_allowed(inputs.record) {
            return WebUseVerdict::DeniedSourceless;
        }
        if inputs.quote_len_chars_u32 > self.max_quote_chars_u32 {
            return WebUseVerdict::DeniedQuoteTooLong;
        }
        if inputs.high_stakes && !inputs.local_verification_done {
            return WebUseVerdict::DeniedHighStakesNeedsLocalVerify;
        }
        WebUseVerdict::AllowedAdvisory
    }

    /// Invariant `false`: a web answer is never proof of code execution.
    #[must_use]
    pub const fn is_code_execution_proof() -> bool {
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::commands::tool::{RightsDecision, WebFetchInputs, WebResearchPhase};

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

    #[test]
    fn no_web_default() {
        let policy = WebSourcePolicy::default();
        assert!(!policy.web_enabled, "web research is opt-in (default off)");
        let rec = grounded_record();
        assert!(rec.is_some());
        if let Some(rec) = rec {
            assert_eq!(
                policy.evaluate(&use_inputs(Some(&rec), 10, false, false)),
                WebUseVerdict::DeniedWebDisabled
            );
        }
    }

    #[test]
    fn source_required() {
        let policy = WebSourcePolicy {
            web_enabled: true,
            max_quote_chars_u32: 512,
        };
        assert_eq!(
            policy.evaluate(&use_inputs(None, 10, false, false)),
            WebUseVerdict::DeniedSourceless
        );
    }

    #[test]
    fn quote_limit() {
        let policy = WebSourcePolicy {
            web_enabled: true,
            max_quote_chars_u32: 32,
        };
        let rec = grounded_record();
        assert!(rec.is_some());
        if let Some(rec) = rec {
            assert_eq!(
                policy.evaluate(&use_inputs(Some(&rec), 1_000, false, false)),
                WebUseVerdict::DeniedQuoteTooLong
            );
        }
    }

    #[test]
    fn redaction_and_never_execution_proof() {
        // a built record redacts browser credentials by construction
        let rec = grounded_record();
        assert!(rec.is_some());
        if let Some(rec) = rec {
            assert!(rec.credential.redacted, "browser credentials are redacted");
        }
        // a web answer is never proof of code execution
        assert!(!WebSourcePolicy::is_code_execution_proof());
    }

    #[test]
    fn local_verify_required_for_high_stakes() {
        let policy = WebSourcePolicy {
            web_enabled: true,
            max_quote_chars_u32: 512,
        };
        let rec = grounded_record();
        assert!(rec.is_some());
        if let Some(rec) = rec {
            assert_eq!(
                policy.evaluate(&use_inputs(Some(&rec), 10, true, false)),
                WebUseVerdict::DeniedHighStakesNeedsLocalVerify
            );
            let ok = policy.evaluate(&use_inputs(Some(&rec), 10, true, true));
            assert_eq!(ok, WebUseVerdict::AllowedAdvisory);
            assert!(ok.is_allowed());
        }
    }
}
