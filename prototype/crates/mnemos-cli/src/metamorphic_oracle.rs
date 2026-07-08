//! `metamorphic_oracle` — the summarization METAMORPHIC deterministic oracle (the
//! Oracle Bootstrap's second domain class). The
//! analog of the [`crate::reconcile_oracle`]: where reconciliation re-derives an
//! accounting INVARIANT, this re-checks a METAMORPHIC RELATION between a `source` text and
//! its `summary` — `summary ⊆ source`. A summary that asserts a QUOTE or a NUMBER absent
//! from the source, or that exceeds a chosen compression target, VIOLATES the relation. The
//! model PROPOSES the summary; this deterministic checker judges the relation — **the LLM is
//! never the judge** (no reward-hacking). 0 LLM tokens, 0 IO, no clock/RNG — pure
//! integer/string set arithmetic over `&str`. Same physics as the reconcile oracle: a cheap
//! deterministic check of a powerful untrusted producer.
//!
//! ## ★ THE METAMORPHIC LAW — a SOUND REJECTOR (Chen et al. 2018)
//! A metamorphic relation has NO ground truth (there is no single "correct" summary). It can
//! only be used as a **REJECTOR**: a VIOLATION is a sound, trustworthy bug; SATISFACTION ⇏
//! correctness. So the verdicts are asymmetric in trust:
//! * **`Rejected`** — a relation was FALSIFIED (a fabricated quote / an unsupported number /
//!   over the compression target). This is the SOUND, load-bearing verdict: the summary is
//!   demonstrably wrong about the source. It NEVER admits a write (it BLOCKS one).
//! * **`NotFalsified`** — no relation was falsified. This is the WEAKEST signal —
//!   "not-yet-falsified", NOT proof the summary is good. A summary can satisfy every relation
//!   and still OMIT the key point or mislead by selection. Per the rejector-only
//!   ladder rung, a `NotFalsified` verdict NEVER admits a write.
//! * **`NotApplicable`** — malformed/empty input (an honest absence), never a false verdict.
//!
//! ## ★ HONEST LOCK (never market past it)
//! The relations checked are SOUND (a `Rejected` is a real violation, zero false-rejects on
//! legitimate paraphrase — only QUOTED spans and NUMBERS, which do not paraphrase, plus a
//! chosen length target, are checked; a paraphrase that introduces no new quote/number passes).
//! But `NotFalsified` is PROVISIONAL: it certifies only that these specific relations hold, NOT
//! that the summary is faithful, complete, or good. The omission/selection failure modes are
//! the fenced residue (they need a human/LLM in the loop forever). Use a
//! `Rejected` as a sound trustworthy negative; never read a `NotFalsified` as a positive
//! verification. custody/funds HARD-LOCKED: pure, no IO, no key.

use std::collections::BTreeSet;

/// The compression target ratio: a summary must satisfy `summary_tokens ≤ (num/den) ·
/// source_tokens` (checked as `summary·den ≤ source·num`, integer — NO floats). A violation
/// is sound FOR THE CHOSEN TARGET (a summary longer than the target is not a summary of that
/// compression); the target is a CHOICE, labeled as such, never read as "is a bad summary".
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CompressionTarget {
    /// The ratio numerator (e.g. 1 in 1/2).
    pub num: u64,
    /// The ratio denominator (e.g. 2 in 1/2). A `0` makes the bound vacuously satisfied.
    pub den: u64,
}

impl CompressionTarget {
    /// The default target: a summary is at most HALF its source's token count (1/2). A real
    /// summary compresses; this is the chosen target, tunable by a stricter caller.
    pub const DEFAULT: Self = Self { num: 1, den: 2 };
}

impl Default for CompressionTarget {
    fn default() -> Self {
        Self::DEFAULT
    }
}

/// The specific metamorphic relation that was VIOLATED (each is a SOUND violation of its
/// precisely-stated relation — reported so a render can SHOW the offending item).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum MetamorphicViolation {
    /// A double-quoted span in the summary does NOT appear (verbatim, case/whitespace
    /// -normalized) in the source — a fabricated quote (you cannot "quote" absent text).
    FabricatedQuote {
        /// The offending quoted span (as written in the summary).
        quote: String,
    },
    /// A NUMBER (digit-run, thousands-comma normalized) in the summary does NOT appear in the
    /// source — an unsupported number (numbers do not paraphrase; an introduced number is
    /// ungrounded). The smallest such number (BTreeSet order) is reported, deterministically.
    UnsupportedNumber {
        /// The offending number (normalized digit-run).
        number: String,
    },
    /// The summary exceeds the chosen compression target `num/den` (it is too long to be a
    /// summary of that compression). Sound FOR THE TARGET (a labeled choice, not "bad summary").
    OverCompression {
        /// The summary's token count.
        summary_tokens: u64,
        /// The source's token count.
        source_tokens: u64,
        /// The target ratio numerator.
        num: u64,
        /// The target ratio denominator.
        den: u64,
    },
}

/// The metamorphic verdict (mirrors the [`crate::reconcile_oracle`] verdict shape).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SummaryVerdict {
    /// A metamorphic relation was FALSIFIED — a SOUND reject (a fabricated quote / unsupported
    /// number / over the compression target). The trustworthy verdict; it BLOCKS a write.
    Rejected,
    /// No relation was falsified — PROVISIONAL ("not-yet-falsified"), NOT proof the summary is
    /// good (it may still OMIT the key point — the fenced honest residue). NEVER admits a write.
    NotFalsified,
    /// Malformed / empty input (no source or no summary tokens) — an honest absence, never a
    /// false `NotFalsified`.
    NotApplicable,
}

/// The typed metamorphic receipt: the verdict, the specific violation (iff `Rejected`), the
/// re-derived token counts, and a secret-zero static reason.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SummaryReceipt {
    /// The verdict.
    pub verdict: SummaryVerdict,
    /// The relation that was violated (`Some` iff `Rejected`, else `None`).
    pub violation: Option<MetamorphicViolation>,
    /// The summary's re-derived token count.
    pub summary_tokens: u64,
    /// The source's re-derived token count.
    pub source_tokens: u64,
    /// A secret-zero static reason.
    pub detail: &'static str,
}

impl SummaryReceipt {
    /// Whether a metamorphic relation was VIOLATED (the only SOUND, trustworthy verdict — it
    /// BLOCKS a write; a `NotFalsified`/`NotApplicable` does not admit one either, per R2).
    #[must_use]
    pub const fn is_rejected(&self) -> bool {
        matches!(self.verdict, SummaryVerdict::Rejected)
    }

    const fn not_applicable(detail: &'static str) -> Self {
        Self {
            verdict: SummaryVerdict::NotApplicable,
            violation: None,
            summary_tokens: 0,
            source_tokens: 0,
            detail,
        }
    }
}

/// Token count of a text (whitespace-split words), saturating to `u64::MAX` (never panics).
fn token_count(text: &str) -> u64 {
    u64::try_from(text.split_whitespace().count()).unwrap_or(u64::MAX)
}

/// Normalize a text for VERBATIM containment: collapse all whitespace runs to single spaces
/// and lowercase. A genuine quote (case/whitespace aside) is a substring of the normalized
/// source; a fabricated one is not (so a REJECT is sound — no false-reject on formatting).
fn normalize(text: &str) -> String {
    text.split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
        .to_lowercase()
}

/// Extract the double-quoted spans of a text (the content between balanced `"` pairs). An
/// unterminated final quote is ignored (no span). Pure, deterministic, allocation-bounded by
/// the input.
fn quoted_spans(text: &str) -> Vec<String> {
    let mut spans = Vec::new();
    let mut in_quote = false;
    let mut cur = String::new();
    for ch in text.chars() {
        if ch == '"' {
            if in_quote {
                spans.push(std::mem::take(&mut cur));
            }
            in_quote = !in_quote;
        } else if in_quote {
            cur.push(ch);
        }
    }
    // an unterminated quote (`cur` while `in_quote`) is dropped — no fabricated-quote claim.
    spans
}

/// Extract the NUMBER set of a text: maximal runs of ASCII digits, with a comma that sits
/// STRICTLY between two digits treated as a thousands-separator and removed (`"1,234"` →
/// `"1234"`). This keeps the containment SOUND across thousands-formatting (no false-reject
/// of `"1,234"` vs `"1234"`). A bare comma-joined digit list with no spaces (`"1,2,3"`) is the
/// documented residue (it merges to `"123"`); real summaries write `"1, 2, 3"` with spaces,
/// which breaks the run. Deterministic; sorted set (so the smallest offender is reported).
fn numbers(text: &str) -> BTreeSet<String> {
    let mut set = BTreeSet::new();
    let mut cur = String::new();
    let mut it = text.chars().peekable();
    while let Some(c) = it.next() {
        if c.is_ascii_digit() {
            cur.push(c);
        } else if c == ',' && !cur.is_empty() && it.peek().is_some_and(|n| n.is_ascii_digit()) {
            // inter-digit comma (thousands separator) — skip it, continue the same number.
        } else if !cur.is_empty() {
            set.insert(std::mem::take(&mut cur));
        }
    }
    if !cur.is_empty() {
        set.insert(cur);
    }
    set
}

/// The DETERMINISTIC metamorphic oracle: check `summary ⊆ source` (quote + number containment)
/// and the compression target, FAIL-CLOSED. The model's prose is NEVER an input beyond the two
/// texts; the verdict is a pure function of `(source, summary, target)`. A SOUND REJECTOR: a
/// `Rejected` is a real violation (zero false-rejects on legitimate paraphrase — only quotes,
/// numbers, and a chosen length target are checked); a `NotFalsified` is PROVISIONAL (it may
/// still OMIT key info — see the module HONEST LOCK). The relations are checked in a fixed
/// order — fabricated quote, then unsupported number, then over-compression — and the FIRST
/// violation is reported (deterministic).
#[must_use]
pub fn check_summary(source: &str, summary: &str, target: CompressionTarget) -> SummaryReceipt {
    let source_tokens = token_count(source);
    let summary_tokens = token_count(summary);
    // honest absence: an empty source or summary cannot be checked (never a false NotFalsified).
    if source_tokens == 0 || summary_tokens == 0 {
        return SummaryReceipt::not_applicable("empty source or summary (nothing to check)");
    }

    // (1) FABRICATED QUOTE: a quoted span in the summary absent (verbatim, normalized) from the
    //     source is a sound fabrication (you cannot quote text the source does not contain).
    let norm_source = normalize(source);
    for raw_quote in quoted_spans(summary) {
        let norm_quote = normalize(&raw_quote);
        // an empty / whitespace-only quote is not a fabrication (vacuously contained).
        if norm_quote.is_empty() {
            continue;
        }
        if !norm_source.contains(&norm_quote) {
            return SummaryReceipt {
                verdict: SummaryVerdict::Rejected,
                violation: Some(MetamorphicViolation::FabricatedQuote { quote: raw_quote }),
                summary_tokens,
                source_tokens,
                detail: "fabricated quote: a quoted span in the summary is not in the source (R2 sound reject)",
            };
        }
    }

    // (2) UNSUPPORTED NUMBER: a number (digit-run, thousands-comma normalized) in the summary
    //     absent from the source is sound (numbers do not paraphrase — an introduced number is
    //     ungrounded). The smallest offender (BTreeSet order) is reported, deterministically.
    let source_numbers = numbers(source);
    for num in numbers(summary) {
        if !source_numbers.contains(&num) {
            return SummaryReceipt {
                verdict: SummaryVerdict::Rejected,
                violation: Some(MetamorphicViolation::UnsupportedNumber { number: num }),
                summary_tokens,
                source_tokens,
                detail: "unsupported number: a number in the summary is not in the source (R2 sound reject)",
            };
        }
    }

    // (3) OVER-COMPRESSION: summary_tokens · den ≤ source_tokens · num must hold (integer, no
    //     float). Overflow ⇒ NotApplicable (honest absence). A violation is sound FOR THE TARGET.
    let (Some(lhs), Some(rhs)) = (
        summary_tokens.checked_mul(target.den),
        source_tokens.checked_mul(target.num),
    ) else {
        return SummaryReceipt::not_applicable("token-count overflow in the compression check");
    };
    if lhs > rhs {
        return SummaryReceipt {
            verdict: SummaryVerdict::Rejected,
            violation: Some(MetamorphicViolation::OverCompression {
                summary_tokens,
                source_tokens,
                num: target.num,
                den: target.den,
            }),
            summary_tokens,
            source_tokens,
            detail: "over the compression target: the summary is too long (R2 sound reject for the chosen target)",
        };
    }

    // no relation falsified — PROVISIONAL ("not-yet-falsified"); NEVER read as a positive verify.
    SummaryReceipt {
        verdict: SummaryVerdict::NotFalsified,
        violation: None,
        summary_tokens,
        source_tokens,
        detail: "no metamorphic relation falsified (PROVISIONAL — may still OMIT key info; never a positive verification)",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SRC: &str = "The Q2 earnings report shows total revenue of 500 and a headcount of 30 \
        employees across all divisions. During the quarterly earnings call the CEO said \
        \"we are profitable\" and reaffirmed the full year outlook.";

    #[test]
    fn a_grounded_summary_is_not_falsified() {
        // uses only source numbers (500, 30) and a real quote; short enough.
        let summary = "Revenue was 500 with 30 staff; the CEO said \"we are profitable\".";
        let r = check_summary(SRC, summary, CompressionTarget::DEFAULT);
        assert_eq!(r.verdict, SummaryVerdict::NotFalsified);
        assert!(r.violation.is_none());
        assert!(!r.is_rejected());
    }

    #[test]
    fn a_fabricated_quote_is_a_sound_reject() {
        let summary = "The CEO said \"we will double revenue next year\".";
        let r = check_summary(SRC, summary, CompressionTarget::DEFAULT);
        assert_eq!(r.verdict, SummaryVerdict::Rejected);
        assert!(r.is_rejected());
        assert!(matches!(
            r.violation,
            Some(MetamorphicViolation::FabricatedQuote { .. })
        ));
    }

    #[test]
    fn an_unsupported_number_is_a_sound_reject() {
        // 45 never appears in the source — a fabricated figure.
        let summary = "Revenue was 500 and profit margin was 45.";
        let r = check_summary(SRC, summary, CompressionTarget::DEFAULT);
        assert_eq!(r.verdict, SummaryVerdict::Rejected);
        assert!(matches!(
            &r.violation,
            Some(MetamorphicViolation::UnsupportedNumber { number }) if number == "45"
        ));
    }

    #[test]
    fn the_smallest_unsupported_number_is_reported_deterministically() {
        // both 45 and 9 are unsupported; the BTreeSet order reports the smallest string "45"
        // before "9"? string order: "45" < "9" (lexicographic), so "45" is reported first.
        let summary = "figures 45 and 9 appear here";
        let r = check_summary(SRC, summary, CompressionTarget { num: 10, den: 1 });
        assert!(matches!(
            &r.violation,
            Some(MetamorphicViolation::UnsupportedNumber { number }) if number == "45"
        ));
        // determinism: a second run is byte-identical.
        let r2 = check_summary(SRC, summary, CompressionTarget { num: 10, den: 1 });
        assert_eq!(r, r2);
    }

    #[test]
    fn over_compression_is_a_sound_reject_for_the_target() {
        let source = "one two three four five six seven eight";
        // 6 summary tokens > 1/2 * 8 = 4 ⇒ over the target.
        let summary = "alpha beta gamma delta epsilon zeta";
        let r = check_summary(source, summary, CompressionTarget::DEFAULT);
        assert_eq!(r.verdict, SummaryVerdict::Rejected);
        assert!(matches!(
            r.violation,
            Some(MetamorphicViolation::OverCompression {
                summary_tokens: 6,
                source_tokens: 8,
                num: 1,
                den: 2
            })
        ));
    }

    /// SOUNDNESS: legitimate PARAPHRASE (different words, no new quote/number) does NOT
    /// false-reject — only quotes and numbers are checked, and a paraphrase introduces neither.
    #[test]
    fn paraphrase_with_no_new_quote_or_number_is_not_falsified() {
        let source = "The corporation expanded its workforce considerably during the reporting period of this past fiscal year.";
        let summary = "The firm grew staff a lot."; // pure paraphrase, no quote, no number
        let r = check_summary(source, summary, CompressionTarget::DEFAULT);
        assert_eq!(
            r.verdict,
            SummaryVerdict::NotFalsified,
            "paraphrase must not false-reject (soundness: zero false-rejects)"
        );
    }

    /// SOUNDNESS: thousands-comma formatting does NOT false-reject (`"1,234"` ≡ `"1234"`).
    #[test]
    fn thousands_comma_formatting_does_not_false_reject() {
        let source = "Total assets were 1234567 at year end.";
        let summary = "Assets: 1,234,567."; // same number, comma-formatted
        let r = check_summary(source, summary, CompressionTarget { num: 10, den: 1 });
        assert_eq!(
            r.verdict,
            SummaryVerdict::NotFalsified,
            "1,234,567 ≡ 1234567 (thousands separator) — no false reject"
        );
        // and the reverse direction.
        let r2 = check_summary(
            "Assets: 1,234,567.",
            "total 1234567",
            CompressionTarget { num: 10, den: 1 },
        );
        assert_eq!(r2.verdict, SummaryVerdict::NotFalsified);
    }

    #[test]
    fn empty_source_or_summary_is_not_applicable() {
        assert_eq!(
            check_summary("", "anything", CompressionTarget::DEFAULT).verdict,
            SummaryVerdict::NotApplicable
        );
        assert_eq!(
            check_summary("source text here", "   ", CompressionTarget::DEFAULT).verdict,
            SummaryVerdict::NotApplicable
        );
    }

    /// THE HONEST LOCK, made a test: a summary that satisfies every metamorphic relation but
    /// OMITS the key point still `NotFalsified`s — proving the checker NEVER asserts the summary
    /// is good/faithful/complete; that is the fenced residue, not a checker failure.
    #[test]
    fn not_falsified_does_not_assert_the_summary_is_good() {
        let source =
            "The bridge passed inspection. CRITICAL: a support beam is cracked and unsafe.";
        // omits the critical danger entirely, but introduces no fabricated quote/number and is short.
        let summary = "The bridge passed inspection.";
        let r = check_summary(source, summary, CompressionTarget::DEFAULT);
        assert_eq!(
            r.verdict,
            SummaryVerdict::NotFalsified,
            "a dangerously-omitting summary still passes the metamorphic relations — the honest LOCK"
        );
        assert!(r.violation.is_none());
    }

    /// DETERMINISM: the same inputs produce a BYTE-IDENTICAL receipt (no clock/RNG/float).
    #[test]
    fn check_is_deterministic_byte_identical() {
        let summary = "Revenue was 500 with 30 staff.";
        let a = check_summary(SRC, summary, CompressionTarget::DEFAULT);
        let b = check_summary(SRC, summary, CompressionTarget::DEFAULT);
        assert_eq!(a, b, "same input ⇒ byte-identical output");
    }

    #[test]
    fn number_extraction_normalizes_thousands_and_splits_on_space() {
        assert!(numbers("1,234,567").contains("1234567"));
        let set = numbers("1, 2, 3"); // comma+space breaks the run → three numbers
        assert!(set.contains("1") && set.contains("2") && set.contains("3"));
        assert!(numbers("no digits here").is_empty());
    }

    #[test]
    fn quoted_span_extraction_is_balanced_and_ignores_unterminated() {
        assert_eq!(quoted_spans("a \"one\" b \"two\" c"), vec!["one", "two"]);
        assert_eq!(
            quoted_spans("a \"unterminated here"),
            Vec::<String>::new(),
            "an unterminated quote yields no span"
        );
    }
}
