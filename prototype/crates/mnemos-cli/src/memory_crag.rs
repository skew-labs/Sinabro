//! `memory_crag` — the P-RAG corrective-retrieval layer.
//!
//! Retrieval instability (P-RAG) is the failure where the agent fetches a memory
//! that is WRONG for the current task and uses it silently. CRAG (2401.15884)
//! turns that silent failure into a DETECTED, RECOVERED event: a lightweight
//! evaluator labels each fetch **Correct / Ambiguous / Incorrect**, and an
//! Incorrect fetch re-routes (widens) to other entries in the MAIN INDEX.
//!
//! ## drift-0 (META-LAW): the evaluator is DETERMINISTIC, never a model
//!
//! Generic CRAG uses a small *learned* evaluator (the paper's T5-large). sinabro's
//! META-LAW forbids a non-deterministic runtime JUDGE — the model only ever
//! PROPOSES; an L0 deterministic check decides. So this evaluator is a pure
//! function of `(query, body)` + the on-disk trust flag: 0 LLM tokens, 0 IO, no
//! clock. A non-deterministic model-judge would BOTH violate the law and need
//! serving infra we do not have; a deterministic relevance×trust scorer is the
//! faithful sinabro shape (the same posture as `verification.rs` and the oracle).
//!
//! ## the trust flag is the on-disk truth, not a new field
//!
//! A memory is VERIFIED iff its body is a `#sinabro-pattern` — those are written
//! ONLY through the `autonomy_evolve` write gate, which requires an oracle
//! [`admits_write`](crate::verification::VerificationReceipt::admits_write) verdict
//! AND cross-memory-consistency. Everything else (a raw `memory save`, speculative
//! text) is UNVERIFIED. So the VERIFIED/UNVERIFIED trust flag the plan asks for is
//! ALREADY encoded on disk via [`parse_pattern_memory`](crate::autonomy_evolve::parse_pattern_memory)
//! — no schema change, no fabricated flag. The agent PREFERS verified memory.
//!
//! custody/funds stay HARD-LOCKED: this module is pure, no IO, no network, no key.

use crate::autonomy_evolve::parse_pattern_memory;
use std::collections::BTreeSet;

/// The minimum token length (in CHARS) a token must have to count toward
/// relevance — drops 1-char noise while keeping CJK bigrams + short English
/// content words. Common English function words (2-3 chars) are kept; they appear
/// in most bodies, so they only INFLATE coverage (fail-open: never a false
/// "Incorrect"), never deflate it.
pub const MIN_TOKEN_CHARS: usize = 2;

/// At/above this query-term coverage (basis points, 0..=10000) a fetch is strongly
/// on-topic: a VERIFIED memory here is `Correct`. Half the distinct query terms.
pub const RELEVANCE_HI_BPS: u32 = 5_000;

/// Below this coverage a fetch is OFF-topic for the query ⇒ `Incorrect` (wrong
/// retrieval, the CRAG recovery trigger), regardless of how trustworthy the memory
/// is in general (a trustworthy-but-irrelevant doc is still the wrong doc).
pub const RELEVANCE_LO_BPS: u32 = 2_000;

/// The maximum number of widen re-fetches the corrective loop attempts after an
/// `Incorrect` verdict — bounds the auto-recovery inside the loop's K read budget.
pub const WIDEN_MAX: usize = 2;

/// The VERIFIED/UNVERIFIED trust flag on a memory — the CRAG evaluator's key input.
/// Derived deterministically from the body (NOT a stored field): a `#sinabro-pattern`
/// body cleared the oracle write-gate ⇒ `Verified`; anything else ⇒ `Unverified`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MemoryTrust {
    /// Confirmed by a real oracle run (a `#sinabro-pattern` written through the
    /// `autonomy_evolve` `admits_write` + cross-memory-consistent gate).
    Verified,
    /// Speculative / owner-raw memory: not (yet) oracle-confirmed. The agent uses
    /// it with caution and prefers a `Verified` alternative.
    Unverified,
}

impl MemoryTrust {
    /// Whether this memory is oracle-VERIFIED.
    #[must_use]
    pub const fn is_verified(self) -> bool {
        matches!(self, Self::Verified)
    }

    /// A stable, secret-zero label for rendering / verifiers.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Verified => "VERIFIED",
            Self::Unverified => "UNVERIFIED",
        }
    }
}

/// Derive the trust flag from a memory body. VERIFIED iff the body is a
/// `#sinabro-pattern` (the oracle-gated write); everything else is UNVERIFIED.
#[must_use]
pub fn memory_trust(body: &str) -> MemoryTrust {
    if parse_pattern_memory(body).is_some() {
        MemoryTrust::Verified
    } else {
        MemoryTrust::Unverified
    }
}

/// The CRAG three-way label for a fetched memory (2401.15884).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CragLabel {
    /// On-topic AND verified — use it directly.
    Correct,
    /// On-topic but unverified, OR weakly on-topic — usable with caution (the agent
    /// should prefer a `Correct` alternative if one exists). NOT a recovery trigger.
    Ambiguous,
    /// Off-topic for the query (or empty/withheld) — WRONG retrieval. Triggers the
    /// corrective widen (re-route within the MAIN INDEX).
    Incorrect,
}

impl CragLabel {
    /// A stable, secret-zero label.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Correct => "Correct",
            Self::Ambiguous => "Ambiguous",
            Self::Incorrect => "Incorrect",
        }
    }
}

/// The corrective verdict for one fetched memory: its trust flag, the CRAG label,
/// and the measured query-term coverage (basis points). Pure data — the model never
/// produces this (it is a deterministic function of `(query, body)`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CragVerdict {
    /// The on-disk trust flag of the fetched memory.
    pub trust: MemoryTrust,
    /// The CRAG label.
    pub label: CragLabel,
    /// Query-term coverage of the body, in basis points (0..=10000).
    pub relevance_bps: u32,
}

impl CragVerdict {
    /// Whether the corrective loop should WIDEN (re-route to other MAIN INDEX
    /// entries): only on `Incorrect` (wrong retrieval). An `Ambiguous` memory is
    /// kept-but-flagged; a `Correct` one is used directly.
    #[must_use]
    pub const fn should_widen(&self) -> bool {
        matches!(self.label, CragLabel::Incorrect)
    }

    /// A short, secret-zero render tag, e.g. `VERIFIED · CRAG=Correct rel=83%`.
    #[must_use]
    pub fn render_tag(&self) -> String {
        format!(
            "{} · CRAG={} rel={}%",
            self.trust.label(),
            self.label.label(),
            self.relevance_bps / 100,
        )
    }
}

/// Tokenize text into the deterministic, distinct, lowercase token set used for
/// relevance: split on non-alphanumeric boundaries (Unicode-aware, so CJK is kept),
/// lowercased, keeping tokens of at least [`MIN_TOKEN_CHARS`] chars. A `BTreeSet`
/// makes the result order-independent + deterministic.
#[must_use]
fn tokenize(text: &str) -> BTreeSet<String> {
    text.split(|c: char| !c.is_alphanumeric())
        .filter(|t| t.chars().count() >= MIN_TOKEN_CHARS)
        .map(str::to_lowercase)
        .collect()
}

/// Query-term coverage of `body`, in basis points (0..=10000): the fraction of the
/// query's DISTINCT scoreable tokens that appear in the body's token set. Deterministic.
///
/// Fail-OPEN on un-assessable input: an empty query (or a query with no scoreable
/// tokens) returns `10000` — we never flag "wrong retrieval" when there is no basis
/// to judge against (that would reject memory we cannot even assess). An empty body
/// is `0` (nothing to cover).
#[must_use]
pub fn relevance_bps(query: &str, body: &str) -> u32 {
    let q = tokenize(query);
    if q.is_empty() {
        return 10_000;
    }
    let b = tokenize(body);
    if b.is_empty() {
        return 0;
    }
    let hit = q.iter().filter(|t| b.contains(*t)).count();
    // hit <= q.len() <= u32::MAX-class; the cast + mul fits since coverage <= 10000.
    let total = q.len() as u64;
    let covered = (hit as u64) * 10_000 / total;
    u32::try_from(covered).unwrap_or(10_000)
}

/// Evaluate a fetched memory against the current task `query` (CRAG, deterministic):
///
/// * empty/withheld `body` ⇒ `Incorrect` (a withheld fetch is a wrong retrieval),
/// * coverage `>= RELEVANCE_HI` ⇒ `Correct` if VERIFIED, else `Ambiguous`
///   (on-topic but unverified — prefer a verified alternative),
/// * `RELEVANCE_LO <= coverage < HI` ⇒ `Ambiguous` (weakly on-topic, any trust),
/// * coverage `< RELEVANCE_LO` ⇒ `Incorrect` (off-topic ⇒ widen), even if VERIFIED
///   (a trustworthy memory fetched for the wrong query is still the wrong doc).
#[must_use]
pub fn evaluate(query: &str, body: &str) -> CragVerdict {
    let trust = memory_trust(body);
    if body.trim().is_empty() {
        return CragVerdict {
            trust,
            label: CragLabel::Incorrect,
            relevance_bps: 0,
        };
    }
    let relevance_bps = relevance_bps(query, body);
    let label = if relevance_bps >= RELEVANCE_HI_BPS {
        if trust.is_verified() {
            CragLabel::Correct
        } else {
            CragLabel::Ambiguous
        }
    } else if relevance_bps >= RELEVANCE_LO_BPS {
        CragLabel::Ambiguous
    } else {
        CragLabel::Incorrect
    };
    CragVerdict {
        trust,
        label,
        relevance_bps,
    }
}

/// Rank the MAIN INDEX entries to WIDEN to after an `Incorrect` fetch (the CRAG
/// re-route, our in-hand analog of CRAG's web-fallback). Each `entries` item is
/// `(memory_id, topic)` from the index; relevance is scored against the cheap topic
/// (we do not fetch every candidate's body). Returns the ids of entries that are
/// PLAUSIBLY relevant (coverage `>= RELEVANCE_LO`), excluding `tried`, ordered by
/// relevance descending then id ascending (a deterministic, stable order). Empty ⇒
/// nothing better to widen to (an honest "no candidate", never a guess).
#[must_use]
pub fn rank_widen_candidates(query: &str, entries: &[(u64, String)], tried: &[u64]) -> Vec<u64> {
    let mut scored: Vec<(u32, u64)> = entries
        .iter()
        .filter(|(id, _)| !tried.contains(id))
        .map(|(id, topic)| (relevance_bps(query, topic), *id))
        .filter(|(rel, _)| *rel >= RELEVANCE_LO_BPS)
        .collect();
    // Highest relevance first; ties broken by ascending id (deterministic).
    scored.sort_by(|a, b| b.0.cmp(&a.0).then(a.1.cmp(&b.1)));
    scored.into_iter().map(|(_, id)| id).collect()
}

/// A retrieval SOURCE for a memory's encrypted sub-store, in the order the resilient
/// fetch tries them (Walrus first, then 0G if Walrus is unavailable): Walrus is
/// PRIMARY, 0G is the FALLBACK. Pure / deterministic.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum FetchSource {
    /// The PRIMARY source: the Walrus blob-id of the encrypted sub-store.
    Walrus(String),
    /// The FALLBACK source: the 0G Storage rootHash of the SAME encrypted sub-store
    /// (only present when the owner backed that sub up to 0G).
    ZeroG(String),
}

/// The ordered fetch plan for a memory: Walrus first, then 0G iff a rootHash is
/// recorded. The single source of truth for the Walrus→0G ordering (the live resilient
/// fetch matches on this). Deterministic, pure.
#[must_use]
pub fn fetch_plan(sub_blob_id: &str, sub_0g_root: Option<&str>) -> Vec<FetchSource> {
    let mut plan = vec![FetchSource::Walrus(sub_blob_id.to_string())];
    if let Some(root) = sub_0g_root {
        plan.push(FetchSource::ZeroG(root.to_string()));
    }
    plan
}

/// The outcome of the corrective retrieval loop: the CHOSEN memory after CRAG widen.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CorrectiveOutcome {
    /// The id of the memory finally chosen (the requested one, or a widen target).
    pub chosen_id: u64,
    /// The chosen memory's decrypted body — `None` iff NOTHING fetched (the requested
    /// id and every widen candidate failed to fetch).
    pub body: Option<String>,
    /// The backend the chosen body came from (`"walrus"` / `"0g-fallback"` / `""`).
    pub backend: &'static str,
    /// The CRAG verdict for the chosen body — `None` iff nothing fetched.
    pub verdict: Option<CragVerdict>,
    /// The widen attempts, in order: `(candidate_id, its label)`. Empty if the
    /// requested fetch was already not-Incorrect (no widen needed).
    pub widen_trail: Vec<(u64, CragLabel)>,
}

/// The CORRECTIVE retrieval loop (CRAG, deterministic, PURE over an injected fetcher).
///
/// Fetch the `requested_id`, CRAG-evaluate it; if `Incorrect` (wrong retrieval), WIDEN
/// to the best-ranked OTHER index `entries` (bounded by [`WIDEN_MAX`]) until one is not
/// Incorrect — turning a silent wrong fetch into a detected, recovered event. The
/// `fetch` closure `(id) -> Option<(body, backend)>` is the only effectful part:
/// tests inject canned bodies; the live executor wires the Walrus→0G resilient fetch.
/// If no widen recovers, the original (flagged) memory is kept (honest, never hidden).
pub fn corrective_fetch<F>(
    query: &str,
    requested_id: u64,
    entries: &[(u64, String)],
    mut fetch: F,
) -> CorrectiveOutcome
where
    F: FnMut(u64) -> Option<(String, &'static str)>,
{
    let Some((body0, backend0)) = fetch(requested_id) else {
        return CorrectiveOutcome {
            chosen_id: requested_id,
            body: None,
            backend: "",
            verdict: None,
            widen_trail: Vec::new(),
        };
    };
    let v0 = evaluate(query, &body0);
    let mut widen_trail: Vec<(u64, CragLabel)> = Vec::new();
    if !v0.should_widen() {
        return CorrectiveOutcome {
            chosen_id: requested_id,
            body: Some(body0),
            backend: backend0,
            verdict: Some(v0),
            widen_trail,
        };
    }
    // Incorrect ⇒ re-route within the MAIN INDEX (our in-hand analog of CRAG's fallback).
    let tried = [requested_id];
    for cand in rank_widen_candidates(query, entries, &tried)
        .into_iter()
        .take(WIDEN_MAX)
    {
        if let Some((c, b)) = fetch(cand) {
            let v = evaluate(query, &c);
            widen_trail.push((cand, v.label));
            if !v.should_widen() {
                return CorrectiveOutcome {
                    chosen_id: cand,
                    body: Some(c),
                    backend: b,
                    verdict: Some(v),
                    widen_trail,
                };
            }
        }
    }
    // No widen recovered ⇒ keep the original, flagged Incorrect (surfaced, not hidden).
    CorrectiveOutcome {
        chosen_id: requested_id,
        body: Some(body0),
        backend: backend0,
        verdict: Some(v0),
        widen_trail,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::autonomy_evolve::format_pattern_memory;

    /// A real `#sinabro-pattern` body (what the oracle write-gate persists) with an
    /// explicit topic, so relevance reflects the memory's actual subject — the persisted
    /// body is `#sinabro-pattern …topic=<t>\n<content>`, exactly what `fetch` returns.
    fn verified(topic: &str, content: &str) -> String {
        format_pattern_memory("abc123", topic, content)
    }

    #[test]
    fn trust_is_derived_from_sinabro_pattern_only() {
        // a #sinabro-pattern body = VERIFIED (it cleared the oracle write gate)
        assert_eq!(
            memory_trust(&verified("sui_move: build a coin", "the verified answer")),
            MemoryTrust::Verified
        );
        // a raw owner note / speculative text = UNVERIFIED
        assert_eq!(memory_trust("just an owner note"), MemoryTrust::Unverified);
        assert_eq!(memory_trust(""), MemoryTrust::Unverified);
        // a body that merely MENTIONS the magic mid-text is NOT a pattern header
        assert_eq!(
            memory_trust("note: #sinabro-pattern is the magic"),
            MemoryTrust::Unverified
        );
    }

    #[test]
    fn relevance_is_query_term_coverage() {
        // all 3 distinct query terms present ⇒ 100%
        assert_eq!(
            relevance_bps("sui move coin", "implement a sui move coin module"),
            10_000
        );
        // 1 of 2 distinct scoreable terms ("solana" absent) ⇒ 50%
        assert_eq!(relevance_bps("sui solana", "a sui move note"), 5_000);
        // none present ⇒ 0%
        assert_eq!(relevance_bps("solana anchor", "a sui move note"), 0);
        // un-assessable query (no scoreable tokens) ⇒ fail-open 100%
        assert_eq!(relevance_bps("a x", "anything at all here"), 10_000);
        assert_eq!(relevance_bps("", "anything"), 10_000);
        // empty body ⇒ 0
        assert_eq!(relevance_bps("sui move", ""), 0);
    }

    #[test]
    fn verified_on_topic_is_correct() {
        let v = evaluate(
            "sui move coin",
            &verified("sui_move: build a coin", "a sui move coin guide"),
        );
        assert_eq!(v.trust, MemoryTrust::Verified);
        assert_eq!(v.label, CragLabel::Correct);
        assert!(!v.should_widen());
        assert!(v.relevance_bps >= RELEVANCE_HI_BPS);
    }

    #[test]
    fn unverified_on_topic_is_ambiguous_not_correct() {
        // on-topic but UNVERIFIED ⇒ Ambiguous (prefer a verified alternative)
        let v = evaluate("sui move coin", "raw note: sui move coin stuff here");
        assert_eq!(v.trust, MemoryTrust::Unverified);
        assert_eq!(v.label, CragLabel::Ambiguous);
        assert!(!v.should_widen());
    }

    #[test]
    fn off_topic_is_incorrect_even_when_verified() {
        // a trustworthy memory fetched for the WRONG query is still wrong retrieval
        let v = evaluate(
            "solana anchor program",
            &verified(
                "web3_frontend: react layout",
                "notes about react frontend layout",
            ),
        );
        assert_eq!(v.trust, MemoryTrust::Verified);
        assert_eq!(v.label, CragLabel::Incorrect);
        assert!(v.should_widen(), "off-topic verified memory must widen");
    }

    #[test]
    fn empty_or_withheld_body_is_incorrect() {
        let v = evaluate("anything", "   ");
        assert_eq!(v.label, CragLabel::Incorrect);
        assert!(v.should_widen());
        assert_eq!(v.relevance_bps, 0);
    }

    #[test]
    fn widen_ranks_relevant_candidates_excluding_tried() {
        let entries = vec![
            (1u64, "react frontend layout notes".to_string()),
            (2u64, "sui move coin module guide".to_string()),
            (3u64, "sui move coin testing tips".to_string()),
            (4u64, "solana anchor program".to_string()),
        ];
        // already tried id=2 (the Incorrect fetch); query = "sui move coin"
        let ranked = rank_widen_candidates("sui move coin", &entries, &[2]);
        // id 3 (sui move coin testing) is the strongest remaining; 1 and 4 are
        // off-topic (< LO) and excluded; 2 is tried.
        assert_eq!(
            ranked,
            vec![3],
            "only the relevant, untried candidate widens"
        );
    }

    #[test]
    fn widen_is_deterministic_and_empty_when_nothing_relevant() {
        let entries = vec![
            (5u64, "react frontend layout".to_string()),
            (6u64, "tailwind css tokens".to_string()),
        ];
        // nothing matches a sui-move query ⇒ empty (honest "no candidate")
        assert!(rank_widen_candidates("sui move coin", &entries, &[]).is_empty());
        // tie order is stable (both fully relevant ⇒ ascending id)
        let tie = vec![
            (9u64, "sui move coin".to_string()),
            (8u64, "sui move coin".to_string()),
        ];
        assert_eq!(
            rank_widen_candidates("sui move coin", &tie, &[]),
            vec![8, 9]
        );
    }

    #[test]
    fn render_tag_is_secret_zero_and_stable() {
        let v = evaluate(
            "sui move coin",
            &verified("sui_move: build a coin", "a sui move coin guide"),
        );
        assert_eq!(v.render_tag(), "VERIFIED · CRAG=Correct rel=100%");
    }

    #[test]
    fn fetch_plan_is_walrus_primary_then_0g_fallback() {
        assert_eq!(
            fetch_plan("blobA", Some("0xroot")),
            vec![
                FetchSource::Walrus("blobA".to_string()),
                FetchSource::ZeroG("0xroot".to_string()),
            ]
        );
        // no 0G root ⇒ Walrus only (no fabricated fallback)
        assert_eq!(
            fetch_plan("blobA", None),
            vec![FetchSource::Walrus("blobA".to_string())]
        );
    }

    #[test]
    fn corrective_fetch_uses_requested_when_correct() {
        let entries = vec![
            (1u64, "sui move coin".to_string()),
            (2, "react".to_string()),
        ];
        let out = corrective_fetch("sui move coin", 1, &entries, |id| {
            (id == 1).then(|| {
                (
                    verified("sui_move: build a coin", "a sui move coin guide"),
                    "walrus",
                )
            })
        });
        assert_eq!(out.chosen_id, 1);
        assert_eq!(out.verdict.expect("verdict").label, CragLabel::Correct);
        assert_eq!(out.backend, "walrus");
        assert!(out.widen_trail.is_empty(), "no widen when already Correct");
    }

    #[test]
    fn corrective_fetch_widens_on_incorrect_retrieval() {
        // requested id=1 is OFF-topic (wrong retrieval); id=2 is the right widen target.
        let entries = vec![
            (1u64, "react frontend layout".to_string()),
            (2u64, "sui move coin module guide".to_string()),
        ];
        let out = corrective_fetch("sui move coin", 1, &entries, |id| match id {
            1 => Some((
                verified("web3_frontend: react layout", "react layout unrelated"),
                "walrus",
            )),
            2 => Some((
                verified("sui_move: coin module", "a sui move coin module guide"),
                "0g-fallback",
            )),
            _ => None,
        });
        assert_eq!(out.chosen_id, 2, "widened to the relevant memory");
        assert_eq!(out.verdict.expect("verdict").label, CragLabel::Correct);
        assert_eq!(
            out.backend, "0g-fallback",
            "the chosen body's backend is tracked"
        );
        assert_eq!(out.widen_trail, vec![(2, CragLabel::Correct)]);
    }

    #[test]
    fn corrective_fetch_keeps_original_when_nothing_recovers() {
        // query has no relevant index entry ⇒ widen candidates empty ⇒ keep the
        // original, flagged Incorrect (surfaced, never silently dropped).
        let entries = vec![(1u64, "react".to_string()), (2u64, "tailwind".to_string())];
        let out = corrective_fetch("sui move coin", 1, &entries, |_| {
            Some((
                verified("web3_frontend: react layout", "react layout stuff"),
                "walrus",
            ))
        });
        assert_eq!(out.chosen_id, 1);
        assert_eq!(out.verdict.expect("verdict").label, CragLabel::Incorrect);
        assert!(
            out.widen_trail.is_empty(),
            "no relevant candidate to widen to"
        );
    }

    #[test]
    fn corrective_fetch_none_when_requested_unfetchable() {
        let out = corrective_fetch("q", 1, &[], |_| None);
        assert!(out.body.is_none());
        assert!(out.verdict.is_none());
        assert_eq!(out.backend, "");
    }
}
