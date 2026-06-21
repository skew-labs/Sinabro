//! `autonomy_evolve` — the autonomous Read-Execute-WRITE evolution loop (P1-4; the
//! §3d spine; plan `ops/evidence/stage_g/agent_loop/P1_ORCHESTRATOR_PLAN.md`).
//!
//! This module owns the DETERMINISTIC WRITE-DECISION core of the self-evolving loop:
//! given the EXECUTE result (an orchestration outcome, projected to pattern candidates)
//! and the held LTM (the READ result), decide which verified patterns may be permanently
//! WRITTEN. It is the P-HALL break wired to persistence: a pattern is written ONLY when
//!   (1) its Typed-Write-Admission receipt `admits_write()` (an oracle Verified it —
//!       e.g. the `sui move build` CODE oracle), AND
//!   (2) it is CROSS-MEMORY consistent with the held LTM (the 5th trust tier applied
//!       at WRITE time — a contradiction is quarantined, never written).
//! Each written pattern carries a DGM-H PERFORMANCE-TRACKING score that is REINFORCED
//! on each verified-good outcome (retrieve→act→verified-good ⇒ reinforce); a pattern
//! that later fails is demoted. This breaks the RAG↔HALL compound: the clean verified
//! corpus can never pull a self-deceived "success" forward.
//!
//! token-min + drift-0 (META-LAW): this whole decision is DETERMINISTIC RUST, 0 IO,
//! 0 external LLM tokens — the ONLY token surface in the loop is the frontier
//! PLAN/SYNTHESIZE inside the EXECUTE step ([`crate::agent_orchestrator`]). The IO
//! (the actual Walrus WRITE + the perf ledger) is the `put-fixture-net`-gated dispatch
//! layer (S2-3b) that CONSUMES this core. custody/funds stay HARD-LOCKED: pure, no IO.

use crate::agent_orchestrator::OrchestratedOutcome;
use crate::verification::{PerfScore, VerificationClass, VerificationEvidence, verify};

/// A slim projection of one orchestrated sub-task — the only fields the WRITE decision
/// needs. The adapter [`candidates_from_outcome`] builds these from the full
/// `OrchestratedOutcome`, so the decision core is testable with NO heavy construction
/// and the model's loop receipt never leaks past this boundary.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PatternCandidate {
    /// The sub-task's expert kind label.
    pub kind: String,
    /// The implementation goal.
    pub goal: String,
    /// The local brain's answer (the candidate content).
    pub answer: String,
    /// Whether the Typed-Write-Admission receipt ADMITTED a write (oracle Verified).
    pub admits_write: bool,
}

/// One held LTM memory the WRITE-decision checks a new pattern against (the READ
/// result, projected to the cross-memory-relevant fields).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HeldMemory {
    /// The bounded topic summary of the held memory.
    pub topic: String,
    /// The held memory's content.
    pub content: String,
}

/// A verified pattern selected for a permanent WRITE: a stable key (so re-running the
/// same task reinforces the SAME pattern), a topic summary, the verified content, and
/// the DGM-H perf score (already reinforced for this verified-good outcome).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EvolutionWrite {
    /// Stable key = `hex(sha256(kind \0 goal))[..16]` — the pattern identity.
    pub pattern_key: String,
    /// A bounded topic summary (kind + goal).
    pub topic: String,
    /// The verified implementation content (the local brain's answer the oracle passed).
    pub content: String,
    /// The DGM-H performance-tracking score (reinforced on this verified-good write).
    pub perf: PerfScore,
}

/// The outcome of one evolution WRITE decision over an orchestration result.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct EvolutionOutcome {
    /// Patterns that admit a Write AND are cross-memory consistent (will persist).
    pub written: Vec<EvolutionWrite>,
    /// Pattern keys that admitted a Write but were QUARANTINED by a cross-memory
    /// contradiction (a conflicting claim on the same topic in the held LTM).
    pub quarantined: Vec<String>,
    /// Pattern keys whose oracle did NOT verify them (no Write — the P-HALL gate).
    pub unverified: Vec<String>,
}

impl EvolutionOutcome {
    /// The number of patterns that will be permanently written.
    #[must_use]
    pub fn written_count(&self) -> usize {
        self.written.len()
    }
}

/// Project the full orchestration outcome to the slim candidates the WRITE decision
/// consumes (the only adapter that touches `OrchestratedOutcome`).
#[must_use]
pub fn candidates_from_outcome(outcome: &OrchestratedOutcome) -> Vec<PatternCandidate> {
    outcome
        .subtasks
        .iter()
        .map(|r| PatternCandidate {
            kind: r.subtask.kind.label().to_string(),
            goal: r.subtask.goal.clone(),
            answer: r.outcome.answer.clone().unwrap_or_default(),
            admits_write: r.receipt.admits_write(),
        })
        .collect()
}

/// The stable pattern identity for a `(kind, goal)` — `hex(sha256(kind \0 goal))[..16]`.
/// Deterministic: the same task always maps to the same key (so perf-tracking
/// reinforces ONE pattern across runs).
#[must_use]
pub fn pattern_key(kind: &str, goal: &str) -> String {
    let mut buf = Vec::with_capacity(kind.len() + 1 + goal.len());
    buf.extend_from_slice(kind.as_bytes());
    buf.push(0);
    buf.extend_from_slice(goal.as_bytes());
    let hex = crate::hex32(&crate::sha256_32(&buf));
    hex[..16].to_string()
}

/// A bounded topic summary for a pattern (`<kind>: <goal>`, single-line, capped).
#[must_use]
pub fn pattern_topic(kind: &str, goal: &str) -> String {
    crate::memory_walrus::summarize_topic(format!("{kind}: {goal}").as_bytes())
}

/// Deterministic write-time CROSS-MEMORY contradiction check: a new pattern
/// CONTRADICTS the held LTM iff the held LTM contains a memory with a BYTE-IDENTICAL
/// topic but DIFFERENT content (a conflicting claim on the SAME subject). Identical
/// content is idempotent (consistent); a different topic is independent (consistent).
/// (v1 conservative proxy — richer semantic contradiction is a future tier.)
#[must_use]
pub fn cross_memory_contradicts(topic: &str, content: &str, held: &[HeldMemory]) -> bool {
    held.iter()
        .any(|h| h.topic == topic && h.content != content)
}

/// The DETERMINISTIC WRITE decision (the P-HALL break wired to persistence): for each
/// pattern candidate, write it ONLY if it `admits_write` (the oracle Verified it) AND it
/// is cross-memory consistent with `held`. `prior_perf` looks up the pattern's existing
/// DGM-H score by key (a fresh pattern has the default); a written pattern's score is
/// REINFORCED (it was just verified-good). The MODEL's text is never trusted — the
/// admit bit came from the oracle, and the cross-memory check is deterministic.
#[must_use]
pub fn select_evolution_writes(
    candidates: &[PatternCandidate],
    held: &[HeldMemory],
    prior_perf: &dyn Fn(&str) -> PerfScore,
) -> EvolutionOutcome {
    let mut result = EvolutionOutcome::default();
    for c in candidates {
        let key = pattern_key(&c.kind, &c.goal);
        // (1) the Typed-Write-Admission gate — the oracle must have Verified it.
        if !c.admits_write {
            result.unverified.push(key);
            continue;
        }
        let topic = pattern_topic(&c.kind, &c.goal);
        // (2) the cross-memory tier applied at WRITE time (via the same verify ladder).
        let contradicts = cross_memory_contradicts(&topic, &c.answer, held);
        let cm = verify(
            VerificationClass::CrossMemory,
            &VerificationEvidence::CrossMemory {
                contradicts_held_ltm: contradicts,
            },
        );
        if !cm.admits_write() {
            result.quarantined.push(key);
            continue;
        }
        // DGM-H: this verified-good pattern reinforces its perf score.
        let perf = prior_perf(&key).reinforce();
        result.written.push(EvolutionWrite {
            pattern_key: key,
            topic,
            content: c.answer.clone(),
            perf,
        });
    }
    result
}

// ===========================================================================
// Pattern-memory format + perf ledger (PURE codec; the S2-3b IO layer persists these)
// ===========================================================================

/// The header that marks a persisted memory as an evolution PATTERN (so the READ step
/// can reconstruct `(key, topic, content)` for the cross-memory check). A `\n` ends the
/// header; the body is the verified content verbatim.
pub const PATTERN_MEMORY_MAGIC: &str = "#sinabro-pattern";

/// The perf ledger filename under the data dir (`key\treinforced\tdemoted` lines).
pub const EVOLUTION_LEDGER_FILE: &str = "evolution_ledger.txt";

/// Render an evolution pattern as a persisted memory body: `#sinabro-pattern key=<k>
/// topic=<t>\n<content>`. The topic is single-line by construction ([`pattern_topic`]).
#[must_use]
pub fn format_pattern_memory(key: &str, topic: &str, content: &str) -> String {
    // topic is already single-line (summarize_topic collapses control chars); guard anyway.
    let topic_one_line = topic.replace(['\n', '\r'], " ");
    format!("{PATTERN_MEMORY_MAGIC} key={key} topic={topic_one_line}\n{content}")
}

/// Parse a persisted memory body back to `(key, topic, content)` if it is an evolution
/// pattern; `None` otherwise (a non-pattern owner memory). Fail-closed on a malformed
/// header.
#[must_use]
pub fn parse_pattern_memory(body: &str) -> Option<(String, String, String)> {
    let (header, content) = body.split_once('\n')?;
    let rest = header.strip_prefix(PATTERN_MEMORY_MAGIC)?.trim_start();
    let rest = rest.strip_prefix("key=")?;
    let (key, rest) = rest.split_once(' ')?;
    let topic = rest.strip_prefix("topic=")?;
    if key.is_empty() {
        return None;
    }
    Some((key.to_string(), topic.to_string(), content.to_string()))
}

/// A deterministic `MemoryId` value for a pattern key (first 8 hex chars → u64), so the
/// SAME pattern persists under a stable id (a revision overwrites, never duplicates the
/// id). Collisions across keys are astronomically unlikely (64-bit from sha256).
#[must_use]
pub fn pattern_memory_id(key: &str) -> u64 {
    let hex = key.get(..16).unwrap_or(key);
    u64::from_str_radix(hex, 16).unwrap_or(0)
}

/// Serialize the perf ledger (`key\treinforced\tdemoted` lines, key-sorted). Pure +
/// deterministic.
#[must_use]
pub fn serialize_ledger(ledger: &std::collections::BTreeMap<String, PerfScore>) -> String {
    use std::fmt::Write as _;
    let mut s = String::new();
    for (key, perf) in ledger {
        let _ = writeln!(s, "{key}\t{}\t{}", perf.reinforced, perf.demoted);
    }
    s
}

/// Parse the perf ledger (fail-soft per line: a malformed line is skipped, never a
/// crash — the ledger is a cache, never the source of admission truth).
#[must_use]
pub fn parse_ledger(text: &str) -> std::collections::BTreeMap<String, PerfScore> {
    let mut map = std::collections::BTreeMap::new();
    for line in text.lines() {
        let mut it = line.split('\t');
        let (Some(key), Some(r), Some(d)) = (it.next(), it.next(), it.next()) else {
            continue;
        };
        if let (Ok(reinforced), Ok(demoted)) = (r.parse::<u32>(), d.parse::<u32>()) {
            if !key.is_empty() {
                map.insert(
                    key.to_string(),
                    PerfScore {
                        reinforced,
                        demoted,
                    },
                );
            }
        }
    }
    map
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use super::*;

    fn cand(kind: &str, goal: &str, answer: &str, admits: bool) -> PatternCandidate {
        PatternCandidate {
            kind: kind.to_string(),
            goal: goal.to_string(),
            answer: answer.to_string(),
            admits_write: admits,
        }
    }

    fn no_prior(_k: &str) -> PerfScore {
        PerfScore::default()
    }

    #[test]
    fn pattern_key_is_stable_and_distinct() {
        let a = pattern_key("sui_move", "build a counter");
        let b = pattern_key("sui_move", "build a counter");
        let c = pattern_key("sui_move", "build a vault");
        assert_eq!(a, b, "same (kind,goal) ⇒ same key");
        assert_ne!(a, c, "different goal ⇒ different key");
        assert_eq!(a.len(), 16);
    }

    /// THE P-HALL WRITE GATE: only an admits_write (oracle-Verified) candidate is
    /// written; an Unverified one is rejected (never written), no matter the answer.
    #[test]
    fn only_verified_patterns_are_written() {
        let candidates = vec![
            cand("sui_move", "build a counter", "module a::c {}", true),
            cand(
                "sui_move",
                "build a vault",
                "module a::v { i claim success }",
                false,
            ),
        ];
        let ev = select_evolution_writes(&candidates, &[], &no_prior);
        assert_eq!(
            ev.written_count(),
            1,
            "only the Verified pattern is written"
        );
        assert_eq!(ev.unverified.len(), 1, "the Unverified pattern is rejected");
        assert_eq!(ev.written[0].content, "module a::c {}");
        // DGM-H: a fresh verified-good pattern is reinforced once.
        assert_eq!(ev.written[0].perf.reinforced, 1);
        assert!(ev.written[0].perf.is_confirmed());
    }

    /// Cross-memory quarantine: a verified pattern that CONTRADICTS the held LTM
    /// (same topic, different content) is quarantined, never written (the 5th tier).
    #[test]
    fn cross_memory_contradiction_is_quarantined() {
        let topic = pattern_topic("sui_move", "build a counter");
        let held = vec![HeldMemory {
            topic,
            content: "module a::c { OLD conflicting }".to_string(),
        }];
        let candidates = vec![cand(
            "sui_move",
            "build a counter",
            "module a::c { NEW different }",
            true,
        )];
        let ev = select_evolution_writes(&candidates, &held, &no_prior);
        assert_eq!(ev.written_count(), 0, "the contradiction is not written");
        assert_eq!(ev.quarantined.len(), 1, "it is quarantined");
    }

    /// Idempotent re-write: a verified pattern byte-identical to a held memory on the
    /// same topic is CONSISTENT (not a contradiction) and is written (reinforced).
    #[test]
    fn identical_content_is_consistent_not_contradiction() {
        let topic = pattern_topic("sui_move", "build a counter");
        let content = "module a::c {}";
        let held = vec![HeldMemory {
            topic,
            content: content.to_string(),
        }];
        let candidates = vec![cand("sui_move", "build a counter", content, true)];
        let ev = select_evolution_writes(&candidates, &held, &no_prior);
        assert_eq!(
            ev.written_count(),
            1,
            "identical content is idempotent-consistent"
        );
        assert!(ev.quarantined.is_empty());
    }

    /// DGM-H reinforcement accumulates across runs: a pattern with a prior score is
    /// reinforced again on a fresh verified-good write.
    #[test]
    fn perf_reinforces_across_runs() {
        let key = pattern_key("sui_move", "build a counter");
        let candidates = vec![cand("sui_move", "build a counter", "module a::c {}", true)];
        let prior = move |k: &str| {
            if k == key {
                PerfScore {
                    reinforced: 3,
                    demoted: 0,
                }
            } else {
                PerfScore::default()
            }
        };
        let ev = select_evolution_writes(&candidates, &[], &prior);
        assert_eq!(ev.written[0].perf.reinforced, 4, "prior 3 + this 1 = 4");
    }

    #[test]
    fn cross_memory_contradicts_is_precise() {
        let held = vec![HeldMemory {
            topic: "t".to_string(),
            content: "x".to_string(),
        }];
        assert!(
            cross_memory_contradicts("t", "y", &held),
            "same topic, diff content"
        );
        assert!(
            !cross_memory_contradicts("t", "x", &held),
            "identical = consistent"
        );
        assert!(
            !cross_memory_contradicts("u", "y", &held),
            "diff topic = independent"
        );
        assert!(
            !cross_memory_contradicts("t", "y", &[]),
            "empty LTM = no conflict"
        );
    }

    #[test]
    fn pattern_memory_round_trips() {
        let body = format_pattern_memory("abc123", "sui_move: build a counter", "module a::c {}");
        let (k, t, c) = parse_pattern_memory(&body).expect("parses");
        assert_eq!(k, "abc123");
        assert_eq!(t, "sui_move: build a counter");
        assert_eq!(c, "module a::c {}");
        // a non-pattern owner memory is not parsed as a pattern.
        assert_eq!(parse_pattern_memory("just an owner note"), None);
        assert_eq!(parse_pattern_memory("#sinabro-pattern malformed"), None);
    }

    #[test]
    fn pattern_memory_id_is_deterministic() {
        let key = pattern_key("sui_move", "build a counter");
        let a = pattern_memory_id(&key);
        let b = pattern_memory_id(&key);
        assert_eq!(
            a, b,
            "same key ⇒ same id (revision overwrites, no duplicate)"
        );
        assert_ne!(
            pattern_memory_id(&pattern_key("sui_move", "build a vault")),
            a,
            "different pattern ⇒ different id"
        );
    }

    #[test]
    fn ledger_round_trips_and_skips_garbage() {
        let mut m = std::collections::BTreeMap::new();
        m.insert(
            "k1".to_string(),
            PerfScore {
                reinforced: 3,
                demoted: 1,
            },
        );
        m.insert(
            "k2".to_string(),
            PerfScore {
                reinforced: 1,
                demoted: 0,
            },
        );
        let text = serialize_ledger(&m);
        let back = parse_ledger(&text);
        assert_eq!(back, m, "ledger round-trips");
        // a malformed line is skipped, never a crash (the ledger is a cache).
        let with_garbage = format!("{text}garbage-no-tabs\nk3\tnotanum\t0\n");
        let parsed = parse_ledger(&with_garbage);
        assert_eq!(parsed.len(), 2, "garbage + non-numeric lines skipped");
    }
}
