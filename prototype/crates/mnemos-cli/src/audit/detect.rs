//! Live source-detect pipeline (ENDGAME E11-2 · `AUDIT_ENGINE_THREAT_MODEL.md` ⑮).
//!
//! `audit detect <path>` drives the dormant `audit/*` game tree on a REAL local
//! source tree and surfaces RANKED CANDIDATES — never findings. This is the ONE
//! shared pipeline behind BOTH the `audit detect` dispatch verb and the loop
//! `TOOL: audit detect <path>` (no second truth source):
//!
//! ```text
//! scan_tree(path) -> AuditCandidate[]            (E5 real walk; hashed anchors)
//!   -> DetectorSurface::flag_source_candidate    (PatternMatch node; candidate-only)
//!   -> per-rule histogram (static labels)        (rule_id_hash -> compile-time label)
//!   -> impact_prior per rule class -> rank_top_k  (by plausible impact, not scary diff)
//!   -> SourceDetectReport (counts + labels + ranks; NO raw source byte)
//! ```
//!
//! A detector flag is ALWAYS a candidate ([`DetectorSurface::direct_finding_count`]
//! is structurally `0`). A candidate becomes a finding ONLY through
//! [`crate::audit::candidate::AuditGameTreeCandidate::promote`] with a reproduced,
//! local-only repro receipt (the owner-gated, kernel-sandboxed repro chokepoint) —
//! this module performs NO promotion, NO repro-run, NO exec, and NO live action
//! (IV-AE1/AE6). The render carries counts + STATIC rule labels + impact scores
//! only; the source anchors stay hashed, so no raw source byte can leak (IV-AE4).
//!
//! Reuse (no reinvention): [`crate::commands::source_scan::scan_tree`] /
//! [`crate::commands::source_scan::rust_rule_hashes`] (E5) · [`DetectorSurface`] ·
//! [`crate::audit::impact_prior`] {`ImpactPrior`, `rank_top_k`}.

use std::path::Path;

use crate::audit::candidate::AuditGameTreeCandidate;
use crate::audit::detectors::DetectorSurface;
use crate::audit::impact_prior::{ImpactPrior, rank_top_k};
use crate::commands::eval_core::AuditProfile;
use crate::commands::source_scan::{rust_rule_hashes, scan_tree};

/// Max ranked rule classes surfaced (bounded render).
const TOP_K: usize = 5;

/// A ranked rule class: the static rule label, how many candidates hit it, and the
/// composite plausible-impact score (NOT a finding severity).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RankedRuleClass {
    /// The static rule label (e.g. `rust.unsafe`) — a compile-time constant.
    pub rule: &'static str,
    /// How many source candidates hit this rule.
    pub count: u32,
    /// The composite plausible-impact score (ranking only; never a severity).
    pub impact_score: u32,
}

/// The structured result of `audit detect <path>`: candidate counts, a per-rule
/// histogram, the impact-ranked rule classes, and the bounded-walk telemetry.
/// Carries NO raw source byte — only counts, STATIC rule labels, and impact scores.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct SourceDetectReport {
    /// Total source-anchored candidates flagged.
    pub total_candidates: u32,
    /// Number of source files actually read.
    pub files_scanned: u32,
    /// Whether the file cap clipped the walk.
    pub files_capped: bool,
    /// Whether the candidate cap clipped the walk.
    pub candidates_capped: bool,
    /// Candidates that are already a direct finding — structurally `0` (a detector
    /// flag is never a finding).
    pub direct_findings: u32,
    /// Per-rule histogram (static label, count) for rules with ≥1 candidate.
    pub rule_counts: Vec<(&'static str, u32)>,
    /// The impact-ranked rule classes (top-K by plausible impact).
    pub ranked: Vec<RankedRuleClass>,
}

/// Build an [`ImpactPrior`] from explicit axes (bps).
const fn prior(funds: u16, auth: u16, acct: u16, live: u16, exploit: u16, fp: u16) -> ImpactPrior {
    ImpactPrior {
        funds_at_risk_bps: funds,
        auth_bypass_bps: auth,
        accounting_drift_bps: acct,
        liveness_dos_bps: live,
        exploitability_bps: exploit,
        false_positive_risk_bps: fp,
    }
}

/// The plausible impact prior for a rule class (a RANKING prior, NOT a finding
/// severity). `unsafe` is the memory-safety / exploitability lead; a `panic` / `todo`
/// / `unimplemented` is a liveness/abort lead; `unwrap` / `expect` are common (high
/// false-positive); `dbg` is noise (penalized so it never outranks a real-impact
/// lead). Ranking by plausible impact, not by how scary the pattern looks
/// (`G-G-AUDIT-GAME-TREE`).
fn impact_for_rule(rule: &str) -> ImpactPrior {
    match rule {
        "rust.unsafe" => prior(0, 0, 0, 0, 6000, 2000),
        "rust.panic" => prior(0, 0, 0, 6000, 2000, 1000),
        "rust.todo" | "rust.unimplemented" => prior(0, 0, 0, 6000, 0, 1000),
        "rust.unwrap" | "rust.expect" => prior(0, 0, 0, 3000, 0, 4000),
        // dbg / any unknown rule = noise: a tiny liveness axis (so it is still
        // representable) heavily penalized by false-positive risk.
        _ => prior(0, 0, 0, 500, 0, 9000),
    }
}

/// Drive the audit game tree on a REAL local source tree and produce the ranked
/// candidate report. Pure: a bounded read-only filesystem walk + in-memory
/// projection; NO promotion, NO repro-run, NO exec, NO network/chain/socket. The
/// candidates are candidate-only (`PatternMatch` origin); a finding never opens here.
#[must_use]
pub fn run_source_detect(root: &Path, profile: AuditProfile) -> SourceDetectReport {
    let scan = scan_tree(root, profile);

    // Each REAL source candidate becomes a candidate-only PatternMatch game-tree
    // node (never a finding): direct_finding_count is structurally 0 (IV-AE1).
    let game_tree: Vec<AuditGameTreeCandidate> = scan
        .candidates
        .iter()
        .map(|c| DetectorSurface::flag_source_candidate(*c))
        .collect();
    let direct_findings = DetectorSurface::direct_finding_count(&game_tree);

    // Per-rule histogram from the STATIC rule-hash table — the labels are
    // compile-time constants, never source bytes (secret-zero, IV-AE4).
    let rule_table = rust_rule_hashes();
    let mut rule_counts: Vec<(&'static str, u32)> = Vec::new();
    for (label, hash) in &rule_table {
        let count = u32::try_from(
            scan.candidates
                .iter()
                .filter(|c| &c.rule_id_hash_32 == hash)
                .count(),
        )
        .unwrap_or(u32::MAX);
        if count > 0 {
            rule_counts.push((*label, count));
        }
    }

    // Rank the rule classes by plausible impact (deterministic; zero-impact dropped;
    // a noisy "scary" class never outranks a real-impact class).
    let priors: Vec<ImpactPrior> = rule_counts
        .iter()
        .map(|(label, _)| impact_for_rule(label))
        .collect();
    let order = rank_top_k(&priors, TOP_K);
    let ranked: Vec<RankedRuleClass> = order
        .iter()
        .map(|&i| {
            let (rule, count) = rule_counts[i];
            RankedRuleClass {
                rule,
                count,
                impact_score: priors[i].score(),
            }
        })
        .collect();

    SourceDetectReport {
        total_candidates: scan.candidate_count_u32(),
        files_scanned: scan.files_scanned,
        files_capped: scan.files_capped,
        candidates_capped: scan.candidates_capped,
        direct_findings,
        rule_counts,
        ranked,
    }
}

/// Render a [`SourceDetectReport`] to honest lines: every item is a CANDIDATE, never
/// a finding, never a severity (IV-AE7). The shared render for BOTH the dispatch verb
/// and the loop tool.
#[must_use]
pub fn report_lines(report: &SourceDetectReport) -> Vec<String> {
    let mut lines = vec![
        format!(
            "audit detect: candidates={} files_scanned={} (REAL source walk; hashed anchors, no raw source byte)",
            report.total_candidates, report.files_scanned
        ),
        format!(
            "direct findings: direct_finding_count={} (a detector flag is NEVER a finding)",
            report.direct_findings
        ),
    ];
    if report.rule_counts.is_empty() {
        lines.push("no pattern candidates in this tree".to_string());
    } else {
        let hist: Vec<String> = report
            .rule_counts
            .iter()
            .map(|(r, c)| format!("{r}x{c}"))
            .collect();
        lines.push(format!("candidate histogram: {}", hist.join(" ")));
        for (rank, rc) in report.ranked.iter().enumerate() {
            lines.push(format!(
                "impact rank #{}: {} x{} impact_score={} (plausible impact prior, NOT a severity)",
                rank + 1,
                rc.rule,
                rc.count,
                rc.impact_score
            ));
        }
    }
    if report.files_capped || report.candidates_capped {
        lines.push(format!(
            "scan bounded: files_capped={} candidates_capped={}",
            report.files_capped, report.candidates_capped
        ));
    }
    lines.push(
        "candidate != finding: promotion needs a reproduced LOCAL repro receipt \
         (owner-gated, kernel-sandboxed, network-DENIED); this verb runs NO repro"
            .to_string(),
    );
    lines
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]
    use super::*;
    use std::io::Write;

    fn unique_dir(tag: &str) -> std::path::PathBuf {
        use std::sync::atomic::{AtomicU32, Ordering};
        static COUNTER: AtomicU32 = AtomicU32::new(0);
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        let dir =
            std::env::temp_dir().join(format!("sinabro_detect_{}_{tag}_{n}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("temp dir");
        dir
    }

    fn write_file(dir: &Path, name: &str, body: &str) {
        let path = dir.join(name);
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).expect("mkdir");
        }
        let mut f = std::fs::File::create(&path).expect("create");
        f.write_all(body.as_bytes()).expect("write");
    }

    #[test]
    fn detects_real_candidates_ranked_never_findings() {
        let dir = unique_dir("rank");
        write_file(
            &dir,
            "src/a.rs",
            "fn f() {\n    let x = m().unwrap();\n    panic!(\"boom\");\n    unsafe { r() }\n}\n",
        );
        let report = run_source_detect(&dir, AuditProfile::Rust);
        // 1 unwrap + 1 panic + 1 unsafe = 3 candidates, all pattern-only.
        assert_eq!(report.total_candidates, 3);
        // A detector flag is NEVER a finding (false-positive 0 by construction).
        assert_eq!(report.direct_findings, 0);
        // The histogram has the three rule classes.
        assert_eq!(report.rule_counts.len(), 3);
        assert!(
            report
                .rule_counts
                .iter()
                .any(|(r, c)| *r == "rust.unsafe" && *c == 1)
        );
        // The ranking is non-empty and ranks by plausible impact (unsafe/panic
        // outrank a noisy class; here all three are real-impact leads).
        assert!(!report.ranked.is_empty());
        // The first ranked class is a real-impact lead (unsafe or panic), never dbg.
        assert!(matches!(
            report.ranked[0].rule,
            "rust.unsafe" | "rust.panic"
        ));
    }

    #[test]
    fn empty_tree_yields_zero_candidates() {
        let dir = unique_dir("empty");
        let report = run_source_detect(&dir, AuditProfile::Rust);
        assert_eq!(report.total_candidates, 0);
        assert_eq!(report.files_scanned, 0);
        assert!(report.rule_counts.is_empty());
        assert!(report.ranked.is_empty());
        let lines = report_lines(&report);
        assert!(lines.iter().any(|l| l.contains("no pattern candidates")));
    }

    #[test]
    fn noise_never_outranks_real_impact() {
        // unsafe (memory-safety) must outrank dbg (noise) regardless of count.
        assert!(impact_for_rule("rust.unsafe").score() > impact_for_rule("rust.dbg").score());
        assert!(impact_for_rule("rust.panic").score() > impact_for_rule("rust.dbg").score());
        // dbg is heavily penalized (noise).
        assert_eq!(impact_for_rule("rust.dbg").score(), 0);
    }

    #[test]
    fn a_source_candidate_cannot_become_a_finding_without_a_repro_receipt() {
        // E11-2-2 verify-before-expose: a REAL source candidate (as `scan_tree`
        // emits) wrapped via the public `flag_source_candidate` adapter is a
        // PatternMatch node — it can become a finding ONLY through `promote` with a
        // reproduced, local-only receipt that backs its node. No reproduced receipt
        // ⇒ it STAYS a candidate (false-positive 0 by construction, IV-AE1).
        use crate::audit::candidate::PromotionReject;
        use crate::audit::repro_receipt::{LocalReproRunnerReceipt, ReproReceiptHashes};
        use crate::commands::eval_core::AuditCandidate;
        use mnemos_l_dataset::AtomDietKey;
        use mnemos_l_dataset::diet_kind::DietSourceStage;
        use mnemos_l_dataset::security::source::SecuritySeverity;

        let inner = AuditCandidate {
            rule_id_hash_32: [0x11; 32],
            location_hash_32: [0x22; 32],
            invariant_hash_32: [0x33; 32],
            evidence_hash_32: [0x44; 32],
            confidence_bps_u16: 5000,
            repro_plan_safe_local: false,
            local_repro_done: false,
        };
        let candidate = DetectorSurface::flag_source_candidate(inner);
        assert!(
            candidate.is_pattern_only(),
            "a source flag is candidate-only"
        );

        let key = AtomDietKey::new(DietSourceStage::StageD, 1);
        // A NON-reproduced receipt for this exact node never promotes.
        let receipt = LocalReproRunnerReceipt::record(
            &ReproReceiptHashes {
                node_hash_32: candidate.node_hash_32,
                command_hash_32: [2u8; 32],
                fixture_hash_32: [3u8; 32],
                result_hash_32: [4u8; 32],
            },
            false, // not reproduced
            false,
            false,
        )
        .expect("a valid local receipt records");
        assert_eq!(
            candidate.promote(&receipt, key, SecuritySeverity::High),
            Err(PromotionReject::ReceiptNotReproduced),
            "verify-before-expose: no reproduced receipt ⇒ stays a candidate"
        );
    }

    #[test]
    fn report_lines_are_honest_candidate_not_finding() {
        let dir = unique_dir("honest");
        write_file(&dir, "src/a.rs", "let y = z.unwrap();\n");
        let report = run_source_detect(&dir, AuditProfile::Rust);
        let lines = report_lines(&report);
        // No line ever labels a candidate a "finding" with a severity.
        assert!(lines.iter().any(|l| l.contains("candidate != finding")));
        assert!(
            lines
                .iter()
                .any(|l| l.contains("needs a reproduced LOCAL repro receipt"))
        );
        assert!(!lines.iter().any(|l| l.to_lowercase().contains("severity=")));
    }
}
