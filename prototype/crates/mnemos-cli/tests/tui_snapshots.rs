//! §4.3 TUI snapshot + score bundle (atom #426 F.2.9).
//!
//! Integration snapshots of the F-WP-03A cockpit panes across terminal sizes.
//! The atom's failure modes — overlap, an unreadable narrow terminal, a false
//! green, and a slow refresh — are each asserted against here. The panes own no
//! terminal (ratatui is deferred), so a "snapshot" is the bounded, colorless,
//! width-clamped text each pane projects, aggregated into a [`TuiScoreBundle`]
//! (the canonical OUT). Reuses the §4.3 [`LatencyBudget`] for the refresh gate.

// Integration tests build as a separate crate; allow the test-only ergonomic
// macros that the production deny-list forbids in lib code.
#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::time::Instant;

use sinabro::command::{CliMode, CommandEnvelope, CommandRisk};
use sinabro::grammar::CliNamespace;
use sinabro::repl::latency::{LatencyBudget, LatencyScore};
use sinabro::repl::prompt::PromptStatus;
use sinabro::route::RouteExecutionState;
use sinabro::tui::RenderTruth;
use sinabro::tui::approval_modal::ApprovalModal;
use sinabro::tui::inspector::{EvidenceHint, HintTier, InspectTarget, InspectorView};
use sinabro::tui::skill_cards::{OfficialTrustDecision, SkillCardList, SkillCardView};
use sinabro::tui::skill_use_modal::{InstallStatus, SkillUseModal, SkillUseView};
use sinabro::tui::status_bar::StatusBar;
use sinabro::tui::trace_pane::{TracePane, TraceSourceKind};
use sinabro::{StageFEvidenceRef, StageFTraceLink};

/// The TUI score bundle — per-dimension snapshot verdicts.
#[derive(Clone, Copy, Debug)]
struct TuiScoreBundle {
    snapshot_80x24_ok: bool,
    snapshot_120x40_ok: bool,
    narrow_ok: bool,
    colorless_ok: bool,
    no_false_green_ok: bool,
    refresh_ok: bool,
}

impl TuiScoreBundle {
    fn all_ok(&self) -> bool {
        self.snapshot_80x24_ok
            && self.snapshot_120x40_ok
            && self.narrow_ok
            && self.colorless_ok
            && self.no_false_green_ok
            && self.refresh_ok
    }
}

fn trace_pane() -> TracePane {
    let raw: String = (0..500).map(|i| format!("log line {i}\n")).collect();
    TracePane::ingest(TraceSourceKind::Log, &raw, 16)
}

fn skill_list() -> SkillCardList {
    let mut l = SkillCardList::new();
    l.push(SkillCardView::new(
        [1u8; 32],
        100,
        9000,
        9000,
        [2u8; 32],
        [3u8; 32],
        [4u8; 32],
        OfficialTrustDecision::OfficialTrusted,
    ));
    l.push(SkillCardView::new(
        [5u8; 32],
        9,
        9000,
        9000,
        [2u8; 32],
        [3u8; 32],
        [4u8; 32],
        OfficialTrustDecision::Quarantined,
    ));
    l
}

fn use_modal() -> SkillUseModal {
    let v = SkillUseView::new([1u8; 32], [2u8; 32], [3u8; 32], [4u8; 32], [5u8; 32], true);
    let mut m = SkillUseModal::new(v, [6u8; 32], [7u8; 32]);
    m.refresh(InstallStatus::DryRunPassed);
    m
}

fn approval_modal() -> ApprovalModal {
    let env = CommandEnvelope::classify(
        CliNamespace::Wallet,
        "sign",
        CliMode::Tui,
        CommandRisk::WalletSign,
        b"preview",
    );
    ApprovalModal::new(
        env,
        [1u8; 32],
        1500,
        [2u8; 32],
        StageFTraceLink::new([9u8; 32], 424, 1),
        "I APPROVE WALLET SIGN",
    )
}

fn inspector() -> InspectorView {
    let ev = StageFEvidenceRef {
        path_hash_32: [0xEE; 32],
        trace: StageFTraceLink::new([7u8; 32], 425, 1),
    };
    let hint = EvidenceHint {
        tier: HintTier::Proven,
        source_atom_u16: 305,
        evidence_hash_32: [3u8; 32],
        memory_root_32: [4u8; 32],
        expires_at_epoch_ms: 0,
        scope_hash_32: [5u8; 32],
        redaction_class_u8: 6,
    };
    InspectorView::new(InspectTarget::Skill, ev, hint, [9u8; 32]).expect("non-zero evidence")
}

/// Compose every pane into one frame for a `cols x rows` terminal, giving each
/// pane an equal share of the rows. The wide-terminal panes that do not
/// self-clamp (modals / inspector) are short by construction.
fn compose_wide(cols: u16, rows: u16) -> Vec<String> {
    let per = (rows / 5).max(2);
    let mut out: Vec<String> = Vec::new();
    out.extend(trace_pane().render(cols, per));
    out.extend(skill_list().render_compact_page(0, per, per));
    out.extend(use_modal().render(per));
    out.extend(approval_modal().render(per));
    out.extend(inspector().render(0, per));
    out
}

/// The narrow cockpit uses the self-clamping compact panes only.
fn compose_narrow(cols: u16, rows: u16) -> Vec<String> {
    let per = (rows / 2).max(2);
    let mut out: Vec<String> = Vec::new();
    out.extend(trace_pane().render(cols, per));
    out.extend(skill_list().render_compact_page(0, per, per));
    out
}

fn no_line_exceeds(frame: &[String], cols: u16) -> bool {
    frame.iter().all(|l| l.chars().count() <= cols as usize)
}

#[test]
fn snapshot_80x24_no_overlap() {
    let frame = compose_wide(80, 24);
    assert!(!frame.is_empty());
    assert!(
        no_line_exceeds(&frame, 80),
        "a pane overflowed 80 cols (overlap)"
    );
}

#[test]
fn snapshot_120x40_no_overlap() {
    let frame = compose_wide(120, 40);
    assert!(!frame.is_empty());
    assert!(no_line_exceeds(&frame, 120));
}

#[test]
fn narrow_terminal_is_readable() {
    let frame = compose_narrow(40, 10);
    assert!(!frame.is_empty(), "narrow terminal must still render");
    assert!(
        no_line_exceeds(&frame, 40),
        "narrow render overflowed (unreadable)"
    );
    // the narrow render still carries the safety signal: the quarantined card's
    // trust state is never dropped in the compact view.
    assert!(frame.iter().any(|l| l.contains("QUARANTINED")));
}

#[test]
fn colorless_mode_has_no_ansi_escape() {
    let mut all = compose_wide(120, 40);
    all.extend(compose_narrow(40, 10));
    // truth is conveyed by labels, never by raw color: no ANSI escape byte.
    assert!(all.iter().all(|l| !l.contains('\u{1b}')));
    // and the truth labels themselves are present (e.g. trace fold marker / card)
    assert!(
        all.iter()
            .any(|l| l.contains("QUARANTINED") || l.contains('…'))
    );
}

#[test]
fn no_false_green_across_panes() {
    // status bar with an Unknown trajectory is never healthy
    let status = PromptStatus {
        workspace_hash_32: [1u8; 32],
        model_hash_32: [2u8; 32],
        context_pressure_bps: 0,
        last_checkpoint_hash_32: [3u8; 32],
        budget_remaining_micros: 1,
        sandbox_tier_u8: 1,
        pending_approvals_u16: 0,
        pending_tasks_u16: 0,
    };
    let bar = StatusBar::new(
        status,
        RouteExecutionState::Normal,
        RenderTruth::Green,
        RenderTruth::Unknown,
    );
    assert!(!bar.is_healthy());

    // a quarantined skill card is Red regardless of popularity
    let quarantined = SkillCardView::new(
        [1u8; 32],
        1_000_000,
        9999,
        9999,
        [2u8; 32],
        [3u8; 32],
        [4u8; 32],
        OfficialTrustDecision::Quarantined,
    );
    assert_eq!(quarantined.render_truth(), RenderTruth::Red);

    // a stale inspector hint is Red
    let ev = StageFEvidenceRef {
        path_hash_32: [0xEE; 32],
        trace: StageFTraceLink::new([7u8; 32], 425, 1),
    };
    let stale = EvidenceHint {
        tier: HintTier::Proven,
        source_atom_u16: 1,
        evidence_hash_32: [3u8; 32],
        memory_root_32: [4u8; 32],
        expires_at_epoch_ms: 1000,
        scope_hash_32: [5u8; 32],
        redaction_class_u8: 0,
    };
    let v = InspectorView::new(InspectTarget::Security, ev, stale, [9u8; 32]).expect("evidence");
    assert_eq!(v.truth(2000), RenderTruth::Red);
}

#[test]
fn refresh_within_budget() {
    // The TUI refresh budget reuses §4.3 LatencyBudget; the TUI refresh ceiling
    // is 250ms (atom #426 criterion). A full compose of bounded panes is orders
    // of magnitude faster, so this is a generous, non-flaky smoke.
    let t = Instant::now();
    let _ = compose_wide(120, 40);
    let elapsed_ms = t.elapsed().as_millis() as u64;
    let tui_budget = LatencyBudget {
        keypress_p95_ms: 16,
        parse_p95_ms: 10,
        render_p95_ms: 5,
        refresh_p95_ms: 250,
    };
    let score = LatencyScore::evaluate(tui_budget, 0, 0, 0, elapsed_ms);
    assert!(
        score.refresh_ok,
        "TUI refresh exceeded 250ms budget: {elapsed_ms}ms"
    );
}

#[test]
fn tui_score_bundle_all_ok() {
    let frame80 = compose_wide(80, 24);
    let frame120 = compose_wide(120, 40);
    let narrow = compose_narrow(40, 10);
    let mut colorless_src = frame120.clone();
    colorless_src.extend(narrow.clone());

    let t = Instant::now();
    let _ = compose_wide(120, 40);
    let elapsed_ms = t.elapsed().as_millis() as u64;

    let bundle = TuiScoreBundle {
        snapshot_80x24_ok: !frame80.is_empty() && no_line_exceeds(&frame80, 80),
        snapshot_120x40_ok: !frame120.is_empty() && no_line_exceeds(&frame120, 120),
        narrow_ok: !narrow.is_empty() && no_line_exceeds(&narrow, 40),
        colorless_ok: colorless_src.iter().all(|l| !l.contains('\u{1b}')),
        no_false_green_ok: SkillCardView::new(
            [1u8; 32],
            1_000_000,
            9999,
            9999,
            [2u8; 32],
            [3u8; 32],
            [4u8; 32],
            OfficialTrustDecision::Quarantined,
        )
        .render_truth()
            == RenderTruth::Red,
        refresh_ok: elapsed_ms <= 250,
    };
    assert!(bundle.all_ok(), "tui score bundle failed: {bundle:?}");
}
