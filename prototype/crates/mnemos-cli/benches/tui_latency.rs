//! Offline TUI refresh latency harness (atom #426 F.2.9).
//!
//! `harness = false` — no criterion (deferred per build-state). It measures the
//! real cockpit-pane `render` / projection hot path with `std::time` and scores
//! the p95 against the §4.3 [`LatencyBudget`] (TUI refresh ceiling 250ms) using
//! the same [`p95_ms`] the unit tests verify. Output is written through a `Write`
//! handle (not `println!`), so the workspace `print_stdout` deny stays clean.
//!
//! Run: `cargo bench --bench tui_latency`.

use std::hint::black_box;
use std::io::Write;
use std::time::Instant;

use sinabro::command::{CliMode, CommandEnvelope, CommandRisk};
use sinabro::grammar::CliNamespace;
use sinabro::repl::latency::{LatencyBudget, LatencyScore, p95_ms};
use sinabro::tui::approval_modal::ApprovalModal;
use sinabro::tui::inspector::{EvidenceHint, HintTier, InspectTarget, InspectorView};
use sinabro::tui::skill_cards::{OfficialTrustDecision, SkillCardList, SkillCardView};
use sinabro::tui::skill_use_modal::{InstallStatus, SkillUseModal, SkillUseView};
use sinabro::tui::trace_pane::{TracePane, TraceSourceKind};
use sinabro::{StageFEvidenceRef, StageFTraceLink};

const ITERS: usize = 2000;

fn measure<F: FnMut()>(mut op: F) -> Vec<u64> {
    let mut samples = Vec::with_capacity(ITERS);
    for _ in 0..ITERS {
        let t = Instant::now();
        op();
        samples.push(t.elapsed().as_nanos() as u64);
    }
    samples
}

fn big_trace() -> TracePane {
    // a 10k-line log, folded once at ingest; render() is the hot path.
    let raw: String = (0..10_000)
        .map(|i| format!("  {}: frame::call site {i}\n", i % 7))
        .collect();
    TracePane::ingest(TraceSourceKind::Log, &raw, 32)
}

fn skill_list() -> SkillCardList {
    let mut l = SkillCardList::new();
    for i in 0..100u64 {
        let trust = if i % 13 == 0 {
            OfficialTrustDecision::Quarantined
        } else {
            OfficialTrustDecision::OfficialTrusted
        };
        l.push(SkillCardView::new(
            [(i as u8); 32],
            i * 7,
            9000,
            9000,
            [2u8; 32],
            [3u8; 32],
            [4u8; 32],
            trust,
        ));
    }
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

fn inspector() -> Option<InspectorView> {
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
    // bench fixture is valid by construction; if a future edit zeroes it the
    // bench simply skips the inspector pane (no panic on the bench path).
    InspectorView::new(InspectTarget::Skill, ev, hint, [9u8; 32])
}

fn main() {
    let trace = big_trace();
    let skills = skill_list();
    let modal = use_modal();
    let approval = approval_modal();
    let insp = inspector();

    // The refresh hot path: re-render every pane into a bounded frame.
    let refresh_ns = measure(|| {
        black_box(trace.render(black_box(120), black_box(40)));
        black_box(skills.render_compact_page(black_box(0), black_box(20), black_box(20)));
        black_box(modal.render(black_box(16)));
        black_box(approval.render(black_box(16)));
        if let Some(v) = insp {
            black_box(v.render(black_box(0), black_box(16)));
        }
    });

    let refresh_p95_ns = p95_ms(&refresh_ns);
    let to_ms = |ns: u64| ns / 1_000_000;
    let refresh_ms = to_ms(refresh_p95_ns);

    let tui_budget = LatencyBudget {
        keypress_p95_ms: 16,
        parse_p95_ms: 10,
        render_p95_ms: 5,
        refresh_p95_ms: 250,
    };
    let score = LatencyScore::evaluate(tui_budget, 0, 0, 0, refresh_ms);

    let mut out = std::io::stdout().lock();
    let _ = writeln!(
        out,
        "tui_latency harness  iters={ITERS}  (p95 nearest-rank)"
    );
    let _ = writeln!(
        out,
        "  full refresh p95={refresh_p95_ns:>10} ns  ({refresh_ms} ms)  budget {} ms",
        tui_budget.refresh_p95_ms
    );
    let _ = writeln!(out, "  score: refresh_ok={}", score.refresh_ok);
}
