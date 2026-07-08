//! Scripted first-run demo journey (atom #476 · F.8.9).
//!
//! The 5-minute first run: install → doctor → setup memory → REPL → context
//! status → checkpoint create/restore → TUI → skill search/use (dry-run) → gas
//! status → eval dry-run → notify test → kill a job. The journey defaults to
//! offline / local-fixture mode: **no live secret, no on-chain write**, every
//! step classified through the canonical [`CommandEnvelope`]. This integration
//! test asserts those invariants on the journey definition.

// Integration tests build as a separate crate; allow the test-only ergonomic
// macros the production deny-list forbids in lib code.
#![allow(clippy::expect_used, clippy::unwrap_used)]

use sinabro::command::{
    ApprovalRequirement, CliMode, CommandEnvelope, CommandRisk, CommandTraceRecord,
};
use sinabro::commands::audit::{AuditAction, AuditEntry, AuditTrail};
use sinabro::commands::release_secret_scan::{ReleaseSecretScan, ReleaseSurface};
use sinabro::config::LearningMode;
use sinabro::grammar::CliNamespace;
use sinabro::trace::{TraceClassKind, TraceWriter};
use sinabro::tui::RenderTruth;
use sinabro::{StageFEvidenceRef, StageFTraceLink, sha256_32};

/// One scripted step of the first-run journey.
struct Step {
    namespace: CliNamespace,
    verb: &'static str,
    mode: CliMode,
    risk: CommandRisk,
}

fn journey() -> Vec<Step> {
    vec![
        Step {
            namespace: CliNamespace::Key,
            verb: "doctor",
            mode: CliMode::Doctor,
            risk: CommandRisk::ReadOnly,
        },
        Step {
            namespace: CliNamespace::Memory,
            verb: "setup",
            mode: CliMode::Run,
            risk: CommandRisk::LocalWrite,
        },
        Step {
            namespace: CliNamespace::Agent,
            verb: "repl",
            mode: CliMode::Repl,
            risk: CommandRisk::ReadOnly,
        },
        Step {
            namespace: CliNamespace::Context,
            verb: "status",
            mode: CliMode::Repl,
            risk: CommandRisk::ReadOnly,
        },
        Step {
            namespace: CliNamespace::Checkpoint,
            verb: "create",
            mode: CliMode::Repl,
            risk: CommandRisk::LocalWrite,
        },
        Step {
            namespace: CliNamespace::Checkpoint,
            verb: "restore",
            mode: CliMode::Repl,
            risk: CommandRisk::LocalWrite,
        },
        Step {
            namespace: CliNamespace::Agent,
            verb: "tui",
            mode: CliMode::Tui,
            risk: CommandRisk::ReadOnly,
        },
        Step {
            namespace: CliNamespace::Skill,
            verb: "search",
            mode: CliMode::Tui,
            risk: CommandRisk::ReadOnly,
        },
        Step {
            namespace: CliNamespace::Skill,
            verb: "use",
            mode: CliMode::Tui,
            risk: CommandRisk::ReadOnly,
        },
        Step {
            namespace: CliNamespace::Gas,
            verb: "status",
            mode: CliMode::Tui,
            risk: CommandRisk::ReadOnly,
        },
        Step {
            namespace: CliNamespace::Eval,
            verb: "run",
            mode: CliMode::Run,
            risk: CommandRisk::ReadOnly,
        },
        Step {
            namespace: CliNamespace::Notify,
            verb: "test",
            mode: CliMode::Run,
            risk: CommandRisk::LocalWrite,
        },
        Step {
            namespace: CliNamespace::Agent,
            verb: "kill",
            mode: CliMode::Repl,
            risk: CommandRisk::Admin,
        },
    ]
}

#[test]
fn first_run_journey_is_offline_with_no_live_secret_or_on_chain_write() {
    let steps = journey();
    assert_eq!(
        steps.len(),
        13,
        "the scripted 5-minute journey has 13 steps"
    );
    for s in &steps {
        let env = CommandEnvelope::classify(s.namespace, s.verb, s.mode, s.risk, b"");
        // No step performs network egress, wallet signing, an on-chain write, or
        // training execution → no live secret, no on-chain write.
        assert!(
            !matches!(
                env.risk,
                CommandRisk::Network
                    | CommandRisk::WalletSign
                    | CommandRisk::ChainWrite
                    | CommandRisk::Training
            ),
            "{}::{} must not be a live action",
            s.namespace.canonical_name(),
            s.verb
        );
        // No step is forbidden in Stage F or needs a multisig (neither belongs in
        // a safe, offline first run).
        assert_ne!(env.approval, ApprovalRequirement::ForbiddenInStageF);
        assert_ne!(env.approval, ApprovalRequirement::Multisig);
    }
}

#[test]
fn first_run_records_audit_trace_and_stays_secret_zero() {
    // The kill + restore steps leave tamper-free, fully-traced audit entries.
    let kill_link = StageFTraceLink::new(sha256_32(b"kill"), 469, 800);
    let kill_ev = StageFEvidenceRef {
        path_hash_32: sha256_32(b"ops/evidence/stage_f/kill"),
        trace: kill_link,
    };
    let restore_link = StageFTraceLink::new(sha256_32(b"restore"), 470, 801);
    let restore_ev = StageFEvidenceRef {
        path_hash_32: sha256_32(b"ops/evidence/stage_f/restore"),
        trace: restore_link,
    };
    let mut trail = AuditTrail::new();
    trail.push(AuditEntry::seal(AuditAction::Kill, kill_link, kill_ev));
    trail.push(AuditEntry::seal(
        AuditAction::Rollback,
        restore_link,
        restore_ev,
    ));
    assert_eq!(trail.tamper_count(), 0);
    assert_eq!(trail.untraced_count(), 0);
    assert_eq!(trail.trail_truth(), RenderTruth::Green);

    // With learning off, the kill (Admin, high-risk) still writes the mandatory
    // audit line, but produces no diet artifacts (learning stays off by default).
    let kill_env = CommandEnvelope::classify(
        CliNamespace::Agent,
        "kill",
        CliMode::Repl,
        CommandRisk::Admin,
        b"",
    );
    let kill_record = CommandTraceRecord {
        envelope: kill_env,
        exit_code_i32: 0,
        evidence: kill_ev,
        redacted_output_hash_32: sha256_32(b"job#1 stopped"),
    };
    let writer = TraceWriter::new(LearningMode::Off);
    let decision = writer.decide(&kill_record, TraceClassKind::SideEffect);
    assert!(decision.mandatory_audit);
    assert!(!decision.local_diet);
    assert!(!decision.local_evidence);

    // The demo transcript carries no baked secret.
    let transcript = "doctor ok\nsetup memory ok\nrepl ready\nkill job#1 -> stopped\n";
    let mut scan = ReleaseSecretScan::new();
    scan.add(ReleaseSurface::Trace, transcript);
    assert!(scan.is_clean());
    assert!(scan.gate().is_ok());
    assert_eq!(scan.render_truth(), RenderTruth::Green);
}
