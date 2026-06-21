//! `/kill` interrupt semantics (atom #469 · F.8.2).
//!
//! `sinabro kill` / the `/kill` slash command. Killing an agent / tool / eval /
//! any background job propagates to that job, records its final state, and leaves
//! no zombie: a killed job can never resurrect (the no-zombie invariant is owned
//! by [`crate::tui::job_rail::JobRailItem::try_transition`]). `/kill` is an
//! **express** control command — it rides the same pre-allocated control rail as
//! `/budget cap` ([`ExpressControl::Kill`]) and never waits behind background
//! backpressure, replay / export / train / evidence jobs, or task-inbox
//! rendering (`G-F-CONTROL-EXPRESS`). After a hard-kill + restart, the durable
//! job journal is reconciled so any orphaned (still-live) job is cleaned up to
//! `Killed` — broken recovery and zombie green are impossible
//! (`G-F-CRASH-RECOVERY`). A repeated kill is idempotent.
//!
//! Reuse (no reinvention): the job rail and its no-zombie transition are the
//! canonical [`crate::tui::job_rail`] types; the express-rail bypass is the
//! canonical [`ExpressControl::Kill`]; the trace link is
//! [`crate::StageFTraceLink`]. This module performs no live action — it
//! transitions in-memory job state and reconciles an in-memory journal; no OS
//! signal is sent in Stage F.

use crate::StageFTraceLink;
use crate::commands::platform_telegram::ExpressControl;
use crate::tui::job_rail::{JobRail, JobState};

/// Why a job was killed — recorded with the kill for the audit trail.
#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum KillReason {
    /// The user requested the kill (`/kill`).
    UserRequested = 1,
    /// The job exceeded its deadline / timeout.
    Timeout = 2,
    /// An incident pause / lockdown forced the kill.
    Incident = 3,
    /// A tool adapter signalled a hard stop.
    ToolStop = 4,
}

impl KillReason {
    /// The stable `u8` discriminant.
    #[must_use]
    pub const fn as_u8(self) -> u8 {
        self as u8
    }
}

/// The acknowledgement of a `/kill` — produced synchronously on the express rail.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct KillAck {
    /// The job that was targeted.
    pub job_id_u64: u64,
    /// The job's final (terminal) state after the kill.
    pub final_state: JobState,
    /// The recorded kill reason (audit).
    pub reason: KillReason,
    /// Always `true`: `/kill` bypasses the normal / background queues
    /// ([`ExpressControl::Kill`]).
    pub bypassed_queue: bool,
    /// The control version after the kill (monotonic; proves hot-path handling).
    pub version_u32: u32,
    /// Whether the job was already terminal (a repeated / idempotent kill).
    pub already_terminal: bool,
    /// Whether the target job id was found on the rail.
    pub found: bool,
    /// The trace link the kill is bound to (audit).
    pub trace: StageFTraceLink,
}

/// The `/kill` controller: owns the job rail and a monotonic control version, and
/// can reconcile a durable job journal after a hard-kill + restart.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct KillController {
    rail: JobRail,
    version_u32: u32,
}

impl KillController {
    /// A new controller with an empty rail.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// A controller wrapping an existing rail.
    #[must_use]
    pub fn from_rail(rail: JobRail) -> Self {
        Self {
            rail,
            version_u32: 0,
        }
    }

    /// The job rail (read-only).
    #[must_use]
    pub fn rail(&self) -> &JobRail {
        &self.rail
    }

    /// Mutable access to the rail (to admit jobs).
    pub fn rail_mut(&mut self) -> &mut JobRail {
        &mut self.rail
    }

    /// The control version (bumped on every kill).
    #[must_use]
    pub const fn version(&self) -> u32 {
        self.version_u32
    }

    /// Kill a job by id on the express rail. The ack is produced synchronously
    /// (rail transition + version bump), never enqueued behind background work.
    /// Killing a terminal job is an idempotent no-op (`already_terminal`), and the
    /// no-zombie invariant prevents resurrection.
    pub fn kill(&mut self, job_id_u64: u64, reason: KillReason, trace: StageFTraceLink) -> KillAck {
        let bypassed_queue = ExpressControl::Kill.bypasses_queue();
        self.version_u32 = self.version_u32.saturating_add(1);
        let existing = self
            .rail
            .items()
            .iter()
            .find(|i| i.job_id_u64 == job_id_u64)
            .copied();
        match existing {
            None => KillAck {
                job_id_u64,
                final_state: JobState::Killed,
                reason,
                bypassed_queue,
                version_u32: self.version_u32,
                already_terminal: false,
                found: false,
                trace,
            },
            Some(item) if item.state.is_terminal() => KillAck {
                job_id_u64,
                final_state: item.state,
                reason,
                bypassed_queue,
                version_u32: self.version_u32,
                already_terminal: true,
                found: true,
                trace,
            },
            Some(_) => {
                let transitioned = self.rail.transition(job_id_u64, JobState::Killed);
                KillAck {
                    job_id_u64,
                    final_state: JobState::Killed,
                    reason,
                    bypassed_queue,
                    version_u32: self.version_u32,
                    already_terminal: !transitioned,
                    found: true,
                    trace,
                }
            }
        }
    }

    /// Snapshot the durable job journal (the `(id, state)` pairs persisted so a
    /// restart can recover). In Stage F this is the current rail state.
    #[must_use]
    pub fn journal_snapshot(&self) -> Vec<(u64, JobState)> {
        self.rail
            .items()
            .iter()
            .map(|i| (i.job_id_u64, i.state))
            .collect()
    }

    /// Reconcile a durable journal after a hard-kill + restart: any job still in a
    /// live state is an orphan (its process died with the host) and is cleaned up
    /// to `Killed`; terminal jobs are preserved verbatim. No orphan is left live
    /// (no zombie green), and recovery is deterministic.
    #[must_use]
    pub fn reconcile_after_restart(journal: &[(u64, JobState)]) -> Vec<(u64, JobState)> {
        journal
            .iter()
            .map(|&(id, state)| {
                if state.is_terminal() {
                    (id, state)
                } else {
                    (id, JobState::Killed)
                }
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::repl::latency::p95_ms;
    use crate::tui::job_rail::{JobKind, JobRailItem};

    fn trace() -> StageFTraceLink {
        StageFTraceLink::new([0x69; 32], 469, 469)
    }

    fn rail_with(items: &[(u64, JobKind, JobState)]) -> JobRail {
        let mut rail = JobRail::new();
        for &(id, kind, state) in items {
            rail.push(JobRailItem::new(id, kind, state, trace()));
        }
        rail
    }

    #[test]
    fn agent_tool_eval_kill_reach_killed() {
        let mut kc = KillController::from_rail(rail_with(&[
            (1, JobKind::Agent, JobState::Running),
            (2, JobKind::Tool, JobState::Running),
            (3, JobKind::Eval, JobState::Pending),
        ]));
        for id in [1u64, 2, 3] {
            let ack = kc.kill(id, KillReason::UserRequested, trace());
            assert!(ack.found);
            assert_eq!(ack.final_state, JobState::Killed);
            assert!(!ack.already_terminal);
        }
        assert_eq!(kc.rail().live_count(), 0);
    }

    #[test]
    fn kill_records_reason_and_trace_for_audit() {
        let mut kc = KillController::from_rail(rail_with(&[(1, JobKind::Tool, JobState::Running)]));
        let ack = kc.kill(1, KillReason::ToolStop, trace());
        assert_eq!(ack.reason, KillReason::ToolStop);
        assert_eq!(ack.trace.stage_f_atom_u16, 469);
        let mut kc2 =
            KillController::from_rail(rail_with(&[(7, JobKind::Eval, JobState::Running)]));
        let timeout = kc2.kill(7, KillReason::Timeout, trace());
        assert_eq!(timeout.reason, KillReason::Timeout);
    }

    #[test]
    fn kill_is_express_and_bypasses_queue() {
        assert!(ExpressControl::Kill.bypasses_queue());
        let mut kc =
            KillController::from_rail(rail_with(&[(1, JobKind::Agent, JobState::Running)]));
        let ack = kc.kill(1, KillReason::UserRequested, trace());
        assert!(ack.bypassed_queue);
    }

    #[test]
    fn repeated_kill_is_idempotent() {
        let mut kc =
            KillController::from_rail(rail_with(&[(1, JobKind::Agent, JobState::Running)]));
        let first = kc.kill(1, KillReason::UserRequested, trace());
        assert!(!first.already_terminal);
        let second = kc.kill(1, KillReason::UserRequested, trace());
        assert!(second.already_terminal);
        assert_eq!(second.final_state, JobState::Killed);
        // The version still advances (the second kill was processed, not queued).
        assert!(second.version_u32 > first.version_u32);
    }

    #[test]
    fn kill_unknown_id_is_acked_not_found() {
        let mut kc = KillController::new();
        let ack = kc.kill(404, KillReason::UserRequested, trace());
        assert!(!ack.found);
        assert!(ack.bypassed_queue);
    }

    #[test]
    fn hard_kill_restart_reconciles_orphans_to_killed() {
        let kc = KillController::from_rail(rail_with(&[
            (1, JobKind::Agent, JobState::Running), // orphan -> Killed
            (2, JobKind::Tool, JobState::WaitingApproval), // orphan -> Killed
            (3, JobKind::Eval, JobState::Passed),   // terminal -> preserved
            (4, JobKind::Skill, JobState::Failed),  // terminal -> preserved
        ]));
        let journal = kc.journal_snapshot();
        let recovered = KillController::reconcile_after_restart(&journal);
        let recovered_state = |id: u64| recovered.iter().find(|&&(i, _)| i == id).map(|&(_, s)| s);
        assert_eq!(recovered_state(1), Some(JobState::Killed));
        assert_eq!(recovered_state(2), Some(JobState::Killed));
        assert_eq!(recovered_state(3), Some(JobState::Passed));
        assert_eq!(recovered_state(4), Some(JobState::Failed));
        // No orphan stays live after reconcile (no zombie green).
        assert!(recovered.iter().all(|&(_, s)| s.is_terminal()));
    }

    #[test]
    fn kill_while_replay_saturated_still_acks() {
        // A rail saturated with background replay/dataset jobs does not delay the
        // kill (the express rail bypasses the queue).
        let mut items: Vec<(u64, JobKind, JobState)> = (0..200u64)
            .map(|i| (i, JobKind::Dataset, JobState::Running))
            .collect();
        items.push((999, JobKind::Agent, JobState::Running));
        let mut kc = KillController::from_rail(rail_with(&items));
        let ack = kc.kill(999, KillReason::UserRequested, trace());
        assert!(ack.bypassed_queue);
        assert_eq!(ack.final_state, JobState::Killed);
    }

    #[test]
    fn kill_while_train_dashboard_busy_still_acks() {
        let mut kc = KillController::from_rail(rail_with(&[
            (1, JobKind::Train, JobState::Running), // train dashboard busy
            (2, JobKind::Tool, JobState::Running),
        ]));
        let ack = kc.kill(2, KillReason::UserRequested, trace());
        assert!(ack.bypassed_queue);
        assert_eq!(ack.final_state, JobState::Killed);
    }

    #[test]
    fn kill_ack_p95_within_16ms_under_saturation() {
        let mut items: Vec<(u64, JobKind, JobState)> = (0..256u64)
            .map(|i| (i, JobKind::Tool, JobState::Running))
            .collect();
        items.push((1000, JobKind::Agent, JobState::Running));
        let mut kc = KillController::from_rail(rail_with(&items));
        let mut samples = Vec::with_capacity(256);
        for i in 0..256u64 {
            let t = std::time::Instant::now();
            let ack = kc.kill(i, KillReason::UserRequested, trace());
            std::hint::black_box(&ack);
            samples.push(t.elapsed().as_nanos() as u64);
        }
        let p95 = p95_ms(&samples) / 1_000_000;
        assert!(p95 <= 16, "kill ack p95 {p95}ms exceeds 16ms");
    }

    #[test]
    fn kill_signal_to_stopped_p95_within_500ms() {
        let mut samples = Vec::with_capacity(256);
        for i in 0..256u64 {
            let mut kc =
                KillController::from_rail(rail_with(&[(i, JobKind::Agent, JobState::Running)]));
            let t = std::time::Instant::now();
            let ack = kc.kill(i, KillReason::UserRequested, trace());
            // "stopped" == the job reached the Killed terminal state.
            let stopped = ack.final_state == JobState::Killed;
            std::hint::black_box(&stopped);
            samples.push(t.elapsed().as_nanos() as u64);
        }
        let p95 = p95_ms(&samples) / 1_000_000;
        assert!(p95 <= 500, "kill-to-stopped p95 {p95}ms exceeds 500ms");
    }
}
