//! Cockpit jobs / task / session dashboard.
//!
//! A read-only cockpit projection over the *canonical* [`crate::tui::job_rail`]
//! truth: the unified task / session / job inbox. It shows every background job
//! (agent / tool / skill / chain / gas / dataset / train / eval / measure /
//! session / notification) with its lifecycle state and killability, the
//! task-inbox affordances (open / resume / detach / watch / cancel), the session
//! export/import round-trip digest, the pending-approval depth, the remaining
//! budget the rail syncs to, and the Telegram delivery staleness.
//!
//! Reuse (no reinvention): every job row is the canonical
//! [`crate::tui::job_rail::JobRailItem`]; the no-zombie invariant and the
//! killability rule are owned there ([`JobRailItem::try_transition`]). The
//! red/yellow/green verdict is the cockpit [`crate::tui::RenderTruth`]. The
//! session digest uses the crate [`crate::sha256_32`] helper. This module mints
//! no job truth, reaches into no private field, performs no live action, and
//! surfaces train jobs as dashboard/doctor only — never execution.
//!
//! Latency: the projection is a single `O(jobs)` pass and the render is bounded
//! by `rows`; nothing scans the repo, replays memory, renders a full trace, or
//! touches the network (refresh p95 ≤ 250ms). No false green: a failed job is
//! `Red`, a job awaiting approval or a stale subsystem is `Yellow`, never a false
//! `Green`.

use crate::sha256_32;
use crate::tui::RenderTruth;
use crate::tui::job_rail::{JobKind, JobRailItem, JobState};

/// A task-inbox action a user can take on a tracked job.
#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TaskInboxAction {
    /// Bring the task to the foreground view.
    Open = 1,
    /// Resume a paused task (`Paused` -> `Running`).
    Resume = 2,
    /// Move a running task to the background (detached).
    Detach = 3,
    /// Re-attach to a detached task (foreground watch).
    Watch = 4,
    /// Cancel a task (-> `Killed`).
    Cancel = 5,
}

impl TaskInboxAction {
    /// The stable `u8` discriminant.
    #[must_use]
    pub const fn as_u8(self) -> u8 {
        self as u8
    }
}

/// One task in the inbox: a canonical [`JobRailItem`] plus whether the user is
/// currently attached (foreground / watching) or detached (background).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct InboxTask {
    /// The canonical job row (state / kind / killability / trace).
    pub item: JobRailItem,
    /// Whether the user is attached (watching) this task.
    pub attached: bool,
}

impl InboxTask {
    /// A new inbox task wrapping a job row.
    #[must_use]
    pub const fn new(item: JobRailItem, attached: bool) -> Self {
        Self { item, attached }
    }

    /// Apply a task-inbox action. Returns `false` (no-op) when the action cannot
    /// apply (resuming a non-paused task, cancelling a terminal job). The
    /// underlying state transition reuses the no-zombie
    /// [`JobRailItem::try_transition`] — a terminal job can never resurrect.
    pub const fn apply(&mut self, action: TaskInboxAction) -> bool {
        match action {
            TaskInboxAction::Open | TaskInboxAction::Watch => {
                self.attached = true;
                true
            }
            TaskInboxAction::Detach => {
                self.attached = false;
                true
            }
            TaskInboxAction::Resume => {
                if matches!(self.item.state, JobState::Paused) {
                    self.item.try_transition(JobState::Running)
                } else {
                    false
                }
            }
            TaskInboxAction::Cancel => self.item.try_transition(JobState::Killed),
        }
    }
}

/// A session export / import digest: the number of tasks plus a content digest
/// over the canonical task encoding. Export produces it; import re-derives it and
/// confirms a byte-identical round-trip (no silent loss of background work).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SessionSnapshot {
    /// Number of tasks captured.
    pub task_count: usize,
    /// SHA-256 over the canonical task encoding.
    pub digest_32: [u8; 32],
}

impl SessionSnapshot {
    /// Export a session snapshot from the inbox tasks.
    #[must_use]
    pub fn export(tasks: &[InboxTask]) -> Self {
        Self {
            task_count: tasks.len(),
            digest_32: session_digest(tasks),
        }
    }

    /// Verify an import round-trip: the snapshot matches the (re-loaded) tasks
    /// exactly. A mismatch means a lossy import, refused upstream.
    #[must_use]
    pub fn verify_import(&self, tasks: &[InboxTask]) -> bool {
        self.task_count == tasks.len() && self.digest_32 == session_digest(tasks)
    }
}

/// Canonical content digest over the inbox tasks (order-sensitive).
#[must_use]
fn session_digest(tasks: &[InboxTask]) -> [u8; 32] {
    let mut buf = Vec::with_capacity(tasks.len() * 11);
    for t in tasks {
        buf.extend_from_slice(&t.item.job_id_u64.to_le_bytes());
        buf.push(t.item.kind as u8);
        buf.push(t.item.state as u8);
        buf.push(u8::from(t.attached));
    }
    sha256_32(&buf)
}

/// The unified task / session / job dashboard projection.
/// Built from the canonical job rail plus a few external platform signals; holds
/// no job truth of its own.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct JobsDashboard {
    /// Total jobs on the rail.
    pub total: usize,
    /// Jobs in a live (killable) state.
    pub live: usize,
    /// Jobs in a failed terminal state.
    pub failed: usize,
    /// Jobs awaiting a user approval.
    pub waiting_approval: usize,
    /// Train jobs present — surfaced as dashboard/doctor only (never execution);
    /// the count is shown so the lock stays visible.
    pub train_locked: usize,
    /// Whether a gas job is currently running.
    pub gas_running: bool,
    /// Whether an eval job has failed.
    pub eval_failed: bool,
    /// Whether a measurement job is stale (paused / not progressing).
    pub measure_stale: bool,
    /// Outstanding delivered-but-unresolved approval requests (from the platform).
    pub pending_approvals: usize,
    /// Whether the Telegram delivery view is stale relative to the shared state.
    pub telegram_stale: bool,
    /// The remaining budget (micro-units) the rail syncs to.
    pub budget_remaining_micros: u64,
    /// The atom of the most recent job's trace (the dashboard's trace row).
    pub latest_trace_atom: u16,
}

impl JobsDashboard {
    /// Project the dashboard from the canonical job rail items plus external
    /// platform signals. A single `O(items)` pass; no scan, replay, or network.
    #[must_use]
    pub fn project(
        items: &[JobRailItem],
        pending_approvals: usize,
        telegram_stale: bool,
        budget_remaining_micros: u64,
    ) -> Self {
        let mut live = 0usize;
        let mut failed = 0usize;
        let mut waiting_approval = 0usize;
        let mut train_locked = 0usize;
        let mut gas_running = false;
        let mut eval_failed = false;
        let mut measure_stale = false;
        let mut latest_trace_atom = 0u16;
        for it in items {
            if it.state.is_live() {
                live += 1;
            }
            match it.state {
                JobState::Failed => failed += 1,
                JobState::WaitingApproval => waiting_approval += 1,
                _ => {}
            }
            match it.kind {
                JobKind::Train => train_locked += 1,
                JobKind::Gas if it.state.is_live() => gas_running = true,
                JobKind::Eval if matches!(it.state, JobState::Failed) => eval_failed = true,
                JobKind::Measure if matches!(it.state, JobState::Paused) => measure_stale = true,
                _ => {}
            }
            latest_trace_atom = it.trace.stage_f_atom_u16;
        }
        Self {
            total: items.len(),
            live,
            failed,
            waiting_approval,
            train_locked,
            gas_running,
            eval_failed,
            measure_stale,
            pending_approvals,
            telegram_stale,
            budget_remaining_micros,
            latest_trace_atom,
        }
    }

    /// The render truth (no false green). `Red` when any job has failed; `Yellow`
    /// when attention is needed (approval pending / waiting / stale measure or
    /// Telegram); otherwise `Green` (running jobs are healthy).
    #[must_use]
    pub const fn render_truth(&self) -> RenderTruth {
        if self.failed > 0 || self.eval_failed {
            RenderTruth::Red
        } else if self.waiting_approval > 0
            || self.pending_approvals > 0
            || self.measure_stale
            || self.telegram_stale
        {
            RenderTruth::Yellow
        } else {
            RenderTruth::Green
        }
    }

    /// Colorless dashboard lines bounded by `rows` (hot-path render).
    #[must_use]
    pub fn render(&self, rows: u16) -> Vec<String> {
        let lines = vec![
            format!("jobs_total={}", self.total),
            format!("jobs_live={}", self.live),
            format!("jobs_failed={}", self.failed),
            format!("waiting_approval={}", self.waiting_approval),
            format!("train_locked={}", self.train_locked),
            format!("gas_running={}", self.gas_running),
            format!("eval_failed={}", self.eval_failed),
            format!("measure_stale={}", self.measure_stale),
            format!("pending_approvals={}", self.pending_approvals),
            format!("telegram_stale={}", self.telegram_stale),
            format!("budget_remaining_micros={}", self.budget_remaining_micros),
            format!("latest_trace_atom={}", self.latest_trace_atom),
            format!("truth_u8={}", self.render_truth() as u8),
        ];
        lines.into_iter().take(rows as usize).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::StageFTraceLink;
    use crate::repl::latency::p95_ms;

    fn trace(atom: u16) -> StageFTraceLink {
        StageFTraceLink::new([0x67; 32], atom, 467)
    }

    fn item(id: u64, kind: JobKind, state: JobState) -> JobRailItem {
        JobRailItem::new(id, kind, state, trace(467))
    }

    #[test]
    fn task_inbox_open_watch_detach_toggle_attachment() {
        let mut t = InboxTask::new(item(1, JobKind::Agent, JobState::Running), false);
        assert!(t.apply(TaskInboxAction::Open));
        assert!(t.attached);
        assert!(t.apply(TaskInboxAction::Detach));
        assert!(!t.attached);
        assert!(t.apply(TaskInboxAction::Watch));
        assert!(t.attached);
    }

    #[test]
    fn task_resume_only_from_paused() {
        let mut paused = InboxTask::new(item(1, JobKind::Tool, JobState::Paused), true);
        assert!(paused.apply(TaskInboxAction::Resume));
        assert_eq!(paused.item.state, JobState::Running);
        // resuming a running task is a no-op
        let mut running = InboxTask::new(item(2, JobKind::Tool, JobState::Running), true);
        assert!(!running.apply(TaskInboxAction::Resume));
    }

    #[test]
    fn task_cancel_kills_live_but_not_terminal() {
        let mut live = InboxTask::new(item(1, JobKind::Eval, JobState::Running), true);
        assert!(live.apply(TaskInboxAction::Cancel));
        assert_eq!(live.item.state, JobState::Killed);
        assert!(!live.item.killable);
        // cancelling a terminal task is a no-op (no zombie resurrection)
        assert!(!live.apply(TaskInboxAction::Cancel));
    }

    #[test]
    fn session_export_import_round_trip_and_mismatch() {
        let tasks = [
            InboxTask::new(item(1, JobKind::Agent, JobState::Running), true),
            InboxTask::new(item(2, JobKind::Session, JobState::Paused), false),
        ];
        let snap = SessionSnapshot::export(&tasks);
        assert_eq!(snap.task_count, 2);
        assert!(snap.verify_import(&tasks));
        // A changed task set fails the round-trip (lossy import surfaced).
        let changed = [InboxTask::new(
            item(1, JobKind::Agent, JobState::Running),
            true,
        )];
        assert!(!snap.verify_import(&changed));
    }

    #[test]
    fn dashboard_counts_states_and_kinds() {
        let items = [
            item(1, JobKind::Agent, JobState::Running),
            item(2, JobKind::Eval, JobState::Failed),
            item(3, JobKind::Train, JobState::Pending),
            item(4, JobKind::Gas, JobState::Running),
            item(5, JobKind::Skill, JobState::WaitingApproval),
        ];
        let d = JobsDashboard::project(&items, 0, false, 1_000);
        assert_eq!(d.total, 5);
        assert_eq!(d.live, 4); // Running, Pending, Running, WaitingApproval (Failed is terminal)
        assert_eq!(d.failed, 1);
        assert_eq!(d.waiting_approval, 1);
        assert_eq!(d.train_locked, 1);
        assert!(d.gas_running);
        assert!(d.eval_failed);
    }

    #[test]
    fn train_jobs_surface_locked_count_dashboard_only() {
        let items = [
            item(1, JobKind::Train, JobState::Pending),
            item(2, JobKind::Train, JobState::Running),
        ];
        let d = JobsDashboard::project(&items, 0, false, 0);
        // Train jobs are dashboard/doctor only; the count is visible.
        assert_eq!(d.train_locked, 2);
    }

    #[test]
    fn eval_failure_is_red_no_false_green() {
        let items = [item(1, JobKind::Eval, JobState::Failed)];
        let d = JobsDashboard::project(&items, 0, false, 0);
        assert_eq!(d.render_truth(), RenderTruth::Red);
    }

    #[test]
    fn measure_stale_and_telegram_stale_are_yellow() {
        let stale_measure = [item(1, JobKind::Measure, JobState::Paused)];
        let d = JobsDashboard::project(&stale_measure, 0, false, 0);
        assert!(d.measure_stale);
        assert_eq!(d.render_truth(), RenderTruth::Yellow);

        let clean = [item(1, JobKind::Agent, JobState::Running)];
        let d2 = JobsDashboard::project(&clean, 0, true, 0);
        assert!(d2.telegram_stale);
        assert_eq!(d2.render_truth(), RenderTruth::Yellow);
    }

    #[test]
    fn approval_pending_is_yellow() {
        let clean = [item(1, JobKind::Agent, JobState::Running)];
        let d = JobsDashboard::project(&clean, 3, false, 0);
        assert_eq!(d.pending_approvals, 3);
        assert_eq!(d.render_truth(), RenderTruth::Yellow);
    }

    #[test]
    fn clean_running_dashboard_is_green() {
        let items = [
            item(1, JobKind::Agent, JobState::Running),
            item(2, JobKind::Tool, JobState::Passed),
        ];
        let d = JobsDashboard::project(&items, 0, false, 5_000);
        assert_eq!(d.render_truth(), RenderTruth::Green);
    }

    #[test]
    fn render_is_bounded_and_no_commerce() {
        let items = [item(1, JobKind::Gas, JobState::Running)];
        let d = JobsDashboard::project(&items, 0, false, 9);
        assert!(d.render(3).len() <= 3);
        assert!(d.render(64).len() <= 13);
        const COMMERCE: &[&str] = &[
            "price", "pay", "buy", "sell", "checkout", "refund", "fee", "$",
        ];
        for line in d.render(64) {
            for t in COMMERCE {
                assert!(!line.contains(*t), "commerce token {t} leaked: {line}");
            }
        }
    }

    #[test]
    fn refresh_p95_within_250ms() {
        let items = [
            item(1, JobKind::Agent, JobState::Running),
            item(2, JobKind::Eval, JobState::Passed),
            item(3, JobKind::Gas, JobState::Pending),
        ];
        let mut samples = Vec::with_capacity(256);
        for _ in 0..256 {
            let t = std::time::Instant::now();
            let d = JobsDashboard::project(&items, 1, false, 1_000);
            let lines = d.render(32);
            std::hint::black_box(&lines);
            samples.push(t.elapsed().as_nanos() as u64);
        }
        let p95 = p95_ms(&samples) / 1_000_000;
        assert!(
            p95 <= 250,
            "jobs dashboard refresh p95 {p95}ms exceeds 250ms"
        );
    }
}
