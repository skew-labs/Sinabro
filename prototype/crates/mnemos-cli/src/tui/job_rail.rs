//! §4.3 cockpit job rail (atom #419 F.2.2).
//!
//! Lists every running tool/skill/train/eval/gas job with its kind, state,
//! killability, and trace id. Refresh is from local state only (no network on
//! the hot path). The core invariant is "no zombie job": a terminal job
//! (`Passed`/`Failed`/`Killed`/`RolledBack`) can never transition back to a live
//! state.

use crate::StageFTraceLink;

/// §4.3 — the kind of background job shown on the rail.
#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum JobKind {
    /// A bounded agent turn.
    Agent = 1,
    /// A tool adapter invocation.
    Tool = 2,
    /// A skill invocation.
    Skill = 3,
    /// A chain (read-only in Stage F) operation.
    Chain = 4,
    /// A gas dashboard / quota query.
    Gas = 5,
    /// A dataset control operation.
    Dataset = 6,
    /// A train-namespace doctor/prepare/dashboard job (never execution).
    Train = 7,
    /// An eval harness run.
    Eval = 8,
    /// A measurement-telemetry job.
    Measure = 9,
    /// A session operation.
    Session = 10,
    /// A notification delivery.
    Notification = 11,
}

/// §4.3 — the lifecycle state of a job.
#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum JobState {
    /// Admitted, not yet started.
    Pending = 1,
    /// Actively running.
    Running = 2,
    /// Blocked on a user approval.
    WaitingApproval = 3,
    /// Finished successfully (terminal).
    Passed = 4,
    /// Finished with failure (terminal).
    Failed = 5,
    /// Killed by the control rail (terminal).
    Killed = 6,
    /// Rolled back after failure (terminal).
    RolledBack = 7,
    /// Paused (live; resumable).
    Paused = 8,
}

impl JobState {
    /// Whether this is a terminal state (no further transition allowed).
    #[must_use]
    pub const fn is_terminal(self) -> bool {
        matches!(
            self,
            Self::Passed | Self::Failed | Self::Killed | Self::RolledBack
        )
    }

    /// Whether this is a live state (the job may still be killed/resumed).
    #[must_use]
    pub const fn is_live(self) -> bool {
        !self.is_terminal()
    }
}

/// §4.3 — one row of the job rail.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct JobRailItem {
    /// Stable job id.
    pub job_id_u64: u64,
    /// What kind of job this is.
    pub kind: JobKind,
    /// Current lifecycle state.
    pub state: JobState,
    /// Whether the job can be killed right now (true iff live).
    pub killable: bool,
    /// Trace link binding this job to its command trace + atom + gate.
    pub trace: StageFTraceLink,
}

impl JobRailItem {
    /// Create a rail item; `killable` is derived from the state (live ⇒ true).
    #[must_use]
    pub const fn new(
        job_id_u64: u64,
        kind: JobKind,
        state: JobState,
        trace: StageFTraceLink,
    ) -> Self {
        Self {
            job_id_u64,
            kind,
            state,
            killable: state.is_live(),
            trace,
        }
    }

    /// Attempt to move this job to `next`. Returns `false` (no-op) if the
    /// current state is terminal — the no-zombie-job invariant — otherwise
    /// applies the transition and recomputes `killable`.
    pub const fn try_transition(&mut self, next: JobState) -> bool {
        if self.state.is_terminal() {
            return false;
        }
        self.state = next;
        self.killable = next.is_live();
        true
    }
}

/// §4.3 — the job rail: a bounded, locally-refreshed list of jobs.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct JobRail {
    items: Vec<JobRailItem>,
}

impl JobRail {
    /// An empty rail.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Append a job row.
    pub fn push(&mut self, item: JobRailItem) {
        self.items.push(item);
    }

    /// The rows, in insertion order.
    #[must_use]
    pub fn items(&self) -> &[JobRailItem] {
        &self.items
    }

    /// Number of currently-live (killable) jobs.
    #[must_use]
    pub fn live_count(&self) -> usize {
        self.items.iter().filter(|i| i.state.is_live()).count()
    }

    /// Transition the job with `job_id_u64` to `next`. Returns `false` if the
    /// job is not found or if it is a terminal (zombie) job.
    pub fn transition(&mut self, job_id_u64: u64, next: JobState) -> bool {
        for it in &mut self.items {
            if it.job_id_u64 == job_id_u64 {
                return it.try_transition(next);
            }
        }
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::StageFTraceLink;

    fn trace(atom: u16) -> StageFTraceLink {
        StageFTraceLink::new([7u8; 32], atom, 419)
    }

    #[test]
    fn live_jobs_are_killable_terminal_are_not() {
        let running = JobRailItem::new(1, JobKind::Tool, JobState::Running, trace(419));
        assert!(running.killable);
        let passed = JobRailItem::new(2, JobKind::Eval, JobState::Passed, trace(419));
        assert!(!passed.killable);
        let waiting = JobRailItem::new(3, JobKind::Skill, JobState::WaitingApproval, trace(419));
        assert!(waiting.killable);
    }

    #[test]
    fn zombie_job_transition_is_denied() {
        let mut killed = JobRailItem::new(9, JobKind::Train, JobState::Killed, trace(419));
        let ok = killed.try_transition(JobState::Running);
        assert!(!ok, "a killed job must not resurrect");
        assert_eq!(killed.state, JobState::Killed);
        assert!(!killed.killable);
    }

    #[test]
    fn live_job_transitions_recompute_killability() {
        let mut j = JobRailItem::new(4, JobKind::Agent, JobState::Running, trace(419));
        assert!(j.try_transition(JobState::Failed));
        assert_eq!(j.state, JobState::Failed);
        assert!(!j.killable);
        // now terminal -> further transition denied
        assert!(!j.try_transition(JobState::Running));
    }

    #[test]
    fn rail_live_count_and_lookup_transition() {
        let mut rail = JobRail::new();
        rail.push(JobRailItem::new(
            1,
            JobKind::Tool,
            JobState::Running,
            trace(419),
        ));
        rail.push(JobRailItem::new(
            2,
            JobKind::Eval,
            JobState::Passed,
            trace(419),
        ));
        rail.push(JobRailItem::new(
            3,
            JobKind::Gas,
            JobState::Pending,
            trace(419),
        ));
        assert_eq!(rail.live_count(), 2);
        assert!(rail.transition(3, JobState::Killed));
        assert_eq!(rail.live_count(), 1);
        // unknown id
        assert!(!rail.transition(999, JobState::Running));
        // zombie on a now-terminal id
        assert!(!rail.transition(2, JobState::Running));
    }
}
