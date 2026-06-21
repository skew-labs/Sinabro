//! Operational task/session inbox integration (atom #510 · G.2.4).
//!
//! Provider consult, audit scan, memory replay, evidence pack, Telegram
//! notification, and Stage H handoff jobs all share ONE task/session inbox: a
//! single [`JobRail`] keyed under one session id, so they share the same id space
//! and checkpointable state (`G-G-CONTROL-EXPRESS`). Each Stage-G operational job
//! class maps onto a canonical [`JobKind`] — Stage G adds no new job-kind truth.
//!
//! Reuse (no reinvention): the rail and its no-zombie transitions are the
//! canonical [`crate::tui::job_rail`]; the inbox affordances and the
//! export/import round-trip digest are the canonical
//! [`crate::tui::jobs_tab::InboxTask`] / [`crate::tui::jobs_tab::SessionSnapshot`].
//! This module performs no live action.

use crate::StageFTraceLink;
use crate::tui::job_rail::{JobKind, JobRail, JobRailItem, JobState};
use crate::tui::jobs_tab::{InboxTask, SessionSnapshot};

/// The Stage-G operational job classes that share one task/session inbox. Each
/// maps onto a canonical [`JobKind`] (Stage G mints no new job-kind truth).
#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OperationalJobClass {
    /// A bounded provider consult.
    ProviderConsult = 1,
    /// A local audit scan.
    AuditScan = 2,
    /// A memory replay.
    MemoryReplay = 3,
    /// An evidence pack.
    EvidencePack = 4,
    /// A Telegram notification.
    TelegramNotify = 5,
    /// A Stage H training handoff (doctor/prepare only; never execution).
    StageHHandoff = 6,
}

impl OperationalJobClass {
    /// Every operational job class, in discriminant order.
    pub const ALL: [OperationalJobClass; 6] = [
        OperationalJobClass::ProviderConsult,
        OperationalJobClass::AuditScan,
        OperationalJobClass::MemoryReplay,
        OperationalJobClass::EvidencePack,
        OperationalJobClass::TelegramNotify,
        OperationalJobClass::StageHHandoff,
    ];

    /// The stable `u8` discriminant.
    #[must_use]
    pub const fn as_u8(self) -> u8 {
        self as u8
    }

    /// The canonical [`JobKind`] this operational class is admitted as.
    #[must_use]
    pub const fn job_kind(self) -> JobKind {
        match self {
            Self::ProviderConsult => JobKind::Agent,
            Self::AuditScan => JobKind::Eval,
            Self::MemoryReplay => JobKind::Dataset,
            Self::EvidencePack => JobKind::Measure,
            Self::TelegramNotify => JobKind::Notification,
            Self::StageHHandoff => JobKind::Train,
        }
    }
}

/// One operational task/session inbox: a shared [`JobRail`] keyed under a single
/// session id. Provider / audit / memory / evidence / notification / handoff jobs
/// share the same id space and checkpointable state.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct OperationalInbox {
    rail: JobRail,
    session_id_u64: u64,
}

impl OperationalInbox {
    /// A new, empty inbox for one session.
    #[must_use]
    pub fn new(session_id_u64: u64) -> Self {
        Self {
            rail: JobRail::new(),
            session_id_u64,
        }
    }

    /// The session id every job in this inbox shares.
    #[must_use]
    pub const fn session_id(&self) -> u64 {
        self.session_id_u64
    }

    /// Admit an operational job into the shared inbox, mapping its class to a
    /// canonical [`JobKind`]. Returns the created row (its trace is preserved
    /// verbatim).
    pub fn admit(
        &mut self,
        job_id_u64: u64,
        class: OperationalJobClass,
        state: JobState,
        trace: StageFTraceLink,
    ) -> JobRailItem {
        let item = JobRailItem::new(job_id_u64, class.job_kind(), state, trace);
        self.rail.push(item);
        item
    }

    /// The rows, in admission order.
    #[must_use]
    pub fn list(&self) -> &[JobRailItem] {
        self.rail.items()
    }

    /// Number of currently-live (killable) jobs.
    #[must_use]
    pub fn live_count(&self) -> usize {
        self.rail.live_count()
    }

    /// Pause a running task (`Running` -> `Paused`). Returns `false` if the job is
    /// not found, is not running, or is terminal (the canonical rail's no-zombie
    /// law refuses a terminal transition — a killed job can never be paused back to
    /// life). Symmetric with [`resume`](Self::resume) / [`cancel`](Self::cancel).
    pub fn pause(&mut self, job_id_u64: u64) -> bool {
        let is_running = self
            .rail
            .items()
            .iter()
            .any(|i| i.job_id_u64 == job_id_u64 && matches!(i.state, JobState::Running));
        if !is_running {
            return false;
        }
        self.rail.transition(job_id_u64, JobState::Paused)
    }

    /// Resume a paused task (`Paused` -> `Running`). Returns `false` if the job is
    /// not found, is not paused, or is terminal (no zombie resurrection).
    pub fn resume(&mut self, job_id_u64: u64) -> bool {
        let is_paused = self
            .rail
            .items()
            .iter()
            .any(|i| i.job_id_u64 == job_id_u64 && matches!(i.state, JobState::Paused));
        if !is_paused {
            return false;
        }
        self.rail.transition(job_id_u64, JobState::Running)
    }

    /// Cancel a task (-> `Killed`). Returns `false` if the job is not found or is
    /// already terminal (the no-zombie invariant is owned by the canonical rail).
    pub fn cancel(&mut self, job_id_u64: u64) -> bool {
        self.rail.transition(job_id_u64, JobState::Killed)
    }

    /// Checkpoint the inbox into a [`SessionSnapshot`] (an order-sensitive content
    /// digest), reusing the canonical session export. The round-trip can be
    /// verified with [`SessionSnapshot::verify_import`].
    #[must_use]
    pub fn checkpoint(&self) -> SessionSnapshot {
        let tasks: Vec<InboxTask> = self
            .rail
            .items()
            .iter()
            .map(|&it| InboxTask::new(it, true))
            .collect();
        SessionSnapshot::export(&tasks)
    }
}

/// Which lane a generation is admitted on. The interactive hot path is prioritized
/// over background work (`interactive_first`).
#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AdmissionLane {
    /// The user's interactive hot path — prioritized; may use a reserved slot.
    Interactive = 1,
    /// Background work — admitted only while a non-reserved slot remains.
    Background = 2,
}

/// Bounded-concurrency admission control for full-job generations (#619). Caps the
/// number of concurrent live generations and reserves slots for the interactive
/// hot path, so background work can never starve the interactive lane
/// (`interactive_first`) and concurrency can never run away (over-admission past
/// the cap is rejected). The decision is pure arithmetic; control commands still
/// ride the express rail — admission bounds new work, never the STOP path.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AdmissionControl {
    max_concurrent_u32: u32,
    interactive_reserved_u32: u32,
    live_u32: u32,
}

impl AdmissionControl {
    /// A new controller: at most `max_concurrent_u32` live generations, with
    /// `interactive_reserved_u32` of those slots reserved for the interactive hot
    /// path (clamped to the max).
    #[must_use]
    pub const fn new(max_concurrent_u32: u32, interactive_reserved_u32: u32) -> Self {
        let interactive_reserved_u32 = if interactive_reserved_u32 > max_concurrent_u32 {
            max_concurrent_u32
        } else {
            interactive_reserved_u32
        };
        Self {
            max_concurrent_u32,
            interactive_reserved_u32,
            live_u32: 0,
        }
    }

    /// Live (admitted, not yet released) generation count.
    #[must_use]
    pub const fn live(&self) -> u32 {
        self.live_u32
    }

    /// Whether the hard concurrency cap is reached (no lane may admit).
    #[must_use]
    pub const fn at_capacity(&self) -> bool {
        self.live_u32 >= self.max_concurrent_u32
    }

    /// Try to admit a generation on `lane`. Fail-closed: past the hard cap both
    /// lanes are rejected (over-admission); a `Background` job is also rejected once
    /// the non-reserved slots are full, so the reserved slots stay available for the
    /// interactive hot path (`interactive_first`). Returns whether admitted.
    pub const fn try_admit(&mut self, lane: AdmissionLane) -> bool {
        if self.live_u32 >= self.max_concurrent_u32 {
            return false;
        }
        if matches!(lane, AdmissionLane::Background) {
            let background_ceiling = self
                .max_concurrent_u32
                .saturating_sub(self.interactive_reserved_u32);
            if self.live_u32 >= background_ceiling {
                return false;
            }
        }
        self.live_u32 = self.live_u32.saturating_add(1);
        true
    }

    /// Release a completed generation's slot (saturating at zero).
    pub const fn release(&mut self) {
        self.live_u32 = self.live_u32.saturating_sub(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::repl::latency::p95_ms;

    fn trace(atom: u16) -> StageFTraceLink {
        StageFTraceLink::new([0x51; 32], atom, 0)
    }

    #[test]
    fn create_task_maps_to_canonical_kind() {
        let mut inbox = OperationalInbox::new(1);
        inbox.admit(
            10,
            OperationalJobClass::ProviderConsult,
            JobState::Pending,
            trace(510),
        );
        assert_eq!(inbox.list().len(), 1);
        assert_eq!(inbox.list()[0].kind, JobKind::Agent);
        assert_eq!(inbox.session_id(), 1);
    }

    #[test]
    fn resume_session_only_from_paused() {
        let mut inbox = OperationalInbox::new(2);
        inbox.admit(
            20,
            OperationalJobClass::AuditScan,
            JobState::Paused,
            trace(510),
        );
        assert!(inbox.resume(20));
        let resumed = inbox
            .list()
            .iter()
            .find(|i| i.job_id_u64 == 20)
            .map(|i| i.state);
        assert_eq!(resumed, Some(JobState::Running));
        // Resuming a now-running task is a no-op.
        assert!(!inbox.resume(20));
        // Resuming an unknown id is a no-op.
        assert!(!inbox.resume(999));
    }

    #[test]
    fn pause_only_from_running_and_never_resurrects_terminal() {
        let mut inbox = OperationalInbox::new(11);
        inbox.admit(
            40,
            OperationalJobClass::ProviderConsult,
            JobState::Running,
            trace(510),
        );
        // Running -> Paused, then Paused -> Running round-trips.
        assert!(inbox.pause(40));
        assert!(inbox.resume(40));
        // Pausing an unknown id is a no-op.
        assert!(!inbox.pause(999));
        // A killed (terminal) job can never be paused back to life (no zombie).
        assert!(inbox.cancel(40));
        assert!(!inbox.pause(40));
    }

    #[test]
    fn list_reflects_all_admitted_classes() {
        let mut inbox = OperationalInbox::new(3);
        for (i, class) in OperationalJobClass::ALL.into_iter().enumerate() {
            inbox.admit(i as u64, class, JobState::Running, trace(510));
        }
        assert_eq!(inbox.list().len(), OperationalJobClass::ALL.len());
        assert_eq!(inbox.live_count(), OperationalJobClass::ALL.len());
    }

    #[test]
    fn cancel_kills_live_but_not_terminal() {
        let mut inbox = OperationalInbox::new(4);
        inbox.admit(
            30,
            OperationalJobClass::MemoryReplay,
            JobState::Running,
            trace(510),
        );
        assert!(inbox.cancel(30));
        let st = inbox
            .list()
            .iter()
            .find(|i| i.job_id_u64 == 30)
            .map(|i| i.state);
        assert_eq!(st, Some(JobState::Killed));
        // Cancelling a terminal job is a no-op (no zombie resurrection).
        assert!(!inbox.cancel(30));
    }

    #[test]
    fn checkpoint_round_trips_and_detects_loss() {
        let mut inbox = OperationalInbox::new(5);
        inbox.admit(
            1,
            OperationalJobClass::ProviderConsult,
            JobState::Running,
            trace(510),
        );
        inbox.admit(
            2,
            OperationalJobClass::EvidencePack,
            JobState::Paused,
            trace(510),
        );
        let snap = inbox.checkpoint();
        assert_eq!(snap.task_count, 2);
        let tasks: Vec<InboxTask> = inbox
            .list()
            .iter()
            .map(|&it| InboxTask::new(it, true))
            .collect();
        assert!(snap.verify_import(&tasks));
        // A lossy reload (fewer tasks) is detected.
        let lossy: Vec<InboxTask> = tasks.iter().take(1).copied().collect();
        assert!(!snap.verify_import(&lossy));
    }

    #[test]
    fn trace_id_equality_preserved_through_inbox() {
        let t = trace(510);
        let mut inbox = OperationalInbox::new(7);
        let returned = inbox.admit(
            1,
            OperationalJobClass::ProviderConsult,
            JobState::Running,
            t,
        );
        // The admitted row, the returned item, and the listed row carry the SAME trace id.
        assert_eq!(returned.trace, t);
        assert_eq!(inbox.list()[0].trace, t);
        assert_eq!(inbox.list()[0].trace.stage_f_atom_u16, 510);
    }

    #[test]
    fn admission_bounds_concurrency_and_rejects_over_admission() {
        let mut a = AdmissionControl::new(3, 1); // 3 max, 1 reserved for interactive
        // background may fill the 2 non-reserved slots
        assert!(a.try_admit(AdmissionLane::Background));
        assert!(a.try_admit(AdmissionLane::Background));
        assert_eq!(a.live(), 2);
        // a 3rd background is rejected — the reserved slot is interactive-only
        assert!(
            !a.try_admit(AdmissionLane::Background),
            "background may not take the reserved interactive slot"
        );
        // interactive may use the reserved slot
        assert!(a.try_admit(AdmissionLane::Interactive));
        assert_eq!(a.live(), 3);
        assert!(a.at_capacity());
        // over the hard cap, EVEN interactive is rejected (no runaway concurrency)
        assert!(
            !a.try_admit(AdmissionLane::Interactive),
            "over-admission past the cap is rejected"
        );
        // releasing frees a slot
        a.release();
        assert_eq!(a.live(), 2);
        assert!(a.try_admit(AdmissionLane::Interactive));
    }

    #[test]
    fn interactive_prioritized_over_background() {
        let mut a = AdmissionControl::new(2, 1); // 1 non-reserved + 1 reserved
        assert!(a.try_admit(AdmissionLane::Background)); // takes the 1 non-reserved slot
        // background now blocked: only the reserved interactive slot remains
        assert!(!a.try_admit(AdmissionLane::Background));
        // interactive still gets in (its reserved slot)
        assert!(a.try_admit(AdmissionLane::Interactive));
        assert!(a.at_capacity());
    }

    #[test]
    fn control_still_express_at_admission_capacity() {
        // admission may be saturated, but a STOP control still bypasses (express).
        let mut a = AdmissionControl::new(1, 0);
        assert!(a.try_admit(AdmissionLane::Background));
        assert!(a.at_capacity(), "admission saturated");
        // the express control rail is independent of admission: it still acks + bypasses
        let mut r = crate::daemon::control_express::ControlExpressRouter::new();
        let ack = r.ack(
            crate::daemon::control_express::ExpressClass::Kill,
            crate::daemon::control_express::BackgroundQueueDepths::saturated(10_000),
        );
        assert!(
            ack.bypassed_queue,
            "control still bypasses even at admission capacity"
        );
        assert!(!ack.live_action);
    }

    #[test]
    fn admission_decision_p95_within_16ms() {
        let mut samples = Vec::with_capacity(256);
        for _ in 0..256 {
            let mut a = AdmissionControl::new(8, 2);
            let t = std::time::Instant::now();
            let ok = a.try_admit(AdmissionLane::Interactive);
            std::hint::black_box(&ok);
            samples.push(t.elapsed().as_nanos() as u64);
        }
        let p95 = p95_ms(&samples) / 1_000_000;
        assert!(p95 <= 16, "admission decision p95 {p95}ms exceeds 16ms");
    }

    #[test]
    fn list_p95_within_50ms_cached() {
        let mut inbox = OperationalInbox::new(8);
        for i in 0..32u64 {
            inbox.admit(
                i,
                OperationalJobClass::ProviderConsult,
                JobState::Running,
                trace(510),
            );
        }
        let mut samples = Vec::with_capacity(256);
        for _ in 0..256 {
            let t = std::time::Instant::now();
            let n = inbox.list().len();
            std::hint::black_box(&n);
            samples.push(t.elapsed().as_nanos() as u64);
        }
        let p95 = p95_ms(&samples) / 1_000_000;
        assert!(p95 <= 50, "operational inbox list p95 {p95}ms exceeds 50ms");
    }
}
