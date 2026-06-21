//! Async runtime supervisor for MNEMOS (atom #3 · A.0.3).
//!
//! # Why this madness
//!
//! Phase 0 runs every async task — agent turn, tool dispatch, walrus PUT/GET,
//! Sui dry-run, wallet signing, memory persist, system housekeeping — under a
//! single fixed-capacity supervisor. No locks, no heap allocations on the hot
//! path. The supervisor is a `[RuntimeTaskSlot; CAP]` array whose every mutable
//! field is an `AtomicU8` / `AtomicU32` / `AtomicU64`, so contention reduces to
//! a single `compare_exchange` per state transition.
//!
//! The security spine is *first-writer-wins everywhere*: a doubled
//! `finish`/`cancel`/`shutdown` cannot rewrite history, and a stale lease that
//! points at a slot already reused by a fresh task is silently rejected. The
//! second guarantee is *no infinite loops by construction*
//! (`MNEMOS_ATOM_PLAN.md` §10.1): once an outside-the-process boundary has been
//! crossed and the outcome is unknown, retry is forbidden at the type level —
//! [`runtime_retry_allowed`] returns `false` for any input whose
//! `boundary_state` is [`RuntimeBoundaryState::UnknownAfterBoundary`], so a
//! caller cannot construct a retry decision that violates the invariant even
//! with a deliberately misconfigured [`RuntimeRetryPolicy`].
//!
//! The `RuntimeSupervisor::new` constructor stamps each instance with a
//! process-unique `supervisor_id_u32`, so a [`RuntimeTaskLease`] minted by one
//! supervisor cannot operate on slots in a different supervisor — even if a
//! later supervisor happens to land on the same memory address or the same
//! slot index. Combined with per-slot `task_id` checking, this gives us
//! complete stale-lease isolation across both slot reuse within a supervisor
//! and supervisor reuse across the process.

use core::sync::atomic::{AtomicU8, AtomicU32, AtomicU64, Ordering};

use crate::error::RedactionClass;

// ---------------------------------------------------------------------------
// Public enums — 11 #[repr(u8)] variants per ATOM_PLAN §4.A A.runtime.
// ---------------------------------------------------------------------------

/// What MNEMOS subsystem a supervised task belongs to. Stable one-byte tag
/// used by metrics, audit logs and retry policy decisions.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum RuntimeTaskKind {
    /// An agent turn / tool loop iteration.
    Agent = 1,
    /// A single tool call dispatched by the agent.
    Tool = 2,
    /// A memory chunk store / persist operation.
    Memory = 3,
    /// A walrus codec / transport operation.
    Walrus = 4,
    /// A Sui / Move on-chain (or dry-run) call.
    Sui = 5,
    /// A wallet keystore / signing operation.
    Wallet = 6,
    /// Internal housekeeping (drain, log flush, shutdown wiring).
    System = 7,
}

/// Lifecycle status of a slot occupied by a registered task.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum RuntimeTaskStatus {
    /// Slot has been claimed but the worker hasn't called `mark_running` yet.
    Registered = 1,
    /// The worker has called `mark_running` and is actively executing.
    Running = 2,
    /// A `request_cancel` won the first-writer-wins race; worker should stop.
    CancelRequested = 3,
    /// `finish` has been recorded; the slot waits for `release` to free it.
    Finished = 4,
}

/// Why a task was cancelled. `None=0` lets the slot field stay zero-initialized
/// and lets the first-writer-wins `compare_exchange` use `0` as the sentinel.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum RuntimeCancelReason {
    /// No cancellation recorded (sentinel for un-cancelled tasks).
    None = 0,
    /// An operator-issued cancellation.
    Operator = 1,
    /// Cancelled as a side effect of supervisor shutdown.
    Shutdown = 2,
    /// Budget exhaustion (tokens, gas, cycles, bytes, …).
    Budget = 3,
    /// Watchdog / deadline timeout.
    Timeout = 4,
    /// A newer task supersedes this one (idempotency / dedup).
    Superseded = 5,
}

/// Where the task is relative to an external (out-of-process) side effect.
/// `UnknownAfterBoundary` is the *type-level* lock that forbids automatic
/// retry: a task that has crossed an external boundary and not learned the
/// outcome cannot be retried safely under any policy.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum RuntimeBoundaryState {
    /// The task hasn't begun executing yet.
    NotStarted = 1,
    /// The task is executing but has not yet performed an external side effect.
    BeforeExternalBoundary = 2,
    /// The task crossed an external boundary; the world-state is now unknown.
    UnknownAfterBoundary = 3,
}

/// Terminal join outcome captured when a task finishes (or is forced finished
/// by drain timeout). Distinct values for timeout / panic / cancel / domain
/// error so policy and audit can fork on the exact terminal condition.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum RuntimeJoinOutcome {
    /// No join outcome has been recorded yet (sentinel; `0` for zero-init).
    NotJoined = 0,
    /// The task ran to completion successfully.
    Completed = 1,
    /// The task returned a domain-level error (no boundary corruption).
    DomainError = 2,
    /// The task was cancelled before `mark_running` was ever called.
    CancelledBeforeStart = 3,
    /// The task was cancelled while running but before any external boundary.
    CancelledBeforeBoundary = 4,
    /// The task was cancelled after an external boundary; outcome is unknown.
    CancelledAfterBoundaryUnknown = 5,
    /// A drain/watchdog deadline elapsed before the task joined.
    JoinTimeout = 6,
    /// The task's join handle observed a panic.
    JoinPanic = 7,
    /// The task's join handle reported a clean cancel (e.g. tokio abort).
    JoinCancelled = 8,
}

/// Policy declaring whether a failed task may be retried. Combined with the
/// observed `boundary_state` / `join_outcome` by [`runtime_retry_allowed`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum RuntimeRetryPolicy {
    /// Never retry, even on a clean cancel before any boundary.
    Never = 1,
    /// Retry only if no external boundary was crossed (idempotent prefix).
    IdempotentNoBoundary = 2,
    /// Retry requires an explicit human-issued action (no auto-retry).
    ManualOnly = 3,
}

/// Process-wide supervisor lifecycle. Monotonically advances through
/// `Accepting → ShutdownRequested → Draining → (Exited | DrainTimedOut)`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum RuntimeShutdownState {
    /// Normal operation; `register` is allowed.
    Accepting = 1,
    /// `request_shutdown` was accepted; live tasks have been signalled.
    ShutdownRequested = 2,
    /// At least one drain snapshot observed live work; drain is in progress.
    Draining = 3,
    /// The drain deadline elapsed; the supervisor recorded a hard timeout.
    DrainTimedOut = 4,
    /// All live tasks finished and the supervisor reached a clean exit.
    Exited = 5,
}

/// Result of a `request_shutdown` call.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum RuntimeShutdownRequestResult {
    /// This call won the CAS and was recorded as the shutdown request.
    Requested = 1,
    /// A prior call already requested shutdown; the deadline was not extended.
    AlreadyRequested = 2,
    /// A drain snapshot already advanced the state to `Draining`.
    AlreadyDraining = 3,
    /// The supervisor already recorded a hard drain timeout.
    AlreadyTimedOut = 4,
    /// The supervisor already exited cleanly.
    AlreadyExited = 5,
}

/// Reason a `register` call failed. Plain one-byte tag (no `MnemosError`
/// allocation needed for the hot register path).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum RuntimeRegisterError {
    /// All `CAP` slots are occupied; no fresh `task_id` was minted.
    CapacityExceeded = 1,
    /// `CAP` exceeds `u16::MAX`, so the slot index cannot fit in
    /// [`RuntimeTaskLease::slot_u16`]. The supervisor refuses to register.
    SlotIndexTooWide = 2,
    /// Shutdown has been requested; the supervisor no longer accepts work.
    ShutdownRequested = 3,
}

/// Result of a `request_cancel` call. Distinct from `JoinOutcome`: this
/// describes the *intent* the cancel call recorded, not the terminal outcome.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum RuntimeCancelResult {
    /// Cancel was recorded before the worker ever marked itself running.
    RequestedBeforeStart = 1,
    /// Cancel was recorded while running but before any external boundary.
    RequestedBeforeBoundary = 2,
    /// Cancel was recorded after an external boundary; outcome is unknown.
    RequestedAfterBoundaryUnknown = 3,
    /// A prior cancel already won the first-writer-wins race.
    AlreadyRequested = 4,
    /// The task already reported `finish`; the cancel call had no effect.
    AlreadyFinished = 5,
    /// The lease does not match the slot's current task (stale lease).
    StaleTask = 6,
}

/// Result of a `release` call.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum RuntimeReleaseResult {
    /// Slot transitioned from `Finished` to free; the lease was the live owner.
    Released = 1,
    /// Slot was already free before this call; nothing to release.
    AlreadyFree = 2,
    /// The lease does not match the slot's current task (stale lease).
    StaleTask = 3,
    /// The slot is still in `Registered` / `Running` / `CancelRequested`.
    NotFinished = 4,
}

// ---------------------------------------------------------------------------
// Newtype identifiers (#[repr(transparent)]).
// ---------------------------------------------------------------------------

/// Process-monotonic identifier for a supervised task. `FIRST` is the value
/// minted by the very first `register` call on a fresh supervisor.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash, Ord, PartialOrd)]
#[repr(transparent)]
pub struct RuntimeTaskId(u64);

impl RuntimeTaskId {
    /// The first valid task id. `0` is reserved as the "slot is free" sentinel.
    pub const FIRST: Self = Self(1);

    /// Inner numeric value (stable wire/log shape).
    #[inline]
    #[must_use]
    pub const fn get(self) -> u64 {
        self.0
    }
}

/// Retry attempt counter attached to a registered task. `FIRST` is the value
/// passed when a task is being attempted for the first time.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash, Ord, PartialOrd)]
#[repr(transparent)]
pub struct RuntimeAttempt(u8);

impl RuntimeAttempt {
    /// The first attempt value (attempt counter is 1-based).
    pub const FIRST: Self = Self(1);

    /// Construct from a raw `u8`. No validation: callers are responsible for
    /// keeping the value monotone across retries.
    #[inline]
    #[must_use]
    pub const fn from_u8(value: u8) -> Self {
        Self(value)
    }

    /// Inner numeric value.
    #[inline]
    #[must_use]
    pub const fn get(self) -> u8 {
        self.0
    }
}

// ---------------------------------------------------------------------------
// Lease / Report / DrainReport.
// ---------------------------------------------------------------------------

/// Handle handed back by `register`. Three values pin the lease to one
/// (supervisor, slot, task) triple: a stale lease — for example one whose
/// slot has been released and reused, or one minted by a different supervisor
/// — is silently rejected by every method that takes a lease.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RuntimeTaskLease {
    task_id: RuntimeTaskId,
    supervisor_id_u32: u32,
    slot_u16: u16,
}

impl RuntimeTaskLease {
    /// The task id minted for this lease.
    #[inline]
    #[must_use]
    pub const fn task_id(self) -> RuntimeTaskId {
        self.task_id
    }

    /// The supervisor instance this lease belongs to.
    #[inline]
    #[must_use]
    pub const fn supervisor_id_u32(self) -> u32 {
        self.supervisor_id_u32
    }

    /// The slot index this lease occupies inside its supervisor.
    #[inline]
    #[must_use]
    pub const fn slot_u16(self) -> u16 {
        self.slot_u16
    }
}

/// Bounded snapshot of a slot's lifecycle, returned by `finish` / `report` /
/// drain bookkeeping. Every field is a plain `Copy` value; no heap, no
/// dynamic strings, so it slots straight into the redacted log channel.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RuntimeTaskReport {
    /// What subsystem this task belongs to.
    pub task_kind: RuntimeTaskKind,
    /// Current lifecycle status of the slot.
    pub status: RuntimeTaskStatus,
    /// Reason recorded by a `request_cancel` (or `None` if not cancelled).
    pub cancel_reason: RuntimeCancelReason,
    /// Terminal join outcome (or `NotJoined` if still live / never joined).
    pub join_outcome: RuntimeJoinOutcome,
    /// Latest boundary-crossing state observed for this task.
    pub boundary_state: RuntimeBoundaryState,
    /// Redaction class for the safe log channel (Phase 0 = `PublicSafe`).
    pub redaction: RedactionClass,
    /// Id of the task this report describes.
    pub task_id: RuntimeTaskId,
    /// Attempt counter at the time of registration.
    pub attempt: RuntimeAttempt,
    /// Elapsed wall time (ms) recorded when the task finished, or `0` if live.
    pub elapsed_ms_u32: u32,
    /// Token estimate recorded when the task finished, or `0` if live.
    pub token_estimate_u32: u32,
}

/// Aggregated drain snapshot. Mirrors the supervisor's per-slot counters at a
/// single SeqCst observation point.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RuntimeDrainReport {
    /// Process-wide supervisor lifecycle at snapshot time.
    pub shutdown_state: RuntimeShutdownState,
    /// Number of slots in `Registered` / `Running` / `CancelRequested`.
    pub active_count_u16: u16,
    /// Number of slots in `Finished` (still occupied; waiting for `release`).
    pub finished_count_u16: u16,
    /// Number of slots whose `join_outcome` is `JoinTimeout`.
    pub timed_out_count_u16: u16,
    /// Number of slots whose `boundary_state` is `UnknownAfterBoundary`.
    pub unknown_after_boundary_count_u16: u16,
    /// Snapshot timestamp (ms since the drain clock started); set by caller.
    pub elapsed_ms_u32: u32,
}

// ---------------------------------------------------------------------------
// Private u8 mirror constants — single source of truth via `as u8` on the
// public `#[repr(u8)]` enums above.
// ---------------------------------------------------------------------------

const ACCEPTING_U8: u8 = RuntimeShutdownState::Accepting as u8;
const SHUTDOWN_REQUESTED_U8: u8 = RuntimeShutdownState::ShutdownRequested as u8;
const DRAINING_U8: u8 = RuntimeShutdownState::Draining as u8;
const DRAIN_TIMED_OUT_U8: u8 = RuntimeShutdownState::DrainTimedOut as u8;
const EXITED_U8: u8 = RuntimeShutdownState::Exited as u8;

const STATUS_FREE_U8: u8 = 0;
const REGISTERED_U8: u8 = RuntimeTaskStatus::Registered as u8;
const RUNNING_U8: u8 = RuntimeTaskStatus::Running as u8;
const CANCEL_REQUESTED_U8: u8 = RuntimeTaskStatus::CancelRequested as u8;
const FINISHED_U8: u8 = RuntimeTaskStatus::Finished as u8;

const CANCEL_REASON_NONE_U8: u8 = RuntimeCancelReason::None as u8;
const CANCEL_REASON_SHUTDOWN_U8: u8 = RuntimeCancelReason::Shutdown as u8;

const NOT_STARTED_U8: u8 = RuntimeBoundaryState::NotStarted as u8;
const BEFORE_EXTERNAL_BOUNDARY_U8: u8 = RuntimeBoundaryState::BeforeExternalBoundary as u8;
const UNKNOWN_AFTER_BOUNDARY_U8: u8 = RuntimeBoundaryState::UnknownAfterBoundary as u8;

const NOT_JOINED_U8: u8 = RuntimeJoinOutcome::NotJoined as u8;
const COMPLETED_U8: u8 = RuntimeJoinOutcome::Completed as u8;
const CANCELLED_BEFORE_START_U8: u8 = RuntimeJoinOutcome::CancelledBeforeStart as u8;
const CANCELLED_BEFORE_BOUNDARY_U8: u8 = RuntimeJoinOutcome::CancelledBeforeBoundary as u8;
const CANCELLED_AFTER_BOUNDARY_UNKNOWN_U8: u8 =
    RuntimeJoinOutcome::CancelledAfterBoundaryUnknown as u8;
const JOIN_TIMEOUT_U8: u8 = RuntimeJoinOutcome::JoinTimeout as u8;

// ---------------------------------------------------------------------------
// Private RuntimeTaskSlot.
// ---------------------------------------------------------------------------

/// A single supervised-task slot. All mutable state is in atomics so the slot
/// can be shared across threads without an outer lock.
///
/// SAFETY / invariants:
/// - `task_id_u64 == 0` ⇔ the slot is free; every other field is logically
///   irrelevant in that state.
/// - When `task_id_u64 != 0`, `status_u8` is one of the four public values.
/// - `cancel_reason_u8 == 0` (`None`) is the sentinel used by the cancel
///   first-writer-wins CAS.
/// - `join_outcome_u8 == 0` (`NotJoined`) is the sentinel used by the finish /
///   drain-timeout first-writer-wins CAS.
struct RuntimeTaskSlot {
    task_id_u64: AtomicU64,
    status_u8: AtomicU8,
    cancel_reason_u8: AtomicU8,
    boundary_state_u8: AtomicU8,
    join_outcome_u8: AtomicU8,
    kind_u8: AtomicU8,
    attempt_u8: AtomicU8,
    elapsed_ms_u32: AtomicU32,
    token_estimate_u32: AtomicU32,
}

impl RuntimeTaskSlot {
    const fn new() -> Self {
        Self {
            task_id_u64: AtomicU64::new(0),
            status_u8: AtomicU8::new(STATUS_FREE_U8),
            cancel_reason_u8: AtomicU8::new(CANCEL_REASON_NONE_U8),
            boundary_state_u8: AtomicU8::new(NOT_STARTED_U8),
            join_outcome_u8: AtomicU8::new(NOT_JOINED_U8),
            kind_u8: AtomicU8::new(RuntimeTaskKind::System as u8),
            attempt_u8: AtomicU8::new(RuntimeAttempt::FIRST.0),
            elapsed_ms_u32: AtomicU32::new(0),
            token_estimate_u32: AtomicU32::new(0),
        }
    }
}

// ---------------------------------------------------------------------------
// Public supervisor.
// ---------------------------------------------------------------------------

/// Fixed-capacity, lock-free, allocation-free supervisor for in-process async
/// tasks. `CAP` is the maximum number of concurrently-registered tasks and is
/// fixed at compile time; storage is a flat `[RuntimeTaskSlot; CAP]` inside
/// the struct itself (no `Vec`, no `Box`).
///
/// Every state transition is a single atomic CAS, and every CAS that races
/// resolves first-writer-wins. A stale [`RuntimeTaskLease`] — one whose
/// `supervisor_id_u32` does not match, or whose `task_id` no longer occupies
/// the slot it points at — is silently rejected by every method.
pub struct RuntimeSupervisor<const CAP: usize> {
    supervisor_id_u32: u32,
    shutdown_state_u8: AtomicU8,
    shutdown_timeout_ms_u32: AtomicU32,
    next_id_u64: AtomicU64,
    slots: [RuntimeTaskSlot; CAP],
}

/// Process-wide monotone counter handing out fresh `supervisor_id_u32` values.
/// Starts at `1` so `0` can stay reserved as an "unset" sentinel for future
/// debug surfaces (atom #2's redaction model never exposes raw values, so
/// this field is safe to leak in audit logs).
static NEXT_SUPERVISOR_ID: AtomicU32 = AtomicU32::new(1);

impl<const CAP: usize> Default for RuntimeSupervisor<CAP> {
    fn default() -> Self {
        Self::new()
    }
}

impl<const CAP: usize> RuntimeSupervisor<CAP> {
    /// Build a fresh supervisor with all `CAP` slots free, no shutdown
    /// requested, and a process-unique `supervisor_id_u32`.
    #[must_use]
    pub fn new() -> Self {
        // SAFETY: we initialise every slot eagerly via `[RuntimeTaskSlot; CAP]
        // from std::array::from_fn`, which calls the const constructor `CAP`
        // times. No `MaybeUninit` is needed.
        let slots = core::array::from_fn::<RuntimeTaskSlot, CAP, _>(|_| RuntimeTaskSlot::new());
        let id = NEXT_SUPERVISOR_ID.fetch_add(1, Ordering::SeqCst);
        Self {
            supervisor_id_u32: id,
            shutdown_state_u8: AtomicU8::new(ACCEPTING_U8),
            shutdown_timeout_ms_u32: AtomicU32::new(0),
            next_id_u64: AtomicU64::new(RuntimeTaskId::FIRST.0),
            slots,
        }
    }

    /// Process-unique id stamped on this supervisor at construction.
    #[inline]
    #[must_use]
    pub const fn supervisor_id_u32(&self) -> u32 {
        self.supervisor_id_u32
    }

    /// Try to claim a free slot. On success the returned lease pins the
    /// caller to one (supervisor, slot, task) triple for the rest of the
    /// task's lifecycle.
    pub fn register(
        &self,
        task_kind: RuntimeTaskKind,
        attempt: RuntimeAttempt,
    ) -> Result<RuntimeTaskLease, RuntimeRegisterError> {
        if CAP > u16::MAX as usize {
            return Err(RuntimeRegisterError::SlotIndexTooWide);
        }
        let state = self.shutdown_state_u8.load(Ordering::SeqCst);
        if state != ACCEPTING_U8 {
            return Err(RuntimeRegisterError::ShutdownRequested);
        }
        for (idx, slot) in self.slots.iter().enumerate() {
            if slot.task_id_u64.load(Ordering::SeqCst) != 0 {
                continue;
            }
            // Only mint a fresh id once we have a candidate slot. Lost races
            // discard the id without leaving an audit hole (the `task_id`
            // field is monotone but does not need to be contiguous).
            let fresh_id = self.next_id_u64.fetch_add(1, Ordering::SeqCst);
            match slot
                .task_id_u64
                .compare_exchange(0, fresh_id, Ordering::SeqCst, Ordering::SeqCst)
            {
                Ok(_) => {
                    slot.kind_u8.store(task_kind as u8, Ordering::SeqCst);
                    slot.attempt_u8.store(attempt.0, Ordering::SeqCst);
                    slot.cancel_reason_u8
                        .store(CANCEL_REASON_NONE_U8, Ordering::SeqCst);
                    slot.boundary_state_u8
                        .store(NOT_STARTED_U8, Ordering::SeqCst);
                    slot.join_outcome_u8.store(NOT_JOINED_U8, Ordering::SeqCst);
                    slot.elapsed_ms_u32.store(0, Ordering::SeqCst);
                    slot.token_estimate_u32.store(0, Ordering::SeqCst);
                    slot.status_u8.store(REGISTERED_U8, Ordering::SeqCst);
                    return Ok(RuntimeTaskLease {
                        task_id: RuntimeTaskId(fresh_id),
                        supervisor_id_u32: self.supervisor_id_u32,
                        slot_u16: idx as u16,
                    });
                }
                Err(_) => {
                    // Lost the race on this slot; keep scanning.
                    continue;
                }
            }
        }
        Err(RuntimeRegisterError::CapacityExceeded)
    }

    /// Ask the supervisor to begin shutdown. First call wins the CAS,
    /// records the deadline, and signals `Shutdown` cancel on every live slot.
    /// Subsequent calls return an `Already*` discriminant and do **not**
    /// extend the deadline.
    pub fn request_shutdown(&self, timeout_ms_u64: u64) -> RuntimeShutdownRequestResult {
        let timeout_u32 = clamp_to_u32(timeout_ms_u64);
        match self.shutdown_state_u8.compare_exchange(
            ACCEPTING_U8,
            SHUTDOWN_REQUESTED_U8,
            Ordering::SeqCst,
            Ordering::SeqCst,
        ) {
            Ok(_) => {
                self.shutdown_timeout_ms_u32
                    .store(timeout_u32, Ordering::SeqCst);
                // Signal Shutdown cancel on every live slot. First-writer-wins
                // on each slot so an already-cancelled task keeps its reason.
                for slot in self.slots.iter() {
                    if slot.task_id_u64.load(Ordering::SeqCst) == 0 {
                        continue;
                    }
                    let s = slot.status_u8.load(Ordering::SeqCst);
                    if s == FINISHED_U8 || s == STATUS_FREE_U8 {
                        continue;
                    }
                    let _ = slot.cancel_reason_u8.compare_exchange(
                        CANCEL_REASON_NONE_U8,
                        CANCEL_REASON_SHUTDOWN_U8,
                        Ordering::SeqCst,
                        Ordering::SeqCst,
                    );
                    let _ = slot.status_u8.compare_exchange(
                        REGISTERED_U8,
                        CANCEL_REQUESTED_U8,
                        Ordering::SeqCst,
                        Ordering::SeqCst,
                    );
                    let _ = slot.status_u8.compare_exchange(
                        RUNNING_U8,
                        CANCEL_REQUESTED_U8,
                        Ordering::SeqCst,
                        Ordering::SeqCst,
                    );
                }
                RuntimeShutdownRequestResult::Requested
            }
            Err(actual) => match actual {
                SHUTDOWN_REQUESTED_U8 => RuntimeShutdownRequestResult::AlreadyRequested,
                DRAINING_U8 => RuntimeShutdownRequestResult::AlreadyDraining,
                DRAIN_TIMED_OUT_U8 => RuntimeShutdownRequestResult::AlreadyTimedOut,
                EXITED_U8 => RuntimeShutdownRequestResult::AlreadyExited,
                _ => RuntimeShutdownRequestResult::AlreadyRequested,
            },
        }
    }

    /// Read the current shutdown state.
    #[must_use]
    pub fn shutdown_state(&self) -> RuntimeShutdownState {
        shutdown_state_from_u8(self.shutdown_state_u8.load(Ordering::SeqCst))
    }

    /// Take a drain snapshot. Also advances `ShutdownRequested → Draining`
    /// the first time work is observed, and `Draining → Exited` once all
    /// slots are free.
    pub fn drain_snapshot(&self, elapsed_ms_u64: u64) -> RuntimeDrainReport {
        let elapsed_u32 = clamp_to_u32(elapsed_ms_u64);
        let mut active: u16 = 0;
        let mut finished: u16 = 0;
        let mut timed_out: u16 = 0;
        let mut unknown_after_boundary: u16 = 0;
        let mut any_occupied = false;
        for slot in self.slots.iter() {
            if slot.task_id_u64.load(Ordering::SeqCst) == 0 {
                continue;
            }
            any_occupied = true;
            let status = slot.status_u8.load(Ordering::SeqCst);
            if status == FINISHED_U8 {
                finished = finished.saturating_add(1);
                let outcome = slot.join_outcome_u8.load(Ordering::SeqCst);
                if outcome == JOIN_TIMEOUT_U8 {
                    timed_out = timed_out.saturating_add(1);
                }
                let boundary = slot.boundary_state_u8.load(Ordering::SeqCst);
                if boundary == UNKNOWN_AFTER_BOUNDARY_U8 {
                    unknown_after_boundary = unknown_after_boundary.saturating_add(1);
                }
            } else if status == REGISTERED_U8
                || status == RUNNING_U8
                || status == CANCEL_REQUESTED_U8
            {
                active = active.saturating_add(1);
            }
        }
        // Auto-advance ShutdownRequested → Draining on the first snapshot.
        let _ = self.shutdown_state_u8.compare_exchange(
            SHUTDOWN_REQUESTED_U8,
            DRAINING_U8,
            Ordering::SeqCst,
            Ordering::SeqCst,
        );
        // Auto-advance Draining → Exited once nothing is occupied.
        if !any_occupied {
            let _ = self.shutdown_state_u8.compare_exchange(
                DRAINING_U8,
                EXITED_U8,
                Ordering::SeqCst,
                Ordering::SeqCst,
            );
        }
        RuntimeDrainReport {
            shutdown_state: shutdown_state_from_u8(self.shutdown_state_u8.load(Ordering::SeqCst)),
            active_count_u16: active,
            finished_count_u16: finished,
            timed_out_count_u16: timed_out,
            unknown_after_boundary_count_u16: unknown_after_boundary,
            elapsed_ms_u32: elapsed_u32,
        }
    }

    /// Record a hard drain timeout. Forces every still-live slot to
    /// `Finished` with `JoinTimeout` (or `CancelledAfterBoundaryUnknown` if
    /// its `boundary_state` is `UnknownAfterBoundary`).
    pub fn record_drain_timeout(&self, elapsed_ms_u64: u64) -> RuntimeDrainReport {
        let elapsed_u32 = clamp_to_u32(elapsed_ms_u64);
        // First-writer-wins transition to DrainTimedOut.
        let _ = self.shutdown_state_u8.compare_exchange(
            SHUTDOWN_REQUESTED_U8,
            DRAIN_TIMED_OUT_U8,
            Ordering::SeqCst,
            Ordering::SeqCst,
        );
        let _ = self.shutdown_state_u8.compare_exchange(
            DRAINING_U8,
            DRAIN_TIMED_OUT_U8,
            Ordering::SeqCst,
            Ordering::SeqCst,
        );
        let mut finished: u16 = 0;
        let mut timed_out: u16 = 0;
        let mut unknown_after_boundary: u16 = 0;
        for slot in self.slots.iter() {
            if slot.task_id_u64.load(Ordering::SeqCst) == 0 {
                continue;
            }
            let status = slot.status_u8.load(Ordering::SeqCst);
            if status == FINISHED_U8 {
                finished = finished.saturating_add(1);
                let outcome = slot.join_outcome_u8.load(Ordering::SeqCst);
                if outcome == JOIN_TIMEOUT_U8 {
                    timed_out = timed_out.saturating_add(1);
                }
                let boundary = slot.boundary_state_u8.load(Ordering::SeqCst);
                if boundary == UNKNOWN_AFTER_BOUNDARY_U8 {
                    unknown_after_boundary = unknown_after_boundary.saturating_add(1);
                }
                continue;
            }
            let boundary = slot.boundary_state_u8.load(Ordering::SeqCst);
            let outcome_byte = if boundary == UNKNOWN_AFTER_BOUNDARY_U8 {
                CANCELLED_AFTER_BOUNDARY_UNKNOWN_U8
            } else {
                JOIN_TIMEOUT_U8
            };
            // First-writer-wins on join_outcome.
            let _ = slot.join_outcome_u8.compare_exchange(
                NOT_JOINED_U8,
                outcome_byte,
                Ordering::SeqCst,
                Ordering::SeqCst,
            );
            // Force status to Finished. Walk the live values; first-writer
            // -wins per arm so a concurrent `finish` keeps its outcome.
            let _ = slot.status_u8.compare_exchange(
                REGISTERED_U8,
                FINISHED_U8,
                Ordering::SeqCst,
                Ordering::SeqCst,
            );
            let _ = slot.status_u8.compare_exchange(
                RUNNING_U8,
                FINISHED_U8,
                Ordering::SeqCst,
                Ordering::SeqCst,
            );
            let _ = slot.status_u8.compare_exchange(
                CANCEL_REQUESTED_U8,
                FINISHED_U8,
                Ordering::SeqCst,
                Ordering::SeqCst,
            );
            slot.elapsed_ms_u32.store(elapsed_u32, Ordering::SeqCst);
            finished = finished.saturating_add(1);
            if outcome_byte == JOIN_TIMEOUT_U8 {
                timed_out = timed_out.saturating_add(1);
            }
            if boundary == UNKNOWN_AFTER_BOUNDARY_U8 {
                unknown_after_boundary = unknown_after_boundary.saturating_add(1);
            }
        }
        RuntimeDrainReport {
            shutdown_state: shutdown_state_from_u8(self.shutdown_state_u8.load(Ordering::SeqCst)),
            active_count_u16: 0,
            finished_count_u16: finished,
            timed_out_count_u16: timed_out,
            unknown_after_boundary_count_u16: unknown_after_boundary,
            elapsed_ms_u32: elapsed_u32,
        }
    }

    /// Promote a registered task to `Running`. Returns `false` if the lease
    /// is stale or if the status had already advanced past `Registered`.
    pub fn mark_running(&self, lease: RuntimeTaskLease) -> bool {
        let Some(slot) = self.slot_if_live(lease) else {
            return false;
        };
        slot.status_u8
            .compare_exchange(
                REGISTERED_U8,
                RUNNING_U8,
                Ordering::SeqCst,
                Ordering::SeqCst,
            )
            .is_ok()
    }

    /// Record that the task has crossed an external boundary and the
    /// outcome is now unknown. Subsequent retry decisions are locked to
    /// `false` by [`runtime_retry_allowed`].
    pub fn mark_external_boundary_unknown(&self, lease: RuntimeTaskLease) -> bool {
        let Some(slot) = self.slot_if_live(lease) else {
            return false;
        };
        slot.boundary_state_u8
            .store(UNKNOWN_AFTER_BOUNDARY_U8, Ordering::SeqCst);
        true
    }

    /// Ask the supervisor to cancel a live task. First-writer-wins on
    /// `cancel_reason`; a doubled call returns `AlreadyRequested`.
    pub fn request_cancel(
        &self,
        lease: RuntimeTaskLease,
        reason: RuntimeCancelReason,
    ) -> RuntimeCancelResult {
        let Some(slot) = self.slot_if_live(lease) else {
            return RuntimeCancelResult::StaleTask;
        };
        let status = slot.status_u8.load(Ordering::SeqCst);
        if status == FINISHED_U8 {
            return RuntimeCancelResult::AlreadyFinished;
        }
        if status == STATUS_FREE_U8 {
            return RuntimeCancelResult::StaleTask;
        }
        match slot.cancel_reason_u8.compare_exchange(
            CANCEL_REASON_NONE_U8,
            reason as u8,
            Ordering::SeqCst,
            Ordering::SeqCst,
        ) {
            Ok(_) => {
                let boundary = slot.boundary_state_u8.load(Ordering::SeqCst);
                let _ = slot.status_u8.compare_exchange(
                    REGISTERED_U8,
                    CANCEL_REQUESTED_U8,
                    Ordering::SeqCst,
                    Ordering::SeqCst,
                );
                let _ = slot.status_u8.compare_exchange(
                    RUNNING_U8,
                    CANCEL_REQUESTED_U8,
                    Ordering::SeqCst,
                    Ordering::SeqCst,
                );
                // Result is sourced from the status we observed at entry +
                // the boundary captured under the same SeqCst fence as the
                // cancel_reason CAS.
                if status == REGISTERED_U8 {
                    RuntimeCancelResult::RequestedBeforeStart
                } else if boundary == BEFORE_EXTERNAL_BOUNDARY_U8 {
                    RuntimeCancelResult::RequestedBeforeBoundary
                } else if boundary == UNKNOWN_AFTER_BOUNDARY_U8 {
                    RuntimeCancelResult::RequestedAfterBoundaryUnknown
                } else {
                    // `Running` with `NotStarted` boundary is the
                    // mark_running-but-not-yet-near-boundary state.
                    RuntimeCancelResult::RequestedBeforeBoundary
                }
            }
            Err(_) => {
                let s2 = slot.status_u8.load(Ordering::SeqCst);
                if s2 == FINISHED_U8 {
                    RuntimeCancelResult::AlreadyFinished
                } else {
                    RuntimeCancelResult::AlreadyRequested
                }
            }
        }
    }

    /// Finalise a task. First-writer-wins on the status CAS: a doubled
    /// `finish` is a no-op (returns `None`); a stale lease is also `None`.
    pub fn finish(
        &self,
        lease: RuntimeTaskLease,
        join_outcome: RuntimeJoinOutcome,
        elapsed_ms_u64: u64,
        token_estimate_u64: u64,
    ) -> Option<RuntimeTaskReport> {
        let slot = self.slot_if_live(lease)?;
        let elapsed_u32 = clamp_to_u32(elapsed_ms_u64);
        let token_u32 = clamp_to_u32(token_estimate_u64);
        // CAS-loop status to Finished, refusing if already Finished.
        let mut current = slot.status_u8.load(Ordering::SeqCst);
        loop {
            if current == FINISHED_U8 || current == STATUS_FREE_U8 {
                return None;
            }
            match slot.status_u8.compare_exchange(
                current,
                FINISHED_U8,
                Ordering::SeqCst,
                Ordering::SeqCst,
            ) {
                Ok(_) => break,
                Err(actual) => {
                    current = actual;
                    continue;
                }
            }
        }
        // We won. Record terminal fields. join_outcome is itself
        // first-writer-wins so a concurrent drain_timeout that observed our
        // pre-CAS status keeps the first outcome it stamped (typically ours,
        // but the SeqCst fence guarantees a single linearisation).
        let _ = slot.join_outcome_u8.compare_exchange(
            NOT_JOINED_U8,
            join_outcome as u8,
            Ordering::SeqCst,
            Ordering::SeqCst,
        );
        slot.elapsed_ms_u32.store(elapsed_u32, Ordering::SeqCst);
        slot.token_estimate_u32.store(token_u32, Ordering::SeqCst);
        Some(self.snapshot_report(slot, lease))
    }

    /// Free a `Finished` slot. Returns `NotFinished` if the task hasn't
    /// reached the terminal state yet; `AlreadyFree` if it was already freed
    /// (idempotent); `StaleTask` if the lease is stale.
    pub fn release(&self, lease: RuntimeTaskLease) -> RuntimeReleaseResult {
        if lease.supervisor_id_u32 != self.supervisor_id_u32 {
            return RuntimeReleaseResult::StaleTask;
        }
        let Some(slot) = self.slots.get(lease.slot_u16 as usize) else {
            return RuntimeReleaseResult::StaleTask;
        };
        let current_id = slot.task_id_u64.load(Ordering::SeqCst);
        // A lease whose task_id no longer occupies the slot is stale, including
        // the case where the slot is now free (someone — possibly an earlier
        // call from the same lease — already released). `AlreadyFree` is
        // reserved for the narrow CAS-race below where a concurrent release
        // ran in parallel with this one.
        if current_id != lease.task_id.0 {
            return RuntimeReleaseResult::StaleTask;
        }
        let status = slot.status_u8.load(Ordering::SeqCst);
        if status != FINISHED_U8 {
            return RuntimeReleaseResult::NotFinished;
        }
        // First-writer-wins: only the live lease can flip task_id to 0.
        match slot
            .task_id_u64
            .compare_exchange(current_id, 0, Ordering::SeqCst, Ordering::SeqCst)
        {
            Ok(_) => {
                slot.status_u8.store(STATUS_FREE_U8, Ordering::SeqCst);
                // Reset per-task fields so the next register starts clean.
                slot.cancel_reason_u8
                    .store(CANCEL_REASON_NONE_U8, Ordering::SeqCst);
                slot.boundary_state_u8
                    .store(NOT_STARTED_U8, Ordering::SeqCst);
                slot.join_outcome_u8.store(NOT_JOINED_U8, Ordering::SeqCst);
                slot.elapsed_ms_u32.store(0, Ordering::SeqCst);
                slot.token_estimate_u32.store(0, Ordering::SeqCst);
                RuntimeReleaseResult::Released
            }
            Err(_) => RuntimeReleaseResult::AlreadyFree,
        }
    }

    /// Read a bounded snapshot of a live (or finished-but-not-released) slot.
    /// Returns `None` for stale leases (mismatched supervisor / task id).
    pub fn report(&self, lease: RuntimeTaskLease) -> Option<RuntimeTaskReport> {
        let slot = self.slot_if_live(lease)?;
        Some(self.snapshot_report(slot, lease))
    }

    // -----------------------------------------------------------------------
    // Private helpers.
    // -----------------------------------------------------------------------

    fn slot_if_live(&self, lease: RuntimeTaskLease) -> Option<&RuntimeTaskSlot> {
        if lease.supervisor_id_u32 != self.supervisor_id_u32 {
            return None;
        }
        let slot = self.slots.get(lease.slot_u16 as usize)?;
        if slot.task_id_u64.load(Ordering::SeqCst) != lease.task_id.0 {
            return None;
        }
        Some(slot)
    }

    fn snapshot_report(
        &self,
        slot: &RuntimeTaskSlot,
        lease: RuntimeTaskLease,
    ) -> RuntimeTaskReport {
        RuntimeTaskReport {
            task_kind: task_kind_from_u8(slot.kind_u8.load(Ordering::SeqCst)),
            status: task_status_from_u8(slot.status_u8.load(Ordering::SeqCst)),
            cancel_reason: cancel_reason_from_u8(slot.cancel_reason_u8.load(Ordering::SeqCst)),
            join_outcome: join_outcome_from_u8(slot.join_outcome_u8.load(Ordering::SeqCst)),
            boundary_state: boundary_state_from_u8(slot.boundary_state_u8.load(Ordering::SeqCst)),
            // Phase 0: every runtime report rides the public-safe log channel.
            // No raw user data is ever attached to a task report.
            redaction: RedactionClass::PublicSafe,
            task_id: lease.task_id,
            attempt: RuntimeAttempt(slot.attempt_u8.load(Ordering::SeqCst)),
            elapsed_ms_u32: slot.elapsed_ms_u32.load(Ordering::SeqCst),
            token_estimate_u32: slot.token_estimate_u32.load(Ordering::SeqCst),
        }
    }
}

// ---------------------------------------------------------------------------
// Public retry decision (const fn — the policy lives in the type system).
// ---------------------------------------------------------------------------

/// Decide whether a failed task may be retried. The function is `const fn`
/// so a policy decision can be evaluated at compile time; the encoding rule
/// is "boundary unknown ⇒ no retry, period", and that rule is enforced
/// before any policy branch.
#[must_use]
pub const fn runtime_retry_allowed(
    policy: RuntimeRetryPolicy,
    boundary_state: RuntimeBoundaryState,
    join_outcome: RuntimeJoinOutcome,
) -> bool {
    // Boundary lock: no retry once external world-state is unknown.
    if matches!(boundary_state, RuntimeBoundaryState::UnknownAfterBoundary) {
        return false;
    }
    // Outcome lock: timeout/panic/already-completed never retry, regardless
    // of policy. CancelledAfterBoundaryUnknown is redundant with the boundary
    // lock above but listed explicitly so audit greps catch both checks.
    match join_outcome {
        RuntimeJoinOutcome::JoinTimeout
        | RuntimeJoinOutcome::JoinPanic
        | RuntimeJoinOutcome::Completed
        | RuntimeJoinOutcome::CancelledAfterBoundaryUnknown => return false,
        _ => {}
    }
    match policy {
        RuntimeRetryPolicy::Never => false,
        RuntimeRetryPolicy::ManualOnly => false,
        RuntimeRetryPolicy::IdempotentNoBoundary => match join_outcome {
            RuntimeJoinOutcome::NotJoined
            | RuntimeJoinOutcome::DomainError
            | RuntimeJoinOutcome::CancelledBeforeStart
            | RuntimeJoinOutcome::CancelledBeforeBoundary
            | RuntimeJoinOutcome::JoinCancelled => matches!(
                boundary_state,
                RuntimeBoundaryState::NotStarted | RuntimeBoundaryState::BeforeExternalBoundary
            ),
            _ => false,
        },
    }
}

// ---------------------------------------------------------------------------
// Private u8 → enum conversions. Every store in this module only ever writes
// a known-good byte, so the `_ => fallback` arms are unreachable in practice;
// they exist purely so the `from_u8` helpers stay panic-free.
// ---------------------------------------------------------------------------

#[inline]
const fn clamp_to_u32(value: u64) -> u32 {
    if value > u32::MAX as u64 {
        u32::MAX
    } else {
        value as u32
    }
}

#[inline]
fn shutdown_state_from_u8(byte: u8) -> RuntimeShutdownState {
    match byte {
        ACCEPTING_U8 => RuntimeShutdownState::Accepting,
        SHUTDOWN_REQUESTED_U8 => RuntimeShutdownState::ShutdownRequested,
        DRAINING_U8 => RuntimeShutdownState::Draining,
        DRAIN_TIMED_OUT_U8 => RuntimeShutdownState::DrainTimedOut,
        EXITED_U8 => RuntimeShutdownState::Exited,
        // Fallback: we only ever store the five values above.
        _ => RuntimeShutdownState::Accepting,
    }
}

#[inline]
fn task_kind_from_u8(byte: u8) -> RuntimeTaskKind {
    match byte {
        1 => RuntimeTaskKind::Agent,
        2 => RuntimeTaskKind::Tool,
        3 => RuntimeTaskKind::Memory,
        4 => RuntimeTaskKind::Walrus,
        5 => RuntimeTaskKind::Sui,
        6 => RuntimeTaskKind::Wallet,
        // Fallback: System is the default kind set by RuntimeTaskSlot::new.
        _ => RuntimeTaskKind::System,
    }
}

#[inline]
fn task_status_from_u8(byte: u8) -> RuntimeTaskStatus {
    match byte {
        REGISTERED_U8 => RuntimeTaskStatus::Registered,
        RUNNING_U8 => RuntimeTaskStatus::Running,
        CANCEL_REQUESTED_U8 => RuntimeTaskStatus::CancelRequested,
        FINISHED_U8 => RuntimeTaskStatus::Finished,
        // Fallback: free slots are never reported (lease guard rejects them).
        _ => RuntimeTaskStatus::Registered,
    }
}

#[inline]
fn cancel_reason_from_u8(byte: u8) -> RuntimeCancelReason {
    match byte {
        1 => RuntimeCancelReason::Operator,
        2 => RuntimeCancelReason::Shutdown,
        3 => RuntimeCancelReason::Budget,
        4 => RuntimeCancelReason::Timeout,
        5 => RuntimeCancelReason::Superseded,
        // Fallback (including the sentinel 0): no cancel recorded.
        _ => RuntimeCancelReason::None,
    }
}

#[inline]
fn boundary_state_from_u8(byte: u8) -> RuntimeBoundaryState {
    match byte {
        NOT_STARTED_U8 => RuntimeBoundaryState::NotStarted,
        BEFORE_EXTERNAL_BOUNDARY_U8 => RuntimeBoundaryState::BeforeExternalBoundary,
        UNKNOWN_AFTER_BOUNDARY_U8 => RuntimeBoundaryState::UnknownAfterBoundary,
        _ => RuntimeBoundaryState::NotStarted,
    }
}

#[inline]
fn join_outcome_from_u8(byte: u8) -> RuntimeJoinOutcome {
    match byte {
        COMPLETED_U8 => RuntimeJoinOutcome::Completed,
        2 => RuntimeJoinOutcome::DomainError,
        CANCELLED_BEFORE_START_U8 => RuntimeJoinOutcome::CancelledBeforeStart,
        CANCELLED_BEFORE_BOUNDARY_U8 => RuntimeJoinOutcome::CancelledBeforeBoundary,
        CANCELLED_AFTER_BOUNDARY_UNKNOWN_U8 => RuntimeJoinOutcome::CancelledAfterBoundaryUnknown,
        JOIN_TIMEOUT_U8 => RuntimeJoinOutcome::JoinTimeout,
        7 => RuntimeJoinOutcome::JoinPanic,
        8 => RuntimeJoinOutcome::JoinCancelled,
        // Fallback (including the sentinel 0).
        _ => RuntimeJoinOutcome::NotJoined,
    }
}

// ---------------------------------------------------------------------------
// Tests (18 named per ATOM_PLAN atom #3 §6).
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    // Tests deliberately panic on failure; the prod deny list (no expect /
    // no panic) does not apply to assertion-driven test code.
    #![allow(clippy::expect_used)]

    use super::*;

    // Small CAP for capacity tests; large enough that "fixed_capacity" still
    // exercises slot reuse without inflating compile time.
    const CAP_SMALL: usize = 2;
    const CAP_MED: usize = 4;

    fn fresh<const N: usize>() -> RuntimeSupervisor<N> {
        RuntimeSupervisor::<N>::new()
    }

    #[test]
    fn fixed_capacity_rejects_cap_plus_one_and_preserves_id_width() {
        let sup = fresh::<CAP_SMALL>();
        let l1 = sup
            .register(RuntimeTaskKind::Agent, RuntimeAttempt::FIRST)
            .expect("first register");
        let l2 = sup
            .register(RuntimeTaskKind::Tool, RuntimeAttempt::FIRST)
            .expect("second register");
        let err = sup
            .register(RuntimeTaskKind::Memory, RuntimeAttempt::FIRST)
            .expect_err("third register must fail with CapacityExceeded");
        assert_eq!(err, RuntimeRegisterError::CapacityExceeded);
        // Ids stay u64-shaped and monotone for the two successful registers.
        assert_eq!(l1.task_id(), RuntimeTaskId::FIRST);
        assert!(l2.task_id().get() > l1.task_id().get());
        // The lease type itself is bounded: stays small + Copy.
        assert!(core::mem::size_of::<RuntimeTaskLease>() <= 16);
    }

    #[test]
    fn release_is_exactly_once_and_reuse_gets_new_id() {
        let sup = fresh::<CAP_SMALL>();
        let l1 = sup
            .register(RuntimeTaskKind::Agent, RuntimeAttempt::FIRST)
            .expect("register");
        // Cannot release before finish.
        assert_eq!(sup.release(l1), RuntimeReleaseResult::NotFinished);
        let _ = sup
            .finish(l1, RuntimeJoinOutcome::Completed, 10, 0)
            .expect("first finish");
        assert_eq!(sup.release(l1), RuntimeReleaseResult::Released);
        // Second release is StaleTask (slot is free; lease no longer matches).
        assert_eq!(sup.release(l1), RuntimeReleaseResult::StaleTask);
        // Reuse mints a strictly greater id.
        let l2 = sup
            .register(RuntimeTaskKind::Tool, RuntimeAttempt::FIRST)
            .expect("re-register");
        assert!(l2.task_id().get() > l1.task_id().get());
    }

    #[test]
    fn cancel_before_start_is_idempotent_and_visible_to_pollers() {
        let sup = fresh::<CAP_SMALL>();
        let l = sup
            .register(RuntimeTaskKind::Tool, RuntimeAttempt::FIRST)
            .expect("register");
        let r1 = sup.request_cancel(l, RuntimeCancelReason::Operator);
        assert_eq!(r1, RuntimeCancelResult::RequestedBeforeStart);
        let r2 = sup.request_cancel(l, RuntimeCancelReason::Operator);
        assert_eq!(r2, RuntimeCancelResult::AlreadyRequested);
        // Pollers see CancelRequested.
        let rep = sup.report(l).expect("report after cancel");
        assert_eq!(rep.status, RuntimeTaskStatus::CancelRequested);
        assert_eq!(rep.cancel_reason, RuntimeCancelReason::Operator);
    }

    #[test]
    fn cancel_after_external_boundary_is_unknown_and_blocks_retry() {
        let sup = fresh::<CAP_SMALL>();
        let l = sup
            .register(RuntimeTaskKind::Walrus, RuntimeAttempt::FIRST)
            .expect("register");
        assert!(sup.mark_running(l));
        assert!(sup.mark_external_boundary_unknown(l));
        let r = sup.request_cancel(l, RuntimeCancelReason::Timeout);
        assert_eq!(r, RuntimeCancelResult::RequestedAfterBoundaryUnknown);
        // After this point retry is locked off, regardless of policy.
        for policy in [
            RuntimeRetryPolicy::Never,
            RuntimeRetryPolicy::ManualOnly,
            RuntimeRetryPolicy::IdempotentNoBoundary,
        ] {
            for outcome in [
                RuntimeJoinOutcome::NotJoined,
                RuntimeJoinOutcome::DomainError,
                RuntimeJoinOutcome::CancelledAfterBoundaryUnknown,
                RuntimeJoinOutcome::JoinCancelled,
            ] {
                assert!(!runtime_retry_allowed(
                    policy,
                    RuntimeBoundaryState::UnknownAfterBoundary,
                    outcome
                ));
            }
        }
    }

    #[test]
    fn report_and_id_layout_stays_bounded() {
        // Fixed-width plain values; exact byte sizes pinned for the typed-unit
        // newtypes + the lease + the report.
        assert_eq!(core::mem::size_of::<RuntimeTaskId>(), 8);
        assert_eq!(core::mem::size_of::<RuntimeAttempt>(), 1);
        // Lease = u64 task_id + u32 supervisor_id + u16 slot. With padding the
        // struct is bounded ≤16 bytes.
        assert!(core::mem::size_of::<RuntimeTaskLease>() <= 16);
        // Report is a fixed bundle of plain values: bounded ≤32 bytes on a
        // 64-bit target (the byte enums each take 1 byte and pack tightly).
        assert!(core::mem::size_of::<RuntimeTaskReport>() <= 32);
        // Drain report is similarly small.
        assert!(core::mem::size_of::<RuntimeDrainReport>() <= 16);
        // Copyability is part of the contract.
        fn assert_copy<T: Copy>() {}
        assert_copy::<RuntimeTaskId>();
        assert_copy::<RuntimeAttempt>();
        assert_copy::<RuntimeTaskLease>();
        assert_copy::<RuntimeTaskReport>();
        assert_copy::<RuntimeDrainReport>();
    }

    #[test]
    fn outcome_matrix_keeps_timeout_panic_cancel_and_domain_error_distinct() {
        let outcomes = [
            RuntimeJoinOutcome::NotJoined,
            RuntimeJoinOutcome::Completed,
            RuntimeJoinOutcome::DomainError,
            RuntimeJoinOutcome::CancelledBeforeStart,
            RuntimeJoinOutcome::CancelledBeforeBoundary,
            RuntimeJoinOutcome::CancelledAfterBoundaryUnknown,
            RuntimeJoinOutcome::JoinTimeout,
            RuntimeJoinOutcome::JoinPanic,
            RuntimeJoinOutcome::JoinCancelled,
        ];
        // Discriminants are pairwise distinct (9 unique bytes for 9 outcomes).
        let mut seen = [false; 256];
        for o in outcomes.iter() {
            let b = *o as u8;
            assert!(!seen[b as usize], "duplicate join outcome byte: {b}");
            seen[b as usize] = true;
        }
        // Specifically: JoinTimeout / JoinPanic / JoinCancelled /
        // CancelledBeforeBoundary / CancelledAfterBoundaryUnknown / DomainError
        // all pairwise distinct.
        let group = [
            RuntimeJoinOutcome::JoinTimeout as u8,
            RuntimeJoinOutcome::JoinPanic as u8,
            RuntimeJoinOutcome::JoinCancelled as u8,
            RuntimeJoinOutcome::CancelledBeforeBoundary as u8,
            RuntimeJoinOutcome::CancelledAfterBoundaryUnknown as u8,
            RuntimeJoinOutcome::DomainError as u8,
        ];
        for i in 0..group.len() {
            for j in (i + 1)..group.len() {
                assert!(
                    group[i] != group[j],
                    "outcome byte collision: {} == {}",
                    group[i],
                    group[j]
                );
            }
        }
    }

    #[test]
    fn no_hang_watchdog_records_timeout_without_retry_permission() {
        let sup = fresh::<CAP_SMALL>();
        let l = sup
            .register(RuntimeTaskKind::Agent, RuntimeAttempt::FIRST)
            .expect("register");
        assert!(sup.mark_running(l));
        // Simulate a watchdog firing: caller records JoinTimeout via finish.
        let rep = sup
            .finish(l, RuntimeJoinOutcome::JoinTimeout, 30_000, 0)
            .expect("finish via watchdog");
        assert_eq!(rep.join_outcome, RuntimeJoinOutcome::JoinTimeout);
        assert_eq!(rep.status, RuntimeTaskStatus::Finished);
        // No retry policy may re-enable a timed-out task.
        for policy in [
            RuntimeRetryPolicy::Never,
            RuntimeRetryPolicy::ManualOnly,
            RuntimeRetryPolicy::IdempotentNoBoundary,
        ] {
            for boundary in [
                RuntimeBoundaryState::NotStarted,
                RuntimeBoundaryState::BeforeExternalBoundary,
                RuntimeBoundaryState::UnknownAfterBoundary,
            ] {
                assert!(!runtime_retry_allowed(
                    policy,
                    boundary,
                    RuntimeJoinOutcome::JoinTimeout
                ));
            }
        }
    }

    #[test]
    fn stale_lease_from_previous_supervisor_cannot_cancel_new_task() {
        let a = fresh::<CAP_SMALL>();
        let stale = a
            .register(RuntimeTaskKind::Agent, RuntimeAttempt::FIRST)
            .expect("register on supervisor a");
        let b = fresh::<CAP_SMALL>();
        // Slot 0 of `b` is freshly free; register a task there.
        let fresh_b = b
            .register(RuntimeTaskKind::Agent, RuntimeAttempt::FIRST)
            .expect("register on supervisor b");
        // Supervisor ids must differ (we minted both this test run).
        assert!(a.supervisor_id_u32() != b.supervisor_id_u32());
        // The stale lease cannot cancel b's task.
        let r = b.request_cancel(stale, RuntimeCancelReason::Operator);
        assert_eq!(r, RuntimeCancelResult::StaleTask);
        // b's task is untouched: still registered, no cancel reason.
        let rep = b.report(fresh_b).expect("report b");
        assert_eq!(rep.status, RuntimeTaskStatus::Registered);
        assert_eq!(rep.cancel_reason, RuntimeCancelReason::None);
    }

    #[test]
    fn finish_is_first_writer_wins_under_double_finish() {
        let sup = fresh::<CAP_SMALL>();
        let l = sup
            .register(RuntimeTaskKind::Tool, RuntimeAttempt::FIRST)
            .expect("register");
        assert!(sup.mark_running(l));
        let r1 = sup
            .finish(l, RuntimeJoinOutcome::Completed, 5, 100)
            .expect("first finish");
        // Second finish must return None and must NOT overwrite outcome.
        let r2 = sup.finish(l, RuntimeJoinOutcome::DomainError, 999, 999);
        assert!(r2.is_none());
        assert_eq!(r1.join_outcome, RuntimeJoinOutcome::Completed);
        // Report still reads Completed.
        let after = sup.report(l).expect("report after double finish");
        assert_eq!(after.join_outcome, RuntimeJoinOutcome::Completed);
        assert_eq!(after.elapsed_ms_u32, 5);
        assert_eq!(after.token_estimate_u32, 100);
    }

    #[test]
    fn cancel_reason_is_first_writer_wins_under_repeated_shutdown() {
        let sup = fresh::<CAP_SMALL>();
        let l = sup
            .register(RuntimeTaskKind::Memory, RuntimeAttempt::FIRST)
            .expect("register");
        // First: operator cancel.
        assert_eq!(
            sup.request_cancel(l, RuntimeCancelReason::Operator),
            RuntimeCancelResult::RequestedBeforeStart
        );
        // Then: request_shutdown — must NOT overwrite the Operator reason.
        assert_eq!(
            sup.request_shutdown(1_000),
            RuntimeShutdownRequestResult::Requested
        );
        let rep = sup.report(l).expect("report after shutdown");
        assert_eq!(rep.cancel_reason, RuntimeCancelReason::Operator);
        // A second request_shutdown is reported as AlreadyRequested.
        assert_eq!(
            sup.request_shutdown(5_000),
            RuntimeShutdownRequestResult::AlreadyRequested
        );
    }

    #[test]
    fn shutdown_request_is_idempotent_and_does_not_extend_deadline() {
        let sup = fresh::<CAP_SMALL>();
        assert_eq!(
            sup.request_shutdown(1_000),
            RuntimeShutdownRequestResult::Requested
        );
        // Capture the deadline observed at first request.
        let first_timeout = sup.shutdown_timeout_ms_u32.load(Ordering::SeqCst);
        assert_eq!(first_timeout, 1_000);
        // Repeated requests with longer deadlines do not extend it.
        assert_eq!(
            sup.request_shutdown(60_000),
            RuntimeShutdownRequestResult::AlreadyRequested
        );
        assert_eq!(sup.shutdown_timeout_ms_u32.load(Ordering::SeqCst), 1_000);
        // State remains ShutdownRequested (no drain_snapshot was called).
        assert_eq!(
            sup.shutdown_state(),
            RuntimeShutdownState::ShutdownRequested
        );
    }

    #[test]
    fn register_after_shutdown_is_rejected_without_consuming_slot_or_task_id() {
        let sup = fresh::<CAP_SMALL>();
        let before_id = sup.next_id_u64.load(Ordering::SeqCst);
        assert_eq!(
            sup.request_shutdown(500),
            RuntimeShutdownRequestResult::Requested
        );
        // Now register must reject without minting a fresh id or touching a slot.
        let err = sup
            .register(RuntimeTaskKind::Agent, RuntimeAttempt::FIRST)
            .expect_err("register after shutdown must fail");
        assert_eq!(err, RuntimeRegisterError::ShutdownRequested);
        let after_id = sup.next_id_u64.load(Ordering::SeqCst);
        assert_eq!(
            before_id, after_id,
            "shutdown-rejected register minted an id"
        );
        // Slot 0 is still free.
        assert_eq!(sup.slots[0].task_id_u64.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn shutdown_requests_cancel_for_all_live_tasks_once() {
        let sup = fresh::<CAP_MED>();
        let l1 = sup
            .register(RuntimeTaskKind::Agent, RuntimeAttempt::FIRST)
            .expect("l1");
        let l2 = sup
            .register(RuntimeTaskKind::Tool, RuntimeAttempt::FIRST)
            .expect("l2");
        // Pre-cancel l2 with Operator so we can verify first-writer-wins.
        assert_eq!(
            sup.request_cancel(l2, RuntimeCancelReason::Operator),
            RuntimeCancelResult::RequestedBeforeStart
        );
        assert_eq!(
            sup.request_shutdown(2_000),
            RuntimeShutdownRequestResult::Requested
        );
        // l1: cancel reason became Shutdown.
        let r1 = sup.report(l1).expect("report l1");
        assert_eq!(r1.cancel_reason, RuntimeCancelReason::Shutdown);
        assert_eq!(r1.status, RuntimeTaskStatus::CancelRequested);
        // l2: cancel reason remains Operator (first-writer-wins).
        let r2 = sup.report(l2).expect("report l2");
        assert_eq!(r2.cancel_reason, RuntimeCancelReason::Operator);
        // A repeated request_shutdown does not re-cancel.
        assert_eq!(
            sup.request_shutdown(2_000),
            RuntimeShutdownRequestResult::AlreadyRequested
        );
    }

    #[test]
    fn drain_completes_when_all_live_tasks_finish_and_releases_once() {
        let sup = fresh::<CAP_MED>();
        let l1 = sup
            .register(RuntimeTaskKind::Agent, RuntimeAttempt::FIRST)
            .expect("l1");
        let l2 = sup
            .register(RuntimeTaskKind::Tool, RuntimeAttempt::FIRST)
            .expect("l2");
        assert_eq!(
            sup.request_shutdown(10_000),
            RuntimeShutdownRequestResult::Requested
        );
        // Both tasks finish and are released.
        let _ = sup
            .finish(l1, RuntimeJoinOutcome::Completed, 1, 0)
            .expect("finish l1");
        let _ = sup
            .finish(l2, RuntimeJoinOutcome::Completed, 2, 0)
            .expect("finish l2");
        // First drain snapshot transitions ShutdownRequested → Draining and
        // counts both as finished.
        let snap1 = sup.drain_snapshot(100);
        assert_eq!(snap1.active_count_u16, 0);
        assert_eq!(snap1.finished_count_u16, 2);
        // Release frees the slots.
        assert_eq!(sup.release(l1), RuntimeReleaseResult::Released);
        assert_eq!(sup.release(l2), RuntimeReleaseResult::Released);
        // Second snapshot transitions Draining → Exited.
        let snap2 = sup.drain_snapshot(200);
        assert_eq!(snap2.active_count_u16, 0);
        assert_eq!(snap2.finished_count_u16, 0);
        assert_eq!(snap2.shutdown_state, RuntimeShutdownState::Exited);
        // Re-releasing a freed slot is StaleTask (idempotent observable).
        assert_eq!(sup.release(l1), RuntimeReleaseResult::StaleTask);
    }

    #[test]
    fn drain_timeout_records_join_timeout_and_blocks_retry() {
        let sup = fresh::<CAP_SMALL>();
        let l = sup
            .register(RuntimeTaskKind::Agent, RuntimeAttempt::FIRST)
            .expect("register");
        assert!(sup.mark_running(l));
        assert_eq!(
            sup.request_shutdown(50),
            RuntimeShutdownRequestResult::Requested
        );
        let snap = sup.record_drain_timeout(60);
        assert_eq!(snap.shutdown_state, RuntimeShutdownState::DrainTimedOut);
        assert!(snap.timed_out_count_u16 >= 1);
        // Verify the slot is now Finished with JoinTimeout and retry is blocked.
        let rep = sup.report(l).expect("report after timeout");
        assert_eq!(rep.status, RuntimeTaskStatus::Finished);
        assert_eq!(rep.join_outcome, RuntimeJoinOutcome::JoinTimeout);
        for policy in [
            RuntimeRetryPolicy::Never,
            RuntimeRetryPolicy::ManualOnly,
            RuntimeRetryPolicy::IdempotentNoBoundary,
        ] {
            assert!(!runtime_retry_allowed(
                policy,
                rep.boundary_state,
                rep.join_outcome
            ));
        }
    }

    #[test]
    fn drain_timeout_after_unknown_boundary_records_unknown_and_blocks_retry() {
        let sup = fresh::<CAP_SMALL>();
        let l = sup
            .register(RuntimeTaskKind::Walrus, RuntimeAttempt::FIRST)
            .expect("register");
        assert!(sup.mark_running(l));
        assert!(sup.mark_external_boundary_unknown(l));
        assert_eq!(
            sup.request_shutdown(10),
            RuntimeShutdownRequestResult::Requested
        );
        let snap = sup.record_drain_timeout(20);
        assert_eq!(snap.shutdown_state, RuntimeShutdownState::DrainTimedOut);
        assert!(snap.unknown_after_boundary_count_u16 >= 1);
        let rep = sup.report(l).expect("report after unknown timeout");
        assert_eq!(
            rep.boundary_state,
            RuntimeBoundaryState::UnknownAfterBoundary
        );
        assert_eq!(
            rep.join_outcome,
            RuntimeJoinOutcome::CancelledAfterBoundaryUnknown
        );
        // Boundary-unknown lock: every policy blocks retry.
        for policy in [
            RuntimeRetryPolicy::Never,
            RuntimeRetryPolicy::ManualOnly,
            RuntimeRetryPolicy::IdempotentNoBoundary,
        ] {
            assert!(!runtime_retry_allowed(
                policy,
                rep.boundary_state,
                rep.join_outcome
            ));
        }
    }

    #[test]
    fn join_cancelled_retry_policy_is_explicit() {
        // Never / ManualOnly: never retry, even with a clean cancel.
        assert!(!runtime_retry_allowed(
            RuntimeRetryPolicy::Never,
            RuntimeBoundaryState::NotStarted,
            RuntimeJoinOutcome::JoinCancelled
        ));
        assert!(!runtime_retry_allowed(
            RuntimeRetryPolicy::ManualOnly,
            RuntimeBoundaryState::BeforeExternalBoundary,
            RuntimeJoinOutcome::JoinCancelled
        ));
        // IdempotentNoBoundary + boundary not crossed + JoinCancelled: allowed.
        assert!(runtime_retry_allowed(
            RuntimeRetryPolicy::IdempotentNoBoundary,
            RuntimeBoundaryState::NotStarted,
            RuntimeJoinOutcome::JoinCancelled
        ));
        assert!(runtime_retry_allowed(
            RuntimeRetryPolicy::IdempotentNoBoundary,
            RuntimeBoundaryState::BeforeExternalBoundary,
            RuntimeJoinOutcome::JoinCancelled
        ));
        // IdempotentNoBoundary + UnknownAfterBoundary: blocked.
        assert!(!runtime_retry_allowed(
            RuntimeRetryPolicy::IdempotentNoBoundary,
            RuntimeBoundaryState::UnknownAfterBoundary,
            RuntimeJoinOutcome::JoinCancelled
        ));
    }

    #[test]
    fn stale_lease_after_slot_reuse_cannot_finish_cancel_or_release_new_task() {
        let sup = fresh::<CAP_SMALL>();
        let stale = sup
            .register(RuntimeTaskKind::Agent, RuntimeAttempt::FIRST)
            .expect("register");
        let _ = sup
            .finish(stale, RuntimeJoinOutcome::Completed, 1, 0)
            .expect("finish");
        assert_eq!(sup.release(stale), RuntimeReleaseResult::Released);
        // Reuse the slot (smallest CAP, so we should land on the same index).
        let fresh_lease = sup
            .register(RuntimeTaskKind::Tool, RuntimeAttempt::FIRST)
            .expect("re-register");
        // Stale lease cannot finish / cancel / release the new task.
        assert!(
            sup.finish(stale, RuntimeJoinOutcome::Completed, 0, 0)
                .is_none(),
            "stale finish leaked"
        );
        assert_eq!(
            sup.request_cancel(stale, RuntimeCancelReason::Operator),
            RuntimeCancelResult::StaleTask
        );
        assert_eq!(sup.release(stale), RuntimeReleaseResult::StaleTask);
        // The fresh lease still observes the new task untouched.
        let rep = sup.report(fresh_lease).expect("fresh report");
        assert_eq!(rep.status, RuntimeTaskStatus::Registered);
        assert_eq!(rep.cancel_reason, RuntimeCancelReason::None);
    }
}
