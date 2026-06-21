//! Autonomy runtime — the bounded background runner (ENDGAME E3).
//!
//! This turns the daemon SCAFFOLD (the static `daemon_live_lines` projection)
//! into a REAL bounded background runner: the owner ARMS a grant, steps away, and
//! the runner works autonomously — local-first, egress-bounded, killable. Threat
//! model: `ops/evidence/stage_g/agent_loop/AUTONOMY_RUNTIME_THREAT_MODEL.md`
//! (⑩ IV-R1..R10), authored before this code.
//!
//! Shape (owner-ratified seams 2026-06-12):
//! - [`AutonomyRuntime`] is a PURE step-machine (no thread, no clock): [`tick`]
//!   advances ONE bounded autonomous job step, deterministically testable. ALL
//!   authority / budget / control / no-zombie decisions are made there, fail-closed,
//!   against the live `(now, used)` — never cached (IV-R1/R2/R10).
//! - [`RuntimeHandle`] is a THIN `std::thread` pump for the live `sinabro daemon`
//!   command (no new crate — `std::thread` is the house concurrency idiom). It owns
//!   NO business logic: it locks the shared runtime, honors terminal/paused, and
//!   calls a caller-supplied driver to advance one tick (IV-R10).
//!
//! The runner holds ONLY READ (free, PD-3; the recall READ is minted INSIDE the
//! agent loop) + an OPTIONAL owner-armed [`EgressGrant`]. It MINTS no capability:
//! the per-action [`EgressCapability`] is RE-DERIVED from the grant at the live
//! `(now, used)` every turn (IV-R1) — a grant is never a cached blank cheque. No
//! field can hold a wallet/secret; custody is unreachable (PD-6, IV-R7). Every
//! local turn re-obeys the ⑧ loopback discipline (re-redact), and every assembled
//! outbound byte still passes the SI-2 `redact()` choke inside the loop (the runner
//! adds no socket and sees no raw bytes; IV-R5). The model cannot mint an
//! `EgressCapability` (E0d) ⇒ cannot self-route to the frontier (IV-R8).

use crate::StageFTraceLink;
use crate::agent_loop::{
    AgentLoopOutcome, AgentLoopStop, AgentTransport, MemoryToolState, run_agent_loop,
};
use crate::commands::authority::{EgressCapability, MutateCapability};
use crate::commands::budget::{BudgetCap, BudgetReject, DispatchRequest};
use crate::commands::grant::{EgressGrant, MutateGrant};
use crate::daemon::budget_kill::{BudgetKillIntegration, SideEffectClass};
use crate::daemon::control_express::{BackgroundQueueDepths, ControlExpressRouter, ExpressClass};
use crate::daemon::supervisor::DaemonSupervisorView;
use crate::daemon::task_session::{
    AdmissionControl, AdmissionLane, OperationalInbox, OperationalJobClass,
};
use crate::mutate_execute::{AuthorizedMutate, MutateExecOutcome, execute_authorized_mutate};
use crate::provider::route_select::{
    ConsultCaller, ConsultPhrase, ConsultRoute, select_consult_route,
};
use crate::route::RouteExecutionState;
use crate::tui::job_rail::JobState;
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::Duration;

/// The typed outcome of one autonomous job step. Each non-`Ran` variant is a
/// fail-closed terminal for that tick — only `Ran` performed a bounded job. The
/// runner records these; no variant ever performs a hidden side effect.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TurnOutcome {
    /// A bounded agent-loop job step ran on `route`, ending with `stop`. Only a
    /// `Frontier` route advances the egress action (rate) count.
    Ran {
        /// The route the step ran on (LocalLoopback or Frontier).
        route: ConsultRoute,
        /// Why the bounded loop ended.
        stop: AgentLoopStop,
    },
    /// Control halted this tick (pause / express STOP) — no side effect (IV-R4).
    Paused,
    /// The budget cap re-check refused the next side effect (fail-closed, IV-R2):
    /// a lowered cap or an exhausted budget stops the NEXT turn before it runs.
    BudgetStopped(BudgetReject),
    /// An autonomous frontier escalation was requested WITHOUT a valid owner-armed
    /// grant — fail-closed, ZERO egress, no silent downgrade to local (IV-R1/R8).
    FrontierDenied,
    /// The job is terminal (killed / done) — `tick` is a no-op (no zombie, IV-R3).
    Terminated,
}

impl TurnOutcome {
    /// Whether this tick actually ran a bounded job step.
    #[must_use]
    pub const fn ran(self) -> bool {
        matches!(self, Self::Ran { .. })
    }
}

/// The typed outcome of one owner-authorized mutate PROCEED step (ENDGAME E10-2b).
/// `Ran` carries the executor receipt; every other variant is a fail-closed
/// terminal that performed NO side effect.
#[derive(Debug)]
pub enum MutateProceedOutcome {
    /// The owner-authorized side effect executed (the gated chokepoint ran). The
    /// inner [`MutateExecOutcome`] carries the executor's own receipt.
    Ran(MutateExecOutcome),
    /// No installed mutate grant, or it was expired / rate-exceeded / revoked —
    /// fail-closed: ZERO side effect, no silent fallback (IV-A1 / IV-A9 / IV-A11).
    MutateDenied,
    /// Control halted this step (pause / express STOP) — no side effect.
    Paused,
    /// The job is terminal (killed / done) — a no-op (no zombie).
    Terminated,
}

/// The budget-gate request for ONE autonomous turn. Modeled on a bounded `Slow`
/// consult (the route state that permits a bounded frontier consult) with a
/// minimal token + cost estimate, so the cap re-check (IV-R2) is exercised on
/// EVERY turn: a lowered cap (or an exhausted token/cost budget) refuses the next
/// turn fail-closed. Pure — no clock, no I/O.
fn autonomous_dispatch_request() -> DispatchRequest {
    DispatchRequest {
        route_state: RouteExecutionState::Slow,
        input_tokens_u32: 1,
        output_tokens_u32: 1,
        estimated_cost_micro: Some(1),
        projected_ms_u32: 0,
        approved: false,
        reason_hash_32: [0u8; 32],
        route_trace_hash_32: [0u8; 32],
    }
}

/// The bounded background runner — a PURE step-machine. See the module docs for
/// the security spine (IV-R1..R10). Holds ONLY an optional owner-armed
/// [`EgressGrant`] as authority; mints nothing; has no field that can carry a
/// wallet/secret (PD-6, IV-R7).
pub struct AutonomyRuntime {
    job_id_u64: u64,
    inbox: OperationalInbox,
    budget_kill: BudgetKillIntegration,
    control: ControlExpressRouter,
    admission: AdmissionControl,
    /// The OPTIONAL owner-armed egress grant. `None` ⇒ the job runs LOCAL-ONLY
    /// (exactly today's per-action default — NO autonomous egress without an arm).
    /// Stored as the GRANT (not a capability) so the capability is re-derived live.
    grant: Option<EgressGrant>,
    /// Egress actions consumed under the grant (the rate budget used). Advances
    /// ONLY on a frontier side effect; a local turn is READ-class (free).
    egress_actions_used_u32: u32,
    /// Autonomous turns run so far (local or frontier).
    turn_u32: u32,
    /// The OPTIONAL owner-armed MUTATE-LOCAL grant (ENDGAME E10-2b — a tier-correct
    /// telegram approval or a broad armed window). `None` ⇒ NO agent-proposed side
    /// effect can proceed (fail-closed). Stored as the GRANT (not a capability) so
    /// the capability is re-derived live per action (IV-A9). Tier-distinct from the
    /// egress grant: an EgressGrant cannot occupy this field (type, IV-A5). No field
    /// can carry a wallet/secret; custody is unreachable (PD-6, IV-A10).
    mutate_grant: Option<MutateGrant>,
    /// MUTATE actions consumed under the installed grant (the rate budget used).
    /// Advances once per proceed; the re-derivation fails closed at the grant cap.
    mutate_actions_used_u32: u32,
}

impl AutonomyRuntime {
    /// Arm the runner for ONE background job. Holds READ freely (PD-3; minted
    /// inside the loop) + the OPTIONAL owner-armed egress grant. The single job is
    /// admitted on the BACKGROUND lane, so the interactive RESERVED slot stays free
    /// (interactive never starves — IV-R4). `admission_max_concurrent_u32` is the
    /// concurrency bound (v1 runs one job; the bound reserves the interactive lane).
    #[must_use]
    pub fn arm(
        job_id_u64: u64,
        grant: Option<EgressGrant>,
        budget: BudgetCap,
        admission_max_concurrent_u32: u32,
        trace: StageFTraceLink,
    ) -> Self {
        let mut inbox = OperationalInbox::new(job_id_u64);
        inbox.admit(
            job_id_u64,
            OperationalJobClass::ProviderConsult,
            JobState::Running,
            trace,
        );
        // Reserve one slot for the interactive hot path; the single background job
        // takes a non-reserved slot. With max=1 the background job still admits and
        // the interactive lane preempts via the reserved-slot arithmetic (IV-R4).
        let interactive_reserved = if admission_max_concurrent_u32 > 1 {
            1
        } else {
            0
        };
        let mut admission =
            AdmissionControl::new(admission_max_concurrent_u32, interactive_reserved);
        let _admitted = admission.try_admit(AdmissionLane::Background);
        Self {
            job_id_u64,
            inbox,
            budget_kill: BudgetKillIntegration::new(budget),
            control: ControlExpressRouter::new(),
            admission,
            grant,
            egress_actions_used_u32: 0,
            turn_u32: 0,
            mutate_grant: None,
            mutate_actions_used_u32: 0,
        }
    }

    /// Advance ONE bounded autonomous job step. The order is the security spine:
    /// control re-read → budget cap re-check → grant re-derivation → typed route →
    /// (only then) ONE bounded agent loop. Every decision is made HERE, fail-closed,
    /// against the live `(now_epoch_ms, egress_actions_used)` — never cached.
    ///
    /// `transport` is the executor for the PERMITTED route (the caller pairs it: the
    /// local loopback transport for the default, the gated frontier transport for an
    /// armed escalation). Whatever transport is injected, it carries its OWN SI-2
    /// `redact()` + loopback-bind walls (IV-R5); a denied route runs NO transport
    /// (zero egress, IV-R1/R8).
    pub fn tick(
        &mut self,
        now_epoch_ms: u64,
        phrase: ConsultPhrase,
        system: &str,
        question: &str,
        transport: &mut dyn AgentTransport,
        state: &MemoryToolState<'_>,
    ) -> TurnOutcome {
        // 1. control re-read (IV-R3 no-zombie / IV-R4 preempt): a terminal job is a
        //    no-op (a killed job never resurrects); a paused/halted job performs no
        //    side effect this tick.
        if self.is_terminal() {
            return TurnOutcome::Terminated;
        }
        if self.is_paused() {
            return TurnOutcome::Paused;
        }
        // 2. budget-kill cap RE-CHECK before the side effect (IV-R2). A lowered cap
        //    (or an exhausted budget) refuses the next turn fail-closed.
        let req = autonomous_dispatch_request();
        if let Err(reject) = self
            .budget_kill
            .authorize_side_effect(SideEffectClass::Provider, &req)
        {
            return TurnOutcome::BudgetStopped(reject);
        }
        // 3. RE-DERIVE the egress capability from the grant at the LIVE (now, used)
        //    (IV-R1). Expired / rate-exceeded / revoked ⇒ None (fail-closed). The
        //    runner stores the grant, never a capability — no cached blank cheque.
        let egress_cap = self.grant.as_ref().and_then(|g| {
            EgressCapability::from_grant(g, now_epoch_ms, self.egress_actions_used_u32)
        });
        // 4. route via the typed selector (IV-R8). The model cannot mint an
        //    EgressCapability (E0d) ⇒ cannot self-route to the frontier.
        let route = select_consult_route(ConsultCaller::Autonomous, phrase, egress_cap.as_ref());
        match route {
            // A frontier escalation without a valid grant fails closed — no egress,
            // no silent downgrade to local (the caller asked for frontier).
            ConsultRoute::FrontierDeniedNoGrant | ConsultRoute::Locked => {
                TurnOutcome::FrontierDenied
            }
            ConsultRoute::LocalLoopback | ConsultRoute::Frontier => {
                // 5. run ONE bounded agent loop. SI-2 redact is intact INSIDE the
                //    loop (every assembled outbound message is an Outbound from
                //    redact()); the runner adds no socket and never sees raw bytes.
                let outcome: AgentLoopOutcome = run_agent_loop(transport, state, system, question);
                // 6. a FRONTIER egress consumes one action of the rate budget; a
                //    LOCAL turn is READ-class (free) and does not.
                if route.is_frontier() {
                    self.egress_actions_used_u32 = self.egress_actions_used_u32.saturating_add(1);
                }
                self.turn_u32 = self.turn_u32.saturating_add(1);
                TurnOutcome::Ran {
                    route,
                    stop: outcome.stop,
                }
            }
        }
    }

    /// Pause the job: the canonical rail reflects `Paused` AND the express control
    /// halts the next side effect (a STOP-class control that bypasses the
    /// background queue — IV-R4).
    pub fn pause(&mut self) {
        let _ = self.inbox.pause(self.job_id_u64);
        let _ack = self
            .control
            .ack(ExpressClass::Pause, BackgroundQueueDepths::default());
    }

    /// Resume the job — ONLY from paused (the canonical rail refuses a terminal, so
    /// a killed job never resurrects — IV-R3).
    pub fn resume(&mut self) {
        let _ = self.inbox.resume(self.job_id_u64);
        self.control.resume();
    }

    /// Kill the job — terminal + IRREVERSIBLE (no zombie, no resurrection; IV-R3).
    /// The next `tick` observes the terminal job and is a no-op; the thread pump's
    /// next loop turn breaks and joins cleanly.
    pub fn kill(&mut self) {
        let _ = self.inbox.cancel(self.job_id_u64);
        let _ack = self
            .control
            .ack(ExpressClass::Kill, BackgroundQueueDepths::default());
    }

    /// Lower the budget cap — the NEXT side effect is refused if over the new cap
    /// (fail-closed; IV-R2).
    pub fn lower_cap(&mut self, new_cap: BudgetCap) {
        self.budget_kill.lower_cap(new_cap);
    }

    /// Revoke the egress grant — the next frontier re-derivation yields `None`
    /// (fail-closed; the job continues LOCAL-only — IV-R1).
    pub fn revoke_grant(&mut self) {
        self.grant = self.grant.map(EgressGrant::revoke);
    }

    /// Install an owner-approved egress grant minted by the inbound remote-approval
    /// path (ENDGAME E4) — the "proceed" half of "away → ping → reply → proceed".
    /// When the runner previously hit a gated frontier action it could NOT fire
    /// (no grant ⇒ `FrontierDenied`), the owner's phone reply mints a NARROW
    /// single-shot grant; installing it ARMS the runner so the next frontier tick
    /// re-derives a valid `EgressCapability` (fail-closed on expiry/rate/revoke) and
    /// the one denied action proceeds. The per-grant rate counter resets to `0`: the
    /// new grant carries its OWN bound (a narrow inbound approval is `max_actions = 1`,
    /// so EXACTLY ONE frontier action can fire, then the re-derivation yields `None`).
    /// The runner still MINTS nothing (it stores the grant; the capability is
    /// re-derived per turn — IV-R1) and holds no secret/wallet (PD-6).
    pub fn install_egress_grant(&mut self, grant: EgressGrant) {
        self.grant = Some(grant);
        self.egress_actions_used_u32 = 0;
    }

    /// Install an owner-approved MUTATE-LOCAL grant — the "proceed" half mirror of
    /// [`install_egress_grant`](Self::install_egress_grant) for AGENT-PROPOSED side
    /// effects (ENDGAME E10-2b). Sources: a tier-correct telegram approval (a
    /// single-shot grant, `max_actions = 1`) or a broad owner-armed autonomy window
    /// (`MUTATE_ARM_PHRASE`). The per-grant mutate rate counter resets to 0 (the new
    /// grant carries its OWN bound). The runner still MINTS nothing (it stores the
    /// grant; the capability is re-derived per action — IV-A9) and holds no
    /// secret/wallet (PD-6). Tier-distinct: an `EgressGrant` cannot be installed
    /// here (the parameter type is `MutateGrant` — IV-A5), so an egress approval
    /// grants ZERO mutate authority.
    pub fn install_mutate_grant(&mut self, grant: MutateGrant) {
        self.mutate_grant = Some(grant);
        self.mutate_actions_used_u32 = 0;
    }

    /// Install an owner-armed COMPOSITE BOLD SESSION grant (ENDGAME E13-4 / ⑳) — arms
    /// BOTH the egress and the mutate-local halves at once by installing each component
    /// through its EXISTING path ([`install_egress_grant`](Self::install_egress_grant) /
    /// [`install_mutate_grant`](Self::install_mutate_grant), each resetting its own
    /// per-grant rate). The runtime adds NO new authority field and NO new capability
    /// type: the egress tick re-derives an `EgressCapability` from the egress half, and
    /// [`proceed_authorized_mutate`](Self::proceed_authorized_mutate) re-derives a
    /// `MutateCapability` from the mutate half — both per action at the live
    /// `(now, used)` (IV-R1 / IV-A9 / ⑳ IV-BS6), fail-closed. The session is
    /// bold-within-bounds: the agent's proposed edits + runs auto-execute within the
    /// bound with NO per-action approval, and an in-session frontier consult fires within
    /// the egress bound. The runner still MINTS nothing and holds no secret/wallet;
    /// CUSTODY is unreachable (PD-6, uninhabited) and DOWNLOAD is absent (D-BS4).
    pub fn install_bold_session(&mut self, bold: &crate::commands::grant::BoldSessionGrant) {
        self.install_egress_grant(*bold.egress());
        self.install_mutate_grant(*bold.mutate());
    }

    /// Revoke the mutate grant — the next proceed re-derivation yields `None`
    /// (fail-closed; the agent-proposed side effects stop — IV-A11).
    pub fn revoke_mutate_grant(&mut self) {
        self.mutate_grant = self.mutate_grant.map(MutateGrant::revoke);
    }

    /// PROCEED with ONE owner-authorized agent-proposed mutate — the EXECUTE half
    /// of "away → ping → reply → proceed", and the per-action step of an armed
    /// mutate window (ENDGAME E10-2b). The order is the security spine: control
    /// re-read (a terminal/paused runner proceeds nothing) → RE-DERIVE the
    /// [`MutateCapability`] from the installed grant at the LIVE `(now, used)`
    /// (IV-A9, fail-closed on expired/rate/revoked) → (only then) the SINGLE gated
    /// chokepoint ([`execute_authorized_mutate`], IV-A1). No grant / an invalid
    /// grant ⇒ [`MutateProceedOutcome::MutateDenied`] — ZERO side effect, no silent
    /// fallback (IV-A11). Custody is unreachable (PD-6, IV-A10). `action` is the
    /// loaded proposal the owner approved; the caller binds WHICH proposal (a
    /// single-shot grant bounds it to exactly one).
    pub fn proceed_authorized_mutate(
        &mut self,
        now_epoch_ms: u64,
        action: &AuthorizedMutate<'_>,
    ) -> MutateProceedOutcome {
        if self.is_terminal() {
            return MutateProceedOutcome::Terminated;
        }
        if self.is_paused() {
            return MutateProceedOutcome::Paused;
        }
        // RE-DERIVE the capability at the LIVE (now, used) — never cached (IV-A9).
        let Some(grant) = self.mutate_grant.as_ref() else {
            return MutateProceedOutcome::MutateDenied;
        };
        let Some(capability) =
            MutateCapability::from_grant(grant, now_epoch_ms, self.mutate_actions_used_u32)
        else {
            return MutateProceedOutcome::MutateDenied;
        };
        // The single gated chokepoint runs the side effect; one capability = one
        // action, so the rate count advances exactly once per proceed (IV-A9).
        let outcome = execute_authorized_mutate(capability, action);
        self.mutate_actions_used_u32 = self.mutate_actions_used_u32.saturating_add(1);
        MutateProceedOutcome::Ran(outcome)
    }

    /// MUTATE actions consumed under the installed grant so far (the rate budget
    /// used).
    #[must_use]
    pub const fn mutate_actions_used(&self) -> u32 {
        self.mutate_actions_used_u32
    }

    /// Try to admit an INTERACTIVE request against the concurrency bound. The
    /// background job never takes the interactive-reserved slot, so this succeeds
    /// even while the background job is live (interactive never starves — IV-R4).
    pub const fn try_admit_interactive(&mut self) -> bool {
        self.admission.try_admit(AdmissionLane::Interactive)
    }

    /// The current job state (from the canonical no-zombie rail), or `None` if the
    /// job row is gone.
    #[must_use]
    pub fn job_state(&self) -> Option<JobState> {
        self.inbox
            .list()
            .iter()
            .find(|i| i.job_id_u64 == self.job_id_u64)
            .map(|i| i.state)
    }

    /// Whether the job is terminal (killed / done) — `tick` is then a no-op.
    #[must_use]
    pub fn is_terminal(&self) -> bool {
        self.job_state().is_none_or(JobState::is_terminal)
    }

    /// Whether the job is paused (rail `Paused` OR the express control has halted
    /// the next side effect).
    #[must_use]
    pub fn is_paused(&self) -> bool {
        matches!(self.job_state(), Some(JobState::Paused))
            || !self.control.next_side_effect_allowed()
    }

    /// Egress actions consumed under the grant so far (the rate budget used).
    #[must_use]
    pub const fn egress_actions_used(&self) -> u32 {
        self.egress_actions_used_u32
    }

    /// Whether an owner-armed egress SESSION is LIVE at `now_epoch_ms` (ENDGAME
    /// E13-2 / ⑱ — the remote-control reply gate, IV-RC5). RE-DERIVES the
    /// [`EgressCapability`] from the installed grant at the LIVE `(now, used)` — the
    /// SAME fail-closed derivation [`tick`](Self::tick) uses — and is `true` IFF a
    /// valid capability results (no grant / expired / rate-exceeded / revoked ⇒
    /// `false`). Under Option A the arm gates the ENTIRE chat loop: an inbound owner
    /// message runs a turn + reply ONLY when this is `true`; otherwise it is a card
    /// only (no turn, no send). The session's `max_actions` bounds the replies (each
    /// delivered reply consumes one action via [`record_egress_action`]). The
    /// `from_grant` re-derivation stays INSIDE `runtime.rs` (the foreseen e0d
    /// CHECK-B owner-path home) — the runner still MINTS nothing and holds no
    /// secret/wallet (PD-6).
    #[must_use]
    pub fn egress_armed_at(&self, now_epoch_ms: u64) -> bool {
        self.grant.as_ref().is_some_and(|g| {
            EgressCapability::from_grant(g, now_epoch_ms, self.egress_actions_used_u32).is_some()
        })
    }

    /// Consume ONE egress action of the armed session's rate budget (ENDGAME E13-2
    /// / ⑱) — called once per DELIVERED remote-control reply so replies are bounded
    /// by the grant's `max_actions` (IV-RC5/RC8). A delivered reply IS an egress
    /// side effect, so this mirrors the frontier-tick rate advance in
    /// [`tick`](Self::tick). The capability stays re-derived per use (never cached);
    /// this only advances the used-count the re-derivation reads, so once the count
    /// reaches `max_actions` the next [`egress_armed_at`](Self::egress_armed_at)
    /// re-derives `None` (fail-closed) and further replies are withheld.
    pub const fn record_egress_action(&mut self) {
        self.egress_actions_used_u32 = self.egress_actions_used_u32.saturating_add(1);
    }

    /// Autonomous turns run so far (local or frontier).
    #[must_use]
    pub const fn turns_run(&self) -> u32 {
        self.turn_u32
    }

    /// The REAL supervisor render-state for the daemon status surface (no longer a
    /// static "phase 0 control surface only" view): `Running` while live, `Stopped`
    /// (Unknown — never a false green) once terminal. Holds no secret/wallet.
    #[must_use]
    pub fn supervisor_view(&self) -> DaemonSupervisorView {
        let id = u32::try_from(self.job_id_u64).unwrap_or(u32::MAX);
        if self.is_terminal() {
            DaemonSupervisorView::stopped(id)
        } else {
            DaemonSupervisorView::started(id, 1)
        }
    }
}

/// A thin `std::thread`-backed pump for the live `sinabro daemon` command. It owns
/// NO business logic (IV-R10): it locks the shared [`AutonomyRuntime`], honors a
/// terminal/paused state, and calls the caller-supplied `driver` (which owns the
/// transport + memory state + clock) to advance ONE tick. A `kill` makes the next
/// loop turn observe a terminal job, so the worker breaks and [`join`](Self::join)
/// returns (no zombie). A poisoned lock stops the worker fail-closed.
pub struct RuntimeHandle {
    shared: Arc<Mutex<AutonomyRuntime>>,
    join: Option<JoinHandle<()>>,
}

impl RuntimeHandle {
    /// Spawn the worker thread. `driver(&mut runtime) -> bool` advances one tick
    /// (building the transport / memory state / `now` it owns) and returns whether
    /// to keep going. The worker stops on a terminal job, a `false` driver result,
    /// or a poisoned lock. `idle` is the sleep between turns while paused (so a
    /// paused worker does not busy-spin).
    #[must_use]
    pub fn spawn<D>(runtime: AutonomyRuntime, mut driver: D, idle: Duration) -> Self
    where
        D: FnMut(&mut AutonomyRuntime) -> bool + Send + 'static,
    {
        let shared = Arc::new(Mutex::new(runtime));
        let worker = Arc::clone(&shared);
        let join = std::thread::spawn(move || {
            loop {
                // A poisoned lock (a panicked holder) stops the worker fail-closed.
                let Ok(mut rt) = worker.lock() else { break };
                if rt.is_terminal() {
                    break;
                }
                if rt.is_paused() {
                    drop(rt);
                    std::thread::sleep(idle);
                    continue;
                }
                let keep = driver(&mut rt);
                drop(rt);
                if !keep {
                    break;
                }
            }
        });
        Self {
            shared,
            join: Some(join),
        }
    }

    /// Pause the live job.
    pub fn pause(&self) {
        if let Ok(mut rt) = self.shared.lock() {
            rt.pause();
        }
    }

    /// Resume the live job.
    pub fn resume(&self) {
        if let Ok(mut rt) = self.shared.lock() {
            rt.resume();
        }
    }

    /// Kill the live job — the worker observes the terminal job on its next loop
    /// turn and breaks; [`join`](Self::join) then returns (no zombie, IV-R3).
    pub fn kill(&self) {
        if let Ok(mut rt) = self.shared.lock() {
            rt.kill();
        }
    }

    /// The live supervisor render-state (REAL state — replaces the static view).
    #[must_use]
    pub fn supervisor_view(&self) -> Option<DaemonSupervisorView> {
        self.shared.lock().ok().map(|rt| rt.supervisor_view())
    }

    /// Autonomous turns run so far (a live snapshot).
    #[must_use]
    pub fn turns_run(&self) -> Option<u32> {
        self.shared.lock().ok().map(|rt| rt.turns_run())
    }

    /// Join the worker (after a kill or natural completion). Returning is itself the
    /// no-zombie proof: a worker that ignored `kill` would hang here forever.
    pub fn join(mut self) {
        if let Some(j) = self.join.take() {
            let _ = j.join();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::agent_loop::{AgentTransport, AgentTransportError, AgentTurn, FnTransport};
    use crate::commands::authority::test_egress_capability_grant;
    use mnemos_b_memory::{MemoryId, MemoryIndexRecord, TombstonePolicy};

    fn trace() -> StageFTraceLink {
        StageFTraceLink::new([0x53; 32], 700, 0)
    }

    /// A scripted transport that records how many turns it served (so a denied /
    /// budget-stopped tick can be PROVEN to have fired NO turn — zero egress).
    struct CountingTransport {
        calls: u32,
    }
    impl AgentTransport for CountingTransport {
        fn turn(
            &mut self,
            _system: &str,
            _user_message: &str,
        ) -> Result<AgentTurn, AgentTransportError> {
            self.calls += 1;
            Ok(AgentTurn {
                answer_text: "ANSWER: done".to_string(),
                input_tokens_u64: 1,
                output_tokens_u64: 1,
                cached_tokens_u64: 0,
            })
        }
    }

    /// One id-to-content pair (kept as a named alias so the empty-state helper's
    /// return type is not flagged `clippy::type_complexity`).
    type IdContent = (MemoryId, &'static [u8]);

    fn empty_state_parts() -> (Vec<MemoryIndexRecord>, Vec<IdContent>, TombstonePolicy) {
        (Vec::new(), Vec::new(), TombstonePolicy::new())
    }

    fn budget(token_cap: u32) -> BudgetCap {
        BudgetCap::new(token_cap, 1_000_000, 1_000_000)
    }

    /// IV-R8 / IV-R1: with NO grant, the autonomous default is LOCAL and a bounded
    /// job runs (READ-class, free); the egress action count never advances.
    #[test]
    fn no_grant_runs_local_default_and_never_egresses() {
        let mut rt = AutonomyRuntime::arm(700, None, budget(1_000), 2, trace());
        let (records, contents, policy) = empty_state_parts();
        let state = MemoryToolState {
            records: &records,
            contents: &contents,
            policy: &policy,
        };
        let mut transport = CountingTransport { calls: 0 };
        let out = rt.tick(
            1,
            ConsultPhrase::None,
            "system",
            "audit the repo",
            &mut transport,
            &state,
        );
        assert!(matches!(
            out,
            TurnOutcome::Ran {
                route: ConsultRoute::LocalLoopback,
                ..
            }
        ));
        assert_eq!(
            rt.egress_actions_used(),
            0,
            "local is READ-class — no egress"
        );
        assert_eq!(rt.turns_run(), 1);
        assert_eq!(transport.calls, 1, "exactly one bounded local turn ran");
    }

    /// IV-R1 / IV-R8 SECURITY PROOF: an autonomous FRONTIER escalation WITHOUT a
    /// valid grant fails closed — ZERO egress, no silent downgrade to local.
    #[test]
    fn frontier_without_grant_fails_closed_zero_egress() {
        let mut rt = AutonomyRuntime::arm(701, None, budget(1_000), 2, trace());
        let (records, contents, policy) = empty_state_parts();
        let state = MemoryToolState {
            records: &records,
            contents: &contents,
            policy: &policy,
        };
        let mut transport = CountingTransport { calls: 0 };
        let out = rt.tick(
            1,
            ConsultPhrase::Frontier,
            "system",
            "ask the frontier",
            &mut transport,
            &state,
        );
        assert_eq!(out, TurnOutcome::FrontierDenied);
        assert_eq!(transport.calls, 0, "fail-closed: NO transport turn fired");
        assert_eq!(rt.egress_actions_used(), 0);
        assert_eq!(rt.turns_run(), 0, "a denied turn is not a run");
    }

    /// IV-R1: a VALID owner-armed grant lets a frontier escalation fire, and the
    /// egress action (rate) count advances — and once the rate cap is exhausted the
    /// next frontier turn fails closed (the grant re-derivation yields None).
    #[test]
    fn armed_grant_fires_frontier_then_rate_caps_fail_closed() {
        // a real owner-armed grant: max 1 action, expires at 10_000.
        let grant = test_egress_capability_grant(1, 10_000);
        let mut rt = AutonomyRuntime::arm(702, Some(grant), budget(1_000), 2, trace());
        let (records, contents, policy) = empty_state_parts();
        let state = MemoryToolState {
            records: &records,
            contents: &contents,
            policy: &policy,
        };
        let mut transport = CountingTransport { calls: 0 };
        // first frontier turn: valid grant (now=1 < 10_000, used=0 < 1) ⇒ fires.
        let out1 = rt.tick(
            1,
            ConsultPhrase::Frontier,
            "system",
            "q1",
            &mut transport,
            &state,
        );
        assert!(matches!(
            out1,
            TurnOutcome::Ran {
                route: ConsultRoute::Frontier,
                ..
            }
        ));
        assert_eq!(rt.egress_actions_used(), 1);
        assert_eq!(transport.calls, 1);
        // second frontier turn: used=1 >= max=1 ⇒ rate-exceeded ⇒ fail-closed.
        let out2 = rt.tick(
            2,
            ConsultPhrase::Frontier,
            "system",
            "q2",
            &mut transport,
            &state,
        );
        assert_eq!(out2, TurnOutcome::FrontierDenied);
        assert_eq!(transport.calls, 1, "rate cap stops the 2nd egress");
    }

    /// ENDGAME E4-3 — the FULL "away → ping → reply → proceed" loop, hermetic (no
    /// real network): the runner is DENIED a frontier egress (no grant); the owner's
    /// SCRIPTED phone reply mints a NARROW single-shot grant via the remote-approval
    /// coordinator; installing it ARMS the runner so the ONE denied action PROCEEDS;
    /// then the single-shot grant is spent and the next frontier turn fails closed.
    #[test]
    fn e4_away_ping_reply_proceed_fires_one_egress_then_caps() {
        use crate::daemon::approval_sync::ApprovalAction;
        use crate::daemon::remote_approval::{RemoteApprovalCoordinator, RemoteApprovalOutcome};
        use crate::telegram::inbound::InboundUpdate;
        use crate::telegram::inbound_auth::PendingApproval;

        const OWNER_CHAT: i64 = 31337;
        let mut rt = AutonomyRuntime::arm(720, None, budget(1_000), 2, trace());
        let (records, contents, policy) = empty_state_parts();
        let state = MemoryToolState {
            records: &records,
            contents: &contents,
            policy: &policy,
        };
        let mut transport = CountingTransport { calls: 0 };

        // AWAY: the runner wants a frontier egress but holds NO grant ⇒ denied, zero
        // egress (this is where the daemon would PING the owner's phone).
        let denied = rt.tick(
            1,
            ConsultPhrase::Frontier,
            "system",
            "ask the frontier",
            &mut transport,
            &state,
        );
        assert_eq!(denied, TurnOutcome::FrontierDenied);
        assert_eq!(transport.calls, 0, "no grant ⇒ zero egress");

        // The pending action the owner is asked to approve (named by its 16-hex id).
        let action = PendingApproval::new(
            crate::sha256_32(b"frontier egress: ask the frontier"),
            ApprovalAction::TelegramRemoteControl,
        );
        let mut coord = RemoteApprovalCoordinator::new(OWNER_CHAT);
        coord.add_pending(action);

        // REPLY: the owner's scripted phone reply (a real getUpdates would carry it).
        let owner_reply =
            InboundUpdate::new_bounded(1, OWNER_CHAT, &format!("approve {}", action.id16()));
        let outcome = coord.ingest_update(&owner_reply, 2);
        assert!(
            matches!(
                outcome,
                RemoteApprovalOutcome::Approved { action_hash_32, .. }
                    if action_hash_32 == action.action_hash_32
            ),
            "the owner's pinned reply must approve the named pending action"
        );
        let RemoteApprovalOutcome::Approved { grant, .. } = outcome else {
            return; // unreachable after the assert above (no panic — stays clippy-clean)
        };

        // PROCEED: install the minted grant ⇒ the next frontier tick fires ONCE.
        rt.install_egress_grant(grant);
        let proceeded = rt.tick(
            3,
            ConsultPhrase::Frontier,
            "system",
            "ask the frontier",
            &mut transport,
            &state,
        );
        assert!(matches!(
            proceeded,
            TurnOutcome::Ran {
                route: ConsultRoute::Frontier,
                ..
            }
        ));
        assert_eq!(transport.calls, 1, "the approved egress fired exactly once");
        assert_eq!(rt.egress_actions_used(), 1);

        // SINGLE-SHOT: the narrow grant is spent ⇒ a 2nd frontier turn fails closed.
        let after = rt.tick(
            4,
            ConsultPhrase::Frontier,
            "system",
            "again",
            &mut transport,
            &state,
        );
        assert_eq!(after, TurnOutcome::FrontierDenied);
        assert_eq!(transport.calls, 1, "single-shot: no second egress");
    }

    /// IV-R1: an EXPIRED grant (now >= expires_at) fails the frontier closed.
    #[test]
    fn expired_grant_fails_frontier_closed() {
        let grant = test_egress_capability_grant(5, 1_000);
        let mut rt = AutonomyRuntime::arm(703, Some(grant), budget(1_000), 2, trace());
        let (records, contents, policy) = empty_state_parts();
        let state = MemoryToolState {
            records: &records,
            contents: &contents,
            policy: &policy,
        };
        let mut transport = CountingTransport { calls: 0 };
        // now=1_000 >= expires_at=1_000 ⇒ expired ⇒ fail-closed.
        let out = rt.tick(
            1_000,
            ConsultPhrase::Frontier,
            "system",
            "q",
            &mut transport,
            &state,
        );
        assert_eq!(out, TurnOutcome::FrontierDenied);
        assert_eq!(transport.calls, 0);
    }

    /// IV-R1: a REVOKED grant fails the frontier closed (and a local turn still runs).
    #[test]
    fn revoked_grant_fails_frontier_but_local_still_runs() {
        let grant = test_egress_capability_grant(5, 10_000);
        let mut rt = AutonomyRuntime::arm(704, Some(grant), budget(1_000), 2, trace());
        rt.revoke_grant();
        let (records, contents, policy) = empty_state_parts();
        let state = MemoryToolState {
            records: &records,
            contents: &contents,
            policy: &policy,
        };
        let mut transport = CountingTransport { calls: 0 };
        let frontier = rt.tick(
            1,
            ConsultPhrase::Frontier,
            "system",
            "q",
            &mut transport,
            &state,
        );
        assert_eq!(frontier, TurnOutcome::FrontierDenied);
        // local still runs (revocation only closes egress; READ is unaffected).
        let local = rt.tick(
            1,
            ConsultPhrase::None,
            "system",
            "q",
            &mut transport,
            &state,
        );
        assert!(local.ran());
        assert_eq!(rt.egress_actions_used(), 0);
    }

    /// IV-R2: lowering the cap to zero stops the NEXT autonomous turn fail-closed
    /// (no transport turn fires).
    #[test]
    fn lower_cap_stops_next_turn_fail_closed() {
        let mut rt = AutonomyRuntime::arm(705, None, budget(1_000), 2, trace());
        let (records, contents, policy) = empty_state_parts();
        let state = MemoryToolState {
            records: &records,
            contents: &contents,
            policy: &policy,
        };
        let mut transport = CountingTransport { calls: 0 };
        assert!(
            rt.tick(1, ConsultPhrase::None, "s", "q", &mut transport, &state)
                .ran()
        );
        rt.lower_cap(BudgetCap::new(0, 0, 1_000_000));
        let out = rt.tick(2, ConsultPhrase::None, "s", "q", &mut transport, &state);
        assert!(matches!(out, TurnOutcome::BudgetStopped(_)));
        assert_eq!(
            transport.calls, 1,
            "the over-budget turn fired NO transport"
        );
    }

    /// IV-R3: a KILLED job's tick is a no-op (Terminated), and resume can NEVER
    /// resurrect it (no zombie).
    #[test]
    fn killed_job_tick_is_noop_and_resume_cannot_resurrect() {
        let mut rt = AutonomyRuntime::arm(706, None, budget(1_000), 2, trace());
        let (records, contents, policy) = empty_state_parts();
        let state = MemoryToolState {
            records: &records,
            contents: &contents,
            policy: &policy,
        };
        let mut transport = CountingTransport { calls: 0 };
        rt.kill();
        assert!(rt.is_terminal());
        let out = rt.tick(1, ConsultPhrase::None, "s", "q", &mut transport, &state);
        assert_eq!(out, TurnOutcome::Terminated);
        assert_eq!(transport.calls, 0, "a killed job runs nothing");
        // resume cannot resurrect a terminal job.
        rt.resume();
        assert!(rt.is_terminal(), "no zombie resurrection");
        assert_eq!(
            rt.tick(2, ConsultPhrase::None, "s", "q", &mut transport, &state),
            TurnOutcome::Terminated
        );
        assert_eq!(transport.calls, 0);
    }

    /// IV-R4: a paused job performs no side effect; resume re-enables it.
    #[test]
    fn paused_job_performs_no_side_effect_until_resume() {
        let mut rt = AutonomyRuntime::arm(707, None, budget(1_000), 2, trace());
        let (records, contents, policy) = empty_state_parts();
        let state = MemoryToolState {
            records: &records,
            contents: &contents,
            policy: &policy,
        };
        let mut transport = CountingTransport { calls: 0 };
        rt.pause();
        assert!(rt.is_paused());
        let out = rt.tick(1, ConsultPhrase::None, "s", "q", &mut transport, &state);
        assert_eq!(out, TurnOutcome::Paused);
        assert_eq!(transport.calls, 0, "a paused job fires no side effect");
        rt.resume();
        assert!(!rt.is_paused());
        assert!(
            rt.tick(2, ConsultPhrase::None, "s", "q", &mut transport, &state)
                .ran()
        );
        assert_eq!(transport.calls, 1);
    }

    /// IV-R4: the single background job never starves the interactive lane — an
    /// interactive request is admitted even while the background job is live.
    #[test]
    fn interactive_never_starves_behind_background() {
        let mut rt = AutonomyRuntime::arm(708, None, budget(1_000), 2, trace());
        // the background job already holds its slot; the interactive reserved slot
        // is still available.
        assert!(
            rt.try_admit_interactive(),
            "interactive preempts via the reserved slot"
        );
    }

    /// IV-R3 (threaded teardown): the REAL worker thread terminates on `kill` and
    /// `join` returns — a worker that ignored kill would hang join forever (the
    /// no-zombie proof at the thread boundary). The driver owns its transport/state.
    #[test]
    fn threaded_worker_terminates_on_kill_and_joins() {
        let rt = AutonomyRuntime::arm(709, None, budget(1_000_000), 2, trace());
        let handle = RuntimeHandle::spawn(
            rt,
            |rt: &mut AutonomyRuntime| -> bool {
                // one trivial bounded LOCAL tick per call; the driver owns its data.
                let records: Vec<MemoryIndexRecord> = Vec::new();
                let contents: Vec<(MemoryId, &[u8])> = Vec::new();
                let policy = TombstonePolicy::new();
                let state = MemoryToolState {
                    records: &records,
                    contents: &contents,
                    policy: &policy,
                };
                let mut transport = FnTransport(|_s: &str, _u: &str| {
                    Ok(AgentTurn {
                        answer_text: "ANSWER: ok".to_string(),
                        input_tokens_u64: 1,
                        output_tokens_u64: 1,
                        cached_tokens_u64: 0,
                    })
                });
                let _ = rt.tick(1, ConsultPhrase::None, "s", "q", &mut transport, &state);
                true // keep going until killed
            },
            Duration::from_millis(1),
        );
        // kill from the control side; join must return (no zombie).
        handle.kill();
        handle.join();
    }

    /// ENDGAME E10-2b (⑬) — the FULL "away → ping → reply → PROCEED-EXECUTE" loop
    /// for an AGENT-PROPOSED MUTATE, hermetic (no real network): the runner holds
    /// NO mutate grant ⇒ a proceed is DENIED (zero side effect); a ToolSideEffect
    /// pending action is APPROVED by the owner's pinned phone reply ⇒ a TIER-CORRECT
    /// single-shot MUTATE grant is minted (NOT an egress grant); installing it lets
    /// the ONE approved exec PROCEED through the gated chokepoint; the single-shot
    /// grant is then spent ⇒ a 2nd proceed fails closed.
    #[test]
    fn e10_mutate_away_ping_reply_proceed_executes_then_caps() {
        use crate::daemon::approval_sync::ApprovalAction;
        use crate::daemon::remote_approval::{RemoteApprovalCoordinator, RemoteApprovalOutcome};
        use crate::exec_proposal::ExecProposal;
        use crate::telegram::inbound::InboundUpdate;
        use crate::telegram::inbound_auth::PendingApproval;

        const OWNER_CHAT: i64 = 51515;
        let mut rt = AutonomyRuntime::arm(820, None, budget(1_000), 2, trace());
        let proposal = ExecProposal {
            command: "/bin/echo e10_mutate_live".to_string(),
        };
        let action = AuthorizedMutate::Exec(&proposal);

        // AWAY: no mutate grant ⇒ a proceed is DENIED (zero side effect, IV-A1).
        assert!(matches!(
            rt.proceed_authorized_mutate(1, &action),
            MutateProceedOutcome::MutateDenied
        ));
        assert_eq!(rt.mutate_actions_used(), 0);

        // the pending MUTATE action (a tool side effect) awaiting approval.
        let pending = PendingApproval::new(
            crate::sha256_32(b"exec proposal: /bin/echo e10_mutate_live"),
            ApprovalAction::ToolSideEffect,
        );
        let mut coord = RemoteApprovalCoordinator::new(OWNER_CHAT);
        coord.add_pending(pending);

        // REPLY: the owner's pinned phone reply approves the named action ⇒ a
        // TIER-CORRECT mutate grant (NOT an EgressGrant — IV-A5).
        let reply =
            InboundUpdate::new_bounded(1, OWNER_CHAT, &format!("approve {}", pending.id16()));
        let outcome = coord.ingest_update(&reply, 2);
        let RemoteApprovalOutcome::ApprovedMutate {
            grant,
            action_hash_32,
        } = outcome
        else {
            panic!("a tool-side-effect approval must mint a MUTATE grant, got {outcome:?}");
        };
        assert_eq!(action_hash_32, pending.action_hash_32);
        assert_eq!(grant.tier(), crate::commands::grant::GrantTier::MutateLocal);

        // PROCEED: install the minted mutate grant ⇒ the one approved exec runs.
        rt.install_mutate_grant(grant);
        assert!(matches!(
            rt.proceed_authorized_mutate(3, &action),
            MutateProceedOutcome::Ran(_)
        ));
        assert_eq!(rt.mutate_actions_used(), 1, "exactly one mutate fired");

        // SINGLE-SHOT: the narrow grant is spent ⇒ a 2nd proceed fails closed.
        assert!(matches!(
            rt.proceed_authorized_mutate(4, &action),
            MutateProceedOutcome::MutateDenied
        ));
        assert_eq!(rt.mutate_actions_used(), 1, "single-shot: no second mutate");
    }

    /// IV-A9 — a broad owner-armed MUTATE grant authorizes up to `max_actions`,
    /// then fails closed; a revoke closes it immediately (the opt-in autonomy
    /// window is bounded + revocable).
    #[test]
    fn e10_armed_mutate_grant_bounds_then_fails_closed() {
        use crate::command::ApprovalRequirement;
        use crate::commands::grant::{GrantBounds, MUTATE_ARM_PHRASE, arm_local_mutate_grant};
        use crate::exec_proposal::ExecProposal;
        use crate::repl::approval::ApprovalPrompt;

        let mut p = ApprovalPrompt::new(ApprovalRequirement::TypedPhrase, MUTATE_ARM_PHRASE);
        let grant = arm_local_mutate_grant(
            &mut p,
            MUTATE_ARM_PHRASE,
            [3u8; 32],
            GrantBounds {
                max_actions_u32: 2,
                expires_at_epoch_ms: 10_000,
            },
        )
        .expect("broad mutate grant arms");
        let mut rt = AutonomyRuntime::arm(821, None, budget(1_000), 2, trace());
        rt.install_mutate_grant(grant);
        let proposal = ExecProposal {
            command: "/bin/echo armed".to_string(),
        };
        let action = AuthorizedMutate::Exec(&proposal);
        // up to 2 proceeds run; the 3rd fails closed (rate cap).
        assert!(matches!(
            rt.proceed_authorized_mutate(1, &action),
            MutateProceedOutcome::Ran(_)
        ));
        assert!(matches!(
            rt.proceed_authorized_mutate(1, &action),
            MutateProceedOutcome::Ran(_)
        ));
        assert_eq!(rt.mutate_actions_used(), 2);
        assert!(matches!(
            rt.proceed_authorized_mutate(1, &action),
            MutateProceedOutcome::MutateDenied
        ));
        // re-arm a fresh grant, then revoke ⇒ the next proceed fails closed.
        let mut p2 = ApprovalPrompt::new(ApprovalRequirement::TypedPhrase, MUTATE_ARM_PHRASE);
        let grant2 = arm_local_mutate_grant(
            &mut p2,
            MUTATE_ARM_PHRASE,
            [4u8; 32],
            GrantBounds {
                max_actions_u32: 5,
                expires_at_epoch_ms: 10_000,
            },
        )
        .expect("re-arm");
        rt.install_mutate_grant(grant2);
        rt.revoke_mutate_grant();
        assert!(matches!(
            rt.proceed_authorized_mutate(1, &action),
            MutateProceedOutcome::MutateDenied
        ));
    }

    /// IV-A5 (tier separation) — an installed EGRESS grant grants ZERO mutate
    /// authority (the mutate grant field is separate + untouched), and a telegram
    /// approval of an EGRESS-tier action mints an egress `Approved`, NEVER
    /// `ApprovedMutate`. An egress approval can never authorize a mutate.
    #[test]
    fn e10_egress_grant_cannot_authorize_a_mutate() {
        use crate::commands::authority::test_egress_capability_grant;
        use crate::daemon::approval_sync::ApprovalAction;
        use crate::daemon::remote_approval::{RemoteApprovalCoordinator, RemoteApprovalOutcome};
        use crate::exec_proposal::ExecProposal;
        use crate::telegram::inbound::InboundUpdate;
        use crate::telegram::inbound_auth::PendingApproval;

        // an installed EGRESS grant does NOT enable a mutate proceed.
        let egress = test_egress_capability_grant(5, 10_000);
        let mut rt = AutonomyRuntime::arm(822, Some(egress), budget(1_000), 2, trace());
        let proposal = ExecProposal {
            command: "/bin/echo nope".to_string(),
        };
        assert!(
            matches!(
                rt.proceed_authorized_mutate(1, &AuthorizedMutate::Exec(&proposal)),
                MutateProceedOutcome::MutateDenied
            ),
            "an egress grant grants zero mutate authority (IV-A5)"
        );

        // a telegram approval of an EGRESS-tier action mints Approved (egress).
        const OWNER_CHAT: i64 = 6262;
        let egress_action = PendingApproval::new(
            crate::sha256_32(b"frontier egress action"),
            ApprovalAction::TelegramRemoteControl,
        );
        let mut coord = RemoteApprovalCoordinator::new(OWNER_CHAT);
        coord.add_pending(egress_action);
        let reply =
            InboundUpdate::new_bounded(1, OWNER_CHAT, &format!("approve {}", egress_action.id16()));
        assert!(
            matches!(
                coord.ingest_update(&reply, 2),
                RemoteApprovalOutcome::Approved { .. }
            ),
            "an egress-tier approval mints Approved (egress), never ApprovedMutate"
        );
    }

    /// E13-4 / ⑳ — installing a composite BOLD SESSION grant arms BOTH halves: the
    /// runner's egress is armed (`egress_armed_at`) AND an agent-proposed mutate
    /// proceeds within the bound; the shared bound caps it fail-closed.
    #[test]
    fn e13_4_bold_session_installs_both_egress_and_mutate() {
        use crate::command::ApprovalRequirement;
        use crate::commands::grant::{BOLD_ARM_PHRASE, GrantBounds, arm_local_bold_session};
        use crate::exec_proposal::ExecProposal;
        use crate::repl::approval::ApprovalPrompt;

        let mut p = ApprovalPrompt::new(ApprovalRequirement::TypedPhrase, BOLD_ARM_PHRASE);
        let bold = arm_local_bold_session(
            &mut p,
            BOLD_ARM_PHRASE,
            [7u8; 32],
            GrantBounds {
                max_actions_u32: 2,
                expires_at_epoch_ms: 10_000,
            },
        )
        .expect("bold session arms");
        let mut rt = AutonomyRuntime::arm(840, None, budget(1_000), 2, trace());
        rt.install_bold_session(&bold);

        // egress half: armed at now=1 (< TTL, used=0 < cap).
        assert!(
            rt.egress_armed_at(1),
            "the bold session arms the egress half"
        );

        // mutate half: an agent-proposed exec proceeds within the bound...
        let proposal = ExecProposal {
            command: "/bin/echo bold".to_string(),
        };
        let action = AuthorizedMutate::Exec(&proposal);
        assert!(matches!(
            rt.proceed_authorized_mutate(1, &action),
            MutateProceedOutcome::Ran(_)
        ));
        assert!(matches!(
            rt.proceed_authorized_mutate(1, &action),
            MutateProceedOutcome::Ran(_)
        ));
        assert_eq!(rt.mutate_actions_used(), 2);
        // ...and the 3rd fails closed at the shared cap.
        assert!(matches!(
            rt.proceed_authorized_mutate(1, &action),
            MutateProceedOutcome::MutateDenied
        ));
    }

    /// E13-4 / ⑳ — revoking the bold session (both halves) stops the next action
    /// fail-closed: egress disarms AND a mutate proceed is denied.
    #[test]
    fn e13_4_bold_session_revoke_closes_both_halves() {
        use crate::command::ApprovalRequirement;
        use crate::commands::grant::{BOLD_ARM_PHRASE, GrantBounds, arm_local_bold_session};
        use crate::exec_proposal::ExecProposal;
        use crate::repl::approval::ApprovalPrompt;

        let mut p = ApprovalPrompt::new(ApprovalRequirement::TypedPhrase, BOLD_ARM_PHRASE);
        let bold = arm_local_bold_session(
            &mut p,
            BOLD_ARM_PHRASE,
            [7u8; 32],
            GrantBounds {
                max_actions_u32: 5,
                expires_at_epoch_ms: 10_000,
            },
        )
        .expect("bold");
        let mut rt = AutonomyRuntime::arm(841, None, budget(1_000), 2, trace());
        rt.install_bold_session(&bold);
        rt.revoke_grant();
        rt.revoke_mutate_grant();
        assert!(!rt.egress_armed_at(1), "revoke closes the egress half");
        let proposal = ExecProposal {
            command: "/bin/echo nope".to_string(),
        };
        assert!(matches!(
            rt.proceed_authorized_mutate(1, &AuthorizedMutate::Exec(&proposal)),
            MutateProceedOutcome::MutateDenied
        ));
    }
}
