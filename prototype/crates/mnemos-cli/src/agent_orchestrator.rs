//! `agent_orchestrator` — the two-model orchestration loop (P1-2, the orchestrator
//! spine; plan `ops/evidence/stage_g/agent_loop/P1_ORCHESTRATOR_PLAN.md`).
//!
//! L1 of the three-layer separation: the OUTER loop that composes the frontier
//! reasoning brain and the local execution brain (Naite) into ONE consult —
//! frontier PLANS -> the plan is DECOMPOSED into typed sub-tasks (the
//! cross-language envelope, [`crate::provider::executor_route`]) -> each sub-task
//! is ROUTED to its specialist `(port, model_id)` and IMPLEMENTED by the local
//! brain -> the frontier SYNTHESIZES the implemented results.
//!
//! It is a NEW caller that chains the EXISTING, UNMODIFIED
//! [`crate::agent_loop::run_agent_loop_with`] N times with different injected
//! transports (R4 reconcile) — the loop driver is byte-untouched. Two-model by
//! INJECTION: the frontier transport and the per-sub-task local turn are passed
//! in (the dispatch verb wires the real owner-armed egress frontier + the loopback
//! local; tests script both). The router decision is the DETERMINISTIC pure
//! function (L2, [`crate::provider::executor_route::select_executor_route`]); the
//! model output stays advisory until verified (the P1-3 oracle gates "success").
//!
//! Drift-0 (META-LAW): the orchestration CONTROL FLOW is deterministic given the
//! transports' replies — the plan is decomposed by a fail-closed parser, each
//! sub-task is routed by the pure map, and a non-parsing plan stops typed
//! (`DecomposeFailed`) rather than guessing. custody/funds stay HARD-LOCKED: this
//! layer adds NO new capability, NO socket, NO mint — it only re-orders calls to
//! the already-gated loop driver.

use crate::agent_loop::{
    AGENT_LOOP_MAX_ITER, AGENT_LOOP_TOKEN_CAP, AgentLoopOutcome, AgentTransport, FnTransport,
    MemoryToolState, run_agent_loop_with,
};
use crate::provider::executor_route::{
    ExecutorRoutingTable, SubTask, parse_subtask_envelope, select_executor_route,
};
use crate::verification::{VerificationEvidence, VerificationReceipt, classify, verify};

/// Why the orchestration stopped (typed; never a guess).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OrchestratorStop {
    /// The full chain completed: plan -> decompose -> implement -> a synthesis answer.
    Synthesized,
    /// The frontier produced no plan answer (nothing to decompose).
    PlanEmpty,
    /// The plan did not parse as a `SUBTASK ...` envelope (fail-closed; no
    /// half-orchestration on a malformed plan).
    DecomposeFailed,
    /// The sub-tasks were implemented but the frontier synthesis produced no answer.
    SynthesisEmpty,
}

/// One routed + implemented sub-task: the decomposed `SubTask`, the `model_id` the
/// router selected for it (the dynamic-LoRA selection), and the local brain's
/// bounded loop receipt.
#[derive(Clone, Debug)]
pub struct RoutedImpl {
    /// The decomposed sub-task (carries the declared expert `kind`).
    pub subtask: SubTask,
    /// The loopback `port` the router selected for this sub-task's worker — Macro mode:
    /// a per-chain worker on its OWN port (the routing table's `port` field is now
    /// load-bearing, not just `model_id`). Mode A serves every kind from one port.
    pub port: u16,
    /// The `model_id` the router selected for this sub-task's `kind`.
    pub model_id: String,
    /// The local brain's bounded loop outcome for this sub-task.
    pub outcome: AgentLoopOutcome,
    /// The Typed-Write-Admission receipt (P1-3, the P-HALL anchor): the
    /// class-typed ORACLE verdict that gates a permanent Write — NEVER the model's
    /// own self-judgment of "success".
    pub receipt: VerificationReceipt,
}

/// The orchestrated consult receipt: the frontier plan, the routed+implemented
/// sub-tasks (in plan order), the frontier synthesis, and the typed stop.
#[derive(Clone, Debug)]
pub struct OrchestratedOutcome {
    /// The frontier's plan text (the decompose input); `None` if the plan was empty.
    pub plan: Option<String>,
    /// Each sub-task routed to its specialist and implemented locally (plan order).
    pub subtasks: Vec<RoutedImpl>,
    /// The frontier's synthesis over the implemented results; `None` if empty.
    pub synthesis: Option<String>,
    /// Why the orchestration stopped.
    pub stop: OrchestratorStop,
}

impl OrchestratedOutcome {
    /// The model_ids the router selected, in plan order (the dynamic-LoRA trail).
    #[must_use]
    pub fn routed_model_ids(&self) -> Vec<&str> {
        self.subtasks.iter().map(|r| r.model_id.as_str()).collect()
    }

    /// The worker ports the router selected, in plan order (the Macro trail: distinct
    /// ports ⇒ per-chain worker processes; one port ⇒ mode A sequential switching).
    #[must_use]
    pub fn routed_ports(&self) -> Vec<u16> {
        self.subtasks.iter().map(|r| r.port).collect()
    }

    /// Sub-tasks whose local implementation produced an answer.
    #[must_use]
    pub fn implemented_count(&self) -> usize {
        self.subtasks
            .iter()
            .filter(|r| r.outcome.answer.is_some())
            .count()
    }

    /// Sub-tasks whose verification receipt ADMITS a permanent Write (the P-HALL
    /// gate: only an oracle-`Verified` receipt admits; advisory / unverified
    /// sub-tasks never do — the model never writes a self-certified "success").
    #[must_use]
    pub fn write_admitted_count(&self) -> usize {
        self.subtasks
            .iter()
            .filter(|r| r.receipt.admits_write())
            .count()
    }
}

/// Build the deterministic synthesis input from the implemented sub-task results
/// (stable order, no model judgment) — the frontier reads this to synthesize.
fn build_synthesis_input(task: &str, routed: &[RoutedImpl]) -> String {
    use std::fmt::Write as _;
    let mut s = String::new();
    let _ = writeln!(s, "TASK: {task}");
    s.push_str("IMPLEMENTED SUB-TASKS:\n");
    for r in routed {
        let answer = r.outcome.answer.as_deref().unwrap_or("(no answer)");
        let _ = writeln!(
            s,
            "- id={} kind={} model={} :: {answer}",
            r.subtask.id,
            r.subtask.kind.label(),
            r.model_id
        );
    }
    s
}

/// The result of the PLAN phase alone (B⑬ Plan Mode's INERT half): the frontier plan text + the
/// parsed sub-tasks, or a typed reason it produced none. NO local implement, NO synthesis, NO write
/// — the owner reviews/approves the sub-tasks before the (costly) implement+synthesize phases run.
#[derive(Clone, Debug)]
pub enum PlanPhase {
    /// The frontier planned AND the plan decomposed into >=1 sub-task (ready for owner approval).
    Ready {
        /// The frontier's raw plan text.
        plan: String,
        /// The decomposed sub-tasks (plan order).
        subtasks: Vec<SubTask>,
    },
    /// The frontier produced no plan answer (nothing to decompose).
    PlanEmpty,
    /// The plan did not parse as a `SUBTASK ...` envelope (fail-closed; the raw plan is kept for review).
    DecomposeFailed {
        /// The frontier's raw plan text (so the owner can see what was produced).
        plan: String,
    },
}

/// Resolve the orchestration caps (`0` ⇒ the single-loop defaults).
const fn orchestrate_caps(max_iter_u8: u8, token_cap_u32: u32) -> (u8, u32) {
    (
        if max_iter_u8 == 0 {
            AGENT_LOOP_MAX_ITER
        } else {
            max_iter_u8
        },
        if token_cap_u32 == 0 {
            AGENT_LOOP_TOKEN_CAP
        } else {
            token_cap_u32
        },
    )
}

/// PLAN + DECOMPOSE only (phases 1-2 of [`run_orchestrated_consult`]) — the INERT half of B⑬ Plan
/// Mode. Runs the frontier PLAN turn then the deterministic fail-closed decompose; NO local
/// implement, NO synthesis, NO write. The owner reviews/approves the returned sub-tasks before
/// [`run_orchestrated_from_subtasks`] runs the implement+synthesize phases.
pub fn run_orchestrated_plan_only(
    frontier: &mut dyn AgentTransport,
    state: &MemoryToolState<'_>,
    plan_system: &str,
    task: &str,
    max_iter_u8: u8,
    token_cap_u32: u32,
) -> PlanPhase {
    let (max_iter, token_cap) = orchestrate_caps(max_iter_u8, token_cap_u32);
    let plan_outcome = run_agent_loop_with(
        frontier,
        state,
        plan_system,
        task,
        max_iter,
        token_cap,
        None,
        None,
        None,
    );
    let Some(plan) = plan_outcome.answer else {
        return PlanPhase::PlanEmpty;
    };
    match parse_subtask_envelope(&plan) {
        Some(subtasks) => PlanPhase::Ready { plan, subtasks },
        None => PlanPhase::DecomposeFailed { plan },
    }
}

/// IMPLEMENT + SYNTHESIZE (phases 3-4 of [`run_orchestrated_consult`]) over an ALREADY-DECOMPOSED
/// (for B⑬ Plan Mode, owner-APPROVED) sub-task list: ROUTE each sub-task -> local IMPLEMENT loop ->
/// typed verify-oracle receipt -> frontier SYNTHESIZE. `plan` is echoed back in the outcome. An
/// EMPTY `subtasks` (e.g. the owner disabled every one) ⇒ `DecomposeFailed` (nothing to run).
#[allow(clippy::too_many_arguments, clippy::type_complexity)]
pub fn run_orchestrated_from_subtasks(
    frontier: &mut dyn AgentTransport,
    local_turn: &mut dyn FnMut(
        u16,
        &str,
        &str,
        &str,
    ) -> Result<
        crate::agent_loop::AgentTurn,
        crate::agent_loop::AgentTransportError,
    >,
    verify_oracle: &mut dyn FnMut(&SubTask, &AgentLoopOutcome) -> VerificationEvidence,
    table: &ExecutorRoutingTable,
    state: &MemoryToolState<'_>,
    impl_system: &str,
    synth_system: &str,
    task: &str,
    plan: String,
    subtasks: Vec<SubTask>,
    max_iter_u8: u8,
    token_cap_u32: u32,
) -> OrchestratedOutcome {
    let (max_iter, token_cap) = orchestrate_caps(max_iter_u8, token_cap_u32);
    if subtasks.is_empty() {
        return OrchestratedOutcome {
            plan: Some(plan),
            subtasks: Vec::new(),
            synthesis: None,
            stop: OrchestratorStop::DecomposeFailed,
        };
    }
    // 3. IMPLEMENT each sub-task: ROUTE (pure L2) -> local brain with the selected
    //    (port, model_id) on the wire (R1 seam).
    let mut routed: Vec<RoutedImpl> = Vec::new();
    for subtask in subtasks {
        let route = select_executor_route(&subtask.kind, table);
        let port = route.port;
        let model_id = route.model_id.clone();
        let outcome = {
            let mut local_tx = FnTransport(|system: &str, user: &str| {
                local_turn(port, model_id.as_str(), system, user)
            });
            run_agent_loop_with(
                &mut local_tx,
                state,
                impl_system,
                &subtask.goal,
                max_iter,
                token_cap,
                None,
                None,
                None,
            )
        };
        // P1-3 (full): the Typed-Write-Admission verify step — the receipt comes from the
        // class-typed ORACLE evidence, NEVER the model's self-judgment (the P-HALL anchor).
        let evidence = verify_oracle(&subtask, &outcome);
        let receipt = verify(classify(&subtask.kind), &evidence);
        routed.push(RoutedImpl {
            subtask,
            port,
            model_id,
            outcome,
            receipt,
        });
    }

    // 4. SYNTHESIZE (frontier reasoning brain) over the implemented results.
    let synth_input = build_synthesis_input(task, &routed);
    let synth_outcome = run_agent_loop_with(
        frontier,
        state,
        synth_system,
        &synth_input,
        max_iter,
        token_cap,
        None,
        None,
        None,
    );
    let synthesis = synth_outcome.answer.clone();
    let stop = if synthesis.is_some() {
        OrchestratorStop::Synthesized
    } else {
        OrchestratorStop::SynthesisEmpty
    };
    OrchestratedOutcome {
        plan: Some(plan),
        subtasks: routed,
        synthesis,
        stop,
    }
}

/// Run the two-model orchestration loop (P1-2): frontier PLAN -> deterministic
/// DECOMPOSE -> per-sub-task ROUTE + local IMPLEMENT -> frontier SYNTHESIZE.
///
/// `frontier` serves the PLAN and SYNTHESIZE turns; `local_turn(model_id, system,
/// user)` serves each sub-task's IMPLEMENT loop with the router-selected
/// `model_id` placed on the wire (the R1 seam). `run_agent_loop_with` is called
/// once per stage, UNMODIFIED — this is purely a new ordering of gated loop calls.
/// Caps default to the single-loop bounds when `0` is passed.
#[allow(clippy::too_many_arguments, clippy::type_complexity)]
pub fn run_orchestrated_consult(
    frontier: &mut dyn AgentTransport,
    local_turn: &mut dyn FnMut(
        u16,
        &str,
        &str,
        &str,
    ) -> Result<
        crate::agent_loop::AgentTurn,
        crate::agent_loop::AgentTransportError,
    >,
    verify_oracle: &mut dyn FnMut(&SubTask, &AgentLoopOutcome) -> VerificationEvidence,
    table: &ExecutorRoutingTable,
    state: &MemoryToolState<'_>,
    plan_system: &str,
    impl_system: &str,
    synth_system: &str,
    task: &str,
    max_iter_u8: u8,
    token_cap_u32: u32,
) -> OrchestratedOutcome {
    // Composed from the two reusable phases (B⑬ Plan Mode shares these): PLAN+DECOMPOSE then, on a
    // ready plan, IMPLEMENT+SYNTHESIZE. Behavior is identical to the former straight-through body.
    match run_orchestrated_plan_only(
        frontier,
        state,
        plan_system,
        task,
        max_iter_u8,
        token_cap_u32,
    ) {
        PlanPhase::PlanEmpty => OrchestratedOutcome {
            plan: None,
            subtasks: Vec::new(),
            synthesis: None,
            stop: OrchestratorStop::PlanEmpty,
        },
        PlanPhase::DecomposeFailed { plan } => OrchestratedOutcome {
            plan: Some(plan),
            subtasks: Vec::new(),
            synthesis: None,
            stop: OrchestratorStop::DecomposeFailed,
        },
        PlanPhase::Ready { plan, subtasks } => run_orchestrated_from_subtasks(
            frontier,
            local_turn,
            verify_oracle,
            table,
            state,
            impl_system,
            synth_system,
            task,
            plan,
            subtasks,
            max_iter_u8,
            token_cap_u32,
        ),
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use super::*;
    use crate::agent_loop::{AgentTransport, AgentTransportError, AgentTurn, MemoryToolState};
    use crate::provider::executor_route::default_routing_table;
    use mnemos_b_memory::TombstonePolicy;

    /// A frontier transport scripted with one reply per turn (PLAN then SYNTHESIZE).
    struct ScriptedFrontier {
        replies: Vec<&'static str>,
        calls: usize,
    }
    impl AgentTransport for ScriptedFrontier {
        fn turn(&mut self, _system: &str, _user: &str) -> Result<AgentTurn, AgentTransportError> {
            let reply = self
                .replies
                .get(self.calls)
                .copied()
                .unwrap_or("ANSWER: out");
            self.calls += 1;
            Ok(AgentTurn {
                answer_text: reply.to_string(),
                input_tokens_u64: 10,
                output_tokens_u64: 5,
                cached_tokens_u64: 0,
            })
        }
    }

    fn empty_state(policy: &TombstonePolicy) -> MemoryToolState<'_> {
        MemoryToolState {
            records: &[],
            contents: &[],
            policy,
        }
    }

    /// THE TWO-MODEL ORCHESTRATION PROOF (P1-2 DoD): a frontier plan that
    /// decomposes into two differently-typed sub-tasks routes EACH to its
    /// specialist model_id (drift-0 via the pure L2 router), the local brain
    /// implements each with that model_id ON THE WIRE, and the frontier
    /// synthesizes — all deterministic, no network.
    #[test]
    fn full_chain_routes_each_subtask_and_synthesizes() {
        let policy = TombstonePolicy::new();
        let state = empty_state(&policy);
        let table = default_routing_table();

        // Frontier: PLAN (a 2-line SUBTASK envelope) then SYNTHESIZE.
        let mut frontier = ScriptedFrontier {
            replies: vec![
                "SUBTASK 1 sui_move - build the transfer module\nSUBTASK 2 solana_anchor 1 port it to anchor",
                "ANSWER: synthesized both implementations",
            ],
            calls: 0,
        };
        // Local: echo which model_id it was invoked with (proves the wire selector).
        let mut seen_models: Vec<String> = Vec::new();
        let mut local_turn = |_port: u16,
                              model_id: &str,
                              _system: &str,
                              _user: &str|
         -> Result<AgentTurn, AgentTransportError> {
            seen_models.push(model_id.to_string());
            Ok(AgentTurn {
                answer_text: format!("ANSWER: implemented via {model_id}"),
                input_tokens_u64: 4,
                output_tokens_u64: 2,
                cached_tokens_u64: 0,
            })
        };

        let mut no_oracle = |_: &SubTask, _: &AgentLoopOutcome| -> VerificationEvidence {
            VerificationEvidence::Absent
        };
        let out = run_orchestrated_consult(
            &mut frontier,
            &mut local_turn,
            &mut no_oracle,
            &table,
            &state,
            "plan-system",
            "impl-system",
            "synth-system",
            "ship the transfer flow on both chains",
            0,
            0,
        );

        assert_eq!(out.stop, OrchestratorStop::Synthesized);
        assert_eq!(out.subtasks.len(), 2);
        // Each sub-task routed to its specialist (drift-0): different kinds ->
        // different model_ids, matching the router table.
        assert_eq!(
            out.routed_model_ids(),
            vec!["naite_sui_move", "naite_solana_anchor"]
        );
        // And those exact model_ids reached the local brain (the wire selector).
        assert_eq!(seen_models, vec!["naite_sui_move", "naite_solana_anchor"]);
        assert_eq!(out.implemented_count(), 2);
        assert_eq!(
            out.synthesis.as_deref(),
            Some("synthesized both implementations")
        );
        assert_eq!(frontier.calls, 2, "frontier serves PLAN + SYNTHESIZE only");
        // P1-3: both sub-tasks are Code class; no oracle evidence (Absent) ⇒
        // NotApplicable ⇒ NONE admits a Write (the model never self-certifies).
        assert!(
            out.subtasks
                .iter()
                .all(|r| r.receipt.class == crate::verification::VerificationClass::Code),
            "sui_move + solana_anchor are code class"
        );
        assert_eq!(
            out.write_admitted_count(),
            0,
            "un-run oracle admits no write"
        );
    }

    /// B⑬ PLAN-ONLY (the INERT half): the frontier PLAN + deterministic decompose run WITHOUT
    /// implementing (this path has no local_turn). A valid envelope ⇒ `Ready` with the parsed
    /// sub-tasks (frontier served the PLAN turn ONLY); a non-SUBTASK reply ⇒ `DecomposeFailed`
    /// (the raw plan is kept for owner review).
    #[test]
    fn plan_only_decomposes_without_implementing() {
        let policy = TombstonePolicy::new();
        let state = empty_state(&policy);

        let mut frontier = ScriptedFrontier {
            replies: vec!["SUBTASK 1 sui_move - build it\nSUBTASK 2 audit 1 review it"],
            calls: 0,
        };
        match run_orchestrated_plan_only(&mut frontier, &state, "plan-system", "task", 0, 0) {
            PlanPhase::Ready { plan, subtasks } => {
                assert_eq!(subtasks.len(), 2);
                assert_eq!(subtasks[0].kind.label(), "sui_move");
                assert_eq!(subtasks[1].kind.label(), "audit");
                assert!(plan.contains("SUBTASK 1"));
            }
            other => panic!("expected Ready, got {other:?}"),
        }
        assert_eq!(
            frontier.calls, 1,
            "plan-only serves ONLY the PLAN turn (no synth, no implement)"
        );

        let mut prose = ScriptedFrontier {
            replies: vec!["ANSWER: I cannot decompose this into sub-tasks"],
            calls: 0,
        };
        match run_orchestrated_plan_only(&mut prose, &state, "plan-system", "task", 0, 0) {
            PlanPhase::DecomposeFailed { plan } => assert!(plan.contains("cannot decompose")),
            other => panic!("expected DecomposeFailed, got {other:?}"),
        }
    }

    /// B⑬ FROM-SUBTASKS (the active half): implement+synthesize over an owner-APPROVED sub-task
    /// list. A SUBSET (the owner disabled one) implements ONLY the approved ones; an EMPTY list
    /// (the owner disabled them all) ⇒ `DecomposeFailed` with NOTHING run (fail-closed).
    #[test]
    fn from_subtasks_implements_only_the_approved_subset() {
        let policy = TombstonePolicy::new();
        let state = empty_state(&policy);
        let table = default_routing_table();

        let all = crate::provider::executor_route::parse_subtask_envelope(
            "SUBTASK 1 sui_move - a\nSUBTASK 2 audit 1 b",
        )
        .unwrap();
        assert_eq!(all.len(), 2);
        // Owner approves ONLY sub-task 1 (disabled 2).
        let approved = vec![all.into_iter().next().unwrap()];

        let mut frontier = ScriptedFrontier {
            replies: vec!["ANSWER: synthesized one"],
            calls: 0,
        };
        let mut seen = 0usize;
        let mut local_turn = |_p: u16,
                              model_id: &str,
                              _s: &str,
                              _u: &str|
         -> Result<AgentTurn, AgentTransportError> {
            seen += 1;
            Ok(AgentTurn {
                answer_text: format!("ANSWER: did {model_id}"),
                input_tokens_u64: 1,
                output_tokens_u64: 1,
                cached_tokens_u64: 0,
            })
        };
        let mut no_oracle = |_: &SubTask, _: &AgentLoopOutcome| -> VerificationEvidence {
            VerificationEvidence::Absent
        };
        let out = run_orchestrated_from_subtasks(
            &mut frontier,
            &mut local_turn,
            &mut no_oracle,
            &table,
            &state,
            "impl",
            "synth",
            "task",
            "PLAN".to_string(),
            approved,
            0,
            0,
        );
        assert_eq!(out.subtasks.len(), 1, "only the approved sub-task ran");
        assert_eq!(seen, 1, "the disabled sub-task was never implemented");
        assert_eq!(out.stop, OrchestratorStop::Synthesized);
        assert_eq!(out.synthesis.as_deref(), Some("synthesized one"));

        // Owner disabled EVERYTHING ⇒ nothing to run (fail-closed; no implement, no synth).
        let mut f2 = ScriptedFrontier {
            replies: vec!["ANSWER: x"],
            calls: 0,
        };
        let mut lt2 =
            |_p: u16, _m: &str, _s: &str, _u: &str| -> Result<AgentTurn, AgentTransportError> {
                panic!("must not implement when the approved set is empty");
            };
        let mut no2 = |_: &SubTask, _: &AgentLoopOutcome| -> VerificationEvidence {
            VerificationEvidence::Absent
        };
        let empty = run_orchestrated_from_subtasks(
            &mut f2,
            &mut lt2,
            &mut no2,
            &table,
            &state,
            "impl",
            "synth",
            "task",
            "PLAN".to_string(),
            Vec::new(),
            0,
            0,
        );
        assert_eq!(empty.stop, OrchestratorStop::DecomposeFailed);
        assert!(empty.subtasks.is_empty());
        assert_eq!(f2.calls, 0, "no synthesis turn when nothing ran");
    }

    /// Fail-closed: a frontier plan that is NOT a SUBTASK envelope stops typed
    /// (`DecomposeFailed`) — no local brain is invoked, no half-orchestration.
    #[test]
    fn malformed_plan_fails_closed_without_implementing() {
        let policy = TombstonePolicy::new();
        let state = empty_state(&policy);
        let table = default_routing_table();
        let mut frontier = ScriptedFrontier {
            replies: vec!["ANSWER: here is a prose plan with no SUBTASK lines"],
            calls: 0,
        };
        let mut invoked = false;
        let mut local_turn = |_port: u16,
                              _model: &str,
                              _s: &str,
                              _u: &str|
         -> Result<AgentTurn, AgentTransportError> {
            invoked = true;
            Ok(AgentTurn {
                answer_text: "ANSWER: x".to_string(),
                input_tokens_u64: 0,
                output_tokens_u64: 0,
                cached_tokens_u64: 0,
            })
        };
        let mut no_oracle = |_: &SubTask, _: &AgentLoopOutcome| -> VerificationEvidence {
            VerificationEvidence::Absent
        };
        let out = run_orchestrated_consult(
            &mut frontier,
            &mut local_turn,
            &mut no_oracle,
            &table,
            &state,
            "p",
            "i",
            "s",
            "task",
            0,
            0,
        );
        assert_eq!(out.stop, OrchestratorStop::DecomposeFailed);
        assert!(out.subtasks.is_empty());
        assert!(out.synthesis.is_none());
        assert!(!invoked, "no local brain runs on a malformed plan");
        assert_eq!(frontier.calls, 1, "only the PLAN turn ran (no synthesis)");
    }

    /// An unmapped kind still routes (totality): a sub-task tagged with an
    /// unregistered expert falls back to the table default — never a panic.
    #[test]
    fn unmapped_kind_routes_to_default() {
        let policy = TombstonePolicy::new();
        let state = empty_state(&policy);
        let table = default_routing_table();
        let mut frontier = ScriptedFrontier {
            replies: vec![
                "SUBTASK 1 personal_memory - recall the owner preference",
                "ANSWER: done",
            ],
            calls: 0,
        };
        let mut local_turn = |_port: u16,
                              model_id: &str,
                              _s: &str,
                              _u: &str|
         -> Result<AgentTurn, AgentTransportError> {
            Ok(AgentTurn {
                answer_text: format!("ANSWER: {model_id}"),
                input_tokens_u64: 0,
                output_tokens_u64: 0,
                cached_tokens_u64: 0,
            })
        };
        let mut no_oracle = |_: &SubTask, _: &AgentLoopOutcome| -> VerificationEvidence {
            VerificationEvidence::Absent
        };
        let out = run_orchestrated_consult(
            &mut frontier,
            &mut local_turn,
            &mut no_oracle,
            &table,
            &state,
            "p",
            "i",
            "s",
            "task",
            0,
            0,
        );
        assert_eq!(out.stop, OrchestratorStop::Synthesized);
        assert_eq!(out.routed_model_ids(), vec!["default"]);
    }

    /// P1-3 thin: the verify oracle gates Write admission — a passing CODE oracle
    /// ⇒ Verified ⇒ admits; an ADVISORY sub-task ⇒ NotApplicable ⇒ never admits.
    /// The verdict ignores the model's (boastful) answer text — no
    /// self-certification (the P-HALL anchor).
    #[test]
    fn verify_oracle_gates_write_admission() {
        use crate::provider::executor_route::ExecutorKind;
        use crate::verification::{VerificationClass, VerificationEvidence, VerificationVerdict};
        let policy = TombstonePolicy::new();
        let state = empty_state(&policy);
        let table = default_routing_table();
        let mut frontier = ScriptedFrontier {
            replies: vec![
                "SUBTASK 1 sui_move - build it\nSUBTASK 2 nl_bridge 1 explain it",
                "ANSWER: done",
            ],
            calls: 0,
        };
        let mut local_turn =
            |_port: u16, _m: &str, _s: &str, _u: &str| -> Result<AgentTurn, AgentTransportError> {
                Ok(AgentTurn {
                    answer_text: "ANSWER: i claim total success".to_string(),
                    input_tokens_u64: 0,
                    output_tokens_u64: 0,
                    cached_tokens_u64: 0,
                })
            };
        // Oracle: the CODE sub-task passed its compiler/test check; the model's
        // boastful answer text is irrelevant — only the typed oracle evidence counts.
        let mut oracle = |st: &SubTask, _o: &AgentLoopOutcome| -> VerificationEvidence {
            if st.kind.label() == ExecutorKind::SUI_MOVE {
                VerificationEvidence::CodeOracle(Some(true))
            } else {
                VerificationEvidence::Absent
            }
        };
        let out = run_orchestrated_consult(
            &mut frontier,
            &mut local_turn,
            &mut oracle,
            &table,
            &state,
            "p",
            "i",
            "s",
            "task",
            0,
            0,
        );
        assert_eq!(out.subtasks.len(), 2);
        // sub-task 1 (sui_move, code, oracle passed) ⇒ Verified ⇒ admits.
        assert_eq!(out.subtasks[0].receipt.class, VerificationClass::Code);
        assert_eq!(
            out.subtasks[0].receipt.verdict,
            VerificationVerdict::Verified
        );
        assert!(out.subtasks[0].receipt.admits_write());
        // sub-task 2 (nl_bridge ⇒ model-inference, no evidence) ⇒ NotApplicable ⇒
        // never admits, despite the model claiming "total success".
        assert_eq!(
            out.subtasks[1].receipt.class,
            VerificationClass::ModelInference
        );
        assert_eq!(
            out.subtasks[1].receipt.verdict,
            VerificationVerdict::NotApplicable
        );
        assert!(!out.subtasks[1].receipt.admits_write());
        assert_eq!(
            out.write_admitted_count(),
            1,
            "only the verified code sub-task admits a write"
        );
    }

    /// MACRO PER-PORT (P1-6): a routing table that maps each kind to its OWN worker PORT
    /// routes each sub-task's IMPLEMENT turn to that port — distinct ports ⇒ per-chain
    /// worker processes (the speed lane), proven on the (port, model_id) wire selector.
    #[test]
    fn macro_mode_routes_each_subtask_to_its_worker_port() {
        use crate::provider::executor_route::{ExecutorKind, ExecutorRoutingTable, ExecutorTarget};
        let policy = TombstonePolicy::new();
        let state = empty_state(&policy);
        // Macro table: sui_move → port 11500, solana_anchor → port 11501 (distinct workers).
        let table = ExecutorRoutingTable::new(
            vec![
                (
                    ExecutorKind::new("sui_move").expect("valid"),
                    ExecutorTarget {
                        port: 11500,
                        model_id: "sui_lora".to_string(),
                    },
                ),
                (
                    ExecutorKind::new("solana_anchor").expect("valid"),
                    ExecutorTarget {
                        port: 11501,
                        model_id: "sol_lora".to_string(),
                    },
                ),
            ],
            ExecutorTarget {
                port: 11434,
                model_id: "default".to_string(),
            },
        );
        let mut frontier = ScriptedFrontier {
            replies: vec![
                "SUBTASK 1 sui_move - build it\nSUBTASK 2 solana_anchor 1 port it",
                "ANSWER: done",
            ],
            calls: 0,
        };
        // Capture the (port, model_id) each IMPLEMENT turn was invoked with.
        let mut seen: Vec<(u16, String)> = Vec::new();
        let mut local_turn = |port: u16,
                              model_id: &str,
                              _s: &str,
                              _u: &str|
         -> Result<AgentTurn, AgentTransportError> {
            seen.push((port, model_id.to_string()));
            Ok(AgentTurn {
                answer_text: "ANSWER: ok".to_string(),
                input_tokens_u64: 0,
                output_tokens_u64: 0,
                cached_tokens_u64: 0,
            })
        };
        let mut no_oracle = |_: &SubTask, _: &AgentLoopOutcome| -> VerificationEvidence {
            VerificationEvidence::Absent
        };
        let out = run_orchestrated_consult(
            &mut frontier,
            &mut local_turn,
            &mut no_oracle,
            &table,
            &state,
            "p",
            "i",
            "s",
            "task",
            0,
            0,
        );
        // Each sub-task's IMPLEMENT turn hit its OWN worker port (Macro), with its adapter.
        assert_eq!(
            seen,
            vec![
                (11500, "sui_lora".to_string()),
                (11501, "sol_lora".to_string())
            ]
        );
        assert_eq!(out.routed_ports(), vec![11500, 11501]);
        assert_eq!(out.routed_model_ids(), vec!["sui_lora", "sol_lora"]);
    }
}
