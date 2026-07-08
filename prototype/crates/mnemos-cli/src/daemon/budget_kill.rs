//! Operational budget/kill integration.
//!
//! The shared budget cap is re-checked **before** every provider / tool / memory /
//! evidence side effect, so lowering the cap stops the next over-budget dispatch
//! before it can cost anything (`G-G-COST-BUDGET`, `G-G-CONTROL-EXPRESS`). A killed
//! task can never continue writing evidence in the background: once a job is
//! killed (terminal), [`BudgetKillIntegration::can_write_evidence`] is `false`.
//!
//! Reuse (no reinvention): the cap gate is the canonical
//! [`crate::commands::budget::BudgetCap`] authorize-before-dispatch check; the kill
//! is the canonical express [`crate::commands::kill::KillController`] over the
//! no-zombie [`crate::tui::job_rail`]. This module performs no live action — it
//! gates and transitions in-memory state only.

use crate::StageFTraceLink;
use crate::commands::budget::{BudgetCap, BudgetCharge, BudgetReject, DispatchRequest};
use crate::commands::kill::{KillAck, KillController, KillReason};

/// The side-effect classes the budget gate is re-checked against before they run.
#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SideEffectClass {
    /// A provider consult dispatch.
    Provider = 1,
    /// A tool-adapter call.
    Tool = 2,
    /// A memory replay/export.
    Memory = 3,
    /// An evidence pack/replay.
    Evidence = 4,
}

impl SideEffectClass {
    /// The stable `u8` discriminant.
    #[must_use]
    pub const fn as_u8(self) -> u8 {
        self as u8
    }
}

/// Budget/kill integration: the shared [`BudgetCap`] is re-checked before each
/// side effect, and the express [`KillController`] guarantees a killed task can
/// never write evidence. Owns no secret and performs no live action.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BudgetKillIntegration {
    cap: BudgetCap,
    kill: KillController,
}

impl BudgetKillIntegration {
    /// A new integration with the given budget cap and an empty kill rail.
    #[must_use]
    pub fn new(cap: BudgetCap) -> Self {
        Self {
            cap,
            kill: KillController::new(),
        }
    }

    /// The current budget cap (a [`BudgetCap`] is `Copy`).
    #[must_use]
    pub fn cap(&self) -> BudgetCap {
        self.cap
    }

    /// The kill controller (read-only).
    #[must_use]
    pub fn kill_controller(&self) -> &KillController {
        &self.kill
    }

    /// Mutable access to the kill controller (to admit jobs onto its rail).
    pub fn kill_controller_mut(&mut self) -> &mut KillController {
        &mut self.kill
    }

    /// Lower (replace) the budget cap. The new cap is enforced before the next
    /// side effect — a tighter cap stops the next over-budget dispatch.
    pub fn lower_cap(&mut self, new_cap: BudgetCap) {
        self.cap = new_cap;
    }

    /// Authorize a side effect against the CURRENT cap (re-checked before
    /// dispatch). After a [`Self::lower_cap`] this uses the tightened cap, so an
    /// over-budget side effect is refused (fail-closed) before it runs. Pure — it
    /// never mutates the ledger and never performs the side effect.
    pub fn authorize_side_effect(
        &self,
        _class: SideEffectClass,
        req: &DispatchRequest,
    ) -> Result<BudgetCharge, BudgetReject> {
        self.cap.authorize(req)
    }

    /// Kill a job on the express rail (reuses the canonical kill).
    pub fn kill(&mut self, job_id_u64: u64, reason: KillReason, trace: StageFTraceLink) -> KillAck {
        self.kill.kill(job_id_u64, reason, trace)
    }

    /// Whether a job may still write evidence. Only a live (non-terminal) job on
    /// the rail may; a killed/terminal job, or an unknown id, may NOT
    /// (fail-closed — no background write after a kill).
    #[must_use]
    pub fn can_write_evidence(&self, job_id_u64: u64) -> bool {
        self.kill
            .rail()
            .items()
            .iter()
            .any(|i| i.job_id_u64 == job_id_u64 && i.state.is_live())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::route::RouteExecutionState;
    use crate::tui::job_rail::{JobKind, JobRailItem, JobState};

    fn trace() -> StageFTraceLink {
        StageFTraceLink::new([0x52; 32], 512, 0)
    }

    fn req(input: u32, output: u32) -> DispatchRequest {
        DispatchRequest {
            route_state: RouteExecutionState::Slow,
            input_tokens_u32: input,
            output_tokens_u32: output,
            estimated_cost_micro: Some(10),
            projected_ms_u32: 100,
            approved: false,
            reason_hash_32: [0u8; 32],
            route_trace_hash_32: [0u8; 32],
        }
    }

    #[test]
    fn lower_cap_stops_next_side_effect() {
        let mut bk = BudgetKillIntegration::new(BudgetCap::new(100_000, 1_000_000, 100_000));
        // Within budget before lowering.
        assert!(
            bk.authorize_side_effect(SideEffectClass::Provider, &req(100, 50))
                .is_ok()
        );
        // Lower the cap to zero — the next dispatch is refused.
        bk.lower_cap(BudgetCap::new(0, 0, 100_000));
        assert!(
            bk.authorize_side_effect(SideEffectClass::Provider, &req(100, 50))
                .is_err()
        );
    }

    #[test]
    fn provider_tool_evidence_all_stop_after_cap_lower() {
        let mut bk = BudgetKillIntegration::new(BudgetCap::new(100_000, 1_000_000, 100_000));
        bk.lower_cap(BudgetCap::new(0, 0, 100_000));
        for class in [
            SideEffectClass::Provider,
            SideEffectClass::Tool,
            SideEffectClass::Memory,
            SideEffectClass::Evidence,
        ] {
            assert!(
                bk.authorize_side_effect(class, &req(1, 1)).is_err(),
                "{class:?} must be stopped after the cap is lowered to zero"
            );
        }
    }

    #[test]
    fn killed_task_cannot_write_evidence() {
        let mut bk = BudgetKillIntegration::new(BudgetCap::new(100, 100, 1_000));
        bk.kill_controller_mut().rail_mut().push(JobRailItem::new(
            1,
            JobKind::Measure,
            JobState::Running,
            trace(),
        ));
        // A live job may write evidence.
        assert!(bk.can_write_evidence(1));
        // After a kill it may not (no background write).
        let ack = bk.kill(1, KillReason::UserRequested, trace());
        assert_eq!(ack.final_state, JobState::Killed);
        assert!(!bk.can_write_evidence(1));
    }

    #[test]
    fn unknown_job_cannot_write_evidence_fail_closed() {
        let bk = BudgetKillIntegration::new(BudgetCap::new(100, 100, 1_000));
        assert!(!bk.can_write_evidence(404));
    }
}
