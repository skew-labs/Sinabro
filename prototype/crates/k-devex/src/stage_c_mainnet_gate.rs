//! Mainnet gate approval-wait state.
//!
//! Public surface: [`MainnetGateReceipt`].
//!
//! # Invariants
//!
//! * **All gates green results in approval wait, not automatic execution.**
//!   [`MainnetGateReceipt::evaluate`] folds the checklist + package lock +
//!   incident pause into a single posture. The *most* it can ever yield is
//!   [`ApprovalPending`](MainnetExecutionState::ApprovalPending) — it can never,
//!   by construction, produce [`Executed`](MainnetExecutionState::Executed),
//!   because it delegates to [`MainnetChecklist::ready_state`] which
//!   caps at `ApprovalPending`. A green checklist makes the gate *wait* for the
//!   operator, it does not execute.
//! * **A missing step cannot execute.** A checklist with any unfilled step (or a
//!   zero evidence hash) stays [`Locked`](MainnetExecutionState::Locked); the
//!   receipt's [`is_executable`](MainnetGateReceipt::is_executable) is `false`
//!   for every non-`Executed` state, and this type never reaches `Executed`.
//! * **Pause dominates.** If the incident pause is engaged, the
//!   receipt is [`Paused`](MainnetExecutionState::Paused) regardless of how green
//!   the checklist is — an operator pause always wins over readiness.
//!
//! # Related
//!
//! * [`MainnetChecklist`](crate::stage_c_checklist::MainnetChecklist)
//!   supplies the green-mask + evidence + `ready_state` ceiling (same crate).
//! * [`MainnetPackageLock`](mnemos_d_move::stage_c_package_lock::MainnetPackageLock)
//!   is the package/bytecode/prover/gas-baseline commitment bound into the
//!   receipt (`d-move`).
//! * [`IncidentPause`](crate::stage_c_pause::IncidentPause)
//!   supplies the pause override (same crate).
//! * The execution posture reuses
//!   [`MainnetExecutionState`](mnemos_a_core::stage_c_env::MainnetExecutionState)
//!   (from `a-core`); no parallel mainnet-state enum is minted.
//!
//! No live action: this folds in-memory state into a posture. It performs no
//! I/O, no signing, no submission; `MainnetExecutionState` never reaches
//! `Executed` through this type.

use mnemos_a_core::stage_c_env::MainnetExecutionState;
use mnemos_d_move::stage_c_package_lock::MainnetPackageLock;

use crate::stage_c_checklist::MainnetChecklist;
use crate::stage_c_pause::IncidentPause;

/// The mainnet gate receipt: the bound checklist, the package lock, and the
/// gated execution posture this gate *permits* (never `Executed`).
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub struct MainnetGateReceipt {
    /// The mainnet readiness checklist.
    pub checklist: MainnetChecklist,
    /// The package lock binding bytecode/prover/gas-baseline.
    pub package_lock: MainnetPackageLock,
    /// The gated execution posture: one of
    /// [`Locked`](MainnetExecutionState::Locked),
    /// [`ApprovalPending`](MainnetExecutionState::ApprovalPending), or
    /// [`Paused`](MainnetExecutionState::Paused). Never
    /// [`Executed`](MainnetExecutionState::Executed).
    pub state: MainnetExecutionState,
}

impl MainnetGateReceipt {
    /// Fold the checklist, package lock, and incident pause into a receipt.
    ///
    /// The posture is computed, never asserted by the caller:
    /// * pause engaged → [`Paused`](MainnetExecutionState::Paused);
    /// * else the checklist's [`ready_state`](MainnetChecklist::ready_state),
    ///   which is [`ApprovalPending`](MainnetExecutionState::ApprovalPending)
    ///   only when every step is green **and** the evidence hash is non-zero,
    ///   and [`Locked`](MainnetExecutionState::Locked) otherwise.
    ///
    /// The result can never be [`Executed`](MainnetExecutionState::Executed):
    /// `ready_state` caps at `ApprovalPending`, and pause maps to `Paused`.
    #[inline]
    #[must_use]
    pub fn evaluate(
        checklist: MainnetChecklist,
        package_lock: MainnetPackageLock,
        pause: &IncidentPause,
    ) -> Self {
        let state = if pause.is_paused() {
            MainnetExecutionState::Paused
        } else {
            checklist.ready_state()
        };
        Self {
            checklist,
            package_lock,
            state,
        }
    }

    /// The gated execution posture.
    #[inline]
    #[must_use]
    pub const fn state(&self) -> MainnetExecutionState {
        self.state
    }

    /// Whether a real mainnet mutation is permitted. Delegates to
    /// [`MainnetExecutionState::is_executable`]; always `false` for a receipt
    /// produced by [`evaluate`](Self::evaluate), since that never yields
    /// `Executed`.
    #[inline]
    #[must_use]
    pub const fn is_executable(&self) -> bool {
        self.state.is_executable()
    }

    /// Whether the gate is waiting on explicit operator approval (all green,
    /// evidence bound, not paused).
    #[inline]
    #[must_use]
    pub const fn is_approval_pending(&self) -> bool {
        matches!(self.state, MainnetExecutionState::ApprovalPending)
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]
    use super::*;
    use crate::stage_c_checklist::MainnetChecklistStep;
    use crate::stage_c_pause::PauseReason;
    use mnemos_d_move::types::ObjectId;

    fn lock() -> MainnetPackageLock {
        MainnetPackageLock::new(
            ObjectId::new([0x33; 32]),
            [0x44; 32],
            [0x55; 32],
            [0x66; 32],
        )
        .expect("valid package lock")
    }

    fn all_green_checklist() -> MainnetChecklist {
        let mut cl = MainnetChecklist::new_locked();
        for step in MainnetChecklistStep::ALL {
            cl = cl.with_step(step, true);
        }
        cl.with_evidence_hash([0x11; 32])
    }

    /// An all-green checklist with bound evidence and a clear pause yields
    /// `ApprovalPending`, never `Executed`, and is not executable.
    #[test]
    fn c2_19_all_green_results_in_approval_pending() {
        let receipt =
            MainnetGateReceipt::evaluate(all_green_checklist(), lock(), &IncidentPause::running());
        assert_eq!(receipt.state(), MainnetExecutionState::ApprovalPending);
        assert!(receipt.is_approval_pending());
        assert_ne!(receipt.state(), MainnetExecutionState::Executed);
        assert!(!receipt.is_executable());
    }

    /// A partial checklist (one step missing) stays `Locked` and is not
    /// executable; a zero-evidence all-green checklist is likewise `Locked`.
    #[test]
    fn c2_19_missing_approval_cannot_execute() {
        // One step missing → Locked.
        let partial =
            all_green_checklist().with_step(MainnetChecklistStep::OperatorApproval, false);
        let r1 = MainnetGateReceipt::evaluate(partial, lock(), &IncidentPause::running());
        assert_eq!(r1.state(), MainnetExecutionState::Locked);
        assert!(!r1.is_executable());
        assert!(!r1.is_approval_pending());

        // All green but zero evidence hash → Locked.
        let mut all_green_no_evidence = MainnetChecklist::new_locked();
        for step in MainnetChecklistStep::ALL {
            all_green_no_evidence = all_green_no_evidence.with_step(step, true);
        }
        let r2 =
            MainnetGateReceipt::evaluate(all_green_no_evidence, lock(), &IncidentPause::running());
        assert_eq!(r2.state(), MainnetExecutionState::Locked);
        assert!(!r2.is_executable());
    }

    /// An engaged incident pause forces `Paused` even with an all-green,
    /// evidence-bound checklist; still not executable.
    #[test]
    fn c2_19_pause_forces_paused() {
        let mut pause = IncidentPause::running();
        pause.pause(PauseReason::OperatorManual);
        let receipt = MainnetGateReceipt::evaluate(all_green_checklist(), lock(), &pause);
        assert_eq!(receipt.state(), MainnetExecutionState::Paused);
        assert!(!receipt.is_executable());
        assert!(!receipt.is_approval_pending());
    }

    /// The receipt carries the exact checklist and package lock it was
    /// evaluated from.
    #[test]
    fn c2_19_receipt_binds_checklist_and_lock() {
        let cl = all_green_checklist();
        let pl = lock();
        let receipt = MainnetGateReceipt::evaluate(cl, pl, &IncidentPause::running());
        assert_eq!(receipt.checklist, cl);
        assert_eq!(receipt.package_lock, pl);
    }
}
