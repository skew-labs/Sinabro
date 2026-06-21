//! Operational prompt / workpackage status view (atom #540 · G.4.9).
//!
//! The operational status view shows where Sinabro is in the Stage B+ WorkPackage
//! lifecycle: the active prompt strip, the stage / workpackage, the plan hash, the
//! physical-law (`validate_workpackage_physics`) status, the sidecar status, the
//! next safe action, and whether the active prompt is stale. Unknown state is
//! *explicit* (a zero hash renders `unknown`, an unwired truth renders `unknown`),
//! never a false-green (`G-G-OPERATIONAL-ENTRY`). This is a pure projection — no
//! I/O, no live action.
//!
//! Reuse (no reinvention): the prompt strip is the Stage F
//! [`crate::repl::prompt::PromptStatus`] / [`render_status_strip`]; the three-valued
//! truth is the cockpit [`RenderTruth`].

use crate::hex32;
use crate::repl::prompt::{PromptStatus, render_status_strip};
use crate::tui::RenderTruth;

const ZERO32: [u8; 32] = [0u8; 32];

/// Short hash for display: a zero hash is the explicit literal `unknown`, never a
/// blank or false-green.
fn short(hash: &[u8; 32]) -> String {
    if *hash == ZERO32 {
        "unknown".to_string()
    } else {
        hex32(hash)[..8].to_string()
    }
}

/// A stable, colorless label for a render truth (readable with no color).
const fn truth_label(t: RenderTruth) -> &'static str {
    match t {
        RenderTruth::Green => "PASS",
        RenderTruth::Yellow => "DEGRADED",
        RenderTruth::Red => "RED",
        RenderTruth::Unknown => "unknown",
    }
}

/// The operational prompt / workpackage status view.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct WorkPackageStatusView {
    /// The Stage F prompt strip status (workspace / model / budget / approvals).
    pub prompt: PromptStatus,
    /// The active stage (e.g. `b'G'`).
    pub stage_u8: u8,
    /// SHA-256 of the active workpackage id.
    pub workpackage_id_hash_32: [u8; 32],
    /// SHA-256 of the active atom plan.
    pub plan_hash_32: [u8; 32],
    /// Physical-law validator status.
    pub physics: RenderTruth,
    /// Sidecar (21-file diet) status.
    pub sidecar: RenderTruth,
    /// SHA-256 of the next safe action (zero = none / unknown).
    pub next_action_hash_32: [u8; 32],
    /// Whether the active workpackage contract is present.
    pub contract_present: bool,
    /// Whether the active prompt is stale (a refreshed contract is required).
    pub prompt_stale: bool,
}

impl WorkPackageStatusView {
    /// Whether the status is actionable: the contract is present, the prompt is
    /// fresh, physics passes, and the sidecar is green. A red / unknown physics or
    /// sidecar, a missing contract, or a stale prompt is never actionable.
    #[must_use]
    pub const fn is_actionable(&self) -> bool {
        self.contract_present
            && !self.prompt_stale
            && self.physics.is_healthy()
            && self.sidecar.is_healthy()
    }

    /// Render the status as colorless, paged lines bounded by `rows`. Line 0 is the
    /// reused Stage F prompt strip; the rest are the workpackage coordinates.
    #[must_use]
    pub fn render(&self, rows: u16) -> Vec<String> {
        let lines = vec![
            render_status_strip(&self.prompt),
            format!("stage={}", self.stage_u8 as char),
            format!("workpackage={}", short(&self.workpackage_id_hash_32)),
            format!("plan={}", short(&self.plan_hash_32)),
            format!("physics={}", truth_label(self.physics)),
            format!("sidecar={}", truth_label(self.sidecar)),
            format!(
                "contract={}",
                if self.contract_present {
                    "present"
                } else {
                    "missing"
                }
            ),
            format!(
                "prompt={}",
                if self.prompt_stale { "STALE" } else { "fresh" }
            ),
            format!("next_action={}", short(&self.next_action_hash_32)),
            format!("actionable={}", self.is_actionable()),
        ];
        lines.into_iter().take(rows as usize).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sha256_32;

    fn prompt() -> PromptStatus {
        PromptStatus {
            workspace_hash_32: sha256_32(b"/Users/heoun/mnemos"),
            model_hash_32: ZERO32,
            context_pressure_bps: 1000,
            last_checkpoint_hash_32: sha256_32(b"ckpt"),
            budget_remaining_micros: 1_000_000,
            sandbox_tier_u8: 1,
            pending_approvals_u16: 0,
            pending_tasks_u16: 1,
        }
    }

    fn view() -> WorkPackageStatusView {
        WorkPackageStatusView {
            prompt: prompt(),
            stage_u8: b'G',
            workpackage_id_hash_32: sha256_32(b"G-WP-05"),
            plan_hash_32: sha256_32(b"plan"),
            physics: RenderTruth::Green,
            sidecar: RenderTruth::Green,
            next_action_hash_32: sha256_32(b"implement"),
            contract_present: true,
            prompt_stale: false,
        }
    }

    #[test]
    fn active_is_actionable() {
        let v = view();
        assert!(v.is_actionable());
        let lines = v.render(16);
        assert!(lines.iter().any(|l| l == "stage=G"));
        assert!(lines.iter().any(|l| l.starts_with("workpackage=")));
        assert!(lines.iter().any(|l| l == "physics=PASS"));
    }

    #[test]
    fn stale_prompt_detected() {
        let mut v = view();
        v.prompt_stale = true;
        assert!(!v.is_actionable());
        assert!(v.render(16).iter().any(|l| l == "prompt=STALE"));
    }

    #[test]
    fn missing_contract_blocks() {
        let mut v = view();
        v.contract_present = false;
        assert!(!v.is_actionable());
        assert!(v.render(16).iter().any(|l| l == "contract=missing"));
    }

    #[test]
    fn physics_red_blocks() {
        let mut v = view();
        v.physics = RenderTruth::Red;
        assert!(!v.is_actionable());
        assert!(v.render(16).iter().any(|l| l == "physics=RED"));
    }

    #[test]
    fn sidecar_incomplete_blocks() {
        let mut v = view();
        v.sidecar = RenderTruth::Red;
        assert!(!v.is_actionable());
        assert!(v.render(16).iter().any(|l| l == "sidecar=RED"));
    }

    #[test]
    fn unknown_state_is_explicit() {
        let mut v = view();
        v.workpackage_id_hash_32 = ZERO32;
        v.physics = RenderTruth::Unknown;
        let lines = v.render(16);
        assert!(lines.iter().any(|l| l == "workpackage=unknown"));
        assert!(lines.iter().any(|l| l == "physics=unknown"));
    }
}
