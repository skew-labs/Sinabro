//! §4.3 prompt status strip (atom #410 F.1.1).
//!
//! The status strip shows workspace, active provider/model, context pressure,
//! checkpoint state, budget, sandbox tier, and pending approval/task counts.
//! Unknown state is *explicit* (a zero hash renders as `unknown`), never a blank
//! or a false-green.

use crate::hex32;

/// §4.3 — the prompt status fields.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PromptStatus {
    /// SHA-256 of the active workspace path.
    pub workspace_hash_32: [u8; 32],
    /// SHA-256 of the active model identity.
    pub model_hash_32: [u8; 32],
    /// Context pressure in basis points (0..=10000).
    pub context_pressure_bps: u16,
    /// SHA-256 of the last checkpoint.
    pub last_checkpoint_hash_32: [u8; 32],
    /// Remaining budget in micro-units.
    pub budget_remaining_micros: u64,
    /// Active sandbox tier.
    pub sandbox_tier_u8: u8,
    /// Pending approvals count.
    pub pending_approvals_u16: u16,
    /// Pending tasks count.
    pub pending_tasks_u16: u16,
}

const ZERO32: [u8; 32] = [0u8; 32];

fn short(hash: &[u8; 32]) -> String {
    if *hash == ZERO32 {
        "unknown".to_string()
    } else {
        hex32(hash)[..8].to_string()
    }
}

/// Render the single-line status strip. Unknown (zero) hashes render explicitly
/// as `unknown` so the prompt never shows a false-green.
#[must_use]
pub fn render_status_strip(status: &PromptStatus) -> String {
    format!(
        "ws:{ws} model:{model} ctx:{ctx}bps ckpt:{ckpt} budget:{budget}u sbx:{sbx} appr:{appr} task:{task}",
        ws = short(&status.workspace_hash_32),
        model = short(&status.model_hash_32),
        ctx = status.context_pressure_bps,
        ckpt = short(&status.last_checkpoint_hash_32),
        budget = status.budget_remaining_micros,
        sbx = status.sandbox_tier_u8,
        appr = status.pending_approvals_u16,
        task = status.pending_tasks_u16,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sha256_32;

    fn sample() -> PromptStatus {
        PromptStatus {
            workspace_hash_32: sha256_32(b"/work/space"),
            model_hash_32: ZERO32,
            context_pressure_bps: 1200,
            last_checkpoint_hash_32: sha256_32(b"ckpt"),
            budget_remaining_micros: 500_000,
            sandbox_tier_u8: 1,
            pending_approvals_u16: 0,
            pending_tasks_u16: 2,
        }
    }

    #[test]
    fn unknown_state_is_explicit() {
        let s = render_status_strip(&sample());
        assert!(s.contains("model:unknown"), "{s}");
    }

    #[test]
    fn known_fields_render() {
        let s = render_status_strip(&sample());
        assert!(s.contains("ctx:1200bps"));
        assert!(s.contains("budget:500000u"));
        assert!(s.contains("task:2"));
        assert!(s.contains("ws:"));
        assert!(!s.starts_with("ws:unknown"));
    }
}
