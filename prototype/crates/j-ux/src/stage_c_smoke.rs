//! Stage C status/budget/kill GA smoke.
//!
//! Canonical OUT: smoke evidence that the `/status`, `/budget` and `/kill`
//! control surfaces are observable and interruptible from the *existing* UX
//! before any mainnet ceremony.
//!
//! # Invariants
//!
//! * **The mainnet gate must be observable and interruptible from existing UX.**
//!   This smoke reuses the canonical control surfaces — the j-ux
//!   [`parse_slash`](crate::slash::parse_slash) command parser and the a-core
//!   [`RuntimeSupervisor`] — to prove the control commands are visible and that
//!   a kill is acknowledged by the supervisor (drain). It is the pre-F smoke
//!   for the later express control rail: Stage C proves visibility + drain;
//!   Stage F/H prove queue-bypass / control-plane express.
//! * **No re-mint.** The supervisor, its task kinds, and the slash parser are
//!   reused verbatim; this atom mints no new control type.
//!
//! # Reachable-surface notes (honest scope)
//!
//! * **`/status` is not a slash verb in this codebase.** The slash grammar
//!   is `{budget, clear, skill, kill}` — there is no `status`
//!   command. The "status path" that is observable here is the supervisor
//!   [`RuntimeDrainReport`] snapshot itself (the live/finished/timed-out
//!   counts), which is the data a `/status` render would read. The smoke
//!   therefore treats the drain snapshot as the status surface.
//! * **`CostLedger` is not reachable from `j-ux`.** The cost ledger lives in
//!   `m-agent`; `j-ux` depends only on `a-core` + `e-skill`,
//!   so wiring the actual ledger read here would invert the crate direction.
//!   What is reachable — and what this smoke asserts — is that the `/budget`
//!   control command is *visible* (parses to [`SlashCommand::Budget`]) in the
//!   existing UX. The ledger-read smoke is deferred to a crate that reaches both
//!   surfaces, exactly as the `SlashCommand::Budget` doc already notes ("the
//!   cost-ledger read is wired by a later atom").

use crate::slash::{SlashCommand, parse_slash};
use mnemos_a_core::{RuntimeAttempt, RuntimeShutdownState, RuntimeSupervisor, RuntimeTaskKind};

/// The observable result of the Stage C control smoke.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct StageCControlSmoke {
    /// `/budget` parses to [`SlashCommand::Budget`] (control command visible).
    pub budget_command_visible: bool,
    /// `/kill` parses to [`SlashCommand::Kill`] (control command visible).
    pub kill_command_visible: bool,
    /// Number of tasks active in the supervisor before the kill.
    pub active_before_u16: u16,
    /// Process-wide supervisor state after the kill (the drain acknowledgement).
    pub shutdown_state_after: RuntimeShutdownState,
    /// Whether the kill was acknowledged: the supervisor left the `Accepting`
    /// state (it is now draining / shut down) and refuses new registrations.
    pub kill_acknowledged: bool,
}

/// Run the Stage C control smoke against the canonical surfaces.
///
/// 1. Asserts (via the return flags) that `/budget` and `/kill` are visible in
///    the existing slash grammar.
/// 2. Registers a few tasks on a [`RuntimeSupervisor`], snapshots the active
///    count (the "status" surface), then issues the `/kill` action
///    ([`RuntimeSupervisor::request_shutdown`]) and confirms the supervisor
///    left `Accepting` and refuses a new registration (interruptible).
pub fn run_stage_c_control_smoke() -> StageCControlSmoke {
    let budget_command_visible = matches!(parse_slash("/budget"), Some(SlashCommand::Budget));
    let kill_command_visible = matches!(parse_slash("/kill"), Some(SlashCommand::Kill));

    let supervisor = RuntimeSupervisor::<8>::new();
    let mut registered: u16 = 0;
    for kind in [
        RuntimeTaskKind::Agent,
        RuntimeTaskKind::Tool,
        RuntimeTaskKind::Memory,
    ] {
        if supervisor.register(kind, RuntimeAttempt::FIRST).is_ok() {
            registered = registered.saturating_add(1);
        }
    }
    let active_before_u16 = supervisor.drain_snapshot(0).active_count_u16;

    // The `/kill` action: request shutdown on the supervisor.
    let _ = supervisor.request_shutdown(1_000);
    let after = supervisor.drain_snapshot(10);

    // Interruptible: after the kill, the supervisor refuses new work.
    let refuses_new_work = supervisor
        .register(RuntimeTaskKind::Agent, RuntimeAttempt::FIRST)
        .is_err();
    let kill_acknowledged =
        after.shutdown_state != RuntimeShutdownState::Accepting && refuses_new_work;

    debug_assert_eq!(registered, active_before_u16);

    StageCControlSmoke {
        budget_command_visible,
        kill_command_visible,
        active_before_u16,
        shutdown_state_after: after.shutdown_state,
        kill_acknowledged,
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]
    use super::*;

    #[test]
    fn budget_and_kill_commands_are_visible_in_existing_ux() {
        let smoke = run_stage_c_control_smoke();
        assert!(smoke.budget_command_visible, "/budget must parse");
        assert!(smoke.kill_command_visible, "/kill must parse");
    }

    #[test]
    fn status_snapshot_observes_active_tasks_before_kill() {
        let smoke = run_stage_c_control_smoke();
        // Three tasks were registered into an 8-slot supervisor.
        assert_eq!(smoke.active_before_u16, 3);
    }

    #[test]
    fn kill_drains_the_supervisor_and_is_interruptible() {
        let smoke = run_stage_c_control_smoke();
        assert_ne!(smoke.shutdown_state_after, RuntimeShutdownState::Accepting);
        assert!(
            smoke.kill_acknowledged,
            "the supervisor must leave Accepting and refuse new work after /kill"
        );
    }

    #[test]
    fn mock_telegram_and_cli_share_the_same_slash_grammar() {
        // Both the Telegram gateway and the CLI REPL route control commands
        // through the one `parse_slash` grammar — the same parse is the status
        // surface for either transport.
        assert_eq!(parse_slash("/budget"), Some(SlashCommand::Budget));
        assert_eq!(parse_slash("/kill"), Some(SlashCommand::Kill));
        assert_eq!(parse_slash("/Budget"), None); // case-sensitive gate
    }
}
