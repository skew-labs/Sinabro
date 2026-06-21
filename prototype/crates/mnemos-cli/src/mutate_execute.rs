//! ENDGAME E10-2a — the single gated EXECUTE chokepoint for agent-proposed side
//! effects ("AGENT ACTS"). Threat model:
//! `ops/evidence/stage_g/agent_loop/AGENT_ACTS_THREAT_MODEL.md` (⑬ IV-A1..A12).
//!
//! # The one place an agent proposal becomes a side effect
//!
//! The model only PROPOSES (a sealed INERT `.xep` exec record / `.fep` edit record
//! — `exec_proposal` / `file_edit`); the loop grammar has no exec tool and
//! `TOOL: exec` stays denied (IV-A2). This module owns the SINGLE function that
//! turns an owner-AUTHORIZED proposal into a real run:
//! [`execute_authorized_mutate`]. Its signature REQUIRES a [`MutateCapability`]
//! witness (IV-A1) — and a `MutateCapability` exists ONLY from a valid owner-armed
//! [`MutateGrant`](crate::commands::grant::MutateGrant) (the local `tool
//! exec-apply` ceremony, a tier-correct telegram approval, or a bounded armed
//! grant). No owner authority ⇒ no capability ⇒ this function cannot be called ⇒
//! the proposal stays inert FOREVER (fail-closed).
//!
//! # What it REUSES (no second executor — no drift)
//!
//! * exec → [`run_in_sandbox_default`]`(LocalWrite, …)`: Seatbelt, network
//!   kernel-DENIED (no socket ⇒ no chain RPC / no exfil), env-scrubbed, timeout +
//!   byte-cap, cwd-pinned (IV-A6). NEVER the un-sandboxed `run_local_command`.
//! * edit → [`apply_proposal`]: lane-A re-confine + `read_sha` staleness lock +
//!   atomic temp+fsync+rename + re-read verify (IV-A7).
//!
//! Custody is unreachable (PD-6, IV-A10): this module references no
//! wallet/chain/funds/sign symbol; the only authority type it names is
//! `MutateCapability` (tier-distinct from egress — an `EgressGrant` cannot make
//! one, IV-A5). Redaction of the captured exec stream is the DISPATCH render
//! layer's job (SI-2, IV-A8) — the same `render_exec_stream` choke the proven
//! `skill eval` path uses; this module returns the raw executor receipt.

use crate::commands::authority::{MutateCapability, local_mutate_capability};
use crate::commands::grant::{GrantBounds, arm_local_mutate_grant};
use crate::commands::sandbox::SandboxTier;
use crate::exec_local::ExecOutcome;
use crate::exec_proposal::ExecProposal;
use crate::file_context::FileReadPolicy;
use crate::file_edit::{ApplyDeny, ApplyReceipt, FileEditProposal, apply_proposal};
use crate::repl::approval::ApprovalPrompt;
use crate::sandbox_exec::{SandboxRunDeny, run_in_sandbox_default};

/// The owner-authorized agent-proposed side effect to execute. Borrows the loaded
/// proposal (the artifact the owner reviewed); an `Edit` also carries the
/// apply-time lane-A read policy (re-confinement happens inside `apply_proposal`).
#[derive(Debug)]
pub enum AuthorizedMutate<'a> {
    /// Run the proposed command in the kernel sandbox (LocalWrite; network DENIED).
    Exec(&'a ExecProposal),
    /// Apply the proposed edit atomically (staleness + re-confine + verify).
    Edit {
        /// The sealed edit proposal (full-content, staleness-bound).
        proposal: &'a FileEditProposal,
        /// The apply-time read policy (re-confines the target at apply time).
        policy: &'a FileReadPolicy,
    },
}

/// The typed receipt of an authorized mutate execution. Carries the executor's OWN
/// result (the DISPATCH layer redacts captured streams before render, SI-2).
#[derive(Debug)]
pub enum MutateExecOutcome {
    /// The exec ran in the kernel sandbox (or a typed sandbox deny).
    Exec(Result<ExecOutcome, SandboxRunDeny>),
    /// The edit applied atomically (or a typed apply deny).
    Edit(Result<ApplyReceipt, ApplyDeny>),
}

/// EXECUTE one owner-authorized agent-proposed side effect — the SINGLE gated
/// chokepoint (IV-A1). The [`MutateCapability`] witness is taken BY VALUE: its
/// mere existence is the structural gate (it exists ONLY from a valid owner-armed
/// [`MutateGrant`](crate::commands::grant::MutateGrant)). The SINGLE-USE bound is
/// enforced at the GRANT layer (`max_actions` + per-action re-derivation at the
/// live `(now, used)`, IV-A9), not by move semantics — the capability is `Copy`
/// (shared shape with `EgressCapability`).
///
/// Custody is unreachable (IV-A10): no wallet/chain/funds path. The exec executor
/// is the kernel sandbox (IV-A6); the edit executor is the atomic verified apply
/// (IV-A7).
///
/// IV-A1 (compile-time): the chokepoint CANNOT be called without a real
/// `MutateCapability` — its only constructor needs a valid owner-armed grant (the
/// forge is proven uninhabited in `commands::authority`), and a non-capability
/// value (here `()`) is a type error, so no side effect runs without owner
/// authority:
/// ```compile_fail
/// use sinabro::mutate_execute::{execute_authorized_mutate, AuthorizedMutate};
/// use sinabro::exec_proposal::ExecProposal;
/// let p = ExecProposal { command: "/bin/echo x".to_string() };
/// // a unit value is NOT a MutateCapability — the signature rejects it.
/// let _ = execute_authorized_mutate((), &AuthorizedMutate::Exec(&p));
/// ```
#[must_use]
pub fn execute_authorized_mutate(
    capability: MutateCapability,
    action: &AuthorizedMutate<'_>,
) -> MutateExecOutcome {
    // The capability is presented (and dropped here). Its existence is the IV-A1
    // gate; the GRANT it came from bounds how many actions may fire (IV-A9).
    let _present = capability;
    match action {
        AuthorizedMutate::Exec(proposal) => MutateExecOutcome::Exec(run_in_sandbox_default(
            SandboxTier::LocalWrite,
            &proposal.command,
        )),
        AuthorizedMutate::Edit { proposal, policy } => {
            MutateExecOutcome::Edit(apply_proposal(policy, proposal))
        }
    }
}

/// Owner-path (ENDGAME E10-2b LOCAL): authorize a SYNCHRONOUS single-shot local
/// mutate from a typed-phrase ceremony completed THIS turn, returning the
/// [`MutateCapability`] that gates [`execute_authorized_mutate`]. `prompt` MUST be
/// a `TypedPhrase` prompt built with the local confirm phrase; `response` is the
/// owner's typed gesture; `command_audit_32` binds the grant to the exact action
/// (`= sha256(command)`) for the audit trail. `None` (fail-closed) on a
/// wrong/replayed phrase. The grant is armed single-shot (`max_actions = 1`),
/// derived once, and dropped within this call — never stored (single-use by
/// construction). The unforgeable gate is the ceremony; the model holds no prompt
/// and types no phrase.
///
/// This composes the e0c/e0d allowlisted homes — it constructs no grant/capability
/// itself: the ceremony + arm live in `commands::grant::arm_local_mutate_grant`
/// (the SI-3 home), and the `from_grant` derive lives in
/// `commands::authority::local_mutate_capability` (the PD-2 home).
#[must_use]
pub fn authorize_local_mutate(
    prompt: &mut ApprovalPrompt,
    response: &str,
    command_audit_32: [u8; 32],
) -> Option<MutateCapability> {
    let grant = arm_local_mutate_grant(
        prompt,
        response,
        command_audit_32,
        GrantBounds {
            max_actions_u32: 1,
            // A synchronous single-derive: the TTL window is not load-bearing here
            // (armed → derived → dropped within one call); any positive expiry
            // admits the one immediate derive. The single-shot max_actions = 1 is
            // what makes it ONE action.
            expires_at_epoch_ms: 1,
        },
    )?;
    local_mutate_capability(&grant)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use super::*;
    use crate::command::ApprovalRequirement;
    use crate::file_context::MAX_FILE_BYTES;
    use crate::sha256_32;

    const LOCAL_PHRASE: &str = "exec-apply-owner-live";

    fn cap_for(cmd: &str) -> MutateCapability {
        let mut p = ApprovalPrompt::new(ApprovalRequirement::TypedPhrase, LOCAL_PHRASE);
        authorize_local_mutate(&mut p, LOCAL_PHRASE, sha256_32(cmd.as_bytes()))
            .expect("a matching phrase mints a capability")
    }

    /// The local authorize is fail-closed: a wrong/replayed phrase or a zero audit
    /// mints NO capability; the exact phrase + a non-zero audit mints one.
    #[test]
    fn local_authorize_requires_the_exact_phrase_and_a_binding() {
        let mut wrong = ApprovalPrompt::new(ApprovalRequirement::TypedPhrase, LOCAL_PHRASE);
        assert!(authorize_local_mutate(&mut wrong, "nope", [1u8; 32]).is_none());
        // zero audit ⇒ no capability even with the right phrase (no silent grant).
        let mut zero = ApprovalPrompt::new(ApprovalRequirement::TypedPhrase, LOCAL_PHRASE);
        assert!(authorize_local_mutate(&mut zero, LOCAL_PHRASE, [0u8; 32]).is_none());
        // right phrase + binding ⇒ a capability; replay of the consumed prompt ⇒ none.
        let mut ok = ApprovalPrompt::new(ApprovalRequirement::TypedPhrase, LOCAL_PHRASE);
        assert!(authorize_local_mutate(&mut ok, LOCAL_PHRASE, [7u8; 32]).is_some());
        assert!(
            authorize_local_mutate(&mut ok, LOCAL_PHRASE, [7u8; 32]).is_none(),
            "the consumed prompt is replay-denied (no second mint)"
        );
    }

    /// The exec action runs in the kernel sandbox at LocalWrite (or fail-closes
    /// SandboxUnavailable on a non-macOS host — NEVER unsandboxed, IV-A6).
    #[test]
    fn exec_action_runs_in_the_kernel_sandbox() {
        let cmd = "/bin/echo e10_2a_exec_ok";
        let proposal = ExecProposal {
            command: cmd.to_string(),
        };
        let cap = cap_for(cmd);
        match execute_authorized_mutate(cap, &AuthorizedMutate::Exec(&proposal)) {
            MutateExecOutcome::Exec(Ok(o)) => {
                assert_eq!(o.exit_code, Some(0), "echo exits 0 under the sandbox");
                assert_eq!(o.stdout.retained, b"e10_2a_exec_ok\n");
                assert!(!o.timed_out);
            }
            MutateExecOutcome::Exec(Err(SandboxRunDeny::SandboxUnavailable)) => {
                // non-macOS host: fail-closed (NEVER unsandboxed). Acceptable.
            }
            other => panic!("unexpected exec outcome: {other:?}"),
        }
    }

    /// The edit action applies atomically through `apply_proposal` (staleness +
    /// re-confine + verify, IV-A7) and writes the new bytes.
    #[test]
    fn edit_action_applies_atomically() {
        let dir = std::env::temp_dir().join(format!(
            "mnemos_e10_2a_edit_{}_{}",
            std::process::id(),
            COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let target = dir.join("doc.md");
        std::fs::write(&target, b"old body\n").unwrap();
        let canonical = std::fs::canonicalize(&target).unwrap();
        let policy = FileReadPolicy::new(std::slice::from_ref(&dir), MAX_FILE_BYTES);
        let proposal = FileEditProposal {
            target_path: canonical.clone(),
            read_sha_32: sha256_32(b"old body\n"),
            content: b"new body\n".to_vec(),
        };
        let cap = cap_for("edit doc.md");
        match execute_authorized_mutate(
            cap,
            &AuthorizedMutate::Edit {
                proposal: &proposal,
                policy: &policy,
            },
        ) {
            MutateExecOutcome::Edit(Ok(receipt)) => {
                assert_eq!(receipt.new_sha_32, sha256_32(b"new body\n"));
                assert_eq!(std::fs::read(&canonical).unwrap(), b"new body\n");
            }
            other => panic!("unexpected edit outcome: {other:?}"),
        }
        std::fs::remove_dir_all(&dir).ok();
    }

    static COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
}
