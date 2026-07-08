//! Speculation status view.
//!
//! `sinabro model speculate status`. Speculative work — a draft model proposes
//! tokens that a verify pass either accepts or rejects (speculative decoding /
//! speculative tool planning) — is **cancellable, budgeted, and route-visible**,
//! and it never commits a side effect without an explicit approval. The view
//! exposes the draft-vs-verify identity, the accepted-token ratio, the
//! rejected-token cost, and the cancellation path.
//!
//! A frontier-role speculation is advisory only: a [`ModelRole::is_frontier`]
//! role may generate options or critique but can never run a tool, edit a file,
//! approve a wallet/gas/live action, or become positive training data before a
//! local verification.
//!
//! Reuse: the saturating-ledger + refusal-channel semantics
//! mirror the `DailyTokenBudget` (`crates/m-agent/src/loop_budget.rs`),
//! modeled here as a local status view rather than imported — the status hot
//! path never pulls the agent runtime. Reuses [`ModelRole`],
//! [`RouteExecutionState`], and [`StageFTraceLink`].

use crate::StageFTraceLink;
use crate::commands::provider::ModelRole;
use crate::route::RouteExecutionState;
use crate::sha256_32;

/// Lifecycle phase of a speculative unit of work.
#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SpeculationPhase {
    /// The draft model is proposing tokens.
    Drafting = 1,
    /// The proposed tokens are being verified.
    Verifying = 2,
    /// The verify pass completed with every drafted token accepted.
    Accepted = 3,
    /// The verify pass completed with one or more rejected (wasted) tokens.
    Rejected = 4,
    /// The speculation was cancelled before completion (the cancel path).
    Cancelled = 5,
}

impl SpeculationPhase {
    /// Whether this is a terminal phase — no further drafting is possible.
    #[must_use]
    pub const fn is_terminal(self) -> bool {
        matches!(self, Self::Accepted | Self::Rejected | Self::Cancelled)
    }
}

/// A speculation token ledger. The draft budget is a hard *cap*: a draft that
/// would exceed it is refused (the `DailyTokenBudget`-style refusal channel),
/// never silently truncated. After the verify pass the drafted tokens split
/// into accepted (kept) and rejected (wasted draft cost). All arithmetic
/// saturates and accepted/rejected can never exceed what was drafted.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SpeculationLedger {
    phase: SpeculationPhase,
    draft_cap_u32: u32,
    drafted_u32: u32,
    accepted_u32: u32,
    rejected_u32: u32,
}

impl SpeculationLedger {
    /// A new ledger in [`SpeculationPhase::Drafting`] with a draft token cap.
    #[must_use]
    pub const fn new(draft_cap_u32: u32) -> Self {
        Self {
            phase: SpeculationPhase::Drafting,
            draft_cap_u32,
            drafted_u32: 0,
            accepted_u32: 0,
            rejected_u32: 0,
        }
    }

    /// The current phase.
    #[must_use]
    pub const fn phase(self) -> SpeculationPhase {
        self.phase
    }

    /// The draft token cap.
    #[must_use]
    pub const fn draft_cap(self) -> u32 {
        self.draft_cap_u32
    }

    /// Total tokens drafted so far.
    #[must_use]
    pub const fn drafted(self) -> u32 {
        self.drafted_u32
    }

    /// Accepted (verified) tokens.
    #[must_use]
    pub const fn accepted(self) -> u32 {
        self.accepted_u32
    }

    /// Rejected (wasted) tokens.
    #[must_use]
    pub const fn rejected(self) -> u32 {
        self.rejected_u32
    }

    /// Draft `tokens` more speculative tokens. Refused (`false`) when the ledger
    /// is terminal or when the draft would exceed the cap — the cap is hard
    /// (budget is enforced before, never after, the work).
    pub fn draft(&mut self, tokens: u32) -> bool {
        if self.phase.is_terminal() {
            return false;
        }
        let next = self.drafted_u32.saturating_add(tokens);
        if next > self.draft_cap_u32 {
            return false;
        }
        self.drafted_u32 = next;
        self.phase = SpeculationPhase::Drafting;
        true
    }

    /// Record the verify outcome: of the drafted tokens, `accepted` were verified
    /// and the remainder are rejected (wasted draft cost). `accepted` is clamped
    /// to what was drafted. Moves to [`SpeculationPhase::Accepted`] when nothing
    /// was rejected, otherwise [`SpeculationPhase::Rejected`]. A no-op on a
    /// terminal ledger.
    pub fn verify(&mut self, accepted: u32) {
        if self.phase.is_terminal() {
            return;
        }
        let accepted = accepted.min(self.drafted_u32);
        self.accepted_u32 = accepted;
        self.rejected_u32 = self.drafted_u32 - accepted;
        self.phase = if self.rejected_u32 == 0 {
            SpeculationPhase::Accepted
        } else {
            SpeculationPhase::Rejected
        };
    }

    /// Cancel the speculation. Any non-terminal ledger moves to
    /// [`SpeculationPhase::Cancelled`]; a terminal ledger is unchanged.
    pub fn cancel(&mut self) {
        if !self.phase.is_terminal() {
            self.phase = SpeculationPhase::Cancelled;
        }
    }

    /// Accepted-token ratio in basis points (`accepted / drafted`, `0..=10000`).
    /// Returns `0` before anything is drafted.
    #[must_use]
    pub const fn accepted_ratio_bps(self) -> u16 {
        if self.drafted_u32 == 0 {
            return 0;
        }
        ((self.accepted_u32 as u64 * 10_000) / self.drafted_u32 as u64) as u16
    }

    /// Wasted (rejected) draft cost in micro-units given a per-token cost. The
    /// product saturates.
    #[must_use]
    pub const fn rejected_cost_micro(self, unit_cost_micro_u64: u64) -> u64 {
        (self.rejected_u32 as u64).saturating_mul(unit_cost_micro_u64)
    }
}

/// The canonical speculative-decoding draft model id — a small fast
/// proposer (Qwen2.5-Coder-1.5B).
pub const SPECULATION_DRAFT_MODEL_ID: &str = "Qwen2.5-Coder-1.5B";

/// The canonical speculative-decoding verify model id — the larger target
/// that accepts/rejects the draft (Strand-Rust-Coder-14B).
pub const SPECULATION_VERIFY_MODEL_ID: &str = "Strand-Rust-Coder-14B";

/// The draft vs verify model identity of a speculation. Speculative decoding
/// uses a small draft model and a larger verify model; both identities are
/// visible and, in the normal case, distinct.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SpeculationIdentity {
    /// SHA-256 of the draft (proposer) model identity.
    pub draft_identity_hash_32: [u8; 32],
    /// SHA-256 of the verify (target) model identity.
    pub verify_identity_hash_32: [u8; 32],
}

impl SpeculationIdentity {
    /// Build a draft/verify identity from the two model id strings.
    #[must_use]
    pub fn new(draft_model_id: &str, verify_model_id: &str) -> Self {
        Self {
            draft_identity_hash_32: sha256_32(draft_model_id.as_bytes()),
            verify_identity_hash_32: sha256_32(verify_model_id.as_bytes()),
        }
    }

    /// Whether the draft and verify identities are distinct (the normal case).
    #[must_use]
    pub fn is_distinct(self) -> bool {
        self.draft_identity_hash_32 != self.verify_identity_hash_32
    }

    /// The canonical draft/verify identity. The draft proposer is the
    /// `Qwen2.5-Coder-1.5B` model and the verify target is the
    /// `Strand-Rust-Coder-14B` model; the two are distinct, so a speculative
    /// speed claim is never a single-model disguise.
    #[must_use]
    pub fn strand_qwen() -> Self {
        Self::new(SPECULATION_DRAFT_MODEL_ID, SPECULATION_VERIFY_MODEL_ID)
    }
}

/// Status-only projection of a speculation (`model speculate status`). A flat
/// `Copy` view; never commits a side effect itself.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SpeculationStatusView {
    /// Current lifecycle phase.
    pub phase: SpeculationPhase,
    /// The role driving the speculation.
    pub speculator_role: ModelRole,
    /// Draft/verify model identity.
    pub identity: SpeculationIdentity,
    /// Tokens drafted.
    pub drafted_token_u32: u32,
    /// Tokens accepted (verified).
    pub accepted_token_u32: u32,
    /// Tokens rejected (wasted).
    pub rejected_token_u32: u32,
    /// Accepted-token ratio in basis points.
    pub accepted_ratio_bps: u16,
    /// Rejected (wasted) cost in micro-units.
    pub rejected_cost_micro_u64: u64,
    /// The route state this speculation runs under (route-visible).
    pub route_state: RouteExecutionState,
    /// The route-trace link attached to this speculation.
    pub trace: StageFTraceLink,
    /// Whether the speculation can still be cancelled (non-terminal).
    pub cancellable: bool,
    /// Whether this role may execute tools / edit files (only `LocalExecutor`).
    pub can_execute: bool,
    /// Whether the output is advisory only (always for a frontier role).
    pub advisory_only: bool,
    /// Local verification is required before the output is trusted — invariant `true`.
    pub local_verification_required: bool,
}

/// A speculation: a ledger plus the role / identity / route / trace it projects.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Speculation {
    ledger: SpeculationLedger,
    role: ModelRole,
    identity: SpeculationIdentity,
    route_state: RouteExecutionState,
    trace: StageFTraceLink,
}

impl Speculation {
    /// Build a speculation bound to a role, a draft/verify identity, a route
    /// state, and a route-trace link, with a draft token cap.
    #[must_use]
    pub fn new(
        role: ModelRole,
        identity: SpeculationIdentity,
        route_state: RouteExecutionState,
        trace: StageFTraceLink,
        draft_cap_u32: u32,
    ) -> Self {
        Self {
            ledger: SpeculationLedger::new(draft_cap_u32),
            role,
            identity,
            route_state,
            trace,
        }
    }

    /// Mutable access to the token ledger (draft / verify / cancel).
    pub fn ledger_mut(&mut self) -> &mut SpeculationLedger {
        &mut self.ledger
    }

    /// The token ledger.
    #[must_use]
    pub const fn ledger(&self) -> SpeculationLedger {
        self.ledger
    }

    /// Whether this speculation's role may run a tool. Only
    /// [`ModelRole::LocalExecutor`] may; a frontier reviewer/critic is denied.
    #[must_use]
    pub const fn can_run_tool(&self) -> bool {
        self.role.can_execute_tools()
    }

    /// Whether this speculation's role may edit a file — same gate as tool-run.
    #[must_use]
    pub const fn can_edit_file(&self) -> bool {
        self.role.can_execute_tools()
    }

    /// Try to commit a side effect. Denied (`false`) unless the role may execute
    /// (`LocalExecutor`) **and** an explicit approval was given. A frontier role
    /// is always denied; an unapproved local commit is always denied.
    #[must_use]
    pub const fn try_commit_side_effect(&self, approved: bool) -> bool {
        self.role.can_execute_tools() && approved
    }

    /// Whether the speculation output is reward-eligible (may become positive
    /// training data). Only `true` after a local verification — unverified advice
    /// (including all frontier advice) is never positive training data.
    #[must_use]
    pub const fn reward_eligible(&self, locally_verified: bool) -> bool {
        locally_verified
    }

    /// The status projection (`model speculate status`).
    #[must_use]
    pub fn status_view(&self, unit_cost_micro_u64: u64) -> SpeculationStatusView {
        SpeculationStatusView {
            phase: self.ledger.phase(),
            speculator_role: self.role,
            identity: self.identity,
            drafted_token_u32: self.ledger.drafted(),
            accepted_token_u32: self.ledger.accepted(),
            rejected_token_u32: self.ledger.rejected(),
            accepted_ratio_bps: self.ledger.accepted_ratio_bps(),
            rejected_cost_micro_u64: self.ledger.rejected_cost_micro(unit_cost_micro_u64),
            route_state: self.route_state,
            trace: self.trace,
            cancellable: !self.ledger.phase().is_terminal(),
            can_execute: self.role.can_execute_tools(),
            advisory_only: self.role.is_frontier(),
            local_verification_required: true,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn trace() -> StageFTraceLink {
        StageFTraceLink::new([7u8; 32], 431, 0)
    }

    fn identity() -> SpeculationIdentity {
        SpeculationIdentity::new("naite-draft-1", "naite-verify-7")
    }

    fn spec(role: ModelRole, cap: u32) -> Speculation {
        Speculation::new(role, identity(), RouteExecutionState::Slow, trace(), cap)
    }

    #[test]
    fn speculation_budget_cap_is_hard() {
        let mut s = spec(ModelRole::LocalExecutor, 100);
        assert!(s.ledger_mut().draft(60));
        // 60 + 50 = 110 > 100 cap -> refused, drafted stays 60
        assert!(!s.ledger_mut().draft(50));
        assert_eq!(s.ledger().drafted(), 60);
        // exactly to the cap is allowed
        assert!(s.ledger_mut().draft(40));
        assert_eq!(s.ledger().drafted(), 100);
    }

    #[test]
    fn cancel_is_terminal_and_blocks_drafting() {
        let mut s = spec(ModelRole::LocalExecutor, 100);
        assert!(s.ledger_mut().draft(10));
        s.ledger_mut().cancel();
        assert_eq!(s.ledger().phase(), SpeculationPhase::Cancelled);
        assert!(
            !s.ledger_mut().draft(10),
            "drafting after cancel must be refused"
        );
        assert!(!s.status_view(1).cancellable);
    }

    #[test]
    fn side_effect_denied_without_approval_or_for_frontier() {
        let local = spec(ModelRole::LocalExecutor, 100);
        assert!(
            !local.try_commit_side_effect(false),
            "unapproved local commit denied"
        );
        assert!(
            local.try_commit_side_effect(true),
            "approved local commit allowed"
        );
        let frontier = spec(ModelRole::FrontierReviewer, 100);
        assert!(
            !frontier.try_commit_side_effect(true),
            "a frontier role can never commit a side effect, even approved"
        );
    }

    #[test]
    fn draft_verify_identity_is_visible_and_distinct() {
        let s = spec(ModelRole::LocalExecutor, 100);
        let v = s.status_view(1);
        assert!(v.identity.is_distinct());
        assert_ne!(
            v.identity.draft_identity_hash_32,
            v.identity.verify_identity_hash_32
        );
    }

    #[test]
    fn accepted_ratio_bps_is_correct() {
        let mut s = spec(ModelRole::LocalExecutor, 100);
        assert!(s.ledger_mut().draft(80));
        s.ledger_mut().verify(60); // 60 accepted of 80 drafted -> 7500 bps
        assert_eq!(s.ledger().accepted_ratio_bps(), 7500);
        assert_eq!(s.ledger().phase(), SpeculationPhase::Rejected);
    }

    #[test]
    fn rejected_cost_is_wasted_draft_times_unit() {
        let mut s = spec(ModelRole::LocalExecutor, 100);
        assert!(s.ledger_mut().draft(80));
        s.ledger_mut().verify(60); // 20 rejected
        assert_eq!(s.ledger().rejected(), 20);
        assert_eq!(s.ledger().rejected_cost_micro(50), 1_000);
    }

    #[test]
    fn route_trace_is_attached() {
        let s = spec(ModelRole::LocalExecutor, 100);
        let v = s.status_view(1);
        assert_eq!(v.trace, trace());
        assert_eq!(v.route_state, RouteExecutionState::Slow);
    }

    #[test]
    fn frontier_tool_run_denied() {
        for role in [ModelRole::FrontierReviewer, ModelRole::FrontierCritic] {
            let s = spec(role, 100);
            assert!(!s.can_run_tool(), "{role:?} must be denied tool-run");
        }
    }

    #[test]
    fn frontier_edit_denied() {
        for role in [ModelRole::FrontierReviewer, ModelRole::FrontierCritic] {
            let s = spec(role, 100);
            assert!(!s.can_edit_file(), "{role:?} must be denied file-edit");
        }
        assert!(spec(ModelRole::LocalExecutor, 100).can_edit_file());
    }

    #[test]
    fn unverified_advice_is_not_reward_eligible() {
        let s = spec(ModelRole::FrontierReviewer, 100);
        assert!(
            !s.reward_eligible(false),
            "unverified advice must not be reward-eligible"
        );
        assert!(
            s.reward_eligible(true),
            "locally verified output may be reward-eligible"
        );
        assert!(s.status_view(1).advisory_only);
        assert!(s.status_view(1).local_verification_required);
    }

    #[test]
    fn canonical_strand_qwen_pairing_distinct_and_route_visible() {
        let id = SpeculationIdentity::strand_qwen();
        // the 1.5B draft and 14B verify are distinct models (no single-model disguise)
        assert!(id.is_distinct());
        assert_eq!(
            id.draft_identity_hash_32,
            sha256_32(SPECULATION_DRAFT_MODEL_ID.as_bytes())
        );
        assert_eq!(
            id.verify_identity_hash_32,
            sha256_32(SPECULATION_VERIFY_MODEL_ID.as_bytes())
        );
        // route-visible via the status view; accepted-ratio is measured (hit saves)
        let mut s = Speculation::new(
            ModelRole::LocalExecutor,
            id,
            RouteExecutionState::Slow,
            trace(),
            100,
        );
        assert!(s.ledger_mut().draft(80));
        s.ledger_mut().verify(72); // 72 of 80 accepted -> 9000 bps
        let v = s.status_view(1);
        assert!(v.identity.is_distinct());
        assert_eq!(v.accepted_ratio_bps, 9000);
        assert_eq!(v.route_state, RouteExecutionState::Slow);
    }

    #[test]
    fn full_accept_moves_to_accepted_phase() {
        let mut s = spec(ModelRole::LocalExecutor, 100);
        assert!(s.ledger_mut().draft(40));
        s.ledger_mut().verify(40);
        assert_eq!(s.ledger().phase(), SpeculationPhase::Accepted);
        assert_eq!(s.ledger().accepted_ratio_bps(), 10_000);
        assert_eq!(s.ledger().rejected(), 0);
    }
}
