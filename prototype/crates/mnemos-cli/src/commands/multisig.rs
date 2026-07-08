//! `sinabro multisig propose|sign|timelock` — multisig + timelock commands.
//!
//! A read-only projection of a queued mainnet action: the multisig proposal it
//! is bound to, the exact signer envelope (which carries the timelock ETA), the
//! roster threshold, the timelock policy, and how many signatures have been
//! collected. The single load-bearing invariant:
//!
//! * **The CLI cannot bypass the timelock with a local flag.**
//!   [`MultisigTimelockView::execute_decision`] takes only the wall-clock
//!   `now_secs`; there is no `force` / `skip` / `override` parameter or field. A
//!   queued action with enough signatures but before its ETA decides
//!   [`TimelockExecuteDecision::TimelockNotMatured`] — premature execution is
//!   refused, and only the passage of real time can change that. And even a
//!   matured, fully-signed action decides
//!   [`TimelockExecuteDecision::LiveExecutionForbiddenInStageF`]:
//!   [`MultisigTimelockView::live_execution_enabled`] is the invariant `false`,
//!   so it never executes live. Every decision is a denial — the surface is
//!   fail-closed.
//!
//! Reuse: the proposal envelope is the canonical
//! [`MultisigProposalEnvelope`] (roster-bound, checklist-gated); the signer
//! envelope and its timelock ETA are [`MainnetSignerEnvelope`] (ETA derived from
//! the [`TimelockPolicy`] delay, never an arbitrary number); the roster is
//! [`MultisigRoster`] (threshold >= 2 by construction); the execution posture is
//! [`mnemos_a_core::MainnetExecutionState`]; the approval gate is the canonical
//! [`approval_for`]`(`[`CommandRisk::ChainWrite`]`)` =
//! [`ApprovalRequirement::Multisig`]. This module mints no new signer/timelock
//! type — it projects the ceremony state.

use crate::command::{ApprovalRequirement, CommandRisk, approval_for};
use crate::hex32;
use mnemos_a_core::MainnetExecutionState;
use mnemos_g_wallet::{
    MainnetSignerEnvelope, MultisigProposalEnvelope, MultisigRoster, TimelockPolicy,
};

/// First 16 hex characters of a 32-byte digest/id — a redacted, display-only
/// prefix.
#[must_use]
fn redact16(bytes: &[u8; 32]) -> String {
    hex32(bytes).chars().take(16).collect()
}

/// The decision on whether a queued mainnet action may execute. Every variant is
/// a denial — the surface is fail-closed and never returns an "allow".
#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TimelockExecuteDecision {
    /// Fewer signatures than the multisig threshold have been collected.
    InsufficientSignatures = 1,
    /// The timelock ETA has not elapsed — premature execution is refused. No
    /// local flag can advance this; only wall-clock time can.
    TimelockNotMatured = 2,
    /// Enough signatures and the ETA has elapsed, but live mainnet execution is
    /// forbidden (the state never reaches `Executed`).
    LiveExecutionForbiddenInStageF = 3,
}

impl TimelockExecuteDecision {
    /// Stable u8 tag.
    #[must_use]
    pub const fn tag(self) -> u8 {
        self as u8
    }

    /// Always `true`: every decision is a denial (fail-closed; no live
    /// execution path exists).
    #[must_use]
    pub const fn is_denied(self) -> bool {
        true
    }
}

/// A read-only view of a queued multisig + timelock mainnet action. Holds no
/// secret: ids/digests are shown redacted and the rest are public counts.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MultisigTimelockView {
    /// The roster-bound, checklist-gated proposal the signers approve.
    pub proposal: MultisigProposalEnvelope,
    /// The exact signer envelope (carries the timelock ETA).
    pub signer: MainnetSignerEnvelope,
    /// The multisig roster (threshold + signer count).
    pub roster: MultisigRoster,
    /// The timelock policy the action must wait out.
    pub timelock: TimelockPolicy,
    /// Number of signatures collected so far.
    pub signatures_collected_u8: u8,
    /// The mainnet execution posture (never `Executed`).
    pub execution_state: MainnetExecutionState,
}

impl MultisigTimelockView {
    /// Build a queued-action view from the proposal, signer envelope, roster,
    /// timelock policy, collected-signature count, and execution posture.
    #[must_use]
    pub const fn new(
        proposal: MultisigProposalEnvelope,
        signer: MainnetSignerEnvelope,
        roster: MultisigRoster,
        timelock: TimelockPolicy,
        signatures_collected_u8: u8,
        execution_state: MainnetExecutionState,
    ) -> Self {
        Self {
            proposal,
            signer,
            roster,
            timelock,
            signatures_collected_u8,
            execution_state,
        }
    }

    /// Whether the collected signatures meet the roster threshold.
    #[must_use]
    pub const fn signatures_met(&self) -> bool {
        self.signatures_collected_u8 >= self.roster.threshold_u8
    }

    /// Whether the timelock ETA has elapsed at `now_secs`. The ETA is the signer
    /// envelope's `timelock_eta_secs_u64`, derived from the timelock policy delay.
    #[must_use]
    pub const fn timelock_matured(&self, now_secs: u64) -> bool {
        now_secs >= self.signer.timelock_eta_secs_u64
    }

    /// Decide whether the queued action may execute at `now_secs`. Checked in a
    /// fixed order — signatures, then timelock maturity — and live execution is
    /// always denied at the end. There is no override parameter: a local
    /// flag cannot bypass the timelock.
    #[must_use]
    pub const fn execute_decision(&self, now_secs: u64) -> TimelockExecuteDecision {
        if !self.signatures_met() {
            return TimelockExecuteDecision::InsufficientSignatures;
        }
        if !self.timelock_matured(now_secs) {
            return TimelockExecuteDecision::TimelockNotMatured;
        }
        TimelockExecuteDecision::LiveExecutionForbiddenInStageF
    }

    /// Whether the CLI may execute the queued action live. Always `false` —
    /// the timelock/multisig ceremony is displayed, never exercised.
    #[must_use]
    pub const fn live_execution_enabled(&self) -> bool {
        false
    }

    /// The approval gate a real execution requires. Always
    /// [`ApprovalRequirement::Multisig`], via the canonical
    /// [`approval_for`]`(`[`CommandRisk::ChainWrite`]`)` mapping.
    #[must_use]
    pub fn approval(&self) -> ApprovalRequirement {
        approval_for(CommandRisk::ChainWrite)
    }

    /// Redacted, colorless state lines bounded by `rows`, evaluated at `now_secs`.
    #[must_use]
    pub fn render(&self, rows: u16, now_secs: u64) -> Vec<String> {
        let lines = vec![
            format!("package={}", redact16(self.proposal.package.as_bytes())),
            format!(
                "package_digest={}",
                redact16(&self.proposal.package_digest_32)
            ),
            format!("checklist={}", redact16(&self.proposal.checklist_hash_32)),
            format!("roster_hash={}", redact16(&self.proposal.roster_hash_32)),
            format!("tx_digest={}", redact16(&self.signer.tx_digest_32)),
            format!("policy_hash={}", redact16(&self.signer.policy_hash_32)),
            format!("timelock_eta_secs={}", self.signer.timelock_eta_secs_u64),
            format!("multisig_threshold={}", self.roster.threshold_u8),
            format!("multisig_signers={}", self.roster.signer_count_u8),
            format!(
                "timelock_min_delay_secs={}",
                self.timelock.min_delay_secs_u32
            ),
            format!(
                "timelock_cancel_window_secs={}",
                self.timelock.cancel_window_secs_u32
            ),
            format!("signatures_collected={}", self.signatures_collected_u8),
            format!("signatures_met={}", self.signatures_met()),
            format!("now_secs={now_secs}"),
            format!("timelock_matured={}", self.timelock_matured(now_secs)),
            format!(
                "execute_decision_u8={}",
                self.execute_decision(now_secs).tag()
            ),
            format!("live_execution_enabled={}", self.live_execution_enabled()),
            format!("execution_state_u8={}", self.execution_state.as_u8()),
            format!("approval_u8={}", self.approval() as u8),
        ];
        lines.into_iter().take(rows as usize).collect()
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    #![allow(clippy::expect_used)]
    #![allow(clippy::panic)]

    use super::*;
    use crate::repl::latency::p95_ms;
    use mnemos_d_move::{ObjectId, SuiAddress};

    const QUEUED_AT: u64 = 1_000;
    // eta = queued_at + MIN_TIMELOCK_DELAY_SECS (86_400)
    const ETA: u64 = QUEUED_AT + 86_400;

    fn roster() -> MultisigRoster {
        MultisigRoster::from_signers(
            &[
                SuiAddress::new([1; 32]),
                SuiAddress::new([2; 32]),
                SuiAddress::new([3; 32]),
            ],
            2,
        )
        .expect("2-of-3 roster builds")
    }

    fn timelock() -> TimelockPolicy {
        TimelockPolicy::from_parts(86_400, 3_600, true).expect("timelock builds")
    }

    fn proposal(r: &MultisigRoster) -> MultisigProposalEnvelope {
        MultisigProposalEnvelope::new(ObjectId::new([0x22; 32]), [0xAB; 32], [0xCD; 32], r)
            .expect("proposal builds")
    }

    fn signer(tl: &TimelockPolicy) -> MainnetSignerEnvelope {
        MainnetSignerEnvelope::from_timelock(
            ObjectId::new([0x22; 32]),
            [0xAB; 32],
            [0xCD; 32],
            tl,
            QUEUED_AT,
        )
        .expect("signer envelope builds")
    }

    fn view(signatures: u8, state: MainnetExecutionState) -> MultisigTimelockView {
        let r = roster();
        let tl = timelock();
        MultisigTimelockView::new(proposal(&r), signer(&tl), r, tl, signatures, state)
    }

    #[test]
    fn propose_is_roster_bound() {
        let r = roster();
        let p = proposal(&r);
        // The proposal binds the roster's signer-set hash.
        assert_eq!(p.roster_hash_32, r.signer_hash());
        assert_eq!(p.verify_package_digest(&[0xAB; 32]), Ok(()));
    }

    #[test]
    fn sign_derives_eta_from_timelock() {
        let tl = timelock();
        let s = signer(&tl);
        // ETA is queued_at + the policy min delay, never an arbitrary number.
        assert_eq!(s.timelock_eta_secs_u64, ETA);
    }

    #[test]
    fn timelock_pending_before_eta_is_denied() {
        // Signatures met, but now < eta -> not matured -> premature deny.
        let v = view(2, MainnetExecutionState::TimelockQueued);
        assert!(v.signatures_met());
        assert!(!v.timelock_matured(ETA - 1));
        assert_eq!(
            v.execute_decision(ETA - 1),
            TimelockExecuteDecision::TimelockNotMatured
        );
    }

    #[test]
    fn premature_execute_cannot_be_bypassed_by_any_local_state() {
        // Even with full signatures AND an `Executed` posture, a now before the
        // ETA still decides TimelockNotMatured: no local flag/state advances the
        // timelock — only wall-clock time can.
        let v = view(2, MainnetExecutionState::Executed);
        assert_eq!(
            v.execute_decision(ETA - 1),
            TimelockExecuteDecision::TimelockNotMatured
        );
        assert!(!v.live_execution_enabled());
    }

    #[test]
    fn insufficient_signatures_is_denied() {
        // One signature, threshold is 2 -> insufficient (checked before timelock).
        let v = view(1, MainnetExecutionState::TimelockQueued);
        assert!(!v.signatures_met());
        assert_eq!(
            v.execute_decision(ETA + 10_000),
            TimelockExecuteDecision::InsufficientSignatures
        );
    }

    #[test]
    fn matured_and_signed_still_forbidden_in_stage_f() {
        // Signatures met + matured -> live execution is still forbidden.
        let v = view(2, MainnetExecutionState::TimelockQueued);
        assert!(v.timelock_matured(ETA));
        let decision = v.execute_decision(ETA);
        assert_eq!(
            decision,
            TimelockExecuteDecision::LiveExecutionForbiddenInStageF
        );
        assert!(decision.is_denied(), "every Stage F decision is a denial");
    }

    #[test]
    fn render_redacts_and_is_bounded() {
        let v = view(2, MainnetExecutionState::TimelockQueued);
        // The full 64-hex digest never appears in the render.
        assert!(
            !v.render(64, ETA)
                .iter()
                .any(|l| l.contains(&hex32(&[0xAB; 32])))
        );
        assert!(v.render(3, ETA).len() <= 3);
    }

    #[test]
    fn state_render_p95_within_50ms() {
        let v = view(2, MainnetExecutionState::TimelockQueued);
        let mut samples = Vec::with_capacity(256);
        for _ in 0..256 {
            let t = std::time::Instant::now();
            let lines = v.render(32, ETA - 1);
            std::hint::black_box(&lines);
            samples.push(t.elapsed().as_nanos() as u64);
        }
        let p95 = p95_ms(&samples) / 1_000_000;
        assert!(
            p95 <= 50,
            "multisig state render p95 {p95}ms exceeds 50ms budget"
        );
    }
}
