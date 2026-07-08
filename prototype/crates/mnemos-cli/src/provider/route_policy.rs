//! Operational provider route policy + no-silent-fallback gate.
//!
//! The [`FallbackDiff`] type (a provider/model fallback carrying a
//! visible reason + approval flag, with `is_silent` / `is_permitted`) backs the
//! *operational policy engine* this module adds: it decides, per route state, whether a
//! fallback may apply and classifies a local→external move as an explicit,
//! user-visible egress event — never a silent upgrade. A silent fallback,
//! and any routing change under `Lockdown`, render `Red`. All decisions are pure
//! projections — no provider call.
//!
//! Reuse (no reinvention): [`FallbackDiff`] from
//! [`crate::commands::model_route`], [`ProviderKind`] from
//! [`crate::commands::provider`], [`RouteExecutionState`] from [`crate::route`],
//! [`RenderTruth`] from [`crate::tui`].

use crate::commands::model_route::FallbackDiff;
use crate::commands::provider::ProviderKind;
use crate::route::RouteExecutionState;
use crate::tui::RenderTruth;

/// The verdict of evaluating a fallback against the route policy.
#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RoutePolicyVerdict {
    /// The fallback stays within the local tier and is explicit + visible.
    Allowed = 1,
    /// The fallback is permitted but crosses the egress boundary
    /// (local → external) — surfaced as an explicit, visible approval event.
    ApprovedEgressEvent = 2,
    /// Denied: the fallback is silent (no visible reason, or not approved).
    DeniedSilentFallback = 3,
    /// Denied: routing changes are frozen while the route is in `Lockdown`.
    DeniedLockdown = 4,
}

impl RoutePolicyVerdict {
    /// Whether the fallback may apply (allowed, or an approved egress event).
    #[must_use]
    pub const fn is_allowed(self) -> bool {
        matches!(self, Self::Allowed | Self::ApprovedEgressEvent)
    }

    /// The cockpit render truth: allowed local → `Green`; approved egress →
    /// `Yellow` (visible egress, attention); any denial → `Red` (no false green).
    #[must_use]
    pub const fn render(self) -> RenderTruth {
        match self {
            Self::Allowed => RenderTruth::Green,
            Self::ApprovedEgressEvent => RenderTruth::Yellow,
            Self::DeniedSilentFallback | Self::DeniedLockdown => RenderTruth::Red,
        }
    }
}

/// The operational route-policy decision for a proposed fallback. Carries the
/// visible from/to provider identities so the route label is never hidden.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RoutePolicyDecision {
    /// The policy verdict.
    pub verdict: RoutePolicyVerdict,
    /// The provider being routed away from (visible).
    pub from_kind: ProviderKind,
    /// The provider being routed to (visible).
    pub to_kind: ProviderKind,
    /// Whether the move crosses the local→external egress boundary.
    pub crosses_egress_boundary: bool,
    /// The cockpit render truth of the verdict.
    pub render: RenderTruth,
}

/// Evaluate a proposed [`FallbackDiff`] against the route policy under `state`. A
/// `Lockdown` route freezes all routing changes; a silent fallback is denied; a
/// permitted local→external move is an explicit, visible egress event; a
/// permitted local→local move is allowed.
#[must_use]
pub fn evaluate_fallback(diff: &FallbackDiff, state: RouteExecutionState) -> RoutePolicyDecision {
    let crosses_egress_boundary = diff.from_kind.is_local() && !diff.to_kind.is_local();
    let verdict = if matches!(state, RouteExecutionState::Lockdown) {
        RoutePolicyVerdict::DeniedLockdown
    } else if diff.is_silent() {
        RoutePolicyVerdict::DeniedSilentFallback
    } else if crosses_egress_boundary {
        RoutePolicyVerdict::ApprovedEgressEvent
    } else {
        RoutePolicyVerdict::Allowed
    };
    RoutePolicyDecision {
        verdict,
        from_kind: diff.from_kind,
        to_kind: diff.to_kind,
        crosses_egress_boundary,
        render: verdict.render(),
    }
}

/// The no-silent-fallback visibility of a proposed fallback. A
/// local→provider fallback is NEVER silent: a permitted fallback surfaces as a
/// VISIBLE, APPROVED route event carrying its reason; a silent fallback (unapproved
/// or reasonless) or a `Lockdown`-frozen route REFUSES the switch (it never
/// applies). This binds [`evaluate_fallback`] to the no-silent-fallback route trace
/// (the [`crate::route::RouteEvent`] a `RouterDecisionTrace` records).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FallbackVisibility {
    /// The underlying route-policy decision (verdict + from/to + render).
    pub decision: RoutePolicyDecision,
    /// Whether the fallback is permitted to apply (a visible, approved event).
    pub permitted: bool,
    /// Whether the switch is refused (silent fallback or `Lockdown`) — never applied.
    pub refused: bool,
}

impl FallbackVisibility {
    /// The visible route event to record IF the fallback is permitted: a permitted
    /// fallback is an approved + reasoned (non-silent) [`crate::route::RouteEvent`].
    /// A refused fallback (silent or `Lockdown`) records NO fallback event — the
    /// switch never applied, so there is nothing a silent switch could mask.
    #[must_use]
    pub fn permitted_event(&self) -> Option<crate::route::RouteEvent> {
        if self.permitted {
            Some(crate::route::RouteEvent::Fallback {
                approved: true,
                reason_visible: true,
            })
        } else {
            None
        }
    }

    /// Whether this fallback is a VISIBLE local→external egress event (the operator
    /// sees + approves a switch off the local executor).
    #[must_use]
    pub const fn is_visible_egress_event(&self) -> bool {
        matches!(
            self.decision.verdict,
            RoutePolicyVerdict::ApprovedEgressEvent
        )
    }
}

/// Classify a proposed fallback for the no-silent-fallback route trace: a
/// permitted local→external move is a visible approved event; a silent move (no
/// approval or no reason) or a `Lockdown`-frozen route is refused — a silent switch
/// is structurally impossible. Reuses [`evaluate_fallback`].
#[must_use]
pub fn fallback_visibility(diff: &FallbackDiff, state: RouteExecutionState) -> FallbackVisibility {
    let decision = evaluate_fallback(diff, state);
    let permitted = decision.verdict.is_allowed();
    FallbackVisibility {
        decision,
        permitted,
        refused: !permitted,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ZERO32: [u8; 32] = [0u8; 32];

    fn diff(
        from: ProviderKind,
        to: ProviderKind,
        approved: bool,
        reason: [u8; 32],
    ) -> FallbackDiff {
        FallbackDiff {
            from_kind: from,
            to_kind: to,
            from_model_hash_32: [1u8; 32],
            to_model_hash_32: [2u8; 32],
            reason_hash_32: reason,
            approved,
        }
    }

    #[test]
    fn no_silent_fallback_is_red() {
        // unapproved + no visible reason => silent
        let d = diff(ProviderKind::Naite, ProviderKind::Naite, false, ZERO32);
        let dec = evaluate_fallback(&d, RouteExecutionState::Slow);
        assert_eq!(dec.verdict, RoutePolicyVerdict::DeniedSilentFallback);
        assert_eq!(dec.render, RenderTruth::Red);
        assert!(!dec.verdict.is_allowed());
    }

    #[test]
    fn fallback_approval_required() {
        // approved but no visible reason => still silent => denied
        let d0 = diff(ProviderKind::Naite, ProviderKind::Naite, true, ZERO32);
        assert_eq!(
            evaluate_fallback(&d0, RouteExecutionState::Slow).verdict,
            RoutePolicyVerdict::DeniedSilentFallback
        );
        // approved + visible reason => allowed
        let d1 = diff(ProviderKind::Naite, ProviderKind::Naite, true, [9u8; 32]);
        assert!(
            evaluate_fallback(&d1, RouteExecutionState::Slow)
                .verdict
                .is_allowed()
        );
    }

    #[test]
    fn egress_fallback_is_visible_approval_event() {
        // local -> external, approved + reason: a visible egress event (Yellow)
        let d = diff(
            ProviderKind::Naite,
            ProviderKind::Anthropic,
            true,
            [9u8; 32],
        );
        let dec = evaluate_fallback(&d, RouteExecutionState::Slow);
        assert_eq!(dec.verdict, RoutePolicyVerdict::ApprovedEgressEvent);
        assert!(dec.crosses_egress_boundary);
        assert_eq!(dec.render, RenderTruth::Yellow);
    }

    #[test]
    fn lockdown_disables_local_route() {
        let d = diff(ProviderKind::Naite, ProviderKind::Naite, true, [9u8; 32]);
        let dec = evaluate_fallback(&d, RouteExecutionState::Lockdown);
        assert_eq!(dec.verdict, RoutePolicyVerdict::DeniedLockdown);
        assert_eq!(dec.render, RenderTruth::Red);
    }

    #[test]
    fn lockdown_disables_external_route() {
        let d = diff(ProviderKind::Naite, ProviderKind::OpenAi, true, [9u8; 32]);
        let dec = evaluate_fallback(&d, RouteExecutionState::Lockdown);
        assert_eq!(dec.verdict, RoutePolicyVerdict::DeniedLockdown);
    }

    #[test]
    fn route_labels_visible() {
        let d = diff(
            ProviderKind::Naite,
            ProviderKind::Anthropic,
            true,
            [9u8; 32],
        );
        let dec = evaluate_fallback(&d, RouteExecutionState::Normal);
        assert_eq!(dec.from_kind, ProviderKind::Naite);
        assert_eq!(dec.to_kind, ProviderKind::Anthropic);
    }

    // ---- no-silent-fallback live (visible approved route event) ----

    #[test]
    fn permitted_fallback_is_a_visible_approved_event() {
        // a degraded (Slow) local→external fallback, approved + reasoned, is a
        // VISIBLE approved egress event (Yellow), recorded as a non-silent event.
        let d = diff(
            ProviderKind::Naite,
            ProviderKind::Anthropic,
            true,
            [9u8; 32],
        );
        let fv = fallback_visibility(&d, RouteExecutionState::Slow);
        assert!(fv.permitted);
        assert!(!fv.refused);
        assert!(fv.is_visible_egress_event());
        assert_eq!(fv.decision.verdict, RoutePolicyVerdict::ApprovedEgressEvent);
        assert_eq!(fv.decision.render, RenderTruth::Yellow);
        let ev = fv.permitted_event();
        assert!(ev.is_some());
        if let Some(ev) = ev {
            assert!(
                !ev.is_silent_fallback(),
                "a permitted fallback is never silent"
            );
        }
    }

    #[test]
    fn silent_fallback_is_refused_no_switch() {
        // unapproved + no reason => silent => refused, no event recorded (no switch)
        let d = diff(ProviderKind::Naite, ProviderKind::Anthropic, false, ZERO32);
        let fv = fallback_visibility(&d, RouteExecutionState::Slow);
        assert!(fv.refused);
        assert!(!fv.permitted);
        assert_eq!(
            fv.decision.verdict,
            RoutePolicyVerdict::DeniedSilentFallback
        );
        assert_eq!(fv.decision.render, RenderTruth::Red);
        assert!(
            fv.permitted_event().is_none(),
            "a silent fallback records no event"
        );
    }

    #[test]
    fn lockdown_refuses_all_fallback() {
        // a Lockdown route refuses even an approved + reasoned fallback (refuse path)
        let d = diff(ProviderKind::Naite, ProviderKind::OpenAi, true, [9u8; 32]);
        let fv = fallback_visibility(&d, RouteExecutionState::Lockdown);
        assert!(fv.refused);
        assert_eq!(fv.decision.verdict, RoutePolicyVerdict::DeniedLockdown);
        assert!(fv.permitted_event().is_none());
    }

    #[test]
    fn escalation_consult_surfaces_as_visible_fallback() {
        // integration (escalation + route_policy): an escalation that opens
        // a consult on a degraded state MUST surface as a VISIBLE approved fallback —
        // a local→external switch is never silent.
        use crate::commands::model_route::ConsultTrigger;
        use crate::provider::escalation::{EscalationInputs, decide};
        let esc = decide(&EscalationInputs {
            route_state: RouteExecutionState::Slow,
            trigger: Some(ConsultTrigger::RepeatedFailure),
            user_approved: true,
        });
        assert!(
            esc.opens_consult(),
            "a typed trigger on SLOW opens a consult"
        );
        let d = diff(
            ProviderKind::Naite,
            ProviderKind::Anthropic,
            true,
            [7u8; 32],
        );
        let fv = fallback_visibility(&d, RouteExecutionState::Slow);
        assert!(fv.permitted && fv.is_visible_egress_event());
        assert!(
            fv.permitted_event()
                .is_some_and(|e| !e.is_silent_fallback())
        );
    }

    // falsifiability canary: permitted vs refused yield different events (Some vs None)
    #[test]
    fn permitted_and_refused_differ_canary() {
        let permitted = fallback_visibility(
            &diff(
                ProviderKind::Naite,
                ProviderKind::Anthropic,
                true,
                [9u8; 32],
            ),
            RouteExecutionState::Slow,
        );
        let refused = fallback_visibility(
            &diff(ProviderKind::Naite, ProviderKind::Anthropic, false, ZERO32),
            RouteExecutionState::Slow,
        );
        assert_ne!(permitted.permitted_event(), refused.permitted_event());
        assert!(permitted.permitted_event().is_some());
        assert!(refused.permitted_event().is_none());
    }
}
