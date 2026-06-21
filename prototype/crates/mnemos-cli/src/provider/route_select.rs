//! `provider::route_select` — the typed consult-route selector
//! (ENDGAME E2-2, PD-7 / RD-49 v1, owner-authorized 2026-06-12).
//!
//! The SINGLE typed source of truth for "which executor serves a consult": the
//! local loopback Naite executor (the autonomy DEFAULT — READ-class, free, zero
//! egress) or the external frontier executor (the owner-ARMED escalation). It
//! replaces the ad-hoc phrase string-compare at the dispatch routing site with
//! ONE testable, capability-routed decision, so the routing policy can never
//! drift across the build combinations.
//!
//! PD-7 (local-first autonomy): an AUTONOMOUS turn defaults to the LOCAL
//! executor. The external frontier is reached ONLY as an explicit owner-armed
//! escalation — it requires a VALID E0d [`EgressCapability`], which exists ONLY
//! from a valid owner-armed E0c grant ([`crate::commands::grant::EgressGrant`]).
//! The model has NO constructor for an `EgressCapability` (E0d, compile-fail
//! proven), so it CANNOT self-route to the frontier (IV-L6, reinforced here at
//! the route layer): a frontier escalation WITHOUT a capability fails closed
//! ([`ConsultRoute::FrontierDeniedNoGrant`]) and is NEVER silently downgraded to
//! local NOR silently fired (L5 no-silent-fallback). A local-unreachable runtime
//! is handled DOWNSTREAM by the executor's typed `Unreachable` — this selector
//! never maps an unreachable local route onto the frontier (no silent egress).
//!
//! Deferred (owner-locked E2 seam pick 2026-06-12 "local-first + 명시적
//! escalation"): a smart confidence / blast-radius router (RD-49 full) is NOT
//! built here — E2 is the simplest honest default (local-first + explicit
//! escalation). The autonomous RUNTIME that calls this selector with
//! [`ConsultCaller::Autonomous`] is the E3 daemon; at E2 the LIVE consumer is the
//! owner-interactive dispatch arm (the local-route decision), and the autonomous
//! branch is the typed seam E3 consumes (the E0c-grant precedent).
//!
//! Reuse (no reinvention; sibling-reuse-check 2026-06-12): [`EgressCapability`]
//! from [`crate::commands::authority`] (E0d). This is the ORTHOGONAL
//! "which executor fires" selection — distinct from the provider↔provider
//! fallback policy ([`crate::provider::route_policy`]), the router status surface
//! ([`crate::commands::model_route`]), and the route state machine
//! ([`crate::provider::route_fsm`]); none of those selects the consult executor.

use crate::commands::authority::EgressCapability;

/// Who is driving the consult. PD-7: an autonomous turn defaults to local.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ConsultCaller {
    /// The interactive owner at the dispatch line. Frontier is selected by the
    /// explicit per-action ceremony phrase (today's typed-phrase gate at the
    /// executor) — the owner's own escalation act.
    Owner,
    /// The autonomous runtime (E3 daemon). Defaults to the local executor
    /// (READ-class, free, zero egress); a frontier escalation requires a VALID
    /// owner-armed [`EgressCapability`].
    Autonomous,
}

/// The route intent classified from the owner's supplied ceremony token (never
/// the raw string — the dispatch arm classifies against the exact phrase
/// constants). For the autonomous caller, [`ConsultPhrase::Frontier`] denotes an
/// explicit frontier escalation intent (still capability-gated).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ConsultPhrase {
    /// The exact local route phrase (`consult-local-naite-live`).
    Local,
    /// The exact frontier route phrase (`consult-frontier-provider-live`) — an
    /// explicit frontier escalation intent.
    Frontier,
    /// No exact route phrase supplied.
    None,
}

/// The selected consult executor — the single typed routing truth (PD-7 / RD-49).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ConsultRoute {
    /// The local loopback Naite executor (READ-class, free, zero egress). The
    /// autonomy DEFAULT.
    LocalLoopback,
    /// The external frontier executor — the owner-armed egress escalation (the
    /// ONLY route off-box).
    Frontier,
    /// No executor fires: the owner supplied no ceremony phrase ⇒ the locked
    /// surface renders.
    Locked,
    /// An autonomous frontier escalation was requested WITHOUT a valid owner-armed
    /// grant ⇒ fail-closed. The runtime surfaces a typed "frontier needs an armed
    /// grant"; it is NEVER silently downgraded to local NOR silently fired (L5).
    FrontierDeniedNoGrant,
}

impl ConsultRoute {
    /// Whether this route fires the LOCAL loopback executor.
    #[must_use]
    pub const fn is_local(self) -> bool {
        matches!(self, Self::LocalLoopback)
    }

    /// Whether this route fires the external FRONTIER executor (the only egress
    /// route).
    #[must_use]
    pub const fn is_frontier(self) -> bool {
        matches!(self, Self::Frontier)
    }

    /// Whether NO executor fires (the locked surface, or a fail-closed denial).
    #[must_use]
    pub const fn fires_no_executor(self) -> bool {
        matches!(self, Self::Locked | Self::FrontierDeniedNoGrant)
    }
}

/// Select the consult executor (PD-7 / RD-49 v1) — the single typed routing truth.
///
/// - OWNER: the explicit ceremony phrase IS the selection — the local phrase ⇒
///   local, the frontier phrase ⇒ frontier (the executor's typed-phrase gate is
///   the per-action escalation), no phrase ⇒ locked. `egress` is unused for the
///   owner: the per-action ceremony at the executor is the owner's gate.
/// - AUTONOMOUS (E3): the default ⇒ local (PD-7). An explicit frontier escalation
///   fires the frontier ONLY with a valid owner-armed [`EgressCapability`];
///   without one it fails closed ([`ConsultRoute::FrontierDeniedNoGrant`]) —
///   never silent local, never silent frontier (L5). The model cannot mint an
///   `EgressCapability` (E0d), so it cannot self-route to the frontier (IV-L6).
#[must_use]
pub fn select_consult_route(
    caller: ConsultCaller,
    phrase: ConsultPhrase,
    egress: Option<&EgressCapability>,
) -> ConsultRoute {
    match caller {
        ConsultCaller::Owner => match phrase {
            ConsultPhrase::Local => ConsultRoute::LocalLoopback,
            ConsultPhrase::Frontier => ConsultRoute::Frontier,
            ConsultPhrase::None => ConsultRoute::Locked,
        },
        ConsultCaller::Autonomous => match phrase {
            // PD-7: the autonomy default is local — free, private, zero egress.
            ConsultPhrase::Local | ConsultPhrase::None => ConsultRoute::LocalLoopback,
            // An explicit frontier escalation needs a valid owner-armed grant.
            ConsultPhrase::Frontier => match egress {
                Some(_) => ConsultRoute::Frontier,
                None => ConsultRoute::FrontierDeniedNoGrant,
            },
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    // E0d CHECK-B (no-self-escalation grep): the capability MINT stays inside
    // authority.rs — this test borrows a valid capability from the shared
    // `#[cfg(test)]` helper there, so NO `from_grant` call exists outside
    // authority.rs (the grep keeps one constructor site; no security relaxation).
    use crate::commands::authority::test_egress_capability;

    // ---- OWNER: the explicit phrase is the route (byte-faithful to dispatch) ----

    #[test]
    fn owner_local_phrase_routes_local() {
        assert_eq!(
            select_consult_route(ConsultCaller::Owner, ConsultPhrase::Local, None),
            ConsultRoute::LocalLoopback
        );
    }

    #[test]
    fn owner_frontier_phrase_routes_frontier() {
        // the owner's explicit ceremony phrase IS the escalation act (the
        // executor's typed-phrase gate enforces it per-action).
        assert_eq!(
            select_consult_route(ConsultCaller::Owner, ConsultPhrase::Frontier, None),
            ConsultRoute::Frontier
        );
    }

    #[test]
    fn owner_no_phrase_is_locked() {
        assert_eq!(
            select_consult_route(ConsultCaller::Owner, ConsultPhrase::None, None),
            ConsultRoute::Locked
        );
    }

    // ---- AUTONOMOUS: PD-7 local-first, frontier is owner-armed only ----

    #[test]
    fn autonomous_defaults_to_local() {
        // PD-7: no phrase and the local phrase both default to the local executor.
        assert_eq!(
            select_consult_route(ConsultCaller::Autonomous, ConsultPhrase::None, None),
            ConsultRoute::LocalLoopback
        );
        assert_eq!(
            select_consult_route(ConsultCaller::Autonomous, ConsultPhrase::Local, None),
            ConsultRoute::LocalLoopback
        );
        // even holding a valid egress capability, the DEFAULT (no frontier
        // escalation intent) stays local — local-first is not overridden by merely
        // having a grant armed.
        let cap = test_egress_capability();
        assert_eq!(
            select_consult_route(ConsultCaller::Autonomous, ConsultPhrase::None, Some(&cap)),
            ConsultRoute::LocalLoopback
        );
    }

    #[test]
    fn autonomous_frontier_fires_only_with_a_valid_grant() {
        let cap = test_egress_capability();
        assert_eq!(
            select_consult_route(
                ConsultCaller::Autonomous,
                ConsultPhrase::Frontier,
                Some(&cap)
            ),
            ConsultRoute::Frontier
        );
    }

    /// THE SECURITY PROOF (IV-L6 at the route layer + L5 no-silent-fallback): an
    /// autonomous frontier escalation WITHOUT an owner-armed capability fails
    /// closed — it is NOT routed to the frontier (no self-route) and NOT silently
    /// downgraded to local (no silent fallback). The model cannot mint an
    /// `EgressCapability` (E0d), so this branch is the only one a model could
    /// reach, and it fires no executor.
    #[test]
    fn autonomous_frontier_without_grant_fails_closed_no_self_route_no_silent_fallback() {
        let route = select_consult_route(ConsultCaller::Autonomous, ConsultPhrase::Frontier, None);
        assert_eq!(route, ConsultRoute::FrontierDeniedNoGrant);
        assert!(
            !route.is_frontier(),
            "no self-route to the frontier without a grant"
        );
        assert!(
            !route.is_local(),
            "no silent downgrade to local (the caller asked for frontier)"
        );
        assert!(route.fires_no_executor(), "fail-closed: no executor fires");
    }

    // ---- predicates + falsifiability canary ----

    #[test]
    fn route_predicates_are_exclusive() {
        assert!(ConsultRoute::LocalLoopback.is_local());
        assert!(!ConsultRoute::LocalLoopback.is_frontier());
        assert!(ConsultRoute::Frontier.is_frontier());
        assert!(!ConsultRoute::Frontier.is_local());
        assert!(ConsultRoute::Locked.fires_no_executor());
        assert!(ConsultRoute::FrontierDeniedNoGrant.fires_no_executor());
        assert!(!ConsultRoute::LocalLoopback.fires_no_executor());
        assert!(!ConsultRoute::Frontier.fires_no_executor());
    }

    /// Falsifiability canary: local and frontier routes are genuinely distinct —
    /// a wrong `assert_ne` here would FAIL on identical routes, proving the
    /// harness can tell the executors apart.
    #[test]
    fn local_and_frontier_routes_differ_canary() {
        let local = select_consult_route(ConsultCaller::Owner, ConsultPhrase::Local, None);
        let frontier = select_consult_route(ConsultCaller::Owner, ConsultPhrase::Frontier, None);
        assert_ne!(local, frontier);
        assert!(local.is_local() && frontier.is_frontier());
    }
}
