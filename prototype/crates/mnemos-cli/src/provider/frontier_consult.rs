//! Operational bounded frontier-consult request (atom #493 · G.1.2).
//!
//! Stage F minted [`ModelRouter::consult_packet`] (which builds a
//! [`FrontierConsultPacketView`], denying a consult when the route-state cap is
//! `(0,0)`, when any redaction/evidence/prompt hash is zero, or when no typed
//! trigger is given) and [`ConsultScope`] (which forbids whole-repo / whole-21-
//! file-sidecar / private-memory inclusion). Stage G composes them into a single
//! [`BoundedConsultRequest`]: small, redacted, hash-linked, timeout-bound, and
//! travelling as a `Network`-risk [`CommandEnvelope`] (approval-gated).
//!
//! Live-boundary custody (`G-G-SECRET-ZERO`, `G-G-COST-BUDGET`; PR_PROMPT §3
//! default dry-run/no-live): the request is **disabled by default** —
//! [`BoundedConsultRequest::live_dispatch_allowed`] is the invariant `false`. It
//! is never dispatched to a live provider here; an actual dispatch requires a
//! separate same-message approval ceremony (absent this session), and even then
//! the global prompt law gates it. This builder performs no I/O.
//!
//! Reuse (no reinvention): [`ConsultScope`] from
//! [`crate::commands::model_compress`]; [`ConsultTrigger`] /
//! [`FrontierConsultPacketView`] / [`ModelRouter`] from
//! [`crate::commands::model_route`]; [`CommandEnvelope`] from
//! [`crate::command`]; [`RouteExecutionState`] from [`crate::route`].

use crate::command::{CliMode, CommandEnvelope, CommandRisk};
use crate::commands::model_compress::ConsultScope;
use crate::commands::model_route::{ConsultTrigger, FrontierConsultPacketView, ModelRouter};
use crate::grammar::CliNamespace;
use crate::route::RouteExecutionState;

const ZERO32: [u8; 32] = [0u8; 32];

/// The inputs to a bounded frontier-consult request.
#[derive(Clone, Copy, Debug)]
pub struct BoundedConsultInputs {
    /// The route state authorizing the consult (only SLOW/STUCK/AUDIT have a cap).
    pub route_state: RouteExecutionState,
    /// The typed trigger.
    pub trigger: ConsultTrigger,
    /// The requested scope (a forbidden surface denies the consult).
    pub scope: ConsultScope,
    /// SHA-256 of the redaction report (must be non-zero).
    pub redaction_report_hash_32: [u8; 32],
    /// SHA-256 of the evidence references (must be non-zero).
    pub evidence_refs_hash_32: [u8; 32],
    /// SHA-256 of the compiled prompt (must be non-zero).
    pub prompt_hash_32: [u8; 32],
    /// The dispatch timeout in milliseconds (must be non-zero — timeout-bound).
    pub timeout_ms_u32: u32,
    /// SHA-256 of the required local-verification command (must be non-zero).
    pub local_verification_command_hash_32: [u8; 32],
}

/// A bounded, redacted, hash-linked, timeout-bound frontier consult request.
/// Disabled by default: [`Self::live_dispatch_allowed`] is the invariant `false`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BoundedConsultRequest {
    /// The bounded consult packet (caps, redaction hash, advisory-only,
    /// `private_memory_included = false`) built by the canonical router.
    pub packet: FrontierConsultPacketView,
    /// The minimal scope (no whole repo / sidecar / private memory).
    pub scope: ConsultScope,
    /// The `Network`-risk command envelope this consult travels as.
    pub envelope: CommandEnvelope,
    /// The dispatch timeout (ms).
    pub timeout_ms_u32: u32,
    /// SHA-256 of the required local-verification command.
    pub local_verification_command_hash_32: [u8; 32],
    /// Invariant `false`: never dispatched live without a separate same-message
    /// approval ceremony.
    pub live_dispatch_allowed: bool,
}

/// Build a bounded frontier-consult request. Returns `None` (the consult is
/// denied) when: the scope requests a forbidden surface (whole repo / 21-file
/// sidecar / private memory); the timeout is zero; the local-verification command
/// is missing; or the canonical [`ModelRouter::consult_packet`] denies it (zero
/// token cap for the state, a zero redaction/evidence/prompt hash, or no trigger).
#[must_use]
pub fn build(inputs: &BoundedConsultInputs) -> Option<BoundedConsultRequest> {
    if inputs.scope.requests_forbidden_surface() {
        return None;
    }
    if inputs.timeout_ms_u32 == 0 {
        return None;
    }
    if inputs.local_verification_command_hash_32 == ZERO32 {
        return None;
    }
    let mut router = ModelRouter::new(ZERO32);
    router.transition(inputs.route_state);
    let packet = router.consult_packet(
        Some(inputs.trigger),
        inputs.redaction_report_hash_32,
        inputs.evidence_refs_hash_32,
        inputs.prompt_hash_32,
    )?;
    let envelope = CommandEnvelope::classify(
        CliNamespace::Provider,
        "consult",
        CliMode::Run,
        CommandRisk::Network,
        b"bounded-frontier-consult",
    );
    Some(BoundedConsultRequest {
        packet,
        scope: inputs.scope,
        envelope,
        timeout_ms_u32: inputs.timeout_ms_u32,
        local_verification_command_hash_32: inputs.local_verification_command_hash_32,
        live_dispatch_allowed: false,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::command::ApprovalRequirement;
    use crate::repl::latency::p95_ms;

    fn inputs(route_state: RouteExecutionState, scope: ConsultScope) -> BoundedConsultInputs {
        BoundedConsultInputs {
            route_state,
            trigger: ConsultTrigger::RepeatedFailure,
            scope,
            redaction_report_hash_32: [1u8; 32],
            evidence_refs_hash_32: [2u8; 32],
            prompt_hash_32: [3u8; 32],
            timeout_ms_u32: 30_000,
            local_verification_command_hash_32: [4u8; 32],
        }
    }

    #[test]
    fn cap_enforced_by_state() {
        // SLOW has a non-zero cap -> built with caps (8000, 2000)
        let req = build(&inputs(RouteExecutionState::Slow, ConsultScope::minimal()));
        assert!(req.is_some(), "SLOW consult must build");
        if let Some(req) = req {
            assert_eq!(req.packet.input_token_cap_u32, 8000);
            assert_eq!(req.packet.output_token_cap_u32, 2000);
            assert!(!req.live_dispatch_allowed, "disabled by default");
            assert!(req.packet.advisory_only);
            assert!(!req.packet.private_memory_included);
            // Network-risk command requires at least a confirm approval.
            assert_ne!(req.envelope.approval, ApprovalRequirement::None);
        }
        // NORMAL / FAST have a (0,0) cap -> consult denied
        assert!(
            build(&inputs(
                RouteExecutionState::Normal,
                ConsultScope::minimal()
            ))
            .is_none()
        );
        assert!(build(&inputs(RouteExecutionState::Fast, ConsultScope::minimal())).is_none());
    }

    #[test]
    fn private_memory_denied() {
        let scope = ConsultScope {
            whole_repo: false,
            whole_sidecar: false,
            private_memory: true,
        };
        assert!(build(&inputs(RouteExecutionState::Slow, scope)).is_none());
    }

    #[test]
    fn sidecar_dump_denied() {
        let scope = ConsultScope {
            whole_repo: false,
            whole_sidecar: true,
            private_memory: false,
        };
        assert!(build(&inputs(RouteExecutionState::Slow, scope)).is_none());
        // whole-repo is denied too
        let repo = ConsultScope {
            whole_repo: true,
            whole_sidecar: false,
            private_memory: false,
        };
        assert!(build(&inputs(RouteExecutionState::Slow, repo)).is_none());
    }

    #[test]
    fn redaction_hash_required() {
        let mut i = inputs(RouteExecutionState::Slow, ConsultScope::minimal());
        i.redaction_report_hash_32 = ZERO32;
        assert!(
            build(&i).is_none(),
            "a zero redaction hash must deny the consult"
        );
    }

    #[test]
    fn timeout_required() {
        let mut i = inputs(RouteExecutionState::Slow, ConsultScope::minimal());
        i.timeout_ms_u32 = 0;
        assert!(build(&i).is_none(), "a zero timeout must deny the consult");
    }

    #[test]
    fn local_verification_command_required() {
        let mut i = inputs(RouteExecutionState::Slow, ConsultScope::minimal());
        i.local_verification_command_hash_32 = ZERO32;
        assert!(
            build(&i).is_none(),
            "a missing local-verification command must deny the consult"
        );
    }

    #[test]
    fn cached_render_p95_within_250ms() {
        let i = inputs(RouteExecutionState::Slow, ConsultScope::minimal());
        let mut samples = Vec::with_capacity(256);
        for _ in 0..256 {
            let t = std::time::Instant::now();
            let r = build(&i);
            std::hint::black_box(&r);
            samples.push(t.elapsed().as_nanos() as u64);
        }
        let p95 = p95_ms(&samples) / 1_000_000;
        assert!(
            p95 <= 250,
            "bounded consult build p95 {p95}ms exceeds 250ms"
        );
    }
}
