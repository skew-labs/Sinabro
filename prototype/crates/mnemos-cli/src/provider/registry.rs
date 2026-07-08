//! Operational provider registry candidate view.
//!
//! [`crate::commands::provider`] registers *configured attachments*
//! with secret references for the `provider add/list/test` CLI surface. This module
//! adds the *operational route-table candidate*: the runtime loop routes only to
//! a provider registered as a [`ProviderCandidate`] carrying a visible provider
//! identity, model id, route label, and policy hash, that is **disabled by
//! default**. A candidate that omits any of those fields, or that tries to be
//! enabled at registration, is rejected (base-provenance). No weight
//! training is performed.
//!
//! Reuse (no reinvention): [`ProviderKind`] / [`ModelRole`] from
//! [`crate::commands::provider`], [`RouteExecutionState`] from [`crate::route`],
//! and [`crate::sha256_32`].

use crate::commands::provider::{ModelRole, ProviderKind};
use crate::route::RouteExecutionState;
use crate::sha256_32;

/// The operational route label of a provider candidate: a local executor route or
/// an external frontier-advisory route. Drives the default route state.
#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RouteLabel {
    /// Local executor route (no external egress).
    Local = 1,
    /// External frontier-advisory route (bounded consult only).
    ExternalFrontierAdvisory = 2,
}

impl RouteLabel {
    /// The route label implied by a [`ProviderKind`]: local providers map to
    /// [`RouteLabel::Local`], external providers to
    /// [`RouteLabel::ExternalFrontierAdvisory`].
    #[must_use]
    pub const fn for_kind(kind: ProviderKind) -> Self {
        if kind.is_local() {
            Self::Local
        } else {
            Self::ExternalFrontierAdvisory
        }
    }

    /// The default route state for this label (local → `Fast`, external → `Slow`).
    #[must_use]
    pub const fn default_route_state(self) -> RouteExecutionState {
        match self {
            Self::Local => RouteExecutionState::Fast,
            Self::ExternalFrontierAdvisory => RouteExecutionState::Slow,
        }
    }
}

/// Parameters for [`ProviderCandidateRegistry::register`].
#[derive(Clone, Copy, Debug)]
pub struct CandidateSpec<'a> {
    /// Which provider.
    pub kind: ProviderKind,
    /// The model identity string (only its hash is kept; must be non-empty).
    pub model_id: &'a str,
    /// The routing role.
    pub role: ModelRole,
    /// The operational policy text (only its hash is kept; must be non-empty).
    pub policy: &'a str,
}

/// An operational provider route candidate. Disabled by default; the runtime loop
/// never routes to a disabled candidate.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ProviderCandidate {
    /// Which provider.
    pub kind: ProviderKind,
    /// SHA-256 of the model identity (visible / non-zero).
    pub model_identity_hash_32: [u8; 32],
    /// The routing role.
    pub role: ModelRole,
    /// The operational route label.
    pub route_label: RouteLabel,
    /// SHA-256 of the operational policy (visible / non-zero).
    pub policy_hash_32: [u8; 32],
    /// The default route state for this candidate.
    pub default_route_state: RouteExecutionState,
    /// Whether the candidate is enabled. Invariant: `false` at registration
    /// (default-disabled); only an explicit [`ProviderCandidateRegistry::enable`]
    /// flips it.
    pub enabled: bool,
}

/// The operational provider candidate registry (the runtime route table).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ProviderCandidateRegistry {
    candidates: Vec<ProviderCandidate>,
}

impl ProviderCandidateRegistry {
    /// A new, empty registry.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a provider candidate (default-disabled). Fail-closed (`false`): an
    /// empty model id or empty policy is rejected (identity / policy hash must be
    /// visible), and a duplicate (same kind + model identity) is rejected. A
    /// candidate can never be registered enabled — it starts disabled and must be
    /// explicitly [`enable`](Self::enable)d.
    pub fn register(&mut self, spec: &CandidateSpec<'_>) -> bool {
        if spec.model_id.is_empty() || spec.policy.is_empty() {
            return false;
        }
        let model_identity_hash_32 = sha256_32(spec.model_id.as_bytes());
        if self
            .candidates
            .iter()
            .any(|c| c.kind == spec.kind && c.model_identity_hash_32 == model_identity_hash_32)
        {
            return false;
        }
        let route_label = RouteLabel::for_kind(spec.kind);
        self.candidates.push(ProviderCandidate {
            kind: spec.kind,
            model_identity_hash_32,
            role: spec.role,
            route_label,
            policy_hash_32: sha256_32(spec.policy.as_bytes()),
            default_route_state: route_label.default_route_state(),
            enabled: false,
        });
        true
    }

    /// Explicitly enable the candidate at `index` (the only way a candidate
    /// becomes routable). Returns `false` for a bad index.
    pub fn enable(&mut self, index: usize) -> bool {
        match self.candidates.get_mut(index) {
            Some(c) => {
                c.enabled = true;
                true
            }
            None => false,
        }
    }

    /// The candidate at `index` (`None` for a bad index). The operational lookup
    /// the runtime loop performs.
    #[must_use]
    pub fn get(&self, index: usize) -> Option<ProviderCandidate> {
        self.candidates.get(index).copied()
    }

    /// All registered candidates.
    #[must_use]
    pub fn candidates(&self) -> &[ProviderCandidate] {
        &self.candidates
    }

    /// The number of registered candidates.
    #[must_use]
    pub fn len(&self) -> usize {
        self.candidates.len()
    }

    /// Whether the registry is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.candidates.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::repl::latency::p95_ms;

    fn spec(kind: ProviderKind, id: &str) -> CandidateSpec<'_> {
        CandidateSpec {
            kind,
            model_id: id,
            role: kind.default_role(),
            policy: "route=advisory;consult=bounded;dispatch=disabled",
        }
    }

    #[test]
    fn register_candidate_default_disabled() {
        let mut reg = ProviderCandidateRegistry::new();
        assert!(reg.register(&spec(ProviderKind::Naite, "naite-local")));
        assert_eq!(reg.len(), 1);
        assert!(!reg.is_empty());
        let c = reg.get(0);
        assert!(c.is_some(), "candidate 0 must exist");
        if let Some(c) = c {
            assert!(!c.enabled, "a candidate must register disabled by default");
            assert_ne!(c.model_identity_hash_32, [0u8; 32], "identity visible");
            assert_ne!(c.policy_hash_32, [0u8; 32], "policy hash visible");
        }
    }

    #[test]
    fn empty_identity_or_policy_rejected() {
        let mut reg = ProviderCandidateRegistry::new();
        assert!(!reg.register(&CandidateSpec {
            kind: ProviderKind::Naite,
            model_id: "",
            role: ModelRole::LocalExecutor,
            policy: "p",
        }));
        assert!(!reg.register(&CandidateSpec {
            kind: ProviderKind::Naite,
            model_id: "naite",
            role: ModelRole::LocalExecutor,
            policy: "",
        }));
        assert!(reg.is_empty());
    }

    #[test]
    fn duplicate_deny() {
        let mut reg = ProviderCandidateRegistry::new();
        assert!(reg.register(&spec(ProviderKind::Anthropic, "claude-opus-4-8")));
        assert!(
            !reg.register(&spec(ProviderKind::Anthropic, "claude-opus-4-8")),
            "duplicate kind+identity must be denied"
        );
        assert_eq!(reg.len(), 1);
    }

    #[test]
    fn hidden_default_deny_then_explicit_enable() {
        let mut reg = ProviderCandidateRegistry::new();
        assert!(reg.register(&spec(ProviderKind::Naite, "naite-local")));
        // No candidate can be enabled by default (hidden default-on is impossible).
        assert!(reg.candidates().iter().all(|c| !c.enabled));
        assert!(reg.enable(0));
        if let Some(c) = reg.get(0) {
            assert!(c.enabled);
        }
        assert!(!reg.enable(9), "bad index must not enable");
    }

    #[test]
    fn local_route_label() {
        let mut reg = ProviderCandidateRegistry::new();
        assert!(reg.register(&spec(ProviderKind::Naite, "naite-local")));
        if let Some(c) = reg.get(0) {
            assert_eq!(c.route_label, RouteLabel::Local);
            assert_eq!(c.default_route_state, RouteExecutionState::Fast);
        }
    }

    #[test]
    fn external_route_label() {
        let mut reg = ProviderCandidateRegistry::new();
        assert!(reg.register(&spec(ProviderKind::OpenAi, "gpt-x")));
        if let Some(c) = reg.get(0) {
            assert_eq!(c.route_label, RouteLabel::ExternalFrontierAdvisory);
            assert_eq!(c.default_route_state, RouteExecutionState::Slow);
        }
    }

    #[test]
    fn registry_lookup_p95_within_100ms() {
        let mut reg = ProviderCandidateRegistry::new();
        assert!(reg.register(&spec(ProviderKind::Naite, "naite-local")));
        let mut samples = Vec::with_capacity(256);
        for _ in 0..256 {
            let t = std::time::Instant::now();
            let c = reg.get(0);
            std::hint::black_box(&c);
            samples.push(t.elapsed().as_nanos() as u64);
        }
        let p95 = p95_ms(&samples) / 1_000_000;
        assert!(p95 <= 100, "registry lookup p95 {p95}ms exceeds 100ms");
    }
}
