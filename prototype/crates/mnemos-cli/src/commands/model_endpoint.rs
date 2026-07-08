//! local / vLLM endpoint config — no run.
//!
//! `sinabro model endpoint add/test`. Configures and *validates* endpoint
//! reachability config only — it never starts a vLLM training or serving
//! job ([`EndpointRegistry::SPAWN_TRAINING_ALLOWED`] is `false` and every
//! [`EndpointView::can_spawn_training`] is `false`). Endpoint identity
//! distinguishes the local Naite executor, a local/vLLM executor, and an external
//! frontier reviewer; a local-only route can never be silently upgraded to an
//! external endpoint ([`EndpointRegistry::route_can_use`]). Secrets are held only
//! as a [`SecretRefView`] reference.
//!
//! Reuse: [`ModelRole`] from [`super::provider`], [`crate::secrets`],
//! [`crate::tui::RenderTruth`].

use super::provider::ModelRole;
use crate::secrets::{SecretLocation, SecretRefView, classify_reference, scan_inline_secret};
use crate::sha256_32;
use crate::tui::RenderTruth;

/// The kind of model endpoint. Local endpoints execute; the external endpoint is
/// a frontier reviewer.
#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EndpointKind {
    /// The local Naite executor endpoint.
    LocalNaite = 1,
    /// A local / self-hosted vLLM executor endpoint.
    LocalVllm = 2,
    /// An external frontier reviewer endpoint.
    ExternalFrontier = 3,
}

impl EndpointKind {
    /// Whether this endpoint is local (no external egress).
    #[must_use]
    pub const fn is_local(self) -> bool {
        matches!(self, Self::LocalNaite | Self::LocalVllm)
    }

    /// The default [`ModelRole`] for this endpoint kind.
    #[must_use]
    pub const fn default_role(self) -> ModelRole {
        match self {
            Self::LocalNaite | Self::LocalVllm => ModelRole::LocalExecutor,
            Self::ExternalFrontier => ModelRole::FrontierReviewer,
        }
    }
}

/// Parameters for [`EndpointRegistry::attach`]. The secret arrives as a
/// reference string only.
#[derive(Clone, Copy, Debug)]
pub struct EndpointSpec<'a> {
    /// The endpoint kind.
    pub kind: EndpointKind,
    /// The endpoint URL string; only its hash is kept (never a raw secret).
    pub url: &'a str,
    /// The routing role for this endpoint.
    pub role: ModelRole,
    /// Logical secret name (hashed for the ref view).
    pub secret_name: &'a str,
    /// Secret *reference* (`keychain:`/`env:`/`kms:`/`vault:` …) — never inline.
    pub secret_reference: &'a str,
}

/// A configured endpoint. Secrets are held only as a [`SecretRefView`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EndpointRecord {
    kind: EndpointKind,
    url_hash_32: [u8; 32],
    role: ModelRole,
    secret: SecretRefView,
    config_health: RenderTruth,
}

impl EndpointRecord {
    /// The status-only projection (one `endpoint list` / `endpoint test` row).
    #[must_use]
    pub fn view(&self) -> EndpointView {
        EndpointView {
            kind: self.kind,
            url_hash_32: self.url_hash_32,
            role: self.role,
            is_local: self.kind.is_local(),
            can_spawn_training: EndpointRegistry::SPAWN_TRAINING_ALLOWED,
            secret_location: self.secret.location,
            value_never_loaded: self.secret.value_never_loaded,
            config_health: self.config_health,
        }
    }
}

/// Status-only endpoint row. A flat `Copy` projection.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EndpointView {
    /// The endpoint kind.
    pub kind: EndpointKind,
    /// SHA-256 of the endpoint URL.
    pub url_hash_32: [u8; 32],
    /// The routing role.
    pub role: ModelRole,
    /// Whether the endpoint is local.
    pub is_local: bool,
    /// Whether a training/serving job may be spawned — invariant `false`.
    pub can_spawn_training: bool,
    /// Where the secret reference resolves (never the value).
    pub secret_location: SecretLocation,
    /// Invariant: the secret value is never loaded.
    pub value_never_loaded: bool,
    /// Config-validity health (never a false green).
    pub config_health: RenderTruth,
}

/// The endpoint registry. Validates reachability config; never spawns a job.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct EndpointRegistry {
    endpoints: Vec<EndpointRecord>,
}

impl EndpointRegistry {
    /// Never spawns a training / serving job from an endpoint.
    pub const SPAWN_TRAINING_ALLOWED: bool = false;

    /// A new, empty registry.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Attach an endpoint (`endpoint add`). Fail-closed: an inline secret is
    /// rejected (`false`), and a non-resolving reference is rejected — only
    /// `keychain:`/`env:`/`kms:`/`vault:` references are accepted. The value is
    /// never loaded and no job is ever spawned.
    pub fn attach(&mut self, spec: &EndpointSpec<'_>) -> bool {
        if scan_inline_secret(spec.secret_reference) {
            return false;
        }
        let secret = classify_reference(spec.secret_name, spec.secret_reference);
        if secret.location == SecretLocation::Missing {
            return false;
        }
        self.endpoints.push(EndpointRecord {
            kind: spec.kind,
            url_hash_32: sha256_32(spec.url.as_bytes()),
            role: spec.role,
            secret,
            config_health: RenderTruth::Green,
        });
        true
    }

    /// All attached endpoints as status rows (`endpoint list`).
    #[must_use]
    pub fn list(&self) -> Vec<EndpointView> {
        self.endpoints.iter().map(EndpointRecord::view).collect()
    }

    /// The number of attached endpoints.
    #[must_use]
    pub fn len(&self) -> usize {
        self.endpoints.len()
    }

    /// Whether the registry is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.endpoints.is_empty()
    }

    /// The config-validation view for the endpoint at `index` (`endpoint test`).
    /// This validates reachability config only; it never starts a job. `None` if
    /// the index is out of range.
    #[must_use]
    pub fn test(&self, index: usize) -> Option<EndpointView> {
        self.endpoints.get(index).map(EndpointRecord::view)
    }

    /// Whether a route may use the endpoint at `index`. A local-only route can
    /// never use an external endpoint (no silent upgrade). `None` if the index is
    /// out of range.
    #[must_use]
    pub fn route_can_use(&self, index: usize, route_is_local_only: bool) -> Option<bool> {
        self.endpoints.get(index).map(|e| {
            if route_is_local_only {
                e.kind.is_local()
            } else {
                true
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::repl::latency::p95_ms;

    fn spec<'a>(kind: EndpointKind, url: &'a str, reference: &'a str) -> EndpointSpec<'a> {
        EndpointSpec {
            kind,
            url,
            role: kind.default_role(),
            secret_name: "endpoint_key",
            secret_reference: reference,
        }
    }

    #[test]
    fn endpoint_add_test() {
        let mut reg = EndpointRegistry::new();
        assert!(reg.attach(&spec(
            EndpointKind::LocalVllm,
            "http://127.0.0.1:8000",
            "keychain:vllm"
        )));
        assert_eq!(reg.len(), 1);
        assert!(!reg.is_empty());
        let v = reg.test(0);
        assert!(v.is_some(), "endpoint 0 must exist");
        if let Some(v) = v {
            assert_eq!(v.kind, EndpointKind::LocalVllm);
            assert!(v.is_local);
        }
        assert!(reg.test(9).is_none());
    }

    #[test]
    fn no_spawn_training() {
        // every endpoint view reports can_spawn_training = false, which is wired
        // straight from EndpointRegistry::SPAWN_TRAINING_ALLOWED — it never
        // starts a training/serving job.
        let mut reg = EndpointRegistry::new();
        assert!(reg.attach(&spec(
            EndpointKind::LocalVllm,
            "http://127.0.0.1:8000",
            "keychain:vllm"
        )));
        assert!(reg.list().iter().all(|v| !v.can_spawn_training));
    }

    #[test]
    fn health_fixture() {
        let mut reg = EndpointRegistry::new();
        assert!(reg.attach(&spec(
            EndpointKind::LocalNaite,
            "local://naite",
            "keychain:naite"
        )));
        assert_eq!(reg.list()[0].config_health, RenderTruth::Green);
    }

    #[test]
    fn secret_redaction() {
        let mut reg = EndpointRegistry::new();
        // inline secret rejected
        assert!(!reg.attach(&spec(
            EndpointKind::ExternalFrontier,
            "https://api.example.com",
            "suiprivkey1qexamplenotreal",
        )));
        assert!(reg.is_empty());
        // reference accepted, value never loaded
        assert!(reg.attach(&spec(
            EndpointKind::ExternalFrontier,
            "https://api.example.com",
            "env:FRONTIER_KEY",
        )));
        assert!(reg.list().iter().all(|v| v.value_never_loaded));
    }

    #[test]
    fn local_executor_role() {
        assert_eq!(
            EndpointKind::LocalNaite.default_role(),
            ModelRole::LocalExecutor
        );
        assert_eq!(
            EndpointKind::LocalVllm.default_role(),
            ModelRole::LocalExecutor
        );
    }

    #[test]
    fn frontier_reviewer_role() {
        assert_eq!(
            EndpointKind::ExternalFrontier.default_role(),
            ModelRole::FrontierReviewer
        );
        assert!(
            !EndpointKind::ExternalFrontier
                .default_role()
                .can_execute_tools()
        );
    }

    #[test]
    fn local_only_route_cannot_use_external() {
        let mut reg = EndpointRegistry::new();
        assert!(reg.attach(&spec(
            EndpointKind::LocalNaite,
            "local://naite",
            "keychain:naite"
        )));
        assert!(reg.attach(&spec(
            EndpointKind::ExternalFrontier,
            "https://api.example.com",
            "env:FRONTIER_KEY"
        )));
        // index 0 = local, index 1 = external
        assert_eq!(reg.route_can_use(0, true), Some(true));
        assert_eq!(
            reg.route_can_use(1, true),
            Some(false),
            "local-only route must not use external"
        );
        assert_eq!(reg.route_can_use(1, false), Some(true));
        assert_eq!(reg.route_can_use(9, true), None);
    }

    #[test]
    fn endpoint_validation_p95_within_budget() {
        let mut reg = EndpointRegistry::new();
        assert!(reg.attach(&spec(
            EndpointKind::LocalNaite,
            "local://naite",
            "keychain:naite"
        )));
        let mut samples = Vec::with_capacity(256);
        for _ in 0..256 {
            let t = std::time::Instant::now();
            let v = reg.test(0);
            std::hint::black_box(&v);
            samples.push(t.elapsed().as_nanos() as u64);
        }
        let p95 = p95_ms(&samples) / 1_000_000;
        assert!(
            p95 <= 25,
            "endpoint validation p95 {p95}ms exceeds 25ms budget"
        );
    }
}
