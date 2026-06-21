//! provider command group + LLM Provider Abstraction view (atom #427 F.3.0).
//!
//! `sinabro provider add/list/test`. Every provider — OpenAI, Anthropic, Gemini,
//! local Naite, vLLM — projects the *same* surface: model identity, routing
//! [`ModelRole`], cost, latency, config health, privacy boundary, and a route
//! state. Provider secrets are held only as a [`SecretRefView`] reference (the
//! value is never loaded, cloned, or `Debug`-printed — gate `G-F-SECRET-ZERO`);
//! `test` is a *local config validation*, never a live provider call (the route
//! speed law: status hot paths do not call providers). Naite/local remains the
//! default executor; a frontier provider is reviewer/critic only and can never
//! execute tools (`G-F-ADAPTIVE-ROUTER`, `G-F-ADAPTER-ABSTRACTION`).
//!
//! Reuse (no reinvention): [`crate::route::RouteExecutionState`],
//! [`crate::tui::RenderTruth`], [`crate::secrets`], and the canonical
//! [`crate::config::compute_digest`] for the config digest.

use crate::config::{CliConfigDigest, ConfigLayer, compute_digest};
use crate::route::RouteExecutionState;
use crate::secrets::{SecretLocation, SecretRefView, classify_reference, scan_inline_secret};
use crate::tui::RenderTruth;
use crate::{hex32, sha256_32};

/// Which LLM provider an attachment speaks to. Local providers (`Naite`, `Vllm`)
/// never egress; the three external providers are frontier consult sources.
#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProviderKind {
    /// OpenAI (external / frontier).
    OpenAi = 1,
    /// Anthropic (external / frontier).
    Anthropic = 2,
    /// Google Gemini (external / frontier).
    Gemini = 3,
    /// Local Naite executor (default executor; no egress).
    Naite = 4,
    /// Local / self-hosted vLLM serving endpoint (no egress).
    Vllm = 5,
}

impl ProviderKind {
    /// Whether this provider runs locally (no external network egress).
    #[must_use]
    pub const fn is_local(self) -> bool {
        matches!(self, Self::Naite | Self::Vllm)
    }

    /// The default [`ModelRole`] for this provider: local providers default to
    /// [`ModelRole::LocalExecutor`]; external providers default to
    /// [`ModelRole::FrontierReviewer`] (never the hidden driver).
    #[must_use]
    pub const fn default_role(self) -> ModelRole {
        if self.is_local() {
            ModelRole::LocalExecutor
        } else {
            ModelRole::FrontierReviewer
        }
    }
}

/// The model's routing role. Discriminants are locked by the adaptive-router
/// amendment (`ops/contracts/stage_f/F_ADAPTIVE_MODEL_ROUTER_DEFERRED_AMENDMENT.md`).
#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ModelRole {
    /// Local executor — the only role that may run tools / shell / file edits.
    LocalExecutor = 1,
    /// Frontier reviewer — bounded, advisory consult; cannot execute.
    FrontierReviewer = 2,
    /// Frontier critic — adversarial advisory consult; cannot execute.
    FrontierCritic = 3,
    /// Local judge — compares answers to local evidence; cannot execute.
    LocalJudge = 4,
}

impl ModelRole {
    /// Only [`ModelRole::LocalExecutor`] may execute tools / shell / file edits.
    /// Frontier reviewer/critic and the local judge are advisory-only.
    #[must_use]
    pub const fn can_execute_tools(self) -> bool {
        matches!(self, Self::LocalExecutor)
    }

    /// Whether this is an external frontier consult role.
    #[must_use]
    pub const fn is_frontier(self) -> bool {
        matches!(self, Self::FrontierReviewer | Self::FrontierCritic)
    }
}

/// Parameters for [`ProviderRegistry::attach`]. Bundled into one struct so the
/// attach call stays within the argument-count budget and the secret arrives as
/// a *reference string* only.
#[derive(Clone, Copy, Debug)]
pub struct ProviderSpec<'a> {
    /// Which provider.
    pub kind: ProviderKind,
    /// The model identity string (e.g. `claude-opus-4-8`); only its hash is kept.
    pub model_id: &'a str,
    /// The routing role for this attachment.
    pub role: ModelRole,
    /// Logical secret name (hashed for the ref view).
    pub secret_name: &'a str,
    /// Secret *reference* (`keychain:`/`env:`/`kms:`/`vault:` …) — never inline.
    pub secret_reference: &'a str,
    /// Cost estimate in micro-units per 1k tokens.
    pub cost_micro_per_1k_u32: u32,
    /// p50 latency estimate in milliseconds.
    pub latency_p50_ms_u16: u16,
}

/// A configured provider attachment. Secrets are held only as a
/// [`SecretRefView`]; the value is never loaded.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ProviderRecord {
    kind: ProviderKind,
    model_identity_hash_32: [u8; 32],
    role: ModelRole,
    secret: SecretRefView,
    cost_micro_per_1k_u32: u32,
    latency_p50_ms_u16: u16,
    config_health: RenderTruth,
    private_memory_egress: bool,
}

impl ProviderRecord {
    /// The status-only projection of this attachment (one `provider list` row).
    #[must_use]
    pub fn view(&self) -> ProviderView {
        ProviderView {
            kind: self.kind,
            model_identity_hash_32: self.model_identity_hash_32,
            role: self.role,
            can_execute_tools: self.role.can_execute_tools(),
            secret_location: self.secret.location,
            value_never_loaded: self.secret.value_never_loaded,
            cost_micro_per_1k_u32: self.cost_micro_per_1k_u32,
            latency_p50_ms_u16: self.latency_p50_ms_u16,
            config_health: self.config_health,
            private_memory_default_deny: !self.private_memory_egress,
            default_route_state: if self.kind.is_local() {
                RouteExecutionState::Fast
            } else {
                RouteExecutionState::Slow
            },
        }
    }

    /// A local config-validation report (the `provider test` command). This never
    /// performs a network call: `config_health` reflects config validity only,
    /// and the secret is exposed as a reference (value never loaded).
    #[must_use]
    pub fn test_report(&self) -> ProviderTestReport {
        let mut cap = Vec::with_capacity(33);
        cap.push(self.kind as u8);
        cap.extend_from_slice(&self.model_identity_hash_32);
        ProviderTestReport {
            kind: self.kind,
            config_health: self.config_health,
            capability_hash_32: sha256_32(&cap),
            cost_micro_per_1k_u32: self.cost_micro_per_1k_u32,
            secret: self.secret,
        }
    }
}

/// Status-only `provider list` row. A flat `Copy` projection.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ProviderView {
    /// Which provider.
    pub kind: ProviderKind,
    /// SHA-256 of the model identity (always visible / non-zero).
    pub model_identity_hash_32: [u8; 32],
    /// Routing role.
    pub role: ModelRole,
    /// Whether this role may execute tools (only `LocalExecutor`).
    pub can_execute_tools: bool,
    /// Where the secret reference resolves (never the value).
    pub secret_location: SecretLocation,
    /// Invariant: the secret value is never loaded.
    pub value_never_loaded: bool,
    /// Cost estimate (micro-units / 1k tokens).
    pub cost_micro_per_1k_u32: u32,
    /// p50 latency estimate (ms).
    pub latency_p50_ms_u16: u16,
    /// Config-validity health (never a false green; live health is not probed here).
    pub config_health: RenderTruth,
    /// Whether private memory is default-denied to this provider (default `true`).
    pub private_memory_default_deny: bool,
    /// The default route-trace state for this provider.
    pub default_route_state: RouteExecutionState,
}

/// Status-only `provider test` report — health / capability / cost with the
/// secret as a reference only.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ProviderTestReport {
    /// Which provider.
    pub kind: ProviderKind,
    /// Config-validity health.
    pub config_health: RenderTruth,
    /// A deterministic capability fingerprint (kind + identity).
    pub capability_hash_32: [u8; 32],
    /// Cost estimate (micro-units / 1k tokens).
    pub cost_micro_per_1k_u32: u32,
    /// The secret reference view (value never loaded).
    pub secret: SecretRefView,
}

/// The provider registry — multiple attachments, all projecting the same
/// surface. Fail-closed on inline secrets.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ProviderRegistry {
    providers: Vec<ProviderRecord>,
}

impl ProviderRegistry {
    /// A new, empty registry.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Attach a provider (`provider add`). Fail-closed: an inline (non-reference)
    /// secret is rejected (`false`), and a reference that does not resolve to a
    /// known scheme is rejected — only `keychain:`/`env:`/`kms:`/`vault:`
    /// references are accepted, and the value is never loaded.
    pub fn attach(&mut self, spec: &ProviderSpec<'_>) -> bool {
        if scan_inline_secret(spec.secret_reference) {
            return false;
        }
        let secret = classify_reference(spec.secret_name, spec.secret_reference);
        if secret.location == SecretLocation::Missing {
            return false;
        }
        self.providers.push(ProviderRecord {
            kind: spec.kind,
            model_identity_hash_32: sha256_32(spec.model_id.as_bytes()),
            role: spec.role,
            secret,
            cost_micro_per_1k_u32: spec.cost_micro_per_1k_u32,
            latency_p50_ms_u16: spec.latency_p50_ms_u16,
            config_health: RenderTruth::Green,
            private_memory_egress: false,
        });
        true
    }

    /// All attached providers as status rows (`provider list`).
    #[must_use]
    pub fn list(&self) -> Vec<ProviderView> {
        self.providers.iter().map(ProviderRecord::view).collect()
    }

    /// The number of attached providers.
    #[must_use]
    pub fn len(&self) -> usize {
        self.providers.len()
    }

    /// Whether the registry is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.providers.is_empty()
    }

    /// The config-validation report for the provider at `index` (`provider test`).
    /// `None` if the index is out of range.
    #[must_use]
    pub fn test(&self, index: usize) -> Option<ProviderTestReport> {
        self.providers.get(index).map(ProviderRecord::test_report)
    }

    /// The precedence-ordered config digest of the registry — reuses the
    /// canonical [`compute_digest`]. The serialized form is secret-free (only
    /// kind / identity hash / role / cost / latency), so the digest changes when
    /// a provider is added but never embeds a secret.
    #[must_use]
    pub fn config_digest(&self) -> CliConfigDigest {
        use core::fmt::Write as _;
        let mut text = String::new();
        for r in &self.providers {
            let _ = writeln!(
                text,
                "{}:{}:{}:{}:{}",
                r.kind as u8,
                hex32(&r.model_identity_hash_32),
                r.role as u8,
                r.cost_micro_per_1k_u32,
                r.latency_p50_ms_u16
            );
        }
        compute_digest(&[(ConfigLayer::Workspace, &text)])
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::repl::latency::p95_ms;

    fn spec<'a>(
        kind: ProviderKind,
        id: &'a str,
        role: ModelRole,
        reference: &'a str,
    ) -> ProviderSpec<'a> {
        ProviderSpec {
            kind,
            model_id: id,
            role,
            secret_name: "provider_key",
            secret_reference: reference,
            cost_micro_per_1k_u32: 1500,
            latency_p50_ms_u16: 800,
        }
    }

    #[test]
    fn add_list_test_roundtrip() {
        let mut reg = ProviderRegistry::new();
        assert!(reg.attach(&spec(
            ProviderKind::Anthropic,
            "claude-opus-4-8",
            ModelRole::FrontierReviewer,
            "env:ANTHROPIC_API_KEY",
        )));
        assert_eq!(reg.len(), 1);
        assert!(!reg.is_empty());
        let rows = reg.list();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].kind, ProviderKind::Anthropic);
        let report = reg.test(0);
        assert!(report.is_some(), "provider 0 must exist");
        if let Some(r) = report {
            assert_eq!(r.kind, ProviderKind::Anthropic);
            assert!(r.secret.value_never_loaded);
            assert_eq!(r.config_health, RenderTruth::Green);
        }
        assert!(reg.test(9).is_none());
    }

    #[test]
    fn bad_key_inline_secret_rejected() {
        let mut reg = ProviderRegistry::new();
        // an inline (live-shaped) secret must be rejected — redaction at the door
        assert!(!reg.attach(&spec(
            ProviderKind::OpenAi,
            "gpt-x",
            ModelRole::FrontierReviewer,
            "suiprivkey1qexamplenotreal",
        )));
        assert!(reg.is_empty());
        // a reference (no inline value) is accepted
        assert!(reg.attach(&spec(
            ProviderKind::OpenAi,
            "gpt-x",
            ModelRole::FrontierReviewer,
            "keychain:OPENAI",
        )));
        assert!(reg.list().iter().all(|v| v.value_never_loaded));
    }

    #[test]
    fn offline_fixture_no_network() {
        // every view is computed from local state only — no I/O, no network.
        let mut reg = ProviderRegistry::new();
        assert!(reg.attach(&spec(
            ProviderKind::Naite,
            "naite-local",
            ModelRole::LocalExecutor,
            "keychain:naite",
        )));
        let rows = reg.list();
        assert_eq!(rows.len(), 1);
        assert!(rows[0].value_never_loaded);
    }

    #[test]
    fn config_digest_updates_on_add() {
        let mut reg = ProviderRegistry::new();
        let before = reg.config_digest();
        assert!(reg.attach(&spec(
            ProviderKind::Gemini,
            "gemini-2",
            ModelRole::FrontierReviewer,
            "env:GEMINI_API_KEY",
        )));
        let after = reg.config_digest();
        assert_ne!(before.merged_hash_32, after.merged_hash_32);
        assert_eq!(after.schema_version_u16, before.schema_version_u16);
    }

    fn fixture(kind: ProviderKind, id: &str, reference: &str) -> ProviderView {
        let mut reg = ProviderRegistry::new();
        assert!(reg.attach(&spec(kind, id, kind.default_role(), reference)));
        reg.list()[0]
    }

    #[test]
    fn provider_fixture_openai() {
        let v = fixture(ProviderKind::OpenAi, "gpt-4o", "env:OPENAI_API_KEY");
        assert_eq!(v.kind, ProviderKind::OpenAi);
        assert_eq!(v.role, ModelRole::FrontierReviewer);
        assert!(!v.can_execute_tools);
    }

    #[test]
    fn provider_fixture_anthropic() {
        let v = fixture(
            ProviderKind::Anthropic,
            "claude-opus-4-8",
            "env:ANTHROPIC_API_KEY",
        );
        assert_eq!(v.kind, ProviderKind::Anthropic);
        assert_eq!(v.role, ModelRole::FrontierReviewer);
    }

    #[test]
    fn provider_fixture_gemini() {
        let v = fixture(ProviderKind::Gemini, "gemini-2", "kms:projects/x/keys/y");
        assert_eq!(v.kind, ProviderKind::Gemini);
        assert_eq!(v.secret_location, SecretLocation::KmsRef);
    }

    #[test]
    fn provider_fixture_naite() {
        let v = fixture(ProviderKind::Naite, "naite-local", "keychain:naite");
        assert_eq!(v.kind, ProviderKind::Naite);
        assert_eq!(v.role, ModelRole::LocalExecutor);
        assert!(v.can_execute_tools);
        assert_eq!(v.default_route_state, RouteExecutionState::Fast);
    }

    #[test]
    fn provider_fixture_vllm() {
        let v = fixture(ProviderKind::Vllm, "vllm-local", "vault:secret/data/vllm");
        assert_eq!(v.kind, ProviderKind::Vllm);
        assert!(v.kind.is_local());
        assert_eq!(v.role, ModelRole::LocalExecutor);
    }

    #[test]
    fn model_identity_visible() {
        let v = fixture(
            ProviderKind::Anthropic,
            "claude-opus-4-8",
            "env:ANTHROPIC_API_KEY",
        );
        assert_ne!(
            v.model_identity_hash_32, [0u8; 32],
            "identity must be visible"
        );
    }

    #[test]
    fn model_role_visible() {
        let v = fixture(ProviderKind::Naite, "naite-local", "keychain:naite");
        assert_eq!(v.role, ModelRole::LocalExecutor);
    }

    #[test]
    fn frontier_role_cannot_execute_tools() {
        for role in [
            ModelRole::FrontierReviewer,
            ModelRole::FrontierCritic,
            ModelRole::LocalJudge,
        ] {
            assert!(!role.can_execute_tools(), "{role:?} must not execute tools");
        }
        assert!(ModelRole::LocalExecutor.can_execute_tools());
    }

    #[test]
    fn private_memory_default_deny() {
        let v = fixture(ProviderKind::OpenAi, "gpt-4o", "env:OPENAI_API_KEY");
        assert!(
            v.private_memory_default_deny,
            "private memory must default to deny"
        );
    }

    #[test]
    fn list_p95_within_budget() {
        let mut reg = ProviderRegistry::new();
        assert!(reg.attach(&spec(
            ProviderKind::Naite,
            "naite-local",
            ModelRole::LocalExecutor,
            "keychain:naite",
        )));
        let mut samples = Vec::with_capacity(256);
        for _ in 0..256 {
            let t = std::time::Instant::now();
            let rows = reg.list();
            std::hint::black_box(&rows);
            samples.push(t.elapsed().as_nanos() as u64);
        }
        let p95 = p95_ms(&samples) / 1_000_000;
        assert!(p95 <= 20, "provider list p95 {p95}ms exceeds 20ms budget");
    }
}
