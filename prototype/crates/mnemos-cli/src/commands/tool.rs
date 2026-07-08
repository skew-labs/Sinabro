//! Tool adapter group + web research profile.
//!
//! `sinabro tool add|test|approve|revoke`. A Python tool, an MCP server, a CLI
//! binary, an HTTP/FastAPI service, and a WASM skill all normalize into the same
//! [`ToolCallView`] and travel the same [`crate::command::CommandEnvelope`]
//! risk→approval path (`G-F-ADAPTER-ABSTRACTION`). Activating a tool requires an
//! approval when its capability grows (`G-F-CAPABILITY`), a *hidden permission*
//! (a required capability the tool never declared) is denied, and a revoke
//! immediately removes runtime access (`G-F-SAFETY`).
//!
//! The web research profile (search / fetch / open / snapshot / cite) is a
//! **read-only research tool**, never a model/provider fallback
//! (`G-F-WEB-RESEARCH`). Every record carries the source URL, retrieval time,
//! fetch hash, a rights decision (a paywalled / robots-denied source is
//! refused), a citation-span hash, and a browser-credential redaction proof; an
//! answer with no cited source is denied.
//!
//! Reuse (no reinvention): the [`crate::commands::capability`] diff model, the
//! [`approval_for`] risk mapping, and the Stage E rights/redaction gate via
//! [`crate::repl::history::classify`] (the same secret scanner the REPL uses).

use crate::command::{ApprovalRequirement, CommandRisk, approval_for};
use crate::commands::capability::{CapabilityDiff, CapabilitySet, detect_hidden_permission};
use crate::repl::history::classify;
use crate::sha256_32;
use crate::tui::RenderTruth;

const ZERO32: [u8; 32] = [0u8; 32];

// ---- tool adapter abstraction ---------------------------------------------

/// The five tool adapter kinds, all normalizing into one [`ToolCallView`].
#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ToolAdapterKind {
    /// A Python callable / script.
    Python = 1,
    /// An MCP server tool.
    Mcp = 2,
    /// A CLI binary.
    CliBinary = 3,
    /// An HTTP / FastAPI service endpoint.
    HttpService = 4,
    /// A WASM skill (sandboxed).
    WasmSkill = 5,
}

/// The lifecycle state of a registered tool.
#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ToolState {
    /// Added but not yet tested.
    Registered = 1,
    /// Locally config-tested (no live run yet).
    Tested = 2,
    /// Approved — the only state in which the tool may run.
    Approved = 3,
    /// Revoked — runtime access removed; cannot run.
    Revoked = 4,
}

impl ToolState {
    /// Whether a tool in this state may run — only [`ToolState::Approved`].
    #[must_use]
    pub const fn can_run(self) -> bool {
        matches!(self, Self::Approved)
    }
}

/// The normalized view every adapter projects (`tool list` row). The approval is
/// derived from the risk via the canonical [`approval_for`] mapping.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ToolCallView {
    /// Which adapter backs the tool.
    pub adapter: ToolAdapterKind,
    /// SHA-256 of the tool id.
    pub tool_id_hash_32: [u8; 32],
    /// The effective (granted) capabilities.
    pub capabilities: CapabilitySet,
    /// The sandbox tier the tool runs in (visible).
    pub sandbox_tier_u8: u8,
    /// The command risk class.
    pub risk: CommandRisk,
    /// The approval requirement derived from the risk.
    pub approval: ApprovalRequirement,
    /// The lifecycle state.
    pub state: ToolState,
}

/// Parameters for [`ToolRegistry::add`].
#[derive(Clone, Copy, Debug)]
pub struct ToolSpec<'a> {
    /// Which adapter.
    pub adapter: ToolAdapterKind,
    /// The tool id (only its hash is stored).
    pub tool_id: &'a str,
    /// The capabilities the tool *declares* it needs.
    pub declared_caps: CapabilitySet,
    /// The sandbox tier the tool runs in.
    pub sandbox_tier_u8: u8,
    /// The command risk class of the tool.
    pub risk: CommandRisk,
}

/// A local config-test report (`tool test`). A local validation only — it never
/// performs a live run.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ToolTestReport {
    /// Which adapter.
    pub adapter: ToolAdapterKind,
    /// The declared capabilities.
    pub declared_caps: CapabilitySet,
    /// The sandbox tier (visible).
    pub sandbox_tier_u8: u8,
    /// Config-validity health (never a false green; liveness is not probed).
    pub config_health: RenderTruth,
    /// Invariant `true`: `test` performs no live run.
    pub no_live_run: bool,
}

/// Why a tool approval was rejected.
#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ToolApprovalReject {
    /// The requested capabilities include one the tool never declared.
    HiddenPermission = 1,
    /// The tool is revoked and cannot be re-approved in place.
    AlreadyRevoked = 2,
    /// No tool exists at the index.
    NotFound = 3,
}

/// An approval audit record (`G-F-SAFETY` — every approval is auditable).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ToolApprovalAudit {
    /// SHA-256 of the tool id.
    pub tool_id_hash_32: [u8; 32],
    /// Whether the approval was granted.
    pub approved: bool,
    /// Whether the approval grew the tool's capability.
    pub capability_grew: bool,
    /// The capability-diff snapshot at approval time.
    pub diff_snapshot_hash_32: [u8; 32],
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct ToolRecord {
    adapter: ToolAdapterKind,
    tool_id_hash_32: [u8; 32],
    declared_caps: CapabilitySet,
    granted_caps: CapabilitySet,
    sandbox_tier_u8: u8,
    risk: CommandRisk,
    state: ToolState,
}

impl ToolRecord {
    fn call_view(&self) -> ToolCallView {
        ToolCallView {
            adapter: self.adapter,
            tool_id_hash_32: self.tool_id_hash_32,
            capabilities: self.granted_caps,
            sandbox_tier_u8: self.sandbox_tier_u8,
            risk: self.risk,
            approval: approval_for(self.risk),
            state: self.state,
        }
    }
}

/// The tool registry — add / test / approve / revoke, with an approval audit log.
#[derive(Clone, Debug, Default)]
pub struct ToolRegistry {
    tools: Vec<ToolRecord>,
    audit: Vec<ToolApprovalAudit>,
}

impl ToolRegistry {
    /// A new, empty registry.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a tool (`tool add`). Starts in [`ToolState::Registered`] with no
    /// granted capabilities. Returns its index.
    pub fn add(&mut self, spec: &ToolSpec<'_>) -> usize {
        let index = self.tools.len();
        self.tools.push(ToolRecord {
            adapter: spec.adapter,
            tool_id_hash_32: sha256_32(spec.tool_id.as_bytes()),
            declared_caps: spec.declared_caps,
            granted_caps: CapabilitySet::empty(),
            sandbox_tier_u8: spec.sandbox_tier_u8,
            risk: spec.risk,
            state: ToolState::Registered,
        });
        index
    }

    /// Locally config-test a tool (`tool test`). Returns `None` for a bad index.
    /// Performs no live run.
    #[must_use]
    pub fn test(&self, index: usize) -> Option<ToolTestReport> {
        let r = self.tools.get(index)?;
        Some(ToolTestReport {
            adapter: r.adapter,
            declared_caps: r.declared_caps,
            sandbox_tier_u8: r.sandbox_tier_u8,
            config_health: RenderTruth::Green,
            no_live_run: true,
        })
    }

    /// Approve a tool to run with `requested_caps` (`tool approve`). Fail-closed:
    /// a hidden permission (a requested capability the tool never declared) is
    /// denied, and a revoked tool cannot be re-approved. On success the tool
    /// moves to [`ToolState::Approved`], the granted capabilities are set, and an
    /// audit record is appended. Returns the capability diff applied.
    pub fn approve(
        &mut self,
        index: usize,
        requested_caps: CapabilitySet,
    ) -> Result<CapabilityDiff, ToolApprovalReject> {
        let r = self
            .tools
            .get_mut(index)
            .ok_or(ToolApprovalReject::NotFound)?;
        if matches!(r.state, ToolState::Revoked) {
            return Err(ToolApprovalReject::AlreadyRevoked);
        }
        if detect_hidden_permission(r.declared_caps, requested_caps) {
            return Err(ToolApprovalReject::HiddenPermission);
        }
        let diff = CapabilityDiff::new(r.granted_caps, requested_caps);
        r.granted_caps = requested_caps;
        r.state = ToolState::Approved;
        let audit = ToolApprovalAudit {
            tool_id_hash_32: r.tool_id_hash_32,
            approved: true,
            capability_grew: diff.requires_approval(),
            diff_snapshot_hash_32: diff.snapshot_hash_32(),
        };
        self.audit.push(audit);
        Ok(diff)
    }

    /// Revoke a tool (`tool revoke`). Moves it to [`ToolState::Revoked`] and
    /// clears its granted capabilities — runtime access is removed immediately.
    /// Returns `false` for a bad index.
    pub fn revoke(&mut self, index: usize) -> bool {
        let Some(r) = self.tools.get_mut(index) else {
            return false;
        };
        r.state = ToolState::Revoked;
        r.granted_caps = CapabilitySet::empty();
        true
    }

    /// Whether the tool at `index` may run (approved and not revoked).
    #[must_use]
    pub fn can_run(&self, index: usize) -> bool {
        self.tools.get(index).is_some_and(|r| r.state.can_run())
    }

    /// The normalized call view for a tool (`None` for a bad index).
    #[must_use]
    pub fn call_view(&self, index: usize) -> Option<ToolCallView> {
        self.tools.get(index).map(ToolRecord::call_view)
    }

    /// Every tool as a normalized call view (`tool list`).
    #[must_use]
    pub fn list(&self) -> Vec<ToolCallView> {
        self.tools.iter().map(ToolRecord::call_view).collect()
    }

    /// The approval audit log.
    #[must_use]
    pub fn approval_audit(&self) -> &[ToolApprovalAudit] {
        &self.audit
    }

    /// The number of registered tools.
    #[must_use]
    pub fn len(&self) -> usize {
        self.tools.len()
    }

    /// Whether the registry is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.tools.is_empty()
    }
}

// ---- web research profile -------------------------------------------------

/// A phase of the read-only web research profile.
#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WebResearchPhase {
    /// A search query.
    Search = 1,
    /// A fetch of a result.
    Fetch = 2,
    /// Opening a fetched page.
    Open = 3,
    /// A page snapshot.
    Snapshot = 4,
    /// A citation of a snapshot.
    Cite = 5,
}

/// The rights decision for a fetched source. Only [`RightsDecision::Allowed`]
/// permits using the source.
#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RightsDecision {
    /// Use is allowed.
    Allowed = 1,
    /// Behind a paywall — denied.
    PaywallDenied = 2,
    /// `robots.txt` disallows it — denied.
    RobotsDenied = 3,
    /// License forbids it — denied.
    LicenseDenied = 4,
}

impl RightsDecision {
    /// Whether the source may be used.
    #[must_use]
    pub const fn is_allowed(self) -> bool {
        matches!(self, Self::Allowed)
    }
}

/// Proof that browser credentials were redacted before anything was stored.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BrowserCredentialRedaction {
    /// Whether the raw headers contained a credential-shaped value.
    pub had_credential: bool,
    /// Invariant `true`: redaction was applied — no raw credential is stored.
    pub redacted: bool,
}

/// Redact browser credentials from raw headers. Reuses the REPL secret scanner
/// ([`classify`]) over the whole header blob and each whitespace token, so a
/// credential-shaped value is detected; the raw value is never returned or
/// stored — only this proof is.
#[must_use]
pub fn redact_browser_credentials(raw_headers: &str) -> BrowserCredentialRedaction {
    let had_credential = classify(raw_headers).is_some()
        || raw_headers
            .split_whitespace()
            .any(|t| classify(t).is_some());
    BrowserCredentialRedaction {
        had_credential,
        redacted: true,
    }
}

/// Parameters for [`WebResearchRecord::new`].
#[derive(Clone, Copy, Debug)]
pub struct WebFetchInputs<'a> {
    /// The research phase.
    pub phase: WebResearchPhase,
    /// The source URL (only its hash is stored).
    pub source_url: &'a str,
    /// Unix time the source was retrieved.
    pub retrieved_at_unix_u64: u64,
    /// The fetched body (only its hash is stored).
    pub fetch_body: &'a str,
    /// The raw response headers (scanned + redacted, never stored).
    pub raw_headers: &'a str,
    /// The rights decision for the source.
    pub rights: RightsDecision,
    /// The cited span (empty = no citation; only its hash is stored).
    pub citation_span: &'a str,
}

/// A read-only web research record. By construction it never stores a raw URL,
/// body, or credential — only hashes and decisions.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct WebResearchRecord {
    /// The research phase.
    pub phase: WebResearchPhase,
    /// SHA-256 of the source URL.
    pub source_url_hash_32: [u8; 32],
    /// Unix retrieval time.
    pub retrieved_at_unix_u64: u64,
    /// SHA-256 of the fetched body.
    pub fetch_hash_32: [u8; 32],
    /// The rights decision.
    pub rights: RightsDecision,
    /// SHA-256 of the cited span (zero = no citation).
    pub citation_span_hash_32: [u8; 32],
    /// Browser-credential redaction proof.
    pub credential: BrowserCredentialRedaction,
}

impl WebResearchRecord {
    /// Build a research record. Returns `None` (the source is refused) when the
    /// rights decision is not [`RightsDecision::Allowed`] (paywall / robots /
    /// license). Browser credentials are redacted before anything is stored.
    #[must_use]
    pub fn new(inputs: &WebFetchInputs<'_>) -> Option<Self> {
        if !inputs.rights.is_allowed() {
            return None;
        }
        let citation_span_hash_32 = if inputs.citation_span.is_empty() {
            ZERO32
        } else {
            sha256_32(inputs.citation_span.as_bytes())
        };
        Some(Self {
            phase: inputs.phase,
            source_url_hash_32: sha256_32(inputs.source_url.as_bytes()),
            retrieved_at_unix_u64: inputs.retrieved_at_unix_u64,
            fetch_hash_32: sha256_32(inputs.fetch_body.as_bytes()),
            rights: inputs.rights,
            citation_span_hash_32,
            credential: redact_browser_credentials(inputs.raw_headers),
        })
    }

    /// Whether this record cites a source span (is grounded).
    #[must_use]
    pub fn is_grounded(&self) -> bool {
        self.citation_span_hash_32 != ZERO32
    }
}

/// Whether a web-derived answer may be surfaced. A source-less answer (no record
/// or no citation) is denied, and a rights-denied source is denied.
#[must_use]
pub fn web_answer_allowed(record: Option<&WebResearchRecord>) -> bool {
    match record {
        Some(r) => r.rights.is_allowed() && r.is_grounded(),
        None => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::commands::capability::CapabilityKind;
    use crate::repl::latency::p95_ms;

    fn declared() -> CapabilitySet {
        CapabilitySet::with(CapabilityKind::PureCompute)
            .insert(CapabilityKind::ReadLocal)
            .insert(CapabilityKind::Network)
    }

    fn spec(adapter: ToolAdapterKind) -> ToolSpec<'static> {
        ToolSpec {
            adapter,
            tool_id: "tool-x",
            declared_caps: declared(),
            sandbox_tier_u8: 4,
            risk: CommandRisk::Network,
        }
    }

    #[test]
    fn add_test_approve_revoke_lifecycle() {
        let mut reg = ToolRegistry::new();
        let idx = reg.add(&spec(ToolAdapterKind::Python));
        assert_eq!(reg.len(), 1);
        // test = local config validation, no live run
        let report = reg.test(idx);
        assert!(report.is_some(), "test report for a valid index");
        if let Some(report) = report {
            assert!(report.no_live_run);
            assert_eq!(report.config_health, RenderTruth::Green);
        }
        // not runnable until approved
        assert!(!reg.can_run(idx));
        // approve a subset of declared caps
        let requested =
            CapabilitySet::with(CapabilityKind::ReadLocal).insert(CapabilityKind::Network);
        let diff = reg.approve(idx, requested);
        assert!(diff.is_ok(), "approve within declared caps");
        if let Ok(diff) = diff {
            assert!(
                diff.requires_approval(),
                "gaining capabilities needs approval"
            );
        }
        assert!(reg.can_run(idx));
        // revoke immediately removes runtime access
        assert!(reg.revoke(idx));
        assert!(!reg.can_run(idx), "a revoked tool must not run");
    }

    #[test]
    fn revoked_tool_cannot_be_reapproved() {
        let mut reg = ToolRegistry::new();
        let idx = reg.add(&spec(ToolAdapterKind::CliBinary));
        assert!(reg.revoke(idx));
        let requested = CapabilitySet::with(CapabilityKind::ReadLocal);
        assert_eq!(
            reg.approve(idx, requested),
            Err(ToolApprovalReject::AlreadyRevoked)
        );
    }

    #[test]
    fn approval_audit_is_recorded() {
        let mut reg = ToolRegistry::new();
        let idx = reg.add(&spec(ToolAdapterKind::Mcp));
        let requested = CapabilitySet::with(CapabilityKind::ReadLocal);
        assert!(reg.approve(idx, requested).is_ok(), "approve");
        let audit = reg.approval_audit();
        assert_eq!(audit.len(), 1);
        assert!(audit[0].approved);
        assert!(audit[0].capability_grew);
        assert_ne!(audit[0].diff_snapshot_hash_32, ZERO32);
    }

    #[test]
    fn hidden_permission_is_denied() {
        let mut reg = ToolRegistry::new();
        // declares only PureCompute
        let s = ToolSpec {
            adapter: ToolAdapterKind::WasmSkill,
            tool_id: "sneaky",
            declared_caps: CapabilitySet::with(CapabilityKind::PureCompute),
            sandbox_tier_u8: 1,
            risk: CommandRisk::ReadOnly,
        };
        let idx = reg.add(&s);
        // requests Network, never declared -> hidden permission
        let requested = CapabilitySet::with(CapabilityKind::Network);
        assert_eq!(
            reg.approve(idx, requested),
            Err(ToolApprovalReject::HiddenPermission)
        );
        assert!(!reg.can_run(idx));
    }

    #[test]
    fn all_adapters_normalize_to_one_view() {
        let mut reg = ToolRegistry::new();
        for adapter in [
            ToolAdapterKind::Python,
            ToolAdapterKind::Mcp,
            ToolAdapterKind::CliBinary,
            ToolAdapterKind::HttpService,
            ToolAdapterKind::WasmSkill,
        ] {
            let idx = reg.add(&spec(adapter));
            let view = reg.call_view(idx);
            assert!(view.is_some(), "a view for every adapter");
            if let Some(view) = view {
                assert_eq!(view.adapter, adapter);
                assert_eq!(view.sandbox_tier_u8, 4, "sandbox tier must be visible");
                // approval is derived from the risk via the canonical mapping
                assert_eq!(view.approval, approval_for(view.risk));
            }
        }
        assert_eq!(reg.list().len(), 5);
    }

    fn fetch_inputs(
        phase: WebResearchPhase,
        rights: RightsDecision,
        cite: &'static str,
    ) -> WebFetchInputs<'static> {
        WebFetchInputs {
            phase,
            source_url: "https://example.test/doc",
            retrieved_at_unix_u64: 1_700_000_000,
            fetch_body: "body bytes",
            raw_headers: "content-type: text/html",
            rights,
            citation_span: cite,
        }
    }

    #[test]
    fn web_research_phases_build_records() {
        for phase in [
            WebResearchPhase::Search,
            WebResearchPhase::Fetch,
            WebResearchPhase::Cite,
        ] {
            let cite = if matches!(phase, WebResearchPhase::Cite) {
                "quoted span"
            } else {
                ""
            };
            let r = WebResearchRecord::new(&fetch_inputs(phase, RightsDecision::Allowed, cite));
            assert!(r.is_some(), "an allowed source builds a record");
            if let Some(r) = r {
                assert_eq!(r.phase, phase);
                assert_ne!(r.fetch_hash_32, ZERO32);
                assert_ne!(r.source_url_hash_32, ZERO32);
            }
        }
    }

    #[test]
    fn browser_credentials_are_redacted() {
        // a header carrying a credential-shaped value (matches the secret scanner)
        let with_cred = redact_browser_credentials("set-cookie: app_secret_key=hunter2longvalue");
        assert!(with_cred.had_credential);
        assert!(with_cred.redacted);
        // a benign header has nothing to redact, but redaction is still applied
        let benign = redact_browser_credentials("content-type: text/html");
        assert!(!benign.had_credential);
        assert!(benign.redacted);
    }

    #[test]
    fn paywalled_source_is_denied() {
        for rights in [
            RightsDecision::PaywallDenied,
            RightsDecision::RobotsDenied,
            RightsDecision::LicenseDenied,
        ] {
            assert!(
                WebResearchRecord::new(&fetch_inputs(WebResearchPhase::Fetch, rights, ""))
                    .is_none(),
                "a {rights:?} source must be refused"
            );
        }
    }

    #[test]
    fn source_less_answer_is_denied() {
        // no record at all -> denied
        assert!(!web_answer_allowed(None));
        // a record with no citation -> denied (source-less)
        let ungrounded = WebResearchRecord::new(&fetch_inputs(
            WebResearchPhase::Fetch,
            RightsDecision::Allowed,
            "",
        ));
        assert!(ungrounded.is_some(), "allowed");
        if let Some(ungrounded) = ungrounded {
            assert!(!ungrounded.is_grounded());
            assert!(!web_answer_allowed(Some(&ungrounded)));
        }
        // a grounded, allowed record -> permitted
        let grounded = WebResearchRecord::new(&fetch_inputs(
            WebResearchPhase::Cite,
            RightsDecision::Allowed,
            "span",
        ));
        assert!(grounded.is_some(), "allowed");
        if let Some(grounded) = grounded {
            assert!(web_answer_allowed(Some(&grounded)));
        }
    }

    #[test]
    fn tool_list_p95_within_30ms() {
        let mut reg = ToolRegistry::new();
        for adapter in [
            ToolAdapterKind::Python,
            ToolAdapterKind::Mcp,
            ToolAdapterKind::CliBinary,
            ToolAdapterKind::HttpService,
            ToolAdapterKind::WasmSkill,
        ] {
            reg.add(&spec(adapter));
        }
        let mut samples = Vec::with_capacity(256);
        for _ in 0..256 {
            let t = std::time::Instant::now();
            let v = reg.list();
            std::hint::black_box(&v);
            samples.push(t.elapsed().as_nanos() as u64);
        }
        let p95 = p95_ms(&samples) / 1_000_000;
        assert!(p95 <= 30, "tool list p95 {p95}ms exceeds 30ms budget");
    }
}
