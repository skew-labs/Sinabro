//! §4.2 config precedence + feature / learning schema (atom #405 F.0.4).
//!
//! Precedence is `BuiltIn < System < User < Workspace < Env < CliArg`. A merged
//! config emits a [`CliConfigDigest`]; secrets are references only (an inline
//! secret is rejected via the a-core [`mnemos_a_core::looks_like_secret`]
//! detector); learning defaults to off, data egress defaults to `None`, and
//! every safety-kernel feature parses as [`FeatureState::Locked`] and can never
//! be disabled by any profile.

use std::collections::BTreeMap;

use mnemos_a_core::looks_like_secret;

use crate::{CONFIG_SCHEMA_VERSION_U16, CliError, CliResult, sha256_32};

/// §4.2 — config layer, lowest to highest precedence.
#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum ConfigLayer {
    /// Compiled-in defaults (lowest precedence).
    BuiltIn = 1,
    /// System-wide config.
    System = 2,
    /// Per-user config.
    User = 3,
    /// Per-workspace config.
    Workspace = 4,
    /// Environment variables.
    Env = 5,
    /// Command-line arguments (highest precedence).
    CliArg = 6,
}

impl ConfigLayer {
    /// Numeric precedence (higher wins).
    #[must_use]
    pub const fn precedence(self) -> u8 {
        self as u8
    }
}

/// §4.2 — sponsor mode view; mirrors the C `GasSponsorMode` discriminants.
#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SponsorModeView {
    /// Hosted Gas Station sponsor.
    Hosted = 1,
    /// Self-hosted sponsor.
    SelfHosted = 2,
    /// No sponsor.
    None = 3,
}

impl SponsorModeView {
    /// Parse a sponsor-mode token.
    #[must_use]
    pub fn parse(s: &str) -> Option<Self> {
        match s.trim().to_ascii_lowercase().as_str() {
            "hosted" => Some(Self::Hosted),
            "self_hosted" | "self" => Some(Self::SelfHosted),
            "none" => Some(Self::None),
            _ => None,
        }
    }
}

/// §4.2 — learning mode (default [`LearningMode::Off`]).
#[repr(u8)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum LearningMode {
    /// No learning artifacts produced (default).
    #[default]
    Off = 1,
    /// Local evidence bundles only.
    EvidenceOnly = 2,
    /// Local AtomDiet / SFT / preference / reward artifacts.
    LocalDiet = 3,
    /// Org/personal adapter shards only.
    PrivateAdapter = 4,
    /// Redacted/consented contribution review packet only.
    ContributeRedacted = 5,
}

impl LearningMode {
    /// Parse a learning-mode token.
    #[must_use]
    pub fn parse(s: &str) -> Option<Self> {
        match s.trim().to_ascii_lowercase().as_str() {
            "off" => Some(Self::Off),
            "evidence_only" => Some(Self::EvidenceOnly),
            "local_diet" => Some(Self::LocalDiet),
            "private_adapter" => Some(Self::PrivateAdapter),
            "contribute_redacted" => Some(Self::ContributeRedacted),
            _ => None,
        }
    }
}

/// §4.2 — data egress mode (default [`DataEgressMode::None`]).
#[repr(u8)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum DataEgressMode {
    /// No data leaves the machine (default).
    #[default]
    None = 1,
    /// Local-only artifacts.
    LocalOnly = 2,
    /// Self-hosted destination.
    SelfHosted = 3,
    /// Explicit, reviewed contribution.
    ExplicitContribution = 4,
}

impl DataEgressMode {
    /// Parse a data-egress token.
    #[must_use]
    pub fn parse(s: &str) -> Option<Self> {
        match s.trim().to_ascii_lowercase().as_str() {
            "none" => Some(Self::None),
            "local_only" => Some(Self::LocalOnly),
            "self_hosted" => Some(Self::SelfHosted),
            "explicit_contribution" => Some(Self::ExplicitContribution),
            _ => None,
        }
    }
}

/// §4.2 — feature state.
#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FeatureState {
    /// Feature on.
    Enabled = 1,
    /// Feature off.
    Disabled = 2,
    /// Feature locked on (safety kernel) — cannot be disabled.
    Locked = 3,
    /// Feature requires approval before each use.
    RequiresApproval = 4,
}

/// §4.2 — merged config digest.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CliConfigDigest {
    /// SHA-256 of the precedence-ordered merge.
    pub merged_hash_32: [u8; 32],
    /// Per-layer SHA-256, in precedence order.
    pub layer_hashes_32: Vec<[u8; 32]>,
    /// Config schema version.
    pub schema_version_u16: u16,
}

/// §4.2 — feature toggle view.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FeatureToggleView {
    /// SHA-256 of the feature name.
    pub feature_hash_32: [u8; 32],
    /// Resolved state.
    pub state: FeatureState,
    /// Whether this is a non-disableable safety-kernel feature.
    pub safety_kernel: bool,
    /// SHA-256 of the static reason label.
    pub reason_hash_32: [u8; 32],
}

/// §4.2 — learning control view.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LearningControlView {
    /// Active learning mode.
    pub mode: LearningMode,
    /// Active data egress mode.
    pub egress: DataEgressMode,
    /// Whether global contribution is on (default false).
    pub global_contribution: bool,
    /// Whether training on external model output is denied (default true).
    pub external_model_output_training_denied: bool,
}

impl Default for LearningControlView {
    fn default() -> Self {
        Self {
            mode: LearningMode::Off,
            egress: DataEgressMode::None,
            global_contribution: false,
            external_model_output_training_denied: true,
        }
    }
}

/// The non-disableable safety-kernel feature names (master §4.5 `SafetyKernelLock`).
pub const SAFETY_KERNEL_FEATURES: &[&str] = &[
    "redaction",
    "capability_diff",
    "no_silent_fallback",
    "no_auto_merge",
    "wallet_preview",
    "gas_drain_invariants",
    "mainnet_approval",
    "skill_sandbox",
    "evidence_trace",
    "self_evolution",
];

/// Allowed feature profiles. An unknown ("unsafe") profile is rejected.
pub const ALLOWED_PROFILES: &[&str] = &["safe-default", "minimal", "power"];

/// Whether `name` is a non-disableable safety-kernel feature.
#[must_use]
pub fn is_safety_kernel_feature(name: &str) -> bool {
    SAFETY_KERNEL_FEATURES.contains(&name)
}

fn is_disabling_value(v: &str) -> bool {
    matches!(
        v.trim().to_ascii_lowercase().as_str(),
        "disabled" | "off" | "false" | "0" | "no"
    )
}

/// Raw config schema as parsed from a single layer's TOML text. Unknown fields
/// are rejected so a typo cannot silently disable a control.
///
/// E11-4-1: `Serialize` is additive (the deserialize path / `deny_unknown_fields`
/// is unchanged) — it lets [`serialize_config`] render the canonical
/// `config.toml` the owner persists. `skip_serializing_if` keeps unset optionals
/// (and an empty `features` table) OUT of the written file, so the persisted text
/// round-trips byte-for-byte through [`parse_layer`].
#[derive(Clone, Debug, Default, serde::Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
pub struct RawCliConfig {
    /// Optional schema version (must be `<=` current).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub schema_version: Option<u16>,
    /// Optional feature profile name.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub profile: Option<String>,
    /// Optional learning mode token.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub learning_mode: Option<String>,
    /// Optional data egress token.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data_egress: Option<String>,
    /// Optional sponsor mode token.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sponsor_mode: Option<String>,
    /// Optional user web3 RPC endpoint (E10-3b / D-A5, READ-intent). A deploy-time
    /// seam: the deployer plugs in their OWN RPC endpoint; the agent then becomes
    /// web3-domain-aware for it and can PROPOSE a kernel-sandboxed READ against it
    /// (owner-approved). NOT dialed in v1 — the exec sandbox is network-DENIED, so
    /// a proposed read cannot reach the endpoint; live fire is a deploy-time /
    /// owner-armed V2 step. No chain host is allowlisted by this field (SI-5
    /// intact) and no chain WRITE is ever representable here.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub web3_rpc_endpoint: Option<String>,
    /// ONCHAIN PIVOT C-1: the owner-configured MULTI-CHAIN READ registry. Each entry is
    /// `"name:family:endpoint"` (e.g. `"ethereum:evm:https://rpc..."`; family ∈ solana/sui/evm).
    /// The agent reads ONLY these chains (the bound — it supplies a chain NAME, never a URL). Each
    /// endpoint is SSRF-walled again at dial time. A chain WRITE is never representable here.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub web3_rpc_chains: Vec<String>,
    /// Walrus self-host (BYO) PUBLISHER endpoint — a deploy-time seam (WALRUS_MAINNET_SELFHOST).
    /// The deployer runs their OWN `walrus publisher` (their wallet pays) or a hosted one and
    /// plugs in its https URL; the agent then stores its two-tier encrypted memory there. The
    /// bearer token rides `WALRUS_PUBLISHER_TOKEN` (a memory-only secret), NEVER a Sui private
    /// key — our app holds no key, never signs, never pays (PD-6 custody intact). https-only +
    /// SSRF-walled at use.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub walrus_publisher_endpoint: Option<String>,
    /// Walrus self-host AGGREGATOR endpoint (the GET side, READ-class) for the same deployment.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub walrus_aggregator_endpoint: Option<String>,
    /// [7] B⑪ (REMOTE_SHELL_THREAT_MODEL.md): the owner's remote box for the owner-armed
    /// READ-only `daemon remote-run` lane — `[user@]hostname[:port]`, config-only (NO
    /// arbitrary-host argument). Validated by `remote::classify_remote_host` at run time
    /// (no `-` option-injection, no shell metacharacter). NOT a chain/funds field — only a
    /// READ diagnostic runs there; custody stays HARD-LOCKED (PD-6).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub remote_ssh_host: Option<String>,
    /// E13-3 (⑲ / D-DL4): owner-added DOWNLOAD allowlist hosts. These EXTEND the
    /// curated `provider::download_fetch::DOWNLOAD_ALLOWLIST_DEFAULT`; the agent may
    /// download (an owner-armed `daemon fetch`) ONLY from `default ∪ owner`, and ONLY
    /// after the SSRF wall (`classify_url`) already passed. Bare hosts (no scheme), e.g.
    /// `["my.mirror.example"]`; matched lowercased. NOT a chain host (chain-RPC hosts
    /// are SSRF-denied regardless) — funds/chain stay HARD-LOCKED.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub download_allowlist: Vec<String>,
    /// B⑫ (CURSOR PARITY keystone-3 / §6 B⑫): owner-configured local stdio MCP
    /// servers. v1 = `tier = "read"` ONLY (read-class, network kernel-DENIED); an
    /// unconfigured server is fail-closed (the chokepoint denies it). Mutating /
    /// http-remote MCP is a separate owner-armed v2. NOT a chain/funds field —
    /// custody stays HARD-LOCKED (PD-6).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub mcp_servers: Vec<McpServerEntry>,
    /// Feature name -> state token map.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub features: BTreeMap<String, String>,
}

/// The one MCP server tier v1 admits (read-only stdio; the fail-closed default).
/// Mutating / http-remote tiers are a separate owner-armed v2 (refused at parse).
pub const MCP_TIER_READ: &str = "read";

/// The default (and v1-only) MCP server tier ([`MCP_TIER_READ`]).
fn default_mcp_tier() -> String {
    MCP_TIER_READ.to_string()
}

/// B⑫ (CURSOR PARITY keystone-3 / §6 B⑫) — ONE owner-configured local stdio MCP
/// server (a `[[mcp_servers]]` table). v1 admits `tier = "read"` ONLY (a read-class
/// stdio server run network + write kernel-DENIED); any other value is refused at
/// [`parse_layer`] ([`validate_config`]) — mutating / http-remote MCP is a separate
/// owner-armed v2. The `command` is a bare name (resolved on `PATH`) or an absolute
/// path; `args` are passed verbatim under the sandbox wrapper. NOT a chain / wallet
/// / funds field — custody stays HARD-LOCKED (PD-6).
#[derive(Clone, Debug, Default, serde::Deserialize, serde::Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct McpServerEntry {
    /// The server's logical name (the `<server>` token in `mcp <server> <tool>`).
    pub name: String,
    /// The command to spawn (bare name resolved on `PATH`, or an absolute path).
    pub command: String,
    /// The command's arguments (passed verbatim under the sandbox wrapper).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub args: Vec<String>,
    /// The per-server capability tier. v1 = `"read"` ONLY (fail-closed default).
    #[serde(default = "default_mcp_tier")]
    pub tier: String,
}

fn validate_config(cfg: &RawCliConfig) -> CliResult<()> {
    if let Some(v) = cfg.schema_version {
        if v > CONFIG_SCHEMA_VERSION_U16 {
            return Err(CliError::InvalidConfig);
        }
    }
    if let Some(p) = &cfg.profile {
        if !ALLOWED_PROFILES.contains(&p.as_str()) {
            return Err(CliError::InvalidConfig);
        }
    }
    if let Some(m) = &cfg.learning_mode {
        if LearningMode::parse(m).is_none() {
            return Err(CliError::InvalidConfig);
        }
    }
    if let Some(e) = &cfg.data_egress {
        if DataEgressMode::parse(e).is_none() {
            return Err(CliError::InvalidConfig);
        }
    }
    if let Some(s) = &cfg.sponsor_mode {
        if SponsorModeView::parse(s).is_none() {
            return Err(CliError::InvalidConfig);
        }
    }
    for (k, v) in &cfg.features {
        if is_safety_kernel_feature(k) && is_disabling_value(v) {
            return Err(CliError::SafetyKernelLocked);
        }
    }
    // B⑫ (§6 B⑫ T2 fail-closed): each MCP server must name a non-empty command and
    // carry the v1-only `read` tier — an empty / mutating / http-remote tier is
    // refused here (owner-armed v2), so an un-tiered or wrongly-tiered server can
    // never be admitted.
    for s in &cfg.mcp_servers {
        if s.name.trim().is_empty() || s.command.trim().is_empty() {
            return Err(CliError::InvalidConfig);
        }
        if !s.tier.eq_ignore_ascii_case(MCP_TIER_READ) {
            return Err(CliError::InvalidConfig);
        }
    }
    Ok(())
}

/// Parse one config layer's TOML text. Rejects: inline secrets
/// ([`CliError::SecretInline`]), unknown fields / bad values / unknown profile /
/// future schema ([`CliError::InvalidConfig`]), and any attempt to disable a
/// safety-kernel feature ([`CliError::SafetyKernelLocked`]). The raw text never
/// enters the error (redaction convention).
pub fn parse_layer(text: &str) -> CliResult<RawCliConfig> {
    if looks_like_secret(text) {
        return Err(CliError::SecretInline);
    }
    let cfg: RawCliConfig = toml::from_str(text).map_err(|_| CliError::InvalidConfig)?;
    validate_config(&cfg)?;
    Ok(cfg)
}

/// E11-4-1 — the file name of the persisted local config under `$HOME/.mnemos`
/// (the SAME home `memory_store::data_dir` returns; the SAME file
/// `gather_release_scan` scans). Persist writes here via `memory_store::atomic_write`.
pub const CONFIG_PERSIST_FILE: &str = "config.toml";

/// E11-4-1 (CONFIG_PERSIST_THREAT_MODEL.md ⑰) — render the canonical `config.toml`
/// text for an owner-specified config, fail-closed on every policy. This is the
/// PURE crux of the persist surface (no I/O): it (1) [`validate_config`]s (profile
/// allowlist + token validity + safety-kernel disable refusal, IV-CP5), then
/// (2) serializes to TOML, then (3) re-runs the SAME inline-secret screen
/// [`parse_layer`] uses on READ — a secret-shaped VALUE ⇒ [`CliError::SecretInline`],
/// so a key/token can NEVER be serialized into a config a caller would then write
/// (IV-CP1). The returned text is guaranteed validated, secret-free, and
/// `parse_layer`-round-trippable (IV-CP6). The raw config values never enter an
/// error (the redaction convention [`parse_layer`] follows).
///
/// ```
/// use sinabro::config::{RawCliConfig, serialize_config, parse_layer};
/// let mut cfg = RawCliConfig::default();
/// cfg.profile = Some("safe-default".to_string());
/// let text = serialize_config(&cfg).expect("validated + secret-free");
/// // The persisted text round-trips through the READ path (IV-CP6).
/// assert!(parse_layer(&text).is_ok());
/// // A secret-shaped value is refused at serialize time (IV-CP1) — never written.
/// // (the SAME `looks_like_secret` screen `parse_layer` runs on READ: an inline
/// // secret reference / raw key material is rejected — secrets belong in env refs).
/// cfg.web3_rpc_endpoint = Some("https://rpc.example/?ref=${RPC_SECRET_KEY}".to_string());
/// assert!(serialize_config(&cfg).is_err());
/// ```
pub fn serialize_config(cfg: &RawCliConfig) -> CliResult<String> {
    validate_config(cfg)?;
    let text = toml::to_string(cfg).map_err(|_| CliError::InvalidConfig)?;
    // IV-CP1: the SAME `looks_like_secret` gate `parse_layer` runs on READ, now on
    // the WRITE side — a secret-shaped value (e.g. an RPC URL carrying `?key=sk-…`)
    // is refused at serialize time, before any byte can reach the disk.
    if looks_like_secret(&text) {
        return Err(CliError::SecretInline);
    }
    Ok(text)
}

/// Compute the precedence-ordered config digest. Input layers may be in any
/// order; they are sorted by precedence before hashing so the digest is stable.
#[must_use]
pub fn compute_digest(layers: &[(ConfigLayer, &str)]) -> CliConfigDigest {
    let mut ordered: Vec<(ConfigLayer, &str)> = layers.to_vec();
    ordered.sort_by_key(|(layer, _)| layer.precedence());
    let mut layer_hashes_32 = Vec::with_capacity(ordered.len());
    let mut merged: Vec<u8> = Vec::new();
    for (layer, text) in &ordered {
        layer_hashes_32.push(sha256_32(text.as_bytes()));
        merged.push(layer.precedence());
        merged.extend_from_slice(text.as_bytes());
        merged.push(b'\n');
    }
    CliConfigDigest {
        merged_hash_32: sha256_32(&merged),
        layer_hashes_32,
        schema_version_u16: CONFIG_SCHEMA_VERSION_U16,
    }
}

/// Resolve the effective learning control by applying layers in precedence
/// order. Starts from the safe default (off / none / external-output denied).
pub fn effective_learning(
    layers: &[(ConfigLayer, RawCliConfig)],
) -> CliResult<LearningControlView> {
    let mut view = LearningControlView::default();
    let mut ordered: Vec<&(ConfigLayer, RawCliConfig)> = layers.iter().collect();
    ordered.sort_by_key(|(layer, _)| layer.precedence());
    for (_, cfg) in ordered {
        if let Some(m) = &cfg.learning_mode {
            view.mode = LearningMode::parse(m).ok_or(CliError::InvalidConfig)?;
        }
        if let Some(e) = &cfg.data_egress {
            view.egress = DataEgressMode::parse(e).ok_or(CliError::InvalidConfig)?;
        }
    }
    Ok(view)
}

/// E10-3b / D-A5 — the deploy-time user-RPC READ seam posture. A deployer plugs in
/// their OWN web3 RPC endpoint (READ-intent) via config; the agent becomes
/// web3-domain-aware for it and can PROPOSE a kernel-sandboxed read against it,
/// which runs only after the owner approves.
///
/// This is an HONEST SEAM, not a live chain client. In v1:
/// * NO chain client is built and NO chain host is allowlisted (SI-5 intact);
/// * the exec sandbox is network-DENIED, so a proposed read CANNOT actually reach
///   the endpoint — even a read stays inert at the network boundary;
/// * live networked RPC reads are a deploy-time / owner-armed V2 step.
///
/// Presence-only by construction: the raw endpoint value is NEVER carried here, so
/// a key-bearing URL cannot leak through the posture view ([`Self::render`]).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Web3RpcReadSeam {
    /// Whether a (non-empty) user RPC endpoint is configured (read-intent).
    /// Presence only — the raw endpoint string is deliberately not stored.
    pub configured: bool,
}

impl Web3RpcReadSeam {
    /// Honest, leak-free posture lines: presence only (never the raw endpoint),
    /// read-intent only, no live client, and explicitly NOT reachable in v1 (the
    /// sandbox is network-DENIED) — so the render can never imply a live read.
    #[must_use]
    pub fn render(&self) -> Vec<String> {
        vec![
            format!("web3_rpc_configured={}", self.configured),
            "web3_rpc_intent=read_only".to_string(),
            "web3_rpc_live_client=absent_v1".to_string(),
            "web3_rpc_reachable_in_v1=false".to_string(),
            "web3_rpc_live_fire=deploy_time_owner_armed_v2".to_string(),
        ]
    }
}

/// Resolve the effective user-RPC read seam across config layers in precedence
/// order (lowest to highest; a later layer wins). A non-empty `web3_rpc_endpoint`
/// sets presence; an empty string in a higher-precedence layer CLEARS it (no
/// silent stale presence). The endpoint VALUE is never propagated into the view
/// (presence-only — see [`Web3RpcReadSeam`]). Infallible: the field is a plain
/// optional string, already validated as non-secret by [`parse_layer`].
#[must_use]
pub fn effective_web3_rpc_seam(layers: &[(ConfigLayer, RawCliConfig)]) -> Web3RpcReadSeam {
    let mut configured = false;
    let mut ordered: Vec<&(ConfigLayer, RawCliConfig)> = layers.iter().collect();
    ordered.sort_by_key(|(layer, _)| layer.precedence());
    for (_, cfg) in ordered {
        if let Some(ep) = &cfg.web3_rpc_endpoint {
            configured = !ep.trim().is_empty();
        }
    }
    Web3RpcReadSeam { configured }
}

/// [3] Web3 RPC reader (E10-3b) — resolve the effective owner-configured RPC endpoint
/// VALUE across config layers in precedence order (lowest to highest; a later layer
/// wins; an empty string in a higher layer CLEARS it). Unlike [`effective_web3_rpc_seam`]
/// (presence-only), this returns the actual endpoint STRING — the ONLY input to the
/// owner-armed `daemon web3-read` dial (there is NO arbitrary-URL argument; the endpoint
/// is config-only, the `chain_env` "no arbitrary endpoint" invariant). The value is
/// SSRF-walled again by [`crate::provider::web3_rpc::classify_rpc_endpoint`] at dial time.
#[must_use]
pub fn effective_web3_rpc_endpoint(layers: &[(ConfigLayer, RawCliConfig)]) -> Option<String> {
    let mut endpoint: Option<String> = None;
    let mut ordered: Vec<&(ConfigLayer, RawCliConfig)> = layers.iter().collect();
    ordered.sort_by_key(|(layer, _)| layer.precedence());
    for (_, cfg) in ordered {
        if let Some(ep) = &cfg.web3_rpc_endpoint {
            let trimmed = ep.trim();
            endpoint = if trimmed.is_empty() {
                None
            } else {
                Some(trimmed.to_string())
            };
        }
    }
    endpoint
}

/// ONCHAIN PIVOT C-1: resolve the owner-configured MULTI-CHAIN READ registry across config layers
/// (lowest to highest precedence; entries from all layers are collected, a later duplicate of a
/// name is ignored — first wins, via [`crate::provider::web3_rpc::Web3ChainRegistry::from_entries`]).
/// Each config entry is `"name:family:endpoint"` (split on the FIRST two `:`, so the endpoint keeps
/// its `://`). A malformed / empty-field entry is dropped (fail-closed). The agent reads ONLY these
/// chains (the bound); each endpoint is SSRF-walled again at dial time.
#[must_use]
pub fn effective_web3_chain_registry(
    layers: &[(ConfigLayer, RawCliConfig)],
) -> crate::provider::web3_rpc::Web3ChainRegistry {
    use crate::provider::web3_rpc::{Web3ChainEntry, Web3ChainRegistry};
    let mut ordered: Vec<&(ConfigLayer, RawCliConfig)> = layers.iter().collect();
    ordered.sort_by_key(|(layer, _)| layer.precedence());
    let mut entries: Vec<Web3ChainEntry> = Vec::new();
    for (_, cfg) in ordered {
        for raw in &cfg.web3_rpc_chains {
            let parts: Vec<&str> = raw.splitn(3, ':').collect();
            if parts.len() == 3 {
                entries.push(Web3ChainEntry::new(parts[0], parts[1], parts[2]));
            }
        }
    }
    Web3ChainRegistry::from_entries(entries)
}

/// S2 (WALRUS_MAINNET_SELFHOST) — presence-only posture of the Walrus self-host
/// endpoints, for the GUI status panel. Like [`Web3RpcReadSeam`] it carries presence
/// ONLY: the raw endpoint URL is never stored here, so a key-bearing URL cannot leak
/// through the posture render.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct WalrusSelfHostSeam {
    /// Whether a (non-empty) self-host PUBLISHER endpoint is configured (WRITE side).
    pub publisher_configured: bool,
    /// Whether a (non-empty) self-host AGGREGATOR endpoint is configured (READ side).
    pub aggregator_configured: bool,
}

impl WalrusSelfHostSeam {
    /// Honest, leak-free posture lines: presence only (never the raw endpoint), the
    /// memory-only bearer secret, no Sui key / no funds (PD-6), and that WRITES stay
    /// owner-ceremony-gated (so a render can never imply an auto-write).
    #[must_use]
    pub fn render(&self) -> Vec<String> {
        vec![
            format!("walrus_publisher_configured={}", self.publisher_configured),
            format!(
                "walrus_aggregator_configured={}",
                self.aggregator_configured
            ),
            "walrus_token_secret=WALRUS_PUBLISHER_TOKEN (memory-only, Authorization: Bearer)"
                .to_string(),
            "walrus_custody=none (no Sui key / no sign / no funds; PD-6 HARD-LOCKED)".to_string(),
            "walrus_reads=autonomous_get".to_string(),
            "walrus_writes=owner_ceremony_gated".to_string(),
        ]
    }
}

/// S2 — resolve the Walrus self-host presence seam across config layers (precedence
/// order; an empty string in a higher layer CLEARS presence). Presence-only — the
/// endpoint VALUE never enters the view. Infallible.
#[must_use]
pub fn effective_walrus_selfhost_seam(
    layers: &[(ConfigLayer, RawCliConfig)],
) -> WalrusSelfHostSeam {
    let mut publisher_configured = false;
    let mut aggregator_configured = false;
    let mut ordered: Vec<&(ConfigLayer, RawCliConfig)> = layers.iter().collect();
    ordered.sort_by_key(|(layer, _)| layer.precedence());
    for (_, cfg) in ordered {
        if let Some(ep) = &cfg.walrus_publisher_endpoint {
            publisher_configured = !ep.trim().is_empty();
        }
        if let Some(ep) = &cfg.walrus_aggregator_endpoint {
            aggregator_configured = !ep.trim().is_empty();
        }
    }
    WalrusSelfHostSeam {
        publisher_configured,
        aggregator_configured,
    }
}

/// S2 — resolve the effective self-host PUBLISHER endpoint VALUE across config layers
/// (lowest to highest; a later layer wins; an empty string in a higher layer CLEARS
/// it). The ONLY input to the owner-armed self-host PUT (there is NO arbitrary-URL
/// argument). The value is SSRF-walled again by
/// [`crate::provider::walrus_selfhost::classify_walrus_endpoint`] at PUT time.
#[must_use]
pub fn effective_walrus_publisher_endpoint(
    layers: &[(ConfigLayer, RawCliConfig)],
) -> Option<String> {
    let mut endpoint: Option<String> = None;
    let mut ordered: Vec<&(ConfigLayer, RawCliConfig)> = layers.iter().collect();
    ordered.sort_by_key(|(layer, _)| layer.precedence());
    for (_, cfg) in ordered {
        if let Some(ep) = &cfg.walrus_publisher_endpoint {
            let trimmed = ep.trim();
            endpoint = if trimmed.is_empty() {
                None
            } else {
                Some(trimmed.to_string())
            };
        }
    }
    endpoint
}

/// S2 — resolve the effective self-host AGGREGATOR endpoint VALUE (the READ/GET side)
/// across config layers. Same precedence + empty-clears semantics as
/// [`effective_walrus_publisher_endpoint`]; SSRF-walled again at GET time.
#[must_use]
pub fn effective_walrus_aggregator_endpoint(
    layers: &[(ConfigLayer, RawCliConfig)],
) -> Option<String> {
    let mut endpoint: Option<String> = None;
    let mut ordered: Vec<&(ConfigLayer, RawCliConfig)> = layers.iter().collect();
    ordered.sort_by_key(|(layer, _)| layer.precedence());
    for (_, cfg) in ordered {
        if let Some(ep) = &cfg.walrus_aggregator_endpoint {
            let trimmed = ep.trim();
            endpoint = if trimmed.is_empty() {
                None
            } else {
                Some(trimmed.to_string())
            };
        }
    }
    endpoint
}

/// [7] B⑪ — resolve the effective owner-configured remote SSH host across config layers
/// (precedence order; empty in a higher layer CLEARS it). The ONLY input to the owner-armed
/// `daemon remote-run` lane (there is NO arbitrary-host argument). Re-validated by
/// [`crate::remote::classify_remote_host`] at run time.
#[must_use]
pub fn effective_remote_ssh_host(layers: &[(ConfigLayer, RawCliConfig)]) -> Option<String> {
    let mut host: Option<String> = None;
    let mut ordered: Vec<&(ConfigLayer, RawCliConfig)> = layers.iter().collect();
    ordered.sort_by_key(|(layer, _)| layer.precedence());
    for (_, cfg) in ordered {
        if let Some(h) = &cfg.remote_ssh_host {
            let trimmed = h.trim();
            host = if trimmed.is_empty() {
                None
            } else {
                Some(trimmed.to_string())
            };
        }
    }
    host
}

/// E13-3 (⑲ / D-DL4) — resolve the owner-extended DOWNLOAD allowlist hosts across
/// config layers (a UNION of every layer's `download_allowlist`, trimmed and
/// lowercased and de-duplicated). These EXTEND the curated default in
/// [`crate::provider::download_fetch::DownloadAllowlist`] (the module unions them); they
/// are bare hosts compared against `classify_url`'s already-lowercased host. Infallible:
/// the field is a plain string list, already screened non-secret by [`parse_layer`].
/// Note: a chain-RPC host added here is still SSRF-denied by `classify_url` (the
/// allowlist only NARROWS after the wall — it can never widen past it; funds/chain
/// stay HARD-LOCKED).
#[must_use]
pub fn effective_download_allowlist_hosts(layers: &[(ConfigLayer, RawCliConfig)]) -> Vec<String> {
    let mut hosts: Vec<String> = Vec::new();
    for (_, cfg) in layers {
        for h in &cfg.download_allowlist {
            let norm = h.trim().to_ascii_lowercase();
            if !norm.is_empty() && !hosts.contains(&norm) {
                hosts.push(norm);
            }
        }
    }
    hosts
}

/// B⑫ (CURSOR PARITY keystone-3 / §6 B⑫) — resolve the owner-configured READ-tier
/// stdio MCP servers across config layers (a UNION, deduped by logical name; first
/// occurrence wins). Only `tier = "read"` entries are returned ([`validate_config`]
/// already refused others at parse, so this is defense in depth). The returned
/// [`crate::mcp::McpServerSpec`]s feed the `McpSeam` the agent loop + the
/// `context mcp` verb consume; an unconfigured server is fail-closed (the chokepoint
/// denies it). Infallible: the field is a plain struct list, already screened
/// non-secret + tier-checked by [`parse_layer`]. NOT a chain/funds path — custody
/// stays HARD-LOCKED (PD-6).
#[must_use]
pub fn effective_mcp_servers(
    layers: &[(ConfigLayer, RawCliConfig)],
) -> Vec<crate::mcp::McpServerSpec> {
    let mut out: Vec<crate::mcp::McpServerSpec> = Vec::new();
    for (_, cfg) in layers {
        for s in &cfg.mcp_servers {
            if !s.tier.eq_ignore_ascii_case(MCP_TIER_READ) {
                continue;
            }
            let name = s.name.trim().to_string();
            if name.is_empty() || out.iter().any(|e| e.name == name) {
                continue;
            }
            out.push(crate::mcp::McpServerSpec::new(
                name,
                s.command.trim().to_string(),
                s.args.clone(),
            ));
        }
    }
    out
}

/// Resolve a feature toggle. Safety-kernel features are forced to
/// [`FeatureState::Locked`] and reject any disable request.
pub fn feature_toggle(name: &str, requested: FeatureState) -> CliResult<FeatureToggleView> {
    let safety = is_safety_kernel_feature(name);
    if safety && matches!(requested, FeatureState::Disabled) {
        return Err(CliError::SafetyKernelLocked);
    }
    let state = if safety {
        FeatureState::Locked
    } else {
        requested
    };
    let reason: &[u8] = if safety {
        b"safety_kernel_locked"
    } else {
        b"user_feature"
    };
    Ok(FeatureToggleView {
        feature_hash_32: sha256_32(name.as_bytes()),
        state,
        safety_kernel: safety,
        reason_hash_32: sha256_32(reason),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_learning_is_off_and_egress_none() {
        let v = LearningControlView::default();
        assert_eq!(v.mode, LearningMode::Off);
        assert_eq!(v.egress, DataEgressMode::None);
        assert!(v.external_model_output_training_denied);
        assert!(!v.global_contribution);
    }

    #[test]
    fn empty_layers_give_default_off() {
        assert!(matches!(effective_learning(&[]), Ok(v) if v.mode == LearningMode::Off));
    }

    #[test]
    fn precedence_cli_arg_overrides_builtin() {
        let builtin = parse_layer("learning_mode = \"off\"");
        let cli = parse_layer("learning_mode = \"local_diet\"");
        assert!(builtin.is_ok() && cli.is_ok());
        // Provide out of order to prove precedence sort, not input order.
        if let (Ok(b), Ok(c)) = (builtin, cli) {
            let merged = effective_learning(&[(ConfigLayer::CliArg, c), (ConfigLayer::BuiltIn, b)]);
            assert!(matches!(merged, Ok(v) if v.mode == LearningMode::LocalDiet));
        }
    }

    #[test]
    fn digest_is_stable_and_precedence_ordered() {
        let a = [(ConfigLayer::BuiltIn, "x=1"), (ConfigLayer::CliArg, "y=2")];
        let b = [(ConfigLayer::CliArg, "y=2"), (ConfigLayer::BuiltIn, "x=1")];
        // unknown fields here are fine: compute_digest does not parse, it hashes.
        assert_eq!(compute_digest(&a), compute_digest(&b));
        assert_eq!(compute_digest(&a).layer_hashes_32.len(), 2);
    }

    #[test]
    fn inline_secret_is_rejected() {
        let r = parse_layer("token = \"suiprivkey1qqqqexamplenotreal\"");
        assert_eq!(r.err(), Some(CliError::SecretInline));
    }

    #[test]
    fn unknown_field_is_invalid() {
        let r = parse_layer("definitely_unknown_field = 1");
        assert_eq!(r.err(), Some(CliError::InvalidConfig));
    }

    #[test]
    fn unsafe_profile_is_rejected() {
        let r = parse_layer("profile = \"unsafe\"");
        assert_eq!(r.err(), Some(CliError::InvalidConfig));
        assert!(parse_layer("profile = \"safe-default\"").is_ok());
    }

    #[test]
    fn safety_kernel_disable_is_rejected_in_config_and_toggle() {
        let r = parse_layer("[features]\nredaction = \"disabled\"");
        assert_eq!(r.err(), Some(CliError::SafetyKernelLocked));
        assert_eq!(
            feature_toggle("redaction", FeatureState::Disabled).err(),
            Some(CliError::SafetyKernelLocked)
        );
        assert!(matches!(
            feature_toggle("redaction", FeatureState::Enabled),
            Ok(v) if v.state == FeatureState::Locked && v.safety_kernel
        ));
        assert!(matches!(
            feature_toggle("fancy_colors", FeatureState::Disabled),
            Ok(v) if v.state == FeatureState::Disabled && !v.safety_kernel
        ));
    }

    // E10-3b / D-A5 — the deploy-time user-RPC READ seam.

    #[test]
    fn web3_rpc_seam_default_is_unconfigured_and_honest() {
        let seam = effective_web3_rpc_seam(&[]);
        assert!(!seam.configured);
        let lines = seam.render();
        // Honest posture: read-intent only, no live client, NOT reachable in v1
        // (the sandbox is network-DENIED) — the render can never imply a live read.
        assert!(lines.iter().any(|l| l == "web3_rpc_configured=false"));
        assert!(lines.iter().any(|l| l == "web3_rpc_intent=read_only"));
        assert!(lines.iter().any(|l| l == "web3_rpc_live_client=absent_v1"));
        assert!(lines.iter().any(|l| l == "web3_rpc_reachable_in_v1=false"));
        assert!(
            lines
                .iter()
                .any(|l| l == "web3_rpc_live_fire=deploy_time_owner_armed_v2")
        );
    }

    #[test]
    fn web3_rpc_seam_parses_and_resolves_with_precedence() {
        // A plain RPC endpoint URL is not secret-shaped — it parses cleanly.
        let user = parse_layer("web3_rpc_endpoint = \"https://rpc.example.test\"")
            .expect("plain endpoint parses");
        assert_eq!(
            user.web3_rpc_endpoint.as_deref(),
            Some("https://rpc.example.test")
        );
        // A configured endpoint flips presence to true.
        let seam = effective_web3_rpc_seam(&[(ConfigLayer::User, user.clone())]);
        assert!(seam.configured);
        // An empty higher-precedence layer CLEARS it (no silent stale presence).
        let cli_clear = parse_layer("web3_rpc_endpoint = \"\"").expect("empty endpoint parses");
        let cleared =
            effective_web3_rpc_seam(&[(ConfigLayer::CliArg, cli_clear), (ConfigLayer::User, user)]);
        assert!(!cleared.configured);
    }

    #[test]
    fn web3_rpc_render_never_echoes_the_raw_endpoint() {
        // The view is presence-only by construction; even a key-bearing URL given
        // directly to the resolver cannot leak through the posture render.
        let cfg = RawCliConfig {
            web3_rpc_endpoint: Some("https://my-rpc.example.test/v1".to_string()),
            ..Default::default()
        };
        let seam = effective_web3_rpc_seam(&[(ConfigLayer::User, cfg)]);
        assert!(seam.configured);
        let joined = seam.render().join("\n");
        assert!(
            !joined.contains("my-rpc.example.test"),
            "the raw endpoint must NEVER appear in the posture render: {joined}"
        );
    }

    #[test]
    fn web3_rpc_endpoint_is_a_known_field_not_an_unknown_typo() {
        // deny_unknown_fields means the field must be declared; a real config can
        // carry it (it is not rejected as an unknown field).
        assert!(parse_layer("web3_rpc_endpoint = \"https://rpc.example.test\"").is_ok());
    }

    #[test]
    fn download_allowlist_parses_resolves_union_and_round_trips() {
        // E13-3 / D-DL4: the owner-extension allowlist is a known field that parses,
        // normalizes (trim + lowercase + drop-empty + dedup), and round-trips.
        let user = parse_layer(
            "download_allowlist = [\"My.Mirror.Example\", \"  \", \"My.Mirror.Example\"]",
        )
        .expect("download_allowlist is a known field");
        assert_eq!(user.download_allowlist.len(), 3);
        let hosts = effective_download_allowlist_hosts(&[(ConfigLayer::User, user.clone())]);
        // trimmed + lowercased; empty dropped; duplicate collapsed
        assert_eq!(hosts, vec!["my.mirror.example".to_string()]);
        // the additive field round-trips through the serialize/READ path (IV-CP6).
        let text = serialize_config(&user).expect("serialize");
        let back = parse_layer(&text).expect("round-trips");
        assert_eq!(back.download_allowlist.len(), 3);
        // empty by default ⇒ no owner extension, and skip_serializing_if keeps it out.
        assert!(effective_download_allowlist_hosts(&[]).is_empty());
    }

    // ---- E11-4-1 config persist (serialize_config crux) -------------------

    #[test]
    fn serialize_config_round_trips_through_parse_layer() {
        // IV-CP6: a serialized config re-parses cleanly through the READ path.
        let cfg = RawCliConfig {
            schema_version: Some(CONFIG_SCHEMA_VERSION_U16),
            profile: Some("safe-default".to_string()),
            learning_mode: Some("off".to_string()),
            data_egress: Some("none".to_string()),
            web3_rpc_endpoint: Some("https://rpc.example.test".to_string()),
            ..Default::default()
        };
        let text = serialize_config(&cfg).expect("validated + secret-free");
        let back = parse_layer(&text).expect("round-trips through the READ path");
        assert_eq!(back.profile.as_deref(), Some("safe-default"));
        assert_eq!(back.learning_mode.as_deref(), Some("off"));
        assert_eq!(
            back.web3_rpc_endpoint.as_deref(),
            Some("https://rpc.example.test")
        );
    }

    #[test]
    fn serialize_config_refuses_a_secret_shaped_value() {
        // IV-CP1: the SAME inline-secret screen `parse_layer` uses on READ — a
        // secret-shaped value is refused at serialize time (never written).
        let interp = RawCliConfig {
            web3_rpc_endpoint: Some("https://rpc/${RPC_SECRET_KEY}".to_string()),
            ..Default::default()
        };
        assert_eq!(serialize_config(&interp), Err(CliError::SecretInline));
        // Raw key material is likewise refused.
        let raw = RawCliConfig {
            web3_rpc_endpoint: Some("suiprivkey1qq0deadbeef".to_string()),
            ..Default::default()
        };
        assert_eq!(serialize_config(&raw), Err(CliError::SecretInline));
    }

    #[test]
    fn serialize_config_refuses_disabling_a_safety_kernel_feature() {
        // IV-CP5: validate-before-write — a config that disables a kernel feature
        // is refused before serialization (nothing could ever be written).
        let mut features = BTreeMap::new();
        features.insert("redaction".to_string(), "disabled".to_string());
        let cfg = RawCliConfig {
            features,
            ..Default::default()
        };
        assert_eq!(serialize_config(&cfg), Err(CliError::SafetyKernelLocked));
    }

    #[test]
    fn serialize_config_refuses_an_unknown_profile() {
        // IV-CP5: an out-of-allowlist profile is refused — the persist path can
        // never write a config the READ path would reject.
        let cfg = RawCliConfig {
            profile: Some("unsafe-yolo".to_string()),
            ..Default::default()
        };
        assert_eq!(serialize_config(&cfg), Err(CliError::InvalidConfig));
    }
}
