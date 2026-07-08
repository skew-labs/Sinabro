//! `provider::lora_manifest` — the corpus→adapter MANIFEST + the send-time
//! HONEST-DEGRADE resolution (the dynamic-LoRA switch's P-HALL gate).
//!
//! The routing table ([`crate::provider::executor_route`]) already selects a `(port,
//! model_id)` per sub-task `kind`, and the orchestrator already places that `model_id`
//! on the wire (`send_local_text_with`). This module adds the two PURE pieces the
//! dynamic-LoRA switch was missing:
//!
//! 1. **The corpus→adapter MANIFEST** ([`LoraManifest`]): the AGENT's catalog of the
//!    LoRA adapters it has LEGITIMATELY EARNED — one per CERTIFIED strategy domain (the
//!    P-HALL gate). Only a `certified == true` summary yields a binding
//!    ([`LoraManifest::from_certified_strategies`]); a hallucinated / uncertified
//!    "success" NEVER becomes an adapter (the precise defense against the owner's
//!    "wrong memory written as success → pattern reinforced → collapse" failure mode).
//!    The key is GENERAL: any domain
//!    label — a strategy archetype (`market_making`, `hedge`), an executor expert
//!    kind (`sui_move`, `audit`), or a user domain — is a valid [`AdapterKey`]. The
//!    strategy archetypes populate it first because they are the only certified corpus
//!    today; a video / physics / marketing domain becomes an adapter the SAME way once
//!    its certified corpus accumulates (the domain-agnostic pivot).
//!
//! 2. **The send-time HONEST-DEGRADE resolution** ([`resolve_adapter`]): given a
//!    REQUESTED adapter id (the routing table's `model_id`), the set a real multi-LoRA
//!    server actually SERVES ([`ServedAdapterSet`]), and the base model, resolve to the
//!    model id that ACTUALLY rides the wire. A requested adapter that NO server serves
//!    degrades to the base model — the served base answers, NEVER a fabricated adapter
//!    ([`AdapterResolution::DegradedToBase`]). The served set is EMPTY by default (no
//!    server up) ⇒ every adapter degrades honestly; the live co-resident serving + the
//!    paid train are the owner GPU go-live.
//!
//! META-LAW (drift-0, money-0): every function here is a TOTAL pure map — no clock, no
//! float, no network, no custody / sign / chain symbol. The manifest + resolution are
//! the agent's HONEST self-knowledge of its adapters; they move no funds and the model
//! never reaches a key. `CustodyCapability` stays uninhabited.

use crate::provider::executor_route::ExecutorRoutingTable;
use std::collections::BTreeSet;

/// A validated GENERAL domain key for an adapter binding: a strategy archetype
/// (`market_making`, `hedge`), an executor
/// expert kind (`sui_move`, `audit`), or any user domain — one snake_case namespace.
/// Closed charset (ascii-lowercase alnum + `_`, 1..=48 bytes), mirroring
/// [`crate::provider::executor_route::ExecutorKind`]'s discipline so the manifest is
/// fail-closed + drift-0; any garbage label is rejected at construction.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct AdapterKey(String);

impl AdapterKey {
    /// Validate + construct. Fail-closed: empty, over-length (>48 bytes), or any byte
    /// outside `[a-z0-9_]` ⇒ `None`.
    #[must_use]
    pub fn new(label: &str) -> Option<Self> {
        if label.is_empty() || label.len() > 48 {
            return None;
        }
        if !label
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_')
        {
            return None;
        }
        Some(Self(label.to_string()))
    }

    /// The validated label.
    #[must_use]
    pub fn label(&self) -> &str {
        &self.0
    }
}

/// A validated served-adapter id — the string a real multi-LoRA server resolves to a
/// co-resident adapter (the `model` field on the wire). Charset = ascii-lowercase alnum
/// + `_` + `-` (PEFT/LoRA adapter names use hyphens), 1..=64 bytes; fail-closed.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct AdapterId(String);

impl AdapterId {
    /// Validate + construct. Fail-closed: empty, over-length (>64 bytes), or any byte
    /// outside `[a-z0-9_-]` ⇒ `None`.
    #[must_use]
    pub fn new(id: &str) -> Option<Self> {
        if id.is_empty() || id.len() > 64 {
            return None;
        }
        if !id
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_' || b == b'-')
        {
            return None;
        }
        Some(Self(id.to_string()))
    }

    /// The validated id.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// The canonical adapter id DERIVED from a key (`naite-<key>-lora`) — the agent's
    /// default served name for a certified domain's adapter (the owner may override it
    /// in `routing_table.txt`). Deterministic + pure; the key's `[a-z0-9_]` charset (≤48
    /// bytes) guarantees the result is a valid `[a-z0-9_-]` id (≤59 bytes), so this is
    /// total (never `None`).
    #[must_use]
    pub fn derive_for(key: &AdapterKey) -> Self {
        Self(format!("naite-{}-lora", key.label()))
    }
}

/// A certified-strategy summary the manifest builder consumes: the domain key + the
/// conformal cert bit. The dispatch sources these from the certified corpus (every entry
/// there is certified by the `admits_write == certified` admission — the upstream P-HALL
/// gate, [`crate::autonomy_evolve::strategy_candidate`]); the builder RE-ASSERTS the gate
/// (drops `certified == false`) as defense-in-depth + the falsifiable pin (the verifier
/// neutralizes this check to prove it bites).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CertifiedStrategy {
    /// The domain key (archetype / expert kind / user domain).
    pub key: AdapterKey,
    /// The conformal certification bit ([`crate::skew_strategy::StrategyCert::certified`]).
    pub certified: bool,
}

/// One manifest binding: a certified domain key → its served-adapter id.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AdapterBinding {
    /// The certified domain key.
    pub key: AdapterKey,
    /// The adapter id (derived canonical name).
    pub adapter_id: AdapterId,
}

/// The agent's catalog of LEGITIMATELY-EARNED LoRA adapters — one per CERTIFIED strategy
/// domain (the P-HALL gate). Built ONLY from certified summaries; an uncertified strategy
/// yields NO binding.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct LoraManifest {
    bindings: Vec<AdapterBinding>,
}

impl LoraManifest {
    /// Build the manifest from certified-strategy summaries — THE P-HALL GATE. ONLY a
    /// `certified == true` summary yields a binding ([`AdapterId::derive_for`] names its
    /// adapter); an uncertified summary is DROPPED (it never becomes an adapter — the
    /// precise defense against "a hallucinated success becomes a LoRA"). First key wins
    /// on a duplicate (stable, deterministic order).
    #[must_use]
    pub fn from_certified_strategies(strategies: &[CertifiedStrategy]) -> Self {
        let mut bindings: Vec<AdapterBinding> = Vec::new();
        for s in strategies {
            // P-HALL: an UNcertified strategy NEVER becomes an adapter.
            if !s.certified {
                continue;
            }
            // First key wins (deterministic; a domain maps to ONE adapter).
            if bindings.iter().any(|b| b.key == s.key) {
                continue;
            }
            bindings.push(AdapterBinding {
                key: s.key.clone(),
                adapter_id: AdapterId::derive_for(&s.key),
            });
        }
        Self { bindings }
    }

    /// The certified adapter bindings, in deterministic insertion order.
    #[must_use]
    pub fn bindings(&self) -> &[AdapterBinding] {
        &self.bindings
    }

    /// Number of certified adapters in the catalog.
    #[must_use]
    pub fn len(&self) -> usize {
        self.bindings.len()
    }

    /// Whether the catalog is empty (no certified strategy has earned an adapter yet).
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.bindings.is_empty()
    }

    /// The adapter id bound to a key, if the domain is certified-backed.
    #[must_use]
    pub fn adapter_for(&self, key: &AdapterKey) -> Option<&AdapterId> {
        self.bindings
            .iter()
            .find(|b| &b.key == key)
            .map(|b| &b.adapter_id)
    }

    /// Whether an adapter id is in the agent's certified catalog (a provenance label —
    /// `true` = the agent earned it from a certified strategy; `false` = e.g. an
    /// owner-connected external adapter that is still legitimately served).
    #[must_use]
    pub fn contains_adapter(&self, id: &AdapterId) -> bool {
        self.bindings.iter().any(|b| &b.adapter_id == id)
    }
}

/// The set of adapter ids a configured multi-LoRA server ACTUALLY serves — the HONEST
/// served set. EMPTY by default (no server up) ⇒ every adapter degrades to the base. The
/// dispatch builds this from [`SERVED_ADAPTERS_FILE`] (the owner declares a served id
/// ONLY when a real co-resident server serves it; the file is the owner's authorization,
/// symmetric with `routing_table.txt`). [`resolve_adapter`] sends an id ONLY if it is
/// here — an unserved adapter NEVER rides the wire.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ServedAdapterSet {
    served: BTreeSet<AdapterId>,
}

impl ServedAdapterSet {
    /// The empty served set (the honest default: no co-resident server up).
    #[must_use]
    pub fn empty() -> Self {
        Self::default()
    }

    /// Build from an explicit id list (the dispatch's file load; tests inject a server).
    #[must_use]
    pub fn from_ids<I: IntoIterator<Item = AdapterId>>(ids: I) -> Self {
        Self {
            served: ids.into_iter().collect(),
        }
    }

    /// Whether the server serves this adapter id.
    #[must_use]
    pub fn contains(&self, id: &AdapterId) -> bool {
        self.served.contains(id)
    }

    /// Number of served adapters.
    #[must_use]
    pub fn len(&self) -> usize {
        self.served.len()
    }

    /// Whether no server serves any adapter (honest no-server).
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.served.is_empty()
    }

    /// The served adapter ids, in deterministic (sorted) order.
    pub fn ids(&self) -> impl Iterator<Item = &AdapterId> {
        self.served.iter()
    }
}

/// The owner config file (under the data dir) listing the adapter ids a real multi-LoRA
/// server serves — one id per line (`#` comments / blank lines ignored). Symmetric with
/// [`crate::provider::executor_route::ROUTING_TABLE_CONFIG_FILE`]. ABSENT / empty ⇒
/// honest no-server (every adapter degrades to the base).
pub const SERVED_ADAPTERS_FILE: &str = "served_adapters.txt";

/// Parse a served-adapters config (PURE, fail-OPEN per line): each non-comment line is
/// ONE adapter id; an INVALID id is SKIPPED (never fabricated into the set). An empty /
/// all-invalid file yields the EMPTY set (honest no-server) — never an error (a missing
/// server is the default, not a failure).
#[must_use]
pub fn parse_served_adapters(text: &str) -> ServedAdapterSet {
    let mut served: BTreeSet<AdapterId> = BTreeSet::new();
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if let Some(id) = AdapterId::new(line) {
            served.insert(id);
        }
    }
    ServedAdapterSet { served }
}

/// Why a requested adapter degraded to the base model (honest-render label).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DegradeReason {
    /// No multi-LoRA server serves the requested adapter id (the served set lacks it,
    /// or the requested label is not a valid adapter id) — the served base answers.
    AdapterNotServed,
}

/// The send-time resolution of a requested adapter id → the model id that ACTUALLY rides
/// the wire. TOTAL + fail-closed: an unserved adapter NEVER reaches the wire; the base
/// model answers instead (honest-degrade; never a fabricated adapter).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AdapterResolution {
    /// The requested id IS the base model (no adapter switch requested).
    Base {
        /// The base model id (rides the wire).
        model_id: String,
    },
    /// A real server serves the requested adapter ⇒ it rides the wire. `certified_backed`
    /// labels whether it is in the agent's certified manifest (`true`) vs an
    /// owner-connected external adapter (`false`) — provenance only; both are served.
    Served {
        /// The served adapter id (rides the wire).
        adapter_id: AdapterId,
        /// Whether the adapter is in the agent's certified manifest (provenance label).
        certified_backed: bool,
    },
    /// The requested adapter is NOT served ⇒ the base model answers (honest-degrade).
    DegradedToBase {
        /// The requested (unserved) adapter label, preserved for the honest render.
        requested: String,
        /// The base model id that ACTUALLY rides the wire.
        base_model_id: String,
        /// Why it degraded.
        reason: DegradeReason,
    },
}

impl AdapterResolution {
    /// The model id that ACTUALLY rides the wire (`send_local_text_with`'s `model`).
    /// NEVER an unserved adapter — `DegradedToBase` yields the base model.
    #[must_use]
    pub fn wire_model_id(&self) -> &str {
        match self {
            Self::Base { model_id } => model_id,
            Self::Served { adapter_id, .. } => adapter_id.as_str(),
            Self::DegradedToBase { base_model_id, .. } => base_model_id,
        }
    }

    /// Whether the resolution honest-degraded (the requested adapter was not served).
    #[must_use]
    pub fn is_degraded(&self) -> bool {
        matches!(self, Self::DegradedToBase { .. })
    }

    /// A short honest label for the render (`base` / `served` / `degraded`). A degraded
    /// line ALWAYS pairs with `wire=<base>` in the render, so "degraded" is unambiguous:
    /// the base answered, the requested adapter did NOT (the reason is in [`DegradeReason`]).
    #[must_use]
    pub fn status_label(&self) -> &'static str {
        match self {
            Self::Base { .. } => "base",
            Self::Served { .. } => "served",
            Self::DegradedToBase { .. } => "degraded",
        }
    }
}

/// Resolve a REQUESTED adapter id (the routing table's `model_id`) → the model id that
/// rides the wire, HONEST-DEGRADING to `base_model_id` when no server serves it. TOTAL,
/// fail-closed, PURE. `manifest` supplies the certified-provenance label only; the SEND
/// decision is purely "does a real server serve this id?". An unserved adapter NEVER
/// rides the wire (the base answers) — the core honesty guarantee.
#[must_use]
pub fn resolve_adapter(
    requested_model_id: &str,
    manifest: &LoraManifest,
    served: &ServedAdapterSet,
    base_model_id: &str,
) -> AdapterResolution {
    // The base model itself is not an adapter switch.
    if requested_model_id == base_model_id {
        return AdapterResolution::Base {
            model_id: base_model_id.to_string(),
        };
    }
    // A valid + SERVED adapter rides the wire; anything else honest-degrades to the base
    // (an unserved or malformed adapter never reaches the wire).
    if let Some(id) = AdapterId::new(requested_model_id) {
        if served.contains(&id) {
            let certified_backed = manifest.contains_adapter(&id);
            return AdapterResolution::Served {
                adapter_id: id,
                certified_backed,
            };
        }
    }
    AdapterResolution::DegradedToBase {
        requested: requested_model_id.to_string(),
        base_model_id: base_model_id.to_string(),
        reason: DegradeReason::AdapterNotServed,
    }
}

/// Render the LoRA status (PURE; the CLI `provider lora-status` verb + the GUI Tauri
/// command share this — one honest truth source, no JS re-implementation). Shows: the
/// agent's certified-adapter MANIFEST (catalog), the SERVED set (what a real server
/// serves — empty ⇒ honest no-server), and the per-kind RESOLUTION for the routing
/// table (requested adapter → wire model, served/degraded). HONEST: a degraded
/// line shows the base model answered, NEVER a fabricated adapter; an empty served set
/// is shown as a degrade-everything no-server state, not faked as up.
#[must_use]
pub fn render_lora_status(
    manifest: &LoraManifest,
    served: &ServedAdapterSet,
    table: &ExecutorRoutingTable,
    base_model_id: &str,
) -> String {
    use std::fmt::Write as _;
    let mut s = String::new();
    let _ = writeln!(
        s,
        "lora-status: mode=sequential certified-adapters={} served={} base={base_model_id}",
        manifest.len(),
        served.len()
    );

    // The agent's certified-adapter catalog (P-HALL: a certified strategy backs each).
    s.push_str("manifest (P-HALL — only a CERTIFIED strategy backs an adapter):\n");
    if manifest.is_empty() {
        s.push_str("  (empty — no certified strategy has earned an adapter yet)\n");
    } else {
        for b in manifest.bindings() {
            let _ = writeln!(s, "  {} -> {}", b.key.label(), b.adapter_id.as_str());
        }
    }

    // What a real multi-LoRA server actually serves (empty ⇒ honest no-server).
    s.push_str("served set (a real co-resident server serves these; the owner go-live):\n");
    if served.is_empty() {
        s.push_str(
            "  (empty — no co-resident server up; every adapter degrades to the base model)\n",
        );
    } else {
        for id in served.ids() {
            let backed = if manifest.contains_adapter(id) {
                " (certified-backed)"
            } else {
                " (owner-connected)"
            };
            let _ = writeln!(s, "  {}{}", id.as_str(), backed);
        }
    }

    // The per-kind resolution for the routing table (requested adapter -> wire model).
    // Compact (kept <80 cols so the [status] tag survives the CLI clamp); the port lives
    // in the routing editor — here the truth is the adapter→wire resolution.
    s.push_str("routing resolution (requested adapter -> wire model; honest-degrade):\n");
    for (kind, target) in table.bindings() {
        let res = resolve_adapter(&target.model_id, manifest, served, base_model_id);
        let _ = writeln!(
            s,
            "  {}: {} -> {} [{}]",
            kind.label(),
            target.model_id,
            res.wire_model_id(),
            res.status_label()
        );
    }
    let d = table.default_target();
    let res = resolve_adapter(&d.model_id, manifest, served, base_model_id);
    let _ = writeln!(
        s,
        "  default: {} -> {} [{}]",
        d.model_id,
        res.wire_model_id(),
        res.status_label()
    );
    s
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use super::*;
    use crate::provider::executor_route::{
        ExecutorKind, ExecutorRoutingTable, ExecutorTarget, default_routing_table,
    };

    // ---- AdapterKey / AdapterId validation (fail-closed, drift-0 charset) ----

    #[test]
    fn adapter_key_accepts_general_domains_and_rejects_garbage() {
        // GENERAL (Q1=both): archetypes, executor kinds, AND user domains are all valid.
        assert!(AdapterKey::new("market_making").is_some(), "archetype");
        assert!(AdapterKey::new("sui_move").is_some(), "executor kind");
        assert!(AdapterKey::new("physics").is_some(), "user domain");
        assert!(AdapterKey::new("").is_none(), "empty rejected");
        assert!(AdapterKey::new("Market_Making").is_none(), "uppercase");
        assert!(AdapterKey::new("market making").is_none(), "space");
        assert!(
            AdapterKey::new("market-making").is_none(),
            "dash not in key"
        );
        assert!(AdapterKey::new(&"x".repeat(49)).is_none(), "over-length");
    }

    #[test]
    fn adapter_id_charset_and_derive() {
        assert!(AdapterId::new("naite-hedge-lora").is_some(), "hyphens ok");
        assert!(
            AdapterId::new("naite_hedge_lora").is_some(),
            "underscore ok"
        );
        assert!(
            AdapterId::new("Naite-Hedge").is_none(),
            "uppercase rejected"
        );
        assert!(AdapterId::new("naite.lora").is_none(), "dot rejected");
        assert!(AdapterId::new(&"x".repeat(65)).is_none(), "over-length");
        // derive_for is TOTAL: an archetype key with `_` yields a valid `[a-z0-9_-]` id.
        let key = AdapterKey::new("market_making").expect("valid");
        assert_eq!(
            AdapterId::derive_for(&key).as_str(),
            "naite-market_making-lora"
        );
        assert!(
            AdapterId::new(AdapterId::derive_for(&key).as_str()).is_some(),
            "derived id re-validates"
        );
    }

    // ---- The P-HALL gate: only a CERTIFIED strategy becomes an adapter ----

    #[test]
    fn manifest_admits_only_certified_strategies() {
        let strategies = vec![
            CertifiedStrategy {
                key: AdapterKey::new("market_making").unwrap(),
                certified: true,
            },
            CertifiedStrategy {
                key: AdapterKey::new("hedge").unwrap(),
                certified: false, // UNcertified — MUST NOT become an adapter (P-HALL).
            },
            CertifiedStrategy {
                key: AdapterKey::new("directional").unwrap(),
                certified: true,
            },
        ];
        let manifest = LoraManifest::from_certified_strategies(&strategies);
        // Only the 2 certified strategies earned adapters; the uncertified one did NOT.
        assert_eq!(manifest.len(), 2);
        assert_eq!(
            manifest
                .adapter_for(&AdapterKey::new("market_making").unwrap())
                .map(AdapterId::as_str),
            Some("naite-market_making-lora")
        );
        assert!(
            manifest
                .adapter_for(&AdapterKey::new("hedge").unwrap())
                .is_none(),
            "an UNcertified strategy NEVER becomes an adapter (the P-HALL gate)"
        );
        assert_eq!(
            manifest
                .adapter_for(&AdapterKey::new("directional").unwrap())
                .map(AdapterId::as_str),
            Some("naite-directional-lora")
        );
    }

    #[test]
    fn manifest_dedups_first_key_wins() {
        let strategies = vec![
            CertifiedStrategy {
                key: AdapterKey::new("hedge").unwrap(),
                certified: true,
            },
            CertifiedStrategy {
                key: AdapterKey::new("hedge").unwrap(),
                certified: true,
            },
        ];
        let manifest = LoraManifest::from_certified_strategies(&strategies);
        assert_eq!(manifest.len(), 1, "a domain maps to ONE adapter");
    }

    #[test]
    fn empty_certified_list_yields_empty_manifest() {
        assert!(LoraManifest::from_certified_strategies(&[]).is_empty());
    }

    // ---- served-adapters config parse (fail-open per line, honest no-server) ----

    #[test]
    fn parse_served_adapters_skips_comments_blanks_and_invalid() {
        let text = "# my running server's adapters\nnaite-hedge-lora\n\n  naite-mm-lora  \nBAD UPPER\nnaite.dot\n";
        let served = parse_served_adapters(text);
        assert_eq!(served.len(), 2, "only the 2 valid ids; garbage skipped");
        assert!(served.contains(&AdapterId::new("naite-hedge-lora").unwrap()));
        assert!(served.contains(&AdapterId::new("naite-mm-lora").unwrap()));
    }

    #[test]
    fn parse_empty_served_is_honest_no_server() {
        assert!(parse_served_adapters("# nothing here\n\n").is_empty());
        assert!(parse_served_adapters("").is_empty());
    }

    // ---- the send-time resolution: honest-degrade, never a fabricated adapter ----

    #[test]
    fn requested_base_resolves_to_base() {
        let manifest = LoraManifest::default();
        let served = ServedAdapterSet::empty();
        let res = resolve_adapter("naite-base", &manifest, &served, "naite-base");
        assert_eq!(
            res,
            AdapterResolution::Base {
                model_id: "naite-base".into()
            }
        );
        assert_eq!(res.wire_model_id(), "naite-base");
        assert!(!res.is_degraded());
    }

    #[test]
    fn served_adapter_rides_the_wire_with_provenance() {
        let manifest = LoraManifest::from_certified_strategies(&[CertifiedStrategy {
            key: AdapterKey::new("hedge").unwrap(),
            certified: true,
        }]);
        // The server serves BOTH the certified adapter AND an owner-connected external one.
        let served = ServedAdapterSet::from_ids([
            AdapterId::new("naite-hedge-lora").unwrap(),
            AdapterId::new("owner-custom-lora").unwrap(),
        ]);
        // certified-backed adapter ⇒ Served, certified_backed=true, rides the wire.
        let r1 = resolve_adapter("naite-hedge-lora", &manifest, &served, "naite-base");
        assert!(matches!(
            r1,
            AdapterResolution::Served {
                certified_backed: true,
                ..
            }
        ));
        assert_eq!(r1.wire_model_id(), "naite-hedge-lora");
        // owner-connected served adapter ⇒ Served, certified_backed=false (still served).
        let r2 = resolve_adapter("owner-custom-lora", &manifest, &served, "naite-base");
        assert!(matches!(
            r2,
            AdapterResolution::Served {
                certified_backed: false,
                ..
            }
        ));
        assert_eq!(r2.wire_model_id(), "owner-custom-lora");
    }

    #[test]
    fn unserved_adapter_honest_degrades_to_base() {
        let manifest = LoraManifest::from_certified_strategies(&[CertifiedStrategy {
            key: AdapterKey::new("hedge").unwrap(),
            certified: true,
        }]);
        // No server up (empty served set) — the honest default.
        let served = ServedAdapterSet::empty();
        // Even the CERTIFIED adapter degrades: it is in the manifest but NO server serves it.
        let res = resolve_adapter("naite-hedge-lora", &manifest, &served, "naite-base");
        assert_eq!(
            res,
            AdapterResolution::DegradedToBase {
                requested: "naite-hedge-lora".into(),
                base_model_id: "naite-base".into(),
                reason: DegradeReason::AdapterNotServed,
            }
        );
        // THE CORE HONESTY GUARANTEE: the wire carries the BASE, never the unserved adapter.
        assert_eq!(res.wire_model_id(), "naite-base");
        assert!(res.is_degraded());
        assert_eq!(res.status_label(), "degraded");
    }

    #[test]
    fn malformed_requested_id_degrades_not_panics() {
        let manifest = LoraManifest::default();
        let served = ServedAdapterSet::empty();
        // An invalid-charset model id can never be a served adapter ⇒ honest-degrade.
        let res = resolve_adapter("My.Fancy.Model", &manifest, &served, "naite-base");
        assert!(res.is_degraded());
        assert_eq!(res.wire_model_id(), "naite-base");
    }

    /// THE NO-SERVER HONESTY PROOF: with NO co-resident server up (the
    /// default), EVERY adapter the routing table requests degrades to the base — the
    /// served base answers, NEVER a fabricated adapter on the wire.
    #[test]
    fn no_server_degrades_every_routing_adapter_to_base() {
        let manifest = LoraManifest::from_certified_strategies(&[
            CertifiedStrategy {
                key: AdapterKey::new("sui_move").unwrap(),
                certified: true,
            },
            CertifiedStrategy {
                key: AdapterKey::new("solana_anchor").unwrap(),
                certified: true,
            },
        ]);
        let served = ServedAdapterSet::empty(); // no server
        let table = default_routing_table();
        for (_kind, target) in table.bindings() {
            let res = resolve_adapter(&target.model_id, &manifest, &served, "naite-base");
            assert_eq!(
                res.wire_model_id(),
                "naite-base",
                "no server up ⇒ {} degrades to the base (never fabricated)",
                target.model_id
            );
        }
    }

    // ---- the honest render (CLI + GUI share it) ----

    #[test]
    fn render_shows_honest_no_server_and_degrade() {
        let manifest = LoraManifest::from_certified_strategies(&[CertifiedStrategy {
            key: AdapterKey::new("market_making").unwrap(),
            certified: true,
        }]);
        let served = ServedAdapterSet::empty();
        let table = ExecutorRoutingTable::new(
            vec![(
                ExecutorKind::new("market_making").unwrap(),
                ExecutorTarget {
                    port: 11434,
                    model_id: "naite-market_making-lora".into(),
                },
            )],
            ExecutorTarget {
                port: 11434,
                model_id: "naite-base".into(),
            },
        );
        let rendered = render_lora_status(&manifest, &served, &table, "naite-base");
        assert!(rendered.contains("certified-adapters=1"));
        assert!(rendered.contains("served=0"));
        assert!(
            rendered.contains("no co-resident server up"),
            "honest no-server line present"
        );
        assert!(
            rendered.contains("[degraded]"),
            "the requested adapter is shown honest-degrading, not faked as served"
        );
        // The render must NEVER claim the unserved adapter rode the wire — it shows the base.
        assert!(rendered.contains("-> naite-base [degraded]"));
    }

    #[test]
    fn render_shows_served_adapter_when_a_server_is_up() {
        let manifest = LoraManifest::from_certified_strategies(&[CertifiedStrategy {
            key: AdapterKey::new("hedge").unwrap(),
            certified: true,
        }]);
        let served = ServedAdapterSet::from_ids([AdapterId::new("naite-hedge-lora").unwrap()]);
        let table = ExecutorRoutingTable::new(
            vec![(
                ExecutorKind::new("hedge").unwrap(),
                ExecutorTarget {
                    port: 11500,
                    model_id: "naite-hedge-lora".into(),
                },
            )],
            ExecutorTarget {
                port: 11434,
                model_id: "naite-base".into(),
            },
        );
        let rendered = render_lora_status(&manifest, &served, &table, "naite-base");
        assert!(rendered.contains("served=1"));
        assert!(rendered.contains("certified-backed"));
        assert!(
            rendered.contains("-> naite-hedge-lora [served]"),
            "the served adapter is shown riding the wire"
        );
    }
}
