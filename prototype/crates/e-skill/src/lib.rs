//! `mnemos-e-skill` — skill manifest loading and the read/write/run builtin whitelist.
//!
//! Phase 0 critical-path crate. Modules are filled in atom-by-atom per
//! `MNEMOS_ATOM_PLAN.md` §4.E; their canonical signatures live there. Each
//! finished atom keeps `cargo build --workspace` green.
//!
//! Filled so far:
//! - [`manifest`] (atom #39 · E.0.1): TOML manifest parse + validate.
//!   Canonical home for [`manifest::SkillManifest`] (private fields +
//!   `pub const fn` accessors per atom #3 `TurnState` / atom #24
//!   `LazyToolSchema` invariant-protection precedent), [`manifest::SkillId`]
//!   (`#[repr(transparent)]` newtype over `u16` per atom #24 `ToolId`
//!   precedent), [`manifest::ManifestError`] (`#[non_exhaustive]`
//!   4-variant `Copy` enum with `manifest.*` class labels — the raw TOML
//!   error is dropped on parse failure so a canary in a manifest body
//!   cannot reach `Debug` / `Display`), and the free function
//!   [`manifest::load_manifest`] (`&str → Result<SkillManifest,
//!   ManifestError>`; the only public surface; never reads the
//!   filesystem). Reuses [`mnemos_m_agent::tool_schema::ToolId`] (atom
//!   #24) verbatim for the declared-tool slice; the `UnknownTool`
//!   rejection cross-pins against [`manifest::KNOWN_TOOL_IDS`] —
//!   the const allow-set matching §4.E line 711 builtin discriminants
//!   `{ReadFile=1, WriteFile=2, RunCommand=3}` (atom #40 promotes this
//!   to the `Builtin` enum; atom #39 cross-pins via the const so the
//!   canonical set stays one source-of-truth).
//! - [`builtins`] (atom #40 · E.0.2): Phase 0 builtin whitelist
//!   dispatcher. Canonical home for [`builtins::Builtin`]
//!   (`#[repr(u8)]` 3-variant enum `{ReadFile=1, WriteFile=2,
//!   RunCommand=3}` — discriminants cross-pinned at compile time to
//!   [`manifest::KNOWN_TOOL_IDS`] so widening either surface alone
//!   fails the build), [`builtins::CommandAllowlist`]
//!   (`&'static [&'static str]` carrier; runtime injection of new
//!   programs is impossible by construction), [`builtins::BuiltinOutcome`]
//!   (12-byte length-only carrier — no field can hold stdout / stderr
//!   bytes, so the "출력은 길이만" §4.E line 714 guarantee holds
//!   by-construction), and the free function [`builtins::dispatch_builtin`]
//!   (validator-only — every rejection folds through
//!   [`mnemos_a_core::MnemosError::tool_denied`] per atom #2 reuse; real
//!   IO / spawn is deferred to the later §2.7 T0~T2 routing wiring
//!   atom per `[[no-disabled-path-workaround]]`). The canonical
//!   Phase 0 set `["cargo", "git", "sui", "walrus"]` is re-exported as
//!   the [`builtins::PHASE0_COMMAND_ALLOWLIST`] const, matching
//!   [`mnemos_a_core::ToolProgram`] variant order.
//! ## D-WP-01A (#241-#254): signed skill package surface
//!
//! Stage D wraps the A [`manifest::SkillManifest`] in a signed
//! [`package::SkillPackageV1`] and never re-mints A/B/C canonical types. The
//! new modules form one verifier pipeline:
//! - [`package`] (#242): the `SkillPackageV1` aggregate + content-digest spine.
//! - [`package_policy`] (#243): the no-commerce forbidden-field scan.
//! - [`capability_diff`] (#244): the permission diff shown before use/install.
//! - [`eval`] (#245): the eval score + reproducible-command / tests digests.
//! - [`provenance`] (#246): single-parent content-addressed lineage.
//! - [`signature`] (#247): the offline author signature over the content digest.
//! - [`package_toml`] (#248): the canonical TOML normal form.
//! - [`bundle`] (#249): extraction-safe bundle layout + artifact digest tree.
//! - [`compat`] (#251): the compatibility constraint model.
//! - [`verify`] (#252): `verify_skill_package` — the typed verifier API.
//!
//! The malicious-fixture gate (#250), property corpus (#253), and verify
//! bench (#254) live in `tests/` + `benches/`.
//! ## D-WP-02 (#256-#275): WASM Tier-2 sandbox policy + try-before-use
//!
//! The [`wasm_tier2`] cluster adds the deny-by-default capability / metering /
//! hostcall policy for a Stage D skill sandbox plus the try-before-use,
//! install-plan, and rollback surfaces. Per the owner-locked architecture
//! decision it is a *policy + declarative-fixture* layer: it carries the
//! limits, grants, hostcall table, and [`wasm_tier2::WasmSandboxDecision`] a
//! real engine will be required to enforce, but embeds no engine and performs
//! no live network / wallet / chain / host-filesystem action. It reuses
//! [`mnemos_a_core::StageDTraceLink`] (minted in `a-core` by this WorkPackage)
//! for sandbox trace evidence and never re-mints an A/B/C canonical type.
//! ## D-WP-03A (#276-#291): registry/provenance/install Move ABI + Rust bindings
//!
//! The Move package `prototype/move/mnemos_skill_registry` mints the on-chain
//! registry / provenance / install-receipt ABI; this crate adds the Rust side:
//! - [`install_state`] (#284): the `InstallState` lifecycle enum, byte-pinned to
//!   the Move `STATE_*` constants, plus the runtime-usable decision.
//! - [`chain_bindings`] (#288): manual fixed-layout BCS encoders for
//!   `SkillRegistryArgs` / `InstallReceiptArgs` / `InstallReceiptView` and
//!   `ProvenanceNode`, parity-pinned with the Move `parity.move` vectors.
//! - [`ptb`] (#290): PTB dry-run builders gated by the C `GasStationPolicy`
//!   (package binding + gas cap + wildcard reject); dry-run / policy-only, no
//!   signing, one acyclic new edge `e-skill -> g-wallet`.
//!
//! The Move-Prover lineage acyclicity proof (#281) is authored under
//! `prototype/move/mnemos_skill_registry/prover/` and DEFERRED (owner-locked
//! Option A): the invariant is runtime-enforced + `sui move test`-green now.
#![deny(missing_docs)]

pub mod anti_gaming;
pub mod author_check;
pub mod builtins;
pub mod bundle;
pub mod capability_diff;
pub mod catalog_cache;
pub mod catalog_card;
pub mod catalog_counters;
pub mod catalog_index;
pub mod chain_bindings;
pub mod community_import;
pub mod compat;
pub mod compat_solver;
pub mod eval;
pub mod install_plan;
pub mod install_receipt;
pub mod install_state;
pub mod manifest;
pub mod no_commerce;
pub mod package;
pub mod package_policy;
pub mod package_toml;
pub mod permission_preview;
pub mod progressive_load;
pub mod provenance;
pub mod ptb;
pub mod ranking;
pub mod recommend;
pub mod review_queue;
pub mod rollback;
pub mod search_query;
pub mod signature;
pub mod starter_pack;
pub mod try_before_use;
pub mod verify;
pub mod wasm_tier2;

#[doc(no_inline)]
pub use builtins::{
    Builtin, BuiltinOutcome, CommandAllowlist, PHASE0_COMMAND_ALLOWLIST, dispatch_builtin,
};
#[doc(no_inline)]
pub use manifest::{KNOWN_TOOL_IDS, ManifestError, SkillId, SkillManifest, load_manifest};

#[doc(no_inline)]
pub use bundle::{BundleEntry, BundleError, BundleLayout, is_safe_bundle_path};
#[doc(no_inline)]
pub use capability_diff::{CapabilityDiff, SkillRuntimePermission, a_capabilities_for_mask};
#[doc(no_inline)]
pub use compat::{
    CompatibilityDecision, HostEnvironment, MnemosVersion, SkillCompatibility, VersionReq,
};
#[doc(no_inline)]
pub use eval::{MAX_EVAL_SCORE, SkillEvalScore, reproducible_command_hash, tests_digest};
#[doc(no_inline)]
pub use install_plan::{InstallBlockReason, InstallDecision, InstallPlan, InstallPreconditions};
#[doc(no_inline)]
pub use install_state::{InstallState, runtime_decision};
#[doc(no_inline)]
pub use package::{
    SkillPackageDigest32, SkillPackageV1, SkillSecurityState, SkillSupplyChainReceipt,
};
#[doc(no_inline)]
pub use package_policy::{
    NoCommerceViolation, is_no_commerce, no_commerce_policy_hash, scan_no_commerce,
};
#[doc(no_inline)]
pub use package_toml::{PackageTomlError, RawPackage, parse_package, to_canonical_toml};
#[doc(no_inline)]
pub use permission_preview::{PermissionPreview, PreviewGate, gate_action, high_risk_first_key};
#[doc(no_inline)]
pub use provenance::{MAX_PROVENANCE_DEPTH, ProvenanceNode, validate_ancestor_chain};
#[doc(no_inline)]
pub use rollback::{LocalSkillState, RollbackOp, apply_rollback};
#[doc(no_inline)]
pub use signature::SkillPackageSignature;
#[doc(no_inline)]
pub use try_before_use::{FixtureSource, TryBeforeUseFixture, TryBeforeUseRun, run_try_before_use};
#[doc(no_inline)]
pub use verify::{VerifiedPackage, VerifyError, verify_skill_package};

#[doc(no_inline)]
pub use wasm_tier2::WasmSandboxDecision;
#[doc(no_inline)]
pub use wasm_tier2::determinism::DeterministicContext;
#[doc(no_inline)]
pub use wasm_tier2::fs_policy::evaluate_fs_access;
#[doc(no_inline)]
pub use wasm_tier2::grant::{
    ScopedSkillCapabilityToken, WasmCapabilityGrant, authorize_with_grants,
};
#[doc(no_inline)]
pub use wasm_tier2::hostcalls::{HOSTCALL_TABLE_VERSION_U16, SkillHostcall, hostcall_table_hash};
#[doc(no_inline)]
pub use wasm_tier2::limits::{LimitExceeded, LimitsError, WasmRuntimeLimits};
#[doc(no_inline)]
pub use wasm_tier2::meter::{
    MAX_HOSTCALLS_PER_RUN_U32, MAX_STACK_DEPTH_U32, ResourceDemand, enforce_meter,
};
#[doc(no_inline)]
pub use wasm_tier2::module_id::{ModuleIdError, WasmTier2ModuleId};
#[doc(no_inline)]
pub use wasm_tier2::net_policy::{NetRunMode, evaluate_net_access};
#[doc(no_inline)]
pub use wasm_tier2::output::{OutputEnvelope, build_output_envelope};
#[doc(no_inline)]
pub use wasm_tier2::secret_policy::{
    ChainActionMode, SECRET_BYTES_ENTER_WASM_MEMORY, evaluate_chain_action, is_secret_family,
    secret_family_override,
};
#[doc(no_inline)]
pub use wasm_tier2::trace::SandboxTraceRecord;

#[doc(no_inline)]
pub use chain_bindings::{
    InstallReceiptArgs, InstallReceiptId, InstallReceiptView, SkillChainAction, SkillRegistryArgs,
    encode_provenance_node_bcs,
};
#[doc(no_inline)]
pub use ptb::{SkillPtbAction, SkillPtbDryRun, build_dry_run};

// ## D-WP-04 (#296-#305): catalog index / cards / search / ranking / recommend
#[doc(no_inline)]
pub use catalog_card::{
    CapabilityClass, SkillCardDetail, SkillCardSummary, card_cta_gate, order_cards_permission_first,
};
#[doc(no_inline)]
pub use catalog_counters::{
    CatalogCounters, VerifiedInstallReceipt, VerifiedInstallState, fold_counters,
};
#[doc(no_inline)]
pub use catalog_index::{CatalogIndexError, SkillCatalogIndexEntry};
#[doc(no_inline)]
pub use compat_solver::{
    bundle_installable, solve_bundle, solve_single, solve_with_tools, tools_supported,
};
#[doc(no_inline)]
pub use ranking::{RankWeights, SkillRankScore, rank, ranking_replay_hash};
#[doc(no_inline)]
pub use recommend::{
    Recommendation, RecommendationCandidate, RecommendationContext, auto_install_allowed,
    meets_security_floor,
};
#[doc(no_inline)]
pub use search_query::{SearchParseError, SkillSearchQuery};

// ## D-WP-05A (#306-#310): catalog cache / anti-gaming / fuzz / bench
#[doc(no_inline)]
pub use anti_gaming::{AntiGamedCounters, anti_gamed_counters};
#[doc(no_inline)]
pub use catalog_cache::{
    CacheRefusal, CacheStatus, CatalogCache, CatalogCacheEntry, SignedCatalogCache,
};

// ## D-WP-05B (#311-#320): starter pack / community import / author guide /
// progressive disclosure / local install receipt + state machine / no-commerce
// surface scan / community review queue
#[doc(no_inline)]
pub use author_check::{
    AuthorCheckError, AuthorChecklist, AuthorStep, check_capability_declaration,
    check_manifest_schema, evaluate_submission,
};
#[doc(no_inline)]
pub use community_import::{
    CommunityImportEvidence, CommunitySkillDecision, CommunitySkillImport, decide_import,
};
#[doc(no_inline)]
pub use install_receipt::{
    LocalInstallReceipt, LocalInstallReceiptId, LocalReceiptKind, ReceiptError,
    compatibility_admits_install, mint_receipt,
};
#[doc(no_inline)]
pub use install_state::{LocalSkillTransition, TransitionAudit, TransitionError, apply_transition};
#[doc(no_inline)]
pub use no_commerce::{
    NoCommerceReport, NoCommerceSurface, NoCommerceSurfaceViolation, forbidden_commerce_token,
    scan_surfaces,
};
#[doc(no_inline)]
pub use progressive_load::{
    LoadTier, ProgressiveSearchResult, load_tier, progressive_inspect, progressive_search,
};
#[doc(no_inline)]
pub use review_queue::{
    MaintainerVerdict, ReviewEntry, ReviewQueue, ReviewQueueError, ReviewState,
};
#[doc(no_inline)]
pub use starter_pack::{SkillStarterPack, StarterPackError, StarterPackMember};

// A/B/C field types exposed by the Stage D public surface (e.g.
// `LocalInstallReceipt.user` / `.trace`), re-exported verbatim so the public API
// is self-contained — reuse, never a re-mint, of the canonical A/D types.
#[doc(no_inline)]
pub use mnemos_a_core::{StageBTraceLink, StageCTraceLink, StageDTraceLink};
#[doc(no_inline)]
pub use mnemos_d_move::types::SuiAddress;
