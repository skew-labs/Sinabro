//! `provider` — Stage G operational provider/router composition layer
//! (G-WP-02, atoms #491–#505).
//!
//! This module is the *operational* layer that sits over the Stage F provider
//! command surface ([`crate::commands::provider`],
//! [`crate::commands::model_route`], [`crate::commands::model_endpoint`],
//! [`crate::commands::model_compress`], [`crate::commands::model_cache`],
//! [`crate::commands::tool`]). It **reuses — never redefines** the Stage F
//! canonical types (`ProviderKind`, `ModelRole`, `RouteExecutionState`,
//! `FallbackDiff`, `FrontierConsultPacketView`, `ConsultTrigger`,
//! `TrajectoryHealth`, `ContextCompressionReport`, `CachePrefixBoundary`,
//! `WebResearchRecord`) and binds them into the bounded, disabled-by-default,
//! redaction-gated, no-silent-fallback operational loop.
//!
//! Stage G law (consistency-lock "Sinabro-First After Stage F"): no model weight
//! training; every frontier consult is advisory only, disabled by default, and
//! never dispatched live without a same-message approval (absent here). All views
//! are pure in-memory projections — no provider / network / chain call on any
//! path in this module.

// E13-3 (⑲): the owner-armed bounded GET → temp download. Pure SSRF wall + allowlist
// + capability-gated glue ALWAYS compiled; the live reqwest transport is gated behind
// the off-default `download-egress` feature. Threat model:
// GATED_DOWNLOAD_THREAT_MODEL.md (⑲ IV-DL1..DL8).
pub mod download_fetch;
pub mod egress;
pub mod escalation;
// P1-1 (owner brief 2026-06-13, orchestrator spine): the task-aware EXECUTOR
// router — a PURE deterministic kind->(port, model_id) map (L2 of the three-layer
// separation). Always compiled (no transport dependency); ORTHOGONAL to
// route_select (which selects local-vs-frontier permission, not the expert).
// Plan: ops/evidence/stage_g/agent_loop/P1_ORCHESTRATOR_PLAN.md.
pub mod executor_route;
pub mod frontier_consult;
// P3-3 (owner-authorized 2026-06-11): the loopback OpenAI-compatible chat
// transport — the consult-shaped fill of the local-serving seam. Compiled
// only when a local-serving adapter feature is on; reuses the egress codec
// (one wire truth). Threat model: LOCAL_ENDPOINT_THREAT_MODEL.md (⑧).
#[cfg(any(feature = "local-mlx", feature = "local-vllm"))]
pub mod local_chat;
pub mod local_endpoint;
#[cfg(feature = "local-mlx")]
pub mod local_mlx;
#[cfg(feature = "local-vllm")]
pub mod local_vllm;
pub mod lora_manifest;
pub mod redaction;
pub mod registry;
pub mod route_fsm;
pub mod route_policy;
// E2-2 (PD-7 / RD-49 v1, owner-authorized 2026-06-12): the typed consult-route
// selector — local (autonomy default, READ-class) vs frontier (owner-armed
// egress escalation). The single routing truth consumed at the dispatch arm.
pub mod route_select;
pub mod trajectory_health;
// S2 (WALRUS_MAINNET_SELFHOST) — the self-host (BYO) mainnet Walrus transport. The
// SSRF wall (`classify_walrus_endpoint`) is always-compiled (testable in the default
// build); the executable PUT/GET transport is gated behind `walrus-mainnet`.
pub mod walrus_selfhost;
pub mod web3_rpc;
pub mod web_fetch;
pub mod web_policy;
