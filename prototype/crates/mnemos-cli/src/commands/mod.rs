//! CLI command-handler modules — the verb-level surface behind the closed
//! [`crate::grammar`] namespaces.
//!
//! Each handler is a pure model / projection over *injected* state; no handler
//! performs network / chain / gas / provider I/O on the hot path (the latency
//! law). Side effects, when later wired, always travel through a
//! [`crate::command::CommandEnvelope`] carrying risk + approval.

pub mod audit;
pub mod audit_log;
pub mod authority;
pub mod budget;
pub mod budget_global;
pub mod capability;
pub mod chain_env;
pub mod checkpoint;
pub mod context;
pub mod contrib;
pub mod dataset_export;
pub mod dataset_ingest;
pub mod eval_core;
pub mod eval_language;
pub mod evidence;
pub mod federation;
pub mod federation_locked;
pub mod gas_request;
pub mod gas_status;
pub mod grant;
pub mod incident;
pub mod kill;
pub mod learning;
pub mod memory_intel;
pub mod memory_portability;
pub mod memory_query;
pub mod memory_setup;
pub mod model_cache;
pub mod model_compress;
pub mod model_endpoint;
pub mod model_route;
pub mod model_select;
pub mod model_speculate;
pub mod multisig;
pub mod package;
pub mod platform_other;
pub mod platform_telegram;
pub mod provider;
pub mod release;
pub mod release_secret_scan;
pub mod review;
pub mod rollback;
pub mod sandbox;
pub mod skill_package;
pub mod skill_provenance;
pub mod skill_search;
pub mod skill_state;
pub mod skill_use;
pub mod source_scan;
pub mod tool;
pub mod trace_pair;
pub mod wallet;
pub mod wallet_sign;
