//! Local audit companion — the Stage G audit game tree (G-WP-04, atoms #516–#530).
//!
//! Sinabro's audit companion reads a protocol like baduk, not like a grep:
//!
//! ```text
//! invariant graph -> bounded state space -> move generator -> impact prior
//!   -> local repro plan -> candidate -> local repro receipt
//!   -> finding (only with a reproduced, local-only receipt) OR defended memory
//! ```
//!
//! Every module here is a pure, local-only projection: there is no Solana/Sui RPC,
//! no live transaction, no production probing, and no third-party-funds touch. A
//! pattern match is a *candidate*, never a finding, until a local repro / proof /
//! replay receipt verifies the affected invariant (`G-G-AUDIT-GAME-TREE`). A
//! defended (non-broken) invariant is kept as memory so the same dead end is not
//! re-read. No model weight training happens in Stage G.
//!
//! Reuse (no reinvention): the candidate / finding spine is the Stage F
//! [`crate::commands::eval_core`] (`AuditCandidate` / `route_to_finding`), the
//! severity is `mnemos_l_dataset::security::source::SecuritySeverity`, and the
//! economic corpus is `datasets/economic_invariant_diet/manifest.json`.

pub mod bundle;
pub mod candidate;
pub mod defended_memory;
pub mod detect;
pub mod detectors;
pub mod impact_prior;
pub mod invariant_graph;
pub mod move_generator;
pub mod report_draft;
pub mod repro_plan;
pub mod repro_receipt;
pub mod solana_patterns;
pub mod state_space;
pub mod static_detector;
pub mod sui_move_patterns;
