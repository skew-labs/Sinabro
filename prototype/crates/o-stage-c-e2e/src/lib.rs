//! `mnemos-o-stage-c-e2e` — Stage C cross-crate integration-test host.
//!
//! This crate intentionally ships **no production code**. It exists only to host
//! the two Stage C integration tests that span more crates than any single
//! production crate dev-depends on:
//!
//! * `tests/stage_c_redaction_canary.rs` — full-pipeline secret
//!   absence across redaction, content policy, and metrics surfaces.
//! * `tests/stage_c_ga_e2e_dry_run.rs` — the complete GA dry-run
//!   path: signed chunk → Walrus verified fixture → Sui dry-run → gas trace →
//!   replay-hash stability, with no live network and no mainnet write.
//!
//! The six domain crates are `dev-dependencies`, so this crate adds no new
//! production dependency edge to the workspace graph.
