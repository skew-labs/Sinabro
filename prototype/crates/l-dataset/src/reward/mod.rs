//! Reward firewall + didactic governance (atoms #388-#391 · E.3.2-E.3.5).
//!
//! [`failure_cause`] governs *why* a step failed and emits evidence-backed
//! didactic signals; [`layered`] turns S1 execution results into a discrete
//! reward behind eight hard nullifiers and the Naite composite weights;
//! [`enforce`] gates any positive reward behind an actual reverify; [`fgo`]
//! builds the fine-grained AST coverage mask. No path mints reward from a
//! self-report, a narrative, or an infra-masked failure.
pub mod enforce;
pub mod failure_cause;
pub mod fgo;
pub mod layered;
