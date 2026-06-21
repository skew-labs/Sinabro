//! Human review + PR provenance collectors (atoms #374–#377).
//!
//! Human approval is **provenance and preference signal**, never ground-truth
//! reward by itself and never an override of a gate-red / privacy-red sample.
//! Reviewer ids and comments are hashed; emails, API tokens, and session ids are
//! never exported. PR metadata preserves repo/commit/diff/reviewer/CI/license as
//! `sha256` anchors without copying private tokens.
pub mod approval;
pub mod pr_metadata;
pub mod privacy;
pub mod review;
