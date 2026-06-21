//! MURPHY failure-attempt tree (atoms #386-#387 · E.3.0-E.3.1).
//!
//! [`schema`] defines the node/tree types and the §4.2 `FailureKind` taxonomy;
//! [`build`] turns a §4.2 `RepairTrace` into a credited node chain. Failed
//! attempts point to later verified successes; credit flows back only when a
//! verified success and a privacy pass both hold.
pub mod build;
pub mod schema;
