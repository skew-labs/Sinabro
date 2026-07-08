//! MURPHY failure-attempt tree.
//!
//! [`schema`] defines the node/tree types and the `FailureKind` taxonomy;
//! [`build`] turns a `RepairTrace` into a credited node chain. Failed
//! attempts point to later verified successes; credit flows back only when a
//! verified success and a privacy pass both hold.
pub mod build;
pub mod schema;
