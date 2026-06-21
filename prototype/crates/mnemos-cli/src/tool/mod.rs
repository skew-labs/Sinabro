//! `tool` — Stage G operational tool composition layer (G-WP-02, atom #503).
//!
//! Sits over the Stage F tool-adapter surface ([`crate::commands::tool`]) and the
//! budget gate ([`crate::commands::budget`]), bridging a normalized
//! [`crate::commands::tool::ToolCallView`] to the shared token/cost/latency
//! [`crate::commands::budget::BudgetCap`] so every tool call shares one capability
//! diff, sandbox tier, budget, and approval state. Pure projections only — no
//! tool is executed here (the latency / no-live law).

pub mod budget_bridge;
pub mod web_status;
