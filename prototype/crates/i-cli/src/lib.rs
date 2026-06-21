//! `mnemos-i-cli` — CLI-first skill catalog / card data contract surface.
//!
//! Phase 0 workspace skeleton (atom #1 · A.0.1); first real content added by
//! atom #305 · D.3.9. Stage D defines a **CLI-first, no-commerce** skill
//! surface: `search` / `inspect` / `recommend` / `use` / `install` / `enable` /
//! `disable` / `update` / `remove` / `fork` / `publish` / `eval` are all
//! initiated from the CLI or by an agent recommendation — never through a
//! web-market checkout. There is no buy / sell / payment / refund / revenue
//! path; `use` / `install` / `remove` require explicit user confirmation.
#![deny(missing_docs)]

pub mod skill_card_contract;

#[doc(no_inline)]
pub use skill_card_contract::{SkillCardContract, SkillCliCommand};
