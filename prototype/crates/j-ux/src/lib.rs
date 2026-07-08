//! `mnemos-j-ux` — Telegram gateway, progressive edit, slash commands and UX redaction.
//!
//! The crate is built up module by module. Modules already filled:
//!
//! - [`telegram`][]: Telegram gateway authorization spine.
//!   Compile-time `&'static` allowlist over [`telegram::TelegramUserId`]; the
//!   gateway carries no token field and the rejection variant carries no
//!   user id, so neither runtime additions nor an information leak through
//!   the error channel are possible.
//! - [`stream_edit`][]: progressive edit throttle decision.
//!   Pure-`const fn` predicate [`stream_edit::should_flush_edit`] over a
//!   `Copy` [`stream_edit::ProgressiveEditor`] config; no I/O, no
//!   allocations, no new Cargo.toml dependency. The actual
//!   `editMessageText` transport is wired by a later module.
//! - [`slash`][]: control command grammar. Fixed 4-variant
//!   [`slash::SlashCommand`] enum + pure [`slash::parse_slash`] predicate
//!   (`&str → Option<SlashCommand>`); no I/O, no side effects, no
//!   supervisor / cost-ledger / Telegram wiring (a later stage promotes
//!   `/kill` and `/budget cap` onto the express control rail). The
//!   `/skill <id>` payload reuses [`mnemos_e_skill::manifest::SkillId`]
//!   verbatim — the only cross-crate import this module adds.
//! - [`redact`][]: outbound redaction forwarder. A
//!   `const fn` [`redact::redact_outbound`] that re-uses the
//!   `mnemos_a_core::logging::redact_for_log` kernel verbatim, so the
//!   Telegram `sendMessage` / `editMessageText` and CLI stdout
//!   surfaces apply the same canary-free redaction discipline as the
//!   structured-log path. No transport wiring here — only the
//!   projection that the transport layer must call before emitting
//!   bytes. Adds a second path-dep on `mnemos-a-core`; 0 new
//!   transitive crates (a-core was already in `Cargo.lock` via the
//!   e-skill path-dep, which itself depends on a-core).
#![deny(missing_docs)]

pub mod redact;
pub mod slash;
pub mod stage_c_smoke;
pub mod stream_edit;
pub mod telegram;

#[doc(no_inline)]
pub use redact::redact_outbound;
#[doc(no_inline)]
pub use slash::{SlashCommand, parse_slash};
#[doc(no_inline)]
pub use stream_edit::{ProgressiveEditor, should_flush_edit};
#[doc(no_inline)]
pub use telegram::{Allowlist, GatewayError, TelegramGateway, TelegramUserId};
