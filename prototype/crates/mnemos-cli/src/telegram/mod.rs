//! `sinabro telegram` — Stage G operational Telegram control surface
//! (G-WP-03 · #506-#508).
//!
//! Stage F (F-WP-06C, [`crate::commands::platform_telegram`]) minted the Telegram
//! platform spine: the authorization-only [`mnemos_j_ux::telegram`] gateway, the
//! platform-neutral [`crate::commands::platform_telegram::MessageEnvelope`], and
//! the [`crate::commands::platform_telegram::NotificationCenter`]. Stage G adds the
//! *operational* layer over that spine and never redefines it:
//!
//! - [`config`] (#506): the readiness view over Telegram secret references —
//!   bot token / chat id are [`crate::secrets::SecretRefView`] only, disabled by
//!   default, and the secret values are never loaded or printed.
//! - [`envelope`] (#507): the Telegram → [`crate::command::CommandEnvelope`]
//!   bridge proving channel parity (a verb is the same command from the CLI or
//!   from Telegram; only the [`crate::commands::platform_telegram::PlatformOrigin`]
//!   differs).
//! - [`notify_rules`] (#508): the operational notify-rule compiler that maps
//!   Stage-G status changes onto the canonical notification classes with dedupe,
//!   mute, and severity ordering (no noisy spam loop).
//!
//! - [`egress`] (#636): the bounded Bot-API egress transport — OFF by default
//!   (the `telegram-egress` cargo feature), triple-gated (live-send approved +
//!   same-message approval + Telegram-host allowlist + bot-token present), with
//!   the bot token held as a [`crate::secrets::SecretRefView`] whose value is
//!   loaded only at the TLS boundary. The default offline build compiles no
//!   transport and returns `TransportNotCompiled`.
//! - [`inbound`] (ENDGAME E4): the bounded Bot-API INBOUND transport (getUpdates
//!   long-poll) for remote-approve-while-away — OFF by default AND independent of
//!   `telegram-egress` (the new `telegram-inbound` cargo feature). Inbound bytes are
//!   UNTRUSTED: every field is length-bounded, the offset is monotone, and this
//!   module only RECEIVES + PARSES (auth + the unforgeable SI-3 mint are E4-2).
//!
//! No module here loads a secret value, signs a wallet transaction, or trains a
//! model (Stage G `G-G-NO-TRAINING-IN-G`); the ONLY live Bot-API transport is the
//! feature-gated, OFF-by-default, triple-gated [`egress`] path.

pub mod config;
pub mod egress;
pub mod envelope;
pub mod inbound;
pub mod inbound_auth;
pub mod notify_rules;
