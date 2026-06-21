//! Operational Telegram config view (atom #506 · G.2.0).
//!
//! The Telegram surface is **disabled by default**. Its bot token and chat id are
//! held as secret *references* only ([`crate::secrets::SecretRefView`]): the value
//! is never loaded, cloned, `Debug`-printed, or networked (`G-G-SECRET-ZERO`). A
//! raw inline secret supplied where a reference is required is refused
//! fail-closed, and the status render shows only a redacted 16-hex name-hash
//! prefix plus the reference location — never a secret value.
//!
//! Reuse (no reinvention): the secret-reference classifier and the inline-secret
//! scanner are the canonical [`crate::secrets::classify_reference`] /
//! [`crate::secrets::scan_inline_secret`]; the red/yellow/green verdict is the
//! cockpit [`crate::tui::RenderTruth`]; the redacted prefix uses [`crate::hex32`].
//! This module performs no live action.

use crate::hex32;
use crate::secrets::{SecretLocation, SecretRefView, classify_reference, scan_inline_secret};
use crate::tui::RenderTruth;

/// First 16 hex characters of a 32-byte hash — a redacted, display-only prefix
/// (mirrors the F `platform_telegram` convention; the full key is never shown).
#[must_use]
fn redact16(bytes: &[u8; 32]) -> String {
    hex32(bytes).chars().take(16).collect()
}

/// The setup readiness of the Telegram surface.
#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TelegramSetupStatus {
    /// Disabled by default — no setup attempted.
    Disabled = 1,
    /// Enabled, but a required secret reference is missing.
    NeedsSetup = 2,
    /// Enabled and both the token + chat-id references resolve.
    Ready = 3,
}

impl TelegramSetupStatus {
    /// The stable `u8` discriminant.
    #[must_use]
    pub const fn as_u8(self) -> u8 {
        self as u8
    }

    /// The cockpit render truth: `Ready` is `Green`; `NeedsSetup` is `Yellow`;
    /// a `Disabled` (never-configured) surface is `Unknown`, never a false green.
    #[must_use]
    pub const fn render_truth(self) -> RenderTruth {
        match self {
            Self::Ready => RenderTruth::Green,
            Self::NeedsSetup => RenderTruth::Yellow,
            Self::Disabled => RenderTruth::Unknown,
        }
    }
}

/// Why a Telegram config input was refused (fail-closed).
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum TelegramConfigReject {
    /// A raw inline secret was supplied where only a `scheme:NAME` reference is
    /// allowed (e.g. a bare bot token instead of `env:TELEGRAM_BOT_TOKEN`).
    #[error("telegram secret must be a reference, not inline")]
    InlineSecret,
}

/// Whether `s` is a raw inline secret rather than a scheme reference. A value is
/// inline if the a-core scanner flags it, or if it is non-empty yet does not
/// classify to a recognized secret location (i.e. it is not a `scheme:NAME`
/// reference). An empty string is the "unset" case, not an inline secret.
#[must_use]
fn is_inline_secret(s: &str) -> bool {
    if scan_inline_secret(s) {
        return true;
    }
    !s.is_empty()
        && matches!(
            classify_reference("ref", s).location,
            SecretLocation::Missing
        )
}

/// The Telegram config view: secret *references* only (the values are never
/// loaded) plus the enabled flag. Disabled by default.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TelegramConfigView {
    /// Reference to the bot-token secret (the value is never loaded).
    pub bot_token_ref: SecretRefView,
    /// Reference to the chat-id secret (the value is never loaded).
    pub chat_id_ref: SecretRefView,
    /// Whether the Telegram surface is enabled. Default `false`.
    pub enabled: bool,
}

impl TelegramConfigView {
    /// A disabled config with no references resolved (the default state).
    #[must_use]
    pub fn disabled() -> Self {
        Self {
            bot_token_ref: classify_reference("telegram_bot_token", ""),
            chat_id_ref: classify_reference("telegram_chat_id", ""),
            enabled: false,
        }
    }

    /// Build a config from secret *reference strings* (e.g.
    /// `env:TELEGRAM_BOT_TOKEN`). Fails closed if either input is a raw inline
    /// secret rather than a reference. An empty reference is allowed (it resolves
    /// to [`SecretLocation::Missing`] and yields [`TelegramSetupStatus::NeedsSetup`]
    /// when enabled).
    pub fn from_references(
        token_ref: &str,
        chat_id_ref: &str,
        enabled: bool,
    ) -> Result<Self, TelegramConfigReject> {
        if is_inline_secret(token_ref) || is_inline_secret(chat_id_ref) {
            return Err(TelegramConfigReject::InlineSecret);
        }
        Ok(Self {
            bot_token_ref: classify_reference("telegram_bot_token", token_ref),
            chat_id_ref: classify_reference("telegram_chat_id", chat_id_ref),
            enabled,
        })
    }

    /// Whether both required secret references resolve to a real location.
    #[must_use]
    pub fn references_present(&self) -> bool {
        !matches!(self.bot_token_ref.location, SecretLocation::Missing)
            && !matches!(self.chat_id_ref.location, SecretLocation::Missing)
    }

    /// The setup status (disabled / needs-setup / ready).
    #[must_use]
    pub fn status(&self) -> TelegramSetupStatus {
        if !self.enabled {
            TelegramSetupStatus::Disabled
        } else if self.references_present() {
            TelegramSetupStatus::Ready
        } else {
            TelegramSetupStatus::NeedsSetup
        }
    }

    /// Whether the surface is ready to use (enabled and both references present).
    #[must_use]
    pub fn is_ready(&self) -> bool {
        matches!(self.status(), TelegramSetupStatus::Ready)
    }

    /// Whether the config holds only references and never a loaded value. A
    /// structural invariant of [`SecretRefView`]; always `true`.
    #[must_use]
    pub const fn value_never_loaded(&self) -> bool {
        self.bot_token_ref.value_never_loaded && self.chat_id_ref.value_never_loaded
    }

    /// Redacted, colorless status lines bounded by `rows` (hot path). Renders only
    /// the 16-hex name-hash prefix, the reference location, and readiness — never a
    /// secret value (the values are never loaded).
    #[must_use]
    pub fn render(&self, rows: u16) -> Vec<String> {
        let lines = vec![
            format!("enabled={}", self.enabled),
            format!("status_u8={}", self.status().as_u8()),
            format!(
                "token_ref_name={}",
                redact16(&self.bot_token_ref.name_hash_32)
            ),
            format!("token_location_u8={}", self.bot_token_ref.location as u8),
            format!(
                "chat_id_ref_name={}",
                redact16(&self.chat_id_ref.name_hash_32)
            ),
            format!("chat_id_location_u8={}", self.chat_id_ref.location as u8),
            format!("value_never_loaded={}", self.value_never_loaded()),
            format!("truth_u8={}", self.status().render_truth() as u8),
        ];
        lines.into_iter().take(rows as usize).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::repl::latency::p95_ms;

    const TOKEN_REF: &str = "env:TELEGRAM_BOT_TOKEN";
    const CHAT_REF: &str = "keychain:TELEGRAM_CHAT_ID";

    #[test]
    fn disabled_default() {
        let c = TelegramConfigView::disabled();
        assert!(!c.enabled);
        assert_eq!(c.status(), TelegramSetupStatus::Disabled);
        assert!(!c.is_ready());
        assert!(!c.references_present());
        assert_eq!(c.status().render_truth(), RenderTruth::Unknown);
    }

    #[test]
    fn secret_ref_render_never_shows_value() {
        let r = TelegramConfigView::from_references(TOKEN_REF, CHAT_REF, true);
        assert!(r.is_ok());
        if let Ok(c) = r {
            assert!(c.is_ready());
            assert_eq!(c.status(), TelegramSetupStatus::Ready);
            assert!(c.value_never_loaded());
            // The render never contains the raw reference names or any value.
            for line in c.render(64) {
                assert!(!line.contains("TELEGRAM_BOT_TOKEN"));
                assert!(!line.contains("TELEGRAM_CHAT_ID"));
            }
        }
    }

    #[test]
    fn raw_token_deny() {
        // A bare bot token (no scheme) is a raw inline secret — refused.
        let r =
            TelegramConfigView::from_references("9876543210:AArawBotTokenValue", CHAT_REF, true);
        assert_eq!(r, Err(TelegramConfigReject::InlineSecret));
        // A raw chat id is refused too.
        let r2 = TelegramConfigView::from_references(TOKEN_REF, "rawchatid12345", true);
        assert_eq!(r2, Err(TelegramConfigReject::InlineSecret));
    }

    #[test]
    fn chat_id_redaction_is_16_hex() {
        let r = TelegramConfigView::from_references(TOKEN_REF, CHAT_REF, true);
        assert!(r.is_ok());
        if let Ok(c) = r {
            let rendered = c.render(64);
            let chat_line = rendered.iter().find(|l| l.starts_with("chat_id_ref_name="));
            assert!(chat_line.is_some());
            if let Some(line) = chat_line {
                let value = line.trim_start_matches("chat_id_ref_name=");
                assert_eq!(value.len(), 16);
                assert!(
                    value
                        .chars()
                        .all(|ch| ch.is_ascii_hexdigit() && !ch.is_ascii_uppercase())
                );
            }
        }
    }

    #[test]
    fn setup_status_transitions() {
        // Disabled by default.
        assert_eq!(
            TelegramConfigView::disabled().status(),
            TelegramSetupStatus::Disabled
        );
        // Enabled but unset references -> needs setup.
        let needs = TelegramConfigView::from_references("", "", true);
        assert!(needs.is_ok());
        if let Ok(c) = needs {
            assert_eq!(c.status(), TelegramSetupStatus::NeedsSetup);
            assert!(!c.is_ready());
        }
        // Enabled + both references -> ready.
        let ready = TelegramConfigView::from_references(TOKEN_REF, CHAT_REF, true);
        assert!(ready.is_ok());
        if let Ok(c) = ready {
            assert_eq!(c.status(), TelegramSetupStatus::Ready);
        }
    }

    #[test]
    fn render_p95_within_50ms() {
        let r = TelegramConfigView::from_references(TOKEN_REF, CHAT_REF, true);
        assert!(r.is_ok());
        if let Ok(c) = r {
            let mut samples = Vec::with_capacity(256);
            for _ in 0..256 {
                let t = std::time::Instant::now();
                let lines = c.render(32);
                std::hint::black_box(&lines);
                samples.push(t.elapsed().as_nanos() as u64);
            }
            let p95 = p95_ms(&samples) / 1_000_000;
            assert!(p95 <= 50, "telegram config render p95 {p95}ms exceeds 50ms");
        }
    }
}
