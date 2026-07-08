//! Guided setup wizard.
//!
//! `sinabro setup` configures provider, memory-owner identity, Telegram, privacy,
//! and a first dry-run without requiring live secrets. The wizard never accepts a
//! seed phrase: memory-owner identity is established via wallet connect, zkLogin,
//! passkey, or a local encrypted keystore only. Learning defaults to off.

use crate::config::LearningControlView;

/// The ordered setup steps.
#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SetupStep {
    /// Configure an LLM provider (reference only).
    Provider = 1,
    /// Establish the memory-owner identity.
    MemoryOwner = 2,
    /// Optionally bind a Telegram channel.
    Telegram = 3,
    /// Set privacy / learning defaults.
    Privacy = 4,
    /// Run a first offline dry-run.
    FirstDryRun = 5,
}

/// The ordered list of setup steps.
pub const STEPS: [SetupStep; 5] = [
    SetupStep::Provider,
    SetupStep::MemoryOwner,
    SetupStep::Telegram,
    SetupStep::Privacy,
    SetupStep::FirstDryRun,
];

/// How memory-owner identity is established. A raw seed phrase is intentionally
/// **not** an option.
#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MemoryOwnerMethod {
    /// Connect an external wallet.
    WalletConnect = 1,
    /// zkLogin.
    ZkLogin = 2,
    /// Passkey.
    Passkey = 3,
    /// Local encrypted keystore.
    LocalEncryptedKeystore = 4,
}

/// The plan produced by the wizard (no live action is taken by the wizard).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SetupPlan {
    /// Whether a provider reference was configured.
    pub provider_configured: bool,
    /// Chosen memory-owner method.
    pub owner_method: MemoryOwnerMethod,
    /// Whether a Telegram channel was bound.
    pub telegram_bound: bool,
    /// Resolved learning controls (default off).
    pub learning: LearningControlView,
    /// Whether the first dry-run is ready to launch.
    pub first_dry_run_ready: bool,
}

impl Default for SetupPlan {
    fn default() -> Self {
        Self {
            provider_configured: false,
            owner_method: MemoryOwnerMethod::LocalEncryptedKeystore,
            telegram_bound: false,
            learning: LearningControlView::default(),
            first_dry_run_ready: false,
        }
    }
}

/// Whether `input` looks like a BIP39-style seed phrase that must be rejected
/// (>=12 lowercase alphabetic words). Memory-owner identity never accepts one.
#[must_use]
pub fn looks_like_seed_phrase(input: &str) -> bool {
    let words: Vec<&str> = input.split_whitespace().collect();
    words.len() >= 12
        && words
            .iter()
            .all(|w| !w.is_empty() && w.chars().all(|c| c.is_ascii_lowercase()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{DataEgressMode, LearningMode};

    #[test]
    fn all_five_steps_present_in_order() {
        assert_eq!(STEPS.len(), 5);
        assert_eq!(STEPS[0], SetupStep::Provider);
        assert_eq!(STEPS[4], SetupStep::FirstDryRun);
    }

    #[test]
    fn default_plan_is_learning_off_and_local_owner() {
        let p = SetupPlan::default();
        assert_eq!(p.learning.mode, LearningMode::Off);
        assert_eq!(p.learning.egress, DataEgressMode::None);
        assert_eq!(p.owner_method, MemoryOwnerMethod::LocalEncryptedKeystore);
        assert!(!p.first_dry_run_ready);
    }

    #[test]
    fn seed_phrase_input_is_rejected() {
        let seed = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        assert!(looks_like_seed_phrase(seed));
        assert!(!looks_like_seed_phrase("env:ANTHROPIC_API_KEY"));
        assert!(!looks_like_seed_phrase("wallet-connect"));
    }
}
