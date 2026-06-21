//! [6] Settings-sync (A⑥) — portable config across machines via an AEAD blob on
//! Walrus. The cross-Cursor "Settings Sync" reframed onto sinabro's physics: the
//! config is serialized + secret-screened (reuse E11-4 `serialize_config`), sealed
//! with the LOCAL AEAD key (the E14-W2 substrate), PUT to the Walrus testnet
//! aggregator (ciphertext only — secret-zero), and pulled + decrypted + re-validated +
//! applied on another machine.
//!
//! # The wall
//!
//! * The plaintext config NEVER leaves the box — only AEAD ciphertext is published
//!   (`PublishPayloadClass::EncryptedUserMemory`, the E14-W policy). The 32-byte key
//!   (`<data_dir>/memory.key`) stays local; a fetched blob is opaque without it.
//! * [`SETTINGS_SYNC_AAD`] is DISTINCT from the memory record / index AADs, so a
//!   settings blob can never be opened as a `.mc` record (or vice-versa) — the AEAD
//!   tag fails.
//! * [`validate_and_normalize`] re-runs the E11-4 secret-screen + validation on BOTH
//!   the push (before seal) and the pull (before apply) — a secret-shaped value is
//!   never synced, and a tampered/foreign blob that somehow decrypts to an invalid
//!   config is rejected (fail-closed) before it overwrites the local config.
//! * custody/funds/wallet/chain-write are HARD-LOCKED (PD-6): the config schema
//!   carries no wallet/funds field, and a Walrus testnet PUT needs no wallet/funds.
//!
//! Cross-machine key: like all E14-W2 Walrus memory, the seal uses the per-machine
//! key (`memory.key`); restoring on a fresh machine needs that key present (the owner
//! provisions it, exactly as for memory restore). A passphrase-derived sync key is a
//! follow-on; the per-machine key keeps settings-sync consistent with the rest of the
//! Walrus substrate.

/// The settings-sync AEAD associated data (DISTINCT from the memory record / index
/// AADs — a settings blob and a memory blob are NOT interchangeable; the tag binds it).
pub const SETTINGS_SYNC_AAD: &[u8] = b"sinabro.settings.v1";

/// Validate + normalize a config TOML through the E11-4 pipeline: parse it
/// (`parse_layer`, which validates the schema) and re-serialize it (`serialize_config`,
/// which re-runs the secret-screen and drops secret-shaped values). Returns the
/// canonical, secret-screened TOML, or `None` (fail-closed) if the config is invalid or
/// could not be normalized. Used on BOTH ends — before a push seal and before a pull
/// apply — so a secret-shaped or malformed config never crosses the sync boundary.
#[must_use]
pub fn validate_and_normalize(config_toml: &str) -> Option<String> {
    let cfg = crate::config::parse_layer(config_toml).ok()?;
    crate::config::serialize_config(&cfg).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn aad_is_distinct_from_the_walrus_index_aad() {
        // A settings blob must never be openable as a memory index blob.
        assert_ne!(SETTINGS_SYNC_AAD, crate::memory_walrus::WALRUS_INDEX_AAD);
        assert_eq!(SETTINGS_SYNC_AAD, b"sinabro.settings.v1");
    }

    #[test]
    fn validate_and_normalize_round_trips_a_valid_config() {
        // A benign config normalizes + re-parses to an equal config.
        let toml = "profile = \"safe-default\"\nlearning_mode = \"off\"\n";
        let normalized = validate_and_normalize(toml).expect("valid config normalizes");
        // the normalized form is itself valid (idempotent through the pipeline).
        let again = validate_and_normalize(&normalized).expect("re-normalizes");
        assert_eq!(normalized, again);
        // a known key survives the round-trip.
        assert!(normalized.contains("profile"));
    }

    #[test]
    fn validate_and_normalize_refuses_a_secret_shaped_value() {
        // A secret-shaped endpoint must be DROPPED by the secret-screen (serialize_config
        // refuses it) ⇒ None ⇒ it never crosses the sync boundary.
        let toml = "web3_rpc_endpoint = \"https://rpc.example/?k=${RPC_SECRET_KEY}\"\n";
        assert!(
            validate_and_normalize(toml).is_none(),
            "a secret-shaped value must not be syncable"
        );
    }

    #[test]
    fn validate_and_normalize_refuses_an_invalid_config() {
        // An unknown profile is a schema error ⇒ fail-closed None (never applied).
        let toml = "profile = \"not-a-real-profile\"\n";
        assert!(validate_and_normalize(toml).is_none());
        // outright garbage is also fail-closed.
        assert!(validate_and_normalize("\u{0}\u{1}not toml at all = =").is_none());
    }
}
