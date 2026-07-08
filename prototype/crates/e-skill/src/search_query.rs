//! Skill search query grammar.
//!
//! Raw user text becomes a hashed intent plus parsed filters (a
//! [`SkillSearchQuery`]). The grammar is offline and panic-free on arbitrary
//! input: free-text words fold into `intent_hash_32`, and a small set of
//! `key:value` filter tokens populate the domain hash, the permission ceiling,
//! and the chain-env hash. An unrecognized filter key, or an unknown permission
//! name, is a typed [`SearchParseError`] — never a panic.
//!
//! `required_permissions_mask_u64` is a **permission ceiling**: it starts with
//! all ten runtime permissions allowed, and a `deny:<perm,...>` token clears
//! bits. [`SkillSearchQuery::matches`] then keeps only entries whose added
//! permissions stay within the ceiling, so `deny:wallet` filters out every
//! wallet-using skill. (Chain-env filtering against a skill's full
//! `SkillCompatibility` happens in the compatibility solver; the index entry alone does
//! not carry the chain-env hash, so the query's `chain_env_hash_32` is a
//! ranking/context hint here.)

#![deny(missing_docs)]

extern crate alloc;

use alloc::vec::Vec;

use crate::capability_diff::SkillRuntimePermission;
use crate::catalog_index::SkillCatalogIndexEntry;

/// Domain tags for the three query hashes (distinct so a domain word and an
/// intent word never collide).
const DOMAIN_SEARCH_INTENT: &[u8] = b"mnemos.d.search_intent.v1";
const DOMAIN_SEARCH_DOMAIN: &[u8] = b"mnemos.d.search_domain.v1";
const DOMAIN_SEARCH_ENV: &[u8] = b"mnemos.d.search_env.v1";

/// All ten runtime-permission bits set — the default permission ceiling
/// (derived from the enum so it can never drift from the variant set).
const ALL_PERMISSIONS_MASK: u64 = SkillRuntimePermission::FileRead.mask_bit()
    | SkillRuntimePermission::FileWrite.mask_bit()
    | SkillRuntimePermission::Network.mask_bit()
    | SkillRuntimePermission::Wallet.mask_bit()
    | SkillRuntimePermission::Chain.mask_bit()
    | SkillRuntimePermission::Secret.mask_bit()
    | SkillRuntimePermission::MemoryRead.mask_bit()
    | SkillRuntimePermission::MemoryWrite.mask_bit()
    | SkillRuntimePermission::AnchorChunk.mask_bit()
    | SkillRuntimePermission::ToolInvoke.mask_bit();

/// Why a raw search string failed to parse. Returned, never panicked.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum SearchParseError {
    /// A `key:value` token used a key the grammar does not recognize.
    UnknownFilter,
    /// A `perm:` / `deny:` token named a permission outside the ten runtime
    /// permissions.
    UnknownPermission,
    /// A recognized key (`security` / `mode`) was given a value outside its
    /// allowed set.
    UnknownValue,
}

impl SearchParseError {
    /// Stable, leak-free class label.
    #[must_use]
    pub const fn class_label(&self) -> &'static str {
        match self {
            Self::UnknownFilter => "search_query.unknown_filter",
            Self::UnknownPermission => "search_query.unknown_permission",
            Self::UnknownValue => "search_query.unknown_value",
        }
    }
}

/// A parsed skill search query.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub struct SkillSearchQuery {
    /// Hash of the free-text intent plus the recognized scalar filters.
    pub intent_hash_32: [u8; 32],
    /// Hash of the `domain:` filter (zero when absent).
    pub domain_hash_32: [u8; 32],
    /// Permission ceiling: added permissions of a matching skill must be a
    /// subset of this mask (default: all ten permissions; `deny:` narrows it).
    pub required_permissions_mask_u64: u64,
    /// Hash of the `env:` chain-env filter (zero when absent; a ranking hint).
    pub chain_env_hash_32: [u8; 32],
}

/// Map a lowercase permission name to its runtime-permission bit.
fn permission_bit(name: &str) -> Result<u64, SearchParseError> {
    let permission = match name {
        "fileread" => SkillRuntimePermission::FileRead,
        "filewrite" => SkillRuntimePermission::FileWrite,
        "network" => SkillRuntimePermission::Network,
        "wallet" => SkillRuntimePermission::Wallet,
        "chain" => SkillRuntimePermission::Chain,
        "secret" => SkillRuntimePermission::Secret,
        "memoryread" => SkillRuntimePermission::MemoryRead,
        "memorywrite" => SkillRuntimePermission::MemoryWrite,
        "anchorchunk" => SkillRuntimePermission::AnchorChunk,
        "toolinvoke" => SkillRuntimePermission::ToolInvoke,
        _ => return Err(SearchParseError::UnknownPermission),
    };
    Ok(permission.mask_bit())
}

/// Hash a normalized string under a domain tag (single variable tail after a
/// fixed-length domain tag — unambiguous framing).
fn hash_text(domain: &[u8], text: &str) -> [u8; 32] {
    crate::package::blake2b_256(&[domain, text.as_bytes()])
}

impl SkillSearchQuery {
    /// Parse a raw search string into a query. Panic-free on any input.
    pub fn parse(raw: &str) -> Result<Self, SearchParseError> {
        let mut intent_parts: Vec<&str> = Vec::new();
        let mut domain: &str = "";
        let mut env: &str = "";
        let mut allowed_mask = ALL_PERMISSIONS_MASK;

        for token in raw.split_whitespace() {
            match token.split_once(':') {
                Some((key, value)) => match key {
                    "domain" => domain = value,
                    "env" => env = value,
                    "deny" => {
                        for name in value.split(',').filter(|s| !s.is_empty()) {
                            allowed_mask &= !permission_bit(name)?;
                        }
                    }
                    "perm" => {
                        // Validate the names; `perm:` does not widen the default
                        // (already all-allowed), it only rejects typos.
                        for name in value.split(',').filter(|s| !s.is_empty()) {
                            permission_bit(name)?;
                        }
                    }
                    "security" => {
                        if !matches!(value, "low" | "medium" | "high") {
                            return Err(SearchParseError::UnknownValue);
                        }
                        intent_parts.push(token);
                    }
                    "mode" => {
                        if !matches!(value, "offline" | "online") {
                            return Err(SearchParseError::UnknownValue);
                        }
                        intent_parts.push(token);
                    }
                    _ => return Err(SearchParseError::UnknownFilter),
                },
                None => intent_parts.push(token),
            }
        }

        let intent_text = intent_parts.join("\n");
        Ok(Self {
            intent_hash_32: hash_text(DOMAIN_SEARCH_INTENT, &intent_text),
            domain_hash_32: if domain.is_empty() {
                [0u8; 32]
            } else {
                hash_text(DOMAIN_SEARCH_DOMAIN, domain)
            },
            required_permissions_mask_u64: allowed_mask,
            chain_env_hash_32: if env.is_empty() {
                [0u8; 32]
            } else {
                hash_text(DOMAIN_SEARCH_ENV, env)
            },
        })
    }

    /// Whether a catalog entry passes the query's permission ceiling: the
    /// entry's added permissions must be a subset of the allowed mask.
    #[must_use]
    pub fn matches(&self, entry: &SkillCatalogIndexEntry) -> bool {
        entry.capability_diff.added_mask_u64 & !self.required_permissions_mask_u64 == 0
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use crate::capability_diff::CapabilityDiff;
    use crate::compat::{HostEnvironment, MnemosVersion};
    use crate::verify::sample_valid_package_toml;
    use alloc::vec;

    fn host() -> HostEnvironment {
        HostEnvironment {
            mnemos_version: MnemosVersion::new(0, 2, 0),
            chain_env_hash_32: [0xC0; 32],
            os_gpu_hash_32: [0x05; 32],
            toolchain_hash_32: [0x70; 32],
            model_provider_hash_32: [0x30; 32],
        }
    }

    fn entry_with_mask(mask: u64) -> SkillCatalogIndexEntry {
        let toml = sample_valid_package_toml();
        let mut e = SkillCatalogIndexEntry::from_package_toml(&toml, &host(), [0x99; 32], 0, 0, 0)
            .expect("index");
        e.capability_diff = CapabilityDiff::new(mask, 0, vec![]);
        e
    }

    #[test]
    fn free_text_intent_sui_gas_optimizer() {
        let q = SkillSearchQuery::parse("sui gas optimizer").expect("parse");
        assert_ne!(q.intent_hash_32, [0u8; 32]);
        // Same text -> same intent hash (deterministic).
        let q2 = SkillSearchQuery::parse("sui gas optimizer").expect("parse");
        assert_eq!(q.intent_hash_32, q2.intent_hash_32);
        // Default ceiling allows everything.
        assert_eq!(q.required_permissions_mask_u64, ALL_PERMISSIONS_MASK);
    }

    #[test]
    fn deny_wallet_perms() {
        let q = SkillSearchQuery::parse("optimizer deny:wallet").expect("parse");
        let wallet_skill = entry_with_mask(SkillRuntimePermission::Wallet.mask_bit());
        let read_skill = entry_with_mask(SkillRuntimePermission::MemoryRead.mask_bit());
        assert!(
            !q.matches(&wallet_skill),
            "wallet skill must be filtered out"
        );
        assert!(q.matches(&read_skill), "read-only skill stays");
    }

    #[test]
    fn security_high_recognized() {
        let q = SkillSearchQuery::parse("audit security:high").expect("parse");
        assert_ne!(q.intent_hash_32, [0u8; 32]);
    }

    #[test]
    fn offline_catalog_recognized() {
        let q = SkillSearchQuery::parse("gas mode:offline").expect("parse");
        assert_ne!(q.intent_hash_32, [0u8; 32]);
    }

    #[test]
    fn invalid_filter_reject() {
        assert_eq!(
            SkillSearchQuery::parse("price:cheap"),
            Err(SearchParseError::UnknownFilter)
        );
        assert_eq!(
            SkillSearchQuery::parse("deny:teleport"),
            Err(SearchParseError::UnknownPermission)
        );
        assert_eq!(
            SkillSearchQuery::parse("security:cosmic"),
            Err(SearchParseError::UnknownValue)
        );
    }

    #[test]
    fn no_panic_on_arbitrary_input() {
        // Adversarial / degenerate inputs must return, never panic.
        for raw in [
            "",
            ":",
            "::",
            "a:b:c",
            "   ",
            "deny:",
            "domain:",
            "🦀 perm:wallet",
        ] {
            let _ = SkillSearchQuery::parse(raw);
        }
    }
}
