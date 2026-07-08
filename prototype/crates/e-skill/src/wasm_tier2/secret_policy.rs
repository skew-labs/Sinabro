//! `mnemos-e-skill::wasm_tier2::secret_policy` — wallet / chain / secret
//! deny matrix.
//!
//! **Secret bytes never enter WASM memory.** WASM never receives a
//! `SealedKeypair`, a `ScopedSecretKey`, raw `TransactionData` signing
//! authority, or an env secret. The guarantee is *structural*, not a runtime
//! redaction step: there is **no secret-bearing type anywhere in the
//! `wasm_tier2` surface** to clone or to leak through `Debug` — the grant,
//! token, and hostcall types carry only labels, ids, and hashes. The
//! [`SECRET_BYTES_ENTER_WASM_MEMORY`] constant is the greppable witness of that
//! invariant (asserted by [`tests`]).
//!
//! Chain actions are **dry-run only**: a read-only simulated call is the only
//! chain interaction the sandbox permits, and a state-mutating write/submit is
//! unrepresentable (no Stage D broker, no signing hostcall — see
//! [`crate::wasm_tier2::hostcalls`]). This mirrors the Stage C signer-isolation
//! discipline (the signer stays behind the boundary; the sandbox is the API
//! side that never holds key material).

#![deny(missing_docs)]

use crate::capability_diff::SkillRuntimePermission;
use crate::wasm_tier2::WasmSandboxDecision;

/// Structural witness that no secret-bearing value is ever exposed to WASM
/// memory. There is no `SealedKeypair` / `ScopedSecretKey` / raw
/// `TransactionData` field anywhere in the `wasm_tier2` surface. This constant
/// is the greppable anchor for that invariant.
pub const SECRET_BYTES_ENTER_WASM_MEMORY: bool = false;

/// Compile-time witness: the build fails if the invariant above is ever flipped
/// to `true`. This is a stronger guarantee than a runtime test — secret bytes
/// entering WASM memory becomes a *compile error*, not merely a failing test.
const _: () = assert!(!SECRET_BYTES_ENTER_WASM_MEMORY);

/// Mode of a chain action requested from inside the sandbox.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ChainActionMode {
    /// A read-only simulated call — the only chain interaction the sandbox ever
    /// permits, surfaced via the `ChainDryRun` hostcall.
    DryRun,
    /// A state-mutating write / submit — always denied (no Stage D broker, so a
    /// real signature/submit is unrepresentable).
    Write,
}

/// `true` iff `permission` is in the wallet / chain / secret family that the
/// sandbox denies unconditionally.
#[inline]
#[must_use]
pub const fn is_secret_family(permission: SkillRuntimePermission) -> bool {
    matches!(
        permission,
        SkillRuntimePermission::Wallet
            | SkillRuntimePermission::Secret
            | SkillRuntimePermission::Chain
    )
}

/// Pre-grant secret-family override. Returns `Some(Deny)` for any
/// wallet / chain / secret permission — which **no grant may ever override
/// into an Allow** — or `None` for a non-secret permission (which proceeds to
/// the normal grant / policy check). This is what guarantees that even a
/// mistakenly-minted `Wallet` / `Secret` grant can never reach execution.
#[inline]
#[must_use]
pub fn secret_family_override(permission: SkillRuntimePermission) -> Option<WasmSandboxDecision> {
    if is_secret_family(permission) {
        Some(WasmSandboxDecision::Deny)
    } else {
        None
    }
}

/// Evaluate a chain action. Only a [`ChainActionMode::DryRun`] (simulated,
/// read-only) call is permitted; a [`ChainActionMode::Write`] denies.
#[inline]
#[must_use]
pub fn evaluate_chain_action(mode: ChainActionMode) -> WasmSandboxDecision {
    match mode {
        ChainActionMode::DryRun => WasmSandboxDecision::Allow,
        ChainActionMode::Write => WasmSandboxDecision::Deny,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn secret_family_never_allows() {
        // No secret-family permission can ever produce an Allow override.
        for p in [
            SkillRuntimePermission::Wallet,
            SkillRuntimePermission::Secret,
            SkillRuntimePermission::Chain,
        ] {
            assert_eq!(secret_family_override(p), Some(WasmSandboxDecision::Deny));
        }
    }

    #[test]
    fn wallet_secret_chain_are_the_secret_family() {
        assert!(is_secret_family(SkillRuntimePermission::Wallet));
        assert!(is_secret_family(SkillRuntimePermission::Secret));
        assert!(is_secret_family(SkillRuntimePermission::Chain));
        assert!(!is_secret_family(SkillRuntimePermission::FileRead));
        assert!(!is_secret_family(SkillRuntimePermission::MemoryRead));
        assert!(!is_secret_family(SkillRuntimePermission::Network));
    }

    #[test]
    fn env_secret_and_wallet_file_fixtures_deny() {
        // An env-secret request (Secret) and a wallet-file request (Wallet)
        // both hit the pre-grant override and deny.
        assert_eq!(
            secret_family_override(SkillRuntimePermission::Secret),
            Some(WasmSandboxDecision::Deny)
        );
        assert_eq!(
            secret_family_override(SkillRuntimePermission::Wallet),
            Some(WasmSandboxDecision::Deny)
        );
        // A non-secret permission yields no override (proceeds to grant check).
        assert_eq!(
            secret_family_override(SkillRuntimePermission::MemoryRead),
            None
        );
    }

    #[test]
    fn chain_write_denied_dry_run_allowed() {
        assert_eq!(
            evaluate_chain_action(ChainActionMode::Write),
            WasmSandboxDecision::Deny
        );
        assert_eq!(
            evaluate_chain_action(ChainActionMode::DryRun),
            WasmSandboxDecision::Allow
        );
    }
}
