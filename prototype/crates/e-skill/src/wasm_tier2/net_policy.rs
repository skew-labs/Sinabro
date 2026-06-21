//! `mnemos-e-skill::wasm_tier2::net_policy` — atom #260 · D.1.4 — network
//! deny-by-default policy.
//!
//! **Try-before-use has no network, ever.** Installed-runtime network access
//! requires both the [`SkillRuntimePermission::Network`] permission and an
//! explicitly allowlisted destination *class*; raw IPs, localhost / loopback,
//! and any bare host not on the allowlist deny. This module performs no live
//! network action — it only classifies a declared destination string.
//!
//! Reuses the #244 [`SkillRuntimePermission`] surface.

#![deny(missing_docs)]

use crate::capability_diff::SkillRuntimePermission;
use crate::wasm_tier2::WasmSandboxDecision;

/// The run context a network request is evaluated under.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NetRunMode {
    /// A dry-run trial — network is denied unconditionally.
    TryBeforeUse,
    /// An installed run — network is allowed only to an allowlisted class.
    Installed,
}

/// `true` for a destination that can never be an allowlisted *class*: a raw
/// IPv4/IPv6 literal, a port-bearing or IPv6 colon form, localhost / loopback /
/// wildcard, or an empty / non-ASCII string. These deny even under an installed
/// run regardless of the allowlist.
#[must_use]
fn is_unsafe_destination(dest: &str) -> bool {
    if dest.is_empty() || !dest.is_ascii() {
        return true;
    }
    // Colon ⇒ IPv6 literal or `host:port` — never a destination class.
    if dest.contains(':') {
        return true;
    }
    // All-digits-and-dots ⇒ a raw IPv4 literal (e.g. `203.0.113.5`).
    if dest.chars().all(|c| c.is_ascii_digit() || c == '.') {
        return true;
    }
    // Loopback / wildcard hostnames.
    matches!(dest, "localhost" | "ip6-localhost" | "broadcasthost")
}

/// Evaluate a network access request. Deny-by-default:
///
/// - any `permission` other than [`SkillRuntimePermission::Network`] denies;
/// - [`NetRunMode::TryBeforeUse`] denies unconditionally (no trial network);
/// - an [`is_unsafe_destination`] (raw IP, localhost, port/IPv6 form) denies;
/// - a destination not exactly present in `allowlist` denies;
/// - only an allowlisted destination class under [`NetRunMode::Installed`]
///   reaches [`WasmSandboxDecision::Allow`].
#[must_use]
pub fn evaluate_net_access(
    allowlist: &[&str],
    destination: &str,
    permission: SkillRuntimePermission,
    mode: NetRunMode,
) -> WasmSandboxDecision {
    if permission != SkillRuntimePermission::Network {
        return WasmSandboxDecision::Deny;
    }
    if matches!(mode, NetRunMode::TryBeforeUse) {
        return WasmSandboxDecision::Deny;
    }
    if is_unsafe_destination(destination) {
        return WasmSandboxDecision::Deny;
    }
    if allowlist.contains(&destination) {
        WasmSandboxDecision::Allow
    } else {
        WasmSandboxDecision::Deny
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ALLOW: &[&str] = &["api.fixture.test"];

    #[test]
    fn allowlisted_destination_accepted_under_installed_only() {
        assert_eq!(
            evaluate_net_access(
                ALLOW,
                "api.fixture.test",
                SkillRuntimePermission::Network,
                NetRunMode::Installed
            ),
            WasmSandboxDecision::Allow
        );
        // The very same destination is denied during a trial.
        assert_eq!(
            evaluate_net_access(
                ALLOW,
                "api.fixture.test",
                SkillRuntimePermission::Network,
                NetRunMode::TryBeforeUse
            ),
            WasmSandboxDecision::Deny
        );
    }

    #[test]
    fn dns_host_not_on_allowlist_denied() {
        assert_eq!(
            evaluate_net_access(
                ALLOW,
                "example.com",
                SkillRuntimePermission::Network,
                NetRunMode::Installed
            ),
            WasmSandboxDecision::Deny
        );
    }

    #[test]
    fn raw_ip_denied() {
        assert_eq!(
            evaluate_net_access(
                &["203.0.113.5"],
                "203.0.113.5",
                SkillRuntimePermission::Network,
                NetRunMode::Installed
            ),
            WasmSandboxDecision::Deny
        );
    }

    #[test]
    fn localhost_denied() {
        for host in ["localhost", "127.0.0.1", "::1", "0.0.0.0"] {
            assert_eq!(
                evaluate_net_access(
                    &[host],
                    host,
                    SkillRuntimePermission::Network,
                    NetRunMode::Installed
                ),
                WasmSandboxDecision::Deny,
                "{host} must deny"
            );
        }
    }

    #[test]
    fn non_network_permission_denied() {
        assert_eq!(
            evaluate_net_access(
                ALLOW,
                "api.fixture.test",
                SkillRuntimePermission::FileRead,
                NetRunMode::Installed
            ),
            WasmSandboxDecision::Deny
        );
    }
}
