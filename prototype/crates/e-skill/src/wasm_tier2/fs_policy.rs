//! Filesystem deny-by-default policy.
//!
//! WASM sees only **declared virtual inputs**. There is no ambient cwd, home,
//! SSH, wallet, env, or repo traversal: every undeclared read denies, every
//! write denies, and any traversal / absolute / `~` / non-ASCII path is
//! rejected by the reused [`crate::bundle::is_safe_bundle_path`] guard before
//! the allowlist is even consulted.
//!
//! This is a pure checking surface over a *declared input map* — it touches no
//! real filesystem (no `std::fs`), reads no cwd / home / env, and cannot follow
//! a symlink because there is no real path to follow: only the exact declared
//! virtual input names are readable. Reuses the
//! [`SkillRuntimePermission`] surface (only `FileRead` is ever eligible).

#![deny(missing_docs)]

use crate::bundle::is_safe_bundle_path;
use crate::capability_diff::SkillRuntimePermission;
use crate::wasm_tier2::WasmSandboxDecision;

/// Evaluate a filesystem access request against the declared virtual-input
/// allowlist. Deny-by-default:
///
/// - any `permission` other than [`SkillRuntimePermission::FileRead`] denies
///   (no host writes, no ambient non-file capability);
/// - any path that fails [`is_safe_bundle_path`] (cwd `.`, `..`, absolute,
///   `~`, non-ASCII look-alike, NUL/backslash/colon) denies;
/// - a path not exactly present in `declared_reads` denies;
/// - only an exactly-declared virtual input read reaches
///   [`WasmSandboxDecision::Allow`].
#[must_use]
pub fn evaluate_fs_access(
    declared_reads: &[&str],
    requested: &str,
    permission: SkillRuntimePermission,
) -> WasmSandboxDecision {
    if permission != SkillRuntimePermission::FileRead {
        return WasmSandboxDecision::Deny;
    }
    if !is_safe_bundle_path(requested) {
        return WasmSandboxDecision::Deny;
    }
    if declared_reads.contains(&requested) {
        WasmSandboxDecision::Allow
    } else {
        WasmSandboxDecision::Deny
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const DECLARED: &[&str] = &["input/sample.json", "fixtures/case_a.txt"];

    #[test]
    fn declared_fixture_read_accepted() {
        assert_eq!(
            evaluate_fs_access(
                DECLARED,
                "input/sample.json",
                SkillRuntimePermission::FileRead
            ),
            WasmSandboxDecision::Allow
        );
    }

    #[test]
    fn cwd_dot_path_denied() {
        assert_eq!(
            evaluate_fs_access(
                DECLARED,
                "./input/sample.json",
                SkillRuntimePermission::FileRead
            ),
            WasmSandboxDecision::Deny
        );
    }

    #[test]
    fn home_path_denied() {
        assert_eq!(
            evaluate_fs_access(DECLARED, "~/.ssh/id_rsa", SkillRuntimePermission::FileRead),
            WasmSandboxDecision::Deny
        );
        assert_eq!(
            evaluate_fs_access(
                DECLARED,
                "/Users/heoun/.ssh/id_rsa",
                SkillRuntimePermission::FileRead
            ),
            WasmSandboxDecision::Deny
        );
    }

    #[test]
    fn parent_traversal_denied() {
        assert_eq!(
            evaluate_fs_access(
                DECLARED,
                "../../etc/passwd",
                SkillRuntimePermission::FileRead
            ),
            WasmSandboxDecision::Deny
        );
    }

    #[test]
    fn undeclared_or_symlink_target_denied() {
        // There is no real filesystem to follow a symlink through; an
        // undeclared name (a symlink's target outside the sandbox) is simply
        // not in the declared input map, so it denies.
        assert_eq!(
            evaluate_fs_access(
                DECLARED,
                "input/evil_link",
                SkillRuntimePermission::FileRead
            ),
            WasmSandboxDecision::Deny
        );
    }

    #[test]
    fn write_denied_even_for_declared_path() {
        assert_eq!(
            evaluate_fs_access(
                DECLARED,
                "input/sample.json",
                SkillRuntimePermission::FileWrite
            ),
            WasmSandboxDecision::Deny
        );
    }

    #[test]
    fn non_file_permission_denied() {
        assert_eq!(
            evaluate_fs_access(
                DECLARED,
                "input/sample.json",
                SkillRuntimePermission::Network
            ),
            WasmSandboxDecision::Deny
        );
    }
}
