//! Oracle test-loop — `sui move test` / `cargo test` as a sandboxed READ
//! capability.
//!
//! ## Thesis (verify-oracle ethos)
//!
//! NOT an interactive breakpoint debugger (off-thesis for an agent-first tool).
//! Instead: run the REAL test runner (`sui move test` for a Move package,
//! `cargo test` for a Cargo package) SANDBOXED (network kernel-DENIED) and surface
//! the GROUND-TRUTH pass/fail + the failure lines to the agent — which then
//! PROPOSE-EXECs a fix and re-runs the oracle. The agent reasons with the
//! compiler/test-runner's verdict, never a guess. Reuses the EXACT
//! [`run_in_sandbox`](crate::sandbox_exec::run_in_sandbox) discipline the LIVE
//! [`crate::code_oracle::sui_build_oracle`] already uses for `sui move build`.
//!
//! ## Security invariants
//!
//! * CAPABILITY = READ (free). A test run COMPILES + RUNS the package's tests, so
//!   it needs file-WRITE (build artifacts) but NO network ⇒
//!   [`SandboxTier::LocalWrite`](crate::commands::sandbox::SandboxTier) = write
//!   allowed, network kernel-DENIED (the load-bearing wall — a test never fetches;
//!   custody unreachable). fail-CLOSED if no kernel sandbox.
//! * FAIL-CLOSED: the package path MUST resolve UNDER the workspace root (no `..`
//!   escape) and contain a `Move.toml` (⇒ `sui move test`) or `Cargo.toml` (⇒
//!   `cargo test --offline`); ONLY those two runners — never an arbitrary command.
//! * REDACTION: the test output passes the `redact` wall; secret-shaped ⇒
//!   WITHHELD.
//! * CUSTODY untouched: no egress/mutate/custody capability, no chain RPC /
//!   socket (net kernel-DENIED); funds hard-locked.
//!
//! ## Reuse (no second spawn discipline)
//!
//! The run is [`run_in_sandbox(LocalWrite, …)`](crate::sandbox_exec::run_in_sandbox)
//! — the SAME proven env-scrub / wall-clock-timeout+reap / byte-cap / cwd path
//! `code_oracle` + `skill eval` use. ALWAYS compiled (no feature) — `sui`/`cargo`
//! are toolchain binaries; an absent binary honest-degrades.

use std::path::PathBuf;

use crate::commands::sandbox::SandboxTier;
use crate::exec_local::EXEC_STREAM_CAP_BYTES;
use crate::sandbox_exec::{SandboxRunDeny, run_in_sandbox};

/// Whole-run wall clock (compile + run the package's tests). Bounded so a hung /
/// looping test can never block the loop. Generous (a cold compile is slow).
const TEST_RUN_TIMEOUT_MS: u64 = 120_000;

/// Bound on the package-path argument (a path is short; refuse, never truncate).
const TEST_RUN_MAX_PKG_BYTES: usize = 512;

/// The detected package kind ⇒ which test runner.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum TestKind {
    /// A `Move.toml` package ⇒ `sui move test`.
    Move,
    /// A `Cargo.toml` package ⇒ `cargo test --offline`.
    Cargo,
}

/// Typed, data-free denial reasons for a test run.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TestRunDeny {
    /// The package path is empty / too long / contains whitespace (the sandbox
    /// splits the line on whitespace, so a whitespace path is unsafe).
    PkgUnsafe,
    /// The resolved package path escapes the workspace root (`..` traversal) — deny.
    PkgEscapesWorkspace,
    /// The path has neither a `Move.toml` nor a `Cargo.toml` (not a test package).
    NotAPackage,
    /// fail-CLOSED: no kernel sandbox on this host (a test is NEVER run unsandboxed).
    SandboxUnavailable,
    /// The test-runner binary (`sui` / `cargo`) was not found on `PATH`
    /// (honest-degrade, never fabricated).
    ToolUnavailable,
    /// The sandboxed runner could not be spawned / a pre-spawn wall fired.
    SpawnFailed,
}

impl TestRunDeny {
    /// Stable, allow-listed `class_label` (namespaced `test_run.*`).
    #[must_use]
    pub const fn class_label(self) -> &'static str {
        match self {
            Self::PkgUnsafe => "test_run.pkg.unsafe",
            Self::PkgEscapesWorkspace => "test_run.pkg.escapes_workspace",
            Self::NotAPackage => "test_run.pkg.not_a_package",
            Self::SandboxUnavailable => "test_run.sandbox.unavailable",
            Self::ToolUnavailable => "test_run.tool.unavailable",
            Self::SpawnFailed => "test_run.spawn_failed",
        }
    }
}

/// The chokepoint's verdict (mirror of [`crate::git::GitReadRender`]): the rendered
/// pass/fail + output (or the typed deny), whether it consumed a READ (a runner that
/// actually produced a verdict), and a stable class label.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TestRunRender {
    /// The rendered test verdict + bounded output (success) or the typed deny.
    pub rendered: String,
    /// `true` only when a real runner produced a verdict (consumes the loop's K-read
    /// budget); every deny / honest-degrade is `false`.
    pub consumed_read: bool,
    /// A stable ASCII class label (`test_run.*`).
    pub class_label: &'static str,
}

/// Resolve a bare binary name to an absolute path by scanning `PATH` (the honest
/// presence probe; `None` ⇒ absent ⇒ honest-degrade). Mirrors the sibling resolvers.
#[must_use]
fn resolve_on_path(bin: &str) -> Option<PathBuf> {
    let path = std::env::var_os("PATH")?;
    for dir in std::env::split_paths(&path) {
        let candidate = dir.join(bin);
        if candidate.is_file() {
            return Some(candidate);
        }
    }
    None
}

/// Resolve + validate the package path: relative to the canonical workspace root,
/// it must stay UNDER the workspace root (no `..` escape) and hold a `Move.toml`
/// (⇒ Move) or a `Cargo.toml` (⇒ Cargo). Returns the canonical package path + kind.
fn classify_pkg(pkg: &str) -> Result<(PathBuf, TestKind), TestRunDeny> {
    if pkg.is_empty() || pkg.len() > TEST_RUN_MAX_PKG_BYTES || pkg.split_whitespace().count() != 1 {
        return Err(TestRunDeny::PkgUnsafe);
    }
    let root = crate::file_context::workspace_root().unwrap_or_else(|| PathBuf::from("."));
    // Canonicalize the root (resolve symlinks, e.g. macOS /tmp -> /private/tmp) so the
    // under-root containment check + the sandbox both see the SAME path.
    let canon_root = std::fs::canonicalize(&root).unwrap_or(root);
    // The package path is taken RELATIVE to the workspace root (an absolute arg that
    // happens to be inside still canonicalizes under it; an outside/`..` path does not).
    let joined = canon_root.join(pkg);
    let Ok(canon_pkg) = std::fs::canonicalize(&joined) else {
        return Err(TestRunDeny::NotAPackage); // does not exist
    };
    if !canon_pkg.starts_with(&canon_root) {
        return Err(TestRunDeny::PkgEscapesWorkspace);
    }
    // A canonical path is whitespace-free here only if the repo layout is; re-check
    // (the sandbox line is whitespace-split — a space would mis-parse the argv).
    if canon_pkg.to_string_lossy().split_whitespace().count() != 1 {
        return Err(TestRunDeny::PkgUnsafe);
    }
    if canon_pkg.join("Move.toml").is_file() {
        Ok((canon_pkg, TestKind::Move))
    } else if canon_pkg.join("Cargo.toml").is_file() {
        Ok((canon_pkg, TestKind::Cargo))
    } else {
        Err(TestRunDeny::NotAPackage)
    }
}

/// The ONE test-run chokepoint shared by BOTH consumers (the loop tool + the dispatch
/// verb). Gate order: validate + classify the package (fail-closed; under-workspace,
/// Move/Cargo only) → resolve the runner binary → run it SANDBOXED under
/// `LocalWrite` (write-allowed, network kernel-DENIED) → redact the output → render
/// the pass/fail verdict. A test run is a free local READ (like `lsp diagnostics` /
/// `git status`), so it is NOT a high-significance audited action. custody/funds
/// untouched (net kernel-DENIED; no egress/mutate/custody capability on this path).
#[must_use]
pub fn render_test_run(pkg: &str) -> TestRunRender {
    let (canon_pkg, kind) = match classify_pkg(pkg) {
        Ok(ok) => ok,
        Err(deny) => return test_deny(deny, pkg),
    };
    let pkg_str = canon_pkg.to_string_lossy().to_string();

    // Build the runner line (whitespace-split argv; pkg validated whitespace-free).
    // Move: `sui move test --path <pkg>`, HOME withheld so `sui` uses its BUNDLED
    // framework offline (the SAME reason code_oracle's build oracle withholds HOME —
    // a cold `~/.move` probe would network-fetch, which is kernel-DENIED here). Cargo:
    // `cargo test --offline --manifest-path <pkg>/Cargo.toml`, HOME KEPT (cargo needs
    // its `~/.cargo` registry cache) + `--offline` (no fetch under the net-DENIED sandbox).
    let (bin, line, env_excludes): (&str, String, &[&str]) = match kind {
        TestKind::Move => {
            let Some(sui) = resolve_on_path("sui") else {
                return test_deny(TestRunDeny::ToolUnavailable, pkg);
            };
            (
                "sui",
                format!("{} move test --path {pkg_str}", sui.to_string_lossy()),
                &["HOME"],
            )
        }
        TestKind::Cargo => {
            let Some(cargo) = resolve_on_path("cargo") else {
                return test_deny(TestRunDeny::ToolUnavailable, pkg);
            };
            (
                "cargo",
                format!(
                    "{} test --offline --manifest-path {pkg_str}/Cargo.toml",
                    cargo.to_string_lossy()
                ),
                &[],
            )
        }
    };
    let _ = bin;

    let outcome = match run_in_sandbox(
        SandboxTier::LocalWrite,
        &line,
        TEST_RUN_TIMEOUT_MS,
        EXEC_STREAM_CAP_BYTES,
        env_excludes,
    ) {
        Ok(o) => o,
        Err(SandboxRunDeny::SandboxUnavailable) => {
            return test_deny(TestRunDeny::SandboxUnavailable, pkg);
        }
        Err(_) => return test_deny(TestRunDeny::SpawnFailed, pkg),
    };

    let passed = outcome.exit_code == Some(0) && !outcome.timed_out;
    let mut combined = String::from_utf8_lossy(&outcome.stdout.retained).into_owned();
    let err = String::from_utf8_lossy(&outcome.stderr.retained);
    if !err.trim().is_empty() {
        if !combined.is_empty() {
            combined.push('\n');
        }
        combined.push_str(err.trim());
    }
    if !redact_passes(&combined) {
        return TestRunRender {
            rendered: format!("test run {pkg}: withheld (test output was secret-shaped)"),
            consumed_read: false,
            class_label: "test_run.result.withheld_secret",
        };
    }
    let verdict = if outcome.timed_out {
        "TIMED OUT"
    } else if passed {
        "PASS"
    } else {
        "FAIL"
    };
    let runner = match kind {
        TestKind::Move => "sui move test",
        TestKind::Cargo => "cargo test --offline",
    };
    TestRunRender {
        rendered: format!(
            "test run {pkg}: {verdict} (oracle: {runner}; sandboxed, network kernel-DENIED — ground truth, not a guess)\n{combined}"
        ),
        consumed_read: true,
        class_label: if passed {
            "test_run.pass"
        } else {
            "test_run.fail"
        },
    }
}

/// redaction gate (the SAME canonical `redact` wall the loop / web fetch / lsp
/// / mcp / git use): `true` ⇒ no secret-shaped fragment; `false` ⇒ WITHHELD.
#[must_use]
fn redact_passes(text: &str) -> bool {
    use crate::provider::redaction::{RedactionRequest, redact};
    let fragments = [text];
    matches!(
        redact(&RedactionRequest {
            fragments: &fragments,
            candidate_memory_ids: &[],
            deleted_ids: &[],
            include_private_memory: false,
        }),
        Ok(receipt) if receipt.secret_fragments_denied_u32() == 0
    )
}

/// Render a typed test-run deny (the package label only — never repo bytes).
#[must_use]
fn test_deny(deny: TestRunDeny, pkg: &str) -> TestRunRender {
    let hint = match deny {
        TestRunDeny::NotAPackage => " (need a Move.toml or Cargo.toml package under the workspace)",
        TestRunDeny::PkgEscapesWorkspace => " (the path must stay under the workspace root)",
        _ => "",
    };
    TestRunRender {
        rendered: format!("test run {pkg}: denied ({}){hint}", deny.class_label()),
        consumed_read: false,
        class_label: deny.class_label(),
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use super::*;

    #[test]
    fn pkg_unsafe_rejects_empty_oversized_and_whitespace() {
        // These fail the pre-resolve wall BEFORE any filesystem / spawn (deterministic).
        assert_eq!(render_test_run("").class_label, "test_run.pkg.unsafe");
        let big = "x".repeat(TEST_RUN_MAX_PKG_BYTES + 1);
        assert_eq!(render_test_run(&big).class_label, "test_run.pkg.unsafe");
        assert_eq!(render_test_run("a b").class_label, "test_run.pkg.unsafe");
    }

    #[test]
    fn nonexistent_or_non_package_path_is_honest_deny() {
        // A path that does not resolve ⇒ NotAPackage (never a fabricated pass).
        let r = render_test_run("definitely/not/a/real/pkg/xyzzy");
        assert!(!r.consumed_read);
        assert_eq!(r.class_label, "test_run.pkg.not_a_package");
    }

    #[test]
    fn deny_labels_are_stable() {
        assert_eq!(TestRunDeny::PkgUnsafe.class_label(), "test_run.pkg.unsafe");
        assert_eq!(
            TestRunDeny::PkgEscapesWorkspace.class_label(),
            "test_run.pkg.escapes_workspace"
        );
        assert_eq!(
            TestRunDeny::NotAPackage.class_label(),
            "test_run.pkg.not_a_package"
        );
        assert_eq!(
            TestRunDeny::ToolUnavailable.class_label(),
            "test_run.tool.unavailable"
        );
    }
}
