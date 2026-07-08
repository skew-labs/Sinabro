//! Git-as-capability-type — git `status`/`diff`/`log`/`show`/`blame` as a
//! sandboxed READ capability.
//!
//! ## Thesis (git mapped onto the capability tiers)
//!
//! MNEMOS itself is not git, but the owner's PROJECTS are. v1 = the READ tier
//! ONLY: `status`/`diff`/`log`/`show`/`blame` (free,
//! no approval). MUTATE (`commit`/`branch`) + EGRESS (`push`) are a separate
//! owner-armed v2 — and the force-push / chain-write refusal primitive already
//! exists at propose-time (`exec_proposal::ExecProposeDeny::ForcePushIntent`/
//! `ChainWriteIntent`), so the safety wall for v2 is in place. TWO consumers over
//! ONE chokepoint ([`render_git_read`]): the agent loop's 12th typed-READ tool
//! `TOOL: git <subcommand> [args]` AND the dispatch verb `context git <subcommand>
//! [args]`.
//!
//! ## Security
//!
//! * CAPABILITY = READ. The real `git` binary runs ONE-SHOT under a custom Seatbelt
//!   profile = `seatbelt_profile_for(ReadOnly)` PLUS a `/dev/null` write allow (git
//!   opens `/dev/null` read+write even for a pure read, the SAME path-scoped pattern
//!   the move-analyzer profile needed). The NETWORK is ALWAYS kernel-DENIED (the
//!   load-bearing wall — a git READ never fetches; a `push`/`fetch` physically
//!   cannot reach a remote). A WRITE (`commit`) is kernel-DENIED even under this
//!   profile (`.git/index.lock: Operation not permitted`) — defense in depth atop
//!   the allowlist. fail-CLOSED if no kernel sandbox (never run unsandboxed).
//! * FAIL-CLOSED allowlist: the subcommand MUST be in [`GIT_READ_SUBCOMMANDS`];
//!   anything else (a write / a config / an unknown verb) ⇒ DENY.
//! * REDACTION: the git output passes the `redact` wall; secret-shaped ⇒
//!   WITHHELD.
//! * CUSTODY untouched: this path constructs no egress/mutate/custody
//!   capability and reaches no chain RPC or socket (the sandbox kernel-denies the
//!   network); user funds stay hard-locked behind the uninhabited custody type.
//!
//! ## Reuse (no second spawn discipline)
//!
//! The bounded run is [`crate::exec_local::run_argv_command_with_env`] (the proven
//! env-scrub / wall-clock timeout + reap / per-stream byte cap / pinned cwd), wrapped
//! by `sandbox-exec -p <profile> --` exactly like [`crate::sandbox_exec::run_in_sandbox`]
//! but with the custom git-read profile. The profile base is the canonical
//! [`crate::sandbox_exec::seatbelt_profile_for`]. ALWAYS compiled (no feature) — git
//! is a system binary; an absent binary honest-degrades.

use std::path::PathBuf;

use crate::exec_local::{
    EXEC_MAX_ARGS, EXEC_STREAM_CAP_BYTES, EXEC_TIMEOUT_MS, run_argv_command_with_env,
};

/// The v1 READ-only git subcommand allowlist (the core 5).
/// Anything outside this set ⇒ [`GitDeny::SubcommandNotAllowed`] (fail-closed). A
/// write (`commit`/`add`/`push`/…) is never here — and is kernel-DENIED by the
/// READ profile even if it somehow reached the spawn.
pub const GIT_READ_SUBCOMMANDS: &[&str] = &["status", "diff", "log", "show", "blame"];

/// Bound on the user-supplied argument string (a git READ never needs a long line;
/// refuse, never truncate). Below the exec line cap.
const GIT_MAX_ARGS_BYTES: usize = 1024;

/// Typed, data-free denial reasons for a git READ.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GitDeny {
    /// The subcommand is not in the v1 READ allowlist (fail-closed; a write /
    /// config / unknown verb).
    SubcommandNotAllowed,
    /// The argument string exceeds [`GIT_MAX_ARGS_BYTES`] / the argv cap.
    ArgsTooLarge,
    /// fail-CLOSED: no kernel sandbox on this host (git is NEVER run unsandboxed).
    SandboxUnavailable,
    /// The `git` binary was not found on `PATH` (honest-degrade, never fabricated).
    GitUnavailable,
    /// The sandboxed git invocation could not be spawned / a pipe I/O error.
    SpawnFailed,
    /// git ran but exited non-zero (e.g. not a git repository) — honest, with its
    /// (redacted, bounded) stderr.
    GitFailed,
}

impl GitDeny {
    /// Stable, allow-listed `class_label` (namespaced `git.*`).
    #[must_use]
    pub const fn class_label(self) -> &'static str {
        match self {
            Self::SubcommandNotAllowed => "git.subcommand.not_allowed",
            Self::ArgsTooLarge => "git.args.too_large",
            Self::SandboxUnavailable => "git.sandbox.unavailable",
            Self::GitUnavailable => "git.unavailable",
            Self::SpawnFailed => "git.spawn_failed",
            Self::GitFailed => "git.failed",
        }
    }
}

/// The chokepoint's verdict (mirror of [`crate::lsp`]'s `(String, bool)` /
/// `WebFetchRender`): the rendered output / deny, whether it consumed a READ (only a
/// successful git result), and a stable class label.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GitReadRender {
    /// The rendered git output (success) or the typed deny (bounded).
    pub rendered: String,
    /// `true` only when a real git READ produced output (consumes the loop's K-read
    /// budget); every deny / withhold / honest-degrade is `false`.
    pub consumed_read: bool,
    /// A stable ASCII class label (`git.*`).
    pub class_label: &'static str,
}

/// Whether `subcommand` is in the v1 READ allowlist (case-insensitive).
#[must_use]
pub fn is_read_subcommand(subcommand: &str) -> bool {
    let lower = subcommand.to_ascii_lowercase();
    GIT_READ_SUBCOMMANDS.iter().any(|s| *s == lower)
}

/// The custom git-read Seatbelt profile: the canonical `ReadOnly` ceiling (network +
/// file-write kernel-DENIED) PLUS a `/dev/null` write allow (git opens `/dev/null`
/// read+write even for a pure read). SBPL "last rule wins", so the `/dev/null` allow
/// MUST follow the generic `(deny file-write*)` (which `seatbelt_profile_for` emits).
/// Every other write — `.git/index.lock` included — stays kernel-DENIED.
#[must_use]
fn git_read_profile() -> String {
    use crate::commands::sandbox::SandboxTier;
    use crate::sandbox_exec::seatbelt_profile_for;
    format!(
        "{}(allow file-write* (literal \"/dev/null\"))",
        seatbelt_profile_for(SandboxTier::ReadOnly)
    )
}

/// Resolve a bare binary name to an absolute path by scanning `PATH` (the honest
/// presence probe; `None` ⇒ absent ⇒ honest-degrade). Mirrors the resolver.
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

/// Run one READ-allowlisted git subcommand sandboxed against the resolved workspace
/// root, returning its stdout. Gate order: allowlist (fail-closed) → arg bounds →
/// fail-closed sandbox admission → resolve `git` → spawn under the git-read profile
/// (network + write kernel-DENIED; `--no-optional-locks` so `status` needs no index
/// write) → exit-code check. The bounded exec core ([`run_argv_command_with_env`])
/// owns the env-scrub / timeout / byte-cap / reap.
fn run_git_read(subcommand: &str, args: &str) -> Result<String, GitDeny> {
    use crate::sandbox_exec::{SANDBOX_EXEC_PATH, seatbelt_available};

    if !is_read_subcommand(subcommand) {
        return Err(GitDeny::SubcommandNotAllowed);
    }
    if args.len() > GIT_MAX_ARGS_BYTES {
        return Err(GitDeny::ArgsTooLarge);
    }
    // fail-closed: never run git unsandboxed.
    if !seatbelt_available() {
        return Err(GitDeny::SandboxUnavailable);
    }
    let Some(git_bin) = resolve_on_path("git") else {
        return Err(GitDeny::GitUnavailable);
    };
    // The repo root: the SINABRO_PROJECT_ROOT override else the nearest .git/.sinabro
    // ancestor of cwd. git discovers the repo from `-C <root>` (read-only walk).
    let root = crate::file_context::workspace_root()
        .unwrap_or_else(|| PathBuf::from("."))
        .display()
        .to_string();

    // Build the sandbox-wrapped argv (the SAME shape `run_in_sandbox` builds, with
    // the custom git-read profile): sandbox-exec -p <profile> -- git -C <root>
    // --no-optional-locks <subcommand> <args...>. The profile rides as ONE argv
    // element (never whitespace re-split).
    let user_args: Vec<String> = args.split_whitespace().map(str::to_string).collect();
    let mut argv: Vec<String> = Vec::with_capacity(user_args.len() + 9);
    argv.push(SANDBOX_EXEC_PATH.to_string());
    argv.push("-p".to_string());
    argv.push(git_read_profile());
    argv.push("--".to_string());
    argv.push(git_bin.display().to_string());
    argv.push("-C".to_string());
    argv.push(root);
    // `--no-optional-locks` (the flag form of GIT_OPTIONAL_LOCKS=0) so `status` never
    // needs to refresh/write the index under the deny-write sandbox; a no-op for the
    // pure-read subcommands. (env vars cannot be added through the exec core's
    // allowlist, so the flag — not the env — carries this.)
    argv.push("--no-optional-locks".to_string());
    argv.push(subcommand.to_ascii_lowercase());
    argv.extend(user_args);
    if argv.len() > EXEC_MAX_ARGS {
        return Err(GitDeny::ArgsTooLarge);
    }

    let outcome = run_argv_command_with_env(argv, EXEC_TIMEOUT_MS, EXEC_STREAM_CAP_BYTES, &[])
        .map_err(|_| GitDeny::SpawnFailed)?;
    if outcome.exit_code == Some(0) {
        Ok(String::from_utf8_lossy(&outcome.stdout.retained).into_owned())
    } else {
        // git ran but exited non-zero (e.g. "not a git repository"). Honest typed
        // failure — nothing was written (the sandbox denies any write); the
        // chokepoint renders the honest hint. The stderr is intentionally not
        // surfaced (it can carry filesystem paths; the typed reason suffices for v1).
        Err(GitDeny::GitFailed)
    }
}

/// The ONE git READ chokepoint shared by BOTH consumers (the loop tool + the
/// dispatch verb). Gate order: allowlist (fail-closed) → sandboxed git READ
/// (network + write kernel-DENIED) → redact the output (secret-shaped ⇒ WITHHELD) →
/// render. A git READ is a free local READ (like `lsp diagnostics` / `audit detect`),
/// so it is NOT a high-significance audited action. custody/funds untouched.
#[must_use]
pub fn render_git_read(subcommand: &str, args: &str) -> GitReadRender {
    match run_git_read(subcommand, args) {
        Ok(stdout) => {
            // a secret-shaped git output is WITHHELD (never surfaces).
            if !redact_passes(&stdout) {
                return GitReadRender {
                    rendered: format!(
                        "git {subcommand}: withheld (the git output was secret-shaped)"
                    ),
                    consumed_read: false,
                    class_label: "git.result.withheld_secret",
                };
            }
            let body = if stdout.trim().is_empty() {
                format!("git {subcommand}: (no output — clean / nothing to report)")
            } else {
                stdout
            };
            GitReadRender {
                rendered: format!(
                    "git {subcommand}: advisory (a sandboxed READ of the local repo; network + write kernel-DENIED)\n{body}"
                ),
                consumed_read: true,
                class_label: "git.read.advisory",
            }
        }
        Err(deny) => {
            let hint = match deny {
                GitDeny::SubcommandNotAllowed => format!(
                    " (v1 allows READ only: {}; commit/branch/push are an owner-armed v2)",
                    GIT_READ_SUBCOMMANDS.join(" / ")
                ),
                GitDeny::GitFailed => {
                    " (git ran but failed — e.g. not a git repository; nothing was written)"
                        .to_string()
                }
                _ => String::new(),
            };
            GitReadRender {
                rendered: format!("git {subcommand}: denied ({}){hint}", deny.class_label()),
                consumed_read: false,
                class_label: deny.class_label(),
            }
        }
    }
}

/// redaction gate (the SAME canonical `redact` wall the loop / web fetch /
/// lsp / mcp use): `true` ⇒ no secret-shaped fragment, may surface; `false` ⇒ WITHHELD.
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

// ---------------------------------------------------------------------------
// v2 EGRESS — git push (owner-armed, origin-only). The FIRST credentialed
// network-WRITE in the agent: `git push origin <branch>` to the repo's configured
// `origin` (a fixed scope, not user-configurable), run under a BESPOKE sandbox profile that ALLOWS
// the network but SCOPES local writes to the repo's `.git` (+ /dev/null). It is
// reachable ONLY with an owner-armed `EgressCapability` witness (the dispatch verb
// `daemon git-push <ARM_PHRASE>` mints it via the E0c ceremony) — the agent loop
// holds only `ReadCapability`, so it can never push. force-push is structurally
// impossible (no `--force`/`--mirror`/`-f`; the only user arg is a validated branch
// ref and the remote is the literal `origin`). Custody/funds HARD-LOCKED.
// ---------------------------------------------------------------------------

/// The owner-arm ceremony phrase for `daemon git-push` (a dedicated phrase for
/// ceremony separation; the grant TIER reused is `GrantTier::Egress` — no new
/// tier).
pub const GIT_PUSH_ARM_PHRASE: &str = "arm-git-push-origin-bounded-revocable";

/// Typed, data-free denial reasons for an owner-armed git push.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GitPushDeny {
    /// The branch ref is not a safe token (empty-after-trim is allowed = HEAD; a
    /// leading `-` / a shell-or-flag-shaped token is refused — no flag injection).
    UnsafeBranch,
    /// The resolved repo root contains a `"`/`\\` (SBPL-injection guard) — refuse
    /// rather than emit a malformed profile.
    RepoPathUnsafe,
    /// fail-CLOSED: no kernel sandbox on this host (git push is NEVER run unsandboxed).
    SandboxUnavailable,
    /// The `git` binary was not found on `PATH` (honest-degrade).
    GitUnavailable,
    /// The sandboxed git push could not be spawned / a pipe I/O error.
    SpawnFailed,
    /// git push ran but exited non-zero (e.g. no `origin`, rejected, auth/network).
    PushFailed,
}

impl GitPushDeny {
    /// Stable, allow-listed `class_label` (namespaced `git.push.*`).
    #[must_use]
    pub const fn class_label(self) -> &'static str {
        match self {
            Self::UnsafeBranch => "git.push.unsafe_branch",
            Self::RepoPathUnsafe => "git.push.repo_path_unsafe",
            Self::SandboxUnavailable => "git.push.sandbox.unavailable",
            Self::GitUnavailable => "git.push.unavailable",
            Self::SpawnFailed => "git.push.spawn_failed",
            Self::PushFailed => "git.push.failed",
        }
    }
}

/// The git-push render (mirror of [`GitReadRender`]): the rendered outcome / deny,
/// whether the push succeeded, and a stable class label.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GitPushRender {
    /// The rendered push outcome (success) or the typed deny (bounded, redacted).
    pub rendered: String,
    /// `true` only when `git push` exited 0.
    pub pushed: bool,
    /// A stable ASCII class label (`git.push.*`).
    pub class_label: &'static str,
}

/// Whether `branch` is a safe git ref token: non-empty, no leading `-` (flag
/// injection), and only `[A-Za-z0-9._/-]` (no whitespace / shell metacharacters).
/// An EMPTY branch is handled by the caller (⇒ `HEAD`), not here.
#[must_use]
fn is_safe_branch(branch: &str) -> bool {
    !branch.is_empty()
        && branch.len() <= 200
        && !branch.starts_with('-')
        && !branch.contains("..") // a `..` is an invalid git ref (check-ref-format) + path-traversal-shaped
        && branch
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'/' | b'-'))
}

/// The bespoke git-PUSH Seatbelt profile: `(allow default)` (network ALLOWED — a
/// push must reach the remote; git may spawn ssh / https helpers) MINUS broad
/// file-write — writes are SCOPED to the repo's `.git` (push updates local refs)
/// and `/dev/null`. SBPL "last rule wins": the generic `(deny file-write*)` precedes
/// the scoped allow. The NETWORK is deliberately NOT denied (this is the EGRESS
/// tier — owner-armed). Returns `None` if the root path is unsafe for SBPL.
#[must_use]
fn git_push_profile(repo_root: &str) -> Option<String> {
    if repo_root.contains('"') || repo_root.contains('\\') {
        return None;
    }
    Some(format!(
        "(version 1)(allow default)(deny file-write*)(allow file-write* (subpath \"{repo_root}/.git\") (literal \"/dev/null\"))"
    ))
}

/// The ONE git-push chokepoint, reachable ONLY with an owner-armed `EgressCapability`
/// witness. Pushes the validated `branch` (empty ⇒ `HEAD`) to the literal `origin`
/// under the bespoke net-allowed, `.git`-write-scoped sandbox. force-push is
/// impossible (no force flag; remote is the literal `origin`). The git output is
/// redact-belted. The capability witness is consumed (proves the owner armed
/// egress); custody/funds untouched.
#[must_use]
pub fn render_git_push(
    cap: &crate::commands::authority::EgressCapability,
    branch: &str,
) -> GitPushRender {
    let _ = cap; // the witness: an owner-armed EgressGrant minted this (E0c).
    use crate::sandbox_exec::{SANDBOX_EXEC_PATH, seatbelt_available};

    let branch = branch.trim();
    let push_ref = if branch.is_empty() {
        "HEAD"
    } else if is_safe_branch(branch) {
        branch
    } else {
        return push_deny(GitPushDeny::UnsafeBranch, branch);
    };
    if !seatbelt_available() {
        return push_deny(GitPushDeny::SandboxUnavailable, push_ref);
    }
    let Some(git_bin) = resolve_on_path("git") else {
        return push_deny(GitPushDeny::GitUnavailable, push_ref);
    };
    // Canonicalize the repo root (resolve symlinks, e.g. macOS /tmp -> /private/tmp)
    // so the profile's `.git` write-scope subpath matches the path the kernel sandbox
    // actually sees — otherwise git's local ref-update (refs/remotes/origin/...) is
    // write-denied even though the remote push itself succeeds.
    let root_pb = crate::file_context::workspace_root().unwrap_or_else(|| PathBuf::from("."));
    let root = std::fs::canonicalize(&root_pb)
        .unwrap_or(root_pb)
        .display()
        .to_string();
    let Some(profile) = git_push_profile(&root) else {
        return push_deny(GitPushDeny::RepoPathUnsafe, push_ref);
    };
    // sandbox-exec -p <profile> -- git -C <root> push origin <push_ref>. The remote
    // is the LITERAL "origin" (a fixed scope, not user-configurable); the ONLY user-derived token is
    // the validated branch ref. No force flag ⇒ a history rewrite is impossible.
    let argv: Vec<String> = vec![
        SANDBOX_EXEC_PATH.to_string(),
        "-p".to_string(),
        profile,
        "--".to_string(),
        git_bin.display().to_string(),
        "-C".to_string(),
        root,
        "push".to_string(),
        "origin".to_string(),
        push_ref.to_string(),
    ];
    let outcome = match run_argv_command_with_env(argv, EXEC_TIMEOUT_MS, EXEC_STREAM_CAP_BYTES, &[])
    {
        Ok(o) => o,
        Err(_) => return push_deny(GitPushDeny::SpawnFailed, push_ref),
    };
    // git push writes progress to stderr; surface both streams (redacted).
    let mut combined = String::from_utf8_lossy(&outcome.stdout.retained).into_owned();
    let err = String::from_utf8_lossy(&outcome.stderr.retained);
    if !err.trim().is_empty() {
        if !combined.is_empty() {
            combined.push('\n');
        }
        combined.push_str(err.trim());
    }
    if outcome.exit_code != Some(0) {
        return push_deny(GitPushDeny::PushFailed, push_ref);
    }
    if !redact_passes(&combined) {
        return GitPushRender {
            rendered: format!(
                "git push origin {push_ref}: withheld (push output was secret-shaped)"
            ),
            pushed: false,
            class_label: "git.push.withheld_secret",
        };
    }
    let body = if combined.trim().is_empty() {
        format!("git push origin {push_ref}: ok (nothing to display)")
    } else {
        combined
    };
    GitPushRender {
        rendered: format!(
            "git push origin {push_ref}: pushed (owner-armed egress; sandboxed, write-scoped to .git, no force)\n{body}"
        ),
        pushed: true,
        class_label: "git.push.ok",
    }
}

/// Render a typed git-push deny (the failing branch/ref label only — never repo bytes).
#[must_use]
fn push_deny(deny: GitPushDeny, push_ref: &str) -> GitPushRender {
    GitPushRender {
        rendered: format!(
            "git push origin {push_ref}: denied ({})",
            deny.class_label()
        ),
        pushed: false,
        class_label: deny.class_label(),
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use super::*;

    #[test]
    fn read_allowlist_is_exactly_core_five() {
        assert_eq!(
            GIT_READ_SUBCOMMANDS,
            &["status", "diff", "log", "show", "blame"]
        );
        for ok in ["status", "diff", "log", "show", "blame", "STATUS", "Log"] {
            assert!(is_read_subcommand(ok), "{ok} must be allowed");
        }
        // Write / config / unknown verbs are NOT in the READ allowlist (fail-closed).
        for bad in [
            "commit", "add", "push", "fetch", "branch", "config", "reset", "rm", "",
        ] {
            assert!(!is_read_subcommand(bad), "{bad} must NOT be allowed");
        }
    }

    #[test]
    fn profile_is_readonly_plus_devnull_in_last_wins_order() {
        let p = git_read_profile();
        // The ReadOnly base (net + write denied) FOLLOWED BY the /dev/null allow.
        assert!(p.starts_with("(version 1)(allow default)"));
        assert!(p.contains("(deny network*)"), "network kernel-DENIED: {p}");
        let deny_at = p
            .find("(deny file-write*)")
            .expect("deny file-write present");
        let allow_at = p
            .find("(allow file-write* (literal \"/dev/null\"))")
            .expect("dev/null allow present");
        assert!(
            allow_at > deny_at,
            "the /dev/null allow must come AFTER the generic deny (SBPL last-rule-wins): {p}"
        );
    }

    #[test]
    fn render_denies_a_non_read_subcommand_before_any_spawn() {
        // A write subcommand ⇒ fail-closed deny (the allowlist gate fires before the
        // sandbox spawn, so this holds on every host).
        let r = render_git_read("commit", "-m wip");
        assert!(!r.consumed_read);
        assert_eq!(r.class_label, "git.subcommand.not_allowed");
        assert!(r.rendered.contains("owner-armed v2"));
        let r2 = render_git_read("push", "origin main");
        assert_eq!(r2.class_label, "git.subcommand.not_allowed");
    }

    #[test]
    fn render_denies_oversized_args() {
        let big = "x ".repeat(GIT_MAX_ARGS_BYTES);
        let r = render_git_read("log", &big);
        assert!(!r.consumed_read);
        assert_eq!(r.class_label, "git.args.too_large");
    }

    // ---- v2 EGRESS git push ----------------------------------------------

    #[test]
    fn push_branch_validation_rejects_flags_and_metachars() {
        for ok in ["main", "feature/x", "v1.2.3", "release-2026", "a/b/c"] {
            assert!(is_safe_branch(ok), "{ok} must be a safe branch ref");
        }
        for bad in [
            "", "-f", "--force", "a b", "x;rm -rf", "--mirror", "../etc", "-d",
        ] {
            assert!(
                !is_safe_branch(bad),
                "{bad} must be rejected (flag/metachar)"
            );
        }
    }

    #[test]
    fn push_profile_is_net_allowed_and_write_scoped_to_dotgit_last_wins() {
        let p = git_push_profile("/tmp/myrepo").expect("safe path");
        assert!(p.starts_with("(version 1)(allow default)"));
        // NETWORK is ALLOWED for push (this is the EGRESS tier) — NO network deny.
        assert!(
            !p.contains("(deny network*)"),
            "push must permit network: {p}"
        );
        // writes are SCOPED to .git (+ /dev/null): the generic deny precedes the allow.
        let deny_at = p.find("(deny file-write*)").expect("deny present");
        let allow_at = p
            .find("(allow file-write* (subpath \"/tmp/myrepo/.git\")")
            .expect("scoped .git allow present");
        assert!(
            allow_at > deny_at,
            "scoped allow must come AFTER the deny (last-wins): {p}"
        );
        // SBPL-injection guard: a quote/backslash path ⇒ None.
        assert!(git_push_profile("/tmp/ev\"il").is_none());
        assert!(git_push_profile("/tmp/ev\\il").is_none());
    }

    #[test]
    fn render_push_denies_unsafe_branch_before_any_spawn() {
        // Reachable ONLY with an owner-armed EgressCapability witness; a flag-shaped
        // branch is refused BEFORE any spawn (fail-closed, every host).
        let cap = crate::commands::authority::test_egress_capability();
        let r = render_git_push(&cap, "--force");
        assert!(!r.pushed);
        assert_eq!(r.class_label, "git.push.unsafe_branch");
        let r2 = render_git_push(&cap, "x;rm -rf /");
        assert_eq!(r2.class_label, "git.push.unsafe_branch");
    }
}
