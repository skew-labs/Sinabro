//! Local owner-initiated command execution — bounded, env-scrubbed.
//! Enforces the.E8 execution walls. THE FIRST process-spawn surface in the
//! core; the MODEL has
//! no path here (the loop grammar is byte-unchanged — `TOOL: exec …` parses
//! `ToolUnknown` and is denied; dispatch is owner-typed only, behind the
//! exact ceremony phrase).
//!
//! This module owns spawn + bounds + scrub ONLY. Redaction of the captured
//! streams is the DISPATCH render's job (the same seam the lane-A file
//! context uses), so the wall order stays: bound here → redact at render.
//!
//! # The walls owned here
//!
//! * **no-shell argv** — the line is whitespace-split and spawned
//!   directly (`Command::new(argv[0]).args(..)`); no `sh -c`, no pipes, no
//!   globs, no env interpolation. What runs is exactly the argv echoed in
//!   the receipt.
//! * **env scrub** — the child env is CLEARED then given the minimal
//!   [`EXEC_ENV_ALLOWLIST`]; provider keys and every other parent var never
//!   cross the spawn boundary.
//! * **bounded child** — wall-clock timeout (kill + reap, no zombie),
//!   per-stream retained-byte caps with honest total counts, null stdin.
//! * **cwd pinned** — the child runs in the canonical current working
//!   directory (the lane-A allowlist anchor); no caller-supplied cwd.

use std::io::Read;
use std::process::Stdio;
use std::time::{Duration, Instant};

/// Default wall-clock timeout for one owner command.
pub const EXEC_TIMEOUT_MS: u64 = 10_000;

/// Default per-stream RETAINED byte cap (stdout and stderr each). The child
/// may write more — the drain keeps reading (so the child never blocks on a
/// full pipe) but retains only this many bytes; the receipt carries the
/// honest total.
pub const EXEC_STREAM_CAP_BYTES: usize = 64 * 1024;

/// Maximum command-line bytes (pre-split).
pub const EXEC_MAX_LINE_BYTES: usize = 4_096;

/// Maximum argv entries after whitespace split.
pub const EXEC_MAX_ARGS: usize = 64;

/// The ONLY environment variables a child inherits. Everything else
/// — provider keys above all — is scrubbed by `env_clear`.
pub const EXEC_ENV_ALLOWLIST: [&str; 4] = ["PATH", "HOME", "LANG", "TERM"];

/// Typed, data-free denial reasons (pre-spawn walls).
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
#[non_exhaustive]
pub enum ExecDeny {
    /// The command line was empty after trimming.
    EmptyArgv,
    /// The command line exceeded [`EXEC_MAX_LINE_BYTES`].
    LineTooLong,
    /// More than [`EXEC_MAX_ARGS`] argv entries.
    TooManyArgs,
    /// The program could not be spawned (not found / not executable / cwd
    /// unavailable). No partial child exists after this error.
    SpawnFailed,
}

impl ExecDeny {
    /// Stable, allow-listed `class_label` (namespaced `exec_local.*`).
    #[inline]
    #[must_use]
    pub const fn class_label(self) -> &'static str {
        match self {
            Self::EmptyArgv => "exec_local.empty_argv",
            Self::LineTooLong => "exec_local.line_too_long",
            Self::TooManyArgs => "exec_local.too_many_args",
            Self::SpawnFailed => "exec_local.spawn_failed",
        }
    }
}

/// One captured stream: the retained head (≤ cap), whether it was truncated
/// and the HONEST total byte count that crossed the pipe.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct CapturedStream {
    /// Retained bytes (≤ the stream cap).
    pub retained: Vec<u8>,
    /// Whether bytes beyond the cap were dropped (still counted below).
    pub truncated: bool,
    /// Total bytes the child wrote to this stream.
    pub total_bytes_u64: u64,
}

/// The full, render-ready outcome of one bounded owner command.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExecOutcome {
    /// The exact argv that ran (echoed verbatim in the receipt).
    pub argv: Vec<String>,
    /// The child's exit code; `None` when it was killed (timeout) or the
    /// status carried no code.
    pub exit_code: Option<i32>,
    /// Whether the wall-clock timeout fired (the child was killed + reaped).
    pub timed_out: bool,
    /// Wall-clock duration in milliseconds.
    pub duration_ms_u64: u64,
    /// Captured stdout (bounded).
    pub stdout: CapturedStream,
    /// Captured stderr (bounded).
    pub stderr: CapturedStream,
}

/// Run one owner command with the default bounds.
pub fn run_local_command(line: &str) -> Result<ExecOutcome, ExecDeny> {
    run_local_command_with(line, EXEC_TIMEOUT_MS, EXEC_STREAM_CAP_BYTES)
}

/// [`run_local_command`] with explicit bounds (tests use a small timeout).
/// The gate order is the threat model's: argv walls → scrubbed spawn →
/// bounded drain + timeout kill + reap.
pub fn run_local_command_with(
    line: &str,
    timeout_ms: u64,
    stream_cap_bytes: usize,
) -> Result<ExecOutcome, ExecDeny> {
    if line.len() > EXEC_MAX_LINE_BYTES {
        return Err(ExecDeny::LineTooLong);
    }
    let argv: Vec<String> = line.split_whitespace().map(str::to_string).collect();
    run_argv_command_with(argv, timeout_ms, stream_cap_bytes)
}

/// Spawn an EXPLICIT argv (already split — each element is one argument) under
/// the SAME bounded, env-scrubbed, timeout+reap discipline as
/// [`run_local_command_with`]. The argv-only contract holds: the argv is
/// `Command::new(argv[0]).args(..)`, never a shell, never re-split — so an
/// element MAY legitimately contain whitespace (e.g. an SBPL profile string).
///
/// This is the reuse seam the OS-sandbox layer ([`crate::sandbox_exec`]) wraps:
/// it prepends the `sandbox-exec -p <profile> --` wrapper as the leading argv
/// elements, so the SAME scrub / timeout / byte-cap / cwd-pin walls bound a
/// kernel-confined child — no second spawn discipline, no drift.
pub fn run_argv_command_with(
    argv: Vec<String>,
    timeout_ms: u64,
    stream_cap_bytes: usize,
) -> Result<ExecOutcome, ExecDeny> {
    run_argv_command_with_env(argv, timeout_ms, stream_cap_bytes, &[])
}

/// [`run_argv_command_with`] but additionally WITHHOLDS the named allowlisted env keys
/// from the child (strictly MORE restrictive than the scrub — withholding can only
/// NARROW the child's view, never widen it, so is never weakened). The CODE oracle
/// uses this to run `sui move build` with NO `HOME`, so `sui` resolves its BUNDLED
/// framework offline instead of probing `$HOME/.move` (which, on a box without a warm
/// cache, would attempt a network fetch — kernel-DENIED in the sandbox — and fail).
pub fn run_argv_command_with_env(
    argv: Vec<String>,
    timeout_ms: u64,
    stream_cap_bytes: usize,
    env_excludes: &[&str],
) -> Result<ExecOutcome, ExecDeny> {
    if argv.is_empty() {
        return Err(ExecDeny::EmptyArgv);
    }
    if argv.len() > EXEC_MAX_ARGS {
        return Err(ExecDeny::TooManyArgs);
    }

    let started = Instant::now();
    let cwd = std::env::current_dir().map_err(|_| ExecDeny::SpawnFailed)?;
    let mut command = std::process::Command::new(&argv[0]);
    command
        .args(&argv[1..])
        .env_clear()
        .current_dir(cwd)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    // the child sees ONLY the allowlist (a parent var that is unset
    // simply stays unset — never a default, never a substitute), minus any key the
    // caller explicitly withholds (`env_excludes` — only ever NARROWS the view).
    for key in EXEC_ENV_ALLOWLIST {
        if env_excludes.contains(&key) {
            continue;
        }
        if let Ok(value) = std::env::var(key) {
            command.env(key, value);
        }
    }
    let mut child = command.spawn().map_err(|_| ExecDeny::SpawnFailed)?;
    let stdout_pipe = child.stdout.take();
    let stderr_pipe = child.stderr.take();

    let (stdout, stderr, exit_code, timed_out) = std::thread::scope(|scope| {
        // Drain BOTH pipes fully on their own threads (the child can never
        // block on a full pipe ⇒ the timeout below is the only clock).
        let out_handle = scope.spawn(move || drain_capped(stdout_pipe, stream_cap_bytes));
        let err_handle = scope.spawn(move || drain_capped(stderr_pipe, stream_cap_bytes));

        let deadline = started + Duration::from_millis(timeout_ms);
        let mut timed_out = false;
        let exit_code = loop {
            match child.try_wait() {
                Ok(Some(status)) => break status.code(),
                Ok(None) => {
                    if Instant::now() >= deadline {
                        timed_out = true;
                        // kill THEN wait — the child is always
                        // reaped, never a zombie. The kill error (already
                        // exited) is benign by construction.
                        let _ = child.kill();
                        break child.wait().ok().and_then(|status| status.code());
                    }
                    std::thread::sleep(Duration::from_millis(10));
                }
                Err(_) => break None,
            }
        };
        (
            out_handle.join().unwrap_or_default(),
            err_handle.join().unwrap_or_default(),
            exit_code,
            timed_out,
        )
    });

    Ok(ExecOutcome {
        argv,
        exit_code,
        timed_out,
        duration_ms_u64: u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX),
        stdout,
        stderr,
    })
}

/// Drain a pipe to EOF, retaining at most `cap` bytes but counting ALL of
/// them (bounded memory, honest totals). A missing pipe drains to
/// the empty capture.
fn drain_capped<R: Read>(pipe: Option<R>, cap: usize) -> CapturedStream {
    let mut captured = CapturedStream::default();
    let Some(mut reader) = pipe else {
        return captured;
    };
    let mut chunk = [0u8; 4096];
    loop {
        match reader.read(&mut chunk) {
            Ok(0) => break,
            Ok(n) => {
                captured.total_bytes_u64 = captured.total_bytes_u64.saturating_add(n as u64);
                if captured.retained.len() < cap {
                    let keep = (cap - captured.retained.len()).min(n);
                    captured.retained.extend_from_slice(&chunk[..keep]);
                    if keep < n {
                        captured.truncated = true;
                    }
                } else {
                    captured.truncated = true;
                }
            }
            Err(_) => break,
        }
    }
    captured
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use super::*;

    /// A plain command runs, exits 0, captures stdout exactly,
    /// echoes its argv verbatim and stays inside the duration bound.
    #[test]
    #[cfg(unix)]
    fn echo_runs_bounded_and_captures() {
        let outcome = run_local_command("/bin/echo hello sinabro").expect("runs");
        assert_eq!(outcome.exit_code, Some(0));
        assert!(!outcome.timed_out);
        assert_eq!(outcome.argv, ["/bin/echo", "hello", "sinabro"]);
        assert_eq!(outcome.stdout.retained, b"hello sinabro\n");
        assert!(!outcome.stdout.truncated);
        assert_eq!(outcome.stdout.total_bytes_u64, 14);
        assert_eq!(outcome.stderr.total_bytes_u64, 0);
    }

    /// The cardinal leak wall: a child dumping its environment sees
    /// ONLY the allowlist. `cargo test` always injects `CARGO*` vars into
    /// THIS parent process, so their absence in the child proves the scrub
    /// (and by extension that provider keys never cross).
    #[test]
    #[cfg(unix)]
    fn env_is_scrubbed_to_the_allowlist() {
        assert!(
            std::env::vars().any(|(key, _)| key.starts_with("CARGO")),
            "precondition: the parent (cargo test) carries CARGO* vars"
        );
        let outcome = run_local_command("/usr/bin/env").expect("runs");
        let dump = String::from_utf8_lossy(&outcome.stdout.retained).to_string();
        assert!(
            !dump.contains("CARGO"),
            "parent env must not cross the spawn boundary: {dump}"
        );
        assert!(
            !dump.contains("OPENROUTER_API_KEY"),
            "provider keys must never cross"
        );
        // The allowlist itself does cross (PATH is always set on macOS/CI).
        assert!(dump.contains("PATH="), "allowlisted PATH crosses: {dump}");
    }

    /// The timeout kills + reaps a hanging child and says so.
    #[test]
    #[cfg(unix)]
    fn timeout_kills_and_reaps() {
        let started = Instant::now();
        let outcome =
            run_local_command_with("/bin/sleep 5", 150, EXEC_STREAM_CAP_BYTES).expect("spawns");
        assert!(outcome.timed_out, "the watchdog fired");
        assert!(
            started.elapsed() < Duration::from_secs(3),
            "killed well before the child's own 5s"
        );
        assert_eq!(outcome.exit_code, None, "killed ⇒ no exit code");
    }

    /// The retained cap holds while the TOTAL stays honest and the
    /// child still runs to completion (the drain never blocks the pipe).
    #[test]
    #[cfg(unix)]
    fn output_cap_retains_head_and_counts_all() {
        // 100 lines × "y\n" = 200 bytes total; retain only 64.
        let outcome =
            run_local_command_with("/usr/bin/head -c 200 /dev/zero", 5_000, 64).expect("runs");
        assert_eq!(outcome.exit_code, Some(0), "child completed");
        assert_eq!(outcome.stdout.retained.len(), 64);
        assert!(outcome.stdout.truncated);
        assert_eq!(outcome.stdout.total_bytes_u64, 200);
    }

    /// Pre-spawn walls: empty / oversized / too-many-args are typed denials
    /// (no child exists on any of these paths).
    #[test]
    fn pre_spawn_walls_deny_typed() {
        assert_eq!(run_local_command("   "), Err(ExecDeny::EmptyArgv));
        let long = "x".repeat(EXEC_MAX_LINE_BYTES + 1);
        assert_eq!(run_local_command(&long), Err(ExecDeny::LineTooLong));
        let many = vec!["a"; EXEC_MAX_ARGS + 1].join(" ");
        assert_eq!(run_local_command(&many), Err(ExecDeny::TooManyArgs));
        assert_eq!(
            run_local_command("/nonexistent-sinabro-binary-xyz"),
            Err(ExecDeny::SpawnFailed)
        );
        assert_eq!(
            ExecDeny::SpawnFailed.class_label(),
            "exec_local.spawn_failed"
        );
    }

    /// A nonzero exit code is captured honestly (stderr path too).
    #[test]
    #[cfg(unix)]
    fn nonzero_exit_and_stderr_capture() {
        let outcome = run_local_command("/bin/ls /nonexistent-dir-sinabro").expect("spawns");
        assert_ne!(outcome.exit_code, Some(0));
        assert!(!outcome.timed_out);
        assert!(outcome.stderr.total_bytes_u64 > 0, "ls complains on stderr");
    }
}
