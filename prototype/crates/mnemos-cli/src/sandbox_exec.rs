//! OS-enforced skill sandbox — kernel-confined bounded execution (ENDGAME E6).
//! Threat model: `ops/evidence/stage_g/agent_loop/SKILL_SANDBOX_THREAT_MODEL.md`
//! (⑫ IV-S1..S12). Owner-ratified 2026-06-12 (AskUserQuestion): **B+Seatbelt** —
//! a skill runs as a bounded child process whose capability ceiling is enforced
//! at the macOS kernel by `sandbox-exec` (Seatbelt), NOT a struct-field label
//! (PD-2). NO new crate (std-only + the OS `sandbox-exec` binary).
//!
//! ## What this module owns
//!
//! * **The tier → profile map** ([`seatbelt_profile_for`]) — a PURE TOTAL
//!   function over the closed [`SandboxTier`] enum (IV-S7: a skill never supplies
//!   profile text). The kernel-separable axes for a spawned PROCESS are NETWORK
//!   and FILE-WRITE; FILE-READ is always allowed (the *process floor* — a child
//!   must read its own binary + dyld to start; `(deny default)` kernel-blocks
//!   `execvp`). A finer PureCompute↔ReadLocal separation needs an in-proc VM
//!   (DEFERRED with the wasm go-live gate — stated honestly, not overclaimed).
//! * **Fail-closed admission** ([`run_in_sandbox`]) — if the kernel sandbox
//!   primitive is unavailable (non-macOS, or the binary is gone) the run is
//!   DENIED, NEVER executed unsandboxed (IV-S9 · [[no-disabled-path-workaround]]).
//!
//! ## What it REUSES (no second spawn discipline — no drift)
//!
//! The bounded child itself is [`crate::exec_local::run_argv_command_with`]: the
//! proven env-scrub (IV-E3 — keys never cross), wall-clock timeout + kill + reap
//! (IV-E4 — no zombie), per-stream byte caps (IV-E4), pinned cwd (IV-E7), and the
//! argv-only no-shell contract (IV-E2). This layer only PREPENDS the
//! `sandbox-exec -p <profile> --` wrapper as leading argv elements, so the same
//! walls bound a kernel-confined child. Custody (PD-6) is untouched: no
//! wallet/chain/funds symbol exists here, and a non-Networked tier is
//! kernel-denied a socket (no chain RPC reachable).

use crate::commands::capability::CapabilityKind;
use crate::commands::sandbox::SandboxTier;
use crate::exec_local::{
    EXEC_MAX_ARGS, EXEC_MAX_LINE_BYTES, EXEC_STREAM_CAP_BYTES, EXEC_TIMEOUT_MS, ExecDeny,
    ExecOutcome, run_argv_command_with_env,
};

/// The canonical macOS Seatbelt wrapper binary. An absolute path (IV-E2: no
/// `$PATH` resolution of the wrapper itself).
pub const SANDBOX_EXEC_PATH: &str = "/usr/bin/sandbox-exec";

/// The number of leading argv elements the wrapper prepends:
/// `sandbox-exec`, `-p`, `<profile>`, `--`.
pub const SANDBOX_WRAPPER_ARGC: usize = 4;

/// Typed, data-free denial reasons for an OS-sandboxed run. A superset of the
/// pre-spawn [`ExecDeny`] walls plus the fail-closed "no kernel sandbox".
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
#[non_exhaustive]
pub enum SandboxRunDeny {
    /// IV-S9 fail-CLOSED: no kernel sandbox primitive is available on this host
    /// (non-macOS, or `sandbox-exec` is absent). The run is DENIED — a skill is
    /// NEVER executed without its kernel ceiling.
    SandboxUnavailable,
    /// The skill command would have more argv entries than fit under the wrapper
    /// (`> EXEC_MAX_ARGS - SANDBOX_WRAPPER_ARGC`).
    SkillArgvTooMany,
    /// A pre-spawn [`exec_local`] wall (empty / line-too-long / spawn-failed).
    Exec(ExecDeny),
}

impl SandboxRunDeny {
    /// Stable, allow-listed `class_label` (namespaced `sandbox_exec.*`).
    #[inline]
    #[must_use]
    pub const fn class_label(self) -> &'static str {
        match self {
            Self::SandboxUnavailable => "sandbox_exec.unavailable",
            Self::SkillArgvTooMany => "sandbox_exec.skill_argv_too_many",
            Self::Exec(deny) => deny.class_label(),
        }
    }
}

/// Whether the kernel sandbox primitive is available on this host. macOS only,
/// and only when the `sandbox-exec` binary exists. On every other platform this
/// is `false` BY CONSTRUCTION ⇒ [`run_in_sandbox`] fail-closes (IV-S9).
#[must_use]
pub fn seatbelt_available() -> bool {
    cfg!(target_os = "macos") && std::path::Path::new(SANDBOX_EXEC_PATH).is_file()
}

/// The Seatbelt (SBPL) profile that kernel-enforces `tier`'s capability ceiling
/// (IV-S1/S3/S7). PURE + TOTAL over the closed [`SandboxTier`] enum; derived from
/// the [`CapabilityKind`] ladder, NEVER from skill-supplied bytes.
///
/// Semantics (smoke-proven 2026-06-12, SBPL "last rule wins"):
/// `(allow default)` then SUBTRACT the axes the ceiling lacks:
/// * `(deny network*)` ⟺ ceiling `!contains(Network)` — kernel-blocks a socket
///   (IV-S4: a non-Networked tier physically cannot egress / reach a chain RPC).
/// * `(deny file-write*)` ⟺ ceiling `!contains(WriteLocal)` — kernel-blocks a
///   filesystem write (read still works; a pipe write to stdout is not a
///   file-write).
/// * FILE-READ is never denied (the process floor).
#[must_use]
pub fn seatbelt_profile_for(tier: SandboxTier) -> String {
    let ceiling = tier.capability_ceiling();
    let mut profile = String::from("(version 1)(allow default)");
    if !ceiling.contains(CapabilityKind::Network) {
        profile.push_str("(deny network*)");
    }
    if !ceiling.contains(CapabilityKind::WriteLocal) {
        profile.push_str("(deny file-write*)");
    }
    profile
}

/// Run one bounded skill command INSIDE the kernel-enforced ceiling of `tier`.
///
/// Gate order (the threat model's): fail-closed admission (IV-S9) → pre-spawn
/// argv walls (IV-E2 reused, IV-S6) → pure tier→profile (IV-S7) → the
/// `sandbox-exec`-wrapped child through the SAME env-scrub / timeout / byte-cap /
/// cwd-pin discipline (IV-E3/E4/E7). The returned [`ExecOutcome`]'s `exit_code`
/// is the inner child's code on success; the RENDER (dispatch) redacts the
/// captured streams before display (SI-2, IV-S10).
pub fn run_in_sandbox(
    tier: SandboxTier,
    line: &str,
    timeout_ms: u64,
    stream_cap_bytes: usize,
    env_excludes: &[&str],
) -> Result<ExecOutcome, SandboxRunDeny> {
    // IV-S9: no kernel sandbox ⇒ DENY (never an unsandboxed fallback).
    if !seatbelt_available() {
        return Err(SandboxRunDeny::SandboxUnavailable);
    }
    // Pre-spawn walls on the SKILL line (reuse the exec_local bounds, IV-S6).
    if line.len() > EXEC_MAX_LINE_BYTES {
        return Err(SandboxRunDeny::Exec(ExecDeny::LineTooLong));
    }
    let skill_argv: Vec<String> = line.split_whitespace().map(str::to_string).collect();
    if skill_argv.is_empty() {
        return Err(SandboxRunDeny::Exec(ExecDeny::EmptyArgv));
    }
    // The wrapped argv must still fit the spawn arg cap.
    if skill_argv.len() > EXEC_MAX_ARGS - SANDBOX_WRAPPER_ARGC {
        return Err(SandboxRunDeny::SkillArgvTooMany);
    }
    // IV-S7: the profile is derived from the tier alone (a closed enum), never
    // from the skill — it rides as ONE argv element (never whitespace re-split).
    let profile = seatbelt_profile_for(tier);
    let mut argv: Vec<String> = Vec::with_capacity(skill_argv.len() + SANDBOX_WRAPPER_ARGC);
    argv.push(SANDBOX_EXEC_PATH.to_string());
    argv.push("-p".to_string());
    argv.push(profile);
    argv.push("--".to_string());
    argv.extend(skill_argv);
    run_argv_command_with_env(argv, timeout_ms, stream_cap_bytes, env_excludes)
        .map_err(SandboxRunDeny::Exec)
}

/// [`run_in_sandbox`] with the default bounds ([`EXEC_TIMEOUT_MS`] /
/// [`EXEC_STREAM_CAP_BYTES`]) and the full env allowlist (no extra withholding).
pub fn run_in_sandbox_default(
    tier: SandboxTier,
    line: &str,
) -> Result<ExecOutcome, SandboxRunDeny> {
    run_in_sandbox(tier, line, EXEC_TIMEOUT_MS, EXEC_STREAM_CAP_BYTES, &[])
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use super::*;

    // ---- pure tier → profile mapping (deterministic, the kernel contract) ----

    #[test]
    fn profile_denies_network_for_every_non_networked_tier() {
        // Strict / ReadOnly / LocalWrite ceilings lack Network ⇒ kernel no-egress.
        for tier in [
            SandboxTier::Strict,
            SandboxTier::ReadOnly,
            SandboxTier::LocalWrite,
        ] {
            let p = seatbelt_profile_for(tier);
            assert!(
                p.contains("(deny network*)"),
                "{tier:?} must kernel-deny network (IV-S4): {p}"
            );
        }
        // Networked / Privileged carry Network ⇒ no network deny.
        for tier in [SandboxTier::Networked, SandboxTier::Privileged] {
            let p = seatbelt_profile_for(tier);
            assert!(
                !p.contains("(deny network*)"),
                "{tier:?} permits network: {p}"
            );
        }
    }

    #[test]
    fn profile_denies_write_only_below_localwrite() {
        for tier in [SandboxTier::Strict, SandboxTier::ReadOnly] {
            assert!(
                seatbelt_profile_for(tier).contains("(deny file-write*)"),
                "{tier:?} must kernel-deny file-write"
            );
        }
        for tier in [
            SandboxTier::LocalWrite,
            SandboxTier::Networked,
            SandboxTier::Privileged,
        ] {
            assert!(
                !seatbelt_profile_for(tier).contains("(deny file-write*)"),
                "{tier:?} permits file-write"
            );
        }
    }

    #[test]
    fn profile_always_starts_with_version_and_allow_default() {
        // The process floor: file-read is never denied (no `(deny file-read*)`).
        for tier in [
            SandboxTier::Strict,
            SandboxTier::ReadOnly,
            SandboxTier::LocalWrite,
            SandboxTier::Networked,
            SandboxTier::Privileged,
        ] {
            let p = seatbelt_profile_for(tier);
            assert!(p.starts_with("(version 1)(allow default)"), "{tier:?}: {p}");
            assert!(!p.contains("(deny file-read*)"), "{tier:?} keeps the floor");
        }
    }

    // ---- pre-spawn walls (typed denials, no child) --------------------------

    #[test]
    fn empty_and_oversized_skill_lines_are_typed_denials() {
        // These walls fire BEFORE any spawn — but only once the sandbox is
        // available; on a non-macOS host the fail-closed wall fires first.
        if !seatbelt_available() {
            assert_eq!(
                run_in_sandbox_default(SandboxTier::Strict, "   "),
                Err(SandboxRunDeny::SandboxUnavailable)
            );
            return;
        }
        assert_eq!(
            run_in_sandbox_default(SandboxTier::Strict, "   "),
            Err(SandboxRunDeny::Exec(ExecDeny::EmptyArgv))
        );
        let long = "x".repeat(EXEC_MAX_LINE_BYTES + 1);
        assert_eq!(
            run_in_sandbox_default(SandboxTier::Strict, &long),
            Err(SandboxRunDeny::Exec(ExecDeny::LineTooLong))
        );
        let many = vec!["a"; EXEC_MAX_ARGS].join(" ");
        assert_eq!(
            run_in_sandbox_default(SandboxTier::Strict, &many),
            Err(SandboxRunDeny::SkillArgvTooMany)
        );
    }

    #[test]
    fn class_labels_are_stable() {
        assert_eq!(
            SandboxRunDeny::SandboxUnavailable.class_label(),
            "sandbox_exec.unavailable"
        );
        assert_eq!(
            SandboxRunDeny::SkillArgvTooMany.class_label(),
            "sandbox_exec.skill_argv_too_many"
        );
        assert_eq!(
            SandboxRunDeny::Exec(ExecDeny::SpawnFailed).class_label(),
            "exec_local.spawn_failed"
        );
    }

    // ---- live kernel-enforcement proofs (macOS only) -----------------------

    /// The floor: pure compute runs under EVERY tier (the sandbox is functional
    /// and `execvp` + stdout-pipe are never blocked, even under deny-write).
    #[test]
    #[cfg(target_os = "macos")]
    fn pure_compute_runs_under_every_tier() {
        assert!(seatbelt_available(), "macOS host must have sandbox-exec");
        for tier in [
            SandboxTier::Strict,
            SandboxTier::ReadOnly,
            SandboxTier::LocalWrite,
            SandboxTier::Networked,
            SandboxTier::Privileged,
        ] {
            let outcome = run_in_sandbox_default(tier, "/bin/echo e6_floor_ok")
                .unwrap_or_else(|e| panic!("{tier:?} echo must run: {e:?}"));
            assert_eq!(outcome.exit_code, Some(0), "{tier:?} echo exit");
            assert_eq!(outcome.stdout.retained, b"e6_floor_ok\n", "{tier:?} stdout");
            assert!(!outcome.timed_out);
        }
    }

    /// IV-S1: file-write is kernel-gated by tier. `touch` (a real fs write,
    /// argv-only) is DENIED under Strict (no WriteLocal) and ALLOWED under
    /// LocalWrite — the difference is the kernel, not a struct field.
    #[test]
    #[cfg(target_os = "macos")]
    fn file_write_is_kernel_gated_by_tier() {
        assert!(seatbelt_available());
        let denied_path = "/tmp/e6_sandbox_write_denied_marker";
        let allowed_path = "/tmp/e6_sandbox_write_allowed_marker";
        let _ = std::fs::remove_file(denied_path);
        let _ = std::fs::remove_file(allowed_path);

        // Strict (deny file-write*): touch must FAIL and create nothing.
        let strict = run_in_sandbox_default(
            SandboxTier::Strict,
            &format!("/usr/bin/touch {denied_path}"),
        )
        .expect("spawns under the sandbox");
        assert_ne!(
            strict.exit_code,
            Some(0),
            "Strict must kernel-deny the write"
        );
        assert!(
            !std::path::Path::new(denied_path).exists(),
            "no file may exist after a denied write"
        );

        // LocalWrite (write permitted): touch must SUCCEED and create the file.
        let lw = run_in_sandbox_default(
            SandboxTier::LocalWrite,
            &format!("/usr/bin/touch {allowed_path}"),
        )
        .expect("spawns under the sandbox");
        assert_eq!(lw.exit_code, Some(0), "LocalWrite permits the write");
        assert!(
            std::path::Path::new(allowed_path).exists(),
            "the file must exist after a permitted write"
        );
        let _ = std::fs::remove_file(allowed_path);
    }

    /// IV-S4 (the load-bearing egress proof): under a non-Networked tier the
    /// kernel BLOCKS the `socket()` syscall — a skill physically cannot egress.
    /// Uses `/usr/bin/python3` (present on macOS) to attempt an outbound connect;
    /// `PermissionError` (the sandbox kill) ⇒ the script exits 13. If python3 is
    /// absent the deterministic profile-string assertion still pins the contract.
    #[test]
    #[cfg(target_os = "macos")]
    fn non_networked_tier_kernel_denies_egress() {
        assert!(seatbelt_available());
        assert!(
            seatbelt_profile_for(SandboxTier::LocalWrite).contains("(deny network*)"),
            "LocalWrite must carry the network deny"
        );
        if !std::path::Path::new("/usr/bin/python3").is_file() {
            return; // profile-string contract above is the proof on this host
        }
        // Write the probe to a no-space temp path (argv-only: the path is one arg).
        let script = "/tmp/e6_sandbox_egress_probe.py";
        std::fs::write(
            script,
            "import socket,sys\n\
             try:\n\
             \x20 s=socket.socket(); s.settimeout(2); s.connect((\"127.0.0.1\",9))\n\
             \x20 print(\"OPENED\"); sys.exit(0)\n\
             except PermissionError:\n\
             \x20 print(\"KERNEL_DENIED\"); sys.exit(13)\n\
             except Exception as e:\n\
             \x20 print(\"OTHER\", type(e).__name__); sys.exit(7)\n",
        )
        .expect("write probe");
        let out = run_in_sandbox_default(
            SandboxTier::LocalWrite,
            &format!("/usr/bin/python3 {script}"),
        )
        .expect("spawns under the sandbox");
        let _ = std::fs::remove_file(script);
        assert_eq!(
            out.exit_code,
            Some(13),
            "LocalWrite must KERNEL-DENY the socket (got {:?}, stdout={:?})",
            out.exit_code,
            String::from_utf8_lossy(&out.stdout.retained)
        );
    }
}
