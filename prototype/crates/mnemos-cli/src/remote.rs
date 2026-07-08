//! Owner-box / remote-shell lane — the highest-risk surface.
//!
//! # The one place sinabro runs a command on a REMOTE box
//!
//! A NEW credentialed-remote capability (no SSH lane existed). Transport =
//! OpenSSH subprocess; command surface = READ-only diagnostic allowlist v1.
//! `daemon remote-run <ARM_PHRASE> <command-token>` runs ONE READ-only diagnostic on the
//! owner's CONFIGURED remote box.
//!
//! Walls:
//! * [`RemoteCommand`] — a closed READ-only allowlist; the on-wire command is a FIXED
//!   literal per variant. An arbitrary shell / a write / a chain-write is
//!   UNREPRESENTABLE.
//! * [`classify_remote_host`] — the host comes ONLY from `remote_ssh_host` config and is
//!   validated (no leading `-` option-injection, no whitespace / shell metacharacters,
//!   safe charset).
//! * the `ssh` binary runs UNDER a Seatbelt profile (network ALLOWED; local writes confined
//!   to `~/.ssh` + `/dev/null`); the credential never enters sinabro (the OS ssh config
//!   handles auth). [`render_remote_run`] requires an [`EgressCapability`]
//!   witness (owner-armed; the model holds no constructor).
//! * the output is `redact()`-gated; custody/chain-write is HARD-LOCKED.

use std::path::PathBuf;

use crate::commands::authority::EgressCapability;
use crate::exec_local::{EXEC_STREAM_CAP_BYTES, EXEC_TIMEOUT_MS, run_argv_command_with_env};

/// The owner-arm phrase for the remote-run ceremony (the model cannot type it).
pub const REMOTE_RUN_ARM_PHRASE: &str = "arm-remote-shell-read-diagnostic-bounded";

/// The ssh connect timeout (seconds) — a bounded dial.
const SSH_CONNECT_TIMEOUT_SECS: u32 = 8;

/// The READ-only remote diagnostic allowlist. The enum is the command wall: a write /
/// arbitrary shell / chain-write command is simply NOT a variant — it cannot be
/// constructed, so only a fixed READ diagnostic can run on the remote box.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RemoteCommand {
    /// `whoami` — the remote login user.
    Whoami,
    /// `uname -a` — the remote kernel / arch.
    Uname,
    /// `df -h` — remote disk free.
    DiskFree,
    /// `git status --short` — the remote login-dir repo status (honest error if not a repo).
    GitStatus,
    /// `git rev-parse --short HEAD` — the remote login-dir repo HEAD.
    GitRevParse,
}

impl RemoteCommand {
    /// The on-wire remote command string (a FIXED literal — never user input). READ-only.
    #[must_use]
    pub const fn wire_str(self) -> &'static str {
        match self {
            Self::Whoami => "whoami",
            Self::Uname => "uname -a",
            Self::DiskFree => "df -h",
            Self::GitStatus => "git status --short",
            Self::GitRevParse => "git rev-parse --short HEAD",
        }
    }

    /// The stable CLI token that selects this command.
    #[must_use]
    pub const fn token(self) -> &'static str {
        match self {
            Self::Whoami => "whoami",
            Self::Uname => "uname",
            Self::DiskFree => "df",
            Self::GitStatus => "git-status",
            Self::GitRevParse => "git-head",
        }
    }

    /// Every READ-only command (for the allowlist render + parse).
    #[must_use]
    pub const fn all() -> [Self; 5] {
        [
            Self::Whoami,
            Self::Uname,
            Self::DiskFree,
            Self::GitStatus,
            Self::GitRevParse,
        ]
    }

    /// Parse a CLI token into a READ command (fail-closed: an unknown token — INCLUDING any
    /// write / arbitrary command — yields `None`, never a guessed command).
    #[must_use]
    pub fn parse(token: &str) -> Option<Self> {
        let t = token.trim();
        Self::all().into_iter().find(|c| c.token() == t)
    }

    /// A space-joined list of every read token (for the honest usage render).
    #[must_use]
    pub fn token_list() -> String {
        Self::all()
            .iter()
            .map(|c| c.token())
            .collect::<Vec<_>>()
            .join(" ")
    }
}

/// Why a remote run was denied (fail-closed; explicit).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RemoteDeny {
    /// No `remote_ssh_host` is configured (nothing to dial).
    NoHostConfigured,
    /// The host is empty / whitespace.
    EmptyHost,
    /// The host begins with `-` (an ssh option-injection vector).
    OptionInjection,
    /// The host carries whitespace / a shell metacharacter / an illegal char.
    UnsafeHostChars,
    /// The host's `:port` suffix is not a valid 1..=65535 port.
    BadPort,
    /// The CLI token did not name a READ command (a write / arbitrary command is not a token).
    UnknownCommand,
    /// No kernel sandbox is available (NEVER run ssh unsandboxed, fail-closed).
    SandboxUnavailable,
    /// The `ssh` binary is absent on PATH.
    SshUnavailable,
    /// The sandboxed ssh spawn failed.
    SpawnFailed,
    /// ssh exited non-zero (connect refused / auth failed / remote error).
    SshFailed,
    /// The remote output was secret-shaped — WITHHELD.
    SecretShapedOutput,
}

impl RemoteDeny {
    /// A stable, secret-free class label.
    #[must_use]
    pub const fn class_label(self) -> &'static str {
        match self {
            Self::NoHostConfigured => "remote.host.not_configured",
            Self::EmptyHost => "remote.host.empty",
            Self::OptionInjection => "remote.host.option_injection",
            Self::UnsafeHostChars => "remote.host.unsafe_chars",
            Self::BadPort => "remote.host.bad_port",
            Self::UnknownCommand => "remote.command.unknown",
            Self::SandboxUnavailable => "remote.sandbox.unavailable",
            Self::SshUnavailable => "remote.ssh.unavailable",
            Self::SpawnFailed => "remote.ssh.spawn_failed",
            Self::SshFailed => "remote.ssh.failed",
            Self::SecretShapedOutput => "remote.output.withheld_secret",
        }
    }
}

/// A validated remote host: the ssh host argument (`[user@]hostname`) + an optional port.
/// Construction is the proof it passed [`classify_remote_host`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SafeRemoteHost {
    host_arg: String,
    port: Option<u16>,
}

impl SafeRemoteHost {
    /// The ssh host argument (`[user@]hostname` — no port).
    #[must_use]
    pub fn host_arg(&self) -> &str {
        &self.host_arg
    }

    /// The port, if a `:port` suffix was given (else ssh's default 22).
    #[must_use]
    pub fn port(&self) -> Option<u16> {
        self.port
    }
}

/// Whether `c` is allowed in an ssh `[user@]hostname` (alphanumeric + `.` `-` `_` `@`). NO
/// `:` (parsed out as the port), NO `/`, NO whitespace, NO shell metacharacter.
fn is_host_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_' | '@')
}

/// Validate the OWNER-CONFIGURED remote host — PURE, no IO. Admit only
/// `[user@]hostname[:port]` with a safe charset: non-empty, no leading `-` (ssh
/// option-injection), no whitespace / shell metacharacter, and (if present) a numeric
/// 1..=65535 port. There is NO arbitrary-host argument — `raw` is the config value.
pub fn classify_remote_host(raw: &str) -> Result<SafeRemoteHost, RemoteDeny> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Err(RemoteDeny::EmptyHost);
    }
    // Split an optional `:port` suffix (the LAST `:` whose suffix is all-numeric).
    let (host_part, port) = match trimmed.rsplit_once(':') {
        Some((h, p)) if !p.is_empty() && p.bytes().all(|b| b.is_ascii_digit()) => {
            let port: u16 = p.parse().map_err(|_| RemoteDeny::BadPort)?;
            if port == 0 {
                return Err(RemoteDeny::BadPort);
            }
            (h, Some(port))
        }
        // a trailing `:` or a non-numeric suffix is an unsafe host (no bare `:` allowed).
        Some(_) => return Err(RemoteDeny::UnsafeHostChars),
        None => (trimmed, None),
    };
    if host_part.is_empty() {
        return Err(RemoteDeny::EmptyHost);
    }
    if host_part.starts_with('-') {
        return Err(RemoteDeny::OptionInjection);
    }
    if !host_part.chars().all(is_host_char) {
        return Err(RemoteDeny::UnsafeHostChars);
    }
    Ok(SafeRemoteHost {
        host_arg: host_part.to_string(),
        port,
    })
}

/// The rendered outcome of a remote run: a secret-free result line + a stable label + an
/// `ok` flag.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RemoteRunRender {
    /// The rendered, secret-free result string (the redacted remote output).
    pub rendered: String,
    /// A stable, secret-free class label.
    pub class_label: &'static str,
    /// Whether the remote command ran successfully (a deny is `false`).
    pub ok: bool,
}

/// The bespoke remote-ssh Seatbelt profile: network ALLOWED (ssh needs it) but local writes
/// CONFINED to `~/.ssh` (known_hosts) + `/dev/null`; every other local write kernel-DENIED.
/// Mirrors the git-push net-allowed profile. `None` if the home path is unsafe for SBPL.
fn ssh_profile(home: &str) -> Option<String> {
    if home.contains('"') || home.contains('\\') {
        return None;
    }
    Some(format!(
        "(version 1)(allow default)(deny file-write*)(allow file-write* (subpath \"{home}/.ssh\") (literal \"/dev/null\"))"
    ))
}

/// Resolve a bare binary name to an absolute path by scanning `PATH` (honest presence
/// probe; `None` ⇒ absent ⇒ honest-degrade).
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

/// Whether `text` passes the canonical `redact()` secret gate (no secret-shaped byte).
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

fn deny(d: RemoteDeny) -> RemoteRunRender {
    RemoteRunRender {
        rendered: format!("remote run denied ({})", d.class_label()),
        class_label: d.class_label(),
        ok: false,
    }
}

/// The SHARED remote-run pipeline. REQUIRES an [`EgressCapability`] witness
/// (owner-armed — the model holds no constructor, so it cannot self-run a remote command).
/// Order: validate the CONFIG-ONLY host (no arbitrary host) → fail-closed sandbox admission →
/// resolve `ssh` → spawn `ssh` UNDER the net-allowed, `~/.ssh`-write-scoped Seatbelt profile
/// with a FIXED READ command (no arbitrary shell) → exit check → redact → render.
#[must_use]
pub fn render_remote_run(
    _cap: &EgressCapability,
    configured_host: Option<&str>,
    command: RemoteCommand,
) -> RemoteRunRender {
    use crate::sandbox_exec::{SANDBOX_EXEC_PATH, seatbelt_available};

    let Some(host) = configured_host.map(str::trim).filter(|h| !h.is_empty()) else {
        return deny(RemoteDeny::NoHostConfigured);
    };
    let safe = match classify_remote_host(host) {
        Ok(safe) => safe,
        Err(d) => return deny(d),
    };
    if !seatbelt_available() {
        return deny(RemoteDeny::SandboxUnavailable);
    }
    let Some(ssh_bin) = resolve_on_path("ssh") else {
        return deny(RemoteDeny::SshUnavailable);
    };
    let home = std::env::var("HOME").unwrap_or_default();
    let Some(profile) = ssh_profile(&home) else {
        return deny(RemoteDeny::UnsafeHostChars);
    };
    // sandbox-exec -p <profile> -- ssh -o BatchMode=yes -o StrictHostKeyChecking=accept-new
    //   -o ConnectTimeout=N [-p <port>] <host> <FIXED read command>
    let mut argv: Vec<String> = vec![
        SANDBOX_EXEC_PATH.to_string(),
        "-p".to_string(),
        profile,
        "--".to_string(),
        ssh_bin.display().to_string(),
        "-o".to_string(),
        "BatchMode=yes".to_string(),
        "-o".to_string(),
        "StrictHostKeyChecking=accept-new".to_string(),
        "-o".to_string(),
        format!("ConnectTimeout={SSH_CONNECT_TIMEOUT_SECS}"),
    ];
    if let Some(port) = safe.port() {
        argv.push("-p".to_string());
        argv.push(port.to_string());
    }
    argv.push(safe.host_arg().to_string());
    // The remote command is a FIXED literal from the READ allowlist — one argv element
    // (no shell interpolation of any user token; the host already validated).
    argv.push(command.wire_str().to_string());

    let outcome = match run_argv_command_with_env(argv, EXEC_TIMEOUT_MS, EXEC_STREAM_CAP_BYTES, &[])
    {
        Ok(o) => o,
        Err(_) => return deny(RemoteDeny::SpawnFailed),
    };
    let mut combined = String::from_utf8_lossy(&outcome.stdout.retained).into_owned();
    let err = String::from_utf8_lossy(&outcome.stderr.retained);
    if !err.trim().is_empty() {
        if !combined.is_empty() {
            combined.push('\n');
        }
        combined.push_str(err.trim());
    }
    if outcome.exit_code != Some(0) {
        return RemoteRunRender {
            rendered: format!(
                "remote run ({}) on {}: ssh failed (exit {:?})",
                command.token(),
                safe.host_arg(),
                outcome.exit_code
            ),
            class_label: RemoteDeny::SshFailed.class_label(),
            ok: false,
        };
    }
    if !redact_passes(&combined) {
        return deny(RemoteDeny::SecretShapedOutput);
    }
    let body: String = combined.chars().take(4_000).collect();
    let rendered = format!(
        "remote run {token} on {host} (READ-only; owner-armed; sandboxed ssh; net-allowed, \
         local-write confined to ~/.ssh)\n{body}",
        token = command.token(),
        host = safe.host_arg(),
        body = body,
    );
    RemoteRunRender {
        rendered,
        class_label: "remote.run.ok",
        ok: true,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn command_tokens_round_trip_and_writes_unrepresentable() {
        for c in RemoteCommand::all() {
            assert_eq!(RemoteCommand::parse(c.token()), Some(c), "{}", c.token());
            assert!(!c.wire_str().is_empty());
        }
        // a write / arbitrary command is NOT a token ⇒ None (the enum has no such variant).
        for bad in [
            "rm",
            "sudo",
            "bash",
            "git push",
            "git push --force",
            "",
            "  ",
            "whoami; rm -rf /",
        ] {
            assert_eq!(RemoteCommand::parse(bad), None, "{bad}");
        }
        // the wire strings are READ-only (no push/rm/write).
        for c in RemoteCommand::all() {
            let w = c.wire_str();
            assert!(
                !w.contains("push") && !w.contains("rm ") && !w.contains(">"),
                "{w}"
            );
        }
    }

    #[test]
    fn host_validation_admits_safe_rejects_injection() {
        let ok = classify_remote_host("user@box.example.com").expect("ok");
        assert_eq!(ok.host_arg(), "user@box.example.com");
        assert_eq!(ok.port(), None);
        let ported = classify_remote_host("127.0.0.1:2222").expect("ok");
        assert_eq!(ported.host_arg(), "127.0.0.1");
        assert_eq!(ported.port(), Some(2222));
        // option injection + shell metacharacters + bad port are fail-closed.
        for (h, want) in [
            ("", RemoteDeny::EmptyHost),
            ("   ", RemoteDeny::EmptyHost),
            ("-oProxyCommand=evil", RemoteDeny::OptionInjection),
            ("host; rm -rf /", RemoteDeny::UnsafeHostChars),
            ("host`whoami`", RemoteDeny::UnsafeHostChars),
            ("host /etc/passwd", RemoteDeny::UnsafeHostChars),
            ("host:0", RemoteDeny::BadPort),
            ("host:notaport", RemoteDeny::UnsafeHostChars),
        ] {
            assert_eq!(classify_remote_host(h).unwrap_err(), want, "{h}");
        }
    }

    #[test]
    fn ssh_profile_is_net_allowed_and_write_scoped() {
        let p = ssh_profile("/Users/x").expect("profile");
        assert!(p.starts_with("(version 1)(allow default)"));
        assert!(p.contains("(deny file-write*)"));
        assert!(p.contains("/Users/x/.ssh"));
        // a home with a quote/backslash is rejected (SBPL injection).
        assert!(ssh_profile("/Users/\"x").is_none());
    }

    #[test]
    fn render_no_host_is_honest_deny() {
        let cap = crate::commands::authority::test_egress_capability();
        for h in [None, Some(""), Some("   ")] {
            let r = render_remote_run(&cap, h, RemoteCommand::Whoami);
            assert!(!r.ok);
            assert_eq!(r.class_label, "remote.host.not_configured");
        }
    }

    #[test]
    fn render_unsafe_host_never_spawns() {
        let cap = crate::commands::authority::test_egress_capability();
        let r = render_remote_run(&cap, Some("-oProxyCommand=evil"), RemoteCommand::Whoami);
        assert!(!r.ok);
        assert_eq!(r.class_label, "remote.host.option_injection");
    }

    #[test]
    fn class_labels_are_stable() {
        assert_eq!(
            RemoteDeny::OptionInjection.class_label(),
            "remote.host.option_injection"
        );
        assert_eq!(
            RemoteDeny::UnknownCommand.class_label(),
            "remote.command.unknown"
        );
    }
}
