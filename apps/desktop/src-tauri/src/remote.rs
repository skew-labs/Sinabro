// remote.rs — VM lane (A1): SSH-exec remote dispatch.
//
// Security contract: ops/evidence/stage_g/gui_desktop/SSH_REMOTE_DISPATCH_THREAT_MODEL.md.
// PHYSICS the design sketch missed (F1): the SSH exec channel JOINS the command
// args into ONE string which the REMOTE login shell re-interprets — discrete
// args handed to the local `ssh` process do NOT survive to the remote side. So
// every remote token must pass a closed charset gate AND is POSIX single-quoted
// (M1). The ssh destination is parsed + validated so it can never be read as an
// option (M3), host keys pin to an app-owned known_hosts file — TOFU then
// fail-closed (M4) — and auth is BatchMode only (keys/agent, nothing
// interactive, M5). Every failure here is a typed error rendered to the user;
// NEVER a silent local fallback (M6).

use std::path::Path;

/// Non-alphanumeric bytes allowed in a remote command token (M1 charset gate).
/// Covers the real dispatch surface (verbs, `--dry-run` flags, `k=v` args, the
/// typed approval phrase) while excluding every shell-significant byte.
const TOKEN_EXTRA: &str = "-_.:/=+,@";

/// M1: a remote token must be non-empty ASCII inside the closed charset.
pub fn validate_token(token: &str) -> bool {
    !token.is_empty()
        && token
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || TOKEN_EXTRA.contains(c))
}

/// POSIX single-quote a token for the remote shell (belt-and-braces under the
/// charset gate, which already excludes `'`).
pub fn quote_token(token: &str) -> String {
    let mut quoted = String::with_capacity(token.len() + 2);
    quoted.push('\'');
    for c in token.chars() {
        if c == '\'' {
            quoted.push_str("'\\''");
        } else {
            quoted.push(c);
        }
    }
    quoted.push('\'');
    quoted
}

/// A validated `user@host[:port]` ssh destination (M3).
pub struct SshTarget {
    pub user: String,
    pub host: String,
    pub port: Option<u16>,
}

/// Closed charset for ssh user/host names; a leading `-` is rejected so the
/// destination can never parse as an ssh option (M3).
fn valid_name(part: &str) -> bool {
    !part.is_empty()
        && !part.starts_with('-')
        && part
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || "-_.".contains(c))
}

/// Parse + validate an ssh target. Reject-not-fix: anything outside
/// `user@host[:port]` with the closed charset is a typed error (blocks ssh
/// option injection via a leading `-` or a `ProxyCommand`-style "hostname").
pub fn parse_target(raw: &str) -> Result<SshTarget, String> {
    let (user, rest) = raw
        .split_once('@')
        .ok_or_else(|| format!("ssh target must be user@host[:port], got '{raw}'"))?;
    let (host, port) = match rest.split_once(':') {
        Some((h, p)) => {
            let port: u16 = p
                .parse()
                .map_err(|_| format!("invalid ssh port '{p}' in target '{raw}'"))?;
            (h, Some(port))
        }
        None => (rest, None),
    };
    if !valid_name(user) {
        return Err(format!("invalid ssh user '{user}' in target '{raw}'"));
    }
    if !valid_name(host) {
        return Err(format!("invalid ssh host '{host}' in target '{raw}'"));
    }
    Ok(SshTarget {
        user: user.to_string(),
        host: host.to_string(),
        port,
    })
}

/// Build the full local `ssh` argv (M1+M3+M4+M5). Pure — unit-testable with no
/// network. The remote command is ONE explicitly-quoted string because that is
/// what the SSH exec channel actually transports (F1).
pub fn build_ssh_args(
    target: &SshTarget,
    known_hosts: &Path,
    argv: &[String],
) -> Result<Vec<String>, String> {
    for token in argv {
        if !validate_token(token) {
            return Err(format!(
                "token rejected by the remote charset gate (M1): '{token}'"
            ));
        }
    }
    let remote_cmd = std::iter::once("sinabro".to_string())
        .chain(argv.iter().cloned())
        .map(|t| quote_token(&t))
        .collect::<Vec<_>>()
        .join(" ");
    let mut args: Vec<String> = vec![
        "-o".into(),
        "BatchMode=yes".into(),
        "-o".into(),
        "StrictHostKeyChecking=accept-new".into(),
        "-o".into(),
        format!("UserKnownHostsFile={}", known_hosts.display()),
        "-o".into(),
        "ConnectTimeout=10".into(),
    ];
    if let Some(port) = target.port {
        args.push("-p".into());
        args.push(port.to_string());
    }
    args.push("--".into());
    args.push(format!("{}@{}", target.user, target.host));
    args.push(remote_cmd);
    Ok(args)
}

/// Execute ONE dispatch on the VM and return the rendered text. The card is
/// explicitly labeled with the executing host (M6) and a non-zero remote exit
/// is surfaced, never masked.
pub fn dispatch_ssh(target_raw: &str, app_data: &Path, argv: &[String]) -> Result<String, String> {
    let target = parse_target(target_raw)?;
    let known_hosts = app_data.join("vm_known_hosts");
    if let Some(parent) = known_hosts.parent() {
        std::fs::create_dir_all(parent).map_err(|e| e.to_string())?;
    }
    let args = build_ssh_args(&target, &known_hosts, argv)?;
    let output = std::process::Command::new("ssh")
        .args(&args)
        .output()
        .map_err(|e| format!("failed to spawn ssh: {e}"))?;
    let mut rendered = String::from_utf8_lossy(&output.stdout).into_owned();
    let stderr = String::from_utf8_lossy(&output.stderr);
    match output.status.code() {
        Some(0) => {}
        // 255 = the ssh client's own failure (auth / network / host-key
        // mismatch) — a typed error card; NEVER a silent local fallback (M6).
        Some(255) => {
            return Err(format!("ssh transport failure: {}", stderr.trim()));
        }
        Some(code) => {
            rendered.push_str(&format!("\nremote_exit={code}"));
        }
        None => return Err("ssh terminated by a signal".to_string()),
    }
    if !stderr.trim().is_empty() {
        rendered.push_str("\n[stderr] ");
        rendered.push_str(stderr.trim_end());
    }
    rendered.push_str(&format!("\nhost=vm:{}@{}", target.user, target.host));
    Ok(rendered)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn token_gate_accepts_the_real_dispatch_surface() {
        for ok in [
            "provider",
            "status",
            "put-fixture",
            "publish-synthetic-fixture-to-walrus-testnet",
            "--dry-run",
            "k=v",
            "a.b:c/d+e,f@g",
            "123",
        ] {
            assert!(validate_token(ok), "should accept {ok}");
        }
    }

    #[test]
    fn token_gate_rejects_shell_significant_bytes() {
        for bad in [
            "", "a b", "a;b", "$(x)", "`x`", "a'b", "a\"b", "a|b", "a&b", "a>b", "a<b", "a\\b",
            "a*b", "a(b", "a)b", "a{b", "a~b", "a!b", "한글", "a\nb", "a\tb",
        ] {
            assert!(!validate_token(bad), "should reject {bad:?}");
        }
    }

    #[test]
    fn quoting_is_posix_single_quote() {
        assert_eq!(quote_token("abc"), "'abc'");
        assert_eq!(quote_token("a'b"), "'a'\\''b'");
    }

    #[test]
    fn target_parse_accepts_user_host_port() {
        let t = parse_target("ubuntu@203.0.113.7").expect("plain target");
        assert_eq!(
            (t.user.as_str(), t.host.as_str(), t.port),
            ("ubuntu", "203.0.113.7", None)
        );
        let t = parse_target("dev@vm.example.com:2222").expect("target with port");
        assert_eq!(t.port, Some(2222));
    }

    #[test]
    fn target_parse_rejects_option_injection_shapes() {
        for bad in [
            "nohost",
            "-oProxyCommand=x@h",
            "u@-h",
            "u@h:99999",
            "u@h:abc",
            "u@",
            "@h",
            "u@h x",
            "u@h;i",
            "u u@h",
        ] {
            assert!(parse_target(bad).is_err(), "should reject {bad}");
        }
    }

    #[test]
    fn ssh_argv_is_pinned_and_quoted() {
        let target = parse_target("ubuntu@vm.example.com:2222").expect("target");
        let argv = vec!["provider".to_string(), "status".to_string()];
        let args = build_ssh_args(&target, Path::new("/tmp/kh"), &argv).expect("args");
        let expected: Vec<String> = [
            "-o",
            "BatchMode=yes",
            "-o",
            "StrictHostKeyChecking=accept-new",
            "-o",
            "UserKnownHostsFile=/tmp/kh",
            "-o",
            "ConnectTimeout=10",
            "-p",
            "2222",
            "--",
            "ubuntu@vm.example.com",
            "'sinabro' 'provider' 'status'",
        ]
        .into_iter()
        .map(String::from)
        .collect();
        assert_eq!(args, expected);
    }

    #[test]
    fn ssh_argv_refuses_a_bad_token() {
        let target = parse_target("u@h").expect("target");
        let argv = vec!["provider".to_string(), "status;rm".to_string()];
        assert!(build_ssh_args(&target, Path::new("/tmp/kh"), &argv).is_err());
    }
}
