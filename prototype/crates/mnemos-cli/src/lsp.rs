//! A① LSP language intelligence — a sandboxed language-server subprocess as a
//! READ capability (CURSOR PARITY keystone-1; design:
//! `ops/evidence/stage_g/agent_loop/CURSOR_PARITY_REFRAME_DESIGN.md` §3 A① + §6).
//!
//! ## Thesis (AXIS-2 / P-HALL, verify-oracle ethos)
//!
//! Diagnostics are COMPILER TRUTH, not a model guess. The REAL language server
//! (`rust-analyzer` for Rust/Solana, `move-analyzer` for Sui Move) runs as a
//! sandboxed child speaking LSP JSON-RPC over stdio; its ground truth feeds BOTH
//! the agent loop (a `TOOL: lsp diagnostics <path>` typed READ) AND a dispatch
//! verb (`context lsp-diagnostics <path>`). The agent reasons with the compiler's
//! verdict — stronger than an editor-only LSP.
//!
//! ## Security (the per-slice §7 invariants)
//!
//! * CAPABILITY = READ (T3) — the agent gets read-only diagnostics, never mutates.
//!   The NETWORK is ALWAYS kernel-DENIED (the load-bearing wall: no egress, custody
//!   unreachable). The sandbox tier is PER-LANGUAGE ([`lsp_seatbelt_profile`]):
//!   rust-analyzer = strict `ReadOnly` (deny network + deny file-write; in-memory);
//!   move-analyzer = the ReadOnly base PLUS a PATH-SCOPED write grant (it must write
//!   its `~/.move` dep cache/lock + run a `git` dep-check) — write confined to
//!   `~/.move`, the package dir, the system temp, and `/dev/null`; every other write
//!   stays denied (owner-locked 2026-06-16).
//! * REUSE, no second spawn DISCIPLINE: the same `seatbelt_profile_for` profile,
//!   the same `sandbox-exec -p <profile> --` wrapper, the same
//!   [`crate::exec_local::EXEC_ENV_ALLOWLIST`] env-scrub, and a pinned cwd. The
//!   only NEW element is the long-lived bidirectional pipe lifecycle that LSP
//!   inherently needs (the one-shot `run_argv_command_with_env` cannot drive a
//!   request/response protocol); the child is reaped on `Drop` (no zombie) and a
//!   reader thread + `recv_timeout` bound every read (no hang).
//! * HONEST-DEGRADE (invariant 3): an absent binary / non-macOS host /
//!   unavailable kernel sandbox / unsupported file type ⇒ an honest "not
//!   available" string, NEVER a fabricated or regex stand-in.
//! * REDACTION (SI-2): the rendered diagnostics pass the `redact()` wall before
//!   they enter a prompt or a display; a secret-shaped diagnostic ⇒ WITHHELD.
//! * CUSTODY untouched (PD-6): this path constructs no egress / mutate / custody
//!   capability and reaches no chain RPC or socket (the sandbox kernel-denies the
//!   network); user funds stay hard-locked behind the uninhabited custody type.
//!
//! ## Codec edge
//!
//! The JSON-RPC build/parse rides `serde_json` — the SAME optional workspace
//! codec the consult build already links (already in `Cargo.lock` ⇒ relock-free).
//! It is gated behind the off-default `lsp` feature; a build without it
//! honest-degrades ("the language-server codec is not compiled").
//!
//! ## Scope (v1)
//!
//! `lsp diagnostics <path>` only, Move + Rust (§9 Q2 owner lock 2026-06-16). NOT a
//! general multi-language IDE (§8 non-goal). `definition` / `references` are
//! documented follow-ons that reuse this client.

/// The languages sinabro targets (a Sui Move + Solana agent — NOT a universal
/// IDE). Detected from the file extension; anything else honest-degrades.
#[cfg(any(feature = "lsp", test))]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Lang {
    /// Rust (`rust-analyzer`) — covers Solana on-chain programs + the host crate.
    Rust,
    /// Sui Move (`move-analyzer`).
    Move,
}

#[cfg(any(feature = "lsp", test))]
impl Lang {
    /// Detect the language from a path's extension (ASCII, case-insensitive).
    /// `None` ⇒ an unsupported file type (honest-degrade, never guessed).
    #[must_use]
    pub fn detect(path: &str) -> Option<Self> {
        let lower = path.to_ascii_lowercase();
        if lower.ends_with(".rs") {
            Some(Self::Rust)
        } else if lower.ends_with(".move") {
            Some(Self::Move)
        } else {
            None
        }
    }

    /// The language server binary name (resolved on `PATH` before spawn).
    #[must_use]
    pub const fn server_bin(self) -> &'static str {
        match self {
            Self::Rust => "rust-analyzer",
            Self::Move => "move-analyzer",
        }
    }

    /// The LSP `languageId` for a `textDocument/didOpen`.
    #[must_use]
    pub const fn language_id(self) -> &'static str {
        match self {
            Self::Rust => "rust",
            Self::Move => "move",
        }
    }

    /// The project-manifest filename whose nearest ancestor is the analysis root
    /// (so an in-crate file gets crate scope, a standalone file is detached).
    #[must_use]
    pub const fn manifest(self) -> &'static str {
        match self {
            Self::Rust => "Cargo.toml",
            Self::Move => "Move.toml",
        }
    }
}

// ---------------------------------------------------------------------------
// LSP base framing — `Content-Length: N\r\n\r\n<body>`. PURE + bounded; testable
// over any `BufRead` with no subprocess. (Always present in an `lsp` or `test`
// build; absent — and therefore not dead — in a plain default build.)
// ---------------------------------------------------------------------------

/// The maximum body of ONE LSP message we accept (a DoS bound — a server that
/// announces a larger `Content-Length` is refused, never buffered).
#[cfg(any(feature = "lsp", test))]
pub const LSP_MAX_FRAME_BYTES: usize = 4 * 1024 * 1024;

/// Frame a JSON-RPC body with the LSP base-protocol header.
#[cfg(any(feature = "lsp", test))]
#[must_use]
pub fn encode_frame(body: &[u8]) -> Vec<u8> {
    let header = format!("Content-Length: {}\r\n\r\n", body.len());
    let mut framed = Vec::with_capacity(header.len() + body.len());
    framed.extend_from_slice(header.as_bytes());
    framed.extend_from_slice(body);
    framed
}

/// Read ONE framed LSP message body from a reader (bounded by `max_body`).
/// Returns `None` on EOF, a malformed/missing `Content-Length`, an over-cap
/// announced length, or a short read — every failure is a clean stop, never a
/// partial/garbage message.
#[cfg(any(feature = "lsp", test))]
pub fn read_frame<R: std::io::BufRead>(reader: &mut R, max_body: usize) -> Option<Vec<u8>> {
    let mut content_len: Option<usize> = None;
    loop {
        let mut line = String::new();
        // ASCII headers; invalid UTF-8 / EOF ⇒ clean stop.
        let read = reader.read_line(&mut line).ok()?;
        if read == 0 {
            return None; // EOF before the header terminator.
        }
        let trimmed = line.trim_end_matches(['\r', '\n']);
        if trimmed.is_empty() {
            break; // blank line: end of headers.
        }
        if let Some(rest) = trimmed.to_ascii_lowercase().strip_prefix("content-length:") {
            content_len = rest.trim().parse::<usize>().ok();
        }
    }
    let len = content_len?;
    if len > max_body {
        return None; // refuse an over-cap message (bounded memory).
    }
    let mut body = vec![0_u8; len];
    reader.read_exact(&mut body).ok()?;
    Some(body)
}

// ---------------------------------------------------------------------------
// The diagnose entry — ALWAYS compiled (so the loop grammar + dispatch verb stay
// closed in every build). The real work is `lsp`-feature gated; otherwise it
// honest-degrades.
// ---------------------------------------------------------------------------

/// `lsp diagnostics <path>`: run the real language server over `path` (sandboxed,
/// READ-class) and return `(rendered, ran)`. `ran` is `true` only when a real
/// server produced a verdict (it consumes the loop's K-read budget); every
/// honest-degrade / deny returns `false`. The rendered diagnostics are
/// redact-belted (SI-2) before return.
#[must_use]
pub fn diagnose(path: &str) -> (String, bool) {
    #[cfg(feature = "lsp")]
    {
        diagnose_real(path)
    }
    #[cfg(not(feature = "lsp"))]
    {
        let _ = path;
        (
            "lsp diagnostics: the language-server codec is not compiled in this build (build --features lsp)".to_string(),
            false,
        )
    }
}

#[cfg(feature = "lsp")]
fn diagnose_real(path: &str) -> (String, bool) {
    use std::path::Path;

    let Some(lang) = Lang::detect(path) else {
        return (
            format!("lsp diagnostics: unsupported file type for {path} (only .rs and .move)"),
            false,
        );
    };

    // Read the target through the FULL walled policy (allowlist + denylist + size
    // cap + UTF-8 gate) — the SAME wall `file read` uses. The content goes ONLY to
    // the network-DENIED sandboxed server; it never crosses the wire.
    let policy = crate::file_context::FileReadPolicy::workspace_default();
    let file = match policy.read(Path::new(path)) {
        Ok(file) => file,
        Err(deny) => {
            return (
                format!("lsp diagnostics: cannot read {path} (denied: {deny:?})"),
                false,
            );
        }
    };
    let Some(content) = file.text else {
        return (
            format!("lsp diagnostics: {path} is binary (no source diagnostics)"),
            false,
        );
    };

    // Resolve the server binary up front — an absent binary is an HONEST degrade
    // (never a fabricated result), and resolving to an absolute path avoids any
    // `$PATH` ambiguity inside the sandbox.
    let bin = lang.server_bin();
    let Some(bin_abs) = resolve_on_path(bin) else {
        return (
            format!(
                "lsp diagnostics: language server '{bin}' not found on PATH (install it — honest-degrade, no fabricated diagnostics)"
            ),
            false,
        );
    };

    let root = analysis_root(&file.canonical_path, lang);
    match run_diagnostics_session(&bin_abs, lang, &root, &file.canonical_path, &content) {
        // A real verdict the server PUBLISHED for THIS file: empty = compiler-clean,
        // non-empty = the diagnostics. Either is a genuine READ result (consumes K).
        Ok(Some(diags)) => (redact_belt(&render_diagnostics(path, &diags)), true),
        // The server NEVER published diagnostics for THIS file (analysis did not
        // complete — e.g. a Move package whose dep cache could not be written under
        // the sandbox). NOT "0 clean": an honest no-verdict (no false compiler-clean).
        Ok(None) => (
            format!(
                "lsp diagnostics: {path}: no verdict — the language server did not return diagnostics for this file (analysis did not complete)"
            ),
            false,
        ),
        Err(deny) => (
            format!("lsp diagnostics: {path}: {}", deny.message()),
            false,
        ),
    }
}

// ---------------------------------------------------------------------------
// Real session — `lsp`-feature gated (serde_json + the sandboxed subprocess).
// ---------------------------------------------------------------------------

/// The whole-session wall clock (initialize + didOpen + collect). Bounded so a
/// silent / hung server can never block the loop. Generous because a cold
/// language server first loads its sysroot/index before emitting diagnostics.
#[cfg(feature = "lsp")]
const LSP_SESSION_TIMEOUT_MS: u64 = 25_000;

/// After the FIRST (often empty, during load) `publishDiagnostics` for our file,
/// wait this long for a POPULATED update before reporting "clean". Must exceed
/// the server's analysis latency or a real error would be missed (the server
/// publishes an empty set on `didOpen`, then the diagnostics after it analyzes).
#[cfg(feature = "lsp")]
const LSP_SETTLE_MS: u64 = 8_000;

/// Cap on rendered diagnostics + on messages processed (DoS bounds).
#[cfg(feature = "lsp")]
const LSP_MAX_DIAGNOSTICS: usize = 64;
#[cfg(feature = "lsp")]
const LSP_MAX_MESSAGES: usize = 512;

/// Typed, data-free denial reasons for a real LSP session.
#[cfg(feature = "lsp")]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum LspDeny {
    /// IV-S9 fail-CLOSED: no kernel sandbox on this host — the server is NEVER
    /// run unsandboxed.
    SandboxUnavailable,
    /// The child could not be spawned (binary vanished between resolve + spawn).
    SpawnFailed,
    /// A pipe I/O error writing a request / taking a stream.
    Io,
    /// `serde_json` could not encode a request body.
    Codec,
    /// The server never completed `initialize` / sent diagnostics in time.
    Timeout,
}

#[cfg(feature = "lsp")]
impl LspDeny {
    const fn message(self) -> &'static str {
        match self {
            Self::SandboxUnavailable => {
                "no kernel sandbox on this host (the server is never run unsandboxed)"
            }
            Self::SpawnFailed => "the language server could not be spawned",
            Self::Io => "a pipe I/O error",
            Self::Codec => "a request could not be encoded",
            Self::Timeout => "the server did not respond within the time budget",
        }
    }
}

/// One parsed LSP diagnostic (the fields we render).
#[cfg(feature = "lsp")]
#[derive(Clone, Debug)]
struct Diag {
    severity: i64,
    line: u64,
    character: u64,
    message: String,
    source: Option<String>,
}

/// A long-lived sandboxed language-server child. Owns the child + its stdin; the
/// stdout is handed to a reader thread. Reaped on `Drop` (kill THEN wait — never a
/// zombie; the kill error of an already-exited child is benign).
#[cfg(feature = "lsp")]
struct LspServer {
    child: std::process::Child,
    stdin: std::process::ChildStdin,
}

#[cfg(feature = "lsp")]
impl Drop for LspServer {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// The Seatbelt profile for a language server. The NETWORK is ALWAYS kernel-DENIED
/// (the load-bearing wall — no egress, custody unreachable). rust-analyzer works
/// fully in-memory ⇒ strict READ (`ReadOnly` = deny network + deny file-write).
/// move-analyzer MUST write its package lock + compiled-dep cache under `~/.move`,
/// and it spawns `git` to verify the framework dep (which needs `/dev/null` + the
/// system temp) — it fails "Operation not permitted" under strict deny-write ⇒ a
/// PATH-SCOPED write grant: the SAME ReadOnly base PLUS `(allow file-write* …)` for
/// ONLY `~/.move`, the package dir, the system temp (`/private/var/folders`), and
/// `/dev/null`; every OTHER write stays denied (SBPL "last rule wins"). Owner-locked
/// 2026-06-16 (path-scoped). The agent-facing capability stays READ (read-only
/// diagnostics); this only lets the trusted, network-isolated analyzer + its git
/// dep-check maintain their caches.
#[cfg(feature = "lsp")]
fn lsp_seatbelt_profile(lang: Lang, root: &std::path::Path) -> String {
    use crate::commands::sandbox::SandboxTier;
    use crate::sandbox_exec::seatbelt_profile_for;
    let base = seatbelt_profile_for(SandboxTier::ReadOnly);
    match lang {
        Lang::Rust => base,
        Lang::Move => {
            let root_str = root.display().to_string();
            let move_home = std::env::var("HOME")
                .ok()
                .map(|home| format!("{home}/.move"));
            match move_home {
                // SBPL injection guard: a quote/backslash in a path could break the
                // profile string ⇒ honest-degrade to strict ReadOnly for such a path
                // rather than emit a malformed profile.
                Some(move_home)
                    if !move_home.contains(['"', '\\']) && !root_str.contains(['"', '\\']) =>
                {
                    format!(
                        "{base}(allow file-write* (subpath \"{move_home}\") (subpath \"{root_str}\") (subpath \"/private/var/folders\") (literal \"/dev/null\"))"
                    )
                }
                _ => base,
            }
        }
    }
}

#[cfg(feature = "lsp")]
impl LspServer {
    /// Spawn `bin_abs` under the per-language [`lsp_seatbelt_profile`] (network
    /// ALWAYS kernel-DENIED; rust-analyzer = strict deny-write, move-analyzer =
    /// write path-scoped to its `~/.move` cache + the package dir) with the SAME
    /// env-scrub the one-shot exec uses, piped stdin/stdout, and a pinned cwd.
    /// Returns the server + its stdout reader.
    fn spawn_sandboxed(
        bin_abs: &std::path::Path,
        lang: Lang,
        root: &std::path::Path,
    ) -> Result<(Self, std::io::BufReader<std::process::ChildStdout>), LspDeny> {
        use crate::exec_local::EXEC_ENV_ALLOWLIST;
        use crate::sandbox_exec::{SANDBOX_EXEC_PATH, seatbelt_available};
        use std::process::Stdio;

        // IV-S9: fail-closed — never an unsandboxed fallback.
        if !seatbelt_available() {
            return Err(LspDeny::SandboxUnavailable);
        }
        let profile = lsp_seatbelt_profile(lang, root);
        let mut command = std::process::Command::new(SANDBOX_EXEC_PATH);
        command
            .arg("-p")
            .arg(&profile)
            .arg("--")
            .arg(bin_abs)
            .env_clear()
            .current_dir(root)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null());
        // IV-E3: the child sees ONLY the allowlist (rust-analyzer needs PATH +
        // HOME to find its toolchain; both are on the allowlist).
        for key in EXEC_ENV_ALLOWLIST {
            if let Ok(value) = std::env::var(key) {
                command.env(key, value);
            }
        }
        let mut child = command.spawn().map_err(|_| LspDeny::SpawnFailed)?;
        let stdin = child.stdin.take().ok_or(LspDeny::SpawnFailed)?;
        let stdout = child.stdout.take().ok_or(LspDeny::SpawnFailed)?;
        Ok((Self { child, stdin }, std::io::BufReader::new(stdout)))
    }

    /// Frame + write a JSON-RPC body to the server's stdin.
    fn send(&mut self, body: &[u8]) -> Result<(), LspDeny> {
        use std::io::Write;
        self.stdin
            .write_all(&encode_frame(body))
            .map_err(|_| LspDeny::Io)?;
        self.stdin.flush().map_err(|_| LspDeny::Io)
    }
}

/// Spawn the server, drive `initialize → initialized → didOpen`, and collect the
/// `publishDiagnostics` for the opened file (bounded). The reader runs on its own
/// thread so every wait is `recv_timeout`-bounded; dropping the server kills the
/// child, which EOFs the reader, which ends the thread (joined, no zombie).
#[cfg(feature = "lsp")]
fn run_diagnostics_session(
    bin_abs: &std::path::Path,
    lang: Lang,
    root: &std::path::Path,
    file: &std::path::Path,
    content: &str,
) -> Result<Option<Vec<Diag>>, LspDeny> {
    use std::time::{Duration, Instant};

    let (mut server, stdout) = LspServer::spawn_sandboxed(bin_abs, lang, root)?;

    // Reader thread: frame messages off stdout into a channel (bounded count).
    let (tx, rx) = std::sync::mpsc::channel::<Vec<u8>>();
    let reader = std::thread::spawn(move || {
        let mut stdout = stdout;
        let mut count = 0_usize;
        while count < LSP_MAX_MESSAGES {
            match read_frame(&mut stdout, LSP_MAX_FRAME_BYTES) {
                Some(frame) => {
                    count += 1;
                    if tx.send(frame).is_err() {
                        break; // receiver gone.
                    }
                }
                None => break, // EOF / malformed → stop.
            }
        }
    });

    let deadline = Instant::now() + Duration::from_millis(LSP_SESSION_TIMEOUT_MS);
    let outcome = (|| {
        let root_uri = path_to_uri(root);
        let file_uri = path_to_uri(file);
        // 1. initialize (id = 1) — disable cargo flycheck + proc-macro so a
        //    network-DENIED, write-DENIED sandbox does not stall the server.
        server.send(&encode_json(&serde_json::json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "processId": serde_json::Value::Null,
                "rootUri": root_uri,
                "capabilities": { "textDocument": { "publishDiagnostics": {} } },
                "initializationOptions": {
                    "checkOnSave": false,
                    "cargo": { "buildScripts": { "enable": false } },
                    "procMacro": { "enable": false },
                    "diagnostics": { "enable": true }
                }
            }
        }))?)?;
        wait_for_initialize(&rx, deadline)?;
        // 2. initialized + didOpen.
        server.send(&encode_json(&serde_json::json!({
            "jsonrpc": "2.0", "method": "initialized", "params": {}
        }))?)?;
        server.send(&encode_json(&serde_json::json!({
            "jsonrpc": "2.0",
            "method": "textDocument/didOpen",
            "params": {
                "textDocument": {
                    "uri": file_uri,
                    "languageId": lang.language_id(),
                    "version": 1,
                    "text": content
                }
            }
        }))?)?;
        // 3. collect diagnostics for our file.
        collect_diagnostics(&rx, &file_uri, deadline)
    })();

    drop(server); // kill + reap → reader EOFs → thread ends.
    let _ = reader.join();
    outcome
}

#[cfg(feature = "lsp")]
fn encode_json(value: &serde_json::Value) -> Result<Vec<u8>, LspDeny> {
    serde_json::to_vec(value).map_err(|_| LspDeny::Codec)
}

/// Wait for the `initialize` response (`id == 1`), ignoring log/window messages.
#[cfg(feature = "lsp")]
fn wait_for_initialize(
    rx: &std::sync::mpsc::Receiver<Vec<u8>>,
    deadline: std::time::Instant,
) -> Result<(), LspDeny> {
    use std::sync::mpsc::RecvTimeoutError;
    use std::time::Instant;
    loop {
        let wait = deadline.saturating_duration_since(Instant::now());
        if wait.is_zero() {
            return Err(LspDeny::Timeout);
        }
        match rx.recv_timeout(wait) {
            Ok(frame) => {
                if let Ok(value) = serde_json::from_slice::<serde_json::Value>(&frame) {
                    if value.get("id").and_then(serde_json::Value::as_u64) == Some(1)
                        && value.get("result").is_some()
                    {
                        return Ok(());
                    }
                }
            }
            Err(RecvTimeoutError::Timeout) => return Err(LspDeny::Timeout),
            Err(RecvTimeoutError::Disconnected) => return Err(LspDeny::Timeout),
        }
    }
}

/// Collect `textDocument/publishDiagnostics` for `file_uri`. `Some(non-empty)` as
/// soon as the errors arrive; `Some(empty)` = a genuine compiler-clean verdict the
/// server published for OUR file; `None` = the server NEVER published a verdict for
/// our file (timeout / failed analysis) — the caller reports an honest "no verdict",
/// NEVER a false "0 compiler-clean".
#[cfg(feature = "lsp")]
fn collect_diagnostics(
    rx: &std::sync::mpsc::Receiver<Vec<u8>>,
    file_uri: &str,
    deadline: std::time::Instant,
) -> Result<Option<Vec<Diag>>, LspDeny> {
    use std::sync::mpsc::RecvTimeoutError;
    use std::time::{Duration, Instant};

    let mut received: Option<Vec<Diag>> = None;
    let mut settle: Option<Instant> = None;
    loop {
        let now = Instant::now();
        let hard = deadline.saturating_duration_since(now);
        if hard.is_zero() {
            break;
        }
        let wait = match settle {
            Some(when) => when.saturating_duration_since(now).min(hard),
            None => hard,
        };
        if wait.is_zero() {
            break; // settle window elapsed with no populated update.
        }
        match rx.recv_timeout(wait) {
            Ok(frame) => {
                if let Ok(value) = serde_json::from_slice::<serde_json::Value>(&frame) {
                    if let Some(diags) = parse_publish_diagnostics(&value, file_uri) {
                        if !diags.is_empty() {
                            return Ok(Some(diags)); // found errors → report immediately.
                        }
                        received = Some(diags); // a clean verdict for OUR file.
                        if settle.is_none() {
                            settle = Some(Instant::now() + Duration::from_millis(LSP_SETTLE_MS));
                        }
                    }
                }
            }
            Err(RecvTimeoutError::Timeout) => break,
            Err(RecvTimeoutError::Disconnected) => break, // server died.
        }
    }
    Ok(received)
}

/// Parse a `textDocument/publishDiagnostics` message for `want_uri`. `None` ⇒ a
/// different method / a different file (ignored, not an error).
#[cfg(feature = "lsp")]
fn parse_publish_diagnostics(value: &serde_json::Value, want_uri: &str) -> Option<Vec<Diag>> {
    if value.get("method")?.as_str()? != "textDocument/publishDiagnostics" {
        return None;
    }
    let params = value.get("params")?;
    if params.get("uri")?.as_str()? != want_uri {
        return None;
    }
    let array = params.get("diagnostics")?.as_array()?;
    let mut out = Vec::new();
    for diag in array.iter().take(LSP_MAX_DIAGNOSTICS) {
        let message = diag
            .get("message")
            .and_then(serde_json::Value::as_str)
            .unwrap_or("")
            .to_string();
        let severity = diag
            .get("severity")
            .and_then(serde_json::Value::as_i64)
            .unwrap_or(1);
        let (line, character) = diag
            .get("range")
            .and_then(|range| range.get("start"))
            .map(|start| {
                (
                    start
                        .get("line")
                        .and_then(serde_json::Value::as_u64)
                        .unwrap_or(0),
                    start
                        .get("character")
                        .and_then(serde_json::Value::as_u64)
                        .unwrap_or(0),
                )
            })
            .unwrap_or((0, 0));
        let source = diag
            .get("source")
            .and_then(serde_json::Value::as_str)
            .map(str::to_string);
        out.push(Diag {
            severity,
            line,
            character,
            message,
            source,
        });
    }
    Some(out)
}

/// Render diagnostics for display / the prompt (1-based lines/cols for humans).
#[cfg(feature = "lsp")]
fn render_diagnostics(path: &str, diags: &[Diag]) -> String {
    if diags.is_empty() {
        return format!("lsp diagnostics for {path}: 0 diagnostics (compiler-clean)");
    }
    let mut lines = vec![format!(
        "lsp diagnostics for {path}: {} diagnostic(s) (compiler truth)",
        diags.len()
    )];
    for diag in diags {
        let severity = match diag.severity {
            1 => "error",
            2 => "warning",
            3 => "info",
            _ => "hint",
        };
        let source = diag.source.as_deref().unwrap_or("lsp");
        lines.push(format!(
            "  {}:{} [{severity}] {} ({source})",
            diag.line.saturating_add(1),
            diag.character.saturating_add(1),
            diag.message
        ));
    }
    lines.join("\n")
}

/// SI-2 redaction belt: a secret-shaped diagnostic ⇒ the whole render is withheld.
#[cfg(feature = "lsp")]
fn redact_belt(rendered: &str) -> String {
    use crate::provider::redaction::{RedactionRequest, redact};
    let fragments = [rendered];
    match redact(&RedactionRequest {
        fragments: &fragments,
        candidate_memory_ids: &[],
        deleted_ids: &[],
        include_private_memory: false,
    }) {
        Ok(receipt) if receipt.secret_fragments_denied_u32() == 0 => rendered.to_string(),
        _ => "lsp diagnostics: withheld (a diagnostic message was secret-shaped)".to_string(),
    }
}

/// Resolve a bare binary name to an absolute path by scanning `PATH` (the honest
/// presence probe). `None` ⇒ absent ⇒ honest-degrade.
#[cfg(feature = "lsp")]
fn resolve_on_path(bin: &str) -> Option<std::path::PathBuf> {
    let path = std::env::var_os("PATH")?;
    for dir in std::env::split_paths(&path) {
        let candidate = dir.join(bin);
        if candidate.is_file() {
            return Some(candidate);
        }
    }
    None
}

/// The analysis root for a file: the nearest ancestor holding the language's
/// manifest (so an in-crate file gets crate scope), else the file's parent (a
/// detached file — fast, syntax + intra-file analysis, no false cross-crate
/// errors).
#[cfg(feature = "lsp")]
fn analysis_root(file: &std::path::Path, lang: Lang) -> std::path::PathBuf {
    let manifest = lang.manifest();
    let mut cursor = file.parent();
    while let Some(dir) = cursor {
        if dir.join(manifest).is_file() {
            return dir.to_path_buf();
        }
        cursor = dir.parent();
    }
    file.parent()
        .map(std::path::Path::to_path_buf)
        .unwrap_or_else(|| std::path::PathBuf::from("."))
}

/// `file://` URI for an absolute path. mnemos paths are space-free; a space (the
/// only character LSP servers reject unencoded here) is percent-encoded.
#[cfg(feature = "lsp")]
fn path_to_uri(path: &std::path::Path) -> String {
    let display = path.display().to_string();
    let encoded = display.replace(' ', "%20");
    format!("file://{encoded}")
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use super::*;

    #[test]
    fn detect_lang_by_extension_case_insensitive() {
        assert_eq!(Lang::detect("a/b/c.rs"), Some(Lang::Rust));
        assert_eq!(Lang::detect("X.RS"), Some(Lang::Rust));
        assert_eq!(Lang::detect("sources/token.move"), Some(Lang::Move));
        assert_eq!(Lang::detect("token.MOVE"), Some(Lang::Move));
        assert_eq!(Lang::detect("readme.txt"), None);
        assert_eq!(Lang::detect("noext"), None);
    }

    #[test]
    fn server_bin_and_language_id_are_stable() {
        assert_eq!(Lang::Rust.server_bin(), "rust-analyzer");
        assert_eq!(Lang::Move.server_bin(), "move-analyzer");
        assert_eq!(Lang::Rust.language_id(), "rust");
        assert_eq!(Lang::Move.language_id(), "move");
        assert_eq!(Lang::Rust.manifest(), "Cargo.toml");
        assert_eq!(Lang::Move.manifest(), "Move.toml");
    }

    #[test]
    fn frame_round_trips_through_a_cursor() {
        let body = br#"{"jsonrpc":"2.0","id":1,"result":{}}"#;
        let framed = encode_frame(body);
        // The header is exactly the LSP base protocol.
        assert!(framed.starts_with(b"Content-Length: 36\r\n\r\n"));
        let mut cursor = std::io::Cursor::new(framed);
        let decoded = read_frame(&mut cursor, LSP_MAX_FRAME_BYTES).unwrap();
        assert_eq!(decoded, body);
    }

    #[test]
    fn frame_reads_two_back_to_back_messages() {
        let mut stream = encode_frame(b"first");
        stream.extend_from_slice(&encode_frame(b"second"));
        let mut cursor = std::io::Cursor::new(stream);
        assert_eq!(
            read_frame(&mut cursor, LSP_MAX_FRAME_BYTES).unwrap(),
            b"first"
        );
        assert_eq!(
            read_frame(&mut cursor, LSP_MAX_FRAME_BYTES).unwrap(),
            b"second"
        );
        // EOF after the last message.
        assert_eq!(read_frame(&mut cursor, LSP_MAX_FRAME_BYTES), None);
    }

    #[test]
    fn frame_refuses_over_cap_and_handles_eof_and_malformed() {
        // Over-cap announced length ⇒ refused (bounded memory).
        let mut over = std::io::Cursor::new(b"Content-Length: 9999\r\n\r\n".to_vec());
        assert_eq!(read_frame(&mut over, 8), None);
        // Missing Content-Length ⇒ None.
        let mut bad = std::io::Cursor::new(b"X-Foo: 1\r\n\r\n".to_vec());
        assert_eq!(read_frame(&mut bad, LSP_MAX_FRAME_BYTES), None);
        // Empty stream ⇒ None (EOF).
        let mut empty = std::io::Cursor::new(Vec::new());
        assert_eq!(read_frame(&mut empty, LSP_MAX_FRAME_BYTES), None);
    }

    #[cfg(feature = "lsp")]
    #[test]
    fn parse_publish_diagnostics_extracts_for_the_right_uri() {
        let value = serde_json::json!({
            "jsonrpc": "2.0",
            "method": "textDocument/publishDiagnostics",
            "params": {
                "uri": "file:///tmp/bad.rs",
                "diagnostics": [
                    {"severity": 1, "message": "expected expression",
                     "source": "rust-analyzer",
                     "range": {"start": {"line": 0, "character": 23}}}
                ]
            }
        });
        let diags = parse_publish_diagnostics(&value, "file:///tmp/bad.rs").unwrap();
        assert_eq!(diags.len(), 1);
        assert_eq!(diags[0].severity, 1);
        assert_eq!(diags[0].line, 0);
        assert_eq!(diags[0].character, 23);
        assert_eq!(diags[0].message, "expected expression");
        // A different uri / method is ignored (None, not an error).
        assert!(parse_publish_diagnostics(&value, "file:///tmp/other.rs").is_none());
        let other = serde_json::json!({"method": "window/logMessage", "params": {}});
        assert!(parse_publish_diagnostics(&other, "file:///tmp/bad.rs").is_none());
    }

    #[cfg(feature = "lsp")]
    #[test]
    fn render_clean_and_dirty() {
        assert!(render_diagnostics("x.rs", &[]).contains("0 diagnostics (compiler-clean)"));
        let diags = vec![Diag {
            severity: 1,
            line: 4,
            character: 8,
            message: "mismatched types".to_string(),
            source: Some("rust-analyzer".to_string()),
        }];
        let rendered = render_diagnostics("x.rs", &diags);
        assert!(rendered.contains("1 diagnostic(s) (compiler truth)"));
        // 1-based human coordinates.
        assert!(rendered.contains("5:9 [error] mismatched types (rust-analyzer)"));
    }
}
