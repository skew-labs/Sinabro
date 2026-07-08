//! MCP client — a sandboxed stdio MCP server as a READ capability.
//!
//! ## Thesis (the capability-type model is the ideal MCP host)
//!
//! Each configured MCP server is a CAPABILITY-TYPED connection. v1 = stdio LOCAL
//! servers only (NO egress — the child's
//! network is kernel-DENIED) speaking hand-rolled JSON-RPC 2.0, and READ-class
//! tools only (`ReadCapability`, free). The whole MCP tool ecosystem becomes
//! SAFELY available to BOTH the agent loop (`TOOL: mcp <server> <tool> [args]`, a
//! typed READ) AND a dispatch verb (`context mcp <server> <tool> [args]`) over ONE
//! chokepoint ([`render_mcp_call`]): wall → redact ARG → call → redact RESULT →
//! audit. http/SSE remote (EGRESS, owner-armed) + mutating MCP tools (MUTATE,
//! owner-armed) are a separate v2 — never auto-run.
//!
//! ## Security (the per-slice invariants)
//!
//! * CAPABILITY = READ (T3). The stdio child runs under
//!   [`seatbelt_profile_for(ReadOnly)`](crate::sandbox_exec::seatbelt_profile_for)
//!   = `(deny network*)(deny file-write*)` — the load-bearing wall: a LOCAL MCP
//!   read server needs no net, custody is unreachable. fail-CLOSED if no kernel
//!   sandbox ([[no-disabled-path-workaround]]) — the server is NEVER run
//!   unsandboxed.
//! * FAIL-CLOSED tiering (T2). An unconfigured server (not in the owner config's
//!   `[[mcp_servers]]`) ⇒ DENY; a tool the server did NOT advertise in
//!   `tools/list` ⇒ DENY. v1 admits only `tier = "read"` servers (the config layer
//!   refuses any other tier); no mutating tool runs.
//! * REDACTION. The outbound tool ARG AND the inbound tool RESULT both pass
//!   the [`redact`](crate::provider::redaction::redact) wall; secret-shaped ⇒
//!   WITHHELD (the arg is never sent, the result never surfaces).
//! * AUDIT (E5). EVERY MCP tool call — success or deny — lands in the hash-linked
//!   chain ([`record_mcp_audit`]). Unlike a fixed language server (`lsp`) or a
//!   public web GET (`web_fetch`), an MCP server runs an ARBITRARY owner-configured
//!   external tool, so each call is a high-significance action worth recording.
//! * CUSTODY untouched: this path constructs no egress / mutate / custody
//!   capability and reaches no chain RPC or socket (the sandbox kernel-denies the
//!   network); user funds stay hard-locked behind the uninhabited custody type.
//!
//! ## Codec edge
//!
//! Hand-rolled JSON-RPC 2.0 over **NDJSON** (newline-delimited JSON — the MCP stdio
//! transport standard, NOT the `lsp` Content-Length framing). The build/parse rides
//! `serde_json` — the SAME optional workspace codec the consult / `lsp` builds
//! already link (already in `Cargo.lock` ⇒ relock-free), gated behind the
//! off-default `mcp` feature; a build without it honest-degrades. The persistent-
//! stdio lifecycle (sandboxed spawn, reader thread + `recv_timeout`, reaped on
//! `Drop`) REUSES the proven [`crate::lsp`] idiom — only the framing differs.

/// The maximum bytes of ONE NDJSON message we accept (a DoS bound — a line longer
/// than this with no terminator is refused, never buffered unbounded).
#[cfg(any(feature = "mcp", test))]
pub const MCP_MAX_LINE_BYTES: usize = 1024 * 1024;

/// Read ONE newline-delimited JSON message body from a reader, bounded by
/// `max_body`. Returns `None` on EOF, an over-cap line (no `\n` within
/// `max_body + 1`), or a truncated final line — every failure is a clean stop,
/// never a partial/garbage message. The trailing `\n` (and an optional `\r`) is
/// stripped; a blank line yields an empty `Vec` (the session loop skips it on a
/// failed parse). PURE + bounded; testable over any `BufRead` with no subprocess.
#[cfg(any(feature = "mcp", test))]
#[must_use]
pub fn read_ndjson_line<R: std::io::BufRead>(reader: &mut R, max_body: usize) -> Option<Vec<u8>> {
    // `read_until` is a `BufRead` method; bring the trait into scope so it resolves
    // on the `Take<&mut R>` adapter below.
    use std::io::BufRead as _;
    // Bound the read to `max_body + 1` bytes so a server that never sends a
    // newline cannot make us allocate unboundedly (the `+ 1` lets a full
    // `max_body`-byte line still capture its terminating `\n`).
    let mut limited = std::io::Read::take(&mut *reader, (max_body as u64).saturating_add(1));
    let mut buf: Vec<u8> = Vec::new();
    let read = limited.read_until(b'\n', &mut buf).ok()?;
    if read == 0 {
        return None; // EOF before any byte.
    }
    if buf.last() != Some(&b'\n') {
        // No delimiter within the bound: an over-cap line OR an EOF mid-line —
        // either way a clean stop (never a partial message).
        return None;
    }
    buf.pop(); // drop the '\n'
    if buf.last() == Some(&b'\r') {
        buf.pop(); // tolerate CRLF
    }
    Some(buf)
}

/// Frame a JSON-RPC body as one NDJSON message (the body followed by a single
/// `\n`). The compact `serde_json` encoding never contains a literal newline, so
/// the message is self-delimiting.
#[cfg(any(feature = "mcp", test))]
#[must_use]
pub fn encode_ndjson_line(body: &[u8]) -> Vec<u8> {
    let mut framed = Vec::with_capacity(body.len() + 1);
    framed.extend_from_slice(body);
    framed.push(b'\n');
    framed
}

// ---------------------------------------------------------------------------
// Always-compiled surface: the server spec, the loop seam, the typed denial, the
// chokepoint render, the redaction belt, and the audit record. The grammar +
// dispatch verb stay CLOSED in every build; the real stdio session is `mcp`-
// feature gated and honest-degrades otherwise.
// ---------------------------------------------------------------------------

/// One owner-configured local stdio MCP server (resolved from the config layer's
/// `[[mcp_servers]]`, v1 = `tier = "read"` only). The `command` is resolved on
/// `PATH` (a bare name) or used as an absolute path (a name with `/`); `args` are
/// passed verbatim AFTER the `sandbox-exec` wrapper.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct McpServerSpec {
    /// The server's logical name (the `<server>` token in `mcp <server> <tool>`).
    pub name: String,
    /// The command to spawn (bare name resolved on `PATH`, or an absolute path).
    pub command: String,
    /// The command's arguments (passed verbatim under the sandbox wrapper).
    pub args: Vec<String>,
}

impl McpServerSpec {
    /// Construct a spec (config-layer use).
    #[must_use]
    pub fn new(name: String, command: String, args: Vec<String>) -> Self {
        Self {
            name,
            command,
            args,
        }
    }
}

/// The feature-independent MCP seam threaded through the agent loop — it carries
/// the owner-configured READ-tier stdio servers (mirror of
/// [`crate::provider::web_fetch::WebFetchSeam`], so the loop signature is ONE shape
/// across feature combos). `inert()` (no servers) ⇒ the loop's `mcp` tool denies
/// ("no MCP server configured"); a real session is `mcp`-feature gated regardless.
#[derive(Clone, Debug, Default)]
pub struct McpSeam {
    servers: Vec<McpServerSpec>,
}

impl McpSeam {
    /// The LIVE seam: the resolved set of owner-configured local READ servers.
    #[must_use]
    pub fn new(servers: Vec<McpServerSpec>) -> Self {
        Self { servers }
    }

    /// An INERT seam — no configured servers, so the loop's `mcp` tool denies
    /// every call (used where MCP is intentionally absent and by hermetic tests).
    #[must_use]
    pub fn inert() -> Self {
        Self {
            servers: Vec::new(),
        }
    }

    /// The configured servers.
    #[must_use]
    pub fn servers(&self) -> &[McpServerSpec] {
        &self.servers
    }

    /// Resolve a configured server by its logical name (fail-closed: `None` ⇒ the
    /// chokepoint denies as `mcp.server.not_configured`).
    #[must_use]
    pub fn find(&self, name: &str) -> Option<&McpServerSpec> {
        self.servers.iter().find(|s| s.name == name)
    }
}

/// Typed, data-free denial reasons for an MCP stdio session. Always compiled (the
/// chokepoint's `Err` arm renders the label in every build); the real session is
/// `mcp`-feature gated, so the default build only ever produces [`Self::NotCompiled`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum McpSessionDeny {
    /// The `mcp` feature is off — the stdio client is not compiled (honest-degrade).
    NotCompiled,
    /// fail-CLOSED: no kernel sandbox on this host — the server is NEVER run
    /// unsandboxed.
    SandboxUnavailable,
    /// The configured command could not be resolved / the child could not spawn.
    SpawnFailed,
    /// A pipe I/O error writing a request / taking a stream.
    Io,
    /// A JSON-RPC body could not be encoded, or the tool argument was not valid JSON.
    Codec,
    /// The server did not complete `initialize` / answer a request in time.
    Timeout,
    /// The server returned a JSON-RPC error or a malformed response.
    ProtocolError,
    /// The requested tool was NOT advertised in the server's `tools/list` (deny).
    ToolNotFound,
}

impl McpSessionDeny {
    /// Stable, allow-listed `class_label` (namespaced `mcp.*`).
    #[must_use]
    pub const fn class_label(self) -> &'static str {
        match self {
            Self::NotCompiled => "mcp.transport.not_compiled",
            Self::SandboxUnavailable => "mcp.sandbox.unavailable",
            Self::SpawnFailed => "mcp.spawn_failed",
            Self::Io => "mcp.io",
            Self::Codec => "mcp.codec",
            Self::Timeout => "mcp.timeout",
            Self::ProtocolError => "mcp.protocol_error",
            Self::ToolNotFound => "mcp.tool_not_found",
        }
    }
}

/// The chokepoint's verdict (mirror of
/// [`crate::provider::web_fetch::WebFetchRender`]): the rendered advisory / deny,
/// whether it consumed a READ (only a verified result), and a stable class label.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct McpCallRender {
    /// The rendered tool advisory (success) or the typed deny (one line).
    pub rendered: String,
    /// `true` only when a verified, redacted result surfaced (consumes the loop's
    /// K-read budget); every deny / withhold / not-compiled is `false`.
    pub consumed_read: bool,
    /// A stable ASCII class label (`mcp.*`).
    pub class_label: &'static str,
}

/// The ONE MCP chokepoint shared by BOTH consumers (the loop tool + the dispatch
/// verb). Gate order: (1) WALL — the server must be an
/// owner-configured stdio server (fail-closed, unknown ⇒ deny); (2) REDACT the
/// OUTBOUND arg (secret-shaped ⇒ WITHHELD, never sent); (3) the sandboxed stdio
/// SESSION (`initialize` → `tools/list` → `tools/call`; an un-advertised tool ⇒
/// deny); (4) REDACT the INBOUND result (secret-shaped ⇒ WITHHELD); (5) success.
/// EVERY path records the call in the E5 audit chain ([`record_mcp_audit`]). The
/// real session is `mcp`-feature gated and honest-degrades otherwise (the grammar
/// stays closed). custody/funds untouched (the child's network is
/// kernel-DENIED; no egress/mutate/custody capability on this path).
#[must_use]
pub fn render_mcp_call(
    seam: Option<&McpSeam>,
    server: &str,
    tool: &str,
    args: &str,
) -> McpCallRender {
    // 1. WALL (T2 fail-closed): only an owner-configured local READ server.
    let Some(spec) = seam.and_then(|s| s.find(server)) else {
        record_mcp_audit(server, tool, false);
        return McpCallRender {
            rendered: format!(
                "mcp {server}/{tool}: denied (server not configured — add an [[mcp_servers]] entry; an unknown / un-tiered server is fail-closed)"
            ),
            consumed_read: false,
            class_label: "mcp.server.not_configured",
        };
    };
    // 2. REDACT the OUTBOUND arg — a secret-shaped argument is WITHHELD (the redaction
    // wall: a key/seed/token is never handed to the server's stdin).
    if !redact_passes(args) {
        record_mcp_audit(server, tool, false);
        return McpCallRender {
            rendered: format!(
                "mcp {server}/{tool}: withheld (the tool argument was secret-shaped — not sent to the server)"
            ),
            consumed_read: false,
            class_label: "mcp.arg.withheld_secret",
        };
    }
    // 3. SESSION (sandboxed, network + write kernel-DENIED; `mcp`-feature gated).
    match mcp_session(spec, tool, args) {
        Ok(result_text) => {
            // 4. REDACT the INBOUND result — a secret-shaped result is WITHHELD.
            if !redact_passes(&result_text) {
                record_mcp_audit(server, tool, false);
                return McpCallRender {
                    rendered: format!(
                        "mcp {server}/{tool}: withheld (the tool result was secret-shaped)"
                    ),
                    consumed_read: false,
                    class_label: "mcp.result.withheld_secret",
                };
            }
            // 5. SUCCESS — a redacted, source-labeled advisory.
            record_mcp_audit(server, tool, true);
            McpCallRender {
                rendered: format!(
                    "mcp {server}/{tool}: advisory (a sandboxed LOCAL MCP tool result; verify locally — never proof of execution)\n{result_text}"
                ),
                consumed_read: true,
                class_label: "mcp.advisory.allowed",
            }
        }
        Err(deny) => {
            record_mcp_audit(server, tool, false);
            McpCallRender {
                rendered: format!("mcp {server}/{tool}: denied ({})", deny.class_label()),
                consumed_read: false,
                class_label: deny.class_label(),
            }
        }
    }
}

/// Redaction gate: `true` ⇒ the text carries no secret-shaped fragment and may
/// cross the boundary; `false` ⇒ it is WITHHELD. Reuses the canonical
/// [`redact`](crate::provider::redaction::redact) wall (the SAME engine the loop /
/// web fetch / lsp use), so there is no second redaction policy.
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

/// Record ONE MCP tool call in the E5 hash-linked audit chain (success ⇒
/// `Approval`, deny ⇒ `Denial`). The trace + evidence hashes bind the
/// `(server, tool)` pair so distinct calls are distinct records. The disk append
/// fires in the shipped binary (smoke-proven); it is suppressed under `cfg(test)`
/// ONLY for test isolation (parallel threads share one process audit dir), exactly
/// as the dispatch audit append. Best-effort: any failure is swallowed so the call
/// render is never affected.
fn record_mcp_audit(server: &str, tool: &str, success: bool) {
    use crate::commands::audit::{AuditAction, AuditEntry};
    let action = if success {
        AuditAction::Approval
    } else {
        AuditAction::Denial
    };
    let mut seed: Vec<u8> = Vec::with_capacity(server.len() + tool.len() + 8);
    seed.extend_from_slice(b"mcp ");
    seed.extend_from_slice(server.as_bytes());
    seed.push(0);
    seed.extend_from_slice(tool.as_bytes());
    let trace = crate::StageFTraceLink::new(crate::sha256_32(&seed), 0, action.as_u8() as u16);
    let mut ev_seed: Vec<u8> = Vec::with_capacity(seed.len() + 16);
    ev_seed.extend_from_slice(b"mcp.audit.evidence.v1");
    ev_seed.extend_from_slice(&seed);
    let evidence = crate::StageFEvidenceRef {
        path_hash_32: crate::sha256_32(&ev_seed),
        trace,
    };
    let entry = AuditEntry::seal(action, trace, evidence);
    #[cfg(not(test))]
    {
        if let Ok(log) = crate::commands::audit_log::ChainedAuditLog::open_local() {
            let _ = log.append(&entry);
        }
    }
    #[cfg(test)]
    {
        let _ = &entry;
    }
}

// ---------------------------------------------------------------------------
// The honest-degrade stub (no `mcp` feature): the chokepoint is always compiled,
// but the real stdio session is not, so every call yields the not-compiled deny.
// ---------------------------------------------------------------------------

/// `mcp`-OFF build: the stdio client is not compiled ⇒ honest-degrade.
#[cfg(not(feature = "mcp"))]
fn mcp_session(_spec: &McpServerSpec, _tool: &str, _args: &str) -> Result<String, McpSessionDeny> {
    Err(McpSessionDeny::NotCompiled)
}

// ---------------------------------------------------------------------------
// The real stdio session — `mcp`-feature gated (serde_json + the sandboxed
// subprocess). REUSES the A① `lsp` persistent-stdio idiom (sandboxed spawn under
// `seatbelt_profile_for(ReadOnly)` with the SAME env-scrub, a reader thread +
// `recv_timeout`, reaped on `Drop`) — only the framing is NDJSON, not LSP
// Content-Length.
// ---------------------------------------------------------------------------

/// The whole-session wall clock (`initialize` + `tools/list` + `tools/call`).
/// Bounded so a silent / hung server can never block the loop.
#[cfg(feature = "mcp")]
const MCP_SESSION_TIMEOUT_MS: u64 = 15_000;

/// Cap on messages the reader thread processes (DoS bound).
#[cfg(feature = "mcp")]
const MCP_MAX_MESSAGES: usize = 256;

/// Cap on `content` items extracted from a `tools/call` result (DoS bound; the
/// loop further truncates the rendered bytes).
#[cfg(feature = "mcp")]
const MCP_MAX_CONTENT_ITEMS: usize = 32;

/// A long-lived sandboxed MCP-server child. Owns the child + its stdin; the stdout
/// is handed to a reader thread. Reaped on `Drop` (kill THEN wait — never a zombie;
/// the kill error of an already-exited child is benign).
#[cfg(feature = "mcp")]
struct McpServer {
    child: std::process::Child,
    stdin: std::process::ChildStdin,
}

#[cfg(feature = "mcp")]
impl Drop for McpServer {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

#[cfg(feature = "mcp")]
impl McpServer {
    /// Spawn the configured command under `seatbelt_profile_for(ReadOnly)`
    /// (network + file-write ALWAYS kernel-DENIED) with the SAME env-scrub the
    /// one-shot exec + the `lsp` client use, piped stdin/stdout, and a neutral cwd.
    /// fail-CLOSED if no kernel sandbox (never an unsandboxed fallback).
    fn spawn_sandboxed(
        spec: &McpServerSpec,
    ) -> Result<(Self, std::io::BufReader<std::process::ChildStdout>), McpSessionDeny> {
        use crate::commands::sandbox::SandboxTier;
        use crate::exec_local::EXEC_ENV_ALLOWLIST;
        use crate::sandbox_exec::{SANDBOX_EXEC_PATH, seatbelt_available, seatbelt_profile_for};
        use std::process::Stdio;

        // fail-closed: no kernel sandbox ⇒ DENY (never run unsandboxed).
        if !seatbelt_available() {
            return Err(McpSessionDeny::SandboxUnavailable);
        }
        // READ-class: the SBPL profile kernel-denies the network AND file-write
        // (`(deny network*)(deny file-write*)`) — a LOCAL read MCP server needs
        // neither; the network deny is the load-bearing wall (no egress, custody
        // unreachable).
        let profile = seatbelt_profile_for(SandboxTier::ReadOnly);
        let Some(bin_abs) = resolve_command(&spec.command) else {
            return Err(McpSessionDeny::SpawnFailed);
        };
        let mut command = std::process::Command::new(SANDBOX_EXEC_PATH);
        command.arg("-p").arg(&profile).arg("--").arg(&bin_abs);
        for arg in &spec.args {
            command.arg(arg);
        }
        command
            .env_clear()
            .current_dir(std::env::temp_dir())
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null());
        // The child sees ONLY the allowlist (the interpreter needs PATH + HOME to
        // start; both are on the allowlist) — keys never cross.
        for key in EXEC_ENV_ALLOWLIST {
            if let Ok(value) = std::env::var(key) {
                command.env(key, value);
            }
        }
        let mut child = command.spawn().map_err(|_| McpSessionDeny::SpawnFailed)?;
        let stdin = child.stdin.take().ok_or(McpSessionDeny::SpawnFailed)?;
        let stdout = child.stdout.take().ok_or(McpSessionDeny::SpawnFailed)?;
        Ok((Self { child, stdin }, std::io::BufReader::new(stdout)))
    }

    /// Frame a JSON-RPC value as one NDJSON message and write it to the server's
    /// stdin (the body followed by a single `\n`).
    fn send(&mut self, value: &serde_json::Value) -> Result<(), McpSessionDeny> {
        use std::io::Write;
        let body = serde_json::to_vec(value).map_err(|_| McpSessionDeny::Codec)?;
        self.stdin
            .write_all(&encode_ndjson_line(&body))
            .map_err(|_| McpSessionDeny::Io)?;
        self.stdin.flush().map_err(|_| McpSessionDeny::Io)
    }
}

/// Drive a bounded MCP session over `spec`: `initialize` → `notifications/
/// initialized` → `tools/list` (the requested tool MUST be advertised) →
/// `tools/call`, returning the extracted, bounded result text. The reader runs on
/// its own thread so every wait is `recv_timeout`-bounded; dropping the server
/// kills the child, which EOFs the reader, which ends the thread (joined, no
/// zombie).
#[cfg(feature = "mcp")]
fn mcp_session(spec: &McpServerSpec, tool: &str, args: &str) -> Result<String, McpSessionDeny> {
    use std::time::{Duration, Instant};

    // The tool argument is a JSON object (empty ⇒ `{}`). A non-JSON arg is a typed
    // codec deny (the model cannot smuggle a non-JSON payload to the server).
    let arg_value: serde_json::Value = if args.trim().is_empty() {
        serde_json::json!({})
    } else {
        serde_json::from_str(args).map_err(|_| McpSessionDeny::Codec)?
    };

    let (mut server, stdout) = McpServer::spawn_sandboxed(spec)?;

    let (tx, rx) = std::sync::mpsc::channel::<Vec<u8>>();
    let reader = std::thread::spawn(move || {
        let mut stdout = stdout;
        let mut count = 0_usize;
        while count < MCP_MAX_MESSAGES {
            match read_ndjson_line(&mut stdout, MCP_MAX_LINE_BYTES) {
                Some(frame) => {
                    count += 1;
                    if tx.send(frame).is_err() {
                        break; // receiver gone.
                    }
                }
                None => break, // EOF / over-cap → stop.
            }
        }
    });

    let deadline = Instant::now() + Duration::from_millis(MCP_SESSION_TIMEOUT_MS);
    let outcome = (|| {
        // 1. initialize (id = 1).
        server.send(&serde_json::json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": "2024-11-05",
                "capabilities": {},
                "clientInfo": { "name": "sinabro", "version": "1.0" }
            }
        }))?;
        wait_for_id(&rx, 1, deadline)?;
        // 2. initialized notification (no id).
        server.send(&serde_json::json!({
            "jsonrpc": "2.0", "method": "notifications/initialized"
        }))?;
        // 3. tools/list (id = 2) — the requested tool MUST be advertised (T2 deny).
        server.send(&serde_json::json!({
            "jsonrpc": "2.0", "id": 2, "method": "tools/list"
        }))?;
        let list = wait_for_id(&rx, 2, deadline)?;
        if !tool_in_list(&list, tool) {
            return Err(McpSessionDeny::ToolNotFound);
        }
        // 4. tools/call (id = 3).
        server.send(&serde_json::json!({
            "jsonrpc": "2.0",
            "id": 3,
            "method": "tools/call",
            "params": { "name": tool, "arguments": arg_value }
        }))?;
        let result = wait_for_id(&rx, 3, deadline)?;
        Ok(extract_tool_text(&result))
    })();

    drop(server); // kill + reap → reader EOFs → thread ends.
    let _ = reader.join();
    outcome
}

/// Wait for the JSON-RPC response with `want_id` (ignoring notifications / other
/// ids). A JSON-RPC `error` member for our id ⇒ [`McpSessionDeny::ProtocolError`];
/// a timeout / disconnect ⇒ [`McpSessionDeny::Timeout`].
#[cfg(feature = "mcp")]
fn wait_for_id(
    rx: &std::sync::mpsc::Receiver<Vec<u8>>,
    want_id: u64,
    deadline: std::time::Instant,
) -> Result<serde_json::Value, McpSessionDeny> {
    use std::sync::mpsc::RecvTimeoutError;
    use std::time::Instant;
    loop {
        let wait = deadline.saturating_duration_since(Instant::now());
        if wait.is_zero() {
            return Err(McpSessionDeny::Timeout);
        }
        match rx.recv_timeout(wait) {
            Ok(frame) => {
                if let Ok(value) = serde_json::from_slice::<serde_json::Value>(&frame) {
                    if value.get("id").and_then(serde_json::Value::as_u64) == Some(want_id) {
                        if value.get("error").is_some() {
                            return Err(McpSessionDeny::ProtocolError);
                        }
                        return Ok(value);
                    }
                    // A notification / a different id → ignore, keep waiting.
                }
            }
            Err(RecvTimeoutError::Timeout | RecvTimeoutError::Disconnected) => {
                return Err(McpSessionDeny::Timeout);
            }
        }
    }
}

/// Whether `tool` appears in a `tools/list` response's `result.tools[].name`.
#[cfg(feature = "mcp")]
#[must_use]
fn tool_in_list(value: &serde_json::Value, tool: &str) -> bool {
    value
        .get("result")
        .and_then(|r| r.get("tools"))
        .and_then(serde_json::Value::as_array)
        .is_some_and(|arr| {
            arr.iter()
                .any(|t| t.get("name").and_then(serde_json::Value::as_str) == Some(tool))
        })
}

/// Extract the text content from a `tools/call` result (`result.content[]` items
/// of `{ "type": "text", "text": ... }`, joined by newlines). An `isError: true`
/// result is prefixed honestly. Bounded by [`MCP_MAX_CONTENT_ITEMS`].
#[cfg(feature = "mcp")]
#[must_use]
fn extract_tool_text(value: &serde_json::Value) -> String {
    let result = value.get("result");
    let is_error = result
        .and_then(|r| r.get("isError"))
        .and_then(serde_json::Value::as_bool)
        .unwrap_or(false);
    let mut text = String::new();
    if let Some(arr) = result
        .and_then(|r| r.get("content"))
        .and_then(serde_json::Value::as_array)
    {
        for item in arr.iter().take(MCP_MAX_CONTENT_ITEMS) {
            if let Some(t) = item.get("text").and_then(serde_json::Value::as_str) {
                if !text.is_empty() {
                    text.push('\n');
                }
                text.push_str(t);
            }
        }
    }
    if text.is_empty() {
        text = "(the tool returned no text content)".to_string();
    }
    if is_error {
        format!("the tool reported an error: {text}")
    } else {
        text
    }
}

/// Resolve a configured command to an absolute path. A name containing `/` is used
/// as a path (must be a file); a bare name is resolved on `PATH` (the honest
/// presence probe). `None` ⇒ absent ⇒ [`McpSessionDeny::SpawnFailed`].
#[cfg(feature = "mcp")]
#[must_use]
fn resolve_command(command: &str) -> Option<std::path::PathBuf> {
    let direct = std::path::Path::new(command);
    if command.contains('/') {
        return if direct.is_file() {
            Some(direct.to_path_buf())
        } else {
            None
        };
    }
    let path = std::env::var_os("PATH")?;
    for dir in std::env::split_paths(&path) {
        let candidate = dir.join(command);
        if candidate.is_file() {
            return Some(candidate);
        }
    }
    None
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use super::*;

    // ---- NDJSON framing (PURE, no subprocess) -------------------------------

    #[test]
    fn ndjson_round_trips_one_line() {
        let body = br#"{"jsonrpc":"2.0","id":1,"result":{}}"#;
        let framed = encode_ndjson_line(body);
        assert_eq!(framed.last(), Some(&b'\n'));
        let mut cursor = std::io::Cursor::new(framed);
        let decoded = read_ndjson_line(&mut cursor, MCP_MAX_LINE_BYTES).unwrap();
        assert_eq!(decoded, body);
    }

    #[test]
    fn ndjson_reads_two_back_to_back_and_eofs() {
        let mut stream = encode_ndjson_line(b"first");
        stream.extend_from_slice(&encode_ndjson_line(b"second"));
        let mut cursor = std::io::Cursor::new(stream);
        assert_eq!(
            read_ndjson_line(&mut cursor, MCP_MAX_LINE_BYTES).unwrap(),
            b"first"
        );
        assert_eq!(
            read_ndjson_line(&mut cursor, MCP_MAX_LINE_BYTES).unwrap(),
            b"second"
        );
        assert_eq!(read_ndjson_line(&mut cursor, MCP_MAX_LINE_BYTES), None);
    }

    #[test]
    fn ndjson_tolerates_crlf_and_refuses_over_cap() {
        let mut crlf = std::io::Cursor::new(b"hello\r\n".to_vec());
        assert_eq!(
            read_ndjson_line(&mut crlf, MCP_MAX_LINE_BYTES).unwrap(),
            b"hello"
        );
        // An over-cap line with no terminator within the bound ⇒ clean stop.
        let mut over = std::io::Cursor::new(b"abcdefghij".to_vec());
        assert_eq!(read_ndjson_line(&mut over, 4), None);
        // A truncated final line (content but no '\n') ⇒ None (never partial).
        let mut trunc = std::io::Cursor::new(b"no newline".to_vec());
        assert_eq!(read_ndjson_line(&mut trunc, MCP_MAX_LINE_BYTES), None);
        // Empty stream ⇒ None (EOF).
        let mut empty = std::io::Cursor::new(Vec::new());
        assert_eq!(read_ndjson_line(&mut empty, MCP_MAX_LINE_BYTES), None);
    }

    // ---- the chokepoint's fail-closed gates (no subprocess: deny before spawn) ----

    #[test]
    fn render_denies_unconfigured_server() {
        // No seam at all ⇒ deny.
        let none = render_mcp_call(None, "ghost", "read", "");
        assert!(!none.consumed_read);
        assert_eq!(none.class_label, "mcp.server.not_configured");
        // A seam without the named server ⇒ deny (fail-closed, T2).
        let seam = McpSeam::new(vec![McpServerSpec::new(
            "localfs".to_string(),
            "/bin/echo".to_string(),
            vec![],
        )]);
        let unknown = render_mcp_call(Some(&seam), "ghost", "read", "");
        assert!(!unknown.consumed_read);
        assert_eq!(unknown.class_label, "mcp.server.not_configured");
        // The inert seam denies every call.
        let inert = McpSeam::inert();
        assert_eq!(
            render_mcp_call(Some(&inert), "localfs", "read", "").class_label,
            "mcp.server.not_configured"
        );
    }

    #[test]
    fn render_withholds_secret_arg_before_any_spawn() {
        // A configured server, but a secret-shaped argument ⇒ WITHHELD (never
        // sent to the server's stdin) — the wall fires BEFORE the session, so this
        // holds in EVERY build (feature on or off).
        let seam = McpSeam::new(vec![McpServerSpec::new(
            "localfs".to_string(),
            "/usr/bin/true".to_string(),
            vec![],
        )]);
        let secret = render_mcp_call(
            Some(&seam),
            "localfs",
            "read",
            r#"{"key":"suiprivkey1qexamplenotrealdeadbeefcafe000111"}"#,
        );
        assert!(!secret.consumed_read);
        assert_eq!(secret.class_label, "mcp.arg.withheld_secret");
    }

    #[cfg(not(feature = "mcp"))]
    #[test]
    fn render_honest_degrades_without_the_feature() {
        // A configured server + a benign arg, but the `mcp` codec is not compiled
        // ⇒ the honest not-compiled deny (NEVER a fabricated result).
        let seam = McpSeam::new(vec![McpServerSpec::new(
            "localfs".to_string(),
            "/usr/bin/true".to_string(),
            vec![],
        )]);
        let render = render_mcp_call(Some(&seam), "localfs", "read", "");
        assert!(!render.consumed_read);
        assert_eq!(render.class_label, "mcp.transport.not_compiled");
    }

    #[cfg(feature = "mcp")]
    #[test]
    fn tool_list_membership_and_text_extraction() {
        let list = serde_json::json!({
            "jsonrpc": "2.0", "id": 2,
            "result": { "tools": [ { "name": "read_motd" }, { "name": "echo" } ] }
        });
        assert!(tool_in_list(&list, "read_motd"));
        assert!(tool_in_list(&list, "echo"));
        assert!(!tool_in_list(&list, "write_file"));
        let ok = serde_json::json!({
            "jsonrpc": "2.0", "id": 3,
            "result": { "content": [ { "type": "text", "text": "hello" } ], "isError": false }
        });
        assert_eq!(extract_tool_text(&ok), "hello");
        let err = serde_json::json!({
            "jsonrpc": "2.0", "id": 3,
            "result": { "content": [ { "type": "text", "text": "boom" } ], "isError": true }
        });
        assert!(extract_tool_text(&err).contains("the tool reported an error"));
    }
}
