// sinabro desktop (G-WP-13 spike) — Tauri backend.
//
// The single IPC seam: the frontend sends a command line, this `dispatch_line`
// command tokenizes it and routes it through the SAME shared router the terminal
// uses — `sinabro::dispatch::run` — then returns the rendered output. No second
// truth source; redaction / secret-zero / approval-gating all live inside the
// core, so the GUI inherits them. funds/wallet/mainnet stay HARD-LOCKED in the
// core (this command cannot reach them).

mod remote;

/// Dispatch ONE command line through the mnemos core and return rendered output.
/// Host-routed (VM lane — SSH_REMOTE_DISPATCH_THREAT_MODEL.md): `local` runs the
/// in-process core; `vm` forwards the SAME argv to `sinabro` on the configured
/// SSH host (the seam is location-neutral). An unknown/incomplete host config is
/// a typed error — NEVER a silent local fallback (M6).
#[tauri::command]
async fn dispatch_line(app: tauri::AppHandle, line: String) -> Result<String, String> {
    // `dispatch::run` uses reqwest::blocking — a live LLM consult can block for up
    // to 60s. A SYNC Tauri command runs on the MAIN (UI) thread, which would freeze
    // the whole window for that duration (and starve the Model panel's own
    // provider-status dispatch, so the Arm input never finishes painting).
    // spawn_blocking moves the blocking work to a dedicated pool; the UI thread
    // stays free and responsive.
    tauri::async_runtime::spawn_blocking(move || dispatch_line_sync(&app, line))
        .await
        .map_err(|e| format!("dispatch task failed: {e}"))?
}

/// The blocking dispatch body — runs on a blocking-pool thread, never the main
/// (UI) thread. Host-routed exactly as before (VM lane unchanged).
fn dispatch_line_sync(app: &tauri::AppHandle, line: String) -> Result<String, String> {
    let argv: Vec<String> = line.split_whitespace().map(String::from).collect();
    let host = load_host_config(app)?;
    match host.mode.as_str() {
        "local" => dispatch_local(&argv),
        "vm" => {
            let target = host
                .ssh_target
                .as_deref()
                .filter(|t| !t.trim().is_empty())
                .ok_or_else(|| {
                    "host=vm with no ssh target configured; refusing silent local fallback"
                        .to_string()
                })?;
            let dir = app_data_dir(app)?;
            remote::dispatch_ssh(target, &dir, &argv)
        }
        other => Err(format!(
            "unknown host mode '{other}' in host.json; refusing to dispatch"
        )),
    }
}

/// The original in-process path — same discipline as the terminal REPL
/// (repl/run.rs dispatch_tokens): run through dispatch::run capturing
/// stdout+stderr. Behavior for host=local is byte-identical to before the VM
/// lane existed.
fn dispatch_local(argv: &[String]) -> Result<String, String> {
    let mut out: Vec<u8> = Vec::new();
    let mut err: Vec<u8> = Vec::new();
    sinabro::dispatch::run(argv, &mut out, &mut err).map_err(|e| e.to_string())?;

    // dispatch::run renders ASCII-clamped lines; lossy decode is total + safe.
    let mut rendered = String::from_utf8_lossy(&out).into_owned();
    let errtext = String::from_utf8_lossy(&err);
    if !errtext.trim().is_empty() {
        rendered.push_str("\n[stderr] ");
        rendered.push_str(errtext.trim_end());
    }
    Ok(rendered)
}

/// The single in-flight streaming consult's cancel token (S-C/C2 true mid-turn cancel):
/// `consult_stream_line` registers a fresh token here; `cancel_consult` (the GUI's Esc)
/// sets it; the core SSE codec observes it between frames + the loop between turns. A
/// desktop chat is single-flight, so one slot suffices. NEVER touches funds/wallet/chain.
fn consult_cancel_slot() -> &'static std::sync::Mutex<Option<sinabro::agent_loop::CancelToken>> {
    static SLOT: std::sync::OnceLock<std::sync::Mutex<Option<sinabro::agent_loop::CancelToken>>> =
        std::sync::OnceLock::new();
    SLOT.get_or_init(|| std::sync::Mutex::new(None))
}

/// STREAMING chat consult (S-C/C2): runs `sinabro::dispatch::consult_stream` and pushes
/// each REDACTED delta to the frontend through `on_delta` (a `tauri::ipc::Channel`) AS the
/// model generates, then returns the final rendered card (same as `dispatch_line`).
/// Streaming is the in-process (local) path only — a `vm` host falls back to the
/// non-streaming dispatch (honest; no fake feed). The CORE stays the sole verifier (the
/// phrase + redaction + bounds live in provider_consult; the per-delta push_chunk
/// redaction wall is in the core). funds/wallet/mainnet stay HARD-LOCKED.
#[tauri::command]
async fn consult_stream_line(
    app: tauri::AppHandle,
    line: String,
    on_delta: tauri::ipc::Channel<String>,
) -> Result<String, String> {
    tauri::async_runtime::spawn_blocking(move || consult_stream_sync(&app, line, on_delta))
        .await
        .map_err(|e| format!("consult stream task failed: {e}"))?
}

fn consult_stream_sync(
    app: &tauri::AppHandle,
    line: String,
    on_delta: tauri::ipc::Channel<String>,
) -> Result<String, String> {
    // Streaming is the in-process path; a vm host streams nothing — fall back honestly.
    let host = load_host_config(app)?;
    if host.mode != "local" {
        return dispatch_line_sync(app, line);
    }
    let cancel = sinabro::agent_loop::CancelToken::new();
    if let Ok(mut slot) = consult_cancel_slot().lock() {
        *slot = Some(cancel.clone());
    }
    let mut sink = |delta: &str| {
        let _ = on_delta.send(delta.to_string());
    };
    let out = sinabro::dispatch::consult_stream(&line, &mut sink, &cancel);
    if let Ok(mut slot) = consult_cancel_slot().lock() {
        *slot = None;
    }
    Ok(String::from_utf8_lossy(&out).into_owned())
}

/// The GUI's Esc during a streaming chat: request a TRUE mid-turn cancel of the in-flight
/// consult (the core stops between SSE frames / turns). Idempotent; a no-op if none is in
/// flight. NEVER touches funds/wallet/chain.
#[tauri::command]
fn cancel_consult() -> Result<(), String> {
    if let Ok(slot) = consult_cancel_slot().lock() {
        if let Some(token) = slot.as_ref() {
            token.cancel();
        }
    }
    Ok(())
}

/// Persisted GUI host selection: `local` (in-process, default) or `vm`
/// (SSH-exec remote dispatch). Stored as `host.json` in app-data; the target
/// string is re-validated on EVERY load and use (TM M3/T10) — an invalid file
/// is a typed error, never a fallback. NOT yet exposed in the UI: per the
/// no-fake-feature gate the `host: local / VM` selector ships only after the
/// SSH backend is proven against a real VM.
#[derive(serde::Serialize, serde::Deserialize, Clone)]
struct HostConfig {
    mode: String,
    #[serde(default)]
    ssh_target: Option<String>,
}

impl Default for HostConfig {
    fn default() -> Self {
        HostConfig {
            mode: "local".to_string(),
            ssh_target: None,
        }
    }
}

/// Resolve the OS app-data dir (`~/Library/Application Support/com.sinabro.desktop`).
fn app_data_dir(app: &tauri::AppHandle) -> Result<std::path::PathBuf, String> {
    use tauri::Manager;
    app.path().app_data_dir().map_err(|e| e.to_string())
}

fn host_path(app: &tauri::AppHandle) -> Result<std::path::PathBuf, String> {
    Ok(app_data_dir(app)?.join("host.json"))
}

/// Load + re-validate the host config (absent file = the local default).
fn load_host_config(app: &tauri::AppHandle) -> Result<HostConfig, String> {
    let path = host_path(app)?;
    let text = match std::fs::read_to_string(&path) {
        Ok(text) => text,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(HostConfig::default()),
        Err(e) => return Err(e.to_string()),
    };
    let cfg: HostConfig =
        serde_json::from_str(&text).map_err(|e| format!("host.json parse error: {e}"))?;
    if cfg.mode == "vm" {
        if let Some(target) = cfg.ssh_target.as_deref() {
            remote::parse_target(target)?;
        }
    }
    Ok(cfg)
}

/// Read the active host selection (for a future, proven host selector UI).
#[tauri::command]
fn get_host(app: tauri::AppHandle) -> Result<HostConfig, String> {
    load_host_config(&app)
}

/// Persist the host selection. `vm` requires a target that passes the M3
/// validator (`user@host[:port]`, closed charset); anything else is rejected.
#[tauri::command]
fn set_host(
    app: tauri::AppHandle,
    mode: String,
    ssh_target: Option<String>,
) -> Result<HostConfig, String> {
    let cfg = match mode.as_str() {
        "local" => HostConfig {
            mode,
            ssh_target: None,
        },
        "vm" => {
            let target = ssh_target
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .ok_or_else(|| "vm mode requires an ssh target: user@host[:port]".to_string())?;
            remote::parse_target(&target)?;
            HostConfig {
                mode,
                ssh_target: Some(target),
            }
        }
        other => return Err(format!("unknown host mode '{other}'")),
    };
    let path = host_path(&app)?;
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| e.to_string())?;
    }
    let tmp = path.with_extension("json.tmp");
    let json = serde_json::to_string_pretty(&cfg).map_err(|e| e.to_string())?;
    std::fs::write(&tmp, json.as_bytes()).map_err(|e| e.to_string())?;
    std::fs::rename(&tmp, &path).map_err(|e| e.to_string())?;
    Ok(cfg)
}

/// A redaction-safe projection of a user input line for display + persistence.
/// `display` is either the verbatim line (when safe) or the core's redaction
/// label (`<redacted:...>`). Returned to the frontend so it can store/show this
/// instead of the raw line.
#[derive(serde::Serialize)]
struct RedactedInput {
    redacted: bool,
    display: String,
}

/// Classify a user input line through the SAME core redactor the terminal REPL
/// uses (`HistoryStore::push` -> `classify` -> `redact_for_log`) and return a
/// secret-zero display projection. Single truth source: the classification and
/// the `<redacted:...>` label come from the core, never re-implemented in JS.
/// The GUI shows/persists this projection — never the raw line — so a pasted
/// key / token never lands in the on-disk session file.
#[tauri::command]
fn redact_input(line: String) -> RedactedInput {
    use sinabro::repl::history::{HistoryEntry, HistoryStore};
    let mut history = HistoryStore::new(1);
    history.push(&line);
    // Take an owned label so the `entries()` borrow ends before `history` drops.
    let redacted_label = match history.entries().next() {
        Some(HistoryEntry::Redacted(value)) => Some(value.to_string()),
        _ => None,
    };
    match redacted_label {
        Some(display) => RedactedInput {
            redacted: true,
            display,
        },
        None => RedactedInput {
            redacted: false,
            display: line,
        },
    }
}

/// Resolve the GUI session-store path under the OS app-data dir
/// (`~/Library/Application Support/com.sinabro.desktop/sessions.json` on macOS).
fn sessions_path(app: &tauri::AppHandle) -> Result<std::path::PathBuf, String> {
    use tauri::Manager;
    let dir = app.path().app_data_dir().map_err(|e| e.to_string())?;
    Ok(dir.join("sessions.json"))
}

/// Load the persisted GUI session transcript JSON (empty string when none yet).
/// The payload is GUI-owned and already secret-zero: every stored input line
/// passed through `redact_input`, and every response card is the core's
/// secret-zero render. funds / wallet / mainnet are unreachable from here.
#[tauri::command]
fn load_sessions(app: tauri::AppHandle) -> Result<String, String> {
    let path = sessions_path(&app)?;
    match std::fs::read_to_string(&path) {
        Ok(text) => Ok(text),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(String::new()),
        Err(e) => Err(e.to_string()),
    }
}

/// Persist the GUI session transcript JSON (atomic: write temp, then rename).
#[tauri::command]
fn save_sessions(app: tauri::AppHandle, json: String) -> Result<(), String> {
    let path = sessions_path(&app)?;
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| e.to_string())?;
    }
    let tmp = path.with_extension("json.tmp");
    std::fs::write(&tmp, json.as_bytes()).map_err(|e| e.to_string())?;
    std::fs::rename(&tmp, &path).map_err(|e| e.to_string())?;
    Ok(())
}

/// Resolve the GUI settings-store path (`…/settings.json`) — durable across restarts,
/// INDEPENDENT of the webview's localStorage (P0 #16/#17, owner 2026-06-30: "닫으면
/// 세팅값 초기화" — the UI prefs must persist regardless of webview storage durability).
fn settings_path(app: &tauri::AppHandle) -> Result<std::path::PathBuf, String> {
    use tauri::Manager;
    let dir = app.path().app_data_dir().map_err(|e| e.to_string())?;
    Ok(dir.join("settings.json"))
}

/// Load the persisted GUI settings JSON (the `sinabro.*` UI prefs: mode / layout / root
/// / wrap …). Empty string when none yet. SECRET-ZERO: the API key is NOT stored here
/// (it goes through `set_secret`); funds / wallet are unreachable from this surface.
#[tauri::command]
fn load_settings(app: tauri::AppHandle) -> Result<String, String> {
    let path = settings_path(&app)?;
    match std::fs::read_to_string(&path) {
        Ok(text) => Ok(text),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(String::new()),
        Err(e) => Err(e.to_string()),
    }
}

/// Persist the GUI settings JSON (atomic: write temp, then rename).
#[tauri::command]
fn save_settings(app: tauri::AppHandle, json: String) -> Result<(), String> {
    let path = settings_path(&app)?;
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| e.to_string())?;
    }
    let tmp = path.with_extension("json.tmp");
    std::fs::write(&tmp, json.as_bytes()).map_err(|e| e.to_string())?;
    std::fs::rename(&tmp, &path).map_err(|e| e.to_string())?;
    Ok(())
}

/// The closed allowlist of env names the GUI may set (S threat model gate 1).
/// ONLY the OpenRouter key + model selector + the two Telegram values + the Walrus
/// self-host publisher bearer (S2, WALRUS_MAINNET_SELFHOST) + the BYO-model routing
/// selectors — never PATH / LD_PRELOAD / DYLD_* / arbitrary env, which would be a
/// code-execution vector. A non-allowlisted name is a typed error, never set.
/// (OPENROUTER_MODEL is not a secret — a plain model selector — but rides the same
/// memory-only env-injection mechanism. WALRUS_PUBLISHER_TOKEN is the bearer the core
/// sends ONLY as `Authorization: Bearer` to the configured self-host publisher; it is
/// NEVER a Sui private key — our app holds no key, never signs, never pays (PD-6 custody
/// HARD-LOCKED). The four SINABRO_* selectors are NOT secrets — plain CLOSED-SET tokens
/// (`local`/`remote`, `openrouter`/`sakana`) + a model id; the core resolves the provider
/// host via a closed enum [`ProviderHost::live_codec_from_token`], so there is NO
/// arbitrary-URL form and funds-egress stays structurally impossible.)
const ALLOWED_SECRET_ENVS: [&str; 9] = [
    "OPENROUTER_API_KEY",
    "OPENROUTER_MODEL",
    "TELEGRAM_BOT_TOKEN",
    "TELEGRAM_CHAT_ID",
    "WALRUS_PUBLISHER_TOKEN",
    // BYO-model routing selectors (Slice 1+2): which frontier provider the consult uses,
    // and the two-model loop's implement-brain mode/provider/model. Plain closed-set
    // selectors (never a URL / secret / code-exec env).
    "SINABRO_FRONTIER_PROVIDER",
    "SINABRO_EXECUTOR_MODE",
    "SINABRO_EXECUTOR_PROVIDER",
    "SINABRO_EXECUTOR_MODEL",
];

/// Presence-only view of a secret env (value NEVER returned — gate 3).
#[derive(serde::Serialize)]
struct SecretStatus {
    name: String,
    present: bool,
}

/// Set one of the three allowlisted egress secrets into the BACKEND PROCESS env
/// (memory only — gate 2). The unchanged core reads it via `std::env::var` at the
/// TLS boundary. NOTHING is written to disk; the value is never logged, echoed,
/// or returned. Cleared when the app closes. Threat model:
/// ops/evidence/stage_g/gui_desktop/SECRET_INPUT_THREAT_MODEL.md.
#[tauri::command]
fn set_secret(name: String, value: String) -> Result<(), String> {
    if !ALLOWED_SECRET_ENVS.contains(&name.as_str()) {
        // Error carries the NAME only, never the value (gate 4).
        return Err(format!("secret name '{name}' is not in the allowlist"));
    }
    if value.is_empty() {
        return Err("empty value; nothing set".to_string());
    }
    // Memory-only sink: process env. No file path exists in this function.
    // SAFETY (edition 2021): `set_var` is a safe fn here; the env data-race is
    // mitigated operationally (single-user desktop, set-then-dispatch).
    std::env::set_var(&name, &value);
    Ok(())
}

/// Register owner-dropped directories as file-read roots (agent-core lane A).
///
/// A drag-drop IS an explicit capability grant: the owner chose these files,
/// so the core's `file read` tool may read inside their parent directories
/// (the secret-denylist + redaction + size cap STILL apply — widening admits
/// ordinary files, never key/dotfile containers). The value is the same
/// `SINABRO_FILE_ROOTS` env the core reads (`file_context::FILE_ROOTS_ENV`);
/// we APPEND unique, non-empty dirs (memory-only, this process, never disk).
/// Paths only — never file bytes (the GUI never reads files).
#[tauri::command]
fn register_file_roots(dirs: Vec<String>) -> Result<(), String> {
    const ENV: &str = "SINABRO_FILE_ROOTS";
    let mut roots: Vec<String> = std::env::var(ENV)
        .ok()
        .map(|v| {
            v.split(':')
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .map(String::from)
                .collect()
        })
        .unwrap_or_default();
    for dir in dirs {
        let trimmed = dir.trim().to_string();
        if !trimmed.is_empty() && !roots.contains(&trimmed) {
            roots.push(trimmed);
        }
    }
    // SAFETY (edition 2021): `set_var` is a safe fn here; same set-then-dispatch
    // single-user mitigation as `set_secret`. No path is logged or returned.
    std::env::set_var(ENV, roots.join(":"));
    Ok(())
}

/// Open a NATIVE folder picker (the GUI `+` button, P4-3 ②) and, on a choice,
/// register the chosen folder as a read root via [`register_file_roots`]
/// (R-F1: a pick is an owner-explicit capability grant, identical in trust to a
/// drag). Returns the chosen ABSOLUTE PATH (or `None` if cancelled) — a PATH
/// only, NEVER file bytes; the gated core re-walls every later access (lane-A
/// allowlist + denylist + size + redaction; `context index` IV-F8..F11). The
/// dialog runs via `blocking_pick_folder` on a `spawn_blocking` worker inside an
/// `async` command so the UI never freezes (PERF-1). The MODEL has no path here
/// (a GUI IPC command, not a loop tool). Threat model:
/// `ops/evidence/stage_g/agent_loop/FILE_CONTEXT_THREAT_MODEL.md` §P4-3.
#[tauri::command]
async fn pick_folder(app: tauri::AppHandle) -> Result<Option<String>, String> {
    use tauri_plugin_dialog::DialogExt;
    let picked =
        tauri::async_runtime::spawn_blocking(move || app.dialog().file().blocking_pick_folder())
            .await
            .map_err(|e| format!("folder dialog task failed: {e}"))?;
    let Some(file_path) = picked else {
        return Ok(None); // owner cancelled — clean no-op
    };
    let path = file_path
        .into_path()
        .map_err(|_| "picked path is not a local folder".to_string())?;
    let path_str = path.to_string_lossy().to_string();
    // Register the picked folder as a read root (the SAME owner-explicit grant as
    // a drag; the lane-A walls still refuse secret containers ON ACCESS). Paths
    // only — never file bytes.
    register_file_roots(vec![path_str.clone()])?;
    Ok(Some(path_str))
}

/// Clear one allowlisted secret from the backend process env.
#[tauri::command]
fn clear_secret(name: String) -> Result<(), String> {
    if !ALLOWED_SECRET_ENVS.contains(&name.as_str()) {
        return Err(format!("secret name '{name}' is not in the allowlist"));
    }
    std::env::remove_var(&name);
    Ok(())
}

/// Report which of the three secrets are currently set — PRESENCE BOOLEANS ONLY
/// (gate 3). No command ever returns a secret value.
#[tauri::command]
fn secret_status() -> Vec<SecretStatus> {
    ALLOWED_SECRET_ENVS
        .iter()
        .map(|name| SecretStatus {
            name: (*name).to_string(),
            present: std::env::var(name).map(|v| !v.is_empty()).unwrap_or(false),
        })
        .collect()
}

/// A#1 (owner 2026-07-01 "모델 설정 아예 안됨") — the RESOLVED frontier consult model, so the
/// Settings panel shows the model the core will ACTUALLY use (not a hardcoded "deepseek-chat"
/// label that lied about an explicit GLM selection). The model id is a public routing string
/// (NOT a credential), so returning it is secret-zero-safe.
#[tauri::command]
fn frontier_model_view() -> String {
    let v = std::env::var("OPENROUTER_MODEL").unwrap_or_default();
    let v = v.trim();
    if v.is_empty() {
        format!(
            "{} (default)",
            sinabro::commands::model_select::FRONTIER_DEFAULT_MODEL
        )
    } else {
        v.to_string()
    }
}

/// S4 (WALRUS_MAINNET_SELFHOST) — presence-only posture of the self-host Walrus config,
/// for the Settings "● connected (memory)" status. Booleans ONLY: no endpoint URL or token
/// value is ever returned (the same secret-zero discipline as `secret_status`).
#[derive(serde::Serialize)]
struct WalrusStatusView {
    /// A valid (https + SSRF-walled) self-host PUBLISHER endpoint is configured.
    publisher_configured: bool,
    /// A valid self-host AGGREGATOR endpoint is configured (the READ side).
    aggregator_configured: bool,
    /// The `WALRUS_PUBLISHER_TOKEN` bearer is present in the process env (memory-only).
    token_present: bool,
}

/// S4 — report the self-host Walrus posture (presence only). Reuses the SAME core resolvers
/// the WRITE ceremony + the auto-activate READ use (`configured_walrus_publisher/aggregator`),
/// so "configured" means "configured AND passes the https + SSRF wall" — never a raw value.
/// custody/funds stay HARD-LOCKED (PD-6): no Sui key / sign / funds is reachable here.
#[tauri::command]
fn walrus_status() -> WalrusStatusView {
    WalrusStatusView {
        publisher_configured: sinabro::provider::walrus_selfhost::configured_walrus_publisher()
            .is_some(),
        aggregator_configured: sinabro::provider::walrus_selfhost::configured_walrus_aggregator()
            .is_some(),
        token_present: std::env::var("WALRUS_PUBLISHER_TOKEN")
            .map(|v| !v.is_empty())
            .unwrap_or(false),
    }
}

/// First 8 bytes of a 32-byte content hash as 16 lowercase hex chars (the
/// `sha=` short form the core renders, computed here without reaching a private
/// core helper).
fn short_hex(bytes: &[u8; 32]) -> String {
    bytes[..8].iter().map(|b| format!("{b:02x}")).collect()
}

/// A file's content for the GUI VIEWER, read through the core's lane-A walls.
///
/// WHY a dedicated command (not the `context file` verb): `dispatch::run`'s emit
/// is a TERMINAL CARD — control-stripped, clamped to 80 columns AND bounded to 64
/// rows (`dispatch.rs` `clamp_ascii` + `ROWS`). That is structurally wrong as an
/// editor data source (a 400-line file would arrive as ~57 clamped lines). This
/// command reuses the SAME safety primitives the `context file` handler uses —
/// `FileReadPolicy::cwd_default().read()` (allowlist + denylist + size + symlink +
/// utf-8 walls) and the canonical `redact()` gate (secret-shaped ⇒ withheld) —
/// but returns the FULL, unclamped content as structured data. NO prototype core
/// change; the walls are the single source of truth, only the render shape differs.
#[derive(serde::Serialize)]
#[serde(tag = "kind")]
enum FileView {
    // `sha_full` = the full 64-hex content hash (the P2-S5 owner-save staleness baseline; the
    // editor sends it back to owner_save_file so a since-changed file is refused). `sha` stays the
    // short display form.
    #[serde(rename = "text")]
    Text {
        content: String,
        bytes: usize,
        sha: String,
        sha_full: String,
        path: String,
    },
    #[serde(rename = "binary")]
    Binary { bytes: usize, sha: String },
    #[serde(rename = "withheld")]
    Withheld { bytes: usize, sha: String },
    #[serde(rename = "denied")]
    Denied { reason: String },
}

/// One file-tree entry (path RELATIVE to the indexed root). Mirrors
/// `sinabro::project_index::ProjectIndexEntry`, content-free.
#[derive(serde::Serialize)]
struct IndexEntry {
    path: String,
    dir: bool,
    link: bool,
    size: u64,
}

/// A project file tree for the GUI EXPLORER, read through the core's lane-A walls.
/// Same rationale as [`FileView`]: the `context index` verb's emit caps the
/// listing to ~57 rows; this returns the full bounded index (≤ the walker's own
/// 4096-entry cap). Safety parity: `index_project` already denylist-prunes secret
/// containers, and a secret-SHAPED name trips `scan_inline_secret` ⇒ the whole
/// listing is withheld (exactly the `project_index_body` `redact_or_withhold`).
#[derive(serde::Serialize)]
#[serde(tag = "kind")]
enum IndexView {
    #[serde(rename = "index")]
    Index {
        root: String,
        truncated: bool,
        entries: Vec<IndexEntry>,
    },
    #[serde(rename = "withheld")]
    Withheld,
    #[serde(rename = "denied")]
    Denied { reason: String },
}

/// Read ONE local file's FULL content for the viewer (lane-A walls + redaction;
/// PATHS only ever cross from the GUI — the core reads the bytes). Mirrors
/// `dispatch.rs::file_context_body` composition, minus the 80x64 emit clamp.
#[tauri::command]
fn read_file_view(path: String) -> FileView {
    let policy = sinabro::file_context::FileReadPolicy::cwd_default();
    let result = match policy.read(std::path::Path::new(&path)) {
        Ok(result) => result,
        Err(deny) => {
            return FileView::Denied {
                reason: deny.class_label().to_string(),
            }
        }
    };
    // Read the non-text fields BEFORE moving `text` out of `result`.
    let bytes = result.len_bytes();
    let sha = short_hex(&result.sha256_32);
    let sha_full = sinabro::hex32(&result.sha256_32); // P2-S5 owner-save staleness baseline
    let canonical = result.canonical_path.display().to_string();
    match result.text {
        None => FileView::Binary { bytes, sha }, // binary ⇒ metadata only (IV-F5)
        Some(text) => {
            // IV-F6 — the canonical redaction gate, on the LOCAL surface too: a
            // secret-shaped file is withheld rather than echoed (identical to the
            // `context file` handler's gate).
            let fragments = [text.as_str()];
            let denied = match sinabro::provider::redaction::redact(
                &sinabro::provider::redaction::RedactionRequest {
                    fragments: &fragments,
                    candidate_memory_ids: &[],
                    deleted_ids: &[],
                    include_private_memory: false,
                },
            ) {
                Ok(receipt) => receipt.secret_fragments_denied_u32() != 0,
                Err(_) => true, // fail-closed: any redaction error ⇒ withhold
            };
            if denied {
                FileView::Withheld { bytes, sha }
            } else {
                FileView::Text {
                    content: text,
                    bytes,
                    sha,
                    sha_full,
                    path: canonical,
                }
            }
        }
    }
}

// ── P2-S5: DIRECT owner save (center editor edit-mode → Save) ─────────────────────────────
// The owner edits a file in the center viewer and saves it. The heavy logic stays in the CORE
// (sinabro::file_edit::owner_save_file): lane-A confinement (only an owner-granted root, exactly
// as it is readable) + the IV-W3 staleness lock (the editor's read sha must still match the disk)
// + atomic mode-preserving replace + verify. This is a GUI IPC command, NOT a loop tool — the
// MODEL has no path to it (it cannot self-save). The receipt is metadata-only (secret-zero — the
// saved content is never echoed back). NEVER chain-write; custody/funds HARD-LOCKED (PD-6).
// Distinct from `tool apply file-apply-owner-live <id>` (which applies a MODEL proposal).

/// The edited file payload from the center editor (single struct arg → no JS/Rust arg-name case
/// ambiguity; nested fields matched by serde). `base_sha` = the full 64-hex the editor read.
#[derive(serde::Deserialize)]
struct OwnerSaveIn {
    path: String,
    content: String,
    base_sha: String,
}

/// The owner-save success receipt (metadata only; never the content).
#[derive(serde::Serialize)]
struct OwnerSaveOk {
    bytes: u64,
    sha: String,
}

/// Persist an owner-edited file through the core's owner_save_file (confinement + staleness +
/// atomic replace + verify). A typed deny (stale / wall / malformed-baseline / io) is a class
/// string the GUI surfaces honestly.
#[tauri::command]
fn owner_save_file(payload: OwnerSaveIn) -> Result<OwnerSaveOk, String> {
    let policy = sinabro::file_context::FileReadPolicy::cwd_default();
    match sinabro::file_edit::owner_save_file(
        &policy,
        std::path::Path::new(&payload.path),
        payload.content.as_bytes(),
        &payload.base_sha,
    ) {
        Ok(receipt) => Ok(OwnerSaveOk {
            bytes: receipt.bytes_written_u64,
            sha: short_hex(&receipt.new_sha_32),
        }),
        Err(deny) => Err(deny.class_label().to_string()),
    }
}

// ── P6: INLINE FIM (fill-in-the-middle) autocomplete for the center editor ──────────────────
// The editor sends the text BEFORE the cursor (`prefix`) and AFTER (`suffix`); the core frames ONE
// bounded chat turn to the LOOPBACK local model (the SAME transport the local consult uses) and
// returns ONLY the predicted insertion text (capped). HONEST-DEGRADES to Err when no local model is
// compiled OR reachable — the GUI then shows NO ghost (never a fabricated completion). This is a GUI
// IPC command, NOT a loop tool — the MODEL has no path to it (it cannot self-complete). LOOPBACK-ONLY
// (no off-box egress); never chain-write; custody/funds HARD-LOCKED (PD-6).

/// The cursor context from the center editor (single struct arg → no JS/Rust arg-name case
/// ambiguity; nested fields matched by serde). `prefix` = text before the cursor; `suffix` = after.
#[derive(serde::Deserialize)]
struct FimIn {
    prefix: String,
    suffix: String,
}

/// One inline FIM completion via the core's `fim_complete_local` (loopback local model, bounded).
/// Runs on a blocking-pool thread (the HTTP round-trip must not block the UI thread). An `Err`
/// (no local model compiled / unreachable) is an honest-degrade ⇒ the GUI shows no ghost.
#[tauri::command]
async fn fim_complete(payload: FimIn) -> Result<String, String> {
    tauri::async_runtime::spawn_blocking(move || {
        sinabro::dispatch::fim_complete_local(&payload.prefix, &payload.suffix)
    })
    .await
    .map_err(|e| format!("fim task failed: {e}"))?
}

// ── B⑧: Cmd-K INLINE EDIT — select → NL instruction → INERT proposal → owner single-approve ──────
// The center editor sends the SELECTED text + a natural-language instruction (+ a bounded context
// window). The core loopback-transforms ONLY the selection (zero egress), then SEALS the result as
// an INERT FileEditProposal (the EXISTING PROPOSE-EDIT machinery — IV-W2 read-bound + secret-screen).
// The GUI renders old→new through its EXISTING diff view; the owner single-approves via the EXISTING
// `tool apply file-apply-owner-live` verb (the MODEL never applies). LOOPBACK-ONLY; custody HARD-LOCKED.

/// The Cmd-K request from the center editor (single struct arg → no JS/Rust arg-name case ambiguity).
/// `sel_text` = the exact selected text (located UNIQUELY in the file server-side — no numeric offset
/// crosses the boundary); `ctx_before`/`ctx_after` = a bounded model-context window.
#[derive(serde::Deserialize)]
struct InlineEditIn {
    path: String,
    sel_text: String,
    instruction: String,
    ctx_before: String,
    ctx_after: String,
}

/// The inline-edit propose receipt: the pending-proposal id + the old/new full content the GUI diffs.
/// The owner approves `id` via `tool apply file-apply-owner-live` (dispatch_line) — a single approve.
#[derive(serde::Serialize)]
struct InlineEditOut {
    id: String,
    old_content: String,
    new_content: String,
}

/// Propose a Cmd-K inline edit via the core's loopback transform + PROPOSE-EDIT seal. Runs on the
/// blocking pool (the model round-trip must not block the UI). An `Err` (no local model / read-deny /
/// ambiguous selection / mint wall) is an honest class string the GUI surfaces — never a fake edit.
#[tauri::command]
async fn inline_edit_propose(payload: InlineEditIn) -> Result<InlineEditOut, String> {
    tauri::async_runtime::spawn_blocking(move || {
        sinabro::dispatch::inline_edit_propose_local(
            &payload.path,
            &payload.sel_text,
            &payload.instruction,
            &payload.ctx_before,
            &payload.ctx_after,
        )
        .map(|p| InlineEditOut {
            id: p.id,
            old_content: p.old_content,
            new_content: p.new_content,
        })
    })
    .await
    .map_err(|e| format!("inline-edit task failed: {e}"))?
}

/// The ADVISORY Move-build oracle badge for a just-minted inline-edit proposal (owner-locked:
/// Move-only, advisory — the single-approve is final). A SECOND IPC so the diff renders instantly and
/// the badge resolves after. Runs on the blocking pool (a bounded `sui move build`).
#[derive(serde::Deserialize)]
struct InlineOracleIn {
    id: String,
    path: String,
}

#[tauri::command]
async fn inline_edit_oracle(payload: InlineOracleIn) -> Result<String, String> {
    // (clippy::needless_question_mark — newer toolchain; the JoinError→String map already yields
    //  the Result<String, String> this command returns. Behavior-identical to the prior Ok(…?)).
    tauri::async_runtime::spawn_blocking(move || {
        sinabro::dispatch::inline_edit_oracle_for(&payload.id, &payload.path)
    })
    .await
    .map_err(|e| format!("inline-oracle task failed: {e}"))
}

// ── B⑬: PLAN MODE — run the frontier PLAN, then execute the OWNER-APPROVED sub-task subset ───────
// Two IPCs: `orchestrate_plan` runs ONLY the frontier PLAN + decompose (returns the canonical SUBTASK
// lines for the editable checklist — NO implement, NO synthesis, INERT); `orchestrate_run` runs
// IMPLEMENT+SYNTHESIZE over the lines the owner approved (re-validated server-side by the SAME
// grammar parser). The frontier calls are phrase-gated (egress); the model never auto-runs the plan.

/// The Plan-phase request (the orchestrate phrase + the task to decompose).
#[derive(serde::Deserialize)]
struct OrchestratePlanIn {
    phrase: String,
    task: String,
}

/// The Plan-phase result: the canonical `SUBTASK ...` lines for the owner to review/disable.
#[derive(serde::Serialize)]
struct OrchestratePlanOut {
    subtasks: Vec<String>,
}

#[tauri::command]
async fn orchestrate_plan(payload: OrchestratePlanIn) -> Result<OrchestratePlanOut, String> {
    tauri::async_runtime::spawn_blocking(move || {
        sinabro::dispatch::orchestrate_plan_for(&payload.phrase, &payload.task)
            .map(|subtasks| OrchestratePlanOut { subtasks })
    })
    .await
    .map_err(|e| format!("orchestrate-plan task failed: {e}"))?
}

/// The Run-phase request: the phrase + task + the owner-APPROVED SUBTASK lines (enabled subset).
#[derive(serde::Deserialize)]
struct OrchestrateRunIn {
    phrase: String,
    task: String,
    approved: Vec<String>,
}

/// One STRUCTURED routed worker for the GUI fleet pane (K-5b): the (port, model_id) the
/// orchestrator fanned out + the DETERMINISTIC verify-oracle verdict/admission. Mirrors
/// `sinabro::dispatch::OrchestrateWorkerView`. Money 0 — a render of an already-gated local
/// loop result; NO custody / sign / chain field exists here (IV-FG7).
#[derive(serde::Serialize)]
struct OrchestrateWorkerOut {
    id: u32,
    kind: String,
    port: u16,
    model_id: String,
    verdict: String,
    admits: bool,
    preview: String,
}

/// The Run-phase result: the typed stop, the synthesis, and the STRUCTURED routed workers
/// (the fleet pane reads fields, never re-parses lines — the single-truth-source law).
#[derive(serde::Serialize)]
struct OrchestrateRunOut {
    stop: String,
    synthesis: Option<String>,
    workers: Vec<OrchestrateWorkerOut>,
}

#[tauri::command]
async fn orchestrate_run(payload: OrchestrateRunIn) -> Result<OrchestrateRunOut, String> {
    tauri::async_runtime::spawn_blocking(move || {
        sinabro::dispatch::orchestrate_run_for(&payload.phrase, &payload.task, &payload.approved)
            .map(|v| OrchestrateRunOut {
                stop: v.stop,
                synthesis: v.synthesis,
                workers: v
                    .workers
                    .into_iter()
                    .map(|w| OrchestrateWorkerOut {
                        id: w.id,
                        kind: w.kind,
                        port: w.port,
                        model_id: w.model_id,
                        verdict: w.verdict,
                        admits: w.admits,
                        preview: w.preview,
                    })
                    .collect(),
            })
    })
    .await
    .map_err(|e| format!("orchestrate-run task failed: {e}"))?
}

/// Read a project's FULL file tree for the explorer (lane-A walls; content-free).
/// Mirrors `dispatch.rs::project_index_body` composition, minus the emit clamp.
#[tauri::command]
fn read_index_view(path: String) -> IndexView {
    let policy = sinabro::file_context::FileReadPolicy::cwd_default();
    let index = match sinabro::project_index::index_project(&policy, std::path::Path::new(&path)) {
        Ok(index) => index,
        Err(deny) => {
            return IndexView::Denied {
                reason: deny.class_label().to_string(),
            }
        }
    };
    // Safety parity with `redact_or_withhold`: a secret-SHAPED name ⇒ withhold the
    // WHOLE listing (the precise inline-secret detector, never the path-false-
    // positive `redact` gate).
    if index
        .entries
        .iter()
        .any(|e| sinabro::secrets::scan_inline_secret(&e.rel_path))
    {
        return IndexView::Withheld;
    }
    let entries = index
        .entries
        .iter()
        .map(|e| IndexEntry {
            path: e.rel_path.clone(),
            dir: e.is_dir,
            link: e.is_symlink,
            size: e.size_bytes,
        })
        .collect();
    IndexView::Index {
        root: index.root.display().to_string(),
        truncated: index.truncated,
        entries,
    }
}

/// One pending file-edit proposal for the GUI diff + SINGLE approval gate (R5).
/// READ-ONLY: this surfaces what the model PROPOSED; the actual write happens
/// ONLY through the real `tool apply file-apply-owner-live <id>` ceremony (the
/// core enforces the typed phrase + staleness lock + atomic replace — the GUI
/// never writes a file). `old`/`new` feed a cosmetic diff; `stale` mirrors the
/// core's staleness check so the owner sees if the target drifted since propose.
#[derive(serde::Serialize)]
struct ProposalView {
    id: String,
    target: String,
    new_content: String,
    old_content: Option<String>,
    stale: bool,
    note: Option<String>,
}

/// List pending file-edit proposals (the model-authored, owner-unapplied set).
/// Reuses the core's `ProposalStore` (sealed, content-addressed) + the lane-A
/// read walls for the CURRENT content + the canonical redaction gate so a
/// secret-shaped current file is never diffed into the GUI. No store / no key ⇒
/// an empty list (honest: nothing pending). NEVER writes.
#[tauri::command]
fn read_proposals() -> Result<Vec<ProposalView>, String> {
    let store = match sinabro::file_edit::ProposalStore::open_local() {
        Ok(store) => store,
        // No proposals dir / no memory key yet ⇒ nothing pending (not an error).
        Err(_) => return Ok(Vec::new()),
    };
    let pending = store.load_pending();
    let policy = sinabro::file_context::FileReadPolicy::cwd_default();
    let mut out = Vec::new();
    for p in pending.proposals {
        let id: String = p
            .record_name
            .chars()
            .take(sinabro::file_edit::PROPOSAL_ID_HEX_CHARS)
            .collect();
        let target = p.proposal.target_path.display().to_string();
        // The proposed content was redaction-REFUSED at mint if secret-shaped, so
        // it is safe to render. The CURRENT file is gated again here.
        let new_content = String::from_utf8_lossy(&p.proposal.content).to_string();
        let (old_content, stale, note) = match policy.read(p.proposal.target_path.as_path()) {
            Ok(result) => {
                let stale = result.sha256_32 != p.proposal.read_sha_32;
                match result.text {
                    Some(text) => {
                        let fragments = [text.as_str()];
                        let secret = match sinabro::provider::redaction::redact(
                            &sinabro::provider::redaction::RedactionRequest {
                                fragments: &fragments,
                                candidate_memory_ids: &[],
                                deleted_ids: &[],
                                include_private_memory: false,
                            },
                        ) {
                            Ok(receipt) => receipt.secret_fragments_denied_u32() != 0,
                            Err(_) => true,
                        };
                        if secret {
                            (
                                None,
                                stale,
                                Some("current file is secret-shaped (redaction)".to_string()),
                            )
                        } else {
                            (Some(text), stale, None)
                        }
                    }
                    None => (None, stale, Some("current file is binary".to_string())),
                }
            }
            // Can't read the current file ⇒ treat as stale (apply will also deny).
            Err(deny) => (
                None,
                true,
                Some(format!("current file unreadable ({})", deny.class_label())),
            ),
        };
        out.push(ProposalView {
            id,
            target,
            new_content,
            old_content,
            stale,
            note,
        });
    }
    Ok(out)
}

/// Always-on status-bar backing (R6 — the "local signature"). A STRUCTURED
/// channel (never emit-text parsing — the R4.5 lesson): the GUI status bar needs
/// stable fields, not a regex over an 80x64 terminal card. The core stays the
/// single source of truth; only the render shape differs.
///
/// Honest-by-construction (no-fake-feature):
/// - `cores` is a real `std::available_parallelism` probe (None ⇒ the GUI shows
///   "—", never a fabricated 0); GPU/VRAM/RAM would need a new dep ⇒ owner-gated.
/// - `budget_*` mirror `dispatch::cmd_budget`'s default — the SAME `BudgetCap`
///   the `budget` verb renders, via the same pub constructor (byte-identical
///   numbers in the GUI and the terminal).
/// - `tps` is None: NO live throughput measurement is wired into the consult path
///   (`route.rs` `ServingMetrics` has no production feeder), so the bar shows an
///   honest "—" rather than a placeholder. It populates only when a real
///   measurement lands — never guessed.
#[derive(serde::Serialize)]
struct StatusView {
    /// Usable CPU cores (`std::thread::available_parallelism`). None ⇒ honest "—".
    cores: Option<u32>,
    /// Session token-budget cap (the pre-dispatch fail-closed gate).
    budget_tokens: u32,
    /// Cost cap in micro-USD (1_000_000 = $1.00).
    budget_cost_micros: u64,
    /// Per-dispatch deadline (ms).
    budget_deadline_ms: u32,
    /// Output tokens/sec — None until a live consult feeds throughput (honest "—").
    tps: Option<u32>,
}

/// Structured status-bar backing for R6 (HW · token budget · TPS). Read-only: no
/// egress, no fs, no secret surface; funds/wallet/mainnet untouched.
#[tauri::command]
fn read_status_view() -> StatusView {
    // HW — a real probe (usable cores, respects cgroup/affinity). None on the rare
    // probe failure ⇒ the GUI renders "—", never a fake number.
    let cores = std::thread::available_parallelism()
        .ok()
        .map(|n| n.get() as u32);
    // Budget — the SAME default `dispatch::cmd_budget` renders: a fresh session cap
    // with no live spend. Called via the pub `BudgetCap::new` + `.view()` so the GUI
    // and the terminal show byte-identical budget numbers (single source of truth;
    // the core exposes no "default session budget" fn to call, and adding one would
    // be a forbidden core edit — this literal mirrors the documented default).
    let view = sinabro::commands::budget::BudgetCap::new(1_000_000, 1_000_000, 60_000).view();
    StatusView {
        cores,
        budget_tokens: view.token_remaining_u32,
        budget_cost_micros: view.cost_remaining_micro_u64,
        budget_deadline_ms: view.deadline_ms_u32,
        // No live TPS feed exists in the consult path — honest absence, not a 0.
        tps: None,
    }
}

/// WAVE G — the deterministic payoff-diagram SVG for the Skew §8 payoff pane. Calls the PURE core
/// `sinabro::skew_payoff_svg` (NO float / clock / network / key / chain ⇒ byte-deterministic) and
/// returns a self-contained `<svg>…</svg>` string the GUI inlines (the title is XML-escaped; no
/// `<script>`). READ-class, money 0: it VISUALIZES a payoff the agent could PROPOSE, signs nothing.
/// `kind` = "straddle" (`f = |S−strike| − premium`) or "forward" (`f = S − strike`, the affine WCC
/// forward). A degenerate domain returns the honest empty-state SVG (never a fabricated curve).
#[tauri::command]
fn skew_payoff_svg(kind: String, lo: i64, hi: i64, tau: u64, strike: i64, premium: i64) -> String {
    use sinabro::skew_payoff_svg::{
        affine_forward_segments, render_payoff_svg, sample_piecewise, straddle_payoff_segs,
    };
    let (lo, hi, strike, premium) = (
        i128::from(lo),
        i128::from(hi),
        i128::from(strike),
        i128::from(premium),
    );
    let (title, segs) = if kind == "forward" {
        (
            format!("forward Pc={strike} [{lo},{hi}]"),
            affine_forward_segments(hi, 1, strike.saturating_neg()),
        )
    } else {
        (
            format!("straddle K={strike} prem={premium} [{lo},{hi}]"),
            straddle_payoff_segs(hi, strike, premium),
        )
    };
    let points = sample_piecewise(lo, hi, u128::from(tau), &segs).unwrap_or_default();
    render_payoff_svg(&title, &points, 360, 220)
}

/// Opt-in OTel telemetry toggle (R7b privacy viz). Sets/clears `SINABRO_OTEL_EXPORT`
/// in the BACKEND PROCESS env (memory-only — the SAME mechanism as `set_secret`;
/// never written to disk). The UNCHANGED core reads this env at the consult site
/// (P4-1 strict tri-state: `1` ⇒ on, unset ⇒ off), so enabling makes the next
/// ANSWERED consult write ONE local OTLP/JSON span to `~/.mnemos/otel`. Default OFF.
/// The value is a fixed `"1"` / absent — not a secret, not owner-controlled content;
/// the span is a LOCAL file (no off-box push in v1). Cleared when the app closes.
#[tauri::command]
fn set_telemetry(on: bool) -> Result<(), String> {
    // SAFETY (edition 2021): `set_var`/`remove_var` are safe fns here; same
    // single-user set-then-dispatch mitigation as `set_secret`.
    if on {
        std::env::set_var("SINABRO_OTEL_EXPORT", "1");
    } else {
        std::env::remove_var("SINABRO_OTEL_EXPORT");
    }
    Ok(())
}

/// Whether opt-in OTel telemetry is currently ON (presence of `SINABRO_OTEL_EXPORT=1`
/// in the backend process env). Boolean only — no value or path is returned.
#[tauri::command]
fn telemetry_status() -> bool {
    std::env::var("SINABRO_OTEL_EXPORT")
        .map(|v| v == "1")
        .unwrap_or(false)
}

/// ONE inbound owner Telegram message surfaced to the GUI session (ENDGAME E13-2 /
/// ⑱). `kind` ∈ {"chat","withheld","approval"}; `text` is ALREADY secret-free — the
/// core's classifier WITHHOLDS a secret-shaped inbound before it reaches here
/// (IV-RC2), and a non-owner update is never surfaced at all (IV-RC1). A surfaced
/// card NEVER carries a sent reply — it is the inbound side only.
#[derive(serde::Serialize)]
struct InboundCard {
    /// The classified kind: a free-form owner chat command, a withheld-secret
    /// marker, or an approve/deny reply note.
    kind: String,
    /// The secret-free text (a chat prompt's body) or a fixed marker (withheld /
    /// approval). Never a raw secret, never a non-owner message.
    text: String,
}

/// Poll the Telegram inbound edge ONCE (read-only) and return the OWNER's
/// remote-control messages as classified cards (ENDGAME E13-2 / ⑱ — the GUI inbound
/// surface). Reuses the SAME audited core primitives the CLI loop uses — the ONE
/// getUpdates edge `InboundTransport::poll_once` + the pure `classify_inbound`
/// (owner-pin FIRST, IV-RC1 → secret-withhold, IV-RC2 → split). A non-owner update is
/// DROPPED (never returned); a secret-shaped update is WITHHELD (a marker, never the
/// text); an owner chat prompt's secret-free text is surfaced. This RUNS NO agent
/// turn and SENDS nothing — it ONLY surfaces inbound messages so the GUI can show a
/// card (the answer/reply loop is the CLI `daemon serve-chat`, Option A). No
/// TELEGRAM_CHAT_ID / no token / a transport error ⇒ an empty list (honest absence,
/// never a fabricated card). custody/wallet/mainnet untouched (PD-6).
///
/// NO backend→frontend push channel exists, so the frontend polls this on an
/// interval — the HONEST wiring (no faked event); the inbound text is redacted by
/// the core before it ever reaches the GUI.
///
/// `poll_once` LONG-polls (blocks up to the server's long-poll timeout), so — like
/// [`dispatch_line`] — the work runs on a blocking-pool thread (`spawn_blocking`),
/// never the main (UI) thread, so the window never freezes while waiting.
#[tauri::command]
async fn poll_inbound_telegram() -> Result<Vec<InboundCard>, String> {
    tauri::async_runtime::spawn_blocking(poll_inbound_telegram_sync)
        .await
        .map_err(|e| format!("inbound poll task failed: {e}"))?
}

/// The blocking body of [`poll_inbound_telegram`] — runs on a blocking-pool thread.
fn poll_inbound_telegram_sync() -> Result<Vec<InboundCard>, String> {
    use sinabro::telegram::inbound_auth::InboundDisposition;
    // The owner pin from TELEGRAM_CHAT_ID — None ⇒ no remote-control channel ⇒ an
    // empty list (not an error). The value is parsed + compared, never rendered.
    let Some(owner_chat_id) = sinabro::telegram::inbound_auth::resolve_owner_chat_id() else {
        return Ok(Vec::new());
    };
    let token_ref =
        sinabro::secrets::classify_reference("telegram_bot_token", "env:TELEGRAM_BOT_TOKEN");
    let transport = sinabro::telegram::inbound::InboundTransport::new(
        sinabro::telegram::egress::TelegramHost::BotApi,
        token_ref,
    );
    // ONE read-only long-poll at the start offset; no offset is persisted (a GUI
    // "current inbox" surface, never a turn/send). A transport error (no token /
    // network / host) ⇒ an empty list (honest absence; the GUI dedupes by content).
    let updates = match transport.poll_once(sinabro::telegram::inbound::UpdateOffset::new()) {
        Ok((updates, _new_offset)) => updates,
        Err(_) => return Ok(Vec::new()),
    };
    let mut cards = Vec::new();
    for update in &updates {
        match sinabro::telegram::inbound_auth::classify_inbound(update, owner_chat_id) {
            // IV-RC1: a non-owner update is DROPPED — never surfaced.
            InboundDisposition::NotOwner => {}
            // IV-RC2: a secret-shaped inbound is WITHHELD — a marker, never the text.
            InboundDisposition::WithheldSecret => cards.push(InboundCard {
                kind: "withheld".to_string(),
                text: "[secret-shaped message withheld before the agent]".to_string(),
            }),
            // an approve/deny reply — a note (handled by the approval flow, not a chat turn).
            InboundDisposition::ApprovalReply => cards.push(InboundCard {
                kind: "approval".to_string(),
                text: "(approve/deny reply — routed to the approval flow)".to_string(),
            }),
            // a free-form owner command — secret-free (passed the withhold gate).
            InboundDisposition::ChatPrompt(text) => cards.push(InboundCard {
                kind: "chat".to_string(),
                text: text.to_string(),
            }),
        }
    }
    Ok(cards)
}

/// One MAIN INDEX entry surfaced to the GUI Walrus memory panel (ENDGAME E14-W2 /
/// "메인 저장소"): a memory's id, its bounded topic summary ("기억관련 내용"), and the
/// short form of its encrypted SUB-STORE blob-id. The topic lived INSIDE the
/// locally-decrypted, AEAD-sealed index — never published raw — so this is
/// content-class-safe to render. No funds; ciphertext-only on the wire.
#[derive(serde::Serialize)]
struct WalrusIndexEntry {
    id: u64,
    topic: String,
    sub_blob: String,
}

/// The agent's two-tier Walrus long-term memory, projected for the GUI. `index`
/// is the decrypted MAIN INDEX listing; `unavailable` is an HONEST reason (no
/// pointer yet / store unreachable / testnet boundary) — NEVER a fabricated empty
/// index that would look "synced".
#[derive(serde::Serialize)]
#[serde(tag = "kind")]
enum WalrusIndexView {
    #[serde(rename = "index")]
    Index { entries: Vec<WalrusIndexEntry> },
    #[serde(rename = "unavailable")]
    Unavailable { reason: String },
}

/// One memory's decrypted SUB-STORE detail for the GUI (ENDGAME E14-W2 / "서브
/// 저장소"). `detail` is the redact-belted content; `withheld` means the memory is
/// itself secret-shaped (decrypted locally but NOT rendered); `unavailable` is an
/// honest fetch/decrypt reason.
#[derive(serde::Serialize)]
#[serde(tag = "kind")]
enum WalrusFetchView {
    #[serde(rename = "detail")]
    Detail { id: u64, content: String },
    #[serde(rename = "withheld")]
    Withheld { id: u64 },
    #[serde(rename = "unavailable")]
    Unavailable { reason: String },
}

/// Read the agent's two-tier Walrus long-term memory MAIN INDEX for the GUI panel
/// (ENDGAME E14-W2). Reuses the SAME audited core primitives the CLI
/// `memory walrus-index` verb + the autonomous loop tool use — opens the local
/// `PersistedStore` (for the AEAD index key) and `load_main_index` (pointer →
/// testnet aggregator GET → local AEAD open → decode). READ-only: no funds, no
/// approval (the agent roams the index freely), ciphertext-only on the wire,
/// custody/wallet/mainnet unreachable (PD-6). The GET long-polls, so — like
/// [`dispatch_line`] — the work runs on a blocking-pool thread (never the UI
/// thread). No pointer / no store ⇒ an honest `unavailable` reason.
#[tauri::command]
async fn walrus_memory_index() -> Result<WalrusIndexView, String> {
    tauri::async_runtime::spawn_blocking(walrus_memory_index_sync)
        .await
        .map_err(|e| format!("walrus index task failed: {e}"))?
}

/// The blocking body of [`walrus_memory_index`] — runs on a blocking-pool thread.
fn walrus_memory_index_sync() -> Result<WalrusIndexView, String> {
    let store = match sinabro::memory_store::PersistedStore::open_local() {
        Ok(store) => store,
        Err(_) => {
            return Ok(WalrusIndexView::Unavailable {
                reason: "memory store unavailable (no key/home)".to_string(),
            })
        }
    };
    match sinabro::memory_walrus::load_main_index(&store) {
        Ok(index) => {
            let entries = index
                .entries
                .iter()
                .map(|e| WalrusIndexEntry {
                    id: e.memory_id,
                    topic: e.topic.clone(),
                    sub_blob: e.sub_blob_id.chars().take(16).collect(),
                })
                .collect();
            Ok(WalrusIndexView::Index { entries })
        }
        Err(reason) => Ok(WalrusIndexView::Unavailable {
            reason: reason.to_string(),
        }),
    }
}

/// Enter a memory's SUB-STORE via the MAIN INDEX, fetch the encrypted detail from
/// Walrus, decrypt it locally, and return it redact-belted (ENDGAME E14-W2). Reuses
/// the SAME core primitives the CLI `memory walrus-fetch <id>` verb uses —
/// `fetch_sub_content` (index → testnet GET → local AEAD open) — and applies the
/// canonical redaction gate so a secret-shaped memory is WITHHELD rather than
/// rendered (identical to the CLI `walrus_fetch_lines` belt). READ-only; no funds;
/// custody/wallet/mainnet unreachable (PD-6). Runs on a blocking-pool thread.
#[tauri::command]
async fn walrus_memory_fetch(id: u64) -> Result<WalrusFetchView, String> {
    tauri::async_runtime::spawn_blocking(move || walrus_memory_fetch_sync(id))
        .await
        .map_err(|e| format!("walrus fetch task failed: {e}"))?
}

/// The blocking body of [`walrus_memory_fetch`] — runs on a blocking-pool thread.
fn walrus_memory_fetch_sync(id: u64) -> Result<WalrusFetchView, String> {
    let store = match sinabro::memory_store::PersistedStore::open_local() {
        Ok(store) => store,
        Err(_) => {
            return Ok(WalrusFetchView::Unavailable {
                reason: "memory store unavailable (no key/home)".to_string(),
            })
        }
    };
    let content = match sinabro::memory_walrus::fetch_sub_content(&store, id) {
        Ok(content) => content,
        Err(reason) => {
            return Ok(WalrusFetchView::Unavailable {
                reason: reason.to_string(),
            })
        }
    };
    // The canonical redaction belt (a memory that is itself secret-shaped is
    // withheld rather than rendered) — identical to the CLI `walrus_fetch_lines` gate.
    let fragments = [content.as_str()];
    let secret = match sinabro::provider::redaction::redact(
        &sinabro::provider::redaction::RedactionRequest {
            fragments: &fragments,
            candidate_memory_ids: &[],
            deleted_ids: &[],
            include_private_memory: false,
        },
    ) {
        Ok(receipt) => receipt.secret_fragments_denied_u32() != 0,
        Err(_) => true, // fail-closed: any redaction error ⇒ withhold
    };
    if secret {
        Ok(WalrusFetchView::Withheld { id })
    } else {
        Ok(WalrusFetchView::Detail { id, content })
    }
}

// ── P2-S4c: the DGM-H perf-ledger view (Settings → Evolution, read-only) ──────────────────
// Surfaces the autonomy evolve loop's performance ledger. The codec is already in the CORE
// (sinabro::autonomy_evolve::parse_ledger + EVOLUTION_LEDGER_FILE + verification::PerfScore);
// this is the thin READ (the GUI never re-parses the ledger format in JS). HONEST-EMPTY when no
// ledger file exists. READ-only; NOT custody (PD-6) — no funds / wallet / chain.

/// One tracked pattern's DGM-H perf entry (key + reinforced/demoted counts).
#[derive(serde::Serialize)]
struct PerfEntry {
    key: String,
    reinforced: u32,
    demoted: u32,
}

/// The perf-ledger view: the tracked patterns + the ledger file path (honest-empty = no run yet).
#[derive(serde::Serialize)]
struct PerfLedgerView {
    entries: Vec<PerfEntry>,
    path: String,
}

/// Read the DGM-H perf ledger (`<data_dir>/evolution_ledger.txt`) via the core's pure
/// `parse_ledger`. Honest-empty when absent/unreadable (parse_ledger("") = no entries) —
/// never a fabricated ledger.
#[tauri::command]
fn read_perf_ledger() -> PerfLedgerView {
    let Ok(dir) = sinabro::memory_store::data_dir() else {
        return PerfLedgerView {
            entries: Vec::new(),
            path: sinabro::autonomy_evolve::EVOLUTION_LEDGER_FILE.to_string(),
        };
    };
    let path = dir.join(sinabro::autonomy_evolve::EVOLUTION_LEDGER_FILE);
    let text = std::fs::read_to_string(&path).unwrap_or_default();
    let ledger = sinabro::autonomy_evolve::parse_ledger(&text);
    let entries = ledger
        .iter()
        .map(|(k, p)| PerfEntry {
            key: k.clone(),
            reinforced: p.reinforced,
            demoted: p.demoted,
        })
        .collect();
    PerfLedgerView {
        entries,
        path: path.display().to_string(),
    }
}

// ── P2-S4a: the dynamic-LoRA routing-table editor (Settings → LoRA / Routing) ─────────────
// The GUI reads + edits + SAVES the routing table the orchestrate verb and the autonomous
// evolve loop consume. The heavy lifting stays in the CORE (single truth source — the GUI
// NEVER re-parses the config in JS): `sinabro::dispatch::read_routing_table` (the SAME load
// the loops use) and `write_routing_table_rows` (build → re-parse-validate → atomic_write).
// NOT custody: a binding is a loopback `port` + a request-body `model_id`; no funds / wallet /
// chain / mainnet (PD-6 untouched). The owner's Save click IS the authorization (like
// `set_secret` / `save_sessions`); the model has no path here.

/// One routing binding for the editor (kind → loopback port · request-body model id).
#[derive(serde::Serialize)]
struct RoutingRow {
    kind: String,
    port: u16,
    model_id: String,
}

/// The default (totality-anchor) target — served when a kind is unmapped.
#[derive(serde::Serialize)]
struct RoutingTarget {
    port: u16,
    model_id: String,
}

/// The routing table the editor reads (the SAME table the orchestrate/evolve loops load).
#[derive(serde::Serialize)]
struct RoutingTableView {
    entries: Vec<RoutingRow>,
    default: RoutingTarget,
    path: String,
}

/// Read the current dynamic-LoRA routing table (owner config or the seed) for the editor —
/// reuses the core's `read_routing_table` (no JS re-parse; the loops see the same table).
#[tauri::command]
fn read_routing_table() -> RoutingTableView {
    let table = sinabro::dispatch::read_routing_table();
    let entries = table
        .bindings()
        .iter()
        .map(|(k, t)| RoutingRow {
            kind: k.label().to_string(),
            port: t.port,
            model_id: t.model_id.clone(),
        })
        .collect();
    let d = table.default_target();
    let path = sinabro::memory_store::data_dir()
        .ok()
        .map(|p| {
            p.join(sinabro::provider::executor_route::ROUTING_TABLE_CONFIG_FILE)
                .display()
                .to_string()
        })
        .unwrap_or_else(|| {
            sinabro::provider::executor_route::ROUTING_TABLE_CONFIG_FILE.to_string()
        });
    RoutingTableView {
        entries,
        default: RoutingTarget {
            port: d.port,
            model_id: d.model_id.clone(),
        },
        path,
    }
}

/// One owner-edited routing row coming FROM the editor.
#[derive(serde::Deserialize)]
struct RoutingRowIn {
    kind: String,
    port: u16,
    model_id: String,
}

/// The edited routing table payload from the editor (single struct arg → no JS/Rust arg-name
/// case ambiguity; the nested fields are matched by serde).
#[derive(serde::Deserialize)]
struct RoutingTableIn {
    entries: Vec<RoutingRowIn>,
    default_port: u16,
    default_model: String,
}

/// Persist the owner-edited routing table — the core validates (fail-closed) + atomic-writes.
/// NOT custody (routing_table.txt is a plain local config; PD-6 untouched). The change drives
/// the dynamic-LoRA route on the next orchestrate/evolve run.
#[tauri::command]
fn write_routing_table(payload: RoutingTableIn) -> Result<(), String> {
    let rows: Vec<(String, u16, String)> = payload
        .entries
        .into_iter()
        .map(|r| (r.kind, r.port, r.model_id))
        .collect();
    sinabro::dispatch::write_routing_table_rows(&rows, payload.default_port, &payload.default_model)
}

/// K-6: read the honest dynamic-LoRA status — the certified corpus→adapter MANIFEST
/// (P-HALL: only a certified strategy backs an adapter), the SERVED set (empty ⇒ honest
/// no-server), and the per-kind RESOLUTION for the routing table (requested adapter →
/// wire model, served/degraded). Returns the SAME core render string the CLI `provider
/// lora-status` emits — the GUI shows it VERBATIM (no JS re-implementation; one truth
/// source). An unserved adapter is shown honest-degrading to the base, never faked as
/// served (PD-1). READ-class, money 0; `CustodyCapability` stays uninhabited (PD-6).
#[tauri::command]
fn read_lora_status() -> String {
    sinabro::dispatch::lora_status_render()
}

/// W5: read the owner-declared served-adapter ids (the ids a real multi-LoRA server serves) for the
/// GUI served-editor. READ-only, money 0.
#[tauri::command]
fn read_served_adapters() -> Vec<String> {
    sinabro::dispatch::read_served_adapter_lines()
}

/// W5: persist the owner-declared served-adapter ids (the GUI served-editor + the connect-adapter
/// seam). The core validates each (fail-closed) + atomic-writes. HONEST: declaring an id served does
/// NOT make it served — `resolve_adapter` still honest-degrades the send to the base if the real
/// server is down. NOT custody (a plain local config; PD-6 untouched).
#[tauri::command]
fn write_served_adapters(ids: Vec<String>) -> Result<(), String> {
    sinabro::dispatch::write_served_adapter_lines(&ids)
}

// ── K-5c: the WALLET SETTINGS WINDOW — the CustodyGrant dial cockpit (READ-class) ──────────
// Surfaces the custody-dial state (per-tx · budget · allowlist · TTL · max-actions · network ·
// isolated-signer presence · armed) the K-2 `daemon trade` path arms WITHIN. The single truth
// source is the CORE `skew_custody_dial()` (the SAME bounds the trade path uses); the GUI never
// re-derives bounds in JS. This command CONFIGURES nothing and SIGNS nothing — it READS the dial
// (IV-FG8). ARM/REVOKE/KILL + isolated-key setup are the owner's typed-phrase ceremony via
// `dispatch_line` (`daemon trade <CUSTODY_ARM_PHRASE> …` / `daemon trade-addr`), never this
// command. `signer_pubkey` is the PUBLIC fee-payer key — NEVER the seed. The wallet window itself
// moves nothing: custody/funds reach real value ONLY through the owner-armed K-2 path (PD-6).

/// The CustodyGrant dial state for the wallet cockpit (mirrors `sinabro::dispatch::CustodyDialView`).
/// Money 0: no sign / mint / spend field exists here; `signer_pubkey` is the PUBLIC fee-payer key.
/// The u128 bounds cross as strings (JSON number-safe; no precision loss in the webview).
#[derive(serde::Serialize)]
struct CustodyDialOut {
    network: String,
    protocol: String,
    signer_pubkey: Option<String>,
    per_tx_max_minor: String,
    total_budget_minor: String,
    ttl_ms: u64,
    max_actions: u32,
    armed: bool,
}

/// Read the custody-dial state for the wallet settings window (K-5c). READ-only: reuses the core
/// `skew_custody_dial()` single source of truth (the SAME bounds the K-2 trade path arms within);
/// no egress, no fs write, no sign / mint / spend.
#[tauri::command]
fn read_custody_dial() -> CustodyDialOut {
    let d = sinabro::dispatch::skew_custody_dial();
    CustodyDialOut {
        network: d.network,
        protocol: d.protocol,
        signer_pubkey: d.signer_pubkey,
        per_tx_max_minor: d.per_tx_max_minor.to_string(),
        total_budget_minor: d.total_budget_minor.to_string(),
        ttl_ms: d.ttl_ms,
        max_actions: d.max_actions,
        armed: d.armed,
    }
}

// ── W8: the owner-configured WEB PANE url (the center web view — e.g. skew.deals) ───────────
// A plain local string the GUI iframes (sandboxed). Stored as `web_pane_url.txt` in the SAME
// GUI-owned app-data home as host.json / settings.json / sessions.json. HONEST-ABSENT by
// construction: an empty string ⇒ the GUI shows its no-feed card, NEVER a fabricated embed.
// READ-class: no secret, no funds / wallet / chain — custody/mainnet untouched (PD-6).

/// Resolve the web-pane url store path (`…/web_pane_url.txt` under the OS app-data dir).
fn web_pane_url_path(app: &tauri::AppHandle) -> Result<std::path::PathBuf, String> {
    Ok(app_data_dir(app)?.join("web_pane_url.txt"))
}

/// Read the owner-configured web-pane URL (empty string when unset — honest absence, never a
/// fabricated default). READ-only; no egress, no secret surface.
#[tauri::command]
fn read_web_pane_url(app: tauri::AppHandle) -> Result<String, String> {
    let path = web_pane_url_path(&app)?;
    match std::fs::read_to_string(&path) {
        Ok(text) => Ok(text.trim().to_string()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(String::new()),
        Err(e) => Err(e.to_string()),
    }
}

/// Persist the owner-configured web-pane URL. Validates `https://` (the iframe is sandboxed; we
/// refuse `http`/`file`/`javascript`/`data`). An EMPTY string CLEARS it (back to honest-absent).
/// The owner's Save IS the authorization (like `save_settings` / `set_host`); the model has no
/// path here. Never a secret, never custody (PD-6). Atomic write (temp + rename).
#[tauri::command]
fn write_web_pane_url(app: tauri::AppHandle, url: String) -> Result<(), String> {
    let trimmed = url.trim();
    let path = web_pane_url_path(&app)?;
    if trimmed.is_empty() {
        // Clear — remove the file (a NotFound is already "cleared").
        return match std::fs::remove_file(&path) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(e.to_string()),
        };
    }
    // https-only (a sandboxed iframe source — never http/file/javascript/data schemes).
    if !trimmed.to_ascii_lowercase().starts_with("https://") || trimmed.len() <= "https://".len() {
        return Err("web pane URL must be an https:// URL".to_string());
    }
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| e.to_string())?;
    }
    let tmp = path.with_extension("txt.tmp");
    std::fs::write(&tmp, trimmed.as_bytes()).map_err(|e| e.to_string())?;
    std::fs::rename(&tmp, &path).map_err(|e| e.to_string())?;
    Ok(())
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_dialog::init())
        .setup(|app| {
            if cfg!(debug_assertions) {
                app.handle().plugin(
                    tauri_plugin_log::Builder::default()
                        .level(log::LevelFilter::Info)
                        .build(),
                )?;
            }
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            dispatch_line,
            consult_stream_line,
            cancel_consult,
            redact_input,
            load_sessions,
            save_sessions,
            load_settings,
            save_settings,
            get_host,
            set_host,
            set_secret,
            clear_secret,
            secret_status,
            frontier_model_view,
            walrus_status,
            register_file_roots,
            pick_folder,
            read_file_view,
            read_index_view,
            read_proposals,
            read_status_view,
            set_telemetry,
            telemetry_status,
            poll_inbound_telegram,
            walrus_memory_index,
            walrus_memory_fetch,
            read_routing_table,
            write_routing_table,
            read_lora_status,
            read_served_adapters,
            write_served_adapters,
            read_custody_dial,
            read_web_pane_url,
            write_web_pane_url,
            skew_payoff_svg,
            read_perf_ledger,
            owner_save_file,
            fim_complete,
            inline_edit_propose,
            inline_edit_oracle,
            orchestrate_plan,
            orchestrate_run
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
