//! Runtime / model SELECTION — the first-class "VM-selector" surface (P4-3).
//!
//! sinabro can consult two runtimes: a FRONTIER provider (OpenRouter, an
//! external gated egress) and a LOCAL loopback endpoint (ollama / mlx / vLLM,
//! zero egress). Until now the *selection* of which runtime + which model id
//! was scattered: the frontier model id resolved from `OPENROUTER_MODEL`
//! inside the `provider-egress` executor, the local port/model from
//! `SINABRO_LOCAL_PORT` / `SINABRO_LOCAL_MODEL` inside the local executor, and
//! the route (frontier vs local) from the typed consult phrase. There was no
//! single surface that RESOLVED + SHOWED the effective selection, and the
//! resolution logic was duplicated per executor (a drift risk).
//!
//! This module is the ONE pure resolver, consumed by BOTH the selector view
//! (`model use` / `model status`) AND the consult executors. Because the
//! selector and the executor read the SAME function, the selector shows
//! EXACTLY what a consult will use (L2 deterministic projection — no second
//! truth, no fork).
//!
//! # Why there is NO config-file persistence (physics-derived)
//!
//! The selection's source of truth is the ENVIRONMENT (`OPENROUTER_MODEL`,
//! `SINABRO_LOCAL_PORT`, `SINABRO_LOCAL_MODEL`). The CLI config precedence
//! (`crate::config`) already places `Env` (precedence 5) ABOVE `User` /
//! `Workspace` config files, and the config layer is a READER only (owner-
//! authored TOML; the code never writes a config file). A selection written to
//! a config file would therefore be silently overridden by a leftover env var
//! (which value wins? — exactly the `G-F-NO-SILENT-FALLBACK` ambiguity, L5),
//! and minting a config WRITER would be a brand-new surface AND a second truth
//! that the executors do not read (drift). So the selector is RESOLVE +
//! VALIDATE + PREVIEW only: it shows the effective selection and the exact env
//! assignment that makes a candidate durable. It never claims to persist (no
//! fake feature). In a long-lived host (the GUI) the existing in-memory env
//! mechanism (`set_secret`) makes a selection stick for the session — still
//! the env, not a new store.
//!
//! # Selection is OWNER-only (L8)
//!
//! `model use` is a dispatch verb reachable only by the owner (terminal type-in
//! or the GUI). The agent loop grammar is byte-unchanged, so a model in the
//! consult loop has NO `model use` tool — a `TOOL: model use …` line parses
//! `ToolUnknown` and is denied (pinned in the `agent_loop` deny test). The
//! model can never self-select its own runtime/model (the RD-49 auto-router is
//! deliberately not wired).

use crate::secrets::scan_inline_secret;
use crate::tui::RenderTruth;

// ---- canonical env names + defaults (the single source for every build) ----

/// The env var selecting the FRONTIER (OpenRouter) request-side model id. A
/// plain selector, never a secret (the secret is `OPENROUTER_API_KEY`).
pub const FRONTIER_MODEL_ENV: &str = "OPENROUTER_MODEL";

/// The frontier model id when `OPENROUTER_MODEL` is unset/blank — SOT
/// "OpenRouter→DeepSeek 기본" (`MNEMOS_ATOM_PLAN.md:1024`).
pub const FRONTIER_DEFAULT_MODEL: &str = "deepseek/deepseek-chat";

/// The env var selecting the secret used at the frontier TLS boundary. NEVER
/// read here (the selector touches no key) — surfaced for the owner only.
pub const FRONTIER_KEY_ENV: &str = "OPENROUTER_API_KEY";

/// The env var selecting the LOCAL loopback port (a plain selector).
pub const LOCAL_PORT_ENV: &str = "SINABRO_LOCAL_PORT";

/// The env var selecting the LOCAL request-side model id (a plain selector;
/// ollama / vLLM need their real served-model name).
pub const LOCAL_MODEL_ENV: &str = "SINABRO_LOCAL_MODEL";

/// The local request-side model id when `SINABRO_LOCAL_MODEL` is unset.
pub const LOCAL_DEFAULT_MODEL: &str = "default";

/// Canonical loopback runtime ports (the menu shown to the owner). These are
/// cross-pinned to the feature adapters' own constants by compile-time asserts
/// in `dispatch.rs` (`OLLAMA_PORT == local_mlx::OLLAMA_DEFAULT_PORT`, etc.) so
/// a drift between this menu and the adapter is caught at build time.
pub const OLLAMA_PORT: u16 = 11434;
/// Canonical mlx_lm.server loopback port.
pub const MLX_PORT: u16 = 8080;
/// Canonical vLLM loopback port.
pub const VLLM_PORT: u16 = 8000;

/// Maximum accepted model-id length for the `model use` validation path. Long
/// enough for `provider/model-name:tag`, short enough to reject a pasted blob.
pub const MAX_MODEL_ID_LEN: usize = 128;

// ---- the two routes --------------------------------------------------------

/// Which runtime a consult is routed to. The route is picked by the typed
/// consult phrase (not an env var) — the selector previews each route's
/// resolved config; it does not change how a consult routes.
#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RuntimeRoute {
    /// External frontier provider (OpenRouter, gated egress).
    Frontier = 1,
    /// Local loopback endpoint (ollama / mlx / vLLM, zero egress).
    Local = 2,
}

impl RuntimeRoute {
    /// Parse an owner-supplied route token (closed set; unknown ⇒ `None` ⇒ a
    /// typed deny, never a silent default).
    #[must_use]
    pub fn from_token(token: &str) -> Option<Self> {
        match token.trim().to_ascii_lowercase().as_str() {
            "frontier" | "openrouter" | "remote" => Some(Self::Frontier),
            "local" | "loopback" | "naite" => Some(Self::Local),
            _ => None,
        }
    }

    /// The exact consult phrase that fires this route (the owner-visible "how
    /// to activate" — the route is phrase-driven, L5 explicit).
    #[must_use]
    pub const fn consult_phrase(self) -> &'static str {
        match self {
            Self::Frontier => "consult-frontier-provider-live",
            Self::Local => "consult-local-naite-live",
        }
    }
}

// ---- pure resolvers (BYTE-VALUE identical to the prior executor copies) -----

/// Resolve the FRONTIER request-side model id from the env value. Absent /
/// blank ⇒ the DeepSeek default; otherwise the RAW env value (untrimmed — the
/// exact byte-value the `provider-egress` executor sends, preserved on the
/// refactor). The owner-facing validation path (`validate_model_id`) is
/// stricter; this resolver stays byte-faithful to the wire.
#[must_use]
pub fn resolve_frontier_model(env_value: Option<&str>) -> String {
    match env_value {
        Some(raw) if !raw.trim().is_empty() => raw.to_string(),
        _ => FRONTIER_DEFAULT_MODEL.to_string(),
    }
}

/// Resolve the LOCAL loopback port from the env value. STRICT: absent / blank
/// ⇒ `default_port`; garbage / `0` / out-of-range ⇒ `None` (a typed deny — the
/// caller never silently defaults on garbage). The HOST is not resolvable
/// (loopback is structural, not policy).
#[must_use]
pub fn resolve_local_port(env_value: Option<&str>, default_port: u16) -> Option<u16> {
    match env_value.map(str::trim) {
        None | Some("") => Some(default_port),
        Some(raw) => match raw.parse::<u16>() {
            Ok(0) | Err(_) => None,
            Ok(port) => Some(port),
        },
    }
}

/// Resolve the LOCAL request-side model id from the env value (trimmed; absent
/// / blank ⇒ the honest default).
#[must_use]
pub fn resolve_local_model(env_value: Option<&str>) -> String {
    env_value
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map_or_else(|| LOCAL_DEFAULT_MODEL.to_string(), str::to_string)
}

// ---- owner-supplied candidate validation (`model use …`) -------------------

/// Why a `model use` candidate was rejected (typed, value-free; fail-closed).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SelectionDeny {
    /// The runtime token was not `frontier` / `local`.
    UnknownRuntime,
    /// The model id failed validation; carries a static, secret-free reason.
    BadModelId(&'static str),
    /// The port was not a valid `1..=65535`.
    BadPort,
}

impl SelectionDeny {
    /// A stable, allow-listed reason label (namespaced; carries no input).
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::UnknownRuntime => "model_select.unknown_runtime",
            Self::BadModelId(reason) => reason,
            Self::BadPort => "model_select.bad_port",
        }
    }
}

/// Validate an owner-supplied model id (the `model use` candidate). Closed
/// charset `[A-Za-z0-9 / . - _ :]`, non-empty, bounded length, and rejected if
/// secret-shaped (an owner fat-fingering a key into the model slot is denied,
/// never echoed). Returns the trimmed id on success.
pub fn validate_model_id(candidate: &str) -> Result<&str, SelectionDeny> {
    let trimmed = candidate.trim();
    if trimmed.is_empty() {
        return Err(SelectionDeny::BadModelId("model_select.empty_model_id"));
    }
    if trimmed.len() > MAX_MODEL_ID_LEN {
        return Err(SelectionDeny::BadModelId("model_select.model_id_too_long"));
    }
    if scan_inline_secret(trimmed) {
        return Err(SelectionDeny::BadModelId(
            "model_select.secret_shaped_model_id",
        ));
    }
    if !trimmed
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'/' | b'.' | b'-' | b'_' | b':'))
    {
        return Err(SelectionDeny::BadModelId("model_select.model_id_charset"));
    }
    Ok(trimmed)
}

/// Validate an owner-supplied port (`1..=65535`; `0` / garbage ⇒ deny).
pub fn parse_port(candidate: &str) -> Result<u16, SelectionDeny> {
    match candidate.trim().parse::<u16>() {
        Ok(0) | Err(_) => Err(SelectionDeny::BadPort),
        Ok(port) => Ok(port),
    }
}

// ---- resolved view + render ------------------------------------------------

/// The env + build inputs the selector resolves over (all injected — this
/// module reads NO process env and consults NO `cfg!` so it is fully unit-
/// testable; `dispatch.rs` snapshots the env + compile flags and passes them).
#[derive(Clone, Copy, Debug)]
pub struct SelectionEnv<'a> {
    /// `OPENROUTER_MODEL` value, if any.
    pub frontier_model: Option<&'a str>,
    /// `SINABRO_LOCAL_PORT` value, if any.
    pub local_port: Option<&'a str>,
    /// `SINABRO_LOCAL_MODEL` value, if any.
    pub local_model: Option<&'a str>,
    /// The compiled local default port (`Some` only in a local-serving build;
    /// `None` in the default build, where the menu is shown instead).
    pub local_default_port: Option<u16>,
    /// Whether THIS build can fire a frontier consult (`provider-egress`).
    pub fireable_frontier: bool,
    /// Whether THIS build can fire a local consult (`local-mlx`/`local-vllm`).
    pub fireable_local: bool,
}

/// The resolved runtime/model selection (a pure projection of [`SelectionEnv`]).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RuntimeSelection {
    /// The frontier request-side model id (resolved).
    pub frontier_model: String,
    /// Whether the frontier model came from the env (vs the default).
    pub frontier_from_env: bool,
    /// The resolved local port, or `None` (env set-but-invalid, or unset with
    /// no compiled default).
    pub local_port: Option<u16>,
    /// Whether `SINABRO_LOCAL_PORT` was set but invalid (a typed-deny state,
    /// distinct from "unset").
    pub local_port_invalid: bool,
    /// The local request-side model id (resolved).
    pub local_model: String,
    /// Whether the local model came from the env (vs the default).
    pub local_model_from_env: bool,
    /// Echoed `fireable_frontier`.
    pub fireable_frontier: bool,
    /// Echoed `fireable_local`.
    pub fireable_local: bool,
}

/// Resolve the effective selection from the injected env + build flags.
#[must_use]
pub fn resolve_selection(env: &SelectionEnv<'_>) -> RuntimeSelection {
    let frontier_from_env = env.frontier_model.is_some_and(|raw| !raw.trim().is_empty());
    let local_model_from_env = env.local_model.is_some_and(|raw| !raw.trim().is_empty());
    // STRICT port: a set-but-garbage env is an explicit invalid state, not a
    // silent fall-back to the default. Distinguish "set+invalid" from "unset".
    let port_set_nonblank = env.local_port.is_some_and(|raw| !raw.trim().is_empty());
    let local_port = match env.local_default_port {
        Some(default) => resolve_local_port(env.local_port, default),
        // No compiled default (default build): only an explicit valid env port
        // resolves; otherwise None (the menu line is shown).
        None => env
            .local_port
            .filter(|raw| !raw.trim().is_empty())
            .and_then(|raw| parse_port(raw).ok()),
    };
    let local_port_invalid = port_set_nonblank && local_port.is_none();
    RuntimeSelection {
        frontier_model: resolve_frontier_model(env.frontier_model),
        frontier_from_env,
        local_port,
        local_port_invalid,
        local_model: resolve_local_model(env.local_model),
        local_model_from_env,
        fireable_frontier: env.fireable_frontier,
        fireable_local: env.fireable_local,
    }
}

/// Maximum width for an echoed model id on a status line — keeps every render
/// line inside the 80-col ASCII budget regardless of the env value's length.
const DISPLAY_MODEL_MAX: usize = 32;

/// Sanitize an owner/env-supplied value for owner display, keeping only
/// printable ASCII and bounding the length. This makes a rendered line unable
/// to exceed the 80-col budget or carry a non-ASCII / escape byte (the
/// `renders_are_colorless_ascii_within_80_cols` core invariant), no matter what
/// an env var holds. Empty after cleaning yields a typed placeholder.
fn sanitize_ascii(value: &str, max: usize) -> String {
    let cleaned: String = value
        .chars()
        .filter(|c| c.is_ascii() && !c.is_ascii_control())
        .take(max)
        .collect();
    if cleaned.is_empty() {
        "<empty>".to_string()
    } else {
        cleaned
    }
}

/// Render a model id for owner display: withhold a secret-shaped value (belt;
/// `OPENROUTER_MODEL` could hold a fat-fingered key), else a sanitized,
/// length-bounded ASCII form.
#[must_use]
fn display_model(model: &str) -> String {
    if scan_inline_secret(model) {
        "<withheld:secret>".to_string()
    } else {
        sanitize_ascii(model, DISPLAY_MODEL_MAX)
    }
}

impl RuntimeSelection {
    /// The "selector home" lines (also appended to `model status`): the resolved
    /// selection + how to pick. EVERY line is ASCII and <=80 cols (env-derived
    /// model ids are sanitized + bounded by [`display_model`]). Honest per-build
    /// (`fireable=` flags reflect THIS binary).
    #[must_use]
    pub fn summary_lines(&self) -> Vec<String> {
        let local_line = if self.local_port_invalid {
            format!("local: {LOCAL_PORT_ENV} set but invalid; fix the port")
        } else if let Some(port) = self.local_port {
            format!(
                "local: 127.0.0.1:{port} model={} fireable={}",
                display_model(&self.local_model),
                self.fireable_local
            )
        } else {
            format!(
                "local: port-unset model={} fireable={}",
                display_model(&self.local_model),
                self.fireable_local
            )
        };
        vec![
            "runtime selection (resolve-only; env=single truth, no config file)".to_string(),
            format!(
                "frontier: model={} fireable={}",
                display_model(&self.frontier_model),
                self.fireable_frontier
            ),
            local_line,
            "select: model use frontier <id> (fire: consult-frontier-provider-live)".to_string(),
            "select: model use local <port> <model> (fire: consult-local-naite-live)".to_string(),
        ]
    }
}

/// Handle `model use <args>` (args = the tokens AFTER `use`). Pure: resolves +
/// validates + previews; never mutates env, never fires a consult. Returns the
/// render truth + lines (`Red` on a typed deny — no silent default).
#[must_use]
pub fn render_use(args: &[&str], env: &SelectionEnv<'_>) -> (RenderTruth, Vec<String>) {
    let selection = resolve_selection(env);
    let Some(route_token) = args.first() else {
        // No runtime ⇒ the selector home (current selection + menu).
        return (RenderTruth::Unknown, selection.summary_lines());
    };
    let Some(route) = RuntimeRoute::from_token(route_token) else {
        return (
            RenderTruth::Red,
            vec![
                format!("model use: unknown runtime '{}'", clamp_token(route_token)),
                "pick a runtime: frontier | local".to_string(),
            ],
        );
    };
    match route {
        RuntimeRoute::Frontier => render_use_frontier(args.get(1).copied(), &selection),
        RuntimeRoute::Local => {
            render_use_local(args.get(1).copied(), args.get(2).copied(), &selection)
        }
    }
}

/// `model use frontier [<model-id>]`.
fn render_use_frontier(
    candidate: Option<&str>,
    selection: &RuntimeSelection,
) -> (RenderTruth, Vec<String>) {
    match candidate {
        None => (
            RenderTruth::Green,
            vec![
                format!(
                    "frontier current: model={} fireable={}",
                    display_model(&selection.frontier_model),
                    selection.fireable_frontier
                ),
                format!(
                    "activate: export {FRONTIER_MODEL_ENV}=<model-id> (key={FRONTIER_KEY_ENV})"
                ),
                format!(
                    "fire: provider consult {} <question>",
                    RuntimeRoute::Frontier.consult_phrase()
                ),
            ],
        ),
        Some(raw) => match validate_model_id(raw) {
            Ok(model) => (
                RenderTruth::Green,
                vec![
                    format!(
                        "frontier selection validated: model={}",
                        display_model(model)
                    ),
                    format!(
                        "activate: export {FRONTIER_MODEL_ENV}={}",
                        display_model(model)
                    ),
                    format!(
                        "key={FRONTIER_KEY_ENV} (TLS-boundary only); fireable={}",
                        selection.fireable_frontier
                    ),
                    format!(
                        "fire: provider consult {} <question>",
                        RuntimeRoute::Frontier.consult_phrase()
                    ),
                ],
            ),
            Err(deny) => (
                RenderTruth::Red,
                vec![
                    format!("frontier model id rejected: {}", deny.label()),
                    "no silent default; supply a valid model id".to_string(),
                ],
            ),
        },
    }
}

/// `model use local [<port> [<model>]]`.
fn render_use_local(
    port_arg: Option<&str>,
    model_arg: Option<&str>,
    selection: &RuntimeSelection,
) -> (RenderTruth, Vec<String>) {
    // Validate a supplied port (strict). An absent port previews the current.
    let port = match port_arg {
        Some(raw) => match parse_port(raw) {
            Ok(port) => Some(port),
            Err(deny) => {
                return (
                    RenderTruth::Red,
                    vec![
                        format!("local port rejected: {} (1-65535)", deny.label()),
                        "no silent default; supply a valid port".to_string(),
                    ],
                );
            }
        },
        None => selection.local_port,
    };
    // Validate a supplied model id (reuse the frontier validator — same rules).
    let model = match model_arg {
        Some(raw) => match validate_model_id(raw) {
            Ok(model) => model.to_string(),
            Err(deny) => {
                return (
                    RenderTruth::Red,
                    vec![
                        format!("local model id rejected: {}", deny.label()),
                        "no silent default; supply a valid model id".to_string(),
                    ],
                );
            }
        },
        None => selection.local_model.clone(),
    };
    let port_line = port.map_or_else(
        || "port-unset".to_string(),
        |port| format!("127.0.0.1:{port}"),
    );
    let mut lines = vec![
        format!(
            "local validated: {port_line} model={}",
            display_model(&model)
        ),
        format!("activate: export {LOCAL_PORT_ENV}=<port> {LOCAL_MODEL_ENV}=<model>"),
        format!("loopback; no key; fireable={}", selection.fireable_local),
        format!(
            "fire: provider consult {} <question>",
            RuntimeRoute::Local.consult_phrase()
        ),
    ];
    // The port menu only when the owner has no port selected yet.
    if port.is_none() {
        lines.push(format!(
            "ports: ollama={OLLAMA_PORT} mlx={MLX_PORT} vllm={VLLM_PORT}"
        ));
    }
    (RenderTruth::Green, lines)
}

/// Clamp an echoed unknown token to a short, control-free, non-secret form for
/// the deny line (never render a pasted blob or a secret-shaped token raw).
fn clamp_token(token: &str) -> String {
    if scan_inline_secret(token) {
        return "<withheld:secret>".to_string();
    }
    sanitize_ascii(token, 24)
}

#[cfg(test)]
mod tests {
    use super::*;

    // ---- resolvers stay BYTE-VALUE identical to the prior executor copies ---

    #[test]
    fn frontier_model_resolution() {
        assert_eq!(resolve_frontier_model(None), FRONTIER_DEFAULT_MODEL);
        assert_eq!(resolve_frontier_model(Some("")), FRONTIER_DEFAULT_MODEL);
        assert_eq!(resolve_frontier_model(Some("   ")), FRONTIER_DEFAULT_MODEL);
        // RAW (untrimmed) value preserved — the exact wire byte-value.
        assert_eq!(resolve_frontier_model(Some(" x ")), " x ");
        assert_eq!(
            resolve_frontier_model(Some("anthropic/claude-3.5-sonnet")),
            "anthropic/claude-3.5-sonnet"
        );
    }

    #[test]
    fn local_port_resolution_is_strict() {
        assert_eq!(resolve_local_port(None, OLLAMA_PORT), Some(OLLAMA_PORT));
        assert_eq!(resolve_local_port(Some("  "), VLLM_PORT), Some(VLLM_PORT));
        assert_eq!(resolve_local_port(Some("8000"), OLLAMA_PORT), Some(8000));
        assert_eq!(resolve_local_port(Some(" 11434 "), VLLM_PORT), Some(11434));
        assert_eq!(resolve_local_port(Some("abc"), OLLAMA_PORT), None);
        assert_eq!(resolve_local_port(Some("0"), OLLAMA_PORT), None);
        assert_eq!(resolve_local_port(Some("70000"), OLLAMA_PORT), None);
        assert_eq!(resolve_local_port(Some("-1"), OLLAMA_PORT), None);
    }

    #[test]
    fn local_model_resolution() {
        assert_eq!(resolve_local_model(None), LOCAL_DEFAULT_MODEL);
        assert_eq!(resolve_local_model(Some("  ")), LOCAL_DEFAULT_MODEL);
        assert_eq!(resolve_local_model(Some(" llama3.2 ")), "llama3.2");
    }

    // ---- route parse (closed set; unknown ⇒ deny) ---------------------------

    #[test]
    fn route_token_parse() {
        assert_eq!(
            RuntimeRoute::from_token("frontier"),
            Some(RuntimeRoute::Frontier)
        );
        assert_eq!(
            RuntimeRoute::from_token("OpenRouter"),
            Some(RuntimeRoute::Frontier)
        );
        assert_eq!(RuntimeRoute::from_token("local"), Some(RuntimeRoute::Local));
        assert_eq!(
            RuntimeRoute::from_token(" naite "),
            Some(RuntimeRoute::Local)
        );
        assert_eq!(RuntimeRoute::from_token("mainnet"), None);
        assert_eq!(RuntimeRoute::from_token(""), None);
        assert_eq!(
            RuntimeRoute::Frontier.consult_phrase(),
            "consult-frontier-provider-live"
        );
        assert_eq!(
            RuntimeRoute::Local.consult_phrase(),
            "consult-local-naite-live"
        );
    }

    // ---- candidate validation (fail-closed) ---------------------------------

    #[test]
    fn model_id_validation() {
        assert_eq!(
            validate_model_id("deepseek/deepseek-chat"),
            Ok("deepseek/deepseek-chat")
        );
        assert_eq!(
            validate_model_id(" anthropic/claude-3.5-sonnet "),
            Ok("anthropic/claude-3.5-sonnet")
        );
        assert_eq!(validate_model_id("qwen2.5:7b"), Ok("qwen2.5:7b"));
        assert!(validate_model_id("").is_err());
        assert!(validate_model_id("   ").is_err());
        assert!(validate_model_id("bad model id").is_err()); // space
        assert!(validate_model_id("bad$model").is_err()); // charset
        assert!(validate_model_id(&"x".repeat(MAX_MODEL_ID_LEN + 1)).is_err());
        // a secret-shaped id is denied, never echoed (a raw-key marker the
        // shared `looks_like_secret` belt catches).
        assert!(validate_model_id("suiprivkey1qexamplenotreal").is_err());
        assert!(validate_model_id("my-private_key-blob").is_err());
    }

    #[test]
    fn port_validation() {
        assert_eq!(parse_port("8000"), Ok(8000));
        assert_eq!(parse_port(" 11434 "), Ok(11434));
        assert_eq!(parse_port("0"), Err(SelectionDeny::BadPort));
        assert_eq!(parse_port("70000"), Err(SelectionDeny::BadPort));
        assert_eq!(parse_port("abc"), Err(SelectionDeny::BadPort));
    }

    // ---- resolved view ------------------------------------------------------

    fn env<'a>(
        frontier: Option<&'a str>,
        port: Option<&'a str>,
        model: Option<&'a str>,
        default_port: Option<u16>,
        fire_f: bool,
        fire_l: bool,
    ) -> SelectionEnv<'a> {
        SelectionEnv {
            frontier_model: frontier,
            local_port: port,
            local_model: model,
            local_default_port: default_port,
            fireable_frontier: fire_f,
            fireable_local: fire_l,
        }
    }

    #[test]
    fn resolve_defaults_in_default_build() {
        // No env, no compiled default port (default build).
        let sel = resolve_selection(&env(None, None, None, None, false, false));
        assert_eq!(sel.frontier_model, FRONTIER_DEFAULT_MODEL);
        assert!(!sel.frontier_from_env);
        assert_eq!(sel.local_port, None); // unset + no compiled default
        assert!(!sel.local_port_invalid);
        assert_eq!(sel.local_model, LOCAL_DEFAULT_MODEL);
        assert!(!sel.fireable_frontier && !sel.fireable_local);
        // summary mentions both routes + the no-config-file truth.
        let lines = sel.summary_lines().join("\n");
        assert!(lines.contains("resolve-only"));
        assert!(lines.contains("no config file"));
        assert!(lines.contains("frontier:"));
        assert!(lines.contains("local:"));
        assert!(lines.contains("fireable=false"));
        // EVERY line ASCII + <=80 cols (the core render invariant), even with
        // env-derived values — bounded by display_model.
        for line in &sel.summary_lines() {
            assert!(line.is_ascii() && line.len() <= 80, "render line: {line}");
        }
    }

    #[test]
    fn resolve_env_overrides_and_invalid_port() {
        let sel = resolve_selection(&env(
            Some("anthropic/claude-3.5-sonnet"),
            Some("8000"),
            Some("llama3.2"),
            Some(OLLAMA_PORT),
            true,
            true,
        ));
        assert_eq!(sel.frontier_model, "anthropic/claude-3.5-sonnet");
        assert!(sel.frontier_from_env);
        assert_eq!(sel.local_port, Some(8000));
        assert!(sel.local_model_from_env);
        assert!(sel.fireable_frontier && sel.fireable_local);

        // Set-but-garbage port is an explicit invalid state (not a silent
        // fall to the compiled default).
        let bad = resolve_selection(&env(
            None,
            Some("garbage"),
            None,
            Some(OLLAMA_PORT),
            false,
            true,
        ));
        assert_eq!(bad.local_port, None);
        assert!(bad.local_port_invalid);
        assert!(bad.summary_lines().join("\n").contains("set but invalid"));
    }

    // ---- `model use` render paths -------------------------------------------

    #[test]
    fn use_home_lists_current() {
        let (truth, lines) = render_use(&[], &env(None, None, None, None, false, false));
        assert_eq!(truth, RenderTruth::Unknown);
        assert!(lines.join("\n").contains("select: model use frontier"));
    }

    #[test]
    fn use_frontier_validates() {
        let e = env(None, None, None, None, true, false);
        let (truth, lines) = render_use(&["frontier", "deepseek/deepseek-chat"], &e);
        assert_eq!(truth, RenderTruth::Green);
        let joined = lines.join("\n");
        assert!(joined.contains("frontier selection validated"));
        assert!(joined.contains("export OPENROUTER_MODEL=deepseek/deepseek-chat"));
        assert!(joined.contains("consult-frontier-provider-live"));

        // bad id ⇒ Red deny, no silent default.
        let (truth, lines) = render_use(&["frontier", "bad id"], &e);
        assert_eq!(truth, RenderTruth::Red);
        assert!(lines.join("\n").contains("rejected"));
    }

    #[test]
    fn use_local_validates() {
        let e = env(None, None, None, Some(OLLAMA_PORT), false, true);
        let (truth, lines) = render_use(&["local", "8000", "llama3.2"], &e);
        assert_eq!(truth, RenderTruth::Green);
        let joined = lines.join("\n");
        assert!(joined.contains("local validated: 127.0.0.1:8000 model=llama3.2"));
        assert!(joined.contains("export SINABRO_LOCAL_PORT"));
        assert!(joined.contains("consult-local-naite-live"));

        // bad port ⇒ Red deny.
        let (truth, _) = render_use(&["local", "0"], &e);
        assert_eq!(truth, RenderTruth::Red);
    }

    #[test]
    fn use_unknown_runtime_denies() {
        let (truth, lines) = render_use(&["mainnet"], &env(None, None, None, None, false, false));
        assert_eq!(truth, RenderTruth::Red);
        assert!(lines.join("\n").contains("unknown runtime"));
    }

    #[test]
    fn secret_shaped_model_in_env_is_withheld_in_render() {
        // OPENROUTER_MODEL holding a raw-key-shaped value: the summary withholds
        // it (a marker the shared `looks_like_secret` belt catches).
        let key = "suiprivkey1qexamplenotrealkeymaterial";
        let sel = resolve_selection(&env(Some(key), None, None, None, true, false));
        let lines = sel.summary_lines().join("\n");
        assert!(
            !lines.contains(key),
            "secret-shaped model must not be echoed"
        );
        assert!(lines.contains("<withheld:secret>"));
    }

    /// A pathological env value (very long + non-ASCII) can NEVER bust the
    /// 80-col ASCII render budget — `display_model` sanitizes + bounds it.
    #[test]
    fn pathological_env_value_stays_within_render_budget() {
        let huge = "한글-".repeat(200); // non-ASCII + way over 80 bytes
        let sel = resolve_selection(&env(
            Some(&huge),
            Some(&huge),
            Some(&huge),
            None,
            true,
            true,
        ));
        for line in sel.summary_lines() {
            assert!(line.is_ascii(), "non-ascii leaked: {line}");
            assert!(line.len() <= 80, "line > 80 cols: {line}");
        }
        // The selector still resolves (the raw value is the wire truth); only
        // the RENDER is bounded.
        assert_eq!(sel.frontier_model, huge);
    }
}
