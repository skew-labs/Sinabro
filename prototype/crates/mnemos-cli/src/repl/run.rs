//! Interactive REPL read-eval loop (atoms #573-#577, #587-#588).
//!
//! `sinabro` / `sinabro repl` runs a REAL read-eval loop — not a one-shot
//! snapshot. Each line is classified through the closed [`ReplEngine`] /
//! [`crate::grammar`] (no envelope bypass) and rendered through the canonical
//! [`crate::dispatch::run`] router; slash lines reuse the closed
//! [`crate::repl::palette`] table, and STOP-class control words / `/kill` ride the
//! [`ControlExpressRouter`] / [`KillController`] express rail (bypassing the
//! background queues). EOF (Ctrl-D) exits cleanly; history auto-redacts secrets.
//! The `setup` / `setup memory` wizards render the #587 / #588 onboarding flows.
//!
//! Live boundary: render / dispatch only. Every side-effect verb stays
//! same-message approval-gated and disabled in Phase 0 — [`crate::dispatch::run`]
//! never executes a side effect. Zero egress, zero model dependency, funds LOCKED.
//!
//! Two presentation surfaces share this one dispatch core
//! ([`run_trimmed_line`]), so they can never drift:
//! - On a real TTY (both stdin + stdout), [`launch`] draws the one-shot `ratatui`
//!   [`crate::repl::splash`] into scrollback and then runs the `reedline` chat
//!   loop ([`crate::repl::chat`]: history, completion, status-bar prompt). This
//!   replaced the G-WP-11 hand-rolled raw-mode line editor (G-WP-12).
//! - Otherwise (pipe / file / checker / test), the byte-exact cooked [`repl_loop`]
//!   uses line-buffered `read_line` (rich SGR coloring iff stdout is a TTY, plain
//!   when piped — so every pipe / checker / test exercises the unchanged plain
//!   path and the G-WP-10 Plain proof stays valid).

use std::io::{self, BufRead, IsTerminal, Write};

use crate::commands::kill::KillController;
use crate::commands::memory_setup::{
    GasSponsorMode, MemorySetupWizard, MemoryStorageMode, PrivacyLearningMode,
};
use crate::daemon::control_express::{BackgroundQueueDepths, ControlExpressRouter, ExpressClass};
use crate::grammar;
use crate::repl::history::HistoryStore;
use crate::repl::prompt::{PromptStatus, render_status_strip};
use crate::repl::{ReplEngine, ReplOutcome};
use crate::setup::{self, SetupPlan};

/// The summary of one REPL session. Fields are read by the inline tests + the
/// headless checker harness.
#[allow(dead_code)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct ReplSummary {
    lines_handled: u32,
    history_len: usize,
    eof_clean: bool,
}

/// A demo prompt-status strip (no live state; workspace hash only). Reused by the
/// reedline chat prompt ([`crate::repl::chat`]) as the single demo-status source.
pub(crate) fn demo_prompt() -> PromptStatus {
    PromptStatus {
        workspace_hash_32: crate::sha256_32(b"/Users/heoun/mnemos"),
        model_hash_32: [0u8; 32],
        context_pressure_bps: 0,
        last_checkpoint_hash_32: [0u8; 32],
        budget_remaining_micros: 1_000_000,
        sandbox_tier_u8: 1,
        pending_approvals_u16: 0,
        pending_tasks_u16: 0,
    }
}

/// The reedline-style rich prompt: cyan+bold left bar + dim chevron. Emitted only
/// on a real TTY (`rich`); the plain path keeps the byte-exact `sinabro> `.
const RICH_PROMPT: &str = "\x1b[36m\x1b[1m▌\x1b[0m sinabro \x1b[2m›\x1b[0m ";

fn greet<W: Write>(out: &mut W, rich: bool) -> io::Result<()> {
    let prompt = demo_prompt();
    if rich {
        // Rich greeting: the four plain banner lines wrapped in one Unicode box by
        // the shared `tui::run::rich_box` (same border/row primitives as the
        // dashboard). `funds LOCKED` is SGR-highlighted by the shared colorizer. An
        // array (not `vec!`) avoids `clippy::useless_vec` under `-D warnings`.
        let rows = [
            "sinabro repl - local-first audit cockpit (NO live action; funds LOCKED)".to_string(),
            render_status_strip(&prompt),
            format!(
                "closed grammar: {} namespaces. type <namespace> <verb>, /<slash>, or setup",
                grammar::COUNT
            ),
            "every line is classified through a CommandEnvelope (no bypass). Ctrl-D exits"
                .to_string(),
        ];
        let mut frame = String::new();
        crate::tui::run::rich_box(&mut frame, &rows, crate::tui::run::term_cols());
        return out.write_all(frame.as_bytes());
    }
    writeln!(
        out,
        "sinabro repl - local-first audit cockpit (NO live action; funds LOCKED)"
    )?;
    writeln!(out, "{}", render_status_strip(&prompt))?;
    writeln!(
        out,
        "closed grammar: {} namespaces. type <namespace> <verb>, /<slash>, or setup",
        grammar::COUNT
    )?;
    writeln!(
        out,
        "every line is classified through a CommandEnvelope (no bypass). Ctrl-D exits"
    )
}

fn prompt_line<W: Write>(out: &mut W, rich: bool) -> io::Result<()> {
    if rich {
        out.write_all(RICH_PROMPT.as_bytes())?;
    } else {
        write!(out, "sinabro> ")?;
    }
    out.flush()
}

/// Render a command through the canonical dispatch router. dispatch::run owns the
/// closed top-level + namespace vocabulary and never executes a side effect.
fn dispatch_tokens<W: Write, E: Write>(
    tokens: &[String],
    out: &mut W,
    err: &mut E,
) -> io::Result<()> {
    crate::dispatch::run(tokens, out, err).map(|_exit| ())
}

/// Acknowledge a STOP-class control on the express rail (atom #576): the ack is
/// produced synchronously, bypassing the (possibly saturated) background queues,
/// and performs no live action.
fn render_express<W: Write>(class: ExpressClass, out: &mut W) -> io::Result<()> {
    let mut router = ControlExpressRouter::new();
    let ack = router.ack(class, BackgroundQueueDepths::saturated(100_000));
    writeln!(
        out,
        "express control: class_u8={} (STOP/freeze/pause; bypasses queues)",
        class.as_u8()
    )?;
    writeln!(
        out,
        "bypassed_queue={} stops_next_side_effect={} live_action={} bypassed_depth={}",
        ack.bypassed_queue, ack.stops_next_side_effect, ack.live_action, ack.bypassed_depth_total
    )?;
    writeln!(
        out,
        "next_side_effect_allowed={} (resume to clear)",
        router.next_side_effect_allowed()
    )?;
    if matches!(class, ExpressClass::Kill) {
        let kc = KillController::new();
        writeln!(
            out,
            "kill: control_version={} live_jobs={} no-zombie (a killed job never resurrects)",
            kc.version(),
            kc.rail().items().len()
        )?;
    }
    Ok(())
}

/// #587 — the 5-step setup wizard (Provider -> MemoryOwner -> Telegram -> Privacy
/// -> FirstDryRun). Learning defaults off; a raw seed phrase is never an option.
fn render_setup_wizard<W: Write>(out: &mut W) -> io::Result<()> {
    let plan = SetupPlan::default();
    writeln!(
        out,
        "setup wizard (5 steps): learning OFF by default; raw seed phrase rejected"
    )?;
    for (i, step) in setup::STEPS.iter().enumerate() {
        writeln!(out, "  step {}/{}: {step:?}", i + 1, setup::STEPS.len())?;
    }
    writeln!(
        out,
        "memory_owner_method={:?} (WalletConnect/ZkLogin/Passkey/LocalKeystore; NO seed phrase)",
        plan.owner_method
    )?;
    writeln!(
        out,
        "learning={:?} first_dry_run_ready={} (the first dry-run is the last step)",
        plan.learning.mode, plan.first_dry_run_ready
    )?;
    writeln!(
        out,
        "no live action runs without approval; each step shows the next safe action"
    )
}

/// #588 — the mandatory first-run 4-axis memory wizard (storage / identity /
/// gas-sponsor / privacy-learning). Owner is bound from a public key only; seed
/// entry is forbidden; the server key can never be the owner; owner != sponsor.
fn render_memory_wizard<W: Write>(out: &mut W) -> io::Result<()> {
    match MemorySetupWizard::configure(
        [1u8; 32],
        None,
        MemoryStorageMode::LocalOnly,
        GasSponsorMode::SelfFunded,
        PrivacyLearningMode::PrivateLearningOff,
    ) {
        Ok(wizard) => {
            writeln!(
                out,
                "memory setup wizard (4 axes: storage/identity/gas-sponsor/privacy)"
            )?;
            writeln!(
                out,
                "owner bound from a public key only; seed-phrase entry forbidden"
            )?;
            for line in wizard.render(32) {
                writeln!(out, "  {line}")?;
            }
            writeln!(
                out,
                "owner_is_not_sponsor={} (server key can NEVER be owner); Walrus = only live writer (testnet)",
                wizard.owner_is_not_sponsor()
            )
        }
        Err(_) => writeln!(out, "memory setup wizard unavailable"),
    }
}

/// #624 — render the live audit game tree (`audit scan/explain/repro-plan`). The
/// pipeline is built by the shared [`crate::tui::run::audit_game_tree_lines`]
/// renderer (no second truth source), so the CLI REPL and the TUI cockpit drive
/// ONE audit pipeline; a candidate stays a candidate until a local repro receipt
/// promotes it (the REPL never promotes a candidate to a finding).
fn render_audit_game_tree<W: Write>(verb: &str, out: &mut W) -> io::Result<()> {
    writeln!(
        out,
        "audit {verb}: game tree (candidate != finding; local-only)"
    )?;
    for line in crate::tui::run::audit_game_tree_lines() {
        writeln!(out, "{line}")?;
    }
    Ok(())
}

/// #627 — render the live memory commands surface (`memory status/list/query/
/// export/delete/replay`). The pipeline is the shared
/// [`crate::tui::run::memory_commands_lines`] renderer (no second truth source);
/// a deleted memory writes a tombstone and can never be resurrected, and raw
/// private content is never shown (redacted summaries only).
fn render_memory_commands<W: Write>(verb: &str, out: &mut W) -> io::Result<()> {
    writeln!(
        out,
        "memory {verb}: user-owned; redacted; tombstone no-resurrection"
    )?;
    for line in crate::tui::run::memory_commands_lines() {
        writeln!(out, "{line}")?;
    }
    Ok(())
}

/// #629 — render the live evidence pack (`evidence pack`). The hash-linked
/// manifest is built by the shared [`crate::tui::run::evidence_pack_lines`]
/// renderer (no second truth source); the pack is secret-zero and archive
/// presence is never training consent.
fn render_evidence_pack<W: Write>(out: &mut W) -> io::Result<()> {
    writeln!(
        out,
        "evidence pack: hash-linked manifest (secret-zero; not training consent)"
    )?;
    for line in crate::tui::run::evidence_pack_lines() {
        writeln!(out, "{line}")?;
    }
    Ok(())
}

/// #631 — render the live skill discovery/use/state surface (`skill search/
/// inspect/recommend/use/enable/disable/update/remove`). The pipeline is the
/// shared [`crate::tui::run::skill_live_lines`] renderer (no second truth
/// source): skills are untrusted-by-default, the capability diff is shown before
/// execution, a use needs a passing dry-run + an explicit confirm, the sandbox
/// tier ceiling bounds execution, quarantine is sticky (fail-closed), and there
/// is no commerce / checkout surface.
fn render_skill_live<W: Write>(verb: &str, out: &mut W) -> io::Result<()> {
    writeln!(
        out,
        "skill {verb}: security-first; sandbox-bound; try-before-use; no-commerce"
    )?;
    for line in crate::tui::run::skill_live_lines() {
        writeln!(out, "{line}")?;
    }
    Ok(())
}

/// #635 — render the live daemon supervisor + task/session inbox + reconnect
/// (`daemon status/inbox/reconnect/supervisor`). The pipeline is the shared
/// [`crate::tui::run::daemon_live_lines`] renderer (no second truth source): the
/// daemon owns no secret or wallet and is killable; provider/audit/memory/
/// evidence/notify/handoff jobs share ONE inbox id space; and the CLI and
/// Telegram reconnect to ONE state hash (a stale view is refused).
fn render_daemon_live<W: Write>(verb: &str, out: &mut W) -> io::Result<()> {
    writeln!(
        out,
        "daemon {verb}: no secret/wallet; killable; one inbox + one state_hash"
    )?;
    for line in crate::tui::run::daemon_live_lines() {
        writeln!(out, "{line}")?;
    }
    Ok(())
}

/// #638 — render the live control-express-under-load surface (`control
/// status/express`). The pipeline is the shared
/// [`crate::tui::run::control_live_lines`] renderer (no second truth source):
/// STOP/freeze/pause controls ride a preallocated express lane that bypasses the
/// saturated background queues, lowering the budget cap stops the next side
/// effect, and a killed task can never write evidence — all halt-class, never a
/// live action. (`pause` / `lockdown` / `/kill` keep their existing express-word
/// behavior via [`render_express`].)
fn render_control_live<W: Write>(verb: &str, out: &mut W) -> io::Result<()> {
    writeln!(
        out,
        "control {verb}: preallocated express lane; halts only; 0 live action"
    )?;
    for line in crate::tui::run::control_live_lines() {
        writeln!(out, "{line}")?;
    }
    Ok(())
}

/// Resolve a leading-`/` palette line. All 28 closed [`crate::repl::palette`]
/// entries resolve to the SAME `(namespace, verb)` as the bare command; `/kill`
/// rides the express rail; an unknown slash is rejected.
fn handle_slash<W: Write, E: Write>(line: &str, out: &mut W, err: &mut E) -> io::Result<()> {
    let rest = line.trim_start_matches('/');
    let mut toks = rest.split_whitespace();
    let key = toks.next().unwrap_or_default();
    match crate::repl::palette::lookup(key) {
        Some((ns, default_verb)) => {
            if key.eq_ignore_ascii_case("kill") {
                return render_express(ExpressClass::Kill, out);
            }
            let verb = toks.next().unwrap_or(default_verb);
            let argv = vec![ns.canonical_name().to_string(), verb.to_string()];
            dispatch_tokens(&argv, out, err)
        }
        // unknown-slash reject (mirrors `CliError::UnknownCommand`'s display text).
        None => writeln!(err, "unknown command"),
    }
}

/// Handle one (non-empty, trimmed) input line.
fn handle_line<W: Write, E: Write>(
    line: &str,
    engine: &ReplEngine,
    out: &mut W,
    err: &mut E,
) -> io::Result<()> {
    if line.starts_with('/') {
        return handle_slash(line, out, err);
    }
    // STOP-class bare control words ride the express rail (`pause`/`lockdown` are
    // not grammar namespaces; `kill`/`budget` are dispatch top-level commands that
    // already render their control surfaces).
    match line {
        "pause" => return render_express(ExpressClass::Pause, out),
        "lockdown" => return render_express(ExpressClass::Lockdown, out),
        _ => {}
    }
    // Interactive onboarding surfaces (#587 / #588).
    let mut head = line.split_whitespace();
    if head.next() == Some("setup") {
        return match head.next() {
            None => render_setup_wizard(out),
            Some("memory") => render_memory_wizard(out),
            Some(other) => {
                writeln!(out, "unknown subcommand: setup {other}")?;
                writeln!(out, "valid: setup · setup memory")
            }
        };
    }
    // #624 — `audit scan/explain/repro-plan` drive the live audit game tree
    // (invariant-graph -> bounded-state-space -> move-generator -> impact-prior ->
    // candidate). A candidate is a tree node only; promotion needs a local repro
    // receipt. The shared cockpit renderer is the single audit-pipeline truth; any
    // other audit verb falls through to the canonical dispatch router below.
    {
        let mut audit = line.split_whitespace();
        if audit.next() == Some("audit") {
            if let Some(verb @ ("scan" | "explain" | "repro-plan")) = audit.next() {
                return render_audit_game_tree(verb, out);
            }
        }
    }
    // #627 — `memory status/list/query/export/delete/replay` drive the live memory
    // commands surface (redacted views; tombstone no-resurrection; owner-verified).
    {
        let mut mem = line.split_whitespace();
        if mem.next() == Some("memory") {
            if let Some(verb @ ("status" | "list" | "query" | "export" | "delete" | "replay")) =
                mem.next()
            {
                return render_memory_commands(verb, out);
            }
        }
    }
    // #629 — `evidence pack` drives the live hash-linked evidence pack manifest
    // (provider/audit/memory/telegram/trace kinds; secret-zero; not training consent).
    {
        let mut ev = line.split_whitespace();
        if ev.next() == Some("evidence") {
            if let Some("pack") = ev.next() {
                return render_evidence_pack(out);
            }
        }
    }
    // #631 — `skill search/inspect/recommend/use/enable/disable/update/remove`
    // drive the live skill discovery/use/state surface (security-first ranking;
    // try-before-use dry-run + confirm; sandbox-bound; quarantine sticky; no
    // commerce). The shared cockpit renderer is the single skill-pipeline truth;
    // a bare `skill` (no verb) or any other verb falls through to dispatch.
    {
        let mut sk = line.split_whitespace();
        if sk.next() == Some("skill") {
            if let Some(
                verb @ ("search" | "inspect" | "recommend" | "use" | "enable" | "disable"
                | "update" | "remove"),
            ) = sk.next()
            {
                return render_skill_live(verb, out);
            }
        }
    }
    // #635 — `daemon status/inbox/reconnect/supervisor` drive the live daemon
    // supervisor + task/session inbox + reconnect surface (killable, owns no
    // secret/wallet; one shared inbox id space; CLI+TG one state_hash; a stale
    // view is refused). The shared cockpit renderer is the single truth source.
    {
        let mut dm = line.split_whitespace();
        if dm.next() == Some("daemon") {
            if let Some(verb @ ("status" | "inbox" | "reconnect" | "supervisor")) = dm.next() {
                return render_daemon_live(verb, out);
            }
        }
    }
    // #638 — `control status/express` drive the live control-express surface
    // (STOP/freeze/pause on a preallocated express lane that bypasses the
    // saturated background queues; the budget cap is re-checked before every side
    // effect; halts only, never a live action). The shared cockpit renderer is the
    // single truth source; `pause`/`lockdown`/`/kill` keep their express words.
    {
        let mut ce = line.split_whitespace();
        if ce.next() == Some("control") {
            if let Some(verb @ ("status" | "express")) = ce.next() {
                return render_control_live(verb, out);
            }
        }
    }
    // Classify through the closed engine (no bypass), then render through the
    // canonical dispatch router (which owns the top-level + namespace vocabulary
    // and rejects a truly-unknown verb).
    match engine.handle_line(line) {
        ReplOutcome::Empty | ReplOutcome::Eof | ReplOutcome::Cancelled => Ok(()),
        ReplOutcome::Unknown | ReplOutcome::Dispatch(_) => {
            let argv: Vec<String> = line.split_whitespace().map(String::from).collect();
            dispatch_tokens(&argv, out, err)
        }
    }
}

/// Draw the captured handler output as one boxed "response card" (rich TTY path).
/// `obuf` (stdout) lines are boxed as-is; `ebuf` (stderr) lines are folded in with a
/// `! ` prefix, so on a TTY the real `err` stream stays untouched. An entirely empty
/// response draws nothing (no empty box). Uses the shared
/// [`crate::tui::run::rich_box`] so the repl and the dashboard share one look.
fn rich_response<W: Write>(out: &mut W, obuf: &[u8], ebuf: &[u8]) -> io::Result<()> {
    let otext = String::from_utf8_lossy(obuf);
    let etext = String::from_utf8_lossy(ebuf);
    let mut rows: Vec<String> = otext.lines().map(String::from).collect();
    rows.extend(etext.lines().map(|l| format!("! {l}")));
    if rows.is_empty() {
        return Ok(());
    }
    let mut frame = String::new();
    crate::tui::run::rich_box(&mut frame, &rows, crate::tui::run::term_cols());
    out.write_all(frame.as_bytes())
}

/// Record + dispatch one already-trimmed, non-empty command line: push it into the
/// (auto-redacting) history, then render through the UNCHANGED [`handle_line`] — as
/// one boxed rich response card on a TTY (`rich`), or straight to `out` / `err`
/// otherwise. The command / engine / dispatch / `render_*` surface is untouched;
/// this is the shared dispatch body of both the cooked ([`repl_loop`]) and the
/// reedline chat ([`crate::repl::chat`]) input loops, so the two can never drift.
pub(crate) fn run_trimmed_line<W: Write, E: Write>(
    trimmed: &str,
    engine: &ReplEngine,
    history: &mut HistoryStore,
    out: &mut W,
    err: &mut E,
    rich: bool,
) -> io::Result<()> {
    // Auto-redact secret-shaped input before it persists in history (#574).
    history.push(trimmed);
    if rich {
        // Rich path: capture the (unchanged) handler output into buffers, then draw
        // it as one boxed response card. `handle_line` / `handle_slash` / every
        // `render_*` / the 24 views stay byte-identical — the box is added purely at
        // this loop layer (buffer-capture-then-box).
        let mut obuf: Vec<u8> = Vec::new();
        let mut ebuf: Vec<u8> = Vec::new();
        handle_line(trimmed, engine, &mut obuf, &mut ebuf)?;
        rich_response(out, &obuf, &ebuf)?;
    } else {
        handle_line(trimmed, engine, out, err)?;
    }
    Ok(())
}

/// The cooked read-eval loop (atom #573): greet, then read a line with line-buffered
/// `read_line` (no terminal required), classify, dispatch, and loop until EOF /
/// `exit`. This is the always-available std core: every pipe / file / checker / test
/// exercises it byte-for-byte, and a real TTY whose termios switch fails falls back
/// to it. Generic over the reader + writers for headless testing.
fn repl_loop<R: BufRead, W: Write, E: Write>(
    input: &mut R,
    out: &mut W,
    err: &mut E,
    rich: bool,
) -> io::Result<ReplSummary> {
    let engine = ReplEngine::new();
    let mut history = HistoryStore::new(256);
    let mut lines_handled = 0u32;
    greet(out, rich)?;
    let mut line = String::new();
    loop {
        prompt_line(out, rich)?;
        line.clear();
        let n = input.read_line(&mut line)?;
        if n == 0 {
            // EOF (Ctrl-D): clean exit.
            let _eof = engine.handle_eof();
            break;
        }
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        if matches!(trimmed, "exit" | "quit" | ":q") {
            break;
        }
        run_trimmed_line(trimmed, &engine, &mut history, out, err, rich)?;
        lines_handled = lines_handled.saturating_add(1);
    }
    Ok(ReplSummary {
        lines_handled,
        history_len: history.len(),
        eof_clean: true,
    })
}

/// Launch the interactive REPL (`sinabro` / `sinabro repl`). On a real TTY (both
/// stdin and stdout) it draws the one-shot `ratatui` [`crate::repl::splash`] into
/// scrollback and then runs the `reedline` chat loop ([`crate::repl::chat`]);
/// when either stream is not a TTY (pipe / file / checker / test) it runs the
/// byte-exact cooked [`repl_loop`] (rich coloring iff stdout is a TTY). Exits
/// cleanly at EOF / Ctrl-D.
///
/// # Errors
/// Propagates an [`io::Error`] from the splash / chat editor or from reading
/// input / writing output (e.g. a broken pipe). There is no panic / unwrap path.
pub fn launch() -> io::Result<()> {
    let stdin = io::stdin();
    let stdout_is_tty = io::stdout().is_terminal();
    // Both streams a real TTY -> the Hermes-style splash + reedline chat loop.
    if stdin.is_terminal() && stdout_is_tty {
        crate::repl::splash::render()?;
        return crate::repl::chat::run();
    }
    // Non-TTY (pipe / file / checker / test): the byte-unchanged cooked loop. This
    // preserves the G-WP-10 Plain proof + the headless `run_repl` tests.
    let mut input = stdin.lock();
    let mut out = io::stdout().lock();
    let mut err = io::stderr().lock();
    let _summary = repl_loop(&mut input, &mut out, &mut err, stdout_is_tty)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;
    use std::io::Cursor;

    fn run_repl(input: &[u8]) -> (ReplSummary, String, String) {
        run_repl_mode(input, false)
    }

    fn run_repl_rich(input: &[u8]) -> (ReplSummary, String, String) {
        run_repl_mode(input, true)
    }

    fn run_repl_mode(input: &[u8], rich: bool) -> (ReplSummary, String, String) {
        let mut reader = Cursor::new(input.to_vec());
        let mut out: Vec<u8> = Vec::new();
        let mut err: Vec<u8> = Vec::new();
        let summary =
            repl_loop(&mut reader, &mut out, &mut err, rich).expect("in-memory io never fails");
        (
            summary,
            String::from_utf8_lossy(&out).into_owned(),
            String::from_utf8_lossy(&err).into_owned(),
        )
    }

    #[test]
    fn eof_exits_clean_with_greeting() {
        let (s, out, _) = run_repl(b"");
        assert!(s.eof_clean);
        assert_eq!(s.lines_handled, 0);
        assert!(out.contains("sinabro repl"));
        assert!(out.contains("sinabro> "));
    }

    #[test]
    fn known_command_dispatches_real_render() {
        let (s, out, _) = run_repl(b"provider status\n");
        assert_eq!(s.lines_handled, 1);
        assert!(out.contains("command=provider status"));
        assert!(out.contains("approval=none"));
    }

    #[test]
    fn top_level_status_dispatches_even_though_not_a_namespace() {
        let (_, out, _) = run_repl(b"status\n");
        assert!(out.contains("command=status"));
    }

    #[test]
    fn unknown_command_is_rejected_on_err() {
        let (_, _, err) = run_repl(b"definitely-not-a-namespace\n");
        assert!(err.contains("unknown command"));
    }

    #[test]
    fn slash_resolves_same_as_bare_command() {
        let (_, out, _) = run_repl(b"/provider\n");
        assert!(out.contains("command=provider status"));
    }

    #[test]
    fn unknown_slash_is_rejected() {
        let (_, _, err) = run_repl(b"/definitely-not\n");
        assert!(err.contains("unknown command"));
    }

    #[test]
    fn kill_slash_rides_the_express_rail() {
        let (_, out, _) = run_repl(b"/kill\n");
        assert!(out.contains("express control"));
        assert!(out.contains("bypassed_queue=true"));
        assert!(out.contains("live_action=false"));
        assert!(out.contains("no-zombie"));
    }

    #[test]
    fn pause_and_lockdown_are_express_stops() {
        let (_, out, _) = run_repl(b"pause\nlockdown\n");
        assert!(out.matches("express control").count() >= 2);
        assert!(out.contains("live_action=false"));
    }

    #[test]
    fn wallet_sign_shows_typed_phrase_gate_not_executed() {
        let (_, out, _) = run_repl(b"wallet sign\n");
        assert!(out.contains("approval=typed-phrase"));
        assert!(out.contains("is NOT executed"));
    }

    #[test]
    fn train_run_is_forbidden_no_training_in_g() {
        let (_, out, _) = run_repl(b"train run\n");
        assert!(out.contains("approval=training-locked"));
        assert!(out.contains("weight training is locked"));
    }

    #[test]
    fn setup_renders_five_step_wizard_seed_rejected() {
        let (_, out, _) = run_repl(b"setup\n");
        assert!(out.contains("setup wizard (5 steps)"));
        assert!(out.contains("NO seed phrase"));
        assert!(out.contains("step 5/5"));
    }

    #[test]
    fn setup_memory_renders_four_axis_wizard() {
        let (_, out, _) = run_repl(b"setup memory\n");
        assert!(out.contains("memory setup wizard (4 axes"));
        assert!(out.contains("owner_is_not_sponsor=true"));
        assert!(out.contains("seed-phrase entry forbidden"));
    }

    #[test]
    fn secret_shaped_input_is_redacted_in_history() {
        let mut line = "a".repeat(64);
        line.push('\n');
        let (s, _, _) = run_repl(line.as_bytes());
        assert_eq!(s.history_len, 1);
        // (raw-value absence is proven by the history module's own unit tests.)
    }

    #[test]
    fn exit_quits_the_loop_before_later_lines() {
        let (s, _, _) = run_repl(b"trace list\nexit\nprovider status\n");
        assert_eq!(s.lines_handled, 1);
    }

    #[test]
    fn empty_lines_are_skipped() {
        let (s, _, _) = run_repl(b"\n   \nprovider status\n");
        assert_eq!(s.lines_handled, 1);
    }

    #[test]
    fn twin_run_is_deterministic() {
        let a = run_repl(b"provider status\n/skill\nbudget\n");
        let b = run_repl(b"provider status\n/skill\nbudget\n");
        assert_eq!(a, b);
    }

    #[test]
    fn audit_scan_drives_live_game_tree_candidate_not_finding() {
        // #624 — `audit scan` drives the full live pipeline (not the bare dispatch
        // status). A candidate stays a candidate: a non-reproduced receipt never
        // promotes, and the search is bounded with no production probe.
        let (_, out, _) = run_repl(b"audit scan\n");
        assert!(out.contains("audit scan: game tree"));
        assert!(out.contains("audit game tree:"));
        assert!(out.contains("bounded state: all_axes_nonzero=true"));
        assert!(out.contains("candidate: pattern_only=true"));
        assert!(out.contains("candidate != finding"));
        assert!(out.contains("production_probe_denied=true"));
        assert!(out.contains("non_repro_promotes=false"));
    }

    #[test]
    fn audit_explain_and_repro_plan_drive_same_pipeline() {
        let (_, out, _) = run_repl(b"audit explain\naudit repro-plan\n");
        assert!(out.contains("audit explain: game tree"));
        assert!(out.contains("audit repro-plan: game tree"));
        assert!(out.contains("repro-plan: schema_complete=true"));
    }

    #[test]
    fn memory_status_drives_live_surface_tombstone_no_resurrection() {
        let (_, out, _) = run_repl(b"memory status\nmemory delete\n");
        assert!(out.contains("memory status: user-owned"));
        assert!(out.contains("memory delete: user-owned"));
        assert!(out.contains("full_replay_on_hot_path=false"));
        assert!(out.contains("zero_resurrections=true"));
        assert!(out.contains("raw_content_visible=false"));
    }

    #[test]
    fn evidence_pack_drives_live_hash_linked_manifest() {
        let (_, out, _) = run_repl(b"evidence pack\n");
        assert!(out.contains("evidence pack: hash-linked"));
        assert!(out.contains("recompute_matches=true"));
        assert!(out.contains("holds_no_secret=true"));
        assert!(out.contains("training_eligible=false"));
    }

    #[test]
    fn skill_verbs_drive_live_security_first_sandbox_bound_quarantine_sticky() {
        // #631 — bare `skill <verb>` drives the live skill surface through the
        // SAME shared renderer as the TUI cockpit (one skill pipeline, no second
        // truth source): security-first discovery, a use that needs dry-run +
        // confirm, a sandbox tier ceiling, and a sticky quarantine.
        let (_, out, _) = run_repl(b"skill search\nskill enable\n");
        assert!(out.contains("skill search: security-first"));
        assert!(out.contains("skill enable: security-first"));
        assert!(out.contains("security_first_holds=true"));
        assert!(out.contains("quarantine_gated_to_zero=true"));
        assert!(out.contains("can_launch=true"));
        assert!(out.contains("is_commerce=false"));
        assert!(out.contains("warmup_widens=false"));
        assert!(out.contains("re_enable_denied=true"));
    }

    #[test]
    fn daemon_verbs_drive_live_no_secret_killable_one_state_hash() {
        // #635 — bare `daemon <verb>` drives the live daemon surface through the
        // SAME shared renderer as the TUI cockpit (one daemon pipeline, no second
        // truth source): the daemon owns no secret/wallet and is killable, the
        // inbox shares one id space, and CLI+TG reconnect to one state_hash (a
        // stale view is refused).
        let (_, out, _) = run_repl(b"daemon status\ndaemon reconnect\n");
        assert!(out.contains("daemon status: no secret/wallet"));
        assert!(out.contains("daemon reconnect: no secret/wallet"));
        assert!(out.contains("holds_no_secret_or_wallet=true"));
        assert!(out.contains("running_killable=true"));
        assert!(out.contains("cli_tg_same_hash=true"));
        assert!(out.contains("stale_view_refused=true"));
    }

    #[test]
    fn control_verbs_drive_live_express_lane_under_load() {
        // #638 — bare `control <verb>` drives the live control-express surface
        // through the SAME shared renderer as the TUI cockpit (one control
        // pipeline): a STOP control bypasses a saturated queue and halts, a
        // lowered cap stops the next dispatch, and a killed task cannot write
        // evidence.
        let (_, out, _) = run_repl(b"control status\ncontrol express\n");
        assert!(out.contains("control status: preallocated express lane"));
        assert!(out.contains("control express: preallocated express lane"));
        assert!(out.contains("kill_bypasses=true"));
        assert!(out.contains("cap_lowered_denies_dispatch=true"));
        assert!(out.contains("killed_cannot_write_evidence=true"));
        assert!(out.contains("every_class_bypasses=true"));
    }

    #[test]
    fn rich_tty_path_boxes_greeting_prompt_and_response() {
        // The rich (real-TTY) path: the greeting is a Unicode box, the prompt is the
        // reedline-style `▌ … ›` bar (not `sinabro> `), each response is a boxed card
        // with SGR color + CRLF, and stderr is folded into the card so the real `err`
        // stream stays empty. Every other test (via `run_repl`) keeps the byte-exact
        // Plain path, so this purely ADDS coverage — G-WP-10's Plain proof is intact.
        let (s, out, err) = run_repl_rich(b"provider status\n");
        assert_eq!(s.lines_handled, 1);
        // greeting + response boxes (top-left / vertical / bottom-left glyphs).
        assert!(out.contains('┌'));
        assert!(out.contains('│'));
        assert!(out.contains('└'));
        // reedline-style rich prompt present, and the plain `sinabro> ` absent.
        assert!(out.contains('▌'));
        assert!(out.contains('›'));
        assert!(!out.contains("sinabro> "));
        // SGR escapes + CRLF line endings on the rich path.
        assert!(out.contains("\x1b["));
        assert!(out.contains("\r\n"));
        // the real command output is inside the card; stderr folded ⇒ `err` empty.
        assert!(out.contains("command=provider status"));
        assert!(err.is_empty());
    }
}
