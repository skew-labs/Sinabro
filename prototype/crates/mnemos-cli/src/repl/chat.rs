//! Reedline chat loop — the Hermes/Codex-style interactive prompt (G-WP-12 / 12-B).
//!
//! On a real TTY [`launch`](crate::repl::run::launch) draws the
//! [`splash`](crate::repl::splash) once and then runs [`run`] here: a `reedline`
//! line editor with Tab completion over the CLOSED command surface (the slash
//! palette + grammar namespaces — no second truth source), a live status-bar
//! prompt ([`SinabroPrompt`]), and a privacy-redacting history
//! ([`RedactingHistory`]). Every submitted line is dispatched through the
//! UNCHANGED [`crate::repl::run::run_trimmed_line`] (rich response card) — the
//! command / engine / dispatch / `render_*` surface is untouched; this module is
//! input + presentation only. Zero egress, zero live action, funds LOCKED.
//!
//! Physics: reedline owns the real terminal (raw mode per `read_line`, restored
//! on return), so [`run`] writes responses directly to the locked real stdout /
//! stderr rather than to injected generic writers — it cannot run on a pipe (the
//! non-TTY / checker / test path stays on the byte-unchanged cooked
//! [`repl_loop`](crate::repl::run) instead).

use std::borrow::Cow;
use std::io::{self, Write};

use reedline::{
    ColumnarMenu, DefaultCompleter, Emacs, FileBackedHistory, History, HistoryItem, HistoryItemId,
    HistorySessionId, KeyCode, KeyModifiers, MenuBuilder, Prompt, PromptEditMode,
    PromptHistorySearch, Reedline, ReedlineEvent, ReedlineMenu, Result as ReedlineResult,
    SearchQuery, Signal, default_emacs_keybindings,
};

use crate::grammar;
use crate::repl::ReplEngine;
use crate::repl::history::{HistoryStore, classify};
use crate::repl::palette;
use crate::repl::prompt::render_status_strip;
use crate::repl::run::{demo_prompt, run_trimmed_line};

/// In-memory recall capacity for the reedline history.
const HISTORY_CAP: usize = 256;
/// The completion-menu name shared between the Tab keybinding and the menu.
const MENU_NAME: &str = "completion_menu";

/// A privacy-redacting [`History`] wrapper (G-G-SECRET-ZERO). It delegates to an
/// in-memory [`FileBackedHistory`] for all navigation / search, but in
/// [`save`](RedactingHistory::save) it DROPS any secret-shaped command line
/// (reusing the same [`classify`] scanner as [`HistoryStore`]) so a typed API key
/// / seed phrase / raw tx never lands in recall. This mirrors
/// [`HistoryStore::recall_lines`] skipping `Redacted` entries: a dropped line was
/// never stored, so Up/Down can never reconstruct it.
struct RedactingHistory {
    inner: FileBackedHistory,
}

impl RedactingHistory {
    /// An in-memory redacting history holding at most `cap` plain entries.
    ///
    /// # Errors
    /// Propagates the [`FileBackedHistory`] capacity error as an [`io::Error`].
    fn new(cap: usize) -> io::Result<Self> {
        let inner = FileBackedHistory::new(cap).map_err(|e| io::Error::other(e.to_string()))?;
        Ok(Self { inner })
    }
}

impl History for RedactingHistory {
    fn save(&mut self, h: HistoryItem) -> ReedlineResult<HistoryItem> {
        // Secret-zero: a secret-shaped line is NOT persisted (no id assigned), so
        // it can never be recalled. A clean line delegates to the inner store.
        if classify(&h.command_line).is_some() {
            return Ok(h);
        }
        self.inner.save(h)
    }

    fn load(&self, id: HistoryItemId) -> ReedlineResult<HistoryItem> {
        self.inner.load(id)
    }

    fn count(&self, query: SearchQuery) -> ReedlineResult<i64> {
        self.inner.count(query)
    }

    fn search(&self, query: SearchQuery) -> ReedlineResult<Vec<HistoryItem>> {
        self.inner.search(query)
    }

    fn update(
        &mut self,
        id: HistoryItemId,
        updater: &dyn Fn(HistoryItem) -> HistoryItem,
    ) -> ReedlineResult<()> {
        self.inner.update(id, updater)
    }

    fn clear(&mut self) -> ReedlineResult<()> {
        self.inner.clear()
    }

    fn delete(&mut self, h: HistoryItemId) -> ReedlineResult<()> {
        self.inner.delete(h)
    }

    fn sync(&mut self) -> io::Result<()> {
        self.inner.sync()
    }

    fn session(&self) -> Option<HistorySessionId> {
        self.inner.session()
    }
}

/// The sinabro chat prompt: a cyan brand indicator on the left and the live
/// status strip on the right. reedline re-renders the prompt each keystroke, so
/// the right status bar stays current. Text is returned PLAIN — reedline applies
/// the indicator / right-prompt colors.
struct SinabroPrompt {
    status: String,
}

impl SinabroPrompt {
    fn new() -> Self {
        Self {
            status: render_status_strip(&demo_prompt()),
        }
    }
}

impl Prompt for SinabroPrompt {
    fn render_prompt_left(&self) -> Cow<'_, str> {
        Cow::Borrowed("")
    }

    fn render_prompt_right(&self) -> Cow<'_, str> {
        Cow::Borrowed(&self.status)
    }

    fn render_prompt_indicator(&self, _mode: PromptEditMode) -> Cow<'_, str> {
        Cow::Borrowed("▌ sinabro › ")
    }

    fn render_prompt_multiline_indicator(&self) -> Cow<'_, str> {
        Cow::Borrowed("· ")
    }

    fn render_prompt_history_search_indicator(
        &self,
        _history_search: PromptHistorySearch,
    ) -> Cow<'_, str> {
        Cow::Borrowed("(reverse-search) ")
    }
}

/// Build the reedline line editor: Tab completion over the closed command
/// surface (slash palette ++ grammar namespaces), a columnar completion menu,
/// emacs keybindings (Tab opens the menu), and the redacting history.
///
/// # Errors
/// Propagates an [`io::Error`] from constructing the in-memory history.
fn build_editor() -> io::Result<Reedline> {
    // Tab completes the FIRST token from the merged closed universe: the slash
    // palette (`/x`) plus the grammar namespaces. Both come from the closed
    // surfaces — there is no out-of-grammar completion.
    let mut commands = palette::slash_completions();
    commands.extend(
        grammar::ALL
            .iter()
            .map(|ns| ns.canonical_name().to_string()),
    );
    let completer = Box::new(DefaultCompleter::new_with_wordlen(commands, 2));
    let menu = ColumnarMenu::default().with_name(MENU_NAME);
    let mut keybindings = default_emacs_keybindings();
    keybindings.add_binding(
        KeyModifiers::NONE,
        KeyCode::Tab,
        ReedlineEvent::UntilFound(vec![
            ReedlineEvent::Menu(MENU_NAME.to_string()),
            ReedlineEvent::MenuNext,
        ]),
    );
    let edit_mode = Box::new(Emacs::new(keybindings));
    let history = Box::new(RedactingHistory::new(HISTORY_CAP)?);
    Ok(Reedline::create()
        .with_completer(completer)
        .with_menu(ReedlineMenu::EngineCompleter(Box::new(menu)))
        .with_edit_mode(edit_mode)
        .with_history(history))
}

/// Run the reedline chat loop until Ctrl-D / `exit`. Each submitted line is
/// dispatched through the UNCHANGED [`run_trimmed_line`] (rich path), printing a
/// boxed response card to the real stdout. Ctrl-C abandons the current line;
/// Ctrl-D / `exit` / `quit` / `:q` exit cleanly.
///
/// # Errors
/// Propagates an [`io::Error`] from reedline (`read_line`) or from writing the
/// response to stdout / stderr. There is no panic / unwrap path.
pub fn run() -> io::Result<()> {
    let engine = ReplEngine::new();
    let mut history = HistoryStore::new(HISTORY_CAP);
    let mut line_editor = build_editor()?;
    let prompt = SinabroPrompt::new();
    let mut out = io::stdout().lock();
    let mut err = io::stderr().lock();
    loop {
        match line_editor.read_line(&prompt)? {
            Signal::Success(buffer) => {
                let trimmed = buffer.trim();
                if trimmed.is_empty() {
                    continue;
                }
                if matches!(trimmed, "exit" | "quit" | ":q") {
                    break;
                }
                // The same UNCHANGED dispatch body as the cooked loop (rich card).
                run_trimmed_line(trimmed, &engine, &mut history, &mut out, &mut err, true)?;
            }
            // Ctrl-C abandons the in-progress line; the loop continues.
            Signal::CtrlC => continue,
            // Ctrl-D ends the session cleanly.
            Signal::CtrlD => break,
            // `Signal` is #[non_exhaustive]; a future signal is ignored (no
            // dispatch, no panic) rather than ending the session.
            _ => continue,
        }
    }
    out.flush()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;
    use reedline::SearchDirection;

    #[test]
    fn redacting_history_drops_secret_shaped_lines() {
        let mut h = RedactingHistory::new(8).unwrap();
        // A 64-char single-token hex string is key-shaped -> classify flags it.
        let secret = "a".repeat(64);
        assert!(classify(&secret).is_some(), "fixture must be secret-shaped");
        h.save(HistoryItem::from_command_line(secret.clone()))
            .unwrap();
        // Nothing was stored: the inner history is empty, so the secret can never
        // be recalled.
        let all = h
            .search(SearchQuery::everything(SearchDirection::Forward, None))
            .unwrap();
        assert!(all.is_empty(), "secret-shaped line must not persist");
    }

    #[test]
    fn redacting_history_keeps_plain_commands() {
        let mut h = RedactingHistory::new(8).unwrap();
        h.save(HistoryItem::from_command_line(
            "provider status".to_string(),
        ))
        .unwrap();
        h.save(HistoryItem::from_command_line("memory status".to_string()))
            .unwrap();
        let all = h
            .search(SearchQuery::everything(SearchDirection::Forward, None))
            .unwrap();
        let lines: Vec<String> = all.into_iter().map(|i| i.command_line).collect();
        assert_eq!(
            lines,
            vec!["provider status".to_string(), "memory status".to_string()]
        );
    }

    #[test]
    fn prompt_indicator_is_the_brand_bar_and_right_is_the_status_strip() {
        let p = SinabroPrompt::new();
        let ind = p.render_prompt_indicator(PromptEditMode::Default);
        assert!(ind.contains('▌'), "{ind}");
        assert!(ind.contains("sinabro"), "{ind}");
        // The right prompt carries the status strip (ws/model/ctx/budget...).
        let right = p.render_prompt_right();
        assert!(right.contains("ws:"), "{right}");
        assert!(right.contains("budget:"), "{right}");
    }

    #[test]
    fn build_editor_succeeds_with_closed_completion_universe() {
        // The editor builds (history allocates, menu/keybindings wire). The
        // completion universe is the closed palette + grammar surfaces.
        assert!(build_editor().is_ok());
        let mut commands = palette::slash_completions();
        commands.extend(
            grammar::ALL
                .iter()
                .map(|ns| ns.canonical_name().to_string()),
        );
        assert_eq!(commands.len(), palette::SLASH_TABLE.len() + grammar::COUNT);
        assert!(commands.iter().any(|c| c == "/skill"));
        assert!(commands.iter().any(|c| c == "provider"));
    }
}
