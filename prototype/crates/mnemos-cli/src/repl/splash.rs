//! Startup splash — ratatui one-shot, rendered into scrollback.
//!
//! On a real TTY [`launch`](crate::repl::run::launch) draws this splash ONCE
//! (above a 1-line inline viewport, so it lands in the terminal scrollback) and
//! then drops the terminal and hands off to the reedline chat loop
//! ([`crate::repl::chat`]). It performs ZERO live action and ZERO egress — it is a
//! pure render of the closed command surface ([`crate::grammar`]). The
//! page-sized `SINABRO` block banner is allowed HERE only (the startup splash);
//! operational views stay clean.
//!
//! Layout mirrors a Hermes/Codex-style splash: block wordmark, a bordered body
//! (left emblem + identity, right `category: members` grid in two sections —
//! Commands / Skills), then a welcome line + a bottom status bar.
//!
//! Honesty: unlike a live agent (Hermes' `browser` / `code_execution`
//! / `image_gen`), this build has NO live tools — funds LOCKED, egress 0. The
//! grid shows OUR real closed grammar (35 namespaces, grouped); the Skills
//! section states sandbox-gated / none enabled. It never draws a tool we lack.
//!
//! We deliberately avoid [`ratatui::init`] / `init_with_options` because they
//! install a global panic hook, which conflicts with our `panic = abort` /
//! clippy-panic-free posture; instead we drive an explicit `Terminal` over a
//! `CrosstermBackend`. The one-shot render reads no input, so no raw mode is
//! needed. [`draw_splash`] is a pure function over a [`Buffer`] so it is unit
//! testable (render into a fixed buffer and assert cells).

use std::io;

use ratatui::backend::CrosstermBackend;
use ratatui::buffer::Buffer;
use ratatui::layout::{Constraint, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Paragraph, Widget};
use ratatui::{Terminal, TerminalOptions, Viewport};

use crate::grammar;

/// Total splash height (rows) reserved above the inline viewport.
const SPLASH_HEIGHT: u16 = 28;
/// Banner block height (5 letter rows + 1 tagline).
const BANNER_H: u16 = 6;
/// Left sidebar width (columns) inside the bordered body block.
const SIDEBAR_W: u16 = 30;

/// Amber/gold accent (banner + border + emblem), matching the Hermes look.
const GOLD: Color = Color::Rgb(247, 162, 51);
const AMBER: Color = Color::Rgb(214, 109, 28);

/// `SINABRO` as a 5-row block font (one `[row;5]` per letter). Assembled at draw
/// time by joining each letter's row with a single space, so the wordmark is one
/// edit-point (no hand-aligned multi-row string to drift).
const BANNER_LETTERS: [[&str; 5]; 7] = [
    ["█████", "█    ", "█████", "    █", "█████"], // S
    ["█████", "  █  ", "  █  ", "  █  ", "█████"], // I
    ["█   █", "██  █", "█ █ █", "█  ██", "█   █"], // N
    ["█████", "█   █", "█████", "█   █", "█   █"], // A
    ["████ ", "█   █", "████ ", "█   █", "████ "], // B
    ["████ ", "█   █", "████ ", "█  █ ", "█   █"], // R
    ["█████", "█   █", "█   █", "█   █", "█████"], // O
];

/// The closed grammar grouped into labelled categories for the splash grid
/// (Hermes-style `category: a, b, c`). The names are the canonical namespace
/// names; a unit test pins every [`grammar::ALL`] name to exactly one group
/// (rename / add / remove ⇒ test fails), so this is a presentation grouping, not
/// a second truth source.
const CMD_GROUPS: &[(&str, &[&str])] = &[
    (
        "agent",
        &["agent", "task", "session", "context", "checkpoint"],
    ),
    ("model", &["provider", "model", "gas"]),
    ("memory", &["memory", "dataset", "trace"]),
    ("skills", &["skill", "registry", "tool", "sandbox"]),
    (
        "chain",
        &["wallet", "identity", "key", "chain", "package", "multisig"],
    ),
    (
        "audit",
        &[
            "audit",
            "approval",
            "privacy",
            "permission",
            "measure",
            "eval",
        ],
    ),
    (
        "ops",
        &[
            "platform",
            "release",
            "federation",
            "admin",
            "feature",
            "learning",
            "train",
            "notify",
        ],
    ),
];

/// Render the startup splash once into the terminal scrollback. Drops the
/// terminal on return so the reedline chat loop owns the screen afterwards.
///
/// # Errors
/// Propagates an [`io::Error`] from the crossterm backend (e.g. a failed write
/// to stdout). There is no panic / unwrap path.
pub fn render() -> io::Result<()> {
    let backend = CrosstermBackend::new(io::stdout());
    let mut terminal = Terminal::with_options(
        backend,
        TerminalOptions {
            viewport: Viewport::Inline(1),
        },
    )?;
    terminal.insert_before(SPLASH_HEIGHT, draw_splash)?;
    // `terminal` drops here: the inline viewport is released and the splash stays
    // in scrollback above the chat prompt.
    Ok(())
}

/// Draw the splash into `buf` (pure; no I/O): block banner, a bordered body
/// (version header + emblem sidebar + capability grid), a welcome line, and a
/// bottom status bar. Kept pure so a unit test can render into a fixed [`Buffer`].
pub fn draw_splash(buf: &mut Buffer) {
    let [banner_area, body_area, welcome_area, status_area] = Layout::vertical([
        Constraint::Length(BANNER_H),
        Constraint::Min(0),
        Constraint::Length(2),
        Constraint::Length(1),
    ])
    .areas(buf.area);

    banner().render(banner_area, buf);

    let block = Block::new()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(AMBER))
        .title(Line::from(Span::styled(
            " sinabro · local-first audit cockpit ",
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        )));
    let inner = block.inner(body_area);
    block.render(body_area, buf);
    let [ver_area, cols_area] =
        Layout::vertical([Constraint::Length(2), Constraint::Min(0)]).areas(inner);
    version_header().render(ver_area, buf);
    let [left, right] =
        Layout::horizontal([Constraint::Length(SIDEBAR_W), Constraint::Min(0)]).areas(cols_area);
    sidebar(left).render(left, buf);
    capabilities(right).render(right, buf);

    welcome().render(welcome_area, buf);
    status_bar().render(status_area, buf);
}

/// The `SINABRO` block banner with a top→bottom yellow→orange gradient, plus a
/// tagline. The wordmark is assembled by joining [`BANNER_LETTERS`].
fn banner() -> Paragraph<'static> {
    let grad = [
        Color::Rgb(255, 214, 92),
        Color::Rgb(252, 191, 73),
        Color::Rgb(247, 162, 51),
        Color::Rgb(234, 133, 36),
        Color::Rgb(214, 109, 28),
    ];
    let mut lines: Vec<Line<'static>> = Vec::with_capacity(BANNER_H as usize);
    for row in 0..5usize {
        let text = BANNER_LETTERS
            .iter()
            .map(|letter| letter[row])
            .collect::<Vec<_>>()
            .join(" ");
        lines.push(Line::from(Span::styled(
            text,
            Style::default().fg(grad[row]).add_modifier(Modifier::BOLD),
        )));
    }
    lines.push(Line::from(Span::styled(
        "the living madness-agent",
        Style::default().fg(Color::DarkGray),
    )));
    Paragraph::new(lines)
}

/// The version / build header line at the top of the body box (Hermes-style
/// `name vX · stage · posture`).
fn version_header() -> Paragraph<'static> {
    Paragraph::new(vec![
        Line::from(vec![
            Span::styled(
                "sinabro",
                Style::default().fg(GOLD).add_modifier(Modifier::BOLD),
            ),
            Span::styled(
                concat!(" v", env!("CARGO_PKG_VERSION")),
                Style::default().fg(Color::Gray),
            ),
            Span::styled(
                "  ·  stage-G  ·  phase-0  ·  funds LOCKED  ·  egress 0",
                Style::default().fg(Color::DarkGray),
            ),
        ]),
        Line::from(""),
    ])
}

/// The left sidebar: a staff/caduceus-style emblem + a compact identity block
/// (model · workspace · session · posture), echoing Hermes' left column.
fn sidebar(_area: Rect) -> Paragraph<'static> {
    let emblem = Style::default().fg(GOLD).add_modifier(Modifier::BOLD);
    let dim = Style::default().fg(Color::DarkGray);
    let key = Style::default().fg(Color::Gray);
    let lock = Style::default()
        .fg(Color::Yellow)
        .add_modifier(Modifier::BOLD);
    let lines = vec![
        Line::from(Span::styled("        ◆", emblem)),
        Line::from(Span::styled("     ╲  ┃  ╱", emblem)),
        Line::from(Span::styled("    ◆══╪══◆", emblem)),
        Line::from(Span::styled("     ╱  ┃  ╲", emblem)),
        Line::from(Span::styled("        ┃", emblem)),
        Line::from(Span::styled("       ◆┃◆", emblem)),
        Line::from(Span::styled("        ┃", emblem)),
        Line::from(Span::styled("        ▼", emblem)),
        Line::from(""),
        Line::from(vec![
            Span::styled("model    ", key),
            Span::styled("unknown · offline", dim),
        ]),
        Line::from(vec![
            Span::styled("worktree ", key),
            Span::styled("local-only", dim),
        ]),
        Line::from(vec![
            Span::styled("session  ", key),
            Span::styled("phase-0", dim),
        ]),
        Line::from(vec![
            Span::styled("funds    ", key),
            Span::styled("LOCKED", lock),
        ]),
    ];
    Paragraph::new(lines)
}

/// The right capability grid: two sections (Commands / Skills) of left-aligned
/// `category: members` rows, then a footer. The command set is [`grammar::ALL`]
/// via [`CMD_GROUPS`] (pinned by test); the count is [`grammar::COUNT`].
fn capabilities(_area: Rect) -> Paragraph<'static> {
    let head = Style::default().fg(GOLD).add_modifier(Modifier::BOLD);
    let label = Style::default().fg(Color::DarkGray);
    let member = Style::default().fg(Color::Gray);
    let dim = Style::default().fg(Color::DarkGray);
    let mut lines = vec![Line::from(Span::styled("Available Commands", head))];
    for (cat, names) in CMD_GROUPS {
        lines.push(Line::from(vec![
            Span::styled(format!("{cat}: "), label),
            Span::styled(names.join(", "), member),
        ]));
    }
    lines.push(Line::from(""));
    lines.push(Line::from(Span::styled("Available Skills", head)));
    lines.push(Line::from(Span::styled(
        "(none enabled · sandbox-bound · try-before-use · phase-0)",
        dim,
    )));
    lines.push(Line::from(""));
    lines.push(Line::from(Span::styled(
        format!(
            "{} commands · 0 skills · /help for commands",
            grammar::COUNT
        ),
        dim,
    )));
    Paragraph::new(lines)
}

/// The welcome line + a tip, below the body box (Hermes-style).
fn welcome() -> Paragraph<'static> {
    Paragraph::new(vec![
        Line::from(Span::styled(
            "Welcome to sinabro! Type a command, /slash, or 'setup'.",
            Style::default()
                .fg(Color::White)
                .add_modifier(Modifier::BOLD),
        )),
        Line::from(Span::styled(
            "✦ Tip: every line is classified through a CommandEnvelope — no bypass; funds LOCKED.",
            Style::default().fg(Color::DarkGray),
        )),
    ])
}

/// The bottom status bar: model · context · a budget bar · funds posture, with
/// dim separators (Hermes-style bottom strip).
fn status_bar() -> Paragraph<'static> {
    let brand = Style::default()
        .fg(Color::Cyan)
        .add_modifier(Modifier::BOLD);
    let sep = Style::default().fg(Color::DarkGray);
    let val = Style::default().fg(Color::Gray);
    let bar = Style::default().fg(Color::Green);
    let lock = Style::default()
        .fg(Color::Yellow)
        .add_modifier(Modifier::BOLD);
    Paragraph::new(Line::from(vec![
        Span::styled("▌ sinabro", brand),
        Span::styled("  │  ", sep),
        Span::styled("model:unknown", val),
        Span::styled("  │  ", sep),
        Span::styled("ctx:0%", val),
        Span::styled("  │  ", sep),
        Span::styled("[░░░░░░░░░░]", bar),
        Span::styled("  │  ", sep),
        Span::styled("funds:LOCKED", lock),
    ]))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Concatenate every cell symbol of `buf`, row by row, into one string for
    /// glyph assertions (the splash has no public text accessor).
    fn dump(buf: &Buffer) -> String {
        buf.content
            .iter()
            .map(ratatui::buffer::Cell::symbol)
            .collect()
    }

    #[test]
    fn splash_draws_banner_sections_and_chrome() {
        let mut buf = Buffer::empty(Rect::new(0, 0, 110, SPLASH_HEIGHT));
        draw_splash(&mut buf);
        let s = dump(&buf);
        assert!(s.contains('█'), "banner block glyph: {s}");
        assert!(s.contains("sinabro"), "{s}");
        assert!(s.contains("Available Commands"), "{s}");
        assert!(s.contains("Available Skills"), "{s}");
        assert!(s.contains("provider"), "namespace in grid: {s}");
        assert!(s.contains("LOCKED"), "funds posture: {s}");
        assert!(s.contains("Welcome"), "welcome line: {s}");
        assert!(s.contains("/help"), "footer: {s}");
        assert!(s.contains('┌'), "border: {s}");
    }

    #[test]
    fn banner_assembles_seven_letters_per_row() {
        for row in 0..5usize {
            let text = BANNER_LETTERS
                .iter()
                .map(|l| l[row])
                .collect::<Vec<_>>()
                .join(" ");
            assert_eq!(text.chars().count(), 41, "row {row}: {text}");
        }
    }

    #[test]
    fn command_groups_pin_every_namespace_exactly_once() {
        // Presentation grouping pinned to the closed grammar: every namespace in
        // exactly one group, groups cover the whole set (drift tripwire).
        let mut seen = std::collections::BTreeSet::new();
        for (_, names) in CMD_GROUPS {
            for n in *names {
                assert!(seen.insert(*n), "namespace {n} appears in two groups");
            }
        }
        assert_eq!(seen.len(), grammar::COUNT, "group coverage != COUNT");
        for ns in grammar::ALL {
            assert!(
                seen.contains(ns.canonical_name()),
                "{} is in no splash group",
                ns.canonical_name()
            );
        }
    }
}
