//! Interactive TUI cockpit loop (atoms #570-#572, #578-#585, #589-#592).
//!
//! `sinabro tui` runs a REAL terminal event loop — not a one-shot snapshot. It
//! reads input events, drives the already-tested pure projections
//! ([`CockpitShell`] lifecycle, [`TabRouter`] 14-tab nav, and the
//! status/job-rail/trace/inspector/provider/gas/platform/jobs/skill/approval
//! panes), and redraws a bounded frame until quit, restoring the terminal on
//! every exit path.
//!
//! Offline std-first core (this session, zero new runtime dependency): raw
//! single-keypress input via the isolated [`crate::tui::raw`] termios guard (the
//! crate's only `unsafe`), an alt-screen + RAII restore, a fixed stack read
//! buffer, and a reused frame string — no heap allocation on the steady-state
//! redraw hot path (the dirty-only redraw recomputes pane content only on a tab /
//! view change). The `tui-rich` feature (crossterm/ratatui) is a deps-gated
//! upgrade documented in `Cargo.toml`; the std core is the always-available
//! fallback and is what these atoms ship.
//!
//! Live boundary: the loop renders only. Every namespace surface is produced by
//! [`crate::dispatch::run`], which classifies through [`CommandEnvelope`] and
//! never executes a side effect in Phase 0 (wallet/chain/train stay approval-
//! gated and disabled). Zero egress, zero model dependency, funds LOCKED.

use std::io::{self, IsTerminal, Read, Write};

use crate::command::{CliMode, CommandEnvelope, CommandRisk};
use crate::commands::platform_telegram::NotificationCenter;
use crate::grammar::CliNamespace;
use crate::repl::prompt::{PromptStatus, render_status_strip};
use crate::route::RouteExecutionState;
use crate::tui::approval_modal::ApprovalModal;
use crate::tui::gas_tab::{ALL_DRAIN_GATES, DrainGateRow, DrainGateStatus, GasDrainDashboard};
use crate::tui::inspector::{EvidenceHint, HintTier, InspectTarget, InspectorView};
use crate::tui::job_rail::JobRail;
use crate::tui::jobs_tab::JobsDashboard;
use crate::tui::platform_tab::PlatformStatusTab;
use crate::tui::provider_tab::ProviderHealthTab;
use crate::tui::skill_cards::SkillCardList;
use crate::tui::skill_use_modal::{SkillUseModal, SkillUseView};
use crate::tui::status_bar::StatusBar;
use crate::tui::tabs::{ALL_TABS, CockpitTab, TAB_COUNT, TabRouter};
use crate::tui::trace_pane::TraceSourceKind;
use crate::tui::{CockpitShell, RenderTruth, ShellPhase};
use crate::ui::trace_pane::{PagedPane, PaneFilter};
use crate::{StageFEvidenceRef, StageFTraceLink, sha256_32};

/// Bounded center-pane row ceiling (the hot path never renders more).
const CENTER_ROWS: usize = 32;
/// Column clamp (no line overlaps the next column; terminal-compat law). This
/// governs ONLY the Plain path ([`clamp80`]); the rich path sizes to the live
/// terminal width (see [`term_cols`] / [`rich_inner_cap`]).
const MAX_COLS: usize = 80;
/// Default assumed terminal width for the rich path when the real size is
/// unavailable (non-TTY / FFI error). Distinct from [`MAX_COLS`] (the Plain clamp).
const FALLBACK_COLS: usize = 80;
/// Per-row box chrome overhead: the `│ ` left gutter (2) + ` │` right gutter (2).
const BOX_OVERHEAD: usize = 4;
/// Lower bound on the rich box inner width, so a pathologically narrow terminal can
/// never drive the inner width to zero (which would make wrapping chunk on an empty
/// step) or invert the saturating subtraction.
const MIN_RICH_INNER: usize = 16;
/// Fixed stack read buffer size (zero per-keystroke heap allocation).
const READ_BUF: usize = 16;

/// How a frame is serialized. `Plain` is pure ASCII with zero escape sequences
/// (used for headless / piped / snapshot output and the falsifiability checker);
/// `Ansi` adds cursor-control only (`\x1b[H` / `\x1b[K` / `\x1b[J`) for in-place
/// redraw — never SGR color (the no-color-readable law).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum RenderMode {
    Ansi,
    Plain,
}

/// The active center view: one of the 14 grammar tabs, or a dedicated dashboard.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum CockpitView {
    Tab,
    Gas,
    Jobs,
    Skills,
    Provider,
    Platform,
    Approval,
    Inspector,
    Audit,
    Detectors,
    Bundle,
    Memory,
    MemoryIntel,
    Evidence,
    EvidenceReplay,
    SkillLive,
    SkillPackage,
    DatasetLive,
    EvalLive,
    DaemonLive,
    SyncLive,
    ControlLive,
    CheckpointLive,
    MultisigLive,
    SafetyKernelLive,
    CapabilityLive,
    WalletLive,
    FindingLive,
    TenLive,
}

/// One decoded input event.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum CockpitEvent {
    Quit,
    Tab(TabNav),
    View(CockpitView),
    Ignore,
}

/// A tab-navigation event.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum TabNav {
    Next,
    Prev,
    Select(usize),
}

/// The summary of one interactive session (returned for tests / the checker).
/// Fields are read by the inline tests and the headless checker harness.
#[allow(dead_code)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct TuiSummary {
    /// Frames actually drawn (proves the loop ran, not a one-shot snapshot).
    frames_drawn: u32,
    /// The final selected tab index.
    final_tab_index: usize,
    /// Whether the shell closed cleanly (terminal restored).
    quit_clean: bool,
}

/// Decode one input byte into a [`CockpitEvent`]. Total + `const`: an unrecognised
/// byte is an explicit no-op (`Ignore`), never a panic. The std core handles
/// single-byte keys; multi-byte escape (arrow) sequences map to `Ignore` (the
/// `tui-rich` crossterm layer decodes them fully).
const fn decode_key(b: u8) -> CockpitEvent {
    match b {
        // q / Ctrl-C / Ctrl-D all quit (raw mode delivers them as bytes).
        b'q' | 0x03 | 0x04 => CockpitEvent::Quit,
        // Tab / n -> next tab; p -> prev tab.
        b'\t' | b'n' => CockpitEvent::Tab(TabNav::Next),
        b'p' => CockpitEvent::Tab(TabNav::Prev),
        // 1..9 -> select tab 0..8.
        b'1'..=b'9' => CockpitEvent::Tab(TabNav::Select((b - b'1') as usize)),
        // dedicated dashboards.
        b'g' => CockpitEvent::View(CockpitView::Gas),
        b'j' => CockpitEvent::View(CockpitView::Jobs),
        b'k' => CockpitEvent::View(CockpitView::Skills),
        b'v' => CockpitEvent::View(CockpitView::Provider),
        b'm' => CockpitEvent::View(CockpitView::Platform),
        b'a' => CockpitEvent::View(CockpitView::Approval),
        b'i' => CockpitEvent::View(CockpitView::Inspector),
        b't' => CockpitEvent::View(CockpitView::Tab),
        // #624 — the live audit game tree (candidate != finding).
        b'd' => CockpitEvent::View(CockpitView::Audit),
        // #625 — the live detector surface (static/solana/sui-move; defensive).
        b'f' => CockpitEvent::View(CockpitView::Detectors),
        // #626 — the live audit evidence bundle + defended-invariant memory.
        b'b' => CockpitEvent::View(CockpitView::Bundle),
        // #627 — the live memory commands surface (tombstone no-resurrection).
        b'r' => CockpitEvent::View(CockpitView::Memory),
        // #628 — the live memory intel (compactor / importance / user-model).
        b'c' => CockpitEvent::View(CockpitView::MemoryIntel),
        // #629 — the live evidence pack (hash-linked manifest; secret-zero).
        b'e' => CockpitEvent::View(CockpitView::Evidence),
        // #630 — the live evidence replay (offline deterministic; no side effect).
        b'l' => CockpitEvent::View(CockpitView::EvidenceReplay),
        // #631 — the live skill discovery/use/state (security-first; sandbox-bound).
        b's' => CockpitEvent::View(CockpitView::SkillLive),
        // #632 — the live skill package / provenance (trust receipt gated).
        b'h' => CockpitEvent::View(CockpitView::SkillPackage),
        // #633 — the live dataset ingest/export (locked-shard immutable; PII-0; no upload).
        b'o' => CockpitEvent::View(CockpitView::DatasetLive),
        // #634 — the live trace-pair + eval (S1-only reward; candidate!=finding; safe wording).
        b'u' => CockpitEvent::View(CockpitView::EvalLive),
        // #635 — the live daemon supervisor + inbox + reconnect (no secret; killable).
        b'w' => CockpitEvent::View(CockpitView::DaemonLive),
        // #637 — the live CLI/TG MessageEnvelope equality (channel parity; divergence=red).
        b'x' => CockpitEvent::View(CockpitView::SyncLive),
        // #638 — the live control-express under load (preallocated lane; halts only).
        b'y' => CockpitEvent::View(CockpitView::ControlLive),
        // #640 — the live checkpoint + restore + rollback/undo (auto-checkpoint before risk).
        b'z' => CockpitEvent::View(CockpitView::CheckpointLive),
        // #641 — the live multisig/chain/gas status (funds LOCKED; UPPERCASE key, 'm' is Platform).
        b'M' => CockpitEvent::View(CockpitView::MultisigLive),
        // #642 — the live safety-kernel feature lock (10 non-disableable; UPPERCASE 'K').
        b'K' => CockpitEvent::View(CockpitView::SafetyKernelLive),
        // #643 — the live capability diff + sandbox tier + tool bridge (UPPERCASE 'P').
        b'P' => CockpitEvent::View(CockpitView::CapabilityLive),
        // #645 — the live wallet/key/gas status (funds LOCKED; sign preview-only; UPPERCASE 'L').
        b'L' => CockpitEvent::View(CockpitView::WalletLive),
        // #646 — the live candidate!=finding + no-authority-expansion (UPPERCASE 'F').
        b'F' => CockpitEvent::View(CockpitView::FindingLive),
        // #647 — the live §10 designed-impossibility summary (UPPERCASE 'T' = Ten).
        b'T' => CockpitEvent::View(CockpitView::TenLive),
        _ => CockpitEvent::Ignore,
    }
}

/// Strip non-printable / non-ASCII bytes and clamp to [`MAX_COLS`] columns.
fn clamp80(line: &str) -> String {
    line.chars()
        .filter(|c| c.is_ascii() && !c.is_ascii_control())
        .take(MAX_COLS)
        .collect()
}

/// Number of fixed chrome (header) lines at the top of the cached line set — the
/// rich renderer draws a separator after them and before the footer.
const CHROME_LINES: usize = 5;

/// ANSI SGR palette for the rich (real-TTY) cockpit. `RenderMode::Plain` never
/// emits any of these — the colorless headless / snapshot frame is unchanged.
mod sgr {
    pub const RST: &str = "\x1b[0m";
    pub const DIM: &str = "\x1b[2m";
    pub const GRN: &str = "\x1b[32m";
    pub const YEL: &str = "\x1b[33m";
    pub const RED: &str = "\x1b[31m";
    pub const CYN: &str = "\x1b[36m";
    /// Reverse video — the active tab highlight (slice e-2). Like the colors it is
    /// width-neutral (an SGR toggle only), so the box stays rectangular.
    pub const REV: &str = "\x1b[7m";
}

/// Append a box-drawing border row of `inner`+2 width (`┌──┐` / `├──┤` / `└──┘`).
fn rich_border(frame: &mut String, left: char, right: char, inner: usize) {
    frame.push_str(sgr::DIM);
    frame.push(left);
    for _ in 0..inner + 2 {
        frame.push('─');
    }
    frame.push(right);
    frame.push_str(sgr::RST);
    frame.push_str("\r\n");
}

/// Status keywords painted by the rich colorizer, each as `(word, sgr-color)`. Every
/// entry is matched only as a WHOLE WORD (the byte on each side is not ASCII
/// alphanumeric), so `RED` paints the truth label but never the `RED` inside
/// `REDACTED`, and `LOCKED` paints `funds=LOCKED` (the `=` is a boundary) but never
/// `UNLOCKED`. `LOCAL-ONLY` is one entry (its inner `-` is part of the literal).
const COLOR_KEYWORDS: &[(&str, &str)] = &[
    ("PASS", sgr::GRN),
    ("DEGRADED", sgr::YEL),
    ("LOCKED", sgr::YEL),
    ("UNKNOWN", sgr::DIM),
    ("RED", sgr::RED),
    ("LOCAL-ONLY", sgr::CYN),
];

/// A byte that can be part of a word, so an adjacent keyword match is NOT a whole
/// word. Letters + digits only; space / punctuation / `=` / `-` are boundaries.
fn is_word_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric()
}

/// Highlight status keywords with SGR color, matching each only as a WHOLE WORD so
/// `RED` never paints `REDACTED` (the documented hazard) and `LOCKED` paints
/// `funds=LOCKED` but not `UNLOCKED`. Only escape sequences are inserted, so the
/// visible width is unchanged and the caller's padding stays correct.
fn rich_colorize(frame: &mut String, line: &str) {
    let bytes = line.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        let prev_is_word = i > 0 && is_word_byte(bytes[i - 1]);
        let mut painted = false;
        if !prev_is_word {
            for &(kw, color) in COLOR_KEYWORDS {
                let end = i + kw.len();
                if end <= bytes.len()
                    && &bytes[i..end] == kw.as_bytes()
                    && (end == bytes.len() || !is_word_byte(bytes[end]))
                {
                    frame.push_str(color);
                    frame.push_str(kw);
                    frame.push_str(sgr::RST);
                    i = end;
                    painted = true;
                    break;
                }
            }
        }
        if !painted {
            let ch = line[i..].chars().next().unwrap_or('\u{fffd}');
            frame.push(ch);
            i += ch.len_utf8();
        }
    }
}

/// How one boxed content row is colorized. The cockpit's `self.lines` are stored
/// SGR-free (the Plain path emits them byte-identically), so ALL coloring happens
/// here in the rich (Ansi) path only — putting any of this into `chrome_lines` /
/// `tab_bar` / `footer_line` would leak escapes into the Plain frame (G-WP-10).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum RowPaint {
    /// Body / banner rows: whole-word status-keyword coloring ([`rich_colorize`]).
    Keyword,
    /// The footer key row: every `[x]` hot-key bracket painted cyan.
    FooterKeys,
    /// The tab-bar row: the active tab's `[Name]` bracket painted reverse-video.
    TabBar,
}

/// Wrap each `[…]` bracket segment of `line` in `color` … `RST`, emitting everything
/// else verbatim. Drives the footer hot-keys (cyan) and the active tab (reverse). Like
/// [`rich_colorize`] it inserts ONLY escape sequences, so the visible width is
/// unchanged (the box stays rectangular). A `[` with no following `]` — e.g. a bracket
/// split across a wrap boundary — is emitted verbatim, never half-colored, so a folded
/// row's width never drifts. Byte-scan is UTF-8 safe: `[`/`]` are ASCII, so they never
/// appear inside a multi-byte codepoint, and the inclusive slice splits on boundaries.
fn rich_colorize_brackets(frame: &mut String, line: &str, color: &str) {
    let bytes = line.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'[' {
            if let Some(rel) = bytes[i + 1..].iter().position(|&b| b == b']') {
                let close = i + 1 + rel;
                frame.push_str(color);
                frame.push_str(&line[i..=close]);
                frame.push_str(sgr::RST);
                i = close + 1;
                continue;
            }
        }
        let ch = line[i..].chars().next().unwrap_or('\u{fffd}');
        frame.push(ch);
        i += ch.len_utf8();
    }
}

/// Append one boxed content row: `│ <colorized per `paint`, padded to inner> │` + CRLF.
fn rich_row(frame: &mut String, line: &str, inner: usize, paint: RowPaint) {
    let visible = line.chars().count();
    frame.push_str(sgr::DIM);
    frame.push('│');
    frame.push_str(sgr::RST);
    frame.push(' ');
    match paint {
        RowPaint::Keyword => rich_colorize(frame, line),
        RowPaint::FooterKeys => rich_colorize_brackets(frame, line, sgr::CYN),
        RowPaint::TabBar => rich_colorize_brackets(frame, line, sgr::REV),
    }
    for _ in visible..inner {
        frame.push(' ');
    }
    frame.push(' ');
    frame.push_str(sgr::DIM);
    frame.push('│');
    frame.push_str(sgr::RST);
    frame.push_str("\r\n");
}

/// The rich box inner-content width cap for a terminal of `cols` columns: the
/// terminal width minus the box chrome ([`BOX_OVERHEAD`]), floored at
/// [`MIN_RICH_INNER`]. The actual inner width is `min(widest_line, this)`, so the
/// box never exceeds the terminal and any wider line is wrapped to fit.
fn rich_inner_cap(cols: usize) -> usize {
    cols.saturating_sub(BOX_OVERHEAD).max(MIN_RICH_INNER)
}

/// Fold `line` into chunks of at most `inner` characters (lossless wrap) so a row
/// never overflows the box right edge. An empty line yields one empty chunk (it
/// still draws as one blank row, matching the pre-wrap one-row-per-line shape).
/// Splitting is by `char`, never mid-codepoint; the step is floored at 1 so a
/// zero `inner` can never panic [`slice::chunks`].
fn rich_wrap(line: &str, inner: usize) -> Vec<String> {
    let chars: Vec<char> = line.chars().collect();
    if chars.is_empty() {
        return vec![String::new()];
    }
    chars
        .chunks(inner.max(1))
        .map(|chunk| chunk.iter().collect::<String>())
        .collect()
}

/// The live terminal width in columns for the rich path, or [`FALLBACK_COLS`] when
/// the size is unavailable (non-TTY / FFI error). The Plain path is unaffected (it
/// always clamps to [`MAX_COLS`]).
pub(crate) fn term_cols() -> usize {
    crate::tui::raw::term_size()
        .map(|(cols, _rows)| cols as usize)
        .unwrap_or(FALLBACK_COLS)
}

/// Serialize the cached lines as a rich cockpit frame: a Unicode box sized to the
/// live terminal width `cols` (lines wider than the inner width are wrapped, never
/// overflowing the right edge), with a header/body/footer separator, SGR-highlighted
/// keywords, and CRLF line endings — so a raw-mode terminal with `OPOST` off does
/// NOT stair-step (the prior bug). `\x1b[H\x1b[2J` homes + clears for an in-place
/// redraw.
fn render_rich_frame(frame: &mut String, lines: &[String], cols: usize) {
    let cap = rich_inner_cap(cols);
    let inner = lines
        .iter()
        .map(|l| l.chars().count())
        .max()
        .unwrap_or(0)
        .min(cap);
    frame.push_str("\x1b[H\x1b[2J");
    rich_border(frame, '┌', '┐', inner);
    let n = lines.len();
    for (i, line) in lines.iter().enumerate() {
        if i == CHROME_LINES && n > CHROME_LINES + 1 {
            rich_border(frame, '├', '┤', inner);
        }
        if i + 1 == n && n > 1 {
            rich_border(frame, '├', '┤', inner);
        }
        // Per-row paint by ORIGINAL line role, computed BEFORE wrapping so every
        // folded row of one source line shares it: the last line is the footer
        // hot-keys (cyan brackets), a chrome `tabs:` line is the tab bar
        // (reverse-video active tab), everything else is keyword-colored.
        let paint = if i + 1 == n {
            RowPaint::FooterKeys
        } else if i < CHROME_LINES && line.starts_with("tabs:") {
            RowPaint::TabBar
        } else {
            RowPaint::Keyword
        };
        for row in rich_wrap(line, inner) {
            rich_row(frame, &row, inner, paint);
        }
    }
    rich_border(frame, '└', '┘', inner);
}

/// Append a complete simple rich box around `lines`: inner width = the widest line,
/// capped to fit a terminal of `cols` columns ([`rich_inner_cap`]) with wider lines
/// wrapped, a top border, one SGR-colorized row per (wrapped) line, and a bottom
/// border. Unlike [`render_rich_frame`] there is no chrome/footer separator and no
/// home/clear escape — this is the plain "card" the cooked-TTY REPL reuses for its
/// greeting banner and per-command response, sharing the exact same border/row
/// primitives so the dashboard and the repl render one rich look.
pub(crate) fn rich_box(frame: &mut String, lines: &[String], cols: usize) {
    let cap = rich_inner_cap(cols);
    let inner = lines
        .iter()
        .map(|l| l.chars().count())
        .max()
        .unwrap_or(0)
        .min(cap);
    rich_border(frame, '┌', '┐', inner);
    for line in lines {
        // The cooked-TTY REPL card has no tab bar / footer, so every row is
        // keyword-colored (the tab-reverse / footer-cyan roles are cockpit-only).
        for row in rich_wrap(line, inner) {
            rich_row(frame, &row, inner, RowPaint::Keyword);
        }
    }
    rich_border(frame, '└', '┘', inner);
}

const fn truth_label(t: RenderTruth) -> &'static str {
    match t {
        RenderTruth::Green => "PASS",
        RenderTruth::Yellow => "DEGRADED",
        RenderTruth::Red => "RED",
        RenderTruth::Unknown => "UNKNOWN",
    }
}

const fn phase_label(p: ShellPhase) -> &'static str {
    match p {
        ShellPhase::Booting => "booting",
        ShellPhase::Active => "active",
        ShellPhase::Quitting => "quitting",
        ShellPhase::Closed => "closed",
    }
}

const fn view_label(v: CockpitView) -> &'static str {
    match v {
        CockpitView::Tab => "tab",
        CockpitView::Gas => "gas-drain",
        CockpitView::Jobs => "jobs",
        CockpitView::Skills => "skills",
        CockpitView::Provider => "provider-health",
        CockpitView::Platform => "platform",
        CockpitView::Approval => "approval",
        CockpitView::Inspector => "inspector",
        CockpitView::Audit => "audit-game-tree",
        CockpitView::Detectors => "audit-detectors",
        CockpitView::Bundle => "audit-bundle",
        CockpitView::Memory => "memory-commands",
        CockpitView::MemoryIntel => "memory-intel",
        CockpitView::Evidence => "evidence-pack",
        CockpitView::EvidenceReplay => "evidence-replay",
        CockpitView::SkillLive => "skill-live",
        CockpitView::SkillPackage => "skill-package",
        CockpitView::DatasetLive => "dataset-live",
        CockpitView::EvalLive => "eval-live",
        CockpitView::DaemonLive => "daemon-live",
        CockpitView::SyncLive => "sync-live",
        CockpitView::ControlLive => "control-live",
        CockpitView::CheckpointLive => "checkpoint-live",
        CockpitView::MultisigLive => "multisig-live",
        CockpitView::SafetyKernelLive => "safety-kernel-live",
        CockpitView::CapabilityLive => "capability-live",
        CockpitView::WalletLive => "wallet-live",
        CockpitView::FindingLive => "finding-live",
        CockpitView::TenLive => "section10-live",
    }
}

/// A demo prompt-status strip (no live state; workspace hash only).
fn demo_prompt() -> PromptStatus {
    PromptStatus {
        workspace_hash_32: sha256_32(b"/Users/heoun/mnemos"),
        model_hash_32: [0u8; 32],
        context_pressure_bps: 0,
        last_checkpoint_hash_32: [0u8; 32],
        budget_remaining_micros: 1_000_000,
        sandbox_tier_u8: 1,
        pending_approvals_u16: 0,
        pending_tasks_u16: 0,
    }
}

fn demo_trace(atom: u16) -> StageFTraceLink {
    StageFTraceLink::new(sha256_32(b"sinabro-cockpit-trace"), atom, 1)
}

fn tab_bar(router: &TabRouter) -> String {
    let sel = router.selected_index() % TAB_COUNT;
    let mut s = String::from("tabs:");
    for (i, tab) in ALL_TABS.iter().enumerate() {
        let name = format!("{tab:?}");
        if i == sel {
            s.push_str(" [");
            s.push_str(&name);
            s.push(']');
        } else {
            s.push(' ');
            s.push_str(&name);
        }
    }
    s
}

/// Render one namespace tab's center via the canonical [`crate::dispatch::run`]
/// (the SAME surface the CLI shows; no side effect runs). Output is captured into
/// an in-memory buffer and split into clamped lines.
fn namespace_center(tab: CockpitTab) -> Vec<String> {
    let argv = [tab.namespace().canonical_name().to_string()];
    let mut out: Vec<u8> = Vec::new();
    let mut err: Vec<u8> = Vec::new();
    // dispatch::run renders the namespace status / approval-locked surface only.
    let _ = crate::dispatch::run(&argv, &mut out, &mut err);
    String::from_utf8_lossy(&out).lines().map(clamp80).collect()
}

/// The Trace tab routes through the paged trace pane (#580): the trace surface is
/// ingested as a bounded, folded, redacted, paged view (full-render denied).
fn trace_pane_lines() -> Vec<String> {
    let mut out: Vec<u8> = Vec::new();
    let mut err: Vec<u8> = Vec::new();
    let _ = crate::dispatch::run(&["trace".to_string()], &mut out, &mut err);
    let raw = String::from_utf8_lossy(&out);
    let pane = PagedPane::from_trace(TraceSourceKind::Plain, &raw, 16, PaneFilter::All);
    let mut lines = vec![format!(
        "trace pane: pages={} full_render_denied={} replay_link={}",
        pane.page_count(),
        PagedPane::full_render_denied(),
        crate::hex32(&pane.raw_replay_link()).get(..8).unwrap_or("")
    )];
    lines.extend(pane.render(16));
    lines
}

/// #582 gas-drain dashboard: the seven §7.5 drain-gate invariants, all holding.
fn gas_drain_lines() -> Vec<String> {
    let mut dash = GasDrainDashboard::new();
    for kind in ALL_DRAIN_GATES {
        dash.push(DrainGateRow::new(
            kind,
            DrainGateStatus::Hold,
            "invariant holds: no drain path",
        ));
    }
    let mut lines = vec![
        format!(
            "gas-drain gates: {} all_hold={} refresh_made_no_live_call={}",
            dash.len(),
            dash.all_invariants_hold(),
            dash.refresh_made_no_live_call()
        ),
        "owner is never the sponsor; request is gated (network); LOCKED".to_string(),
    ];
    for (i, row) in dash.rows().iter().enumerate() {
        lines.push(format!(
            "gate[{i}] kind_u8={} truth={}",
            row.kind.tag(),
            truth_label(row.render_truth())
        ));
    }
    lines
}

/// #585 jobs/tasks dashboard: one shared inbox; control-express kill; no zombie.
fn jobs_lines() -> Vec<String> {
    let dash = JobsDashboard::project(&[], 0, false, 1_000_000);
    let mut lines =
        vec!["jobs/tasks: one shared inbox; full export/replay is a background job".to_string()];
    lines.extend(dash.render(CENTER_ROWS as u16));
    lines
}

/// #584 skill cards (security-first) + the skill-use modal (dry-run + confirm).
fn skill_cards_lines() -> Vec<String> {
    let cards = SkillCardList::new();
    let mut lines = vec![format!(
        "skill cards: {} (security-first ranking; quarantine never tops; no-commerce)",
        cards.len()
    )];
    lines.extend(cards.render_compact_page(0, 8, 8));
    if cards.is_empty() {
        lines
            .push("no skills discovered; search/recommend = read-only (gated install)".to_string());
    }
    // The skill-use modal: dry-run-before-install + explicit confirm gate.
    let view = SkillUseView::new(
        sha256_32(b"skill-id"),
        sha256_32(b"package"),
        sha256_32(b"dry-run-trace"),
        [0u8; 32],
        sha256_32(b"trust"),
        true,
    );
    let modal = SkillUseModal::new(view, sha256_32(b"cap-diff"), sha256_32(b"rollback"));
    lines.push(format!(
        "use-modal: can_install={} is_commerce={} (dry-run before install; confirm required)",
        modal.can_install(),
        modal.is_commerce()
    ));
    lines.extend(modal.render(8));
    lines
}

/// #582 provider-health dashboard (refresh makes no live provider call).
fn provider_health_lines() -> Vec<String> {
    let tab = ProviderHealthTab::new();
    vec![
        format!(
            "provider-health: rows={} all_healthy={} refresh_made_no_provider_call={}",
            tab.len(),
            tab.is_all_healthy(),
            tab.refresh_made_no_provider_call()
        ),
        "no providers configured; status / dry-run only; 0 live provider calls".to_string(),
        "local executor default; frontier = reviewer-only; no silent fallback".to_string(),
    ]
}

/// #582 platform tab: shared CLI<->Telegram envelope; zero live sends.
fn platform_lines() -> Vec<String> {
    let center = NotificationCenter::new(16);
    let version = center.sync_state().version_u32;
    let tab = PlatformStatusTab::project(&center, version, &[], None);
    let mut lines = vec![format!(
        "platform: CLI<->Telegram observe one MessageEnvelope; truth={} 0 live sends",
        truth_label(tab.render_truth())
    )];
    lines.extend(tab.render(CENTER_ROWS as u16));
    lines
}

/// #583 approval modal (render-only demo): wallet-sign is typed-phrase gated and
/// the side effect is NOT executed in Phase 0.
fn approval_demo_lines() -> Vec<String> {
    let env = CommandEnvelope::classify(
        CliNamespace::Wallet,
        "sign",
        CliMode::Tui,
        CommandRisk::WalletSign,
        b"preview",
    );
    let modal = ApprovalModal::new(
        env,
        sha256_32(b"capability-diff"),
        0,
        sha256_32(b"rollback-path"),
        demo_trace(583),
        "I APPROVE WALLET SIGN",
    );
    let mut lines = vec![
        "approval modal (render-only): typed-phrase exact-match; bare Enter never approves"
            .to_string(),
        format!(
            "high_risk={} fields_complete={} side effect NOT executed (preview)",
            modal.is_high_risk(),
            modal.has_required_fields()
        ),
    ];
    lines.extend(modal.render(CENTER_ROWS as u16));
    lines
}

/// #581 inspector: an evidence-backed "why" (cannot construct without evidence).
fn inspector_lines() -> Vec<String> {
    let evidence = StageFEvidenceRef {
        path_hash_32: sha256_32(b"evidence-path"),
        trace: demo_trace(581),
    };
    let hint = EvidenceHint {
        tier: HintTier::Cached,
        source_atom_u16: 581,
        evidence_hash_32: sha256_32(b"evidence-artifact"),
        memory_root_32: sha256_32(b"memory-root"),
        expires_at_epoch_ms: 0,
        scope_hash_32: sha256_32(b"scope"),
        redaction_class_u8: 0,
    };
    match InspectorView::new(InspectTarget::Trace, evidence, hint, sha256_32(b"reason")) {
        Some(view) => {
            let mut lines = vec![format!(
                "inspector: target=trace verdict={} (evidence-backed; no bare status)",
                truth_label(view.truth(0))
            )];
            lines.extend(view.render(0, 16));
            lines
        }
        None => vec!["inspector: cannot construct a verdict without an evidence path".to_string()],
    }
}

/// #624 (G.9.0) — the live audit game tree: invariant-graph -> bounded-state-space
/// -> move-generator -> impact-prior -> candidate. A candidate is a tree node
/// only; promotion needs a [`LocalReproRunnerReceipt`] (safe-local + reproduced +
/// node-hash-match) and the cockpit never promotes. The state space is bounded (no
/// production axis); random fuzz / production probe / live tx are all denied. Pure
/// local-only projection — no live action. Reused by `repl::run` so CLI and TUI
/// drive ONE audit pipeline (no second truth source).
pub(crate) fn audit_game_tree_lines() -> Vec<String> {
    use crate::audit::candidate::{AuditGameTreeCandidate, CandidateOrigin};
    use crate::audit::impact_prior::{ImpactPrior, rank_top_k};
    use crate::audit::invariant_graph::{InvariantGraphBuilder, InvariantKind};
    use crate::audit::move_generator::{AuditMove, AuditMoveGenerator, StopCondition};
    use crate::audit::repro_plan::{LocalReproPlan, ReproPlanFlags, ReproPlanInputs};
    use crate::audit::repro_receipt::{LocalReproRunnerReceipt, ReproReceiptHashes};
    use crate::audit::state_space::{AxisCardinalities, StateSpaceBounds};
    use crate::commands::eval_core::AuditCandidate;

    // 1) invariant graph — an audit starts from the invariants that must not break.
    const KINDS: [InvariantKind; 9] = [
        InvariantKind::Solvency,
        InvariantKind::SignerOwner,
        InvariantKind::OracleFreshness,
        InvariantKind::PdaObjectIdentity,
        InvariantKind::ReceiptIntegrity,
        InvariantKind::ReplayDelete,
        InvariantKind::Permission,
        InvariantKind::GasCost,
        InvariantKind::EconomicPnl,
    ];
    let mut graph = InvariantGraphBuilder::new();
    for (i, kind) in KINDS.iter().enumerate() {
        let tag = u8::try_from(i + 1).unwrap_or(1);
        let _ = graph.add(*kind, sha256_32(&[tag, 0x10]), sha256_32(&[tag, 0x20]));
    }
    let g = graph.build();

    // 2) bounded state space — every axis capped; a production axis is forbidden.
    let bounds = StateSpaceBounds::new(16, 6);
    let axes = AxisCardinalities {
        account: 4,
        object: 3,
        oracle: 2,
        cache: 2,
        epoch: 2,
        permission: 3,
        amount: 5,
        price: 3,
        sequence: 2,
        reward: 2,
        collateral: 2,
    };
    let (state_hash_32, all_axes_nonzero) = match bounds.bounded(&axes) {
        Ok(space) => (space.state_hash_32, space.all_axes_nonzero()),
        Err(_) => ([0u8; 32], false),
    };
    let production_axis_denied = StateSpaceBounds::try_production_axis().is_err();

    // 3) move generator — invariant-bound; bounded depth/branch; no fuzz/probe.
    let mut generator = AuditMoveGenerator::new(6, 16);
    let invariant_hash_32 = sha256_32(b"solvency-invariant");
    let root = generator.root(invariant_hash_32, sha256_32(b"sequence"), state_hash_32);
    let mv = AuditMove {
        current_move_hash_32: sha256_32(b"entry-move"),
        expected_response_hash_32: sha256_32(b"expected-response"),
        refutation_hash_32: sha256_32(b"refutation"),
        invariant_hash_32,
        resulting_state_hash_32: state_hash_32,
        stop: StopCondition::InvariantDefended,
    };
    let node_hash_32 = match generator.expand(&root, &mv, 0) {
        Ok(child) => child.node_hash_32,
        Err(_) => root.node_hash_32,
    };
    let random_fuzz_denied = AuditMoveGenerator::try_random_fuzz().is_err();
    let production_probe_denied = AuditMoveGenerator::try_production_probe().is_err();

    // 4) impact prior — rank by plausible impact, not by how scary a diff looks.
    let priors = [
        ImpactPrior {
            funds_at_risk_bps: 9000,
            auth_bypass_bps: 0,
            accounting_drift_bps: 0,
            liveness_dos_bps: 0,
            exploitability_bps: 5000,
            false_positive_risk_bps: 0,
        },
        ImpactPrior {
            funds_at_risk_bps: 0,
            auth_bypass_bps: 6000,
            accounting_drift_bps: 0,
            liveness_dos_bps: 0,
            exploitability_bps: 0,
            false_positive_risk_bps: 0,
        },
        // a "scary diff" with no real impact axis is dropped (never ranked).
        ImpactPrior {
            funds_at_risk_bps: 0,
            auth_bypass_bps: 0,
            accounting_drift_bps: 0,
            liveness_dos_bps: 0,
            exploitability_bps: 0,
            false_positive_risk_bps: 9000,
        },
    ];
    let ranked = rank_top_k(&priors, 3);
    let dropped_no_impact = priors.len().saturating_sub(ranked.len());

    // 5) candidate — a tree node only; promotion needs a reproduced local receipt.
    let candidate = AuditGameTreeCandidate {
        inner: AuditCandidate {
            rule_id_hash_32: sha256_32(b"rule"),
            location_hash_32: sha256_32(b"location"),
            invariant_hash_32,
            evidence_hash_32: sha256_32(b"evidence"),
            confidence_bps_u16: 7000,
            repro_plan_safe_local: true,
            local_repro_done: false,
        },
        origin: CandidateOrigin::SuspiciousInvariantGap,
        node_hash_32,
    };
    let pattern_only = candidate.is_pattern_only();
    // a non-reproduced local receipt never promotes (candidate stays candidate).
    let non_repro_promotes = match LocalReproRunnerReceipt::record(
        &ReproReceiptHashes {
            node_hash_32,
            command_hash_32: sha256_32(b"repro-command"),
            fixture_hash_32: sha256_32(b"local-fixture"),
            result_hash_32: sha256_32(b"repro-result"),
        },
        false,
        false,
        false,
    ) {
        Ok(receipt) => receipt.promotes(),
        Err(_) => false,
    };

    // repro-plan — report-first / exploit-last (prod rpc / live tx / 3p funds denied).
    let plan_complete = matches!(
        LocalReproPlan::new(
            &ReproPlanInputs {
                repo_hash_32: sha256_32(b"repo"),
                fixture_hash_32: sha256_32(b"local-fixture"),
                command_hash_32: sha256_32(b"repro-command"),
                expected_failure_hash_32: sha256_32(b"expected-failure"),
            },
            ReproPlanFlags::default(),
        ),
        Ok(plan) if plan.schema_complete()
    );

    vec![
        format!(
            "audit game tree: invariants={} axes(econ/auth/state)={}/{}/{}",
            g.invariant_count_u32, g.economic_axis_bps, g.authority_axis_bps, g.state_axis_bps
        ),
        format!(
            "bounded state: all_axes_nonzero={all_axes_nonzero} branch_cap={}",
            bounds.branch_cap()
        ),
        format!("state guard: production_axis_denied={production_axis_denied}"),
        format!(
            "search moves: seq={} invariant_bound={}",
            generator.sequence_count_u32, generator.invariant_bound
        ),
        format!(
            "search guard: random_fuzz_denied={random_fuzz_denied} production_probe_denied={production_probe_denied}"
        ),
        format!(
            "impact rank (by impact, not scary diff): ranked={ranked:?} dropped_no_impact={dropped_no_impact}"
        ),
        format!(
            "candidate: pattern_only={pattern_only} origin_u8={} (candidate != finding)",
            candidate.origin as u8
        ),
        format!(
            "promotion gate: non_repro_promotes={non_repro_promotes} (needs reproduced local receipt)"
        ),
        format!(
            "repro-plan: schema_complete={plan_complete} local-only; no prod rpc / live tx / 3p funds"
        ),
        "no live probe / no live tx; bounded local-only search (no production axis)".to_string(),
    ]
}

/// #625 (G.9.1) — the live detector surface (static / Solana / Sui-Move) plus a
/// defensive audit report draft. Every detector flag is a candidate-only node, so
/// [`DetectorSurface::direct_finding_count`] is structurally `0`. A low-confidence
/// detection is quarantined as a likely false positive. A report draft opens ONLY
/// from a reproduced local receipt and is secret-zero + defensive (no exploit
/// instruction, no candidate-certainty wording). Pure local-only projection.
pub(crate) fn audit_detectors_lines() -> Vec<String> {
    use crate::audit::candidate::AuditGameTreeCandidate;
    use crate::audit::detectors::DetectorSurface;
    use crate::audit::report_draft::{AuditReportDraft, ReportDraftInputs};
    use crate::audit::repro_receipt::{LocalReproRunnerReceipt, ReproReceiptHashes};
    use crate::audit::solana_patterns::SolanaPattern;
    use crate::audit::static_detector::{
        DetectorKind, FALSE_POSITIVE_QUARANTINE_BPS, StaticCandidate,
    };
    use crate::audit::sui_move_patterns::SuiMovePattern;
    use crate::commands::eval_core::AuditProfile;
    use crate::commands::eval_language::assert_no_exploit_instruction;

    // 1) detector surface — static / Solana / Sui-Move flags are candidate-only.
    let mut candidates: Vec<AuditGameTreeCandidate> = vec![
        DetectorSurface::flag_solana(
            SolanaPattern::OracleFreshness,
            sha256_32(b"solana-location"),
            sha256_32(b"oracle-invariant"),
            sha256_32(b"evidence"),
            8000,
        ),
        DetectorSurface::flag_sui_move(
            SuiMovePattern::ObjectOwnership,
            sha256_32(b"move-location"),
            sha256_32(b"owner-invariant"),
            sha256_32(b"evidence"),
            7500,
        ),
    ];
    if let Some(static_flag) = DetectorSurface::flag_static(
        DetectorKind::Auth,
        AuditProfile::Rust,
        sha256_32(b"static-anchor"),
        sha256_32(b"auth-invariant"),
        sha256_32(b"evidence"),
        7000,
    ) {
        candidates.push(static_flag);
    }
    let flagged = candidates.len();
    let direct_findings = DetectorSurface::direct_finding_count(&candidates);
    let scan = DetectorSurface::scan(AuditProfile::Rust, true, &candidates);

    // 2) false-positive quarantine — a low-confidence detection is quarantined.
    let quarantine_bps = FALSE_POSITIVE_QUARANTINE_BPS;
    let quarantined = matches!(
        StaticCandidate::detect(
            DetectorKind::Oracle,
            AuditProfile::SolanaSource,
            sha256_32(b"static-anchor"),
            sha256_32(b"oracle-invariant"),
            sha256_32(b"evidence"),
            1000,
        ),
        Some(c) if c.is_quarantined()
    );

    // 3) defensive report draft — opens ONLY from a reproduced local receipt.
    let report_defensive = match LocalReproRunnerReceipt::record(
        &ReproReceiptHashes {
            node_hash_32: sha256_32(b"node"),
            command_hash_32: sha256_32(b"repro-command"),
            fixture_hash_32: sha256_32(b"local-fixture"),
            result_hash_32: sha256_32(b"repro-result"),
        },
        true,
        false,
        false,
    ) {
        Ok(receipt) => matches!(
            AuditReportDraft::from_receipt(
                &receipt,
                &ReportDraftInputs {
                    impact_summary_hash_32: sha256_32(b"impact"),
                    affected_invariant_hash_32: sha256_32(b"auth-invariant"),
                    remediation_hash_32: sha256_32(b"remediation"),
                    source_anchor_hash_32: sha256_32(b"static-anchor"),
                    scope_hash_32: sha256_32(b"scope"),
                },
            ),
            Ok(draft) if draft.secret_zero_and_defensive()
        ),
        Err(_) => false,
    };

    // 4) report wording — report-first / exploit-last (no exploit procedure).
    let no_exploit_instruction =
        assert_no_exploit_instruction("add the missing signer/owner check; needs local repro")
            .is_ok();

    vec![
        format!(
            "audit detectors: flagged={flagged} candidate_count={} (static/solana/sui-move)",
            scan.candidate_count_u32
        ),
        format!(
            "direct findings: direct_finding_count={direct_findings} (never a finding directly)"
        ),
        format!(
            "false-positive quarantine: low_confidence_quarantined={quarantined} (<{quarantine_bps}bps)"
        ),
        format!(
            "scan boundary: local_only={} no_live_call={}",
            scan.is_local_only(),
            scan.made_no_live_call()
        ),
        format!(
            "report draft: defensive_and_secret_zero={report_defensive} (from a reproduced receipt)"
        ),
        format!(
            "report wording: no_exploit_instruction={no_exploit_instruction} (report-first / exploit-last)"
        ),
        "candidate != finding: a flag is a candidate; promotion needs a receipt".to_string(),
    ]
}

/// #626 (G.9.2) — the live audit evidence bundle (candidate / finding / defended)
/// with a stable `bundle_hash_32`, plus defended-invariant memory (don't re-read
/// dead ends). A bundle is hash-linked product evidence; a live export is
/// structurally denied ([`AuditBundle::try_live_export`] always refuses); a finding
/// bundle opens ONLY on a reproduced local receipt. Pure local-only projection.
pub(crate) fn audit_bundle_lines() -> Vec<String> {
    use crate::audit::bundle::AuditBundle;
    use crate::audit::candidate::{AuditGameTreeCandidate, CandidateOrigin};
    use crate::audit::defended_memory::{DefendedInvariantStore, DefendedScope, defended};
    use crate::audit::report_draft::ReportDraftInputs;
    use crate::audit::repro_receipt::{LocalReproRunnerReceipt, ReproReceiptHashes};
    use crate::commands::eval_core::AuditCandidate;

    let invariant_hash_32 = sha256_32(b"solvency-invariant");
    let node_hash_32 = sha256_32(b"candidate-node");
    let candidate = AuditGameTreeCandidate {
        inner: AuditCandidate {
            rule_id_hash_32: sha256_32(b"rule"),
            location_hash_32: sha256_32(b"location"),
            invariant_hash_32,
            evidence_hash_32: sha256_32(b"evidence"),
            confidence_bps_u16: 7000,
            repro_plan_safe_local: true,
            local_repro_done: false,
        },
        origin: CandidateOrigin::SuspiciousInvariantGap,
        node_hash_32,
    };

    // candidate bundle — hash-linked product evidence; export is local-only.
    let bundle =
        AuditBundle::candidate(&candidate, sha256_32(b"anchor"), sha256_32(b"remediation"));
    let live_export_denied = bundle.try_live_export().is_err();
    let secret_zero_local_only = bundle.secret_zero_local_only();

    // finding gate — a finding bundle opens ONLY on a reproduced local receipt.
    let inputs = ReportDraftInputs {
        impact_summary_hash_32: sha256_32(b"impact"),
        affected_invariant_hash_32: invariant_hash_32,
        remediation_hash_32: sha256_32(b"remediation"),
        source_anchor_hash_32: sha256_32(b"anchor"),
        scope_hash_32: sha256_32(b"scope"),
    };
    let hashes = ReproReceiptHashes {
        node_hash_32,
        command_hash_32: sha256_32(b"repro-command"),
        fixture_hash_32: sha256_32(b"local-fixture"),
        result_hash_32: sha256_32(b"repro-result"),
    };
    let non_repro_denied = match LocalReproRunnerReceipt::record(&hashes, false, false, false) {
        Ok(receipt) => AuditBundle::finding(&candidate, &receipt, &inputs).is_err(),
        Err(_) => true,
    };
    let repro_ok = match LocalReproRunnerReceipt::record(&hashes, true, false, false) {
        Ok(receipt) => AuditBundle::finding(&candidate, &receipt, &inputs).is_ok(),
        Err(_) => false,
    };

    // defended memory — record a non-breaking combo as a replay hint (dead end).
    let mut store = DefendedInvariantStore::new();
    let scope_hash_32 = sha256_32(b"scope");
    let memory = defended(invariant_hash_32, 12, 11, 0);
    store.record(
        memory,
        DefendedScope {
            scope_hash_32,
            expiry_epoch_u64: 1000,
        },
    );
    let known_dead_end = store.is_known_dead_end(&invariant_hash_32, &scope_hash_32, 500);
    let replay_hint = store
        .replay_hint(&invariant_hash_32, &scope_hash_32)
        .is_some();
    let fully_defended = memory.fully_defended();

    vec![
        format!(
            "audit bundle: kind_u8={} hash={} (hash-linked product evidence)",
            bundle.kind.as_u8(),
            bundle.redacted_bundle_hash()
        ),
        format!(
            "bundle export: live_export_denied={live_export_denied} secret_zero_local_only={secret_zero_local_only}"
        ),
        format!("finding gate: non_repro_denied={non_repro_denied} repro_ok={repro_ok}"),
        format!(
            "defended memory: entries={} known_dead_end={known_dead_end} replay_hint={replay_hint}",
            store.len()
        ),
        format!(
            "defended outcome: fully_defended={fully_defended} reward_neutral=true (held => no finding)"
        ),
        "candidate != finding: a finding bundle opens only on a reproduced local receipt"
            .to_string(),
        "local-only: no live export / upload; don't re-read defended dead ends".to_string(),
    ]
}

/// #627 (G.9.3) — the live memory commands surface (status / list / query / export
/// / delete / replay). `status` is a hot-path summary that NEVER triggers a full
/// replay; a deleted memory writes an auditable tombstone and can never be
/// resurrected by import / compaction / replay; raw private content is never
/// shown (redacted summaries only). Owner-verified; secret-zero; pure projection.
pub(crate) fn memory_commands_lines() -> Vec<String> {
    use crate::commands::memory_query::{MemoryListView, MemorySummaryRow};
    use crate::memory::commands::MemoryCommandSurface;
    use mnemos_b_memory::{
        DeleteSemantics, MemoryId, MemoryTier, StageBReplayReport, TombstonePolicy,
        stage_b_transcript_hash,
    };

    // status — a hot-path summary that NEVER triggers a full replay.
    let mut policy = TombstonePolicy::new();
    policy.record(MemoryId::new(10), DeleteSemantics::Tombstone);
    let status = MemoryCommandSurface::status(&policy, sha256_32(b"memory-root"));
    let full_replay_on_hot_path = status.full_replay_on_hot_path();
    let status_secret_zero = status.holds_no_secret();

    // delete — an auditable tombstone; deletion wins (no resurrection).
    let mut del_policy = TombstonePolicy::new();
    let receipt = MemoryCommandSurface::delete_dry_run(
        &mut del_policy,
        MemoryId::new(5),
        DeleteSemantics::Tombstone,
    );
    let tombstoned = receipt.tombstoned;
    let is_deleted = MemoryCommandSurface::is_deleted(&del_policy, MemoryId::new(5));

    // replay — a deleted id can never be resurrected (deletion wins over replay).
    let replay_report = StageBReplayReport {
        transcript: stage_b_transcript_hash(b"memory-replay-fixture"),
        applied_u64: 4,
        duplicate_u64: 0,
        rejected_u64: 0,
    };
    let scan = del_policy.scan_candidates(&replay_report, &[MemoryId::new(5), MemoryId::new(6)]);
    let deleted_resurrections = scan.deleted_resurrections_u64;
    let zero_resurrections = scan.zero_resurrections();

    // list — redacted summaries only; raw private content is NEVER shown.
    let list = MemoryListView::new(vec![MemorySummaryRow::redacted(
        1,
        b"private memory content never shown",
        MemoryTier::Recent,
    )]);
    let raw_content_visible = list.raw_content_visible();

    vec![
        format!(
            "memory status: full_replay_on_hot_path={full_replay_on_hot_path} secret_zero={status_secret_zero}"
        ),
        format!("memory delete: tombstoned={tombstoned} is_deleted={is_deleted} (deletion wins)"),
        format!(
            "memory replay: deleted_resurrections={deleted_resurrections} zero_resurrections={zero_resurrections}"
        ),
        format!("memory list: raw_content_visible={raw_content_visible} (redacted summaries only)"),
        "memory export/replay are background jobs (status off the full-replay hot path)"
            .to_string(),
        "owner-verified: a memory is shown only to its owner; tombstone no-resurrection"
            .to_string(),
    ]
}

/// #628 (G.9.4) — the live memory intelligence surface (compactor status /
/// importance labels / user-model status). Compaction runs as a cooperative
/// BACKGROUND step machine; deletion ALWAYS wins over compaction (a tombstone is
/// never aged or removed); a deleted memory is never scored; importance / user
/// model are explainable (hashes only, no raw content); an intel suggestion is
/// advisory and applying it needs approval (never auto-applied). Pure projection.
pub(crate) fn memory_intel_lines() -> Vec<String> {
    use crate::commands::memory_intel::{
        CompactorStatusView, ImportanceLabelView, MemoryIntelSuggestion, MemoryIntelSuggestionKind,
        deletion_wins_over_compaction,
    };
    use mnemos_b_memory::{
        BackgroundCompactor, CompactorEntry, DeleteSemantics, ImportanceFeatures, ImportanceModel,
        MemoryId, MemoryTier, ReplayCursor, TombstonePolicy, stage_b_transcript_hash,
    };

    // compactor — a cooperative BACKGROUND step machine; status snapshot only.
    let compactor = BackgroundCompactor::new(
        vec![
            CompactorEntry {
                id: MemoryId::new(1),
                tier: MemoryTier::Recent,
            },
            CompactorEntry {
                id: MemoryId::new(2),
                tier: MemoryTier::Recent,
            },
            CompactorEntry {
                id: MemoryId::new(3),
                tier: MemoryTier::DeletedTombstone,
            },
        ],
        ReplayCursor::from_replay(&[MemoryId::new(1), MemoryId::new(2)]),
        stage_b_transcript_hash(b"memory-intel-transcript"),
    );
    let status = CompactorStatusView::from_compactor(&compactor);

    // deletion wins over compaction — a tombstoned id is never aged or removed.
    let mut tombs = TombstonePolicy::new();
    tombs.record(MemoryId::new(7), DeleteSemantics::Tombstone);
    let deletion_wins = deletion_wins_over_compaction(&tombs, MemoryId::new(7));

    // importance — explainable score; a deleted memory is BLOCKED (never scored).
    let model = ImportanceModel::new();
    let features = ImportanceFeatures {
        recency_rank_u16: 0,
        access_count_u16: 5,
        content_len_u32: 200,
    };
    let score = ImportanceLabelView::score_status(&model, MemoryId::new(9), &features, None, false)
        .as_ref()
        .map_or(0, |v| v.score_u16);
    let deleted_blocked =
        ImportanceLabelView::score_status(&model, MemoryId::new(4), &features, None, true).is_err();

    // intel suggestion — advisory; applying needs approval (never auto-applied).
    let suggestion = MemoryIntelSuggestion::new(MemoryIntelSuggestionKind::Compact);
    let requires_approval = suggestion.requires_approval();

    vec![
        format!(
            "memory intel compactor: total={} cursor={} done={} (background step machine)",
            status.total_entries_u32, status.cursor_u32, status.done
        ),
        format!(
            "deletion_wins_over_compaction={deletion_wins} (a tombstone is never aged or removed)"
        ),
        format!("importance: score={score} explainable; deleted_memory_blocked={deleted_blocked}"),
        format!(
            "intel suggestion: requires_approval={requires_approval} (advisory; never auto-applied)"
        ),
        "user-model: hashed components only (no raw bytes); explainable context".to_string(),
        "compaction is a background job; deletion always wins over compaction".to_string(),
    ]
}

/// #629 (G.9.5) — the live evidence pack: a hash-linked [`EvidencePackManifest`]
/// grouping provider / audit / memory / telegram / trace evidence by task /
/// session, with a stable order-independent pack hash that recomputes verbatim
/// (replay determinism). Archive presence is NOT training consent
/// (`training_eligible=false` by default); secret-zero (hashes + counts only);
/// entries are built from command traces (the redacted output hash, never raw).
pub(crate) fn evidence_pack_lines() -> Vec<String> {
    use crate::command::{CliMode, CommandEnvelope, CommandRisk, CommandTraceRecord};
    use crate::evidence::pack_manifest::{EvidenceKind, EvidencePackBuilder, EvidencePackEntry};
    use crate::grammar::CliNamespace;
    use crate::{StageFEvidenceRef, StageFTraceLink};

    let task = sha256_32(b"task");
    let session = sha256_32(b"session");
    let mut builder = EvidencePackBuilder::new(task, session);

    // entries are built from command traces (redacted output hash; raw never carried).
    let env = CommandEnvelope::classify(
        CliNamespace::Trace,
        "list",
        CliMode::Run,
        CommandRisk::ReadOnly,
        b"",
    );
    let trace_record = CommandTraceRecord {
        envelope: env,
        exit_code_i32: 0,
        evidence: StageFEvidenceRef {
            path_hash_32: sha256_32(b"path"),
            trace: StageFTraceLink::new(sha256_32(b"trace"), 629, 1),
        },
        redacted_output_hash_32: sha256_32(b"redacted-output"),
    };
    let _ = builder.add(EvidencePackEntry::from_command_trace(&trace_record));
    let _ = builder.add(EvidencePackEntry::new(
        EvidenceKind::ProviderConsult,
        sha256_32(b"provider"),
    ));
    let _ = builder.add(EvidencePackEntry::new(
        EvidenceKind::AuditCandidate,
        sha256_32(b"audit"),
    ));
    let _ = builder.add(EvidencePackEntry::new(
        EvidenceKind::MemoryReplay,
        sha256_32(b"memory"),
    ));
    let _ = builder.add(EvidencePackEntry::new(
        EvidenceKind::TelegramEvent,
        sha256_32(b"telegram"),
    ));

    let manifest = builder.build();
    let entries_snapshot = builder.entries().to_vec();
    let recompute_matches =
        manifest.recompute_pack_hash(&entries_snapshot) == manifest.pack_hash_32();
    let secret_zero = manifest.holds_no_secret();
    let links_task_session = manifest.links(&task, &session);

    vec![
        format!(
            "evidence pack: entries={} hash={} (hash-linked manifest)",
            manifest.entry_count_u32,
            manifest.redacted_pack_hash()
        ),
        "pack kinds: provider/audit/memory/telegram/trace (from command traces)".to_string(),
        format!(
            "hash-linked: recompute_matches={recompute_matches} links_task_session={links_task_session}"
        ),
        format!("secret-zero: holds_no_secret={secret_zero} (hashes + counts only, never a body)"),
        "training_eligible=false by default: archive presence != training consent".to_string(),
        "entries are built from command traces (redacted output hash; raw never carried)"
            .to_string(),
    ]
}

/// #630 (G.9.6) — the live evidence replay: an OFFLINE, deterministic re-derivation
/// of a pack hash that proves the trace is stable WITHOUT running any live provider
/// / tool / wallet / gas side effect ([`EvidenceReplayDryRun::try_live_side_effect`]
/// always refuses). The terminal output is redacted; replay is a background job,
/// never the status hot path. Pure offline explanation — no live action.
pub(crate) fn evidence_replay_lines() -> Vec<String> {
    use crate::evidence::pack_manifest::{EvidenceKind, EvidencePackBuilder, EvidencePackEntry};
    use crate::evidence::replay::EvidenceReplayDryRun;

    let mut builder = EvidencePackBuilder::new(sha256_32(b"task"), sha256_32(b"session"));
    let _ = builder.add(EvidencePackEntry::new(
        EvidenceKind::ProviderConsult,
        sha256_32(b"provider"),
    ));
    let _ = builder.add(EvidencePackEntry::new(
        EvidenceKind::GateResult,
        sha256_32(b"gate"),
    ));
    let manifest = builder.build();
    let entries = builder.entries().to_vec();

    // offline + deterministic replay — re-derives the pack hash; no live side effect.
    let replay_a = EvidenceReplayDryRun::replay(&manifest, &entries);
    let replay_b = EvidenceReplayDryRun::replay(&manifest, &entries);
    let deterministic = matches!((&replay_a, &replay_b), (Ok(a), Ok(b)) if a == b);
    let (replayed, trace_hash_stable, live_side_effect, terminal, no_secret, live_denied) =
        match &replay_a {
            Ok(r) => (
                r.replayed_entry_count_u32,
                r.trace_hash_stable,
                r.live_side_effect,
                r.terminal_redacted(),
                r.holds_no_secret(),
                r.try_live_side_effect().is_err(),
            ),
            Err(_) => (0, false, true, String::new(), false, false),
        };

    vec![
        format!(
            "evidence replay: replayed_entries={replayed} trace_hash_stable={trace_hash_stable} (offline)"
        ),
        format!("determinism: twin_replay_equal={deterministic} pack={terminal} (re-derived hash)"),
        format!(
            "live boundary: live_side_effect={live_side_effect} live_side_effect_denied={live_denied}"
        ),
        format!("secret-zero: holds_no_secret={no_secret} terminal output redacted"),
        "replay is a background job, never the status hot path (offline explanation only)"
            .to_string(),
    ]
}

/// #631 (G.9.7) — the live skill discovery / use / state surface. Discovery is
/// security-first ([`SkillDiscovery`]: a quarantined skill is gated to a zero
/// score and can never out-rank an audited one — popularity cannot override the
/// security gate). A use is try-before-use ([`SkillUseLaunch`]: it needs a
/// passing dry-run AND an explicit confirm before it can launch, and it is never
/// a commerce / checkout surface). The install-state controller
/// ([`SkillStateController`]) makes quarantine sticky / fail-closed: a revoked
/// skill can never be re-enabled. A capability diff ([`CapabilityDiff`]) is shown
/// BEFORE execution and a hidden permission is denied; the sandbox tier ceiling
/// ([`Sandbox`]) is immutable — warmup is performance-only and never widens it.
/// Pure local-only projection: no network, wallet, chain, gas, or provider call.
/// Reused by `repl::run` so the CLI REPL and the TUI cockpit drive ONE skill
/// pipeline (no second truth source).
pub(crate) fn skill_live_lines() -> Vec<String> {
    use crate::commands::capability::{
        CapabilityDiff, CapabilityKind, CapabilitySet, detect_hidden_permission,
    };
    use crate::commands::sandbox::{Sandbox, SandboxTier};
    use crate::commands::skill_search::SkillDiscovery;
    use crate::commands::skill_state::SkillStateController;
    use crate::commands::skill_use::SkillUseLaunch;
    use mnemos_a_core::{StageBTraceLink, StageCTraceLink, StageDTraceLink};
    use mnemos_e_skill::{
        CatalogCache, CompatibilityDecision, FixtureSource, LocalInstallReceipt,
        LocalInstallReceiptId, LocalSkillState, ProvenanceNode, SignedCatalogCache,
        SkillCatalogIndexEntry, SkillEvalScore, SkillId, SkillPackageDigest32,
        SkillRuntimePermission, SkillSecurityState, SuiAddress, TryBeforeUseFixture,
        WasmTier2ModuleId, reproducible_command_hash,
    };

    // --- security-first discovery: a quarantined skill is gated to zero and
    // never out-ranks an audited one (popularity cannot override security). ---
    let mk_entry = |skill: u16, security: SkillSecurityState| -> SkillCatalogIndexEntry {
        let package = SkillPackageDigest32::new([(skill as u8).wrapping_add(1); 32]);
        SkillCatalogIndexEntry {
            skill: SkillId(skill),
            package,
            name_hash_32: [0x99; 32],
            downloads_u64: 100,
            verified_installs_u64: 10,
            active_users_u64: 2,
            eval: SkillEvalScore {
                rust_u16: 9_000,
                move_u16: 9_000,
                prover_u16: 9_000,
                gas_u16: 9_000,
                security_u16: 9_000,
                korean_u16: 9_000,
                reproducible_command_hash_32: reproducible_command_hash(&["cargo test"]),
            },
            security,
            compatibility: CompatibilityDecision::Compatible,
            capability_diff: mnemos_e_skill::CapabilityDiff::new(0, 0, Vec::new()),
            provenance: ProvenanceNode {
                skill: SkillId(skill),
                package,
                parent: None,
                author: SuiAddress::new([0x11; 32]),
                provenance_depth_u16: 0,
            },
        }
    };
    let entries = vec![
        mk_entry(1, SkillSecurityState::Quarantined),
        mk_entry(2, SkillSecurityState::AuditPass),
    ];
    let cache = SignedCatalogCache::sign(CatalogCache::rebuild(&entries, &[]));
    let live = cache.cache().watermark();
    let disc = SkillDiscovery::new(&cache, live);
    let (search_rows, security_first_holds, quarantine_gated) = match disc.search("", 10) {
        Ok(r) => {
            let top_real = r
                .rows
                .first()
                .is_some_and(|row| !row.explanation.gated_to_zero && row.score.total_u32 > 0);
            let any_gated = r.rows.iter().any(|row| row.explanation.gated_to_zero);
            let q_gated = r
                .rows
                .iter()
                .find(|row| row.card.skill.0 == 1)
                .is_some_and(|row| row.explanation.gated_to_zero);
            (r.rows.len(), top_real && any_gated, q_gated)
        }
        Err(_) => (0, false, false),
    };

    // --- try-before-use launch: a use needs a passing dry-run + an explicit
    // confirm; cancelling the confirm makes it un-launchable; never commerce. ---
    let mk_trace = |salt: u64, seq: u16| -> StageDTraceLink {
        let b = StageBTraceLink::new(0xF631_0000_u64 | salt, 631, 0);
        let c = StageCTraceLink::new(b, 240, 9);
        StageDTraceLink::new(c, 631, seq)
    };
    let use_diff = mnemos_e_skill::CapabilityDiff::new(
        SkillRuntimePermission::MemoryRead.mask_bit(),
        0,
        Vec::new(),
    );
    let mut launch = SkillUseLaunch::open(
        SkillId(7),
        SkillPackageDigest32::new([0x44; 32]),
        WasmTier2ModuleId::from_bytes([0x55; 32]),
        &use_diff,
    );
    launch.set_package_verified(true);
    launch.set_compatibility(CompatibilityDecision::Compatible);
    launch.run_dry_run(
        &TryBeforeUseFixture {
            fixture_hash_32: [0x11; 32],
            source: FixtureSource::Sample,
            redaction_token_32: [0u8; 32],
        },
        mk_trace(1, 1),
    );
    launch.confirm();
    let dry_run_passed = launch.dry_run_passed();
    let can_launch = launch.can_launch();
    let is_commerce = launch.is_commerce();
    let mut launch_no_confirm = launch.clone();
    launch_no_confirm.cancel();
    let can_without_confirm = launch_no_confirm.can_launch();

    // --- install-state controller: quarantine is sticky (fail-closed) — a
    // revoked skill can never be re-enabled and is never executable. ---
    let receipt = LocalInstallReceipt {
        id: LocalInstallReceiptId::new([0x33; 32]),
        skill: SkillId(7),
        package: SkillPackageDigest32::new([0x44; 32]),
        user: SuiAddress::new([0xAB; 32]),
        state: LocalSkillState::Enabled,
        capability_approval_hash_32: [0x77; 32],
        trace: mk_trace(2, 2),
    };
    let mut state = SkillStateController::from_receipt(receipt);
    let _ = state.quarantine();
    let re_enable_denied = state.enable().is_err();
    let executable_after_quarantine = state.is_executable();

    // --- capability diff shown BEFORE execution + hidden-permission deny ---
    let before = CapabilitySet::with(CapabilityKind::PureCompute);
    let after = before.insert(CapabilityKind::Network);
    let cdiff = CapabilityDiff::new(before, after);
    let gained = cdiff.gained_capability();
    let tier_escalation = cdiff.is_tier_escalation();
    let requires_approval = cdiff.requires_approval();
    let declared =
        CapabilitySet::with(CapabilityKind::PureCompute).insert(CapabilityKind::ReadLocal);
    let required = declared.insert(CapabilityKind::Network);
    let hidden_denied = detect_hidden_permission(declared, required);

    // --- sandbox tier ceiling: immutable; warmup is performance-only ---
    let mut sandbox = Sandbox::new(SandboxTier::Networked);
    let allowed_before = sandbox.allowed_capabilities().count();
    let inspect = sandbox.warmup();
    let tier_ordinal = inspect.tier.ordinal();
    let allowed_count = inspect.allowed.count();
    let denied_count = inspect.denied.count();
    let warmup_widens = inspect.allowed.count() > allowed_before;

    vec![
        format!(
            "skill search: rows={search_rows} security_first_holds={security_first_holds} quarantine_gated_to_zero={quarantine_gated}"
        ),
        format!(
            "skill use: dry_run_passed={dry_run_passed} can_launch={can_launch} is_commerce={is_commerce}"
        ),
        format!(
            "skill use gate: without_confirm can_launch={can_without_confirm} (confirm required)"
        ),
        format!(
            "skill state: quarantine_revoked re_enable_denied={re_enable_denied} executable={executable_after_quarantine}"
        ),
        format!(
            "capability diff: gained={gained} tier_escalation={tier_escalation} requires_approval={requires_approval}"
        ),
        format!(
            "hidden permission: declared_lt_required denied={hidden_denied} (no permission-free path)"
        ),
        format!(
            "sandbox: tier={tier_ordinal} allowed={allowed_count} denied={denied_count} warmup_widens={warmup_widens} (ceiling immutable)"
        ),
        "skills untrusted-by-default; output as patch/evidence; 0 live action".to_string(),
    ]
}

/// #632 (G.9.8) — the live skill package / provenance surface. A package
/// lifecycle ([`SkillPackageFlow`]) mints a trust receipt ONLY when every hard
/// gate passes (consistent capability diff, installable security, complete
/// supply chain — SBOM + reproducible-build + dependency-lock + deny-audit +
/// license + network-denied build script — a valid safety-kernel attestation,
/// and a clean malicious-fixture fold): a signature proves AUTHORSHIP only, not
/// safety, so the receipt's absence is itself the deny signal. Install is gated
/// on that receipt; publish is a local dry-run (no upload / sign / charge, state
/// unchanged); revoke is terminal (a revoked package can never run again); a fork
/// is a pure preview (a self-parent child is malformed). The provenance card
/// ([`SkillProvenanceCard`]) makes the lineage / fork graph visible and lets
/// lineage / security / review dominate reputation (an invalid chain renders
/// RED). Pure local-only projection: no network, wallet, chain, gas, or upload.
pub(crate) fn skill_package_lines() -> Vec<String> {
    use crate::commands::skill_package::SkillPackageFlow;
    use crate::commands::skill_provenance::{SkillProvenanceCard, render_fork_graph};
    use mnemos_e_skill::{
        ProvenanceNode, ReviewState, SkillEvalScore, SkillId, SkillPackageDigest32, SkillRankScore,
        SkillRuntimePermission, SkillSecurityState, SkillSupplyChainReceipt, SuiAddress,
        reproducible_command_hash,
    };
    use mnemos_g_wallet::{OfficialTrustDecision, SafetyKernelAttestation, SafetyKernelBuildRef};

    const NOW: u64 = 10;

    // --- package lifecycle over a fully-gated (clean) verified package ---
    let supply_chain = SkillSupplyChainReceipt {
        sbom_hash_32: [1; 32],
        reproducible_build_hash_32: [2; 32],
        dependency_lock_hash_32: [3; 32],
        deny_audit_hash_32: [4; 32],
        license_hash_32: [5; 32],
        build_script_network_denied: true,
    };
    let eval = SkillEvalScore {
        rust_u16: 9_000,
        move_u16: 9_000,
        prover_u16: 8_000,
        gas_u16: 8_000,
        security_u16: 9_000,
        korean_u16: 9_000,
        reproducible_command_hash_32: reproducible_command_hash(&["cargo test"]),
    };
    let diff = mnemos_e_skill::CapabilityDiff::new(
        SkillRuntimePermission::MemoryRead.mask_bit(),
        0,
        Vec::new(),
    );
    let attestation = SafetyKernelAttestation {
        build: SafetyKernelBuildRef {
            build_id_u64: 632,
            release_hash_32: [0x9; 32],
        },
        sbom_hash_32: [1; 32],
        reproducible_build_hash_32: [2; 32],
        sandbox_policy_hash_32: [3; 32],
        evidence_schema_hash_32: [4; 32],
        expires_epoch_u64: 100,
    };
    let root_provenance = ProvenanceNode {
        skill: SkillId(7),
        package: SkillPackageDigest32::new([0xA0; 32]),
        parent: None,
        author: SuiAddress::new([0x11; 32]),
        provenance_depth_u16: 0,
    };
    let mut flow = SkillPackageFlow::open(
        SkillId(7),
        SkillPackageDigest32::new([0xA0; 32]),
        root_provenance,
        supply_chain,
        SkillSecurityState::AuditPass,
        eval,
        &diff,
        true,
        Some(attestation),
        OfficialTrustDecision::OfficialTrusted,
    );

    let receipt_minted = flow.trust_receipt(NOW).is_ok();
    let state_before_publish = flow.state();
    let publish = flow.publish_dry_run(NOW);
    let dry_run_publishable = publish.publishable;
    let supply_chain_complete = publish.supply_chain_complete;
    let attestation_valid = publish.attestation_valid;
    let state_unchanged = flow.state() == state_before_publish;
    let child_ok = flow
        .fork_preview(
            SkillPackageDigest32::new([0xB0; 32]),
            SuiAddress::new([0x22; 32]),
        )
        .is_ok();
    let self_parent_denied = flow
        .fork_preview(
            SkillPackageDigest32::new([0xA0; 32]),
            SuiAddress::new([0x22; 32]),
        )
        .is_err();
    let installed = flow.install(NOW).is_ok();
    let runnable = flow.is_runnable();
    let revocation = flow.revoke();
    let revoked_executable = revocation.executable;
    let runnable_after_revoke = flow.is_runnable();

    // --- provenance card + fork graph (lineage > reputation; invalid -> RED) ---
    let prov_root = || ProvenanceNode {
        skill: SkillId(1),
        package: SkillPackageDigest32::new([0xA0; 32]),
        parent: None,
        author: SuiAddress::new([0x11; 32]),
        provenance_depth_u16: 0,
    };
    let prov_leaf = || ProvenanceNode {
        skill: SkillId(1),
        package: SkillPackageDigest32::new([0xB0; 32]),
        parent: Some(SkillPackageDigest32::new([0xA0; 32])),
        author: SuiAddress::new([0x22; 32]),
        provenance_depth_u16: 1,
    };
    let rank = SkillRankScore {
        entry: SkillId(1),
        total_u32: 5_000,
        eval_weight_u16: 0,
        security_weight_u16: 0,
        compatibility_weight_u16: 0,
        verified_weight_u16: 0,
    };
    let chain = [prov_leaf(), prov_root()];
    let (chain_valid, ancestors, prov_truth) = match SkillProvenanceCard::build(
        &chain,
        SkillSecurityState::AuditPass,
        ReviewState::Approved,
        OfficialTrustDecision::OfficialTrusted,
        &rank,
    ) {
        Ok(card) => (
            card.chain_valid,
            card.ancestor_count,
            truth_label(card.render_truth()),
        ),
        Err(_) => (false, 0usize, "RED"),
    };
    let fork_graph = render_fork_graph(&chain, 4).join(" | ");

    // a missing-ancestor chain still builds a card (the user SEES the bad
    // lineage) but renders RED — lineage dominates reputation.
    let bad_leaf = ProvenanceNode {
        parent: Some(SkillPackageDigest32::new([0xFF; 32])),
        ..prov_leaf()
    };
    let bad_chain = [bad_leaf, prov_root()];
    let (bad_chain_valid, bad_truth) = match SkillProvenanceCard::build(
        &bad_chain,
        SkillSecurityState::AuditPass,
        ReviewState::Approved,
        OfficialTrustDecision::OfficialTrusted,
        &rank,
    ) {
        Ok(card) => (card.chain_valid, truth_label(card.render_truth())),
        Err(_) => (false, "RED"),
    };

    vec![
        format!("pkg trust: receipt_minted={receipt_minted} sig_proves_authorship_only=true"),
        format!(
            "pkg gates: supply_chain_complete={supply_chain_complete} attestation_valid={attestation_valid}"
        ),
        format!("pkg install: installed={installed} runnable={runnable} (gated on trust receipt)"),
        format!(
            "pkg publish: dry_run_publishable={dry_run_publishable} live_published=false state_unchanged={state_unchanged}"
        ),
        format!(
            "pkg revoke: revoked_executable={revoked_executable} runnable_after_revoke={runnable_after_revoke} (terminal)"
        ),
        format!(
            "pkg fork: child_ok={child_ok} self_parent_denied={self_parent_denied} (preview only)"
        ),
        format!(
            "provenance card: chain_valid={chain_valid} ancestors={ancestors} truth={prov_truth} (lineage>reputation)"
        ),
        format!(
            "provenance bad-chain: chain_valid={bad_chain_valid} truth={bad_truth} (missing-ancestor)"
        ),
        format!("fork-graph: {fork_graph}"),
        "skill packages: untrusted-by-default; trust=authorship-only; 0 live publish".to_string(),
    ]
}

/// #633 (G.9.9) — the live dataset ingest / export surface. Ingest runs the
/// canonical redaction gate ([`DatasetIngestView`]: clean text passes, any
/// secret / PII / encoded residue is refused) and a content-hash dedup; a locked
/// dataset shard is structurally immutable (`try_write_locked_shard` -> Err — no
/// silent rewrite of locked truth). Export is gated on a PII-zero quality report
/// ([`QualityGateView::assert_clean`]); an S2 narrative is NEVER reward eligible
/// ([`s2_reward_blocked`] — only S1 ground truth, re-verified, is reward-bearing);
/// a straddling leakage group is refused ([`SplitSummary`]); and a contribution
/// upload is a local dry-run ([`request_contribution_upload`] / [`export_target`]
/// — `ContributeRedacted` builds a review packet that never uploads without
/// approval, and Stage G performs NO live upload). Pure local-only projection;
/// the rendered surface is itself secret-zero (no secret / PII bytes).
pub(crate) fn dataset_live_lines() -> Vec<String> {
    use crate::commands::dataset_export::{
        ExportTarget, QualityGateView, SplitSummary, export_target, request_contribution_upload,
        reward_provenance_ok, s2_reward_blocked,
    };
    use crate::commands::dataset_ingest::{DatasetIngestView, IngestFileSpec};
    use crate::config::LearningMode;
    use mnemos_l_dataset::AtomDietKey;
    use mnemos_l_dataset::diet_kind::DietSourceStage;
    use mnemos_l_dataset::privacy::PrivacyDecision;
    use mnemos_l_dataset::quality::QualityReport;
    use mnemos_l_dataset::split::{SplitAssignment, TrainingSplit};
    use mnemos_l_dataset::stream_split::S2NarrativeRecord;

    let mk_key = |atom: u16| AtomDietKey::new(DietSourceStage::StageD, atom);

    // --- ingest: redaction gate (clean ok; residue denied) + content dedup ---
    let redaction_clean =
        DatasetIngestView::redaction_gate("a perfectly ordinary sentence").is_ok();
    let residue_denied =
        DatasetIngestView::redaction_gate("ghp_ABCDEFGHIJKLMNOP aws_secret_access_key=AKIA")
            .is_err();
    let files = [
        IngestFileSpec::new(1, 100, [0xAA; 32]),
        IngestFileSpec::new(2, 200, [0xAA; 32]),
        IngestFileSpec::new(3, 300, [0xBB; 32]),
    ];
    let dedup_unique = DatasetIngestView::unique_count(&files);

    // --- locked-shard write is structurally denied (no silent rewrite) ---
    let locked_shard_write_allowed = DatasetIngestView::locked_shard_write_allowed();
    let locked_write_denied = DatasetIngestView::try_write_locked_shard().is_err();

    // --- quality gate: a PII-0 report passes; any PII/secret hit fails closed ---
    let clean_report = QualityReport {
        records_u64: 10,
        pii_hits_u32: 0,
        secret_hits_u32: 0,
        encoded_hits_u32: 0,
        duplicate_u32: 0,
        malformed_u32: 0,
        oversize_u32: 0,
        decision: PrivacyDecision::Pass,
    };
    let dirty_report = QualityReport {
        records_u64: 10,
        pii_hits_u32: 3,
        secret_hits_u32: 0,
        encoded_hits_u32: 0,
        duplicate_u32: 0,
        malformed_u32: 0,
        oversize_u32: 0,
        decision: PrivacyDecision::Reject,
    };
    let quality_clean = QualityGateView::assert_clean(&clean_report).is_ok();
    let dirty_denied = QualityGateView::assert_clean(&dirty_report).is_err();

    // --- reward: an S2 narrative is never reward-eligible; reward needs S1 reverify ---
    let s2 = S2NarrativeRecord::new(mk_key(633), [0x01; 32]);
    let s2_reward_blocked_v = s2_reward_blocked(&s2);
    let s1_reverify_required =
        !reward_provenance_ok(true, false) && reward_provenance_ok(false, false);

    // --- split: a straddling leakage group is denied; distinct groups summarise ---
    let leaky = [
        SplitAssignment {
            key: mk_key(633),
            split: TrainingSplit::Train,
            leakage_group_hash_32: [7; 32],
        },
        SplitAssignment {
            key: mk_key(634),
            split: TrainingSplit::Test,
            leakage_group_hash_32: [7; 32],
        },
    ];
    let leakage_conflict_denied = SplitSummary::from_assignments(&leaky).is_err();
    let clean_split = [
        SplitAssignment {
            key: mk_key(633),
            split: TrainingSplit::Train,
            leakage_group_hash_32: [1; 32],
        },
        SplitAssignment {
            key: mk_key(634),
            split: TrainingSplit::Test,
            leakage_group_hash_32: [2; 32],
        },
        SplitAssignment {
            key: mk_key(635),
            split: TrainingSplit::HeldOut,
            leakage_group_hash_32: [3; 32],
        },
    ];
    let clean_split_total = match SplitSummary::from_assignments(&clean_split) {
        Ok(s) => s.total(),
        Err(_) => 0,
    };

    // --- export: no live upload; ContributeRedacted is a review packet only ---
    let upload_without_approval_denied = request_contribution_upload(false).is_err();
    let approved_no_live_upload = request_contribution_upload(true).is_ok();
    let target_review_packet = matches!(
        export_target(LearningMode::ContributeRedacted),
        Some(ExportTarget::ReviewPacketNoUpload)
    );

    vec![
        format!(
            "dataset ingest: redaction_clean={redaction_clean} residue_denied={residue_denied} dedup_unique={dedup_unique}"
        ),
        format!(
            "dataset shard: locked_shard_write_allowed={locked_shard_write_allowed} locked_write_denied={locked_write_denied}"
        ),
        format!("dataset quality: pii_hits=0 clean={quality_clean} dirty_denied={dirty_denied}"),
        format!(
            "dataset reward: s2_reward_blocked={s2_reward_blocked_v} s1_reverify_required={s1_reverify_required}"
        ),
        format!(
            "dataset split: leakage_conflict_denied={leakage_conflict_denied} clean_split_total={clean_split_total}"
        ),
        format!(
            "dataset export: upload_without_approval_denied={upload_without_approval_denied} live_upload=false"
        ),
        format!(
            "dataset export: target_review_packet={target_review_packet} approved_no_live_upload={approved_no_live_upload}"
        ),
        "datasets: locked-shard immutable; PII-0 gate; S1-only reward; 0 live upload".to_string(),
    ]
}

/// #634 (G.9.10) — the live SFT trace-pair + eval surface. A trace is reward
/// eligible ONLY when it is S1 ground truth, verified, rights-clear, opted-in,
/// not self-report / raw-frontier / frontier-only ([`TracePairView`]); an S2
/// narrative never earns reward, and an audit candidate stays S2 (candidate !=
/// finding) until a local reproducer promotes it. An eval run
/// ([`EvalRunView`]) cannot record a false pass (a claimed pass with no evidence
/// is refused). Audit reports ([`AuditReportView`]) are report-first (status +
/// hashes only — never an exploit recipe): [`assert_no_exploit_instruction`]
/// refuses an exploit procedure and [`assert_no_candidate_certainty`] refuses
/// certainty language for an unreproduced candidate (a reproduced finding may
/// state its verified result). Pure local-only projection; the rendered surface
/// is itself exploit-recipe-free and candidate-certainty-free.
pub(crate) fn eval_live_lines() -> Vec<String> {
    use crate::commands::eval_core::{EvalKind, EvalRunView};
    use crate::commands::eval_language::{
        AuditReportView, ReportLang, assert_no_candidate_certainty, assert_no_exploit_instruction,
    };
    use crate::commands::trace_pair::{TraceClass, TraceFacts, TracePairView};

    // --- trace pairing: S1-only reward; S2 / audit-candidate / frontier-only do not ---
    let clean = TraceFacts {
        ground_truth: true,
        verified: true,
        has_rights: true,
        opt_in: true,
        ..TraceFacts::default()
    };
    let s1_reward_eligible = matches!(TracePairView::classify(clean), Ok(v) if v.reward_eligible);
    let s2_no_reward = matches!(
        TracePairView::classify(TraceFacts { ground_truth: false, ..clean }),
        Ok(v) if !v.reward_eligible
    );
    let cand_not_finding = matches!(
        TracePairView::classify(TraceFacts { audit_candidate: true, local_repro_done: false, ..clean }),
        Ok(v) if v.class == TraceClass::S2NarrativeOnly && !v.reward_eligible
    );
    let repro_promotes = matches!(
        TracePairView::classify(TraceFacts { audit_candidate: true, local_repro_done: true, ..clean }),
        Ok(v) if v.reward_eligible
    );
    let frontier_no_promote = matches!(
        TracePairView::classify(TraceFacts { frontier_only: true, ..clean }),
        Ok(v) if !v.reward_eligible
    );

    // --- eval run: a false pass (claimed pass, zero evidence) cannot be recorded ---
    let eval = EvalRunView::record(
        EvalKind::Rust,
        true,
        sha256_32(b"cargo test"),
        sha256_32(b"env-lock"),
        sha256_32(b"evidence"),
    );
    let (eval_passed, eval_reproducible) = match &eval {
        Ok(e) => (e.passed, e.reproducible()),
        Err(_) => (false, false),
    };
    let false_pass_denied = EvalRunView::record(
        EvalKind::Rust,
        true,
        sha256_32(b"cmd"),
        sha256_32(b"env"),
        [0u8; 32],
    )
    .is_err();

    // --- audit report: candidate != finding (report-first; status + hashes only) ---
    let report_candidate = AuditReportView::candidate(
        ReportLang::Korean,
        &[1; 32],
        &[2; 32],
        &[3; 32],
        &[4; 32],
        6000,
    );
    let report_finding =
        AuditReportView::finding(ReportLang::English, &[1; 32], &[2; 32], &[3; 32], &[4; 32]);
    let candidate_is_finding = report_candidate.is_finding;
    let finding_is_finding = report_finding.is_finding;

    // --- safe wording: no exploit recipe; no certainty for an unreproduced candidate ---
    let candidate_certainty_denied =
        assert_no_candidate_certainty("this is definitely exploitable", false).is_err();
    let exploit_instruction_denied =
        assert_no_exploit_instruction("step 1: rm -rf / then drain").is_err();
    let hedged_candidate_ok =
        assert_no_candidate_certainty("this may affect the invariant; needs local repro", false)
            .is_ok();
    let finding_may_state_result =
        assert_no_candidate_certainty("this is definitely exploitable", true).is_ok();

    vec![
        format!("trace pair: s1_reward_eligible={s1_reward_eligible} s2_no_reward={s2_no_reward}"),
        format!(
            "trace audit: cand_not_finding={cand_not_finding} repro_promotes={repro_promotes} frontier_no_promote={frontier_no_promote}"
        ),
        format!(
            "eval run: passed={eval_passed} reproducible={eval_reproducible} false_pass_denied={false_pass_denied}"
        ),
        format!(
            "audit report: candidate_is_finding={candidate_is_finding} finding_is_finding={finding_is_finding}"
        ),
        format!(
            "report wording: candidate_certainty_denied={candidate_certainty_denied} exploit_instruction_denied={exploit_instruction_denied}"
        ),
        format!(
            "report wording: hedged_candidate_ok={hedged_candidate_ok} finding_may_state_result={finding_may_state_result}"
        ),
        "eval/trace: S1-only reward; candidate!=finding; report-first safe-wording; 0 live probe"
            .to_string(),
    ]
}

/// #635 (G.9.11) — the live daemon supervisor + task/session inbox + reconnect
/// surface. The supervisor ([`DaemonSupervisorView`]) is killable and
/// structurally owns NO secret or wallet (its type has no field that could hold
/// one); a stopped daemon renders Unknown, never a false green. One shared
/// inbox ([`OperationalInbox`]) gives provider / audit / memory / evidence /
/// notify / handoff jobs a single id space and checkpointable state. After a
/// restart the CLI and Telegram reconnect ([`reconnect`]) against ONE shared
/// state hash; a matching hash is fresh, a non-matching one is stale and refused
/// (no silent stale-UI accept), and the two channels cannot diverge by origin.
/// Pure local-only projection; the rendered surface holds no secret value.
/// Reused by `repl::run` so the CLI REPL and the TUI cockpit drive ONE daemon
/// pipeline (no second truth source).
pub(crate) fn daemon_live_lines() -> Vec<String> {
    use crate::commands::platform_telegram::PlatformOrigin;
    use crate::daemon::reconnect::{SharedRuntimeState, reconnect};
    use crate::daemon::supervisor::DaemonSupervisorView;
    use crate::daemon::task_session::{OperationalInbox, OperationalJobClass};
    use crate::tui::job_rail::JobState;

    // --- supervisor: a started daemon is killable + owns no secret/wallet; a
    // stopped daemon is Unknown (never a false green) and is not killable. ---
    let running = DaemonSupervisorView::started(7, 4);
    let running_killable = running.is_killable();
    let holds_no_secret_or_wallet = running.holds_no_secret_or_wallet();
    let stopped_not_killable = !DaemonSupervisorView::stopped(7).is_killable();

    // --- inbox: provider/audit/memory/evidence/notify/handoff share ONE id space ---
    let mut inbox = OperationalInbox::new(635);
    let _ = inbox.admit(
        1,
        OperationalJobClass::ProviderConsult,
        JobState::Running,
        demo_trace(635),
    );
    let _ = inbox.admit(
        2,
        OperationalJobClass::AuditScan,
        JobState::Running,
        demo_trace(635),
    );
    let inbox_session = inbox.session_id();
    let inbox_jobs = inbox.list().len();
    let inbox_live = inbox.live_count();
    let shared_id_space = OperationalJobClass::ALL.len();

    // --- reconnect: CLI + Telegram reconnect to ONE state_hash; stale is refused ---
    let shared = SharedRuntimeState {
        task_count_u32: 3,
        session_id_u64: 635,
        context_version_u32: 2,
        budget_remaining_micros_u64: 5_000,
    };
    let cli = reconnect(PlatformOrigin::Cli, &shared, shared.state_hash());
    let tg = reconnect(PlatformOrigin::Telegram, &shared, shared.state_hash());
    let cli_fresh = cli.verdict.is_fresh();
    let tg_fresh = tg.verdict.is_fresh();
    let cli_tg_same_hash = cli.current_hash_32 == tg.current_hash_32;
    let stale_view_refused = !reconnect(PlatformOrigin::Tui, &shared, [0xAB; 32])
        .verdict
        .is_fresh();

    vec![
        format!(
            "daemon: running_killable={running_killable} holds_no_secret_or_wallet={holds_no_secret_or_wallet}"
        ),
        format!("daemon stopped: not_killable={stopped_not_killable} (Unknown not false-green)"),
        format!(
            "inbox: session={inbox_session} jobs={inbox_jobs} live_count={inbox_live} shared_id_space={shared_id_space}"
        ),
        format!(
            "reconnect: cli_fresh={cli_fresh} tg_fresh={tg_fresh} cli_tg_same_hash={cli_tg_same_hash}"
        ),
        format!("reconnect: stale_view_refused={stale_view_refused} (no silent stale-UI accept)"),
        "daemon: owns no secret/wallet; killable; CLI+TG one state_hash; reconnect refuses stale"
            .to_string(),
    ]
}

/// #637 (G.9.13) — the live CLI/TG `MessageEnvelope` equality surface. The CLI
/// and Telegram are two windows on the SAME envelope: a control verb classifies
/// to a byte-identical [`crate::command::CommandEnvelope`] on either channel
/// ([`same_command_across_channels`] / [`bridge`]) — only the
/// [`crate::commands::platform_telegram::PlatformOrigin`] differs (the
/// [`MessageSyncReceipt`]-style `equal = true`). Divergence is RED: two different
/// verbs are distinct commands, and a verb outside the closed control set is
/// refused fail-closed. The CLI and Telegram reconnect to ONE shared state hash,
/// so control / approval / route state cannot diverge by channel. Pure
/// local-only projection — no live action.
pub(crate) fn sync_live_lines() -> Vec<String> {
    use crate::commands::platform_telegram::PlatformOrigin;
    use crate::daemon::reconnect::{SharedRuntimeState, reconnect};
    use crate::telegram::envelope::{ControlVerb, bridge, same_command_across_channels};

    // --- envelope parity: every control verb is the SAME command on CLI or TG ---
    let all_channel_identical = ControlVerb::ALL
        .iter()
        .all(|&v| same_command_across_channels(v));
    let control_verb_count = ControlVerb::ALL.len();

    // --- sync receipt: the same verb yields an equal envelope on either channel ---
    let sync_equal = match (
        bridge(PlatformOrigin::Cli, "kill"),
        bridge(PlatformOrigin::Telegram, "kill"),
    ) {
        (Ok(cli), Ok(tg)) => cli.origin != tg.origin && cli.same_command(&tg),
        _ => false,
    };

    // --- divergence is RED: distinct verbs differ; a non-control verb is refused ---
    let different_verb_distinct = match (
        bridge(PlatformOrigin::Telegram, "kill"),
        bridge(PlatformOrigin::Telegram, "budget"),
    ) {
        (Ok(kill), Ok(budget)) => !kill.same_command(&budget),
        _ => false,
    };
    let forbidden_verb_refused = bridge(PlatformOrigin::Telegram, "sign").is_err();

    // --- shared control/approval/route state: CLI + TG observe ONE state_hash ---
    let shared = SharedRuntimeState {
        task_count_u32: 2,
        session_id_u64: 637,
        context_version_u32: 1,
        budget_remaining_micros_u64: 9_000,
    };
    let cli = reconnect(PlatformOrigin::Cli, &shared, shared.state_hash());
    let tg = reconnect(PlatformOrigin::Telegram, &shared, shared.state_hash());
    let cli_tg_one_state_hash = cli.current_hash_32 == tg.current_hash_32;

    vec![
        format!(
            "sync envelope: control_verbs={control_verb_count} all_channel_identical={all_channel_identical}"
        ),
        format!("sync receipt: equal={sync_equal} (same verb -> same CommandEnvelope CLI or TG)"),
        format!(
            "sync divergence: different_verb_distinct={different_verb_distinct} forbidden_verb_refused={forbidden_verb_refused}"
        ),
        format!(
            "sync state: cli_tg_one_state_hash={cli_tg_one_state_hash} (shared control/approval/route)"
        ),
        "CLI+TG = two windows on ONE MessageEnvelope; same verb same command; divergence=RED"
            .to_string(),
    ]
}

/// #638 (G.9.14) — the live control-express-under-load surface. STOP/freeze/pause
/// controls (`/kill`, `/budget cap lower`, `/pause`, `/lockdown`, provider freeze,
/// wallet/gas hard stop) ride a PREALLOCATED express lane
/// ([`ControlExpressRouter`]): each bypasses the saturated provider / audit /
/// memory / evidence background queues and is acknowledged synchronously, halting
/// the next side effect and never performing a live action. The shared budget cap
/// is re-checked BEFORE every side effect ([`BudgetKillIntegration`]) — lowering
/// the cap stops the next over-budget dispatch before it costs anything — and a
/// killed task can never write evidence in the background (no-zombie). Pure
/// local-only projection. Reused by `repl::run` (one control pipeline).
pub(crate) fn control_live_lines() -> Vec<String> {
    use crate::commands::budget::{BudgetCap, DispatchRequest};
    use crate::commands::kill::KillReason;
    use crate::daemon::budget_kill::{BudgetKillIntegration, SideEffectClass};
    use crate::daemon::control_express::{
        BackgroundQueueDepths, ControlExpressRouter, ExpressClass,
    };
    use crate::tui::job_rail::{JobKind, JobRailItem, JobState};

    // --- express lane: a STOP control bypasses a saturated bg queue and halts ---
    let mut router = ControlExpressRouter::new();
    let kill_ack = router.ack(
        ExpressClass::Kill,
        BackgroundQueueDepths::saturated(100_000),
    );
    let kill_bypasses = kill_ack.bypassed_queue;
    let live_action = kill_ack.live_action;
    let every_class_bypasses = ExpressClass::ALL.iter().all(|&c| c.bypasses_queue());

    let mut router2 = ControlExpressRouter::new();
    let _ = router2.ack(
        ExpressClass::BudgetCapLower,
        BackgroundQueueDepths::saturated(1_000),
    );
    let cap_lower_stops_next = !router2.next_side_effect_allowed();
    router2.resume();
    let resume_reenables = router2.next_side_effect_allowed();

    // --- budget kill: a lowered cap stops the NEXT side effect (re-checked before) ---
    let mut bk = BudgetKillIntegration::new(BudgetCap::new(100_000, 1_000_000, 100_000));
    bk.lower_cap(BudgetCap::new(0, 0, 100_000));
    let req = DispatchRequest {
        route_state: RouteExecutionState::Slow,
        input_tokens_u32: 100,
        output_tokens_u32: 50,
        estimated_cost_micro: Some(10),
        projected_ms_u32: 100,
        approved: false,
        reason_hash_32: [0u8; 32],
        route_trace_hash_32: [0u8; 32],
    };
    let cap_lowered_denies_dispatch = bk
        .authorize_side_effect(SideEffectClass::Provider, &req)
        .is_err();
    let all_side_effects_stopped = [
        SideEffectClass::Provider,
        SideEffectClass::Tool,
        SideEffectClass::Memory,
        SideEffectClass::Evidence,
    ]
    .iter()
    .all(|&c| bk.authorize_side_effect(c, &req).is_err());

    // --- kill: a killed task can never write evidence (no-zombie background write) ---
    let mut bk2 = BudgetKillIntegration::new(BudgetCap::new(100, 100, 1_000));
    bk2.kill_controller_mut().rail_mut().push(JobRailItem::new(
        1,
        JobKind::Measure,
        JobState::Running,
        demo_trace(638),
    ));
    let kill_ack2 = bk2.kill(1, KillReason::UserRequested, demo_trace(638));
    let killed = kill_ack2.final_state == JobState::Killed;
    let killed_cannot_write_evidence = !bk2.can_write_evidence(1);
    let unknown_denied = !bk2.can_write_evidence(404);

    vec![
        format!(
            "control express: kill_bypasses={kill_bypasses} live_action={live_action} every_class_bypasses={every_class_bypasses}"
        ),
        format!(
            "control express: cap_lower_stops_next={cap_lower_stops_next} resume_reenables={resume_reenables}"
        ),
        format!(
            "budget kill: cap_lowered_denies_dispatch={cap_lowered_denies_dispatch} all_side_effects_stopped={all_side_effects_stopped}"
        ),
        format!(
            "kill: killed={killed} killed_cannot_write_evidence={killed_cannot_write_evidence} unknown_denied={unknown_denied}"
        ),
        "control on a preallocated express lane (not job/serving/bg queue); halts only; 0 live action"
            .to_string(),
    ]
}

/// #640 (G.9.16) — the live checkpoint + restore + rollback/undo surface. A risk
/// command auto-checkpoints FIRST ([`CheckpointStore::requires_checkpoint`] —
/// local-write / wallet-sign / chain-write / admin do; read-only / network do
/// not), so no irreversible edit happens without a restore point. Restore and
/// undo are USER-CHANGE PROTECTED ([`RollbackController`]): a target the user
/// edited since the checkpoint is refused (no clobber without an explicit force),
/// a target already at the restore point is an idempotent no-op, and undo spans
/// files / task / all plus config and skill (the canonical `apply_rollback`)
/// rollback. Pure local-only projection — holds only content digests, never file
/// content; no live action.
pub(crate) fn checkpoint_live_lines() -> Vec<String> {
    use crate::commands::checkpoint::{CheckpointScope, CheckpointStore};
    use crate::commands::rollback::{RollbackController, RollbackReject, UndoScope};
    use mnemos_e_skill::{LocalSkillState, RollbackOp};

    let h = |s: u8| [s; 32];

    // --- a risk command auto-checkpoints first; a read-only one does not ---
    let risk_requires_checkpoint = CheckpointStore::requires_checkpoint(CommandRisk::LocalWrite);
    let readonly_no_checkpoint = !CheckpointStore::requires_checkpoint(CommandRisk::ReadOnly);

    // --- a controller with files / task / config auto-checkpoints (digests only) ---
    let mut ctrl = RollbackController::new();
    let _ = ctrl
        .store_mut()
        .auto_checkpoint(CheckpointScope::Files, h(1), h(2), demo_trace(640));
    let _ = ctrl
        .store_mut()
        .auto_checkpoint(CheckpointScope::Task, h(3), h(4), demo_trace(640));
    let _ = ctrl
        .store_mut()
        .auto_checkpoint(CheckpointScope::Config, h(5), h(6), demo_trace(640));
    let auto_checkpoints = ctrl.store().list().len();

    // --- undo files / task / all (observed == applied -> restore) ---
    let undo_files = ctrl.undo(UndoScope::Files, h(2), false).is_ok();
    let undo_task = ctrl.undo(UndoScope::Task, h(4), false).is_ok();
    let undo_all = ctrl.undo(UndoScope::All, h(6), false).is_ok();

    // --- restore is user-change protected + idempotent ---
    let user_change_protected = matches!(
        ctrl.undo(UndoScope::Files, h(99), false),
        Err(RollbackReject::UserChangeProtected)
    );
    let restore_idempotent_noop = matches!(
        ctrl.undo(UndoScope::Files, h(1), false),
        Ok(o) if o.idempotent_noop
    );

    // --- config + skill rollback (skill quarantine is terminal) ---
    let config_rollback = ctrl.config_rollback(h(6), false).is_ok();
    let skill_quarantine_terminal = matches!(
        RollbackController::skill_rollback(LocalSkillState::Enabled, RollbackOp::Quarantine),
        LocalSkillState::Revoked
    );

    vec![
        format!(
            "checkpoint: risk_requires_checkpoint={risk_requires_checkpoint} readonly_no_checkpoint={readonly_no_checkpoint}"
        ),
        format!(
            "checkpoint: auto_checkpoints={auto_checkpoints} restore_idempotent_noop={restore_idempotent_noop}"
        ),
        format!("restore: user_change_protected={user_change_protected} (no clobber without force)"),
        format!("undo: files={undo_files} task={undo_task} all={undo_all}"),
        format!(
            "rollback: config_rollback={config_rollback} skill_quarantine_terminal={skill_quarantine_terminal}"
        ),
        "auto-checkpoint before risk; restore user-change-protected; no irreversible edit w/o checkpoint"
            .to_string(),
    ]
}

/// #641 (G.9.17) — the live multisig/timelock + chain-env + gas-status surface,
/// with funds LOCKED. Every funds path is STATUS-VIEW-ONLY: the multisig timelock
/// ([`MultisigTimelockView`]) has `live_execution_enabled = false` and its
/// execute decision always denies (live mainnet execution is forbidden in this
/// phase); a mainnet write requires the multisig approval gate
/// ([`ChainEnvView::mainnet_write_requires_approval`] = true); the gas safety
/// gates are independent of telemetry ([`GasStatusView`]) and hold no secret; and
/// a gas SPONSOR can never sign the owner's intent ([`GasRequestPrecheck`] —
/// `sponsor_can_sign_owner_intent = false`, and a sponsor == owner request is
/// refused). The egress lift does NOT touch funds: wallet / gas / chain / mainnet
/// stay LOCKED. Pure local-only projection — secret-zero, 0 live funds action.
pub(crate) fn multisig_live_lines() -> Vec<String> {
    use crate::commands::chain_env::ChainEnvView;
    use crate::commands::gas_request::GasRequestPrecheck;
    use crate::commands::gas_status::GasStatusView;
    use crate::commands::multisig::MultisigTimelockView;
    use mnemos_a_core::{MainnetExecutionState, StageCChainEnv};
    use mnemos_d_move::{ObjectId, SuiAddress};
    use mnemos_g_wallet::{
        GasSponsorMode, MainnetSignerEnvelope, MultisigProposalEnvelope, MultisigRoster,
        OfficialTrustDecision, SponsoredFunction, TimelockPolicy,
    };

    // Build the queued multisig+timelock view from the canonical (fallible)
    // constructors; a fail-closed `None` still yields the same locked posture.
    fn mk_multisig_view() -> Option<MultisigTimelockView> {
        let roster = MultisigRoster::from_signers(
            &[
                SuiAddress::new([1; 32]),
                SuiAddress::new([2; 32]),
                SuiAddress::new([3; 32]),
            ],
            2,
        )
        .ok()?;
        let timelock = TimelockPolicy::from_parts(86_400, 3_600, true).ok()?;
        let proposal = MultisigProposalEnvelope::new(
            ObjectId::new([0x22; 32]),
            [0xAB; 32],
            [0xCD; 32],
            &roster,
        )
        .ok()?;
        let signer = MainnetSignerEnvelope::from_timelock(
            ObjectId::new([0x22; 32]),
            [0xAB; 32],
            [0xCD; 32],
            &timelock,
            1_000,
        )
        .ok()?;
        Some(MultisigTimelockView::new(
            proposal,
            signer,
            roster,
            timelock,
            2,
            MainnetExecutionState::TimelockQueued,
        ))
    }

    // --- multisig: live execution is forbidden; the decision always denies ---
    let (live_execution_enabled, execute_decision_denied) = match mk_multisig_view() {
        // eta = 1_000 + 86_400 = 87_400 -> sigs met + timelock matured -> still denied.
        Some(v) => (
            v.live_execution_enabled(),
            v.execute_decision(87_400).is_denied(),
        ),
        None => (false, true),
    };

    // --- chain env: a mainnet write always requires the multisig approval gate ---
    let chain = ChainEnvView::new(
        StageCChainEnv::TestnetVerified,
        MainnetExecutionState::Locked,
        GasSponsorMode::None,
        ObjectId::new([0x33; 32]),
        "fullnode.testnet",
    );
    let mainnet_write_requires_approval = chain.mainnet_write_requires_approval();
    let env_consistent = chain.env_consistent();

    // --- gas status: the safety gates are independent of telemetry; no secret ---
    let gas = GasStatusView::new(
        GasSponsorMode::None,
        OfficialTrustDecision::LocalOnly,
        &[0x44; 32],
        &[0x55; 32],
        100,
        1_000,
        10,
        500,
        0,
    );
    let gates_independent = gas.gates_independent_of_telemetry();
    let secrets_absent = gas.secrets_absent();

    // --- gas request: a sponsor never signs the owner's intent; sponsor != owner ---
    let precheck = GasRequestPrecheck {
        function: SponsoredFunction::MemoryAddChunk,
        allowed_mask_u16: 0,
        dry_run_ok: true,
        within_quota: true,
        lease_active: true,
        owner_pubkey_32: [0x66; 32],
        sponsor_pubkey_32: [0x77; 32],
    };
    let sponsor_can_sign_owner_intent = precheck.sponsor_can_sign_owner_intent();
    let sponsor_eq_owner_denied = GasRequestPrecheck {
        sponsor_pubkey_32: [0x66; 32],
        ..precheck
    }
    .evaluate()
    .is_err();

    vec![
        format!(
            "multisig: live_execution_enabled={live_execution_enabled} execute_decision_denied={execute_decision_denied}"
        ),
        format!(
            "chain env: mainnet_write_requires_approval={mainnet_write_requires_approval} env_consistent={env_consistent}"
        ),
        format!(
            "gas status: gates_independent_of_telemetry={gates_independent} secrets_absent={secrets_absent}"
        ),
        format!(
            "gas request: sponsor_can_sign_owner_intent={sponsor_can_sign_owner_intent} sponsor_eq_owner_denied={sponsor_eq_owner_denied}"
        ),
        "funds LOCKED (wallet/gas/chain/mainnet); status-view-only; 0 live funds action"
            .to_string(),
    ]
}

/// #642 (G.9.18) — the live safety-kernel feature-lock surface. The 10
/// [`SAFETY_KERNEL_FEATURES`] (redaction / capability_diff / no_silent_fallback /
/// no_auto_merge / wallet_preview / gas_drain_invariants / mainnet_approval /
/// skill_sandbox / evidence_trace / self_evolution) are a protocol-critical
/// boundary, NOT a toggle: a [`feature_toggle`] that tries to DISABLE any of them
/// fails with [`crate::CliError::SafetyKernelLocked`] (no profile can weaken it),
/// while ordinary user features remain toggleable. A broken kernel renders
/// [`SafetyKernelTrust::Quarantined`] regardless of any other claim
/// ([`safety_kernel_trust`]), and learning / egress default OFF. Pure local-only
/// projection — no live action.
pub(crate) fn safety_kernel_live_lines() -> Vec<String> {
    use crate::config::{
        DataEgressMode, FeatureState, LearningControlView, LearningMode, SAFETY_KERNEL_FEATURES,
        feature_toggle, is_safety_kernel_feature,
    };
    use crate::doctor::{SafetyKernelTrust, safety_kernel_trust};

    // --- the 10 safety-kernel features are non-disableable (locked) ---
    let kernel_feature_count = SAFETY_KERNEL_FEATURES.len();
    let all_are_kernel = SAFETY_KERNEL_FEATURES
        .iter()
        .all(|f| is_safety_kernel_feature(f));
    let all_disable_denied = SAFETY_KERNEL_FEATURES
        .iter()
        .all(|f| feature_toggle(f, FeatureState::Disabled).is_err());

    // --- an ordinary user feature is still toggleable (only the kernel is locked) ---
    let non_kernel_toggleable =
        feature_toggle("user_experimental_flag", FeatureState::Disabled).is_ok();

    // --- a broken kernel quarantines; an intact local kernel is local-only trust ---
    let intact_local_only = matches!(
        safety_kernel_trust(true, false, false),
        SafetyKernelTrust::LocalOnly
    );
    let broken_quarantined = matches!(
        safety_kernel_trust(false, true, true),
        SafetyKernelTrust::Quarantined
    );

    // --- learning / egress default OFF ---
    let learn = LearningControlView::default();
    let learning_off = matches!(learn.mode, LearningMode::Off);
    let egress_none = matches!(learn.egress, DataEgressMode::None);

    vec![
        format!(
            "kernel features: count={kernel_feature_count} all_kernel={all_are_kernel} all_disable_denied={all_disable_denied}"
        ),
        format!(
            "kernel toggle: non_kernel_toggleable={non_kernel_toggleable} (kernel-disable denied)"
        ),
        format!(
            "kernel trust: intact_local_only={intact_local_only} broken_quarantined={broken_quarantined}"
        ),
        format!(
            "learning/egress: learning_off={learning_off} egress_none={egress_none} (default OFF)"
        ),
        "safety kernel = protocol boundary not a toggle; 10 non-disableable; learning/egress OFF"
            .to_string(),
    ]
}

/// #643 (G.9.19) — the live capability-diff + sandbox-tier + tool-bridge surface.
/// A capability diff ([`CapabilityDiff`]) is shown BEFORE any tool/skill
/// execution and a GAIN renders DEGRADED (Yellow — never a silent grant), a
/// hidden permission is denied ([`detect_hidden_permission`]), the sandbox tier
/// ceiling is immutable ([`Sandbox`] — warmup never raises it), and a tool
/// dispatch goes through the Tool Adapter Abstraction with NO bypass
/// ([`bridge_view`]: only an `Approved` tool runs, and network egress is denied by
/// default). Pure local-only projection — no live action.
pub(crate) fn capability_live_lines() -> Vec<String> {
    use crate::command::{CommandRisk, approval_for};
    use crate::commands::capability::{
        CapabilityDiff, CapabilityKind, CapabilitySet, detect_hidden_permission,
    };
    use crate::commands::sandbox::{Sandbox, SandboxTier};
    use crate::commands::tool::{ToolAdapterKind, ToolCallView, ToolState};
    use crate::tool::budget_bridge::bridge_view;

    // --- capability diff shown BEFORE exec: a gain renders DEGRADED (not silent) ---
    let before = CapabilitySet::with(CapabilityKind::PureCompute);
    let after = before.insert(CapabilityKind::Network);
    let cdiff = CapabilityDiff::new(before, after);
    let gain_before_exec = cdiff.gained_capability();
    let cap_truth = truth_label(cdiff.render_truth());
    let requires_approval = cdiff.requires_approval();

    // --- a hidden permission (declared < required) is denied ---
    let declared =
        CapabilitySet::with(CapabilityKind::PureCompute).insert(CapabilityKind::ReadLocal);
    let required = declared.insert(CapabilityKind::Network);
    let hidden_permission_denied = detect_hidden_permission(declared, required);

    // --- sandbox tier ceiling is immutable (warmup never raises it) ---
    let mut sb = Sandbox::new(SandboxTier::Networked);
    let allowed_before = sb.allowed_capabilities().count();
    let _ = sb.warmup();
    let tier_ceiling_immutable = sb.allowed_capabilities().count() == allowed_before;

    // --- no adapter bypass: an Approved non-network tool runs THROUGH the adapter;
    // a network-egress tool is denied by default ---
    let approved_local = ToolCallView {
        adapter: ToolAdapterKind::Python,
        tool_id_hash_32: [0x11; 32],
        capabilities: CapabilitySet::with(CapabilityKind::ReadLocal),
        sandbox_tier_u8: 2,
        risk: CommandRisk::ReadOnly,
        approval: approval_for(CommandRisk::ReadOnly),
        state: ToolState::Approved,
    };
    let runnable_through_adapter = bridge_view(&approved_local).runnable;
    let net_tool = ToolCallView {
        adapter: ToolAdapterKind::HttpService,
        ..approved_local
    };
    let network_egress_denied = !bridge_view(&net_tool).runnable;

    vec![
        format!(
            "capability: gain_before_exec={gain_before_exec} truth={cap_truth} requires_approval={requires_approval}"
        ),
        format!("capability: hidden_permission_denied={hidden_permission_denied} (declared<required)"),
        format!("sandbox: tier_ceiling_immutable={tier_ceiling_immutable} (warmup never raises)"),
        format!(
            "tool bridge: runnable_through_adapter={runnable_through_adapter} network_egress_denied={network_egress_denied}"
        ),
        "capability diff shown before exec (gain=DEGRADED); tier ceiling immutable; no adapter bypass"
            .to_string(),
    ]
}

/// #645 (G.9.21) — the live wallet/key/gas surface, status-only with funds
/// LOCKED. Wallet status is read from the PUBLIC key only (no seed; the keystore
/// is a [`SecretRefView`] whose value is never loaded — `secret_custody_ok`), the
/// memory owner is always a different key from the gas sponsor
/// (`owner_is_not_sponsor`), and the rendered status passes the [`key_leak_scan`].
/// A signature is PREVIEW-ONLY ([`SignSimulatePreview`]: `live_signing_enabled =
/// false`, a decoded human-checkable intent, the [`ApprovalRequirement::TypedPhrase`]
/// gate); an opaque (blind) payload is denied ([`preview_opaque_denied`]); and the
/// key doctor ([`audit_refs`]) reports secret-zero (an inline secret breaks it).
/// Pure local-only projection — sign is never executed in Phase 0.
pub(crate) fn wallet_live_lines() -> Vec<String> {
    use crate::command::ApprovalRequirement;
    use crate::commands::wallet::{
        MemoryOwnerBinding, WalletAuthKind, WalletStatusView, key_leak_scan,
    };
    use crate::commands::wallet_sign::{
        DecodedIntentView, SignSimulatePreview, SimulateOutcome, preview_opaque_denied,
    };
    use crate::doctor::key::audit_refs;
    use mnemos_g_wallet::{SignerBackendKind, SignerBoundaryError};

    // --- wallet status from the PUBLIC key only; owner != gas sponsor; no key leak ---
    let owner = MemoryOwnerBinding::new([0x11; 32], Some([0x22; 32]));
    let wallet = WalletStatusView::connect(WalletAuthKind::ZkLogin, owner, None, "keychain:wallet");
    let secret_custody_ok = wallet.secret_custody_ok();
    let key_material_loaded = wallet.key_material_loaded;
    let owner_is_not_sponsor = owner.owner_is_not_sponsor();
    let render_no_key_leak = !key_leak_scan(&wallet.render(32));

    // --- a signature is PREVIEW-ONLY: decoded intent + dry-run; live signing off ---
    let decoded = DecodedIntentView::new(
        &[0x33; 32],
        "memory::add_chunk",
        1_000,
        &[0x44; 32],
        &[0x55; 32],
        87_400,
    );
    let preview = SignSimulatePreview::from_decoded(
        decoded,
        SimulateOutcome::Ok,
        1_000,
        SignerBackendKind::Kms,
    );
    let live_signing_enabled = preview.live_signing_enabled;
    let approval_typed_phrase = matches!(preview.approval, ApprovalRequirement::TypedPhrase);
    let signable_preview_only = preview.is_signable();

    // --- an opaque (blind) payload is denied; the key doctor reports secret-zero ---
    let opaque_denied = matches!(
        preview_opaque_denied(b"\x00\x01opaque-bytes"),
        SignerBoundaryError::OpaquePayloadRejected
    );
    let key_doctor_secret_zero = audit_refs(
        &[
            ("provider", "env:ANTHROPIC_API_KEY"),
            ("wallet", "keychain:owner"),
        ],
        &["learning_mode = \"off\""],
    )
    .secret_zero;
    let inline_secret_breaks_zero =
        !audit_refs(&[], &["leaked = \"suiprivkey1qexamplenotreal\""]).secret_zero;

    vec![
        format!(
            "wallet status: secret_custody_ok={secret_custody_ok} owner_is_not_sponsor={owner_is_not_sponsor}"
        ),
        format!(
            "wallet keys: key_material_loaded={key_material_loaded} render_no_key_leak={render_no_key_leak}"
        ),
        format!(
            "sign preview: live_signing_enabled={live_signing_enabled} approval_typed_phrase={approval_typed_phrase}"
        ),
        format!(
            "sign opaque: blind_sign_denied={opaque_denied} signable_preview_only={signable_preview_only}"
        ),
        format!(
            "key doctor: secret_zero={key_doctor_secret_zero} inline_secret_breaks_zero={inline_secret_breaks_zero}"
        ),
        "funds LOCKED: status from public key only; sign preview-only (NOT executed); secret-zero"
            .to_string(),
    ]
}

/// #646 (G.9.22) — the live candidate≠finding + no-authority-expansion surface.
/// An audit candidate ([`AuditGameTreeCandidate`]) is PATTERN-ONLY: it never
/// becomes a finding / high-reward / external report without a reproduced,
/// node-matching, safe-local [`LocalReproRunnerReceipt`] — a non-reproduced
/// receipt never promotes, a reproduced one does. No-authority-expansion is
/// STRUCTURAL: [`crate::trace::TraceWriter::try_apply_self_evolution`] returns a
/// `Result<core::convert::Infallible, _>` — an UNINHABITED success that can never
/// be `Ok`, so applying a self-evolution is impossible (a better Naite gains no
/// new rights: no self-modifying production path, no safety-kernel edit by the
/// model, performance != authority). Pure local-only projection.
pub(crate) fn finding_live_lines() -> Vec<String> {
    use crate::audit::candidate::{AuditGameTreeCandidate, CandidateOrigin};
    use crate::audit::repro_receipt::{LocalReproRunnerReceipt, ReproReceiptHashes};
    use crate::commands::eval_core::AuditCandidate;
    use crate::config::LearningMode;
    use crate::trace::TraceWriter;
    use mnemos_l_dataset::AtomDietKey;
    use mnemos_l_dataset::diet_kind::DietSourceStage;
    use mnemos_l_dataset::security::source::SecuritySeverity;

    let node: u8 = 5;
    let candidate = AuditGameTreeCandidate {
        inner: AuditCandidate {
            rule_id_hash_32: [0x11; 32],
            location_hash_32: [0x22; 32],
            invariant_hash_32: [0x33; 32],
            evidence_hash_32: [0x44; 32],
            confidence_bps_u16: 7000,
            repro_plan_safe_local: true,
            local_repro_done: false,
        },
        origin: CandidateOrigin::PatternMatch,
        node_hash_32: [node; 32],
    };
    let mk_key = || AtomDietKey::new(DietSourceStage::StageD, 253);
    let mk_receipt = |reproduced: bool| {
        LocalReproRunnerReceipt::record(
            &ReproReceiptHashes {
                node_hash_32: [node; 32],
                command_hash_32: [2; 32],
                fixture_hash_32: [3; 32],
                result_hash_32: [4; 32],
            },
            reproduced,
            false,
            false,
        )
    };

    // --- candidate != finding: pattern-only; a non-reproduced receipt never promotes ---
    let pattern_only = candidate.is_pattern_only();
    let non_repro_promotes = match mk_receipt(false) {
        Ok(r) => candidate
            .promote(&r, mk_key(), SecuritySeverity::High)
            .is_ok(),
        Err(_) => false,
    };
    // --- a reproduced, node-matching receipt promotes to a canonical finding ---
    let repro_promotes_to_finding = match mk_receipt(true) {
        Ok(r) => candidate
            .promote(&r, mk_key(), SecuritySeverity::High)
            .is_ok(),
        Err(_) => false,
    };

    // --- no-authority-expansion: self-evolution apply is structurally impossible ---
    let tw = TraceWriter::new(LearningMode::Off);
    let self_evolution_apply_impossible = tw.try_apply_self_evolution().is_err();

    vec![
        format!(
            "candidate: pattern_only={pattern_only} non_repro_promotes={non_repro_promotes} (candidate!=finding)"
        ),
        format!(
            "finding: repro_promotes_to_finding={repro_promotes_to_finding} (needs LocalReproRunnerReceipt)"
        ),
        format!(
            "self-evolution: apply_impossible={self_evolution_apply_impossible} (uninhabited success)"
        ),
        "candidate!=finding (no claim w/o local repro); performance!=authority; no kernel edit by model"
            .to_string(),
    ]
}

/// #647 (G.9.23) — the live §10 designed-impossibility summary. These are
/// STRUCTURAL invariants, not mitigations: a loop always carries a finite
/// token/cost/deadline [`BudgetCap`] (an infinite loop is unrepresentable —
/// runaway); learning defaults OFF with no egress and user memory excluded
/// (memory-misuse); a secret is a [`crate::secrets::SecretRefView`] reference
/// whose value is never loaded (no baked key — key-security); and the Stage-H
/// handoff is verified and FAILS CLOSED if training / GRPO is unlocked
/// ([`verify_handoff`] — completion / no-authority-expansion). Reward never takes
/// a self-report (#634) and every change is rollback-able (#640); performance is
/// never authority. Pure local-only projection.
pub(crate) fn ten_live_lines() -> Vec<String> {
    use crate::commands::budget::BudgetCap;
    use crate::config::{DataEgressMode, LearningControlView, LearningMode};
    use crate::secrets::classify_reference;
    use crate::{HandoffInputs, StageGUnlockView, verify_handoff};

    // --- runaway: every loop carries a finite token/cost/deadline budget ---
    let cap = BudgetCap::new(5_000, 1_000_000, 30_000);
    let v = cap.view();
    let loop_bounded = v.token_remaining_u32 > 0 && v.deadline_ms_u32 > 0;

    // --- memory-misuse: no-training default + no egress; key-security: no baked key ---
    let learn = LearningControlView::default();
    let no_training_default = matches!(learn.mode, LearningMode::Off);
    let egress_none = matches!(learn.egress, DataEgressMode::None);
    let no_baked_key = classify_reference("wallet_key", "env:WALLET_KEY").value_never_loaded;

    // --- completion / no-authority-expansion: handoff verified + fails closed ---
    let inputs = HandoffInputs {
        atom_plan_a: b"a",
        stage_b_plan: b"b",
        stage_c_plan: b"c",
        stage_d_plan: b"d",
        stage_e_plan: b"e",
        stage_e_dod: b"dod",
        command_grammar: b"grammar",
    };
    let locked = StageGUnlockView {
        sft_smoke_ready: false,
        grpo_locked: true,
        self_evolution_promotion_locked: true,
    };
    let handoff_verified = verify_handoff(&inputs, locked).is_ok();
    let unlocked = StageGUnlockView {
        grpo_locked: false,
        ..locked
    };
    let training_unlock_denied = verify_handoff(&inputs, unlocked).is_err();

    vec![
        format!("s10 runaway: loop_bounded={loop_bounded} (finite token+money+deadline budget)"),
        format!(
            "s10 memory: no_training_default={no_training_default} egress_none={egress_none} no_baked_key={no_baked_key}"
        ),
        format!(
            "s10 completion: handoff_verified={handoff_verified} training_unlock_denied={training_unlock_denied}"
        ),
        "s10 designed-impossibilities: structural invariants not mitigations; reward!=self-report"
            .to_string(),
    ]
}

/// The interactive cockpit state machine. Holds the pure [`CockpitShell`] /
/// [`TabRouter`] projections, the active view, a recomputed-on-dirty line cache,
/// and a reused frame string (the zero-alloc steady-state redraw buffer).
struct Cockpit {
    shell: CockpitShell,
    router: TabRouter,
    view: CockpitView,
    lines: Vec<String>,
    frame: String,
    frames_drawn: u32,
}

impl Cockpit {
    fn new() -> Self {
        let mut shell = CockpitShell::new();
        shell.boot();
        Self {
            shell,
            router: TabRouter::new(),
            view: CockpitView::Tab,
            lines: Vec::with_capacity(64),
            frame: String::with_capacity(4096),
            frames_drawn: 0,
        }
    }

    /// Apply one event; returns whether the frame is now dirty (needs a redraw).
    fn handle_event(&mut self, ev: CockpitEvent) -> bool {
        match ev {
            CockpitEvent::Quit => {
                self.shell.request_quit();
                true
            }
            CockpitEvent::Tab(TabNav::Next) => {
                self.router.next();
                self.view = CockpitView::Tab;
                true
            }
            CockpitEvent::Tab(TabNav::Prev) => {
                self.router.prev();
                self.view = CockpitView::Tab;
                true
            }
            CockpitEvent::Tab(TabNav::Select(i)) => {
                let ok = self.router.select(i);
                if ok {
                    self.view = CockpitView::Tab;
                }
                ok
            }
            CockpitEvent::View(v) => {
                let changed = self.view != v;
                self.view = v;
                changed
            }
            CockpitEvent::Ignore => false,
        }
    }

    fn quitting(&self) -> bool {
        matches!(self.shell.phase(), ShellPhase::Quitting)
    }

    fn close(&mut self) {
        self.shell.close();
    }

    fn chrome_lines(&self) -> Vec<String> {
        let prompt = demo_prompt();
        let bar = StatusBar::new(
            prompt,
            RouteExecutionState::Normal,
            RenderTruth::Unknown,
            RenderTruth::Unknown,
        );
        let rail = JobRail::new();
        vec![
            format!(
                "SINABRO cockpit  phase={}  view={}",
                phase_label(self.shell.phase()),
                view_label(self.view)
            ),
            // Fixed-width safety banner (never truncated): the locked posture is
            // always visible regardless of the variable phase/view widths above.
            "LOCAL-ONLY  NO-LIVE-ACTION  funds=LOCKED  candidate!=finding".to_string(),
            format!(
                "route={} ctx={} healthy={} | {}",
                truth_label(bar.route_truth()),
                truth_label(bar.context_truth()),
                bar.is_healthy(),
                render_status_strip(&prompt)
            ),
            tab_bar(&self.router),
            format!(
                "job-rail: live={} total={} (no-zombie; control-express kill ready)",
                rail.live_count(),
                rail.items().len()
            ),
        ]
    }

    fn center_lines(&self) -> Vec<String> {
        let raw = match self.view {
            CockpitView::Tab => {
                let tab = self.router.selected_tab();
                if matches!(tab, CockpitTab::Trace) {
                    trace_pane_lines()
                } else {
                    namespace_center(tab)
                }
            }
            CockpitView::Gas => gas_drain_lines(),
            CockpitView::Jobs => jobs_lines(),
            CockpitView::Skills => skill_cards_lines(),
            CockpitView::Provider => provider_health_lines(),
            CockpitView::Platform => platform_lines(),
            CockpitView::Approval => approval_demo_lines(),
            CockpitView::Inspector => inspector_lines(),
            CockpitView::Audit => audit_game_tree_lines(),
            CockpitView::Detectors => audit_detectors_lines(),
            CockpitView::Bundle => audit_bundle_lines(),
            CockpitView::Memory => memory_commands_lines(),
            CockpitView::MemoryIntel => memory_intel_lines(),
            CockpitView::Evidence => evidence_pack_lines(),
            CockpitView::EvidenceReplay => evidence_replay_lines(),
            CockpitView::SkillLive => skill_live_lines(),
            CockpitView::SkillPackage => skill_package_lines(),
            CockpitView::DatasetLive => dataset_live_lines(),
            CockpitView::EvalLive => eval_live_lines(),
            CockpitView::DaemonLive => daemon_live_lines(),
            CockpitView::SyncLive => sync_live_lines(),
            CockpitView::ControlLive => control_live_lines(),
            CockpitView::CheckpointLive => checkpoint_live_lines(),
            CockpitView::MultisigLive => multisig_live_lines(),
            CockpitView::SafetyKernelLive => safety_kernel_live_lines(),
            CockpitView::CapabilityLive => capability_live_lines(),
            CockpitView::WalletLive => wallet_live_lines(),
            CockpitView::FindingLive => finding_live_lines(),
            CockpitView::TenLive => ten_live_lines(),
        };
        raw.into_iter()
            .take(CENTER_ROWS)
            .map(|s| clamp80(&s))
            .collect()
    }

    fn footer_line() -> String {
        clamp80(
            "[n/Tab]next [p]prev [1-9]tab | [d]audit [f]detect [b]bundle [r]mem [c]intel [e]evid [l]replay [s]skill-live [h]pkg [o]data [u]eval [w]daemon [x]sync [y]control [z]ckpt [M]msig [K]kernel [P]cap [L]wallet [F]finding [T]s10 \
             [g]as [j]obs [k]skill [v]prov [m]platform [a]pproval [i]nspect [t]ab | [q]uit",
        )
    }

    /// Recompute the cached line set (only called on a dirty event, never on the
    /// steady-state redraw — that keeps the redraw allocation-free).
    fn recompute(&mut self) {
        self.lines.clear();
        for l in self.chrome_lines() {
            self.lines.push(clamp80(&l));
        }
        self.lines.extend(self.center_lines());
        self.lines.push(Self::footer_line());
    }

    /// Serialize the cached lines into the reused frame buffer and write them. The
    /// frame `String` retains its capacity across redraws, so a redraw with no
    /// preceding `recompute` performs no heap allocation (the zero-alloc hot path).
    fn redraw<W: Write>(&mut self, out: &mut W, mode: RenderMode) -> io::Result<()> {
        let frame = &mut self.frame;
        frame.clear();
        match mode {
            // Plain: pure ASCII, zero escape (headless / pipe / snapshot / checker).
            RenderMode::Plain => {
                for line in &self.lines {
                    frame.push_str(line);
                    frame.push('\n');
                }
            }
            // Ansi: the rich cockpit (Unicode box + SGR color + CRLF; raw-safe),
            // sized to the live terminal width (wraps wide lines; no overflow).
            RenderMode::Ansi => render_rich_frame(frame, &self.lines, term_cols()),
        }
        out.write_all(frame.as_bytes())?;
        out.flush()?;
        self.frames_drawn = self.frames_drawn.saturating_add(1);
        Ok(())
    }

    fn summary(&self) -> TuiSummary {
        TuiSummary {
            frames_drawn: self.frames_drawn,
            final_tab_index: self.router.selected_index() % TAB_COUNT,
            quit_clean: matches!(self.shell.phase(), ShellPhase::Closed),
        }
    }
}

/// The terminal harness (atom #570): enters the alt-screen + hides the cursor and
/// installs raw mode, restoring everything on `Drop` (panic-safe RAII). Holds the
/// isolated [`crate::tui::raw::RawModeGuard`]; `None` on a non-TTY (cooked input).
struct TerminalGuard {
    _raw: Option<crate::tui::raw::RawModeGuard>,
}

impl TerminalGuard {
    /// Enter the alt-screen, hide the cursor, and switch to raw mode. The
    /// alt-screen escape write can fail (broken pipe) and is propagated; raw mode
    /// fails closed (cooked fallback) and never errors.
    fn install() -> io::Result<Self> {
        let mut so = io::stdout().lock();
        // alt-screen on + hide cursor (cursor-control only; never SGR color).
        so.write_all(b"\x1b[?1049h\x1b[?25l")?;
        so.flush()?;
        Ok(Self {
            _raw: crate::tui::raw::RawModeGuard::enter(),
        })
    }
}

impl Drop for TerminalGuard {
    fn drop(&mut self) {
        // Best-effort restore on every exit path (including an unwind under a
        // panic=unwind build): show cursor + leave alt-screen, then the raw guard
        // drops (restoring termios). Teardown never panics.
        let mut so = io::stdout().lock();
        let _ = so.write_all(b"\x1b[?25h\x1b[?1049l");
        let _ = so.flush();
        // self._raw drops here -> termios restored.
    }
}

/// The core event loop (atoms #571/#572): draw the first frame, then read input
/// events, drive the [`Cockpit`] state machine, and redraw on every dirty change
/// until EOF or quit. Generic over the input reader and output writer so it is
/// fully testable headlessly (no terminal required) and pty/headless-injectable.
fn event_loop<R: Read, W: Write>(
    input: &mut R,
    out: &mut W,
    mode: RenderMode,
) -> io::Result<TuiSummary> {
    let mut cockpit = Cockpit::new();
    cockpit.recompute();
    cockpit.redraw(out, mode)?;
    let mut buf = [0u8; READ_BUF];
    loop {
        let n = input.read(&mut buf)?;
        if n == 0 {
            // EOF: exit the loop (the shell closes below).
            break;
        }
        let mut dirty = false;
        for &b in &buf[..n] {
            if cockpit.handle_event(decode_key(b)) {
                dirty = true;
            }
            if cockpit.quitting() {
                break;
            }
        }
        if cockpit.quitting() {
            cockpit.close();
            cockpit.recompute();
            cockpit.redraw(out, mode)?;
            return Ok(cockpit.summary());
        }
        if dirty {
            cockpit.recompute();
            cockpit.redraw(out, mode)?;
        }
    }
    // EOF path: close the shell so the summary reflects a clean teardown.
    cockpit.close();
    Ok(cockpit.summary())
}

/// Launch the interactive TUI cockpit (`sinabro tui`). On a real terminal this
/// installs the raw-mode + alt-screen [`TerminalGuard`] and uses the in-place ANSI
/// renderer; on a non-TTY (pipe / CI / headless) it renders plain frames and exits
/// at EOF (never hangs). The terminal is restored on every exit path.
///
/// # Errors
/// Propagates an [`io::Error`] from reading input or writing a frame (e.g. a
/// broken pipe). There is no panic / unwrap path.
pub fn launch() -> io::Result<()> {
    let stdin = io::stdin();
    let interactive = stdin.is_terminal() && io::stdout().is_terminal();
    if interactive {
        let _guard = TerminalGuard::install()?;
        let mut input = stdin.lock();
        let mut out = io::stdout().lock();
        let _summary = event_loop(&mut input, &mut out, RenderMode::Ansi)?;
        Ok(())
    } else {
        let mut input = stdin.lock();
        let mut out = io::stdout().lock();
        let _summary = event_loop(&mut input, &mut out, RenderMode::Plain)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;
    use crate::repl::latency::{LatencyBudget, LatencyScore, p95_ms};
    use std::io::Cursor;

    fn run_bytes(input: &[u8]) -> (TuiSummary, String) {
        let mut reader = Cursor::new(input.to_vec());
        let mut out: Vec<u8> = Vec::new();
        let summary = event_loop(&mut reader, &mut out, RenderMode::Plain)
            .unwrap_or_else(|_| panic!("in-memory io never fails"));
        (summary, String::from_utf8_lossy(&out).into_owned())
    }

    #[test]
    fn empty_input_draws_one_frame_then_eof_closes_clean() {
        let (summary, text) = run_bytes(b"");
        // A real loop draws the first frame even with no input, then EOF closes.
        assert_eq!(summary.frames_drawn, 1);
        assert!(summary.quit_clean);
        assert!(text.contains("SINABRO cockpit"));
        assert!(text.contains("tabs:"));
    }

    #[test]
    fn quit_byte_closes_and_restores() {
        let (summary, _) = run_bytes(b"q");
        assert!(summary.quit_clean, "q must close the shell cleanly");
        // first frame + the post-quit frame.
        assert!(summary.frames_drawn >= 2);
    }

    #[test]
    fn ctrl_c_and_ctrl_d_also_quit() {
        for b in [0x03u8, 0x04] {
            let (summary, _) = run_bytes(&[b]);
            assert!(summary.quit_clean, "0x{b:02x} must quit");
        }
    }

    #[test]
    fn tab_navigation_advances_and_wraps_14() {
        // 'n' three times -> tab index 3.
        let (summary, _) = run_bytes(b"nnn");
        assert_eq!(summary.final_tab_index, 3);
        // 14 nexts wrap back to 0.
        let (wrapped, _) = run_bytes(b"nnnnnnnnnnnnnn");
        assert_eq!(wrapped.final_tab_index, 0);
        // 'p' from 0 wraps to the last tab (13).
        let (prev, _) = run_bytes(b"p");
        assert_eq!(prev.final_tab_index, TAB_COUNT - 1);
    }

    #[test]
    fn digit_selects_tab() {
        let (summary, _) = run_bytes(b"5");
        assert_eq!(summary.final_tab_index, 4); // '5' -> tab 4
    }

    #[test]
    fn unknown_byte_is_a_noop_no_extra_frame() {
        // 'Z' is not bound -> Ignore -> no redraw beyond the initial frame.
        let (summary, _) = run_bytes(b"Z");
        assert_eq!(summary.frames_drawn, 1);
    }

    #[test]
    fn every_dashboard_view_renders_real_content() {
        // Each dashboard key switches the center and renders its pane.
        let cases: &[(u8, &str)] = &[
            (b'g', "gas-drain gates:"),
            (b'j', "jobs/tasks:"),
            (b'k', "skill cards:"),
            (b'v', "provider-health:"),
            (b'm', "platform:"),
            (b'a', "approval modal"),
            (b'i', "inspector:"),
        ];
        for (key, needle) in cases {
            let (_, text) = run_bytes(&[*key]);
            assert!(text.contains(needle), "view {key} missing {needle}: {text}");
        }
    }

    #[test]
    fn trace_tab_uses_the_paged_pane() {
        // Tab index 1 is Trace -> routed through the paged trace pane.
        let (_, text) = run_bytes(b"2"); // '2' -> tab 1 (Trace)
        assert!(text.contains("trace pane:"));
        assert!(text.contains("full_render_denied=true"));
    }

    #[test]
    fn plain_render_is_colorless_no_escape_sequences() {
        // The Plain (headless / snapshot) frame must contain ZERO escape bytes. This
        // is the PLAIN-path half of the redefined `G-G-TERMINAL-DESIGN` gate
        // (rich-but-not-cringe, contract §3.1): the no-color path stays colorless +
        // readable, while the Ansi path is rich — see the sibling
        // `ansi_frame_is_rich_boxed_colored_crlf`.
        let (_, text) = run_bytes(b"njka");
        assert!(
            !text.contains('\u{1b}'),
            "plain frames must be escape-free (no-color readable)"
        );
        for line in text.lines() {
            assert!(line.is_ascii(), "non-ascii line: {line}");
            assert!(
                line.chars().count() <= MAX_COLS,
                "line over 80 cols: {line}"
            );
        }
    }

    #[test]
    fn ansi_frame_is_rich_boxed_colored_crlf() {
        // The Ansi (real-TTY) frame is the rich cockpit: a unicode box, SGR color,
        // and CRLF endings (so raw mode with OPOST off does not stair-step). This
        // is the regression guard for the staircase bug the Plain-only suite missed.
        let mut cockpit = Cockpit::new();
        cockpit.recompute();
        let mut sink = Vec::new();
        cockpit
            .redraw(&mut sink, RenderMode::Ansi)
            .expect("ansi draw");
        let s = String::from_utf8(sink).expect("utf8 frame");
        assert!(
            s.contains('┌') && s.contains('│') && s.contains('└'),
            "rich frame must draw a unicode box"
        );
        assert!(s.contains('\u{1b}'), "rich frame must carry SGR color");
        assert!(
            s.contains("\r\n"),
            "rich frame must use CRLF (raw-safe; no staircase)"
        );
        assert_eq!(
            s.matches('\n').count(),
            s.matches("\r\n").count(),
            "every LF must be part of a CRLF (no bare LF -> no stair-step)"
        );
        assert!(
            s.contains("SINABRO cockpit"),
            "chrome content preserved inside the box"
        );
    }

    /// Strip CSI escape sequences (`\x1b[ … <final letter>`) so a drawn row can be
    /// measured by its visible width — covers SGR `m` plus the `H` / `J` cursor ops.
    fn strip_sgr(s: &str) -> String {
        let mut out = String::new();
        let mut in_csi = false;
        for c in s.chars() {
            if in_csi {
                if c.is_ascii_alphabetic() {
                    in_csi = false;
                }
                continue;
            }
            if c == '\u{1b}' {
                in_csi = true;
                continue;
            }
            out.push(c);
        }
        out
    }

    #[test]
    fn rich_box_wraps_long_line_to_terminal_width() {
        // A line wider than the terminal is folded (lossless) so no row overflows
        // the box: with cols=40 the inner width is 40-4=36, so the longest unbroken
        // run is capped at 36 and every 'A' survives across the wrapped rows.
        let mut s = String::new();
        rich_box(&mut s, &["A".repeat(100)], 40);
        let full = "A".repeat(36);
        let over = "A".repeat(37);
        assert!(s.contains(full.as_str()), "a full 36-wide row is emitted");
        assert!(
            !s.contains(over.as_str()),
            "no row exceeds the 36-col inner width (wrap, not overflow)"
        );
        assert_eq!(s.matches('A').count(), 100, "wrap is lossless");
    }

    #[test]
    fn rich_box_wide_terminal_keeps_line_unwrapped() {
        // On a wide terminal the box grows to the content width (no artificial 80
        // cap), so an 83-col line is NOT wrapped (cols=120 -> inner cap 116 >= 83).
        let mut s = String::new();
        let line = "B".repeat(83);
        rich_box(&mut s, std::slice::from_ref(&line), 120);
        assert!(
            s.contains(line.as_str()),
            "the full 83-col line sits on one row (no wrap)"
        );
    }

    #[test]
    fn rich_box_rows_are_all_equal_width_after_wrap() {
        // The box is rectangular: after stripping SGR, every drawn row (borders +
        // content, including wrapped continuation rows) has the identical display
        // width. Direct regression guard for the slice-c overflow (an over-wide row
        // 3 cols past the border on an 80-col terminal).
        let mut s = String::new();
        let lines = ["short".to_string(), "C".repeat(83), "tiny".to_string()];
        rich_box(&mut s, &lines, 80); // cap = 76 -> the 83-col line wraps
        let widths: Vec<usize> = strip_sgr(&s)
            .split("\r\n")
            .filter(|r| !r.is_empty())
            .map(|r| r.chars().count())
            .collect();
        assert!(!widths.is_empty(), "the box drew at least one row");
        assert!(
            widths.iter().all(|w| *w == widths[0]),
            "all rows equal width (rectangular box); got {widths:?}"
        );
    }

    #[test]
    fn rich_colorize_paints_red_label_but_not_redacted() {
        // `RED` (the truth label) is painted, but the `RED` inside `REDACTED` is NOT
        // (whole-word match only) — the documented slice-e hazard.
        let mut s = String::new();
        rich_colorize(&mut s, "truth=RED kind=REDACTED");
        assert!(
            s.contains("\x1b[31mRED\x1b[0m"),
            "the standalone RED label is colored"
        );
        assert!(s.contains("REDACTED"), "REDACTED text survives");
        assert!(
            !s.contains("\x1b[31mRED\x1b[0mACTED"),
            "REDACTED is never split-colored on its RED prefix"
        );
    }

    #[test]
    fn rich_colorize_paints_banner_keywords_and_preserves_width() {
        // The locked-posture banner: LOCAL-ONLY (cyan) + funds=LOCKED (LOCKED yellow,
        // the `=` is a word boundary). Coloring only inserts escapes, so the
        // SGR-stripped text is byte-identical to the input (padding stays correct).
        let input = "LOCAL-ONLY  NO-LIVE-ACTION  funds=LOCKED  candidate!=finding";
        let mut s = String::new();
        rich_colorize(&mut s, input);
        assert!(
            s.contains("\x1b[36mLOCAL-ONLY\x1b[0m"),
            "LOCAL-ONLY is cyan"
        );
        assert!(
            s.contains("\x1b[33mLOCKED\x1b[0m"),
            "funds=LOCKED keeps LOCKED yellow"
        );
        assert_eq!(
            strip_sgr(&s),
            input,
            "coloring preserves the visible text exactly"
        );
    }

    #[test]
    fn rich_colorize_paints_status_keywords_whole_word() {
        // The four legacy truth keywords still paint, as whole words.
        let mut s = String::new();
        rich_colorize(&mut s, "route=PASS DEGRADED UNKNOWN LOCKED");
        assert!(s.contains("\x1b[32mPASS\x1b[0m"));
        assert!(s.contains("\x1b[33mDEGRADED\x1b[0m"));
        assert!(s.contains("\x1b[2mUNKNOWN\x1b[0m"));
        assert!(s.contains("\x1b[33mLOCKED\x1b[0m"));
    }

    #[test]
    fn rich_colorize_brackets_wraps_each_segment_and_preserves_width() {
        // Each `[…]` segment is wrapped in the given color; the rest is verbatim, so
        // SGR-stripping the result is byte-identical to the input (width preserved).
        let mut s = String::new();
        rich_colorize_brackets(&mut s, "[a]x[bc]", sgr::CYN);
        assert!(s.contains("\x1b[36m[a]\x1b[0m"), "first bracket cyan");
        assert!(s.contains("\x1b[36m[bc]\x1b[0m"), "second bracket cyan");
        assert_eq!(
            strip_sgr(&s),
            "[a]x[bc]",
            "only escapes inserted (width exact)"
        );
    }

    #[test]
    fn rich_colorize_brackets_emits_unclosed_bracket_verbatim() {
        // A `[` with no following `]` (a bracket split across a wrap boundary) is
        // emitted verbatim — never half-colored — so the row width never drifts.
        let mut s = String::new();
        rich_colorize_brackets(&mut s, "ab[cd", sgr::REV);
        assert_eq!(s, "ab[cd", "no escapes emitted without a closing bracket");
    }

    #[test]
    fn render_rich_frame_reverses_active_tab_and_cyans_footer_keys() {
        // The line-aware paint step (slice e-2): the chrome `tabs:` row paints its
        // active `[Name]` bracket reverse-video, the final (footer) row paints every
        // `[x]` hot-key bracket cyan, and body rows stay keyword-colored — all keyed
        // off the ORIGINAL line index. cols=120 keeps every line on one row.
        let lines = [
            "SINABRO cockpit".to_string(),
            "tabs: [Status] Gas".to_string(),
            "[q]uit".to_string(),
        ];
        let mut s = String::new();
        render_rich_frame(&mut s, &lines, 120);
        assert!(
            s.contains("\x1b[7m[Status]\x1b[0m"),
            "the active tab bracket is reverse-video"
        );
        assert!(
            s.contains("\x1b[36m[q]\x1b[0m"),
            "the footer hot-key bracket is cyan"
        );
    }

    #[test]
    fn no_live_action_or_training_label_leaks() {
        // The cockpit advertises the locked posture and never claims execution.
        let (_, text) = run_bytes(b"a");
        assert!(text.contains("NO-LIVE-ACTION"));
        assert!(text.contains("funds=LOCKED"));
        assert!(text.contains("NOT executed"));
    }

    #[test]
    fn audit_game_tree_view_renders_pipeline_candidate_not_finding() {
        // #624 — 'd' drives the live invariant-graph -> bounded-state-space ->
        // move-generator -> impact-prior -> candidate pipeline. A candidate stays a
        // candidate (a non-reproduced receipt never promotes); the state space is
        // bounded; fuzz / production probe / production axis are all denied.
        let (_, text) = run_bytes(b"d");
        assert!(text.contains("audit game tree:"));
        assert!(text.contains("bounded state: all_axes_nonzero=true"));
        assert!(text.contains("production_axis_denied=true"));
        assert!(text.contains("random_fuzz_denied=true"));
        assert!(text.contains("production_probe_denied=true"));
        assert!(text.contains("candidate: pattern_only=true"));
        assert!(text.contains("candidate != finding"));
        assert!(text.contains("non_repro_promotes=false"));
        assert!(text.contains("no live probe"));
    }

    #[test]
    fn audit_game_tree_canary_finding_words_absent() {
        // Falsifiability canary: the live audit surface never claims a confirmed
        // finding / exploit, and never advertises a live action.
        let (_, text) = run_bytes(b"d");
        assert!(!text.to_ascii_lowercase().contains("confirmed finding"));
        assert!(!text.to_ascii_lowercase().contains("exploit ready"));
        assert!(text.contains("local-only"));
    }

    #[test]
    fn audit_detectors_view_renders_candidate_only_defensive() {
        // #625 — 'f' drives the detector surface (static/solana/sui-move). Every
        // flag is candidate-only (direct_finding_count=0), a low-confidence flag is
        // quarantined, and the report draft is defensive + secret-zero.
        let (_, text) = run_bytes(b"f");
        assert!(text.contains("audit detectors:"));
        assert!(text.contains("direct_finding_count=0"));
        assert!(text.contains("low_confidence_quarantined=true"));
        assert!(text.contains("local_only=true no_live_call=true"));
        assert!(text.contains("defensive_and_secret_zero=true"));
        assert!(text.contains("no_exploit_instruction=true"));
        assert!(text.contains("candidate != finding"));
    }

    #[test]
    fn audit_detectors_canary_no_direct_finding_or_exploit_recipe() {
        // Falsifiability canary: a detector NEVER emits a finding directly and the
        // surface never renders an exploit recipe.
        let (_, text) = run_bytes(b"f");
        let lower = text.to_ascii_lowercase();
        assert!(text.contains("direct_finding_count=0"));
        assert!(!lower.contains("step 1:"));
        assert!(!lower.contains("exploit:"));
    }

    #[test]
    fn audit_bundle_view_renders_hash_linked_local_only_finding_gated() {
        // #626 — 'b' drives the audit evidence bundle (hash-linked) + defended
        // memory. A live export is denied (local-only); a finding bundle opens only
        // on a reproduced receipt; defended dead ends carry a replay hint.
        let (_, text) = run_bytes(b"b");
        assert!(text.contains("audit bundle: kind_u8=1"));
        assert!(text.contains("live_export_denied=true"));
        assert!(text.contains("secret_zero_local_only=true"));
        assert!(text.contains("non_repro_denied=true"));
        assert!(text.contains("repro_ok=true"));
        assert!(text.contains("known_dead_end=true"));
        assert!(text.contains("replay_hint=true"));
        assert!(text.contains("candidate != finding"));
    }

    #[test]
    fn memory_commands_view_renders_tombstone_no_resurrection_redacted() {
        // #627 — 'r' drives the memory commands surface: status off the full-replay
        // hot path, delete writes a tombstone (no resurrection), raw content hidden.
        let (_, text) = run_bytes(b"r");
        assert!(text.contains("memory status: full_replay_on_hot_path=false"));
        assert!(text.contains("memory delete: tombstoned=true is_deleted=true"));
        assert!(text.contains("deleted_resurrections=0 zero_resurrections=true"));
        assert!(text.contains("raw_content_visible=false"));
        assert!(text.contains("tombstone no-resurrection"));
    }

    #[test]
    fn memory_intel_view_renders_deletion_wins_and_approval_gated() {
        // #628 — 'c' drives the memory intel surface: compactor is a background
        // step machine, deletion always wins over compaction, a deleted memory is
        // blocked from scoring, and an intel suggestion needs approval.
        let (_, text) = run_bytes(b"c");
        assert!(text.contains("memory intel compactor: total=3"));
        assert!(text.contains("background step machine"));
        assert!(text.contains("deletion_wins_over_compaction=true"));
        assert!(text.contains("deleted_memory_blocked=true"));
        assert!(text.contains("requires_approval=true"));
        assert!(text.contains("deletion always wins over compaction"));
    }

    #[test]
    fn evidence_pack_view_renders_hash_linked_secret_zero_not_training() {
        // #629 — 'e' drives the evidence pack: a hash-linked manifest that
        // recomputes verbatim, holds no secret, and is not training consent.
        let (_, text) = run_bytes(b"e");
        assert!(text.contains("evidence pack: entries=5"));
        assert!(text.contains("recompute_matches=true"));
        assert!(text.contains("links_task_session=true"));
        assert!(text.contains("holds_no_secret=true"));
        assert!(text.contains("training_eligible=false"));
        assert!(text.contains("from command traces"));
    }

    #[test]
    fn evidence_replay_view_renders_offline_deterministic_no_side_effect() {
        // #630 — 'l' drives the evidence replay: offline + deterministic (twin
        // replay equal), re-derives the pack hash, never runs a live side effect.
        let (_, text) = run_bytes(b"l");
        assert!(text.contains("evidence replay: replayed_entries=2"));
        assert!(text.contains("trace_hash_stable=true"));
        assert!(text.contains("twin_replay_equal=true"));
        assert!(text.contains("live_side_effect=false"));
        assert!(text.contains("live_side_effect_denied=true"));
        assert!(text.contains("background job"));
    }

    #[test]
    fn skill_live_lines_are_security_first_sandbox_bound_and_commerce_free() {
        // #631 — the live skill surface holds every invariant: security-first
        // discovery (a quarantined skill is gated to zero), a use needs a passing
        // dry-run + an explicit confirm (cancelling the confirm makes it
        // un-launchable), the sandbox tier ceiling is immutable (warmup never
        // widens it), and quarantine is sticky (a revoked skill can never be
        // re-enabled). Falsifiability canary: the surface carries NO commerce
        // token, so flipping any rendered line to a buy/checkout word fails here.
        let joined = skill_live_lines().join("\n");
        assert!(joined.contains("security_first_holds=true"));
        assert!(joined.contains("quarantine_gated_to_zero=true"));
        assert!(joined.contains("dry_run_passed=true"));
        assert!(joined.contains("can_launch=true"));
        assert!(joined.contains("is_commerce=false"));
        assert!(joined.contains("without_confirm can_launch=false"));
        assert!(joined.contains("requires_approval=true"));
        assert!(joined.contains("denied=true"));
        assert!(joined.contains("warmup_widens=false"));
        assert!(joined.contains("re_enable_denied=true"));
        assert!(joined.contains("executable=false"));
        for bad in [
            "price", "pay", "buy", "sell", "checkout", "refund", "fee", "cost", "$",
        ] {
            assert!(
                !joined.contains(bad),
                "commerce token `{bad}` must never appear in the skill-live surface"
            );
        }
    }

    #[test]
    fn skill_live_view_renders_via_s_key_security_first_quarantine_sticky() {
        // #631 — 's' switches the center to the live skill surface; the bounded
        // (80-col clamped) render keeps every invariant needle in view.
        let (_, text) = run_bytes(b"s");
        assert!(text.contains("view=skill-live"));
        assert!(text.contains("skill search: rows=2"));
        assert!(text.contains("quarantine_gated_to_zero=true"));
        assert!(text.contains("can_launch=true"));
        assert!(text.contains("warmup_widens=false"));
        assert!(text.contains("re_enable_denied=true"));
    }

    #[test]
    fn skill_package_lines_trust_gated_dry_run_publish_revoke_terminal_commerce_free() {
        // #632 — the live package surface holds every invariant: a trust receipt
        // is minted ONLY when all hard gates pass (a signature proves authorship,
        // not safety); install is gated on that receipt; publish is a local
        // dry-run (no upload; the lifecycle state is unchanged); revoke is
        // terminal (never runnable again); a fork is a pure preview (a
        // self-parent child is denied); the provenance card makes the lineage
        // visible and lets it dominate reputation (an invalid chain renders RED).
        // Falsifiability canary: the surface carries NO commerce token.
        let joined = skill_package_lines().join("\n");
        assert!(joined.contains("receipt_minted=true"));
        assert!(joined.contains("supply_chain_complete=true"));
        assert!(joined.contains("attestation_valid=true"));
        assert!(joined.contains("installed=true"));
        assert!(joined.contains("runnable=true"));
        assert!(joined.contains("dry_run_publishable=true"));
        assert!(joined.contains("live_published=false"));
        assert!(joined.contains("state_unchanged=true"));
        assert!(joined.contains("revoked_executable=false"));
        assert!(joined.contains("runnable_after_revoke=false"));
        assert!(joined.contains("child_ok=true"));
        assert!(joined.contains("self_parent_denied=true"));
        assert!(joined.contains("chain_valid=true"));
        assert!(joined.contains("truth=PASS"));
        assert!(joined.contains("chain_valid=false"));
        assert!(joined.contains("truth=RED"));
        for bad in [
            "price", "pay", "buy", "sell", "checkout", "refund", "fee", "cost", "$",
        ] {
            assert!(
                !joined.contains(bad),
                "commerce token `{bad}` must never appear in the skill-package surface"
            );
        }
    }

    #[test]
    fn skill_package_view_renders_via_h_key_trust_gated_provenance_visible() {
        // #632 — 'h' switches the center to the live package/provenance surface;
        // the bounded (80-col clamped) render keeps every invariant needle in view.
        let (_, text) = run_bytes(b"h");
        assert!(text.contains("view=skill-package"));
        assert!(text.contains("receipt_minted=true"));
        assert!(text.contains("dry_run_publishable=true"));
        assert!(text.contains("live_published=false"));
        assert!(text.contains("runnable_after_revoke=false"));
        assert!(text.contains("truth=PASS"));
    }

    #[test]
    fn dataset_live_lines_locked_shard_pii_zero_s1_only_no_upload_secret_zero() {
        // #633 — the live dataset surface holds every invariant: the redaction
        // gate refuses secret/PII residue, a locked shard is structurally
        // immutable, the quality gate fails closed on any PII hit, an S2
        // narrative is never reward-eligible (S1-only), a straddling leakage
        // group is refused, and a contribution upload is a dry-run (no live
        // upload). Falsifiability canary: the rendered surface is itself
        // secret/PII clean (the canonical scanner finds nothing) AND carries no
        // commerce token.
        let joined = dataset_live_lines().join("\n");
        assert!(joined.contains("redaction_clean=true"));
        assert!(joined.contains("residue_denied=true"));
        assert!(joined.contains("dedup_unique=2"));
        assert!(joined.contains("locked_shard_write_allowed=false"));
        assert!(joined.contains("locked_write_denied=true"));
        assert!(joined.contains("dirty_denied=true"));
        assert!(joined.contains("s2_reward_blocked=true"));
        assert!(joined.contains("s1_reverify_required=true"));
        assert!(joined.contains("leakage_conflict_denied=true"));
        assert!(joined.contains("clean_split_total=3"));
        assert!(joined.contains("upload_without_approval_denied=true"));
        assert!(joined.contains("live_upload=false"));
        assert!(joined.contains("target_review_packet=true"));
        let scan = mnemos_l_dataset::privacy_scanner::scan_str(&joined);
        assert!(scan.clean(), "the dataset surface must be secret/PII clean");
        for bad in [
            "price", "pay", "buy", "sell", "checkout", "refund", "fee", "cost", "$",
        ] {
            assert!(
                !joined.contains(bad),
                "commerce token `{bad}` must never appear in the dataset surface"
            );
        }
    }

    #[test]
    fn dataset_live_view_renders_via_o_key_locked_shard_pii_zero_no_upload() {
        // #633 — 'o' switches the center to the live dataset surface; the bounded
        // (80-col clamped) render keeps every invariant needle in view.
        let (_, text) = run_bytes(b"o");
        assert!(text.contains("view=dataset-live"));
        assert!(text.contains("locked_shard_write_allowed=false"));
        assert!(text.contains("dirty_denied=true"));
        assert!(text.contains("s2_reward_blocked=true"));
        assert!(text.contains("live_upload=false"));
    }

    #[test]
    fn eval_live_lines_s1_only_candidate_not_finding_safe_wording_self_clean() {
        // #634 — the live trace/eval surface holds every invariant: S1-only
        // reward (S2 / frontier-only / un-reproduced audit candidate earn none),
        // a false eval pass cannot be recorded, candidate != finding in the
        // report, and the safe-wording gates refuse an exploit recipe and refuse
        // certainty for an unreproduced candidate (a finding may state its
        // verified result). Falsifiability canary: the rendered surface is itself
        // free of exploit recipes and of candidate-certainty language.
        let joined = eval_live_lines().join("\n");
        assert!(joined.contains("s1_reward_eligible=true"));
        assert!(joined.contains("s2_no_reward=true"));
        assert!(joined.contains("cand_not_finding=true"));
        assert!(joined.contains("repro_promotes=true"));
        assert!(joined.contains("frontier_no_promote=true"));
        assert!(joined.contains("false_pass_denied=true"));
        assert!(joined.contains("candidate_is_finding=false"));
        assert!(joined.contains("finding_is_finding=true"));
        assert!(joined.contains("candidate_certainty_denied=true"));
        assert!(joined.contains("exploit_instruction_denied=true"));
        assert!(joined.contains("hedged_candidate_ok=true"));
        assert!(joined.contains("finding_may_state_result=true"));
        assert!(
            crate::commands::eval_language::assert_no_exploit_instruction(&joined).is_ok(),
            "the eval surface must carry no exploit recipe"
        );
        assert!(
            crate::commands::eval_language::assert_no_candidate_certainty(&joined, false).is_ok(),
            "the eval surface must carry no candidate-certainty language"
        );
        for bad in [
            "price", "pay", "buy", "sell", "checkout", "refund", "fee", "cost", "$",
        ] {
            assert!(
                !joined.contains(bad),
                "commerce token `{bad}` must never appear in the eval surface"
            );
        }
    }

    #[test]
    fn eval_live_view_renders_via_u_key_s1_only_candidate_not_finding() {
        // #634 — 'u' switches the center to the live trace/eval surface; the
        // bounded (80-col clamped) render keeps every invariant needle in view.
        let (_, text) = run_bytes(b"u");
        assert!(text.contains("view=eval-live"));
        assert!(text.contains("s1_reward_eligible=true"));
        assert!(text.contains("cand_not_finding=true"));
        assert!(text.contains("false_pass_denied=true"));
        assert!(text.contains("candidate_certainty_denied=true"));
    }

    #[test]
    fn daemon_live_lines_no_secret_killable_shared_inbox_one_state_hash() {
        // #635 — the live daemon surface holds every invariant: a started daemon
        // is killable and owns no secret/wallet, a stopped daemon is not killable
        // (Unknown not a false green), the inbox shares one id space across the
        // six operational job classes, and CLI+TG reconnect to one state_hash
        // (a stale view is refused). Secret-zero canary: the surface renders no
        // secret-shaped value.
        let joined = daemon_live_lines().join("\n");
        assert!(joined.contains("running_killable=true"));
        assert!(joined.contains("holds_no_secret_or_wallet=true"));
        assert!(joined.contains("not_killable=true"));
        assert!(joined.contains("jobs=2"));
        assert!(joined.contains("shared_id_space=6"));
        assert!(joined.contains("cli_fresh=true"));
        assert!(joined.contains("tg_fresh=true"));
        assert!(joined.contains("cli_tg_same_hash=true"));
        assert!(joined.contains("stale_view_refused=true"));
        let lower = joined.to_ascii_lowercase();
        for bad in ["privkey", "suiprivkey", "begin private", "0x"] {
            assert!(
                !lower.contains(bad),
                "secret-shaped token `{bad}` must never appear in the daemon surface"
            );
        }
        for bad in [
            "price", "pay", "buy", "sell", "checkout", "refund", "fee", "cost", "$",
        ] {
            assert!(
                !joined.contains(bad),
                "commerce token `{bad}` must never appear in the daemon surface"
            );
        }
    }

    #[test]
    fn daemon_live_view_renders_via_w_key_no_secret_one_state_hash() {
        // #635 — 'w' switches the center to the live daemon surface; the bounded
        // (80-col clamped) render keeps every invariant needle in view.
        let (_, text) = run_bytes(b"w");
        assert!(text.contains("view=daemon-live"));
        assert!(text.contains("holds_no_secret_or_wallet=true"));
        assert!(text.contains("jobs=2"));
        assert!(text.contains("cli_tg_same_hash=true"));
        assert!(text.contains("stale_view_refused=true"));
    }

    #[test]
    fn sync_live_lines_envelope_equality_and_divergence_red() {
        // #637 — the live sync surface holds CLI/TG channel parity: every control
        // verb is the SAME command on either channel, the same verb yields an
        // equal envelope (the sync receipt equal=true), and divergence is RED — two
        // different verbs are distinct commands and a non-control verb is refused.
        // Falsifiable BOTH directions: equal=true for the same verb AND
        // different_verb_distinct=true for different verbs (the divergence canary).
        let joined = sync_live_lines().join("\n");
        assert!(joined.contains("control_verbs=7"));
        assert!(joined.contains("all_channel_identical=true"));
        assert!(joined.contains("equal=true"));
        assert!(joined.contains("different_verb_distinct=true"));
        assert!(joined.contains("forbidden_verb_refused=true"));
        assert!(joined.contains("cli_tg_one_state_hash=true"));
        for bad in [
            "price", "pay", "buy", "sell", "checkout", "refund", "fee", "cost", "$",
        ] {
            assert!(
                !joined.contains(bad),
                "commerce token `{bad}` must never appear in the sync surface"
            );
        }
    }

    #[test]
    fn sync_live_view_renders_via_x_key_envelope_equality() {
        // #637 — 'x' switches the center to the live CLI/TG sync surface; the
        // bounded (80-col clamped) render keeps every invariant needle in view.
        let (_, text) = run_bytes(b"x");
        assert!(text.contains("view=sync-live"));
        assert!(text.contains("all_channel_identical=true"));
        assert!(text.contains("equal=true"));
        assert!(text.contains("forbidden_verb_refused=true"));
        assert!(text.contains("cli_tg_one_state_hash=true"));
    }

    #[test]
    fn control_live_lines_express_lane_bypass_halt_and_budget_kill() {
        // #638 — the live control surface holds every invariant: a STOP control
        // bypasses a saturated background queue and halts (no live action), every
        // express class bypasses, lowering the cap stops the NEXT side effect
        // (re-checked before dispatch), and a killed task can never write evidence
        // (no-zombie). Falsifiable: cap_lower stops AND resume re-enables.
        let joined = control_live_lines().join("\n");
        assert!(joined.contains("kill_bypasses=true"));
        assert!(joined.contains("live_action=false"));
        assert!(joined.contains("every_class_bypasses=true"));
        assert!(joined.contains("cap_lower_stops_next=true"));
        assert!(joined.contains("resume_reenables=true"));
        assert!(joined.contains("cap_lowered_denies_dispatch=true"));
        assert!(joined.contains("all_side_effects_stopped=true"));
        assert!(joined.contains("killed=true"));
        assert!(joined.contains("killed_cannot_write_evidence=true"));
        assert!(joined.contains("unknown_denied=true"));
        for bad in [
            "price", "pay", "buy", "sell", "checkout", "refund", "fee", "cost", "$",
        ] {
            assert!(
                !joined.contains(bad),
                "commerce token `{bad}` must never appear in the control surface"
            );
        }
    }

    #[test]
    fn control_live_view_renders_via_y_key_express_lane() {
        // #638 — 'y' switches the center to the live control-express surface; the
        // bounded (80-col clamped) render keeps every invariant needle in view.
        let (_, text) = run_bytes(b"y");
        assert!(text.contains("view=control-live"));
        assert!(text.contains("kill_bypasses=true"));
        assert!(text.contains("cap_lowered_denies_dispatch=true"));
        assert!(text.contains("killed_cannot_write_evidence=true"));
    }

    #[test]
    fn checkpoint_live_lines_auto_checkpoint_restore_protected_undo_rollback() {
        // #640 — the live checkpoint surface holds every invariant: a risk command
        // auto-checkpoints first (read-only does not), restore is user-change
        // protected (a user-edited target is refused) and idempotent (already at
        // the restore point is a no-op), undo spans files/task/all, and config +
        // skill rollback work (skill quarantine is terminal -> Revoked).
        let joined = checkpoint_live_lines().join("\n");
        assert!(joined.contains("risk_requires_checkpoint=true"));
        assert!(joined.contains("readonly_no_checkpoint=true"));
        assert!(joined.contains("auto_checkpoints=3"));
        assert!(joined.contains("restore_idempotent_noop=true"));
        assert!(joined.contains("user_change_protected=true"));
        assert!(joined.contains("files=true task=true all=true"));
        assert!(joined.contains("config_rollback=true"));
        assert!(joined.contains("skill_quarantine_terminal=true"));
        for bad in [
            "price", "pay", "buy", "sell", "checkout", "refund", "fee", "cost", "$",
        ] {
            assert!(
                !joined.contains(bad),
                "commerce token `{bad}` must never appear in the checkpoint surface"
            );
        }
    }

    #[test]
    fn checkpoint_live_view_renders_via_z_key_auto_checkpoint_and_protected_restore() {
        // #640 — 'z' switches the center to the live checkpoint surface; the
        // bounded (80-col clamped) render keeps every invariant needle in view.
        let (_, text) = run_bytes(b"z");
        assert!(text.contains("view=checkpoint-live"));
        assert!(text.contains("risk_requires_checkpoint=true"));
        assert!(text.contains("auto_checkpoints=3"));
        assert!(text.contains("user_change_protected=true"));
        assert!(text.contains("config_rollback=true"));
    }

    #[test]
    fn multisig_live_lines_funds_locked_status_view_only_secret_zero() {
        // #641 — the live funds surface is status-view-only with funds LOCKED:
        // multisig live execution disabled + the execute decision always denies, a
        // mainnet write requires the multisig approval gate, the gas safety gates
        // are independent of telemetry and hold no secret, and a sponsor can never
        // sign the owner's intent (sponsor == owner is refused). Secret-zero
        // canary: the surface renders no secret-shaped value.
        let joined = multisig_live_lines().join("\n");
        assert!(joined.contains("live_execution_enabled=false"));
        assert!(joined.contains("execute_decision_denied=true"));
        assert!(joined.contains("mainnet_write_requires_approval=true"));
        assert!(joined.contains("env_consistent=true"));
        assert!(joined.contains("gates_independent_of_telemetry=true"));
        assert!(joined.contains("secrets_absent=true"));
        assert!(joined.contains("sponsor_can_sign_owner_intent=false"));
        assert!(joined.contains("sponsor_eq_owner_denied=true"));
        assert!(joined.contains("funds LOCKED"));
        let lower = joined.to_ascii_lowercase();
        for bad in ["privkey", "suiprivkey", "begin private", "0x"] {
            assert!(
                !lower.contains(bad),
                "secret-shaped token `{bad}` must never appear in the funds surface"
            );
        }
        for bad in [
            "price", "pay", "buy", "sell", "checkout", "refund", "fee", "cost", "$",
        ] {
            assert!(
                !joined.contains(bad),
                "commerce token `{bad}` must never appear in the funds surface"
            );
        }
    }

    #[test]
    fn multisig_live_view_renders_via_uppercase_m_key_funds_locked() {
        // #641 — UPPERCASE 'M' switches the center to the live funds surface
        // (lowercase 'm' is the Platform dashboard); the bounded (80-col clamped)
        // render keeps every invariant needle in view.
        let (_, text) = run_bytes(b"M");
        assert!(text.contains("view=multisig-live"));
        assert!(text.contains("live_execution_enabled=false"));
        assert!(text.contains("mainnet_write_requires_approval=true"));
        assert!(text.contains("sponsor_can_sign_owner_intent=false"));
        assert!(text.contains("funds LOCKED"));
        // lowercase 'm' still routes to the Platform dashboard (not the funds view).
        let (_, platform) = run_bytes(b"m");
        assert!(platform.contains("view=platform"));
    }

    #[test]
    fn safety_kernel_live_lines_ten_non_disableable_and_broken_quarantines() {
        // #642 — the safety kernel is a protocol boundary, not a toggle: all 10
        // SAFETY_KERNEL_FEATURES are non-disableable (a disable attempt is
        // SafetyKernelLocked), an ordinary user feature is still toggleable, a
        // broken kernel quarantines regardless of any other claim, and learning /
        // egress default OFF.
        let joined = safety_kernel_live_lines().join("\n");
        assert!(joined.contains("count=10"));
        assert!(joined.contains("all_kernel=true"));
        assert!(joined.contains("all_disable_denied=true"));
        assert!(joined.contains("non_kernel_toggleable=true"));
        assert!(joined.contains("intact_local_only=true"));
        assert!(joined.contains("broken_quarantined=true"));
        assert!(joined.contains("learning_off=true"));
        assert!(joined.contains("egress_none=true"));
        for bad in [
            "price", "pay", "buy", "sell", "checkout", "refund", "fee", "cost", "$",
        ] {
            assert!(
                !joined.contains(bad),
                "commerce token `{bad}` must never appear in the safety-kernel surface"
            );
        }
    }

    #[test]
    fn safety_kernel_live_view_renders_via_uppercase_k_key() {
        // #642 — UPPERCASE 'K' switches the center to the live safety-kernel
        // surface; the bounded (80-col clamped) render keeps the needles in view.
        let (_, text) = run_bytes(b"K");
        assert!(text.contains("view=safety-kernel-live"));
        assert!(text.contains("count=10"));
        assert!(text.contains("all_disable_denied=true"));
        assert!(text.contains("broken_quarantined=true"));
    }

    #[test]
    fn capability_live_lines_diff_before_exec_degraded_tier_immutable_no_bypass() {
        // #643 — a capability gain renders DEGRADED before execution (never a
        // silent grant), a hidden permission is denied, the sandbox tier ceiling
        // is immutable (warmup never raises it), and a tool runs only THROUGH the
        // adapter (network egress denied by default — no bypass).
        let joined = capability_live_lines().join("\n");
        assert!(joined.contains("gain_before_exec=true"));
        assert!(joined.contains("truth=DEGRADED"));
        assert!(joined.contains("requires_approval=true"));
        assert!(joined.contains("hidden_permission_denied=true"));
        assert!(joined.contains("tier_ceiling_immutable=true"));
        assert!(joined.contains("runnable_through_adapter=true"));
        assert!(joined.contains("network_egress_denied=true"));
        for bad in [
            "price", "pay", "buy", "sell", "checkout", "refund", "fee", "cost", "$",
        ] {
            assert!(
                !joined.contains(bad),
                "commerce token `{bad}` must never appear in the capability surface"
            );
        }
    }

    #[test]
    fn capability_live_view_renders_via_uppercase_p_key() {
        // #643 — UPPERCASE 'P' switches the center to the live capability surface.
        let (_, text) = run_bytes(b"P");
        assert!(text.contains("view=capability-live"));
        assert!(text.contains("truth=DEGRADED"));
        assert!(text.contains("tier_ceiling_immutable=true"));
        assert!(text.contains("network_egress_denied=true"));
    }

    #[test]
    fn wallet_live_lines_status_only_sign_preview_only_funds_locked() {
        // #645 — the wallet surface is status-only with funds LOCKED: status from
        // the public key (no key material loaded), owner != gas sponsor, the render
        // leaks no key, a signature is PREVIEW-ONLY (live signing disabled,
        // TypedPhrase gate), an opaque/blind payload is denied, and the key doctor
        // reports secret-zero (an inline secret breaks it). Secret-shaped canary.
        let joined = wallet_live_lines().join("\n");
        assert!(joined.contains("secret_custody_ok=true"));
        assert!(joined.contains("owner_is_not_sponsor=true"));
        assert!(joined.contains("key_material_loaded=false"));
        assert!(joined.contains("render_no_key_leak=true"));
        assert!(joined.contains("live_signing_enabled=false"));
        assert!(joined.contains("approval_typed_phrase=true"));
        assert!(joined.contains("blind_sign_denied=true"));
        assert!(joined.contains("secret_zero=true"));
        assert!(joined.contains("inline_secret_breaks_zero=true"));
        assert!(joined.contains("funds LOCKED"));
        let lower = joined.to_ascii_lowercase();
        for bad in ["suiprivkey", "privkey", "begin private", "0x"] {
            assert!(
                !lower.contains(bad),
                "secret-shaped token `{bad}` must never appear in the wallet surface"
            );
        }
        for bad in [
            "price", "pay", "buy", "sell", "checkout", "refund", "fee", "cost", "$",
        ] {
            assert!(
                !joined.contains(bad),
                "commerce token `{bad}` must never appear in the wallet surface"
            );
        }
    }

    #[test]
    fn wallet_live_view_renders_via_uppercase_l_key_funds_locked() {
        // #645 — UPPERCASE 'L' switches the center to the live wallet surface.
        let (_, text) = run_bytes(b"L");
        assert!(text.contains("view=wallet-live"));
        assert!(text.contains("secret_custody_ok=true"));
        assert!(text.contains("live_signing_enabled=false"));
        assert!(text.contains("blind_sign_denied=true"));
        assert!(text.contains("funds LOCKED"));
    }

    #[test]
    fn finding_live_lines_candidate_not_finding_and_no_authority_expansion() {
        // #646 — an audit candidate is pattern-only: a non-reproduced receipt never
        // promotes it to a finding, a reproduced node-matching receipt does, and a
        // self-evolution apply is structurally impossible (the uninhabited success
        // of try_apply_self_evolution) — a better Naite gains no new rights.
        let joined = finding_live_lines().join("\n");
        assert!(joined.contains("pattern_only=true"));
        assert!(joined.contains("non_repro_promotes=false"));
        assert!(joined.contains("repro_promotes_to_finding=true"));
        assert!(joined.contains("apply_impossible=true"));
        assert!(joined.contains("candidate!=finding"));
        assert!(joined.contains("performance!=authority"));
        for bad in [
            "price", "pay", "buy", "sell", "checkout", "refund", "fee", "cost", "$",
        ] {
            assert!(
                !joined.contains(bad),
                "commerce token `{bad}` must never appear in the finding surface"
            );
        }
    }

    #[test]
    fn finding_live_view_renders_via_uppercase_f_key() {
        // #646 — UPPERCASE 'F' switches the center to the live candidate/finding
        // surface (candidate != finding; no authority expansion).
        let (_, text) = run_bytes(b"F");
        assert!(text.contains("view=finding-live"));
        assert!(text.contains("pattern_only=true"));
        assert!(text.contains("non_repro_promotes=false"));
        assert!(text.contains("apply_impossible=true"));
    }

    #[test]
    fn ten_live_lines_section10_designed_impossibilities_structural() {
        // #647 — the §10 designed-impossibilities are structural: a loop is bounded
        // by a finite budget (runaway unrepresentable), learning defaults OFF with
        // no egress, a secret is a never-loaded reference (no baked key), and the
        // Stage-H handoff is verified AND fails closed when training is unlocked
        // (no-authority-expansion). ASCII-only labels (clamp80 strips non-ASCII §).
        let joined = ten_live_lines().join("\n");
        assert!(joined.contains("loop_bounded=true"));
        assert!(joined.contains("no_training_default=true"));
        assert!(joined.contains("egress_none=true"));
        assert!(joined.contains("no_baked_key=true"));
        assert!(joined.contains("handoff_verified=true"));
        assert!(joined.contains("training_unlock_denied=true"));
        assert!(joined.contains("reward!=self-report"));
        for bad in [
            "price", "pay", "buy", "sell", "checkout", "refund", "fee", "cost", "$",
        ] {
            assert!(
                !joined.contains(bad),
                "commerce token `{bad}` must never appear in the section-10 surface"
            );
        }
    }

    #[test]
    fn ten_live_view_renders_via_uppercase_t_key() {
        // #647 — UPPERCASE 'T' switches the center to the live §10 surface (the
        // last of the 24 live CockpitViews).
        let (_, text) = run_bytes(b"T");
        assert!(text.contains("view=section10-live"));
        assert!(text.contains("loop_bounded=true"));
        assert!(text.contains("no_baked_key=true"));
        assert!(text.contains("training_unlock_denied=true"));
    }

    #[test]
    fn steady_state_redraw_does_not_reallocate_the_frame_buffer() {
        // Zero-alloc proxy (atom #590): after warmup, a redraw with no preceding
        // recompute reuses the frame buffer (capacity stable) and the cached line
        // set (len unchanged) — no heap growth on the steady-state hot path.
        let mut cockpit = Cockpit::new();
        cockpit.recompute();
        let mut sink: Vec<u8> = Vec::new();
        cockpit
            .redraw(&mut sink, RenderMode::Plain)
            .expect("warmup draw");
        let cap_after_warmup = cockpit.frame.capacity();
        let lines_after_warmup = cockpit.lines.len();
        for _ in 0..1000 {
            sink.clear();
            cockpit
                .redraw(&mut sink, RenderMode::Plain)
                .expect("hot redraw");
        }
        assert_eq!(
            cockpit.frame.capacity(),
            cap_after_warmup,
            "frame buffer must not reallocate on the steady-state redraw"
        );
        assert_eq!(
            cockpit.lines.len(),
            lines_after_warmup,
            "the cached line set must not rebuild on a redraw"
        );
    }

    #[test]
    fn keystroke_and_render_p95_within_budget() {
        // atom #589: keystroke (decode + handle) and render p95 within the budget.
        let budget = LatencyBudget::DEFAULT;
        let mut cockpit = Cockpit::new();
        cockpit.recompute();
        let mut sink: Vec<u8> = Vec::new();

        let mut keystroke = Vec::with_capacity(512);
        for _ in 0..512 {
            let t = std::time::Instant::now();
            let ev = decode_key(b'n');
            let dirty = cockpit.handle_event(ev);
            std::hint::black_box(dirty);
            keystroke.push(t.elapsed().as_millis() as u64);
        }
        let mut render = Vec::with_capacity(512);
        for _ in 0..512 {
            cockpit.recompute();
            let t = std::time::Instant::now();
            sink.clear();
            cockpit.redraw(&mut sink, RenderMode::Plain).expect("draw");
            render.push(t.elapsed().as_millis() as u64);
        }
        let score = LatencyScore::evaluate(budget, p95_ms(&keystroke), 0, p95_ms(&render), 0);
        assert!(score.keypress_ok, "keystroke p95 over 16ms budget");
        assert!(score.render_ok, "render p95 over 5ms budget");
    }

    #[test]
    fn decode_key_is_total_and_maps_controls() {
        assert_eq!(decode_key(b'q'), CockpitEvent::Quit);
        assert_eq!(decode_key(b'\t'), CockpitEvent::Tab(TabNav::Next));
        assert_eq!(decode_key(b'p'), CockpitEvent::Tab(TabNav::Prev));
        assert_eq!(decode_key(b'3'), CockpitEvent::Tab(TabNav::Select(2)));
        assert_eq!(decode_key(b'g'), CockpitEvent::View(CockpitView::Gas));
        assert_eq!(decode_key(0x1b), CockpitEvent::Ignore); // lone ESC -> no-op
    }

    #[test]
    fn twin_run_is_deterministic() {
        let (a, ta) = run_bytes(b"njkvgmai");
        let (b, tb) = run_bytes(b"njkvgmai");
        assert_eq!(a, b);
        assert_eq!(ta, tb);
    }
}
