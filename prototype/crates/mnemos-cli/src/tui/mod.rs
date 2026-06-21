//! §4.3 TUI cockpit screen model (atom #417 F.2.0) + the shared render-truth enum.
//!
//! The TUI is a *read / project / approve* surface only: it renders truth the
//! core crates own and never holds business state. The interactive
//! `ratatui`/`crossterm` binding is deferred until its dependency is
//! cache-confirmed (mirroring the `reedline` deferral in [`crate::repl`]); this
//! screen model is the canonical OUT and is fully testable with no terminal.
//!
//! Submodules: [`status_bar`] (#418), [`job_rail`] (#419), [`tabs`] (#420),
//! [`trace_pane`] (#421), [`skill_cards`] (#422), [`skill_use_modal`] (#423),
//! [`approval_modal`] (#424), [`inspector`] (#425).

pub mod approval_modal;
pub mod gas_tab;
pub mod inspector;
pub mod job_rail;
pub mod jobs_tab;
pub mod platform_tab;
pub mod provider_tab;
pub mod raw;
pub mod run;
pub mod skill_cards;
pub mod skill_use_modal;
pub mod status_bar;
pub mod tabs;
pub mod trace_pane;

/// §4.3 — the three-valued (plus unknown) render truth every cockpit surface
/// projects. `Unknown` is *explicit*: an unwired or stale subsystem renders as
/// `Unknown`, never as a false `Green`.
#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RenderTruth {
    /// Healthy / passing.
    Green = 1,
    /// Degraded / warning.
    Yellow = 2,
    /// Failing / blocked.
    Red = 3,
    /// Not yet known (unwired subsystem, stale, or never-measured).
    Unknown = 4,
}

impl RenderTruth {
    /// Whether this truth may be shown as healthy. Only `Green` is healthy;
    /// `Yellow` / `Red` / `Unknown` are never healthy (the no-false-green law).
    #[must_use]
    pub const fn is_healthy(self) -> bool {
        matches!(self, Self::Green)
    }
}

/// §4.3 — the cockpit lifecycle phase.
#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ShellPhase {
    /// First frame is being prepared.
    Booting = 1,
    /// Interactive: rendering + accepting input.
    Active = 2,
    /// Quit requested; tearing down.
    Quitting = 3,
    /// Fully closed; terminal restored.
    Closed = 4,
}

/// §4.3 screen model — the cockpit shell state machine (atom #417). Holds no
/// business state: only the lifecycle phase and the last known terminal size,
/// so a real (deferred) `ratatui`/`crossterm` binding can drive it without
/// owning any truth. Every transition is total and teardown never panics.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CockpitShell {
    phase: ShellPhase,
    cols: u16,
    rows: u16,
}

impl Default for CockpitShell {
    fn default() -> Self {
        Self {
            phase: ShellPhase::Booting,
            cols: 0,
            rows: 0,
        }
    }
}

impl CockpitShell {
    /// Create a shell in [`ShellPhase::Booting`] with an unknown (`0x0`) size.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// The current lifecycle phase.
    #[must_use]
    pub const fn phase(self) -> ShellPhase {
        self.phase
    }

    /// The last known terminal size as `(cols, rows)`.
    #[must_use]
    pub const fn size(self) -> (u16, u16) {
        (self.cols, self.rows)
    }

    /// Whether the shell is interactive (renders + accepts input).
    #[must_use]
    pub const fn is_running(self) -> bool {
        matches!(self.phase, ShellPhase::Active)
    }

    /// Finish booting: `Booting` -> `Active`. From any other phase this is a
    /// no-op (a closed/quitting shell cannot be revived without a `new`).
    pub const fn boot(&mut self) {
        if matches!(self.phase, ShellPhase::Booting) {
            self.phase = ShellPhase::Active;
        }
    }

    /// Apply a resize. Updates the cached size in any non-closed phase; on a
    /// closed shell the size is frozen (no-op). Never changes the phase.
    pub const fn on_resize(&mut self, cols: u16, rows: u16) {
        if !matches!(self.phase, ShellPhase::Closed) {
            self.cols = cols;
            self.rows = rows;
        }
    }

    /// Request a quit: any live phase (`Booting`/`Active`) -> `Quitting`. From
    /// `Quitting`/`Closed` this is a no-op.
    pub const fn request_quit(&mut self) {
        if matches!(self.phase, ShellPhase::Booting | ShellPhase::Active) {
            self.phase = ShellPhase::Quitting;
        }
    }

    /// Tear down: from *any* phase -> `Closed`. Total and idempotent — this is
    /// the panic-free teardown the atom requires; calling it twice is safe.
    pub const fn close(&mut self) {
        self.phase = ShellPhase::Closed;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn render_truth_only_green_is_healthy() {
        assert!(RenderTruth::Green.is_healthy());
        assert!(!RenderTruth::Yellow.is_healthy());
        assert!(!RenderTruth::Red.is_healthy());
        assert!(!RenderTruth::Unknown.is_healthy());
    }

    #[test]
    fn boot_moves_booting_to_active() {
        let mut s = CockpitShell::new();
        assert_eq!(s.phase(), ShellPhase::Booting);
        assert!(!s.is_running());
        s.boot();
        assert_eq!(s.phase(), ShellPhase::Active);
        assert!(s.is_running());
    }

    #[test]
    fn boot_is_a_noop_after_close() {
        let mut s = CockpitShell::new();
        s.close();
        s.boot();
        assert_eq!(s.phase(), ShellPhase::Closed);
    }

    #[test]
    fn resize_updates_size_but_not_phase() {
        let mut s = CockpitShell::new();
        s.boot();
        s.on_resize(120, 40);
        assert_eq!(s.size(), (120, 40));
        assert_eq!(s.phase(), ShellPhase::Active);
    }

    #[test]
    fn resize_is_frozen_after_close() {
        let mut s = CockpitShell::new();
        s.on_resize(80, 24);
        s.close();
        s.on_resize(200, 50);
        assert_eq!(s.size(), (80, 24));
    }

    #[test]
    fn quit_then_close_lifecycle() {
        let mut s = CockpitShell::new();
        s.boot();
        s.request_quit();
        assert_eq!(s.phase(), ShellPhase::Quitting);
        s.close();
        assert_eq!(s.phase(), ShellPhase::Closed);
    }

    #[test]
    fn teardown_is_total_and_idempotent_from_every_phase() {
        for build in [
            CockpitShell::new,
            || {
                let mut s = CockpitShell::new();
                s.boot();
                s
            },
            || {
                let mut s = CockpitShell::new();
                s.boot();
                s.request_quit();
                s
            },
        ] {
            let mut s = build();
            s.close();
            assert_eq!(s.phase(), ShellPhase::Closed);
            // idempotent second close never panics and stays Closed
            s.close();
            assert_eq!(s.phase(), ShellPhase::Closed);
        }
    }
}
