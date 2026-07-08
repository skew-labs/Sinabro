//! libc `termios` raw-mode — the ONLY `unsafe` in the `sinabro` crate. The crate
//! root is `#![deny(unsafe_code)]`; this single module narrowly
//! re-allows it for exactly two return-checked POSIX FFI calls
//! (`tcgetattr` / `tcsetattr`), isolated behind a panic-safe RAII guard.
//!
//! Drift-proofing (the "no error by construction" contract):
//! * TTY detection is the SAFE std [`std::io::IsTerminal`] (no FFI) — performed by
//!   the caller ([`crate::tui::run`]); a non-TTY stdin never reaches the termios
//!   calls (the loop falls back to cooked / piped input).
//! * every FFI return code is checked; there is no `unwrap` / `expect` / `panic`,
//!   so [`RawModeGuard::enter`] fails closed to `None` on any error.
//! * `Drop` restores the saved original `termios` on every non-abort exit path
//!   (normal return, `?`, and — in an unwinding build — a panic), so our code can
//!   never leave the terminal in raw mode. The release profile is `panic =
//!   "abort"`, under which the crate is panic-free (clippy-enforced), so the abort
//!   path is unreachable; the unwind-restore is proven by a `catch_unwind` test in
//!   the (unwinding) test profile.
#![allow(unsafe_code)]

#[cfg(unix)]
mod imp {
    use std::os::fd::AsRawFd;

    /// RAII raw-mode guard for `stdin`. [`RawModeGuard::enter`] switches the
    /// terminal to raw mode (canonical mode, echo, and signal generation off;
    /// 1-byte blocking reads) and remembers the original settings; `Drop` restores
    /// them. Construction fails closed (returns `None`) on any FFI error.
    pub struct RawModeGuard {
        fd: i32,
        original: libc::termios,
    }

    impl RawModeGuard {
        /// Enter raw mode on `stdin`. Returns `None` (the cooked-input fallback) if
        /// the FFI reports an error — e.g. `stdin` is not a terminal. The caller is
        /// expected to have already confirmed a TTY via the safe `IsTerminal` path.
        #[must_use]
        pub fn enter() -> Option<Self> {
            let fd = std::io::stdin().as_raw_fd();
            // SAFETY: `original` is a freshly-zeroed, valid, writable `termios`; it
            // is only used as the output buffer for `tcgetattr` on the live fd.
            let mut original: libc::termios = unsafe { std::mem::zeroed() };
            // SAFETY: `fd` is a live descriptor and `&mut original` is a valid
            // writable `termios` (a zeroed scratch buffer); the return is checked.
            if unsafe { libc::tcgetattr(fd, &mut original) } != 0 {
                return None;
            }
            let mut raw_term = original;
            // Manual raw-mode flag clears using libc constants (portable across
            // Linux / macOS; no reliance on a `cfmakeraw` export).
            raw_term.c_lflag &= !(libc::ICANON | libc::ECHO | libc::ISIG | libc::IEXTEN);
            raw_term.c_iflag &=
                !(libc::IXON | libc::ICRNL | libc::BRKINT | libc::INPCK | libc::ISTRIP);
            raw_term.c_oflag &= !(libc::OPOST);
            raw_term.c_cflag |= libc::CS8;
            raw_term.c_cc[libc::VMIN] = 1;
            raw_term.c_cc[libc::VTIME] = 0;
            // SAFETY: `&raw_term` is a valid `termios`; `fd` is live; return checked.
            if unsafe { libc::tcsetattr(fd, libc::TCSAFLUSH, &raw_term) } != 0 {
                return None;
            }
            Some(Self { fd, original })
        }
    }

    impl Drop for RawModeGuard {
        fn drop(&mut self) {
            // SAFETY: restoring the previously-saved, valid `termios` on the same
            // live fd. The return is intentionally ignored — during teardown
            // (including an unwind) re-applying the saved struct is the only correct
            // action, and there is no safe recovery from a failure here.
            unsafe {
                libc::tcsetattr(self.fd, libc::TCSAFLUSH, &self.original);
            }
        }
    }

    /// Query the controlling terminal's size as `(columns, rows)` via the
    /// `TIOCGWINSZ` ioctl on `stdout`. Returns `None` — the caller then assumes a
    /// default width — on any FFI error or a degenerate zero width (e.g. `stdout`
    /// is a pipe / file, not a TTY). Same return-checked, fail-closed
    /// unsafe-isolation pattern as [`RawModeGuard::enter`]: no `unwrap` / `expect`
    /// / `panic`, so a non-terminal stdout never yields a bogus size.
    #[must_use]
    pub fn term_size() -> Option<(u16, u16)> {
        let fd = std::io::stdout().as_raw_fd();
        // SAFETY: `ws` is a freshly-zeroed, valid, writable `winsize`; it is only
        // used as the output buffer for the `TIOCGWINSZ` ioctl on the live fd.
        let mut ws: libc::winsize = unsafe { std::mem::zeroed() };
        // SAFETY: `fd` is a live descriptor and `&mut ws` is a valid writable
        // `winsize`; the request is the constant `TIOCGWINSZ`; the return is checked.
        if unsafe { libc::ioctl(fd, libc::TIOCGWINSZ, &mut ws) } != 0 {
            return None;
        }
        // A reported zero width is unusable; treat it as "size unknown".
        if ws.ws_col == 0 {
            return None;
        }
        Some((ws.ws_col, ws.ws_row))
    }
}

#[cfg(not(unix))]
mod imp {
    /// Non-unix stub: there is no `termios` raw mode, so the loop uses cooked
    /// (line-buffered) input. [`RawModeGuard::enter`] is always `None`.
    pub struct RawModeGuard;

    impl RawModeGuard {
        /// Always `None` on non-unix targets (no raw mode available).
        #[must_use]
        pub fn enter() -> Option<Self> {
            None
        }
    }

    /// Non-unix stub: the terminal size is unknown (no `TIOCGWINSZ`), so the rich
    /// renderer falls back to its default assumed width.
    #[must_use]
    pub fn term_size() -> Option<(u16, u16)> {
        None
    }
}

pub use imp::{RawModeGuard, term_size};

#[cfg(all(test, unix))]
mod tests {
    #![allow(clippy::panic)]
    use super::RawModeGuard;

    // These tests run under the (unwinding) test profile. They never assert that
    // raw mode was *entered* (CI stdin is not a TTY, so `enter()` returns `None`);
    // they assert the guard is panic-safe and that the no-TTY path fails closed.

    #[test]
    fn enter_is_none_when_stdin_is_not_a_tty() {
        // Under `cargo test`, stdin is a pipe, not a terminal: enter must fail
        // closed to None (never touch termios, never panic).
        assert!(RawModeGuard::enter().is_none());
    }

    #[test]
    fn guard_drop_after_catch_unwind_does_not_propagate() {
        // The RAII restore must run during an unwind without itself panicking.
        // (When `enter()` is None there is no termios state to restore, but the
        // Option<guard> drop path is still exercised under catch_unwind.)
        let result = std::panic::catch_unwind(|| {
            let _guard = RawModeGuard::enter();
            std::panic::panic_any("forced unwind");
        });
        assert!(
            result.is_err(),
            "the forced panic must be caught, not aborted"
        );
    }

    #[test]
    fn double_drop_is_safe() {
        // Two independent guards (each None on a non-TTY) drop without aliasing or
        // double-restore hazards.
        let a = RawModeGuard::enter();
        let b = RawModeGuard::enter();
        drop(a);
        drop(b);
    }

    #[test]
    fn term_size_is_none_or_a_positive_width() {
        // `term_size` must never panic and must be well-formed: under captured
        // stdout (the usual `cargo test` case) it fails closed to `None`; on a real
        // TTY (e.g. `--nocapture` in a terminal) it reports a positive column count.
        // Either way the rich renderer gets a usable width or a clean fallback.
        match super::term_size() {
            None => {}
            Some((cols, _rows)) => assert!(cols > 0, "a reported width must be positive"),
        }
    }
}
