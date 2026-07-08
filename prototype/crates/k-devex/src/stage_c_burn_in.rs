//! Burn-in monitoring window.
//!
//! Public surface: [`BurnInWindow`].
//!
//! # Invariants
//!
//! * **Read-only monitoring plus pause triggers — never a reward signal.** A
//!   burn-in window records when monitoring started, how long it must run, how
//!   many anomalies were observed, and whether an operator paused it. It exposes
//!   no positive signal of any kind; nothing here feeds training reward. Its
//!   only authority is to *withhold* the gate ([`gate_open`](BurnInWindow::gate_open)
//!   returns `false`) until the window has elapsed cleanly.
//! * **Anomalies are monotonic and saturating.** [`record_anomaly`](BurnInWindow::record_anomaly)
//!   increments a saturating `u32` counter, mirroring the
//!   [`MetricsExporter`](crate::metrics::MetricsExporter) counter discipline
//!   — a runaway producer can never wrap the count to a small
//!   (passing) value. A single observed anomaly keeps the gate closed.
//! * **Paused blocks the gate.** While `paused` is set the gate is closed
//!   regardless of elapsed time or anomaly count, so an operator can always halt
//!   promotion.
//!
//! # Related
//!
//! * The anomaly counter follows the [`crate::metrics`]
//!   monotonic-saturating-counter discipline; the concrete
//!   [`MetricsExporter`](crate::metrics::MetricsExporter) is driven by the
//!   canary monitor that feeds this window.
//! * A burn-in window gates the mainnet ceremony transcript.
//!
//! No live action: this is monitoring state. `MainnetExecutionState` stays
//! `Locked`.

/// Burn-in window monitoring state.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub struct BurnInWindow {
    /// The epoch at which burn-in monitoring started.
    pub started_epoch_u64: u64,
    /// The required burn-in duration in seconds.
    pub duration_secs_u32: u32,
    /// The number of anomalies observed during the window (saturating).
    pub anomaly_count_u32: u32,
    /// Whether an operator has paused the window (gate stays closed).
    pub paused: bool,
}

/// Burn-in duration-parse error. Every variant is data-free.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
#[repr(u8)]
pub enum BurnInError {
    /// The duration string was empty.
    EmptyDuration = 1,
    /// The duration string was not a non-negative integer with an optional
    /// `s`/`m`/`h` suffix.
    MalformedDuration = 2,
    /// The parsed duration overflowed `u32` seconds.
    DurationOverflow = 3,
}

impl core::fmt::Display for BurnInError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let msg = match self {
            Self::EmptyDuration => "stage_c burn-in: empty duration",
            Self::MalformedDuration => "stage_c burn-in: malformed duration",
            Self::DurationOverflow => "stage_c burn-in: duration overflow",
        };
        f.write_str(msg)
    }
}

impl core::error::Error for BurnInError {}

/// Parse a burn-in duration into seconds. Accepts a non-negative integer with an
/// optional unit suffix: `s` (seconds, default), `m` (minutes), `h` (hours).
///
/// # Errors
///
/// [`BurnInError::EmptyDuration`] for an empty string,
/// [`BurnInError::MalformedDuration`] for a non-numeric body or unknown suffix,
/// and [`BurnInError::DurationOverflow`] when the result exceeds `u32`.
pub fn parse_duration_secs(raw: &str) -> Result<u32, BurnInError> {
    let s = raw.trim();
    if s.is_empty() {
        return Err(BurnInError::EmptyDuration);
    }
    let (digits, mult) = match s.as_bytes().last() {
        Some(b's') => (&s[..s.len() - 1], 1u32),
        Some(b'm') => (&s[..s.len() - 1], 60u32),
        Some(b'h') => (&s[..s.len() - 1], 3600u32),
        Some(b'0'..=b'9') => (s, 1u32),
        _ => return Err(BurnInError::MalformedDuration),
    };
    if digits.is_empty() {
        return Err(BurnInError::MalformedDuration);
    }
    let base: u32 = digits.parse().map_err(|_| BurnInError::MalformedDuration)?;
    base.checked_mul(mult).ok_or(BurnInError::DurationOverflow)
}

impl BurnInWindow {
    /// Start a fresh, unpaused burn-in window with no anomalies.
    #[inline]
    #[must_use]
    pub const fn new(started_epoch_u64: u64, duration_secs_u32: u32) -> Self {
        Self {
            started_epoch_u64,
            duration_secs_u32,
            anomaly_count_u32: 0,
            paused: false,
        }
    }

    /// Record one observed anomaly (saturating increment).
    #[inline]
    pub fn record_anomaly(&mut self) {
        self.anomaly_count_u32 = self.anomaly_count_u32.saturating_add(1);
    }

    /// Pause the window (gate stays closed).
    #[inline]
    pub fn pause(&mut self) {
        self.paused = true;
    }

    /// Resume the window.
    #[inline]
    pub fn resume(&mut self) {
        self.paused = false;
    }

    /// Whether the burn-in duration has elapsed at `now_epoch` (saturating add
    /// so a far-future start cannot wrap the deadline).
    #[inline]
    #[must_use]
    pub const fn is_elapsed(&self, now_epoch_u64: u64) -> bool {
        let deadline = self
            .started_epoch_u64
            .saturating_add(self.duration_secs_u32 as u64);
        now_epoch_u64 >= deadline
    }

    /// Whether the gate may open: not paused, the duration has elapsed, and no
    /// anomaly was observed. This is the only authority the window has, and it
    /// is purely a *withholding* one.
    #[inline]
    #[must_use]
    pub const fn gate_open(&self, now_epoch_u64: u64) -> bool {
        !self.paused && self.is_elapsed(now_epoch_u64) && self.anomaly_count_u32 == 0
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]
    use super::*;

    #[test]
    fn duration_parse() {
        assert_eq!(parse_duration_secs("3600"), Ok(3600));
        assert_eq!(parse_duration_secs("90s"), Ok(90));
        assert_eq!(parse_duration_secs("5m"), Ok(300));
        assert_eq!(parse_duration_secs("2h"), Ok(7200));
        assert_eq!(parse_duration_secs(""), Err(BurnInError::EmptyDuration));
        assert_eq!(
            parse_duration_secs("ten"),
            Err(BurnInError::MalformedDuration)
        );
        assert_eq!(
            parse_duration_secs("h"),
            Err(BurnInError::MalformedDuration)
        );
        assert_eq!(
            parse_duration_secs("4000000000h"),
            Err(BurnInError::DurationOverflow)
        );
    }

    #[test]
    fn anomaly_increments() {
        let mut w = BurnInWindow::new(100, 3600);
        assert_eq!(w.anomaly_count_u32, 0);
        w.record_anomaly();
        w.record_anomaly();
        assert_eq!(w.anomaly_count_u32, 2);
        // Saturating: cannot wrap.
        w.anomaly_count_u32 = u32::MAX;
        w.record_anomaly();
        assert_eq!(w.anomaly_count_u32, u32::MAX);
        // One anomaly keeps the gate closed even after elapse.
        let mut clean = BurnInWindow::new(100, 100);
        assert!(clean.gate_open(300));
        clean.record_anomaly();
        assert!(!clean.gate_open(300));
    }

    #[test]
    fn paused_blocks_gate() {
        let mut w = BurnInWindow::new(100, 100);
        // Elapsed, clean, not paused -> open.
        assert!(w.gate_open(300));
        // Not elapsed -> closed.
        assert!(!w.gate_open(150));
        // Paused -> closed regardless of elapse.
        w.pause();
        assert!(!w.gate_open(300));
        w.resume();
        assert!(w.gate_open(300));
    }
}
