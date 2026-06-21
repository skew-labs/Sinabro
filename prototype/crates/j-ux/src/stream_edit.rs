//! `stream_edit.rs` — Progressive edit throttle decision (atom #42 · J.0.2).
//!
//! # Why this madness
//!
//! Phase 0 never performs a Telegram `editMessageText` call. This atom
//! defines only the *decision* surface: given the current wall-clock
//! position and a count of pending bytes accumulated by the upstream
//! SSE buffer, [`should_flush_edit`] returns `true` iff the throttle
//! window has elapsed *and* the pending byte count reaches the
//! editor's batch threshold. The flush itself (a `editMessageText`
//! API call) is wired by a later J.0.x atom — this surface is byte-
//! and clock-pure (zero I/O, zero allocations, no `unsafe`, no new
//! dependencies on the j-ux Cargo.toml).
//!
//! Reuse: upstream concept reuse only from atom #22 (`SseDelta`) and
//! atom #23 (`TurnState`). This module never touches the SSE token
//! strings themselves; it consumes only the integer `pending_bytes_u32`
//! count that the upstream sse buffer exposes ("delta는 M.0.2 sse에서
//! 흘러옴(zero-copy 연결); atom #42 consumes pending_bytes_u32 count
//! from the upstream sse buffer without touching token strings",
//! BUILD_STATE atom #42 reuse note).
//!
//! Throttle spine: `now_ms_u64 - last_edit_ms_u64 >= min_edit_interval_ms_u16`
//! is the time gate; `pending_bytes_u32 >= buf_len_u32` is the size
//! gate; both must hold for a flush. `pending_bytes_u32 == 0` short-
//! circuits to `false` (no idle flush). The end-to-end latency target
//! (first-call <1.2s, median 1.8s — ATOM_PLAN §9.5) lives in J
//! integration and is *not* asserted by this atom — the criterion here
//! is the throttle decision time-base only ("edit throttle 동작(시간
//! 기반; latency 목표는 J 통합에서)", ATOM_PLAN line 1255).
//!
//! Canonical OUT (verbatim from ATOM_PLAN §4.J line 729-730):
//!
//! ```text
//! pub struct ProgressiveEditor { min_edit_interval_ms_u16: u16, last_edit_ms_u64: u64, buf_len_u32: u32 }
//! pub fn should_flush_edit(ed: &ProgressiveEditor, now_ms_u64: u64, pending_bytes_u32: u32) -> bool;
//! ```

// ===========================================================================
// 1. ProgressiveEditor — throttle window + batch threshold configuration
// ===========================================================================

/// Progressive edit throttle configuration. Captures the minimum
/// inter-edit interval (the rate-limit window), the wall-clock
/// millisecond timestamp at which the previous edit was emitted, and
/// the minimum pending-bytes threshold that must accumulate before a
/// new edit becomes eligible.
///
/// The three field widths are pinned by the canonical OUT signature
/// (§4.J line 729): `u16` for the interval (≤ ~65 s — Phase 0 expects
/// sub-second values, e.g. 1_500 ms = the §9.5 "median 1.8 s"
/// baseline), `u64` for the last-edit timestamp (millisecond-resolution
/// wall clock — `u32` would saturate before ~50 days of uptime, which
/// is below the supervisor's intended uptime), and `u32` for the byte
/// threshold (Telegram caps `editMessageText` at 4 096 characters,
/// well inside `u32`).
///
/// Field visibility is private — public accessors are `const fn` and
/// return owned values. Construction goes through
/// [`ProgressiveEditor::new`]; the editor is `Copy`, so callers may
/// freely snapshot it before each decision without moving the
/// configuration out of the surrounding `&self` borrow.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub struct ProgressiveEditor {
    /// Minimum number of milliseconds that must elapse between two
    /// consecutive flushes. `u16` upper-bounds the interval at
    /// 65_535 ms (~65 s), which is sufficient for any progressive-
    /// edit cadence (§9.5 expects 1_200–1_800 ms).
    min_edit_interval_ms_u16: u16,
    /// Wall-clock millisecond timestamp of the previous successful
    /// flush. `u64` matches the canonical OUT signature; values are
    /// expected to be milliseconds since the Unix epoch (or any
    /// monotonic-millisecond clock the caller chooses — the
    /// arithmetic in [`should_flush_edit`] is `saturating_sub`, so a
    /// retrograde reading cannot panic).
    last_edit_ms_u64: u64,
    /// Minimum number of pending bytes that must accumulate before a
    /// flush becomes eligible. `u32` is wide enough to express
    /// Telegram's 4 096-character `editMessageText` limit many times
    /// over and matches the canonical OUT signature.
    buf_len_u32: u32,
}

impl ProgressiveEditor {
    /// Construct a [`ProgressiveEditor`] from its three field-pinned
    /// configuration values. All three widths are verbatim from the
    /// canonical OUT (`u16` / `u64` / `u32`); the constructor is
    /// `const fn` so an editor may be declared at module scope or
    /// inside a `const` item for compile-time wiring.
    #[inline]
    pub const fn new(
        min_edit_interval_ms_u16: u16,
        last_edit_ms_u64: u64,
        buf_len_u32: u32,
    ) -> Self {
        Self {
            min_edit_interval_ms_u16,
            last_edit_ms_u64,
            buf_len_u32,
        }
    }

    /// Read the configured minimum inter-edit interval in milliseconds.
    #[inline]
    pub const fn min_edit_interval_ms(&self) -> u16 {
        self.min_edit_interval_ms_u16
    }

    /// Read the timestamp (wall-clock milliseconds) of the previous
    /// flush. Returns `0` for a freshly-constructed editor that has
    /// not yet flushed.
    #[inline]
    pub const fn last_edit_ms(&self) -> u64 {
        self.last_edit_ms_u64
    }

    /// Read the configured byte threshold above which the pending
    /// buffer becomes flush-eligible.
    #[inline]
    pub const fn buf_len(&self) -> u32 {
        self.buf_len_u32
    }
}

// ===========================================================================
// 2. should_flush_edit — pure decision function (no I/O, no mutation)
// ===========================================================================

/// Decide whether a progressive edit should be flushed *now*.
///
/// Returns `true` iff **all three** of the following predicates hold:
///
/// 1. `pending_bytes_u32 > 0` — the upstream buffer has new content. A
///    zero count short-circuits to `false`: an empty flush would
///    produce no user-visible change while consuming the editor's
///    rate-limit budget (`j0_2_no_flush_when_idle` spine, ATOM_PLAN
///    line 1254).
///
/// 2. `now_ms_u64 - ed.last_edit_ms_u64 >= ed.min_edit_interval_ms_u16`
///    — the throttle window has elapsed since the previous flush. The
///    subtraction is `saturating_sub`, so a `now_ms_u64` that is
///    *earlier* than `last_edit_ms_u64` (clock skew, retrograde
///    monotonic counter) collapses to a zero-elapsed reading and
///    therefore returns `false` rather than panicking
///    (`j0_2_flush_respects_interval` spine, ATOM_PLAN line 1254).
///
/// 3. `pending_bytes_u32 >= ed.buf_len_u32` — the pending content has
///    grown to at least the configured batch threshold. This is the
///    `j0_2_flush_on_threshold` spine (ATOM_PLAN line 1254): a sub-
///    threshold buffer waits for more deltas even if the interval
///    elapsed, which limits how chatty the editor can be when the
///    upstream SSE delivers tiny token chunks.
///
/// The function is `const fn` (all arithmetic is `const`-compatible),
/// takes `&ProgressiveEditor` (no mutation), and performs no I/O — it
/// is the *decision* surface; the corresponding `editMessageText`
/// transport call is wired by a later J.0.x atom.
#[inline]
pub const fn should_flush_edit(
    ed: &ProgressiveEditor,
    now_ms_u64: u64,
    pending_bytes_u32: u32,
) -> bool {
    // Predicate 1: idle short-circuit. A zero pending count means no
    // user-visible change would result from flushing now; emitting an
    // edit would waste the throttle budget.
    if pending_bytes_u32 == 0 {
        return false;
    }
    // Predicate 2: time gate. `saturating_sub` collapses retrograde
    // clock readings to zero elapsed (which then fails the `<`
    // comparison and returns `false`), strictly safer than panicking
    // on underflow. The `u16 → u64` widening conversion is lossless
    // by construction.
    let elapsed_ms_u64 = now_ms_u64.saturating_sub(ed.last_edit_ms_u64);
    if elapsed_ms_u64 < ed.min_edit_interval_ms_u16 as u64 {
        return false;
    }
    // Predicate 3: size gate. Both operands are `u32`, so the
    // comparison is direct (no widening required).
    pending_bytes_u32 >= ed.buf_len_u32
}

// ===========================================================================
// 3. Tests — three test names verbatim per ATOM_PLAN line 1254
// ===========================================================================

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    /// The throttle window is respected: even a buffer well above the
    /// size threshold cannot trigger a flush before the configured
    /// interval has elapsed.
    #[test]
    fn j0_2_flush_respects_interval() {
        // Interval 100 ms, previous flush at t = 1_000 ms, threshold 8 B.
        let ed = ProgressiveEditor::new(100, 1_000, 8);

        // Only 50 ms after the previous flush — even a generous 256 B
        // pending buffer must NOT flush.
        assert!(!should_flush_edit(&ed, 1_050, 256));
        // Exactly 99 ms — still inside the throttle window.
        assert!(!should_flush_edit(&ed, 1_099, 256));
        // Exactly 100 ms elapsed AND pending ≥ threshold — eligible.
        assert!(should_flush_edit(&ed, 1_100, 256));
        // 101 ms elapsed (one tick past the boundary) — still eligible.
        assert!(should_flush_edit(&ed, 1_101, 256));

        // Retrograde clock (now < last_edit_ms) collapses to zero
        // elapsed via saturating_sub — must return false, not panic.
        assert!(!should_flush_edit(&ed, 500, 256));
        assert!(!should_flush_edit(&ed, 0, 256));
    }

    /// The size threshold is respected: even after the throttle window
    /// has fully elapsed, a sub-threshold pending count must NOT flush,
    /// while a count at or above the threshold MUST flush.
    #[test]
    fn j0_2_flush_on_threshold() {
        // Interval 50 ms, previous flush at t = 0, threshold 16 B.
        let ed = ProgressiveEditor::new(50, 0, 16);

        // Interval elapsed (10x) but pending below threshold — no flush.
        assert!(!should_flush_edit(&ed, 500, 1));
        assert!(!should_flush_edit(&ed, 500, 15));
        // Pending exactly at threshold and interval elapsed — flush.
        assert!(should_flush_edit(&ed, 500, 16));
        // Pending above threshold and interval elapsed — flush.
        assert!(should_flush_edit(&ed, 500, 32));
        assert!(should_flush_edit(&ed, 500, u32::MAX));

        // Threshold of zero means *any* non-empty pending count flushes
        // (subject to the time gate). Useful for "flush as soon as the
        // throttle allows" cadences.
        let no_size_gate = ProgressiveEditor::new(50, 0, 0);
        assert!(should_flush_edit(&no_size_gate, 500, 1));
        assert!(should_flush_edit(&no_size_gate, 500, u32::MAX));
        // Still respects the idle short-circuit:
        assert!(!should_flush_edit(&no_size_gate, 500, 0));
    }

    /// The idle short-circuit: a zero pending byte count NEVER flushes,
    /// regardless of how much wall-clock time has elapsed. Also pins
    /// the `ProgressiveEditor` byte size and round-trips every public
    /// accessor (atom #41 `j0_1_allowlist_is_static` size-pin pattern).
    #[test]
    fn j0_2_no_flush_when_idle() {
        // Interval 50 ms, previous flush at t = 0, threshold 8 B.
        let ed = ProgressiveEditor::new(50, 0, 8);

        // Immediately after the previous flush — idle, no flush.
        assert!(!should_flush_edit(&ed, 0, 0));
        // Long after the previous flush — still idle, still no flush.
        assert!(!should_flush_edit(&ed, 10_000, 0));
        // Maximum possible wall-clock — still no flush. The size gate
        // (here threshold 8 B vs pending 0 B) is enforced first by
        // structure: pending == 0 short-circuits before the time gate.
        assert!(!should_flush_edit(&ed, u64::MAX, 0));

        // A zero-threshold editor (which would otherwise eagerly flush)
        // also obeys the idle short-circuit.
        let eager = ProgressiveEditor::new(0, 0, 0);
        assert!(!should_flush_edit(&eager, 0, 0));
        assert!(!should_flush_edit(&eager, u64::MAX, 0));

        // Surface-stability pin: u16 (2 B) + u64 (8 B) + u32 (4 B) =
        // 14 B raw; with natural alignment to 8 B (u64 forces 8 B
        // alignment), the struct occupies at most 24 B on every
        // Tier-1 target. Asserts an upper bound to stay portable;
        // a future accidental field addition (e.g. a String buffer or
        // a token field) would change the byte size and fail here,
        // surfacing the surface-creep at the gate, not at runtime.
        assert!(core::mem::size_of::<ProgressiveEditor>() <= 24);

        // Accessor round-trip: every config value returned losslessly.
        let cfg = ProgressiveEditor::new(1_500, 9_876_543, 64);
        assert_eq!(cfg.min_edit_interval_ms(), 1_500);
        assert_eq!(cfg.last_edit_ms(), 9_876_543);
        assert_eq!(cfg.buf_len(), 64);

        // Editor is Copy — snapshotting before each decision does not
        // move the configuration out of any surrounding borrow.
        let snapshot = cfg;
        assert_eq!(snapshot.last_edit_ms(), cfg.last_edit_ms());
    }
}
