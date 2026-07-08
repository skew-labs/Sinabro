//! Streaming agent-turn bridge.
//!
//! The bridge lets the first token render while tools still run in the
//! background: chunks flow as soon as they arrive, each carrying the turn's
//! trace id, and a cancel stops the flow immediately. Partial output is redacted
//! before it is ever surfaced — a secret-shaped chunk never renders raw.

use crate::StageFTraceLink;
use crate::repl::history::classify;

/// Lifecycle of a streaming turn.
#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StreamState {
    /// Created, not yet streaming.
    Idle = 1,
    /// Actively streaming chunks.
    Streaming = 2,
    /// Cancelled by the user; no further chunks accepted.
    Cancelled = 3,
    /// Completed normally.
    Done = 4,
}

/// One streamed chunk. Bound to the turn's trace id; `redacted` marks a chunk
/// whose raw text was secret-shaped and was replaced before surfacing.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StreamChunk {
    /// Zero-based sequence number within the turn.
    pub seq_u32: u32,
    /// Trace link binding the chunk to its turn.
    pub trace: StageFTraceLink,
    /// Whether the chunk text was redacted.
    pub redacted: bool,
    /// The (possibly redacted) chunk text.
    pub text: String,
}

/// The streaming bridge for one agent turn.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StreamBridge {
    state: StreamState,
    trace: StageFTraceLink,
    next_seq: u32,
    first_rendered: bool,
}

impl StreamBridge {
    /// A bridge for the turn identified by `trace`, in [`StreamState::Idle`].
    #[must_use]
    pub const fn new(trace: StageFTraceLink) -> Self {
        Self {
            state: StreamState::Idle,
            trace,
            next_seq: 0,
            first_rendered: false,
        }
    }

    /// Begin streaming: `Idle` -> `Streaming`. No-op in any other state.
    pub const fn begin(&mut self) {
        if matches!(self.state, StreamState::Idle) {
            self.state = StreamState::Streaming;
        }
    }

    /// Current lifecycle state.
    #[must_use]
    pub const fn state(&self) -> StreamState {
        self.state
    }

    /// Whether at least one chunk has rendered (proves first-token-render can
    /// happen before the turn finishes).
    #[must_use]
    pub const fn first_rendered(&self) -> bool {
        self.first_rendered
    }

    /// Number of chunks emitted so far.
    #[must_use]
    pub const fn chunk_count(&self) -> u32 {
        self.next_seq
    }

    /// Push a raw chunk. Returns the (redaction-checked) [`StreamChunk`] while
    /// streaming, or `None` once the turn is cancelled / done / not yet begun.
    /// Secret-shaped text is replaced with `<redacted>` before it leaves here.
    pub fn push_chunk(&mut self, raw: &str) -> Option<StreamChunk> {
        if !matches!(self.state, StreamState::Streaming) {
            return None;
        }
        // Reuse the shared secret/key classifier from `history` so the REPL's
        // input history and its streamed output redact by the same policy.
        let redacted = classify(raw).is_some();
        let text = if redacted {
            "<redacted>".to_string()
        } else {
            raw.to_string()
        };
        let chunk = StreamChunk {
            seq_u32: self.next_seq,
            trace: self.trace,
            redacted,
            text,
        };
        self.next_seq = self.next_seq.saturating_add(1);
        self.first_rendered = true;
        Some(chunk)
    }

    /// Cancel the turn: `Streaming` -> `Cancelled`. Returns whether a live turn
    /// was actually cancelled.
    pub const fn cancel(&mut self) -> bool {
        if matches!(self.state, StreamState::Streaming) {
            self.state = StreamState::Cancelled;
            true
        } else {
            false
        }
    }

    /// Finish the turn normally: `Streaming` -> `Done`. Returns whether a live
    /// turn was actually finished.
    pub const fn finish(&mut self) -> bool {
        if matches!(self.state, StreamState::Streaming) {
            self.state = StreamState::Done;
            true
        } else {
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn trace() -> StageFTraceLink {
        StageFTraceLink::new([4u8; 32], 414, 414)
    }

    #[test]
    fn streaming_emits_sequenced_chunks() {
        let mut b = StreamBridge::new(trace());
        assert!(!b.first_rendered());
        b.begin();
        let c0 = b.push_chunk("hello");
        let c1 = b.push_chunk(" world");
        assert!(b.first_rendered());
        assert_eq!(c0.map(|c| c.seq_u32), Some(0));
        assert_eq!(c1.map(|c| c.seq_u32), Some(1));
        assert_eq!(b.chunk_count(), 2);
    }

    #[test]
    fn no_chunk_before_begin() {
        let mut b = StreamBridge::new(trace());
        assert_eq!(b.push_chunk("x"), None);
        assert!(!b.first_rendered());
    }

    #[test]
    fn cancel_stops_the_flow() {
        let mut b = StreamBridge::new(trace());
        b.begin();
        assert!(b.push_chunk("partial").is_some());
        assert!(b.cancel());
        assert_eq!(b.state(), StreamState::Cancelled);
        assert_eq!(b.push_chunk("after-cancel"), None);
        // double cancel is a no-op
        assert!(!b.cancel());
    }

    #[test]
    fn secret_chunk_is_redacted() {
        let mut b = StreamBridge::new(trace());
        b.begin();
        let chunk = b.push_chunk("placeholderSecretForRedactionUnitTestOnly00");
        assert!(chunk.is_some());
        if let Some(c) = chunk {
            assert!(c.redacted);
            assert_eq!(c.text, "<redacted>");
        }
    }

    #[test]
    fn every_chunk_links_the_same_trace() {
        let mut b = StreamBridge::new(trace());
        b.begin();
        let a = b.push_chunk("a");
        let c = b.push_chunk("b");
        assert_eq!(a.map(|x| x.trace), Some(trace()));
        assert_eq!(c.map(|x| x.trace), Some(trace()));
    }

    #[test]
    fn finish_closes_the_turn() {
        let mut b = StreamBridge::new(trace());
        b.begin();
        assert!(b.finish());
        assert_eq!(b.state(), StreamState::Done);
        assert_eq!(b.push_chunk("late"), None);
        assert!(!b.finish());
    }
}
