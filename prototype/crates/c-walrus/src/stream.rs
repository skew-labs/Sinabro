//! Bounded chunk-frame stream for `c-walrus`.
//!
//! # Wire format (canonical, reuses the `wire` primitives)
//!
//! A stream is a sequence of length-prefixed frames concatenated into a
//! single byte buffer:
//!
//! ```text
//! frame_0 = uleb128(len_0) || body_0          (body_0.len() == len_0, uleb128 strict-canonical)
//! frame_1 = uleb128(len_1) || body_1
//! ...
//! stream  = frame_0 || frame_1 || ... || frame_{N-1}
//! ```
//!
//! The `uleb128` encoding is *byte-identical* to the `uleb128(len) || bytes`
//! prefix used by `Vec<u8>` in the BCS chunk envelope ([`crate::codec`]),
//! so a frame body can itself be the encoded envelope ([`crate::codec::encode_chunk_v1`]
//! output) without any further wrapping. That is the reuse seam this atom
//! claims: stream multiplexes raw byte frames; the codec atom decides what
//! each body means.
//!
//! # Invariants
//!
//! * **Reader is zero-copy.** [`ChunkStreamReader::next_frame`] returns
//!   `&'a [u8]` slices borrowed directly from the source slice the reader
//!   was constructed with; no per-frame allocation, no per-frame copy.
//!   The borrow checker carries the invariant: the returned slice shares
//!   the source's lifetime `'a`.
//! * **Writer enforces a cumulative byte cap (no unbounded buffering).**
//!   Each successful push extends `sink: &mut Vec<u8>` by `uleb128_len(frame.len())
//!   + frame.len()` bytes; the writer tracks the running total in
//!   `written_u32` and refuses any push whose new total would exceed
//!   `cap_u32`. On refusal the writer transitions to a *closed* state
//!   (`written_u32 == u32::MAX`); subsequent pushes return
//!   [`StreamError::BackpressureClosed`] (no-infinite-buffer discipline).
//! * **No `unsafe`.** The crate-level `#![deny(unsafe_code)]` is retained;
//!   the close sentinel is a value of `written_u32`, not a separate `bool`
//!   field (the public struct shape has exactly three
//!   fields: `sink`, `written_u32`, `cap_u32`).
//! * **Frame length is u32.** Any frame whose `len()` would not fit in
//!   `u32`, any cumulative arithmetic that would overflow `u32`, and any
//!   reader-side length prefix that exceeds `u32::MAX` is rejected via the
//!   same surface (`CapExceeded` for the writer, `Truncated` for the
//!   reader). The `uleb128_u32` codec from [`crate::wire`] caps prefixes
//!   at five bytes.
//!
//! # Carve-outs
//!
//! * **`cap_u32 == u32::MAX` is undefined as "ever-closing".** The close
//!   sentinel is `written_u32 == u32::MAX`; if a caller chooses a cap of
//!   `u32::MAX`, the cumulative-cap check never trips (cumulative bytes
//!   are bounded above by `u32::MAX` themselves), so the writer never
//!   closes via the cap path. That is precisely the unbounded-buffer
//!   behavior this stream forbids; callers are expected to choose a finite cap.
//!   The constructor does not validate this — caller responsibility.

use crate::wire::{WireReader, append_uleb128_u32};

// ===========================================================================
// 1. Public error surface
// ===========================================================================

/// Failure modes for the bounded chunk-frame stream.
///
/// All variants are `Copy` and field-light (the only field is the cap
/// itself, a `u32`), so a raw frame body is never embedded in an error
/// class.
///
/// Class-label namespace: `stream.*`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum StreamError {
    /// The push would have caused the cumulative written byte count to
    /// exceed the writer's `cap_u32`. The writer is now closed; subsequent
    /// pushes return [`StreamError::BackpressureClosed`].
    CapExceeded {
        /// The cap that was breached, in bytes.
        cap_u32: u32,
    },
    /// The reader's source slice ended mid-frame: either the length
    /// prefix itself was incomplete / non-canonical / overflowed `u32`,
    /// or the prefix promised more body bytes than remained in the
    /// source.
    Truncated,
    /// A push was attempted after the writer had already closed due to a
    /// prior [`StreamError::CapExceeded`]. The writer never reopens.
    BackpressureClosed,
}

impl StreamError {
    /// Stable per-variant byte tag (audit-targetability mirror of
    /// `ChunkCodecError`, `PublisherClientError`, `FetchStopReason`,
    /// `BlobIdError`).
    #[inline]
    pub const fn tag(&self) -> u8 {
        match self {
            StreamError::CapExceeded { .. } => 1,
            StreamError::Truncated => 2,
            StreamError::BackpressureClosed => 3,
        }
    }

    /// Stable, namespaced `'static` class label for log redaction
    /// allowlists.
    #[inline]
    pub const fn class_label(&self) -> &'static str {
        match self {
            StreamError::CapExceeded { .. } => "stream.cap_exceeded",
            StreamError::Truncated => "stream.truncated",
            StreamError::BackpressureClosed => "stream.backpressure_closed",
        }
    }
}

// ===========================================================================
// 2. Helper — canonical uleb128 length for u32 (no allocation)
// ===========================================================================

/// Number of bytes a canonical uleb128 encoding of `value` occupies.
///
/// Pinned by `uleb128_encoded_len_u32_matches_actual_encoding` against the
/// concrete byte counts produced by [`crate::wire::append_uleb128_u32`].
#[inline]
pub const fn uleb128_encoded_len_u32(value: u32) -> u32 {
    // ceil(bits_needed / 7), with a floor of 1.
    if value < 0x80 {
        1
    } else if value < 0x4000 {
        2
    } else if value < 0x0020_0000 {
        3
    } else if value < 0x1000_0000 {
        4
    } else {
        5
    }
}

// ===========================================================================
// 3. Writer
// ===========================================================================

/// Append-only writer that emits canonical length-prefixed frames into a
/// borrowed `Vec<u8>` and enforces a cumulative byte cap.
///
/// The internal sentinel for the closed state is `written_u32 == u32::MAX`.
/// See the module-level *Carve-outs* note for the `cap_u32 == u32::MAX`
/// edge case.
pub struct ChunkStreamWriter<'a> {
    /// Destination buffer the writer appends to. Pre-existing contents
    /// of `sink` are *not* counted against `cap_u32`; only bytes the
    /// writer itself appends do.
    sink: &'a mut Vec<u8>,
    /// Cumulative bytes appended by this writer (uleb128 prefix + body
    /// per frame). `u32::MAX` is the closed sentinel.
    written_u32: u32,
    /// Maximum cumulative bytes the writer may append. See the
    /// carve-outs note for `u32::MAX`.
    cap_u32: u32,
}

impl<'a> ChunkStreamWriter<'a> {
    /// Construct a writer that may append at most `cap_u32` cumulative
    /// bytes to `sink`. The constructor does not touch `sink`.
    #[inline]
    pub const fn new(sink: &'a mut Vec<u8>, cap_u32: u32) -> Self {
        Self {
            sink,
            written_u32: 0,
            cap_u32,
        }
    }

    /// Cumulative bytes the writer has appended so far (does not include
    /// pre-existing contents of `sink`). Returns `u32::MAX` when the
    /// writer has been closed by a prior [`StreamError::CapExceeded`].
    #[inline]
    pub const fn written_bytes_u32(&self) -> u32 {
        self.written_u32
    }

    /// The cumulative byte cap the writer was constructed with.
    #[inline]
    pub const fn cap_bytes_u32(&self) -> u32 {
        self.cap_u32
    }

    /// Whether the writer has closed due to a prior
    /// [`StreamError::CapExceeded`]. A closed writer never reopens.
    #[inline]
    pub const fn is_closed(&self) -> bool {
        self.written_u32 == u32::MAX
    }

    /// Append a length-prefixed frame to the underlying `sink`.
    ///
    /// On success returns the new cumulative byte count
    /// (`written_bytes_u32` after the push).
    ///
    /// Failure modes:
    /// * [`StreamError::BackpressureClosed`] if the writer was already
    ///   closed by an earlier push.
    /// * [`StreamError::CapExceeded`] if any of the following holds:
    ///   `frame.len()` does not fit in `u32`; the
    ///   `prefix + body + already-written` arithmetic would overflow `u32`;
    ///   or the new cumulative total would exceed `cap_u32`. In all three
    ///   sub-cases the writer transitions to the closed state.
    pub fn push_frame(&mut self, frame: &[u8]) -> Result<u32, StreamError> {
        if self.written_u32 == u32::MAX {
            return Err(StreamError::BackpressureClosed);
        }
        let cap = self.cap_u32;
        // Frame length must fit in u32 (uleb128_u32 prefix universe).
        let frame_len_u32 = match u32::try_from(frame.len()) {
            Ok(v) => v,
            Err(_) => {
                self.written_u32 = u32::MAX;
                return Err(StreamError::CapExceeded { cap_u32: cap });
            }
        };
        let prefix_len_u32 = uleb128_encoded_len_u32(frame_len_u32);
        // needed = prefix + body, checked for u32 overflow.
        let needed_u32 = match prefix_len_u32.checked_add(frame_len_u32) {
            Some(v) => v,
            None => {
                self.written_u32 = u32::MAX;
                return Err(StreamError::CapExceeded { cap_u32: cap });
            }
        };
        // new_total = written + needed, checked for u32 overflow.
        let new_total = match self.written_u32.checked_add(needed_u32) {
            Some(v) => v,
            None => {
                self.written_u32 = u32::MAX;
                return Err(StreamError::CapExceeded { cap_u32: cap });
            }
        };
        if new_total > cap {
            self.written_u32 = u32::MAX;
            return Err(StreamError::CapExceeded { cap_u32: cap });
        }
        // Cumulative-cap check passed; emit the frame.
        // Both calls below are infallible byte appends on a `Vec<u8>`.
        append_uleb128_u32(self.sink, frame_len_u32);
        self.sink.extend_from_slice(frame);
        self.written_u32 = new_total;
        Ok(new_total)
    }
}

// ===========================================================================
// 4. Reader (zero-copy)
// ===========================================================================

/// Forward, zero-copy reader over a stream of length-prefixed frames.
///
/// Each [`ChunkStreamReader::next_frame`] call returns either:
/// * `Ok(Some(&'a [u8]))` — a slice borrowing from the original source
///   slice, with the same lifetime; the caller may consume it without
///   copying;
/// * `Ok(None)` — the source has been fully consumed;
/// * `Err(StreamError::Truncated)` — the source ended mid-frame, or a
///   length prefix was malformed (non-canonical uleb128 / `u32`
///   overflow).
pub struct ChunkStreamReader<'a> {
    /// Backing slice. Lifetime `'a` propagates to returned frames.
    src: &'a [u8],
    /// Byte position within `src` of the next frame to read.
    pos: usize,
}

impl<'a> ChunkStreamReader<'a> {
    /// Construct a reader positioned at byte 0 of `src`.
    #[inline]
    pub const fn new(src: &'a [u8]) -> Self {
        Self { src, pos: 0 }
    }

    /// Current byte offset into the source slice.
    #[inline]
    pub const fn position(&self) -> usize {
        self.pos
    }

    /// Bytes remaining in the source slice (saturated at zero).
    #[inline]
    pub const fn remaining(&self) -> usize {
        // `usize::saturating_sub` is not yet `const`; do it by hand.
        if self.pos >= self.src.len() {
            0
        } else {
            self.src.len() - self.pos
        }
    }

    /// Return the next frame as a zero-copy borrow into the source slice,
    /// advancing the reader past it.
    ///
    /// Returns `Ok(None)` when the source has been fully consumed.
    ///
    /// Returns `Err(StreamError::Truncated)` if the next length prefix is
    /// itself truncated, non-canonical, or overflows `u32`, or if the
    /// prefix promises more body bytes than the source has remaining.
    pub fn next_frame(&mut self) -> Result<Option<&'a [u8]>, StreamError> {
        if self.pos == self.src.len() {
            return Ok(None);
        }
        // Decode the next length prefix.
        let tail: &'a [u8] = &self.src[self.pos..];
        let mut wr = WireReader::new(tail);
        let frame_len_u32 = wr.read_uleb128_u32().map_err(|_| StreamError::Truncated)?;
        // Borrow the body as a zero-copy slice from `tail` (and hence
        // from `self.src`), with lifetime `'a`.
        let frame: &'a [u8] = wr
            .take(frame_len_u32 as usize)
            .map_err(|_| StreamError::Truncated)?;
        // Advance `self.pos` by exactly prefix + body. The prefix size
        // is a deterministic function of the decoded value.
        let prefix_len = uleb128_encoded_len_u32(frame_len_u32) as usize;
        // Both adds are bounded by `self.src.len()` (the take above
        // already verified the bytes existed) and so cannot overflow.
        self.pos = self.pos + prefix_len + (frame_len_u32 as usize);
        Ok(Some(frame))
    }
}

// ===========================================================================
// 5. Inline unit tests (within-module invariants; integration tests live
//     in `tests/stream.rs`).
// ===========================================================================

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    #![allow(clippy::expect_used)]
    #![allow(clippy::panic)]

    use super::*;

    #[test]
    fn stream_error_tag_values_are_stable_and_in_order() {
        assert_eq!(StreamError::CapExceeded { cap_u32: 0 }.tag(), 1);
        assert_eq!(StreamError::Truncated.tag(), 2);
        assert_eq!(StreamError::BackpressureClosed.tag(), 3);
    }

    #[test]
    fn stream_error_class_labels_are_namespaced_under_stream() {
        let labels = [
            StreamError::CapExceeded { cap_u32: 0 }.class_label(),
            StreamError::Truncated.class_label(),
            StreamError::BackpressureClosed.class_label(),
        ];
        for label in labels {
            assert!(
                label.starts_with("stream."),
                "label `{label}` must be namespaced under `stream.*`"
            );
        }
        // Uniqueness.
        assert_ne!(labels[0], labels[1]);
        assert_ne!(labels[1], labels[2]);
        assert_ne!(labels[0], labels[2]);
    }

    #[test]
    fn uleb128_encoded_len_u32_matches_actual_encoding() {
        // For each value tested, compare the `const fn` against
        // `append_uleb128_u32` byte length.
        let samples: [u32; 12] = [
            0,
            1,
            0x7F,
            0x80,
            0x3FFF,
            0x4000,
            0x001F_FFFF,
            0x0020_0000,
            0x0FFF_FFFF,
            0x1000_0000,
            u32::MAX - 1,
            u32::MAX,
        ];
        for v in samples {
            let mut buf = Vec::new();
            append_uleb128_u32(&mut buf, v);
            let actual = buf.len() as u32;
            let predicted = uleb128_encoded_len_u32(v);
            assert_eq!(
                predicted, actual,
                "uleb128_encoded_len_u32({v}) = {predicted}, actual append = {actual}",
            );
            // And the prediction must be in [1, 5].
            assert!((1..=5).contains(&predicted));
        }
    }

    #[test]
    fn writer_starts_with_zero_written_bytes() {
        let mut sink = Vec::new();
        let w = ChunkStreamWriter::new(&mut sink, 100);
        assert_eq!(w.written_bytes_u32(), 0);
        assert_eq!(w.cap_bytes_u32(), 100);
        assert!(!w.is_closed());
    }

    #[test]
    fn reader_at_empty_source_returns_none_first_call() {
        let mut r = ChunkStreamReader::new(&[]);
        assert_eq!(r.position(), 0);
        assert_eq!(r.remaining(), 0);
        let first = r.next_frame();
        assert_eq!(first, Ok(None));
        // Idempotent past end.
        assert_eq!(r.next_frame(), Ok(None));
    }

    #[test]
    fn writer_at_exact_cap_accepts_pushes() {
        // Cap = uleb128(3) [1 byte] + 3 bytes body = 4. Exact.
        let mut sink = Vec::new();
        let mut w = ChunkStreamWriter::new(&mut sink, 4);
        let new_total = w.push_frame(&[0xAA, 0xBB, 0xCC]).unwrap();
        assert_eq!(new_total, 4);
        assert!(!w.is_closed());
        assert_eq!(sink, vec![0x03, 0xAA, 0xBB, 0xCC]);
    }

    #[test]
    fn writer_above_cap_by_one_byte_rejects_and_closes() {
        // Cap = 3 (one byte short of a 3-byte body + 1-byte prefix).
        let mut sink = Vec::new();
        let mut w = ChunkStreamWriter::new(&mut sink, 3);
        let err = w.push_frame(&[0xAA, 0xBB, 0xCC]).unwrap_err();
        assert_eq!(err, StreamError::CapExceeded { cap_u32: 3 });
        assert!(w.is_closed());
        // sink is untouched on refusal (push is all-or-nothing).
        assert!(sink.is_empty());
    }

    #[test]
    fn writer_closed_sentinel_is_u32_max() {
        let mut sink = Vec::new();
        let mut w = ChunkStreamWriter::new(&mut sink, 0);
        // Even an empty frame needs 1 byte (uleb128(0) = 0x00). Cap 0 fails.
        let _ = w.push_frame(&[]).unwrap_err();
        assert_eq!(w.written_bytes_u32(), u32::MAX);
        assert!(w.is_closed());
    }

    #[test]
    fn roundtrip_single_empty_frame_yields_empty_frame() {
        let mut sink = Vec::new();
        let mut w = ChunkStreamWriter::new(&mut sink, 16);
        w.push_frame(&[]).unwrap();
        assert_eq!(sink, vec![0x00]);
        let mut r = ChunkStreamReader::new(&sink);
        let f = r.next_frame().unwrap().unwrap();
        assert!(f.is_empty());
        assert_eq!(r.next_frame(), Ok(None));
    }

    #[test]
    fn reader_rejects_non_canonical_length_prefix() {
        // 0x80 0x00 is the non-canonical encoding of 0 — wire layer
        // refuses; stream reports it as Truncated.
        let src = [0x80u8, 0x00u8];
        let mut r = ChunkStreamReader::new(&src);
        assert_eq!(r.next_frame(), Err(StreamError::Truncated));
    }
}
