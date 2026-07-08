//! Integration tests for `c-walrus::stream` (atom #11 · C.0.5).
//!
//! Four `c0_5_*` named tests are verbatim from `MNEMOS_ATOM_PLAN.md` line
//! 903, plus one proptest that exercises the partition-invariance of the
//! writer/reader round-trip.

#![allow(clippy::unwrap_used)]
#![allow(clippy::expect_used)]
#![allow(clippy::panic)]
#![allow(clippy::print_stdout)]
#![allow(clippy::print_stderr)]

use mnemos_c_walrus::{ChunkStreamReader, ChunkStreamWriter, StreamError};
use proptest::prelude::*;

// ---------------------------------------------------------------------------
// 1. c0_5_reader_yields_zero_copy_frames
// ---------------------------------------------------------------------------

#[test]
fn c0_5_reader_yields_zero_copy_frames() {
    // Build a stream of three frames into a sink.
    let mut sink: Vec<u8> = Vec::new();
    {
        let mut w = ChunkStreamWriter::new(&mut sink, 1024);
        w.push_frame(&[0xAA, 0xAB, 0xAC]).unwrap();
        w.push_frame(&[0xBB, 0xBC]).unwrap();
        w.push_frame(b"hello").unwrap();
    }

    // Now read the frames out. Each returned slice must lie within the
    // source slice's allocation: same allocation, same byte values.
    let src: &[u8] = &sink;
    let base_addr = src.as_ptr() as usize;
    let end_addr = base_addr + src.len();

    let mut r = ChunkStreamReader::new(src);

    let f0 = r.next_frame().unwrap().unwrap();
    assert_eq!(f0, &[0xAA, 0xAB, 0xAC]);
    // Same allocation as source.
    let f0_start = f0.as_ptr() as usize;
    let f0_end = f0_start + f0.len();
    assert!(
        base_addr <= f0_start && f0_end <= end_addr,
        "frame 0 ptr {f0_start:#x}..{f0_end:#x} must lie in source {base_addr:#x}..{end_addr:#x}",
    );

    let f1 = r.next_frame().unwrap().unwrap();
    assert_eq!(f1, &[0xBB, 0xBC]);
    let f1_start = f1.as_ptr() as usize;
    let f1_end = f1_start + f1.len();
    assert!(base_addr <= f1_start && f1_end <= end_addr);
    // Frame 1 starts strictly after frame 0 ends.
    assert!(
        f0_end <= f1_start,
        "frame 1 must come strictly after frame 0"
    );

    let f2 = r.next_frame().unwrap().unwrap();
    assert_eq!(f2, b"hello");
    let f2_start = f2.as_ptr() as usize;
    let f2_end = f2_start + f2.len();
    assert!(base_addr <= f2_start && f2_end <= end_addr);
    assert!(f1_end <= f2_start);

    // End of stream.
    assert_eq!(r.next_frame(), Ok(None));
}

// ---------------------------------------------------------------------------
// 2. c0_5_writer_enforces_cumulative_cap
// ---------------------------------------------------------------------------

#[test]
fn c0_5_writer_enforces_cumulative_cap() {
    // Cap = 20.
    // Frame A (5 bytes body): uleb128 prefix = 1 byte; cost = 6. New total: 6.
    // Frame B (10 bytes body): uleb128 prefix = 1 byte; cost = 11. New total: 17.
    // Frame C (8 bytes body): would cost 9; cumulative would become 26 > 20 ⇒ reject.
    let mut sink: Vec<u8> = Vec::new();
    let mut w = ChunkStreamWriter::new(&mut sink, 20);

    let after_a = w.push_frame(&[0xAA; 5]).unwrap();
    assert_eq!(after_a, 6);
    assert_eq!(w.written_bytes_u32(), 6);
    assert!(!w.is_closed());

    let after_b = w.push_frame(&[0xBB; 10]).unwrap();
    assert_eq!(after_b, 17);
    assert_eq!(w.written_bytes_u32(), 17);
    assert!(!w.is_closed());

    let err = w.push_frame(&[0xCC; 8]).unwrap_err();
    assert_eq!(err, StreamError::CapExceeded { cap_u32: 20 });
    // Writer transitioned to closed.
    assert!(w.is_closed());

    // The sink only contains the two accepted frames; the rejected frame
    // was *not* partially appended (all-or-nothing push).
    assert_eq!(sink.len(), 17);
    // Spot-check the boundary bytes — frame A starts with prefix 0x05.
    assert_eq!(sink[0], 0x05);
    assert_eq!(&sink[1..6], &[0xAA; 5][..]);
    // Frame B prefix is 0x0A.
    assert_eq!(sink[6], 0x0A);
    assert_eq!(&sink[7..17], &[0xBB; 10][..]);
}

// ---------------------------------------------------------------------------
// 3. c0_5_truncated_frame_rejected
// ---------------------------------------------------------------------------

#[test]
fn c0_5_truncated_frame_rejected() {
    // Hand-craft a buffer whose prefix promises 10 body bytes but only
    // 5 follow. Reader must report Truncated.
    let mut src: Vec<u8> = Vec::new();
    src.push(0x0A); // uleb128(10), one byte.
    src.extend_from_slice(&[0xAA; 5]);
    let mut r = ChunkStreamReader::new(&src);
    let err = r.next_frame().unwrap_err();
    assert_eq!(err, StreamError::Truncated);

    // Also: a buffer that is exactly one prefix byte (length 1) with no
    // body at all is Truncated.
    let src2: Vec<u8> = vec![0x05]; // uleb128(5), zero body bytes follow.
    let mut r2 = ChunkStreamReader::new(&src2);
    assert_eq!(r2.next_frame().unwrap_err(), StreamError::Truncated);

    // And: a buffer whose prefix is itself incomplete (a continuation
    // byte alone, with nothing after) is also Truncated.
    let src3: Vec<u8> = vec![0x80]; // continuation byte, no terminator.
    let mut r3 = ChunkStreamReader::new(&src3);
    assert_eq!(r3.next_frame().unwrap_err(), StreamError::Truncated);
}

// ---------------------------------------------------------------------------
// 4. c0_5_backpressure_closes
// ---------------------------------------------------------------------------

#[test]
fn c0_5_backpressure_closes() {
    // Push a frame that exceeds the cap → CapExceeded; writer closes.
    // Then attempt any subsequent push (including an empty one) →
    // BackpressureClosed. The writer never reopens.
    let mut sink: Vec<u8> = Vec::new();
    let mut w = ChunkStreamWriter::new(&mut sink, 3);

    // First push is over-cap (1-byte prefix + 5-byte body = 6 > 3).
    let first = w.push_frame(&[0xAA; 5]).unwrap_err();
    assert_eq!(first, StreamError::CapExceeded { cap_u32: 3 });
    assert!(w.is_closed());

    // Second push (even of an empty frame) is BackpressureClosed.
    let second = w.push_frame(&[]).unwrap_err();
    assert_eq!(second, StreamError::BackpressureClosed);

    // Third push (with a fresh body) is still BackpressureClosed —
    // the close is permanent.
    let third = w.push_frame(b"x").unwrap_err();
    assert_eq!(third, StreamError::BackpressureClosed);

    // sink remains empty: nothing was ever committed.
    assert!(sink.is_empty());
}

// ---------------------------------------------------------------------------
// 5. Proptest — partition-invariant round-trip (ATOM_PLAN line 903:
//                "proptest(frame 분할 무관 동일)").
// ---------------------------------------------------------------------------

proptest! {
    #![proptest_config(ProptestConfig::with_cases(256))]

    /// For any sequence of small byte-frames that collectively fit in the
    /// writer's cap, reading them back yields exactly the same sequence
    /// in the same order. The total stream byte length is independent of
    /// how the original content was partitioned into frames — only the
    /// per-frame boundaries differ.
    #[test]
    fn proptest_writer_reader_roundtrip_is_partition_invariant(
        frames in proptest::collection::vec(
            proptest::collection::vec(any::<u8>(), 0..=64),
            0..=12,
        ),
    ) {
        // Cap large enough for any combination of the input.
        let mut sink: Vec<u8> = Vec::new();
        let written_total: usize = {
            let mut w = ChunkStreamWriter::new(&mut sink, 1024 * 1024);
            for f in &frames {
                w.push_frame(f).unwrap();
            }
            w.written_bytes_u32() as usize
        };
        // The sink length matches the writer's running counter exactly.
        prop_assert_eq!(written_total, sink.len());

        // Read everything back into owned Vecs and compare.
        let src: &[u8] = &sink;
        let mut r = ChunkStreamReader::new(src);
        let mut read_back: Vec<Vec<u8>> = Vec::new();
        while let Some(frame) = r.next_frame().unwrap() {
            read_back.push(frame.to_vec());
        }
        prop_assert_eq!(&read_back, &frames);

        // Reader has consumed the entire source.
        prop_assert_eq!(r.position(), sink.len());
        prop_assert_eq!(r.remaining(), 0);
        prop_assert_eq!(r.next_frame().unwrap(), None);
    }
}
