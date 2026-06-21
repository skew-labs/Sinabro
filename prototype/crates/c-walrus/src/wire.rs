//! Private BCS-compatible wire primitives for the `c-walrus` codec.
//!
//! This module is the only place in `c-walrus` that touches raw byte cursors.
//! It exposes:
//!
//! * a strict, canonical `uleb128` reader/writer (rejects non-minimal
//!   encodings — `0x80 0x00`, trailing zero bytes — and detects overflow
//!   without panicking),
//! * fixed-width little-endian `u16` / `u32` helpers, and
//! * a buffered byte cursor that performs every length math with
//!   `checked_add` so a malformed length prefix can never overflow `usize`.
//!
//! The module is `pub(crate)`: `codec.rs` consumes it and decides the
//! domain-typed `ChunkCodecError` mapping. No `unsafe`. No panic surface
//! (`#![deny(unsafe_code)]` at the crate root and the `clippy::unwrap_used`,
//! `clippy::expect_used`, `clippy::panic`, etc. deny set at workspace level
//! catch any drift).
//!
//! BCS compatibility notes:
//! * `Vec<u8>` is encoded as `uleb128(len) || bytes`.
//! * `Option<T>` is encoded as `0` (None) or `1 || T` (Some).
//! * `[u8; N]` is encoded as `N` contiguous bytes (no length prefix).
//! * `u16` / `u32` are encoded little-endian, fixed width.
//! * `enum` variants with index `0..=127` encode as one byte; the codec
//!   pins every variant in that range, so the single-byte form is used
//!   throughout.

/// Maximum number of bytes a canonical uleb128 may occupy for a value that
/// fits in `u32`. ceil(32/7) = 5.
pub(crate) const ULEB128_U32_MAX_BYTES: usize = 5;

/// Hidden, structural error shape produced by the wire layer. `codec.rs`
/// maps each variant to a public [`crate::codec::ChunkCodecError`] case.
/// Kept `Copy` and field-free so the wire layer never carries an owned
/// payload (raw bytes never escape into an error class).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum WireError {
    /// The cursor reached end-of-input mid-frame.
    Truncated,
    /// A uleb128 was not the canonical minimal encoding (extra trailing
    /// `0x80 ... 0x00`, or a single `0x80` representing `0`).
    NonCanonicalUleb,
    /// A uleb128 represented a value larger than `u32::MAX` (so it cannot
    /// be a valid length prefix in this codec's universe).
    UlebOverflowU32,
}

/// Read-only cursor over a `[u8]` source.
pub(crate) struct WireReader<'a> {
    src: &'a [u8],
    pos: usize,
}

impl<'a> WireReader<'a> {
    #[inline]
    pub(crate) const fn new(src: &'a [u8]) -> Self {
        Self { src, pos: 0 }
    }

    /// Whether every byte of the source has been consumed.
    #[inline]
    pub(crate) const fn is_at_end(&self) -> bool {
        self.pos == self.src.len()
    }

    /// Borrow the next `n` bytes without copying. Fails with `Truncated`
    /// if fewer than `n` bytes remain.
    pub(crate) fn take(&mut self, n: usize) -> Result<&'a [u8], WireError> {
        let end = self.pos.checked_add(n).ok_or(WireError::Truncated)?;
        if end > self.src.len() {
            return Err(WireError::Truncated);
        }
        let slice = &self.src[self.pos..end];
        self.pos = end;
        Ok(slice)
    }

    /// Consume one byte.
    pub(crate) fn read_u8(&mut self) -> Result<u8, WireError> {
        let s = self.take(1)?;
        Ok(s[0])
    }

    /// Consume a little-endian `u16`.
    pub(crate) fn read_u16_le(&mut self) -> Result<u16, WireError> {
        let s = self.take(2)?;
        Ok(u16::from_le_bytes([s[0], s[1]]))
    }

    /// Consume a little-endian `u32`.
    pub(crate) fn read_u32_le(&mut self) -> Result<u32, WireError> {
        let s = self.take(4)?;
        Ok(u32::from_le_bytes([s[0], s[1], s[2], s[3]]))
    }

    /// Consume a fixed-length `[u8; N]` slice into an owned array.
    pub(crate) fn read_fixed<const N: usize>(&mut self) -> Result<[u8; N], WireError> {
        let s = self.take(N)?;
        let mut out = [0u8; N];
        out.copy_from_slice(s);
        Ok(out)
    }

    /// Read a canonical uleb128 into a `u32`. Rejects:
    ///
    /// * truncated frames (`Truncated`),
    /// * non-minimal encodings: any byte chain ending with a `0x00`
    ///   continuation byte that was not the first byte (`NonCanonicalUleb`),
    /// * values that overflow `u32` (`UlebOverflowU32`).
    ///
    /// Returns the decoded value. The number of consumed bytes equals
    /// `position_after - position_before` and is bounded by
    /// [`ULEB128_U32_MAX_BYTES`].
    pub(crate) fn read_uleb128_u32(&mut self) -> Result<u32, WireError> {
        let mut result: u64 = 0;
        let mut shift: u32 = 0;
        let mut bytes_read: usize = 0;
        loop {
            let b = self.read_u8()?;
            bytes_read += 1;
            if bytes_read > ULEB128_U32_MAX_BYTES {
                return Err(WireError::UlebOverflowU32);
            }
            let payload = u64::from(b & 0x7F);
            result |= payload << shift;
            if result > u64::from(u32::MAX) {
                return Err(WireError::UlebOverflowU32);
            }
            let cont = b & 0x80;
            if cont == 0 {
                // Canonical-form check: the final byte may only be 0 when
                // the value itself is 0 (single-byte 0x00). Any other
                // chain whose last byte is `0x00` was padded non-minimally
                // (e.g. `0x80 0x00`).
                if b == 0 && bytes_read != 1 {
                    return Err(WireError::NonCanonicalUleb);
                }
                return Ok(result as u32);
            }
            shift += 7;
        }
    }
}

/// Append a canonical (minimal) uleb128 encoding of `value` to `out`.
pub(crate) fn append_uleb128_u32(out: &mut Vec<u8>, mut value: u32) {
    loop {
        let b = (value & 0x7F) as u8;
        value >>= 7;
        if value == 0 {
            out.push(b);
            return;
        } else {
            out.push(b | 0x80);
        }
    }
}

/// Append a little-endian `u16`.
#[inline]
pub(crate) fn append_u16_le(out: &mut Vec<u8>, value: u16) {
    out.extend_from_slice(&value.to_le_bytes());
}

/// Append a little-endian `u32`.
#[inline]
pub(crate) fn append_u32_le(out: &mut Vec<u8>, value: u32) {
    out.extend_from_slice(&value.to_le_bytes());
}

/// Append a fixed-byte array.
#[inline]
pub(crate) fn append_fixed<const N: usize>(out: &mut Vec<u8>, value: &[u8; N]) {
    out.extend_from_slice(value);
}
