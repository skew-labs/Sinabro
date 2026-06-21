//! Walrus PUT/GET byte + latency collector (C-WP-02A · atom #182 · C.0.11).
//!
//! Canonical OUT: a Walrus PUT/GET byte-and-latency sample derived from the
//! Stage B [`WalrusRoundTripReceipt`] (atom #110).
//!
//! # Crate-boundary note
//!
//! The Stage C atom plan's `file` field originally named `c-walrus`, but this
//! collector reuses the Stage B [`WalrusRoundTripReceipt`], which lives in
//! `b-memory` (orchestration), and `b-memory` already depends on `c-walrus`
//! (transport). Homing the collector in `c-walrus` would force a
//! `c-walrus → b-memory` edge and a cargo cycle. Per the user-locked Stage B
//! crate-boundary decision (`c-walrus = transport`, `b-memory = Walrus
//! orchestration / receipt`), this atom lives in `b-memory` with the canonical
//! OUT unchanged.
//!
//! # Madness invariants (atom #182)
//!
//! * **Reuse the verified receipt — no re-mint.** A [`WalrusMeasureSample`] is
//!   built only via [`WalrusMeasureSample::from_receipt`] from a
//!   [`WalrusRoundTripReceipt`]. The blob id it records is the receipt's
//!   [`VerifiedBlobId`], whose sole construction path is
//!   `stage_b_verify_blob_id` (atom #108) — so **no server-reported blob id can
//!   enter the metrics unverified**.
//! * **Body is redacted by construction.** The sample carries only
//!   [`bytes_u32`](WalrusMeasureSample::bytes_u32) — the *length* of the
//!   transferred chunk body, a count. There is no field that can hold the raw
//!   body, mirroring the receipt's own content-free contract.
//! * **Allocation stable.** The sample is a `Copy` struct and every method is
//!   alloc-free (the byte form writes into a fixed stack array), so a collection
//!   pass does not grow the heap per sample.
//! * **No live call.** The receipt is the already-measured evidence of a prior
//!   (Stage B) round trip; this atom performs no network egress.

use crate::stage_b_receipt::WalrusRoundTripReceipt;
use mnemos_a_core::trace::StageCTraceLink;
use mnemos_c_walrus::{BLOB_ID_BYTES, VerifiedBlobId};

/// Fixed serialized byte width of a [`WalrusMeasureSample`]:
/// `32` (verified blob id) + `4` (put ms) + `4` (get ms) + `4` (bytes) + `15`
/// (trace: `8 + 2 + 1 + 2 + 2`).
pub const WALRUS_MEASURE_SAMPLE_BYTES: usize = 59;

/// One Walrus PUT/GET byte-and-latency measurement (atom #182).
///
/// Derived from a verified [`WalrusRoundTripReceipt`]; carries the verified blob
/// id, the PUT and GET wall-clock latencies, the transferred body length (a
/// count only), and a Stage C trace stamp.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub struct WalrusMeasureSample {
    /// The locally-verified blob id the round trip published and read back. By
    /// construction this is never a server-self-reported id.
    pub blob: VerifiedBlobId,
    /// Measured PUT wall-clock cost in milliseconds.
    pub put_ms_u32: u32,
    /// Measured GET wall-clock cost in milliseconds.
    pub get_ms_u32: u32,
    /// **Length** of the transferred chunk body in bytes — a count only. The
    /// raw body is never stored.
    pub bytes_u32: u32,
    /// The Stage C trace stamp for this measurement.
    pub trace: StageCTraceLink,
}

impl WalrusMeasureSample {
    /// Build a measurement sample from a verified Walrus round-trip receipt,
    /// stamping it with a Stage C trace.
    ///
    /// Reuses the receipt's `VerifiedBlobId`, PUT/GET latencies, and body length
    /// verbatim — it does not re-derive or re-verify any field, and it cannot
    /// introduce an unverified blob id.
    #[inline]
    pub const fn from_receipt(receipt: &WalrusRoundTripReceipt, trace: StageCTraceLink) -> Self {
        Self {
            blob: receipt.blob,
            put_ms_u32: receipt.put_ms_u32,
            get_ms_u32: receipt.get_ms_u32,
            bytes_u32: receipt.bytes_u32,
            trace,
        }
    }

    /// Total round-trip latency = `put_ms + get_ms`, widened to `u64` so the sum
    /// of two `u32` latencies cannot overflow.
    #[inline]
    pub const fn total_ms_u64(&self) -> u64 {
        self.put_ms_u32 as u64 + self.get_ms_u32 as u64
    }

    /// The transferred body length in bytes (a count; never the body).
    #[inline]
    pub const fn bytes_u32(&self) -> u32 {
        self.bytes_u32
    }

    /// Borrow the verified blob id.
    #[inline]
    pub const fn blob(&self) -> &VerifiedBlobId {
        &self.blob
    }

    /// Serialize the sample to its fixed [`WALRUS_MEASURE_SAMPLE_BYTES`] byte
    /// form, in field-declaration order (little-endian for every integer). The
    /// trace is appended as `trace_id_u64 ‖ atom_id_u16 ‖ attempt_u8 ‖
    /// stage_c_atom_u16 ‖ gate_id_u16`. Alloc-free.
    pub fn to_bytes(&self) -> [u8; WALRUS_MEASURE_SAMPLE_BYTES] {
        let mut out = [0u8; WALRUS_MEASURE_SAMPLE_BYTES];
        out[0..BLOB_ID_BYTES].copy_from_slice(self.blob.as_blob_id().as_bytes());
        out[32..36].copy_from_slice(&self.put_ms_u32.to_le_bytes());
        out[36..40].copy_from_slice(&self.get_ms_u32.to_le_bytes());
        out[40..44].copy_from_slice(&self.bytes_u32.to_le_bytes());
        out[44..52].copy_from_slice(&self.trace.trace.trace_id_u64.to_le_bytes());
        out[52..54].copy_from_slice(&self.trace.trace.atom_id_u16.to_le_bytes());
        out[54] = self.trace.trace.attempt_u8;
        out[55..57].copy_from_slice(&self.trace.stage_c_atom_u16.to_le_bytes());
        out[57..59].copy_from_slice(&self.trace.gate_id_u16.to_le_bytes());
        out
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]
    use super::*;
    use crate::chunk::StorageObjectRef;
    use crate::stage_b_blob_id::{derive_walrus_blob_id, stage_b_verify_blob_id};
    use crate::stage_b_receipt::WalrusRoundTripReceipt;
    use mnemos_a_core::trace::{StageBTraceLink, StageCTraceLink};
    use mnemos_c_walrus::PublisherReportedBlobId;

    /// Test-only URL-safe base64 (no padding) encoder for a 32-byte id — the
    /// faithful inverse of `c-walrus`'s private `decode_base64url_no_pad_32`.
    /// `c-walrus`'s own encoder is `pub(crate)`, so a cross-crate test cannot
    /// call it; this mirrors the atom #108 / #109 test-only duplicate used to
    /// synthesize a *correctly* reported id text so the only `VerifiedBlobId`
    /// constructor can be driven. No bare/unverified `BlobId` is fabricated.
    fn base64url_no_pad_encode_32(raw: &[u8; 32]) -> String {
        const ALPHABET: &[u8; 64] =
            b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
        let mut out = String::with_capacity(43);
        let mut buf: u32 = 0;
        let mut bits: u32 = 0;
        for &b in raw {
            buf = (buf << 8) | (b as u32);
            bits += 8;
            while bits >= 6 {
                bits -= 6;
                out.push(ALPHABET[((buf >> bits) & 0x3f) as usize] as char);
            }
        }
        if bits > 0 {
            out.push(ALPHABET[((buf << (6 - bits)) & 0x3f) as usize] as char);
        }
        out
    }

    /// Promote `bytes` to a `VerifiedBlobId` via the *only* sanctioned path
    /// (atom #108 `stage_b_verify_blob_id`): derive the local id, encode it as
    /// the publisher would report it, then verify the reported text against the
    /// same bytes.
    fn verified_blob_for(bytes: &[u8]) -> VerifiedBlobId {
        let id = derive_walrus_blob_id(bytes);
        let text = base64url_no_pad_encode_32(id.as_bytes());
        let reported = PublisherReportedBlobId::try_from_text(&text).unwrap();
        stage_b_verify_blob_id(bytes, &reported)
            .expect("a reported id equal to the local derive must verify")
    }

    /// A Walrus-primary `StorageObjectRef` carrying the verified blob (atom #31
    /// const constructor).
    fn storage_for(bytes: &[u8], verified: VerifiedBlobId) -> StorageObjectRef {
        let id = derive_walrus_blob_id(bytes);
        StorageObjectRef::walrus_primary(*id.as_bytes(), verified)
    }

    fn receipt() -> WalrusRoundTripReceipt {
        let body = b"mnemos atom 182 walrus measure body content vector";
        let verified = verified_blob_for(body);
        let storage = storage_for(body, verified);
        WalrusRoundTripReceipt::new(
            verified,
            storage,
            82, // put_ms
            61, // get_ms
            85, // bytes (transferred body length)
            StageBTraceLink::new(0xB182, 182, 0),
        )
    }

    fn trace() -> StageCTraceLink {
        StageCTraceLink::new(StageBTraceLink::new(0xA182, 182, 0), 182, 6)
    }

    #[test]
    fn receipt_to_sample_copies_verified_fields() {
        let r = receipt();
        let s = WalrusMeasureSample::from_receipt(&r, trace());
        // The verified blob id is the receipt's — structurally, not re-derived.
        assert_eq!(s.blob(), r.blob());
        assert_eq!(s.put_ms_u32, 82);
        assert_eq!(s.get_ms_u32, 61);
        assert_eq!(s.bytes_u32(), 85);
        assert_eq!(s.trace.stage_c_atom_u16, 182);
    }

    #[test]
    fn body_is_redacted_to_a_length_count_only() {
        // Two DIFFERENT bodies of the SAME length, pinned to one verified
        // blob/storage, yield byte-identical receipts (Stage B #109 contract);
        // the samples built from them must therefore be byte-identical too —
        // proving no body content crosses into the measurement, only its length.
        let pinned = b"mnemos atom 182 redaction witness body";
        let verified = verified_blob_for(pinned);
        let storage = storage_for(pinned, verified);
        let tb = StageBTraceLink::new(0xB182, 182, 1);
        let body_a = vec![0xAAu8; 100];
        let body_b = vec![0x55u8; 100];
        assert_ne!(body_a, body_b, "the two bodies must genuinely differ");
        let ra = WalrusRoundTripReceipt::from_round_trip(verified, storage, 9, 4, &body_a, tb)
            .expect("100 bytes within u32");
        let rb = WalrusRoundTripReceipt::from_round_trip(verified, storage, 9, 4, &body_b, tb)
            .expect("100 bytes within u32");
        let sa = WalrusMeasureSample::from_receipt(&ra, trace());
        let sb = WalrusMeasureSample::from_receipt(&rb, trace());
        assert_eq!(
            sa, sb,
            "equal-length different-body samples must be identical"
        );
        assert_eq!(sa.to_bytes(), sb.to_bytes());
        assert_eq!(sa.bytes_u32(), 100, "only the length is recorded");
        // The byte form is fixed width — it cannot grow with the body size.
        assert_eq!(sa.to_bytes().len(), WALRUS_MEASURE_SAMPLE_BYTES);
        assert_eq!(sa.to_bytes().len(), 59);
        // The blob id bytes are the verified id's bytes.
        assert_eq!(&sa.to_bytes()[0..32], sa.blob().as_blob_id().as_bytes());
    }

    #[test]
    fn latency_widths_total_without_overflow() {
        let r = receipt();
        let s = WalrusMeasureSample::from_receipt(&r, trace());
        assert_eq!(s.total_ms_u64(), 82 + 61);
        // Two max u32 latencies sum without overflow (widened to u64).
        let mut max = s;
        max.put_ms_u32 = u32::MAX;
        max.get_ms_u32 = u32::MAX;
        assert_eq!(max.total_ms_u64(), (u32::MAX as u64) * 2);
    }
}
