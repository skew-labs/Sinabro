//! `stage_b_receipt.rs` (atom #109 · B.2.8 round-trip receipt) — the Stage B
//! **content-free** receipt minted after a Walrus PUT→GET round trip completes.
//!
//! This module mints one §4.2-row entry point: [`WalrusRoundTripReceipt`] — the
//! evidence record proving that a chunk was published and read back, carrying
//! the **verified** blob id (the local-derive trust root, atom #108), the
//! storage reference (atom #29-#31 lock-in breaker), the measured PUT/GET
//! latencies, the transferred *length*, and the per-action [`StageBTraceLink`]
//! (atom #81). It is exactly the "A canonical을 조합하는 … receipt/evidence 타입"
//! category that §4.0 permits Stage B to mint — it composes Stage A/earlier
//! Stage B canonicals and introduces no new wire, no new error type, and no new
//! id/address newtype.
//!
//! # Madness invariant (`MNEMOS_STAGE_B_ATOM_PLAN.md` atom #109)
//!
//! > receipt stores verified blob id, bytes, latency, trace; no raw payload body.
//!
//! * **No raw payload body (redaction by construction).** The struct has **no**
//!   `Vec<u8>` / `&[u8]` / body field. The only thing it records about the
//!   transferred payload is its **length** ([`bytes_u32`](Self::bytes_u32)) — a
//!   single `u32` count, never the bytes themselves. The
//!   [`from_round_trip`](Self::from_round_trip) constructor reads a `&[u8]` body
//!   only to take its length and then drops the borrow; nothing derived from the
//!   body content survives into the receipt. So two payloads of equal length
//!   produce byte-identical receipts (the `b2_8_receipt_redacts_body` proof):
//!   the user's memory body never enters the measurement / evidence trail. The
//!   receipt is `Copy` precisely because it holds no heap-owned body.
//!
//! * **Verified blob id only.** The [`blob`](Self::blob) field is a
//!   [`VerifiedBlobId`](mnemos_c_walrus::VerifiedBlobId) (atom #108), whose sole
//!   construction path is [`stage_b_verify_blob_id`](crate::stage_b_verify_blob_id)
//!   — a server's *self-reported* id can never become a receipt's trust root
//!   without matching the local derivation byte-for-byte. The receipt cannot
//!   even be expressed over a bare server `BlobId`; the type system forbids it.
//!
//! * **Latency preserved.** The PUT and GET wall-clock costs are kept verbatim
//!   as two `u32` millisecond counts and summed losslessly (widening, never
//!   truncating) by [`total_ms_u64`](Self::total_ms_u64), so the measurement
//!   side reads exactly what the round trip cost.
//!
//! * **Trace linked (fail-closed).** The [`trace`](Self::trace) field holds the
//!   atom #81 [`StageBTraceLink`] verbatim; [`trace_evidence`](Self::trace_evidence)
//!   projects it into the atom #94 content-free [`StageBTraceEvidence`], which
//!   rejects the missing/unstamped sentinel (`atom_id_u16 == 0`) by returning
//!   `None`. So a receipt whose action is not bound to a real atom yields no
//!   evidence record — the same fail-closed "missing trace reject" the chunk
//!   header / trace-evidence seam uses, reused here rather than re-minted.
//!
//! # Reuse (재발명 0)
//!
//! * #108 [`VerifiedBlobId`](mnemos_c_walrus::VerifiedBlobId) — the local-verify
//!   trust root, carried unchanged (no Stage-B receipt-local id type).
//! * #29-#31 [`StorageObjectRef`](crate::StorageObjectRef) — the backend/role/
//!   phase + content-hash + verified-blob reference, carried verbatim (the
//!   Walrus-primary lock-in breaker; IPFS/Filecoin stay future-only).
//! * #81 [`StageBTraceLink`](crate::stage_b_handoff::StageBTraceLink) — the
//!   `(trace_id, atom_id, attempt)` stamp, used verbatim. No second stamp type.
//! * #94 [`StageBTraceEvidence`](crate::trace_link::StageBTraceEvidence) — the
//!   content-free trace projection consumed for the "trace linked" seam.
//!
//! No new dependency, no new wire format, no new error type, no network.

use crate::chunk::StorageObjectRef;
use crate::stage_b_handoff::StageBTraceLink;
use crate::trace_link::StageBTraceEvidence;
use mnemos_c_walrus::VerifiedBlobId;

/// Content-free evidence of a completed Walrus testnet PUT→GET round trip.
///
/// The atom #109 canonical OUT (`MNEMOS_STAGE_B_ATOM_PLAN.md` §4.2). Fields are
/// `pub` per the §4.0 canonical registry; [`new`](Self::new) and
/// [`from_round_trip`](Self::from_round_trip) are provided for ergonomic,
/// redaction-safe construction at call sites.
///
/// It carries the verified blob id, the storage reference, the PUT/GET
/// latencies, the transferred **length** (not the bytes), and the per-action
/// trace stamp — and deliberately nothing else. There is no field that could
/// hold the raw chunk body, the owner address, or any provider text, so the
/// receipt is redaction-safe by construction and `Copy`.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub struct WalrusRoundTripReceipt {
    /// The locally-verified blob id (atom #108) the round trip published and
    /// read back. The sole construction path is
    /// [`stage_b_verify_blob_id`](crate::stage_b_verify_blob_id) — a server's
    /// self-reported id can never reach this field unverified.
    pub blob: VerifiedBlobId,
    /// The storage reference (atom #29-#31): backend kind / role / phase, the
    /// 32-byte content hash, and the verified Walrus blob. Walrus is the only
    /// live writer this phase; IPFS/Filecoin stay future-only here.
    pub storage: StorageObjectRef,
    /// Measured PUT wall-clock cost in milliseconds.
    pub put_ms_u32: u32,
    /// Measured GET wall-clock cost in milliseconds.
    pub get_ms_u32: u32,
    /// **Length** of the transferred chunk body in bytes — a count only. The
    /// raw body is never stored (see the module-level redaction invariant).
    pub bytes_u32: u32,
    /// The atom #81 per-action trace stamp `(trace_id, atom_id, attempt)`.
    pub trace: StageBTraceLink,
}

impl WalrusRoundTripReceipt {
    /// Construct a receipt from its six §4.2 components.
    ///
    /// `bytes_u32` is the transferred body **length**; this constructor never
    /// sees the body itself. Prefer [`from_round_trip`](Self::from_round_trip)
    /// when a `&[u8]` body is in hand so the length is derived (and the body
    /// dropped) at one redaction-safe seam.
    #[inline]
    pub const fn new(
        blob: VerifiedBlobId,
        storage: StorageObjectRef,
        put_ms_u32: u32,
        get_ms_u32: u32,
        bytes_u32: u32,
        trace: StageBTraceLink,
    ) -> Self {
        Self {
            blob,
            storage,
            put_ms_u32,
            get_ms_u32,
            bytes_u32,
            trace,
        }
    }

    /// Build a receipt from a completed round trip, recording **only the
    /// length** of the transferred `body` — the borrow is read for its length
    /// and then dropped; no byte of the body content survives into the receipt.
    ///
    /// Returns `None` if the body length exceeds [`u32::MAX`] (fail-closed: the
    /// §4.2 `bytes_u32` field is a `u32`, and a silent `as u32` truncation would
    /// misreport the transferred size — refusing is safer than lying about it).
    /// Walrus testnet chunk bodies are far below this bound; the guard exists so
    /// no oversized input can produce a wrong-length receipt.
    #[inline]
    pub fn from_round_trip(
        blob: VerifiedBlobId,
        storage: StorageObjectRef,
        put_ms_u32: u32,
        get_ms_u32: u32,
        body: &[u8],
        trace: StageBTraceLink,
    ) -> Option<Self> {
        let bytes_u32 = u32::try_from(body.len()).ok()?;
        Some(Self::new(
            blob, storage, put_ms_u32, get_ms_u32, bytes_u32, trace,
        ))
    }

    /// Borrow the verified blob id this round trip published and read back.
    #[inline]
    pub const fn blob(&self) -> &VerifiedBlobId {
        &self.blob
    }

    /// Borrow the storage reference.
    #[inline]
    pub const fn storage(&self) -> &StorageObjectRef {
        &self.storage
    }

    /// The transferred body length in bytes (count only; the body is absent).
    #[inline]
    pub const fn bytes_u32(&self) -> u32 {
        self.bytes_u32
    }

    /// Total round-trip wall-clock cost: `put_ms_u32 + get_ms_u32`, summed in
    /// `u64` so the addition is lossless (widening, never truncating) even when
    /// both legs are near `u32::MAX`.
    #[inline]
    pub const fn total_ms_u64(&self) -> u64 {
        self.put_ms_u32 as u64 + self.get_ms_u32 as u64
    }

    /// The per-action trace stamp (verbatim copy).
    #[inline]
    pub const fn trace(&self) -> StageBTraceLink {
        self.trace
    }

    /// Project this receipt's trace into the atom #94 content-free
    /// [`StageBTraceEvidence`] — the "trace linked" seam. Returns `None` if the
    /// trace is the missing/unstamped sentinel (`atom_id_u16 == 0`), fail-closed,
    /// so a receipt not bound to a real atom mints no evidence record.
    #[inline]
    pub const fn trace_evidence(&self) -> Option<StageBTraceEvidence> {
        StageBTraceEvidence::from_trace(self.trace)
    }
}

#[cfg(test)]
mod tests {
    // Test helpers prefer direct failure surfaces over `Result`-bubbling;
    // suppress prod-only clippy denies inside this module (b-memory
    // #86/#88/#89/#90/#91/#107/#108 precedent).
    #![allow(clippy::unwrap_used)]
    #![allow(clippy::expect_used)]
    #![allow(clippy::panic)]

    use super::*;
    use crate::stage_b_blob_id::{derive_walrus_blob_id, stage_b_verify_blob_id};
    use mnemos_c_walrus::{BlobId, PublisherReportedBlobId};

    /// Test-only URL-safe base64 (no padding) encoder for a 32-byte id — the
    /// faithful inverse of `c-walrus`'s private `decode_base64url_no_pad_32`.
    /// `c-walrus`'s own encoder is `pub(crate)`, so a cross-crate test cannot
    /// call it; this is the test-only duplicate used by the #108 tests
    /// (`stage_b_blob_id.rs`), reproduced here to synthesize a *correctly*
    /// reported id text so the only `VerifiedBlobId` constructor can be driven.
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
    /// same bytes. No bare/unverified `BlobId` is ever fabricated.
    fn verified_blob_for(bytes: &[u8]) -> VerifiedBlobId {
        let id: BlobId = derive_walrus_blob_id(bytes);
        let text = base64url_no_pad_encode_32(id.as_bytes());
        let reported = PublisherReportedBlobId::try_from_text(&text).unwrap();
        stage_b_verify_blob_id(bytes, &reported)
            .expect("a reported id equal to the local derive must verify")
    }

    /// A Walrus-primary `StorageObjectRef` carrying the verified blob, built via
    /// the atom #31 const constructor (no receipt-local storage type).
    fn storage_for(bytes: &[u8], verified: VerifiedBlobId) -> StorageObjectRef {
        let id = derive_walrus_blob_id(bytes);
        StorageObjectRef::walrus_primary(*id.as_bytes(), verified)
    }

    /// `receipt redacts body` — two **different** payload bodies of the **same
    /// length** produce byte-identical receipts (when blob/storage/timings/trace
    /// match), proving the raw body never enters the receipt; only its length
    /// (`bytes_u32`) is recorded. The `VerifiedBlobId`/`StorageObjectRef` are
    /// pinned to one body so the only varying input is the *content* of the
    /// other body — which must make no difference.
    #[test]
    fn b2_8_receipt_redacts_body() {
        let pinned = b"mnemos atom 109 round trip body content vector";
        let verified = verified_blob_for(pinned);
        let storage = storage_for(pinned, verified);
        let trace = StageBTraceLink::new(0xA90F_0109, 109, 0);

        // Two distinct 100-byte bodies (all 0xAA vs all 0x55).
        let body_a = vec![0xAAu8; 100];
        let body_b = vec![0x55u8; 100];
        assert_ne!(body_a, body_b, "the two bodies must genuinely differ");

        let receipt_a =
            WalrusRoundTripReceipt::from_round_trip(verified, storage, 12, 7, &body_a, trace)
                .expect("100 bytes is within u32");
        let receipt_b =
            WalrusRoundTripReceipt::from_round_trip(verified, storage, 12, 7, &body_b, trace)
                .expect("100 bytes is within u32");

        assert_eq!(
            receipt_a, receipt_b,
            "receipts for equal-length but different bodies must be byte-identical (no body carried)"
        );
        assert_eq!(receipt_a.bytes_u32(), 100, "only the length is recorded");
    }

    /// `from_round_trip` records the body length and refuses oversize lengths
    /// fail-closed (the `u32::MAX` guard) — a length, never the bytes.
    #[test]
    fn b2_8_length_only_recorded() {
        let bytes = b"len witness";
        let verified = verified_blob_for(bytes);
        let storage = storage_for(bytes, verified);
        let trace = StageBTraceLink::new(7, 109, 1);

        let body = vec![0u8; 4096];
        let receipt =
            WalrusRoundTripReceipt::from_round_trip(verified, storage, 1, 1, &body, trace)
                .expect("4096 within u32");
        assert_eq!(receipt.bytes_u32(), 4096);
        // The receipt is Copy — it owns no heap body.
        let _copied: WalrusRoundTripReceipt = receipt;
        assert_eq!(_copied, receipt);
    }

    /// `preserves latency` — the PUT and GET millisecond counts survive verbatim
    /// and sum losslessly via `total_ms_u64`.
    #[test]
    fn b2_8_preserves_latency() {
        let bytes = b"latency witness";
        let verified = verified_blob_for(bytes);
        let storage = storage_for(bytes, verified);
        let trace = StageBTraceLink::new(42, 109, 0);

        let receipt = WalrusRoundTripReceipt::new(verified, storage, 1234, 5678, 16, trace);
        assert_eq!(receipt.put_ms_u32, 1234, "PUT latency preserved verbatim");
        assert_eq!(receipt.get_ms_u32, 5678, "GET latency preserved verbatim");
        assert_eq!(
            receipt.total_ms_u64(),
            1234 + 5678,
            "total is the lossless sum"
        );

        // Near-u32::MAX legs sum without truncation (the u64 widening).
        let big = WalrusRoundTripReceipt::new(verified, storage, u32::MAX, u32::MAX, 0, trace);
        assert_eq!(big.total_ms_u64(), u32::MAX as u64 * 2);
    }

    /// `trace linked` — a stamped receipt projects to `Some` content-free
    /// evidence whose ids equal the receipt's trace components; an unstamped
    /// receipt (`atom_id_u16 == 0`) projects to `None`, fail-closed.
    #[test]
    fn b2_8_trace_linked() {
        let bytes = b"trace witness";
        let verified = verified_blob_for(bytes);
        let storage = storage_for(bytes, verified);

        let trace = StageBTraceLink::new(0xDEAD_BEEF, 109, 3);
        let receipt = WalrusRoundTripReceipt::new(verified, storage, 5, 6, 8, trace);
        let evidence = receipt
            .trace_evidence()
            .expect("a receipt stamped with atom #109 must project to evidence");
        assert_eq!(
            evidence.evidence_ids(),
            (0xDEAD_BEEF, 109, 3),
            "evidence ids must equal the receipt's trace components"
        );
        assert_eq!(
            receipt.trace(),
            trace,
            "the receipt's trace is the verbatim stamp"
        );

        // Missing/unstamped sentinel (atom #0 RESET) — fail-closed to None.
        let unstamped = StageBTraceLink::new(123, 0, 0);
        let receipt_unstamped = WalrusRoundTripReceipt::new(verified, storage, 5, 6, 8, unstamped);
        assert!(
            receipt_unstamped.trace_evidence().is_none(),
            "an unstamped (atom_id_u16 == 0) receipt mints no evidence record"
        );
    }
}
