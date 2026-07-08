//! Memory index record — fixed-layout catalog entry for agentic selective
//! retrieval.
//!
//! One [`MemoryIndexRecord`] catalogs one memory: `{id, content hash, Walrus
//! location, deterministic summary, importance, tier, privacy class}` in a
//! single `#[repr(C)]` 336-byte fixed layout. The agent reads these cheap
//! fixed-width records every turn and selectively fetches only the K relevant
//! memories' content (read CU `O(K)`) — the record is the cheap
//! thing, the content stays cold.
//!
//! # The two physical laws (drift is unrepresentable, not policed)
//!
//! * **Law 1 — content-addressing ⇒ no location drift.** `blob_id_32` is the
//!   locally derived Walrus location of the cataloged blob bytes
//!   ([`derive_walrus_blob_id`] — the same derivation the
//!   `verify_reported_blob_id` seam promotes a reported id against, never
//!   trusting a self-reported id). Change one byte and you have a *different* address,
//!   not a stale pointer.
//! * **Law 2 — deterministic summary + immutable content ⇒ no summary
//!   drift.** `summary` is the pure function [`derive_summary`]`(content)`,
//!   computed at construction and hash-bound to `content_hash_32`
//!   ([`ContentHash32::of`]). Any reader re-derives and compares
//!   ([`MemoryIndexRecord::verify_against_content`]). A summary can never
//!   describe the wrong memory: it is computed FROM the memory and bound TO
//!   the memory's hash.
//!
//! # Byte-level lock (cross-language)
//!
//! Field order is largest-align-first (`u64 → [u8;N] → u16 → u8`), so every
//! field is naturally aligned and the declared `pad_2` is the ONLY padding:
//! `size_of == 336`, `align_of == 8`, zero implicit padding. The layout is
//! pinned three ways, each failing the *build* (never the run): compile-time
//! `size_of`/`align_of` asserts, compile-time `offset_of!` asserts against
//! the named `OFFSET_*` constants, and a cross-language re-computation of
//! the same offsets (`0/8/40/72/328/330/332/333/334`, size 336,
//! align 8, implicit pad 0). The naive declaration order computes to 344
//! bytes WITH implicit padding and was REJECTED at design time.
//!
//! # Drift invariants owned here
//!
//! | invariant | enforcement |
//! |---|---|
//! | location ↔ content never drift | `blob_id_32` = [`derive_walrus_blob_id`] of the blob bytes; re-derivable via [`MemoryIndexRecord::verify_blob_location`] |
//! | summary ↔ content never drift | `summary = derive_summary(content)` pure, hash-bound; re-derive + compare |
//! | record layout never drifts | `#[repr(C)]` + const asserts + cross-language width lock |
//! | a read returns the claimed bytes | [`MemoryIndexRecord::verify_against_content`] re-hashes + re-derives |
//!
//! Fail-closed privacy default: an unclassified memory
//! is PRIVATE ([`UNCLASSIFIED_IS_PRIVATE`]); `private_u8` validates to
//! `{0, 1}` on decode and ANY nonzero byte reads back as private.
//!
//! # Reuse map (no reinvention)
//!
//! * [`MemoryId`] — monotone local id, stored as its raw `u64`.
//! * [`ContentHash32::of`] — domain-separated content hash.
//! * [`derive_walrus_blob_id`] — local Walrus location derivation.
//! * [`MemoryTier`] — tier byte via [`MemoryTier::tag`].
//! * [`MAX_IMPORTANCE_SCORE`] — importance stays in `0..=10000`.
//! * [`MAX_STAGE_B_CONTENT_BYTES`] — the same 1 MiB content cap,
//!   re-checked fail-closed before hashing (mirrors `stage_b_chunk_digest`).
//!
//! # Module layers
//!
//! * the record + deterministic summary (sections 1-5).
//! * the trust-tier retrieval selectors (section 6), consumed by
//!   the `memory index` / `memory read <id>` read-only dispatch verbs.
//! * the chunk fold (section 7; the index is a CACHE, the chunks
//!   are the truth) + the cache image codec (section 8, re-derivable).
//! * the agentic loop driver consumes this same surface.
//!
//! [`MemoryIndexRecord::from_parts`] separates `content` (summary + hash
//! binding) from `blob_id` (location of the published blob bytes), so the
//! fold binds a verified Walrus id without a format change.

use crate::chunk::{MemoryChunk, MemoryId, StorageObjectRef};
use crate::chunk_digest::ContentHash32;
use crate::chunk_schema::MAX_STAGE_B_CONTENT_BYTES;
use crate::intelligence::compactor::MemoryTier;
use crate::intelligence::delete_semantics::TombstonePolicy;
use crate::intelligence::importance::{ImportanceFeatures, ImportanceModel, MAX_IMPORTANCE_SCORE};
use crate::stage_b_blob_id::derive_walrus_blob_id;
use mnemos_c_walrus::BlobId;

// ===========================================================================
// 1. Byte-layout constants (the cross-language lock surface)
// ===========================================================================

/// Fixed summary capacity in bytes. The summary is
/// UTF-8, zero-padded to this width; the index stays `O(N) × fixed`.
pub const SUMMARY_CAP: usize = 256;

/// Total record width in bytes, compile-time asserted below. A layout drift
/// is a build failure.
pub const MEMORY_INDEX_RECORD_BYTES: usize = 336;

/// Record alignment in bytes (the `u64` field dominates).
pub const MEMORY_INDEX_RECORD_ALIGN: usize = 8;

/// Fail-closed privacy class default: an unclassified
/// memory is treated PRIVATE, never accidentally shareable. The fold
/// projection consumes this constant when a chunk carries
/// no explicit classification.
pub const UNCLASSIFIED_IS_PRIVATE: bool = true;

/// Owner-facing privacy classification of one memory. The byte VALUES mirror
/// the index record's `private_u8` encoding
/// (`0` = shareable, `1` = private), so the persisted class byte and the
/// projected record can never disagree on meaning (cross-surface byte-VALUE
/// lock).
///
/// Fail-closed: the DEFAULT everywhere is [`MemoryPrivacy::Private`]. Only an
/// explicit owner act (the `memory save --shareable` typed flag) produces
/// [`MemoryPrivacy::Shareable`], and only shareable records may list for a
/// frontier-bound turn ([`catalog_select`]) — after the redaction gate,
/// which classification never bypasses.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Hash)]
#[repr(u8)]
pub enum MemoryPrivacy {
    /// Explicitly owner-classified as shareable with a frontier provider.
    Shareable = 0,
    /// Private to the owner's machine (the fail-closed default).
    #[default]
    Private = 1,
}

impl MemoryPrivacy {
    /// Stable persisted tag byte (`0` shareable / `1` private — the same
    /// encoding as the record's `private_u8` field).
    #[inline]
    #[must_use]
    pub const fn tag(self) -> u8 {
        self as u8
    }

    /// Decode a persisted tag byte, fail-closed: ONLY the two locked values
    /// decode; any other byte is `None` (the caller skips the record — an
    /// unparseable class is never guessed).
    #[inline]
    #[must_use]
    pub const fn from_tag(tag: u8) -> Option<Self> {
        match tag {
            0 => Some(Self::Shareable),
            1 => Some(Self::Private),
            _ => None,
        }
    }

    /// Whether this class is private (the record projection value).
    #[inline]
    #[must_use]
    pub const fn is_private(self) -> bool {
        matches!(self, Self::Private)
    }
}

/// Byte offset of `memory_id_u64` (`@0`).
pub const OFFSET_MEMORY_ID: usize = 0;
/// Byte offset of `content_hash_32` (`@8`).
pub const OFFSET_CONTENT_HASH: usize = 8;
/// Byte offset of `blob_id_32` (`@40`).
pub const OFFSET_BLOB_ID: usize = 40;
/// Byte offset of `summary` (`@72`).
pub const OFFSET_SUMMARY: usize = 72;
/// Byte offset of `summary_len_u16` (`@328`).
pub const OFFSET_SUMMARY_LEN: usize = 328;
/// Byte offset of `importance_u16` (`@330`).
pub const OFFSET_IMPORTANCE: usize = 330;
/// Byte offset of `tier_u8` (`@332`).
pub const OFFSET_TIER: usize = 332;
/// Byte offset of `private_u8` (`@333`).
pub const OFFSET_PRIVATE: usize = 333;
/// Byte offset of the explicit two-byte tail pad (`@334`).
pub const OFFSET_TAIL_PAD: usize = 334;

// ===========================================================================
// 2. The record
// ===========================================================================

/// One fixed-layout catalog entry per memory.
///
/// Fields are **private**: the only constructors are
/// [`from_parts`](Self::from_parts) / [`from_content`](Self::from_content)
/// (which *compute* the summary and hash from the content — law 2 is enforced
/// by construction, not by discipline) and [`from_bytes`](Self::from_bytes)
/// (which fail-closed validates every field). A record whose summary was not
/// derived from its content is unrepresentable through this API; a forged
/// byte image is caught by [`verify_against_content`](Self::verify_against_content).
///
/// Declaration order is the `#[repr(C)]` byte order — largest-align-first so
/// every field is naturally aligned and `pad_2` is the only padding.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
#[repr(C)]
pub struct MemoryIndexRecord {
    /// Monotone local memory id (`MemoryId` raw value) — replay-reconstructable.
    memory_id_u64: u64,
    /// [`ContentHash32`] of the cataloged content (binds `summary`, law 2).
    content_hash_32: [u8; 32],
    /// Locally derived Walrus location of the blob bytes (law 1).
    blob_id_32: [u8; 32],
    /// Deterministic UTF-8 summary, zero-padded to [`SUMMARY_CAP`].
    summary: [u8; SUMMARY_CAP],
    /// Used byte length of `summary` (`0..=SUMMARY_CAP`).
    summary_len_u16: u16,
    /// Importance score in `0..=MAX_IMPORTANCE_SCORE`.
    importance_u16: u16,
    /// [`MemoryTier`] stable tag (`1..=4`; `4` = tombstone).
    tier_u8: u8,
    /// Privacy class: `1` private (default), `0` shareable. Fail-closed.
    private_u8: u8,
    /// Explicit tail padding — always zero; rejected nonzero on decode.
    pad_2: [u8; 2],
}

// Compile-time byte lock: a drift in size, alignment or ANY field offset
// is a build failure, before any test runs. Mirrors the cross-language
// layout check.
const _: () = assert!(core::mem::size_of::<MemoryIndexRecord>() == MEMORY_INDEX_RECORD_BYTES);
const _: () = assert!(core::mem::align_of::<MemoryIndexRecord>() == MEMORY_INDEX_RECORD_ALIGN);
const _: () = assert!(core::mem::offset_of!(MemoryIndexRecord, memory_id_u64) == OFFSET_MEMORY_ID);
const _: () =
    assert!(core::mem::offset_of!(MemoryIndexRecord, content_hash_32) == OFFSET_CONTENT_HASH);
const _: () = assert!(core::mem::offset_of!(MemoryIndexRecord, blob_id_32) == OFFSET_BLOB_ID);
const _: () = assert!(core::mem::offset_of!(MemoryIndexRecord, summary) == OFFSET_SUMMARY);
const _: () =
    assert!(core::mem::offset_of!(MemoryIndexRecord, summary_len_u16) == OFFSET_SUMMARY_LEN);
const _: () =
    assert!(core::mem::offset_of!(MemoryIndexRecord, importance_u16) == OFFSET_IMPORTANCE);
const _: () = assert!(core::mem::offset_of!(MemoryIndexRecord, tier_u8) == OFFSET_TIER);
const _: () = assert!(core::mem::offset_of!(MemoryIndexRecord, private_u8) == OFFSET_PRIVATE);
const _: () = assert!(core::mem::offset_of!(MemoryIndexRecord, pad_2) == OFFSET_TAIL_PAD);

// ===========================================================================
// 3. Error surface
// ===========================================================================

/// Typed, data-free error surface for record construction / decode / verify.
/// `Copy` + no owned bytes (crate idiom): the error channel cannot leak a
/// summary fragment or raw content through `Debug`.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
#[non_exhaustive]
pub enum MemoryIndexError {
    /// Content exceeded [`MAX_STAGE_B_CONTENT_BYTES`] (fail-closed cap
    /// re-check before hashing; mirrors `stage_b_chunk_digest`).
    ContentTooLarge,
    /// Importance exceeded [`MAX_IMPORTANCE_SCORE`].
    ImportanceOutOfRange,
    /// Decoded `summary_len` exceeded [`SUMMARY_CAP`].
    SummaryLenOutOfRange,
    /// A byte past `summary_len` was nonzero (zero-padding violated).
    SummaryPaddingNonZero,
    /// The used summary bytes were not valid UTF-8.
    SummaryNotUtf8,
    /// The tier byte was not a valid [`MemoryTier`] tag (`1..=4`).
    TierTagInvalid,
    /// The privacy byte was outside `{0, 1}`.
    PrivateFlagInvalid,
    /// The explicit tail pad was nonzero.
    TailPadNonZero,
    /// Re-hashing the presented content did not match `content_hash_32`.
    ContentHashMismatch,
    /// Re-deriving the presented blob bytes did not match `blob_id_32`.
    BlobIdMismatch,
    /// Re-deriving the summary from the presented content did not match the
    /// stored summary (law 2 re-derive + compare).
    SummaryMismatch,
}

impl MemoryIndexError {
    /// Stable, allow-listed `class_label` for diagnostic envelopes (crate
    /// idiom; namespaced under `memory_index.*`).
    #[inline]
    #[must_use]
    pub const fn class_label(self) -> &'static str {
        match self {
            Self::ContentTooLarge => "memory_index.content_too_large",
            Self::ImportanceOutOfRange => "memory_index.importance_out_of_range",
            Self::SummaryLenOutOfRange => "memory_index.summary_len_out_of_range",
            Self::SummaryPaddingNonZero => "memory_index.summary_padding_non_zero",
            Self::SummaryNotUtf8 => "memory_index.summary_not_utf8",
            Self::TierTagInvalid => "memory_index.tier_tag_invalid",
            Self::PrivateFlagInvalid => "memory_index.private_flag_invalid",
            Self::TailPadNonZero => "memory_index.tail_pad_non_zero",
            Self::ContentHashMismatch => "memory_index.content_hash_mismatch",
            Self::BlobIdMismatch => "memory_index.blob_id_mismatch",
            Self::SummaryMismatch => "memory_index.summary_mismatch",
        }
    }
}

// ===========================================================================
// 4. Deterministic summary — the pure `f(content)`
// ===========================================================================

/// Derive the deterministic summary of `content`: the rule-based
/// extractive head (no LLM ⇒ no non-determinism ⇒ no drift, and
/// no private content sent anywhere to summarize).
///
/// Algorithm (pure, total, allocation-free):
///
/// 1. Take the longest valid UTF-8 prefix of `content` (binary tails drop
///    off deterministically; wholly binary content summarizes to empty).
/// 2. Walk its chars: whitespace runs (including newlines/tabs) collapse to
///    a single ASCII space between words; leading/trailing whitespace is
///    trimmed; non-whitespace control chars are dropped (the same
///    `!is_control` posture as the GUI render filter — Hangul/CJK are KEPT).
/// 3. Stop at the FIRST char that would overflow [`SUMMARY_CAP`] bytes
///    (strict prefix semantics, never best-fit packing, never a split char —
///    the result is always valid UTF-8).
///
/// Returns the zero-padded summary buffer and its used byte length. Same
/// content ⇒ same bytes, bit-for-bit (pinned by tests).
#[must_use]
pub fn derive_summary(content: &[u8]) -> ([u8; SUMMARY_CAP], u16) {
    let text = longest_utf8_prefix(content);
    let mut out = [0u8; SUMMARY_CAP];
    let mut len = 0usize;
    let mut pending_space = false;
    for c in text.chars() {
        if c.is_whitespace() {
            // Collapse runs; suppress a leading separator entirely.
            pending_space = len > 0;
            continue;
        }
        if c.is_control() {
            // Non-whitespace control (BEL, ESC, …) is dropped, render-safe.
            continue;
        }
        let need = c.len_utf8() + usize::from(pending_space);
        if len + need > SUMMARY_CAP {
            break;
        }
        if pending_space {
            out[len] = b' ';
            len += 1;
            pending_space = false;
        }
        // Capacity was checked above, so `encode_utf8` always fits.
        len += c.encode_utf8(&mut out[len..]).len();
    }
    // `len <= SUMMARY_CAP == 256` by the loop bound, so the cast is exact.
    (out, len as u16)
}

/// Longest valid UTF-8 prefix of `bytes` (total: invalid input degrades to
/// the valid head, never an error).
fn longest_utf8_prefix(bytes: &[u8]) -> &str {
    match core::str::from_utf8(bytes) {
        Ok(text) => text,
        Err(err) => {
            // `valid_up_to` marks the longest valid prefix; the re-check is
            // total and the empty summary is the (unreachable) fallback.
            core::str::from_utf8(&bytes[..err.valid_up_to()]).unwrap_or("")
        }
    }
}

// ===========================================================================
// 5. Construction / accessors / codec / verify
// ===========================================================================

impl MemoryIndexRecord {
    /// Construct a record from its parts: `content` drives the content hash
    /// and the deterministic summary (law 2); `blob_id` is the Walrus
    /// location of the blob bytes (law 1) — for a published chunk that is the
    /// id of the encoded chunk wire, which is generally NOT the raw content.
    ///
    /// Fail-closed: rejects over-cap content before hashing and an
    /// out-of-range importance before storing.
    pub fn from_parts(
        memory_id: MemoryId,
        content: &[u8],
        blob_id: BlobId,
        importance_u16: u16,
        tier: MemoryTier,
        private: bool,
    ) -> Result<Self, MemoryIndexError> {
        if content.len() > MAX_STAGE_B_CONTENT_BYTES as usize {
            return Err(MemoryIndexError::ContentTooLarge);
        }
        if importance_u16 > MAX_IMPORTANCE_SCORE {
            return Err(MemoryIndexError::ImportanceOutOfRange);
        }
        let (summary, summary_len_u16) = derive_summary(content);
        Ok(Self {
            memory_id_u64: memory_id.get(),
            content_hash_32: *ContentHash32::of(content).as_bytes(),
            blob_id_32: *blob_id.as_bytes(),
            summary,
            summary_len_u16,
            importance_u16,
            tier_u8: tier.tag(),
            private_u8: u8::from(private),
            pad_2: [0u8; 2],
        })
    }

    /// Convenience constructor for the content-as-published-payload case:
    /// the blob location is derived from `content` itself
    /// ([`derive_walrus_blob_id`]). The fold projection uses
    /// [`from_parts`](Self::from_parts) with the encoded chunk wire's id
    /// instead.
    pub fn from_content(
        memory_id: MemoryId,
        content: &[u8],
        importance_u16: u16,
        tier: MemoryTier,
        private: bool,
    ) -> Result<Self, MemoryIndexError> {
        if content.len() > MAX_STAGE_B_CONTENT_BYTES as usize {
            return Err(MemoryIndexError::ContentTooLarge);
        }
        Self::from_parts(
            memory_id,
            content,
            derive_walrus_blob_id(content),
            importance_u16,
            tier,
            private,
        )
    }

    /// The cataloged memory's monotone local id.
    #[inline]
    #[must_use]
    pub const fn memory_id(&self) -> MemoryId {
        MemoryId::new(self.memory_id_u64)
    }

    /// Borrow the 32-byte content hash that binds the summary (law 2).
    #[inline]
    #[must_use]
    pub const fn content_hash_32(&self) -> &[u8; 32] {
        &self.content_hash_32
    }

    /// Borrow the 32-byte Walrus location (law 1).
    #[inline]
    #[must_use]
    pub const fn blob_id_32(&self) -> &[u8; 32] {
        &self.blob_id_32
    }

    /// The summary as `&str`. Total: the used bytes are valid UTF-8 by
    /// construction ([`derive_summary`]) and by decode validation
    /// ([`from_bytes`](Self::from_bytes)); the bound and the fallback keep
    /// this panic-free even against an impossible internal state.
    #[inline]
    #[must_use]
    pub fn summary_str(&self) -> &str {
        let len = (self.summary_len_u16 as usize).min(SUMMARY_CAP);
        core::str::from_utf8(&self.summary[..len]).unwrap_or("")
    }

    /// Used byte length of the summary (`0..=SUMMARY_CAP`).
    #[inline]
    #[must_use]
    pub const fn summary_len_u16(&self) -> u16 {
        self.summary_len_u16
    }

    /// Importance score (`0..=MAX_IMPORTANCE_SCORE`).
    #[inline]
    #[must_use]
    pub const fn importance_u16(&self) -> u16 {
        self.importance_u16
    }

    /// The memory's tier. The tag is validated to `1..=4` at every
    /// construction site; an out-of-range byte (unreachable through this
    /// API) reads fail-closed as the most-denied tier,
    /// [`MemoryTier::DeletedTombstone`] — a tombstone is excluded from
    /// retrieval, so corruption degrades to denial, never to
    /// exposure.
    #[inline]
    #[must_use]
    pub const fn tier(&self) -> MemoryTier {
        match self.tier_u8 {
            1 => MemoryTier::Recent,
            2 => MemoryTier::Mid,
            3 => MemoryTier::Ancient,
            _ => MemoryTier::DeletedTombstone,
        }
    }

    /// Whether this record is tombstoned (terminal; excluded from retrieval).
    #[inline]
    #[must_use]
    pub const fn is_tombstone(&self) -> bool {
        self.tier().is_tombstone()
    }

    /// Privacy class. Fail-closed read: ANY nonzero byte is private — only
    /// an explicit `0` is shareable.
    #[inline]
    #[must_use]
    pub const fn is_private(&self) -> bool {
        self.private_u8 != 0
    }

    /// Serialize to the locked 336-byte little-endian image. The `OFFSET_*`
    /// constants are the single source of truth for every field span (the
    /// same constants the compile-time asserts and the cross-language layout
    /// check pin).
    #[must_use]
    pub fn to_bytes(&self) -> [u8; MEMORY_INDEX_RECORD_BYTES] {
        let mut out = [0u8; MEMORY_INDEX_RECORD_BYTES];
        out[OFFSET_MEMORY_ID..OFFSET_CONTENT_HASH]
            .copy_from_slice(&self.memory_id_u64.to_le_bytes());
        out[OFFSET_CONTENT_HASH..OFFSET_BLOB_ID].copy_from_slice(&self.content_hash_32);
        out[OFFSET_BLOB_ID..OFFSET_SUMMARY].copy_from_slice(&self.blob_id_32);
        out[OFFSET_SUMMARY..OFFSET_SUMMARY_LEN].copy_from_slice(&self.summary);
        out[OFFSET_SUMMARY_LEN..OFFSET_IMPORTANCE]
            .copy_from_slice(&self.summary_len_u16.to_le_bytes());
        out[OFFSET_IMPORTANCE..OFFSET_TIER].copy_from_slice(&self.importance_u16.to_le_bytes());
        out[OFFSET_TIER] = self.tier_u8;
        out[OFFSET_PRIVATE] = self.private_u8;
        // OFFSET_TAIL_PAD..: stays zero (pad_2 is zero by construction).
        out
    }

    /// Decode a 336-byte image, fail-closed validating EVERY field: summary
    /// length bound, zero padding past the summary, UTF-8 validity of the
    /// used summary bytes, importance bound, tier tag domain, privacy-byte
    /// domain and the explicit tail pad. Any violation is a typed error —
    /// never a silently repaired record.
    pub fn from_bytes(bytes: &[u8; MEMORY_INDEX_RECORD_BYTES]) -> Result<Self, MemoryIndexError> {
        let memory_id_u64 = u64::from_le_bytes(read_8(bytes, OFFSET_MEMORY_ID));
        let content_hash_32 = read_32(bytes, OFFSET_CONTENT_HASH);
        let blob_id_32 = read_32(bytes, OFFSET_BLOB_ID);
        let mut summary = [0u8; SUMMARY_CAP];
        summary.copy_from_slice(&bytes[OFFSET_SUMMARY..OFFSET_SUMMARY_LEN]);
        let summary_len_u16 = u16::from_le_bytes(read_2(bytes, OFFSET_SUMMARY_LEN));
        let importance_u16 = u16::from_le_bytes(read_2(bytes, OFFSET_IMPORTANCE));
        let tier_u8 = bytes[OFFSET_TIER];
        let private_u8 = bytes[OFFSET_PRIVATE];
        let pad_2 = [bytes[OFFSET_TAIL_PAD], bytes[OFFSET_TAIL_PAD + 1]];

        // Length bound FIRST: every later slice is in range because of it.
        let len = summary_len_u16 as usize;
        if len > SUMMARY_CAP {
            return Err(MemoryIndexError::SummaryLenOutOfRange);
        }
        if summary[len..].iter().any(|b| *b != 0) {
            return Err(MemoryIndexError::SummaryPaddingNonZero);
        }
        if core::str::from_utf8(&summary[..len]).is_err() {
            return Err(MemoryIndexError::SummaryNotUtf8);
        }
        if importance_u16 > MAX_IMPORTANCE_SCORE {
            return Err(MemoryIndexError::ImportanceOutOfRange);
        }
        if !matches!(tier_u8, 1..=4) {
            return Err(MemoryIndexError::TierTagInvalid);
        }
        if private_u8 > 1 {
            return Err(MemoryIndexError::PrivateFlagInvalid);
        }
        if pad_2 != [0u8; 2] {
            return Err(MemoryIndexError::TailPadNonZero);
        }
        Ok(Self {
            memory_id_u64,
            content_hash_32,
            blob_id_32,
            summary,
            summary_len_u16,
            importance_u16,
            tier_u8,
            private_u8,
            pad_2,
        })
    }

    /// Read-side verify (law 2): re-hash the presented content and
    /// re-derive its summary, comparing both against the record. A record
    /// can therefore never *describe* bytes it was not computed from —
    /// drift is detected, not trusted.
    pub fn verify_against_content(&self, content: &[u8]) -> Result<(), MemoryIndexError> {
        if ContentHash32::of(content).as_bytes() != &self.content_hash_32 {
            return Err(MemoryIndexError::ContentHashMismatch);
        }
        let (expected_summary, expected_len) = derive_summary(content);
        if expected_len != self.summary_len_u16 || expected_summary != self.summary {
            return Err(MemoryIndexError::SummaryMismatch);
        }
        Ok(())
    }

    /// Read-side verify (law 1): re-derive the Walrus location of the
    /// presented blob bytes and compare against the stored location. A
    /// forged or stale index entry cannot point at wrong-but-accepted bytes.
    pub fn verify_blob_location(&self, blob_bytes: &[u8]) -> Result<(), MemoryIndexError> {
        if derive_walrus_blob_id(blob_bytes).as_bytes() != &self.blob_id_32 {
            return Err(MemoryIndexError::BlobIdMismatch);
        }
        Ok(())
    }
}

/// Read 8 bytes at `at..at + 8` (caller passes const offsets within bounds).
fn read_8(bytes: &[u8; MEMORY_INDEX_RECORD_BYTES], at: usize) -> [u8; 8] {
    let mut out = [0u8; 8];
    out.copy_from_slice(&bytes[at..at + 8]);
    out
}

/// Read 2 bytes at `at..at + 2` (caller passes const offsets within bounds).
fn read_2(bytes: &[u8; MEMORY_INDEX_RECORD_BYTES], at: usize) -> [u8; 2] {
    let mut out = [0u8; 2];
    out.copy_from_slice(&bytes[at..at + 2]);
    out
}

/// Read 32 bytes at `at..at + 32` (caller passes const offsets within bounds).
fn read_32(bytes: &[u8; MEMORY_INDEX_RECORD_BYTES], at: usize) -> [u8; 32] {
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes[at..at + 32]);
    out
}

// ===========================================================================
// 6. Retrieval selectors — pure + trust-tier aware
// ===========================================================================

/// Why a `memory read` candidate was denied (data-free, `Copy`).
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
#[non_exhaustive]
pub enum MemoryReadDeny {
    /// The id is not in the index (an unindexed memory is unreadable).
    NotInIndex,
    /// The record is tombstoned — terminal, never resurrected.
    Tombstoned,
    /// The record is private and the read is frontier-bound: a
    /// private memory never crosses to a frontier provider. A LOCAL read
    /// (the owner's own surface) is NOT denied by this arm.
    PrivateToFrontier,
}

impl MemoryReadDeny {
    /// Stable, allow-listed `class_label` for diagnostic envelopes.
    #[inline]
    #[must_use]
    pub const fn class_label(self) -> &'static str {
        match self {
            Self::NotInIndex => "memory_index.read_deny.not_in_index",
            Self::Tombstoned => "memory_index.read_deny.tombstoned",
            Self::PrivateToFrontier => "memory_index.read_deny.private_to_frontier",
        }
    }
}

/// List-time catalog selection (`memory index`): tombstoned records
/// are excluded ALWAYS (a deleted memory is never a
/// retrieval candidate); private records are excluded ONLY when the catalog
/// is frontier-bound (the local owner surface and a
/// future local model may see private records, a frontier provider may not).
///
/// Pure projection: borrows, never mutates, returns references in input
/// order (deterministic).
#[must_use]
pub fn catalog_select(
    records: &[MemoryIndexRecord],
    frontier_bound: bool,
) -> Vec<&MemoryIndexRecord> {
    records
        .iter()
        .filter(|record| {
            if record.is_tombstone() {
                // A deleted memory is never a retrieval candidate.
                return false;
            }
            if frontier_bound && record.is_private() {
                // A private record never lists for a frontier turn.
                return false;
            }
            true
        })
        .collect()
}

/// Read-time gate (`memory read <id>`): the id must be in the
/// records (else [`MemoryReadDeny::NotInIndex`]), not tombstoned (else
/// [`MemoryReadDeny::Tombstoned`]) and — when frontier-bound — not private
/// (else [`MemoryReadDeny::PrivateToFrontier`]). Tombstone denial
/// outranks privacy (the stronger no-resurrection signal).
///
/// Content integrity is the NEXT gate, on the bytes the caller then
/// fetches: [`MemoryIndexRecord::verify_against_content`].
pub fn read_select(
    records: &[MemoryIndexRecord],
    memory_id: MemoryId,
    frontier_bound: bool,
) -> Result<&MemoryIndexRecord, MemoryReadDeny> {
    let record = records
        .iter()
        .find(|record| record.memory_id() == memory_id)
        .ok_or(MemoryReadDeny::NotInIndex)?;
    if record.is_tombstone() {
        return Err(MemoryReadDeny::Tombstoned);
    }
    if frontier_bound && record.is_private() {
        return Err(MemoryReadDeny::PrivateToFrontier);
    }
    Ok(record)
}

// ===========================================================================
// 7. Index fold — the index is a CACHE; the chunks are the truth
// ===========================================================================

/// Outcome of one index fold: the projected records plus honest skip
/// counters — a fold never silently drops a chunk.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct IndexFoldOutcome {
    /// One record per admitted chunk, in input (append) order.
    pub records: Vec<MemoryIndexRecord>,
    /// Chunks skipped because a verified storage ref violated its own
    /// constructor invariant (`content_hash_32 == verified blob id bytes`,
    /// the `walrus_primary` production shape) — a forged/corrupt ref is
    /// never projected (fail closed).
    pub skipped_integrity_u32: u32,
    /// Chunks skipped because the record constructor rejected them
    /// (e.g. over-cap content) — counted, never silently dropped.
    pub skipped_invalid_u32: u32,
}

/// Fold UNCLASSIFIED chunks into the index: every chunk projects PRIVATE
/// ([`UNCLASSIFIED_IS_PRIVATE`], fail-closed); importance IS scored.
/// Production dispatch folds the persisted store through
/// [`fold_index_classified`] with each chunk's OWNER class; this wrapper is
/// the no-classification entry (tests, callers without an owner
/// classification surface).
pub fn fold_index<'a, I>(chunks: I, policy: &TombstonePolicy) -> IndexFoldOutcome
where
    I: IntoIterator<Item = &'a MemoryChunk>,
{
    fold_index_classified(
        chunks
            .into_iter()
            .map(|chunk| (chunk, MemoryPrivacy::Private)),
        policy,
    )
}

/// Fold owner-CLASSIFIED chunks into the index: a PURE projection. The index
/// never becomes a second source of truth — re-running
/// the fold over the same `(chunk, class)` items yields the same records bit
/// for bit, so a lost or corrupted index image is a cache miss, never data
/// loss.
///
/// Projection (each refines later WITHOUT a format change):
/// * `importance` = the deterministic [`ImportanceModel`] score over
///   `{recency rank, access count = 0, content length}` — a pure function of
///   the input sequence (same store, same scores). The recency rank is
///   the REVERSE input position (input is append order — the dispatch path
///   loads id-sorted — so rank 0 = the most recently appended). Access
///   tracking is a later refinement (0 until then). A tombstoned chunk
///   scores the floor `0` (the model fail-closed blocks deleted ids — a
///   deleted memory has no importance).
/// * `private` = the per-chunk [`MemoryPrivacy`] (owner-classified at save
///   time — ONLY an explicit [`MemoryPrivacy::Shareable`] record may
///   later list frontier-bound, and the redaction gate still applies).
/// * `tier` = `Recent`, except the delete truth ([`TombstonePolicy`])
///   projects `DeletedTombstone` (`catalog_select` then excludes it).
/// * `blob_id` = the chunk's verified Walrus id when one exists (its
///   constructor invariant cross-checked), else the local derivation of the
///   content bytes — the content-addressed location those bytes would have.
pub fn fold_index_classified<'a, I>(items: I, policy: &TombstonePolicy) -> IndexFoldOutcome
where
    I: IntoIterator<Item = (&'a MemoryChunk, MemoryPrivacy)>,
{
    // The recency rank needs the total count (rank 0 = LAST appended), so the
    // items buffer once — references plus one class byte each, no content
    // copies (the fold stays O(N) with an O(N)-pointer buffer; CU unchanged).
    let items: Vec<(&MemoryChunk, MemoryPrivacy)> = items.into_iter().collect();
    let total = items.len();
    let model = ImportanceModel::new();
    let mut outcome = IndexFoldOutcome::default();
    for (position, (chunk, privacy)) in items.into_iter().enumerate() {
        let content = chunk.envelope().content.as_slice();
        let blob_id = match chunk.storage().and_then(StorageObjectRef::walrus_blob) {
            Some(verified) => {
                let constructor_invariant_holds = chunk
                    .storage()
                    .is_some_and(|s| s.content_hash_32() == verified.as_blob_id().as_bytes());
                if !constructor_invariant_holds {
                    outcome.skipped_integrity_u32 = outcome.skipped_integrity_u32.saturating_add(1);
                    continue;
                }
                *verified.as_blob_id()
            }
            None => derive_walrus_blob_id(content),
        };
        let deleted = policy.is_tombstoned(chunk.id());
        let tier = if deleted {
            MemoryTier::DeletedTombstone
        } else {
            MemoryTier::Recent
        };
        let importance_u16 = if deleted {
            0
        } else {
            let features = ImportanceFeatures {
                // Saturating casts cannot change a score: recency zeroes past
                // rank 10000 and the length term caps at 100k bytes, both far
                // inside the saturation points.
                recency_rank_u16: u16::try_from(total - 1 - position).unwrap_or(u16::MAX),
                access_count_u16: 0,
                content_len_u32: u32::try_from(content.len()).unwrap_or(u32::MAX),
            };
            model
                .score(chunk.id(), &features, None, false)
                .map_or(0, |scored| scored.score_u16)
        };
        match MemoryIndexRecord::from_parts(
            chunk.id(),
            content,
            blob_id,
            importance_u16,
            tier,
            privacy.is_private(),
        ) {
            Ok(record) => outcome.records.push(record),
            Err(_) => {
                outcome.skipped_invalid_u32 = outcome.skipped_invalid_u32.saturating_add(1);
            }
        }
    }
    outcome
}

// ===========================================================================
// 8. Index image codec — the local cache FORMAT
// ===========================================================================
//
// The serialized image is the at-rest cache representation. It deliberately
// carries NO key material and claims no confidentiality; at-rest encryption
// binds when a seal/crypto seam is wired. Until then the image is a
// caller-managed artifact whose loss or corruption is a cache miss by
// construction (decode fails closed ⇒ re-fold from chunks).

/// Magic + version prefix of a serialized index image.
pub const INDEX_IMAGE_MAGIC: [u8; 8] = *b"MNIDX001";

/// Fixed header width: magic (8) + record count (`u32` LE).
pub const INDEX_IMAGE_HEADER_BYTES: usize = 12;

/// Trailing integrity hash width ([`ContentHash32`] over header + records).
pub const INDEX_IMAGE_HASH_BYTES: usize = 32;

/// Typed decode errors for an index image. ANY violation rejects the WHOLE
/// image — the caller re-folds from chunks (a damaged cache is a cache miss,
/// never repaired in place, never partially loaded).
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
#[non_exhaustive]
pub enum IndexImageError {
    /// Shorter than header + trailing hash.
    TooShort,
    /// The magic/version prefix did not match [`INDEX_IMAGE_MAGIC`].
    BadMagic,
    /// The declared record count does not tile the body exactly.
    LengthMismatch,
    /// The trailing integrity hash did not match the payload.
    IntegrityHashMismatch,
    /// A record failed its own fail-closed validation.
    Record {
        /// Zero-based index of the offending record.
        index_u32: u32,
        /// The record-level validation error.
        error: MemoryIndexError,
    },
}

impl IndexImageError {
    /// Stable, allow-listed `class_label` for diagnostic envelopes.
    #[inline]
    #[must_use]
    pub const fn class_label(self) -> &'static str {
        match self {
            Self::TooShort => "memory_index.image.too_short",
            Self::BadMagic => "memory_index.image.bad_magic",
            Self::LengthMismatch => "memory_index.image.length_mismatch",
            Self::IntegrityHashMismatch => "memory_index.image.integrity_hash_mismatch",
            Self::Record { .. } => "memory_index.image.record_invalid",
        }
    }
}

/// Serialize records into one cache image:
/// `[magic 8][count u32 LE][records N × 336][ContentHash32 32]`.
#[must_use]
pub fn index_to_bytes(records: &[MemoryIndexRecord]) -> Vec<u8> {
    let mut out = Vec::with_capacity(
        INDEX_IMAGE_HEADER_BYTES
            + records.len() * MEMORY_INDEX_RECORD_BYTES
            + INDEX_IMAGE_HASH_BYTES,
    );
    out.extend_from_slice(&INDEX_IMAGE_MAGIC);
    // 2^32 records would be a 1.4 TB image — structurally unreachable; a
    // saturated count still fails closed at decode (LengthMismatch).
    let count = u32::try_from(records.len()).unwrap_or(u32::MAX);
    out.extend_from_slice(&count.to_le_bytes());
    for record in records {
        out.extend_from_slice(&record.to_bytes());
    }
    let hash = ContentHash32::of(&out);
    out.extend_from_slice(hash.as_bytes());
    out
}

/// Decode a cache image, fail-closed: magic, trailing integrity hash, exact
/// length tiling and EVERY record's own validation must all hold, or the
/// whole image is rejected with a typed error and the caller re-folds.
pub fn index_from_bytes(bytes: &[u8]) -> Result<Vec<MemoryIndexRecord>, IndexImageError> {
    if bytes.len() < INDEX_IMAGE_HEADER_BYTES + INDEX_IMAGE_HASH_BYTES {
        return Err(IndexImageError::TooShort);
    }
    if bytes[..INDEX_IMAGE_MAGIC.len()] != INDEX_IMAGE_MAGIC {
        return Err(IndexImageError::BadMagic);
    }
    let payload_len = bytes.len() - INDEX_IMAGE_HASH_BYTES;
    let (payload, trailer) = bytes.split_at(payload_len);
    let mut expected_hash = [0u8; INDEX_IMAGE_HASH_BYTES];
    expected_hash.copy_from_slice(trailer);
    if ContentHash32::of(payload).as_bytes() != &expected_hash {
        return Err(IndexImageError::IntegrityHashMismatch);
    }
    let mut count_bytes = [0u8; 4];
    count_bytes.copy_from_slice(&payload[INDEX_IMAGE_MAGIC.len()..INDEX_IMAGE_HEADER_BYTES]);
    let count = u32::from_le_bytes(count_bytes) as usize;
    let body = &payload[INDEX_IMAGE_HEADER_BYTES..];
    let expected_body = count
        .checked_mul(MEMORY_INDEX_RECORD_BYTES)
        .ok_or(IndexImageError::LengthMismatch)?;
    if body.len() != expected_body {
        return Err(IndexImageError::LengthMismatch);
    }
    let mut records = Vec::with_capacity(count);
    for (index, image) in body.chunks_exact(MEMORY_INDEX_RECORD_BYTES).enumerate() {
        let mut record_bytes = [0u8; MEMORY_INDEX_RECORD_BYTES];
        record_bytes.copy_from_slice(image);
        match MemoryIndexRecord::from_bytes(&record_bytes) {
            Ok(record) => records.push(record),
            Err(error) => {
                // `index` is bounded by `body.len() / 336`, far below u32::MAX.
                return Err(IndexImageError::Record {
                    index_u32: index as u32,
                    error,
                });
            }
        }
    }
    Ok(records)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    #![allow(clippy::expect_used)]
    #![allow(clippy::panic)]

    use super::*;

    fn record_over(content: &[u8]) -> MemoryIndexRecord {
        MemoryIndexRecord::from_content(MemoryId::new(7), content, 5_000, MemoryTier::Recent, true)
            .expect("valid record")
    }

    /// The byte lock, runtime-visible: size 336, align 8, and the full
    /// offset table (`0/8/40/72/328/330/332/333/334`).
    #[test]
    fn layout_locked_336_bytes_align_8_offsets() {
        assert_eq!(core::mem::size_of::<MemoryIndexRecord>(), 336);
        assert_eq!(core::mem::align_of::<MemoryIndexRecord>(), 8);
        assert_eq!(
            [
                OFFSET_MEMORY_ID,
                OFFSET_CONTENT_HASH,
                OFFSET_BLOB_ID,
                OFFSET_SUMMARY,
                OFFSET_SUMMARY_LEN,
                OFFSET_IMPORTANCE,
                OFFSET_TIER,
                OFFSET_PRIVATE,
                OFFSET_TAIL_PAD,
            ],
            [0, 8, 40, 72, 328, 330, 332, 333, 334],
        );
        // Spans tile the record exactly: explicit pad ends at 336.
        assert_eq!(OFFSET_TAIL_PAD + 2, MEMORY_INDEX_RECORD_BYTES);
    }

    /// Law 2 — `derive_summary` is a pure function: same content, same bytes,
    /// bit-for-bit; and the same content builds byte-identical records.
    #[test]
    fn summary_deterministic_bit_for_bit() {
        let content = "시나브로의 기억은 결정적으로 요약된다 — deterministic.".as_bytes();
        let (a_bytes, a_len) = derive_summary(content);
        let (b_bytes, b_len) = derive_summary(content);
        assert_eq!(a_len, b_len);
        assert_eq!(a_bytes, b_bytes);

        let r1 = record_over(content);
        let r2 = record_over(content);
        assert_eq!(r1, r2);
        assert_eq!(r1.to_bytes(), r2.to_bytes());
    }

    /// UTF-8 safety — Hangul survives (the `!is_control` posture, never
    /// ASCII-only) and the 256-byte clamp cuts at a char boundary: 3-byte
    /// Hangul chars pack to 255 bytes (85 chars), never a split char.
    #[test]
    fn summary_keeps_hangul_and_clamps_at_char_boundary() {
        let short = record_over("안녕하세요 시나브로".as_bytes());
        assert_eq!(short.summary_str(), "안녕하세요 시나브로");

        let long = "가".repeat(100); // 300 bytes of 3-byte chars, no spaces
        let (bytes, len) = derive_summary(long.as_bytes());
        assert_eq!(len, 255, "85 × 3-byte chars = 255 (256 splits a char)");
        let text = core::str::from_utf8(&bytes[..len as usize]).expect("valid UTF-8");
        assert_eq!(text.chars().count(), 85);
        assert!(text.chars().all(|c| c == '가'));
        // Zero padding past the used length.
        assert!(bytes[len as usize..].iter().all(|b| *b == 0));
    }

    /// Rule-based head: whitespace runs (incl. newlines/tabs) collapse to a
    /// single space, leading/trailing whitespace trims, and non-whitespace
    /// control chars (BEL here) drop — Hangul/CJK kept throughout.
    #[test]
    fn summary_strips_control_and_collapses_whitespace() {
        let content = "  Hello,\n\n월드!\tagent \u{7}core  ".as_bytes();
        let (bytes, len) = derive_summary(content);
        let text = core::str::from_utf8(&bytes[..len as usize]).expect("valid UTF-8");
        assert_eq!(text, "Hello, 월드! agent core");
    }

    /// Binary content degrades deterministically: the longest valid UTF-8
    /// prefix summarizes; a wholly binary body summarizes to empty.
    #[test]
    fn summary_of_invalid_utf8_takes_valid_prefix() {
        let (bytes, len) = derive_summary(b"ok\xFF\xFE tail");
        assert_eq!(core::str::from_utf8(&bytes[..len as usize]), Ok("ok"));

        let (_, empty_len) = derive_summary(b"\xFF\xFE\xFD");
        assert_eq!(empty_len, 0);
    }

    /// Round-trip: `to_bytes → from_bytes` reproduces the record exactly,
    /// including the empty-content boundary record.
    #[test]
    fn record_round_trip_to_from_bytes() {
        for content in [
            "the quick brown fox — 빠른 갈색 여우".as_bytes(),
            b"" as &[u8],
        ] {
            let record = record_over(content);
            let bytes = record.to_bytes();
            let back = MemoryIndexRecord::from_bytes(&bytes).expect("decodes");
            assert_eq!(record, back);
            assert_eq!(bytes, back.to_bytes());
        }
    }

    /// Fail-closed decode: every corrupted field is a typed reject, never a
    /// silently repaired record.
    #[test]
    fn from_bytes_rejects_each_corruption() {
        let valid = record_over(b"ab").to_bytes();

        let mut len_over = valid;
        len_over[OFFSET_SUMMARY_LEN..OFFSET_IMPORTANCE].copy_from_slice(&300u16.to_le_bytes());
        assert_eq!(
            MemoryIndexRecord::from_bytes(&len_over),
            Err(MemoryIndexError::SummaryLenOutOfRange)
        );

        let mut pad_dirty = valid;
        pad_dirty[OFFSET_SUMMARY + 5] = 7; // past summary_len == 2
        assert_eq!(
            MemoryIndexRecord::from_bytes(&pad_dirty),
            Err(MemoryIndexError::SummaryPaddingNonZero)
        );

        let mut bad_utf8 = valid;
        bad_utf8[OFFSET_SUMMARY] = 0xFF; // inside the used summary bytes
        assert_eq!(
            MemoryIndexRecord::from_bytes(&bad_utf8),
            Err(MemoryIndexError::SummaryNotUtf8)
        );

        let mut importance_over = valid;
        importance_over[OFFSET_IMPORTANCE..OFFSET_TIER].copy_from_slice(&10_001u16.to_le_bytes());
        assert_eq!(
            MemoryIndexRecord::from_bytes(&importance_over),
            Err(MemoryIndexError::ImportanceOutOfRange)
        );

        for bad_tier in [0u8, 5] {
            let mut tier_bad = valid;
            tier_bad[OFFSET_TIER] = bad_tier;
            assert_eq!(
                MemoryIndexRecord::from_bytes(&tier_bad),
                Err(MemoryIndexError::TierTagInvalid)
            );
        }

        let mut private_bad = valid;
        private_bad[OFFSET_PRIVATE] = 2;
        assert_eq!(
            MemoryIndexRecord::from_bytes(&private_bad),
            Err(MemoryIndexError::PrivateFlagInvalid)
        );

        let mut pad_bad = valid;
        pad_bad[OFFSET_TAIL_PAD + 1] = 1;
        assert_eq!(
            MemoryIndexRecord::from_bytes(&pad_bad),
            Err(MemoryIndexError::TailPadNonZero)
        );
    }

    /// Verify detects drift (law 2): wrong content fails the hash, and
    /// a FORGED summary (locally consistent bytes spliced from another
    /// record, which `from_bytes` alone cannot catch) fails the re-derive.
    #[test]
    fn verify_against_content_detects_drift() {
        let content = b"the quick brown fox";
        let record = record_over(content);
        assert_eq!(record.verify_against_content(content), Ok(()));
        assert_eq!(
            record.verify_against_content(b"other bytes"),
            Err(MemoryIndexError::ContentHashMismatch)
        );

        // Splice a DIFFERENT record's (valid) summary + length over this
        // record's bytes: decode passes (locally consistent), but the
        // hash-bound re-derivation catches the forgery.
        let donor = record_over(b"completely different summary text");
        let mut forged = record.to_bytes();
        forged[OFFSET_SUMMARY..OFFSET_IMPORTANCE]
            .copy_from_slice(&donor.to_bytes()[OFFSET_SUMMARY..OFFSET_IMPORTANCE]);
        let forged_record = MemoryIndexRecord::from_bytes(&forged).expect("locally consistent");
        assert_eq!(
            forged_record.verify_against_content(content),
            Err(MemoryIndexError::SummaryMismatch)
        );
    }

    /// The location IS the content: `from_content` binds both hashes to
    /// the same bytes; `from_parts` binds the location to the (distinct)
    /// blob wire; a bit flip moves the address instead of staling it.
    #[test]
    fn record_binds_location_and_hash_to_content() {
        let content = b"hello walrus";
        let record = record_over(content);
        assert_eq!(
            record.content_hash_32(),
            ContentHash32::of(content).as_bytes()
        );
        assert_eq!(
            record.blob_id_32(),
            derive_walrus_blob_id(content).as_bytes()
        );
        assert_eq!(record.verify_blob_location(content), Ok(()));
        assert_eq!(
            record.verify_blob_location(b"hello walrut"),
            Err(MemoryIndexError::BlobIdMismatch)
        );

        // Split binding: summary/hash over readable content, location over
        // the encoded wire (the fold's split-binding shape).
        let wire = b"\x01\x02encoded chunk wire bytes";
        let split = MemoryIndexRecord::from_parts(
            MemoryId::new(9),
            content,
            derive_walrus_blob_id(wire),
            0,
            MemoryTier::Mid,
            false,
        )
        .expect("valid");
        assert_eq!(split.verify_against_content(content), Ok(()));
        assert_eq!(split.verify_blob_location(wire), Ok(()));
        assert_eq!(
            split.verify_blob_location(content),
            Err(MemoryIndexError::BlobIdMismatch)
        );

        // Avalanche: different content ⇒ different address + hash.
        let other = record_over(b"hello walrut");
        assert_ne!(record.content_hash_32(), other.content_hash_32());
        assert_ne!(record.blob_id_32(), other.blob_id_32());
    }

    /// Bounds fail closed: importance caps at 10000 inclusive; content caps
    /// at `MAX_STAGE_B_CONTENT_BYTES` inclusive (both constructors).
    #[test]
    fn importance_and_content_caps_fail_closed() {
        let at_cap = MemoryIndexRecord::from_content(
            MemoryId::new(1),
            b"x",
            MAX_IMPORTANCE_SCORE,
            MemoryTier::Recent,
            true,
        );
        assert!(at_cap.is_ok());
        assert_eq!(
            MemoryIndexRecord::from_content(
                MemoryId::new(1),
                b"x",
                MAX_IMPORTANCE_SCORE + 1,
                MemoryTier::Recent,
                true,
            ),
            Err(MemoryIndexError::ImportanceOutOfRange)
        );

        let over = vec![0u8; MAX_STAGE_B_CONTENT_BYTES as usize + 1];
        assert_eq!(
            MemoryIndexRecord::from_content(MemoryId::new(1), &over, 0, MemoryTier::Recent, true),
            Err(MemoryIndexError::ContentTooLarge)
        );
        assert_eq!(
            MemoryIndexRecord::from_parts(
                MemoryId::new(1),
                &over,
                derive_walrus_blob_id(b"wire"),
                0,
                MemoryTier::Recent,
                true,
            ),
            Err(MemoryIndexError::ContentTooLarge)
        );
    }

    /// Tier and privacy semantics: all four tiers round-trip through the
    /// byte image; tombstone reads as tombstone; ONLY an explicit `0`
    /// is shareable; the unclassified default is private.
    #[test]
    fn tier_and_private_flags() {
        const { assert!(UNCLASSIFIED_IS_PRIVATE) };

        for tier in [
            MemoryTier::Recent,
            MemoryTier::Mid,
            MemoryTier::Ancient,
            MemoryTier::DeletedTombstone,
        ] {
            let record =
                MemoryIndexRecord::from_content(MemoryId::new(3), b"tiered", 0, tier, true)
                    .expect("valid");
            let back = MemoryIndexRecord::from_bytes(&record.to_bytes()).expect("decodes");
            assert_eq!(back.tier(), tier);
            assert_eq!(back.is_tombstone(), tier.is_tombstone());
        }

        let shared =
            MemoryIndexRecord::from_content(MemoryId::new(4), b"s", 0, MemoryTier::Recent, false)
                .expect("valid");
        assert!(!shared.is_private());
        let private = record_over(b"p");
        assert!(private.is_private());
        assert_eq!(private.memory_id().get(), 7);
    }

    fn rec(id: u64, tier: MemoryTier, private: bool) -> MemoryIndexRecord {
        let content = format!("memory body {id}");
        MemoryIndexRecord::from_content(MemoryId::new(id), content.as_bytes(), 100, tier, private)
            .expect("valid record")
    }

    /// List layer: tombstoned records never list (either tier
    /// mode); private records drop ONLY on the frontier-bound catalog; order
    /// is deterministic (input order).
    #[test]
    fn catalog_select_excludes_tombstones_always_private_only_frontier() {
        let records = [
            rec(1, MemoryTier::Recent, false),
            rec(2, MemoryTier::Mid, true),
            rec(3, MemoryTier::DeletedTombstone, false),
            rec(4, MemoryTier::DeletedTombstone, true),
            rec(5, MemoryTier::Ancient, true),
        ];

        let local: Vec<u64> = catalog_select(&records, false)
            .iter()
            .map(|r| r.memory_id().get())
            .collect();
        assert_eq!(local, [1, 2, 5], "local: tombstones out, private KEPT");

        let frontier: Vec<u64> = catalog_select(&records, true)
            .iter()
            .map(|r| r.memory_id().get())
            .collect();
        assert_eq!(frontier, [1], "frontier: tombstones AND private out");
    }

    /// Read layer, exhaustive over tier × private × frontier: a
    /// tombstone always denies; privacy denies only frontier-bound; a live
    /// shareable record always reads; missing id denies NotInIndex.
    #[test]
    fn read_select_gates_exhaustively() {
        let tiers = [
            MemoryTier::Recent,
            MemoryTier::Mid,
            MemoryTier::Ancient,
            MemoryTier::DeletedTombstone,
        ];
        for tier in tiers {
            for private in [false, true] {
                for frontier in [false, true] {
                    let records = [rec(10, tier, private)];
                    let got = read_select(&records, MemoryId::new(10), frontier);
                    let expect = if tier.is_tombstone() {
                        Err(MemoryReadDeny::Tombstoned)
                    } else if frontier && private {
                        Err(MemoryReadDeny::PrivateToFrontier)
                    } else {
                        Ok(())
                    };
                    assert_eq!(
                        got.map(|r| {
                            assert_eq!(r.memory_id().get(), 10);
                        }),
                        expect,
                        "tier={tier:?} private={private} frontier={frontier}"
                    );
                }
            }
        }

        assert_eq!(
            read_select(
                &[rec(10, MemoryTier::Recent, false)],
                MemoryId::new(11),
                false
            ),
            Err(MemoryReadDeny::NotInIndex)
        );
        // Stable diagnostic labels.
        assert_eq!(
            MemoryReadDeny::NotInIndex.class_label(),
            "memory_index.read_deny.not_in_index"
        );
        assert_eq!(
            MemoryReadDeny::Tombstoned.class_label(),
            "memory_index.read_deny.tombstoned"
        );
        assert_eq!(
            MemoryReadDeny::PrivateToFrontier.class_label(),
            "memory_index.read_deny.private_to_frontier"
        );
    }

    // ---- fold + cache image -----------------------------------------------

    fn chunk_of(id: u64, content: &[u8]) -> MemoryChunk {
        use mnemos_c_walrus::codec::{ChunkEnvelopeV1, ChunkKind, MemoryRole};
        MemoryChunk::new(
            MemoryId::new(id),
            ChunkEnvelopeV1 {
                kind: ChunkKind::UserMessage,
                role: MemoryRole::User,
                parent: None,
                content: content.to_vec(),
                embedding: None,
                signature: None,
                provenance: None,
            },
        )
    }

    fn encode_b64url(raw: &[u8; 32]) -> String {
        const ALPHABET: &[u8; 64] =
            b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
        let mut out = String::with_capacity(43);
        let mut buf: u32 = 0;
        let mut bits: u32 = 0;
        for &b in raw {
            buf = (buf << 8) | u32::from(b);
            bits += 8;
            while bits >= 6 {
                bits -= 6;
                let v = ((buf >> bits) & 0x3F) as usize;
                out.push(ALPHABET[v] as char);
            }
        }
        if bits > 0 {
            let v = ((buf << (6 - bits)) & 0x3F) as usize;
            out.push(ALPHABET[v] as char);
        }
        out
    }

    fn verified_blob(seed: &[u8]) -> mnemos_c_walrus::VerifiedBlobId {
        use mnemos_c_walrus::{PublisherReportedBlobId, derive_blob_id, verify_reported_blob_id};
        let derived = derive_blob_id(seed);
        let text = encode_b64url(derived.as_bytes());
        let reported = PublisherReportedBlobId::try_from_text(&text).expect("43-char base64url");
        verify_reported_blob_id(seed, &reported).expect("self-derived round-trip verifies")
    }

    /// The fold is a pure deterministic projection: same chunks + same
    /// delete truth ⇒ bit-identical records; fields project per the
    /// projection choices (scored importance, fail-closed private via the
    /// unclassified wrapper, tombstone tier from the delete truth) and
    /// `catalog_select` then excludes the tombstone (the retrieval chain).
    #[test]
    fn fold_is_deterministic_and_projects_fields() {
        let chunks = [chunk_of(1, b"hello"), chunk_of(2, b"world")];
        let mut policy = TombstonePolicy::new();
        policy.record(
            MemoryId::new(2),
            crate::intelligence::DeleteSemantics::Tombstone,
        );

        let a = fold_index(&chunks, &policy);
        let b = fold_index(&chunks, &policy);
        assert_eq!(a, b, "fold is deterministic");
        assert_eq!(a.records.len(), 2);
        assert_eq!(a.skipped_integrity_u32, 0);
        assert_eq!(a.skipped_invalid_u32, 0);

        let r1 = &a.records[0];
        assert_eq!(r1.memory_id().get(), 1);
        assert_eq!(r1.tier(), MemoryTier::Recent);
        assert_eq!(
            r1.importance_u16(),
            4999,
            "scored: rank 1 of 2, len 5 ⇒ (50·9999 + 20·0)/100 (Python-pinned)"
        );
        assert!(r1.is_private(), "fail-closed unclassified default");
        assert_eq!(r1.verify_against_content(b"hello"), Ok(()));
        assert_eq!(r1.blob_id_32(), derive_walrus_blob_id(b"hello").as_bytes());

        let r2 = &a.records[1];
        assert_eq!(
            r2.tier(),
            MemoryTier::DeletedTombstone,
            "delete truth projects"
        );
        assert_eq!(r2.importance_u16(), 0, "tombstone scores the floor");

        // The folded tombstone never lists.
        let listed: Vec<u64> = catalog_select(&a.records, false)
            .iter()
            .map(|r| r.memory_id().get())
            .collect();
        assert_eq!(listed, [1]);
    }

    /// A chunk with a VERIFIED Walrus ref binds that location (the
    /// split binding: summary/hash over content, location over the published
    /// bytes); a ref violating the `walrus_primary` constructor invariant is
    /// fail-closed skipped and counted.
    #[test]
    fn fold_binds_verified_blob_and_skips_forged_ref() {
        use crate::chunk::StorageObjectRef;

        let published = b"the published blob bytes";
        let verified = verified_blob(published);
        let good_ref =
            StorageObjectRef::walrus_primary(*verified.as_blob_id().as_bytes(), verified);
        let good = chunk_of(1, b"readable content").with_storage(good_ref);

        let forged_ref = StorageObjectRef::walrus_primary([0xAA; 32], verified);
        let forged = chunk_of(2, b"other content").with_storage(forged_ref);

        let policy = TombstonePolicy::new();
        let outcome = fold_index([&good, &forged], &policy);

        assert_eq!(outcome.records.len(), 1);
        assert_eq!(outcome.skipped_integrity_u32, 1, "forged ref fail-closed");
        let record = &outcome.records[0];
        assert_eq!(record.blob_id_32(), verified.as_blob_id().as_bytes());
        assert_eq!(record.verify_against_content(b"readable content"), Ok(()));
        assert_eq!(record.verify_blob_location(published), Ok(()));
        assert_eq!(
            record.verify_blob_location(b"readable content"),
            Err(MemoryIndexError::BlobIdMismatch),
            "location binds the PUBLISHED bytes, not the readable content"
        );
    }

    /// The fold SCORES importance deterministically: exact fixed
    /// fixtures; appended-later never scores
    /// lower (ties allowed — the `/100` blend quantizes adjacent ranks); the
    /// length term raises a same-rank score; a re-fold reproduces identical
    /// scores bit for bit.
    #[test]
    fn fold_scores_importance_deterministically() {
        let chunks = [chunk_of(1, b"x"), chunk_of(2, b"y"), chunk_of(3, b"z")];
        let policy = TombstonePolicy::new();
        let a = fold_index(&chunks, &policy);
        let scores: Vec<u16> = a.records.iter().map(|r| r.importance_u16()).collect();
        assert_eq!(scores, [4999, 4999, 5000], "Python-pinned fixtures");
        // Non-strict recency monotonicity: newer (later input) ≥ older.
        assert!(scores.windows(2).all(|w| w[0] <= w[1]));

        // Length term: 250 bytes at rank 0 ⇒ (50·10000 + 20·25)/100 = 5005.
        let long_chunk = chunk_of(9, &[b'a'; 250]);
        let long = fold_index([&long_chunk], &policy);
        assert_eq!(long.records[0].importance_u16(), 5005);

        // Determinism: same input ⇒ bit-identical outcome (scores included).
        assert_eq!(fold_index(&chunks, &policy), a);
    }

    /// A tombstoned chunk scores the importance FLOOR 0 (the model
    /// fail-closed blocks deleted ids; a deleted memory has no importance),
    /// while its live sibling still scores.
    #[test]
    fn fold_tombstone_scores_zero() {
        let chunks = [chunk_of(1, &[b'a'; 250]), chunk_of(2, &[b'b'; 250])];
        let mut policy = TombstonePolicy::new();
        policy.record(
            MemoryId::new(1),
            crate::intelligence::DeleteSemantics::Tombstone,
        );
        let folded = fold_index(&chunks, &policy);
        assert_eq!(folded.records[0].importance_u16(), 0, "tombstone floor");
        assert!(
            folded.records[1].importance_u16() > 0,
            "live sibling scores"
        );
    }

    /// The classified fold projects the OWNER class per chunk; the
    /// unclassified wrapper stays all-private; and the privacy chain
    /// holds: ONLY the explicit shareable record lists frontier-bound.
    #[test]
    fn fold_classified_projects_owner_classes() {
        let c1 = chunk_of(1, b"shareable note");
        let c2 = chunk_of(2, b"private note");
        let policy = TombstonePolicy::new();

        let folded = fold_index_classified(
            [
                (&c1, MemoryPrivacy::Shareable),
                (&c2, MemoryPrivacy::Private),
            ],
            &policy,
        );
        assert!(!folded.records[0].is_private(), "explicit shareable");
        assert!(folded.records[1].is_private(), "explicit private");

        // The frontier catalog lists ONLY the explicit shareable record.
        let frontier: Vec<u64> = catalog_select(&folded.records, true)
            .iter()
            .map(|r| r.memory_id().get())
            .collect();
        assert_eq!(frontier, [1]);
        assert_eq!(
            catalog_select(&folded.records, false).len(),
            2,
            "the owner's local surface sees both"
        );

        // The unclassified wrapper projects PRIVATE for every chunk.
        let unclassified = fold_index([&c1, &c2], &policy);
        assert!(unclassified.records.iter().all(|r| r.is_private()));
    }

    /// MemoryPrivacy byte lock: the persisted tag values mirror the
    /// record's `private_u8` encoding exactly (`{0 shareable, 1 private}`);
    /// decode is fail-closed (any other byte is None); the DEFAULT is
    /// private.
    #[test]
    fn memory_privacy_tag_round_trip_and_fail_closed() {
        assert_eq!(MemoryPrivacy::Shareable.tag(), 0);
        assert_eq!(MemoryPrivacy::Private.tag(), 1);
        assert_eq!(MemoryPrivacy::from_tag(0), Some(MemoryPrivacy::Shareable));
        assert_eq!(MemoryPrivacy::from_tag(1), Some(MemoryPrivacy::Private));
        for bad in [2u8, 7, 255] {
            assert_eq!(MemoryPrivacy::from_tag(bad), None, "fail-closed decode");
        }
        assert_eq!(MemoryPrivacy::default(), MemoryPrivacy::Private);
        assert!(MemoryPrivacy::Private.is_private());
        assert!(!MemoryPrivacy::Shareable.is_private());
        // The enum value and the projected record byte agree by construction.
        assert_eq!(
            u8::from(MemoryPrivacy::Private.is_private()),
            MemoryPrivacy::Private.tag()
        );
        assert_eq!(
            u8::from(MemoryPrivacy::Shareable.is_private()),
            MemoryPrivacy::Shareable.tag()
        );
    }

    /// The cache image round-trips exactly; EVERY corruption class is a
    /// typed whole-image reject; and the recovery path holds: a failed
    /// decode re-folds from chunks to bit-identical records (the index is
    /// never a second source of truth).
    #[test]
    fn index_image_round_trip_rejects_corruption_and_recovers() {
        let chunks = [
            chunk_of(1, "첫 번째 기억".as_bytes()),
            chunk_of(2, b"second memory"),
        ];
        let policy = TombstonePolicy::new();
        let folded = fold_index(&chunks, &policy);
        let image = index_to_bytes(&folded.records);
        assert_eq!(
            image.len(),
            INDEX_IMAGE_HEADER_BYTES + 2 * MEMORY_INDEX_RECORD_BYTES + INDEX_IMAGE_HASH_BYTES
        );
        assert_eq!(index_from_bytes(&image), Ok(folded.records.clone()));

        // Empty image round-trips too.
        let empty = index_to_bytes(&[]);
        assert_eq!(index_from_bytes(&empty), Ok(Vec::new()));

        // Bit corruption inside a record -> integrity hash catches it first.
        let mut flipped = image.clone();
        flipped[INDEX_IMAGE_HEADER_BYTES + 100] ^= 0x01;
        assert_eq!(
            index_from_bytes(&flipped),
            Err(IndexImageError::IntegrityHashMismatch)
        );

        // Same corruption with a RECOMPUTED trailing hash -> the per-record
        // validation catches it (summary padding violated in record 0).
        let mut resealed = image.clone();
        resealed[INDEX_IMAGE_HEADER_BYTES + OFFSET_SUMMARY + 200] = 0x07;
        let payload_len = resealed.len() - INDEX_IMAGE_HASH_BYTES;
        let new_hash = *ContentHash32::of(&resealed[..payload_len]).as_bytes();
        resealed[payload_len..].copy_from_slice(&new_hash);
        assert_eq!(
            index_from_bytes(&resealed),
            Err(IndexImageError::Record {
                index_u32: 0,
                error: MemoryIndexError::SummaryPaddingNonZero,
            })
        );

        // Bad magic / too short / count-body mismatch.
        let mut bad_magic = image.clone();
        bad_magic[0] ^= 0xFF;
        assert_eq!(index_from_bytes(&bad_magic), Err(IndexImageError::BadMagic));
        assert_eq!(
            index_from_bytes(&image[..INDEX_IMAGE_HEADER_BYTES + 3]),
            Err(IndexImageError::TooShort)
        );
        let mut wrong_count = image.clone();
        wrong_count[INDEX_IMAGE_MAGIC.len()..INDEX_IMAGE_HEADER_BYTES]
            .copy_from_slice(&9u32.to_le_bytes());
        let payload_len = wrong_count.len() - INDEX_IMAGE_HASH_BYTES;
        let new_hash = *ContentHash32::of(&wrong_count[..payload_len]).as_bytes();
        wrong_count[payload_len..].copy_from_slice(&new_hash);
        assert_eq!(
            index_from_bytes(&wrong_count),
            Err(IndexImageError::LengthMismatch)
        );

        // RECOVERY: every decode failure above degrades to a
        // cache miss — re-folding the chunks reproduces the records exactly.
        let refolded = fold_index(&chunks, &policy);
        assert_eq!(refolded.records, folded.records);
        let refolded_image = index_to_bytes(&refolded.records);
        assert_eq!(refolded_image, image, "image itself is deterministic");

        // Stable diagnostic labels.
        assert_eq!(
            IndexImageError::TooShort.class_label(),
            "memory_index.image.too_short"
        );
        assert_eq!(
            IndexImageError::Record {
                index_u32: 0,
                error: MemoryIndexError::SummaryPaddingNonZero,
            }
            .class_label(),
            "memory_index.image.record_invalid"
        );
    }
}
