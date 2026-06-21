//! Stage B chunk tag enums (atom #83 · B.1.2).
//!
//! Stage B does **not** mint a new chunk wire format. The on-the-wire chunk
//! schema is Stage A's [`ChunkEnvelopeV1`](mnemos_c_walrus::ChunkEnvelopeV1),
//! and its tag set — [`ChunkKind`], [`MemoryRole`] — together with the
//! publisher payload classifier [`PublishPayloadClass`] are reused **verbatim**
//! from `c-walrus`. This module re-exports those three Stage A enums so the
//! downstream Stage B chunk surface (`StageBChunkHeaderV1` at atom #84,
//! `StageBChunkView` at atom #85, …) names them through one Stage B path, and
//! it adds exactly one Stage-B-owned tag enum on top: [`StageBChunkFlags`].
//!
//! # Madness invariants (`MNEMOS_STAGE_B_ATOM_PLAN.md` §4.1 / atom #83)
//!
//! * **No new wire tag.** The chunk kind/role tags stay Stage A's. Stage B adds
//!   only a *flags/policy* byte; it never introduces a competing wire tag set.
//!   Unknown / reserved tags are rejected by Stage A's codec
//!   ([`ChunkKind::from_tag`] / [`MemoryRole::from_tag`] return
//!   [`ChunkCodecError::UnknownKind`](mnemos_c_walrus::ChunkCodecError::UnknownKind)
//!   / `UnknownRole`); Stage B reuses that reject **as-is** rather than
//!   re-deriving it.
//! * **Flags are a bounded bitset.** [`StageBChunkFlags`] enumerates the four
//!   V1 flag values (`None`/`HasParent`/`HasAuditLink`/`SealStubbed`). A raw
//!   `flags_u8` bitset is valid iff every set bit is inside
//!   [`StageBChunkFlags::VALID_MASK_U8`]; any reserved bit is rejected
//!   fail-closed by [`StageBChunkFlags::validate_flag_bits`].
//! * **Reject is a predicate, not an invented canonical error.** §4.1 declares
//!   a `StageBChunkError` whose variants (`ContentTooLarge` / `SignatureInvalid`
//!   / `PublishClassDenied` / `NonCanonicalAChunk`) belong to the later content-
//!   cap / signature / publish atoms. Minting that enum now — with four unused
//!   variants — would be premature, so the reserved-flag reject is expressed as
//!   an `Option` (`None` = rejected), mirroring the atom #81 (§4.0) and atom #82
//!   (§4.2) reject-as-predicate precedent. The full `StageBChunkError` is minted
//!   by the atom that first owns its other variants.
//!
//! # Reuse map (atom contract)
//!
//! * **reuse: A #7 [`ChunkKind`] / [`MemoryRole`]** — chunk kind/role wire tags,
//!   re-exported, not redefined.
//! * **reuse: A #8 [`PublishPayloadClass`]** — content classifier, re-exported.
//!   Stage A provides no `from_tag` reverse map for it (only `tag()` /
//!   `class_label()`); Stage B does **not** invent one here (no A extension from
//!   `b-memory`), so the "unknown tag reject" invariant is reused only through
//!   `ChunkKind` / `MemoryRole`, which do carry a fail-closed `from_tag`.
//! * **reuse: #82 network boundary** — `StageBNetwork` (the testnet typed guard)
//!   is the live-network sibling; this atom is a pure tag/flag surface with zero
//!   external action, so it consumes no network value (the network enters the
//!   Walrus/Sui plans at #101+).

#[doc(no_inline)]
pub use mnemos_c_walrus::{ChunkKind, MemoryRole, PublishPayloadClass};

use crate::stage_b_handoff::StageBTraceLink;
use mnemos_c_walrus::{BlobId, ChunkEnvelopeV1};
use mnemos_d_move::SuiAddress;

/// Stage-B-owned chunk flag bits layered on top of Stage A's chunk wire.
///
/// The four values are bit positions in a `flags_u8` bitset: `None` is the
/// empty set, and the three positive flags occupy bits `0`/`1`/`2`. They are
/// the only flag bits the Stage B V1 schema defines; a `flags_u8` byte with any
/// other bit set carries *reserved* bits and is rejected (see
/// [`StageBChunkFlags::validate_flag_bits`]).
///
/// `#[repr(u8)]` with explicit discriminants so the byte values are stable for
/// the chunk header wire form introduced at atom #84 (mirrors the atom #81
/// `Evidence*Class` and atom #82 `StageBNetwork` byte-stable enums).
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
#[repr(u8)]
pub enum StageBChunkFlags {
    /// No flags set — the empty bitset (`0`).
    None = 0,
    /// The chunk declares a parent blob (its `ChunkEnvelopeV1.parent` is
    /// `Some`). Parent provides integrity linkage only; it does not impose a
    /// replay order (atom #88 madness spec).
    HasParent = 1,
    /// The chunk is linked into the owner's append-only audit log.
    HasAuditLink = 2,
    /// The chunk's payload is wrapped by the Seal **stub** (no real encryption;
    /// the name must never imply confidentiality — atom #4.4 invariant).
    SealStubbed = 4,
}

impl StageBChunkFlags {
    /// Bit-union of every flag the V1 schema defines (`0b0000_0111`). A
    /// `flags_u8` byte with any bit outside this mask carries reserved bits and
    /// is rejected by [`validate_flag_bits`](Self::validate_flag_bits).
    pub const VALID_MASK_U8: u8 =
        Self::HasParent as u8 | Self::HasAuditLink as u8 | Self::SealStubbed as u8;

    /// Stable `u8` tag — mirrors the `#[repr(u8)]` discriminant.
    #[inline]
    pub const fn tag(self) -> u8 {
        self as u8
    }

    /// Reverse map a **single-flag** tag byte to its variant.
    ///
    /// Only the four declared discriminants (`0`/`1`/`2`/`4`) map to a variant.
    /// A combined bitset (e.g. `3` = `HasParent | HasAuditLink`) is not a single
    /// flag and yields `None`; a reserved value (e.g. `8`) likewise yields
    /// `None`. Combined bitsets are validated as a whole by
    /// [`validate_flag_bits`](Self::validate_flag_bits), not by this reverse map.
    #[inline]
    pub const fn from_tag(tag: u8) -> Option<Self> {
        match tag {
            0 => Some(Self::None),
            1 => Some(Self::HasParent),
            2 => Some(Self::HasAuditLink),
            4 => Some(Self::SealStubbed),
            _ => None,
        }
    }

    /// Validate a raw `flags_u8` bitset: accept iff every set bit lies inside
    /// [`VALID_MASK_U8`](Self::VALID_MASK_U8), rejecting any reserved bit
    /// fail-closed.
    ///
    /// Returns `Some(raw)` (the byte unchanged) on accept and `None` on any
    /// reserved bit. `None` carries no data, so a rejected byte's reserved bits
    /// are not surfaced as a new canonical error here — the reject is a
    /// predicate, mirroring the atom #81/#82 precedent. §4.1's
    /// `StageBChunkError::ReservedFlags` is minted by the later atom that owns
    /// the full chunk-error surface and can map this `None` onto it at that
    /// boundary.
    #[inline]
    pub const fn validate_flag_bits(raw: u8) -> Option<u8> {
        if raw & !Self::VALID_MASK_U8 != 0 {
            None
        } else {
            Some(raw)
        }
    }

    /// Whether `flag` is present in a `flags_u8` bitset.
    ///
    /// Tests the positive flags (`HasParent` / `HasAuditLink` / `SealStubbed`).
    /// Querying [`StageBChunkFlags::None`] (the empty set, value `0`) always
    /// returns `false` — "is the empty set present" is not a meaningful
    /// membership test; callers ask about the three positive flags.
    #[inline]
    pub const fn is_set(bits: u8, flag: StageBChunkFlags) -> bool {
        let f = flag as u8;
        f != 0 && (bits & f) == f
    }
}

// ===========================================================================
// StageBChunkHeaderV1 — fixed chunk header (atom #84 · B.1.3)
// ===========================================================================

/// Stage B chunk schema version carried in [`StageBChunkHeaderV1::schema_version_u8`].
///
/// §4.1 lists this const inside the signed-chunk-schema block; the header is
/// its first and defining consumer, so it is minted here at atom #84 (the
/// `from_tag`-style reverse map and the full chunk codec — `encode_stage_b_chunk`
/// / `decode_stage_b_chunk` — remain Stage A's wire and arrive at later atoms).
/// Stage B does not mint a new chunk *wire* format; this byte only versions the
/// Stage-B-owned ownership/replay header that wraps Stage A's `ChunkEnvelopeV1`.
pub const STAGE_B_CHUNK_SCHEMA_V1: u8 = 1;

/// Fixed serialized length, in bytes, of a [`StageBChunkHeaderV1`] produced by
/// [`StageBChunkHeaderV1::to_bytes`].
///
/// The header is **content-free**: its encoded length is constant regardless of
/// `content_len_u32`, so the ownership + replay boundary (owner / parent / trace)
/// is visible without ever materializing the chunk body. Layout (little-endian,
/// matching Stage A's `c-walrus` fixed-width wire convention):
///
/// | offset | width | field |
/// |--------|-------|-------|
/// | 0      | 1     | `schema_version_u8` |
/// | 1      | 1     | `kind` tag |
/// | 2      | 1     | `role` tag |
/// | 3      | 1     | `content_class` tag |
/// | 4      | 1     | `flags_u8` |
/// | 5      | 4     | `content_len_u32` (LE) |
/// | 9      | 32    | `owner` (Sui address bytes) |
/// | 41     | 1     | parent present tag (`0`/`1`) |
/// | 42     | 32    | parent blob id (all-zero when absent) |
/// | 74     | 8     | `trace.trace_id_u64` (LE) |
/// | 82     | 2     | `trace.atom_id_u16` (LE) |
/// | 84     | 1     | `trace.attempt_u8` |
///
/// Total `1+1+1+1+1+4+32+1+32+8+2+1 = 85`.
pub const STAGE_B_CHUNK_HEADER_ENCODED_LEN: usize = 85;

/// The fixed chunk header: everything a verifier needs to see a chunk's
/// ownership and replay boundary **without** the content body.
///
/// Stage B does not mint a new chunk wire format — the body still rides Stage
/// A's [`ChunkEnvelopeV1`](mnemos_c_walrus::ChunkEnvelopeV1). This header is the
/// Stage-B-owned envelope *around* that wire: it pins the schema version, the
/// reused Stage A kind/role/content-class tags, the validated flag bitset, the
/// declared content length, the owning [`SuiAddress`], the optional parent
/// [`BlobId`], and the [`StageBTraceLink`] replay stamp.
///
/// # Invariants (constructed via [`new`](Self::new), fail-closed)
///
/// * **Reserved-flag reject.** `flags_u8` must pass
///   [`StageBChunkFlags::validate_flag_bits`] — any reserved bit ⇒ rejected.
/// * **Parent flag consistency.** The [`StageBChunkFlags::HasParent`] bit is set
///   in `flags_u8` **iff** `parent` is `Some`. A header that claims a parent it
///   does not carry (or carries a parent without the flag) is rejected.
/// * **Trace required.** `trace` is a non-optional [`StageBTraceLink`]; every
///   header is stamped, so the evidence trail can never be detached from a
///   header by construction.
///
/// `new` returns `Option<Self>` (`None` = rejected) rather than a minted
/// `StageBChunkError`: §4.1's full error enum belongs to the content-cap /
/// signature / publish atoms, and reject-as-predicate mirrors the atom
/// #81/#82/#83 precedent. The later atom owning `StageBChunkError::ReservedFlags`
/// maps this `None` onto it at that boundary.
///
/// The public fields mirror the §4.1 canonical declaration; `new` is the
/// validated construction path (a raw struct literal bypasses the invariants,
/// exactly as for Stage A's `ChunkEnvelopeV1`).
///
/// `Hash` is intentionally **not** derived: the reused Stage A `ChunkKind` /
/// `MemoryRole` tags do not implement `Hash`, and minting `Hash` for them from
/// `b-memory` would extend a Stage A canonical (reuse-lock violation). The
/// header carries `Copy + Eq + PartialEq + Debug`, which is all the schema
/// surface needs.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct StageBChunkHeaderV1 {
    /// Stage B chunk schema version. [`new`](Self::new) always sets this to
    /// [`STAGE_B_CHUNK_SCHEMA_V1`].
    pub schema_version_u8: u8,
    /// Reused Stage A chunk kind wire tag (no new wire tag minted).
    pub kind: ChunkKind,
    /// Reused Stage A speaker/authoring role wire tag.
    pub role: MemoryRole,
    /// Reused Stage A publisher payload classifier (only
    /// `SyntheticPublicFixture` is admissible onto the public testnet — that
    /// policy is enforced at the publish atom, not here).
    pub content_class: PublishPayloadClass,
    /// Validated flag bitset (every set bit inside
    /// [`StageBChunkFlags::VALID_MASK_U8`]).
    pub flags_u8: u8,
    /// Declared length of the chunk body. The header itself carries **no** body
    /// bytes; this is the length the body *will* have on Stage A's wire.
    pub content_len_u32: u32,
    /// The owning Sui account — reused Stage A [`SuiAddress`], not a second
    /// address newtype.
    pub owner: SuiAddress,
    /// Optional parent blob id for integrity linkage. Presence must agree with
    /// the [`StageBChunkFlags::HasParent`] bit (see invariants).
    pub parent: Option<BlobId>,
    /// Per-action replay/evidence stamp.
    pub trace: StageBTraceLink,
}

impl StageBChunkHeaderV1 {
    /// Construct a fixed chunk header, enforcing the fail-closed invariants
    /// (reserved-flag reject + parent flag consistency). Returns `None` on any
    /// violation. `schema_version_u8` is set to [`STAGE_B_CHUNK_SCHEMA_V1`].
    #[allow(clippy::too_many_arguments)]
    #[inline]
    pub fn new(
        kind: ChunkKind,
        role: MemoryRole,
        content_class: PublishPayloadClass,
        flags_u8: u8,
        content_len_u32: u32,
        owner: SuiAddress,
        parent: Option<BlobId>,
        trace: StageBTraceLink,
    ) -> Option<Self> {
        // Reserved-flag reject (reuse atom #83 fail-closed validator).
        StageBChunkFlags::validate_flag_bits(flags_u8)?;
        // Parent flag consistency: HasParent bit set iff a parent is carried.
        if StageBChunkFlags::is_set(flags_u8, StageBChunkFlags::HasParent) != parent.is_some() {
            return None;
        }
        Some(Self {
            schema_version_u8: STAGE_B_CHUNK_SCHEMA_V1,
            kind,
            role,
            content_class,
            flags_u8,
            content_len_u32,
            owner,
            parent,
            trace,
        })
    }

    /// Serialize the content-free header to its fixed
    /// [`STAGE_B_CHUNK_HEADER_ENCODED_LEN`]-byte form (little-endian; layout
    /// documented on that const).
    ///
    /// Allocation-free: the output is a stack array, so there is **zero heap
    /// allocation** per encode (the atom #84 `alloc=0` criterion; the throughput
    /// bench is the atom #85 `G-B-BENCH` follow-on). The encoded length is
    /// constant, so the ownership/replay boundary is observable without the
    /// chunk body.
    #[inline]
    pub const fn to_bytes(&self) -> [u8; STAGE_B_CHUNK_HEADER_ENCODED_LEN] {
        let mut out = [0u8; STAGE_B_CHUNK_HEADER_ENCODED_LEN];
        out[0] = self.schema_version_u8;
        out[1] = self.kind.tag();
        out[2] = self.role.tag();
        out[3] = self.content_class.tag();
        out[4] = self.flags_u8;

        let len = self.content_len_u32.to_le_bytes();
        out[5] = len[0];
        out[6] = len[1];
        out[7] = len[2];
        out[8] = len[3];

        let owner = self.owner.as_bytes();
        let mut i = 0;
        while i < 32 {
            out[9 + i] = owner[i];
            i += 1;
        }

        match self.parent {
            Some(parent) => {
                out[41] = 1;
                let pb = parent.as_bytes();
                let mut j = 0;
                while j < 32 {
                    out[42 + j] = pb[j];
                    j += 1;
                }
            }
            // None: parent-present tag stays 0 and bytes 42..74 stay zero.
            None => out[41] = 0,
        }

        let tid = self.trace.trace_id_u64.to_le_bytes();
        let mut k = 0;
        while k < 8 {
            out[74 + k] = tid[k];
            k += 1;
        }
        let aid = self.trace.atom_id_u16.to_le_bytes();
        out[82] = aid[0];
        out[83] = aid[1];
        out[84] = self.trace.attempt_u8;

        out
    }
}

// ===========================================================================
// StageBChunkView + content cap (atom #85 · B.1.4)
// ===========================================================================

/// Stage B per-chunk content-size policy cap, in bytes (`1_048_576` = 1 MiB).
///
/// This is a *Stage B policy* cap, deliberately **tighter** than Stage A's
/// wire-level [`MAX_CONTENT_BYTES`](mnemos_c_walrus::codec::MAX_CONTENT_BYTES)
/// (`13_000_000`). A [`StageBChunkView`] whose borrowed envelope carries more
/// than this many content bytes is rejected at view construction — *before* any
/// Stage A codec call (`encode_chunk_v1`) could `Vec::with_capacity` the body
/// (atom #85 madness spec). The value `1_048_576 = 2^20` fits in a `u32` and is
/// the boundary the header's `content_len_u32` is validated against.
pub const MAX_STAGE_B_CONTENT_BYTES: u32 = 1_048_576;

/// A borrowed pairing of a validated [`StageBChunkHeaderV1`] with the Stage A
/// [`ChunkEnvelopeV1`](mnemos_c_walrus::ChunkEnvelopeV1) it describes.
///
/// The envelope is held by **shared borrow** (`&'a ChunkEnvelopeV1`): the view
/// never clones the body, so constructing and inspecting a view is
/// allocation-free (the atom #85 `alloc/op = 0` criterion). Stage B does not
/// mint a new chunk wire — the body still rides Stage A's envelope; this view is
/// the zero-copy lens a digest / signer pass (atom #86+) reads through.
///
/// # Invariants (constructed via [`new`](Self::new), fail-closed)
///
/// * **Content cap.** The borrowed `envelope.content` length must be
///   `<= MAX_STAGE_B_CONTENT_BYTES`. An oversized body is rejected here, before
///   any Stage A codec allocation — the view only borrows, so the reject costs
///   no heap.
/// * **Declared length truthful.** `header.content_len_u32` must equal the
///   borrowed `envelope.content.len()`. The header may not claim a body length
///   different from the one it lenses, so the cap reads identically off the
///   header or the body.
///
/// Cross-validation of the header's `kind` / `role` / `parent` against the
/// envelope's is **not** performed here: that binding is the domain of the chunk
/// *digest* (atom #86, `stage_b_chunk_digest`), which hashes header and envelope
/// together. This atom owns only the borrowed lens + the content cap.
///
/// `new` returns `Option<Self>` (`None` = rejected) — reject-as-predicate,
/// mirroring atoms #81–#84. §4.1's `StageBChunkError::ContentTooLarge` is minted
/// by the later atom that owns the full chunk-error surface and maps this `None`
/// onto it at that boundary.
///
/// `Copy` is derivable because the view holds only a `Copy`
/// [`StageBChunkHeaderV1`] and a shared reference (`&ChunkEnvelopeV1`, itself
/// `Copy`); copying a view never copies the borrowed body.
#[derive(Clone, Copy, Debug)]
pub struct StageBChunkView<'a> {
    /// The validated Stage B header describing the borrowed chunk.
    pub header: StageBChunkHeaderV1,
    /// The borrowed Stage A chunk envelope (body + wire fields). Shared borrow:
    /// no copy of the content body is ever made by this view.
    pub envelope: &'a ChunkEnvelopeV1,
}

impl<'a> StageBChunkView<'a> {
    /// Pair a validated header with the borrowed envelope it describes,
    /// enforcing the content-cap + declared-length invariants fail-closed.
    /// Returns `None` on any violation.
    ///
    /// The content-cap check reads `envelope.content.len()` and rejects an
    /// oversized body **before** returning a view — and therefore before any
    /// caller could hand the borrowed envelope to a Stage A codec
    /// (`encode_chunk_v1`) that would `Vec::with_capacity` the body. The view
    /// itself allocates nothing.
    #[inline]
    pub fn new(header: StageBChunkHeaderV1, envelope: &'a ChunkEnvelopeV1) -> Option<Self> {
        let content_len = envelope.content.len();
        // Content cap (the atom #85 named behavior): reject oversized bodies
        // before any Stage A codec allocation.
        if content_len > MAX_STAGE_B_CONTENT_BYTES as usize {
            return None;
        }
        // Declared length truthful: the header's content_len_u32 must equal the
        // borrowed body length. `content_len <= MAX` here, so it fits a `u32`
        // and the widening cast on the header field is exact.
        if header.content_len_u32 as usize != content_len {
            return None;
        }
        Some(Self { header, envelope })
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    #![allow(clippy::expect_used)]
    #![allow(clippy::panic)]

    use super::*;
    use mnemos_c_walrus::ChunkCodecError;

    /// `b1_2_flag_tag_roundtrip` — every `StageBChunkFlags` variant survives a
    /// `tag()` → `from_tag()` round trip, and the reused Stage A tag enums
    /// (`ChunkKind` / `MemoryRole`) round-trip through their own `from_tag`. The
    /// reused `PublishPayloadClass` exposes only `tag()` in Stage A (no reverse
    /// map), so its byte tags are asserted directly rather than round-tripped.
    #[test]
    fn b1_2_flag_tag_roundtrip() {
        for f in [
            StageBChunkFlags::None,
            StageBChunkFlags::HasParent,
            StageBChunkFlags::HasAuditLink,
            StageBChunkFlags::SealStubbed,
        ] {
            assert_eq!(StageBChunkFlags::from_tag(f.tag()), Some(f));
        }
        // Discriminants are exactly the §4.1 byte values.
        assert_eq!(StageBChunkFlags::None.tag(), 0);
        assert_eq!(StageBChunkFlags::HasParent.tag(), 1);
        assert_eq!(StageBChunkFlags::HasAuditLink.tag(), 2);
        assert_eq!(StageBChunkFlags::SealStubbed.tag(), 4);

        // Reused Stage A kind/role tags round-trip through A's own codec.
        for k in [
            ChunkKind::UserMessage,
            ChunkKind::AssistantMessage,
            ChunkKind::SystemMemory,
            ChunkKind::ToolResult,
            ChunkKind::SkillArtifact,
        ] {
            assert_eq!(ChunkKind::from_tag(k.tag()), Ok(k));
        }
        for r in [
            MemoryRole::User,
            MemoryRole::Assistant,
            MemoryRole::System,
            MemoryRole::Tool,
            MemoryRole::Agent,
        ] {
            assert_eq!(MemoryRole::from_tag(r.tag()), Ok(r));
        }
        // PublishPayloadClass: reused as-is; assert its byte tag is the expected
        // §4.C value (no `from_tag` exists in Stage A, and none is invented).
        assert_eq!(PublishPayloadClass::SyntheticPublicFixture.tag(), 1);
    }

    /// `b1_2_unknown_tag_rejected` — the "unknown tag reject" invariant. Stage
    /// A's codec rejects unknown kind/role tags fail-closed, and Stage B reuses
    /// that reject as-is; `StageBChunkFlags::from_tag` rejects any byte that is
    /// not one of the four declared single-flag discriminants (including a
    /// combined bitset like `3`).
    #[test]
    fn b1_2_unknown_tag_rejected() {
        for bad in [0u8, 6, 7, 200, 255] {
            assert!(
                matches!(ChunkKind::from_tag(bad), Err(ChunkCodecError::UnknownKind { tag }) if tag == bad),
                "ChunkKind tag {bad} must be rejected as UnknownKind",
            );
            assert!(
                matches!(MemoryRole::from_tag(bad), Err(ChunkCodecError::UnknownRole { tag }) if tag == bad),
                "MemoryRole tag {bad} must be rejected as UnknownRole",
            );
        }
        // A combined bitset and reserved values are not single-flag tags.
        for not_a_single_flag in [3u8, 5, 6, 7, 8, 16, 255] {
            assert_eq!(
                StageBChunkFlags::from_tag(not_a_single_flag),
                None,
                "byte {not_a_single_flag} is not a single StageBChunkFlags variant",
            );
        }
    }

    /// `b1_2_reserved_flag_bits_rejected` — the "reserved flag reject"
    /// invariant. Every bitset whose bits all lie inside `VALID_MASK_U8`
    /// (`0..=7`) is accepted unchanged; any byte with a reserved bit (bit 3 or
    /// higher) is rejected fail-closed.
    #[test]
    fn b1_2_reserved_flag_bits_rejected() {
        assert_eq!(StageBChunkFlags::VALID_MASK_U8, 0b0000_0111);
        // All in-mask bitsets accepted, byte preserved.
        for ok in 0u8..=StageBChunkFlags::VALID_MASK_U8 {
            assert_eq!(StageBChunkFlags::validate_flag_bits(ok), Some(ok));
        }
        // Any reserved bit (>= bit 3) rejected.
        for bad in [
            0b0000_1000u8, // bit 3
            0b0001_0000,
            0b1000_0000,
            0b1000_0001, // valid bit + reserved bit ⇒ still rejected
            0b0000_1111, // 0b0111 valid bits + bit 3 reserved
            255,
        ] {
            assert_eq!(
                StageBChunkFlags::validate_flag_bits(bad),
                None,
                "flags byte {bad:#010b} has reserved bits and must be rejected",
            );
        }
    }

    /// `b1_2_flag_bitset_semantics` — `is_set` membership over a combined
    /// bitset, and the empty-set (`None`) query convention.
    #[test]
    fn b1_2_flag_bitset_semantics() {
        let bits = StageBChunkFlags::HasParent as u8 | StageBChunkFlags::SealStubbed as u8; // 0b0000_0101
        assert!(StageBChunkFlags::is_set(bits, StageBChunkFlags::HasParent));
        assert!(StageBChunkFlags::is_set(
            bits,
            StageBChunkFlags::SealStubbed
        ));
        assert!(!StageBChunkFlags::is_set(
            bits,
            StageBChunkFlags::HasAuditLink
        ));
        // The empty-set query is always false (documented convention).
        assert!(!StageBChunkFlags::is_set(bits, StageBChunkFlags::None));
        assert!(!StageBChunkFlags::is_set(0, StageBChunkFlags::None));
        // A validated full-mask bitset contains all three positive flags.
        let all = StageBChunkFlags::VALID_MASK_U8;
        assert_eq!(StageBChunkFlags::validate_flag_bits(all), Some(all));
        assert!(StageBChunkFlags::is_set(all, StageBChunkFlags::HasParent));
        assert!(StageBChunkFlags::is_set(
            all,
            StageBChunkFlags::HasAuditLink
        ));
        assert!(StageBChunkFlags::is_set(all, StageBChunkFlags::SealStubbed));
    }

    /// `b1_3_header_size_bounded` — the fixed header encodes to a constant
    /// [`STAGE_B_CHUNK_HEADER_ENCODED_LEN`] bytes regardless of the declared
    /// `content_len_u32`, proving the header is content-free (the ownership /
    /// replay boundary is visible without the chunk body).
    #[test]
    fn b1_3_header_size_bounded() {
        assert_eq!(STAGE_B_CHUNK_HEADER_ENCODED_LEN, 85);
        let owner = SuiAddress::new([0u8; 32]);
        let trace = StageBTraceLink::new(7, 84, 0);
        let empty = StageBChunkHeaderV1::new(
            ChunkKind::UserMessage,
            MemoryRole::User,
            PublishPayloadClass::SyntheticPublicFixture,
            StageBChunkFlags::None as u8,
            0,
            owner,
            None,
            trace,
        )
        .expect("genesis header valid");
        assert_eq!(empty.schema_version_u8, STAGE_B_CHUNK_SCHEMA_V1);
        assert_eq!(empty.to_bytes().len(), STAGE_B_CHUNK_HEADER_ENCODED_LEN);

        // A 1 MiB-declared body encodes to the same 85 bytes as an empty one —
        // the header never carries the body.
        let large = StageBChunkHeaderV1::new(
            ChunkKind::UserMessage,
            MemoryRole::User,
            PublishPayloadClass::SyntheticPublicFixture,
            StageBChunkFlags::None as u8,
            1_048_576,
            owner,
            None,
            trace,
        )
        .expect("large content_len header valid");
        assert_eq!(large.to_bytes().len(), STAGE_B_CHUNK_HEADER_ENCODED_LEN);
    }

    /// `b1_3_parent_flag_consistency` — the `HasParent` bit is set iff a parent
    /// blob is carried; any mismatch (or a reserved flag bit) is rejected
    /// fail-closed by [`StageBChunkHeaderV1::new`].
    #[test]
    fn b1_3_parent_flag_consistency() {
        let owner = SuiAddress::new([0x11; 32]);
        let trace = StageBTraceLink::new(1, 84, 0);
        let parent = BlobId([0xAB; 32]);
        let has_parent = StageBChunkFlags::HasParent as u8;
        let no_flags = StageBChunkFlags::None as u8;

        let mk = |flags: u8, parent: Option<BlobId>| {
            StageBChunkHeaderV1::new(
                ChunkKind::SystemMemory,
                MemoryRole::System,
                PublishPayloadClass::SyntheticPublicFixture,
                flags,
                10,
                owner,
                parent,
                trace,
            )
        };

        // Consistent: flag set + parent present; flag clear + parent absent.
        assert!(mk(has_parent, Some(parent)).is_some());
        assert!(mk(no_flags, None).is_some());
        // Inconsistent: flag set without a parent, or parent without the flag.
        assert!(mk(has_parent, None).is_none());
        assert!(mk(no_flags, Some(parent)).is_none());
        // Reserved flag bit (bit 3) rejected even with a consistent parent.
        assert!(mk(0b0000_1000, None).is_none());
        // The other valid flags (AuditLink / SealStubbed) are free to co-occur
        // with HasParent as long as the parent is present.
        assert!(mk(StageBChunkFlags::VALID_MASK_U8, Some(parent)).is_some());
        // Full mask requires HasParent ⇒ a parent; absent ⇒ rejected.
        assert!(mk(StageBChunkFlags::VALID_MASK_U8, None).is_none());
    }

    /// `b1_3_trace_required` — every header carries a non-optional
    /// [`StageBTraceLink`]; it is stored verbatim and round-trips through the
    /// encoding at the documented little-endian offsets.
    #[test]
    fn b1_3_trace_required() {
        let owner = SuiAddress::new([0x22; 32]);
        let trace = StageBTraceLink::new(0xDEAD_BEEF_0000_1234, 84, 3);
        let h = StageBChunkHeaderV1::new(
            ChunkKind::ToolResult,
            MemoryRole::Tool,
            PublishPayloadClass::SyntheticPublicFixture,
            StageBChunkFlags::None as u8,
            42,
            owner,
            None,
            trace,
        )
        .expect("valid header");
        assert_eq!(h.trace, trace);

        let b = h.to_bytes();
        assert_eq!(
            u64::from_le_bytes(b[74..82].try_into().unwrap()),
            trace.trace_id_u64
        );
        assert_eq!(
            u16::from_le_bytes(b[82..84].try_into().unwrap()),
            trace.atom_id_u16
        );
        assert_eq!(b[84], trace.attempt_u8);
    }

    /// `b1_3_header_encode_layout` — the madness spec: ownership (owner) and
    /// replay boundary (parent + trace) are observable in the encoded header
    /// with **no** content body, at the documented offsets, deterministically.
    #[test]
    fn b1_3_header_encode_layout() {
        let owner = SuiAddress::new([0x33; 32]);
        let parent = BlobId([0x44; 32]);
        let trace = StageBTraceLink::new(9, 84, 1);
        let h = StageBChunkHeaderV1::new(
            ChunkKind::AssistantMessage,
            MemoryRole::Assistant,
            PublishPayloadClass::SyntheticPublicFixture,
            StageBChunkFlags::HasParent as u8,
            0x0102_0304,
            owner,
            Some(parent),
            trace,
        )
        .expect("valid header");
        let b = h.to_bytes();
        assert_eq!(b[0], STAGE_B_CHUNK_SCHEMA_V1);
        assert_eq!(b[1], ChunkKind::AssistantMessage.tag());
        assert_eq!(b[2], MemoryRole::Assistant.tag());
        assert_eq!(b[3], PublishPayloadClass::SyntheticPublicFixture.tag());
        assert_eq!(b[4], StageBChunkFlags::HasParent as u8);
        assert_eq!(u32::from_le_bytes(b[5..9].try_into().unwrap()), 0x0102_0304);
        assert_eq!(&b[9..41], owner.as_bytes());
        assert_eq!(b[41], 1); // parent present tag
        assert_eq!(&b[42..74], parent.as_bytes());

        // Absent parent ⇒ present tag 0 and a zeroed 32-byte parent slot.
        let genesis = StageBChunkHeaderV1::new(
            ChunkKind::AssistantMessage,
            MemoryRole::Assistant,
            PublishPayloadClass::SyntheticPublicFixture,
            StageBChunkFlags::None as u8,
            0,
            owner,
            None,
            trace,
        )
        .expect("valid genesis header");
        let gb = genesis.to_bytes();
        assert_eq!(gb[41], 0);
        assert_eq!(&gb[42..74], &[0u8; 32]);
        // Encoding is deterministic.
        assert_eq!(genesis.to_bytes(), gb);
    }

    // -----------------------------------------------------------------------
    // atom #85 · B.1.4 — borrowed chunk view + content cap
    // -----------------------------------------------------------------------

    /// Build a Stage A envelope with a `len`-byte body and otherwise minimal
    /// fields (no embedding / signature / provenance, genesis parent).
    fn env(kind: ChunkKind, role: MemoryRole, len: usize) -> ChunkEnvelopeV1 {
        ChunkEnvelopeV1 {
            kind,
            role,
            parent: None,
            content: vec![0u8; len],
            embedding: None,
            signature: None,
            provenance: None,
        }
    }

    /// Build a header whose `content_len_u32` matches a `len`-byte body.
    fn header_for(kind: ChunkKind, role: MemoryRole, len: u32) -> StageBChunkHeaderV1 {
        StageBChunkHeaderV1::new(
            kind,
            role,
            PublishPayloadClass::SyntheticPublicFixture,
            StageBChunkFlags::None as u8,
            len,
            SuiAddress::new([0x55; 32]),
            None,
            StageBTraceLink::new(85, 85, 0),
        )
        .expect("valid header")
    }

    /// `b1_4_borrowed_lifetime_smoke` — a view borrows its envelope (no body
    /// copy), exposes both the header and the borrowed envelope, and is `Copy`
    /// (it holds only a `Copy` header + a shared reference). The borrow is tied
    /// to the envelope's lifetime by construction.
    #[test]
    fn b1_4_borrowed_lifetime_smoke() {
        let e = env(ChunkKind::UserMessage, MemoryRole::User, 128);
        let h = header_for(ChunkKind::UserMessage, MemoryRole::User, 128);
        let view = StageBChunkView::new(h, &e).expect("within cap");

        // Header carried verbatim.
        assert_eq!(view.header, h);
        // Envelope borrowed — the view points at the *same* envelope (no copy
        // of the 128-byte body was made).
        assert!(core::ptr::eq(view.envelope, &e));
        assert_eq!(view.envelope.content.len(), 128);

        // A view is `Copy`: copying it copies only the header + the reference.
        let view2 = view;
        assert!(core::ptr::eq(view2.envelope, &e));
        assert_eq!(view2.envelope.content.len(), 128);
    }

    /// `b1_4_cap_edge` — the content cap is inclusive at exactly
    /// [`MAX_STAGE_B_CONTENT_BYTES`] and rejects one byte over; one byte under
    /// is accepted.
    #[test]
    fn b1_4_cap_edge() {
        assert_eq!(MAX_STAGE_B_CONTENT_BYTES, 1_048_576);
        let at = MAX_STAGE_B_CONTENT_BYTES as usize;

        // Exactly at the cap: accepted (inclusive boundary).
        let e_at = env(ChunkKind::SystemMemory, MemoryRole::System, at);
        let h_at = header_for(ChunkKind::SystemMemory, MemoryRole::System, at as u32);
        assert!(StageBChunkView::new(h_at, &e_at).is_some());

        // One byte under the cap: accepted.
        let e_under = env(ChunkKind::SystemMemory, MemoryRole::System, at - 1);
        let h_under = header_for(ChunkKind::SystemMemory, MemoryRole::System, (at - 1) as u32);
        assert!(StageBChunkView::new(h_under, &e_under).is_some());

        // One byte over the cap: rejected.
        let e_over = env(ChunkKind::SystemMemory, MemoryRole::System, at + 1);
        let h_over = header_for(ChunkKind::SystemMemory, MemoryRole::System, (at + 1) as u32);
        assert!(StageBChunkView::new(h_over, &e_over).is_none());
    }

    /// `b1_4_oversized_reject_before_allocation` — an oversized body is rejected
    /// at view construction, before any Stage A codec call (`encode_chunk_v1`)
    /// that would `Vec::with_capacity` for it. Also pins the declared-length
    /// invariant: a within-cap body whose length disagrees with the header's
    /// `content_len_u32` is rejected (the header may not lie about the body it
    /// lenses).
    #[test]
    fn b1_4_oversized_reject_before_allocation() {
        let over = MAX_STAGE_B_CONTENT_BYTES as usize + 1;
        let e_over = env(ChunkKind::ToolResult, MemoryRole::Tool, over);
        let h_over = header_for(ChunkKind::ToolResult, MemoryRole::Tool, over as u32);
        // Rejected at the view boundary — no `encode_chunk_v1` is ever called,
        // so no Stage A `Vec::with_capacity` for the oversized body occurs.
        assert!(StageBChunkView::new(h_over, &e_over).is_none());

        // Declared-length truthfulness: body is 20 bytes (within cap) but the
        // header claims 10 ⇒ rejected.
        let e_small = env(ChunkKind::ToolResult, MemoryRole::Tool, 20);
        let h_lies = header_for(ChunkKind::ToolResult, MemoryRole::Tool, 10);
        assert!(StageBChunkView::new(h_lies, &e_small).is_none());

        // The matching header (claims 20, body is 20) is accepted.
        let h_match = header_for(ChunkKind::ToolResult, MemoryRole::Tool, 20);
        assert!(StageBChunkView::new(h_match, &e_small).is_some());
    }
}
