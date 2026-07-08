//! BCS chunk envelope V1 codec for `c-walrus`.
//!
//! # Wire format (canonical, cross-language schema-locked)
//!
//! Encoded chunk = BCS-compatible byte string in field-declaration order:
//!
//! ```text
//! schema_version  : u8                                 (must equal SCHEMA_VERSION_V1)
//! kind            : ChunkKind                          (uleb128 variant index, 1 byte for tag <= 127)
//! role            : MemoryRole                         (uleb128)
//! reserved_flags  : u16 little-endian                  (must be 0 in V1)
//! parent          : Option<BlobId>                     (tag 0/1; if 1, 32 bytes)
//! content         : Vec<u8>                            (uleb128 len; cap MAX_CONTENT_BYTES, checked BEFORE alloc)
//! embedding       : Option<EmbeddingRefV1>             (tag 0/1; if 1, EMBEDDING_WIRE_BYTES = 36)
//! signature       : Option<SignaturePlaceholderV1>     (tag 0/1; if 1, SIGNATURE_WIRE_BYTES = 97)
//! provenance      : Option<ProvenanceRefV1>            (tag 0/1; if 1, PROVENANCE_WIRE_BYTES = 37)
//! ```
//!
//! `MIN_EMPTY_CHUNK_V1_BYTES = 10` (matches the pinned constant; all
//! Options None and `content.len() == 0`).
//!
//! # Invariants
//!
//! * **Body-cap before alloc.** `decode_chunk_v1` reads the canonical uleb128
//!   length prefix and validates `length <= MAX_CONTENT_BYTES` *before* any
//!   `Vec::with_capacity(length)` could be invoked. A malicious frame
//!   claiming 4 GiB of body bytes is rejected at ~10 bytes of work.
//! * **Canonical strict.** A non-minimal uleb128, an unknown enum tag, a
//!   non-zero reserved-flags word, an invalid `Option` tag, trailing bytes,
//!   or an embedding with `dims_u16 == 0` are all rejected. After a
//!   successful decode, the resulting `ChunkEnvelopeV1` is re-encoded and
//!   byte-compared to the input; any drift returns `NonCanonical`. This is
//!   the **cross-language schema lock**: a Python or Move encoder that
//!   produces a different byte string for the same logical value is caught
//!   here, because Rust will refuse to round-trip it.
//! * **Fixed-byte arrays.** `[u8; 32]` and `[u8; 64]` blobs are wired
//!   contiguously (no length prefix, no variable header). Wire byte counts
//!   are pinned in [`EMBEDDING_WIRE_BYTES`], [`SIGNATURE_WIRE_BYTES`],
//!   [`PROVENANCE_WIRE_BYTES`].
//! * **No `unsafe`.** The crate-level `#![deny(unsafe_code)]` is retained;
//!   every byte cursor lives in [`crate::wire`] and uses `checked_add` so a
//!   length overflow cannot wrap.

use crate::wire::{
    WireError, WireReader, append_fixed, append_u16_le, append_u32_le, append_uleb128_u32,
};

// ===========================================================================
// 1. Wire & layout constants
// ===========================================================================

/// Wire schema version. Bumped only when the byte layout itself changes.
pub const SCHEMA_VERSION_V1: u8 = 1;

/// Fixed wire width of a [`BlobId`]. Walrus blob ids are 32 bytes.
pub const BLOB_ID_BYTES: usize = 32;

/// Fixed wire width of a single Ed25519 signature blob.
pub const SIGNATURE_BYTES: usize = 64;

/// Fixed wire width of a provenance identifier (e.g. a skill or marketplace
/// registry entry id). Matches the 32-byte digest length used elsewhere on the
/// MNEMOS chain.
pub const PROVENANCE_ID_BYTES: usize = 32;

/// Maximum number of bytes allowed in `ChunkEnvelopeV1.content`. The cap is
/// enforced **before any body buffer is allocated**, so an oversized frame
/// cannot trigger a multi-megabyte allocation.
pub const MAX_CONTENT_BYTES: u32 = 13_000_000;

/// Minimum encoded length of a chunk envelope in V1. Achieved when
/// `content.len() == 0` and `parent / embedding / signature / provenance`
/// are all `None`. Used as a fast `EmptyInput` / `Truncated` boundary.
pub const MIN_EMPTY_CHUNK_V1_BYTES: usize = 10;

/// Wire byte count of an inner [`EmbeddingRefV1`] payload (without the
/// outer `Option` tag): `model_tag_u16(2) + dims_u16(2) + vector_hash(32)`.
pub const EMBEDDING_WIRE_BYTES: usize = 2 + 2 + BLOB_ID_BYTES;

/// Wire byte count of an inner [`SignaturePlaceholderV1`] payload (without
/// the outer `Option` tag): `scheme(1) + public_key(32) + signature(64)`.
pub const SIGNATURE_WIRE_BYTES: usize = 1 + BLOB_ID_BYTES + SIGNATURE_BYTES;

/// Wire byte count of an inner [`ProvenanceRefV1`] payload (without the
/// outer `Option` tag): `namespace(1) + id(32) + version_u32(4)`.
pub const PROVENANCE_WIRE_BYTES: usize = 1 + PROVENANCE_ID_BYTES + 4;

// ===========================================================================
// 2. Tag enums (every variant carries an explicit discriminant)
// ===========================================================================

/// What kind of content a chunk holds. Stable wire tags; reorder is a
/// breaking change.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
#[non_exhaustive]
#[repr(u8)]
pub enum ChunkKind {
    /// A user-authored message in a conversation.
    UserMessage = 1,
    /// An assistant-generated message.
    AssistantMessage = 2,
    /// A system-injected memory fragment.
    SystemMemory = 3,
    /// The result body of a tool invocation.
    ToolResult = 4,
    /// A skill artifact produced or consumed by the agent.
    SkillArtifact = 5,
}

impl ChunkKind {
    /// One-byte wire tag for this kind.
    #[inline]
    pub const fn tag(self) -> u8 {
        self as u8
    }

    /// Reverse mapping from a wire tag to a [`ChunkKind`]. Returns
    /// [`ChunkCodecError::UnknownKind`] for any tag the codec does not know.
    pub const fn from_tag(tag: u8) -> Result<Self, ChunkCodecError> {
        match tag {
            1 => Ok(Self::UserMessage),
            2 => Ok(Self::AssistantMessage),
            3 => Ok(Self::SystemMemory),
            4 => Ok(Self::ToolResult),
            5 => Ok(Self::SkillArtifact),
            other => Err(ChunkCodecError::UnknownKind { tag: other }),
        }
    }
}

/// Speaker / authoring role of a memory chunk.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
#[repr(u8)]
pub enum MemoryRole {
    /// End user.
    User = 1,
    /// Assistant (model output).
    Assistant = 2,
    /// System prompt / scaffolding.
    System = 3,
    /// Tool dispatcher / tool reply.
    Tool = 4,
    /// Higher-level agent loop.
    Agent = 5,
}

impl MemoryRole {
    /// One-byte wire tag.
    #[inline]
    pub const fn tag(self) -> u8 {
        self as u8
    }

    /// Reverse mapping.
    pub const fn from_tag(tag: u8) -> Result<Self, ChunkCodecError> {
        match tag {
            1 => Ok(Self::User),
            2 => Ok(Self::Assistant),
            3 => Ok(Self::System),
            4 => Ok(Self::Tool),
            5 => Ok(Self::Agent),
            other => Err(ChunkCodecError::UnknownRole { tag: other }),
        }
    }
}

/// Signature algorithm carried by a [`SignaturePlaceholderV1`]. Phase 0 only
/// admits Ed25519; the variant set is `#[non_exhaustive]` so adding a scheme
/// later is not a breaking change for downstream `match`es.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
#[repr(u8)]
pub enum SignatureScheme {
    /// Ed25519 (Walrus / Sui default).
    Ed25519 = 1,
}

impl SignatureScheme {
    /// One-byte wire tag.
    #[inline]
    pub const fn tag(self) -> u8 {
        self as u8
    }

    /// Reverse mapping.
    pub const fn from_tag(tag: u8) -> Result<Self, ChunkCodecError> {
        match tag {
            1 => Ok(Self::Ed25519),
            other => Err(ChunkCodecError::UnknownSignatureScheme { tag: other }),
        }
    }
}

/// Namespace that disambiguates a [`ProvenanceRefV1::id`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
#[repr(u8)]
pub enum ProvenanceNamespace {
    /// Skill registry entry.
    SkillRegistry = 1,
    /// Marketplace registry entry.
    MarketplaceRegistry = 2,
}

impl ProvenanceNamespace {
    /// One-byte wire tag.
    #[inline]
    pub const fn tag(self) -> u8 {
        self as u8
    }

    /// Reverse mapping.
    pub const fn from_tag(tag: u8) -> Result<Self, ChunkCodecError> {
        match tag {
            1 => Ok(Self::SkillRegistry),
            2 => Ok(Self::MarketplaceRegistry),
            other => Err(ChunkCodecError::UnknownProvenanceNamespace { tag: other }),
        }
    }
}

// ===========================================================================
// 3. Codec error
// ===========================================================================

/// Every failure mode the chunk codec can report. `Copy`, field-bounded, no
/// owned bytes — so the error channel cannot leak a raw provider body or a
/// canary substring through `Debug` / `Display` / `source()`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum ChunkCodecError {
    /// The input byte slice was empty.
    EmptyInput,
    /// The leading `schema_version` byte did not match [`SCHEMA_VERSION_V1`].
    UnsupportedVersion {
        /// Observed version byte.
        version: u8,
    },
    /// A `ChunkKind` tag was outside the known set.
    UnknownKind {
        /// Observed wire tag.
        tag: u8,
    },
    /// A `MemoryRole` tag was outside the known set.
    UnknownRole {
        /// Observed wire tag.
        tag: u8,
    },
    /// A `SignatureScheme` tag was outside the known set.
    UnknownSignatureScheme {
        /// Observed wire tag.
        tag: u8,
    },
    /// A `ProvenanceNamespace` tag was outside the known set.
    UnknownProvenanceNamespace {
        /// Observed wire tag.
        tag: u8,
    },
    /// `reserved_flags` carried a non-zero value (forward-compatibility
    /// bits the V1 codec is not allowed to interpret).
    ReservedFlags {
        /// Observed flag bits.
        flags: u16,
    },
    /// An `Option<T>` tag byte was neither 0 nor 1.
    InvalidOptionTag {
        /// Which option field the bad tag belonged to.
        field: &'static str,
        /// Observed tag byte.
        tag: u8,
    },
    /// `content.len()` would exceed [`MAX_CONTENT_BYTES`]. Reported with
    /// both observed and limit values so an operator can size their cap.
    ContentTooLarge {
        /// Observed length in bytes.
        observed_u32: u32,
        /// Configured maximum.
        max_u32: u32,
    },
    /// An [`EmbeddingRefV1`] carried `dims_u16 == 0`.
    ZeroEmbeddingDims,
    /// The cursor reached end-of-input while reading a named field.
    Truncated {
        /// Field that ran out of bytes.
        field: &'static str,
    },
    /// A uleb128 length prefix was non-minimal or did not fit in `u32`.
    InvalidLengthPrefix,
    /// Either trailing bytes remained after the envelope ended, or
    /// `decode → re-encode → byte compare` produced a different sequence.
    NonCanonical,
    /// Reserved variant for future BCS-encoder backends. Not emitted by the
    /// hand-rolled V1 path.
    BcsEncode,
    /// Reserved variant for future BCS-decoder backends. Not emitted by the
    /// hand-rolled V1 path.
    BcsDecode,
}

impl ChunkCodecError {
    const fn from_wire(err: WireError, field: &'static str) -> Self {
        match err {
            WireError::Truncated => Self::Truncated { field },
            WireError::NonCanonicalUleb => Self::InvalidLengthPrefix,
            WireError::UlebOverflowU32 => Self::InvalidLengthPrefix,
        }
    }
}

impl core::fmt::Display for ChunkCodecError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(self.class_label())
    }
}

impl std::error::Error for ChunkCodecError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        None
    }
}

impl ChunkCodecError {
    /// Static class label for the error. Mirrors the error-redaction policy
    /// in `mnemos-a-core::error` — every variant maps to a stable `&'static`
    /// string so logs and metrics never carry a dynamically formatted body.
    pub const fn class_label(&self) -> &'static str {
        match self {
            Self::EmptyInput => "chunk_codec.empty_input",
            Self::UnsupportedVersion { .. } => "chunk_codec.unsupported_version",
            Self::UnknownKind { .. } => "chunk_codec.unknown_kind",
            Self::UnknownRole { .. } => "chunk_codec.unknown_role",
            Self::UnknownSignatureScheme { .. } => "chunk_codec.unknown_signature_scheme",
            Self::UnknownProvenanceNamespace { .. } => "chunk_codec.unknown_provenance_namespace",
            Self::ReservedFlags { .. } => "chunk_codec.reserved_flags",
            Self::InvalidOptionTag { .. } => "chunk_codec.invalid_option_tag",
            Self::ContentTooLarge { .. } => "chunk_codec.content_too_large",
            Self::ZeroEmbeddingDims => "chunk_codec.zero_embedding_dims",
            Self::Truncated { .. } => "chunk_codec.truncated",
            Self::InvalidLengthPrefix => "chunk_codec.invalid_length_prefix",
            Self::NonCanonical => "chunk_codec.non_canonical",
            Self::BcsEncode => "chunk_codec.bcs_encode",
            Self::BcsDecode => "chunk_codec.bcs_decode",
        }
    }
}

// ===========================================================================
// 4. Fixed-byte wrapper types (Copy)
// ===========================================================================

/// 32-byte Walrus blob identifier. `repr(transparent)` over `[u8; 32]` so
/// `size_of::<BlobId>() == 32` is byte-exact.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
#[repr(transparent)]
pub struct BlobId(pub [u8; BLOB_ID_BYTES]);

impl BlobId {
    /// Borrow the underlying bytes.
    #[inline]
    pub const fn as_bytes(&self) -> &[u8; BLOB_ID_BYTES] {
        &self.0
    }
}

/// 64-byte signature blob (e.g. Ed25519). `repr(transparent)` over
/// `[u8; 64]` so `size_of::<SignatureBytes>() == 64` is byte-exact.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
#[repr(transparent)]
pub struct SignatureBytes(pub [u8; SIGNATURE_BYTES]);

impl SignatureBytes {
    /// Borrow the underlying bytes.
    #[inline]
    pub const fn as_bytes(&self) -> &[u8; SIGNATURE_BYTES] {
        &self.0
    }
}

// ===========================================================================
// 5. Inner envelope payloads
// ===========================================================================

/// Reference to a vector embedding by model tag, dimensionality, and the
/// digest of the embedding vector itself (the embedding bytes themselves
/// live elsewhere — Walrus or a local store).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(C)]
pub struct EmbeddingRefV1 {
    /// Stable model identifier (registry-assigned u16).
    pub model_tag_u16: u16,
    /// Embedding dimension. Must be non-zero (decoder enforces).
    pub dims_u16: u16,
    /// 32-byte digest of the embedding vector bytes.
    pub vector_hash: [u8; BLOB_ID_BYTES],
}

/// Placeholder for a per-chunk signature. The signature itself is
/// **not** validated by the codec; that is the responsibility of the
/// verifier in `c-walrus::blob_id` and `mnemos-g-wallet`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(C)]
pub struct SignaturePlaceholderV1 {
    /// Signature algorithm.
    pub scheme: SignatureScheme,
    /// 32-byte signing public key.
    pub public_key: [u8; BLOB_ID_BYTES],
    /// 64-byte signature blob.
    pub signature: SignatureBytes,
}

/// Provenance pointer (which registry, which entry, which version).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(C)]
pub struct ProvenanceRefV1 {
    /// Which registry the id refers to.
    pub namespace: ProvenanceNamespace,
    /// 32-byte registry entry id.
    pub id: [u8; PROVENANCE_ID_BYTES],
    /// Monotonically advancing registry version.
    pub version_u32: u32,
}

// ===========================================================================
// 6. Top-level envelope
// ===========================================================================

/// In-memory representation of a chunk before/after wire serialization.
/// Owns its body bytes via `Vec<u8>`; everything else is fixed-width.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ChunkEnvelopeV1 {
    /// What sort of chunk this is.
    pub kind: ChunkKind,
    /// Speaker / authoring role.
    pub role: MemoryRole,
    /// Optional parent blob id (e.g. previous turn).
    pub parent: Option<BlobId>,
    /// Body bytes. Length must satisfy `<= MAX_CONTENT_BYTES`.
    pub content: Vec<u8>,
    /// Optional embedding reference.
    pub embedding: Option<EmbeddingRefV1>,
    /// Optional signature placeholder.
    pub signature: Option<SignaturePlaceholderV1>,
    /// Optional provenance reference.
    pub provenance: Option<ProvenanceRefV1>,
}

// ===========================================================================
// 7. Move-side anchor projections
// ===========================================================================

/// Stable seed projected from a [`ChunkEnvelopeV1`] for deriving the
/// Move-side `add_chunk` parameters. Equality on this struct is the
/// fingerprint b-memory uses to detect a duplicate anchor request before
/// any Walrus PUT (so retry storms can't double-anchor).
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
#[repr(C)]
pub struct MoveAnchorSeedV1 {
    /// Chunk kind (mirrors envelope).
    pub kind: ChunkKind,
    /// Parent blob id, if any.
    pub parent: Option<BlobId>,
}

/// Arguments handed to the Move `add_chunk` entry function for this chunk.
/// `blob_id` is the **locally-derived** Walrus blob id (not the
/// publisher-reported text), enforced by
/// `c-walrus::blob_id::VerifiedBlobId`.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
#[repr(C)]
pub struct MoveAnchorArgsV1 {
    /// Verified blob id.
    pub blob_id: BlobId,
    /// Chunk kind.
    pub kind: ChunkKind,
    /// Parent blob id, if any.
    pub parent: Option<BlobId>,
}

impl MoveAnchorArgsV1 {
    /// Produce the seed projection (drops `blob_id`).
    #[inline]
    pub const fn seed(self) -> MoveAnchorSeedV1 {
        MoveAnchorSeedV1 {
            kind: self.kind,
            parent: self.parent,
        }
    }
}

// ===========================================================================
// 8. Compile-time-measurable size table
// ===========================================================================

/// Snapshot of the in-memory sizes of every codec public type. The numbers
/// are emitted by [`public_type_sizes_v1`] and asserted by the test
/// `public_type_sizes_are_fixed_for_measurements`, so any drift across
/// rustc versions or `repr` changes is caught at build time. `b-memory`
/// consumes this table to budget fixed-capacity queues without runtime
/// `size_of` calls.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(C)]
pub struct PublicTypeSizesV1 {
    /// `size_of::<BlobId>()`.
    pub blob_id: usize,
    /// `size_of::<SignatureBytes>()`.
    pub signature_bytes: usize,
    /// `size_of::<EmbeddingRefV1>()`.
    pub embedding_ref: usize,
    /// `size_of::<ProvenanceRefV1>()`.
    pub provenance_ref: usize,
    /// `size_of::<MoveAnchorSeedV1>()`.
    pub move_anchor_seed: usize,
    /// `size_of::<MoveAnchorArgsV1>()`.
    pub move_anchor_args: usize,
}

/// Returns the measurement table for the V1 codec. `const fn` so callers
/// can use the values in array-size positions.
pub const fn public_type_sizes_v1() -> PublicTypeSizesV1 {
    PublicTypeSizesV1 {
        blob_id: core::mem::size_of::<BlobId>(),
        signature_bytes: core::mem::size_of::<SignatureBytes>(),
        embedding_ref: core::mem::size_of::<EmbeddingRefV1>(),
        provenance_ref: core::mem::size_of::<ProvenanceRefV1>(),
        move_anchor_seed: core::mem::size_of::<MoveAnchorSeedV1>(),
        move_anchor_args: core::mem::size_of::<MoveAnchorArgsV1>(),
    }
}

// ===========================================================================
// 9. Length budgeting helpers
// ===========================================================================

/// Length in bytes of the canonical uleb128 encoding of `value`. Pure
/// arithmetic — used to size buffers before allocation.
const fn uleb128_len_u32(value: u32) -> usize {
    if value < 1u32 << 7 {
        1
    } else if value < 1u32 << 14 {
        2
    } else if value < 1u32 << 21 {
        3
    } else if value < 1u32 << 28 {
        4
    } else {
        5
    }
}

/// Bytes required to encode a minimal envelope whose `content` has length
/// `content_len` and whose `parent / embedding / signature / provenance`
/// are all `None`. Fails with `ContentTooLarge` if the body exceeds the
/// cap.
pub const fn encoded_len_for_content_len(content_len: u32) -> Result<usize, ChunkCodecError> {
    if content_len > MAX_CONTENT_BYTES {
        return Err(ChunkCodecError::ContentTooLarge {
            observed_u32: content_len,
            max_u32: MAX_CONTENT_BYTES,
        });
    }
    // 9 = 1 (schema_version) + 1 (kind) + 1 (role) + 2 (reserved_flags)
    //   + 1 (parent None tag) + 1 (embedding None tag) + 1 (signature None tag)
    //   + 1 (provenance None tag); plus uleb128(content_len) + content_len.
    let header_no_content = 9usize;
    let body = uleb128_len_u32(content_len) + content_len as usize;
    Ok(header_no_content + body)
}

/// Same as [`encoded_len_for_content_len`] minus `content_len`: the bytes
/// of metadata wrapping a body of the given length.
pub const fn metadata_overhead_for_content_len(content_len: u32) -> Result<usize, ChunkCodecError> {
    if content_len > MAX_CONTENT_BYTES {
        return Err(ChunkCodecError::ContentTooLarge {
            observed_u32: content_len,
            max_u32: MAX_CONTENT_BYTES,
        });
    }
    Ok(9usize + uleb128_len_u32(content_len))
}

// ===========================================================================
// 10. Encoder
// ===========================================================================

/// Serialize a [`ChunkEnvelopeV1`] to its canonical V1 wire bytes. Pre-checks:
///
/// * `content.len() <= MAX_CONTENT_BYTES`,
/// * if `embedding` is `Some`, then `dims_u16 != 0`.
pub fn encode_chunk_v1(chunk: &ChunkEnvelopeV1) -> Result<Vec<u8>, ChunkCodecError> {
    let content_len_usize = chunk.content.len();
    let content_len_u32 =
        u32::try_from(content_len_usize).map_err(|_| ChunkCodecError::ContentTooLarge {
            observed_u32: u32::MAX,
            max_u32: MAX_CONTENT_BYTES,
        })?;
    if content_len_u32 > MAX_CONTENT_BYTES {
        return Err(ChunkCodecError::ContentTooLarge {
            observed_u32: content_len_u32,
            max_u32: MAX_CONTENT_BYTES,
        });
    }
    if let Some(emb) = chunk.embedding.as_ref() {
        if emb.dims_u16 == 0 {
            return Err(ChunkCodecError::ZeroEmbeddingDims);
        }
    }

    // Capacity reservation (best-effort; an exact total is computed for sanity
    // but the `Vec` is allowed to grow). Header + Optional payloads + body.
    let header_min = 9usize + uleb128_len_u32(content_len_u32);
    let parent_extra = chunk.parent.map_or(0, |_| BLOB_ID_BYTES);
    let embedding_extra = chunk.embedding.map_or(0, |_| EMBEDDING_WIRE_BYTES);
    let signature_extra = chunk.signature.map_or(0, |_| SIGNATURE_WIRE_BYTES);
    let provenance_extra = chunk.provenance.map_or(0, |_| PROVENANCE_WIRE_BYTES);
    let total = header_min
        + content_len_usize
        + parent_extra
        + embedding_extra
        + signature_extra
        + provenance_extra;

    let mut out: Vec<u8> = Vec::with_capacity(total);

    out.push(SCHEMA_VERSION_V1);
    out.push(chunk.kind.tag());
    out.push(chunk.role.tag());
    append_u16_le(&mut out, 0u16); // reserved_flags

    match chunk.parent {
        None => out.push(0u8),
        Some(parent) => {
            out.push(1u8);
            append_fixed(&mut out, parent.as_bytes());
        }
    }

    append_uleb128_u32(&mut out, content_len_u32);
    out.extend_from_slice(&chunk.content);

    match chunk.embedding.as_ref() {
        None => out.push(0u8),
        Some(emb) => {
            out.push(1u8);
            append_u16_le(&mut out, emb.model_tag_u16);
            append_u16_le(&mut out, emb.dims_u16);
            append_fixed(&mut out, &emb.vector_hash);
        }
    }

    match chunk.signature.as_ref() {
        None => out.push(0u8),
        Some(sig) => {
            out.push(1u8);
            out.push(sig.scheme.tag());
            append_fixed(&mut out, &sig.public_key);
            append_fixed(&mut out, sig.signature.as_bytes());
        }
    }

    match chunk.provenance.as_ref() {
        None => out.push(0u8),
        Some(prov) => {
            out.push(1u8);
            out.push(prov.namespace.tag());
            append_fixed(&mut out, &prov.id);
            append_u32_le(&mut out, prov.version_u32);
        }
    }

    Ok(out)
}

// ===========================================================================
// 11. Decoder (canonical-strict)
// ===========================================================================

/// Read an `Option<T>` tag byte and reject anything outside `{0, 1}`.
fn read_option_tag(r: &mut WireReader<'_>, field: &'static str) -> Result<bool, ChunkCodecError> {
    let tag = r
        .read_u8()
        .map_err(|e| ChunkCodecError::from_wire(e, field))?;
    match tag {
        0 => Ok(false),
        1 => Ok(true),
        other => Err(ChunkCodecError::InvalidOptionTag { field, tag: other }),
    }
}

/// Parse the raw bytes once. Used both by [`decode_chunk_v1`] and the
/// internal canonical re-encode check.
fn decode_one_pass(bytes: &[u8]) -> Result<ChunkEnvelopeV1, ChunkCodecError> {
    if bytes.is_empty() {
        return Err(ChunkCodecError::EmptyInput);
    }
    let mut r = WireReader::new(bytes);

    let version = r
        .read_u8()
        .map_err(|e| ChunkCodecError::from_wire(e, "schema_version"))?;
    if version != SCHEMA_VERSION_V1 {
        return Err(ChunkCodecError::UnsupportedVersion { version });
    }

    let kind_tag = r
        .read_u8()
        .map_err(|e| ChunkCodecError::from_wire(e, "kind"))?;
    let kind = ChunkKind::from_tag(kind_tag)?;

    let role_tag = r
        .read_u8()
        .map_err(|e| ChunkCodecError::from_wire(e, "role"))?;
    let role = MemoryRole::from_tag(role_tag)?;

    let flags = r
        .read_u16_le()
        .map_err(|e| ChunkCodecError::from_wire(e, "reserved_flags"))?;
    if flags != 0 {
        return Err(ChunkCodecError::ReservedFlags { flags });
    }

    let parent = if read_option_tag(&mut r, "parent")? {
        let raw = r
            .read_fixed::<BLOB_ID_BYTES>()
            .map_err(|e| ChunkCodecError::from_wire(e, "parent"))?;
        Some(BlobId(raw))
    } else {
        None
    };

    // ----- Body cap check BEFORE Vec allocation. -----
    let content_len = r
        .read_uleb128_u32()
        .map_err(|e| ChunkCodecError::from_wire(e, "content_len"))?;
    if content_len > MAX_CONTENT_BYTES {
        return Err(ChunkCodecError::ContentTooLarge {
            observed_u32: content_len,
            max_u32: MAX_CONTENT_BYTES,
        });
    }
    let content_slice = r
        .take(content_len as usize)
        .map_err(|e| ChunkCodecError::from_wire(e, "content"))?;
    let content: Vec<u8> = content_slice.to_vec();

    let embedding = if read_option_tag(&mut r, "embedding")? {
        let model_tag_u16 = r
            .read_u16_le()
            .map_err(|e| ChunkCodecError::from_wire(e, "embedding.model_tag"))?;
        let dims_u16 = r
            .read_u16_le()
            .map_err(|e| ChunkCodecError::from_wire(e, "embedding.dims"))?;
        if dims_u16 == 0 {
            return Err(ChunkCodecError::ZeroEmbeddingDims);
        }
        let vector_hash = r
            .read_fixed::<BLOB_ID_BYTES>()
            .map_err(|e| ChunkCodecError::from_wire(e, "embedding.vector_hash"))?;
        Some(EmbeddingRefV1 {
            model_tag_u16,
            dims_u16,
            vector_hash,
        })
    } else {
        None
    };

    let signature = if read_option_tag(&mut r, "signature")? {
        let scheme_tag = r
            .read_u8()
            .map_err(|e| ChunkCodecError::from_wire(e, "signature.scheme"))?;
        let scheme = SignatureScheme::from_tag(scheme_tag)?;
        let public_key = r
            .read_fixed::<BLOB_ID_BYTES>()
            .map_err(|e| ChunkCodecError::from_wire(e, "signature.public_key"))?;
        let sig_bytes = r
            .read_fixed::<SIGNATURE_BYTES>()
            .map_err(|e| ChunkCodecError::from_wire(e, "signature.signature"))?;
        Some(SignaturePlaceholderV1 {
            scheme,
            public_key,
            signature: SignatureBytes(sig_bytes),
        })
    } else {
        None
    };

    let provenance = if read_option_tag(&mut r, "provenance")? {
        let ns_tag = r
            .read_u8()
            .map_err(|e| ChunkCodecError::from_wire(e, "provenance.namespace"))?;
        let namespace = ProvenanceNamespace::from_tag(ns_tag)?;
        let id = r
            .read_fixed::<PROVENANCE_ID_BYTES>()
            .map_err(|e| ChunkCodecError::from_wire(e, "provenance.id"))?;
        let version_u32 = r
            .read_u32_le()
            .map_err(|e| ChunkCodecError::from_wire(e, "provenance.version_u32"))?;
        Some(ProvenanceRefV1 {
            namespace,
            id,
            version_u32,
        })
    } else {
        None
    };

    if !r.is_at_end() {
        return Err(ChunkCodecError::NonCanonical);
    }

    Ok(ChunkEnvelopeV1 {
        kind,
        role,
        parent,
        content,
        embedding,
        signature,
        provenance,
    })
}

/// Decode a wire byte string into a [`ChunkEnvelopeV1`].
///
/// Strict-canonical: after a successful parse the envelope is re-encoded
/// and byte-compared to the input. Any drift is rejected with
/// [`ChunkCodecError::NonCanonical`]. This is the cross-language schema
/// lock — a Python or Move encoder that disagrees with this Rust path on
/// the byte representation of any value is caught here.
pub fn decode_chunk_v1(bytes: &[u8]) -> Result<ChunkEnvelopeV1, ChunkCodecError> {
    let envelope = decode_one_pass(bytes)?;
    let reencoded = encode_chunk_v1(&envelope)?;
    if reencoded.as_slice() != bytes {
        return Err(ChunkCodecError::NonCanonical);
    }
    Ok(envelope)
}
