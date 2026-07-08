//! `mnemos-d-move::stage_b_types` — Stage B Rust↔Move
//! anchor/audit call-arg bindings.
//!
//! Canonical OUT:
//! - [`MemoryRootAnchorArgs`] — the Rust-side call args a caller hands the
//!   `mnemos::memory_root` module when anchoring a chunk: the on-chain
//!   `root` object id ([`crate::types::ObjectId`]), the verified
//!   Walrus `anchor` (`MoveAnchorArgsV1`, already `BlobId([u8; 32])`
//!   -typed), and the 32-byte content `digest`.
//! - [`AuditAppendArgs`] — the Rust-side call args for
//!   `mnemos::audit_log::append`: the `log` object id and the 32-byte
//!   `entry_hash`.
//! - [`StageBMoveBindError`] — the Stage B Move-binding failure channel,
//!   the complete five-variant set declared verbatim.
//!
//! ## `digest` is `[u8; 32]`, NOT `ChunkDigest32`
//!
//! The canonical `digest` field type is `ChunkDigest32`. That
//! type lives in `b-memory` (`crates/b-memory/src/chunk_digest.rs`).
//! `b-memory` ALREADY depends on `d-move`
//! (`crates/b-memory/Cargo.toml`, reused by the Walrus
//! wrappers for `SuiAddress`), so `d-move` referencing a `b-memory` type
//! would form a cargo dependency cycle (`b-memory -> d-move -> b-memory`)
//! and fail to compile. Compounding this, `ChunkDigest32` has a private
//! inner field and is constructible only by `b-memory`'s
//! `stage_b_chunk_digest` — the digest is produced UP in `b-memory` and
//! flows DOWN to these call args, the opposite of the dependency edge.
//!
//! Resolution (reuse + verify locally): `digest` is a raw `[u8; 32]` here.
//! The typed-unit guard is meaningless at the `d-move` layer anyway —
//! `d-move` cannot construct or validate a `ChunkDigest32`. The `b-memory`
//! caller (which owns the typed digest) unwraps `chunk_digest.as_bytes()`
//! at the construction boundary and passes the already-validated 32 bytes
//! down into [`MemoryRootAnchorArgs::new`]. The relocation alternative
//! (move `ChunkDigest32` to `c-walrus`) was rejected as out of this
//! single-file module's scope.
//!
//! ## Move `vector<u8>` length checked at the boundary
//!
//! The Move side carries `digest` / `entry_hash` as `vector<u8>` with a
//! `len == 32` invariant (`E_BAD_BLOB_LEN`-class gates on the Move side).
//! The typed Rust constructors ([`MemoryRootAnchorArgs::new`],
//! [`AuditAppendArgs::new`]) take a fixed `[u8; 32]`, so a wrong length is
//! unrepresentable. The `try_from_move_*` constructors are the boundary
//! adapters that accept a runtime `&[u8]` (an inbound Move `vector<u8>`)
//! and reject `len != 32` with [`StageBMoveBindError::Len32`].
//!
//! ## Full five-variant error mint
//!
//! [`StageBMoveBindError`] mints all five variants verbatim in one unit,
//! preserving the cross-language schema lock. Only
//! [`StageBMoveBindError::Len32`] is emitted here (the boundary
//! adapters). `OwnerMismatch` / `EpochNotMonotone` / `NetworkNotTestnet` /
//! `GasBudgetZero` are the cross-module channel consumed by the call builder
//! (the PTB/call-builder dry-run: mainnet reject, gas-zero reject)
//! — defining the full set ahead of consumption keeps the channel
//! byte-stable.
//!
//! ## No raw address string in core
//!
//! Every identifier crosses this boundary as a fixed-width byte newtype
//! ([`crate::types::ObjectId`] = `[u8; 32]`) or a raw `[u8; 32]`, never as
//! a `String` / hex text. Both call-arg structs are `Copy`; a `String`
//! field would break `Copy` and the `b3_11_no_raw_address_string_in_core`
//! test compile-pins that property.

use mnemos_c_walrus::{BLOB_ID_BYTES, MoveAnchorArgsV1};

use crate::types::ObjectId;

// ===========================================================================
// 1. Compile-time reuse marker
// ===========================================================================

/// Pins the Stage B Move-boundary `vector<u8>` length to the
/// `BLOB_ID_BYTES = 32`. Any drift breaks the build via a
/// zero-length array index trick before any test runs. Mirror of
/// `crate::types::_ROOT_HASH_REUSES_BLOB_ID_BYTES_32`.
const _STAGE_B_MOVE_VEC_LEN_REUSES_BLOB_ID_BYTES_32: [(); 0 - !(BLOB_ID_BYTES == 32) as usize] = [];

// ===========================================================================
// 2. Compile-time canonical constant
// ===========================================================================

/// Length in bytes of a Move-boundary `vector<u8>` carrying a content
/// digest or an audit entry hash. Equal to `BLOB_ID_BYTES` (= 32) so the
/// Rust fixed-array side and the Move length invariant cannot drift.
pub const STAGE_B_MOVE_VEC_LEN: usize = BLOB_ID_BYTES;

// ===========================================================================
// 3. Move-binding failure channel (full five-variant set)
// ===========================================================================

/// Failure modes raised by the Stage B Move-binding layer. `Copy`, with no
/// owned bytes, so the channel cannot leak a raw provider body through
/// `Debug` / `Display`. The complete five-variant set is declared verbatim
/// (cross-language schema lock — a sixth variant would
/// be drift). Class labels are namespaced `stage_b_move_bind.*`, mirroring
/// the [`crate::types::MoveBindError`] `class_label()` discipline.
///
/// Here only [`StageBMoveBindError::Len32`] is emitted (the
/// `try_from_move_*` boundary adapters). The other four are the cross-module
/// channel consumed by the call builder.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum StageBMoveBindError {
    /// A `vector<u8>` crossing the Move↔Rust boundary did not have
    /// `len == 32` ([`STAGE_B_MOVE_VEC_LEN`]).
    Len32,
    /// The transaction sender did not match the on-chain `owner` field of
    /// the targeted `MemoryRoot` / `AuditLog`. (Consumed by the call builder.)
    OwnerMismatch,
    /// The epoch counter handed to the binding layer was not strictly
    /// greater than the previous on-chain value. (Consumed by the call builder.)
    EpochNotMonotone,
    /// The targeted network was not a Stage B testnet — Stage B forbids
    /// mainnet by construction. (Consumed by the call builder.)
    NetworkNotTestnet,
    /// The gas budget handed to a call builder was zero. (Consumed by
    /// the call builder.)
    GasBudgetZero,
}

impl StageBMoveBindError {
    /// Stable class label of this failure mode, namespaced under
    /// `stage_b_move_bind.*` so audit pipelines can fan out on one prefix.
    #[inline]
    pub const fn class_label(&self) -> &'static str {
        match self {
            Self::Len32 => "stage_b_move_bind.len32",
            Self::OwnerMismatch => "stage_b_move_bind.owner_mismatch",
            Self::EpochNotMonotone => "stage_b_move_bind.epoch_not_monotone",
            Self::NetworkNotTestnet => "stage_b_move_bind.network_not_testnet",
            Self::GasBudgetZero => "stage_b_move_bind.gas_budget_zero",
        }
    }
}

/// Copy a Move-boundary `&[u8]` into a fixed `[u8; 32]`, rejecting any
/// length other than [`STAGE_B_MOVE_VEC_LEN`] with
/// [`StageBMoveBindError::Len32`]. The single boundary length check shared
/// by both `try_from_move_*` constructors.
#[inline]
fn copy_move_vec_32(src: &[u8]) -> Result<[u8; STAGE_B_MOVE_VEC_LEN], StageBMoveBindError> {
    if src.len() != STAGE_B_MOVE_VEC_LEN {
        return Err(StageBMoveBindError::Len32);
    }
    let mut out = [0u8; STAGE_B_MOVE_VEC_LEN];
    out.copy_from_slice(src);
    Ok(out)
}

// ===========================================================================
// 4. memory_root anchor call args
// ===========================================================================

/// Rust-side call args for anchoring a chunk on the `mnemos::memory_root`
/// Move module. `#[repr(C)]` so the field order is the source-declaration
/// order (consumed in declaration order by the BCS parity vectors).
/// `Copy` is safe because every field is `Copy`.
///
/// `digest` is a raw `[u8; 32]` rather than `b-memory::ChunkDigest32`; see
/// the module-level note for the cargo-cycle reason.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
#[repr(C)]
pub struct MemoryRootAnchorArgs {
    /// 32-byte on-chain object id of the target `MemoryRoot`.
    root: ObjectId,
    /// Verified Walrus anchor (`MoveAnchorArgsV1`; carries the
    /// locally-derived `blob_id`, the chunk `kind`, and an optional
    /// `parent` blob id).
    anchor: MoveAnchorArgsV1,
    /// 32-byte content digest. The nominal type is `ChunkDigest32`; held
    /// here as raw bytes (the typed value is unwrapped by the
    /// `b-memory` caller at the construction boundary).
    digest: [u8; STAGE_B_MOVE_VEC_LEN],
}

impl MemoryRootAnchorArgs {
    /// Build anchor call args from a typed 32-byte digest. Total /
    /// infallible — the caller (`b-memory`) supplies an already-validated
    /// `*chunk_digest.as_bytes()`. `const` so the value can be built in a
    /// const context.
    #[inline]
    pub const fn new(
        root: ObjectId,
        anchor: MoveAnchorArgsV1,
        digest: [u8; STAGE_B_MOVE_VEC_LEN],
    ) -> Self {
        Self {
            root,
            anchor,
            digest,
        }
    }

    /// Boundary adapter: build anchor call args from an inbound Move
    /// `vector<u8>` digest, rejecting `len != 32` with
    /// [`StageBMoveBindError::Len32`].
    #[inline]
    pub fn try_from_move_vectors(
        root: ObjectId,
        anchor: MoveAnchorArgsV1,
        digest: &[u8],
    ) -> Result<Self, StageBMoveBindError> {
        let digest = copy_move_vec_32(digest)?;
        Ok(Self::new(root, anchor, digest))
    }

    /// Borrow the target root object id.
    #[inline]
    pub const fn root(&self) -> &ObjectId {
        &self.root
    }

    /// Borrow the verified Walrus anchor.
    #[inline]
    pub const fn anchor(&self) -> &MoveAnchorArgsV1 {
        &self.anchor
    }

    /// Borrow the 32-byte content digest.
    #[inline]
    pub const fn digest(&self) -> &[u8; STAGE_B_MOVE_VEC_LEN] {
        &self.digest
    }
}

// ===========================================================================
// 5. audit_log append call args
// ===========================================================================

/// Rust-side call args for `mnemos::audit_log::append`. `#[repr(C)]`,
/// `Copy`; carries only the `log` object id and the 32-byte `entry_hash`
/// — no owner, no raw content (the append is owner-gated on the Move side
/// and the entry hash is content-addressed).
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
#[repr(C)]
pub struct AuditAppendArgs {
    /// 32-byte on-chain object id of the target `AuditLog`.
    log: ObjectId,
    /// 32-byte audit entry hash.
    entry_hash: [u8; STAGE_B_MOVE_VEC_LEN],
}

impl AuditAppendArgs {
    /// Build audit-append call args from a typed 32-byte entry hash.
    /// Total / infallible. `const`.
    #[inline]
    pub const fn new(log: ObjectId, entry_hash: [u8; STAGE_B_MOVE_VEC_LEN]) -> Self {
        Self { log, entry_hash }
    }

    /// Boundary adapter: build audit-append call args from an inbound Move
    /// `vector<u8>` entry hash, rejecting `len != 32` with
    /// [`StageBMoveBindError::Len32`].
    #[inline]
    pub fn try_from_move_entry_hash(
        log: ObjectId,
        entry_hash: &[u8],
    ) -> Result<Self, StageBMoveBindError> {
        let entry_hash = copy_move_vec_32(entry_hash)?;
        Ok(Self::new(log, entry_hash))
    }

    /// Borrow the target log object id.
    #[inline]
    pub const fn log(&self) -> &ObjectId {
        &self.log
    }

    /// Borrow the 32-byte audit entry hash.
    #[inline]
    pub const fn entry_hash(&self) -> &[u8; STAGE_B_MOVE_VEC_LEN] {
        &self.entry_hash
    }
}

// ===========================================================================
// 6. Inline unit tests (module-internal invariants only)
// ===========================================================================

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use core::mem::size_of;

    use mnemos_c_walrus::{BlobId, ChunkKind};

    fn sample_anchor() -> MoveAnchorArgsV1 {
        MoveAnchorArgsV1 {
            blob_id: BlobId([0xCDu8; 32]),
            kind: ChunkKind::UserMessage,
            parent: None,
        }
    }

    /// `len32 accepted`.
    #[test]
    fn b3_11_len32_digest_accepted() {
        let root = ObjectId::new([0x11u8; 32]);
        let digest = [0x22u8; 32];
        let args =
            MemoryRootAnchorArgs::try_from_move_vectors(root, sample_anchor(), &digest).unwrap();
        assert_eq!(args.digest(), &digest);
        assert_eq!(args.root().as_bytes(), &[0x11u8; 32]);

        let log = ObjectId::new([0x33u8; 32]);
        let entry = [0x44u8; 32];
        let aargs = AuditAppendArgs::try_from_move_entry_hash(log, &entry).unwrap();
        assert_eq!(aargs.entry_hash(), &entry);
        assert_eq!(aargs.log().as_bytes(), &[0x33u8; 32]);
    }

    /// `wrong len rejected`: both a short (31) and a long (33) vector are
    /// rejected with `Len32`, on both boundary adapters.
    #[test]
    fn b3_11_wrong_len_rejected() {
        let root = ObjectId::new([0x11u8; 32]);
        let log = ObjectId::new([0x33u8; 32]);

        for bad_len in [0usize, 31, 33, 64] {
            let bad = vec![0xEEu8; bad_len];
            assert_eq!(
                MemoryRootAnchorArgs::try_from_move_vectors(root, sample_anchor(), &bad),
                Err(StageBMoveBindError::Len32),
                "digest len {bad_len} should be rejected"
            );
            assert_eq!(
                AuditAppendArgs::try_from_move_entry_hash(log, &bad),
                Err(StageBMoveBindError::Len32),
                "entry_hash len {bad_len} should be rejected"
            );
        }
    }

    /// `no raw address string in core`.
    /// Compile-pins that every call-arg field is a fixed-width byte type:
    /// a `String` / hex-text field would break the `Copy` bound below, and
    /// the size_of values are exact byte counts (no heap pointer).
    #[test]
    fn b3_11_no_raw_address_string_in_core() {
        fn assert_copy<T: Copy>() {}
        assert_copy::<MemoryRootAnchorArgs>();
        assert_copy::<AuditAppendArgs>();

        // AuditAppendArgs = ObjectId(32) + [u8; 32](32), repr(C) → 64.
        assert_eq!(size_of::<AuditAppendArgs>(), 64);
        // ObjectId reuse stays byte-exact at 32.
        assert_eq!(size_of::<ObjectId>(), 32);
        // The digest field is exactly 32 raw bytes (no String, no pointer).
        assert_eq!(size_of::<[u8; STAGE_B_MOVE_VEC_LEN]>(), 32);
    }

    #[test]
    fn b3_11_stage_b_move_vec_len_is_32() {
        assert_eq!(STAGE_B_MOVE_VEC_LEN, 32);
        assert_eq!(STAGE_B_MOVE_VEC_LEN, BLOB_ID_BYTES);
    }

    #[test]
    fn b3_11_new_round_trips_typed_digest() {
        let root = ObjectId::new([0x11u8; 32]);
        let digest = [0x22u8; 32];
        let args = MemoryRootAnchorArgs::new(root, sample_anchor(), digest);
        assert_eq!(args.digest(), &digest);
        assert_eq!(args.anchor(), &sample_anchor());
    }

    #[test]
    fn b3_11_full_five_variants_have_namespaced_unique_class_labels() {
        let labels = [
            StageBMoveBindError::Len32.class_label(),
            StageBMoveBindError::OwnerMismatch.class_label(),
            StageBMoveBindError::EpochNotMonotone.class_label(),
            StageBMoveBindError::NetworkNotTestnet.class_label(),
            StageBMoveBindError::GasBudgetZero.class_label(),
        ];
        // All five present (full mint) and namespaced.
        assert_eq!(labels.len(), 5);
        for label in labels {
            assert!(
                label.starts_with("stage_b_move_bind."),
                "class label {label} not under stage_b_move_bind.*"
            );
        }
        // Pairwise unique.
        for i in 0..labels.len() {
            for j in (i + 1)..labels.len() {
                assert_ne!(labels[i], labels[j]);
            }
        }
    }
}
