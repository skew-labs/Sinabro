//! `mnemos-d-move::types` — MemoryRoot Rust bindings.
//!
//! Canonical output types wired in this module:
//! - `GasBudgetMist` newtype over `u64` so a gas budget is never confused
//!   with a token count, a chunk byte length, or a blob id (typed-unit
//!   discipline).
//! - `SuiAddress` newtype over `[u8; 32]` (32-byte Sui account id) and
//!   `ObjectId` newtype over `[u8; 32]` (32-byte on-chain object id).
//!   Both are `#[repr(transparent)]` so `size_of` is exactly 32 bytes.
//! - `MemoryRootArgs` (`#[repr(C)]`, `Copy`) — Rust-side projection of the
//!   `mnemos::memory_root::MemoryRoot` fields that callers pass through
//!   the SDK (`owner`, `root_hash`, `epoch_u64`). `root_hash` is fixed at
//!   `[u8; 32]` on the Rust side; the Move side stores it as
//!   `vector<u8>` with a `len == 32` invariant proved by the Move
//!   Prover. The boundary check between the two is
//!   carried by [`MoveBindError::RootHashLen`].
//! - `MoveBindError` (`Copy`, `#[non_exhaustive]`, class-label namespaced
//!   `move_bind.*`) — failure modes raised by the binding layer; the
//!   `EpochNotMonotone` / `OwnerMismatch` variants are emitted from their
//!   own enforcement sites elsewhere. `RootHashLen` is the only variant
//!   emitted here (currently only reachable via the future
//!   `try_from_root_hash_slice` constructor — at present the public
//!   surface for converting an anchor only ever sees a fixed-size
//!   `[u8; 32]`, so the channel exists for downstream symmetry).
//! - `memory_root_args_from_anchor(anchor, owner, epoch_u64)` — the
//!   single conversion entrypoint. Takes a verified `MoveAnchorArgsV1`
//!   (already `BlobId([u8; 32])`-typed, gated through
//!   `c-walrus::blob_id::VerifiedBlobId`) plus an owner address and an
//!   epoch counter, returns a `MemoryRootArgs`. The conversion is total
//!   here (always `Ok`); the `Result` wrapper is kept so future
//!   epoch-monotonicity or owner-mismatch checks do not break the
//!   canonical signature.
//!
//! ## Cross-language schema lock (BCS test vector)
//!
//! The Rust-side `MemoryRootArgs` is `#[repr(C)]` with three fields in
//! declaration order: `owner` (32 bytes), `root_hash` (32 bytes),
//! `epoch_u64` (8 bytes little-endian). The Move-side `mnemos::memory_root`
//! module exposes the same fields on `MemoryRoot` (minus the `UID` and
//! the `chunk_count`, which are object-infrastructure fields owned by
//! the Sui framework and are not in the SDK call args). The BCS encoding
//! of `MemoryRootArgs` is therefore the simple concatenation
//! `owner ‖ root_hash ‖ epoch_u64_le` = 72 bytes total, with no length
//! prefixes (fixed-size arrays in BCS are emitted as raw bytes). The
//! known-vector test `d0_1_bcs_parity_vector` in `tests/types.rs` pins
//! a single canonical sample (owner = 0x11..11, root_hash = 0x22..22,
//! epoch_u64 = 42) byte-for-byte; a Python BCS reference oracle
//! independently reproduces the same 72-byte string.
//!
//! ## Carve-outs
//!
//! 1. `MoveBindError::EpochNotMonotone` + `MoveBindError::OwnerMismatch`
//!    are **defined** but **not emitted** by any function here. They are
//!    the failure channel that the `add_chunk` / `transfer_root` / SDK
//!    enforcement sites consume; defining them ahead of consumption is
//!    intentional so the downstream consumers have a stable channel.
//! 2. `memory_root_args_from_anchor` currently always returns `Ok`. The
//!    `Result` wrapper is preserved so that future fallible checks can be
//!    added without an API break.
//! 3. The `chunk_count` and `id: UID` fields of `MemoryRoot` (Move side)
//!    do NOT have a Rust-side mirror in `MemoryRootArgs`. `UID` is
//!    object-infrastructure and `chunk_count` is monotone-managed by
//!    the on-chain module (`add_chunk` increments it).
//!    The Rust SDK never sets either field directly.

use mnemos_c_walrus::{BLOB_ID_BYTES, MoveAnchorArgsV1};

// ===========================================================================
// 1. Compile-time reuse markers
// ===========================================================================

/// Pins the Rust-side root-hash length to the
/// `BLOB_ID_BYTES = 32`. Any drift breaks the build via a zero-length
/// array index trick. Mirror of `c-walrus::blob_id::_BLOB_ID_REUSES_ATOM7_32`.
const _ROOT_HASH_REUSES_BLOB_ID_BYTES_32: [(); 0 - !(BLOB_ID_BYTES == 32) as usize] = [];

/// Pins the Rust-side `MemoryRootArgs` BCS encoded length to 72 bytes
/// (32 owner + 32 root_hash + 8 epoch_u64_le). Any reordering or
/// field-width change breaks the build before the cross-language vector
/// even runs.
const _MEMORY_ROOT_ARGS_BCS_LEN_IS_72: [(); 0 - !(MEMORY_ROOT_ARGS_BCS_LEN == 72) as usize] = [];

// ===========================================================================
// 2. Compile-time canonical constants
// ===========================================================================

/// Length in bytes of a Sui account address. The Move side stores
/// addresses as 32-byte values; the Rust `SuiAddress` is fixed at the
/// same width so the BCS encoding is byte-stable across the two.
pub const SUI_ADDRESS_BYTES: usize = 32;

/// Length in bytes of a Sui on-chain object id. Mirrors `SUI_ADDRESS_BYTES`.
pub const SUI_OBJECT_ID_BYTES: usize = 32;

/// BCS-encoded byte length of [`MemoryRootArgs`]. Equal to
/// `SUI_ADDRESS_BYTES + BLOB_ID_BYTES + 8` = `32 + 32 + 8` = `72`.
/// Pinned by `_MEMORY_ROOT_ARGS_BCS_LEN_IS_72` above.
pub const MEMORY_ROOT_ARGS_BCS_LEN: usize = SUI_ADDRESS_BYTES + BLOB_ID_BYTES + 8;

// ===========================================================================
// 3. Typed-unit newtypes
// ===========================================================================

/// Gas budget in `MIST` (Sui's smallest unit). `#[repr(transparent)]`
/// over `u64`, so `size_of::<GasBudgetMist>() == 8` is byte-exact and
/// the value crosses an FFI boundary as a plain `u64`. The type-system
/// keeps a raw `u64` token / chunk-byte-length / epoch counter from
/// being silently passed where a gas budget is expected. Zero is a
/// representable value here; the `CallBuildError::GasBudgetZero` reject
/// is owned by `SuiCallBuilder::add_chunk`.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
#[repr(transparent)]
pub struct GasBudgetMist(u64);

impl GasBudgetMist {
    /// Wrap a raw `u64` MIST count in a typed gas budget.
    #[inline]
    pub const fn new(mist: u64) -> Self {
        Self(mist)
    }

    /// Unwrap the typed gas budget back to a raw `u64`.
    #[inline]
    pub const fn get(self) -> u64 {
        self.0
    }
}

/// A 32-byte Sui account address. `#[repr(transparent)]` over
/// `[u8; SUI_ADDRESS_BYTES]`, so `size_of::<SuiAddress>() == 32` is
/// byte-exact. Equality / hashing are byte-equal on the underlying
/// array.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
#[repr(transparent)]
pub struct SuiAddress([u8; SUI_ADDRESS_BYTES]);

impl SuiAddress {
    /// Wrap 32 raw bytes as a Sui address.
    #[inline]
    pub const fn new(bytes: [u8; SUI_ADDRESS_BYTES]) -> Self {
        Self(bytes)
    }

    /// Borrow the underlying 32-byte array.
    #[inline]
    pub const fn as_bytes(&self) -> &[u8; SUI_ADDRESS_BYTES] {
        &self.0
    }
}

/// A 32-byte Sui on-chain object id. `#[repr(transparent)]` over
/// `[u8; SUI_OBJECT_ID_BYTES]`, so `size_of::<ObjectId>() == 32`. Distinct
/// from [`SuiAddress`] at the type level even though both are 32-byte
/// arrays — a wallet address is never silently usable where an object
/// id is expected (and vice versa).
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
#[repr(transparent)]
pub struct ObjectId([u8; SUI_OBJECT_ID_BYTES]);

impl ObjectId {
    /// Wrap 32 raw bytes as an object id.
    #[inline]
    pub const fn new(bytes: [u8; SUI_OBJECT_ID_BYTES]) -> Self {
        Self(bytes)
    }

    /// Borrow the underlying 32-byte array.
    #[inline]
    pub const fn as_bytes(&self) -> &[u8; SUI_OBJECT_ID_BYTES] {
        &self.0
    }
}

// ===========================================================================
// 4. Memory-root call args
// ===========================================================================

/// Rust-side projection of the fields a caller hands to the
/// `mnemos::memory_root` Move module when they want to spin up a new
/// memory-root object (or address one for `add_chunk`). The Move-side
/// `MemoryRoot` struct also carries a Sui `UID` and a `chunk_count`
/// counter; those are owned by the on-chain module and are not part
/// of the SDK call args — they are set / updated by Sui's object
/// infrastructure and by `add_chunk` respectively.
///
/// `#[repr(C)]` so the field order is the declaration order (the BCS
/// encoding consumes fields in source-declaration order). The full
/// `Copy` derive is safe because every field is `Copy`.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
#[repr(C)]
pub struct MemoryRootArgs {
    /// 32-byte wallet that owns the root object on Sui.
    pub owner: SuiAddress,
    /// 32-byte root hash anchored on-chain. Move-side type is
    /// `vector<u8>` with a `len == 32` invariant proved by the
    /// Move Prover.
    pub root_hash: [u8; BLOB_ID_BYTES],
    /// Monotonically-increasing epoch counter. The monotonicity
    /// invariant is enforced by the Move Prover and
    /// raised through [`MoveBindError::EpochNotMonotone`] by
    /// `add_chunk`.
    pub epoch_u64: u64,
}

// ===========================================================================
// 5. Move-binding failure channel
// ===========================================================================

/// Failure modes raised by the Move-binding layer. `Copy`, field-bounded,
/// no owned bytes — so the channel cannot leak a raw provider body
/// through `Debug` / `Display`. Class label namespace `move_bind.*`
/// mirrors the `class_label()` discipline used by sibling
/// binding-error types.
///
/// Currently only [`MoveBindError::RootHashLen`] is conceptually
/// reachable here (via a future fallible constructor from a runtime
/// `&[u8]`); other call sites consume the rest:
/// - `EpochNotMonotone` — emitted by `add_chunk` on `next <= prev`.
/// - `OwnerMismatch` — emitted by `add_chunk` and `transfer_root`
///   when `ctx.sender() != root.owner`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum MoveBindError {
    /// A `vector<u8>` crossing the Move↔Rust boundary did not have
    /// `len == 32`. Carries the observed length so audit pipelines can
    /// pin the exact drift size.
    RootHashLen {
        /// Observed vector length (expected 32).
        observed: usize,
    },
    /// The epoch counter handed to the binding layer was not strictly
    /// greater than the previous on-chain value.
    EpochNotMonotone {
        /// Previous on-chain epoch.
        prev: u64,
        /// Attempted new epoch.
        next: u64,
    },
    /// The transaction sender did not match the on-chain `owner` field
    /// of the targeted `MemoryRoot`.
    OwnerMismatch,
}

impl MoveBindError {
    /// Stable class label of this failure mode. Namespaced under
    /// `move_bind.*` so audit pipelines can fan out on a single
    /// prefix.
    #[inline]
    pub const fn class_label(&self) -> &'static str {
        match self {
            Self::RootHashLen { .. } => "move_bind.root_hash_len",
            Self::EpochNotMonotone { .. } => "move_bind.epoch_not_monotone",
            Self::OwnerMismatch => "move_bind.owner_mismatch",
        }
    }
}

// ===========================================================================
// 6. Conversion entrypoint
// ===========================================================================

/// Build a [`MemoryRootArgs`] from a verified Walrus anchor + an
/// `(owner, epoch)` pair. The blob id of the anchor becomes the
/// `root_hash` of the memory root — that is the "anchor" relation the
/// system enforces: each `MemoryRoot` is keyed by the locally-derived
/// blob id of the latest chunk it has anchored.
///
/// The function is total (always `Ok`). The `Result`
/// wrapper is preserved so later call sites
/// can layer fallible checks (epoch monotonicity, owner
/// match) without changing the canonical signature.
///
/// The `anchor.kind` and `anchor.parent` fields are intentionally
/// dropped here: the SDK-level args ([`MemoryRootArgs`]) carry only
/// the data Sui needs at `MemoryRoot` creation; the chunk-level
/// `kind` / `parent` ride in the `ChunkAnchored` event emitted by
/// `add_chunk`.
#[inline]
pub fn memory_root_args_from_anchor(
    anchor: &MoveAnchorArgsV1,
    owner: SuiAddress,
    epoch_u64: u64,
) -> Result<MemoryRootArgs, MoveBindError> {
    let root_hash: [u8; BLOB_ID_BYTES] = *anchor.blob_id.as_bytes();
    Ok(MemoryRootArgs {
        owner,
        root_hash,
        epoch_u64,
    })
}

// ===========================================================================
// 7. BCS serialization for cross-language schema lock
// ===========================================================================

/// Encode a [`MemoryRootArgs`] as the byte-exact 72-byte BCS sequence
/// `owner ‖ root_hash ‖ epoch_u64_le`. Fixed-size arrays serialise in
/// BCS as their raw bytes (no length prefix); `u64` serialises as
/// 8 bytes little-endian. The order is the source-declaration order.
///
/// A Python BCS reference oracle
/// independently reproduces the same byte string for the same input,
/// closing the Rust↔Python↔Move byte-level loop.
#[inline]
pub fn encode_memory_root_args_bcs(args: &MemoryRootArgs) -> [u8; MEMORY_ROOT_ARGS_BCS_LEN] {
    let mut out = [0u8; MEMORY_ROOT_ARGS_BCS_LEN];
    let mut cursor: usize = 0;

    // owner (32 bytes)
    let owner_bytes = args.owner.as_bytes();
    out[cursor..cursor + SUI_ADDRESS_BYTES].copy_from_slice(owner_bytes);
    cursor += SUI_ADDRESS_BYTES;

    // root_hash (32 bytes)
    out[cursor..cursor + BLOB_ID_BYTES].copy_from_slice(&args.root_hash);
    cursor += BLOB_ID_BYTES;

    // epoch_u64 (8 bytes little-endian)
    let epoch_le = args.epoch_u64.to_le_bytes();
    out[cursor..cursor + 8].copy_from_slice(&epoch_le);

    out
}

// ===========================================================================
// 8. Inline unit tests (module-internal invariants only)
// ===========================================================================

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use core::mem::size_of;

    #[test]
    fn typed_unit_size_of_is_byte_exact() {
        assert_eq!(size_of::<GasBudgetMist>(), 8);
        assert_eq!(size_of::<SuiAddress>(), SUI_ADDRESS_BYTES);
        assert_eq!(size_of::<ObjectId>(), SUI_OBJECT_ID_BYTES);
    }

    #[test]
    fn memory_root_args_bcs_len_constant_is_72() {
        assert_eq!(MEMORY_ROOT_ARGS_BCS_LEN, 72);
    }

    #[test]
    fn sui_address_round_trip() {
        let bytes = [7u8; SUI_ADDRESS_BYTES];
        let addr = SuiAddress::new(bytes);
        assert_eq!(addr.as_bytes(), &bytes);
    }

    #[test]
    fn object_id_distinct_type_from_sui_address() {
        // Compile-time-ish: a SuiAddress cannot be assigned to an ObjectId
        // even though both wrap [u8; 32]. We can't test that directly here
        // (it would be a compile_fail test), but we can at least pin that
        // the size_of values match (drift-detection).
        assert_eq!(size_of::<SuiAddress>(), size_of::<ObjectId>());
    }

    #[test]
    fn gas_budget_mist_round_trip() {
        let gb = GasBudgetMist::new(800_000);
        assert_eq!(gb.get(), 800_000);
    }

    #[test]
    fn move_bind_error_class_labels_are_namespaced() {
        let labels = [
            MoveBindError::RootHashLen { observed: 31 }.class_label(),
            MoveBindError::EpochNotMonotone { prev: 5, next: 5 }.class_label(),
            MoveBindError::OwnerMismatch.class_label(),
        ];
        for label in labels {
            assert!(
                label.starts_with("move_bind."),
                "class label {label} not under move_bind.*"
            );
        }
    }

    #[test]
    fn move_bind_error_class_labels_are_unique() {
        let labels = [
            MoveBindError::RootHashLen { observed: 31 }.class_label(),
            MoveBindError::EpochNotMonotone { prev: 5, next: 5 }.class_label(),
            MoveBindError::OwnerMismatch.class_label(),
        ];
        for i in 0..labels.len() {
            for j in (i + 1)..labels.len() {
                assert_ne!(labels[i], labels[j]);
            }
        }
    }

    #[test]
    fn encode_memory_root_args_bcs_emits_72_bytes() {
        let args = MemoryRootArgs {
            owner: SuiAddress::new([0u8; 32]),
            root_hash: [0u8; 32],
            epoch_u64: 0,
        };
        let encoded = encode_memory_root_args_bcs(&args);
        assert_eq!(encoded.len(), 72);
    }

    #[test]
    fn encode_memory_root_args_bcs_field_order_is_owner_then_hash_then_epoch_le() {
        let owner_bytes = [0xAAu8; 32];
        let root_bytes = [0xBBu8; 32];
        let epoch: u64 = 0x0102_0304_0506_0708;
        let args = MemoryRootArgs {
            owner: SuiAddress::new(owner_bytes),
            root_hash: root_bytes,
            epoch_u64: epoch,
        };
        let encoded = encode_memory_root_args_bcs(&args);

        // bytes 0..32 = owner
        assert_eq!(&encoded[0..32], &owner_bytes);
        // bytes 32..64 = root_hash
        assert_eq!(&encoded[32..64], &root_bytes);
        // bytes 64..72 = epoch LE
        let mut expected_epoch_le = [0u8; 8];
        expected_epoch_le.copy_from_slice(&epoch.to_le_bytes());
        assert_eq!(&encoded[64..72], &expected_epoch_le);
    }

    #[test]
    fn memory_root_args_from_anchor_drops_kind_and_parent() {
        use mnemos_c_walrus::{BlobId, ChunkKind};

        let blob = BlobId([0xCDu8; 32]);
        let anchor = MoveAnchorArgsV1 {
            blob_id: blob,
            kind: ChunkKind::UserMessage,
            parent: None,
        };
        let owner = SuiAddress::new([0x11u8; 32]);
        let args = memory_root_args_from_anchor(&anchor, owner, 7).unwrap();

        // root_hash mirrors anchor.blob_id byte-for-byte
        assert_eq!(args.root_hash, [0xCDu8; 32]);
        // owner / epoch passed through verbatim
        assert_eq!(args.owner.as_bytes(), &[0x11u8; 32]);
        assert_eq!(args.epoch_u64, 7);
        // (kind and parent are intentionally dropped — no field for them
        //  on MemoryRootArgs)
    }
}
