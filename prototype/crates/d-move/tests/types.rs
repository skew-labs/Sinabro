//! atom #15 · D.0.1 integration tests — verbatim ATOM_PLAN line 947.
//!
//! Two named tests required by the plan:
//! - `d0_1_args_from_anchor_enforces_len32`
//! - `d0_1_bcs_parity_vector`
//!
//! The first verifies the type-system-level boundary check (every Rust
//! input to `memory_root_args_from_anchor` is fixed at `[u8; 32]`, so a
//! `len != 32` slice cannot reach the entrypoint without an explicit
//! `try_from` cast that would itself fail at compile time). The second
//! pins the cross-language BCS byte vector against an independent
//! oracle in `ops/evidence/phase_0/atom_015/oracle_bcs_memory_root_v0.py`.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use core::mem::size_of;

use mnemos_c_walrus::{BLOB_ID_BYTES, BlobId, ChunkKind, MoveAnchorArgsV1};
use mnemos_d_move::types::{
    GasBudgetMist, MEMORY_ROOT_ARGS_BCS_LEN, MemoryRootArgs, MoveBindError, ObjectId,
    SUI_ADDRESS_BYTES, SUI_OBJECT_ID_BYTES, SuiAddress, encode_memory_root_args_bcs,
    memory_root_args_from_anchor,
};

// ===========================================================================
// ATOM_PLAN line 947 verbatim test #1
// ===========================================================================

/// Pins that `memory_root_args_from_anchor` only ever sees a fixed
/// 32-byte blob id (via the `BlobId([u8; 32])` newtype on the
/// `MoveAnchorArgsV1` input) and faithfully copies it into the
/// 32-byte `root_hash` field of `MemoryRootArgs`. The `len == 32`
/// invariant therefore holds by construction; a 31-byte or 33-byte
/// slice cannot be silently smuggled across the Rust↔Move boundary.
#[test]
fn d0_1_args_from_anchor_enforces_len32() {
    // Type-level enforcement: BlobId is repr(transparent) over [u8; 32].
    assert_eq!(size_of::<BlobId>(), BLOB_ID_BYTES);
    assert_eq!(BLOB_ID_BYTES, 32);
    assert_eq!(size_of::<[u8; 32]>(), 32);
    // MemoryRootArgs.root_hash is fixed at [u8; 32] (= 32 bytes).
    assert_eq!(size_of::<[u8; BLOB_ID_BYTES]>(), 32);

    // Round-trip: every byte of the anchor blob_id lands in root_hash
    // verbatim. We exercise every byte position (not just first/last)
    // so a partial-copy bug cannot hide.
    let mut bytes = [0u8; 32];
    for (i, slot) in bytes.iter_mut().enumerate() {
        *slot = i as u8;
    }
    let anchor = MoveAnchorArgsV1 {
        blob_id: BlobId(bytes),
        kind: ChunkKind::UserMessage,
        parent: None,
    };
    let owner = SuiAddress::new([0u8; 32]);
    let args = memory_root_args_from_anchor(&anchor, owner, 0).unwrap();
    assert_eq!(args.root_hash, bytes);
    // root_hash field width is 32 bytes — not 31, not 33. This is the
    // canonical "len == 32" enforcement on the Rust side; the Move
    // Prover atom #18 (`D.0.4`) raises the matching invariant on the
    // Move side over the `vector<u8>` representation.
    assert_eq!(args.root_hash.len(), 32);
}

// ===========================================================================
// ATOM_PLAN line 947 verbatim test #2
// ===========================================================================

/// Cross-language BCS test vector. Pins that the Rust-side
/// `encode_memory_root_args_bcs` for a known `(owner, root_hash, epoch)`
/// triple emits the exact 72-byte sequence
/// `owner ‖ root_hash ‖ epoch_u64_le`. The same triple, fed to the
/// Python oracle at
/// `ops/evidence/phase_0/atom_015/oracle_bcs_memory_root_v0.py`,
/// reproduces the same 72 bytes — independently. The Move side will
/// emit the same encoding once `sui move test` is wired into the
/// G-MOVE gate (see ATOM_PLAN line 949).
///
/// Sample (deliberately diagonal-distinct):
///   owner    = 0x11_11_11_..._11   (32 bytes of 0x11)
///   root     = 0x22_22_22_..._22   (32 bytes of 0x22)
///   epoch    = 42                  (u64 little-endian = 2A 00 00 00 00 00 00 00)
#[test]
fn d0_1_bcs_parity_vector() {
    let owner_bytes = [0x11u8; 32];
    let root_bytes = [0x22u8; 32];
    let epoch: u64 = 42;

    let args = MemoryRootArgs {
        owner: SuiAddress::new(owner_bytes),
        root_hash: root_bytes,
        epoch_u64: epoch,
    };
    let encoded = encode_memory_root_args_bcs(&args);

    // 72 = 32 (owner) + 32 (root_hash) + 8 (epoch_u64 LE)
    assert_eq!(encoded.len(), MEMORY_ROOT_ARGS_BCS_LEN);
    assert_eq!(MEMORY_ROOT_ARGS_BCS_LEN, 72);

    let mut expected = [0u8; 72];
    // owner: 0x11 × 32
    for byte in expected.iter_mut().take(32) {
        *byte = 0x11;
    }
    // root_hash: 0x22 × 32
    for byte in expected.iter_mut().skip(32).take(32) {
        *byte = 0x22;
    }
    // epoch_u64 little-endian: 0x2A, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    expected[64] = 0x2A;
    expected[65] = 0x00;
    expected[66] = 0x00;
    expected[67] = 0x00;
    expected[68] = 0x00;
    expected[69] = 0x00;
    expected[70] = 0x00;
    expected[71] = 0x00;

    assert_eq!(encoded, expected);

    // Hex literal cross-check (so Session 2 / future readers can eyeball
    // the bytes without running the test). The string is a 144-hex-char
    // (= 72-byte) lower-case rendering of `expected`.
    let mut hex = String::with_capacity(144);
    for byte in expected {
        let hi = (byte >> 4) & 0x0F;
        let lo = byte & 0x0F;
        hex.push(hex_nibble(hi));
        hex.push(hex_nibble(lo));
    }
    let expected_hex = concat!(
        "1111111111111111111111111111111111111111111111111111111111111111", // owner 32B
        "2222222222222222222222222222222222222222222222222222222222222222", // root 32B
        "2a00000000000000",                                                 // epoch LE 8B
    );
    assert_eq!(hex, expected_hex);
}

// ===========================================================================
// Supplementary integration coverage (atom #2 / #7 / #11 precedent)
// ===========================================================================

#[test]
fn d0_1_typed_units_are_repr_transparent_byte_exact() {
    assert_eq!(size_of::<GasBudgetMist>(), 8);
    assert_eq!(size_of::<SuiAddress>(), SUI_ADDRESS_BYTES);
    assert_eq!(size_of::<ObjectId>(), SUI_OBJECT_ID_BYTES);
    assert_eq!(SUI_ADDRESS_BYTES, 32);
    assert_eq!(SUI_OBJECT_ID_BYTES, 32);
}

#[test]
fn d0_1_move_bind_error_channel_is_copy_and_class_labelled() {
    fn assert_copy<T: Copy>() {}
    assert_copy::<MoveBindError>();

    // RootHashLen carries observed length for audit pinning
    let err = MoveBindError::RootHashLen { observed: 31 };
    assert_eq!(err.class_label(), "move_bind.root_hash_len");

    let err = MoveBindError::EpochNotMonotone { prev: 5, next: 5 };
    assert_eq!(err.class_label(), "move_bind.epoch_not_monotone");

    let err = MoveBindError::OwnerMismatch;
    assert_eq!(err.class_label(), "move_bind.owner_mismatch");
}

#[test]
fn d0_1_anchor_kind_and_parent_dropped_by_args_conversion() {
    // The kind / parent fields on the Walrus-side anchor do NOT have a
    // mirror in MemoryRootArgs (per §4.D). They ride in the
    // ChunkAnchored Move event emitted by add_chunk (atom #16) instead.
    let anchor = MoveAnchorArgsV1 {
        blob_id: BlobId([9u8; 32]),
        kind: ChunkKind::SkillArtifact,
        parent: Some(BlobId([1u8; 32])),
    };
    let owner = SuiAddress::new([0x33u8; 32]);
    let args = memory_root_args_from_anchor(&anchor, owner, 12345).unwrap();

    assert_eq!(args.root_hash, [9u8; 32]);
    assert_eq!(args.owner.as_bytes(), &[0x33u8; 32]);
    assert_eq!(args.epoch_u64, 12345);
}

#[test]
fn d0_1_gas_budget_mist_round_trip() {
    let gb = GasBudgetMist::new(800_000);
    assert_eq!(gb.get(), 800_000);
    // Phase 0 carve-out: GasBudgetMist::new accepts zero (the
    // `CallBuildError::GasBudgetZero` reject is owned by atom #20
    // SuiCallBuilder, not the constructor).
    let zero = GasBudgetMist::new(0);
    assert_eq!(zero.get(), 0);
}

// ---------------------------------------------------------------------------

fn hex_nibble(nibble: u8) -> char {
    match nibble {
        0..=9 => (b'0' + nibble) as char,
        10..=15 => (b'a' + nibble - 10) as char,
        _ => '0', // unreachable in encode path: nibble masked to 0..=15
    }
}
