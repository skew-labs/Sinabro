//! atom #20 · D.0.6 integration tests — verbatim ATOM_PLAN line 997.
//!
//! Four named tests required by the plan:
//! - `d0_6_add_chunk_call_builds`
//! - `d0_6_zero_gas_rejected`
//! - `d0_6_dry_run_bytes_are_bcs`
//! - `d0_6_dry_run_bytes_gas_measurement` (the plan's "gas 측정 (dry-run)"
//!   item — interpreted as a unit test that pins the gas-slot encoding
//!   in the dry-run output since the G-SUI gate explicitly forbids
//!   live RPC at atom #20).
//!
//! The first three exercise the happy / reject / byte-layout paths of
//! [`SuiCallBuilder::add_chunk`] and [`SuiCallBuilder::to_dry_run_bytes`].
//! The fourth pins the gas budget's exact byte slot inside the dry-run
//! output so future atoms (G.0.x signing, K.0.1 CI) can byte-scan the
//! gas field without re-deriving the offset.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use mnemos_d_move::sdk::{
    CallBuildError, MNEMOS_MEMORY_ROOT_PACKAGE_PLACEHOLDER, MNEMOS_MOVE_FUNCTION_ADD_CHUNK,
    MNEMOS_MOVE_MODULE_NAME, SUI_DRY_RUN_BYTES_ADD_CHUNK_LEN, SuiCallBuilder,
};
use mnemos_d_move::types::{
    GasBudgetMist, MEMORY_ROOT_ARGS_BCS_LEN, MemoryRootArgs, ObjectId, SuiAddress,
    encode_memory_root_args_bcs,
};

// ---------------------------------------------------------------------------
// Test fixtures (deliberately distinct byte patterns per field so a
// copy-paste / offset bug between fields cannot hide)
// ---------------------------------------------------------------------------

fn fixture_root() -> ObjectId {
    ObjectId::new([0xCCu8; 32])
}

fn fixture_args() -> MemoryRootArgs {
    MemoryRootArgs {
        owner: SuiAddress::new([0xAAu8; 32]),
        root_hash: [0xBBu8; 32],
        epoch_u64: 0x0102_0304_0506_0708,
    }
}

fn fixture_gas() -> GasBudgetMist {
    GasBudgetMist::new(800_000)
}

// ===========================================================================
// ATOM_PLAN line 997 verbatim test #1
// ===========================================================================

/// Pins that the happy-path constructor `SuiCallBuilder::add_chunk`
/// produces an `Ok(SuiCallBuilder)` whose six fields (four canonical
/// + two implementation-private) match the inputs exactly.
#[test]
fn d0_6_add_chunk_call_builds() {
    let builder = SuiCallBuilder::add_chunk(fixture_root(), &fixture_args(), fixture_gas())
        .expect("happy-path add_chunk must succeed for non-zero gas");

    // Canonical four routing fields.
    assert_eq!(
        builder.package().as_bytes(),
        MNEMOS_MEMORY_ROOT_PACKAGE_PLACEHOLDER.as_bytes()
    );
    assert_eq!(builder.module(), MNEMOS_MOVE_MODULE_NAME);
    assert_eq!(builder.function(), MNEMOS_MOVE_FUNCTION_ADD_CHUNK);
    assert_eq!(builder.gas_budget().get(), 800_000);

    // Implementation-private accessors (Session 2 audit hooks).
    assert_eq!(builder.root().as_bytes(), &[0xCCu8; 32]);
    let expected_args = encode_memory_root_args_bcs(&fixture_args());
    assert_eq!(builder.encoded_args(), &expected_args);
}

// ===========================================================================
// ATOM_PLAN line 997 verbatim test #2
// ===========================================================================

/// Pins that a gas budget of zero is rejected at the constructor
/// boundary with [`CallBuildError::GasBudgetZero`] — before any BCS
/// encode work runs. Sui validators reject zero-budget transactions,
/// so we fail-closed early.
#[test]
fn d0_6_zero_gas_rejected() {
    let zero_gas = GasBudgetMist::new(0);
    let result = SuiCallBuilder::add_chunk(fixture_root(), &fixture_args(), zero_gas);
    assert_eq!(result, Err(CallBuildError::GasBudgetZero));
    assert_eq!(
        CallBuildError::GasBudgetZero.class_label(),
        "sui_call_build.gas_budget_zero"
    );
}

// ===========================================================================
// ATOM_PLAN line 997 verbatim test #3
// ===========================================================================

/// Pins the 166-byte dry-run output to a known byte vector. The same
/// inputs, fed to the Python oracle at
/// `ops/evidence/phase_0/atom_020/oracle_sui_call_builder_v0.py`,
/// reproduce the same 166 bytes — independently. This is the
/// cross-language schema lock for the atom #20 dry-run carrier.
///
/// Fixture (distinct byte patterns per field):
///   package    = [0x00 × 32]              (placeholder until D-1/D-2)
///   module     = "memory_root"            (11 ASCII bytes, uleb128(11)=0x0B)
///   function   = "add_chunk"              ( 9 ASCII bytes, uleb128(9) =0x09)
///   root       = [0xCC × 32]
///   owner      = [0xAA × 32]              (inside encoded_args [86..118])
///   root_hash  = [0xBB × 32]              (inside encoded_args [118..150])
///   epoch_u64  = 0x0102_0304_0506_0708    (inside encoded_args [150..158] LE)
///   gas_budget = 800_000                  (final 8 bytes [158..166] LE)
#[test]
fn d0_6_dry_run_bytes_are_bcs() {
    let builder = SuiCallBuilder::add_chunk(fixture_root(), &fixture_args(), fixture_gas())
        .expect("happy-path add_chunk must succeed");
    let bytes = builder
        .to_dry_run_bytes()
        .expect("to_dry_run_bytes must be infallible for fixed-len inputs");

    // Total length is the pinned constant.
    assert_eq!(bytes.len(), SUI_DRY_RUN_BYTES_ADD_CHUNK_LEN);
    assert_eq!(bytes.len(), 166);

    // ---- segment-by-segment pin (Session 2 audit-targetable) -------------
    // [0..32] package id placeholder
    assert_eq!(&bytes[0..32], &[0u8; 32]);
    // [32] uleb128(11) for module-name length
    assert_eq!(bytes[32], 0x0B);
    // [33..44] "memory_root"
    assert_eq!(&bytes[33..44], b"memory_root");
    // [44] uleb128(9) for function-name length
    assert_eq!(bytes[44], 0x09);
    // [45..54] "add_chunk"
    assert_eq!(&bytes[45..54], b"add_chunk");
    // [54..86] root ObjectId
    assert_eq!(&bytes[54..86], &[0xCCu8; 32]);
    // [86..158] encoded MemoryRootArgs (72 bytes)
    let expected_args = encode_memory_root_args_bcs(&fixture_args());
    assert_eq!(&bytes[86..158], &expected_args);
    // Args internal layout: owner [86..118], root_hash [118..150],
    // epoch_u64 LE [150..158] — sanity-pin against the atom #15 schema.
    assert_eq!(MEMORY_ROOT_ARGS_BCS_LEN, 72);
    assert_eq!(&bytes[86..118], &[0xAAu8; 32]);
    assert_eq!(&bytes[118..150], &[0xBBu8; 32]);
    assert_eq!(&bytes[150..158], &0x0102_0304_0506_0708u64.to_le_bytes());
    // [158..166] gas budget LE
    assert_eq!(&bytes[158..166], &800_000u64.to_le_bytes());

    // ---- known-vector hex literal (eyeball cross-check) ------------------
    // 166 bytes = 332 hex chars, broken at segment boundaries for review.
    let expected_hex = concat!(
        "0000000000000000000000000000000000000000000000000000000000000000", // package 32B
        "0b",                                                               // uleb128(11)
        "6d656d6f72795f726f6f74",                                           // "memory_root"
        "09",                                                               // uleb128(9)
        "6164645f6368756e6b",                                               // "add_chunk"
        "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc", // root 32B
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", // owner 32B
        "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", // root_hash 32B
        "0807060504030201",                                                 // epoch LE 8B
        "00350c0000000000",                                                 // gas LE 8B (800_000)
    );
    let actual_hex = hex_lower(&bytes);
    assert_eq!(actual_hex, expected_hex);
}

// ===========================================================================
// ATOM_PLAN line 997 verbatim test #4 — "gas 측정 (dry-run)"
// ===========================================================================

/// Pins the gas budget's byte position inside the dry-run output. The
/// G-SUI gate explicitly forbids live RPC at atom #20 ("dry-run, 실서명
/// 금지"), so the "gas measurement" surface here is the byte-slot
/// position + the LE encoding — not a Sui-validator gas estimate.
///
/// Three distinct budgets exercise the slot to prove the rest of the
/// payload (158 bytes prefix) is byte-identical and only the final
/// 8-byte gas slot varies.
#[test]
fn d0_6_dry_run_bytes_gas_measurement() {
    let cases: [u64; 5] = [1, 800_000, u32::MAX as u64, u64::MAX / 2, u64::MAX];
    let mut first_prefix: Option<Vec<u8>> = None;
    for budget in cases {
        let builder =
            SuiCallBuilder::add_chunk(fixture_root(), &fixture_args(), GasBudgetMist::new(budget))
                .unwrap();
        let bytes = builder.to_dry_run_bytes().unwrap();
        assert_eq!(bytes.len(), SUI_DRY_RUN_BYTES_ADD_CHUNK_LEN);

        // Gas slot encoded as little-endian u64 at [158..166].
        let expected_le: [u8; 8] = budget.to_le_bytes();
        assert_eq!(&bytes[158..166], &expected_le);

        // Prefix [0..158] is invariant across gas budgets.
        match &first_prefix {
            None => first_prefix = Some(bytes[..158].to_vec()),
            Some(prev) => assert_eq!(&bytes[..158], prev.as_slice()),
        }
    }
}

// ===========================================================================
// Supplementary coverage (atom #2 / #7 / #11 / #15 precedent)
// ===========================================================================

/// Pins that `add_chunk` rejects any zero gas regardless of the
/// `root` / `args` payload — proves the reject is a pure precondition
/// on the gas parameter, not a side effect of arg state.
#[test]
fn d0_6_zero_gas_reject_is_input_independent() {
    let root_variants = [
        ObjectId::new([0x00u8; 32]),
        ObjectId::new([0xFFu8; 32]),
        ObjectId::new([0xCCu8; 32]),
    ];
    let args_variants = [
        MemoryRootArgs {
            owner: SuiAddress::new([0u8; 32]),
            root_hash: [0u8; 32],
            epoch_u64: 0,
        },
        MemoryRootArgs {
            owner: SuiAddress::new([0xFFu8; 32]),
            root_hash: [0xFFu8; 32],
            epoch_u64: u64::MAX,
        },
        fixture_args(),
    ];
    for root in root_variants {
        for args in args_variants {
            let result = SuiCallBuilder::add_chunk(root, &args, GasBudgetMist::new(0));
            assert_eq!(result, Err(CallBuildError::GasBudgetZero));
        }
    }
}

/// Pins that the dry-run output is deterministic for identical inputs
/// — required for any cross-session byte-stable measurement.
#[test]
fn d0_6_dry_run_bytes_are_deterministic_across_two_builds() {
    let b1 = SuiCallBuilder::add_chunk(fixture_root(), &fixture_args(), fixture_gas()).unwrap();
    let b2 = SuiCallBuilder::add_chunk(fixture_root(), &fixture_args(), fixture_gas()).unwrap();
    let bytes1 = b1.to_dry_run_bytes().unwrap();
    let bytes2 = b2.to_dry_run_bytes().unwrap();
    assert_eq!(bytes1, bytes2);
}

/// Pins that distinct roots / args / gas all change the dry-run
/// output — i.e. no field is silently dropped on its way through the
/// builder.
#[test]
fn d0_6_dry_run_bytes_distinguish_every_input() {
    let base = SuiCallBuilder::add_chunk(fixture_root(), &fixture_args(), fixture_gas())
        .unwrap()
        .to_dry_run_bytes()
        .unwrap();

    // Different root.
    let alt_root =
        SuiCallBuilder::add_chunk(ObjectId::new([0x77u8; 32]), &fixture_args(), fixture_gas())
            .unwrap()
            .to_dry_run_bytes()
            .unwrap();
    assert_ne!(base, alt_root);

    // Different args.
    let alt_args_value = MemoryRootArgs {
        owner: SuiAddress::new([0xAAu8; 32]),
        root_hash: [0xBBu8; 32],
        epoch_u64: 0xDEAD_BEEF_DEAD_BEEF,
    };
    let alt_args = SuiCallBuilder::add_chunk(fixture_root(), &alt_args_value, fixture_gas())
        .unwrap()
        .to_dry_run_bytes()
        .unwrap();
    assert_ne!(base, alt_args);

    // Different gas.
    let alt_gas = SuiCallBuilder::add_chunk(fixture_root(), &fixture_args(), GasBudgetMist::new(1))
        .unwrap()
        .to_dry_run_bytes()
        .unwrap();
    assert_ne!(base, alt_gas);
}

// ---------------------------------------------------------------------------

fn hex_lower(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        let hi = (byte >> 4) & 0x0F;
        let lo = byte & 0x0F;
        out.push(hex_nibble(hi));
        out.push(hex_nibble(lo));
    }
    out
}

fn hex_nibble(nibble: u8) -> char {
    match nibble {
        0..=9 => (b'0' + nibble) as char,
        10..=15 => (b'a' + nibble - 10) as char,
        _ => '0',
    }
}
