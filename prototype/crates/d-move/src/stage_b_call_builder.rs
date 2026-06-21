//! `mnemos-d-move::stage_b_call_builder` — atom #134 · B.3.13 — Stage B
//! testnet-only PTB/call-builder dry-run.
//!
//! Canonical OUT (Stage B ATOM_PLAN lines 971-980): testnet-only call
//! builders for the three owner-gated Move entry functions exercised by
//! Stage B —
//! - `mnemos::memory_root::create_root` (no args; mints a fresh root),
//! - `mnemos::memory_root::add_chunk` (anchors a chunk via the atom #132
//!   [`MemoryRootAnchorArgs`]),
//! - `mnemos::audit_log::append` (appends an audit entry via the atom #132
//!   [`AuditAppendArgs`]).
//!
//! Each builder **refuses a non-testnet network and a zero gas budget** and
//! produces **byte-stable dry-run bytes without signing**. There is no live
//! RPC, no wallet, no key material, and no real Sui intent prefix on any
//! code path here — exactly like the atom #20 [`crate::sdk::SuiCallBuilder`]
//! measurement carrier, extended to three call shapes and gated on network.
//!
//! ## OD-A (cargo-cycle network mirror — #132 OD-1 / #133 OD-1 precedent)
//!
//! The canonical Stage B network type is §4.2 `StageBNetwork` with its
//! `parse_label` testnet-only allowlist, which lives in `b-memory`
//! (`crates/b-memory/src/network.rs`, atom #82). `b-memory` ALREADY depends
//! on `d-move` (`b-memory -> d-move -> c-walrus`, confirmed by
//! `cargo metadata`), so `d-move` importing `StageBNetwork` would form a
//! cargo dependency cycle and fail to compile — the identical constraint
//! that forced atom #132's `digest: [u8; 32]` (not `b-memory::ChunkDigest32`).
//!
//! Resolution (Option-A reuse+verify+disparity-flag, same as #132 / #133):
//! this module MIRRORS the canonical testnet-only allowlist locally as
//! [`STAGE_B_CALL_TESTNET_LABEL`] + [`require_testnet`]. The mirror copies
//! the canonical semantics verbatim — accept ONLY `"testnet"`
//! (ASCII-case-insensitive, surrounding whitespace trimmed), reject every
//! other label fail-closed — so `"mainnet"` (and any other value) is
//! rejected with [`StageBMoveBindError::NetworkNotTestnet`]. The single
//! cross-crate disparity flagged for the Session 2 verifier (ACCEPT or
//! RAISE): the `"testnet"` label string is duplicated here rather than
//! imported from `StageBNetwork::CANONICAL_LABEL`; a future change to the
//! canonical label would not auto-propagate. Relocating `StageBNetwork`
//! down to a cycle-free crate is out of this single-file atom's scope.
//!
//! ## Network input is a `&str` label (OD-C), not the canonical enum
//!
//! The atom test list requires a "mainnet reject" path. The canonical
//! `StageBNetwork` enum is testnet-only **by construction** — it cannot
//! even represent mainnet — so a builder taking a `StageBNetwork` could
//! never be handed a mainnet value to reject. The reject therefore happens
//! at the **string label** boundary (exactly where `parse_label(&str)`
//! does the canonical reject), so the builder constructors take a
//! `network_label: &str`.
//!
//! ## Call-arg wire is the REAL Move entry ABI (OD-B — repaired 2026-05-31)
//!
//! Each builder serializes ONLY the pure call arguments the real Move entry
//! actually takes, and carries each `&mut <Object>` parameter as a SEPARATE
//! object-input reference (never folded into the pure-arg BCS):
//! - `create_root(ctx)` — no object input, no pure args.
//! - `add_chunk(root: &mut MemoryRoot, blob_id: vector<u8>, kind: u8,
//!   parent: vector<u8>, ctx)` — object input `root`; pure args
//!   `blob_id ‖ kind ‖ parent` (`parent` is the empty vector when `None`).
//!   There is **NO `digest` argument**: `MemoryRootAnchorArgs::digest` is
//!   Rust-side evidence/replay data, NOT an `add_chunk` parameter, so it
//!   never enters the call wire. The `(blob_id, kind, parent)` triple is
//!   taken verbatim from the atom #7 [`MoveAnchorArgsV1`] (whose own doc
//!   reads "Arguments handed to the Move `add_chunk` entry function").
//! - `append(log: &mut AuditLog, entry_hash: vector<u8>, ctx)` — object
//!   input `log`; pure args `entry_hash`.
//!
//! This repair honours the atom #133 FORWARD ADVISORY (build state §1):
//! *"the real add_chunk PTB takes (blob_id, kind, parent) only (no
//! serialized root, no digest) — #134 SuiCallBuilder must NOT reuse this
//! struct-parity wire verbatim."* The #132/#133 BCS struct-parity wire is
//! retained ONLY as parity/replay evidence in [`encode_anchor_args_bcs`] /
//! [`encode_audit_append_args_bcs`] (still cross-pinned to the #133 fixture
//! lengths 100 / 132 / 65) and is explicitly **not** the PTB call-arg wire.
//!
//! ## Dry-run envelope
//! ```text
//! package[32 raw] ‖ uleb128(len(module)) ‖ module
//!                 ‖ uleb128(len(function)) ‖ function
//!                 ‖ uleb128(num_object_inputs) ‖ object_id[32 raw] * n
//!                 ‖ pure_args_bcs ‖ gas_budget[u64 LE, 8]
//! ```
//! Object inputs are modeled as their 32-byte object id; the owned-object
//! version + digest (the full `ObjectArg`), the Sui intent prefix, the
//! `TransactionData` wrapper, the gas-object refs, and the PTB command list
//! are deferred to future domain-G signing atoms (atom #20 carve-out #4).
//! Module / function names are all `< 128` bytes and `num_object_inputs <=
//! 1`, so each uleb128 prefix is a single byte; the totals are pinned by the
//! `STAGE_B_*_DRY_RUN_LEN*` constants and the criterion test
//! `b3_13_dry_run_tx_byte_sizes_are_recorded` (create_root 65, add_chunk
//! 130 / 162, append 123 — Python-verified). This is a measurement-only
//! carrier, NOT a signable transaction.

use mnemos_c_walrus::MoveAnchorArgsV1;

use crate::sdk::{
    MNEMOS_MEMORY_ROOT_PACKAGE_PLACEHOLDER, MNEMOS_MOVE_FUNCTION_ADD_CHUNK, MNEMOS_MOVE_MODULE_NAME,
};
use crate::stage_b_types::{
    AuditAppendArgs, MemoryRootAnchorArgs, STAGE_B_MOVE_VEC_LEN, StageBMoveBindError,
};
use crate::types::{GasBudgetMist, ObjectId};

// ===========================================================================
// 1. Move-side name constants (reuse + atom-#134 additions)
// ===========================================================================

/// Move function name for the owner-only root-minting entry point
/// (`public entry fun create_root(ctx: &mut TxContext)`, §4.3 line 300,
/// `prototype/move/sources/memory_root.move`). 11-byte ASCII.
pub const MNEMOS_MOVE_FUNCTION_CREATE_ROOT: &str = "create_root";

/// Move module name for the append-only audit log (`module
/// mnemos::audit_log`, §4.3 line 305). 9-byte ASCII.
pub const MNEMOS_MOVE_MODULE_AUDIT_LOG: &str = "audit_log";

/// Move function name for the owner-only audit append entry point
/// (`public entry fun append(log: &mut AuditLog, entry_hash: vector<u8>,
/// ctx)`, §4.3 line 309). 6-byte ASCII.
pub const MNEMOS_MOVE_FUNCTION_APPEND: &str = "append";

/// Canonical lowercase label for the single Stage B network. Local mirror
/// of `b-memory::StageBNetwork::CANONICAL_LABEL` (`"testnet"`), duplicated
/// here because `b-memory` is unreachable from `d-move` (cargo cycle — see
/// the module-level OD-A note). Parsing is ASCII-case-insensitive after
/// trimming surrounding whitespace, exactly as the canonical `parse_label`.
pub const STAGE_B_CALL_TESTNET_LABEL: &str = "testnet";

// ===========================================================================
// 2. Compile-time width pins (atom #20 precedent)
// ===========================================================================

/// Pins the `create_root` function name at 11 bytes; rename = build fail.
const _MNEMOS_MOVE_FUNCTION_CREATE_ROOT_LEN_IS_11: [(); 0 - !(MNEMOS_MOVE_FUNCTION_CREATE_ROOT
    .len()
    == 11) as usize] = [];

/// Pins the `audit_log` module name at 9 bytes; rename = build fail.
const _MNEMOS_MOVE_MODULE_AUDIT_LOG_LEN_IS_9: [(); 0 - !(MNEMOS_MOVE_MODULE_AUDIT_LOG.len() == 9)
    as usize] = [];

/// Pins the `append` function name at 6 bytes; rename = build fail.
const _MNEMOS_MOVE_FUNCTION_APPEND_LEN_IS_6: [(); 0 - !(MNEMOS_MOVE_FUNCTION_APPEND.len() == 6)
    as usize] = [];

// ===========================================================================
// 3a. #132/#133 BCS struct-parity wire lengths
//     (parity / replay EVIDENCE ONLY — NOT the PTB call-arg wire; see OD-B)
// ===========================================================================

/// Canonical BCS struct-parity length of a `MemoryRootAnchorArgs` with
/// `parent == None`. = 100. Pinned against atom #133's
/// `b3_12_anchor_args_bcs_parity_vector_parent_none` fixture. This is the
/// #132/#133 struct-parity wire (`root ‖ blob_id ‖ kind ‖ parent ‖ digest`),
/// retained for replay/parity testing — it is NOT what `add_chunk` is called
/// with (the real entry takes no serialized root and no digest).
pub const STAGE_B_ANCHOR_ARGS_BCS_LEN_PARENT_NONE: usize =
    STAGE_B_MOVE_VEC_LEN + (1 + STAGE_B_MOVE_VEC_LEN) + 1 + 1 + (1 + STAGE_B_MOVE_VEC_LEN);

/// Canonical BCS struct-parity length of a `MemoryRootAnchorArgs` with
/// `parent == Some`. = 132. Pinned against atom #133's
/// `b3_12_anchor_args_bcs_parity_vector_parent_some` fixture. Parity-only.
pub const STAGE_B_ANCHOR_ARGS_BCS_LEN_PARENT_SOME: usize = STAGE_B_MOVE_VEC_LEN
    + (1 + STAGE_B_MOVE_VEC_LEN)
    + 1
    + (1 + STAGE_B_MOVE_VEC_LEN)
    + (1 + STAGE_B_MOVE_VEC_LEN);

/// Canonical BCS struct-parity length of an `AuditAppendArgs`. = 65. Pinned
/// against atom #133's `b3_12_audit_append_args_bcs_parity_vector` fixture.
/// Parity-only (`log ‖ entry_hash`) — NOT the `append` call-arg wire.
pub const STAGE_B_AUDIT_APPEND_ARGS_BCS_LEN: usize =
    STAGE_B_MOVE_VEC_LEN + (1 + STAGE_B_MOVE_VEC_LEN);

/// Compile-time pin: anchor (parent-none) parity wire is 100 bytes (#133).
const _ANCHOR_NONE_BCS_LEN_IS_100: [(); 0 - !(STAGE_B_ANCHOR_ARGS_BCS_LEN_PARENT_NONE == 100)
    as usize] = [];
/// Compile-time pin: anchor (parent-some) parity wire is 132 bytes (#133).
const _ANCHOR_SOME_BCS_LEN_IS_132: [(); 0 - !(STAGE_B_ANCHOR_ARGS_BCS_LEN_PARENT_SOME == 132)
    as usize] = [];
/// Compile-time pin: audit-append parity wire is 65 bytes (#133).
const _AUDIT_APPEND_BCS_LEN_IS_65: [(); 0 - !(STAGE_B_AUDIT_APPEND_ARGS_BCS_LEN == 65) as usize] =
    [];

// ===========================================================================
// 3b. REAL PTB pure call-arg wire lengths (the add_chunk / append ABI)
// ===========================================================================

/// Pure call-arg wire length of `add_chunk` with `parent == None`. = 35.
/// `blob_id[vec 1+32] ‖ kind[u8 1] ‖ parent[empty vec 1]`. No root, no digest.
pub const STAGE_B_ADD_CHUNK_PURE_ARGS_LEN_PARENT_NONE: usize = (1 + STAGE_B_MOVE_VEC_LEN) + 1 + 1;

/// Pure call-arg wire length of `add_chunk` with `parent == Some`. = 67.
/// `blob_id[vec 1+32] ‖ kind[u8 1] ‖ parent[vec 1+32]`. No root, no digest.
pub const STAGE_B_ADD_CHUNK_PURE_ARGS_LEN_PARENT_SOME: usize =
    (1 + STAGE_B_MOVE_VEC_LEN) + 1 + (1 + STAGE_B_MOVE_VEC_LEN);

/// Pure call-arg wire length of `append`. = 33. `entry_hash[vec 1+32]`.
pub const STAGE_B_APPEND_PURE_ARGS_LEN: usize = 1 + STAGE_B_MOVE_VEC_LEN;

/// Compile-time pin: add_chunk pure args (parent-none) is 35 bytes.
const _ADD_CHUNK_PURE_NONE_IS_35: [(); 0 - !(STAGE_B_ADD_CHUNK_PURE_ARGS_LEN_PARENT_NONE == 35)
    as usize] = [];
/// Compile-time pin: add_chunk pure args (parent-some) is 67 bytes.
const _ADD_CHUNK_PURE_SOME_IS_67: [(); 0 - !(STAGE_B_ADD_CHUNK_PURE_ARGS_LEN_PARENT_SOME == 67)
    as usize] = [];
/// Compile-time pin: append pure args is 33 bytes.
const _APPEND_PURE_IS_33: [(); 0 - !(STAGE_B_APPEND_PURE_ARGS_LEN == 33) as usize] = [];

// ===========================================================================
// 3c. Dry-run envelope byte-size constants (Python-verified; test-pinned)
// ===========================================================================

/// Dry-run byte length: `package(32)` then `uleb(len(module)) + module`,
/// then `uleb(len(function)) + function`, then `uleb(num_object_inputs) + 32
/// * num_object_inputs`, then `pure_args_len`, then `gas_le(8)`. With
/// `num_object_inputs <= 1` the count uleb128 is always a single byte.
const fn dry_run_len_const(
    module: &str,
    function: &str,
    num_object_inputs: usize,
    pure_args_len: usize,
) -> usize {
    32 + 1 + module.len() + 1 + function.len() + 1 + (32 * num_object_inputs) + pure_args_len + 8
}

/// Total dry-run byte length of a `create_root` call (no object input, no
/// pure args). = 65. `32 + 1 + 11 + 1 + 11 + 1 + 0 + 0 + 8`.
pub const STAGE_B_CREATE_ROOT_DRY_RUN_LEN: usize = dry_run_len_const(
    MNEMOS_MOVE_MODULE_NAME,
    MNEMOS_MOVE_FUNCTION_CREATE_ROOT,
    0,
    0,
);

/// Total dry-run byte length of an `add_chunk` call, `parent == None`. = 130.
/// One object input (`root`) + 35-byte pure args.
pub const STAGE_B_ADD_CHUNK_DRY_RUN_LEN_PARENT_NONE: usize = dry_run_len_const(
    MNEMOS_MOVE_MODULE_NAME,
    MNEMOS_MOVE_FUNCTION_ADD_CHUNK,
    1,
    STAGE_B_ADD_CHUNK_PURE_ARGS_LEN_PARENT_NONE,
);

/// Total dry-run byte length of an `add_chunk` call, `parent == Some`. = 162.
/// One object input (`root`) + 67-byte pure args.
pub const STAGE_B_ADD_CHUNK_DRY_RUN_LEN_PARENT_SOME: usize = dry_run_len_const(
    MNEMOS_MOVE_MODULE_NAME,
    MNEMOS_MOVE_FUNCTION_ADD_CHUNK,
    1,
    STAGE_B_ADD_CHUNK_PURE_ARGS_LEN_PARENT_SOME,
);

/// Total dry-run byte length of an `audit_log::append` call. = 123.
/// One object input (`log`) + 33-byte pure args.
pub const STAGE_B_AUDIT_APPEND_DRY_RUN_LEN: usize = dry_run_len_const(
    MNEMOS_MOVE_MODULE_AUDIT_LOG,
    MNEMOS_MOVE_FUNCTION_APPEND,
    1,
    STAGE_B_APPEND_PURE_ARGS_LEN,
);

/// Compile-time pin: `create_root` dry-run is 65 bytes.
const _CREATE_ROOT_DRY_RUN_LEN_IS_65: [(); 0 - !(STAGE_B_CREATE_ROOT_DRY_RUN_LEN == 65) as usize] =
    [];
/// Compile-time pin: `add_chunk` (parent-none) dry-run is 130 bytes.
const _ADD_CHUNK_DRY_RUN_NONE_IS_130: [(); 0
    - !(STAGE_B_ADD_CHUNK_DRY_RUN_LEN_PARENT_NONE == 130) as usize] = [];
/// Compile-time pin: `add_chunk` (parent-some) dry-run is 162 bytes.
const _ADD_CHUNK_DRY_RUN_SOME_IS_162: [(); 0
    - !(STAGE_B_ADD_CHUNK_DRY_RUN_LEN_PARENT_SOME == 162) as usize] = [];
/// Compile-time pin: `append` dry-run is 123 bytes.
const _AUDIT_APPEND_DRY_RUN_IS_123: [(); 0 - !(STAGE_B_AUDIT_APPEND_DRY_RUN_LEN == 123) as usize] =
    [];

// ===========================================================================
// 4. Local network allowlist mirror (OD-A) + uleb128 / BCS helpers
// ===========================================================================

/// Accept ONLY the canonical testnet label, rejecting every other network
/// fail-closed with [`StageBMoveBindError::NetworkNotTestnet`]. ASCII
/// case-insensitive, surrounding whitespace trimmed — a verbatim local
/// mirror of `b-memory::StageBNetwork::parse_label` (unreachable from
/// `d-move`; see OD-A). The rejected raw label is NOT carried in the error
/// (the channel is `Copy`, dataless), so a non-testnet label cannot leak
/// through the return value.
#[inline]
fn require_testnet(network_label: &str) -> Result<(), StageBMoveBindError> {
    if network_label
        .trim()
        .eq_ignore_ascii_case(STAGE_B_CALL_TESTNET_LABEL)
    {
        Ok(())
    } else {
        Err(StageBMoveBindError::NetworkNotTestnet)
    }
}

/// Reject a zero gas budget with [`StageBMoveBindError::GasBudgetZero`]
/// before any byte work — Sui validators reject zero-budget transactions
/// (mirrors the atom #20 `add_chunk` gas guard, routed through the Stage B
/// error channel).
#[inline]
fn require_nonzero_gas(gas: GasBudgetMist) -> Result<(), StageBMoveBindError> {
    if gas.get() == 0 {
        Err(StageBMoveBindError::GasBudgetZero)
    } else {
        Ok(())
    }
}

/// Append a BCS `ULEB128` length prefix. For every Stage B call wire here
/// `len <= 32`, so this emits a single byte; the full loop is kept so the
/// encoder stays correct for any length. Local copy of the atom #133 /
/// atom #20 uleb128 idiom (kept local per the atom #11 sibling-layer
/// precedent — promote only if a fourth production consumer appears).
#[inline]
fn push_uleb128_len(out: &mut Vec<u8>, mut len: usize) {
    loop {
        let byte = (len & 0x7F) as u8;
        len >>= 7;
        if len != 0 {
            out.push(byte | 0x80);
        } else {
            out.push(byte);
            break;
        }
    }
}

/// Append a BCS `vector<u8>` = `ULEB128(len)` prefix + raw bytes.
#[inline]
fn push_vec_u8(out: &mut Vec<u8>, payload: &[u8]) {
    push_uleb128_len(out, payload.len());
    out.extend_from_slice(payload);
}

// ===========================================================================
// 5a. REAL PTB pure call-arg encoders (add_chunk / append ABI)
// ===========================================================================

/// Encode the REAL `add_chunk` pure call-arg wire from the atom #7
/// [`MoveAnchorArgsV1`] — `blob_id[vec] ‖ kind[u8] ‖ parent[vec]`, with
/// `parent == None` → the empty vector (`0x00`). This is the exact tuple the
/// Move entry `add_chunk(root, blob_id, kind, parent, ctx)` consumes (the
/// `root` object and `ctx` are NOT pure args). There is **no `digest`** in
/// this wire — `MemoryRootAnchorArgs::digest` is replay/evidence data, not an
/// `add_chunk` parameter. 35 bytes parent-none, 67 bytes parent-some.
pub fn encode_add_chunk_pure_args(anchor: &MoveAnchorArgsV1) -> Vec<u8> {
    let mut out: Vec<u8> = Vec::with_capacity(STAGE_B_ADD_CHUNK_PURE_ARGS_LEN_PARENT_SOME);
    // blob_id: vector<u8> (Move enforces length == 32).
    push_vec_u8(&mut out, &anchor.blob_id.0);
    // kind: u8 wire tag.
    out.push(anchor.kind.tag());
    // parent: vector<u8>; None → empty vector.
    match anchor.parent {
        Some(parent) => push_vec_u8(&mut out, &parent.0),
        None => push_vec_u8(&mut out, &[]),
    }
    out
}

/// Encode the REAL `append` pure call-arg wire — `entry_hash[vec]`. This is
/// the only pure argument the Move entry `append(log, entry_hash, ctx)`
/// consumes (the `log` object and `ctx` are NOT pure args). 33 bytes.
pub fn encode_append_pure_args(entry_hash: &[u8; STAGE_B_MOVE_VEC_LEN]) -> Vec<u8> {
    let mut out: Vec<u8> = Vec::with_capacity(STAGE_B_APPEND_PURE_ARGS_LEN);
    push_vec_u8(&mut out, entry_hash);
    out
}

// ===========================================================================
// 5b. #132/#133 BCS struct-parity encoders (PARITY / REPLAY EVIDENCE ONLY)
//     NOT the PTB call-arg wire — see OD-B + the #133 forward advisory.
// ===========================================================================

/// Encode a [`MemoryRootAnchorArgs`] to its #132/#133 BCS struct-parity wire,
/// reproducing the atom #133 layout byte-for-byte:
/// `root[32 raw] ‖ blob_id[vec] ‖ kind[u8] ‖ parent[vec] ‖ digest[vec]`.
/// `parent == None` → empty vector (`0x00`); 100 bytes parent-none, 132
/// bytes parent-some.
///
/// **This is replay/parity EVIDENCE, NOT the `add_chunk` PTB call args.** Per
/// the atom #133 forward advisory, the [`StageBCallBuilder`] must NOT use
/// this wire as call args (it would inject a serialized `root` and a phantom
/// `digest` the real entry never takes); the builder uses
/// [`encode_add_chunk_pure_args`] instead. This encoder exists so the #134
/// tests can keep cross-pinning the #133 fixture lengths/layout.
pub fn encode_anchor_args_bcs(args: &MemoryRootAnchorArgs) -> Vec<u8> {
    let anchor: &MoveAnchorArgsV1 = args.anchor();
    let mut out: Vec<u8> = Vec::with_capacity(STAGE_B_ANCHOR_ARGS_BCS_LEN_PARENT_SOME);
    // root: ObjectId / on-chain ID — 32 raw bytes, no length prefix.
    out.extend_from_slice(args.root().as_bytes());
    // anchor.blob_id: vector<u8>.
    push_vec_u8(&mut out, &anchor.blob_id.0);
    // anchor.kind: u8 wire tag.
    out.push(anchor.kind.tag());
    // anchor.parent: vector<u8>; None → empty vector.
    match anchor.parent {
        Some(parent) => push_vec_u8(&mut out, &parent.0),
        None => push_vec_u8(&mut out, &[]),
    }
    // digest: trailing vector<u8> (#133 OD-1) — parity evidence only.
    push_vec_u8(&mut out, args.digest());
    out
}

/// Encode an [`AuditAppendArgs`] to its #132/#133 BCS struct-parity wire,
/// reproducing the atom #133 layout byte-for-byte:
/// `log[32 raw] ‖ entry_hash[vec]`. 65 bytes.
///
/// **Replay/parity EVIDENCE, NOT the `append` PTB call args** (which carry
/// only `entry_hash`; `log` is an object input). The builder uses
/// [`encode_append_pure_args`].
pub fn encode_audit_append_args_bcs(args: &AuditAppendArgs) -> Vec<u8> {
    let mut out: Vec<u8> = Vec::with_capacity(STAGE_B_AUDIT_APPEND_ARGS_BCS_LEN);
    // log: ObjectId / on-chain ID — 32 raw bytes, no length prefix.
    out.extend_from_slice(args.log().as_bytes());
    // entry_hash: vector<u8>.
    push_vec_u8(&mut out, args.entry_hash());
    out
}

// ===========================================================================
// 6. Stage B call kind + builder
// ===========================================================================

/// Which Stage B Move entry function a [`StageBCallBuilder`] targets. The
/// `#[repr(u8)]` discriminants are stable diagnostic tags (not wire bytes).
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
#[repr(u8)]
pub enum StageBCallKind {
    /// `mnemos::memory_root::create_root` — mints a fresh root (no args).
    CreateRoot = 1,
    /// `mnemos::memory_root::add_chunk` — anchors a chunk.
    AddChunk = 2,
    /// `mnemos::audit_log::append` — appends an audit entry.
    AuditAppend = 3,
}

impl StageBCallKind {
    /// Stable u8 tag — mirrors the `#[repr(u8)]` discriminant.
    #[inline]
    pub const fn tag(self) -> u8 {
        self as u8
    }
}

/// A testnet-only, unsigned Stage B Move-call dry-run plan.
///
/// Built by one of the three constructors ([`StageBCallBuilder::create_root`],
/// [`StageBCallBuilder::add_chunk`], [`StageBCallBuilder::audit_append`]),
/// each of which refuses a non-testnet network and a zero gas budget before
/// any byte work. [`StageBCallBuilder::to_dry_run_bytes`] emits the
/// byte-stable measurement carrier; [`StageBCallBuilder::dry_run_len`]
/// records the planned transaction byte size (the atom criterion).
///
/// `object_inputs` holds the `&mut <Object>` PTB inputs (the `root` for
/// `add_chunk`, the `log` for `append`, none for `create_root`) as their
/// 32-byte object ids — kept SEPARATE from `args` so the pure call-arg wire
/// never serializes a struct's object id or a non-argument field. `args`
/// is the pure call-arg BCS (0 / 33 / 35 / 67 bytes). The `package` id is the
/// atom #20 [`MNEMOS_MEMORY_ROOT_PACKAGE_PLACEHOLDER`] (32 zero bytes) until
/// the operator-side testnet-deploy step fills the real `published-at`.
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct StageBCallBuilder {
    kind: StageBCallKind,
    package: ObjectId,
    module: &'static str,
    function: &'static str,
    object_inputs: Vec<ObjectId>,
    gas_budget: GasBudgetMist,
    args: Vec<u8>,
}

impl StageBCallBuilder {
    /// Build a testnet-only `create_root` dry-run plan (no object input, no
    /// call args). Rejects a non-testnet `network_label` with
    /// [`StageBMoveBindError::NetworkNotTestnet`] and a zero gas budget with
    /// [`StageBMoveBindError::GasBudgetZero`], in that order, before any
    /// byte work.
    pub fn create_root(
        network_label: &str,
        gas: GasBudgetMist,
    ) -> Result<Self, StageBMoveBindError> {
        require_testnet(network_label)?;
        require_nonzero_gas(gas)?;
        Ok(Self {
            kind: StageBCallKind::CreateRoot,
            package: MNEMOS_MEMORY_ROOT_PACKAGE_PLACEHOLDER,
            module: MNEMOS_MOVE_MODULE_NAME,
            function: MNEMOS_MOVE_FUNCTION_CREATE_ROOT,
            object_inputs: Vec::new(),
            gas_budget: gas,
            args: Vec::new(),
        })
    }

    /// Build a testnet-only `add_chunk` dry-run plan. The target `root`
    /// object id (from the atom #132 [`MemoryRootAnchorArgs`]) becomes the
    /// single object input; the pure call args are the REAL entry ABI
    /// `(blob_id, kind, parent)` via [`encode_add_chunk_pure_args`]. The
    /// struct's `digest` is replay/evidence data and is NOT placed on the
    /// call wire (atom #133 forward advisory). Network + gas gated as in
    /// [`StageBCallBuilder::create_root`].
    pub fn add_chunk(
        network_label: &str,
        args: &MemoryRootAnchorArgs,
        gas: GasBudgetMist,
    ) -> Result<Self, StageBMoveBindError> {
        require_testnet(network_label)?;
        require_nonzero_gas(gas)?;
        Ok(Self {
            kind: StageBCallKind::AddChunk,
            package: MNEMOS_MEMORY_ROOT_PACKAGE_PLACEHOLDER,
            module: MNEMOS_MOVE_MODULE_NAME,
            function: MNEMOS_MOVE_FUNCTION_ADD_CHUNK,
            object_inputs: vec![*args.root()],
            gas_budget: gas,
            args: encode_add_chunk_pure_args(args.anchor()),
        })
    }

    /// Build a testnet-only `audit_log::append` dry-run plan. The target
    /// `log` object id (from the atom #132 [`AuditAppendArgs`]) becomes the
    /// single object input; the pure call arg is the REAL entry ABI
    /// `entry_hash` via [`encode_append_pure_args`]. Network + gas gated as
    /// in [`StageBCallBuilder::create_root`].
    pub fn audit_append(
        network_label: &str,
        args: &AuditAppendArgs,
        gas: GasBudgetMist,
    ) -> Result<Self, StageBMoveBindError> {
        require_testnet(network_label)?;
        require_nonzero_gas(gas)?;
        Ok(Self {
            kind: StageBCallKind::AuditAppend,
            package: MNEMOS_MEMORY_ROOT_PACKAGE_PLACEHOLDER,
            module: MNEMOS_MOVE_MODULE_AUDIT_LOG,
            function: MNEMOS_MOVE_FUNCTION_APPEND,
            object_inputs: vec![*args.log()],
            gas_budget: gas,
            args: encode_append_pure_args(args.entry_hash()),
        })
    }

    /// Emit the byte-stable, unsigned dry-run representation of this call:
    /// `package[32] ‖ uleb128(len(module)) ‖ module ‖ uleb128(len(function))
    /// ‖ function ‖ uleb128(num_object_inputs) ‖ object_id[32] * n ‖
    /// pure_args ‖ gas_budget[u64 LE]`. Infallible — module / function names
    /// are compile-time constants `< 128` bytes and `num_object_inputs <= 1`,
    /// so every uleb128 prefix is one byte and no step can fail.
    ///
    /// This is a measurement-only carrier, NOT a signable Sui transaction
    /// (no intent prefix, no `TransactionData` wrapper, no owned-object
    /// version/digest — those are owned by future domain-G signing atoms).
    pub fn to_dry_run_bytes(&self) -> Vec<u8> {
        let mut out: Vec<u8> = Vec::with_capacity(self.dry_run_len());
        out.extend_from_slice(self.package.as_bytes());
        push_uleb128_len(&mut out, self.module.len());
        out.extend_from_slice(self.module.as_bytes());
        push_uleb128_len(&mut out, self.function.len());
        out.extend_from_slice(self.function.as_bytes());
        push_uleb128_len(&mut out, self.object_inputs.len());
        for obj in &self.object_inputs {
            out.extend_from_slice(obj.as_bytes());
        }
        out.extend_from_slice(&self.args);
        out.extend_from_slice(&self.gas_budget.get().to_le_bytes());
        out
    }

    /// The planned transaction byte size (atom criterion: "tx byte size
    /// recorded"). Equals `to_dry_run_bytes().len()` without allocating —
    /// module / function uleb128 prefixes and the object-input count are one
    /// byte each (`< 128`).
    #[inline]
    pub fn dry_run_len(&self) -> usize {
        32 + 1
            + self.module.len()
            + 1
            + self.function.len()
            + 1
            + (32 * self.object_inputs.len())
            + self.args.len()
            + 8
    }

    /// The call kind this builder targets.
    #[inline]
    pub const fn kind(&self) -> StageBCallKind {
        self.kind
    }

    /// Borrow the on-builder package [`ObjectId`].
    #[inline]
    pub const fn package(&self) -> &ObjectId {
        &self.package
    }

    /// The Move module name (`"memory_root"` or `"audit_log"`).
    #[inline]
    pub const fn module(&self) -> &'static str {
        self.module
    }

    /// The Move function name.
    #[inline]
    pub const fn function(&self) -> &'static str {
        self.function
    }

    /// Borrow the `&mut <Object>` PTB object inputs (the `root` for
    /// `add_chunk`, the `log` for `append`, empty for `create_root`).
    #[inline]
    pub fn object_inputs(&self) -> &[ObjectId] {
        &self.object_inputs
    }

    /// The typed gas budget the caller supplied.
    #[inline]
    pub const fn gas_budget(&self) -> GasBudgetMist {
        self.gas_budget
    }

    /// Borrow the pre-encoded pure call-arg BCS wire (empty for
    /// `create_root`). Does NOT include object inputs (see
    /// [`StageBCallBuilder::object_inputs`]).
    #[inline]
    pub fn args(&self) -> &[u8] {
        &self.args
    }
}

// ===========================================================================
// 7. Inline unit tests
// ===========================================================================

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use mnemos_c_walrus::{BlobId, ChunkKind};

    fn gas() -> GasBudgetMist {
        GasBudgetMist::new(800_000)
    }

    fn anchor_args(parent: Option<u8>) -> MemoryRootAnchorArgs {
        let anchor = MoveAnchorArgsV1 {
            blob_id: BlobId([0x22u8; 32]),
            kind: ChunkKind::UserMessage,
            parent: parent.map(|b| BlobId([b; 32])),
        };
        MemoryRootAnchorArgs::new(ObjectId::new([0x11u8; 32]), anchor, [0x33u8; 32])
    }

    fn audit_args() -> AuditAppendArgs {
        AuditAppendArgs::new(ObjectId::new([0x88u8; 32]), [0x99u8; 32])
    }

    // ---- ATOM_PLAN line 976 test #1 — "build calls" -----------------------

    #[test]
    fn b3_13_build_calls_all_three_kinds_on_testnet() {
        let cr = StageBCallBuilder::create_root("testnet", gas()).unwrap();
        assert_eq!(cr.kind(), StageBCallKind::CreateRoot);
        assert_eq!(cr.module(), "memory_root");
        assert_eq!(cr.function(), "create_root");
        assert!(cr.args().is_empty());
        assert!(cr.object_inputs().is_empty()); // create_root mints, no input

        let ac = StageBCallBuilder::add_chunk("testnet", &anchor_args(None), gas()).unwrap();
        assert_eq!(ac.kind(), StageBCallKind::AddChunk);
        assert_eq!(ac.module(), "memory_root");
        assert_eq!(ac.function(), "add_chunk");
        assert_eq!(ac.object_inputs(), &[ObjectId::new([0x11u8; 32])]); // root input

        let ap = StageBCallBuilder::audit_append("testnet", &audit_args(), gas()).unwrap();
        assert_eq!(ap.kind(), StageBCallKind::AuditAppend);
        assert_eq!(ap.module(), "audit_log");
        assert_eq!(ap.function(), "append");
        assert_eq!(ap.object_inputs(), &[ObjectId::new([0x88u8; 32])]); // log input

        // Package id is the atom #20 placeholder (32 zero bytes) on all three.
        for b in [&cr, &ac, &ap] {
            assert_eq!(b.package().as_bytes(), &[0u8; 32]);
            assert_eq!(b.gas_budget().get(), 800_000);
        }
    }

    // ---- ATOM_PLAN line 976 test #2 — "gas zero reject" -------------------

    #[test]
    fn b3_13_gas_zero_rejected_on_all_three_before_byte_work() {
        let zero = GasBudgetMist::new(0);
        assert_eq!(
            StageBCallBuilder::create_root("testnet", zero),
            Err(StageBMoveBindError::GasBudgetZero)
        );
        assert_eq!(
            StageBCallBuilder::add_chunk("testnet", &anchor_args(None), zero),
            Err(StageBMoveBindError::GasBudgetZero)
        );
        assert_eq!(
            StageBCallBuilder::audit_append("testnet", &audit_args(), zero),
            Err(StageBMoveBindError::GasBudgetZero)
        );
    }

    // ---- ATOM_PLAN line 976 test #3 — "mainnet reject" --------------------

    #[test]
    fn b3_13_mainnet_and_every_non_testnet_label_rejected() {
        // The headline mainnet reject.
        assert_eq!(
            StageBCallBuilder::create_root("mainnet", gas()),
            Err(StageBMoveBindError::NetworkNotTestnet)
        );
        // Network is checked BEFORE gas: a mainnet + zero-gas call reports
        // the network reject (fail-closed at the outer guard).
        assert_eq!(
            StageBCallBuilder::create_root("mainnet", GasBudgetMist::new(0)),
            Err(StageBMoveBindError::NetworkNotTestnet)
        );
        for bad in [
            "mainnet", "devnet", "localnet", "MAINNET", "", "test", "testnetx", "sui",
        ] {
            assert_eq!(
                StageBCallBuilder::add_chunk(bad, &anchor_args(None), gas()),
                Err(StageBMoveBindError::NetworkNotTestnet),
                "label {bad:?} must be rejected"
            );
            assert_eq!(
                StageBCallBuilder::audit_append(bad, &audit_args(), gas()),
                Err(StageBMoveBindError::NetworkNotTestnet),
                "label {bad:?} must be rejected"
            );
        }
    }

    #[test]
    fn b3_13_testnet_label_is_case_insensitive_and_trimmed() {
        for ok in ["testnet", "Testnet", "TESTNET", "  testnet ", "\ttestnet\n"] {
            assert!(
                StageBCallBuilder::create_root(ok, gas()).is_ok(),
                "label {ok:?} must be accepted"
            );
        }
    }

    // ---- criterion — "tx byte size recorded" (real-ABI wire) --------------

    #[test]
    fn b3_13_dry_run_tx_byte_sizes_are_recorded() {
        let cr = StageBCallBuilder::create_root("testnet", gas()).unwrap();
        assert_eq!(cr.dry_run_len(), STAGE_B_CREATE_ROOT_DRY_RUN_LEN);
        assert_eq!(cr.dry_run_len(), 65);
        assert_eq!(cr.to_dry_run_bytes().len(), 65);

        let ac_none = StageBCallBuilder::add_chunk("testnet", &anchor_args(None), gas()).unwrap();
        assert_eq!(
            ac_none.dry_run_len(),
            STAGE_B_ADD_CHUNK_DRY_RUN_LEN_PARENT_NONE
        );
        assert_eq!(ac_none.dry_run_len(), 130);
        assert_eq!(ac_none.to_dry_run_bytes().len(), 130);

        let ac_some =
            StageBCallBuilder::add_chunk("testnet", &anchor_args(Some(0x66)), gas()).unwrap();
        assert_eq!(
            ac_some.dry_run_len(),
            STAGE_B_ADD_CHUNK_DRY_RUN_LEN_PARENT_SOME
        );
        assert_eq!(ac_some.dry_run_len(), 162);
        assert_eq!(ac_some.to_dry_run_bytes().len(), 162);

        let ap = StageBCallBuilder::audit_append("testnet", &audit_args(), gas()).unwrap();
        assert_eq!(ap.dry_run_len(), STAGE_B_AUDIT_APPEND_DRY_RUN_LEN);
        assert_eq!(ap.dry_run_len(), 123);
        assert_eq!(ap.to_dry_run_bytes().len(), 123);
    }

    // ---- REAL ABI lock: pure args carry (blob_id, kind, parent) only ------

    #[test]
    fn b3_13_add_chunk_pure_args_are_blob_kind_parent_only_no_root_no_digest() {
        let args = anchor_args(None);
        let pure = encode_add_chunk_pure_args(args.anchor());
        // 35 bytes: uleb(32) ‖ blob_id[32] ‖ kind ‖ uleb(0).
        assert_eq!(pure.len(), STAGE_B_ADD_CHUNK_PURE_ARGS_LEN_PARENT_NONE);
        assert_eq!(pure.len(), 35);
        assert_eq!(pure[0], 0x20); // ULEB128(32) blob_id prefix
        assert_eq!(&pure[1..33], &[0x22u8; 32]); // blob_id
        assert_eq!(pure[33], ChunkKind::UserMessage.tag()); // kind = 1
        assert_eq!(pure[34], 0x00); // parent None → empty vector
        // The root object id (0x11*32) and the digest (0x33*32) MUST NOT
        // appear anywhere in the pure call-arg wire (the #133 advisory).
        assert!(
            !pure.windows(32).any(|w| w == [0x11u8; 32]),
            "root must not be serialized into pure add_chunk args"
        );
        assert!(
            !pure.windows(32).any(|w| w == [0x33u8; 32]),
            "digest must not be serialized into add_chunk args"
        );

        // parent = Some → 67 bytes, with parent bytes present.
        let some = encode_add_chunk_pure_args(anchor_args(Some(0x66)).anchor());
        assert_eq!(some.len(), STAGE_B_ADD_CHUNK_PURE_ARGS_LEN_PARENT_SOME);
        assert_eq!(some.len(), 67);
        assert_eq!(some[34], 0x20); // parent Some → ULEB128(32) prefix
        assert_eq!(&some[35..67], &[0x66u8; 32]); // parent bytes
        assert!(
            !some.windows(32).any(|w| w == [0x33u8; 32]),
            "digest must not appear even with a parent"
        );
    }

    #[test]
    fn b3_13_full_add_chunk_dry_run_excludes_digest_and_separates_root() {
        let bytes = StageBCallBuilder::add_chunk("testnet", &anchor_args(Some(0x66)), gas())
            .unwrap()
            .to_dry_run_bytes();
        // root present exactly once, as the object input (not in pure args).
        let root_hits = bytes.windows(32).filter(|w| *w == [0x11u8; 32]).count();
        assert_eq!(root_hits, 1, "root appears once, as the object input");
        // digest never appears on the call wire.
        assert!(
            !bytes.windows(32).any(|w| w == [0x33u8; 32]),
            "digest must never be on the add_chunk call wire"
        );
    }

    // ---- #133 struct-parity EVIDENCE is preserved (NOT the call wire) -----

    #[test]
    fn b3_13_anchor_bcs_matches_atom_133_layout_and_lengths() {
        // parent = None → 100 bytes (atom #133
        // b3_12_anchor_args_bcs_parity_vector_parent_none). Parity evidence.
        let none = encode_anchor_args_bcs(&anchor_args(None));
        assert_eq!(none.len(), 100);
        assert_eq!(none.len(), STAGE_B_ANCHOR_ARGS_BCS_LEN_PARENT_NONE);
        // Field boundaries (mirror of #133 b3_12_anchor_wire_field_boundaries).
        assert_eq!(&none[0..32], &[0x11u8; 32]); // root
        assert_eq!(none[32], 0x20); // ULEB128(32) blob_id prefix
        assert_eq!(&none[33..65], &[0x22u8; 32]); // blob_id
        assert_eq!(none[65], ChunkKind::UserMessage.tag()); // kind = 1
        assert_eq!(none[66], 0x00); // parent None → empty vector
        assert_eq!(none[67], 0x20); // ULEB128(32) digest prefix
        assert_eq!(&none[68..100], &[0x33u8; 32]); // digest

        // parent = Some → 132 bytes.
        let some = encode_anchor_args_bcs(&anchor_args(Some(0x66)));
        assert_eq!(some.len(), 132);
        assert_eq!(some.len(), STAGE_B_ANCHOR_ARGS_BCS_LEN_PARENT_SOME);
        assert_eq!(some[66], 0x20); // parent Some → ULEB128(32) prefix
        assert_eq!(&some[67..99], &[0x66u8; 32]); // parent bytes
    }

    #[test]
    fn b3_13_audit_bcs_matches_atom_133_layout_and_length() {
        // 65 bytes (atom #133 b3_12_audit_append_args_bcs_parity_vector).
        let e = encode_audit_append_args_bcs(&audit_args());
        assert_eq!(e.len(), 65);
        assert_eq!(e.len(), STAGE_B_AUDIT_APPEND_ARGS_BCS_LEN);
        assert_eq!(&e[0..32], &[0x88u8; 32]); // log
        assert_eq!(e[32], 0x20); // ULEB128(32) entry_hash prefix
        assert_eq!(&e[33..65], &[0x99u8; 32]); // entry_hash
    }

    // ---- dry-run envelope byte layout (append, real-ABI) ------------------

    #[test]
    fn b3_13_dry_run_envelope_layout_is_exact() {
        let ap = StageBCallBuilder::audit_append("testnet", &audit_args(), gas()).unwrap();
        let bytes = ap.to_dry_run_bytes();
        // [0..32] package placeholder
        assert_eq!(&bytes[0..32], &[0u8; 32]);
        // [32] uleb128(9) module-len, [33..42] "audit_log"
        assert_eq!(bytes[32], 9);
        assert_eq!(&bytes[33..42], b"audit_log");
        // [42] uleb128(6) function-len, [43..49] "append"
        assert_eq!(bytes[42], 6);
        assert_eq!(&bytes[43..49], b"append");
        // [49] uleb128(1) object-input count, [50..82] log object id
        assert_eq!(bytes[49], 1);
        assert_eq!(&bytes[50..82], &[0x88u8; 32]);
        // [82..115] pure args entry_hash vector (uleb(32) ‖ 32 bytes)
        assert_eq!(bytes[82], 0x20);
        assert_eq!(&bytes[83..115], &[0x99u8; 32]);
        assert_eq!(&bytes[82..115], &encode_append_pure_args(&[0x99u8; 32])[..]);
        // [115..123] gas LE
        assert_eq!(&bytes[115..123], &800_000u64.to_le_bytes());
    }

    // ---- determinism + no-signing surface ---------------------------------

    #[test]
    fn b3_13_dry_run_bytes_are_deterministic() {
        let a = StageBCallBuilder::add_chunk("testnet", &anchor_args(None), gas()).unwrap();
        let b = StageBCallBuilder::add_chunk("testnet", &anchor_args(None), gas()).unwrap();
        assert_eq!(a.to_dry_run_bytes(), b.to_dry_run_bytes());
    }

    #[test]
    fn b3_13_gas_slot_is_the_only_variation_for_fixed_call() {
        let small =
            StageBCallBuilder::audit_append("testnet", &audit_args(), GasBudgetMist::new(1))
                .unwrap()
                .to_dry_run_bytes();
        let large =
            StageBCallBuilder::audit_append("testnet", &audit_args(), GasBudgetMist::new(800_000))
                .unwrap()
                .to_dry_run_bytes();
        assert_eq!(&small[..115], &large[..115]);
        assert_eq!(&small[115..123], &1u64.to_le_bytes());
        assert_eq!(&large[115..123], &800_000u64.to_le_bytes());
    }

    #[test]
    fn b3_13_call_kind_tags_are_stable_and_unique() {
        assert_eq!(StageBCallKind::CreateRoot.tag(), 1);
        assert_eq!(StageBCallKind::AddChunk.tag(), 2);
        assert_eq!(StageBCallKind::AuditAppend.tag(), 3);
    }
}
