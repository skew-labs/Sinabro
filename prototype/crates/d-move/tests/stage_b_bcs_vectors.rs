//! atom #133 · B.3.12 — Stage B Rust↔Move BCS parity vectors (Rust side).
//!
//! Canonical OUT (ATOM_PLAN line 963): "Rust/Move BCS parity fixtures". The
//! companion Move test `prototype/move/tests/bcs_vectors.move` decodes the
//! SAME byte sequences with `sui::bcs` and asserts every field; an
//! independent Python oracle
//! (`ops/evidence/stage_b/atom_133/oracle_bcs_stage_b_args_v0.py`) reproduces
//! the identical hex, closing the Rust↔Python↔Move byte-level loop (atom #15
//! `d0_1_bcs_parity_vector` / `oracle_bcs_memory_root_v0.py` precedent).
//!
//! ## OD-1 (atom #133, grounded Option-A call — #132 OD-1/OD-2 + CLAUDE.md §10)
//!
//! §4.3 (ATOM_PLAN lines 313-316) fixes the Rust struct shapes
//! ([`MemoryRootAnchorArgs`] / [`AuditAppendArgs`], reuse from atom #132) and
//! the Move struct/function shapes, but does NOT fix the byte-level BCS wire.
//! Defining that wire is this atom's canonical OUT. The wire MIRRORS the
//! Move §4.3 field types (the chain-truth side the parity locks against), and
//! follows the BCS convention already committed by `audit_log.move` lines
//! 224-238 (the `AuditAppended` 105-byte pin: `ID`/`address` = 32 raw bytes
//! with NO length prefix; `vector<u8>` = `ULEB128(len)` prefix + bytes;
//! `u64` = 8 bytes LE):
//!
//! - `root` / `log` (`ObjectId`, on-chain `ID`): 32 RAW bytes, no prefix
//!   (`sui::bcs::peel_address`).
//! - `anchor.blob_id` / `anchor.parent` / `entry_hash` / `digest`
//!   (`vector<u8>`): `ULEB128(len)` + bytes (`sui::bcs::peel_vec_u8`).
//!   `len == 32` for the populated case → prefix byte `0x20`.
//! - `anchor.kind` (`u8` wire tag, [`ChunkKind::tag`]): 1 byte
//!   (`sui::bcs::peel_u8`).
//! - `anchor.parent == None`: the empty `vector<u8>` → `ULEB128(0)` = `0x00`,
//!   matching the `memory_root.move` "empty parent = no parent" convention.
//!
//! The single extrapolation flagged for the Session 2 verifier (ACCEPT or
//! RAISE): `digest` has NO `add_chunk` Move argument (`memory_root.move`
//! line 165), so it is encoded as a TRAILING `vector<u8>(32)` by analogy to
//! the other 32-byte content fields. The Rust mirror of the *event* byte
//! values (`ChunkAnchored` / `AuditAppended`) is a separate, future surface
//! (atoms #137 / #140 per `audit_log.move` line 238) and is NOT this atom.
//!
//! No production code is touched by this atom — both files are test-only.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use mnemos_c_walrus::{BlobId, ChunkKind, MoveAnchorArgsV1};
use mnemos_d_move::stage_b_types::{AuditAppendArgs, MemoryRootAnchorArgs};
use mnemos_d_move::types::ObjectId;

// ===========================================================================
// Canonical encoders (the "Rust encodes vector" side of ATOM_PLAN line 965).
// These build the canonical BCS wire from the typed atom-#132 args using only
// the public accessor surface — no serde, mirroring the manual fixed-width
// encoder style of `d-move::types::encode_memory_root_args_bcs` (atom #15).
// ===========================================================================

/// Append a BCS `ULEB128` length prefix for `len`. For every fixture here
/// `len <= 32`, so this emits a single byte (`0x00..=0x20`); the full loop is
/// kept so the encoder is correct for any length.
fn push_uleb128(out: &mut Vec<u8>, mut len: usize) {
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
fn push_vec_u8(out: &mut Vec<u8>, payload: &[u8]) {
    push_uleb128(out, payload.len());
    out.extend_from_slice(payload);
}

/// Encode a [`MemoryRootAnchorArgs`] to its canonical BCS wire (OD-1).
/// Layout: `root[32 raw] ‖ blob_id[vec] ‖ kind[u8] ‖ parent[vec] ‖ digest[vec]`.
fn encode_anchor_args_bcs(a: &MemoryRootAnchorArgs) -> Vec<u8> {
    let mut out = Vec::new();
    // root: ObjectId / ID — 32 raw bytes, no length prefix.
    out.extend_from_slice(a.root().as_bytes());
    // anchor.blob_id: vector<u8>.
    push_vec_u8(&mut out, &a.anchor().blob_id.0);
    // anchor.kind: u8 wire tag.
    out.push(a.anchor().kind.tag());
    // anchor.parent: vector<u8>; None → empty vector.
    match a.anchor().parent {
        Some(parent) => push_vec_u8(&mut out, &parent.0),
        None => push_vec_u8(&mut out, &[]),
    }
    // digest: vector<u8> (OD-1 trailing field).
    push_vec_u8(&mut out, a.digest());
    out
}

/// Encode an [`AuditAppendArgs`] to its canonical BCS wire (OD-1).
/// Layout: `log[32 raw] ‖ entry_hash[vec]`.
fn encode_audit_append_args_bcs(a: &AuditAppendArgs) -> Vec<u8> {
    let mut out = Vec::new();
    // log: ObjectId / ID — 32 raw bytes, no length prefix.
    out.extend_from_slice(a.log().as_bytes());
    // entry_hash: vector<u8>.
    push_vec_u8(&mut out, a.entry_hash());
    out
}

// ===========================================================================
// Hex helper — lets Session 2 / future readers eyeball the bytes and pins the
// fixture string itself (so a re-encoding drift flips a visible literal).
// ===========================================================================

fn to_hex(bytes: &[u8]) -> String {
    const NIB: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        s.push(NIB[(b >> 4) as usize] as char);
        s.push(NIB[(b & 0x0F) as usize] as char);
    }
    s
}

// Golden hex fixtures — IDENTICAL bytes to `move/tests/bcs_vectors.move` and
// to the Python oracle output. Any drift in the encoder flips one of these.
const AUDIT_HEX: &str = "8888888888888888888888888888888888888888888888888888888888888888209999999999999999999999999999999999999999999999999999999999999999";
const ANCHOR_NONE_HEX: &str = "11111111111111111111111111111111111111111111111111111111111111112022222222222222222222222222222222222222222222222222222222222222220100203333333333333333333333333333333333333333333333333333333333333333";
const ANCHOR_SOME_HEX: &str = "444444444444444444444444444444444444444444444444444444444444444420555555555555555555555555555555555555555555555555555555555555555503206666666666666666666666666666666666666666666666666666666666666666207777777777777777777777777777777777777777777777777777777777777777";

// ===========================================================================
// Fixture builders
// ===========================================================================

fn anchor_args(
    root: u8,
    blob: u8,
    kind: ChunkKind,
    parent: Option<u8>,
    digest: u8,
) -> MemoryRootAnchorArgs {
    let anchor = MoveAnchorArgsV1 {
        blob_id: BlobId([blob; 32]),
        kind,
        parent: parent.map(|b| BlobId([b; 32])),
    };
    MemoryRootAnchorArgs::new(ObjectId::new([root; 32]), anchor, [digest; 32])
}

// ===========================================================================
// ATOM_PLAN line 965 — "Rust encodes vector" + "fixture stable"
// ===========================================================================

/// MemoryRootAnchorArgs parity vector, `parent = None` (empty-vector path —
/// the only variable-width field at its minimum width). 100 bytes.
#[test]
fn b3_12_anchor_args_bcs_parity_vector_parent_none() {
    let args = anchor_args(0x11, 0x22, ChunkKind::UserMessage, None, 0x33);
    let encoded = encode_anchor_args_bcs(&args);

    assert_eq!(
        encoded.len(),
        100,
        "parent-none anchor wire must be 100 bytes"
    );
    assert_eq!(to_hex(&encoded), ANCHOR_NONE_HEX);
}

/// MemoryRootAnchorArgs parity vector, `parent = Some` (32-byte-vector path —
/// the variable-width field at its populated width). 132 bytes.
#[test]
fn b3_12_anchor_args_bcs_parity_vector_parent_some() {
    let args = anchor_args(0x44, 0x55, ChunkKind::SystemMemory, Some(0x66), 0x77);
    let encoded = encode_anchor_args_bcs(&args);

    assert_eq!(
        encoded.len(),
        132,
        "parent-some anchor wire must be 132 bytes"
    );
    assert_eq!(to_hex(&encoded), ANCHOR_SOME_HEX);
}

/// AuditAppendArgs parity vector. 65 bytes = `log[32 raw] ‖ 0x20 ‖ hash[32]`.
#[test]
fn b3_12_audit_append_args_bcs_parity_vector() {
    let args = AuditAppendArgs::new(ObjectId::new([0x88; 32]), [0x99; 32]);
    let encoded = encode_audit_append_args_bcs(&args);

    assert_eq!(encoded.len(), 65, "audit-append wire must be 65 bytes");
    assert_eq!(to_hex(&encoded), AUDIT_HEX);
}

/// Field-boundary pin — proves the parity is not a coincidence of uniform
/// bytes: each declared sub-range carries exactly the source field's bytes,
/// including the `ULEB128(32)=0x20` prefixes and the `0x00` empty-parent and
/// the `kind` tag byte, in source-declaration order.
#[test]
fn b3_12_anchor_wire_field_boundaries_are_exact() {
    let args = anchor_args(0x11, 0x22, ChunkKind::UserMessage, None, 0x33);
    let e = encode_anchor_args_bcs(&args);

    assert_eq!(&e[0..32], &[0x11u8; 32]); // root (32 raw, no prefix)
    assert_eq!(e[32], 0x20); // ULEB128(32) prefix for blob_id
    assert_eq!(&e[33..65], &[0x22u8; 32]); // blob_id bytes
    assert_eq!(e[65], ChunkKind::UserMessage.tag()); // kind tag (= 1)
    assert_eq!(e[66], 0x00); // parent None → empty vector ULEB128(0)
    assert_eq!(e[67], 0x20); // ULEB128(32) prefix for digest
    assert_eq!(&e[68..100], &[0x33u8; 32]); // digest bytes
}

/// `kind` tag round-trips through the wire for every `ChunkKind` variant —
/// guards against a tag-table drift between `c-walrus::ChunkKind` and the
/// Move-side `kind: u8`.
#[test]
fn b3_12_kind_tag_byte_matches_chunk_kind() {
    for (kind, tag) in [
        (ChunkKind::UserMessage, 1u8),
        (ChunkKind::AssistantMessage, 2),
        (ChunkKind::SystemMemory, 3),
        (ChunkKind::ToolResult, 4),
        (ChunkKind::SkillArtifact, 5),
    ] {
        let args = anchor_args(0x00, 0x00, kind, None, 0x00);
        let e = encode_anchor_args_bcs(&args);
        // kind byte sits right after root(32) + blob_id(1 prefix + 32).
        assert_eq!(e[65], tag, "{kind:?} tag byte mismatch");
        assert_eq!(kind.tag(), tag);
    }
}
