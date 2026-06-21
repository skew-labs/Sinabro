// atom #133 · B.3.12 — Stage B Rust↔Move BCS parity vectors (Move side).
//
// Canonical OUT (ATOM_PLAN line 963): "Rust/Move BCS parity fixtures". This
// module decodes the SAME byte sequences that the Rust side encodes in
// `prototype/crates/d-move/tests/stage_b_bcs_vectors.rs` and that the Python
// oracle `ops/evidence/stage_b/atom_133/oracle_bcs_stage_b_args_v0.py`
// reproduces — proving the cross-language schema lock. "Move test decodes,
// fixture stable" (ATOM_PLAN line 965).
//
// Canonical wire (OD-1 grounded Option-A call; see the Rust file's module doc
// + ops/evidence/stage_b/atom_133/SESSION_1_IMPLEMENTED.md). Mirrors Move 4.3
// field types using the BCS convention committed by audit_log.move 224-238:
//   - root / log (ID):                  32 RAW bytes, no prefix  -> peel_address
//   - blob_id / parent / entry_hash /   vector<u8> = ULEB128+bytes -> peel_vec_u8
//       digest
//   - kind:                             u8 = 1 byte              -> peel_u8
//   - parent == None:                   empty vector<u8> = 0x00
//
// This is a test-only module under the package `tests/` directory; it adds no
// production Move surface (no struct, no entry fun, no field).

#[test_only]
module mnemos::bcs_vectors;

use sui::address;
use sui::bcs;

// ===========================================================================
// Fixture builders — produce the IDENTICAL bytes to the Rust encoder + oracle.
// ===========================================================================

/// A 32-byte `vector<u8>` all equal to `b` (mirrors memory_root.move
/// `fixture_blob_id_32`).
fun raw32(b: u8): vector<u8> {
    let mut v: vector<u8> = vector[];
    let mut i = 0u64;
    while (i < 32) {
        v.push_back(b);
        i = i + 1;
    };
    v
}

/// MemoryRootAnchorArgs wire, `parent = None` (100 bytes).
/// root[32] ‖ 0x20 ‖ blob_id[32] ‖ kind ‖ 0x00 ‖ 0x20 ‖ digest[32].
fun anchor_fixture_parent_none(): vector<u8> {
    let mut b: vector<u8> = vector[];
    b.append(raw32(0x11)); // root (ID, 32 raw)
    b.push_back(0x20); // ULEB128(32) prefix for blob_id
    b.append(raw32(0x22)); // blob_id bytes
    b.push_back(0x01); // kind = UserMessage
    b.push_back(0x00); // parent None → empty vector ULEB128(0)
    b.push_back(0x20); // ULEB128(32) prefix for digest
    b.append(raw32(0x33)); // digest bytes
    b
}

/// MemoryRootAnchorArgs wire, `parent = Some` (132 bytes).
/// root[32] ‖ 0x20 ‖ blob_id[32] ‖ kind ‖ 0x20 ‖ parent[32] ‖ 0x20 ‖ digest[32].
fun anchor_fixture_parent_some(): vector<u8> {
    let mut b: vector<u8> = vector[];
    b.append(raw32(0x44)); // root
    b.push_back(0x20); // ULEB128(32) prefix for blob_id
    b.append(raw32(0x55)); // blob_id
    b.push_back(0x03); // kind = SystemMemory
    b.push_back(0x20); // ULEB128(32) prefix for parent
    b.append(raw32(0x66)); // parent bytes
    b.push_back(0x20); // ULEB128(32) prefix for digest
    b.append(raw32(0x77)); // digest
    b
}

/// AuditAppendArgs wire (65 bytes). log[32] ‖ 0x20 ‖ entry_hash[32].
fun audit_fixture(): vector<u8> {
    let mut b: vector<u8> = vector[];
    b.append(raw32(0x88)); // log (ID, 32 raw)
    b.push_back(0x20); // ULEB128(32) prefix for entry_hash
    b.append(raw32(0x99)); // entry_hash bytes
    b
}

// ===========================================================================
// ATOM_PLAN line 965 — "Move test decodes, fixture stable"
// ===========================================================================

#[test]
fun b3_12_anchor_args_bcs_decode_parent_none() {
    let bytes = anchor_fixture_parent_none();
    assert!(bytes.length() == 100, 100);

    let mut b = bcs::new(bytes);
    // root: 32 raw bytes via peel_address (no length prefix).
    let root = b.peel_address();
    assert!(address::to_bytes(root) == raw32(0x11), 101);
    // anchor.blob_id: vector<u8>.
    let blob_id = b.peel_vec_u8();
    assert!(blob_id == raw32(0x22), 102);
    // anchor.kind: u8 wire tag.
    let kind = b.peel_u8();
    assert!(kind == 0x01, 103);
    // anchor.parent: empty vector<u8> (None).
    let parent = b.peel_vec_u8();
    assert!(parent.is_empty(), 104);
    // digest: vector<u8>.
    let digest = b.peel_vec_u8();
    assert!(digest == raw32(0x33), 105);
    // Nothing left over — the wire is fully consumed.
    let rest = b.into_remainder_bytes();
    assert!(rest.is_empty(), 106);
}

#[test]
fun b3_12_anchor_args_bcs_decode_parent_some() {
    let bytes = anchor_fixture_parent_some();
    assert!(bytes.length() == 132, 200);

    let mut b = bcs::new(bytes);
    let root = b.peel_address();
    assert!(address::to_bytes(root) == raw32(0x44), 201);
    let blob_id = b.peel_vec_u8();
    assert!(blob_id == raw32(0x55), 202);
    let kind = b.peel_u8();
    assert!(kind == 0x03, 203);
    let parent = b.peel_vec_u8();
    assert!(parent == raw32(0x66), 204);
    let digest = b.peel_vec_u8();
    assert!(digest == raw32(0x77), 205);
    let rest = b.into_remainder_bytes();
    assert!(rest.is_empty(), 206);
}

#[test]
fun b3_12_audit_append_args_bcs_decode() {
    let bytes = audit_fixture();
    assert!(bytes.length() == 65, 300);

    let mut b = bcs::new(bytes);
    // log: 32 raw bytes (ID, no length prefix).
    let log = b.peel_address();
    assert!(address::to_bytes(log) == raw32(0x88), 301);
    // entry_hash: vector<u8>.
    let entry_hash = b.peel_vec_u8();
    assert!(entry_hash == raw32(0x99), 302);
    let rest = b.into_remainder_bytes();
    assert!(rest.is_empty(), 303);
}

/// Drift canary: a fixture whose `entry_hash` length prefix claims 31 instead
/// of 32 must NOT decode to a 32-byte vector — proves the parity assertions
/// are length-sensitive (a wrong ULEB128 prefix is a schema break).
#[test]
fun b3_12_wrong_length_prefix_breaks_parity() {
    let mut bad: vector<u8> = vector[];
    bad.append(raw32(0x88)); // log
    bad.push_back(0x1F); // ULEB128(31) — deliberately wrong
    bad.append(raw32(0x99)); // 32 bytes follow, but prefix says 31

    let mut b = bcs::new(bad);
    let _log = b.peel_address();
    let entry_hash = b.peel_vec_u8();
    // Only 31 bytes consumed → NOT equal to the 32-byte fixture, and a
    // trailing byte remains. Both checks confirm the drift is observable.
    assert!(entry_hash.length() == 31, 400);
    assert!(entry_hash != raw32(0x99), 401);
    let rest = b.into_remainder_bytes();
    assert!(rest.length() == 1, 402);
}
