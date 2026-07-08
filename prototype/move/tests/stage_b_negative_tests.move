// atom #141 · B.3.20 — abort code / negative matrix.
//
// Canonical OUT (ATOM_PLAN line 1125): "stable abort codes for owner/len/
// state failures." 광기 사양 (line 1126): "failure reasons are part of the
// contract; opaque aborts are not acceptable." Test list (line 1127): "abort
// code matrix, no catch-all abort." Gate G-B-MOVE. Reuse #136-#140 (the
// memory_root / audit_log public surface already proven by the Move Prover
// cluster #136-#140).
//
// WHY a dedicated tests/ module (not more in-source tests):
//   The in-source negative tests (memory_root.move:441/491/685,
//   audit_log.move:523/539) each live INSIDE their own module and reference
//   their PRIVATE abort consts by bare name. This file is the consolidated,
//   cross-module CONTRACT matrix: it drives every failure path through the
//   PUBLIC entry API only and pins each abort to a SPECIFIC numeric code AND
//   originating module via `#[expected_failure(abort_code = <named const>,
//   location = <module>)]`. No test here uses a bare `#[expected_failure]`
//   (which would match ANY abort) — that bare form IS the "catch-all abort"
//   the 광기 사양 forbids. Every negative case names its reason.
//
// CROSS-MODULE PRIVATE-CONST NOTE:
//   `memory_root::E_NOT_OWNER` (=1, memory_root.move:78), `E_BAD_BLOB_LEN`
//   (=2, :83), `audit_log::E_NOT_OWNER` (=1, audit_log.move:180), and
//   `E_BAD_ENTRY_LEN` (=2, :190) are MODULE-PRIVATE consts; a foreign module
//   cannot name them. This matrix therefore declares its OWN named mirror
//   consts and pins the originating module via `location = ...`. The mirror is
//   an INDEPENDENT contract assertion (falsifiable per
//   [[formal-method-assertion-must-be-falsifiable]]): if a source module ever
//   renumbered an abort code, the `abort_code = <mirror>` comparison would
//   FAIL here, surfacing the drift. The numbers are decoupled per module
//   (each module numbers its abort space from 1 — audit_log.move:174-179).
//
// FALSIFIABILITY / NO-VACUITY:
//   Each module gets a POSITIVE control (`*_good_inputs_succeeds`) that drives
//   the SAME public entry with VALID inputs and asserts a success projection
//   (epoch advanced / owner set). A spurious always-abort gate would also fail
//   the positive control, so the negative tests genuinely isolate the named
//   owner / length / post-transfer-state gates rather than passing vacuously.
//
// E_BAD_ROOT_HASH_LEN (=3) is NOT covered here: it gates a `#[test_only]`
// constructor (`new_root_with_root_hash`, memory_root.move:643) and is
// unreachable through the public `create_root` (genesis head is the fixed
// 32-byte zero constant), so it is already and only exercisable in-module
// (struct_init_rejects_bad_root_hash_len, memory_root.move:686). Recorded in
// the WorkPackage sidecar no_op_decisions.

#[test_only]
module mnemos::stage_b_negative_tests;

use mnemos::memory_root::{Self, MemoryRoot};
use mnemos::audit_log::{Self, AuditLog};
use sui::test_scenario;

// --- abort-code contract mirror (independent pin; see header note) ---------

/// Mirrors `mnemos::memory_root::E_NOT_OWNER` (= 1, memory_root.move:78):
/// `add_chunk` / `transfer_root` raise this when `ctx.sender() != root.owner`.
const E_NOT_OWNER_MEMORY_ROOT: u64 = 1;

/// Mirrors `mnemos::memory_root::E_BAD_BLOB_LEN` (= 2, memory_root.move:83):
/// `add_chunk` raises this when `blob_id.length() != 32`.
const E_BAD_BLOB_LEN_MEMORY_ROOT: u64 = 2;

/// Mirrors `mnemos::audit_log::E_NOT_OWNER` (= 1, audit_log.move:180):
/// `append` raises this when `ctx.sender() != log.owner`.
const E_NOT_OWNER_AUDIT_LOG: u64 = 1;

/// Mirrors `mnemos::audit_log::E_BAD_ENTRY_LEN` (= 2, audit_log.move:190):
/// `append` raises this when `entry_hash.length() != 32`.
const E_BAD_ENTRY_LEN_AUDIT_LOG: u64 = 2;

// --- fixture addresses ------------------------------------------------------

const OWNER: address = @0xA11CE;
const NON_OWNER: address = @0xB0B;

// --- local test fixtures (memory_root's #[test_only] helpers are private) ---

/// 32-byte vector of a single repeated byte — a length-valid blob id / entry
/// hash. Mirrors `memory_root::fixture_blob_id_32` (memory_root.move:388),
/// re-declared here because that helper is `#[test_only]` private.
fun bytes32(b: u8): vector<u8> {
    let mut v: vector<u8> = vector[];
    let mut i = 0u64;
    while (i < 32) {
        v.push_back(b);
        i = i + 1;
    };
    v
}

// ===========================================================================
// memory_root matrix
// ===========================================================================

/// POSITIVE control: owner anchors a valid 32-byte chunk; epoch advances 0->1.
/// Proves the negative `add_chunk` gates below are not vacuous.
#[test]
fun add_chunk_good_inputs_succeeds() {
    let mut scenario = test_scenario::begin(OWNER);
    memory_root::create_root(scenario.ctx());

    scenario.next_tx(OWNER);
    let mut root = test_scenario::take_from_sender<MemoryRoot>(&scenario);
    memory_root::add_chunk(&mut root, bytes32(0x11), 1u8, vector[], scenario.ctx());

    assert!(memory_root::epoch(&root) == 1, 0);

    test_scenario::return_to_sender<MemoryRoot>(&scenario, root);
    scenario.end();
}

/// OWNER failure: a non-owner caller cannot `add_chunk`.
#[test]
#[expected_failure(abort_code = E_NOT_OWNER_MEMORY_ROOT, location = mnemos::memory_root)]
fun add_chunk_by_non_owner_aborts_e_not_owner() {
    let mut scenario = test_scenario::begin(OWNER);
    memory_root::create_root(scenario.ctx());

    // Run the mutation tx as NON_OWNER but reach into OWNER's object.
    scenario.next_tx(NON_OWNER);
    let mut root = test_scenario::take_from_address<MemoryRoot>(&scenario, OWNER);
    memory_root::add_chunk(&mut root, bytes32(0x33), 1u8, vector[], scenario.ctx());

    // Unreachable — add_chunk aborts E_NOT_OWNER above.
    test_scenario::return_to_address<MemoryRoot>(OWNER, root);
    scenario.end();
}

/// LENGTH failure: a non-32-byte blob id is rejected before any state write.
#[test]
#[expected_failure(abort_code = E_BAD_BLOB_LEN_MEMORY_ROOT, location = mnemos::memory_root)]
fun add_chunk_bad_blob_len_aborts_e_bad_blob_len() {
    let mut scenario = test_scenario::begin(OWNER);
    memory_root::create_root(scenario.ctx());

    scenario.next_tx(OWNER);
    let mut root = test_scenario::take_from_sender<MemoryRoot>(&scenario);
    let short_blob: vector<u8> = vector[1u8, 2u8, 3u8];
    memory_root::add_chunk(&mut root, short_blob, 1u8, vector[], scenario.ctx());

    // Unreachable — add_chunk aborts E_BAD_BLOB_LEN above.
    test_scenario::return_to_sender<MemoryRoot>(&scenario, root);
    scenario.end();
}

/// OWNER failure: a non-owner caller cannot `transfer_root`.
#[test]
#[expected_failure(abort_code = E_NOT_OWNER_MEMORY_ROOT, location = mnemos::memory_root)]
fun transfer_root_by_non_owner_aborts_e_not_owner() {
    let mut scenario = test_scenario::begin(OWNER);
    memory_root::create_root(scenario.ctx());

    scenario.next_tx(NON_OWNER);
    let root = test_scenario::take_from_address<MemoryRoot>(&scenario, OWNER);
    memory_root::transfer_root(root, NON_OWNER, scenario.ctx());

    // Unreachable — transfer_root aborts E_NOT_OWNER above.
    scenario.end();
}

/// STATE failure: after a valid transfer, the OLD owner's `add_chunk` now hits
/// the owner gate because `transfer_root` mutated `root.owner`. The failure is
/// state-dependent (same E_NOT_OWNER code, reached only because of the prior
/// transfer) — the "state failure" arm of the canonical OUT.
#[test]
#[expected_failure(abort_code = E_NOT_OWNER_MEMORY_ROOT, location = mnemos::memory_root)]
fun post_transfer_old_owner_add_chunk_aborts_e_not_owner() {
    let mut scenario = test_scenario::begin(OWNER);
    memory_root::create_root(scenario.ctx());

    scenario.next_tx(OWNER);
    let root = test_scenario::take_from_sender<MemoryRoot>(&scenario);
    memory_root::transfer_root(root, NON_OWNER, scenario.ctx());

    // Old owner (OWNER) attempts to anchor under the now-NON_OWNER-owned root.
    scenario.next_tx(OWNER);
    let mut received = test_scenario::take_from_address<MemoryRoot>(&scenario, NON_OWNER);
    memory_root::add_chunk(&mut received, bytes32(0x55), 1u8, vector[], scenario.ctx());

    // Unreachable — add_chunk aborts E_NOT_OWNER above.
    test_scenario::return_to_address<MemoryRoot>(NON_OWNER, received);
    scenario.end();
}

// ===========================================================================
// audit_log matrix
// ===========================================================================

/// POSITIVE control: owner appends a valid 32-byte entry hash without abort;
/// owner projection unchanged. Proves the negative `append` gates are not
/// vacuous.
#[test]
fun append_good_inputs_succeeds() {
    let mut scenario = test_scenario::begin(OWNER);
    audit_log::create_log(scenario.ctx());

    scenario.next_tx(OWNER);
    let mut log = test_scenario::take_from_sender<AuditLog>(&scenario);
    audit_log::append(&mut log, bytes32(0xAA), scenario.ctx());

    assert!(audit_log::owner(&log) == OWNER, 0);

    test_scenario::return_to_sender<AuditLog>(&scenario, log);
    scenario.end();
}

/// OWNER failure: a non-owner caller cannot `append`.
#[test]
#[expected_failure(abort_code = E_NOT_OWNER_AUDIT_LOG, location = mnemos::audit_log)]
fun append_by_non_owner_aborts_e_not_owner() {
    let mut scenario = test_scenario::begin(OWNER);
    audit_log::create_log(scenario.ctx());

    scenario.next_tx(NON_OWNER);
    let mut log = test_scenario::take_from_address<AuditLog>(&scenario, OWNER);
    audit_log::append(&mut log, bytes32(0xAA), scenario.ctx());

    // Unreachable — append aborts E_NOT_OWNER above.
    test_scenario::return_to_address<AuditLog>(OWNER, log);
    scenario.end();
}

/// LENGTH failure: a non-32-byte entry hash is rejected before any state write.
#[test]
#[expected_failure(abort_code = E_BAD_ENTRY_LEN_AUDIT_LOG, location = mnemos::audit_log)]
fun append_bad_entry_len_aborts_e_bad_entry_len() {
    let mut scenario = test_scenario::begin(OWNER);
    audit_log::create_log(scenario.ctx());

    scenario.next_tx(OWNER);
    let mut log = test_scenario::take_from_sender<AuditLog>(&scenario);
    let short_entry: vector<u8> = vector[1u8, 2u8, 3u8];
    audit_log::append(&mut log, short_entry, scenario.ctx());

    // Unreachable — append aborts E_BAD_ENTRY_LEN above.
    test_scenario::return_to_sender<AuditLog>(&scenario, log);
    scenario.end();
}
