// atom #15 · D.0.1 — MNEMOS memory-root Move module (struct + event).
// atom #16 · D.0.2 — `add_chunk` entry function + `ChunkAnchored` emit.
// atom #17 · D.0.3 — `transfer_root` entry function (owner-only ownership transfer).
//
// Canonical OUT (§4.D, ATOM_PLAN line 528-559):
//   public struct MemoryRoot has key {
//       id: UID,
//       owner: address,
//       root_hash: vector<u8>,   // len == 32 (invariant; proved by Move Prover in atom #18)
//       chunk_count: u64,
//       epoch: u64,              // monotone (invariant; proved by Move Prover in atom #18)
//   }
//   public struct ChunkAnchored has copy, drop {
//       root: ID, blob_id: vector<u8>, kind: u8, parent: vector<u8>, epoch: u64,
//   }
//   public entry fun add_chunk(root: &mut MemoryRoot, blob_id: vector<u8>, kind: u8, parent: vector<u8>, ctx: &mut TxContext);  // owner-only
//   public entry fun transfer_root(root: MemoryRoot, to: address, ctx: &mut TxContext);                                      // owner-only
//
// atom #16 광기 사양 (ATOM_PLAN line 956):
// - owner-only (`ctx.sender() == root.owner`) — `E_NOT_OWNER` abort otherwise.
// - `blob_id` length == 32 enforced — `E_BAD_BLOB_LEN` abort otherwise.
// - `epoch` monotonically incremented by 1 per successful call.
// - `chunk_count` monotonically incremented by 1 per successful call.
// - `ChunkAnchored` event emitted with `root = object::id(root)`,
//   `epoch` set to the *post-increment* value.
// - "anchor된 blob immutable": events are write-only; no on-chain state
//   stores the (blob_id, kind, parent) tuple. Once emitted, the event
//   record is immutable by Sui's event model. The formal invariant is
//   proved by the Move Prover spec in atom #18 (D.0.4).
//
// atom #17 광기 사양 (ATOM_PLAN line 966):
// - `transfer_root` is owner-only (`ctx.sender() == root.owner`) — same
//   `E_NOT_OWNER` abort const reused from atom #16.
// - After transfer, the OLD owner can no longer mutate the root: the
//   atomic effect inside `transfer_root` is `root.owner = to` BEFORE
//   `sui::transfer::transfer(root, to)`, so any subsequent `add_chunk`
//   call whose `ctx.sender()` equals the old owner aborts on the
//   `add_chunk` owner gate. The formal invariant is proved by the Move
//   Prover spec in atom #18 (D.0.4).
// - Self-transfer (`to == root.owner == ctx.sender()`) is well-defined
//   and harmless: `root.owner` is re-assigned to itself, and Sui's
//   `transfer::transfer` accepts `to == sender` (the object remains
//   account-owned by the same address).
//
// atom #17 scope deliberately omits:
// - Move Prover spec file `memory_root.spec.move` (atom #18 / D.0.4).
// - testnet deploy / Rust SDK call builder (atoms #19 / #20).
// - `root_hash` mutation (see atom #16 carve-out below).
//
// atom #16 scope deliberately omits (still in force this atom):
// - `root_hash` mutation: §4.D canonical signature for `add_chunk` does
//   NOT include a new-root-hash argument and does NOT derive one from
//   `blob_id` / `parent`. The atom-#15 doc-comment on `root_hash` says
//   "anchoring the latest chunk", which is a future-atom-#18 Prover
//   invariant. atom #16 leaves `root_hash` untouched (atom-#2 / atom-#3
//   disparity-marker precedent: only implement canonical-OUT-explicit
//   surface; defer everything else).
// - Move Prover spec file `memory_root.spec.move` (atom #18 / D.0.4).
// - testnet deploy / Rust SDK call builder (atoms #19 / #20).
//
// Cross-language schema lock (§V.3 — ATOM_PLAN line 946): the Rust
// counterpart `mnemos_d_move::types::MemoryRootArgs` carries the call-
// args projection (`owner`, `root_hash`, `epoch_u64`) and BCS-encodes
// them as the byte-exact 72-byte sequence `owner ‖ root_hash ‖
// epoch_u64_le`. The `id: UID` and `chunk_count: u64` fields of
// `MemoryRoot` are Sui object-infrastructure / on-chain-managed and
// are NOT part of the SDK call args, so they intentionally have no
// Rust mirror. atom #16 `add_chunk` takes (`blob_id`, `kind`, `parent`)
// as transaction-level args; only `blob_id` (32 B) and `kind` (u8) and
// `parent` (vector<u8>, 0 or 32 B by event convention) cross language.

module mnemos::memory_root;

use sui::event;

/// Abort code raised by `add_chunk` when `ctx.sender() != root.owner`.
/// Matches the §10.2 / atom #18 Prover invariant "owner-only mutate".
const E_NOT_OWNER: u64 = 1;

/// Abort code raised by `add_chunk` when `blob_id.length() != 32`.
/// Matches the atom-#7 wire-format constant `BLOB_ID_BYTES = 32`
/// (`mnemos_c_walrus::BLOB_ID_BYTES`).
const E_BAD_BLOB_LEN: u64 = 2;

/// Memory-root object pinned to a Sui account. Every chunk that an
/// owner anchors lives under one of these.
///
/// Fields:
/// - `id` — Sui object infrastructure handle; set by `object::new`.
/// - `owner` — 32-byte wallet address that owns this root. Mutation
///   entry points (atoms #16 / #17) gate on
///   `ctx.sender() == self.owner`.
/// - `root_hash` — 32-byte hash anchoring the latest chunk. The
///   `len == 32` invariant is proved by the Move Prover spec in
///   atom #18 / D.0.4; the Rust binding enforces it at the type
///   level via `MemoryRootArgs.root_hash: [u8; 32]`.
/// - `chunk_count` — monotonically-increasing counter of anchored
///   chunks. Incremented exactly once per successful `add_chunk`.
/// - `epoch` — monotonically-increasing epoch counter. The invariant
///   `next_epoch > prev_epoch` is proved by the Move Prover spec in
///   atom #18 / D.0.4 and raised through
///   `mnemos_d_move::types::MoveBindError::EpochNotMonotone` on the
///   Rust side.
///
/// `root_hash` is intentionally not read or written by atom #16
/// (see module header — canonical-OUT-explicit only). The Move
/// Prover spec in atom #18 reasons about its length invariant;
/// until then the W09009 `unused_field` lint is suppressed via
/// `#[allow(unused_field)]`.
#[allow(unused_field)]
public struct MemoryRoot has key {
    id: sui::object::UID,
    owner: address,
    root_hash: vector<u8>,
    chunk_count: u64,
    epoch: u64,
}

/// Event emitted by `add_chunk` (atom #16) each time a chunk is
/// successfully anchored under a `MemoryRoot`.
///
/// Fields:
/// - `root` — `ID` of the parent `MemoryRoot` object.
/// - `blob_id` — 32-byte Walrus blob id of the chunk just anchored.
///   `len == 32` invariant enforced by `add_chunk` (`E_BAD_BLOB_LEN`).
/// - `kind` — `mnemos_c_walrus::ChunkKind` wire tag (u8 ∈ {1..5}).
/// - `parent` — blob id of the prior chunk in the chain. Either an
///   empty `vector<u8>` (no parent) or 32 bytes (chained). atom #16
///   does NOT enforce a length on `parent` (canonical OUT does not
///   specify one); atom #18 Prover spec is the canonical place to
///   pin this if needed.
/// - `epoch` — value of `MemoryRoot.epoch` AFTER the increment
///   performed by `add_chunk` (so the very first successful anchor
///   emits `epoch = 1`).
public struct ChunkAnchored has copy, drop {
    root: sui::object::ID,
    blob_id: vector<u8>,
    kind: u8,
    parent: vector<u8>,
    epoch: u64,
}

/// Owner-only entry point: anchor a single chunk under `root`.
///
/// Aborts:
/// - `E_NOT_OWNER` when `ctx.sender() != root.owner`.
/// - `E_BAD_BLOB_LEN` when `blob_id.length() != 32`.
///
/// Effects on success (in order):
/// 1. `root.epoch` is incremented by 1.
/// 2. `root.chunk_count` is incremented by 1.
/// 3. `root.root_hash` (the chain head) is advanced to
///    `blake2b256(previous_root_hash ‖ blob_id)` — atom #126 / B.3.5.
/// 4. A `ChunkAnchored` event is emitted carrying the parent
///    `MemoryRoot`'s `ID`, the (just-validated) 32-byte `blob_id`,
///    the chunk `kind`, the `parent` blob id (empty or 32 bytes by
///    convention), and the post-increment `epoch`.
///
/// atom #126 (B.3.5) head-update rule — USER-LOCKED 2026-05-31:
/// - `next_root_hash = sui::hash::blake2b256(previous_root_hash ‖ blob_id)`.
///   Preimage is the byte-exact concatenation `previous_root_hash[32] ‖
///   blob_id[32]` = 64 B; NO parent / kind / epoch / digest / domain-tag
///   is folded in (any addition would desync the Rust replay parity at
///   atoms #132 / #133).
/// - The signature is UNCHANGED (no `digest` arg — the atom #124
///   USER-LOCK stands; the on-chain Walrus `blob_id` IS the content
///   digest), and `ChunkAnchored` gains NO field.
/// - The head is a hash chain: a duplicate anchor of the same `blob_id`
///   still advances the head because `previous_root_hash` has changed.
/// - `root_hash` stays exactly 32 bytes by construction (blake2b256
///   output width), preserving the §4.D / spec I-2 `len == 32` invariant.
/// - CROSS-LANGUAGE BYTE-VALUE LOCK: the Rust mirror
///   `mnemos_d_move::types::memory_root_args_from_anchor` still carries
///   the legacy latest-blob-id alias (`root_hash := blob_id`); atoms #132
///   `MemoryRootAnchorArgs` / #133 BCS parity MUST adopt this identical
///   `blake2b256(prev ‖ blob_id)` formula. Python oracle pins
///   `blake2b256(0x00*32 ‖ 0x11*32) = 04422c94…9c12`.
///
/// The `public entry` modifier is canonical per ATOM_PLAN line 558
/// (byte-stable signature `public entry fun add_chunk(...)`). The
/// Move 2024 linter flags `entry` on `public` as redundant
/// (W99010 / `public_entry`), but the canonical signature is pinned
/// by the plan and consumed by downstream atoms (#17 / #18 / #20).
/// The lint is suppressed locally via `#[allow(lint(public_entry))]`.
#[allow(lint(public_entry))]
public entry fun add_chunk(
    root: &mut MemoryRoot,
    blob_id: vector<u8>,
    kind: u8,
    parent: vector<u8>,
    ctx: &mut TxContext,
) {
    assert!(ctx.sender() == root.owner, E_NOT_OWNER);
    assert!(blob_id.length() == 32, E_BAD_BLOB_LEN);

    root.epoch = root.epoch + 1;
    root.chunk_count = root.chunk_count + 1;

    // atom #126 (B.3.5): advance the chain head.
    // preimage = previous_root_hash[32] || blob_id[32]  (64 bytes,
    // byte-exact; no other field is folded in — see the doc-comment
    // cross-language byte-value lock). `root.root_hash` is a copyable
    // vector<u8>, so reading it here copies the PREVIOUS head before the
    // overwrite below; `blob_id` is likewise copied for the append and
    // stays available for the `ChunkAnchored` emit.
    let mut preimage = root.root_hash;
    preimage.append(blob_id);
    root.root_hash = sui::hash::blake2b256(&preimage);

    event::emit(ChunkAnchored {
        root: sui::object::id(root),
        blob_id,
        kind,
        parent,
        epoch: root.epoch,
    });
}

/// Owner-only entry point: transfer this `MemoryRoot` to a new address.
///
/// Aborts:
/// - `E_NOT_OWNER` when `ctx.sender() != root.owner` (reuses the abort
///   const introduced by atom #16 / `add_chunk`).
///
/// Effects on success (atomic, in order):
/// 1. `root.owner` is set to `to`. This mutation is the post-transfer
///    invariant carrier: any subsequent `add_chunk` invocation whose
///    `ctx.sender()` equals the OLD owner aborts on the existing
///    `add_chunk` owner gate (`E_NOT_OWNER`). The Move Prover spec in
///    atom #18 / D.0.4 lifts this to a formal invariant.
/// 2. The `MemoryRoot` object is transferred to `to` via
///    `sui::transfer::transfer`. `MemoryRoot has key` only (no `store`),
///    so the appropriate sui-framework transfer entry is the
///    module-internal `transfer::transfer`.
///
/// Self-transfer (`to == root.owner == ctx.sender()`) is allowed and
/// harmless: `root.owner` is re-assigned to itself and Sui's
/// `transfer::transfer` accepts `to == sender` (the object stays
/// account-owned by the same address).
///
/// `root.chunk_count`, `root.epoch`, and `root.root_hash` are NOT
/// touched by this atom — the canonical OUT signature has no semantics
/// for them, and atom-#2 / atom-#3 disparity-marker precedent says to
/// implement only the canonical-OUT-explicit surface.
///
/// The `public entry` modifier is canonical per ATOM_PLAN line 559
/// (byte-stable signature `public entry fun transfer_root(...)`). The
/// Move 2024 linter flags `entry` on `public` as redundant
/// (W99010 / `public_entry`); the lint is suppressed locally with the
/// same justification as `add_chunk` (atom #16): the canonical
/// signature is pinned by the plan and consumed by downstream atoms
/// (#18 Prover spec / #20 Rust SDK call builder).
#[allow(lint(public_entry))]
public entry fun transfer_root(
    mut root: MemoryRoot,
    to: address,
    ctx: &mut TxContext,
) {
    assert!(ctx.sender() == root.owner, E_NOT_OWNER);
    root.owner = to;
    sui::transfer::transfer(root, to);
}

/// atom #138 · B.3.17 — additive owner getter for the owner-only Move
/// Prover invariant (gate G-B-PROVER).
///
/// This is the ONLY production change atom #138 makes to this module. It
/// exposes the already-present private `owner` field as a zero-logic read
/// so the separate `MnemosProver` package (`prototype/move-prover/`) can
/// state the owner-only invariant on the REAL `add_chunk` / `transfer_root`
/// functions without reaching a private field.
///
/// Owner-only is proven as success-implies-owner, NOT as a no-abort claim
/// (`#[spec(prove, ignore_abort)]` + `ensures(ctx.sender() == pre_owner)`):
/// if a mutation succeeds, the caller equals the owner that existed before
/// the call. `add_chunk` does not mutate `owner`, and `transfer_root`'s
/// line-259 gate checks `ctx.sender() == root.owner` before any mutation,
/// so a non-owner caller aborts before reaching state mutation. atom #138
/// deliberately does NOT add `epoch()` / `chunk_count()` getters — the
/// independent length / overflow aborts are left to atom #139 (the
/// `ignore_abort` form intentionally does not characterise them). USER-LOCKED
/// 2026-06-01.
public fun owner(root: &MemoryRoot): address {
    root.owner
}

/// atom #139 · B.3.18 — additive `epoch` getter for the Move Prover
/// len/monotone invariant (gate G-B-PROVER); mirror of `owner`.
///
/// Exposes the private `epoch` field as a zero-logic read so the separate
/// `MnemosProver` package can state the monotone invariant on the REAL
/// `add_chunk` function: a successful anchor advances `epoch` by exactly 1
/// (`ensures(epoch(root) == pre_epoch + 1)`), so the epoch never decreases.
/// atom #138 deliberately deferred this getter to #139 (see the `owner` doc
/// above). USER-LOCKED 2026-06-01: the consumed-only ABI adds the `epoch`
/// getter ONLY — no `chunk_count()` / `root_hash()` getter (the `root_hash`
/// state length invariant is not provable while the pinned SuiSpecs
/// `blake2b256` spec is a passthrough, so no unconsumed getter is added).
public fun epoch(root: &MemoryRoot): u64 {
    root.epoch
}

/// Genesis `root_hash` for a freshly minted `MemoryRoot`: the 32-byte
/// all-zero constant. atom #123 / B.3.2 광기 사양 (ATOM_PLAN line 854):
/// "genesis head is zero/hash constant". Encoded as a byte-exact hex
/// literal (64 hex chars == 32 bytes) so the §4.3 / §4.D `root_hash`
/// `len == 32` invariant holds by construction: `create_root` takes no
/// caller-supplied `root_hash` argument (canonical signature §4.3
/// line 300), so there is no untrusted length to gate at runtime.
const GENESIS_ROOT_HASH: vector<u8> =
    x"0000000000000000000000000000000000000000000000000000000000000000";

/// Entry point: mint a fresh `MemoryRoot` owned by the transaction
/// sender and hand it to that sender's account.
///
/// atom #123 / B.3.2 canonical OUT (§4.3 line 300 / ATOM_PLAN line 853):
///   `public entry fun create_root(ctx: &mut TxContext)`
///
/// 광기 사양 (ATOM_PLAN line 854):
/// - `owner` is `ctx.sender()` (`tx_context::sender`); there is no
///   caller-supplied owner argument, so a root can only be created for
///   the calling wallet.
/// - genesis `root_hash` is the 32-byte zero constant `GENESIS_ROOT_HASH`.
/// - `chunk_count` starts at 0; `epoch` starts at 0.
///
/// The minted object is account-owned: `MemoryRoot has key` only (no
/// `store`), so the module-internal `sui::transfer::transfer` is the
/// canonical handoff (same family as `transfer_root`, atom #17). `owner`
/// is bound once before `sui::object::new` to avoid aliasing the `ctx`
/// borrow across the mutable `object::new` and the immutable `sender()`.
///
/// `root_hash` is set to the genesis constant and is NOT derived from any
/// input this atom; chunk anchoring (atom #124) is the first operation
/// that advances `epoch` / `chunk_count`. The criterion "gas trace
/// recorded" (ATOM_PLAN line 856) is a live-testnet-deploy artifact and
/// is out of scope for local build/test (recorded as not_run in the
/// sidecar — no live approval this session).
///
/// The `public entry` modifier is canonical per §4.3; Move 2024 flags
/// `entry` on `public` as redundant (W99010 / `public_entry`), suppressed
/// locally with the same justification as `add_chunk` / `transfer_root`:
/// the canonical signature is pinned by the plan and consumed downstream
/// (atom #125 owner-only spine / atom #146 Rust SDK call builder).
#[allow(lint(public_entry))]
public entry fun create_root(ctx: &mut TxContext) {
    let owner = ctx.sender();
    let root = MemoryRoot {
        id: sui::object::new(ctx),
        owner,
        root_hash: GENESIS_ROOT_HASH,
        chunk_count: 0,
        epoch: 0,
    };
    sui::transfer::transfer(root, owner);
}

// ============================================================
// #[test_only] helpers and tests for atom #16 (D.0.2).
// ============================================================
//
// Test naming is verbatim from ATOM_PLAN line 957:
//   add_chunk_by_owner_succeeds
//   add_chunk_by_non_owner_aborts
//   add_chunk_emits_event
//   add_chunk_rejects_bad_blob_len
//
// Cleanup: `MemoryRoot has key` (no `drop`), so test bodies route
// instances through `sui::test_utils::destroy` after the assertions.
// This matches the idiomatic sui-framework test pattern.

#[test_only]
const TEST_OWNER: address = @0xAA;
#[test_only]
const TEST_NON_OWNER: address = @0xBB;

#[test_only]
fun zero_blob_id_32(): vector<u8> {
    let mut v: vector<u8> = vector[];
    let mut i = 0u64;
    while (i < 32) {
        v.push_back(0u8);
        i = i + 1;
    };
    v
}

#[test_only]
fun fixture_blob_id_32(byte: u8): vector<u8> {
    let mut v: vector<u8> = vector[];
    let mut i = 0u64;
    while (i < 32) {
        v.push_back(byte);
        i = i + 1;
    };
    v
}

#[test_only]
fun new_root_for_test(owner: address, ctx: &mut TxContext): MemoryRoot {
    MemoryRoot {
        id: sui::object::new(ctx),
        owner,
        root_hash: zero_blob_id_32(),
        chunk_count: 0,
        epoch: 0,
    }
}

#[test]
fun add_chunk_by_owner_succeeds() {
    let mut scenario = sui::test_scenario::begin(TEST_OWNER);
    let mut root = new_root_for_test(TEST_OWNER, scenario.ctx());

    add_chunk(
        &mut root,
        fixture_blob_id_32(0x11),
        1u8,
        vector[],
        scenario.ctx(),
    );

    assert!(root.epoch == 1, 100);
    assert!(root.chunk_count == 1, 101);

    add_chunk(
        &mut root,
        fixture_blob_id_32(0x22),
        2u8,
        fixture_blob_id_32(0x11),
        scenario.ctx(),
    );

    assert!(root.epoch == 2, 102);
    assert!(root.chunk_count == 2, 103);

    std::unit_test::destroy(root);
    scenario.end();
}

#[test]
#[expected_failure(abort_code = E_NOT_OWNER)]
fun add_chunk_by_non_owner_aborts() {
    let mut scenario = sui::test_scenario::begin(TEST_OWNER);
    let mut root = new_root_for_test(TEST_OWNER, scenario.ctx());

    scenario.next_tx(TEST_NON_OWNER);

    add_chunk(
        &mut root,
        fixture_blob_id_32(0x33),
        1u8,
        vector[],
        scenario.ctx(),
    );

    std::unit_test::destroy(root);
    scenario.end();
}

#[test]
fun add_chunk_emits_event() {
    let mut scenario = sui::test_scenario::begin(TEST_OWNER);
    let mut root = new_root_for_test(TEST_OWNER, scenario.ctx());
    let root_id = sui::object::id(&root);

    let blob_id = fixture_blob_id_32(0x44);
    let parent = fixture_blob_id_32(0x11);

    add_chunk(
        &mut root,
        blob_id,
        3u8,
        parent,
        scenario.ctx(),
    );

    let events = event::events_by_type<ChunkAnchored>();
    assert!(events.length() == 1, 200);
    let ev = &events[0];
    assert!(ev.root == root_id, 201);
    assert!(ev.blob_id == fixture_blob_id_32(0x44), 202);
    assert!(ev.kind == 3u8, 203);
    assert!(ev.parent == fixture_blob_id_32(0x11), 204);
    assert!(ev.epoch == 1, 205);

    std::unit_test::destroy(root);
    scenario.end();
}

#[test]
#[expected_failure(abort_code = E_BAD_BLOB_LEN)]
fun add_chunk_rejects_bad_blob_len() {
    let mut scenario = sui::test_scenario::begin(TEST_OWNER);
    let mut root = new_root_for_test(TEST_OWNER, scenario.ctx());

    let short_blob: vector<u8> = vector[1u8, 2u8, 3u8];

    add_chunk(
        &mut root,
        short_blob,
        1u8,
        vector[],
        scenario.ctx(),
    );

    std::unit_test::destroy(root);
    scenario.end();
}

// ============================================================
// atom #17 (D.0.3) — transfer_root tests.
// ============================================================
//
// Test naming is verbatim from ATOM_PLAN line 967:
//   transfer_by_owner_changes_owner
//   transfer_by_non_owner_aborts
//   post_transfer_old_owner_cannot_add_chunk
//
// Cleanup: `transfer_root` *consumes* the `MemoryRoot` by value and
// hands it off via `sui::transfer::transfer`, so the success-path
// tests do NOT call `std::unit_test::destroy` on `root` (the object
// is owned by Sui after transfer). They re-fetch the transferred
// object in a follow-up tx via `sui::test_scenario::take_from_sender`
// and then return it via `return_to_sender` to satisfy the test
// framework's object-leak check. The abort-path tests rely on Move's
// `#[expected_failure]` semantics: control never reaches any
// cleanup, and the framework tolerates the leaked local because the
// test is marked as expected-to-abort.

#[test]
fun transfer_by_owner_changes_owner() {
    let mut scenario = sui::test_scenario::begin(TEST_OWNER);
    let root = new_root_for_test(TEST_OWNER, scenario.ctx());
    transfer_root(root, TEST_NON_OWNER, scenario.ctx());

    // After transfer_root, `root` has been consumed and the on-chain
    // MemoryRoot is account-owned by TEST_NON_OWNER. Open a new tx as
    // the new owner and pull the object back out for inspection.
    scenario.next_tx(TEST_NON_OWNER);
    let received = sui::test_scenario::take_from_sender<MemoryRoot>(&scenario);

    assert!(received.owner == TEST_NON_OWNER, 300);
    assert!(received.chunk_count == 0, 301);
    assert!(received.epoch == 0, 302);

    sui::test_scenario::return_to_sender<MemoryRoot>(&scenario, received);
    scenario.end();
}

#[test]
#[expected_failure(abort_code = E_NOT_OWNER)]
fun transfer_by_non_owner_aborts() {
    let mut scenario = sui::test_scenario::begin(TEST_OWNER);
    let root = new_root_for_test(TEST_OWNER, scenario.ctx());

    // Hand the tx off to TEST_NON_OWNER (who is NOT root.owner) and
    // attempt to call transfer_root — the owner check must abort.
    scenario.next_tx(TEST_NON_OWNER);
    transfer_root(root, TEST_NON_OWNER, scenario.ctx());

    // Unreachable — transfer_root aborts with E_NOT_OWNER above.
    scenario.end();
}

#[test]
#[expected_failure(abort_code = E_NOT_OWNER)]
fun post_transfer_old_owner_cannot_add_chunk() {
    let mut scenario = sui::test_scenario::begin(TEST_OWNER);
    let root = new_root_for_test(TEST_OWNER, scenario.ctx());
    transfer_root(root, TEST_NON_OWNER, scenario.ctx());

    // In production the old owner cannot reach the object at all
    // (Sui account-owned object access control). The test framework
    // lets us simulate the would-be-attempt by taking the object out
    // of TEST_NON_OWNER's inventory while running the tx as
    // TEST_OWNER (the old owner). This isolates the module-level
    // `add_chunk` owner gate (E_NOT_OWNER) from Sui's runtime owner
    // check — the test asserts that `transfer_root` mutated
    // `root.owner` to TEST_NON_OWNER and therefore add_chunk's guard
    // now fires for the old owner.
    scenario.next_tx(TEST_OWNER);
    let mut received = sui::test_scenario::take_from_address<MemoryRoot>(
        &scenario,
        TEST_NON_OWNER,
    );

    add_chunk(
        &mut received,
        fixture_blob_id_32(0x55),
        1u8,
        vector[],
        scenario.ctx(),
    );

    // Unreachable — add_chunk aborts with E_NOT_OWNER above.
    sui::test_scenario::return_to_address<MemoryRoot>(TEST_NON_OWNER, received);
    scenario.end();
}

// ============================================================
// atom #122 (B.3.1) — MemoryRoot object: root_hash len==32
// invariant + struct-init test + bad-len abort placeholder.
// ============================================================
//
// Reuse, NOT re-scaffold: the `MemoryRoot` struct above is the Stage A
// (atom #15) canonical OUT and is exactly the §4.3 `MemoryRoot` of atom
// #122 (ATOM_PLAN line 842; §4.3 lines 286-292). atom #121's Session-2
// forward advisory pins this — future Cluster-3 Session 1s reuse +
// verify the existing struct rather than redefine it (redefinition is a
// duplicate-definition compile error). atom #122 therefore adds NO
// production struct / entry / field; it adds only the test-only surface
// that exercises the §4.D / §4.3 `root_hash` length invariant
// (len == 32, matching the 32-byte
// `mnemos_b_memory::chunk_digest::ChunkDigest32` reused conceptually via
// #86) plus a struct-init test.
//
// The PRODUCTION `root_hash` len-gate lands with the `create_root` entry
// (atom #123 / B.3.2) and the Move Prover spec; `create_root` is NOT
// implemented here (its own canonical OUT — one-atom-one-OUT, atom-#2 /
// atom-#3 disparity precedent). Until then the bad-length abort is
// exercised through the #[test_only] `new_root_with_root_hash`
// constructor, so the "bad len abort test placeholder" (ATOM_PLAN line
// 844) is a real `#[expected_failure]` test rather than a doc-only stub.

/// Test-only abort code for the `root_hash` length invariant
/// (len == 32). The production enforcement point is `create_root`
/// (atom #123) + the Move Prover spec; this const exists only so the
/// atom-#122 bad-length test can assert a concrete abort path. It
/// mirrors the `add_chunk` `E_BAD_BLOB_LEN` (= 2) blob-id len gate and
/// continues the abort-code numbering (E_NOT_OWNER = 1, E_BAD_BLOB_LEN
/// = 2, E_BAD_ROOT_HASH_LEN = 3).
#[test_only]
const E_BAD_ROOT_HASH_LEN: u64 = 3;

/// Test-only constructor that builds a `MemoryRoot` from a caller-
/// supplied `root_hash`, enforcing the §4.D / §4.3 `len == 32`
/// invariant (`E_BAD_ROOT_HASH_LEN` abort otherwise). This is the
/// test-only stand-in for the production `create_root` len-gate
/// (atom #123); it mirrors the `add_chunk` `blob_id.length() == 32`
/// gate for the root-hash field. `chunk_count` and `epoch` start at 0
/// (the genesis values `create_root` will also set in #123).
#[test_only]
fun new_root_with_root_hash(
    owner: address,
    root_hash: vector<u8>,
    ctx: &mut TxContext,
): MemoryRoot {
    assert!(root_hash.length() == 32, E_BAD_ROOT_HASH_LEN);
    MemoryRoot {
        id: sui::object::new(ctx),
        owner,
        root_hash,
        chunk_count: 0,
        epoch: 0,
    }
}

/// atom #122 "struct init test" (ATOM_PLAN line 844): a freshly
/// constructed `MemoryRoot` carries the supplied owner, a 32-byte
/// `root_hash`, and zeroed `chunk_count` / `epoch`.
#[test]
fun struct_init_sets_fields_and_root_hash_len_32() {
    let mut scenario = sui::test_scenario::begin(TEST_OWNER);
    let root = new_root_with_root_hash(
        TEST_OWNER,
        fixture_blob_id_32(0x77),
        scenario.ctx(),
    );

    assert!(root.owner == TEST_OWNER, 400);
    assert!(root.root_hash.length() == 32, 401);
    assert!(root.chunk_count == 0, 402);
    assert!(root.epoch == 0, 403);

    std::unit_test::destroy(root);
    scenario.end();
}

/// atom #122 "bad len abort test placeholder" (ATOM_PLAN line 844):
/// constructing a `MemoryRoot` with a non-32-byte `root_hash` aborts
/// with `E_BAD_ROOT_HASH_LEN`. Placeholder for the production
/// `create_root` len-gate (#123) + Prover invariant, exercised here
/// through the #[test_only] `new_root_with_root_hash` constructor.
#[test]
#[expected_failure(abort_code = E_BAD_ROOT_HASH_LEN)]
fun struct_init_rejects_bad_root_hash_len() {
    let mut scenario = sui::test_scenario::begin(TEST_OWNER);
    let short_root_hash: vector<u8> = vector[1u8, 2u8, 3u8];

    let root = new_root_with_root_hash(
        TEST_OWNER,
        short_root_hash,
        scenario.ctx(),
    );

    // Unreachable — new_root_with_root_hash aborts with
    // E_BAD_ROOT_HASH_LEN above.
    std::unit_test::destroy(root);
    scenario.end();
}

// ============================================================
// atom #123 (B.3.2) — create_root entry: owner == tx sender, genesis
// zero head, epoch/count start at 0.
// ============================================================
//
// The ATOM_PLAN line 855 test list is descriptive ("create root owner,
// initial epoch/count/head"), not verbatim snake_case (unlike atoms
// #16 / #17 / #122). It is covered by two tests:
//   create_root_sets_sender_as_owner      — owner == tx sender.
//   create_root_initial_epoch_count_head  — epoch == 0, chunk_count == 0,
//                                            root_hash len == 32 AND all-zero.
//
// `create_root` consumes the minted object into the sender's account via
// `sui::transfer::transfer` (no return value), so each test opens a
// follow-up tx as the sender and pulls the object back with
// `take_from_sender` for inspection, then returns it via
// `return_to_sender` to satisfy the framework's object-leak check (same
// pattern as atom #17 `transfer_by_owner_changes_owner`).

#[test]
fun create_root_sets_sender_as_owner() {
    let mut scenario = sui::test_scenario::begin(TEST_OWNER);
    create_root(scenario.ctx());

    scenario.next_tx(TEST_OWNER);
    let received = sui::test_scenario::take_from_sender<MemoryRoot>(&scenario);
    assert!(received.owner == TEST_OWNER, 500);

    sui::test_scenario::return_to_sender<MemoryRoot>(&scenario, received);
    scenario.end();
}

#[test]
fun create_root_initial_epoch_count_head() {
    let mut scenario = sui::test_scenario::begin(TEST_OWNER);
    create_root(scenario.ctx());

    scenario.next_tx(TEST_OWNER);
    let received = sui::test_scenario::take_from_sender<MemoryRoot>(&scenario);
    assert!(received.epoch == 0, 510);
    assert!(received.chunk_count == 0, 511);
    // Head is the genesis 32-byte zero constant. Assert len == 32 and
    // compare against an INDEPENDENT zero derivation (`zero_blob_id_32`),
    // not the `GENESIS_ROOT_HASH` source itself, so the equality is a
    // falsifiable property rather than a self-compare.
    assert!(received.root_hash.length() == 32, 512);
    assert!(received.root_hash == zero_blob_id_32(), 513);

    sui::test_scenario::return_to_sender<MemoryRoot>(&scenario, received);
    scenario.end();
}

// ============================================================
// atom #124 (B.3.3) — add_chunk anchor entry: REUSE + VERIFY of the
// byte-stable Stage A #16 `add_chunk` (no re-scaffold).
// ============================================================
//
// PROVENANCE: the §4.D / §4 canonical `add_chunk` entry function
//   `public entry fun add_chunk(root: &mut MemoryRoot, blob_id: vector<u8>,
//    kind: u8, parent: vector<u8>, ctx: &mut TxContext)`  (line 167 above)
// was minted byte-stable by Stage A atom #16 (D.0.2). Per the #121
// (B.3.0) VERIFIED_GREEN forward advisory, Stage A already implements the
// §4.3 / §4.D surface of #124; this atom REUSES + VERIFIES it and adds NO
// new production code, NO new signature, and NO new event field.
//
// #124 PLAN TEST-LIST MAPPING (ATOM_PLAN line 866) onto the EXISTING
// byte-stable surface — the covered tests already pass under
// `sui move test` (no rewrite of the Stage A tests):
//   * "valid anchor increments count"  -> add_chunk_by_owner_succeeds
//       (line 341): asserts root.epoch == 1/2 and root.chunk_count == 1/2
//       across two successive owner calls (count + epoch monotone +1).
//   * "bad blob len aborts"            -> add_chunk_rejects_bad_blob_len
//       (line 423): a 31-byte blob_id aborts with E_BAD_BLOB_LEN (= 2),
//       i.e. the `assert!(blob_id.length() == 32, ...)` gate at line 175.
//   * (anchor binds verified blob id)  -> add_chunk_emits_event
//       (line 392): ChunkAnchored carries blob_id (len 32), kind, parent,
//       post-increment epoch — content itself is never put on-chain.
// Owner-only (E_NOT_OWNER) is additionally covered by
// add_chunk_by_non_owner_aborts (atom #16) and
// post_transfer_old_owner_cannot_add_chunk (atom #17).
//
// ATOM_PLAN DISPARITY — "bad digest len aborts" (ATOM_PLAN line 866):
//   The §4 / §4.D `add_chunk` signature (PLAN line 301; code line 167)
//   has NO `digest` parameter, and `ChunkAnchored` (line 135) has NO
//   `digest` field. Both are byte-stable canonical (Stage A #16) and are
//   intentionally NOT changed here. The on-chain anchor binds the
//   VERIFIED Walrus blob id (`blob_id`, content-addressed, len-32 gated by
//   E_BAD_BLOB_LEN) — the Walrus blob id IS the content digest on-chain.
//   The DISTINCT off-chain chunk digest binding (#124 spec: "anchor binds
//   verified blob id + chunk digest") is canonically assigned to the RUST
//   call-args struct `MemoryRootAnchorArgs { root, anchor, digest:
//   ChunkDigest32 }` (PLAN §4 line 314) carried by the SuiCallBuilder —
//   NOT yet implemented (future Rust call-builder / anchor-args atom; cf.
//   ATOM_PLAN line 974 family). `ChunkDigest32` already exists at
//   prototype/crates/b-memory/src/chunk_digest.rs:118 (atom #86).
//   THEREFORE the "bad digest len aborts" test has no on-chain target and
//   is DEFERRED to that Rust anchor-args / SuiCallBuilder atom, where the
//   ChunkDigest32 len invariant is the natural enforcement point. This is
//   the same explicit-disparity protocol used by atoms #2 / #3 / #122
//   (implement the stated byte-stable signature only; flag the residual;
//   defer to its true canonical home). USER-LOCKED 2026-05-31 (Option-A
//   reuse+verify+disparity-flag): no digest arg added to add_chunk, no
//   digest field added to ChunkAnchored, no Stage A test rewrite, no
//   cross-language schema break.

// ============================================================
// atom #125 (B.3.4) — owner-only mutation: REUSE + VERIFY of the
// byte-stable Stage A owner-gate spine (no new production code).
// ============================================================
//
// CANONICAL OUT (ATOM_PLAN line 875): "owner check for A `add_chunk`
// and `transfer_root`." This owner-only mutation spine was minted
// byte-stable by Stage A (#16 / #17) and is ALREADY PRESENT in this
// module:
//   * `const E_NOT_OWNER: u64 = 1`                          (line 78)
//   * add_chunk owner gate
//       `assert!(ctx.sender() == root.owner, E_NOT_OWNER)`  (line 174)
//   * transfer_root owner gate
//       `assert!(ctx.sender() == root.owner, E_NOT_OWNER)`  (line 229)
// Per the atom #124 (B.3.3) USER-LOCKED 2026-05-31 Option-A precedent
// (reuse+verify+disparity-flag when Stage A is byte-stable), atom #125
// REUSES + VERIFIES this spine and adds NO new production code, NO new
// signature, NO new event field, and NO new abort const. The atom's
// declared gate is G-B-MOVE (`sui move build` + `sui move test`); the
// green build+test over the existing owner gates IS the verification
// artifact.
//
// MUTATION-SURFACE COMPLETENESS (광기 사양 line 876 "non-owner cannot
// mutate root; Stage B's ownership spine"): the ONLY entry points that
// MUTATE a pre-existing `MemoryRoot` are `add_chunk` (line 167) and
// `transfer_root` (line 224); BOTH gate on
// `ctx.sender() == root.owner` (E_NOT_OWNER). `create_root` (line 276)
// is a MINT, not a mutation of a pre-existing root — its `owner` is
// bound to `ctx.sender()` at genesis, so it has no prior owner to gate
// against (adding a gate there would be a semantic error). No other
// `public` / `entry` mutation path exists in this module. Therefore the
// owner-only spine is COMPLETE: every state-changing path on an
// existing root is owner-gated.
//
// #125 PLAN TEST-LIST MAPPING (ATOM_PLAN line 877; descriptive, like
// #123 / #124) onto the EXISTING byte-stable tests — all pass under
// `sui move test`, with NO rewrite of any Stage A test:
//   * "owner succeeds"                  ->
//       add_chunk_by_owner_succeeds (line 341): owner add_chunk twice,
//         epoch / chunk_count advance 1 -> 2; AND
//       transfer_by_owner_changes_owner (line 462): owner transfers,
//         new owner observed via take_from_sender.
//   * "non-owner aborts"                ->
//       add_chunk_by_non_owner_aborts (line 373, E_NOT_OWNER); AND
//       transfer_by_non_owner_aborts (line 483, E_NOT_OWNER).
//   * "post-transfer old owner aborts"  ->
//       post_transfer_old_owner_cannot_add_chunk (line 498): after
//         transfer_root reassigns `root.owner`, the OLD owner's
//         add_chunk aborts on the line-174 owner gate (E_NOT_OWNER).
// Coverage is COMPLETE with ZERO gap across BOTH owner-gated entry
// points, so atom #125 adds NO new test (a new test would duplicate
// existing coverage — the #124 no-Stage-A-test-rewrite discipline).
//
// SCOPE — deliberately omitted (each has its own canonical home;
// atom-#2 / #3 / #122 / #124 disparity-marker precedent):
//   * Move Prover FORMAL owner-only invariant: atoms #133-#135
//     (`memory_root.spec.move`) — ATOM_PLAN line 1017 / 1028.
//   * monotone epoch / head update rule: atom #126 (B.3.5).
//   * Rust `SuiCallBuilder` owner-args projection: atom #146 family.
// ============================================================
// END atom #125 (B.3.4) reuse+verify block.
// ============================================================

// ============================================================
// atom #126 (B.3.5) — monotone epoch/head update tests.
// ============================================================
//
// Canonical OUT (ATOM_PLAN line 886): "epoch and `root_hash` update rule."
// 광기 (line 887): each anchor increments epoch exactly once and computes
// the next head from previous head + blob (+ digest). USER-LOCKED
// 2026-05-31: head = blake2b256(previous_root_hash[32] || blob_id[32]); the
// off-chain digest is NOT an add_chunk argument (atom #124 byte-stable
// USER-LOCK), and the on-chain Walrus blob_id IS the content digest, so the
// preimage is exactly prev_head || blob_id with NO other field.
//
// FALSIFIABILITY: the head constants below are NOT recomputed inside Move
// from the same blake2b256 call (that would be a self-compare). They are
// INDEPENDENT reference vectors produced by the Python oracle
// `hashlib.blake2b(data, digest_size=32)`; asserting Move's
// `sui::hash::blake2b256` output equals them is a genuine cross-
// implementation check (and the exact value future Rust #132/#133 parity
// must reproduce). A wrong hash function / preimage order / endianness
// would flip these asserts to failure.
//   HEAD1     = blake2b256(0x00*32 || 0x11*32)
//   HEAD2     = blake2b256(HEAD1   || 0x22*32)
//   HEAD_DUP  = blake2b256(HEAD1   || 0x11*32)   (duplicate same blob)

#[test_only]
const HEAD1: vector<u8> =
    x"04422c9487f442300bf68985ccf6aa95843dffa3c16f4b0003ee06a54bcb9c12";
#[test_only]
const HEAD2: vector<u8> =
    x"53f989c806a9aa5dfb3f02dd58548325a1003e41356bd5546f9df15a741bb4cf";
#[test_only]
const HEAD_DUP: vector<u8> =
    x"77c136aa8f2681b77992f23fa64fb42b5bcf9a975357c2e362f0fa927d2a53d5";

/// "epoch monotone" + "head changes deterministically" (ATOM_PLAN line
/// 888): two successive owner anchors advance epoch 1 -> 2 and chain the
/// head HEAD1 -> HEAD2, each matching the Python reference vector and each
/// 32 bytes long.
#[test]
fun head_chains_match_python_reference() {
    let mut scenario = sui::test_scenario::begin(TEST_OWNER);
    let mut root = new_root_for_test(TEST_OWNER, scenario.ctx());

    add_chunk(&mut root, fixture_blob_id_32(0x11), 1u8, vector[], scenario.ctx());
    assert!(root.epoch == 1, 600);
    assert!(root.root_hash == HEAD1, 601);
    assert!(root.root_hash.length() == 32, 602);

    add_chunk(
        &mut root,
        fixture_blob_id_32(0x22),
        2u8,
        fixture_blob_id_32(0x11),
        scenario.ctx(),
    );
    assert!(root.epoch == 2, 603);
    assert!(root.root_hash == HEAD2, 604);
    assert!(root.root_hash.length() == 32, 605);

    std::unit_test::destroy(root);
    scenario.end();
}

/// "head changes deterministically" — same previous head + same blob id on
/// two independent roots yields the SAME computed head (and equals the
/// Python reference HEAD1).
#[test]
fun head_deterministic_same_inputs_same_head() {
    let mut scenario = sui::test_scenario::begin(TEST_OWNER);
    let mut root_a = new_root_for_test(TEST_OWNER, scenario.ctx());
    let mut root_b = new_root_for_test(TEST_OWNER, scenario.ctx());

    add_chunk(&mut root_a, fixture_blob_id_32(0x11), 1u8, vector[], scenario.ctx());
    add_chunk(&mut root_b, fixture_blob_id_32(0x11), 1u8, vector[], scenario.ctx());

    assert!(root_a.root_hash == root_b.root_hash, 610);
    assert!(root_a.root_hash == HEAD1, 611);

    std::unit_test::destroy(root_a);
    std::unit_test::destroy(root_b);
    scenario.end();
}

/// Same previous head + DIFFERENT blob id -> DIFFERENT head. Falsifiable by
/// inequality of two genuinely-computed heads (not a self-compare).
#[test]
fun head_different_blob_different_head() {
    let mut scenario = sui::test_scenario::begin(TEST_OWNER);
    let mut root_a = new_root_for_test(TEST_OWNER, scenario.ctx());
    let mut root_b = new_root_for_test(TEST_OWNER, scenario.ctx());

    add_chunk(&mut root_a, fixture_blob_id_32(0x11), 1u8, vector[], scenario.ctx());
    add_chunk(&mut root_b, fixture_blob_id_32(0x99), 1u8, vector[], scenario.ctx());

    assert!(root_a.root_hash != root_b.root_hash, 620);

    std::unit_test::destroy(root_a);
    std::unit_test::destroy(root_b);
    scenario.end();
}

/// "duplicate call different epoch" (ATOM_PLAN line 888) + head-chain
/// property: anchoring the SAME blob id twice still advances BOTH the epoch
/// (+1) AND the head, because the second call's previous head is HEAD1, not
/// the genesis zero. The advanced head matches the Python reference
/// HEAD_DUP = blake2b256(HEAD1 || 0x11*32).
#[test]
fun duplicate_same_blob_advances_epoch_and_head() {
    let mut scenario = sui::test_scenario::begin(TEST_OWNER);
    let mut root = new_root_for_test(TEST_OWNER, scenario.ctx());

    add_chunk(&mut root, fixture_blob_id_32(0x11), 1u8, vector[], scenario.ctx());
    let epoch_after_first = root.epoch;
    let head_after_first = root.root_hash;

    add_chunk(&mut root, fixture_blob_id_32(0x11), 1u8, vector[], scenario.ctx());

    assert!(root.epoch != epoch_after_first, 630);
    assert!(root.epoch == epoch_after_first + 1, 631);
    assert!(root.root_hash != head_after_first, 632);
    assert!(root.root_hash == HEAD_DUP, 633);

    std::unit_test::destroy(root);
    scenario.end();
}
// ============================================================
// END atom #126 (B.3.5) head-update tests.
// ============================================================

// ============================================================
// atom #127 (B.3.6) — ChunkAnchored event: REUSE + VERIFY + MEASURE of
// the byte-stable Stage A #16 event (no new production code, no new field).
// ============================================================
//
// PROVENANCE: the §4.3 canonical `ChunkAnchored` event struct (code line
// 135) and its `event::emit` inside `add_chunk` (code line 210) were
// minted byte-stable by Stage A atom #16 (D.0.2) and are unchanged by
// atoms #124 / #126. Per the #121 (B.3.0) VERIFIED_GREEN forward
// advisory, Stage A already implements the §4.3 surface of #127; this
// atom REUSES + VERIFIES the event shape and ADDS the criterion
// measurement ("event byte size recorded"). It adds NO new production
// code, NO new signature, and NO new event field.
//
// #127 PLAN TEST-LIST MAPPING (ATOM_PLAN line 899) onto the event:
//   * "event emitted"     -> add_chunk_emits_event (code line 422, Stage
//       A #16): asserts exactly one ChunkAnchored carrying root / blob_id
//       / kind / parent / post-increment epoch.
//   * "len32 fields"      -> chunk_anchored_event_len32_and_byte_size
//       (below): asserts the EMITTED event's `blob_id.length() == 32`
//       explicitly (not merely fixture equality), and the chained case's
//       `parent.length() == 32`.
//   * "no content field"  -> proven BY BYTE ACCOUNTING (below): the total
//       BCS size equals the exact sum of the five declared fields, leaving
//       no bytes for any hidden raw-content field. The event carries only
//       a content-ADDRESS (32-byte Walrus `blob_id`) and a chain link
//       (`parent` blob id), never chunk content.
//
// CRITERION (ATOM_PLAN line 900) "event byte size recorded": the BCS
// serialization length of `ChunkAnchored` is RECORDED and pinned here. It
// is variable in exactly one field, `parent`:
//   * parent == 32 bytes : 107 B = root ID 32 + blob_id (uleb 1 + 32)
//                          + kind 1 + parent (uleb 1 + 32) + epoch 8.
//   * parent == empty    :  75 B = ... + parent (uleb 1 + 0) + ...
//   fixed overhead = 74 B (root 32 + blob 33 + kind 1 + epoch 8); the only
//   variable component is `parent` (uleb(len) + len). BCS rules: `ID`
//   wraps a fixed 32-byte `address` (no length prefix); `vector<u8>` is
//   ULEB128(len)-prefixed; `u8`=1; `u64`=8. Python oracle pins 107 and
//   75 — the exact byte counts the future Rust #132 `MemoryRootAnchorArgs`
//   / #133 BCS parity vectors must reproduce for the event projection
//   (CROSS-LANGUAGE BYTE-VALUE LOCK; no Rust mirror exists yet, so this
//   Move-side size is the canonical anchor #132/#133 will mirror).
//
// ATOM_PLAN DISPARITY — 광기 line 898 ("event contains root id, owner,
// blob id, chunk digest, epoch") vs the §4.3 canonical struct
// {root, blob_id, kind, parent, epoch} (PLAN line 293; code line 135):
//   The byte-stable event has NO `owner` field and NO separate
//   `chunk digest` field. This atom adds NEITHER — a new field would break
//   cross-language BCS parity at #132 / #133 and violate the atom #124 /
//   #126 USER-LOCK "ChunkAnchored gains NO field". Resolution (same
//   Option-A reuse+verify+disparity-flag protocol as #2 / #3 / #122 /
//   #124 / #125):
//     * `owner`        — observable via the event's `root` ID: the parent
//        `MemoryRoot.owner` is the ONLY address allowed to emit (add_chunk
//        owner gate E_NOT_OWNER, code line 193). The owner is bound to the
//        root, not duplicated into every event.
//     * `chunk digest` — canonically the Rust call-args field
//        `MemoryRootAnchorArgs.digest: ChunkDigest32` (PLAN §4 line 314),
//        carried off-chain by the SuiCallBuilder, NOT an on-chain event
//        field. On-chain, the content-addressed Walrus `blob_id` (len-32,
//        E_BAD_BLOB_LEN gated) IS the content digest. `ChunkDigest32`
//        already exists at b-memory/src/chunk_digest.rs:118 (atom #86);
//        the binding is implemented by the future Rust anchor-args atom
//        (#132 family), not here.
//
// FALSIFIABILITY: the 107 / 75 constants are INDEPENDENT Python-oracle
// reference values, not recomputed inside Move from the same to_bytes
// call (which would be a self-compare). Asserting
// `std::bcs::to_bytes(ev).length()` equals them is a genuine cross-
// implementation check. A hidden extra field, a wrong length prefix, or a
// content field would flip these asserts to failure.

#[test]
fun chunk_anchored_event_len32_and_byte_size() {
    let mut scenario = sui::test_scenario::begin(TEST_OWNER);
    let mut root = new_root_for_test(TEST_OWNER, scenario.ctx());
    let root_id = sui::object::id(&root);

    // Emit #1: chained parent (32 bytes) -> BCS size 107.
    add_chunk(
        &mut root,
        fixture_blob_id_32(0x44),
        3u8,
        fixture_blob_id_32(0x11),
        scenario.ctx(),
    );
    // Emit #2: no parent (empty vector) -> BCS size 75.
    add_chunk(
        &mut root,
        fixture_blob_id_32(0x55),
        2u8,
        vector[],
        scenario.ctx(),
    );

    let events = event::events_by_type<ChunkAnchored>();
    assert!(events.length() == 2, 700);

    // Event #1 — chained-parent case.
    let ev0 = &events[0];
    assert!(ev0.root == root_id, 701);
    assert!(ev0.blob_id.length() == 32, 702); // "len32 fields"
    assert!(ev0.parent.length() == 32, 703);
    assert!(ev0.epoch == 1, 704);

    // Event #2 — empty-parent case.
    let ev1 = &events[1];
    assert!(ev1.blob_id.length() == 32, 706); // "len32 fields"
    assert!(ev1.parent.length() == 0, 707);
    assert!(ev1.epoch == 2, 708);

    // criterion: event byte size recorded. Independent Python-oracle
    // reference values (107 chained / 75 empty parent); the 32-byte delta
    // confirms `parent` is the sole variable-width field and no hidden
    // content field exists ("no content field" by byte accounting).
    let bytes0 = std::bcs::to_bytes(ev0);
    let bytes1 = std::bcs::to_bytes(ev1);
    assert!(bytes0.length() == 107, 705);
    assert!(bytes1.length() == 75, 709);
    assert!(bytes0.length() - bytes1.length() == 32, 710);

    std::unit_test::destroy(root);
    scenario.end();
}
// ============================================================
// END atom #127 (B.3.6) ChunkAnchored event reuse+verify+measure block.
// ============================================================

// ============================================================
// atom #131 (B.3.10) — transfer_root: REUSE + VERIFY of the
// byte-stable Stage A ownership-transfer entry (no new production
// code) + criterion gas-trace recorded.
// ============================================================
//
// CANONICAL OUT (ATOM_PLAN line 941): "§4.3 `transfer_root`." The
// §4.3 transfer_root entry function was minted byte-stable by Stage A
// (#17 / D.0.3) and is ALREADY PRESENT in this module:
//   * `public entry fun transfer_root(`                     (line 254)
//   * owner gate `assert!(ctx.sender() == root.owner, E_NOT_OWNER)` (line 259)
//   * post-transfer mutation `root.owner = to;`             (line 260)
//   * object handoff `sui::transfer::transfer(root, to);`   (line 261)
// Per the atom #124 (B.3.3) USER-LOCKED 2026-05-31 Option-A precedent
// and the atom #125 (B.3.4) owner-only-spine precedent (reuse + verify
// when Stage A is byte-stable), atom #131 REUSES + VERIFIES this entry
// and adds NO new production code, NO new signature, NO new abort const,
// and performs NO §4 registry mint in Session 1 (that is Session 2's
// ratification step). The declared gate is G-B-MOVE (`sui move build` +
// `sui move test`); the green build+test over the existing entry IS the
// verification artifact.
//
// 광기 사양 MAPPING (ATOM_PLAN line 942: "transfer changes owner through
// Sui object transfer; old owner loses mutation path"):
//   * "changes owner through Sui object transfer" -> `root.owner = to`
//     (line 260) is committed BEFORE `sui::transfer::transfer(root, to)`
//     (line 261). `MemoryRoot has key` only (no `store`), so the
//     module-internal `sui::transfer::transfer` is the canonical handoff
//     and the receiver becomes the on-chain owner of the object.
//   * "old owner loses mutation path" -> the in-struct `root.owner`
//     reassignment makes any subsequent `add_chunk` whose `ctx.sender()`
//     equals the OLD owner abort on the add_chunk owner gate
//     (E_NOT_OWNER, line 193). At the Sui runtime layer the old owner
//     also no longer holds the transferred object, so the path is closed
//     at BOTH the module-logic layer and the runtime ownership layer.
//   * Self-transfer (`to == root.owner == ctx.sender()`) is well-defined
//     and harmless: `root.owner` is re-assigned to itself and Sui's
//     `transfer::transfer` accepts `to == sender` (the object stays with
//     the same owner).
//
// #131 PLAN TEST-LIST MAPPING (ATOM_PLAN line 943: "owner transfers,
// non-owner aborts, old owner cannot anchor") onto the EXISTING
// byte-stable tests minted by atom #17 — all pass under `sui move test`,
// with NO rewrite of any Stage A test and NO new test added (a new test
// would duplicate existing coverage — the #124 / #125 no-Stage-A-test-
// rewrite discipline):
//   * "owner transfers"        -> transfer_by_owner_changes_owner
//       (line 492): owner transfers, new owner observed via
//       take_from_sender (`received.owner == TEST_NON_OWNER`).
//   * "non-owner aborts"       -> transfer_by_non_owner_aborts
//       (line 513, expected_failure E_NOT_OWNER): a sender that is NOT
//       root.owner calling transfer_root aborts on the line-259 gate.
//   * "old owner cannot anchor" -> post_transfer_old_owner_cannot_add_chunk
//       (line 528): after transfer_root reassigns `root.owner`, the OLD
//       owner's add_chunk aborts on the line-193 owner gate (E_NOT_OWNER).
// Coverage is COMPLETE with ZERO gap across the transfer entry's three
// declared behaviors.
//
// CRITERION — "gas trace recorded" (ATOM_PLAN line 944): recorded via
// `sui move test -s` (`--statistics`), which reports per-test execution
// statistics for the three transfer tests above. HONEST CLASSIFICATION:
// the Move UNIT-TEST framework reports test-harness statistics, NOT the
// on-chain VM gas a real testnet PTB would consume. The byte-exact
// on-chain gas trace for a live `transfer_root` PTB is produced by the
// testnet dry-run path (atom #134 / B.3.13, gate G-B-SUI-DRYRUN) and is
// DEFERRED there; recording it here would require a live network call,
// which this Move-unit atom does not make. The recorded artifact is the
// `sui move test -s` statistics output captured in the atom #131 sidecar
// (test_results.json + gate_results.json).
//
// SCOPE — deliberately omitted (each has its own canonical home;
// atom-#2 / #3 / #122 / #124 / #125 disparity-marker precedent):
//   * Move Prover FORMAL transfer/owner invariant: spec atoms
//     (`memory_root.spec.move`) — ATOM_PLAN §4 Prover family.
//   * Rust `SuiCallBuilder` transfer-args projection: atom #132 / #134 /
//     #146 family (testnet-only call builders, dry-run, no signing).
//   * true on-chain gas trace: atom #134 (B.3.13) testnet dry-run.
// ============================================================

// ============================================================
// atom #136 (B.3.15) — Move unit tests: memory_root REUSE-ACK (no new code).
// ============================================================
//
// atom #136 (B.3.15) canonical OUT (ATOM_PLAN line 996): "memory_root test
// suite". The plan `file` field (ATOM_PLAN line 995) names a NEW
// `prototype/move/tests/memory_root_tests.move`, but the byte-stable
// memory_root test suite that covers every owner/len/epoch/event path
// (ATOM_PLAN line 997-998) was already minted IN-MODULE by Stage A atom
// #16 / #17 + Stage B atoms #122 / #123 / #126 / #127 and re-verified green
// here. #136 is therefore a REUSE-ACK (no new code), the same discipline as
// #124 / #125 / #131.
//
// FILE-FIELD DISPARITY (advisory; #124 / #125 / #131 disparity-marker
// precedent): a SEPARATE `tests/` module CANNOT reach the `MemoryRoot`
// struct fields (`owner` / `root_hash` / `chunk_count` / `epoch`) or the
// `#[test_only]` helpers (`new_root_for_test` line 360,
// `new_root_with_root_hash` line 604, `fixture_blob_id_32` line 349,
// `zero_blob_id_32` line 338) that the white-box owner/len/epoch/event
// assertions require. Re-scaffolding into the canonical
// `tests/memory_root_tests.move` path would EITHER duplicate the existing
// coverage OR force a production test-getter surface expansion on
// `MemoryRoot` — both rejected. The in-module `#[test]` suite is the
// canonical test home; NO new `tests/` file is created (USER-LOCKED option
// B, 2026-06-01). `prototype/move/tests/bcs_vectors.move` (#133) remains the
// separate black-box BCS-layout suite.
//
// #136 PLAN TEST-LIST MAPPING (ATOM_PLAN line 998: "create, anchor,
// non-owner, bad len, transfer, event") onto the EXISTING byte-stable
// in-module tests — all pass under `sui move test` (16 memory_root tests,
// 0 failed; total package 27/27 incl 7 audit_log + 4 bcs_vectors), with NO
// rewrite of any prior test and NO new test added:
//   * "create"    -> create_root_sets_sender_as_owner (line 683),
//       create_root_initial_epoch_count_head (line 696),
//       struct_init_sets_fields_and_root_hash_len_32 (line 623).
//   * "anchor"    -> add_chunk_by_owner_succeeds (line 371),
//       head_chains_match_python_reference (line 870),
//       head_deterministic_same_inputs_same_head (line 898),
//       head_different_blob_different_head (line 917),
//       duplicate_same_blob_advances_epoch_and_head (line 938).
//   * "non-owner" -> add_chunk_by_non_owner_aborts (line 403,
//       expected_failure E_NOT_OWNER), transfer_by_non_owner_aborts (line
//       513, E_NOT_OWNER), post_transfer_old_owner_cannot_add_chunk (line
//       528, E_NOT_OWNER).
//   * "bad len"   -> add_chunk_rejects_bad_blob_len (line 453,
//       expected_failure E_BAD_BLOB_LEN),
//       struct_init_rejects_bad_root_hash_len (line 647,
//       expected_failure E_BAD_ROOT_HASH_LEN).
//   * "transfer"  -> transfer_by_owner_changes_owner (line 492),
//       transfer_by_non_owner_aborts (line 513),
//       post_transfer_old_owner_cannot_add_chunk (line 528).
//   * "event"     -> add_chunk_emits_event (line 422),
//       chunk_anchored_event_len32_and_byte_size (line 1033).
// Coverage is COMPLETE with ZERO gap across all six declared paths.
//
// CRITERION — "gas trace emitted" (ATOM_PLAN line 999): recorded via
// `sui move test -s` (`--statistics`), which prints a per-test
// `name / time / gas_used` table for all 16 memory_root tests. HONEST
// CLASSIFICATION (identical to #131): the Move UNIT-TEST framework reports
// test-harness gas statistics, NOT the on-chain VM gas a real testnet PTB
// would consume. The byte-exact on-chain gas trace for live memory_root PTBs
// is produced by the testnet dry-run path (atom #134 / B.3.13, gate
// G-B-SUI-DRYRUN) and the publish ceremony (#142 / #143), both DEFERRED
// there; recording it here would require a live network call, which this
// Move-unit atom does not make. The recorded artifact is the
// `sui move test -s` statistics output captured in the atom #136 sidecar
// (test_results.json + gate_results.json).
//
// SCOPE — deliberately omitted (each has its own canonical home;
// atom-#2 / #3 / #122 / #124 / #125 / #131 disparity-marker precedent):
//   * Move Prover FORMAL owner / len / monotone invariants: spec atoms
//     #138 / #139 (`memory_root.spec.move`) — ATOM_PLAN §4 Prover family.
//     #136 is a G-B-MOVE unit-test atom, NOT a G-B-PROVER atom.
//   * audit_log unit tests: atom #137 (`audit_log` in-module suite).
//   * Rust `SuiCallBuilder` projection / dry-run / live publish: atoms #132 /
//     #134 / #142 / #143 / #146 family (testnet-only, no signing this atom).
//   * true on-chain gas trace: atom #134 (B.3.13) testnet dry-run.
// ============================================================
