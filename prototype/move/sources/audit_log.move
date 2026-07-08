// atom #121 · B.3.0 — Stage B Move package scaffold: mnemos::audit_log.
// atom #128 · B.3.7 — fills the AuditLog object + create_log entry fun.
//
// Canonical OUT (atom #121, ATOM_PLAN line 831): "Stage B Move package
// skeleton." This file is the Cluster-3 (#121-#145) source for the
// audit-log module. atom #121 reserved the `mnemos::audit_log` module
// namespace inside the EXISTING testnet-targeted `mnemos` package
// (prototype/move/Move.toml, Stage A atoms #15/#19) so that the Walrus/Sui
// memory-ownership atoms downstream can fill its append-only surface without
// re-scaffolding the package.
//
// atom #121 광기 사양 (ATOM_PLAN line 832):
// - package is testnet-targeted: Move.toml `mnemos = "0x0"` pre-publish
//   placeholder, `published-at` commented out, Sui rev vendored-pinned. NO
//   mainnet network / RPC / published-at config exists (mainnet-config grep
//   over non-comment lines == 0; the only "mainnet" occurrences in Move.toml
//   are anti-mainnet safety comments documenting the ban).
// - named addresses explicit: `[addresses] mnemos = "0x0"`.
// - no mainnet publish config: scaffold introduces none.
// - mirrors the Stage B no-mainnet discipline of #82
//   `mnemos_b_memory::network::StageBNetwork` (which has NO mainnet enum
//   variant; testnet-only at the Rust boundary). This Move package carries
//   the same testnet-only spine on the on-chain side.
//
// ============================================================
// atom #128 (B.3.7) — audit_log object: AuditLog struct + create_log.
// ============================================================
//
// atom #128 canonical OUT (§4.3 lines 305-310 / ATOM_PLAN line 908):
//   public struct AuditLog has key { id: UID, owner: address, seq: u64,
//                                    head_hash: vector<u8> }
//   public entry fun create_log(ctx: &mut TxContext)
// The #121 scaffold header explicitly assigned BOTH the struct AND
// `create_log` to this atom (#121 deferral note lines: "atom #128 (B.3.7):
// `public struct AuditLog ...` + `public entry fun create_log(ctx)`").
//
// atom #128 광기 사양 (ATOM_PLAN line 909):
// - audit log stores owner, seq, head_hash.
// - append-only by construction: this atom introduces NO mutation entry
//   point. The owner-gated, monotone-`seq`, head-chained `append` is atom
//   #129 (B.3.8); the `AuditAppended` event is atom #130 (B.3.9). Because
//   #128 ships only `create_log` (which mints an immutable-until-#129
//   object) there is no on-chain path that can rewrite or delete an entry —
//   append-only is a structural property, not a runtime check.
//
// Genesis values (create_log):
// - `owner` is `ctx.sender()` (`tx_context::sender`); there is no
//   caller-supplied owner argument, so a log can only be created for the
//   calling wallet. Mirrors `memory_root::create_root` (atom #123).
// - `seq` starts at 0 (no entries appended yet).
// - `head_hash` is the 32-byte zero genesis constant `GENESIS_HEAD_HASH`,
//   matching the 32-byte width of the audit entry-hash produced off-chain
//   by #95 `mnemos_b_memory::audit_digest::stage_b_audit_entry_hash(...) ->
//   [u8; 32]` (prototype/crates/b-memory/src/audit_digest.rs:150). The
//   `head_hash` is the chain head that #129 `append` will advance; #128 only
//   seeds it. This is the same genesis-zero discipline as
//   `memory_root::GENESIS_ROOT_HASH` (atom #123, line ~271) — a fresh local
//   constant, NOT a cross-module import (audit_log keeps its own genesis to
//   avoid coupling its head-chain to the memory-root chain).
//
// REUSE NOTE (ATOM_PLAN line 913, "#95 audit digest"): the reuse is a
// CROSS-LANGUAGE 32-byte WIDTH concordance only — the off-chain Rust
// `stage_b_audit_entry_hash` yields the `[u8; 32]` digest that #129 `append`
// will pass in as `entry_hash` and fold into `head_hash`. It is NOT a Move
// symbol imported here; #128 ships no `append` and binds no entry hash yet.
//
// audit_log never stores raw content (ATOM_PLAN line 504): the only
// vector<u8> field is `head_hash`, a 32-byte digest. No content / secret /
// payload field exists on `AuditLog`.
//
// Scope deliberately deferred to later Cluster-3 atoms (NOT implemented here):
// - atom #129 (B.3.8): `public entry fun append(log, entry_hash, ctx)` —
//   owner-only, append-only `seq` monotone +1, `head_hash` chained; entry
//   hash len == 32; audit_log never stores raw content.
// - atom #130 (B.3.9): `public struct AuditAppended has copy, drop { log,
//   owner, seq, entry_hash }` emit.
// Implementing append / AuditAppended here would steal #129 / #130 scope
// (same canonical-OUT-explicit discipline as atoms #2 / #3 / #122 / #124).
//
// criterion (ATOM_PLAN line 911): N/A — no gas trace / live deploy this atom
// (G-B-MOVE local build/test only; no testnet approval this session).

module mnemos::audit_log;

/// Genesis 32-byte zero `head_hash` for a freshly created `AuditLog`.
///
/// 32 bytes wide to match the audit entry-hash width minted off-chain by
/// #95 `mnemos_b_memory::audit_digest::stage_b_audit_entry_hash -> [u8; 32]`
/// and the `head_hash`/`entry_hash` chain that atom #129 `append` advances.
/// A fresh local constant (NOT `memory_root::GENESIS_ROOT_HASH`) so the
/// audit-log head chain is decoupled from the memory-root chain. There is no
/// caller-supplied `head_hash` argument on `create_log` (canonical signature
/// §4.3 line 308 takes only `ctx`), so there is no untrusted length to gate
/// at runtime this atom.
const GENESIS_HEAD_HASH: vector<u8> =
    x"0000000000000000000000000000000000000000000000000000000000000000";

/// Append-only audit-log object pinned to a Sui account. One per owner
/// wallet records, by `seq` and chained `head_hash`, every audited memory
/// mutation — without ever storing the raw content itself.
///
/// Fields:
/// - `id` — Sui object infrastructure handle; set by `object::new`.
/// - `owner` — 32-byte wallet address that owns this log. The append entry
///   point (atom #129) gates on `ctx.sender() == self.owner`.
/// - `seq` — monotonically-increasing entry counter. Starts at 0 on
///   `create_log`; atom #129 `append` increments it exactly once per
///   successful append (the append-only `seq` monotone invariant proved by
///   the Move Prover spec in atom #139 / audit_log.spec.move).
/// - `head_hash` — 32-byte hash chaining the appended audit entries. Seeded
///   to `GENESIS_HEAD_HASH` (all-zero) by `create_log`; advanced by atom
///   #129 `append`. The `len == 32` invariant matches the off-chain audit
///   entry-hash width (#95) and is held by construction here (the genesis
///   constant is exactly 32 bytes).
///
/// `seq` and `head_hash` are written by `create_log` but not read by any
/// production code THIS atom (the first reader is atom #129 `append`); the
/// W09009 `unused_field` lint is suppressed via `#[allow(unused_field)]`,
/// the same pattern used by `memory_root::MemoryRoot` (atom #16) for its
/// `root_hash` field before atom #126 began reading it.
#[allow(unused_field)]
public struct AuditLog has key {
    id: sui::object::UID,
    owner: address,
    seq: u64,
    head_hash: vector<u8>,
}

/// Entry point: mint a fresh `AuditLog` owned by the transaction sender and
/// hand it to that sender's account.
///
/// atom #128 / B.3.7 canonical OUT (§4.3 line 308 / ATOM_PLAN line 908):
///   `public entry fun create_log(ctx: &mut TxContext)`
///
/// 광기 사양 (ATOM_PLAN line 909):
/// - `owner` is `ctx.sender()` (`tx_context::sender`); there is no
///   caller-supplied owner argument, so a log can only be created for the
///   calling wallet.
/// - `seq` starts at 0.
/// - `head_hash` is the 32-byte zero genesis constant `GENESIS_HEAD_HASH`.
/// - append-only by construction: this atom adds no mutation path; `append`
///   is atom #129.
///
/// The minted object is account-owned: `AuditLog has key` only (no `store`),
/// so the module-internal `sui::transfer::transfer` is the canonical handoff
/// (same family as `memory_root::create_root`, atom #123). `owner` is bound
/// once before `sui::object::new` to avoid aliasing the `ctx` borrow across
/// the mutable `object::new` and the immutable `sender()`.
///
/// The `public entry` modifier is canonical per §4.3; Move 2024 flags
/// `entry` on `public` as redundant (W99010 / `public_entry`), suppressed
/// locally with the same justification as `memory_root::create_root`: the
/// canonical signature is pinned by the plan and consumed downstream (atom
/// #129 `append` takes `&mut AuditLog`, atom #146 Rust SDK call builder).
#[allow(lint(public_entry))]
public entry fun create_log(ctx: &mut TxContext) {
    let owner = ctx.sender();
    let log = AuditLog {
        id: sui::object::new(ctx),
        owner,
        seq: 0,
        head_hash: GENESIS_HEAD_HASH,
    };
    sui::transfer::transfer(log, owner);
}

// ============================================================
// atom #129 (B.3.8) — audit append entry: owner-gated, monotone-seq,
// head-chained `append`.
// ============================================================

/// Abort code raised by `append` when `ctx.sender() != log.owner`.
///
/// Module-local numbering mirrors `memory_root` (`E_NOT_OWNER = 1`,
/// memory_root.move:78): each module numbers its own abort codes from 1, so
/// `audit_log` mints its OWN `E_NOT_OWNER` rather than importing the
/// memory_root constant. The two modules' abort spaces stay decoupled — the
/// same decoupling discipline as the local `GENESIS_HEAD_HASH` (which is NOT
/// `memory_root::GENESIS_ROOT_HASH`).
const E_NOT_OWNER: u64 = 1;

/// Abort code raised by `append` when `entry_hash.length() != 32`.
///
/// Mirrors the `add_chunk` `E_BAD_BLOB_LEN` (= 2) length gate
/// (memory_root.move:83). The 32-byte width is the off-chain audit
/// entry-hash width minted by #95
/// `mnemos_b_memory::audit_digest::stage_b_audit_entry_hash -> [u8; 32]`
/// (prototype/crates/b-memory/src/audit_digest.rs:150); a wrong-width entry
/// hash is rejected before any state write.
const E_BAD_ENTRY_LEN: u64 = 2;

// ============================================================
// atom #130 (B.3.9) — AuditAppended event.
// ============================================================

/// Event emitted by `append` (atom #130 / B.3.9) once an audit entry has been
/// folded into an owner's `AuditLog`.
///
/// atom #130 canonical OUT (§4.3 line 307 / ATOM_PLAN line 930):
///   `public struct AuditAppended has copy, drop { log: ID, owner: address,
///                                                 seq: u64, entry_hash: vector<u8> }`
///
/// 광기 사양 (ATOM_PLAN line 931): the event carries the log id, owner, seq,
/// and entry hash — and NO raw content or secret. Every field is either an
/// identifier/counter or the 32-byte audit DIGEST:
/// - `log` — the parent `AuditLog`'s Sui object `ID` (`sui::object::id`), so a
///   subscriber can attribute the entry to the owning log without the log
///   duplicating itself into the event.
/// - `owner` — the 32-byte wallet address that owns the log and is the ONLY
///   address allowed to emit (the `append` owner gate, `E_NOT_OWNER`). Carried
///   explicitly here (unlike `ChunkAnchored`, which leaves `owner` implicit via
///   its `root` ID) because the §4.3 canonical struct names `owner` as a field.
/// - `seq` — the POST-increment entry counter (so the first emit carries
///   `seq = 1`), mirroring the persisted `AuditLog.seq` after the append.
/// - `entry_hash` — the 32-byte audit entry hash minted off-chain by #95
///   `mnemos_b_memory::audit_digest::stage_b_audit_entry_hash -> [u8; 32]`
///   (b-memory/src/audit_digest.rs:150). It is a content-ADDRESS / digest, not
///   the audited content itself; `AuditLog` and this event have no content /
///   secret / payload field (ATOM_PLAN line 504 / 931).
///
/// `has copy, drop` is the event-struct ability set required by
/// `sui::event::emit` (same as `memory_root::ChunkAnchored`, code line 135).
///
/// CRITERION (ATOM_PLAN line 933) "event byte size recorded": the BCS
/// serialization length of `AuditAppended` is the FIXED constant 105 B:
///   `log` ID 32 (BCS `ID` wraps a fixed 32-byte `address`, no length prefix)
///   + `owner` address 32 + `seq` u64 8
///   + `entry_hash` vector<u8> (ULEB128(32) = 1 byte + 32 bytes = 33).
/// = 105 B. Unlike `ChunkAnchored` (107 / 75, variable in `parent`), there is
/// NO variable-width field: `entry_hash` is gated to exactly 32 bytes by
/// `E_BAD_ENTRY_LEN`, so the event size is a single canonical value. The 105
/// constant is an INDEPENDENT Python-oracle reference (NOT recomputed inside
/// Move from the same `to_bytes` call); a hidden raw-content field, a wrong
/// length prefix, or a stray field would push the size off 105 and flip the
/// `audit_appended_event_emitted_seq_and_byte_size` assert — a falsifiable
/// cross-implementation check (`[[formal-method-assertion-must-be-falsifiable]]`,
/// same discipline as `ChunkAnchored` 107 / 75). The cross-language byte-value
/// pin for the future Rust mirror lands with #137 / #140.
public struct AuditAppended has copy, drop {
    log: sui::object::ID,
    owner: address,
    seq: u64,
    entry_hash: vector<u8>,
}

/// Entry point: append one audit entry hash to an owner's `AuditLog`,
/// advancing the `seq` counter and the chained `head_hash`.
///
/// atom #129 / B.3.8 canonical OUT (§4.3 line 309 / ATOM_PLAN line 919):
///   `public entry fun append(log: &mut AuditLog, entry_hash: vector<u8>, ctx: &mut TxContext)`
///
/// 광기 사양 (ATOM_PLAN line 920):
/// - owner-only: `ctx.sender() == log.owner` — `E_NOT_OWNER` abort otherwise.
/// - `entry_hash` length == 32 enforced — `E_BAD_ENTRY_LEN` abort otherwise.
/// - `seq` increments exactly once (`+ 1`) per successful append.
///
/// head_hash advance (USER-LOCKED 2026-05-31; byte-exact mirror of the
/// memory_root #126 rule, memory_root.move:206-208):
/// - `next_head_hash = sui::hash::blake2b256(previous_head_hash[32] || entry_hash[32])`.
///   The preimage is the byte-exact 64-byte concatenation
///   `previous_head_hash || entry_hash` with NO other field folded in (NOT
///   `seq`, NOT `owner`) — the same "no other field" discipline as the
///   user-locked memory_root head rule, and explicitly NOT the rejected
///   latest-alias (`head_hash := entry_hash`; the alias loses the chain
///   property the way memory_root.move:174 rejects `root_hash := blob_id`).
/// - `head_hash` stays exactly 32 bytes by construction (blake2b256 output
///   width) and chains off the 32-byte `GENESIS_HEAD_HASH` seed minted by
///   `create_log`.
///
/// Append-only: this is the ONLY mutation entry point on `AuditLog`. It adds
/// to `seq`/`head_hash` and never deletes or rewrites an entry. As of atom
/// #130 (B.3.9) an `AuditAppended` event IS emitted here AFTER the state
/// advance; the emit is read-only with respect to state (the event is a
/// `copy, drop` projection of the post-increment `seq` + the just-validated
/// `entry_hash`), so the append-only property is preserved. The
/// append-only `seq` monotone + no-overwrite/delete invariant is formalized
/// by the Move Prover spec in atom #140 / audit_log.spec.move; the exact
/// cross-language head byte-value is pinned later by #137 / #140 (this atom
/// asserts only falsifiable structural head properties).
///
/// No raw content is stored: `entry_hash` is a 32-byte digest folded into
/// the head; the audited content itself never touches on-chain state
/// (audit_log has no content / secret / payload field — ATOM_PLAN line 504).
///
/// `entry_hash` is reused by the atom #130 `AuditAppended` emit below, so the
/// `vector::append` into `preimage` is an implicit COPY (not a move) — the
/// byte-exact `add_chunk` pattern where `blob_id` stays available for the
/// `ChunkAnchored` emit (memory_root.move:204-216). `log.head_hash` is a
/// copyable `vector<u8>`, so reading it copies the PREVIOUS head before the
/// overwrite below.
///
/// The `public entry` modifier is canonical per §4.3; Move 2024 flags
/// `entry` on `public` as redundant (W99010 / `public_entry`), suppressed
/// locally with the same justification as `create_log` / `add_chunk`: the
/// canonical signature is pinned by the plan and consumed downstream (atom
/// #146 Rust SDK call builder for `audit_log::append`).
#[allow(lint(public_entry))]
public entry fun append(
    log: &mut AuditLog,
    entry_hash: vector<u8>,
    ctx: &mut TxContext,
) {
    assert!(ctx.sender() == log.owner, E_NOT_OWNER);
    assert!(entry_hash.length() == 32, E_BAD_ENTRY_LEN);

    log.seq = log.seq + 1;

    // atom #129 (B.3.8): advance the chain head (USER-LOCKED #126 mirror).
    // preimage = previous_head_hash[32] || entry_hash[32]  (64 bytes,
    // byte-exact; NO other field folded in). `log.head_hash` is a copyable
    // vector<u8>, so reading it here copies the PREVIOUS head before the
    // overwrite below; `entry_hash` is COPIED into the preimage (it is reused
    // by the atom #130 emit below, so this `append` is an implicit copy — the
    // add_chunk/blob_id pattern, memory_root.move:204-216).
    let mut preimage = log.head_hash;
    preimage.append(entry_hash);
    log.head_hash = sui::hash::blake2b256(&preimage);

    // atom #130 (B.3.9): emit AuditAppended AFTER the seq + head advance so
    // `seq` is the POST-increment value and the event mirrors the persisted
    // state ("seq matches state", ATOM_PLAN line 932). Byte-exact mirror of
    // the add_chunk -> ChunkAnchored emit (memory_root.move:210-216):
    // `log = sui::object::id(log)` (auto-freeze of the `&mut AuditLog`),
    // `owner`/`seq` are Copy, and `entry_hash` is copied (used here AND in the
    // preimage append above). No raw content / secret is carried — `entry_hash`
    // is the 32-byte off-chain audit digest (#95) and there is no content /
    // payload field (ATOM_PLAN line 504 / 931).
    sui::event::emit(AuditAppended {
        log: sui::object::id(log),
        owner: log.owner,
        seq: log.seq,
        entry_hash,
    });
}

/// atom #138 · B.3.17 — additive owner getter for the owner-only Move
/// Prover invariant (gate G-B-PROVER); mirror of `memory_root::owner`.
///
/// The ONLY production change atom #138 makes to this module. It exposes
/// the private `owner` field as a zero-logic read so the separate
/// `MnemosProver` package can state owner-only on the REAL `append`
/// function. Owner-only is proven as success-implies-owner, NOT a no-abort
/// claim (`#[spec(prove, ignore_abort)]` + `ensures(ctx.sender() == pre_owner)`):
/// `append`'s line-303 gate checks `ctx.sender() == log.owner` before any
/// mutation, so a non-owner caller aborts before reaching state mutation.
/// No `seq()` getter is added — the independent entry-length / seq-overflow
/// aborts belong to atoms #139 / #140. USER-LOCKED 2026-06-01.
public fun owner(log: &AuditLog): address {
    log.owner
}

/// atom #140 · B.3.19 — additive `seq` getter for the Move Prover
/// append-only invariant (gate G-B-PROVER); mirror of `owner`.
///
/// Exposes the private `seq` field as a zero-logic read so the separate
/// `MnemosProver` package can state the append-only invariant on the REAL
/// `append` function: a successful append advances `seq` by exactly 1
/// (`ensures(seq(log) == pre_seq + 1)`), so the audit log is append-only and
/// the sequence number never resets or decreases. atom #138 deliberately
/// deferred this getter to #140 (see the `owner` doc above). USER-LOCKED
/// 2026-06-01: the consumed-only ABI adds the `seq` getter ONLY — no
/// `head_hash()` getter (the plan #140 광기 is append-only + seq-once, not a
/// head length claim, and head_hash state length is not provable while the
/// pinned SuiSpecs `blake2b256` spec is a passthrough).
public fun seq(log: &AuditLog): u64 {
    log.seq
}

// ============================================================
// #[test_only] helpers and tests for atom #128 (B.3.7).
// ============================================================
//
// The ATOM_PLAN line 910 test list is descriptive ("create log, initial
// seq/head, owner set"), not verbatim snake_case (same shape as atom #123's
// "create root owner, initial epoch/count/head"). It is covered by two
// tests, mirroring the #123 create_root tests:
//   create_log_sets_sender_as_owner   — owner == tx sender.
//   create_log_initial_seq_head       — seq == 0, head_hash len == 32 AND
//                                        all-zero.
//
// `create_log` consumes the minted object into the sender's account via
// `sui::transfer::transfer` (no return value), so each test opens a
// follow-up tx as the sender and pulls the object back with
// `take_from_sender` for inspection, then returns it via `return_to_sender`
// to satisfy the framework's object-leak check (same pattern as
// `memory_root::create_root_sets_sender_as_owner`, atom #123).

#[test_only]
const TEST_OWNER: address = @0xAA;
/// A wallet that is NOT the log owner; drives the `append` owner-gate
/// negative test (atom #129). Mirrors `memory_root::TEST_NON_OWNER` (@0xBB).
#[test_only]
const TEST_NON_OWNER: address = @0xBB;

/// Independent 32-byte all-zero derivation, built byte-by-byte. Used to
/// assert `head_hash == genesis` WITHOUT self-comparing against the
/// `GENESIS_HEAD_HASH` source constant, so the equality is a falsifiable
/// property rather than a tautology (`[[formal-method-assertion-must-be-
/// falsifiable]]`; same discipline as `memory_root::zero_blob_id_32`).
#[test_only]
fun zero_hash_32(): vector<u8> {
    let mut v: vector<u8> = vector[];
    let mut i = 0u64;
    while (i < 32) {
        v.push_back(0u8);
        i = i + 1;
    };
    v
}

/// A deterministic 32-byte fixture entry hash filled with `fill`, built
/// byte-by-byte. Stands in for the off-chain #95
/// `stage_b_audit_entry_hash -> [u8; 32]` digest at the `append` boundary.
/// Mirrors `memory_root::fixture_blob_id_32`.
#[test_only]
fun entry_hash_32(fill: u8): vector<u8> {
    let mut v: vector<u8> = vector[];
    let mut i = 0u64;
    while (i < 32) {
        v.push_back(fill);
        i = i + 1;
    };
    v
}

/// Construct an `AuditLog` in genesis state (seq 0, head = `GENESIS_HEAD_HASH`)
/// owned by `owner`, returned by value so a test can hold `&mut log` and then
/// switch the tx sender (the owner-gate negative test needs a sender that is
/// NOT the owner). Mirrors `memory_root::new_root_for_test` (atom #16). The
/// returned object is routed through `std::unit_test::destroy` by each test
/// (`AuditLog has key`, no `drop`).
#[test_only]
fun new_log_for_test(owner: address, ctx: &mut TxContext): AuditLog {
    AuditLog {
        id: sui::object::new(ctx),
        owner,
        seq: 0,
        head_hash: GENESIS_HEAD_HASH,
    }
}

#[test]
fun create_log_sets_sender_as_owner() {
    let mut scenario = sui::test_scenario::begin(TEST_OWNER);
    create_log(scenario.ctx());

    scenario.next_tx(TEST_OWNER);
    let received = sui::test_scenario::take_from_sender<AuditLog>(&scenario);
    assert!(received.owner == TEST_OWNER, 600);

    sui::test_scenario::return_to_sender<AuditLog>(&scenario, received);
    scenario.end();
}

#[test]
fun create_log_initial_seq_head() {
    let mut scenario = sui::test_scenario::begin(TEST_OWNER);
    create_log(scenario.ctx());

    scenario.next_tx(TEST_OWNER);
    let received = sui::test_scenario::take_from_sender<AuditLog>(&scenario);
    assert!(received.seq == 0, 610);
    // Head is the genesis 32-byte zero constant. Assert len == 32 and
    // compare against an INDEPENDENT zero derivation (`zero_hash_32`), not
    // the `GENESIS_HEAD_HASH` source itself, so the equality is falsifiable.
    assert!(received.head_hash.length() == 32, 611);
    assert!(received.head_hash == zero_hash_32(), 612);

    sui::test_scenario::return_to_sender<AuditLog>(&scenario, received);
    scenario.end();
}

// ============================================================
// atom #129 (B.3.8) — append tests.
// ============================================================
//
// Test naming maps to ATOM_PLAN line 921 ("append succeeds owner, non-owner
// aborts, bad len aborts"):
//   append_by_owner_succeeds      — owner appends; seq 0 -> 1 (exactly once);
//                                    head advances to 32 bytes != genesis.
//   append_by_non_owner_aborts    — non-owner sender aborts E_NOT_OWNER.
//   append_rejects_bad_entry_len  — entry_hash len != 32 aborts E_BAD_ENTRY_LEN.
//
// All three construct the log via `new_log_for_test` (mirroring
// `memory_root`'s add_chunk tests) so the test holds `&mut log` directly and
// can switch the tx sender for the owner-gate negative case. `AuditLog has
// key` (no `drop`), so each body routes the instance through
// `std::unit_test::destroy` after the assertions.
//
// The exact head BYTE value is intentionally NOT pinned here (no external
// reference vector this atom); #129 asserts only falsifiable STRUCTURAL head
// properties (len == 32, head != genesis via an independent zero
// derivation). The cross-language head byte-value pin lands with #137 /
// #140. This keeps #129 from unilaterally locking a cross-language byte
// surface (`[[cross-language-schema-lock]]`).

#[test]
fun append_by_owner_succeeds() {
    let mut scenario = sui::test_scenario::begin(TEST_OWNER);
    let mut log = new_log_for_test(TEST_OWNER, scenario.ctx());

    // Precondition (falsifiable, independent zero derivation): fresh log
    // starts at seq 0 with the genesis 32-byte zero head.
    assert!(log.seq == 0, 620);
    assert!(log.head_hash == zero_hash_32(), 621);

    append(&mut log, entry_hash_32(0xAA), scenario.ctx());

    // seq increments exactly once: 0 -> 1 (not +2, not unchanged).
    assert!(log.seq == 1, 622);
    // head advanced to exactly 32 bytes and is no longer the genesis seed.
    // A no-op append (head left unchanged) would FAIL the inequality, so the
    // chain genuinely advanced (compared against an independent zero
    // derivation, not the GENESIS_HEAD_HASH source).
    assert!(log.head_hash.length() == 32, 623);
    assert!(log.head_hash != zero_hash_32(), 624);

    std::unit_test::destroy(log);
    scenario.end();
}

#[test]
#[expected_failure(abort_code = E_NOT_OWNER)]
fun append_by_non_owner_aborts() {
    let mut scenario = sui::test_scenario::begin(TEST_OWNER);
    let mut log = new_log_for_test(TEST_OWNER, scenario.ctx());

    // Hand the tx to TEST_NON_OWNER (who is NOT log.owner); append must abort
    // on the owner gate before any state write.
    scenario.next_tx(TEST_NON_OWNER);
    append(&mut log, entry_hash_32(0xAA), scenario.ctx());

    // Unreachable — append aborts with E_NOT_OWNER above.
    std::unit_test::destroy(log);
    scenario.end();
}

#[test]
#[expected_failure(abort_code = E_BAD_ENTRY_LEN)]
fun append_rejects_bad_entry_len() {
    let mut scenario = sui::test_scenario::begin(TEST_OWNER);
    let mut log = new_log_for_test(TEST_OWNER, scenario.ctx());

    // A 3-byte (non-32) entry hash must abort on the length gate.
    let short_entry: vector<u8> = vector[1u8, 2u8, 3u8];
    append(&mut log, short_entry, scenario.ctx());

    // Unreachable — append aborts with E_BAD_ENTRY_LEN above.
    std::unit_test::destroy(log);
    scenario.end();
}

// ============================================================
// atom #130 (B.3.9) — AuditAppended event tests.
// ============================================================
//
// Test naming maps to ATOM_PLAN line 932 ("event emitted, seq matches state,
// no content field"):
//   audit_appended_event_emitted_seq_and_byte_size — exactly one
//       AuditAppended emitted; carries log id / owner / post-increment seq /
//       32-byte entry hash; BCS byte size == 105 (criterion "event byte size
//       recorded"); "no content field" PROVEN by byte accounting.
//   audit_appended_seq_matches_state_across_two_appends — two emits track the
//       monotone seq 1 then 2; the final event mirrors the persisted seq and
//       each event carries its own distinct entry hash (no stale copy).
//
// Both mirror the #127 `chunk_anchored_event_len32_and_byte_size` pattern:
// emit from a `new_log_for_test`-held object (events are captured by the
// test_scenario event store within the tx — same as add_chunk emits), then
// pull them with `sui::event::events_by_type<AuditAppended>()`.
//
// FALSIFIABILITY: 105 is an INDEPENDENT Python-oracle reference, NOT
// recomputed inside Move from the same `to_bytes` call (which would be a
// self-compare). A hidden raw-content field, a wrong length prefix, or a
// stray field flips the size off 105 and fails the assert
// (`[[formal-method-assertion-must-be-falsifiable]]`). "no content field" is
// proven BY BYTE ACCOUNTING: 105 == log ID 32 + owner 32 + seq 8 +
// entry_hash (uleb(32) 1 + 32) leaves zero bytes for any hidden field, and
// the carried `entry_hash` is the 32-byte audit DIGEST, never raw content.

#[test]
fun audit_appended_event_emitted_seq_and_byte_size() {
    let mut scenario = sui::test_scenario::begin(TEST_OWNER);
    let mut log = new_log_for_test(TEST_OWNER, scenario.ctx());
    let log_id = sui::object::id(&log);

    append(&mut log, entry_hash_32(0xAA), scenario.ctx());

    let events = sui::event::events_by_type<AuditAppended>();
    // "event emitted": exactly one AuditAppended.
    assert!(events.length() == 1, 630);

    let ev = &events[0];
    // event has log id, owner, seq, entry hash (광기 ATOM_PLAN line 931).
    assert!(ev.log == log_id, 631);
    assert!(ev.owner == TEST_OWNER, 632);
    // "seq matches state": event seq == the post-increment persisted seq (1).
    assert!(ev.seq == 1, 633);
    assert!(ev.seq == log.seq, 634);
    // entry_hash is the 32-byte digest carried verbatim — not raw content.
    assert!(ev.entry_hash.length() == 32, 635);
    assert!(ev.entry_hash == entry_hash_32(0xAA), 636);

    // criterion "event byte size recorded" + "no content field" by byte
    // accounting: independent Python-oracle constant 105 ==
    //   log ID 32 + owner address 32 + seq u64 8 + entry_hash (uleb(32)=1 + 32).
    // entry_hash is gated to len 32 (E_BAD_ENTRY_LEN), so the size is FIXED (no
    // variable-width field, unlike ChunkAnchored 107 / 75). A hidden raw-content
    // field would push the size past 105 and flip this assert — falsifiable.
    let bytes = std::bcs::to_bytes(ev);
    assert!(bytes.length() == 105, 637);

    std::unit_test::destroy(log);
    scenario.end();
}

#[test]
fun audit_appended_seq_matches_state_across_two_appends() {
    let mut scenario = sui::test_scenario::begin(TEST_OWNER);
    let mut log = new_log_for_test(TEST_OWNER, scenario.ctx());

    append(&mut log, entry_hash_32(0xAA), scenario.ctx());
    append(&mut log, entry_hash_32(0xBB), scenario.ctx());

    let events = sui::event::events_by_type<AuditAppended>();
    // two emits -> two events, captured in append order.
    assert!(events.length() == 2, 640);

    // "seq matches state": the event seq tracks the monotone counter 1 then 2,
    // and the second event mirrors the final persisted seq.
    assert!(events[0].seq == 1, 641);
    assert!(events[1].seq == 2, 642);
    assert!(events[1].seq == log.seq, 643);
    // each emit carries its own distinct entry hash (no collapse / stale copy).
    assert!(events[0].entry_hash == entry_hash_32(0xAA), 644);
    assert!(events[1].entry_hash == entry_hash_32(0xBB), 645);

    std::unit_test::destroy(log);
    scenario.end();
}

// ============================================================
// atom #137 (B.3.16) — Move unit tests: audit_log (in-module suite).
// ============================================================
//
// USER-LOCKED (2026-06-01, Session 1 option B): the in-module `#[test]` suite
// in THIS file is the canonical test home for atom #137 (B.3.16). NO separate
// `prototype/move/tests/audit_log_tests.move` is created — the `AuditLog`
// struct fields (`owner`/`seq`/`head_hash`), the module-private abort
// constants (`E_NOT_OWNER`, `E_BAD_ENTRY_LEN`), and the `#[test_only]` helpers
// (`new_log_for_test`, `entry_hash_32`, `zero_hash_32`) are all module-private,
// so an out-of-module black-box test cannot read them without widening the
// production API (forbidden this atom: no public getter / helper). Mirrors the
// atom #136 USER-LOCK (memory_root in-module suite) and the #131 / #124 / #125
// precedent; `memory_root.move` already pre-declares "audit_log unit tests:
// atom #137 (`audit_log` in-module suite)".
//
// ATOM_PLAN line 1006 file-field disparity (ADVISORY, not RED): the plan field
// names `prototype/move/tests/audit_log_tests.move`; reality is this in-module
// suite. Recorded as advisory disparity in
// `ops/evidence/stage_b/atom_137/VERIFY_TODO.json` (same shape as #136 ADV-1).
//
// #137 plan test-list (ATOM_PLAN line 1009) -> existing in-module test map:
//   create        -> create_log_sets_sender_as_owner   (owner == tx sender)
//                  + create_log_initial_seq_head        (seq 0, head genesis 32B)
//   append        -> append_by_owner_succeeds           (seq 0 -> 1, head advances)
//   non-owner     -> append_by_non_owner_aborts         (E_NOT_OWNER)
//   bad len       -> append_rejects_bad_entry_len       (E_BAD_ENTRY_LEN)
//   event         -> audit_appended_event_emitted_seq_and_byte_size (emit, 105 B)
//   seq monotone  -> audit_appended_seq_matches_state_across_two_appends (1, 2)
// All six paths were already covered before this atom; #137 adds NO new
// production logic and NO new path coverage. It ADDS the cross-language head
// byte-value pin deliberately deferred to "#137 / #140" by #129 / #130
// (audit_log.move lines 238 / 278 / 460) and #133
// (stage_b_bcs_vectors.rs). #140 keeps the Move Prover append-only / seq / head
// INVARIANT proof (abstract); #137 closes the concrete head BYTE-VALUE pin
// (unit test). The `AuditAppended` event byte size 105 is already pinned by
// `audit_appended_event_emitted_seq_and_byte_size`.
//
// criterion (ATOM_PLAN line 1010) "gas trace emitted": `sui move test` emits a
// per-test gas trace; captured in `ops/evidence/stage_b/atom_137/`.
//
// FALSIFIABILITY (no self-compare): the production `append`
// (audit_log.move:315-317) computes `head =
// sui::hash::blake2b256(previous_head[32] || entry_hash[32])`. The two tests
// below compare that ON-CHAIN head against a hard-coded expected vector
// produced by an INDEPENDENT off-chain Python `blake2b256` oracle
// (`hashlib.blake2b(data, digest_size=32)`), NOT recomputed inside Move from
// the same `blake2b256` call. The oracle is calibrated: Python
// `blake2b256(0x00*32 || 0x11*32) == 04422c94...9c12 ==` the
// `memory_root.move:857` HEAD1 reference already Move-verified by
// `memory_root::head_chains_match_python_reference` (line 870). A wrong head
// (no-op append, wrong preimage order, an extra folded field) flips the
// equality — the same cross-implementation discipline as the memory_root head
// reference vectors (`[[formal-method-assertion-must-be-falsifiable]]`,
// `[[cross-language-schema-lock]]`).

/// Cross-language head byte-value pin — single append.
///
/// After one owner append of `entry_hash = 0xAA*32` onto the genesis zero
/// head, the production `append` head equals the INDEPENDENT Python-oracle
/// reference `blake2b256(0x00*32 || 0xAA*32)`. Hard-coded expected bytes (NOT
/// recomputed in Move) -> falsifiable cross-implementation check.
#[test]
fun append_head_matches_python_reference_single() {
    let mut scenario = sui::test_scenario::begin(TEST_OWNER);
    let mut log = new_log_for_test(TEST_OWNER, scenario.ctx());

    // Precondition (independent zero derivation): fresh log head is genesis.
    assert!(log.head_hash == zero_hash_32(), 650);

    append(&mut log, entry_hash_32(0xAA), scenario.ctx());

    // Independent Python-oracle reference: blake2b256(0x00*32 || 0xAA*32).
    // Calibrated against the memory_root HEAD1 vector (04422c94...); NOT
    // recomputed here from the same Move blake2b256 call.
    let expected_head_aa =
        x"738fdfe1064f54c21495c1df79b81e9c74e050dc2a8f9af8b588e1113d838301";
    assert!(log.head_hash == expected_head_aa, 651);
    // Structural backstop: exactly 32 bytes, not the genesis seed.
    assert!(log.head_hash.length() == 32, 652);

    std::unit_test::destroy(log);
    scenario.end();
}

/// Cross-language head byte-value pin — chained two appends.
///
/// After appending `0xAA*32` then `0xBB*32`, the chained head equals the
/// INDEPENDENT Python-oracle reference `H2 = blake2b256(H1 || 0xBB*32)` where
/// `H1 = blake2b256(0x00*32 || 0xAA*32)`. Proves the head genuinely chains the
/// PREVIOUS head (a rejected `head := entry_hash` alias would mismatch H2).
/// Hard-coded expected bytes (NOT recomputed in Move).
#[test]
fun append_head_matches_python_reference_chained() {
    let mut scenario = sui::test_scenario::begin(TEST_OWNER);
    let mut log = new_log_for_test(TEST_OWNER, scenario.ctx());

    append(&mut log, entry_hash_32(0xAA), scenario.ctx());
    append(&mut log, entry_hash_32(0xBB), scenario.ctx());

    // Independent Python-oracle reference H2 = blake2b256(H1 || 0xBB*32).
    let expected_head_aa_bb =
        x"beaa57c595dd60e5a244a800a344d3e70fa7fdd90899a793cde2cbd1b22df967";
    assert!(log.head_hash == expected_head_aa_bb, 660);
    // seq is the monotone counter after exactly two appends.
    assert!(log.seq == 2, 661);
    assert!(log.head_hash.length() == 32, 662);

    std::unit_test::destroy(log);
    scenario.end();
}
