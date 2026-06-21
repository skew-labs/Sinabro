// atom #18 · D.0.4 — MNEMOS memory-root Move Prover invariant SPEC TEXT.
//
// ============================================================
// 1. CANONICAL OUT (ATOM_PLAN line 973-981, §4.D line 569)
// ============================================================
//
// This file is the canonical SPEC TEXT for the Move Prover invariants on
// the `mnemos::memory_root` module (atoms #15 / #16 / #17). The
// invariants enumerated below are the §4.D / D.0.4 canonical OUT:
//
//   (I-1)  owner-only mutate.
//   (I-2)  `root_hash` length is always 32 bytes.
//   (I-3)  `epoch` is strictly monotone (increases by 1 per mutate).
//   (I-4)  Anchored `blob_id` is immutable (once emitted via
//          `ChunkAnchored`, the event record is write-only and never
//          revised — Sui's event model is the immutability carrier).
//   (I-5)  Royalty sum = 100%   — Phase 0 N/A EXPLICIT (no royalty
//          surface exists in the `mnemos::memory_root` module at this
//          phase; recorded here so atom #18's canonical-OUT bullet list
//          is byte-complete vs. ATOM_PLAN line 975).
//
// ============================================================
// 2. TOOL-ABSENCE DISPARITY  (G-PROVER structurally unavailable)
// ============================================================
//
// ATOM_PLAN line 228 defines gate G-PROVER as `sui move prove` and
// declares "미증명=차단" (unproven = blocked). On the macOS Darwin
// 25.5.0 host as of 2026-05-27:
//
//   sui --version          → sui 1.72.1-homebrew
//   sui move --help        → no `prove` subcommand
//                            (build / coverage / disassemble / migrate /
//                             new / test / summary / update-deps / help)
//   which move-prover mvp boogie   → all absent
//   which z3               → /Library/Frameworks/Python.framework/...
//                            (generic SMT solver, no Move frontend)
//
// Sui Move 2024 edition (the package edition pinned in
// `prototype/move/Move.toml`) does NOT support the legacy
// `module X { spec fun ... { aborts_if ... } }` syntax inherited from
// Diem / Aptos Move. The Sui Move Prover replacement is not yet shipped
// in the homebrew `sui` CLI at this version.
//
// Therefore atom #18 produces the canonical SPEC TEXT as a
// documentation-style Move-2024-valid module that:
//
//   - parses under `sui move build` (so G-MOVE atom-#16 / #17 gates do
//     not regress);
//   - emits NO new executable surface (no entry fns, no public consts,
//     no events) — keeps the canonical OUT scope tight per
//     [[ai-advisory-user-decides]] + [[plan-document-authority-read-all-before-work]];
//   - enumerates each invariant with cross-references to the atom #16 /
//     #17 RUNTIME-ENFORCING sites and the existing
//     `sui move test`-executed tests that exercise each invariant.
//
// Gate G-PROVER is recorded as `status: not_run` in
// `ops/training/phase_0/atom_018/gate_results.json` with the reason
// above, surfaced as advisory in `redteam_decision.json`, and carried
// into `VERIFY_TODO.json` as a 4-option user decision (see
// SESSION_1_IMPLEMENTED.md §"G-PROVER advisory"). This is NOT a
// `[[no-disabled-path-workaround]]` violation: G-PROVER is honestly
// recorded as failed/blocked for this atom — the failure is surfaced,
// not bypassed.
//
// ============================================================
// 3. INVARIANT ENUMERATION (with runtime-enforcer cross-refs)
// ============================================================
//
// Each entry lists: (a) the formal invariant, (b) the atom #16 / #17
// runtime-enforcement site (file + function + abort const or stmt),
// and (c) the existing `sui move test`-executed test that exercises
// the invariant.
//
// ------------------------------------------------------------
// (I-1) owner-only mutate
// ------------------------------------------------------------
//
//   FORMAL:  forall f in {add_chunk, transfer_root}.
//              precondition (ctx.sender() != root.owner) =>
//                f aborts with code E_NOT_OWNER (= 1).
//
//   ENFORCER add_chunk:
//     memory_root.move :: add_chunk (line 167-187):
//       assert!(ctx.sender() == root.owner, E_NOT_OWNER);
//
//   ENFORCER transfer_root:
//     memory_root.move :: transfer_root (line 224-232):
//       assert!(ctx.sender() == root.owner, E_NOT_OWNER);
//
//   TEST (add_chunk):
//     memory_root.move :: add_chunk_by_non_owner_aborts
//       (line 317-335)
//       — #[expected_failure(abort_code = E_NOT_OWNER)]
//
//   TEST (transfer_root):
//     memory_root.move :: transfer_by_non_owner_aborts
//       (line 427-440)
//       — #[expected_failure(abort_code = E_NOT_OWNER)]
//
//   TEST (post-transfer immutability of OLD owner):
//     memory_root.move :: post_transfer_old_owner_cannot_add_chunk
//       (line 442-475)
//       — Proves that after `transfer_root(... TEST_NON_OWNER ...)`,
//         a subsequent `add_chunk` invoked with the OLD owner's
//         ctx.sender() aborts on the existing add_chunk owner gate
//         (E_NOT_OWNER). This is the formal cross-binding from atom
//         #17 (mutation) to atom #16 (gate).
//
// ------------------------------------------------------------
// (I-2) root_hash length == 32
// ------------------------------------------------------------
//
//   FORMAL:  invariant root.root_hash.length() == 32
//              for every reachable state of MemoryRoot.
//
//   ENFORCER (boundary, off-chain side):
//     mnemos_d_move::types::MemoryRootArgs.root_hash : [u8; 32]
//     — the Rust binding pins the length at the TYPE level (atom #15
//       canonical OUT, §4.D line 549). Any caller that constructs
//       `MemoryRootArgs` from a non-32-byte source is rejected by
//       `MoveBindError::RootHashLen{observed}` at the binding boundary
//       (see crates/d-move/src/types.rs).
//
//   ENFORCER (on-chain side, current atom #16 surface):
//     atom #16 `add_chunk` does NOT mutate `root_hash` (atom #16
//     deliberate carve-out, memory_root.move module header line 50-58).
//     The construction site that would set `root_hash` is the future
//     atom #19 (D.0.5) testnet deploy / atom #20 (D.0.6) SDK call
//     builder. Until then, the on-chain `root_hash` is exclusively
//     materialised through the Rust binding type
//     `MemoryRootArgs.root_hash : [u8; 32]` and is therefore len=32
//     by construction at every Sui state.
//
//   TEST:
//     d-move crates/d-move/tests/d0_1_args_from_anchor_enforces_len32.rs
//     (per ATOM_PLAN line 947) — bounded-len property at the
//     cross-language boundary. Test name verbatim
//     `d0_1_args_from_anchor_enforces_len32`.
//
//     memory_root.move tests do NOT need a len=32 assert on `root_hash`
//     because no atom-#16-or-#17 entry point reads or writes it; the
//     `#[allow(unused_field)]` attribute on `MemoryRoot.root_hash`
//     (memory_root.move line 110) documents this invariant carrier.
//
// ------------------------------------------------------------
// (I-3) epoch strictly monotone
// ------------------------------------------------------------
//
//   FORMAL:  forall successful add_chunk call.
//              post(root.epoch) == pre(root.epoch) + 1.
//
//          forall successful transfer_root call.
//              post(root.epoch) == pre(root.epoch).
//            (transfer does not advance epoch — see atom #17
//             memory_root.move line 211-214 carve-out doc.)
//
//   ENFORCER:
//     memory_root.move :: add_chunk (line 177):
//       root.epoch = root.epoch + 1;
//     (Sequential u64 increment; overflow is u64::MAX add_chunk calls
//      away — not a Phase 0 concern; the Sui Move arithmetic-abort
//      semantics handle the upper bound by aborting on overflow, which
//      preserves the monotone-or-abort weaker invariant.)
//
//   TEST:
//     memory_root.move :: add_chunk_by_owner_succeeds (line 286-315):
//       Asserts `root.epoch == 1` after the first add_chunk,
//       `root.epoch == 2` after the second add_chunk
//       (lines 299, 310). Direct executable witness for the
//       +1-per-call invariant. test name verbatim per ATOM_PLAN
//       line 957.
//
//     memory_root.move :: add_chunk_emits_event (line 337-365):
//       Asserts `ev.epoch == 1` for the first emission (line 361)
//       — verifies that the emitted event carries the POST-increment
//       epoch (atom #16 SPEC line 154-155).
//
// ------------------------------------------------------------
// (I-4) anchored blob_id immutable
// ------------------------------------------------------------
//
//   FORMAL:  forall ChunkAnchored event e emitted by add_chunk.
//              no subsequent Sui state transition mutates the
//              (root, epoch, blob_id) tuple recorded in e.
//
//   ENFORCER (by-construction):
//     `ChunkAnchored has copy, drop` (memory_root.move line 135-141)
//     is an EVENT struct, not an on-chain stored object. Sui's event
//     model is write-only: `event::emit<T>(ev)` appends to the
//     transaction's effect stream and the event record is never
//     subsequently revised by any Move call. There is no
//     `set_blob_id` / `mutate_event` / `revoke_chunk` entry function
//     in the `mnemos::memory_root` module, so the (root, epoch,
//     blob_id) tuple is permanent at the canonical-OUT surface.
//
//     Cross-reference: atom #16 module header
//     (memory_root.move line 24-29) is the design doc for this
//     immutability claim.
//
//   TEST (event payload integrity, single-shot):
//     memory_root.move :: add_chunk_emits_event (line 337-365)
//       — verifies emitted event tuple
//         (root, blob_id=0x44..×32, kind=3, parent=0x11..×32,
//          epoch=1) matches the call args byte-for-byte.
//       (Sui's event-mutation absence is by-construction; no
//        executable test can witness "no mutation ever" — that is the
//        canonical role of the formal G-PROVER gate, which is
//        recorded as not_run for this atom.)
//
// ------------------------------------------------------------
// (I-5) royalty sum = 100%  — Phase 0 N/A EXPLICIT
// ------------------------------------------------------------
//
//   FORMAL:  N/A — the `mnemos::memory_root` module declares no
//            royalty / fee / split surface at Phase 0. ATOM_PLAN
//            line 975 calls out this Phase 0 carve-out
//            ("royalty 합=100% — Phase0 N/A 명시"), which is
//            preserved verbatim here.
//
//   ENFORCER:
//     grep -n "royalty\|fee\|split\|percent" memory_root.move → 0
//     matches in atom #15 / #16 / #17 surface as of 2026-05-27.
//
//   TEST: N/A — no surface to test.
//
//   FUTURE: if a royalty / fee / split surface is added in any
//   future atom of domain D, this (I-5) invariant MUST be
//   re-instantiated to a non-trivial proof obligation and the
//   `Phase 0 N/A` qualifier MUST be removed from this file.
//
// ============================================================
// 4. NON-GOALS OF ATOM #18  (carve-out, [[plan-document-authority]] discipline)
// ============================================================
//
//   - testnet deploy (atom #19 / D.0.5).
//   - Rust SDK call builder (atom #20 / D.0.6).
//   - root_hash mutation surface (atom #16 / #17 carve-out, see
//     memory_root.move line 50-58).
//   - mechanized formal proof execution (G-PROVER gate; tool absent,
//     recorded as user-decides advisory).
//   - any new constant / function / event / abort code (this spec
//     module is documentation-only; the canonical OUT is the
//     SPEC TEXT itself).
//
// ============================================================
// 5. CROSS-LANGUAGE SCHEMA LOCK  ([[cross-language-schema-lock]])
// ============================================================
//
//   The 4 + 1 invariants above are mirrored on the Rust binding side:
//
//     (I-1) owner-only mutate
//             ↔ MoveBindError::OwnerMismatch (§4.D line 550;
//               crates/d-move/src/types.rs)
//     (I-2) root_hash len=32
//             ↔ MemoryRootArgs.root_hash : [u8; 32] +
//               MoveBindError::RootHashLen{observed:usize}
//     (I-3) epoch strictly monotone
//             ↔ MoveBindError::EpochNotMonotone{prev:u64, next:u64}
//     (I-4) anchored blob_id immutable
//             ↔ Sui event model (no Rust mirror needed; Sui-runtime
//               invariant)
//     (I-5) royalty Phase 0 N/A
//             ↔ no Rust surface (parity-preserving N/A)
//
//   The Rust enum `MoveBindError` is enumerated by ATOM_PLAN line 550
//   and is the canonical OUT of atom #15 (D.0.1). This spec file
//   reinforces the schema lock by listing each pair, so that any
//   future drift between the Move invariants and the Rust binding
//   surfaces in BOTH `memory_root.spec.move` AND
//   `crates/d-move/src/types.rs` simultaneously — atom-#18 is the
//   anchor for that bidirectional check.
//
// ============================================================
// 6. MODULE BODY
// ============================================================

/// `mnemos::memory_root_spec` — Phase 0 documentation-only module that
/// carries the canonical SPEC TEXT for the four invariants of
/// `mnemos::memory_root` (atoms #15 / #16 / #17) plus the Phase 0
/// royalty N/A qualifier.
///
/// This module emits no executable surface. It exists to satisfy the
/// atom #18 / D.0.4 canonical OUT requirement that the Prover spec
/// text reside in a dedicated `.spec.move` file beside the
/// implementation module, byte-exact per ATOM_PLAN line 974.
///
/// The mechanized Move Prover gate (G-PROVER) is recorded as
/// `not_run` for this atom (sui 1.72.1-homebrew has no `prove`
/// subcommand; Sui Move 2024 dropped the legacy `spec` block
/// syntax; no `move-prover` / `mvp` / `boogie` binary is installed
/// system-wide). See module header §2 and
/// `ops/training/phase_0/atom_018/gate_results.json` for the full
/// disparity record + 4-option user-decides advisory.
module mnemos::memory_root_spec;
