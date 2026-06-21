// atom #281 · D.2.5 — provenance acyclicity proof (Move Prover spec).
//
// ============================================================================
// G-D-PROVER STATUS: INVARIANT_TEST_GREEN + PROVER_RUN_DEFERRED
// (owner-locked Option A, 2026-06-04 via AskUserQuestion)
// ============================================================================
//
// This file is DOCUMENTATION-ONLY this WorkPackage. It carries the spec TEXT for
// the lineage invariants of `mnemos_skill_registry::skill_provenance` and
// `::skill_registry`. It lives in `prover/` (a sibling of `sources/`, NOT in the
// default `sui move test` source set) and contains NO live `prover::` imports, so
// it can never break the offline `sui move test` gate.
//
// WHY DEFERRED (physics, not laziness): sui-prover 1.5.3 requires the
// asymptotic-code Sui framework fork (see prototype/move-prover/Move.toml
// `override = true`). That fork is INCOMPATIBLE with the MystenLabs Sui framework
// this package pins (Move.toml rev 73dd2c2…) for `sui move test`. The two
// frameworks cannot co-exist in ONE package, so the mechanized proof is carried
// by a SEPARATE prover-only package in a later prover-integration atom — exactly
// the precedent set by memory_root.spec.move / atom #18 (G-PROVER
// NOT_RUN_TOOL_ABSENT, deferred to Stage K).
//
// THE INVARIANTS ARE RUNTIME-ENFORCED + TEST-GREEN NOW:
//   INV-1 PARENT_EXISTS   : fork_skill asserts reg.contains(parent)
//                           (skill_registry::E_PARENT_MISSING)
//   INV-2 NO_SELF_PARENT  : fork_skill asserts package != parent
//                           (skill_registry::E_SELF_PARENT)
//   INV-3 ACYCLIC_BY_DEPTH: a derivative's depth = parent.depth + 1 and the
//                           parent must already be present, so no cycle can form;
//                           depth is bounded by MAX_PROVENANCE_DEPTH (1_024).
//   INV-4 IMMUTABLE_DIGEST : a package digest, once added, is never mutated;
//                           update_skill_metadata publishes a NEW linked digest.
// Test witnesses (tests/registry_tests.move):
//   fork_missing_parent_aborts, fork_self_parent_aborts,
//   fork_derivative_succeeds (depth == 1), update_metadata_succeeds (old digest
//   intact + new linked), update_same_digest_aborts, update_not_author_aborts.
//
// FUTURE (prover-integration atom) — promote to asymptotic syntax, e.g.:
//   // use prover::prover::{requires, ensures};
//   // #[spec(prove, ignore_abort,
//   //        target = mnemos_skill_registry::skill_registry::fork_skill)]
//   // fun fork_skill_parent_exists_spec(reg, skill, package, parent, author, ctx) {
//   //     requires(skill_registry::contains_package(reg, parent));
//   //     requires(package != parent);
//   //     fork_skill(reg, skill, package, parent, author, ctx);
//   //     ensures(skill_registry::contains_package(reg, package));
//   //     ensures(skill_registry::entry_depth(reg, package)
//   //             == skill_registry::entry_depth(reg, parent) + 1);
//   // }
//
// No payout / percent / royalty / money semantics: provenance proves origin and
// auditability only. Offline-only: no live network egress, mainnet locked, no
// prover run this WorkPackage. This module emits no executable surface.
module mnemos_skill_registry::provenance_spec;
