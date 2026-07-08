// atom #292 · D.2.16 — registry parent-existence + immutable-digest proof
// (Move Prover spec).
//
// ============================================================================
// G-D-PROVER STATUS: INVARIANT_TEST_GREEN + PROVER_RUN_DEFERRED
// (owner-locked Option A, 2026-06-04 via AskUserQuestion; D-WP-03A #281 precedent)
// ============================================================================
//
// This file is DOCUMENTATION-ONLY this WorkPackage. It carries the spec TEXT for
// the registry invariants of `mnemos_skill_registry::skill_registry` and
// `::skill_provenance`. It lives in `prover/` (a sibling of `sources/`, NOT in
// the default `sui move test` source set) and contains NO live `prover::`
// imports, so it can never break the offline `sui move test` gate (29/29 stays
// green, build-neutral). It emits no executable surface.
//
// WHY DEFERRED (physics, not laziness): sui-prover 1.5.3 requires the
// asymptotic-code Sui framework fork (see prototype/move-prover/Move.toml:
// `Prover`/`Sui`/`MoveStdlib`/`SuiSpecs` all `override = true` to the
// asymptotic-code/sui-prover + asymptotic-code/sui `next` checkouts). That fork
// is INCOMPATIBLE with the MystenLabs Sui framework this package pins (Move.toml
// rev 73dd2c2…) for `sui move test`. The two frameworks cannot co-exist in ONE
// package, so the mechanized proof is carried by a SEPARATE prover-only package
// in a later prover-integration atom — exactly the precedent set by
// provenance.spec.move (#281) and memory_root.spec.move / atom #18.
//
// THE INVARIANTS ARE RUNTIME-ENFORCED + TEST-GREEN NOW:
//   INV-R1 PARENT_EXISTS    : fork_skill asserts reg.skills.contains(parent)
//                             (skill_registry.move:98, E_PARENT_MISSING=5) — a
//                             derivative cannot be created without a present
//                             parent. update_skill_metadata likewise requires the
//                             old package to exist (skill_registry.move:124,
//                             E_PACKAGE_MISSING=8).
//   INV-R2 NO_SELF_PARENT   : fork_skill asserts package != parent
//                             (skill_registry.move:97, E_SELF_PARENT=4).
//   INV-R3 IMMUTABLE_DIGEST : a package digest, once added to `reg.skills`, is
//                             NEVER mutated. publish_skill/fork_skill/
//                             update_skill_metadata only ever `reg.skills.add(..)`
//                             a NEW key (skill_registry.move:79, :104, :137);
//                             there is no `borrow_mut` of a stored SkillEntry's
//                             package/author/depth anywhere. update publishes a
//                             NEW digest linked by parent=some(old)
//                             (skill_registry.move:130-137); the old entry stays
//                             byte-identical. "registry cannot mutate package
//                             digest after publish."
//   INV-R4 NO_DUPLICATE     : publish/fork/update assert !contains(new key)
//                             (skill_registry.move:77, :99, :125,
//                             E_DUPLICATE_PACKAGE=3) — an existing digest can
//                             never be re-added/overwritten (reinforces INV-R3).
//   INV-R5 AUTHOR_BINDING   : author == ctx.sender() on publish/fork
//                             (skill_registry.move:76, :96, E_AUTHOR_NOT_SENDER=2)
//                             and update requires stored author == author
//                             (skill_registry.move:128, E_NOT_AUTHOR=9) — any
//                             lineage extension requires authority, not just a
//                             matching signature.
//   INV-R6 ACYCLIC_BY_DEPTH : a derivative's depth = parent.depth + 1, the parent
//                             must already be present, and depth is bounded by
//                             MAX_PROVENANCE_DEPTH (1_024)
//                             (skill_registry.move:100-102, E_DEPTH_EXCEEDED=6);
//                             so no cycle can form. Per-edge witness:
//                             skill_provenance::is_acyclic_step
//                             (skill_provenance.move:73) and is_well_formed
//                             (skill_provenance.move:83).
//
// Test witnesses (tests/registry_tests.move) — "Move Prover green" is carried as
// INVARIANT_TEST_GREEN by the 29/29 `sui move test` run:
//   missing-parent counterexample RED : fork_missing_parent_aborts (:163, INV-R1),
//                                        update_missing_old_aborts (:188, INV-R1).
//   mutation counterexample RED       : publish_duplicate_package_aborts (:114,
//                                        INV-R4), update_same_digest_aborts (:175,
//                                        INV-R4) — any attempt to re-add/overwrite
//                                        an existing digest aborts;
//                                        update_metadata_succeeds (:89) asserts the
//                                        old digest 0x11 is STILL present and the
//                                        new 0x33 is linked (INV-R3 immutability).
//   self-parent counterexample RED    : fork_self_parent_aborts (:151, INV-R2).
//   author counterexample RED         : publish_author_not_sender_aborts (:127,
//                                        update_not_author_aborts (:200, INV-R5).
//   positive                          : create_and_publish_root_succeeds (:44),
//                                        fork_derivative_succeeds (:67, depth==1,
//                                        parent==0x11, INV-R6).
//
// FUTURE (separate prover-only package, prover-integration atom) — promote to
// asymptotic syntax, e.g.:
//   // use prover::prover::{requires, ensures};
//   // #[spec(prove, ignore_abort,
//   //        target = mnemos_skill_registry::skill_registry::fork_skill)]
//   // fun fork_parent_exists_spec(reg, skill, package, parent, author, ctx) {
//   //     requires(skill_registry::contains_package(reg, parent)); // INV-R1
//   //     requires(package != parent);                             // INV-R2
//   //     fork_skill(reg, skill, package, parent, author, ctx);
//   //     ensures(skill_registry::contains_package(reg, package));
//   //     ensures(skill_registry::entry_depth(reg, package)
//   //             == old(skill_registry::entry_depth(reg, parent)) + 1); // INV-R6
//   // }
//   // #[spec(prove, ignore_abort,
//   //        target = mnemos_skill_registry::skill_registry::update_skill_metadata)]
//   // fun update_immutable_digest_spec(reg, skill, oldp, newp, author, ctx) {
//   //     requires(skill_registry::contains_package(reg, oldp));
//   //     let old_author = old(skill_registry::entry_author(reg, oldp));
//   //     update_skill_metadata(reg, skill, oldp, newp, author, ctx);
//   //     ensures(skill_registry::contains_package(reg, oldp));        // INV-R3
//   //     ensures(skill_registry::entry_author(reg, oldp) == old_author); // INV-R3
//   //     ensures(skill_registry::contains_package(reg, newp));
//   // }
//
// No payout / percent / royalty / money semantics: the registry proves origin,
// immutability, and auditability only (no-commerce law). Offline-only: no live
// network egress, mainnet locked, no live on-chain action, no prover run this
// WorkPackage. This module emits no executable surface.
module mnemos_skill_registry::registry_spec;
