// atom #293 · D.2.17 — install state-machine proof (Move Prover spec).
//
// ============================================================================
// G-D-PROVER STATUS: INVARIANT_TEST_GREEN + PROVER_RUN_DEFERRED
// (owner-locked Option A, 2026-06-04 via AskUserQuestion; D-WP-03A #281 precedent)
// G-D-INSTALL-RECEIPT: record_install AND-gate + terminal-state invariants
// ============================================================================
//
// This file is DOCUMENTATION-ONLY this WorkPackage. It carries the spec TEXT for
// the install-receipt state machine of `mnemos_skill_registry::install_receipt`
// (§4.3, discriminants byte-pinned to Rust e-skill `InstallState`). It lives in
// `prover/` (a sibling of `sources/`, NOT in the default `sui move test` source
// set) and contains NO live `prover::` imports, so it can never break the offline
// `sui move test` gate (29/29 stays green, build-neutral). It emits no
// executable surface.
//
// WHY DEFERRED (physics, not laziness): sui-prover 1.5.3 requires the
// asymptotic-code Sui framework fork (prototype/move-prover/Move.toml, all deps
// `override = true`). That fork is INCOMPATIBLE with the MystenLabs Sui framework
// this package pins (Move.toml rev 73dd2c2…) for `sui move test`. The two
// frameworks cannot co-exist in ONE package, so the mechanized proof is carried
// by a SEPARATE prover-only package in a later prover-integration atom — the
// precedent set by provenance.spec.move (#281) + registry.spec.move (#292) +
// memory_root.spec.move / atom #18.
//
// State discriminants (install_receipt.move:26-30), byte-pinned to Rust e-skill
// `InstallState` (§4.3): None=1, DryRun=2, Installed=3, Enabled=4, Disabled=5,
// Removed=6, Revoked=7. On-chain receipts are minted only at Installed=3 by
// record_install; None/DryRun are pre-chain Rust-local states.
//
// THE INVARIANTS ARE RUNTIME-ENFORCED + TEST-GREEN NOW:
//   INV-I1 TERMINAL_NO_REANIMATE     : a Removed or Revoked receipt can never
//                                      become Enabled (or any usable state).
//                                      enable_install + disable_install assert
//                                      old != Removed && old != Revoked
//                                      (install_receipt.move:95, :105,
//                                      E_TERMINAL_STATE=6); remove asserts
//                                      old != Revoked (install_receipt.move:115).
//                                      There is NO mutator on an existing receipt
//                                      that targets Removed/Revoked -> Enabled.
//                                      The ONLY route to a usable state after a
//                                      terminal state is a FRESH record_install
//                                      minting a NEW receipt, which must itself
//                                      pass INV-I2. "removed/revoked cannot become
//                                      enabled without a new verified install
//                                      path."
//   INV-I2 INSTALL_REQUIRES_VERIFIED : record_install (install_receipt.move:63-89)
//          _PATH                       is a 4-way AND-gate; failing ANY clause
//                                      aborts before a receipt is minted:
//                                      (a) package.length()==32
//                                          (install_receipt.move:71,
//                                          E_BAD_DIGEST_LEN=1) — a real signed-
//                                          package digest, not a bare flag =>
//                                          "unsigned package" rejected;
//                                      (b) local_install_digest is 32B AND
//                                          non-zero (install_receipt.move:72, :75,
//                                          E_MISSING_DRY_RUN_HASH=3) — a real
//                                          dry-run/local-install digest =>
//                                          "unchecked local flag" rejected;
//                                      (c) capability_approval_hash is 32B AND
//                                          non-zero (install_receipt.move:73, :76,
//                                          E_MISSING_CAPABILITY_APPROVAL=4);
//                                      (d) user == ctx.sender()
//                                          (install_receipt.move:74,
//                                          E_USER_NOT_SENDER=2) — the installer is
//                                          the signer => "from redirect"
//                                          (third-party-initiated) rejected.
//                                      "Install cannot happen from redirect,
//                                      unchecked local flag, or unsigned package."
//   INV-I3 RUNTIME_GATE              : is_runtime_usable is true ONLY for
//                                      Installed or Enabled
//                                      (install_receipt.move:131-133);
//                                      Disabled/Removed/Revoked always deny
//                                      (parity with Rust e-skill
//                                      install_state::runtime_decision stale-deny).
//   INV-I4 USER_BINDING             : every mutation asserts
//                                      ctx.sender() == receipt.user
//                                      (install_receipt.move:93, :103, :113, :123,
//                                      E_USER_MISMATCH=5).
//   INV-I5 IDEMPOTENT_TERMINAL      : revoke (install_receipt.move:125) and remove
//                                      (install_receipt.move:116) early-return when
//                                      already in that state — idempotent, exactly
//                                      one event per transition, no double-spend of
//                                      state.
//
// Test witnesses (tests/install_tests.move) — "Move Prover green" is carried as
// INVARIANT_TEST_GREEN by the 29/29 `sui move test` run:
//   illegal-transition counterexample RED : enable_after_remove_aborts (:162,
//                                           INV-I1 Removed is terminal),
//                                           enable_by_non_user_aborts (:150,
//                                           INV-I4).
//   unverified-install counterexample RED : record_user_not_sender_aborts (:118,
//                                           INV-I2d), record_missing_dry_run_hash_
//                                           aborts (:126, INV-I2b), record_missing_
//                                           capability_approval_aborts (:134,
//                                           INV-I2c), record_bad_digest_len_aborts
//                                           (:142, INV-I2a).
//   positive / runtime-gate               : record_install_succeeds (:44,
//                                           is_runtime_usable true, INV-I3),
//                                           enable_disable_cycle (:63, disabled =>
//                                           not usable), remove_makes_unusable
//                                           (:84, INV-I3), revoke_is_idempotent
//                                           (:99, INV-I5).
//
// FUTURE (separate prover-only package, prover-integration atom) — promote to
// asymptotic syntax, e.g.:
//   // use prover::prover::{requires, ensures, asserts};
//   // #[spec(prove, target = mnemos_skill_registry::install_receipt::record_install)]
//   // fun record_install_verified_path_spec(skill, package, user,
//   //                                        local_install_digest,
//   //                                        capability_approval_hash, ctx) {
//   //     asserts(package.length() == 32);                       // INV-I2a
//   //     asserts(local_install_digest.length() == 32
//   //             && !is_zero_32(&local_install_digest));        // INV-I2b
//   //     asserts(capability_approval_hash.length() == 32
//   //             && !is_zero_32(&capability_approval_hash));    // INV-I2c
//   //     asserts(user == ctx.sender());                         // INV-I2d
//   // }
//   // #[spec(prove, ignore_abort,
//   //        target = mnemos_skill_registry::install_receipt::enable_install)]
//   // fun enable_no_reanimate_spec(receipt, ctx) {
//   //     let old = old(install_receipt::state(receipt));
//   //     enable_install(receipt, ctx);
//   //     asserts(old != install_receipt::state_removed()
//   //             && old != install_receipt::state_revoked());   // INV-I1
//   // }
//
// No payment / checkout / key / secret field is stored on the receipt
// (install_receipt.move:40-49) and no payout/royalty/money semantics exist
// (no-commerce + no-secret law). Offline-only: no live network egress, mainnet
// locked, no live on-chain action, no prover run this WorkPackage. This module
// emits no executable surface.
module mnemos_skill_registry::install_spec;
