// atom #291 · D.2.15 — Move tests for install receipt lifecycle.
//
// Covers record_install + enable/disable/remove/revoke with success, failure,
// duplicate/idempotent, and event assertions. Negative cases name their abort
// reason via local-mirror `abort_code` + `location`. Offline-only: `sui move
// test`; no live network; mainnet locked; receipt carries no payment/secret.
#[test_only]
module mnemos_skill_registry::install_tests;

use sui::test_scenario;
use sui::event;
use mnemos_skill_registry::install_receipt::{Self, InstallReceipt};
use mnemos_skill_registry::events;

const USER: address = @0xC4;
const OTHER: address = @0xD5;

// ---- cross-pin mirrors of install_receipt private error consts ----
const E_BAD_DIGEST_LEN: u64 = 1;
const E_USER_NOT_SENDER: u64 = 2;
const E_MISSING_DRY_RUN_HASH: u64 = 3;
const E_MISSING_CAPABILITY_APPROVAL: u64 = 4;
const E_USER_MISMATCH: u64 = 5;
const E_TERMINAL_STATE: u64 = 6;

fun digest(b: u8): vector<u8> {
    let mut v = vector[];
    let mut i = 0u64;
    while (i < 32) { v.push_back(b); i = i + 1; };
    v
}

fun zeros(): vector<u8> { digest(0x00) }

fun short_digest(): vector<u8> {
    let mut v = vector[];
    v.push_back(0x11);
    v
}

// ---------------------------- success ----------------------------

#[test]
fun record_install_succeeds() {
    let mut sc = test_scenario::begin(USER);
    install_receipt::record_install(7u16, digest(0x11), USER, digest(0x22), digest(0x33), sc.ctx());
    let evs = event::events_by_type<events::InstallRecorded>();
    assert!(evs.length() == 1, 100);
    let (_id, sk, pkg, usr, st) = events::recorded_fields(&evs[0]);
    assert!(sk == 7u16 && pkg == digest(0x11) && usr == USER, 101);
    assert!(st == install_receipt::state_installed(), 102);
    sc.next_tx(USER);
    let r = test_scenario::take_from_sender<InstallReceipt>(&sc);
    assert!(install_receipt::state(&r) == install_receipt::state_installed(), 103);
    assert!(install_receipt::is_runtime_usable(&r), 104);
    assert!(install_receipt::user(&r) == USER, 105);
    assert!(install_receipt::package(&r) == digest(0x11), 106);
    test_scenario::return_to_sender(&sc, r);
    sc.end();
}

#[test]
fun enable_disable_cycle() {
    let mut sc = test_scenario::begin(USER);
    install_receipt::record_install(7u16, digest(0x11), USER, digest(0x22), digest(0x33), sc.ctx());
    sc.next_tx(USER);
    let mut r = test_scenario::take_from_sender<InstallReceipt>(&sc);
    install_receipt::enable_install(&mut r, sc.ctx());
    assert!(install_receipt::state(&r) == install_receipt::state_enabled(), 200);
    assert!(install_receipt::is_runtime_usable(&r), 201);
    install_receipt::disable_install(&mut r, sc.ctx());
    assert!(install_receipt::state(&r) == install_receipt::state_disabled(), 202);
    assert!(!install_receipt::is_runtime_usable(&r), 203);
    let en = event::events_by_type<events::InstallEnabled>();
    let di = event::events_by_type<events::InstallDisabled>();
    assert!(en.length() == 1 && di.length() == 1, 204);
    let (eo, enw) = events::enabled_states(&en[0]);
    assert!(eo == install_receipt::state_installed() && enw == install_receipt::state_enabled(), 205);
    test_scenario::return_to_sender(&sc, r);
    sc.end();
}

#[test]
fun remove_makes_unusable() {
    let mut sc = test_scenario::begin(USER);
    install_receipt::record_install(7u16, digest(0x11), USER, digest(0x22), digest(0x33), sc.ctx());
    sc.next_tx(USER);
    let mut r = test_scenario::take_from_sender<InstallReceipt>(&sc);
    install_receipt::remove_install(&mut r, sc.ctx());
    assert!(install_receipt::state(&r) == install_receipt::state_removed(), 300);
    assert!(!install_receipt::is_runtime_usable(&r), 301);
    let rm = event::events_by_type<events::InstallRemoved>();
    assert!(rm.length() == 1, 302);
    test_scenario::return_to_sender(&sc, r);
    sc.end();
}

#[test]
fun revoke_is_idempotent() {
    let mut sc = test_scenario::begin(USER);
    install_receipt::record_install(7u16, digest(0x11), USER, digest(0x22), digest(0x33), sc.ctx());
    sc.next_tx(USER);
    let mut r = test_scenario::take_from_sender<InstallReceipt>(&sc);
    install_receipt::revoke_install(&mut r, sc.ctx());
    install_receipt::revoke_install(&mut r, sc.ctx()); // second = noop, no abort
    assert!(install_receipt::state(&r) == install_receipt::state_revoked(), 400);
    assert!(!install_receipt::is_runtime_usable(&r), 401);
    let rv = event::events_by_type<events::InstallRevoked>();
    assert!(rv.length() == 1, 402); // only the first revoke emits
    test_scenario::return_to_sender(&sc, r);
    sc.end();
}

// ---------------------------- failure ----------------------------

#[test]
#[expected_failure(abort_code = E_USER_NOT_SENDER, location = mnemos_skill_registry::install_receipt)]
fun record_user_not_sender_aborts() {
    let mut sc = test_scenario::begin(USER);
    install_receipt::record_install(7u16, digest(0x11), OTHER, digest(0x22), digest(0x33), sc.ctx());
    sc.end();
}

#[test]
#[expected_failure(abort_code = E_MISSING_DRY_RUN_HASH, location = mnemos_skill_registry::install_receipt)]
fun record_missing_dry_run_hash_aborts() {
    let mut sc = test_scenario::begin(USER);
    install_receipt::record_install(7u16, digest(0x11), USER, zeros(), digest(0x33), sc.ctx());
    sc.end();
}

#[test]
#[expected_failure(abort_code = E_MISSING_CAPABILITY_APPROVAL, location = mnemos_skill_registry::install_receipt)]
fun record_missing_capability_approval_aborts() {
    let mut sc = test_scenario::begin(USER);
    install_receipt::record_install(7u16, digest(0x11), USER, digest(0x22), zeros(), sc.ctx());
    sc.end();
}

#[test]
#[expected_failure(abort_code = E_BAD_DIGEST_LEN, location = mnemos_skill_registry::install_receipt)]
fun record_bad_digest_len_aborts() {
    let mut sc = test_scenario::begin(USER);
    install_receipt::record_install(7u16, short_digest(), USER, digest(0x22), digest(0x33), sc.ctx());
    sc.end();
}

#[test]
#[expected_failure(abort_code = E_USER_MISMATCH, location = mnemos_skill_registry::install_receipt)]
fun enable_by_non_user_aborts() {
    let mut sc = test_scenario::begin(USER);
    install_receipt::record_install(7u16, digest(0x11), USER, digest(0x22), digest(0x33), sc.ctx());
    sc.next_tx(OTHER);
    let mut r = test_scenario::take_from_address<InstallReceipt>(&sc, USER);
    install_receipt::enable_install(&mut r, sc.ctx()); // sender OTHER != receipt.user USER
    test_scenario::return_to_address(USER, r);
    sc.end();
}

#[test]
#[expected_failure(abort_code = E_TERMINAL_STATE, location = mnemos_skill_registry::install_receipt)]
fun enable_after_remove_aborts() {
    let mut sc = test_scenario::begin(USER);
    install_receipt::record_install(7u16, digest(0x11), USER, digest(0x22), digest(0x33), sc.ctx());
    sc.next_tx(USER);
    let mut r = test_scenario::take_from_sender<InstallReceipt>(&sc);
    install_receipt::remove_install(&mut r, sc.ctx());
    install_receipt::enable_install(&mut r, sc.ctx()); // Removed is terminal
    test_scenario::return_to_sender(&sc, r);
    sc.end();
}
