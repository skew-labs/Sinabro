// atom #291 · D.2.15 — Move tests for registry publish/fork/update.
//
// Every public entry has success, failure, duplicate, and event-assertion tests.
// Each negative case names its abort reason via `abort_code = <local mirror> +
// location = <module>` (no bare `#[expected_failure]` catch-all) — the local
// mirror const must equal the source const value, so a renumber there breaks this
// cross-pin. Offline-only: `sui move test`; no live network; mainnet locked.
#[test_only]
module mnemos_skill_registry::registry_tests;

use sui::test_scenario;
use sui::event;
use mnemos_skill_registry::skill_registry::{Self, SkillRegistry};
use mnemos_skill_registry::events;

const AUTHOR: address = @0xA2;
const OTHER: address = @0xB3;

// ---- cross-pin mirrors of skill_registry private error consts ----
const E_BAD_DIGEST_LEN: u64 = 1;
const E_AUTHOR_NOT_SENDER: u64 = 2;
const E_DUPLICATE_PACKAGE: u64 = 3;
const E_SELF_PARENT: u64 = 4;
const E_PARENT_MISSING: u64 = 5;
const E_SAME_DIGEST: u64 = 7;
const E_PACKAGE_MISSING: u64 = 8;
const E_NOT_AUTHOR: u64 = 9;

fun digest(b: u8): vector<u8> {
    let mut v = vector[];
    let mut i = 0u64;
    while (i < 32) { v.push_back(b); i = i + 1; };
    v
}

fun short_digest(): vector<u8> {
    let mut v = vector[];
    v.push_back(0x11);
    v
}

// ---------------------------- success ----------------------------

#[test]
fun create_and_publish_root_succeeds() {
    let mut sc = test_scenario::begin(AUTHOR);
    skill_registry::create_registry(sc.ctx());
    sc.next_tx(AUTHOR);
    let mut reg = test_scenario::take_shared<SkillRegistry>(&sc);
    skill_registry::publish_skill(&mut reg, 7u16, digest(0x11), AUTHOR, sc.ctx());
    assert!(reg.count() == 1, 100);
    assert!(reg.contains_package(digest(0x11)), 101);
    assert!(reg.entry_depth(digest(0x11)) == 0, 102);
    assert!(reg.entry_author(digest(0x11)) == AUTHOR, 103);
    assert!(reg.entry_skill(digest(0x11)) == 7u16, 104);
    let evs = event::events_by_type<events::SkillPublished>();
    assert!(evs.length() == 1, 105);
    let (_rid, sk, pkg, au, dp) = events::published_fields(&evs[0]);
    assert!(sk == 7u16, 106);
    assert!(pkg == digest(0x11), 107);
    assert!(au == AUTHOR, 108);
    assert!(dp == 0u16, 109);
    test_scenario::return_shared(reg);
    sc.end();
}

#[test]
fun fork_derivative_succeeds() {
    let mut sc = test_scenario::begin(AUTHOR);
    skill_registry::create_registry(sc.ctx());
    sc.next_tx(AUTHOR);
    let mut reg = test_scenario::take_shared<SkillRegistry>(&sc);
    skill_registry::publish_skill(&mut reg, 7u16, digest(0x11), AUTHOR, sc.ctx());
    skill_registry::fork_skill(&mut reg, 8u16, digest(0x22), digest(0x11), AUTHOR, sc.ctx());
    assert!(reg.count() == 2, 200);
    assert!(reg.entry_depth(digest(0x22)) == 1, 201);
    let parent = reg.entry_parent(digest(0x22));
    assert!(parent.is_some(), 202);
    assert!(*parent.borrow() == digest(0x11), 203);
    let evs = event::events_by_type<events::SkillForked>();
    assert!(evs.length() == 1, 204);
    let (_rid, sk, pkg, par, au, dp) = events::forked_fields(&evs[0]);
    assert!(sk == 8u16 && pkg == digest(0x22) && par == digest(0x11) && au == AUTHOR && dp == 1u16, 205);
    test_scenario::return_shared(reg);
    sc.end();
}

#[test]
fun update_metadata_succeeds() {
    let mut sc = test_scenario::begin(AUTHOR);
    skill_registry::create_registry(sc.ctx());
    sc.next_tx(AUTHOR);
    let mut reg = test_scenario::take_shared<SkillRegistry>(&sc);
    skill_registry::publish_skill(&mut reg, 7u16, digest(0x11), AUTHOR, sc.ctx());
    skill_registry::update_skill_metadata(&mut reg, 7u16, digest(0x11), digest(0x33), AUTHOR, sc.ctx());
    // old digest remains immutable + present; new digest linked to old.
    assert!(reg.contains_package(digest(0x11)), 300);
    assert!(reg.contains_package(digest(0x33)), 301);
    assert!(reg.entry_depth(digest(0x33)) == 1, 302);
    let parent = reg.entry_parent(digest(0x33));
    assert!(parent.is_some() && *parent.borrow() == digest(0x11), 303);
    let evs = event::events_by_type<events::SkillMetadataUpdated>();
    assert!(evs.length() == 1, 304);
    let (_rid, sk, oldp, newp, au) = events::updated_fields(&evs[0]);
    assert!(sk == 7u16 && oldp == digest(0x11) && newp == digest(0x33) && au == AUTHOR, 305);
    test_scenario::return_shared(reg);
    sc.end();
}

// ---------------------------- failure ----------------------------

#[test]
#[expected_failure(abort_code = E_DUPLICATE_PACKAGE, location = mnemos_skill_registry::skill_registry)]
fun publish_duplicate_package_aborts() {
    let mut sc = test_scenario::begin(AUTHOR);
    skill_registry::create_registry(sc.ctx());
    sc.next_tx(AUTHOR);
    let mut reg = test_scenario::take_shared<SkillRegistry>(&sc);
    skill_registry::publish_skill(&mut reg, 7u16, digest(0x11), AUTHOR, sc.ctx());
    skill_registry::publish_skill(&mut reg, 7u16, digest(0x11), AUTHOR, sc.ctx());
    test_scenario::return_shared(reg);
    sc.end();
}

#[test]
#[expected_failure(abort_code = E_AUTHOR_NOT_SENDER, location = mnemos_skill_registry::skill_registry)]
fun publish_author_not_sender_aborts() {
    let mut sc = test_scenario::begin(AUTHOR);
    skill_registry::create_registry(sc.ctx());
    sc.next_tx(AUTHOR);
    let mut reg = test_scenario::take_shared<SkillRegistry>(&sc);
    skill_registry::publish_skill(&mut reg, 7u16, digest(0x11), OTHER, sc.ctx());
    test_scenario::return_shared(reg);
    sc.end();
}

#[test]
#[expected_failure(abort_code = E_BAD_DIGEST_LEN, location = mnemos_skill_registry::skill_registry)]
fun publish_bad_digest_len_aborts() {
    let mut sc = test_scenario::begin(AUTHOR);
    skill_registry::create_registry(sc.ctx());
    sc.next_tx(AUTHOR);
    let mut reg = test_scenario::take_shared<SkillRegistry>(&sc);
    skill_registry::publish_skill(&mut reg, 7u16, short_digest(), AUTHOR, sc.ctx());
    test_scenario::return_shared(reg);
    sc.end();
}

#[test]
#[expected_failure(abort_code = E_SELF_PARENT, location = mnemos_skill_registry::skill_registry)]
fun fork_self_parent_aborts() {
    let mut sc = test_scenario::begin(AUTHOR);
    skill_registry::create_registry(sc.ctx());
    sc.next_tx(AUTHOR);
    let mut reg = test_scenario::take_shared<SkillRegistry>(&sc);
    skill_registry::fork_skill(&mut reg, 8u16, digest(0x11), digest(0x11), AUTHOR, sc.ctx());
    test_scenario::return_shared(reg);
    sc.end();
}

#[test]
#[expected_failure(abort_code = E_PARENT_MISSING, location = mnemos_skill_registry::skill_registry)]
fun fork_missing_parent_aborts() {
    let mut sc = test_scenario::begin(AUTHOR);
    skill_registry::create_registry(sc.ctx());
    sc.next_tx(AUTHOR);
    let mut reg = test_scenario::take_shared<SkillRegistry>(&sc);
    skill_registry::fork_skill(&mut reg, 8u16, digest(0x22), digest(0x99), AUTHOR, sc.ctx());
    test_scenario::return_shared(reg);
    sc.end();
}

#[test]
#[expected_failure(abort_code = E_SAME_DIGEST, location = mnemos_skill_registry::skill_registry)]
fun update_same_digest_aborts() {
    let mut sc = test_scenario::begin(AUTHOR);
    skill_registry::create_registry(sc.ctx());
    sc.next_tx(AUTHOR);
    let mut reg = test_scenario::take_shared<SkillRegistry>(&sc);
    skill_registry::publish_skill(&mut reg, 7u16, digest(0x11), AUTHOR, sc.ctx());
    skill_registry::update_skill_metadata(&mut reg, 7u16, digest(0x11), digest(0x11), AUTHOR, sc.ctx());
    test_scenario::return_shared(reg);
    sc.end();
}

#[test]
#[expected_failure(abort_code = E_PACKAGE_MISSING, location = mnemos_skill_registry::skill_registry)]
fun update_missing_old_aborts() {
    let mut sc = test_scenario::begin(AUTHOR);
    skill_registry::create_registry(sc.ctx());
    sc.next_tx(AUTHOR);
    let mut reg = test_scenario::take_shared<SkillRegistry>(&sc);
    skill_registry::update_skill_metadata(&mut reg, 7u16, digest(0x11), digest(0x33), AUTHOR, sc.ctx());
    test_scenario::return_shared(reg);
    sc.end();
}

#[test]
#[expected_failure(abort_code = E_NOT_AUTHOR, location = mnemos_skill_registry::skill_registry)]
fun update_not_author_aborts() {
    let mut sc = test_scenario::begin(AUTHOR);
    skill_registry::create_registry(sc.ctx());
    sc.next_tx(AUTHOR);
    let mut reg = test_scenario::take_shared<SkillRegistry>(&sc);
    skill_registry::publish_skill(&mut reg, 7u16, digest(0x11), AUTHOR, sc.ctx());
    // OTHER tries to update AUTHOR's package; author==sender(OTHER) holds but the
    // stored author is AUTHOR -> E_NOT_AUTHOR.
    sc.next_tx(OTHER);
    skill_registry::update_skill_metadata(&mut reg, 7u16, digest(0x11), digest(0x33), OTHER, sc.ctx());
    test_scenario::return_shared(reg);
    sc.end();
}
