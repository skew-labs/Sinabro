// atom #287 · D.2.11 — typed registry/provenance/install events.
//
// Off-chain index never guesses state. It consumes these typed events with
// package digest, actor, state, and a traceable object id. No secret, payment,
// checkout, or commerce field appears in any event payload (no-commerce law).
//
// Events are defined here (single catalog-facing surface) and emitted by the
// sibling modules through `public(package)` helpers so every state-changing
// entry emits exactly one event. Offline-only: `sui move test` exercises these;
// no live network egress, mainnet locked.
module mnemos_skill_registry::events;

use sui::event;
use sui::object::ID;

/// #278 publish — a root skill package is recorded on-chain.
public struct SkillPublished has copy, drop {
    registry: ID,
    skill: u16,
    package: vector<u8>,
    author: address,
    depth: u16,
}

/// #279 fork — a derivative package linked to an existing parent.
public struct SkillForked has copy, drop {
    registry: ID,
    skill: u16,
    package: vector<u8>,
    parent: vector<u8>,
    author: address,
    depth: u16,
}

/// #286 update — a new immutable digest linked to the prior one.
public struct SkillMetadataUpdated has copy, drop {
    registry: ID,
    skill: u16,
    old_package: vector<u8>,
    new_package: vector<u8>,
    author: address,
}

/// #283 record_install — first install receipt minted (state = Installed).
public struct InstallRecorded has copy, drop {
    receipt: ID,
    skill: u16,
    package: vector<u8>,
    user: address,
    state: u8,
}

/// #285 enable — Installed/Disabled -> Enabled.
public struct InstallEnabled has copy, drop {
    receipt: ID,
    user: address,
    old_state: u8,
    new_state: u8,
}

/// #285 disable — Installed/Enabled -> Disabled.
public struct InstallDisabled has copy, drop {
    receipt: ID,
    user: address,
    old_state: u8,
    new_state: u8,
}

/// #285 remove — non-terminal -> Removed.
public struct InstallRemoved has copy, drop {
    receipt: ID,
    user: address,
    old_state: u8,
    new_state: u8,
}

/// #285 revoke — any -> Revoked (idempotent).
public struct InstallRevoked has copy, drop {
    receipt: ID,
    user: address,
    old_state: u8,
    new_state: u8,
}

public(package) fun emit_skill_published(
    registry: ID,
    skill: u16,
    package: vector<u8>,
    author: address,
    depth: u16,
) {
    event::emit(SkillPublished { registry, skill, package, author, depth });
}

public(package) fun emit_skill_forked(
    registry: ID,
    skill: u16,
    package: vector<u8>,
    parent: vector<u8>,
    author: address,
    depth: u16,
) {
    event::emit(SkillForked { registry, skill, package, parent, author, depth });
}

public(package) fun emit_skill_metadata_updated(
    registry: ID,
    skill: u16,
    old_package: vector<u8>,
    new_package: vector<u8>,
    author: address,
) {
    event::emit(SkillMetadataUpdated { registry, skill, old_package, new_package, author });
}

public(package) fun emit_install_recorded(
    receipt: ID,
    skill: u16,
    package: vector<u8>,
    user: address,
    state: u8,
) {
    event::emit(InstallRecorded { receipt, skill, package, user, state });
}

public(package) fun emit_install_enabled(receipt: ID, user: address, old_state: u8, new_state: u8) {
    event::emit(InstallEnabled { receipt, user, old_state, new_state });
}

public(package) fun emit_install_disabled(receipt: ID, user: address, old_state: u8, new_state: u8) {
    event::emit(InstallDisabled { receipt, user, old_state, new_state });
}

public(package) fun emit_install_removed(receipt: ID, user: address, old_state: u8, new_state: u8) {
    event::emit(InstallRemoved { receipt, user, old_state, new_state });
}

public(package) fun emit_install_revoked(receipt: ID, user: address, old_state: u8, new_state: u8) {
    event::emit(InstallRevoked { receipt, user, old_state, new_state });
}

// ---- test-only accessors (events have no public getters in prod) ----

#[test_only]
public fun published_fields(e: &SkillPublished): (ID, u16, vector<u8>, address, u16) {
    (e.registry, e.skill, e.package, e.author, e.depth)
}

#[test_only]
public fun forked_fields(e: &SkillForked): (ID, u16, vector<u8>, vector<u8>, address, u16) {
    (e.registry, e.skill, e.package, e.parent, e.author, e.depth)
}

#[test_only]
public fun updated_fields(e: &SkillMetadataUpdated): (ID, u16, vector<u8>, vector<u8>, address) {
    (e.registry, e.skill, e.old_package, e.new_package, e.author)
}

#[test_only]
public fun recorded_fields(e: &InstallRecorded): (ID, u16, vector<u8>, address, u8) {
    (e.receipt, e.skill, e.package, e.user, e.state)
}

#[test_only]
public fun enabled_states(e: &InstallEnabled): (u8, u8) { (e.old_state, e.new_state) }

#[test_only]
public fun disabled_states(e: &InstallDisabled): (u8, u8) { (e.old_state, e.new_state) }

#[test_only]
public fun removed_states(e: &InstallRemoved): (u8, u8) { (e.old_state, e.new_state) }

#[test_only]
public fun revoked_states(e: &InstallRevoked): (u8, u8) { (e.old_state, e.new_state) }
