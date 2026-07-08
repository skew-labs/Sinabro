// atom #277 · D.2.1 — SkillRegistry object/struct.
// atom #278 · D.2.2 — publish_skill entry.
// atom #279 · D.2.3 — fork_skill parent-graph invariant.
// atom #286 · D.2.10 — update_skill_metadata (new immutable digest, linked).
//
// The registry stores digest + provenance POINTERS (skill id, package digest,
// parent digest, author, depth) keyed by the 32-byte package digest — never
// arbitrary unbounded metadata blobs (storage bytes bounded). A package digest,
// once added, is IMMUTABLE: update publishes a NEW digest linked to the old one.
//
// Parent existence + strictly-increasing depth + pre-existing-parent requirement
// make the fork graph acyclic BY CONSTRUCTION (a derivative's depth = parent
// depth + 1, and the parent must already be present, so no cycle can form). This
// is the runtime witness for the deferred Move-Prover invariant (#281).
//
// No buy/sell/payment/checkout/revenue/royalty/price/unlock state is defined
// here (no-commerce law). Offline-only: `sui move test`; no live network egress;
// mainnet locked; publish performs no live on-chain action this WorkPackage.
#[allow(lint(public_entry))]
module mnemos_skill_registry::skill_registry;

use std::option::{Self, Option};
use sui::table::{Self, Table};
use mnemos_skill_registry::events;

/// Mirrors e-skill `MAX_PROVENANCE_DEPTH` (1_024). Bounds lineage depth.
const MAX_PROVENANCE_DEPTH: u16 = 1024;

const E_BAD_DIGEST_LEN: u64 = 1;
const E_AUTHOR_NOT_SENDER: u64 = 2;
const E_DUPLICATE_PACKAGE: u64 = 3;
const E_SELF_PARENT: u64 = 4;
const E_PARENT_MISSING: u64 = 5;
const E_DEPTH_EXCEEDED: u64 = 6;
const E_SAME_DIGEST: u64 = 7;
const E_PACKAGE_MISSING: u64 = 8;
const E_NOT_AUTHOR: u64 = 9;

/// One published package's pointers. `has store` so it can live in the Table.
public struct SkillEntry has store {
    skill: u16,
    package: vector<u8>,
    parent: Option<vector<u8>>,
    author: address,
    depth: u16,
}

/// Shared registry object. `skills` is keyed by the 32-byte package digest, so
/// duplicate-package reject and parent-existence lookup are both O(1).
public struct SkillRegistry has key {
    id: sui::object::UID,
    skills: Table<vector<u8>, SkillEntry>,
    count: u64,
}

/// Create + share an empty registry (mirrors C mainnet-gate package lock shape).
public entry fun create_registry(ctx: &mut TxContext) {
    let reg = SkillRegistry {
        id: sui::object::new(ctx),
        skills: table::new<vector<u8>, SkillEntry>(ctx),
        count: 0,
    };
    sui::transfer::share_object(reg);
}

/// #278 — publish a ROOT skill package. Requires a 32-byte digest and an author
/// that equals the signer (author spoofing rejected). Duplicate package rejected.
public entry fun publish_skill(
    reg: &mut SkillRegistry,
    skill: u16,
    package: vector<u8>,
    author: address,
    ctx: &mut TxContext,
) {
    assert!(package.length() == 32, E_BAD_DIGEST_LEN);
    assert!(author == ctx.sender(), E_AUTHOR_NOT_SENDER);
    assert!(!reg.skills.contains(package), E_DUPLICATE_PACKAGE);
    let entry = SkillEntry { skill, package, parent: option::none(), author, depth: 0 };
    reg.skills.add(package, entry);
    reg.count = reg.count + 1;
    events::emit_skill_published(sui::object::id(reg), skill, package, author, 0);
}

/// #279 — fork a DERIVATIVE from an existing parent. Self-parent, missing parent,
/// duplicate package, and unbounded depth are all rejected; depth = parent + 1.
public entry fun fork_skill(
    reg: &mut SkillRegistry,
    skill: u16,
    package: vector<u8>,
    parent: vector<u8>,
    author: address,
    ctx: &mut TxContext,
) {
    assert!(package.length() == 32, E_BAD_DIGEST_LEN);
    assert!(parent.length() == 32, E_BAD_DIGEST_LEN);
    assert!(author == ctx.sender(), E_AUTHOR_NOT_SENDER);
    assert!(package != parent, E_SELF_PARENT);
    assert!(reg.skills.contains(parent), E_PARENT_MISSING);
    assert!(!reg.skills.contains(package), E_DUPLICATE_PACKAGE);
    let parent_depth = reg.skills.borrow(parent).depth;
    assert!(parent_depth < MAX_PROVENANCE_DEPTH, E_DEPTH_EXCEEDED);
    let depth = parent_depth + 1;
    let entry = SkillEntry { skill, package, parent: option::some(parent), author, depth };
    reg.skills.add(package, entry);
    reg.count = reg.count + 1;
    events::emit_skill_forked(sui::object::id(reg), skill, package, parent, author, depth);
}

/// #286 — publish a NEW digest linked to an existing one. The existing digest is
/// never mutated; a same-digest update and a missing prior package are rejected;
/// only the original author may update.
public entry fun update_skill_metadata(
    reg: &mut SkillRegistry,
    skill: u16,
    old_package: vector<u8>,
    new_package: vector<u8>,
    author: address,
    ctx: &mut TxContext,
) {
    assert!(old_package.length() == 32, E_BAD_DIGEST_LEN);
    assert!(new_package.length() == 32, E_BAD_DIGEST_LEN);
    assert!(author == ctx.sender(), E_AUTHOR_NOT_SENDER);
    assert!(old_package != new_package, E_SAME_DIGEST);
    assert!(reg.skills.contains(old_package), E_PACKAGE_MISSING);
    assert!(!reg.skills.contains(new_package), E_DUPLICATE_PACKAGE);
    let old_depth = reg.skills.borrow(old_package).depth;
    let old_author = reg.skills.borrow(old_package).author;
    assert!(old_author == author, E_NOT_AUTHOR);
    assert!(old_depth < MAX_PROVENANCE_DEPTH, E_DEPTH_EXCEEDED);
    let entry = SkillEntry {
        skill,
        package: new_package,
        parent: option::some(old_package),
        author,
        depth: old_depth + 1,
    };
    reg.skills.add(new_package, entry);
    reg.count = reg.count + 1;
    events::emit_skill_metadata_updated(sui::object::id(reg), skill, old_package, new_package, author);
}

// ---- getters (read-only, bounded) ----

public fun count(reg: &SkillRegistry): u64 { reg.count }

public fun contains_package(reg: &SkillRegistry, package: vector<u8>): bool {
    reg.skills.contains(package)
}

public fun entry_skill(reg: &SkillRegistry, package: vector<u8>): u16 {
    reg.skills.borrow(package).skill
}

public fun entry_depth(reg: &SkillRegistry, package: vector<u8>): u16 {
    reg.skills.borrow(package).depth
}

public fun entry_author(reg: &SkillRegistry, package: vector<u8>): address {
    reg.skills.borrow(package).author
}

public fun entry_parent(reg: &SkillRegistry, package: vector<u8>): Option<vector<u8>> {
    reg.skills.borrow(package).parent
}

public fun max_depth(): u16 { MAX_PROVENANCE_DEPTH }
