// atom #280 · D.2.4 — provenance link type (matches §4.1 `ProvenanceNode`).
// atom #281 · D.2.5 — provenance acyclicity invariant (runtime-enforced here;
//   formal Move-Prover proof authored in ../prover/provenance.spec.move and
//   DEFERRED — see that file + SESSION_1_IMPLEMENTED.md G-D-PROVER record).
//
// Provenance proves PARENTAGE and FORK LINEAGE only. It has NO payout, percent
// split, royalty, or money semantics in active Stage D (no-commerce law).
//
// BCS layout (parity with Rust e-skill `ProvenanceNode`, manual encoder in
// e-skill/src/chain_bindings.rs):
//   skill  : u16            -> 2 bytes LE
//   package: vector<u8>(32) -> uleb(32)=0x20 ++ 32 bytes
//   parent : Option<vector<u8>(32)> -> 0x00 (None) | 0x01 ++ 0x20 ++ 32 bytes
//   author : address        -> 32 raw bytes
//   depth  : u16            -> 2 bytes LE
//
// Offline-only: `sui move test`; no live network egress, mainnet locked.
module mnemos_skill_registry::skill_provenance;

use std::option::{Self, Option};

/// Maximum lineage depth. Mirrors e-skill `MAX_PROVENANCE_DEPTH` (1_024).
const MAX_PROVENANCE_DEPTH: u16 = 1024;

const E_BAD_DIGEST_LEN: u64 = 1;
const E_SELF_PARENT: u64 = 2;
const E_DEPTH_EXCEEDED: u64 = 3;

/// On-chain mirror of §4.1 `ProvenanceNode` (lineage pointer, not a money node).
public struct ProvenanceLink has copy, drop, store {
    skill: u16,
    package: vector<u8>,
    parent: Option<vector<u8>>,
    author: address,
    depth: u16,
}

/// Construct a ROOT lineage node (no parent, depth 0).
public fun new_root(skill: u16, package: vector<u8>, author: address): ProvenanceLink {
    assert!(package.length() == 32, E_BAD_DIGEST_LEN);
    ProvenanceLink { skill, package, parent: option::none(), author, depth: 0 }
}

/// Construct a DERIVATIVE lineage node from an existing parent's depth.
/// Rejects self-parent and unbounded lineage; depth strictly increases by 1.
public fun new_derivative(
    skill: u16,
    package: vector<u8>,
    parent: vector<u8>,
    author: address,
    parent_depth: u16,
): ProvenanceLink {
    assert!(package.length() == 32, E_BAD_DIGEST_LEN);
    assert!(parent.length() == 32, E_BAD_DIGEST_LEN);
    assert!(package != parent, E_SELF_PARENT);
    assert!(parent_depth < MAX_PROVENANCE_DEPTH, E_DEPTH_EXCEEDED);
    ProvenanceLink {
        skill,
        package,
        parent: option::some(parent),
        author,
        depth: parent_depth + 1,
    }
}

public fun is_root(link: &ProvenanceLink): bool {
    link.parent.is_none()
}

/// A child's parent pointer must reference the parent's package digest, the
/// depth must increase by exactly 1, and the child cannot be its own parent.
/// This is the per-edge acyclicity step the lineage invariant rests on.
public fun is_acyclic_step(child: &ProvenanceLink, parent: &ProvenanceLink): bool {
    if (child.parent.is_none()) return false;
    let p = child.parent.borrow();
    (*p == parent.package)
        && (child.package != parent.package)
        && (child.depth == parent.depth + 1)
}

/// Well-formedness independent of any parent object: bounded depth + a root
/// has no parent while a non-zero depth implies a parent pointer.
public fun is_well_formed(link: &ProvenanceLink): bool {
    if (link.depth > MAX_PROVENANCE_DEPTH) return false;
    if (link.depth == 0) {
        link.parent.is_none()
    } else {
        link.parent.is_some()
    }
}

public fun skill(link: &ProvenanceLink): u16 { link.skill }

public fun package(link: &ProvenanceLink): vector<u8> { link.package }

public fun parent(link: &ProvenanceLink): Option<vector<u8>> { link.parent }

public fun author(link: &ProvenanceLink): address { link.author }

public fun depth(link: &ProvenanceLink): u16 { link.depth }

public fun max_depth(): u16 { MAX_PROVENANCE_DEPTH }
