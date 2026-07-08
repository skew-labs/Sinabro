// atom #289 · D.2.13 — Move side of the Rust<->Move BCS parity vectors.
//
// These tests pin the CANONICAL byte layout that e-skill `chain_bindings.rs`
// (manual encoder) must reproduce byte-for-byte. If a byte changes on either
// side, both fail loudly before any later evidence can be reused. This atom
// performs NO mainnet call and NO gas spend; it is offline-only / read-only /
// status-only and only marks later evidence invalid unless parity is green.
//
// Canonical layout:
//   u16            -> 2 bytes little-endian
//   u64            -> 8 bytes little-endian
//   u8             -> 1 byte
//   digest (32 B)  -> vector<u8>: uleb(32)=0x20 ++ 32 bytes
//   address / ID   -> 32 raw bytes (no length prefix)
//   Option<digest> -> 0x00 (None) | 0x01 ++ 0x20 ++ 32 bytes (Some)
//
// Field orders mirror §4.1 ProvenanceNode and §4.3 SkillRegistryArgs /
// InstallReceiptArgs / InstallReceiptView exactly.
#[test_only]
module mnemos_skill_registry::parity;

use sui::bcs::{Self, BCS};
use sui::address;

fun raw32(b: u8): vector<u8> {
    let mut v = vector[];
    let mut i = 0u64;
    while (i < 32) { v.push_back(b); i = i + 1; };
    v
}

fun u16_le(v: u16): vector<u8> {
    vector[((v & 0xff) as u8), (((v >> 8) & 0xff) as u8)]
}

fun u64_le(v: u64): vector<u8> {
    let mut o = vector[];
    let mut i = 0u64;
    while (i < 8) { o.push_back((((v >> ((i * 8) as u8)) & 0xff) as u8)); i = i + 1; };
    o
}

/// digest as a BCS vector<u8>: uleb(32) ++ 32 bytes.
fun vec_digest(b: u8): vector<u8> {
    let mut o = vector[0x20u8];
    o.append(raw32(b));
    o
}

fun peel_u16_le(p: &mut BCS): u16 {
    let lo = p.peel_u8();
    let hi = p.peel_u8();
    (lo as u16) | ((hi as u16) << 8)
}

// ---- builders (canonical golden vectors) ----

fun build_registry_args(skill: u16, pkg: u8, author: u8, parent: u8, has_parent: bool): vector<u8> {
    // §4.3 SkillRegistryArgs { skill, package, author, parent }
    let mut o = vector[];
    o.append(u16_le(skill));
    o.append(vec_digest(pkg));
    o.append(raw32(author));
    if (has_parent) {
        o.push_back(0x01);
        o.append(vec_digest(parent));
    } else {
        o.push_back(0x00);
    };
    o
}

fun build_provenance_node(skill: u16, pkg: u8, parent: u8, has_parent: bool, author: u8, depth: u16): vector<u8> {
    // §4.1 ProvenanceNode { skill, package, parent, author, provenance_depth_u16 }
    let mut o = vector[];
    o.append(u16_le(skill));
    o.append(vec_digest(pkg));
    if (has_parent) { o.push_back(0x01); o.append(vec_digest(parent)); } else { o.push_back(0x00); };
    o.append(raw32(author));
    o.append(u16_le(depth));
    o
}

fun build_install_receipt_args(skill: u16, pkg: u8, user: u8, local: u8, cap: u8): vector<u8> {
    // §4.3 InstallReceiptArgs { skill, package, user, local_install_digest, capability_approval_hash }
    let mut o = vector[];
    o.append(u16_le(skill));
    o.append(vec_digest(pkg));
    o.append(raw32(user));
    o.append(vec_digest(local));
    o.append(vec_digest(cap));
    o
}

fun build_install_receipt_view(id: u8, state: u8, user: u8, pkg: u8, epoch: u64): vector<u8> {
    // §4.3 InstallReceiptView { id, state, user, package, recorded_epoch_u64 }
    let mut o = vector[];
    o.append(raw32(id));
    o.push_back(state);
    o.append(raw32(user));
    o.append(vec_digest(pkg));
    o.append(u64_le(epoch));
    o
}

fun build_install_recorded_event(rid: u8, skill: u16, pkg: u8, user: u8, state: u8): vector<u8> {
    // events::InstallRecorded { receipt: ID, skill, package, user, state }
    let mut o = vector[];
    o.append(raw32(rid));
    o.append(u16_le(skill));
    o.append(vec_digest(pkg));
    o.append(raw32(user));
    o.push_back(state);
    o
}

// ---- decode parity tests ----

#[test]
fun registry_args_none_parity() {
    let bytes = build_registry_args(7, 0x11, 0xA2, 0x00, false);
    assert!(bytes.length() == 68, 100);
    let mut p = bcs::new(bytes);
    assert!(peel_u16_le(&mut p) == 7, 101);
    assert!(p.peel_vec_u8() == raw32(0x11), 102);
    assert!(address::to_bytes(p.peel_address()) == raw32(0xA2), 103);
    assert!(p.peel_vec_length() == 0, 104);
    assert!(p.into_remainder_bytes().is_empty(), 105);
}

#[test]
fun registry_args_some_parity() {
    let bytes = build_registry_args(8, 0x22, 0xA2, 0x11, true);
    assert!(bytes.length() == 101, 110);
    let mut p = bcs::new(bytes);
    assert!(peel_u16_le(&mut p) == 8, 111);
    assert!(p.peel_vec_u8() == raw32(0x22), 112);
    assert!(address::to_bytes(p.peel_address()) == raw32(0xA2), 113);
    assert!(p.peel_vec_length() == 1, 114);
    assert!(p.peel_vec_u8() == raw32(0x11), 115);
    assert!(p.into_remainder_bytes().is_empty(), 116);
}

#[test]
fun provenance_node_none_parity() {
    let bytes = build_provenance_node(7, 0x11, 0x00, false, 0xA2, 0);
    assert!(bytes.length() == 70, 120);
    let mut p = bcs::new(bytes);
    assert!(peel_u16_le(&mut p) == 7, 121);
    assert!(p.peel_vec_u8() == raw32(0x11), 122);
    assert!(p.peel_vec_length() == 0, 123);
    assert!(address::to_bytes(p.peel_address()) == raw32(0xA2), 124);
    assert!(peel_u16_le(&mut p) == 0, 125);
    assert!(p.into_remainder_bytes().is_empty(), 126);
}

#[test]
fun provenance_node_some_parity() {
    let bytes = build_provenance_node(8, 0x22, 0x11, true, 0xA2, 1);
    assert!(bytes.length() == 103, 130);
    let mut p = bcs::new(bytes);
    assert!(peel_u16_le(&mut p) == 8, 131);
    assert!(p.peel_vec_u8() == raw32(0x22), 132);
    assert!(p.peel_vec_length() == 1, 133);
    assert!(p.peel_vec_u8() == raw32(0x11), 134);
    assert!(address::to_bytes(p.peel_address()) == raw32(0xA2), 135);
    assert!(peel_u16_le(&mut p) == 1, 136);
    assert!(p.into_remainder_bytes().is_empty(), 137);
}

#[test]
fun install_receipt_args_parity() {
    let bytes = build_install_receipt_args(7, 0x11, 0xC4, 0x22, 0x33);
    assert!(bytes.length() == 133, 140);
    let mut p = bcs::new(bytes);
    assert!(peel_u16_le(&mut p) == 7, 141);
    assert!(p.peel_vec_u8() == raw32(0x11), 142);
    assert!(address::to_bytes(p.peel_address()) == raw32(0xC4), 143);
    assert!(p.peel_vec_u8() == raw32(0x22), 144);
    assert!(p.peel_vec_u8() == raw32(0x33), 145);
    assert!(p.into_remainder_bytes().is_empty(), 146);
}

#[test]
fun install_receipt_view_parity() {
    let bytes = build_install_receipt_view(0xE5, 3, 0xC4, 0x11, 42);
    assert!(bytes.length() == 106, 150);
    let mut p = bcs::new(bytes);
    assert!(address::to_bytes(p.peel_address()) == raw32(0xE5), 151);
    assert!(p.peel_u8() == 3, 152);
    assert!(address::to_bytes(p.peel_address()) == raw32(0xC4), 153);
    assert!(p.peel_vec_u8() == raw32(0x11), 154);
    assert!(p.peel_u64() == 42, 155);
    assert!(p.into_remainder_bytes().is_empty(), 156);
}

#[test]
fun install_recorded_event_parity() {
    let bytes = build_install_recorded_event(0xE5, 7, 0x11, 0xC4, 3);
    assert!(bytes.length() == 100, 160);
    let mut p = bcs::new(bytes);
    assert!(address::to_bytes(p.peel_address()) == raw32(0xE5), 161);
    assert!(peel_u16_le(&mut p) == 7, 162);
    assert!(p.peel_vec_u8() == raw32(0x11), 163);
    assert!(address::to_bytes(p.peel_address()) == raw32(0xC4), 164);
    assert!(p.peel_u8() == 3, 165);
    assert!(p.into_remainder_bytes().is_empty(), 166);
}

/// Drift canary: a wrong length prefix must break parity (proves the harness CAN fail).
#[test]
fun wrong_length_prefix_breaks_parity() {
    let mut bad = vector[];
    bad.append(u16_le(7));
    bad.push_back(0x1F); // uleb(31) — deliberately wrong (should be 0x20)
    bad.append(raw32(0x11));
    let mut p = bcs::new(bad);
    assert!(peel_u16_le(&mut p) == 7, 170);
    let pkg = p.peel_vec_u8();
    assert!(pkg.length() == 31, 171);
    assert!(pkg != raw32(0x11), 172);
}
