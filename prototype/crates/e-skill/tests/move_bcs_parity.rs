//! atom #289 · D.2.13 — Rust side of the Rust<->Move BCS parity vectors.
//!
//! Asserts the e-skill `chain_bindings` encoders produce byte-for-byte the same
//! golden vectors that `prototype/move/mnemos_skill_registry/tests/parity.move`
//! pins. If a byte drifts on either side, both fail loudly. Offline / read-only:
//! no network, no gas spend, no mainnet, no live action.

use mnemos_d_move::types::{ObjectId, SuiAddress};
use mnemos_e_skill::chain_bindings::{
    InstallReceiptArgs, InstallReceiptId, InstallReceiptView, SkillRegistryArgs,
    encode_provenance_node_bcs,
};
use mnemos_e_skill::install_state::InstallState;
use mnemos_e_skill::manifest::SkillId;
use mnemos_e_skill::package::SkillPackageDigest32;
use mnemos_e_skill::provenance::ProvenanceNode;

fn raw32(b: u8) -> Vec<u8> {
    vec![b; 32]
}

/// digest as a BCS vector<u8>: uleb(32)=0x20 ++ 32 bytes (matches Move `vec_digest`).
fn vec_digest(b: u8) -> Vec<u8> {
    let mut v = vec![0x20u8];
    v.extend_from_slice(&[b; 32]);
    v
}

fn d32(b: u8) -> SkillPackageDigest32 {
    SkillPackageDigest32::new([b; 32])
}

#[test]
fn registry_args_none_matches_move_golden() {
    let args = SkillRegistryArgs {
        skill: SkillId(7),
        package: d32(0x11),
        author: SuiAddress::new([0xA2; 32]),
        parent: None,
    };
    let mut expected = Vec::new();
    expected.extend_from_slice(&7u16.to_le_bytes());
    expected.extend_from_slice(&vec_digest(0x11));
    expected.extend_from_slice(&raw32(0xA2));
    expected.push(0x00);
    assert_eq!(expected.len(), 68);
    assert_eq!(args.to_bcs(), expected);
}

#[test]
fn registry_args_some_matches_move_golden() {
    let args = SkillRegistryArgs {
        skill: SkillId(8),
        package: d32(0x22),
        author: SuiAddress::new([0xA2; 32]),
        parent: Some(d32(0x11)),
    };
    let mut expected = Vec::new();
    expected.extend_from_slice(&8u16.to_le_bytes());
    expected.extend_from_slice(&vec_digest(0x22));
    expected.extend_from_slice(&raw32(0xA2));
    expected.push(0x01);
    expected.extend_from_slice(&vec_digest(0x11));
    assert_eq!(expected.len(), 101);
    assert_eq!(args.to_bcs(), expected);
}

#[test]
fn provenance_node_none_matches_move_golden() {
    let node = ProvenanceNode {
        skill: SkillId(7),
        package: d32(0x11),
        parent: None,
        author: SuiAddress::new([0xA2; 32]),
        provenance_depth_u16: 0,
    };
    let mut expected = Vec::new();
    expected.extend_from_slice(&7u16.to_le_bytes());
    expected.extend_from_slice(&vec_digest(0x11));
    expected.push(0x00);
    expected.extend_from_slice(&raw32(0xA2));
    expected.extend_from_slice(&0u16.to_le_bytes());
    assert_eq!(expected.len(), 70);
    assert_eq!(encode_provenance_node_bcs(&node), expected);
}

#[test]
fn provenance_node_some_matches_move_golden() {
    let node = ProvenanceNode {
        skill: SkillId(8),
        package: d32(0x22),
        parent: Some(d32(0x11)),
        author: SuiAddress::new([0xA2; 32]),
        provenance_depth_u16: 1,
    };
    let mut expected = Vec::new();
    expected.extend_from_slice(&8u16.to_le_bytes());
    expected.extend_from_slice(&vec_digest(0x22));
    expected.push(0x01);
    expected.extend_from_slice(&vec_digest(0x11));
    expected.extend_from_slice(&raw32(0xA2));
    expected.extend_from_slice(&1u16.to_le_bytes());
    assert_eq!(expected.len(), 103);
    assert_eq!(encode_provenance_node_bcs(&node), expected);
}

#[test]
fn install_receipt_args_matches_move_golden() {
    let args = InstallReceiptArgs {
        skill: SkillId(7),
        package: d32(0x11),
        user: SuiAddress::new([0xC4; 32]),
        local_install_digest_32: [0x22; 32],
        capability_approval_hash_32: [0x33; 32],
    };
    let mut expected = Vec::new();
    expected.extend_from_slice(&7u16.to_le_bytes());
    expected.extend_from_slice(&vec_digest(0x11));
    expected.extend_from_slice(&raw32(0xC4));
    expected.extend_from_slice(&vec_digest(0x22));
    expected.extend_from_slice(&vec_digest(0x33));
    assert_eq!(expected.len(), 133);
    assert_eq!(args.to_bcs(), expected);
}

#[test]
fn install_receipt_view_matches_move_golden() {
    let view = InstallReceiptView {
        id: InstallReceiptId::new(ObjectId::new([0xE5; 32])),
        state: InstallState::Installed,
        user: SuiAddress::new([0xC4; 32]),
        package: d32(0x11),
        recorded_epoch_u64: 42,
    };
    let mut expected = Vec::new();
    expected.extend_from_slice(&raw32(0xE5));
    expected.push(3); // InstallState::Installed
    expected.extend_from_slice(&raw32(0xC4));
    expected.extend_from_slice(&vec_digest(0x11));
    expected.extend_from_slice(&42u64.to_le_bytes());
    assert_eq!(expected.len(), 106);
    assert_eq!(view.to_bcs(), expected);
}

#[test]
fn install_state_discriminants_match_move() {
    assert_eq!(InstallState::Installed.as_u8(), 3);
    assert_eq!(InstallState::Enabled.as_u8(), 4);
    assert_eq!(InstallState::Disabled.as_u8(), 5);
    assert_eq!(InstallState::Removed.as_u8(), 6);
    assert_eq!(InstallState::Revoked.as_u8(), 7);
}
