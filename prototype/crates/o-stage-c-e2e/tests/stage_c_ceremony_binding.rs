//! Stage C cross-type binding test for the mainnet ceremony (C-WP-07 · atom #234).
//!
//! The atom #234 ceremony transcript lives in `k-devex` and consumes the exact
//! transaction digest as a `[u8; 32]` *value* rather than importing the atom
//! #214 `MainnetSignerEnvelope` type — so `k-devex` gains no `g-wallet`
//! dependency (Sinabro Physical Law 1: the test home owns both symbols, and this
//! `o-stage-c-e2e` crate already dev-depends on `g-wallet` + `k-devex` +
//! `d-move`). This test is the binding that proves "reuse #214": the transcript's
//! `exact_tx_digest_32` is exactly the signer envelope's `tx_digest_32`, and the
//! sponsor signer request (atom #230) commits to the same envelope.
//!
//! No live action: all values are in-memory; nothing signs or submits.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use mnemos_d_move::stage_c_package_lock::MainnetPackageLock;
use mnemos_d_move::types::ObjectId;
use mnemos_g_wallet::{MainnetSignerEnvelope, SponsorSignerRequest};
use mnemos_k_devex::{CeremonyTranscript, MainnetChecklist};

const PACKAGE: [u8; 32] = [0x33; 32];
const TX_DIGEST: [u8; 32] = [0xD1; 32];
const POLICY_HASH: [u8; 32] = [0xCD; 32];
const MULTISIG_HASH: [u8; 32] = [0x88; 32];

fn envelope() -> MainnetSignerEnvelope {
    MainnetSignerEnvelope::new(
        ObjectId::new(PACKAGE),
        TX_DIGEST,
        POLICY_HASH,
        1_700_000_000,
    )
    .expect("valid signer envelope")
}

fn package_lock() -> MainnetPackageLock {
    MainnetPackageLock::new(ObjectId::new(PACKAGE), [0x44; 32], [0x55; 32], [0x66; 32])
        .expect("valid package lock")
}

fn green_checklist() -> MainnetChecklist {
    MainnetChecklist::new_locked().with_evidence_hash([0x77; 32])
}

/// The ceremony's exact tx digest is byte-equal to the atom #214 signer
/// envelope's `tx_digest_32` — the cross-crate reuse #214 binding.
#[test]
fn ceremony_digest_binds_signer_envelope() {
    let env = envelope();
    let transcript = CeremonyTranscript::build(
        package_lock(),
        &green_checklist(),
        MULTISIG_HASH,
        3600,
        1800,
        env.tx_digest_32,
        env.policy_hash_32,
    )
    .expect("bound transcript");

    // The digest the operator signs (#214) is exactly the digest the ceremony
    // transcript (#234) is addressed over.
    assert_eq!(transcript.exact_tx_digest_32, env.tx_digest_32);
    assert_eq!(transcript.signer_policy_hash_32, env.policy_hash_32);

    // The transcript is hash-addressed and reproducible.
    assert_eq!(transcript.transcript_hash(), transcript.transcript_hash());
}

/// The atom #230 sponsor signer request commits to the very same envelope the
/// ceremony transcript references, and admits only under the matching policy.
#[test]
fn sponsor_signer_commits_same_envelope() {
    let env = envelope();
    let req = SponsorSignerRequest::new(env, 42, 1_700_000_500);

    // Admits under the matching policy hash and a current epoch.
    let grant = req
        .admit(&POLICY_HASH, 1_700_000_100)
        .expect("admitted under matching policy");
    assert_eq!(
        grant.exact_bytes_commitment_32,
        req.exact_bytes_commitment()
    );

    // The transcript built from the same envelope shares its digest.
    let transcript = CeremonyTranscript::build(
        package_lock(),
        &green_checklist(),
        MULTISIG_HASH,
        3600,
        1800,
        env.tx_digest_32,
        env.policy_hash_32,
    )
    .expect("bound transcript");
    assert_eq!(transcript.exact_tx_digest_32, req.envelope.tx_digest_32);
}
