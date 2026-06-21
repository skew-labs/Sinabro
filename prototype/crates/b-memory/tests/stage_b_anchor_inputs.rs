//! atom #144 · B.3.23 — anchor-input producer (b-memory half of the testnet
//! anchor ceremony). `feature = "net-testnet"` only, `#[ignore]`d.
//!
//! # Why this lives in b-memory (not d-move)
//!
//! The anchor's inputs — a signed chunk ([`StageBSignedChunkV1`], #90), its
//! Walrus [`VerifiedBlobId`] (#116/#117 derive+verify), and the audit
//! [`stage_b_audit_entry_hash`] (#95) — all live in `b-memory`. `b-memory` already
//! normal-depends on `d-move`, so putting this producer in `d-move` would force a
//! `d-move -> b-memory` dev-dep cycle the project deliberately avoids
//! (USER-LOCKED, B-WP-02). The plan named
//! `prototype/crates/d-move/tests/stage_b_live_anchor.rs`; that file is a
//! recorded DISPARITY — the realized #144 is this producer + a `scripts/` CLI
//! ceremony (`sui client call` on the published package) + redacted evidence,
//! because there is no Rust Sui-tx submitter yet (promote at Stage C/F).
//!
//! # What it does
//!
//! 1. Build a synthetic, public, signature-verified [`StageBSignedChunkV1`].
//! 2. Encode it ([`encode_stage_b_chunk`], the exact bytes that go to Walrus).
//! 3. One live Walrus testnet PUT of those bytes (`max_attempts = 1`, fail-closed)
//!    → reported id → official RS2 verify → 32-byte [`VerifiedBlobId`].
//! 4. Compute the 32-byte audit entry hash over (signed chunk, verified blob id).
//! 5. Print the machine-parseable anchor args (`blob_id_hex`, `entry_hash_hex`,
//!    `kind`, `chunk_digest_hex`) the `sui client call` ceremony feeds into
//!    `memory_root::add_chunk` and `audit_log::append`.
//!
//! Run:
//!   `cargo test -p mnemos-b-memory --features net-testnet --test stage_b_anchor_inputs -- --ignored --nocapture`
//!
//! Approval scope (user, same-message): Walrus testnet PUT of one synthetic
//! public fixture only; no mainnet; no wallet signing here (Sui signing happens
//! in the separate `sui client call` ceremony); redacted evidence only.

#![cfg(feature = "net-testnet")]
#![allow(clippy::unwrap_used)]
#![allow(clippy::expect_used)]
#![allow(clippy::panic)]
#![allow(clippy::print_stdout)]

use ed25519_dalek::{Signer, SigningKey};
use mnemos_b_memory::{
    OwnerPublicKeyBinding, SigningPublicKey, StageBChunkFlags, StageBChunkHeaderV1,
    StageBChunkView, StageBSignedChunkV1, StageBTraceEvidence, StageBTraceLink, WalrusPutPlan,
    WalrusTestnetEndpoint, chunk_sign_preimage, derive_walrus_testnet_blob_id,
    encode_stage_b_chunk, stage_b_audit_entry_hash, stage_b_chunk_digest,
    stage_b_verify_testnet_blob_id,
};
use mnemos_c_walrus::SignatureBytes;
use mnemos_c_walrus::codec::{ChunkEnvelopeV1, ChunkKind, MemoryRole};
use mnemos_c_walrus::publisher::{
    EpochCount, PublishPayloadClass, PublisherResponseDecision, publish_blob_with_transport,
};
use mnemos_c_walrus::reqwest_transport::ReqwestPublisher;
use mnemos_d_move::SuiAddress;

/// Synthetic, public, hand-authored chunk content — no user memory, no secret.
const ANCHOR_CONTENT: &[u8] =
    b"mnemos atom 144 B.3.23 synthetic signed chunk -- live Walrus testnet anchor";

/// Per-attempt timeout for the one live PUT, ms.
const LIVE_PUT_TIMEOUT_MS: u32 = 30_000;

/// 32-byte id as lower-case hex (public-safe — a content-addressed id is not secret).
fn hex32(bytes: &[u8; 32]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(64);
    for &b in bytes {
        out.push(HEX[(b >> 4) as usize] as char);
        out.push(HEX[(b & 0x0f) as usize] as char);
    }
    out
}

#[test]
#[ignore = "live Walrus testnet PUT for the #144 anchor inputs; requires same-message approval + network. Run: --features net-testnet --test stage_b_anchor_inputs -- --ignored --nocapture"]
fn b3_23_produce_testnet_anchor_inputs() {
    // --- build a synthetic signed chunk (mirrors signed_chunk.rs #90 test pattern) ---
    let envelope = ChunkEnvelopeV1 {
        kind: ChunkKind::UserMessage,
        role: MemoryRole::User,
        parent: None,
        content: ANCHOR_CONTENT.to_vec(),
        embedding: None,
        signature: None,
        provenance: None,
    };
    let trace = StageBTraceLink::new(0xB323_0001, 144, 0);
    let header = StageBChunkHeaderV1::new(
        ChunkKind::UserMessage,
        MemoryRole::User,
        PublishPayloadClass::SyntheticPublicFixture,
        StageBChunkFlags::None as u8,
        ANCHOR_CONTENT.len() as u32,
        SuiAddress::new([0x6a; 32]),
        None,
        trace,
    )
    .expect("known header is valid");
    let view = StageBChunkView::new(header, &envelope).expect("content within cap");
    let digest = stage_b_chunk_digest(&view).expect("digest computes");

    // ed25519 signer (test stand-in for the #150 wallet signer; production sign deferred).
    let signing = SigningKey::from_bytes(&[0x44; 32]);
    let signing_public =
        SigningPublicKey::from_bytes(&signing.verifying_key().to_bytes()).expect("32-byte pubkey");
    let binding = OwnerPublicKeyBinding::new(SuiAddress::new([0x6a; 32]), signing_public);
    let signature = SignatureBytes(signing.sign(&chunk_sign_preimage(&digest)).to_bytes());

    let signed = StageBSignedChunkV1::new(&view, signature, &binding).expect("valid chunk mints");

    // --- encode: the exact bytes PUT to Walrus ---
    let encoded = encode_stage_b_chunk(&signed.envelope).expect("chunk encodes");
    let local_derive = derive_walrus_testnet_blob_id(&encoded).expect("under encoding cap");

    // --- one live Walrus testnet PUT (no Sui gas; keyless public publisher) ---
    let ev = StageBTraceEvidence::from_trace(trace).expect("atom_id 144 non-zero so trace stamped");
    let put_plan = WalrusPutPlan::plan(
        WalrusTestnetEndpoint::testnet(),
        EpochCount::new(1).expect("1 epoch is positive"),
        &encoded,
        PublishPayloadClass::SyntheticPublicFixture,
        ev,
    )
    .expect("synthetic public fixture within cap plans");

    let mut transport =
        ReqwestPublisher::new(LIVE_PUT_TIMEOUT_MS).expect("client builds with positive timeout");
    let run = publish_blob_with_transport(&mut transport, &put_plan.request, 0xB323_0001, 1)
        .expect("the publisher loop returns a well-formed single-attempt run");

    let reported = match run.decision {
        PublisherResponseDecision::Accepted {
            reported_blob_id, ..
        } => reported_blob_id,
        other => panic!("live PUT not accepted: {other:?}"),
    };
    println!(
        "ANCHOR_PUT atom=144 endpoint=publisher.walrus-testnet.walrus.space encoded_len={} local_derive={} reported_blob_id={}",
        encoded.len(),
        hex32(local_derive.as_bytes()),
        reported.as_str(),
    );

    // --- verify (server is not an oracle): reported must equal local RS2 derive ---
    let verified = stage_b_verify_testnet_blob_id(&encoded, &reported)
        .expect("reported id verifies against the encoded bytes under the RS2 oracle");
    assert_eq!(
        verified.as_blob_id().as_bytes(),
        local_derive.as_bytes(),
        "verified id must wrap the locally derived official id, not server bytes"
    );

    // --- audit entry hash over (signed chunk, verified blob id) ---
    let entry_hash = stage_b_audit_entry_hash(&signed, &verified);

    // --- machine-parseable anchor args for the sui client call ceremony ---
    println!(
        "ANCHOR_INPUT atom=144 blob_id_hex={} entry_hash_hex={} kind={} chunk_digest_hex={}",
        hex32(verified.as_blob_id().as_bytes()),
        hex32(&entry_hash),
        ChunkKind::UserMessage as u8,
        hex32(digest.as_bytes()),
    );
}
