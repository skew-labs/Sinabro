//! Integration test — Stage B **full testnet roundtrip replay**
//! (atom #168 · B.5.5). `feature = "net-testnet"` only, `#[ignore]`d.
//!
//! # What this atom is
//!
//! The canonical OUT is *live evidence linking the Stage B custody chain to a
//! deterministic replay hash*: signed chunk → Walrus testnet → Sui testnet
//! anchor/audit → replay hash.
//!
//! Per WorkPackage physical-law **Law 3**, the **Sui** anchor/audit published at
//! atom #144 (B-WP-02A) is an immutable input and is **not** re-anchored — this
//! ceremony re-queries it (the script half) and reuses its object ids. The
//! **Walrus** blob, however, has a short testnet storage epoch and expires; since
//! it is a content-addressed synthetic public fixture, this atom re-provisions it
//! with one **keyless** public-publisher PUT (no wallet, no gas, identical
//! content → identical blob id `5a34…f016a`), then replays the reconstructed
//! custody chain to the deterministic transcript hash.
//!
//! Flow:
//! 1. Reconstruct the exact #144 synthetic signed chunk (same content, trace,
//!    owner, key as `tests/stage_b_anchor_inputs.rs`); the official RS2 derive of
//!    the reconstruction equals the on-chain #144 `blob_id` (proven by the
//!    reported-id verify below).
//! 2. One keyless live Walrus testnet PUT (re-provision the expired blob);
//!    require the publisher's reported id to verify against the local official
//!    derive (server is not an oracle).
//! 3. Best-effort read-only GET liveness probe (non-fatal: a just-PUT blob may
//!    not be immediately retrievable on testnet).
//! 4. Run [`replay_stage_b`] (#165/#166) over the reconstructed chain, keyed to
//!    the real on-chain `MemoryRoot` / `AuditLog` object ids → transcript hash.
//!
//! # Phase-0 ARX ↔ RS2 derive seam (documented honestly)
//!
//! The on-chain anchor carries the official Walrus RS2 id
//! ([`derive_walrus_testnet_blob_id`], #116.5), verified live here. The replay
//! pipeline (#163–#167) keys blobs by the Phase-0 ARX placeholder derive
//! ([`derive_walrus_blob_id`]); the reconstructed anchor therefore uses the ARX
//! id so the replay matches. Full RS2-keyed replay matching is a Stage C/F
//! promotion (same deferral as the Rust-native Sui submitter).
//!
//! Run:
//!   `cargo test -p mnemos-b-memory --features net-testnet --test stage_b_live_replay -- --ignored --nocapture`
//!
//! Approval scope (user, same-message, this session): one keyless Walrus testnet
//! PUT (re-provision) + read-only GET of the same synthetic public fixture; no
//! new Sui anchor, no mainnet, no wallet signing, no secret; redacted evidence.

#![cfg(feature = "net-testnet")]
#![allow(clippy::unwrap_used)]
#![allow(clippy::expect_used)]
#![allow(clippy::panic)]
#![allow(clippy::print_stdout)]

use ed25519_dalek::{Signer, SigningKey};
use mnemos_b_memory::{
    OwnerPublicKeyBinding, SigningPublicKey, StageBChunkFlags, StageBChunkHeaderV1,
    StageBChunkView, StageBReplayInput, StageBSignedChunkV1, StageBTraceEvidence, StageBTraceLink,
    WalrusGetPlan, WalrusPutPlan, WalrusTestnetEndpoint, chunk_sign_preimage,
    derive_walrus_blob_id, derive_walrus_testnet_blob_id, encode_stage_b_chunk,
    parse_walrus_get_response, replay_stage_b, stage_b_audit_entry_hash, stage_b_chunk_digest,
    stage_b_verify_testnet_blob_id,
};
use mnemos_c_walrus::codec::{ChunkEnvelopeV1, ChunkKind, MemoryRole, MoveAnchorArgsV1};
use mnemos_c_walrus::publisher::{
    EpochCount, PublishPayloadClass, PublisherReportedBlobId, PublisherResponseDecision,
    publish_blob_with_transport,
};
use mnemos_c_walrus::reqwest_transport::{ReqwestAggregator, ReqwestPublisher};
use mnemos_c_walrus::{AggregatorEndpoint, AggregatorTransport, SignatureBytes};
use mnemos_d_move::{AuditAppendArgs, MemoryRootAnchorArgs, ObjectId, SuiAddress};

/// The exact synthetic public fixture signed + anchored at atom #144 — pinned
/// identically to `tests/stage_b_anchor_inputs.rs::ANCHOR_CONTENT`.
const ANCHOR_CONTENT: &[u8] =
    b"mnemos atom 144 B.3.23 synthetic signed chunk -- live Walrus testnet anchor";

/// The base64url (no-pad, 43 char) id the public Walrus testnet publisher
/// reported for the #144 blob (on-chain `ChunkAnchored.blob_id`).
const ATOM_144_REPORTED_ID: &str = "WjQK0P0B9CFxzneSpuln10MqtsZBt_K71z017zBvAWo";

/// On-chain `MemoryRoot` object id created at #144 (`anchor_create_root.json`).
const MEMORY_ROOT_OBJ: &str = "0x32badaaeb22a98bc743da6f2bb2337e0060c7eaf4de7476c697cd5d1ef74ca16";
/// On-chain `AuditLog` object id created at #144 (`anchor_create_log.json`).
const AUDIT_LOG_OBJ: &str = "0x237aa20c93917b7cd345ec82b9af7527264b7e591ef7ee9783b8c59adb1ec5a9";

/// Per-attempt timeout for the one live PUT / GET, ms.
const LIVE_TIMEOUT_MS: u32 = 30_000;

fn hex32(bytes: &[u8; 32]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(64);
    for &b in bytes {
        out.push(HEX[(b >> 4) as usize] as char);
        out.push(HEX[(b & 0x0f) as usize] as char);
    }
    out
}

/// Decode a `0x`-prefixed 64-char hex object id into an [`ObjectId`].
fn obj(hex64: &str) -> ObjectId {
    let h = hex64.strip_prefix("0x").unwrap_or(hex64);
    assert_eq!(h.len(), 64, "object id is 32 bytes / 64 hex chars");
    let mut out = [0u8; 32];
    for (i, byte) in out.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&h[i * 2..i * 2 + 2], 16).expect("valid hex");
    }
    ObjectId::new(out)
}

/// Reconstruct the exact #144 signed chunk (deterministic, offline).
fn rebuild_144_signed() -> StageBSignedChunkV1 {
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

    let signing = SigningKey::from_bytes(&[0x44; 32]);
    let signing_public =
        SigningPublicKey::from_bytes(&signing.verifying_key().to_bytes()).expect("32-byte pubkey");
    let binding = OwnerPublicKeyBinding::new(SuiAddress::new([0x6a; 32]), signing_public);
    let signature = SignatureBytes(signing.sign(&chunk_sign_preimage(&digest)).to_bytes());

    StageBSignedChunkV1::new(&view, signature, &binding).expect("valid chunk mints")
}

#[test]
#[ignore = "live Walrus testnet PUT(re-provision)+GET + replay of the #144 custody chain; requires same-message approval + network. Run: --features net-testnet --test stage_b_live_replay -- --ignored --nocapture"]
fn b5_5_full_testnet_roundtrip_replay() {
    let trace = StageBTraceLink::new(0xB550_0001, 168, 0);

    // --- (1) reconstruct the #144 chunk + its encoded wire ---
    let signed = rebuild_144_signed();
    let encoded = encode_stage_b_chunk(&signed.envelope).expect("chunk encodes");
    let official = derive_walrus_testnet_blob_id(&encoded).expect("under encoding cap");
    let arx = derive_walrus_blob_id(&encoded);
    println!(
        "REPLAY_RECON atom=168 encoded_len={} official_rs2={} arx_placeholder={}",
        encoded.len(),
        hex32(official.as_bytes()),
        hex32(arx.as_bytes()),
    );

    // The on-chain reported id verifies against the reconstructed bytes (offline,
    // server-not-an-oracle): proves our reconstruction is the #144 chunk.
    let reported = PublisherReportedBlobId::try_from_text(ATOM_144_REPORTED_ID)
        .expect("the #144 reported id is well-formed base64url-43 text");
    let verified = stage_b_verify_testnet_blob_id(&encoded, &reported)
        .expect("the on-chain #144 reported id verifies against the reconstructed bytes");
    assert_eq!(
        verified.as_blob_id().as_bytes(),
        official.as_bytes(),
        "verified id wraps the local official derive"
    );

    // --- (2, G-B-WALRUS-TESTNET) one keyless live PUT to re-provision the expired
    //     content-addressed blob; the publisher's reported id must verify. ---
    let ev_put =
        StageBTraceEvidence::from_trace(trace).expect("atom_id 168 non-zero so trace stamped");
    let put_plan = WalrusPutPlan::plan(
        WalrusTestnetEndpoint::testnet(),
        EpochCount::new(1).expect("1 epoch is positive"),
        &encoded,
        PublishPayloadClass::SyntheticPublicFixture,
        ev_put,
    )
    .expect("synthetic public fixture within cap plans");
    let mut publisher = ReqwestPublisher::new(LIVE_TIMEOUT_MS).expect("publisher builds");
    let run = publish_blob_with_transport(&mut publisher, &put_plan.request, 0xB550_0001, 1)
        .expect("the publisher loop returns a well-formed single-attempt run");
    let put_reported = match run.decision {
        PublisherResponseDecision::Accepted {
            reported_blob_id, ..
        } => reported_blob_id,
        other => panic!("live PUT not accepted: {other:?}"),
    };
    let put_verified = stage_b_verify_testnet_blob_id(&encoded, &put_reported)
        .expect("PUT-reported id verifies against the encoded bytes");
    assert_eq!(
        put_verified.as_blob_id().as_bytes(),
        official.as_bytes(),
        "PUT-reported id equals the local official derive"
    );
    println!(
        "LIVE_PUT atom=168 reported_blob_id={} verified={} match=true",
        put_reported.as_str(),
        hex32(put_verified.as_blob_id().as_bytes()),
    );

    // --- (3) best-effort read-only GET liveness probe (non-fatal) ---
    let ev_get =
        StageBTraceEvidence::from_trace(trace).expect("atom_id 168 non-zero so trace stamped");
    let plan = WalrusGetPlan::plan(AggregatorEndpoint::testnet_public(), &put_verified, ev_get);
    let mut aggregator = ReqwestAggregator::new(LIVE_TIMEOUT_MS).expect("aggregator builds");
    match aggregator.get_blob(&plan.request) {
        Ok(response) => {
            println!(
                "LIVE_GET atom=168 http_status={} body_len={} latency_ms={}",
                response.http_status_u16,
                response.body.len(),
                response.elapsed_ms_u32,
            );
            match parse_walrus_get_response(response.http_status_u16, &response.body) {
                Ok(fetched) => {
                    assert_eq!(
                        fetched.body(),
                        encoded.as_slice(),
                        "GET bytes equal the reconstructed chunk when retrievable"
                    );
                    println!("LIVE_GET_VERIFIED atom=168 bytes_match=true");
                }
                Err(_) => println!(
                    "LIVE_GET atom=168 not_yet_retrievable (non-fatal; blob just re-provisioned, testnet propagation)"
                ),
            }
        }
        Err(e) => println!("LIVE_GET atom=168 transport_note={e:?} (non-fatal)"),
    }

    // --- (4, G-B-REPLAY) replay the reconstructed chain, keyed to the real
    //     on-chain root/log object ids. ---
    let entry_hash = stage_b_audit_entry_hash(&signed, &verified);
    let move_anchor = MoveAnchorArgsV1 {
        blob_id: arx,
        kind: ChunkKind::UserMessage,
        parent: None,
    };
    let anchor = MemoryRootAnchorArgs::new(
        obj(MEMORY_ROOT_OBJ),
        move_anchor,
        *signed.digest().as_bytes(),
    );
    let audit = AuditAppendArgs::new(obj(AUDIT_LOG_OBJ), entry_hash);

    let input = StageBReplayInput {
        anchors: vec![anchor],
        audit: vec![audit],
        blobs: vec![signed],
    };
    let report = replay_stage_b(&input).expect("replay over the reconstructed chain succeeds");

    assert_eq!(report.applied_u64, 2, "1 anchor + 1 audit applied");
    assert_eq!(report.duplicate_u64, 0);
    assert_eq!(report.rejected_u64, 0);

    println!(
        "REPLAY_RESULT atom=168 applied={} duplicate={} rejected={} transcript_hash={}",
        report.applied_u64,
        report.duplicate_u64,
        report.rejected_u64,
        hex32(report.transcript.as_bytes()),
    );
    println!(
        "REPLAY_LINK atom=168 root_obj={} log_obj={} official_blob_id={} entry_hash={} transcript_hash={}",
        MEMORY_ROOT_OBJ,
        AUDIT_LOG_OBJ,
        hex32(official.as_bytes()),
        hex32(&entry_hash),
        hex32(report.transcript.as_bytes()),
    );
}
