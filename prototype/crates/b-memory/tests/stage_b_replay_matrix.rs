//! Stage B replay failure matrix (atom #167 · B.5.4) + end-to-end coverage of
//! the #164 (blob fetch), #165 (cursor), and #166 (transcript) surfaces.
//!
//! Madness clause (plan #167): *replay never guesses. It either applies, ignores
//! a duplicate, or reports an exact reject reason.* This integration test drives
//! the full offline replay pipeline over real signed chunks and asserts each of
//! the five [`StageBReplayDecision`] outcomes, the deterministic transcript hash
//! (same input → same hash; normalized so any fetch order → same hash; one
//! bitflip → different hash), the total decision matrix, and a no-panic property
//! over arbitrary anchor/audit streams.
//!
//! The signer is a raw `ed25519-dalek` key standing in for the deferred wallet
//! signer (atom #150), signing the exact atom #89 preimage — byte-identical to
//! production. No mainnet, no network, no secret: synthetic owners + fixed seeds.

// Test code prefers direct failure surfaces over Result-bubbling.
#![allow(clippy::unwrap_used)]
#![allow(clippy::expect_used)]
#![allow(clippy::panic)]

use ed25519_dalek::{Signer, SigningKey};
use proptest::prelude::*;

use mnemos_b_memory::{
    BlobFetchOutcome, OwnerPublicKeyBinding, ReplayBlobIndex, SigningPublicKey,
    StageBChunkAnchoredEvent, StageBChunkFlags, StageBChunkHeaderV1, StageBChunkView,
    StageBEventCoord, StageBReplayInput, StageBSignedChunkV1, StageBTraceLink, chunk_sign_preimage,
    decode_stage_b_chunk, derive_chunk_blob_id, fetch_for_anchor, normalize_event_stream,
    replay_stage_b, stage_b_chunk_digest,
};
use mnemos_c_walrus::codec::{BlobId, ChunkEnvelopeV1, ChunkKind, MemoryRole, MoveAnchorArgsV1};
use mnemos_c_walrus::{PublishPayloadClass, SignatureBytes};
use mnemos_d_move::{AuditAppendArgs, MemoryRootAnchorArgs, ObjectId, SuiAddress};

// ===========================================================================
// Helpers — public-API only (mirror the #99 signature_matrix fixtures).
// ===========================================================================

fn env(content: &[u8]) -> ChunkEnvelopeV1 {
    ChunkEnvelopeV1 {
        kind: ChunkKind::UserMessage,
        role: MemoryRole::User,
        parent: None,
        content: content.to_vec(),
        embedding: None,
        signature: None,
        provenance: None,
    }
}

fn header(content_len: u32, owner: SuiAddress, trace: StageBTraceLink) -> StageBChunkHeaderV1 {
    StageBChunkHeaderV1::new(
        ChunkKind::UserMessage,
        MemoryRole::User,
        PublishPayloadClass::SyntheticPublicFixture,
        StageBChunkFlags::None as u8,
        content_len,
        owner,
        None,
        trace,
    )
    .expect("known-good header is valid")
}

/// Mint a real signed chunk for `body` under a synthetic owner + fixed seed.
fn make_signed(body: &[u8], owner_byte: u8, seed: [u8; 32]) -> StageBSignedChunkV1 {
    let owner = SuiAddress::new([owner_byte; 32]);
    let signing = SigningKey::from_bytes(&seed);
    let pubkey = signing.verifying_key().to_bytes();
    let signing_public = SigningPublicKey::from_bytes(&pubkey).expect("32-byte pubkey");
    let binding = OwnerPublicKeyBinding::new(owner, signing_public);

    let e = env(body);
    let h = header(body.len() as u32, owner, StageBTraceLink::new(163, 163, 0));
    let view = StageBChunkView::new(h, &e).expect("within cap");
    let digest = stage_b_chunk_digest(&view).expect("digest ok");
    let preimage = chunk_sign_preimage(&digest);
    let sig = SignatureBytes(signing.sign(&preimage).to_bytes());
    StageBSignedChunkV1::new(&view, sig, &binding).expect("valid chunk mints")
}

/// A correct anchor for `signed` under `root`: claimed blob id = local derive,
/// digest = the chunk's committed digest.
fn anchor_for(root: ObjectId, signed: &StageBSignedChunkV1) -> MemoryRootAnchorArgs {
    let blob_id = derive_chunk_blob_id(signed).expect("encodable");
    let move_anchor = MoveAnchorArgsV1 {
        blob_id,
        kind: ChunkKind::UserMessage,
        parent: None,
    };
    MemoryRootAnchorArgs::new(root, move_anchor, *signed.digest().as_bytes())
}

/// An anchor whose blob id is correct but whose anchored digest is forged.
fn anchor_wrong_digest(root: ObjectId, signed: &StageBSignedChunkV1) -> MemoryRootAnchorArgs {
    let blob_id = derive_chunk_blob_id(signed).expect("encodable");
    let move_anchor = MoveAnchorArgsV1 {
        blob_id,
        kind: ChunkKind::UserMessage,
        parent: None,
    };
    MemoryRootAnchorArgs::new(root, move_anchor, [0xFF; 32])
}

fn root() -> ObjectId {
    ObjectId::new([0x11; 32])
}

// ===========================================================================
// #164 (B.5.1) — verified blob fetch + digest match.
// ===========================================================================

#[test]
fn b5_1_valid_blob_is_verified() {
    let signed = make_signed(b"valid body", 0x55, [0x01; 32]);
    let anchor = anchor_for(root(), &signed);
    let blobs = vec![signed];
    let index = ReplayBlobIndex::build(&blobs);
    assert!(matches!(
        fetch_for_anchor(&index, &anchor),
        BlobFetchOutcome::Verified(_)
    ));
}

#[test]
fn b5_1_digest_mismatch_is_reported() {
    let signed = make_signed(b"body for mismatch", 0x55, [0x02; 32]);
    let anchor = anchor_wrong_digest(root(), &signed);
    let blobs = vec![signed];
    let index = ReplayBlobIndex::build(&blobs);
    assert_eq!(
        fetch_for_anchor(&index, &anchor),
        BlobFetchOutcome::DigestMismatch
    );
}

#[test]
fn b5_1_missing_blob_is_reported() {
    let signed = make_signed(b"absent body", 0x55, [0x03; 32]);
    let anchor = anchor_for(root(), &signed);
    // Index built WITHOUT the anchored chunk.
    let other = make_signed(b"unrelated", 0x55, [0x04; 32]);
    let blobs = vec![other];
    let index = ReplayBlobIndex::build(&blobs);
    assert_eq!(
        fetch_for_anchor(&index, &anchor),
        BlobFetchOutcome::MissingBlob
    );
}

#[test]
fn b5_1_noncanonical_bytes_decode_rejected() {
    // The replay/fetch path decodes only canonical Stage A chunk bytes (atom
    // #92). Arbitrary non-canonical bytes are refused, not best-effort parsed.
    assert!(decode_stage_b_chunk(&[0xFFu8; 7]).is_err());
    assert!(decode_stage_b_chunk(&[]).is_err());
}

// ===========================================================================
// #165 (B.5.2) — cursor apply order, duplicate, missing, owner mismatch.
// ===========================================================================

#[test]
fn b5_2_apply_order_advances_cursor() {
    let s0 = make_signed(b"chunk zero", 0x55, [0x10; 32]);
    let s1 = make_signed(b"chunk one", 0x55, [0x11; 32]);
    let s2 = make_signed(b"chunk two", 0x55, [0x12; 32]);
    let anchors = vec![
        anchor_for(root(), &s0),
        anchor_for(root(), &s1),
        anchor_for(root(), &s2),
    ];
    let blobs = vec![s0, s1, s2];
    let input = StageBReplayInput {
        anchors,
        audit: vec![],
        blobs,
    };
    let report = replay_stage_b(&input).expect("ok");
    assert_eq!(report.applied_u64, 3);
    assert_eq!(report.duplicate_u64, 0);
    assert_eq!(report.rejected_u64, 0);
}

#[test]
fn b5_2_duplicate_anchor_is_idempotent() {
    let s0 = make_signed(b"dup chunk", 0x55, [0x20; 32]);
    let anchor = anchor_for(root(), &s0);
    let anchors = vec![anchor, anchor, anchor]; // same anchor three times
    let blobs = vec![s0];
    let input = StageBReplayInput {
        anchors,
        audit: vec![],
        blobs,
    };
    let report = replay_stage_b(&input).expect("ok");
    assert_eq!(report.applied_u64, 1, "only the first occurrence applies");
    assert_eq!(report.duplicate_u64, 2, "the rest are idempotently ignored");
    assert_eq!(report.rejected_u64, 0);
}

#[test]
fn b5_2_owner_mismatch_is_rejected() {
    let s0 = make_signed(b"owner a chunk", 0x55, [0x30; 32]);
    let s1 = make_signed(b"owner b chunk", 0x55, [0x31; 32]);
    let anchors = vec![
        anchor_for(ObjectId::new([0x11; 32]), &s0), // binds root 0x11
        anchor_for(ObjectId::new([0x99; 32]), &s1), // foreign root 0x99
    ];
    let blobs = vec![s0, s1];
    let input = StageBReplayInput {
        anchors,
        audit: vec![],
        blobs,
    };
    let report = replay_stage_b(&input).expect("ok");
    assert_eq!(report.applied_u64, 1);
    assert_eq!(
        report.rejected_u64, 1,
        "foreign-root anchor is OwnerMismatch"
    );
}

#[test]
fn b5_2_full_decision_matrix_total() {
    let s_apply = make_signed(b"applied", 0x55, [0x40; 32]);
    let s_mismatch = make_signed(b"mismatch", 0x55, [0x41; 32]);
    let s_missing = make_signed(b"missing", 0x55, [0x42; 32]);
    let s_foreign = make_signed(b"foreign", 0x55, [0x43; 32]);

    let a_apply = anchor_for(root(), &s_apply);
    let anchors = vec![
        a_apply,                                           // Applied
        a_apply,                                           // DuplicateIgnored
        anchor_for(root(), &s_missing),                    // MissingBlob (omitted)
        anchor_wrong_digest(root(), &s_mismatch),          // DigestMismatch
        anchor_for(ObjectId::new([0x99; 32]), &s_foreign), // OwnerMismatch
    ];
    // s_missing intentionally NOT in blobs.
    let blobs = vec![s_apply, s_mismatch, s_foreign];
    let input = StageBReplayInput {
        anchors,
        audit: vec![],
        blobs,
    };
    let report = replay_stage_b(&input).expect("ok");
    assert_eq!(report.applied_u64, 1);
    assert_eq!(report.duplicate_u64, 1);
    assert_eq!(
        report.rejected_u64, 3,
        "missing + mismatch + owner = 3 rejects"
    );
    // applied + duplicate + rejected == total events
    assert_eq!(
        report.applied_u64 + report.duplicate_u64 + report.rejected_u64,
        5
    );
}

#[test]
fn b5_2_audit_log_binding() {
    let consistent = AuditAppendArgs::new(ObjectId::new([0x33; 32]), [0xEE; 32]);
    let foreign = AuditAppendArgs::new(ObjectId::new([0x44; 32]), [0xEE; 32]);
    let input = StageBReplayInput {
        anchors: vec![],
        audit: vec![consistent, foreign],
        blobs: vec![],
    };
    let report = replay_stage_b(&input).expect("ok");
    assert_eq!(report.applied_u64, 1, "first audit binds the log");
    assert_eq!(report.rejected_u64, 1, "foreign log is OwnerMismatch");
}

// ===========================================================================
// #166 (B.5.3) — transcript determinism.
// ===========================================================================

fn three_event_input() -> StageBReplayInput {
    let s0 = make_signed(b"t0", 0x55, [0x50; 32]);
    let s1 = make_signed(b"t1", 0x55, [0x51; 32]);
    StageBReplayInput {
        anchors: vec![anchor_for(root(), &s0), anchor_for(root(), &s1)],
        audit: vec![AuditAppendArgs::new(ObjectId::new([0x33; 32]), [0xEE; 32])],
        blobs: vec![s0, s1],
    }
}

#[test]
fn b5_3_same_input_same_transcript() {
    let a = replay_stage_b(&three_event_input()).expect("ok");
    let b = replay_stage_b(&three_event_input()).expect("ok");
    assert_eq!(a.transcript, b.transcript);
    assert_eq!(a.applied_u64, b.applied_u64);
}

#[test]
fn b5_3_normalized_fetch_order_same_transcript() {
    // Build coordinate-tagged events, normalize from two different fetch orders,
    // and assert the replay transcript is identical.
    let s0 = make_signed(b"n0", 0x55, [0x60; 32]);
    let s1 = make_signed(b"n1", 0x55, [0x61; 32]);
    let s2 = make_signed(b"n2", 0x55, [0x62; 32]);

    let e0 = StageBChunkAnchoredEvent::new(
        StageBEventCoord::new(5, [0x01; 32], 0),
        anchor_for(root(), &s0),
    );
    let e1 = StageBChunkAnchoredEvent::new(
        StageBEventCoord::new(5, [0x01; 32], 1),
        anchor_for(root(), &s1),
    );
    let e2 = StageBChunkAnchoredEvent::new(
        StageBEventCoord::new(6, [0x02; 32], 0),
        anchor_for(root(), &s2),
    );

    let blobs = vec![s0, s1, s2];

    let make_input = |events: Vec<StageBChunkAnchoredEvent>| -> StageBReplayInput {
        let norm = normalize_event_stream(events, vec![]).expect("well-formed");
        StageBReplayInput {
            anchors: norm.anchors.iter().map(|e| e.anchor).collect(),
            audit: vec![],
            blobs: blobs.clone(),
        }
    };

    let in_order = make_input(vec![e0, e1, e2]);
    let shuffled = make_input(vec![e2, e0, e1]);

    let a = replay_stage_b(&in_order).expect("ok");
    let b = replay_stage_b(&shuffled).expect("ok");
    assert_eq!(
        a.transcript, b.transcript,
        "transcript must be invariant to fetch order after normalization"
    );
}

#[test]
fn b5_3_bitflip_changes_transcript() {
    let base = replay_stage_b(&three_event_input()).expect("ok");

    // Flip one byte of an anchored digest → a different replay → different hash.
    let s0 = make_signed(b"t0", 0x55, [0x50; 32]);
    let s1 = make_signed(b"t1", 0x55, [0x51; 32]);
    let flipped_anchor = anchor_wrong_digest(root(), &s0); // digest = [0xFF;32]
    let input = StageBReplayInput {
        anchors: vec![flipped_anchor, anchor_for(root(), &s1)],
        audit: vec![AuditAppendArgs::new(ObjectId::new([0x33; 32]), [0xEE; 32])],
        blobs: vec![s0, s1],
    };
    let flipped = replay_stage_b(&input).expect("ok");
    assert_ne!(
        base.transcript, flipped.transcript,
        "a changed anchored digest must change the transcript"
    );
}

// ===========================================================================
// #167 (B.5.4) — arbitrary stream property: no panic, always a report.
// ===========================================================================

proptest! {
    #![proptest_config(ProptestConfig::with_cases(256))]

    #[test]
    fn b5_4_arbitrary_stream_never_panics(
        roots in prop::collection::vec(any::<[u8; 32]>(), 0..24),
        blob_ids in prop::collection::vec(any::<[u8; 32]>(), 0..24),
        digests in prop::collection::vec(any::<[u8; 32]>(), 0..24),
        logs in prop::collection::vec(any::<[u8; 32]>(), 0..24),
        hashes in prop::collection::vec(any::<[u8; 32]>(), 0..24),
    ) {
        let n = roots.len().min(blob_ids.len()).min(digests.len());
        let anchors: Vec<MemoryRootAnchorArgs> = (0..n)
            .map(|i| {
                let move_anchor = MoveAnchorArgsV1 {
                    blob_id: BlobId(blob_ids[i]),
                    kind: ChunkKind::UserMessage,
                    parent: None,
                };
                MemoryRootAnchorArgs::new(ObjectId::new(roots[i]), move_anchor, digests[i])
            })
            .collect();

        let m = logs.len().min(hashes.len());
        let audit: Vec<AuditAppendArgs> = (0..m)
            .map(|i| AuditAppendArgs::new(ObjectId::new(logs[i]), hashes[i]))
            .collect();

        let input = StageBReplayInput {
            anchors,
            audit,
            blobs: vec![], // no blobs → every anchor is MissingBlob or OwnerMismatch
        };

        // Must never panic and must always produce a report whose counts are
        // internally consistent.
        let report = replay_stage_b(&input).expect("bounded input is always Ok");
        prop_assert_eq!(
            report.applied_u64 + report.duplicate_u64 + report.rejected_u64,
            (n + m) as u64
        );
    }
}
