//! Integration tests for `mnemos_c_walrus::codec` (atom #7 · C.0.1).
//!
//! Every byte-stable hex literal in this file was computed by the
//! out-of-tree Python oracle at
//! `ops/evidence/phase_0/atom_007/oracle_bcs_chunk_v1.py` (Session 1
//! evidence) and re-asserted here. A drift between the Python oracle and
//! the Rust codec is caught at test time — that is the cross-language
//! schema lock the atom delivers.
#![allow(clippy::unwrap_used)]
#![allow(clippy::expect_used)]
#![allow(clippy::panic)]
#![allow(clippy::print_stdout)]
#![allow(clippy::print_stderr)]

use mnemos_c_walrus::{
    BLOB_ID_BYTES, BlobId, ChunkCodecError, ChunkEnvelopeV1, ChunkKind, EMBEDDING_WIRE_BYTES,
    EmbeddingRefV1, MAX_CONTENT_BYTES, MIN_EMPTY_CHUNK_V1_BYTES, MemoryRole, PROVENANCE_ID_BYTES,
    PROVENANCE_WIRE_BYTES, ProvenanceNamespace, ProvenanceRefV1, SCHEMA_VERSION_V1,
    SIGNATURE_BYTES, SIGNATURE_WIRE_BYTES, SignatureBytes, SignaturePlaceholderV1, SignatureScheme,
    decode_chunk_v1, encode_chunk_v1, encoded_len_for_content_len,
    metadata_overhead_for_content_len, public_type_sizes_v1,
};
use proptest::collection::vec as prop_vec;
use proptest::prelude::*;

// ===========================================================================
// Helpers
// ===========================================================================

fn hex_encode(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

fn minimal_empty() -> ChunkEnvelopeV1 {
    ChunkEnvelopeV1 {
        kind: ChunkKind::UserMessage,
        role: MemoryRole::User,
        parent: None,
        content: Vec::new(),
        embedding: None,
        signature: None,
        provenance: None,
    }
}

fn one_byte_content() -> ChunkEnvelopeV1 {
    ChunkEnvelopeV1 {
        kind: ChunkKind::UserMessage,
        role: MemoryRole::User,
        parent: None,
        content: vec![0x42],
        embedding: None,
        signature: None,
        provenance: None,
    }
}

fn saturated_parent_signature_provenance() -> ChunkEnvelopeV1 {
    ChunkEnvelopeV1 {
        kind: ChunkKind::AssistantMessage,
        role: MemoryRole::System,
        parent: Some(BlobId([0xAA; BLOB_ID_BYTES])),
        content: b"hello mnemos".to_vec(),
        embedding: None,
        signature: Some(SignaturePlaceholderV1 {
            scheme: SignatureScheme::Ed25519,
            public_key: [0xBB; BLOB_ID_BYTES],
            signature: SignatureBytes([0xCC; SIGNATURE_BYTES]),
        }),
        provenance: Some(ProvenanceRefV1 {
            namespace: ProvenanceNamespace::SkillRegistry,
            id: [0xDD; PROVENANCE_ID_BYTES],
            version_u32: 0x01020304,
        }),
    }
}

// ===========================================================================
// 9 named tests verbatim from MNEMOS_ATOM_PLAN §C.0.1
// ===========================================================================

#[test]
fn minimal_empty_vector_bytes_are_stable() {
    // From Python oracle: minimal_empty → 10 bytes "01010100000000000000".
    const ORACLE_HEX: &str = "01010100000000000000";
    let chunk = minimal_empty();
    let bytes = encode_chunk_v1(&chunk).expect("encode minimal empty");
    assert_eq!(bytes.len(), MIN_EMPTY_CHUNK_V1_BYTES);
    assert_eq!(hex_encode(&bytes), ORACLE_HEX);
    let round = decode_chunk_v1(&bytes).expect("decode minimal empty");
    assert_eq!(round, chunk);
}

#[test]
fn one_byte_vector_bytes_are_stable() {
    // From Python oracle: one_byte_content → 11 bytes "0101010000000142000000".
    const ORACLE_HEX: &str = "0101010000000142000000";
    let chunk = one_byte_content();
    let bytes = encode_chunk_v1(&chunk).expect("encode one-byte");
    assert_eq!(bytes.len(), 11);
    assert_eq!(hex_encode(&bytes), ORACLE_HEX);
    let round = decode_chunk_v1(&bytes).expect("decode one-byte");
    assert_eq!(round, chunk);
}

#[test]
fn parent_signature_provenance_vector_round_trips() {
    // From Python oracle: parent_signature_provenance → 188 bytes.
    const ORACLE_HEX: &str = concat!(
        "010203000001",
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        "0c",
        "68656c6c6f206d6e656d6f73",
        "00",
        "0101",
        "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
        "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
        "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
        "0101",
        "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
        "04030201",
    );
    let chunk = saturated_parent_signature_provenance();
    let bytes = encode_chunk_v1(&chunk).expect("encode saturated");
    assert_eq!(bytes.len(), 188);
    assert_eq!(hex_encode(&bytes), ORACLE_HEX);
    let round = decode_chunk_v1(&bytes).expect("decode saturated");
    assert_eq!(round, chunk);
}

#[test]
fn length_edges_are_measured_without_live_network() {
    // Pure arithmetic over `encoded_len_for_content_len` and
    // `metadata_overhead_for_content_len`. No network, no allocation.

    // content_len == 0 → minimum envelope.
    assert_eq!(
        encoded_len_for_content_len(0).unwrap(),
        MIN_EMPTY_CHUNK_V1_BYTES
    );
    assert_eq!(metadata_overhead_for_content_len(0).unwrap(), 10);

    // uleb128 length transitions (1B → 2B at 128, 2B → 3B at 16_384, etc.)
    // overhead = 9 + uleb128_len(content_len).
    let cases: &[(u32, usize)] = &[
        (0, 10),
        (1, 10),
        (127, 10),
        (128, 11),
        (16_383, 11),
        (16_384, 12),
        (2_097_151, 12),
        (2_097_152, 13),
        (MAX_CONTENT_BYTES, 13),
    ];
    for &(content_len, expected_overhead) in cases {
        assert_eq!(
            metadata_overhead_for_content_len(content_len).unwrap(),
            expected_overhead,
            "metadata overhead for content_len={content_len}"
        );
        assert_eq!(
            encoded_len_for_content_len(content_len).unwrap(),
            expected_overhead + content_len as usize,
            "encoded len for content_len={content_len}"
        );
    }

    // Cap enforcement.
    let over = MAX_CONTENT_BYTES + 1;
    assert!(matches!(
        encoded_len_for_content_len(over),
        Err(ChunkCodecError::ContentTooLarge { observed_u32, max_u32 })
            if observed_u32 == over && max_u32 == MAX_CONTENT_BYTES
    ));
    assert!(matches!(
        metadata_overhead_for_content_len(over),
        Err(ChunkCodecError::ContentTooLarge { observed_u32, max_u32 })
            if observed_u32 == over && max_u32 == MAX_CONTENT_BYTES
    ));
}

#[test]
fn public_type_sizes_are_fixed_for_measurements() {
    let sizes = public_type_sizes_v1();
    // `repr(transparent)` over `[u8; 32]` / `[u8; 64]`.
    assert_eq!(sizes.blob_id, 32);
    assert_eq!(sizes.signature_bytes, 64);
    // `repr(C)` payloads. Stable for V1; bumped only with a SCHEMA_VERSION
    // change.
    assert_eq!(sizes.embedding_ref, 36);
    assert_eq!(sizes.provenance_ref, 40);

    // Move-side projections. Pin observed sizes so any future rustc change
    // is caught.
    let seed = sizes.move_anchor_seed;
    let args = sizes.move_anchor_args;
    assert!(
        seed >= 33,
        "MoveAnchorSeedV1 must fit at minimum 1 (kind) + 1 (Option tag) + 32 (parent)"
    );
    assert!(
        args >= 65,
        "MoveAnchorArgsV1 must fit at minimum 32 (blob_id) + 1 (kind) + 1 (Option tag) + 32 (parent)"
    );

    // Sanity: wire-byte constants line up.
    assert_eq!(EMBEDDING_WIRE_BYTES, 36);
    assert_eq!(SIGNATURE_WIRE_BYTES, 97);
    assert_eq!(PROVENANCE_WIRE_BYTES, 37);
    assert_eq!(SCHEMA_VERSION_V1, 1);
    assert_eq!(BLOB_ID_BYTES, 32);
    assert_eq!(SIGNATURE_BYTES, 64);
    assert_eq!(PROVENANCE_ID_BYTES, 32);
    assert_eq!(MAX_CONTENT_BYTES, 13_000_000);
}

#[test]
fn reject_unknown_kind_reserved_flags_and_trailing_bytes() {
    let base = encode_chunk_v1(&minimal_empty()).unwrap();

    // (a) Tamper kind tag → UnknownKind. `base[1]` is the kind byte.
    let mut tampered_kind = base.clone();
    tampered_kind[1] = 99;
    assert!(matches!(
        decode_chunk_v1(&tampered_kind),
        Err(ChunkCodecError::UnknownKind { tag: 99 })
    ));

    // (b) Tamper reserved_flags (offset 3..=4, u16 LE) → ReservedFlags.
    let mut tampered_flags = base.clone();
    tampered_flags[3] = 0x01;
    tampered_flags[4] = 0x00;
    assert!(matches!(
        decode_chunk_v1(&tampered_flags),
        Err(ChunkCodecError::ReservedFlags { flags: 0x0001 })
    ));
    let mut tampered_flags_high = base.clone();
    tampered_flags_high[3] = 0x00;
    tampered_flags_high[4] = 0x80;
    assert!(matches!(
        decode_chunk_v1(&tampered_flags_high),
        Err(ChunkCodecError::ReservedFlags { flags: 0x8000 })
    ));

    // (c) Trailing byte → NonCanonical.
    let mut with_trailing = base.clone();
    with_trailing.push(0x00);
    assert!(matches!(
        decode_chunk_v1(&with_trailing),
        Err(ChunkCodecError::NonCanonical)
    ));
}

#[test]
fn reject_truncated_prefixes() {
    // Empty buffer → EmptyInput (special case).
    assert!(matches!(
        decode_chunk_v1(&[]),
        Err(ChunkCodecError::EmptyInput)
    ));

    // Every strict prefix of a valid minimal-empty encoding must error.
    // Some prefixes will report Truncated (the cursor ran out); others may
    // report UnsupportedVersion, UnknownKind, etc. (the prefix happens to
    // collide with a field check). The invariant is `decode == Err(_)`.
    let base = encode_chunk_v1(&minimal_empty()).unwrap();
    assert_eq!(base.len(), 10);
    for cut in 0..base.len() {
        let prefix = &base[..cut];
        let err = decode_chunk_v1(prefix).unwrap_err();
        assert!(
            matches!(
                err,
                ChunkCodecError::EmptyInput | ChunkCodecError::Truncated { .. }
            ),
            "prefix len {cut} must be Truncated or EmptyInput, got {err:?}"
        );
    }

    // A saturated envelope: trim each suffix and assert Truncated.
    let big = encode_chunk_v1(&saturated_parent_signature_provenance()).unwrap();
    for cut in 10..big.len() {
        let prefix = &big[..cut];
        let err = decode_chunk_v1(prefix).unwrap_err();
        assert!(
            matches!(err, ChunkCodecError::Truncated { .. }),
            "saturated prefix len {cut} expected Truncated, got {err:?}"
        );
    }
}

#[test]
fn reject_oversized_content_before_allocating_body() {
    // Header + parent None + uleb128(MAX_CONTENT_BYTES + 1) — *no body bytes*.
    // The decoder MUST reject before attempting `Vec::with_capacity(over)`.
    //
    // uleb128(13_000_001) computed externally: 0xC1 0xBA 0x99 0x06.
    let mut frame: Vec<u8> = vec![
        SCHEMA_VERSION_V1, // version
        1,                 // kind = UserMessage
        1,                 // role = User
        0x00,
        0x00, // reserved_flags = 0
        0x00, // parent: None
        0xC1,
        0xBA,
        0x99,
        0x06, // uleb128(13_000_001)
    ];
    // Add no body bytes at all — decoder would crash on huge alloc if the
    // cap check came AFTER `Vec::with_capacity(content_len)`.
    let err = decode_chunk_v1(&frame).unwrap_err();
    assert!(
        matches!(
            err,
            ChunkCodecError::ContentTooLarge { observed_u32, max_u32 }
                if observed_u32 == MAX_CONTENT_BYTES + 1 && max_u32 == MAX_CONTENT_BYTES
        ),
        "expected ContentTooLarge, got {err:?}"
    );

    // Even appending a small body keeps the same decision: cap check fires
    // before body consumption.
    frame.extend_from_slice(&[0u8; 16]);
    let err2 = decode_chunk_v1(&frame).unwrap_err();
    assert!(matches!(err2, ChunkCodecError::ContentTooLarge { .. }));

    // At-cap claim with truncated body → Truncated{field:"content"},
    // NOT a panic. uleb128(13_000_000) = 0xC0 0xBA 0x99 0x06.
    let frame3: Vec<u8> = vec![
        SCHEMA_VERSION_V1,
        1,
        1,
        0x00,
        0x00,
        0x00,
        0xC0,
        0xBA,
        0x99,
        0x06,
    ];
    let err3 = decode_chunk_v1(&frame3).unwrap_err();
    assert!(matches!(
        err3,
        ChunkCodecError::Truncated { field: "content" }
    ));

    // Non-canonical uleb128 (`0x80 0x00` represents zero non-minimally) →
    // InvalidLengthPrefix.
    let frame4: Vec<u8> = vec![
        SCHEMA_VERSION_V1,
        1,
        1,
        0x00,
        0x00,
        0x00,
        0x80,
        0x00,
        0x00,
        0x00,
        0x00,
    ];
    let err4 = decode_chunk_v1(&frame4).unwrap_err();
    assert!(matches!(err4, ChunkCodecError::InvalidLengthPrefix));
}

#[test]
fn reject_invalid_option_and_zero_embedding_dims() {
    // (a) Parent Option tag = 2 → InvalidOptionTag{field:"parent"}.
    let base = encode_chunk_v1(&minimal_empty()).unwrap();
    let mut bad_parent = base.clone();
    bad_parent[5] = 2; // parent option tag is byte 5 in minimal empty.
    let err = decode_chunk_v1(&bad_parent).unwrap_err();
    assert!(
        matches!(
            err,
            ChunkCodecError::InvalidOptionTag {
                field: "parent",
                tag: 2,
            }
        ),
        "expected InvalidOptionTag{{parent,2}}, got {err:?}"
    );

    // (b) embedding with dims_u16 == 0 → ZeroEmbeddingDims at encode AND at
    // decode (built by hand, since encode would refuse).
    let chunk_with_zero_dims = ChunkEnvelopeV1 {
        kind: ChunkKind::UserMessage,
        role: MemoryRole::User,
        parent: None,
        content: Vec::new(),
        embedding: Some(EmbeddingRefV1 {
            model_tag_u16: 7,
            dims_u16: 0, // illegal
            vector_hash: [0u8; BLOB_ID_BYTES],
        }),
        signature: None,
        provenance: None,
    };
    let enc_err = encode_chunk_v1(&chunk_with_zero_dims).unwrap_err();
    assert_eq!(enc_err, ChunkCodecError::ZeroEmbeddingDims);

    // Build wire bytes directly bypassing encode_chunk_v1 to test decode.
    let mut wire: Vec<u8> = vec![
        SCHEMA_VERSION_V1,
        1,
        1,
        0x00,
        0x00, // header (no flags)
        0x00, // parent: None
        0x00, // content len = 0
        0x01, // embedding: Some
        0x07,
        0x00, // model_tag = 7
        0x00,
        0x00, // dims = 0 (illegal)
    ];
    wire.extend(std::iter::repeat_n(0u8, BLOB_ID_BYTES)); // vector_hash
    wire.push(0x00); // signature: None
    wire.push(0x00); // provenance: None
    let dec_err = decode_chunk_v1(&wire).unwrap_err();
    assert_eq!(dec_err, ChunkCodecError::ZeroEmbeddingDims);
}

// ===========================================================================
// Proptest round-trip
// ===========================================================================

prop_compose! {
    fn arb_blob_id()(bytes in prop_vec(any::<u8>(), BLOB_ID_BYTES)) -> BlobId {
        let mut a = [0u8; BLOB_ID_BYTES];
        a.copy_from_slice(&bytes);
        BlobId(a)
    }
}

prop_compose! {
    fn arb_sig_bytes()(bytes in prop_vec(any::<u8>(), SIGNATURE_BYTES)) -> SignatureBytes {
        let mut a = [0u8; SIGNATURE_BYTES];
        a.copy_from_slice(&bytes);
        SignatureBytes(a)
    }
}

prop_compose! {
    fn arb_pubkey()(bytes in prop_vec(any::<u8>(), BLOB_ID_BYTES)) -> [u8; BLOB_ID_BYTES] {
        let mut a = [0u8; BLOB_ID_BYTES];
        a.copy_from_slice(&bytes);
        a
    }
}

prop_compose! {
    fn arb_prov_id()(bytes in prop_vec(any::<u8>(), PROVENANCE_ID_BYTES)) -> [u8; PROVENANCE_ID_BYTES] {
        let mut a = [0u8; PROVENANCE_ID_BYTES];
        a.copy_from_slice(&bytes);
        a
    }
}

fn arb_kind() -> impl Strategy<Value = ChunkKind> {
    prop_oneof![
        Just(ChunkKind::UserMessage),
        Just(ChunkKind::AssistantMessage),
        Just(ChunkKind::SystemMemory),
        Just(ChunkKind::ToolResult),
        Just(ChunkKind::SkillArtifact),
    ]
}

fn arb_role() -> impl Strategy<Value = MemoryRole> {
    prop_oneof![
        Just(MemoryRole::User),
        Just(MemoryRole::Assistant),
        Just(MemoryRole::System),
        Just(MemoryRole::Tool),
        Just(MemoryRole::Agent),
    ]
}

fn arb_provenance_ns() -> impl Strategy<Value = ProvenanceNamespace> {
    prop_oneof![
        Just(ProvenanceNamespace::SkillRegistry),
        Just(ProvenanceNamespace::MarketplaceRegistry),
    ]
}

prop_compose! {
    fn arb_embedding()(
        model_tag_u16 in any::<u16>(),
        dims_u16 in 1u16..=u16::MAX,
        vector_hash in arb_pubkey(),
    ) -> EmbeddingRefV1 {
        EmbeddingRefV1 { model_tag_u16, dims_u16, vector_hash }
    }
}

prop_compose! {
    fn arb_signature()(
        public_key in arb_pubkey(),
        signature in arb_sig_bytes(),
    ) -> SignaturePlaceholderV1 {
        SignaturePlaceholderV1 {
            scheme: SignatureScheme::Ed25519,
            public_key,
            signature,
        }
    }
}

prop_compose! {
    fn arb_provenance()(
        namespace in arb_provenance_ns(),
        id in arb_prov_id(),
        version_u32 in any::<u32>(),
    ) -> ProvenanceRefV1 {
        ProvenanceRefV1 { namespace, id, version_u32 }
    }
}

prop_compose! {
    fn arb_envelope()(
        kind in arb_kind(),
        role in arb_role(),
        parent in proptest::option::of(arb_blob_id()),
        content in prop_vec(any::<u8>(), 0..=512),
        embedding in proptest::option::of(arb_embedding()),
        signature in proptest::option::of(arb_signature()),
        provenance in proptest::option::of(arb_provenance()),
    ) -> ChunkEnvelopeV1 {
        ChunkEnvelopeV1 { kind, role, parent, content, embedding, signature, provenance }
    }
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 256, ..ProptestConfig::default() })]

    /// `encode ∘ decode == identity` for every valid envelope.
    #[test]
    fn proptest_encode_decode_round_trip(envelope in arb_envelope()) {
        let bytes = encode_chunk_v1(&envelope).unwrap();
        let decoded = decode_chunk_v1(&bytes).unwrap();
        prop_assert_eq!(decoded, envelope);
    }

    /// For arbitrary byte strings the decoder either errors or accepts; if
    /// it accepts, the re-encoding must equal the original input (canonical
    /// strict — the cross-language schema lock).
    #[test]
    fn proptest_arbitrary_bytes_decode_then_re_encode_is_canonical(
        bytes in prop_vec(any::<u8>(), 0..=128)
    ) {
        match decode_chunk_v1(&bytes) {
            Ok(env) => {
                let re = encode_chunk_v1(&env).unwrap();
                prop_assert_eq!(re, bytes);
            }
            Err(_) => {
                // Reject is allowed — most random byte strings are invalid.
            }
        }
    }
}
