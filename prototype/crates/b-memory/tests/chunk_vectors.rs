//! Stage B chunk schema golden vectors (atom #96 · B.1.15).
//!
//! Cross-language Move/Rust parity anchors. The fixture
//! `tests/fixtures/stage_b_chunk_v1.json` is the single source of truth for the
//! Stage B chunk header / content hash / digest / signature / blob id / audit
//! entry hash / canonical wire bytes of a fixed set of synthetic chunks. This
//! integration test re-derives every one of those quantities from the public
//! `mnemos-b-memory` API (reusing atoms #91–#95 verbatim) and asserts each
//! matches the stored vector — so any byte drift in the schema, the digest core,
//! the signature preimage, or the canonical encoder is caught here, and the Move
//! side (§4.3) can read the same JSON to stay byte-identical with Rust.
//!
//! The fixture's `v1_known_audit_anchor` reproduces the atom #95 golden audit
//! entry hash `b768ea44…`, which was itself independently derived by the
//! cross-language Python reference `/tmp/mnemos_audit_ref.py` — so the vectors
//! are anchored to an already-verified constant, never self-captured.
//!
//! Madness clause: "Drift requires explicit version bump." `b1_15_schema_lock`
//! pins `STAGE_B_CHUNK_SCHEMA_V1`, the wire schema version byte, and the two
//! domain strings against the fixture, so a silent version/domain change fails.
//!
//! Reuse only — this atom mints no production code (zero `src/` change); it
//! consumes the canonical OUTs of #91 (`encode_stage_b_chunk`), #92
//! (`decode_stage_b_chunk`), #93 (`stage_b_publish_allowed`), #94 (the trace
//! carried in the chunk header) and #95 (`stage_b_audit_entry_hash`), plus the
//! #84–#90 header / view / digest / signed-chunk constructors.

// Test code prefers direct failure surfaces (`expect`/`unwrap`/`assert`) over
// `Result`-bubbling; suppress the prod-only clippy denies for this test crate
// (b-memory #86/#88/#89/#90/#95 unit-test precedent).
#![allow(clippy::unwrap_used)]
#![allow(clippy::expect_used)]
#![allow(clippy::panic)]

use ed25519_dalek::{Signer, SigningKey};
use mnemos_b_memory::{
    AUDIT_ENTRY_DOMAIN, CHUNK_SIGN_DOMAIN, ContentHash32, OwnerPublicKeyBinding,
    STAGE_B_CHUNK_SCHEMA_V1, SigningPublicKey, StageBChunkHeaderV1, StageBChunkView,
    StageBSignedChunkV1, StageBTraceLink, chunk_sign_preimage, decode_stage_b_chunk,
    encode_stage_b_chunk, stage_b_audit_entry_hash, stage_b_chunk_digest, stage_b_publish_allowed,
};
use mnemos_c_walrus::codec::{BlobId, ChunkEnvelopeV1, ChunkKind, MemoryRole};
use mnemos_c_walrus::{
    PublishPayloadClass, PublisherReportedBlobId, SignatureBytes, VerifiedBlobId, derive_blob_id,
    verify_reported_blob_id,
};
use mnemos_d_move::SuiAddress;

/// The fixture, embedded at compile time so the test is hermetic and needs no
/// runtime path resolution. Parsing it below is the "vectors load" step.
const FIXTURE: &str = include_str!("fixtures/stage_b_chunk_v1.json");

// ===========================================================================
// Minimal serde-free JSON readers (test-only; no new dependency).
//
// The fixture is a flat object with a `"vectors"` array of flat objects (no
// nested objects/arrays inside a vector, and no `"` or `\` inside any string
// value), so these readers are correct for this exact well-formed file. They
// are deliberately tiny — a golden-fixture reader, not a general JSON parser.
// ===========================================================================

/// The string value of `"key": "..."` within `obj`. Empty string if the value
/// is `""`. Panics if the key is absent (a fixture-shape regression).
fn sfield<'a>(obj: &'a str, key: &str) -> &'a str {
    let pat = format!("\"{key}\":");
    let start = obj.find(&pat).expect("string key present") + pat.len();
    let rest = obj[start..]
        .trim_start()
        .strip_prefix('"')
        .expect("string value opens with a quote");
    let end = rest.find('"').expect("string value closes with a quote");
    &rest[..end]
}

/// The unsigned-integer value of `"key": <digits>` within `obj`.
fn nfield(obj: &str, key: &str) -> u64 {
    let pat = format!("\"{key}\":");
    let start = obj.find(&pat).expect("numeric key present") + pat.len();
    let rest = obj[start..].trim_start();
    let end = rest
        .find(|c: char| !c.is_ascii_digit())
        .unwrap_or(rest.len());
    rest[..end].parse().expect("decimal integer")
}

/// Slice the fixture into its flat vector objects. Each `{ … }` after the
/// `"vectors"` key is one vector (the objects carry no nested braces).
fn vector_objects(doc: &str) -> Vec<&str> {
    let region = &doc[doc.find("\"vectors\":").expect("vectors array present")..];
    let bytes = region.as_bytes();
    let mut out = Vec::new();
    let mut i = 0usize;
    while i < bytes.len() {
        if bytes[i] == b'{' {
            let rel_end = region[i..].find('}').expect("flat object closes");
            out.push(&region[i..=i + rel_end]);
            i += rel_end + 1;
        } else {
            i += 1;
        }
    }
    out
}

/// Decode an even-length lowercase hex string into bytes.
fn unhex(s: &str) -> Vec<u8> {
    assert!(s.len() % 2 == 0, "hex string has even length");
    (0..s.len() / 2)
        .map(|i| u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).expect("hex byte"))
        .collect()
}

/// Decode a 64-hex-char field into a fixed `[u8; 32]`.
fn unhex32(s: &str) -> [u8; 32] {
    let v = unhex(s);
    assert_eq!(v.len(), 32, "32-byte hex field");
    let mut a = [0u8; 32];
    a.copy_from_slice(&v);
    a
}

// ===========================================================================
// Blob-id verification helpers (verbatim from the #95 unit-test helpers —
// the only local-verify path to a `VerifiedBlobId`).
// ===========================================================================

/// URL-safe base64 (no pad) over a 32-byte id — duplicates `c-walrus`'s
/// `pub(crate)` encoder (chunk.rs / #95 test-helper precedent).
fn encode_b64url(raw: &[u8; 32]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut out = String::with_capacity(43);
    let mut buf: u32 = 0;
    let mut bits: u32 = 0;
    for &b in raw {
        buf = (buf << 8) | u32::from(b);
        bits += 8;
        while bits >= 6 {
            bits -= 6;
            out.push(ALPHABET[((buf >> bits) & 0x3F) as usize] as char);
        }
    }
    if bits > 0 {
        out.push(ALPHABET[((buf << (6 - bits)) & 0x3F) as usize] as char);
    }
    out
}

/// Build a `VerifiedBlobId` from `witness` via the public `derive_blob_id` +
/// `verify_reported_blob_id` round-trip (raw `BlobId` is unrepresentable at the
/// audit seam, so this is the only construction path).
fn verified_blob(witness: &[u8]) -> VerifiedBlobId {
    let derived = derive_blob_id(witness);
    let text = encode_b64url(derived.as_bytes());
    let reported = PublisherReportedBlobId::try_from_text(&text).expect("base64url length 43");
    verify_reported_blob_id(witness, &reported).expect("self-derived round-trip verifies")
}

// ===========================================================================
// Tests
// ===========================================================================

/// `b1_15_vectors_load` — the fixture parses and yields the expected vector set.
/// This is the "all vectors load" madness test (and a guard that the serde-free
/// reader stays aligned with the fixture shape).
#[test]
fn b1_15_vectors_load() {
    let vectors = vector_objects(FIXTURE);
    assert_eq!(vectors.len(), 3, "fixture carries exactly three vectors");
    let names: Vec<&str> = vectors.iter().map(|v| sfield(v, "name")).collect();
    assert_eq!(
        names,
        vec![
            "v1_known_audit_anchor",
            "v2_long_body_uleb_boundary",
            "v3_parent_present",
        ],
        "vector names match the fixture",
    );
}

/// `b1_15_schema_lock` — the schema version and the domain strings are pinned to
/// the fixture, so a silent wire/version/domain drift fails (the "drift requires
/// explicit version bump" madness clause). Also confirms the publish class the
/// vectors use is the only admitted one (#93).
#[test]
fn b1_15_schema_lock() {
    assert_eq!(
        u64::from(STAGE_B_CHUNK_SCHEMA_V1),
        nfield(FIXTURE, "stage_b_chunk_schema_v1"),
        "Stage B chunk schema version is pinned",
    );
    assert_eq!(
        STAGE_B_CHUNK_SCHEMA_V1, 1,
        "schema version 1 (a bump must be deliberate)",
    );
    assert_eq!(
        CHUNK_SIGN_DOMAIN,
        sfield(FIXTURE, "chunk_sign_domain_utf8").as_bytes(),
        "chunk-sign domain matches the fixture",
    );
    assert_eq!(
        AUDIT_ENTRY_DOMAIN,
        sfield(FIXTURE, "audit_entry_domain_utf8").as_bytes(),
        "audit-entry domain matches the fixture",
    );
    // All vectors are SyntheticPublicFixture; that class is admitted, and the
    // closed default policy admits nothing else (#93).
    assert!(
        stage_b_publish_allowed(PublishPayloadClass::SyntheticPublicFixture),
        "the synthetic public fixture class is publishable",
    );
    assert!(
        !stage_b_publish_allowed(PublishPayloadClass::RealUserMemory),
        "real user memory is denied by the default policy",
    );
}

/// `b1_15_all_vectors_match` — the heart of the gate. For every vector, re-derive
/// the header, content hash, chunk digest, blob id, signature, audit entry hash,
/// and canonical wire from the public API and assert each equals the stored
/// golden bytes; then assert the wire decodes back to the same envelope.
#[test]
fn b1_15_all_vectors_match() {
    for obj in vector_objects(FIXTURE) {
        let name = sfield(obj, "name");

        // --- inputs ---
        let content = unhex(sfield(obj, "content_hex"));
        let owner = SuiAddress::new(unhex32(sfield(obj, "owner_hex")));
        let seed = unhex32(sfield(obj, "signing_seed_hex"));
        let flags_u8 = nfield(obj, "flags_u8") as u8;
        let trace = StageBTraceLink::new(
            nfield(obj, "trace_id_u64"),
            nfield(obj, "atom_id_u16") as u16,
            nfield(obj, "attempt_u8") as u8,
        );
        let parent_hex = sfield(obj, "parent_blob_id_hex");
        let parent: Option<BlobId> = if parent_hex.is_empty() {
            None
        } else {
            Some(BlobId(unhex32(parent_hex)))
        };

        // --- header bytes (#84) ---
        let header = StageBChunkHeaderV1::new(
            ChunkKind::UserMessage,
            MemoryRole::User,
            PublishPayloadClass::SyntheticPublicFixture,
            flags_u8,
            content.len() as u32,
            owner,
            parent,
            trace,
        )
        .expect("fixture header is valid");
        assert_eq!(
            header.to_bytes().as_slice(),
            unhex(sfield(obj, "header_hex")).as_slice(),
            "{name}: header bytes match the vector",
        );
        assert_eq!(header.to_bytes().len(), 85, "{name}: header is 85 bytes");

        // --- content hash (#86) ---
        assert_eq!(
            ContentHash32::of(&content).as_bytes().as_slice(),
            unhex(sfield(obj, "content_hash_hex")).as_slice(),
            "{name}: content hash matches the vector",
        );

        // --- envelope + view + digest (#85/#86) ---
        let envelope = ChunkEnvelopeV1 {
            kind: ChunkKind::UserMessage,
            role: MemoryRole::User,
            parent,
            content: content.clone(),
            embedding: None,
            signature: None,
            provenance: None,
        };
        let view = StageBChunkView::new(header, &envelope).expect("body within cap");
        let digest = stage_b_chunk_digest(&view).expect("digest derives");
        assert_eq!(
            digest.as_bytes().as_slice(),
            unhex(sfield(obj, "chunk_digest_hex")).as_slice(),
            "{name}: chunk digest matches the vector",
        );

        // --- signature (#89): RFC8032-deterministic, so a stable golden ---
        let signing = SigningKey::from_bytes(&seed);
        let pubkey = signing.verifying_key().to_bytes();
        assert_eq!(
            pubkey.as_slice(),
            unhex(sfield(obj, "signing_public_key_hex")).as_slice(),
            "{name}: derived public key matches the vector",
        );
        let signature = SignatureBytes(signing.sign(&chunk_sign_preimage(&digest)).to_bytes());
        assert_eq!(
            signature.as_bytes().as_slice(),
            unhex(sfield(obj, "signature_hex")).as_slice(),
            "{name}: signature is the deterministic golden value",
        );

        // The signed chunk mints only if the signature verifies over the
        // recomputed digest under the owner's key (#90 binds digest -> verify).
        let binding =
            OwnerPublicKeyBinding::new(owner, SigningPublicKey::from_bytes(&pubkey).unwrap());
        let signed = StageBSignedChunkV1::new(&view, signature, &binding)
            .expect("valid signature mints a signed chunk");

        // --- blob id (#10) ---
        let witness = unhex(sfield(obj, "blob_witness_hex"));
        assert_eq!(
            derive_blob_id(&witness).as_bytes().as_slice(),
            unhex(sfield(obj, "blob_id_hex")).as_slice(),
            "{name}: derived blob id matches the vector",
        );
        let verified = verified_blob(&witness);
        assert_eq!(
            verified.as_blob_id().as_bytes().as_slice(),
            unhex(sfield(obj, "blob_id_hex")).as_slice(),
            "{name}: verified blob id matches the vector",
        );

        // --- audit entry hash (#95) ---
        assert_eq!(
            stage_b_audit_entry_hash(&signed, &verified).as_slice(),
            unhex32(sfield(obj, "audit_entry_hash_hex")).as_slice(),
            "{name}: audit entry hash matches the vector",
        );

        // --- canonical wire (#91 encode / #92 decode round-trip) ---
        let encoded = encode_stage_b_chunk(&envelope).expect("encode succeeds");
        assert_eq!(
            encoded.as_slice(),
            unhex(sfield(obj, "encoded_chunk_hex")).as_slice(),
            "{name}: canonical wire matches the vector",
        );
        let decoded = decode_stage_b_chunk(&encoded).expect("decode succeeds");
        assert_eq!(
            decoded, envelope,
            "{name}: wire round-trips to the envelope"
        );
    }
}

/// `b1_15_noncanonical_reject` — the G-B-CHUNK-SCHEMA "noncanonical reject"
/// facet. A trailing byte appended to a vector's canonical wire must be rejected
/// by `decode_stage_b_chunk` (Stage A's `TrailingBytes` reject, reused not
/// reinvented — atom #92), so the vectors define *exactly* the canonical bytes
/// and nothing longer decodes to the same chunk.
#[test]
fn b1_15_noncanonical_reject() {
    let first = vector_objects(FIXTURE)
        .into_iter()
        .next()
        .expect("at least one vector");
    let mut wire = unhex(sfield(first, "encoded_chunk_hex"));
    // The canonical wire itself decodes.
    assert!(
        decode_stage_b_chunk(&wire).is_ok(),
        "the canonical vector wire decodes",
    );
    // One trailing byte makes it non-canonical → reject.
    wire.push(0x00);
    assert!(
        decode_stage_b_chunk(&wire).is_err(),
        "a trailing byte is rejected (non-canonical)",
    );
}
