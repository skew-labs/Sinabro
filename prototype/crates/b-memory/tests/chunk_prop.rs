//! Stage B chunk schema property + fuzz suite (atom #97 · B.1.16).
//!
//! The §4.1 canonical OUT for atom #97 is an **encode / decode / signature
//! property suite** over the Stage B canonical codec. It consumes the canonical
//! OUTs of #91 [`encode_stage_b_chunk`](mnemos_b_memory::encode_stage_b_chunk),
//! #92 [`decode_stage_b_chunk`](mnemos_b_memory::decode_stage_b_chunk) and #93
//! [`stage_b_publish_allowed`](mnemos_b_memory::stage_b_publish_allowed) verbatim
//! (reuse: #92, #93) — it mints **no** production code (zero `src/` change) and
//! adds **no** dependency (`proptest` and `ed25519-dalek` are already b-memory
//! dev-/normal-deps since atoms #32 / #89).
//!
//! # Madness invariants (`MNEMOS_STAGE_B_ATOM_PLAN.md` atom #97)
//!
//! > arbitrary valid chunks round-trip; arbitrary bytes never panic; invalid
//! > class never publish-plans.
//!
//! The three plan test-list items are realised as proptest properties:
//!
//! * **proptest roundtrip** — [`prop_valid_envelope_roundtrip`]: for any valid
//!   [`ChunkEnvelopeV1`] (arbitrary kind / role / parent / body), `decode(encode(x)) == x`
//!   and the re-encode is byte-stable.
//! * **fuzz no panic** — [`prop_arbitrary_bytes_never_panic`]: for any input
//!   bytes, `decode_stage_b_chunk` returns `Ok | Err` and never panics; and any
//!   **accepted** bytes are canonical (`encode(decode(b)) == b`), proving Stage
//!   A's non-canonical reject is in force. The coverage-guided libFuzzer mirror
//!   lives in `fuzz/fuzz_targets/chunk_decode.rs` (deferred run — see that file).
//! * **invalid class property** — [`prop_invalid_class_never_publishes`]: across
//!   the full [`PublishPayloadClass`] set, `stage_b_publish_allowed(c)` is `true`
//!   iff `c == SyntheticPublicFixture`; every other class is denied fail-closed.
//!
//! A light **signature** property ([`prop_signature_roundtrip`]) rounds out the
//! "signature property suite" clause: a real ed25519 signature over the
//! domain-separated digest verifies, and a single-byte-tampered signature is
//! rejected. The exhaustive wrong-owner / wrong-domain / wrong-content /
//! wrong-parent / wrong-trace / wrong-network *confusion matrix* is the dedicated
//! scope of atom #99 (`tests/signature_matrix.rs`) and is **not** duplicated here.
//!
//! # G-B-MIRI (real run, this machine)
//!
//! [`miri_parser_byte_sweep_no_panic_and_canonical`] is a deterministic,
//! I/O-free, RNG-free, crypto-free byte sweep over the parser / byte hot path
//! (the #92 `splitmix64` precedent). It is the G-B-MIRI target: miri is present
//! on this machine (verified `cargo +nightly miri --version`, sysroot built), so
//! the gate is run for real — `cargo +nightly miri test --test chunk_prop
//! miri_parser_byte_sweep`. It is deliberately separate from the proptest block
//! because proptest seeds its RNG from the OS (`getrandom`), which miri's default
//! isolation blocks; the deterministic sweep needs no such syscall.

// Test code prefers direct failure surfaces (`expect` / `unwrap` / `assert`) over
// `Result`-bubbling; suppress the prod-only clippy denies for this test crate
// (b-memory #86 / #88 / #89 / #90 / #95 / #96 unit/integration-test precedent).
#![allow(clippy::unwrap_used)]
#![allow(clippy::expect_used)]
#![allow(clippy::panic)]

use ed25519_dalek::{Signer, SigningKey};
use mnemos_b_memory::{
    OwnerPublicKeyBinding, SigningPublicKey, StageBChunkFlags, StageBChunkHeaderV1,
    StageBChunkView, StageBTraceLink, chunk_sign_preimage, decode_stage_b_chunk,
    encode_stage_b_chunk, stage_b_chunk_digest, stage_b_publish_allowed, verify_stage_b_chunk,
};
use mnemos_c_walrus::codec::{BlobId, ChunkEnvelopeV1, ChunkKind, MemoryRole};
use mnemos_c_walrus::{PublishPayloadClass, SignatureBytes};
use mnemos_d_move::SuiAddress;
use proptest::prelude::*;

// ===========================================================================
// Strategies
// ===========================================================================

/// A strategy producing **valid** minimal envelopes: arbitrary kind (1..=5),
/// role (1..=5), optional 32-byte parent blob id, and a body up to 2 KiB. The
/// embedding / signature / provenance options stay `None` (the codec's own
/// minimal-valid-envelope lane, atoms #91 / #92 / #86); their `Some` variants are
/// exercised by c-walrus's own codec proptest and are out of scope here (see
/// `no_op_decisions.jsonl`). 2 KiB stays well under both Stage A's 13 MB
/// `MAX_CONTENT_BYTES` and the 1 MiB `MAX_STAGE_B_CONTENT_BYTES`, so every
/// produced envelope encodes successfully.
fn valid_envelope() -> impl Strategy<Value = ChunkEnvelopeV1> {
    (
        1u8..=5u8,
        1u8..=5u8,
        proptest::option::of(any::<[u8; 32]>()),
        proptest::collection::vec(any::<u8>(), 0..2048),
    )
        .prop_map(|(kind_tag, role_tag, parent, content)| ChunkEnvelopeV1 {
            kind: ChunkKind::from_tag(kind_tag).expect("kind tag in 1..=5"),
            role: MemoryRole::from_tag(role_tag).expect("role tag in 1..=5"),
            parent: parent.map(BlobId),
            content,
            embedding: None,
            signature: None,
            provenance: None,
        })
}

/// A strategy over the full [`PublishPayloadClass`] variant set (the Stage A
/// `#[non_exhaustive]` enum's six current classes).
fn any_publish_class() -> impl Strategy<Value = PublishPayloadClass> {
    prop_oneof![
        Just(PublishPayloadClass::SyntheticPublicFixture),
        Just(PublishPayloadClass::RealUserMemory),
        Just(PublishPayloadClass::PromptOrProviderText),
        Just(PublishPayloadClass::ToolOutput),
        Just(PublishPayloadClass::SecretLike),
        Just(PublishPayloadClass::PrivateProvenance),
    ]
}

// ===========================================================================
// G-B-PROPTEST — the property suite
// ===========================================================================

proptest! {
    // No on-disk failure-persistence file: keep the test crate hermetic (no
    // `proptest-regressions/` artifact written under any run).
    #![proptest_config(ProptestConfig { failure_persistence: None, cases: 256, ..ProptestConfig::default() })]

    /// **proptest roundtrip.** Any valid envelope encodes, decodes back to the
    /// exact original, and the re-encode of the decoded value is byte-identical
    /// (canonical, stable wire).
    #[test]
    fn prop_valid_envelope_roundtrip(e in valid_envelope()) {
        let wire = encode_stage_b_chunk(&e).expect("valid envelope encodes");
        let back = decode_stage_b_chunk(&wire).expect("valid wire decodes");
        prop_assert_eq!(&back, &e, "decode(encode(x)) == x");

        let wire2 = encode_stage_b_chunk(&back).expect("re-encode");
        prop_assert_eq!(wire2, wire, "re-encode is byte-stable");
    }

    /// **fuzz no panic.** Decoding arbitrary bytes never panics — the call
    /// returns `Ok | Err`. And any bytes that *do* decode are canonical:
    /// re-encoding the decoded envelope reproduces the input exactly (Stage A's
    /// non-canonical / trailing-byte reject guarantees the accepted set is the
    /// canonical set). A proptest body that panicked would fail the test, so
    /// reaching the end of every case *is* the no-panic assertion.
    #[test]
    fn prop_arbitrary_bytes_never_panic(bytes in proptest::collection::vec(any::<u8>(), 0..4096)) {
        if let Ok(env) = decode_stage_b_chunk(&bytes) {
            let re = encode_stage_b_chunk(&env).expect("accepted bytes re-encode");
            prop_assert_eq!(re, bytes, "accepted bytes are canonical (encode∘decode == id)");
        }
    }

    /// **invalid class property.** Only `SyntheticPublicFixture` may publish;
    /// every other content class is denied fail-closed. Pins the default-deny
    /// posture against a future `#[non_exhaustive]` class addition silently
    /// flipping to admitted.
    #[test]
    fn prop_invalid_class_never_publishes(class in any_publish_class()) {
        let allowed = stage_b_publish_allowed(class);
        prop_assert_eq!(
            allowed,
            class == PublishPayloadClass::SyntheticPublicFixture,
            "publish-allow predicate must match the synthetic-only policy"
        );
        if class != PublishPayloadClass::SyntheticPublicFixture {
            prop_assert!(!allowed, "non-synthetic class must never publish-plan");
        }
    }

    /// **signature property (suite breadth).** A real ed25519 signature over the
    /// domain-separated `CHUNK_SIGN_DOMAIN || digest` preimage verifies under the
    /// owner's bound public key; flipping a single byte of the 64-byte signature
    /// makes it invalid and verify rejects with `SignatureInvalid`. (The full
    /// wrong-owner / wrong-domain / wrong-content confusion matrix is atom #99.)
    #[test]
    fn prop_signature_roundtrip(
        content in proptest::collection::vec(any::<u8>(), 0..1024),
        seed in any::<[u8; 32]>(),
        owner_byte in any::<u8>(),
    ) {
        let e = ChunkEnvelopeV1 {
            kind: ChunkKind::UserMessage,
            role: MemoryRole::User,
            parent: None,
            content: content.clone(),
            embedding: None,
            signature: None,
            provenance: None,
        };
        let owner = SuiAddress::new([owner_byte; 32]);
        let header = StageBChunkHeaderV1::new(
            ChunkKind::UserMessage,
            MemoryRole::User,
            PublishPayloadClass::SyntheticPublicFixture,
            StageBChunkFlags::None as u8,
            content.len() as u32,
            owner,
            None,
            StageBTraceLink::new(97, 97, 0),
        )
        .expect("header valid");
        let view = StageBChunkView::new(header, &e).expect("within Stage B cap");
        let digest = stage_b_chunk_digest(&view).expect("digest");

        let signing = SigningKey::from_bytes(&seed);
        let pubkey = signing.verifying_key().to_bytes();
        let binding = OwnerPublicKeyBinding::new(
            owner,
            SigningPublicKey::from_bytes(&pubkey).expect("32-byte pubkey"),
        );
        let sig = SignatureBytes(signing.sign(&chunk_sign_preimage(&digest)).to_bytes());

        // valid signature verifies ...
        prop_assert!(
            verify_stage_b_chunk(&sig, digest, &binding).is_ok(),
            "valid ed25519 signature verifies"
        );
        // ... single-byte tamper is rejected.
        let mut bad = sig;
        bad.0[0] ^= 0xFF;
        prop_assert!(
            verify_stage_b_chunk(&bad, digest, &binding).is_err(),
            "tampered signature rejected"
        );
    }
}

// ===========================================================================
// G-B-MIRI — deterministic parser / byte hot-path sweep (real miri run)
// ===========================================================================

/// std-only deterministic PRNG (the #92 `splitmix64` precedent). No OS RNG, so
/// the sweep runs cleanly under miri's default isolation.
fn splitmix64(state: &mut u64) -> u64 {
    *state = state.wrapping_add(0x9E37_79B9_7F4A_7C15);
    let mut z = *state;
    z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
    z ^ (z >> 31)
}

/// The G-B-MIRI target: a fixed-seed sweep over the codec byte path asserting
/// (a) every valid envelope round-trips, (b) decoding arbitrary bytes never
/// panics and any accepted bytes are canonical, (c) a trailing byte on a valid
/// wire is always rejected. Deterministic and reproducible by Session 2 under
/// both stable and miri.
#[test]
fn miri_parser_byte_sweep_no_panic_and_canonical() {
    let mut s = 0x51A5_2E97_3CD1_0F0Bu64;
    for _ in 0..256 {
        // body_len spans the 1-byte / 2-byte uleb128 length-prefix boundary.
        let body_len = (splitmix64(&mut s) % 300) as usize;
        let body: Vec<u8> = (0..body_len)
            .map(|_| (splitmix64(&mut s) & 0xff) as u8)
            .collect();
        let e = ChunkEnvelopeV1 {
            kind: ChunkKind::UserMessage,
            role: MemoryRole::User,
            parent: None,
            content: body,
            embedding: None,
            signature: None,
            provenance: None,
        };

        // (a) valid round-trip.
        let wire = encode_stage_b_chunk(&e).expect("encode valid");
        let back = decode_stage_b_chunk(&wire).expect("decode valid round-trips");
        assert_eq!(back, e, "round-trip preserves envelope");

        // (b) arbitrary bytes never panic; accepted bytes are canonical.
        let n = (splitmix64(&mut s) % 64) as usize;
        let garbage: Vec<u8> = (0..n).map(|_| (splitmix64(&mut s) & 0xff) as u8).collect();
        if let Ok(env2) = decode_stage_b_chunk(&garbage) {
            assert_eq!(
                encode_stage_b_chunk(&env2).expect("re-encode accepted bytes"),
                garbage,
                "accepted bytes are canonical"
            );
        }

        // (c) trailing byte on a valid wire is always rejected.
        let mut tampered = wire.clone();
        tampered.push((splitmix64(&mut s) & 0xff) as u8);
        assert!(
            decode_stage_b_chunk(&tampered).is_err(),
            "trailing byte on valid wire rejected"
        );
    }
}
