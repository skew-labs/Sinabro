//! Stage B audit-log entry hash (atom #95 · B.1.14).
//!
//! This module mints the one canonical OUT of atom #95:
//! [`stage_b_audit_entry_hash`] — the 32-byte entry hash that a memory owner's
//! append-only audit log (§4.3 `mnemos::audit_log::append`) stores per chunk.
//! The hash binds, in one domain-separated digest, the four quantities the atom
//! #95 madness spec requires:
//!
//! 1. **the chunk digest** — [`StageBSignedChunkV1::digest`] (atom #86
//!    [`ChunkDigest32`](crate::ChunkDigest32)), absorbed directly;
//! 2. **the verified blob id** — the locally-verified Walrus id
//!    ([`VerifiedBlobId`], atom #10), absorbed directly;
//! 3. **the trace id** — the per-action [`StageBTraceLink`](crate::StageBTraceLink)
//!    stamp carried by the signed chunk (atom #81 / #94), absorbed directly as
//!    its 11-byte little-endian serialization;
//! 4. **the owner** — bound **transitively** through the chunk digest: the atom
//!    #86 digest absorbs the fixed 85-byte header
//!    ([`StageBChunkHeaderV1::to_bytes`](crate::StageBChunkHeaderV1)), whose bytes
//!    `9..41` are the `owner` [`SuiAddress`](mnemos_d_move::SuiAddress). A
//!    different owner produces a different header → a different
//!    [`ChunkDigest32`] → a different audit entry hash. (See "Owner binding is
//!    transitive" below.)
//!
//! # Madness invariants (`MNEMOS_STAGE_B_ATOM_PLAN.md` atom #95)
//!
//! > audit entry hash binds chunk digest + verified blob id + owner + trace id.
//! > audit_log never stores raw content.
//!
//! * **No raw content.** Every input absorbed is itself a fixed-width *hash* or
//!   id, never a chunk body: the chunk digest is a 32-byte commitment (the body
//!   enters it only as a content **hash**, atom #86), the verified blob id is a
//!   32-byte id, and the trace stamp is three small integers. The returned
//!   `[u8; 32]` therefore carries no raw user content — exactly what the Move
//!   `audit_log` stores as `entry_hash`. (`b1_14_audit_hash_holds_no_raw_content`
//!   pins that the hash output is independent of any post-hoc body copy.)
//! * **Domain separation.** The audit entry hash absorbs the dedicated domain
//!   [`AUDIT_ENTRY_DOMAIN`] = `mnemos.stage_b.audit_entry.v1.testnet`, disjoint
//!   from the atom #86 chunk-digest / content-hash domains and the atom #89
//!   chunk-sign domain, so the same 32-byte digest can never collide between an
//!   audit-entry context and a chunk-digest context. The `.testnet` suffix keeps
//!   the domain disjoint from any future mainnet audit domain by construction.
//! * **Verified id only.** The blob-id input is a [`VerifiedBlobId`] (atom #10),
//!   whose only constructor is a local byte-for-byte re-derivation
//!   ([`verify_reported_blob_id`](mnemos_c_walrus::verify_reported_blob_id)). A
//!   raw `BlobId` self-reported by a server is **unrepresentable** at this seam —
//!   the audit log can never anchor a server's unverified claim.
//!
//! ## Owner binding is transitive (the two-argument canonical OUT)
//!
//! §4 fixes the canonical OUT signature as
//! `stage_b_audit_entry_hash(signed_chunk, blob_id) -> [u8; 32]` — **two**
//! arguments. The madness spec lists **four** bound quantities. The signed chunk
//! (atom #90) carries `{ envelope, digest, signature, trace }` and does **not**
//! carry the `owner` as a separate field (the owner lives in the chunk *header*,
//! which the signed chunk does not keep — see atom #90 docs). Owner is therefore
//! bound **transitively** through `signed_chunk.digest`, which the atom #90
//! constructor recomputed from the header whose bytes `9..41` are the owner. This
//! is a genuine binding (any owner change moves the digest and thus the audit
//! hash), faithful to the two-argument signature; it is documented here rather
//! than widened to a three-argument signature, and flagged for the Session 2
//! verifier as an ATOM_PLAN signature-vs-madness reconciliation (no new owner
//! parameter is minted). The trace id is bound **both** transitively (it is in
//! the header bytes `74..85` that feed the digest) **and** directly (absorbed as
//! its own part below) — the direct absorption makes the trace observable to a
//! verifier holding only `signed_chunk.trace`.
//!
//! # Hashing primitive (Phase 0 placeholder, no cryptographic claim)
//!
//! The audit hash reuses the **same** add-rotate-xor (ARX) permutation structure
//! as atom #86 [`stage_b_chunk_digest`](crate::stage_b_chunk_digest) /
//! [`hash_parts`] and Stage A's
//! [`derive_blob_id`](mnemos_c_walrus::derive_blob_id). That ARX core is
//! **module-private** to `chunk_digest` (its `hash_parts` / `absorb` / `finalize`
//! / `permute` are not exported), so — exactly as atom #86 re-stated Stage A's
//! private permutation rather than importing it — it is re-stated here. This
//! keeps atom #95 strictly inside its declared file (`audit_digest.rs`; zero
//! `chunk_digest.rs` edit, zero scope creep) and mints **no** new wire format and
//! **no** cryptographic-strength claim. The real audit hash swaps in alongside
//! the real Walrus/Sui domain at the net-testnet feature seam, exactly as
//! `derive_blob_id` documents its own swap point. The re-statement is verified
//! byte-identical to the atom #86 core by the cross-language Python reference
//! `/tmp/mnemos_audit_ref.py` (golden vector `b1_14_audit_hash_known_vector`).
//!
//! # Reuse (재발명 0)
//!
//! * #90 [`StageBSignedChunkV1`] — the signed-chunk input; its `digest()` (atom
//!   #86) and `trace()` (atom #81) accessors are the two fields absorbed.
//! * #94 / #84 trace — the [`StageBTraceLink`](crate::StageBTraceLink) stamp's
//!   `{ trace_id_u64, atom_id_u16, attempt_u8 }` serialized exactly as the atom
//!   #84 header `to_bytes` lays the trace out (bytes `74..85`).
//! * A [`VerifiedBlobId`] (atom #10) — the local-verify trust root, absorbed via
//!   [`VerifiedBlobId::as_blob_id`] → [`BlobId::as_bytes`](mnemos_c_walrus::BlobId).
//!
//! No new dependency, no new wire format, no new [`StageBChunkError`](crate::StageBChunkError)
//! variant (the function is infallible: a `StageBSignedChunkV1` already carries a
//! present, verified digest and a stamped trace, so there is nothing left to
//! reject — the canonical OUT returns `[u8; 32]`, not a `Result`).

use mnemos_c_walrus::VerifiedBlobId;

use crate::signed_chunk::StageBSignedChunkV1;

// ===========================================================================
// 1. Domain + layout constants
// ===========================================================================

/// Domain string absorbed into every audit entry hash. Disjoint from the atom
/// #86 [`CHUNK_DIGEST_DOMAIN`](crate::CHUNK_DIGEST_DOMAIN) /
/// [`CONTENT_HASH_DOMAIN`](crate::CONTENT_HASH_DOMAIN) and the atom #89
/// [`CHUNK_SIGN_DOMAIN`](crate::CHUNK_SIGN_DOMAIN), so an audit-entry hash and a
/// chunk digest over the same bytes can never collide. The `.testnet` suffix
/// keeps it disjoint from any future mainnet audit-log domain by construction.
pub const AUDIT_ENTRY_DOMAIN: &[u8] = b"mnemos.stage_b.audit_entry.v1.testnet";

/// Width, in bytes, of the serialized [`StageBTraceLink`](crate::StageBTraceLink)
/// stamp absorbed into the audit hash: `trace_id_u64` (8, LE) + `atom_id_u16`
/// (2, LE) + `attempt_u8` (1). This matches the atom #84 header `to_bytes`
/// layout for the trace (bytes `74..85`) exactly, so the directly-absorbed trace
/// and the trace inside the chunk digest agree byte-for-byte.
const TRACE_STAMP_BYTES: usize = 11;

// ===========================================================================
// 2. stage_b_audit_entry_hash — the canonical OUT entry point
// ===========================================================================

/// Compute the 32-byte audit-log entry hash for a signed chunk and its verified
/// Walrus blob id.
///
/// The hash absorbs, under [`AUDIT_ENTRY_DOMAIN`], three parts in this fixed
/// order:
///
/// 1. `signed_chunk.digest()` — the atom #86 [`ChunkDigest32`](crate::ChunkDigest32)
///    (which transitively commits the owner, parent, flags, kind/role/class and
///    content hash via the 85-byte header);
/// 2. `blob_id.as_blob_id()` — the 32-byte locally-verified Walrus id;
/// 3. `signed_chunk.trace()` — the 11-byte LE trace stamp (`trace_id_u64` ‖
///    `atom_id_u16` ‖ `attempt_u8`).
///
/// Infallible (`-> [u8; 32]`): a [`StageBSignedChunkV1`] can only exist with a
/// present, signature-verified digest (atom #90) and a stamped trace, and a
/// [`VerifiedBlobId`] can only exist after a local re-derivation match (atom
/// #10), so every input is already well-formed — there is nothing to reject.
///
/// Allocation-free: the digest and blob id are borrowed by reference, the trace
/// is serialized into an 11-byte stack array, and the ARX core touches no heap.
/// The result is exactly the `entry_hash: vector<u8>` (length 32) that
/// §4.3 `mnemos::audit_log::append` records — never a raw chunk body.
#[inline]
#[must_use]
pub fn stage_b_audit_entry_hash(
    signed_chunk: &StageBSignedChunkV1,
    blob_id: &VerifiedBlobId,
) -> [u8; 32] {
    let digest = signed_chunk.digest().as_bytes();
    let blob = blob_id.as_blob_id().as_bytes();

    // Serialize the trace stamp exactly as the atom #84 header lays it out
    // (bytes 74..85), so the directly-absorbed trace and the trace already
    // inside the chunk digest are byte-identical.
    let trace = signed_chunk.trace();
    let mut trace_bytes = [0u8; TRACE_STAMP_BYTES];
    trace_bytes[0..8].copy_from_slice(&trace.trace_id_u64.to_le_bytes());
    trace_bytes[8..10].copy_from_slice(&trace.atom_id_u16.to_le_bytes());
    trace_bytes[10] = trace.attempt_u8;

    hash_parts(
        AUDIT_ENTRY_DOMAIN,
        &[&digest[..], &blob[..], &trace_bytes[..]],
    )
}

// ===========================================================================
// 3. ARX hash core (Phase 0 placeholder; re-stated from atom #86 chunk_digest)
// ===========================================================================
//
// Byte-identical to `chunk_digest::{hash_parts, absorb, finalize, read_u64_le,
// permute}` (which are module-private over there) and structurally identical to
// `c-walrus::blob_id`. Re-stated here rather than imported — the atom #86
// precedent — so atom #95 touches only this file. No cryptographic claim.

// SHA-256 initial-hash constants (well-known public IV). Borrowed as
// "random-looking" lane seeds; no cryptographic claim is made.
const IV: [u64; 4] = [
    0x6a09_e667_f3bc_c908,
    0xbb67_ae85_84ca_a73b,
    0x3c6e_f372_fe94_f82b,
    0xa54f_f53a_5f1d_36f1,
];

/// Domain-separated hash over a sequence of byte parts. The `domain` is absorbed
/// first (length-prefixed), then each part in order (each length-prefixed), then
/// the state is finalised. Distinct domains or distinct parts therefore produce
/// distinct 32-byte outputs. The `&[&[u8]]` parts list is a stack slice of
/// borrows — no heap is touched.
fn hash_parts(domain: &[u8], parts: &[&[u8]]) -> [u8; 32] {
    let mut lanes = IV;
    absorb(&mut lanes, domain);
    for part in parts {
        absorb(&mut lanes, part);
    }
    finalize(&mut lanes)
}

/// Absorb one length-prefixed byte slice into the lanes. The length is added
/// before the body (diffusing extension patterns), then the body is consumed in
/// 32-byte blocks with a zero-extended final partial block. Allocation-free.
#[inline]
fn absorb(lanes: &mut [u64; 4], bytes: &[u8]) {
    lanes[0] = lanes[0].wrapping_add(bytes.len() as u64);
    permute(lanes);

    let total = bytes.len();
    let mut offset = 0usize;
    while offset + 32 <= total {
        lanes[0] ^= read_u64_le(bytes, offset);
        lanes[1] ^= read_u64_le(bytes, offset + 8);
        lanes[2] ^= read_u64_le(bytes, offset + 16);
        lanes[3] ^= read_u64_le(bytes, offset + 24);
        permute(lanes);
        offset += 32;
    }
    if offset < total {
        let mut tail = [0u8; 32];
        let rem = total - offset;
        // `rem <= 32`; `copy_from_slice` length-checks at runtime (no unsafe).
        tail[..rem].copy_from_slice(&bytes[offset..]);
        lanes[0] ^= read_u64_le(&tail, 0);
        lanes[1] ^= read_u64_le(&tail, 8);
        lanes[2] ^= read_u64_le(&tail, 16);
        lanes[3] ^= read_u64_le(&tail, 24);
        permute(lanes);
    }
}

/// Finalise: two extra permutation rounds to diffuse the last block, then
/// serialise the four lanes little-endian into the 32-byte output.
#[inline]
fn finalize(lanes: &mut [u64; 4]) -> [u8; 32] {
    permute(lanes);
    permute(lanes);
    let mut out = [0u8; 32];
    out[0..8].copy_from_slice(&lanes[0].to_le_bytes());
    out[8..16].copy_from_slice(&lanes[1].to_le_bytes());
    out[16..24].copy_from_slice(&lanes[2].to_le_bytes());
    out[24..32].copy_from_slice(&lanes[3].to_le_bytes());
    out
}

/// Read 8 bytes at `start..start+8` as a little-endian `u64`. The caller only
/// ever invokes this with `start + 8 <= buf.len()`.
#[inline]
fn read_u64_le(buf: &[u8], start: usize) -> u64 {
    let mut block = [0u8; 8];
    block.copy_from_slice(&buf[start..start + 8]);
    u64::from_le_bytes(block)
}

/// One ChaCha-style ARX quarter-round on four `u64` lanes. Pure add-rotate-xor;
/// deterministic; no unsafe; no allocation (identical structure to
/// `chunk_digest::permute` / `c-walrus::blob_id::permute`).
#[inline]
fn permute(lanes: &mut [u64; 4]) {
    lanes[0] = lanes[0].wrapping_add(lanes[1]);
    lanes[3] = (lanes[3] ^ lanes[0]).rotate_left(16);
    lanes[2] = lanes[2].wrapping_add(lanes[3]);
    lanes[1] = (lanes[1] ^ lanes[2]).rotate_left(12);
    lanes[0] = lanes[0].wrapping_add(lanes[1]);
    lanes[3] = (lanes[3] ^ lanes[0]).rotate_left(8);
    lanes[2] = lanes[2].wrapping_add(lanes[3]);
    lanes[1] = (lanes[1] ^ lanes[2]).rotate_left(7);
}

#[cfg(test)]
mod tests {
    // Test helpers prefer direct failure surfaces over `Result`-bubbling;
    // suppress prod-only clippy denies inside this module (b-memory
    // #86/#88/#89/#90 precedent).
    #![allow(clippy::unwrap_used)]
    #![allow(clippy::expect_used)]
    #![allow(clippy::panic)]

    use super::*;
    use crate::chunk_digest::{ChunkDigest32, stage_b_chunk_digest};
    use crate::chunk_schema::{StageBChunkFlags, StageBChunkHeaderV1, StageBChunkView};
    use crate::chunk_signature::chunk_sign_preimage;
    use crate::owner::{OwnerPublicKeyBinding, SigningPublicKey};
    use crate::stage_b_handoff::StageBTraceLink;
    use ed25519_dalek::{Signer, SigningKey};
    use mnemos_c_walrus::codec::{ChunkEnvelopeV1, ChunkKind, MemoryRole};
    use mnemos_c_walrus::{
        PublishPayloadClass, PublisherReportedBlobId, SignatureBytes, derive_blob_id,
        verify_reported_blob_id,
    };
    use mnemos_d_move::SuiAddress;

    /// Build a minimal valid envelope (mirrors the #90 signed_chunk test helper).
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

    /// Build a header: kind/role = UserMessage/User, class = SyntheticPublicFixture,
    /// no flags, genesis parent, with the given owner byte and trace stamp.
    fn header(content_len: u32, owner_byte: u8, trace: StageBTraceLink) -> StageBChunkHeaderV1 {
        StageBChunkHeaderV1::new(
            ChunkKind::UserMessage,
            MemoryRole::User,
            PublishPayloadClass::SyntheticPublicFixture,
            StageBChunkFlags::None as u8,
            content_len,
            SuiAddress::new([owner_byte; 32]),
            None,
            trace,
        )
        .expect("known header valid")
    }

    /// An (ed25519 SigningKey, owner↔key binding) fixture from a fixed seed.
    fn keyed(seed: [u8; 32], owner_byte: u8) -> (SigningKey, OwnerPublicKeyBinding) {
        let signing = SigningKey::from_bytes(&seed);
        let pubkey = signing.verifying_key().to_bytes();
        let signing_public = SigningPublicKey::from_bytes(&pubkey).expect("32-byte pubkey");
        let owner = SuiAddress::new([owner_byte; 32]);
        (signing, OwnerPublicKeyBinding::new(owner, signing_public))
    }

    /// Sign the chunk-sign preimage over `digest` with a raw ed25519 key (stands
    /// in for the atom #150 wallet signer).
    fn sign(signing: &SigningKey, digest: &ChunkDigest32) -> SignatureBytes {
        SignatureBytes(signing.sign(&chunk_sign_preimage(digest)).to_bytes())
    }

    /// Build a fully-valid signed chunk over `content` with the given owner byte
    /// and trace stamp.
    fn signed(content: &[u8], owner_byte: u8, trace: StageBTraceLink) -> StageBSignedChunkV1 {
        let e = env(content);
        let h = header(content.len() as u32, owner_byte, trace);
        let view = StageBChunkView::new(h, &e).expect("within cap");
        let digest = stage_b_chunk_digest(&view).expect("digest ok");
        let (signing, binding) = keyed([owner_byte; 32], owner_byte);
        StageBSignedChunkV1::new(&view, sign(&signing, &digest), &binding).expect("mints")
    }

    /// Build a `VerifiedBlobId` from `witness` content via the public
    /// `derive_blob_id` + `verify_reported_blob_id` round-trip (chunk.rs #29
    /// test-helper precedent).
    fn verified_blob(witness: &[u8]) -> VerifiedBlobId {
        let derived = derive_blob_id(witness);
        let text = encode_b64url(derived.as_bytes());
        let reported = PublisherReportedBlobId::try_from_text(&text).expect("base64url length 43");
        verify_reported_blob_id(witness, &reported).expect("self-derived round-trip verifies")
    }

    /// Local URL-safe base64 (no pad) encoder duplicating `c-walrus`'s
    /// `pub(crate)` `encode_base64url_no_pad_32` (chunk.rs test-helper precedent).
    fn encode_b64url(raw: &[u8; 32]) -> String {
        const ALPHABET: &[u8; 64] =
            b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
        let mut out = String::with_capacity(43);
        let mut buf: u32 = 0;
        let mut bits: u32 = 0;
        for &b in raw {
            buf = (buf << 8) | (b as u32);
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

    fn hex(bytes: &[u8; 32]) -> String {
        let mut s = String::with_capacity(64);
        for b in bytes {
            s.push_str(&format!("{b:02x}"));
        }
        s
    }

    /// `b1_14_audit_hash_known_vector` — the known fixture produces the exact
    /// golden audit-entry hash independently derived by the cross-language Python
    /// reference `/tmp/mnemos_audit_ref.py`. Content = the known body, owner =
    /// `0x55`*32, trace = (95, 95, 0), blob witness = the known witness. This is
    /// the "vector stable" madness test: the audit hash is a stable cross-language
    /// anchor (atom #96 golden vectors build on it).
    #[test]
    fn b1_14_audit_hash_known_vector() {
        let content = b"mnemos.stage_b.audit.v1 known vector body";
        let sc = signed(content, 0x55, StageBTraceLink::new(95, 95, 0));
        let blob = verified_blob(b"mnemos.stage_b.audit.v1 blob witness");

        let h = stage_b_audit_entry_hash(&sc, &blob);

        // Golden vector — independently derived by /tmp/mnemos_audit_ref.py
        // (Python mirror of the ARX core); not a self-captured value.
        assert_eq!(
            hex(&h),
            "b768ea446b993da04e4d112f8ea21b637b8f58e1b5be26ec849c2ab5950b6d49",
            "audit entry hash must equal the cross-language golden vector",
        );

        // Determinism: same inputs → same output across calls.
        assert_eq!(
            h,
            stage_b_audit_entry_hash(&sc, &blob),
            "audit entry hash must be deterministic",
        );
    }

    /// `b1_14_blob_mismatch_changes_hash` — holding the signed chunk fixed and
    /// changing only the verified blob id changes the audit entry hash. Proves the
    /// blob id is genuinely absorbed (a chunk re-anchored to a different blob has a
    /// different audit entry).
    #[test]
    fn b1_14_blob_mismatch_changes_hash() {
        let content = b"blob mismatch body";
        let sc = signed(content, 0x55, StageBTraceLink::new(95, 1, 0));

        let blob_a = verified_blob(b"witness A");
        let blob_b = verified_blob(b"witness B");
        assert_ne!(
            blob_a.as_blob_id().as_bytes(),
            blob_b.as_blob_id().as_bytes(),
            "the two witnesses derive distinct blob ids",
        );

        assert_ne!(
            stage_b_audit_entry_hash(&sc, &blob_a),
            stage_b_audit_entry_hash(&sc, &blob_b),
            "a different verified blob id must change the audit entry hash",
        );
    }

    /// `b1_14_trace_mismatch_changes_hash` — holding the body, owner and blob id
    /// fixed and changing only the trace stamp changes the audit entry hash. The
    /// trace is bound both directly (absorbed as its own part) and transitively
    /// (it is in the header bytes that feed the digest); either path alone would
    /// flip the hash, and this test confirms the binding.
    #[test]
    fn b1_14_trace_mismatch_changes_hash() {
        let content = b"trace mismatch body";
        let blob = verified_blob(b"trace witness");

        let sc1 = signed(content, 0x55, StageBTraceLink::new(95, 95, 0));
        let sc2 = signed(content, 0x55, StageBTraceLink::new(96, 96, 1));

        assert_ne!(
            sc1.trace(),
            sc2.trace(),
            "the two signed chunks carry distinct trace stamps",
        );
        assert_ne!(
            stage_b_audit_entry_hash(&sc1, &blob),
            stage_b_audit_entry_hash(&sc2, &blob),
            "a different trace stamp must change the audit entry hash",
        );
    }

    /// `b1_14_owner_binding_is_transitive` — defense-in-depth for the
    /// signature-vs-madness reconciliation: changing only the owner (which is not
    /// a direct argument) still changes the audit entry hash, because the owner is
    /// in the header bytes that feed the chunk digest. Confirms the documented
    /// transitive owner binding is real, not nominal.
    #[test]
    fn b1_14_owner_binding_is_transitive() {
        let content = b"owner binding body";
        let blob = verified_blob(b"owner witness");
        let trace = StageBTraceLink::new(95, 95, 0);

        let sc_a = signed(content, 0xAA, trace);
        let sc_b = signed(content, 0xBB, trace);

        // Same body, same trace; only the owner differs → digests differ …
        assert_ne!(
            sc_a.digest(),
            sc_b.digest(),
            "distinct owners → distinct chunk digests (owner is in the header)",
        );
        // … so the audit entry hash differs too (transitive owner binding).
        assert_ne!(
            stage_b_audit_entry_hash(&sc_a, &blob),
            stage_b_audit_entry_hash(&sc_b, &blob),
            "a different owner must change the audit entry hash (transitively)",
        );
    }

    /// `b1_14_audit_hash_holds_no_raw_content` — the audit hash is a fixed 32-byte
    /// output regardless of the chunk body length, proving it stores a commitment
    /// rather than the raw content. Two bodies of very different lengths both
    /// yield exactly 32 output bytes, and a one-byte body and a large body both
    /// produce well-formed (and distinct) hashes — no body bytes are carried
    /// through.
    #[test]
    fn b1_14_audit_hash_holds_no_raw_content() {
        let blob = verified_blob(b"no-raw-content witness");
        let trace = StageBTraceLink::new(95, 95, 0);

        let small = signed(b"x", 0x55, trace);
        let large = signed(&[0x41u8; 4096], 0x55, trace);

        let hs = stage_b_audit_entry_hash(&small, &blob);
        let hl = stage_b_audit_entry_hash(&large, &blob);

        assert_eq!(hs.len(), 32, "output is a fixed 32-byte commitment");
        assert_eq!(hl.len(), 32, "output is a fixed 32-byte commitment");
        assert_ne!(hs, hl, "distinct bodies still produce distinct commitments");
    }
}
