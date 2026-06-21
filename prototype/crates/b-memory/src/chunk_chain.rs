//! Stage B parent chain encoding (atom #87 · B.1.6).
//!
//! Stage A §4.C carries a chunk's parent linkage in three independent places
//! once a Stage B header lenses a Stage A envelope:
//!
//! 1. the [`StageBChunkFlags::HasParent`] bit inside the header's `flags_u8`,
//! 2. the header's own `parent: Option<BlobId>` field, and
//! 3. the borrowed [`ChunkEnvelopeV1::parent`](mnemos_c_walrus::ChunkEnvelopeV1)
//!    `Option<BlobId>`.
//!
//! This module mints the canonical OUT for atom #87: the **parent validation
//! helpers** that hold those three views in agreement. Atom #84's
//! [`StageBChunkHeaderV1::new`] already pins the *header-internal* invariant
//! (flag ⇔ header `parent`); atom #85 deferred — and atom #86 bound only "by
//! inclusion" (the header, parent field and all, is hashed into the digest) —
//! the **cross-binding** of the header's parent against the *borrowed envelope's*
//! parent. Atom #87 closes that gap with [`parent_linkage_consistent`].
//!
//! # Madness invariants (`MNEMOS_STAGE_B_ATOM_PLAN.md` §4.1 / atom #87)
//!
//! * **Parent agreement, three ways.** A chunk view is parent-consistent iff the
//!   `HasParent` flag is set exactly when the header carries a parent, **and** the
//!   header's parent equals the borrowed envelope's parent. A header that claims a
//!   parent the envelope it lenses does not carry (or carries a *different* parent)
//!   is rejected by [`parent_linkage_consistent`].
//! * **Genesis is the no-parent state.** A genesis chunk declares no parent in any
//!   of the three places ([`is_genesis`]); it is the root of an integrity chain.
//! * **Integrity, not order.** Parent provides *integrity linkage only*: it is
//!   bound into the atom #86 [`ChunkDigest32`] through the header bytes, so a
//!   different parent yields a different digest. It does **not** impose a replay
//!   order — these helpers never compare parents against a sequence, never require
//!   a parent to precede a child, and never reject a cycle (replay ordering is the
//!   domain of §4.5's `replay_stage_b`, a later atom). The helpers are pure
//!   predicates over a single view.
//! * **Reject is a predicate, not an invented canonical error.** §4.1's
//!   [`StageBChunkError`](crate::StageBChunkError) variant set
//!   (`ReservedFlags`/`ContentTooLarge`/`SignatureInvalid`/`PublishClassDenied`/
//!   `NonCanonicalAChunk`) is `#[non_exhaustive]` and was minted **verbatim** at
//!   atom #86; it carries no parent-mismatch variant. Minting one here would
//!   extend that frozen set, so the parent reject is expressed as a `bool`
//!   predicate, mirroring the atom #81–#85 reject-as-predicate precedent. A later
//!   atom that owns a chunk-acceptance error surface maps a `false` here onto its
//!   own reject at that boundary.
//!
//! # Reuse map (atom contract)
//!
//! * **reuse: #84 [`StageBChunkHeaderV1`]** — the header carrying the `flags_u8`
//!   `HasParent` bit and the `parent: Option<BlobId>` field.
//! * **reuse: #84 [`StageBChunkFlags::is_set`]** — the flag membership test (no new
//!   flag decoder minted).
//! * **reuse: #85 [`StageBChunkView`]** — the borrowed lens pairing the header with
//!   the Stage A envelope, so the cross-binding can read both without a copy.
//! * **reuse: #86 [`stage_b_chunk_digest`](crate::stage_b_chunk_digest)** — the
//!   digest the parent is bound into (the `b1_6_parent_digest_vector` test pins a
//!   parent-bearing digest and proves a parent change moves it). No new digest is
//!   minted here.

use crate::chunk_schema::{StageBChunkFlags, StageBChunkView};

/// Whether the chunk view declares a parent: the [`StageBChunkFlags::HasParent`]
/// bit is set in the header's `flags_u8`.
///
/// This reads the *flag* only. [`parent_linkage_consistent`] is what proves the
/// flag agrees with the header's and the envelope's `parent` fields; this helper
/// is the cheap "does it claim a parent at all" probe a caller uses before
/// reaching for the blob id.
#[inline]
pub const fn declares_parent(view: &StageBChunkView<'_>) -> bool {
    StageBChunkFlags::is_set(view.header.flags_u8, StageBChunkFlags::HasParent)
}

/// Whether the chunk view is a **genesis** chunk: no parent is declared in any of
/// the three places (the `HasParent` flag is clear, the header `parent` is `None`,
/// and the borrowed envelope `parent` is `None`).
///
/// A genesis chunk is the root of an integrity chain. This is the
/// "no-parent genesis" predicate; it is the complement of a *consistent*
/// parent-bearing chunk, not the complement of [`declares_parent`] alone — a view
/// whose flag is clear but whose envelope still carries a parent is neither a
/// genesis chunk nor consistent.
#[inline]
pub fn is_genesis(view: &StageBChunkView<'_>) -> bool {
    !declares_parent(view) && view.header.parent.is_none() && view.envelope.parent.is_none()
}

/// The atom #87 canonical OUT: validate a chunk view's parent linkage across all
/// three carriers, fail-closed.
///
/// Returns `true` iff **both** invariants hold:
///
/// 1. **Flag ⇔ header parent** (re-affirms atom #84's header-internal invariant;
///    a raw `StageBChunkHeaderV1` struct literal can bypass `new`, so this is
///    re-checked here as defense in depth): the `HasParent` flag is set exactly
///    when `header.parent` is `Some`.
/// 2. **Header parent == envelope parent** (the atom #87 cross-binding, deferred
///    by #85 and bound only by inclusion at #86): the header's parent blob id
///    equals the borrowed envelope's parent. Both `None` (genesis on both sides)
///    agrees; `Some(a)` vs `Some(b)` with `a != b` is rejected; `Some` vs `None`
///    in either direction is rejected.
///
/// This is a pure predicate over the single view. It imposes **no** replay order
/// and performs **no** self-parent / cycle check (integrity only — the madness
/// spec forbids order here). It returns a `bool` rather than a
/// [`StageBChunkError`](crate::StageBChunkError): §4.1's error set is frozen
/// `#[non_exhaustive]` with no parent variant, so the reject stays a predicate
/// (atom #81–#85 precedent).
#[inline]
pub fn parent_linkage_consistent(view: &StageBChunkView<'_>) -> bool {
    // (1) flag ⇔ header parent (header-internal, re-checked against raw literals).
    if declares_parent(view) != view.header.parent.is_some() {
        return false;
    }
    // (2) header parent == envelope parent (the #87 cross-binding). `BlobId`
    //     derives `Eq`, so `Option<BlobId>` equality covers both-None (genesis),
    //     both-Some-equal (consistent child), and every mismatch in one compare.
    view.header.parent == view.envelope.parent
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    #![allow(clippy::expect_used)]
    #![allow(clippy::panic)]

    use super::*;
    use crate::chunk_digest::stage_b_chunk_digest;
    use crate::chunk_schema::{StageBChunkHeaderV1, StageBChunkView};
    use crate::stage_b_handoff::StageBTraceLink;
    use mnemos_c_walrus::PublishPayloadClass;
    use mnemos_c_walrus::codec::{BlobId, ChunkEnvelopeV1, ChunkKind, MemoryRole};
    use mnemos_d_move::SuiAddress;

    /// Build a Stage A envelope with a `len`-byte `0`-filled body, the given
    /// `parent`, and all other optional fields empty.
    fn env(len: usize, parent: Option<BlobId>) -> ChunkEnvelopeV1 {
        ChunkEnvelopeV1 {
            kind: ChunkKind::UserMessage,
            role: MemoryRole::User,
            parent,
            content: vec![0u8; len],
            embedding: None,
            signature: None,
            provenance: None,
        }
    }

    /// Build a header via the validated `new` path: kind/role = UserMessage/User,
    /// class = SyntheticPublicFixture, owner = `0x55`*32, trace = (87, 87, 0),
    /// `flags_u8` and `parent` as given. Panics if `new` rejects (the caller is
    /// responsible for passing a header-internally-consistent flag/parent pair).
    fn header(flags_u8: u8, content_len: u32, parent: Option<BlobId>) -> StageBChunkHeaderV1 {
        StageBChunkHeaderV1::new(
            ChunkKind::UserMessage,
            MemoryRole::User,
            PublishPayloadClass::SyntheticPublicFixture,
            flags_u8,
            content_len,
            SuiAddress::new([0x55; 32]),
            parent,
            StageBTraceLink::new(87, 87, 0),
        )
        .expect("header-internally-consistent inputs")
    }

    /// Hex-decode a 32-byte vector for golden comparisons (mirrors atom #86).
    fn hex32(s: &str) -> [u8; 32] {
        assert_eq!(s.len(), 64, "expected 64 hex chars");
        let mut out = [0u8; 32];
        for (i, byte) in out.iter_mut().enumerate() {
            *byte = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).expect("hex");
        }
        out
    }

    /// `b1_6_no_parent_genesis` — a genesis chunk (flag clear, header parent
    /// `None`, envelope parent `None`) is recognised as genesis and is
    /// parent-consistent; it does not declare a parent.
    #[test]
    fn b1_6_no_parent_genesis() {
        let no_flags = StageBChunkFlags::None as u8;
        let e = env(5, None);
        let h = header(no_flags, 5, None);
        let view = StageBChunkView::new(h, &e).expect("within cap");

        assert!(is_genesis(&view), "no parent anywhere ⇒ genesis");
        assert!(!declares_parent(&view), "genesis declares no parent");
        assert!(
            parent_linkage_consistent(&view),
            "genesis (None == None) is consistent"
        );
    }

    /// `b1_6_parent_flag_mismatch_reject` — every parent-linkage mismatch is
    /// rejected fail-closed: a header claiming a parent the envelope lacks, an
    /// envelope carrying a parent the header lacks, two *different* parents, and
    /// (via a raw struct literal that bypasses `StageBChunkHeaderV1::new`) a flag
    /// that disagrees with the header's own parent field. The matching cases stay
    /// consistent.
    #[test]
    fn b1_6_parent_flag_mismatch_reject() {
        let has_parent = StageBChunkFlags::HasParent as u8;
        let no_flags = StageBChunkFlags::None as u8;
        let p_ab = BlobId([0xAB; 32]);
        let p_cd = BlobId([0xCD; 32]);

        // Consistent child: flag set, header parent == envelope parent.
        let e_ab = env(5, Some(p_ab));
        let h_ab = header(has_parent, 5, Some(p_ab));
        assert!(parent_linkage_consistent(
            &StageBChunkView::new(h_ab, &e_ab).expect("cap")
        ));

        // Header claims parent 0xAB, envelope is genesis ⇒ cross-binding reject.
        let e_none = env(5, None);
        assert!(!parent_linkage_consistent(
            &StageBChunkView::new(h_ab, &e_none).expect("cap")
        ));

        // Header is genesis, envelope carries a parent ⇒ cross-binding reject.
        let h_genesis = header(no_flags, 5, None);
        assert!(!parent_linkage_consistent(
            &StageBChunkView::new(h_genesis, &e_ab).expect("cap")
        ));

        // Two different parents (header 0xAB, envelope 0xCD) ⇒ reject.
        let e_cd = env(5, Some(p_cd));
        assert!(!parent_linkage_consistent(
            &StageBChunkView::new(h_ab, &e_cd).expect("cap")
        ));

        // Flag/header-parent disagreement: `new` would reject this pairing, so we
        // build the header by a raw struct literal to exercise the in-helper
        // re-check (defense in depth against a literal that skips `new`).
        let h_flag_no_parent = StageBChunkHeaderV1 {
            schema_version_u8: crate::chunk_schema::STAGE_B_CHUNK_SCHEMA_V1,
            kind: ChunkKind::UserMessage,
            role: MemoryRole::User,
            content_class: PublishPayloadClass::SyntheticPublicFixture,
            flags_u8: has_parent, // flag set ...
            content_len_u32: 5,
            owner: SuiAddress::new([0x55; 32]),
            parent: None, // ... but no parent field ⇒ inconsistent
            trace: StageBTraceLink::new(87, 87, 0),
        };
        // Pair with a genesis envelope so only the flag/header-parent rule fires.
        assert!(!parent_linkage_consistent(
            &StageBChunkView::new(h_flag_no_parent, &e_none).expect("cap")
        ));
    }

    /// `b1_6_parent_digest_vector` — the parent is bound into the atom #86 chunk
    /// digest (through the header bytes). Pins the golden parent-bearing digest and
    /// the golden genesis digest (both independently derived by
    /// `/tmp/mnemos_parent_ref.py`, whose ARX core self-checks against the atom #86
    /// vector `053d4a27…`), and proves a parent change moves the digest while the
    /// content is held fixed at `b"hello"`.
    #[test]
    fn b1_6_parent_digest_vector() {
        let has_parent = StageBChunkFlags::HasParent as u8;
        let no_flags = StageBChunkFlags::None as u8;
        let p_ab = BlobId([0xAB; 32]);
        let p_cd = BlobId([0xCD; 32]);
        let body = b"hello";

        // Parent-bearing consistent chunk (parent 0xAB, content "hello").
        let e_ab = ChunkEnvelopeV1 {
            kind: ChunkKind::UserMessage,
            role: MemoryRole::User,
            parent: Some(p_ab),
            content: body.to_vec(),
            embedding: None,
            signature: None,
            provenance: None,
        };
        let h_ab = header(has_parent, body.len() as u32, Some(p_ab));
        let v_ab = StageBChunkView::new(h_ab, &e_ab).expect("cap");
        assert!(parent_linkage_consistent(&v_ab));
        let d_ab = stage_b_chunk_digest(&v_ab).expect("digest ok");
        assert_eq!(
            d_ab.as_bytes(),
            &hex32("33bef9abe1ea39d9f03602e2eddc29afd2cdd297b4818f1b59957645077d1bd9"),
            "parent-bearing golden digest (Python-derived, self-checked vs #86)",
        );

        // Genesis chunk, same content, trace (87,87,0): a distinct golden digest.
        let e_g = ChunkEnvelopeV1 {
            kind: ChunkKind::UserMessage,
            role: MemoryRole::User,
            parent: None,
            content: body.to_vec(),
            embedding: None,
            signature: None,
            provenance: None,
        };
        let h_g = header(no_flags, body.len() as u32, None);
        let v_g = StageBChunkView::new(h_g, &e_g).expect("cap");
        let d_g = stage_b_chunk_digest(&v_g).expect("digest ok");
        assert_eq!(
            d_g.as_bytes(),
            &hex32("a84219f4dd21dc08c3ddd79f7a34e4ed69f005a213d3ad2ac3f2aa10f9974249"),
            "genesis golden digest (Python-derived)",
        );

        // Parent is genuinely bound: a different parent (0xCD) moves the digest,
        // and the genesis digest differs from the parent-bearing one.
        let e_cd = ChunkEnvelopeV1 {
            kind: ChunkKind::UserMessage,
            role: MemoryRole::User,
            parent: Some(p_cd),
            content: body.to_vec(),
            embedding: None,
            signature: None,
            provenance: None,
        };
        let h_cd = header(has_parent, body.len() as u32, Some(p_cd));
        let v_cd = StageBChunkView::new(h_cd, &e_cd).expect("cap");
        let d_cd = stage_b_chunk_digest(&v_cd).expect("digest ok");
        assert_ne!(
            d_ab.as_bytes(),
            d_cd.as_bytes(),
            "a different parent must change the digest (integrity binding)",
        );
        assert_ne!(
            d_ab.as_bytes(),
            d_g.as_bytes(),
            "genesis and parent-bearing digests differ",
        );
    }
}
