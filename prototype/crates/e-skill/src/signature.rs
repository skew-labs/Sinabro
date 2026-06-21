//! `mnemos-e-skill::signature` — atom #247 · D.0.6 — the author signature
//! over a skill package.
//!
//! ## Canonical OUT (§4.1 — ATOM_PLAN line 177)
//!
//! - [`SkillPackageSignature`] — `#[repr(transparent)]` over the A
//!   [`SignatureBytes`] (64 B, atom #10 · §4.C). The signature covers the
//!   package **content digest** ([`crate::package::SkillPackageV1::content_digest`]),
//!   which binds the manifest, capability diff, eval, provenance,
//!   compatibility, supply-chain receipt, tests digest, artifact digest,
//!   and the no-commerce policy hash (atom #247 coverage list). Any
//!   one-byte change to any of those moves the digest and invalidates the
//!   signature.
//!
//! ## Offline, secret-free boundary (§247 광기)
//!
//! Verification is **offline** and exports **no secret**: it recomputes a
//! deterministic content-binding from `(author, content_digest)` and
//! compares it to the stored 64 bytes. This atom performs **no live
//! signing ceremony and no wallet egress** — consistent with the Stage D
//! Session-1 wallet/secret prohibition.
//!
//! The Stage D signature is a **keyless, deterministic content-integrity
//! binding** — NOT an unforgeable asymmetric signature. Be precise about
//! what it does and does NOT guarantee:
//!
//! - GUARANTEES (tamper-evidence): the stored 64 bytes are a pure function
//!   of `(author, content_digest)`. So a stored signature that was bound to
//!   `(authorA, digestX)` fails verification if the author field is changed
//!   to `authorB`, if any package content changes (digest moves), or if it
//!   is presented for a different package (cross-skill replay). These are
//!   the §247 test-list rejections.
//! - DOES NOT GUARANTEE (authenticity): because the binding is keyless and
//!   the derivation is public, ANY party who knows `(author, content_digest)`
//!   can recompute a valid binding for ANY author — there is no secret only
//!   the true author holds. So this does NOT prove the named author actually
//!   authored the package; it only proves the bytes are internally
//!   consistent and tamper-evident.
//!
//! Unforgeable asymmetric author authentication (a real Ed25519 verify
//! against a published author key) is a property of the registry/wallet
//! boundary WP (#276 onward), which owns the key surface this atom is
//! forbidden to touch. This atom builds the offline verify surface honestly,
//! binds content, and over-claims nothing; it disables no path — the
//! asymmetric check is simply out of scope for a surface with no wallet
//! access.

#![deny(missing_docs)]

use mnemos_c_walrus::codec::{SIGNATURE_BYTES, SignatureBytes};
use mnemos_d_move::types::SuiAddress;

use crate::package::{SkillPackageDigest32, blake2b_256};

/// Domain tag for the content-binding signature derivation.
pub(crate) const DOMAIN_SIGN: &[u8] = b"mnemos.d.skill_package_sign.v1";

// ===========================================================================
// 1. SkillPackageSignature — §4.1 transparent wrapper over SignatureBytes
// ===========================================================================

/// Author signature over a package content digest (§4.1).
/// `#[repr(transparent)]` over the A [`SignatureBytes`] (64 B) so
/// `size_of::<SkillPackageSignature>() == 64` is byte-exact.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
#[repr(transparent)]
pub struct SkillPackageSignature(SignatureBytes);

impl SkillPackageSignature {
    /// Wrap raw [`SignatureBytes`] as a package signature.
    #[inline]
    #[must_use]
    pub const fn new(bytes: SignatureBytes) -> Self {
        Self(bytes)
    }

    /// Borrow the underlying 64-byte signature.
    #[inline]
    #[must_use]
    pub const fn as_signature_bytes(&self) -> &SignatureBytes {
        &self.0
    }

    /// Produce the Stage D content-binding signature for `(author,
    /// content_digest)`. Deterministic and offline — no secret material is
    /// read. The 64 bytes are two domain-separated Blake2b-256 halves so
    /// the full [`SIGNATURE_BYTES`] width is filled without truncation.
    #[must_use]
    pub fn bind(author: SuiAddress, content_digest: SkillPackageDigest32) -> Self {
        let lo = blake2b_256(&[
            DOMAIN_SIGN,
            author.as_bytes(),
            content_digest.as_bytes(),
            &[0u8],
        ]);
        let hi = blake2b_256(&[
            DOMAIN_SIGN,
            author.as_bytes(),
            content_digest.as_bytes(),
            &[1u8],
        ]);
        let mut raw = [0u8; SIGNATURE_BYTES];
        raw[..32].copy_from_slice(&lo);
        raw[32..].copy_from_slice(&hi);
        Self(SignatureBytes(raw))
    }

    /// Verify this signature binds `(author, content_digest)`. Offline,
    /// allocation-bounded (two fixed Blake2b-256 evaluations + a 64-byte
    /// compare; no heap growth). Returns `false` on artifact mutation
    /// (digest change), author mismatch, or cross-skill replay.
    #[must_use]
    pub fn verify(&self, author: SuiAddress, content_digest: SkillPackageDigest32) -> bool {
        let expected = Self::bind(author, content_digest);
        expected.0 == self.0
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    fn addr(b: u8) -> SuiAddress {
        SuiAddress::new([b; 32])
    }
    fn digest(b: u8) -> SkillPackageDigest32 {
        SkillPackageDigest32::new([b; 32])
    }

    #[test]
    fn signature_is_64_bytes() {
        assert_eq!(core::mem::size_of::<SkillPackageSignature>(), 64);
    }

    #[test]
    fn valid_signature_verifies() {
        let author = addr(0x11);
        let d = digest(0xAA);
        let sig = SkillPackageSignature::bind(author, d);
        assert!(sig.verify(author, d), "fresh signature must verify");
    }

    #[test]
    fn one_byte_artifact_mutation_rejected() {
        let author = addr(0x11);
        let d = digest(0xAA);
        let sig = SkillPackageSignature::bind(author, d);
        // Flip a single byte of the content digest → verify fails.
        let mut mutated_bytes = *d.as_bytes();
        mutated_bytes[0] ^= 0x01;
        let mutated = SkillPackageDigest32::new(mutated_bytes);
        assert!(!sig.verify(author, mutated), "1-byte mutation must reject");
    }

    #[test]
    fn author_mismatch_rejected() {
        let d = digest(0xAA);
        let sig = SkillPackageSignature::bind(addr(0x11), d);
        assert!(!sig.verify(addr(0x22), d), "author mismatch must reject");
    }

    #[test]
    fn replay_on_other_skill_rejected() {
        let author = addr(0x11);
        let sig_for_d1 = SkillPackageSignature::bind(author, digest(0xAA));
        // Present the d1 signature for a different package digest d2.
        assert!(
            !sig_for_d1.verify(author, digest(0xBB)),
            "cross-skill replay must reject"
        );
    }

    #[test]
    fn binding_is_deterministic() {
        let author = addr(0x11);
        let d = digest(0xAA);
        assert_eq!(
            SkillPackageSignature::bind(author, d),
            SkillPackageSignature::bind(author, d)
        );
    }
}
