//! `owner.rs` — the Stage B **owner ↔ signing-public-key
//! boundary**.
//!
//! Two distinct 32-byte identities meet at a signed memory chunk:
//!
//! * the **owner** — the wallet that owns the on-chain memory root. It travels
//!   as Stage A's [`SuiAddress`] (`mnemos-d-move`) **verbatim**, never as a
//!   raw `String`. [`crate::chunk_schema::StageBChunkHeaderV1::owner`]
//!   already carries it this way; this module re-uses the same canonical type so
//!   there is exactly one address representation in Stage B.
//! * the **signing public key** — the 32-byte key under which a chunk signature
//!   verifies. Its home of record is Stage A's
//!   [`SignaturePlaceholderV1::public_key`] field (`mnemos-c-walrus`); this
//!   module does **not** mint a second storage location for it. [`SigningPublicKey`]
//!   is a typed *boundary view* of that field, length-validated at the runtime
//!   `&[u8]` edge.
//!
//! # Why a distinct key type (`SigningPublicKey` ≠ `SuiAddress`)
//!
//! A Sui address is *derived from* a public key (hash + scheme-flag), but the two
//! are not the same value and must never be silently interchanged. Mirroring the
//! `mnemos-d-move` `ObjectId`-vs-`SuiAddress` separation, [`SigningPublicKey`] is
//! type-distinct from [`SuiAddress`] so a 32-byte public key can never be used
//! where a wallet address is expected (or vice-versa) without an explicit,
//! auditable conversion.
//!
//! # Boundary invariant
//!
//! The public-key → `SuiAddress` **conversion is performed only in the d-move
//! binding** — never here. [`OwnerPublicKeyBinding`] therefore carries *both*
//! sides side-by-side without ever converting one into the other; it asserts no
//! equality between the key and the address. The actual derivation (and the
//! check that an address indeed corresponds to a key) lives on
//! the Move-binding seam, where the chain's canonical scheme-flag + hash rule is
//! applied. This module mints the typed carriers, not that conversion.
//!
//! # No raw leak
//!
//! Neither [`SigningPublicKey`] nor [`OwnerPublicKeyBinding`] implements
//! [`core::fmt::Display`] at all, and both carry a **redacting** [`core::fmt::Debug`]
//! that never echoes the raw bytes. A public key is public data rather than a
//! secret, but the boundary still refuses to splatter raw key/owner bytes into
//! logs or user-facing strings by accident — the same redaction discipline the
//! Stage A error channels follow.
//!
//! # Reuse (zero reinvention)
//!
//! * A `mnemos-d-move::SuiAddress` — owner address, reused verbatim (no new
//!   address type minted).
//! * A `mnemos-c-walrus::SignaturePlaceholderV1::public_key` — the public-key
//!   field; [`SigningPublicKey::from_placeholder`] reads it, it is not re-homed.
//! * A `mnemos-c-walrus::BLOB_ID_BYTES` (= 32) — the single width source for
//!   [`SIGNING_PUBLIC_KEY_BYTES`]; no new `32` literal.
//! * `StageBChunkHeaderV1.owner: SuiAddress` — the precedent that the owner
//!   already flows as a `SuiAddress`.

use mnemos_c_walrus::{BLOB_ID_BYTES, SignaturePlaceholderV1};
use mnemos_d_move::SuiAddress;

/// Byte length of a Stage B signing public key. Equal to Stage A's
/// `BLOB_ID_BYTES` (= 32), which is also the width of
/// [`SignaturePlaceholderV1::public_key`]; reusing that constant keeps a single
/// width source rather than introducing a second `32` literal.
pub const SIGNING_PUBLIC_KEY_BYTES: usize = BLOB_ID_BYTES;

/// A 32-byte signing public key, type-distinct from [`SuiAddress`].
///
/// `#[repr(transparent)]` over `[u8; SIGNING_PUBLIC_KEY_BYTES]`, so
/// `size_of::<SigningPublicKey>() == 32`. The inner array is private: a value is
/// constructed only through the fail-closed [`SigningPublicKey::from_bytes`] (a
/// runtime `&[u8]` of exactly 32 bytes) or by extracting the home-of-record field
/// via [`SigningPublicKey::from_placeholder`].
///
/// `Debug` is **redacting** and `Display` is intentionally **not** implemented
/// (see the module-level "No raw leak" note).
#[derive(Clone, Copy, Eq, PartialEq)]
#[repr(transparent)]
pub struct SigningPublicKey([u8; SIGNING_PUBLIC_KEY_BYTES]);

impl SigningPublicKey {
    /// Wrap a runtime byte slice as a signing public key, **fail-closed** on
    /// length: returns `Some` iff `bytes.len() == SIGNING_PUBLIC_KEY_BYTES`
    /// (32), and `None` for every other length. Reject-as-predicate, following
    /// the same convention — no canonical error variant is minted here (the
    /// `StageBChunkError` set is frozen `#[non_exhaustive]`).
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        if bytes.len() != SIGNING_PUBLIC_KEY_BYTES {
            return None;
        }
        let mut out = [0u8; SIGNING_PUBLIC_KEY_BYTES];
        out.copy_from_slice(bytes);
        Some(Self(out))
    }

    /// Read the public key out of its home-of-record, Stage A's
    /// [`SignaturePlaceholderV1::public_key`]. The field is a `[u8; 32]`, so the
    /// length is guaranteed by the type and this mapping is infallible — it does
    /// not re-home or re-validate the key, it only views it through the typed
    /// boundary.
    pub fn from_placeholder(sig: &SignaturePlaceholderV1) -> Self {
        Self(sig.public_key)
    }

    /// Borrow the underlying 32-byte key.
    #[inline]
    pub const fn as_bytes(&self) -> &[u8; SIGNING_PUBLIC_KEY_BYTES] {
        &self.0
    }
}

impl core::fmt::Debug for SigningPublicKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        // Redact: never echo the raw public-key bytes. (No `Display` exists.)
        write!(
            f,
            "SigningPublicKey(<redacted; {SIGNING_PUBLIC_KEY_BYTES} bytes>)"
        )
    }
}

/// The owner ↔ signing-public-key boundary: a chunk's [`SuiAddress`] owner paired
/// with the [`SigningPublicKey`] it was (or will be) signed under, carried
/// side-by-side **without** converting one into the other.
///
/// The invariant: the public-key → `SuiAddress` derivation is the
/// exclusive job of the d-move binding seam. This type performs
/// **no** such conversion and asserts **no** equality between [`Self::owner`]
/// and [`Self::signing_key`]; it only keeps the two type-distinct identities
/// together so a downstream consumer can hand the d-move binding the exact pair
/// to validate.
///
/// `Debug` is redacting and `Display` is intentionally not implemented.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct OwnerPublicKeyBinding {
    owner: SuiAddress,
    signing_key: SigningPublicKey,
}

impl OwnerPublicKeyBinding {
    /// Pair an owner address with a signing public key. No conversion or
    /// owner⇔key consistency check is performed (that is the d-move binding's
    /// responsibility); this is a pure carrier.
    #[inline]
    pub const fn new(owner: SuiAddress, signing_key: SigningPublicKey) -> Self {
        Self { owner, signing_key }
    }

    /// Pair an owner address with the public key read from its home-of-record
    /// [`SignaturePlaceholderV1`]. Convenience over
    /// [`SigningPublicKey::from_placeholder`] + [`OwnerPublicKeyBinding::new`].
    pub fn from_placeholder(owner: SuiAddress, sig: &SignaturePlaceholderV1) -> Self {
        Self {
            owner,
            signing_key: SigningPublicKey::from_placeholder(sig),
        }
    }

    /// The owner wallet address (Stage A [`SuiAddress`], `Copy`).
    #[inline]
    pub const fn owner(&self) -> SuiAddress {
        self.owner
    }

    /// The signing public key (`Copy`).
    #[inline]
    pub const fn signing_key(&self) -> SigningPublicKey {
        self.signing_key
    }
}

impl core::fmt::Debug for OwnerPublicKeyBinding {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        // Redact both the owner address and the key; no raw bytes, no `Display`.
        write!(f, "OwnerPublicKeyBinding(<redacted owner+key>)")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mnemos_c_walrus::{SignatureBytes, SignatureScheme};

    fn placeholder(public_key: [u8; SIGNING_PUBLIC_KEY_BYTES]) -> SignaturePlaceholderV1 {
        SignaturePlaceholderV1 {
            scheme: SignatureScheme::Ed25519,
            public_key,
            signature: SignatureBytes([0u8; 64]),
        }
    }

    #[test]
    fn b1_7_signing_key_length_32_accepted() {
        let raw = [7u8; SIGNING_PUBLIC_KEY_BYTES];
        let key = SigningPublicKey::from_bytes(&raw);
        assert!(key.is_some(), "exactly-32-byte key must be accepted");
        if let Some(k) = key {
            assert_eq!(k.as_bytes(), &raw, "round-trip must preserve the 32 bytes");
        }
    }

    #[test]
    fn b1_7_signing_key_wrong_length_rejected() {
        // fail-closed on every non-32 length
        assert!(SigningPublicKey::from_bytes(&[]).is_none());
        assert!(SigningPublicKey::from_bytes(&[0u8; 1]).is_none());
        assert!(SigningPublicKey::from_bytes(&[0u8; 31]).is_none());
        assert!(SigningPublicKey::from_bytes(&[0u8; 33]).is_none());
        assert!(SigningPublicKey::from_bytes(&[0u8; 64]).is_none());
    }

    #[test]
    fn b1_7_no_display_raw_leak() {
        // 0xAB = 171 decimal / "ab" hex — none of these must appear in Debug.
        let raw = [0xABu8; SIGNING_PUBLIC_KEY_BYTES];
        let key = SigningPublicKey::from_bytes(&raw);
        assert!(key.is_some());
        if let Some(k) = key {
            let dbg = format!("{k:?}");
            assert!(dbg.contains("redacted"), "Debug must redact: {dbg}");
            assert!(!dbg.contains("171"), "raw decimal byte leaked: {dbg}");
            assert!(!dbg.contains("ab"), "raw hex byte leaked: {dbg}");
            assert!(!dbg.contains("AB"), "raw hex byte leaked: {dbg}");
        }

        // The binding's Debug also redacts both owner (0x11 = 17) and key.
        let owner = SuiAddress::new([0x11u8; 32]);
        if let Some(k) = SigningPublicKey::from_bytes(&raw) {
            let binding = OwnerPublicKeyBinding::new(owner, k);
            let dbg = format!("{binding:?}");
            assert!(dbg.contains("redacted"), "binding Debug must redact: {dbg}");
            assert!(!dbg.contains("17"), "raw owner byte leaked: {dbg}");
            assert!(!dbg.contains("171"), "raw key byte leaked: {dbg}");
        }
    }

    #[test]
    fn b1_7_from_placeholder_extracts_home_of_record_key() {
        let pk = [0x5Au8; SIGNING_PUBLIC_KEY_BYTES];
        let sig = placeholder(pk);
        let key = SigningPublicKey::from_placeholder(&sig);
        assert_eq!(
            key.as_bytes(),
            &pk,
            "must view the placeholder's public_key"
        );
    }

    #[test]
    fn b1_7_binding_carries_both_without_conversion() {
        let pk = [0x5Au8; SIGNING_PUBLIC_KEY_BYTES];
        let owner = SuiAddress::new([0x22u8; 32]);
        let sig = placeholder(pk);
        let binding = OwnerPublicKeyBinding::from_placeholder(owner, &sig);

        // both identities are carried, unchanged
        assert_eq!(binding.owner(), owner);
        assert_eq!(binding.signing_key().as_bytes(), &pk);
        // the boundary does NOT convert the key into the owner address:
        // distinct bytes stay distinct (no silent pk→address derivation here).
        assert_ne!(binding.signing_key().as_bytes(), owner.as_bytes());
    }
}
