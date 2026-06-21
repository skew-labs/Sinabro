//! Stage B testnet address derivation (atom #149 · B.4.3, WorkPackage
//! B-WP-03).
//!
//! Canonical OUT (`MNEMOS_STAGE_B_ATOM_PLAN.md` §4.4): derive a Stage A
//! [`SuiAddress`] from a 32-byte ed25519 signing public key, and map that key
//! to / from the Stage A [`SignaturePlaceholderV1::public_key`] field. This
//! is the public-key → address binding seam the atom #88 owner module
//! explicitly deferred to "the d-move binding seam (atom #149)"
//! (`b-memory/src/owner.rs:126`).
//!
//! # Madness invariants (§4.4 / atom #149)
//!
//! * **Conversion is explicit and length-checked.** A raw runtime byte slice
//!   enters only through [`derive_testnet_address_from_bytes`], which routes
//!   the length check through the reused, fail-closed
//!   [`SigningPublicKey::from_bytes`] (returns `None` for any length other
//!   than 32). A typed [`SigningPublicKey`] enters
//!   [`derive_testnet_address`] infallibly (length already guaranteed by the
//!   type).
//! * **The derivation is the Sui ed25519 convention.** The address is
//!   `Blake2b-256(0x00 ‖ pubkey)[..32]`, byte-identical to the Stage A
//!   [`SealedKeypair::public_address`](crate::keystore::SealedKeypair::public_address)
//!   derivation (`keystore.rs:399`) — the same scheme flag (`0x00`) and the
//!   same hash. Both sites compute the same address for the same key.
//! * **No owner⇔key equality is asserted at construction.** Like atom #88,
//!   [`owner_binding`] carries the derived owner address and the signing key
//!   side-by-side; the binding is a typed carrier, and the *derivation* (this
//!   module) is what makes the owner match the key.
//!
//! # Reuse map (atom contract)
//!
//! * **reuse: #88** — [`SigningPublicKey`] / [`OwnerPublicKeyBinding`]
//!   (`b-memory/src/owner.rs:78` / `:134`).
//! * **reuse: #132** — Stage B d-move binding types (the [`SuiAddress`] this
//!   seam produces feeds `MemoryRootAnchorArgs` owner fields downstream).
//! * **reuse: #148** — the scoped secret whose public key flows through this
//!   address seam after signing (#150/#151).

use blake2::Blake2b;
use blake2::Digest;
use blake2::digest::consts::U32;
use mnemos_b_memory::owner::{OwnerPublicKeyBinding, SigningPublicKey};
use mnemos_c_walrus::SignaturePlaceholderV1;
use mnemos_d_move::types::SuiAddress;

/// The Sui signature-scheme flag for ed25519 (`0x00`), mixed in front of the
/// public key before the Blake2b address hash. Byte-identical to the Stage A
/// keystore's private `SUI_ED25519_FLAG` and to
/// [`crate::stage_b_sign_tx`]'s `SignatureFlag::ED25519` discriminant — the
/// one scheme Stage B's bot wallet uses (§9.5).
pub const STAGE_B_SUI_ED25519_FLAG: u8 = 0x00;

/// Derive the Stage A testnet [`SuiAddress`] from a typed 32-byte signing
/// public key: `Blake2b-256(0x00 ‖ pubkey)[..32]`.
///
/// Infallible — [`SigningPublicKey`] already guarantees the 32-byte width, so
/// there is no length to re-check here.
#[must_use]
pub fn derive_testnet_address(pubkey: &SigningPublicKey) -> SuiAddress {
    let mut hasher = Blake2b::<U32>::new();
    hasher.update([STAGE_B_SUI_ED25519_FLAG]);
    hasher.update(pubkey.as_bytes());
    let digest = hasher.finalize();

    let mut addr = [0u8; 32];
    addr.copy_from_slice(&digest);
    SuiAddress::new(addr)
}

/// Derive the testnet [`SuiAddress`] from a raw runtime byte slice,
/// **fail-closed on length**. Returns `Some(address)` iff `bytes.len() == 32`
/// (routed through the reused [`SigningPublicKey::from_bytes`]) and `None`
/// for every other length — no canonical error variant is minted (atom #88
/// reject-as-predicate precedent).
#[must_use]
pub fn derive_testnet_address_from_bytes(bytes: &[u8]) -> Option<SuiAddress> {
    let pubkey = SigningPublicKey::from_bytes(bytes)?;
    Some(derive_testnet_address(&pubkey))
}

/// Derive the testnet [`SuiAddress`] from the public key carried by a Stage A
/// [`SignaturePlaceholderV1`]'s home-of-record `public_key` field. Infallible
/// — the field is a `[u8; 32]`, so the length is guaranteed by the type
/// (reuses [`SigningPublicKey::from_placeholder`]).
#[must_use]
pub fn address_from_placeholder(sig: &SignaturePlaceholderV1) -> SuiAddress {
    derive_testnet_address(&SigningPublicKey::from_placeholder(sig))
}

/// Pair a signing public key with the testnet owner address derived from it,
/// as a Stage A #88 [`OwnerPublicKeyBinding`]. Unlike
/// [`OwnerPublicKeyBinding::new`] (which takes an independently-supplied
/// owner), this constructor *derives* the owner from the key, so the binding
/// is guaranteed self-consistent by construction.
#[must_use]
pub fn owner_binding(pubkey: &SigningPublicKey) -> OwnerPublicKeyBinding {
    let owner = derive_testnet_address(pubkey);
    OwnerPublicKeyBinding::new(owner, *pubkey)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    #![allow(clippy::expect_used)]
    #![allow(clippy::panic)]

    use super::*;
    use mnemos_c_walrus::codec::SignatureScheme;
    use mnemos_c_walrus::{SignatureBytes, SignaturePlaceholderV1};

    /// Fixed 32-byte public key for the known-answer vector.
    const KAT_PUBKEY: [u8; 32] = [
        0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, //
        0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00, //
        0x0F, 0x1E, 0x2D, 0x3C, 0x4B, 0x5A, 0x69, 0x78, //
        0x87, 0x96, 0xA5, 0xB4, 0xC3, 0xD2, 0xE1, 0xF0, //
    ];

    /// Independently computed (Python `hashlib.blake2b(b"\x00" + pubkey,
    /// digest_size=32)`) Blake2b-256 address for [`KAT_PUBKEY`]. This is the
    /// non-reflexive oracle: the expected bytes come from a *different*
    /// implementation than the Rust derivation under test.
    const KAT_ADDRESS: [u8; 32] = [
        0xD9, 0x7F, 0xD9, 0x52, 0x17, 0xA8, 0x47, 0x41, //
        0xE4, 0x65, 0x28, 0x4F, 0xA0, 0x64, 0x30, 0x0B, //
        0x51, 0xF6, 0x07, 0xBC, 0x5A, 0x04, 0x5D, 0x7A, //
        0x49, 0x71, 0x14, 0x3D, 0x16, 0x90, 0x64, 0x2D, //
    ];

    /// `b4_3_known_vector` — the derivation matches an independently computed
    /// Blake2b-256 address (Python oracle), proving the byte order and scheme
    /// flag are correct (not merely self-consistent).
    #[test]
    fn b4_3_known_vector() {
        let pubkey = SigningPublicKey::from_bytes(&KAT_PUBKEY).expect("32-byte key");
        let addr = derive_testnet_address(&pubkey);
        assert_eq!(
            addr.as_bytes(),
            &KAT_ADDRESS,
            "derived address must match the independent Python Blake2b oracle",
        );

        // A deliberately-wrong expectation MUST NOT match (falsification
        // canary: proves the assertion above can fail).
        let mut wrong = KAT_ADDRESS;
        wrong[0] ^= 0x01;
        assert_ne!(addr.as_bytes(), &wrong, "canary: wrong address must differ");
    }

    /// `b4_3_owner_pubkey_matches_chunk_owner` — the address derived from a
    /// `SignaturePlaceholderV1`'s `public_key` equals the address derived from
    /// the same key directly, and the `owner_binding` carries exactly that
    /// owner alongside the verbatim key. This is the "owner pubkey matches
    /// chunk owner" invariant.
    #[test]
    fn b4_3_owner_pubkey_matches_chunk_owner() {
        let sig = SignaturePlaceholderV1 {
            scheme: SignatureScheme::Ed25519,
            public_key: KAT_PUBKEY,
            signature: SignatureBytes([7u8; 64]),
        };
        let via_placeholder = address_from_placeholder(&sig);
        assert_eq!(via_placeholder.as_bytes(), &KAT_ADDRESS);

        let pubkey = SigningPublicKey::from_placeholder(&sig);
        let binding = owner_binding(&pubkey);
        assert_eq!(
            binding.owner().as_bytes(),
            &KAT_ADDRESS,
            "binding owner must be the derived address",
        );
        assert_eq!(
            binding.signing_key().as_bytes(),
            &KAT_PUBKEY,
            "binding must carry the verbatim public key",
        );
    }

    /// `b4_3_wrong_length_reject` — a runtime byte slice of any length other
    /// than 32 is rejected fail-closed (`None`); exactly 32 resolves.
    #[test]
    fn b4_3_wrong_length_reject() {
        for bad_len in [0usize, 1, 16, 31, 33, 64] {
            let bytes = vec![0xABu8; bad_len];
            assert!(
                derive_testnet_address_from_bytes(&bytes).is_none(),
                "length {bad_len} must be rejected",
            );
        }
        assert!(
            derive_testnet_address_from_bytes(&KAT_PUBKEY).is_some(),
            "exactly 32 bytes must resolve",
        );
        assert_eq!(
            derive_testnet_address_from_bytes(&KAT_PUBKEY)
                .expect("32 bytes resolves")
                .as_bytes(),
            &KAT_ADDRESS,
        );
    }
}
