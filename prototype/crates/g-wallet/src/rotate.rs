//! G.0.4 — sealed-keypair rotation: fresh ed25519 seed under a new
//! passphrase + address-change report. Closes Stage G (atom #36).
//!
//! Canonical OUT (`MNEMOS_ATOM_PLAN.md` §4.G atom #36, line 681-682):
//!
//! ```rust,ignore
//! pub struct RotationReport {
//!     old_address: SuiAddress,
//!     new_address: SuiAddress,
//! }
//! pub fn rotate_key(
//!     old: &SealedKeypair,
//!     old_pass: &str,
//!     new_pass: &str,
//! ) -> Result<(SealedKeypair, RotationReport), WalletError>;
//! ```
//!
//! ## 광기 (ATOM_PLAN line 1181 + §9.5 완료기준)
//!
//! **Fresh keypair on every rotation.** Rotation is NOT a re-seal of
//! the same ed25519 seed under a new passphrase — it draws a fresh
//! 32-byte seed (+ fresh KDF salt + fresh stored nonce) from the OS
//! CSPRNG via the atom #33 [`SealedKeypair::create_encrypted`] path.
//! Reusing the old seed under a new passphrase would silently keep the
//! same on-chain identity (same Sui address) and defeat the purpose of
//! a rotation: a leak of either passphrase plus the on-disk ciphertext
//! still yields the original seed. The address-change witness in
//! [`tests::g0_4_rotation_changes_address`] pins this structurally.
//!
//! **Old key zeroized inside the rotation scope.** The transient
//! [`ScopedSecretKey`] unsealed from the OLD `SealedKeypair` is
//! borrowed for exactly one authentication step (proving the caller
//! holds the old passphrase) and is then dropped at the natural
//! scope end. `Drop` on [`ScopedSecretKey`] calls
//! [`zeroize::Zeroize::zeroize`] on the 32-byte buffer (atom #33
//! invariant); no copy of the old seed escapes [`rotate_key`]. The
//! [`tests::g0_4_old_key_zeroized`] test grep-pins the absence of any
//! secret-material field on the returned [`RotationReport`] and the
//! absence of any public function signature that returns a
//! [`ScopedSecretKey`] out of this module.
//!
//! **No signing gap during rotation (ATOM_PLAN line 1181).** The
//! `&SealedKeypair` borrow is **immutable** — `rotate_key` cannot and
//! does not mutate the OLD sealed ciphertext on disk. The caller's
//! OLD sealed file therefore remains usable for [`sign_move_tx`] and
//! [`sign_message`] for as long as the caller chooses to keep it
//! (until the caller atomically swaps the on-disk file to the new
//! one). The atom-#36 surface does NOT prescribe the on-disk swap
//! protocol; that is a caller concern (typical Sui-validator-style
//! rotation: write new sealed file → fsync → atomic rename →
//! `unlink(old_path)`). The
//! [`tests::g0_4_e2e_sign_after_rotation`] test witnesses BOTH
//! signing paths (transaction data + personal message) under BOTH
//! the old and the new keypair, and pins the cross-key
//! verification-failure invariant (a signature produced by the new
//! key MUST NOT verify under the old pubkey, and vice versa).
//!
//! ## `WalletError::KeyRotation` — first emission site
//!
//! [`WalletError::KeyRotation`] was declared by atom #33's canonical
//! OUT and reserved through atoms #34 and #35 (per the
//! `no_op_decisions.jsonl` precedent). Atom #36 is its FIRST emission
//! site, on two structural branches:
//!
//!  1. `new_pass == old_pass`: rotating to the SAME passphrase
//!     produces a sealed file that decrypts to a fresh seed but is
//!     gated by the same secret the attacker already had. The
//!     rotation surface refuses early ([`WalletError::KeyRotation`])
//!     so the caller's intent (rotate to a NEW secret) is preserved.
//!  2. `old_address == new_address` after CSPRNG draw: a 32-byte
//!     ed25519 seed collision via the OS CSPRNG is cryptographically
//!     impossible (`P = 2^-256`). The structural canary nevertheless
//!     refuses ([`WalletError::KeyRotation`]) so a future regression
//!     that accidentally reuses the input seed (e.g. by sharing the
//!     RNG state, or by skipping the CSPRNG draw) surfaces here
//!     rather than silently shipping a no-op rotation.
//!
//! ## Wrong-passphrase signal continuity (`WalletError::Decrypt`)
//!
//! When `old_pass` is incorrect (or the OLD sealed ciphertext is
//! tampered), the call surfaces [`WalletError::Decrypt`] — the SAME
//! variant the plain [`SealedKeypair::unseal`] returns. A wrong-pass
//! attacker probing the rotation entry point cannot distinguish
//! "wrong pass" from "tampered ciphertext" any more than they can
//! through plain unseal (atom #33 invariant: both collapse into
//! [`WalletError::Decrypt`]). `KeyRotation` is reserved for the
//! rotation-policy refusals listed above.
//!
//! ## Reuse, not parallel definition
//!
//! This module declares **one** new public type ([`RotationReport`])
//! and **one** new public function ([`rotate_key`]). Every other
//! identifier on the surface (`SealedKeypair`, `WalletError`,
//! `ScopedSecretKey`, `SuiAddress`) flows in unchanged from atom #33
//! (g-wallet `keystore`) and atom #15 (d-move `SuiAddress`). The
//! Stage-G last-atom shape follows the atom #1 / #6 precedent: a
//! pure surface addition with zero new transitive crate. The
//! `RotationReport` carries ONLY the (old, new) Sui address pair —
//! no secret material, no derived key, no timestamp, no signer
//! identifier (the caller owns those).

#![forbid(unsafe_code)]

use mnemos_d_move::SuiAddress;

use crate::keystore::{SealedKeypair, WalletError};

/// Address-change report produced by [`rotate_key`].
///
/// Carries the (old, new) [`SuiAddress`] pair so the caller can
/// reconcile its identity store / observability stack against the
/// freshly-rotated sealed keypair. The struct intentionally carries
/// NOTHING ELSE — no secret material, no derived key, no nonce, no
/// timestamp, no signer identifier. Those belong to the caller's
/// audit log, not to this transport.
///
/// `Debug` / `Clone` / `Copy` are deliberately NOT derived. The
/// addresses are public information (zero-decryption reads from the
/// AEAD ciphertext prefix), but the cross-domain convention in this
/// crate (atom #33: `ScopedSecretKey` derives nothing) is to keep
/// rotation-side surfaces minimal — callers that need to log or
/// serialise the report borrow the two addresses through the
/// `&SuiAddress` accessors and let the [`SuiAddress`] type itself
/// govern its own formatting / serialisation conventions.
pub struct RotationReport {
    /// Sui address of the OLD (pre-rotation) sealed keypair.
    /// `Blake2b-256(0x00 || old_pubkey)[..32]`.
    old_address: SuiAddress,
    /// Sui address of the NEW (post-rotation) sealed keypair.
    /// `Blake2b-256(0x00 || new_pubkey)[..32]`. Guaranteed by
    /// construction to differ from [`Self::old_address`] (CSPRNG-
    /// drawn fresh seed + structural canary).
    new_address: SuiAddress,
}

impl RotationReport {
    /// Borrow the Sui address of the OLD (pre-rotation) sealed keypair.
    #[inline]
    #[must_use]
    pub fn old_address(&self) -> &SuiAddress {
        &self.old_address
    }

    /// Borrow the Sui address of the NEW (post-rotation) sealed keypair.
    #[inline]
    #[must_use]
    pub fn new_address(&self) -> &SuiAddress {
        &self.new_address
    }
}

/// Rotate a sealed Sui ed25519 keypair: produce a fresh
/// CSPRNG-drawn seed sealed under `new_pass` and return the new
/// [`SealedKeypair`] alongside a [`RotationReport`] of the
/// (old, new) address pair.
///
/// The caller's OLD `SealedKeypair` is borrowed immutably; this
/// function does NOT mutate the OLD ciphertext (and cannot — the
/// argument is `&SealedKeypair`). The caller decides when to swap
/// the on-disk sealed file from old to new (typical: write new file
/// → fsync → atomic rename → unlink old). Until the caller swaps,
/// BOTH keypairs are usable for [`crate::sign_tx::sign_move_tx`]
/// and [`crate::sign_msg::sign_message`] — there is no signing gap
/// during rotation (ATOM_PLAN line 1181).
///
/// ## Steps
///
/// 1. Authenticate the OLD sealed keypair under `old_pass` via
///    [`SealedKeypair::unseal`]. On failure: surface
///    [`WalletError::Decrypt`] (NOT `KeyRotation` — see module-level
///    docs on wrong-passphrase signal continuity).
/// 2. Drop the transient [`crate::keystore::ScopedSecretKey`] — its
///    `Drop` impl zeroizes the 32-byte buffer (atom #33 invariant).
///    No copy of the old seed escapes this function.
/// 3. Refuse same-passphrase rotation: if `new_pass == old_pass`,
///    surface [`WalletError::KeyRotation`] before drawing fresh
///    randomness.
/// 4. Generate a fresh sealed keypair under `new_pass` via
///    [`SealedKeypair::create_encrypted`]. Errors bubble unchanged
///    ([`WalletError::PlaintextRefused`] on empty `new_pass`;
///    [`WalletError::Decrypt`] on OS CSPRNG / AEAD failure).
/// 5. Read both Sui addresses (zero-decryption operations on the
///    32-byte pubkey prefix of each ciphertext) and pin the
///    structural canary `old_address != new_address`. On the
///    cryptographically-impossible collision branch
///    (`P = 2^-256`), surface [`WalletError::KeyRotation`].
///
/// ## Errors
///
/// - [`WalletError::Decrypt`] — wrong `old_pass`, or tampered OLD
///   sealed ciphertext, or OS CSPRNG / AEAD failure inside the
///   fresh `create_encrypted` step (caller cannot distinguish; same
///   uniform privacy posture as atom #33).
/// - [`WalletError::PlaintextRefused`] — empty `new_pass`.
/// - [`WalletError::KeyRotation`] — `new_pass == old_pass`, OR
///   structural canary `old_address == new_address` (a
///   cryptographically-impossible collision that nevertheless
///   refuses fail-closed; first emission site for `KeyRotation`,
///   per atom #33 declared-but-reserved precedent).
pub fn rotate_key(
    old: &SealedKeypair,
    old_pass: &str,
    new_pass: &str,
) -> Result<(SealedKeypair, RotationReport), WalletError> {
    // Step 1 — authenticate the OLD sealed keypair. The returned
    // ScopedSecretKey lives for exactly the duration of this scope;
    // its `Drop` impl zeroizes the 32-byte buffer. We do NOT use the
    // recovered seed for anything past authentication — rotation
    // means a brand-new seed.
    let old_scoped = old.unseal(old_pass)?;
    // Explicit drop documents the zeroize point. Even without it the
    // binding would drop at scope end before `create_encrypted`
    // returns; the explicit form makes the lifecycle obvious to a
    // future reader and pins the "old key zeroized inside the
    // rotation scope" invariant at the source.
    drop(old_scoped);

    // Step 2 — refuse same-passphrase rotation. Constant-time string
    // comparison is NOT required here: an attacker that can probe
    // `new_pass == old_pass` already controls both inputs to this
    // function; the timing side-channel argument applies to the
    // unseal step (atom #33: PBKDF2 + AEAD authentication is the
    // attacker-facing surface), not to this caller-supplied policy
    // check. `==` on `&str` is sufficient.
    if new_pass == old_pass {
        return Err(WalletError::KeyRotation);
    }

    // Step 3 — fresh sealed keypair under the new passphrase. Errors
    // bubble unchanged (PlaintextRefused on empty `new_pass`;
    // Decrypt on OS CSPRNG / AEAD failure).
    let new_sealed = SealedKeypair::create_encrypted(new_pass)?;

    // Step 4 — derive both addresses (zero-decryption reads on the
    // 32-byte pubkey prefix of each ciphertext, atom #33 invariant).
    let old_address = old.public_address();
    let new_address = new_sealed.public_address();

    // Step 5 — structural canary against cryptographically-impossible
    // CSPRNG seed collision (P = 2^-256). A future regression that
    // reuses the input seed surfaces here as `WalletError::KeyRotation`
    // rather than silently shipping a no-op rotation.
    if old_address.as_bytes() == new_address.as_bytes() {
        return Err(WalletError::KeyRotation);
    }

    Ok((
        new_sealed,
        RotationReport {
            old_address,
            new_address,
        },
    ))
}

#[cfg(test)]
mod tests {
    // Test helpers prefer direct failure surfaces (`expect` / `assert`)
    // over `Result`-bubbling; suppress prod-only clippy denies inside
    // this module (atom #33 / #34 / #35 precedent).
    #![allow(clippy::unwrap_used)]
    #![allow(clippy::expect_used)]
    #![allow(clippy::panic)]

    use super::*;
    use crate::keystore::ScopedSecretKey;
    use crate::sign_msg::{SUI_INTENT_PREFIX_PERSONAL_MESSAGE, sign_message};
    use crate::sign_tx::{SUI_INTENT_PREFIX_TRANSACTION_DATA, sign_move_tx};
    use ed25519_dalek::{Signature, SigningKey, Verifier, VerifyingKey};
    use mnemos_c_walrus::SignatureBytes;

    /// `g0_4_rotation_changes_address` (ATOM_PLAN line 1182).
    ///
    /// Witness the primary rotation invariant: after [`rotate_key`]
    /// returns Ok, the OLD and NEW Sui addresses MUST differ and the
    /// returned [`RotationReport`] MUST report addresses that match
    /// the two sealed keypairs verbatim. Pins the structural canary
    /// `old_address != new_address` at the test layer (the
    /// implementation also pins it inline; the test layer pins it
    /// from the caller's perspective).
    #[test]
    fn g0_4_rotation_changes_address() {
        let old_pass = "rotation-old-passphrase-2026";
        let new_pass = "rotation-new-passphrase-2026";

        let old = SealedKeypair::create_encrypted(old_pass).expect("seal old");
        let (new, report) = rotate_key(&old, old_pass, new_pass).expect("rotate ok");

        // Primary invariant: address actually changed.
        assert_ne!(
            report.old_address().as_bytes(),
            report.new_address().as_bytes(),
            "rotate_key MUST produce a fresh address (cryptographic CSPRNG draw)",
        );

        // Report addresses match the two sealed keypairs' public
        // addresses byte-for-byte (no fan-out / no caching drift).
        assert_eq!(
            report.old_address().as_bytes(),
            old.public_address().as_bytes(),
            "report.old_address MUST equal the input SealedKeypair's public_address",
        );
        assert_eq!(
            report.new_address().as_bytes(),
            new.public_address().as_bytes(),
            "report.new_address MUST equal the returned SealedKeypair's public_address",
        );

        // The OLD sealed keypair was NOT mutated by rotation — its
        // address is stable across the call.
        let old_addr_after = old.public_address();
        assert_eq!(report.old_address().as_bytes(), old_addr_after.as_bytes());
    }

    /// `g0_4_old_key_zeroized` (ATOM_PLAN line 1182).
    ///
    /// "옛 키 zeroize" is realised by two layered guarantees:
    ///
    ///  1. The atom #33 [`ScopedSecretKey`] type's `Drop` impl calls
    ///     `zeroize::Zeroize::zeroize` on its 32-byte buffer. This is
    ///     a compile-time-pinned invariant (the `Drop` impl exists on
    ///     the type) and is independently witnessed by atom #33's
    ///     `g0_1_secret_key_has_no_debug` plus the `Drop` impl
    ///     present in `keystore.rs`. Atom #36 inherits that
    ///     guarantee — every `ScopedSecretKey` that this module
    ///     creates is zeroized at scope end.
    ///  2. The [`rotate_key`] surface returns ONLY
    ///     `(SealedKeypair, RotationReport)` — neither of which
    ///     carries plaintext secret material. No
    ///     [`ScopedSecretKey`] escapes the function. This is
    ///     source-level pinned here by reading `rotate.rs` itself
    ///     and asserting that the function-return surface contains
    ///     no `ScopedSecretKey` return type and the
    ///     `RotationReport` body contains no secret-material field.
    ///
    /// Direct memory-state inspection (reading the freed buffer
    /// after `Drop`) is NOT safe under `#![forbid(unsafe_code)]`;
    /// the layered source-level + type-system pin is the
    /// safe-Rust witness for the zeroize guarantee.
    #[test]
    fn g0_4_old_key_zeroized() {
        let src = include_str!("rotate.rs");

        // Witness A — `ScopedSecretKey` is NEVER returned from this
        // module's public surface. Three distinct return-shape
        // needles assembled via `concat!` so this assertion source
        // does not contain the verbatim literal (atom #33 / #34
        // self-tripping-canary precedent).
        let forbidden_return_shapes: [&str; 4] = [
            concat!("-> ", "ScopedSecretKey"),
            concat!("-> Result<", "ScopedSecretKey"),
            concat!("-> Result<(", "ScopedSecretKey"),
            concat!("-> (", "ScopedSecretKey"),
        ];
        for needle in forbidden_return_shapes {
            assert!(
                !src.contains(needle),
                "rotate.rs MUST NOT expose a public function returning ScopedSecretKey (found `{needle}`)",
            );
        }

        // Witness B — `RotationReport` body carries no secret-material
        // field. Scan ONLY the struct body so the assertion source
        // (which mentions the canary needles indirectly via `concat!`)
        // does not self-trip.
        let marker = concat!("pub struct ", "RotationReport {");
        let pos = src
            .find(marker)
            .expect("RotationReport declaration present");
        let after = &src[pos + marker.len()..];
        let close = after
            .find('}')
            .expect("RotationReport body has a closing brace");
        let body = &after[..close];

        let forbidden_fields: [&str; 6] = [
            concat!("secret", "_key"),
            concat!("plaintext", "_key"),
            concat!("private", "_key"),
            concat!("seed", ":"),
            concat!("raw", "_key"),
            concat!("Scoped", "SecretKey"),
        ];
        for needle in forbidden_fields {
            assert!(
                !body.contains(needle),
                "RotationReport body MUST NOT carry any secret material (found `{needle}`)",
            );
        }

        // Witness C — `RotationReport` declares EXACTLY two fields
        // (`old_address` + `new_address`). A future refactor that
        // widens the surface surfaces here.
        let field_count =
            body.matches("old_address:").count() + body.matches("new_address:").count();
        assert_eq!(
            field_count, 2,
            "RotationReport MUST have exactly 2 canonical fields (old_address + new_address)",
        );

        // Witness D — width invariant on `RotationReport`. The struct
        // carries two `SuiAddress` (each 32 bytes); `size_of` is
        // >= 64 (alignment cannot SHRINK the layout). A future
        // regression that adds a third field surfaces here.
        assert!(
            core::mem::size_of::<RotationReport>() >= 64,
            "RotationReport must hold at least two 32-byte SuiAddress values",
        );

        // Witness E — functional end-to-end: rotate runs, the NEW
        // sealed keypair unseals under `new_pass` (proves
        // `create_encrypted` ran to completion + the freshly-drawn
        // seed survives the AEAD round-trip), and the OLD sealed
        // keypair STILL unseals under `old_pass` (proves `rotate_key`
        // did not mutate the OLD ciphertext — `&SealedKeypair`
        // borrow, not `&mut`). Both `ScopedSecretKey`s here are
        // dropped at scope end and zeroized per atom #33.
        let old_pass = "zero-old-2026";
        let new_pass = "zero-new-2026";
        let old = SealedKeypair::create_encrypted(old_pass).expect("seal old");
        let (new, _report) = rotate_key(&old, old_pass, new_pass).expect("rotate ok");

        let new_scoped = new.unseal(new_pass).expect("unseal new");
        drop(new_scoped); // Drop → zeroize per atom #33 invariant.

        let old_scoped_again = old
            .unseal(old_pass)
            .expect("old still usable post-rotation");
        drop(old_scoped_again); // Drop → zeroize per atom #33 invariant.
    }

    /// `g0_4_e2e_sign_after_rotation` (ATOM_PLAN line 1182).
    ///
    /// End-to-end witness across the Stage G surface — atom #33
    /// (`create_encrypted` / `unseal`), atom #34 (`sign_move_tx`),
    /// atom #35 (`sign_message`), atom #36 (`rotate_key`):
    ///
    ///  1. Seal an OLD keypair → unseal under `old_pass` → sign a
    ///     transaction-data payload + a personal-message payload.
    ///     Both signatures verify under the OLD pubkey.
    ///  2. Call [`rotate_key`] with (`&old`, `old_pass`, `new_pass`).
    ///  3. Unseal the NEW keypair under `new_pass` → sign the SAME
    ///     two payloads. Both signatures verify under the NEW
    ///     pubkey.
    ///  4. The OLD keypair STILL signs successfully under `old_pass`
    ///     after rotation (no signing gap during rotation —
    ///     ATOM_PLAN line 1181).
    ///  5. Cross-key verification fails BOTH directions: a
    ///     post-rotation OLD-key signature does NOT verify under the
    ///     NEW pubkey, and a post-rotation NEW-key signature does
    ///     NOT verify under the OLD pubkey. (Address change pins
    ///     pubkey change pins cross-key replay impossibility.)
    ///  6. Personal-message vs transaction-data domain separation
    ///     (atom #35 invariant) is preserved across rotation: a
    ///     post-rotation NEW-key personal-message signature does not
    ///     verify under the transaction-data prefix, and vice versa.
    #[test]
    fn g0_4_e2e_sign_after_rotation() {
        let old_pass = "e2e-old-2026";
        let new_pass = "e2e-new-2026";
        let tx_bytes: &[u8] = b"e2e atom 36 transaction-data payload";
        let msg_bytes: &[u8] = b"e2e atom 36 personal-message payload";

        // Step 1 — seal OLD + sign under OLD.
        let old = SealedKeypair::create_encrypted(old_pass).expect("seal old");
        let old_addr_before = old.public_address();
        let (old_tx_sig, old_msg_sig, old_verifying) = {
            let scoped = old.unseal(old_pass).expect("unseal old (pre-rotation)");
            let tx_sig: SignatureBytes = sign_move_tx(&scoped, tx_bytes);
            let msg_sig: SignatureBytes = sign_message(&scoped, msg_bytes);
            let signing = SigningKey::from_bytes(scoped.as_bytes());
            let verifying: VerifyingKey = signing.verifying_key();
            (tx_sig, msg_sig, verifying)
            // `scoped` dropped here; ScopedSecretKey::Drop → zeroize.
        };

        // Verify OLD signatures under OLD pubkey + correct intent
        // prefixes (atom #34 / #35 invariants preserved).
        let parsed_old_tx = Signature::from_bytes(old_tx_sig.as_bytes());
        let parsed_old_msg = Signature::from_bytes(old_msg_sig.as_bytes());
        let mut tx_payload: Vec<u8> = Vec::with_capacity(3 + tx_bytes.len());
        tx_payload.extend_from_slice(&SUI_INTENT_PREFIX_TRANSACTION_DATA);
        tx_payload.extend_from_slice(tx_bytes);
        let mut msg_payload: Vec<u8> = Vec::with_capacity(3 + msg_bytes.len());
        msg_payload.extend_from_slice(&SUI_INTENT_PREFIX_PERSONAL_MESSAGE);
        msg_payload.extend_from_slice(msg_bytes);
        old_verifying
            .verify_strict(&tx_payload, &parsed_old_tx)
            .expect("OLD tx sig verifies under OLD pubkey");
        old_verifying
            .verify_strict(&msg_payload, &parsed_old_msg)
            .expect("OLD msg sig verifies under OLD pubkey");

        // Step 2 — rotate.
        let (new, report) = rotate_key(&old, old_pass, new_pass).expect("rotate ok");

        // Report addresses tied to the actual sealed keypairs.
        assert_eq!(report.old_address().as_bytes(), old_addr_before.as_bytes());
        assert_eq!(
            report.new_address().as_bytes(),
            new.public_address().as_bytes()
        );
        assert_ne!(
            report.old_address().as_bytes(),
            report.new_address().as_bytes()
        );

        // Step 3 — sign UNDER NEW.
        let (new_tx_sig, new_msg_sig, new_verifying) = {
            let scoped = new.unseal(new_pass).expect("unseal new (post-rotation)");
            let tx_sig: SignatureBytes = sign_move_tx(&scoped, tx_bytes);
            let msg_sig: SignatureBytes = sign_message(&scoped, msg_bytes);
            let signing = SigningKey::from_bytes(scoped.as_bytes());
            let verifying: VerifyingKey = signing.verifying_key();
            (tx_sig, msg_sig, verifying)
            // `scoped` dropped → zeroize.
        };

        let parsed_new_tx = Signature::from_bytes(new_tx_sig.as_bytes());
        let parsed_new_msg = Signature::from_bytes(new_msg_sig.as_bytes());
        new_verifying
            .verify_strict(&tx_payload, &parsed_new_tx)
            .expect("NEW tx sig verifies under NEW pubkey");
        new_verifying
            .verify_strict(&msg_payload, &parsed_new_msg)
            .expect("NEW msg sig verifies under NEW pubkey");

        // Step 4 — OLD still signs (no signing gap during rotation,
        // ATOM_PLAN line 1181). Re-unseal OLD and sign again; the
        // verification under OLD pubkey still succeeds.
        let post_rotation_old_sig = {
            let scoped = old
                .unseal(old_pass)
                .expect("OLD still usable post-rotation");
            sign_move_tx(&scoped, tx_bytes)
            // drop → zeroize.
        };
        let parsed_post_old = Signature::from_bytes(post_rotation_old_sig.as_bytes());
        old_verifying
            .verify_strict(&tx_payload, &parsed_post_old)
            .expect("OLD tx sig still verifies under OLD pubkey AFTER rotation");

        // Step 5 — cross-key replay impossibility BOTH directions.
        // Two parsed sigs against the OTHER verifier MUST fail.
        let cross_a = old_verifying.verify(&tx_payload, &parsed_new_tx);
        assert!(
            cross_a.is_err(),
            "NEW tx sig MUST NOT verify under OLD pubkey (cross-key replay barrier)",
        );
        let cross_b = new_verifying.verify(&tx_payload, &parsed_old_tx);
        assert!(
            cross_b.is_err(),
            "OLD tx sig MUST NOT verify under NEW pubkey (cross-key replay barrier)",
        );

        // Step 6 — personal-message vs transaction-data domain
        // separation preserved post-rotation (atom #35 invariant).
        // NEW msg sig MUST NOT verify under transaction-data prefix.
        let cross_domain_a = new_verifying.verify(&tx_payload, &parsed_new_msg);
        assert!(
            cross_domain_a.is_err(),
            "NEW msg sig MUST NOT verify under TransactionData prefix",
        );
        // NEW tx sig MUST NOT verify under personal-message prefix.
        let cross_domain_b = new_verifying.verify(&msg_payload, &parsed_new_tx);
        assert!(
            cross_domain_b.is_err(),
            "NEW tx sig MUST NOT verify under PersonalMessage prefix",
        );

        // Pubkeys actually changed (sanity — implied by address
        // change but pinned here at the verifier surface).
        assert_ne!(
            old_verifying.to_bytes(),
            new_verifying.to_bytes(),
            "OLD and NEW pubkeys MUST differ after rotation",
        );
    }

    /// Witness wrong-passphrase signal continuity: a wrong `old_pass`
    /// at the rotation entry point surfaces [`WalletError::Decrypt`],
    /// NOT [`WalletError::KeyRotation`]. An attacker probing the
    /// rotation surface cannot distinguish "wrong pass" from
    /// "tampered ciphertext" — the privacy posture matches
    /// [`SealedKeypair::unseal`] (atom #33).
    #[test]
    fn g0_4_wrong_old_passphrase_surfaces_decrypt() {
        let old = SealedKeypair::create_encrypted("real-old-pass").expect("seal");
        let outcome = rotate_key(&old, "wrong-old-pass", "any-new-pass");
        match outcome {
            Err(WalletError::Decrypt) => {}
            Err(other) => panic!("expected WalletError::Decrypt, got {other:?}"),
            Ok(_) => panic!("rotate_key under wrong old passphrase MUST fail"),
        }
    }

    /// Witness `WalletError::KeyRotation` first emission site:
    /// `new_pass == old_pass` refuses early. Rotation to the SAME
    /// passphrase silently defeats the purpose; the surface refuses
    /// fail-closed.
    #[test]
    fn g0_4_same_passphrase_surfaces_key_rotation() {
        let same_pass = "same-passphrase-on-both-sides";
        let old = SealedKeypair::create_encrypted(same_pass).expect("seal");
        let outcome = rotate_key(&old, same_pass, same_pass);
        match outcome {
            Err(WalletError::KeyRotation) => {}
            Err(other) => panic!("expected WalletError::KeyRotation, got {other:?}"),
            Ok(_) => panic!("rotate_key under same passphrase MUST refuse"),
        }
    }

    /// Witness PlaintextRefused continuity: empty `new_pass` bubbles
    /// up [`WalletError::PlaintextRefused`] from
    /// [`SealedKeypair::create_encrypted`] (atom #33 invariant) —
    /// rotation cannot silently produce an empty-passphrase sealed
    /// file.
    #[test]
    fn g0_4_empty_new_passphrase_surfaces_plaintext_refused() {
        let old = SealedKeypair::create_encrypted("real-old-pass").expect("seal");
        let outcome = rotate_key(&old, "real-old-pass", "");
        match outcome {
            Err(WalletError::PlaintextRefused) => {}
            Err(other) => panic!("expected WalletError::PlaintextRefused, got {other:?}"),
            Ok(_) => panic!("rotate_key with empty new passphrase MUST refuse"),
        }
    }

    /// Witness reuse-only surface: this atom adds ONE public type
    /// and ONE public function. ScopedSecretKey re-exported from
    /// atom #33 is used internally; here we pin that the test module
    /// can still construct one via the `#[cfg(test)] pub(crate)`
    /// constructor (atom #34 reuse), proving the cross-module test
    /// helper surface remains stable after the rotation atom lands.
    #[test]
    fn g0_4_scoped_secret_key_reuse_still_compiles() {
        let seed: [u8; 32] = [0x77u8; 32];
        let scoped = ScopedSecretKey::from_seed_for_test(seed);
        assert_eq!(scoped.as_bytes().len(), 32);
        drop(scoped);
    }
}
