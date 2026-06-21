//! G.0.2 — sign Sui Move transaction intent messages with the borrowed
//! ed25519 secret seed from atom #33's [`ScopedSecretKey`].
//!
//! Canonical OUT (`MNEMOS_ATOM_PLAN.md` §4.G atom #34):
//!
//! ```rust,ignore
//! pub struct SignatureFlag(u8);     // ed25519 = 0
//! pub fn sign_move_tx(key: &ScopedSecretKey, intent_tx_bytes: &[u8]) -> SignatureBytes;
//! ```
//!
//! ## 광기 (ATOM_PLAN line 1161 + §9.5)
//!
//! **Sui intent prefix.** The Sui transaction-signing convention prepends
//! a 3-byte `IntentMessage` header
//! `[IntentScope::TransactionData=0, IntentVersion::V0=0, AppId::Sui=0]`
//! to the BCS-encoded `TransactionData` before the message reaches the
//! signing primitive. This atom anchors that prefix as
//! [`SUI_INTENT_PREFIX_TRANSACTION_DATA`] and prepends it to the caller-
//! supplied `intent_tx_bytes` inside [`sign_move_tx`] — callers pass
//! only the inner tx-data slice; the prefix is byte-pinned by the
//! function and cannot be supplied (or omitted) by the caller. This
//! enforces, by construction, the structural invariant that every
//! signature this surface emits is over a Sui-intent-prefixed message
//! (cross-domain replay against `IntentScope::PersonalMessage=3` or
//! other scopes is impossible because the prefix bytes are not
//! parameterised).
//!
//! **Reuse, not parallel definition.** The returned signature type is
//! the c-walrus [`SignatureBytes`] from atom #7 (`pub struct
//! SignatureBytes(pub [u8; 64])` in `mnemos_c_walrus::codec`). The G
//! domain does NOT redeclare a parallel 64-byte signature wrapper —
//! every Sui ed25519 signature in mnemos flows through one type so the
//! storage path (c-walrus envelope) and the signing path (g-wallet)
//! agree byte-for-byte.
//!
//! **Gas-only bot wallet (§9.5).** This signing surface is the bot
//! gas wallet's only public entry point for tx signatures. The bot
//! wallet holds **low gas balance only** — no user-funds custody, no
//! treasury access, no coin transfers. The structural invariants here:
//!
//!  - The function takes ONLY `intent_tx_bytes: &[u8]` (opaque blob).
//!    No coin-transfer / treasury-cap / withdraw / mint / pay-user
//!    custody surface is constructed or referenced anywhere in this
//!    module. (Hyphenated lowercase in this prose so the
//!    `g0_2_only_gas_wallet_scope` canary needles —
//!    code-style `CamelCase` and `snake_case::` literals — do NOT
//!    self-trip on the explanatory doc-comment itself; atom #14
//!    self-tripping-canary precedent.)
//!  - The caller-side contract (enforced upstream by atom #20 `d-move`
//!    `SuiCallBuilder::to_dry_run_bytes`) is that
//!    `intent_tx_bytes` was produced by a dry-run-verified
//!    `mnemos::memory_root::add_chunk` call. Atom #34 itself does not
//!    encode that ownership in the type system (the bytes are
//!    intentionally opaque — wrapping them in a typed `DryRunBytes` is
//!    deferred to a future atom that wires the dry-run + sign path
//!    end-to-end). The bot-wallet invariant is preserved by the source
//!    of the bytes, not by re-parsing them here. The `g0_2_only_gas_wallet_scope`
//!    test grep-pins the user-funds-surface absence at the source level.
//!
//! **No `WalletError::Sign` emission.** The canonical OUT signature
//! `-> SignatureBytes` is total — [`ed25519_dalek::SigningKey::sign`]
//! is infallible over `&[u8]` (the ed25519 primitive itself does not
//! reject any message length, and the `SigningKey` is already
//! well-formed because [`ScopedSecretKey`] only exists after a
//! successful `SealedKeypair::unseal` or a `#[cfg(test)]` constructor).
//! `WalletError::Sign` therefore remains *declared but not yet emitted*
//! at this atom (atom #33's declared-but-reserved precedent continues;
//! recorded in `no_op_decisions.jsonl` for Session 2 acceptance).

#![forbid(unsafe_code)]

use ed25519_dalek::{Signature, Signer, SigningKey};
use mnemos_c_walrus::SignatureBytes;

use crate::keystore::ScopedSecretKey;

/// Sui signature-scheme flag for ed25519 keys (canonical OUT §4.G:
/// `SignatureFlag(u8)` with `ed25519 = 0`). The flag itself is NOT
/// prepended to the 64-byte signature returned by [`sign_move_tx`] —
/// it is exposed as a typed constant so future Stage G atoms that need
/// the prefixed wire form (e.g. authority-signature serialisation,
/// `flag || signature || pubkey`) read the flag byte from one
/// canonical source.
pub const SUI_SIGNATURE_FLAG_ED25519: u8 = 0x00;

/// Byte width of the Sui intent prefix.
pub const SUI_INTENT_PREFIX_BYTES: usize = 3;

/// Sui intent prefix for a `TransactionData` message:
/// `[IntentScope::TransactionData=0, IntentVersion::V0=0, AppId::Sui=0]`.
/// Pinned as a compile-time constant — callers cannot pass an
/// alternate scope / version / app-id, so cross-scope replay against
/// `IntentScope::PersonalMessage` (atom #35 surface) is structurally
/// impossible at this entry point.
pub const SUI_INTENT_PREFIX_TRANSACTION_DATA: [u8; SUI_INTENT_PREFIX_BYTES] = [0, 0, 0];

/// Byte width of an ed25519 signature.
pub const SIGNATURE_BYTES: usize = 64;

/// Compile-time pin: the c-walrus `SignatureBytes` payload width must
/// equal 64. If atom #7 ever re-widens the signature byte array, this
/// fails the build before any test runs — the G domain refuses to
/// silently re-cast a wider blob.
const _G_WALLET_SIGNATURE_WIDTH_PIN: [(); 0 - !(core::mem::size_of::<SignatureBytes>()
    == SIGNATURE_BYTES) as usize] = [];

/// Compile-time pin: the Sui intent prefix has exactly 3 bytes.
const _SUI_INTENT_PREFIX_LEN_IS_3: [(); 0 - !(SUI_INTENT_PREFIX_TRANSACTION_DATA.len()
    == SUI_INTENT_PREFIX_BYTES) as usize] = [];

/// Sui signature-scheme flag byte (canonical OUT §4.G). `repr(transparent)`
/// over `u8` so `size_of::<SignatureFlag>() == 1`. The wrapper exists so
/// future call sites that prepend the scheme flag to a serialised
/// authority signature read the byte through one typed surface rather
/// than passing a bare `u8` that could be confused with the discriminant
/// of any other 1-byte enum on the Sui wire.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
#[repr(transparent)]
pub struct SignatureFlag(u8);

impl SignatureFlag {
    /// ed25519 scheme flag (`0x00`). The Sui spec reserves `0x01` for
    /// Secp256k1 and `0x02` for Secp256r1; only ed25519 is in scope for
    /// the Phase 0 bot wallet (§9.5).
    pub const ED25519: Self = Self(SUI_SIGNATURE_FLAG_ED25519);

    /// Wrap an arbitrary flag byte. Reserved for future schemes —
    /// atom #34 itself only ever constructs [`SignatureFlag::ED25519`].
    #[inline]
    #[must_use]
    pub const fn new(byte: u8) -> Self {
        Self(byte)
    }

    /// Borrow the underlying flag byte.
    #[inline]
    #[must_use]
    pub const fn as_byte(self) -> u8 {
        self.0
    }
}

/// Sign Sui Move transaction intent bytes with the borrowed ed25519
/// secret seed.
///
/// The function prepends the canonical 3-byte Sui intent prefix
/// (`[IntentScope::TransactionData, IntentVersion::V0, AppId::Sui] = [0,0,0]`)
/// to `intent_tx_bytes` and hands the result to
/// [`ed25519_dalek::SigningKey::sign`]. The returned
/// [`SignatureBytes`] is the raw 64-byte ed25519 signature — the
/// signature-scheme flag ([`SignatureFlag::ED25519`]) and the public
/// key are NOT bound into the returned bytes (those layers belong to
/// the serialised authority-signature wire form, which is built by a
/// downstream caller).
///
/// `key`'s 32-byte seed is borrowed for the duration of this call
/// only; the underlying buffer is zeroized when the caller's
/// [`ScopedSecretKey`] drops. No copy of the seed escapes this
/// function — `SigningKey::from_bytes` copies the seed into the
/// ed25519-dalek internal state, which itself zeroizes on drop
/// (ed25519-dalek 2.x default).
///
/// Total over `&[u8]` — the function returns [`SignatureBytes`]
/// directly, not `Result<_, WalletError>`. The Sui validator-side
/// `intent_tx_bytes` length / shape checks live in the *caller* (atom
/// #20 `d-move` dry-run + future intent-builder atom).
#[must_use]
pub fn sign_move_tx(key: &ScopedSecretKey, intent_tx_bytes: &[u8]) -> SignatureBytes {
    let signing = SigningKey::from_bytes(key.as_bytes());

    // Assemble `intent_prefix(3) || intent_tx_bytes(N)`. The prefix is
    // a compile-time constant so the byte layout cannot drift from
    // SUI_INTENT_PREFIX_TRANSACTION_DATA.
    let mut intent_msg: Vec<u8> =
        Vec::with_capacity(SUI_INTENT_PREFIX_BYTES + intent_tx_bytes.len());
    intent_msg.extend_from_slice(&SUI_INTENT_PREFIX_TRANSACTION_DATA);
    intent_msg.extend_from_slice(intent_tx_bytes);

    let signature: Signature = signing.sign(&intent_msg);
    SignatureBytes(signature.to_bytes())
}

#[cfg(test)]
mod tests {
    // Test helpers prefer direct failure surfaces (`expect` / `assert`)
    // over `Result`-bubbling; suppress prod-only clippy denies inside
    // this module (atom #33 precedent).
    #![allow(clippy::unwrap_used)]
    #![allow(clippy::expect_used)]
    #![allow(clippy::panic)]

    use super::*;
    use ed25519_dalek::{Signature, SigningKey, Verifier, VerifyingKey};

    /// `g0_2_signs_known_intent_vector` (ATOM_PLAN line 1162).
    ///
    /// Deterministic test vector: fixed 32-byte seed + fixed
    /// `intent_tx_bytes` slice. The produced signature MUST verify
    /// under the derived ed25519 public key when the verifier
    /// reconstructs the SAME intent-prefixed message; the SAME
    /// signature MUST FAIL verification when the verifier presents
    /// `intent_tx_bytes` WITHOUT the Sui intent prefix — proving the
    /// 3-byte prefix is actually mixed into the message digest.
    #[test]
    fn g0_2_signs_known_intent_vector() {
        // Fixed seed — chosen non-zero so the derived pubkey is not a
        // degenerate edge case.
        let seed: [u8; 32] = [
            0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, //
            0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, //
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, //
            0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
        ];
        let key = ScopedSecretKey::from_seed_for_test(seed);
        // Representative dry-run-style payload (the actual atom #20
        // dry-run is 166 bytes; the signature test does not depend on
        // length so a shorter pinned slice keeps the test source
        // self-contained).
        let intent_tx_bytes: &[u8] = b"mnemos::memory_root::add_chunk:dry-run-bytes";

        let sig: SignatureBytes = sign_move_tx(&key, intent_tx_bytes);
        let sig_bytes: &[u8; 64] = sig.as_bytes();

        // Width invariant: ed25519 signature is exactly 64 bytes.
        assert_eq!(sig_bytes.len(), 64);
        assert_eq!(core::mem::size_of::<SignatureBytes>(), 64);

        // Reconstruct verifier-side context and verify the signature.
        let signing = SigningKey::from_bytes(&seed);
        let verifying: VerifyingKey = signing.verifying_key();
        let parsed: Signature = Signature::from_bytes(sig_bytes);

        let mut intent_msg: Vec<u8> = Vec::with_capacity(3 + intent_tx_bytes.len());
        intent_msg.extend_from_slice(&SUI_INTENT_PREFIX_TRANSACTION_DATA);
        intent_msg.extend_from_slice(intent_tx_bytes);

        // Positive: same prefix + same payload MUST verify.
        verifying
            .verify_strict(&intent_msg, &parsed)
            .expect("ed25519 verify under Sui intent prefix MUST succeed");

        // Negative: the SAME signature against the SAME payload but
        // WITHOUT the intent prefix MUST FAIL. Proves the 3-byte
        // prefix actually entered the message digest.
        let outcome_without_prefix = verifying.verify_strict(intent_tx_bytes, &parsed);
        assert!(
            outcome_without_prefix.is_err(),
            "ed25519 verify WITHOUT the Sui intent prefix MUST fail (else the prefix was not bound to the digest)",
        );

        // Negative: a different intent prefix MUST also fail (canary
        // against silent scope drift to e.g. PersonalMessage = 3).
        let mut wrong_scope: Vec<u8> = Vec::with_capacity(3 + intent_tx_bytes.len());
        wrong_scope.extend_from_slice(&[3u8, 0u8, 0u8]); // PersonalMessage
        wrong_scope.extend_from_slice(intent_tx_bytes);
        let outcome_wrong_scope = verifying.verify(&wrong_scope, &parsed);
        assert!(
            outcome_wrong_scope.is_err(),
            "ed25519 verify under a non-TransactionData intent scope MUST fail",
        );
    }

    /// `g0_2_signature_is_64_bytes` (ATOM_PLAN line 1162).
    ///
    /// Width invariant on the returned signature. Pinned across two
    /// independent inputs (empty payload + non-empty payload) so a
    /// future regression that returns the prefixed-form
    /// `flag || signature || pubkey = 97` bytes (Sui authority
    /// signature) would surface here, not in the validator at
    /// submission time.
    #[test]
    fn g0_2_signature_is_64_bytes() {
        let seed: [u8; 32] = [7u8; 32];
        let key = ScopedSecretKey::from_seed_for_test(seed);

        let sig_empty = sign_move_tx(&key, b"");
        assert_eq!(sig_empty.as_bytes().len(), 64);

        let sig_payload = sign_move_tx(&key, b"non-empty-dry-run-payload");
        assert_eq!(sig_payload.as_bytes().len(), 64);

        // Type-level pin (would catch a future re-shape of
        // `SignatureBytes` to a heap-backed `Vec<u8>` or a different
        // fixed width).
        assert_eq!(core::mem::size_of::<SignatureBytes>(), 64);
        assert_eq!(SIGNATURE_BYTES, 64);
    }

    /// `g0_2_only_gas_wallet_scope` (ATOM_PLAN line 1162).
    ///
    /// Bot wallet = gas-only low balance (§9.5). The Phase 0 signing
    /// surface MUST NOT reference any user-funds custody primitives.
    /// This test reads the on-disk source of `sign_tx.rs` itself and
    /// asserts the absence of user-funds-surface identifiers. The
    /// forbidden needles are assembled via `concat!` so the test
    /// source does NOT contain the verbatim literals (otherwise the
    /// canary would match its own assertion).
    #[test]
    fn g0_2_only_gas_wallet_scope() {
        let src = include_str!("sign_tx.rs");

        // User-funds-surface identifiers banned from this module.
        let forbidden: [&str; 7] = [
            concat!("coin", "::transfer"),
            concat!("Treasury", "Cap"),
            concat!("::mint", "_to"),
            concat!("withdraw_", "user"),
            concat!("pay_", "user"),
            concat!("user_", "funds"),
            concat!("transfer_", "coins"),
        ];
        for needle in forbidden {
            assert!(
                !src.contains(needle),
                "sign_tx.rs MUST NOT reference user-funds custody surface (found `{needle}`); bot wallet is gas-only (§9.5)",
            );
        }

        // Functional witness: the canonical signing entry point
        // accepts only the opaque `intent_tx_bytes: &[u8]` produced
        // upstream by atom #20 d-move dry-run; the bot wallet sees no
        // typed coin / treasury argument. Construct a payload that
        // mimics the 166-byte dry-run shape and confirm it round-
        // trips through `sign_move_tx` without panic and without
        // widening the API surface.
        let seed: [u8; 32] = [0x42u8; 32];
        let key = ScopedSecretKey::from_seed_for_test(seed);
        let dry_run_like: Vec<u8> = (0u8..166u8).collect(); // exactly 166 bytes
        let sig = sign_move_tx(&key, &dry_run_like);
        assert_eq!(sig.as_bytes().len(), 64);

        let signing = SigningKey::from_bytes(&seed);
        let verifying = signing.verifying_key();
        let parsed = Signature::from_bytes(sig.as_bytes());
        let mut intent_msg: Vec<u8> = Vec::with_capacity(3 + dry_run_like.len());
        intent_msg.extend_from_slice(&SUI_INTENT_PREFIX_TRANSACTION_DATA);
        intent_msg.extend_from_slice(&dry_run_like);
        verifying
            .verify_strict(&intent_msg, &parsed)
            .expect("dry-run-shape payload signature MUST verify under derived pubkey");
    }

    /// Witness that [`SignatureFlag::ED25519`] is exactly the byte
    /// `0x00` — the Sui ed25519 scheme flag.
    #[test]
    fn g0_2_signature_flag_ed25519_is_zero() {
        assert_eq!(SignatureFlag::ED25519.as_byte(), 0x00);
        assert_eq!(SUI_SIGNATURE_FLAG_ED25519, 0x00);
        assert_eq!(core::mem::size_of::<SignatureFlag>(), 1);
    }

    /// Witness that the Sui intent prefix is exactly
    /// `[TransactionData=0, V0=0, Sui=0]` — three bytes, all zero.
    #[test]
    fn g0_2_intent_prefix_is_transaction_data_v0_sui() {
        assert_eq!(SUI_INTENT_PREFIX_TRANSACTION_DATA, [0u8, 0u8, 0u8]);
        assert_eq!(SUI_INTENT_PREFIX_BYTES, 3);
    }
}
