//! Sign Sui *personal-message* intents with the borrowed
//! ed25519 secret seed from the [`ScopedSecretKey`].
//!
//! Canonical shape:
//!
//! ```rust,ignore
//! pub fn sign_message(key: &ScopedSecretKey, message: &[u8]) -> SignatureBytes;
//! ```
//!
//! ## Design notes
//!
//! **Personal-message intent prefix — domain-separated from transaction
//! data.** Sui's signing convention prepends a 3-byte `IntentMessage`
//! header `[IntentScope, IntentVersion::V0=0, AppId::Sui=0]` to the
//! signed payload. [`crate::sign_tx`] pinned the
//! `IntentScope::TransactionData=0` prefix
//! ([`SUI_INTENT_PREFIX_TRANSACTION_DATA`](crate::sign_tx::SUI_INTENT_PREFIX_TRANSACTION_DATA)
//! = `[0,0,0]`) so transaction signatures cannot be replayed under any
//! other intent scope. This module pins the **distinct**
//! `IntentScope::PersonalMessage=3` prefix
//! ([`SUI_INTENT_PREFIX_PERSONAL_MESSAGE`] = `[3,0,0]`) so a signature
//! produced by [`sign_message`] CANNOT verify against the prefixed
//! payload [`crate::sign_tx::sign_move_tx`] would have produced, and
//! vice versa. Cross-domain replay (a personal-message signature being
//! accepted by a Sui validator as a transaction signature, or the
//! mirror direction) is structurally impossible at this entry point —
//! the prefix bytes are compile-time constants and cannot be supplied
//! (or omitted) by the caller.
//!
//! **Placeholder → real signing path.** The
//! returned [`SignatureBytes`] is byte-identical to the
//! [`SignaturePlaceholderV1::signature`] field declared in
//! `c-walrus::codec`. Callers that hold a placeholder envelope (e.g. a
//! [`ChunkEnvelopeV1`](mnemos_c_walrus::ChunkEnvelopeV1) decoded with a
//! `signature: Some(SignaturePlaceholderV1 { signature: SignatureBytes([0;64]), .. })`)
//! finalise it by replacing the placeholder bytes with the real signing
//! output of this function — there is exactly one 64-byte signature
//! shape across the C / G domain boundary (no parallel
//! `PersonalMessageSignature` type is declared here). The
//! `g0_3_signs_message_vector` test witnesses this placeholder → real
//! substitution path end-to-end.
//!
//! **Reuse, not parallel definition.** This module declares **zero**
//! new public type. The returned signature is the c-walrus
//! [`SignatureBytes`]; the secret-seed accessor is the
//! [`ScopedSecretKey::as_bytes`] borrow; the signing primitive is
//! `ed25519_dalek::SigningKey::sign` (already a transitive workspace
//! dep via [`crate::sign_tx`], no new dep added).
//!
//! **Gas-only bot wallet — message surface is opaque.** This
//! signing surface, like [`crate::sign_tx`], takes ONLY `message: &[u8]` (opaque
//! blob). No coin-transfer / treasury-cap / withdraw / mint / pay-user
//! custody identifier is constructed or referenced anywhere in this
//! module. The bot wallet's user-funds-surface absence is preserved
//! source-of-bytes-upstream (the caller supplies what it intends to
//! sign as a personal message; this function does not parse or
//! interpret the bytes). The `g0_3_message_domain_separated_from_tx`
//! test grep-pins the user-funds-surface absence at the source level.
//!
//! **No `WalletError::Sign` emission.** The canonical signature
//! `-> SignatureBytes` is total by design — every Sui
//! personal-message length is admissible at the ed25519 primitive
//! layer (length checks, if any, are a Sui validator concern, not a
//! signing-side concern), and [`ScopedSecretKey`] only exists after a
//! successful `SealedKeypair::unseal` or `#[cfg(test)]` constructor.
//! `WalletError::Sign` therefore continues to be *declared but not yet
//! emitted* — the same declared-but-reserved precedent is reused; the
//! same no-emission precedent from [`crate::sign_tx`] is extended.
//!
//! **Optional Sui personal-message BCS wrapping is the caller's
//! responsibility.** Sui's off-chain `IntentMessage<PersonalMessage>`
//! verifier wraps the message in
//! `PersonalMessage { message: Vec<u8> }` and BCS-encodes it
//! (`ULEB128(len) || bytes`) before prepending the 3-byte intent
//! prefix. This module does NOT impose that BCS wrapping inside
//! [`sign_message`]: the `message: &[u8]` argument is treated as
//! opaque, mirroring [`crate::sign_tx`]'s `intent_tx_bytes: &[u8]` opaque
//! contract (the BCS shaping is upstream of the signing surface in
//! both modules). A future addition that wires the off-chain Sui personal-
//! message verifier into mnemos will own the BCS-wrap step; until
//! then, callers that need the Sui-canonical wire form must wrap the
//! payload before calling this function. The mnemos-internal
//! placeholder → real path (the dominant Phase 0 use case) does not
//! require BCS wrapping — the signature simply needs to be reproducible
//! by the verifier, which uses the same `(key, message)` pair.

#![forbid(unsafe_code)]

use ed25519_dalek::{Signature, Signer, SigningKey};
use mnemos_c_walrus::SignatureBytes;

use crate::keystore::ScopedSecretKey;
use crate::sign_tx::SUI_INTENT_PREFIX_BYTES;

/// Sui `IntentScope::PersonalMessage` discriminant byte. Pinned as a
/// typed constant so the cross-domain replay barrier — distinct from
/// [`crate::sign_tx`]'s `IntentScope::TransactionData=0` — is documented
/// at one canonical source.
pub const SUI_INTENT_SCOPE_PERSONAL_MESSAGE: u8 = 3;

/// Sui intent prefix for a `PersonalMessage`:
/// `[IntentScope::PersonalMessage=3, IntentVersion::V0=0, AppId::Sui=0]`.
/// Pinned as a compile-time constant — callers cannot pass an
/// alternate scope / version / app-id, so cross-scope replay against
/// `IntentScope::TransactionData` (the [`crate::sign_tx`] surface,
/// [`SUI_INTENT_PREFIX_TRANSACTION_DATA`](crate::sign_tx::SUI_INTENT_PREFIX_TRANSACTION_DATA)
/// = `[0,0,0]`) is structurally impossible at this entry point.
pub const SUI_INTENT_PREFIX_PERSONAL_MESSAGE: [u8; SUI_INTENT_PREFIX_BYTES] =
    [SUI_INTENT_SCOPE_PERSONAL_MESSAGE, 0, 0];

/// Compile-time pin: the personal-message intent prefix has exactly 3
/// bytes (the same width [`crate::sign_tx`] pinned for the transaction-data
/// prefix). A future edit that widens / narrows the prefix on one side
/// without the other would fail to build here before any test runs.
const _SUI_INTENT_PREFIX_PERSONAL_MESSAGE_LEN_IS_3: [(); 0 - !(SUI_INTENT_PREFIX_PERSONAL_MESSAGE
    .len()
    == SUI_INTENT_PREFIX_BYTES)
    as usize] = [];

/// Compile-time pin: the personal-message intent prefix and the
/// transaction-data intent prefix MUST differ in at least one byte —
/// otherwise the domain-separation invariant collapses (the same
/// signature would verify under both scopes). The differing byte is
/// the first one (3 vs 0); this assertion proves it byte-wise so a
/// future edit that aligns the two prefixes is a compile error.
const _SUI_INTENT_PREFIX_DOMAINS_DIFFER: [(); 0 - !(SUI_INTENT_PREFIX_PERSONAL_MESSAGE[0]
    != crate::sign_tx::SUI_INTENT_PREFIX_TRANSACTION_DATA[0])
    as usize] = [];

/// Sign a Sui personal-message payload with the borrowed ed25519
/// secret seed.
///
/// The function prepends the canonical 3-byte Sui intent prefix
/// (`[IntentScope::PersonalMessage=3, IntentVersion::V0=0, AppId::Sui=0]`)
/// to `message` and hands the result to
/// [`ed25519_dalek::SigningKey::sign`]. The returned
/// [`SignatureBytes`] is the raw 64-byte ed25519 signature — the
/// signature-scheme flag and the public key are NOT bound into the
/// returned bytes (those layers belong to a downstream wire form, when
/// one is wired in).
///
/// `key`'s 32-byte seed is borrowed for the duration of this call
/// only; the underlying buffer is zeroized when the caller's
/// [`ScopedSecretKey`] drops. No copy of the seed escapes this
/// function — `SigningKey::from_bytes` copies the seed into the
/// ed25519-dalek internal state, which itself zeroizes on drop
/// (ed25519-dalek 2.x default; same precedent as [`crate::sign_tx`]).
///
/// Total over `&[u8]` — the function returns [`SignatureBytes`]
/// directly, not `Result<_, WalletError>`. The Sui validator-side
/// personal-message length / shape checks (and any BCS-wrap concerns)
/// live in the *caller*; this module keeps the signing surface opaque
/// over the message bytes, matching [`crate::sign_tx`]'s opaque-`intent_tx_bytes`
/// contract.
#[must_use]
pub fn sign_message(key: &ScopedSecretKey, message: &[u8]) -> SignatureBytes {
    let signing = SigningKey::from_bytes(key.as_bytes());

    // Assemble `intent_prefix(3) || message(N)`. The prefix is a
    // compile-time constant so the byte layout cannot drift from
    // SUI_INTENT_PREFIX_PERSONAL_MESSAGE; the first byte differs from
    // the transaction-data prefix (proven at compile time above) so a
    // signature produced here cannot verify under that scope.
    let mut intent_msg: Vec<u8> = Vec::with_capacity(SUI_INTENT_PREFIX_BYTES + message.len());
    intent_msg.extend_from_slice(&SUI_INTENT_PREFIX_PERSONAL_MESSAGE);
    intent_msg.extend_from_slice(message);

    let signature: Signature = signing.sign(&intent_msg);
    SignatureBytes(signature.to_bytes())
}

#[cfg(test)]
mod tests {
    // Test helpers prefer direct failure surfaces (`expect` / `assert`)
    // over `Result`-bubbling; suppress prod-only clippy denies inside
    // this module (same precedent as elsewhere in this crate).
    #![allow(clippy::unwrap_used)]
    #![allow(clippy::expect_used)]
    #![allow(clippy::panic)]

    use super::*;
    use crate::sign_tx::{SUI_INTENT_PREFIX_TRANSACTION_DATA, sign_move_tx};
    use ed25519_dalek::{Signature, SigningKey, Verifier, VerifyingKey};
    use mnemos_c_walrus::{SignaturePlaceholderV1, SignatureScheme};

    /// `g0_3_signs_message_vector`.
    ///
    /// Deterministic test vector: fixed 32-byte seed + fixed personal-
    /// message payload. Witnesses three properties:
    ///
    ///  1. The produced signature verifies under the derived ed25519
    ///     public key when the verifier reconstructs the SAME personal-
    ///     message-prefixed payload (positive case).
    ///  2. The same signature MUST FAIL verification when the verifier
    ///     presents `message` WITHOUT the personal-message intent
    ///     prefix — proving the 3-byte prefix is actually mixed into
    ///     the message digest.
    ///  3. The returned `SignatureBytes` substitutes byte-for-byte for
    ///     the `signature` field of a c-walrus
    ///     `SignaturePlaceholderV1` (the placeholder → real path),
    ///     with the surrounding placeholder
    ///     verifying as a well-formed structure (scheme = Ed25519,
    ///     public_key = derived ed25519 pubkey).
    #[test]
    fn g0_3_signs_message_vector() {
        // Fixed seed — distinct from `crate::sign_tx`'s vector seed to keep
        // the two test vectors independent (so a future cross-test
        // regression cannot accidentally satisfy both).
        let seed: [u8; 32] = [
            0xa0, 0xb1, 0xc2, 0xd3, 0xe4, 0xf5, 0x06, 0x17, //
            0x28, 0x39, 0x4a, 0x5b, 0x6c, 0x7d, 0x8e, 0x9f, //
            0x10, 0x21, 0x32, 0x43, 0x54, 0x65, 0x76, 0x87, //
            0x98, 0xa9, 0xba, 0xcb, 0xdc, 0xed, 0xfe, 0x0f,
        ];
        let key = ScopedSecretKey::from_seed_for_test(seed);
        // Representative personal-message payload (UTF-8 prose so the
        // test vector is human-readable while remaining a bare `&[u8]`
        // at the signing surface).
        let message: &[u8] = b"mnemos::g_wallet::sign_message personal-message vector";

        let sig: SignatureBytes = sign_message(&key, message);
        let sig_bytes: &[u8; 64] = sig.as_bytes();

        // Width invariant: ed25519 signature is exactly 64 bytes.
        assert_eq!(sig_bytes.len(), 64);
        assert_eq!(core::mem::size_of::<SignatureBytes>(), 64);

        // Reconstruct verifier-side context and verify the signature.
        let signing = SigningKey::from_bytes(&seed);
        let verifying: VerifyingKey = signing.verifying_key();
        let parsed: Signature = Signature::from_bytes(sig_bytes);

        let mut intent_msg: Vec<u8> = Vec::with_capacity(3 + message.len());
        intent_msg.extend_from_slice(&SUI_INTENT_PREFIX_PERSONAL_MESSAGE);
        intent_msg.extend_from_slice(message);

        // Positive: same personal-message prefix + same payload MUST
        // verify under the derived pubkey.
        verifying
            .verify_strict(&intent_msg, &parsed)
            .expect("ed25519 verify under Sui PersonalMessage intent prefix MUST succeed");

        // Negative: the SAME signature against the SAME payload but
        // WITHOUT the personal-message intent prefix MUST FAIL —
        // proves the 3-byte prefix entered the digest.
        let outcome_without_prefix = verifying.verify_strict(message, &parsed);
        assert!(
            outcome_without_prefix.is_err(),
            "ed25519 verify WITHOUT the Sui PersonalMessage intent prefix MUST fail",
        );

        // Placeholder → real path: a c-walrus
        // SignaturePlaceholderV1 finalised with this signature is a
        // well-formed structure with the canonical (scheme, pubkey,
        // signature) triple — the placeholder slot consumes the
        // returned 64-byte blob directly (no re-encoding, no parallel
        // signature type).
        let derived_pubkey: [u8; 32] = verifying.to_bytes();
        let placeholder = SignaturePlaceholderV1 {
            scheme: SignatureScheme::Ed25519,
            public_key: derived_pubkey,
            signature: sig,
        };
        assert_eq!(placeholder.scheme, SignatureScheme::Ed25519);
        assert_eq!(placeholder.public_key, derived_pubkey);
        assert_eq!(placeholder.signature.as_bytes(), sig_bytes);

        // And the placeholder-carried bytes verify the same way the
        // direct bytes do (sanity: the field substitution did not
        // corrupt the signature).
        let parsed_from_placeholder = Signature::from_bytes(placeholder.signature.as_bytes());
        verifying
            .verify_strict(&intent_msg, &parsed_from_placeholder)
            .expect("placeholder.signature MUST verify identically to the direct SignatureBytes");
    }

    /// `g0_3_message_domain_separated_from_tx`.
    ///
    /// Domain-separation invariant — the structural reason for this
    /// module to exist as a distinct entry point from [`crate::sign_tx`].
    /// Pinned across three independent witnesses:
    ///
    ///  1. The personal-message intent prefix differs from the
    ///     transaction-data intent prefix at byte 0 (`3` vs `0`) and
    ///     the constants are typed at the same width (`[u8;3]`). This
    ///     is also pinned at compile time
    ///     (`_SUI_INTENT_PREFIX_DOMAINS_DIFFER`), but a runtime
    ///     witness here lets a future verifier independently confirm
    ///     the invariant without recompiling.
    ///  2. Given the SAME seed and the SAME payload bytes:
    ///     `sign_message` produces a signature that VERIFIES under the
    ///     personal-message-prefixed payload AND FAILS to verify under
    ///     the transaction-data-prefixed payload; `sign_move_tx`
    ///     produces a signature that VERIFIES under the transaction-
    ///     data-prefixed payload AND FAILS to verify under the
    ///     personal-message-prefixed payload. A personal-message
    ///     signature therefore cannot be replayed as a transaction
    ///     signature on a Sui validator, and vice versa.
    ///  3. This module's source carries no user-funds-surface
    ///     identifier (gas-only bot wallet contract). Asserted
    ///     by reading `include_str!("sign_msg.rs")` and grepping a
    ///     `concat!`-assembled needle list (same precedent as
    ///     [`crate::sign_tx`] so the canary does not self-trip on its
    ///     own assertion source).
    #[test]
    fn g0_3_message_domain_separated_from_tx() {
        // Witness 1 — prefix bytes pinned at runtime.
        assert_eq!(SUI_INTENT_PREFIX_PERSONAL_MESSAGE, [3u8, 0u8, 0u8]);
        assert_eq!(SUI_INTENT_PREFIX_TRANSACTION_DATA, [0u8, 0u8, 0u8]);
        assert_eq!(SUI_INTENT_SCOPE_PERSONAL_MESSAGE, 3);
        assert_ne!(
            SUI_INTENT_PREFIX_PERSONAL_MESSAGE[0], SUI_INTENT_PREFIX_TRANSACTION_DATA[0],
            "PersonalMessage and TransactionData intent prefixes MUST differ at byte 0",
        );
        assert_eq!(
            SUI_INTENT_PREFIX_PERSONAL_MESSAGE.len(),
            SUI_INTENT_PREFIX_TRANSACTION_DATA.len(),
            "intent prefixes share the canonical 3-byte width",
        );

        // Witness 2 — cross-domain replay impossibility, both
        // directions, against the SAME seed + SAME payload bytes.
        let seed: [u8; 32] = [0x5a; 32];
        let key = ScopedSecretKey::from_seed_for_test(seed);
        let payload: &[u8] = b"mnemos cross-domain replay barrier payload";

        let sig_msg: SignatureBytes = sign_message(&key, payload);
        let sig_tx: SignatureBytes = sign_move_tx(&key, payload);

        // The two signatures over the same `payload` MUST differ —
        // because the prefixed message that entered the digest
        // differs (only the first byte, but ed25519 cascades that
        // through the entire signature).
        assert_ne!(
            sig_msg.as_bytes(),
            sig_tx.as_bytes(),
            "personal-message signature MUST differ from transaction-data signature over same payload",
        );

        let signing = SigningKey::from_bytes(&seed);
        let verifying: VerifyingKey = signing.verifying_key();
        let parsed_msg: Signature = Signature::from_bytes(sig_msg.as_bytes());
        let parsed_tx: Signature = Signature::from_bytes(sig_tx.as_bytes());

        // Reconstruct both prefixed payloads.
        let mut msg_payload: Vec<u8> = Vec::with_capacity(3 + payload.len());
        msg_payload.extend_from_slice(&SUI_INTENT_PREFIX_PERSONAL_MESSAGE);
        msg_payload.extend_from_slice(payload);

        let mut tx_payload: Vec<u8> = Vec::with_capacity(3 + payload.len());
        tx_payload.extend_from_slice(&SUI_INTENT_PREFIX_TRANSACTION_DATA);
        tx_payload.extend_from_slice(payload);

        // Direction A — personal-message signature.
        verifying
            .verify_strict(&msg_payload, &parsed_msg)
            .expect("sign_message signature MUST verify under PersonalMessage prefix");
        let cross_a = verifying.verify(&tx_payload, &parsed_msg);
        assert!(
            cross_a.is_err(),
            "sign_message signature MUST NOT verify under TransactionData prefix (cross-domain replay)",
        );

        // Direction B — transaction-data signature.
        verifying
            .verify_strict(&tx_payload, &parsed_tx)
            .expect("sign_move_tx signature MUST verify under TransactionData prefix");
        let cross_b = verifying.verify(&msg_payload, &parsed_tx);
        assert!(
            cross_b.is_err(),
            "sign_move_tx signature MUST NOT verify under PersonalMessage prefix (cross-domain replay)",
        );

        // Witness 3 — source-level user-funds-surface absence.
        // Forbidden needles assembled via `concat!` so the test source
        // does NOT contain the verbatim literals (same self-
        // tripping-canary precedent used elsewhere in this crate; needles
        // in CamelCase / snake_case form match the same pattern used by
        // `g0_2_only_gas_wallet_scope`).
        let src = include_str!("sign_msg.rs");
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
                "sign_msg.rs MUST NOT reference user-funds custody surface (found `{needle}`); bot wallet is gas-only (§9.5)",
            );
        }
    }
}
