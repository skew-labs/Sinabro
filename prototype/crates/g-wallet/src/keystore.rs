//! G.0.1 — sealed Sui keypair with at-rest authenticated encryption.
//!
//! Canonical OUT (`MNEMOS_ATOM_PLAN.md` §4.G atom #33):
//!
//! ```rust,ignore
//! pub struct SealedKeypair {
//!     ciphertext: Vec<u8>,
//!     kdf_salt: [u8; 16],
//!     nonce:    [u8; 24],
//! }
//! pub struct ScopedSecretKey([u8; 32]);    // Drop-zeroize, no Debug/Display/Clone/serde
//! pub enum WalletError { Decrypt, Sign, KeyRotation, PlaintextRefused }
//! impl SealedKeypair {
//!     pub fn create_encrypted(passphrase: &str) -> Result<Self, WalletError>;
//!     pub fn unseal(&self, passphrase: &str) -> Result<ScopedSecretKey, WalletError>;
//!     pub fn public_address(&self) -> SuiAddress;
//! }
//! ```
//!
//! ## 광기 (ATOM_PLAN line 1148 + §10.3)
//!
//! The secret key value lives on disk **only** as AEAD ciphertext; in
//! memory it lives **only** inside [`ScopedSecretKey`], a wrapper that
//!
//!  - implements `Drop` to call `zeroize::Zeroize::zeroize` on the
//!    32-byte buffer, and
//!  - **does NOT** implement `Debug`, `Display`, `Clone`, `serde`.
//!
//! Trait absence is the load-bearing invariant: `tracing::debug!(?key)`,
//! `format!("{key:?}")`, `let copy = key.clone()`, and
//! `serde_json::to_string(&key)` all fail at *compile time*. Plaintext-key
//! exfiltration through a log line or accidental clone is structurally
//! impossible — there is no code path that even *type-checks*. The
//! compile-time invariant is mechanically pinned in
//! `tests/keystore_trait_absence.rs` via
//! `static_assertions::assert_not_impl_any!`.
//!
//! ## Disparity from prose ("age 암호화") — recorded in `no_op_decisions.jsonl`
//!
//! ATOM_PLAN prose names the `age` crate; the canonical OUT struct
//! signature (`kdf_salt: [u8;16]`, `nonce: [u8;24]`, opaque
//! `ciphertext: Vec<u8>`) is implementation-agnostic over the AEAD
//! primitive. The `age` / `chacha20poly1305` / `argon2` crates are NOT
//! present in the local `~/.cargo/registry/cache/` and the build is
//! gated `--locked --offline`. This atom realises the same on-disk
//! envelope layout with primitives that ARE in the offline cache:
//!
//!  - **KDF**: PBKDF2-HMAC-SHA256, 600 000 iterations (OWASP 2023
//!    baseline for password-based key derivation; deliberately CPU-heavy
//!    so brute-forcing a stolen sealed file is expensive).
//!  - **AEAD**: AES-256-GCM-SIV (RFC 8452, nonce-misuse-resistant
//!    authenticated encryption with a 12-byte AEAD nonce).
//!  - **Stored 24-byte nonce reconciliation**: the 24-byte
//!    `SealedKeypair::nonce` field is split — the trailing 12 bytes are
//!    fed to AES-GCM-SIV as the AEAD nonce, and the leading 12 bytes are
//!    bound into the authenticated associated data (AAD) so that the
//!    full 24 bytes participate in tag verification. This preserves the
//!    canonical 24-byte stored-nonce surface and binds it to the
//!    ciphertext byte-for-byte.
//!  - **Public-key co-location**: the AEAD ciphertext blob is laid out
//!    as `pubkey(32) || aead_output(secret_ciphertext+tag)`, so
//!    [`SealedKeypair::public_address`] is a zero-decryption operation
//!    (reads the leading 32 bytes only). The pubkey is **also** bound
//!    into the AAD, so a tampered pubkey prefix invalidates the AEAD
//!    tag at unseal time.

#![forbid(unsafe_code)]

use aes_gcm_siv::aead::{Aead, KeyInit, Payload};
use aes_gcm_siv::{Aes256GcmSiv, Key as AesKey, Nonce as AesNonce};
use blake2::{Blake2b, Digest, digest::consts::U32};
use ed25519_dalek::SigningKey;
use hmac::Hmac;
use mnemos_d_move::SuiAddress;
use sha2::Sha256;
use zeroize::Zeroize;

/// PBKDF2-HMAC-SHA256 PRF type alias. Centralised so that the KDF
/// primitive choice for atom #33 is recorded in one place.
type Pbkdf2HmacSha256 = Hmac<Sha256>;

/// Byte width of the at-rest PBKDF2 salt (canonical OUT §4.G).
pub const KDF_SALT_BYTES: usize = 16;

/// Byte width of the stored nonce surface (canonical OUT §4.G). The full
/// 24 bytes are bound to the AEAD tag — the trailing 12 act as the
/// AES-GCM-SIV IV; the leading 12 are mixed into the AAD.
pub const STORED_NONCE_BYTES: usize = 24;

/// Byte width of an ed25519 raw secret seed.
pub const SECRET_KEY_BYTES: usize = 32;

/// Byte width of an ed25519 raw public key.
pub const PUBLIC_KEY_BYTES: usize = 32;

/// Byte width of an AES-256-GCM-SIV authentication tag.
const AEAD_TAG_BYTES: usize = 16;

/// Byte width of the AES-256-GCM-SIV IV consumed at the AEAD layer.
const AEAD_NONCE_BYTES: usize = 12;

/// PBKDF2-HMAC-SHA256 iteration count. OWASP 2023 password-storage
/// baseline. Hard-coded — never expose a knob that lets a future caller
/// downgrade the cost factor at sealing time.
const KDF_ITERATIONS: u32 = 600_000;

/// Sui signature-scheme flag prefix for ed25519 addresses (§4.G).
/// `address = Blake2b-256(0x00 || pubkey)[..32]`.
const SUI_ED25519_FLAG: u8 = 0x00;

/// Expected minimum length of `SealedKeypair::ciphertext`:
///   pubkey(32) || encrypted_secret(32) || aead_tag(16) = 80 bytes.
const MIN_CIPHERTEXT_LEN: usize = PUBLIC_KEY_BYTES + SECRET_KEY_BYTES + AEAD_TAG_BYTES;

/// Disk-resident encrypted Sui ed25519 keypair. Three canonical fields
/// per ATOM_PLAN §4.G — no extra columns. The plaintext secret never
/// reaches disk.
///
/// `Debug` / `Display` / `Clone` / `serde` are intentionally NOT
/// derived. The ciphertext blob is opaque; if a future caller wants to
/// persist it, it must do so through an explicit byte-array
/// serialisation that the caller (not this type) owns.
pub struct SealedKeypair {
    /// Opaque AEAD output. Internal layout (private to this module):
    /// `pubkey(32) || aes_gcm_siv_ciphertext_with_tag(48) = 80 bytes`.
    /// The leading 32 bytes are also bound into the AAD so a tampered
    /// pubkey prefix invalidates the AEAD tag at unseal time.
    ciphertext: Vec<u8>,
    /// PBKDF2-HMAC-SHA256 salt. Fresh 16 bytes from the OS CSPRNG per
    /// sealing.
    kdf_salt: [u8; KDF_SALT_BYTES],
    /// Stored nonce surface (24 bytes). Full width is bound to the AEAD
    /// tag (see module-level docs); trailing 12 bytes feed the
    /// AES-GCM-SIV IV slot, leading 12 bytes are mixed into AAD.
    nonce: [u8; STORED_NONCE_BYTES],
}

/// 32-byte ed25519 secret seed, alive only inside a single unseal
/// scope. `Drop` zeroizes the buffer. **No** `Debug` / `Display` /
/// `Clone` / serde — every leak path through formatting, copying, or
/// serialisation fails at compile time (§10.3 광기). Accessors are
/// intentionally minimal: callers that need the bytes for downstream
/// signing (atom #34) borrow `&[u8; 32]` and let `Drop` run when the
/// scope closes.
pub struct ScopedSecretKey([u8; SECRET_KEY_BYTES]);

impl ScopedSecretKey {
    /// Borrow the 32-byte secret seed for a downstream signing API.
    /// The returned reference does not outlive `self` and the buffer
    /// is zeroized when `self` drops.
    #[inline]
    #[must_use]
    pub fn as_bytes(&self) -> &[u8; SECRET_KEY_BYTES] {
        &self.0
    }

    /// Test-only constructor: wrap a caller-supplied 32-byte seed into a
    /// `ScopedSecretKey` so deterministic signing test vectors (atom #34
    /// `g0_2_signs_known_intent_vector`) can pin a fixed
    /// (seed, intent_tx_bytes, derived_pubkey) tuple without going
    /// through the CSPRNG-driven `SealedKeypair::create_encrypted` path.
    ///
    /// Marked `#[cfg(test)]` and `pub(crate)` — the symbol does not
    /// exist in release builds and is unreachable to downstream crates,
    /// so it cannot widen the plaintext-secret import surface. The
    /// `Drop`-zeroize invariant on the returned value is preserved
    /// (same wrapper type, same destructor).
    #[cfg(test)]
    #[must_use]
    pub(crate) fn from_seed_for_test(seed: [u8; SECRET_KEY_BYTES]) -> Self {
        Self(seed)
    }
}

impl Drop for ScopedSecretKey {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

/// Errors produced by the sealed-keystore surface (ATOM_PLAN §4.G).
/// Variants are deliberately coarse — the disk-side attacker MUST NOT
/// learn whether decryption failed for "wrong passphrase" vs "tampered
/// ciphertext"; both collapse into [`WalletError::Decrypt`].
///
/// `Sign` and `KeyRotation` are declared by the canonical OUT but their
/// emission sites land in atoms #34 (signing) and #36 (rotation). At
/// atom #33 they are recorded against `PersistError::Anchor`-style
/// declared-but-not-yet-emitted accounting in `no_op_decisions.jsonl`.
#[derive(Debug)]
pub enum WalletError {
    /// AEAD authentication tag verification failed OR the stored
    /// ciphertext is structurally malformed. Surfaced uniformly for
    /// wrong passphrase, tampered nonce/salt, tampered pubkey prefix,
    /// or truncated blob.
    Decrypt,
    /// Reserved for atoms #34/#35 (`sign_move_tx` / `sign_message`).
    /// Declared by the canonical OUT; not emitted by this atom.
    Sign,
    /// Reserved for atom #36 (`rotate_key`). Declared by the canonical
    /// OUT; not emitted by this atom.
    KeyRotation,
    /// The caller asked the keystore to seal an empty passphrase, OR a
    /// non-passphrase-protected path was requested. Plaintext-secret
    /// storage is structurally refused.
    PlaintextRefused,
}

impl core::fmt::Display for WalletError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let msg = match self {
            Self::Decrypt => "wallet decrypt: authentication failed or ciphertext malformed",
            Self::Sign => "wallet sign: reserved for atom #34 (sign_move_tx) / #35 (sign_message)",
            Self::KeyRotation => "wallet key rotation: reserved for atom #36 (rotate_key)",
            Self::PlaintextRefused => "wallet seal refused: empty passphrase / plaintext path",
        };
        f.write_str(msg)
    }
}

impl core::error::Error for WalletError {}

impl SealedKeypair {
    /// Seal a fresh ed25519 keypair under `passphrase`. Steps:
    ///
    /// 1. Refuse an empty passphrase ([`WalletError::PlaintextRefused`]).
    /// 2. Draw 16 random KDF salt bytes + 24 random stored-nonce bytes + 32
    ///    random secret seed bytes from the OS CSPRNG via `getrandom`.
    /// 3. Derive the ed25519 public key from the secret seed.
    /// 4. Stretch the passphrase via PBKDF2-HMAC-SHA256 with 600 000 iterations
    ///    into a 32-byte AES-256 key.
    /// 5. Encrypt the 32-byte secret seed via AES-256-GCM-SIV with the trailing
    ///    12 bytes of the stored 24-byte nonce as the AEAD IV, binding the
    ///    leading 12 nonce bytes **and** the public key into AAD.
    /// 6. Lay the ciphertext out as `pubkey || aead_output`; zeroize every
    ///    transient buffer.
    ///
    /// On success the returned [`SealedKeypair`] is safe to write to
    /// disk verbatim — the plaintext seed never leaves this function.
    ///
    /// # Errors
    ///
    /// - [`WalletError::PlaintextRefused`] when `passphrase` is empty.
    /// - [`WalletError::Decrypt`] when the OS CSPRNG fails to provide
    ///   randomness OR the AEAD encryption layer returns an error
    ///   (both are catastrophic and indistinguishable to the caller).
    pub fn create_encrypted(passphrase: &str) -> Result<Self, WalletError> {
        if passphrase.is_empty() {
            return Err(WalletError::PlaintextRefused);
        }

        let mut secret_seed = [0u8; SECRET_KEY_BYTES];
        getrandom::getrandom(&mut secret_seed).map_err(|_| WalletError::Decrypt)?;

        let mut kdf_salt = [0u8; KDF_SALT_BYTES];
        getrandom::getrandom(&mut kdf_salt).map_err(|_| {
            secret_seed.zeroize();
            WalletError::Decrypt
        })?;

        let mut nonce = [0u8; STORED_NONCE_BYTES];
        getrandom::getrandom(&mut nonce).map_err(|_| {
            secret_seed.zeroize();
            WalletError::Decrypt
        })?;

        let signing = SigningKey::from_bytes(&secret_seed);
        let public_key: [u8; PUBLIC_KEY_BYTES] = signing.verifying_key().to_bytes();

        let mut derived_key = [0u8; 32];
        pbkdf2::pbkdf2::<Pbkdf2HmacSha256>(
            passphrase.as_bytes(),
            &kdf_salt,
            KDF_ITERATIONS,
            &mut derived_key,
        );

        let aead_nonce_bytes: [u8; AEAD_NONCE_BYTES] = match nonce[12..].try_into() {
            Ok(b) => b,
            Err(_) => {
                secret_seed.zeroize();
                derived_key.zeroize();
                return Err(WalletError::Decrypt);
            }
        };
        let aad = build_aad(&nonce[..12], &public_key);

        let cipher = Aes256GcmSiv::new(AesKey::<Aes256GcmSiv>::from_slice(&derived_key));
        let aead_output = cipher
            .encrypt(
                AesNonce::from_slice(&aead_nonce_bytes),
                Payload {
                    msg: &secret_seed,
                    aad: &aad,
                },
            )
            .map_err(|_| {
                // Zeroize transient material before the early return.
                WalletError::Decrypt
            });

        // Zeroize regardless of encrypt outcome.
        secret_seed.zeroize();
        derived_key.zeroize();

        let aead_output = aead_output?;

        let mut ciphertext = Vec::with_capacity(PUBLIC_KEY_BYTES + aead_output.len());
        ciphertext.extend_from_slice(&public_key);
        ciphertext.extend_from_slice(&aead_output);

        Ok(Self {
            ciphertext,
            kdf_salt,
            nonce,
        })
    }

    /// Unseal the secret seed under `passphrase` for a single short
    /// scope. The returned [`ScopedSecretKey`] zeroizes its buffer on
    /// drop. **Wrong passphrase and tampered ciphertext are
    /// indistinguishable** — both surface as [`WalletError::Decrypt`].
    ///
    /// # Errors
    ///
    /// - [`WalletError::Decrypt`] for wrong passphrase, tampered
    ///   nonce / salt / pubkey-prefix, truncated ciphertext, or any
    ///   AEAD verification failure.
    pub fn unseal(&self, passphrase: &str) -> Result<ScopedSecretKey, WalletError> {
        if self.ciphertext.len() < MIN_CIPHERTEXT_LEN {
            return Err(WalletError::Decrypt);
        }
        let pubkey_prefix: [u8; PUBLIC_KEY_BYTES] =
            match self.ciphertext[..PUBLIC_KEY_BYTES].try_into() {
                Ok(b) => b,
                Err(_) => return Err(WalletError::Decrypt),
            };
        let aead_blob = &self.ciphertext[PUBLIC_KEY_BYTES..];

        let mut derived_key = [0u8; 32];
        pbkdf2::pbkdf2::<Pbkdf2HmacSha256>(
            passphrase.as_bytes(),
            &self.kdf_salt,
            KDF_ITERATIONS,
            &mut derived_key,
        );

        let aead_nonce_bytes: [u8; AEAD_NONCE_BYTES] = match self.nonce[12..].try_into() {
            Ok(b) => b,
            Err(_) => {
                derived_key.zeroize();
                return Err(WalletError::Decrypt);
            }
        };
        let aad = build_aad(&self.nonce[..12], &pubkey_prefix);

        let cipher = Aes256GcmSiv::new(AesKey::<Aes256GcmSiv>::from_slice(&derived_key));
        let decrypted = cipher.decrypt(
            AesNonce::from_slice(&aead_nonce_bytes),
            Payload {
                msg: aead_blob,
                aad: &aad,
            },
        );

        derived_key.zeroize();

        let mut plaintext = decrypted.map_err(|_| WalletError::Decrypt)?;

        if plaintext.len() != SECRET_KEY_BYTES {
            plaintext.zeroize();
            return Err(WalletError::Decrypt);
        }

        let mut seed = [0u8; SECRET_KEY_BYTES];
        seed.copy_from_slice(&plaintext);
        plaintext.zeroize();

        // Cross-check the recovered seed against the stored pubkey
        // prefix. If a future bug reorders the AAD binding this catches
        // it before the secret leaves the function.
        let recovered_signing = SigningKey::from_bytes(&seed);
        let recovered_pub: [u8; PUBLIC_KEY_BYTES] = recovered_signing.verifying_key().to_bytes();
        if recovered_pub != pubkey_prefix {
            seed.zeroize();
            return Err(WalletError::Decrypt);
        }

        Ok(ScopedSecretKey(seed))
    }

    /// Derive the Sui address from the stored public key. This is a
    /// zero-decryption operation — the public key is the leading 32
    /// bytes of [`SealedKeypair::ciphertext`] and is bound to the AEAD
    /// tag via AAD so it is tamper-evident at unseal time. The address
    /// itself is `Blake2b-256(0x00 || pubkey)[..32]` per the Sui
    /// signature-scheme convention.
    #[must_use]
    pub fn public_address(&self) -> SuiAddress {
        // `SealedKeypair` can only be constructed by `create_encrypted`,
        // which always lays at least `MIN_CIPHERTEXT_LEN` (= 80) bytes
        // into `ciphertext`. The slice `.get(..32)` therefore yields
        // `Some` on every valid instance. If a future caller bypasses
        // the constructor through unsafe transmutation (forbidden — see
        // `#![forbid(unsafe_code)]`) we fall back to the all-zero
        // address sentinel, which is itself observably invalid on Sui.
        let pubkey_slice = self
            .ciphertext
            .get(..PUBLIC_KEY_BYTES)
            .unwrap_or(&[0u8; PUBLIC_KEY_BYTES]);
        let pubkey: [u8; PUBLIC_KEY_BYTES] =
            pubkey_slice.try_into().unwrap_or([0u8; PUBLIC_KEY_BYTES]);

        let mut hasher = Blake2b::<U32>::new();
        hasher.update([SUI_ED25519_FLAG]);
        hasher.update(pubkey);
        let digest = hasher.finalize();

        let mut addr = [0u8; 32];
        addr.copy_from_slice(&digest);
        SuiAddress::new(addr)
    }
}

/// Build the AEAD AAD = `nonce_tweak(12) || pubkey(32) = 44 bytes`.
/// Centralised so the byte-layout is byte-identical between
/// `create_encrypted` and `unseal`.
#[inline]
fn build_aad(
    nonce_tweak: &[u8],
    public_key: &[u8; PUBLIC_KEY_BYTES],
) -> [u8; 12 + PUBLIC_KEY_BYTES] {
    let mut buf = [0u8; 12 + PUBLIC_KEY_BYTES];
    // Caller passes exactly 12 bytes; we pin that by copying byte-wise
    // through a fixed-width slice and panic-free saturation.
    let n = nonce_tweak.len().min(12);
    buf[..n].copy_from_slice(&nonce_tweak[..n]);
    buf[12..].copy_from_slice(public_key);
    buf
}

#[cfg(test)]
mod tests {
    // Test helpers favour direct failure surfaces over `Result`-bubbling;
    // suppress prod-only clippy denies inside this module.
    #![allow(clippy::unwrap_used)]
    #![allow(clippy::expect_used)]
    #![allow(clippy::panic)]

    use super::*;

    /// `g0_1_roundtrip_seal_unseal` (ATOM_PLAN line 1149).
    /// Seal → unseal under the correct passphrase recovers the same
    /// 32-byte seed AND the same public address.
    #[test]
    fn g0_1_roundtrip_seal_unseal() {
        let pass = "correct-horse-battery-staple-2026";
        let sealed = SealedKeypair::create_encrypted(pass).expect("seal");
        let addr_before = sealed.public_address();
        let scoped = sealed.unseal(pass).expect("unseal");
        // Re-derive the public key from the recovered seed and confirm
        // it matches the Sui address that `public_address` returned.
        let signing = SigningKey::from_bytes(scoped.as_bytes());
        let pubkey: [u8; PUBLIC_KEY_BYTES] = signing.verifying_key().to_bytes();
        let mut hasher = Blake2b::<U32>::new();
        hasher.update([SUI_ED25519_FLAG]);
        hasher.update(pubkey);
        let digest = hasher.finalize();
        let mut addr_after = [0u8; 32];
        addr_after.copy_from_slice(&digest);
        assert_eq!(*addr_before.as_bytes(), addr_after);
    }

    /// `g0_1_wrong_passphrase_fails` (ATOM_PLAN line 1149).
    /// A different passphrase MUST surface `WalletError::Decrypt` and
    /// MUST NOT return a `ScopedSecretKey`.
    #[test]
    fn g0_1_wrong_passphrase_fails() {
        let sealed = SealedKeypair::create_encrypted("right-pass").expect("seal");
        let outcome = sealed.unseal("wrong-pass");
        match outcome {
            Err(WalletError::Decrypt) => {}
            Err(other) => panic!("expected WalletError::Decrypt, got {other:?}"),
            Ok(_) => panic!("unseal under wrong passphrase MUST fail"),
        }
    }

    /// `g0_1_plaintext_key_never_on_disk` (ATOM_PLAN line 1149).
    /// Read the on-disk source of `keystore.rs` itself and assert that
    /// the prod surface stores **no** plaintext key material — every
    /// `nonce`-side field name is the AEAD nonce, never a key. The
    /// grep is intentionally conservative: it scans the source for any
    /// identifier that looks like a stored plaintext key field on
    /// `SealedKeypair`.
    #[test]
    fn g0_1_plaintext_key_never_on_disk() {
        let src = include_str!("keystore.rs");
        // Locate the `SealedKeypair` declaration and scan ONLY its
        // struct body. Scanning the whole file would self-trip on this
        // very test's canary literals; the structural invariant we
        // actually need is "no plaintext-key field on `SealedKeypair`",
        // which lives between the opening `{` and matching `}`.
        let marker = concat!("pub struct ", "SealedKeypair {");
        let pos = src.find(marker).expect("SealedKeypair declaration present");
        let after = &src[pos + marker.len()..];
        let close = after
            .find('}')
            .expect("SealedKeypair body has a closing brace");
        let body = &after[..close];

        // Forbidden field-name fragments — assembled via `concat!` so
        // this test's source does NOT contain the verbatim needles
        // (otherwise the canary would match its own literal). Each
        // entry is `"<field_name>:"` and is checked against the struct
        // body only.
        let forbidden: [&str; 5] = [
            concat!("secret", "_key:"),
            concat!("plaintext", "_key:"),
            concat!("private", "_key:"),
            concat!("seed", ":"),
            concat!("raw", "_key:"),
        ];
        for needle in forbidden {
            assert!(
                !body.contains(needle),
                "SealedKeypair body MUST NOT declare a plaintext-key field (found `{needle}`)",
            );
        }

        // Confirm `SealedKeypair` declares exactly the three canonical
        // fields — a future refactor that adds a fourth field would
        // surface here and force re-review.
        let field_count = body.matches("ciphertext:").count()
            + body.matches("kdf_salt:").count()
            + body.matches("nonce:").count();
        assert_eq!(
            field_count, 3,
            "SealedKeypair MUST have exactly 3 canonical fields"
        );
    }

    /// `g0_1_secret_key_has_no_debug` (ATOM_PLAN line 1149).
    /// Trait absence is normally a compile-time invariant; this
    /// runtime check delegates to `static_assertions` which only
    /// compiles if `ScopedSecretKey` has NO `Debug` / `Display` /
    /// `Clone` impl. If a future change adds any of these, this
    /// `assert_not_impl_any!` invocation FAILS TO COMPILE — turning a
    /// silent privacy regression into a hard build break.
    #[test]
    fn g0_1_secret_key_has_no_debug() {
        // The macro emits compile-time `static_assert_*` items; the
        // runtime body of this test is only a witness that the macro
        // expansion was reachable in test compilation.
        static_assertions::assert_not_impl_any!(
            ScopedSecretKey: core::fmt::Debug,
            core::fmt::Display,
            Clone
        );
        // Witness the secret-buffer width too — the canonical OUT
        // pins `ScopedSecretKey([u8; 32])` and a refactor that widens
        // / narrows the secret seed would invalidate the AEAD layout.
        assert_eq!(core::mem::size_of::<ScopedSecretKey>(), SECRET_KEY_BYTES);
    }

    /// Witness that the canonical struct widths match ATOM_PLAN §4.G.
    #[test]
    fn g0_1_canonical_field_widths_pinned() {
        // SealedKeypair owns a Vec (no fixed size) plus two arrays of
        // declared width. Pin the array widths so a future edit to
        // `KDF_SALT_BYTES` / `STORED_NONCE_BYTES` breaks compile.
        let _: [u8; 16] = [0u8; KDF_SALT_BYTES];
        let _: [u8; 24] = [0u8; STORED_NONCE_BYTES];
    }
}
