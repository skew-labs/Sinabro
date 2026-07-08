//! Secret reference + inline-secret scanning.
//!
//! Status-only: the CLI can tell whether a secret exists and where it lives
//! (keychain / env / KMS / external vault) without ever loading, cloning,
//! `Debug`-printing, or networking the value. Inline-secret detection reuses the
//! a-core [`mnemos_a_core::looks_like_secret`] helper.

use mnemos_a_core::looks_like_secret;

use crate::sha256_32;

/// Where a secret reference resolves (the value is never loaded here).
#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SecretLocation {
    /// OS keychain reference (`keychain:NAME`).
    Keychain = 1,
    /// Environment-variable reference (`env:NAME`).
    EnvRef = 2,
    /// KMS reference (`kms:...`).
    KmsRef = 3,
    /// External vault reference (`vault:...`).
    ExternalVaultRef = 4,
    /// No reference present.
    Missing = 5,
}

/// A status-only view of a secret reference.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SecretRefView {
    /// SHA-256 of the secret's logical name (never the value).
    pub name_hash_32: [u8; 32],
    /// Where the reference resolves.
    pub location: SecretLocation,
    /// Invariant: the CLI never loads the secret value. Always `true`.
    pub value_never_loaded: bool,
}

/// Classify a secret *reference string* by scheme prefix without loading the
/// value. An empty / unknown reference is [`SecretLocation::Missing`].
#[must_use]
pub fn classify_reference(name: &str, reference: &str) -> SecretRefView {
    let location = match reference.split_once(':') {
        Some(("keychain", _)) => SecretLocation::Keychain,
        Some(("env", _)) => SecretLocation::EnvRef,
        Some(("kms", _)) => SecretLocation::KmsRef,
        Some(("vault", _)) => SecretLocation::ExternalVaultRef,
        _ => SecretLocation::Missing,
    };
    SecretRefView {
        name_hash_32: sha256_32(name.as_bytes()),
        location,
        value_never_loaded: true,
    }
}

/// Whether `text` contains an inline (live-shaped) secret. Used by the config /
/// history / docs leak scans. Reuses the a-core detector.
#[must_use]
pub fn scan_inline_secret(text: &str) -> bool {
    looks_like_secret(text)
}

/// A secret value that physically cannot be rendered, logged, persisted,
/// or serialized. The structural invariant: the leak state is
/// UNREPRESENTABLE, not runtime-checked. `Secret<T>` implements NONE of
/// [`Debug`](core::fmt::Debug), [`Display`](core::fmt::Display),
/// `serde::Serialize`, nor `ToString`, and exposes no clone-to-inner — so a
/// secret cannot reach a log line, a trace, a panic message, or a serialized
/// record by construction. The wrapped value is reachable ONLY through
/// [`Secret::expose_secret`], named so every read site is greppable
/// (`rg expose_secret`) in an audit.
///
/// `#[repr(transparent)]` makes the wrapper zero-cost: it has the exact memory
/// layout of `T` (no runtime overhead).
///
/// Secrets currently carried on this type: `OPENROUTER_API_KEY`,
/// `TELEGRAM_BOT_TOKEN`, `TELEGRAM_CHAT_ID` (egress credentials, read only at the
/// TLS boundary) and the 32-byte local memory key
/// ([`crate::memory_store::MemoryCipher`]).
///
/// # Redteam — every leak path fails to COMPILE
///
/// A secret cannot be `Debug`-formatted (`{:?}`):
/// ```compile_fail
/// let s = sinabro::secrets::Secret::new(7u8);
/// let _leak = format!("{s:?}");
/// ```
/// A secret cannot be `Display`-formatted (`{}`):
/// ```compile_fail
/// let s = sinabro::secrets::Secret::new(7u8);
/// let _leak = format!("{s}");
/// ```
/// A secret cannot be `.to_string()`-ed:
/// ```compile_fail
/// let s = sinabro::secrets::Secret::new(7u8);
/// let _leak = s.to_string();
/// ```
/// A secret cannot be serialized (persisted):
/// ```compile_fail
/// fn assert_serialize<T: serde::Serialize>() {}
/// assert_serialize::<sinabro::secrets::Secret<u8>>();
/// ```
#[repr(transparent)]
pub struct Secret<T>(T);

impl<T> Secret<T> {
    /// Wrap `value` as a secret. `const` so secret-holding constructors (e.g.
    /// [`MemoryCipher::from_key`](crate::memory_store::MemoryCipher::from_key))
    /// stay `const`.
    #[inline]
    #[must_use]
    pub const fn new(value: T) -> Self {
        Self(value)
    }

    /// Borrow the wrapped secret — the ONLY read path. Named `expose_secret` so
    /// every site that touches a raw secret is greppable for audit.
    #[inline]
    #[must_use]
    pub fn expose_secret(&self) -> &T {
        &self.0
    }
}

/// A clone stays wrapped (yields another `Secret<T>`, never a bare value), so it
/// preserves the no-leak invariant. Present so secret-holding structs may keep
/// deriving `Clone`.
impl<T: Clone> Clone for Secret<T> {
    #[inline]
    fn clone(&self) -> Self {
        Self(self.0.clone())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn references_classify_without_loading() {
        for (reference, expect) in [
            ("keychain:OPENAI", SecretLocation::Keychain),
            ("env:ANTHROPIC_API_KEY", SecretLocation::EnvRef),
            ("kms:projects/x/keys/y", SecretLocation::KmsRef),
            ("vault:secret/data/z", SecretLocation::ExternalVaultRef),
            ("", SecretLocation::Missing),
            ("plain-no-scheme", SecretLocation::Missing),
        ] {
            let v = classify_reference("provider_key", reference);
            assert_eq!(v.location, expect);
            assert!(v.value_never_loaded);
        }
    }

    #[test]
    fn inline_secret_is_detected_but_reference_is_not() {
        assert!(scan_inline_secret("k = \"suiprivkey1qexamplenotreal\""));
        assert!(!scan_inline_secret(
            "provider_key = \"env:ANTHROPIC_API_KEY\""
        ));
    }

    #[test]
    fn secret_exposes_only_via_expose_secret() {
        let key = Secret::new([7u8; 32]);
        assert_eq!(key.expose_secret(), &[7u8; 32]);
        let token = Secret::new(String::from("not-a-real-wrapped-value"));
        assert_eq!(token.expose_secret().as_str(), "not-a-real-wrapped-value");
    }

    #[test]
    fn secret_clone_stays_wrapped_and_preserves_value() {
        let original = Secret::new(String::from("k"));
        let cloned = original.clone();
        assert_eq!(original.expose_secret(), cloned.expose_secret());
    }
}
