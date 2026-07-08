//! Stage C signer isolation boundary.
//!
//! A signer boundary spec for a KMS / HSM / TEE / signing daemon backend.
//!
//! # Invariants
//!
//! * **The API process never reads mainnet key material.** The side of the
//!   boundary the API process holds is [`ApiProcessSignerHandle`], a
//!   **zero-sized** type with no key-bearing field and no accessor that yields a
//!   [`SealedKeypair`](crate::keystore::SealedKeypair) or a
//!   [`ScopedSecretKey`](crate::keystore::ScopedSecretKey). Key material lives
//!   only behind [`SignerBackendBinding`] (the KMS/HSM/TEE/daemon side); the API
//!   side can build a *request* (a hash) and nothing else. A zero-sized handle
//!   cannot carry a 32-byte secret — `size_of::<ApiProcessSignerHandle>() == 0`.
//! * **The signer accepts exactly one envelope shape.** Admission is granted by
//!   [`SignerIsolationBoundary::admit`] only for a typed
//!   [`MainnetSignerEnvelope`] whose binding hash the caller
//!   presents. There is no path that admits an opaque byte blob —
//!   [`SignerIsolationBoundary::reject_opaque_request`] makes that refusal an
//!   explicit, testable value and reuses
//!   [`MainnetSignerEnvelope::reject_opaque_payload`].
//! * **Envelope hash is mandatory.** A zero presented envelope hash is
//!   [`SignerBoundaryError::EnvelopeHashRequired`]; a non-zero hash that does not
//!   match the recomputed binding is [`SignerBoundaryError::EnvelopeHashMismatch`].
//!   The backend never signs without the exact envelope binding.
//! * **Inert datatype, no execution.** No I/O, no network, no `sui` invocation,
//!   no gas, no live signing. The boundary admits or rejects; the actual sign
//!   borrows a `ScopedSecretKey` from [`SealedKeypair::unseal`] in the existing
//!   unseal path — not re-minted here. `MainnetExecutionState` stays `Locked`.
//!
//! # Reuse
//!
//! * `SealedKeypair` — [`crate::keystore::SealedKeypair`]
//!   (`g-wallet/src/keystore.rs:123`); the backend side holds it at rest and
//!   derives its public address without decryption.
//! * `ScopedSecretKey` — [`crate::keystore::ScopedSecretKey`]
//!   (`g-wallet/src/keystore.rs:145`, no-`Debug`/no-`Clone`/`Drop`-zeroize); the
//!   backend unseals to it for exactly one admitted envelope.
//! * `MainnetSignerEnvelope` —
//!   [`crate::stage_c_signer_envelope::MainnetSignerEnvelope`]; the only shape
//!   the boundary admits, via its `exact_signing_preimage`.

use blake2::{Blake2b, Digest, digest::consts::U32};
use mnemos_d_move::types::SuiAddress;

use crate::keystore::SealedKeypair;
use crate::stage_c_signer_envelope::MainnetSignerEnvelope;

/// Domain separator for the signer-boundary envelope binding hash, so it can
/// never collide with another Stage C 32-byte hash preimage.
const SIGNER_BOUNDARY_DOMAIN: &[u8] = b"mnemos.stage_c.signer_boundary.v1";

/// The signer backend that holds mainnet key material. Mirrors the deployment
/// choices an operator can make; the boundary is identical for all of them —
/// the API process is on the other side of every variant.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
#[repr(u8)]
pub enum SignerBackendKind {
    /// A cloud / on-prem Key Management Service.
    Kms = 1,
    /// A Hardware Security Module.
    Hsm = 2,
    /// A Trusted Execution Environment enclave.
    Tee = 3,
    /// A local signing daemon process, isolated from the API process.
    SigningDaemon = 4,
}

/// Signer-boundary admission error. Every variant is data-free.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
#[repr(u8)]
pub enum SignerBoundaryError {
    /// An opaque byte payload was offered to the boundary — refused.
    OpaquePayloadRejected = 1,
    /// The presented envelope hash was all-zero (absent).
    EnvelopeHashRequired = 2,
    /// The presented envelope hash did not match the recomputed binding.
    EnvelopeHashMismatch = 3,
}

impl core::fmt::Display for SignerBoundaryError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let msg = match self {
            Self::OpaquePayloadRejected => "stage_c signer boundary: opaque payload refused",
            Self::EnvelopeHashRequired => {
                "stage_c signer boundary: envelope hash required (non-zero)"
            }
            Self::EnvelopeHashMismatch => "stage_c signer boundary: envelope hash mismatch",
        };
        f.write_str(msg)
    }
}

impl core::error::Error for SignerBoundaryError {}

/// The API-process side of the boundary: a **zero-sized** handle. It can build
/// a [`SigningRequest`] (a hash) from a typed envelope and nothing else — there
/// is no field and no method that yields key material. Being zero-sized, it
/// cannot physically carry a 32-byte secret.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash, Default)]
pub struct ApiProcessSignerHandle;

impl ApiProcessSignerHandle {
    /// Construct the API-side handle. Carries no key material.
    #[inline]
    #[must_use]
    pub const fn new() -> Self {
        Self
    }

    /// Build a signing request from a typed envelope. The request carries only
    /// the envelope binding hash — never a key, never the raw envelope's
    /// secrets (there are none). This is the only thing the API side can do.
    #[inline]
    #[must_use]
    pub fn request(&self, envelope: &MainnetSignerEnvelope) -> SigningRequest {
        SigningRequest {
            envelope_hash_32: envelope_binding_hash(envelope),
        }
    }
}

/// The API process's signing request: only the envelope binding hash crosses
/// the boundary. No key material, no opaque bytes.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub struct SigningRequest {
    /// `Blake2b-256(domain ‖ envelope.exact_signing_preimage())`.
    pub envelope_hash_32: [u8; 32],
}

/// The backend side of the boundary — the only side that ever holds key
/// material. It borrows a [`SealedKeypair`](crate::keystore::SealedKeypair) at
/// rest and (in the existing unseal path) unseals it to a
/// [`ScopedSecretKey`](crate::keystore::ScopedSecretKey) for exactly one
/// admitted envelope. The API side cannot construct this type with a key.
pub struct SignerBackendBinding<'a> {
    backend: SignerBackendKind,
    sealed: &'a SealedKeypair,
}

impl<'a> SignerBackendBinding<'a> {
    /// Bind the backend to a sealed keypair it holds at rest.
    #[inline]
    #[must_use]
    pub const fn new(backend: SignerBackendKind, sealed: &'a SealedKeypair) -> Self {
        Self { backend, sealed }
    }

    /// The backend kind.
    #[inline]
    #[must_use]
    pub const fn backend(&self) -> SignerBackendKind {
        self.backend
    }

    /// The public address of the held keypair, derived WITHOUT decryption (the
    /// secret never leaves the backend, and never reaches the API process).
    #[inline]
    #[must_use]
    pub fn public_address(&self) -> SuiAddress {
        self.sealed.public_address()
    }
}

/// `Blake2b-256(domain ‖ envelope.exact_signing_preimage())` — the single
/// binding hash the API request and the backend admission agree on.
#[must_use]
pub fn envelope_binding_hash(envelope: &MainnetSignerEnvelope) -> [u8; 32] {
    let mut hasher = Blake2b::<U32>::new();
    hasher.update(SIGNER_BOUNDARY_DOMAIN);
    hasher.update(envelope.exact_signing_preimage());
    let digest = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest);
    out
}

const fn is_zero_32(h: &[u8; 32]) -> bool {
    let mut i = 0;
    while i < 32 {
        if h[i] != 0 {
            return false;
        }
        i += 1;
    }
    true
}

/// An admission token: the backend accepted the exact envelope binding. Carries
/// only the backend kind and the envelope hash — never key material.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub struct SigningAdmission {
    /// The backend that admitted the request.
    pub backend: SignerBackendKind,
    /// The admitted envelope binding hash.
    pub envelope_hash_32: [u8; 32],
}

/// The signer isolation boundary for a chosen backend.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub struct SignerIsolationBoundary {
    backend: SignerBackendKind,
}

impl SignerIsolationBoundary {
    /// Construct a boundary for the given backend.
    #[inline]
    #[must_use]
    pub const fn new(backend: SignerBackendKind) -> Self {
        Self { backend }
    }

    /// Admit a signing request for an exact envelope. The caller presents the
    /// envelope and the binding hash they computed (the API-side
    /// [`SigningRequest::envelope_hash_32`]); the boundary recomputes the
    /// binding and admits only on an exact match.
    ///
    /// # Errors
    ///
    /// [`SignerBoundaryError::EnvelopeHashRequired`] when the presented hash is
    /// all-zero, and [`SignerBoundaryError::EnvelopeHashMismatch`] when it does
    /// not match the recomputed binding.
    pub fn admit(
        &self,
        envelope: &MainnetSignerEnvelope,
        presented_envelope_hash_32: &[u8; 32],
    ) -> Result<SigningAdmission, SignerBoundaryError> {
        if is_zero_32(presented_envelope_hash_32) {
            return Err(SignerBoundaryError::EnvelopeHashRequired);
        }
        let expected = envelope_binding_hash(envelope);
        if &expected != presented_envelope_hash_32 {
            return Err(SignerBoundaryError::EnvelopeHashMismatch);
        }
        Ok(SigningAdmission {
            backend: self.backend,
            envelope_hash_32: expected,
        })
    }

    /// Explicit refusal of an opaque byte request. There is no constructor that
    /// turns a blob into an admission; this surfaces the refusal as a value and
    /// reuses the envelope's own opaque-bytes refusal.
    #[inline]
    #[must_use]
    pub fn reject_opaque_request(payload: &[u8]) -> SignerBoundaryError {
        // Bind to the envelope refusal so the two boundaries agree.
        let _ = MainnetSignerEnvelope::reject_opaque_payload(payload);
        SignerBoundaryError::OpaquePayloadRejected
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    #![allow(clippy::expect_used)]
    #![allow(clippy::panic)]

    use super::*;
    use mnemos_d_move::types::ObjectId;

    fn sample_envelope() -> MainnetSignerEnvelope {
        MainnetSignerEnvelope::new(
            ObjectId::new([0x22; 32]),
            [0xAB; 32],
            [0xCD; 32],
            1_700_000_000,
        )
        .expect("envelope builds")
    }

    /// `c2_8_api_key_path_unavailable` — the API-side handle is zero-sized (it
    /// cannot carry a 32-byte secret), its request carries only a hash, and key
    /// material lives only behind the backend binding (reuse `SealedKeypair`).
    #[test]
    fn c2_8_api_key_path_unavailable() {
        // Zero-sized: structurally cannot hold key material.
        assert_eq!(core::mem::size_of::<ApiProcessSignerHandle>(), 0);

        let api = ApiProcessSignerHandle::new();
        let env = sample_envelope();
        let req = api.request(&env);
        // The only thing that crossed the boundary is a 32-byte hash.
        assert_eq!(req.envelope_hash_32, envelope_binding_hash(&env));

        // Key material lives only on the backend side.
        let sealed = SealedKeypair::create_encrypted("test-pass-c2-8").unwrap();
        let backend = SignerBackendBinding::new(SignerBackendKind::Hsm, &sealed);
        assert_eq!(backend.backend(), SignerBackendKind::Hsm);
        // Public address derives without decryption; the secret never crosses.
        assert_eq!(backend.public_address(), sealed.public_address());
    }

    /// `c2_8_opaque_request_reject` — an opaque payload cannot become an
    /// admission; the refusal is an explicit value.
    #[test]
    fn c2_8_opaque_request_reject() {
        let opaque = [0x00u8, 0x01, 0x02, 0x03, 0xFF];
        assert_eq!(
            SignerIsolationBoundary::reject_opaque_request(&opaque),
            SignerBoundaryError::OpaquePayloadRejected,
        );
    }

    /// `c2_8_envelope_hash_required` — a zero presented hash is refused, a
    /// drifted hash is refused, and the exact binding is admitted.
    #[test]
    fn c2_8_envelope_hash_required() {
        let boundary = SignerIsolationBoundary::new(SignerBackendKind::Kms);
        let env = sample_envelope();
        let correct = envelope_binding_hash(&env);

        // Absent (zero) hash → required.
        assert_eq!(
            boundary.admit(&env, &[0u8; 32]),
            Err(SignerBoundaryError::EnvelopeHashRequired),
        );
        // Drifted hash → mismatch.
        assert_eq!(
            boundary.admit(&env, &[0x11u8; 32]),
            Err(SignerBoundaryError::EnvelopeHashMismatch),
        );
        // Exact binding → admitted, carrying only backend + hash.
        let admission = boundary.admit(&env, &correct).unwrap();
        assert_eq!(admission.backend, SignerBackendKind::Kms);
        assert_eq!(admission.envelope_hash_32, correct);
    }
}
