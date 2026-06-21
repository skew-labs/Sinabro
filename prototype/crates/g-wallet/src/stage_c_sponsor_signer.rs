//! Stage C sponsor signer request/response boundary (C-WP-07 · atom #230 · C.2.11).
//!
//! Canonical OUT: the sponsor signer request/response boundary built on the
//! atom #214 [`MainnetSignerEnvelope`](crate::stage_c_signer_envelope::MainnetSignerEnvelope).
//!
//! # Madness invariants (atom #230)
//!
//! * **The signer signs exact bytes.** A [`SponsorSignerRequest`] binds the
//!   envelope (package · tx digest · policy hash · timelock ETA) to a gas-coin
//!   `lease_id` and an `expires_epoch`. Admission yields a
//!   [`SponsorSignerGrant`] carrying a single 32-byte commitment to those exact
//!   bytes — there is no path that hands the signer an arbitrary blob.
//! * **No raw key export.** Neither the request, the grant, nor this module's
//!   functions touch key material. The request is a description of *what* will
//!   be signed; the key stays behind the atom #227 signer boundary
//!   ([`crate::stage_c_signer_boundary`]). This module never imports a keypair
//!   type.
//! * **Policy-bound and time-bound.** Admission refuses a request whose
//!   envelope policy hash does not match the presented Gas Station policy hash
//!   ([`SponsorSignerError::PolicyHashMismatch`]) and refuses a request whose
//!   `expires_epoch` has passed ([`SponsorSignerError::RequestExpired`]).
//!
//! # Reuse map (atom contract)
//!
//! * **reuse: #214** — [`MainnetSignerEnvelope`] is the exact-bytes commitment.
//! * **reuse: #217** — the presented policy hash is the §4.3 Gas Station policy
//!   hash this signature is bound to.
//! * **reuse: #229** — the `lease_id` originates from a hot-wallet-capped
//!   [`GasCoinLeasePool`](crate::stage_c_gas_coin_lease::GasCoinLeasePool).
//!
//! No live action: admission computes a commitment hash and a verdict. No
//! signing, no submission, no egress. `MainnetExecutionState` stays `Locked`.

use blake2::{Blake2b, Digest, digest::consts::U32};

use crate::stage_c_signer_envelope::MainnetSignerEnvelope;

/// Domain separator for the sponsor-signer exact-bytes commitment, so it can
/// never collide with another Stage C 32-byte preimage.
const SPONSOR_SIGNER_DOMAIN: &[u8] = b"mnemos.stage_c.sponsor_signer.v1";

/// A sponsor signing request: the exact envelope plus the gas-coin lease and
/// expiry it is bound to. No key material.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub struct SponsorSignerRequest {
    /// The exact bytes (envelope) the sponsor would sign.
    pub envelope: MainnetSignerEnvelope,
    /// The gas-coin lease id this request consumes (atom #231 / #229).
    pub lease_id_u64: u64,
    /// The epoch at (and after) which this request is stale and unsignable.
    pub expires_epoch_u64: u64,
}

/// The response side: a commitment to the exact bytes admitted for signing. It
/// is *not* a signature and carries no key material — it is the hash a downstream
/// (key-holding) signer boundary would actually commit to.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub struct SponsorSignerGrant {
    /// `Blake2b-256(domain ‖ envelope.exact_signing_preimage ‖ lease_id ‖ expires)`.
    pub exact_bytes_commitment_32: [u8; 32],
}

/// Sponsor-signer admission error. Every variant is data-free.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
#[repr(u8)]
pub enum SponsorSignerError {
    /// The envelope's policy hash did not match the presented policy hash.
    PolicyHashMismatch = 1,
    /// The request's `expires_epoch` has passed.
    RequestExpired = 2,
    /// An opaque byte payload was offered instead of a typed envelope — refused.
    OpaqueBytesRejected = 3,
}

impl core::fmt::Display for SponsorSignerError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let msg = match self {
            Self::PolicyHashMismatch => "stage_c sponsor signer: policy hash mismatch",
            Self::RequestExpired => "stage_c sponsor signer: request expired",
            Self::OpaqueBytesRejected => "stage_c sponsor signer: opaque bytes signing refused",
        };
        f.write_str(msg)
    }
}

impl core::error::Error for SponsorSignerError {}

impl SponsorSignerRequest {
    /// Construct a request from a typed envelope, lease id and expiry.
    #[inline]
    #[must_use]
    pub const fn new(
        envelope: MainnetSignerEnvelope,
        lease_id_u64: u64,
        expires_epoch_u64: u64,
    ) -> Self {
        Self {
            envelope,
            lease_id_u64,
            expires_epoch_u64,
        }
    }

    /// Explicit refusal of opaque-byte requests. There is no constructor that
    /// turns an arbitrary blob into a request; this surfaces that refusal as a
    /// value for callers and tests.
    #[inline]
    #[must_use]
    pub const fn reject_opaque_payload(_payload: &[u8]) -> SponsorSignerError {
        SponsorSignerError::OpaqueBytesRejected
    }

    /// Admit this request against the presented Gas Station policy hash and the
    /// current epoch, returning a commitment to the exact bytes to sign.
    ///
    /// # Errors
    ///
    /// [`SponsorSignerError::PolicyHashMismatch`] if the envelope's policy hash
    /// differs from `presented_policy_hash_32`, and
    /// [`SponsorSignerError::RequestExpired`] if `now_epoch_u64 >=
    /// self.expires_epoch_u64`.
    pub fn admit(
        &self,
        presented_policy_hash_32: &[u8; 32],
        now_epoch_u64: u64,
    ) -> Result<SponsorSignerGrant, SponsorSignerError> {
        if &self.envelope.policy_hash_32 != presented_policy_hash_32 {
            return Err(SponsorSignerError::PolicyHashMismatch);
        }
        if now_epoch_u64 >= self.expires_epoch_u64 {
            return Err(SponsorSignerError::RequestExpired);
        }
        Ok(SponsorSignerGrant {
            exact_bytes_commitment_32: self.exact_bytes_commitment(),
        })
    }

    /// The deterministic 32-byte commitment to the exact bytes this request
    /// would have signed (independent of admission, for binding/auditing).
    #[must_use]
    pub fn exact_bytes_commitment(&self) -> [u8; 32] {
        let mut h = Blake2b::<U32>::new();
        h.update(SPONSOR_SIGNER_DOMAIN);
        h.update(self.envelope.exact_signing_preimage());
        h.update(self.lease_id_u64.to_le_bytes());
        h.update(self.expires_epoch_u64.to_le_bytes());
        h.finalize().into()
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]
    use super::*;
    use mnemos_d_move::types::ObjectId;

    fn envelope(policy_hash: [u8; 32]) -> MainnetSignerEnvelope {
        MainnetSignerEnvelope::new(ObjectId::new([0x22; 32]), [0xAB; 32], policy_hash, 42)
            .expect("valid envelope")
    }

    #[test]
    fn exact_bytes_accepted() {
        let policy = [0xCD; 32];
        let req = SponsorSignerRequest::new(envelope(policy), 7, 1_000);
        let grant = req.admit(&policy, 10).expect("admitted");
        // The commitment is deterministic and equals the standalone derivation.
        assert_eq!(
            grant.exact_bytes_commitment_32,
            req.exact_bytes_commitment()
        );
        // A different lease id changes the committed bytes.
        let req2 = SponsorSignerRequest::new(envelope(policy), 8, 1_000);
        assert_ne!(req2.exact_bytes_commitment(), req.exact_bytes_commitment());
    }

    #[test]
    fn policy_mismatch_reject() {
        let req = SponsorSignerRequest::new(envelope([0xCD; 32]), 7, 1_000);
        assert_eq!(
            req.admit(&[0xEE; 32], 10),
            Err(SponsorSignerError::PolicyHashMismatch)
        );
    }

    #[test]
    fn expired_request_reject() {
        let policy = [0xCD; 32];
        let req = SponsorSignerRequest::new(envelope(policy), 7, 1_000);
        assert_eq!(
            req.admit(&policy, 1_000),
            Err(SponsorSignerError::RequestExpired)
        );
        // Opaque payloads are refused with no constructor path.
        assert_eq!(
            SponsorSignerRequest::reject_opaque_payload(&[0u8; 16]),
            SponsorSignerError::OpaqueBytesRejected
        );
    }
}
