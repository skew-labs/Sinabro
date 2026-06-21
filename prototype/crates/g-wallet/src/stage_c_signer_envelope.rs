//! Stage C exact signer envelope (C-WP-05 · atom #214 · C.1.13).
//!
//! Canonical OUT (§4.2): [`MainnetSignerEnvelope`].
//!
//! # Madness invariants (atom #214)
//!
//! * **No opaque bytes signing.** A mainnet signer envelope can only be built
//!   from the four typed fields a signer must see — package id, transaction
//!   digest, policy hash, and timelock ETA. There is no constructor that takes
//!   an arbitrary byte blob; [`MainnetSignerEnvelope::reject_opaque_payload`]
//!   exists only to make the refusal explicit and testable.
//! * **The signer sees exactly what they sign.** [`MainnetSignerEnvelope::display_fields`]
//!   surfaces the four committed values, and
//!   [`exact_signing_preimage`](MainnetSignerEnvelope::exact_signing_preimage)
//!   is the fixed-width byte preimage derived from them — the displayed fields
//!   and the signed bytes are the same data.
//! * **Digest and policy hash are mandatory.** A zero transaction digest or a
//!   zero policy hash is rejected; a mainnet signature is never produced over a
//!   missing digest or an unbound policy.
//!
//! # Reuse map (atom contract)
//!
//! * **reuse: A `ObjectId`** — [`mnemos_d_move::types::ObjectId`]
//!   (`d-move/src/types.rs:163`).
//! * **reuse: #213** — [`TimelockPolicy`](crate::stage_c_timelock::TimelockPolicy);
//!   [`from_timelock`](MainnetSignerEnvelope::from_timelock) derives the ETA as
//!   `queued_at + policy.min_delay_secs`, so the envelope's ETA is the timelock
//!   policy's delay, not an arbitrary number.

use crate::stage_c_timelock::TimelockPolicy;
use mnemos_d_move::types::ObjectId;

/// Domain separator for the exact signer preimage.
const SIGNER_PREIMAGE_DOMAIN: &[u8] = b"mnemos.stage_c.mainnet_signer_envelope.v1";

/// Byte width of the exact signer preimage: `domain ‖ package(32) ‖
/// tx_digest(32) ‖ policy_hash(32) ‖ timelock_eta(8 LE)`.
pub const SIGNER_PREIMAGE_BYTES: usize = SIGNER_PREIMAGE_DOMAIN.len() + 32 * 3 + 8;

/// The exact bytes a mainnet signer commits to (§4.2 canonical OUT).
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub struct MainnetSignerEnvelope {
    /// The on-chain package the signature targets.
    pub package: ObjectId,
    /// The exact transaction digest being signed.
    pub tx_digest_32: [u8; 32],
    /// The hash of the gas / mainnet policy this signature is bound to.
    pub policy_hash_32: [u8; 32],
    /// The timelock ETA (seconds) after which the signed action may execute.
    pub timelock_eta_secs_u64: u64,
}

/// The four human-checkable fields a signer is shown before approving.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub struct SignerDisplayFields {
    /// Package id.
    pub package: ObjectId,
    /// Transaction digest.
    pub tx_digest_32: [u8; 32],
    /// Policy hash.
    pub policy_hash_32: [u8; 32],
    /// Timelock ETA (seconds).
    pub timelock_eta_secs_u64: u64,
}

/// Signer envelope construction / verification error. Every variant is
/// data-free.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
#[repr(u8)]
pub enum SignerEnvelopeError {
    /// An attempt to build an envelope from an opaque byte payload — refused.
    OpaqueBytesRejected = 1,
    /// The transaction digest was all-zero.
    TxDigestRequired = 2,
    /// The policy hash was all-zero.
    PolicyHashRequired = 3,
    /// A presented policy hash did not match the envelope's.
    PolicyHashMismatch = 4,
}

impl core::fmt::Display for SignerEnvelopeError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let msg = match self {
            Self::OpaqueBytesRejected => "stage_c signer: opaque bytes signing refused",
            Self::TxDigestRequired => "stage_c signer: transaction digest required (non-zero)",
            Self::PolicyHashRequired => "stage_c signer: policy hash required (non-zero)",
            Self::PolicyHashMismatch => "stage_c signer: policy hash mismatch",
        };
        f.write_str(msg)
    }
}

impl core::error::Error for SignerEnvelopeError {}

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

impl MainnetSignerEnvelope {
    /// Build an envelope from the four typed fields.
    ///
    /// # Errors
    ///
    /// [`SignerEnvelopeError::TxDigestRequired`] when `tx_digest_32` is
    /// all-zero, and [`SignerEnvelopeError::PolicyHashRequired`] when
    /// `policy_hash_32` is all-zero.
    pub fn new(
        package: ObjectId,
        tx_digest_32: [u8; 32],
        policy_hash_32: [u8; 32],
        timelock_eta_secs_u64: u64,
    ) -> Result<Self, SignerEnvelopeError> {
        if is_zero_32(&tx_digest_32) {
            return Err(SignerEnvelopeError::TxDigestRequired);
        }
        if is_zero_32(&policy_hash_32) {
            return Err(SignerEnvelopeError::PolicyHashRequired);
        }
        Ok(Self {
            package,
            tx_digest_32,
            policy_hash_32,
            timelock_eta_secs_u64,
        })
    }

    /// Build an envelope whose ETA is derived from a timelock policy: `eta =
    /// queued_at_secs + policy.min_delay_secs`. The saturating add keeps the
    /// ETA from wrapping at the `u64` ceiling.
    ///
    /// # Errors
    ///
    /// Same as [`new`](Self::new).
    pub fn from_timelock(
        package: ObjectId,
        tx_digest_32: [u8; 32],
        policy_hash_32: [u8; 32],
        policy: &TimelockPolicy,
        queued_at_secs_u64: u64,
    ) -> Result<Self, SignerEnvelopeError> {
        let eta = queued_at_secs_u64.saturating_add(u64::from(policy.min_delay_secs_u32));
        Self::new(package, tx_digest_32, policy_hash_32, eta)
    }

    /// Explicit refusal of opaque-byte signing. There is no constructor that
    /// turns an arbitrary blob into an envelope; this surfaces that refusal as
    /// a value for callers and tests.
    #[inline]
    #[must_use]
    pub const fn reject_opaque_payload(_payload: &[u8]) -> SignerEnvelopeError {
        SignerEnvelopeError::OpaqueBytesRejected
    }

    /// The four fields a signer is shown before approving.
    #[inline]
    #[must_use]
    pub const fn display_fields(&self) -> SignerDisplayFields {
        SignerDisplayFields {
            package: self.package,
            tx_digest_32: self.tx_digest_32,
            policy_hash_32: self.policy_hash_32,
            timelock_eta_secs_u64: self.timelock_eta_secs_u64,
        }
    }

    /// The fixed-width byte preimage derived from the displayed fields.
    pub fn exact_signing_preimage(&self) -> [u8; SIGNER_PREIMAGE_BYTES] {
        let mut out = [0u8; SIGNER_PREIMAGE_BYTES];
        let d = SIGNER_PREIMAGE_DOMAIN.len();
        out[..d].copy_from_slice(SIGNER_PREIMAGE_DOMAIN);
        out[d..d + 32].copy_from_slice(self.package.as_bytes());
        out[d + 32..d + 64].copy_from_slice(&self.tx_digest_32);
        out[d + 64..d + 96].copy_from_slice(&self.policy_hash_32);
        out[d + 96..d + 104].copy_from_slice(&self.timelock_eta_secs_u64.to_le_bytes());
        out
    }

    /// Verify a presented policy hash matches the envelope's.
    ///
    /// # Errors
    ///
    /// [`SignerEnvelopeError::PolicyHashMismatch`] when the hashes differ.
    pub fn verify_policy_hash(
        &self,
        presented_policy_hash_32: &[u8; 32],
    ) -> Result<(), SignerEnvelopeError> {
        if &self.policy_hash_32 == presented_policy_hash_32 {
            Ok(())
        } else {
            Err(SignerEnvelopeError::PolicyHashMismatch)
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    #![allow(clippy::expect_used)]
    #![allow(clippy::panic)]

    use super::*;
    use crate::stage_c_timelock::MIN_TIMELOCK_DELAY_SECS;

    /// `c1_13_exact_digest_vector` — the preimage is fixed-width, deterministic,
    /// and embeds each field at its known offset; the displayed fields equal
    /// the signed data.
    #[test]
    fn c1_13_exact_digest_vector() {
        let env = MainnetSignerEnvelope::new(
            ObjectId::new([0x22; 32]),
            [0xAB; 32],
            [0xCD; 32],
            1_700_000_000,
        )
        .expect("envelope builds");
        let pre = env.exact_signing_preimage();
        assert_eq!(pre.len(), SIGNER_PREIMAGE_BYTES);
        let d = b"mnemos.stage_c.mainnet_signer_envelope.v1".len();
        assert_eq!(&pre[d..d + 32], &[0x22u8; 32]);
        assert_eq!(&pre[d + 32..d + 64], &[0xABu8; 32]);
        assert_eq!(&pre[d + 64..d + 96], &[0xCDu8; 32]);
        assert_eq!(&pre[d + 96..d + 104], &1_700_000_000u64.to_le_bytes());

        let shown = env.display_fields();
        assert_eq!(shown.package, env.package);
        assert_eq!(shown.tx_digest_32, env.tx_digest_32);
        assert_eq!(shown.policy_hash_32, env.policy_hash_32);
        assert_eq!(shown.timelock_eta_secs_u64, env.timelock_eta_secs_u64);

        // ETA derives from the #213 timelock min delay.
        let policy = TimelockPolicy::from_parts(MIN_TIMELOCK_DELAY_SECS, 3_600, true).unwrap();
        let from_tl = MainnetSignerEnvelope::from_timelock(
            ObjectId::new([0x22; 32]),
            [0xAB; 32],
            [0xCD; 32],
            &policy,
            1_000,
        )
        .unwrap();
        assert_eq!(
            from_tl.timelock_eta_secs_u64,
            1_000 + u64::from(MIN_TIMELOCK_DELAY_SECS)
        );
    }

    /// `c1_13_policy_hash_mismatch_reject` — a presented policy hash that
    /// differs from the envelope's is rejected; the matching one passes; a zero
    /// policy hash blocks construction.
    #[test]
    fn c1_13_policy_hash_mismatch_reject() {
        let env = MainnetSignerEnvelope::new(ObjectId::new([0x22; 32]), [0xAB; 32], [0xCD; 32], 42)
            .expect("envelope builds");
        assert_eq!(env.verify_policy_hash(&[0xCD; 32]), Ok(()));
        assert_eq!(
            env.verify_policy_hash(&[0x00; 32]),
            Err(SignerEnvelopeError::PolicyHashMismatch),
        );
        assert_eq!(
            MainnetSignerEnvelope::new(ObjectId::new([0x22; 32]), [0xAB; 32], [0u8; 32], 42),
            Err(SignerEnvelopeError::PolicyHashRequired),
        );
    }

    /// `c1_13_opaque_bytes_reject` — an opaque payload cannot become an
    /// envelope, and a zero transaction digest is refused.
    #[test]
    fn c1_13_opaque_bytes_reject() {
        let opaque = [0x00u8, 0x01, 0x02, 0x03];
        assert_eq!(
            MainnetSignerEnvelope::reject_opaque_payload(&opaque),
            SignerEnvelopeError::OpaqueBytesRejected,
        );
        // A zero (i.e. absent / opaque) transaction digest is refused.
        assert_eq!(
            MainnetSignerEnvelope::new(ObjectId::new([0x22; 32]), [0u8; 32], [0xCD; 32], 42),
            Err(SignerEnvelopeError::TxDigestRequired),
        );
    }
}
