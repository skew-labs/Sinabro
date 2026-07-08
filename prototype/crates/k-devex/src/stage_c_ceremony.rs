//! Mainnet ceremony transcript builder.
//!
//! A reproducible, hash-addressed ceremony transcript binding the
//! package lock, checklist evidence hash, multisig roster hash, timelock policy,
//! and the exact transaction digest the operator will sign.
//!
//! # Invariants
//!
//! * **Reproducible and hash-addressed.** [`CeremonyTranscript`] serializes to a
//!   fixed-width canonical preimage ([`CEREMONY_PREIMAGE_BYTES`]); the same
//!   inputs always produce the same bytes and therefore the same
//!   [`transcript_hash`](CeremonyTranscript::transcript_hash). The transcript is
//!   addressed by that hash.
//! * **The operator sees exactly what will be signed.** Every field — package
//!   lock, checklist evidence, multisig roster, timelock delays, and the exact
//!   tx digest — is present in the transcript and in the preimage. There is no
//!   hidden field and no signing here: this builder produces a transcript, it
//!   does not execute a ceremony.
//! * **Missing inputs are red.** A zero checklist evidence hash
//!   ([`CeremonyError::MissingChecklistEvidence`]), a zero exact tx digest
//!   ([`CeremonyError::MissingTxDigest`]), or a zero multisig roster hash
//!   ([`CeremonyError::MissingMultisigRoster`]) refuses construction — an
//!   unbound ceremony can never be addressed.
//!
//! # Related
//!
//! * [`MainnetChecklist`](crate::stage_c_checklist::MainnetChecklist)
//!   supplies the bound evidence hash (same crate).
//! * [`MainnetPackageLock`](mnemos_d_move::stage_c_package_lock::MainnetPackageLock)
//!   supplies the package / bytecode / prover / gas-baseline commitment (`d-move`).
//! * The `exact_tx_digest_32` is the
//!   `MainnetSignerEnvelope::tx_digest_32` (`g-wallet`). This module
//!   consumes the digest *value* rather than importing the envelope type, so
//!   `k-devex` does not gain a `g-wallet` dependency. The cross-type binding —
//!   that this digest equals the envelope's — is proven in the `o-stage-c-e2e`
//!   integration crate, which depends on both `g-wallet` and `k-devex`
//!   (the test home owns both symbols).
//!
//! No live action: this builds and hashes a transcript. No signing, no
//! submission, no egress. `MainnetExecutionState` stays `Locked`; the referenced
//! checklist caps at `ApprovalPending`, never `Executed`.

use blake2::{Blake2b, Digest, digest::consts::U32};
use mnemos_d_move::stage_c_package_lock::{MAINNET_PACKAGE_LOCK_BYTES, MainnetPackageLock};

use crate::stage_c_checklist::MainnetChecklist;

/// Domain separator for the ceremony transcript preimage / hash.
const CEREMONY_DOMAIN: &[u8] = b"mnemos.stage_c.mainnet_ceremony.v1";

/// Fixed-width canonical transcript preimage length:
/// domain ‖ package_lock(128) ‖ checklist_evidence(32) ‖ multisig_hash(32)
/// ‖ timelock_min_delay(4) ‖ timelock_cancel_window(4) ‖ exact_tx_digest(32)
/// ‖ signer_policy_hash(32).
pub const CEREMONY_PREIMAGE_BYTES: usize =
    CEREMONY_DOMAIN.len() + MAINNET_PACKAGE_LOCK_BYTES + 32 + 32 + 4 + 4 + 32 + 32;

/// A reproducible, hash-addressed mainnet ceremony transcript.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub struct CeremonyTranscript {
    /// The package lock (package id + bytecode/prover/gas-baseline hashes).
    pub package_lock: MainnetPackageLock,
    /// The checklist's bound evidence hash (non-zero).
    pub checklist_evidence_hash_32: [u8; 32],
    /// The multisig roster hash that must approve (non-zero).
    pub multisig_roster_hash_32: [u8; 32],
    /// The timelock minimum delay in seconds.
    pub timelock_min_delay_secs_u32: u32,
    /// The timelock cancel window in seconds.
    pub timelock_cancel_window_secs_u32: u32,
    /// The exact transaction digest the operator will sign (non-zero). Equals
    /// the `MainnetSignerEnvelope::tx_digest_32`.
    pub exact_tx_digest_32: [u8; 32],
    /// The Gas Station / mainnet policy hash this signature is bound to.
    pub signer_policy_hash_32: [u8; 32],
}

/// Ceremony transcript construction error. Every variant is data-free.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
#[repr(u8)]
pub enum CeremonyError {
    /// The checklist had no bound evidence hash (all-zero).
    MissingChecklistEvidence = 1,
    /// The exact transaction digest was all-zero.
    MissingTxDigest = 2,
    /// The multisig roster hash was all-zero.
    MissingMultisigRoster = 3,
}

impl core::fmt::Display for CeremonyError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let msg = match self {
            Self::MissingChecklistEvidence => "stage_c ceremony: checklist evidence hash required",
            Self::MissingTxDigest => "stage_c ceremony: exact tx digest required (non-zero)",
            Self::MissingMultisigRoster => "stage_c ceremony: multisig roster hash required",
        };
        f.write_str(msg)
    }
}

impl core::error::Error for CeremonyError {}

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

impl CeremonyTranscript {
    /// Build a transcript, refusing any unbound (zero) commitment.
    ///
    /// # Errors
    ///
    /// [`CeremonyError::MissingChecklistEvidence`] when the checklist has no
    /// bound evidence hash, [`CeremonyError::MissingTxDigest`] when the exact tx
    /// digest is zero, and [`CeremonyError::MissingMultisigRoster`] when the
    /// multisig roster hash is zero.
    pub fn build(
        package_lock: MainnetPackageLock,
        checklist: &MainnetChecklist,
        multisig_roster_hash_32: [u8; 32],
        timelock_min_delay_secs_u32: u32,
        timelock_cancel_window_secs_u32: u32,
        exact_tx_digest_32: [u8; 32],
        signer_policy_hash_32: [u8; 32],
    ) -> Result<Self, CeremonyError> {
        if !checklist.has_evidence_hash() {
            return Err(CeremonyError::MissingChecklistEvidence);
        }
        if is_zero_32(&exact_tx_digest_32) {
            return Err(CeremonyError::MissingTxDigest);
        }
        if is_zero_32(&multisig_roster_hash_32) {
            return Err(CeremonyError::MissingMultisigRoster);
        }
        Ok(Self {
            package_lock,
            checklist_evidence_hash_32: checklist.evidence_hash_32,
            multisig_roster_hash_32,
            timelock_min_delay_secs_u32,
            timelock_cancel_window_secs_u32,
            exact_tx_digest_32,
            signer_policy_hash_32,
        })
    }

    /// The fixed-width canonical preimage. Deterministic: equal inputs give
    /// equal bytes.
    #[must_use]
    pub fn preimage(&self) -> [u8; CEREMONY_PREIMAGE_BYTES] {
        let mut out = [0u8; CEREMONY_PREIMAGE_BYTES];
        let mut o = 0usize;
        let d = CEREMONY_DOMAIN.len();
        out[o..o + d].copy_from_slice(CEREMONY_DOMAIN);
        o += d;
        out[o..o + MAINNET_PACKAGE_LOCK_BYTES].copy_from_slice(&self.package_lock.to_bytes());
        o += MAINNET_PACKAGE_LOCK_BYTES;
        out[o..o + 32].copy_from_slice(&self.checklist_evidence_hash_32);
        o += 32;
        out[o..o + 32].copy_from_slice(&self.multisig_roster_hash_32);
        o += 32;
        out[o..o + 4].copy_from_slice(&self.timelock_min_delay_secs_u32.to_le_bytes());
        o += 4;
        out[o..o + 4].copy_from_slice(&self.timelock_cancel_window_secs_u32.to_le_bytes());
        o += 4;
        out[o..o + 32].copy_from_slice(&self.exact_tx_digest_32);
        o += 32;
        out[o..o + 32].copy_from_slice(&self.signer_policy_hash_32);
        out
    }

    /// The hash address of this transcript: `Blake2b-256(preimage)`.
    #[must_use]
    pub fn transcript_hash(&self) -> [u8; 32] {
        let mut h = Blake2b::<U32>::new();
        h.update(self.preimage());
        h.finalize().into()
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]
    use super::*;
    use mnemos_d_move::types::ObjectId;

    fn lock() -> MainnetPackageLock {
        MainnetPackageLock::new(
            ObjectId::new([0x33; 32]),
            [0x44; 32],
            [0x55; 32],
            [0x66; 32],
        )
        .expect("valid package lock")
    }

    fn green_checklist() -> MainnetChecklist {
        MainnetChecklist::new_locked().with_evidence_hash([0x77; 32])
    }

    #[test]
    fn transcript_hash_stable() {
        let t1 = CeremonyTranscript::build(
            lock(),
            &green_checklist(),
            [0x88; 32],
            3600,
            1800,
            [0x99; 32],
            [0xAA; 32],
        )
        .expect("bound transcript");
        let t2 = CeremonyTranscript::build(
            lock(),
            &green_checklist(),
            [0x88; 32],
            3600,
            1800,
            [0x99; 32],
            [0xAA; 32],
        )
        .expect("bound transcript");
        // Reproducible: same inputs -> same preimage -> same hash.
        assert_eq!(t1.preimage(), t2.preimage());
        assert_eq!(t1.transcript_hash(), t2.transcript_hash());
        assert_eq!(t1.preimage().len(), CEREMONY_PREIMAGE_BYTES);
        // A changed timelock delay changes the address.
        let t3 = CeremonyTranscript::build(
            lock(),
            &green_checklist(),
            [0x88; 32],
            7200,
            1800,
            [0x99; 32],
            [0xAA; 32],
        )
        .expect("bound transcript");
        assert_ne!(t1.transcript_hash(), t3.transcript_hash());
    }

    #[test]
    fn digest_mismatch_red() {
        // A zero exact tx digest is refused.
        assert_eq!(
            CeremonyTranscript::build(
                lock(),
                &green_checklist(),
                [0x88; 32],
                3600,
                1800,
                [0u8; 32],
                [0xAA; 32],
            ),
            Err(CeremonyError::MissingTxDigest)
        );
        // A zero multisig roster hash is refused.
        assert_eq!(
            CeremonyTranscript::build(
                lock(),
                &green_checklist(),
                [0u8; 32],
                3600,
                1800,
                [0x99; 32],
                [0xAA; 32],
            ),
            Err(CeremonyError::MissingMultisigRoster)
        );
    }

    #[test]
    fn missing_checklist_red() {
        // A checklist with no bound evidence hash is refused.
        let unbound = MainnetChecklist::new_locked();
        assert_eq!(
            CeremonyTranscript::build(
                lock(),
                &unbound,
                [0x88; 32],
                3600,
                1800,
                [0x99; 32],
                [0xAA; 32],
            ),
            Err(CeremonyError::MissingChecklistEvidence)
        );
    }
}
