//! Stage C multisig proposal envelope (C-WP-05 · atom #212 · C.1.11).
//!
//! Canonical OUT: a mainnet proposal envelope bound to a package digest and a
//! checklist hash.
//!
//! # Madness invariants (atom #212)
//!
//! * **Signers approve exact bytes, not descriptions.** The envelope exposes a
//!   single fixed-width [`signing_preimage`](MultisigProposalEnvelope::signing_preimage)
//!   — `domain ‖ package ‖ package_digest ‖ checklist_hash ‖ roster_hash` — so
//!   what a signer commits to is the byte preimage, never a prose summary.
//! * **A checklist hash is mandatory.** A proposal with a zero checklist hash is
//!   rejected with [`ProposalError::ChecklistHashRequired`]; an unverified
//!   mainnet action cannot even be proposed.
//! * **The proposal is roster-bound.** The envelope stores the roster's
//!   signer-set hash (reused from atom #211, not re-minted); approving requires
//!   presenting a signer set whose canonical hash matches, and a signer outside
//!   that set is rejected with [`ProposalError::SignerNotInRoster`].
//!
//! # Reuse map (atom contract)
//!
//! * **reuse: #211** — [`signer_set_hash`](crate::stage_c_multisig::signer_set_hash)
//!   and [`MultisigRoster`](crate::stage_c_multisig::MultisigRoster). The
//!   binding hash is computed by the atom #211 canonical hasher.
//! * **reuse: #204** — the checklist hash is the §4.2 `MainnetChecklist`
//!   evidence hash (a 32-byte value), referenced by hash only; no `k-devex`
//!   type is imported here.

use crate::stage_c_multisig::{MultisigError, MultisigRoster, signer_set_hash};
use mnemos_d_move::types::{ObjectId, SuiAddress};

/// Domain separator for the proposal signing preimage.
const PROPOSAL_PREIMAGE_DOMAIN: &[u8] = b"mnemos.stage_c.multisig_proposal.v1";

/// Byte width of the proposal signing preimage: `domain ‖ package(32) ‖
/// package_digest(32) ‖ checklist_hash(32) ‖ roster_hash(32)`.
pub const PROPOSAL_PREIMAGE_BYTES: usize = PROPOSAL_PREIMAGE_DOMAIN.len() + 32 * 4;

/// A mainnet multisig proposal envelope bound to a package digest and a
/// checklist hash.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub struct MultisigProposalEnvelope {
    /// The on-chain package the proposal targets.
    pub package: ObjectId,
    /// The exact bytecode/transaction digest the signers approve.
    pub package_digest_32: [u8; 32],
    /// The §4.2 mainnet-checklist evidence hash the proposal is gated on.
    pub checklist_hash_32: [u8; 32],
    /// The atom #211 signer-set hash of the approving roster.
    pub roster_hash_32: [u8; 32],
}

/// Proposal construction / verification error. Every variant is data-free.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
#[repr(u8)]
pub enum ProposalError {
    /// The checklist hash was all-zero — an unverified action cannot be
    /// proposed.
    ChecklistHashRequired = 1,
    /// The presented package digest did not match the envelope's digest.
    DigestMismatch = 2,
    /// The presented signer set did not hash to the envelope's roster hash, or
    /// the approving signer was not a member of it.
    SignerNotInRoster = 3,
}

impl core::fmt::Display for ProposalError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let msg = match self {
            Self::ChecklistHashRequired => "stage_c proposal: checklist hash required (non-zero)",
            Self::DigestMismatch => "stage_c proposal: package digest mismatch",
            Self::SignerNotInRoster => "stage_c proposal: signer not in bound roster",
        };
        f.write_str(msg)
    }
}

impl core::error::Error for ProposalError {}

impl From<MultisigError> for ProposalError {
    /// A roster-hash recomputation failure (count/dup) means the presented set
    /// cannot be the bound roster.
    fn from(_: MultisigError) -> Self {
        Self::SignerNotInRoster
    }
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

impl MultisigProposalEnvelope {
    /// Build a proposal envelope binding a package + its digest + a checklist
    /// hash to a roster.
    ///
    /// # Errors
    ///
    /// [`ProposalError::ChecklistHashRequired`] when `checklist_hash_32` is
    /// all-zero.
    pub fn new(
        package: ObjectId,
        package_digest_32: [u8; 32],
        checklist_hash_32: [u8; 32],
        roster: &MultisigRoster,
    ) -> Result<Self, ProposalError> {
        if is_zero_32(&checklist_hash_32) {
            return Err(ProposalError::ChecklistHashRequired);
        }
        Ok(Self {
            package,
            package_digest_32,
            checklist_hash_32,
            roster_hash_32: roster.signer_hash(),
        })
    }

    /// The exact byte preimage the signers approve.
    pub fn signing_preimage(&self) -> [u8; PROPOSAL_PREIMAGE_BYTES] {
        let mut out = [0u8; PROPOSAL_PREIMAGE_BYTES];
        let d = PROPOSAL_PREIMAGE_DOMAIN.len();
        out[..d].copy_from_slice(PROPOSAL_PREIMAGE_DOMAIN);
        out[d..d + 32].copy_from_slice(self.package.as_bytes());
        out[d + 32..d + 64].copy_from_slice(&self.package_digest_32);
        out[d + 64..d + 96].copy_from_slice(&self.checklist_hash_32);
        out[d + 96..d + 128].copy_from_slice(&self.roster_hash_32);
        out
    }

    /// Verify the presented package digest matches the envelope.
    ///
    /// # Errors
    ///
    /// [`ProposalError::DigestMismatch`] when the digests differ.
    pub fn verify_package_digest(
        &self,
        presented_digest_32: &[u8; 32],
    ) -> Result<(), ProposalError> {
        if &self.package_digest_32 == presented_digest_32 {
            Ok(())
        } else {
            Err(ProposalError::DigestMismatch)
        }
    }

    /// Check that `signer` is a member of the roster this envelope is bound to.
    ///
    /// The full `roster_signers` set is recomputed through the atom #211
    /// canonical hasher and compared against the envelope's `roster_hash_32`
    /// (so a substituted set cannot pass), then membership of `signer` is
    /// checked.
    ///
    /// # Errors
    ///
    /// [`ProposalError::SignerNotInRoster`] when the set does not bind to the
    /// envelope's roster hash, or when `signer` is not in the set.
    pub fn check_signer_in_roster(
        &self,
        signer: SuiAddress,
        roster_signers: &[SuiAddress],
    ) -> Result<(), ProposalError> {
        let (hash, _count) = signer_set_hash(roster_signers)?;
        if hash != self.roster_hash_32 {
            return Err(ProposalError::SignerNotInRoster);
        }
        if roster_signers.contains(&signer) {
            Ok(())
        } else {
            Err(ProposalError::SignerNotInRoster)
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    #![allow(clippy::expect_used)]
    #![allow(clippy::panic)]

    use super::*;

    fn addr(b: u8) -> SuiAddress {
        SuiAddress::new([b; 32])
    }

    fn sample_roster() -> (MultisigRoster, [SuiAddress; 3]) {
        let signers = [addr(1), addr(2), addr(3)];
        let roster = MultisigRoster::from_signers(&signers, 2).expect("roster builds");
        (roster, signers)
    }

    /// `c1_11_digest_mismatch_reject` — a presented digest that differs from
    /// the envelope's bound digest is rejected; the matching digest passes.
    #[test]
    fn c1_11_digest_mismatch_reject() {
        let (roster, _) = sample_roster();
        let env = MultisigProposalEnvelope::new(
            ObjectId::new([0x22; 32]),
            [0xAB; 32],
            [0xCD; 32],
            &roster,
        )
        .expect("envelope builds");
        assert_eq!(env.verify_package_digest(&[0xAB; 32]), Ok(()));
        assert_eq!(
            env.verify_package_digest(&[0x00; 32]),
            Err(ProposalError::DigestMismatch),
        );
        assert_eq!(env.signing_preimage().len(), PROPOSAL_PREIMAGE_BYTES);
    }

    /// `c1_11_checklist_hash_required` — a zero checklist hash blocks
    /// construction.
    #[test]
    fn c1_11_checklist_hash_required() {
        let (roster, _) = sample_roster();
        assert_eq!(
            MultisigProposalEnvelope::new(
                ObjectId::new([0x22; 32]),
                [0xAB; 32],
                [0u8; 32],
                &roster
            ),
            Err(ProposalError::ChecklistHashRequired),
        );
    }

    /// `c1_11_signer_not_in_roster_reject` — a signer outside the bound roster
    /// is rejected, an in-roster signer passes, and a substituted signer set
    /// (different hash) is rejected.
    #[test]
    fn c1_11_signer_not_in_roster_reject() {
        let (roster, signers) = sample_roster();
        let env = MultisigProposalEnvelope::new(
            ObjectId::new([0x22; 32]),
            [0xAB; 32],
            [0xCD; 32],
            &roster,
        )
        .expect("envelope builds");

        // In-roster signer passes.
        assert_eq!(env.check_signer_in_roster(addr(2), &signers), Ok(()));
        // Out-of-roster signer rejected.
        assert_eq!(
            env.check_signer_in_roster(addr(9), &signers),
            Err(ProposalError::SignerNotInRoster),
        );
        // Substituted set (binds to a different roster hash) rejected even for
        // a member of the substituted set.
        let substituted = [addr(4), addr(5), addr(6)];
        assert_eq!(
            env.check_signer_in_roster(addr(4), &substituted),
            Err(ProposalError::SignerNotInRoster),
        );
    }
}
