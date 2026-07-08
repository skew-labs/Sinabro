//! Stage C no-single-key mainnet guard.
//!
//! A compile/runtime guard blocking a single-key mainnet publish/sign path.
//!
//! # Invariants
//!
//! * **A single key cannot author a mainnet mutation.** A
//!   [`MainnetSigningAuthority`] is the only token that represents
//!   "authorised to execute on mainnet", and its sole constructor
//!   ([`authorize`](MainnetSigningAuthority::authorize)) requires at least
//!   `roster.threshold` (`>= 2`) **distinct** approvers, each a
//!   member of the bound roster. There is no constructor that takes a single
//!   [`ScopedSecretKey`](crate::keystore::ScopedSecretKey), so the single-key
//!   path is unrepresentable, not merely checked.
//! * **Testnet signing is unaffected.** This guard governs only the mainnet
//!   authority token. The Stage B testnet signing surface
//!   ([`sign_testnet_call`](crate::stage_b_sign_tx::sign_testnet_call),
//!   [`sign_chunk_digest`](crate::stage_b_sign_message::sign_chunk_digest)) is
//!   a separate path that this type neither wraps nor restricts — a single
//!   testnet key keeps working for faucet-funded testnet actions.
//!
//! # Reuse
//!
//! * [`ScopedSecretKey`](crate::keystore::ScopedSecretKey) — the per-signer
//!   secret remains the zeroizing, non-`Debug`/`Clone` type. One
//!   `ScopedSecretKey` yields at most one approval, which is below the `>= 2`
//!   threshold by construction.
//! * The roster ([`MultisigRoster`](crate::stage_c_multisig::MultisigRoster))
//!   and its signer-set hash; the authority is bound to the roster hash so a
//!   substituted signer set cannot manufacture authority.

use crate::stage_c_multisig::{MultisigError, MultisigRoster, signer_set_hash};
use mnemos_d_move::types::SuiAddress;

/// A token proving that at least `threshold` distinct, in-roster signers have
/// approved a mainnet action. There is intentionally no constructor from a
/// single key.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub struct MainnetSigningAuthority {
    /// The signer-set hash of the roster that authorised the action.
    roster_hash_32: [u8; 32],
    /// The number of distinct in-roster approvers (`>= threshold`).
    approvals_u8: u8,
    /// The roster's approval threshold (`>= 2`).
    threshold_u8: u8,
}

/// Authority construction error. Every variant is data-free.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
#[repr(u8)]
pub enum NoSingleKeyError {
    /// Fewer distinct approvers than the roster threshold — the single-key (or
    /// below-threshold) path is refused.
    ThresholdNotMet = 1,
    /// An approver appeared more than once.
    DuplicateApproval = 2,
    /// An approver was not a member of the bound roster, or the presented
    /// roster set did not bind to the roster's hash.
    ApproverNotInRoster = 3,
}

impl core::fmt::Display for NoSingleKeyError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let msg = match self {
            Self::ThresholdNotMet => "stage_c no-single-key: distinct approvers below threshold",
            Self::DuplicateApproval => "stage_c no-single-key: duplicate approver",
            Self::ApproverNotInRoster => "stage_c no-single-key: approver not in bound roster",
        };
        f.write_str(msg)
    }
}

impl core::error::Error for NoSingleKeyError {}

impl From<MultisigError> for NoSingleKeyError {
    fn from(_: MultisigError) -> Self {
        Self::ApproverNotInRoster
    }
}

impl MainnetSigningAuthority {
    /// Authorise a mainnet action from a roster + its signer set + the set of
    /// approvers.
    ///
    /// # Errors
    ///
    /// - [`NoSingleKeyError::ApproverNotInRoster`] when the presented signer
    ///   set does not bind to `roster`'s hash, or an approver is not a member.
    /// - [`NoSingleKeyError::DuplicateApproval`] when an approver repeats.
    /// - [`NoSingleKeyError::ThresholdNotMet`] when fewer than
    ///   `roster.threshold` distinct approvers are present (this is the
    ///   single-key refusal).
    pub fn authorize(
        roster: &MultisigRoster,
        roster_signers: &[SuiAddress],
        approvers: &[SuiAddress],
    ) -> Result<Self, NoSingleKeyError> {
        // The presented signer set must be the roster the authority binds to.
        let (set_hash, _count) = signer_set_hash(roster_signers)?;
        if set_hash != roster.signer_hash() {
            return Err(NoSingleKeyError::ApproverNotInRoster);
        }

        // Count distinct approvers, each a roster member; reject duplicates.
        let mut distinct: u8 = 0;
        for (i, approver) in approvers.iter().enumerate() {
            if !roster_signers.contains(approver) {
                return Err(NoSingleKeyError::ApproverNotInRoster);
            }
            if approvers[..i].contains(approver) {
                return Err(NoSingleKeyError::DuplicateApproval);
            }
            distinct = distinct.saturating_add(1);
        }

        if distinct < roster.threshold_u8 {
            return Err(NoSingleKeyError::ThresholdNotMet);
        }

        Ok(Self {
            roster_hash_32: roster.signer_hash(),
            approvals_u8: distinct,
            threshold_u8: roster.threshold_u8,
        })
    }

    /// The number of distinct approvers that produced this authority.
    #[inline]
    #[must_use]
    pub const fn approvals(&self) -> u8 {
        self.approvals_u8
    }

    /// The threshold this authority satisfied.
    #[inline]
    #[must_use]
    pub const fn threshold(&self) -> u8 {
        self.threshold_u8
    }

    /// The roster hash this authority is bound to.
    #[inline]
    #[must_use]
    pub const fn roster_hash(&self) -> [u8; 32] {
        self.roster_hash_32
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

    fn roster_2of3() -> (MultisigRoster, [SuiAddress; 3]) {
        let signers = [addr(1), addr(2), addr(3)];
        (
            MultisigRoster::from_signers(&signers, 2).expect("builds"),
            signers,
        )
    }

    /// `c1_14_single_key_mainnet_sign_reject` — a single approver (the
    /// single-key path) is below the `>= 2` threshold and is refused; two
    /// distinct in-roster approvers succeed.
    #[test]
    fn c1_14_single_key_mainnet_sign_reject() {
        let (roster, signers) = roster_2of3();

        // One approver = single-key path = rejected.
        assert_eq!(
            MainnetSigningAuthority::authorize(&roster, &signers, &[addr(1)]),
            Err(NoSingleKeyError::ThresholdNotMet),
        );
        // Zero approvers = rejected.
        assert_eq!(
            MainnetSigningAuthority::authorize(&roster, &signers, &[]),
            Err(NoSingleKeyError::ThresholdNotMet),
        );

        // Two distinct in-roster approvers = authorised.
        let authority = MainnetSigningAuthority::authorize(&roster, &signers, &[addr(1), addr(2)])
            .expect("2-of-3 authority builds");
        assert_eq!(authority.approvals(), 2);
        assert_eq!(authority.threshold(), 2);
        assert_eq!(authority.roster_hash(), roster.signer_hash());
    }

    /// `c1_14_duplicate_and_outsider_reject` — a repeated approver and an
    /// out-of-roster approver are both refused (a single key cannot be counted
    /// twice to fake a threshold).
    #[test]
    fn c1_14_duplicate_and_outsider_reject() {
        let (roster, signers) = roster_2of3();

        // The same key approving twice does not reach the threshold.
        assert_eq!(
            MainnetSigningAuthority::authorize(&roster, &signers, &[addr(1), addr(1)]),
            Err(NoSingleKeyError::DuplicateApproval),
        );
        // An outsider cannot contribute an approval.
        assert_eq!(
            MainnetSigningAuthority::authorize(&roster, &signers, &[addr(1), addr(9)]),
            Err(NoSingleKeyError::ApproverNotInRoster),
        );
        // A substituted roster set does not bind.
        assert_eq!(
            MainnetSigningAuthority::authorize(
                &roster,
                &[addr(4), addr(5), addr(6)],
                &[addr(4), addr(5)]
            ),
            Err(NoSingleKeyError::ApproverNotInRoster),
        );
    }

    /// `c1_14_testnet_sign_unaffected` — the mainnet authority guard is a
    /// separate surface; the Stage B testnet wallet config (the testnet signing
    /// posture) still builds normally and is in no way gated by this type. No
    /// signing is performed.
    #[test]
    fn c1_14_testnet_sign_unaffected() {
        use crate::stage_b_config::StageBTestnetWalletConfig;
        use mnemos_b_memory::network::StageBNetwork;
        use mnemos_d_move::types::GasBudgetMist;

        // The testnet path is untouched: a testnet wallet config builds with a
        // single (testnet) key posture, independent of any mainnet threshold.
        let testnet_cfg =
            StageBTestnetWalletConfig::new(StageBNetwork::Testnet, GasBudgetMist::new(800_000));
        assert_eq!(testnet_cfg.network(), StageBNetwork::Testnet);

        // Meanwhile the mainnet authority still demands a threshold.
        let (roster, signers) = roster_2of3();
        assert!(MainnetSigningAuthority::authorize(&roster, &signers, &[addr(1)]).is_err());
    }
}
