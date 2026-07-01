//! `chain_execute` — ONCHAIN PIVOT C-0: the single gated CHOKEPOINT for an owner-BOUNDED
//! on-chain transaction. Mirrors [`crate::mutate_execute::execute_authorized_mutate`]: it
//! requires a [`ChainTxCapability`] witness, so a chain tx is UNREACHABLE without a VALID
//! owner-armed, within-bounds custody authorization (the witness is minted ONLY by
//! [`ChainTxCapability::from_grant`](crate::commands::authority::ChainTxCapability::from_grant)).
//!
//! ## C-0 is PURE / INERT (money 0)
//! This chokepoint validates the witness and returns a typed RECEIPT of what it WOULD do — it
//! does NOT sign or broadcast: no signing key is held or read, no RPC is dialed, no transaction
//! is built or sent. The real build → sign (isolated signer) → broadcast is the C-2 slice, added
//! UNDER THE SAME `ChainTxCapability` witness + testnet-first. Beyond the user's armed bound,
//! custody stays HARD-LOCKED; the blanket `CustodyCapability` stays uninhabited (unbounded custody
//! is impossible). custody/funds never move autonomously outside an owner-armed bounded grant.

use crate::commands::authority::ChainTxCapability;
use crate::commands::grant::ChainTxRequest;

/// The status of a bounded chain-tx at the C-0 chokepoint.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ChainTxStatus {
    /// C-0: the tx was AUTHORIZED within the owner's bounds, but C-0 does NOT sign or broadcast
    /// — it WOULD build + sign + broadcast in C-2. No money moved, no key touched.
    WouldExecute,
}

/// A receipt for one bounded chain-tx at the C-0 chokepoint (metadata only — NO key, NO
/// signature, NO broadcast). Records what was authorized + that C-0 is inert.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ChainTxReceipt {
    /// The authorized tx request (chain / protocol / amount).
    pub request: ChainTxRequest,
    /// The C-0 status (always `WouldExecute` — inert).
    pub status: ChainTxStatus,
}

/// THE single C-0 chokepoint: "execute" (INERT) an owner-BOUNDED chain tx. Requires a
/// [`ChainTxCapability`] witness BY VALUE — so this is UNREACHABLE without a valid owner-armed,
/// within-bounds custody authorization, and the single-shot witness is consumed here. C-0 does
/// NOT sign or broadcast: it returns a receipt of what it WOULD do, money 0 (C-2 adds the
/// isolated signer + the RPC broadcast under the SAME witness, testnet-first).
#[must_use]
pub fn execute_authorized_chain_tx(
    _capability: ChainTxCapability,
    tx: &ChainTxRequest,
) -> ChainTxReceipt {
    // C-0: the witness proves owner-armed, within-bounds authorization. We DO NOT sign or
    // broadcast — no key, no transport. Return the inert "would-execute" receipt.
    ChainTxReceipt {
        request: tx.clone(),
        status: ChainTxStatus::WouldExecute,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::commands::authority::ChainTxCapability;
    use crate::commands::grant::{
        CUSTODY_ARM_PHRASE, ChainTxRequest, CustodyBounds, CustodyGrant, GrantBounds, GrantTier,
        OwnerArmCeremony,
    };
    use crate::repl::approval::ApprovalPrompt;

    fn capability_and_tx() -> (ChainTxCapability, ChainTxRequest) {
        use crate::command::ApprovalRequirement;
        let mut p = ApprovalPrompt::new(ApprovalRequirement::TypedPhrase, CUSTODY_ARM_PHRASE);
        let c =
            OwnerArmCeremony::complete(&mut p, CUSTODY_ARM_PHRASE, GrantTier::Custody, [9u8; 32])
                .expect("ceremony");
        let g = CustodyGrant::arm(
            c,
            CustodyBounds {
                base: GrantBounds {
                    max_actions_u32: 2,
                    expires_at_epoch_ms: 1000,
                },
                per_tx_max_minor: 1000,
                total_budget_minor: 1000,
                chain_allowlist: vec!["ethereum".to_string()],
                protocol_allowlist: vec!["uniswap".to_string()],
            },
        )
        .expect("arm");
        let tx = ChainTxRequest {
            chain: "ethereum".to_string(),
            protocol: "uniswap".to_string(),
            amount_minor: 500,
        };
        let cap = ChainTxCapability::from_grant(&g, 1, 0, 0, &tx).expect("within bounds");
        (cap, tx)
    }

    /// The chokepoint requires the witness (the type system enforces it) and is INERT: it
    /// returns a `WouldExecute` receipt — no signing, no broadcast, money 0.
    #[test]
    fn chokepoint_is_inert_and_witness_gated() {
        let (cap, tx) = capability_and_tx();
        let receipt = execute_authorized_chain_tx(cap, &tx);
        assert_eq!(receipt.status, ChainTxStatus::WouldExecute);
        assert_eq!(receipt.request, tx);
    }
}
