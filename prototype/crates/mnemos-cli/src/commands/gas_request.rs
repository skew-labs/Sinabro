//! `sinabro gas request` — gasless intent + local policy precheck + lease revoke
//! (F-WP-05C, atom #449 · F.5.6 gas request/quota/dry-run/revoke).
//!
//! The CLI constructs a *gasless* intent and runs a **local advisory precheck**
//! before ever requesting a sponsor, so the user sees a likely
//! dry-run/quota/lease outcome without a round trip. Two custody rules are
//! structural:
//!
//! * **The sponsor is never the memory owner.** A precheck whose sponsor key
//!   equals the owner key is rejected with the canonical
//!   [`GasStationRejectReason::Identity`], and
//!   [`GasRequestPrecheck::sponsor_can_sign_owner_intent`] is the invariant
//!   `false` — a hosted sponsor pays policy-limited gas and can never sign the
//!   memory-ownership intent.
//! * **This precheck is a SUBSET, not the authority.** It covers only the
//!   locally-checkable gates (sponsor≠owner identity, wildcard mask, function
//!   allowlist, dry-run-done, quota, gas-coin lease), reusing the canonical
//!   [`GasStationRejectReason`] taxonomy, the
//!   [`GasStationPolicy::FUNCTION_BITS_MASK`] constant and
//!   [`SponsoredFunction::bit`]. The authoritative effect-shape,
//!   attestation, nonce and full-reconstruction checks run in g-wallet
//!   `evaluate_sponsorship` at the (future, non-Stage-F) real signer boundary —
//!   this module never signs and never spends.
//!
//! Lease revoke reuses the canonical [`GasCoinLeaseError`] taxonomy.

use mnemos_g_wallet::{
    GasCoinLeaseError, GasStationPolicy, GasStationRejectReason, SponsoredFunction,
};

/// Local view of a gas-coin lease's state, for the revoke precheck.
#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LeaseState {
    /// A live, non-expired lease is held — revocable.
    Active = 1,
    /// No lease exists for the coin.
    Absent = 2,
    /// The lease has expired.
    Expired = 3,
    /// The presented lease id is superseded (a newer lease exists).
    Superseded = 4,
}

/// The inputs to a local gas-request precheck — the locally-checkable subset of
/// the canonical sponsorship gates. No d-move type is constructed: the allowlist
/// is a `u16` mask, the function is the canonical [`SponsoredFunction`], and
/// identities are 32-byte public keys.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct GasRequestPrecheck {
    /// The function the request claims to invoke.
    pub function: SponsoredFunction,
    /// The policy allowlist bitmask (over [`SponsoredFunction`] bits).
    pub allowed_mask_u16: u16,
    /// Whether the local dry-run completed successfully (effect shape confirmed).
    pub dry_run_ok: bool,
    /// Whether the request is within the per-identity quota.
    pub within_quota: bool,
    /// Whether a valid, uncontended gas-coin lease is held.
    pub lease_active: bool,
    /// The memory-owner public key.
    pub owner_pubkey_32: [u8; 32],
    /// The gas-sponsor public key (must differ from the owner).
    pub sponsor_pubkey_32: [u8; 32],
}

impl GasRequestPrecheck {
    /// Run the local advisory precheck in the canonical order. `Ok(())` means the
    /// request may proceed to the real sponsor boundary; otherwise the canonical
    /// reject reason. This is the locally-checkable subset (see the module doc).
    ///
    /// # Errors
    ///
    /// - [`GasStationRejectReason::Identity`] when sponsor == owner.
    /// - [`GasStationRejectReason::Wildcard`] when the mask sets a reserved bit.
    /// - [`GasStationRejectReason::PackageFunction`] when the function is not on
    ///   the allowlist.
    /// - [`GasStationRejectReason::EffectShape`] when the dry-run was aborted /
    ///   not completed.
    /// - [`GasStationRejectReason::QuotaRisk`] when over quota.
    /// - [`GasStationRejectReason::GasCoinLease`] when no valid lease is held.
    pub fn evaluate(&self) -> Result<(), GasStationRejectReason> {
        // 0. Identity: the sponsor must never be the memory owner.
        if self.sponsor_pubkey_32 == self.owner_pubkey_32 {
            return Err(GasStationRejectReason::Identity);
        }
        // 1. Wildcard: no reserved/wildcard allowlist bit.
        if self.allowed_mask_u16 & !GasStationPolicy::FUNCTION_BITS_MASK != 0 {
            return Err(GasStationRejectReason::Wildcard);
        }
        // 2. Function allowlist.
        if self.allowed_mask_u16 & self.function.bit() == 0 {
            return Err(GasStationRejectReason::PackageFunction);
        }
        // 3. Dry-run abort => effect shape not confirmed.
        if !self.dry_run_ok {
            return Err(GasStationRejectReason::EffectShape);
        }
        // 4. Quota.
        if !self.within_quota {
            return Err(GasStationRejectReason::QuotaRisk);
        }
        // 5. Gas-coin lease.
        if !self.lease_active {
            return Err(GasStationRejectReason::GasCoinLease);
        }
        Ok(())
    }

    /// Whether the local precheck accepts the request.
    #[must_use]
    pub fn is_accepted(&self) -> bool {
        self.evaluate().is_ok()
    }

    /// Whether a sponsor may sign the memory-ownership intent. Always `false`:
    /// the sponsor pays policy-limited gas and never signs ownership.
    #[must_use]
    pub const fn sponsor_can_sign_owner_intent(&self) -> bool {
        false
    }

    /// Redacted, colorless precheck lines bounded by `rows`.
    #[must_use]
    pub fn render(&self, rows: u16) -> Vec<String> {
        let verdict = match self.evaluate() {
            Ok(()) => "accepted".to_string(),
            Err(reason) => format!("reject_u8={}", reason.as_u8()),
        };
        let lines = vec![
            format!("function_u8={}", self.function.as_u8()),
            format!("allowed_mask_u16={}", self.allowed_mask_u16),
            format!("dry_run_ok={}", self.dry_run_ok),
            format!("within_quota={}", self.within_quota),
            format!("lease_active={}", self.lease_active),
            format!(
                "sponsor_can_sign_owner_intent={}",
                self.sponsor_can_sign_owner_intent()
            ),
            format!("verdict={verdict}"),
        ];
        lines.into_iter().take(rows as usize).collect()
    }
}

/// Revoke a gas-coin lease locally, reusing the canonical lease-error taxonomy.
/// An active lease is revocable; the other states map to their canonical errors.
///
/// # Errors
///
/// - [`GasCoinLeaseError::NoSuchLease`] when no lease exists.
/// - [`GasCoinLeaseError::Expired`] when the lease has already expired.
/// - [`GasCoinLeaseError::StaleLease`] when the presented lease id is superseded.
pub const fn revoke_lease(state: LeaseState) -> Result<(), GasCoinLeaseError> {
    match state {
        LeaseState::Active => Ok(()),
        LeaseState::Absent => Err(GasCoinLeaseError::NoSuchLease),
        LeaseState::Expired => Err(GasCoinLeaseError::Expired),
        LeaseState::Superseded => Err(GasCoinLeaseError::StaleLease),
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    #![allow(clippy::expect_used)]
    #![allow(clippy::panic)]

    use super::*;
    use crate::repl::latency::p95_ms;

    fn key(b: u8) -> [u8; 32] {
        [b; 32]
    }

    fn base() -> GasRequestPrecheck {
        GasRequestPrecheck {
            function: SponsoredFunction::MemoryAddChunk,
            allowed_mask_u16: GasStationPolicy::INITIAL_ALLOWED_MASK,
            dry_run_ok: true,
            within_quota: true,
            lease_active: true,
            owner_pubkey_32: key(1),
            sponsor_pubkey_32: key(2),
        }
    }

    #[test]
    fn allowlist_pass() {
        let p = base();
        assert_eq!(p.evaluate(), Ok(()));
        assert!(p.is_accepted());
    }

    #[test]
    fn function_not_on_allowlist_rejected() {
        let mut p = base();
        // update-compat is not separately allowed by the initial mask.
        p.function = SponsoredFunction::MemoryUpdateCompat;
        assert_eq!(p.evaluate(), Err(GasStationRejectReason::PackageFunction));
    }

    #[test]
    fn wildcard_mask_rejected() {
        let mut p = base();
        p.allowed_mask_u16 = 0b0000_1000; // a reserved bit outside FUNCTION_BITS_MASK
        assert_eq!(p.evaluate(), Err(GasStationRejectReason::Wildcard));
    }

    #[test]
    fn quota_fail() {
        let mut p = base();
        p.within_quota = false;
        assert_eq!(p.evaluate(), Err(GasStationRejectReason::QuotaRisk));
    }

    #[test]
    fn dry_run_abort() {
        let mut p = base();
        p.dry_run_ok = false;
        assert_eq!(p.evaluate(), Err(GasStationRejectReason::EffectShape));
    }

    #[test]
    fn revoke_lease_outcomes() {
        assert_eq!(revoke_lease(LeaseState::Active), Ok(()));
        assert_eq!(
            revoke_lease(LeaseState::Absent),
            Err(GasCoinLeaseError::NoSuchLease)
        );
        assert_eq!(
            revoke_lease(LeaseState::Expired),
            Err(GasCoinLeaseError::Expired)
        );
        assert_eq!(
            revoke_lease(LeaseState::Superseded),
            Err(GasCoinLeaseError::StaleLease)
        );
    }

    #[test]
    fn sponsor_policy_separation() {
        // owner == sponsor is a custody violation => Identity reject.
        let mut p = base();
        p.sponsor_pubkey_32 = p.owner_pubkey_32;
        assert_eq!(p.evaluate(), Err(GasStationRejectReason::Identity));
    }

    #[test]
    fn sponsor_cannot_sign_memory_owner() {
        let p = base();
        assert!(
            !p.sponsor_can_sign_owner_intent(),
            "sponsor never signs ownership"
        );
    }

    #[test]
    fn gas_request_precheck_p95_within_50ms() {
        let p = base();
        let mut samples = Vec::with_capacity(256);
        for _ in 0..256 {
            let t = std::time::Instant::now();
            let r = p.evaluate();
            std::hint::black_box(&r);
            samples.push(t.elapsed().as_nanos() as u64);
        }
        let p95 = p95_ms(&samples) / 1_000_000;
        assert!(
            p95 <= 50,
            "gas request precheck p95 {p95}ms exceeds 50ms budget"
        );
    }
}
