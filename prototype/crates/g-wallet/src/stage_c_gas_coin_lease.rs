//! Stage C gas coin lease pool (C-WP-07 · atom #231 · C.2.12).
//!
//! Canonical OUT (§4.3): [`GasCoinLease`].
//!
//! # Madness invariants (atom #231)
//!
//! * **One coin, one inflight tx.** A sponsor gas coin can back at most one
//!   inflight transaction at a time. While a coin's lease is live, a second
//!   [`acquire`](GasCoinLeasePool::acquire) of the same coin is refused
//!   ([`GasCoinLeaseError::DoubleLease`]) — double-spending one gas object across
//!   two concurrent transactions is impossible.
//! * **Timeout / settlement returns the lease.** A lease carries an
//!   `expires_epoch`. Once expired it is reclaimable: a fresh acquire of the
//!   same coin succeeds (the stale lease is dropped), and
//!   [`reclaim_expired`](GasCoinLeasePool::reclaim_expired) sweeps all expired
//!   leases back into the free pool.
//! * **A stale lease cannot sign.** [`authorize_signing`](GasCoinLeasePool::authorize_signing)
//!   admits a `(coin, lease_id)` pair only when the live lease matches the
//!   presented `lease_id` *and* has not expired. A superseded `lease_id`
//!   ([`StaleLease`](GasCoinLeaseError::StaleLease)) or an expired lease
//!   ([`Expired`](GasCoinLeaseError::Expired)) is refused — there is no path by
//!   which a returned/expired coin authorizes a signature.
//!
//! `O(1)` lease lookup: the pool is a `HashMap` keyed by the coin
//! [`ObjectId`](mnemos_d_move::types::ObjectId), so acquire / authorize /
//! release are all single hashed lookups.
//!
//! # Reuse map (atom contract)
//!
//! * **reuse: A [`ObjectId`](mnemos_d_move::types::ObjectId)** — the gas coin id
//!   is the d-move §4.D canonical object id, not re-minted.
//!
//! No signer, no transaction submitter, no key material: this is lease
//! bookkeeping only. `MainnetExecutionState` stays `Locked`.

use std::collections::HashMap;

use mnemos_d_move::types::ObjectId;

/// A lease binding one sponsor gas coin to one inflight transaction (§4.3).
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub struct GasCoinLease {
    /// The sponsor gas coin object under lease.
    pub coin: ObjectId,
    /// The monotonically-issued lease id. A new lease for the same coin gets a
    /// fresh id; the old id becomes stale.
    pub lease_id_u64: u64,
    /// The epoch at (and after) which this lease is expired and reclaimable.
    pub expires_epoch_u64: u64,
}

impl GasCoinLease {
    /// Construct a lease.
    #[inline]
    #[must_use]
    pub const fn new(coin: ObjectId, lease_id_u64: u64, expires_epoch_u64: u64) -> Self {
        Self {
            coin,
            lease_id_u64,
            expires_epoch_u64,
        }
    }

    /// Whether the lease is expired at `now_epoch` (expiry is inclusive: a lease
    /// expiring at epoch `e` is expired once `now >= e`).
    #[inline]
    #[must_use]
    pub const fn is_expired(&self, now_epoch_u64: u64) -> bool {
        now_epoch_u64 >= self.expires_epoch_u64
    }
}

/// Lease-pool admission error. Every variant is data-free.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
#[repr(u8)]
pub enum GasCoinLeaseError {
    /// The coin already has a live (non-expired) lease.
    DoubleLease = 1,
    /// No lease exists for the presented coin.
    NoSuchLease = 2,
    /// A lease exists for the coin but the presented `lease_id` is superseded.
    StaleLease = 3,
    /// The matching lease has expired and cannot authorize a signature.
    Expired = 4,
}

impl core::fmt::Display for GasCoinLeaseError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let msg = match self {
            Self::DoubleLease => "stage_c gas coin lease: coin already leased (one inflight tx)",
            Self::NoSuchLease => "stage_c gas coin lease: no lease for coin",
            Self::StaleLease => "stage_c gas coin lease: superseded lease id cannot sign",
            Self::Expired => "stage_c gas coin lease: expired lease cannot sign",
        };
        f.write_str(msg)
    }
}

impl core::error::Error for GasCoinLeaseError {}

/// An `O(1)`-lookup pool enforcing one-inflight-tx-per-coin (§4.3).
#[derive(Clone, Debug, Default)]
pub struct GasCoinLeasePool {
    live: HashMap<ObjectId, GasCoinLease>,
}

impl GasCoinLeasePool {
    /// A fresh, empty pool.
    #[inline]
    #[must_use]
    pub fn new() -> Self {
        Self {
            live: HashMap::new(),
        }
    }

    /// Number of leases currently tracked (live or not-yet-reclaimed).
    #[inline]
    #[must_use]
    pub fn len(&self) -> usize {
        self.live.len()
    }

    /// Whether the pool holds no leases.
    #[inline]
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.live.is_empty()
    }

    /// Acquire a lease for `coin`. If the coin already has a *live* lease the
    /// acquire is refused; if it has an *expired* lease that stale lease is
    /// reclaimed and replaced.
    ///
    /// # Errors
    ///
    /// [`GasCoinLeaseError::DoubleLease`] when a non-expired lease already
    /// exists for the coin.
    pub fn acquire(
        &mut self,
        lease: GasCoinLease,
        now_epoch_u64: u64,
    ) -> Result<(), GasCoinLeaseError> {
        if let Some(existing) = self.live.get(&lease.coin) {
            if !existing.is_expired(now_epoch_u64) {
                return Err(GasCoinLeaseError::DoubleLease);
            }
        }
        self.live.insert(lease.coin, lease);
        Ok(())
    }

    /// Admit a `(coin, lease_id)` pair for signing.
    ///
    /// # Errors
    ///
    /// [`GasCoinLeaseError::NoSuchLease`] when the coin is unleased,
    /// [`GasCoinLeaseError::StaleLease`] when the live lease has a different id,
    /// and [`GasCoinLeaseError::Expired`] when the matching lease has expired.
    pub fn authorize_signing(
        &self,
        coin: ObjectId,
        lease_id_u64: u64,
        now_epoch_u64: u64,
    ) -> Result<(), GasCoinLeaseError> {
        let lease = self.live.get(&coin).ok_or(GasCoinLeaseError::NoSuchLease)?;
        if lease.lease_id_u64 != lease_id_u64 {
            return Err(GasCoinLeaseError::StaleLease);
        }
        if lease.is_expired(now_epoch_u64) {
            return Err(GasCoinLeaseError::Expired);
        }
        Ok(())
    }

    /// Release the lease for `coin` (settlement). Returns the released lease if
    /// one existed.
    pub fn release(&mut self, coin: ObjectId) -> Option<GasCoinLease> {
        self.live.remove(&coin)
    }

    /// Sweep every expired lease back into the free pool. Returns the count
    /// reclaimed.
    pub fn reclaim_expired(&mut self, now_epoch_u64: u64) -> usize {
        let before = self.live.len();
        self.live
            .retain(|_, lease| !lease.is_expired(now_epoch_u64));
        before - self.live.len()
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]
    use super::*;

    fn coin(b: u8) -> ObjectId {
        ObjectId::new([b; 32])
    }

    #[test]
    fn double_lease_reject() {
        let mut pool = GasCoinLeasePool::new();
        pool.acquire(GasCoinLease::new(coin(1), 1, 100), 10)
            .expect("first lease");
        // Same coin, still live -> refused.
        assert_eq!(
            pool.acquire(GasCoinLease::new(coin(1), 2, 200), 10),
            Err(GasCoinLeaseError::DoubleLease)
        );
        // A different coin is fine.
        pool.acquire(GasCoinLease::new(coin(2), 3, 100), 10)
            .expect("other coin");
        assert_eq!(pool.len(), 2);
    }

    #[test]
    fn expired_lease_recover() {
        let mut pool = GasCoinLeasePool::new();
        pool.acquire(GasCoinLease::new(coin(1), 1, 100), 10)
            .expect("first lease");
        // After expiry the same coin can be re-acquired with a fresh id.
        pool.acquire(GasCoinLease::new(coin(1), 2, 300), 150)
            .expect("reacquire after expiry");
        assert_eq!(pool.len(), 1);
        // reclaim_expired sweeps expired leases.
        assert_eq!(pool.reclaim_expired(400), 1);
        assert!(pool.is_empty());
    }

    #[test]
    fn stale_lease_cannot_sign() {
        let mut pool = GasCoinLeasePool::new();
        pool.acquire(GasCoinLease::new(coin(1), 1, 100), 10)
            .expect("first lease");
        // Live + matching id + not expired -> authorized.
        pool.authorize_signing(coin(1), 1, 50).expect("authorized");
        // Superseded id -> stale.
        assert_eq!(
            pool.authorize_signing(coin(1), 99, 50),
            Err(GasCoinLeaseError::StaleLease)
        );
        // Expired -> refused even with the right id.
        assert_eq!(
            pool.authorize_signing(coin(1), 1, 100),
            Err(GasCoinLeaseError::Expired)
        );
        // Unleased coin -> none.
        assert_eq!(
            pool.authorize_signing(coin(7), 1, 50),
            Err(GasCoinLeaseError::NoSuchLease)
        );
    }
}
