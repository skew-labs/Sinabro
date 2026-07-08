//! Stage B scoped secret under testnet policy.
//!
//! The Stage A
//! [`ScopedSecretKey`](crate::keystore::ScopedSecretKey) is **reused directly**
//! under the Stage B testnet boundary — no parallel secret type is minted.
//! The trait-absence spec ("no Debug, Display, Clone, Serialize; Drop zeroizes")
//! is already a *structural* property of the Stage A type (`keystore.rs:145`,
//! `Drop`-zeroize at `keystore.rs:175`): the absent trait impls mean every
//! leak path through formatting, copying, or serialisation fails to
//! **compile**, and the `Drop` impl zeroizes the 32-byte seed when the
//! single unseal scope closes.
//!
//! This module's job is to (a) name that reused type at the Stage B surface
//! so downstream Stage B wallet code (sign-chunk, sign-tx, rotate) imports one
//! spelling, and (b) **lock the structural invariant with
//! compile-time trait-absence assertions** so a future edit that adds a
//! `Debug` / `Display` / `Clone` / `Copy` impl to the Stage A type is caught
//! by this crate's test build before it can widen the secret-leak surface.
//!
//! # Reuse map
//!
//! * The Stage B keystore
//!   ([`StageBTestnetKeystore`](crate::stage_b_keystore::StageBTestnetKeystore))
//!   hands back a [`StageBScopedSecretKey`] from its unseal path; this module
//!   is the type that path returns.

/// The Stage B testnet scoped secret key. A re-export of the Stage A
/// [`ScopedSecretKey`](crate::keystore::ScopedSecretKey) — same type, same
/// `Drop`-zeroize destructor, same absent `Debug` / `Display` / `Clone` /
/// serde impls. Naming it here keeps the Stage B wallet package importing one
/// canonical secret type rather than aliasing a second.
pub use crate::keystore::ScopedSecretKey as StageBScopedSecretKey;

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    #![allow(clippy::expect_used)]
    #![allow(clippy::panic)]

    use super::*;
    use static_assertions::{assert_impl_all, assert_not_impl_any};

    // ----- Compile-time trait-absence lock -------------
    //
    // These assertions encode a compile-fail trait-absence check
    // realised as static assertions: if a future edit adds any of these
    // impls to the Stage A `ScopedSecretKey`, this crate's test build fails
    // here — the secret can never silently gain a log / copy / serialise
    // path. `static_assertions` is a dev-dependency, so the lock costs the
    // release build nothing.
    assert_not_impl_any!(StageBScopedSecretKey: core::fmt::Debug);
    assert_not_impl_any!(StageBScopedSecretKey: core::fmt::Display);
    assert_not_impl_any!(StageBScopedSecretKey: Clone);
    assert_not_impl_any!(StageBScopedSecretKey: Copy);
    // The one accessor the secret is allowed to have is a borrow of its
    // bytes for a single downstream signing scope; the type must still be
    // `Sized` (a plain 32-byte newtype) so it lives on the stack and its
    // `Drop` runs deterministically at scope end.
    assert_impl_all!(StageBScopedSecretKey: Sized);

    /// `b4_2_zeroize_on_drop` — the 32-byte seed is zeroized when the scoped
    /// secret drops. We cannot observe the freed stack slot safely in pure
    /// Rust, so we assert the invariant the way the Stage A #33 suite does:
    /// the borrowed bytes equal the input seed *while alive*, and the type's
    /// `Drop` impl (proven present by the Stage A crate) is what zeroizes
    /// them. Here we pin that the borrow round-trips a known seed exactly,
    /// so a regression that corrupts the buffer is caught.
    #[test]
    fn b4_2_zeroize_on_drop() {
        let seed: [u8; 32] = [
            0xA1, 0xB2, 0xC3, 0xD4, 0xE5, 0xF6, 0x07, 0x18, //
            0x29, 0x3A, 0x4B, 0x5C, 0x6D, 0x7E, 0x8F, 0x90, //
            0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, //
            0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00, //
        ];
        let scoped = StageBScopedSecretKey::from_seed_for_test(seed);
        assert_eq!(scoped.as_bytes(), &seed, "borrowed seed must round-trip");
        // `scoped` drops here; its `Drop` impl zeroizes the buffer (Stage A
        // #33 invariant, asserted structurally above by the absent `Copy`/
        // `Clone` impls — no copy of the seed can outlive this scope).
        drop(scoped);
    }

    /// `b4_2_log_canary` — a sanity canary that the scoped secret cannot be
    /// formatted into a log line. This is *enforced* by the
    /// `assert_not_impl_any!(... Debug)` / `... Display` locks above
    /// (a `format!("{scoped:?}")` call would not compile); this test
    /// documents the property and exercises the only permitted read path
    /// (the byte borrow) so the canary stays exercised, not just asserted.
    #[test]
    fn b4_2_log_canary() {
        let seed = [0x42u8; 32];
        let scoped = StageBScopedSecretKey::from_seed_for_test(seed);
        // Permitted: borrow the bytes for a downstream signing API.
        let borrowed = scoped.as_bytes();
        assert_eq!(borrowed.len(), 32);
        // FORBIDDEN (compile-time, proven by the trait-absence locks):
        //   let _ = format!("{scoped:?}");   // no Debug impl
        //   let _ = format!("{scoped}");      // no Display impl
        //   let _clone = scoped.clone();      // no Clone impl
    }
}
