//! atom #160 · B.4.14 — wallet half of the wallet/Seal redteam matrix.
//!
//! ATOM_PLAN line 1336-1345. Offline fixture tests: each likely wallet mistake
//! is encoded as a denied/fail-closed case. No live network, no wallet signing,
//! no gas spend, no secret material — these are compile-time and pure-logic
//! assertions only. The Seal half lives in `mnemos-f-seal`
//! (`tests/stage_b_seal_redteam.rs`); the verdicts are joined in
//! `ops/evidence/stage_b/wp_B_WP_04/wallet_seal_redteam.md` (no dev-dep cycle).
//!
//! Case ids mirror `tests/fixtures/stage_b/wallet_seal_redteam/wallet_*.json`.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use mnemos_d_move::GasBudgetMist;
use mnemos_g_wallet::{StageBScopedSecretKey, StageBTestnetWalletConfig, StageBWalletError};
use static_assertions::assert_not_impl_any;

// case `wallet_clone_leak` + `wallet_log_leak`: the scoped secret key must carry
// NO `Clone` / `Copy` (no silent duplicate of the seed) and NO `Debug` /
// `Display` (no formatting path that prints the seed into a log). These are
// compile-time guarantees — if a future edit adds any of these impls, this test
// crate fails to compile, which is the redteam failing closed at build time.
assert_not_impl_any!(StageBScopedSecretKey: Clone, Copy, core::fmt::Debug, core::fmt::Display);

/// case `wallet_clone_leak` / `wallet_log_leak` (runtime witness): a trivial
/// test that records the compile-time assertion above is in force. If the
/// `assert_not_impl_any!` ever stops holding, this crate does not compile, so a
/// green run of this test *is* the evidence that the secret has no leak path.
#[test]
fn redteam_wallet_secret_has_no_clone_or_log_path() {
    // No secret is constructed here (the test-only seed constructor is not on
    // the public API by design). The guarantee is structural and proven by the
    // module-level `assert_not_impl_any!`.
    let _ = core::marker::PhantomData::<StageBScopedSecretKey>;
}

/// case `wallet_mainnet_sign_request`: a request to configure (and therefore
/// sign for) a non-testnet network must fail closed with `NetworkNotTestnet`.
/// `StageBTestnetWalletConfig::from_label` is the upstream gate that the
/// testnet-only signer (`sign_testnet_call`) structurally requires — a mainnet
/// label has no type path past it.
#[test]
fn redteam_wallet_mainnet_sign_request_denied() {
    let gas = GasBudgetMist::new(1);
    for bad in ["mainnet", "devnet", "localnet", "custom", ""] {
        assert_eq!(
            StageBTestnetWalletConfig::from_label(bad, gas).err(),
            Some(StageBWalletError::NetworkNotTestnet),
            "non-testnet label must fail closed: {bad:?}"
        );
    }
    // testnet is the only accepted label.
    assert!(StageBTestnetWalletConfig::from_label("testnet", gas).is_ok());
}
