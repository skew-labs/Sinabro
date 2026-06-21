//! atom #160 · B.4.14 — Seal half of the wallet/Seal redteam matrix.
//!
//! ATOM_PLAN line 1336-1345. These are **offline fixture tests**: each likely
//! mistake on the Seal surface is encoded as a denied case that must fail
//! closed. No live network, no wallet signing, no gas, no secret material. The
//! companion wallet half lives in `mnemos-g-wallet`
//! (`tests/stage_b_wallet_redteam.rs`); the two crates' verdicts are joined in
//! `ops/evidence/stage_b/wp_B_WP_04/wallet_seal_redteam.md` rather than by a
//! cross-crate dev-dependency (no dev-dep cycle).
//!
//! Case ids mirror `tests/fixtures/stage_b/wallet_seal_redteam/seal_*.json`.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use mnemos_c_walrus::PublishPayloadClass;
use mnemos_f_seal::{StageBSealStubError, StageBSealStubPolicy, stage_b_wording_ok};

/// case `seal_private_publish_request`: an attacker offers real user / private
/// provenance memory for publish. The default testnet policy must deny it with
/// `PrivatePublishDenied`.
#[test]
fn redteam_seal_private_publish_request_denied() {
    let policy = StageBSealStubPolicy::default_testnet();
    for class in [
        PublishPayloadClass::RealUserMemory,
        PublishPayloadClass::PrivateProvenance,
        PublishPayloadClass::PromptOrProviderText,
        PublishPayloadClass::ToolOutput,
    ] {
        assert_eq!(
            policy.admits(class),
            Err(StageBSealStubError::PrivatePublishDenied),
            "private-class publish must fail closed: {}",
            class.class_label()
        );
    }
}

/// case `seal_secret_like_request`: secret-like bytes are offered for publish.
/// They must be denied with `SecretLikeDenied` regardless of policy — even an
/// (unsafe) allow-private policy cannot admit them.
#[test]
fn redteam_seal_secret_like_request_denied() {
    assert_eq!(
        StageBSealStubPolicy::default_testnet().admits(PublishPayloadClass::SecretLike),
        Err(StageBSealStubError::SecretLikeDenied)
    );
    assert_eq!(
        StageBSealStubPolicy {
            allow_private_memory_publish: true,
        }
        .admits(PublishPayloadClass::SecretLike),
        Err(StageBSealStubError::SecretLikeDenied)
    );
}

/// case `seal_misleading_encryption_claim`: UX/log/doc copy claims real Seal
/// encryption. The wording guard must reject it with
/// `MisleadingEncryptionClaim`.
#[test]
fn redteam_seal_misleading_encryption_claim_denied() {
    for claim in [
        "Your memory is encrypted with Seal.",
        "End-to-end encrypted, zero-knowledge storage.",
        "Cryptographically sealed and fully encrypted.",
    ] {
        assert_eq!(
            stage_b_wording_ok(claim),
            Err(StageBSealStubError::MisleadingEncryptionClaim),
            "misleading claim must be rejected: {claim}"
        );
    }
    // honest negative copy is NOT a false positive.
    assert_eq!(
        stage_b_wording_ok("Stage B Seal is a stub boundary; no encryption."),
        Ok(())
    );
}
