//! Malicious package fixture gate — atom #250 · D.0.9.
//!
//! One fixture per attack class. Every fixture MUST be rejected by
//! [`verify_skill_package`] (or [`BundleLayout::validate`] for the bundle
//! path-traversal case) with a stable [`VerifyError`] / [`BundleError`], and
//! malformed bytes must reject without a panic (§250 광기 + test list).
//!
//! Non-vacuity: the known-good baseline ([`sample_valid_package_toml`])
//! verifies, so the suite proves the verifier CAN pass — the reds below are
//! real rejections, not a verifier that rejects everything.
//!
//! Secret-handling: the `encoded_secret` fixture carries a FAKE base64
//! string (`ZmFrZS1ub3QtcmVhbA==` = "fake-not-real") as an unknown top-level
//! key; `deny_unknown_fields` rejects it at the schema gate and the
//! payload-less error drops the value — no real secret is loaded, cloned,
//! logged, or debugged (§250 광기).

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use mnemos_e_skill::bundle::{BundleEntry, BundleError, BundleLayout};
use mnemos_e_skill::verify::{VerifyError, sample_valid_package_toml, verify_skill_package};

/// Each `(fixture_bytes, expected_error, label)` row. The label is the
/// attack class; the error is the stable rejection reason.
fn malicious_rows() -> Vec<(&'static str, VerifyError, &'static str)> {
    vec![
        (
            include_str!("fixtures/stage_d/malicious_packages/fake_commerce.toml"),
            VerifyError::Commerce,
            "fake_commerce",
        ),
        (
            include_str!("fixtures/stage_d/malicious_packages/eval_spoof.toml"),
            VerifyError::EvalInvalid,
            "eval_spoof",
        ),
        (
            include_str!("fixtures/stage_d/malicious_packages/provenance_cycle.toml"),
            VerifyError::ProvenanceInvalid,
            "provenance_cycle",
        ),
        (
            include_str!("fixtures/stage_d/malicious_packages/missing_sbom.toml"),
            VerifyError::SupplyChainIncomplete,
            "missing_sbom",
        ),
        (
            include_str!("fixtures/stage_d/malicious_packages/unreproducible_build.toml"),
            VerifyError::SupplyChainIncomplete,
            "unreproducible_build",
        ),
        (
            include_str!("fixtures/stage_d/malicious_packages/networked_build_script.toml"),
            VerifyError::SupplyChainIncomplete,
            "networked_build_script",
        ),
        (
            include_str!("fixtures/stage_d/malicious_packages/bad_signature.toml"),
            VerifyError::Signature,
            "bad_signature(forged/stale)",
        ),
        (
            include_str!("fixtures/stage_d/malicious_packages/encoded_secret.toml"),
            VerifyError::Schema,
            "encoded_secret",
        ),
        (
            include_str!("fixtures/stage_d/malicious_packages/unknown_section.toml"),
            VerifyError::Schema,
            "unknown_section",
        ),
        (
            include_str!("fixtures/stage_d/malicious_packages/capability_tool_mismatch.toml"),
            VerifyError::CapabilityToolMismatch,
            "capability_tool_mismatch",
        ),
    ]
}

#[test]
fn baseline_is_non_vacuous() {
    // The verifier CAN pass — the reds below are genuine rejections.
    let ok = sample_valid_package_toml();
    assert!(
        verify_skill_package(&ok).is_ok(),
        "known-good baseline must verify (non-vacuity)"
    );
}

#[test]
fn every_malicious_fixture_is_rejected_with_stable_reason() {
    for (bytes, expected, label) in malicious_rows() {
        let first = verify_skill_package(bytes);
        assert_eq!(
            first,
            Err(expected),
            "fixture `{label}` must reject with {expected:?}"
        );
        // Reject reason is stable across re-runs.
        let second = verify_skill_package(bytes);
        assert_eq!(first, second, "fixture `{label}` reason must be stable");
    }
}

#[test]
fn malformed_bytes_reject_without_panic() {
    let garbage = include_str!("fixtures/stage_d/malicious_packages/malformed.bin");
    // Must not panic; must reject (Schema/TooLarge — i.e. an Err).
    let r = verify_skill_package(garbage);
    assert!(r.is_err(), "malformed bytes must reject");

    // A few more adversarial byte strings — none may panic.
    for evil in [
        "",
        "\0\0\0",
        "[manifest]",                   // truncated
        "[[[[[[",                       // unbalanced
        &"a".repeat(1_000),             // long junk
        "[manifest]\nid = 99999999999", // out-of-range int
    ] {
        let _ = verify_skill_package(evil); // must return, not panic
    }
}

#[test]
fn bundle_path_traversal_rejected() {
    // The bundle path-traversal attack is caught by BundleLayout::validate.
    let malicious = BundleLayout {
        entries: vec![
            BundleEntry {
                path: String::from("manifest.toml"),
                content_hash_32: [1u8; 32],
                size_bytes_u64: 10,
            },
            BundleEntry {
                path: String::from("../../etc/passwd"),
                content_hash_32: [2u8; 32],
                size_bytes_u64: 10,
            },
        ],
    };
    assert_eq!(malicious.validate(), Err(BundleError::PathTraversal));
}

#[test]
fn forged_author_breaks_signature() {
    // Forged author: the author hex (`11`×32) is the ONLY field using that
    // value in the fixture. Swapping it changes the content digest AND
    // mismatches the signature bound to the original author — rejected.
    let valid = sample_valid_package_toml();
    assert!(verify_skill_package(&valid).is_ok());
    let forged = valid.replace(&"11".repeat(32), &"22".repeat(32));
    assert_ne!(forged, valid);
    assert_eq!(verify_skill_package(&forged), Err(VerifyError::Signature));
}

#[test]
fn stale_signature_rejected_in_place() {
    // Stale signature: keep the content, flip one signature nibble to a
    // different (well-formed) hex digit — it no longer binds the digest.
    let valid = sample_valid_package_toml();
    let marker = "bytes = \"";
    let start = valid.rfind(marker).expect("sig marker") + marker.len();
    let first = &valid[start..start + 1];
    let repl = if first == "0" { "1" } else { "0" };
    let s = format!("{}{}{}", &valid[..start], repl, &valid[start + 1..]);
    assert_ne!(s, valid);
    assert_eq!(verify_skill_package(&s), Err(VerifyError::Signature));
}

#[test]
fn hidden_permission_is_structurally_unrepresentable() {
    // The canonical TOML stores only masks + tool ids; `a_capabilities` and
    // the human digest are DERIVED by the verifier. So every permission in
    // `added_mask` is always surfaced — there is no field to hide one in.
    // (A skill claiming an UNDECLARED tool — a hidden capability — is caught
    // separately by capability_tool_mismatch.toml above.)
    let valid = sample_valid_package_toml();
    let verified = verify_skill_package(&valid).expect("valid");
    // Fixture added_mask = MemoryRead bit (64), faithfully surfaced as the
    // single A capability — nothing hidden, and the diff is self-consistent.
    assert_eq!(verified.package.capability_diff.added_mask_u64, 64);
    assert!(verified.package.capability_diff.is_consistent());
}

#[test]
fn one_fixture_per_attack_class_present() {
    // Guardrail: the row count tracks the attack-class list so a future
    // dropped fixture is visible. 10 package-TOML rows + bundle-traversal +
    // malformed-bytes + forged-author + stale-signature + hidden-permission
    // are exercised by the tests in this file.
    assert_eq!(malicious_rows().len(), 10, "attack-class fixture count");
}
