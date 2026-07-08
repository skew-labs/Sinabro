//! Cross-module poison-resistance suite for the security + human collectors
//! (atom #384 · E.2.13).
//!
//! High-value human/security data must be **hard to poison**: a false approval,
//! a hidden critical finding, a PII/secret export, a license drift, and an S2
//! self-report must all fail closed — no positive reward, no raw export. These
//! integration tests exercise the public #371–#383 API end-to-end.
use mnemos_l_dataset::human::approval;
use mnemos_l_dataset::human::privacy::reviewer_identity;
use mnemos_l_dataset::human::review::{parse_reviews, signal};
use mnemos_l_dataset::license_governance::govern;
use mnemos_l_dataset::privacy::PrivacyDecision;
use mnemos_l_dataset::privacy_scanner::scan_str;
use mnemos_l_dataset::provenance::ProvenanceChain;
use mnemos_l_dataset::redaction_policy::redact_bytes;
use mnemos_l_dataset::reward_firewall::firewall_claim;
use mnemos_l_dataset::security::audit_finding::{aggregate, parse_findings};
use mnemos_l_dataset::security::repro;
use mnemos_l_dataset::security::source::SecuritySeverity;
use mnemos_l_dataset::stream_split::RewardEligibility;
use mnemos_l_dataset::{AtomDietKey, DietError, DietResult, DietSourceStage};

fn key() -> AtomDietKey {
    AtomDietKey::new(DietSourceStage::StageD, 384)
}

/// A false approval (many approvals, zero denials) can never override a gate-red.
#[test]
fn false_approval_never_overrides_gate_red() -> DietResult<()> {
    let doc = r#"{"approvals_count":5,"denials_count":0,"events":[]}"#;
    let n = approval::normalize(key(), doc, true, false)?;
    assert!(n.operator_controlled);
    assert!(n.reward_blocked, "approval must not override gate red");
    Ok(())
}

/// An open critical finding is always caught and blocks reward (cannot be hidden).
#[test]
fn open_critical_finding_blocks_reward() -> DietResult<()> {
    let doc = r#"{"findings":[{"id":"X","severity":"critical","status":"open","evidence":"poc"}]}"#;
    let f = parse_findings(key(), doc)?;
    let sig = aggregate(key(), &f, [0u8; 32], [0u8; 32]);
    assert_eq!(sig.open_critical_u32, 1);
    assert!(sig.blocks_reward());
    Ok(())
}

/// A claimed-fixed critical with no backing evidence rejects — a "fixed" label
/// cannot launder a finding past the evidence requirement.
#[test]
fn fixed_without_evidence_still_rejects() {
    let doc = r#"{"findings":[{"id":"Y","severity":"critical","status":"fixed"}]}"#;
    assert!(matches!(
        parse_findings(key(), doc),
        Err(DietError::MissingEvidence { .. })
    ));
}

/// PII / secret in an export candidate is rejected (scanner + reviewer identity).
#[test]
fn pii_and_secret_export_is_rejected() {
    assert_eq!(
        scan_str("wallet_secret abc").decision,
        PrivacyDecision::Reject
    );
    assert_eq!(
        scan_str("contact alice@example.com").decision,
        PrivacyDecision::Redacted
    );
    assert!(matches!(
        reviewer_identity("alice@example.com"),
        Err(DietError::SecretResidue { .. })
    ));
}

/// License drift (unknown / proprietary) is quarantined, never exported.
#[test]
fn license_drift_is_quarantined() {
    let prov = ProvenanceChain::new(key(), [1u8; 32], [2u8; 32], true);
    assert!(govern(key(), "weird-license", &prov).quarantined);
    assert!(govern(key(), "proprietary", &prov).quarantined);
    // a known good license with provenance is not quarantined.
    assert!(!govern(key(), "MIT", &prov).quarantined);
}

/// S2 self-report (SAFE-TO-COMMIT / Grade-A) is reward-blocked even if reverified.
#[test]
fn s2_self_report_is_reward_blocked() {
    assert_eq!(
        firewall_claim("SAFE-TO-COMMIT", true),
        RewardEligibility::NoRewardNarrative
    );
    assert_eq!(
        firewall_claim("Grade-A work", true),
        RewardEligibility::NoRewardNarrative
    );
    // only an independently reverified ground-truth claim is eligible.
    assert_eq!(
        firewall_claim("all tests pass", true),
        RewardEligibility::Eligible
    );
}

/// Human review approval is provenance metadata, never reward by itself.
#[test]
fn human_review_approval_is_metadata_only() -> DietResult<()> {
    let r = parse_reviews(r#"{"verdict":"approved","reviewer":"owner","comment":"lgtm"}"#)?;
    let s = signal(key(), &r);
    assert!(s.approved);
    // approval is provenance only; a rejection in the set removes the approval.
    let denied = parse_reviews(r#"{"verdict":"rejected","reviewer":"owner","comment":"no"}"#)?;
    assert!(!signal(key(), &denied).approved);
    Ok(())
}

/// An exploit repro without a fix is quarantine-only, never S1-eligible.
#[test]
fn exploit_without_fix_is_quarantine_only() {
    let s = repro::collect(key(), SecuritySeverity::Critical, true, false, false, "poc");
    assert!(s.quarantine_only);
    assert!(!s.s1_eligible);
}

/// Redaction is irreversible (secret gone) or rejects unredactable binary.
#[test]
fn redaction_is_irreversible_or_rejects() -> DietResult<()> {
    let out = redact_bytes(b"ok\nsk-live_ABCDEF0123456789abcdef\nok2")?;
    assert!(out.was_redacted());
    assert!(!out.text().contains("sk-live_"));
    assert!(redact_bytes(&[0xff, 0xfe, 0x00]).is_err());
    Ok(())
}
