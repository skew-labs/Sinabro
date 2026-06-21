//! atom #319 · D.4.8 — starter pack smoke.
//!
//! Proves at least one useful starter pack can be searched, inspected,
//! dry-run, installed, enabled, disabled, and removed in a **local fixture**
//! environment. The smoke path is dry-run/read-only, status-only: no live
//! network egress, no gas spend, no live action; mainnet locked. No live
//! secrets and no payment are allowed, and registry upload is out of scope.
//! The transcript is redacted with no secret read and no secret clone/debug.
//!
//! This is an offline integration test: it constructs typed fixtures and folds
//! them through the public Stage D API. It performs no I/O, no network, no
//! wallet signing, and no chain action.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use mnemos_e_skill::verify::sample_valid_package_toml;
use mnemos_e_skill::{
    CatalogCache, CompatibilityDecision, HostEnvironment, InstallPlan, InstallPreconditions,
    LocalReceiptKind, LocalSkillState, LocalSkillTransition, MnemosVersion, SignedCatalogCache,
    SkillCatalogIndexEntry, SkillId, SkillPackageDigest32, SkillStarterPack, StageBTraceLink,
    StageCTraceLink, StageDTraceLink, StarterPackMember, SuiAddress, WasmTier2ModuleId,
    apply_transition, mint_receipt, progressive_inspect, progressive_search, scan_surfaces,
};

fn host() -> HostEnvironment {
    HostEnvironment {
        mnemos_version: MnemosVersion::new(0, 2, 0),
        chain_env_hash_32: [0xC0; 32],
        os_gpu_hash_32: [0x05; 32],
        toolchain_hash_32: [0x70; 32],
        model_provider_hash_32: [0x30; 32],
    }
}

fn trace() -> StageDTraceLink {
    let b = StageBTraceLink::new(0xD319_0001, 319, 0);
    let c = StageCTraceLink::new(b, 240, 9);
    StageDTraceLink::new(c, 319, 1)
}

/// A useful starter pack groups three already-verified, compatible skills.
fn starter_pack() -> SkillStarterPack {
    let members = [
        StarterPackMember {
            package: SkillPackageDigest32::new([0x51; 32]),
            compatibility: CompatibilityDecision::Compatible,
            eval_hash_32: [0xE1; 32],
        },
        StarterPackMember {
            package: SkillPackageDigest32::new([0x52; 32]),
            compatibility: CompatibilityDecision::Compatible,
            eval_hash_32: [0xE2; 32],
        },
        StarterPackMember {
            package: SkillPackageDigest32::new([0x53; 32]),
            compatibility: CompatibilityDecision::Compatible,
            eval_hash_32: [0xE3; 32],
        },
    ];
    let requested: Vec<SkillPackageDigest32> = members.iter().map(|m| m.package).collect();
    SkillStarterPack::build(&members, &requested).expect("starter pack must build")
}

#[test]
fn starter_pack_end_to_end_fixture_only_smoke() {
    let mut transcript: Vec<&'static str> = Vec::new();

    // --- a useful starter pack exists and is installable ---
    let pack = starter_pack();
    assert_eq!(pack.len(), 3);
    assert_eq!(pack.compatibility, CompatibilityDecision::Compatible);
    assert!(pack.is_installable());

    // --- catalog with one useful skill (the canonical sample) ---
    let entry = SkillCatalogIndexEntry::from_package_toml(
        &sample_valid_package_toml(),
        &host(),
        [0x99; 32],
        10,
        7,
        3,
    )
    .expect("catalog entry");
    let skill = entry.skill;
    let cache = SignedCatalogCache::sign(CatalogCache::rebuild(&[entry], &[]));
    let live = cache.cache().watermark();

    // --- search: lightweight cards only, no full manifest ---
    let search = progressive_search(&cache, live, 20).expect("search");
    assert_eq!(search.summaries.len(), 1);
    assert!(!search.stale_warning);
    transcript.push("search");

    // --- inspect: full detail loaded only for the selected skill ---
    let detail = progressive_inspect(&cache, skill, true).expect("inspect");
    assert!(detail.malicious_fixture_pass);
    transcript.push("inspect");

    // --- dry-run: a use receipt requires every gate (no live action) ---
    let pkg = SkillPackageDigest32::new([0x44; 32]);
    let plan = InstallPlan::new(skill, pkg, WasmTier2ModuleId::from_bytes([0x55; 32]));
    let pre = InstallPreconditions::all_met();
    let user = SuiAddress::new([0xAB; 32]);
    let cap_hash = *detail.summary.capability_diff.human_digest_32();
    let use_receipt = mint_receipt(
        LocalReceiptKind::Use,
        &plan,
        &pre,
        pkg.as_bytes(),
        false,
        user,
        cap_hash,
        trace(),
    )
    .expect("dry-run/use receipt");
    assert_eq!(use_receipt.state, LocalSkillState::DryRunPassed);
    assert!(
        !use_receipt.is_executable(),
        "a dry-run/use receipt is not executable"
    );
    transcript.push("dry-run");

    // --- install: an install receipt only on the Proceed path ---
    let install_receipt = mint_receipt(
        LocalReceiptKind::Install,
        &plan,
        &pre,
        pkg.as_bytes(),
        false,
        user,
        cap_hash,
        trace(),
    )
    .expect("install receipt");
    assert_eq!(install_receipt.state, LocalSkillState::Installed);
    transcript.push("install");

    // --- enable -> disable -> remove (local state machine, audited) ---
    let enabled = apply_transition(install_receipt.state, LocalSkillTransition::Enable, None)
        .expect("enable");
    assert_eq!(enabled.to, LocalSkillState::Enabled);
    assert!(enabled.to.is_executable());
    transcript.push("enable");

    let disabled =
        apply_transition(enabled.to, LocalSkillTransition::Disable, None).expect("disable");
    assert_eq!(disabled.to, LocalSkillState::Disabled);
    assert!(!disabled.to.is_executable());
    transcript.push("disable");

    let removed =
        apply_transition(disabled.to, LocalSkillTransition::Remove, None).expect("remove");
    assert_eq!(removed.to, LocalSkillState::Removed);
    assert!(
        !removed.to.is_executable(),
        "a removed skill can never execute"
    );
    transcript.push("remove");

    // --- the whole flow stayed fixture-only: no commerce surface ---
    let report = scan_surfaces(
        &[
            "search", "inspect", "dry-run", "install", "enable", "disable", "remove",
        ],
        &["SkillStarterPack", "LocalInstallReceipt", "ReviewQueue"],
        &["--dry-run", "--inspect", "--offline"],
        "Search, inspect, dry-run, install, enable, disable, and remove skills offline.",
    );
    assert!(report.is_clean(), "smoke path must have 0 commerce hits");
    transcript.push("no-payment");

    // --- fixture-only transcript covers every required stage ---
    for stage in [
        "search",
        "inspect",
        "dry-run",
        "install",
        "enable",
        "disable",
        "remove",
        "no-payment",
    ] {
        assert!(
            transcript.contains(&stage),
            "transcript missing stage {stage}"
        );
    }
}

#[test]
fn install_refused_without_dry_run() {
    // The install authority gate holds in the smoke environment: dropping the
    // dry-run precondition blocks the receipt (no auto-install).
    let pkg = SkillPackageDigest32::new([0x44; 32]);
    let plan = InstallPlan::new(SkillId(42), pkg, WasmTier2ModuleId::from_bytes([0x55; 32]));
    let mut pre = InstallPreconditions::all_met();
    pre.dry_run_passed = false;
    let result = mint_receipt(
        LocalReceiptKind::Install,
        &plan,
        &pre,
        pkg.as_bytes(),
        false,
        SuiAddress::new([0xAB; 32]),
        [0x77; 32],
        trace(),
    );
    assert!(result.is_err(), "install without dry-run must be refused");
}
