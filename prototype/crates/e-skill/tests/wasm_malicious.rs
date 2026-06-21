//! D-WP-02 · atom #269 · D.1.13 — malicious WASM / attack-fixture suite.
//!
//! Every attack class — escape, loop, alloc, recursion, hostcall-flood,
//! network, file, secret, wallet, chain-write, nondeterminism, output-leak —
//! must **fail closed** through the public `mnemos-e-skill` API, and one valid
//! canary proves the suite is non-vacuous (it CAN accept a well-formed module).
//! Everything here is offline and pure: no live network, no wallet signing, no
//! payment, no host filesystem mutation outside the (unused) temp sandbox.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use mnemos_e_skill::{
    ChainActionMode, ModuleIdError, NetRunMode, ResourceDemand, SkillHostcall,
    SkillRuntimePermission, WasmRuntimeLimits, WasmSandboxDecision, WasmTier2ModuleId,
    build_output_envelope, enforce_meter, evaluate_chain_action, evaluate_fs_access,
    evaluate_net_access, secret_family_override,
};

#[test]
fn malformed_wasm_fixtures_all_reject() {
    assert_eq!(
        WasmTier2ModuleId::from_wasm_bytes(include_bytes!(
            "fixtures/stage_d/malicious_wasm/short.wasm"
        )),
        Err(ModuleIdError::TooShort)
    );
    assert_eq!(
        WasmTier2ModuleId::from_wasm_bytes(include_bytes!(
            "fixtures/stage_d/malicious_wasm/bad_magic.wasm"
        )),
        Err(ModuleIdError::BadMagic)
    );
    assert_eq!(
        WasmTier2ModuleId::from_wasm_bytes(include_bytes!(
            "fixtures/stage_d/malicious_wasm/bad_version.wasm"
        )),
        Err(ModuleIdError::UnsupportedVersion)
    );
    assert_eq!(
        WasmTier2ModuleId::from_wasm_bytes(include_bytes!(
            "fixtures/stage_d/malicious_wasm/truncated_section.wasm"
        )),
        Err(ModuleIdError::MalformedSection)
    );
    assert_eq!(
        WasmTier2ModuleId::from_wasm_bytes(include_bytes!(
            "fixtures/stage_d/malicious_wasm/overlong_leb.wasm"
        )),
        Err(ModuleIdError::MalformedLeb128)
    );
    // Non-minimal (underlong) LEB128 `0x80 0x00` for value 0 — rejected so one
    // logical module cannot mint two distinct ids (adversarial finding F1).
    assert_eq!(
        WasmTier2ModuleId::from_wasm_bytes(include_bytes!(
            "fixtures/stage_d/malicious_wasm/underlong_leb.wasm"
        )),
        Err(ModuleIdError::MalformedLeb128)
    );
}

#[test]
fn valid_canary_module_accepts() {
    // Non-vacuous: the validator is not rejecting everything — a well-formed
    // header-only module is accepted, so the rejections above are meaningful.
    assert!(
        WasmTier2ModuleId::from_wasm_bytes(include_bytes!(
            "fixtures/stage_d/malicious_wasm/valid_minimal.wasm"
        ))
        .is_ok()
    );
}

#[test]
fn filesystem_escape_fixtures_deny() {
    let declared = ["input/sample.json", "fixtures/case_a.txt"];
    for evil in [
        "../../etc/passwd",
        "~/.ssh/id_rsa",
        "/etc/shadow",
        "./cwd_secret",
        "input/../../escape",
    ] {
        assert_eq!(
            evaluate_fs_access(&declared, evil, SkillRuntimePermission::FileRead),
            WasmSandboxDecision::Deny,
            "fs escape {evil} must deny"
        );
    }
}

#[test]
fn network_fixtures_deny() {
    // No network during a trial, and raw IP / non-allowlisted host denies even
    // when installed.
    assert_eq!(
        evaluate_net_access(
            &["api.fixture.test"],
            "evil.example.com",
            SkillRuntimePermission::Network,
            NetRunMode::TryBeforeUse
        ),
        WasmSandboxDecision::Deny
    );
    assert_eq!(
        evaluate_net_access(
            &["api.fixture.test"],
            "203.0.113.5",
            SkillRuntimePermission::Network,
            NetRunMode::Installed
        ),
        WasmSandboxDecision::Deny
    );
}

#[test]
fn secret_wallet_chain_write_fixtures_deny() {
    assert_eq!(
        secret_family_override(SkillRuntimePermission::Secret),
        Some(WasmSandboxDecision::Deny)
    );
    assert_eq!(
        secret_family_override(SkillRuntimePermission::Wallet),
        Some(WasmSandboxDecision::Deny)
    );
    assert_eq!(
        evaluate_chain_action(ChainActionMode::Write),
        WasmSandboxDecision::Deny
    );
}

#[test]
fn resource_bomb_fixtures_meter_out() {
    let limits = WasmRuntimeLimits::deny_small();
    let base = ResourceDemand::minimal();
    let bombs = [
        ResourceDemand {
            fuel_u64: u64::MAX,
            ..base
        }, // loop bomb
        ResourceDemand {
            memory_pages_u32: u32::MAX,
            ..base
        }, // alloc bomb
        ResourceDemand {
            stack_depth_u32: u32::MAX,
            ..base
        }, // recursion bomb
        ResourceDemand {
            hostcall_count_u32: u32::MAX,
            ..base
        }, // hostcall flood
    ];
    for bomb in bombs {
        assert_eq!(
            enforce_meter(&limits, &bomb),
            WasmSandboxDecision::MeterExceeded
        );
    }
}

#[test]
fn nondeterminism_and_signing_hostcalls_absent() {
    // No ambient-time / random / signing hostcall exists; an attempt to import
    // one is unknown and rejected before instantiation.
    assert_eq!(SkillHostcall::from_import_name("mnemos_get_random"), None);
    assert_eq!(SkillHostcall::from_import_name("mnemos_wall_clock"), None);
    assert_eq!(SkillHostcall::from_import_name("mnemos_sign_tx"), None);
}

#[test]
fn output_leak_fixture_redacted() {
    // A 64-hex-char secret in output is redacted before the digest is taken.
    let secret = b"key=deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef end";
    let env = build_output_envelope(secret, 1024);
    assert!(env.redacted, "secret-shaped output must be redacted");
}
