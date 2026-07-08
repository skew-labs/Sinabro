//! Bin smoke tests for `mnemos-agent` (atom #6 — A.0.6 graceful shutdown 배선).
//!
//! Covers the two ATOM_PLAN line 849 surfaces that exercise the boot wiring
//! without registering a real task: `--help` short-circuits cleanly, and a
//! missing `--config` argument fails closed with the canonical
//! `config_failure` JSON envelope (atom #4 single-line schema) on stderr.
//! Drain-complete / drain-timeout / four-event JSON wire shape are already
//! covered by atoms #3 / #4 (library-level unit tests) and are not re-asserted
//! here.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::process::Command;

const BIN: &str = env!("CARGO_BIN_EXE_mnemos-agent");

/// `--help` must short-circuit before any logging / supervisor wiring and
/// exit with success. The usage text is written to stderr (the canonical
/// envelope sink) and must not absorb a raw secret-like canary.
#[test]
fn bin_help_flag_short_circuits_and_exits_zero() {
    let out = Command::new(BIN)
        .arg("--help")
        .output()
        .expect("spawn mnemos-agent --help");
    assert!(
        out.status.success(),
        "expected success, got {:?}",
        out.status
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("mnemos-agent"),
        "stderr missing binary name: {stderr}"
    );
    assert!(
        stderr.contains("--config"),
        "stderr missing --config option: {stderr}"
    );
    assert!(
        !stderr.contains("\"event\":\"config_failure\""),
        "help path must not emit a config_failure event: {stderr}"
    );
}

/// Running the bin with no arguments fails closed: the canonical
/// `config_failure` line is written to stderr and the process exits non-zero.
/// The line must contain the atom #4 schema stamp and the `&'static`
/// state-rejection message (no raw cause).
#[test]
fn bin_missing_config_emits_redacted_config_failure_and_exits_nonzero() {
    let out = Command::new(BIN)
        .output()
        .expect("spawn mnemos-agent (no args)");
    assert!(
        !out.status.success(),
        "expected non-zero exit, got {:?}",
        out.status
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("\"event\":\"config_failure\""),
        "stderr missing config_failure event: {stderr}"
    );
    assert!(
        stderr.contains("\"schema\":\"mnemos.log.v0\""),
        "stderr missing schema stamp: {stderr}"
    );
    assert!(
        stderr.contains("\"service\":\"agent\""),
        "stderr missing service tag: {stderr}"
    );
    assert!(
        stderr.contains("state rejected by phase/ownership/lifetime/unit-width gate"),
        "stderr missing &'static state-rejection message: {stderr}"
    );
    assert!(
        !stderr.contains("CANARY_RAW_VALUE"),
        "stderr leaked a raw canary marker: {stderr}"
    );
}
