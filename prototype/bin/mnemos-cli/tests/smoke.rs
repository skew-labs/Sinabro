//! Bin smoke tests for `mnemos-cli` (atom #6 — A.0.6 graceful shutdown 배선).
//!
//! Mirrors `bin/mnemos-agent/tests/smoke.rs` but pins the `LogService::Cli`
//! discriminant on every event line (atom #4 schema). Both bins share the
//! same boot/shutdown chain; the only wire-level delta is the `"service"`
//! tag.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::process::Command;

const BIN: &str = env!("CARGO_BIN_EXE_mnemos-cli");

/// `--help` must short-circuit before any logging / supervisor wiring and
/// exit with success.
#[test]
fn bin_help_flag_short_circuits_and_exits_zero() {
    let out = Command::new(BIN)
        .arg("--help")
        .output()
        .expect("spawn mnemos-cli --help");
    assert!(
        out.status.success(),
        "expected success, got {:?}",
        out.status
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("mnemos-cli"),
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
#[test]
fn bin_missing_config_emits_redacted_config_failure_and_exits_nonzero() {
    let out = Command::new(BIN)
        .output()
        .expect("spawn mnemos-cli (no args)");
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
        stderr.contains("\"service\":\"cli\""),
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
