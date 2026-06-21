//! First-run install doctor (atom #408 F.0.7).
//!
//! The doctor is the first 5-minute trust anchor: it reports Rust / Sui / Walrus
//! / provider / secret status, the safety-kernel trust state
//! (official / local / self-host / quarantined), and — on any failure — an
//! actionable next step. The report builder is pure over an injected
//! [`DoctorProbe`] so it is fully testable and performs no network in quick mode.

pub mod key;

use crate::sha256_32;
use mnemos_l_dataset::privacy_scanner::scan_str;

/// §4.2 — the first-run doctor report.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FirstRunDoctorReport {
    /// Rust toolchain present.
    pub rust_ok: bool,
    /// Sui CLI present.
    pub sui_ok: bool,
    /// Walrus CLI present.
    pub walrus_ok: bool,
    /// A provider is configured (reference only; value never read).
    pub provider_ok: bool,
    /// No inline secret found in scanned surfaces.
    pub secret_zero: bool,
    /// SHA-256 of the static next-action label.
    pub next_action_hash_32: [u8; 32],
}

/// Safety-kernel trust state shown by the doctor. A hash mismatch (kernel not
/// intact) blocks official-trust surfaces and renders as
/// [`SafetyKernelTrust::Quarantined`].
#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SafetyKernelTrust {
    /// Official, attested build.
    Official = 1,
    /// Local-only (intact kernel, no official attestation).
    LocalOnly = 2,
    /// Self-hosted deployment.
    SelfHost = 3,
    /// Kernel hash mismatch — official-trust surfaces blocked.
    Quarantined = 4,
}

/// Injected probe inputs for the doctor (populated by the binary via local,
/// network-free checks).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DoctorProbe {
    /// Rust toolchain present.
    pub rust_ok: bool,
    /// Sui CLI present.
    pub sui_ok: bool,
    /// Walrus CLI present.
    pub walrus_ok: bool,
    /// A provider is configured.
    pub provider_ok: bool,
    /// No inline secret found.
    pub secret_zero: bool,
    /// Safety kernel hash intact.
    pub safety_kernel_intact: bool,
}

/// The actionable next step, derived from the first failing check. Always
/// returns a non-empty static label (the "ready" path included).
#[must_use]
pub const fn next_action(probe: &DoctorProbe) -> &'static str {
    if !probe.safety_kernel_intact {
        "safety kernel hash mismatch: reinstall an official sinabro build before using trust surfaces"
    } else if !probe.secret_zero {
        "inline secret detected: move it to a reference (env:/keychain:/kms:/vault:) and re-run: sinabro doctor"
    } else if !probe.rust_ok {
        "install the Rust toolchain (rustup) and re-run: sinabro doctor"
    } else if !probe.sui_ok {
        "install the Sui CLI (optional for local-only memory) and re-run: sinabro doctor"
    } else if !probe.walrus_ok {
        "install the Walrus CLI (optional for Walrus storage) and re-run: sinabro doctor"
    } else if !probe.provider_ok {
        "configure a provider reference (sinabro setup) — no live secret required"
    } else {
        "ready: run sinabro setup memory"
    }
}

/// Build the first-run doctor report from a probe (pure; no network).
#[must_use]
pub fn build_report(probe: &DoctorProbe) -> FirstRunDoctorReport {
    FirstRunDoctorReport {
        rust_ok: probe.rust_ok,
        sui_ok: probe.sui_ok,
        walrus_ok: probe.walrus_ok,
        provider_ok: probe.provider_ok,
        secret_zero: probe.secret_zero,
        next_action_hash_32: sha256_32(next_action(probe).as_bytes()),
    }
}

/// Resolve the safety-kernel trust state. A non-intact kernel is always
/// [`SafetyKernelTrust::Quarantined`] regardless of any other claim.
#[must_use]
pub const fn safety_kernel_trust(
    intact: bool,
    official_release: bool,
    self_hosted: bool,
) -> SafetyKernelTrust {
    if !intact {
        SafetyKernelTrust::Quarantined
    } else if official_release {
        SafetyKernelTrust::Official
    } else if self_hosted {
        SafetyKernelTrust::SelfHost
    } else {
        SafetyKernelTrust::LocalOnly
    }
}

/// MEASURED `secret_zero` (ENDGAME E5-2 — PD-1). Scan the doctor-visible local
/// surfaces with the canonical Stage-E secret engine
/// ([`mnemos_l_dataset::privacy_scanner::scan_str`]); `true` iff NO surface
/// carries a hard or encoded secret (fail-closed — a single hit ⇒ `false`). Pure
/// over the injected surface bytes (the binary gathers them from the config +
/// data-dir plaintext files; the encrypted key/store is never read). This
/// REPLACES the FORBIDDEN hardcoded `secret_zero: true`: a real inline secret now
/// makes the doctor report a non-clean state instead of lying green.
#[must_use]
pub fn measure_secret_zero(surfaces: &[&str]) -> bool {
    surfaces.iter().all(|s| {
        let r = scan_str(s);
        r.secret_hits_u32 == 0 && r.encoded_hits_u32 == 0
    })
}

/// MEASURED `safety_kernel_intact` (ENDGAME E5-2 — PD-1). A runtime self-test that
/// the safety-kernel feature lock is actually ENFORCED: every non-disableable
/// kernel feature both (a) resolves to [`crate::config::FeatureState::Locked`]
/// with `safety_kernel = true`, AND (b) REJECTS a disable request with
/// [`crate::CliError::SafetyKernelLocked`]. `true` only if all checks hold for
/// every kernel feature. This REPLACES the FORBIDDEN hardcoded
/// `safety_kernel_intact: true`: if the lock were ever weakened (a feature dropped
/// from the kernel set, or a disable silently accepted), this measures `false` and
/// the doctor quarantines the official-trust surfaces.
#[must_use]
pub fn measure_safety_kernel_intact() -> bool {
    use crate::CliError;
    use crate::config::{
        FeatureState, SAFETY_KERNEL_FEATURES, feature_toggle, is_safety_kernel_feature,
    };
    SAFETY_KERNEL_FEATURES.iter().all(|name| {
        is_safety_kernel_feature(name)
            && matches!(
                feature_toggle(name, FeatureState::Disabled),
                Err(CliError::SafetyKernelLocked)
            )
            && matches!(
                feature_toggle(name, FeatureState::Locked),
                Ok(v) if v.state == FeatureState::Locked && v.safety_kernel
            )
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn all_ok() -> DoctorProbe {
        DoctorProbe {
            rust_ok: true,
            sui_ok: true,
            walrus_ok: true,
            provider_ok: true,
            secret_zero: true,
            safety_kernel_intact: true,
        }
    }

    #[test]
    fn ready_when_all_ok() {
        assert_eq!(next_action(&all_ok()), "ready: run sinabro setup memory");
        let r = build_report(&all_ok());
        assert!(r.rust_ok && r.secret_zero);
        assert_eq!(
            r.next_action_hash_32,
            sha256_32(b"ready: run sinabro setup memory")
        );
    }

    #[test]
    fn missing_tools_yield_actionable_next_step() {
        let mut p = all_ok();
        p.rust_ok = false;
        assert!(next_action(&p).contains("Rust toolchain"));
        let mut p = all_ok();
        p.sui_ok = false;
        assert!(next_action(&p).contains("Sui CLI"));
        let mut p = all_ok();
        p.walrus_ok = false;
        assert!(next_action(&p).contains("Walrus CLI"));
        let mut p = all_ok();
        p.provider_ok = false;
        assert!(next_action(&p).contains("provider"));
    }

    #[test]
    fn secret_leak_takes_priority_and_is_actionable() {
        let mut p = all_ok();
        p.secret_zero = false;
        assert!(next_action(&p).contains("inline secret"));
    }

    #[test]
    fn secret_zero_is_measured_not_hardcoded() {
        // A clean config surface measures secret-zero TRUE.
        assert!(measure_secret_zero(&["profile = \"safe-default\"\n"]));
        // An empty surface set is vacuously clean (nothing to flag).
        assert!(measure_secret_zero(&[]));
        // REDTEAM: a surface carrying an inline secret measures FALSE — this is the
        // falsifiability the hardcoded `true` lacked (it could never go false).
        assert!(!measure_secret_zero(&[
            "provider_api_key=sk_test_fakefakefake"
        ]));
        assert!(!measure_secret_zero(&[
            "profile = \"safe-default\"\n",
            "wallet_secret leftover in a stray config",
        ]));
    }

    #[test]
    fn safety_kernel_intact_measures_the_real_enforced_lock() {
        // The real, intact kernel passes the enforced-lock self-test (every kernel
        // feature is Locked + a disable is rejected). If the lock regressed, this
        // would measure false rather than render a hardcoded green.
        assert!(measure_safety_kernel_intact());
    }

    #[test]
    fn safety_kernel_mismatch_quarantines_and_blocks_official() {
        assert_eq!(
            safety_kernel_trust(false, true, false),
            SafetyKernelTrust::Quarantined
        );
        assert_eq!(
            safety_kernel_trust(true, true, false),
            SafetyKernelTrust::Official
        );
        assert_eq!(
            safety_kernel_trust(true, false, true),
            SafetyKernelTrust::SelfHost
        );
        assert_eq!(
            safety_kernel_trust(true, false, false),
            SafetyKernelTrust::LocalOnly
        );
        let mut p = all_ok();
        p.safety_kernel_intact = false;
        assert!(next_action(&p).contains("safety kernel hash mismatch"));
    }
}
