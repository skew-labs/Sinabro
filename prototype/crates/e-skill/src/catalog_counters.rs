//! `mnemos-e-skill::catalog_counters` — downloads and
//! verified-install counters.
//!
//! Downloads are a **weak** signal: anyone can pull bytes. A *verified install*
//! is a **strong** signal that requires install / eval / active-trace evidence
//! (a [`VerifiedInstallReceipt`] whose [`VerifiedInstallState`] is one of
//! `Installed` / `EvalPassed` / `ActiveTrace`) and explicitly **excludes**
//! revoked installs. Ranking must show both so popularity can never
//! launder a low-trust skill past a secure one.
//!
//! Counters are derived by a deterministic, replay-idempotent fold over a slice
//! of receipts: applying the same receipt twice is a no-op
//! ([`fold_counters`] dedups by [`VerifiedInstallReceipt::replay_key`]), and the
//! result is independent of receipt order.

#![deny(missing_docs)]

extern crate alloc;

use alloc::collections::BTreeSet;

use mnemos_a_core::StageDTraceLink;

use crate::install_state::InstallState;
use crate::manifest::SkillId;
use crate::package::SkillPackageDigest32;

/// Domain tag for the replay-idempotency key of a verified install receipt.
const DOMAIN_VERIFIED_INSTALL: &[u8] = b"mnemos.d.verified_install.v1";

/// The lifecycle a verified install moved through, as observed off-chain from
/// the registry event stream. `Downloaded` is the weak floor;
/// `Installed` / `EvalPassed` / `ActiveTrace` are verified; `Revoked` is
/// excluded from the verified count.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
#[repr(u8)]
pub enum VerifiedInstallState {
    /// Bytes were pulled — a weak popularity signal only.
    Downloaded = 1,
    /// The package was installed (verified path).
    Installed = 2,
    /// The skill's eval suite passed for this install (verified path).
    EvalPassed = 3,
    /// The install is in an active-trace state (verified + active).
    ActiveTrace = 4,
    /// The install was revoked — excluded from the verified count.
    Revoked = 5,
}

impl VerifiedInstallState {
    /// The byte discriminant.
    #[must_use]
    pub const fn as_u8(self) -> u8 {
        self as u8
    }

    /// Parse a byte discriminant.
    #[must_use]
    pub const fn from_u8(byte: u8) -> Option<Self> {
        match byte {
            1 => Some(Self::Downloaded),
            2 => Some(Self::Installed),
            3 => Some(Self::EvalPassed),
            4 => Some(Self::ActiveTrace),
            5 => Some(Self::Revoked),
            _ => None,
        }
    }

    /// `true` for a state that counts as a verified install (install / eval /
    /// active), `false` for a mere download or a revoked install.
    #[must_use]
    pub const fn is_verified_install(self) -> bool {
        matches!(self, Self::Installed | Self::EvalPassed | Self::ActiveTrace)
    }

    /// `true` only for an active-trace install (also a verified install).
    #[must_use]
    pub const fn is_active(self) -> bool {
        matches!(self, Self::ActiveTrace)
    }

    /// `true` only for a revoked install (excluded from the verified count).
    #[must_use]
    pub const fn is_revoked(self) -> bool {
        matches!(self, Self::Revoked)
    }
}

/// A single off-chain verified-install observation. Carries no user,
/// payment, or secret field — only the skill, the package digest, the observed
/// state, the eval hash, and a Stage-D trace link.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub struct VerifiedInstallReceipt {
    /// The skill this receipt is about.
    pub skill: SkillId,
    /// The package content digest installed.
    pub package: SkillPackageDigest32,
    /// The observed verified-install state.
    pub state: VerifiedInstallState,
    /// Hash of the eval evidence that backed a verified install (zero when the
    /// state is a bare download).
    pub eval_hash_32: [u8; 32],
    /// Stage-D trace link binding this observation to its event source.
    pub trace: StageDTraceLink,
}

impl VerifiedInstallReceipt {
    /// Construct a verified-install receipt.
    #[must_use]
    pub const fn new(
        skill: SkillId,
        package: SkillPackageDigest32,
        state: VerifiedInstallState,
        eval_hash_32: [u8; 32],
        trace: StageDTraceLink,
    ) -> Self {
        Self {
            skill,
            package,
            state,
            eval_hash_32,
            trace,
        }
    }

    /// Map an on-chain [`InstallState`] onto a verified-install
    /// observation. Terminal `Removed` and the pre-install `None` produce no
    /// receipt; `Revoked` produces an explicitly-excluded `Revoked` receipt.
    #[must_use]
    pub fn from_install_state(
        skill: SkillId,
        package: SkillPackageDigest32,
        install: InstallState,
        eval_hash_32: [u8; 32],
        trace: StageDTraceLink,
    ) -> Option<Self> {
        let state = match install {
            InstallState::None | InstallState::Removed => return None,
            InstallState::DryRun => VerifiedInstallState::Downloaded,
            InstallState::Installed | InstallState::Disabled => VerifiedInstallState::Installed,
            InstallState::Enabled => VerifiedInstallState::ActiveTrace,
            InstallState::Revoked => VerifiedInstallState::Revoked,
        };
        Some(Self::new(skill, package, state, eval_hash_32, trace))
    }

    /// A stable per-receipt identity key. Two receipts with the same skill,
    /// package, state, eval hash, and trace fold to one (replay idempotency).
    #[must_use]
    pub fn replay_key(&self) -> [u8; 32] {
        let skill = self.skill.0.to_le_bytes();
        let state = [self.state.as_u8()];
        let trace = flatten_trace(&self.trace);
        crate::package::blake2b_256(&[
            DOMAIN_VERIFIED_INSTALL,
            &skill,
            self.package.as_bytes(),
            &state,
            &self.eval_hash_32,
            &trace,
        ])
    }
}

/// Flatten a [`StageDTraceLink`] into a fixed 19-byte little-endian form so it
/// can feed the no-separator `blake2b_256` framing unambiguously.
#[must_use]
fn flatten_trace(trace: &StageDTraceLink) -> [u8; 19] {
    let c = trace.stage_c_trace();
    let b = c.stage_b_trace();
    let mut out = [0u8; 19];
    out[0..8].copy_from_slice(&b.trace_id_u64.to_le_bytes());
    out[8..10].copy_from_slice(&b.atom_id_u16.to_le_bytes());
    out[10] = b.attempt_u8;
    out[11..13].copy_from_slice(&c.stage_c_atom_u16.to_le_bytes());
    out[13..15].copy_from_slice(&c.gate_id_u16.to_le_bytes());
    out[15..17].copy_from_slice(&trace.stage_d_atom_u16.to_le_bytes());
    out[17..19].copy_from_slice(&trace.sandbox_event_u16.to_le_bytes());
    out
}

/// The three popularity counters maintained for a catalog entry.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash, Default)]
pub struct CatalogCounters {
    /// Weak signal: every unique receipt is at least one download.
    pub downloads_u64: u64,
    /// Strong signal: unique verified installs, revoked excluded.
    pub verified_installs_u64: u64,
    /// Unique installs currently in an active-trace state.
    pub active_users_u64: u64,
}

impl CatalogCounters {
    /// All-zero counters.
    #[must_use]
    pub const fn zero() -> Self {
        Self {
            downloads_u64: 0,
            verified_installs_u64: 0,
            active_users_u64: 0,
        }
    }
}

/// Deterministically fold a slice of receipts into the three counters.
///
/// Idempotent: receipts are deduplicated by [`VerifiedInstallReceipt::replay_key`]
/// before counting, so replaying the same event stream — or the same receipt
/// many times — always yields the same counters. Order-independent, and uses
/// saturating addition so an adversarial event flood can never overflow-panic.
#[must_use]
pub fn fold_counters(receipts: &[VerifiedInstallReceipt]) -> CatalogCounters {
    let mut seen: BTreeSet<[u8; 32]> = BTreeSet::new();
    let mut counters = CatalogCounters::zero();
    for receipt in receipts {
        if !seen.insert(receipt.replay_key()) {
            continue;
        }
        counters.downloads_u64 = counters.downloads_u64.saturating_add(1);
        if receipt.state.is_verified_install() {
            counters.verified_installs_u64 = counters.verified_installs_u64.saturating_add(1);
        }
        if receipt.state.is_active() {
            counters.active_users_u64 = counters.active_users_u64.saturating_add(1);
        }
    }
    counters
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use mnemos_a_core::{StageBTraceLink, StageCTraceLink};

    fn trace(event: u16) -> StageDTraceLink {
        StageDTraceLink::new(
            StageCTraceLink::new(StageBTraceLink::new(1, 297, 1), 297, 142),
            297,
            event,
        )
    }

    fn receipt(state: VerifiedInstallState, event: u16) -> VerifiedInstallReceipt {
        VerifiedInstallReceipt::new(
            SkillId(42),
            SkillPackageDigest32::new([0xA0; 32]),
            state,
            [0x7E; 32],
            trace(event),
        )
    }

    #[test]
    fn download_increment() {
        let counters = fold_counters(&[
            receipt(VerifiedInstallState::Downloaded, 1),
            receipt(VerifiedInstallState::Downloaded, 2),
        ]);
        assert_eq!(counters.downloads_u64, 2);
        assert_eq!(counters.verified_installs_u64, 0);
    }

    #[test]
    fn verified_install_from_eval_pass() {
        let counters = fold_counters(&[receipt(VerifiedInstallState::EvalPassed, 1)]);
        assert_eq!(counters.downloads_u64, 1);
        assert_eq!(counters.verified_installs_u64, 1);
    }

    #[test]
    fn active_trace() {
        let counters = fold_counters(&[receipt(VerifiedInstallState::ActiveTrace, 1)]);
        assert_eq!(counters.verified_installs_u64, 1);
        assert_eq!(counters.active_users_u64, 1);
    }

    #[test]
    fn revoked_install_excluded() {
        let counters = fold_counters(&[
            receipt(VerifiedInstallState::Installed, 1),
            receipt(VerifiedInstallState::Revoked, 2),
        ]);
        // Two unique downloads, but only the non-revoked one is a verified
        // install.
        assert_eq!(counters.downloads_u64, 2);
        assert_eq!(counters.verified_installs_u64, 1);
        assert_eq!(counters.active_users_u64, 0);
    }

    #[test]
    fn replay_idempotency() {
        let r = receipt(VerifiedInstallState::ActiveTrace, 1);
        let once = fold_counters(&[r]);
        let thrice = fold_counters(&[r, r, r]);
        assert_eq!(once, thrice);
        assert_eq!(thrice.verified_installs_u64, 1);
        assert_eq!(thrice.active_users_u64, 1);
    }

    #[test]
    fn from_install_state_maps_lifecycle() {
        let skill = SkillId(42);
        let pkg = SkillPackageDigest32::new([0xA0; 32]);
        assert!(
            VerifiedInstallReceipt::from_install_state(
                skill,
                pkg,
                InstallState::None,
                [0; 32],
                trace(1)
            )
            .is_none()
        );
        let enabled = VerifiedInstallReceipt::from_install_state(
            skill,
            pkg,
            InstallState::Enabled,
            [0; 32],
            trace(1),
        )
        .expect("enabled maps to a receipt");
        assert_eq!(enabled.state, VerifiedInstallState::ActiveTrace);
    }
}
