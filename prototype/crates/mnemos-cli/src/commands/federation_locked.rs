//! `sinabro federation locked` — Seal / WinFLoRA locked future controls (atom
//! #466 · F.7.7 Seal/WinFLoRA controls locked).
//!
//! Makes the advanced federation primitives — Seal secure aggregation and
//! WinFLoRA — **visible as locked future gates**. In Stage F they cannot be
//! started: there is no path from this module to an aggregation or a training
//! spawn ([`FederationLockedView::try_start`] always refuses,
//! [`FederationLockedView::can_start_aggregation`] /
//! [`FederationLockedView::can_start_training`] are always `false`), and the
//! controls never render `Green` (they render [`RenderTruth::Unknown`] — a
//! locked, never-measured future gate, the G-F-FEDERATION-LOCK posture).
//!
//! Reuse (no reinvention — USER-LOCKED Option A, AskUserQuestion 2026-06-07):
//! the Seal boundary is the canonical Stage B
//! [`mnemos_f_seal::StageBSealStubPolicy`] (#156) — its `default_testnet`
//! constructor proves the Seal stub **denies private-memory publish** by default
//! — and the user-facing copy is guarded by the canonical
//! [`mnemos_f_seal::stage_b_wording_ok`] (#157) against any misleading
//! "encryption active" claim, displaying the canonical safe
//! [`mnemos_f_seal::STAGE_B_SEAL_STUB_BOUNDARY_PHRASE`] (`"stub boundary"`). This
//! module mints no Seal/federation truth and performs no live action.

use crate::tui::RenderTruth;
use mnemos_f_seal::{STAGE_B_SEAL_STUB_BOUNDARY_PHRASE, StageBSealStubPolicy, stage_b_wording_ok};

/// The advanced (locked) federation controls Stage F surfaces but cannot run.
#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LockedFederationControl {
    /// Seal secure aggregation (custody-adjacent; deferred past Stage F).
    SealSecureAggregation = 1,
    /// WinFLoRA federated low-rank adaptation (L3 training; locked).
    WinFlora = 2,
}

impl LockedFederationControl {
    /// Both locked controls, in discriminant order.
    pub const ALL: [LockedFederationControl; 2] = [
        LockedFederationControl::SealSecureAggregation,
        LockedFederationControl::WinFlora,
    ];

    /// The stable `u8` discriminant.
    #[must_use]
    pub const fn as_u8(self) -> u8 {
        self as u8
    }

    /// A stable, colorless label.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::SealSecureAggregation => "seal_secure_aggregation",
            Self::WinFlora => "winflora",
        }
    }
}

/// Why a locked-federation action refused (fail-closed).
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum FederationLockedReject {
    /// Starting a locked control (aggregation / training) is forbidden in Stage F.
    #[error("locked federation control cannot start in stage F")]
    StartForbiddenInStageF,
}

/// The canonical locked-gate copy. Uses the safe boundary phrasing and makes no
/// affirmative encryption claim, so it passes the #157 wording guard.
const LOCKED_DOC: &str = "Seal secure aggregation and WinFLoRA are locked future gates. \
This is a stub boundary only — no encryption is performed, and no aggregation or \
training runs in Stage F.";

/// A read-only view of the locked Seal / WinFLoRA federation controls.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FederationLockedView {
    seal_policy: StageBSealStubPolicy,
}

impl FederationLockedView {
    /// The Stage F locked view: the Seal policy is the canonical default-deny
    /// testnet policy (private-memory publish denied).
    #[must_use]
    pub const fn locked() -> Self {
        Self {
            seal_policy: StageBSealStubPolicy::default_testnet(),
        }
    }

    /// Whether the given control is locked. Always `true` in Stage F.
    #[must_use]
    pub const fn is_locked(&self, _control: LockedFederationControl) -> bool {
        true
    }

    /// Whether the canonical Seal stub denies private-memory publish (it does, by
    /// default — the reuse proof).
    #[must_use]
    pub const fn seal_denies_private_publish(&self) -> bool {
        !self.seal_policy.allow_private_memory_publish
    }

    /// Always `false`: secure aggregation cannot start in Stage F.
    #[must_use]
    pub const fn can_start_aggregation(&self) -> bool {
        false
    }

    /// Always `false`: federated (WinFLoRA) training cannot start in Stage F.
    #[must_use]
    pub const fn can_start_training(&self) -> bool {
        false
    }

    /// Attempt to start a locked control. Always refuses — there is no spawn path.
    pub const fn try_start(
        &self,
        _control: LockedFederationControl,
    ) -> Result<(), FederationLockedReject> {
        Err(FederationLockedReject::StartForbiddenInStageF)
    }

    /// The canonical safe boundary phrase (`"stub boundary"`).
    #[must_use]
    pub const fn boundary_phrase(&self) -> &'static str {
        STAGE_B_SEAL_STUB_BOUNDARY_PHRASE
    }

    /// The stable locked-gate documentation snapshot.
    #[must_use]
    pub const fn docs_snapshot(&self) -> &'static str {
        LOCKED_DOC
    }

    /// Whether the docs snapshot passes the canonical #157 wording guard — i.e.
    /// it makes no misleading encryption claim. Always `true` for [`LOCKED_DOC`].
    #[must_use]
    pub fn docs_wording_ok(&self) -> bool {
        stage_b_wording_ok(LOCKED_DOC).is_ok()
    }

    /// The render truth: a locked future gate is `Unknown` — never `Green` (it is
    /// not measured / not available), the no-false-green law for locked controls.
    #[must_use]
    pub const fn render_truth(&self) -> RenderTruth {
        RenderTruth::Unknown
    }

    /// Colorless locked-control status lines bounded by `rows`.
    #[must_use]
    pub fn render(&self, rows: u16) -> Vec<String> {
        let mut lines = vec![
            format!(
                "seal_denies_private_publish={}",
                self.seal_denies_private_publish()
            ),
            format!("can_start_aggregation={}", self.can_start_aggregation()),
            format!("can_start_training={}", self.can_start_training()),
            format!("boundary_phrase={}", self.boundary_phrase()),
            format!("docs_wording_ok={}", self.docs_wording_ok()),
            format!("truth_u8={}", self.render_truth() as u8),
        ];
        for control in LockedFederationControl::ALL {
            lines.push(format!(
                "control={} locked={}",
                control.label(),
                self.is_locked(control)
            ));
        }
        lines.into_iter().take(rows as usize).collect()
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    #![allow(clippy::expect_used)]
    #![allow(clippy::panic)]

    use super::*;
    use mnemos_f_seal::StageBSealStubError;

    #[test]
    fn both_controls_are_locked() {
        let v = FederationLockedView::locked();
        assert!(v.is_locked(LockedFederationControl::SealSecureAggregation));
        assert!(v.is_locked(LockedFederationControl::WinFlora));
    }

    #[test]
    fn unlock_status_is_never_green() {
        let v = FederationLockedView::locked();
        // A locked future gate renders Unknown, never a false Green.
        assert_eq!(v.render_truth(), RenderTruth::Unknown);
        assert_ne!(v.render_truth(), RenderTruth::Green);
    }

    #[test]
    fn no_training_or_aggregation_spawn() {
        let v = FederationLockedView::locked();
        assert!(!v.can_start_aggregation());
        assert!(!v.can_start_training());
        for control in LockedFederationControl::ALL {
            assert_eq!(
                v.try_start(control),
                Err(FederationLockedReject::StartForbiddenInStageF)
            );
        }
    }

    #[test]
    fn seal_stub_denies_private_publish_reuse_proof() {
        let v = FederationLockedView::locked();
        // The reused canonical Seal stub default-denies private-memory publish.
        assert!(v.seal_denies_private_publish());
    }

    #[test]
    fn docs_snapshot_uses_boundary_phrase_and_passes_wording_guard() {
        let v = FederationLockedView::locked();
        assert_eq!(v.boundary_phrase(), "stub boundary");
        assert!(
            v.docs_snapshot()
                .contains(STAGE_B_SEAL_STUB_BOUNDARY_PHRASE)
        );
        // The canonical #157 wording guard accepts the honest locked-gate copy.
        assert!(v.docs_wording_ok());
        assert_eq!(stage_b_wording_ok(v.docs_snapshot()), Ok(()));
        // And it would reject a misleading encryption claim (reuse proof).
        assert_eq!(
            stage_b_wording_ok("Your memory is encrypted end-to-end with Seal."),
            Err(StageBSealStubError::MisleadingEncryptionClaim)
        );
    }

    #[test]
    fn render_is_bounded_and_no_commerce() {
        let v = FederationLockedView::locked();
        assert!(v.render(2).len() <= 2);
        const COMMERCE: &[&str] = &["price", "buy", "sell", "checkout", "refund", "$"];
        for line in v.render(64) {
            for t in COMMERCE {
                assert!(!line.contains(*t), "commerce token {t} leaked: {line}");
            }
        }
    }
}
