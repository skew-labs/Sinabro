//! Incident pause / rollback gate.
//!
//! A pause state for the mainnet gate, the Gas Station sponsor
//! path, and the mainnet ceremony path.
//!
//! # Invariants
//!
//! * **Pause withholds; it never executes.** [`IncidentPause`] is a withholding
//!   authority only: while paused it forces a sponsor decision to *not proceed*
//!   ([`allows_sponsor_decision`](IncidentPause::allows_sponsor_decision) returns
//!   `false`) and refuses to build a ceremony transcript
//!   ([`gated_ceremony_build`](IncidentPause::gated_ceremony_build) returns
//!   [`CeremonyGuardError::Paused`]) — *before* any signer boundary is reached.
//!   It cannot, by construction, make any mainnet action happen.
//! * **An anomaly pauses the sponsor mode and the ceremony path.** A burn-in
//!   window that has been paused or has observed any anomaly engages the pause
//!   automatically ([`engage_from_burn_in`](IncidentPause::engage_from_burn_in)),
//!   mirroring the [`BurnInWindow`](crate::stage_c_burn_in::BurnInWindow)
//!   withhold-on-anomaly discipline.
//! * **Resume requires an evidence hash.** [`resume`](IncidentPause::resume)
//!   refuses an all-zero evidence hash with
//!   [`PauseError::ResumeEvidenceRequired`]; a pause can only be lifted against a
//!   non-zero evidence commitment, which is recorded on the state. There is no
//!   field a caller can set to clear the pause without that evidence.
//!
//! # Related
//!
//! * The sponsor decision this gate withholds is the
//!   `g-wallet` `GasStationDecision::accepted` boolean. This module
//!   consumes that decision as a plain `bool` rather than importing the
//!   `g-wallet` type, so `k-devex` gains no `g-wallet` dependency; the cross-type
//!   binding — that the gated boolean is exactly a real `evaluate_sponsorship`
//!   verdict — is proven in the `o-stage-c-e2e` integration crate (the test home
//!   owns both symbols, the same pattern as the ceremony binding).
//! * [`BurnInWindow`](crate::stage_c_burn_in::BurnInWindow)
//!   supplies the anomaly / paused signal that auto-engages the pause.
//! * [`CeremonyTranscript`](crate::stage_c_ceremony::CeremonyTranscript)
//!   is the ceremony path the pause gates (same crate).
//!
//! No live action: this is in-memory withholding state. `MainnetExecutionState`
//! stays `Locked`; the pause sink is `Paused`.

use crate::stage_c_burn_in::BurnInWindow;
use crate::stage_c_ceremony::{CeremonyError, CeremonyTranscript};
use crate::stage_c_checklist::MainnetChecklist;
use mnemos_d_move::stage_c_package_lock::MainnetPackageLock;

/// Why the incident pause was engaged. Every variant is data-free.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
#[repr(u8)]
pub enum PauseReason {
    /// An operator manually engaged the pause.
    OperatorManual = 1,
    /// A burn-in window observed an anomaly or was paused.
    BurnInAnomaly = 2,
    /// A Gas Station / sponsor-path alert engaged the pause.
    GasStationAnomaly = 3,
    /// A read-only canary monitor flagged an anomaly.
    CanaryAnomaly = 4,
}

impl PauseReason {
    /// The raw `#[repr(u8)]` discriminant (`1..=4`).
    #[inline]
    #[must_use]
    pub const fn as_u8(self) -> u8 {
        self as u8
    }

    /// Parse from the discriminant byte, rejecting unknown values.
    #[inline]
    #[must_use]
    pub const fn from_u8(byte: u8) -> Option<Self> {
        match byte {
            1 => Some(Self::OperatorManual),
            2 => Some(Self::BurnInAnomaly),
            3 => Some(Self::GasStationAnomaly),
            4 => Some(Self::CanaryAnomaly),
            _ => None,
        }
    }
}

/// Incident-pause state-transition error. Every variant is data-free.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
#[repr(u8)]
pub enum PauseError {
    /// [`IncidentPause::resume`] was called with an all-zero evidence hash.
    ResumeEvidenceRequired = 1,
}

impl core::fmt::Display for PauseError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let msg = match self {
            Self::ResumeEvidenceRequired => {
                "stage_c incident pause: resume requires a non-zero evidence hash"
            }
        };
        f.write_str(msg)
    }
}

impl core::error::Error for PauseError {}

/// Error from a pause-gated ceremony build: either the pause blocked it, or the
/// underlying [`CeremonyTranscript::build`] rejected the inputs.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum CeremonyGuardError {
    /// The incident pause was engaged, so the ceremony path is blocked before
    /// the signer boundary.
    Paused,
    /// The pause was clear, but [`CeremonyTranscript::build`] rejected the
    /// inputs (unbound commitment).
    Build(CeremonyError),
}

impl core::fmt::Display for CeremonyGuardError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Paused => f.write_str("stage_c incident pause: ceremony path blocked (paused)"),
            Self::Build(e) => write!(f, "stage_c incident pause: ceremony build rejected: {e}"),
        }
    }
}

impl core::error::Error for CeremonyGuardError {}

const fn is_zero_32(h: &[u8; 32]) -> bool {
    let mut i = 0;
    while i < 32 {
        if h[i] != 0 {
            return false;
        }
        i += 1;
    }
    true
}

/// The incident-pause / rollback gate state.
///
/// Private fields enforce the invariants: a pause can only be lifted through
/// [`resume`](Self::resume) against a non-zero evidence hash, and there is no
/// public field a caller can flip to clear the pause without that evidence.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub struct IncidentPause {
    paused: bool,
    reason: PauseReason,
    resume_evidence_hash_32: [u8; 32],
}

impl IncidentPause {
    /// A fresh, *running* (not paused) gate. The `reason` slot is a placeholder
    /// that is only meaningful once [`pause`](Self::pause) is called.
    #[inline]
    #[must_use]
    pub const fn running() -> Self {
        Self {
            paused: false,
            reason: PauseReason::OperatorManual,
            resume_evidence_hash_32: [0u8; 32],
        }
    }

    /// Whether the pause is currently engaged.
    #[inline]
    #[must_use]
    pub const fn is_paused(&self) -> bool {
        self.paused
    }

    /// The reason the pause was engaged, or `None` while running.
    #[inline]
    #[must_use]
    pub const fn reason(&self) -> Option<PauseReason> {
        if self.paused { Some(self.reason) } else { None }
    }

    /// The evidence hash recorded by the most recent successful
    /// [`resume`](Self::resume). All-zero until the first resume.
    #[inline]
    #[must_use]
    pub const fn resume_evidence_hash_32(&self) -> [u8; 32] {
        self.resume_evidence_hash_32
    }

    /// Engage the pause with a reason. Idempotent: re-pausing overwrites the
    /// reason. Clears any previously recorded resume-evidence hash, so a later
    /// resume must present fresh evidence.
    #[inline]
    pub fn pause(&mut self, reason: PauseReason) {
        self.paused = true;
        self.reason = reason;
        self.resume_evidence_hash_32 = [0u8; 32];
    }

    /// Engage the pause from a burn-in window: if the window is paused or has
    /// observed any anomaly, engage with [`PauseReason::BurnInAnomaly`] and
    /// return `true`; otherwise leave the gate unchanged and return `false`.
    ///
    /// This reuses the [`BurnInWindow`](crate::stage_c_burn_in::BurnInWindow)
    /// withhold-on-anomaly signal.
    #[inline]
    pub fn engage_from_burn_in(&mut self, window: &BurnInWindow) -> bool {
        if window.paused || window.anomaly_count_u32 > 0 {
            self.pause(PauseReason::BurnInAnomaly);
            true
        } else {
            false
        }
    }

    /// Lift the pause against a non-zero evidence hash.
    ///
    /// # Errors
    ///
    /// [`PauseError::ResumeEvidenceRequired`] when `evidence_hash_32` is all-zero
    /// — a pause can never be cleared without an evidence commitment.
    pub fn resume(&mut self, evidence_hash_32: [u8; 32]) -> Result<(), PauseError> {
        if is_zero_32(&evidence_hash_32) {
            return Err(PauseError::ResumeEvidenceRequired);
        }
        self.paused = false;
        self.resume_evidence_hash_32 = evidence_hash_32;
        Ok(())
    }

    /// Gate a Gas Station sponsor decision: a sponsor request may
    /// proceed only if it was itself accepted **and** the pause is clear. While
    /// paused, even an accepted decision is withheld.
    ///
    /// `sponsor_accepted` is the `GasStationDecision::accepted` boolean consumed
    /// as a value (no `g-wallet` dependency edge — see the module reuse map).
    #[inline]
    #[must_use]
    pub const fn allows_sponsor_decision(&self, sponsor_accepted: bool) -> bool {
        !self.paused && sponsor_accepted
    }

    /// Whether the ceremony path may proceed (the pause is clear).
    #[inline]
    #[must_use]
    pub const fn allows_ceremony(&self) -> bool {
        !self.paused
    }

    /// Build a mainnet ceremony transcript only if the pause is
    /// clear. While paused the ceremony path is blocked before the signer
    /// boundary.
    ///
    /// # Errors
    ///
    /// [`CeremonyGuardError::Paused`] when the incident pause is engaged, or
    /// [`CeremonyGuardError::Build`] wrapping the underlying
    /// [`CeremonyError`] when the pause is clear but the transcript inputs are
    /// unbound.
    #[allow(clippy::too_many_arguments)]
    pub fn gated_ceremony_build(
        &self,
        package_lock: MainnetPackageLock,
        checklist: &MainnetChecklist,
        multisig_roster_hash_32: [u8; 32],
        timelock_min_delay_secs_u32: u32,
        timelock_cancel_window_secs_u32: u32,
        exact_tx_digest_32: [u8; 32],
        signer_policy_hash_32: [u8; 32],
    ) -> Result<CeremonyTranscript, CeremonyGuardError> {
        if self.paused {
            return Err(CeremonyGuardError::Paused);
        }
        CeremonyTranscript::build(
            package_lock,
            checklist,
            multisig_roster_hash_32,
            timelock_min_delay_secs_u32,
            timelock_cancel_window_secs_u32,
            exact_tx_digest_32,
            signer_policy_hash_32,
        )
        .map_err(CeremonyGuardError::Build)
    }
}

impl Default for IncidentPause {
    #[inline]
    fn default() -> Self {
        Self::running()
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]
    use super::*;
    use mnemos_d_move::types::ObjectId;

    fn lock() -> MainnetPackageLock {
        MainnetPackageLock::new(
            ObjectId::new([0x33; 32]),
            [0x44; 32],
            [0x55; 32],
            [0x66; 32],
        )
        .expect("valid package lock")
    }

    fn green_checklist() -> MainnetChecklist {
        MainnetChecklist::new_locked().with_evidence_hash([0x77; 32])
    }

    /// While paused, even an accepted sponsor decision is withheld; while
    /// running, an accepted decision passes and a rejected one stays rejected.
    #[test]
    fn c2_18_pause_blocks_sponsor_decision() {
        let mut gate = IncidentPause::running();
        // Running: accepted passes, rejected stays rejected.
        assert!(gate.allows_sponsor_decision(true));
        assert!(!gate.allows_sponsor_decision(false));

        // Paused: an accepted decision is withheld.
        gate.pause(PauseReason::GasStationAnomaly);
        assert!(!gate.allows_sponsor_decision(true));
        assert!(!gate.allows_sponsor_decision(false));
        assert_eq!(gate.reason(), Some(PauseReason::GasStationAnomaly));
    }

    /// While paused the ceremony path is blocked before any signer boundary;
    /// while running it composes with the real transcript builder.
    #[test]
    fn c2_18_pause_blocks_ceremony() {
        let mut gate = IncidentPause::running();
        assert!(gate.allows_ceremony());

        // Running + bound inputs → a real transcript is built.
        let built = gate.gated_ceremony_build(
            lock(),
            &green_checklist(),
            [0x88; 32],
            3600,
            1800,
            [0x99; 32],
            [0xAA; 32],
        );
        assert!(built.is_ok());

        // Paused → blocked before the builder runs (even with bound inputs).
        gate.pause(PauseReason::OperatorManual);
        assert!(!gate.allows_ceremony());
        assert_eq!(
            gate.gated_ceremony_build(
                lock(),
                &green_checklist(),
                [0x88; 32],
                3600,
                1800,
                [0x99; 32],
                [0xAA; 32],
            ),
            Err(CeremonyGuardError::Paused),
        );
    }

    /// A pause cannot be lifted with an all-zero evidence hash; a non-zero hash
    /// lifts it and is recorded.
    #[test]
    fn c2_18_resume_requires_evidence_hash() {
        let mut gate = IncidentPause::running();
        gate.pause(PauseReason::BurnInAnomaly);
        assert!(gate.is_paused());

        // All-zero evidence → refused, pause stays engaged.
        assert_eq!(
            gate.resume([0u8; 32]),
            Err(PauseError::ResumeEvidenceRequired)
        );
        assert!(gate.is_paused());

        // Non-zero evidence → lifted and recorded.
        assert_eq!(gate.resume([0xEE; 32]), Ok(()));
        assert!(!gate.is_paused());
        assert_eq!(gate.resume_evidence_hash_32(), [0xEE; 32]);
        assert_eq!(gate.reason(), None);
    }

    /// A clean burn-in window does not engage the pause; a window with an
    /// anomaly (or a paused window) does, with [`PauseReason::BurnInAnomaly`].
    #[test]
    fn c2_18_anomaly_from_burn_in_pauses() {
        // Clean window → no engage.
        let clean = BurnInWindow::new(100, 100);
        let mut gate = IncidentPause::running();
        assert!(!gate.engage_from_burn_in(&clean));
        assert!(!gate.is_paused());

        // Anomalous window → engage with BurnInAnomaly.
        let mut anomalous = BurnInWindow::new(100, 100);
        anomalous.record_anomaly();
        let mut gate2 = IncidentPause::running();
        assert!(gate2.engage_from_burn_in(&anomalous));
        assert!(gate2.is_paused());
        assert_eq!(gate2.reason(), Some(PauseReason::BurnInAnomaly));

        // Paused window → also engages.
        let mut paused_window = BurnInWindow::new(100, 100);
        paused_window.pause();
        let mut gate3 = IncidentPause::running();
        assert!(gate3.engage_from_burn_in(&paused_window));
        assert!(gate3.is_paused());
    }

    /// `c2_18_reason_roundtrips` — the data-free reason discriminants round-trip
    /// and reject unknown bytes.
    #[test]
    fn c2_18_reason_roundtrips() {
        for r in [
            PauseReason::OperatorManual,
            PauseReason::BurnInAnomaly,
            PauseReason::GasStationAnomaly,
            PauseReason::CanaryAnomaly,
        ] {
            assert_eq!(PauseReason::from_u8(r.as_u8()), Some(r));
        }
        for b in [0u8, 5, 99, 255] {
            assert!(PauseReason::from_u8(b).is_none());
        }
    }
}
