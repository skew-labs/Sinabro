//! Stage C audit finding state machine (C-WP-04A · atom #203 · C.1.2).
//!
//! Canonical OUT (§4.2): [`AuditFindingSeverity`], [`AuditFindingState`],
//! [`AuditFinding`].
//!
//! # Madness invariants (atom #203)
//!
//! * **High/Critical cannot be hand-waved.** [`AuditFinding::verdict`] returns
//!   [`BlocksMainnet`](AuditFindingVerdict::BlocksMainnet) for any *open*
//!   High/Critical finding, so an unresolved serious finding cannot be smuggled
//!   past the mainnet checklist (atom #207 `AuditResolved` step consumes
//!   [`audit_resolved`]).
//! * **A "fixed" High/Critical needs evidence.** Marking a High/Critical as
//!   [`Fixed`](AuditFindingState::Fixed) without an evidence hash yields
//!   [`EvidenceMissing`](AuditFindingVerdict::EvidenceMissing) — which still
//!   blocks. The fix claim must point at a real, content-addressed
//!   [`StageCEvidenceRef`].
//! * **Accepted risk needs a signed ref.** An [`AcceptedRisk`](AuditFindingState::AcceptedRisk)
//!   finding of *any* severity requires a non-zero evidence ref (the
//!   auditor-signed acceptance record); without it the verdict is
//!   [`EvidenceMissing`](AuditFindingVerdict::EvidenceMissing).
//! * **Each finding has state, evidence, and an owner-trace.** The `owner` is
//!   not a separate field: it is carried by the [`StageCEvidenceRef`]'s
//!   [`StageCTraceLink`](mnemos_a_core::trace::StageCTraceLink) (atom/attempt/gate),
//!   so the §4.2 four-field signature is implemented verbatim without re-minting
//!   an owner type.
//! * **No re-mint.** Evidence reuses the §4.0 [`StageCEvidenceRef`] (atom #177);
//!   no parallel evidence/trace type is introduced.

use crate::stage_c_evidence::{STAGE_C_EVIDENCE_REF_BYTES, StageCEvidenceRef};

/// Fixed serialized byte width of an [`AuditFinding`]: `4` (`id_u32`) + `1`
/// (severity) + `1` (state) + `47` ([`STAGE_C_EVIDENCE_REF_BYTES`]).
pub const AUDIT_FINDING_BYTES: usize = 4 + 1 + 1 + STAGE_C_EVIDENCE_REF_BYTES;

/// Severity of an audit finding (§4.2). Higher discriminant = more serious.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
#[repr(u8)]
pub enum AuditFindingSeverity {
    /// Informational; no action required for mainnet.
    Info = 1,
    /// Low severity.
    Low = 2,
    /// Medium severity.
    Medium = 3,
    /// High severity — blocks mainnet while open.
    High = 4,
    /// Critical severity — blocks mainnet while open.
    Critical = 5,
}

impl AuditFindingSeverity {
    /// The raw `#[repr(u8)]` discriminant.
    #[inline]
    pub const fn as_u8(self) -> u8 {
        self as u8
    }

    /// Parse from the discriminant byte, rejecting unknown values.
    #[inline]
    pub const fn from_u8(byte: u8) -> Option<Self> {
        match byte {
            1 => Some(Self::Info),
            2 => Some(Self::Low),
            3 => Some(Self::Medium),
            4 => Some(Self::High),
            5 => Some(Self::Critical),
            _ => None,
        }
    }

    /// Whether this severity is [`High`](Self::High) or
    /// [`Critical`](Self::Critical) — the two severities that can block a
    /// mainnet checklist.
    #[inline]
    pub const fn is_high_or_critical(self) -> bool {
        matches!(self, Self::High | Self::Critical)
    }
}

/// Lifecycle state of an audit finding (§4.2).
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
#[repr(u8)]
pub enum AuditFindingState {
    /// Reported and not yet addressed.
    Open = 1,
    /// Fixed; for High/Critical this requires a non-zero evidence ref.
    Fixed = 2,
    /// Risk explicitly accepted; requires a non-zero (signed) evidence ref.
    AcceptedRisk = 3,
    /// Determined not to be a real finding.
    FalsePositive = 4,
}

impl AuditFindingState {
    /// The raw `#[repr(u8)]` discriminant.
    #[inline]
    pub const fn as_u8(self) -> u8 {
        self as u8
    }

    /// Parse from the discriminant byte, rejecting unknown values.
    #[inline]
    pub const fn from_u8(byte: u8) -> Option<Self> {
        match byte {
            1 => Some(Self::Open),
            2 => Some(Self::Fixed),
            3 => Some(Self::AcceptedRisk),
            4 => Some(Self::FalsePositive),
            _ => None,
        }
    }
}

/// The machine-checkable verdict of one [`AuditFinding`] against the mainnet
/// gate.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
#[repr(u8)]
pub enum AuditFindingVerdict {
    /// An open High/Critical finding — blocks mainnet outright.
    BlocksMainnet = 1,
    /// A resolved-state claim (Fixed/AcceptedRisk) that lacks the required
    /// evidence ref — still blocks until the evidence is attached.
    EvidenceMissing = 2,
    /// Adequately resolved (or never blocking): does not block mainnet.
    Resolved = 3,
}

/// A single audit finding (§4.2): a stable id, a severity, a lifecycle state,
/// and a content-addressed evidence ref.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub struct AuditFinding {
    /// Stable finding id (e.g. an auditor's tracking number).
    pub id_u32: u32,
    /// Severity classification.
    pub severity: AuditFindingSeverity,
    /// Lifecycle state.
    pub state: AuditFindingState,
    /// Content-addressed evidence ref (the fix/acceptance record). Reuses the
    /// §4.0 [`StageCEvidenceRef`]; its trace stamp identifies the owner.
    pub evidence: StageCEvidenceRef,
}

impl AuditFinding {
    /// Construct a finding from its components.
    #[inline]
    pub const fn new(
        id_u32: u32,
        severity: AuditFindingSeverity,
        state: AuditFindingState,
        evidence: StageCEvidenceRef,
    ) -> Self {
        Self {
            id_u32,
            severity,
            state,
            evidence,
        }
    }

    /// Whether this finding carries a non-zero evidence content hash. An
    /// all-zero hash is treated as "no evidence attached".
    #[inline]
    pub const fn has_evidence(&self) -> bool {
        let h = &self.evidence.path_hash_32;
        let mut i = 0;
        while i < 32 {
            if h[i] != 0 {
                return true;
            }
            i += 1;
        }
        false
    }

    /// The machine-checkable verdict for this finding against the mainnet gate.
    ///
    /// * open High/Critical → [`BlocksMainnet`](AuditFindingVerdict::BlocksMainnet);
    /// * High/Critical [`Fixed`](AuditFindingState::Fixed) without evidence →
    ///   [`EvidenceMissing`](AuditFindingVerdict::EvidenceMissing);
    /// * any [`AcceptedRisk`](AuditFindingState::AcceptedRisk) without a signed
    ///   (non-zero) ref → [`EvidenceMissing`](AuditFindingVerdict::EvidenceMissing);
    /// * everything else → [`Resolved`](AuditFindingVerdict::Resolved).
    #[inline]
    pub const fn verdict(&self) -> AuditFindingVerdict {
        match self.state {
            AuditFindingState::Open => {
                if self.severity.is_high_or_critical() {
                    AuditFindingVerdict::BlocksMainnet
                } else {
                    AuditFindingVerdict::Resolved
                }
            }
            AuditFindingState::Fixed => {
                if self.severity.is_high_or_critical() && !self.has_evidence() {
                    AuditFindingVerdict::EvidenceMissing
                } else {
                    AuditFindingVerdict::Resolved
                }
            }
            AuditFindingState::AcceptedRisk => {
                if self.has_evidence() {
                    AuditFindingVerdict::Resolved
                } else {
                    AuditFindingVerdict::EvidenceMissing
                }
            }
            AuditFindingState::FalsePositive => AuditFindingVerdict::Resolved,
        }
    }

    /// Whether this finding blocks the mainnet checklist. Both
    /// [`BlocksMainnet`](AuditFindingVerdict::BlocksMainnet) and
    /// [`EvidenceMissing`](AuditFindingVerdict::EvidenceMissing) block.
    #[inline]
    pub const fn blocks_mainnet(&self) -> bool {
        !matches!(self.verdict(), AuditFindingVerdict::Resolved)
    }

    /// Serialize to the fixed [`AUDIT_FINDING_BYTES`] byte form:
    /// `id_u32 (LE) ‖ severity ‖ state ‖ evidence.to_bytes()`.
    pub fn to_bytes(&self) -> [u8; AUDIT_FINDING_BYTES] {
        let mut out = [0u8; AUDIT_FINDING_BYTES];
        out[0..4].copy_from_slice(&self.id_u32.to_le_bytes());
        out[4] = self.severity.as_u8();
        out[5] = self.state.as_u8();
        out[6..AUDIT_FINDING_BYTES].copy_from_slice(&self.evidence.to_bytes());
        out
    }

    /// Parse a finding from its fixed [`AUDIT_FINDING_BYTES`] byte form,
    /// rejecting unknown severity/state discriminants.
    pub fn from_bytes(bytes: &[u8; AUDIT_FINDING_BYTES]) -> Option<Self> {
        let mut id = [0u8; 4];
        id.copy_from_slice(&bytes[0..4]);
        let severity = AuditFindingSeverity::from_u8(bytes[4])?;
        let state = AuditFindingState::from_u8(bytes[5])?;
        let mut ev = [0u8; STAGE_C_EVIDENCE_REF_BYTES];
        ev.copy_from_slice(&bytes[6..AUDIT_FINDING_BYTES]);
        Some(Self::new(
            u32::from_le_bytes(id),
            severity,
            state,
            StageCEvidenceRef::from_bytes(&ev),
        ))
    }
}

/// Whether a set of findings clears the audit step of the mainnet checklist
/// (atom #207 `AuditResolved`): `true` iff **no** finding
/// [`blocks_mainnet`](AuditFinding::blocks_mainnet).
#[inline]
pub fn audit_resolved(findings: &[AuditFinding]) -> bool {
    findings.iter().all(|f| !f.blocks_mainnet())
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]
    use super::*;
    use mnemos_a_core::trace::{StageBTraceLink, StageCTraceLink};

    fn ev(nonzero: bool) -> StageCEvidenceRef {
        let hash = if nonzero { [0xAB; 32] } else { [0x00; 32] };
        StageCEvidenceRef::new(
            hash,
            StageCTraceLink::new(StageBTraceLink::new(0xA203, 203, 0), 203, 8),
        )
    }

    #[test]
    fn audit_finding_byte_width_is_53() {
        assert_eq!(AUDIT_FINDING_BYTES, 53);
    }

    #[test]
    fn severity_and_state_reject_unknown_discriminants() {
        for b in [0u8, 6, 7, 255] {
            assert!(AuditFindingSeverity::from_u8(b).is_none());
        }
        for b in 1u8..=5 {
            assert!(AuditFindingSeverity::from_u8(b).is_some());
        }
        for b in [0u8, 5, 9, 255] {
            assert!(AuditFindingState::from_u8(b).is_none());
        }
        for b in 1u8..=4 {
            assert!(AuditFindingState::from_u8(b).is_some());
        }
    }

    #[test]
    fn critical_open_blocks_mainnet() {
        let f = AuditFinding::new(
            1,
            AuditFindingSeverity::Critical,
            AuditFindingState::Open,
            ev(false),
        );
        assert_eq!(f.verdict(), AuditFindingVerdict::BlocksMainnet);
        assert!(f.blocks_mainnet());
        // A High open finding also blocks.
        let h = AuditFinding::new(
            2,
            AuditFindingSeverity::High,
            AuditFindingState::Open,
            ev(false),
        );
        assert!(h.blocks_mainnet());
        // A Medium/Low/Info open finding does NOT block.
        for sev in [
            AuditFindingSeverity::Medium,
            AuditFindingSeverity::Low,
            AuditFindingSeverity::Info,
        ] {
            let m = AuditFinding::new(3, sev, AuditFindingState::Open, ev(false));
            assert_eq!(m.verdict(), AuditFindingVerdict::Resolved);
            assert!(!m.blocks_mainnet());
        }
    }

    #[test]
    fn high_fixed_requires_evidence() {
        let no_ev = AuditFinding::new(
            10,
            AuditFindingSeverity::High,
            AuditFindingState::Fixed,
            ev(false),
        );
        assert_eq!(no_ev.verdict(), AuditFindingVerdict::EvidenceMissing);
        assert!(no_ev.blocks_mainnet());

        let with_ev = AuditFinding::new(
            10,
            AuditFindingSeverity::High,
            AuditFindingState::Fixed,
            ev(true),
        );
        assert_eq!(with_ev.verdict(), AuditFindingVerdict::Resolved);
        assert!(!with_ev.blocks_mainnet());
    }

    #[test]
    fn accepted_risk_requires_signed_ref() {
        let no_ref = AuditFinding::new(
            20,
            AuditFindingSeverity::Medium,
            AuditFindingState::AcceptedRisk,
            ev(false),
        );
        assert_eq!(no_ref.verdict(), AuditFindingVerdict::EvidenceMissing);
        assert!(no_ref.blocks_mainnet());

        let signed = AuditFinding::new(
            20,
            AuditFindingSeverity::Medium,
            AuditFindingState::AcceptedRisk,
            ev(true),
        );
        assert_eq!(signed.verdict(), AuditFindingVerdict::Resolved);
        assert!(!signed.blocks_mainnet());
    }

    #[test]
    fn audit_resolved_is_true_only_when_nothing_blocks() {
        let blocking = AuditFinding::new(
            1,
            AuditFindingSeverity::Critical,
            AuditFindingState::Open,
            ev(false),
        );
        let clean = AuditFinding::new(
            2,
            AuditFindingSeverity::High,
            AuditFindingState::Fixed,
            ev(true),
        );
        let false_pos = AuditFinding::new(
            3,
            AuditFindingSeverity::Critical,
            AuditFindingState::FalsePositive,
            ev(false),
        );
        assert!(audit_resolved(&[]));
        assert!(audit_resolved(&[clean, false_pos]));
        assert!(!audit_resolved(&[clean, blocking]));
    }

    #[test]
    fn audit_finding_roundtrips_through_bytes() {
        let f = AuditFinding::new(
            0xDEAD_BEEF,
            AuditFindingSeverity::High,
            AuditFindingState::AcceptedRisk,
            ev(true),
        );
        let bytes = f.to_bytes();
        assert_eq!(bytes.len(), AUDIT_FINDING_BYTES);
        assert_eq!(AuditFinding::from_bytes(&bytes), Some(f));
    }

    #[test]
    fn from_bytes_rejects_unknown_discriminants() {
        let f = AuditFinding::new(
            1,
            AuditFindingSeverity::Low,
            AuditFindingState::Open,
            ev(true),
        );
        let mut bad_sev = f.to_bytes();
        bad_sev[4] = 9;
        assert!(AuditFinding::from_bytes(&bad_sev).is_none());
        let mut bad_state = f.to_bytes();
        bad_state[5] = 9;
        assert!(AuditFinding::from_bytes(&bad_state).is_none());
    }
}
