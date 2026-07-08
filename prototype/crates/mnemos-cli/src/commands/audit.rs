//! Audit trail command.
//!
//! `sinabro audit list` / `audit filter`. The audit trail is the tamper-evident
//! record proving that every *high-significance* action — an approval, a denial,
//! a skill install/remove, a gas action, a wallet signing, a chain write, a
//! `/kill`, or a rollback — left behind a trace id and an evidence hash. The
//! trail is a **read-only projection** over sealed [`AuditEntry`] values; it
//! performs no network / chain / gas / wallet I/O and never renders a false
//! green: an entry whose trace id or evidence hash is missing, or whose sealed
//! content hash no longer matches its fields (tamper), renders
//! [`RenderTruth::Red`].
//!
//! Reuse (no reinvention): the per-action identity ties back to the canonical
//! [`crate::command::CommandRisk`] safety taxonomy; the trace + evidence stamps
//! are the canonical [`crate::StageFTraceLink`] / [`crate::StageFEvidenceRef`];
//! the content seal uses [`crate::sha256_32`]; the verdict is the shared
//! [`crate::tui::RenderTruth`].

use crate::command::CommandRisk;
use crate::tui::RenderTruth;
use crate::{StageFEvidenceRef, StageFTraceLink, sha256_32};

/// The closed set of high-significance actions the audit trail must capture.
/// Every variant carries a trace id + evidence hash.
#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AuditAction {
    /// An approval was granted.
    Approval = 1,
    /// A command was denied (fail-closed).
    Denial = 2,
    /// A skill was installed.
    SkillInstall = 3,
    /// A skill was removed.
    SkillRemove = 4,
    /// A gas action (request / quota / drain gate).
    GasAction = 5,
    /// A wallet signing preview / action.
    Signing = 6,
    /// An on-chain write.
    ChainWrite = 7,
    /// A `/kill` express interrupt.
    Kill = 8,
    /// A checkpoint rollback / undo.
    Rollback = 9,
}

impl AuditAction {
    /// The stable `u8` discriminant.
    #[must_use]
    pub const fn as_u8(self) -> u8 {
        self as u8
    }

    /// Decode a stable `u8` discriminant back to an action (the persisted-log
    /// reload path). An out-of-range byte is refused (fail-closed) so a
    /// corrupt on-disk record can never silently decode to a wrong class.
    #[must_use]
    pub const fn from_u8(byte: u8) -> Option<Self> {
        match byte {
            1 => Some(Self::Approval),
            2 => Some(Self::Denial),
            3 => Some(Self::SkillInstall),
            4 => Some(Self::SkillRemove),
            5 => Some(Self::GasAction),
            6 => Some(Self::Signing),
            7 => Some(Self::ChainWrite),
            8 => Some(Self::Kill),
            9 => Some(Self::Rollback),
            _ => None,
        }
    }

    /// The canonical command-risk class this audited action belongs to. Ties the
    /// audit taxonomy back to the single [`CommandRisk`] safety kernel rather than
    /// re-minting a parallel one.
    #[must_use]
    pub const fn risk(self) -> CommandRisk {
        match self {
            Self::Approval | Self::Denial | Self::Kill => CommandRisk::Admin,
            Self::SkillInstall | Self::SkillRemove | Self::Rollback => CommandRisk::LocalWrite,
            Self::GasAction => CommandRisk::Network,
            Self::Signing => CommandRisk::WalletSign,
            Self::ChainWrite => CommandRisk::ChainWrite,
        }
    }

    /// A stable lower-case ASCII label (colorless terminals rely on the word).
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Approval => "approval",
            Self::Denial => "denial",
            Self::SkillInstall => "skill_install",
            Self::SkillRemove => "skill_remove",
            Self::GasAction => "gas",
            Self::Signing => "signing",
            Self::ChainWrite => "chain_write",
            Self::Kill => "kill",
            Self::Rollback => "rollback",
        }
    }
}

/// Canonical seal bytes for `(action, trace, evidence)`: a fixed 105-byte layout
/// (action `u8` + the trace + evidence hashes / ids) hashed to detect any later
/// mutation of a sealed entry.
fn seal_bytes(
    action: AuditAction,
    trace: &StageFTraceLink,
    evidence: &StageFEvidenceRef,
) -> [u8; 105] {
    let mut b = [0u8; 105];
    b[0] = action.as_u8();
    b[1..33].copy_from_slice(&trace.command_trace_hash_32);
    b[33..35].copy_from_slice(&trace.stage_f_atom_u16.to_le_bytes());
    b[35..37].copy_from_slice(&trace.gate_id_u16.to_le_bytes());
    b[37..69].copy_from_slice(&evidence.path_hash_32);
    b[69..101].copy_from_slice(&evidence.trace.command_trace_hash_32);
    b[101..103].copy_from_slice(&evidence.trace.stage_f_atom_u16.to_le_bytes());
    b[103..105].copy_from_slice(&evidence.trace.gate_id_u16.to_le_bytes());
    b
}

/// A sealed audit-trail entry: a high-significance [`AuditAction`] bound to its
/// trace link + evidence ref, with a content seal hash over those fields so any
/// later mutation is detectable (tamper-evident).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AuditEntry {
    /// The audited action class.
    pub action: AuditAction,
    /// The trace link (trace-record hash + atom + gate).
    pub trace: StageFTraceLink,
    /// The evidence reference (evidence path hash + its trace link).
    pub evidence: StageFEvidenceRef,
    /// SHA-256 seal over `(action, trace, evidence)`. Recomputed on read to
    /// detect tamper.
    pub seal_hash_32: [u8; 32],
}

impl AuditEntry {
    /// Seal a new audit entry, computing the content hash over its fields.
    #[must_use]
    pub fn seal(action: AuditAction, trace: StageFTraceLink, evidence: StageFEvidenceRef) -> Self {
        let seal_hash_32 = sha256_32(&seal_bytes(action, &trace, &evidence));
        Self {
            action,
            trace,
            evidence,
            seal_hash_32,
        }
    }

    /// The canonical 105-byte seal layout for this entry (the persisted-log
    /// record body). Identical bytes to the content the seal hash covers,
    /// so a reload + re-seal round-trips exactly.
    #[must_use]
    pub fn seal_bytes_105(&self) -> [u8; 105] {
        seal_bytes(self.action, &self.trace, &self.evidence)
    }

    /// Decode a 105-byte seal record back into a sealed entry (the persisted-log
    /// reload path). Refuses an out-of-range action byte (fail-closed); the
    /// seal hash is recomputed so the returned entry is internally consistent.
    #[must_use]
    pub fn decode_seal_bytes(b: &[u8; 105]) -> Option<Self> {
        let action = AuditAction::from_u8(b[0])?;
        let mut tr_hash = [0u8; 32];
        tr_hash.copy_from_slice(&b[1..33]);
        let tr_atom = u16::from_le_bytes([b[33], b[34]]);
        let tr_gate = u16::from_le_bytes([b[35], b[36]]);
        let mut ev_path = [0u8; 32];
        ev_path.copy_from_slice(&b[37..69]);
        let mut ev_tr_hash = [0u8; 32];
        ev_tr_hash.copy_from_slice(&b[69..101]);
        let ev_atom = u16::from_le_bytes([b[101], b[102]]);
        let ev_gate = u16::from_le_bytes([b[103], b[104]]);
        let trace = StageFTraceLink::new(tr_hash, tr_atom, tr_gate);
        let evidence = StageFEvidenceRef {
            path_hash_32: ev_path,
            trace: StageFTraceLink::new(ev_tr_hash, ev_atom, ev_gate),
        };
        Some(Self::seal(action, trace, evidence))
    }

    /// Whether the entry carries both a non-empty trace id and a non-empty
    /// evidence hash (every audited action must). A missing trace renders Red.
    #[must_use]
    pub fn has_trace_and_evidence(&self) -> bool {
        self.trace.command_trace_hash_32 != [0u8; 32] && self.evidence.path_hash_32 != [0u8; 32]
    }

    /// Whether the sealed content hash still matches the fields (no tamper).
    #[must_use]
    pub fn is_tamper_free(&self) -> bool {
        sha256_32(&seal_bytes(self.action, &self.trace, &self.evidence)) == self.seal_hash_32
    }

    /// No-false-green verdict: Red if the trace/evidence is missing or the seal no
    /// longer matches; otherwise Green.
    #[must_use]
    pub fn render_truth(&self) -> RenderTruth {
        if self.has_trace_and_evidence() && self.is_tamper_free() {
            RenderTruth::Green
        } else {
            RenderTruth::Red
        }
    }
}

/// A bounded, read-only audit trail: an ordered list of sealed entries with
/// filter + tamper/missing detection. O(n) projections only (no I/O).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct AuditTrail {
    entries: Vec<AuditEntry>,
}

impl AuditTrail {
    /// An empty trail.
    #[must_use]
    pub fn new() -> Self {
        Self {
            entries: Vec::new(),
        }
    }

    /// Append a sealed entry.
    pub fn push(&mut self, entry: AuditEntry) {
        self.entries.push(entry);
    }

    /// The full ordered trail.
    #[must_use]
    pub fn entries(&self) -> &[AuditEntry] {
        &self.entries
    }

    /// The number of entries.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether the trail is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Filter by action class (bounded O(n)).
    #[must_use]
    pub fn filter_action(&self, action: AuditAction) -> Vec<AuditEntry> {
        self.entries
            .iter()
            .filter(|e| e.action == action)
            .copied()
            .collect()
    }

    /// Filter by atom id (bounded O(n)).
    #[must_use]
    pub fn filter_atom(&self, stage_f_atom_u16: u16) -> Vec<AuditEntry> {
        self.entries
            .iter()
            .filter(|e| e.trace.stage_f_atom_u16 == stage_f_atom_u16)
            .copied()
            .collect()
    }

    /// The count of entries missing a trace id or evidence hash.
    #[must_use]
    pub fn untraced_count(&self) -> usize {
        self.entries
            .iter()
            .filter(|e| !e.has_trace_and_evidence())
            .count()
    }

    /// The count of entries whose seal no longer matches (tamper).
    #[must_use]
    pub fn tamper_count(&self) -> usize {
        self.entries.iter().filter(|e| !e.is_tamper_free()).count()
    }

    /// No-false-green trail verdict: Red if ANY entry is untraced or tampered;
    /// Unknown if the trail is empty (never measured); else Green.
    #[must_use]
    pub fn trail_truth(&self) -> RenderTruth {
        if self.entries.is_empty() {
            RenderTruth::Unknown
        } else if self.untraced_count() > 0 || self.tamper_count() > 0 {
            RenderTruth::Red
        } else {
            RenderTruth::Green
        }
    }

    /// A bounded, colorless, ASCII one-line summary for any terminal (no ANSI, no
    /// color reliance) — used by the accessibility / terminal-compat matrix.
    #[must_use]
    pub fn render_plain(&self) -> String {
        format!(
            "audit entries={} untraced={} tamper={} truth={}",
            self.len(),
            self.untraced_count(),
            self.tamper_count(),
            render_truth_label(self.trail_truth()),
        )
    }
}

/// The stable ASCII label for a render truth. Colorless terminals and screen
/// readers rely on the word, never a color.
#[must_use]
pub const fn render_truth_label(truth: RenderTruth) -> &'static str {
    match truth {
        RenderTruth::Green => "GREEN",
        RenderTruth::Yellow => "YELLOW",
        RenderTruth::Red => "RED",
        RenderTruth::Unknown => "UNKNOWN",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::repl::latency::p95_ms;

    fn trace(atom: u16) -> StageFTraceLink {
        StageFTraceLink::new(sha256_32(&atom.to_le_bytes()), atom, 100)
    }

    fn evidence(atom: u16) -> StageFEvidenceRef {
        StageFEvidenceRef {
            path_hash_32: sha256_32(b"evidence/path"),
            trace: trace(atom),
        }
    }

    #[test]
    fn list_collects_pushed_entries() {
        let mut trail = AuditTrail::new();
        assert!(trail.is_empty());
        trail.push(AuditEntry::seal(
            AuditAction::Kill,
            trace(469),
            evidence(469),
        ));
        trail.push(AuditEntry::seal(
            AuditAction::Rollback,
            trace(470),
            evidence(470),
        ));
        assert_eq!(trail.len(), 2);
        assert_eq!(trail.entries().len(), 2);
    }

    #[test]
    fn filter_by_action_and_atom() {
        let mut trail = AuditTrail::new();
        trail.push(AuditEntry::seal(
            AuditAction::Kill,
            trace(469),
            evidence(469),
        ));
        trail.push(AuditEntry::seal(
            AuditAction::Kill,
            trace(471),
            evidence(471),
        ));
        trail.push(AuditEntry::seal(
            AuditAction::Signing,
            trace(447),
            evidence(447),
        ));
        assert_eq!(trail.filter_action(AuditAction::Kill).len(), 2);
        assert_eq!(trail.filter_action(AuditAction::Signing).len(), 1);
        assert_eq!(trail.filter_atom(471).len(), 1);
        assert_eq!(trail.filter_atom(401).len(), 0);
    }

    #[test]
    fn missing_trace_renders_red() {
        // An entry with a zero trace id + zero evidence hash is untraced -> Red.
        let zero_trace = StageFTraceLink::new([0u8; 32], 472, 100);
        let zero_ev = StageFEvidenceRef {
            path_hash_32: [0u8; 32],
            trace: zero_trace,
        };
        let entry = AuditEntry::seal(AuditAction::ChainWrite, zero_trace, zero_ev);
        assert!(!entry.has_trace_and_evidence());
        assert_eq!(entry.render_truth(), RenderTruth::Red);

        let mut trail = AuditTrail::new();
        trail.push(entry);
        assert_eq!(trail.untraced_count(), 1);
        assert_eq!(trail.trail_truth(), RenderTruth::Red);
    }

    #[test]
    fn tamper_hash_mismatch_is_detected() {
        let mut entry = AuditEntry::seal(AuditAction::Signing, trace(447), evidence(447));
        assert!(entry.is_tamper_free());
        assert_eq!(entry.render_truth(), RenderTruth::Green);
        // Mutate a field after sealing without re-sealing -> the recomputed hash
        // no longer matches the stored seal.
        entry.action = AuditAction::ChainWrite;
        assert!(!entry.is_tamper_free());
        assert_eq!(entry.render_truth(), RenderTruth::Red);

        let mut trail = AuditTrail::new();
        trail.push(entry);
        assert_eq!(trail.tamper_count(), 1);
        assert_eq!(trail.trail_truth(), RenderTruth::Red);
    }

    #[test]
    fn empty_trail_is_unknown_not_green() {
        let trail = AuditTrail::new();
        assert_eq!(trail.trail_truth(), RenderTruth::Unknown);
        assert!(!trail.trail_truth().is_healthy());
    }

    #[test]
    fn action_risk_maps_to_canonical_kernel() {
        assert_eq!(AuditAction::Signing.risk(), CommandRisk::WalletSign);
        assert_eq!(AuditAction::ChainWrite.risk(), CommandRisk::ChainWrite);
        assert_eq!(AuditAction::GasAction.risk(), CommandRisk::Network);
        assert_eq!(AuditAction::Kill.risk(), CommandRisk::Admin);
        assert_eq!(AuditAction::Rollback.risk(), CommandRisk::LocalWrite);
    }

    #[test]
    fn render_plain_is_colorless_ascii_and_bounded() {
        let mut trail = AuditTrail::new();
        trail.push(AuditEntry::seal(
            AuditAction::Kill,
            trace(469),
            evidence(469),
        ));
        let line = trail.render_plain();
        assert!(line.is_ascii(), "plain render must be ASCII");
        assert!(!line.contains('\u{1b}'), "no ANSI escape");
        assert!(line.len() <= 60, "fits a 60-col terminal: {}", line.len());
        assert!(line.contains("truth=GREEN"));
    }

    #[test]
    fn filter_10k_p95_within_250ms() {
        let mut trail = AuditTrail::new();
        for i in 0..10_000u32 {
            let atom = 401 + (i % 80) as u16;
            let action = match i % 9 {
                0 => AuditAction::Approval,
                1 => AuditAction::Denial,
                2 => AuditAction::SkillInstall,
                3 => AuditAction::SkillRemove,
                4 => AuditAction::GasAction,
                5 => AuditAction::Signing,
                6 => AuditAction::ChainWrite,
                7 => AuditAction::Kill,
                _ => AuditAction::Rollback,
            };
            let tr = StageFTraceLink::new(sha256_32(&i.to_le_bytes()), atom, 100);
            let ev = StageFEvidenceRef {
                path_hash_32: sha256_32(&atom.to_le_bytes()),
                trace: tr,
            };
            trail.push(AuditEntry::seal(action, tr, ev));
        }
        assert_eq!(trail.len(), 10_000);
        let mut samples = Vec::with_capacity(64);
        for _ in 0..64 {
            let t = std::time::Instant::now();
            let got = trail.filter_action(AuditAction::Kill);
            std::hint::black_box(&got);
            samples.push(t.elapsed().as_nanos() as u64);
        }
        let p95 = p95_ms(&samples) / 1_000_000;
        assert!(p95 <= 250, "audit 10k filter p95 {p95}ms exceeds 250ms");
        // The trail is internally consistent (every entry sealed + traced).
        assert_eq!(trail.trail_truth(), RenderTruth::Green);
    }
}
