//! §4.3 cockpit inspector pane (atom #425 F.2.8).
//!
//! The inspector explains *why* a gate is red / yellow / green and always backs
//! the verdict with an evidence path — never a bare status. An evidence-backed
//! hint carries its tier, source atom, evidence hash, memory root, expiry,
//! scope, and redaction class; a hint that is only prompt-asserted or stale
//! renders `Red`. A view cannot even be constructed without a non-zero evidence
//! reference and reason, so a bare status is structurally impossible.
//!
//! Reuses the §4.0 [`StageFEvidenceRef`] / [`StageFTraceLink`] evidence seam
//! (B/C/D/E evidence refs project into it) and the [`RenderTruth`] enum. Pure
//! projection; cached state only (no I/O on the hot path).

use crate::StageFEvidenceRef;
use crate::tui::RenderTruth;

const ZERO32: [u8; 32] = [0u8; 32];

/// §4.3 — what the inspector is focused on.
#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum InspectTarget {
    /// A command trace.
    Trace = 1,
    /// A memory hit.
    Memory = 2,
    /// A skill (provenance / trust).
    Skill = 3,
    /// A tool invocation.
    Tool = 4,
    /// A web source / citation.
    WebSource = 5,
    /// A gas quota / sponsor state.
    Gas = 6,
    /// A safety / security attestation.
    Security = 7,
}

impl InspectTarget {
    /// A short colorless label.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Trace => "trace",
            Self::Memory => "memory",
            Self::Skill => "skill",
            Self::Tool => "tool",
            Self::WebSource => "web-source",
            Self::Gas => "gas",
            Self::Security => "security",
        }
    }
}

/// §4.3 — the evidential tier of a hint. Prompt-only and stale tiers are never
/// healthy (the no-bare-status / no-prompt-only-green law).
#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HintTier {
    /// Backed by reproducible evidence (a test / proof / receipt).
    Proven = 1,
    /// A cached projection of evidence (still backed, but not freshly proven).
    Cached = 2,
    /// Asserted only by a prompt / model output (never trustworthy alone).
    PromptOnly = 3,
    /// Previously proven but now expired.
    Stale = 4,
}

/// §4.3 — an evidence-backed hint. Every field the inspector promises is present
/// so a verdict is never bare.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EvidenceHint {
    /// Evidential tier.
    pub tier: HintTier,
    /// Source atom that produced the evidence (#0..#480).
    pub source_atom_u16: u16,
    /// SHA-256 of the evidence artifact.
    pub evidence_hash_32: [u8; 32],
    /// SHA-256 of the memory root the evidence anchors to.
    pub memory_root_32: [u8; 32],
    /// Expiry epoch (ms); `0` means non-expiring.
    pub expires_at_epoch_ms: u64,
    /// SHA-256 of the scope the hint applies to.
    pub scope_hash_32: [u8; 32],
    /// Redaction class tag (mirrors `a-core` `LogRedactionKind` discriminants).
    pub redaction_class_u8: u8,
}

impl EvidenceHint {
    /// Whether the hint carries an evidence artifact.
    #[must_use]
    pub fn has_evidence(&self) -> bool {
        self.evidence_hash_32 != ZERO32
    }

    /// Whether the hint has expired at `now_epoch_ms` (a non-zero expiry in the
    /// past).
    #[must_use]
    pub const fn is_stale(&self, now_epoch_ms: u64) -> bool {
        self.expires_at_epoch_ms != 0 && now_epoch_ms >= self.expires_at_epoch_ms
    }

    /// The render truth of the hint at `now_epoch_ms`. Prompt-only, stale, or
    /// evidence-less hints are `Red`; cached is `Yellow`; only fresh proven
    /// evidence is `Green`.
    #[must_use]
    pub fn truth(&self, now_epoch_ms: u64) -> RenderTruth {
        if !self.has_evidence() || self.is_stale(now_epoch_ms) {
            return RenderTruth::Red;
        }
        match self.tier {
            HintTier::PromptOnly | HintTier::Stale => RenderTruth::Red,
            HintTier::Cached => RenderTruth::Yellow,
            HintTier::Proven => RenderTruth::Green,
        }
    }
}

/// §4.3 — the inspector view for a selected target. Always carries an evidence
/// path + reason (constructed via [`InspectorView::new`], which rejects a bare
/// status).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct InspectorView {
    /// What is being inspected.
    pub target: InspectTarget,
    /// The evidence reference backing the verdict (path + trace/gate/atom).
    pub evidence: StageFEvidenceRef,
    /// The evidence-backed hint.
    pub hint: EvidenceHint,
    /// SHA-256 of the human-readable reason.
    pub reason_hash_32: [u8; 32],
}

impl InspectorView {
    /// Build an inspector view. Returns `None` (a bare status is rejected) if the
    /// evidence path hash or the reason hash is zero — the inspector never shows
    /// a verdict without an evidence path.
    #[must_use]
    pub fn new(
        target: InspectTarget,
        evidence: StageFEvidenceRef,
        hint: EvidenceHint,
        reason_hash_32: [u8; 32],
    ) -> Option<Self> {
        if evidence.path_hash_32 == ZERO32 || reason_hash_32 == ZERO32 {
            return None;
        }
        Some(Self {
            target,
            evidence,
            hint,
            reason_hash_32,
        })
    }

    /// The verdict truth at `now_epoch_ms`. Derived from the hint; the evidence
    /// path is guaranteed present by construction.
    #[must_use]
    pub fn truth(&self, now_epoch_ms: u64) -> RenderTruth {
        self.hint.truth(now_epoch_ms)
    }

    /// The gate id this verdict explains (from the evidence trace link).
    #[must_use]
    pub const fn gate_id(&self) -> u16 {
        self.evidence.trace.gate_id_u16
    }

    /// A short colorless verdict label.
    const fn truth_label(truth: RenderTruth) -> &'static str {
        match truth {
            RenderTruth::Green => "green",
            RenderTruth::Yellow => "yellow",
            RenderTruth::Red => "red",
            RenderTruth::Unknown => "unknown",
        }
    }

    /// A one-line explanation: target, verdict, gate, tier, source atom, scope,
    /// redaction class, expiry, and the evidence path hash. Never a bare status.
    #[must_use]
    pub fn explain(&self, now_epoch_ms: u64) -> String {
        format!(
            "{target}: {verdict} gate={gate} tier={tier:?} src_atom=#{atom} \
             evidence={ev} memory_root={mem} scope={scope} redaction={red} expiry={exp}",
            target = self.target.label(),
            verdict = Self::truth_label(self.truth(now_epoch_ms)),
            gate = self.gate_id(),
            tier = self.hint.tier,
            atom = self.hint.source_atom_u16,
            ev = hex8(&self.evidence.path_hash_32),
            mem = hex8(&self.hint.memory_root_32),
            scope = hex8(&self.hint.scope_hash_32),
            red = self.hint.redaction_class_u8,
            exp = self.hint.expires_at_epoch_ms,
        )
    }

    /// Render the inspector as bounded colorless lines.
    #[must_use]
    pub fn render(&self, now_epoch_ms: u64, rows: u16) -> Vec<String> {
        self.explain(now_epoch_ms)
            .split(' ')
            .collect::<Vec<_>>()
            .chunks(4)
            .map(|c| c.join(" "))
            .take(rows as usize)
            .collect()
    }
}

/// First 8 hex chars of a 32-byte hash.
fn hex8(bytes: &[u8; 32]) -> String {
    crate::hex32(bytes)[..8].to_string()
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;
    use crate::StageFTraceLink;

    fn evidence(gate: u16) -> StageFEvidenceRef {
        StageFEvidenceRef {
            path_hash_32: [0xEE; 32],
            trace: StageFTraceLink::new([7u8; 32], 425, gate),
        }
    }

    fn proven_hint() -> EvidenceHint {
        EvidenceHint {
            tier: HintTier::Proven,
            source_atom_u16: 305,
            evidence_hash_32: [3u8; 32],
            memory_root_32: [4u8; 32],
            expires_at_epoch_ms: 0,
            scope_hash_32: [5u8; 32],
            redaction_class_u8: 6,
        }
    }

    fn view(target: InspectTarget, hint: EvidenceHint) -> InspectorView {
        InspectorView::new(target, evidence(1), hint, [9u8; 32])
            .expect("non-zero evidence + reason")
    }

    #[test]
    fn bare_status_without_evidence_is_rejected() {
        let mut ev = evidence(1);
        ev.path_hash_32 = [0u8; 32];
        assert!(InspectorView::new(InspectTarget::Trace, ev, proven_hint(), [9u8; 32]).is_none());
        // zero reason is also rejected
        assert!(
            InspectorView::new(InspectTarget::Trace, evidence(1), proven_hint(), [0u8; 32])
                .is_none()
        );
    }

    #[test]
    fn trace_inspect_proven_is_green_with_evidence_path() {
        let v = view(InspectTarget::Trace, proven_hint());
        assert_eq!(v.truth(1000), RenderTruth::Green);
        let line = v.explain(1000);
        assert!(line.contains("trace:"));
        assert!(line.contains("evidence="));
        assert!(line.contains("gate=1"));
    }

    #[test]
    fn memory_hit_inspect_carries_memory_root() {
        let v = view(InspectTarget::Memory, proven_hint());
        assert!(v.explain(0).contains("memory_root="));
    }

    #[test]
    fn skill_provenance_inspect_has_scope_and_src_atom() {
        let v = view(InspectTarget::Skill, proven_hint());
        let line = v.explain(0);
        assert!(line.contains("scope="));
        assert!(line.contains("src_atom=#305"));
    }

    #[test]
    fn web_source_and_gas_inspect_render_target() {
        assert!(
            view(InspectTarget::WebSource, proven_hint())
                .explain(0)
                .contains("web-source:")
        );
        assert!(
            view(InspectTarget::Gas, proven_hint())
                .explain(0)
                .contains("gas:")
        );
    }

    #[test]
    fn cached_hint_is_yellow_and_prompt_only_is_red() {
        let mut cached = proven_hint();
        cached.tier = HintTier::Cached;
        assert_eq!(
            view(InspectTarget::Security, cached).truth(0),
            RenderTruth::Yellow
        );

        let mut prompt_only = proven_hint();
        prompt_only.tier = HintTier::PromptOnly;
        assert_eq!(
            view(InspectTarget::Security, prompt_only).truth(0),
            RenderTruth::Red
        );
    }

    #[test]
    fn stale_hint_renders_red() {
        let mut hint = proven_hint();
        hint.expires_at_epoch_ms = 1_000;
        let v = view(InspectTarget::Trace, hint);
        assert_eq!(v.truth(999), RenderTruth::Green, "fresh before expiry");
        assert_eq!(v.truth(1_000), RenderTruth::Red, "stale at/after expiry");
        assert_eq!(v.truth(5_000), RenderTruth::Red);
    }

    #[test]
    fn evidenceless_hint_is_red_even_if_proven_tier() {
        let mut hint = proven_hint();
        hint.evidence_hash_32 = [0u8; 32];
        assert_eq!(view(InspectTarget::Trace, hint).truth(0), RenderTruth::Red);
    }
}
