//! `mnemos-k-devex` — developer-experience tooling and the Prometheus metrics exporter.
//!
//! Phase 0 K-stage. Atom #49 (K.0.4) lands the Prometheus text exposition
//! surface — `metrics::Metric` (`#[repr(u8)]` 7-axis enum) and
//! `metrics::MetricsExporter` (fixed `[AtomicU64; 7]`, heap 0, no label
//! dimension by construction so secret exposure is 0). Other K-stage atoms
//! (K.0.1 CI, K.0.2 systemd, K.0.3 bootstrap, K.0.5 runbook) are
//! configuration/scripts/docs and so do not contribute Rust types — they live
//! outside this crate root per `MNEMOS_ATOM_PLAN.md` §4.K.
#![deny(missing_docs)]

pub mod metrics;
pub mod stage_c_audit;
// Stage C WorkPackage C-WP-07 (atoms #234–#236): mainnet ceremony transcript
// builder, burn-in window, and read-only canary monitor. Hash-addressed
// transcript + monitoring state — no signer, no submitter, no write authority.
// Reuses #204 `MainnetChecklist`, #225 `MainnetPackageLock` (d-move), and the
// atom #49 `MetricsExporter`. The atom #214 signer-envelope digest is consumed
// as a value (no `k-devex -> g-wallet` edge); the cross-type binding is proven
// in `o-stage-c-e2e`. `MainnetExecutionState` stays `Locked`.
pub mod stage_c_burn_in;
pub mod stage_c_canary_monitor;
pub mod stage_c_ceremony;
pub mod stage_c_checklist;
pub mod stage_c_evidence;
pub mod stage_c_gas_jsonl;
// Stage C WorkPackage C-WP-08 (atoms #237–#238): the incident-pause / rollback
// gate and the mainnet gate approval-wait receipt. Withholding-only state — the
// pause blocks the sponsor decision and the ceremony path before any signer
// boundary, and the gate receipt caps at `ApprovalPending` (never `Executed`).
// Reuses #235 `BurnInWindow`, #234 `CeremonyTranscript`, #204 `MainnetChecklist`
// (same crate), and #225 `MainnetPackageLock` + #173 `MainnetExecutionState`
// (d-move / a-core, existing edges). No `k-devex -> g-wallet` edge: the sponsor
// decision (#218) is consumed as a `bool`, bound in `o-stage-c-e2e`.
pub mod stage_c_mainnet_gate;
pub mod stage_c_pause;
// atom #294 · D.2.18 (D-WP-03C): the Stage D skill-registry / install gas trace
// + Gas Station allowlist extension. UNLIKE the Stage C atoms above (which
// avoided a `k-devex -> g-wallet` edge by consuming the sponsor decision as a
// `bool` and binding it in `o-stage-c-e2e`), this atom needs a TYPED eight-action
// allowlist evaluator over the C `GasStationPolicy`, so it takes direct, ACYCLIC
// `k-devex -> g-wallet` and `k-devex -> e-skill` edges (neither crate's closure
// depends on k-devex). Reuse is types only — no signer, no wallet, no secret, no
// network, no chain action. Offline / read-only; mainnet locked.
pub mod stage_d_gas_trace;

pub use metrics::{METRIC_AXES, Metric, MetricsExporter};
pub use stage_c_audit::{
    AUDIT_FINDING_BYTES, AuditFinding, AuditFindingSeverity, AuditFindingState,
    AuditFindingVerdict, audit_resolved,
};
pub use stage_c_burn_in::{BurnInError, BurnInWindow, parse_duration_secs};
pub use stage_c_canary_monitor::{CanaryAnomaly, CanaryInputs, CanaryMonitor, CanaryStatus};
pub use stage_c_ceremony::{CEREMONY_PREIMAGE_BYTES, CeremonyError, CeremonyTranscript};
pub use stage_c_checklist::{MAINNET_CHECKLIST_BYTES, MainnetChecklist, MainnetChecklistStep};
pub use stage_c_evidence::{STAGE_C_EVIDENCE_REF_BYTES, StageCEvidenceCheck, StageCEvidenceRef};
pub use stage_c_gas_jsonl::{
    STAGE_C_GAS_TRACE_KEYS, STAGE_C_GAS_TRACE_SCHEMA, build_gas_trace_line,
};
pub use stage_c_mainnet_gate::MainnetGateReceipt;
pub use stage_c_pause::{CeremonyGuardError, IncidentPause, PauseError, PauseReason};
pub use stage_d_gas_trace::{
    SKILL_GAS_ACTION_COUNT, STAGE_D_SKILL_GAS_TRACE_KEYS, STAGE_D_SKILL_GAS_TRACE_SCHEMA,
    SkillGasBaseline, SkillGasTraceRecord, SkillSponsorshipRequest, build_skill_gas_trace_line,
    evaluate_skill_sponsorship,
};
