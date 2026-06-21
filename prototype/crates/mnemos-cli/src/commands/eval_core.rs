//! `sinabro eval` (rust/move/prover/kani/lean/gas) + `eval ab` + `audit`
//! detector routing — core eval command group (F-WP-06B, atom #457 · F.6.6).
//!
//! Eval commands emit a reproducible command, an env lock, and an evidence hash;
//! a **false pass is red** (a claimed pass with no evidence is refused).
//! `eval ab` compares paired manifests (token/cost/pass) and never promotes on an
//! evidence mismatch. `audit status/scan/explain/repro-plan/watch/export-diet` is
//! **local-only source analysis**: it emits candidate findings (rule id, location,
//! affected invariant, evidence hash, confidence, safe local repro plan) and must
//! never run production RPC, live tx, production fuzzing, or DoS-like probes. A
//! pattern-only candidate cannot become a high-reward finding until a local
//! reproducer/proof verifies the affected invariant.
//!
//! Reuse (no reinvention): the gas harness is the Stage C
//! [`mnemos_d_move::stage_c_gas_trace::GasTraceSample`] +
//! [`mnemos_d_move::stage_c_gas_baseline`] (`GasTraceBaseline` /
//! `classify_gas_regression`); a confirmed candidate routes into the canonical
//! Stage E [`AuditFinding`]. The atom's "A/E MeasureTrace" reuse names no on-disk
//! type (verified absent) — the local [`EvalRunView`] is its grounded stand-in.
//! This module performs no live action.

use crate::hex32;
use crate::tui::RenderTruth;
use mnemos_d_move::stage_c_gas_baseline::{
    GasRegressionDecision, GasTraceBaseline, classify_gas_regression,
};
use mnemos_d_move::stage_c_gas_trace::GasTraceSample;
use mnemos_l_dataset::AtomDietKey;
use mnemos_l_dataset::security::audit_finding::{AuditFinding, FindingStatus};
use mnemos_l_dataset::security::source::SecuritySeverity;

/// First 16 hex characters of a 32-byte hash — a redacted, display-only prefix.
#[must_use]
fn redact16(bytes: &[u8; 32]) -> String {
    hex32(bytes).chars().take(16).collect()
}

/// Why an eval / audit command was refused (fail-closed).
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum EvalReject {
    /// A pass was claimed with no evidence (a false pass), or a candidate lacks
    /// the evidence to become a finding.
    #[error("evidence mismatch")]
    EvidenceMismatch,
    /// The audit detector must not run production RPC.
    #[error("production RPC denied")]
    ProductionRpcDenied,
    /// The audit detector must not run a live transaction.
    #[error("live tx denied")]
    LiveTxDenied,
}

/// The eval families the core command group runs.
#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EvalKind {
    /// Rust test/build eval.
    Rust = 1,
    /// Move build/test eval.
    Move = 2,
    /// Sui prover eval.
    Prover = 3,
    /// Kani model-checking eval.
    Kani = 4,
    /// Lean proof eval.
    Lean = 5,
    /// Gas-budget eval.
    Gas = 6,
}

impl EvalKind {
    /// Stable u8 discriminant.
    #[must_use]
    pub const fn as_u8(self) -> u8 {
        self as u8
    }
}

/// A single eval run projection: the family, whether it passed, and the
/// reproducible command / env-lock / evidence hashes that back the verdict.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EvalRunView {
    /// The eval family.
    pub kind: EvalKind,
    /// Whether the eval passed.
    pub passed: bool,
    /// `sha256` of the reproducible command.
    pub command_hash_32: [u8; 32],
    /// `sha256` of the env lock.
    pub env_lock_hash_32: [u8; 32],
    /// `sha256` of the recorded evidence.
    pub evidence_hash_32: [u8; 32],
}

impl EvalRunView {
    /// Record an eval run. A claimed pass with no evidence is a **false pass** and
    /// is refused ([`EvalReject::EvidenceMismatch`]).
    pub fn record(
        kind: EvalKind,
        passed: bool,
        command_hash_32: [u8; 32],
        env_lock_hash_32: [u8; 32],
        evidence_hash_32: [u8; 32],
    ) -> Result<Self, EvalReject> {
        if passed && evidence_hash_32 == [0u8; 32] {
            return Err(EvalReject::EvidenceMismatch);
        }
        Ok(Self {
            kind,
            passed,
            command_hash_32,
            env_lock_hash_32,
            evidence_hash_32,
        })
    }

    /// Whether the run is reproducible (non-zero command + env-lock hashes).
    #[must_use]
    pub fn reproducible(&self) -> bool {
        self.command_hash_32 != [0u8; 32] && self.env_lock_hash_32 != [0u8; 32]
    }

    /// Render truth: a passing run is `Green`, a failing run is `Red`. (A recorded
    /// pass always carries evidence — a false pass cannot be recorded.)
    #[must_use]
    pub fn render_truth(&self) -> RenderTruth {
        if self.passed {
            RenderTruth::Green
        } else {
            RenderTruth::Red
        }
    }

    /// Redacted, colorless run lines bounded by `rows`.
    #[must_use]
    pub fn render(&self, rows: u16) -> Vec<String> {
        let lines = vec![
            format!("eval_kind_u8={}", self.kind.as_u8()),
            format!("passed={}", self.passed),
            format!("command={}", redact16(&self.command_hash_32)),
            format!("env_lock={}", redact16(&self.env_lock_hash_32)),
            format!("evidence={}", redact16(&self.evidence_hash_32)),
            format!("reproducible={}", self.reproducible()),
            format!("truth_u8={}", self.render_truth() as u8),
        ];
        lines.into_iter().take(rows as usize).collect()
    }
}

/// Map a Stage C gas regression verdict onto the cockpit render truth (reuse of
/// the canonical [`classify_gas_regression`] gas harness).
#[must_use]
pub fn gas_cap(sample: &GasTraceSample, baseline: &GasTraceBaseline) -> RenderTruth {
    match classify_gas_regression(sample, baseline) {
        GasRegressionDecision::Green => RenderTruth::Green,
        GasRegressionDecision::Warn => RenderTruth::Yellow,
        GasRegressionDecision::Red => RenderTruth::Red,
    }
}

/// Which arm of an A/B eval a feature lands in.
#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AbArm {
    /// The baseline arm.
    Baseline = 1,
    /// The candidate arm.
    Candidate = 2,
}

/// Deterministically assign a feature to an A/B arm by the parity of its hash —
/// the same feature hash always lands in the same arm.
#[must_use]
pub fn ab_assignment(feature_hash_32: &[u8; 32]) -> AbArm {
    if feature_hash_32[0] & 1 == 0 {
        AbArm::Baseline
    } else {
        AbArm::Candidate
    }
}

/// The result of an A/B eval comparison.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AbDecision {
    /// candidate − baseline token delta (negative is an improvement).
    pub token_delta_i64: i64,
    /// candidate − baseline cost delta in micro-units (negative is an improvement).
    pub cost_delta_micro_i64: i64,
    /// Whether the candidate passed.
    pub candidate_passed: bool,
    /// Whether the baseline passed.
    pub baseline_passed: bool,
    /// Whether the evidence is consistent across the pair.
    pub evidence_consistent: bool,
    /// Whether the candidate may be promoted.
    pub promote: bool,
}

/// Compare a baseline and a candidate eval run with their token/cost measurements.
/// A promotion needs consistent evidence, both runs passing, and a candidate that
/// is no worse on tokens and cost. An evidence mismatch never promotes.
#[must_use]
pub fn compare(
    baseline: &EvalRunView,
    candidate: &EvalRunView,
    baseline_tokens_u64: u64,
    candidate_tokens_u64: u64,
    baseline_cost_micro_u64: u64,
    candidate_cost_micro_u64: u64,
) -> AbDecision {
    let evidence_consistent = candidate.evidence_hash_32 != [0u8; 32]
        && candidate.evidence_hash_32 != baseline.evidence_hash_32;
    let token_delta_i64 = i64::try_from(candidate_tokens_u64)
        .unwrap_or(i64::MAX)
        .saturating_sub(i64::try_from(baseline_tokens_u64).unwrap_or(i64::MAX));
    let cost_delta_micro_i64 = i64::try_from(candidate_cost_micro_u64)
        .unwrap_or(i64::MAX)
        .saturating_sub(i64::try_from(baseline_cost_micro_u64).unwrap_or(i64::MAX));
    let promote = evidence_consistent
        && baseline.passed
        && candidate.passed
        && token_delta_i64 <= 0
        && cost_delta_micro_i64 <= 0;
    AbDecision {
        token_delta_i64,
        cost_delta_micro_i64,
        candidate_passed: candidate.passed,
        baseline_passed: baseline.passed,
        evidence_consistent,
        promote,
    }
}

/// A G-WP-09 B/C performance feature that must pass a paired A/B comparison before
/// it becomes a stable path. The baseline arm is always the feature OFF (the
/// control); the candidate arm is the feature ON.
#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PromotableFeature {
    /// Cache-safe token compression (#612).
    TokenCompress = 1,
    /// Prompt prefix cache (#611 / #615).
    PrefixCache = 2,
    /// Speculative draft/verify decoding (#616).
    Speculative = 3,
    /// Quantized KV-cache mode (#614 / #620).
    KvMode = 4,
    /// Route-FSM steering (#599 / #600).
    RouteFsm = 5,
}

impl PromotableFeature {
    /// Every promotable feature, in discriminant order.
    pub const ALL: [PromotableFeature; 5] = [
        Self::TokenCompress,
        Self::PrefixCache,
        Self::Speculative,
        Self::KvMode,
        Self::RouteFsm,
    ];

    /// The stable `u8` discriminant.
    #[must_use]
    pub const fn as_u8(self) -> u8 {
        self as u8
    }

    /// The exact `--feature` CLI token for this feature.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::TokenCompress => "token_compress",
            Self::PrefixCache => "prefix_cache",
            Self::Speculative => "speculative",
            Self::KvMode => "kv_mode",
            Self::RouteFsm => "route_fsm",
        }
    }

    /// SHA-256 of the feature's CLI label — the deterministic A/B assignment key
    /// (`ab_assignment`). The baseline arm is the feature off.
    #[must_use]
    pub fn feature_hash_32(self) -> [u8; 32] {
        crate::sha256_32(self.label().as_bytes())
    }
}

/// The full 7-metric A/B verdict for a promotable feature: the canonical
/// token / cost / pass / evidence-mismatch comparison ([`AbDecision`]) plus the
/// latency, cache-hit, and quality deltas. A feature becomes a STABLE path ONLY
/// when every metric is green ([`Self::is_stable_promotion`]) — no stable path
/// without a paired A/B green, and the baseline arm is the feature off.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FeatureAbVerdict {
    /// Which feature the A/B compared.
    pub feature: PromotableFeature,
    /// The canonical token / cost / pass / evidence decision.
    pub decision: AbDecision,
    /// candidate − baseline latency delta (ms); negative is faster.
    pub latency_delta_ms_i64: i64,
    /// candidate − baseline cache-hit delta (bps); positive is a better hit-rate.
    pub cache_hit_delta_bps_i32: i32,
    /// Whether output quality regressed on the candidate arm.
    pub quality_regressed: bool,
}

impl FeatureAbVerdict {
    /// Whether this A/B verdict promotes the feature to a STABLE path. Requires all
    /// 7 metrics green: the canonical decision promotes (consistent evidence + both
    /// arms passed + no token or cost regression), latency is no worse, the cache
    /// hit-rate is no worse, and quality did not regress. Otherwise the feature
    /// stays a B/C candidate — never silently stable.
    #[must_use]
    pub fn is_stable_promotion(self) -> bool {
        self.decision.promote
            && self.latency_delta_ms_i64 <= 0
            && self.cache_hit_delta_bps_i32 >= 0
            && !self.quality_regressed
    }
}

/// The local-only audit source-analysis profiles.
#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AuditProfile {
    /// Rust source.
    Rust = 1,
    /// Move source.
    Move = 2,
    /// Sui source.
    SuiSource = 3,
    /// Solana source.
    SolanaSource = 4,
    /// Finance logic.
    Finance = 5,
    /// Storage logic.
    Storage = 6,
}

impl AuditProfile {
    /// Stable u8 discriminant.
    #[must_use]
    pub const fn as_u8(self) -> u8 {
        self as u8
    }
}

/// A local audit candidate finding (advisory until a local reproducer verifies it).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AuditCandidate {
    /// `sha256` of the rule id.
    pub rule_id_hash_32: [u8; 32],
    /// `sha256` of the source location.
    pub location_hash_32: [u8; 32],
    /// `sha256` of the affected invariant.
    pub invariant_hash_32: [u8; 32],
    /// `sha256` of the local evidence.
    pub evidence_hash_32: [u8; 32],
    /// Confidence in basis points (0..=10000).
    pub confidence_bps_u16: u16,
    /// Whether the repro plan is safe + local-only.
    pub repro_plan_safe_local: bool,
    /// Whether a local reproducer/proof backs the candidate.
    pub local_repro_done: bool,
}

impl AuditCandidate {
    /// Whether the candidate carries every required field (non-zero hashes and a
    /// bounded confidence).
    #[must_use]
    pub fn fields_complete(&self) -> bool {
        self.rule_id_hash_32 != [0u8; 32]
            && self.location_hash_32 != [0u8; 32]
            && self.invariant_hash_32 != [0u8; 32]
            && self.evidence_hash_32 != [0u8; 32]
            && self.confidence_bps_u16 <= 10000
    }

    /// Whether the candidate may become a high-reward finding: it must be field
    /// complete, have a safe local repro plan, and be locally reproduced. A
    /// pattern-only (unreproduced) candidate is never high-reward.
    #[must_use]
    pub fn high_reward_allowed(&self) -> bool {
        self.fields_complete() && self.repro_plan_safe_local && self.local_repro_done
    }
}

/// A local-only audit scan projection.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AuditScanView {
    /// The scanned profile.
    pub profile: AuditProfile,
    /// Whether the scan was changed-only.
    pub changed_only: bool,
    /// The candidate count.
    pub candidate_count_u32: u32,
}

impl AuditScanView {
    /// Run a local-only audit scan over already-collected candidates (the scan is
    /// pure source analysis — it performs no live call).
    #[must_use]
    pub fn scan(profile: AuditProfile, changed_only: bool, candidates: &[AuditCandidate]) -> Self {
        Self {
            profile,
            changed_only,
            candidate_count_u32: u32::try_from(candidates.len()).unwrap_or(u32::MAX),
        }
    }

    /// The audit detector is local-only — always `true`.
    #[must_use]
    pub const fn is_local_only(&self) -> bool {
        true
    }

    /// The scan made no live call — always `true` (status is cached/local).
    #[must_use]
    pub const fn made_no_live_call(&self) -> bool {
        true
    }

    /// Production RPC is denied to the audit detector.
    pub const fn try_production_rpc() -> Result<(), EvalReject> {
        Err(EvalReject::ProductionRpcDenied)
    }

    /// A live transaction is denied to the audit detector.
    pub const fn try_live_tx() -> Result<(), EvalReject> {
        Err(EvalReject::LiveTxDenied)
    }
}

/// Route a *locally reproduced* candidate into a canonical Stage E
/// [`AuditFinding`]. A pattern-only / unreproduced candidate is refused
/// ([`EvalReject::EvidenceMismatch`]) — it can never become a finding.
pub fn route_to_finding(
    candidate: &AuditCandidate,
    key: AtomDietKey,
    severity: SecuritySeverity,
) -> Result<AuditFinding, EvalReject> {
    if !candidate.high_reward_allowed() {
        return Err(EvalReject::EvidenceMismatch);
    }
    Ok(AuditFinding {
        key,
        severity,
        status: FindingStatus::Open,
        finding_hash_32: candidate.rule_id_hash_32,
        evidence_present: true,
    })
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    #![allow(clippy::expect_used)]
    #![allow(clippy::panic)]

    use super::*;
    use mnemos_a_core::{StageBTraceLink, StageCTraceLink};
    use mnemos_d_move::stage_c_gas_trace::GasTraceFunction;
    use mnemos_d_move::{GasBudgetMist, ObjectId};
    use mnemos_l_dataset::AtomDietKey;
    use mnemos_l_dataset::diet_kind::DietSourceStage;

    const COMMERCE_TOKENS: &[&str] = &[
        "price", "pay", "buy", "sell", "checkout", "refund", "fee", "cost", "$",
    ];

    fn pass(kind: EvalKind) -> EvalRunView {
        EvalRunView::record(kind, true, [1u8; 32], [2u8; 32], [3u8; 32]).unwrap()
    }

    fn fail(kind: EvalKind) -> EvalRunView {
        EvalRunView::record(kind, false, [1u8; 32], [2u8; 32], [0u8; 32]).unwrap()
    }

    fn add_chunk_sample(computation: u64) -> GasTraceSample {
        GasTraceSample {
            function: GasTraceFunction::MemoryAddChunk,
            package: ObjectId::new([0x01; 32]),
            gas_budget: GasBudgetMist::new(1_000_000),
            computation_mist_u64: computation,
            storage_mist_u64: 50_000,
            rebate_mist_u64: 0,
            object_writes_u16: 1,
            event_bytes_u32: 0,
            tx_bytes_u32: 200,
            trace: StageCTraceLink::new(StageBTraceLink::new(0xABCD, 250, 0), 250, 5),
        }
    }

    fn baseline() -> GasTraceBaseline {
        GasTraceBaseline {
            package: ObjectId::new([0x01; 32]),
            add_chunk_max: GasBudgetMist::new(800_000),
            audit_append_max: GasBudgetMist::new(800_000),
            samples_u32: 16,
        }
    }

    fn candidate(reproduced: bool) -> AuditCandidate {
        AuditCandidate {
            rule_id_hash_32: [0x11; 32],
            location_hash_32: [0x22; 32],
            invariant_hash_32: [0x33; 32],
            evidence_hash_32: [0x44; 32],
            confidence_bps_u16: 7000,
            repro_plan_safe_local: true,
            local_repro_done: reproduced,
        }
    }

    #[test]
    fn rust_pass_and_fail() {
        assert_eq!(pass(EvalKind::Rust).render_truth(), RenderTruth::Green);
        assert_eq!(fail(EvalKind::Rust).render_truth(), RenderTruth::Red);
    }

    #[test]
    fn move_and_prover_pass_fail() {
        assert_eq!(pass(EvalKind::Move).render_truth(), RenderTruth::Green);
        assert_eq!(fail(EvalKind::Move).render_truth(), RenderTruth::Red);
        assert_eq!(pass(EvalKind::Prover).render_truth(), RenderTruth::Green);
        assert_eq!(fail(EvalKind::Prover).render_truth(), RenderTruth::Red);
    }

    #[test]
    fn kani_and_lean_fixtures() {
        assert!(pass(EvalKind::Kani).reproducible());
        assert!(pass(EvalKind::Lean).reproducible());
    }

    #[test]
    fn false_pass_is_refused() {
        // A claimed pass with no evidence is a false pass — red, refused.
        assert_eq!(
            EvalRunView::record(EvalKind::Rust, true, [1u8; 32], [2u8; 32], [0u8; 32]),
            Err(EvalReject::EvidenceMismatch)
        );
    }

    #[test]
    fn gas_cap_under_not_red_over_not_green() {
        let under = gas_cap(&add_chunk_sample(400_000), &baseline());
        assert_ne!(under, RenderTruth::Red);
        let over = gas_cap(&add_chunk_sample(5_000_000), &baseline());
        assert_ne!(over, RenderTruth::Green);
    }

    #[test]
    fn ab_assignment_is_deterministic() {
        let even = [0x02u8; 32];
        let odd = [0x03u8; 32];
        assert_eq!(ab_assignment(&even), AbArm::Baseline);
        assert_eq!(ab_assignment(&odd), AbArm::Candidate);
        // same input -> same arm
        assert_eq!(ab_assignment(&even), ab_assignment(&even));
    }

    #[test]
    fn ab_compare_token_cost_pass() {
        let base = pass(EvalKind::Rust);
        // distinct evidence so the pair is consistent
        let cand =
            EvalRunView::record(EvalKind::Rust, true, [1u8; 32], [2u8; 32], [9u8; 32]).unwrap();
        let d = compare(&base, &cand, 1000, 800, 500, 400);
        assert_eq!(d.token_delta_i64, -200);
        assert_eq!(d.cost_delta_micro_i64, -100);
        assert!(d.candidate_passed && d.baseline_passed);
        assert!(d.evidence_consistent);
        assert!(d.promote);
    }

    #[test]
    fn ab_evidence_mismatch_no_promote() {
        let base = pass(EvalKind::Rust);
        // candidate reuses the baseline's evidence hash -> not a genuine new run.
        let cand =
            EvalRunView::record(EvalKind::Rust, true, [1u8; 32], [2u8; 32], [3u8; 32]).unwrap();
        let d = compare(&base, &cand, 1000, 800, 500, 400);
        assert!(!d.evidence_consistent);
        assert!(!d.promote);
    }

    #[test]
    fn promotable_features_have_canonical_cli_labels() {
        let labels: Vec<&str> = PromotableFeature::ALL.iter().map(|f| f.label()).collect();
        assert_eq!(
            labels,
            [
                "token_compress",
                "prefix_cache",
                "speculative",
                "kv_mode",
                "route_fsm"
            ]
        );
        // deterministic A/B arm assignment per feature (reuses ab_assignment); the
        // baseline arm is the feature off (the control).
        for f in PromotableFeature::ALL {
            assert_eq!(
                ab_assignment(&f.feature_hash_32()),
                ab_assignment(&f.feature_hash_32())
            );
        }
    }

    #[test]
    fn feature_ab_gate_requires_all_7_metrics_green() {
        let green = AbDecision {
            token_delta_i64: -100,
            cost_delta_micro_i64: -50,
            candidate_passed: true,
            baseline_passed: true,
            evidence_consistent: true,
            promote: true,
        };
        let v = FeatureAbVerdict {
            feature: PromotableFeature::PrefixCache,
            decision: green,
            latency_delta_ms_i64: -5,
            cache_hit_delta_bps_i32: 200,
            quality_regressed: false,
        };
        assert!(
            v.is_stable_promotion(),
            "all 7 metrics green -> promote to a stable path"
        );
        // no stable path if the canonical token/cost/pass/evidence decision fails
        let no_promote = FeatureAbVerdict {
            decision: AbDecision {
                promote: false,
                ..green
            },
            ..v
        };
        assert!(!no_promote.is_stable_promotion());
        // no stable path on a latency regression
        assert!(
            !FeatureAbVerdict {
                latency_delta_ms_i64: 10,
                ..v
            }
            .is_stable_promotion()
        );
        // no stable path on a cache-hit regression
        assert!(
            !FeatureAbVerdict {
                cache_hit_delta_bps_i32: -100,
                ..v
            }
            .is_stable_promotion()
        );
        // no stable path on a quality regression
        assert!(
            !FeatureAbVerdict {
                quality_regressed: true,
                ..v
            }
            .is_stable_promotion()
        );
    }

    #[test]
    fn audit_scan_local_only_cached_changed_only() {
        let scan = AuditScanView::scan(AuditProfile::Rust, true, &[candidate(false)]);
        assert!(scan.is_local_only());
        assert!(scan.made_no_live_call());
        assert!(scan.changed_only);
        assert_eq!(scan.candidate_count_u32, 1);
    }

    #[test]
    fn audit_production_rpc_and_live_tx_denied() {
        assert_eq!(
            AuditScanView::try_production_rpc(),
            Err(EvalReject::ProductionRpcDenied)
        );
        assert_eq!(AuditScanView::try_live_tx(), Err(EvalReject::LiveTxDenied));
    }

    #[test]
    fn candidate_fields_complete_and_repro_plan_safe() {
        let c = candidate(true);
        assert!(c.fields_complete());
        assert!(c.repro_plan_safe_local);
        let incomplete = AuditCandidate {
            evidence_hash_32: [0u8; 32],
            ..c
        };
        assert!(!incomplete.fields_complete());
    }

    #[test]
    fn pattern_only_no_high_reward_and_no_finding() {
        let pattern_only = candidate(false);
        assert!(!pattern_only.high_reward_allowed());
        assert_eq!(
            route_to_finding(
                &pattern_only,
                AtomDietKey::new(DietSourceStage::StageD, 253),
                SecuritySeverity::High
            ),
            Err(EvalReject::EvidenceMismatch)
        );
        // A locally reproduced candidate routes into a canonical finding.
        let reproduced = candidate(true);
        let finding = route_to_finding(
            &reproduced,
            AtomDietKey::new(DietSourceStage::StageD, 253),
            SecuritySeverity::High,
        )
        .unwrap();
        assert_eq!(finding.status, FindingStatus::Open);
        assert!(finding.evidence_present);
    }

    #[test]
    fn render_bounded_no_commerce_and_p95_within_20ms() {
        let v = pass(EvalKind::Rust);
        assert!(v.render(3).len() <= 3);
        assert!(v.render(64).len() <= 7);
        for line in v.render(64) {
            for bad in COMMERCE_TOKENS {
                assert!(!line.contains(bad), "commerce token {bad} in {line}");
            }
        }
        let mut samples = Vec::with_capacity(256);
        for _ in 0..256 {
            let t = std::time::Instant::now();
            let lines = v.render(32);
            std::hint::black_box(&lines);
            samples.push(t.elapsed().as_nanos() as u64);
        }
        let p95 = crate::repl::latency::p95_ms(&samples) / 1_000_000;
        assert!(p95 <= 20, "eval dispatch p95 {p95}ms exceeds 20ms budget");
    }
}
