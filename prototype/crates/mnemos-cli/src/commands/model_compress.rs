//! Compression + context-window + KV-cache mode status.
//!
//! `sinabro model compress status`. Three status-only surfaces, none of which
//! starts a serving job:
//!
//! * **context compression** — reports its loss and risk; it can shrink the
//!   token footprint but can never hide that it dropped information. A
//!   specialized compressor per source kind (compiler /
//!   cargo-test / log / tool, reusing [`TraceSourceKind`]) MUST preserve the
//!   first failing command, its error code + file/line, the governing invariant,
//!   the approval boundary, the evidence hash, and the redaction report — and
//!   keep the raw transcript replayable by hash + path. A context is assembled
//!   from memory that excludes deleted ids (delete/replay truth is never
//!   bypassed).
//! * **KV-cache modes** — BF16 / FP8 / TurboQuant-watch, the quantized-serving
//!   canary, the prefill/decode split candidate, and the prefix/KV hit-rate are
//!   status-only: the supported runtime, the expected VRAM / latency / quality
//!   risk, and the canary requirement are visible, but no serving job is
//!   started here.
//! * **minimal consult packet** — a frontier consult is compiled from a fixed
//!   minimal field set and never from the whole repo, whole chat, whole sidecar,
//!   or private memory.

use crate::commands::model_route::ConsultTrigger;
use crate::route::RouteExecutionState;
use crate::tui::RenderTruth;
use crate::tui::trace_pane::TraceSourceKind;

const ZERO32: [u8; 32] = [0u8; 32];

// ---- context compression --------------------------------------------------

/// The proof a compressor may never drop. Specialized compressors fold
/// verbosity, but the first failing command, its error code and file/line, the
/// governing invariant, the approval boundary, the evidence hash, and the
/// redaction report all survive — and the raw transcript stays replayable by
/// hash + path.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CompressionProof {
    /// SHA-256 of the first failing command (must be preserved / non-zero).
    pub first_failure_hash_32: [u8; 32],
    /// The first failure's exit / error code.
    pub error_code_i32: i32,
    /// SHA-256 of the failing file:line.
    pub file_line_hash_32: [u8; 32],
    /// SHA-256 of the governing invariant.
    pub invariant_hash_32: [u8; 32],
    /// SHA-256 of the approval boundary that applied.
    pub approval_boundary_hash_32: [u8; 32],
    /// SHA-256 of the evidence reference (must be preserved / non-zero).
    pub evidence_hash_32: [u8; 32],
    /// SHA-256 of the redaction report (must be preserved / non-zero).
    pub redaction_report_hash_32: [u8; 32],
    /// SHA-256 of the raw transcript (replay; must be non-zero).
    pub raw_transcript_hash_32: [u8; 32],
    /// SHA-256 of the raw transcript path (replay; must be non-zero).
    pub raw_transcript_path_hash_32: [u8; 32],
}

impl CompressionProof {
    /// Whether the proof is complete — none of the un-droppable fields (first
    /// failure, evidence, redaction report, raw transcript hash + path) is zero.
    #[must_use]
    pub fn is_complete(&self) -> bool {
        ![
            self.first_failure_hash_32,
            self.evidence_hash_32,
            self.redaction_report_hash_32,
            self.raw_transcript_hash_32,
            self.raw_transcript_path_hash_32,
        ]
        .contains(&ZERO32)
    }
}

/// A context-window compression report. The loss and risk are always reported;
/// the report cannot be constructed without a complete [`CompressionProof`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ContextCompressionReport {
    /// Which specialized compressor produced this report.
    pub source_kind: TraceSourceKind,
    /// Tokens before compression.
    pub original_tokens_u32: u32,
    /// Tokens after compression (never greater than original).
    pub compressed_tokens_u32: u32,
    /// Fraction of tokens dropped, in basis points.
    pub loss_bps: u16,
    /// Risk truth of the loss (no false green: more loss is never greener).
    pub risk: RenderTruth,
    /// The un-droppable proof.
    pub proof: CompressionProof,
}

impl ContextCompressionReport {
    /// Build a compression report. Returns `None` (the report is refused) when
    /// the proof is incomplete (loss report required) or when `compressed`
    /// exceeds `original` (not a compression).
    #[must_use]
    pub fn new(
        source_kind: TraceSourceKind,
        original_tokens_u32: u32,
        compressed_tokens_u32: u32,
        proof: CompressionProof,
    ) -> Option<Self> {
        if !proof.is_complete() {
            return None;
        }
        if compressed_tokens_u32 > original_tokens_u32 {
            return None;
        }
        let dropped = original_tokens_u32 - compressed_tokens_u32;
        let loss_bps = if original_tokens_u32 == 0 {
            0
        } else {
            ((dropped as u64 * 10_000) / original_tokens_u32 as u64) as u16
        };
        let risk = match loss_bps {
            0..=2_000 => RenderTruth::Green,
            2_001..=5_000 => RenderTruth::Yellow,
            _ => RenderTruth::Red,
        };
        Some(Self {
            source_kind,
            original_tokens_u32,
            compressed_tokens_u32,
            loss_bps,
            risk,
            proof,
        })
    }

    /// Tokens freed by this compression (the budget update delta).
    #[must_use]
    pub const fn freed_tokens(self) -> u32 {
        self.original_tokens_u32 - self.compressed_tokens_u32
    }

    /// The new context-budget usage after applying this compression to a prior
    /// `used_before` total: the original footprint is replaced by the compressed
    /// one (saturating).
    #[must_use]
    pub const fn budget_used_after(self, used_before_u32: u32) -> u32 {
        used_before_u32
            .saturating_sub(self.original_tokens_u32)
            .saturating_add(self.compressed_tokens_u32)
    }
}

/// Assemble a context from candidate memory ids, excluding any that were
/// deleted. Reuses the delete/replay truth: a deleted memory can never
/// re-enter a compressed context. Returns the included ids in input order.
#[must_use]
pub fn assemble_context(candidate_ids: &[[u8; 32]], deleted_ids: &[[u8; 32]]) -> Vec<[u8; 32]> {
    candidate_ids
        .iter()
        .filter(|id| !deleted_ids.contains(id))
        .copied()
        .collect()
}

// ---- KV-cache mode status -------------------------------------------------

/// A KV-cache / quantization serving mode. Status-only.
#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum KvCacheMode {
    /// BF16 — full-precision baseline (no quantization).
    Bf16 = 1,
    /// FP8 — 8-bit float quantized KV cache.
    Fp8 = 2,
    /// TurboQuant — aggressive quantization (watch / experimental).
    TurboQuant = 3,
}

impl KvCacheMode {
    /// Whether this mode quantizes the KV cache (FP8 / TurboQuant).
    #[must_use]
    pub const fn is_quantized(self) -> bool {
        matches!(self, Self::Fp8 | Self::TurboQuant)
    }

    /// Whether this mode requires a quantized-serving canary before it
    /// may be enabled — every quantized mode does.
    #[must_use]
    pub const fn requires_stage_h_canary(self) -> bool {
        self.is_quantized()
    }
}

/// Status-only view of a KV-cache mode. Carries the supported runtime, the
/// expected VRAM / latency / quality risk, the canary requirement, and
/// the prefill/decode split candidacy. `serving_started` is the invariant
/// `false` — no serving job is started.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct KvCacheModeStatus {
    /// The mode.
    pub mode: KvCacheMode,
    /// Whether the current runtime supports this mode.
    pub runtime_supported: bool,
    /// Expected VRAM saving in basis points.
    pub expected_vram_saving_bps: u16,
    /// Expected latency delta in basis points (negative = faster).
    pub expected_latency_delta_bps: i32,
    /// Expected quality risk (quantized modes are never Green).
    pub expected_quality_risk: RenderTruth,
    /// Whether a canary is required before enabling.
    pub requires_stage_h_canary: bool,
    /// Whether this mode is a prefill/decode split candidate.
    pub prefill_decode_split_candidate: bool,
    /// Invariant `false`: no serving job is started.
    pub serving_started: bool,
}

impl KvCacheModeStatus {
    /// Build the status fixture for `mode` on a (possibly unsupported) runtime,
    /// marking whether it is a prefill/decode split candidate.
    #[must_use]
    pub const fn for_mode(
        mode: KvCacheMode,
        runtime_supported: bool,
        prefill_decode_split_candidate: bool,
    ) -> Self {
        let (vram, latency) = match mode {
            KvCacheMode::Bf16 => (0u16, 0i32),
            KvCacheMode::Fp8 => (5_000u16, -1_000i32),
            KvCacheMode::TurboQuant => (6_500u16, -1_500i32),
        };
        Self {
            mode,
            runtime_supported,
            expected_vram_saving_bps: vram,
            expected_latency_delta_bps: latency,
            expected_quality_risk: if mode.is_quantized() {
                RenderTruth::Yellow
            } else {
                RenderTruth::Green
            },
            requires_stage_h_canary: mode.requires_stage_h_canary(),
            prefill_decode_split_candidate,
            serving_started: false,
        }
    }

    /// The render truth of this mode's status. An unsupported runtime is a
    /// warning (`Yellow`); otherwise the quality risk is shown verbatim.
    #[must_use]
    pub const fn status_truth(self) -> RenderTruth {
        if !self.runtime_supported {
            RenderTruth::Yellow
        } else {
            self.expected_quality_risk
        }
    }
}

/// A prefix / KV cache hit-rate placeholder. Until a real measurement is wired
/// it is [`RenderTruth::Unknown`], never a false `Green`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HitRatePlaceholder {
    /// Whether a real hit-rate has been measured.
    pub is_measured: bool,
    /// Measured hit-rate in basis points (meaningful only when measured).
    pub hit_rate_bps: u16,
}

impl HitRatePlaceholder {
    /// An unmeasured placeholder (renders `Unknown`).
    #[must_use]
    pub const fn unmeasured() -> Self {
        Self {
            is_measured: false,
            hit_rate_bps: 0,
        }
    }

    /// A measured hit-rate.
    #[must_use]
    pub const fn with_rate(hit_rate_bps: u16) -> Self {
        Self {
            is_measured: true,
            hit_rate_bps,
        }
    }

    /// Render truth: `Unknown` until measured, then `Green` at/above 5000 bps,
    /// else `Yellow`.
    #[must_use]
    pub const fn truth(self) -> RenderTruth {
        if !self.is_measured {
            RenderTruth::Unknown
        } else if self.hit_rate_bps >= 5_000 {
            RenderTruth::Green
        } else {
            RenderTruth::Yellow
        }
    }
}

// ---- minimal consult packet -----------------------------------------------

/// What a consult would be compiled *from*. Whole-repo / whole-sidecar /
/// private-memory inclusion are all forbidden; a request for any of them denies
/// the consult.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ConsultScope {
    /// Request to include the whole repository (forbidden).
    pub whole_repo: bool,
    /// Request to include the whole 21-file sidecar (forbidden).
    pub whole_sidecar: bool,
    /// Request to include private memory (forbidden).
    pub private_memory: bool,
}

impl ConsultScope {
    /// A minimal scope: none of the forbidden surfaces requested.
    #[must_use]
    pub const fn minimal() -> Self {
        Self {
            whole_repo: false,
            whole_sidecar: false,
            private_memory: false,
        }
    }

    /// Whether this scope requests any forbidden surface.
    #[must_use]
    pub const fn requests_forbidden_surface(self) -> bool {
        self.whole_repo || self.whole_sidecar || self.private_memory
    }
}

/// The minimal reasoning fields a consult packet is compiled from.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MinimalConsultParts {
    /// SHA-256 of the problem statement (required / non-zero).
    pub problem_hash_32: [u8; 32],
    /// The route state authorizing the consult.
    pub route_state: RouteExecutionState,
    /// SHA-256 of the exact contradiction (required / non-zero).
    pub contradiction_hash_32: [u8; 32],
    /// SHA-256 of the relevant code lines.
    pub code_lines_hash_32: [u8; 32],
    /// SHA-256 of the redacted command summary.
    pub redacted_command_summary_hash_32: [u8; 32],
    /// SHA-256 of the governing invariants.
    pub invariants_hash_32: [u8; 32],
    /// SHA-256 of the ruled-out options.
    pub ruled_out_options_hash_32: [u8; 32],
    /// SHA-256 of the requested answer shape.
    pub requested_answer_shape_hash_32: [u8; 32],
    /// The typed consult trigger.
    pub trigger: ConsultTrigger,
}

/// A compiled minimal consult packet. By construction it never includes the
/// whole repo, whole sidecar, or private memory.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MinimalConsultPacket {
    /// The minimal reasoning fields.
    pub parts: MinimalConsultParts,
    /// Invariant `false`: the whole repo is never included.
    pub includes_whole_repo: bool,
    /// Invariant `false`: the whole sidecar is never included.
    pub includes_whole_sidecar: bool,
    /// Invariant `false`: private memory is never included.
    pub private_memory_included: bool,
}

impl MinimalConsultPacket {
    /// Compile a minimal consult packet. Returns `None` (the consult is denied)
    /// when the scope requests any forbidden surface (whole repo / whole sidecar
    /// / private memory) or when a required minimal field (problem,
    /// contradiction) is missing.
    #[must_use]
    pub fn compile(parts: &MinimalConsultParts, scope: ConsultScope) -> Option<Self> {
        if scope.requests_forbidden_surface() {
            return None;
        }
        if parts.problem_hash_32 == ZERO32 || parts.contradiction_hash_32 == ZERO32 {
            return None;
        }
        Some(Self {
            parts: *parts,
            includes_whole_repo: false,
            includes_whole_sidecar: false,
            private_memory_included: false,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn complete_proof() -> CompressionProof {
        CompressionProof {
            first_failure_hash_32: [1u8; 32],
            error_code_i32: 101,
            file_line_hash_32: [2u8; 32],
            invariant_hash_32: [3u8; 32],
            approval_boundary_hash_32: [4u8; 32],
            evidence_hash_32: [5u8; 32],
            redaction_report_hash_32: [6u8; 32],
            raw_transcript_hash_32: [7u8; 32],
            raw_transcript_path_hash_32: [8u8; 32],
        }
    }

    #[test]
    fn compressed_context_report_reports_loss() {
        let r = ContextCompressionReport::new(TraceSourceKind::Plain, 1_000, 250, complete_proof());
        assert!(r.is_some(), "a valid compression must build a report");
        if let Some(r) = r {
            assert_eq!(r.compressed_tokens_u32, 250);
            assert_eq!(r.loss_bps, 7_500);
            assert_eq!(r.risk, RenderTruth::Red);
            assert!(r.compressed_tokens_u32 < r.original_tokens_u32);
        }
    }

    #[test]
    fn loss_report_required_rejects_incomplete_proof() {
        let mut proof = complete_proof();
        proof.evidence_hash_32 = ZERO32; // drop a required field
        assert!(
            ContextCompressionReport::new(TraceSourceKind::Compiler, 100, 10, proof).is_none(),
            "a report without a complete proof must be refused"
        );
    }

    #[test]
    fn first_failure_and_raw_proof_preserved() {
        let r =
            ContextCompressionReport::new(TraceSourceKind::CargoTest, 500, 50, complete_proof());
        assert!(r.is_some(), "valid");
        if let Some(r) = r {
            assert_ne!(r.proof.first_failure_hash_32, ZERO32);
            assert_ne!(r.proof.raw_transcript_hash_32, ZERO32);
            assert_ne!(r.proof.raw_transcript_path_hash_32, ZERO32);
            assert_eq!(r.proof.error_code_i32, 101);
        }
    }

    #[test]
    fn specialized_compressor_per_source_kind() {
        for kind in [
            TraceSourceKind::Compiler,
            TraceSourceKind::CargoTest,
            TraceSourceKind::Log,
            TraceSourceKind::Tool,
        ] {
            let r = ContextCompressionReport::new(kind, 200, 40, complete_proof());
            assert!(r.is_some(), "each source kind builds a report");
            if let Some(r) = r {
                assert_eq!(r.source_kind, kind);
            }
        }
    }

    #[test]
    fn deleted_memory_not_included() {
        let a = [10u8; 32];
        let b = [11u8; 32];
        let c = [12u8; 32];
        let included = assemble_context(&[a, b, c], &[b]);
        assert_eq!(included, vec![a, c]);
        assert!(
            !included.contains(&b),
            "a deleted memory must never re-enter context"
        );
    }

    #[test]
    fn budget_update_frees_tokens() {
        let r = ContextCompressionReport::new(TraceSourceKind::Log, 1_000, 300, complete_proof());
        assert!(r.is_some(), "valid");
        if let Some(r) = r {
            assert_eq!(r.freed_tokens(), 700);
            // used_before 4000 with this 1000-token block compressed to 300 -> 3300
            assert_eq!(r.budget_used_after(4_000), 3_300);
        }
    }

    #[test]
    fn kv_cache_mode_status_fixture_per_mode() {
        for mode in [KvCacheMode::Bf16, KvCacheMode::Fp8, KvCacheMode::TurboQuant] {
            let s = KvCacheModeStatus::for_mode(mode, true, false);
            assert_eq!(s.mode, mode);
            assert!(!s.serving_started, "Stage F starts no serving job");
        }
    }

    #[test]
    fn unsupported_runtime_is_a_warning() {
        let s = KvCacheModeStatus::for_mode(KvCacheMode::Bf16, false, false);
        assert_eq!(s.status_truth(), RenderTruth::Yellow);
    }

    #[test]
    fn quantized_modes_require_canary_and_are_not_green() {
        for mode in [KvCacheMode::Fp8, KvCacheMode::TurboQuant] {
            assert!(mode.is_quantized());
            assert!(mode.requires_stage_h_canary());
            let s = KvCacheModeStatus::for_mode(mode, true, true);
            assert!(s.requires_stage_h_canary);
            assert_eq!(s.expected_quality_risk, RenderTruth::Yellow);
            assert!(s.prefill_decode_split_candidate);
        }
        // BF16 is the full-precision baseline: no canary required.
        assert!(!KvCacheMode::Bf16.requires_stage_h_canary());
    }

    #[test]
    fn prefix_kv_hit_rate_placeholder_is_unknown_until_measured() {
        assert_eq!(
            HitRatePlaceholder::unmeasured().truth(),
            RenderTruth::Unknown
        );
        assert_eq!(
            HitRatePlaceholder::with_rate(6_000).truth(),
            RenderTruth::Green
        );
        assert_eq!(
            HitRatePlaceholder::with_rate(2_000).truth(),
            RenderTruth::Yellow
        );
    }

    fn parts() -> MinimalConsultParts {
        MinimalConsultParts {
            problem_hash_32: [1u8; 32],
            route_state: RouteExecutionState::Slow,
            contradiction_hash_32: [2u8; 32],
            code_lines_hash_32: [3u8; 32],
            redacted_command_summary_hash_32: [4u8; 32],
            invariants_hash_32: [5u8; 32],
            ruled_out_options_hash_32: [6u8; 32],
            requested_answer_shape_hash_32: [7u8; 32],
            trigger: ConsultTrigger::PlanDiskContradiction,
        }
    }

    #[test]
    fn minimal_consult_compiles_with_minimal_scope() {
        let p = MinimalConsultPacket::compile(&parts(), ConsultScope::minimal());
        assert!(p.is_some(), "a minimal-scope consult must compile");
        if let Some(p) = p {
            assert!(!p.includes_whole_repo);
            assert!(!p.includes_whole_sidecar);
            assert!(!p.private_memory_included);
        }
    }

    #[test]
    fn consult_packet_denies_whole_repo() {
        let scope = ConsultScope {
            whole_repo: true,
            whole_sidecar: false,
            private_memory: false,
        };
        assert!(MinimalConsultPacket::compile(&parts(), scope).is_none());
    }

    #[test]
    fn consult_packet_denies_whole_sidecar() {
        let scope = ConsultScope {
            whole_repo: false,
            whole_sidecar: true,
            private_memory: false,
        };
        assert!(MinimalConsultPacket::compile(&parts(), scope).is_none());
    }

    #[test]
    fn consult_packet_denies_private_memory() {
        let scope = ConsultScope {
            whole_repo: false,
            whole_sidecar: false,
            private_memory: true,
        };
        assert!(MinimalConsultPacket::compile(&parts(), scope).is_none());
    }

    #[test]
    fn consult_packet_requires_minimal_fields() {
        let mut p = parts();
        p.problem_hash_32 = ZERO32;
        assert!(
            MinimalConsultPacket::compile(&p, ConsultScope::minimal()).is_none(),
            "a consult missing the problem statement must be denied"
        );
    }
}
