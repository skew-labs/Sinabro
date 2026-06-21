//! Router execution-state FSM (canonical, plan §4.2).
//!
//! Defined here at its *first consumer* — the cockpit status bar (atom #418) —
//! and reused unchanged by the provider/model router atoms (#427+, F-WP-03B/04).
//! This is the single definition of [`RouteExecutionState`]; later work-packages
//! `use crate::route::RouteExecutionState`, they never redefine it.

use crate::commands::model_route::{ConsultTrigger, FrontierConsultPacketView};
use crate::commands::provider::ProviderKind;
use crate::provider::local_endpoint::ServingMetrics;
use crate::repl::latency::LatencyScore;
use crate::tui::RenderTruth;

/// Plan §4.2 — the router finite-state-machine execution state.
#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RouteExecutionState {
    /// Local executor, fast path; no external consult.
    Fast = 1,
    /// Normal local execution.
    Normal = 2,
    /// Slowed; a bounded frontier consult may be allowed (warning).
    Slow = 3,
    /// Stuck — repeated failure / contradiction; not healthy.
    Stuck = 4,
    /// Under audit-detector scrutiny; not healthy.
    Audit = 5,
    /// Safety boundary tripped; not healthy.
    Lockdown = 6,
    /// User explicitly requested a full / deep run.
    UserFull = 7,
}

impl RouteExecutionState {
    /// Project the route state onto the cockpit [`RenderTruth`]. The invariant
    /// enforced here is the status-bar law: `Stuck` / `Audit` / `Lockdown` can
    /// never render healthy (they map to `Red`); `Slow` is a warning (`Yellow`);
    /// `Fast` / `Normal` / `UserFull` are healthy (`Green`).
    #[must_use]
    pub const fn render_truth(self) -> RenderTruth {
        match self {
            Self::Fast | Self::Normal | Self::UserFull => RenderTruth::Green,
            Self::Slow => RenderTruth::Yellow,
            Self::Stuck | Self::Audit | Self::Lockdown => RenderTruth::Red,
        }
    }

    /// Whether this route state may be rendered as healthy.
    #[must_use]
    pub const fn is_healthy(self) -> bool {
        self.render_truth().is_healthy()
    }
}

/// A single routing event recorded in a [`RouterDecisionTrace`] (#601/#602).
/// Every event is visible: a local-base step, a typed bounded-consult escalation,
/// or a fallback that carries its approval + visible-reason flags. A fallback that
/// is missing either flag is a *silent* fallback and fails
/// [`RouterDecisionTrace::is_no_silent_fallback`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RouteEvent {
    /// Default local-base execution — no external egress (#598).
    LocalOnly,
    /// A typed bounded-consult escalation opened (visible, never silent).
    ConsultOpened(crate::commands::model_route::ConsultTrigger),
    /// A provider/model fallback. `approved` AND `reason_visible` must both be
    /// true for the fallback to be permitted (never silent).
    Fallback {
        /// Whether the user explicitly approved this fallback.
        approved: bool,
        /// Whether the fallback carries a visible reason.
        reason_visible: bool,
    },
}

impl RouteEvent {
    /// Whether this event is a *silent* fallback — a fallback missing approval or
    /// a visible reason. Local and consult events are never silent.
    #[must_use]
    pub fn is_silent_fallback(self) -> bool {
        match self {
            Self::Fallback {
                approved,
                reason_visible,
            } => !approved || !reason_visible,
            Self::LocalOnly | Self::ConsultOpened(_) => false,
        }
    }

    /// Append this event's deterministic byte encoding (tag + payload) to `buf`.
    fn encode(self, buf: &mut Vec<u8>) {
        match self {
            Self::LocalOnly => buf.push(0),
            Self::ConsultOpened(trigger) => {
                buf.push(1);
                buf.push(trigger as u8);
            }
            Self::Fallback {
                approved,
                reason_visible,
            } => {
                buf.push(2);
                buf.push(u8::from(approved));
                buf.push(u8::from(reason_visible));
            }
        }
    }
}

/// One recorded routing decision. A pure, replayable projection: the same
/// (state, trajectory, event) inputs always produce the same `fingerprint_32`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RouteStep {
    /// The route state the decision was made in (visible, #599).
    pub state: RouteExecutionState,
    /// The route recommended after folding trajectory health (#600).
    pub recommended: RouteExecutionState,
    /// The unhealthy-trajectory bitset that drove the recommendation.
    pub trajectory_bits_u16: u16,
    /// The visible routing event.
    pub event: RouteEvent,
    /// Deterministic SHA-256 fingerprint of the decision inputs.
    pub fingerprint_32: [u8; 32],
}

/// A rich, replayable consult-trace entry (#608, G.8.14). Every provider consult
/// appends one of these so the consult is fully auditable after the fact: which
/// provider, the prompt + output hashes, the bounded cost + measured latency, the
/// typed trigger, and the same-message approval-summary hash (#607). The provider
/// output is `advisory` (never canonical, never training data) until locally
/// verified — the invariant `advisory == true` is carried from the bounded packet.
/// Deterministic: the same inputs always recompute the same `fingerprint_32`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ConsultTraceEntry {
    /// Which provider was consulted (visible).
    pub provider: ProviderKind,
    /// The typed trigger that provoked the consult.
    pub trigger: ConsultTrigger,
    /// SHA-256 of the compiled prompt that was sent (redacted upstream).
    pub prompt_hash_32: [u8; 32],
    /// SHA-256 of the provider response (advisory until locally verified).
    pub output_hash_32: [u8; 32],
    /// The bounded token cost ceiling of the consult.
    pub cost_tokens_u32: u32,
    /// The measured round-trip latency in milliseconds.
    pub latency_ms_u32: u32,
    /// SHA-256 of the same-message approval summary (#607) that authorized the send.
    pub approval_summary_hash_32: [u8; 32],
    /// Whether the provider output is advisory (invariant `true` — not canonical,
    /// not training data, until locally verified).
    pub advisory: bool,
    /// Deterministic SHA-256 fingerprint of the entry's inputs (replayable).
    pub fingerprint_32: [u8; 32],
}

impl ConsultTraceEntry {
    /// Record a consult from its bounded packet + measured outcome. The trigger and
    /// prompt hash are read from the canonical [`FrontierConsultPacketView`]; the
    /// `advisory` flag is the packet's invariant (`advisory_only == true`); the
    /// caller supplies the provider, the output hash, the cost, the latency, and the
    /// #607 approval-summary hash.
    #[must_use]
    pub fn record(
        provider: ProviderKind,
        packet: &FrontierConsultPacketView,
        output_hash_32: [u8; 32],
        cost_tokens_u32: u32,
        latency_ms_u32: u32,
        approval_summary_hash_32: [u8; 32],
    ) -> Self {
        let mut entry = Self {
            provider,
            trigger: packet.trigger,
            prompt_hash_32: packet.prompt_hash_32,
            output_hash_32,
            cost_tokens_u32,
            latency_ms_u32,
            approval_summary_hash_32,
            advisory: packet.advisory_only,
            fingerprint_32: [0u8; 32],
        };
        entry.fingerprint_32 = entry.compute_fingerprint();
        entry
    }

    /// Whether the provider output is advisory (invariant `true`).
    #[must_use]
    pub const fn is_advisory(&self) -> bool {
        self.advisory
    }

    /// Whether the stored fingerprint matches a recompute from the inputs
    /// (deterministic replay; a tampered field breaks the match).
    #[must_use]
    pub fn replay_matches(&self) -> bool {
        self.compute_fingerprint() == self.fingerprint_32
    }

    /// Deterministic SHA-256 over the entry's inputs (excluding the stored
    /// fingerprint itself).
    fn compute_fingerprint(&self) -> [u8; 32] {
        let mut buf = Vec::with_capacity(106);
        buf.push(self.provider as u8);
        buf.push(self.trigger as u8);
        buf.extend_from_slice(&self.prompt_hash_32);
        buf.extend_from_slice(&self.output_hash_32);
        buf.extend_from_slice(&self.cost_tokens_u32.to_le_bytes());
        buf.extend_from_slice(&self.latency_ms_u32.to_le_bytes());
        buf.extend_from_slice(&self.approval_summary_hash_32);
        buf.push(u8::from(self.advisory));
        crate::sha256_32(&buf)
    }
}

/// A deterministic, replayable record of routing decisions (#602). The same input
/// sequence always replays to identical bytes; a fallback is recorded as a visible
/// event, never a silent switch — the no-silent-fallback evidence backbone. It
/// reuses the canonical [`RouteExecutionState`],
/// [`crate::commands::model_route::TrajectoryHealth`], and
/// [`crate::provider::trajectory_health::recommended_route`] — it mints no new
/// routing logic, only the trace.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct RouterDecisionTrace {
    steps: Vec<RouteStep>,
    consults: Vec<ConsultTraceEntry>,
    metrics: Vec<ServingMetrics>,
}

impl RouterDecisionTrace {
    /// A new, empty trace.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Record a routing decision. The recommended route is derived from the
    /// trajectory via the canonical guard ([`recommended_route`]), and a
    /// deterministic fingerprint is computed over (state, recommended, trajectory
    /// bits, event).
    ///
    /// [`recommended_route`]: crate::provider::trajectory_health::recommended_route
    pub fn record(
        &mut self,
        state: RouteExecutionState,
        trajectory: crate::commands::model_route::TrajectoryHealth,
        event: RouteEvent,
    ) {
        let recommended = crate::provider::trajectory_health::recommended_route(trajectory);
        let trajectory_bits_u16 = trajectory.bits();
        let fingerprint_32 = Self::fingerprint(state, recommended, trajectory_bits_u16, event);
        self.steps.push(RouteStep {
            state,
            recommended,
            trajectory_bits_u16,
            event,
            fingerprint_32,
        });
    }

    /// The recorded steps.
    #[must_use]
    pub fn steps(&self) -> &[RouteStep] {
        &self.steps
    }

    /// The number of recorded steps.
    #[must_use]
    pub fn len(&self) -> usize {
        self.steps.len()
    }

    /// Whether the trace is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.steps.is_empty()
    }

    /// The per-step fingerprints, in order.
    #[must_use]
    pub fn fingerprints(&self) -> Vec<[u8; 32]> {
        self.steps.iter().map(|s| s.fingerprint_32).collect()
    }

    /// Replay the trace from its recorded inputs and return whether every step's
    /// recomputed fingerprint matches the stored one (deterministic replay).
    #[must_use]
    pub fn replay_matches(&self) -> bool {
        self.steps.iter().all(|s| {
            Self::fingerprint(s.state, s.recommended, s.trajectory_bits_u16, s.event)
                == s.fingerprint_32
        })
    }

    /// Whether the trace contains no silent fallback (every fallback event is
    /// approved AND carries a visible reason). The no-silent-fallback invariant.
    #[must_use]
    pub fn is_no_silent_fallback(&self) -> bool {
        !self.steps.iter().any(|s| s.event.is_silent_fallback())
    }

    /// Record a provider consult (#608). Every consult appends one entry — the
    /// 100%-traced invariant. The entry is fully auditable (provider, prompt +
    /// output hashes, cost, latency, trigger, approval summary) and replayable, and
    /// marks the provider output advisory (never canonical until locally verified).
    pub fn record_consult(&mut self, entry: ConsultTraceEntry) {
        self.consults.push(entry);
    }

    /// The recorded consult entries, in order.
    #[must_use]
    pub fn consults(&self) -> &[ConsultTraceEntry] {
        &self.consults
    }

    /// The number of recorded consults.
    #[must_use]
    pub fn consult_count(&self) -> usize {
        self.consults.len()
    }

    /// Whether every recorded consult replays to its stored fingerprint
    /// (deterministic consult trace).
    #[must_use]
    pub fn consults_replay_matches(&self) -> bool {
        self.consults.iter().all(ConsultTraceEntry::replay_matches)
    }

    /// Whether every recorded consult is marked advisory — the provider output is
    /// never canonical / training data until locally verified.
    #[must_use]
    pub fn all_consults_advisory(&self) -> bool {
        self.consults.iter().all(ConsultTraceEntry::is_advisory)
    }

    /// Record the split serving metrics for a generation (#618) — TTFT / TPOT /
    /// stream-gap / queue / prefill / decode, measured separately and route-visible.
    pub fn record_serving_metrics(&mut self, metrics: ServingMetrics) {
        self.metrics.push(metrics);
    }

    /// The recorded serving metrics, in order (route-visible split latency).
    #[must_use]
    pub fn serving_metrics(&self) -> &[ServingMetrics] {
        &self.metrics
    }

    /// Whether every recorded serving-metric is internally consistent — the
    /// no-aggregate-lie invariant across the whole trace (each split present and
    /// coherent, never one blended number).
    #[must_use]
    pub fn all_metrics_consistent(&self) -> bool {
        self.metrics.iter().all(|m| m.splits_consistent())
    }

    /// The deterministic fingerprint of one decision's inputs.
    fn fingerprint(
        state: RouteExecutionState,
        recommended: RouteExecutionState,
        trajectory_bits_u16: u16,
        event: RouteEvent,
    ) -> [u8; 32] {
        let mut buf = Vec::with_capacity(8);
        buf.push(state as u8);
        buf.push(recommended as u8);
        buf.extend_from_slice(&trajectory_bits_u16.to_le_bytes());
        event.encode(&mut buf);
        crate::sha256_32(&buf)
    }
}

/// The full split CU evidence bundle for one served route (#621, RD-36). Every
/// speed claim attaches this: no route claims "fast" without latency percentiles,
/// the TTFT/TPOT/prefill/decode/queue split (#618), throughput, prefix-hit + KV-hit
/// rates, VRAM headroom, the perceived UI-latency score, and a quality verdict. A
/// scorecard missing any dimension cannot back a fast claim; it also feeds the
/// Stage H diet.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PerfScorecard {
    /// Latency p50 (ms).
    pub p50_ms_u32: u32,
    /// Latency p95 (ms).
    pub p95_ms_u32: u32,
    /// Latency p99 (ms).
    pub p99_ms_u32: u32,
    /// The split serving metrics (#618: TTFT / TPOT / stream-gap / queue / prefill / decode).
    pub metrics: ServingMetrics,
    /// Throughput (output tokens per second).
    pub throughput_tok_s_u32: u32,
    /// Prefix-cache hit-rate (basis points).
    pub prefix_hit_bps_u16: u16,
    /// KV-cache hit-rate (basis points).
    pub kv_hit_bps_u16: u16,
    /// VRAM headroom (basis points; 0 = exhausted, 10000 = fully free).
    pub vram_headroom_bps_u16: u16,
    /// The perceived UI-latency score (keypress / parse / render / refresh).
    pub ui_latency: LatencyScore,
    /// Quality verdict for the served route (never a false green).
    pub quality: RenderTruth,
}

impl PerfScorecard {
    /// Whether this scorecard is complete enough to back a "fast" route claim
    /// (RD-36). Requires ordered, present latency percentiles (p50 ≤ p95 ≤ p99 and
    /// p99 > 0), a consistent serving-metric split (#618, no aggregate-one-number
    /// lie), measured throughput (> 0), an all-within-budget UI-latency score, and
    /// a non-Red quality verdict. A route missing any of these can never claim fast
    /// — no fast claim without the full scorecard.
    #[must_use]
    pub fn backs_fast_claim(&self) -> bool {
        self.p99_ms_u32 > 0
            && self.p50_ms_u32 <= self.p95_ms_u32
            && self.p95_ms_u32 <= self.p99_ms_u32
            && self.metrics.splits_consistent()
            && self.throughput_tok_s_u32 > 0
            && self.ui_latency.all_ok()
            && !matches!(self.quality, RenderTruth::Red)
    }

    /// A deterministic hash over the whole bundle — the scorecard is hash-linked to
    /// its route so a "fast" claim can be replayed against the evidence that backed
    /// it.
    #[must_use]
    pub fn scorecard_hash_32(&self) -> [u8; 32] {
        let mut buf = Vec::with_capacity(64);
        buf.extend_from_slice(&self.p50_ms_u32.to_le_bytes());
        buf.extend_from_slice(&self.p95_ms_u32.to_le_bytes());
        buf.extend_from_slice(&self.p99_ms_u32.to_le_bytes());
        buf.extend_from_slice(&self.metrics.ttft_ms_u32.to_le_bytes());
        buf.extend_from_slice(&self.metrics.tpot_micro_u32.to_le_bytes());
        buf.extend_from_slice(&self.metrics.stream_gap_max_ms_u32.to_le_bytes());
        buf.extend_from_slice(&self.metrics.queue_ms_u32.to_le_bytes());
        buf.extend_from_slice(&self.metrics.prefill_ms_u32.to_le_bytes());
        buf.extend_from_slice(&self.metrics.decode_ms_u32.to_le_bytes());
        buf.extend_from_slice(&self.throughput_tok_s_u32.to_le_bytes());
        buf.extend_from_slice(&self.prefix_hit_bps_u16.to_le_bytes());
        buf.extend_from_slice(&self.kv_hit_bps_u16.to_le_bytes());
        buf.extend_from_slice(&self.vram_headroom_bps_u16.to_le_bytes());
        buf.push(u8::from(self.ui_latency.all_ok()));
        buf.push(self.quality as u8);
        crate::sha256_32(&buf)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn serving_metrics_are_route_visible_and_consistent() {
        let mut trace = RouterDecisionTrace::new();
        assert!(trace.serving_metrics().is_empty());
        let m = ServingMetrics {
            ttft_ms_u32: 120,
            tpot_micro_u32: 8_000,
            stream_gap_max_ms_u32: 15,
            queue_ms_u32: 20,
            prefill_ms_u32: 80,
            decode_ms_u32: 240,
        };
        trace.record_serving_metrics(m);
        assert_eq!(trace.serving_metrics().len(), 1);
        assert!(
            trace.all_metrics_consistent(),
            "split metrics are route-visible and consistent"
        );
        // an inconsistent (aggregate-lie) metric is caught in the trace
        let lie = ServingMetrics {
            ttft_ms_u32: 1,
            ..m
        };
        trace.record_serving_metrics(lie);
        assert!(
            !trace.all_metrics_consistent(),
            "an aggregate-lie metric fails the trace guard"
        );
    }

    fn good_scorecard() -> PerfScorecard {
        PerfScorecard {
            p50_ms_u32: 40,
            p95_ms_u32: 120,
            p99_ms_u32: 300,
            metrics: ServingMetrics {
                ttft_ms_u32: 120,
                tpot_micro_u32: 8_000,
                stream_gap_max_ms_u32: 15,
                queue_ms_u32: 20,
                prefill_ms_u32: 80,
                decode_ms_u32: 240,
            },
            throughput_tok_s_u32: 95,
            prefix_hit_bps_u16: 9_500,
            kv_hit_bps_u16: 8_000,
            vram_headroom_bps_u16: 3_000,
            ui_latency: LatencyScore::evaluate(
                crate::repl::latency::LatencyBudget::DEFAULT,
                2,
                1,
                1,
                10,
            ),
            quality: RenderTruth::Green,
        }
    }

    #[test]
    fn scorecard_backs_fast_claim_only_when_complete() {
        let s = good_scorecard();
        assert!(
            s.backs_fast_claim(),
            "a complete scorecard backs a fast claim"
        );
        // no fast claim without throughput evidence
        let no_tput = PerfScorecard {
            throughput_tok_s_u32: 0,
            ..s
        };
        assert!(!no_tput.backs_fast_claim());
        // no fast claim with a red quality verdict
        let red = PerfScorecard {
            quality: RenderTruth::Red,
            ..s
        };
        assert!(!red.backs_fast_claim());
        // no fast claim with an aggregate-lie metric split (TTFT < queue + prefill)
        let mut bad_metrics = s;
        bad_metrics.metrics.ttft_ms_u32 = 1;
        assert!(!bad_metrics.backs_fast_claim());
        // no fast claim with unordered percentiles (p95 120 > p99 50)
        let unordered = PerfScorecard {
            p99_ms_u32: 50,
            ..s
        };
        assert!(!unordered.backs_fast_claim());
    }

    #[test]
    fn scorecard_is_hash_linked() {
        let s = good_scorecard();
        let h1 = s.scorecard_hash_32();
        assert_eq!(h1, s.scorecard_hash_32(), "hash is deterministic");
        assert_ne!(h1, [0u8; 32]);
        // a different scorecard hashes differently (hash-linked to its evidence)
        let other = PerfScorecard {
            throughput_tok_s_u32: 96,
            ..s
        };
        assert_ne!(s.scorecard_hash_32(), other.scorecard_hash_32());
    }

    #[test]
    fn healthy_states_are_green() {
        for s in [
            RouteExecutionState::Fast,
            RouteExecutionState::Normal,
            RouteExecutionState::UserFull,
        ] {
            assert_eq!(s.render_truth(), RenderTruth::Green);
            assert!(s.is_healthy());
        }
    }

    #[test]
    fn slow_is_yellow_warning() {
        assert_eq!(
            RouteExecutionState::Slow.render_truth(),
            RenderTruth::Yellow
        );
        assert!(!RouteExecutionState::Slow.is_healthy());
    }

    #[test]
    fn stuck_audit_lockdown_can_never_be_healthy() {
        for s in [
            RouteExecutionState::Stuck,
            RouteExecutionState::Audit,
            RouteExecutionState::Lockdown,
        ] {
            assert_eq!(s.render_truth(), RenderTruth::Red);
            assert!(!s.is_healthy(), "{s:?} must never render healthy");
        }
    }
}

#[cfg(test)]
mod decision_trace_tests {
    use super::*;
    use crate::commands::model_route::{
        ConsultTrigger, TrajectoryHealth, TrajectorySignal, consult_token_cap,
    };

    fn healthy() -> TrajectoryHealth {
        TrajectoryHealth::healthy()
    }

    fn with_signal(sig: TrajectorySignal) -> TrajectoryHealth {
        let mut h = TrajectoryHealth::healthy();
        h.record(sig);
        h
    }

    /// #598 — the default route is local-first: FAST/NORMAL authorize 0 external
    /// tokens, so the local base model is the default executor (RD-49 Option C).
    #[test]
    fn default_route_is_local_first_zero_external() {
        for state in [RouteExecutionState::Fast, RouteExecutionState::Normal] {
            assert_eq!(
                consult_token_cap(state),
                (0, 0),
                "{state:?} must be local-only (0 external tokens)"
            );
        }
        let mut trace = RouterDecisionTrace::new();
        trace.record(
            RouteExecutionState::Normal,
            healthy(),
            RouteEvent::LocalOnly,
        );
        assert_eq!(trace.len(), 1);
        assert!(!trace.is_empty());
        assert!(trace.is_no_silent_fallback());
    }

    /// #600 — trajectory health folds into the recommended route (guard binding):
    /// a secret touch forces Lockdown, a semantic loop slows the route.
    #[test]
    fn trajectory_drives_recommended_route() {
        let mut trace = RouterDecisionTrace::new();
        trace.record(
            RouteExecutionState::Normal,
            with_signal(TrajectorySignal::SecretTouch),
            RouteEvent::LocalOnly,
        );
        trace.record(
            RouteExecutionState::Normal,
            with_signal(TrajectorySignal::SemanticLoop),
            RouteEvent::LocalOnly,
        );
        let steps = trace.steps();
        assert_eq!(steps[0].recommended, RouteExecutionState::Lockdown);
        assert_eq!(steps[1].recommended, RouteExecutionState::Slow);
    }

    /// #599 — unhealthy route states are recorded visibly and never render green.
    #[test]
    fn unhealthy_states_recorded_visible() {
        let mut trace = RouterDecisionTrace::new();
        trace.record(RouteExecutionState::Stuck, healthy(), RouteEvent::LocalOnly);
        let step = trace.steps()[0];
        assert_eq!(step.state, RouteExecutionState::Stuck);
        assert_eq!(step.state.render_truth(), RenderTruth::Red);
    }

    /// #601 — a fallback is recorded as a visible event; a fallback missing
    /// approval or a visible reason is silent and fails the invariant.
    #[test]
    fn silent_fallback_is_detected() {
        let mut visible = RouterDecisionTrace::new();
        visible.record(
            RouteExecutionState::Slow,
            healthy(),
            RouteEvent::Fallback {
                approved: true,
                reason_visible: true,
            },
        );
        assert!(visible.is_no_silent_fallback());

        let mut unapproved = RouterDecisionTrace::new();
        unapproved.record(
            RouteExecutionState::Slow,
            healthy(),
            RouteEvent::Fallback {
                approved: false,
                reason_visible: true,
            },
        );
        assert!(
            !unapproved.is_no_silent_fallback(),
            "an unapproved fallback is silent"
        );

        let mut reasonless = RouterDecisionTrace::new();
        reasonless.record(
            RouteExecutionState::Slow,
            healthy(),
            RouteEvent::Fallback {
                approved: true,
                reason_visible: false,
            },
        );
        assert!(
            !reasonless.is_no_silent_fallback(),
            "a reasonless fallback is silent"
        );
    }

    /// #601 — a consult escalation is a visible (non-silent) event carrying its
    /// typed trigger.
    #[test]
    fn consult_escalation_is_visible() {
        let mut trace = RouterDecisionTrace::new();
        trace.record(
            RouteExecutionState::Slow,
            healthy(),
            RouteEvent::ConsultOpened(ConsultTrigger::RepeatedFailure),
        );
        assert!(trace.is_no_silent_fallback());
        assert!(matches!(
            trace.steps()[0].event,
            RouteEvent::ConsultOpened(ConsultTrigger::RepeatedFailure)
        ));
    }

    /// #602 — deterministic replay: the same input sequence twin-runs to identical
    /// bytes, and replaying the recorded inputs equals the original.
    #[test]
    fn replay_is_deterministic() {
        let build = || {
            let mut t = RouterDecisionTrace::new();
            t.record(
                RouteExecutionState::Normal,
                healthy(),
                RouteEvent::LocalOnly,
            );
            t.record(
                RouteExecutionState::Slow,
                with_signal(TrajectorySignal::SemanticLoop),
                RouteEvent::ConsultOpened(ConsultTrigger::RepeatedFailure),
            );
            t.record(
                RouteExecutionState::Slow,
                healthy(),
                RouteEvent::Fallback {
                    approved: true,
                    reason_visible: true,
                },
            );
            t
        };
        let a = build();
        let b = build();
        assert_eq!(
            a.fingerprints(),
            b.fingerprints(),
            "twin-run identical bytes"
        );
        assert_eq!(a, b);
        assert!(a.replay_matches(), "replay equals original");
    }

    /// #602 falsifiability — different inputs must produce different fingerprints
    /// (the trace is a real function of its inputs, not a constant).
    #[test]
    fn different_inputs_differ() {
        let mut a = RouterDecisionTrace::new();
        a.record(
            RouteExecutionState::Normal,
            healthy(),
            RouteEvent::LocalOnly,
        );
        let mut b = RouterDecisionTrace::new();
        b.record(RouteExecutionState::Slow, healthy(), RouteEvent::LocalOnly);
        assert_ne!(a.fingerprints(), b.fingerprints());
    }

    // ---- #608 rich consult trace (provider, hashes, cost, latency, advisory) ----

    fn consult_packet_fixture(trigger: ConsultTrigger) -> Option<FrontierConsultPacketView> {
        // build a canonical bounded packet on a consult-capable state (advisory_only)
        let mut router = crate::commands::model_route::ModelRouter::new([0u8; 32]);
        router.transition(RouteExecutionState::Stuck);
        router.consult_packet(Some(trigger), [1u8; 32], [2u8; 32], [3u8; 32])
    }

    #[test]
    fn consult_trace_records_all_fields_and_is_advisory() {
        let trigger = ConsultTrigger::AbiMismatch;
        let p = consult_packet_fixture(trigger);
        assert!(p.is_some());
        if let Some(p) = p {
            let entry = ConsultTraceEntry::record(
                ProviderKind::Anthropic,
                &p,
                [9u8; 32],
                10_000,
                1_234,
                [8u8; 32],
            );
            assert_eq!(entry.provider, ProviderKind::Anthropic);
            assert_eq!(entry.trigger, trigger);
            assert_eq!(entry.prompt_hash_32, p.prompt_hash_32);
            assert_eq!(entry.output_hash_32, [9u8; 32]);
            assert_eq!(entry.cost_tokens_u32, 10_000);
            assert_eq!(entry.latency_ms_u32, 1_234);
            assert_eq!(entry.approval_summary_hash_32, [8u8; 32]);
            // provider output is advisory (not canonical / not training data)
            assert!(entry.is_advisory());
            assert!(entry.advisory);
            assert!(entry.replay_matches());
        }
    }

    #[test]
    fn every_consult_is_traced_100_percent_and_advisory() {
        let mut trace = RouterDecisionTrace::new();
        assert_eq!(trace.consult_count(), 0);
        let mut recorded = 0usize;
        for trigger in ConsultTrigger::ALL {
            if let Some(p) = consult_packet_fixture(trigger) {
                trace.record_consult(ConsultTraceEntry::record(
                    ProviderKind::Anthropic,
                    &p,
                    [1u8; 32],
                    8_000,
                    500,
                    [2u8; 32],
                ));
                recorded += 1;
            }
        }
        // 100% of consults traced
        assert_eq!(trace.consult_count(), recorded);
        assert!(recorded >= 1);
        assert_eq!(trace.consults().len(), recorded);
        assert!(
            trace.all_consults_advisory(),
            "every consult output is advisory"
        );
        assert!(
            trace.consults_replay_matches(),
            "the consult trace is replayable"
        );
    }

    // falsifiability canary: a tampered entry (changed cost, fingerprint not
    // recomputed) no longer replays — the replay check CAN fail.
    #[test]
    fn consult_trace_replay_detects_tamper_canary() {
        let p = consult_packet_fixture(ConsultTrigger::SafetyBoundary);
        assert!(p.is_some());
        if let Some(p) = p {
            let mut entry = ConsultTraceEntry::record(
                ProviderKind::OpenAi,
                &p,
                [3u8; 32],
                12_000,
                700,
                [4u8; 32],
            );
            assert!(entry.replay_matches());
            entry.cost_tokens_u32 = 999_999;
            assert!(
                !entry.replay_matches(),
                "a tampered cost must break the replay fingerprint"
            );
        }
    }
}
