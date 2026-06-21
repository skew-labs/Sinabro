//! `provider::local_vllm` — feature-gated vLLM loopback adapter
//! (G-WP-09 atom #596 G.8.2). Linux/GPU prod target.
//!
//! The PROD counterpart to the MLX/ollama dev adapter (#595), behind the IDENTICAL
//! [`LocalModelEndpoint`] trait so dev and prod are interchangeable with a uniform
//! route identity (`backend=local_base`) and uniform serving evidence. Behind the
//! `local-vllm` cargo feature (OFF by default). Loopback (`127.0.0.1`) only — a vLLM
//! OpenAI-compatible endpoint on loopback is LOCAL serving, not egress
//! ([`LoopbackBind`] rejects any non-loopback target); the only route off-box is the
//! separate triple-gated provider egress path ([`crate::provider::egress`], #603).
//!
//! KV-cache mode is ROUTE-VISIBLE (no hidden compression, `G-G-NO-SILENT-FALLBACK`):
//! the endpoint carries a [`KvCacheMode`] (default [`KvCacheMode::Bf16`] — the
//! full-precision baseline, no canary) and surfaces it — with its
//! [`KvCacheModeStatus`] and the [`RouteFsm`] route state it served under — in a
//! [`VllmServingManifest`]. A quantized mode (FP8 / TurboQuant) is never a false
//! green and always flags its Stage-H canary requirement, so it can never silently
//! become a stable serving path (the quantized canary is #620; the scorecard #621).
//! This adapter makes NO speed claim — TTFT/TPOT measurement is #618, gated by the
//! scorecard (`[[optimize-only-with-data]]`).
//!
//! Phase-0 autonomous makes ZERO live calls: the loopback transport is a deferred
//! seam (identical posture to #595). A freshly constructed [`VllmEndpoint`] has no
//! runtime attached and every serving call fails closed
//! ([`EndpointError::RuntimeUnavailable`]) — a clean typed error, never a panic and
//! never a silent fallback; a test attaches an in-process loopback double (no
//! socket). BASE model only ([`AdapterSwapPoint::Empty`], `G-G-NO-TRAINING-IN-G`);
//! secret-zero (the receipt holds only hashes / enums / bools + a [`SecretRefView`]).
//!
//! Reuse (no reinvention): [`LocalModelEndpoint`] + friends and [`LoopbackBind`]
//! from [`crate::provider::local_endpoint`]; [`KvCacheMode`] / [`KvCacheModeStatus`]
//! from [`crate::commands::model_compress`]; [`RouteFsm`] from
//! [`crate::provider::route_fsm`]. New here: [`VllmEndpoint`],
//! [`VllmServingManifest`].

use crate::commands::model_compress::{KvCacheMode, KvCacheModeStatus};
use crate::provider::local_endpoint::{
    AdapterSwapPoint, EndpointError, EndpointHealth, GenChunk, GenStream, LocalModelEndpoint,
    LocalReadyReceipt, LoopbackBind, RouteIdentity,
};
use crate::provider::route_fsm::RouteFsm;
use crate::route::RouteExecutionState;
use crate::secrets::SecretRefView;
use crate::tui::RenderTruth;

/// The default vLLM OpenAI-compatible loopback port.
pub const VLLM_DEFAULT_PORT: u16 = 8000;

/// Whether a loopback vLLM runtime is reachable. Phase-0 autonomous attaches NONE →
/// serving fails closed. The real loopback HTTP transport (an OpenAI-compatible call
/// to a `127.0.0.1` vLLM server) is a deferred seam; a test attaches an in-process
/// double to exercise the load → stream contract with 0 socket / 0 egress.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum VllmProbe {
    /// No loopback runtime — the Phase-0 default. Every serving call fails closed.
    Unreachable,
    /// An in-process loopback double stands in for the runtime (no socket; the real
    /// loopback transport is a later seam). Never attached on the autonomous path.
    InProcessDouble,
}

/// Route-visible serving evidence for a vLLM-served generation: the uniform route
/// identity (`local_base`, identical to the MLX adapter), the KV-cache mode + its
/// status (no hidden compression), and the [`RouteFsm`] route state / render the
/// serving ran under. This is the "KV-mode in the route trace" surface — a quantized
/// mode can never be hidden or a false green.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct VllmServingManifest {
    /// The uniform route identity (`backend=local_base`).
    pub identity: RouteIdentity,
    /// The KV-cache mode status (mode + support + risk + canary requirement).
    pub kv: KvCacheModeStatus,
    /// The route FSM state the serving ran under.
    pub route_state: RouteExecutionState,
    /// The route render truth (canonical, no false green).
    pub route_render: RenderTruth,
}

impl VllmServingManifest {
    /// Whether the served route is shown healthy-green. A quantized KV mode (FP8 /
    /// TurboQuant) OR an unhealthy route state (Slow / Stuck / Audit / Lockdown) is
    /// never a false green — both must be green.
    #[must_use]
    pub fn is_healthy_green(&self) -> bool {
        self.route_render == RenderTruth::Green && self.kv.status_truth() == RenderTruth::Green
    }
}

/// A local vLLM serving endpoint over a loopback bind. Prod target (Linux/GPU);
/// feature-gated (`local-vllm`); loopback only; BASE model only; KV-mode
/// route-visible. Behind the identical [`LocalModelEndpoint`] trait as the MLX dev
/// adapter (#595) — uniform route identity + evidence.
#[derive(Clone, Debug)]
pub struct VllmEndpoint {
    bind: LoopbackBind,
    identity: RouteIdentity,
    secret: SecretRefView,
    kv_mode: KvCacheMode,
    probe: VllmProbe,
    loaded: bool,
}

impl VllmEndpoint {
    /// A new vLLM endpoint bound to `bind`, serving the BASE model whose identity
    /// hashes to `base_model_hash_32`, authenticating the loopback runtime with the
    /// key reference `secret` (value never loaded). Default KV-cache mode
    /// [`KvCacheMode::Bf16`] (full-precision baseline, no canary). NO runtime is
    /// attached: the Phase-0 autonomous default fails serving closed
    /// ([`EndpointError::RuntimeUnavailable`]) until a real loopback runtime is wired
    /// (a later seam).
    #[must_use]
    pub fn new(bind: LoopbackBind, base_model_hash_32: [u8; 32], secret: SecretRefView) -> Self {
        Self {
            bind,
            identity: RouteIdentity::local_base(base_model_hash_32),
            secret,
            kv_mode: KvCacheMode::Bf16,
            probe: VllmProbe::Unreachable,
            loaded: false,
        }
    }

    /// Select the KV-cache mode. A quantized mode (FP8 / TurboQuant) stays
    /// route-visible and flags its Stage-H canary requirement via
    /// [`KvCacheModeStatus`] — it can never silently become a stable serving path
    /// (the quantized canary is #620).
    #[must_use]
    pub fn with_kv_mode(mut self, kv_mode: KvCacheMode) -> Self {
        self.kv_mode = kv_mode;
        self
    }

    /// Attach an in-process loopback double standing in for a running vLLM runtime
    /// (NO socket; the real loopback HTTP transport is a later seam). The autonomous
    /// Phase-0 path NEVER calls this — it exists so the load → stream contract is
    /// testable offline with 0 egress, and so a later stage can swap the in-process
    /// body for a real `127.0.0.1` call without changing this seam.
    #[must_use]
    pub fn with_loopback_double(mut self) -> Self {
        self.probe = VllmProbe::InProcessDouble;
        self
    }

    /// The loopback bind (always a loopback address — non-loopback never builds).
    #[must_use]
    pub fn bind(&self) -> LoopbackBind {
        self.bind
    }

    /// Whether a loopback runtime is attached (false on the Phase-0 autonomous
    /// default — serving fails closed).
    #[must_use]
    pub fn runtime_reachable(&self) -> bool {
        matches!(self.probe, VllmProbe::InProcessDouble)
    }

    /// The KV-cache mode this endpoint serves under (route-visible).
    #[must_use]
    pub fn kv_mode(&self) -> KvCacheMode {
        self.kv_mode
    }

    /// Whether this endpoint serves a *quantized canary* route — a quantized KV
    /// mode (FP8 / TurboQuant) is always canary-only and never a silently promoted
    /// stable path. Promotion to stable is gated by
    /// `PrefixCacheHitEvidence::quantized_promotable` (#620: evidence + A/B), never
    /// automatic.
    #[must_use]
    pub fn is_quantized_canary(&self) -> bool {
        self.kv_mode.is_quantized()
    }

    /// The KV-cache mode status (mode + runtime support + quality risk + canary
    /// requirement). `runtime_supported` reflects whether a loopback runtime is
    /// attached — with none, the status is a warning (never a false green).
    #[must_use]
    pub fn kv_status(&self) -> KvCacheModeStatus {
        // prefill/decode split candidacy is deferred to #618 (no over-claim here)
        KvCacheModeStatus::for_mode(self.kv_mode, self.runtime_reachable(), false)
    }

    /// The route-visible serving manifest for a generation served under `fsm` — the
    /// uniform identity + KV-mode status + route state / render. This surfaces the
    /// KV-cache mode IN the route trace (no hidden compression).
    #[must_use]
    pub fn serving_manifest(&self, fsm: &RouteFsm) -> VllmServingManifest {
        VllmServingManifest {
            identity: self.identity,
            kv: self.kv_status(),
            route_state: fsm.state(),
            route_render: fsm.effects().render,
        }
    }
}

impl LocalModelEndpoint for VllmEndpoint {
    fn load(&mut self) -> Result<LocalReadyReceipt, EndpointError> {
        if !self.runtime_reachable() {
            // Phase-0 default: no loopback runtime → fail closed (never a panic,
            // never a silent fallback to egress).
            return Err(EndpointError::RuntimeUnavailable);
        }
        if !self.identity.is_visible() {
            return Err(EndpointError::IdentityIncomplete);
        }
        self.loaded = true;
        Ok(LocalReadyReceipt {
            identity: self.identity,
            tokenizer_hash_32: crate::sha256_32(b"tokenizer:vllm-local"),
            template_hash_32: crate::sha256_32(b"template:chatml"),
            // Stage G serves BASE only — the adapter seam is empty (no fine-tune).
            adapter: AdapterSwapPoint::Empty,
            secret: self.secret,
        })
    }

    fn health(&self) -> EndpointHealth {
        match (self.probe, self.loaded) {
            // no loopback runtime is never a false green
            (VllmProbe::Unreachable, _) => EndpointHealth::Unavailable,
            (VllmProbe::InProcessDouble, false) => EndpointHealth::Unloaded,
            (VllmProbe::InProcessDouble, true) => EndpointHealth::Ready,
        }
    }

    fn route_identity(&self) -> RouteIdentity {
        self.identity
    }

    fn generate_stream(&self, prompt: &str) -> Result<GenStream, EndpointError> {
        if !self.runtime_reachable() {
            return Err(EndpointError::RuntimeUnavailable);
        }
        if !self.loaded {
            return Err(EndpointError::NotLoaded);
        }
        // Deterministic loopback chunks — a function of the prompt (not a constant
        // blob), emitted in-process with 0 socket / 0 egress. The real loopback
        // transport (the vLLM OpenAI-compatible streaming API) replaces this body in
        // a later seam; the sequencing + final-flag contract stays identical.
        let chunks = vec![
            GenChunk {
                seq_u32: 0,
                text: "[vllm:local_base] ack:".to_string(),
                final_chunk: false,
            },
            GenChunk {
                seq_u32: 1,
                text: format!("prompt_len={}", prompt.len()),
                final_chunk: false,
            },
            GenChunk {
                seq_u32: 2,
                text: " done".to_string(),
                final_chunk: true,
            },
        ];
        Ok(GenStream::from_chunks(chunks))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::commands::provider::ModelRole;
    use crate::provider::local_endpoint::Backend;
    use crate::secrets::classify_reference;
    use std::net::{IpAddr, Ipv4Addr};

    fn secret() -> SecretRefView {
        // loopback auth held as a reference only (value never loaded)
        classify_reference("vllm_local", "keychain:loopback")
    }

    fn attached() -> VllmEndpoint {
        VllmEndpoint::new(
            LoopbackBind::localhost(VLLM_DEFAULT_PORT),
            crate::sha256_32(b"base-model:naite-vllm"),
            secret(),
        )
        .with_loopback_double()
    }

    #[test]
    fn loads_base_via_vllm_then_streams() {
        let mut ep = attached();
        assert_eq!(ep.health(), EndpointHealth::Unloaded);
        let receipt = ep.load();
        assert!(
            receipt.is_ok(),
            "load must succeed once a loopback runtime is attached"
        );
        assert_eq!(ep.health(), EndpointHealth::Ready);
        if let Ok(r) = receipt {
            assert!(r.is_base_only());
            assert_eq!(r.adapter, AdapterSwapPoint::Empty);
            assert!(r.is_locked(), "identity+tokenizer+template all visible");
            assert!(r.holds_no_secret(), "receipt secret is a reference only");
        }
        let stream = ep.generate_stream("hello vllm");
        assert!(stream.is_ok());
        if let Ok(stream) = stream {
            let chunks: Vec<GenChunk> = stream.collect();
            assert_eq!(chunks.len(), 3);
            assert!(chunks[2].final_chunk, "last chunk marks final");
            assert!(chunks[1].text.contains("prompt_len=10"));
        }
    }

    #[test]
    fn uniform_route_identity_with_mlx() {
        // identical trait → uniform route identity (backend=local_base, LocalExecutor)
        let ep = attached();
        let id = ep.route_identity();
        assert_eq!(id.backend, Backend::LocalBase);
        assert_eq!(id.backend.label(), "local_base");
        assert_eq!(id.role, ModelRole::LocalExecutor);
        assert!(id.is_visible());
    }

    #[test]
    fn kv_mode_is_route_visible_default_bf16() {
        let ep = attached();
        // default BF16 — full-precision baseline, not quantized, no canary
        assert_eq!(ep.kv_mode(), KvCacheMode::Bf16);
        assert!(!ep.kv_mode().is_quantized());
        let fsm = RouteFsm::new([2u8; 32]); // starts Normal (healthy / green)
        let manifest = ep.serving_manifest(&fsm);
        // KV-mode visible in the route trace, bound to the route state
        assert_eq!(manifest.kv.mode, KvCacheMode::Bf16);
        assert!(!manifest.kv.requires_stage_h_canary);
        assert_eq!(manifest.route_state, RouteExecutionState::Normal);
        assert_eq!(
            manifest.route_render,
            RouteExecutionState::Normal.render_truth()
        );
        // BF16 on a supported (attached) runtime + healthy route = green
        assert!(manifest.is_healthy_green());
    }

    #[test]
    fn quantized_mode_is_canary_only() {
        // BF16 baseline is not a canary; FP8 / TurboQuant are canary-only.
        assert!(!attached().is_quantized_canary());
        assert!(
            attached()
                .with_kv_mode(KvCacheMode::Fp8)
                .is_quantized_canary()
        );
        assert!(
            attached()
                .with_kv_mode(KvCacheMode::TurboQuant)
                .is_quantized_canary()
        );
    }

    #[test]
    fn quantized_kv_mode_is_never_a_false_green_and_flags_canary() {
        // FP8 / TurboQuant stay route-visible, flag the Stage-H canary, and are never
        // a false green — they cannot silently become a stable serving path (#620).
        for mode in [KvCacheMode::Fp8, KvCacheMode::TurboQuant] {
            let ep = attached().with_kv_mode(mode);
            assert_eq!(ep.kv_mode(), mode);
            assert!(ep.kv_status().requires_stage_h_canary);
            let fsm = RouteFsm::new([3u8; 32]);
            let manifest = ep.serving_manifest(&fsm);
            assert!(manifest.kv.mode.is_quantized());
            assert!(
                !manifest.is_healthy_green(),
                "a quantized KV mode is never a false green"
            );
        }
    }

    #[test]
    fn unhealthy_route_is_never_a_false_green_even_with_bf16() {
        // even BF16 (green KV) is not shown green under a degraded route state.
        // fresh FSM (Normal) → Lockdown is not a flap-back, so the transition is
        // deterministic (transition rejects only an immediate reverse).
        let ep = attached(); // BF16
        let mut fsm = RouteFsm::new([4u8; 32]);
        assert!(
            fsm.transition(RouteExecutionState::Lockdown),
            "fresh Normal → Lockdown is not a flap-back"
        );
        assert_eq!(fsm.state(), RouteExecutionState::Lockdown);
        let manifest = ep.serving_manifest(&fsm);
        assert_eq!(manifest.route_render, RenderTruth::Red);
        assert!(
            !manifest.is_healthy_green(),
            "a locked route is never a false green even with BF16"
        );
    }

    #[test]
    fn missing_runtime_is_a_clean_error() {
        let mut ep = VllmEndpoint::new(
            LoopbackBind::localhost(VLLM_DEFAULT_PORT),
            crate::sha256_32(b"base-model:naite-vllm"),
            secret(),
        );
        assert!(!ep.runtime_reachable());
        assert_eq!(ep.health(), EndpointHealth::Unavailable);
        assert_eq!(ep.load().err(), Some(EndpointError::RuntimeUnavailable));
        assert_eq!(
            ep.generate_stream("x").err(),
            Some(EndpointError::RuntimeUnavailable)
        );
        // with no runtime the KV status is a warning (unsupported runtime), not green
        assert_eq!(ep.kv_status().status_truth(), RenderTruth::Yellow);
    }

    #[test]
    fn loopback_only_non_loopback_rejected() {
        assert!(LoopbackBind::new(IpAddr::V4(Ipv4Addr::LOCALHOST), VLLM_DEFAULT_PORT).is_some());
        assert!(LoopbackBind::new(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)), 443).is_none());
        let ep = attached();
        assert!(ep.bind().is_loopback());
        assert_eq!(ep.bind().port(), VLLM_DEFAULT_PORT);
    }

    #[test]
    fn generate_before_load_fails_closed() {
        // runtime attached but load() not called → fail closed, never route elsewhere
        let ep = attached();
        assert_eq!(
            ep.generate_stream("x").err(),
            Some(EndpointError::NotLoaded)
        );
    }

    // Falsifiability canary: BF16 vs FP8 produce DIFFERENT manifests (KV-mode is a
    // real, route-visible distinction) — a wrong `assert_ne` would FAIL on identical
    // manifests, and the green/not-green split proves the no-false-green logic fires.
    #[test]
    fn kv_mode_distinction_canary() {
        let bf16 = attached(); // BF16
        let fp8 = attached().with_kv_mode(KvCacheMode::Fp8);
        let fsm = RouteFsm::new([5u8; 32]);
        assert_ne!(
            bf16.serving_manifest(&fsm).kv.mode,
            fp8.serving_manifest(&fsm).kv.mode,
            "BF16 and FP8 manifests must differ (KV-mode is route-visible)"
        );
        assert!(bf16.serving_manifest(&fsm).is_healthy_green());
        assert!(!fp8.serving_manifest(&fsm).is_healthy_green());
    }
}
