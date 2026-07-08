//! `provider::local_mlx` — feature-gated MLX/ollama loopback adapter.
//! Apple-Silicon dev target.
//!
//! Implements [`LocalModelEndpoint`] over a `127.0.0.1` loopback MLX/ollama
//! runtime, behind the `local-mlx` cargo feature (OFF by default — the std-core
//! default build never compiles it). Loopback IPC (`127.0.0.1`) only: this is
//! LOCAL SERVING, not egress — a non-loopback target is structurally
//! unrepresentable ([`LoopbackBind`] rejects it), and the only route off-box is the
//! separate triple-gated provider egress path ([`crate::provider::egress`]).
//!
//! The autonomous default makes ZERO live calls: the loopback transport is a deferred
//! seam. A freshly constructed [`MlxEndpoint`] has NO runtime attached
//! ([`MlxProbe::Unreachable`]) so every serving call fails closed
//! ([`EndpointError::RuntimeUnavailable`]) — a clean typed error, never a panic and
//! never a silent fallback. A test attaches an in-process loopback double (no
//! socket) to exercise the load → stream contract; the real loopback HTTP transport
//! is wired in a later stage. Secret-zero: the endpoint holds a
//! [`SecretRefView`] (value never loaded) and the receipt carries only
//! hashes / enums / bools.
//!
//! Serves a BASE model only (no fine-tune): the [`LocalReadyReceipt`] always
//! carries [`AdapterSwapPoint::Empty`] (no training here); a later stage fills the
//! adapter seam.
//!
//! Reuse (no reinvention): [`LocalModelEndpoint`] + friends from
//! [`crate::provider::local_endpoint`]; [`SecretRefView`] from [`crate::secrets`].
//! New here: [`MlxEndpoint`].

use crate::provider::local_endpoint::{
    AdapterSwapPoint, EndpointError, EndpointHealth, GenChunk, GenStream, LocalModelEndpoint,
    LocalReadyReceipt, LoopbackBind, RouteIdentity,
};
use crate::secrets::SecretRefView;

/// The default ollama loopback port (MLX/ollama dev runtime).
pub const OLLAMA_DEFAULT_PORT: u16 = 11434;

/// Whether a loopback MLX/ollama runtime is reachable. The autonomous default attaches
/// NONE → serving fails closed. The real loopback HTTP transport (a call to a
/// `127.0.0.1` MLX/ollama server) is a deferred seam; a test attaches an in-process
/// double to exercise the load → stream contract with 0 socket / 0 egress.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum MlxProbe {
    /// No loopback runtime — the autonomous default. Every serving call fails closed.
    Unreachable,
    /// An in-process loopback double stands in for the runtime (no socket; the real
    /// loopback transport is a later seam). Never attached on the autonomous path.
    InProcessDouble,
}

/// A local MLX/ollama serving endpoint over a loopback bind. Dev target on Apple
/// Silicon; feature-gated (`local-mlx`); loopback only; BASE model only.
#[derive(Clone, Debug)]
pub struct MlxEndpoint {
    bind: LoopbackBind,
    identity: RouteIdentity,
    secret: SecretRefView,
    probe: MlxProbe,
    loaded: bool,
}

impl MlxEndpoint {
    /// A new MLX/ollama endpoint bound to `bind`, serving the BASE model whose
    /// identity hashes to `base_model_hash_32`, authenticating the loopback runtime
    /// with the key reference `secret` (value never loaded). NO runtime is attached:
    /// the autonomous default fails serving closed
    /// ([`EndpointError::RuntimeUnavailable`]) until a real loopback runtime is wired
    /// (a later seam).
    #[must_use]
    pub fn new(bind: LoopbackBind, base_model_hash_32: [u8; 32], secret: SecretRefView) -> Self {
        Self {
            bind,
            identity: RouteIdentity::local_base(base_model_hash_32),
            secret,
            probe: MlxProbe::Unreachable,
            loaded: false,
        }
    }

    /// The loopback bind (always a loopback address — non-loopback never builds).
    #[must_use]
    pub fn bind(&self) -> LoopbackBind {
        self.bind
    }

    /// Attach an in-process loopback double standing in for a running MLX/ollama
    /// runtime (NO socket; the real loopback HTTP transport is a later seam). The
    /// autonomous path NEVER calls this — it exists so the load → stream
    /// contract is testable offline with 0 egress, and so a later stage can swap the
    /// in-process body for a real `127.0.0.1` call without changing this seam.
    #[must_use]
    pub fn with_loopback_double(mut self) -> Self {
        self.probe = MlxProbe::InProcessDouble;
        self
    }

    /// Whether a loopback runtime is attached (false on the autonomous
    /// default — serving fails closed).
    #[must_use]
    pub fn runtime_reachable(&self) -> bool {
        matches!(self.probe, MlxProbe::InProcessDouble)
    }
}

impl LocalModelEndpoint for MlxEndpoint {
    fn load(&mut self) -> Result<LocalReadyReceipt, EndpointError> {
        if !self.runtime_reachable() {
            // Default: no loopback runtime → fail closed (never a panic,
            // never a silent fallback to egress).
            return Err(EndpointError::RuntimeUnavailable);
        }
        if !self.identity.is_visible() {
            return Err(EndpointError::IdentityIncomplete);
        }
        self.loaded = true;
        Ok(LocalReadyReceipt {
            identity: self.identity,
            tokenizer_hash_32: crate::sha256_32(b"tokenizer:mlx-local"),
            template_hash_32: crate::sha256_32(b"template:chatml"),
            // Serves BASE only — the adapter seam is empty (no fine-tune).
            adapter: AdapterSwapPoint::Empty,
            secret: self.secret,
        })
    }

    fn health(&self) -> EndpointHealth {
        match (self.probe, self.loaded) {
            // no loopback runtime is never a false green
            (MlxProbe::Unreachable, _) => EndpointHealth::Unavailable,
            (MlxProbe::InProcessDouble, false) => EndpointHealth::Unloaded,
            (MlxProbe::InProcessDouble, true) => EndpointHealth::Ready,
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
        // transport (streaming from the MLX/ollama runtime) replaces this body in a
        // later seam; the sequencing + final-flag contract stays identical.
        let chunks = vec![
            GenChunk {
                seq_u32: 0,
                text: "[mlx:local_base] ack:".to_string(),
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
    use crate::secrets::{SecretLocation, classify_reference};
    use std::net::{IpAddr, Ipv4Addr};

    fn secret() -> SecretRefView {
        // loopback auth held as a reference only (value never loaded)
        classify_reference("mlx_local", "keychain:loopback")
    }

    fn attached_endpoint() -> MlxEndpoint {
        let bind = LoopbackBind::localhost(OLLAMA_DEFAULT_PORT);
        MlxEndpoint::new(bind, crate::sha256_32(b"base-model:naite-mlx"), secret())
            .with_loopback_double()
    }

    #[test]
    fn loads_base_then_streams() {
        let mut ep = attached_endpoint();
        assert_eq!(ep.health(), EndpointHealth::Unloaded);
        let receipt = ep.load();
        assert!(
            receipt.is_ok(),
            "load must succeed once a loopback runtime is attached"
        );
        assert_eq!(ep.health(), EndpointHealth::Ready);
        if let Ok(r) = receipt {
            // BASE only (adapter empty) — no fine-tune here
            assert!(r.is_base_only());
            assert_eq!(r.adapter, AdapterSwapPoint::Empty);
            assert!(r.is_locked(), "identity+tokenizer+template all visible");
        }
        let stream = ep.generate_stream("hello mlx");
        assert!(stream.is_ok(), "stream must start once loaded");
        if let Ok(stream) = stream {
            let chunks: Vec<GenChunk> = stream.collect();
            assert_eq!(chunks.len(), 3);
            assert_eq!(chunks[2].seq_u32, 2);
            assert!(chunks[2].final_chunk, "last chunk marks final");
            // the stream is a function of the prompt (len 9), not a constant
            assert!(chunks[1].text.contains("prompt_len=9"));
        }
    }

    #[test]
    fn missing_runtime_is_a_clean_error_not_a_panic() {
        // Default: no loopback runtime attached → fail closed (no panic, no
        // silent fallback to egress).
        let mut ep = MlxEndpoint::new(
            LoopbackBind::localhost(OLLAMA_DEFAULT_PORT),
            crate::sha256_32(b"base-model:naite-mlx"),
            secret(),
        );
        assert!(!ep.runtime_reachable());
        assert_eq!(ep.health(), EndpointHealth::Unavailable);
        assert_eq!(ep.load().err(), Some(EndpointError::RuntimeUnavailable));
        assert_eq!(
            ep.generate_stream("x").err(),
            Some(EndpointError::RuntimeUnavailable)
        );
    }

    #[test]
    fn loopback_only_non_loopback_rejected() {
        // a loopback host binds; a non-loopback (remote) host is structurally
        // rejected — the local adapter can never target a remote.
        assert!(LoopbackBind::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 11434).is_some());
        assert!(LoopbackBind::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 5)), 11434).is_some());
        assert!(LoopbackBind::new(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)), 443).is_none());
        assert!(LoopbackBind::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 443).is_none());
        let ep = attached_endpoint();
        assert!(ep.bind().is_loopback());
        assert_eq!(ep.bind().port(), OLLAMA_DEFAULT_PORT);
    }

    #[test]
    fn generate_before_load_fails_closed() {
        // runtime attached but load() not called → fail closed, never route elsewhere
        let ep = attached_endpoint();
        assert_eq!(
            ep.generate_stream("x").err(),
            Some(EndpointError::NotLoaded)
        );
    }

    #[test]
    fn route_identity_is_local_base() {
        let ep = attached_endpoint();
        let id = ep.route_identity();
        assert_eq!(id.backend, Backend::LocalBase);
        assert_eq!(id.backend.label(), "local_base");
        assert_eq!(id.role, ModelRole::LocalExecutor);
        assert!(id.is_visible());
    }

    #[test]
    fn receipt_is_secret_zero() {
        let mut ep = attached_endpoint();
        let r = ep.load();
        assert!(r.is_ok());
        if let Ok(r) = r {
            // the receipt's secret is a reference only (value never loaded)
            assert!(r.holds_no_secret());
            assert!(r.secret.value_never_loaded);
            assert_eq!(r.secret.location, SecretLocation::Keychain);
        }
    }

    // Falsifiability canary: a DIFFERENT prompt yields a DIFFERENT stream (the body
    // is a function of input, not a constant), proving the harness can distinguish
    // behaviors — a wrong `assert_ne` here would FAIL on identical streams.
    #[test]
    fn stream_is_function_of_prompt_canary() {
        let mut ep = attached_endpoint();
        assert!(ep.load().is_ok());
        let collect = |ep: &MlxEndpoint, p: &str| -> Vec<String> {
            match ep.generate_stream(p) {
                Ok(s) => s.map(|c| c.text).collect(),
                Err(_) => Vec::new(),
            }
        };
        let a = collect(&ep, "short");
        let b = collect(&ep, "a much longer prompt here");
        assert_ne!(a, b, "different prompts must yield different streams");
        assert!(!a.is_empty(), "an attached+loaded endpoint must stream");
    }
}
