//! `provider::local_endpoint` — the local base-model serving abstraction
//! (atoms #594 G.8.0, #597 G.8.3).
//!
//! Stage F minted the endpoint *config* surface
//! ([`crate::commands::model_endpoint`]: validate reachability, hold a
//! [`SecretRefView`], never spawn a job). Stage G Live-Agent adds the *serving*
//! seam: a [`LocalModelEndpoint`] trait that loads a BASE model, reports health,
//! and yields a [`GenStream`] of generated chunks. Every endpoint serves over
//! loopback only (no egress on any path in this module); the concrete MLX (#595)
//! and vLLM (#596) adapters are feature-gated and added separately.
//!
//! ENDGAME DISK-TRUTH (2026-06-12): this trait + its [`GenStream`] are
//! currently ORPHANED — `generate_stream` has ZERO production callers (whole-tree
//! grep; the MLX/vLLM `generate_stream` bodies are in-process doubles exercised
//! only by their own tests). The LIVE local-generation path is the CONSULT
//! transport ([`crate::provider::local_chat::LocalChatTransport`], a REAL loopback
//! call driven by `provider consult consult-local-naite-live`). Wiring a real
//! producer→consumer STREAMING chain (this trait → [`crate::repl::stream`]) is the
//! E7 STREAMING seam; E2 does NOT wire a producer nobody reads (no-hollow-
//! label; owner-ratified 2026-06-12). The autonomy default routes to the LIVE
//! local consult via [`crate::provider::route_select`], not this seam.
//!
//! No model weight training (`G-G-NO-TRAINING-IN-G`): a [`LocalReadyReceipt`]
//! always carries [`AdapterSwapPoint::Empty`] in Stage G — the seam Stage H fills
//! with the fine-tuned Naite adapter hash, so H is a swap-in, not a serving
//! stand-up. Secret-zero (`G-F-SECRET-ZERO`): the receipt holds only hashes,
//! enums, bools, and a [`SecretRefView`] reference (value never loaded).
//!
//! Reuse (no reinvention): [`ModelRole`] from [`crate::commands::provider`],
//! [`crate::secrets::SecretRefView`], [`crate::tui::RenderTruth`]. New here:
//! [`LocalModelEndpoint`], [`RouteIdentity`], [`LocalReadyReceipt`],
//! [`AdapterSwapPoint`].

use crate::commands::provider::ModelRole;
use crate::secrets::SecretRefView;
use crate::tui::RenderTruth;

/// The serving backend. Stage G serves exactly one identity: a local BASE model
/// (no fine-tune, no egress). External providers are reached via the bounded
/// egress path (#603), never through this trait.
#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Backend {
    /// Local base-model executor (MLX/ollama dev, vLLM prod) — no egress.
    LocalBase = 1,
}

impl Backend {
    /// The stable route-identity label rendered on every served route, so a
    /// served answer always shows `backend=local_base` (no hidden route).
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::LocalBase => "local_base",
        }
    }
}

/// The route identity stamped on every locally-served generation: which backend,
/// which base model (hash only), and the serving role. Rendered on every route so
/// a served answer always shows `backend=local_base`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RouteIdentity {
    /// The serving backend (Stage G: always [`Backend::LocalBase`]).
    pub backend: Backend,
    /// SHA-256 of the served base-model identity (visible / non-zero).
    pub base_model_hash_32: [u8; 32],
    /// The serving role — a local base model is always a
    /// [`ModelRole::LocalExecutor`].
    pub role: ModelRole,
}

impl RouteIdentity {
    /// A local-base identity for the model whose identity hashes to
    /// `base_model_hash_32`.
    #[must_use]
    pub const fn local_base(base_model_hash_32: [u8; 32]) -> Self {
        Self {
            backend: Backend::LocalBase,
            base_model_hash_32,
            role: ModelRole::LocalExecutor,
        }
    }

    /// Whether the base-model identity is visible (non-zero). A zero identity is
    /// never a healthy route.
    #[must_use]
    pub fn is_visible(&self) -> bool {
        self.base_model_hash_32 != [0u8; 32]
    }
}

/// The point at which Stage H swaps a fine-tuned Naite adapter into the live
/// serving slot. [`AdapterSwapPoint::Empty`] in Stage G (BASE only); a
/// [`AdapterSwapPoint::Present`] is never constructed in Stage G. No weight
/// training occurs in Stage G — this is a typed seam, not a trained artifact
/// (`G-G-NO-TRAINING-IN-G`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AdapterSwapPoint {
    /// No adapter — the Stage G invariant (BASE model only).
    Empty,
    /// A fine-tuned adapter identified by hash — Stage H only.
    Present([u8; 32]),
}

impl AdapterSwapPoint {
    /// Whether no adapter is present (the Stage G invariant). Always `true` for a
    /// receipt produced in Stage G.
    #[must_use]
    pub const fn is_empty(self) -> bool {
        matches!(self, Self::Empty)
    }
}

/// Readiness receipt for a loaded local base model. Built only after the model is
/// loaded and the tokenizer + chat template are locked. Carries no secret value —
/// every field is a hash, an enum, a bool, or a [`SecretRefView`] reference
/// (`G-F-SECRET-ZERO`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LocalReadyReceipt {
    /// The route identity (backend + base-model hash + role).
    pub identity: RouteIdentity,
    /// SHA-256 of the tokenizer identity (visible / non-zero).
    pub tokenizer_hash_32: [u8; 32],
    /// SHA-256 of the chat/template identity (visible / non-zero).
    pub template_hash_32: [u8; 32],
    /// The Stage H adapter seam — [`AdapterSwapPoint::Empty`] in Stage G.
    pub adapter: AdapterSwapPoint,
    /// Secret reference for the (loopback) endpoint auth — value never loaded.
    pub secret: SecretRefView,
}

impl LocalReadyReceipt {
    /// Whether this receipt proves BASE-only serving (no adapter) — the Stage G
    /// invariant.
    #[must_use]
    pub const fn is_base_only(&self) -> bool {
        self.adapter.is_empty()
    }

    /// Whether the receipt holds no secret value (the secret is a reference only;
    /// every other field is a hash/enum/bool).
    #[must_use]
    pub const fn holds_no_secret(&self) -> bool {
        self.secret.value_never_loaded
    }

    /// Whether identity + tokenizer + template are all locked (non-zero). A
    /// receipt is not ready until all three are visible.
    #[must_use]
    pub fn is_locked(&self) -> bool {
        self.identity.is_visible()
            && self.tokenizer_hash_32 != [0u8; 32]
            && self.template_hash_32 != [0u8; 32]
    }
}

/// Health of a local endpoint. Never a false green: an unloaded or unreachable
/// endpoint is not healthy.
#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EndpointHealth {
    /// Loaded and ready to serve.
    Ready = 1,
    /// Reachable but the model is not yet loaded.
    Unloaded = 2,
    /// The local runtime is unreachable (e.g. no MLX/vLLM server on loopback).
    Unavailable = 3,
}

impl EndpointHealth {
    /// The render truth — only [`EndpointHealth::Ready`] is green (no false
    /// green).
    #[must_use]
    pub const fn truth(self) -> RenderTruth {
        match self {
            Self::Ready => RenderTruth::Green,
            Self::Unloaded => RenderTruth::Yellow,
            Self::Unavailable => RenderTruth::Red,
        }
    }

    /// Whether the endpoint is loaded and ready to serve.
    #[must_use]
    pub const fn is_ready(self) -> bool {
        matches!(self, Self::Ready)
    }
}

/// A typed local-serving error. No `unwrap`/`panic`; the loop maps these to a
/// visible route state, never a silent fallback.
#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EndpointError {
    /// The local runtime is unreachable (loopback server absent).
    RuntimeUnavailable = 1,
    /// `generate_stream` was called before the model was loaded.
    NotLoaded = 2,
    /// The model identity / tokenizer / template was empty (not lockable).
    IdentityIncomplete = 3,
}

/// One generated chunk from a local endpoint. Loopback-sourced; carries its
/// sequence number and whether generation is complete. Redaction happens at the
/// surface ([`crate::repl::stream::StreamBridge`]), not here.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GenChunk {
    /// Zero-based sequence number within the generation.
    pub seq_u32: u32,
    /// The chunk text.
    pub text: String,
    /// Whether this is the final chunk of the generation.
    pub final_chunk: bool,
}

/// A pull-based stream of [`GenChunk`]s from a local endpoint. The base
/// abstraction is an in-memory iterator (loopback / test); the feature-gated
/// MLX/vLLM adapters currently feed it CANNED chunks (in-process doubles — 0
/// production caller). It implements [`Iterator`] so a future cockpit loop can
/// drive [`crate::repl::stream::StreamBridge::push_chunk`] chunk-by-chunk while
/// tools still run — but that consumer does NOT exist yet.
#[derive(Clone, Debug)]
pub struct GenStream {
    chunks: std::vec::IntoIter<GenChunk>,
}

impl GenStream {
    /// A stream over a pre-collected chunk sequence (loopback / test double / a
    /// feature-gated adapter's drained loopback buffer).
    #[must_use]
    pub fn from_chunks(chunks: Vec<GenChunk>) -> Self {
        Self {
            chunks: chunks.into_iter(),
        }
    }

    /// An empty stream (no chunks).
    #[must_use]
    pub fn empty() -> Self {
        Self::from_chunks(Vec::new())
    }
}

impl Iterator for GenStream {
    type Item = GenChunk;

    fn next(&mut self) -> Option<Self::Item> {
        self.chunks.next()
    }
}

/// The local base-model serving abstraction. One trait so MLX/ollama (dev) and
/// vLLM (prod) are interchangeable behind a uniform route identity. Serves a BASE
/// model (no fine-tune); loopback only (no egress on any path).
pub trait LocalModelEndpoint {
    /// Load the base model and lock the tokenizer + template. Returns a
    /// [`LocalReadyReceipt`] (BASE only, adapter empty) or a typed error. Must be
    /// called before [`generate_stream`](Self::generate_stream).
    fn load(&mut self) -> Result<LocalReadyReceipt, EndpointError>;

    /// Cheap health probe (target p95 ≤ 50ms). Never a false green.
    fn health(&self) -> EndpointHealth;

    /// The stable route identity (`backend=local_base`) stamped on every served
    /// generation.
    fn route_identity(&self) -> RouteIdentity;

    /// Begin a loopback generation for `prompt`. Fails closed if the model is not
    /// loaded ([`EndpointError::NotLoaded`]) — never silently routes elsewhere.
    fn generate_stream(&self, prompt: &str) -> Result<GenStream, EndpointError>;
}

/// Split serving-latency metrics for one local generation, measured *separately*
/// (the dual-compression speed law: no aggregate-one-number latency lie). Each
/// phase is its own field and there is deliberately no single collapsed "latency"
/// accessor, so a route can never claim "fast" on one blended number. These feed
/// the perf scorecard (#621) and the Stage H diet.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ServingMetrics {
    /// Time-to-first-token (ms): the queue + prefill latency until the first
    /// decoded token is emitted.
    pub ttft_ms_u32: u32,
    /// Time-per-output-token (microseconds): the steady-state decode cadence.
    pub tpot_micro_u32: u32,
    /// The largest gap between consecutive streamed chunks (ms) — a stall signal.
    pub stream_gap_max_ms_u32: u32,
    /// Queue wait before serving started (ms).
    pub queue_ms_u32: u32,
    /// Prefill (prompt-processing) time (ms).
    pub prefill_ms_u32: u32,
    /// Decode (token-generation) time (ms).
    pub decode_ms_u32: u32,
}

impl ServingMetrics {
    /// Whether the split metrics are internally consistent — the no-aggregate-lie
    /// guard. Time-to-first-token must cover at least the pre-first-token phases
    /// (queue + prefill), and decode time co-occurs with a non-zero per-token
    /// cadence (neither is a hidden zero). A route that reports one blended number,
    /// zeroing the splits, fails this check.
    #[must_use]
    pub const fn splits_consistent(self) -> bool {
        self.ttft_ms_u32 >= self.queue_ms_u32.saturating_add(self.prefill_ms_u32)
            && (self.decode_ms_u32 == 0) == (self.tpot_micro_u32 == 0)
    }
}

/// A loopback-only serving bind for a local adapter (#595 MLX/ollama,
/// #596 vLLM). Constructible only from a loopback IP (`127.0.0.0/8` or `::1`); a
/// non-loopback host is rejected, so a local adapter can never target a remote —
/// local serving stays on loopback and the bounded provider egress path (#603) is
/// the ONLY route off-box. Holds no live socket: this is the typed proof that local
/// serving is loopback, not egress. Compiled only when a local-serving adapter
/// feature (`local-mlx` or `local-vllm`) is enabled (no dead weight in the default
/// offline build).
#[cfg(any(feature = "local-mlx", feature = "local-vllm"))]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LoopbackBind {
    ip: std::net::IpAddr,
    port: u16,
}

#[cfg(any(feature = "local-mlx", feature = "local-vllm"))]
impl LoopbackBind {
    /// Bind to `ip:port`, or `None` when `ip` is not a loopback address (a
    /// non-loopback host is a remote, which local serving must never target — the
    /// structural loopback-only proof).
    #[must_use]
    pub fn new(ip: std::net::IpAddr, port: u16) -> Option<Self> {
        if ip.is_loopback() {
            Some(Self { ip, port })
        } else {
            None
        }
    }

    /// The IPv4 localhost bind (`127.0.0.1:port`) — the MLX/ollama (dev) and vLLM
    /// (prod) loopback default.
    #[must_use]
    pub const fn localhost(port: u16) -> Self {
        Self {
            ip: std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST),
            port,
        }
    }

    /// Whether the bound address is a loopback address (always `true` for a
    /// successfully constructed bind — non-loopback never builds).
    #[must_use]
    pub fn is_loopback(&self) -> bool {
        self.ip.is_loopback()
    }

    /// The bound port.
    #[must_use]
    pub const fn port(&self) -> u16 {
        self.port
    }

    /// The `ip:port` label for route rendering (loopback only).
    #[must_use]
    pub fn endpoint_label(&self) -> String {
        format!("{}:{}", self.ip, self.port)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::repl::latency::p95_ms;
    use crate::secrets::classify_reference;
    use crate::sha256_32;

    /// A deterministic loopback endpoint test double — no network, no model, no
    /// egress. Proves the trait contract (load → health → stream) offline.
    struct LoopbackEndpoint {
        loaded: bool,
        identity: RouteIdentity,
        secret: SecretRefView,
    }

    impl LoopbackEndpoint {
        fn new() -> Self {
            Self {
                loaded: false,
                identity: RouteIdentity::local_base(sha256_32(b"base-model:naite-local")),
                // loopback auth held as a reference only (value never loaded)
                secret: classify_reference("local_endpoint", "keychain:loopback"),
            }
        }
    }

    impl LocalModelEndpoint for LoopbackEndpoint {
        fn load(&mut self) -> Result<LocalReadyReceipt, EndpointError> {
            if !self.identity.is_visible() {
                return Err(EndpointError::IdentityIncomplete);
            }
            self.loaded = true;
            Ok(LocalReadyReceipt {
                identity: self.identity,
                tokenizer_hash_32: sha256_32(b"tokenizer:naite"),
                template_hash_32: sha256_32(b"template:chatml"),
                adapter: AdapterSwapPoint::Empty,
                secret: self.secret,
            })
        }

        fn health(&self) -> EndpointHealth {
            if self.loaded {
                EndpointHealth::Ready
            } else {
                EndpointHealth::Unloaded
            }
        }

        fn route_identity(&self) -> RouteIdentity {
            self.identity
        }

        fn generate_stream(&self, prompt: &str) -> Result<GenStream, EndpointError> {
            if !self.loaded {
                return Err(EndpointError::NotLoaded);
            }
            // Deterministic loopback chunks — proves sequencing + final flag. The
            // content reads the prompt length so the stream is a function of input
            // (not a constant), but emits no model / network call.
            let chunks = vec![
                GenChunk {
                    seq_u32: 0,
                    text: "[local_base] ack:".to_string(),
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

    #[test]
    fn trait_dispatches_load_health_then_stream() {
        let mut ep = LoopbackEndpoint::new();
        assert_eq!(ep.health(), EndpointHealth::Unloaded);
        let receipt = ep.load();
        assert!(receipt.is_ok(), "load must succeed for a visible identity");
        assert_eq!(ep.health(), EndpointHealth::Ready);
        let stream = ep.generate_stream("hello world");
        assert!(stream.is_ok(), "generate_stream must succeed once loaded");
    }

    #[test]
    fn generate_before_load_fails_closed() {
        let ep = LoopbackEndpoint::new();
        // no load() called → must fail closed, never silently route elsewhere
        assert_eq!(
            ep.generate_stream("x").err(),
            Some(EndpointError::NotLoaded)
        );
    }

    #[test]
    fn stream_yields_sequenced_chunks_with_final() {
        let mut ep = LoopbackEndpoint::new();
        assert!(ep.load().is_ok());
        let stream = ep.generate_stream("abc");
        assert!(stream.is_ok(), "stream must start once loaded");
        if let Ok(stream) = stream {
            let chunks: Vec<GenChunk> = stream.collect();
            assert_eq!(chunks.len(), 3);
            assert_eq!(chunks[0].seq_u32, 0);
            assert_eq!(chunks[1].seq_u32, 1);
            assert_eq!(chunks[2].seq_u32, 2);
            assert!(!chunks[0].final_chunk);
            assert!(!chunks[1].final_chunk);
            assert!(chunks[2].final_chunk, "last chunk marks final");
            // the stream is a function of the prompt (not a constant blob)
            assert!(chunks[1].text.contains("prompt_len=3"));
        }
    }

    #[test]
    fn empty_stream_yields_nothing() {
        let mut s = GenStream::empty();
        assert!(s.next().is_none());
    }

    #[test]
    fn route_identity_is_local_base() {
        let ep = LoopbackEndpoint::new();
        let id = ep.route_identity();
        assert_eq!(id.backend, Backend::LocalBase);
        assert_eq!(id.backend.label(), "local_base");
        assert_eq!(id.role, ModelRole::LocalExecutor);
        assert!(id.is_visible());
    }

    #[test]
    fn ready_receipt_requires_loaded_and_is_base_only() {
        let mut ep = LoopbackEndpoint::new();
        let receipt = ep.load();
        assert!(receipt.is_ok(), "load must succeed for a visible identity");
        if let Ok(receipt) = receipt {
            // #597: adapter None in G; swap-point typed + empty; base hash present
            assert!(receipt.is_base_only());
            assert!(receipt.adapter.is_empty());
            assert_eq!(receipt.adapter, AdapterSwapPoint::Empty);
            assert!(
                receipt.is_locked(),
                "identity+tokenizer+template all visible"
            );
            assert_ne!(receipt.identity.base_model_hash_32, [0u8; 32]);
        }
    }

    #[test]
    fn ready_receipt_holds_no_secret() {
        let mut ep = LoopbackEndpoint::new();
        let receipt = ep.load();
        assert!(receipt.is_ok(), "load must succeed");
        if let Ok(receipt) = receipt {
            // #604/#597 secret custody: the receipt's secret is a reference only
            assert!(receipt.holds_no_secret());
            assert!(receipt.secret.value_never_loaded);
        }
    }

    #[test]
    fn adapter_present_is_never_base_only() {
        // structural: a Present adapter (Stage H) is not base-only; Stage G never
        // constructs this on the load() path (proven by the receipt tests above).
        let present = AdapterSwapPoint::Present([7u8; 32]);
        assert!(!present.is_empty());
    }

    #[test]
    fn health_truth_has_no_false_green() {
        assert_eq!(EndpointHealth::Ready.truth(), RenderTruth::Green);
        assert_eq!(EndpointHealth::Unloaded.truth(), RenderTruth::Yellow);
        assert_eq!(EndpointHealth::Unavailable.truth(), RenderTruth::Red);
        assert!(EndpointHealth::Ready.is_ready());
        assert!(!EndpointHealth::Unloaded.is_ready());
    }

    #[test]
    fn serving_metrics_split_no_aggregate_lie() {
        let m = ServingMetrics {
            ttft_ms_u32: 120, // >= queue(20) + prefill(80)
            tpot_micro_u32: 8_000,
            stream_gap_max_ms_u32: 15,
            queue_ms_u32: 20,
            prefill_ms_u32: 80,
            decode_ms_u32: 240,
        };
        assert!(m.splits_consistent());
        // each split is separately visible (no single collapsed latency number)
        assert_eq!(m.queue_ms_u32, 20);
        assert_eq!(m.prefill_ms_u32, 80);
        assert_eq!(m.decode_ms_u32, 240);
        // falsifiability: a TTFT smaller than queue+prefill is an impossible split
        let lie = ServingMetrics {
            ttft_ms_u32: 5,
            ..m
        };
        assert!(!lie.splits_consistent());
        // falsifiability: decode time with a zero per-token cadence is inconsistent
        let decode_without_cadence = ServingMetrics {
            tpot_micro_u32: 0,
            ..m
        };
        assert!(!decode_without_cadence.splits_consistent());
    }

    #[test]
    fn health_probe_p95_within_50ms() {
        let mut ep = LoopbackEndpoint::new();
        assert!(ep.load().is_ok());
        let mut samples = Vec::with_capacity(256);
        for _ in 0..256 {
            let t = std::time::Instant::now();
            let h = ep.health();
            std::hint::black_box(&h);
            samples.push(t.elapsed().as_nanos() as u64);
        }
        let p95 = p95_ms(&samples) / 1_000_000;
        assert!(p95 <= 50, "health probe p95 {p95}ms exceeds 50ms budget");
    }
}
