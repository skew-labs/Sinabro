//! Web3 RPC reader — the agent's owner-armed CHAIN READ (E10-3b). Threat model:
//! `ops/evidence/stage_g/agent_loop/WEB3_RPC_READER_THREAT_MODEL.md` (IV-W3R1..IV-W3R9).
//!
//! # The one place sinabro dials a chain RPC endpoint (READ-ONLY)
//!
//! This OPENS the wall E6/E10 keep `(deny network*)` — but only a BOUNDED,
//! owner-armed, READ-ONLY JSON-RPC query to the OWNER'S OWN configured endpoint.
//! Unlike `web_fetch` (a free loop READ tool), the web3 reader is NOT a loop tool:
//! the only entry is the owner ceremony (`daemon web3-read`), and
//! [`render_web3_read`] REQUIRES an [`EgressCapability`] witness (minted ONLY from a
//! valid owner-armed `EgressGrant`) — the model holds no constructor, so it cannot
//! self-dial a chain (IV-W3R7). The agent still "cannot reach a chain on its own".
//!
//! Parts (always-compiled unless noted):
//! * [`Web3RpcMethod`] — a READ-ONLY method allowlist (Solana + Sui). A WRITE method
//!   (`sendTransaction` / `requestAirdrop` / `sui_executeTransactionBlock`) is
//!   UNREPRESENTABLE: the enum carries no such variant, so a chain WRITE cannot be
//!   issued through this path (structural — atop `ExecProposeDeny::ChainWriteIntent`
//!   at propose-time and `CustodyCapability` uninhabited, PD-6).
//! * [`classify_rpc_endpoint`] — SSRF hygiene on the OWNER-CONFIGURED endpoint
//!   (https-only · no IP literal · no localhost-class · no embedded credentials ·
//!   fail-closed). A chain-RPC host is ALLOWED here (it is the intended target) —
//!   the inverse of `web_fetch`'s `classify_url`, which DENIES chain-RPC hosts. The
//!   endpoint comes ONLY from config (`web3_rpc_endpoint`); there is NO arbitrary-URL
//!   argument (the `chain_env` "no arbitrary endpoint" invariant, IV-W3R3).
//! * a `#[cfg(feature = "web3-egress")]` [`Web3RpcTransport`] — the only real
//!   `.send()`: a POST of the JSON-RPC body, SECRET-ZERO (NO Authorization / cookie /
//!   key / owner secret in the request), `redirect(none)` + `no_proxy()` + a per-call
//!   timeout + a response byte cap. The outbound `params` are REDACTED by
//!   [`render_web3_read`] BEFORE the send (a secret-shaped param ⇒ WITHHELD), so the
//!   SI-2 "no unredacted outbound byte" property holds via the redact() choke; the
//!   `method` is from the read-only enum (no chain WRITE).
//! * [`Web3RpcPort`] (always-compiled trait) + [`Web3RpcSeam`] so the dispatch holds
//!   ONE shape across feature combos (default build ⇒ no transport ⇒ the honest
//!   [`Web3Denied::TransportNotCompiled`]).
//!
//! The response is UNTRUSTED and passes [`redact`](crate::provider::redaction::redact)
//! before it surfaces (a secret-shaped result ⇒ WITHHELD, IV-W3R5). CUSTODY is
//! untouched: no wallet/sign/funds symbol exists here, the method allowlist blocks a
//! chain WRITE, and `CustodyCapability` is uninhabited (PD-6).

use crate::commands::authority::EgressCapability;
use crate::provider::redaction::{RedactionRequest, redact};

/// The owner-arm phrase for the web3 RPC reader ceremony (distinct audit binding).
/// The model cannot type it (IV-W3R7); only the owner-input loop supplies it.
pub const WEB3_READ_ARM_PHRASE: &str = "arm-web3-rpc-read-bounded-revocable";

/// The default per-call timeout (ms) and the response-body byte cap (IV-W3R6). An RPC
/// read is small (a balance / an account / a status), but it is still bounded.
pub const WEB3_RPC_TIMEOUT_MS: u32 = 12_000;
/// The default response-body byte cap — a read result, never a download.
pub const WEB3_RPC_BODY_CAP_BYTES: usize = 256 * 1024;

/// The READ-ONLY JSON-RPC method allowlist (Solana + Sui). The enum is the write
/// wall: a mutating method (`sendTransaction`, `requestAirdrop`,
/// `sui_executeTransactionBlock`) is simply NOT a variant — it cannot be constructed,
/// so a chain WRITE cannot be issued through this transport (structural, IV-W3R1).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Web3RpcMethod {
    /// Solana `getBalance` — lamports for an address.
    SolGetBalance,
    /// Solana `getAccountInfo` — account data for an address.
    SolGetAccountInfo,
    /// Solana `getSignatureStatuses` — confirmation status of signatures.
    SolGetSignatureStatuses,
    /// Solana `getSlot` — the current slot.
    SolGetSlot,
    /// Solana `getHealth` — node health.
    SolGetHealth,
    /// Solana `getBlockHeight` — the current block height.
    SolGetBlockHeight,
    /// Sui `suix_getBalance` — coin balance for an address.
    SuiGetBalance,
    /// Sui `sui_getObject` — an object by id.
    SuiGetObject,
    /// Sui `sui_getTransactionBlock` — a transaction block by digest.
    SuiGetTransactionBlock,
    /// Sui `sui_getLatestCheckpointSequenceNumber` — the latest checkpoint.
    SuiGetLatestCheckpoint,
}

impl Web3RpcMethod {
    /// The on-wire JSON-RPC method string (a fixed literal — never user input).
    #[must_use]
    pub const fn wire_str(self) -> &'static str {
        match self {
            Self::SolGetBalance => "getBalance",
            Self::SolGetAccountInfo => "getAccountInfo",
            Self::SolGetSignatureStatuses => "getSignatureStatuses",
            Self::SolGetSlot => "getSlot",
            Self::SolGetHealth => "getHealth",
            Self::SolGetBlockHeight => "getBlockHeight",
            Self::SuiGetBalance => "suix_getBalance",
            Self::SuiGetObject => "sui_getObject",
            Self::SuiGetTransactionBlock => "sui_getTransactionBlock",
            Self::SuiGetLatestCheckpoint => "sui_getLatestCheckpointSequenceNumber",
        }
    }

    /// The chain label (`solana` / `sui`) for the render.
    #[must_use]
    pub const fn chain(self) -> &'static str {
        match self {
            Self::SolGetBalance
            | Self::SolGetAccountInfo
            | Self::SolGetSignatureStatuses
            | Self::SolGetSlot
            | Self::SolGetHealth
            | Self::SolGetBlockHeight => "solana",
            Self::SuiGetBalance
            | Self::SuiGetObject
            | Self::SuiGetTransactionBlock
            | Self::SuiGetLatestCheckpoint => "sui",
        }
    }

    /// The stable CLI token that selects this method (the dispatch verb argument).
    #[must_use]
    pub const fn token(self) -> &'static str {
        match self {
            Self::SolGetBalance => "sol_balance",
            Self::SolGetAccountInfo => "sol_account",
            Self::SolGetSignatureStatuses => "sol_sig_status",
            Self::SolGetSlot => "sol_slot",
            Self::SolGetHealth => "sol_health",
            Self::SolGetBlockHeight => "sol_block_height",
            Self::SuiGetBalance => "sui_balance",
            Self::SuiGetObject => "sui_object",
            Self::SuiGetTransactionBlock => "sui_tx",
            Self::SuiGetLatestCheckpoint => "sui_checkpoint",
        }
    }

    /// Every read method (for the honest "available methods" render + parse).
    #[must_use]
    pub const fn all() -> [Self; 10] {
        [
            Self::SolGetBalance,
            Self::SolGetAccountInfo,
            Self::SolGetSignatureStatuses,
            Self::SolGetSlot,
            Self::SolGetHealth,
            Self::SolGetBlockHeight,
            Self::SuiGetBalance,
            Self::SuiGetObject,
            Self::SuiGetTransactionBlock,
            Self::SuiGetLatestCheckpoint,
        ]
    }

    /// Parse a CLI token into a read method (fail-closed: an unknown token — INCLUDING
    /// any write method name — yields `None`, never a guessed method, IV-W3R1).
    #[must_use]
    pub fn parse(token: &str) -> Option<Self> {
        let t = token.trim();
        Self::all().into_iter().find(|m| m.token() == t)
    }

    /// A space-joined list of every read token (for the honest usage render).
    #[must_use]
    pub fn token_list() -> String {
        Self::all()
            .iter()
            .map(|m| m.token())
            .collect::<Vec<_>>()
            .join(" ")
    }
}

/// Why a web3 RPC read was denied (fail-closed; explicit). Every denial is visible;
/// there is no silent fallback.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Web3Denied {
    /// The owner has not configured a `web3_rpc_endpoint` (nothing to dial).
    NoEndpointConfigured,
    /// The configured endpoint scheme is not `https`.
    NotHttps,
    /// The configured endpoint host is an IP literal (loopback / link-local-metadata /
    /// private range risk) — a DNS name is required.
    IpLiteralHost,
    /// The configured endpoint host is a `localhost`-class name.
    LocalHostName,
    /// The configured endpoint embeds credentials (`user:pass@host`).
    UserInfoPresent,
    /// The configured endpoint is malformed / unparsable (fail-closed).
    MalformedUrl,
    /// The CLI token did not name a known READ method (a write method is not a token).
    UnknownMethod,
    /// The outbound `params` were secret-shaped — WITHHELD before any send (IV-W3R4).
    SecretShapedParams,
    /// No web3 transport is compiled (the default build; `web3-egress` off).
    TransportNotCompiled,
    /// The transport call failed (DNS / connect / TLS / timeout / read error).
    Unreachable,
    /// The response status was not 2xx (a 3xx redirect lands here too — never followed).
    HttpStatus,
    /// The response body exceeded [`WEB3_RPC_BODY_CAP_BYTES`] (refused, never truncated).
    OverCap,
    /// The response was secret-shaped — WITHHELD before it surfaced (IV-W3R5).
    SecretShapedResult,
}

impl Web3Denied {
    /// A stable, secret-free class label (for renders + the e17 grep spine).
    #[must_use]
    pub const fn class_label(self) -> &'static str {
        match self {
            Self::NoEndpointConfigured => "web3.endpoint.not_configured",
            Self::NotHttps => "web3.endpoint.not_https",
            Self::IpLiteralHost => "web3.endpoint.ip_literal_host",
            Self::LocalHostName => "web3.endpoint.localhost_name",
            Self::UserInfoPresent => "web3.endpoint.userinfo_present",
            Self::MalformedUrl => "web3.endpoint.malformed",
            Self::UnknownMethod => "web3.method.unknown",
            Self::SecretShapedParams => "web3.params.withheld_secret",
            Self::TransportNotCompiled => "web3.transport.not_compiled",
            Self::Unreachable => "web3.transport.unreachable",
            Self::HttpStatus => "web3.transport.http_status",
            Self::OverCap => "web3.transport.over_cap",
            Self::SecretShapedResult => "web3.result.withheld_secret",
        }
    }
}

/// An endpoint that PASSED [`classify_rpc_endpoint`]. Construction is the proof: the
/// only way to make one is through the SSRF wall. Carries the URL (for the POST) and
/// the lowercased host (for renders / audit — never the full URL, which may embed a
/// query-string API key in the owner's own endpoint).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SafeRpcUrl {
    url: String,
    host: String,
}

impl SafeRpcUrl {
    /// The full URL to POST (already wall-checked, owner-configured).
    #[must_use]
    pub fn url(&self) -> &str {
        &self.url
    }

    /// The lowercased host (no port, no scheme, no query) — render/audit safe.
    #[must_use]
    pub fn host(&self) -> &str {
        &self.host
    }
}

/// Whether every dot-separated label of `host` is all-ASCII-digits (an IPv4 dotted
/// literal, a zero-padded form, or a bare decimal). Such a host is an IP literal and
/// refused — a DNS name is required so a request cannot be aimed at a numeric internal
/// address (the SSRF posture, mirrors `web_fetch::is_all_numeric_host`).
fn is_all_numeric_host(host: &str) -> bool {
    !host.is_empty()
        && host
            .split('.')
            .all(|label| !label.is_empty() && label.bytes().all(|b| b.is_ascii_digit()))
}

/// SSRF hygiene on the OWNER-CONFIGURED endpoint (IV-W3R3) — PURE, no network. Admit
/// `raw` ONLY if it is `https`, names a DNS host (no IP literal), is not a
/// `localhost`-class name, and embeds no credentials. A chain-RPC host is ALLOWED (it
/// is the intended target — the inverse of `web_fetch::classify_url`). Any parse
/// failure is fail-closed [`Web3Denied::MalformedUrl`]. There is NO arbitrary-URL
/// argument — `raw` is the config value, so this only guards owner-misconfiguration /
/// config-injection.
///
/// ```
/// use sinabro::provider::web3_rpc::{classify_rpc_endpoint, Web3Denied};
/// assert!(classify_rpc_endpoint("https://api.testnet.solana.com").is_ok());
/// assert!(classify_rpc_endpoint("https://fullnode.testnet.sui.io:443").is_ok());
/// assert_eq!(classify_rpc_endpoint("http://api.testnet.solana.com").unwrap_err(), Web3Denied::NotHttps);
/// assert_eq!(classify_rpc_endpoint("https://127.0.0.1:8899").unwrap_err(), Web3Denied::IpLiteralHost);
/// assert_eq!(classify_rpc_endpoint("https://localhost:8899").unwrap_err(), Web3Denied::LocalHostName);
/// ```
pub fn classify_rpc_endpoint(raw: &str) -> Result<SafeRpcUrl, Web3Denied> {
    let lower = raw.to_ascii_lowercase();
    let rest = match lower.strip_prefix("https://") {
        Some(_) => &raw["https://".len()..],
        None => {
            if lower.contains("://") {
                return Err(Web3Denied::NotHttps);
            }
            return Err(Web3Denied::MalformedUrl);
        }
    };
    let authority_end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
    let authority = &rest[..authority_end];
    if authority.is_empty() {
        return Err(Web3Denied::MalformedUrl);
    }
    if authority.contains('@') {
        return Err(Web3Denied::UserInfoPresent);
    }
    if authority.starts_with('[') {
        return Err(Web3Denied::IpLiteralHost);
    }
    let host = match authority.rfind(':') {
        Some(i) => &authority[..i],
        None => authority,
    };
    if host.is_empty() {
        return Err(Web3Denied::MalformedUrl);
    }
    let host_lower = host.to_ascii_lowercase();
    if is_all_numeric_host(&host_lower) {
        return Err(Web3Denied::IpLiteralHost);
    }
    if host_lower == "localhost"
        || host_lower.ends_with(".local")
        || host_lower.ends_with(".internal")
        || host_lower.ends_with(".localhost")
    {
        return Err(Web3Denied::LocalHostName);
    }
    Ok(SafeRpcUrl {
        url: raw.to_string(),
        host: host_lower,
    })
}

/// The bounded result of a permitted RPC read: the HTTP status, the host, and the
/// response body (the caller redacts it before it surfaces — IV-W3R5).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Web3RpcResponse {
    /// The HTTP status code (always 2xx here — a non-2xx is a typed deny).
    pub status_u16: u16,
    /// The lowercased host dialed.
    pub host: String,
    /// The response body (UTF-8 lossy, byte-capped). UNTRUSTED — redact before use.
    pub body: String,
}

/// The always-compiled web3 read seam — the dispatch holds this trait object so its
/// signature is feature-INDEPENDENT. The ONLY implementor is the `web3-egress`
/// [`Web3RpcTransport`]; the default build has none ⇒ the honest not-compiled deny.
pub trait Web3RpcPort {
    /// POST a JSON-RPC read to a wall-checked endpoint. `method` is from the read-only
    /// enum (no chain WRITE); `params_json` is the ALREADY-REDACTED params value. The
    /// response bytes are UNTRUSTED — [`render_web3_read`] redacts before they surface.
    fn call(
        &self,
        safe: &SafeRpcUrl,
        method: Web3RpcMethod,
        params_json: &str,
    ) -> Result<Web3RpcResponse, Web3Denied>;
}

/// The live web3 RPC transport (compiled ONLY under `web3-egress`). Holds ONE pooled
/// blocking client built with the paranoia set: `redirect(none)` + `no_proxy()` + a
/// fixed UA + the timeout. It sends NO auth header (secret-zero), issues a POST whose
/// body is the JSON-RPC envelope built from the READ-only method + the redacted params,
/// and reads a byte-capped body.
#[cfg(feature = "web3-egress")]
#[derive(Debug)]
pub struct Web3RpcTransport {
    client: reqwest::blocking::Client,
    body_cap_bytes: usize,
}

#[cfg(feature = "web3-egress")]
impl Web3RpcTransport {
    /// A transport with the given per-call `timeout_ms_u32` and response `body_cap_bytes`.
    /// Returns `None` only when the client builder itself fails (typed fail-closed).
    #[must_use]
    pub fn new(timeout_ms_u32: u32, body_cap_bytes: usize) -> Option<Self> {
        let client = reqwest::blocking::Client::builder()
            .timeout(std::time::Duration::from_millis(u64::from(timeout_ms_u32)))
            .redirect(reqwest::redirect::Policy::none())
            .no_proxy()
            .user_agent("sinabro-web3-read/1.0")
            .build()
            .ok()?;
        Some(Self {
            client,
            body_cap_bytes,
        })
    }

    /// A transport with the default timeout + body cap.
    #[must_use]
    pub fn with_defaults() -> Option<Self> {
        Self::new(WEB3_RPC_TIMEOUT_MS, WEB3_RPC_BODY_CAP_BYTES)
    }

    /// POST the JSON-RPC read. SECRET-ZERO: NO Authorization / cookie / key / owner
    /// secret in the request — only a `content-type: application/json` header and the
    /// JSON-RPC body. The body is built from the FIXED read-only `method` literal and
    /// the ALREADY-REDACTED `params_json`. `redirect(none)`, byte- + time-bounded. A
    /// 3xx / non-2xx is a typed deny; an over-cap body is refused.
    pub fn call(
        &self,
        safe: &SafeRpcUrl,
        method: Web3RpcMethod,
        params_json: &str,
    ) -> Result<Web3RpcResponse, Web3Denied> {
        let params = if params_json.trim().is_empty() {
            "[]"
        } else {
            params_json
        };
        // The body is built from the FIXED method literal + the redacted params — no
        // owner secret / memory content (the params already passed redact()).
        let body = format!(
            "{{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"{}\",\"params\":{}}}",
            method.wire_str(),
            params
        );
        let response = self
            .client
            .post(safe.url())
            .header(reqwest::header::CONTENT_TYPE, "application/json")
            .body(body)
            .send()
            .map_err(|_| Web3Denied::Unreachable)?;
        let status_u16 = response.status().as_u16();
        if !(200..300).contains(&status_u16) {
            return Err(Web3Denied::HttpStatus);
        }
        let bytes = response.bytes().map_err(|_| Web3Denied::Unreachable)?;
        if bytes.len() > self.body_cap_bytes {
            return Err(Web3Denied::OverCap);
        }
        Ok(Web3RpcResponse {
            status_u16,
            host: safe.host().to_string(),
            body: String::from_utf8_lossy(bytes.as_ref()).into_owned(),
        })
    }
}

#[cfg(feature = "web3-egress")]
impl Web3RpcPort for Web3RpcTransport {
    fn call(
        &self,
        safe: &SafeRpcUrl,
        method: Web3RpcMethod,
        params_json: &str,
    ) -> Result<Web3RpcResponse, Web3Denied> {
        // The inherent method (shadows the trait method) — not recursion.
        Web3RpcTransport::call(self, safe, method, params_json)
    }
}

/// The dispatch-threadable web3 read seam — ALWAYS compiled, feature-INDEPENDENT so
/// the dispatch signature never changes shape across builds. Under `web3-egress` it
/// owns ONE live [`Web3RpcTransport`]; in the default build it owns nothing and
/// [`Web3RpcSeam::port`] is `None` (every read is the honest not-compiled deny).
#[derive(Debug, Default)]
pub struct Web3RpcSeam {
    #[cfg(feature = "web3-egress")]
    transport: Option<Web3RpcTransport>,
}

impl Web3RpcSeam {
    /// The LIVE seam: a live transport under `web3-egress`, inert otherwise. This is
    /// what the `daemon web3-read` dispatch constructs.
    #[must_use]
    pub fn new() -> Self {
        Self {
            #[cfg(feature = "web3-egress")]
            transport: Web3RpcTransport::with_defaults(),
        }
    }

    /// An INERT seam — no transport in ANY build, so [`Web3RpcSeam::port`] is always
    /// `None` and a read is the honest not-compiled deny. Used by hermetic tests (NO
    /// network — never a live socket) and where web3 egress is intentionally absent.
    #[must_use]
    pub fn inert() -> Self {
        Self {
            #[cfg(feature = "web3-egress")]
            transport: None,
        }
    }

    /// The threaded port — `None` in the default build (no web3 socket) ⇒
    /// [`render_web3_read`] yields the honest not-compiled deny.
    #[must_use]
    pub fn port(&self) -> Option<&dyn Web3RpcPort> {
        #[cfg(feature = "web3-egress")]
        {
            self.transport.as_ref().map(|t| t as &dyn Web3RpcPort)
        }
        #[cfg(not(feature = "web3-egress"))]
        {
            None
        }
    }
}

/// The rendered outcome of a web3 RPC read: a secret-free result line + a stable class
/// label + an `ok` flag.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Web3RpcRender {
    /// The rendered, secret-free result string (the redacted result, bounded).
    pub rendered: String,
    /// A stable, secret-free class label.
    pub class_label: &'static str,
    /// Whether the read succeeded (a deny / withhold is `false`).
    pub ok: bool,
}

/// The default rendered-result cap (chars) — a read result, never a body dump.
pub const WEB3_RESULT_CHARS: usize = 2_048;

/// Whether `text` passes the canonical `redact()` secret gate as ONE fragment (no
/// secret-shaped byte). Used for BOTH the outbound params (IV-W3R4) and the inbound
/// result (IV-W3R5) — the same wall the file-read / web-fetch tools use.
fn redact_passes(text: &str) -> bool {
    let fragments = [text];
    matches!(
        redact(&RedactionRequest {
            fragments: &fragments,
            candidate_memory_ids: &[],
            deleted_ids: &[],
            include_private_memory: false,
        }),
        Ok(receipt) if receipt.secret_fragments_denied_u32() == 0
    )
}

/// The SHARED web3-read pipeline (IV-W3R1..IV-W3R9) — the one place the `daemon
/// web3-read` verb runs an RPC read. It REQUIRES an [`EgressCapability`] witness (the
/// owner-arm proof at the type level — this fn is UNREACHABLE without one, IV-W3R7).
/// Order:
///
/// 1. endpoint presence — `None` ⇒ `NoEndpointConfigured` (the owner set nothing).
/// 2. [`classify_rpc_endpoint`] — the SSRF wall on the CONFIGURED endpoint (deny ⇒
///    typed render). There is no arbitrary-URL argument (IV-W3R3).
/// 3. `redact(params)` — the OUTBOUND params pass the canonical secret gate BEFORE the
///    send; a secret-shaped param ⇒ WITHHELD (IV-W3R4). This is the SI-2 choke for the
///    POST body (the method is a fixed read-only literal).
/// 4. `port.call` — the secret-zero POST (`None` ⇒ `TransportNotCompiled`).
/// 5. `redact(response)` — the UNTRUSTED result passes the secret gate; a secret-shaped
///    result ⇒ WITHHELD (IV-W3R5).
/// 6. metadata + redacted-result render — chain / method / host / status + the bounded
///    redacted result; the full URL (which may embed an owner API key) is NEVER shown.
#[must_use]
pub fn render_web3_read(
    _cap: &EgressCapability,
    port: Option<&dyn Web3RpcPort>,
    configured_endpoint: Option<&str>,
    method: Web3RpcMethod,
    params_json: &str,
) -> Web3RpcRender {
    // 1. the owner-configured endpoint (no arbitrary URL — config only, IV-W3R3).
    let Some(endpoint) = configured_endpoint.map(str::trim).filter(|e| !e.is_empty()) else {
        return Web3RpcRender {
            rendered:
                "web3 read: no RPC endpoint configured (set web3_rpc_endpoint in config first)"
                    .to_string(),
            class_label: Web3Denied::NoEndpointConfigured.class_label(),
            ok: false,
        };
    };
    // 2. SSRF wall on the configured endpoint.
    let safe = match classify_rpc_endpoint(endpoint) {
        Ok(safe) => safe,
        Err(deny) => {
            return Web3RpcRender {
                rendered: format!(
                    "web3 read denied ({}): configured endpoint",
                    deny.class_label()
                ),
                class_label: deny.class_label(),
                ok: false,
            };
        }
    };
    // 3. the OUTBOUND params pass redact() BEFORE any send (SI-2, IV-W3R4). A
    //    secret-shaped param is WITHHELD — it never reaches the socket.
    if !redact_passes(params_json) {
        return Web3RpcRender {
            rendered: format!(
                "web3 read {}: params withheld (secret-shaped) — not sent",
                safe.host()
            ),
            class_label: Web3Denied::SecretShapedParams.class_label(),
            ok: false,
        };
    }
    // 4. the secret-zero POST. `None` port (default build) ⇒ honest not-compiled.
    let Some(port) = port else {
        return Web3RpcRender {
            rendered: format!(
                "web3 read {host} ({chain}/{method}): transport not compiled (build --features web3-egress)",
                host = safe.host(),
                chain = method.chain(),
                method = method.wire_str(),
            ),
            class_label: Web3Denied::TransportNotCompiled.class_label(),
            ok: false,
        };
    };
    let response = match port.call(&safe, method, params_json) {
        Ok(response) => response,
        Err(deny) => {
            return Web3RpcRender {
                rendered: format!("web3 read {}: denied ({})", safe.host(), deny.class_label()),
                class_label: deny.class_label(),
                ok: false,
            };
        }
    };
    // 5. redact the UNTRUSTED result BEFORE it surfaces (IV-W3R5). A secret-shaped
    //    result is WITHHELD wholesale (an RPC node could echo a secret-looking value).
    if !redact_passes(&response.body) {
        return Web3RpcRender {
            rendered: format!("web3 read {}: result withheld (secret-shaped)", safe.host()),
            class_label: Web3Denied::SecretShapedResult.class_label(),
            ok: false,
        };
    }
    // 6. metadata + redacted result (bounded; char-safe). The full URL is NEVER shown
    //    (it may carry an owner API key in its query — only the host surfaces).
    let result: String = response.body.chars().take(WEB3_RESULT_CHARS).collect();
    let rendered = format!(
        "web3 read {host} ({chain}/{method}): ok (READ-only; chain-write refused)\n\
         status={status} bytes={bytes}\n\
         result:\n{result}",
        host = safe.host(),
        chain = method.chain(),
        method = method.wire_str(),
        status = response.status_u16,
        bytes = response.body.len(),
        result = result,
    );
    Web3RpcRender {
        rendered,
        class_label: "web3.read.ok",
        ok: true,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ---- the read-only method allowlist (write methods unrepresentable) -----

    #[test]
    fn method_tokens_round_trip_and_unknown_is_none() {
        for m in Web3RpcMethod::all() {
            assert_eq!(Web3RpcMethod::parse(m.token()), Some(m), "{}", m.token());
            assert!(!m.wire_str().is_empty());
            assert!(m.chain() == "solana" || m.chain() == "sui");
        }
        // a WRITE method name is NOT a token ⇒ None (the enum has no write variant).
        for write in [
            "sendTransaction",
            "requestAirdrop",
            "sui_executeTransactionBlock",
            "transfer",
            "",
            "  ",
        ] {
            assert_eq!(Web3RpcMethod::parse(write), None, "{write}");
        }
        // the token list names every read method (for the honest usage render).
        let list = Web3RpcMethod::token_list();
        assert!(list.contains("sol_balance"));
        assert!(list.contains("sui_object"));
    }

    // ---- SSRF hygiene on the configured endpoint ----------------------------

    #[test]
    fn classify_admits_https_dns_chain_hosts() {
        // a chain-RPC host is ALLOWED here (the intended target) — the inverse of
        // web_fetch::classify_url, which DENIES it.
        for ep in [
            "https://api.testnet.solana.com",
            "https://api.mainnet-beta.solana.com",
            "https://fullnode.testnet.sui.io:443",
            "https://my-rpc.example.org/path?cluster=testnet",
        ] {
            assert!(classify_rpc_endpoint(ep).is_ok(), "{ep}");
        }
        let safe = classify_rpc_endpoint("https://API.Testnet.Solana.com:443/rpc").expect("ok");
        assert_eq!(safe.host(), "api.testnet.solana.com");
    }

    #[test]
    fn classify_denies_ssrf_endpoints() {
        for (ep, want) in [
            ("http://api.testnet.solana.com", Web3Denied::NotHttps),
            ("ftp://api.testnet.solana.com", Web3Denied::NotHttps),
            ("https://127.0.0.1:8899", Web3Denied::IpLiteralHost),
            ("https://169.254.169.254/", Web3Denied::IpLiteralHost),
            ("https://[::1]:8899", Web3Denied::IpLiteralHost),
            ("https://2130706433/", Web3Denied::IpLiteralHost),
            ("https://localhost:8899", Web3Denied::LocalHostName),
            ("https://node.internal/rpc", Web3Denied::LocalHostName),
            (
                "https://user:pass@api.testnet.solana.com",
                Web3Denied::UserInfoPresent,
            ),
            ("notaurl", Web3Denied::MalformedUrl),
            ("https://", Web3Denied::MalformedUrl),
        ] {
            assert_eq!(classify_rpc_endpoint(ep).unwrap_err(), want, "{ep}");
        }
    }

    // ---- the shared glue (scripted port; NO network) ------------------------

    struct MockPort {
        response: Result<Web3RpcResponse, Web3Denied>,
        last_params: std::cell::RefCell<String>,
    }
    impl Web3RpcPort for MockPort {
        fn call(
            &self,
            safe: &SafeRpcUrl,
            method: Web3RpcMethod,
            params_json: &str,
        ) -> Result<Web3RpcResponse, Web3Denied> {
            *self.last_params.borrow_mut() = params_json.to_string();
            // sanity: the wall passed a chain host + a read method reached us.
            assert!(!safe.host().is_empty());
            assert!(!method.wire_str().is_empty());
            self.response.clone()
        }
    }
    fn mock(response: Result<Web3RpcResponse, Web3Denied>) -> MockPort {
        MockPort {
            response,
            last_params: std::cell::RefCell::new(String::new()),
        }
    }
    fn ok_response(body: &str) -> Web3RpcResponse {
        Web3RpcResponse {
            status_u16: 200,
            host: "api.testnet.solana.com".to_string(),
            body: body.to_string(),
        }
    }

    #[test]
    fn glue_benign_read_is_ok() {
        let cap = crate::commands::authority::test_egress_capability();
        let port = mock(Ok(ok_response(
            "{\"jsonrpc\":\"2.0\",\"result\":{\"value\":12345},\"id\":1}",
        )));
        let out = render_web3_read(
            &cap,
            Some(&port),
            Some("https://api.testnet.solana.com"),
            Web3RpcMethod::SolGetBalance,
            "[\"SoMeBase58Addr\"]",
        );
        assert!(out.ok, "{}", out.rendered);
        assert_eq!(out.class_label, "web3.read.ok");
        assert!(out.rendered.contains("api.testnet.solana.com"));
        assert!(out.rendered.contains("solana/getBalance"));
        assert!(out.rendered.contains("12345"));
        // the params reached the transport unchanged (benign).
        assert_eq!(port.last_params.borrow().as_str(), "[\"SoMeBase58Addr\"]");
    }

    #[test]
    fn glue_no_endpoint_is_honest_deny() {
        let cap = crate::commands::authority::test_egress_capability();
        let port = mock(Ok(ok_response("{}")));
        for ep in [None, Some(""), Some("   ")] {
            let out = render_web3_read(&cap, Some(&port), ep, Web3RpcMethod::SolGetSlot, "[]");
            assert!(!out.ok);
            assert_eq!(out.class_label, "web3.endpoint.not_configured");
        }
    }

    #[test]
    fn glue_ssrf_endpoint_never_reaches_transport() {
        let cap = crate::commands::authority::test_egress_capability();
        // a port that PANICS if called proves the SSRF deny short-circuits.
        struct NeverPort;
        impl Web3RpcPort for NeverPort {
            fn call(
                &self,
                _s: &SafeRpcUrl,
                _m: Web3RpcMethod,
                _p: &str,
            ) -> Result<Web3RpcResponse, Web3Denied> {
                unreachable!("a denied endpoint must never reach the transport")
            }
        }
        for (ep, label) in [
            ("http://api.testnet.solana.com", "web3.endpoint.not_https"),
            ("https://127.0.0.1:8899", "web3.endpoint.ip_literal_host"),
            ("https://localhost:8899", "web3.endpoint.localhost_name"),
        ] {
            let out = render_web3_read(
                &cap,
                Some(&NeverPort),
                Some(ep),
                Web3RpcMethod::SolGetBalance,
                "[]",
            );
            assert!(!out.ok, "{ep}");
            assert_eq!(out.class_label, label, "{ep}");
        }
    }

    #[test]
    fn glue_secret_shaped_params_withheld_before_send() {
        let cap = crate::commands::authority::test_egress_capability();
        struct NeverPort;
        impl Web3RpcPort for NeverPort {
            fn call(
                &self,
                _s: &SafeRpcUrl,
                _m: Web3RpcMethod,
                _p: &str,
            ) -> Result<Web3RpcResponse, Web3Denied> {
                unreachable!("secret-shaped params must never reach the transport")
            }
        }
        // a secret-shaped params blob trips looks_like_secret on `private_key`.
        let out = render_web3_read(
            &cap,
            Some(&NeverPort),
            Some("https://api.testnet.solana.com"),
            Web3RpcMethod::SolGetAccountInfo,
            "[\"x\", {\"private_key\": \"do-not-leak-this-secret-blob-value\"}]",
        );
        assert!(!out.ok);
        assert_eq!(out.class_label, "web3.params.withheld_secret");
        assert!(!out.rendered.contains("private_key"));
    }

    #[test]
    fn glue_secret_shaped_result_withheld() {
        let cap = crate::commands::authority::test_egress_capability();
        let port = mock(Ok(ok_response(
            "node config: private_key = leaked-secret-material-do-not-surface",
        )));
        let out = render_web3_read(
            &cap,
            Some(&port),
            Some("https://api.testnet.solana.com"),
            Web3RpcMethod::SolGetHealth,
            "[]",
        );
        assert!(!out.ok);
        assert_eq!(out.class_label, "web3.result.withheld_secret");
        assert!(!out.rendered.contains("private_key"));
    }

    #[test]
    fn glue_none_port_is_honest_not_compiled() {
        let cap = crate::commands::authority::test_egress_capability();
        let out = render_web3_read(
            &cap,
            None,
            Some("https://api.testnet.solana.com"),
            Web3RpcMethod::SolGetSlot,
            "[]",
        );
        assert!(!out.ok);
        assert_eq!(out.class_label, "web3.transport.not_compiled");
        assert!(out.rendered.contains("transport not compiled"));
    }

    #[test]
    fn glue_transport_denies_pass_through() {
        let cap = crate::commands::authority::test_egress_capability();
        for (resp, label) in [
            (Err(Web3Denied::HttpStatus), "web3.transport.http_status"),
            (Err(Web3Denied::Unreachable), "web3.transport.unreachable"),
            (Err(Web3Denied::OverCap), "web3.transport.over_cap"),
        ] {
            let port = mock(resp);
            let out = render_web3_read(
                &cap,
                Some(&port),
                Some("https://api.testnet.solana.com"),
                Web3RpcMethod::SolGetSlot,
                "[]",
            );
            assert!(!out.ok);
            assert_eq!(out.class_label, label);
        }
    }

    #[test]
    fn class_labels_are_stable_and_secret_free() {
        assert_eq!(
            Web3Denied::TransportNotCompiled.class_label(),
            "web3.transport.not_compiled"
        );
        assert_eq!(
            Web3Denied::SecretShapedResult.class_label(),
            "web3.result.withheld_secret"
        );
        assert_eq!(
            Web3Denied::IpLiteralHost.class_label(),
            "web3.endpoint.ip_literal_host"
        );
    }

    #[test]
    fn seam_port_shape_matches_build() {
        let seam = Web3RpcSeam::new();
        #[cfg(not(feature = "web3-egress"))]
        assert!(seam.port().is_none(), "default build has no web3 transport");
        #[cfg(feature = "web3-egress")]
        assert!(
            seam.port().is_some(),
            "web3-egress build wires a live transport"
        );
        assert!(Web3RpcSeam::inert().port().is_none());
    }
}
