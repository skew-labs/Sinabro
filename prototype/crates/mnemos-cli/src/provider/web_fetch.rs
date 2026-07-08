//! Web fetch — the agent's LIVE web READ.
//!
//! # The one place the agent reaches the public web
//!
//! Two parts live here:
//! * an ALWAYS-COMPILED pure SSRF wall — [`classify_url`] — testable in the
//!   default build with NO network: an URL is admitted ONLY if it is `https`,
//!   names a DNS host (an IP literal is rejected — that is what would aim a
//!   request at loopback / link-local metadata / a private range), is not a
//!   `localhost`-class name, carries no embedded credentials, and is not a
//!   known chain-RPC host (custody reinforcement). Fail-closed on any parse
//!   error.
//! * a `#[cfg(feature = "web-egress")]` [`WebFetchTransport`] — the only real
//!   `.send()`: an UNAUTHENTICATED `GET` (secret-zero — no Authorization /
//!   cookie / key / owner secret), `redirect(none)` (a 302 → internal-host exfil
//!   is impossible), `no_proxy()`, a per-call timeout and a response-body
//!   byte cap. GET-only is the structural chain-WRITE wall: a JSON-RPC
//!   mutation needs a POST, which this transport cannot issue, and no wallet key
//!   exists (`CustodyCapability` uninhabited).
//!
//! The default (terminal `curl|bash`) build compiles NO transport: a
//! `TOOL: web fetch` there yields the honest [`WebFetchDenied::TransportNotCompiled`]
//! and the loop grammar stays closed. The fetched body is redacted by
//! the CALLER before it enters loop context and a web answer is
//! surfaced only through the existing `WebSourcePolicy` (source-linked,
//! quote-limited, advisory-only).

/// Why a web fetch was denied (fail-closed). Every denial is explicit + visible;
/// there is no silent fallback. The `classify_url` variants (1..6) need no
/// network; the transport variants (7..11) are feature-gated outcomes.
#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WebFetchDenied {
    /// The scheme is not `https` (no `http`, `file`, `ftp`, `gopher`, …).
    NotHttps = 1,
    /// The host is an IP literal (IPv4 dotted, all-numeric, or a `[..]` IPv6) —
    /// rejected so a request cannot be aimed at loopback / link-local-metadata /
    /// a private range. A DNS name is required.
    IpLiteralHost = 2,
    /// The host is a `localhost`-class name (`localhost`, `*.local`,
    /// `*.internal`, `*.localhost`).
    LocalHostName = 3,
    /// The authority embeds credentials (`user:pass@host`) — an SSRF/parse
    /// obfuscation vector; rejected.
    UserInfoPresent = 4,
    /// The URL is malformed / unparsable (fail-closed: a half-URL is never
    /// guessed into a target).
    MalformedUrl = 5,
    /// The host is a known chain-RPC endpoint (custody reinforcement, defense in
    /// depth atop GET-only + no-wallet-key).
    ChainRpcHost = 6,
    /// No web transport is compiled (the default offline build; the `web-egress`
    /// cargo feature is off).
    TransportNotCompiled = 7,
    /// The transport call itself failed (DNS / connect / TLS / timeout).
    Unreachable = 8,
    /// The response status was not 2xx (a 3xx redirect lands here too — we never
    /// follow it).
    HttpStatus = 9,
    /// The response body exceeded the byte cap (refused, never truncated-as-truth).
    OverCap = 10,
}

impl WebFetchDenied {
    /// A stable, secret-free class label (for renders + the e11 grep spine).
    #[must_use]
    pub const fn class_label(self) -> &'static str {
        match self {
            Self::NotHttps => "web_fetch.url.not_https",
            Self::IpLiteralHost => "web_fetch.url.ip_literal_host",
            Self::LocalHostName => "web_fetch.url.localhost_name",
            Self::UserInfoPresent => "web_fetch.url.userinfo_present",
            Self::MalformedUrl => "web_fetch.url.malformed",
            Self::ChainRpcHost => "web_fetch.url.chain_rpc_host",
            Self::TransportNotCompiled => "web_fetch.transport.not_compiled",
            Self::Unreachable => "web_fetch.transport.unreachable",
            Self::HttpStatus => "web_fetch.transport.http_status",
            Self::OverCap => "web_fetch.transport.over_cap",
        }
    }
}

/// An URL that PASSED the SSRF wall ([`classify_url`]). Construction is the proof:
/// the only way to make one is through the wall. Carries the original URL (for
/// the GET) and the lowercased host (for renders / audit).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SafeUrl {
    url: String,
    host: String,
}

impl SafeUrl {
    /// The full URL to GET (already wall-checked).
    #[must_use]
    pub fn url(&self) -> &str {
        &self.url
    }

    /// The lowercased host (no port, no scheme).
    #[must_use]
    pub fn host(&self) -> &str {
        &self.host
    }
}

/// The canonical chain-RPC hosts refused by [`classify_url`] (defense in depth —
/// the real chain-WRITE wall is GET-only + no wallet key). EXACT host match only,
/// so it never blocks doc sites (`docs.solana.com`, `sui.io`).
const CHAIN_RPC_HOSTS: &[&str] = &[
    "api.mainnet-beta.solana.com",
    "api.devnet.solana.com",
    "api.testnet.solana.com",
    "fullnode.mainnet.sui.io",
    "fullnode.testnet.sui.io",
    "fullnode.devnet.sui.io",
    "mainnet.helius-rpc.com",
    "rpc.ankr.com",
];

/// Whether every dot-separated label of `host` is all-ASCII-digits (an IPv4
/// dotted literal like `127.0.0.1`, a zero-padded `010.0.0.1`, or a bare decimal
/// `2130706433`). Such a host is treated as an IP literal and refused — a DNS
/// name is required so a request cannot be aimed at a numeric internal address.
fn is_all_numeric_host(host: &str) -> bool {
    !host.is_empty()
        && host
            .split('.')
            .all(|label| !label.is_empty() && label.bytes().all(|b| b.is_ascii_digit()))
}

/// The SSRF wall — PURE, no network. Admit `raw` ONLY if it is
/// `https`, names a DNS host (no IP literal), is not a `localhost`-class name,
/// embeds no credentials, and is not a known chain-RPC host. Any parse failure is
/// fail-closed [`WebFetchDenied::MalformedUrl`].
///
/// ```
/// use sinabro::provider::web_fetch::{classify_url, WebFetchDenied};
/// assert!(classify_url("https://docs.rs/serde/latest/serde/").is_ok());
/// assert_eq!(classify_url("http://docs.rs/").unwrap_err(), WebFetchDenied::NotHttps);
/// assert_eq!(classify_url("https://127.0.0.1/").unwrap_err(), WebFetchDenied::IpLiteralHost);
/// assert_eq!(classify_url("https://localhost/").unwrap_err(), WebFetchDenied::LocalHostName);
/// ```
pub fn classify_url(raw: &str) -> Result<SafeUrl, WebFetchDenied> {
    // Scheme: case-insensitive `https://` only (no http/file/ftp/gopher/…).
    let lower = raw.to_ascii_lowercase();
    let rest = match lower.strip_prefix("https://") {
        Some(_) => &raw["https://".len()..],
        None => {
            // Distinguish a wrong scheme (http/ftp/…) from outright garbage.
            if lower.contains("://") {
                return Err(WebFetchDenied::NotHttps);
            }
            return Err(WebFetchDenied::MalformedUrl);
        }
    };
    // Authority = up to the first path/query/fragment delimiter.
    let authority_end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
    let authority = &rest[..authority_end];
    if authority.is_empty() {
        return Err(WebFetchDenied::MalformedUrl);
    }
    // Embedded credentials (`user:pass@host`) — refused (obfuscation vector).
    if authority.contains('@') {
        return Err(WebFetchDenied::UserInfoPresent);
    }
    // IPv6 literal (`[::1]`, `[fe80::1]`) — refused (IP literal).
    if authority.starts_with('[') {
        return Err(WebFetchDenied::IpLiteralHost);
    }
    // Strip `:port` (no IPv6 ambiguity — bracketed forms already refused).
    let host = match authority.rfind(':') {
        Some(i) => &authority[..i],
        None => authority,
    };
    if host.is_empty() {
        return Err(WebFetchDenied::MalformedUrl);
    }
    let host_lower = host.to_ascii_lowercase();
    // IPv4 / all-numeric literal — refused (a DNS name is required).
    if is_all_numeric_host(&host_lower) {
        return Err(WebFetchDenied::IpLiteralHost);
    }
    // localhost-class names — refused.
    if host_lower == "localhost"
        || host_lower.ends_with(".local")
        || host_lower.ends_with(".internal")
        || host_lower.ends_with(".localhost")
    {
        return Err(WebFetchDenied::LocalHostName);
    }
    // Known chain-RPC hosts — refused (defense in depth; exact match).
    if CHAIN_RPC_HOSTS.contains(&host_lower.as_str()) {
        return Err(WebFetchDenied::ChainRpcHost);
    }
    Ok(SafeUrl {
        url: raw.to_string(),
        host: host_lower,
    })
}

/// The bounded result of a permitted web fetch: the HTTP status, the host, and
/// the response body (the CALLER redacts it before it enters loop context or any
/// render).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WebFetchResponse {
    /// The HTTP status code (always 2xx here — non-2xx is a typed deny).
    pub status_u16: u16,
    /// The lowercased host fetched.
    pub host: String,
    /// The raw response headers (the caller scans + redacts; never trusted).
    pub raw_headers: String,
    /// The response body (UTF-8 lossy, byte-capped). UNTRUSTED — redact before use.
    pub body: String,
}

/// The default per-fetch timeout (ms) and response-body byte cap.
pub const WEB_FETCH_TIMEOUT_MS: u32 = 8_000;
/// The default response-body byte cap — a research read, not a download.
pub const WEB_FETCH_BODY_CAP_BYTES: usize = 512 * 1024;

/// The live web-fetch transport (compiled ONLY under `web-egress`). Holds ONE
/// pooled blocking client built with the paranoia set:
/// `redirect(none)` + `no_proxy()` + a fixed UA + the timeout. It sends NO auth
/// header (secret-zero), issues GET only (no chain WRITE possible), and reads a
/// byte-capped body.
#[cfg(feature = "web-egress")]
#[derive(Debug)]
pub struct WebFetchTransport {
    client: reqwest::blocking::Client,
    body_cap_bytes: usize,
}

#[cfg(feature = "web-egress")]
impl WebFetchTransport {
    /// A transport with the given per-call `timeout_ms_u32` and response `body_cap_bytes`.
    /// Returns `None` only when the client builder itself fails (typed fail-closed).
    #[must_use]
    pub fn new(timeout_ms_u32: u32, body_cap_bytes: usize) -> Option<Self> {
        let client = reqwest::blocking::Client::builder()
            .timeout(std::time::Duration::from_millis(u64::from(timeout_ms_u32)))
            .redirect(reqwest::redirect::Policy::none())
            .no_proxy()
            .user_agent("sinabro-web-fetch/1.0")
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
        Self::new(WEB_FETCH_TIMEOUT_MS, WEB_FETCH_BODY_CAP_BYTES)
    }

    /// GET `safe` — UNAUTHENTICATED (no Authorization / cookie / key), no
    /// redirect, byte-capped. A 3xx (redirect) or any non-2xx is a typed deny;
    /// an over-cap body is refused. The bytes are UNTRUSTED —
    /// the caller redacts before use.
    pub fn fetch(&self, safe: &SafeUrl) -> Result<WebFetchResponse, WebFetchDenied> {
        let response = self
            .client
            .get(safe.url())
            .send()
            .map_err(|_| WebFetchDenied::Unreachable)?;
        let status_u16 = response.status().as_u16();
        // Capture headers as a flat string for the browser-credential redaction
        // belt (the caller scans them); values are never trusted.
        let mut raw_headers = String::new();
        for (name, value) in response.headers() {
            raw_headers.push_str(name.as_str());
            raw_headers.push_str(": ");
            raw_headers.push_str(value.to_str().unwrap_or("<non-ascii>"));
            raw_headers.push('\n');
        }
        if !(200..300).contains(&status_u16) {
            return Err(WebFetchDenied::HttpStatus);
        }
        let bytes = response.bytes().map_err(|_| WebFetchDenied::Unreachable)?;
        if bytes.len() > self.body_cap_bytes {
            return Err(WebFetchDenied::OverCap);
        }
        Ok(WebFetchResponse {
            status_u16,
            host: safe.host().to_string(),
            raw_headers,
            body: String::from_utf8_lossy(bytes.as_ref()).into_owned(),
        })
    }
}

// ===========================================================================
// The SHARED GLUE (loop tool + dispatch verb both call it)
// ===========================================================================

/// The always-compiled fetch seam. The loop + dispatch hold this trait object so
/// the loop signature stays feature-INDEPENDENT across every feature combo. The
/// ONLY implementor is the `web-egress` [`WebFetchTransport`]; the default build
/// has none, so a threaded `None` port is the honest
/// [`WebFetchDenied::TransportNotCompiled`] and the loop stays pure.
pub trait WebFetchPort {
    /// GET a wall-checked URL (secret-zero, redirect-none, byte-capped). The
    /// bytes are UNTRUSTED — [`render_web_fetch`] redacts before they surface.
    fn fetch(&self, safe: &SafeUrl) -> Result<WebFetchResponse, WebFetchDenied>;
}

#[cfg(feature = "web-egress")]
impl WebFetchPort for WebFetchTransport {
    fn fetch(&self, safe: &SafeUrl) -> Result<WebFetchResponse, WebFetchDenied> {
        // The inherent method (shadows the trait method) — not recursion.
        WebFetchTransport::fetch(self, safe)
    }
}

/// The loop-threadable web-fetch seam — ALWAYS compiled, feature-INDEPENDENT so
/// the loop signature never changes shape across feature builds. Under
/// `web-egress` it owns ONE live [`WebFetchTransport`]; in the default build it
/// owns nothing and [`WebFetchSeam::port`] is `None` (every fetch is the honest
/// not-compiled deny).
#[derive(Debug)]
pub struct WebFetchSeam {
    #[cfg(feature = "web-egress")]
    transport: Option<WebFetchTransport>,
}

impl Default for WebFetchSeam {
    /// `Default` == [`WebFetchSeam::new`] (the LIVE seam) so the two never drift;
    /// the INERT seam is the explicit [`WebFetchSeam::inert`].
    fn default() -> Self {
        Self::new()
    }
}

impl WebFetchSeam {
    /// The LIVE seam: a live transport under `web-egress`, inert otherwise. This
    /// is what the production consult call sites construct.
    #[must_use]
    pub fn new() -> Self {
        Self {
            #[cfg(feature = "web-egress")]
            transport: WebFetchTransport::with_defaults(),
        }
    }

    /// An INERT seam — no transport in ANY build, so [`WebFetchSeam::port`] is
    /// always `None` and the loop's `web fetch` is the honest not-compiled deny.
    /// Used where web egress is intentionally absent and by hermetic tests (NO
    /// network — never a live socket).
    #[must_use]
    pub fn inert() -> Self {
        Self {
            #[cfg(feature = "web-egress")]
            transport: None,
        }
    }

    /// The threaded port — `None` in the default build (no web socket) ⇒
    /// [`render_web_fetch`] yields the honest not-compiled deny.
    #[must_use]
    pub fn port(&self) -> Option<&dyn WebFetchPort> {
        #[cfg(feature = "web-egress")]
        {
            self.transport.as_ref().map(|t| t as &dyn WebFetchPort)
        }
        #[cfg(not(feature = "web-egress"))]
        {
            None
        }
    }
}

/// The rendered outcome of the shared web-fetch pipeline: a secret-zero result
/// line for the surface (loop tool result / dispatch render), the K-budget
/// `consumed_read` flag (true ONLY when a verified advisory entered context —
/// a deny / withhold never consumes K), and a stable class label (for
/// renders + the e11 grep spine).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WebFetchRender {
    /// The rendered, secret-free result string.
    pub rendered: String,
    /// Whether a verified advisory surfaced (the ONLY outcome that consumes K).
    pub consumed_read: bool,
    /// A stable, secret-free class label.
    pub class_label: &'static str,
}

/// The default advisory cited-quote cap (chars) when the policy does not narrow
/// it — a research read excerpt, never a page dump.
pub const WEB_FETCH_QUOTE_CHARS: u32 = 512;

/// A stable label for a [`crate::provider::web_policy::WebUseVerdict`] (the type
/// itself carries no label).
fn web_use_verdict_label(verdict: crate::provider::web_policy::WebUseVerdict) -> &'static str {
    use crate::provider::web_policy::WebUseVerdict;
    match verdict {
        WebUseVerdict::DeniedWebDisabled => "web_use.denied.web_disabled",
        WebUseVerdict::DeniedSourceless => "web_use.denied.sourceless",
        WebUseVerdict::DeniedQuoteTooLong => "web_use.denied.quote_too_long",
        WebUseVerdict::DeniedHighStakesNeedsLocalVerify => {
            "web_use.denied.high_stakes_needs_local_verify"
        }
        WebUseVerdict::AllowedAdvisory => "web_use.allowed.advisory",
    }
}

/// A bounded, char-safe echo of a raw (possibly-rejected) URL for deny renders.
fn bounded_url(raw: &str) -> String {
    raw.chars().take(160).collect()
}

/// The SHARED web-fetch pipeline — the one place the loop tool
/// and the `context web-fetch` dispatch verb agree. Pure over its inputs (the
/// `port` is the only side-effecting seam; `None` ⇒ the honest not-compiled
/// deny). Order:
///
/// 1. [`classify_url`] — the SSRF wall (deny ⇒ typed render, K NOT consumed).
/// 2. `port.fetch` — the secret-zero GET (`None` ⇒ `TransportNotCompiled`).
/// 3. [`redact`](crate::provider::redaction::redact) — the body passes the
///    canonical secret gate BEFORE it surfaces; a secret-shaped body is WITHHELD
///    exactly as the file-read tool withholds a secret-shaped file.
/// 4. [`WebResearchRecord::new`](crate::commands::tool::WebResearchRecord::new) —
///    a source-linked, hashes-only record (rights gate).
/// 5. [`WebSourcePolicy::evaluate`](crate::provider::web_policy::WebSourcePolicy::evaluate)
///    — surfaced ONLY as advisory, source-linked, quote-limited, never proof of
///    code execution. A non-advisory verdict is a typed deny.
#[must_use]
pub fn render_web_fetch(
    port: Option<&dyn WebFetchPort>,
    policy: &crate::provider::web_policy::WebSourcePolicy,
    raw_url: &str,
    retrieved_at_unix_u64: u64,
) -> WebFetchRender {
    use crate::commands::tool::{
        RightsDecision, WebFetchInputs, WebResearchPhase, WebResearchRecord,
    };
    use crate::provider::redaction::{RedactionRequest, redact};
    use crate::provider::web_policy::{WebUseInputs, WebUseVerdict};

    // 1. SSRF wall. Deny ⇒ K not consumed. The reason LEADS the
    //    line (the URL echo trails) so the class label survives the dispatch
    //    surface's 80-col clamp even for a long URL.
    let safe = match classify_url(raw_url) {
        Ok(safe) => safe,
        Err(deny) => {
            return WebFetchRender {
                rendered: format!(
                    "web fetch denied ({}): {}",
                    deny.class_label(),
                    bounded_url(raw_url)
                ),
                consumed_read: false,
                class_label: deny.class_label(),
            };
        }
    };
    // 2. The secret-zero GET. `None` port (default build) ⇒ honest not-compiled.
    let Some(port) = port else {
        return WebFetchRender {
            rendered: format!(
                "web fetch {}: web transport not compiled (build --features web-egress)",
                safe.host()
            ),
            consumed_read: false,
            class_label: WebFetchDenied::TransportNotCompiled.class_label(),
        };
    };
    let response = match port.fetch(&safe) {
        Ok(response) => response,
        Err(deny) => {
            return WebFetchRender {
                rendered: format!("web fetch {}: denied ({})", safe.host(), deny.class_label()),
                consumed_read: false,
                class_label: deny.class_label(),
            };
        }
    };
    // 3. Redact the UNTRUSTED body BEFORE it surfaces. The whole body
    //    is ONE fragment: a secret-shaped byte anywhere ⇒ the body is WITHHELD
    //    (the file-read tool's posture, applied to the fetched bytes).
    let body_text = response.body.as_str();
    let fragments = [body_text];
    let passed = matches!(
        redact(&RedactionRequest {
            fragments: &fragments,
            candidate_memory_ids: &[],
            deleted_ids: &[],
            include_private_memory: false,
        }),
        Ok(receipt) if receipt.secret_fragments_denied_u32() == 0
    );
    if !passed {
        return WebFetchRender {
            rendered: format!("web fetch {}: withheld (secret-shaped body)", safe.host()),
            consumed_read: false,
            class_label: "web_fetch.body.withheld_secret",
        };
    }
    // 4. The source-linked, quote-limited record (rights gate; hashes only). The
    //    cited span is a bounded excerpt of the gate-passed body (char-safe).
    let quote_cap = if policy.max_quote_chars_u32 == 0 {
        WEB_FETCH_QUOTE_CHARS as usize
    } else {
        policy.max_quote_chars_u32 as usize
    };
    let quote: String = body_text.chars().take(quote_cap).collect();
    let quote_len_chars_u32 = u32::try_from(quote.chars().count()).unwrap_or(u32::MAX);
    let Some(record) = WebResearchRecord::new(&WebFetchInputs {
        phase: WebResearchPhase::Fetch,
        source_url: safe.url(),
        retrieved_at_unix_u64,
        fetch_body: body_text,
        raw_headers: response.raw_headers.as_str(),
        rights: RightsDecision::Allowed,
        citation_span: &quote,
    }) else {
        return WebFetchRender {
            rendered: format!("web fetch {}: denied (rights)", safe.host()),
            consumed_read: false,
            class_label: "web_fetch.rights.denied",
        };
    };
    // 5. The operational policy gate: advisory-only, source-linked, quote-limited
    //    A non-advisory verdict is a typed deny (K not consumed).
    let verdict = policy.evaluate(&WebUseInputs {
        record: Some(&record),
        quote_len_chars_u32,
        high_stakes: false,
        local_verification_done: false,
    });
    if verdict != WebUseVerdict::AllowedAdvisory {
        return WebFetchRender {
            rendered: format!(
                "web fetch {}: denied ({})",
                safe.host(),
                web_use_verdict_label(verdict)
            ),
            consumed_read: false,
            class_label: web_use_verdict_label(verdict),
        };
    }
    let rendered = format!(
        "web fetch {host}: advisory (source-linked; verify locally; never proof of execution)\n\
         status={status} body_bytes={bytes} source={url}\n\
         quote:\n{quote}",
        host = safe.host(),
        status = response.status_u16,
        bytes = response.body.len(),
        url = safe.url(),
        quote = quote,
    );
    WebFetchRender {
        rendered,
        consumed_read: true,
        class_label: "web_fetch.advisory.allowed",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn https_dns_host_is_admitted() {
        let ok = classify_url("https://docs.rs/serde/latest/serde/").expect("admit");
        assert_eq!(ok.host(), "docs.rs");
        assert_eq!(ok.url(), "https://docs.rs/serde/latest/serde/");
        // case-insensitive scheme + host
        assert_eq!(
            classify_url("HTTPS://Docs.RS/x").expect("admit").host(),
            "docs.rs"
        );
        // port is stripped from the host
        assert_eq!(
            classify_url("https://example.com:8443/p")
                .expect("admit")
                .host(),
            "example.com"
        );
    }

    #[test]
    fn non_https_scheme_is_denied() {
        for u in [
            "http://docs.rs/",
            "ftp://host/x",
            "file:///etc/passwd",
            "gopher://host/",
        ] {
            assert_eq!(
                classify_url(u).unwrap_err(),
                WebFetchDenied::NotHttps,
                "{u}"
            );
        }
    }

    #[test]
    fn ip_literal_hosts_are_denied() {
        for u in [
            "https://127.0.0.1/",
            "https://127.0.0.1:8080/x",
            "https://169.254.169.254/latest/meta-data/", // cloud metadata
            "https://10.0.0.5/",
            "https://192.168.1.1/",
            "https://0.0.0.0/",
            "https://2130706433/",     // decimal 127.0.0.1
            "https://[::1]/",          // IPv6 loopback
            "https://[fe80::1]:443/x", // IPv6 link-local
        ] {
            assert_eq!(
                classify_url(u).unwrap_err(),
                WebFetchDenied::IpLiteralHost,
                "{u}"
            );
        }
    }

    #[test]
    fn localhost_class_names_are_denied() {
        for u in [
            "https://localhost/",
            "https://localhost:3000/x",
            "https://printer.local/",
            "https://svc.internal/x",
            "https://app.localhost/",
        ] {
            assert_eq!(
                classify_url(u).unwrap_err(),
                WebFetchDenied::LocalHostName,
                "{u}"
            );
        }
    }

    #[test]
    fn embedded_credentials_are_denied() {
        assert_eq!(
            classify_url("https://user:pass@evil.example/x").unwrap_err(),
            WebFetchDenied::UserInfoPresent
        );
        // the `@`-before-host SSRF trick (real host is after the @)
        assert_eq!(
            classify_url("https://docs.rs@127.0.0.1/x").unwrap_err(),
            WebFetchDenied::UserInfoPresent
        );
    }

    #[test]
    fn chain_rpc_hosts_are_denied_but_docs_are_not() {
        assert_eq!(
            classify_url("https://api.mainnet-beta.solana.com/").unwrap_err(),
            WebFetchDenied::ChainRpcHost
        );
        assert_eq!(
            classify_url("https://fullnode.mainnet.sui.io/").unwrap_err(),
            WebFetchDenied::ChainRpcHost
        );
        // a documentation host is NOT a chain-RPC host (exact match only)
        assert!(classify_url("https://docs.solana.com/").is_ok());
        assert!(classify_url("https://sui.io/").is_ok());
    }

    #[test]
    fn malformed_urls_are_fail_closed() {
        for u in ["", "https://", "notaurl", "https:///path"] {
            assert!(
                matches!(
                    classify_url(u),
                    Err(WebFetchDenied::MalformedUrl | WebFetchDenied::NotHttps)
                ),
                "{u}"
            );
        }
    }

    #[test]
    fn class_labels_are_stable_and_secret_free() {
        assert_eq!(
            WebFetchDenied::IpLiteralHost.class_label(),
            "web_fetch.url.ip_literal_host"
        );
        assert_eq!(
            WebFetchDenied::TransportNotCompiled.class_label(),
            "web_fetch.transport.not_compiled"
        );
    }

    // -- glue: the SHARED pipeline (loop tool + dispatch verb) ---------------

    /// A scripted port (always compiled, no network) — exercises the glue's
    /// post-fetch path (redact → record → policy) deterministically.
    struct MockPort {
        response: Result<WebFetchResponse, WebFetchDenied>,
    }
    impl WebFetchPort for MockPort {
        fn fetch(&self, _safe: &SafeUrl) -> Result<WebFetchResponse, WebFetchDenied> {
            self.response.clone()
        }
    }

    fn benign_response() -> WebFetchResponse {
        WebFetchResponse {
            status_u16: 200,
            host: "docs.rs".to_string(),
            raw_headers: "content-type: text/html".to_string(),
            body: "The serde crate is a framework for serializing Rust data.".to_string(),
        }
    }

    fn enabled_policy() -> crate::provider::web_policy::WebSourcePolicy {
        crate::provider::web_policy::WebSourcePolicy {
            web_enabled: true,
            max_quote_chars_u32: 512,
        }
    }

    #[test]
    fn glue_advisory_allowed_on_benign_body() {
        let port = MockPort {
            response: Ok(benign_response()),
        };
        let out = render_web_fetch(
            Some(&port),
            &enabled_policy(),
            "https://docs.rs/serde/",
            1_700,
        );
        assert!(out.consumed_read, "a verified advisory consumes K");
        assert_eq!(out.class_label, "web_fetch.advisory.allowed");
        assert!(out.rendered.contains("advisory"));
        assert!(out.rendered.contains("docs.rs"));
        assert!(out.rendered.contains("framework for serializing"));
    }

    #[test]
    fn glue_classify_deny_does_not_consume_k() {
        let port = MockPort {
            response: Ok(benign_response()),
        };
        for (u, label) in [
            ("http://docs.rs/", "web_fetch.url.not_https"),
            ("https://127.0.0.1/", "web_fetch.url.ip_literal_host"),
            (
                "https://api.mainnet-beta.solana.com/",
                "web_fetch.url.chain_rpc_host",
            ),
        ] {
            let out = render_web_fetch(Some(&port), &enabled_policy(), u, 0);
            assert!(!out.consumed_read, "{u}");
            assert_eq!(out.class_label, label, "{u}");
            assert!(out.rendered.contains("denied"), "{u}");
        }
    }

    #[test]
    fn glue_none_port_is_honest_not_compiled() {
        let out = render_web_fetch(None, &enabled_policy(), "https://docs.rs/", 0);
        assert!(!out.consumed_read);
        assert_eq!(out.class_label, "web_fetch.transport.not_compiled");
        assert!(out.rendered.contains("web transport not compiled"));
    }

    #[test]
    fn glue_secret_shaped_body_is_withheld() {
        let mut resp = benign_response();
        // a multi-word body trips `looks_like_secret` on the `private_key` marker.
        resp.body = "deploy config: private_key = do-not-share-this-blob".to_string();
        let port = MockPort { response: Ok(resp) };
        let out = render_web_fetch(Some(&port), &enabled_policy(), "https://docs.rs/", 0);
        assert!(!out.consumed_read, "a secret-shaped body never surfaces");
        assert_eq!(out.class_label, "web_fetch.body.withheld_secret");
        assert!(out.rendered.contains("withheld"));
        assert!(
            !out.rendered.contains("private_key"),
            "the secret-shaped body never reaches the render"
        );
    }

    #[test]
    fn glue_policy_disabled_denies_advisory_non_vacuous() {
        // The WebSourcePolicy gate is REAL: a disabled policy denies even a
        // benign fetched body (the advisory gate is not vacuous).
        let port = MockPort {
            response: Ok(benign_response()),
        };
        let disabled = crate::provider::web_policy::WebSourcePolicy::default();
        assert!(!disabled.web_enabled);
        let out = render_web_fetch(Some(&port), &disabled, "https://docs.rs/serde/", 0);
        assert!(!out.consumed_read);
        assert_eq!(out.class_label, "web_use.denied.web_disabled");
    }

    #[test]
    fn glue_transport_failure_denies_without_consuming_k() {
        let port = MockPort {
            response: Err(WebFetchDenied::HttpStatus),
        };
        let out = render_web_fetch(Some(&port), &enabled_policy(), "https://docs.rs/", 0);
        assert!(!out.consumed_read);
        assert_eq!(out.class_label, "web_fetch.transport.http_status");
    }

    #[test]
    fn seam_port_shape_matches_build() {
        // Default build (no web-egress): the seam owns no transport ⇒ port None ⇒
        // the loop's web fetch is the honest not-compiled deny. The web-egress
        // build wires a live transport ⇒ port Some.
        let seam = WebFetchSeam::new();
        #[cfg(not(feature = "web-egress"))]
        assert!(seam.port().is_none(), "default build has no web transport");
        #[cfg(feature = "web-egress")]
        assert!(
            seam.port().is_some(),
            "web-egress build wires a live transport"
        );
    }
}
