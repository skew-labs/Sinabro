//! `provider::local_chat` — the loopback OpenAI-compatible chat transport
//! (P3-3 Naite local, owner-authorized 2026-06-11).
//!
//! THE FIRST REAL LOOPBACK HTTP TRANSPORT IN THE CORE. mlx_lm.server, ollama
//! (`/v1/...`) and vLLM all speak the SAME OpenAI-compatible
//! `POST /v1/chat/completions` wire the OpenRouter codec already speaks, so
//! this module REUSES `egress::{openai_chat_body, parse_openai_chat_response,
//! extract_error_type}` byte-for-byte — no second JSON codec exists to drift.
//! New here is ONLY the loopback client wrapper. Threat model:
//! `ops/evidence/stage_g/agent_loop/LOCAL_ENDPOINT_THREAT_MODEL.md` (⑧,
//! IV-L1..L7).
//!
//! Loopback is STRUCTURAL, not policy (IV-L1): the only target type is
//! [`LoopbackBind`] (non-loopback rejected at construction), the URL is built
//! from an IP literal (no DNS ⇒ no rebinding surface), the client is built
//! with `no_proxy()` (proxy env must not route the "local" call off-box) and
//! `redirect(Policy::none())` (a malicious local server's `302 Location:
//! https://evil` is surfaced as a typed error, never followed). Plaintext
//! HTTP on loopback is the design — these runtimes serve no TLS; bytes never
//! leave the host interface.
//!
//! Secret-zero trivially: this path handles NO key — no Authorization header
//! exists in v1 (loopback runtimes default to no-auth; a key-protected
//! endpoint surfaces a typed 401 card, residual R2). The local server's
//! response is UNTRUSTED network-input regardless of locality (IV-L7):
//! serde_json parse only, typed `MalformedResponse`, sanitized error class.
//!
//! CU: ONE [`reqwest::blocking::Client`] per transport, shared across the
//! bounded loop's ≤5 turns (keep-alive — no per-turn TCP handshake).

use crate::provider::egress::{extract_error_type, openai_chat_body, parse_openai_chat_response};
use crate::provider::local_endpoint::LoopbackBind;

/// Why a local chat call failed (fail-closed; every label is static or a
/// sanitized closed-charset class — never response prose, never a key).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum LocalChatError {
    /// The loopback runtime is unreachable (connect refused / timeout / no
    /// server on the bound port).
    Unreachable,
    /// The server answered a non-200 status. Carries ONLY the status and the
    /// sanitized (alnum + `_`, ≤40 chars) error class label.
    Http {
        /// The HTTP status code.
        status_u16: u16,
        /// The sanitized error class label.
        error_type: String,
    },
    /// The 200 response body did not parse as a Chat Completions answer.
    MalformedResponse,
}

impl LocalChatError {
    /// Stable, secret-zero class label for trail/receipt rendering.
    #[must_use]
    pub fn class_label(&self) -> String {
        match self {
            Self::Unreachable => "local endpoint unreachable (loopback)".to_string(),
            Self::Http {
                status_u16,
                error_type,
            } => format!("local http status={status_u16} error_type={error_type}"),
            Self::MalformedResponse => "local response did not parse as a chat answer".to_string(),
        }
    }
}

/// The outcome of ONE permitted local chat turn: the answer text, the
/// response-echoed model id, finish reason, token usage, and the
/// request/response SHA-256 receipts (L4 replay parity with the frontier
/// card). Carries no key and no raw response body.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LocalChatOutcome {
    /// The HTTP status code (200 on this path).
    pub status_u16: u16,
    /// The model id echoed by the response (not assumed from the request).
    pub model: String,
    /// The answer: `choices[0].message.content`.
    pub answer_text: String,
    /// The response `finish_reason` (`stop`, `length`, ...).
    pub stop_reason: String,
    /// Input tokens reported (`usage.prompt_tokens`; honest 0 when absent).
    pub input_tokens: u64,
    /// Output tokens reported (`usage.completion_tokens`; honest 0 when absent).
    pub output_tokens: u64,
    /// Server-reported cached prompt tokens (OpenAI-compatible detail shape
    /// or the flat DeepSeek field; honest 0 when absent). vLLM's automatic
    /// prefix caching reports here when enabled.
    pub cached_tokens: u64,
    /// SHA-256 of the exact request body sent.
    pub request_hash_32: [u8; 32],
    /// SHA-256 of the exact response body received.
    pub response_hash_32: [u8; 32],
}

/// The loopback OpenAI-compatible chat transport. Holds the loopback-proven
/// bind, the model selector, the bounded timeout, and ONE pooled HTTP client
/// reused across the bounded loop's turns (CU: keep-alive, no per-turn
/// handshake). Construction can fail ONLY on client-builder failure (typed,
/// no panic).
#[derive(Debug)]
pub struct LocalChatTransport {
    bind: LoopbackBind,
    model: String,
    timeout_ms_u32: u32,
    client: reqwest::blocking::Client,
}

impl LocalChatTransport {
    /// A transport for the loopback endpoint `bind`, requesting `model`, with
    /// every call bounded by `timeout_ms_u32`. The client is built ONCE with
    /// the IV-L1 paranoia set: `no_proxy()` (proxy env must never route a
    /// loopback call off-box) + `redirect(Policy::none())` (redirect-exfil
    /// closed) + the timeout. Returns `None` only when the client builder
    /// itself fails (typed fail-closed, never a panic).
    #[must_use]
    pub fn new(bind: LoopbackBind, model: &str, timeout_ms_u32: u32) -> Option<Self> {
        let client = reqwest::blocking::Client::builder()
            .timeout(std::time::Duration::from_millis(u64::from(timeout_ms_u32)))
            .redirect(reqwest::redirect::Policy::none())
            .no_proxy()
            .build()
            .ok()?;
        Some(Self {
            bind,
            model: model.to_string(),
            timeout_ms_u32,
            client,
        })
    }

    /// The loopback bind (always loopback — non-loopback never constructs).
    #[must_use]
    pub const fn bind(&self) -> LoopbackBind {
        self.bind
    }

    /// The model selector sent in the request body (the RECEIPT renders the
    /// response-echoed id, never this request-side value).
    #[must_use]
    pub fn model(&self) -> &str {
        &self.model
    }

    /// The per-call timeout (ms).
    #[must_use]
    pub const fn timeout_ms(&self) -> u32 {
        self.timeout_ms_u32
    }

    /// The full loopback URL (IP literal — no DNS, no rebinding surface).
    #[must_use]
    pub fn url(&self) -> String {
        format!("http://{}/v1/chat/completions", self.bind.endpoint_label())
    }

    /// Send ONE bounded chat turn to the loopback endpoint and parse the
    /// answer. One attempt, no retry, no redirect, no proxy, no auth header
    /// (v1 — IV-L1/R2). The response bytes are UNTRUSTED (IV-L7): non-200 ⇒
    /// typed sanitized class; non-answer 200 ⇒ typed `MalformedResponse`.
    pub fn send_local_text(
        &self,
        system: &str,
        question: &str,
        max_output_tokens_u32: u32,
    ) -> Result<LocalChatOutcome, LocalChatError> {
        self.send_local_text_with(&self.model, system, question, max_output_tokens_u32)
    }

    /// Send ONE bounded chat turn requesting an EXPLICIT `model` id — the L2
    /// executor router's per-sub-task adapter selection (the R1 seam,
    /// [`crate::provider::executor_route`]). Identical to [`Self::send_local_text`]
    /// except the request-body `model` field is `model` instead of the
    /// construction-time `self.model`; the dynamic-LoRA switch is purely this
    /// per-request field (the external server hot-swaps the adapter). The RECEIPT
    /// still renders the response-echoed id, never this request-side value.
    pub fn send_local_text_with(
        &self,
        model: &str,
        system: &str,
        question: &str,
        max_output_tokens_u32: u32,
    ) -> Result<LocalChatOutcome, LocalChatError> {
        let body = openai_chat_body(model, max_output_tokens_u32, system, question);
        let request_hash_32 = crate::sha256_32(body.as_bytes());
        let response = self
            .client
            .post(self.url())
            .header("content-type", "application/json")
            .body(body)
            .send()
            .map_err(|_| LocalChatError::Unreachable)?;
        let status_u16 = response.status().as_u16();
        let bytes = response.bytes().map_err(|_| LocalChatError::Unreachable)?;
        let response_hash_32 = crate::sha256_32(bytes.as_ref());
        if status_u16 != 200 {
            return Err(LocalChatError::Http {
                status_u16,
                error_type: extract_error_type(bytes.as_ref()),
            });
        }
        let parsed =
            parse_openai_chat_response(bytes.as_ref()).ok_or(LocalChatError::MalformedResponse)?;
        Ok(LocalChatOutcome {
            status_u16,
            model: parsed.model,
            answer_text: parsed.answer_text,
            stop_reason: parsed.stop_reason,
            input_tokens: parsed.input_tokens,
            output_tokens: parsed.output_tokens,
            cached_tokens: parsed.cached_tokens,
            request_hash_32,
            response_hash_32,
        })
    }
}

/// Test-only canned loopback HTTP machinery — SHARED between this module's
/// transport tests and the dispatch-level local-consult tests (one test
/// double, no drift). A REAL `std::net::TcpListener` on `127.0.0.1:0`:
/// hermetic, deterministic, zero egress — the established real-fs (lane A) /
/// real-process (⑥ exec) test pattern extended to a real loopback socket.
#[cfg(test)]
pub(crate) mod test_support {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use std::io::{Read, Write};
    use std::net::TcpListener;

    /// A one-shot canned HTTP server on an ephemeral loopback port: accepts
    /// ONE connection, reads the request until the body is complete
    /// (Content-Length honored), replies with `canned`, and hands the raw
    /// captured request back through the returned receiver.
    pub(crate) fn canned_server(canned: String) -> (u16, std::sync::mpsc::Receiver<String>) {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind ephemeral loopback");
        let port = listener.local_addr().expect("addr").port();
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            if let Ok((mut stream, _)) = listener.accept() {
                let mut buf = Vec::new();
                let mut chunk = [0u8; 4096];
                // Read until the headers + declared body are in.
                loop {
                    match stream.read(&mut chunk) {
                        Ok(0) => break,
                        Ok(n) => {
                            buf.extend_from_slice(&chunk[..n]);
                            let text = String::from_utf8_lossy(&buf);
                            if let Some(header_end) = text.find("\r\n\r\n") {
                                let content_len = text
                                    .lines()
                                    .find_map(|line| {
                                        line.to_ascii_lowercase()
                                            .strip_prefix("content-length:")
                                            .map(|v| v.trim().parse::<usize>().unwrap_or(0))
                                    })
                                    .unwrap_or(0);
                                if buf.len() >= header_end + 4 + content_len {
                                    break;
                                }
                            }
                        }
                        Err(_) => break,
                    }
                }
                let _ = tx.send(String::from_utf8_lossy(&buf).to_string());
                let _ = stream.write_all(canned.as_bytes());
                let _ = stream.flush();
            }
        });
        (port, rx)
    }

    /// Wrap a JSON body in a canned `200 OK` response (Content-Length set).
    pub(crate) fn http_200(json_body: &str) -> String {
        format!(
            "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{json_body}",
            json_body.len()
        )
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use super::test_support::{canned_server, http_200};
    use super::*;
    use std::net::TcpListener;

    const HAPPY_JSON: &str = r#"{"model":"naite-local-7b","choices":[{"message":{"role":"assistant","content":"ANSWER: local says hi"},"finish_reason":"stop"}],"usage":{"prompt_tokens":21,"completion_tokens":7,"prompt_tokens_details":{"cached_tokens":16}}}"#;

    fn transport(port: u16) -> LocalChatTransport {
        LocalChatTransport::new(LoopbackBind::localhost(port), "default", 5_000)
            .expect("client builds")
    }

    /// Happy path over a REAL loopback socket: the canned OpenAI-compatible
    /// answer parses (model/answer/finish/usage/cached), the receipts hash
    /// the exact wire bytes, and the CAPTURED request proves (a) the
    /// system/question rode the body, (b) NO Authorization header exists
    /// (v1 sends no key — secret-zero structurally), (c) the Host is the
    /// loopback literal.
    #[test]
    fn local_happy_path_parses_and_request_is_authless() {
        let (port, captured) = canned_server(http_200(HAPPY_JSON));
        let t = transport(port);
        let outcome = t.send_local_text("you are sinabro", "what ships?", 256);
        assert!(outcome.is_ok(), "{outcome:?}");
        if let Ok(o) = outcome {
            assert_eq!(o.status_u16, 200);
            assert_eq!(o.model, "naite-local-7b");
            assert_eq!(o.answer_text, "ANSWER: local says hi");
            assert_eq!(o.stop_reason, "stop");
            assert_eq!(o.input_tokens, 21);
            assert_eq!(o.output_tokens, 7);
            assert_eq!(o.cached_tokens, 16, "vLLM-class prefix-cache report");
            assert_eq!(o.response_hash_32, crate::sha256_32(HAPPY_JSON.as_bytes()));
        }
        let request = captured.recv().expect("request captured");
        assert!(request.contains("POST /v1/chat/completions"));
        assert!(request.contains("you are sinabro"), "system in body");
        assert!(request.contains("what ships?"), "question in body");
        assert!(
            !request.to_ascii_lowercase().contains("authorization"),
            "v1 sends NO auth header (no key exists on this path)"
        );
        assert!(request.contains("host: 127.0.0.1") || request.contains("Host: 127.0.0.1"));
    }

    /// IV-L1 redirect-exfil closed: a malicious local server answering 302
    /// with an external Location is surfaced as a TYPED error — reqwest
    /// must NOT follow it (Policy::none()).
    #[test]
    fn local_redirect_is_typed_never_followed() {
        let (port, _captured) = canned_server(
            "HTTP/1.1 302 Found\r\nlocation: https://evil.example.com/exfil\r\ncontent-length: 0\r\nconnection: close\r\n\r\n"
                .to_string(),
        );
        let t = transport(port);
        let result = t.send_local_text("s", "q", 64);
        assert_eq!(
            result.err().map(|e| match e {
                LocalChatError::Http { status_u16, .. } => status_u16,
                _ => 0,
            }),
            Some(302),
            "302 must surface typed, not be followed"
        );
    }

    /// Connect-refused (no server on a fresh ephemeral port) ⇒ typed
    /// Unreachable — the fail-closed default when no runtime is up.
    #[test]
    fn local_unreachable_is_typed() {
        let port = {
            let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
            listener.local_addr().expect("addr").port()
            // listener dropped here ⇒ nothing listens on `port`
        };
        let t = transport(port);
        assert_eq!(
            t.send_local_text("s", "q", 64).err(),
            Some(LocalChatError::Unreachable)
        );
    }

    /// Non-200 with an OpenAI-shaped error body ⇒ the sanitized closed-charset
    /// class label (never response prose).
    #[test]
    fn local_http_error_is_sanitized() {
        let body = r#"{"error":{"message":"secret prose never rendered","type":"model_not_found<script>"}}"#;
        let canned = format!(
            "HTTP/1.1 404 Not Found\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
            body.len()
        );
        let (port, _captured) = canned_server(canned);
        let t = transport(port);
        let err = t.send_local_text("s", "q", 64).err();
        assert_eq!(
            err,
            Some(LocalChatError::Http {
                status_u16: 404,
                error_type: "model_not_foundscript".to_string(),
            }),
            "type sanitized to alnum+underscore; message prose dropped"
        );
    }

    /// A 200 that is not a Chat Completions answer ⇒ typed MalformedResponse
    /// (IV-L7 — local bytes are untrusted network input).
    #[test]
    fn local_malformed_200_is_typed() {
        let (port, _captured) = canned_server(http_200(r#"{"hello":"not an answer"}"#));
        let t = transport(port);
        assert_eq!(
            t.send_local_text("s", "q", 64).err(),
            Some(LocalChatError::MalformedResponse)
        );
    }

    /// IV-L1 structural loopback: the transport's only target type is
    /// LoopbackBind — a non-loopback IP never constructs one, so a remote
    /// target is unrepresentable at the type level (compile-time wall,
    /// asserted here at the value level for the record).
    #[test]
    fn non_loopback_target_unrepresentable() {
        use std::net::{IpAddr, Ipv4Addr};
        assert!(LoopbackBind::new(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)), 443).is_none());
        assert!(LoopbackBind::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 11434).is_some());
        let t = transport(1);
        assert!(t.bind().is_loopback());
        assert!(t.url().starts_with("http://127.0.0.1:1/"));
    }

    /// Error labels stay stable + secret-zero (trail/receipt contract).
    #[test]
    fn error_labels_stable() {
        assert_eq!(
            LocalChatError::Unreachable.class_label(),
            "local endpoint unreachable (loopback)"
        );
        assert_eq!(
            LocalChatError::MalformedResponse.class_label(),
            "local response did not parse as a chat answer"
        );
        assert_eq!(
            LocalChatError::Http {
                status_u16: 401,
                error_type: "auth".to_string()
            }
            .class_label(),
            "local http status=401 error_type=auth"
        );
    }

    /// P1-1 R1 seam: `send_local_text_with` places an EXPLICIT model id in the
    /// request body (the per-sub-task adapter switch) — a different id yields a
    /// different body, proving the dynamic-LoRA selector rides the wire. The
    /// construction-time `self.model` ("default") is overridden.
    #[test]
    fn send_with_explicit_model_puts_that_model_on_the_wire() {
        for id in ["naite_sui_move", "naite_solana_anchor"] {
            let (port, captured) = canned_server(http_200(HAPPY_JSON));
            let t = transport(port);
            let outcome = t.send_local_text_with(id, "sys", "impl", 128);
            assert!(outcome.is_ok(), "{outcome:?}");
            let request = captured.recv().expect("request captured");
            assert!(
                request.contains(id),
                "explicit model `{id}` must ride the request body: {request}"
            );
        }
    }
}
