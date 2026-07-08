//! `zerog_attestation` — 0G Compute TEE attestation verify, via a Node sidecar.
//!
//! The **"TEE-verified Compute" gate**: prove a 0G Compute provider runs genuine
//! TEE-attested inference (the wedge 0G's prize tracks rewarded). 0G's attestation
//! verifier ships ONLY as the TS `@0gfoundation/0g-compute-ts-sdk`
//! (`broker.verifyService(provider)` → a dstack/TDX TEE quote + a verdict); there is no
//! Rust SDK, so this module drives a Node sidecar
//! (`prototype/sidecar/zerog-attestation/verify.js`) — exactly as drives the Go
//! storage client.
//!
//! ## funds-safe posture — keyless, no funds, no on-chain write
//! `verifyService` is READ-ONLY. The sidecar uses the SDK's read-only broker for
//! discovery and, for the verify call, an **EPHEMERAL, UNFUNDED wallet**
//! (`Wallet.createRandom`, never persisted, balance 0 ⇒ structurally cannot spend; the
//! live verify SUCCEEDED with a 0-balance wallet, proving it issues no on-chain write).
//! There is NO signer key read, NO funds, NO chain WRITE. The Rust side holds no key;
//! `CustodyCapability` stays uninhabited. The argv is FIXED (`node <verify.js>
//! [provider]`) and runs through the SAME bounded `exec_local` runner as — no shell,
//! no arbitrary command.
//!
//! The subprocess is gated behind the off-default `zerog-attestation` cargo feature (the
//! build that may spawn the external Node sidecar; honest-degrade when off). The argv
//! builder + the verdict parser are always-compiled + unit-tested via injected JSON.

/// The 0G Galileo testnet EVM RPC (chain 16602) — reused single source.
pub const ZEROG_TESTNET_EVM_RPC: &str = crate::zerog_storage::ZEROG_TESTNET_EVM_RPC;
/// Env naming the Node sidecar's `verify.js` path. The agent runs `node <verify.js>`;
/// there is NO key/funds (the sidecar is read-only). The owner/build sets this to
/// `prototype/sidecar/zerog-attestation/verify.js` after `npm install`.
pub const ZEROG_ATTESTATION_SIDECAR_ENV: &str = "ZEROG_ATTESTATION_SIDECAR";
/// Wall-clock cap for the verify subprocess (TEE collateral fetch + quote verify is slow).
pub const ZEROG_ATTEST_TIMEOUT_MS: u64 = 180_000;
/// Captured-stdout cap (the JSON verdict; the raw TEE quote can be large).
pub const ZEROG_ATTEST_STREAM_CAP_BYTES: usize = 512 * 1024;

/// A 0G compute provider address: `0x` + exactly 40 hex chars. Validated before it ever
/// enters the subprocess argv (no injection surface; the runner takes separate args, but
/// this also rejects a malformed provider early).
#[must_use]
pub fn is_valid_provider_address(s: &str) -> bool {
    let hex = match s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        Some(h) => h,
        None => return false,
    };
    hex.len() == 40 && hex.bytes().all(|b| b.is_ascii_hexdigit())
}

/// The KEYLESS verify argv: `node <verify.js> [provider]`. NO `--key`, NO signer — the
/// sidecar verifies a provider's TEE attestation read-only. A provider is included ONLY
/// when it is a valid address (else the sidecar auto-discovers one).
#[must_use]
pub fn verify_argv(node_bin: &str, verify_js: &str, provider: Option<&str>) -> Vec<String> {
    let mut argv = vec![node_bin.to_string(), verify_js.to_string()];
    if let Some(p) = provider {
        if is_valid_provider_address(p) {
            argv.push(p.to_string());
        }
    }
    argv
}

/// The parsed TEE attestation verdict (fail-closed). `verified` is true ONLY when the
/// sidecar reported `"ok": true` (which it sets from `verification.success === true`).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct AttestationVerdict {
    /// Whether the provider's TEE attestation verified.
    pub verified: bool,
    /// The TEE verifier used (e.g. `dstack`).
    pub tee_verifier: String,
    /// The verified provider address.
    pub provider: String,
    /// The provider's model (e.g. `qwen/qwen2.5-omni-7b`).
    pub model: String,
}

/// Extract a `"key":"value"` string from the sidecar's flat JSON (tolerant of spaces).
/// `None` if absent.
fn json_str_field(json: &str, key: &str) -> Option<String> {
    let needle = format!("\"{key}\"");
    let start = json.find(&needle)? + needle.len();
    let rest = json[start..].trim_start().strip_prefix(':')?.trim_start();
    let rest = rest.strip_prefix('"')?;
    let end = rest.find('"')?;
    Some(rest[..end].to_string())
}

/// Whether `"key": true` appears (tolerant of spaces). FAIL-CLOSED: missing ⇒ false.
fn json_field_is_true(json: &str, key: &str) -> bool {
    let needle = format!("\"{key}\"");
    if let Some(start) = json.find(&needle) {
        if let Some(rest) = json[start + needle.len()..].trim_start().strip_prefix(':') {
            return rest.trim_start().starts_with("true");
        }
    }
    false
}

/// Parse the sidecar's one-line JSON verdict. FAIL-CLOSED: malformed / `ok:false` / any
/// error ⇒ `verified=false`.
#[must_use]
pub fn parse_verification(json: &str) -> AttestationVerdict {
    AttestationVerdict {
        verified: json_field_is_true(json, "ok"),
        tee_verifier: json_str_field(json, "teeVerifier").unwrap_or_default(),
        provider: json_str_field(json, "provider").unwrap_or_default(),
        model: json_str_field(json, "model").unwrap_or_default(),
    }
}

/// Run the Node sidecar to verify a provider's TEE attestation (KEYLESS). Gated behind
/// `zerog-attestation` (the build that may spawn the external Node sidecar). Returns the
/// verdict, or `None` on spawn failure (fail-closed ⇒ the caller renders UNVERIFIED).
#[cfg(feature = "zerog-attestation")]
#[must_use]
pub fn run_verify(
    node_bin: &str,
    verify_js: &str,
    provider: Option<&str>,
) -> Option<AttestationVerdict> {
    let argv = verify_argv(node_bin, verify_js, provider);
    let outcome = crate::exec_local::run_argv_command_with_env(
        argv,
        ZEROG_ATTEST_TIMEOUT_MS,
        ZEROG_ATTEST_STREAM_CAP_BYTES,
        &[],
    )
    .ok()?;
    let json = String::from_utf8_lossy(&outcome.stdout.retained);
    Some(parse_verification(&json))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn provider_address_validation() {
        assert!(is_valid_provider_address(
            "0xa48f01287233509FD694a22Bf840225062E67836"
        ));
        assert!(!is_valid_provider_address(
            "a48f01287233509FD694a22Bf840225062E67836"
        )); // no 0x
        assert!(!is_valid_provider_address("0x1234")); // too short
        assert!(!is_valid_provider_address(
            "0xZZZZ01287233509FD694a22Bf840225062E67836"
        )); // non-hex
        assert!(!is_valid_provider_address(""));
    }

    #[test]
    fn verify_argv_is_keyless_and_validates_provider() {
        // no provider ⇒ `node verify.js` (sidecar auto-discovers).
        assert_eq!(
            verify_argv("node", "/s/verify.js", None),
            vec!["node".to_string(), "/s/verify.js".to_string()]
        );
        // a valid provider is appended; there is NO `--key`/signer anywhere.
        let argv = verify_argv(
            "node",
            "/s/verify.js",
            Some("0xa48f01287233509FD694a22Bf840225062E67836"),
        );
        assert_eq!(argv.len(), 3);
        assert!(
            argv.iter()
                .all(|a| !a.contains("--key") && !a.contains("private"))
        );
        // an INVALID provider is dropped (never reaches argv).
        assert_eq!(
            verify_argv("node", "/s/verify.js", Some("not-an-addr")).len(),
            2
        );
    }

    #[test]
    fn parse_verified_result() {
        // the real shape the live sidecar emits.
        let json = r#"{"ok":true,"mode":"ephemeral-wallet","provider":"0xa48f01287233509FD694a22Bf840225062E67836","model":"qwen/qwen2.5-omni-7b","verification":{"success":true,"teeVerifier":"dstack"}}"#;
        let v = parse_verification(json);
        assert!(v.verified);
        assert_eq!(v.tee_verifier, "dstack");
        assert_eq!(v.provider, "0xa48f01287233509FD694a22Bf840225062E67836");
        assert_eq!(v.model, "qwen/qwen2.5-omni-7b");
    }

    #[test]
    fn parse_is_fail_closed() {
        // ok:false ⇒ unverified.
        assert!(!parse_verification(r#"{"ok":false,"error":"no provider found"}"#).verified);
        // malformed ⇒ unverified, empty fields (no panic).
        let v = parse_verification("not json at all");
        assert!(!v.verified);
        assert!(v.tee_verifier.is_empty());
        // missing ok ⇒ unverified.
        assert!(!parse_verification(r#"{"provider":"0xabc"}"#).verified);
        // a `"ok":true` substring inside a string must still parse the real boolean form.
        assert!(parse_verification(r#"{"ok":true}"#).verified);
    }
}
