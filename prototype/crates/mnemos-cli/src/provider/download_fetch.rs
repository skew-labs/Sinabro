//! ⑲ Gated download — the agent's owner-armed bounded GET into a temp file (E13-3).
//! Threat model: `ops/evidence/stage_g/agent_loop/GATED_DOWNLOAD_THREAT_MODEL.md`
//! (IV-DL1..IV-DL8).
//!
//! # The one place the agent fetches remote bytes ONTO DISK
//!
//! This deliberately OPENS the wall E6/E10 keep `(deny network*)` — but only a
//! BOUNDED, owner-armed, GET-class download. Unlike `web_fetch` (a loop READ tool),
//! download is NOT a loop tool: the only entry is the owner ceremony (`daemon fetch`),
//! and `render_download_fetch` REQUIRES a [`FetchCapability`] witness (minted ONLY from
//! a valid owner-armed `DownloadGrant`) — the model holds no constructor, so it cannot
//! self-fetch (IV-DL7 / D-DL5).
//!
//! Parts (always-compiled unless noted):
//! * [`classify_download_url`] — the EXISTING SSRF wall [`classify_url`] (https-only ·
//!   IP-literal / localhost / userinfo / chain-RPC DENY · fail-closed) THEN an
//!   allowlist narrowing (the host must ALSO be in [`DownloadAllowlist`]). The SSRF
//!   wall is REUSED, not reinvented (IV-DL1/DL2).
//! * [`DownloadAllowlist`] — a curated `DOWNLOAD_ALLOWLIST_DEFAULT` (package/SDK hosts)
//!   `with_owner_hosts` extension; deny-by-default (IV-DL2 / D-DL4).
//! * a `#[cfg(feature = "download-egress")]` [`DownloadTransport`] — the only real
//!   `.send()`: an UNAUTHENTICATED GET (secret-zero — no Authorization / cookie / key),
//!   `redirect(none)`, `no_proxy()`, a per-call timeout, a HARD byte cap on a bounded
//!   read, then a write to ONE path under `std::env::temp_dir()` (a separator-free name
//!   — the write CANNOT escape the temp dir, IV-DL3). GET-only ⇒ no chain WRITE.
//! * [`DownloadPort`] (always-compiled trait) + [`DownloadSeam`] so the dispatch holds
//!   ONE shape across feature combos (default build ⇒ no transport ⇒ the honest
//!   [`DownloadDenied::TransportNotCompiled`]).
//!
//! The downloaded bytes are UNTRUSTED and NEVER executed; [`render_download_fetch`]
//! surfaces ONLY metadata (host / status / bytes / temp_path / sha) — never the body.
//! Any later re-egress of the file's contents passes the canonical `redact()` choke at
//! THAT surface (the file-read tool's posture), not here (IV-DL8). CUSTODY is untouched:
//! no wallet/chain/funds symbol exists here, GET-only blocks chain WRITE, and
//! `CustodyCapability` is uninhabited (PD-6).

use crate::commands::authority::FetchCapability;
use crate::provider::web_fetch::{SafeUrl, WebFetchDenied, classify_url};

/// The default per-download timeout (ms) and the HARD response byte cap (IV-DL6). A
/// download can be larger than a web read (an SDK tarball), but it is still bounded.
pub const DOWNLOAD_TIMEOUT_MS: u32 = 30_000;
/// The default response byte cap — over-cap is refused (never truncated-as-truth).
pub const DOWNLOAD_MAX_BYTES: usize = 64 * 1024 * 1024;
/// The fixed temp-file name prefix (so a produced name can never be `..` or empty).
/// Compiled only where a real write can happen (`download-egress`) or where the
/// write-confinement is tested — it has no use in the default offline build.
#[cfg(any(test, feature = "download-egress"))]
const DOWNLOAD_TEMP_PREFIX: &str = "sinabro-download-";

/// The curated default download allowlist (package / SDK registries). Layered ON the
/// SSRF wall (`classify_url`); a host must be in `default ∪ owner` to be downloaded
/// from. EXACT host match (lowercased). Owner-extended via the `config.rs` seam (D-DL4).
const DOWNLOAD_ALLOWLIST_DEFAULT: &[&str] = &[
    "crates.io",
    "static.crates.io",
    "github.com",
    "codeload.github.com",
    "objects.githubusercontent.com",
    "raw.githubusercontent.com",
    "files.pythonhosted.org",
    "registry.npmjs.org",
];

/// Why a gated download was denied (fail-closed; explicit). Every denial is visible;
/// there is no silent fallback.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DownloadDenied {
    /// The SSRF wall ([`classify_url`]) refused the URL (scheme / IP-literal /
    /// localhost / userinfo / chain-RPC / malformed) — the inner reason is carried.
    Ssrf(WebFetchDenied),
    /// The host passed the SSRF wall but is NOT in the download allowlist
    /// (deny-by-default; owner-extensible — IV-DL2).
    HostNotAllowlisted,
    /// No download transport is compiled (the default build; `download-egress` off).
    TransportNotCompiled,
    /// The transport call failed (DNS / connect / TLS / timeout / read error).
    Unreachable,
    /// The response status was not 2xx (a 3xx redirect lands here too — never followed).
    HttpStatus,
    /// The response body exceeded [`DOWNLOAD_MAX_BYTES`] (refused; nothing left on disk).
    OverSizeCap,
    /// The temp-file write failed (no bytes persisted).
    TempWriteFailed,
}

impl DownloadDenied {
    /// A stable, secret-free class label (for renders + the e15 grep spine).
    #[must_use]
    pub const fn class_label(self) -> &'static str {
        match self {
            Self::Ssrf(inner) => inner.class_label(),
            Self::HostNotAllowlisted => "download.host_not_allowlisted",
            Self::TransportNotCompiled => "download.transport.not_compiled",
            Self::Unreachable => "download.transport.unreachable",
            Self::HttpStatus => "download.transport.http_status",
            Self::OverSizeCap => "download.transport.over_size_cap",
            Self::TempWriteFailed => "download.transport.temp_write_failed",
        }
    }
}

/// The download allowlist: the curated `DOWNLOAD_ALLOWLIST_DEFAULT` plus the owner's
/// extension hosts (from the `config.rs` seam). Deny-by-default: a host is permitted
/// ONLY if it is in `default ∪ owner` (AFTER the SSRF wall already passed).
#[derive(Clone, Debug, Default)]
pub struct DownloadAllowlist {
    /// Owner-added hosts, lowercased + trimmed (from `download_allowlist` config).
    owner_hosts: Vec<String>,
}

impl DownloadAllowlist {
    /// The curated default allowlist with no owner extension (out-of-box utility).
    #[must_use]
    pub fn curated_default() -> Self {
        Self {
            owner_hosts: Vec::new(),
        }
    }

    /// The curated default extended with owner-added hosts (lowercased + trimmed;
    /// empties dropped). A malformed entry simply never matches (it is compared as a
    /// bare lowercase host against `classify_url`'s already-lowercased host).
    #[must_use]
    pub fn with_owner_hosts(hosts: &[String]) -> Self {
        let owner_hosts = hosts
            .iter()
            .map(|h| h.trim().to_ascii_lowercase())
            .filter(|h| !h.is_empty())
            .collect();
        Self { owner_hosts }
    }

    /// Whether `host` (an already-walled, lowercased DNS host) is permitted.
    #[must_use]
    pub fn permits(&self, host: &str) -> bool {
        let h = host.to_ascii_lowercase();
        DOWNLOAD_ALLOWLIST_DEFAULT.contains(&h.as_str()) || self.owner_hosts.contains(&h)
    }

    /// The number of curated-default hosts (for the honest render).
    #[must_use]
    pub fn default_count(&self) -> usize {
        DOWNLOAD_ALLOWLIST_DEFAULT.len()
    }

    /// The number of owner-added hosts (for the honest render).
    #[must_use]
    pub fn owner_count(&self) -> usize {
        self.owner_hosts.len()
    }
}

/// The SSRF wall + allowlist narrowing (IV-DL1/DL2) — PURE, no network. Admit `raw`
/// ONLY if it passes the EXISTING [`classify_url`] SSRF wall (https-only, no IP literal,
/// no localhost-class, no userinfo, no chain-RPC host, fail-closed) AND its host is in
/// the `allowlist`. The returned [`SafeUrl`] is the proof the wall passed.
///
/// ```
/// use sinabro::provider::download_fetch::{classify_download_url, DownloadAllowlist, DownloadDenied};
/// let al = DownloadAllowlist::curated_default();
/// assert!(classify_download_url("https://static.crates.io/x.crate", &al).is_ok());
/// // an SSRF-safe but non-allowlisted host is refused (deny-by-default).
/// assert_eq!(
///     classify_download_url("https://evil.example/x", &al).unwrap_err(),
///     DownloadDenied::HostNotAllowlisted
/// );
/// // a loopback host is refused by the SSRF wall BEFORE the allowlist is consulted.
/// assert!(matches!(
///     classify_download_url("https://127.0.0.1/x", &al).unwrap_err(),
///     DownloadDenied::Ssrf(_)
/// ));
/// ```
pub fn classify_download_url(
    raw: &str,
    allowlist: &DownloadAllowlist,
) -> Result<SafeUrl, DownloadDenied> {
    // 1. the EXISTING SSRF wall FIRST (IV-DL1): https-only, IP-literal / localhost /
    //    userinfo / chain-RPC DENY, fail-closed. An un-walled URL never reaches a fetch.
    let safe = classify_url(raw).map_err(DownloadDenied::Ssrf)?;
    // 2. the allowlist narrowing (IV-DL2): even an SSRF-safe host must be allowlisted.
    if !allowlist.permits(safe.host()) {
        return Err(DownloadDenied::HostNotAllowlisted);
    }
    Ok(safe)
}

/// Build the temp-file path for a download (IV-DL3) — a DIRECT child of
/// `std::env::temp_dir()` with a SEPARATOR-FREE name. The name keeps ONLY `[a-z0-9.-]`
/// from the host and ONLY hex from the content sha, wrapped in a fixed prefix + `.bin`
/// suffix, so it can NEVER contain a path separator nor be `..`/empty — the write
/// cannot escape the temp dir (not the workspace / `.ssh` / `.git`). The file name is
/// OURS, never the server's (no `Content-Disposition` naming). Compiled only where a
/// real write can happen (`download-egress`) or where the confinement is tested.
#[cfg(any(test, feature = "download-egress"))]
fn temp_path_for(host: &str, content_sha_hex: &str) -> std::path::PathBuf {
    let safe_host: String = host
        .chars()
        .filter(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || *c == '.' || *c == '-')
        .take(64)
        .collect();
    let safe_sha: String = content_sha_hex
        .chars()
        .filter(char::is_ascii_hexdigit)
        .take(16)
        .collect();
    let file_name = format!("{DOWNLOAD_TEMP_PREFIX}{safe_host}-{safe_sha}.bin");
    std::env::temp_dir().join(file_name)
}

/// The bounded, metadata-only result of a permitted download (IV-DL8). It carries NO
/// body — only the host, status, bytes written, the temp path, and the content sha.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DownloadReceipt {
    /// The lowercased host fetched.
    pub host: String,
    /// The HTTP status (always 2xx here — a non-2xx is a typed deny).
    pub status_u16: u16,
    /// The number of bytes written to the temp file.
    pub bytes_written_u64: u64,
    /// The temp-file path (a direct child of `std::env::temp_dir()`).
    pub temp_path: String,
    /// The SHA-256 (full, 64-hex) of the downloaded bytes.
    pub sha256_hex: String,
}

/// The always-compiled download seam — the dispatch holds this trait object so its
/// signature is feature-INDEPENDENT. The ONLY implementor is the `download-egress`
/// [`DownloadTransport`]; the default build has none ⇒ the honest not-compiled deny.
pub trait DownloadPort {
    /// GET a wall-checked URL (secret-zero, redirect-none, byte + time bounded) and
    /// write the UNTRUSTED bytes to a temp file. Returns metadata only — NEVER the body.
    fn fetch_to_temp(&self, safe: &SafeUrl) -> Result<DownloadReceipt, DownloadDenied>;
}

/// The live download transport (compiled ONLY under `download-egress`). Holds ONE
/// blocking client built with the IV-DL5/DL6 paranoia set: `redirect(none)` +
/// `no_proxy()` + a fixed UA + the timeout. It sends NO auth header (secret-zero),
/// issues GET only (no chain WRITE possible), reads a byte-capped body, and writes it
/// to a temp file with a separator-free name.
#[cfg(feature = "download-egress")]
#[derive(Debug)]
pub struct DownloadTransport {
    client: reqwest::blocking::Client,
    max_bytes: usize,
}

#[cfg(feature = "download-egress")]
impl DownloadTransport {
    /// A transport with the given per-call `timeout_ms_u32` and `max_bytes` cap.
    /// Returns `None` only when the client builder itself fails (typed fail-closed).
    #[must_use]
    pub fn new(timeout_ms_u32: u32, max_bytes: usize) -> Option<Self> {
        let client = reqwest::blocking::Client::builder()
            .timeout(std::time::Duration::from_millis(u64::from(timeout_ms_u32)))
            .redirect(reqwest::redirect::Policy::none())
            .no_proxy()
            .user_agent("sinabro-download/1.0")
            .build()
            .ok()?;
        Some(Self { client, max_bytes })
    }

    /// A transport with the default timeout + byte cap.
    #[must_use]
    pub fn with_defaults() -> Option<Self> {
        Self::new(DOWNLOAD_TIMEOUT_MS, DOWNLOAD_MAX_BYTES)
    }

    /// GET `safe` → temp file. UNAUTHENTICATED (no Authorization / cookie / key,
    /// IV-DL5), `redirect(none)`, byte- + time-bounded (IV-DL6). A 3xx / non-2xx is a
    /// typed deny; an over-cap body is refused (nothing left on disk). The bytes are
    /// UNTRUSTED and NEVER executed (IV-DL4/DL8) — only metadata is returned.
    pub fn fetch_to_temp(&self, safe: &SafeUrl) -> Result<DownloadReceipt, DownloadDenied> {
        use std::io::Read;
        let response = self
            .client
            .get(safe.url())
            .send()
            .map_err(|_| DownloadDenied::Unreachable)?;
        let status_u16 = response.status().as_u16();
        if !(200..300).contains(&status_u16) {
            return Err(DownloadDenied::HttpStatus);
        }
        // Bounded read (IV-DL6): read at most max_bytes+1; MORE than max_bytes ⇒ refuse
        // (no truncation-as-truth). The cap bounds both memory and disk.
        let cap_plus_one = u64::try_from(self.max_bytes)
            .unwrap_or(u64::MAX)
            .saturating_add(1);
        let mut buf: Vec<u8> = Vec::new();
        let mut limited = response.take(cap_plus_one);
        limited
            .read_to_end(&mut buf)
            .map_err(|_| DownloadDenied::Unreachable)?;
        if buf.len() > self.max_bytes {
            return Err(DownloadDenied::OverSizeCap);
        }
        // The file name is OURS (host + content sha), separator-free (IV-DL3); the
        // bytes are written but NEVER executed (IV-DL4).
        let sha32 = crate::sha256_32(&buf);
        let sha_hex = crate::hex32(&sha32);
        let path = temp_path_for(safe.host(), &sha_hex);
        std::fs::write(&path, &buf).map_err(|_| DownloadDenied::TempWriteFailed)?;
        Ok(DownloadReceipt {
            host: safe.host().to_string(),
            status_u16,
            bytes_written_u64: u64::try_from(buf.len()).unwrap_or(u64::MAX),
            temp_path: path.to_string_lossy().into_owned(),
            sha256_hex: sha_hex,
        })
    }
}

#[cfg(feature = "download-egress")]
impl DownloadPort for DownloadTransport {
    fn fetch_to_temp(&self, safe: &SafeUrl) -> Result<DownloadReceipt, DownloadDenied> {
        // The inherent method (shadows the trait method) — not recursion.
        DownloadTransport::fetch_to_temp(self, safe)
    }
}

/// The loop-/dispatch-threadable download seam — ALWAYS compiled, feature-INDEPENDENT
/// so the dispatch signature never changes shape across builds. Under `download-egress`
/// it owns ONE live [`DownloadTransport`]; in the default build it owns nothing and
/// [`DownloadSeam::port`] is `None` (every fetch is the honest not-compiled deny).
#[derive(Debug, Default)]
pub struct DownloadSeam {
    #[cfg(feature = "download-egress")]
    transport: Option<DownloadTransport>,
}

impl DownloadSeam {
    /// The LIVE seam: a live transport under `download-egress`, inert otherwise. This
    /// is what the `daemon fetch` dispatch constructs.
    #[must_use]
    pub fn new() -> Self {
        Self {
            #[cfg(feature = "download-egress")]
            transport: DownloadTransport::with_defaults(),
        }
    }

    /// An INERT seam — no transport in ANY build, so [`DownloadSeam::port`] is always
    /// `None` and a download is the honest not-compiled deny. Used by hermetic tests
    /// (NO network — never a live socket) and where download is intentionally absent.
    #[must_use]
    pub fn inert() -> Self {
        Self {
            #[cfg(feature = "download-egress")]
            transport: None,
        }
    }

    /// The threaded port — `None` in the default build (no download socket) ⇒
    /// [`render_download_fetch`] yields the honest not-compiled deny.
    #[must_use]
    pub fn port(&self) -> Option<&dyn DownloadPort> {
        #[cfg(feature = "download-egress")]
        {
            self.transport.as_ref().map(|t| t as &dyn DownloadPort)
        }
        #[cfg(not(feature = "download-egress"))]
        {
            None
        }
    }
}

/// The rendered outcome of a gated download: a secret-free result line (metadata only)
/// + a stable class label + an `ok` flag.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DownloadRender {
    /// The rendered, secret-free result string (metadata only — never the body).
    pub rendered: String,
    /// A stable, secret-free class label.
    pub class_label: &'static str,
    /// Whether the download succeeded (a deny is `false`).
    pub ok: bool,
}

/// A bounded, char-safe echo of a raw (possibly-rejected) URL for deny renders.
fn bounded_url(raw: &str) -> String {
    raw.chars().take(160).collect()
}

/// The SHARED gated-download pipeline (IV-DL1..IV-DL8) — the one place the `daemon
/// fetch` verb runs a download. It REQUIRES a `&FetchCapability` witness (the owner-arm
/// proof at the type level — this fn is UNREACHABLE without one, IV-DL7). Order:
///
/// 1. [`classify_download_url`] — the SSRF wall + the allowlist (deny ⇒ typed render).
/// 2. `port.fetch_to_temp` — the secret-zero GET → temp (`None` ⇒ `TransportNotCompiled`).
/// 3. metadata-only render (IV-DL8) — host / status / bytes / temp_path / sha, NEVER the
///    body (the UNTRUSTED bytes are on disk; any re-egress passes redact() elsewhere).
#[must_use]
pub fn render_download_fetch(
    _cap: &FetchCapability,
    port: Option<&dyn DownloadPort>,
    allowlist: &DownloadAllowlist,
    raw_url: &str,
) -> DownloadRender {
    // 1. SSRF wall + allowlist (IV-DL1/DL2). Deny ⇒ typed render (reason LEADS the line).
    let safe = match classify_download_url(raw_url, allowlist) {
        Ok(safe) => safe,
        Err(deny) => {
            return DownloadRender {
                rendered: format!(
                    "download denied ({}): {}",
                    deny.class_label(),
                    bounded_url(raw_url)
                ),
                class_label: deny.class_label(),
                ok: false,
            };
        }
    };
    // 2. the secret-zero GET → temp. `None` port (default build) ⇒ honest not-compiled.
    let Some(port) = port else {
        return DownloadRender {
            rendered: format!(
                "download {}: transport not compiled (build --features download-egress)",
                safe.host()
            ),
            class_label: DownloadDenied::TransportNotCompiled.class_label(),
            ok: false,
        };
    };
    let receipt = match port.fetch_to_temp(&safe) {
        Ok(receipt) => receipt,
        Err(deny) => {
            return DownloadRender {
                rendered: format!("download {}: denied ({})", safe.host(), deny.class_label()),
                class_label: deny.class_label(),
                ok: false,
            };
        }
    };
    // 3. metadata-only render (IV-DL8): host / status / bytes / temp_path / sha — NEVER
    //    the body. The UNTRUSTED bytes sit on disk; a later re-read passes redact() at
    //    that surface (the file-read tool's posture), not here.
    let rendered = format!(
        "download {host}: fetched (UNTRUSTED bytes; never executed; re-read passes redact)\n\
         status={status} bytes={bytes} sha256={sha}\n\
         saved_to={path}",
        host = receipt.host,
        status = receipt.status_u16,
        bytes = receipt.bytes_written_u64,
        sha = receipt.sha256_hex,
        path = receipt.temp_path,
    );
    DownloadRender {
        rendered,
        class_label: "download.fetched",
        ok: true,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ---- pure SSRF wall + allowlist (no network) ----------------------------

    #[test]
    fn classify_download_url_ssrf_hosts_are_denied_before_the_allowlist() {
        let al = DownloadAllowlist::curated_default();
        // each SSRF-bad URL is refused by the wall (carried as Ssrf(...)) — the
        // allowlist (which would PERMIT github.com) is never consulted.
        for u in [
            "http://github.com/x",                       // not https
            "https://127.0.0.1/x",                       // ip literal / loopback
            "https://169.254.169.254/latest/meta-data/", // cloud metadata
            "https://localhost/x",                       // localhost-class
            "https://api.mainnet-beta.solana.com/",      // chain-rpc host
            "https://user:pass@github.com/x",            // userinfo
        ] {
            assert!(
                matches!(classify_download_url(u, &al), Err(DownloadDenied::Ssrf(_))),
                "{u} must be SSRF-denied"
            );
        }
    }

    #[test]
    fn classify_download_url_non_allowlisted_host_is_denied_owner_can_extend() {
        let default = DownloadAllowlist::curated_default();
        // an SSRF-safe DNS host that is NOT in the allowlist ⇒ deny-by-default.
        assert_eq!(
            classify_download_url("https://evil.example/payload.tar.gz", &default).unwrap_err(),
            DownloadDenied::HostNotAllowlisted
        );
        // a curated-default host passes (out-of-box utility).
        assert!(classify_download_url("https://static.crates.io/x.crate", &default).is_ok());
        assert!(
            classify_download_url("https://codeload.github.com/o/r/tar.gz/v1", &default).is_ok()
        );
        // an owner-added host passes; a non-added one still does not.
        let extended = DownloadAllowlist::with_owner_hosts(&["my.mirror.example".to_string()]);
        assert!(classify_download_url("https://my.mirror.example/x.bin", &extended).is_ok());
        assert_eq!(
            classify_download_url("https://other.example/x", &extended).unwrap_err(),
            DownloadDenied::HostNotAllowlisted
        );
    }

    #[test]
    fn download_allowlist_permits_default_and_owner_hosts_only() {
        let al = DownloadAllowlist::with_owner_hosts(&[
            "  Mirror.Example  ".to_string(), // trimmed + lowercased
            String::new(),                    // empty dropped
        ]);
        assert!(al.permits("crates.io")); // curated default
        assert!(al.permits("mirror.example")); // owner-added, normalized
        assert!(al.permits("MIRROR.EXAMPLE")); // case-insensitive compare
        assert!(!al.permits("not.allowed.example"));
        assert_eq!(al.owner_count(), 1); // the empty entry was dropped
        assert!(al.default_count() >= 8);
    }

    // ---- temp-path write confinement (IV-DL3) -------------------------------

    #[test]
    fn temp_path_for_is_separator_free_and_under_temp_dir() {
        let tmp = std::env::temp_dir();
        // adversarial host/sha containing separators / traversal / NUL must NOT escape.
        for (host, sha) in [
            ("github.com", "deadbeefcafe0123"),
            ("../../../etc", "../../passwd"),
            ("a/b/c", "zz//\u{0}\\xx"),
            ("..", ".."),
        ] {
            let p = temp_path_for(host, sha);
            assert_eq!(
                p.parent(),
                Some(tmp.as_path()),
                "must be a direct child of temp_dir"
            );
            let name = p.file_name().expect("has a file name").to_string_lossy();
            assert!(!name.contains('/'), "no path separator in {name}");
            assert!(!name.contains('\\'), "no backslash in {name}");
            assert!(!name.contains('\u{0}'), "no NUL in {name}");
            assert!(name.starts_with(DOWNLOAD_TEMP_PREFIX) && name.ends_with(".bin"));
            assert_ne!(name, "..");
        }
    }

    // ---- the shared glue (scripted port; no network) ------------------------

    struct MockPort {
        response: Result<DownloadReceipt, DownloadDenied>,
    }
    impl DownloadPort for MockPort {
        fn fetch_to_temp(&self, _safe: &SafeUrl) -> Result<DownloadReceipt, DownloadDenied> {
            self.response.clone()
        }
    }

    fn ok_receipt() -> DownloadReceipt {
        DownloadReceipt {
            host: "static.crates.io".to_string(),
            status_u16: 200,
            bytes_written_u64: 4096,
            temp_path: "/tmp/sinabro-download-static.crates.io-deadbeefcafe0123.bin".to_string(),
            sha256_hex: "deadbeef".repeat(8),
        }
    }

    #[test]
    fn render_none_port_is_honest_not_compiled() {
        let cap = crate::commands::authority::test_fetch_capability();
        let al = DownloadAllowlist::curated_default();
        let out = render_download_fetch(&cap, None, &al, "https://static.crates.io/x.crate");
        assert!(!out.ok);
        assert_eq!(out.class_label, "download.transport.not_compiled");
        assert!(out.rendered.contains("transport not compiled"));
    }

    #[test]
    fn render_allowlisted_host_fetches_metadata_only() {
        let cap = crate::commands::authority::test_fetch_capability();
        let al = DownloadAllowlist::curated_default();
        let port = MockPort {
            response: Ok(ok_receipt()),
        };
        let out = render_download_fetch(&cap, Some(&port), &al, "https://static.crates.io/x.crate");
        assert!(out.ok);
        assert_eq!(out.class_label, "download.fetched");
        assert!(out.rendered.contains("static.crates.io"));
        assert!(out.rendered.contains("sha256="));
        assert!(out.rendered.contains("saved_to="));
        assert!(out.rendered.contains("UNTRUSTED"));
    }

    #[test]
    fn render_ssrf_and_allowlist_denies_do_not_fetch() {
        let cap = crate::commands::authority::test_fetch_capability();
        let al = DownloadAllowlist::curated_default();
        // a port that would PANIC if called proves the deny short-circuits before fetch.
        struct NeverPort;
        impl DownloadPort for NeverPort {
            fn fetch_to_temp(&self, _safe: &SafeUrl) -> Result<DownloadReceipt, DownloadDenied> {
                unreachable!("a denied URL must never reach the transport")
            }
        }
        for (u, label) in [
            ("http://static.crates.io/x", "web_fetch.url.not_https"),
            ("https://127.0.0.1/x", "web_fetch.url.ip_literal_host"),
            ("https://evil.example/x", "download.host_not_allowlisted"),
        ] {
            let out = render_download_fetch(&cap, Some(&NeverPort), &al, u);
            assert!(!out.ok, "{u}");
            assert_eq!(out.class_label, label, "{u}");
            assert!(out.rendered.contains("denied"), "{u}");
        }
    }

    #[test]
    fn render_over_cap_is_a_typed_deny_no_body_surfaced() {
        let cap = crate::commands::authority::test_fetch_capability();
        let al = DownloadAllowlist::curated_default();
        let port = MockPort {
            response: Err(DownloadDenied::OverSizeCap),
        };
        let out =
            render_download_fetch(&cap, Some(&port), &al, "https://static.crates.io/big.crate");
        assert!(!out.ok);
        assert_eq!(out.class_label, "download.transport.over_size_cap");
    }

    #[test]
    fn class_labels_are_stable_and_secret_free() {
        assert_eq!(
            DownloadDenied::HostNotAllowlisted.class_label(),
            "download.host_not_allowlisted"
        );
        assert_eq!(
            DownloadDenied::TransportNotCompiled.class_label(),
            "download.transport.not_compiled"
        );
        // the SSRF inner reason is surfaced verbatim (reuses web_fetch labels).
        assert_eq!(
            DownloadDenied::Ssrf(WebFetchDenied::IpLiteralHost).class_label(),
            "web_fetch.url.ip_literal_host"
        );
    }
}
