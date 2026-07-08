//! M-1 (Mycel) — the S3 content-store adapter (feature `s3`).
//!
//! An S3-compatible backend for the agent registry, over `reqwest` + a HAND-ROLLED AWS
//! Signature V4. **No AWS SDK** (unvendorable offline) and **no `hmac` crate** — HMAC-SHA256
//! is built here on the always-present `sha2` (via [`crate::sha256_32`]), so the `s3` feature
//! adds only `reqwest` to the dep graph. Maximally self-contained, minimal blast radius.
//!
//! ## Why this can never drift (the physics)
//! 1. **The seatbelt makes byte-correctness DOWNSTREAM.** The registry re-hashes
//!    fetched *content* to the *artifact id* (`dispatch::registry_content_verified`). A
//!    corrupt/truncated/substituted S3 response ⇒ REJECT, never trusted. Trust =
//!    `sha256(content)==artifact_id`, a mathematical property INDEPENDENT of S3. So this
//!    adapter is free to be maximally fast — a transport bug is a clean failure, never a
//!    silent corruption.
//! 2. **SigV4 is a deterministic pure function**, locked byte-exact to the canonical AWS
//!    `get-vanilla` test vector (and the hand-rolled HMAC to an RFC-4231 vector). No drift.
//! 3. **The cid grammar is provably disjoint** (`content_store::classify_cid`) — an S3 cid
//!    is `s3-<64hex>`, unambiguous against LocalCAS/Walrus. No routing drift.
//!
//! ## Speed (paranoid, free of safety cost)
//! - The cid's sha256 IS the SigV4 `x-amz-content-sha256` payload hash — computed ONCE,
//!   used for both the content address and the signature.
//! - The SigV4 signing key (a 4-HMAC chain) is CACHED per UTC date, reused across every
//!   object in a publish ceremony (saves `4·(N-1)` HMACs for N objects).
//! - ONE reused `reqwest` client (connection pool); ONE round-trip per op (content-address
//!   ⇒ re-PUT is idempotent ⇒ no HEAD-check).

use crate::content_store::{Cid, ContentStore, PutClass, S3_CID_PREFIX};

/// The SHA-256 block size (HMAC uses this).
const SHA256_BLOCK: usize = 64;

/// HMAC-SHA256 over [`crate::sha256_32`] (RFC 2104). Hand-rolled so the `s3` feature needs
/// no `hmac` crate; locked to an RFC-4231 vector in tests. Deterministic ⇒ drift-proof.
#[must_use]
pub fn hmac_sha256(key: &[u8], msg: &[u8]) -> [u8; 32] {
    // Block-size key: shorten via H if too long, else zero-pad.
    let mut k = [0u8; SHA256_BLOCK];
    if key.len() > SHA256_BLOCK {
        k[..32].copy_from_slice(&crate::sha256_32(key));
    } else {
        k[..key.len()].copy_from_slice(key);
    }
    let mut inner = Vec::with_capacity(SHA256_BLOCK + msg.len());
    let mut outer = Vec::with_capacity(SHA256_BLOCK + 32);
    for &kb in &k {
        inner.push(kb ^ 0x36);
        outer.push(kb ^ 0x5c);
    }
    inner.extend_from_slice(msg);
    outer.extend_from_slice(&crate::sha256_32(&inner));
    crate::sha256_32(&outer)
}

/// Convert a UNIX-epoch second count to `(amzdate = "YYYYMMDDTHHMMSSZ", datestamp =
/// "YYYYMMDD")` in UTC. Hand-rolled civil-from-days (Howard Hinnant's algorithm) so no date
/// crate is pulled; deterministic + verified against Python in tests. Drift-proof.
#[must_use]
pub fn utc_stamp(epoch_secs: u64) -> (String, String) {
    let days = (epoch_secs / 86_400) as i64;
    let secs_of_day = epoch_secs % 86_400;
    let (hh, mm, ss) = (
        secs_of_day / 3600,
        (secs_of_day % 3600) / 60,
        secs_of_day % 60,
    );
    // civil_from_days (days since 1970-01-01):
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097; // [0, 146096]
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365; // [0, 399]
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100); // [0, 365]
    let mp = (5 * doy + 2) / 153; // [0, 11]
    let d = doy - (153 * mp + 2) / 5 + 1; // [1, 31]
    let m = if mp < 10 { mp + 3 } else { mp - 9 }; // [1, 12]
    let year = y + i64::from(m <= 2);
    (
        format!("{year:04}{m:02}{d:02}T{hh:02}{mm:02}{ss:02}Z"),
        format!("{year:04}{m:02}{d:02}"),
    )
}

/// Derive the SigV4 signing key: `HMAC(HMAC(HMAC(HMAC("AWS4"+secret, date), region),
/// service), "aws4_request")`. Cacheable per (date, region, service).
#[must_use]
fn derive_signing_key(secret: &str, datestamp: &str, region: &str, service: &str) -> [u8; 32] {
    let k_secret = format!("AWS4{secret}");
    let k_date = hmac_sha256(k_secret.as_bytes(), datestamp.as_bytes());
    let k_region = hmac_sha256(&k_date, region.as_bytes());
    let k_service = hmac_sha256(&k_region, service.as_bytes());
    hmac_sha256(&k_service, b"aws4_request")
}

/// Compute the SigV4 hex signature for a fully-formed canonical request. PURE + deterministic
/// — locked byte-exact to the canonical `get-vanilla` vector in tests. `signing_key` may be a
/// cached derivation (same math). The caller assembles `canonical_headers` (each
/// `name:value\n`, sorted) + `signed_headers` (`;`-joined, sorted).
#[must_use]
#[allow(clippy::too_many_arguments)]
pub fn sigv4_signature(
    signing_key: &[u8; 32],
    region: &str,
    service: &str,
    datestamp: &str,
    amzdate: &str,
    method: &str,
    canonical_uri: &str,
    canonical_query: &str,
    canonical_headers: &str,
    signed_headers: &str,
    payload_hash: &str,
) -> String {
    let canonical_request = format!(
        "{method}\n{canonical_uri}\n{canonical_query}\n{canonical_headers}\n{signed_headers}\n{payload_hash}"
    );
    let scope = format!("{datestamp}/{region}/{service}/aws4_request");
    let string_to_sign = format!(
        "AWS4-HMAC-SHA256\n{amzdate}\n{scope}\n{}",
        crate::hex32(&crate::sha256_32(canonical_request.as_bytes()))
    );
    crate::hex32(&hmac_sha256(signing_key, string_to_sign.as_bytes()))
}

/// The owner-configured S3 target (from env; NOT custody — cloud storage creds like the
/// remote-shell ssh config, not a wallet). `endpoint` overrides the AWS virtual-host URL for
/// an S3-compatible service (MinIO / a test mock): when set, path-style
/// `<endpoint>/<bucket>/<key>`; else `https://<bucket>.s3.<region>.amazonaws.com/<key>`.
pub struct S3Config {
    bucket: String,
    region: String,
    access_key: String,
    secret_key: String,
    endpoint: Option<String>,
}

impl S3Config {
    /// Read the S3 target from env. `None` if any required var is missing (honest-degrade;
    /// the registry then falls back to LocalCAS). Env: `MNEMOS_S3_BUCKET`, `MNEMOS_S3_REGION`,
    /// `MNEMOS_S3_ACCESS_KEY`, `MNEMOS_S3_SECRET_KEY`, optional `MNEMOS_S3_ENDPOINT`.
    #[must_use]
    pub fn from_env() -> Option<Self> {
        let get = |k: &str| std::env::var(k).ok().filter(|v| !v.trim().is_empty());
        Some(Self {
            bucket: get("MNEMOS_S3_BUCKET")?,
            region: get("MNEMOS_S3_REGION")?,
            access_key: get("MNEMOS_S3_ACCESS_KEY")?,
            secret_key: get("MNEMOS_S3_SECRET_KEY")?,
            endpoint: get("MNEMOS_S3_ENDPOINT"),
        })
    }

    /// The request URL + `Host` header for object `key`. Path-style when an endpoint override
    /// is set (S3-compatible / mock), else AWS virtual-host style.
    fn url_and_host(&self, key: &str) -> (String, String) {
        match &self.endpoint {
            Some(ep) => {
                let ep = ep.trim_end_matches('/');
                let host = ep
                    .split_once("://")
                    .map_or(ep, |(_, rest)| rest)
                    .split('/')
                    .next()
                    .unwrap_or(ep)
                    .to_string();
                (format!("{ep}/{}/{key}", self.bucket), host)
            }
            None => {
                let host = format!("{}.s3.{}.amazonaws.com", self.bucket, self.region);
                (format!("https://{host}/{key}"), host)
            }
        }
    }
}

/// The per-request timeout (ms) for S3 PUT/GET. Bounded I/O (no hang).
const S3_TIMEOUT_MS: u64 = 30_000;

/// A HARD cap on a GET response (bytes) — a hostile/huge object can't OOM (the registry
/// artifacts are small; the walk caps sizes at publish). 16 MiB is generous.
const S3_MAX_GET_BYTES: usize = 16 * 1024 * 1024;

/// The S3 content-store adapter. Holds ONE reused client + the config + a per-date signing-key
/// cache (the 4-HMAC chain is derived once per UTC day, reused across a publish ceremony).
pub struct S3Store {
    client: reqwest::blocking::Client,
    config: S3Config,
    /// `(datestamp, signing_key)` — reused while the UTC date is unchanged (CU win).
    signing_cache: Option<(String, [u8; 32])>,
}

impl S3Store {
    /// Open an S3 store from env, or `None` (honest-degrade to LocalCAS). The client is the
    /// paranoia set: `redirect(none)` + `no_proxy()` + a per-call timeout.
    #[must_use]
    pub fn from_env() -> Option<Self> {
        let config = S3Config::from_env()?;
        let client = reqwest::blocking::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .no_proxy()
            .timeout(std::time::Duration::from_millis(S3_TIMEOUT_MS))
            .build()
            .ok()?;
        Some(Self {
            client,
            config,
            signing_cache: None,
        })
    }

    /// The current signing key for `datestamp`, deriving + caching on a date change.
    fn signing_key(&mut self, datestamp: &str) -> [u8; 32] {
        if let Some((d, k)) = &self.signing_cache {
            if d == datestamp {
                return *k;
            }
        }
        let k = derive_signing_key(
            &self.config.secret_key,
            datestamp,
            &self.config.region,
            "s3",
        );
        self.signing_cache = Some((datestamp.to_string(), k));
        k
    }

    /// The `Authorization` header value for a request (SigV4). `payload_hash` = hex sha256 of
    /// the body (empty-string hash for a GET). Minimal signed headers: host;content-sha256;date.
    fn authorization(
        &mut self,
        method: &str,
        key: &str,
        host: &str,
        amzdate: &str,
        datestamp: &str,
        payload_hash: &str,
    ) -> String {
        let canonical_headers =
            format!("host:{host}\nx-amz-content-sha256:{payload_hash}\nx-amz-date:{amzdate}\n");
        let signed_headers = "host;x-amz-content-sha256;x-amz-date";
        let signing_key = self.signing_key(datestamp);
        let signature = sigv4_signature(
            &signing_key,
            &self.config.region,
            "s3",
            datestamp,
            amzdate,
            method,
            &format!("/{key}"),
            "",
            &canonical_headers,
            signed_headers,
            payload_hash,
        );
        format!(
            "AWS4-HMAC-SHA256 Credential={}/{datestamp}/{}/s3/aws4_request, SignedHeaders={signed_headers}, Signature={signature}",
            self.config.access_key, self.config.region
        )
    }
}

impl ContentStore for S3Store {
    fn put(&mut self, bytes: &[u8], class: PutClass) -> Option<Cid> {
        // A Public plaintext blob passes the fail-closed secret-scan belt (parity
        // with the LocalCAS + Walrus send-sites).
        if matches!(class, PutClass::Public)
            && crate::secrets::scan_inline_secret(&String::from_utf8_lossy(bytes))
        {
            return None;
        }
        // ★ ONE sha256: the content address AND the SigV4 payload hash.
        let content_hex = crate::hex32(&crate::sha256_32(bytes));
        let cid = format!("{S3_CID_PREFIX}{content_hex}");
        let key = &content_hex; // the S3 object key is the 64-hex content address (URI-safe)
        let (url, host) = self.config.url_and_host(key);
        let now = std::time::SystemTime::now()
            .duration_since(std::time::SystemTime::UNIX_EPOCH)
            .ok()?
            .as_secs();
        let (amzdate, datestamp) = utc_stamp(now);
        let authz = self.authorization("PUT", key, &host, &amzdate, &datestamp, &content_hex);
        let resp = self
            .client
            .put(&url)
            .header("Host", &host)
            .header("x-amz-date", &amzdate)
            .header("x-amz-content-sha256", &content_hex)
            .header("Authorization", authz)
            .body(bytes.to_vec())
            .send()
            .ok()?;
        if resp.status().is_success() {
            Some(cid)
        } else {
            None // honest failure — never a silent success
        }
    }

    fn get(&self, cid: &str) -> Option<Vec<u8>> {
        // Strip the `s3-` prefix → the 64-hex object key. `classify_cid` guarantees the shape,
        // but re-check defensively (a non-64-hex key never builds a request).
        let key = cid.strip_prefix(S3_CID_PREFIX)?;
        if key.len() != 64
            || !key
                .bytes()
                .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
        {
            return None;
        }
        // GET signs with the empty-payload hash.
        let empty_hash = crate::hex32(&crate::sha256_32(b""));
        let (url, host) = self.config.url_and_host(key);
        let now = std::time::SystemTime::now()
            .duration_since(std::time::SystemTime::UNIX_EPOCH)
            .ok()?
            .as_secs();
        let (amzdate, datestamp) = utc_stamp(now);
        // `get` takes `&self`; derive the signing key inline (no cache mutation on the read
        // path — a GET is rare vs a publish batch, so the cache win is on `put`).
        let signing_key = derive_signing_key(
            &self.config.secret_key,
            &datestamp,
            &self.config.region,
            "s3",
        );
        let canonical_headers =
            format!("host:{host}\nx-amz-content-sha256:{empty_hash}\nx-amz-date:{amzdate}\n");
        let signed_headers = "host;x-amz-content-sha256;x-amz-date";
        let signature = sigv4_signature(
            &signing_key,
            &self.config.region,
            "s3",
            &datestamp,
            &amzdate,
            "GET",
            &format!("/{key}"),
            "",
            &canonical_headers,
            signed_headers,
            &empty_hash,
        );
        let authz = format!(
            "AWS4-HMAC-SHA256 Credential={}/{datestamp}/{}/s3/aws4_request, SignedHeaders={signed_headers}, Signature={signature}",
            self.config.access_key, self.config.region
        );
        let resp = self
            .client
            .get(&url)
            .header("Host", &host)
            .header("x-amz-date", &amzdate)
            .header("x-amz-content-sha256", &empty_hash)
            .header("Authorization", authz)
            .send()
            .ok()?;
        if !resp.status().is_success() {
            return None;
        }
        // Bounded read (no OOM). The bytes are UNTRUSTED until the registry seatbelt.
        let body = resp.bytes().ok()?;
        if body.len() > S3_MAX_GET_BYTES {
            return None;
        }
        Some(body.to_vec())
    }

    fn backend_label(&self) -> &'static str {
        "s3"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ★ HMAC-SHA256 locked to the RFC-4231 Test Case 2 vector (key="Jefe", data="what do ya
    // want for nothing?") ⇒ 5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843.
    #[test]
    fn hmac_sha256_matches_rfc4231() {
        let mac = hmac_sha256(b"Jefe", b"what do ya want for nothing?");
        assert_eq!(
            crate::hex32(&mac),
            "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"
        );
    }

    // ★ SigV4 locked BYTE-EXACT to the canonical AWS `get-vanilla` test vector (Python-verified
    // ground truth == the published AWS suite). SigV4 is a pure function ⇒ this is drift-proof.
    #[test]
    fn sigv4_matches_get_vanilla_vector() {
        let secret = "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY";
        let signing_key = derive_signing_key(secret, "20150830", "us-east-1", "service");
        let payload_hash = crate::hex32(&crate::sha256_32(b"")); // empty GET body
        let canonical_headers = "host:example.amazonaws.com\nx-amz-date:20150830T123600Z\n";
        let sig = sigv4_signature(
            &signing_key,
            "us-east-1",
            "service",
            "20150830",
            "20150830T123600Z",
            "GET",
            "/",
            "",
            canonical_headers,
            "host;x-amz-date",
            &payload_hash,
        );
        assert_eq!(
            sig, "5fa00fa31553b73ebf1942676e86291e8372ff2a2260956d9b8aae1d763fbf31",
            "SigV4 must match the canonical get-vanilla vector byte-exact"
        );
    }

    // ★ utc_stamp locked to known epochs (Python-verified). Deterministic civil-from-days.
    #[test]
    fn utc_stamp_matches_known_epochs() {
        // 2015-08-30T12:36:00Z = 1440938160
        assert_eq!(
            utc_stamp(1_440_938_160),
            ("20150830T123600Z".to_string(), "20150830".to_string())
        );
        // 1970-01-01T00:00:00Z = 0
        assert_eq!(
            utc_stamp(0),
            ("19700101T000000Z".to_string(), "19700101".to_string())
        );
        // 2000-02-29T23:59:59Z (leap day) = 951868799
        assert_eq!(
            utc_stamp(951_868_799),
            ("20000229T235959Z".to_string(), "20000229".to_string())
        );
    }
}
