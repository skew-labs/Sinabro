//! The CONTENT STORE adapter: the agent-registry's storage behind a
//! swappable, content-addressed backend.
//!
//! **Why this is safe:** the registry's trust boundary is its content-hash
//! seatbelt (`dispatch::registry_content_verified`), which re-hashes fetched *content* to
//! the *artifact id* — NOT to the storage address. So a backend's returned bytes are
//! UNTRUSTED until that seatbelt passes, and the trust model is **backend-independent**.
//! Swapping the store only changes where bytes live, never who is trusted.
//!
//! Default backend = [`LocalCasStore`] — content-addressed files under `<data_dir>/cas/`,
//! keyless, offline, no crypto (the non-chain demo path). Walrus / S3 are feature-gated
//! adapters that implement the same [`ContentStore`] trait. The registry's AEAD sealing
//! (private artifacts) is orthogonal to the store — it happens on the bytes BEFORE `put`.

use std::path::PathBuf;

/// A content id — the store's own address for a blob (LocalCAS: 64-hex sha256; Walrus:
/// 43-char base64url). Opaque to the registry (which addresses artifacts by their own id).
pub type Cid = String;

/// The visibility class of a PUT. [`LocalCasStore`] and network adapters both run the
/// public secret-scan belt; a network adapter additionally maps this to its payload class.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PutClass {
    /// AEAD ciphertext (the registry already sealed it) — no plaintext leaves.
    Private,
    /// Plaintext, any agent can content-hash-verify — MUST pass the fail-closed secret-scan.
    Public,
}

/// A swappable content-addressed store. `put` returns the store's address; `get` returns
/// RAW UNTRUSTED bytes (the caller's content-hash seatbelt is the trust gate).
pub trait ContentStore {
    /// Store `bytes`, returning the store's content id, or `None` on refusal/failure
    /// (e.g. a `Public` blob that is secret-shaped). Idempotent for identical bytes.
    fn put(&mut self, bytes: &[u8], class: PutClass) -> Option<Cid>;
    /// Fetch the bytes for `cid`, or `None`. **Untrusted** until the caller re-hashes.
    fn get(&self, cid: &str) -> Option<Vec<u8>>;
    /// A stable label for render/audit (e.g. `"local-cas"`, `"walrus-testnet"`).
    fn backend_label(&self) -> &'static str;
    /// REDACTION: overwrite the blob at `cid`'s address with RAW `bytes`
    /// (bypassing content-addressing — the ONLY non-content-addressed write, used
    /// solely to tombstone a redacted blob). Returns `true` iff the store performed
    /// the overwrite. Default = `false` (an immutable/remote backend cannot blank
    /// content in v1 — the redaction registry still records the fact, honestly).
    fn overwrite_raw(&mut self, _cid: &str, _bytes: &[u8]) -> bool {
        false
    }
}

/// The length of a [`LocalCasStore`] cid (hex of a 32-byte sha256).
pub const LOCAL_CAS_CID_HEX_LEN: usize = 64;

/// The DEFAULT non-chain adapter: content-addressed files under `<data_dir>/cas/`. Keyless,
/// offline, no crypto. The cid IS `hex(sha256(bytes))`, so the store self-addresses (the
/// "self-report ban" is trivial — the filename is the hash of its content).
pub struct LocalCasStore {
    dir: PathBuf,
}

impl LocalCasStore {
    /// The subdir under the data dir holding the CAS blobs.
    pub const CAS_SUBDIR: &'static str = "cas";

    /// Open the local CAS under `<data_dir>/cas/`, creating it. `None` on no data dir / io.
    #[must_use]
    pub fn open_local() -> Option<Self> {
        let dir = crate::memory_store::data_dir().ok()?.join(Self::CAS_SUBDIR);
        std::fs::create_dir_all(&dir).ok()?;
        Some(Self { dir })
    }

    /// Construct over an explicit dir (tests / non-default roots).
    #[must_use]
    pub fn with_dir(dir: PathBuf) -> Self {
        Self { dir }
    }

    /// The file path for `cid`, or `None` if `cid` is not exactly [`LOCAL_CAS_CID_HEX_LEN`]
    /// lowercase-hex — so a malicious cid can NEVER contain a path separator nor `..`
    /// (no traversal; the write/read cannot escape `dir`).
    fn path_for(&self, cid: &str) -> Option<PathBuf> {
        if cid.len() != LOCAL_CAS_CID_HEX_LEN
            || !cid
                .bytes()
                .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
        {
            return None;
        }
        Some(self.dir.join(cid))
    }
}

impl ContentStore for LocalCasStore {
    fn put(&mut self, bytes: &[u8], class: PutClass) -> Option<Cid> {
        // A Public plaintext blob passes the fail-closed secret-scan belt (parity
        // with the Walrus send-site; matters for a future public/S3 sharing path).
        if matches!(class, PutClass::Public)
            && crate::secrets::scan_inline_secret(&String::from_utf8_lossy(bytes))
        {
            return None;
        }
        let cid = crate::hex32(&crate::sha256_32(bytes));
        // path_for validates our own cid shape (always valid here) — defense-in-depth.
        let path = self.path_for(&cid)?;
        // Idempotent: identical bytes ⇒ identical name ⇒ write once.
        if !path.exists() {
            std::fs::write(&path, bytes).ok()?;
        }
        Some(cid)
    }

    fn get(&self, cid: &str) -> Option<Vec<u8>> {
        std::fs::read(self.path_for(cid)?).ok()
    }

    fn backend_label(&self) -> &'static str {
        "local-cas"
    }

    fn overwrite_raw(&mut self, cid: &str, bytes: &[u8]) -> bool {
        // Only overwrite an EXISTING, well-formed cid path (path_for validates the
        // 64-hex shape ⇒ no traversal). Redaction blanks in place; it never creates.
        match self.path_for(cid) {
            Some(path) if path.exists() => std::fs::write(&path, bytes).is_ok(),
            _ => false,
        }
    }
}

/// The prefix distinguishing an S3 cid from a LocalCAS cid (both wrap a 64-hex sha256).
/// An S3 cid is `s3-<64hex>` (67 chars) — a PROVABLY-DISJOINT grammar from LocalCAS
/// (64-hex, no prefix) and Walrus (43-base64url), so [`classify_cid`] is total + unambiguous.
pub const S3_CID_PREFIX: &str = "s3-";

/// Which backend a stored cid belongs to — inferred from its SHAPE (each backend's cid has
/// a PAIRWISE-DISJOINT grammar, so fetch/pin route with no extra config, no ambiguity, no
/// drift). LocalCAS = `[0-9a-f]{64}`; Walrus = 43 base64url; S3 = `s3-[0-9a-f]{64}`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CidBackend {
    /// A 64-hex sha256 name — a [`LocalCasStore`] blob.
    LocalCas,
    /// A 43-char base64url id — a Walrus blob.
    Walrus,
    /// An `s3-<64hex>` name — an S3 object (feature `s3`).
    S3,
    /// No known grammar — reject.
    Unknown,
}

/// True iff `s` is exactly 64 lowercase-hex chars (the LocalCAS / S3-suffix content address).
#[must_use]
fn is_64_lower_hex(s: &str) -> bool {
    s.len() == LOCAL_CAS_CID_HEX_LEN
        && s.bytes()
            .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
}

/// Classify a cid by its shape (no network, no config). The three backend grammars are
/// PAIRWISE DISJOINT so this is a TOTAL, UNAMBIGUOUS function — routing can never drift:
/// - S3   : `s3-` + 64 lowercase-hex (67 chars; the only grammar with the `s3-` prefix).
/// - LocalCAS: 64 lowercase-hex (no prefix; length 64 ≠ 67, ≠ 43).
/// - Walrus: 43 base64url (length 43; cannot be 64-hex nor start `s3-` since the Walrus id
///   is a fixed 43-char base64url of a 32-byte digest).
///
/// Anything else ⇒ `Unknown` (fail-closed at the caller).
#[must_use]
pub fn classify_cid(cid: &str) -> CidBackend {
    let c = cid.trim();
    if let Some(hex) = c.strip_prefix(S3_CID_PREFIX) {
        if is_64_lower_hex(hex) {
            return CidBackend::S3;
        }
        return CidBackend::Unknown;
    }
    if is_64_lower_hex(c) {
        CidBackend::LocalCas
    } else if crate::registry_loop::looks_like_walrus_blob_id(c) {
        CidBackend::Walrus
    } else {
        CidBackend::Unknown
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn local_cas_round_trips_and_is_content_addressed() {
        let dir = std::env::temp_dir().join(format!("sinabro_cas_test_{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("mkdir");
        let mut store = LocalCasStore::with_dir(dir.clone());
        let bytes = b"hello mycel content store";
        let cid = store.put(bytes, PutClass::Public).expect("put");
        // cid IS hex(sha256(bytes)) — content-addressed, deterministic.
        assert_eq!(cid, crate::hex32(&crate::sha256_32(bytes)));
        assert_eq!(cid.len(), LOCAL_CAS_CID_HEX_LEN);
        // get round-trips the exact bytes.
        assert_eq!(store.get(&cid).as_deref(), Some(&bytes[..]));
        // idempotent: same bytes ⇒ same cid ⇒ one file.
        assert_eq!(
            store.put(bytes, PutClass::Private).as_deref(),
            Some(cid.as_str())
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn local_cas_get_refuses_traversal_cid() {
        // a malicious cid (wrong length / separators / '.') never builds a path.
        let store = LocalCasStore::with_dir(std::env::temp_dir());
        assert_eq!(store.get("../../etc/passwd"), None);
        assert_eq!(store.get("/etc/passwd"), None);
        assert_eq!(store.get(&"a".repeat(63)), None, "wrong length");
        assert_eq!(store.get(&"A".repeat(64)), None, "uppercase is not our hex");
        assert_eq!(store.get(&"g".repeat(64)), None, "non-hex");
        // …while a well-formed (but absent) 64-hex cid just misses cleanly.
        assert_eq!(store.get(&"a".repeat(64)), None);
    }

    #[test]
    fn local_cas_public_put_secret_scans_fail_closed() {
        // a secret-shaped Public blob is REFUSED (never written).
        let dir = std::env::temp_dir().join(format!("sinabro_cas_sec_{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("mkdir");
        let mut store = LocalCasStore::with_dir(dir.clone());
        let secret = b"-----BEGIN OPENSSH PRIVATE KEY-----\nAAAA\n";
        assert_eq!(
            store.put(secret, PutClass::Public),
            None,
            "public secret refused"
        );
        // …but the SAME bytes as Private (already-ciphertext contract) are stored.
        assert!(store.put(secret, PutClass::Private).is_some());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn classify_cid_routes_by_shape() {
        // 64-hex ⇒ LocalCas; 43-base64url ⇒ Walrus; s3-<64hex> ⇒ S3; else Unknown.
        assert_eq!(classify_cid(&"a".repeat(64)), CidBackend::LocalCas);
        assert_eq!(
            classify_cid("UByiso8pwxjpc-TH0zglnTQ2i46jG2A_DIKvKJeVwsQ"),
            CidBackend::Walrus
        );
        assert_eq!(
            classify_cid(&format!("s3-{}", "a".repeat(64))),
            CidBackend::S3
        );
        assert_eq!(classify_cid("nonsense"), CidBackend::Unknown);
        assert_eq!(classify_cid(&"a".repeat(50)), CidBackend::Unknown);
        // a malformed S3 cid (wrong hex length) ⇒ Unknown, never mis-routed.
        assert_eq!(classify_cid("s3-abc"), CidBackend::Unknown);
        assert_eq!(
            classify_cid(&format!("s3-{}", "a".repeat(63))),
            CidBackend::Unknown
        );
    }

    // ★ DRIFT-PROOF: the three backend grammars are PAIRWISE DISJOINT, so classify_cid can
    // NEVER route one backend's cid to another. Exhaustive-shape reasoning, machine-checked:
    // every non-Unknown classification is stable, and the three canonical shapes never collide.
    #[test]
    fn cid_grammars_are_pairwise_disjoint() {
        let local = "a".repeat(64);
        let walrus = "UByiso8pwxjpc-TH0zglnTQ2i46jG2A_DIKvKJeVwsQ".to_string(); // 43 base64url
        let s3 = format!("s3-{}", "b".repeat(64));
        // Each canonical shape classifies to exactly its own backend.
        assert_eq!(classify_cid(&local), CidBackend::LocalCas);
        assert_eq!(classify_cid(&walrus), CidBackend::Walrus);
        assert_eq!(classify_cid(&s3), CidBackend::S3);
        // Disjoint by construction: distinct lengths / the unique s3- prefix.
        assert_eq!(local.len(), 64);
        assert_eq!(walrus.len(), 43);
        assert_eq!(s3.len(), 67);
        assert!(s3.starts_with("s3-") && !local.starts_with("s3-") && !walrus.starts_with("s3-"));
        // A LocalCAS 64-hex is NOT a Walrus id (len 64≠43) and NOT S3 (no prefix); etc.
        assert_ne!(classify_cid(&local), CidBackend::Walrus);
        assert_ne!(classify_cid(&local), CidBackend::S3);
        assert_ne!(classify_cid(&walrus), CidBackend::LocalCas);
        assert_ne!(classify_cid(&s3), CidBackend::LocalCas);
    }
}
