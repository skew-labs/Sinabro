//! The REDACTION PROTOCOL: satisfy "delete my data / remove this
//! secret" WITHOUT breaking the append-only audit chain.
//!
//! ## The resolution (physics)
//!
//! The ledger chain hashes OPERATIONS (`link_hash = sha256(domain ‖ prev ‖ op_bytes)`),
//! NOT content. So content-availability and audit-integrity are SEPARABLE: redaction
//! overwrites the ContentStore blob at `hex(cid)` with a fixed
//! [`REDACTION_TOMBSTONE`] and records the cid + reason-class in the `RDXN` registry.
//! The LEDGER is byte-UNCHANGED — the chain stays GREEN, the audit SHAPE is preserved
//! (-1/3). The tombstone deliberately does not hash back to `cid`; the registry
//! is what tells a consumer "this mismatch is INTENTIONAL (redacted), not tampered"
//! ([`classify_fetch`], -2).
//!
//! Redaction is owner-ceremony gated (destructive) and SELF-AUDITABLE (the registry
//! is an append-only record of {cid, reason-class, version} — you prove a redaction
//! happened and its class without ever storing the secret, -4). A redaction only
//! BLANKS an existing cid — it mints no new content (-5). Keyless; no custody
//! .

use std::path::Path;

use crate::content_store::ContentStore;

/// The fixed tombstone written in place of a redacted blob (25 bytes,
/// Python-verified). Unrecoverable: the original bytes are overwritten.
pub const REDACTION_TOMBSTONE: &[u8] = b"sinabro.nous.redacted.v1\x00";

/// The redaction-registry magic (4 bytes) — `RDXN`.
pub const REDACTION_MAGIC: [u8; 4] = *b"RDXN";

/// The registry wire version.
pub const REDACTION_VERSION: u8 = 1;

/// The registry file under `<data_dir>/nous/`.
pub const REDACTION_FILE: &str = "redactions.rdx";

/// The owner ceremony phrase that authorizes a redaction (destructive).
pub const REDACT_ARM_PHRASE: &str = "redact-owner-live";

/// Why a cid was redacted — a CLASS, never the secret itself.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum RedactionReason {
    /// A leaked secret / credential.
    Secret,
    /// Personal data (a "right to be forgotten" request).
    Pii,
    /// A legal / takedown request.
    LegalRequest,
    /// Any other owner-decided reason.
    Other,
}

impl RedactionReason {
    /// The STABLE wire byte (bound into the registry; never renumber).
    #[must_use]
    pub const fn wire(self) -> u8 {
        match self {
            RedactionReason::Secret => 1,
            RedactionReason::Pii => 2,
            RedactionReason::LegalRequest => 3,
            RedactionReason::Other => 4,
        }
    }

    /// Decode a wire byte (fail-closed).
    #[must_use]
    pub const fn from_wire(b: u8) -> Option<Self> {
        match b {
            1 => Some(RedactionReason::Secret),
            2 => Some(RedactionReason::Pii),
            3 => Some(RedactionReason::LegalRequest),
            4 => Some(RedactionReason::Other),
            _ => None,
        }
    }

    /// Parse a CLI label (fail-closed).
    #[must_use]
    pub fn from_label(s: &str) -> Option<Self> {
        match s {
            "secret" => Some(RedactionReason::Secret),
            "pii" => Some(RedactionReason::Pii),
            "legal" => Some(RedactionReason::LegalRequest),
            "other" => Some(RedactionReason::Other),
            _ => None,
        }
    }

    /// A stable label (for renders — never the secret).
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            RedactionReason::Secret => "secret",
            RedactionReason::Pii => "pii",
            RedactionReason::LegalRequest => "legal-request",
            RedactionReason::Other => "other",
        }
    }
}

/// One registry entry: a redacted cid + its reason-class + the registry version at
/// which it was recorded.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RedactionEntry {
    /// The raw 32-byte cid that was redacted.
    pub cid: [u8; 32],
    /// Why (class only).
    pub reason: RedactionReason,
    /// The registry version when recorded (append order).
    pub version: u32,
}

/// The append-only redaction registry (sorted by cid for a canonical encoding).
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct RedactionRegistry {
    /// The recorded redactions.
    pub entries: Vec<RedactionEntry>,
}

/// Typed codec failures (fail-closed).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum RedactionError {
    /// Bytes shorter than a field demanded.
    Truncated,
    /// The magic was not [`REDACTION_MAGIC`].
    BadMagic,
    /// The version byte was unknown.
    UnknownVersion,
    /// An unknown reason wire byte.
    UnknownReason,
    /// Trailing garbage after the last entry.
    TrailingBytes,
    /// The content store write failed.
    StoreIo,
}

impl RedactionError {
    /// A stable, honest one-liner for renders.
    #[must_use]
    pub const fn message(self) -> &'static str {
        match self {
            RedactionError::Truncated => "truncated redaction registry",
            RedactionError::BadMagic => "bad redaction magic",
            RedactionError::UnknownVersion => "unknown redaction version",
            RedactionError::UnknownReason => "unknown redaction reason",
            RedactionError::TrailingBytes => "trailing bytes",
            RedactionError::StoreIo => "content store write failed",
        }
    }
}

impl RedactionRegistry {
    /// True iff `cid` has been redacted.
    #[must_use]
    pub fn is_redacted(&self, cid: &[u8; 32]) -> Option<RedactionReason> {
        self.entries
            .iter()
            .find(|e| &e.cid == cid)
            .map(|e| e.reason)
    }
}

/// Encode the registry (`RDXN`; entries sorted by cid). `None` never (all fields
/// bounded) — returns `Some` for API symmetry.
#[must_use]
pub fn encode_registry(reg: &RedactionRegistry) -> Vec<u8> {
    let mut sorted = reg.entries.clone();
    sorted.sort_by(|a, b| a.cid.cmp(&b.cid));
    let mut b = Vec::with_capacity(9 + sorted.len() * 37);
    b.extend_from_slice(&REDACTION_MAGIC);
    b.push(REDACTION_VERSION);
    b.extend_from_slice(
        &u32::try_from(sorted.len())
            .unwrap_or(u32::MAX)
            .to_le_bytes(),
    );
    for e in &sorted {
        b.extend_from_slice(&e.cid);
        b.push(e.reason.wire());
        b.extend_from_slice(&e.version.to_le_bytes());
    }
    b
}

fn take<'a>(bytes: &'a [u8], at: &mut usize, n: usize) -> Result<&'a [u8], RedactionError> {
    let end = at.checked_add(n).ok_or(RedactionError::Truncated)?;
    if end > bytes.len() {
        return Err(RedactionError::Truncated);
    }
    let s = &bytes[*at..end];
    *at = end;
    Ok(s)
}

/// Decode the registry (fail-closed).
pub fn decode_registry(bytes: &[u8]) -> Result<RedactionRegistry, RedactionError> {
    let mut at = 0usize;
    if take(bytes, &mut at, 4)? != REDACTION_MAGIC {
        return Err(RedactionError::BadMagic);
    }
    if take(bytes, &mut at, 1)?[0] != REDACTION_VERSION {
        return Err(RedactionError::UnknownVersion);
    }
    let mut c = [0u8; 4];
    c.copy_from_slice(take(bytes, &mut at, 4)?);
    let count = u32::from_le_bytes(c) as usize;
    let mut entries = Vec::with_capacity(count.min(4096));
    for _ in 0..count {
        let mut cid = [0u8; 32];
        cid.copy_from_slice(take(bytes, &mut at, 32)?);
        let reason = RedactionReason::from_wire(take(bytes, &mut at, 1)?[0])
            .ok_or(RedactionError::UnknownReason)?;
        let mut v = [0u8; 4];
        v.copy_from_slice(take(bytes, &mut at, 4)?);
        entries.push(RedactionEntry {
            cid,
            reason,
            version: u32::from_le_bytes(v),
        });
    }
    if at != bytes.len() {
        return Err(RedactionError::TrailingBytes);
    }
    Ok(RedactionRegistry { entries })
}

/// The registry path: `<data_dir>/nous/redactions.rdx`.
#[must_use]
pub fn registry_path() -> Option<std::path::PathBuf> {
    let dir = crate::memory_store::data_dir().ok()?.join("nous");
    std::fs::create_dir_all(&dir).ok()?;
    Some(dir.join(REDACTION_FILE))
}

/// Load the registry (absent = empty; corrupt = typed error).
pub fn load_registry(path: &Path) -> Result<RedactionRegistry, RedactionError> {
    match std::fs::read(path) {
        Ok(bytes) => decode_registry(&bytes),
        Err(_) => Ok(RedactionRegistry::default()),
    }
}

/// The classification of a content-store fetch (-2: a single chokepoint so
/// every consumer treats a redaction uniformly).
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum FetchClass {
    /// The bytes are present and hash to the cid.
    Present(Vec<u8>),
    /// The blob is the tombstone AND the cid is in the registry — intentionally
    /// withheld.
    Redacted(RedactionReason),
    /// The content does not hash to the cid AND is NOT in the registry — CORRUPT.
    Tampered,
    /// No blob for that cid.
    Absent,
}

/// Classify a fetch against the redaction registry (-2). A cid whose content
/// hashes correctly = `Present`; a tombstone/mismatch with a registry entry =
/// `Redacted`; a mismatch with NO registry entry = `Tampered`; nothing = `Absent`.
#[must_use]
pub fn classify_fetch(
    store: &dyn ContentStore,
    registry: &RedactionRegistry,
    cid_hex: &str,
) -> FetchClass {
    let Some(cid) = crate::namespace::cid_from_hex(cid_hex) else {
        // Non-LocalCAS cid shape (e.g. Walrus): out of L-3 v1 scope — treat a
        // present blob as-is, else absent.
        return match store.get(cid_hex) {
            Some(bytes) => FetchClass::Present(bytes),
            None => FetchClass::Absent,
        };
    };
    let Some(bytes) = store.get(cid_hex) else {
        return FetchClass::Absent;
    };
    if crate::sha256_32(&bytes) == cid {
        return FetchClass::Present(bytes);
    }
    // Content does NOT hash to the cid: redacted (intentional) or tampered.
    match registry.is_redacted(&cid) {
        Some(reason) => FetchClass::Redacted(reason),
        None => FetchClass::Tampered,
    }
}

/// A redaction receipt (render data — never the redacted content).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RedactionReceipt {
    /// The cid that was redacted (hex).
    pub cid_hex: String,
    /// The reason class.
    pub reason: RedactionReason,
    /// The registry length after this redaction.
    pub registry_len: usize,
    /// True iff the cid existed in the store before redaction (else it was
    /// pre-recorded only).
    pub blob_overwritten: bool,
}

/// Why a redaction refused (fail-closed).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum RedactDeny {
    /// The cid was not 64-hex (LocalCAS) — v1 redacts LocalCAS blobs only.
    NotLocalCid,
    /// The content store overwrite failed.
    StoreIo,
    /// The registry failed to load/persist.
    RegistryFailed,
}

impl RedactDeny {
    /// A stable, honest one-liner for renders.
    #[must_use]
    pub const fn message(self) -> &'static str {
        match self {
            RedactDeny::NotLocalCid => "cid is not a 64-hex LocalCAS blob (v1 scope)",
            RedactDeny::StoreIo => "content store overwrite failed",
            RedactDeny::RegistryFailed => "redaction registry load/persist failed",
        }
    }
}

/// REDACT a cid: overwrite its ContentStore blob with the tombstone (-5: a
/// FIXED constant — no new content) and record {cid, reason, version} in the
/// append-only registry (-4). The LEDGER is NOT touched (-1). Idempotent
/// on the registry (a re-redaction updates nothing new but re-tombstones the blob).
pub fn redact_cid(
    store: &mut dyn ContentStore,
    registry_p: &Path,
    cid_hex: &str,
    reason: RedactionReason,
) -> Result<RedactionReceipt, RedactDeny> {
    let Some(_cid) = crate::namespace::cid_from_hex(cid_hex) else {
        return Err(RedactDeny::NotLocalCid);
    };
    let mut reg = load_registry(registry_p).map_err(|_| RedactDeny::RegistryFailed)?;
    // Overwrite the blob with the fixed tombstone (unrecoverable). `put` won't help
    // here (it content-addresses); redaction must write UNDER the existing cid name.
    let blob_overwritten = store.overwrite_raw(cid_hex, REDACTION_TOMBSTONE);
    if !blob_overwritten {
        // The cid may not be a store this backend can overwrite; still record the
        // redaction intent (the registry is the audit fact).
    }
    // Record (append-only; a duplicate cid keeps the earliest reason — honest history
    // lives in the version numbers). Only append if not already present.
    let cid = crate::namespace::cid_from_hex(cid_hex).ok_or(RedactDeny::NotLocalCid)?;
    if reg.is_redacted(&cid).is_none() {
        let version = u32::try_from(reg.entries.len()).unwrap_or(u32::MAX);
        reg.entries.push(RedactionEntry {
            cid,
            reason,
            version,
        });
    }
    let bytes = encode_registry(&reg);
    crate::memory_store::atomic_write(registry_p, &bytes)
        .map_err(|_| RedactDeny::RegistryFailed)?;
    Ok(RedactionReceipt {
        cid_hex: cid_hex.to_string(),
        reason,
        registry_len: reg.entries.len(),
        blob_overwritten,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::content_store::{LocalCasStore, PutClass};

    fn seq(from: u8) -> [u8; 32] {
        let mut c = [0u8; 32];
        for (i, b) in c.iter_mut().enumerate() {
            *b = u8::try_from(i).expect("small") + from;
        }
        c
    }

    /// Cross-language lock (Python 2026-07-08): the tombstone + the 2-entry golden
    /// registry match the Python vectors.
    #[test]
    fn registry_matches_python_golden_vector() {
        assert_eq!(REDACTION_TOMBSTONE.len(), 25);
        let reg = RedactionRegistry {
            entries: vec![
                RedactionEntry {
                    cid: seq(0),
                    reason: RedactionReason::Secret,
                    version: 3,
                },
                RedactionEntry {
                    cid: seq(1),
                    reason: RedactionReason::Pii,
                    version: 7,
                },
            ],
        };
        let bytes = encode_registry(&reg);
        assert_eq!(bytes.len(), 83);
        assert_eq!(
            crate::hex32(&crate::sha256_32(&bytes)),
            "bc7b2cb8f85f85ac43e390643a780277c94fa3195456825337a2eb1fe1133acb"
        );
        assert_eq!(decode_registry(&bytes).expect("decodes"), reg);
    }

    /// ★ -2/3 — the heart: a real blob is Present; after redaction it is
    /// Redacted (NOT tampered), the content is GONE, and a DIFFERENT corrupt blob
    /// is Tampered — the three are distinguishable.
    #[test]
    fn redacted_is_distinguishable_from_tampered_and_present() {
        let dir = std::env::temp_dir().join(format!("sinabro_l3_{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("mkdir");
        let mut store = LocalCasStore::with_dir(dir.clone());
        let reg_p = dir.join(REDACTION_FILE);
        // store a real secret-free blob.
        let cid = store
            .put(b"the sensitive source", PutClass::Public)
            .expect("put");
        // present + hashes.
        let reg0 = load_registry(&reg_p).expect("empty");
        assert!(matches!(
            classify_fetch(&store, &reg0, &cid),
            FetchClass::Present(_)
        ));
        // redact it.
        let receipt =
            redact_cid(&mut store, &reg_p, &cid, RedactionReason::Secret).expect("redact");
        assert!(receipt.blob_overwritten);
        assert_eq!(receipt.reason, RedactionReason::Secret);
        // the original bytes are GONE (the blob is the tombstone).
        assert_eq!(store.get(&cid).as_deref(), Some(REDACTION_TOMBSTONE));
        // classify: REDACTED (not tampered), with the reason.
        let reg1 = load_registry(&reg_p).expect("reg");
        assert_eq!(
            classify_fetch(&store, &reg1, &cid),
            FetchClass::Redacted(RedactionReason::Secret)
        );
        // a DIFFERENT cid with corrupt content (not in the registry) = Tampered.
        let other = store.put(b"another blob", PutClass::Public).expect("put2");
        // corrupt it by overwriting with junk that is NOT the tombstone and NOT in reg.
        assert!(store.overwrite_raw(&other, b"corrupted junk bytes"));
        assert_eq!(classify_fetch(&store, &reg1, &other), FetchClass::Tampered);
        // an unknown cid = Absent.
        assert_eq!(
            classify_fetch(&store, &reg1, &crate::hex32(&seq(9))),
            FetchClass::Absent
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// -1 — redaction does NOT touch a ledger: prove it by writing a ledger,
    /// redacting a store blob, and re-reading the ledger byte-for-byte.
    #[test]
    fn redaction_leaves_the_ledger_untouched() {
        let dir = std::env::temp_dir().join(format!("sinabro_l3led_{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("mkdir");
        let mut store = LocalCasStore::with_dir(dir.clone());
        let reg_p = dir.join(REDACTION_FILE);
        let ledger_p = dir.join("ledger.lgx");
        // a real ledger with a Proof op.
        crate::ledger::record_proof(&ledger_p, seq(1), seq(2), "owner").expect("proof");
        let ledger_before = std::fs::read(&ledger_p).expect("read");
        // redact a store blob — the ledger must NOT change.
        let cid = store.put(b"pii to remove", PutClass::Public).expect("put");
        redact_cid(&mut store, &reg_p, &cid, RedactionReason::Pii).expect("redact");
        assert_eq!(
            std::fs::read(&ledger_p).expect("read"),
            ledger_before,
            "the append-only ledger is byte-unchanged by redaction"
        );
        // and the chain still rewalks GREEN.
        assert!(crate::ledger::load_ledger(&ledger_p).is_ok());
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Registry codec fail-closed + the reason is a CLASS (no secret).
    #[test]
    fn registry_fails_closed() {
        let reg = RedactionRegistry {
            entries: vec![RedactionEntry {
                cid: seq(0),
                reason: RedactionReason::LegalRequest,
                version: 0,
            }],
        };
        let bytes = encode_registry(&reg);
        assert_eq!(decode_registry(&bytes[..3]), Err(RedactionError::Truncated));
        let mut bad = bytes.clone();
        bad[0] = b'X';
        assert_eq!(decode_registry(&bad), Err(RedactionError::BadMagic));
        let mut bad_reason = bytes.clone();
        bad_reason[9 + 32] = 9;
        assert_eq!(
            decode_registry(&bad_reason),
            Err(RedactionError::UnknownReason)
        );
        let mut trailing = bytes.clone();
        trailing.push(0);
        assert_eq!(
            decode_registry(&trailing),
            Err(RedactionError::TrailingBytes)
        );
    }
}
