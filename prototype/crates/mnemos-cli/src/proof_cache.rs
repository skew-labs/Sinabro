//! PF-2 (Nous IR) — the PROOF CACHE: verification results memoized GLOBALLY by
//! `(input-closure cid, procedure)` — a re-verification of identical bytes is a
//! LOOKUP, never a recomputation. "CI = a pure function over the graph" (build
//! a pure function over the graph.
//!
//! ## Key + receipt
//!
//! ```text
//! key     = sha256(PF_DOMAIN ‖ procedure_kind ‖ input_cid)     (input_cid = sha256(bytes))
//! receipt = "PRFX" ‖ ver ‖ kind ‖ key[32] ‖ input_cid[32]
//!           ‖ denied u8 ‖ le32 skipped ‖ le32 n ‖ node_cid[32]…
//!           ‖ le16 |author| ‖ author
//! ```
//!
//! The receipt STORES its key and a loader RE-DERIVES it (the AGRX
//! `id_matches_content` discipline) — a receipt filed under the wrong key, or a
//! tampered receipt body, is NEVER trusted: it is recomputed honestly
//! (-3). Cache home = `<data_dir>/nous/proofs/<key-hex>` (the LocalCAS
//! filename discipline: 64 lowercase hex, no separators, no traversal).
//!
//! ## The v1 procedure (an honest determinism catch)
//!
//! `DefnIngestTsV1` = the PURE N-1 ingest/normalization pass — deterministic BY
//! CONSTRUCTION (stronger than sandbox isolation; PF-1's nondeterminism fences
//! are unnecessary for an in-process pure function). The plan's `test run`
//! oracle (cargo/sui test) is NOT deterministic (timings, toolchain, machine
//! state) and its trust story is PF-3's slice — the procedure-kind wire keeps
//! that seam open, and this module refuses unknown kinds fail-closed.
//!
//! ## Ledger integration (the L-1 Proof op gets its first real producer)
//!
//! A COMPUTED verification appends `Proof { subject = the cache key, evidence =
//! sha256(receipt bytes) }` via [`crate::ledger::record_proof`] — a typed,
//! Proof-ONLY append (it cannot construct a Pin/NameBind; the pin ceremony
//! witness is untouched). A cache HIT appends NOTHING (the chain records
//! verification EVENTS, not lookups).
//!
//! Threat notes (PF-3 owns the full cache-trust model): this cache is local,
//! single-owner, and derived — poisoning it can mislead only its owner and is
//! repaired by deleting the entry (recompute). Cross-agent receipt trust,
//! signer reputation, and random re-verification are PF-3. custody untouched
//! : no network, no keys, no execution.

use std::path::{Path, PathBuf};

/// Domain tag for the proof-cache key (25 bytes, Python-verified 2026-07-08).
pub const PF_DOMAIN: &[u8] = b"sinabro.nous.proof.key.v1";

/// The receipt magic (4 bytes) — `PRFX`.
pub const PROOF_MAGIC: [u8; 4] = *b"PRFX";

/// The receipt wire version this codec WRITES.
pub const PROOF_VERSION: u8 = 1;

/// Max bytes of the author tag.
pub const PROOF_AUTHOR_CAP_BYTES: usize = 96;

/// The cache subdir under `<data_dir>/nous/`.
pub const PROOF_CACHE_SUBDIR: &str = "proofs";

/// The verification procedures this cache knows. The wire byte is bound into
/// the KEY, so it is STABLE (append only). Unknown bytes are refused.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum ProcedureKind {
    /// The PURE N-1 TypeScript ingest/normalization pass (deterministic by
    /// construction; runs in-process).
    DefnIngestTsV1,
}

impl ProcedureKind {
    /// The STABLE wire byte (bound into the key; never renumber).
    #[must_use]
    pub const fn wire(self) -> u8 {
        match self {
            ProcedureKind::DefnIngestTsV1 => 1,
        }
    }

    /// Decode a wire byte (fail-closed).
    #[must_use]
    pub const fn from_wire(b: u8) -> Option<Self> {
        match b {
            1 => Some(ProcedureKind::DefnIngestTsV1),
            _ => None,
        }
    }

    /// A stable label (for renders).
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            ProcedureKind::DefnIngestTsV1 => "defn-ingest-ts.v1",
        }
    }
}

/// The proof-cache key: `sha256(PF_DOMAIN ‖ kind ‖ input_cid)`.
#[must_use]
pub fn proof_key(kind: ProcedureKind, input_cid: &[u8; 32]) -> [u8; 32] {
    let mut pre = Vec::with_capacity(PF_DOMAIN.len() + 1 + 32);
    pre.extend_from_slice(PF_DOMAIN);
    pre.push(kind.wire());
    pre.extend_from_slice(input_cid);
    crate::sha256_32(&pre)
}

/// The DETERMINISTIC result of the v1 procedure (canonical value bytes).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IngestResultSummary {
    /// True iff the fail-closed lexer refused the file (still a cacheable fact).
    pub denied: bool,
    /// Non-definition statements skipped.
    pub skipped: u32,
    /// The node cids in source order.
    pub nodes: Vec<[u8; 32]>,
}

/// A verification receipt — the cache VALUE (self-describing, key re-derivable).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProofReceipt {
    /// The cache key (re-derived + checked on load).
    pub key: [u8; 32],
    /// Which procedure ran.
    pub kind: ProcedureKind,
    /// The input-closure cid (`sha256(input bytes)`).
    pub input_cid: [u8; 32],
    /// The deterministic result.
    pub result: IngestResultSummary,
    /// Who computed it (data stub; signer reputation = PF-3).
    pub author: String,
}

/// Typed codec/cache failures (fail-closed; a bad receipt is never trusted).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum ProofError {
    /// Bytes shorter than a field demanded.
    Truncated,
    /// The magic was not [`PROOF_MAGIC`].
    BadMagic,
    /// The version byte was unknown.
    UnknownVersion,
    /// An unknown procedure kind.
    UnknownKind,
    /// The stored key does not re-derive from `(kind, input_cid)` — mis-filed
    /// or tampered.
    KeyMismatch,
    /// The author was over cap / not UTF-8.
    BadText,
    /// Trailing garbage after the last field.
    TrailingBytes,
}

impl ProofError {
    /// A stable, honest one-liner for renders.
    #[must_use]
    pub const fn message(self) -> &'static str {
        match self {
            ProofError::Truncated => "truncated receipt",
            ProofError::BadMagic => "bad receipt magic",
            ProofError::UnknownVersion => "unknown receipt version",
            ProofError::UnknownKind => "unknown procedure kind",
            ProofError::KeyMismatch => "receipt key does not re-derive (tampered/mis-filed)",
            ProofError::BadText => "author over cap or not UTF-8",
            ProofError::TrailingBytes => "trailing bytes",
        }
    }
}

/// Encode a receipt to its canonical bytes. `None` iff a field is invalid.
#[must_use]
pub fn encode_receipt(r: &ProofReceipt) -> Option<Vec<u8>> {
    if r.author.len() > PROOF_AUTHOR_CAP_BYTES {
        return None;
    }
    let mut b = Vec::with_capacity(150 + r.result.nodes.len() * 32);
    b.extend_from_slice(&PROOF_MAGIC);
    b.push(PROOF_VERSION);
    b.push(r.kind.wire());
    b.extend_from_slice(&r.key);
    b.extend_from_slice(&r.input_cid);
    b.push(u8::from(r.result.denied));
    b.extend_from_slice(&r.result.skipped.to_le_bytes());
    b.extend_from_slice(&u32::try_from(r.result.nodes.len()).ok()?.to_le_bytes());
    for c in &r.result.nodes {
        b.extend_from_slice(c);
    }
    b.extend_from_slice(&u16::try_from(r.author.len()).ok()?.to_le_bytes());
    b.extend_from_slice(r.author.as_bytes());
    Some(b)
}

fn take<'a>(bytes: &'a [u8], at: &mut usize, n: usize) -> Result<&'a [u8], ProofError> {
    let end = at.checked_add(n).ok_or(ProofError::Truncated)?;
    if end > bytes.len() {
        return Err(ProofError::Truncated);
    }
    let s = &bytes[*at..end];
    *at = end;
    Ok(s)
}

fn take32(bytes: &[u8], at: &mut usize) -> Result<[u8; 32], ProofError> {
    let mut out = [0u8; 32];
    out.copy_from_slice(take(bytes, at, 32)?);
    Ok(out)
}

/// Decode + VERIFY a receipt (fail-closed): magic/version/kind gates, then the
/// stored key must RE-DERIVE from `(kind, input_cid)` (-3).
pub fn decode_receipt(bytes: &[u8]) -> Result<ProofReceipt, ProofError> {
    let mut at = 0usize;
    if take(bytes, &mut at, 4)? != PROOF_MAGIC {
        return Err(ProofError::BadMagic);
    }
    if take(bytes, &mut at, 1)?[0] != PROOF_VERSION {
        return Err(ProofError::UnknownVersion);
    }
    let kind =
        ProcedureKind::from_wire(take(bytes, &mut at, 1)?[0]).ok_or(ProofError::UnknownKind)?;
    let key = take32(bytes, &mut at)?;
    let input_cid = take32(bytes, &mut at)?;
    let denied = take(bytes, &mut at, 1)?[0] != 0;
    let mut w = [0u8; 4];
    w.copy_from_slice(take(bytes, &mut at, 4)?);
    let skipped = u32::from_le_bytes(w);
    w.copy_from_slice(take(bytes, &mut at, 4)?);
    let n = u32::from_le_bytes(w) as usize;
    let mut nodes = Vec::with_capacity(n.min(4096));
    for _ in 0..n {
        nodes.push(take32(bytes, &mut at)?);
    }
    let mut l = [0u8; 2];
    l.copy_from_slice(take(bytes, &mut at, 2)?);
    let alen = u16::from_le_bytes(l) as usize;
    let author = core::str::from_utf8(take(bytes, &mut at, alen)?)
        .map_err(|_| ProofError::BadText)?
        .to_string();
    if author.len() > PROOF_AUTHOR_CAP_BYTES {
        return Err(ProofError::BadText);
    }
    if at != bytes.len() {
        return Err(ProofError::TrailingBytes);
    }
    if key != proof_key(kind, &input_cid) {
        return Err(ProofError::KeyMismatch);
    }
    Ok(ProofReceipt {
        key,
        kind,
        input_cid,
        result: IngestResultSummary {
            denied,
            skipped,
            nodes,
        },
        author,
    })
}

/// The cache dir: `<data_dir>/nous/proofs/` (created on demand).
#[must_use]
pub fn proof_cache_dir() -> Option<PathBuf> {
    let dir = crate::memory_store::data_dir()
        .ok()?
        .join("nous")
        .join(PROOF_CACHE_SUBDIR);
    std::fs::create_dir_all(&dir).ok()?;
    Some(dir)
}

/// The receipt path for a key — the LocalCAS filename discipline: exactly the
/// 64-lowercase-hex key (no separators possible ⇒ no traversal).
#[must_use]
pub fn receipt_path(dir: &Path, key: &[u8; 32]) -> PathBuf {
    dir.join(crate::hex32(key))
}

/// Parse a cache FILENAME back to its key iff it is exactly 64 lowercase hex
/// (PF-3 walks the dir; anything else is not a receipt). Inverse of the filename
/// discipline above.
#[must_use]
pub fn cid_like_key(name: &str) -> Option<[u8; 32]> {
    crate::namespace::cid_from_hex(name)
}

/// Load + verify the receipt for `key` (`None` = absent or UNTRUSTWORTHY — a
/// corrupt/mis-filed receipt is treated as a miss, never trusted).
#[must_use]
pub fn load_receipt(dir: &Path, key: &[u8; 32]) -> Option<ProofReceipt> {
    let bytes = std::fs::read(receipt_path(dir, key)).ok()?;
    match decode_receipt(&bytes) {
        Ok(r) if r.key == *key => Some(r),
        _ => None,
    }
}

/// Run the PURE v1 procedure (deterministic by construction).
#[must_use]
pub fn run_defn_ingest_procedure(src: &str) -> IngestResultSummary {
    let report = crate::ingest_ts::ingest_ts_source(src);
    IngestResultSummary {
        denied: report.deny.is_some(),
        skipped: u32::try_from(report.skipped_statements).unwrap_or(u32::MAX),
        nodes: report
            .nodes
            .iter()
            .filter_map(|n| crate::namespace::cid_from_hex(&n.cid))
            .collect(),
    }
}

/// How a verification concluded.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum VerifyOutcome {
    /// The cache answered — the procedure DID NOT RUN (recomputation 0).
    Hit(ProofReceipt),
    /// A fresh computation: receipt stored + a `Proof` op recorded on the ledger.
    Computed {
        /// The new receipt.
        receipt: ProofReceipt,
        /// `sha256(receipt bytes)` — the ledger evidence digest.
        evidence: [u8; 32],
        /// The ledger length after the Proof op landed.
        ledger_len: usize,
        /// True iff a cached entry existed but was corrupt/mis-filed and was
        /// honestly recomputed + replaced.
        replaced_corrupt: bool,
        /// PF-3: true iff the input CLOSURE landed in the ContentStore (so a
        /// later random re-verification can re-run the claim). False = the
        /// secret-scan belt refused the source — that entry is honestly
        /// UNAUDITABLE, never fake-passed.
        closure_stored: bool,
    },
}

/// Why a verification refused (fail-closed; nothing written).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum VerifyDeny {
    /// The receipt failed to encode (over-cap author).
    EncodeFailed,
    /// The cache write failed.
    CacheIo,
    /// The ledger append failed (incl. a chain RED).
    LedgerFailed,
}

/// VERIFY `src` under the v1 procedure: LOOKUP first (a hit returns BEFORE the
/// procedure is reachable-1); on a miss, compute, store the receipt,
/// persist the input CLOSURE to the ContentStore (best-effort — PF-3's raw
/// material; a LocalCAS cid IS `hex(input_cid)` by construction), and record
/// the `Proof` op (subject = the key, evidence = the receipt digest).
pub fn verify_ts(
    cache_dir: &Path,
    ledger_p: &Path,
    store: &mut dyn crate::content_store::ContentStore,
    src: &str,
    author: &str,
) -> Result<VerifyOutcome, VerifyDeny> {
    let input_cid = crate::sha256_32(src.as_bytes());
    let key = proof_key(ProcedureKind::DefnIngestTsV1, &input_cid);
    let existed = receipt_path(cache_dir, &key).exists();
    if let Some(receipt) = load_receipt(cache_dir, &key) {
        // The lookup IS the verification — the procedure below is NOT reached.
        return Ok(VerifyOutcome::Hit(receipt));
    }
    let result = run_defn_ingest_procedure(src);
    let receipt = ProofReceipt {
        key,
        kind: ProcedureKind::DefnIngestTsV1,
        input_cid,
        result,
        author: author.to_string(),
    };
    let bytes = encode_receipt(&receipt).ok_or(VerifyDeny::EncodeFailed)?;
    let evidence = crate::sha256_32(&bytes);
    // PF-3 closure: best-effort — the public secret-scan belt may refuse a
    // secret-shaped source ⇒ closure absent ⇒ honestly unauditable (-4).
    let closure_stored = store
        .put(src.as_bytes(), crate::content_store::PutClass::Public)
        .is_some();
    crate::memory_store::atomic_write(&receipt_path(cache_dir, &key), &bytes)
        .map_err(|_| VerifyDeny::CacheIo)?;
    let ledger_len = crate::ledger::record_proof(ledger_p, key, evidence, author)
        .map_err(|_| VerifyDeny::LedgerFailed)?;
    Ok(VerifyOutcome::Computed {
        receipt,
        evidence,
        ledger_len,
        replaced_corrupt: existed,
        closure_stored,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn seq(from: u8) -> [u8; 32] {
        let mut c = [0u8; 32];
        for (i, b) in c.iter_mut().enumerate() {
            *b = u8::try_from(i).expect("small") + from;
        }
        c
    }

    /// Cross-language lock (Python 2026-07-08): key derivation + the 150-byte
    /// golden receipt match the Python vectors; round-trip decodes.
    #[test]
    fn receipt_matches_python_golden_vectors() {
        let input = seq(0);
        let key = proof_key(ProcedureKind::DefnIngestTsV1, &input);
        assert_eq!(
            crate::hex32(&key),
            "ac19c6e8833594c64851c17211f4cbd398e90d3799c7fb50abe1527517ca2d59"
        );
        let r = ProofReceipt {
            key,
            kind: ProcedureKind::DefnIngestTsV1,
            input_cid: input,
            result: IngestResultSummary {
                denied: false,
                skipped: 3,
                nodes: vec![seq(1), seq(2)],
            },
            author: "owner".to_string(),
        };
        let bytes = encode_receipt(&r).expect("encodes");
        assert_eq!(bytes.len(), 150);
        assert_eq!(
            crate::hex32(&crate::sha256_32(&bytes)),
            "c2ef977050b2dd149e8dc36bae32b21e468efe938161cdafe8446ae69cc6feab"
        );
        assert_eq!(decode_receipt(&bytes).expect("decodes"), r);
    }

    /// -3 — fail-closed: tamper/mis-file/unknown-kind receipts are NEVER
    /// trusted (typed refusal or a load miss).
    #[test]
    fn corrupt_receipts_are_never_trusted() {
        let input = seq(0);
        let key = proof_key(ProcedureKind::DefnIngestTsV1, &input);
        let r = ProofReceipt {
            key,
            kind: ProcedureKind::DefnIngestTsV1,
            input_cid: input,
            result: IngestResultSummary {
                denied: false,
                skipped: 0,
                nodes: vec![],
            },
            author: "owner".to_string(),
        };
        let bytes = encode_receipt(&r).expect("encodes");
        // flip a byte inside input_cid ⇒ the stored key no longer re-derives.
        let mut bad = bytes.clone();
        bad[40] ^= 1;
        assert_eq!(decode_receipt(&bad), Err(ProofError::KeyMismatch));
        assert_eq!(decode_receipt(&bytes[..10]), Err(ProofError::Truncated));
        let mut trailing = bytes.clone();
        trailing.push(0);
        assert_eq!(decode_receipt(&trailing), Err(ProofError::TrailingBytes));
        let mut badkind = bytes.clone();
        badkind[5] = 9;
        assert_eq!(decode_receipt(&badkind), Err(ProofError::UnknownKind));
        // load path: a receipt filed under the WRONG key is a miss, never trusted.
        let dir = std::env::temp_dir().join(format!("sinabro_pf2_mf_{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("mkdir");
        let wrong = seq(9);
        std::fs::write(receipt_path(&dir, &wrong), &bytes).expect("write");
        assert_eq!(load_receipt(&dir, &wrong), None, "mis-filed = miss");
        let _ = std::fs::remove_dir_all(&dir);
    }

    fn temp_sinks(tag: &str) -> (PathBuf, PathBuf) {
        let root = std::env::temp_dir().join(format!("sinabro_pf2_{tag}_{}", std::process::id()));
        std::fs::create_dir_all(root.join("proofs")).expect("mkdir");
        std::fs::create_dir_all(root.join("cas")).expect("mkdir");
        (root.join("proofs"), root.join("ledger.lgx"))
    }

    /// A LocalCAS store rooted next to a test's proof cache (for the PF-3 closure).
    fn store_for(cache: &std::path::Path) -> crate::content_store::LocalCasStore {
        crate::content_store::LocalCasStore::with_dir(cache.parent().expect("root").join("cas"))
    }

    /// ★ -1/2 — the memoization heart: run 1 = COMPUTED (receipt stored,
    /// Proof op on the chain, evidence == receipt digest); run 2 on IDENTICAL
    /// bytes = HIT with the IDENTICAL receipt and the LEDGER UNCHANGED
    /// (recomputation 0, recording 0); different bytes = a different key.
    #[test]
    fn second_verification_is_a_lookup() {
        let (cache, lp) = temp_sinks("memo");
        let src = "export function add(a: number, b: number) { return a + b; }\n";
        let out1 = verify_ts(&cache, &lp, &mut store_for(&cache), src, "owner").expect("run 1");
        let VerifyOutcome::Computed {
            receipt: r1,
            evidence,
            ledger_len,
            replaced_corrupt,
            closure_stored,
        } = out1
        else {
            panic!("run 1 must COMPUTE");
        };
        assert!(closure_stored, "a benign source closure is CAS-persisted");
        assert!(!replaced_corrupt);
        assert_eq!(ledger_len, 1);
        assert_eq!(r1.result.nodes.len(), 1);
        // the chain holds EXACTLY the Proof op, evidence == sha256(receipt bytes).
        let chain = crate::ledger::load_ledger(&lp).expect("chain GREEN");
        assert_eq!(chain.ops.len(), 1);
        match &chain.ops[0] {
            crate::ledger::LedgerOp::Proof {
                subject,
                evidence: ev,
                ..
            } => {
                assert_eq!(*subject, r1.key);
                assert_eq!(*ev, evidence);
                let stored = std::fs::read(receipt_path(&cache, &r1.key)).expect("receipt");
                assert_eq!(crate::sha256_32(&stored), evidence);
            }
            other => panic!("expected a Proof op, got {other:?}"),
        }
        let ledger_bytes = std::fs::read(&lp).expect("ledger");
        // run 2: IDENTICAL bytes ⇒ HIT, identical receipt, ledger byte-unchanged.
        let out2 = verify_ts(&cache, &lp, &mut store_for(&cache), src, "owner").expect("run 2");
        assert_eq!(
            out2,
            VerifyOutcome::Hit(r1.clone()),
            "lookup, not recompute"
        );
        assert_eq!(
            std::fs::read(&lp).expect("ledger"),
            ledger_bytes,
            "a HIT records nothing"
        );
        // determinism: a fresh cache recomputes to the SAME receipt bytes.
        let (cache2, lp2) = temp_sinks("memo2");
        let out3 = verify_ts(&cache2, &lp2, &mut store_for(&cache2), src, "owner").expect("run 3");
        let VerifyOutcome::Computed { receipt: r3, .. } = out3 else {
            panic!("fresh cache must COMPUTE");
        };
        assert_eq!(encode_receipt(&r3), encode_receipt(&r1), "deterministic");
        // different bytes ⇒ different key (correct keying).
        let out4 = verify_ts(
            &cache,
            &lp,
            &mut store_for(&cache),
            "export function add(a: number, b: number) { return a - b; }\n",
            "owner",
        )
        .expect("run 4");
        let VerifyOutcome::Computed { receipt: r4, .. } = out4 else {
            panic!("different content must COMPUTE");
        };
        assert_ne!(r4.key, r1.key);
        let _ = std::fs::remove_dir_all(cache.parent().expect("parent"));
        let _ = std::fs::remove_dir_all(cache2.parent().expect("parent"));
    }

    /// A corrupt cached entry is honestly RECOMPUTED and replaced (and the
    /// replacement is flagged in the outcome).
    #[test]
    fn corrupt_cache_entry_recomputes_honestly() {
        let (cache, lp) = temp_sinks("corrupt");
        let src = "const x = 1;\n";
        let VerifyOutcome::Computed { receipt, .. } =
            verify_ts(&cache, &lp, &mut store_for(&cache), src, "owner").expect("seed")
        else {
            panic!("seed must COMPUTE");
        };
        // tamper the stored receipt.
        let p = receipt_path(&cache, &receipt.key);
        let mut bytes = std::fs::read(&p).expect("read");
        bytes[7] ^= 1;
        std::fs::write(&p, &bytes).expect("tamper");
        // verify again: the corrupt receipt is NOT trusted — recomputed + replaced.
        let VerifyOutcome::Computed {
            receipt: r2,
            replaced_corrupt,
            ..
        } = verify_ts(&cache, &lp, &mut store_for(&cache), src, "owner").expect("recompute")
        else {
            panic!("must recompute, never trust a corrupt receipt");
        };
        assert!(replaced_corrupt, "honest replacement flag");
        assert_eq!(r2.key, receipt.key);
        // the replacement is trustworthy again.
        assert!(matches!(
            verify_ts(&cache, &lp, &mut store_for(&cache), src, "owner").expect("hit"),
            VerifyOutcome::Hit(_)
        ));
        let _ = std::fs::remove_dir_all(cache.parent().expect("parent"));
    }

    /// A lexer-DENIED file is a cacheable fact too (denied=true receipt; the
    /// second run is still a lookup).
    #[test]
    fn denied_ingest_is_a_cacheable_fact() {
        let (cache, lp) = temp_sinks("denied");
        let src = "const s = 'unterminated;\n";
        let VerifyOutcome::Computed { receipt, .. } =
            verify_ts(&cache, &lp, &mut store_for(&cache), src, "owner").expect("compute")
        else {
            panic!("must compute");
        };
        assert!(receipt.result.denied);
        assert!(receipt.result.nodes.is_empty());
        assert!(matches!(
            verify_ts(&cache, &lp, &mut store_for(&cache), src, "owner").expect("hit"),
            VerifyOutcome::Hit(_)
        ));
        let _ = std::fs::remove_dir_all(cache.parent().expect("parent"));
    }
}
