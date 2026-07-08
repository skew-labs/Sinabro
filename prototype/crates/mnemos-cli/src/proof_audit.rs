//! PF-3 (Nous IR) — PROOF AUDIT: random re-verification + signer reputation (the
//! cache-trust triple).
//!
//! PF-2 made verification a memoized lookup. PF-3 is the counter to a POISONED
//! receipt (a claim that never held): identity · reputation · random re-run.
//!
//! ## Selection (-1: write-time unpredictable, audit-time deterministic)
//!
//! ```text
//! selected(seed, key) = u16_le(sha256(AUDIT_DOMAIN ‖ seed ‖ key)) < rate_bps·65536/10000
//! ```
//!
//! The SEED is supplied at AUDIT time, so a write-time poisoner cannot know which
//! entries a future audit will re-run; given `(seed, rate)` the selection is
//! DETERMINISTIC — an audit is reproducible evidence (no clock, no randomness).
//!
//! ## Re-verification (-2/3/4)
//!
//! A selected receipt is re-run from its CAS CLOSURE (persisted on the PF-2
//! compute path; a LocalCAS cid IS `hex(input_cid)`). The CLAIM fields
//! (key/kind/input_cid/result) must reproduce — the author is EXCLUDED (claim ≠
//! identity). A mismatch bumps the claimant's `mismatched` counter (monotone, no
//! recovery), records an `Audit{passed=false}` op, and collapses the standing. A
//! receipt whose closure is absent (secret-scan refused / pre-PF-3) or no longer
//! hashes to its `input_cid` is UNAUDITABLE / a mismatch — never fake-passed.
//!
//! ## Reputation (-6: counters are truth; the score is derived)
//!
//! The `RPUX` ledger stores per-author `(passed, mismatched)` counters ONLY; the
//! standing is DERIVED (`10000·passed/(passed+100·mismatched)`) so nothing drifts.
//! One mismatch ⇒ SLASHED (no recovery path, v1 honest). Identity is the author
//! data tag (the L-1/N-2 stub — cryptographic signatures are custody-adjacent,
//! deferred); the reputation's trust ceiling is stated, not overclaimed. custody
//! untouched: no network, no keys, no execution.

use std::collections::BTreeMap;
use std::path::Path;

use crate::content_store::ContentStore;
use crate::proof_cache::{ProcedureKind, ProofReceipt, decode_receipt, proof_key};

/// Domain tag for the audit-selection hash (27 bytes, Python-verified 2026-07-08).
pub const AUDIT_DOMAIN: &[u8] = b"sinabro.nous.proof.audit.v1";

/// The reputation-ledger magic (4 bytes) — `RPUX`.
pub const REP_MAGIC: [u8; 4] = *b"RPUX";

/// The reputation wire version.
pub const REP_VERSION: u8 = 1;

/// Max bytes of an author tag in the reputation ledger.
pub const REP_AUTHOR_CAP_BYTES: usize = 96;

/// The reputation file under `<data_dir>/nous/`.
pub const REP_FILE: &str = "reputation.rpx";

/// The per-mismatch penalty weight (a heavy slash: one strike collapses a long
/// clean record — Python-verified `standing(99,1)=4974`).
pub const MISMATCH_PENALTY: u64 = 100;

/// The u16 selection threshold for `rate_bps` (Python-verified: 2500→16384).
#[must_use]
pub fn selection_threshold(rate_bps: u32) -> u32 {
    // rate_bps in 0..=10000; (rate_bps * 65536) / 10000. Saturates above full.
    (u64::from(rate_bps).saturating_mul(65536) / 10000).min(65536) as u32
}

/// True iff the receipt keyed by `key` is SELECTED for audit under `(seed, rate)`.
#[must_use]
pub fn is_selected(seed: &[u8], key: &[u8; 32], rate_bps: u32) -> bool {
    let mut pre = Vec::with_capacity(AUDIT_DOMAIN.len() + seed.len() + 32);
    pre.extend_from_slice(AUDIT_DOMAIN);
    pre.extend_from_slice(seed);
    pre.extend_from_slice(key);
    let h = crate::sha256_32(&pre);
    let draw = u32::from(u16::from_le_bytes([h[0], h[1]]));
    draw < selection_threshold(rate_bps)
}

/// One claimant's audit history (counters only — the standing is derived).
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct RepCounters {
    /// Re-verifications that reproduced the claim.
    pub passed: u64,
    /// Detected mismatches (monotone; no decrement path — SLASHED is permanent).
    pub mismatched: u64,
}

impl RepCounters {
    /// The derived standing in basis points, or `None` if never audited. One
    /// mismatch weighs [`MISMATCH_PENALTY`]× a pass (a heavy slash).
    #[must_use]
    pub fn standing_bps(self) -> Option<u32> {
        let denom = self
            .passed
            .saturating_add(MISMATCH_PENALTY.saturating_mul(self.mismatched));
        if denom == 0 {
            return None;
        }
        Some((self.passed.saturating_mul(10000) / denom) as u32)
    }

    /// SLASHED iff any mismatch was ever recorded (permanent in v1 — honest).
    #[must_use]
    pub fn is_slashed(self) -> bool {
        self.mismatched > 0
    }
}

/// The reputation ledger: author → counters.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ReputationLedger {
    /// Per-author counters, name-keyed (sorted for a canonical encoding).
    pub entries: BTreeMap<String, RepCounters>,
}

/// Typed reputation codec failures (fail-closed).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum RepError {
    /// Bytes shorter than a field demanded.
    Truncated,
    /// The magic was not [`REP_MAGIC`].
    BadMagic,
    /// The version byte was unknown.
    UnknownVersion,
    /// An author was over cap / not UTF-8.
    BadAuthor,
    /// Trailing garbage after the last entry.
    TrailingBytes,
}

impl RepError {
    /// A stable, honest one-liner for renders.
    #[must_use]
    pub const fn message(self) -> &'static str {
        match self {
            RepError::Truncated => "truncated reputation ledger",
            RepError::BadMagic => "bad reputation magic",
            RepError::UnknownVersion => "unknown reputation version",
            RepError::BadAuthor => "author over cap or not UTF-8",
            RepError::TrailingBytes => "trailing bytes",
        }
    }
}

/// Encode the reputation ledger to canonical bytes (`RPUX`). `None` iff an
/// author is over cap.
#[must_use]
pub fn encode_reputation(rep: &ReputationLedger) -> Option<Vec<u8>> {
    let mut b = Vec::with_capacity(9 + rep.entries.len() * 25);
    b.extend_from_slice(&REP_MAGIC);
    b.push(REP_VERSION);
    b.extend_from_slice(&u32::try_from(rep.entries.len()).ok()?.to_le_bytes());
    for (author, c) in &rep.entries {
        if author.len() > REP_AUTHOR_CAP_BYTES {
            return None;
        }
        b.extend_from_slice(&u16::try_from(author.len()).ok()?.to_le_bytes());
        b.extend_from_slice(author.as_bytes());
        b.extend_from_slice(&c.passed.to_le_bytes());
        b.extend_from_slice(&c.mismatched.to_le_bytes());
    }
    Some(b)
}

fn take<'a>(bytes: &'a [u8], at: &mut usize, n: usize) -> Result<&'a [u8], RepError> {
    let end = at.checked_add(n).ok_or(RepError::Truncated)?;
    if end > bytes.len() {
        return Err(RepError::Truncated);
    }
    let s = &bytes[*at..end];
    *at = end;
    Ok(s)
}

/// Decode the reputation ledger (fail-closed).
pub fn decode_reputation(bytes: &[u8]) -> Result<ReputationLedger, RepError> {
    let mut at = 0usize;
    if take(bytes, &mut at, 4)? != REP_MAGIC {
        return Err(RepError::BadMagic);
    }
    if take(bytes, &mut at, 1)?[0] != REP_VERSION {
        return Err(RepError::UnknownVersion);
    }
    let mut c = [0u8; 4];
    c.copy_from_slice(take(bytes, &mut at, 4)?);
    let count = u32::from_le_bytes(c) as usize;
    let mut entries = BTreeMap::new();
    for _ in 0..count {
        let mut l = [0u8; 2];
        l.copy_from_slice(take(bytes, &mut at, 2)?);
        let alen = u16::from_le_bytes(l) as usize;
        let author = core::str::from_utf8(take(bytes, &mut at, alen)?)
            .map_err(|_| RepError::BadAuthor)?
            .to_string();
        if author.len() > REP_AUTHOR_CAP_BYTES {
            return Err(RepError::BadAuthor);
        }
        let mut w = [0u8; 8];
        w.copy_from_slice(take(bytes, &mut at, 8)?);
        let passed = u64::from_le_bytes(w);
        w.copy_from_slice(take(bytes, &mut at, 8)?);
        let mismatched = u64::from_le_bytes(w);
        entries.insert(author, RepCounters { passed, mismatched });
    }
    if at != bytes.len() {
        return Err(RepError::TrailingBytes);
    }
    Ok(ReputationLedger { entries })
}

/// The reputation-ledger path: `<data_dir>/nous/reputation.rpx`.
#[must_use]
pub fn reputation_path() -> Option<std::path::PathBuf> {
    let dir = crate::memory_store::data_dir().ok()?.join("nous");
    std::fs::create_dir_all(&dir).ok()?;
    Some(dir.join(REP_FILE))
}

/// Load the reputation ledger (absent = empty; a corrupt ledger is a typed RED).
pub fn load_reputation(path: &Path) -> Result<ReputationLedger, RepError> {
    match std::fs::read(path) {
        Ok(bytes) => decode_reputation(&bytes),
        Err(_) => Ok(ReputationLedger::default()),
    }
}

/// The per-receipt audit verdict.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum AuditVerdict {
    /// Re-run reproduced the claim.
    Pass,
    /// Re-run diverged from the stored claim (a slash).
    Mismatch,
    /// The receipt was not selected under `(seed, rate)`.
    Skipped,
    /// The closure is absent / the receipt is corrupt — cannot re-run (never a
    /// pass; the count is the owner's signal).
    Unauditable,
}

/// The RE-VERIFICATION of ONE receipt against its CAS closure. PURE (given the
/// store) — no clock, no network. Compares the CLAIM only (author excluded).
#[must_use]
pub fn reverify_receipt(store: &dyn ContentStore, receipt: &ProofReceipt) -> AuditVerdict {
    // Fetch the closure by its content id (== hex(input_cid), by construction).
    let Some(src_bytes) = store.get(&crate::hex32(&receipt.input_cid)) else {
        return AuditVerdict::Unauditable;
    };
    // The closure MUST hash back to input_cid (a swapped closure is a mismatch).
    if crate::sha256_32(&src_bytes) != receipt.input_cid {
        return AuditVerdict::Mismatch;
    }
    let Ok(src) = core::str::from_utf8(&src_bytes) else {
        return AuditVerdict::Mismatch;
    };
    // Re-run the SAME deterministic procedure and re-derive the CLAIM.
    let redone_result = crate::proof_cache::run_defn_ingest_procedure(src);
    let redone_key = proof_key(ProcedureKind::DefnIngestTsV1, &receipt.input_cid);
    // Claim = key + kind + input_cid + result. Author is NOT compared (-3).
    if redone_key == receipt.key
        && receipt.kind == ProcedureKind::DefnIngestTsV1
        && redone_result == receipt.result
    {
        AuditVerdict::Pass
    } else {
        AuditVerdict::Mismatch
    }
}

/// One audited entry (render data).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuditedEntry {
    /// The receipt key (hex).
    pub key_hex: String,
    /// The claimant.
    pub author: String,
    /// The verdict.
    pub verdict: AuditVerdict,
}

/// The whole-run audit result.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuditReport {
    /// Per-entry outcomes (selected only; skipped entries omitted).
    pub audited: Vec<AuditedEntry>,
    /// Count of receipts considered.
    pub considered: usize,
    /// Count re-run.
    pub selected: usize,
    /// Count that reproduced.
    pub passed: usize,
    /// Count that DIVERGED (slashes recorded).
    pub mismatched: usize,
    /// Count unauditable (closure absent / corrupt receipt).
    pub unauditable: usize,
    /// Corrupt receipt FILES skipped at load (author unrecoverable).
    pub corrupt_receipts: usize,
}

/// Run an audit over the proof cache: for every receipt file, decide selection
/// under `(seed, rate)`, re-run the selected ones, update the reputation ledger
/// (fail-closed persist), and record an `Audit` op per selected receipt. PURE
/// selection/re-run; the only writes are the reputation ledger + the L-1 chain.
pub fn run_audit(
    cache_dir: &Path,
    ledger_p: &Path,
    rep_p: &Path,
    store: &dyn ContentStore,
    seed: &[u8],
    rate_bps: u32,
    auditor: &str,
) -> Result<AuditReport, RepError> {
    let mut rep = load_reputation(rep_p)?;
    let mut report = AuditReport {
        audited: Vec::new(),
        considered: 0,
        selected: 0,
        passed: 0,
        mismatched: 0,
        unauditable: 0,
        corrupt_receipts: 0,
    };
    // Deterministic order: sort the receipt filenames.
    let mut names: Vec<String> = match std::fs::read_dir(cache_dir) {
        Ok(rd) => rd
            .filter_map(|e| e.ok().map(|e| e.file_name().to_string_lossy().to_string()))
            .collect(),
        Err(_) => Vec::new(),
    };
    names.sort();
    // Audit ops to append (collected, then chained once — the chain is atomic).
    let mut audit_ops: Vec<(bool, [u8; 32], [u8; 32])> = Vec::new();
    for name in names {
        // Only well-formed cache filenames (64-hex keys) are receipts.
        let Some(key) = crate::proof_cache::cid_like_key(&name) else {
            continue;
        };
        let Ok(bytes) = std::fs::read(cache_dir.join(&name)) else {
            continue;
        };
        let receipt = match decode_receipt(&bytes) {
            Ok(r) if r.key == key => r,
            _ => {
                // A corrupt/mis-filed receipt: honestly counted; no slash target.
                report.corrupt_receipts += 1;
                continue;
            }
        };
        report.considered += 1;
        if !is_selected(seed, &key, rate_bps) {
            continue;
        }
        report.selected += 1;
        let verdict = reverify_receipt(store, &receipt);
        match verdict {
            AuditVerdict::Pass => {
                // Only a real verdict touches reputation (Unauditable creates NO
                // entry — an absent closure is not a pass and not a slash).
                let counters = rep.entries.entry(receipt.author.clone()).or_default();
                counters.passed = counters.passed.saturating_add(1);
                report.passed += 1;
                audit_ops.push((true, key, crate::sha256_32(&bytes)));
            }
            AuditVerdict::Mismatch => {
                let counters = rep.entries.entry(receipt.author.clone()).or_default();
                counters.mismatched = counters.mismatched.saturating_add(1);
                report.mismatched += 1;
                // Evidence for a mismatch = the digest of the STORED (claimed)
                // receipt bytes that failed to reproduce.
                audit_ops.push((false, key, crate::sha256_32(&bytes)));
            }
            AuditVerdict::Unauditable => {
                report.unauditable += 1;
            }
            AuditVerdict::Skipped => {}
        }
        report.audited.push(AuditedEntry {
            key_hex: crate::hex32(&key),
            author: receipt.author,
            verdict,
        });
    }
    // Persist reputation (fail-closed) then append the Audit ops to the chain.
    let rep_bytes = encode_reputation(&rep).ok_or(RepError::BadAuthor)?;
    crate::memory_store::atomic_write(rep_p, &rep_bytes).map_err(|_| RepError::Truncated)?;
    for (passed, subject, evidence) in audit_ops {
        crate::ledger::record_audit(ledger_p, subject, evidence, passed, auditor)
            .map_err(|_| RepError::Truncated)?;
    }
    Ok(report)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::content_store::{LocalCasStore, PutClass};
    use crate::proof_cache::{IngestResultSummary, verify_ts};

    fn seq(from: u8) -> [u8; 32] {
        let mut c = [0u8; 32];
        for (i, b) in c.iter_mut().enumerate() {
            *b = u8::try_from(i).expect("small") + from;
        }
        c
    }

    /// Cross-language lock (Python 2026-07-08): selection threshold + reputation
    /// codec + standing formula match the Python vectors.
    #[test]
    fn selection_and_reputation_match_python_golden() {
        assert_eq!(selection_threshold(10000), 65536);
        assert_eq!(selection_threshold(2500), 16384);
        assert_eq!(selection_threshold(0), 0);
        let key = seq(0);
        assert!(is_selected(b"audit-1", &key, 2500));
        assert!(!is_selected(b"audit-2", &key, 2500));
        // reputation codec golden (57 bytes, sha d62612…)
        let mut rep = ReputationLedger::default();
        rep.entries.insert(
            "owner".to_string(),
            RepCounters {
                passed: 3,
                mismatched: 0,
            },
        );
        rep.entries.insert(
            "mallory".to_string(),
            RepCounters {
                passed: 1,
                mismatched: 2,
            },
        );
        let bytes = encode_reputation(&rep).expect("encodes");
        assert_eq!(bytes.len(), 57);
        // canonical = BTreeMap order (mallory < owner); Python-verified 2026-07-08.
        assert_eq!(
            crate::hex32(&crate::sha256_32(&bytes)),
            "de3441a7888d8c4e8cb3dbe4bd71bad25cc34978fc6266ebdb68bfd77f91a4b4"
        );
        assert_eq!(decode_reputation(&bytes).expect("decodes"), rep);
        // standing formula
        assert_eq!(RepCounters::default().standing_bps(), None);
        assert_eq!(
            RepCounters {
                passed: 10,
                mismatched: 0
            }
            .standing_bps(),
            Some(10000)
        );
        assert_eq!(
            RepCounters {
                passed: 99,
                mismatched: 1
            }
            .standing_bps(),
            Some(4974)
        );
        assert!(
            RepCounters {
                passed: 99,
                mismatched: 1
            }
            .is_slashed()
        );
    }

    /// -1 — selection is a bounded, seed-late-bound fraction (empirical
    /// rate near the target over a synthetic key space).
    #[test]
    fn selection_rate_is_approximately_the_target() {
        let mut n = 0u32;
        for i in 0..10000u32 {
            let key = crate::sha256_32(&i.to_le_bytes());
            if is_selected(b"s", &key, 2500) {
                n += 1;
            }
        }
        assert!((2200..2800).contains(&n), "empirical rate {n} off target");
    }

    /// RPUX decodes fail-closed.
    #[test]
    fn reputation_fails_closed() {
        let mut rep = ReputationLedger::default();
        rep.entries.insert(
            "a".to_string(),
            RepCounters {
                passed: 1,
                mismatched: 0,
            },
        );
        let bytes = encode_reputation(&rep).expect("encodes");
        assert_eq!(decode_reputation(&bytes[..3]), Err(RepError::Truncated));
        let mut bad = bytes.clone();
        bad[0] = b'X';
        assert_eq!(decode_reputation(&bad), Err(RepError::BadMagic));
        let mut trailing = bytes.clone();
        trailing.push(0);
        assert_eq!(decode_reputation(&trailing), Err(RepError::TrailingBytes));
    }

    fn sinks(
        tag: &str,
    ) -> (
        std::path::PathBuf,
        std::path::PathBuf,
        std::path::PathBuf,
        LocalCasStore,
    ) {
        let root = std::env::temp_dir().join(format!("sinabro_pf3_{tag}_{}", std::process::id()));
        std::fs::create_dir_all(root.join("proofs")).expect("mkdir");
        std::fs::create_dir_all(root.join("cas")).expect("mkdir");
        (
            root.join("proofs"),
            root.join("ledger.lgx"),
            root.join("reputation.rpx"),
            LocalCasStore::with_dir(root.join("cas")),
        )
    }

    /// ★ The PF-3 heart: a clean receipt PASSES re-audit (reputation +1); then a
    /// POISONED receipt (result claim swapped in place) is DETECTED as a mismatch,
    /// SLASHES the author, and lands an `Audit{passed=false}` op on the chain.
    #[test]
    fn poisoned_receipt_is_caught_and_slashed() {
        let (cache, lp, rp, mut store) = sinks("catch");
        let src = "export function add(a: number, b: number) { return a + b; }\n";
        // seed the cache honestly (closure persisted).
        let out = verify_ts(&cache, &lp, &mut store, src, "owner").expect("seed");
        let crate::proof_cache::VerifyOutcome::Computed { receipt, .. } = out else {
            panic!("seed must compute");
        };
        // audit rate=100% ⇒ selected; a clean receipt PASSES.
        let r1 = run_audit(&cache, &lp, &rp, &store, b"seed-1", 10000, "auditor").expect("audit");
        assert_eq!(r1.selected, 1);
        assert_eq!(r1.passed, 1);
        assert_eq!(r1.mismatched, 0);
        let rep = load_reputation(&rp).expect("rep");
        assert_eq!(rep.entries.get("owner").expect("owner").passed, 1);
        assert!(!rep.entries.get("owner").expect("owner").is_slashed());
        // POISON: rewrite the receipt with a FALSE result (claims 99 nodes) but
        // keep its key/input_cid, then re-file under the same key.
        let poisoned = ProofReceipt {
            key: receipt.key,
            kind: receipt.kind,
            input_cid: receipt.input_cid,
            result: IngestResultSummary {
                denied: false,
                skipped: 0,
                nodes: vec![seq(7); 99],
            },
            author: "mallory".to_string(),
        };
        let pbytes = crate::proof_cache::encode_receipt(&poisoned).expect("encode");
        // it must still be filed under the REAL key (a poisoner keeps the key so
        // the lookup path serves it) — write it there.
        std::fs::write(
            crate::proof_cache::receipt_path(&cache, &receipt.key),
            &pbytes,
        )
        .expect("poison");
        // audit again ⇒ the re-run from the REAL closure DIVERGES ⇒ MISMATCH.
        let r2 = run_audit(&cache, &lp, &rp, &store, b"seed-2", 10000, "auditor").expect("audit");
        assert_eq!(r2.mismatched, 1, "poison detected");
        assert_eq!(r2.passed, 0);
        let rep2 = load_reputation(&rp).expect("rep");
        let mal = rep2.entries.get("mallory").expect("mallory");
        assert_eq!(mal.mismatched, 1);
        assert!(mal.is_slashed(), "one mismatch ⇒ SLASHED");
        assert_eq!(mal.standing_bps(), Some(0), "0 passes / 1 mismatch");
        // the chain carries an Audit{passed=false} op.
        let chain = crate::ledger::load_ledger(&lp).expect("chain GREEN");
        assert!(
            chain
                .ops
                .iter()
                .any(|op| matches!(op, crate::ledger::LedgerOp::Audit { passed: false, .. }))
        );
        let _ = std::fs::remove_dir_all(cache.parent().expect("parent"));
    }

    /// -4 — a receipt whose closure is ABSENT is UNAUDITABLE, never passed.
    #[test]
    fn absent_closure_is_unauditable_not_a_pass() {
        let (cache, lp, rp, store) = sinks("noclosure");
        // hand-file a receipt whose input_cid closure was never stored.
        let receipt = ProofReceipt {
            key: proof_key(ProcedureKind::DefnIngestTsV1, &seq(5)),
            kind: ProcedureKind::DefnIngestTsV1,
            input_cid: seq(5),
            result: IngestResultSummary {
                denied: false,
                skipped: 0,
                nodes: vec![],
            },
            author: "ghost".to_string(),
        };
        let bytes = crate::proof_cache::encode_receipt(&receipt).expect("encode");
        std::fs::write(
            crate::proof_cache::receipt_path(&cache, &receipt.key),
            &bytes,
        )
        .expect("write");
        let r = run_audit(&cache, &lp, &rp, &store, b"s", 10000, "auditor").expect("audit");
        assert_eq!(r.selected, 1);
        assert_eq!(r.unauditable, 1);
        assert_eq!(r.passed, 0);
        assert_eq!(r.mismatched, 0);
        // no slash, no pass — the author's counters stay at zero.
        assert!(
            !load_reputation(&rp)
                .expect("rep")
                .entries
                .contains_key("ghost")
        );
        let _ = std::fs::remove_dir_all(cache.parent().expect("parent"));
    }

    /// A swapped CLOSURE (bytes that no longer hash to input_cid) is a mismatch.
    #[test]
    fn swapped_closure_is_a_mismatch() {
        let (_c, _l, _r, mut store) = sinks("swap");
        let receipt = ProofReceipt {
            key: proof_key(ProcedureKind::DefnIngestTsV1, &seq(3)),
            kind: ProcedureKind::DefnIngestTsV1,
            input_cid: seq(3),
            result: IngestResultSummary {
                denied: false,
                skipped: 0,
                nodes: vec![],
            },
            author: "x".to_string(),
        };
        // store DIFFERENT bytes under hex(input_cid) is impossible via put (cid is
        // content-derived) — simulate a poisoned store by writing the file directly.
        let cas = _c.parent().expect("root").join("cas");
        std::fs::write(cas.join(crate::hex32(&seq(3))), b"not the real source").expect("poison");
        let _ = store.put(b"x", PutClass::Public); // touch (unused)
        assert_eq!(reverify_receipt(&store, &receipt), AuditVerdict::Mismatch);
        let _ = std::fs::remove_dir_all(_c.parent().expect("parent"));
    }
}
