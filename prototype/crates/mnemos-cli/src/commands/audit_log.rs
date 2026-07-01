//! Persisted, hash-linked audit trail (ENDGAME E5-1).
//!
//! The in-memory [`crate::commands::audit::AuditTrail`] proves the *taxonomy* of
//! a high-significance action; THIS module makes the trail a REAL tamper-evident
//! record on disk. Every appended [`AuditEntry`] becomes one content-addressed
//! file under `~/.mnemos/audit/` whose name IS its `link_hash`, and whose body is
//! `prev_link_hash(32) ‖ seal_bytes(105)` = a fixed **137-byte** record. The chain
//! links genesis→tail by `prev_link_hash`, so removing, reordering, inserting, or
//! editing any record breaks the re-walk (a SHA-256 preimage would be required to
//! forge it).
//!
//! Why per-record content-addressed files (not one append-log): it reuses the
//! EXACT proven OTel-span discipline (`data_dir` + `atomic_write` + a
//! `<hash>.<ext>` name) — concurrent writers write DISTINCT files and an identical
//! record is idempotent (the name IS its hash), so the store is race-tolerant
//! under the parallel test harness where a single mutable append-log would corrupt
//! the chain via read-modify-rewrite. The hash-link essence (fixed binary record,
//! `prev`-pointer chain, rewalk-to-verify, append-only) is preserved.
//!
//! Reuse (no reinvention): the record body is the canonical
//! [`AuditEntry::seal_bytes_105`]; the directory is the P1-1 [`data_dir`]; the
//! write is the single [`atomic_write`] discipline; the verdict is the shared
//! [`RenderTruth`]. This module performs no network / chain / wallet I/O.

use std::path::{Path, PathBuf};

use crate::commands::audit::AuditEntry;
use crate::memory_store::atomic_write;
use crate::tui::RenderTruth;
use crate::{hex32, sha256_32};

/// Fixed sub-directory of the data dir holding the audit chain (one fixed
/// component, no variable part — the OTel-dir discipline). Only the production
/// `audit_dir` references it (the test build uses a temp dir).
#[cfg(not(test))]
const AUDIT_DIR_NAME: &str = "audit";

/// Content-addressed file suffix for one chained audit record.
const AUDIT_FILE_SUFFIX: &str = ".audit";

/// Domain separator for the chain link hash (so an audit link can never collide
/// with any other SHA-256 use in the binary).
const LINK_DOMAIN: &[u8] = b"sinabro.audit.link.v1";

/// The genesis predecessor link (the first record's `prev_link_hash`).
pub const GENESIS_LINK: [u8; 32] = [0u8; 32];

/// On-disk record width: `prev_link_hash(32) ‖ seal_bytes(105)`.
const RECORD_LEN: usize = 32 + 105;

/// Defensive cap on records read from a directory (DoS guard; a genuine
/// high-significance audit volume is far below this).
const MAX_RECORDS_READ: usize = 100_000;

/// Why a persisted audit-log operation was refused (typed, fail-closed).
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum AuditLogError {
    /// `$HOME` could not be resolved (no data dir).
    #[error("HOME unresolved; no audit dir")]
    NoHome,
    /// Creating the directory or writing/reading a record failed.
    #[error("audit log io failure")]
    Io,
}

/// The hash-link over `(prev_link_hash ‖ seal_bytes)` under the audit domain. The
/// genesis predecessor is [`GENESIS_LINK`]. Deterministic + injective over the
/// record content; an all-zero link would need a 256-bit SHA-256 preimage.
#[must_use]
pub fn link_hash(prev_link_hash_32: &[u8; 32], seal_bytes_105: &[u8; 105]) -> [u8; 32] {
    let mut buf: Vec<u8> = Vec::with_capacity(LINK_DOMAIN.len() + RECORD_LEN);
    buf.extend_from_slice(LINK_DOMAIN);
    buf.extend_from_slice(prev_link_hash_32);
    buf.extend_from_slice(seal_bytes_105);
    sha256_32(&buf)
}

/// One parsed chained record: the predecessor link, the sealed entry, and this
/// record's own link hash (= its content-addressed file name).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ChainedAuditRecord {
    /// The predecessor link this record chains onto (genesis = [`GENESIS_LINK`]).
    pub prev_link_hash_32: [u8; 32],
    /// The sealed audit entry.
    pub entry: AuditEntry,
    /// This record's link hash (its file name, hex-encoded).
    pub link_hash_32: [u8; 32],
}

impl ChainedAuditRecord {
    /// Encode the 137-byte on-disk record body (`prev ‖ seal_bytes`).
    #[must_use]
    pub fn encode(&self) -> [u8; RECORD_LEN] {
        let mut out = [0u8; RECORD_LEN];
        out[..32].copy_from_slice(&self.prev_link_hash_32);
        out[32..].copy_from_slice(&self.entry.seal_bytes_105());
        out
    }
}

/// The genesis→tail chain projection plus a no-false-green verdict.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuditChainView {
    /// Entries in genesis→tail order (only the records reachable on the linear
    /// chain from genesis).
    pub ordered: Vec<AuditEntry>,
    /// Total well-formed records found on disk (a divergence from `ordered.len()`
    /// signals a fork / orphan / gap — chain tamper).
    pub total_records: usize,
    /// Count of records whose recomputed link hash ≠ their file name (byte tamper).
    pub misnamed_records: usize,
    /// The chain verdict.
    pub truth: RenderTruth,
    /// A stable ASCII anomaly label when the chain is not clean (else empty).
    pub anomaly: &'static str,
}

impl AuditChainView {
    /// The tail link hash (the link an append must chain onto). Genesis when the
    /// clean chain is empty.
    #[must_use]
    pub fn tail_link(&self) -> [u8; 32] {
        // Re-derive from the ordered entries by re-walking the link function:
        // the tail link is the link of the last ordered entry, or genesis.
        let mut prev = GENESIS_LINK;
        for entry in &self.ordered {
            prev = link_hash(&prev, &entry.seal_bytes_105());
        }
        prev
    }

    /// A bounded, colorless, ASCII one-line summary for any terminal.
    #[must_use]
    pub fn render_plain(&self) -> String {
        format!(
            "audit_chain entries={} records={} misnamed={} truth={} anomaly={}",
            self.ordered.len(),
            self.total_records,
            self.misnamed_records,
            crate::commands::audit::render_truth_label(self.truth),
            if self.anomaly.is_empty() {
                "none"
            } else {
                self.anomaly
            },
        )
    }
}

/// The audit-chain directory. In a `cfg(test)` build it is a per-process throwaway
/// dir under the OS temp root (so the parallel test harness never writes to a
/// developer's real `~/.mnemos`; content-addressing keeps even that dir safe);
/// in production it is the fixed `~/.mnemos/audit`.
fn audit_dir() -> Result<PathBuf, AuditLogError> {
    #[cfg(test)]
    {
        Ok(std::env::temp_dir().join(format!("sinabro_audit_test_{}", std::process::id())))
    }
    #[cfg(not(test))]
    {
        crate::memory_store::data_dir()
            .map(|d| d.join(AUDIT_DIR_NAME))
            .map_err(|_| AuditLogError::NoHome)
    }
}

/// The persisted, hash-linked, append-only audit chain over a directory of
/// content-addressed 137-byte records.
#[derive(Clone, Debug)]
pub struct ChainedAuditLog {
    dir: PathBuf,
}

impl ChainedAuditLog {
    /// Open the production chain (`~/.mnemos/audit`, created on first append).
    pub fn open_local() -> Result<Self, AuditLogError> {
        Ok(Self { dir: audit_dir()? })
    }

    /// Open a chain rooted at an explicit directory (hermetic tests).
    #[must_use]
    pub fn open_at(dir: PathBuf) -> Self {
        Self { dir }
    }

    /// The chain directory.
    #[must_use]
    pub fn dir(&self) -> &Path {
        &self.dir
    }

    /// Append a sealed entry to the tail of the chain and return its link hash.
    /// Reads the current chain to find the tail, computes the new link, and writes
    /// ONE content-addressed record via the single [`atomic_write`] discipline.
    /// Idempotent: re-appending the identical entry onto the identical tail maps to
    /// the identical file (the name IS its hash).
    pub fn append(&self, entry: &AuditEntry) -> Result<[u8; 32], AuditLogError> {
        let view = self.load_chain()?;
        let prev = view.tail_link();
        self.write_record(&prev, entry)
    }

    /// Write ONE content-addressed record chaining `entry` onto `prev` and return
    /// its link hash. Content-addressed + idempotent: an identical `(prev, entry)`
    /// maps to the identical file, and an existing file short-circuits without a
    /// rewrite (the name IS its hash — safe under a concurrent / crash retry).
    fn write_record(&self, prev: &[u8; 32], entry: &AuditEntry) -> Result<[u8; 32], AuditLogError> {
        let seal = entry.seal_bytes_105();
        let link = link_hash(prev, &seal);
        std::fs::create_dir_all(&self.dir).map_err(|_| AuditLogError::Io)?;
        let name = format!("{}{}", hex32(&link), AUDIT_FILE_SUFFIX);
        let path = self.dir.join(&name);
        if path.exists() {
            return Ok(link);
        }
        let record = ChainedAuditRecord {
            prev_link_hash_32: *prev,
            entry: *entry,
            link_hash_32: link,
        };
        atomic_write(&path, &record.encode()).map_err(|_| AuditLogError::Io)?;
        Ok(link)
    }

    /// Test-only access to the content-addressed write (proves the idempotency
    /// short-circuit on an explicit predecessor without advancing the tail).
    #[cfg(test)]
    pub fn write_record_for_test(
        &self,
        prev: &[u8; 32],
        entry: &AuditEntry,
    ) -> Result<[u8; 32], AuditLogError> {
        self.write_record(prev, entry)
    }

    /// Read + parse every well-formed record file in the directory (no ordering).
    /// A file that is not exactly 137 bytes, or whose action byte is out of range,
    /// is skipped (not a valid chain record); a file whose recomputed link hash ≠
    /// its name is counted as `misnamed` (byte tamper) but still parsed so the
    /// re-walk can surface the break.
    fn read_records(&self) -> Result<(Vec<ChainedAuditRecord>, usize), AuditLogError> {
        let mut records = Vec::new();
        let mut misnamed = 0usize;
        let entries = match std::fs::read_dir(&self.dir) {
            Ok(rd) => rd,
            // A missing directory is an empty (never-measured) chain, not an error.
            Err(_) => return Ok((records, misnamed)),
        };
        for dirent in entries {
            // Defensive DoS bound: a real high-significance audit volume is tiny;
            // a pathological directory is capped rather than read unbounded.
            if records.len() >= MAX_RECORDS_READ {
                break;
            }
            let dirent = dirent.map_err(|_| AuditLogError::Io)?;
            let path = dirent.path();
            let Some(name) = path.file_name().and_then(|n| n.to_str()) else {
                continue;
            };
            let Some(stem) = name.strip_suffix(AUDIT_FILE_SUFFIX) else {
                continue;
            };
            let bytes = std::fs::read(&path).map_err(|_| AuditLogError::Io)?;
            let Ok(buf): Result<[u8; RECORD_LEN], _> = bytes.as_slice().try_into() else {
                continue;
            };
            let mut prev = [0u8; 32];
            prev.copy_from_slice(&buf[..32]);
            let mut seal = [0u8; 105];
            seal.copy_from_slice(&buf[32..]);
            let Some(entry) = AuditEntry::decode_seal_bytes(&seal) else {
                continue;
            };
            let link = link_hash(&prev, &seal);
            if hex32(&link) != stem {
                misnamed += 1;
            }
            records.push(ChainedAuditRecord {
                prev_link_hash_32: prev,
                entry,
                link_hash_32: link,
            });
        }
        Ok((records, misnamed))
    }

    /// Re-walk the chain from genesis and produce the no-false-green view. Empty ⇒
    /// `Unknown` (never measured); any byte tamper / fork / orphan / gap / a Red
    /// entry ⇒ `Red`; a clean linear all-traced chain ⇒ `Green`.
    pub fn load_chain(&self) -> Result<AuditChainView, AuditLogError> {
        let (records, misnamed) = self.read_records()?;
        let total_records = records.len();
        if total_records == 0 {
            return Ok(AuditChainView {
                ordered: Vec::new(),
                total_records: 0,
                misnamed_records: 0,
                truth: RenderTruth::Unknown,
                anomaly: "",
            });
        }
        // Index by predecessor link so the walk is O(n). A duplicate predecessor is
        // a FORK (two records chaining onto the same point) — chain tamper.
        let mut by_prev: std::collections::HashMap<[u8; 32], Vec<&ChainedAuditRecord>> =
            std::collections::HashMap::new();
        for r in &records {
            by_prev.entry(r.prev_link_hash_32).or_default().push(r);
        }
        let mut fork = false;
        for successors in by_prev.values() {
            if successors.len() > 1 {
                fork = true;
            }
        }
        let mut ordered: Vec<AuditEntry> = Vec::with_capacity(total_records);
        let mut cursor = GENESIS_LINK;
        // Walk genesis→tail following the unique successor at each step.
        while let Some(successors) = by_prev.get(&cursor) {
            let Some(next) = successors.first() else {
                break;
            };
            ordered.push(next.entry);
            cursor = next.link_hash_32;
            if ordered.len() > total_records {
                break; // defensive: a cycle is impossible by SHA-256 but never loop.
            }
        }
        let reachable = ordered.len();
        let any_red = ordered.iter().any(|e| e.render_truth() == RenderTruth::Red);
        let (truth, anomaly) = if misnamed > 0 {
            (RenderTruth::Red, "byte_tamper")
        } else if fork {
            (RenderTruth::Red, "fork")
        } else if reachable != total_records {
            // an orphan record (no path from genesis) or a gap broke the walk.
            (RenderTruth::Red, "orphan_or_gap")
        } else if any_red {
            (RenderTruth::Red, "untraced_entry")
        } else {
            (RenderTruth::Green, "")
        };
        Ok(AuditChainView {
            ordered,
            total_records,
            misnamed_records: misnamed,
            truth,
            anomaly,
        })
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use super::*;
    use crate::commands::audit::{AuditAction, AuditEntry};
    use crate::{StageFEvidenceRef, StageFTraceLink};

    fn unique_dir(tag: &str) -> PathBuf {
        use std::sync::atomic::{AtomicU32, Ordering};
        static COUNTER: AtomicU32 = AtomicU32::new(0);
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        let dir =
            std::env::temp_dir().join(format!("sinabro_auditlog_{}_{tag}_{n}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("temp dir");
        dir
    }

    fn entry(action: AuditAction, seed: &[u8], atom: u16, gate: u16) -> AuditEntry {
        let trace = StageFTraceLink::new(sha256_32(seed), atom, gate);
        let evidence = StageFEvidenceRef {
            path_hash_32: sha256_32(&[seed, b"/ev"].concat()),
            trace,
        };
        AuditEntry::seal(action, trace, evidence)
    }

    /// CROSS-LANGUAGE LOCK: the Rust link hashes for a known 2-record chain MUST
    /// equal the independent Python derivation (E5-1 byte-format lock). If either
    /// the record layout or the link domain/scheme drifts, these fail.
    #[test]
    fn link_hash_matches_python_reference() {
        // Record 0 (genesis): Kill, atom 469, gate 800; seeds "kill"/"ev/kill".
        let s0 = {
            let tr = StageFTraceLink::new(sha256_32(b"kill"), 469, 800);
            let ev = StageFEvidenceRef {
                path_hash_32: sha256_32(b"ev/kill"),
                trace: StageFTraceLink::new(sha256_32(b"kill"), 469, 800),
            };
            AuditEntry::seal(AuditAction::Kill, tr, ev).seal_bytes_105()
        };
        let l0 = link_hash(&GENESIS_LINK, &s0);
        assert_eq!(
            hex32(&l0),
            "4dd41a06f6cb16009b8840361b6ab028ef6ded66d6269e2d92a39cfa1ac1badf"
        );
        let s1 = {
            let tr = StageFTraceLink::new(sha256_32(b"restore"), 470, 801);
            let ev = StageFEvidenceRef {
                path_hash_32: sha256_32(b"ev/restore"),
                trace: StageFTraceLink::new(sha256_32(b"restore"), 470, 801),
            };
            AuditEntry::seal(AuditAction::Rollback, tr, ev).seal_bytes_105()
        };
        let l1 = link_hash(&l0, &s1);
        assert_eq!(
            hex32(&l1),
            "76f1a52c70bd3a33f32542daf65afe9668682a13f820b232af5788abd7498dc4"
        );
    }

    #[test]
    fn append_persists_and_reloads_in_order() {
        let log = ChainedAuditLog::open_at(unique_dir("order"));
        assert_eq!(log.load_chain().unwrap().truth, RenderTruth::Unknown);
        log.append(&entry(AuditAction::Approval, b"a", 1, 10))
            .unwrap();
        log.append(&entry(AuditAction::Denial, b"b", 2, 20))
            .unwrap();
        log.append(&entry(AuditAction::Kill, b"c", 3, 30)).unwrap();
        // A NEW handle over the SAME dir proves persistence across "restart".
        let reopened = ChainedAuditLog::open_at(log.dir().to_path_buf());
        let view = reopened.load_chain().unwrap();
        assert_eq!(view.total_records, 3);
        assert_eq!(view.ordered.len(), 3);
        assert_eq!(view.truth, RenderTruth::Green);
        assert_eq!(view.ordered[0].action, AuditAction::Approval);
        assert_eq!(view.ordered[1].action, AuditAction::Denial);
        assert_eq!(view.ordered[2].action, AuditAction::Kill);
    }

    #[test]
    fn same_entry_twice_extends_chain_but_record_write_is_idempotent() {
        let log = ChainedAuditLog::open_at(unique_dir("idem"));
        let e = entry(AuditAction::Signing, b"x", 7, 70);
        let l1 = log.append(&e).unwrap();
        // The genesis record's link is deterministic over its content.
        assert_eq!(l1, link_hash(&GENESIS_LINK, &e.seal_bytes_105()));
        let l2 = log.append(&e).unwrap();
        // The SAME high-significance action happening twice is TWO events: the
        // second legitimately chains onto the first (append-only event log).
        assert_ne!(l1, l2);
        assert_eq!(l2, link_hash(&l1, &e.seal_bytes_105()));
        assert_eq!(log.load_chain().unwrap().total_records, 2);
        // Content-addressed idempotency: re-writing the EXACT genesis record (same
        // prev+seal, e.g. a concurrent / crash retry) maps to the SAME file and
        // never duplicates it — the count stays 2.
        let again = log.write_record_for_test(&GENESIS_LINK, &e).unwrap();
        assert_eq!(again, l1);
        assert_eq!(log.load_chain().unwrap().total_records, 2);
    }

    #[test]
    fn byte_tamper_breaks_the_chain() {
        let dir = unique_dir("tamper");
        let log = ChainedAuditLog::open_at(dir.clone());
        log.append(&entry(AuditAction::Approval, b"a", 1, 10))
            .unwrap();
        log.append(&entry(AuditAction::Kill, b"b", 2, 20)).unwrap();
        assert_eq!(log.load_chain().unwrap().truth, RenderTruth::Green);
        // Flip a byte inside one record body WITHOUT renaming the file -> the
        // recomputed link no longer matches the file name (byte tamper).
        let victim = std::fs::read_dir(&dir)
            .unwrap()
            .filter_map(Result::ok)
            .map(|d| d.path())
            .find(|p| p.extension().is_some_and(|e| e == "audit"))
            .unwrap();
        let mut bytes = std::fs::read(&victim).unwrap();
        bytes[40] ^= 0x01;
        std::fs::write(&victim, &bytes).unwrap();
        let view = log.load_chain().unwrap();
        assert_eq!(view.truth, RenderTruth::Red);
        assert!(view.misnamed_records >= 1 || view.anomaly == "orphan_or_gap");
    }

    #[test]
    fn deleting_a_record_breaks_the_walk() {
        let dir = unique_dir("delete");
        let log = ChainedAuditLog::open_at(dir.clone());
        log.append(&entry(AuditAction::Approval, b"a", 1, 10))
            .unwrap();
        let mid = log
            .append(&entry(AuditAction::Denial, b"b", 2, 20))
            .unwrap();
        log.append(&entry(AuditAction::Kill, b"c", 3, 30)).unwrap();
        // Remove the middle record -> the tail becomes an orphan (gap in the walk).
        let mid_path = dir.join(format!("{}{}", hex32(&mid), AUDIT_FILE_SUFFIX));
        std::fs::remove_file(&mid_path).unwrap();
        let view = log.load_chain().unwrap();
        assert_eq!(view.truth, RenderTruth::Red);
        assert_eq!(view.anomaly, "orphan_or_gap");
    }

    #[test]
    fn empty_chain_is_unknown_not_green() {
        let log = ChainedAuditLog::open_at(unique_dir("empty"));
        let view = log.load_chain().unwrap();
        assert_eq!(view.truth, RenderTruth::Unknown);
        assert!(!view.truth.is_healthy());
        assert!(view.render_plain().contains("truth=UNKNOWN"));
    }
}
