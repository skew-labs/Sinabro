//! Rewind — a content-capturing revert-point HISTORY (the differentiator Codex
//! lacks: it shipped `/undo`, removed it, and has only git rollback against loud
//! user demand).
//!
//! The apply path ([`crate::file_edit::apply_proposal`]) already holds the
//! displaced bytes for one instant (`ApplyReceipt.old_text`) and then drops
//! them. This module CAPTURES those bytes into a sealed, bounded, recency-ordered
//! store, and restores them through the SAME [`owner_save_file`] discipline:
//! lane-A write confinement (IV-W4) + the IV-W3 staleness lock (refuses if the
//! file changed since the apply) + atomic mode-preserving replace + a
//! verify-after-write receipt.
//!
//! # v2 = multi-level history (was v1 single-slot)
//! Each apply appends a NEW revert point keyed by a strictly-increasing recency
//! `seq` (the next seq = the max existing + 1 — collision-free, no clock
//! dependency). [`revert_last`] pops the most-recent (the one-key undo);
//! [`revert_to`] undoes a SPECIFIC point; [`revert_list`] enumerates them
//! (metadata only). The history is bounded ([`REVERT_HISTORY_CAP`], like
//! `MAX_PENDING_PROPOSALS`) — the oldest point is evicted past the cap. Sequential
//! `revert_last` calls form a recency LIFO undo stack; the staleness lock keeps
//! every step honest (a point whose target moved since the apply is refused, never
//! clobbered).
//!
//! # drift-0 / custody
//! Rewind touches ONLY a local file (through the confined, staleness-locked,
//! atomic owner-save path) — never funds/wallet/mainnet/chain. [`owner_save_file`]
//! is "NEVER chain-write" (PD-6; `CustodyCapability` stays uninhabited). The
//! captured bytes already passed the lane-A read walls at apply time, and the
//! E5 audit chain stays append-only (a rewind logs a NEW `Rollback` entry, it
//! never rewrites history).
//!
//! # store discipline (reused verbatim from the proposal store, IV-W6)
//! AEAD-sealed with the P1-1 [`MemoryCipher`], a DISTINCT magic/extension/subdir
//! so a revert blob can never masquerade as a proposal or a memory record. The
//! AEAD associated data is the header ‖ the recency `seq` — so a revert file
//! renamed to a DIFFERENT seq fails the tag (a key-less attacker cannot reorder
//! the undo history), and a cross-store renamed file fails too.

use std::path::PathBuf;

use crate::file_context::{FileReadPolicy, MAX_FILE_BYTES};
use crate::file_edit::{OwnerSaveDeny, owner_save_file};
use crate::hex32;
use crate::memory_store::{CipherError, MemoryCipher, atomic_write, data_dir};

/// Revert record magic (4 bytes) — `MNRV` = MNemos ReVert.
pub const REVERT_MAGIC: [u8; 4] = *b"MNRV";
/// Revert record version (the on-disk header byte; AAD-bound).
pub const REVERT_RECORD_VERSION: u8 = 1;
/// Sealed-plaintext wire version (the first byte INSIDE the seal).
pub const REVERT_WIRE_VERSION: u8 = 1;
/// Fixed record header width: magic(4) + version(1).
pub const REVERT_HEADER_BYTES: usize = 5;
/// Revert subdirectory under the data dir (`$HOME/.mnemos`).
pub const REVERT_SUBDIR: &str = "reverts";
/// Revert-point filename suffix. A point is `{seq:020}.rev` — the 20-digit
/// zero-pad makes lexical order == numeric (recency) order.
pub const REVERT_SLOT_SUFFIX: &str = ".rev";
/// Bounded revert history depth (recency-ordered; the oldest is evicted past it).
/// Mirrors `MAX_PENDING_PROPOSALS` — a small, fixed, fail-closed ceiling.
pub const REVERT_HISTORY_CAP: usize = 16;
/// Minimum wire length: version(1) + applied_sha(32) + path_len(2) + old_len(4).
const REVERT_WIRE_MIN: usize = 1 + 32 + 2 + 4;

/// One captured revert point: the bytes to restore + the hash the apply LEFT
/// (the staleness baseline the restore must still observe).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RevertBlob {
    /// The CANONICAL target path the apply wrote (== `ApplyReceipt.target_path`).
    pub target_path: PathBuf,
    /// The hash the apply LEFT on disk (== `ApplyReceipt.new_sha_32`). The
    /// restore refuses unless the target STILL hashes to this (IV-W3) — so a
    /// rewind never clobbers an edit the owner made after the apply.
    pub applied_sha_32: [u8; 32],
    /// The displaced content to write back (== `ApplyReceipt.old_text` bytes).
    pub old_bytes: Vec<u8>,
}

impl RevertBlob {
    /// Canonical sealed-plaintext wire: `version | applied_sha(32) | path_len(u16 LE)
    /// | path_utf8 | old_len(u32 LE) | old_bytes`. `None` if a field exceeds its
    /// width (non-UTF-8 path / >64 KiB path / >4 GiB content).
    #[must_use]
    pub fn to_wire(&self) -> Option<Vec<u8>> {
        let path = self.target_path.to_str()?;
        let path_bytes = path.as_bytes();
        let path_len = u16::try_from(path_bytes.len()).ok()?;
        let old_len = u32::try_from(self.old_bytes.len()).ok()?;
        let mut w = Vec::with_capacity(REVERT_WIRE_MIN + path_bytes.len() + self.old_bytes.len());
        w.push(REVERT_WIRE_VERSION);
        w.extend_from_slice(&self.applied_sha_32);
        w.extend_from_slice(&path_len.to_le_bytes());
        w.extend_from_slice(path_bytes);
        w.extend_from_slice(&old_len.to_le_bytes());
        w.extend_from_slice(&self.old_bytes);
        Some(w)
    }

    /// Fail-closed decode (exact length — no trailing slop, no partial trust).
    #[must_use]
    pub fn from_wire(b: &[u8]) -> Option<Self> {
        if b.len() < REVERT_WIRE_MIN || b[0] != REVERT_WIRE_VERSION {
            return None;
        }
        let mut o = 1usize;
        let mut applied_sha_32 = [0u8; 32];
        applied_sha_32.copy_from_slice(&b[o..o + 32]);
        o += 32;
        let path_len = u16::from_le_bytes([b[o], b[o + 1]]) as usize;
        o += 2;
        if b.len() < o + path_len + 4 {
            return None;
        }
        let path = std::str::from_utf8(&b[o..o + path_len]).ok()?;
        o += path_len;
        let old_len = u32::from_le_bytes([b[o], b[o + 1], b[o + 2], b[o + 3]]) as usize;
        o += 4;
        if b.len() != o + old_len {
            return None; // exact length — fail-closed
        }
        Some(Self {
            target_path: PathBuf::from(path),
            applied_sha_32,
            old_bytes: b[o..o + old_len].to_vec(),
        })
    }
}

/// Typed rewind denials (namespaced `revert.*`).
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RevertDeny {
    /// Key / IO / seal trouble opening or writing the revert store.
    StoreFailed,
    /// No revert point captured (or it was unreadable / tampered).
    NoRevertPoint,
    /// The target changed since the apply (the owner-save IV-W3 staleness lock) —
    /// a rewind refuses rather than clobber a newer owner edit.
    Stale,
    /// The owner-save write-back failed for another typed reason (its class label).
    WriteBack(String),
}

impl RevertDeny {
    /// Stable, allow-listed class label (namespaced `revert.*`).
    #[must_use]
    pub fn class_label(&self) -> String {
        match self {
            Self::StoreFailed => "revert.store_failed".to_string(),
            Self::NoRevertPoint => "revert.no_point".to_string(),
            Self::Stale => "revert.stale_target".to_string(),
            Self::WriteBack(c) => format!("revert.write_back:{c}"),
        }
    }
}

/// A successful rewind receipt (metadata only — the restored bytes are never echoed).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RevertReceipt {
    /// The canonical target that was restored.
    pub target_path: PathBuf,
    /// The hash the file had BEFORE the rewind (== the apply's `new_sha`).
    pub from_sha_32: [u8; 32],
    /// The restored content's hash (verified by re-read).
    pub restored_sha_32: [u8; 32],
    /// Bytes written back.
    pub bytes_written_u64: u64,
}

/// One revert-history entry's metadata (NO content — the bytes are never listed).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RevertEntry {
    /// The recency id (higher = more recent); the handle for [`revert_to`].
    pub seq: u64,
    /// The canonical target this point would restore.
    pub target_path: PathBuf,
    /// The hash the apply LEFT (the staleness baseline this restore observes).
    pub applied_sha_32: [u8; 32],
    /// The size of the content this point would write back.
    pub old_bytes_len: u64,
}

/// The sealed, bounded, recency-ordered revert store (`$HOME/.mnemos/reverts/`).
/// Each point is one `{seq:020}.rev` file; the seq is AAD-bound.
#[derive(Clone, Debug)]
pub struct RevertStore {
    cipher: MemoryCipher,
    store_dir: PathBuf,
}

impl RevertStore {
    /// Open the local store, creating the dir. Fail-closed on key/io trouble.
    pub fn open_local() -> Result<Self, RevertDeny> {
        let cipher = MemoryCipher::open_local().map_err(|_| RevertDeny::StoreFailed)?;
        let store_dir = data_dir()
            .map_err(|_| RevertDeny::StoreFailed)?
            .join(REVERT_SUBDIR);
        std::fs::create_dir_all(&store_dir).map_err(|_| RevertDeny::StoreFailed)?;
        Ok(Self { cipher, store_dir })
    }

    /// Construct over an explicit cipher + dir (tests / non-default roots).
    #[must_use]
    pub fn with_dir(cipher: MemoryCipher, store_dir: PathBuf) -> Self {
        Self { cipher, store_dir }
    }

    /// The on-disk record header (magic ‖ version) — validated on read.
    const fn record_header() -> [u8; REVERT_HEADER_BYTES] {
        [
            REVERT_MAGIC[0],
            REVERT_MAGIC[1],
            REVERT_MAGIC[2],
            REVERT_MAGIC[3],
            REVERT_RECORD_VERSION,
        ]
    }

    /// AEAD associated data = the record header ‖ the recency seq (u64 LE). Binding
    /// the seq cryptographically means a revert file renamed to a different seq
    /// fails the tag (a key-less attacker cannot reorder the undo history).
    fn record_aad(seq: u64) -> [u8; REVERT_HEADER_BYTES + 8] {
        let mut aad = [0u8; REVERT_HEADER_BYTES + 8];
        aad[..REVERT_HEADER_BYTES].copy_from_slice(&Self::record_header());
        aad[REVERT_HEADER_BYTES..].copy_from_slice(&seq.to_le_bytes());
        aad
    }

    fn slot_name(seq: u64) -> String {
        format!("{seq:020}{REVERT_SLOT_SUFFIX}")
    }

    fn slot_path(&self, seq: u64) -> PathBuf {
        self.store_dir.join(Self::slot_name(seq))
    }

    /// Parse a recency seq from a `{seq:020}.rev` filename. `None` for anything
    /// else (so a stray / cross-store file — e.g. a legacy `last.rev` — is ignored).
    fn parse_seq(name: &str) -> Option<u64> {
        let stem = name.strip_suffix(REVERT_SLOT_SUFFIX)?;
        if stem.is_empty() || !stem.bytes().all(|b| b.is_ascii_digit()) {
            return None;
        }
        stem.parse::<u64>().ok()
    }

    /// All present revert seqs, sorted DESCENDING (most-recent first). Bounded by
    /// what is on disk (the cap keeps it ≤ [`REVERT_HISTORY_CAP`] + races).
    fn seqs_desc(&self) -> Vec<u64> {
        let mut seqs: Vec<u64> = match std::fs::read_dir(&self.store_dir) {
            Ok(rd) => rd
                .filter_map(Result::ok)
                .filter_map(|e| e.file_name().to_str().and_then(Self::parse_seq))
                .collect(),
            Err(_) => Vec::new(),
        };
        seqs.sort_unstable_by(|a, b| b.cmp(a));
        seqs
    }

    fn record_bytes(&self, blob: &RevertBlob, seq: u64) -> Result<Vec<u8>, RevertDeny> {
        let wire = blob.to_wire().ok_or(RevertDeny::StoreFailed)?;
        let header = Self::record_header();
        let sealed = self
            .cipher
            .seal_with_aad(&wire, &Self::record_aad(seq))
            .map_err(|_: CipherError| RevertDeny::StoreFailed)?;
        let mut record = Vec::with_capacity(REVERT_HEADER_BYTES + sealed.len());
        record.extend_from_slice(&header);
        record.extend_from_slice(&sealed);
        Ok(record)
    }

    /// APPEND a revert point at a fresh recency seq (= max existing + 1), then evict
    /// the oldest past the cap. Returns the new seq. Bounded by `MAX_FILE_BYTES`.
    pub fn capture(&self, blob: &RevertBlob) -> Result<u64, RevertDeny> {
        if blob.old_bytes.len() as u64 > MAX_FILE_BYTES {
            return Err(RevertDeny::StoreFailed);
        }
        std::fs::create_dir_all(&self.store_dir).map_err(|_| RevertDeny::StoreFailed)?;
        let next = self.seqs_desc().first().map_or(0, |&m| m.saturating_add(1));
        let record = self.record_bytes(blob, next)?;
        atomic_write(&self.slot_path(next), &record).map_err(|_| RevertDeny::StoreFailed)?;
        self.evict_beyond_cap();
        Ok(next)
    }

    /// Drop the oldest points until at most [`REVERT_HISTORY_CAP`] remain.
    fn evict_beyond_cap(&self) {
        let mut seqs = self.seqs_desc(); // recency desc
        while seqs.len() > REVERT_HISTORY_CAP {
            if let Some(oldest) = seqs.pop() {
                let _ = std::fs::remove_file(self.slot_path(oldest));
            } else {
                break;
            }
        }
    }

    /// Read + verify ONE revert point (header → AEAD tag w/ header‖seq AAD →
    /// fail-closed wire decode), or `None` (missing / unreadable / tampered /
    /// wrong key / seq-rebound).
    #[must_use]
    pub fn peek_seq(&self, seq: u64) -> Option<RevertBlob> {
        let bytes = std::fs::read(self.slot_path(seq)).ok()?;
        if bytes.len() < REVERT_HEADER_BYTES
            || bytes[..4] != REVERT_MAGIC
            || bytes[4] != REVERT_RECORD_VERSION
        {
            return None;
        }
        let wire = self
            .cipher
            .open_with_aad(&bytes[REVERT_HEADER_BYTES..], &Self::record_aad(seq))
            .ok()?;
        RevertBlob::from_wire(&wire)
    }

    /// The most-recent revert seq, if any.
    #[must_use]
    pub fn latest_seq(&self) -> Option<u64> {
        self.seqs_desc().first().copied()
    }

    /// Whether any revert point is present.
    #[must_use]
    pub fn has_point(&self) -> bool {
        !self.seqs_desc().is_empty()
    }

    /// The revert history as metadata (most-recent first; unreadable points
    /// skipped; capped). NEVER returns content.
    #[must_use]
    pub fn list(&self) -> Vec<RevertEntry> {
        self.seqs_desc()
            .into_iter()
            .take(REVERT_HISTORY_CAP)
            .filter_map(|seq| {
                self.peek_seq(seq).map(|b| RevertEntry {
                    seq,
                    target_path: b.target_path,
                    applied_sha_32: b.applied_sha_32,
                    old_bytes_len: b.old_bytes.len() as u64,
                })
            })
            .collect()
    }

    /// Consume one revert point (after a successful rewind).
    pub fn remove_seq(&self, seq: u64) -> std::io::Result<()> {
        std::fs::remove_file(self.slot_path(seq))
    }
}

/// Restore ONE revert point (`seq`) through the staleness-locked, confined, atomic
/// [`owner_save_file`] path. The point is consumed ONLY on a successful write-back
/// (a refused rewind — e.g. the target moved since the apply — keeps it, IV-W3).
/// NEVER touches funds/wallet/chain (owner-save is local-file-only, PD-6).
fn restore_seq(
    policy: &FileReadPolicy,
    store: &RevertStore,
    seq: u64,
) -> Result<RevertReceipt, RevertDeny> {
    let blob = store.peek_seq(seq).ok_or(RevertDeny::NoRevertPoint)?;
    let base_hex = hex32(&blob.applied_sha_32);
    match owner_save_file(policy, &blob.target_path, &blob.old_bytes, &base_hex) {
        Ok(receipt) => {
            let _ = store.remove_seq(seq);
            Ok(RevertReceipt {
                target_path: receipt.target_path,
                from_sha_32: blob.applied_sha_32,
                restored_sha_32: receipt.new_sha_32,
                bytes_written_u64: receipt.bytes_written_u64,
            })
        }
        Err(OwnerSaveDeny::Stale) => Err(RevertDeny::Stale),
        Err(deny) => Err(RevertDeny::WriteBack(deny.class_label().to_string())),
    }
}

/// Rewind the LAST applied edit (pop the most-recent revert point — the one-key undo).
pub fn revert_last(
    policy: &FileReadPolicy,
    store: &RevertStore,
) -> Result<RevertReceipt, RevertDeny> {
    let seq = store.latest_seq().ok_or(RevertDeny::NoRevertPoint)?;
    restore_seq(policy, store, seq)
}

/// Rewind a SPECIFIC revert point by its recency id (from [`revert_list`]).
pub fn revert_to(
    policy: &FileReadPolicy,
    store: &RevertStore,
    seq: u64,
) -> Result<RevertReceipt, RevertDeny> {
    restore_seq(policy, store, seq)
}

/// Enumerate the revert history (metadata only; most-recent first).
#[must_use]
pub fn revert_list(store: &RevertStore) -> Vec<RevertEntry> {
    store.list()
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use super::*;
    use crate::sha256_32;

    fn temp_dir(name: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("sinabro_revert_{name}"));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        std::fs::canonicalize(&d).unwrap()
    }

    fn store_in(dir: &Path) -> RevertStore {
        RevertStore::with_dir(MemoryCipher::from_key([7u8; 32]), dir.join("reverts"))
    }

    // Capture a point for a file whose on-disk content is `new`, displacing `old`.
    fn capture_edit(store: &RevertStore, path: &Path, old: &[u8], new: &[u8]) -> u64 {
        std::fs::write(path, new).unwrap();
        let canonical = std::fs::canonicalize(path).unwrap();
        store
            .capture(&RevertBlob {
                target_path: canonical,
                applied_sha_32: sha256_32(new),
                old_bytes: old.to_vec(),
            })
            .unwrap()
    }

    #[test]
    fn capture_then_revert_last_restores_old_bytes() {
        let dir = temp_dir("restore");
        let path = dir.join("t.rs");
        let old = b"fn old() {}\n".to_vec();
        let new = b"fn new() {}\n".to_vec();
        let policy = FileReadPolicy::new(std::slice::from_ref(&dir), MAX_FILE_BYTES);
        let store = store_in(&dir);
        capture_edit(&store, &path, &old, &new);
        assert!(store.has_point());
        let receipt = revert_last(&policy, &store).expect("reverts the last applied edit");
        assert_eq!(receipt.restored_sha_32, sha256_32(&old));
        assert_eq!(receipt.from_sha_32, sha256_32(&new));
        assert_eq!(
            std::fs::read(&path).unwrap(),
            old,
            "file restored to the old bytes"
        );
        assert!(!store.has_point(), "the revert point is consumed");
    }

    #[test]
    fn revert_refuses_when_target_changed_since_apply() {
        let dir = temp_dir("stale");
        let path = dir.join("t.rs");
        let new = b"fn new() {}\n".to_vec();
        let policy = FileReadPolicy::new(std::slice::from_ref(&dir), MAX_FILE_BYTES);
        let store = store_in(&dir);
        capture_edit(&store, &path, b"fn old() {}\n", &new);
        // The owner edited the file AFTER the apply ⇒ current hash != applied hash.
        std::fs::write(&path, b"fn user_edited_since() {}\n").unwrap();
        assert_eq!(revert_last(&policy, &store), Err(RevertDeny::Stale));
        assert_eq!(
            std::fs::read_to_string(&path).unwrap(),
            "fn user_edited_since() {}\n",
            "the owner's newer content is untouched"
        );
        assert!(store.has_point(), "a refused rewind keeps the revert point");
    }

    #[test]
    fn no_revert_point_is_typed_deny() {
        let dir = temp_dir("nopoint");
        let policy = FileReadPolicy::new(std::slice::from_ref(&dir), MAX_FILE_BYTES);
        let store = store_in(&dir);
        assert_eq!(revert_last(&policy, &store), Err(RevertDeny::NoRevertPoint));
        assert_eq!(
            revert_to(&policy, &store, 0),
            Err(RevertDeny::NoRevertPoint)
        );
        assert!(revert_list(&store).is_empty());
    }

    #[test]
    fn multi_level_pop_is_recency_lifo() {
        // Three edits to ONE file: a->b->c->d. Each capture displaces the prior body.
        let dir = temp_dir("multilevel");
        let path = dir.join("t.txt");
        let policy = FileReadPolicy::new(std::slice::from_ref(&dir), MAX_FILE_BYTES);
        let store = store_in(&dir);
        let s0 = capture_edit(&store, &path, b"a", b"b"); // body now "b", point restores "a"
        let s1 = capture_edit(&store, &path, b"b", b"c"); // body now "c", point restores "b"
        let s2 = capture_edit(&store, &path, b"c", b"d"); // body now "d", point restores "c"
        assert!(s0 < s1 && s1 < s2, "seq strictly increases with recency");
        assert_eq!(revert_list(&store).len(), 3);
        // Pop most-recent: d -> c -> b -> a (a proper undo stack).
        revert_last(&policy, &store).expect("undo d->c");
        assert_eq!(std::fs::read(&path).unwrap(), b"c");
        revert_last(&policy, &store).expect("undo c->b");
        assert_eq!(std::fs::read(&path).unwrap(), b"b");
        revert_last(&policy, &store).expect("undo b->a");
        assert_eq!(std::fs::read(&path).unwrap(), b"a");
        assert!(!store.has_point(), "history exhausted");
    }

    #[test]
    fn revert_to_specific_point() {
        // Two different files; revert_to undoes a SPECIFIC point, leaving the other.
        let dir = temp_dir("revertto");
        let fa = dir.join("a.txt");
        let fb = dir.join("b.txt");
        let policy = FileReadPolicy::new(std::slice::from_ref(&dir), MAX_FILE_BYTES);
        let store = store_in(&dir);
        let sa = capture_edit(&store, &fa, b"a-old", b"a-new");
        let sb = capture_edit(&store, &fb, b"b-old", b"b-new");
        // Undo the OLDER point (a) by id, while b stays applied.
        let r = revert_to(&policy, &store, sa).expect("undo a by id");
        assert_eq!(r.target_path, std::fs::canonicalize(&fa).unwrap());
        assert_eq!(std::fs::read(&fa).unwrap(), b"a-old", "a restored");
        assert_eq!(std::fs::read(&fb).unwrap(), b"b-new", "b untouched");
        let remaining = revert_list(&store);
        assert_eq!(remaining.len(), 1);
        assert_eq!(remaining[0].seq, sb, "only b's point remains");
    }

    #[test]
    fn list_is_recency_desc_and_metadata_only() {
        let dir = temp_dir("listmeta");
        let policy = FileReadPolicy::new(std::slice::from_ref(&dir), MAX_FILE_BYTES);
        let store = store_in(&dir);
        let s0 = capture_edit(&store, &dir.join("x.txt"), b"xo", b"xn");
        let s1 = capture_edit(&store, &dir.join("y.txt"), b"yold", b"ynew");
        let list = revert_list(&store);
        assert_eq!(list.len(), 2);
        assert_eq!(list[0].seq, s1, "most-recent first");
        assert_eq!(list[1].seq, s0);
        assert_eq!(
            list[0].old_bytes_len, 4,
            "metadata = the byte length, not the content"
        );
        assert_eq!(list[1].applied_sha_32, sha256_32(b"xn"));
        let _ = policy;
    }

    #[test]
    fn history_is_capped_evicting_oldest() {
        let dir = temp_dir("capevict");
        let store = store_in(&dir);
        // Capture CAP + 3 points (independent /tmp targets; not restored here).
        for i in 0..(REVERT_HISTORY_CAP + 3) {
            store
                .capture(&RevertBlob {
                    target_path: PathBuf::from(format!("/x/f{i}")),
                    applied_sha_32: [i as u8; 32],
                    old_bytes: vec![b'z'; i + 1],
                })
                .unwrap();
        }
        let list = revert_list(&store);
        assert_eq!(list.len(), REVERT_HISTORY_CAP, "bounded to the cap");
        // The newest survives; the three oldest (seq 0,1,2) were evicted.
        assert_eq!(list[0].seq, (REVERT_HISTORY_CAP + 2) as u64);
        assert!(store.peek_seq(0).is_none(), "the oldest was evicted");
        assert!(store.peek_seq(2).is_none());
        assert!(store.peek_seq(3).is_some(), "seq 3 is the new oldest");
    }

    #[test]
    fn wire_round_trips_and_fails_closed() {
        let blob = RevertBlob {
            target_path: PathBuf::from("/a/b/c.rs"),
            applied_sha_32: [9u8; 32],
            old_bytes: b"hello\n".to_vec(),
        };
        let w = blob.to_wire().expect("wire");
        assert_eq!(RevertBlob::from_wire(&w).as_ref(), Some(&blob));
        assert!(
            RevertBlob::from_wire(&w[..w.len() - 1]).is_none(),
            "truncation fails closed"
        );
        let mut slop = w.clone();
        slop.push(0);
        assert!(
            RevertBlob::from_wire(&slop).is_none(),
            "trailing slop fails closed"
        );
        let mut badv = w.clone();
        badv[0] = 9;
        assert!(
            RevertBlob::from_wire(&badv).is_none(),
            "bad version fails closed"
        );
    }

    #[test]
    fn sealed_record_rejects_tamper_and_wrong_key() {
        let dir = temp_dir("tamper");
        let store = store_in(&dir);
        let blob = RevertBlob {
            target_path: PathBuf::from("/x/y"),
            applied_sha_32: [3u8; 32],
            old_bytes: b"data".to_vec(),
        };
        let seq = store.capture(&blob).unwrap();
        let slot = dir.join("reverts").join(RevertStore::slot_name(seq));
        let mut bytes = std::fs::read(&slot).unwrap();
        let n = bytes.len();
        bytes[n - 1] ^= 0xff;
        std::fs::write(&slot, &bytes).unwrap();
        assert!(
            store.peek_seq(seq).is_none(),
            "a tampered record fails the AEAD tag"
        );
        // Restore a clean record, then prove a wrong key cannot open it.
        std::fs::write(&slot, store.record_bytes(&blob, seq).unwrap()).unwrap();
        let wrong = RevertStore::with_dir(MemoryCipher::from_key([8u8; 32]), dir.join("reverts"));
        assert!(
            wrong.peek_seq(seq).is_none(),
            "a wrong key cannot open the record"
        );
    }

    #[test]
    fn seq_rebind_rejected_by_aad() {
        // A key-less attacker renames a revert file to a different seq ⇒ the AAD
        // (header ‖ seq) no longer matches ⇒ the AEAD tag fails ⇒ None. The undo
        // history cannot be reordered without the key.
        let dir = temp_dir("rebind");
        let store = store_in(&dir);
        let blob = RevertBlob {
            target_path: PathBuf::from("/x/z"),
            applied_sha_32: [4u8; 32],
            old_bytes: b"payload".to_vec(),
        };
        let seq = store.capture(&blob).unwrap();
        assert!(store.peek_seq(seq).is_some(), "reads at its own seq");
        let from = dir.join("reverts").join(RevertStore::slot_name(seq));
        let to = dir.join("reverts").join(RevertStore::slot_name(seq + 100));
        std::fs::rename(&from, &to).unwrap();
        assert!(
            store.peek_seq(seq + 100).is_none(),
            "a seq-rebound file fails the AAD-bound tag"
        );
    }
}
