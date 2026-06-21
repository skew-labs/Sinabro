//! File-edit proposals — read→propose→apply with a staleness content-hash
//! lock (agent-core P3-2 VS-1; owner-locked tool-not-IDE shape). Threat
//! model: `ops/evidence/stage_g/agent_loop/MULTI_FILE_EDIT_THREAT_MODEL.md`
//! (IV-W1..W9).
//!
//! THE FIRST ARBITRARY-PATH FILESYSTEM WRITE IN THE CORE. The split of
//! authority is the whole design (IV-W1): the MODEL only PROPOSES (a typed,
//! sealed, INERT artifact extracted from its final answer — the loop grammar
//! is byte-unchanged and has no write tool); the OWNER alone APPLIES, per
//! action, behind the exact `file-apply-owner-live` ceremony in dispatch.
//!
//! # The drift-0 laws owned here
//!
//! * **IV-W2 propose-binds-a-verified-read** — a proposal is minted only for
//!   a target the loop actually verified-read; `read_sha` comes from the
//!   executor's own record, never from model-claimed text.
//! * **IV-W3 staleness lock** — apply refuses unless the target's CURRENT
//!   content hash equals the proposal's `read_sha` (typed [`ApplyDeny::Stale`]).
//!   An edit over moved ground is structurally rejected.
//! * **IV-W4 write confinement** — the target re-passes the lane-A
//!   [`FileReadPolicy`] wall stack (canonicalise → allowlist prefix →
//!   denylist → size cap) at apply time, in the apply-time cwd.
//! * **IV-W5 atomic write** — sibling temp, original-mode preserve, fsync,
//!   rename; then a re-read VERIFY against `sha256(content)` (a receipt,
//!   never a claim). P1-1 `atomic_write` discipline; journal = v2.
//! * **IV-W6 sealed inert store** — artifacts are AEAD-sealed (the P1-1
//!   [`MemoryCipher`], content-derived nonce ⇒ deterministic ⇒ idempotent
//!   re-propose), content-addressed (`hex(sha256(record)).fep`), bounded.
//!
//! Redaction of every render is the DISPATCH layer's job (same seam as the
//! lane-A file context); this module additionally REFUSES secret-shaped
//! proposed content at mint time (IV-W7a — an unreviewable diff must not
//! exist), via the caller-supplied gate to keep this module IO-pure on the
//! redaction axis.

use std::path::{Path, PathBuf};

use crate::file_context::{FileReadDeny, FileReadPolicy, MAX_FILE_BYTES, denied_token};
use crate::memory_store::{CipherError, MemoryCipher, data_dir};
use crate::{hex32, sha256_32};

/// Proposal record magic (4 bytes) — `MNFP` = MNemos File-edit Proposal.
pub const PROPOSAL_MAGIC: [u8; 4] = *b"MNFP";

/// Proposal record version (the on-disk header byte; AAD-bound).
pub const PROPOSAL_RECORD_VERSION: u8 = 1;

/// Sealed-plaintext wire version (the first byte INSIDE the seal). v1 = one
/// single-file full-content edit; multi-file batches extend this byte.
pub const PROPOSAL_WIRE_VERSION: u8 = 1;

/// Fixed record header width: magic(4) + version(1). Python-verified
/// 2026-06-11 (`header_hex = 4d4e465001`, len 5).
pub const PROPOSAL_HEADER_BYTES: usize = 5;

/// On-disk proposal file extension.
pub const PROPOSAL_EXT: &str = "fep";

/// Proposals subdirectory under the data dir (`$HOME/.mnemos`).
pub const PROPOSALS_SUBDIR: &str = "proposals";

/// Pending-proposal cap (IV-W8): a save beyond this is a typed deny — the
/// pending set stays a bounded, reviewable, actionable list.
pub const MAX_PENDING_PROPOSALS: usize = 32;

/// Bounded diff render lines (IV-W8; explicit truncation marker beyond).
pub const DIFF_RENDER_LINE_CAP: usize = 40;

/// The id the owner types at apply: the first 16 hex chars of the record
/// name (prefix-matched; ambiguity is a typed deny).
pub const PROPOSAL_ID_HEX_CHARS: usize = 16;

// ===========================================================================
// 1. The proposal value + canonical wire codec (L3 — golden-vector pinned)
// ===========================================================================

/// One single-file edit proposal (VS-1): replace `target_path`'s ENTIRE
/// content with `content`, valid only while the target still hashes to
/// `read_sha_32` (IV-W3).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FileEditProposal {
    /// The CANONICAL target path (symlink/`..`-resolved at read time).
    pub target_path: PathBuf,
    /// `sha256` of the target's bytes AS VERIFIED-READ by the loop (IV-W2).
    pub read_sha_32: [u8; 32],
    /// The proposed full new content (UTF-8 by construction — it came from
    /// the model's answer text; normalized to end with one `\n`).
    pub content: Vec<u8>,
}

/// Typed wire-codec failures (decode is fail-closed; no partial trust).
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
#[non_exhaustive]
pub enum ProposalWireError {
    /// The wire bytes were shorter than a field demanded.
    Truncated,
    /// The wire version byte is not [`PROPOSAL_WIRE_VERSION`].
    UnknownVersion,
    /// The path bytes were not valid UTF-8.
    PathNotUtf8,
    /// Trailing garbage followed the last field.
    TrailingBytes,
}

impl FileEditProposal {
    /// Canonical wire encoding (Python-verified golden vector 2026-06-11:
    /// `ver(1) || path_len(u16 LE) || path || read_sha(32) ||
    /// content_len(u32 LE) || content`; the `notes.txt`/`hello\n` vector is
    /// 54 bytes — pinned in tests). Paths longer than `u16::MAX` bytes or
    /// content longer than `u32::MAX` cannot occur (both are capped far
    /// below by the mint walls), but the encoder still saturates fail-closed
    /// by refusing via `None`.
    #[must_use]
    pub fn to_wire(&self) -> Option<Vec<u8>> {
        let path_bytes = self.target_path.to_str()?.as_bytes();
        let path_len = u16::try_from(path_bytes.len()).ok()?;
        let content_len = u32::try_from(self.content.len()).ok()?;
        let mut wire = Vec::with_capacity(1 + 2 + path_bytes.len() + 32 + 4 + self.content.len());
        wire.push(PROPOSAL_WIRE_VERSION);
        wire.extend_from_slice(&path_len.to_le_bytes());
        wire.extend_from_slice(path_bytes);
        wire.extend_from_slice(&self.read_sha_32);
        wire.extend_from_slice(&content_len.to_le_bytes());
        wire.extend_from_slice(&self.content);
        Some(wire)
    }

    /// Fail-closed wire decode — every length is checked before it is
    /// consumed; trailing bytes reject (a record is exactly one proposal).
    pub fn from_wire(wire: &[u8]) -> Result<Self, ProposalWireError> {
        let mut at = 0usize;
        let take = |at: &mut usize, n: usize| -> Result<&[u8], ProposalWireError> {
            let end = at.checked_add(n).ok_or(ProposalWireError::Truncated)?;
            if end > wire.len() {
                return Err(ProposalWireError::Truncated);
            }
            let slice = &wire[*at..end];
            *at = end;
            Ok(slice)
        };
        let version = take(&mut at, 1)?[0];
        if version != PROPOSAL_WIRE_VERSION {
            return Err(ProposalWireError::UnknownVersion);
        }
        let mut path_len_bytes = [0u8; 2];
        path_len_bytes.copy_from_slice(take(&mut at, 2)?);
        let path_len = usize::from(u16::from_le_bytes(path_len_bytes));
        let path_bytes = take(&mut at, path_len)?;
        let path_text =
            core::str::from_utf8(path_bytes).map_err(|_| ProposalWireError::PathNotUtf8)?;
        let mut read_sha_32 = [0u8; 32];
        read_sha_32.copy_from_slice(take(&mut at, 32)?);
        let mut content_len_bytes = [0u8; 4];
        content_len_bytes.copy_from_slice(take(&mut at, 4)?);
        let content_len = usize::try_from(u32::from_le_bytes(content_len_bytes))
            .map_err(|_| ProposalWireError::Truncated)?;
        let content = take(&mut at, content_len)?.to_vec();
        if at != wire.len() {
            return Err(ProposalWireError::TrailingBytes);
        }
        Ok(Self {
            target_path: PathBuf::from(path_text),
            read_sha_32,
            content,
        })
    }
}

// ===========================================================================
// 2. PROPOSE — answer-block extraction + mint walls (IV-W2/W7a/W8)
// ===========================================================================

/// A verified file read the loop performed (the executor's OWN record —
/// IV-W2's truth source; never model-claimed). Recorded only when the read
/// reached the `(verified)` state (walls + redaction all passed).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerifiedFileRead {
    /// The path exactly as the model typed it in the tool line.
    pub path_as_typed: String,
    /// The canonical (resolved) path the policy actually read.
    pub canonical_path: PathBuf,
    /// `sha256` of the bytes that entered the prompt.
    pub sha256_32: [u8; 32],
}

/// The parsed-but-unminted shape of a `PROPOSE-EDIT` answer block.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProposedEdit {
    /// The model's claimed target (matched against verified reads at mint).
    pub target_as_typed: String,
    /// The proposed full content (newline-normalized; see codec note).
    pub content: String,
}

/// Typed propose denials (data-free; rendered as honest reasons).
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
#[non_exhaustive]
pub enum ProposeDeny {
    /// The block had `PROPOSE-EDIT` but not the closed grammar shape.
    Malformed,
    /// The claimed target was never verified-read this run (IV-W2).
    TargetNotRead,
    /// A CREATE proposal named a target that ALREADY exists — EDIT it (read-first)
    /// instead of creating (E-NEW; the create path never overwrites).
    TargetExists,
    /// A CREATE proposal's parent did not confine to an allowed root (E-NEW; IV-W4).
    TargetNotConfined,
    /// The proposed content exceeds [`MAX_FILE_BYTES`] (IV-W8).
    ContentTooLarge,
    /// The target name matches the secret-container denylist (belt; IV-W4).
    DeniedName,
    /// The proposed content is secret-shaped (IV-W7a — refused outright).
    SecretShaped,
    /// The pending store already holds [`MAX_PENDING_PROPOSALS`] (IV-W8).
    StoreFull,
    /// The proposal could not be encoded/sealed/written (io class).
    StoreFailed,
}

impl ProposeDeny {
    /// Stable, allow-listed `class_label` (namespaced `file_edit.propose.*`).
    #[inline]
    #[must_use]
    pub const fn class_label(self) -> &'static str {
        match self {
            Self::Malformed => "file_edit.propose.malformed",
            Self::TargetNotRead => "file_edit.propose.target_not_read",
            Self::TargetExists => "file_edit.propose.target_exists",
            Self::TargetNotConfined => "file_edit.propose.target_not_confined",
            Self::ContentTooLarge => "file_edit.propose.content_too_large",
            Self::DeniedName => "file_edit.propose.denied_name",
            Self::SecretShaped => "file_edit.propose.secret_shaped",
            Self::StoreFull => "file_edit.propose.store_full",
            Self::StoreFailed => "file_edit.propose.store_failed",
        }
    }
}

/// The first line of a propose-shaped answer (exact, case-sensitive — a
/// closed grammar, the same discipline as the loop's `TOOL:` lines).
const PROPOSE_HEAD: &str = "PROPOSE-EDIT";
/// The target line prefix.
const PROPOSE_TARGET_PREFIX: &str = "TARGET:";
/// The content sentinel line.
const PROPOSE_CONTENT_LINE: &str = "CONTENT:";

/// Parse a final answer for the closed `PROPOSE-EDIT` block.
///
/// * `None` — the answer is not propose-shaped at all (an ordinary answer).
/// * `Some(Err(Malformed))` — it claimed `PROPOSE-EDIT` but broke the shape
///   (fail-closed: a half-proposal is never guessed into one).
/// * `Some(Ok(_))` — a structurally valid proposal (mint walls still apply).
///
/// Codec rule (TM DESIGN LOCK): the loop's answer parse trims outer
/// whitespace, so this channel cannot carry a trailing newline; non-empty
/// content is therefore normalized to end with exactly one `\n`.
#[must_use]
pub fn extract_proposal(answer: &str) -> Option<Result<ProposedEdit, ProposeDeny>> {
    let mut lines = answer.lines();
    let head = lines.next()?.trim();
    if head != PROPOSE_HEAD {
        return None;
    }
    let Some(target_line) = lines.next() else {
        return Some(Err(ProposeDeny::Malformed));
    };
    let Some(target_raw) = target_line.trim().strip_prefix(PROPOSE_TARGET_PREFIX) else {
        return Some(Err(ProposeDeny::Malformed));
    };
    let target_as_typed = target_raw.trim();
    if target_as_typed.is_empty() {
        return Some(Err(ProposeDeny::Malformed));
    }
    let Some(content_line) = lines.next() else {
        return Some(Err(ProposeDeny::Malformed));
    };
    if content_line.trim() != PROPOSE_CONTENT_LINE {
        return Some(Err(ProposeDeny::Malformed));
    }
    // Everything after the CONTENT: line, verbatim (line structure kept).
    let mut content = lines.collect::<Vec<&str>>().join("\n");
    if !content.is_empty() && !content.ends_with('\n') {
        content.push('\n');
    }
    Some(Ok(ProposedEdit {
        target_as_typed: target_as_typed.to_string(),
        content,
    }))
}

/// Mint a [`FileEditProposal`] from a parsed block + the loop's OWN
/// verified-read records (IV-W2). `content_is_secret_shaped` is the caller's
/// canonical redaction verdict over the proposed content (IV-W7a) — passed
/// as a bool so this module stays decoupled from the redaction types.
pub fn mint_proposal(
    proposed: &ProposedEdit,
    verified_reads: &[VerifiedFileRead],
    content_is_secret_shaped: bool,
) -> Result<FileEditProposal, ProposeDeny> {
    // IV-W2 — the binding read: match the claimed target against the
    // executor's records (as-typed first, then by canonical resolution).
    let read = verified_reads
        .iter()
        .find(|read| read.path_as_typed == proposed.target_as_typed)
        .or_else(|| {
            let canonical = std::fs::canonicalize(&proposed.target_as_typed).ok()?;
            verified_reads
                .iter()
                .find(|read| read.canonical_path == canonical)
        })
        .ok_or(ProposeDeny::TargetNotRead)?;
    // Belt (IV-W4 upstream): a denylisted name was never readable, but the
    // claim is re-checked anyway — classify-fail = deny.
    if denied_token(&read.canonical_path).is_some() {
        return Err(ProposeDeny::DeniedName);
    }
    // IV-W8 — bounded content (refuse, never truncate).
    if proposed.content.len() as u64 > MAX_FILE_BYTES {
        return Err(ProposeDeny::ContentTooLarge);
    }
    // IV-W7a — secret-shaped content is refused outright (an unreviewable
    // diff must not exist; fail-closed beats withhold-and-ask).
    if content_is_secret_shaped {
        return Err(ProposeDeny::SecretShaped);
    }
    Ok(FileEditProposal {
        target_path: read.canonical_path.clone(),
        read_sha_32: read.sha256_32,
        content: proposed.content.clone().into_bytes(),
    })
}

/// The "absent baseline" sentinel for a NEW-FILE proposal: a `read_sha_32` of all zeros.
/// SHA-256 of any byte string is never all-zero, so this value can ONLY mean "the target
/// did not exist when proposed" — [`apply_proposal`] branches on it to CREATE (never
/// overwrite). Keeps the proposal wire/codec/store byte-compatible (no new field).
pub const ABSENT_BASELINE_SHA: [u8; 32] = [0u8; 32];

/// Mint a NEW-FILE [`FileEditProposal`] (E-NEW): the create-time sibling of
/// [`mint_proposal`]. The edit path binds to a prior verified read (IV-W2); a file that
/// does not exist yet cannot be read, so creation takes a DISTINCT, equally fail-closed
/// path — it NEVER relaxes the edit gate. Refuses unless: the target is ABSENT (else EDIT
/// it, read-first), its PARENT confines to an allowed root + clears the denylist
/// ([`FileReadPolicy::confine_new`]), the content is bounded (IV-W8) + non-secret (IV-W7a).
/// The baseline is [`ABSENT_BASELINE_SHA`]; apply creates-if-still-absent (never overwrites).
pub fn mint_new_file_proposal(
    proposed: &ProposedEdit,
    policy: &FileReadPolicy,
    content_is_secret_shaped: bool,
) -> Result<FileEditProposal, ProposeDeny> {
    // The target must be ABSENT. `symlink_metadata` (not `exists`) so a dangling symlink
    // also counts as present — never create through one.
    if std::fs::symlink_metadata(&proposed.target_as_typed).is_ok() {
        return Err(ProposeDeny::TargetExists);
    }
    // Confine the parent to an allowed root + denylist the resolved name (IV-W4 at create).
    let resolved = policy
        .confine_new(std::path::Path::new(&proposed.target_as_typed))
        .map_err(|deny| match deny {
            FileReadDeny::DeniedName(_) => ProposeDeny::DeniedName,
            _ => ProposeDeny::TargetNotConfined,
        })?;
    // IV-W8 — bounded content (refuse, never truncate).
    if proposed.content.len() as u64 > MAX_FILE_BYTES {
        return Err(ProposeDeny::ContentTooLarge);
    }
    // IV-W7a — secret-shaped content refused outright.
    if content_is_secret_shaped {
        return Err(ProposeDeny::SecretShaped);
    }
    Ok(FileEditProposal {
        target_path: resolved,
        read_sha_32: ABSENT_BASELINE_SHA,
        content: proposed.content.clone().into_bytes(),
    })
}

// ===========================================================================
// 3. The sealed, content-addressed, bounded proposal store (IV-W6/W8)
// ===========================================================================

/// One pending proposal as listed/loaded: its full record name (the
/// content-addressed filename stem + extension) plus the decoded value.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PendingProposal {
    /// The on-disk record filename (`<64-hex>.fep`).
    pub record_name: String,
    /// The decoded proposal.
    pub proposal: FileEditProposal,
}

/// Outcome of a pending-store load: decoded proposals (record-name-sorted,
/// deterministic) + an honest skip count (DL-5 discipline).
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct PendingLoad {
    /// Decoded proposals, sorted ascending by record name.
    pub proposals: Vec<PendingProposal>,
    /// Records skipped (name/tag/header/wire failures) — never loaded as truth.
    pub skipped_u32: u32,
}

/// Typed apply denials (IV-W1..W5 walls; data-free except hashes the caller
/// already holds). `Clone`-not-`Copy`: it embeds the lane-A
/// [`FileReadDeny`], which is `Clone` only.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum ApplyDeny {
    /// No pending proposal matched the supplied id prefix.
    UnknownId,
    /// More than one pending proposal matched the id prefix.
    AmbiguousId,
    /// The target failed the lane-A read wall stack at apply time (IV-W4);
    /// carries the read-side denial class.
    TargetWall(FileReadDeny),
    /// The target's CURRENT hash differs from the proposal's `read_sha_32`
    /// (IV-W3 — the staleness lock).
    Stale,
    /// The atomic write failed (temp/perms/fsync/rename io class).
    WriteFailed,
    /// The post-rename re-read did not hash to the proposed content.
    VerifyFailed,
    /// A CREATE proposal's target now EXISTS at apply time (it appeared since the
    /// proposal was minted) — the creation-staleness law: fail-closed, never overwrite
    /// (E-NEW; the create-time analog of [`Stale`](Self::Stale)).
    NewFileExists,
}

impl ApplyDeny {
    /// Stable, allow-listed `class_label` (namespaced `file_edit.apply.*`).
    #[inline]
    #[must_use]
    pub const fn class_label(&self) -> &'static str {
        match self {
            Self::UnknownId => "file_edit.apply.unknown_id",
            Self::AmbiguousId => "file_edit.apply.ambiguous_id",
            Self::TargetWall(_) => "file_edit.apply.target_wall",
            Self::Stale => "file_edit.apply.stale_target",
            Self::WriteFailed => "file_edit.apply.write_failed",
            Self::VerifyFailed => "file_edit.apply.verify_failed",
            Self::NewFileExists => "file_edit.apply.new_file_exists",
        }
    }
}

/// The sealed proposal store. Same key + cipher + atomic-write discipline as
/// the P1-1 memory store; a DIFFERENT magic/extension/subdir so a proposal
/// can never masquerade as a memory record (and vice versa — the AAD header
/// differs, so even a renamed cross-store file fails the tag).
#[derive(Clone, Debug)]
pub struct ProposalStore {
    cipher: MemoryCipher,
    store_dir: PathBuf,
}

impl ProposalStore {
    /// Open the local store (`$HOME/.mnemos/proposals/`), creating the dir.
    /// Fail-closed on key/io trouble (the caller renders a degraded surface).
    pub fn open_local() -> Result<Self, ProposeDeny> {
        let cipher = MemoryCipher::open_local().map_err(|_| ProposeDeny::StoreFailed)?;
        let store_dir = data_dir()
            .map_err(|_| ProposeDeny::StoreFailed)?
            .join(PROPOSALS_SUBDIR);
        std::fs::create_dir_all(&store_dir).map_err(|_| ProposeDeny::StoreFailed)?;
        Ok(Self { cipher, store_dir })
    }

    /// Construct over an explicit cipher + dir (tests / non-default roots).
    #[must_use]
    pub fn with_dir(cipher: MemoryCipher, store_dir: PathBuf) -> Self {
        Self { cipher, store_dir }
    }

    /// The on-disk record header — also the AEAD associated data (IV-W6).
    const fn record_header() -> [u8; PROPOSAL_HEADER_BYTES] {
        [
            PROPOSAL_MAGIC[0],
            PROPOSAL_MAGIC[1],
            PROPOSAL_MAGIC[2],
            PROPOSAL_MAGIC[3],
            PROPOSAL_RECORD_VERSION,
        ]
    }

    /// The canonical record bytes for a proposal: `magic|version|sealed`,
    /// `sealed = AEAD(wire, aad = header)`. Deterministic (content-derived
    /// nonce) ⇒ the same proposal always yields the same record ⇒ the same
    /// content-addressed name (idempotent re-propose, TM T10).
    fn record_bytes(&self, proposal: &FileEditProposal) -> Result<Vec<u8>, ProposeDeny> {
        let wire = proposal.to_wire().ok_or(ProposeDeny::StoreFailed)?;
        let header = Self::record_header();
        let sealed = self
            .cipher
            .seal_with_aad(&wire, &header)
            .map_err(|_: CipherError| ProposeDeny::StoreFailed)?;
        let mut record = Vec::with_capacity(PROPOSAL_HEADER_BYTES + sealed.len());
        record.extend_from_slice(&header);
        record.extend_from_slice(&sealed);
        Ok(record)
    }

    /// The content-addressed filename (`hex(sha256(record)).fep`).
    fn record_name(record: &[u8]) -> String {
        format!("{}.{PROPOSAL_EXT}", hex32(&sha256_32(record)))
    }

    /// Persist one proposal: encode → seal → bounded-pending check → atomic
    /// write. Returns the record name (its 16-hex prefix is the owner-typed
    /// apply id). Idempotent for an identical proposal (same bytes, same
    /// name — re-saving an already-pending proposal is NOT a second slot,
    /// so the pending cap ignores an exact duplicate).
    pub fn save(&self, proposal: &FileEditProposal) -> Result<String, ProposeDeny> {
        let record = self.record_bytes(proposal)?;
        let name = Self::record_name(&record);
        let path = self.store_dir.join(&name);
        if !path.exists() {
            // IV-W8 — the pending cap counts DISTINCT pending artifacts.
            let pending = self.load_pending();
            if pending.proposals.len() >= MAX_PENDING_PROPOSALS {
                return Err(ProposeDeny::StoreFull);
            }
        }
        atomic_write_file(&path, &record).map_err(|_| ProposeDeny::StoreFailed)?;
        Ok(name)
    }

    /// Load every readable pending proposal, fail-closed per record (a bad
    /// record is SKIPPED + counted, never trusted), record-name-sorted
    /// (deterministic listing regardless of dir enumeration order).
    #[must_use]
    pub fn load_pending(&self) -> PendingLoad {
        let mut outcome = PendingLoad::default();
        let entries = match std::fs::read_dir(&self.store_dir) {
            Ok(entries) => entries,
            Err(_) => return outcome,
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.extension().and_then(|e| e.to_str()) != Some(PROPOSAL_EXT) {
                continue;
            }
            match self.load_one(&path) {
                Some(pending) => outcome.proposals.push(pending),
                None => outcome.skipped_u32 = outcome.skipped_u32.saturating_add(1),
            }
        }
        outcome
            .proposals
            .sort_by(|a, b| a.record_name.cmp(&b.record_name));
        outcome
    }

    /// Load + verify ONE record file, or `None` (skip) on any gate failure:
    /// name-hash → header → AEAD(tag + nonce re-bind, header as AAD) →
    /// fail-closed wire decode.
    fn load_one(&self, path: &Path) -> Option<PendingProposal> {
        let bytes = std::fs::read(path).ok()?;
        let expected = Self::record_name(&bytes);
        if path.file_name().and_then(|n| n.to_str()) != Some(expected.as_str()) {
            return None;
        }
        if bytes.len() < PROPOSAL_HEADER_BYTES
            || bytes[..4] != PROPOSAL_MAGIC
            || bytes[4] != PROPOSAL_RECORD_VERSION
        {
            return None;
        }
        let wire = self
            .cipher
            .open_with_aad(
                &bytes[PROPOSAL_HEADER_BYTES..],
                &bytes[..PROPOSAL_HEADER_BYTES],
            )
            .ok()?;
        let proposal = FileEditProposal::from_wire(&wire).ok()?;
        Some(PendingProposal {
            record_name: expected,
            proposal,
        })
    }

    /// Find ONE pending proposal by id prefix (the owner types ≥
    /// [`PROPOSAL_ID_HEX_CHARS`] chars; fewer still works if unambiguous).
    /// Zero matches ⇒ `UnknownId`; two or more ⇒ `AmbiguousId` (typed,
    /// fail-closed — never "the first one").
    pub fn find_by_prefix(&self, id_prefix: &str) -> Result<PendingProposal, ApplyDeny> {
        let prefix = id_prefix.trim().to_ascii_lowercase();
        if prefix.is_empty() {
            return Err(ApplyDeny::UnknownId);
        }
        let pending = self.load_pending();
        let mut matches = pending
            .proposals
            .into_iter()
            .filter(|p| p.record_name.starts_with(&prefix));
        match (matches.next(), matches.next()) {
            (None, _) => Err(ApplyDeny::UnknownId),
            (Some(one), None) => Ok(one),
            (Some(_), Some(_)) => Err(ApplyDeny::AmbiguousId),
        }
    }

    /// Remove a consumed artifact (apply success path; IV gate 9). A failed
    /// removal is reported by the caller, never silent.
    pub fn remove(&self, record_name: &str) -> std::io::Result<()> {
        std::fs::remove_file(self.store_dir.join(record_name))
    }
}

// ===========================================================================
// 4. APPLY — staleness + confinement + atomic replace (IV-W3/W4/W5)
// ===========================================================================

/// The apply receipt: every hash the audit trail needs (L4 — the receipt +
/// the target file ARE the evidence; the artifact is consumed).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ApplyReceipt {
    /// The canonical target that was replaced.
    pub target_path: PathBuf,
    /// The displaced content's hash (== the proposal's `read_sha_32`).
    pub old_sha_32: [u8; 32],
    /// The written content's hash (verified by re-read).
    pub new_sha_32: [u8; 32],
    /// Bytes written.
    pub bytes_written_u64: u64,
    /// The displaced content's UTF-8 text (for the diff render; the bytes
    /// passed the lane-A read walls — `None` if the old content was binary,
    /// which cannot happen for a proposal minted from a verified read).
    pub old_text: Option<String>,
}

/// Apply ONE proposal through the full wall stack (TM gate stack 5-8):
/// lane-A read walls on the CURRENT target (IV-W4, apply-time cwd policy) →
/// staleness hash equality (IV-W3) → atomic mode-preserving replace
/// (IV-W5) → re-read verify. Returns the receipt; every failure is typed
/// and the target is untouched on every deny path (the only mutation is the
/// final rename).
pub fn apply_proposal(
    policy: &FileReadPolicy,
    proposal: &FileEditProposal,
) -> Result<ApplyReceipt, ApplyDeny> {
    // E-NEW — the absent-baseline sentinel routes to create-if-still-absent (never
    // overwrites; the staleness law for a NEW file is "it still does not exist").
    if proposal.read_sha_32 == ABSENT_BASELINE_SHA {
        return apply_new_file(policy, proposal);
    }
    // IV-W4 — re-confinement + the staleness read in one gated pass.
    let current = policy
        .read(&proposal.target_path)
        .map_err(ApplyDeny::TargetWall)?;
    // IV-W3 — the drift-0 law.
    if current.sha256_32 != proposal.read_sha_32 {
        return Err(ApplyDeny::Stale);
    }
    // IV-W5 — atomic replace: sibling temp (same dir = same fs), original
    // mode preserved BEFORE the rename, fsync, rename.
    let target = &current.canonical_path;
    let file_name = target
        .file_name()
        .and_then(|n| n.to_str())
        .ok_or(ApplyDeny::WriteFailed)?;
    let temp = target.with_file_name(format!(".{file_name}.sinabro.tmp"));
    let original_mode = std::fs::metadata(target)
        .map(|m| m.permissions())
        .map_err(|_| ApplyDeny::WriteFailed)?;
    let write_result = (|| -> std::io::Result<()> {
        use std::io::Write;
        {
            let mut file = std::fs::File::create(&temp)?;
            file.write_all(&proposal.content)?;
            file.sync_all()?;
        }
        std::fs::set_permissions(&temp, original_mode)?;
        std::fs::rename(&temp, target)
    })();
    if write_result.is_err() {
        // Leave no temp litter on a failed attempt (best-effort; the target
        // itself is intact — the rename either happened atomically or not).
        let _ = std::fs::remove_file(&temp);
        return Err(ApplyDeny::WriteFailed);
    }
    // Gate 8 — verify-after-write: a receipt, never a claim.
    let new_sha_32 = sha256_32(&proposal.content);
    let reread = std::fs::read(target).map_err(|_| ApplyDeny::VerifyFailed)?;
    if sha256_32(&reread) != new_sha_32 {
        return Err(ApplyDeny::VerifyFailed);
    }
    Ok(ApplyReceipt {
        target_path: target.clone(),
        old_sha_32: current.sha256_32,
        new_sha_32,
        bytes_written_u64: proposal.content.len() as u64,
        old_text: current.text,
    })
}

/// Apply a NEW-FILE proposal (E-NEW): re-confine the parent (IV-W4 at apply time) →
/// EXCLUSIVE create (`O_CREAT|O_EXCL` — atomically fails if the target exists, so it
/// NEVER overwrites; an existing target is [`ApplyDeny::NewFileExists`], the creation-
/// staleness law) → fsync → re-read verify. The target is untouched on every deny path;
/// a failed write removes only the (new) partial file it just made, never a pre-existing
/// one. NOTE (v1): rewinding a create restores the file to EMPTY, not deletion.
fn apply_new_file(
    policy: &FileReadPolicy,
    proposal: &FileEditProposal,
) -> Result<ApplyReceipt, ApplyDeny> {
    let target = policy
        .confine_new(&proposal.target_path)
        .map_err(ApplyDeny::TargetWall)?;
    // IV-W8 belt (the mint already capped; re-check at the write boundary).
    if proposal.content.len() as u64 > MAX_FILE_BYTES {
        return Err(ApplyDeny::WriteFailed);
    }
    use std::io::Write;
    let mut file = match std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&target)
    {
        Ok(file) => file,
        Err(err) if err.kind() == std::io::ErrorKind::AlreadyExists => {
            return Err(ApplyDeny::NewFileExists);
        }
        Err(_) => return Err(ApplyDeny::WriteFailed),
    };
    if file
        .write_all(&proposal.content)
        .and_then(|()| file.sync_all())
        .is_err()
    {
        drop(file);
        let _ = std::fs::remove_file(&target); // no partial NEW-file litter (best-effort)
        return Err(ApplyDeny::WriteFailed);
    }
    drop(file);
    // Gate 8 — verify-after-write: a receipt, never a claim.
    let new_sha_32 = sha256_32(&proposal.content);
    let reread = std::fs::read(&target).map_err(|_| ApplyDeny::VerifyFailed)?;
    if sha256_32(&reread) != new_sha_32 {
        return Err(ApplyDeny::VerifyFailed);
    }
    Ok(ApplyReceipt {
        target_path: target,
        old_sha_32: ABSENT_BASELINE_SHA,
        new_sha_32,
        bytes_written_u64: proposal.content.len() as u64,
        old_text: Some(String::new()), // no prior content — the diff renders all-additions
    })
}

// ===========================================================================
// 4b. OWNER SAVE — a DIRECT owner write (P2-S5; PersonalOwner tier)
// ===========================================================================

/// The owner-save receipt — metadata ONLY (secret-zero: the saved content is never echoed
/// back, so a secret-shaped file the owner saves never round-trips through a render).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OwnerSaveReceipt {
    /// The canonical target that was replaced.
    pub target_path: PathBuf,
    /// The displaced content's hash (== the editor's read baseline).
    pub old_sha_32: [u8; 32],
    /// The written content's hash (verified by re-read).
    pub new_sha_32: [u8; 32],
    /// Bytes written.
    pub bytes_written_u64: u64,
}

/// Typed owner-save denials (namespaced `file_edit.owner_save.*`).
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum OwnerSaveDeny {
    /// The target failed the lane-A read wall stack (IV-W4) — only an owner-granted root is
    /// writable, exactly as it is readable (the save reuses the read confinement).
    TargetWall(FileReadDeny),
    /// The supplied baseline is not 64 lowercase hex chars (a malformed staleness baseline).
    BaseShaMalformed,
    /// The target's CURRENT hash differs from the editor's read baseline (IV-W3 staleness).
    Stale,
    /// The atomic write failed (temp/perms/fsync/rename io class).
    WriteFailed,
    /// The post-rename re-read did not hash to the saved content.
    VerifyFailed,
}

impl OwnerSaveDeny {
    /// Stable, allow-listed `class_label` (namespaced `file_edit.owner_save.*`).
    #[inline]
    #[must_use]
    pub const fn class_label(&self) -> &'static str {
        match self {
            Self::TargetWall(_) => "file_edit.owner_save.target_wall",
            Self::BaseShaMalformed => "file_edit.owner_save.base_sha_malformed",
            Self::Stale => "file_edit.owner_save.stale_target",
            Self::WriteFailed => "file_edit.owner_save.write_failed",
            Self::VerifyFailed => "file_edit.owner_save.verify_failed",
        }
    }
}

/// P2-S5 — a DIRECT owner save (PersonalOwner tier): write `new_content` to `path` IFF the
/// target's CURRENT content hash equals `base_sha_hex` (the hash the owner's editor read when it
/// opened the file). The SAME wall stack as [`apply_proposal`] — lane-A confinement on the CURRENT
/// target (IV-W4; only an owner-granted root is writable, exactly as it is readable) → staleness
/// equality (IV-W3, refuse a file changed since the editor read it) → atomic mode-preserving
/// replace (IV-W5) → re-read verify — but the content comes DIRECTLY from the owner, NOT a model
/// proposal. The model has NO path here (this is a GUI IPC command, not a loop tool — the model
/// cannot self-save). The receipt is metadata-only (secret-zero). NEVER chain-write (a local file
/// write; no chain/wallet/custody on this path; PD-6 untouched).
pub fn owner_save_file(
    policy: &FileReadPolicy,
    path: &Path,
    new_content: &[u8],
    base_sha_hex: &str,
) -> Result<OwnerSaveReceipt, OwnerSaveDeny> {
    // Reject a malformed baseline up front (64 lowercase hex chars = a 32-byte sha).
    if base_sha_hex.len() != 64
        || !base_sha_hex
            .bytes()
            .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
    {
        return Err(OwnerSaveDeny::BaseShaMalformed);
    }
    // IV-W4 — re-confinement + the staleness read in one gated pass (the lane-A read walls).
    let current = policy.read(path).map_err(OwnerSaveDeny::TargetWall)?;
    // IV-W3 — the drift-0 staleness law: refuse a target changed since the editor read it.
    if hex32(&current.sha256_32) != base_sha_hex {
        return Err(OwnerSaveDeny::Stale);
    }
    // IV-W5 — atomic replace: sibling temp (same dir = same fs), original mode preserved
    // BEFORE the rename, fsync, rename (mirrors apply_proposal exactly).
    let target = &current.canonical_path;
    let file_name = target
        .file_name()
        .and_then(|n| n.to_str())
        .ok_or(OwnerSaveDeny::WriteFailed)?;
    let temp = target.with_file_name(format!(".{file_name}.sinabro-owner.tmp"));
    let original_mode = std::fs::metadata(target)
        .map(|m| m.permissions())
        .map_err(|_| OwnerSaveDeny::WriteFailed)?;
    let write_result = (|| -> std::io::Result<()> {
        use std::io::Write;
        {
            let mut file = std::fs::File::create(&temp)?;
            file.write_all(new_content)?;
            file.sync_all()?;
        }
        std::fs::set_permissions(&temp, original_mode)?;
        std::fs::rename(&temp, target)
    })();
    if write_result.is_err() {
        let _ = std::fs::remove_file(&temp);
        return Err(OwnerSaveDeny::WriteFailed);
    }
    // verify-after-write: a receipt, never a claim.
    let new_sha_32 = sha256_32(new_content);
    let reread = std::fs::read(target).map_err(|_| OwnerSaveDeny::VerifyFailed)?;
    if sha256_32(&reread) != new_sha_32 {
        return Err(OwnerSaveDeny::VerifyFailed);
    }
    Ok(OwnerSaveReceipt {
        target_path: target.clone(),
        old_sha_32: current.sha256_32,
        new_sha_32,
        bytes_written_u64: new_content.len() as u64,
    })
}

/// Atomically write `bytes` to `path` in the PROPOSAL STORE (hash-named
/// files — a static `.tmp` sibling cannot collide with a record name).
/// Same temp+fsync+rename discipline as the P1-1 store.
fn atomic_write_file(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    use std::io::Write;
    let tmp = path.with_extension("tmp");
    {
        let mut file = std::fs::File::create(&tmp)?;
        file.write_all(bytes)?;
        file.sync_all()?;
    }
    std::fs::rename(&tmp, path)
}

// ===========================================================================
// 5. Bounded deterministic line diff (render-only; O(n) trim, no fuzz)
// ===========================================================================

/// Render a bounded `-`/`+` line diff between two texts: common prefix and
/// suffix lines are trimmed (two-pointer, O(n), deterministic — no LCS, no
/// heuristics), the changed middle renders with explicit per-side caps and
/// truncation markers. Render-only: apply NEVER consumes a diff (the
/// artifact carries full content; a patch-application ambiguity therefore
/// cannot exist — TM DESIGN LOCK).
#[must_use]
pub fn render_line_diff(old_text: &str, new_text: &str) -> Vec<String> {
    let old_lines: Vec<&str> = old_text.lines().collect();
    let new_lines: Vec<&str> = new_text.lines().collect();
    let mut prefix = 0usize;
    while prefix < old_lines.len()
        && prefix < new_lines.len()
        && old_lines[prefix] == new_lines[prefix]
    {
        prefix += 1;
    }
    let mut suffix = 0usize;
    while suffix < old_lines.len().saturating_sub(prefix)
        && suffix < new_lines.len().saturating_sub(prefix)
        && old_lines[old_lines.len() - 1 - suffix] == new_lines[new_lines.len() - 1 - suffix]
    {
        suffix += 1;
    }
    let old_mid = &old_lines[prefix..old_lines.len() - suffix];
    let new_mid = &new_lines[prefix..new_lines.len() - suffix];
    let mut out = vec![format!(
        "diff: -{} +{} lines (context: {} prefix / {} suffix unchanged)",
        old_mid.len(),
        new_mid.len(),
        prefix,
        suffix
    )];
    let per_side_cap = DIFF_RENDER_LINE_CAP / 2;
    for line in old_mid.iter().take(per_side_cap) {
        out.push(format!("- {line}"));
    }
    if old_mid.len() > per_side_cap {
        out.push(format!(
            "- … {} more removed lines",
            old_mid.len() - per_side_cap
        ));
    }
    for line in new_mid.iter().take(per_side_cap) {
        out.push(format!("+ {line}"));
    }
    if new_mid.len() > per_side_cap {
        out.push(format!(
            "+ … {} more added lines",
            new_mid.len() - per_side_cap
        ));
    }
    out
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use super::*;
    use std::io::Write;

    fn unique_dir(tag: &str) -> PathBuf {
        use std::sync::atomic::{AtomicU32, Ordering};
        static COUNTER: AtomicU32 = AtomicU32::new(0);
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        let dir =
            std::env::temp_dir().join(format!("sinabro_fileedit_{}_{tag}_{n}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("temp dir");
        dir
    }

    fn write_file(dir: &Path, name: &str, content: &[u8]) -> PathBuf {
        let path = dir.join(name);
        let mut f = std::fs::File::create(&path).expect("create");
        f.write_all(content).expect("write");
        path
    }

    fn test_store(tag: &str) -> (ProposalStore, PathBuf) {
        let dir = unique_dir(tag);
        let store = ProposalStore::with_dir(MemoryCipher::from_key([7u8; 32]), dir.clone());
        (store, dir)
    }

    // ---- 1. wire codec (L3 golden vector — Python-verified 2026-06-11) ----

    /// The exact Python-verified golden vector: 54 bytes, every offset pinned.
    #[test]
    fn wire_golden_vector_byte_exact() {
        let proposal = FileEditProposal {
            target_path: PathBuf::from("notes.txt"),
            read_sha_32: [0xAA; 32],
            content: b"hello\n".to_vec(),
        };
        let wire = proposal.to_wire().expect("encodes");
        assert_eq!(wire.len(), 54, "1+2+9+32+4+6 (Python-verified)");
        let mut expected = Vec::new();
        expected.push(0x01);
        expected.extend_from_slice(&[0x09, 0x00]);
        expected.extend_from_slice(b"notes.txt");
        expected.extend_from_slice(&[0xAA; 32]);
        expected.extend_from_slice(&[0x06, 0x00, 0x00, 0x00]);
        expected.extend_from_slice(b"hello\n");
        assert_eq!(wire, expected, "golden vector byte-exact");
        assert_eq!(
            FileEditProposal::from_wire(&wire).expect("decodes"),
            proposal,
            "round-trip"
        );
    }

    /// Fail-closed decode: truncation at every field, version flip, trailing
    /// garbage, and non-UTF-8 path all reject typed.
    #[test]
    fn wire_decode_fail_closed() {
        let proposal = FileEditProposal {
            target_path: PathBuf::from("a.md"),
            read_sha_32: [1; 32],
            content: b"x".to_vec(),
        };
        let wire = proposal.to_wire().expect("encodes");
        for cut in [0usize, 1, 2, 10, wire.len() - 1] {
            assert_eq!(
                FileEditProposal::from_wire(&wire[..cut]),
                Err(ProposalWireError::Truncated),
                "cut at {cut}"
            );
        }
        let mut flipped = wire.clone();
        flipped[0] = 2;
        assert_eq!(
            FileEditProposal::from_wire(&flipped),
            Err(ProposalWireError::UnknownVersion)
        );
        let mut trailing = wire.clone();
        trailing.push(0);
        assert_eq!(
            FileEditProposal::from_wire(&trailing),
            Err(ProposalWireError::TrailingBytes)
        );
        let mut bad_path = wire;
        bad_path[3] = 0xFF; // first path byte → invalid UTF-8
        assert_eq!(
            FileEditProposal::from_wire(&bad_path),
            Err(ProposalWireError::PathNotUtf8)
        );
    }

    // ---- 2. extraction (closed block grammar) ------------------------------

    /// A well-formed block parses; content keeps inner structure and is
    /// normalized to end with one newline (the documented codec rule).
    #[test]
    fn extract_well_formed_block() {
        let answer = "PROPOSE-EDIT\nTARGET: notes.txt\nCONTENT:\nline one\n\nline three";
        let proposed = extract_proposal(answer)
            .expect("propose-shaped")
            .expect("valid");
        assert_eq!(proposed.target_as_typed, "notes.txt");
        assert_eq!(proposed.content, "line one\n\nline three\n");
        // Already-terminated content gains nothing (no double newline) —
        // lines() drops the trailing terminator, the normalizer re-adds ONE.
        let answer2 = "PROPOSE-EDIT\nTARGET: a\nCONTENT:\nbody\n";
        let p2 = extract_proposal(answer2).expect("shaped").expect("valid");
        assert_eq!(p2.content, "body\n");
        // Empty content is representable (an intentional truncate-to-empty).
        let answer3 = "PROPOSE-EDIT\nTARGET: a\nCONTENT:";
        let p3 = extract_proposal(answer3).expect("shaped").expect("valid");
        assert_eq!(p3.content, "");
    }

    /// Ordinary answers are not propose-shaped (`None`); a claimed block
    /// with a broken shape is `Malformed` (fail-closed, never guessed).
    #[test]
    fn extract_rejects_non_propose_and_malformed() {
        assert_eq!(extract_proposal("The answer is 42."), None);
        assert_eq!(extract_proposal(""), None);
        // Lowercase head is NOT the closed grammar.
        assert_eq!(
            extract_proposal("propose-edit\nTARGET: a\nCONTENT:\nx"),
            None
        );
        for malformed in [
            "PROPOSE-EDIT",                       // nothing after head
            "PROPOSE-EDIT\nCONTENT:\nx",          // no TARGET line
            "PROPOSE-EDIT\nTARGET:\nCONTENT:\nx", // empty target
            "PROPOSE-EDIT\nTARGET: a",            // no CONTENT line
            "PROPOSE-EDIT\nTARGET: a\nBODY:\nx",  // wrong sentinel
        ] {
            assert_eq!(
                extract_proposal(malformed),
                Some(Err(ProposeDeny::Malformed)),
                "{malformed:?}"
            );
        }
    }

    // ---- 2b. mint walls -----------------------------------------------------

    fn verified(path_typed: &str, canonical: &Path, sha: [u8; 32]) -> VerifiedFileRead {
        VerifiedFileRead {
            path_as_typed: path_typed.to_string(),
            canonical_path: canonical.to_path_buf(),
            sha256_32: sha,
        }
    }

    /// IV-W2 — mint binds the EXECUTOR's read record (as-typed match), and a
    /// target never read is a typed deny; walls for size + secret-shaped.
    #[test]
    fn mint_walls_hold() {
        let dir = unique_dir("mint");
        let target = write_file(&dir, "doc.md", b"old body\n");
        let canonical = std::fs::canonicalize(&target).expect("canon");
        let sha = sha256_32(b"old body\n");
        let reads = vec![verified("doc.md", &canonical, sha)];

        let ok = ProposedEdit {
            target_as_typed: "doc.md".to_string(),
            content: "new body\n".to_string(),
        };
        let minted = mint_proposal(&ok, &reads, false).expect("mints");
        assert_eq!(minted.target_path, canonical);
        assert_eq!(minted.read_sha_32, sha);
        assert_eq!(minted.content, b"new body\n");

        // Never-read target ⇒ TargetNotRead (IV-W2).
        let unread = ProposedEdit {
            target_as_typed: "other.md".to_string(),
            content: "x\n".to_string(),
        };
        assert_eq!(
            mint_proposal(&unread, &reads, false),
            Err(ProposeDeny::TargetNotRead)
        );
        // No verified reads at all ⇒ TargetNotRead.
        assert_eq!(
            mint_proposal(&ok, &[], false),
            Err(ProposeDeny::TargetNotRead)
        );
        // Over-cap content ⇒ ContentTooLarge (refuse, never truncate).
        let huge = ProposedEdit {
            target_as_typed: "doc.md".to_string(),
            content: "y".repeat(usize::try_from(MAX_FILE_BYTES).expect("fits") + 1),
        };
        assert_eq!(
            mint_proposal(&huge, &reads, false),
            Err(ProposeDeny::ContentTooLarge)
        );
        // Secret-shaped verdict ⇒ refused outright (IV-W7a).
        assert_eq!(
            mint_proposal(&ok, &reads, true),
            Err(ProposeDeny::SecretShaped)
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    /// E-NEW: `mint_new_file_proposal` — an ABSENT target in a root mints with the absent
    /// baseline; existing target, unconfined parent, and secret content all fail-closed.
    #[test]
    fn mint_new_file_walls_hold() {
        let dir = unique_dir("mintnew");
        let policy = FileReadPolicy::new(std::slice::from_ref(&dir), MAX_FILE_BYTES);
        let canonical_dir = std::fs::canonicalize(&dir).expect("canon");

        // Absent target in a root ⇒ mints with the absent baseline + resolved path.
        let create = ProposedEdit {
            target_as_typed: dir.join("fresh.txt").to_string_lossy().to_string(),
            content: "hello\n".to_string(),
        };
        let minted = mint_new_file_proposal(&create, &policy, false).expect("mints new");
        assert_eq!(minted.read_sha_32, ABSENT_BASELINE_SHA);
        assert_eq!(minted.target_path, canonical_dir.join("fresh.txt"));
        assert_eq!(minted.content, b"hello\n");

        // Existing target ⇒ TargetExists (EDIT it; the create path never overwrites).
        write_file(&dir, "exists.txt", b"x\n");
        let dup = ProposedEdit {
            target_as_typed: dir.join("exists.txt").to_string_lossy().to_string(),
            content: "y\n".to_string(),
        };
        assert_eq!(
            mint_new_file_proposal(&dup, &policy, false),
            Err(ProposeDeny::TargetExists)
        );

        // Parent outside every root ⇒ TargetNotConfined (path-escape refused).
        let outside = unique_dir("mintnew_outside");
        let escape = ProposedEdit {
            target_as_typed: outside.join("escape.txt").to_string_lossy().to_string(),
            content: "z\n".to_string(),
        };
        assert_eq!(
            mint_new_file_proposal(&escape, &policy, false),
            Err(ProposeDeny::TargetNotConfined)
        );

        // Secret-shaped content ⇒ refused outright (IV-W7a).
        assert_eq!(
            mint_new_file_proposal(&create, &policy, true),
            Err(ProposeDeny::SecretShaped)
        );
        std::fs::remove_dir_all(&dir).ok();
        std::fs::remove_dir_all(&outside).ok();
    }

    /// E-NEW: `apply_proposal` with the absent baseline CREATES the target (round-trip),
    /// then a SECOND apply fails closed (`NewFileExists`) — never overwrites.
    #[test]
    fn apply_new_file_creates_then_fails_closed() {
        let dir = unique_dir("applynew");
        let policy = FileReadPolicy::new(std::slice::from_ref(&dir), MAX_FILE_BYTES);
        let canonical_dir = std::fs::canonicalize(&dir).expect("canon");
        let target = canonical_dir.join("created.txt");
        let proposal = FileEditProposal {
            target_path: target.clone(),
            read_sha_32: ABSENT_BASELINE_SHA,
            content: b"created body\n".to_vec(),
        };
        // First apply CREATES the file.
        assert!(!target.exists());
        let receipt = apply_proposal(&policy, &proposal).expect("creates");
        assert_eq!(receipt.target_path, target);
        assert_eq!(receipt.old_sha_32, ABSENT_BASELINE_SHA);
        assert_eq!(receipt.new_sha_32, sha256_32(b"created body\n"));
        assert_eq!(std::fs::read(&target).expect("read"), b"created body\n");
        // Second apply ⇒ NewFileExists (the creation-staleness law: never overwrite).
        assert_eq!(
            apply_proposal(&policy, &proposal),
            Err(ApplyDeny::NewFileExists)
        );
        assert_eq!(
            std::fs::read(&target).expect("read"),
            b"created body\n",
            "second apply must not clobber the existing file"
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    /// Canonical-resolution match: the model may type a relative/aliased
    /// path; if it canonicalises to a verified read, the bind holds.
    #[test]
    fn mint_matches_by_canonical_resolution() {
        let dir = unique_dir("canon");
        let target = write_file(&dir, "note.txt", b"v1\n");
        let canonical = std::fs::canonicalize(&target).expect("canon");
        // The loop recorded a DIFFERENT as-typed spelling.
        let reads = vec![verified(
            "./somewhere/note.txt",
            &canonical,
            sha256_32(b"v1\n"),
        )];
        let proposed = ProposedEdit {
            // The model claims the absolute path; canonicalize matches it.
            target_as_typed: target.to_string_lossy().to_string(),
            content: "v2\n".to_string(),
        };
        let minted = mint_proposal(&proposed, &reads, false).expect("mints by canonical");
        assert_eq!(minted.target_path, canonical);
        std::fs::remove_dir_all(&dir).ok();
    }

    // ---- 3. sealed store ----------------------------------------------------

    /// IV-W6 — save→load round-trip; ciphertext at rest (no plaintext
    /// marker); deterministic name (idempotent re-save); tamper/wrong-key/
    /// version-flip/foreign all SKIP typed.
    #[test]
    fn store_round_trip_sealed_and_fail_closed() {
        let (store, dir) = test_store("rt");
        let proposal = FileEditProposal {
            target_path: PathBuf::from("/tmp/example.md"),
            read_sha_32: [3; 32],
            content: b"proposed-plaintext-marker body\n".to_vec(),
        };
        let name_a = store.save(&proposal).expect("saves");
        let name_b = store.save(&proposal).expect("idempotent");
        assert_eq!(
            name_a, name_b,
            "same proposal ⇒ same content-addressed name"
        );

        let raw = std::fs::read(dir.join(&name_a)).expect("read");
        assert_eq!(&raw[..4], &PROPOSAL_MAGIC);
        assert_eq!(raw[4], PROPOSAL_RECORD_VERSION);
        assert!(
            !raw.windows(26).any(|w| w == b"proposed-plaintext-marker "),
            "plaintext must NOT appear on disk (IV-W6)"
        );

        let pending = store.load_pending();
        assert_eq!(pending.skipped_u32, 0);
        assert_eq!(pending.proposals.len(), 1);
        assert_eq!(pending.proposals[0].proposal, proposal);
        assert_eq!(pending.proposals[0].record_name, name_a);

        // Tamper: flip one byte, rename to its re-hashed name so the DL-3
        // name gate passes — the AEAD tag still rejects it.
        let mut flipped = raw.clone();
        let last = flipped.len() - 1;
        flipped[last] ^= 1;
        std::fs::remove_file(dir.join(&name_a)).expect("rm");
        let renamed = format!("{}.{PROPOSAL_EXT}", hex32(&sha256_32(&flipped)));
        std::fs::write(dir.join(&renamed), &flipped).expect("write tampered");
        let after = store.load_pending();
        assert!(after.proposals.is_empty(), "tampered record never loads");
        assert_eq!(after.skipped_u32, 1);

        // Wrong key ⇒ skip.
        let wrong = ProposalStore::with_dir(MemoryCipher::from_key([8u8; 32]), dir.clone());
        std::fs::remove_file(dir.join(&renamed)).expect("rm");
        store.save(&proposal).expect("re-save");
        let wrong_load = wrong.load_pending();
        assert!(wrong_load.proposals.is_empty());
        assert_eq!(wrong_load.skipped_u32, 1);

        // Foreign garbage ⇒ skip.
        std::fs::write(dir.join(format!("deadbeef.{PROPOSAL_EXT}")), b"junk").expect("write");
        assert_eq!(store.load_pending().skipped_u32, 1, "foreign skipped");
        std::fs::remove_dir_all(&dir).ok();
    }

    /// A memory-store record dropped into the proposals dir (cross-store
    /// masquerade) fails the AAD header bind even before wire decode.
    #[test]
    fn cross_store_record_is_skipped() {
        let (store, dir) = test_store("cross");
        // Forge a record with the MEMORY header sealed under the SAME key
        // but the memory AAD — then give it a proposal-extension hash name.
        let cipher = MemoryCipher::from_key([7u8; 32]);
        let memory_header = *b"MNMC\x02";
        let sealed = cipher
            .seal_with_aad(b"\x01\x00\x00", &memory_header)
            .expect("seal");
        let mut record = memory_header.to_vec();
        record.extend_from_slice(&sealed);
        let name = format!("{}.{PROPOSAL_EXT}", hex32(&sha256_32(&record)));
        std::fs::write(dir.join(name), &record).expect("write");
        let load = store.load_pending();
        assert!(load.proposals.is_empty(), "magic gate skips it");
        assert_eq!(load.skipped_u32, 1);
        std::fs::remove_dir_all(&dir).ok();
    }

    /// IV-W8 — the pending cap denies the 33rd DISTINCT proposal, while an
    /// exact duplicate of a pending one stays idempotent (same name).
    #[test]
    fn pending_cap_denies_beyond_bound() {
        let (store, dir) = test_store("cap");
        let mut last = None;
        for i in 0..MAX_PENDING_PROPOSALS {
            let proposal = FileEditProposal {
                target_path: PathBuf::from(format!("/tmp/f{i}.md")),
                read_sha_32: [9; 32],
                content: format!("body {i}\n").into_bytes(),
            };
            last = Some(store.save(&proposal).expect("under cap"));
        }
        let overflow = FileEditProposal {
            target_path: PathBuf::from("/tmp/overflow.md"),
            read_sha_32: [9; 32],
            content: b"one too many\n".to_vec(),
        };
        assert_eq!(store.save(&overflow), Err(ProposeDeny::StoreFull));
        // An exact duplicate of an EXISTING pending artifact is not a new
        // slot — idempotent re-save still succeeds at the cap.
        let dup = FileEditProposal {
            target_path: PathBuf::from(format!("/tmp/f{}.md", MAX_PENDING_PROPOSALS - 1)),
            read_sha_32: [9; 32],
            content: format!("body {}\n", MAX_PENDING_PROPOSALS - 1).into_bytes(),
        };
        assert_eq!(
            store.save(&dup).expect("idempotent at cap"),
            last.expect("saved")
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    /// Prefix lookup: 16-hex prefix finds the one; unknown ⇒ typed; an
    /// ambiguous prefix ⇒ typed. Ambiguity is GUARANTEED deterministically:
    /// 17 distinct records over a 16-char hex alphabet must share a first
    /// char (pigeonhole), so the (Some, Some) branch always exercises.
    #[test]
    fn find_by_prefix_typed_outcomes() {
        let (store, dir) = test_store("prefix");
        let mut names = Vec::new();
        for i in 0..17u8 {
            names.push(
                store
                    .save(&FileEditProposal {
                        target_path: PathBuf::from(format!("/tmp/p{i}.md")),
                        read_sha_32: [i; 32],
                        content: format!("body {i}\n").into_bytes(),
                    })
                    .expect("save"),
            );
        }
        let first = &names[0];
        let id: String = first.chars().take(PROPOSAL_ID_HEX_CHARS).collect();
        let found = store.find_by_prefix(&id).expect("finds by 16-hex id");
        assert_eq!(&found.record_name, first);
        assert_eq!(
            store.find_by_prefix("ffffffffffffffff0000"),
            Err(ApplyDeny::UnknownId)
        );
        assert_eq!(store.find_by_prefix(""), Err(ApplyDeny::UnknownId));
        // Pigeonhole: some first hex char is shared by ≥ 2 of the 17 names.
        let shared = (0..16u32)
            .map(|d| char::from_digit(d, 16).expect("hex digit"))
            .find(|c| names.iter().filter(|n| n.starts_with(*c)).count() >= 2)
            .expect("pigeonhole guarantees a shared first char");
        assert_eq!(
            store.find_by_prefix(&shared.to_string()),
            Err(ApplyDeny::AmbiguousId)
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    // ---- 4. apply -----------------------------------------------------------

    /// The happy vertical: read walls pass → staleness matches → atomic
    /// replace → mode preserved → verify-after-write → receipt hashes.
    #[test]
    #[cfg(unix)]
    fn apply_replaces_atomically_and_preserves_mode() {
        use std::os::unix::fs::PermissionsExt;
        let dir = unique_dir("apply");
        let target = write_file(&dir, "script.sh", b"#!/bin/sh\necho old\n");
        std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o755)).expect("chmod");
        let canonical = std::fs::canonicalize(&target).expect("canon");
        let policy = FileReadPolicy::new(std::slice::from_ref(&dir), MAX_FILE_BYTES);
        let proposal = FileEditProposal {
            target_path: canonical.clone(),
            read_sha_32: sha256_32(b"#!/bin/sh\necho old\n"),
            content: b"#!/bin/sh\necho new\n".to_vec(),
        };
        let receipt = apply_proposal(&policy, &proposal).expect("applies");
        assert_eq!(receipt.target_path, canonical);
        assert_eq!(receipt.old_sha_32, sha256_32(b"#!/bin/sh\necho old\n"));
        assert_eq!(receipt.new_sha_32, sha256_32(b"#!/bin/sh\necho new\n"));
        assert_eq!(receipt.bytes_written_u64, 19);
        assert_eq!(receipt.old_text.as_deref(), Some("#!/bin/sh\necho old\n"));
        assert_eq!(
            std::fs::read(&canonical).expect("read"),
            b"#!/bin/sh\necho new\n"
        );
        let mode = std::fs::metadata(&canonical)
            .expect("meta")
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o755, "original mode preserved (T12)");
        // No temp litter remains.
        assert!(!dir.join(".script.sh.sinabro.tmp").exists());
        std::fs::remove_dir_all(&dir).ok();
    }

    /// IV-W3 — the staleness lock: ANY current-byte drift after the bound
    /// read refuses the apply and leaves the target untouched.
    #[test]
    fn apply_refuses_stale_target() {
        let dir = unique_dir("stale");
        let target = write_file(&dir, "doc.md", b"as-read body\n");
        let canonical = std::fs::canonicalize(&target).expect("canon");
        let policy = FileReadPolicy::new(std::slice::from_ref(&dir), MAX_FILE_BYTES);
        let proposal = FileEditProposal {
            target_path: canonical.clone(),
            read_sha_32: sha256_32(b"as-read body\n"),
            content: b"replacement\n".to_vec(),
        };
        // The owner (or anything) edits the file AFTER the model read it.
        std::fs::write(&canonical, b"as-read body + newer owner work\n").expect("drift");
        assert_eq!(apply_proposal(&policy, &proposal), Err(ApplyDeny::Stale));
        assert_eq!(
            std::fs::read(&canonical).expect("read"),
            b"as-read body + newer owner work\n",
            "deny path leaves the target untouched"
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    /// IV-W4 — apply-time confinement: outside-root and missing targets are
    /// the lane-A typed denials (cross-cwd fail-closed, TM T11).
    #[test]
    fn apply_re_confines_at_apply_time() {
        let inside = unique_dir("inside");
        let outside = unique_dir("outside");
        let target = write_file(&outside, "afar.md", b"body\n");
        let canonical = std::fs::canonicalize(&target).expect("canon");
        // The apply-time policy confines to `inside` only.
        let policy = FileReadPolicy::new(std::slice::from_ref(&inside), MAX_FILE_BYTES);
        let proposal = FileEditProposal {
            target_path: canonical,
            read_sha_32: sha256_32(b"body\n"),
            content: b"new\n".to_vec(),
        };
        assert_eq!(
            apply_proposal(&policy, &proposal),
            Err(ApplyDeny::TargetWall(FileReadDeny::OutsideAllowedRoots))
        );
        // An EDIT proposal (NON-ZERO baseline) on a missing target ⇒ NotFound. A zero
        // baseline now means CREATE (covered by apply_new_file_creates_then_fails_closed),
        // so an edit-path test must use a real read hash.
        let missing = FileEditProposal {
            target_path: inside.join("never-existed.md"),
            read_sha_32: [7; 32],
            content: b"x\n".to_vec(),
        };
        assert_eq!(
            apply_proposal(&policy, &missing),
            Err(ApplyDeny::TargetWall(FileReadDeny::NotFound))
        );
        std::fs::remove_dir_all(&inside).ok();
        std::fs::remove_dir_all(&outside).ok();
    }

    /// Idempotent identity edit: a proposal whose content EQUALS the current
    /// bytes applies cleanly (old == new hash) — and applies again (T8 note).
    #[test]
    fn apply_identity_edit_is_idempotent() {
        let dir = unique_dir("ident");
        let target = write_file(&dir, "same.md", b"same\n");
        let canonical = std::fs::canonicalize(&target).expect("canon");
        let policy = FileReadPolicy::new(std::slice::from_ref(&dir), MAX_FILE_BYTES);
        let proposal = FileEditProposal {
            target_path: canonical,
            read_sha_32: sha256_32(b"same\n"),
            content: b"same\n".to_vec(),
        };
        let first = apply_proposal(&policy, &proposal).expect("applies");
        assert_eq!(first.old_sha_32, first.new_sha_32);
        let second = apply_proposal(&policy, &proposal).expect("re-applies (identity)");
        assert_eq!(second.new_sha_32, first.new_sha_32);
        std::fs::remove_dir_all(&dir).ok();
    }

    // ---- 4b. owner save (P2-S5) ---------------------------------------------

    /// The happy vertical: lane-A confinement passes → base-sha matches → atomic
    /// mode-preserving replace → verify-after-write → metadata receipt.
    #[test]
    fn owner_save_replaces_when_base_sha_matches() {
        let dir = unique_dir("ownersave");
        let target = write_file(&dir, "note.txt", b"old owner text\n");
        let canonical = std::fs::canonicalize(&target).expect("canon");
        let policy = FileReadPolicy::new(std::slice::from_ref(&dir), MAX_FILE_BYTES);
        let base = hex32(&sha256_32(b"old owner text\n"));
        let receipt =
            owner_save_file(&policy, &canonical, b"new owner text\n", &base).expect("saves");
        assert_eq!(receipt.old_sha_32, sha256_32(b"old owner text\n"));
        assert_eq!(receipt.new_sha_32, sha256_32(b"new owner text\n"));
        assert_eq!(receipt.bytes_written_u64, 15);
        assert_eq!(
            std::fs::read(&canonical).expect("read"),
            b"new owner text\n"
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    /// IV-W3 — the staleness lock: a file changed since the editor read it refuses the
    /// save and leaves the target untouched (no blind overwrite of newer work).
    #[test]
    fn owner_save_refuses_stale_target() {
        let dir = unique_dir("ownersave-stale");
        let target = write_file(&dir, "note.txt", b"as-read\n");
        let canonical = std::fs::canonicalize(&target).expect("canon");
        let policy = FileReadPolicy::new(std::slice::from_ref(&dir), MAX_FILE_BYTES);
        let base = hex32(&sha256_32(b"as-read\n"));
        std::fs::write(&canonical, b"changed on disk\n").expect("drift");
        assert_eq!(
            owner_save_file(&policy, &canonical, b"my edit\n", &base),
            Err(OwnerSaveDeny::Stale)
        );
        assert_eq!(
            std::fs::read(&canonical).expect("read"),
            b"changed on disk\n",
            "deny path leaves the target untouched"
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    /// A malformed staleness baseline is rejected up front (fail-closed; no write).
    #[test]
    fn owner_save_rejects_malformed_base_sha() {
        let dir = unique_dir("ownersave-bad");
        let target = write_file(&dir, "note.txt", b"x\n");
        let canonical = std::fs::canonicalize(&target).expect("canon");
        let policy = FileReadPolicy::new(std::slice::from_ref(&dir), MAX_FILE_BYTES);
        assert_eq!(
            owner_save_file(&policy, &canonical, b"y\n", "not-a-64-hex-baseline"),
            Err(OwnerSaveDeny::BaseShaMalformed)
        );
        assert_eq!(
            std::fs::read(&canonical).expect("read"),
            b"x\n",
            "no write on reject"
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    // ---- 5. diff render -----------------------------------------------------

    /// Deterministic trim diff: unchanged prefix/suffix counted, the changed
    /// middle rendered `-`/`+`, caps marked explicitly.
    #[test]
    fn diff_renders_bounded_middle() {
        let old_text = "a\nb\nc\nd\n";
        let new_text = "a\nB2\nc\nd\n";
        let diff = render_line_diff(old_text, new_text);
        assert_eq!(
            diff,
            vec![
                "diff: -1 +1 lines (context: 1 prefix / 2 suffix unchanged)".to_string(),
                "- b".to_string(),
                "+ B2".to_string(),
            ]
        );
        // Identity ⇒ zero-line diff, full context.
        let same = render_line_diff("x\ny\n", "x\ny\n");
        assert_eq!(
            same[0],
            "diff: -0 +0 lines (context: 2 prefix / 0 suffix unchanged)"
        );
        assert_eq!(same.len(), 1);
        // Over-cap middles get explicit truncation markers.
        let many_old: String = (0..60).map(|i| format!("old{i}\n")).collect();
        let many_new: String = (0..60).map(|i| format!("new{i}\n")).collect();
        let big = render_line_diff(&many_old, &many_new);
        assert!(big.iter().any(|l| l.contains("more removed lines")));
        assert!(big.iter().any(|l| l.contains("more added lines")));
        assert!(big.len() <= 3 + DIFF_RENDER_LINE_CAP, "render bounded");
    }

    /// Class labels stay stable (diagnostic envelopes).
    #[test]
    fn class_labels_stable() {
        assert_eq!(
            ProposeDeny::TargetNotRead.class_label(),
            "file_edit.propose.target_not_read"
        );
        assert_eq!(
            ProposeDeny::SecretShaped.class_label(),
            "file_edit.propose.secret_shaped"
        );
        assert_eq!(
            ApplyDeny::Stale.class_label(),
            "file_edit.apply.stale_target"
        );
        assert_eq!(
            ApplyDeny::TargetWall(FileReadDeny::NotFound).class_label(),
            "file_edit.apply.target_wall"
        );
    }
}
