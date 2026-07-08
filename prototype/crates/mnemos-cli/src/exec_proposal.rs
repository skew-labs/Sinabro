//! Exec proposals — the model PROPOSES a command; the owner alone executes.
//!
//! THE SECOND AGENT-PROPOSED SIDE EFFECT (after `file_edit`'s edit proposals).
//! The split of authority is the whole design: the MODEL only
//! PROPOSES (a typed, sealed, INERT artifact extracted from its final answer —
//! the loop grammar is byte-unchanged and has NO exec tool; `TOOL: exec` stays
//! denied); the OWNER alone authorizes execution (a terminal typed-phrase
//! ceremony, a telegram approval, or a bounded armed `MutateGrant`). A proposal
//! that no one authorizes stays inert FOREVER.
//!
//! # Why an exec proposal mirrors a file-edit proposal (and is simpler)
//!
//! An edit carries `{target, read_sha, content}` and applies through a staleness
//! lock. An exec carries ONLY `{command}` — it runs in the kernel sandbox
//! (`run_in_sandbox_default(LocalWrite, …)`: network kernel-DENIED, env-scrubbed,
//! timeout + byte-cap), so there is no target, no staleness, no
//! atomic-replace. It REUSES the proven `file_edit` discipline: AEAD-sealed
//! ( [`MemoryCipher`], content-derived nonce ⇒ idempotent re-propose),
//! content-addressed (`hex(sha256(record)).xep`), bounded pending set, a
//! DIFFERENT magic/extension/subdir so an exec proposal can never masquerade as
//! an edit proposal or a memory record (the AAD header differs ⇒ even a renamed
//! cross-store file fails the tag).
//!
//! The SandboxTier is NOT carried here: it is fixed by the
//! executor from the tier ladder, NEVER from model-supplied bytes. This module
//! owns PROPOSE + the sealed inert STORE; the EXECUTE path (the
//! `MutateCapability`-gated sandbox run) is wired in dispatch — there is no
//! execute function here, so a proposal cannot run by reaching into this module.
//!
//! Redaction of every render is the DISPATCH layer's job; this module REFUSES a
//! secret-shaped proposed command at mint time ( an unreviewable command
//! must not exist), via the caller-supplied redaction verdict (kept IO-pure on
//! the redaction axis, same seam as `file_edit::mint_proposal`).

use std::path::{Path, PathBuf};

use crate::exec_local::EXEC_MAX_LINE_BYTES;
use crate::memory_store::{CipherError, MemoryCipher, atomic_write, data_dir};
use crate::{hex32, sha256_32};

/// Exec-proposal record magic (4 bytes) — `MNXP` = MNemos eXec Proposal.
/// DISTINCT from `file_edit`'s `MNFP` so the two stores never cross (the magic
/// is AAD-bound ⇒ a swapped file fails the AEAD tag).
pub const EXEC_PROPOSAL_MAGIC: [u8; 4] = *b"MNXP";

/// On-disk record version (the header byte; AAD-bound).
pub const EXEC_PROPOSAL_RECORD_VERSION: u8 = 1;

/// Sealed-plaintext wire version (the first byte INSIDE the seal). v1 = one
/// single-command exec; a multi-command batch extends this byte.
pub const EXEC_PROPOSAL_WIRE_VERSION: u8 = 1;

/// Fixed record header width: magic(4) + version(1).
pub const EXEC_PROPOSAL_HEADER_BYTES: usize = 5;

/// On-disk exec-proposal file extension (DISTINCT from `fep`).
pub const EXEC_PROPOSAL_EXT: &str = "xep";

/// Exec-proposals subdirectory under the data dir (`$HOME/.mnemos`). DISTINCT
/// from `file_edit`'s `proposals/`.
pub const EXEC_PROPOSALS_SUBDIR: &str = "exec_proposals";

/// Pending exec-proposal cap ( analog): a save beyond this is a typed
/// deny — the pending set stays a bounded, reviewable, actionable list.
pub const MAX_PENDING_EXEC_PROPOSALS: usize = 32;

/// The id the owner types at execute: the first 16 hex chars of the record name
/// (prefix-matched; ambiguity is a typed deny). Mirrors
/// [`crate::file_edit::PROPOSAL_ID_HEX_CHARS`].
pub const EXEC_PROPOSAL_ID_HEX_CHARS: usize = 16;

// ===========================================================================
// 1. The proposal value + canonical wire codec (golden-vector pinned)
// ===========================================================================

/// One single-command exec proposal: run `command` in the kernel sandbox. The
/// command is UTF-8 by construction (it came from the model's answer text).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExecProposal {
    /// The proposed command line, argv-split + run under Seatbelt at the
    /// executor's fixed tier (LocalWrite; network kernel-DENIED). The exact
    /// string the owner reviews before authorizing.
    pub command: String,
}

/// Typed wire-codec failures (decode is fail-closed; no partial trust).
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
#[non_exhaustive]
pub enum ExecWireError {
    /// The wire bytes were shorter than a field demanded.
    Truncated,
    /// The wire version byte is not [`EXEC_PROPOSAL_WIRE_VERSION`].
    UnknownVersion,
    /// The command bytes were not valid UTF-8.
    CommandNotUtf8,
    /// Trailing garbage followed the last field.
    TrailingBytes,
}

impl ExecProposal {
    /// Canonical wire encoding: `ver(1) || cmd_len(u32 LE) || cmd`. The command
    /// is capped far below `u32::MAX` by the mint wall, but the encoder still
    /// refuses (`None`) fail-closed on an impossible length.
    #[must_use]
    pub fn to_wire(&self) -> Option<Vec<u8>> {
        let cmd_bytes = self.command.as_bytes();
        let cmd_len = u32::try_from(cmd_bytes.len()).ok()?;
        let mut wire = Vec::with_capacity(1 + 4 + cmd_bytes.len());
        wire.push(EXEC_PROPOSAL_WIRE_VERSION);
        wire.extend_from_slice(&cmd_len.to_le_bytes());
        wire.extend_from_slice(cmd_bytes);
        Some(wire)
    }

    /// Fail-closed wire decode — every length is checked before it is consumed;
    /// trailing bytes reject (a record is exactly one proposal).
    pub fn from_wire(wire: &[u8]) -> Result<Self, ExecWireError> {
        let mut at = 0usize;
        let take = |at: &mut usize, n: usize| -> Result<&[u8], ExecWireError> {
            let end = at.checked_add(n).ok_or(ExecWireError::Truncated)?;
            if end > wire.len() {
                return Err(ExecWireError::Truncated);
            }
            let slice = &wire[*at..end];
            *at = end;
            Ok(slice)
        };
        let version = take(&mut at, 1)?[0];
        if version != EXEC_PROPOSAL_WIRE_VERSION {
            return Err(ExecWireError::UnknownVersion);
        }
        let mut cmd_len_bytes = [0u8; 4];
        cmd_len_bytes.copy_from_slice(take(&mut at, 4)?);
        let cmd_len = usize::try_from(u32::from_le_bytes(cmd_len_bytes))
            .map_err(|_| ExecWireError::Truncated)?;
        let cmd_bytes = take(&mut at, cmd_len)?;
        let command = core::str::from_utf8(cmd_bytes).map_err(|_| ExecWireError::CommandNotUtf8)?;
        if at != wire.len() {
            return Err(ExecWireError::TrailingBytes);
        }
        Ok(Self {
            command: command.to_string(),
        })
    }
}

// ===========================================================================
// 2. PROPOSE — answer-block extraction + mint walls
// ===========================================================================

/// The parsed-but-unminted shape of a `PROPOSE-EXEC` answer block.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProposedExec {
    /// The model's claimed command (the rest of the `COMMAND:` line, trimmed).
    pub command_as_typed: String,
}

/// Typed propose denials (data-free; rendered as honest reasons).
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
#[non_exhaustive]
pub enum ExecProposeDeny {
    /// The block had `PROPOSE-EXEC` but not the closed grammar shape.
    Malformed,
    /// The command was empty after trimming.
    EmptyCommand,
    /// The command exceeds [`EXEC_MAX_LINE_BYTES`] (it could never run in the
    /// sandbox anyway — refuse, never truncate).
    CommandTooLarge,
    /// The proposed command is secret-shaped ( refused outright; an
    /// unreviewable command must not exist).
    SecretShaped,
    /// The proposed command's intent is a chain WRITE / signing / fund-moving
    /// operation ( structurally refused at PROPOSE time, so a chain-write
    /// proposal is never minted/sealed and can never reach the executor or the
    /// armed auto-run). Web3 READS may still be proposed. Defense-in-depth on top
    /// of the load-bearing barriers (the sandbox is network-DENIED, no wallet key
    /// exists, `CustodyCapability` is uninhabited, and allowlists no chain
    /// host); chain-WRITE/sign/funds are HARD-LOCKED ALWAYS.
    ChainWriteIntent,
    /// The proposed command's intent is a git FORCE-PUSH (history rewrite to a remote)
    /// An IRREVERSIBLE escalation ( ⑳, the escalation family sibling of
    /// [`Self::ChainWriteIntent`]). Structurally refused at PROPOSE time, so a
    /// force-push proposal is never minted/sealed and can never reach the executor or
    /// the armed auto-run (incl. a bold session). Defense-in-depth on top of the
    /// load-bearing barrier (the exec sandbox is network-DENIED ⇒ no remote to push to).
    ForcePushIntent,
    /// The proposed command's intent is a private-KEY EXPORT / keygen — a custody-
    /// adjacent escalation ( ⑳). Structurally refused at PROPOSE time, so a
    /// key-export proposal is never minted/sealed (incl. a bold session). Defense-in-
    /// depth on top of the load-bearing barrier (the exec sandbox is network-DENIED ⇒ no
    /// exfil; `CustodyCapability` is uninhabited; key material stays HARD-LOCKED).
    KeyExportIntent,
    /// The pending store already holds [`MAX_PENDING_EXEC_PROPOSALS`].
    StoreFull,
    /// The proposal could not be encoded/sealed/written (io class).
    StoreFailed,
}

impl ExecProposeDeny {
    /// Stable, allow-listed `class_label` (namespaced `exec_proposal.propose.*`).
    #[inline]
    #[must_use]
    pub const fn class_label(self) -> &'static str {
        match self {
            Self::Malformed => "exec_proposal.propose.malformed",
            Self::EmptyCommand => "exec_proposal.propose.empty_command",
            Self::CommandTooLarge => "exec_proposal.propose.command_too_large",
            Self::SecretShaped => "exec_proposal.propose.secret_shaped",
            Self::ChainWriteIntent => "exec_proposal.propose.chain_write_intent",
            Self::ForcePushIntent => "exec_proposal.propose.force_push_intent",
            Self::KeyExportIntent => "exec_proposal.propose.key_export_intent",
            Self::StoreFull => "exec_proposal.propose.store_full",
            Self::StoreFailed => "exec_proposal.propose.store_failed",
        }
    }
}

/// The first line of an exec-propose answer (exact, case-sensitive — a closed
/// grammar, the same discipline as the loop's `TOOL:` lines and `PROPOSE-EDIT`).
const PROPOSE_EXEC_HEAD: &str = "PROPOSE-EXEC";
/// The command line prefix (the command is INLINE, one logical line).
const PROPOSE_COMMAND_PREFIX: &str = "COMMAND:";

/// Parse a final answer for the closed `PROPOSE-EXEC` block.
///
/// * `None` — the answer is not exec-propose-shaped at all (an ordinary answer,
///   or a `PROPOSE-EDIT` block handled by `file_edit`).
/// * `Some(Err(Malformed))` — it claimed `PROPOSE-EXEC` but broke the shape
///   (fail-closed: a half-proposal is never guessed into one).
/// * `Some(Ok(_))` — a structurally valid proposal (mint walls still apply).
///
/// Grammar (closed):
/// ```text
/// PROPOSE-EXEC
/// COMMAND: <the single command line>
/// ```
#[must_use]
pub fn extract_exec_proposal(answer: &str) -> Option<Result<ProposedExec, ExecProposeDeny>> {
    let mut lines = answer.lines();
    let head = lines.next()?.trim();
    if head != PROPOSE_EXEC_HEAD {
        return None;
    }
    let Some(command_line) = lines.next() else {
        return Some(Err(ExecProposeDeny::Malformed));
    };
    let Some(command_raw) = command_line.trim().strip_prefix(PROPOSE_COMMAND_PREFIX) else {
        return Some(Err(ExecProposeDeny::Malformed));
    };
    let command_as_typed = command_raw.trim();
    if command_as_typed.is_empty() {
        return Some(Err(ExecProposeDeny::EmptyCommand));
    }
    Some(Ok(ProposedExec {
        command_as_typed: command_as_typed.to_string(),
    }))
}

/// The closed denylist of chain-WRITE / signing / fund-moving INTENT tokens
/// . A command is chain-write-intent iff ANY of its tokens (split on
/// whitespace / symbols / camelCase, lowercased) EXACTLY equals one of these.
/// Exact-token match is deliberate: the canonical READ method
/// `getSignatureStatuses` tokenizes to `["get","signature","statuses"]` — none
/// equals `"sign"` — so a read is not refused, while `signTransaction`
/// (`["sign","transaction"]`) and `sendTransaction` (`["send","transaction"]`)
/// are. Same word-boundary discipline as the E6 `kill`-vs-`skill` fix.
///
/// CONSERVATIVE deny (it over-refuses borderline commands) and DEFENSE-IN-DEPTH,
/// NOT the load-bearing barrier: a write that slipped past this still could not
/// reach a chain — the exec sandbox is network-DENIED (no socket ⇒ no RPC), no
/// wallet key exists (env-scrubbed), `CustodyCapability` is uninhabited, and
/// allowlists no chain host. The owner-direct un-sandboxed exec path is
/// unaffected; only the AGENT's auto-proposal is narrowed to reads.
const CHAIN_WRITE_INTENT_TOKENS: &[&str] = &[
    "send", "sign", "transfer", "airdrop", "withdraw", "deposit", "stake", "unstake", "delegate",
    "swap", "mint", "burn", "approve", "keypair",
];

/// Split `command` on non-alphanumeric AND camelCase boundaries, lowercasing each
/// token. `eth_sendRawTransaction` -> `[eth, send, raw, transaction]`;
/// `getSignatureStatuses` -> `[get, signature, statuses]`.
fn intent_tokens(command: &str) -> Vec<String> {
    let mut tokens: Vec<String> = Vec::new();
    let mut cur = String::new();
    // True after a lowercase letter or a digit — an uppercase that follows one is
    // a camelCase boundary (start of a new token).
    let mut prev_lower_or_digit = false;
    for ch in command.chars() {
        if ch.is_ascii_alphanumeric() {
            if ch.is_ascii_uppercase() && prev_lower_or_digit && !cur.is_empty() {
                tokens.push(core::mem::take(&mut cur));
            }
            cur.push(ch.to_ascii_lowercase());
            prev_lower_or_digit = !ch.is_ascii_uppercase();
        } else {
            if !cur.is_empty() {
                tokens.push(core::mem::take(&mut cur));
            }
            prev_lower_or_digit = false;
        }
    }
    if !cur.is_empty() {
        tokens.push(cur);
    }
    tokens
}

/// Whether `command`'s intent is a chain WRITE / signing / fund-moving operation
/// `true` iff any token matches [`CHAIN_WRITE_INTENT_TOKENS`]. Used by
/// [`mint_exec_proposal`] to structurally refuse a chain-write proposal at mint.
#[must_use]
pub fn command_is_chain_write_intent(command: &str) -> bool {
    intent_tokens(command)
        .iter()
        .any(|tok| CHAIN_WRITE_INTENT_TOKENS.contains(&tok.as_str()))
}

/// Private key-material tokens for the KEY-EXPORT escalation ( ⑳): an
/// `export` co-occurring with one of these is a private-key export. `export PATH=…` /
/// `gpg --export > pub.asc` (a PUBLIC key) carry no key-material token, so they pass.
const KEY_MATERIAL_TOKENS: &[&str] = &[
    "key", "keys", "keychain", "secret", "private", "privkey", "seed", "mnemonic",
];

/// Whether `command`'s intent is a git FORCE-PUSH (history rewrite to a remote) — an
/// IRREVERSIBLE escalation ( ⑳). STRUCTURAL co-presence (NOT a flat
/// `intent_tokens` any-match, which cannot express it): the command must invoke `git`
/// AND `push` (tokens) AND carry a force flag (`--force` / `--force-with-lease` /
/// `--mirror`, or a standalone `-f` argument). A regular `git push origin main` is NOT
/// force-push (it may be proposed; it would still fail in the network-DENIED sandbox);
/// `git commit -m '…force…'` and `cp -f push.txt` are NOT caught (Python-verified,
/// `RUST_FAITHFUL_ALL_CORRECT=True`). Used by [`mint_exec_proposal`] to refuse a
/// force-push proposal at mint, so it is un-armable in EVERY mode incl bold.
#[must_use]
pub fn command_is_force_push_intent(command: &str) -> bool {
    let tokens = intent_tokens(command);
    let has_git = tokens.iter().any(|t| t == "git");
    let has_push = tokens.iter().any(|t| t == "push");
    if !(has_git && has_push) {
        return false;
    }
    let lc = command.to_ascii_lowercase();
    lc.contains("--force")
        || lc.contains("--mirror")
        || command.split_whitespace().any(|arg| arg == "-f")
}

/// Whether `command`'s intent is a private-KEY EXPORT / keygen — a custody-adjacent
/// escalation ( ⑳). `true` iff a `keygen` / `keytool` token is present
/// (e.g. `ssh-keygen`, `sui keytool export`), OR an `export` token co-occurs with a
/// [`KEY_MATERIAL_TOKENS`] token (e.g. `gpg --export-secret-keys`, `security export -k
/// login.keychain`). A PUBLIC-key `gpg --export > pub.asc` and a shell `export PATH=…`
/// carry no key-material token, so they pass (Python-verified). Used by
/// [`mint_exec_proposal`] to refuse a key-export proposal at mint.
#[must_use]
pub fn command_is_key_export_intent(command: &str) -> bool {
    let tokens = intent_tokens(command);
    if tokens.iter().any(|t| t == "keygen" || t == "keytool") {
        return true;
    }
    let has_export = tokens.iter().any(|t| t == "export");
    let has_key_material = tokens
        .iter()
        .any(|t| KEY_MATERIAL_TOKENS.contains(&t.as_str()));
    has_export && has_key_material
}

/// Mint an [`ExecProposal`] from a parsed block. `command_is_secret_shaped` is
/// the caller's canonical redaction verdict over the command — a bool so
/// this module stays decoupled from the redaction types (same seam as
/// [`crate::file_edit::mint_proposal`]).
pub fn mint_exec_proposal(
    proposed: &ProposedExec,
    command_is_secret_shaped: bool,
) -> Result<ExecProposal, ExecProposeDeny> {
    let command = proposed.command_as_typed.trim();
    if command.is_empty() {
        return Err(ExecProposeDeny::EmptyCommand);
    }
    // Bounded — the command must fit the sandbox line cap (refuse, never
    // truncate); a longer command could never run.
    if command.len() > EXEC_MAX_LINE_BYTES {
        return Err(ExecProposeDeny::CommandTooLarge);
    }
    // A chain-WRITE / signing / fund-moving command is structurally
    // refused at PROPOSE time, so a chain-write proposal is never minted or
    // sealed (it can never reach the executor or the armed auto-run). Web3 READS
    // may still be proposed. Defense-in-depth atop the network-DENIED sandbox,
    // the absent wallet key, the uninhabited `CustodyCapability`, and;
    // chain-WRITE/sign/funds stay HARD-LOCKED ALWAYS.
    if command_is_chain_write_intent(command) {
        return Err(ExecProposeDeny::ChainWriteIntent);
    }
    // / ⑳ — the escalation family (force-push / key-export) is refused at
    // PROPOSE time too, so the proposal is never minted/sealed and can never reach the
    // executor or the armed auto-run (incl. a BOLD session — un-armable in EVERY mode).
    // Defense-in-depth atop the network-DENIED sandbox + uninhabited `CustodyCapability`.
    if command_is_force_push_intent(command) {
        return Err(ExecProposeDeny::ForcePushIntent);
    }
    if command_is_key_export_intent(command) {
        return Err(ExecProposeDeny::KeyExportIntent);
    }
    // A secret-shaped command is refused outright (an unreviewable
    // command must not exist; fail-closed beats withhold-and-ask).
    if command_is_secret_shaped {
        return Err(ExecProposeDeny::SecretShaped);
    }
    Ok(ExecProposal {
        command: command.to_string(),
    })
}

// ===========================================================================
// 3. The sealed, content-addressed, bounded exec-proposal store
// ===========================================================================

/// One pending exec proposal as listed/loaded.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PendingExecProposal {
    /// The on-disk record filename (`<64-hex>.xep`).
    pub record_name: String,
    /// The decoded proposal.
    pub proposal: ExecProposal,
}

/// Outcome of a pending-store load: decoded proposals (record-name-sorted,
/// deterministic) + an honest skip count.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ExecPendingLoad {
    /// Decoded proposals, sorted ascending by record name.
    pub proposals: Vec<PendingExecProposal>,
    /// Records skipped (name/header/wire failures) — never loaded as truth.
    pub skipped_u32: u32,
}

/// Typed lookup denials for [`ExecProposalStore::find_by_prefix`].
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
#[non_exhaustive]
pub enum ExecLookupDeny {
    /// No pending exec proposal matched the supplied id prefix.
    UnknownId,
    /// More than one pending exec proposal matched the id prefix.
    AmbiguousId,
}

impl ExecLookupDeny {
    /// Stable, allow-listed `class_label`.
    #[inline]
    #[must_use]
    pub const fn class_label(self) -> &'static str {
        match self {
            Self::UnknownId => "exec_proposal.lookup.unknown_id",
            Self::AmbiguousId => "exec_proposal.lookup.ambiguous_id",
        }
    }
}

/// The sealed exec-proposal store. Same key + cipher + atomic-write discipline as
/// the memory store and the `file_edit` proposal store; a DIFFERENT magic /
/// extension / subdir so an exec proposal can never masquerade as an edit
/// proposal or a memory record.
#[derive(Clone, Debug)]
pub struct ExecProposalStore {
    cipher: MemoryCipher,
    store_dir: PathBuf,
}

impl ExecProposalStore {
    /// Open the local store (`$HOME/.mnemos/exec_proposals/`), creating the dir.
    /// Fail-closed on key/io trouble.
    pub fn open_local() -> Result<Self, ExecProposeDeny> {
        let cipher = MemoryCipher::open_local().map_err(|_| ExecProposeDeny::StoreFailed)?;
        let store_dir = data_dir()
            .map_err(|_| ExecProposeDeny::StoreFailed)?
            .join(EXEC_PROPOSALS_SUBDIR);
        std::fs::create_dir_all(&store_dir).map_err(|_| ExecProposeDeny::StoreFailed)?;
        Ok(Self { cipher, store_dir })
    }

    /// Construct over an explicit cipher + dir (tests / non-default roots).
    #[must_use]
    pub fn with_dir(cipher: MemoryCipher, store_dir: PathBuf) -> Self {
        Self { cipher, store_dir }
    }

    /// The on-disk record header — also the AEAD associated data.
    const fn record_header() -> [u8; EXEC_PROPOSAL_HEADER_BYTES] {
        [
            EXEC_PROPOSAL_MAGIC[0],
            EXEC_PROPOSAL_MAGIC[1],
            EXEC_PROPOSAL_MAGIC[2],
            EXEC_PROPOSAL_MAGIC[3],
            EXEC_PROPOSAL_RECORD_VERSION,
        ]
    }

    /// The canonical record bytes: `magic|version|sealed`,
    /// `sealed = AEAD(wire, aad = header)`. Deterministic (content-derived
    /// nonce) ⇒ the same proposal always yields the same content-addressed name
    /// (idempotent re-propose).
    fn record_bytes(&self, proposal: &ExecProposal) -> Result<Vec<u8>, ExecProposeDeny> {
        let wire = proposal.to_wire().ok_or(ExecProposeDeny::StoreFailed)?;
        let header = Self::record_header();
        let sealed = self
            .cipher
            .seal_with_aad(&wire, &header)
            .map_err(|_: CipherError| ExecProposeDeny::StoreFailed)?;
        let mut record = Vec::with_capacity(EXEC_PROPOSAL_HEADER_BYTES + sealed.len());
        record.extend_from_slice(&header);
        record.extend_from_slice(&sealed);
        Ok(record)
    }

    /// The content-addressed filename (`hex(sha256(record)).xep`).
    fn record_name(record: &[u8]) -> String {
        format!("{}.{EXEC_PROPOSAL_EXT}", hex32(&sha256_32(record)))
    }

    /// Persist one proposal: encode → seal → bounded-pending check → atomic
    /// write. Returns the record name (its 16-hex prefix is the owner-typed
    /// execute id). Idempotent for an identical proposal (same bytes, same name).
    pub fn save(&self, proposal: &ExecProposal) -> Result<String, ExecProposeDeny> {
        let record = self.record_bytes(proposal)?;
        let name = Self::record_name(&record);
        let path = self.store_dir.join(&name);
        if !path.exists() {
            let pending = self.load_pending();
            if pending.proposals.len() >= MAX_PENDING_EXEC_PROPOSALS {
                return Err(ExecProposeDeny::StoreFull);
            }
        }
        atomic_write(&path, &record).map_err(|_| ExecProposeDeny::StoreFailed)?;
        Ok(name)
    }

    /// Load every readable pending proposal, fail-closed per record (a bad
    /// record is SKIPPED + counted, never trusted), record-name-sorted.
    #[must_use]
    pub fn load_pending(&self) -> ExecPendingLoad {
        let mut outcome = ExecPendingLoad::default();
        let entries = match std::fs::read_dir(&self.store_dir) {
            Ok(entries) => entries,
            Err(_) => return outcome,
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.extension().and_then(|e| e.to_str()) != Some(EXEC_PROPOSAL_EXT) {
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
    /// name-hash → header → AEAD(tag + header as AAD) → fail-closed wire decode.
    fn load_one(&self, path: &Path) -> Option<PendingExecProposal> {
        let bytes = std::fs::read(path).ok()?;
        let expected = Self::record_name(&bytes);
        if path.file_name().and_then(|n| n.to_str()) != Some(expected.as_str()) {
            return None;
        }
        if bytes.len() < EXEC_PROPOSAL_HEADER_BYTES
            || bytes[..4] != EXEC_PROPOSAL_MAGIC
            || bytes[4] != EXEC_PROPOSAL_RECORD_VERSION
        {
            return None;
        }
        let wire = self
            .cipher
            .open_with_aad(
                &bytes[EXEC_PROPOSAL_HEADER_BYTES..],
                &bytes[..EXEC_PROPOSAL_HEADER_BYTES],
            )
            .ok()?;
        let proposal = ExecProposal::from_wire(&wire).ok()?;
        Some(PendingExecProposal {
            record_name: expected,
            proposal,
        })
    }

    /// Find ONE pending proposal by id prefix. Zero matches ⇒ `UnknownId`; two
    /// or more ⇒ `AmbiguousId` (typed, fail-closed — never "the first one").
    pub fn find_by_prefix(&self, id_prefix: &str) -> Result<PendingExecProposal, ExecLookupDeny> {
        let prefix = id_prefix.trim().to_ascii_lowercase();
        if prefix.is_empty() {
            return Err(ExecLookupDeny::UnknownId);
        }
        let pending = self.load_pending();
        let mut matches = pending
            .proposals
            .into_iter()
            .filter(|p| p.record_name.starts_with(&prefix));
        match (matches.next(), matches.next()) {
            (None, _) => Err(ExecLookupDeny::UnknownId),
            (Some(one), None) => Ok(one),
            (Some(_), Some(_)) => Err(ExecLookupDeny::AmbiguousId),
        }
    }

    /// Remove a consumed artifact (execute success path). A failed removal is
    /// reported by the caller, never silent.
    pub fn remove(&self, record_name: &str) -> std::io::Result<()> {
        std::fs::remove_file(self.store_dir.join(record_name))
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use super::*;

    // ---- extract (closed grammar) -----------------------------------------

    #[test]
    fn extract_non_exec_answer_is_none() {
        assert!(extract_exec_proposal("just a normal answer").is_none());
        // A PROPOSE-EDIT block is NOT an exec block (file_edit owns it).
        assert!(extract_exec_proposal("PROPOSE-EDIT\nTARGET: x\nCONTENT:\nhi").is_none());
    }

    #[test]
    fn extract_valid_exec_block() {
        let parsed = extract_exec_proposal("PROPOSE-EXEC\nCOMMAND: cargo test --workspace");
        let Some(Ok(p)) = parsed else {
            panic!("expected a valid proposed exec");
        };
        assert_eq!(p.command_as_typed, "cargo test --workspace");
    }

    #[test]
    fn extract_malformed_and_empty_are_typed_denials() {
        // claims PROPOSE-EXEC but no COMMAND line
        assert_eq!(
            extract_exec_proposal("PROPOSE-EXEC"),
            Some(Err(ExecProposeDeny::Malformed))
        );
        // COMMAND prefix present but empty value
        assert_eq!(
            extract_exec_proposal("PROPOSE-EXEC\nCOMMAND:   "),
            Some(Err(ExecProposeDeny::EmptyCommand))
        );
        // wrong second line
        assert_eq!(
            extract_exec_proposal("PROPOSE-EXEC\nRUN: x"),
            Some(Err(ExecProposeDeny::Malformed))
        );
    }

    // ---- mint walls -------------------------------------------------------

    fn proposed(cmd: &str) -> ProposedExec {
        ProposedExec {
            command_as_typed: cmd.to_string(),
        }
    }

    #[test]
    fn mint_accepts_a_benign_command() {
        let p = mint_exec_proposal(&proposed("/bin/echo hi"), false).expect("mint");
        assert_eq!(p.command, "/bin/echo hi");
    }

    #[test]
    fn mint_refuses_secret_shaped_command() {
        assert_eq!(
            mint_exec_proposal(&proposed("curl -H 'authorization: sk-live-xxx'"), true),
            Err(ExecProposeDeny::SecretShaped)
        );
    }

    #[test]
    fn mint_refuses_oversized_and_empty() {
        let long = "x".repeat(EXEC_MAX_LINE_BYTES + 1);
        assert_eq!(
            mint_exec_proposal(&proposed(&long), false),
            Err(ExecProposeDeny::CommandTooLarge)
        );
        assert_eq!(
            mint_exec_proposal(&proposed("   "), false),
            Err(ExecProposeDeny::EmptyCommand)
        );
    }

    // ---- chain-write intent structurally refused at propose time --

    #[test]
    fn chain_write_intent_refuses_writes_allows_reads() {
        // WRITE / signing / fund-moving intents are chain-write-intent (refused).
        for w in [
            "solana transfer 5 SoLAddr",
            "cast send 0xabc --value 1ether",
            "curl -d '{\"method\":\"sendTransaction\"}' http://localhost:8899",
            "curl -d '{\"method\":\"eth_sendRawTransaction\"}' http://localhost:8545",
            "curl -d '{\"method\":\"signTransaction\"}' http://localhost:8899",
            "solana airdrop 1",
            "sui client call --function withdraw",
            "sui keytool sign --data 0xdead",
            "solana stake-account create",
            "near send alice.near bob.near 1",
        ] {
            assert!(
                command_is_chain_write_intent(w),
                "must be chain-write-intent: {w}"
            );
        }
        // READS may be PROPOSED. Note getSignatureStatuses tokenizes to
        // ["get","signature","statuses"] — "signature" != "sign" — so it passes.
        for r in [
            "curl -d '{\"method\":\"getBalance\"}' http://localhost:8899",
            "curl -d '{\"method\":\"eth_call\"}' http://localhost:8545",
            "curl -d '{\"method\":\"getSignatureStatuses\"}' http://localhost:8899",
            "curl -d '{\"method\":\"getAccountInfo\"}' http://localhost:8899",
            "curl -d '{\"method\":\"eth_getBalance\"}' http://localhost:8545",
            "curl -d '{\"method\":\"getTransaction\"}' http://localhost:8899",
            "curl -d '{\"method\":\"getProgramAccounts\"}' http://localhost:8899",
            "swapon --show",
            "codesign --display /bin/ls",
        ] {
            assert!(
                !command_is_chain_write_intent(r),
                "read must be allowed to propose: {r}"
            );
        }
    }

    #[test]
    fn mint_refuses_chain_write_intent_but_mints_a_read() {
        // A write-intent proposal is refused at mint (never sealed -> never runs).
        assert_eq!(
            mint_exec_proposal(&proposed("solana transfer 5 SoLAddr"), false),
            Err(ExecProposeDeny::ChainWriteIntent)
        );
        // The refusal holds regardless of the (independent) secret-shaped verdict.
        assert_eq!(
            mint_exec_proposal(&proposed("cast send 0xabc --value 1"), true),
            Err(ExecProposeDeny::ChainWriteIntent)
        );
        // A read-intent command still mints (allowed to be PROPOSED) — but it
        // would only ever run in the network-DENIED sandbox after owner approval.
        let read = "curl -d '{\"method\":\"getBalance\"}' http://localhost:8899";
        assert!(mint_exec_proposal(&proposed(read), false).is_ok());
    }

    #[test]
    fn chain_write_intent_class_label_is_stable() {
        assert_eq!(
            ExecProposeDeny::ChainWriteIntent.class_label(),
            "exec_proposal.propose.chain_write_intent"
        );
    }

    // ---- / ⑳ force-push + key-export refused at propose time --------

    #[test]
    fn force_push_intent_refuses_force_push_allows_regular_push() {
        // FORCE-push (history rewrite to a remote) is refused; the -f short form too.
        for w in [
            "git push --force origin main",
            "git push --force-with-lease",
            "git push -f origin main",
            "git push --mirror",
            "git push origin main --force",
        ] {
            assert!(
                command_is_force_push_intent(w),
                "must be force-push-intent: {w}"
            );
        }
        // a REGULAR push / 'force' in a commit message / a cp -f / a branch named
        // `feature-f` are NOT force-push (co-presence, Python-verified).
        for ok in [
            "git push origin main",
            "git commit -m 'force the issue'",
            "git pull --rebase",
            "cp -f notes.txt backup.txt",
            "git push origin feature-f",
        ] {
            assert!(
                !command_is_force_push_intent(ok),
                "must NOT be force-push-intent: {ok}"
            );
        }
    }

    #[test]
    fn key_export_intent_refuses_private_key_export_allows_public_and_path() {
        for w in [
            "gpg --export-secret-keys",
            "gpg --export-secret-key > key.asc",
            "ssh-keygen -t rsa -f id_rsa",
            "security export -k login.keychain -t identities -o out.p12",
            "sui keytool export --key-identity addr",
        ] {
            assert!(
                command_is_key_export_intent(w),
                "must be key-export-intent: {w}"
            );
        }
        // a PUBLIC-key export / a shell `export` / a build are NOT key-export.
        for ok in [
            "gpg --export > pub.asc",
            "export PATH=/usr/bin",
            "echo 'export the data to csv'",
            "cargo build --release",
        ] {
            assert!(
                !command_is_key_export_intent(ok),
                "must NOT be key-export-intent: {ok}"
            );
        }
    }

    #[test]
    fn mint_refuses_force_push_and_key_export_at_propose_time_but_mints_benign() {
        assert_eq!(
            mint_exec_proposal(&proposed("git push --force origin main"), false),
            Err(ExecProposeDeny::ForcePushIntent)
        );
        assert_eq!(
            mint_exec_proposal(&proposed("gpg --export-secret-keys"), false),
            Err(ExecProposeDeny::KeyExportIntent)
        );
        // a benign edit/run still mints (a bold session can auto-execute it).
        assert!(mint_exec_proposal(&proposed("cargo test --workspace"), false).is_ok());
        assert!(mint_exec_proposal(&proposed("rm -rf target/debug"), false).is_ok());
    }

    #[test]
    fn escalation_class_labels_are_stable() {
        assert_eq!(
            ExecProposeDeny::ForcePushIntent.class_label(),
            "exec_proposal.propose.force_push_intent"
        );
        assert_eq!(
            ExecProposeDeny::KeyExportIntent.class_label(),
            "exec_proposal.propose.key_export_intent"
        );
    }

    // ---- wire codec (round-trip + fail-closed) ----------------------------

    #[test]
    fn wire_round_trips() {
        let p = ExecProposal {
            command: "cargo build --locked \u{b0b4}\u{c77c}".to_string(),
        };
        let wire = p.to_wire().expect("encode");
        // ver(1) + cmd_len(4) + cmd bytes
        assert_eq!(wire.len(), 1 + 4 + p.command.len());
        assert_eq!(wire[0], EXEC_PROPOSAL_WIRE_VERSION);
        assert_eq!(ExecProposal::from_wire(&wire), Ok(p));
    }

    #[test]
    fn wire_decode_is_fail_closed() {
        assert_eq!(ExecProposal::from_wire(&[]), Err(ExecWireError::Truncated));
        assert_eq!(
            ExecProposal::from_wire(&[9, 0, 0, 0, 0]),
            Err(ExecWireError::UnknownVersion)
        );
        // ver=1, len=1, but no command byte
        assert_eq!(
            ExecProposal::from_wire(&[1, 1, 0, 0, 0]),
            Err(ExecWireError::Truncated)
        );
        // ver=1, len=0, plus a trailing byte
        assert_eq!(
            ExecProposal::from_wire(&[1, 0, 0, 0, 0, 0xff]),
            Err(ExecWireError::TrailingBytes)
        );
    }

    // ---- sealed store (save / load / find / remove) -----------------------

    fn temp_store() -> (ExecProposalStore, PathBuf) {
        let cipher = MemoryCipher::from_key([7u8; 32]);
        let base = std::env::temp_dir().join(format!(
            "mnemos_xep_test_{}_{}",
            std::process::id(),
            COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
        ));
        std::fs::create_dir_all(&base).expect("mk store dir");
        (ExecProposalStore::with_dir(cipher, base.clone()), base)
    }

    static COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

    #[test]
    fn store_save_load_find_remove_round_trip() {
        let (store, dir) = temp_store();
        let p = ExecProposal {
            command: "/bin/echo e10_inert".to_string(),
        };
        let name = store.save(&p).expect("save");
        // idempotent re-save: same name, still one pending.
        let name2 = store.save(&p).expect("save again");
        assert_eq!(name, name2);
        let pending = store.load_pending();
        assert_eq!(pending.proposals.len(), 1);
        assert_eq!(pending.skipped_u32, 0);
        assert_eq!(pending.proposals[0].proposal, p);
        // find by 16-hex prefix.
        let id16: String = name.chars().take(EXEC_PROPOSAL_ID_HEX_CHARS).collect();
        let found = store.find_by_prefix(&id16).expect("find");
        assert_eq!(found.proposal, p);
        // remove consumes it.
        store.remove(&found.record_name).expect("remove");
        assert!(store.load_pending().proposals.is_empty());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn store_find_unknown_and_ambiguous_are_typed() {
        let (store, dir) = temp_store();
        assert_eq!(
            store.find_by_prefix("deadbeef").err(),
            Some(ExecLookupDeny::UnknownId)
        );
        // an empty prefix is UnknownId, never "the first one".
        assert_eq!(
            store.find_by_prefix("   ").err(),
            Some(ExecLookupDeny::UnknownId)
        );
        let _ = std::fs::remove_dir_all(&dir);
    }
}
