//! Persisted memory store — AEAD encrypt-at-rest + local key management
//! (agent-core P1-1; owner "메모리 휘발성 해결" 2026-06-11). Threat model:
//! `ops/evidence/stage_g/agent_loop/PERSISTED_MEMORY_THREAT_MODEL.md`.
//!
//! This module owns the cardinal at-rest guarantees (the cipher + key half);
//! the record format / atomic writer / boot loader / dispatch wiring are the
//! later P1-1 sub-steps over this base.
//!
//! # The two at-rest laws this stands on
//!
//! 1. **DL-1 plaintext NEVER on disk.** Every persisted byte is
//!    `aes-gcm-siv` (AES-256-GCM-SIV) AEAD ciphertext. The plaintext is the
//!    canonical `encode_stage_b_chunk` wire; this module only seals/opens it.
//!    Same `Aes256GcmSiv` the workspace `g-wallet` keystore uses — reused,
//!    not a second cipher.
//! 2. **DL-2 deterministic ciphertext (the madness move).** `aes-gcm-siv` is
//!    nonce-MISUSE-RESISTANT (SIV), so the nonce is CONTENT-DERIVED
//!    (`sha256(plaintext)[..12]`), never random. ⇒ the same chunk always
//!    seals to byte-identical output ⇒ the content-addressed filename is
//!    stable ⇒ a replayed chunk re-persists byte-for-byte (L1+L2+L4 at once).
//!    Drift is a SHA-256 + SIV impossibility, not a discipline. On open, the
//!    recovered plaintext's content-nonce is RE-checked against the stored
//!    nonce — a tampered nonce/ciphertext fails the AEAD tag AND this re-bind.
//!
//! # Key management (KM-1..KM-4)
//!
//! A 32-byte AES-256 key at `<data_dir>/memory.key` (`data_dir =
//! $HOME/.mnemos`), `getrandom`-generated on first run, `0600` (owner-only).
//! Held as a `Secret<[u8; 32]>` (SI-1) in [`MemoryCipher`] — structurally
//! unrenderable (no `Debug`/`Display`/`Serialize`/`to_string` path exists for
//! the key bytes); the cipher's own `Debug` additionally masks the field
//! (KM-2 secret-zero: the key never appears in a trace/receipt/Debug). Key
//! trouble is fail-closed (KM-3) — the caller opens a degraded no-op store
//! rather than ever writing plaintext. This is a LOCAL at-rest key, NOT a
//! wallet/custody key (KM-4); it touches no funds.

use std::path::{Path, PathBuf};

use aes_gcm_siv::aead::{Aead, KeyInit};
use aes_gcm_siv::{Aes256GcmSiv, Key as AesKey, Nonce as AesNonce};

use crate::secrets::Secret;
use mnemos_b_memory::{
    MemoryChunk, MemoryId, MemoryPrivacy, decode_stage_b_chunk, encode_stage_b_chunk,
};

use crate::{hex32, sha256_32};

/// AEAD key width (AES-256).
pub const MEMORY_AEAD_KEY_BYTES: usize = 32;

/// AEAD nonce width (`aes-gcm-siv` 96-bit nonce).
pub const MEMORY_AEAD_NONCE_BYTES: usize = 12;

/// On-disk key filename under the data dir.
pub const MEMORY_KEY_FILE: &str = "memory.key";

/// Data-dir name under `$HOME`.
pub const MEMORY_DATA_DIR: &str = ".mnemos";

/// Typed, data-free AEAD failures (the AEAD error is opaque ⇒ no plaintext or
/// key can leak through `Debug`).
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
#[non_exhaustive]
pub enum CipherError {
    /// AES-GCM-SIV encryption failed (allocation / internal).
    EncryptFailed,
    /// AEAD tag did not verify — wrong key, or tampered ciphertext.
    DecryptFailed,
    /// The sealed blob was shorter than the nonce header.
    SealedTooShort,
    /// The recovered plaintext's content-nonce did not match the stored nonce
    /// (DL-2 re-bind: a tampered nonce that still somehow opened is rejected).
    NonceRebindMismatch,
}

impl CipherError {
    /// Stable, allow-listed `class_label` (namespaced `memory_store.cipher.*`).
    #[inline]
    #[must_use]
    pub const fn class_label(self) -> &'static str {
        match self {
            Self::EncryptFailed => "memory_store.cipher.encrypt_failed",
            Self::DecryptFailed => "memory_store.cipher.decrypt_failed",
            Self::SealedTooShort => "memory_store.cipher.sealed_too_short",
            Self::NonceRebindMismatch => "memory_store.cipher.nonce_rebind_mismatch",
        }
    }
}

/// Typed key-management failures (KM-3 fail-closed; no path/byte leaked).
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
#[non_exhaustive]
pub enum KeyError {
    /// `$HOME` could not be resolved (no data dir).
    NoHome,
    /// The data dir could not be created.
    DataDirCreateFailed,
    /// The key file could not be read.
    KeyReadFailed,
    /// The key file did not contain exactly 32 bytes.
    KeyLengthInvalid,
    /// The key could not be generated (`getrandom`).
    KeyGenFailed,
    /// The freshly generated key could not be written `0600`.
    KeyWriteFailed,
}

impl KeyError {
    /// Stable, allow-listed `class_label` (namespaced `memory_store.key.*`).
    #[inline]
    #[must_use]
    pub const fn class_label(self) -> &'static str {
        match self {
            Self::NoHome => "memory_store.key.no_home",
            Self::DataDirCreateFailed => "memory_store.key.data_dir_create_failed",
            Self::KeyReadFailed => "memory_store.key.read_failed",
            Self::KeyLengthInvalid => "memory_store.key.length_invalid",
            Self::KeyGenFailed => "memory_store.key.gen_failed",
            Self::KeyWriteFailed => "memory_store.key.write_failed",
        }
    }
}

/// The content-derived nonce (DL-2): `sha256(plaintext)[..12]`. Deterministic;
/// SIV makes the (only) reuse — identical plaintext — safe by construction.
#[must_use]
fn content_nonce(plaintext: &[u8]) -> [u8; MEMORY_AEAD_NONCE_BYTES] {
    let digest = sha256_32(plaintext);
    let mut nonce = [0u8; MEMORY_AEAD_NONCE_BYTES];
    nonce.copy_from_slice(&digest[..MEMORY_AEAD_NONCE_BYTES]);
    nonce
}

/// The at-rest cipher. Holds the 32-byte key as a [`Secret`] (SI-1) so it is
/// structurally unrenderable — no `Debug`/`Display`/`Serialize`/`to_string` path
/// exists for the key bytes by construction. `Debug` on the cipher additionally
/// masks the field (KM-2 defence-in-depth). The only constructors take the key
/// bytes explicitly, so a key never appears in a log line by accident.
#[derive(Clone)]
pub struct MemoryCipher {
    key: Secret<[u8; MEMORY_AEAD_KEY_BYTES]>,
}

impl core::fmt::Debug for MemoryCipher {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        // KM-2: never render the key — a fixed redacted label only.
        f.debug_struct("MemoryCipher")
            .field("key", &"<redacted:32B>")
            .finish()
    }
}

impl MemoryCipher {
    /// Construct from raw key bytes (the loader / a test supplies them).
    #[inline]
    #[must_use]
    pub const fn from_key(key: [u8; MEMORY_AEAD_KEY_BYTES]) -> Self {
        Self {
            key: Secret::new(key),
        }
    }

    /// Open or create the local key (`<data_dir>/memory.key`, `0600`) and
    /// build the cipher. Fail-closed (KM-3): any key trouble is a typed error;
    /// the caller then opens a degraded no-op store, NEVER plaintext.
    pub fn open_local() -> Result<Self, KeyError> {
        let data_dir = data_dir()?;
        std::fs::create_dir_all(&data_dir).map_err(|_| KeyError::DataDirCreateFailed)?;
        let key = load_or_create_key(&data_dir)?;
        Ok(Self::from_key(key))
    }

    /// Seal `plaintext` → `nonce(12) || ciphertext+tag` (DL-1/DL-2). Same
    /// plaintext ⇒ byte-identical output (deterministic).
    pub fn seal(&self, plaintext: &[u8]) -> Result<Vec<u8>, CipherError> {
        self.seal_with_aad(plaintext, &[])
    }

    /// Seal with ASSOCIATED DATA (authenticated, not encrypted): the v2
    /// persisted record binds its on-disk header (`magic || version`) here,
    /// so a header flip fails the AEAD tag itself — not only the
    /// content-addressed filename check. Determinism (DL-2) holds: the nonce
    /// is content-derived from the plaintext alone, and the same
    /// `(key, plaintext, aad)` always seals to byte-identical output.
    pub fn seal_with_aad(&self, plaintext: &[u8], aad: &[u8]) -> Result<Vec<u8>, CipherError> {
        use aes_gcm_siv::aead::Payload;
        let nonce = content_nonce(plaintext);
        let cipher =
            Aes256GcmSiv::new(AesKey::<Aes256GcmSiv>::from_slice(self.key.expose_secret()));
        let ciphertext = cipher
            .encrypt(
                AesNonce::from_slice(&nonce),
                Payload {
                    msg: plaintext,
                    aad,
                },
            )
            .map_err(|_| CipherError::EncryptFailed)?;
        let mut sealed = Vec::with_capacity(MEMORY_AEAD_NONCE_BYTES + ciphertext.len());
        sealed.extend_from_slice(&nonce);
        sealed.extend_from_slice(&ciphertext);
        Ok(sealed)
    }

    /// Open `nonce(12) || ciphertext+tag` → plaintext, fail-closed: the AEAD
    /// tag must verify AND the recovered plaintext's content-nonce must equal
    /// the stored nonce (DL-2 re-bind). A wrong key or any tamper rejects.
    pub fn open(&self, sealed: &[u8]) -> Result<Vec<u8>, CipherError> {
        self.open_with_aad(sealed, &[])
    }

    /// Open with ASSOCIATED DATA: the same `aad` bytes used at seal time must
    /// be presented or the tag fails (the v2 record presents its header).
    pub fn open_with_aad(&self, sealed: &[u8], aad: &[u8]) -> Result<Vec<u8>, CipherError> {
        use aes_gcm_siv::aead::Payload;
        if sealed.len() < MEMORY_AEAD_NONCE_BYTES {
            return Err(CipherError::SealedTooShort);
        }
        let (nonce_bytes, ciphertext) = sealed.split_at(MEMORY_AEAD_NONCE_BYTES);
        let cipher =
            Aes256GcmSiv::new(AesKey::<Aes256GcmSiv>::from_slice(self.key.expose_secret()));
        let plaintext = cipher
            .decrypt(
                AesNonce::from_slice(nonce_bytes),
                Payload {
                    msg: ciphertext,
                    aad,
                },
            )
            .map_err(|_| CipherError::DecryptFailed)?;
        if content_nonce(&plaintext) != nonce_bytes {
            return Err(CipherError::NonceRebindMismatch);
        }
        Ok(plaintext)
    }
}

// TEST-ONLY data-dir override for hermetic dispatch tests. Thread-local so it is
// race-free under the parallel test harness (each test runs on its own thread),
// and `#[cfg(test)]` so it is COMPILED OUT of the shipped binary entirely. When
// set, `data_dir` returns this path instead of `$HOME/.mnemos`, giving a test a
// guaranteed-isolated store without mutating the process-global `HOME`.
#[cfg(test)]
thread_local! {
    static TEST_DATA_DIR_OVERRIDE: std::cell::RefCell<Option<PathBuf>> =
        const { std::cell::RefCell::new(None) };
}

/// Set (or clear with `None`) the current thread's test-only data-dir override
/// (`TEST_DATA_DIR_OVERRIDE`); `#[cfg(test)]` ⇒ absent from production.
#[cfg(test)]
pub(crate) fn set_test_data_dir(dir: Option<PathBuf>) {
    TEST_DATA_DIR_OVERRIDE.with(|cell| *cell.borrow_mut() = dir);
}

/// The data dir: `$HOME/.mnemos` (KM-1). Fail-closed if `$HOME` is unset.
pub fn data_dir() -> Result<PathBuf, KeyError> {
    #[cfg(test)]
    {
        if let Some(dir) = TEST_DATA_DIR_OVERRIDE.with(|cell| cell.borrow().clone()) {
            return Ok(dir);
        }
    }
    let home = std::env::var_os("HOME").ok_or(KeyError::NoHome)?;
    if home.is_empty() {
        return Err(KeyError::NoHome);
    }
    Ok(Path::new(&home).join(MEMORY_DATA_DIR))
}

/// Load the 32-byte key from `<data_dir>/memory.key`, generating + writing it
/// `0600` on first run. The key bytes never leave this function except as the
/// returned array (held by [`MemoryCipher`], masked in `Debug`).
fn load_or_create_key(data_dir: &Path) -> Result<[u8; MEMORY_AEAD_KEY_BYTES], KeyError> {
    let key_path = data_dir.join(MEMORY_KEY_FILE);
    match std::fs::read(&key_path) {
        Ok(bytes) => {
            if bytes.len() != MEMORY_AEAD_KEY_BYTES {
                return Err(KeyError::KeyLengthInvalid);
            }
            let mut key = [0u8; MEMORY_AEAD_KEY_BYTES];
            key.copy_from_slice(&bytes);
            Ok(key)
        }
        Err(_) => {
            let mut key = [0u8; MEMORY_AEAD_KEY_BYTES];
            getrandom::getrandom(&mut key).map_err(|_| KeyError::KeyGenFailed)?;
            write_key_0600(&key_path, &key)?;
            Ok(key)
        }
    }
}

/// Write the key file `0600` (owner read/write only). On unix the mode is set
/// at create; elsewhere the OS default applies (documented residual).
fn write_key_0600(path: &Path, key: &[u8; MEMORY_AEAD_KEY_BYTES]) -> Result<(), KeyError> {
    // Atomic-ish: write then set perms before the key is useful at rest.
    std::fs::write(path, key).map_err(|_| KeyError::KeyWriteFailed)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let perms = std::fs::Permissions::from_mode(0o600);
        std::fs::set_permissions(path, perms).map_err(|_| KeyError::KeyWriteFailed)?;
    }
    Ok(())
}

// ===========================================================================
// Persisted store — content-addressed, encrypted, replay-recoverable (P1-1-b)
// ===========================================================================

/// Record magic (4 bytes) — `MNMC` = MNemos Memory Chunk.
pub const RECORD_MAGIC: [u8; 4] = *b"MNMC";

/// Record format version. v2 (P1-2): the sealed plaintext is
/// `id(8 LE) || privacy class(1) || canonical wire` and the 5 header bytes
/// (`magic || version`) are bound as AEAD ASSOCIATED DATA — a version/magic
/// flip fails the tag itself, not only the content-addressed name (no
/// downgrade-confusion class, L5). The v1 layout (`id || wire`, no class, no
/// AAD) is REJECTED-as-skip: the live store held ZERO v1 records at upgrade
/// time (probed 2026-06-11), so no readable data is dropped and no legacy
/// decode path is carried.
pub const RECORD_VERSION: u8 = 2;

/// Fixed record header width: magic(4) + version(1). The body (sealed bytes)
/// is variable, so only the header is byte-locked (const + tests); the
/// content-addressed filename pins the whole record (DL-3).
pub const RECORD_HEADER_BYTES: usize = 5;

/// On-disk chunk file extension.
pub const RECORD_EXT: &str = "mc";

/// Store subdirectory under the data dir.
pub const STORE_SUBDIR: &str = "store";

/// Typed store failures (the load path SKIPS bad records rather than failing;
/// this is the WRITE / open path's error surface).
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
#[non_exhaustive]
pub enum StoreError {
    /// Key management failed (KM-3).
    Key(KeyError),
    /// AEAD seal failed.
    Cipher(CipherError),
    /// The chunk could not be encoded to the canonical wire.
    Encode,
    /// A filesystem write/read/rename failed.
    Io,
}

impl StoreError {
    /// Stable, allow-listed `class_label` (namespaced `memory_store.store.*`).
    #[inline]
    #[must_use]
    pub const fn class_label(self) -> &'static str {
        match self {
            Self::Key(_) => "memory_store.store.key",
            Self::Cipher(_) => "memory_store.store.cipher",
            Self::Encode => "memory_store.store.encode",
            Self::Io => "memory_store.store.io",
        }
    }
}

/// Outcome of a boot load: the recovered chunks with their OWNER privacy
/// class (id-sorted, deterministic) plus an honest skip count — a bad
/// on-disk record is skipped, never loaded as truth and never aborts the
/// load (DL-5).
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct LoadOutcome {
    /// Recovered `(chunk, owner class)` pairs, sorted ascending by
    /// `MemoryId` (replay order). The class feeds `fold_index_classified`
    /// (IV2: only explicit shareable records may list frontier-bound).
    pub chunks: Vec<(MemoryChunk, MemoryPrivacy)>,
    /// Records skipped (name mismatch / bad header / tag fail / bad class /
    /// non-canonical).
    pub skipped_u32: u32,
}

/// The persisted, encrypted, content-addressed chunk store. Each chunk is one
/// file `<store>/<hex(sha256(record))>.mc` whose body is `aes-gcm-siv`
/// ciphertext of `id(8 LE) || privacy class(1) || encode_stage_b_chunk(envelope)`
/// with the record header as AEAD associated data (v2). The index
/// (`fold_index_classified`) is re-derived from `load_all()`, so the store is
/// the truth and the index is a cache (DL-4).
#[derive(Clone, Debug)]
pub struct PersistedStore {
    cipher: MemoryCipher,
    store_dir: PathBuf,
}

impl PersistedStore {
    /// Open the local store: load/create the key and ensure
    /// `$HOME/.mnemos/store/` exists. Fail-closed on any key/io trouble.
    pub fn open_local() -> Result<Self, StoreError> {
        let cipher = MemoryCipher::open_local().map_err(StoreError::Key)?;
        let store_dir = data_dir().map_err(StoreError::Key)?.join(STORE_SUBDIR);
        std::fs::create_dir_all(&store_dir).map_err(|_| StoreError::Io)?;
        Ok(Self { cipher, store_dir })
    }

    /// Construct over an explicit cipher + dir (tests / non-default roots).
    #[must_use]
    pub fn with_dir(cipher: MemoryCipher, store_dir: PathBuf) -> Self {
        Self { cipher, store_dir }
    }

    /// The on-disk record header (`magic || version`) — also the AEAD
    /// associated data of every v2 record (a header flip fails the tag).
    const fn record_header() -> [u8; RECORD_HEADER_BYTES] {
        [
            RECORD_MAGIC[0],
            RECORD_MAGIC[1],
            RECORD_MAGIC[2],
            RECORD_MAGIC[3],
            RECORD_VERSION,
        ]
    }

    /// The canonical v2 record bytes for `(id, class, envelope)` —
    /// `magic|version|sealed` where `sealed = AEAD(id(8 LE) || class(1) ||
    /// canonical_wire, aad = magic||version)`. Deterministic (DL-2), so the
    /// same `(chunk, class)` always yields byte-identical record bytes; a
    /// different class is a different plaintext ⇒ a different record.
    fn record_bytes(
        &self,
        chunk: &MemoryChunk,
        privacy: MemoryPrivacy,
    ) -> Result<Vec<u8>, StoreError> {
        let wire = encode_stage_b_chunk(chunk.envelope()).map_err(|_| StoreError::Encode)?;
        let mut plaintext = Vec::with_capacity(8 + 1 + wire.len());
        plaintext.extend_from_slice(&chunk.id().get().to_le_bytes());
        plaintext.push(privacy.tag());
        plaintext.extend_from_slice(&wire);
        let header = Self::record_header();
        let sealed = self
            .cipher
            .seal_with_aad(&plaintext, &header)
            .map_err(StoreError::Cipher)?;
        let mut record = Vec::with_capacity(RECORD_HEADER_BYTES + sealed.len());
        record.extend_from_slice(&header);
        record.extend_from_slice(&sealed);
        Ok(record)
    }

    /// The content-addressed filename for a record (`hex(sha256(record)).mc`).
    fn record_name(record: &[u8]) -> String {
        format!("{}.{RECORD_EXT}", hex32(&sha256_32(record)))
    }

    /// Persist one chunk with its OWNER privacy class: encode → seal → name →
    /// atomic write. Returns the content-addressed filename. Re-persisting
    /// the same `(chunk, class)` is idempotent (same bytes, same name —
    /// DL-2/DL-3). The class is the owner's save-time decision (IV2): the
    /// caller's default MUST be [`MemoryPrivacy::Private`] (fail-closed).
    pub fn save_chunk(
        &self,
        chunk: &MemoryChunk,
        privacy: MemoryPrivacy,
    ) -> Result<String, StoreError> {
        let record = self.record_bytes(chunk, privacy)?;
        let name = Self::record_name(&record);
        let path = self.store_dir.join(&name);
        atomic_write(&path, &record).map_err(|_| StoreError::Io)?;
        Ok(name)
    }

    /// E14-W: the raw on-disk record bytes (AEAD CIPHERTEXT) of every `.mc` record,
    /// name-sorted as `(record_name, ciphertext_bytes)`. Each record is
    /// `magic||version||AEAD(...)` — the 32-byte key (`<data_dir>/memory.key`) is
    /// NEVER part of a record, so these bytes expose NO plaintext. This is the
    /// publish surface for the autonomous encrypted-memory Walrus backup (the
    /// ciphertext is opaque without the local key, so it is safe on a public store).
    #[must_use]
    pub fn raw_records(&self) -> Vec<(String, Vec<u8>)> {
        let mut out: Vec<(String, Vec<u8>)> = Vec::new();
        let Ok(entries) = std::fs::read_dir(&self.store_dir) else {
            return out;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.extension().and_then(|e| e.to_str()) != Some(RECORD_EXT) {
                continue;
            }
            if let (Ok(bytes), Some(name)) = (
                std::fs::read(&path),
                path.file_name().and_then(|n| n.to_str()),
            ) {
                out.push((name.to_string(), bytes));
            }
        }
        out.sort_by(|a, b| a.0.cmp(&b.0));
        out
    }

    /// Load every readable record, fail-closed per record (DL-5), returning
    /// chunks SORTED by id (deterministic replay order regardless of dir
    /// enumeration order — L2/L4). A bad record increments `skipped_u32`.
    #[must_use]
    pub fn load_all(&self) -> LoadOutcome {
        let mut outcome = LoadOutcome::default();
        let entries = match std::fs::read_dir(&self.store_dir) {
            Ok(entries) => entries,
            // A missing/unreadable dir = an empty store (not a crash).
            Err(_) => return outcome,
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.extension().and_then(|e| e.to_str()) != Some(RECORD_EXT) {
                continue;
            }
            match self.load_one(&path) {
                Some(chunk) => outcome.chunks.push(chunk),
                None => outcome.skipped_u32 = outcome.skipped_u32.saturating_add(1),
            }
        }
        // Deterministic replay order: ascending id (the monotone append order).
        outcome.chunks.sort_by_key(|(chunk, _)| chunk.id().get());
        outcome
    }

    /// Load + verify ONE record file, or `None` (skip) on any gate failure.
    fn load_one(&self, path: &Path) -> Option<(MemoryChunk, MemoryPrivacy)> {
        let bytes = std::fs::read(path).ok()?;
        // DL-3: the filename must be the content hash of the bytes.
        let expected = Self::record_name(&bytes);
        if path.file_name().and_then(|n| n.to_str()) != Some(expected.as_str()) {
            return None;
        }
        // Header (L5): magic + version. A v1 record (version byte 1) skips
        // here by design — see [`RECORD_VERSION`].
        if bytes.len() < RECORD_HEADER_BYTES
            || bytes[..4] != RECORD_MAGIC
            || bytes[4] != RECORD_VERSION
        {
            return None;
        }
        // DL-1/DL-5: AEAD open (tag + nonce re-bind), the header as AAD — a
        // header flip fails the tag even before the layout checks above.
        let plaintext = self
            .cipher
            .open_with_aad(&bytes[RECORD_HEADER_BYTES..], &bytes[..RECORD_HEADER_BYTES])
            .ok()?;
        // v2 plaintext: id(8 LE) || class(1) || wire.
        if plaintext.len() < 9 {
            return None;
        }
        let mut id_bytes = [0u8; 8];
        id_bytes.copy_from_slice(&plaintext[..8]);
        let id = MemoryId::new(u64::from_le_bytes(id_bytes));
        // Fail-closed class decode: only the two locked tag bytes load (an
        // unparseable class is never guessed — DL-5).
        let privacy = MemoryPrivacy::from_tag(plaintext[8])?;
        // Canonical decode (L5): garbage past the AEAD tag is still rejected.
        let envelope = decode_stage_b_chunk(&plaintext[9..]).ok()?;
        Some((MemoryChunk::new(id, envelope), privacy))
    }

    /// E14-W2: every memory as `(memory_id, topic_summary, ciphertext)` for the
    /// two-tier Walrus backup — the SUB-STORE ciphertext (the deterministic `.mc`
    /// record bytes) plus a bounded topic for the MAIN INDEX. The topic is derived from
    /// the decoded content but is only ever placed INSIDE the later-encrypted index;
    /// the ciphertext is the AEAD record (no plaintext leaves).
    #[must_use]
    pub fn records_for_walrus(&self) -> Vec<(u64, String, Vec<u8>)> {
        let loaded = self.load_all();
        let mut out: Vec<(u64, String, Vec<u8>)> = Vec::new();
        for (chunk, privacy) in &loaded.chunks {
            if let Ok(ciphertext) = self.record_bytes(chunk, *privacy) {
                let topic =
                    crate::memory_walrus::summarize_topic(chunk.envelope().content.as_slice());
                out.push((chunk.id().get(), topic, ciphertext));
            }
        }
        out
    }

    /// E14-W2: decode a FETCHED record blob (e.g. a sub-store blob fetched back from
    /// Walrus) into `(MemoryChunk, MemoryPrivacy)` — the SAME header + AEAD + canonical
    /// decode as [`load_one`](Self::load_one), MINUS the on-disk filename check (a
    /// fetched blob has no filename; its integrity is the Walrus blob-id + the AEAD
    /// tag). `None` (fail-closed) on any gate failure.
    #[must_use]
    pub fn decode_record(&self, bytes: &[u8]) -> Option<(MemoryChunk, MemoryPrivacy)> {
        if bytes.len() < RECORD_HEADER_BYTES
            || bytes[..4] != RECORD_MAGIC
            || bytes[4] != RECORD_VERSION
        {
            return None;
        }
        let plaintext = self
            .cipher
            .open_with_aad(&bytes[RECORD_HEADER_BYTES..], &bytes[..RECORD_HEADER_BYTES])
            .ok()?;
        if plaintext.len() < 9 {
            return None;
        }
        let mut id_bytes = [0u8; 8];
        id_bytes.copy_from_slice(&plaintext[..8]);
        let id = MemoryId::new(u64::from_le_bytes(id_bytes));
        let privacy = MemoryPrivacy::from_tag(plaintext[8])?;
        let envelope = decode_stage_b_chunk(&plaintext[9..]).ok()?;
        Some((MemoryChunk::new(id, envelope), privacy))
    }

    /// E14-W2: seal the Walrus MAIN-INDEX manifest with the LOCAL AEAD key, bound to the
    /// index AAD (so an index blob can never be opened as a `.mc` record). The sealed
    /// bytes are what is published; only a LOCAL open reveals the manifest (secret-zero).
    pub fn seal_index(&self, plaintext: &[u8]) -> Result<Vec<u8>, CipherError> {
        self.cipher
            .seal_with_aad(plaintext, crate::memory_walrus::WALRUS_INDEX_AAD)
    }

    /// E14-W2: open a fetched Walrus MAIN-INDEX blob back to the manifest bytes (AEAD
    /// tag + index-AAD verified). `Err` (fail-closed) on wrong key / tampered blob.
    pub fn open_index(&self, sealed: &[u8]) -> Result<Vec<u8>, CipherError> {
        self.cipher
            .open_with_aad(sealed, crate::memory_walrus::WALRUS_INDEX_AAD)
    }

    /// K-3: seal a Skew history-time-series WINDOW with the LOCAL AEAD key, bound to the
    /// history AAD (so a window blob can never be opened as a `.mc` record / index / settings).
    /// The sealed bytes are the local storage-of-record AND the Walrus sub-blob (secret-zero —
    /// only a LOCAL open reveals the series; the plaintext window never leaves the box).
    pub fn seal_skew_history(&self, plaintext: &[u8]) -> Result<Vec<u8>, CipherError> {
        self.cipher
            .seal_with_aad(plaintext, crate::skew_history::SKEW_HISTORY_AAD)
    }

    /// K-3: open a sealed Skew history window back to its plaintext bytes (AEAD tag + history-AAD
    /// verified). `Err` (fail-closed) on wrong key / tampered / wrong-AAD blob.
    pub fn open_skew_history(&self, sealed: &[u8]) -> Result<Vec<u8>, CipherError> {
        self.cipher
            .open_with_aad(sealed, crate::skew_history::SKEW_HISTORY_AAD)
    }

    /// K-4: seal a CERTIFIED strategy corpus entry (the canonical strategy TOML as a pattern memory)
    /// with the LOCAL AEAD key, bound to the strategy-corpus AAD (so a corpus blob can never be opened
    /// as a `.mc` record / index / history window). The certified corpus is the agent's OWN encrypted
    /// data; only a LOCAL open reveals the plaintext.
    pub fn seal_strategy_corpus(&self, plaintext: &[u8]) -> Result<Vec<u8>, CipherError> {
        self.cipher
            .seal_with_aad(plaintext, crate::skew_strategy::STRATEGY_CORPUS_AAD)
    }

    /// K-4: open a sealed strategy corpus entry back to its plaintext bytes (AEAD tag + corpus-AAD
    /// verified). `Err` (fail-closed) on wrong key / tampered / wrong-AAD blob.
    pub fn open_strategy_corpus(&self, sealed: &[u8]) -> Result<Vec<u8>, CipherError> {
        self.cipher
            .open_with_aad(sealed, crate::skew_strategy::STRATEGY_CORPUS_AAD)
    }

    /// [6] Settings-sync: seal a (secret-screened) config TOML with the LOCAL AEAD key,
    /// bound to the settings AAD (so a settings blob can never be opened as a `.mc`
    /// record / index). The sealed bytes are what is PUT to Walrus; only a LOCAL open
    /// reveals the config (secret-zero — the plaintext never leaves the box).
    pub fn seal_settings(&self, plaintext: &[u8]) -> Result<Vec<u8>, CipherError> {
        self.cipher
            .seal_with_aad(plaintext, crate::settings_sync::SETTINGS_SYNC_AAD)
    }

    /// [6] Settings-sync: open a fetched Walrus settings blob back to the config TOML
    /// bytes (AEAD tag + settings-AAD verified). `Err` (fail-closed) on wrong key /
    /// tampered blob / a blob that was not a settings blob.
    pub fn open_settings(&self, sealed: &[u8]) -> Result<Vec<u8>, CipherError> {
        self.cipher
            .open_with_aad(sealed, crate::settings_sync::SETTINGS_SYNC_AAD)
    }

    /// [4] Semantic codebase index: seal the serialized vector store with the LOCAL key,
    /// bound to the codebase-index AAD (so the index blob is opaque at rest and cannot be
    /// opened as any other blob). The plaintext index never touches disk.
    pub fn seal_codebase_index(&self, plaintext: &[u8]) -> Result<Vec<u8>, CipherError> {
        self.cipher
            .seal_with_aad(plaintext, crate::codebase_index::CODEBASE_INDEX_AAD)
    }

    /// [4] Semantic codebase index: open a sealed index blob back to the serialized bytes
    /// (AEAD tag + codebase-AAD verified). `Err` (fail-closed) on wrong key / tampered blob.
    pub fn open_codebase_index(&self, sealed: &[u8]) -> Result<Vec<u8>, CipherError> {
        self.cipher
            .open_with_aad(sealed, crate::codebase_index::CODEBASE_INDEX_AAD)
    }
}

/// Mint a `MemoryChunk` for a user-authored memory `text` at `id` (P1-1-c).
/// Uses the b-memory-re-exported envelope types (c-walrus stays unnamed here).
/// The content cap is the caller's responsibility (the save verb checks it).
#[must_use]
pub fn make_user_chunk(id: MemoryId, text: &str) -> MemoryChunk {
    use mnemos_b_memory::{ChunkEnvelopeV1, ChunkKind, MemoryRole};
    MemoryChunk::new(
        id,
        ChunkEnvelopeV1 {
            kind: ChunkKind::UserMessage,
            role: MemoryRole::User,
            parent: None,
            content: text.as_bytes().to_vec(),
            embedding: None,
            signature: None,
            provenance: None,
        },
    )
}

/// Atomically write `bytes` to `path`: write a sibling temp file, fsync, then
/// rename over the target (no torn write; a crash leaves the prior file
/// intact — T6). Reuses the lane-A / sessions.json discipline. `pub(crate)`
/// since P4-1: the OTel exporter writes its span files with THIS one
/// implementation (⑨ IV-O3 — one atomic-write discipline, zero drift).
pub(crate) fn atomic_write(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    use std::io::Write;
    let tmp = path.with_extension("tmp");
    {
        let mut file = std::fs::File::create(&tmp)?;
        file.write_all(bytes)?;
        file.sync_all()?;
    }
    std::fs::rename(&tmp, path)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use super::*;

    fn unique_dir(tag: &str) -> PathBuf {
        use std::sync::atomic::{AtomicU32, Ordering};
        static COUNTER: AtomicU32 = AtomicU32::new(0);
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        let dir =
            std::env::temp_dir().join(format!("sinabro_memstore_{}_{tag}_{n}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("temp dir");
        dir
    }

    /// DL-1/DL-2 — round-trip + DETERMINISTIC ciphertext: the same plaintext
    /// seals to byte-identical output (the property the content-addressed
    /// filename + replay stand on), and opens back to the original.
    #[test]
    fn seal_open_round_trip_is_deterministic() {
        let cipher = MemoryCipher::from_key([7u8; 32]);
        let pt = "시나브로 기억은 디스크에 암호문으로만 — deterministic".as_bytes();

        let a = cipher.seal(pt).expect("seal");
        let b = cipher.seal(pt).expect("seal again");
        assert_eq!(
            a, b,
            "same plaintext + key ⇒ byte-identical ciphertext (SIV)"
        );
        assert_ne!(
            &a[MEMORY_AEAD_NONCE_BYTES..],
            pt,
            "ciphertext is not plaintext"
        );
        assert_eq!(cipher.open(&a).expect("open"), pt);

        // The nonce is content-derived (DL-2), not random.
        assert_eq!(&a[..MEMORY_AEAD_NONCE_BYTES], &content_nonce(pt));

        // Different plaintext ⇒ different sealed bytes.
        let other = cipher.seal(b"different").expect("seal");
        assert_ne!(a, other);
    }

    /// DL-5 — fail-closed open: a wrong key, a flipped ciphertext byte, a
    /// flipped nonce, and a too-short blob all reject with a typed error;
    /// no plaintext is returned.
    #[test]
    fn open_rejects_wrong_key_and_tamper() {
        let cipher = MemoryCipher::from_key([1u8; 32]);
        let sealed = cipher.seal(b"secret memory body").expect("seal");

        // Wrong key ⇒ tag fail.
        let wrong = MemoryCipher::from_key([2u8; 32]);
        assert_eq!(wrong.open(&sealed), Err(CipherError::DecryptFailed));

        // Flip a ciphertext byte ⇒ tag fail.
        let mut tampered = sealed.clone();
        let last = tampered.len() - 1;
        tampered[last] ^= 0x01;
        assert_eq!(cipher.open(&tampered), Err(CipherError::DecryptFailed));

        // Flip a nonce byte ⇒ tag fail (the nonce is AEAD-bound) or rebind
        // mismatch — either way, never plaintext.
        let mut nonce_tamper = sealed.clone();
        nonce_tamper[0] ^= 0x01;
        assert!(matches!(
            cipher.open(&nonce_tamper),
            Err(CipherError::DecryptFailed) | Err(CipherError::NonceRebindMismatch)
        ));

        // Too short ⇒ typed reject.
        assert_eq!(cipher.open(&[0u8; 4]), Err(CipherError::SealedTooShort));
    }

    /// KM-2 — the key is masked in `Debug` (never rendered).
    #[test]
    fn debug_masks_the_key() {
        let cipher = MemoryCipher::from_key([0xAB; 32]);
        let shown = format!("{cipher:?}");
        assert!(shown.contains("<redacted:32B>"));
        assert!(!shown.contains("171"), "no key byte value rendered");
        assert!(!shown.contains("ab"), "no key hex rendered");
    }

    /// KM-1 — the key file is created (32 bytes, `0600` on unix), reloads to
    /// the SAME key (so persisted data stays openable across restarts), and a
    /// length-corrupt key file is a typed reject.
    #[test]
    fn key_file_create_reload_and_perms() {
        let dir = unique_dir("key");
        let key_a = load_or_create_key(&dir).expect("create");
        let key_b = load_or_create_key(&dir).expect("reload");
        assert_eq!(key_a, key_b, "key reloads identically across runs");

        let key_path = dir.join(MEMORY_KEY_FILE);
        assert_eq!(std::fs::read(&key_path).expect("read").len(), 32);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&key_path)
                .expect("meta")
                .permissions()
                .mode();
            assert_eq!(mode & 0o777, 0o600, "key file is owner-only 0600");
        }

        // A corrupt-length key file is rejected, never used.
        std::fs::write(&key_path, b"too short").expect("write");
        assert_eq!(load_or_create_key(&dir), Err(KeyError::KeyLengthInvalid));

        std::fs::remove_dir_all(&dir).ok();
    }

    /// Sealed-with-loaded-key round-trips: the persisted-file lifecycle
    /// (generate key → seal → open with the reloaded key) recovers the bytes.
    #[test]
    fn loaded_key_seals_and_opens() {
        let dir = unique_dir("lifecycle");
        let key = load_or_create_key(&dir).expect("key");
        let cipher = MemoryCipher::from_key(key);
        let pt = b"a memory chunk's canonical wire bytes";
        let sealed = cipher.seal(pt).expect("seal");

        // Simulate a restart: reload the key, rebuild the cipher, open.
        let reloaded = MemoryCipher::from_key(load_or_create_key(&dir).expect("reload"));
        assert_eq!(reloaded.open(&sealed).expect("open"), pt);
        std::fs::remove_dir_all(&dir).ok();
    }

    /// Class labels stay stable (diagnostic envelopes).
    #[test]
    fn error_labels_stable() {
        assert_eq!(
            CipherError::DecryptFailed.class_label(),
            "memory_store.cipher.decrypt_failed"
        );
        assert_eq!(KeyError::NoHome.class_label(), "memory_store.key.no_home");
        assert_eq!(
            StoreError::Encode.class_label(),
            "memory_store.store.encode"
        );
    }

    // ---- persisted store (P1-1-b) -----------------------------------------

    fn chunk(id: u64, content: &[u8]) -> MemoryChunk {
        use mnemos_c_walrus::codec::{ChunkEnvelopeV1, ChunkKind, MemoryRole};
        MemoryChunk::new(
            MemoryId::new(id),
            ChunkEnvelopeV1 {
                kind: ChunkKind::UserMessage,
                role: MemoryRole::User,
                parent: None,
                content: content.to_vec(),
                embedding: None,
                signature: None,
                provenance: None,
            },
        )
    }

    fn test_store(tag: &str) -> (PersistedStore, PathBuf) {
        let dir = unique_dir(tag);
        let store = PersistedStore::with_dir(MemoryCipher::from_key([9u8; 32]), dir.clone());
        (store, dir)
    }

    /// DL-1/DL-2/DL-3 — save→load round-trip; the on-disk file is ciphertext
    /// (no plaintext content visible); the filename is deterministic (re-save
    /// is idempotent); load recovers the exact chunk WITH its class; a
    /// different class is a different sealed plaintext ⇒ a different name.
    #[test]
    fn save_load_round_trip_encrypted_and_deterministic() {
        let (store, dir) = test_store("rt");
        let c = chunk(1, "비밀 기억 본문 plaintext-marker".as_bytes());

        let name_a = store.save_chunk(&c, MemoryPrivacy::Private).expect("save");
        let name_b = store
            .save_chunk(&c, MemoryPrivacy::Private)
            .expect("save again");
        assert_eq!(
            name_a, name_b,
            "same (chunk, class) ⇒ same content-addressed name (DL-2/3)"
        );

        let raw = std::fs::read(dir.join(&name_a)).expect("read file");
        assert_eq!(&raw[..4], &RECORD_MAGIC);
        assert_eq!(raw[4], RECORD_VERSION);
        assert!(
            !raw.windows(16).any(|w| w == "plaintext-marker".as_bytes()),
            "plaintext must NOT appear on disk (DL-1)"
        );

        let loaded = store.load_all();
        assert_eq!(loaded.skipped_u32, 0);
        assert_eq!(loaded.chunks, vec![(c.clone(), MemoryPrivacy::Private)]);

        // The class byte is INSIDE the sealed plaintext: the same chunk
        // classified shareable seals to different bytes ⇒ a different name.
        let (store2, dir2) = test_store("rt_class");
        let name_shareable = store2
            .save_chunk(&c, MemoryPrivacy::Shareable)
            .expect("save shareable");
        assert_ne!(
            name_a, name_shareable,
            "class is part of the sealed content"
        );
        std::fs::remove_dir_all(&dir2).ok();
        std::fs::remove_dir_all(&dir).ok();
    }

    /// L2/L4 — load returns chunks SORTED by id regardless of write order, so
    /// replay order is deterministic; and the index re-folds from the store
    /// (DL-4: store is truth, index is a re-derivable cache).
    #[test]
    fn load_is_id_sorted_and_index_refolds() {
        use mnemos_b_memory::{TombstonePolicy, fold_index_classified};
        let (store, dir) = test_store("sort");
        store
            .save_chunk(&chunk(3, b"third"), MemoryPrivacy::Private)
            .expect("s3");
        store
            .save_chunk(&chunk(1, b"first"), MemoryPrivacy::Private)
            .expect("s1");
        store
            .save_chunk(&chunk(2, b"second"), MemoryPrivacy::Private)
            .expect("s2");

        let loaded = store.load_all();
        let ids: Vec<u64> = loaded.chunks.iter().map(|(c, _)| c.id().get()).collect();
        assert_eq!(
            ids,
            [1, 2, 3],
            "ascending id order regardless of write order"
        );

        let folded = fold_index_classified(
            loaded.chunks.iter().map(|(c, p)| (c, *p)),
            &TombstonePolicy::new(),
        );
        assert_eq!(folded.records.len(), 3);
        assert_eq!(folded.records[0].memory_id().get(), 1);
        std::fs::remove_dir_all(&dir).ok();
    }

    /// DL-5 — fail-closed load: a bit-flipped record (name mismatch) and a
    /// wrong-key store both SKIP (counted) without aborting or yielding wrong
    /// bytes; the intact record still loads.
    #[test]
    fn load_skips_tampered_and_wrong_key() {
        let (store, dir) = test_store("skip");
        let good = store
            .save_chunk(&chunk(1, b"good"), MemoryPrivacy::Private)
            .expect("save");
        store
            .save_chunk(&chunk(2, b"also good"), MemoryPrivacy::Private)
            .expect("save2");

        let path = dir.join(&good);
        let mut bytes = std::fs::read(&path).expect("read");
        let last = bytes.len() - 1;
        bytes[last] ^= 0x01;
        std::fs::write(&path, &bytes).expect("write tampered");

        let loaded = store.load_all();
        assert_eq!(loaded.skipped_u32, 1, "tampered record skipped");
        assert_eq!(loaded.chunks.len(), 1, "the intact record still loads");
        assert_eq!(loaded.chunks[0].0.id().get(), 2);

        let wrong = PersistedStore::with_dir(MemoryCipher::from_key([0u8; 32]), dir.clone());
        let wrong_load = wrong.load_all();
        assert!(wrong_load.chunks.is_empty(), "wrong key opens nothing");
        assert!(wrong_load.skipped_u32 >= 1, "records counted as skipped");
        std::fs::remove_dir_all(&dir).ok();
    }

    /// A foreign / garbage `.mc` file (name ≠ hash) is skipped, never loaded.
    #[test]
    fn load_skips_foreign_files() {
        let (store, dir) = test_store("foreign");
        store
            .save_chunk(&chunk(1, b"real"), MemoryPrivacy::Private)
            .expect("save");
        std::fs::write(dir.join("deadbeef.mc"), b"not a record").expect("write");
        let loaded = store.load_all();
        assert_eq!(loaded.chunks.len(), 1);
        assert_eq!(loaded.skipped_u32, 1);
        std::fs::remove_dir_all(&dir).ok();
    }

    /// P1-2 — the AAD path binds: a blob sealed under one associated-data
    /// value opens ONLY under that value (a different aad, or none, fails
    /// the tag); determinism holds with aad; and the empty-aad delegation
    /// keeps `seal`/`open` byte-compatible with `*_with_aad(.., &[])`.
    #[test]
    fn aad_binds_seal_and_open() {
        let cipher = MemoryCipher::from_key([5u8; 32]);
        let sealed = cipher
            .seal_with_aad(b"payload", b"header-A")
            .expect("seal with aad");
        assert_eq!(
            cipher.open_with_aad(&sealed, b"header-A").expect("open"),
            b"payload"
        );
        assert_eq!(
            cipher.open_with_aad(&sealed, b"header-B"),
            Err(CipherError::DecryptFailed),
            "different aad fails the tag"
        );
        assert_eq!(
            cipher.open(&sealed),
            Err(CipherError::DecryptFailed),
            "missing aad fails the tag"
        );
        // Determinism holds with aad (DL-2 unchanged).
        assert_eq!(
            sealed,
            cipher
                .seal_with_aad(b"payload", b"header-A")
                .expect("seal again")
        );
        // Delegation: plain seal == seal_with_aad(.., &[]).
        assert_eq!(
            cipher.seal(b"x").expect("plain"),
            cipher.seal_with_aad(b"x", b"").expect("empty aad")
        );
    }

    /// P1-2 — a legacy v1 record (`id || wire`, version byte 1, no class, no
    /// AAD) is REJECTED-as-skip, never misparsed. The live store held ZERO v1
    /// records at upgrade time (probed 2026-06-11); this pins the fail-closed
    /// posture if one ever appears.
    #[test]
    fn v1_legacy_record_is_skipped() {
        let (store, dir) = test_store("v1");
        let c = chunk(1, b"legacy body");
        let wire = encode_stage_b_chunk(c.envelope()).expect("wire");
        let mut plaintext = Vec::new();
        plaintext.extend_from_slice(&c.id().get().to_le_bytes());
        plaintext.extend_from_slice(&wire); // v1: NO class byte
        let cipher = MemoryCipher::from_key([9u8; 32]); // test_store's key
        let sealed = cipher.seal(&plaintext).expect("seal"); // v1: NO aad
        let mut record = Vec::new();
        record.extend_from_slice(&RECORD_MAGIC);
        record.push(1); // v1 version byte
        record.extend_from_slice(&sealed);
        let name = PersistedStore::record_name(&record);
        std::fs::write(dir.join(&name), &record).expect("write v1 record");

        let loaded = store.load_all();
        assert!(loaded.chunks.is_empty(), "a v1 record never loads");
        assert_eq!(loaded.skipped_u32, 1, "counted as skipped, not silent");
        std::fs::remove_dir_all(&dir).ok();
    }

    /// P1-2 — a version-flipped v2 record, RENAMED to its new content-
    /// addressed name so the DL-3 filename gate passes, is still skipped:
    /// the header version gate rejects it, and the header-as-AAD binding
    /// would fail the tag even if a permissive parser accepted the header.
    #[test]
    fn version_flip_skips_even_with_rehashed_name() {
        let (store, dir) = test_store("verflip");
        let name = store
            .save_chunk(&chunk(1, b"body"), MemoryPrivacy::Private)
            .expect("save");
        let mut bytes = std::fs::read(dir.join(&name)).expect("read");
        std::fs::remove_file(dir.join(&name)).expect("rm original");
        bytes[4] = 3; // claim an unknown future version
        let renamed = PersistedStore::record_name(&bytes);
        std::fs::write(dir.join(&renamed), &bytes).expect("write flipped");

        let loaded = store.load_all();
        assert!(loaded.chunks.is_empty(), "flipped version never loads");
        assert_eq!(loaded.skipped_u32, 1);
        std::fs::remove_dir_all(&dir).ok();
    }

    /// P1-2 lifecycle — the owner class persists across a "restart" (a NEW
    /// store handle over the same dir + key), survives the fold, and gates
    /// the frontier: ONLY the explicit shareable record lists frontier-bound
    /// (IV2), while the owner's local surface sees both.
    #[test]
    fn class_persists_across_restart_and_gates_frontier() {
        use mnemos_b_memory::{TombstonePolicy, catalog_select, fold_index_classified};
        let (store, dir) = test_store("class");
        let pub_chunk = chunk(1, b"shareable knowledge");
        let prv_chunk = chunk(2, b"private secret thought");
        store
            .save_chunk(&pub_chunk, MemoryPrivacy::Shareable)
            .expect("save shareable");
        store
            .save_chunk(&prv_chunk, MemoryPrivacy::Private)
            .expect("save private");

        // Restart: a fresh handle over the same dir + key.
        let restarted = PersistedStore::with_dir(MemoryCipher::from_key([9u8; 32]), dir.clone());
        let loaded = restarted.load_all();
        assert_eq!(loaded.skipped_u32, 0);
        assert_eq!(
            loaded.chunks,
            vec![
                (pub_chunk, MemoryPrivacy::Shareable),
                (prv_chunk, MemoryPrivacy::Private)
            ],
            "classes survive the restart, id-sorted"
        );

        let policy = TombstonePolicy::new();
        let folded = fold_index_classified(loaded.chunks.iter().map(|(c, p)| (c, *p)), &policy);
        assert_eq!(folded.records.len(), 2);
        assert!(!folded.records[0].is_private(), "explicit shareable");
        assert!(folded.records[1].is_private(), "explicit private");
        assert!(
            folded.records.iter().all(|r| r.importance_u16() > 0),
            "live records carry a real Stage-D score"
        );

        let frontier: Vec<u64> = catalog_select(&folded.records, true)
            .iter()
            .map(|r| r.memory_id().get())
            .collect();
        assert_eq!(
            frontier,
            [1],
            "IV2: only the explicit shareable record lists frontier-bound"
        );
        assert_eq!(
            catalog_select(&folded.records, false).len(),
            2,
            "the owner's local surface sees both"
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    /// ENDGAME E1 — recall is LIVE + redacted from a REAL store. A
    /// save→restart→`load_all`→`fold_index_classified`→`run_agent_loop`
    /// round-trip (the EXACT path the dispatch consult executors use) proves
    /// the autonomous loop's `memory index`/`read` tools recall the owner's
    /// own PERSISTED memories — closing the stale "the live loop sees 0
    /// records" framing with a real run. IV2 holds (a private record never
    /// lists frontier-bound), and a secret-shaped record read on the recall
    /// path is WITHHELD + locks the loop down (SI-2 redaction on recall, from
    /// a real store). Zero egress: the transport is a scripted double.
    #[test]
    fn recall_loop_sees_real_persisted_store_and_redacts() {
        use crate::agent_loop::{
            AgentLoopStop, AgentTurn, FnTransport, MemoryToolState, run_agent_loop,
        };
        use mnemos_b_memory::{MemoryId, TombstonePolicy, fold_index_classified};

        // --- store A: a shareable + a private memory (the IV2 frontier gate) ---
        let (store, dir) = test_store("recall_a");
        store
            .save_chunk(
                &chunk(1, b"the owner ships sinabro 1.0"),
                MemoryPrivacy::Shareable,
            )
            .expect("s1");
        store
            .save_chunk(
                &chunk(2, b"private medical note about nothing"),
                MemoryPrivacy::Private,
            )
            .expect("s2");

        // Restart + load + fold — the EXACT dispatch wire (open→load_all→fold).
        let restarted = PersistedStore::with_dir(MemoryCipher::from_key([9u8; 32]), dir.clone());
        let loaded = restarted.load_all();
        assert_eq!(loaded.skipped_u32, 0);
        let policy = TombstonePolicy::new();
        let folded = fold_index_classified(loaded.chunks.iter().map(|(c, p)| (c, *p)), &policy);
        let loop_contents: Vec<(MemoryId, &[u8])> = loaded
            .chunks
            .iter()
            .map(|(c, _)| (c.id(), c.envelope().content.as_slice()))
            .collect();
        let state = MemoryToolState {
            records: &folded.records,
            contents: &loop_contents,
            policy: &policy,
        };

        // Recall happy path: index → read 1 → answer.
        let replies = std::cell::RefCell::new(vec![
            "TOOL: memory index".to_string(),
            "TOOL: memory read 1".to_string(),
            "ANSWER: done".to_string(),
        ]);
        let msgs = std::cell::RefCell::new(Vec::<String>::new());
        let mut transport = FnTransport(|_s: &str, user: &str| {
            msgs.borrow_mut().push(user.to_string());
            Ok(AgentTurn {
                answer_text: replies.borrow_mut().remove(0),
                input_tokens_u64: 10,
                output_tokens_u64: 5,
                cached_tokens_u64: 0,
            })
        });
        let outcome = run_agent_loop(&mut transport, &state, "sys", "what ships?");
        assert_eq!(outcome.stop, AgentLoopStop::Completed);
        assert_eq!(
            outcome.recalled_memory_ids(),
            vec![1],
            "the loop recalled the REAL saved shareable memory"
        );
        let all = msgs.borrow().join("\n");
        assert!(
            all.contains("id=1"),
            "shareable record listed in the live index"
        );
        assert!(
            !all.contains("id=2"),
            "IV2: the private record never lists frontier-bound"
        );
        assert!(
            all.contains("the owner ships sinabro 1.0"),
            "the verified persisted content reached the prompt"
        );
        assert!(
            !all.contains("medical note"),
            "private content never enters a frontier prompt"
        );
        std::fs::remove_dir_all(&dir).ok();

        // --- store B: a secret-shaped SHAREABLE memory; reading it withholds ---
        let (store_b, dir_b) = test_store("recall_b");
        store_b
            .save_chunk(
                &chunk(7, b"key = \"suiprivkey1qexamplenotreal\""),
                MemoryPrivacy::Shareable,
            )
            .expect("s7");
        let loaded_b = store_b.load_all();
        let folded_b = fold_index_classified(loaded_b.chunks.iter().map(|(c, p)| (c, *p)), &policy);
        let contents_b: Vec<(MemoryId, &[u8])> = loaded_b
            .chunks
            .iter()
            .map(|(c, _)| (c.id(), c.envelope().content.as_slice()))
            .collect();
        let state_b = MemoryToolState {
            records: &folded_b.records,
            contents: &contents_b,
            policy: &policy,
        };
        // Read the secret-shaped record directly (no index turn): the read is
        // withheld and the guard locks down before any further egress turn.
        let replies_b = std::cell::RefCell::new(vec![
            "TOOL: memory read 7".to_string(),
            "ANSWER: never-reached".to_string(),
        ]);
        let msgs_b = std::cell::RefCell::new(Vec::<String>::new());
        let calls = std::cell::Cell::new(0u8);
        let mut transport_b = FnTransport(|_s: &str, user: &str| {
            msgs_b.borrow_mut().push(user.to_string());
            calls.set(calls.get() + 1);
            Ok(AgentTurn {
                answer_text: replies_b.borrow_mut().remove(0),
                input_tokens_u64: 10,
                output_tokens_u64: 5,
                cached_tokens_u64: 0,
            })
        });
        let outcome_b = run_agent_loop(&mut transport_b, &state_b, "sys", "read it");
        assert_eq!(
            outcome_b.stop,
            AgentLoopStop::GuardLockdown,
            "a secret-shaped recall locks the loop down"
        );
        assert_eq!(
            calls.get(),
            1,
            "no further egress turn after the secret touch"
        );
        assert_eq!(outcome_b.reads_u8, 0, "a withheld read is not a recall");
        assert!(outcome_b.recalled_memory_ids().is_empty());
        assert!(
            !msgs_b.borrow().join("\n").contains("suiprivkey"),
            "secret bytes never enter a prompt"
        );
        std::fs::remove_dir_all(&dir_b).ok();
    }
}
