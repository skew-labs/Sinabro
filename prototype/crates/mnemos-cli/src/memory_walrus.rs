//! E14-W2 — the two-tier AUTONOMOUS Walrus memory hierarchy (owner-directed
//! 2026-06-13). The agent navigates a MAIN INDEX blob on Walrus — a manifest of
//! `(memory_id, topic, sub_blob_id)` for every memory — then fetches the matching
//! SUB-STORE blob (the encrypted detail of one memory) and uses it in a task.
//!
//! Secret-zero: the manifest is itself AEAD ciphertext (sealed with the local
//! `memory.key` via [`PersistedStore::seal_index`](crate::memory_store::PersistedStore::seal_index))
//! before it leaves the process, so topics + ids are opaque on the public testnet; only
//! a LOCAL decrypt reveals them. The sub-store blobs are the existing `.mc` AEAD records
//! (E14-W). NO funds / NO wallet (the publisher pays); custody / chain-write are
//! HARD-LOCKED (PD-6).
//!
//! This module is PURE (no network, no clock): the model + the byte codec + the topic
//! summarizer + the local pointer file. The publish/fetch glue is the
//! `put-fixture-net`-gated dispatch layer (where the Walrus transports live).

use std::path::{Path, PathBuf};

/// The local pointer file (under the data dir) holding the LATEST main-index Walrus
/// blob-id (base64url text). The agent reads it to find the current index; a new
/// backup overwrites it. NOT a secret (a blob-id is a public content address).
pub const MAIN_INDEX_POINTER_FILE: &str = "walrus_main_index.ref";

/// S3 (WALRUS_MAINNET_SELFHOST) — the local pointer file holding the latest MAINNET
/// self-host main-index blob-id. SEPARATE from the testnet pointer so the two networks
/// never collide (a testnet blob-id is not addressable on the mainnet aggregator and
/// vice-versa). The mainnet backup ceremony writes it; the auto-activate READ path uses
/// it when a self-host aggregator is configured. NOT a secret (a public content address).
pub const MAIN_INDEX_POINTER_MAINNET_FILE: &str = "walrus_main_index_mainnet.ref";

/// The sealed-manifest magic (4 bytes) — `WMIX` = Walrus Main IndeX.
pub const WALRUS_INDEX_MAGIC: [u8; 4] = *b"WMIX";

/// The manifest wire version (the first byte after the magic).
pub const WALRUS_INDEX_VERSION: u8 = 1;

/// The index AAD: the manifest seal binds this string, so an index blob can never be
/// opened as a `.mc` record (their AADs differ) and vice-versa.
pub const WALRUS_INDEX_AAD: &[u8] = b"sinabro.walrus.index.v1";

/// Max topic bytes carried per entry (a bounded single-line summary).
pub const WALRUS_TOPIC_CAP_BYTES: usize = 96;

/// One main-index entry: a memory's id, a bounded topic summary ("기억관련 내용"), and
/// the Walrus blob-id of its encrypted SUB-STORE detail.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WalrusMemEntry {
    /// The memory's stable id.
    pub memory_id: u64,
    /// A bounded, single-line summary of the memory (plaintext only INSIDE the
    /// later-encrypted index — never published raw).
    pub topic: String,
    /// The Walrus blob-id of this memory's encrypted `.mc` sub-store detail.
    pub sub_blob_id: String,
}

/// The MAIN INDEX: the manifest of every memory's `(id, topic, sub_blob_id)`. Encrypted
/// before publish; the agent fetches + decrypts it to navigate the sub-stores.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct WalrusMainIndex {
    /// The entries, in input order (the builder sorts by id).
    pub entries: Vec<WalrusMemEntry>,
}

/// Typed codec failures (fail-closed; no partial trust).
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
#[non_exhaustive]
pub enum WalrusIndexError {
    /// The bytes were shorter than a field demanded.
    Truncated,
    /// The 4-byte magic was not [`WALRUS_INDEX_MAGIC`].
    BadMagic,
    /// The version byte was not [`WALRUS_INDEX_VERSION`].
    UnknownVersion,
    /// A topic / blob-id field was not valid UTF-8.
    NotUtf8,
    /// Trailing garbage followed the last entry.
    TrailingBytes,
}

impl WalrusMainIndex {
    /// Canonical bytes: `magic | version | count(u32 LE) | [ id(u64 LE) |
    /// topic_len(u16 LE) | topic | blob_len(u16 LE) | blob ]*`. Deterministic.
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&WALRUS_INDEX_MAGIC);
        out.push(WALRUS_INDEX_VERSION);
        let count = u32::try_from(self.entries.len()).unwrap_or(u32::MAX);
        out.extend_from_slice(&count.to_le_bytes());
        for e in self.entries.iter().take(count as usize) {
            out.extend_from_slice(&e.memory_id.to_le_bytes());
            let topic = e.topic.as_bytes();
            let tlen = u16::try_from(topic.len()).unwrap_or(u16::MAX);
            out.extend_from_slice(&tlen.to_le_bytes());
            out.extend_from_slice(&topic[..tlen as usize]);
            let blob = e.sub_blob_id.as_bytes();
            let blen = u16::try_from(blob.len()).unwrap_or(u16::MAX);
            out.extend_from_slice(&blen.to_le_bytes());
            out.extend_from_slice(&blob[..blen as usize]);
        }
        out
    }

    /// Fail-closed decode (every length checked before consumed; trailing rejects).
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, WalrusIndexError> {
        let mut at = 0usize;
        let take = |at: &mut usize, n: usize| -> Result<&[u8], WalrusIndexError> {
            let end = at.checked_add(n).ok_or(WalrusIndexError::Truncated)?;
            if end > bytes.len() {
                return Err(WalrusIndexError::Truncated);
            }
            let slice = &bytes[*at..end];
            *at = end;
            Ok(slice)
        };
        if take(&mut at, 4)? != WALRUS_INDEX_MAGIC {
            return Err(WalrusIndexError::BadMagic);
        }
        if take(&mut at, 1)?[0] != WALRUS_INDEX_VERSION {
            return Err(WalrusIndexError::UnknownVersion);
        }
        let mut count_b = [0u8; 4];
        count_b.copy_from_slice(take(&mut at, 4)?);
        let count = u32::from_le_bytes(count_b) as usize;
        let mut entries = Vec::new();
        for _ in 0..count {
            let mut id_b = [0u8; 8];
            id_b.copy_from_slice(take(&mut at, 8)?);
            let memory_id = u64::from_le_bytes(id_b);
            let mut tl = [0u8; 2];
            tl.copy_from_slice(take(&mut at, 2)?);
            let topic = core::str::from_utf8(take(&mut at, u16::from_le_bytes(tl) as usize)?)
                .map_err(|_| WalrusIndexError::NotUtf8)?
                .to_string();
            let mut bl = [0u8; 2];
            bl.copy_from_slice(take(&mut at, 2)?);
            let sub_blob_id = core::str::from_utf8(take(&mut at, u16::from_le_bytes(bl) as usize)?)
                .map_err(|_| WalrusIndexError::NotUtf8)?
                .to_string();
            entries.push(WalrusMemEntry {
                memory_id,
                topic,
                sub_blob_id,
            });
        }
        if at != bytes.len() {
            return Err(WalrusIndexError::TrailingBytes);
        }
        Ok(Self { entries })
    }

    /// The sub-store blob-id for `memory_id`, if the index has an entry for it.
    #[must_use]
    pub fn sub_blob_for(&self, memory_id: u64) -> Option<&str> {
        self.entries
            .iter()
            .find(|e| e.memory_id == memory_id)
            .map(|e| e.sub_blob_id.as_str())
    }
}

/// A bounded, single-line topic summary of a memory's content (the main-index
/// "기억관련 내용"): control chars → spaces, whitespace collapsed, lossy-UTF-8, capped at
/// [`WALRUS_TOPIC_CAP_BYTES`] on a char boundary.
#[must_use]
pub fn summarize_topic(content: &[u8]) -> String {
    let text = String::from_utf8_lossy(content);
    let cleaned: String = text
        .chars()
        .map(|c| if c.is_control() { ' ' } else { c })
        .collect();
    let mut summary = cleaned.split_whitespace().collect::<Vec<_>>().join(" ");
    if summary.len() > WALRUS_TOPIC_CAP_BYTES {
        let mut end = WALRUS_TOPIC_CAP_BYTES;
        while end > 0 && !summary.is_char_boundary(end) {
            end -= 1;
        }
        summary.truncate(end);
    }
    if summary.is_empty() {
        summary.push_str("(empty)");
    }
    summary
}

/// The pointer-file path under a data dir.
#[must_use]
pub fn main_index_pointer_path(data_dir: &Path) -> PathBuf {
    data_dir.join(MAIN_INDEX_POINTER_FILE)
}

/// Read the latest main-index blob-id from the pointer file (trimmed). `None` if
/// absent / empty / unreadable.
#[must_use]
pub fn read_main_index_pointer(data_dir: &Path) -> Option<String> {
    let text = std::fs::read_to_string(main_index_pointer_path(data_dir)).ok()?;
    let trimmed = text.trim();
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed.to_string())
    }
}

/// Write the latest main-index blob-id to the pointer file (a public content address).
pub fn write_main_index_pointer(data_dir: &Path, blob_id: &str) -> std::io::Result<()> {
    std::fs::write(main_index_pointer_path(data_dir), blob_id.as_bytes())
}

/// S3 — the MAINNET self-host pointer path under a data dir.
#[must_use]
pub fn main_index_pointer_mainnet_path(data_dir: &Path) -> PathBuf {
    data_dir.join(MAIN_INDEX_POINTER_MAINNET_FILE)
}

/// S3 — read the latest MAINNET main-index blob-id from its pointer file (trimmed).
/// `None` if absent / empty / unreadable.
#[must_use]
pub fn read_main_index_pointer_mainnet(data_dir: &Path) -> Option<String> {
    let text = std::fs::read_to_string(main_index_pointer_mainnet_path(data_dir)).ok()?;
    let trimmed = text.trim();
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed.to_string())
    }
}

/// S3 — write the latest MAINNET main-index blob-id to its pointer file.
pub fn write_main_index_pointer_mainnet(data_dir: &Path, blob_id: &str) -> std::io::Result<()> {
    std::fs::write(
        main_index_pointer_mainnet_path(data_dir),
        blob_id.as_bytes(),
    )
}

/// E14-W2 + S3 — the feature-gated network navigation the AUTONOMOUS agent loop uses (and
/// the dispatch verbs share the same model). AUTO-ACTIVATE: when the owner has configured a
/// self-host AGGREGATOR (S2), the agent reads its MAINNET memory (mainnet pointer + the
/// self-host transport); otherwise it reads the testnet store (unchanged — zero behaviour
/// change when unconfigured). Off-build, the loop tool honest-degrades. NO funds.
#[cfg(feature = "put-fixture-net")]
mod net {
    use super::WalrusMainIndex;
    use crate::memory_store::PersistedStore;

    const WALRUS_TIMEOUT_MS: u32 = 30_000;

    /// GET a blob from the TESTNET aggregator by a STORED blob-id text. Bytes are UNTRUSTED
    /// until the AEAD open verifies the tag.
    fn walrus_get_testnet(blob_text: &str) -> Option<Vec<u8>> {
        use mnemos_c_walrus::aggregator::{
            AggregatorEndpoint, AggregatorGetRequest, AggregatorResponseDecision,
            fetch_blob_with_transport,
        };
        use mnemos_c_walrus::blob_id_from_text;
        use mnemos_c_walrus::reqwest_transport::ReqwestAggregator;
        let blob_id = blob_id_from_text(blob_text)?;
        let request = AggregatorGetRequest::new(AggregatorEndpoint::testnet_public(), &blob_id);
        let mut agg = ReqwestAggregator::new(WALRUS_TIMEOUT_MS).ok()?;
        match fetch_blob_with_transport(&mut agg, &request, 0x6713_0004, 2).ok()? {
            AggregatorResponseDecision::Fetched { body, .. } => Some(body),
            _ => None,
        }
    }

    /// S3 — GET a blob from the configured self-host (MAINNET) aggregator (READ-class,
    /// secret-zero). Bytes are UNTRUSTED until the AEAD open verifies the tag.
    #[cfg(feature = "walrus-mainnet")]
    fn walrus_get_mainnet(
        agg: &crate::provider::walrus_selfhost::SafeWalrusEndpoint,
        blob_text: &str,
    ) -> Option<Vec<u8>> {
        use crate::provider::walrus_selfhost::WalrusSelfHostTransport;
        let transport = WalrusSelfHostTransport::new()?;
        transport.get_blob(agg, blob_text).ok()
    }

    /// Read + decrypt the agent's MAIN INDEX from Walrus (pointer → GET → AEAD open → decode).
    /// `Err(reason)` fail-closed. AUTO-ROUTES to the configured self-host aggregator (mainnet)
    /// when set, else the testnet store. This is how the agent learns every memory's id + topic.
    pub fn load_main_index(store: &PersistedStore) -> Result<WalrusMainIndex, &'static str> {
        let dir = crate::memory_store::data_dir().map_err(|_| "no data dir")?;
        // AUTO-ACTIVATE: a configured self-host aggregator ⇒ the agent reads MAINNET memory.
        #[cfg(feature = "walrus-mainnet")]
        if let Some(agg) = crate::provider::walrus_selfhost::configured_walrus_aggregator() {
            let pointer = super::read_main_index_pointer_mainnet(&dir).ok_or(
                "no mainnet main-index pointer (run `memory backup-walrus-mainnet` first)",
            )?;
            let fetched = walrus_get_mainnet(&agg, &pointer)
                .ok_or("mainnet main index not fetched (self-host aggregator/propagation)")?;
            let plain = store
                .open_index(&fetched)
                .map_err(|_| "mainnet main index decrypt failed (wrong key / tampered)")?;
            return WalrusMainIndex::from_bytes(&plain)
                .map_err(|_| "mainnet main index decode failed");
        }
        // TESTNET (default / unconfigured) — unchanged.
        let pointer = super::read_main_index_pointer(&dir)
            .ok_or("no main-index pointer (run `memory backup-walrus` first)")?;
        let fetched = walrus_get_testnet(&pointer)
            .ok_or("main index not fetched from Walrus (propagation/boundary)")?;
        let plain = store
            .open_index(&fetched)
            .map_err(|_| "main index decrypt failed (wrong key / tampered)")?;
        WalrusMainIndex::from_bytes(&plain).map_err(|_| "main index decode failed")
    }

    /// Enter the SUB-STORE for `memory_id` (via the MAIN INDEX), fetch the encrypted detail
    /// from Walrus, and DECRYPT it locally → the raw content text. `Err(reason)` fail-closed.
    /// AUTO-ROUTES the sub-GET to the SAME source (mainnet/testnet) as the index. The caller
    /// redact-belts the result before it reaches the frontier.
    pub fn fetch_sub_content(
        store: &PersistedStore,
        memory_id: u64,
    ) -> Result<String, &'static str> {
        let index = load_main_index(store)?;
        let sub_blob = index
            .sub_blob_for(memory_id)
            .ok_or("id not in the MAIN INDEX")?
            .to_string();
        // AUTO-ACTIVATE: fetch the sub-store from the same network the index came from.
        #[cfg(feature = "walrus-mainnet")]
        if let Some(agg) = crate::provider::walrus_selfhost::configured_walrus_aggregator() {
            let fetched = walrus_get_mainnet(&agg, &sub_blob)
                .ok_or("mainnet sub-store not fetched (self-host aggregator/propagation)")?;
            let (chunk, _privacy) = store
                .decode_record(&fetched)
                .ok_or("mainnet sub-store decrypt/decode failed (wrong key / tampered)")?;
            return Ok(String::from_utf8_lossy(chunk.envelope().content.as_slice()).to_string());
        }
        let fetched =
            walrus_get_testnet(&sub_blob).ok_or("sub-store not fetched (propagation/boundary)")?;
        let (chunk, _privacy) = store
            .decode_record(&fetched)
            .ok_or("sub-store decrypt/decode failed (wrong key / tampered)")?;
        Ok(String::from_utf8_lossy(chunk.envelope().content.as_slice()).to_string())
    }
}

#[cfg(feature = "put-fixture-net")]
pub use net::{fetch_sub_content, load_main_index};

#[cfg(test)]
mod tests {
    use super::*;

    fn idx() -> WalrusMainIndex {
        WalrusMainIndex {
            entries: vec![
                WalrusMemEntry {
                    memory_id: 0,
                    topic: "delta-neutral funding harvester notes".to_string(),
                    sub_blob_id: "cZWixH4naNATvO4P2IzANkBX7RdJt3nFyCFeZ1SSIks".to_string(),
                },
                WalrusMemEntry {
                    memory_id: 7,
                    topic: "sui move audit — bug bounty 분야".to_string(),
                    sub_blob_id: "KzXL8IANxQocPkWDuYJPmFwsVL3Sp5dSDvu874Qi-Ew".to_string(),
                },
            ],
        }
    }

    #[test]
    fn index_round_trips_and_finds_sub_blob() {
        let i = idx();
        let bytes = i.to_bytes();
        let back = WalrusMainIndex::from_bytes(&bytes).expect("decode");
        assert_eq!(back, i);
        assert_eq!(
            back.sub_blob_for(7),
            Some("KzXL8IANxQocPkWDuYJPmFwsVL3Sp5dSDvu874Qi-Ew")
        );
        assert_eq!(back.sub_blob_for(99), None);
    }

    #[test]
    fn index_decode_is_fail_closed() {
        assert_eq!(
            WalrusMainIndex::from_bytes(&[]),
            Err(WalrusIndexError::Truncated)
        );
        assert_eq!(
            WalrusMainIndex::from_bytes(b"XXXX\x01\x00\x00\x00\x00"),
            Err(WalrusIndexError::BadMagic)
        );
        // right magic, wrong version
        let mut bad = WALRUS_INDEX_MAGIC.to_vec();
        bad.push(9);
        bad.extend_from_slice(&0u32.to_le_bytes());
        assert_eq!(
            WalrusMainIndex::from_bytes(&bad),
            Err(WalrusIndexError::UnknownVersion)
        );
        // valid empty index + a trailing byte ⇒ TrailingBytes
        let mut t = WalrusMainIndex::default().to_bytes();
        t.push(0xff);
        assert_eq!(
            WalrusMainIndex::from_bytes(&t),
            Err(WalrusIndexError::TrailingBytes)
        );
    }

    #[test]
    fn summarize_topic_is_single_line_and_capped() {
        let s = summarize_topic(b"first line\nsecond line\t\tlots   of   space");
        assert!(!s.contains('\n') && !s.contains('\t'));
        assert_eq!(s, "first line second line lots of space");
        let long = "x".repeat(500);
        let capped = summarize_topic(long.as_bytes());
        assert!(capped.len() <= WALRUS_TOPIC_CAP_BYTES);
        assert_eq!(summarize_topic(b""), "(empty)");
    }
}
