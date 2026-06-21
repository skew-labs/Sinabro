//! `memory list / query / root / anchor / status / backend` read commands
//! (F-WP-05B, atom #443 · F.5.0).
//!
//! These are read-only projections over canonical `b-memory` truth. The Stage F
//! privacy rule is structural: **raw private content is never shown by default** —
//! `memory list` and `memory query` expose only redacted summaries (a content
//! digest prefix + length + tier), and [`MemoryListView::raw_content_visible`] /
//! [`MemoryQueryResult::raw_content_visible`] are always `false`. `memory root`
//! surfaces the auditable, non-secret facts the user is entitled to see: the
//! memory root hash, the Stage B replay cursor, the StorageBackend receipt, the
//! owner (redacted), the Sui anchor state, and the tombstone count.

use super::memory_setup::MemoryBackendReceiptView;
use crate::{hex32, sha256_32};
use mnemos_b_memory::{
    MemoryTier, ReplayCursor, SigningPublicKey, StageBTranscriptHash32, StorageObjectRef,
    TombstonePolicy,
};

/// First 16 hex characters of a 32-byte digest — a redacted, display-only prefix.
#[must_use]
fn redact16(bytes: &[u8; 32]) -> String {
    hex32(bytes).chars().take(16).collect()
}

/// The Sui anchor state of a memory root, for display only. No variant performs a
/// live RPC / mainnet action; an anchored state is a read-only fact.
#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SuiAnchorState {
    /// The root is not anchored on Sui.
    NotAnchored = 1,
    /// The root is anchored on Sui testnet.
    AnchoredTestnet = 2,
    /// The root carries a Stage C mainnet-gate anchor (read-only provenance).
    AnchoredMainnetGate = 3,
}

impl SuiAnchorState {
    /// Stable u8 tag.
    #[must_use]
    pub const fn tag(self) -> u8 {
        self as u8
    }
}

/// One redacted row in a `memory list` / `memory query` result. Carries a content
/// digest prefix and length, **never** the raw content bytes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MemorySummaryRow {
    /// The memory id.
    pub memory_id_u64: u64,
    /// Redacted 16-hex prefix of the content digest (never the content itself).
    pub content_redaction_hash: String,
    /// Content length in bytes (size is admissible; content is not).
    pub content_len_u32: u32,
    /// The memory's compaction tier tag.
    pub tier_u8: u8,
}

impl MemorySummaryRow {
    /// Build a redacted row from raw content: the content is hashed and discarded,
    /// only the digest prefix + length + tier survive.
    #[must_use]
    pub fn redacted(memory_id_u64: u64, raw_content: &[u8], tier: MemoryTier) -> Self {
        let content_len_u32 = u32::try_from(raw_content.len()).unwrap_or(u32::MAX);
        Self {
            memory_id_u64,
            content_redaction_hash: redact16(&sha256_32(raw_content)),
            content_len_u32,
            tier_u8: tier.tag(),
        }
    }

    /// The single redacted display line for this row.
    #[must_use]
    pub fn render_line(&self) -> String {
        format!(
            "id={} redaction={} len={} tier_u8={}",
            self.memory_id_u64, self.content_redaction_hash, self.content_len_u32, self.tier_u8
        )
    }
}

/// A `memory list` projection: redacted summaries only.
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct MemoryListView {
    rows: Vec<MemorySummaryRow>,
}

impl MemoryListView {
    /// Construct a list view over redacted rows.
    #[must_use]
    pub fn new(rows: Vec<MemorySummaryRow>) -> Self {
        Self { rows }
    }

    /// Borrow the redacted rows.
    #[must_use]
    pub fn rows(&self) -> &[MemorySummaryRow] {
        &self.rows
    }

    /// Whether raw private content is shown — always `false` by default in Stage F.
    #[must_use]
    pub const fn raw_content_visible(&self) -> bool {
        false
    }

    /// Redacted, colorless list lines bounded by `rows`.
    #[must_use]
    pub fn render(&self, rows: u16) -> Vec<String> {
        self.rows
            .iter()
            .map(MemorySummaryRow::render_line)
            .take(rows as usize)
            .collect()
    }
}

/// A `memory query` result: the query is hashed for the trace, and the matches are
/// redacted summaries — raw content is never returned.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MemoryQueryResult {
    /// Redacted 16-hex prefix of the query digest.
    pub query_redaction_hash: String,
    matches: Vec<MemorySummaryRow>,
}

impl MemoryQueryResult {
    /// Build a redacted query result from the raw query text and the matched rows.
    #[must_use]
    pub fn redacted(raw_query: &str, matches: Vec<MemorySummaryRow>) -> Self {
        Self {
            query_redaction_hash: redact16(&sha256_32(raw_query.as_bytes())),
            matches,
        }
    }

    /// Borrow the redacted matches.
    #[must_use]
    pub fn matches(&self) -> &[MemorySummaryRow] {
        &self.matches
    }

    /// Whether raw private content is shown — always `false`.
    #[must_use]
    pub const fn raw_content_visible(&self) -> bool {
        false
    }

    /// Redacted, colorless result lines bounded by `rows`.
    #[must_use]
    pub fn render(&self, rows: u16) -> Vec<String> {
        let mut lines = vec![format!("query={}", self.query_redaction_hash)];
        lines.extend(self.matches.iter().map(MemorySummaryRow::render_line));
        lines.into_iter().take(rows as usize).collect()
    }
}

/// Why a memory read command was refused (fail-closed).
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum MemoryQueryReject {
    /// The claimed owner does not match the memory root's owner.
    #[error("owner mismatch")]
    OwnerMismatch,
}

/// A `memory root` projection: the auditable, non-secret facts of a memory root.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MemoryRootView {
    owner_key_32: [u8; 32],
    /// Redacted 16-hex prefix of the owner public key.
    pub owner_redacted: String,
    /// Redacted 16-hex prefix of the root content hash.
    pub root_hash_redacted: String,
    /// Redacted 16-hex prefix of the Stage B replay transcript hash.
    pub transcript_redacted: String,
    /// Count of unique anchors recovered by replay (the replay cursor).
    pub replay_recovered_u32: u32,
    /// Count of tombstoned (deleted) memories.
    pub tombstone_count_u64: u64,
    /// The Sui anchor state (display only).
    pub anchor_state: SuiAnchorState,
    /// The StorageBackend receipt for the root's primary backend.
    pub backend: MemoryBackendReceiptView,
}

impl MemoryRootView {
    /// Project a memory root from its canonical pieces: the owner key, the root
    /// [`StorageObjectRef`], the Stage B [`StageBTranscriptHash32`], the
    /// [`ReplayCursor`], the [`TombstonePolicy`] (for the tombstone count), and the
    /// Sui anchor state.
    #[must_use]
    pub fn new(
        owner: &SigningPublicKey,
        root: &StorageObjectRef,
        transcript: &StageBTranscriptHash32,
        replay: ReplayCursor,
        tombstones: &TombstonePolicy,
        anchor: SuiAnchorState,
    ) -> Self {
        let owner_key_32 = *owner.as_bytes();
        Self {
            owner_key_32,
            owner_redacted: redact16(&owner_key_32),
            root_hash_redacted: redact16(root.content_hash_32()),
            transcript_redacted: redact16(transcript.as_bytes()),
            replay_recovered_u32: replay.recovered_u32(),
            tombstone_count_u64: tombstones.len() as u64,
            anchor_state: anchor,
            backend: MemoryBackendReceiptView::from_object_ref(root),
        }
    }

    /// Whether the root's Walrus blob evidence is missing (a future-only / local
    /// backend with no verified blob id).
    #[must_use]
    pub fn blob_missing(&self) -> bool {
        !self.backend.has_walrus_evidence()
    }

    /// Whether `claimed` is the owner of this root.
    #[must_use]
    pub fn owner_matches(&self, claimed: &SigningPublicKey) -> bool {
        &self.owner_key_32 == claimed.as_bytes()
    }

    /// Redacted, colorless root lines bounded by `rows`.
    #[must_use]
    pub fn render(&self, rows: u16) -> Vec<String> {
        let mut lines = vec![
            format!("owner={}", self.owner_redacted),
            format!("root_hash={}", self.root_hash_redacted),
            format!("transcript={}", self.transcript_redacted),
            format!("replay_recovered={}", self.replay_recovered_u32),
            format!("tombstone_count={}", self.tombstone_count_u64),
            format!("anchor_state_u8={}", self.anchor_state.tag()),
            format!("blob_missing={}", self.blob_missing()),
        ];
        lines.extend(self.backend.render(rows));
        lines.into_iter().take(rows as usize).collect()
    }
}

/// Verify that `claimed` owns `root`, returning [`MemoryQueryReject::OwnerMismatch`]
/// otherwise. Used by owner-scoped read commands so a memory is shown only to its
/// owner.
pub fn verify_owner(
    claimed: &SigningPublicKey,
    root: &MemoryRootView,
) -> Result<(), MemoryQueryReject> {
    if root.owner_matches(claimed) {
        Ok(())
    } else {
        Err(MemoryQueryReject::OwnerMismatch)
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    #![allow(clippy::expect_used)]
    #![allow(clippy::panic)]

    use super::*;
    use mnemos_b_memory::stage_b_transcript_hash;
    use mnemos_b_memory::{DeleteSemantics, MemoryId, StorageBackendKind, StorageBackendRole};
    use mnemos_c_walrus::{
        PublisherReportedBlobId, VerifiedBlobId, derive_blob_id, verify_reported_blob_id,
    };

    const COMMERCE_TOKENS: &[&str] = &[
        "price", "pay", "buy", "sell", "checkout", "refund", "fee", "cost", "$",
    ];

    fn encode_b64url(raw: &[u8; 32]) -> String {
        const ALPHABET: &[u8; 64] =
            b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
        let mut out = String::with_capacity(43);
        let mut buf: u32 = 0;
        let mut bits: u32 = 0;
        for &b in raw {
            buf = (buf << 8) | u32::from(b);
            bits += 8;
            while bits >= 6 {
                bits -= 6;
                let v = ((buf >> bits) & 0x3F) as usize;
                out.push(ALPHABET[v] as char);
            }
        }
        if bits > 0 {
            let v = ((buf << (6 - bits)) & 0x3F) as usize;
            out.push(ALPHABET[v] as char);
        }
        out
    }

    fn verified_blob(seed: &[u8]) -> VerifiedBlobId {
        let derived = derive_blob_id(seed);
        let text = encode_b64url(derived.as_bytes());
        let reported = PublisherReportedBlobId::try_from_text(&text).expect("base64url length 43");
        verify_reported_blob_id(seed, &reported).expect("self-derived round-trip must verify")
    }

    fn owner(b: u8) -> SigningPublicKey {
        SigningPublicKey::from_bytes(&[b; 32]).expect("32-byte owner key")
    }

    fn walrus_root() -> StorageObjectRef {
        StorageObjectRef::walrus_primary([0x11; 32], verified_blob(b"root-blob"))
    }

    fn tombstones(n: u8) -> TombstonePolicy {
        let mut p = TombstonePolicy::new();
        for i in 0..n {
            p.record(MemoryId::new(u64::from(i) + 1), DeleteSemantics::Tombstone);
        }
        p
    }

    #[test]
    fn list_redaction_hides_raw_content() {
        let raw = b"my private memory content that must never be shown";
        let row = MemorySummaryRow::redacted(1, raw, MemoryTier::Recent);
        let view = MemoryListView::new(vec![row]);
        assert!(!view.raw_content_visible());
        for line in view.render(16) {
            assert!(
                !line.contains("private memory content"),
                "raw content leaked: {line}"
            );
        }
    }

    #[test]
    fn query_redaction_hides_raw_content() {
        let raw = b"secret fact about the user";
        let result = MemoryQueryResult::redacted(
            "what does the user like",
            vec![MemorySummaryRow::redacted(2, raw, MemoryTier::Mid)],
        );
        assert!(!result.raw_content_visible());
        for line in result.render(16) {
            assert!(!line.contains("secret fact"), "raw content leaked: {line}");
            assert!(
                !line.contains("what does the user like"),
                "raw query leaked: {line}"
            );
        }
    }

    #[test]
    fn root_display_shows_auditable_facts() {
        let transcript = stage_b_transcript_hash(b"root-transcript");
        let replay = ReplayCursor::from_replay(&[MemoryId::new(1), MemoryId::new(2)]);
        let root = MemoryRootView::new(
            &owner(0xAB),
            &walrus_root(),
            &transcript,
            replay,
            &tombstones(3),
            SuiAnchorState::AnchoredTestnet,
        );
        assert_eq!(root.replay_recovered_u32, 2);
        assert_eq!(root.tombstone_count_u64, 3);
        assert_eq!(root.anchor_state, SuiAnchorState::AnchoredTestnet);
        assert!(!root.blob_missing());
        let lines = root.render(32);
        assert!(lines.iter().any(|l| l.contains("replay_recovered=2")));
        assert!(lines.iter().any(|l| l.contains("tombstone_count=3")));
    }

    #[test]
    fn backend_status_present_in_root() {
        let transcript = stage_b_transcript_hash(b"t");
        let root = MemoryRootView::new(
            &owner(1),
            &walrus_root(),
            &transcript,
            ReplayCursor::start(),
            &TombstonePolicy::new(),
            SuiAnchorState::AnchoredTestnet,
        );
        assert!(root.backend.has_walrus_evidence());
        assert!(root.backend.live_writer);
    }

    #[test]
    fn anchor_status_tags() {
        assert_eq!(SuiAnchorState::NotAnchored.tag(), 1);
        assert_eq!(SuiAnchorState::AnchoredTestnet.tag(), 2);
        assert_eq!(SuiAnchorState::AnchoredMainnetGate.tag(), 3);
    }

    #[test]
    fn missing_blob_flagged() {
        let transcript = stage_b_transcript_hash(b"t");
        let future_root = StorageObjectRef::future_only(
            StorageBackendKind::IpfsMirror,
            StorageBackendRole::Mirror,
            [0x77; 32],
        );
        let root = MemoryRootView::new(
            &owner(1),
            &future_root,
            &transcript,
            ReplayCursor::start(),
            &TombstonePolicy::new(),
            SuiAnchorState::NotAnchored,
        );
        assert!(root.blob_missing());
    }

    #[test]
    fn owner_mismatch_rejected() {
        let transcript = stage_b_transcript_hash(b"t");
        let root = MemoryRootView::new(
            &owner(0xAA),
            &walrus_root(),
            &transcript,
            ReplayCursor::start(),
            &TombstonePolicy::new(),
            SuiAnchorState::AnchoredTestnet,
        );
        assert!(verify_owner(&owner(0xAA), &root).is_ok());
        assert_eq!(
            verify_owner(&owner(0xBB), &root),
            Err(MemoryQueryReject::OwnerMismatch)
        );
    }

    #[test]
    fn tombstone_count_reflects_policy() {
        let transcript = stage_b_transcript_hash(b"t");
        let root = MemoryRootView::new(
            &owner(1),
            &walrus_root(),
            &transcript,
            ReplayCursor::start(),
            &tombstones(5),
            SuiAnchorState::AnchoredTestnet,
        );
        assert_eq!(root.tombstone_count_u64, 5);
    }

    #[test]
    fn no_commerce_render() {
        let transcript = stage_b_transcript_hash(b"t");
        let root = MemoryRootView::new(
            &owner(1),
            &walrus_root(),
            &transcript,
            ReplayCursor::start(),
            &tombstones(1),
            SuiAnchorState::AnchoredTestnet,
        );
        let list = MemoryListView::new(vec![MemorySummaryRow::redacted(
            1,
            b"x",
            MemoryTier::Recent,
        )]);
        for line in root.render(32).into_iter().chain(list.render(32)) {
            for bad in COMMERCE_TOKENS {
                assert!(!line.contains(bad), "commerce token {bad} in: {line}");
            }
        }
    }
}
