//! `sinabro setup memory` wizard + StorageBackend receipt projection (F-WP-05B,
//! atom #443 · F.5.0).
//!
//! The first-run memory wizard separates four user-owned axes — memory owner
//! identity, storage mode, gas sponsor mode, and privacy/learning mode — so the
//! user explicitly chooses where their memory lives and who pays to anchor it.
//! Three Stage F invariants are structural here:
//!
//! * **Seed phrase input is rejected.** Owner identity is bound from a public key
//!   only; a seed-phrase-shaped free-text input is refused
//!   ([`MemorySetupReject::SeedPhraseRejected`]) so the CLI never holds key
//!   material.
//! * **Owner is never the sponsor.** The Sinabro server / Gas Station key cannot
//!   become the memory owner, and the memory-owner authority is never merged with
//!   the sponsor gas authority ([`MemorySetupReject::OwnerIsSponsor`]).
//! * **IPFS / Filecoin are dry-run / future-only.** A non-Walrus mirror/archive
//!   backend is admissible as a label but has no live writer in Stage F
//!   ([`StorageBackendPhase::FutureOnly`] => [`MemoryBackendReceiptView::live_writer`]
//!   is `false`).
//!
//! Every type is a read-only projection over the canonical `b-memory` storage
//! truth ([`StorageObjectRef`] / [`StorageBackendKind`] / [`StorageWritePlan`]);
//! nothing here mutates a memory, signs, or touches the network.

use crate::command::{ApprovalRequirement, CommandRisk, approval_for};
use crate::{hex32, sha256_32};
use mnemos_b_memory::{
    StorageBackendKind, StorageBackendPhase, StorageBackendRole, StorageObjectRef, StorageWritePlan,
};

/// First 16 hex characters of a 32-byte digest — a redacted, display-only prefix
/// that never reveals a full key or content hash.
#[must_use]
fn redact16(bytes: &[u8; 32]) -> String {
    hex32(bytes).chars().take(16).collect()
}

/// The storage backend mode chosen in the memory setup wizard. Each maps to a
/// canonical [`StorageBackendKind`]: only Walrus has a live writer in Stage F;
/// IPFS mirror and Filecoin archive are dry-run only.
#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MemoryStorageMode {
    /// Local-only: on-device encrypted storage, no network backend.
    LocalOnly = 1,
    /// Walrus testnet primary backend (the only live writer in Stage F).
    WalrusTestnet = 2,
    /// Walrus primary + IPFS mirror, where the IPFS mirror is dry-run only.
    WalrusIpfsMirrorDryRun = 3,
    /// Walrus primary + Filecoin archive, where the archive is dry-run only.
    WalrusFilecoinArchiveDryRun = 4,
}

impl MemoryStorageMode {
    /// Stable u8 tag.
    #[must_use]
    pub const fn tag(self) -> u8 {
        self as u8
    }

    /// The canonical primary [`StorageBackendKind`] for this mode.
    #[must_use]
    pub const fn primary_kind(self) -> StorageBackendKind {
        match self {
            Self::LocalOnly => StorageBackendKind::LocalEncrypted,
            Self::WalrusTestnet
            | Self::WalrusIpfsMirrorDryRun
            | Self::WalrusFilecoinArchiveDryRun => StorageBackendKind::Walrus,
        }
    }

    /// The optional secondary (mirror/archive) backend kind for this mode; `None`
    /// for local-only and plain Walrus. The secondary is always a `FutureOnly`
    /// label with no Stage F live writer.
    #[must_use]
    pub const fn secondary_kind(self) -> Option<StorageBackendKind> {
        match self {
            Self::WalrusIpfsMirrorDryRun => Some(StorageBackendKind::IpfsMirror),
            Self::WalrusFilecoinArchiveDryRun => Some(StorageBackendKind::FilecoinArchive),
            Self::LocalOnly | Self::WalrusTestnet => None,
        }
    }

    /// Whether this mode carries a dry-run-only secondary (IPFS/Filecoin).
    #[must_use]
    pub const fn has_dry_run_secondary(self) -> bool {
        self.secondary_kind().is_some()
    }
}

/// Who pays gas for memory anchoring. The memory owner authority and the sponsor
/// gas authority are NEVER the same key (atom #443 separation rule).
#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GasSponsorMode {
    /// The memory owner funds their own anchoring gas.
    SelfFunded = 1,
    /// A hosted sponsor (Sinabro server / Gas Station) pays gas but never owns the
    /// memory.
    HostedSponsor = 2,
    /// No sponsor: anchoring is offline / dry-run only.
    NoneOffline = 3,
}

impl GasSponsorMode {
    /// Stable u8 tag.
    #[must_use]
    pub const fn tag(self) -> u8 {
        self as u8
    }
}

/// Privacy / learning posture chosen in the wizard. Stage F default is fully
/// private: learning off, egress none. The wizard cannot enable training.
#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PrivacyLearningMode {
    /// Private: learning off, egress none (the Stage F default).
    PrivateLearningOff = 1,
    /// Local-learning-only opt-in: still no external egress, never training in
    /// Stage F (advisory posture only).
    LocalLearningOnly = 2,
}

impl PrivacyLearningMode {
    /// Stable u8 tag.
    #[must_use]
    pub const fn tag(self) -> u8 {
        self as u8
    }

    /// Whether this is the private, learning-off Stage F default.
    #[must_use]
    pub const fn is_private_default(self) -> bool {
        matches!(self, Self::PrivateLearningOff)
    }
}

/// Why the memory setup wizard refused an input (fail-closed).
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum MemorySetupReject {
    /// A seed-phrase-shaped secret was entered; owner identity is bound from a
    /// public key only, never a seed phrase.
    #[error("seed phrase input rejected")]
    SeedPhraseRejected,
    /// The chosen memory owner is the same key as the gas sponsor; owner and
    /// sponsor authority must stay separate.
    #[error("memory owner cannot also be the gas sponsor")]
    OwnerIsSponsor,
}

/// Whether `input` looks like a BIP-39-style seed phrase (a run of 12/15/18/21/24
/// lowercase space-separated words). Used to refuse seed-phrase entry in the owner
/// step — the CLI binds identity from a public key, never key material.
#[must_use]
pub fn looks_like_seed_phrase(input: &str) -> bool {
    let words: Vec<&str> = input.split_whitespace().collect();
    let plausible_len = matches!(words.len(), 12 | 15 | 18 | 21 | 24);
    plausible_len
        && words
            .iter()
            .all(|w| w.len() >= 3 && w.chars().all(|c| c.is_ascii_lowercase()))
}

/// The first-run memory setup wizard state: the four separated user-owned axes.
/// Constructed via [`MemorySetupWizard::configure`], which fails closed if the
/// owner is the sponsor.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MemorySetupWizard {
    owner_key_32: [u8; 32],
    sponsor_key_32: Option<[u8; 32]>,
    storage_mode: MemoryStorageMode,
    sponsor_mode: GasSponsorMode,
    privacy_mode: PrivacyLearningMode,
}

impl MemorySetupWizard {
    /// Configure the wizard from an owner public key (32 bytes), an optional
    /// sponsor public key, and the three mode choices. Fails closed with
    /// [`MemorySetupReject::OwnerIsSponsor`] when a sponsor key equals the owner
    /// key. The owner key is taken as raw public-key bytes — never a seed phrase
    /// (use [`looks_like_seed_phrase`] / [`configure_from_input`] to pre-screen
    /// any free-text owner input).
    pub fn configure(
        owner_key_32: [u8; 32],
        sponsor_key_32: Option<[u8; 32]>,
        storage_mode: MemoryStorageMode,
        sponsor_mode: GasSponsorMode,
        privacy_mode: PrivacyLearningMode,
    ) -> Result<Self, MemorySetupReject> {
        if let Some(sponsor) = sponsor_key_32 {
            if sponsor == owner_key_32 {
                return Err(MemorySetupReject::OwnerIsSponsor);
            }
        }
        Ok(Self {
            owner_key_32,
            sponsor_key_32,
            storage_mode,
            sponsor_mode,
            privacy_mode,
        })
    }

    /// Configure the wizard from free-text owner input, refusing a seed phrase
    /// before anything else. `owner_key_32` is the already-derived public key;
    /// `raw_owner_input` is the text the user typed, screened for seed-phrase
    /// shape.
    pub fn configure_from_input(
        raw_owner_input: &str,
        owner_key_32: [u8; 32],
        sponsor_key_32: Option<[u8; 32]>,
        storage_mode: MemoryStorageMode,
        sponsor_mode: GasSponsorMode,
        privacy_mode: PrivacyLearningMode,
    ) -> Result<Self, MemorySetupReject> {
        if looks_like_seed_phrase(raw_owner_input) {
            return Err(MemorySetupReject::SeedPhraseRejected);
        }
        Self::configure(
            owner_key_32,
            sponsor_key_32,
            storage_mode,
            sponsor_mode,
            privacy_mode,
        )
    }

    /// The chosen storage mode.
    #[must_use]
    pub const fn storage_mode(&self) -> MemoryStorageMode {
        self.storage_mode
    }

    /// The chosen gas sponsor mode.
    #[must_use]
    pub const fn sponsor_mode(&self) -> GasSponsorMode {
        self.sponsor_mode
    }

    /// The chosen privacy / learning mode.
    #[must_use]
    pub const fn privacy_mode(&self) -> PrivacyLearningMode {
        self.privacy_mode
    }

    /// Whether the memory owner is separate from the gas sponsor (always `true` by
    /// construction — [`configure`](Self::configure) rejects an owner==sponsor
    /// key).
    #[must_use]
    pub fn owner_is_not_sponsor(&self) -> bool {
        match self.sponsor_key_32 {
            Some(s) => s != self.owner_key_32,
            None => true,
        }
    }

    /// The command risk of committing this setup (it writes local config).
    #[must_use]
    pub const fn risk(&self) -> CommandRisk {
        CommandRisk::LocalWrite
    }

    /// The approval requirement for committing this setup, via the canonical
    /// closed mapping (Confirm).
    #[must_use]
    pub fn approval(&self) -> ApprovalRequirement {
        approval_for(self.risk())
    }

    /// Redacted, colorless setup summary lines (no key material, no commerce
    /// field, bounded by `rows`).
    #[must_use]
    pub fn render(&self, rows: u16) -> Vec<String> {
        let sponsor = match self.sponsor_key_32 {
            Some(s) => redact16(&s),
            None => "none".to_string(),
        };
        let lines = vec![
            format!("owner={}", redact16(&self.owner_key_32)),
            format!("sponsor={sponsor}"),
            format!("owner_is_not_sponsor={}", self.owner_is_not_sponsor()),
            format!("storage_mode_u8={}", self.storage_mode.tag()),
            format!(
                "primary_backend_u8={}",
                self.storage_mode.primary_kind().tag()
            ),
            format!(
                "dry_run_secondary={}",
                self.storage_mode.has_dry_run_secondary()
            ),
            format!("sponsor_mode_u8={}", self.sponsor_mode.tag()),
            format!("privacy_mode_u8={}", self.privacy_mode.tag()),
            format!(
                "learning_private_default={}",
                self.privacy_mode.is_private_default()
            ),
            format!("approval_u8={}", self.approval() as u8),
        ];
        lines.into_iter().take(rows as usize).collect()
    }
}

/// A read-only projection of a canonical [`StorageObjectRef`] (or
/// [`StorageWritePlan`]): the StorageBackend receipt the user inspects. Shows the
/// backend triple, the redacted content hash, whether Walrus blob evidence is
/// present, and whether a live writer exists in Stage F.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MemoryBackendReceiptView {
    /// Primary backend kind tag.
    pub backend_kind_u8: u8,
    /// Backend role tag.
    pub role_u8: u8,
    /// Backend lifecycle phase tag.
    pub phase_u8: u8,
    /// Redacted 16-hex prefix of the 32-byte content hash / posture digest.
    pub content_hash_redacted: String,
    /// Redacted 16-hex prefix of the verified Walrus blob id, when present.
    pub walrus_blob_evidence: Option<String>,
    /// Whether a live writer exists for this backend in Stage F (only Walrus
    /// `Enabled`); IPFS/Filecoin `FutureOnly` => `false`.
    pub live_writer: bool,
}

impl MemoryBackendReceiptView {
    /// Project a [`StorageObjectRef`]. Walrus blob evidence is the redacted blob
    /// id when the ref carries one (Walrus primary), `None` otherwise (a missing
    /// blob / future-only backend).
    #[must_use]
    pub fn from_object_ref(obj: &StorageObjectRef) -> Self {
        let walrus_blob_evidence = obj
            .walrus_blob()
            .map(|vb| redact16(vb.as_blob_id().as_bytes()));
        Self {
            backend_kind_u8: obj.backend().tag(),
            role_u8: obj.role().tag(),
            phase_u8: obj.phase().tag(),
            content_hash_redacted: redact16(obj.content_hash_32()),
            walrus_blob_evidence,
            live_writer: matches!(obj.phase(), StorageBackendPhase::Enabled),
        }
    }

    /// Project a borrowed [`StorageWritePlan`] persistence manifest (the form
    /// `b-memory` emits at plan time). Reuse-only: the plan has no public
    /// constructor outside `b-memory`, so this path is exercised by real code, not
    /// a unit fixture (the unit tests use [`from_object_ref`](Self::from_object_ref)).
    /// The content hash is a redacted digest of the plan's observable backend
    /// posture (primary kind + mirror phase).
    #[must_use]
    pub fn from_write_plan(plan: &StorageWritePlan<'_>) -> Self {
        let posture = [plan.primary().tag(), plan.mirror_phase().tag()];
        Self {
            backend_kind_u8: plan.primary().tag(),
            role_u8: StorageBackendRole::Primary.tag(),
            phase_u8: plan.mirror_phase().tag(),
            content_hash_redacted: redact16(&sha256_32(&posture)),
            walrus_blob_evidence: None,
            live_writer: matches!(plan.primary(), StorageBackendKind::Walrus),
        }
    }

    /// Whether this receipt is for a Walrus blob with present evidence.
    #[must_use]
    pub fn has_walrus_evidence(&self) -> bool {
        self.walrus_blob_evidence.is_some()
    }

    /// Whether a live IPFS/Filecoin writer is (correctly) denied for this backend
    /// in Stage F: `true` when the backend is a mirror/archive with no live
    /// writer.
    #[must_use]
    pub fn ipfs_filecoin_live_writer_denied(&self) -> bool {
        let is_mirror_or_archive = self.backend_kind_u8 == StorageBackendKind::IpfsMirror.tag()
            || self.backend_kind_u8 == StorageBackendKind::FilecoinArchive.tag();
        is_mirror_or_archive && !self.live_writer
    }

    /// Redacted, colorless receipt lines bounded by `rows`.
    #[must_use]
    pub fn render(&self, rows: u16) -> Vec<String> {
        let blob = self
            .walrus_blob_evidence
            .clone()
            .unwrap_or_else(|| "missing".to_string());
        let lines = vec![
            format!("backend_kind_u8={}", self.backend_kind_u8),
            format!("role_u8={}", self.role_u8),
            format!("phase_u8={}", self.phase_u8),
            format!("content_hash={}", self.content_hash_redacted),
            format!("walrus_blob_evidence={blob}"),
            format!("live_writer={}", self.live_writer),
        ];
        lines.into_iter().take(rows as usize).collect()
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    #![allow(clippy::expect_used)]
    #![allow(clippy::panic)]

    use super::*;
    use mnemos_c_walrus::{
        PublisherReportedBlobId, VerifiedBlobId, derive_blob_id, verify_reported_blob_id,
    };

    const COMMERCE_TOKENS: &[&str] = &[
        "price", "pay", "buy", "sell", "checkout", "refund", "fee", "cost", "$",
    ];

    /// URL-safe base64 (no pad) over 32 bytes — replicates the canonical c-walrus
    /// reported-blob-id text encoder so a self-derived id round-trips through the
    /// verify path (the only way to mint a `VerifiedBlobId`).
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

    fn key(b: u8) -> [u8; 32] {
        [b; 32]
    }

    #[test]
    fn setup_local_only() {
        let w = MemorySetupWizard::configure(
            key(1),
            None,
            MemoryStorageMode::LocalOnly,
            GasSponsorMode::SelfFunded,
            PrivacyLearningMode::PrivateLearningOff,
        )
        .unwrap();
        assert_eq!(w.storage_mode(), MemoryStorageMode::LocalOnly);
        assert_eq!(
            w.storage_mode().primary_kind(),
            StorageBackendKind::LocalEncrypted
        );
        assert!(!w.storage_mode().has_dry_run_secondary());
        assert!(w.owner_is_not_sponsor());
        assert_eq!(w.approval(), ApprovalRequirement::Confirm);
    }

    #[test]
    fn setup_walrus_testnet_shows_blob_evidence() {
        let obj = StorageObjectRef::walrus_primary([0x11; 32], verified_blob(b"walrus-root"));
        let receipt = MemoryBackendReceiptView::from_object_ref(&obj);
        assert_eq!(receipt.backend_kind_u8, StorageBackendKind::Walrus.tag());
        assert!(receipt.has_walrus_evidence());
        assert!(receipt.live_writer, "Walrus has a live writer in Stage F");
        assert!(!receipt.ipfs_filecoin_live_writer_denied());
    }

    #[test]
    fn setup_walrus_ipfs_mirror_dry_run() {
        let mode = MemoryStorageMode::WalrusIpfsMirrorDryRun;
        assert!(mode.has_dry_run_secondary());
        assert_eq!(mode.secondary_kind(), Some(StorageBackendKind::IpfsMirror));
        let obj = StorageObjectRef::future_only(
            StorageBackendKind::IpfsMirror,
            StorageBackendRole::Mirror,
            [0x22; 32],
        );
        let receipt = MemoryBackendReceiptView::from_object_ref(&obj);
        assert!(!receipt.live_writer);
        assert!(receipt.ipfs_filecoin_live_writer_denied());
    }

    #[test]
    fn setup_walrus_filecoin_archive_dry_run() {
        let mode = MemoryStorageMode::WalrusFilecoinArchiveDryRun;
        assert_eq!(
            mode.secondary_kind(),
            Some(StorageBackendKind::FilecoinArchive)
        );
        let obj = StorageObjectRef::future_only(
            StorageBackendKind::FilecoinArchive,
            StorageBackendRole::Archive,
            [0x33; 32],
        );
        let receipt = MemoryBackendReceiptView::from_object_ref(&obj);
        assert!(!receipt.live_writer);
        assert!(receipt.ipfs_filecoin_live_writer_denied());
    }

    #[test]
    fn setup_hosted_sponsor_with_owner_separation() {
        let w = MemorySetupWizard::configure(
            key(1),
            Some(key(2)),
            MemoryStorageMode::WalrusTestnet,
            GasSponsorMode::HostedSponsor,
            PrivacyLearningMode::PrivateLearningOff,
        )
        .unwrap();
        assert!(w.owner_is_not_sponsor());
        assert_eq!(w.sponsor_mode(), GasSponsorMode::HostedSponsor);
    }

    #[test]
    fn seed_phrase_input_deny() {
        let phrase =
            "abandon ability able about above absent absorb abstract absurd abuse access accident";
        assert!(looks_like_seed_phrase(phrase));
        let r = MemorySetupWizard::configure_from_input(
            phrase,
            key(1),
            None,
            MemoryStorageMode::LocalOnly,
            GasSponsorMode::NoneOffline,
            PrivacyLearningMode::PrivateLearningOff,
        );
        assert_eq!(r, Err(MemorySetupReject::SeedPhraseRejected));
        // A normal owner label is not a seed phrase.
        assert!(!looks_like_seed_phrase("my-laptop-key"));
    }

    #[test]
    fn owner_sponsor_mismatch_display() {
        // owner == sponsor is rejected fail-closed.
        let r = MemorySetupWizard::configure(
            key(7),
            Some(key(7)),
            MemoryStorageMode::WalrusTestnet,
            GasSponsorMode::HostedSponsor,
            PrivacyLearningMode::PrivateLearningOff,
        );
        assert_eq!(r, Err(MemorySetupReject::OwnerIsSponsor));
    }

    #[test]
    fn ipfs_filecoin_live_writer_deny() {
        for kind in [
            StorageBackendKind::IpfsMirror,
            StorageBackendKind::FilecoinArchive,
        ] {
            let obj = StorageObjectRef::future_only(kind, StorageBackendRole::Mirror, [0x44; 32]);
            let receipt = MemoryBackendReceiptView::from_object_ref(&obj);
            assert!(receipt.ipfs_filecoin_live_writer_denied());
        }
        // A Walrus primary is not an IPFS/Filecoin writer, so the deny predicate is
        // false (it has a legitimate live writer).
        let walrus = StorageObjectRef::walrus_primary([0x55; 32], verified_blob(b"w"));
        assert!(
            !MemoryBackendReceiptView::from_object_ref(&walrus).ipfs_filecoin_live_writer_denied()
        );
    }

    #[test]
    fn missing_blob_renders_as_missing() {
        let obj = StorageObjectRef::future_only(
            StorageBackendKind::IpfsMirror,
            StorageBackendRole::Mirror,
            [0x66; 32],
        );
        let receipt = MemoryBackendReceiptView::from_object_ref(&obj);
        assert!(!receipt.has_walrus_evidence());
        assert!(
            receipt
                .render(16)
                .iter()
                .any(|l| l.contains("walrus_blob_evidence=missing"))
        );
    }

    #[test]
    fn no_commerce_render() {
        let w = MemorySetupWizard::configure(
            key(1),
            Some(key(2)),
            MemoryStorageMode::WalrusTestnet,
            GasSponsorMode::HostedSponsor,
            PrivacyLearningMode::PrivateLearningOff,
        )
        .unwrap();
        let obj = StorageObjectRef::walrus_primary([0x11; 32], verified_blob(b"seed"));
        let receipt = MemoryBackendReceiptView::from_object_ref(&obj);
        for line in w.render(32).into_iter().chain(receipt.render(32)) {
            for bad in COMMERCE_TOKENS {
                assert!(!line.contains(bad), "commerce token {bad} in: {line}");
            }
        }
    }
}
