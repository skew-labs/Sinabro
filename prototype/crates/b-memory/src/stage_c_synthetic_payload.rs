//! Stage C first synthetic payload builder (C-WP-06A · atom #221 · C.2.2).
//!
//! Canonical OUT: §4.4 [`WalrusMainnetPrepare`] — the description of the first
//! mainnet Walrus blob. That first blob is a **synthetic public fixture only**.
//! The builder consumes a Stage B signed-chunk ([`StageBSignedChunkV1`], atom
//! #89) — so it sits on the canonical signed-chunk path — encodes the Stage A
//! [`ChunkEnvelopeV1`](mnemos_c_walrus::codec::ChunkEnvelopeV1) (atom #91),
//! derives + self-verifies a synthetic blob id locally (no network), and
//! attaches a [`StorageObjectRef`] with **Walrus as the primary** backend.
//!
//! # Madness invariants (atom #221)
//!
//! * **Synthetic fixture only.** Only
//!   [`SyntheticPublicFixture`](PublishPayloadClass::SyntheticPublicFixture) is
//!   admitted; every private payload class is rejected with
//!   [`WalrusPrepareError::PrivateClassRejected`].
//! * **Walrus primary, mirror/archive future-only.** The attached
//!   [`StorageObjectRef`] is built with
//!   [`walrus_primary`](StorageObjectRef::walrus_primary) — Walrus is `Primary`
//!   and `Enabled`. IPFS/Filecoin remain `FutureOnly` mirror/archive labels by
//!   construction (the atom #29 [`StorageObjectRef`] split); this builder never
//!   emits one.
//! * **Self-report ban preserved.** The blob id is derived locally (atom #10)
//!   and the §4.4 `storage` carries a
//!   [`VerifiedBlobId`](mnemos_c_walrus::VerifiedBlobId) obtained only through
//!   [`verify_reported_blob_id`](mnemos_c_walrus::verify_reported_blob_id).
//! * **Encoded bytes recorded.** `payload_hash_32` is the atom #86
//!   [`ContentHash32`] over the encoded payload, so the prepared descriptor
//!   commits the exact encoded bytes.
//! * **No re-mint.** Reuses A [`ChunkEnvelopeV1`](mnemos_c_walrus::codec::ChunkEnvelopeV1)
//!   / [`PublishPayloadClass`], B [`StageBSignedChunkV1`] /
//!   [`StorageObjectRef`], and the §4.0 [`StageCTraceLink`].

use mnemos_a_core::StageCTraceLink;
use mnemos_c_walrus::{
    PublishPayloadClass, PublisherReportedBlobId, VerifiedBlobId, derive_blob_id,
    encode_base64url_no_pad_32, verify_reported_blob_id,
};

use crate::chunk::{StorageBackendKind, StorageBackendRole, StorageObjectRef};
use crate::chunk_codec::encode_stage_b_chunk;
use crate::chunk_digest::ContentHash32;
use crate::signed_chunk::StageBSignedChunkV1;

/// §4.4 description of the first (synthetic) mainnet Walrus blob.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub struct WalrusMainnetPrepare {
    /// The admitted payload class (always
    /// [`SyntheticPublicFixture`](PublishPayloadClass::SyntheticPublicFixture)).
    pub payload_class: PublishPayloadClass,
    /// The atom #86 content hash over the encoded payload bytes.
    pub payload_hash_32: [u8; 32],
    /// The Walrus-primary storage pointer (carries the verified blob id).
    pub storage: StorageObjectRef,
    /// The §4.0 trace stamp for this prepared blob.
    pub trace: StageCTraceLink,
}

/// Synthetic-payload build error. Data-free.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
#[repr(u8)]
pub enum WalrusPrepareError {
    /// The payload class was not the only admissible synthetic public fixture.
    PrivateClassRejected = 1,
    /// The Stage A envelope failed to encode.
    Encode = 2,
    /// The locally derived id could not form a valid reported-text witness.
    ReportedText = 3,
    /// The local-derive self-verify failed (should be unreachable for a
    /// well-formed synthetic fixture; fail-closed).
    BlobVerify = 4,
}

impl core::fmt::Display for WalrusPrepareError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let msg = match self {
            Self::PrivateClassRejected => {
                "synthetic payload: only SyntheticPublicFixture is admitted"
            }
            Self::Encode => "synthetic payload: envelope encode failed",
            Self::ReportedText => "synthetic payload: reported-text witness invalid",
            Self::BlobVerify => "synthetic payload: local-derive self-verify failed",
        };
        f.write_str(msg)
    }
}

impl core::error::Error for WalrusPrepareError {}

impl WalrusMainnetPrepare {
    /// `true` iff the attached storage names Walrus as the `Primary` backend.
    #[inline]
    #[must_use]
    pub const fn is_walrus_primary(&self) -> bool {
        matches!(self.storage.backend(), StorageBackendKind::Walrus)
            && matches!(self.storage.role(), StorageBackendRole::Primary)
    }
}

/// Build the first synthetic mainnet payload description from a Stage B signed
/// chunk.
///
/// Rejects any payload class other than
/// [`SyntheticPublicFixture`](PublishPayloadClass::SyntheticPublicFixture).
/// Encodes the signed chunk's envelope, derives + self-verifies the synthetic
/// blob id locally (no network), and attaches a Walrus-primary storage ref.
///
/// # Errors
///
/// [`WalrusPrepareError`] for a private payload class, an encode failure, or a
/// failed reported-text / self-verify step.
pub fn build_synthetic(
    signed: &StageBSignedChunkV1,
    payload_class: PublishPayloadClass,
    trace: StageCTraceLink,
) -> Result<WalrusMainnetPrepare, WalrusPrepareError> {
    if payload_class != PublishPayloadClass::SyntheticPublicFixture {
        return Err(WalrusPrepareError::PrivateClassRejected);
    }
    let encoded = encode_stage_b_chunk(&signed.envelope).map_err(|_| WalrusPrepareError::Encode)?;

    // Local derive + self-verify: synthetic blob id, no network. The derived id
    // is presented as the reported text and re-verified through the canonical
    // atom #10 path so the §4.4 storage carries a real `VerifiedBlobId`.
    let derived = derive_blob_id(&encoded);
    let blob_id_bytes = *derived.as_bytes();
    let text = encode_base64url_no_pad_32(&blob_id_bytes);
    let reported = PublisherReportedBlobId::try_from_text(&text)
        .map_err(|_| WalrusPrepareError::ReportedText)?;
    let verified: VerifiedBlobId =
        verify_reported_blob_id(&encoded, &reported).map_err(|_| WalrusPrepareError::BlobVerify)?;

    let payload_hash_32 = *ContentHash32::of(&encoded).as_bytes();
    let storage = StorageObjectRef::walrus_primary(blob_id_bytes, verified);

    Ok(WalrusMainnetPrepare {
        payload_class,
        payload_hash_32,
        storage,
        trace,
    })
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;
    use crate::chunk::StorageBackendPhase;
    use crate::chunk_digest::{ChunkDigest32, stage_b_chunk_digest};
    use crate::chunk_schema::{StageBChunkFlags, StageBChunkHeaderV1, StageBChunkView};
    use crate::chunk_signature::chunk_sign_preimage;
    use crate::owner::{OwnerPublicKeyBinding, SigningPublicKey};
    use ed25519_dalek::{Signer, SigningKey};
    use mnemos_a_core::StageBTraceLink;
    use mnemos_c_walrus::SignatureBytes;
    use mnemos_c_walrus::codec::{ChunkEnvelopeV1, ChunkKind, MemoryRole};
    use mnemos_d_move::SuiAddress;

    fn env(content: &[u8]) -> ChunkEnvelopeV1 {
        ChunkEnvelopeV1 {
            kind: ChunkKind::UserMessage,
            role: MemoryRole::User,
            parent: None,
            content: content.to_vec(),
            embedding: None,
            signature: None,
            provenance: None,
        }
    }

    fn header(content_len: u32) -> StageBChunkHeaderV1 {
        StageBChunkHeaderV1::new(
            ChunkKind::UserMessage,
            MemoryRole::User,
            PublishPayloadClass::SyntheticPublicFixture,
            StageBChunkFlags::None as u8,
            content_len,
            SuiAddress::new([0x55; 32]),
            None,
            StageBTraceLink::new(221, 221, 0),
        )
        .expect("known header valid")
    }

    fn signed_fixture(content: &[u8]) -> StageBSignedChunkV1 {
        let e = env(content);
        let h = header(content.len() as u32);
        let view = StageBChunkView::new(h, &e).expect("within cap");
        let signing = SigningKey::from_bytes(&[7u8; 32]);
        let pubkey = signing.verifying_key().to_bytes();
        let binding = OwnerPublicKeyBinding::new(
            SuiAddress::new([0x55; 32]),
            SigningPublicKey::from_bytes(&pubkey).expect("32-byte pubkey"),
        );
        let digest: ChunkDigest32 = stage_b_chunk_digest(&view).expect("digest");
        let sig = SignatureBytes(signing.sign(&chunk_sign_preimage(&digest)).to_bytes());
        StageBSignedChunkV1::new(&view, sig, &binding).expect("signed chunk")
    }

    fn trace() -> StageCTraceLink {
        StageCTraceLink::new(StageBTraceLink::new(221, 221, 0), 221, 0)
    }

    /// `c2_2_payload_class_synthetic` — a synthetic fixture builds, and the
    /// attached storage is Walrus-primary + enabled.
    #[test]
    fn c2_2_payload_class_synthetic() {
        let signed = signed_fixture(b"synthetic-public-fixture-payload-v1");
        let prep = build_synthetic(
            &signed,
            PublishPayloadClass::SyntheticPublicFixture,
            trace(),
        )
        .expect("synthetic prepares");
        assert_eq!(
            prep.payload_class,
            PublishPayloadClass::SyntheticPublicFixture
        );
        assert!(prep.is_walrus_primary());
        assert_eq!(prep.storage.backend(), StorageBackendKind::Walrus);
        assert_eq!(prep.storage.role(), StorageBackendRole::Primary);
        assert_eq!(prep.storage.phase(), StorageBackendPhase::Enabled);
        assert!(prep.storage.walrus_blob().is_some());
    }

    /// `c2_2_private_classes_reject` — every private payload class is rejected.
    #[test]
    fn c2_2_private_classes_reject() {
        let signed = signed_fixture(b"synthetic-public-fixture-payload-v1");
        for class in [
            PublishPayloadClass::RealUserMemory,
            PublishPayloadClass::PromptOrProviderText,
            PublishPayloadClass::ToolOutput,
            PublishPayloadClass::SecretLike,
            PublishPayloadClass::PrivateProvenance,
        ] {
            assert_eq!(
                build_synthetic(&signed, class, trace()),
                Err(WalrusPrepareError::PrivateClassRejected),
                "class {class:?} must be rejected",
            );
        }
    }

    /// `c2_2_payload_hash_stable` — the same input yields the same payload hash.
    #[test]
    fn c2_2_payload_hash_stable() {
        let signed = signed_fixture(b"deterministic-fixture");
        let a = build_synthetic(
            &signed,
            PublishPayloadClass::SyntheticPublicFixture,
            trace(),
        )
        .expect("a");
        let b = build_synthetic(
            &signed,
            PublishPayloadClass::SyntheticPublicFixture,
            trace(),
        )
        .expect("b");
        assert_eq!(a.payload_hash_32, b.payload_hash_32);
        assert_ne!(a.payload_hash_32, [0u8; 32]);
    }

    /// `c2_2_storage_primary_walrus_mirror_archive_future_only` — Walrus is the
    /// only primary/enabled backend; IPFS/Filecoin labels are future-only.
    #[test]
    fn c2_2_storage_primary_walrus_mirror_archive_future_only() {
        let signed = signed_fixture(b"synthetic-public-fixture-payload-v1");
        let prep = build_synthetic(
            &signed,
            PublishPayloadClass::SyntheticPublicFixture,
            trace(),
        )
        .expect("prepares");
        assert_eq!(prep.storage.phase(), StorageBackendPhase::Enabled);

        // The split: IPFS mirror / Filecoin archive are always FutureOnly and
        // carry no blob id — this builder never emits one.
        let mirror = StorageObjectRef::future_only(
            StorageBackendKind::IpfsMirror,
            StorageBackendRole::Mirror,
            [0x01; 32],
        );
        let archive = StorageObjectRef::future_only(
            StorageBackendKind::FilecoinArchive,
            StorageBackendRole::Archive,
            [0x02; 32],
        );
        assert_eq!(mirror.phase(), StorageBackendPhase::FutureOnly);
        assert_eq!(archive.phase(), StorageBackendPhase::FutureOnly);
        assert!(mirror.walrus_blob().is_none());
        assert!(archive.walrus_blob().is_none());
    }
}
