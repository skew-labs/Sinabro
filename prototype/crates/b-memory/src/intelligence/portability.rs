//! Portable memory bundle + offline replay (Stage D Cluster 6, atom #329 · D.5.8).
//!
//! A [`PortableMemoryBundle`] (§4.6) is the user-owned, portable root of a memory:
//! the verified root blob ([`VerifiedBlobId`]), the Stage B replay transcript hash
//! ([`StageBTranscriptHash32`]), the user-model hash, and the tombstone-set hash
//! (#328 [`TombstonePolicy::tombstone_hash_32`]). [`export_bundle`] produces one;
//! [`import_bundle`] verifies it; [`ProviderMigration::replay_portable`] re-applies
//! it across a model / provider / platform migration **offline**, producing a
//! [`ReplayPortabilityReport`] (§4.6).
//!
//! ## Structural invariants
//!
//! * **Transcript stable.** The bundle's Stage B transcript hash is carried through
//!   export / import / replay / migration unchanged.
//! * **Deleted resurrection zero.** Replay routes every candidate id through the
//!   #328 [`TombstonePolicy`]; a tombstoned id is never re-applied, so
//!   `deleted_resurrections_u64 == 0` (the #329 criterion).
//! * **No auto-apply policy.** The exported bundle carries **no** retrieval /
//!   context policy that could auto-apply on import
//!   ([`BUNDLE_CARRIES_AUTO_APPLY_POLICY`] is `false`). Replay may *compare*
//!   candidate policies offline, but only as a measurement-only
//!   [`StageDPolicyObservation`] whose `production_change_allowed` is `false`.
//!
//! ## Offline / read-only
//!
//! No network, filesystem, wallet, secret or chain action
//! ([`PORTABILITY_PERFORMS_LIVE_ACTION`] is `false`). A Stage C mainnet-gate
//! evidence anchor, *if anchored*, is consumed only as a redacted
//! [`StageDEvidenceRef`] provenance summary (G-D-EVIDENCE-SUMMARY) — never a live
//! mainnet / RPC / anchor action, and never the `MainnetGateReceipt` type itself
//! (no `b-memory -> k-devex` dependency edge is introduced).

use crate::chunk::MemoryId;
use crate::intelligence::delete_semantics::{ResurrectionScan, TombstonePolicy};
use crate::intelligence::user_model::UserModelDelta;
use crate::intelligence::{
    StageDEvidenceRef, StageDPolicyObservation, StageDPolicyObservationKind,
};
use crate::stage_b_replay::{StageBReplayReport, StageBTranscriptHash32};
use mnemos_c_walrus::{VerifiedBlobId, derive_blob_id};

/// Greppable, compile-time guarantee that portability performs no live
/// (network / filesystem / wallet / secret / chain) action.
pub const PORTABILITY_PERFORMS_LIVE_ACTION: bool = false;

/// Greppable, compile-time guarantee that an exported bundle carries no auto-apply
/// retrieval / context policy.
pub const BUNDLE_CARRIES_AUTO_APPLY_POLICY: bool = false;

/// Domain tag for the bundle digest.
const PORTABLE_BUNDLE_DOMAIN: &[u8] = b"mnemos.stage_d.portable_bundle.v1";

/// Domain tag for the bundle's user-model hash.
const PORTABLE_USER_MODEL_DOMAIN: &[u8] = b"mnemos.stage_d.portable_user_model.v1";

/// §4.6 portable memory bundle — the user-owned root for export / import / replay.
///
/// Exactly the four §4.6 fields; there is deliberately **no** policy field, so an
/// import can never auto-apply a retrieval / context policy
/// ([`BUNDLE_CARRIES_AUTO_APPLY_POLICY`]).
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub struct PortableMemoryBundle {
    /// Verified root blob id (A; never a bare server-reported id).
    pub root_blob: VerifiedBlobId,
    /// Stage B replay transcript hash (B; carried verbatim, never re-minted).
    pub transcript: StageBTranscriptHash32,
    /// 32-byte hash of the user model (preferences / facts / boundaries /
    /// relationship-graph + deletion semantics), via [`user_model_bundle_hash`].
    pub user_model_hash_32: [u8; 32],
    /// 32-byte hash of the tombstone set (#328
    /// [`TombstonePolicy::tombstone_hash_32`]).
    pub tombstone_hash_32: [u8; 32],
}

impl PortableMemoryBundle {
    /// Construct a bundle from its four §4.6 components.
    #[must_use]
    pub const fn new(
        root_blob: VerifiedBlobId,
        transcript: StageBTranscriptHash32,
        user_model_hash_32: [u8; 32],
        tombstone_hash_32: [u8; 32],
    ) -> Self {
        Self {
            root_blob,
            transcript,
            user_model_hash_32,
            tombstone_hash_32,
        }
    }

    /// The deterministic 32-byte bundle digest: a domain-tagged [`derive_blob_id`]
    /// over the root blob, transcript, user-model hash and tombstone hash. Used as
    /// the bundle identity and the [`import_bundle`] root-match witness.
    #[must_use]
    pub fn bundle_hash_32(&self) -> [u8; 32] {
        let mut buf: Vec<u8> = Vec::with_capacity(PORTABLE_BUNDLE_DOMAIN.len() + 32 * 4);
        buf.extend_from_slice(PORTABLE_BUNDLE_DOMAIN);
        buf.extend_from_slice(self.root_blob.as_blob_id().as_bytes());
        buf.extend_from_slice(self.transcript.as_bytes());
        buf.extend_from_slice(&self.user_model_hash_32);
        buf.extend_from_slice(&self.tombstone_hash_32);
        *derive_blob_id(&buf).as_bytes()
    }
}

/// Compute the §4.6 bundle `user_model_hash_32` from a [`UserModelDelta`]: a
/// domain-tagged digest over the four component hashes plus the deletion-semantics
/// tag. Deterministic — the same user model always yields the same value, so the
/// user model is preserved across a migration by hash comparison.
#[must_use]
pub fn user_model_bundle_hash(delta: &UserModelDelta) -> [u8; 32] {
    let mut buf: Vec<u8> = Vec::with_capacity(PORTABLE_USER_MODEL_DOMAIN.len() + 32 * 4 + 1);
    buf.extend_from_slice(PORTABLE_USER_MODEL_DOMAIN);
    buf.extend_from_slice(&delta.preferences_hash_32);
    buf.extend_from_slice(&delta.facts_hash_32);
    buf.extend_from_slice(&delta.boundaries_hash_32);
    buf.extend_from_slice(&delta.relationship_graph_hash_32);
    buf.push(delta.delete_semantics.tag());
    *derive_blob_id(&buf).as_bytes()
}

/// Export a portable bundle from a verified root, a Stage B replay, the user-model
/// delta and the tombstone policy. The transcript is taken verbatim from the replay
/// (B); the user-model and tombstone hashes are derived. The result carries no
/// auto-apply policy.
#[must_use]
pub fn export_bundle(
    root_blob: VerifiedBlobId,
    replay: &StageBReplayReport,
    user_model: &UserModelDelta,
    tombstones: &TombstonePolicy,
) -> PortableMemoryBundle {
    PortableMemoryBundle::new(
        root_blob,
        replay.transcript,
        user_model_bundle_hash(user_model),
        tombstones.tombstone_hash_32(),
    )
}

/// Import / replay error set (frozen; every variant is a data-free tag).
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
#[non_exhaustive]
pub enum PortabilityError {
    /// The recomputed bundle digest did not match the claimed one — the root is not
    /// the bundle it claims to be (tamper / drift). This is the root-mismatch
    /// rejection.
    RootMismatch,
}

impl PortabilityError {
    /// Stable, allow-listed `class_label` for diagnostic JSON envelopes.
    #[inline]
    pub const fn class_label(self) -> &'static str {
        match self {
            Self::RootMismatch => "portability.root_mismatch",
        }
    }
}

/// An imported root: a bundle whose digest matched its claimed identity, plus an
/// optional redacted Stage C mainnet-gate evidence anchor.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub struct ImportedRoot {
    /// The verified bundle.
    pub bundle: PortableMemoryBundle,
    /// Optional redacted Stage C mainnet-gate evidence anchor (read-only provenance
    /// only; never a live mainnet action). `None` when the root is not
    /// mainnet-anchored ("if anchored").
    pub mainnet_anchor: Option<StageDEvidenceRef>,
}

/// Import a bundle by verifying its digest against the claimed identity. Returns
/// [`PortabilityError::RootMismatch`] when the recomputed digest differs from
/// `claimed_bundle_hash_32`. The optional mainnet anchor is carried verbatim as a
/// redacted provenance reference — import performs no live mainnet / RPC action.
pub fn import_bundle(
    bundle: PortableMemoryBundle,
    claimed_bundle_hash_32: &[u8; 32],
    mainnet_anchor: Option<StageDEvidenceRef>,
) -> Result<ImportedRoot, PortabilityError> {
    if &bundle.bundle_hash_32() != claimed_bundle_hash_32 {
        return Err(PortabilityError::RootMismatch);
    }
    Ok(ImportedRoot {
        bundle,
        mainnet_anchor,
    })
}

/// §4.6 replay-portability report — the outcome of replaying a bundle's candidate
/// id stream across a model / provider / platform migration.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub struct ReplayPortabilityReport {
    /// The bundle digest this replay is bound to.
    pub bundle_hash_32: [u8; 32],
    /// Candidate ids re-applied (not tombstoned).
    pub replayed_chunks_u64: u64,
    /// Candidate ids rejected (tombstoned; blocked from resurrection).
    pub rejected_chunks_u64: u64,
    /// Deleted memories that resurrected — always 0 (criterion #329).
    pub deleted_resurrections_u64: u64,
    /// Stage B transcript hash, carried verbatim from the bundle (stable across the
    /// migration).
    pub transcript: StageBTranscriptHash32,
}

impl ReplayPortabilityReport {
    /// Whether the replay upheld both #329 criteria: the transcript is stable
    /// (equal to `expected_transcript`) and there were zero deleted resurrections.
    #[must_use]
    pub fn upholds_criteria(&self, expected_transcript: &StageBTranscriptHash32) -> bool {
        self.deleted_resurrections_u64 == 0
            && self.transcript.as_bytes() == expected_transcript.as_bytes()
    }
}

/// A model / provider / platform migration descriptor. A pure relabel: it carries
/// the source and target provider tags only and triggers no live action — replay
/// truth must be invariant to it.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub struct ProviderMigration {
    /// Source provider / model tag.
    pub from_provider_u16: u16,
    /// Target provider / model tag.
    pub to_provider_u16: u16,
}

impl ProviderMigration {
    /// Construct a migration descriptor.
    #[must_use]
    pub const fn new(from_provider_u16: u16, to_provider_u16: u16) -> Self {
        Self {
            from_provider_u16,
            to_provider_u16,
        }
    }

    /// Whether this migration crosses providers (source != target).
    #[must_use]
    pub const fn is_cross_provider(self) -> bool {
        self.from_provider_u16 != self.to_provider_u16
    }

    /// Replay `bundle`'s candidate id stream across this migration, **offline**.
    /// Every candidate is routed through the #328 [`TombstonePolicy`]: a tombstoned
    /// id is rejected (never re-applied), so `deleted_resurrections_u64 == 0`. The
    /// Stage B transcript is carried verbatim from the bundle — a provider relabel
    /// never changes replay truth — so the result is invariant to the migration.
    #[must_use]
    pub fn replay_portable(
        self,
        bundle: &PortableMemoryBundle,
        tombstones: &TombstonePolicy,
        candidates: &[MemoryId],
        replay: &StageBReplayReport,
    ) -> ReplayPortabilityReport {
        let scan: ResurrectionScan = tombstones.scan_candidates(replay, candidates);
        ReplayPortabilityReport {
            bundle_hash_32: bundle.bundle_hash_32(),
            replayed_chunks_u64: scan.admitted_u64,
            rejected_chunks_u64: scan.tombstone_blocked_u64,
            deleted_resurrections_u64: scan.deleted_resurrections_u64,
            transcript: bundle.transcript,
        }
    }
}

/// Compare two candidate retrieval / context policies **offline**, as a
/// measurement-only [`StageDPolicyObservation`]. The observation can never promote
/// itself into a production policy change (`production_change_allowed == false`).
/// This is the only "policy" surface portability exposes — the exported bundle
/// itself carries none ([`BUNDLE_CARRIES_AUTO_APPLY_POLICY`]).
#[must_use]
pub fn compare_policies_offline(
    kind: StageDPolicyObservationKind,
    evidence: StageDEvidenceRef,
    candidate_a_effect_hash_32: [u8; 32],
    candidate_b_effect_hash_32: [u8; 32],
) -> StageDPolicyObservation {
    StageDPolicyObservation::new(
        kind,
        evidence,
        candidate_a_effect_hash_32,
        candidate_b_effect_hash_32,
    )
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    #![allow(clippy::expect_used)]
    #![allow(clippy::panic)]

    use super::*;
    use crate::intelligence::DeleteSemantics;
    use crate::intelligence::user_model::UserModel;
    use crate::owner::SigningPublicKey;
    use crate::stage_b_replay::stage_b_transcript_hash;
    use mnemos_a_core::{StageBTraceLink, StageCTraceLink, StageDTraceLink};
    use mnemos_c_walrus::{PublisherReportedBlobId, verify_reported_blob_id};

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

    fn sample_verified_blob_id(seed: &[u8]) -> VerifiedBlobId {
        let derived = derive_blob_id(seed);
        let text = encode_b64url(derived.as_bytes());
        let reported = PublisherReportedBlobId::try_from_text(&text).expect("base64url length 43");
        verify_reported_blob_id(seed, &reported).expect("round-trip self-derived must verify")
    }

    fn owner() -> SigningPublicKey {
        SigningPublicKey::from_bytes(&[9_u8; 32]).expect("32-byte owner key")
    }

    fn sample_user_model() -> UserModelDelta {
        let mut m = UserModel::empty(owner());
        m.set_preferences(b"terse-replies");
        m.set_facts(b"lives-in-seoul");
        m.to_delta(DeleteSemantics::Tombstone)
    }

    fn sample_tombstones() -> TombstonePolicy {
        let mut p = TombstonePolicy::new();
        p.record(MemoryId::new(10), DeleteSemantics::Tombstone);
        p.record(MemoryId::new(11), DeleteSemantics::HardDeleteLocal);
        p
    }

    fn sample_replay() -> StageBReplayReport {
        StageBReplayReport {
            transcript: stage_b_transcript_hash(b"portability-fixture-transcript"),
            applied_u64: 8,
            duplicate_u64: 0,
            rejected_u64: 0,
        }
    }

    fn sample_evidence() -> StageDEvidenceRef {
        let trace = StageDTraceLink::new(
            StageCTraceLink::new(StageBTraceLink::new(7, 329, 0), 329, 99),
            329,
            0,
        );
        StageDEvidenceRef::new([0xC3; 32], trace)
    }

    #[test]
    fn export_carries_transcript_and_derived_hashes() {
        let blob = sample_verified_blob_id(b"root-export");
        let replay = sample_replay();
        let bundle = export_bundle(blob, &replay, &sample_user_model(), &sample_tombstones());
        assert_eq!(
            bundle.transcript, replay.transcript,
            "Stage B transcript carried verbatim"
        );
        assert_eq!(
            bundle.user_model_hash_32,
            user_model_bundle_hash(&sample_user_model())
        );
        assert_eq!(
            bundle.tombstone_hash_32,
            sample_tombstones().tombstone_hash_32()
        );
        assert_eq!(bundle.root_blob, blob);
    }

    #[test]
    fn import_round_trips_on_matching_hash() {
        let blob = sample_verified_blob_id(b"root-import");
        let bundle = export_bundle(
            blob,
            &sample_replay(),
            &sample_user_model(),
            &sample_tombstones(),
        );
        let h = bundle.bundle_hash_32();
        let imported = import_bundle(bundle, &h, None).unwrap();
        assert_eq!(imported.bundle, bundle);
        assert!(imported.mainnet_anchor.is_none());
        // The optional Stage C mainnet-gate anchor is carried as a redacted ref.
        let with_anchor = import_bundle(bundle, &h, Some(sample_evidence())).unwrap();
        assert_eq!(with_anchor.mainnet_anchor, Some(sample_evidence()));
    }

    #[test]
    fn root_mismatch_is_rejected() {
        let blob = sample_verified_blob_id(b"root-mismatch");
        let bundle = export_bundle(
            blob,
            &sample_replay(),
            &sample_user_model(),
            &sample_tombstones(),
        );
        let mut wrong = bundle.bundle_hash_32();
        wrong[0] ^= 0x01;
        assert_eq!(
            import_bundle(bundle, &wrong, None),
            Err(PortabilityError::RootMismatch)
        );
        assert_eq!(
            PortabilityError::RootMismatch.class_label(),
            "portability.root_mismatch"
        );
    }

    #[test]
    fn full_replay_admits_live_and_blocks_tombstoned() {
        let blob = sample_verified_blob_id(b"root-replay");
        let tombs = sample_tombstones(); // tombstones ids 10, 11
        let bundle = export_bundle(blob, &sample_replay(), &sample_user_model(), &tombs);
        let candidates = [
            MemoryId::new(10),
            MemoryId::new(11),
            MemoryId::new(12),
            MemoryId::new(13),
        ];
        let migration = ProviderMigration::new(1, 2);
        assert!(migration.is_cross_provider());
        let report = migration.replay_portable(&bundle, &tombs, &candidates, &sample_replay());
        assert_eq!(report.replayed_chunks_u64, 2); // 12, 13 live
        assert_eq!(report.rejected_chunks_u64, 2); // 10, 11 tombstoned
        assert_eq!(report.deleted_resurrections_u64, 0);
        assert_eq!(report.transcript, bundle.transcript);
        assert_eq!(report.bundle_hash_32, bundle.bundle_hash_32());
        assert!(report.upholds_criteria(&bundle.transcript));
    }

    #[test]
    fn provider_migration_preserves_transcript_and_user_model() {
        let blob = sample_verified_blob_id(b"root-migrate");
        let tombs = sample_tombstones();
        let bundle = export_bundle(blob, &sample_replay(), &sample_user_model(), &tombs);
        let original_transcript = bundle.transcript;
        let r1 = ProviderMigration::new(1, 2).replay_portable(
            &bundle,
            &tombs,
            &[MemoryId::new(12)],
            &sample_replay(),
        );
        let r2 = ProviderMigration::new(2, 3).replay_portable(
            &bundle,
            &tombs,
            &[MemoryId::new(12)],
            &sample_replay(),
        );
        // Replay truth is invariant to the provider relabel.
        assert_eq!(r1.transcript, original_transcript);
        assert_eq!(r2.transcript, original_transcript);
        assert_eq!(r1.deleted_resurrections_u64, 0);
        assert_eq!(r2.deleted_resurrections_u64, 0);
        // The user model is preserved across the migration (hash unchanged).
        assert_eq!(
            bundle.user_model_hash_32,
            user_model_bundle_hash(&sample_user_model())
        );
        // An identity migration is admissible too.
        assert!(!ProviderMigration::new(5, 5).is_cross_provider());
    }

    #[test]
    fn deleted_resurrection_is_rejected_in_replay() {
        // A bundle exported with a tombstone; a candidate stream tries to re-apply
        // the tombstoned id twice -> blocked, resurrection stays 0.
        let blob = sample_verified_blob_id(b"root-resurrect");
        let mut tombs = TombstonePolicy::new();
        tombs.record(MemoryId::new(42), DeleteSemantics::Tombstone);
        let bundle = export_bundle(blob, &sample_replay(), &sample_user_model(), &tombs);
        let report = ProviderMigration::new(1, 9).replay_portable(
            &bundle,
            &tombs,
            &[MemoryId::new(42), MemoryId::new(42)],
            &sample_replay(),
        );
        assert_eq!(report.replayed_chunks_u64, 0);
        assert_eq!(report.rejected_chunks_u64, 2);
        assert_eq!(report.deleted_resurrections_u64, 0);
    }

    #[test]
    fn no_auto_apply_policy_and_offline_only() {
        // Compile-time + greppable: the bundle carries no auto-apply policy and
        // portability performs no live action.
        const { assert!(!BUNDLE_CARRIES_AUTO_APPLY_POLICY) };
        const { assert!(!PORTABILITY_PERFORMS_LIVE_ACTION) };
        // The only policy surface is a measurement-only observation that can never
        // promote itself into production.
        let obs = compare_policies_offline(
            StageDPolicyObservationKind::ContextSelection,
            sample_evidence(),
            [0x01; 32],
            [0x02; 32],
        );
        assert!(
            !obs.production_change_allowed(),
            "an offline policy comparison must never promote production policy"
        );
    }
}
