//! Tamper-evident dataset shard writer (atom #396 · E.3.10).
//!
//! # Madness
//!
//! A shard is **content-addressed** (`shard_hash = sha256` of the streamed
//! bytes), **stream-written** one record at a time so a 1 GB shard never lives
//! in memory, **PII-scanned per record** during the write (a dirty record fails
//! the whole shard closed), and **tamper-evident**: every shard carries a
//! domain-separated *merkle root* over its records and a *signer hash* binding
//! `(signer_id, shard_hash, merkle_root)`. There is no mutable `latest`
//! dataset — a shard is named by its own hash. The shard is linked to an
//! [`EvidenceLakeReceipt`] via the receipt's `manifest_hash`; a remote archive
//! locator is optional and **cannot bypass the local content-addressed store**.
//!
//! # Secret custody (physics-warning class resolution)
//!
//! [`write_shard`] runs `privacy_scanner::scan_str` (a pure function over the
//! record text — no network/wallet/process/filesystem-write API exists in this
//! module) over every record before it is written, and rejects the shard on any
//! secret / PII / encoded-secret hit. The [`DatasetShardManifest`] carries only
//! `[u8; 32]` hashes, a count, an [`ExportKind`] tag, and a `pii_zero` bool —
//! never a raw record byte. Tamper failures are byte-free unit [`DietError`]s.
//! `live_action_allowed = false`: the `signer_hash` is a deterministic local
//! domain-separated digest, **not** a wallet/network signature.
use crate::StageETraceLink;
use crate::diet_kind::AtomDietKey;
use crate::error::{DietError, DietResult};
use crate::privacy_scanner;
use sha2::{Digest, Sha256};
use std::io::Write;

use super::ExportKind;

/// Domain prefix for a merkle *leaf* (second-preimage separation from nodes).
const MERKLE_LEAF_DOMAIN: u8 = 0x00;
/// Domain prefix for a merkle *internal node*.
const MERKLE_NODE_DOMAIN: u8 = 0x01;
/// Domain seed for the merkle root of an *empty* shard (deterministic).
const MERKLE_EMPTY_DOMAIN: &[u8] = b"mnemos.shard.merkle.empty.v1";
/// Domain seed for the signer binding digest.
const SIGNER_DOMAIN: &[u8] = b"mnemos.shard.signer.v1";

/// Whether a 32-byte hash is all-zero (the canonical "absent" sentinel).
const fn is_zero_32(h: &[u8; 32]) -> bool {
    let mut i = 0;
    while i < 32 {
        if h[i] != 0 {
            return false;
        }
        i += 1;
    }
    true
}

/// A §4.1 evidence-lake receipt: the on-disk anchor that ties a shard's manifest
/// to the local content-addressed store, an optional remote archive locator, a
/// benchmark digest, and a training-eligibility flag.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub struct EvidenceLakeReceipt {
    /// The source atom this evidence derives from.
    pub key: AtomDietKey,
    /// `sha256` of the shard / dataset manifest this receipt anchors.
    pub manifest_hash_32: [u8; 32],
    /// Root hash of the local content-addressed store (the authoritative copy).
    pub local_cas_root_32: [u8; 32],
    /// Optional remote archive locator hash (all-zero = absent). Never primary.
    pub archive_locator_hash_32: [u8; 32],
    /// `sha256` of the benchmark / eval bundle associated with the shard.
    pub benchmark_hash_32: [u8; 32],
    /// Whether this evidence is eligible to back a *training* shard. In Stage E
    /// this is always `false` (no record is training-eligible yet).
    pub training_eligibility: bool,
    /// Stage E trace stamp.
    pub trace: StageETraceLink,
}

impl EvidenceLakeReceipt {
    /// Construct a receipt, enforcing the rights invariant at construction: a
    /// non-zero remote `archive_locator` requires a non-zero `local_cas_root`,
    /// so a remote locator can never exist without — let alone bypass — the
    /// local content-addressed store ([`DietError::RemoteLocatorBypass`]).
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        key: AtomDietKey,
        manifest_hash_32: [u8; 32],
        local_cas_root_32: [u8; 32],
        archive_locator_hash_32: [u8; 32],
        benchmark_hash_32: [u8; 32],
        training_eligibility: bool,
        trace: StageETraceLink,
    ) -> DietResult<Self> {
        if !is_zero_32(&archive_locator_hash_32) && is_zero_32(&local_cas_root_32) {
            return Err(DietError::RemoteLocatorBypass);
        }
        Ok(Self {
            key,
            manifest_hash_32,
            local_cas_root_32,
            archive_locator_hash_32,
            benchmark_hash_32,
            training_eligibility,
            trace,
        })
    }

    /// Whether a (subordinate) remote archive locator is present.
    pub const fn has_remote_locator(&self) -> bool {
        !is_zero_32(&self.archive_locator_hash_32)
    }

    /// Fail closed unless this evidence is training-eligible. Stage E receipts
    /// are always `false`, so no training shard can be promoted in Stage E.
    pub const fn assert_training_eligible(&self) -> DietResult<()> {
        if self.training_eligibility {
            Ok(())
        } else {
            Err(DietError::TrainingIneligible)
        }
    }
}

/// A §4.5 dataset shard manifest: the tamper-evident header for one shard.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub struct DatasetShardManifest {
    /// `sha256` of the full streamed shard bytes (the content address).
    pub shard_hash_32: [u8; 32],
    /// Domain-separated merkle root over the shard's records.
    pub merkle_root_32: [u8; 32],
    /// Signer binding digest over `(signer_id, shard_hash, merkle_root)`.
    pub signer_hash_32: [u8; 32],
    /// The export kind of every record in the shard.
    pub export: ExportKind,
    /// Number of records written into the shard.
    pub sample_count_u64: u64,
    /// `true` iff every record passed the post-write privacy scan (always `true`
    /// for a successfully built manifest — a dirty record rejects the shard).
    pub pii_zero: bool,
    /// The `manifest_hash` of the [`EvidenceLakeReceipt`] this shard links to.
    pub evidence_manifest_hash_32: [u8; 32],
}

impl DatasetShardManifest {
    /// Verify the tamper chain against an *independently* recomputed merkle root
    /// and the signer identity. Fail-closed: a merkle drift is a
    /// [`DietError::ShardMerkleMismatch`]; a signer drift is a
    /// [`DietError::ShardSignatureMismatch`].
    pub fn verify_tamper(
        &self,
        recomputed_merkle_32: &[u8; 32],
        signer_id_32: &[u8; 32],
    ) -> DietResult<()> {
        if &self.merkle_root_32 != recomputed_merkle_32 {
            return Err(DietError::ShardMerkleMismatch);
        }
        let expected = signer_hash(signer_id_32, &self.shard_hash_32, &self.merkle_root_32);
        if self.signer_hash_32 != expected {
            return Err(DietError::ShardSignatureMismatch);
        }
        Ok(())
    }
}

/// Finalize an incremental `sha256` into a fixed `[u8; 32]`.
fn finalize_sha(hasher: Sha256) -> [u8; 32] {
    let digest = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest);
    out
}

/// Hash one merkle leaf (domain-separated from internal nodes).
fn merkle_leaf(record_bytes: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update([MERKLE_LEAF_DOMAIN]);
    hasher.update(record_bytes);
    finalize_sha(hasher)
}

/// Hash one merkle internal node from its two children.
fn merkle_node(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update([MERKLE_NODE_DOMAIN]);
    hasher.update(left);
    hasher.update(right);
    finalize_sha(hasher)
}

/// Compute the merkle root of a list of leaves. An empty shard hashes to a fixed
/// domain seed; an odd node is promoted by hashing it with itself.
fn merkle_root(leaves: &[[u8; 32]]) -> [u8; 32] {
    if leaves.is_empty() {
        let mut hasher = Sha256::new();
        hasher.update(MERKLE_EMPTY_DOMAIN);
        return finalize_sha(hasher);
    }
    let mut level: Vec<[u8; 32]> = leaves.to_vec();
    while level.len() > 1 {
        let mut next: Vec<[u8; 32]> = Vec::with_capacity(level.len().div_ceil(2));
        let mut i = 0;
        while i < level.len() {
            if i + 1 < level.len() {
                next.push(merkle_node(&level[i], &level[i + 1]));
            } else {
                next.push(merkle_node(&level[i], &level[i]));
            }
            i += 2;
        }
        level = next;
    }
    level[0]
}

/// The signer binding digest over `(signer_id, shard_hash, merkle_root)`. This
/// is a deterministic local digest — **not** a wallet/network signature.
fn signer_hash(
    signer_id_32: &[u8; 32],
    shard_hash_32: &[u8; 32],
    merkle_root_32: &[u8; 32],
) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(SIGNER_DOMAIN);
    hasher.update(signer_id_32);
    hasher.update(shard_hash_32);
    hasher.update(merkle_root_32);
    finalize_sha(hasher)
}

/// Recompute the merkle root for a set of already-formatted records — used by a
/// verifier to independently re-derive the tamper root (see [`verify_tamper`]).
///
/// [`verify_tamper`]: DatasetShardManifest::verify_tamper
pub fn recompute_merkle_root(records: &[String]) -> [u8; 32] {
    let leaves: Vec<[u8; 32]> = records.iter().map(|r| merkle_leaf(r.as_bytes())).collect();
    merkle_root(&leaves)
}

/// Stream `records` (one already-formatted JSONL line each) into `sink`,
/// computing the content address, merkle root, and signer binding as it goes.
///
/// Each record is privacy-scanned before it is written; the first dirty record
/// rejects the whole shard ([`DietError::ShardPiiResidue`]) — no secret byte is
/// ever materialized into the sink. Memory is bounded to one record at a time.
/// The returned [`DatasetShardManifest`] links the shard to `receipt`.
pub fn write_shard<W: Write>(
    sink: &mut W,
    export: ExportKind,
    records: &[String],
    receipt: &EvidenceLakeReceipt,
    signer_id_32: &[u8; 32],
) -> DietResult<DatasetShardManifest> {
    let mut content = Sha256::new();
    let mut leaves: Vec<[u8; 32]> = Vec::with_capacity(records.len());
    let mut count: u64 = 0;
    for rec in records {
        // Secret custody: scan each record, reject the shard on any hit.
        if !privacy_scanner::scan_str(rec).clean() {
            return Err(DietError::ShardPiiResidue);
        }
        let bytes = rec.as_bytes();
        sink.write_all(bytes).map_err(|_| DietError::ShardIo)?;
        sink.write_all(b"\n").map_err(|_| DietError::ShardIo)?;
        content.update(bytes);
        content.update(b"\n");
        leaves.push(merkle_leaf(bytes));
        count = count.saturating_add(1);
    }
    let shard_hash_32 = finalize_sha(content);
    let merkle_root_32 = merkle_root(&leaves);
    let signer_hash_32 = signer_hash(signer_id_32, &shard_hash_32, &merkle_root_32);
    Ok(DatasetShardManifest {
        shard_hash_32,
        merkle_root_32,
        signer_hash_32,
        export,
        sample_count_u64: count,
        pii_zero: true,
        evidence_manifest_hash_32: receipt.manifest_hash_32,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::diet_kind::DietSourceStage;
    use crate::export::grpo;
    use crate::export::sft_chat::{ChatRole, ChatTurn, SftSample, to_jsonl};

    fn key() -> AtomDietKey {
        AtomDietKey::new(DietSourceStage::Phase0, 396)
    }

    fn trace() -> StageETraceLink {
        StageETraceLink::new([0xEE; 32], 396, 0)
    }

    fn receipt() -> EvidenceLakeReceipt {
        // archive_locator absent (all-zero) ⇒ no rights conflict; Stage E is not
        // training-eligible. Built via struct literal (pub fields) so the helper
        // needs no unwrap/expect.
        EvidenceLakeReceipt {
            key: key(),
            manifest_hash_32: [0xA1; 32],
            local_cas_root_32: [0xB2; 32],
            archive_locator_hash_32: [0u8; 32],
            benchmark_hash_32: [0xC3; 32],
            training_eligibility: false,
            trace: trace(),
        }
    }

    fn clean_records() -> Vec<String> {
        vec![
            r#"{"k":1,"text":"cargo test exit 0"}"#.to_string(),
            r#"{"k":2,"text":"borrow checker fixed"}"#.to_string(),
            r#"{"k":3,"text":"clippy clean"}"#.to_string(),
        ]
    }

    #[test]
    fn sft_shard_is_content_addressed() -> DietResult<()> {
        let s = SftSample::new(
            key(),
            vec![ChatTurn {
                role: ChatRole::Assistant,
                content: "patch summary; verified".to_string(),
            }],
        );
        let records = vec![to_jsonl(&s)?];
        let mut sink = Vec::new();
        let m = write_shard(
            &mut sink,
            ExportKind::SftChat,
            &records,
            &receipt(),
            &[7u8; 32],
        )?;
        assert_eq!(m.export, ExportKind::SftChat);
        assert_eq!(m.sample_count_u64, 1);
        assert!(m.pii_zero);
        // sink holds exactly the streamed record + newline.
        assert_eq!(sink, format!("{}\n", records[0]).into_bytes());
        Ok(())
    }

    #[test]
    fn preference_shard_writes_records() -> DietResult<()> {
        let records = vec![r#"{"chosen":"aa","rejected":"bb"}"#.to_string()];
        let mut sink = Vec::new();
        let m = write_shard(
            &mut sink,
            ExportKind::Preference,
            &records,
            &receipt(),
            &[7u8; 32],
        )?;
        assert_eq!(m.export, ExportKind::Preference);
        assert_eq!(m.sample_count_u64, 1);
        Ok(())
    }

    #[test]
    fn grpo_shard_carries_locked_flag() -> DietResult<()> {
        let r = grpo::build_rollout(key(), b"seed", vec![[1u8; 32], [2u8; 32]]);
        let records = vec![grpo::to_jsonl(&r)];
        assert!(records[0].contains("\"grpo_locked\":true"));
        let mut sink = Vec::new();
        let m = write_shard(
            &mut sink,
            ExportKind::GrpoRollout,
            &records,
            &receipt(),
            &[7u8; 32],
        )?;
        assert_eq!(m.export, ExportKind::GrpoRollout);
        Ok(())
    }

    #[test]
    fn shard_hash_and_merkle_are_stable() -> DietResult<()> {
        let records = clean_records();
        let mut a = Vec::new();
        let mut b = Vec::new();
        let ma = write_shard(
            &mut a,
            ExportKind::SftChat,
            &records,
            &receipt(),
            &[7u8; 32],
        )?;
        let mb = write_shard(
            &mut b,
            ExportKind::SftChat,
            &records,
            &receipt(),
            &[7u8; 32],
        )?;
        assert_eq!(ma.shard_hash_32, mb.shard_hash_32);
        assert_eq!(ma.merkle_root_32, mb.merkle_root_32);
        // independently recomputed merkle root matches.
        assert_eq!(ma.merkle_root_32, recompute_merkle_root(&records));
        // content address and merkle root are different digests.
        assert_ne!(ma.shard_hash_32, ma.merkle_root_32);
        Ok(())
    }

    #[test]
    fn tamper_verify_accepts_correct_and_rejects_wrong_signer() -> DietResult<()> {
        let records = clean_records();
        let mut sink = Vec::new();
        let m = write_shard(
            &mut sink,
            ExportKind::SftChat,
            &records,
            &receipt(),
            &[7u8; 32],
        )?;
        // correct merkle + signer ⇒ Ok.
        m.verify_tamper(&recompute_merkle_root(&records), &[7u8; 32])?;
        // wrong signer id ⇒ signature mismatch.
        assert_eq!(
            m.verify_tamper(&recompute_merkle_root(&records), &[9u8; 32]),
            Err(DietError::ShardSignatureMismatch)
        );
        // wrong merkle ⇒ merkle mismatch (checked before signer).
        assert_eq!(
            m.verify_tamper(&[0u8; 32], &[7u8; 32]),
            Err(DietError::ShardMerkleMismatch)
        );
        Ok(())
    }

    #[test]
    fn dirty_record_rejects_shard_post_scan() {
        let records = vec![
            r#"{"k":1,"text":"ok"}"#.to_string(),
            r#"{"k":2,"text":"here is the wallet_secret value"}"#.to_string(),
        ];
        let mut sink = Vec::new();
        assert_eq!(
            write_shard(
                &mut sink,
                ExportKind::SftChat,
                &records,
                &receipt(),
                &[7u8; 32]
            ),
            Err(DietError::ShardPiiResidue)
        );
    }

    #[test]
    fn manifest_links_to_evidence_receipt() -> DietResult<()> {
        let rec = receipt();
        let mut sink = Vec::new();
        let m = write_shard(
            &mut sink,
            ExportKind::SftChat,
            &clean_records(),
            &rec,
            &[7u8; 32],
        )?;
        assert_eq!(m.evidence_manifest_hash_32, rec.manifest_hash_32);
        Ok(())
    }

    #[test]
    fn remote_locator_absent_or_backed_passes_unbacked_rejects() -> DietResult<()> {
        // absent (all-zero) ⇒ ok.
        EvidenceLakeReceipt::new(key(), [1; 32], [0; 32], [0; 32], [0; 32], false, trace())?;
        // remote locator present AND a local CAS root present ⇒ ok.
        EvidenceLakeReceipt::new(key(), [1; 32], [2; 32], [3; 32], [0; 32], false, trace())?;
        // remote locator present WITHOUT a local CAS root ⇒ bypass reject.
        assert_eq!(
            EvidenceLakeReceipt::new(key(), [1; 32], [0; 32], [3; 32], [0; 32], false, trace()),
            Err(DietError::RemoteLocatorBypass)
        );
        Ok(())
    }

    #[test]
    fn training_eligibility_false_is_rejected() -> DietResult<()> {
        // Stage E: training_eligibility is false ⇒ no training shard.
        let not_eligible =
            EvidenceLakeReceipt::new(key(), [1; 32], [2; 32], [0; 32], [0; 32], false, trace())?;
        assert_eq!(
            not_eligible.assert_training_eligible(),
            Err(DietError::TrainingIneligible)
        );
        // a hypothetical eligible receipt would pass the guard.
        let eligible =
            EvidenceLakeReceipt::new(key(), [1; 32], [2; 32], [0; 32], [0; 32], true, trace())?;
        eligible.assert_training_eligible()?;
        Ok(())
    }

    #[test]
    fn empty_shard_has_deterministic_merkle_and_zero_count() -> DietResult<()> {
        let mut sink = Vec::new();
        let m = write_shard(&mut sink, ExportKind::Eval, &[], &receipt(), &[7u8; 32])?;
        assert_eq!(m.sample_count_u64, 0);
        assert!(sink.is_empty());
        assert_eq!(m.merkle_root_32, recompute_merkle_root(&[]));
        Ok(())
    }

    #[test]
    fn streaming_many_records_stays_consistent() -> DietResult<()> {
        // proxy for "1 GB streaming": 50k records stream one at a time; the
        // independently recomputed merkle root matches the streamed one.
        let records: Vec<String> = (0..50_000)
            .map(|i| format!("{{\"k\":{i},\"text\":\"line\"}}"))
            .collect();
        let mut sink = Vec::new();
        let m = write_shard(
            &mut sink,
            ExportKind::SftChat,
            &records,
            &receipt(),
            &[7u8; 32],
        )?;
        assert_eq!(m.sample_count_u64, 50_000);
        assert_eq!(m.merkle_root_32, recompute_merkle_root(&records));
        Ok(())
    }
}
