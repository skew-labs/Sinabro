//! `sinabro dataset ingest` — dataset ingest / redact / dedup controls
//! (F-WP-06B, atom #454 · F.6.3).
//!
//! A read-only control surface over the Stage E AtomDiet corpus: it previews
//! what an ingest would cover, runs the canonical redaction scan, reports a
//! content-hash dedup, and projects whether a source record is training
//! eligible — all without mutating any locked dataset shard. Stage F may
//! prepare/validate but never silently rewrites locked truth.
//!
//! Reuse (no reinvention): the source record is the Stage E
//! [`mnemos_l_dataset::AtomDietRecord`]; the redaction gate is the canonical
//! [`mnemos_l_dataset::privacy_scanner::scan_str`] returning a
//! [`ScanReport`]; the verdict is [`PrivacyDecision`]. This module mints no new
//! dataset type and performs no live action.

use std::collections::BTreeSet;

use crate::tui::RenderTruth;
use mnemos_l_dataset::AtomDietRecord;
use mnemos_l_dataset::privacy::PrivacyDecision;
use mnemos_l_dataset::privacy_scanner::{ScanReport, scan_str};

/// Why a dataset-ingest command was refused (fail-closed).
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum DatasetIngestReject {
    /// The candidate content carried secret / PII / encoded-secret residue and
    /// cannot be ingested until redaction passes.
    #[error("redaction residue present")]
    RedactionResidue,
    /// Stage F cannot mutate a locked dataset shard.
    #[error("locked shard write denied")]
    LockedShardWrite,
}

/// One file in an ingest preview: its kind tag, byte length, and content hash.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct IngestFileSpec {
    /// The diet file-kind discriminant (1..=21).
    pub kind_u8: u8,
    /// The file length in bytes.
    pub bytes_u64: u64,
    /// `sha256` of the file content (used for dedup).
    pub content_hash_32: [u8; 32],
}

impl IngestFileSpec {
    /// Construct an ingest file spec.
    #[must_use]
    pub const fn new(kind_u8: u8, bytes_u64: u64, content_hash_32: [u8; 32]) -> Self {
        Self {
            kind_u8,
            bytes_u64,
            content_hash_32,
        }
    }
}

/// A `sinabro dataset ingest` projection: what an ingest covers, its redaction
/// verdict, and the training-eligibility of the source record.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DatasetIngestView {
    /// Number of files in the ingest set.
    pub file_count_u32: u32,
    /// Total bytes across the ingest set.
    pub total_bytes_u64: u64,
    /// Distinct files after content-hash dedup.
    pub unique_count_u32: u32,
    /// The redaction verdict (Pass / Redacted / Reject).
    pub redaction: PrivacyDecision,
    /// Whether the source record is training eligible (display only — Stage F
    /// never executes training).
    pub training_eligible: bool,
}

impl DatasetIngestView {
    /// Run the canonical redaction scan over candidate text. A clean scan returns
    /// the [`ScanReport`]; any secret / PII / encoded residue is refused.
    pub fn redaction_gate(raw: &str) -> Result<ScanReport, DatasetIngestReject> {
        let report = scan_str(raw);
        if report.clean() {
            Ok(report)
        } else {
            Err(DatasetIngestReject::RedactionResidue)
        }
    }

    /// Count distinct files by content hash (the dedup the ingest would apply).
    #[must_use]
    pub fn unique_count(files: &[IngestFileSpec]) -> u32 {
        let set: BTreeSet<[u8; 32]> = files.iter().map(|f| f.content_hash_32).collect();
        u32::try_from(set.len()).unwrap_or(u32::MAX)
    }

    /// Build an ingest view from the candidate file set, its redaction report, and
    /// the source [`AtomDietRecord`].
    #[must_use]
    pub fn from_ingest(
        files: &[IngestFileSpec],
        redaction: &ScanReport,
        record: &AtomDietRecord,
    ) -> Self {
        let total_bytes_u64 = files
            .iter()
            .map(|f| f.bytes_u64)
            .fold(0u64, u64::saturating_add);
        Self {
            file_count_u32: u32::try_from(files.len()).unwrap_or(u32::MAX),
            total_bytes_u64,
            unique_count_u32: Self::unique_count(files),
            redaction: redaction.decision,
            training_eligible: record.training_eligible(),
        }
    }

    /// Whether Stage F may write a locked dataset shard — always `false`.
    #[must_use]
    pub const fn locked_shard_write_allowed() -> bool {
        false
    }

    /// Attempt to write a locked shard — always refused in Stage F.
    pub const fn try_write_locked_shard() -> Result<(), DatasetIngestReject> {
        Err(DatasetIngestReject::LockedShardWrite)
    }

    /// Render truth: a non-`Pass` redaction verdict is `Red` (ingest blocked);
    /// otherwise `Green`. Training eligibility is display-only and never lifts the
    /// verdict.
    #[must_use]
    pub fn render_truth(&self) -> RenderTruth {
        match self.redaction {
            PrivacyDecision::Pass => RenderTruth::Green,
            _ => RenderTruth::Red,
        }
    }

    /// Colorless status lines bounded by `rows`.
    #[must_use]
    pub fn render(&self, rows: u16) -> Vec<String> {
        let lines = vec![
            format!("file_count={}", self.file_count_u32),
            format!("total_bytes={}", self.total_bytes_u64),
            format!("unique_count={}", self.unique_count_u32),
            format!("redaction_u8={}", self.redaction.as_u8()),
            format!("training_eligible={}", self.training_eligible),
            format!(
                "locked_shard_write_allowed={}",
                Self::locked_shard_write_allowed()
            ),
            format!("truth_u8={}", self.render_truth() as u8),
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
    use mnemos_l_dataset::diet_kind::DietSourceStage;
    use mnemos_l_dataset::manifest::{AtomDietManifest, DietCompleteness, DietFileRef};
    use mnemos_l_dataset::{AtomDietKey, DietFileKind, StageETraceLink};

    const COMMERCE_TOKENS: &[&str] = &[
        "price", "pay", "buy", "sell", "checkout", "refund", "fee", "cost", "$",
    ];

    /// Build a source record. `complete` => `DietCompleteness::Complete`, else the
    /// reward-blocked `PartialNoReward`.
    fn record(complete: bool) -> AtomDietRecord {
        let key = AtomDietKey::new(DietSourceStage::StageD, 250);
        let completeness = if complete {
            DietCompleteness::Complete
        } else {
            DietCompleteness::PartialNoReward
        };
        let files = vec![DietFileRef::new(
            DietFileKind::InputContext,
            [1u8; 32],
            [2u8; 32],
            10,
        )];
        let manifest = AtomDietManifest::new(
            1,
            key,
            files,
            completeness,
            StageETraceLink::new([3u8; 32], 250, 1),
        );
        AtomDietRecord {
            manifest,
            s1_hash_32: [4u8; 32],
            s2_hash_32: [5u8; 32],
            privacy_hash_32: [6u8; 32],
            trajectory_hash_32: [7u8; 32],
            compression_hash_32: [8u8; 32],
        }
    }

    #[test]
    fn ingest_preview_counts_and_bytes() {
        let r = record(false);
        let files = vec![
            IngestFileSpec::new(1, 100, [0xAA; 32]),
            IngestFileSpec::new(2, 200, [0xBB; 32]),
        ];
        let report = DatasetIngestView::redaction_gate("a perfectly ordinary sentence").unwrap();
        let v = DatasetIngestView::from_ingest(&files, &report, &r);
        assert_eq!(v.file_count_u32, 2);
        assert_eq!(v.total_bytes_u64, 300);
        assert_eq!(v.unique_count_u32, 2);
        assert_eq!(v.redaction, PrivacyDecision::Pass);
        assert_eq!(v.render_truth(), RenderTruth::Green);
        assert_eq!(v.training_eligible, r.training_eligible());
    }

    #[test]
    fn dedup_counts_distinct_content() {
        let files = vec![
            IngestFileSpec::new(1, 10, [0x01; 32]),
            IngestFileSpec::new(2, 20, [0x01; 32]), // duplicate content hash
            IngestFileSpec::new(3, 30, [0x02; 32]),
        ];
        assert_eq!(DatasetIngestView::unique_count(&files), 2);
    }

    #[test]
    fn redaction_gate_mirrors_scanner_cleanliness() {
        // The gate accepts clean text and refuses exactly when the canonical
        // scanner is not clean — no guessing of the scanner's internal detection.
        assert!(DatasetIngestView::redaction_gate("a perfectly ordinary sentence").is_ok());
        let raw = "ghp_ABCDEFGHIJKLMNOP aws_secret_access_key=AKIA";
        let direct = scan_str(raw);
        let gated = DatasetIngestView::redaction_gate(raw);
        assert_eq!(gated.is_err(), !direct.clean());
        if !direct.clean() {
            assert_eq!(gated, Err(DatasetIngestReject::RedactionResidue));
        }
    }

    #[test]
    fn locked_shard_write_denied() {
        assert!(!DatasetIngestView::locked_shard_write_allowed());
        assert_eq!(
            DatasetIngestView::try_write_locked_shard(),
            Err(DatasetIngestReject::LockedShardWrite)
        );
    }

    #[test]
    fn training_eligibility_false_for_partial_record() {
        let r = record(false);
        assert!(!r.training_eligible());
        let report = DatasetIngestView::redaction_gate("clean").unwrap();
        let v = DatasetIngestView::from_ingest(&[], &report, &r);
        assert!(!v.training_eligible);
    }

    #[test]
    fn render_bounded_no_commerce() {
        let r = record(false);
        let report = DatasetIngestView::redaction_gate("clean").unwrap();
        let v =
            DatasetIngestView::from_ingest(&[IngestFileSpec::new(1, 1, [0u8; 32])], &report, &r);
        assert!(v.render(3).len() <= 3);
        assert!(v.render(64).len() <= 7);
        for line in v.render(64) {
            for bad in COMMERCE_TOKENS {
                assert!(!line.contains(bad), "commerce token {bad} in {line}");
            }
        }
    }

    #[test]
    fn dataset_ingest_p95_within_100ms() {
        let r = record(false);
        let files = vec![
            IngestFileSpec::new(1, 100, [0xAA; 32]),
            IngestFileSpec::new(2, 200, [0xBB; 32]),
        ];
        let report = DatasetIngestView::redaction_gate("clean").unwrap();
        let v = DatasetIngestView::from_ingest(&files, &report, &r);
        let mut samples = Vec::with_capacity(256);
        for _ in 0..256 {
            let t = std::time::Instant::now();
            let lines = v.render(32);
            std::hint::black_box(&lines);
            samples.push(t.elapsed().as_nanos() as u64);
        }
        let p95 = crate::repl::latency::p95_ms(&samples) / 1_000_000;
        assert!(
            p95 <= 100,
            "dataset ingest p95 {p95}ms exceeds 100ms budget"
        );
    }
}
