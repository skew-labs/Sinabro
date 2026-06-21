//! Stage B replay-evidence importer (C-WP-01 · atom #176 · C.0.5).
//!
//! Canonical OUT: an importer for the Stage B [`StageBReplayReport`] /
//! [`StageBTranscriptHash32`] into a Stage C evidence linkage.
//!
//! # Madness invariants (atom #176)
//!
//! * **Evidence is linked to a deterministic B replay root, not loose logs.**
//!   A [`StageCReplayImport`] is built from a finished [`StageBReplayReport`]
//!   and the [`StageBReplayState`] it produced, binding the Stage A
//!   [`ReplayCursor`] (the recovered custody root) to the transcript hash. The
//!   importer performs **no live mainnet/testnet call** — it consumes already
//!   computed deterministic Stage B values.
//! * **Transcript mismatch is rejected.** [`StageCReplayImport::from_report`]
//!   takes the *expected* transcript hash and refuses
//!   ([`StageCReplayImportError::TranscriptMismatch`]) any report whose
//!   transcript does not match it byte-for-byte.
//! * **Duplicate import is idempotent.** [`StageCReplayImportLedger`] dedups by
//!   transcript hash: re-importing an already-seen transcript returns
//!   [`StageCImportOutcome::DuplicateIgnored`] and does not grow the ledger.
//! * **No re-mint.** The transcript reuses the Stage B canonical type; the
//!   cursor reuses the Stage A [`ReplayCursor`]; no parallel evidence type is
//!   minted.

use crate::replay::ReplayCursor;
use crate::stage_b_replay::{StageBReplayReport, StageBReplayState, StageBTranscriptHash32};

/// Why a Stage B replay report was refused for Stage C import.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
#[repr(u8)]
pub enum StageCReplayImportError {
    /// The report's transcript hash did not match the expected transcript.
    TranscriptMismatch = 1,
}

/// A Stage C evidence linkage to one deterministic Stage B replay.
///
/// Binds the Stage B transcript hash (the deterministic custody root) to the
/// recovered Stage A [`ReplayCursor`] and the applied/duplicate/rejected event
/// counts copied verbatim from the [`StageBReplayReport`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct StageCReplayImport {
    /// The deterministic Stage B replay transcript hash.
    pub transcript: StageBTranscriptHash32,
    /// The Stage A recovered custody cursor at the end of the replay.
    pub cursor: ReplayCursor,
    /// Count of applied (accepted) events.
    pub applied_u64: u64,
    /// Count of idempotently-ignored duplicate anchors.
    pub duplicate_u64: u64,
    /// Count of rejected events.
    pub rejected_u64: u64,
}

impl StageCReplayImport {
    /// Build a Stage C import from a finished Stage B report + the state it
    /// produced, validating the transcript against `expected`.
    ///
    /// Returns [`StageCReplayImportError::TranscriptMismatch`] if
    /// `report.transcript != expected`.
    #[inline]
    pub fn from_report(
        report: &StageBReplayReport,
        state: &StageBReplayState,
        expected: StageBTranscriptHash32,
    ) -> Result<Self, StageCReplayImportError> {
        if report.transcript != expected {
            return Err(StageCReplayImportError::TranscriptMismatch);
        }
        Ok(Self {
            transcript: report.transcript,
            cursor: state.cursor,
            applied_u64: report.applied_u64,
            duplicate_u64: report.duplicate_u64,
            rejected_u64: report.rejected_u64,
        })
    }

    /// Borrow the 32-byte transcript hash that identifies this import.
    #[inline]
    pub const fn transcript_bytes(&self) -> &[u8; 32] {
        self.transcript.as_bytes()
    }
}

/// Outcome of importing a [`StageCReplayImport`] into a ledger.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
#[repr(u8)]
pub enum StageCImportOutcome {
    /// The transcript was new and was recorded.
    Inserted = 1,
    /// The transcript was already present — ignored idempotently.
    DuplicateIgnored = 2,
}

/// A dedup ledger of imported Stage B replay transcripts.
///
/// Importing is idempotent on the transcript hash: a transcript already in the
/// ledger yields [`StageCImportOutcome::DuplicateIgnored`] without growing the
/// ledger. The order of first insertion is preserved.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct StageCReplayImportLedger {
    imported: Vec<StageBTranscriptHash32>,
}

impl StageCReplayImportLedger {
    /// A fresh, empty ledger.
    #[inline]
    pub const fn new() -> Self {
        Self {
            imported: Vec::new(),
        }
    }

    /// Import one Stage C replay record, deduping by transcript hash.
    pub fn import(&mut self, item: &StageCReplayImport) -> StageCImportOutcome {
        if self.imported.contains(&item.transcript) {
            return StageCImportOutcome::DuplicateIgnored;
        }
        self.imported.push(item.transcript);
        StageCImportOutcome::Inserted
    }

    /// Number of distinct transcripts recorded.
    #[inline]
    pub fn len(&self) -> usize {
        self.imported.len()
    }

    /// Whether the ledger has no recorded transcripts.
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.imported.is_empty()
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]
    use super::*;
    use crate::stage_b_replay::stage_b_transcript_hash;

    fn report_with(transcript: StageBTranscriptHash32) -> StageBReplayReport {
        StageBReplayReport {
            transcript,
            applied_u64: 3,
            duplicate_u64: 1,
            rejected_u64: 2,
        }
    }

    #[test]
    fn valid_report_is_accepted_and_carries_the_replay_root() {
        let t = stage_b_transcript_hash(b"replay-A");
        let report = report_with(t);
        let state = StageBReplayState::start();
        let import = StageCReplayImport::from_report(&report, &state, t)
            .expect("matching transcript is accepted");
        assert_eq!(import.transcript, t);
        assert_eq!(import.cursor, state.cursor);
        assert_eq!(import.applied_u64, 3);
        assert_eq!(import.duplicate_u64, 1);
        assert_eq!(import.rejected_u64, 2);
        assert_eq!(import.transcript_bytes(), t.as_bytes());
    }

    #[test]
    fn mismatched_transcript_is_rejected() {
        let real = stage_b_transcript_hash(b"replay-A");
        let other = stage_b_transcript_hash(b"replay-B");
        let report = report_with(real);
        let state = StageBReplayState::start();
        let err = StageCReplayImport::from_report(&report, &state, other)
            .expect_err("transcript mismatch must be rejected");
        assert_eq!(err, StageCReplayImportError::TranscriptMismatch);
    }

    #[test]
    fn duplicate_import_is_idempotent() {
        let t = stage_b_transcript_hash(b"replay-A");
        let report = report_with(t);
        let state = StageBReplayState::start();
        let import = StageCReplayImport::from_report(&report, &state, t).expect("accepted");

        let mut ledger = StageCReplayImportLedger::new();
        assert!(ledger.is_empty());
        assert_eq!(ledger.import(&import), StageCImportOutcome::Inserted);
        assert_eq!(ledger.len(), 1);
        // Re-importing the same transcript does not grow the ledger.
        assert_eq!(
            ledger.import(&import),
            StageCImportOutcome::DuplicateIgnored
        );
        assert_eq!(ledger.len(), 1);

        // A different transcript is a distinct insert.
        let t2 = stage_b_transcript_hash(b"replay-B");
        let report2 = report_with(t2);
        let import2 = StageCReplayImport::from_report(&report2, &state, t2).expect("accepted");
        assert_eq!(ledger.import(&import2), StageCImportOutcome::Inserted);
        assert_eq!(ledger.len(), 2);
    }
}
