//! Final dataset quality filters.
//!
//! # Rationale
//!
//! The last gate before a shard becomes a dataset. The quality filter streams
//! every record and checks, fail-closed: **PII zero**, **encoded-secret bypass**,
//! **dedup**, **split leakage**, **token length**, **malformed JSONL**, **reward
//! provenance** (no reward without an S1 reverify), and the **tamper-proof shard
//! chain** (merkle root + signer binding). No live secret and no user memory may
//! survive.
//!
//! # Secret custody
//!
//! Every record is scanned with `privacy_scanner::scan_str` / `scan` — a pure
//! function over the record text with **no network/wallet/process/filesystem-
//! write API** (mirrors `privacy_scanner` and the `sft_chat` scan-then-reject
//! spine). [`QualityReport`] carries **only `u32`/`u64` counts and a
//! [`PrivacyDecision`]** — never a raw record byte. Every rejection is a
//! byte-free unit/scalar [`DietError`] whose `Error::source` is `None`. The
//! filter performs no live action; `live_action_allowed = false`.
use crate::diet_kind::DietFileKind;
use crate::error::{DietError, DietResult};
use crate::export::sft_chat::TOKEN_CAP;
use crate::export::shard::DatasetShardManifest;
use crate::privacy::PrivacyDecision;
use crate::privacy_scanner;
use crate::split::{self, SplitAssignment};
use std::collections::BTreeSet;
use std::io::BufRead;

/// The quality filter is the eval-summary-producing pass; its redacted I/O and
/// parse errors are tagged with this kind.
const KIND: DietFileKind = DietFileKind::EvalSummary;

/// Approximate token count for `s` (≈ 4 bytes per token; matches `sft_chat`).
fn estimate_tokens(s: &str) -> u32 {
    (s.len() / 4) as u32
}

/// A streaming quality report: counts + a final decision, never a raw byte.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub struct QualityReport {
    /// Number of non-empty records scanned.
    pub records_u64: u64,
    /// Count of redactable PII hits.
    pub pii_hits_u32: u32,
    /// Count of hard-secret hits.
    pub secret_hits_u32: u32,
    /// Count of encoded-secret hits.
    pub encoded_hits_u32: u32,
    /// Count of duplicate records.
    pub duplicate_u32: u32,
    /// Count of malformed (non-JSON) records.
    pub malformed_u32: u32,
    /// Count of records over the token budget.
    pub oversize_u32: u32,
    /// The overall verdict.
    pub decision: PrivacyDecision,
}

impl QualityReport {
    /// Whether nothing at all was flagged.
    pub const fn clean(&self) -> bool {
        self.pii_hits_u32 == 0
            && self.secret_hits_u32 == 0
            && self.encoded_hits_u32 == 0
            && self.duplicate_u32 == 0
            && self.malformed_u32 == 0
            && self.oversize_u32 == 0
    }

    /// Finalize the decision fail-closed: any secret / encoded / malformed /
    /// oversize / duplicate ⇒ `Reject`; PII-only ⇒ `Redacted`; else `Pass`.
    const fn finalize(mut self) -> Self {
        self.decision = if self.secret_hits_u32 > 0
            || self.encoded_hits_u32 > 0
            || self.malformed_u32 > 0
            || self.oversize_u32 > 0
            || self.duplicate_u32 > 0
        {
            PrivacyDecision::Reject
        } else if self.pii_hits_u32 > 0 {
            PrivacyDecision::Redacted
        } else {
            PrivacyDecision::Pass
        };
        self
    }
}

const EMPTY: QualityReport = QualityReport {
    records_u64: 0,
    pii_hits_u32: 0,
    secret_hits_u32: 0,
    encoded_hits_u32: 0,
    duplicate_u32: 0,
    malformed_u32: 0,
    oversize_u32: 0,
    decision: PrivacyDecision::Pass,
};

/// Whether a record line parses as a single JSON value.
fn is_valid_json(line: &str) -> bool {
    serde_json::from_str::<serde_json::Value>(line).is_ok()
}

/// Check one record fail-closed: malformed ⇒ [`DietError::MalformedJsonl`];
/// over-budget ⇒ [`DietError::SftTokenBudgetExceeded`]; secret / encoded ⇒
/// [`DietError::SecretResidue`]. A PII-only record passes (it is redactable, not
/// a hard reject); the streaming [`scan_jsonl`] records the redaction count.
pub fn check_record(line: &str) -> DietResult<()> {
    if !is_valid_json(line) {
        return Err(DietError::MalformedJsonl {
            kind: KIND,
            record_u32: 1,
        });
    }
    let tokens = estimate_tokens(line);
    if tokens > TOKEN_CAP {
        return Err(DietError::SftTokenBudgetExceeded { tokens_u32: tokens });
    }
    let scan = privacy_scanner::scan_str(line);
    if scan.secret_hits_u32 > 0 || scan.encoded_hits_u32 > 0 {
        return Err(DietError::SecretResidue { kind: KIND });
    }
    Ok(())
}

/// Stream every record from `reader`, accumulating a [`QualityReport`] in bounded
/// memory (one line + a set of record digests for dedup). A read failure is a
/// redacted [`DietError::IoUntrusted`]. Empty lines are skipped, not counted.
pub fn scan_jsonl<R: BufRead>(reader: R) -> DietResult<QualityReport> {
    let mut report = EMPTY;
    let mut seen: BTreeSet<[u8; 32]> = BTreeSet::new();
    for line_res in reader.lines() {
        let line = line_res.map_err(|_| DietError::IoUntrusted { kind: KIND })?;
        if line.trim().is_empty() {
            continue;
        }
        report.records_u64 = report.records_u64.saturating_add(1);

        if !is_valid_json(&line) {
            report.malformed_u32 = report.malformed_u32.saturating_add(1);
        }
        if estimate_tokens(&line) > TOKEN_CAP {
            report.oversize_u32 = report.oversize_u32.saturating_add(1);
        }
        let scan = privacy_scanner::scan_str(&line);
        report.pii_hits_u32 = report.pii_hits_u32.saturating_add(scan.pii_hits_u32);
        report.secret_hits_u32 = report.secret_hits_u32.saturating_add(scan.secret_hits_u32);
        report.encoded_hits_u32 = report
            .encoded_hits_u32
            .saturating_add(scan.encoded_hits_u32);

        // dedup by record content digest (bounded set of 32-byte digests).
        let digest = crate::sha256(line.as_bytes());
        if !seen.insert(digest) {
            report.duplicate_u32 = report.duplicate_u32.saturating_add(1);
        }
    }
    Ok(report.finalize())
}

/// Verify reward provenance: a record may claim reward eligibility only if it
/// carries an S1 ground-truth reverify. Fail-closed
/// ([`DietError::RewardProvenanceViolation`]).
pub const fn verify_reward_provenance(
    reward_eligible: bool,
    s1_reverified: bool,
) -> DietResult<()> {
    if reward_eligible && !s1_reverified {
        Err(DietError::RewardProvenanceViolation)
    } else {
        Ok(())
    }
}

/// Verify the split has no leakage (delegates to the canonical guard).
pub fn verify_split(assignments: &[SplitAssignment]) -> DietResult<()> {
    split::verify_no_leakage(assignments)
}

/// Verify a shard's tamper chain against an independently recomputed merkle root
/// and the signer identity (delegates to the canonical shard verifier).
pub fn verify_shard_chain(
    manifest: &DatasetShardManifest,
    recomputed_merkle_32: &[u8; 32],
    signer_id_32: &[u8; 32],
) -> DietResult<()> {
    manifest.verify_tamper(recomputed_merkle_32, signer_id_32)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::StageETraceLink;
    use crate::diet_kind::{AtomDietKey, DietSourceStage};
    use crate::export::ExportKind;
    use crate::export::shard::{EvidenceLakeReceipt, recompute_merkle_root, write_shard};
    use crate::split::{TrainingSplit, assign};
    use std::io::Cursor;

    fn key(a: u16) -> AtomDietKey {
        AtomDietKey::new(DietSourceStage::Phase0, a)
    }

    #[test]
    fn malformed_jsonl_is_rejected() {
        assert!(matches!(
            check_record("{not valid json"),
            Err(DietError::MalformedJsonl { .. })
        ));
    }

    #[test]
    fn oversize_record_is_rejected() {
        let big = format!("{{\"t\":\"{}\"}}", "x".repeat(40_000));
        assert!(matches!(
            check_record(&big),
            Err(DietError::SftTokenBudgetExceeded { .. })
        ));
    }

    #[test]
    fn secret_fixture_is_rejected() {
        assert_eq!(
            check_record(r#"{"t":"the wallet_secret is here"}"#),
            Err(DietError::SecretResidue { kind: KIND })
        );
    }

    #[test]
    fn encoded_secret_fixture_is_rejected() {
        // long high-entropy base64 inside a JSON string.
        let enc = "Zm9vYmFyQUJDMTIzZm9vYmFyQUJDMTIzZm9vYmFyQUJD12345";
        let line = format!("{{\"blob\":\"{enc}\"}}");
        assert_eq!(
            check_record(&line),
            Err(DietError::SecretResidue { kind: KIND })
        );
    }

    #[test]
    fn duplicate_record_is_flagged() -> DietResult<()> {
        let buf = "{\"k\":1}\n{\"k\":1}\n{\"k\":2}\n";
        let r = scan_jsonl(Cursor::new(buf))?;
        assert_eq!(r.records_u64, 3);
        assert_eq!(r.duplicate_u32, 1);
        assert_eq!(r.decision, PrivacyDecision::Reject);
        Ok(())
    }

    #[test]
    fn leakage_is_rejected() {
        let g = [9u8; 32];
        let a = SplitAssignment {
            key: key(1),
            split: TrainingSplit::Train,
            leakage_group_hash_32: g,
        };
        let b = SplitAssignment {
            key: key(2),
            split: TrainingSplit::Test,
            leakage_group_hash_32: g,
        };
        assert_eq!(verify_split(&[a, b]), Err(DietError::SplitLeakageDetected));
        // a single group, two samples, same split ⇒ no leakage.
        let c = assign(key(3), crate::sha256(b"grp"), false);
        let d = assign(key(4), crate::sha256(b"grp"), false);
        assert!(verify_split(&[c, d]).is_ok());
    }

    #[test]
    fn reward_without_s1_is_rejected() {
        assert_eq!(
            verify_reward_provenance(true, false),
            Err(DietError::RewardProvenanceViolation)
        );
        // eligible + reverified ⇒ ok; not-eligible ⇒ ok regardless.
        assert!(verify_reward_provenance(true, true).is_ok());
        assert!(verify_reward_provenance(false, false).is_ok());
    }

    #[test]
    fn shard_signature_mismatch_is_rejected() -> DietResult<()> {
        let receipt = EvidenceLakeReceipt::new(
            key(399),
            [1; 32],
            [2; 32],
            [0; 32],
            [0; 32],
            false,
            StageETraceLink::new([0; 32], 399, 0),
        )?;
        let records = vec![r#"{"k":1}"#.to_string(), r#"{"k":2}"#.to_string()];
        let mut sink = Vec::new();
        let m = write_shard(
            &mut sink,
            ExportKind::SftChat,
            &records,
            &receipt,
            &[7u8; 32],
        )?;
        let merkle = recompute_merkle_root(&records);
        // correct signer ⇒ ok; wrong signer ⇒ signature mismatch.
        verify_shard_chain(&m, &merkle, &[7u8; 32])?;
        assert_eq!(
            verify_shard_chain(&m, &merkle, &[8u8; 32]),
            Err(DietError::ShardSignatureMismatch)
        );
        Ok(())
    }

    #[test]
    fn clean_stream_passes_in_streaming_mode() -> DietResult<()> {
        let mut buf = String::new();
        for i in 0..5_000 {
            buf.push_str(&format!("{{\"k\":{i},\"t\":\"cargo test exit 0\"}}\n"));
        }
        let r = scan_jsonl(Cursor::new(buf))?;
        assert!(r.clean());
        assert_eq!(r.decision, PrivacyDecision::Pass);
        assert_eq!(r.records_u64, 5_000);
        Ok(())
    }

    #[test]
    fn one_secret_in_a_large_stream_rejects() -> DietResult<()> {
        let mut buf = String::new();
        for i in 0..2_000 {
            buf.push_str(&format!("{{\"k\":{i}}}\n"));
        }
        buf.push_str("{\"leak\":\"wallet_secret value\"}\n");
        let r = scan_jsonl(Cursor::new(buf))?;
        assert!(r.secret_hits_u32 >= 1);
        assert_eq!(r.decision, PrivacyDecision::Reject);
        Ok(())
    }
}
