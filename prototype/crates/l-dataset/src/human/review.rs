//! Human review schema.
//!
//! Re-exports the canonical [`HumanReviewSignal`] (defined in
//! `collect::audit_repo_pair`, never reinvented) and adds a per-record verdict
//! parser over `human_review.jsonl`. A reviewer's verdict is **provenance and
//! preference signal, not ground-truth reward by itself**: the reviewer id and
//! comment are hashed (never stored raw), and an approval alone never sets a
//! reward label. A reviewer id or comment that carries secret residue rejects.
pub use crate::collect::audit_repo_pair::HumanReviewSignal;
use crate::diet_kind::{AtomDietKey, DietFileKind};
use crate::error::{DietError, DietResult};
use crate::terminal::looks_secret;
use serde_json::Value;

const KIND: DietFileKind = DietFileKind::HumanReview;

/// A human reviewer's verdict on a change.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
#[repr(u8)]
pub enum ReviewVerdict {
    /// The change was approved.
    Approved = 1,
    /// Changes were requested (not a hard rejection).
    RequestedChanges = 2,
    /// The change was rejected.
    Rejected = 3,
}

impl ReviewVerdict {
    /// Numeric discriminant (`1..=3`).
    pub const fn as_u8(self) -> u8 {
        self as u8
    }

    /// Classify a verdict string. Unknown / unset fall to `RequestedChanges`
    /// (neither an approval nor a hard rejection), never silently `Approved`.
    pub fn from_tag(s: &str) -> Self {
        match s.trim().to_ascii_lowercase().as_str() {
            "approved" | "approve" | "lgtm" | "accept" => Self::Approved,
            "rejected" | "reject" | "deny" | "denied" => Self::Rejected,
            _ => Self::RequestedChanges,
        }
    }

    /// Only an explicit approval counts as approved provenance.
    pub const fn is_approved(self) -> bool {
        matches!(self, Self::Approved)
    }
}

/// One normalized human review record (reviewer + comment hashed, never raw).
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub struct HumanReviewRecord {
    /// The reviewer's verdict.
    pub verdict: ReviewVerdict,
    /// `sha256` of the reviewer identifier.
    pub reviewer_hash_32: [u8; 32],
    /// `sha256` of the review comment.
    pub comment_hash_32: [u8; 32],
}

/// Parse `human_review.jsonl` into normalized review records. Reviewer id and
/// comment are hashed; secret residue in either is a hard reject.
pub fn parse_reviews(text: &str) -> DietResult<Vec<HumanReviewRecord>> {
    let mut out = Vec::new();
    let mut rec = 0u32;
    for line in text.lines() {
        if line.trim().is_empty() {
            continue;
        }
        rec = rec.saturating_add(1);
        let v: Value = serde_json::from_str(line).map_err(|_| DietError::MalformedJsonl {
            kind: KIND,
            record_u32: rec,
        })?;
        let obj = v.as_object().ok_or(DietError::MalformedJsonl {
            kind: KIND,
            record_u32: rec,
        })?;
        let verdict = ReviewVerdict::from_tag(
            obj.get("verdict")
                .and_then(|x| x.as_str())
                .unwrap_or("requested_changes"),
        );
        let reviewer = obj
            .get("reviewer")
            .and_then(|x| x.as_str())
            .unwrap_or("none");
        let comment = obj
            .get("comment")
            .and_then(|x| x.as_str())
            .unwrap_or("none");
        if looks_secret(reviewer) || looks_secret(comment) {
            return Err(DietError::SecretResidue { kind: KIND });
        }
        out.push(HumanReviewRecord {
            verdict,
            reviewer_hash_32: crate::sha256(reviewer.as_bytes()),
            comment_hash_32: crate::sha256(comment.as_bytes()),
        });
    }
    Ok(out)
}

/// Aggregate parsed reviews into the canonical [`HumanReviewSignal`].
/// `approved` requires at least one approval and **no** rejection; the reviewer
/// and comment anchors are deterministic folds over the per-record hashes.
pub fn signal(key: AtomDietKey, reviews: &[HumanReviewRecord]) -> HumanReviewSignal {
    let approved = !reviews.is_empty()
        && reviews.iter().any(|r| r.verdict.is_approved())
        && !reviews
            .iter()
            .any(|r| matches!(r.verdict, ReviewVerdict::Rejected));
    let mut rbuf = Vec::with_capacity(reviews.len() * 32);
    let mut cbuf = Vec::with_capacity(reviews.len() * 32);
    for r in reviews {
        rbuf.extend_from_slice(&r.reviewer_hash_32);
        cbuf.extend_from_slice(&r.comment_hash_32);
    }
    HumanReviewSignal {
        key,
        approved,
        reviewer_hash_32: crate::sha256(&rbuf),
        comment_hash_32: crate::sha256(&cbuf),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::diet_kind::DietSourceStage;

    fn key() -> AtomDietKey {
        AtomDietKey::new(DietSourceStage::StageD, 374)
    }

    #[test]
    fn approved_requested_rejected_parse() -> DietResult<()> {
        let doc = concat!(
            r#"{"verdict":"approved","reviewer":"owner","comment":"lgtm"}"#,
            "\n",
            r#"{"verdict":"requested_changes","reviewer":"alice","comment":"nit"}"#,
            "\n",
            r#"{"verdict":"rejected","reviewer":"bob","comment":"no"}"#,
            "\n",
        );
        let r = parse_reviews(doc)?;
        assert_eq!(r.len(), 3);
        assert_eq!(r[0].verdict, ReviewVerdict::Approved);
        assert_eq!(r[1].verdict, ReviewVerdict::RequestedChanges);
        assert_eq!(r[2].verdict, ReviewVerdict::Rejected);
        Ok(())
    }

    #[test]
    fn reviewer_id_is_hashed() -> DietResult<()> {
        let r = parse_reviews(r#"{"verdict":"approved","reviewer":"owner","comment":"ok"}"#)?;
        assert_eq!(r[0].reviewer_hash_32, crate::sha256(b"owner"));
        Ok(())
    }

    #[test]
    fn signal_approved_requires_approval_and_no_rejection() -> DietResult<()> {
        let approved = parse_reviews(r#"{"verdict":"approved","reviewer":"o","comment":"ok"}"#)?;
        assert!(signal(key(), &approved).approved);
        let mixed = parse_reviews(concat!(
            r#"{"verdict":"approved","reviewer":"o","comment":"ok"}"#,
            "\n",
            r#"{"verdict":"rejected","reviewer":"p","comment":"no"}"#,
            "\n",
        ))?;
        assert!(!signal(key(), &mixed).approved);
        Ok(())
    }

    #[test]
    fn secret_in_comment_rejects() {
        let doc =
            r#"{"verdict":"approved","reviewer":"o","comment":"key sk-live_ABCDEF0123456789"}"#;
        assert!(matches!(
            parse_reviews(doc),
            Err(DietError::SecretResidue {
                kind: DietFileKind::HumanReview
            })
        ));
    }
}
