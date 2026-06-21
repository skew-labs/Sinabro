//! Importance score (Stage D Cluster 6, atom #324 · D.5.3).
//!
//! [`ImportanceScore`] (§4.6) attaches a bounded `0..=10000` score to a
//! [`MemoryId`], optionally adjusted by a user [`FeedbackLabel`], and stamped
//! with the scoring model's hash.
//!
//! The model is **small, local, explainable and label-aware**: the score is a
//! fixed integer-weighted blend of recency, access frequency and content size,
//! plus a transparent per-label delta. There is no opaque learned weight, no
//! network call, and no hidden state. Crucially, it **cannot silently retain a
//! deleted memory**: scoring a tombstoned id is rejected fail-closed
//! ([`ImportanceError::DeletedTombstoneBlocked`]).

use crate::chunk::MemoryId;
use crate::intelligence::feedback::FeedbackLabel;
use mnemos_c_walrus::derive_blob_id;

/// Maximum importance score (basis-point scale, 10000 = 1.0).
pub const MAX_IMPORTANCE_SCORE: u16 = 10_000;

const MODEL_VERSION_U16: u16 = 1;
const W_RECENCY: i64 = 50;
const W_ACCESS: i64 = 30;
const W_LEN: i64 = 20;
const MODEL_DOMAIN: &[u8] = b"mnemos.stage_d.importance.v1";

/// Explainable features the importance model scores over. Each is a transparent,
/// caller-supplied signal — there is no hidden retrieval.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub struct ImportanceFeatures {
    /// Recency rank, `0` = most recent. Higher rank = older = less important.
    pub recency_rank_u16: u16,
    /// How many times the memory has been accessed.
    pub access_count_u16: u16,
    /// Content length in bytes.
    pub content_len_u32: u32,
}

/// A scored memory (§4.6).
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub struct ImportanceScore {
    /// Which memory was scored.
    pub memory: MemoryId,
    /// Bounded score in `0..=10000`.
    pub score_u16: u16,
    /// User feedback label applied, if any.
    pub label: Option<FeedbackLabel>,
    /// Hash of the scoring model that produced this score.
    pub model_hash_32: [u8; 32],
}

/// Importance error set (frozen). Every variant is a data-free tag.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
#[non_exhaustive]
pub enum ImportanceError {
    /// The memory is tombstoned; a deleted memory is never scored or retained.
    DeletedTombstoneBlocked,
}

/// The small local importance model (stateless; fixed transparent weights).
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ImportanceModel;

impl ImportanceModel {
    /// Construct the model. It carries no learned state — the weights are fixed
    /// constants pinned into [`model_hash`](Self::model_hash).
    #[must_use]
    pub const fn new() -> Self {
        Self
    }

    /// The 32-byte hash of this model: a [`derive_blob_id`] digest over the
    /// model domain, version and the three integer weights. Deterministic and
    /// stable across calls; it changes only if the model definition changes.
    #[must_use]
    pub fn model_hash(&self) -> [u8; 32] {
        let mut d = Vec::with_capacity(MODEL_DOMAIN.len() + 2 + 24);
        d.extend_from_slice(MODEL_DOMAIN);
        d.extend_from_slice(&MODEL_VERSION_U16.to_le_bytes());
        d.extend_from_slice(&W_RECENCY.to_le_bytes());
        d.extend_from_slice(&W_ACCESS.to_le_bytes());
        d.extend_from_slice(&W_LEN.to_le_bytes());
        *derive_blob_id(&d).as_bytes()
    }

    /// Score a memory. Tombstoned (`deleted`) memories are blocked. The score is
    /// a transparent integer blend clamped to `0..=10000`, then adjusted by the
    /// user label delta and re-clamped.
    pub fn score(
        &self,
        memory: MemoryId,
        features: &ImportanceFeatures,
        label: Option<FeedbackLabel>,
        deleted: bool,
    ) -> Result<ImportanceScore, ImportanceError> {
        if deleted {
            return Err(ImportanceError::DeletedTombstoneBlocked);
        }
        let recency = i64::from(MAX_IMPORTANCE_SCORE)
            - i64::from(features.recency_rank_u16).min(i64::from(MAX_IMPORTANCE_SCORE));
        let access =
            (i64::from(features.access_count_u16) * 100).min(i64::from(MAX_IMPORTANCE_SCORE));
        let len = (i64::from(features.content_len_u32) / 10).min(i64::from(MAX_IMPORTANCE_SCORE));
        let base = (W_RECENCY * recency + W_ACCESS * access + W_LEN * len) / 100;
        let adjusted = base + label_delta(label);
        let clamped = adjusted.clamp(0, i64::from(MAX_IMPORTANCE_SCORE));
        Ok(ImportanceScore {
            memory,
            score_u16: clamped as u16,
            label,
            model_hash_32: self.model_hash(),
        })
    }
}

/// Transparent per-label score delta. `Forget` and `Boundary` drive the score to
/// the floor; `Promote`/`Demote` are bounded nudges; `Keep` is neutral.
const fn label_delta(label: Option<FeedbackLabel>) -> i64 {
    match label {
        None | Some(FeedbackLabel::Keep) => 0,
        Some(FeedbackLabel::Promote) => 2_000,
        Some(FeedbackLabel::Demote) => -2_000,
        Some(FeedbackLabel::Forget) | Some(FeedbackLabel::Boundary) => {
            -(MAX_IMPORTANCE_SCORE as i64)
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    #![allow(clippy::expect_used)]
    #![allow(clippy::panic)]

    use super::*;

    fn features(recency: u16, access: u16, len: u32) -> ImportanceFeatures {
        ImportanceFeatures {
            recency_rank_u16: recency,
            access_count_u16: access,
            content_len_u32: len,
        }
    }

    #[test]
    fn score_within_bounds() {
        let m = ImportanceModel::new();
        // Extreme high inputs still clamp to 10000.
        let high = m
            .score(
                MemoryId::new(1),
                &features(0, u16::MAX, u32::MAX),
                None,
                false,
            )
            .unwrap();
        assert!(high.score_u16 <= MAX_IMPORTANCE_SCORE);
        // Extreme low inputs floor at 0.
        let low = m
            .score(MemoryId::new(2), &features(u16::MAX, 0, 0), None, false)
            .unwrap();
        assert!(low.score_u16 <= MAX_IMPORTANCE_SCORE);
        // Forget label drives the score to the floor.
        let forgotten = m
            .score(
                MemoryId::new(3),
                &features(0, u16::MAX, u32::MAX),
                Some(FeedbackLabel::Forget),
                false,
            )
            .unwrap();
        assert_eq!(forgotten.score_u16, 0);
    }

    #[test]
    fn model_hash_is_stable_and_nonzero() {
        let m = ImportanceModel::new();
        let h1 = m.model_hash();
        let h2 = m.model_hash();
        assert_eq!(h1, h2);
        assert_ne!(h1, [0_u8; 32]);
    }

    #[test]
    fn deleted_tombstone_score_blocked() {
        let m = ImportanceModel::new();
        assert_eq!(
            m.score(MemoryId::new(4), &features(0, 5, 100), None, true),
            Err(ImportanceError::DeletedTombstoneBlocked)
        );
    }

    #[test]
    fn deterministic_fixture() {
        let m = ImportanceModel::new();
        let f = features(10, 4, 250);
        let a = m
            .score(MemoryId::new(5), &f, Some(FeedbackLabel::Keep), false)
            .unwrap();
        let b = m
            .score(MemoryId::new(5), &f, Some(FeedbackLabel::Keep), false)
            .unwrap();
        assert_eq!(a, b);
        // Promote raises the score relative to Keep on the same features.
        let keep = m
            .score(MemoryId::new(6), &f, Some(FeedbackLabel::Keep), false)
            .unwrap();
        let promote = m
            .score(MemoryId::new(6), &f, Some(FeedbackLabel::Promote), false)
            .unwrap();
        assert!(promote.score_u16 >= keep.score_u16);
    }
}
