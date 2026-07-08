//! Preference pair export builder.
//!
//! # Rationale
//!
//! Preference pairs prefer a **verified fix** over a failed attempt, a **safe
//! deny** over an unsafe success, and a **privacy-clean** candidate over any
//! contaminated one. A contaminated (privacy-failing) candidate is excluded from
//! export entirely — it can appear on neither side of a pair. Two candidates of
//! equal rank cannot form a pair.
use crate::diet_kind::{AtomDietKey, DietFileKind};
use crate::error::{DietError, DietResult};

use super::ExportKind;

const KIND: DietFileKind = DietFileKind::PreferencePairs;

/// The safety/verification outcome of a candidate, ordered by preference rank
/// (higher discriminant = more preferred).
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
#[repr(u8)]
pub enum CandidateOutcome {
    /// "Succeeded" but via an unsafe path — least preferred.
    UnsafeSuccess = 1,
    /// A genuine, safe failed attempt.
    FailedAttempt = 2,
    /// A safe refusal of an unsafe action.
    SafeDeny = 3,
    /// A reverified, eligible fix — most preferred.
    VerifiedFix = 4,
}

impl CandidateOutcome {
    /// Numeric discriminant (the preference rank).
    pub const fn as_u8(self) -> u8 {
        self as u8
    }
}

/// One preference candidate.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub struct PreferenceCandidate {
    /// The source atom.
    pub key: AtomDietKey,
    /// `sha256` of the candidate content (text-free).
    pub content_hash_32: [u8; 32],
    /// The safety/verification outcome.
    pub outcome: CandidateOutcome,
    /// Whether the candidate passed privacy.
    pub privacy_pass: bool,
}

/// A built preference pair (chosen strictly preferred over rejected).
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub struct PreferencePair {
    /// The source atom of the chosen candidate.
    pub key: AtomDietKey,
    /// `sha256` of the preferred content.
    pub chosen_hash_32: [u8; 32],
    /// `sha256` of the rejected content.
    pub rejected_hash_32: [u8; 32],
    /// Export tag (always [`ExportKind::Preference`]).
    pub export: ExportKind,
}

/// Build a preference pair from two candidates. A contaminated candidate is
/// excluded (hard privacy reject); two equal-rank candidates cannot be paired.
pub fn build_pair(a: PreferenceCandidate, b: PreferenceCandidate) -> DietResult<PreferencePair> {
    if !a.privacy_pass || !b.privacy_pass {
        return Err(DietError::PrivacyInconsistent { kind: KIND });
    }
    let (chosen, rejected) = match a.outcome.as_u8().cmp(&b.outcome.as_u8()) {
        core::cmp::Ordering::Greater => (a, b),
        core::cmp::Ordering::Less => (b, a),
        core::cmp::Ordering::Equal => return Err(DietError::PreferenceEqualPair),
    };
    Ok(PreferencePair {
        key: chosen.key,
        chosen_hash_32: chosen.content_hash_32,
        rejected_hash_32: rejected.content_hash_32,
        export: ExportKind::Preference,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::diet_kind::DietSourceStage;

    fn key() -> AtomDietKey {
        AtomDietKey::new(DietSourceStage::Phase0, 392)
    }

    fn cand(outcome: CandidateOutcome, privacy_pass: bool, tag: u8) -> PreferenceCandidate {
        PreferenceCandidate {
            key: key(),
            content_hash_32: [tag; 32],
            outcome,
            privacy_pass,
        }
    }

    #[test]
    fn verified_fix_beats_failed_attempt() -> DietResult<()> {
        let fix = cand(CandidateOutcome::VerifiedFix, true, 1);
        let fail = cand(CandidateOutcome::FailedAttempt, true, 2);
        let pair = build_pair(fail, fix)?;
        assert_eq!(pair.chosen_hash_32, [1u8; 32]);
        assert_eq!(pair.rejected_hash_32, [2u8; 32]);
        assert_eq!(pair.export, ExportKind::Preference);
        Ok(())
    }

    #[test]
    fn unsafe_success_loses_to_safe_deny() -> DietResult<()> {
        let deny = cand(CandidateOutcome::SafeDeny, true, 3);
        let unsafe_win = cand(CandidateOutcome::UnsafeSuccess, true, 4);
        let pair = build_pair(deny, unsafe_win)?;
        assert_eq!(pair.chosen_hash_32, [3u8; 32]);
        Ok(())
    }

    #[test]
    fn privacy_reject_is_excluded() {
        let clean = cand(CandidateOutcome::VerifiedFix, true, 1);
        let dirty = cand(CandidateOutcome::FailedAttempt, false, 2);
        assert_eq!(
            build_pair(clean, dirty),
            Err(DietError::PrivacyInconsistent { kind: KIND })
        );
    }

    #[test]
    fn equal_rank_pair_is_rejected() {
        let a = cand(CandidateOutcome::FailedAttempt, true, 1);
        let b = cand(CandidateOutcome::FailedAttempt, true, 2);
        assert_eq!(build_pair(a, b), Err(DietError::PreferenceEqualPair));
    }
}
