//! Sidecar completeness validator.
//!
//! Complete records can enter SFT/export; partial records can enter diagnostics
//! but never earn reward; any unknown/extra file quarantines the record.
use crate::diet_kind::DietFileKind;
use crate::manifest::DietCompleteness;

const FULL_MASK: u32 = 0x001F_FFFF; // bits 0..=20 set = all 21 kinds present

fn distinct_mask(present: &[DietFileKind]) -> u32 {
    let mut mask = 0u32;
    for k in present {
        mask |= 1u32 << (k.as_u8() - 1);
    }
    mask
}

/// Classify completeness from the recognized kinds present and the count of
/// unrecognized files:
///
/// * `unknown_count > 0` ⇒ [`DietCompleteness::Rejected`]
/// * all 21 distinct kinds present ⇒ [`DietCompleteness::Complete`]
/// * a proper subset ⇒ [`DietCompleteness::PartialNoReward`]
pub fn classify(present: &[DietFileKind], unknown_count: u32) -> DietCompleteness {
    if unknown_count > 0 {
        return DietCompleteness::Rejected;
    }
    if distinct_mask(present) == FULL_MASK {
        DietCompleteness::Complete
    } else {
        DietCompleteness::PartialNoReward
    }
}

/// The kinds missing from `present`, in canonical order, for diagnostics.
pub fn missing_kinds(present: &[DietFileKind]) -> Vec<DietFileKind> {
    let mask = distinct_mask(present);
    DietFileKind::ALL
        .into_iter()
        .filter(|k| mask & (1u32 << (k.as_u8() - 1)) == 0)
        .collect()
}

/// Whether a completeness state blocks all reward (partial/rejected do).
pub fn reward_blocked(completeness: DietCompleteness) -> bool {
    completeness.reward_blocked()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn all() -> Vec<DietFileKind> {
        DietFileKind::ALL.into_iter().collect()
    }

    #[test]
    fn all_21_is_complete() {
        assert_eq!(classify(&all(), 0), DietCompleteness::Complete);
        assert!(missing_kinds(&all()).is_empty());
        assert!(!reward_blocked(DietCompleteness::Complete));
    }

    #[test]
    fn subset_is_partial_no_reward() {
        let some = [DietFileKind::EnvLock, DietFileKind::CommandManifest];
        assert_eq!(classify(&some, 0), DietCompleteness::PartialNoReward);
        assert_eq!(missing_kinds(&some).len(), 19);
        assert!(reward_blocked(DietCompleteness::PartialNoReward));
    }

    #[test]
    fn unknown_file_rejects_even_when_all_present() {
        assert_eq!(classify(&all(), 1), DietCompleteness::Rejected);
        assert!(reward_blocked(DietCompleteness::Rejected));
    }

    #[test]
    fn duplicate_present_kinds_do_not_double_count() {
        let dup = [DietFileKind::EnvLock, DietFileKind::EnvLock];
        assert_eq!(classify(&dup, 0), DietCompleteness::PartialNoReward);
        assert_eq!(missing_kinds(&dup).len(), 20);
    }
}
