//! Deterministic skill rank score.
//!
//! Ranking is **not** popularity-only ([`SkillRankScore`]). Eval, security,
//! compatibility, verified installs (never raw downloads), provenance, and a
//! permission-risk penalty all contribute with documented [`RankWeights`]. Two
//! hard gates protect users from gaming:
//!
//! - a `Quarantined` / `Revoked` skill scores `0` no matter how many installs
//!   it has (popularity can never launder bad security past a secure skill);
//! - an `Incompatible` skill scores `0` (pushed to the bottom / blocked).
//!
//! [`rank`] filters by the query's permission ceiling, scores each survivor, and
//! sorts by total descending with a stable skill-id tie-break. [`ranking_replay_hash`]
//! lets a verifier confirm the ordering is replay-stable.

#![deny(missing_docs)]

extern crate alloc;

use alloc::vec::Vec;

use crate::catalog_card::CapabilityClass;
use crate::catalog_index::SkillCatalogIndexEntry;
use crate::compat::CompatibilityDecision;
use crate::eval::MAX_EVAL_SCORE;
use crate::manifest::SkillId;
use crate::package::SkillSecurityState;
use crate::search_query::SkillSearchQuery;

/// Domain tag for the replay-stable ranking hash.
const DOMAIN_RANK: &[u8] = b"mnemos.d.rank.v1";

/// Verified-install saturation cap. Above this, more installs do not raise the
/// verified weight — so a flood of (capped, deduped) installs cannot dominate
/// eval / security / compatibility.
const VERIFIED_CAP: u64 = 10_000;

/// Documented ranking weights. The first four feed the recorded component
/// weights; the last two are internal (penalty / bonus).
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub struct RankWeights {
    /// Max weight from the eval axes average.
    pub eval_u16: u16,
    /// Max weight from the security state.
    pub security_u16: u16,
    /// Max weight from the compatibility decision.
    pub compatibility_u16: u16,
    /// Max weight from (capped) verified installs.
    pub verified_u16: u16,
    /// Max penalty subtracted for high-risk permission classes.
    pub permission_risk_penalty_u16: u16,
    /// Bonus added for a well-formed provenance node.
    pub provenance_bonus_u16: u16,
}

impl RankWeights {
    /// The documented default weights: eval > security > compatibility >
    /// verified, with a permission-risk penalty and a small provenance bonus.
    #[must_use]
    pub const fn default_weights() -> Self {
        Self {
            eval_u16: 4_000,
            security_u16: 3_000,
            compatibility_u16: 2_000,
            verified_u16: 1_000,
            permission_risk_penalty_u16: 500,
            provenance_bonus_u16: 200,
        }
    }
}

/// A deterministic rank score for one catalog entry.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub struct SkillRankScore {
    /// The ranked skill id.
    pub entry: SkillId,
    /// The gated total (0 for a Quarantined / Revoked / Incompatible skill).
    pub total_u32: u32,
    /// Eval component.
    pub eval_weight_u16: u16,
    /// Security component (0 for Quarantined / Revoked).
    pub security_weight_u16: u16,
    /// Compatibility component (0 for Incompatible).
    pub compatibility_weight_u16: u16,
    /// Verified-install component (capped).
    pub verified_weight_u16: u16,
}

fn security_weight(state: SkillSecurityState, max: u16) -> u16 {
    match state {
        SkillSecurityState::AuditPass => max,
        SkillSecurityState::SandboxPass => max / 2,
        SkillSecurityState::Unknown => max / 4,
        SkillSecurityState::Quarantined | SkillSecurityState::Revoked => 0,
    }
}

fn compat_weight(decision: CompatibilityDecision, max: u16) -> u16 {
    match decision {
        CompatibilityDecision::Compatible => max,
        CompatibilityDecision::Warn => max / 2,
        CompatibilityDecision::Unknown => max / 4,
        CompatibilityDecision::Incompatible => 0,
    }
}

fn permission_penalty(entry: &SkillCatalogIndexEntry, max: u16) -> u16 {
    match CapabilityClass::from_added_mask(entry.capability_diff.added_mask_u64) {
        CapabilityClass::WalletOrSecret => max,
        CapabilityClass::NetworkOrChain => max / 2,
        CapabilityClass::FileWrite => max / 4,
        CapabilityClass::MemoryWrite | CapabilityClass::ReadOnly => 0,
    }
}

impl SkillRankScore {
    /// Score one entry under `weights`. Deterministic and panic-free
    /// (saturating arithmetic throughout).
    #[must_use]
    pub fn score(entry: &SkillCatalogIndexEntry, weights: &RankWeights) -> Self {
        let axes = entry.eval.axes();
        let axis_sum: u32 = axes.iter().map(|a| u32::from(*a)).sum();
        let avg_eval = axis_sum / 6;
        let eval_weight_u16 =
            ((avg_eval * u32::from(weights.eval_u16)) / u32::from(MAX_EVAL_SCORE)) as u16;

        let security_weight_u16 = security_weight(entry.security, weights.security_u16);
        let compatibility_weight_u16 =
            compat_weight(entry.compatibility, weights.compatibility_u16);

        let verified_capped = entry.verified_installs_u64.min(VERIFIED_CAP);
        let verified_weight_u16 =
            ((verified_capped * u64::from(weights.verified_u16)) / VERIFIED_CAP) as u16;

        let provenance_bonus = if entry.provenance.is_well_formed() {
            weights.provenance_bonus_u16
        } else {
            0
        };
        let penalty = permission_penalty(entry, weights.permission_risk_penalty_u16);

        let blocked = matches!(
            entry.security,
            SkillSecurityState::Quarantined | SkillSecurityState::Revoked
        ) || entry.compatibility == CompatibilityDecision::Incompatible;

        let base = u32::from(eval_weight_u16)
            + u32::from(security_weight_u16)
            + u32::from(compatibility_weight_u16)
            + u32::from(verified_weight_u16)
            + u32::from(provenance_bonus);
        let total_u32 = if blocked {
            0
        } else {
            base.saturating_sub(u32::from(penalty))
        };

        Self {
            entry: entry.skill,
            total_u32,
            eval_weight_u16,
            security_weight_u16,
            compatibility_weight_u16,
            verified_weight_u16,
        }
    }
}

/// Rank the entries that pass the query's permission ceiling, sorted by total
/// descending with a stable skill-id tie-break. Deterministic: same inputs
/// always produce the same ordering.
#[must_use]
pub fn rank(
    entries: &[SkillCatalogIndexEntry],
    query: &SkillSearchQuery,
    weights: &RankWeights,
) -> Vec<SkillRankScore> {
    let mut scores: Vec<SkillRankScore> = entries
        .iter()
        .filter(|e| query.matches(e))
        .map(|e| SkillRankScore::score(e, weights))
        .collect();
    scores.sort_by(|a, b| {
        b.total_u32
            .cmp(&a.total_u32)
            .then_with(|| a.entry.0.cmp(&b.entry.0))
    });
    scores
}

/// A replay-stable hash over the ranked order (skill id + total per row). Two
/// identical rankings hash equal; any reorder or total change changes the hash.
#[must_use]
pub fn ranking_replay_hash(scores: &[SkillRankScore]) -> [u8; 32] {
    let mut buf: Vec<u8> = Vec::with_capacity(scores.len() * 6);
    for score in scores {
        buf.extend_from_slice(&score.entry.0.to_le_bytes());
        buf.extend_from_slice(&score.total_u32.to_le_bytes());
    }
    crate::package::blake2b_256(&[DOMAIN_RANK, &buf])
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use crate::compat::{HostEnvironment, MnemosVersion};
    use crate::verify::sample_valid_package_toml;
    use alloc::vec;

    fn host() -> HostEnvironment {
        HostEnvironment {
            mnemos_version: MnemosVersion::new(0, 2, 0),
            chain_env_hash_32: [0xC0; 32],
            os_gpu_hash_32: [0x05; 32],
            toolchain_hash_32: [0x70; 32],
            model_provider_hash_32: [0x30; 32],
        }
    }

    fn entry(
        skill: u16,
        security: SkillSecurityState,
        compat: CompatibilityDecision,
        verified: u64,
    ) -> SkillCatalogIndexEntry {
        let toml = sample_valid_package_toml();
        let mut e = SkillCatalogIndexEntry::from_package_toml(
            &toml,
            &host(),
            [0x99; 32],
            1_000,
            verified,
            0,
        )
        .expect("index");
        e.skill = SkillId(skill);
        e.security = security;
        e.compatibility = compat;
        e
    }

    fn any_query() -> SkillSearchQuery {
        SkillSearchQuery::parse("").expect("empty query parses")
    }

    #[test]
    fn deterministic_order() {
        let entries = vec![
            entry(
                3,
                SkillSecurityState::AuditPass,
                CompatibilityDecision::Compatible,
                10,
            ),
            entry(
                1,
                SkillSecurityState::SandboxPass,
                CompatibilityDecision::Warn,
                50,
            ),
        ];
        let w = RankWeights::default_weights();
        let a = rank(&entries, &any_query(), &w);
        let b = rank(&entries, &any_query(), &w);
        assert_eq!(a, b);
        assert_eq!(ranking_replay_hash(&a), ranking_replay_hash(&b));
    }

    #[test]
    fn popularity_gaming_loses_to_bad_security() {
        // skill 1: millions of installs but Quarantined -> total 0.
        // skill 2: modest installs but AuditPass -> wins.
        let entries = vec![
            entry(
                1,
                SkillSecurityState::Quarantined,
                CompatibilityDecision::Compatible,
                9_999_999,
            ),
            entry(
                2,
                SkillSecurityState::AuditPass,
                CompatibilityDecision::Compatible,
                10,
            ),
        ];
        let scores = rank(&entries, &any_query(), &RankWeights::default_weights());
        assert_eq!(scores[0].entry.0, 2);
        // The quarantined skill is gated to zero.
        let quarantined = scores.iter().find(|s| s.entry.0 == 1).expect("present");
        assert_eq!(quarantined.total_u32, 0);
    }

    #[test]
    fn incompatible_pushed_down_and_blocked() {
        let entries = vec![
            entry(
                1,
                SkillSecurityState::AuditPass,
                CompatibilityDecision::Incompatible,
                1_000,
            ),
            entry(
                2,
                SkillSecurityState::Unknown,
                CompatibilityDecision::Compatible,
                1,
            ),
        ];
        let scores = rank(&entries, &any_query(), &RankWeights::default_weights());
        let incompatible = scores.iter().find(|s| s.entry.0 == 1).expect("present");
        assert_eq!(incompatible.total_u32, 0);
        // The compatible (even Unknown-security) skill ranks above the blocked one.
        assert_eq!(scores[0].entry.0, 2);
    }

    #[test]
    fn tie_break_stable() {
        // Two identically-scoring entries -> ordered by skill id ascending.
        let entries = vec![
            entry(
                5,
                SkillSecurityState::AuditPass,
                CompatibilityDecision::Compatible,
                10,
            ),
            entry(
                3,
                SkillSecurityState::AuditPass,
                CompatibilityDecision::Compatible,
                10,
            ),
        ];
        let scores = rank(&entries, &any_query(), &RankWeights::default_weights());
        assert_eq!(scores[0].total_u32, scores[1].total_u32);
        assert_eq!(scores[0].entry.0, 3);
        assert_eq!(scores[1].entry.0, 5);
    }
}
