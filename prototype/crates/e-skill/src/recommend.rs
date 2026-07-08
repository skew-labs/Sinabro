//! Agent recommendation context.
//!
//! An agent can **recommend** skills but can never install or use one silently.
//! [`Recommendation::build`] ranks catalog entries for a workspace
//! [`RecommendationContext`] (workspace / Move.toml / tests hashes, a gas budget
//! carried as input data, a security floor, and the available tool set), and
//! every [`RecommendationCandidate`] row carries a permission preview and
//! `requires_user_confirm = true`. There is no auto-install path
//! ([`auto_install_allowed`] is always `false`): a recommendation waits for an
//! explicit user selection / confirmation and shows the capability diff before
//! any dry-run.
//!
//! The "gas trace" the spec mentions is consumed here as **input data** (a
//! [`GasBudgetMist`] from `mnemos-d-move`), never by importing the k-devex gas
//! evaluator — that would create an `e-skill -> k-devex` cargo cycle, since
//! k-devex already depends on e-skill.

#![deny(missing_docs)]

extern crate alloc;

use alloc::vec::Vec;

use mnemos_d_move::types::GasBudgetMist;
use mnemos_m_agent::tool_schema::ToolId;

use crate::catalog_index::SkillCatalogIndexEntry;
use crate::manifest::SkillId;
use crate::package::SkillSecurityState;
use crate::permission_preview::PermissionPreview;
use crate::ranking::{RankWeights, SkillRankScore, rank};
use crate::search_query::SkillSearchQuery;

/// Domain tag for a candidate's rationale hash.
const DOMAIN_RECOMMEND: &[u8] = b"mnemos.d.recommend.v1";

/// Always `false`: a recommendation never installs or uses a skill on its own.
/// Use / install always require an explicit, separately-gated user action.
#[must_use]
pub const fn auto_install_allowed() -> bool {
    false
}

/// The workspace context an agent recommendation is computed for. The gas
/// budget is plain input data (a gas-trace summary), not a live call.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RecommendationContext {
    /// Hash of the workspace summary.
    pub workspace_hash_32: [u8; 32],
    /// Hash of the `Move.toml` (zero for a non-Move workspace).
    pub move_toml_hash_32: [u8; 32],
    /// Hash of the test surface.
    pub tests_hash_32: [u8; 32],
    /// Gas budget available for any later (separately-confirmed) on-chain action.
    pub gas_budget: GasBudgetMist,
    /// The minimum security state a recommended skill must meet.
    pub security_floor: SkillSecurityState,
    /// Tool ids available in the workspace.
    pub available_tools: Vec<ToolId>,
}

/// One recommended skill row. Always carries a permission preview and requires
/// explicit user confirmation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RecommendationCandidate {
    /// The recommended skill.
    pub skill: SkillId,
    /// Its rank score.
    pub rank: SkillRankScore,
    /// The permission diff preview shown in this row (never omitted).
    pub permission_preview: PermissionPreview,
    /// Always `true`: use / install needs explicit user confirmation.
    pub requires_user_confirm: bool,
    /// Stable rationale hash binding this row to the context + score.
    pub rationale_hash_32: [u8; 32],
}

/// An agent recommendation: ranked candidate rows plus the top-N rationale
/// hashes.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Recommendation {
    /// The recommended candidates, best first.
    pub candidates: Vec<RecommendationCandidate>,
    /// Rationale hashes of the candidates, in order.
    pub top_n_rationale_hashes: Vec<[u8; 32]>,
    /// Whether a non-zero gas budget was supplied (a missing budget is
    /// surfaced, not silently assumed).
    pub budget_known: bool,
}

/// Trust rank for the security floor. Quarantined / Revoked are untrusted (0);
/// Unknown < SandboxPass < AuditPass.
const fn trust_rank(state: SkillSecurityState) -> u8 {
    match state {
        SkillSecurityState::Quarantined | SkillSecurityState::Revoked => 0,
        SkillSecurityState::Unknown => 1,
        SkillSecurityState::SandboxPass => 2,
        SkillSecurityState::AuditPass => 3,
    }
}

/// Whether `state` meets the security `floor`.
#[must_use]
pub const fn meets_security_floor(state: SkillSecurityState, floor: SkillSecurityState) -> bool {
    trust_rank(state) >= trust_rank(floor)
}

fn rationale_hash(ctx: &RecommendationContext, score: &SkillRankScore) -> [u8; 32] {
    crate::package::blake2b_256(&[
        DOMAIN_RECOMMEND,
        &ctx.workspace_hash_32,
        &ctx.move_toml_hash_32,
        &ctx.tests_hash_32,
        &ctx.gas_budget.get().to_le_bytes(),
        &score.entry.0.to_le_bytes(),
        &score.total_u32.to_le_bytes(),
    ])
}

impl Recommendation {
    /// Build a recommendation: rank `entries` for `query`, keep up to `top_n`
    /// candidates that meet the context's security floor, and attach a
    /// permission preview + confirmation requirement + rationale hash to each.
    /// Installs nothing.
    #[must_use]
    pub fn build(
        ctx: &RecommendationContext,
        entries: &[SkillCatalogIndexEntry],
        query: &SkillSearchQuery,
        weights: &RankWeights,
        top_n: usize,
    ) -> Self {
        let ranked = rank(entries, query, weights);
        let mut candidates: Vec<RecommendationCandidate> = Vec::new();
        for score in ranked {
            if candidates.len() >= top_n {
                break;
            }
            let Some(entry) = entries.iter().find(|e| e.skill == score.entry) else {
                continue;
            };
            if !meets_security_floor(entry.security, ctx.security_floor) {
                continue;
            }
            candidates.push(RecommendationCandidate {
                skill: score.entry,
                rank: score,
                permission_preview: PermissionPreview::from_diff(&entry.capability_diff),
                requires_user_confirm: true,
                rationale_hash_32: rationale_hash(ctx, &score),
            });
        }
        let top_n_rationale_hashes = candidates.iter().map(|c| c.rationale_hash_32).collect();
        Self {
            candidates,
            top_n_rationale_hashes,
            budget_known: ctx.gas_budget.get() != 0,
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use crate::compat::{CompatibilityDecision, HostEnvironment, MnemosVersion};
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

    fn entry(skill: u16, security: SkillSecurityState) -> SkillCatalogIndexEntry {
        let toml = sample_valid_package_toml();
        let mut e =
            SkillCatalogIndexEntry::from_package_toml(&toml, &host(), [0x99; 32], 100, 10, 2)
                .expect("index");
        e.skill = SkillId(skill);
        e.security = security;
        e.compatibility = CompatibilityDecision::Compatible;
        e
    }

    fn ctx(move_toml: u8, budget: u64) -> RecommendationContext {
        RecommendationContext {
            workspace_hash_32: [0x10; 32],
            move_toml_hash_32: [move_toml; 32],
            tests_hash_32: [0x20; 32],
            gas_budget: GasBudgetMist::new(budget),
            security_floor: SkillSecurityState::Unknown,
            available_tools: vec![ToolId(1), ToolId(2), ToolId(3)],
        }
    }

    fn query() -> SkillSearchQuery {
        SkillSearchQuery::parse("optimizer").expect("parse")
    }

    #[test]
    fn move_gas_context() {
        let entries = vec![entry(1, SkillSecurityState::AuditPass)];
        let rec = Recommendation::build(
            &ctx(0x55, 1_000_000),
            &entries,
            &query(),
            &RankWeights::default_weights(),
            5,
        );
        assert_eq!(rec.candidates.len(), 1);
        assert!(rec.budget_known);
        assert_eq!(rec.top_n_rationale_hashes.len(), 1);
    }

    #[test]
    fn rust_context_differs_from_move() {
        let entries = vec![entry(1, SkillSecurityState::AuditPass)];
        let w = RankWeights::default_weights();
        let move_rec = Recommendation::build(&ctx(0x55, 1_000_000), &entries, &query(), &w, 5);
        let rust_rec = Recommendation::build(&ctx(0x00, 1_000_000), &entries, &query(), &w, 5);
        // Different workspace context -> different rationale hashes.
        assert_ne!(
            move_rec.top_n_rationale_hashes,
            rust_rec.top_n_rationale_hashes
        );
    }

    #[test]
    fn missing_budget_flagged() {
        let entries = vec![entry(1, SkillSecurityState::AuditPass)];
        let rec = Recommendation::build(
            &ctx(0x55, 0),
            &entries,
            &query(),
            &RankWeights::default_weights(),
            5,
        );
        assert!(!rec.budget_known);
    }

    #[test]
    fn confirm_required_on_every_candidate() {
        let entries = vec![
            entry(1, SkillSecurityState::AuditPass),
            entry(2, SkillSecurityState::SandboxPass),
        ];
        let rec = Recommendation::build(
            &ctx(0x55, 1_000),
            &entries,
            &query(),
            &RankWeights::default_weights(),
            5,
        );
        assert!(!rec.candidates.is_empty());
        assert!(rec.candidates.iter().all(|c| c.requires_user_confirm));
    }

    #[test]
    fn no_auto_install_or_use() {
        // The recommendation surface exposes no install/use action; the global
        // policy constant is false.
        assert!(!auto_install_allowed());
    }

    #[test]
    fn security_floor_excludes_below() {
        // Floor = AuditPass excludes a SandboxPass skill.
        let mut c = ctx(0x55, 1_000);
        c.security_floor = SkillSecurityState::AuditPass;
        let entries = vec![entry(1, SkillSecurityState::SandboxPass)];
        let rec = Recommendation::build(&c, &entries, &query(), &RankWeights::default_weights(), 5);
        assert!(rec.candidates.is_empty());
    }
}
