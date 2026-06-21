//! `memory compact / importance / user-model` intelligence status (F-WP-05B,
//! atom #444 · F.5.1).
//!
//! Read-only projections over the canonical Stage D memory-intelligence types
//! (which live in `b-memory`'s `intelligence` module). The cockpit can SHOW the
//! background compactor's progress, a memory's importance score, and the user
//! model's hashed components — but it never silently retains a deleted memory and
//! never auto-applies a suggestion:
//!
//! * **Deletion wins over compaction.** A tombstoned id maps to the terminal
//!   [`MemoryTier::DeletedTombstone`], which the compactor never ages or removes
//!   ([`deletion_wins_over_compaction`]).
//! * **A deleted memory is never scored.** [`ImportanceLabelView::score_status`]
//!   forwards the canonical fail-closed [`ImportanceError::DeletedTombstoneBlocked`].
//! * **Suggestions require approval.** [`MemoryIntelSuggestion`] is advisory;
//!   applying one is a local write that needs a confirm — never auto-applied.
//! * **User-model content is hashed.** [`UserModelStatusView`] exposes only the
//!   four 32-byte component hashes (redacted prefixes) + owner, never raw bytes.

use crate::command::{ApprovalRequirement, CommandRisk, approval_for};
use crate::hex32;
use mnemos_b_memory::{
    BackgroundCompactor, ChangedComponents, FeedbackLabel, ImportanceError, ImportanceFeatures,
    ImportanceModel, ImportanceScore, MemoryId, MemoryTier, SigningPublicKey, TombstonePolicy,
    UserModel, UserModelDelta,
};

/// First 16 hex characters of a 32-byte digest — a redacted, display-only prefix.
#[must_use]
fn redact16(bytes: &[u8; 32]) -> String {
    hex32(bytes).chars().take(16).collect()
}

/// A read-only projection of the canonical [`BackgroundCompactor`]: its progress
/// cursor and the replay truth it preserves verbatim. The compactor runs as a
/// cooperative background step machine; this is a status snapshot only.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CompactorStatusView {
    /// Total entries the compactor is tracking.
    pub total_entries_u32: u32,
    /// Current resume cursor position.
    pub cursor_u32: u32,
    /// Whether every entry has been visited at least once this pass.
    pub done: bool,
    /// Unique anchors recovered (the preserved replay cursor).
    pub replay_recovered_u32: u32,
    /// Redacted 16-hex prefix of the preserved Stage B transcript anchor.
    pub transcript_redacted: String,
}

impl CompactorStatusView {
    /// Project a [`BackgroundCompactor`] status snapshot.
    #[must_use]
    pub fn from_compactor(compactor: &BackgroundCompactor) -> Self {
        Self {
            total_entries_u32: u32::try_from(compactor.entries().len()).unwrap_or(u32::MAX),
            cursor_u32: u32::try_from(compactor.cursor()).unwrap_or(u32::MAX),
            done: compactor.is_done(),
            replay_recovered_u32: compactor.replay_link().recovered_u32(),
            transcript_redacted: redact16(compactor.transcript_anchor().as_bytes()),
        }
    }

    /// Redacted, colorless status lines bounded by `rows`.
    #[must_use]
    pub fn render(&self, rows: u16) -> Vec<String> {
        let lines = vec![
            format!("total_entries={}", self.total_entries_u32),
            format!("cursor={}", self.cursor_u32),
            format!("done={}", self.done),
            format!("replay_recovered={}", self.replay_recovered_u32),
            format!("transcript={}", self.transcript_redacted),
        ];
        lines.into_iter().take(rows as usize).collect()
    }
}

/// A read-only projection of a canonical [`ImportanceScore`]: the bounded score,
/// the applied feedback label tag, and the scoring model hash. Content is never
/// shown — only the id, the bounded score, and the model identity.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ImportanceLabelView {
    /// The scored memory id.
    pub memory_id_u64: u64,
    /// Bounded importance score (`0..=10000`).
    pub score_u16: u16,
    /// Applied feedback label tag (`0` = none).
    pub label_u8: u8,
    /// Redacted 16-hex prefix of the scoring model hash.
    pub model_hash_redacted: String,
}

impl ImportanceLabelView {
    /// Project an already-computed [`ImportanceScore`].
    #[must_use]
    pub fn from_score(score: &ImportanceScore) -> Self {
        Self {
            memory_id_u64: score.memory.get(),
            score_u16: score.score_u16,
            label_u8: score.label.map_or(0, FeedbackLabel::tag),
            model_hash_redacted: redact16(&score.model_hash_32),
        }
    }

    /// Score a memory via the canonical [`ImportanceModel`] and project the result.
    /// A deleted (tombstoned) memory is blocked fail-closed with the canonical
    /// [`ImportanceError::DeletedTombstoneBlocked`] — a deleted memory is never
    /// scored or silently retained.
    pub fn score_status(
        model: &ImportanceModel,
        memory: MemoryId,
        features: &ImportanceFeatures,
        label: Option<FeedbackLabel>,
        deleted: bool,
    ) -> Result<Self, ImportanceError> {
        let score = model.score(memory, features, label, deleted)?;
        Ok(Self::from_score(&score))
    }

    /// Redacted, colorless label lines bounded by `rows`.
    #[must_use]
    pub fn render(&self, rows: u16) -> Vec<String> {
        let lines = vec![
            format!("memory_id={}", self.memory_id_u64),
            format!("score={}", self.score_u16),
            format!("label_u8={}", self.label_u8),
            format!("model_hash={}", self.model_hash_redacted),
        ];
        lines.into_iter().take(rows as usize).collect()
    }
}

/// A read-only projection of a canonical [`UserModelDelta`]: the owner plus the
/// four hashed user-model components. Content is structurally redacted — the
/// canonical type stores only 32-byte digests, never raw preference/fact bytes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UserModelStatusView {
    /// Redacted 16-hex prefix of the owner public key.
    pub owner_redacted: String,
    /// Redacted 16-hex prefix of the preferences component hash.
    pub preferences_redacted: String,
    /// Redacted 16-hex prefix of the facts component hash.
    pub facts_redacted: String,
    /// Redacted 16-hex prefix of the boundaries component hash.
    pub boundaries_redacted: String,
    /// Redacted 16-hex prefix of the relationship-graph component hash.
    pub relationship_graph_redacted: String,
    /// The delta's deletion-semantics tag.
    pub delete_semantics_u8: u8,
}

impl UserModelStatusView {
    /// Project a [`UserModelDelta`] snapshot for an owner.
    #[must_use]
    pub fn from_delta(owner: &SigningPublicKey, delta: &UserModelDelta) -> Self {
        Self {
            owner_redacted: redact16(owner.as_bytes()),
            preferences_redacted: redact16(&delta.preferences_hash_32),
            facts_redacted: redact16(&delta.facts_hash_32),
            boundaries_redacted: redact16(&delta.boundaries_hash_32),
            relationship_graph_redacted: redact16(&delta.relationship_graph_hash_32),
            delete_semantics_u8: delta.delete_semantics.tag(),
        }
    }

    /// Which components changed relative to a previous model (reuses the canonical
    /// [`UserModelDelta::changed_from`]).
    #[must_use]
    pub fn changed(prev: &UserModel, delta: &UserModelDelta) -> ChangedComponents {
        delta.changed_from(prev)
    }

    /// Redacted, colorless user-model status lines bounded by `rows`.
    #[must_use]
    pub fn render(&self, rows: u16) -> Vec<String> {
        let lines = vec![
            format!("owner={}", self.owner_redacted),
            format!("preferences={}", self.preferences_redacted),
            format!("facts={}", self.facts_redacted),
            format!("boundaries={}", self.boundaries_redacted),
            format!("relationship_graph={}", self.relationship_graph_redacted),
            format!("delete_semantics_u8={}", self.delete_semantics_u8),
        ];
        lines.into_iter().take(rows as usize).collect()
    }
}

/// Whether deletion wins over compaction for `id`: a tombstoned id maps to the
/// terminal [`MemoryTier::DeletedTombstone`], which the background compactor never
/// ages or removes — so a deleted memory cannot be resurrected by compaction.
#[must_use]
pub fn deletion_wins_over_compaction(tombstones: &TombstonePolicy, id: MemoryId) -> bool {
    matches!(tombstones.tier(id), Some(MemoryTier::DeletedTombstone))
}

/// Kind of memory-intelligence suggestion the cockpit can surface.
#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MemoryIntelSuggestionKind {
    /// Suggest compacting a tier.
    Compact = 1,
    /// Suggest an importance re-score.
    Reimportance = 2,
    /// Suggest a user-model update.
    UserModelUpdate = 3,
}

impl MemoryIntelSuggestionKind {
    /// Stable u8 tag.
    #[must_use]
    pub const fn tag(self) -> u8 {
        self as u8
    }
}

/// A memory-intelligence suggestion. Suggestions are advisory: applying one writes
/// local state and therefore requires approval — it is never auto-applied.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MemoryIntelSuggestion {
    /// What the suggestion proposes.
    pub kind: MemoryIntelSuggestionKind,
}

impl MemoryIntelSuggestion {
    /// Construct a suggestion of the given kind.
    #[must_use]
    pub const fn new(kind: MemoryIntelSuggestionKind) -> Self {
        Self { kind }
    }

    /// The command risk of applying this suggestion (a local write).
    #[must_use]
    pub const fn risk(&self) -> CommandRisk {
        CommandRisk::LocalWrite
    }

    /// The approval requirement for applying this suggestion (Confirm).
    #[must_use]
    pub fn approval(&self) -> ApprovalRequirement {
        approval_for(self.risk())
    }

    /// Whether applying requires user approval — always `true` (never auto-applied).
    #[must_use]
    pub fn requires_approval(&self) -> bool {
        !matches!(self.approval(), ApprovalRequirement::None)
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    #![allow(clippy::expect_used)]
    #![allow(clippy::panic)]

    use super::*;
    use mnemos_b_memory::{CompactorEntry, DeleteSemantics, ReplayCursor, stage_b_transcript_hash};

    const COMMERCE_TOKENS: &[&str] = &[
        "price", "pay", "buy", "sell", "checkout", "refund", "fee", "cost", "$",
    ];

    fn owner(b: u8) -> SigningPublicKey {
        SigningPublicKey::from_bytes(&[b; 32]).expect("32-byte owner key")
    }

    fn compactor(n: u64) -> BackgroundCompactor {
        let entries: Vec<CompactorEntry> = (0..n)
            .map(|i| CompactorEntry {
                id: MemoryId::new(i + 1),
                tier: MemoryTier::Recent,
            })
            .collect();
        BackgroundCompactor::new(
            entries,
            ReplayCursor::from_replay(&[MemoryId::new(1), MemoryId::new(2)]),
            stage_b_transcript_hash(b"intel-fixture-transcript"),
        )
    }

    #[test]
    fn importance_label_projects_score() {
        let model = ImportanceModel::new();
        let features = ImportanceFeatures {
            recency_rank_u16: 0,
            access_count_u16: 5,
            content_len_u32: 200,
        };
        let view = ImportanceLabelView::score_status(
            &model,
            MemoryId::new(9),
            &features,
            Some(FeedbackLabel::Promote),
            false,
        )
        .unwrap();
        assert_eq!(view.memory_id_u64, 9);
        assert!(view.score_u16 <= 10_000);
        assert_eq!(view.label_u8, FeedbackLabel::Promote.tag());
        assert_ne!(view.model_hash_redacted, redact16(&[0u8; 32]));
    }

    #[test]
    fn compactor_status_reflects_progress_and_preserves_replay() {
        let mut c = compactor(5);
        let before = CompactorStatusView::from_compactor(&c);
        assert_eq!(before.total_entries_u32, 5);
        assert_eq!(before.cursor_u32, 0);
        assert!(!before.done);
        assert_eq!(before.replay_recovered_u32, 2);
        let _ = c.step(2);
        let mid = CompactorStatusView::from_compactor(&c);
        assert_eq!(mid.cursor_u32, 2);
        assert!(!mid.done);
        // Replay truth + transcript anchor are preserved verbatim across stepping.
        assert_eq!(mid.replay_recovered_u32, before.replay_recovered_u32);
        assert_eq!(mid.transcript_redacted, before.transcript_redacted);
    }

    #[test]
    fn user_model_redaction_shows_only_hashes() {
        let o = owner(0xAB);
        let mut model = UserModel::empty(o);
        model.set_preferences(b"prefers-terse-replies-and-no-emoji");
        model.set_facts(b"lives-in-seoul-studies-finance");
        let delta = model.to_delta(DeleteSemantics::Tombstone);
        let view = UserModelStatusView::from_delta(&o, &delta);
        for line in view.render(16) {
            assert!(
                !line.contains("prefers-terse"),
                "raw preference leaked: {line}"
            );
            assert!(!line.contains("lives-in-seoul"), "raw fact leaked: {line}");
        }
        // Changed-components reuse: preferences + facts changed vs the empty model.
        let changed = UserModelStatusView::changed(&UserModel::empty(o), &delta);
        assert!(changed.preferences);
        assert!(changed.facts);
        assert!(!changed.relationship_graph);
    }

    #[test]
    fn deleted_memory_deny() {
        let model = ImportanceModel::new();
        let features = ImportanceFeatures {
            recency_rank_u16: 0,
            access_count_u16: 1,
            content_len_u32: 10,
        };
        let r = ImportanceLabelView::score_status(
            &model,
            MemoryId::new(4),
            &features,
            None,
            true, // deleted / tombstoned
        );
        assert_eq!(r, Err(ImportanceError::DeletedTombstoneBlocked));
    }

    #[test]
    fn deletion_wins_over_compaction_holds() {
        let mut tombs = TombstonePolicy::new();
        tombs.record(MemoryId::new(7), DeleteSemantics::Tombstone);
        assert!(deletion_wins_over_compaction(&tombs, MemoryId::new(7)));
        assert!(!deletion_wins_over_compaction(&tombs, MemoryId::new(8)));
        // And the compactor preserves a tombstone tier (never ages it).
        let mut c = BackgroundCompactor::new(
            vec![CompactorEntry {
                id: MemoryId::new(7),
                tier: MemoryTier::DeletedTombstone,
            }],
            ReplayCursor::start(),
            stage_b_transcript_hash(b"t"),
        );
        let step = c.step(16);
        assert_eq!(step.tombstones_preserved_u32, 1);
        assert_eq!(step.aged_u32, 0);
        assert_eq!(c.entries()[0].tier, MemoryTier::DeletedTombstone);
    }

    #[test]
    fn suggestions_require_approval() {
        for kind in [
            MemoryIntelSuggestionKind::Compact,
            MemoryIntelSuggestionKind::Reimportance,
            MemoryIntelSuggestionKind::UserModelUpdate,
        ] {
            let s = MemoryIntelSuggestion::new(kind);
            assert!(s.requires_approval());
            assert_eq!(s.approval(), ApprovalRequirement::Confirm);
            assert_eq!(s.risk(), CommandRisk::LocalWrite);
        }
    }

    #[test]
    fn no_commerce_render() {
        let c = compactor(3);
        let status = CompactorStatusView::from_compactor(&c);
        let model = ImportanceModel::new();
        let label = ImportanceLabelView::score_status(
            &model,
            MemoryId::new(1),
            &ImportanceFeatures {
                recency_rank_u16: 1,
                access_count_u16: 1,
                content_len_u32: 1,
            },
            Some(FeedbackLabel::Keep),
            false,
        )
        .unwrap();
        let o = owner(1);
        let um = UserModelStatusView::from_delta(
            &o,
            &UserModel::empty(o).to_delta(DeleteSemantics::Tombstone),
        );
        for line in status
            .render(32)
            .into_iter()
            .chain(label.render(32))
            .chain(um.render(32))
        {
            for bad in COMMERCE_TOKENS {
                assert!(!line.contains(bad), "commerce token {bad} in: {line}");
            }
        }
    }
}
