//! §4.3 context map + the `context` command model (atom #413 F.1.4, map half).
//!
//! The context map makes the model's working set *inspectable*: repo symbols,
//! files, memory hits, skills, web sources, and user-pinned items — each with a
//! visible provenance (`reason_hash_32`). The hard law: there is no invisible
//! context selection and no prompt-only hint injection, so every item must carry
//! a non-zero provenance hash or it is rejected. The view is computed from local
//! state only (no network / full scan on the hot path).
//!
//! Commands modelled: `map` (list items), `status` (summary view), `add` /
//! `drop` / `pin`, `compact`, `why` (provenance lookup), `sources` (distinct
//! kinds). The completion provider half of #413 lives in [`crate::repl::complete`].

use crate::sha256_32;
use mnemos_b_memory::{CompactionError, CompactionPlan, MemoryTier};

const ZERO32: [u8; 32] = [0u8; 32];

/// The per-tick stall budget (ms) for background context compaction — the
/// foreground may not block longer than this on a compaction tick (the ≤100ms
/// operational-entry law). Passed to the canonical [`CompactionPlan`].
pub const CONTEXT_COMPACT_STALL_BUDGET_MS: u16 = 100;

/// §4.3 — where a context item came from.
#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ContextSourceKind {
    /// A repository symbol (fn / type / module).
    RepoSymbol = 1,
    /// A file path.
    File = 2,
    /// A memory hit.
    Memory = 3,
    /// A skill.
    Skill = 4,
    /// A web source.
    WebSource = 5,
    /// An item the user explicitly pinned.
    UserPinned = 6,
}

/// §4.3 — one item in the context map.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ContextMapItem {
    /// What kind of source this is.
    pub kind: ContextSourceKind,
    /// SHA-256 identity of the source (path / symbol / memory root …).
    pub source_hash_32: [u8; 32],
    /// SHA-256 of the *reason* this item is in context (provenance / evidence
    /// hint). Must be non-zero — invisible selection is forbidden.
    pub reason_hash_32: [u8; 32],
    /// Whether the user pinned this item (never auto-dropped on compaction).
    pub pinned: bool,
    /// Whether this item is excluded from the working set.
    pub excluded: bool,
}

impl ContextMapItem {
    /// Build a context item with visible provenance. `pinned`/`excluded` start
    /// `false`.
    #[must_use]
    pub const fn new(
        kind: ContextSourceKind,
        source_hash_32: [u8; 32],
        reason_hash_32: [u8; 32],
    ) -> Self {
        Self {
            kind,
            source_hash_32,
            reason_hash_32,
            pinned: false,
            excluded: false,
        }
    }

    /// Whether this item carries a visible provenance (non-zero reason hash).
    #[must_use]
    pub fn has_visible_provenance(&self) -> bool {
        self.reason_hash_32 != ZERO32
    }
}

/// §4.3 — the summary view of the context map.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ContextMapView {
    /// SHA-256 over the ordered item identities (a stable map fingerprint).
    pub items_hash_32: [u8; 32],
    /// Token budget for the working set.
    pub token_budget_u32: u32,
    /// Tokens currently used.
    pub used_tokens_u32: u32,
    /// Compaction risk in basis points (0..=10000).
    pub compact_risk_bps: u16,
}

/// The context map: a locally-held, fully-inspectable working set.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ContextMap {
    items: Vec<ContextMapItem>,
    token_budget_u32: u32,
    used_tokens_u32: u32,
}

impl ContextMap {
    /// A new context map with the given token budget.
    #[must_use]
    pub fn new(token_budget_u32: u32) -> Self {
        Self {
            items: Vec::new(),
            token_budget_u32,
            used_tokens_u32: 0,
        }
    }

    /// Add an item. Fail-closed: an item with no visible provenance (zero reason
    /// hash) is rejected and `false` is returned — invisible context selection
    /// is forbidden.
    pub fn add(&mut self, item: ContextMapItem) -> bool {
        if !item.has_visible_provenance() {
            return false;
        }
        self.items.push(item);
        true
    }

    /// All items, in insertion order (the `context map` command).
    #[must_use]
    pub fn items(&self) -> &[ContextMapItem] {
        &self.items
    }

    /// Record additional used tokens (saturating).
    pub fn add_used_tokens(&mut self, n: u32) {
        self.used_tokens_u32 = self.used_tokens_u32.saturating_add(n);
    }

    /// Pin the item with `source_hash_32`. Returns `false` if not found.
    pub fn pin(&mut self, source_hash_32: &[u8; 32]) -> bool {
        for it in &mut self.items {
            if &it.source_hash_32 == source_hash_32 {
                it.pinned = true;
                return true;
            }
        }
        false
    }

    /// Drop (exclude) the item with `source_hash_32`. A pinned item cannot be
    /// dropped. Returns `false` if not found or pinned.
    pub fn drop_source(&mut self, source_hash_32: &[u8; 32]) -> bool {
        for it in &mut self.items {
            if &it.source_hash_32 == source_hash_32 {
                if it.pinned {
                    return false;
                }
                it.excluded = true;
                return true;
            }
        }
        false
    }

    /// The provenance (`reason_hash_32`) of the item with `source_hash_32` — the
    /// `context why` command. `None` if not found.
    #[must_use]
    pub fn why(&self, source_hash_32: &[u8; 32]) -> Option<[u8; 32]> {
        self.items
            .iter()
            .find(|it| &it.source_hash_32 == source_hash_32)
            .map(|it| it.reason_hash_32)
    }

    /// The distinct source kinds present, in discriminant order — the `context
    /// sources` command.
    #[must_use]
    pub fn sources(&self) -> Vec<ContextSourceKind> {
        let mut out: Vec<ContextSourceKind> = Vec::new();
        for it in &self.items {
            if !out.contains(&it.kind) {
                out.push(it.kind);
            }
        }
        out
    }

    /// Compaction risk in bps: `used / budget`, saturating to 10000; a zero
    /// budget reports maximum risk.
    #[must_use]
    pub fn compact_risk_bps(&self) -> u16 {
        if self.token_budget_u32 == 0 {
            return 10000;
        }
        let ratio = (u64::from(self.used_tokens_u32) * 10000) / u64::from(self.token_budget_u32);
        ratio.min(10000) as u16
    }

    /// Compact the working set: remove excluded, non-pinned items. Returns the
    /// number removed. Pinned items are always retained.
    pub fn compact(&mut self) -> usize {
        let before = self.items.len();
        self.items.retain(|it| it.pinned || !it.excluded);
        before - self.items.len()
    }

    /// A bounded **background** compaction plan for the context working set,
    /// reusing the canonical [`CompactionPlan`] from the memory-tier compactor
    /// (same cooperative bounded-job contract). The working set is the `Recent`
    /// tier and compaction ages it toward `Mid`; the per-tick stall is bounded by
    /// the [`CONTEXT_COMPACT_STALL_BUDGET_MS`] ≤100ms law so the foreground never
    /// blocks. `input_count` is the current item count; `output_count` the count
    /// that survives compaction (pinned, or not excluded). The fixed `Recent`→
    /// `Mid` aging is always legal, so this never errors; the `Result` mirrors the
    /// canonical [`CompactionPlan::new`] constructor.
    pub fn background_compaction_plan(&self) -> Result<CompactionPlan, CompactionError> {
        let input_count_u32 = u32::try_from(self.items.len()).unwrap_or(u32::MAX);
        let survivors = self
            .items
            .iter()
            .filter(|it| it.pinned || !it.excluded)
            .count();
        let output_count_u32 = u32::try_from(survivors).unwrap_or(u32::MAX);
        CompactionPlan::new(
            MemoryTier::Recent,
            MemoryTier::Mid,
            input_count_u32,
            output_count_u32,
            CONTEXT_COMPACT_STALL_BUDGET_MS,
        )
    }

    /// The summary view — the `context status` command.
    #[must_use]
    pub fn view(&self) -> ContextMapView {
        let mut buf: Vec<u8> = Vec::with_capacity(self.items.len() * 98);
        for it in &self.items {
            buf.push(it.kind as u8);
            buf.extend_from_slice(&it.source_hash_32);
            buf.extend_from_slice(&it.reason_hash_32);
            buf.push(u8::from(it.pinned));
            buf.push(u8::from(it.excluded));
        }
        ContextMapView {
            items_hash_32: sha256_32(&buf),
            token_budget_u32: self.token_budget_u32,
            used_tokens_u32: self.used_tokens_u32,
            compact_risk_bps: self.compact_risk_bps(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn item(kind: ContextSourceKind, src: u8) -> ContextMapItem {
        ContextMapItem::new(kind, [src; 32], [src.wrapping_add(1); 32])
    }

    #[test]
    fn invisible_selection_is_rejected() {
        let mut m = ContextMap::new(1000);
        let no_prov = ContextMapItem::new(ContextSourceKind::Memory, [9u8; 32], ZERO32);
        assert!(!m.add(no_prov), "item without provenance must be rejected");
        assert_eq!(m.items().len(), 0);
    }

    #[test]
    fn repo_map_fixture_with_mixed_kinds() {
        let mut m = ContextMap::new(10_000);
        assert!(m.add(item(ContextSourceKind::RepoSymbol, 1)));
        assert!(m.add(item(ContextSourceKind::File, 2)));
        assert!(m.add(item(ContextSourceKind::Memory, 3)));
        assert!(m.add(item(ContextSourceKind::Skill, 4)));
        assert!(m.add(item(ContextSourceKind::WebSource, 5)));
        assert_eq!(m.items().len(), 5);
        assert_eq!(m.sources().len(), 5);
    }

    #[test]
    fn why_returns_provenance() {
        let mut m = ContextMap::new(1000);
        let it = item(ContextSourceKind::Skill, 7);
        let expect = it.reason_hash_32;
        assert!(m.add(it));
        assert_eq!(m.why(&[7u8; 32]), Some(expect));
        assert_eq!(m.why(&[123u8; 32]), None);
    }

    #[test]
    fn pin_protects_against_drop_and_compaction() {
        let mut m = ContextMap::new(1000);
        assert!(m.add(item(ContextSourceKind::File, 2)));
        assert!(m.pin(&[2u8; 32]));
        // pinned cannot be dropped
        assert!(!m.drop_source(&[2u8; 32]));
        assert!(m.add(item(ContextSourceKind::File, 3)));
        assert!(m.drop_source(&[3u8; 32]));
        let removed = m.compact();
        assert_eq!(removed, 1);
        assert_eq!(m.items().len(), 1);
        assert!(m.items()[0].pinned);
    }

    #[test]
    fn compact_risk_thresholds() {
        let mut m = ContextMap::new(1000);
        assert_eq!(m.compact_risk_bps(), 0);
        m.add_used_tokens(500);
        assert_eq!(m.compact_risk_bps(), 5000);
        m.add_used_tokens(1000);
        assert_eq!(m.compact_risk_bps(), 10000); // saturates
        let zero = ContextMap::new(0);
        assert_eq!(zero.compact_risk_bps(), 10000); // zero budget = max risk
    }

    #[test]
    fn background_compaction_plan_is_bounded_recent_to_mid() {
        let mut m = ContextMap::new(10_000);
        assert!(m.add(item(ContextSourceKind::File, 1)));
        assert!(m.add(item(ContextSourceKind::File, 2)));
        assert!(m.add(item(ContextSourceKind::File, 3)));
        // nothing excluded yet: every item survives compaction
        let plan = m.background_compaction_plan();
        assert!(
            plan.is_ok(),
            "Recent->Mid aging is always a legal transition"
        );
        if let Ok(plan) = plan {
            assert_eq!(plan.source_tier, MemoryTier::Recent);
            assert_eq!(plan.target_tier, MemoryTier::Mid);
            assert_eq!(plan.input_count_u32, 3);
            assert_eq!(plan.output_count_u32, 3, "no excluded item: all survive");
            // the per-tick stall is bounded by the <=100ms law
            assert_eq!(plan.stall_budget_ms_u16, CONTEXT_COMPACT_STALL_BUDGET_MS);
            assert!(plan.stall_budget_ms_u16 <= 100);
        }
        // dropping (excluding) a non-pinned item lowers the survivor (output) count
        assert!(m.drop_source(&[3u8; 32]));
        let plan2 = m.background_compaction_plan();
        assert!(plan2.is_ok());
        if let Ok(plan2) = plan2 {
            assert_eq!(plan2.input_count_u32, 3);
            assert_eq!(
                plan2.output_count_u32, 2,
                "an excluded non-pinned item does not survive compaction"
            );
        }
    }

    #[test]
    fn view_fingerprint_is_stable_and_tracks_state() {
        let mut m = ContextMap::new(2000);
        m.add(item(ContextSourceKind::RepoSymbol, 1));
        m.add_used_tokens(400);
        let v1 = m.view();
        let v2 = m.view();
        assert_eq!(v1, v2);
        assert_eq!(v1.compact_risk_bps, 2000);
        assert_eq!(v1.used_tokens_u32, 400);
    }
}
