//! 5-tier capability diff.
//!
//! `sinabro capability diff`. Every tool / skill install or run shows a
//! capability diff *before* execution: what is added, what is
//! removed, and whether the privilege tier escalated. A skill that declares
//! fewer capabilities than it actually requires (a *hidden permission*) is
//! denied.
//!
//! Reuse: mirrors the canonical `CapabilityKind` and the
//! WASM Tier-2 capability model, expressed here as a local `repr(u8)` ladder +
//! `u8` bitset so the diff is a pure, allocation-free projection.

use crate::sha256_32;
use crate::tui::RenderTruth;

/// A capability tier. The ladder is ordered by privilege: a higher discriminant
/// is strictly more powerful, so an increase in the maximum held tier is an
/// escalation.
#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum CapabilityKind {
    /// Tier 1 — pure computation; no I/O.
    PureCompute = 1,
    /// Tier 2 — read the local filesystem.
    ReadLocal = 2,
    /// Tier 3 — write the local filesystem.
    WriteLocal = 3,
    /// Tier 4 — network egress.
    Network = 4,
    /// Tier 5 — privileged (process spawn / system).
    Privileged = 5,
}

impl CapabilityKind {
    /// Every capability in ladder order.
    pub const ALL: [CapabilityKind; 5] = [
        CapabilityKind::PureCompute,
        CapabilityKind::ReadLocal,
        CapabilityKind::WriteLocal,
        CapabilityKind::Network,
        CapabilityKind::Privileged,
    ];

    /// The privilege tier (1..=5).
    #[must_use]
    pub const fn tier(self) -> u8 {
        self as u8
    }
}

/// A set of capabilities as a 5-bit `u8` bitset.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct CapabilitySet {
    bits_u8: u8,
}

impl CapabilitySet {
    const fn bit(kind: CapabilityKind) -> u8 {
        1u8 << (kind as u8 - 1)
    }

    /// The empty capability set.
    #[must_use]
    pub const fn empty() -> Self {
        Self { bits_u8: 0 }
    }

    /// The full capability set (all five tiers).
    #[must_use]
    pub const fn all() -> Self {
        Self {
            bits_u8: 0b0001_1111,
        }
    }

    /// A set containing exactly one capability.
    #[must_use]
    pub const fn with(kind: CapabilityKind) -> Self {
        Self {
            bits_u8: Self::bit(kind),
        }
    }

    /// Return a copy with `kind` inserted.
    #[must_use]
    pub const fn insert(self, kind: CapabilityKind) -> Self {
        Self {
            bits_u8: self.bits_u8 | Self::bit(kind),
        }
    }

    /// Whether `kind` is in the set.
    #[must_use]
    pub const fn contains(self, kind: CapabilityKind) -> bool {
        self.bits_u8 & Self::bit(kind) != 0
    }

    /// The raw bitset.
    #[must_use]
    pub const fn bits(self) -> u8 {
        self.bits_u8
    }

    /// Whether the set is empty.
    #[must_use]
    pub const fn is_empty(self) -> bool {
        self.bits_u8 == 0
    }

    /// Whether `self` is a subset of `other` (every capability in `self` is in
    /// `other`).
    #[must_use]
    pub const fn is_subset_of(self, other: Self) -> bool {
        self.bits_u8 & other.bits_u8 == self.bits_u8
    }

    /// The union of two sets.
    #[must_use]
    pub const fn union(self, other: Self) -> Self {
        Self {
            bits_u8: self.bits_u8 | other.bits_u8,
        }
    }

    /// The capabilities in `self` not in `other`.
    #[must_use]
    pub const fn difference(self, other: Self) -> Self {
        Self {
            bits_u8: self.bits_u8 & !other.bits_u8,
        }
    }

    /// The maximum privilege tier held (0 when empty).
    #[must_use]
    pub const fn max_tier(self) -> u8 {
        if self.contains(CapabilityKind::Privileged) {
            5
        } else if self.contains(CapabilityKind::Network) {
            4
        } else if self.contains(CapabilityKind::WriteLocal) {
            3
        } else if self.contains(CapabilityKind::ReadLocal) {
            2
        } else if self.contains(CapabilityKind::PureCompute) {
            1
        } else {
            0
        }
    }

    /// The number of capabilities in the set.
    #[must_use]
    pub const fn count(self) -> u32 {
        self.bits_u8.count_ones()
    }
}

/// A before→after capability diff shown before a tool/skill install or run.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CapabilityDiff {
    /// Capabilities held before.
    pub before: CapabilitySet,
    /// Capabilities held after.
    pub after: CapabilitySet,
}

impl CapabilityDiff {
    /// Build a diff.
    #[must_use]
    pub const fn new(before: CapabilitySet, after: CapabilitySet) -> Self {
        Self { before, after }
    }

    /// Capabilities added (in `after`, not `before`).
    #[must_use]
    pub const fn added(self) -> CapabilitySet {
        self.after.difference(self.before)
    }

    /// Capabilities removed (in `before`, not `after`).
    #[must_use]
    pub const fn removed(self) -> CapabilitySet {
        self.before.difference(self.after)
    }

    /// Whether any capability was gained.
    #[must_use]
    pub const fn gained_capability(self) -> bool {
        !self.added().is_empty()
    }

    /// Whether the maximum privilege tier increased (an escalation).
    #[must_use]
    pub const fn is_tier_escalation(self) -> bool {
        self.after.max_tier() > self.before.max_tier()
    }

    /// Whether this diff requires an approval — any gained capability does.
    #[must_use]
    pub const fn requires_approval(self) -> bool {
        self.gained_capability()
    }

    /// A deterministic diff snapshot (stable for the same before/after).
    #[must_use]
    pub fn snapshot_hash_32(self) -> [u8; 32] {
        sha256_32(&[self.before.bits(), self.after.bits()])
    }

    /// Render truth: a diff that gains capability is a `Yellow` warning (needs
    /// approval before execution); an unchanged-or-narrower diff is `Green`.
    #[must_use]
    pub const fn render_truth(self) -> RenderTruth {
        if self.requires_approval() {
            RenderTruth::Yellow
        } else {
            RenderTruth::Green
        }
    }
}

/// Whether a `required` capability set hides a permission not in `declared`. A
/// hidden permission must be denied before execution.
#[must_use]
pub const fn detect_hidden_permission(declared: CapabilitySet, required: CapabilitySet) -> bool {
    !required.is_subset_of(declared)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn added_capability_is_detected() {
        let before = CapabilitySet::with(CapabilityKind::PureCompute);
        let after = before.insert(CapabilityKind::Network);
        let diff = CapabilityDiff::new(before, after);
        assert!(diff.added().contains(CapabilityKind::Network));
        assert!(!diff.added().contains(CapabilityKind::PureCompute));
        assert!(diff.gained_capability());
        assert!(diff.requires_approval());
        assert_eq!(diff.render_truth(), RenderTruth::Yellow);
    }

    #[test]
    fn removed_capability_is_detected() {
        let before =
            CapabilitySet::with(CapabilityKind::PureCompute).insert(CapabilityKind::Network);
        let after = CapabilitySet::with(CapabilityKind::PureCompute);
        let diff = CapabilityDiff::new(before, after);
        assert!(diff.removed().contains(CapabilityKind::Network));
        assert!(!diff.gained_capability());
        // narrowing capabilities needs no approval
        assert_eq!(diff.render_truth(), RenderTruth::Green);
    }

    #[test]
    fn tier_escalation_is_detected() {
        let before = CapabilitySet::with(CapabilityKind::Network); // tier 4
        let after = before.insert(CapabilityKind::Privileged); // tier 5
        let diff = CapabilityDiff::new(before, after);
        assert!(diff.is_tier_escalation());
        assert_eq!(before.max_tier(), 4);
        assert_eq!(after.max_tier(), 5);
    }

    #[test]
    fn hidden_permission_is_denied() {
        let declared =
            CapabilitySet::with(CapabilityKind::PureCompute).insert(CapabilityKind::ReadLocal);
        // requires Network, which was not declared -> hidden permission
        let required = declared.insert(CapabilityKind::Network);
        assert!(detect_hidden_permission(declared, required));
        // a required set within the declared set is not hidden
        let honest = CapabilitySet::with(CapabilityKind::ReadLocal);
        assert!(!detect_hidden_permission(declared, honest));
    }

    #[test]
    fn diff_snapshot_is_stable_and_distinguishing() {
        let a = CapabilityDiff::new(
            CapabilitySet::empty(),
            CapabilitySet::with(CapabilityKind::ReadLocal),
        );
        assert_eq!(a.snapshot_hash_32(), a.snapshot_hash_32());
        let b = CapabilityDiff::new(
            CapabilitySet::empty(),
            CapabilitySet::with(CapabilityKind::Network),
        );
        assert_ne!(a.snapshot_hash_32(), b.snapshot_hash_32());
    }

    #[test]
    fn set_algebra_basics() {
        let s = CapabilitySet::all();
        assert_eq!(s.count(), 5);
        assert_eq!(s.max_tier(), 5);
        assert!(CapabilitySet::empty().is_subset_of(s));
        assert!(!s.is_subset_of(CapabilitySet::empty()));
        assert_eq!(CapabilitySet::empty().max_tier(), 0);
    }
}
