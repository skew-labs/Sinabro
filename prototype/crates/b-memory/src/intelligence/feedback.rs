//! User feedback labels (Stage D Cluster 6, atom #325 · D.5.4).
//!
//! [`FeedbackLabel`] (§4.6) is both a training signal and a policy signal. The
//! resolution rule is explicit: a user label **overrides** the model's own
//! curiosity, and within the labels, `Forget` and `Boundary` take precedence —
//! a user asking to forget or to set a boundary always wins over the model
//! wanting to retain or surface a memory.
//!
//! Resolution is deterministic and order-independent: the same set of labels
//! resolves to the same decision regardless of the order they were recorded, so
//! a replayed label log reproduces the same outcome.

/// User feedback on a memory (§4.6).
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
#[repr(u8)]
pub enum FeedbackLabel {
    /// Keep the memory as-is.
    Keep = 1,
    /// Forget the memory (delete intent).
    Forget = 2,
    /// Promote the memory (raise importance / retrieval priority).
    Promote = 3,
    /// Demote the memory (lower importance / retrieval priority).
    Demote = 4,
    /// Set a hard boundary (do not store / surface this content).
    Boundary = 5,
}

impl FeedbackLabel {
    /// Stable `u8` tag — mirrors the `#[repr(u8)]` discriminant.
    #[inline]
    pub const fn tag(self) -> u8 {
        self as u8
    }

    /// Parse a label from its `u8` tag, fail-closed on any unknown value.
    #[must_use]
    pub const fn from_tag(tag: u8) -> Option<Self> {
        match tag {
            1 => Some(Self::Keep),
            2 => Some(Self::Forget),
            3 => Some(Self::Promote),
            4 => Some(Self::Demote),
            5 => Some(Self::Boundary),
            _ => None,
        }
    }

    /// Conflict precedence (higher wins). `Boundary` is the most restrictive,
    /// then `Forget`; the importance nudges (`Demote`/`Promote`) and `Keep`
    /// rank below. This encodes "boundary/forget precedence".
    #[must_use]
    pub const fn precedence(self) -> u8 {
        match self {
            Self::Keep => 1,
            Self::Promote => 2,
            Self::Demote => 3,
            Self::Forget => 4,
            Self::Boundary => 5,
        }
    }

    /// Whether this label overrides the model's own curiosity. `Forget` and
    /// `Boundary` always override; the others coexist with model proposals.
    #[must_use]
    pub const fn overrides_model_curiosity(self) -> bool {
        matches!(self, Self::Forget | Self::Boundary)
    }
}

/// The model's own proposal for a memory, absent any user label.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum ModelCuriosity {
    /// The model wants to retain / surface the memory.
    Retain,
    /// The model proposes demoting the memory.
    Demote,
    /// The model proposes dropping the memory.
    Drop,
}

/// The resolved feedback decision after combining the model's curiosity with any
/// user labels.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum ResolvedFeedback {
    /// No user label; the model's curiosity governs.
    FollowModel(ModelCuriosity),
    /// User asked to keep.
    Keep,
    /// User asked to promote.
    Promote,
    /// User asked to demote.
    Demote,
    /// User asked to forget (overrides model curiosity).
    Forget,
    /// User set a boundary (overrides model curiosity).
    Boundary,
}

/// Resolve the effective decision for a memory: the highest-precedence user
/// label wins and overrides the model's curiosity; with no labels the model's
/// curiosity governs. Order-independent over the label set.
#[must_use]
pub fn resolve(model: ModelCuriosity, labels: &[FeedbackLabel]) -> ResolvedFeedback {
    match labels.iter().copied().max_by_key(|l| l.precedence()) {
        None => ResolvedFeedback::FollowModel(model),
        Some(FeedbackLabel::Keep) => ResolvedFeedback::Keep,
        Some(FeedbackLabel::Promote) => ResolvedFeedback::Promote,
        Some(FeedbackLabel::Demote) => ResolvedFeedback::Demote,
        Some(FeedbackLabel::Forget) => ResolvedFeedback::Forget,
        Some(FeedbackLabel::Boundary) => ResolvedFeedback::Boundary,
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    #![allow(clippy::expect_used)]
    #![allow(clippy::panic)]

    use super::*;

    #[test]
    fn keep_promote_demote_follow_label() {
        assert_eq!(
            resolve(ModelCuriosity::Retain, &[FeedbackLabel::Keep]),
            ResolvedFeedback::Keep
        );
        assert_eq!(
            resolve(ModelCuriosity::Retain, &[FeedbackLabel::Promote]),
            ResolvedFeedback::Promote
        );
        assert_eq!(
            resolve(ModelCuriosity::Retain, &[FeedbackLabel::Demote]),
            ResolvedFeedback::Demote
        );
    }

    #[test]
    fn forget_and_boundary_override_model_curiosity() {
        assert!(FeedbackLabel::Forget.overrides_model_curiosity());
        assert!(FeedbackLabel::Boundary.overrides_model_curiosity());
        assert!(!FeedbackLabel::Keep.overrides_model_curiosity());
        assert!(!FeedbackLabel::Promote.overrides_model_curiosity());
        assert!(!FeedbackLabel::Demote.overrides_model_curiosity());
        // Even when the model wants to retain, Forget/Boundary win.
        assert_eq!(
            resolve(ModelCuriosity::Retain, &[FeedbackLabel::Forget]),
            ResolvedFeedback::Forget
        );
        assert_eq!(
            resolve(ModelCuriosity::Retain, &[FeedbackLabel::Boundary]),
            ResolvedFeedback::Boundary
        );
    }

    #[test]
    fn no_labels_follows_model() {
        assert_eq!(
            resolve(ModelCuriosity::Drop, &[]),
            ResolvedFeedback::FollowModel(ModelCuriosity::Drop)
        );
    }

    #[test]
    fn conflicting_labels_resolve_by_precedence() {
        // Forget beats Promote.
        assert_eq!(
            resolve(
                ModelCuriosity::Retain,
                &[FeedbackLabel::Promote, FeedbackLabel::Forget]
            ),
            ResolvedFeedback::Forget
        );
        // Boundary beats Forget.
        assert_eq!(
            resolve(
                ModelCuriosity::Retain,
                &[FeedbackLabel::Forget, FeedbackLabel::Boundary]
            ),
            ResolvedFeedback::Boundary
        );
    }

    #[test]
    fn replay_labels_is_order_independent() {
        let forward = resolve(
            ModelCuriosity::Retain,
            &[
                FeedbackLabel::Keep,
                FeedbackLabel::Promote,
                FeedbackLabel::Forget,
            ],
        );
        let reverse = resolve(
            ModelCuriosity::Retain,
            &[
                FeedbackLabel::Forget,
                FeedbackLabel::Promote,
                FeedbackLabel::Keep,
            ],
        );
        assert_eq!(forward, reverse);
        assert_eq!(forward, ResolvedFeedback::Forget);
    }

    #[test]
    fn tag_round_trip() {
        for label in [
            FeedbackLabel::Keep,
            FeedbackLabel::Forget,
            FeedbackLabel::Promote,
            FeedbackLabel::Demote,
            FeedbackLabel::Boundary,
        ] {
            assert_eq!(FeedbackLabel::from_tag(label.tag()), Some(label));
        }
        assert_eq!(FeedbackLabel::from_tag(0), None);
        assert_eq!(FeedbackLabel::from_tag(6), None);
    }
}
