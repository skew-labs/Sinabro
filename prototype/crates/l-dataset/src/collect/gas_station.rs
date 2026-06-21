//! Sui effect-shape / Gas Station signal (atom #359 · E.1.8).
//!
//! **Read-only classifier.** Sponsor-eligible code is positive only if the
//! effect shape is allowlisted by the C `GasStationPolicy`. A wildcard policy,
//! a raw `GasData` shape, a missing quota, or an unbounded-storage shape are
//! *hard negative* examples. Anything unrecognized fails closed to a deny. This
//! collector never sponsors, signs, or submits anything — it classifies an
//! effect-shape descriptor already present in C/D evidence.
use crate::diet_kind::AtomDietKey;

/// The effect-shape decision for a sponsor-eligibility classification.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
#[repr(u8)]
pub enum EffectShapeDecision {
    /// Shape matches an allowlisted Gas Station policy entry.
    Allowlisted = 1,
    /// Wildcard policy (`*`) — denied.
    WildcardDeny = 2,
    /// Raw `GasData` shape — denied.
    RawGasDataDeny = 3,
    /// Missing / exceeded quota — denied.
    QuotaDeny = 4,
    /// Unbounded-storage ("storage bomb") shape — denied.
    StorageBombDeny = 5,
    /// Unrecognized shape — fail-closed deny.
    UnknownDeny = 6,
}

impl EffectShapeDecision {
    /// Numeric discriminant (`1..=6`).
    pub const fn as_u8(self) -> u8 {
        self as u8
    }

    /// Whether the decision is a deny (anything but [`Self::Allowlisted`]).
    pub const fn is_deny(self) -> bool {
        !matches!(self, Self::Allowlisted)
    }
}

/// Sui effect-shape / Gas Station sponsor-eligibility signal.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub struct GasStationSignal {
    /// The source atom.
    pub key: AtomDietKey,
    /// The classified effect-shape decision.
    pub decision: EffectShapeDecision,
    /// Sponsor-eligible only when the shape is allowlisted.
    pub sponsor_eligible: bool,
    /// Any deny becomes a hard negative training example.
    pub hard_negative: bool,
    /// Deterministic anchor of the (hashed) effect-shape descriptor.
    pub evidence_hash_32: [u8; 32],
}

/// Classify an effect-shape descriptor, fail-closed. Order matters: deny shapes
/// are matched before the allow path so a descriptor that mentions both a
/// wildcard and "allow" still denies.
pub fn classify_effect(descriptor: &str) -> EffectShapeDecision {
    let u = descriptor.trim().to_ascii_uppercase();
    if u.contains('*') || u.contains("WILDCARD") {
        EffectShapeDecision::WildcardDeny
    } else if u.contains("RAW") && u.contains("GASDATA") || u.contains("RAW_GAS_DATA") {
        EffectShapeDecision::RawGasDataDeny
    } else if u.contains("QUOTA") {
        EffectShapeDecision::QuotaDeny
    } else if u.contains("STORAGE") && (u.contains("BOMB") || u.contains("UNBOUNDED")) {
        EffectShapeDecision::StorageBombDeny
    } else if u.contains("ALLOWLIST") || u.starts_with("ALLOW") {
        EffectShapeDecision::Allowlisted
    } else {
        EffectShapeDecision::UnknownDeny
    }
}

/// Collect a [`GasStationSignal`] by classifying an effect-shape descriptor.
/// Infallible: an unrecognized descriptor classifies to a fail-closed deny.
pub fn collect(key: AtomDietKey, effect_shape: &str) -> GasStationSignal {
    let decision = classify_effect(effect_shape);
    let sponsor_eligible = matches!(decision, EffectShapeDecision::Allowlisted);
    GasStationSignal {
        key,
        decision,
        sponsor_eligible,
        hard_negative: decision.is_deny(),
        evidence_hash_32: crate::sha256(effect_shape.as_bytes()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::diet_kind::DietSourceStage;

    fn key() -> AtomDietKey {
        AtomDietKey::new(DietSourceStage::StageC, 359)
    }

    #[test]
    fn allowlisted_effect_is_sponsor_eligible() {
        let s = collect(key(), "ALLOWLISTED move call pkg::module::function");
        assert_eq!(s.decision, EffectShapeDecision::Allowlisted);
        assert!(s.sponsor_eligible);
        assert!(!s.hard_negative);
    }

    #[test]
    fn wildcard_is_hard_negative() {
        let s = collect(key(), "policy allows * (any target)");
        assert_eq!(s.decision, EffectShapeDecision::WildcardDeny);
        assert!(!s.sponsor_eligible);
        assert!(s.hard_negative);
    }

    #[test]
    fn raw_gasdata_is_denied() {
        assert_eq!(
            classify_effect("raw GasData passed by caller"),
            EffectShapeDecision::RawGasDataDeny
        );
    }

    #[test]
    fn quota_deny() {
        assert_eq!(
            classify_effect("quota exceeded for sponsor"),
            EffectShapeDecision::QuotaDeny
        );
    }

    #[test]
    fn storage_bomb_deny() {
        assert_eq!(
            classify_effect("unbounded storage growth (storage bomb)"),
            EffectShapeDecision::StorageBombDeny
        );
    }

    #[test]
    fn unrecognized_fails_closed() {
        let s = collect(key(), "weird opaque effect");
        assert_eq!(s.decision, EffectShapeDecision::UnknownDeny);
        assert!(s.hard_negative);
    }
}
