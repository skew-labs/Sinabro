//! User model delta.
//!
//! [`UserModel`] stores the four user-model components — preferences, facts,
//! boundaries and the relationship graph — as **hashed, diffable** 32-byte
//! components bound to a memory owner ([`SigningPublicKey`]). A
//! [`UserModelDelta`] is the hashed snapshot of a model plus its
//! [`DeleteSemantics`]; diffing a delta against a previous model reports which
//! components changed. Hashes are canonical [`derive_blob_id`] digests over
//! domain-tagged component bytes, so a delta **replays deterministically**: the
//! same component content always yields the same hashes, regardless of update
//! order.
//!
//! The model may **emit** a measurement-only [`StageDPolicyObservation`] for
//! Stage E, but it cannot rewrite retention / retrieval policy: the emitted
//! observation's `production_change_allowed` is `false` by construction (a
//! no-op for production policy until Stage E sandbox / held-out approval).
//!
//! `DeleteSemantics` is imported from the module boundary ([`super`]); the
//! tombstone / resurrection-prevention **policy** over it is owned by the
//! tombstone-policy module.

use crate::intelligence::feedback::FeedbackLabel;
use crate::owner::SigningPublicKey;
use mnemos_c_walrus::derive_blob_id;

use super::{
    DeleteSemantics, StageDEvidenceRef, StageDPolicyObservation, StageDPolicyObservationKind,
};

const PREFERENCES_DOMAIN: &[u8] = b"mnemos.stage_d.user_model.preferences.v1";
const FACTS_DOMAIN: &[u8] = b"mnemos.stage_d.user_model.facts.v1";
const BOUNDARIES_DOMAIN: &[u8] = b"mnemos.stage_d.user_model.boundaries.v1";
const RELATIONSHIP_GRAPH_DOMAIN: &[u8] = b"mnemos.stage_d.user_model.relationship_graph.v1";

/// The four hashed, diffable user-model components bound to a memory owner.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct UserModel {
    owner: SigningPublicKey,
    preferences_hash_32: [u8; 32],
    facts_hash_32: [u8; 32],
    boundaries_hash_32: [u8; 32],
    relationship_graph_hash_32: [u8; 32],
}

impl UserModel {
    /// Construct an empty user model for an owner. Each component starts at its
    /// well-defined empty hash (domain digest of no content).
    #[must_use]
    pub fn empty(owner: SigningPublicKey) -> Self {
        Self {
            owner,
            preferences_hash_32: component_hash(PREFERENCES_DOMAIN, &[]),
            facts_hash_32: component_hash(FACTS_DOMAIN, &[]),
            boundaries_hash_32: component_hash(BOUNDARIES_DOMAIN, &[]),
            relationship_graph_hash_32: component_hash(RELATIONSHIP_GRAPH_DOMAIN, &[]),
        }
    }

    /// The memory owner this model belongs to.
    #[must_use]
    pub const fn owner(&self) -> &SigningPublicKey {
        &self.owner
    }

    /// Set the preferences component from its canonical bytes.
    pub fn set_preferences(&mut self, bytes: &[u8]) {
        self.preferences_hash_32 = component_hash(PREFERENCES_DOMAIN, bytes);
    }

    /// Set the facts component from its canonical bytes.
    pub fn set_facts(&mut self, bytes: &[u8]) {
        self.facts_hash_32 = component_hash(FACTS_DOMAIN, bytes);
    }

    /// Set the relationship-graph component from its canonical bytes.
    pub fn set_relationship_graph(&mut self, bytes: &[u8]) {
        self.relationship_graph_hash_32 = component_hash(RELATIONSHIP_GRAPH_DOMAIN, bytes);
    }

    /// Set the boundaries component from the user's boundary-bearing feedback
    /// labels (`Forget` / `Boundary`). Order-independent (tags are sorted before
    /// hashing) so the boundary component replays deterministically.
    pub fn set_boundaries_from_labels(&mut self, labels: &[FeedbackLabel]) {
        let mut tags: Vec<u8> = labels
            .iter()
            .filter(|l| l.overrides_model_curiosity())
            .map(|l| l.tag())
            .collect();
        tags.sort_unstable();
        self.boundaries_hash_32 = component_hash(BOUNDARIES_DOMAIN, &tags);
    }

    /// Snapshot this model as a [`UserModelDelta`] with the given deletion
    /// semantics attached.
    #[must_use]
    pub const fn to_delta(&self, delete_semantics: DeleteSemantics) -> UserModelDelta {
        UserModelDelta {
            preferences_hash_32: self.preferences_hash_32,
            facts_hash_32: self.facts_hash_32,
            boundaries_hash_32: self.boundaries_hash_32,
            relationship_graph_hash_32: self.relationship_graph_hash_32,
            delete_semantics,
        }
    }

    /// Emit a measurement-only policy observation. `production_change_allowed` is
    /// always `false` — the observation can never promote itself into a
    /// production retention / retrieval policy change.
    #[must_use]
    pub const fn emit_policy_observation(
        &self,
        kind: StageDPolicyObservationKind,
        evidence: StageDEvidenceRef,
        expected_effect_hash_32: [u8; 32],
        measured_effect_hash_32: [u8; 32],
    ) -> StageDPolicyObservation {
        StageDPolicyObservation::new(
            kind,
            evidence,
            expected_effect_hash_32,
            measured_effect_hash_32,
        )
    }
}

/// Which user-model components changed between a previous model and a delta.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash, Default)]
pub struct ChangedComponents {
    /// Preferences component changed.
    pub preferences: bool,
    /// Facts component changed.
    pub facts: bool,
    /// Boundaries component changed.
    pub boundaries: bool,
    /// Relationship-graph component changed.
    pub relationship_graph: bool,
}

impl ChangedComponents {
    /// Whether any component changed.
    #[must_use]
    pub const fn any(&self) -> bool {
        self.preferences || self.facts || self.boundaries || self.relationship_graph
    }
}

/// A hashed snapshot of a user model plus its deletion semantics.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub struct UserModelDelta {
    /// Preferences component hash.
    pub preferences_hash_32: [u8; 32],
    /// Facts component hash.
    pub facts_hash_32: [u8; 32],
    /// Boundaries component hash.
    pub boundaries_hash_32: [u8; 32],
    /// Relationship-graph component hash.
    pub relationship_graph_hash_32: [u8; 32],
    /// How deletions in this delta are handled (policy owned by the tombstone-policy module).
    pub delete_semantics: DeleteSemantics,
}

impl UserModelDelta {
    /// Report which components changed relative to a previous model.
    #[must_use]
    pub fn changed_from(&self, prev: &UserModel) -> ChangedComponents {
        ChangedComponents {
            preferences: self.preferences_hash_32 != prev.preferences_hash_32,
            facts: self.facts_hash_32 != prev.facts_hash_32,
            boundaries: self.boundaries_hash_32 != prev.boundaries_hash_32,
            relationship_graph: self.relationship_graph_hash_32 != prev.relationship_graph_hash_32,
        }
    }
}

/// Canonical 32-byte component hash: [`derive_blob_id`] over `domain || bytes`.
fn component_hash(domain: &[u8], bytes: &[u8]) -> [u8; 32] {
    let mut d = Vec::with_capacity(domain.len() + bytes.len());
    d.extend_from_slice(domain);
    d.extend_from_slice(bytes);
    *derive_blob_id(&d).as_bytes()
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    #![allow(clippy::expect_used)]
    #![allow(clippy::panic)]

    use super::*;
    use mnemos_a_core::{StageBTraceLink, StageCTraceLink, StageDTraceLink};

    fn owner() -> SigningPublicKey {
        SigningPublicKey::from_bytes(&[7_u8; 32]).expect("32-byte owner key")
    }

    fn trace() -> StageDTraceLink {
        StageDTraceLink::new(
            StageCTraceLink::new(StageBTraceLink::new(7, 327, 0), 327, 99),
            327,
            0,
        )
    }

    #[test]
    fn preference_delta_isolates_component() {
        let prev = UserModel::empty(owner());
        let mut next = prev;
        next.set_preferences(b"prefers-terse-replies");
        let delta = next.to_delta(DeleteSemantics::Tombstone);
        let changed = delta.changed_from(&prev);
        assert!(changed.preferences);
        assert!(!changed.facts);
        assert!(!changed.boundaries);
        assert!(!changed.relationship_graph);
    }

    #[test]
    fn fact_delta_isolates_component() {
        let prev = UserModel::empty(owner());
        let mut next = prev;
        next.set_facts(b"lives-in-seoul");
        let changed = next
            .to_delta(DeleteSemantics::Tombstone)
            .changed_from(&prev);
        assert!(changed.facts);
        assert!(!changed.preferences);
    }

    #[test]
    fn boundary_delta_from_labels() {
        let prev = UserModel::empty(owner());
        let mut next = prev;
        next.set_boundaries_from_labels(&[FeedbackLabel::Boundary, FeedbackLabel::Keep]);
        let changed = next
            .to_delta(DeleteSemantics::Tombstone)
            .changed_from(&prev);
        assert!(changed.boundaries);
        assert!(!changed.preferences);
    }

    #[test]
    fn relationship_graph_delta_isolates_component() {
        let prev = UserModel::empty(owner());
        let mut next = prev;
        next.set_relationship_graph(b"alice->bob:colleague");
        let changed = next
            .to_delta(DeleteSemantics::Tombstone)
            .changed_from(&prev);
        assert!(changed.relationship_graph);
        assert!(!changed.facts);
    }

    #[test]
    fn delete_semantics_round_trips() {
        let m = UserModel::empty(owner());
        assert_eq!(
            m.to_delta(DeleteSemantics::Tombstone).delete_semantics,
            DeleteSemantics::Tombstone
        );
        assert_eq!(
            m.to_delta(DeleteSemantics::HardDeleteLocal)
                .delete_semantics,
            DeleteSemantics::HardDeleteLocal
        );
        assert_eq!(
            m.to_delta(DeleteSemantics::ExportRedacted).delete_semantics,
            DeleteSemantics::ExportRedacted
        );
    }

    #[test]
    fn policy_observation_is_no_op() {
        let m = UserModel::empty(owner());
        let evidence = StageDEvidenceRef::new([0x44; 32], trace());
        let obs = m.emit_policy_observation(
            StageDPolicyObservationKind::MemoryRetrieval,
            evidence,
            [0x55; 32],
            [0x66; 32],
        );
        assert!(
            !obs.production_change_allowed(),
            "an emitted policy observation must be a no-op for production policy"
        );
    }

    #[test]
    fn deltas_replay_deterministically() {
        // Two independent builds with identical content must produce identical
        // models and identical deltas, regardless of label order.
        let mut a = UserModel::empty(owner());
        a.set_preferences(b"p");
        a.set_facts(b"f");
        a.set_boundaries_from_labels(&[FeedbackLabel::Boundary, FeedbackLabel::Forget]);

        let mut b = UserModel::empty(owner());
        b.set_boundaries_from_labels(&[FeedbackLabel::Forget, FeedbackLabel::Boundary]);
        b.set_facts(b"f");
        b.set_preferences(b"p");

        assert_eq!(a, b, "same content + owner must yield identical models");
        assert_eq!(
            a.to_delta(DeleteSemantics::Tombstone),
            b.to_delta(DeleteSemantics::Tombstone),
            "deltas must replay deterministically"
        );
    }
}
