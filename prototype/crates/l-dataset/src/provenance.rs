//! sample provenance chain (atom #369 · E.1.18).
//!
//! Every sample carries a provenance chain: the source-stage + atom lineage, the
//! path hash, and the content hash — *path alone is never provenance*. A sample
//! whose license is unknown is quarantined (never exported, never reward) until
//! the license is resolved. The [`ProvenanceChain::lineage_hash`] feeds the
//! dedup composite (#369) so lineage participates in duplicate detection.
use crate::diet_kind::AtomDietKey;

/// A content + path + source-lineage provenance chain for one sample.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub struct ProvenanceChain {
    /// The source atom.
    pub key: AtomDietKey,
    /// `sha256` of the `(source stage, atom number)` lineage tuple.
    pub source_stage_atom_hash_32: [u8; 32],
    /// `sha256` of the sample's path (where it lives).
    pub path_hash_32: [u8; 32],
    /// `sha256` of the sample's content (what it is).
    pub content_hash_32: [u8; 32],
    /// Whether the sample's license is known (unknown ⇒ quarantine).
    pub license_known: bool,
}

impl ProvenanceChain {
    /// Build a provenance chain. The lineage hash is derived from the atom key so
    /// two samples from the same source atom share a lineage anchor.
    pub fn new(
        key: AtomDietKey,
        path_hash_32: [u8; 32],
        content_hash_32: [u8; 32],
        license_known: bool,
    ) -> Self {
        let mut buf = [0u8; 3];
        buf[0] = key.source.as_u8();
        buf[1..3].copy_from_slice(&key.atom_u16.to_le_bytes());
        Self {
            key,
            source_stage_atom_hash_32: crate::sha256(&buf),
            path_hash_32,
            content_hash_32,
            license_known,
        }
    }

    /// A sample with an unknown license is quarantined.
    pub const fn quarantined(&self) -> bool {
        !self.license_known
    }

    /// A deterministic lineage hash over `(lineage, path, content)`. Feeds the
    /// dedup composite so source lineage participates in duplicate detection.
    pub fn lineage_hash(&self) -> [u8; 32] {
        let mut buf = [0u8; 96];
        buf[0..32].copy_from_slice(&self.source_stage_atom_hash_32);
        buf[32..64].copy_from_slice(&self.path_hash_32);
        buf[64..96].copy_from_slice(&self.content_hash_32);
        crate::sha256(&buf)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::diet_kind::DietSourceStage;

    fn key() -> AtomDietKey {
        AtomDietKey::new(DietSourceStage::StageD, 369)
    }

    #[test]
    fn license_unknown_is_quarantined() {
        let p = ProvenanceChain::new(key(), [1u8; 32], [2u8; 32], false);
        assert!(p.quarantined());
        let ok = ProvenanceChain::new(key(), [1u8; 32], [2u8; 32], true);
        assert!(!ok.quarantined());
    }

    #[test]
    fn lineage_hash_is_deterministic_and_content_sensitive() {
        let a = ProvenanceChain::new(key(), [1u8; 32], [2u8; 32], true);
        let b = ProvenanceChain::new(key(), [1u8; 32], [2u8; 32], true);
        assert_eq!(a.lineage_hash(), b.lineage_hash());
        // a content change flips the lineage hash (path alone is not provenance).
        let c = ProvenanceChain::new(key(), [1u8; 32], [9u8; 32], true);
        assert_ne!(a.lineage_hash(), c.lineage_hash());
    }

    #[test]
    fn different_source_atoms_have_different_lineage() {
        let a = ProvenanceChain::new(
            AtomDietKey::new(DietSourceStage::StageD, 1),
            [1u8; 32],
            [2u8; 32],
            true,
        );
        let b = ProvenanceChain::new(
            AtomDietKey::new(DietSourceStage::StageC, 1),
            [1u8; 32],
            [2u8; 32],
            true,
        );
        assert_ne!(a.source_stage_atom_hash_32, b.source_stage_atom_hash_32);
    }
}
