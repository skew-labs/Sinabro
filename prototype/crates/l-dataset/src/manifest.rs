//! AtomDiet manifest: per-file references + the per-atom manifest with a
//! monotone schema version and deterministic digest.
//!
//! Every source file is content-hashed *and* path-hashed; path alone is never
//! provenance. The 21-kind set is closed, so a duplicate kind, an empty hash, a
//! schema downgrade, or a `Complete` claim missing a required kind all reject.
use crate::StageETraceLink;
use crate::diet_kind::{AtomDietKey, DietFileKind};
use crate::error::{DietError, DietResult};

/// The schema version this builder writes and the lowest it will accept. A
/// stored manifest below `MIN` is a downgrade; above `CURRENT` is unsupported.
pub const CURRENT_SCHEMA_VERSION: u16 = 1;
/// Minimum accepted manifest schema version.
pub const MIN_SCHEMA_VERSION: u16 = 1;

/// Whether a record's evidence set is complete enough to flow downstream.
/// Only `Complete` is ever reward-shaped; the others block reward.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
#[repr(u8)]
pub enum DietCompleteness {
    /// All 21 sidecar kinds present and consistent — may enter SFT/export.
    Complete = 1,
    /// A proper subset — may enter diagnostics but never earns reward.
    PartialNoReward = 2,
    /// An unknown/extra file or hard inconsistency — quarantined.
    Rejected = 3,
}

impl DietCompleteness {
    /// Numeric discriminant.
    pub const fn as_u8(self) -> u8 {
        self as u8
    }

    /// Parse from a discriminant; `None` if not `1..=3`.
    pub const fn from_u8(v: u8) -> Option<Self> {
        match v {
            1 => Some(Self::Complete),
            2 => Some(Self::PartialNoReward),
            3 => Some(Self::Rejected),
            _ => None,
        }
    }

    /// Whether this completeness state blocks all reward (partial/rejected do).
    /// Note `Complete` is *necessary, not sufficient* for reward — S1 reverify
    /// and privacy checks must also pass.
    pub const fn reward_blocked(self) -> bool {
        !matches!(self, Self::Complete)
    }
}

/// A content-addressed reference to one sidecar file.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub struct DietFileRef {
    /// Which of the 21 kinds this file is.
    pub kind: DietFileKind,
    /// `sha256` of the file's path (provenance of *where* it lives).
    pub path_hash_32: [u8; 32],
    /// `sha256` of the file's bytes (provenance of *what* it is).
    pub content_hash_32: [u8; 32],
    /// File length in bytes.
    pub bytes_u64: u64,
}

impl DietFileRef {
    /// Construct a file reference from its components.
    pub const fn new(
        kind: DietFileKind,
        path_hash_32: [u8; 32],
        content_hash_32: [u8; 32],
        bytes_u64: u64,
    ) -> Self {
        Self {
            kind,
            path_hash_32,
            content_hash_32,
            bytes_u64,
        }
    }
}

/// The per-atom manifest: a versioned, trace-stamped set of file refs
/// with a completeness verdict.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AtomDietManifest {
    /// Schema version (monotone; see [`CURRENT_SCHEMA_VERSION`]).
    pub schema_version_u16: u16,
    /// The source atom identity.
    pub key: AtomDietKey,
    /// The file references (any order; hashed in kind order).
    pub files: Vec<DietFileRef>,
    /// Completeness verdict for the file set.
    pub completeness: DietCompleteness,
    /// Stage E trace stamp.
    pub trace: StageETraceLink,
}

impl AtomDietManifest {
    /// Construct a manifest with an explicit schema version.
    pub fn new(
        schema_version_u16: u16,
        key: AtomDietKey,
        files: Vec<DietFileRef>,
        completeness: DietCompleteness,
        trace: StageETraceLink,
    ) -> Self {
        Self {
            schema_version_u16,
            key,
            files,
            completeness,
            trace,
        }
    }

    /// Construct a manifest stamped with [`CURRENT_SCHEMA_VERSION`].
    pub fn current(
        key: AtomDietKey,
        files: Vec<DietFileRef>,
        completeness: DietCompleteness,
        trace: StageETraceLink,
    ) -> Self {
        Self::new(CURRENT_SCHEMA_VERSION, key, files, completeness, trace)
    }

    /// Validate structural integrity: schema bounds, no duplicate kind, no empty
    /// hash, and `Complete`⇒all-21-present consistency.
    pub fn validate(&self) -> DietResult<()> {
        if self.schema_version_u16 < MIN_SCHEMA_VERSION {
            return Err(DietError::SchemaVersionDowngrade {
                got_u16: self.schema_version_u16,
                min_u16: MIN_SCHEMA_VERSION,
            });
        }
        if self.schema_version_u16 > CURRENT_SCHEMA_VERSION {
            return Err(DietError::SchemaVersionUnsupported {
                got_u16: self.schema_version_u16,
                max_u16: CURRENT_SCHEMA_VERSION,
            });
        }
        let mut seen = 0u32;
        for r in &self.files {
            let bit = 1u32 << (r.kind.as_u8() - 1);
            if seen & bit != 0 {
                return Err(DietError::DuplicateFileKind { kind: r.kind });
            }
            seen |= bit;
            if r.content_hash_32 == [0u8; 32] || r.path_hash_32 == [0u8; 32] {
                return Err(DietError::EmptyHash { kind: r.kind });
            }
        }
        if matches!(self.completeness, DietCompleteness::Complete) {
            for k in DietFileKind::ALL {
                if seen & (1u32 << (k.as_u8() - 1)) == 0 {
                    return Err(DietError::MissingRequiredFile { kind: k });
                }
            }
        }
        Ok(())
    }

    /// A deterministic `sha256` digest of the manifest. Files are encoded in
    /// kind order so the digest is independent of input ordering — the same
    /// evidence set always yields the same manifest hash.
    pub fn manifest_hash(&self) -> [u8; 32] {
        let mut sorted: Vec<&DietFileRef> = self.files.iter().collect();
        sorted.sort_by_key(|r| r.kind.as_u8());
        let mut buf: Vec<u8> = Vec::with_capacity(16 + sorted.len() * 73);
        buf.extend_from_slice(&self.schema_version_u16.to_le_bytes());
        buf.push(self.key.source.as_u8());
        buf.extend_from_slice(&self.key.atom_u16.to_le_bytes());
        buf.extend_from_slice(&(sorted.len() as u32).to_le_bytes());
        for r in sorted {
            buf.push(r.kind.as_u8());
            buf.extend_from_slice(&r.path_hash_32);
            buf.extend_from_slice(&r.content_hash_32);
            buf.extend_from_slice(&r.bytes_u64.to_le_bytes());
        }
        buf.push(self.completeness.as_u8());
        buf.extend_from_slice(&self.trace.source_trace_hash_32);
        buf.extend_from_slice(&self.trace.stage_e_atom_u16.to_le_bytes());
        buf.extend_from_slice(&self.trace.gate_id_u16.to_le_bytes());
        crate::sha256(&buf)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::diet_kind::DietSourceStage;

    fn key() -> AtomDietKey {
        AtomDietKey::new(DietSourceStage::StageD, 331)
    }

    fn trace() -> StageETraceLink {
        StageETraceLink::new([7u8; 32], 331, 1)
    }

    fn good_ref(kind: DietFileKind) -> DietFileRef {
        DietFileRef::new(kind, [1u8; 32], [2u8; 32], 64)
    }

    fn all_21() -> Vec<DietFileRef> {
        DietFileKind::ALL.into_iter().map(good_ref).collect()
    }

    #[test]
    fn complete_manifest_validates() -> DietResult<()> {
        let m = AtomDietManifest::current(key(), all_21(), DietCompleteness::Complete, trace());
        m.validate()
    }

    #[test]
    fn duplicate_kind_rejects() {
        let mut files = vec![
            good_ref(DietFileKind::EnvLock),
            good_ref(DietFileKind::EnvLock),
        ];
        files.push(good_ref(DietFileKind::CommandManifest));
        let m = AtomDietManifest::current(key(), files, DietCompleteness::PartialNoReward, trace());
        assert!(matches!(
            m.validate(),
            Err(DietError::DuplicateFileKind {
                kind: DietFileKind::EnvLock
            })
        ));
    }

    #[test]
    fn empty_hash_rejects() {
        let bad = DietFileRef::new(DietFileKind::EnvLock, [0u8; 32], [0u8; 32], 0);
        let m =
            AtomDietManifest::current(key(), vec![bad], DietCompleteness::PartialNoReward, trace());
        assert!(matches!(
            m.validate(),
            Err(DietError::EmptyHash {
                kind: DietFileKind::EnvLock
            })
        ));
    }

    #[test]
    fn schema_downgrade_and_unsupported_reject() {
        let m0 = AtomDietManifest::new(0, key(), all_21(), DietCompleteness::Complete, trace());
        assert!(matches!(
            m0.validate(),
            Err(DietError::SchemaVersionDowngrade {
                got_u16: 0,
                min_u16: 1
            })
        ));
        let m2 = AtomDietManifest::new(2, key(), all_21(), DietCompleteness::Complete, trace());
        assert!(matches!(
            m2.validate(),
            Err(DietError::SchemaVersionUnsupported {
                got_u16: 2,
                max_u16: 1
            })
        ));
    }

    #[test]
    fn complete_claim_missing_required_rejects() {
        let files = vec![good_ref(DietFileKind::EnvLock)];
        let m = AtomDietManifest::current(key(), files, DietCompleteness::Complete, trace());
        assert!(matches!(
            m.validate(),
            Err(DietError::MissingRequiredFile { .. })
        ));
    }

    #[test]
    fn manifest_hash_is_order_independent_and_stable() {
        let forward =
            AtomDietManifest::current(key(), all_21(), DietCompleteness::Complete, trace());
        let mut rev_files = all_21();
        rev_files.reverse();
        let reversed =
            AtomDietManifest::current(key(), rev_files, DietCompleteness::Complete, trace());
        assert_eq!(forward.manifest_hash(), reversed.manifest_hash());
        // A content change flips the digest.
        let mut changed = all_21();
        changed[0] = DietFileRef::new(DietFileKind::InputContext, [9u8; 32], [9u8; 32], 1);
        let other = AtomDietManifest::current(key(), changed, DietCompleteness::Complete, trace());
        assert_ne!(forward.manifest_hash(), other.manifest_hash());
    }

    #[test]
    fn reward_blocked_only_for_non_complete() {
        assert!(!DietCompleteness::Complete.reward_blocked());
        assert!(DietCompleteness::PartialNoReward.reward_blocked());
        assert!(DietCompleteness::Rejected.reward_blocked());
    }
}
