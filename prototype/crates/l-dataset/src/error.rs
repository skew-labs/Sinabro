//! Stage E dataset error taxonomy.
//!
//! # Rationale
//!
//! A [`DietError`] is a `Copy`, heap-free, fixed-width value. Every variant
//! carries only plain scalar metadata — a [`DietFileKind`], a count, a static
//! `&'static str` field label, a byte offset — and **never** a slice of the
//! file being parsed. This mirrors the `a-core` source-redaction spine: a
//! canary secret living in a malformed sidecar can never escape through the
//! error channel into `Debug`, `Display`, or `Error::source` (which is always
//! `None`). The only human-readable strings are compile-time `&'static` labels.
use crate::diet_kind::DietFileKind;

/// Crate result alias: every fallible Stage E dataset API returns this.
pub type DietResult<T> = core::result::Result<T, DietError>;

/// A Stage E dataset error: `Copy`, allocation-free, and secret-free by
/// construction (no variant can hold a raw file byte, only fixed scalars).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum DietError {
    /// A file name was not one of the 21 closed sidecar kinds.
    UnknownFileKind,
    /// The same [`DietFileKind`] appeared twice in one manifest.
    DuplicateFileKind {
        /// The kind that was duplicated.
        kind: DietFileKind,
    },
    /// A required sidecar file was absent from the atom directory.
    MissingRequiredFile {
        /// The kind that was missing.
        kind: DietFileKind,
    },
    /// A required JSON field was absent. `field` is a compile-time label.
    MissingField {
        /// The file kind being parsed.
        kind: DietFileKind,
        /// Static name of the missing field.
        field: &'static str,
    },
    /// A JSON field was present but of the wrong type.
    UnexpectedType {
        /// The file kind being parsed.
        kind: DietFileKind,
        /// Static name of the mistyped field.
        field: &'static str,
    },
    /// `serde_json` rejected the document; only line/column are retained.
    MalformedJson {
        /// The file kind being parsed.
        kind: DietFileKind,
        /// 1-based line of the syntax error.
        line_u32: u32,
        /// 1-based column of the syntax error.
        column_u32: u32,
    },
    /// A JSONL record line failed to parse (1-based record index).
    MalformedJsonl {
        /// The file kind being parsed.
        kind: DietFileKind,
        /// 1-based record index that failed.
        record_u32: u32,
    },
    /// A JSONL file that must be non-empty had zero records.
    EmptyJsonl {
        /// The empty file kind.
        kind: DietFileKind,
    },
    /// A hex hash string was not exactly 64 characters.
    InvalidHexLength {
        /// Actual character count.
        got_u32: u32,
    },
    /// A hex hash string had a non-hex byte at this 0-based position.
    InvalidHexChar {
        /// 0-based position of the offending byte.
        at_u32: u32,
    },
    /// A hash field was present but empty.
    EmptyHash {
        /// The file kind whose hash was empty.
        kind: DietFileKind,
    },
    /// A computed content hash did not match the stored hash.
    HashMismatch {
        /// The file kind whose hash drifted.
        kind: DietFileKind,
    },
    /// The manifest schema version is older than the minimum supported.
    SchemaVersionDowngrade {
        /// Version seen.
        got_u16: u16,
        /// Minimum accepted version.
        min_u16: u16,
    },
    /// The manifest schema version is newer than this builder supports.
    SchemaVersionUnsupported {
        /// Version seen.
        got_u16: u16,
        /// Maximum supported version.
        max_u16: u16,
    },
    /// Discovery found a symlink that escapes the training root.
    SymlinkEscape,
    /// A path component attempted directory traversal (`..`).
    PathTraversal,
    /// A redaction check found secret-like residue. The residue is never stored.
    SecretResidue {
        /// The file kind in which residue was found.
        kind: DietFileKind,
    },
    /// A privacy report was internally inconsistent (e.g. `Pass` with hits > 0).
    PrivacyInconsistent {
        /// The file kind whose report was inconsistent.
        kind: DietFileKind,
    },
    /// A required 5-review axis was missing. `axis` is a compile-time label.
    ReviewAxisMissing {
        /// Static name of the missing axis.
        axis: &'static str,
    },
    /// A code diff was binary (no textual unified-diff body).
    BinaryDiffRejected,
    /// A code diff lacked the unified-diff `---`/`+++` headers.
    MalformedPatch,
    /// An underlying I/O read failed; the path/cause is redacted.
    IoUntrusted {
        /// The file kind whose read failed.
        kind: DietFileKind,
    },
    /// A discovery-time directory/symlink read failed; the path is redacted.
    DiscoveryIo,
    /// A record/field count exceeded a defensive upper bound.
    CountOverflow,
    /// A security source tag was not one of the closed source classes.
    UnknownSecuritySource,
    /// A required evidence anchor (audit finding / exploit repro) was absent.
    MissingEvidence {
        /// The file kind whose evidence was missing.
        kind: DietFileKind,
    },
    /// A MURPHY parent chain formed a cycle (not an acyclic forest).
    MurphyCycle,
    /// A MURPHY node referenced a parent absent from the node set.
    MurphyBrokenChain {
        /// The node whose parent reference is dangling.
        node_id_u64: u64,
    },
    /// Two MURPHY nodes shared the same node id.
    MurphyDuplicateNode {
        /// The duplicated node id.
        node_id_u64: u64,
    },
    /// Two preference candidates had equal rank and cannot form a pair.
    PreferenceEqualPair,
    /// An SFT sample exceeded the per-sample token budget.
    SftTokenBudgetExceeded {
        /// The estimated token count that exceeded the budget.
        tokens_u32: u32,
    },
    /// A leakage group was assigned to two different splits.
    SplitLeakageDetected,
    /// A shard's recomputed signer hash did not match its manifest (tamper).
    ShardSignatureMismatch,
    /// A shard's recomputed merkle root did not match its manifest (tamper).
    ShardMerkleMismatch,
    /// A shard candidate carried a secret / PII residue at post-write scan.
    ShardPiiResidue,
    /// An evidence-lake receipt was not training-eligible (Stage E is always
    /// `false`), so no training shard may be promoted from it.
    TrainingIneligible,
    /// A remote archive locator was present without a local CAS root — a remote
    /// locator can never bypass the local content-addressed store.
    RemoteLocatorBypass,
    /// A record claimed reward eligibility without an S1 ground-truth reverify.
    RewardProvenanceViolation,
    /// A duplicate record was found during the final quality filter.
    QualityDuplicate,
    /// A streamed shard write to the output sink failed; the cause is redacted.
    ShardIo,
    /// A context/harness/self-evolution quality signal lacked its evidence
    /// anchor (an all-zero hash) — no "prompt vibes" record may be minted.
    QualitySignalUnbacked,
    /// A context-quality basis-point axis exceeded 100% (`10_000` bps).
    QualityAxisOutOfRange,
    /// A self-evolution candidate left a promotion guard off or allowed
    /// authority expansion (it could promote, mutate production, or widen its
    /// own authority) — forbidden in Stage E.
    SelfEvolutionAuthorityWidened,
}

impl DietError {
    /// The sidecar file kind this error concerns, when applicable.
    pub const fn file_kind(&self) -> Option<DietFileKind> {
        match *self {
            DietError::DuplicateFileKind { kind }
            | DietError::MissingRequiredFile { kind }
            | DietError::MissingField { kind, .. }
            | DietError::UnexpectedType { kind, .. }
            | DietError::MalformedJson { kind, .. }
            | DietError::MalformedJsonl { kind, .. }
            | DietError::EmptyJsonl { kind }
            | DietError::EmptyHash { kind }
            | DietError::HashMismatch { kind }
            | DietError::SecretResidue { kind }
            | DietError::PrivacyInconsistent { kind }
            | DietError::MissingEvidence { kind }
            | DietError::IoUntrusted { kind } => Some(kind),
            _ => None,
        }
    }
}

impl core::fmt::Display for DietError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            DietError::UnknownFileKind => {
                f.write_str("file name is not one of the 21 sidecar kinds")
            }
            DietError::DuplicateFileKind { kind } => {
                write!(f, "duplicate sidecar file kind {kind:?}")
            }
            DietError::MissingRequiredFile { kind } => {
                write!(f, "missing required sidecar file {kind:?}")
            }
            DietError::MissingField { kind, field } => {
                write!(f, "missing field '{field}' in {kind:?}")
            }
            DietError::UnexpectedType { kind, field } => {
                write!(f, "field '{field}' has unexpected type in {kind:?}")
            }
            DietError::MalformedJson {
                kind,
                line_u32,
                column_u32,
            } => {
                write!(
                    f,
                    "malformed json in {kind:?} at line {line_u32} column {column_u32}"
                )
            }
            DietError::MalformedJsonl { kind, record_u32 } => {
                write!(f, "malformed jsonl record {record_u32} in {kind:?}")
            }
            DietError::EmptyJsonl { kind } => write!(f, "jsonl file {kind:?} has zero records"),
            DietError::InvalidHexLength { got_u32 } => {
                write!(f, "hex hash is {got_u32} chars, expected 64")
            }
            DietError::InvalidHexChar { at_u32 } => {
                write!(f, "non-hex character at position {at_u32}")
            }
            DietError::EmptyHash { kind } => write!(f, "empty hash field in {kind:?}"),
            DietError::HashMismatch { kind } => write!(f, "content hash mismatch for {kind:?}"),
            DietError::SchemaVersionDowngrade { got_u16, min_u16 } => {
                write!(f, "schema version {got_u16} below minimum {min_u16}")
            }
            DietError::SchemaVersionUnsupported { got_u16, max_u16 } => {
                write!(f, "schema version {got_u16} above supported {max_u16}")
            }
            DietError::SymlinkEscape => f.write_str("symlink escapes the training root"),
            DietError::PathTraversal => f.write_str("path traversal component rejected"),
            DietError::SecretResidue { kind } => {
                write!(f, "secret-like residue detected in {kind:?}")
            }
            DietError::PrivacyInconsistent { kind } => {
                write!(f, "privacy report inconsistent in {kind:?}")
            }
            DietError::ReviewAxisMissing { axis } => write!(f, "5-review axis '{axis}' missing"),
            DietError::BinaryDiffRejected => f.write_str("binary diff rejected"),
            DietError::MalformedPatch => f.write_str("patch lacks unified-diff headers"),
            DietError::IoUntrusted { kind } => write!(f, "i/o read failed for {kind:?} (redacted)"),
            DietError::DiscoveryIo => f.write_str("discovery i/o read failed (redacted)"),
            DietError::CountOverflow => f.write_str("record/field count exceeded defensive bound"),
            DietError::UnknownSecuritySource => {
                f.write_str("security source tag is not a known class")
            }
            DietError::MissingEvidence { kind } => {
                write!(f, "required evidence absent in {kind:?}")
            }
            DietError::MurphyCycle => f.write_str("murphy parent chain forms a cycle"),
            DietError::MurphyBrokenChain { node_id_u64 } => {
                write!(f, "murphy node {node_id_u64} references a missing parent")
            }
            DietError::MurphyDuplicateNode { node_id_u64 } => {
                write!(f, "murphy duplicate node id {node_id_u64}")
            }
            DietError::PreferenceEqualPair => f.write_str("preference candidates have equal rank"),
            DietError::SftTokenBudgetExceeded { tokens_u32 } => {
                write!(f, "sft sample {tokens_u32} tokens exceeds budget")
            }
            DietError::SplitLeakageDetected => f.write_str("leakage group straddles two splits"),
            DietError::ShardSignatureMismatch => f.write_str("shard signer hash mismatch (tamper)"),
            DietError::ShardMerkleMismatch => f.write_str("shard merkle root mismatch (tamper)"),
            DietError::ShardPiiResidue => f.write_str("shard candidate carries secret/pii residue"),
            DietError::TrainingIneligible => {
                f.write_str("evidence-lake receipt is not training-eligible")
            }
            DietError::RemoteLocatorBypass => {
                f.write_str("remote archive locator without a local cas root")
            }
            DietError::RewardProvenanceViolation => {
                f.write_str("reward claimed without an s1 ground-truth reverify")
            }
            DietError::QualityDuplicate => f.write_str("duplicate record in quality filter"),
            DietError::ShardIo => f.write_str("shard write to output sink failed (redacted)"),
            DietError::QualitySignalUnbacked => {
                f.write_str("quality/self-evolution signal lacks an evidence anchor")
            }
            DietError::QualityAxisOutOfRange => {
                f.write_str("context-quality axis exceeds 10000 bps")
            }
            DietError::SelfEvolutionAuthorityWidened => {
                f.write_str("self-evolution candidate widens authority or skips a guard")
            }
        }
    }
}

impl std::error::Error for DietError {
    /// Always `None`: the raw source is never retained, so the error chain
    /// terminates here and cannot leak a nested cause.
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn diet_error_is_copy_and_bounded() {
        fn assert_copy<T: Copy>() {}
        assert_copy::<DietError>();
        // Bounded fixed-width value: the widest payload is one `&'static str`
        // (a static pointer+len into rodata, never a heap string), so no
        // variant can own a secret. 40 bytes is generous headroom.
        assert!(core::mem::size_of::<DietError>() <= 40);
    }

    #[test]
    fn display_is_bounded_and_secret_free() {
        let canary = "CANARY-7f3a9b-do-not-leak";
        let cases = [
            DietError::UnknownFileKind,
            DietError::DuplicateFileKind {
                kind: DietFileKind::CommandManifest,
            },
            DietError::MissingField {
                kind: DietFileKind::EnvLock,
                field: "rust",
            },
            DietError::MalformedJson {
                kind: DietFileKind::PrivacyReport,
                line_u32: 3,
                column_u32: 9,
            },
            DietError::HashMismatch {
                kind: DietFileKind::CodeDiff,
            },
            DietError::SecretResidue {
                kind: DietFileKind::TerminalRedacted,
            },
            DietError::PrivacyInconsistent {
                kind: DietFileKind::PrivacyReport,
            },
            DietError::ReviewAxisMissing { axis: "security" },
            DietError::SchemaVersionDowngrade {
                got_u16: 0,
                min_u16: 1,
            },
        ];
        for e in cases.iter() {
            let msg = format!("{e}");
            assert!(!msg.contains(canary));
            assert!(msg.len() <= 96);
        }
        assert!(std::error::Error::source(&DietError::UnknownFileKind).is_none());
    }

    #[test]
    fn file_kind_accessor_maps_known_variants() {
        assert_eq!(
            DietError::HashMismatch {
                kind: DietFileKind::EnvLock
            }
            .file_kind(),
            Some(DietFileKind::EnvLock)
        );
        assert_eq!(DietError::UnknownFileKind.file_kind(), None);
        assert_eq!(DietError::SymlinkEscape.file_kind(), None);
    }
}
