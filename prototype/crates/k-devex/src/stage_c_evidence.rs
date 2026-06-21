//! Stage C evidence bundle index ref (C-WP-01 · atom #177 · C.0.6).
//!
//! Canonical OUT (§4.0): [`StageCEvidenceRef`].
//!
//! # Madness invariants (atom #177)
//!
//! * **Every gate output has a content hash and a trace.** A
//!   [`StageCEvidenceRef`] binds the 32-byte content hash of an evidence file
//!   to a [`StageCTraceLink`]. There are no orphan screenshots and no
//!   unhashable claims: a ref cannot exist without both a hash and a trace.
//! * **Missing file and hash mismatch are distinct rejections.**
//!   [`StageCEvidenceRef::check`] reports
//!   [`Missing`](StageCEvidenceCheck::Missing) when the file is absent and
//!   [`HashMismatch`](StageCEvidenceCheck::HashMismatch) when its content hash
//!   does not match the recorded one — only
//!   [`Match`](StageCEvidenceCheck::Match) accepts the evidence.
//! * **No re-mint.** The trace reuses the §4.0 [`StageCTraceLink`] (atom #171);
//!   no parallel trace type is introduced.
//!
//! Reuse is conceptual for "A logging": these refs are the content-addressed
//! anchors the a-core logging / trace surface points at. The hashing itself is
//! done by the evidence producer; this type stores and verifies the result.

use mnemos_a_core::trace::StageCTraceLink;

/// Fixed serialized byte width of a [`StageCEvidenceRef`]: `32` (path hash) +
/// `15` (trace: `8 + 2 + 1 + 2 + 2`).
pub const STAGE_C_EVIDENCE_REF_BYTES: usize = 47;

/// A content-addressed reference to one Stage C evidence file (§4.0).
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub struct StageCEvidenceRef {
    /// 32-byte content hash of the evidence file.
    pub path_hash_32: [u8; 32],
    /// The Stage C trace stamp that produced the evidence.
    pub trace: StageCTraceLink,
}

/// The verdict of checking a [`StageCEvidenceRef`] against an actual file.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
#[repr(u8)]
pub enum StageCEvidenceCheck {
    /// The file is present and its content hash matches the recorded one.
    Match = 1,
    /// The file is absent.
    Missing = 2,
    /// The file is present but its content hash does not match.
    HashMismatch = 3,
}

impl StageCEvidenceRef {
    /// Build an evidence ref from a content hash and a trace.
    #[inline]
    pub const fn new(path_hash_32: [u8; 32], trace: StageCTraceLink) -> Self {
        Self {
            path_hash_32,
            trace,
        }
    }

    /// Check this ref against an actual file's content hash.
    ///
    /// `actual_file_hash` is `None` when the file is absent (→
    /// [`Missing`](StageCEvidenceCheck::Missing)), or `Some(hash)` of the
    /// file's content (→ [`Match`](StageCEvidenceCheck::Match) /
    /// [`HashMismatch`](StageCEvidenceCheck::HashMismatch)). The hashing is the
    /// caller's responsibility; this verifier only compares.
    #[inline]
    pub fn check(&self, actual_file_hash: Option<&[u8; 32]>) -> StageCEvidenceCheck {
        match actual_file_hash {
            None => StageCEvidenceCheck::Missing,
            Some(h) if *h == self.path_hash_32 => StageCEvidenceCheck::Match,
            Some(_) => StageCEvidenceCheck::HashMismatch,
        }
    }

    /// Serialize to the fixed [`STAGE_C_EVIDENCE_REF_BYTES`] byte form:
    /// `path_hash_32 ‖ trace_id_u64 ‖ atom_id_u16 ‖ attempt_u8 ‖
    /// stage_c_atom_u16 ‖ gate_id_u16` (little-endian integers).
    pub fn to_bytes(&self) -> [u8; STAGE_C_EVIDENCE_REF_BYTES] {
        let mut out = [0u8; STAGE_C_EVIDENCE_REF_BYTES];
        out[0..32].copy_from_slice(&self.path_hash_32);
        out[32..40].copy_from_slice(&self.trace.trace.trace_id_u64.to_le_bytes());
        out[40..42].copy_from_slice(&self.trace.trace.atom_id_u16.to_le_bytes());
        out[42] = self.trace.trace.attempt_u8;
        out[43..45].copy_from_slice(&self.trace.stage_c_atom_u16.to_le_bytes());
        out[45..47].copy_from_slice(&self.trace.gate_id_u16.to_le_bytes());
        out
    }

    /// Parse a ref from its fixed [`STAGE_C_EVIDENCE_REF_BYTES`] byte form,
    /// inverting [`to_bytes`](Self::to_bytes) exactly.
    pub fn from_bytes(bytes: &[u8; STAGE_C_EVIDENCE_REF_BYTES]) -> Self {
        let mut path_hash_32 = [0u8; 32];
        path_hash_32.copy_from_slice(&bytes[0..32]);
        let mut trace_id = [0u8; 8];
        trace_id.copy_from_slice(&bytes[32..40]);
        let mut atom_id = [0u8; 2];
        atom_id.copy_from_slice(&bytes[40..42]);
        let attempt = bytes[42];
        let mut stage_c_atom = [0u8; 2];
        stage_c_atom.copy_from_slice(&bytes[43..45]);
        let mut gate_id = [0u8; 2];
        gate_id.copy_from_slice(&bytes[45..47]);
        let trace = StageCTraceLink::new(
            mnemos_a_core::trace::StageBTraceLink::new(
                u64::from_le_bytes(trace_id),
                u16::from_le_bytes(atom_id),
                attempt,
            ),
            u16::from_le_bytes(stage_c_atom),
            u16::from_le_bytes(gate_id),
        );
        Self::new(path_hash_32, trace)
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]
    use super::*;
    use mnemos_a_core::trace::StageBTraceLink;

    fn ref_fixture() -> StageCEvidenceRef {
        StageCEvidenceRef::new(
            [0xE1; 32],
            StageCTraceLink::new(StageBTraceLink::new(0xA177, 177, 0), 177, 4),
        )
    }

    #[test]
    fn evidence_ref_parse_roundtrips() {
        let r = ref_fixture();
        let bytes = r.to_bytes();
        assert_eq!(bytes.len(), STAGE_C_EVIDENCE_REF_BYTES);
        assert_eq!(bytes.len(), 47);
        assert_eq!(StageCEvidenceRef::from_bytes(&bytes), r);
    }

    #[test]
    fn missing_file_is_rejected() {
        let r = ref_fixture();
        assert_eq!(r.check(None), StageCEvidenceCheck::Missing);
    }

    #[test]
    fn hash_mismatch_is_rejected_and_match_is_accepted() {
        let r = ref_fixture();
        assert_eq!(r.check(Some(&[0xE1; 32])), StageCEvidenceCheck::Match);
        assert_eq!(
            r.check(Some(&[0x00; 32])),
            StageCEvidenceCheck::HashMismatch
        );
        let mut almost = [0xE1u8; 32];
        almost[0] = 0xE0;
        assert_eq!(r.check(Some(&almost)), StageCEvidenceCheck::HashMismatch);
    }
}
