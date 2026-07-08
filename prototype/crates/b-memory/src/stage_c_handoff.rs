//! Stage C ← A+B handoff digest.
//!
//! Canonical OUT: [`StageCHandoffDigest`]. The companion trace
//! type [`StageCTraceLink`](mnemos_a_core::trace::StageCTraceLink) lives in the
//! dependency root `a-core` (so the low gas/evidence crates can compose it);
//! this module owns only the handoff digest, which embeds the Stage B
//! [`StageBTranscriptHash32`] and therefore stays in `b-memory`.
//!
//! # Invariants
//!
//! * **C starts only from A+B green evidence.** The digest pins five Stage A/B
//!   evidence hashes: the Stage A atom plan, the Stage B atom plan, the Stage B
//!   DoD, the Stage B replay transcript, and the canonical-reuse table. Four
//!   are raw 32-byte hashes; an all-zero slot is the "evidence missing"
//!   sentinel (mirroring `StageAHandoffDigest` in
//!   [`stage_b_handoff`](crate::stage_b_handoff)).
//!   [`missing_evidence_mask`](StageCHandoffDigest::missing_evidence_mask)
//!   reports exactly which raw slots are still the sentinel, and the gate layer
//!   refuses to start Stage C while that mask is non-zero.
//! * **The transcript is structurally present.** The
//!   [`StageBTranscriptHash32`] field is a non-optional, non-mintable value
//!   (it can only come from a real Stage B replay), so "no B transcript" is
//!   unrepresentable — a `StageCHandoffDigest` cannot be built without one.
//! * **No re-mint.** The transcript reuses the Stage B canonical type verbatim;
//!   no second transcript-hash newtype is introduced.

use crate::stage_b_replay::StageBTranscriptHash32;

/// `const`-evaluable "is this 32-byte hash the all-zero sentinel?" check.
/// Hand-rolled byte loop because `[u8; 32]: PartialEq` is not usable in a
/// `const fn` context on this toolchain.
#[inline]
const fn is_zero_hash(h: &[u8; 32]) -> bool {
    let mut i = 0;
    while i < 32 {
        if h[i] != 0 {
            return false;
        }
        i += 1;
    }
    true
}

/// Number of raw (all-zero-sentinel) evidence slots in a
/// [`StageCHandoffDigest`]. The transcript slot is excluded because it is
/// structurally always present (non-mintable). Drives the
/// [`missing_evidence_mask`](StageCHandoffDigest::missing_evidence_mask) width.
pub const STAGE_C_HANDOFF_RAW_SLOT_COUNT: usize = 4;

/// Total serialized byte length of a [`StageCHandoffDigest`]: the four raw
/// 32-byte hashes plus the 32-byte transcript hash.
pub const STAGE_C_HANDOFF_DIGEST_BYTES: usize = (STAGE_C_HANDOFF_RAW_SLOT_COUNT + 1) * 32;

/// The frozen Stage A+B → Stage C evidence digest.
///
/// Each raw field is a 32-byte hash; an all-zero raw field means "this evidence
/// is missing" and blocks the start of Stage C (see
/// [`missing_evidence_mask`](Self::missing_evidence_mask)). The transcript field
/// reuses the Stage B [`StageBTranscriptHash32`] verbatim.
///
/// Fields are `pub`. The byte order used by [`to_bytes`](Self::to_bytes)
/// and by the missing-evidence bitmask is exactly the declaration order below
/// (bit 0 = `atom_plan_a_hash_32` … bit 3 = `canonical_reuse_hash_32`).
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub struct StageCHandoffDigest {
    /// Hash of the Stage A atom plan.
    pub atom_plan_a_hash_32: [u8; 32],
    /// Hash of the Stage B atom plan.
    pub stage_b_plan_hash_32: [u8; 32],
    /// Hash of the Stage B Definition-of-Done evidence.
    pub stage_b_dod_hash_32: [u8; 32],
    /// The Stage B replay transcript hash (deterministic custody root).
    pub stage_b_transcript_hash: StageBTranscriptHash32,
    /// Hash of the A↔B canonical-reuse table.
    pub canonical_reuse_hash_32: [u8; 32],
}

impl StageCHandoffDigest {
    /// Bitmask of raw evidence slots still set to the all-zero sentinel. Bit 0
    /// is `atom_plan_a_hash_32`, bit 1 `stage_b_plan_hash_32`, bit 2
    /// `stage_b_dod_hash_32`, bit 3 `canonical_reuse_hash_32`. A non-zero mask
    /// means Stage C must not start.
    #[inline]
    pub const fn missing_evidence_mask(&self) -> u8 {
        let mut mask = 0u8;
        if is_zero_hash(&self.atom_plan_a_hash_32) {
            mask |= 1 << 0;
        }
        if is_zero_hash(&self.stage_b_plan_hash_32) {
            mask |= 1 << 1;
        }
        if is_zero_hash(&self.stage_b_dod_hash_32) {
            mask |= 1 << 2;
        }
        if is_zero_hash(&self.canonical_reuse_hash_32) {
            mask |= 1 << 3;
        }
        mask
    }

    /// Whether every raw evidence slot is populated (mask == 0). The transcript
    /// is always present by construction.
    #[inline]
    pub const fn is_complete(&self) -> bool {
        self.missing_evidence_mask() == 0
    }

    /// Serialize the digest to its fixed [`STAGE_C_HANDOFF_DIGEST_BYTES`] byte
    /// form in declaration order: the four raw hashes followed by the 32-byte
    /// transcript hash.
    #[inline]
    pub fn to_bytes(&self) -> [u8; STAGE_C_HANDOFF_DIGEST_BYTES] {
        let mut out = [0u8; STAGE_C_HANDOFF_DIGEST_BYTES];
        out[0..32].copy_from_slice(&self.atom_plan_a_hash_32);
        out[32..64].copy_from_slice(&self.stage_b_plan_hash_32);
        out[64..96].copy_from_slice(&self.stage_b_dod_hash_32);
        out[96..128].copy_from_slice(self.stage_b_transcript_hash.as_bytes());
        out[128..160].copy_from_slice(&self.canonical_reuse_hash_32);
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::stage_b_replay::stage_b_transcript_hash;

    fn real_transcript() -> StageBTranscriptHash32 {
        // A real (non-zero) transcript hash from the Stage B canonical hasher.
        stage_b_transcript_hash(b"c-wp-01 atom 171 handoff fixture")
    }

    #[test]
    fn complete_digest_has_zero_missing_mask() {
        let d = StageCHandoffDigest {
            atom_plan_a_hash_32: [1u8; 32],
            stage_b_plan_hash_32: [2u8; 32],
            stage_b_dod_hash_32: [3u8; 32],
            stage_b_transcript_hash: real_transcript(),
            canonical_reuse_hash_32: [4u8; 32],
        };
        assert_eq!(d.missing_evidence_mask(), 0);
        assert!(d.is_complete());
    }

    #[test]
    fn missing_a_evidence_is_rejected() {
        let d = StageCHandoffDigest {
            atom_plan_a_hash_32: [0u8; 32], // missing
            stage_b_plan_hash_32: [2u8; 32],
            stage_b_dod_hash_32: [3u8; 32],
            stage_b_transcript_hash: real_transcript(),
            canonical_reuse_hash_32: [4u8; 32],
        };
        assert_eq!(d.missing_evidence_mask() & (1 << 0), 1 << 0);
        assert!(!d.is_complete());
    }

    #[test]
    fn missing_b_dod_is_rejected() {
        let d = StageCHandoffDigest {
            atom_plan_a_hash_32: [1u8; 32],
            stage_b_plan_hash_32: [2u8; 32],
            stage_b_dod_hash_32: [0u8; 32], // missing
            stage_b_transcript_hash: real_transcript(),
            canonical_reuse_hash_32: [4u8; 32],
        };
        assert_eq!(d.missing_evidence_mask() & (1 << 2), 1 << 2);
        assert!(!d.is_complete());
    }

    #[test]
    fn to_bytes_pins_declaration_order_and_width() {
        let t = real_transcript();
        let d = StageCHandoffDigest {
            atom_plan_a_hash_32: [0xA1; 32],
            stage_b_plan_hash_32: [0xB2; 32],
            stage_b_dod_hash_32: [0xD0; 32],
            stage_b_transcript_hash: t,
            canonical_reuse_hash_32: [0xCE; 32],
        };
        let bytes = d.to_bytes();
        assert_eq!(bytes.len(), 160);
        assert_eq!(&bytes[0..32], &[0xA1u8; 32]);
        assert_eq!(&bytes[32..64], &[0xB2u8; 32]);
        assert_eq!(&bytes[64..96], &[0xD0u8; 32]);
        assert_eq!(&bytes[96..128], t.as_bytes());
        assert_eq!(&bytes[128..160], &[0xCEu8; 32]);
    }

    #[test]
    fn zero_hash_sentinel_detection() {
        assert!(is_zero_hash(&[0u8; 32]));
        assert!(!is_zero_hash(&[1u8; 32]));
        let mut almost = [0u8; 32];
        almost[31] = 1;
        assert!(!is_zero_hash(&almost));
    }
}
