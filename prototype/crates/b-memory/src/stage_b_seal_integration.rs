//! atom #159 · B.4.13 — Seal stub integration with the signed chunk.
//!
//! ATOM_PLAN line 1325-1334 canonical OUT — the signed-chunk constructor path
//! checks the Seal stub policy. The madness line: "chunk signing cannot
//! accidentally bless private publish. Fixture-only, no live egress;
//! same-message approval required for any live path, none in Stage B" (line
//! 1329). This module is the seam where the atom #158 f-seal Seal-stub envelope
//! mapping meets the atom #90 signed chunk and the atom #83 chunk flags: a
//! private or secret content class is rejected **before** a publish plan can
//! form, and an envelope's `seal_stubbed` marker must agree with the chunk's
//! [`StageBChunkFlags::SealStubbed`] bit.
//!
//! Canonical IN:
//! - f-seal [`stage_b_seal_envelope`] (atom #158) — the content-class → envelope
//!   decision, reused verbatim (the edge `b-memory -> f-seal` is one-way).
//! - [`StageBChunkFlags`](crate::chunk_schema::StageBChunkFlags) (atom #83) — the
//!   chunk flag bitset carrying `SealStubbed = 4`.
//!
//! No new [`StageBChunkError`](crate::StageBChunkError) variant is minted (that
//! enum is frozen `#[non_exhaustive]`); the Seal-stub denial is surfaced as the
//! f-seal [`StageBSealStubError`].

use mnemos_c_walrus::PublishPayloadClass;
use mnemos_f_seal::{
    Capability, StageBSealStubEnvelope, StageBSealStubError, StageBSealStubPolicy,
    stage_b_seal_envelope,
};

use crate::chunk_schema::StageBChunkFlags;

/// Guard the publish-plan boundary for a signed chunk of content class `class`.
///
/// Returns the atom #158 [`StageBSealStubEnvelope`] when the class is admissible
/// under `policy` (and, for user-owned public memory, `owner_signed`), or the
/// f-seal [`StageBSealStubError`] otherwise. A private or secret class returns
/// `Err`, so a signed chunk of that class **cannot become a publish plan** — the
/// gate fails closed before any Walrus planner is reached.
///
/// This is the single Stage B seam through which a signed chunk reaches the
/// publish boundary; it reuses the f-seal decision rather than re-deriving the
/// policy, so the chunk path and the Seal path can never disagree.
#[inline]
pub fn stage_b_seal_publish_plan_guard(
    class: PublishPayloadClass,
    capability: Capability,
    owner_signed: bool,
    policy: StageBSealStubPolicy,
) -> Result<StageBSealStubEnvelope, StageBSealStubError> {
    stage_b_seal_envelope(class, capability, owner_signed, policy)
}

/// Whether a Seal-stub `envelope` is consistent with a chunk's `flags_u8`
/// bitset.
///
/// The invariant: an envelope minted through the Stage B stub path carries
/// `seal_stubbed == true`, and a signed chunk that is wrapped by the Seal stub
/// must carry the [`StageBChunkFlags::SealStubbed`] bit in its `flags_u8`.
/// Consistency holds iff the envelope's stub marker equals the presence of that
/// bit. A `true` envelope with the bit unset (or vice versa) is a drift between
/// the Seal surface and the chunk header and returns `false`.
#[inline]
pub fn seal_stubbed_flag_consistent(envelope: &StageBSealStubEnvelope, flags_u8: u8) -> bool {
    let bit_set = StageBChunkFlags::is_set(flags_u8, StageBChunkFlags::SealStubbed);
    envelope.is_seal_stubbed() == bit_set
}

#[cfg(test)]
mod tests {
    // Test helpers prefer direct failure surfaces (`expect`) over `Result`
    // bubbling; suppress prod-only clippy denies inside this module (b-memory
    // #86/#88/#89 precedent).
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use super::*;
    use mnemos_d_move::SuiAddress;
    use mnemos_f_seal::CapabilityKind;

    fn owner_cap() -> Capability {
        Capability::new(CapabilityKind::WriteMemory, SuiAddress::new([0x11u8; 32]))
    }

    /// test #1 (private chunk cannot become publish plan): a private-provenance
    /// or real-user-memory chunk is rejected at the guard under the default
    /// policy, so no publish plan can be formed from it.
    #[test]
    fn b4_13_private_chunk_cannot_become_publish_plan() {
        let policy = StageBSealStubPolicy::default_testnet();
        assert_eq!(
            stage_b_seal_publish_plan_guard(
                PublishPayloadClass::PrivateProvenance,
                owner_cap(),
                true,
                policy,
            ),
            Err(StageBSealStubError::PrivatePublishDenied)
        );
        assert_eq!(
            stage_b_seal_publish_plan_guard(
                PublishPayloadClass::RealUserMemory,
                owner_cap(),
                true,
                policy,
            ),
            Err(StageBSealStubError::PrivatePublishDenied)
        );
        // The one admissible class does form an envelope.
        assert!(
            stage_b_seal_publish_plan_guard(
                PublishPayloadClass::SyntheticPublicFixture,
                owner_cap(),
                false,
                policy,
            )
            .is_ok()
        );
    }

    /// test #2 (seal_stubbed flag consistency): a stub envelope agrees with a
    /// `flags_u8` carrying the `SealStubbed` bit and disagrees with one that does
    /// not.
    #[test]
    fn b4_13_seal_stubbed_flag_consistency() {
        let env = stage_b_seal_publish_plan_guard(
            PublishPayloadClass::SyntheticPublicFixture,
            owner_cap(),
            false,
            StageBSealStubPolicy::default_testnet(),
        )
        .expect("synthetic is admissible");
        assert!(env.is_seal_stubbed());

        // flags with the SealStubbed bit set -> consistent.
        let with_bit = StageBChunkFlags::SealStubbed.tag();
        assert!(seal_stubbed_flag_consistent(&env, with_bit));
        // flags with the bit also combined with HasParent -> still consistent.
        let combined = StageBChunkFlags::SealStubbed.tag() | StageBChunkFlags::HasParent.tag();
        assert!(seal_stubbed_flag_consistent(&env, combined));
        // flags without the SealStubbed bit -> inconsistent (drift).
        let no_bit = StageBChunkFlags::HasParent.tag();
        assert!(!seal_stubbed_flag_consistent(&env, no_bit));
        let empty = StageBChunkFlags::None.tag();
        assert!(!seal_stubbed_flag_consistent(&env, empty));
    }
}
