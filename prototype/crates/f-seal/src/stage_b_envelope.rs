//! atom #158 · B.4.12 — content class to Seal stub envelope mapping.
//!
//! ATOM_PLAN line 1314-1323 canonical OUT — the mapping from a publish content
//! class to a [`StageBSealStubEnvelope`]. The madness line: "private/secret-like
//! classes stop before Walrus planner. Secret-like residue is denied fixture
//! only, no debug, no clone, redact" (line 1318). This module is the *only*
//! place that turns a content class into a stub envelope; it reuses the atom
//! #156 [`StageBSealStubPolicy::admits`] decision and layers the **owner
//! signature** requirement on top for user-owned public memory.
//!
//! The four test obligations (ATOM_PLAN line 1319) are: private denied, secret
//! denied, synthetic envelope ok, and user-owned public requires owner
//! signature. The function is fail-closed: a future `#[non_exhaustive]`
//! `PublishPayloadClass` variant falls onto the default-deny wildcard.

use mnemos_c_walrus::PublishPayloadClass;

use crate::capability::Capability;
use crate::stage_b_stub::{StageBSealStubEnvelope, StageBSealStubError, StageBSealStubPolicy};

/// Map a publish content class onto a Stage B Seal stub envelope, fail-closed.
///
/// - [`SyntheticPublicFixture`](PublishPayloadClass::SyntheticPublicFixture):
///   admitted — the one freely publishable class (atom #93 posture). Returns a
///   `seal_stubbed` envelope.
/// - [`SecretLike`](PublishPayloadClass::SecretLike): rejected with
///   [`StageBSealStubError::SecretLikeDenied`], regardless of `owner_signed` or
///   `policy`. Secret-like bytes stop before the Walrus planner and never enter
///   a trace.
/// - [`RealUserMemory`](PublishPayloadClass::RealUserMemory) (user-owned public):
///   admitted **only** when `owner_signed` is `true` **and** the policy permits
///   private-memory publish. Under the Stage B default policy
///   ([`StageBSealStubPolicy::default_testnet`], `allow_private_memory_publish =
///   false`) it is denied even with an owner signature — private memory does not
///   leave owner control on a public network this phase.
/// - every other class (`PromptOrProviderText`, `ToolOutput`,
///   `PrivateProvenance`, and any future variant) defers to
///   [`StageBSealStubPolicy::admits`] — default-deny with
///   [`StageBSealStubError::PrivatePublishDenied`].
///
/// `owner_signed` models the user explicitly authorising their own memory to be
/// made public (an owner signature over the publish intent). It is a necessary
/// but not sufficient condition: the policy gate still applies.
#[inline]
pub fn stage_b_seal_envelope(
    class: PublishPayloadClass,
    capability: Capability,
    owner_signed: bool,
    policy: StageBSealStubPolicy,
) -> Result<StageBSealStubEnvelope, StageBSealStubError> {
    match class {
        PublishPayloadClass::SyntheticPublicFixture => {
            Ok(StageBSealStubEnvelope::stub(class, capability))
        }
        PublishPayloadClass::SecretLike => Err(StageBSealStubError::SecretLikeDenied),
        PublishPayloadClass::RealUserMemory => {
            if owner_signed && policy.allow_private_memory_publish {
                Ok(StageBSealStubEnvelope::stub(class, capability))
            } else {
                Err(StageBSealStubError::PrivatePublishDenied)
            }
        }
        // PromptOrProviderText / ToolOutput / PrivateProvenance / future
        // `#[non_exhaustive]` additions: default-deny via the atom #156 policy.
        _ => policy
            .admits(class)
            .map(|()| StageBSealStubEnvelope::stub(class, capability)),
    }
}

#[cfg(test)]
mod tests {
    // Test helpers prefer direct failure surfaces (`expect`) over `Result`
    // bubbling; suppress prod-only clippy denies inside this module (f-seal
    // capability.rs / b-memory #86 precedent).
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use super::*;
    use crate::capability::{Capability, CapabilityKind};
    use mnemos_d_move::SuiAddress;

    fn owner_cap() -> Capability {
        Capability::new(CapabilityKind::WriteMemory, SuiAddress::new([0x11u8; 32]))
    }

    /// test #1 (synthetic envelope ok): the synthetic public fixture class maps
    /// to a `seal_stubbed` envelope under the default policy, no owner signature
    /// needed.
    #[test]
    fn b4_12_synthetic_envelope_ok() {
        let env = stage_b_seal_envelope(
            PublishPayloadClass::SyntheticPublicFixture,
            owner_cap(),
            false,
            StageBSealStubPolicy::default_testnet(),
        )
        .expect("synthetic public fixture is admissible");
        assert!(env.is_seal_stubbed());
        assert_eq!(
            env.content_class(),
            PublishPayloadClass::SyntheticPublicFixture
        );
    }

    /// test #2 (private denied): private provenance is rejected with
    /// `PrivatePublishDenied` under the default policy.
    #[test]
    fn b4_12_private_denied() {
        assert_eq!(
            stage_b_seal_envelope(
                PublishPayloadClass::PrivateProvenance,
                owner_cap(),
                true,
                StageBSealStubPolicy::default_testnet(),
            ),
            Err(StageBSealStubError::PrivatePublishDenied)
        );
    }

    /// test #3 (secret denied): secret-like is rejected with `SecretLikeDenied`
    /// even with an owner signature and an (unsafe) allow-private policy.
    #[test]
    fn b4_12_secret_denied() {
        assert_eq!(
            stage_b_seal_envelope(
                PublishPayloadClass::SecretLike,
                owner_cap(),
                true,
                StageBSealStubPolicy {
                    allow_private_memory_publish: true,
                },
            ),
            Err(StageBSealStubError::SecretLikeDenied)
        );
    }

    /// test #4 (user-owned public requires owner signature): real user memory is
    /// denied without an owner signature; with an owner signature it still needs
    /// a policy that permits private publish (the default policy denies it), and
    /// only owner-signed + allow-private admits it.
    #[test]
    fn b4_12_user_owned_public_requires_owner_signature() {
        // (a) no owner signature, default policy -> denied.
        assert_eq!(
            stage_b_seal_envelope(
                PublishPayloadClass::RealUserMemory,
                owner_cap(),
                false,
                StageBSealStubPolicy::default_testnet(),
            ),
            Err(StageBSealStubError::PrivatePublishDenied)
        );
        // (b) owner signature, but default-deny policy -> still denied.
        assert_eq!(
            stage_b_seal_envelope(
                PublishPayloadClass::RealUserMemory,
                owner_cap(),
                true,
                StageBSealStubPolicy::default_testnet(),
            ),
            Err(StageBSealStubError::PrivatePublishDenied)
        );
        // (c) owner signature + allow-private policy -> admitted.
        let env = stage_b_seal_envelope(
            PublishPayloadClass::RealUserMemory,
            owner_cap(),
            true,
            StageBSealStubPolicy {
                allow_private_memory_publish: true,
            },
        )
        .expect("owner-signed real user memory with allow-private policy is admissible");
        assert!(env.is_seal_stubbed());
    }
}
