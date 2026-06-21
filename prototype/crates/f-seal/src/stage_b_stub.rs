//! atom #156 · B.4.10 — Seal stub capability types.
//!
//! ATOM_PLAN §4.4 (line 401-403) canonical OUT — [`StageBSealStubPolicy`],
//! [`StageBSealStubEnvelope`], [`StageBSealStubError`]. This is the Stage B
//! *Seal boundary marker* surface and nothing more: there is **no encryption,
//! no key server, and no private-memory publish path** here. The madness line
//! in ATOM_PLAN is direct — "stub marks boundary only. No encryption claim, no
//! key server, no private memory publish. Fixture-only, no live egress;
//! secret-like inputs are denied fixtures with no debug, no clone, redact in
//! traces" (line 1296). The real Seal AEAD / threshold path is custody-adjacent
//! and deferred to Phase 1 per §3.4 master.
//!
//! Canonical IN:
//! - [`PublishPayloadClass`](mnemos_c_walrus::PublishPayloadClass) — the
//!   home-of-record content classifier (atom #8 · `c-walrus` `publisher.rs`),
//!   reused verbatim. No second classifier is minted; the edge `f-seal ->
//!   c-walrus` is acyclic (c-walrus is a leaf crate).
//! - [`Capability`](crate::capability::Capability) — the atom #37 ownership
//!   token binding a [`CapabilityKind`](crate::capability::CapabilityKind) to a
//!   Sui owner address. The envelope carries it by value (it is `Copy`).
//!
//! The default policy is fail-closed: [`StageBSealStubPolicy::default_testnet`]
//! denies private-memory publish, and [`StageBSealStubPolicy::admits`] rejects
//! every secret-like or private class before any Walrus planner is reached.

use mnemos_c_walrus::PublishPayloadClass;

use crate::capability::Capability;

/// §4.4 Seal stub policy. The single boolean gate decides whether real
/// user-owned (private-provenance) memory may be published at all. In Stage B
/// this defaults to `false` and the only safe constructor
/// ([`default_testnet`](Self::default_testnet)) hard-codes that default — the
/// field is `pub` to match the §4.4 declaration, but the default-deny posture
/// is the construction path callers are expected to use.
///
/// There is no encryption represented by this type. It is a *boundary marker*:
/// it records the decision "may this class cross the publish boundary?" and
/// nothing about how bytes would be sealed (that is Phase 1).
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub struct StageBSealStubPolicy {
    /// Whether real user / private-provenance memory may be published onto the
    /// Walrus public testnet. Default-deny (`false`) in Stage B: private memory
    /// never leaves the owner's control on a public network in this phase.
    pub allow_private_memory_publish: bool,
}

impl StageBSealStubPolicy {
    /// The only safe Stage B default: private-memory publish is denied. Every
    /// call site that does not have an explicit, owner-authorised override must
    /// use this constructor so the default-deny posture is byte-stable.
    #[inline]
    pub const fn default_testnet() -> Self {
        Self {
            allow_private_memory_publish: false,
        }
    }

    /// Decide whether `class` may cross the Stage B publish boundary under this
    /// policy, fail-closed.
    ///
    /// - [`SyntheticPublicFixture`](PublishPayloadClass::SyntheticPublicFixture)
    ///   is the one freely admissible class (reuses the atom #93 default-deny
    ///   posture: only synthetic public fixtures publish).
    /// - [`SecretLike`](PublishPayloadClass::SecretLike) is always rejected with
    ///   [`StageBSealStubError::SecretLikeDenied`] — secret-like bytes never
    ///   publish and never appear in traces.
    /// - every other class (`RealUserMemory`, `PromptOrProviderText`,
    ///   `ToolOutput`, `PrivateProvenance`, plus any future
    ///   `#[non_exhaustive]` addition) is private-by-default and is rejected
    ///   with [`StageBSealStubError::PrivatePublishDenied`] unless
    ///   [`allow_private_memory_publish`](Self::allow_private_memory_publish) is
    ///   set.
    ///
    /// Written as explicit positive arms with a fail-closed wildcard so a future
    /// payload class added to the Stage A `#[non_exhaustive]` enum is denied by
    /// construction.
    #[inline]
    pub const fn admits(&self, class: PublishPayloadClass) -> Result<(), StageBSealStubError> {
        match class {
            PublishPayloadClass::SyntheticPublicFixture => Ok(()),
            PublishPayloadClass::SecretLike => Err(StageBSealStubError::SecretLikeDenied),
            _ => {
                if self.allow_private_memory_publish {
                    Ok(())
                } else {
                    Err(StageBSealStubError::PrivatePublishDenied)
                }
            }
        }
    }
}

/// §4.4 Seal stub error. Exactly the three variants ATOM_PLAN line 403
/// declares. `Copy` + no owned bytes so the error channel cannot leak a body or
/// a secret-like substring through `Debug` (mirrors
/// [`CapabilityError`](crate::capability::CapabilityError)).
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
#[non_exhaustive]
pub enum StageBSealStubError {
    /// A private / user-owned class was offered for publish while the policy
    /// denies private-memory publish (the Stage B default).
    PrivatePublishDenied,
    /// A secret-like class was offered for publish. Always rejected, regardless
    /// of policy — secret-like bytes never cross the boundary.
    SecretLikeDenied,
    /// A UX / log / doc surface claimed real Seal encryption in Stage B. Used by
    /// the atom #157 wording guard; minted here so the Seal-stub error set is
    /// declared once and frozen `#[non_exhaustive]`.
    MisleadingEncryptionClaim,
}

impl StageBSealStubError {
    /// Stable, allow-listed `class_label` for diagnostic JSON envelopes,
    /// namespaced under `stage_b.seal_stub.*`. Carries no body bytes, so it is
    /// redaction-safe by construction.
    #[inline]
    pub const fn class_label(self) -> &'static str {
        match self {
            Self::PrivatePublishDenied => "stage_b.seal_stub.private_publish_denied",
            Self::SecretLikeDenied => "stage_b.seal_stub.secret_like_denied",
            Self::MisleadingEncryptionClaim => "stage_b.seal_stub.misleading_encryption_claim",
        }
    }
}

/// §4.4 Seal stub envelope — a *boundary marker* binding a publish content
/// class to the owner [`Capability`] that asserted it, with the `seal_stubbed`
/// flag recording that this path is the Stage B stub (not a real Seal AEAD).
///
/// The fields are `pub` to match the §4.4 declaration and to let the atom #159
/// signed-chunk integration read them; the canonical mint path is
/// [`stub`](Self::stub), which always sets `seal_stubbed = true`. A value of
/// this type never means "these bytes are encrypted" — it means "this class was
/// admitted at the stub boundary under a recorded capability".
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub struct StageBSealStubEnvelope {
    /// The publish content class being marked at the boundary.
    pub content_class: PublishPayloadClass,
    /// The owner capability token that authorised reaching this boundary.
    pub capability: Capability,
    /// Always `true` for a value built through [`stub`](Self::stub): this is the
    /// Stage B Seal *stub*, never a real encryption path.
    pub seal_stubbed: bool,
}

impl StageBSealStubEnvelope {
    /// Mint a Seal stub envelope. `seal_stubbed` is always set to `true` — there
    /// is no constructor that produces a `false` flag, so a Stage B envelope can
    /// never be mistaken for a real (non-stub) Seal path.
    #[inline]
    pub const fn stub(content_class: PublishPayloadClass, capability: Capability) -> Self {
        Self {
            content_class,
            capability,
            seal_stubbed: true,
        }
    }

    /// Borrow-free accessor for the marked content class.
    #[inline]
    pub const fn content_class(&self) -> PublishPayloadClass {
        self.content_class
    }

    /// Whether this envelope is the Stage B stub. Always `true` for a value
    /// minted by [`stub`](Self::stub); exposed so callers (atom #159) can assert
    /// the stub invariant without reaching into the field.
    #[inline]
    pub const fn is_seal_stubbed(&self) -> bool {
        self.seal_stubbed
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::capability::{Capability, CapabilityKind};
    use mnemos_d_move::SuiAddress;

    /// 32-byte test owner `[0x11; 32]`, mirroring the f-seal capability test
    /// fixture.
    fn owner_cap() -> Capability {
        Capability::new(CapabilityKind::WriteMemory, SuiAddress::new([0x11u8; 32]))
    }

    /// test #1 (default denies private publish): the default testnet policy
    /// rejects real user memory and private provenance with
    /// `PrivatePublishDenied`.
    #[test]
    fn b4_10_default_denies_private_publish() {
        let policy = StageBSealStubPolicy::default_testnet();
        assert!(!policy.allow_private_memory_publish);
        assert_eq!(
            policy.admits(PublishPayloadClass::RealUserMemory),
            Err(StageBSealStubError::PrivatePublishDenied)
        );
        assert_eq!(
            policy.admits(PublishPayloadClass::PrivateProvenance),
            Err(StageBSealStubError::PrivatePublishDenied)
        );
    }

    /// test #2 (secret-like denied): secret-like bytes are rejected with
    /// `SecretLikeDenied` regardless of policy — even an (unsafe) allow-private
    /// policy cannot admit them.
    #[test]
    fn b4_10_secret_like_denied() {
        let deny = StageBSealStubPolicy::default_testnet();
        assert_eq!(
            deny.admits(PublishPayloadClass::SecretLike),
            Err(StageBSealStubError::SecretLikeDenied)
        );
        let allow_private = StageBSealStubPolicy {
            allow_private_memory_publish: true,
        };
        assert_eq!(
            allow_private.admits(PublishPayloadClass::SecretLike),
            Err(StageBSealStubError::SecretLikeDenied)
        );
    }

    /// test #3 (stub flag set): every envelope minted through `stub` carries
    /// `seal_stubbed == true` — the boundary can never be confused with a real
    /// Seal path.
    #[test]
    fn b4_10_stub_flag_set() {
        let env =
            StageBSealStubEnvelope::stub(PublishPayloadClass::SyntheticPublicFixture, owner_cap());
        assert!(env.seal_stubbed);
        assert!(env.is_seal_stubbed());
        assert_eq!(
            env.content_class(),
            PublishPayloadClass::SyntheticPublicFixture
        );
    }

    /// Synthetic public fixture is the one freely admissible class under the
    /// default-deny policy (reuses the atom #93 posture).
    #[test]
    fn b4_10_synthetic_admitted() {
        let policy = StageBSealStubPolicy::default_testnet();
        assert_eq!(
            policy.admits(PublishPayloadClass::SyntheticPublicFixture),
            Ok(())
        );
    }

    /// The error channel is `Copy` and carries no owned bytes — a redaction-safe
    /// label is all it exposes.
    #[test]
    fn b4_10_error_labels_redaction_safe() {
        assert_eq!(
            StageBSealStubError::PrivatePublishDenied.class_label(),
            "stage_b.seal_stub.private_publish_denied"
        );
        assert_eq!(
            StageBSealStubError::SecretLikeDenied.class_label(),
            "stage_b.seal_stub.secret_like_denied"
        );
        assert_eq!(
            StageBSealStubError::MisleadingEncryptionClaim.class_label(),
            "stage_b.seal_stub.misleading_encryption_claim"
        );
    }
}
