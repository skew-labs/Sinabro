//! Stage B publish content-class policy.
//!
//! Stage A classifies every payload that could leave the process with a
//! [`PublishPayloadClass`] (home-of-record `c-walrus` `publisher.rs`).
//! Stage A's `PublisherPutRequest::new` already admits **only**
//! [`PublishPayloadClass::SyntheticPublicFixture`] onto the Walrus public
//! testnet. This module mints the canonical OUT: the **default
//! Stage B publish-class admission predicate** that the Walrus PUT and the Sui
//! anchor seams read *before* a chunk is allowed to leave the machine, so the
//! same admission rule is one reusable, testable function rather than an inlined
//! `match` re-spelled at every external seam.
//!
//! # Design invariants
//!
//! * **`SyntheticPublicFixture` only, by default.** Under the default Stage B
//!   policy [`stage_b_publish_allowed`] returns `true` for
//!   [`PublishPayloadClass::SyntheticPublicFixture`] and `false` for **every**
//!   other class — real user memory, raw prompt / provider text, tool output,
//!   secret-like bytes, and private provenance are all denied fail-closed. A
//!   chunk derived from real user content never reaches a public network through
//!   the default predicate; admitting user-owned content is reserved for an
//!   explicit owner-flagged override that this module does **not** mint (see the
//!   reuse / scope note below).
//!
//! * **Reject is a predicate, not an invented canonical error.** The
//!   [`StageBChunkError`](crate::StageBChunkError) variant set is frozen
//!   `#[non_exhaustive]` and already carries the home-of-record denial variant
//!   [`StageBChunkError::PublishClassDenied`] ("the chunk's publish payload
//!   class is not admissible onto the public testnet — enforced at the publish
//!   boundary"). The OUT is a `bool` predicate (the reject-as-predicate
//!   precedent); a later stage that owns the Walrus PUT / Sui anchor boundary
//!   maps a `false` here onto `PublishClassDenied` at that seam. No new error
//!   variant is minted here.
//!
//! * **Default-deny over a `#[non_exhaustive]` enum.** The predicate is written
//!   as a single positive `matches!` arm so that any *future* payload class
//!   added to the Stage A enum is denied by construction (the wildcard `=> false`
//!   that `matches!` emits), never silently admitted. The closed policy is
//!   verified exhaustively by `b1_12_closed_policy_only_synthetic`.
//!
//! # Reuse map
//!
//! * **reuse [`PublishPayloadClass`]** — the content classifier, re-exported
//!   verbatim from `c-walrus` (`chunk_schema::PublishPayloadClass`,
//!   ultimately `mnemos_c_walrus::publisher::PublishPayloadClass`). No second
//!   classifier or wire tag is minted; this module only reads the existing class.
//!
//! # Scope note — the owner-flagged override is a later feature (seal-stub)
//!
//! The publish-policy test list includes "user-owned public allowed only with
//! owner flag". The canonical OUT signature is `stage_b_publish_allowed(class) -> bool`
//! — it takes **no** owner flag, so here user-owned content
//! ([`PublishPayloadClass::RealUserMemory`]) is denied. The owner-flagged
//! override surface is the `StageBSealStubPolicy { allow_private_memory_publish }`
//! envelope, whose home is the seal-stub cluster (a later feature). Minting that
//! flag here would steal the later feature's scope, so this
//! module implements the default predicate exactly and proves the user-owned
//! denial *without* the owner-flag path
//! (`b1_12_user_owned_denied_without_owner_flag`).

use crate::chunk_schema::PublishPayloadClass;

/// The canonical OUT: the default Stage B publish-class admission
/// predicate, fail-closed.
///
/// Returns `true` iff `class` may be PUT to the Walrus public testnet (and
/// anchored to Sui) under the Stage B policy. TWO classes are admitted:
/// [`PublishPayloadClass::SyntheticPublicFixture`] (a hand-authored public demo) and
/// [`PublishPayloadClass::EncryptedUserMemory`] (AEAD CIPHERTEXT whose 32-byte
/// key never leaves the local machine, so publishing it leaks no plaintext).
/// Every PLAINTEXT / secret class —
/// [`RealUserMemory`](PublishPayloadClass::RealUserMemory),
/// [`PromptOrProviderText`](PublishPayloadClass::PromptOrProviderText),
/// [`ToolOutput`](PublishPayloadClass::ToolOutput),
/// [`SecretLike`](PublishPayloadClass::SecretLike) and
/// [`PrivateProvenance`](PublishPayloadClass::PrivateProvenance) — STAYS denied
/// (secret-zero holds: only ciphertext or synthetic bytes ever leave the process).
///
/// This is a pure predicate over the class alone. It performs no network I/O and
/// reads no owner flag; the owner-flagged override that could admit user-owned
/// content is the seal-stub surface (a later feature). It returns a `bool`
/// rather than a [`StageBChunkError`](crate::StageBChunkError): the error set
/// is frozen `#[non_exhaustive]` and the denial is mapped onto
/// [`StageBChunkError::PublishClassDenied`] at the publish boundary, not
/// here (reject-as-predicate precedent).
///
/// Written as explicit positive `matches!` arms so a future payload class added to the
/// `#[non_exhaustive]` enum is denied by construction (default-deny).
///
/// Admitted arms: `SyntheticPublicFixture` (hand-authored public fixture),
/// `EncryptedUserMemory` (AEAD ciphertext, key stays local), and
/// `PublicRegistryArtifact` (a GitHub-style PUBLIC registry artifact, so a user
/// can choose either public or private publication). The public artifact is
/// PLAINTEXT, admitted ONLY because its SOLE constructor, the registry
/// public-publish chokepoint in `dispatch.rs`, runs a mandatory fail-closed
/// secret-scan first — so a secret-shaped artifact is never published. The safety
/// is that construction confinement, not this predicate. (The mainnet self-host
/// `put_blob` still rejects it via its `_` arm.)
#[inline]
pub const fn stage_b_publish_allowed(class: PublishPayloadClass) -> bool {
    matches!(
        class,
        PublishPayloadClass::SyntheticPublicFixture
            | PublishPayloadClass::EncryptedUserMemory
            | PublishPayloadClass::PublicRegistryArtifact
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    /// test 1 (synthetic allowed): the one admissible class returns `true`.
    #[test]
    fn b1_12_synthetic_allowed() {
        assert!(stage_b_publish_allowed(
            PublishPayloadClass::SyntheticPublicFixture
        ));
    }

    /// test 2 (user-owned public allowed only with owner flag): the canonical
    /// OUT takes no owner flag, so user-owned content is denied by the default
    /// predicate. The owner-flagged override is the seal-stub surface (a
    /// later feature); under this no-owner-flag default the answer is `false`.
    #[test]
    fn b1_12_user_owned_denied_without_owner_flag() {
        assert!(!stage_b_publish_allowed(
            PublishPayloadClass::RealUserMemory
        ));
    }

    /// test 3 (private denied): private provenance never publishes.
    #[test]
    fn b1_12_private_denied() {
        assert!(!stage_b_publish_allowed(
            PublishPayloadClass::PrivateProvenance
        ));
    }

    /// test 4 (secret-like denied): secret-like bytes never publish.
    #[test]
    fn b1_12_secret_like_denied() {
        assert!(!stage_b_publish_allowed(PublishPayloadClass::SecretLike));
    }

    /// Security pin: the AEAD CIPHERTEXT class is admitted, but the PLAINTEXT
    /// real-memory class STAYS denied — only ciphertext or synthetic bytes may leave.
    #[test]
    fn encrypted_ciphertext_admitted_plaintext_real_memory_denied() {
        assert!(
            stage_b_publish_allowed(PublishPayloadClass::EncryptedUserMemory),
            "AEAD ciphertext is admitted (no plaintext leaks)"
        );
        assert!(
            !stage_b_publish_allowed(PublishPayloadClass::RealUserMemory),
            "PLAINTEXT real memory stays denied (secret-zero)"
        );
    }

    /// Closed-policy exhaustiveness: across the full Stage A variant set, exactly the
    /// synthetic fixture + the encrypted-ciphertext class are admitted and every
    /// PLAINTEXT/secret class is denied. This pins the posture so a future class
    /// addition cannot silently flip to admitted.
    #[test]
    fn b1_12_closed_policy_synthetic_and_ciphertext_only() {
        let all = [
            (PublishPayloadClass::SyntheticPublicFixture, true),
            (PublishPayloadClass::EncryptedUserMemory, true),
            // The public-registry artifact is admitted (its sole
            // constructor secret-scans fail-closed first; see `stage_b_publish_allowed`).
            (PublishPayloadClass::PublicRegistryArtifact, true),
            (PublishPayloadClass::RealUserMemory, false),
            (PublishPayloadClass::PromptOrProviderText, false),
            (PublishPayloadClass::ToolOutput, false),
            (PublishPayloadClass::SecretLike, false),
            (PublishPayloadClass::PrivateProvenance, false),
        ];
        for (class, expected) in all {
            assert_eq!(
                stage_b_publish_allowed(class),
                expected,
                "publish policy drift for {}",
                class.class_label()
            );
        }
    }
}
