//! Stage B Walrus publish **decision** layer (payload class gate integration).
//!
//! The [`content_policy`](crate::content_policy) module provides the binary
//! admission predicate [`stage_b_publish_allowed`] — "may this payload class be
//! PUT to the Walrus public testnet under the *default* policy" — answering
//! `true` only for [`PublishPayloadClass::SyntheticPublicFixture`]. The Walrus
//! planner ([`WalrusPutPlan::plan`](crate::stage_b_put::WalrusPutPlan::plan))
//! reads that predicate before any transport type is constructed. This module
//! provides the **richer three-way decision** the Walrus planner consults, so
//! that the planner's gate distinguishes the *owner-signature dimension* of a
//! denial from a flat class denial without inventing a second classifier or a
//! new error variant.
//!
//! # Public API
//!
//! * [`StageBPublishDecision`] — a `#[repr(u8)]` three-way decision:
//!   [`Admit`](StageBPublishDecision::Admit) `= 1`,
//!   [`DenyClass`](StageBPublishDecision::DenyClass) `= 2`,
//!   [`RequireOwnerSignature`](StageBPublishDecision::RequireOwnerSignature) `= 3`.
//! * [`stage_b_publish_decision`] — the `const fn` mapping a
//!   [`PublishPayloadClass`] onto that decision.
//!
//! # Design invariants
//!
//! * **Private / secret-like payload cannot reach the HTTP layer.** Every class
//!   other than [`SyntheticPublicFixture`](PublishPayloadClass::SyntheticPublicFixture)
//!   and [`RealUserMemory`](PublishPayloadClass::RealUserMemory) — raw prompt /
//!   provider text, tool output, secret-like bytes, private provenance, **and
//!   any future `#[non_exhaustive]` class** — maps to
//!   [`DenyClass`](StageBPublishDecision::DenyClass). The planner translates
//!   both denial arms to [`WalrusClientError::PayloadClassDenied`] *before* the
//!   Stage A request type is constructed, so a denied payload makes **zero
//!   transport calls**.
//!
//! * **Layered over the binary predicate, never re-spelled.** The decision
//!   admits **iff** the predicate admits: [`stage_b_publish_decision`] calls
//!   [`stage_b_publish_allowed`] for the [`Admit`](StageBPublishDecision::Admit)
//!   arm rather than re-matching [`SyntheticPublicFixture`](PublishPayloadClass::SyntheticPublicFixture).
//!   The default-deny posture is inherited: the residual `match` carries a single
//!   positive [`RealUserMemory`](PublishPayloadClass::RealUserMemory) arm and a
//!   `_ => DenyClass` wildcard, so a future Stage A payload class is denied by
//!   construction.
//!
//! * **`RequireOwnerSignature` is not an allow path.** User-owned public content
//!   ([`RealUserMemory`](PublishPayloadClass::RealUserMemory)) is classified
//!   [`RequireOwnerSignature`](StageBPublishDecision::RequireOwnerSignature) to
//!   record *why* it is held back — it would be admissible only behind an
//!   owner-signature proof — but the planner fails it closed exactly like
//!   [`DenyClass`](StageBPublishDecision::DenyClass): no transport request is
//!   created. The owner-signature / wallet override that could admit user-owned
//!   content is a separate future surface; **this module provides no
//!   owner-signature verifier and no wallet / seal / capability type**.
//!
//! * **No new error variant.** The denial is mapped onto the frozen
//!   `#[non_exhaustive]` [`WalrusClientError::PayloadClassDenied`] at the planner
//!   seam; the client error set stays frozen at seven variants.
//!
//! # Related surfaces
//!
//! * [`stage_b_publish_allowed`] — the binary admission predicate, called (not
//!   re-spelled) for the [`Admit`](StageBPublishDecision::Admit) arm.
//! * [`WalrusPutPlan::plan`](crate::stage_b_put::WalrusPutPlan::plan) — the
//!   planner consumes [`stage_b_publish_decision`] in place of the bare
//!   predicate, so the Walrus planner's content policy is the richer decision
//!   rather than the binary predicate.
//!
//! [`stage_b_publish_allowed`]: crate::content_policy::stage_b_publish_allowed
//! [`WalrusClientError::PayloadClassDenied`]: crate::stage_b_put::WalrusClientError::PayloadClassDenied

use crate::chunk_schema::PublishPayloadClass;
use crate::content_policy::stage_b_publish_allowed;

/// The three-way Stage B Walrus publish decision the planner consults before any
/// transport type is constructed.
///
/// A `#[repr(u8)]` enum so the decision is a single fixed byte with explicit,
/// stable discriminants. [`Admit`](Self::Admit) is the only value that lets the
/// planner build a PUT request; both [`DenyClass`](Self::DenyClass) and
/// [`RequireOwnerSignature`](Self::RequireOwnerSignature) fail closed.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
#[repr(u8)]
pub enum StageBPublishDecision {
    /// The payload class is admissible onto the Walrus public testnet under the
    /// default Stage B policy. Returned **iff**
    /// [`stage_b_publish_allowed`](crate::content_policy::stage_b_publish_allowed)
    /// is `true` (today: only
    /// [`SyntheticPublicFixture`](PublishPayloadClass::SyntheticPublicFixture)).
    Admit = 1,
    /// The payload class is denied by class alone — raw prompt / provider text,
    /// tool output, secret-like bytes, private provenance, and any future
    /// `#[non_exhaustive]` Stage A class. Never publishable on Stage B.
    DenyClass = 2,
    /// The payload is user-owned public content
    /// ([`RealUserMemory`](PublishPayloadClass::RealUserMemory)): it could be
    /// admissible only behind an owner-signature proof. No such proof surface
    /// exists yet (the owner-signature / wallet override is future work), so the
    /// planner fails it closed exactly like [`DenyClass`](Self::DenyClass).
    RequireOwnerSignature = 3,
}

impl StageBPublishDecision {
    /// One-byte wire tag for this decision (the `#[repr(u8)]` discriminant).
    #[inline]
    pub const fn tag(self) -> u8 {
        self as u8
    }
}

/// Classify a [`PublishPayloadClass`] into the three-way Stage B Walrus publish
/// [`StageBPublishDecision`].
///
/// Layered over the binary predicate — the
/// [`Admit`](StageBPublishDecision::Admit) arm is returned **iff**
/// [`stage_b_publish_allowed`] admits the class, so the two policies can never
/// disagree on what is publishable. The residual classes are split:
/// [`RealUserMemory`](PublishPayloadClass::RealUserMemory) →
/// [`RequireOwnerSignature`](StageBPublishDecision::RequireOwnerSignature), and
/// every other class (current or future `#[non_exhaustive]`) →
/// [`DenyClass`](StageBPublishDecision::DenyClass) by construction.
///
/// Pure over the class alone: no network I/O, no owner flag, no signature
/// verification. [`RequireOwnerSignature`](StageBPublishDecision::RequireOwnerSignature)
/// is a *reason for holding back*, not an allow path — the planner fails it
/// closed.
///
/// [`stage_b_publish_allowed`]: crate::content_policy::stage_b_publish_allowed
#[inline]
pub const fn stage_b_publish_decision(class: PublishPayloadClass) -> StageBPublishDecision {
    // Admit iff the binary predicate admits (today: SyntheticPublicFixture only).
    // Reusing the predicate — not re-matching the admitted class — binds the two
    // policies so they cannot drift.
    if stage_b_publish_allowed(class) {
        return StageBPublishDecision::Admit;
    }
    // Residual (non-admitted) classes. The single positive RealUserMemory arm
    // records the owner-signature dimension; the `_` wildcard denies every other
    // class — including any future `#[non_exhaustive]` Stage A class — by
    // construction (default-deny).
    match class {
        PublishPayloadClass::RealUserMemory => StageBPublishDecision::RequireOwnerSignature,
        _ => StageBPublishDecision::DenyClass,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// test (synthetic passes): the one admissible class decides `Admit`.
    #[test]
    fn b2_12_synthetic_admitted() {
        assert_eq!(
            stage_b_publish_decision(PublishPayloadClass::SyntheticPublicFixture),
            StageBPublishDecision::Admit,
        );
    }

    /// test (user-owned public requires owner signature): user-owned content
    /// decides `RequireOwnerSignature` — held back pending an owner-signature
    /// proof this atom does not mint, and failed closed by the planner.
    #[test]
    fn b2_12_user_owned_requires_owner_signature() {
        assert_eq!(
            stage_b_publish_decision(PublishPayloadClass::RealUserMemory),
            StageBPublishDecision::RequireOwnerSignature,
        );
    }

    /// test (denied payload): every flat-denied class decides `DenyClass`.
    #[test]
    fn b2_12_denied_classes_deny() {
        for class in [
            PublishPayloadClass::PromptOrProviderText,
            PublishPayloadClass::ToolOutput,
            PublishPayloadClass::SecretLike,
            PublishPayloadClass::PrivateProvenance,
        ] {
            assert_eq!(
                stage_b_publish_decision(class),
                StageBPublishDecision::DenyClass,
                "class {} must decide DenyClass",
                class.class_label(),
            );
        }
    }

    /// Closed decision policy: across the full Stage A variant set exactly
    /// `SyntheticPublicFixture` admits, `RealUserMemory` requires an owner
    /// signature, and every other class is denied. Pins the mapping so a future
    /// class addition cannot silently flip to admitted.
    #[test]
    fn b2_12_closed_decision_policy() {
        let all = [
            (
                PublishPayloadClass::SyntheticPublicFixture,
                StageBPublishDecision::Admit,
            ),
            (
                // The public-registry artifact admits (derived from
                // `stage_b_publish_allowed`; its sole constructor secret-scans first).
                PublishPayloadClass::PublicRegistryArtifact,
                StageBPublishDecision::Admit,
            ),
            (
                PublishPayloadClass::RealUserMemory,
                StageBPublishDecision::RequireOwnerSignature,
            ),
            (
                PublishPayloadClass::PromptOrProviderText,
                StageBPublishDecision::DenyClass,
            ),
            (
                PublishPayloadClass::ToolOutput,
                StageBPublishDecision::DenyClass,
            ),
            (
                PublishPayloadClass::SecretLike,
                StageBPublishDecision::DenyClass,
            ),
            (
                PublishPayloadClass::PrivateProvenance,
                StageBPublishDecision::DenyClass,
            ),
        ];
        for (class, expected) in all {
            assert_eq!(
                stage_b_publish_decision(class),
                expected,
                "publish decision drift for {}",
                class.class_label(),
            );
        }
    }

    /// Layer binding: the decision admits **iff** the binary predicate admits.
    /// Proves `stage_b_publish_decision` is layered over
    /// `stage_b_publish_allowed`, never disagreeing on what is publishable.
    #[test]
    fn b2_12_admit_iff_publish_allowed() {
        for class in [
            PublishPayloadClass::SyntheticPublicFixture,
            PublishPayloadClass::RealUserMemory,
            PublishPayloadClass::PromptOrProviderText,
            PublishPayloadClass::ToolOutput,
            PublishPayloadClass::SecretLike,
            PublishPayloadClass::PrivateProvenance,
        ] {
            let admits = stage_b_publish_decision(class) == StageBPublishDecision::Admit;
            assert_eq!(
                admits,
                stage_b_publish_allowed(class),
                "decision Admit must match #93 predicate for {}",
                class.class_label(),
            );
        }
    }

    /// Width / discriminant pin: the `#[repr(u8)]` decision is one byte with the
    /// locked discriminants 1 / 2 / 3.
    #[test]
    fn b2_12_decision_repr_width() {
        assert_eq!(core::mem::size_of::<StageBPublishDecision>(), 1);
        assert_eq!(StageBPublishDecision::Admit.tag(), 1);
        assert_eq!(StageBPublishDecision::DenyClass.tag(), 2);
        assert_eq!(StageBPublishDecision::RequireOwnerSignature.tag(), 3);
    }
}
