//! Stage B Walrus publish **decision** layer (atom #113 · B.2.12 payload class
//! gate integration).
//!
//! Atom #93 ([`content_policy`](crate::content_policy)) minted the binary
//! admission predicate [`stage_b_publish_allowed`] — "may this payload class be
//! PUT to the Walrus public testnet under the *default* policy" — answering
//! `true` only for [`PublishPayloadClass::SyntheticPublicFixture`]. Atom #103
//! ([`WalrusPutPlan::plan`](crate::stage_b_put::WalrusPutPlan::plan)) already
//! reads that predicate before any transport type is constructed. This atom
//! mints the **richer three-way decision** the Walrus planner consults, so that
//! the planner's gate distinguishes the *owner-signature dimension* of a denial
//! from a flat class denial without inventing a second classifier or a new
//! error variant.
//!
//! # Canonical OUT (atom #113, user-locked 2026-05-30)
//!
//! * [`StageBPublishDecision`] — a `#[repr(u8)]` three-way decision:
//!   [`Admit`](StageBPublishDecision::Admit) `= 1`,
//!   [`DenyClass`](StageBPublishDecision::DenyClass) `= 2`,
//!   [`RequireOwnerSignature`](StageBPublishDecision::RequireOwnerSignature) `= 3`.
//! * [`stage_b_publish_decision`] — the `const fn` mapping a
//!   [`PublishPayloadClass`] onto that decision.
//!
//! # Madness invariants (`MNEMOS_STAGE_B_ATOM_PLAN.md` #113)
//!
//! * **Private / secret-like payload cannot reach the HTTP layer.** Every class
//!   other than [`SyntheticPublicFixture`](PublishPayloadClass::SyntheticPublicFixture)
//!   and [`RealUserMemory`](PublishPayloadClass::RealUserMemory) — raw prompt /
//!   provider text, tool output, secret-like bytes, private provenance, **and
//!   any future `#[non_exhaustive]` class** — maps to
//!   [`DenyClass`](StageBPublishDecision::DenyClass). The planner translates
//!   both denial arms to [`WalrusClientError::PayloadClassDenied`] *before* the
//!   Stage A request type is constructed, so a denied payload makes **zero
//!   transport calls** (`b2_12_*` + the #103 `b2_2_private_denied_before_request`
//!   precedent).
//!
//! * **Layered over #93, never re-spelled.** The decision admits **iff** the
//!   atom #93 predicate admits: [`stage_b_publish_decision`] calls
//!   [`stage_b_publish_allowed`] for the [`Admit`](StageBPublishDecision::Admit)
//!   arm rather than re-matching [`SyntheticPublicFixture`](PublishPayloadClass::SyntheticPublicFixture).
//!   The default-deny posture is inherited: the residual `match` carries a single
//!   positive [`RealUserMemory`](PublishPayloadClass::RealUserMemory) arm and a
//!   `_ => DenyClass` wildcard, so a future Stage A payload class is denied by
//!   construction (`b2_12_admit_iff_publish_allowed` pins the binding;
//!   `b2_12_closed_decision_policy` pins the full mapping).
//!
//! * **`RequireOwnerSignature` is not an allow path in this atom.** User-owned
//!   public content ([`RealUserMemory`](PublishPayloadClass::RealUserMemory)) is
//!   classified [`RequireOwnerSignature`](StageBPublishDecision::RequireOwnerSignature)
//!   to record *why* it is held back — it would be admissible only behind an
//!   owner-signature proof — but the planner fails it closed exactly like
//!   [`DenyClass`](StageBPublishDecision::DenyClass): no transport request is
//!   created. The owner-signature / `StageBSealStubPolicy` override that could
//!   admit user-owned content is the §4.4 seal-stub / wallet cluster surface (a
//!   later atom, atoms > #120); **this atom mints no owner-signature verifier,
//!   no `StageBSealStubPolicy`, and no wallet / seal / capability type**
//!   (OD-1 = R1, user-locked 2026-05-30).
//!
//! * **No new error variant.** The denial is mapped onto the frozen
//!   `#[non_exhaustive]` [`WalrusClientError::PayloadClassDenied`] at the planner
//!   seam (atom #103); the §4.2 error set stays frozen at 7 (atom #81–#87
//!   reject-as-predicate / map-at-seam precedent).
//!
//! # Reuse map (atom contract — reuse: #93, #103)
//!
//! * **reuse: #93** [`stage_b_publish_allowed`] — the binary admission predicate,
//!   called (not re-spelled) for the [`Admit`](StageBPublishDecision::Admit) arm.
//!   `content_policy.rs` is untouched.
//! * **reuse: #103** [`WalrusPutPlan::plan`](crate::stage_b_put::WalrusPutPlan::plan)
//!   — the planner is migrated to consume [`stage_b_publish_decision`] in place of
//!   the bare predicate (see `stage_b_put.rs`), so "the Walrus planner calls Stage
//!   B content policy" is the richer decision rather than the binary predicate.
//!
//! [`stage_b_publish_allowed`]: crate::content_policy::stage_b_publish_allowed
//! [`WalrusClientError::PayloadClassDenied`]: crate::stage_b_put::WalrusClientError::PayloadClassDenied

use crate::chunk_schema::PublishPayloadClass;
use crate::content_policy::stage_b_publish_allowed;

/// The atom #113 canonical OUT: the three-way Stage B Walrus publish decision
/// the planner consults before any transport type is constructed.
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
    /// admissible only behind an owner-signature proof. This atom mints no such
    /// proof surface (the §4.4 seal-stub / wallet override is a later atom), so
    /// the planner fails it closed exactly like [`DenyClass`](Self::DenyClass).
    RequireOwnerSignature = 3,
}

impl StageBPublishDecision {
    /// One-byte wire tag for this decision (the `#[repr(u8)]` discriminant).
    #[inline]
    pub const fn tag(self) -> u8 {
        self as u8
    }
}

/// The atom #113 canonical OUT: classify a [`PublishPayloadClass`] into the
/// three-way Stage B Walrus publish [`StageBPublishDecision`].
///
/// Layered over atom #93's binary predicate — the
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
/// closed (atom #113 OD-1 = R1, user-locked).
///
/// [`stage_b_publish_allowed`]: crate::content_policy::stage_b_publish_allowed
#[inline]
pub const fn stage_b_publish_decision(class: PublishPayloadClass) -> StageBPublishDecision {
    // Admit iff atom #93's binary predicate admits (today: SyntheticPublicFixture
    // only). Reusing the predicate — not re-matching the admitted class — binds
    // the two policies so they cannot drift.
    if stage_b_publish_allowed(class) {
        return StageBPublishDecision::Admit;
    }
    // Residual (non-admitted) classes. The single positive RealUserMemory arm
    // records the owner-signature dimension; the `_` wildcard denies every other
    // class — including any future `#[non_exhaustive]` Stage A class — by
    // construction (default-deny inherited from #93).
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

    /// Layer binding: the decision admits **iff** atom #93's binary predicate
    /// admits. Proves `stage_b_publish_decision` is layered over
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
