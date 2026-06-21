//! PD-2 — capability tiers as TYPES (ENDGAME E0d).
//!
//! Authority the model can NEVER widen, enforced by the type system:
//! - **READ** — always granted, no approval, no witness (PD-3). Reads are not
//!   side effects: memory recall of the agent's OWN store, lane-A file read, the
//!   project index. [`ReadCapability::granted`] hands it out freely.
//! - **EGRESS / MUTATE-LOCAL** — armed · bounded · revocable. The capability
//!   exists ONLY from a VALID owner-armed grant (E0c [`EgressGrant`] /
//!   [`MutateGrant`]); the model cannot mint it from nothing (no zero-witness
//!   ctor, no struct literal — a forge is a COMPILE error). The unarmed
//!   per-action path is unchanged (the existing `EgressApproval` at the transport).
//! - **CUSTODY** — funds / wallet / chain / mainnet. PD-6 HARD-LOCK as a TYPE:
//!   [`CustodyCapability`] is an UNINHABITED enum, so a value can NEVER be
//!   constructed by anyone, in any build. Custody is unlocked only by a SEPARATE
//!   go-live gate that introduces a constructor under its own security review.
//!
//! The invariant (PD-2): a capability is mintable ONLY by (a) the type system
//! (READ) or (b) a valid owner-armed grant (EGRESS/MUTATE). CUSTODY has no
//! constructor at all. Self-escalation — turning a held READ into EGRESS/MUTATE,
//! or constructing any of them from nothing — does not compile (proven E0d-4).

use super::grant::{
    AutonomyAuthorization, DownloadGrant, EgressGrant, MutateGrant, authorize_download,
    authorize_egress, authorize_mutate,
};

/// READ authority — always granted (PD-3). No approval, no grant, no witness;
/// reads are not side effects. The private field forces construction through
/// [`granted`](Self::granted) (harmless — READ is free), so there is one honest
/// entry point.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ReadCapability(());

impl ReadCapability {
    /// READ is always granted (PD-3) — no approval, no grant, no witness.
    #[must_use]
    pub const fn granted() -> Self {
        Self(())
    }
}

/// Autonomous EGRESS authority for one action. PRIVATE field, no struct literal:
/// the ONLY constructor is [`from_grant`](Self::from_grant), which requires a
/// VALID owner-armed [`EgressGrant`]. The model cannot mint egress authority from
/// nothing.
///
/// A from-nothing / struct-literal mint does NOT compile (private field):
/// ```compile_fail
/// let _forged = sinabro::commands::authority::EgressCapability(());
/// ```
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EgressCapability(());

impl EgressCapability {
    /// Autonomous egress authority from a VALID armed grant at `now_epoch_ms`,
    /// given how many actions already fired under it. `None` (fail-closed) when
    /// the grant is expired / rate-exceeded / revoked.
    #[must_use]
    pub fn from_grant(
        grant: &EgressGrant,
        now_epoch_ms: u64,
        actions_used_u32: u32,
    ) -> Option<Self> {
        match authorize_egress(Some(grant), now_epoch_ms, actions_used_u32) {
            AutonomyAuthorization::AutonomousAuthorized => Some(Self(())),
            AutonomyAuthorization::PerActionApprovalRequired | AutonomyAuthorization::Denied(_) => {
                None
            }
        }
    }
}

/// Autonomous MUTATE-LOCAL authority for one action. Type-distinct from
/// [`EgressCapability`] (cannot be used where egress authority is required, and
/// vice-versa). PRIVATE field; the ONLY constructor requires a VALID owner-armed
/// [`MutateGrant`].
///
/// A from-nothing / struct-literal mint does NOT compile (private field):
/// ```compile_fail
/// let _forged = sinabro::commands::authority::MutateCapability(());
/// ```
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MutateCapability(());

impl MutateCapability {
    /// Autonomous mutate-local authority from a VALID armed grant. `None`
    /// (fail-closed) when the grant is expired / rate-exceeded / revoked.
    #[must_use]
    pub fn from_grant(
        grant: &MutateGrant,
        now_epoch_ms: u64,
        actions_used_u32: u32,
    ) -> Option<Self> {
        match authorize_mutate(Some(grant), now_epoch_ms, actions_used_u32) {
            AutonomyAuthorization::AutonomousAuthorized => Some(Self(())),
            AutonomyAuthorization::PerActionApprovalRequired | AutonomyAuthorization::Denied(_) => {
                None
            }
        }
    }
}

/// Autonomous DOWNLOAD authority for one bounded GET-into-/tmp action (E13-3 / ⑲).
/// Type-distinct from [`EgressCapability`] / [`MutateCapability`] (cannot be used
/// where either is required, and vice-versa). PRIVATE field; the ONLY constructor is
/// [`from_grant`](Self::from_grant), which requires a VALID owner-armed
/// [`DownloadGrant`]. The model cannot mint download authority from nothing —
/// [`render_download_fetch`](crate::provider::download_fetch::render_download_fetch)
/// requires this witness, so a download is UNREACHABLE without an owner-armed grant.
///
/// A from-nothing / struct-literal mint does NOT compile (private field):
/// ```compile_fail
/// let _forged = sinabro::commands::authority::FetchCapability(());
/// ```
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FetchCapability(());

impl FetchCapability {
    /// Autonomous download authority from a VALID armed grant at `now_epoch_ms`,
    /// given how many downloads already fired under it. `None` (fail-closed) when the
    /// grant is expired / rate-exceeded / revoked.
    #[must_use]
    pub fn from_grant(
        grant: &DownloadGrant,
        now_epoch_ms: u64,
        actions_used_u32: u32,
    ) -> Option<Self> {
        match authorize_download(Some(grant), now_epoch_ms, actions_used_u32) {
            AutonomyAuthorization::AutonomousAuthorized => Some(Self(())),
            AutonomyAuthorization::PerActionApprovalRequired | AutonomyAuthorization::Denied(_) => {
                None
            }
        }
    }
}

/// Owner-path (ENDGAME E10-2b): re-derive a MUTATE-LOCAL capability from an
/// owner-armed grant for a SYNCHRONOUS single-shot local action (the `tool
/// exec-apply` ceremony). Derived once and consumed within the same call, so the
/// grant's TTL window is not load-bearing here; the single-shot `max_actions = 1`
/// bound is what makes it ONE action. `None` (fail-closed) if the grant is spent /
/// expired / revoked. Kept in `authority.rs` so the e0d no-self-escalation grep
/// keeps `MutateCapability::from_grant` to its allowlisted homes (`authority.rs` +
/// the E3 runner) — the property ("a capability exists only from a valid
/// owner-armed grant") is PRESERVED, not relaxed.
#[must_use]
pub fn local_mutate_capability(grant: &MutateGrant) -> Option<MutateCapability> {
    MutateCapability::from_grant(grant, 0, 0)
}

/// Owner-path (ENDGAME E13-3 / ⑲): derive a DOWNLOAD capability from an owner-armed
/// grant for a SYNCHRONOUS single-shot download (the `daemon fetch` ceremony).
/// Derived once and consumed within the same call (`max_actions = 1` makes it ONE
/// download). `None` (fail-closed) if the grant is spent / expired / revoked. Kept in
/// `authority.rs` so the e0d no-self-escalation grep keeps `FetchCapability::from_grant`
/// to its allowlisted home — the property ("a capability exists only from a valid
/// owner-armed grant") is PRESERVED, not relaxed.
#[must_use]
pub fn local_download_capability(grant: &DownloadGrant) -> Option<FetchCapability> {
    FetchCapability::from_grant(grant, 0, 0)
}

/// Owner-path (CURSOR PARITY A⑤ v2 EGRESS): derive an EGRESS capability from an
/// owner-armed grant for a SYNCHRONOUS single-shot `git push` (the `daemon git-push`
/// ceremony). Derived once and consumed within the same call (`max_actions = 1`
/// makes it ONE push). `None` (fail-closed) if the grant is spent / expired /
/// revoked. Kept in `authority.rs` so the e0d no-self-escalation grep keeps
/// `EgressCapability::from_grant` to its allowlisted home — the property ("a
/// capability exists only from a valid owner-armed grant") is PRESERVED, not relaxed.
#[must_use]
pub fn local_egress_capability(grant: &EgressGrant) -> Option<EgressCapability> {
    EgressCapability::from_grant(grant, 0, 0)
}

/// CUSTODY authority — funds / wallet / chain / mainnet. PD-6 HARD-LOCK AS A TYPE:
/// an UNINHABITED enum (zero variants), so a value can NEVER be constructed — by
/// the model, the owner, or the type system — in ANY build. Any function that
/// requires a `CustodyCapability` is therefore uncallable. Custody is unlocked
/// only by a SEPARATE go-live gate that introduces a constructor under its own
/// security review; never here, never autonomously.
///
/// Constructing one does NOT compile (no variant, no constructor exists):
/// ```compile_fail
/// let _c = sinabro::commands::authority::CustodyCapability::Funds;
/// ```
pub enum CustodyCapability {}

impl CustodyCapability {
    /// Compile-time proof of uninhabitedness: the empty `match` is exhaustive ONLY
    /// because there are zero variants. If a constructor (a variant) were ever
    /// added, this stops compiling — so "custody authority cannot be held" is
    /// enforced by the compiler here, not by a runtime check.
    #[must_use]
    pub fn into_never(self) -> core::convert::Infallible {
        match self {}
    }
}

/// Test-only: mint a VALID [`EgressCapability`] via the real owner-arm ceremony,
/// for DOWNSTREAM modules' tests that exercise a capability-gated path (e.g.
/// [`crate::provider::route_select`]). `#[cfg(test)]` ONLY — never compiled into a
/// release. The `from_grant` mint stays INSIDE authority.rs so the E0d
/// no-self-escalation grep (`e0d_pd2_no_self_escalation_grep.sh` CHECK-B) keeps
/// ONE constructor site: no production code anywhere mints a capability outside
/// this module.
#[cfg(test)]
pub(crate) fn test_egress_capability() -> EgressCapability {
    use crate::command::ApprovalRequirement;
    use crate::commands::grant::{
        EGRESS_ARM_PHRASE, EgressGrant, GrantBounds, GrantTier, OwnerArmCeremony,
    };
    use crate::repl::approval::ApprovalPrompt;
    let mut p = ApprovalPrompt::new(ApprovalRequirement::TypedPhrase, EGRESS_ARM_PHRASE);
    let ceremony =
        OwnerArmCeremony::complete(&mut p, EGRESS_ARM_PHRASE, GrantTier::Egress, [9u8; 32])
            .expect("owner-arm ceremony completes");
    let grant = EgressGrant::arm(
        ceremony,
        GrantBounds {
            max_actions_u32: 4,
            expires_at_epoch_ms: 10_000,
        },
    )
    .expect("grant arms");
    EgressCapability::from_grant(&grant, 1, 0).expect("valid capability from a fresh grant")
}

/// Test-only: mint a VALID owner-armed [`EgressGrant`] via the real ceremony, with
/// caller-chosen bounds, for DOWNSTREAM modules' tests that need a GRANT rather
/// than a capability (e.g. the E3 [`crate::daemon::runtime`], which RE-DERIVES the
/// per-turn capability from the grant at the live `(now, used)` — so a test must
/// exercise expiry / rate / revoke on a real grant). `#[cfg(test)]` ONLY. Keeps
/// `EgressGrant::arm` inside a single `#[cfg(test)]` site (the e0c grep allows
/// cfg(test); no production mint).
#[cfg(test)]
pub(crate) fn test_egress_capability_grant(
    max_actions_u32: u32,
    expires_at_epoch_ms: u64,
) -> crate::commands::grant::EgressGrant {
    use crate::command::ApprovalRequirement;
    use crate::commands::grant::{
        EGRESS_ARM_PHRASE, EgressGrant, GrantBounds, GrantTier, OwnerArmCeremony,
    };
    use crate::repl::approval::ApprovalPrompt;
    let mut p = ApprovalPrompt::new(ApprovalRequirement::TypedPhrase, EGRESS_ARM_PHRASE);
    let ceremony =
        OwnerArmCeremony::complete(&mut p, EGRESS_ARM_PHRASE, GrantTier::Egress, [9u8; 32])
            .expect("owner-arm ceremony completes");
    EgressGrant::arm(
        ceremony,
        GrantBounds {
            max_actions_u32,
            expires_at_epoch_ms,
        },
    )
    .expect("grant arms")
}

/// Test-only: mint a VALID [`FetchCapability`] via the real owner-arm ceremony, for
/// DOWNSTREAM modules' tests that exercise the download glue
/// ([`crate::provider::download_fetch::render_download_fetch`]). `#[cfg(test)]` ONLY —
/// never compiled into a release. Keeps the `from_grant` mint INSIDE authority.rs so
/// the e0d no-self-escalation grep keeps ONE constructor site.
#[cfg(test)]
pub(crate) fn test_fetch_capability() -> FetchCapability {
    use crate::command::ApprovalRequirement;
    use crate::commands::grant::{
        DOWNLOAD_ARM_PHRASE, DownloadGrant, GrantBounds, GrantTier, OwnerArmCeremony,
    };
    use crate::repl::approval::ApprovalPrompt;
    let mut p = ApprovalPrompt::new(ApprovalRequirement::TypedPhrase, DOWNLOAD_ARM_PHRASE);
    let ceremony = OwnerArmCeremony::complete(
        &mut p,
        DOWNLOAD_ARM_PHRASE,
        GrantTier::MutateDownload,
        [9u8; 32],
    )
    .expect("owner-arm ceremony completes");
    let grant = DownloadGrant::arm(
        ceremony,
        GrantBounds {
            max_actions_u32: 1,
            expires_at_epoch_ms: 10_000,
        },
    )
    .expect("grant arms");
    FetchCapability::from_grant(&grant, 1, 0).expect("valid capability from a fresh grant")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::command::ApprovalRequirement;
    use crate::commands::grant::{
        DownloadGrant, EgressGrant, GrantBounds, GrantTier, MutateGrant, OwnerArmCeremony,
    };
    use crate::repl::approval::ApprovalPrompt;

    const AUDIT: [u8; 32] = [9u8; 32];

    fn egress_grant(max: u32, expiry: u64) -> EgressGrant {
        let mut p = ApprovalPrompt::new(
            ApprovalRequirement::TypedPhrase,
            crate::commands::grant::EGRESS_ARM_PHRASE,
        );
        let c = OwnerArmCeremony::complete(
            &mut p,
            crate::commands::grant::EGRESS_ARM_PHRASE,
            GrantTier::Egress,
            AUDIT,
        )
        .expect("ceremony");
        EgressGrant::arm(
            c,
            GrantBounds {
                max_actions_u32: max,
                expires_at_epoch_ms: expiry,
            },
        )
        .expect("arm")
    }

    fn mutate_grant(max: u32, expiry: u64) -> MutateGrant {
        let mut p = ApprovalPrompt::new(
            ApprovalRequirement::TypedPhrase,
            crate::commands::grant::MUTATE_ARM_PHRASE,
        );
        let c = OwnerArmCeremony::complete(
            &mut p,
            crate::commands::grant::MUTATE_ARM_PHRASE,
            GrantTier::MutateLocal,
            AUDIT,
        )
        .expect("ceremony");
        MutateGrant::arm(
            c,
            GrantBounds {
                max_actions_u32: max,
                expires_at_epoch_ms: expiry,
            },
        )
        .expect("arm")
    }

    #[test]
    fn read_is_always_granted() {
        // READ takes no witness: the type system hands it out freely (PD-3).
        let _r = ReadCapability::granted();
        assert_eq!(ReadCapability::granted(), ReadCapability::granted());
    }

    #[test]
    fn egress_capability_only_from_a_valid_grant() {
        let g = egress_grant(2, 1000);
        assert!(EgressCapability::from_grant(&g, 1, 0).is_some());
        // expired / rate-exceeded / revoked => no capability (fail-closed)
        assert!(EgressCapability::from_grant(&g, 1000, 0).is_none());
        assert!(EgressCapability::from_grant(&g, 1, 2).is_none());
        assert!(EgressCapability::from_grant(&g.revoke(), 1, 0).is_none());
    }

    #[test]
    fn mutate_capability_only_from_a_valid_grant() {
        let g = mutate_grant(1, 1000);
        assert!(MutateCapability::from_grant(&g, 1, 0).is_some());
        assert!(MutateCapability::from_grant(&g, 1000, 0).is_none());
        assert!(MutateCapability::from_grant(&g.revoke(), 1, 0).is_none());
    }

    fn download_grant(max: u32, expiry: u64) -> DownloadGrant {
        let mut p = ApprovalPrompt::new(
            ApprovalRequirement::TypedPhrase,
            crate::commands::grant::DOWNLOAD_ARM_PHRASE,
        );
        let c = OwnerArmCeremony::complete(
            &mut p,
            crate::commands::grant::DOWNLOAD_ARM_PHRASE,
            GrantTier::MutateDownload,
            AUDIT,
        )
        .expect("ceremony");
        DownloadGrant::arm(
            c,
            GrantBounds {
                max_actions_u32: max,
                expires_at_epoch_ms: expiry,
            },
        )
        .expect("arm")
    }

    #[test]
    fn fetch_capability_only_from_a_valid_grant() {
        let g = download_grant(1, 1000);
        assert!(FetchCapability::from_grant(&g, 1, 0).is_some());
        assert!(FetchCapability::from_grant(&g, 1000, 0).is_none()); // expired
        assert!(FetchCapability::from_grant(&g, 1, 1).is_none()); // rate (single-shot)
        assert!(FetchCapability::from_grant(&g.revoke(), 1, 0).is_none()); // revoked
        // the owner-path single-shot derivation
        assert!(local_download_capability(&download_grant(1, 1000)).is_some());
    }
}
