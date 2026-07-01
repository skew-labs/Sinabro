//! SI-3 — unforgeable owner-armed capability grants (ENDGAME E0c).
//!
//! PD-2 names two ARMABLE capability tiers: **EGRESS** (provider consult /
//! telegram / fan) and **MUTATE-LOCAL** (exec / file-apply). Default-unarmed they
//! stay per-action approved (today's gate). The owner ARMS a session / time /
//! rate-boxed grant ("I'm stepping away"); egress/mutate then fires autonomously
//! WITHIN the bounds, auto-expires, and is revocable. (The daemon that CONSUMES a
//! grant to fire autonomously is E3 — this module only mints + validates the
//! token, and leaves every live per-action path unchanged.)
//!
//! # The SI-3 invariant (unforgeable token)
//!
//! A grant has a PRIVATE field and NO public struct literal. The ONLY way to
//! obtain one is [`EgressGrant::arm`] / [`MutateGrant::arm`], which consume an
//! [`OwnerArmCeremony`] — itself obtainable ONLY by completing a typed-phrase
//! [`ApprovalPrompt`](crate::repl::approval::ApprovalPrompt) (exact match,
//! replay-deny, bare-Enter-never-approves) AND supplying a non-zero audit hash
//! (no silent grant — mirrors [`PermissionRuleView`](crate::repl::approval::PermissionRuleView)).
//! Consequences:
//! - a grant cannot be struct-literal'd outside this module (private field) — a
//!   forge is a COMPILE error (PD-4 "the bad state does not compile");
//! - an `ApprovalDecision::Approved` (a public enum) is NOT sufficient to mint a
//!   ceremony — you need a real, consumed typed-phrase evaluation;
//! - a ceremony is tier-bound, so an EGRESS ceremony cannot arm a `MutateGrant`
//!   (and vice-versa) — no cross-tier privilege confusion;
//! - the model/agent path holds no ceremony and constructs no grant
//!   (`agent_loop` never references `arm`/`complete` — grep-proven, E0c-4), so
//!   self-escalation is not reachable.
//!
//! CUSTODY (funds / wallet / chain / mainnet) is deliberately NOT representable
//! here — there is no custody [`GrantTier`] variant (PD-6 HARD-LOCK).

use crate::repl::approval::ApprovalPrompt;

const ZERO32: [u8; 32] = [0u8; 32];

/// Which armed tier a grant authorizes. CUSTODY is deliberately ABSENT (PD-6):
/// funds/wallet/chain/mainnet are never armable.
#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GrantTier {
    /// Network egress — provider consult / telegram / fan.
    Egress = 1,
    /// Local mutation — exec / file-apply. STRICTER: armed only by its own
    /// explicit, distinct ceremony (per PD-2 MUTATE-LOCAL).
    MutateLocal = 2,
    /// Bounded network download — an owner-armed GET that fetches UNTRUSTED bytes
    /// into a temp file (ENDGAME E13-3 / ⑲). STRICTER than egress: it egresses AND
    /// persists untrusted bytes, so it is armed ONLY by its own distinct ceremony
    /// ([`DOWNLOAD_ARM_PHRASE`]) — the egress gesture can never authorize a download
    /// (PD-2: a tier is armed only by its own phrase). CUSTODY is still ABSENT.
    MutateDownload = 3,
    /// Composite BOLD SESSION — one owner gesture ([`BOLD_ARM_PHRASE`]) that arms
    /// BOTH egress AND mutate-local for a bounded, revocable session: bold-within-
    /// bounds (the agent's proposed edits + runs AUTO-EXECUTE with NO per-action
    /// approval inside the armed workspace; an in-session frontier consult fires
    /// within the egress bound) — ENDGAME E13-4 / ⑳. It composes the EXISTING grant
    /// types (no new capability type). It does NOT arm download (D-BS4) and CUSTODY
    /// is still ABSENT (PD-6). A `BoldSession` ceremony arms ONLY a [`BoldSessionGrant`]
    /// (via [`arm_bold_session`]) — never a plain single-tier grant (compile-forced).
    BoldSession = 4,
    /// User-BOUNDED CUSTODY — a single on-chain transaction within an owner-armed
    /// bound (per-tx max · total budget · chain/protocol allowlist · TTL · revoke ·
    /// kill). ONCHAIN PIVOT C-0: REPLACES the blanket PD-6 funds-lock with a BOUNDED
    /// grant. It does NOT inhabit [`crate::commands::authority::CustodyCapability`]
    /// (that stays UNINHABITED — blanket/unbounded custody is STILL impossible); it
    /// mints the NEW, distinct [`crate::commands::authority::ChainTxCapability`]. Armed
    /// ONLY by its own [`CUSTODY_ARM_PHRASE`]; never inbound-armable; the model holds
    /// no phrase, so it cannot arm custody.
    Custody = 5,
}

/// The arming typed-phrase for the EGRESS tier (the owner types this EXACTLY at
/// the arm ceremony; distinct from the mutate phrase so the tiers cannot be
/// armed by the same gesture).
pub const EGRESS_ARM_PHRASE: &str = "arm-egress-autonomy-bounded-revocable";
/// The arming typed-phrase for the (stricter) MUTATE-LOCAL tier.
pub const MUTATE_ARM_PHRASE: &str = "arm-mutate-local-autonomy-bounded-revocable";
/// The arming typed-phrase for the (stricter) MUTATE-DOWNLOAD tier (E13-3 / ⑲). A
/// distinct gesture so a download is NEVER armed by the egress / mutate phrase
/// (PD-2). The model holds no `ApprovalPrompt` and types no phrase, so it cannot arm.
pub const DOWNLOAD_ARM_PHRASE: &str = "arm-download-bounded-revocable";
/// The arming typed-phrase for the (composite) BOLD-SESSION tier (E13-4 / ⑳). A
/// DISTINCT gesture: one owner phrase explicitly arms BOTH egress AND mutate-local for
/// a bounded, revocable session (bold-within-bounds). It does NOT arm download (D-BS4)
/// or custody (PD-6, uninhabited). The model holds no `ApprovalPrompt` and types no
/// phrase, so it cannot arm a bold session.
pub const BOLD_ARM_PHRASE: &str = "arm-bold-session-edit-run-bounded-revocable";
/// The arming typed-phrase for the user-BOUNDED CUSTODY tier (ONCHAIN PIVOT C-0). A
/// DISTINCT gesture: the owner arms a per-tx-max / total-budget / chain+protocol-allowlist
/// / TTL bound for on-chain transactions. NEVER armed by any other phrase (PD-2) and NEVER
/// inbound-armable (custody is local-owner-ceremony only). The model holds no
/// [`ApprovalPrompt`] and types no phrase, so it cannot arm custody.
pub const CUSTODY_ARM_PHRASE: &str = "arm-custody-chain-tx-bounded-revocable";

/// Proof that the owner completed the arming typed-phrase ceremony this turn,
/// bound to the tier it was completed for. PRIVATE fields + the ONLY constructor
/// ([`complete`](Self::complete)) evaluates a typed-phrase prompt — so it cannot
/// be struct-literal'd, and a public `ApprovalDecision::Approved` is NOT enough.
///
/// A hand-forged ceremony does NOT compile (private fields, no public ctor):
/// ```compile_fail
/// let _forged = sinabro::commands::grant::OwnerArmCeremony {
///     tier: sinabro::commands::grant::GrantTier::Egress,
///     audit_hash_32: [0u8; 32],
/// };
/// ```
#[derive(Clone, Copy, Debug)]
pub struct OwnerArmCeremony {
    tier: GrantTier,
    audit_hash_32: [u8; 32],
}

impl OwnerArmCeremony {
    /// Complete the arm ceremony for `tier`. Returns `Some` ONLY when the owner's
    /// `response` exactly matches the arming typed-phrase carried by `prompt`
    /// (consuming it — replay-deny) AND a non-zero `audit_hash_32` is supplied (no
    /// silent grant). Returns `None` otherwise — fail-closed.
    ///
    /// `prompt` MUST be a `TypedPhrase` prompt built with the tier's arm phrase
    /// ([`EGRESS_ARM_PHRASE`] / [`MUTATE_ARM_PHRASE`]); the caller (the owner-input
    /// command path) owns that binding.
    #[must_use]
    pub fn complete(
        prompt: &mut ApprovalPrompt,
        response: &str,
        tier: GrantTier,
        audit_hash_32: [u8; 32],
    ) -> Option<Self> {
        if audit_hash_32 == ZERO32 {
            return None;
        }
        if prompt.evaluate(response).is_approved() {
            Some(Self {
                tier,
                audit_hash_32,
            })
        } else {
            None
        }
    }

    /// The tier this ceremony was completed for.
    #[must_use]
    pub const fn tier(&self) -> GrantTier {
        self.tier
    }
}

/// The session bounds an armed grant is boxed by (PD-2: session / time / rate).
/// Every bound is an UPPER limit; a grant authorizes an action ONLY while it is
/// unexpired, within the action cap, and unrevoked.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct GrantBounds {
    /// Maximum autonomous actions permitted under this grant (the rate/turn cap).
    pub max_actions_u32: u32,
    /// Expiry epoch (ms). The grant is dead AT or AFTER this instant.
    pub expires_at_epoch_ms: u64,
}

/// Why an armed grant did not authorize an action (fail-closed; explicit).
#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GrantDenied {
    /// `now >= expires_at` — the arm window ended.
    Expired = 1,
    /// `actions_used >= max_actions` — the autonomous budget is spent.
    RateExceeded = 2,
    /// The owner revoked the grant.
    Revoked = 3,
}

/// A grant's authorization verdict for one action.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GrantAuthorization {
    /// The grant authorizes this autonomous action.
    Authorized,
    /// The grant does not authorize it (with the reason).
    Denied(GrantDenied),
}

/// The shared, PRIVATE grant core. Not constructible or nameable outside this
/// module — both public grant newtypes wrap it, so neither can be struct-literal'd
/// by an external (or agent) code path.
#[derive(Clone, Copy, Debug)]
struct GrantCore {
    bounds: GrantBounds,
    audit_hash_32: [u8; 32],
    revoked: bool,
}

impl GrantCore {
    const fn new(audit_hash_32: [u8; 32], bounds: GrantBounds) -> Self {
        Self {
            bounds,
            audit_hash_32,
            revoked: false,
        }
    }

    const fn authorize(&self, now_epoch_ms: u64, actions_used_u32: u32) -> GrantAuthorization {
        if self.revoked {
            return GrantAuthorization::Denied(GrantDenied::Revoked);
        }
        if now_epoch_ms >= self.bounds.expires_at_epoch_ms {
            return GrantAuthorization::Denied(GrantDenied::Expired);
        }
        if actions_used_u32 >= self.bounds.max_actions_u32 {
            return GrantAuthorization::Denied(GrantDenied::RateExceeded);
        }
        GrantAuthorization::Authorized
    }

    const fn revoke(self) -> Self {
        Self {
            revoked: true,
            ..self
        }
    }
}

/// An owner-armed EGRESS grant. Unforgeable: private field, no struct literal;
/// the ONLY constructor is [`arm`](Self::arm), which consumes an
/// [`OwnerArmCeremony`] completed for [`GrantTier::Egress`].
///
/// A hand-forged grant does NOT compile (private field, no public ctor) — so an
/// agent cannot mint authority by struct literal:
/// ```compile_fail
/// let _forged = sinabro::commands::grant::EgressGrant(todo!());
/// ```
#[derive(Clone, Copy, Debug)]
pub struct EgressGrant(GrantCore);

impl EgressGrant {
    /// Arm an egress grant from a completed egress ceremony + bounds. Returns
    /// `None` if the ceremony was for a different tier (no cross-tier arming) —
    /// the ONLY constructor.
    #[must_use]
    pub fn arm(ceremony: OwnerArmCeremony, bounds: GrantBounds) -> Option<Self> {
        match ceremony.tier {
            GrantTier::Egress => Some(Self(GrantCore::new(ceremony.audit_hash_32, bounds))),
            GrantTier::MutateLocal
            | GrantTier::MutateDownload
            | GrantTier::BoldSession
            | GrantTier::Custody => None,
        }
    }

    /// Fail-closed authorization for one egress action at `now_epoch_ms`, given
    /// how many actions have already fired under this grant.
    #[must_use]
    pub const fn authorize(&self, now_epoch_ms: u64, actions_used_u32: u32) -> GrantAuthorization {
        self.0.authorize(now_epoch_ms, actions_used_u32)
    }

    /// Revoke the grant (returns a revoked copy; [`authorize`](Self::authorize)
    /// then always denies with [`GrantDenied::Revoked`]).
    #[must_use]
    pub const fn revoke(self) -> Self {
        Self(self.0.revoke())
    }

    /// The audit hash bound at arm time.
    #[must_use]
    pub const fn audit_hash_32(&self) -> [u8; 32] {
        self.0.audit_hash_32
    }

    /// The tier this grant authorizes (always [`GrantTier::Egress`]).
    #[must_use]
    pub const fn tier(&self) -> GrantTier {
        GrantTier::Egress
    }
}

/// An owner-armed MUTATE-LOCAL grant (exec / file-apply). STRICTER than egress:
/// type-distinct (cannot authorize egress, and an egress ceremony cannot arm it)
/// and armed only by its own explicit ceremony ([`MUTATE_ARM_PHRASE`]).
#[derive(Clone, Copy, Debug)]
pub struct MutateGrant(GrantCore);

impl MutateGrant {
    /// Arm a mutate-local grant from a completed mutate ceremony + bounds. Returns
    /// `None` if the ceremony was for a different tier — the ONLY constructor.
    #[must_use]
    pub fn arm(ceremony: OwnerArmCeremony, bounds: GrantBounds) -> Option<Self> {
        match ceremony.tier {
            GrantTier::MutateLocal => Some(Self(GrantCore::new(ceremony.audit_hash_32, bounds))),
            GrantTier::Egress
            | GrantTier::MutateDownload
            | GrantTier::BoldSession
            | GrantTier::Custody => None,
        }
    }

    /// Fail-closed authorization for one mutate-local action at `now_epoch_ms`.
    #[must_use]
    pub const fn authorize(&self, now_epoch_ms: u64, actions_used_u32: u32) -> GrantAuthorization {
        self.0.authorize(now_epoch_ms, actions_used_u32)
    }

    /// Revoke the grant.
    #[must_use]
    pub const fn revoke(self) -> Self {
        Self(self.0.revoke())
    }

    /// The audit hash bound at arm time.
    #[must_use]
    pub const fn audit_hash_32(&self) -> [u8; 32] {
        self.0.audit_hash_32
    }

    /// The tier this grant authorizes (always [`GrantTier::MutateLocal`]).
    #[must_use]
    pub const fn tier(&self) -> GrantTier {
        GrantTier::MutateLocal
    }
}

/// The egress authorization decision for an action that wants to fire. This is
/// the typed seam the E3 daemon consumes; it does NOT touch the live per-action
/// paths (no regression). Fail-closed: a present-but-invalid grant does NOT
/// silently fall back to autonomous firing.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AutonomyAuthorization {
    /// No armed grant: the per-action same-message approval is required (today's
    /// default, unchanged).
    PerActionApprovalRequired,
    /// A valid armed grant authorizes this autonomous action.
    AutonomousAuthorized,
    /// A grant was presented but is invalid (expired / rate / revoked): the
    /// autonomous path is DENIED with the reason. The consumer may still fall back
    /// to per-action approval, but it never fires autonomously on an invalid grant.
    Denied(GrantDenied),
}

/// Authorize one EGRESS action: no grant ⇒ per-action approval; valid grant ⇒
/// autonomous; invalid grant ⇒ denied (with reason). Pure + fail-closed.
#[must_use]
pub const fn authorize_egress(
    grant: Option<&EgressGrant>,
    now_epoch_ms: u64,
    actions_used_u32: u32,
) -> AutonomyAuthorization {
    match grant {
        None => AutonomyAuthorization::PerActionApprovalRequired,
        Some(g) => match g.authorize(now_epoch_ms, actions_used_u32) {
            GrantAuthorization::Authorized => AutonomyAuthorization::AutonomousAuthorized,
            GrantAuthorization::Denied(reason) => AutonomyAuthorization::Denied(reason),
        },
    }
}

/// Authorize one MUTATE-LOCAL action (mirror of [`authorize_egress`]).
#[must_use]
pub const fn authorize_mutate(
    grant: Option<&MutateGrant>,
    now_epoch_ms: u64,
    actions_used_u32: u32,
) -> AutonomyAuthorization {
    match grant {
        None => AutonomyAuthorization::PerActionApprovalRequired,
        Some(g) => match g.authorize(now_epoch_ms, actions_used_u32) {
            GrantAuthorization::Authorized => AutonomyAuthorization::AutonomousAuthorized,
            GrantAuthorization::Denied(reason) => AutonomyAuthorization::Denied(reason),
        },
    }
}

/// Owner-path (ENDGAME E10-2b): arm a MUTATE-LOCAL grant from a typed-phrase
/// ceremony completed THIS turn. This is the SINGLE home for the mutate ceremony +
/// arm (the e0c SI-3 allowlist), used by BOTH the synchronous single-shot local
/// `tool exec-apply` ceremony (`bounds = 1 action`) and the broad owner-armed
/// autonomy window ([`MUTATE_ARM_PHRASE`], `bounds = a few actions / short TTL`).
/// `None` (fail-closed) on a wrong/replayed phrase or a tier mismatch. The
/// unforgeable gate is the ceremony: the model holds no [`ApprovalPrompt`] and
/// types no phrase, so it cannot reach this path (the property the e0c grep
/// proves is PRESERVED — a grant is minted only via the owner-arm ceremony).
#[must_use]
pub fn arm_local_mutate_grant(
    prompt: &mut ApprovalPrompt,
    response: &str,
    audit_hash_32: [u8; 32],
    bounds: GrantBounds,
) -> Option<MutateGrant> {
    let ceremony =
        OwnerArmCeremony::complete(prompt, response, GrantTier::MutateLocal, audit_hash_32)?;
    MutateGrant::arm(ceremony, bounds)
}

/// An owner-armed DOWNLOAD grant (a bounded network GET that fetches UNTRUSTED bytes
/// into a temp file; E13-3 / ⑲). STRICTER than egress + type-distinct: it cannot
/// authorize egress or mutate-local, and neither of their ceremonies can arm it —
/// only a [`GrantTier::MutateDownload`] ceremony ([`DOWNLOAD_ARM_PHRASE`]) does.
/// Unforgeable: private field, no struct literal; [`arm`](Self::arm) is the ONLY ctor.
///
/// A hand-forged grant does NOT compile (private field, no public ctor):
/// ```compile_fail
/// let _forged = sinabro::commands::grant::DownloadGrant(todo!());
/// ```
#[derive(Clone, Copy, Debug)]
pub struct DownloadGrant(GrantCore);

impl DownloadGrant {
    /// Arm a download grant from a completed download ceremony + bounds. Returns
    /// `None` if the ceremony was for a different tier (no cross-tier arming) — the
    /// ONLY constructor.
    #[must_use]
    pub fn arm(ceremony: OwnerArmCeremony, bounds: GrantBounds) -> Option<Self> {
        match ceremony.tier {
            GrantTier::MutateDownload => Some(Self(GrantCore::new(ceremony.audit_hash_32, bounds))),
            GrantTier::Egress
            | GrantTier::MutateLocal
            | GrantTier::BoldSession
            | GrantTier::Custody => None,
        }
    }

    /// Fail-closed authorization for one download action at `now_epoch_ms`.
    #[must_use]
    pub const fn authorize(&self, now_epoch_ms: u64, actions_used_u32: u32) -> GrantAuthorization {
        self.0.authorize(now_epoch_ms, actions_used_u32)
    }

    /// Revoke the grant.
    #[must_use]
    pub const fn revoke(self) -> Self {
        Self(self.0.revoke())
    }

    /// The audit hash bound at arm time.
    #[must_use]
    pub const fn audit_hash_32(&self) -> [u8; 32] {
        self.0.audit_hash_32
    }

    /// The tier this grant authorizes (always [`GrantTier::MutateDownload`]).
    #[must_use]
    pub const fn tier(&self) -> GrantTier {
        GrantTier::MutateDownload
    }
}

/// Authorize one DOWNLOAD action: no grant ⇒ per-action approval; valid grant ⇒
/// autonomous; invalid grant ⇒ denied (with reason). Pure + fail-closed (mirror of
/// [`authorize_egress`]).
#[must_use]
pub const fn authorize_download(
    grant: Option<&DownloadGrant>,
    now_epoch_ms: u64,
    actions_used_u32: u32,
) -> AutonomyAuthorization {
    match grant {
        None => AutonomyAuthorization::PerActionApprovalRequired,
        Some(g) => match g.authorize(now_epoch_ms, actions_used_u32) {
            GrantAuthorization::Authorized => AutonomyAuthorization::AutonomousAuthorized,
            GrantAuthorization::Denied(reason) => AutonomyAuthorization::Denied(reason),
        },
    }
}

/// Owner-path (ENDGAME E13-3 / ⑲): arm a DOWNLOAD grant from a typed-phrase ceremony
/// completed THIS turn. The SINGLE home for the download ceremony + arm (the e0c SI-3
/// allowlist home, `grant.rs`), used by the single-shot owner-armed `daemon fetch`
/// verb (`bounds = 1 action / fast TTL`, revocable). `None` (fail-closed) on a
/// wrong/replayed phrase or a tier mismatch. The unforgeable gate is the ceremony:
/// the model holds no [`ApprovalPrompt`] and types no phrase, so it cannot reach this
/// path (the property the e0c grep proves is PRESERVED — a grant is minted only via
/// the owner-arm ceremony).
#[must_use]
pub fn arm_local_download_grant(
    prompt: &mut ApprovalPrompt,
    response: &str,
    audit_hash_32: [u8; 32],
    bounds: GrantBounds,
) -> Option<DownloadGrant> {
    let ceremony =
        OwnerArmCeremony::complete(prompt, response, GrantTier::MutateDownload, audit_hash_32)?;
    DownloadGrant::arm(ceremony, bounds)
}

/// An owner-armed COMPOSITE bold session grant (ENDGAME E13-4 / ⑳). One
/// [`BOLD_ARM_PHRASE`] ceremony mints BOTH an [`EgressGrant`] AND a [`MutateGrant`]
/// under the SAME bounds + audit hash, so the agent's proposed edits + runs
/// AUTO-EXECUTE within the bound with NO per-action approval, and an in-session
/// frontier consult fires within the egress bound — the Claude Code / Cursor "auto"
/// model. It composes the EXISTING grant types (the runtime fields + chokepoints
/// consume them unchanged); bold adds NO new capability type. CUSTODY is ABSENT (no
/// `GrantTier::Custody`, PD-6) and DOWNLOAD is ABSENT (D-BS4) — a bold session can never
/// arm either.
///
/// Unforgeable: PRIVATE fields, no struct literal; [`arm_bold_session`] (consuming a
/// `BoldSession` ceremony) is the ONLY ctor — a forge is a COMPILE error (PD-4):
/// ```compile_fail
/// let _forged = sinabro::commands::grant::BoldSessionGrant {
///     egress: todo!(),
///     mutate: todo!(),
/// };
/// ```
#[derive(Clone, Copy, Debug)]
pub struct BoldSessionGrant {
    egress: EgressGrant,
    mutate: MutateGrant,
}

impl BoldSessionGrant {
    /// The session's EGRESS component — installed on the runtime via
    /// [`install_egress_grant`](crate::daemon::runtime::AutonomyRuntime::install_egress_grant).
    #[must_use]
    pub const fn egress(&self) -> &EgressGrant {
        &self.egress
    }

    /// The session's MUTATE-LOCAL component — installed on the runtime via
    /// [`install_mutate_grant`](crate::daemon::runtime::AutonomyRuntime::install_mutate_grant).
    #[must_use]
    pub const fn mutate(&self) -> &MutateGrant {
        &self.mutate
    }

    /// Revoke BOTH components — the next egress/mutate re-derivation yields `None`
    /// (fail-closed; the whole bold session stops).
    #[must_use]
    pub const fn revoke(self) -> Self {
        Self {
            egress: self.egress.revoke(),
            mutate: self.mutate.revoke(),
        }
    }
}

/// Arm a COMPOSITE bold session from a completed `BoldSession` ceremony + SHARED bounds.
/// Returns `None` if the ceremony was for a different tier (no cross-tier arming) — the
/// ONLY ctor. The component [`EgressGrant`] / [`MutateGrant`] are constructed here
/// (INSIDE the e0c mint home, `grant.rs`) from the SAME audit hash + bounds, so the bold
/// session is bounded + revocable as one unit. PD-2 is preserved: a `BoldSession`
/// ceremony arms a bold session — NOT a plain single-tier grant (`EgressGrant::arm(bold)`
/// / `MutateGrant::arm(bold)` / `DownloadGrant::arm(bold)` all return `None`,
/// compile-forced) — and the egress/mutate/download gestures cannot produce a bold
/// session.
#[must_use]
pub fn arm_bold_session(
    ceremony: OwnerArmCeremony,
    bounds: GrantBounds,
) -> Option<BoldSessionGrant> {
    match ceremony.tier {
        GrantTier::BoldSession => Some(BoldSessionGrant {
            egress: EgressGrant(GrantCore::new(ceremony.audit_hash_32, bounds)),
            mutate: MutateGrant(GrantCore::new(ceremony.audit_hash_32, bounds)),
        }),
        GrantTier::Egress
        | GrantTier::MutateLocal
        | GrantTier::MutateDownload
        | GrantTier::Custody => None,
    }
}

/// Owner-path (ENDGAME E13-4 / ⑳): arm a composite bold session from a typed-phrase
/// ceremony completed THIS turn. The SINGLE home for the bold ceremony + arm (the e0c
/// SI-3 allowlist home, `grant.rs`), used by the owner-armed `daemon bold` verb. `None`
/// (fail-closed) on a wrong/replayed phrase or a tier mismatch. The unforgeable gate is
/// the ceremony: the model holds no [`ApprovalPrompt`] and types no phrase, so it cannot
/// reach this path (the e0c grep property is PRESERVED — a grant is minted only via the
/// owner-arm ceremony).
#[must_use]
pub fn arm_local_bold_session(
    prompt: &mut ApprovalPrompt,
    response: &str,
    audit_hash_32: [u8; 32],
    bounds: GrantBounds,
) -> Option<BoldSessionGrant> {
    let ceremony =
        OwnerArmCeremony::complete(prompt, response, GrantTier::BoldSession, audit_hash_32)?;
    arm_bold_session(ceremony, bounds)
}

// ===========================================================================
// ONCHAIN PIVOT C-0 — user-BOUNDED custody (a NEW bounded capability, NOT blanket).
// `CustodyCapability` (commands/authority.rs) STAYS uninhabited (blanket/unbounded custody
// is forever impossible). This block mints the bounded, owner-armed CUSTODY grant that gates
// the NEW `ChainTxCapability` — the typed authorization for ONE on-chain tx within the
// owner's bounds. C-0 is PURE/typed: it AUTHORIZES; it never signs or broadcasts (no key,
// money 0 — the real signing/transport is C-2).
// ===========================================================================

/// A proposed on-chain transaction — the typed thing a [`CustodyGrant`] authorizes against
/// its bounds. Carries only what the bound check needs (the chain, the protocol, and the
/// amount in integer MINOR units — NO float). The signing/calldata details are C-2; C-0 only
/// decides whether this request is within the owner's bound.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ChainTxRequest {
    /// The target chain (matched against the grant's `chain_allowlist`, exact).
    pub chain: String,
    /// The target protocol / contract label (matched against `protocol_allowlist`, exact).
    pub protocol: String,
    /// The transaction value in integer MINOR units (e.g. wei / lamports). NO float.
    pub amount_minor: u128,
}

/// The bounds an owner-armed CUSTODY grant boxes on-chain spending by (ONCHAIN PIVOT C-0).
/// Every field is an UPPER limit / an allowlist: a tx authorizes ONLY while the grant is
/// unexpired + within the action cap + unrevoked AND its chain/protocol are allowlisted AND
/// `amount <= per_tx_max` AND `spent + amount <= total_budget`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CustodyBounds {
    /// The reused base bounds: `max_actions` (tx-count cap) + `expires_at` (TTL).
    pub base: GrantBounds,
    /// The maximum value of a SINGLE transaction (minor units) — the user's per-tx ceiling.
    pub per_tx_max_minor: u128,
    /// The maximum CUMULATIVE value across all txs under this grant — the user's total budget.
    pub total_budget_minor: u128,
    /// The chains a tx may target (exact match). Empty ⇒ nothing authorized (fail-closed).
    pub chain_allowlist: Vec<String>,
    /// The protocols a tx may target (exact match). Empty ⇒ nothing authorized (fail-closed).
    pub protocol_allowlist: Vec<String>,
}

/// Why a custody grant did not authorize a transaction (fail-closed; explicit). The first
/// three mirror [`GrantDenied`] (the reused base); the rest are custody-specific.
#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CustodyDenied {
    /// `now >= expires_at` — the arm window ended.
    Expired = 1,
    /// `actions_used >= max_actions` — the tx-count cap is spent.
    RateExceeded = 2,
    /// The owner revoked the grant.
    Revoked = 3,
    /// `amount > per_tx_max` — the single-tx ceiling is exceeded.
    PerTxExceeded = 4,
    /// `spent + amount > total_budget` (or the sum overflowed) — the budget is exceeded.
    BudgetExceeded = 5,
    /// The tx's chain is not in the allowlist.
    ChainNotAllowed = 6,
    /// The tx's protocol is not in the allowlist.
    ProtocolNotAllowed = 7,
}

/// A custody grant's authorization verdict for one transaction.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CustodyAuthorization {
    /// The grant authorizes this on-chain transaction (within ALL bounds).
    Authorized,
    /// The grant does not authorize it (with the reason).
    Denied(CustodyDenied),
}

/// The shared, PRIVATE custody grant core — not constructible or nameable outside this module
/// (the public [`CustodyGrant`] newtype wraps it, so it cannot be struct-literal'd by any
/// external / agent path). Reuses [`GrantCore`] for expiry/rate/revoke + adds the custody bounds.
#[derive(Clone, Debug)]
struct CustodyGrantCore {
    base: GrantCore,
    per_tx_max_minor: u128,
    total_budget_minor: u128,
    chain_allowlist: Vec<String>,
    protocol_allowlist: Vec<String>,
}

impl CustodyGrantCore {
    /// Fail-closed custody authorization for ONE tx at `now`, given how many txs already
    /// fired (`actions_used`) and how much has been spent (`spent_minor`). Order: the base
    /// (revoked/expired/rate) → chain allowlist → protocol allowlist → per-tx ceiling → total
    /// budget (checked add; an overflow is denied). Every check is an upper limit; ANY failure
    /// denies (no silent authorize).
    fn authorize(
        &self,
        now_epoch_ms: u64,
        actions_used_u32: u32,
        spent_minor: u128,
        tx: &ChainTxRequest,
    ) -> CustodyAuthorization {
        match self.base.authorize(now_epoch_ms, actions_used_u32) {
            GrantAuthorization::Denied(GrantDenied::Expired) => {
                return CustodyAuthorization::Denied(CustodyDenied::Expired);
            }
            GrantAuthorization::Denied(GrantDenied::RateExceeded) => {
                return CustodyAuthorization::Denied(CustodyDenied::RateExceeded);
            }
            GrantAuthorization::Denied(GrantDenied::Revoked) => {
                return CustodyAuthorization::Denied(CustodyDenied::Revoked);
            }
            GrantAuthorization::Authorized => {}
        }
        if !self.chain_allowlist.iter().any(|c| c == &tx.chain) {
            return CustodyAuthorization::Denied(CustodyDenied::ChainNotAllowed);
        }
        if !self.protocol_allowlist.iter().any(|p| p == &tx.protocol) {
            return CustodyAuthorization::Denied(CustodyDenied::ProtocolNotAllowed);
        }
        if tx.amount_minor > self.per_tx_max_minor {
            return CustodyAuthorization::Denied(CustodyDenied::PerTxExceeded);
        }
        match spent_minor.checked_add(tx.amount_minor) {
            Some(total) if total <= self.total_budget_minor => CustodyAuthorization::Authorized,
            _ => CustodyAuthorization::Denied(CustodyDenied::BudgetExceeded),
        }
    }

    fn revoke(self) -> Self {
        Self {
            base: self.base.revoke(),
            ..self
        }
    }
}

/// An owner-armed user-BOUNDED CUSTODY grant (ONCHAIN PIVOT C-0). Type-distinct from every
/// other grant; armed ONLY by a [`GrantTier::Custody`] ceremony ([`CUSTODY_ARM_PHRASE`]).
/// Unforgeable: PRIVATE field, no struct literal; [`arm`](Self::arm) is the ONLY ctor — a
/// forge is a COMPILE error (PD-4). It gates the NEW
/// [`crate::commands::authority::ChainTxCapability`]; it does NOT touch the (uninhabited)
/// `CustodyCapability` — blanket custody stays impossible.
///
/// ```compile_fail
/// let _forged = sinabro::commands::grant::CustodyGrant(todo!());
/// ```
#[derive(Clone, Debug)]
pub struct CustodyGrant(CustodyGrantCore);

impl CustodyGrant {
    /// Arm a custody grant from a completed custody ceremony + bounds. Returns `None` if the
    /// ceremony was for a different tier (no cross-tier arming) — the ONLY constructor.
    #[must_use]
    pub fn arm(ceremony: OwnerArmCeremony, bounds: CustodyBounds) -> Option<Self> {
        match ceremony.tier {
            GrantTier::Custody => Some(Self(CustodyGrantCore {
                base: GrantCore::new(ceremony.audit_hash_32, bounds.base),
                per_tx_max_minor: bounds.per_tx_max_minor,
                total_budget_minor: bounds.total_budget_minor,
                chain_allowlist: bounds.chain_allowlist,
                protocol_allowlist: bounds.protocol_allowlist,
            })),
            GrantTier::Egress
            | GrantTier::MutateLocal
            | GrantTier::MutateDownload
            | GrantTier::BoldSession => None,
        }
    }

    /// Fail-closed authorization for one on-chain tx at `now`, given the txs already fired +
    /// the amount already spent under this grant.
    #[must_use]
    pub fn authorize(
        &self,
        now_epoch_ms: u64,
        actions_used_u32: u32,
        spent_minor: u128,
        tx: &ChainTxRequest,
    ) -> CustodyAuthorization {
        self.0
            .authorize(now_epoch_ms, actions_used_u32, spent_minor, tx)
    }

    /// Revoke the grant (the next re-derivation denies with [`CustodyDenied::Revoked`]).
    #[must_use]
    pub fn revoke(self) -> Self {
        Self(self.0.revoke())
    }

    /// The audit hash bound at arm time.
    #[must_use]
    pub fn audit_hash_32(&self) -> [u8; 32] {
        self.0.base.audit_hash_32
    }

    /// The tier this grant authorizes (always [`GrantTier::Custody`]).
    #[must_use]
    pub const fn tier(&self) -> GrantTier {
        GrantTier::Custody
    }
}

/// Owner-path (ONCHAIN PIVOT C-0): arm a user-BOUNDED custody grant from a typed-phrase
/// ceremony completed THIS turn. The SINGLE home for the custody ceremony + arm (the e0c SI-3
/// allowlist home, `grant.rs`), used by the owner-armed `daemon chain-*` verb. `None`
/// (fail-closed) on a wrong/replayed phrase or a tier mismatch. The unforgeable gate is the
/// ceremony: the model holds no [`ApprovalPrompt`] and types no phrase, so it cannot reach this
/// path — a custody grant is minted ONLY via the owner-arm ceremony.
#[must_use]
pub fn arm_local_custody_grant(
    prompt: &mut ApprovalPrompt,
    response: &str,
    audit_hash_32: [u8; 32],
    bounds: CustodyBounds,
) -> Option<CustodyGrant> {
    let ceremony = OwnerArmCeremony::complete(prompt, response, GrantTier::Custody, audit_hash_32)?;
    CustodyGrant::arm(ceremony, bounds)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::command::ApprovalRequirement;

    const AUDIT: [u8; 32] = [9u8; 32];

    fn egress_ceremony() -> Option<OwnerArmCeremony> {
        let mut p = ApprovalPrompt::new(ApprovalRequirement::TypedPhrase, EGRESS_ARM_PHRASE);
        OwnerArmCeremony::complete(&mut p, EGRESS_ARM_PHRASE, GrantTier::Egress, AUDIT)
    }

    fn bounds(max: u32, expiry: u64) -> GrantBounds {
        GrantBounds {
            max_actions_u32: max,
            expires_at_epoch_ms: expiry,
        }
    }

    #[test]
    fn ceremony_requires_exact_phrase_audit_and_no_replay() {
        // wrong phrase -> None
        let mut p = ApprovalPrompt::new(ApprovalRequirement::TypedPhrase, EGRESS_ARM_PHRASE);
        assert!(OwnerArmCeremony::complete(&mut p, "nope", GrantTier::Egress, AUDIT).is_none());
        // bare enter -> None (and a fresh prompt, since a denial does not consume)
        assert!(OwnerArmCeremony::complete(&mut p, "", GrantTier::Egress, AUDIT).is_none());
        // zero audit -> None even with the right phrase
        assert!(
            OwnerArmCeremony::complete(&mut p, EGRESS_ARM_PHRASE, GrantTier::Egress, ZERO32)
                .is_none()
        );
        // correct phrase + audit -> Some, and the prompt is now consumed (replay-deny)
        assert!(
            OwnerArmCeremony::complete(&mut p, EGRESS_ARM_PHRASE, GrantTier::Egress, AUDIT)
                .is_some()
        );
        assert!(
            OwnerArmCeremony::complete(&mut p, EGRESS_ARM_PHRASE, GrantTier::Egress, AUDIT)
                .is_none()
        );
    }

    #[test]
    fn egress_grant_authorizes_within_bounds() {
        let c = egress_ceremony().expect("ceremony");
        let g = EgressGrant::arm(c, bounds(3, 1000)).expect("egress arm");
        assert_eq!(g.authorize(999, 0), GrantAuthorization::Authorized);
        assert_eq!(g.authorize(999, 2), GrantAuthorization::Authorized);
        assert_eq!(g.audit_hash_32(), AUDIT);
        assert_eq!(g.tier(), GrantTier::Egress);
    }

    #[test]
    fn egress_grant_denies_expired_rate_and_revoked() {
        let g = EgressGrant::arm(egress_ceremony().expect("c"), bounds(2, 1000)).expect("arm");
        assert_eq!(
            g.authorize(1000, 0),
            GrantAuthorization::Denied(GrantDenied::Expired)
        );
        assert_eq!(
            g.authorize(999, 2),
            GrantAuthorization::Denied(GrantDenied::RateExceeded)
        );
        let r = g.revoke();
        assert_eq!(
            r.authorize(0, 0),
            GrantAuthorization::Denied(GrantDenied::Revoked)
        );
    }

    #[test]
    fn an_egress_ceremony_cannot_arm_a_mutate_grant_and_vice_versa() {
        // egress ceremony -> MutateGrant::arm = None (no cross-tier escalation)
        assert!(MutateGrant::arm(egress_ceremony().expect("c"), bounds(1, 1)).is_none());
        // mutate ceremony -> EgressGrant::arm = None
        let mut p = ApprovalPrompt::new(ApprovalRequirement::TypedPhrase, MUTATE_ARM_PHRASE);
        let mc =
            OwnerArmCeremony::complete(&mut p, MUTATE_ARM_PHRASE, GrantTier::MutateLocal, AUDIT)
                .expect("mutate ceremony");
        assert!(EgressGrant::arm(mc, bounds(1, 1)).is_none());
        // and the mutate ceremony DOES arm a mutate grant
        let mut p2 = ApprovalPrompt::new(ApprovalRequirement::TypedPhrase, MUTATE_ARM_PHRASE);
        let mc2 =
            OwnerArmCeremony::complete(&mut p2, MUTATE_ARM_PHRASE, GrantTier::MutateLocal, AUDIT)
                .expect("mutate ceremony 2");
        assert!(MutateGrant::arm(mc2, bounds(1, 1000)).is_some());
    }

    #[test]
    fn authorize_gate_falls_back_to_per_action_without_a_grant() {
        assert_eq!(
            authorize_egress(None, 0, 0),
            AutonomyAuthorization::PerActionApprovalRequired
        );
        let g = EgressGrant::arm(egress_ceremony().expect("c"), bounds(1, 1000)).expect("arm");
        assert_eq!(
            authorize_egress(Some(&g), 1, 0),
            AutonomyAuthorization::AutonomousAuthorized
        );
        assert_eq!(
            authorize_egress(Some(&g), 1000, 0),
            AutonomyAuthorization::Denied(GrantDenied::Expired)
        );
        assert_eq!(
            authorize_mutate(None, 0, 0),
            AutonomyAuthorization::PerActionApprovalRequired
        );
    }

    fn download_ceremony() -> Option<OwnerArmCeremony> {
        let mut p = ApprovalPrompt::new(ApprovalRequirement::TypedPhrase, DOWNLOAD_ARM_PHRASE);
        OwnerArmCeremony::complete(
            &mut p,
            DOWNLOAD_ARM_PHRASE,
            GrantTier::MutateDownload,
            AUDIT,
        )
    }

    #[test]
    fn download_grant_authorizes_within_bounds_and_denies_outside() {
        let g = DownloadGrant::arm(download_ceremony().expect("c"), bounds(1, 1000)).expect("arm");
        assert_eq!(g.authorize(999, 0), GrantAuthorization::Authorized);
        assert_eq!(g.tier(), GrantTier::MutateDownload);
        assert_eq!(g.audit_hash_32(), AUDIT);
        // single-shot: one action used ⇒ rate-exceeded; expired ⇒ denied; revoked ⇒ denied
        assert_eq!(
            g.authorize(999, 1),
            GrantAuthorization::Denied(GrantDenied::RateExceeded)
        );
        assert_eq!(
            g.authorize(1000, 0),
            GrantAuthorization::Denied(GrantDenied::Expired)
        );
        assert_eq!(
            g.revoke().authorize(0, 0),
            GrantAuthorization::Denied(GrantDenied::Revoked)
        );
    }

    #[test]
    fn a_download_ceremony_is_tier_distinct_from_egress_and_mutate() {
        // a download ceremony cannot arm an egress or a mutate grant
        assert!(EgressGrant::arm(download_ceremony().expect("c"), bounds(1, 1)).is_none());
        assert!(MutateGrant::arm(download_ceremony().expect("c"), bounds(1, 1)).is_none());
        // an egress ceremony cannot arm a download grant
        assert!(DownloadGrant::arm(egress_ceremony().expect("c"), bounds(1, 1)).is_none());
        // a mutate ceremony cannot arm a download grant
        let mut p = ApprovalPrompt::new(ApprovalRequirement::TypedPhrase, MUTATE_ARM_PHRASE);
        let mc =
            OwnerArmCeremony::complete(&mut p, MUTATE_ARM_PHRASE, GrantTier::MutateLocal, AUDIT)
                .expect("mutate ceremony");
        assert!(DownloadGrant::arm(mc, bounds(1, 1)).is_none());
    }

    #[test]
    fn arm_local_download_grant_requires_the_exact_phrase_and_a_grant_gate() {
        // wrong phrase ⇒ None (fail-closed)
        let mut p = ApprovalPrompt::new(ApprovalRequirement::TypedPhrase, DOWNLOAD_ARM_PHRASE);
        assert!(arm_local_download_grant(&mut p, "nope", AUDIT, bounds(1, 1000)).is_none());
        // exact phrase ⇒ Some, then the per-action gate authorizes within bounds
        let mut p2 = ApprovalPrompt::new(ApprovalRequirement::TypedPhrase, DOWNLOAD_ARM_PHRASE);
        let g = arm_local_download_grant(&mut p2, DOWNLOAD_ARM_PHRASE, AUDIT, bounds(1, 1000))
            .expect("arm");
        assert_eq!(
            authorize_download(Some(&g), 1, 0),
            AutonomyAuthorization::AutonomousAuthorized
        );
        assert_eq!(
            authorize_download(Some(&g), 1, 1),
            AutonomyAuthorization::Denied(GrantDenied::RateExceeded)
        );
        assert_eq!(
            authorize_download(None, 0, 0),
            AutonomyAuthorization::PerActionApprovalRequired
        );
    }

    // ---- E13-4 / ⑳ composite BOLD SESSION --------------------------------------

    fn bold_ceremony() -> Option<OwnerArmCeremony> {
        let mut p = ApprovalPrompt::new(ApprovalRequirement::TypedPhrase, BOLD_ARM_PHRASE);
        OwnerArmCeremony::complete(&mut p, BOLD_ARM_PHRASE, GrantTier::BoldSession, AUDIT)
    }

    #[test]
    fn bold_session_arms_egress_and_mutate_within_bounds_and_revoke_closes_both() {
        let g = arm_bold_session(bold_ceremony().expect("c"), bounds(3, 1000)).expect("bold arm");
        // BOTH components authorize within the shared bound, are tier-correct, and
        // carry the shared audit hash.
        assert_eq!(g.egress().authorize(999, 0), GrantAuthorization::Authorized);
        assert_eq!(g.mutate().authorize(999, 0), GrantAuthorization::Authorized);
        assert_eq!(g.egress().tier(), GrantTier::Egress);
        assert_eq!(g.mutate().tier(), GrantTier::MutateLocal);
        assert_eq!(g.egress().audit_hash_32(), AUDIT);
        assert_eq!(g.mutate().audit_hash_32(), AUDIT);
        // revoke closes BOTH (fail-closed; the whole session stops).
        let r = g.revoke();
        assert_eq!(
            r.egress().authorize(0, 0),
            GrantAuthorization::Denied(GrantDenied::Revoked)
        );
        assert_eq!(
            r.mutate().authorize(0, 0),
            GrantAuthorization::Denied(GrantDenied::Revoked)
        );
    }

    #[test]
    fn a_bold_ceremony_is_tier_distinct_from_every_single_tier() {
        // a BoldSession ceremony cannot arm any plain single-tier grant (PD-2).
        assert!(EgressGrant::arm(bold_ceremony().expect("c"), bounds(1, 1)).is_none());
        assert!(MutateGrant::arm(bold_ceremony().expect("c"), bounds(1, 1)).is_none());
        assert!(DownloadGrant::arm(bold_ceremony().expect("c"), bounds(1, 1)).is_none());
        // and a non-bold ceremony cannot arm a bold session.
        assert!(arm_bold_session(egress_ceremony().expect("c"), bounds(1, 1)).is_none());
        assert!(arm_bold_session(download_ceremony().expect("c"), bounds(1, 1)).is_none());
        let mut p = ApprovalPrompt::new(ApprovalRequirement::TypedPhrase, MUTATE_ARM_PHRASE);
        let mc =
            OwnerArmCeremony::complete(&mut p, MUTATE_ARM_PHRASE, GrantTier::MutateLocal, AUDIT)
                .expect("mutate ceremony");
        assert!(arm_bold_session(mc, bounds(1, 1)).is_none());
    }

    #[test]
    fn arm_local_bold_session_requires_the_exact_phrase_and_gates_both_components() {
        // wrong phrase ⇒ None (fail-closed)
        let mut p = ApprovalPrompt::new(ApprovalRequirement::TypedPhrase, BOLD_ARM_PHRASE);
        assert!(arm_local_bold_session(&mut p, "nope", AUDIT, bounds(2, 1000)).is_none());
        // exact phrase ⇒ Some; both components gate within the shared bound.
        let mut p2 = ApprovalPrompt::new(ApprovalRequirement::TypedPhrase, BOLD_ARM_PHRASE);
        let g =
            arm_local_bold_session(&mut p2, BOLD_ARM_PHRASE, AUDIT, bounds(2, 1000)).expect("arm");
        assert_eq!(
            authorize_egress(Some(g.egress()), 1, 0),
            AutonomyAuthorization::AutonomousAuthorized
        );
        assert_eq!(
            authorize_mutate(Some(g.mutate()), 1, 0),
            AutonomyAuthorization::AutonomousAuthorized
        );
        // rate cap: used >= max ⇒ denied on each component.
        assert_eq!(
            authorize_egress(Some(g.egress()), 1, 2),
            AutonomyAuthorization::Denied(GrantDenied::RateExceeded)
        );
        assert_eq!(
            authorize_mutate(Some(g.mutate()), 1, 2),
            AutonomyAuthorization::Denied(GrantDenied::RateExceeded)
        );
    }

    // ---- ONCHAIN PIVOT C-0 user-BOUNDED custody --------------------------------

    fn custody_ceremony() -> Option<OwnerArmCeremony> {
        let mut p = ApprovalPrompt::new(ApprovalRequirement::TypedPhrase, CUSTODY_ARM_PHRASE);
        OwnerArmCeremony::complete(&mut p, CUSTODY_ARM_PHRASE, GrantTier::Custody, AUDIT)
    }

    fn custody_bounds(per_tx: u128, budget: u128) -> CustodyBounds {
        CustodyBounds {
            base: bounds(3, 1000),
            per_tx_max_minor: per_tx,
            total_budget_minor: budget,
            chain_allowlist: vec!["ethereum".to_string(), "base".to_string()],
            protocol_allowlist: vec!["uniswap".to_string()],
        }
    }

    fn tx(chain: &str, protocol: &str, amount: u128) -> ChainTxRequest {
        ChainTxRequest {
            chain: chain.to_string(),
            protocol: protocol.to_string(),
            amount_minor: amount,
        }
    }

    #[test]
    fn custody_grant_authorizes_within_all_bounds() {
        let g = CustodyGrant::arm(custody_ceremony().expect("c"), custody_bounds(100, 250))
            .expect("custody arm");
        assert_eq!(
            g.authorize(999, 0, 0, &tx("ethereum", "uniswap", 100)),
            CustodyAuthorization::Authorized
        );
        // an allowlisted second chain, within the remaining budget
        assert_eq!(
            g.authorize(999, 1, 150, &tx("base", "uniswap", 100)),
            CustodyAuthorization::Authorized
        );
        assert_eq!(g.tier(), GrantTier::Custody);
        assert_eq!(g.audit_hash_32(), AUDIT);
    }

    #[test]
    fn custody_grant_denies_every_bound_breach_fail_closed() {
        let g = CustodyGrant::arm(custody_ceremony().expect("c"), custody_bounds(100, 250))
            .expect("arm");
        use CustodyDenied as D;
        // per-tx ceiling exceeded
        assert_eq!(
            g.authorize(999, 0, 0, &tx("ethereum", "uniswap", 101)),
            CustodyAuthorization::Denied(D::PerTxExceeded)
        );
        // total budget exceeded (spent 200 + 100 > 250)
        assert_eq!(
            g.authorize(999, 0, 200, &tx("ethereum", "uniswap", 100)),
            CustodyAuthorization::Denied(D::BudgetExceeded)
        );
        // chain not allowlisted
        assert_eq!(
            g.authorize(999, 0, 0, &tx("solana", "uniswap", 10)),
            CustodyAuthorization::Denied(D::ChainNotAllowed)
        );
        // protocol not allowlisted
        assert_eq!(
            g.authorize(999, 0, 0, &tx("ethereum", "unknown-protocol", 10)),
            CustodyAuthorization::Denied(D::ProtocolNotAllowed)
        );
        // expired / rate / revoked (the reused base)
        assert_eq!(
            g.authorize(1000, 0, 0, &tx("ethereum", "uniswap", 10)),
            CustodyAuthorization::Denied(D::Expired)
        );
        assert_eq!(
            g.authorize(999, 3, 0, &tx("ethereum", "uniswap", 10)),
            CustodyAuthorization::Denied(D::RateExceeded)
        );
        assert_eq!(
            g.clone()
                .revoke()
                .authorize(0, 0, 0, &tx("ethereum", "uniswap", 10)),
            CustodyAuthorization::Denied(D::Revoked)
        );
        // budget overflow (checked_add) is denied — never a silent authorize
        let gmax = CustodyGrant::arm(
            custody_ceremony().expect("c"),
            custody_bounds(u128::MAX, u128::MAX),
        )
        .expect("arm");
        assert_eq!(
            gmax.authorize(999, 0, u128::MAX, &tx("ethereum", "uniswap", 1)),
            CustodyAuthorization::Denied(D::BudgetExceeded)
        );
    }

    #[test]
    fn custody_ceremony_is_tier_distinct_from_every_other_tier() {
        // a custody ceremony cannot arm any other grant (no cross-tier escalation)
        assert!(EgressGrant::arm(custody_ceremony().expect("c"), bounds(1, 1)).is_none());
        assert!(MutateGrant::arm(custody_ceremony().expect("c"), bounds(1, 1)).is_none());
        assert!(DownloadGrant::arm(custody_ceremony().expect("c"), bounds(1, 1)).is_none());
        assert!(arm_bold_session(custody_ceremony().expect("c"), bounds(1, 1)).is_none());
        // and no other ceremony can arm a custody grant
        assert!(CustodyGrant::arm(egress_ceremony().expect("c"), custody_bounds(1, 1)).is_none());
        assert!(CustodyGrant::arm(download_ceremony().expect("c"), custody_bounds(1, 1)).is_none());
        assert!(CustodyGrant::arm(bold_ceremony().expect("c"), custody_bounds(1, 1)).is_none());
    }

    #[test]
    fn arm_local_custody_grant_requires_the_exact_phrase() {
        let mut p = ApprovalPrompt::new(ApprovalRequirement::TypedPhrase, CUSTODY_ARM_PHRASE);
        assert!(arm_local_custody_grant(&mut p, "nope", AUDIT, custody_bounds(10, 10)).is_none());
        let mut p2 = ApprovalPrompt::new(ApprovalRequirement::TypedPhrase, CUSTODY_ARM_PHRASE);
        let g =
            arm_local_custody_grant(&mut p2, CUSTODY_ARM_PHRASE, AUDIT, custody_bounds(100, 100))
                .expect("arm");
        assert_eq!(
            g.authorize(1, 0, 0, &tx("ethereum", "uniswap", 50)),
            CustodyAuthorization::Authorized
        );
    }
}
