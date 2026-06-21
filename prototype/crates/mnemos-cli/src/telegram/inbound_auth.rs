//! `telegram::inbound_auth` — inbound approval AUTH + the narrow, unforgeable SI-3
//! mint (ENDGAME E4-2). The paranoid heart of Telegram full-duplex.
//!
//! An [`InboundUpdate`](crate::telegram::inbound::InboundUpdate) is UNTRUSTED. This
//! module turns an owner's phone reply into authority to fire a SPECIFIC pending
//! gated action — and NOTHING else — through four fail-closed gates, in order:
//!
//! 1. **Sender pin (IV-T1).** The reply authorizes nothing unless its `chat.id`
//!    equals the configured `TELEGRAM_CHAT_ID` (the owner's chat, resolved + parsed
//!    at the edge by [`resolve_owner_chat_id`]; never rendered). A spoofed update
//!    from any other chat is DROPPED before any work — `SenderNotOwner`.
//! 2. **Action binding (IV-T3).** The reply must NAME a pending action by its
//!    16-hex hash prefix. An approval for an unknown action mints nothing —
//!    `NoSuchPendingAction`. The approval binds to THAT action, never "any" action.
//! 3. **Replay ledger (IV-T2).** The approval is recorded ONCE in the (now
//!    load-bearing) [`ApprovalSyncLedger`], bound by an `event_hash_32 =
//!    SHA-256(action_hash || decision)`. A missing/zero hash or an already-recorded
//!    hash is REFUSED — `ReplayOrUnbound`. A captured approval cannot fire twice.
//! 4. **Narrow SI-3 mint (IV-T4).** On approval, a single-shot, action-bound,
//!    fast-expiring [`EgressGrant`] is minted through the SAME unforgeable
//!    [`OwnerArmCeremony::complete`] + [`EgressGrant::arm`] path the LOCAL ceremony
//!    uses (a spoof forges no ceremony). The grant is `max_actions = 1`, expires in
//!    [`TELEGRAM_APPROVE_GRANT_TTL_MS`], and its `audit_hash` IS the action hash — so
//!    it can authorize ONLY that one action and can NEVER widen to a broad grant.
//!    Broad arming stays the LOCAL typed-phrase ceremony (E0c `EGRESS_ARM_PHRASE`),
//!    which the network cannot reach (owner pick (b): narrow).
//!
//! CUSTODY is unreachable (PD-6): the mint is egress-tier only; there is no
//! `GrantTier::Custody`, and this module references no mutate/custody constructor.
//! The model cannot self-approve (IV-T9): it cannot satisfy the sender pin (it holds
//! no `TELEGRAM_CHAT_ID`), and `agent_loop.rs` references no symbol here.
//!
//! This is an OWNER-PATH SI-3 caller — the foreseen handler in the
//! `e0c_si3_no_self_mint_grep.sh` CHECK-B comment. Its file is on the allowlist;
//! the no-self-mint PROPERTY is preserved (a grant is minted only via the owner-arm
//! ceremony — here, gated by the owner-pinned `chat.id`), not relaxed.

use crate::commands::grant::{EgressGrant, GrantBounds, GrantTier, MutateGrant, OwnerArmCeremony};
use crate::commands::platform_telegram::PlatformOrigin;
use crate::daemon::approval_sync::{
    ApprovalAction, ApprovalEvent, ApprovalSyncLedger, ApprovalSyncReject, SyncDecision,
};
use crate::repl::history::classify;
use crate::secrets::scan_inline_secret;
use crate::telegram::inbound::InboundUpdate;

/// The inbound per-action APPROVE typed-phrase — distinct from the broad arm phrase
/// ([`crate::commands::grant::EGRESS_ARM_PHRASE`]) so a phone reply can NEVER arm
/// broad egress (owner pick (b): narrow). A short verb is sufficient HERE: the
/// unforgeable gate is the sender pin + the action-hash binding + the SI-3 grant
/// machinery, not the phrase entropy.
pub const TELEGRAM_APPROVE_PHRASE: &str = "approve";
/// The inbound per-action DENY verb. A deny is recorded (with its binding hash) and
/// mints no grant — the owner can refuse a pending action from the phone.
pub const TELEGRAM_DENY_PHRASE: &str = "deny";

/// How long a narrow inbound-approved egress grant lives (ms). An approved action
/// should fire promptly; the grant is single-shot regardless, but a short TTL bounds
/// the window in which the one approved action can fire.
pub const TELEGRAM_APPROVE_GRANT_TTL_MS: u64 = 5 * 60 * 1000;

/// A gated action awaiting remote (phone) approval. Identified by the SHA-256 of the
/// action; the owner approves it by replying with its 16-hex prefix.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PendingApproval {
    /// SHA-256 identity of the specific gated action awaiting approval.
    pub action_hash_32: [u8; 32],
    /// The action class (recorded in the approval_sync ledger + named in the ping).
    pub action: ApprovalAction,
}

impl PendingApproval {
    /// Build a pending approval for `action` identified by `action_hash_32`.
    #[must_use]
    pub const fn new(action_hash_32: [u8; 32], action: ApprovalAction) -> Self {
        Self {
            action_hash_32,
            action,
        }
    }

    /// The 16-hex prefix the owner names this action by (the ping shows it).
    #[must_use]
    pub fn id16(&self) -> String {
        hash16(&self.action_hash_32)
    }
}

/// The 16-hex display prefix of a 32-byte hash (the canonical `redact16` idiom —
/// the full hash is never shown).
#[must_use]
fn hash16(h: &[u8; 32]) -> String {
    crate::hex32(h).chars().take(16).collect()
}

/// The recognized approve/deny decision parsed from a reply verb.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ReplyDecision {
    Approve,
    Deny,
}

impl ReplyDecision {
    /// The `SyncDecision` recorded in the ledger.
    const fn sync(self) -> SyncDecision {
        match self {
            Self::Approve => SyncDecision::Approved,
            Self::Deny => SyncDecision::Denied,
        }
    }
}

/// The (verb, hash-token) parsed from an untrusted reply text. Pure + bounded (the
/// text is already capped by [`InboundUpdate`]). A reply is `"<verb> <hash16>"`,
/// optionally `/`-prefixed; tokens beyond the second are ignored.
fn parse_reply(text: &str) -> Option<(ReplyDecision, String)> {
    let mut toks = text.split_whitespace();
    let verb_raw = toks.next()?;
    let verb = verb_raw.trim_start_matches('/').to_ascii_lowercase();
    let decision = if verb == TELEGRAM_APPROVE_PHRASE {
        ReplyDecision::Approve
    } else if verb == TELEGRAM_DENY_PHRASE {
        ReplyDecision::Deny
    } else {
        return None;
    };
    let hash_token = toks.next().unwrap_or_default().to_ascii_lowercase();
    Some((decision, hash_token))
}

/// The `event_hash_32` binding an approval to its (action, decision) — distinct for
/// approve vs deny of the SAME action, so each is replay-refused independently.
fn event_hash(action_hash_32: &[u8; 32], decision: ReplyDecision) -> [u8; 32] {
    let mut buf = [0u8; 33];
    buf[..32].copy_from_slice(action_hash_32);
    buf[32] = decision.sync().as_u8();
    crate::sha256_32(&buf)
}

/// The typed outcome of authenticating an inbound reply (fail-closed; every
/// non-`Approved` variant mints NOTHING). Each maps to a threat (IV-T#). No
/// `PartialEq`/`Eq` — the `Approved` variant holds an [`EgressGrant`] (an
/// unforgeable token, deliberately not comparable); callers `match` on it.
#[derive(Clone, Copy, Debug)]
pub enum InboundAuthOutcome {
    /// IV-T1: the sender's `chat.id` is not the owner's pin — dropped, nothing
    /// recorded, nothing minted.
    SenderNotOwner,
    /// The reply verb was not `approve` / `deny` — ignored (not an approval reply).
    UnrecognizedReply,
    /// IV-T3: the reply names no known pending action — refused, nothing minted.
    NoSuchPendingAction,
    /// IV-T2: the approval had no binding hash or was already recorded (replay) —
    /// refused, nothing minted.
    ReplayOrUnbound(ApprovalSyncReject),
    /// The owner DENIED the pending action — recorded (bound), no grant minted.
    Denied {
        /// The action that was denied (its hash).
        action_hash_32: [u8; 32],
    },
    /// IV-T4: the owner APPROVED an EGRESS action — a single-shot, action-bound,
    /// fast-expiring egress grant is minted (the SI-3 reuse). It authorizes ONLY
    /// this action.
    Approved {
        /// The narrow, single-shot grant (`max_actions = 1`, `audit_hash =
        /// action_hash`, expires in `TELEGRAM_APPROVE_GRANT_TTL_MS`).
        grant: EgressGrant,
        /// The action the grant is bound to (its hash).
        action_hash_32: [u8; 32],
    },
    /// IV-T4 / D-A2 (ENDGAME E10-2b): the owner APPROVED a MUTATE-LOCAL action (a
    /// tool side effect — an agent-proposed exec / file-apply) — a single-shot,
    /// action-bound, fast-expiring MUTATE grant is minted (tier-correct: an
    /// `EgressGrant` could NEVER authorize this, IV-A5). It authorizes ONLY this
    /// action.
    ApprovedMutate {
        /// The narrow, single-shot mutate grant (`max_actions = 1`, `audit_hash =
        /// action_hash`, fast-expiring).
        grant: MutateGrant,
        /// The action the grant is bound to (its hash).
        action_hash_32: [u8; 32],
    },
    /// Fail-closed: the SI-3 ceremony/arm refused (should not occur for a valid
    /// approve + non-zero action hash) — nothing minted.
    MintFailed,
}

/// The capability TIER a remote approval of `action` mints (ENDGAME E10-2b D-A2):
/// a tool side effect (an agent-proposed exec / file-apply) is a MUTATE-LOCAL
/// action; every other class is EGRESS. CUSTODY is never representable (PD-6 —
/// there is no `GrantTier::Custody`), so a phone reply can never mint funds/chain
/// authority. The branch is exhaustive over the closed [`ApprovalAction`] enum.
const fn tier_for(action: ApprovalAction) -> GrantTier {
    match action {
        ApprovalAction::ToolSideEffect => GrantTier::MutateLocal,
        ApprovalAction::ProviderFallback
        | ApprovalAction::MemoryExportDelete
        | ApprovalAction::TelegramRemoteControl
        | ApprovalAction::StageHHandoff => GrantTier::Egress,
    }
}

/// The disposition of an UNTRUSTED inbound owner message on the Telegram
/// REMOTE-CONTROL chat path (ENDGAME E13-2 / ⑱). PURE classification, fail-closed in
/// this exact order: owner-pin (IV-RC1) → secret-withhold (IV-RC2) → approval-reply
/// vs free-form split. The `ChatPrompt` arm borrows the already-bounded text (no copy).
///
/// This is the router for the NEW chat path: an `ApprovalReply` routes to the
/// EXISTING approval flow ([`authenticate_and_mint`] via
/// [`RemoteApprovalCoordinator::ingest_update`](crate::daemon::remote_approval::RemoteApprovalCoordinator::ingest_update));
/// a `ChatPrompt` is the secret-free, owner-pinned prompt that drives a LOCAL agent
/// turn whose redacted answer is replied back (`serve_chat_cycle`, ⑱).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum InboundDisposition<'a> {
    /// IV-RC1: the sender's `chat.id` is not the owner pin — dropped before ANY work
    /// (no secret scan, no turn, no reply, nothing recorded).
    NotOwner,
    /// IV-RC2: the inbound text is secret-shaped — WITHHELD before the agent ever
    /// sees it (never fed to a turn, never echoed back). Uses the SAME scanners the
    /// SI-2 [`redact`](crate::provider::redaction::redact) choke uses.
    WithheldSecret,
    /// The text is an `approve` / `deny` reply — routed to the EXISTING ⑪ approval
    /// path, NOT a chat turn. An unknown / non-matching hash is still an approval
    /// ATTEMPT here; the approval path returns `NoSuchPendingAction` (fail-closed) —
    /// it never runs a turn.
    ApprovalReply,
    /// A free-form owner command — the bounded, secret-free prompt to run as a LOCAL
    /// agent turn (IV-RC4) whose redacted answer is replied (IV-RC3/RC5).
    ChatPrompt(&'a str),
}

/// Classify an UNTRUSTED inbound update for the Telegram remote-control CHAT path —
/// PURE and fail-closed, in this exact order (IV-RC1 → IV-RC2 → split). Takes the
/// resolved `owner_chat_id` (the env lives at the edge), so it is hermetically
/// testable with no env and no network. Calls the private [`parse_reply`] (same
/// module — no visibility widened) for the approval-vs-free-form split.
///
/// Note: a free-form message that merely STARTS with the word `approve` / `deny`
/// classifies as `ApprovalReply` and routes to the approval path (which fails closed
/// on a non-matching hash) — it does NOT run a turn. This is the intended fail-closed
/// ordering: the chat path never runs a turn on anything shaped like a reply.
#[must_use]
pub fn classify_inbound(update: &InboundUpdate, owner_chat_id: i64) -> InboundDisposition<'_> {
    // GATE 1 — owner pin FIRST (IV-RC1): a non-owner sender is dropped before any
    // parse / scan / turn / reply (cheap rejection of a flood; IV-T8 reuse).
    if update.sender_chat_id() != owner_chat_id {
        return InboundDisposition::NotOwner;
    }
    let text = update.text();
    // GATE 2 — secret withhold (IV-RC2): a secret-shaped inbound is WITHHELD before
    // the agent sees it — the SAME scanners the SI-2 `redact()` choke uses
    // (`scan_inline_secret` || `classify`). Never fed to a turn, never echoed.
    if scan_inline_secret(text) || classify(text).is_some() {
        return InboundDisposition::WithheldSecret;
    }
    // GATE 3 — approval-reply vs free-form split: an `approve` / `deny` reply routes
    // to the EXISTING approval path; anything else is a free-form chat prompt.
    if parse_reply(text).is_some() {
        return InboundDisposition::ApprovalReply;
    }
    InboundDisposition::ChatPrompt(text)
}

/// Authenticate an inbound reply and, on approval, MINT a narrow single-action
/// egress grant — the four fail-closed gates (IV-T1..T4), in order. PURE: takes the
/// resolved `owner_chat_id` + `now_epoch_ms` (the env + clock live at the edge), so
/// the whole auth+mint is hermetically testable with no env and no network.
///
/// `ledger` is the LONG-LIVED approval-sync ledger (owned by the poll loop) — it is
/// what makes replay-refusal real across polls (IV-T2). It is mutated ONLY on a
/// sender-pinned, action-bound reply.
#[must_use]
pub fn authenticate_and_mint(
    update: &InboundUpdate,
    owner_chat_id: i64,
    pending: &[PendingApproval],
    ledger: &mut ApprovalSyncLedger,
    now_epoch_ms: u64,
) -> InboundAuthOutcome {
    // GATE 1 — sender pin (IV-T1): a non-owner sender authorizes nothing, records
    // nothing, mints nothing. Checked FIRST, before any other work (cheap drop of a
    // flood; IV-T8).
    if update.sender_chat_id() != owner_chat_id {
        return InboundAuthOutcome::SenderNotOwner;
    }
    // Parse the bounded, untrusted reply text into (decision, hash-token).
    let Some((decision, hash_token)) = parse_reply(update.text()) else {
        return InboundAuthOutcome::UnrecognizedReply;
    };
    // GATE 2 — action binding (IV-T3): the reply must name a KNOWN pending action by
    // its 16-hex prefix. No match ⇒ nothing recorded, nothing minted.
    let Some(target) = pending.iter().find(|p| p.id16() == hash_token) else {
        return InboundAuthOutcome::NoSuchPendingAction;
    };
    // GATE 3 — replay ledger (IV-T2): record the approval ONCE, bound by
    // event_hash = SHA-256(action_hash || decision). Missing/zero hash or a replay
    // is refused; the mint happens ONLY on a fresh, recorded event.
    let event_hash_32 = event_hash(&target.action_hash_32, decision);
    let event = ApprovalEvent {
        action: target.action,
        source: PlatformOrigin::Telegram,
        decision: decision.sync(),
        event_hash_32,
    };
    if let Err(reject) = ledger.record(event) {
        return InboundAuthOutcome::ReplayOrUnbound(reject);
    }
    // A deny is a recorded decision; it mints no grant.
    if matches!(decision, ReplyDecision::Deny) {
        return InboundAuthOutcome::Denied {
            action_hash_32: target.action_hash_32,
        };
    }
    // GATE 4 — narrow SI-3 mint (IV-T4 / D-A2): the SAME unforgeable ceremony/grant
    // path, bound to THIS action (audit_hash = action_hash) and single-shot
    // (max_actions = 1, fast-expiring), minted at the action's TIER. A tool side
    // effect (an agent-proposed exec / file-apply) ⇒ a MUTATE grant; every other
    // class ⇒ an EGRESS grant. The tiers are type-distinct: an egress approval can
    // NEVER authorize a mutate and vice-versa (IV-A5). It can authorize ONLY this
    // action and can never widen. A spoof forges no ceremony.
    let bounds = GrantBounds {
        max_actions_u32: 1,
        expires_at_epoch_ms: now_epoch_ms.saturating_add(TELEGRAM_APPROVE_GRANT_TTL_MS),
    };
    match tier_for(target.action) {
        GrantTier::MutateLocal => {
            let mut prompt = crate::repl::approval::ApprovalPrompt::new(
                crate::command::ApprovalRequirement::TypedPhrase,
                TELEGRAM_APPROVE_PHRASE,
            );
            let Some(ceremony) = OwnerArmCeremony::complete(
                &mut prompt,
                TELEGRAM_APPROVE_PHRASE,
                GrantTier::MutateLocal,
                target.action_hash_32,
            ) else {
                return InboundAuthOutcome::MintFailed;
            };
            let Some(grant) = MutateGrant::arm(ceremony, bounds) else {
                return InboundAuthOutcome::MintFailed;
            };
            InboundAuthOutcome::ApprovedMutate {
                grant,
                action_hash_32: target.action_hash_32,
            }
        }
        GrantTier::Egress => {
            let mut prompt = crate::repl::approval::ApprovalPrompt::new(
                crate::command::ApprovalRequirement::TypedPhrase,
                TELEGRAM_APPROVE_PHRASE,
            );
            let Some(ceremony) = OwnerArmCeremony::complete(
                &mut prompt,
                TELEGRAM_APPROVE_PHRASE,
                GrantTier::Egress,
                target.action_hash_32,
            ) else {
                return InboundAuthOutcome::MintFailed;
            };
            let Some(grant) = EgressGrant::arm(ceremony, bounds) else {
                return InboundAuthOutcome::MintFailed;
            };
            InboundAuthOutcome::Approved {
                grant,
                action_hash_32: target.action_hash_32,
            }
        }
        // E13-3 / D-DL5: a DOWNLOAD is owner-armed DISPATCH only, NEVER an inbound
        // remote-approvable action — `tier_for` never returns MutateDownload, so this
        // arm is unreachable; fail-closed (mint nothing) keeps inbound download
        // structurally impossible while the closed-enum match stays exhaustive (PD-4).
        GrantTier::MutateDownload => InboundAuthOutcome::MintFailed,
        // E13-4 / ⑳ D-BS4: a BOLD SESSION is owner-armed DISPATCH only (`daemon bold`),
        // NEVER an inbound remote-approvable action — `tier_for` never returns
        // BoldSession, so this arm is unreachable; fail-closed (mint nothing) keeps an
        // inbound-armed bold session structurally impossible while the match stays
        // exhaustive (PD-4). A bold session is NOT a single-tier grant anyway (it has no
        // EgressGrant ctor here — `arm_bold_session` is the sole home, in grant.rs).
        GrantTier::BoldSession => InboundAuthOutcome::MintFailed,
    }
}

/// Resolve + parse the owner's `chat.id` pin from `TELEGRAM_CHAT_ID` at the edge.
/// `None` when the env var is absent or not an integer (fail-closed — with no pin,
/// the sender check in [`authenticate_and_mint`] can never match, so no inbound
/// reply is authorized). Feature-gated: the env edge only exists when the inbound
/// transport is compiled. The value is parsed and compared, never rendered.
#[cfg(feature = "telegram-inbound")]
#[must_use]
pub fn resolve_owner_chat_id() -> Option<i64> {
    let host = crate::telegram::egress::TelegramHost::BotApi;
    let raw = crate::secrets::Secret::new(std::env::var(host.chat_env()).ok()?);
    raw.expose_secret().trim().parse::<i64>().ok()
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic)]
    #![allow(clippy::unwrap_used)]
    #![allow(clippy::expect_used)]

    use super::*;

    const OWNER: i64 = 1001;
    const ATTACKER: i64 = 9999;

    fn action_hash(seed: u8) -> [u8; 32] {
        crate::sha256_32(&[seed; 16])
    }

    fn pending(seed: u8) -> PendingApproval {
        PendingApproval::new(action_hash(seed), ApprovalAction::TelegramRemoteControl)
    }

    fn reply(chat_id: i64, text: &str) -> InboundUpdate {
        InboundUpdate::new_bounded(1, chat_id, text)
    }

    fn approve_text(p: &PendingApproval) -> String {
        format!("approve {}", p.id16())
    }

    // --- IV-RC1/RC2 — classify_inbound: the pure chat-path router (E13-2 / ⑱). -----

    /// A secret-shaped owner text — the canonical `suiprivkey` fixture the SI-2 choke
    /// scanners catch (same family as the redaction-gate tests).
    const SECRET_TEXT: &str = "key = \"suiprivkey1qexamplenotreal\"";

    // IV-RC1 — a non-owner message is dropped before ANY work (no turn, no reply),
    // even when its text is a perfect chat command / secret / approval (the owner pin
    // is checked FIRST, before the secret scan and the split).
    #[test]
    fn iv_rc1_classify_non_owner_is_dropped_before_any_turn() {
        assert_eq!(
            classify_inbound(&reply(ATTACKER, "what is the build status?"), OWNER),
            InboundDisposition::NotOwner
        );
        assert_eq!(
            classify_inbound(&reply(ATTACKER, SECRET_TEXT), OWNER),
            InboundDisposition::NotOwner
        );
        assert_eq!(
            classify_inbound(&reply(ATTACKER, "approve 0000000000000000"), OWNER),
            InboundDisposition::NotOwner
        );
    }

    // IV-RC2 — a secret-shaped owner text is WITHHELD before the agent sees it
    // (WithheldSecret, never ChatPrompt, never ApprovalReply).
    #[test]
    fn iv_rc2_classify_secret_shaped_is_withheld_before_split() {
        assert_eq!(
            classify_inbound(&reply(OWNER, SECRET_TEXT), OWNER),
            InboundDisposition::WithheldSecret
        );
    }

    // The split: an approve/deny reply routes to the approval path; a free-form owner
    // message is a ChatPrompt carrying the bounded text verbatim (drives a LOCAL turn).
    #[test]
    fn classify_splits_approval_reply_from_free_form_chat() {
        let p = pending(1);
        assert_eq!(
            classify_inbound(&reply(OWNER, &approve_text(&p)), OWNER),
            InboundDisposition::ApprovalReply
        );
        assert_eq!(
            classify_inbound(&reply(OWNER, "deny deadbeefdeadbeef"), OWNER),
            InboundDisposition::ApprovalReply
        );
        let q = "summarize the latest audit findings";
        assert_eq!(
            classify_inbound(&reply(OWNER, q), OWNER),
            InboundDisposition::ChatPrompt(q)
        );
    }

    // IV-T1 — a spoofed sender mints NOTHING and records NOTHING, even with a
    // perfect approve text for a real pending action.
    #[test]
    fn iv_t1_spoofed_sender_is_dropped_before_any_mint() {
        let p = pending(1);
        let mut ledger = ApprovalSyncLedger::new();
        let out = authenticate_and_mint(
            &reply(ATTACKER, &approve_text(&p)),
            OWNER,
            &[p],
            &mut ledger,
            1,
        );
        assert!(matches!(out, InboundAuthOutcome::SenderNotOwner));
        // Nothing was recorded — a spoof cannot even consume a replay slot.
        assert_eq!(ledger.recorded(), 0);
    }

    // IV-T3 — an approval for an unknown action mints nothing; approving X never
    // touches Y.
    #[test]
    fn iv_t3_approval_binds_only_a_named_pending_action() {
        let x = pending(1);
        let y = pending(2);
        let mut ledger = ApprovalSyncLedger::new();
        // An approve naming an UNKNOWN action.
        let unknown = "approve 0000000000000000";
        let out = authenticate_and_mint(&reply(OWNER, unknown), OWNER, &[x, y], &mut ledger, 1);
        assert!(matches!(out, InboundAuthOutcome::NoSuchPendingAction));
        assert_eq!(ledger.recorded(), 0);
        // Approving X mints a grant bound to X — never Y.
        let out = authenticate_and_mint(
            &reply(OWNER, &approve_text(&x)),
            OWNER,
            &[x, y],
            &mut ledger,
            1,
        );
        match out {
            InboundAuthOutcome::Approved {
                grant,
                action_hash_32,
            } => {
                assert_eq!(action_hash_32, x.action_hash_32);
                assert_ne!(action_hash_32, y.action_hash_32);
                // The grant is bound to X by its audit hash.
                assert_eq!(grant.audit_hash_32(), x.action_hash_32);
            }
            other => panic!("expected Approved, got {other:?}"),
        }
    }

    // IV-T2 — a replayed approval is refused and fires the mint exactly once.
    #[test]
    fn iv_t2_replayed_approval_is_refused_and_fires_once() {
        let p = pending(1);
        let mut ledger = ApprovalSyncLedger::new();
        let first = authenticate_and_mint(
            &reply(OWNER, &approve_text(&p)),
            OWNER,
            &[p],
            &mut ledger,
            1,
        );
        assert!(matches!(first, InboundAuthOutcome::Approved { .. }));
        assert_eq!(ledger.recorded(), 1);
        // The SAME approval delivered again is refused (replay) — no second mint.
        let second = authenticate_and_mint(
            &reply(OWNER, &approve_text(&p)),
            OWNER,
            &[p],
            &mut ledger,
            2,
        );
        assert!(matches!(
            second,
            InboundAuthOutcome::ReplayOrUnbound(ApprovalSyncReject::ReplayDenied)
        ));
        assert_eq!(ledger.recorded(), 1);
    }

    // IV-T4 — an inbound mint is single-action + egress-only + fast-expiring; it
    // cannot authorize a SECOND action and cannot widen.
    #[test]
    fn iv_t4_mint_is_single_shot_and_cannot_widen() {
        use crate::commands::grant::GrantAuthorization;
        let p = pending(1);
        let mut ledger = ApprovalSyncLedger::new();
        let now = 10_000;
        let out = authenticate_and_mint(
            &reply(OWNER, &approve_text(&p)),
            OWNER,
            &[p],
            &mut ledger,
            now,
        );
        let InboundAuthOutcome::Approved { grant, .. } = out else {
            panic!("expected Approved");
        };
        // Single-shot: the FIRST action authorizes, a SECOND (used=1) is rate-denied.
        assert_eq!(grant.authorize(now + 1, 0), GrantAuthorization::Authorized);
        assert!(matches!(
            grant.authorize(now + 1, 1),
            GrantAuthorization::Denied(_)
        ));
        // Fast-expiring: at/after the TTL the grant is dead.
        assert!(matches!(
            grant.authorize(now + TELEGRAM_APPROVE_GRANT_TTL_MS, 0),
            GrantAuthorization::Denied(_)
        ));
        // Egress tier only (never mutate/custody).
        assert_eq!(grant.tier(), GrantTier::Egress);
    }

    // A deny is recorded (bound) but mints no grant; a different decision on the SAME
    // action is a distinct event (its own replay slot).
    #[test]
    fn deny_is_recorded_and_mints_no_grant() {
        let p = pending(1);
        let mut ledger = ApprovalSyncLedger::new();
        let out = authenticate_and_mint(
            &reply(OWNER, &format!("deny {}", p.id16())),
            OWNER,
            &[p],
            &mut ledger,
            1,
        );
        assert!(matches!(
            out,
            InboundAuthOutcome::Denied { action_hash_32 } if action_hash_32 == p.action_hash_32
        ));
        assert_eq!(ledger.recorded(), 1);
        // Approve of the SAME action is a DISTINCT event (different event_hash), so
        // it is not replay-blocked by the deny.
        let approve = authenticate_and_mint(
            &reply(OWNER, &approve_text(&p)),
            OWNER,
            &[p],
            &mut ledger,
            1,
        );
        assert!(matches!(approve, InboundAuthOutcome::Approved { .. }));
        assert_eq!(ledger.recorded(), 2);
    }

    // A non approve/deny reply is ignored (records nothing).
    #[test]
    fn unrecognized_reply_is_ignored() {
        let p = pending(1);
        let mut ledger = ApprovalSyncLedger::new();
        let out = authenticate_and_mint(
            &reply(OWNER, "hello there bot"),
            OWNER,
            &[p],
            &mut ledger,
            1,
        );
        assert!(matches!(out, InboundAuthOutcome::UnrecognizedReply));
        assert_eq!(ledger.recorded(), 0);
    }

    // IV-A5 / D-A2 (ENDGAME E10-2b) — a tool-side-effect (MUTATE) approval mints a
    // TIER-CORRECT mutate grant bound to the action; a TelegramRemoteControl
    // (EGRESS) approval mints an egress grant. The tiers cannot cross.
    #[test]
    fn tool_side_effect_mints_a_mutate_grant_egress_action_mints_egress() {
        use crate::commands::grant::GrantTier;

        let mutate_pending = PendingApproval::new(action_hash(7), ApprovalAction::ToolSideEffect);
        let mut ledger = ApprovalSyncLedger::new();
        let out = authenticate_and_mint(
            &reply(OWNER, &approve_text(&mutate_pending)),
            OWNER,
            &[mutate_pending],
            &mut ledger,
            10_000,
        );
        match out {
            InboundAuthOutcome::ApprovedMutate {
                grant,
                action_hash_32,
            } => {
                assert_eq!(action_hash_32, mutate_pending.action_hash_32);
                assert_eq!(grant.tier(), GrantTier::MutateLocal);
                // bound to THIS action by its audit hash (single-shot).
                assert_eq!(grant.audit_hash_32(), mutate_pending.action_hash_32);
            }
            other => panic!("expected ApprovedMutate, got {other:?}"),
        }

        // an EGRESS-tier action still mints an egress Approved (byte-unchanged path).
        let egress_pending =
            PendingApproval::new(action_hash(8), ApprovalAction::TelegramRemoteControl);
        let mut ledger2 = ApprovalSyncLedger::new();
        let out2 = authenticate_and_mint(
            &reply(OWNER, &approve_text(&egress_pending)),
            OWNER,
            &[egress_pending],
            &mut ledger2,
            10_000,
        );
        match out2 {
            InboundAuthOutcome::Approved { grant, .. } => {
                assert_eq!(grant.tier(), GrantTier::Egress);
            }
            other => panic!("expected Approved (egress), got {other:?}"),
        }
    }
}
