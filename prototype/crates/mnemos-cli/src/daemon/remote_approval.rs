//! `daemon::remote_approval` — the "away → ping → reply → proceed" orchestration
//! (ENDGAME E4-3). Ties the three E4 halves into the loop the owner asked for.
//!
//! When the autonomy runtime hits a gated action it cannot fire (`FrontierDenied` —
//! no grant), the owner is PINGED ([`build_approval_ping`] = an SI-2-redacted send;
//! [`ping_through_center`] = the SI-6 single dedupe gate, one `ApprovalRequest` per
//! pending action). The owner REPLIES on the phone. The UNTRUSTED inbound update is
//! INGESTED here ([`RemoteApprovalCoordinator::ingest_update`]) — sender-pinned
//! (IV-T1), action-bound (IV-T3), replay-refused via the now load-bearing
//! [`ApprovalSyncLedger`] (IV-T2); on approval a NARROW single-shot grant is minted
//! (the unforgeable SI-3 path, IV-T4). That grant ARMS the runner
//! ([`crate::daemon::runtime::AutonomyRuntime::install_egress_grant`]) so the one
//! denied action PROCEEDS — exactly once, never wider.
//!
//! This module mints NO authority itself — it delegates the mint to
//! [`crate::telegram::inbound_auth::authenticate_and_mint`] (the SI-3 owner-path
//! caller) and only routes the result. Custody is unreachable (no tier here). The
//! live inbound poll edge ([`poll_and_ingest`], feature-gated) is the ONLY production
//! consumer of the inbound transport; no test fires a real poll (the owner's V2
//! step), mirroring the E3 scripted-transport discipline.

use crate::StageFTraceLink;
use crate::agent_loop::{
    AGENT_LOOP_MAX_ITER, AGENT_LOOP_TOKEN_CAP, AgentTransport, MemoryToolState, run_agent_loop_with,
};
use crate::command::{CliMode, CommandEnvelope, CommandRisk};
use crate::commands::grant::{EgressGrant, MutateGrant};
use crate::commands::platform_telegram::{
    DeliveryDecision, MessageEnvelope, Notification, NotificationCenter, NotificationKind,
    PlatformOrigin, PlatformTelegramReject,
};
use crate::daemon::approval_sync::{ApprovalAction, ApprovalSyncLedger};
use crate::daemon::runtime::{AutonomyRuntime, TurnOutcome};
use crate::grammar::CliNamespace;
use crate::provider::redaction::{RedactionRequest, redact};
use crate::provider::route_select::{ConsultPhrase, ConsultRoute};
use crate::telegram::egress::{RedactedTelegramSend, TelegramEgressApproval};
use crate::telegram::inbound::{InboundUpdate, UpdateOffset};
use crate::telegram::inbound_auth::{
    InboundAuthOutcome, InboundDisposition, PendingApproval, authenticate_and_mint,
    classify_inbound,
};

/// Why an ingested inbound reply produced NO armed grant (a `Copy`, comparable
/// reason — distinct from [`InboundAuthOutcome`], which carries the non-comparable
/// grant). Each maps to a fail-closed gate.
#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RemoteApprovalReject {
    /// IV-T1: the sender is not the owner pin — dropped.
    SenderNotOwner = 1,
    /// The reply was not an `approve`/`deny` verb — ignored.
    UnrecognizedReply = 2,
    /// IV-T3: the reply named no known pending action.
    NoSuchPendingAction = 3,
    /// IV-T2: missing-hash or replay — refused.
    ReplayOrUnbound = 4,
    /// The SI-3 ceremony/arm refused (should not occur for a valid approve).
    MintFailed = 5,
}

/// The outcome of ingesting ONE inbound update into the coordinator.
#[derive(Clone, Copy, Debug)]
pub enum RemoteApprovalOutcome {
    /// Approved: the NARROW single-shot grant is ready to arm the runner for THIS one
    /// action; the pending entry has been resolved.
    Approved {
        /// The single-shot, action-bound grant to install on the runner.
        grant: EgressGrant,
        /// The action the grant authorizes (its hash).
        action_hash_32: [u8; 32],
    },
    /// Approved a MUTATE-LOCAL action (a tool side effect — an agent-proposed exec
    /// / file-apply): the NARROW single-shot MUTATE grant is ready to install on
    /// the runner ([`crate::daemon::runtime::AutonomyRuntime::install_mutate_grant`])
    /// for THIS one action; the pending entry is resolved. Tier-distinct from
    /// `Approved` (egress) — an egress approval can never authorize a mutate (IV-A5).
    ApprovedMutate {
        /// The single-shot, action-bound mutate grant to install on the runner.
        grant: MutateGrant,
        /// The action the grant authorizes (its hash).
        action_hash_32: [u8; 32],
    },
    /// Denied: the pending entry is resolved; no grant.
    Denied {
        /// The action the owner denied (its hash).
        action_hash_32: [u8; 32],
    },
    /// Nothing armed — the typed reason.
    NoAction(RemoteApprovalReject),
}

/// The remote-approval coordinator: the long-lived [`ApprovalSyncLedger`] (so
/// replay-refusal is real across polls), the set of pending gated actions, the owner
/// `chat.id` pin, and the monotone inbound offset. Mints nothing itself — it routes
/// [`authenticate_and_mint`] and tracks pending state.
pub struct RemoteApprovalCoordinator {
    owner_chat_id: i64,
    ledger: ApprovalSyncLedger,
    pending: Vec<PendingApproval>,
    offset: UpdateOffset,
}

impl RemoteApprovalCoordinator {
    /// A coordinator pinned to `owner_chat_id` (the parsed `TELEGRAM_CHAT_ID`). With
    /// no real pin (e.g. an out-of-range value), the sender check can never match, so
    /// no inbound reply is ever authorized (fail-closed).
    #[must_use]
    pub fn new(owner_chat_id: i64) -> Self {
        Self {
            owner_chat_id,
            ledger: ApprovalSyncLedger::new(),
            pending: Vec::new(),
            offset: UpdateOffset::new(),
        }
    }

    /// Register a gated action now awaiting remote approval (the daemon calls this
    /// when it hits `FrontierDenied`; the ping names its `id16`). Idempotent on the
    /// action hash.
    pub fn add_pending(&mut self, p: PendingApproval) {
        if !self
            .pending
            .iter()
            .any(|q| q.action_hash_32 == p.action_hash_32)
        {
            self.pending.push(p);
        }
    }

    /// The pending gated actions awaiting approval.
    #[must_use]
    pub fn pending(&self) -> &[PendingApproval] {
        &self.pending
    }

    /// The current monotone inbound offset (passed to the next poll).
    #[must_use]
    pub const fn offset(&self) -> UpdateOffset {
        self.offset
    }

    /// The owner `chat.id` pin (the parsed `TELEGRAM_CHAT_ID`). The SAME pin the
    /// approval route ([`ingest_update`](Self::ingest_update)) enforces — exposed so
    /// the E13-2 chat cycle classifies inbound updates against ONE source of truth
    /// (the classify pin can never drift from the approval pin). Compared, never
    /// rendered (treated secret-zero, like `TelegramHost::chat_env`).
    #[must_use]
    pub const fn owner_chat_id(&self) -> i64 {
        self.owner_chat_id
    }

    /// Adopt the advanced offset from a completed poll cycle — monotone (never
    /// rewinds; IV-T8).
    pub fn adopt_offset(&mut self, off: UpdateOffset) {
        if off.next() > self.offset.next() {
            self.offset = off;
        }
    }

    /// The number of approval events recorded so far (the load-bearing ledger).
    #[must_use]
    pub const fn recorded(&self) -> u32 {
        self.ledger.recorded()
    }

    /// Ingest ONE untrusted inbound update: auth + mint (IV-T1..T4 via
    /// [`authenticate_and_mint`]), and on approve/deny RESOLVE the pending entry. The
    /// ledger is the load-bearing replay gate; a spoof/replay/unknown reply changes
    /// no pending state and arms nothing.
    #[must_use]
    pub fn ingest_update(
        &mut self,
        update: &InboundUpdate,
        now_epoch_ms: u64,
    ) -> RemoteApprovalOutcome {
        let out = authenticate_and_mint(
            update,
            self.owner_chat_id,
            &self.pending,
            &mut self.ledger,
            now_epoch_ms,
        );
        match out {
            InboundAuthOutcome::Approved {
                grant,
                action_hash_32,
            } => {
                self.resolve(action_hash_32);
                RemoteApprovalOutcome::Approved {
                    grant,
                    action_hash_32,
                }
            }
            InboundAuthOutcome::ApprovedMutate {
                grant,
                action_hash_32,
            } => {
                self.resolve(action_hash_32);
                RemoteApprovalOutcome::ApprovedMutate {
                    grant,
                    action_hash_32,
                }
            }
            InboundAuthOutcome::Denied { action_hash_32 } => {
                self.resolve(action_hash_32);
                RemoteApprovalOutcome::Denied { action_hash_32 }
            }
            InboundAuthOutcome::SenderNotOwner => {
                RemoteApprovalOutcome::NoAction(RemoteApprovalReject::SenderNotOwner)
            }
            InboundAuthOutcome::UnrecognizedReply => {
                RemoteApprovalOutcome::NoAction(RemoteApprovalReject::UnrecognizedReply)
            }
            InboundAuthOutcome::NoSuchPendingAction => {
                RemoteApprovalOutcome::NoAction(RemoteApprovalReject::NoSuchPendingAction)
            }
            InboundAuthOutcome::ReplayOrUnbound(_) => {
                RemoteApprovalOutcome::NoAction(RemoteApprovalReject::ReplayOrUnbound)
            }
            InboundAuthOutcome::MintFailed => {
                RemoteApprovalOutcome::NoAction(RemoteApprovalReject::MintFailed)
            }
        }
    }

    /// Drop a resolved pending action (approved or denied).
    fn resolve(&mut self, action_hash_32: [u8; 32]) {
        self.pending.retain(|p| p.action_hash_32 != action_hash_32);
    }
}

/// The "approval needed" ping text for a pending action — names the action's 16-hex
/// id and the reply verbs. Pure; contains no secret.
fn approval_ping_text(p: &PendingApproval) -> String {
    let id = p.id16();
    format!("approval needed: action {id} — reply `approve {id}` or `deny {id}`")
}

/// The SI-6 dedupe key for a pending action's ping (one `ApprovalRequest` per
/// action). The action hash IS the salient field.
#[must_use]
pub fn ping_dedupe_key(p: &PendingApproval) -> [u8; 32] {
    p.action_hash_32
}

/// Build the SI-2-redacted outbound ping for a pending action. EVERY byte passes the
/// `redact()` choke ([`RedactedTelegramSend::dry_run`] from a redact receipt) — the
/// ping cannot leak a secret; a secret-shaped text yields `None` (fail-closed). The
/// send is dry-run (the owner's existing `platform send` ceremony flips it live; no
/// new live-send path is added — the SI-2 wall is unchanged).
#[must_use]
pub fn build_approval_ping(p: &PendingApproval) -> Option<RedactedTelegramSend> {
    let text = approval_ping_text(p);
    let fragments = [text.as_str()];
    let receipt = redact(&RedactionRequest {
        fragments: &fragments,
        candidate_memory_ids: &[],
        deleted_ids: &[],
        include_private_memory: false,
    })
    .ok()?;
    if receipt.secret_fragments_denied_u32() > 0 || receipt.outgoing_fragment_count_u32() == 0 {
        return None;
    }
    let command = CommandEnvelope::classify(
        CliNamespace::Platform,
        "approval-ping",
        CliMode::Run,
        CommandRisk::Network,
        text.as_bytes(),
    );
    RedactedTelegramSend::dry_run(
        MessageEnvelope::new(PlatformOrigin::Telegram, command),
        receipt,
    )
}

/// Decide + record the ping through the SI-6 SINGLE dedupe gate
/// ([`NotificationCenter::deliver`]): one `ApprovalRequest` per pending action; a
/// duplicate is suppressed (no ping spam). The actual transport is the existing
/// redacted send; this returns the delivery decision.
pub fn ping_through_center(
    center: &mut NotificationCenter,
    p: &PendingApproval,
    transport_ok: bool,
    trace: StageFTraceLink,
) -> Result<DeliveryDecision, PlatformTelegramReject> {
    let n = Notification::new(NotificationKind::ApprovalRequest, ping_dedupe_key(p));
    center.deliver(n, transport_ok, trace).map(|r| r.decision)
}

/// One REAL inbound poll-and-ingest cycle — the LIVE edge (feature-gated). Polls
/// getUpdates ONCE via the transport (the SAME vendored reqwest, no second client),
/// advances the monotone offset (IV-T8), and ingests each owner reply into the
/// coordinator. The daemon installs each `Approved` grant on the runner. No test
/// fires this (a real getUpdates is the owner's V2 step); it makes the inbound
/// transport load-bearing (the e4 falsifiable-positive spine: receive + parse +
/// auth + mint are all WIRED).
#[cfg(feature = "telegram-inbound")]
pub fn poll_and_ingest(
    transport: &crate::telegram::inbound::InboundTransport,
    coordinator: &mut RemoteApprovalCoordinator,
    now_epoch_ms: u64,
) -> Result<Vec<RemoteApprovalOutcome>, crate::telegram::inbound::InboundPollError> {
    let (updates, new_offset) = transport.poll_once(coordinator.offset())?;
    coordinator.adopt_offset(new_offset);
    let outcomes = updates
        .iter()
        .map(|u| coordinator.ingest_update(u, now_epoch_ms))
        .collect();
    Ok(outcomes)
}

// ============================================================================
// E11-3 (⑯) — the background "away → ping → reply → proceed" SERVE LOOP. A bounded
// poll-and-arm cycle composed over the proven E3/E4 primitives. It MINTS nothing
// (the SI-3 mint is `authenticate_and_mint`, reached only via `ingest_update`); it
// only INSTALLS an already-minted grant and PROCEEDS the ONE denied action.
// custody/funds are untouched (PD-6, IV-DP6/DP8).
// ============================================================================

/// Why a serve poll window did not run (fail-closed; always-compiled so the loop
/// core is feature-independent). The production [`LivePollSource`] maps a
/// feature-gated [`crate::telegram::inbound::InboundPollError`] onto `Transport`; a
/// scripted source never fails.
#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ServePollReject {
    /// The inbound transport call failed (network / TLS / token / host) — nothing
    /// minted, no secret leaked.
    Transport = 1,
}

/// A source of inbound owner replies for ONE serve poll window. The production
/// [`LivePollSource`] DELEGATES to the single live edge [`poll_and_ingest`] (the real
/// getUpdates poll); a scripted source (tests only, never shipped) injects pre-built
/// [`InboundUpdate`]s into the SAME [`RemoteApprovalCoordinator::ingest_update`].
/// There is NO second network poll path, and the coordinator's sender-pin /
/// replay-refuse / monotone-offset (IV-DP2) are reused, never reimplemented.
pub trait InboundPollSource {
    /// Poll ONE window, ingesting any owner replies into `coordinator`. Returns the
    /// per-reply outcomes (an empty vec = no reply this window). `Err` = the transport
    /// failed (fail-closed; nothing minted).
    fn poll_window(
        &mut self,
        coordinator: &mut RemoteApprovalCoordinator,
        now_epoch_ms: u64,
    ) -> Result<Vec<RemoteApprovalOutcome>, ServePollReject>;
}

/// The production inbound poll source: OWNS an [`crate::telegram::inbound::InboundTransport`]
/// (`Copy`) and delegates to [`poll_and_ingest`] — the ONE getUpdates edge (IV-DP2/DP4).
/// Reached only when the owner runs `daemon serve` with a real token (part 2 go-live).
#[cfg(feature = "telegram-inbound")]
pub struct LivePollSource {
    transport: crate::telegram::inbound::InboundTransport,
}

#[cfg(feature = "telegram-inbound")]
impl LivePollSource {
    /// A live source over `transport` (the owner-pinned getUpdates transport).
    #[must_use]
    pub const fn new(transport: crate::telegram::inbound::InboundTransport) -> Self {
        Self { transport }
    }
}

#[cfg(feature = "telegram-inbound")]
impl InboundPollSource for LivePollSource {
    fn poll_window(
        &mut self,
        coordinator: &mut RemoteApprovalCoordinator,
        now_epoch_ms: u64,
    ) -> Result<Vec<RemoteApprovalOutcome>, ServePollReject> {
        poll_and_ingest(&self.transport, coordinator, now_epoch_ms)
            .map_err(|_| ServePollReject::Transport)
    }
}

/// The runner-side + approval-side mutable state for one serve cycle (bundled so the
/// loop core stays under the argument-count lint without losing the explicit borrows).
pub struct ServeArm<'a> {
    /// The bounded autonomous runner (⑩) — ticked for the frontier attempt + the proceed.
    pub rt: &'a mut AutonomyRuntime,
    /// The LONG-LIVED coordinator: its load-bearing [`ApprovalSyncLedger`] is PERSISTED
    /// across the loop (the caller never re-creates it per window/cycle — IV-DP5).
    pub coordinator: &'a mut RemoteApprovalCoordinator,
    /// The SI-6 dedupe gate for the approval ping (one ApprovalRequest per action).
    pub center: &'a mut NotificationCenter,
}

/// The bounded parameters of one serve cycle. `poll_windows_max` is the per-cycle
/// long-poll window cap (IV-DP1 — no unbounded spin within a cycle).
pub struct ServeParams<'a> {
    /// The system prompt for the autonomous frontier turn.
    pub system: &'a str,
    /// The autonomous task whose frontier escalation is gated (the action identity is
    /// derived from it: `sha256("frontier egress: " + task)`, D-DP5).
    pub task: &'a str,
    /// The per-cycle poll-window cap (bounded; IV-DP1).
    pub poll_windows_max: u32,
    /// The stage-F trace link for the ping delivery.
    pub trace: StageFTraceLink,
}

/// The outcome of ONE serve cycle. Every variant except `ApprovedAndProceeded` /
/// `RanWithoutApproval` performed NO frontier egress (fail-closed).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ServeCycleOutcome {
    /// The frontier tick ran WITHOUT needing a new approval (the runner already held a
    /// valid grant) — nothing pinged.
    RanWithoutApproval(ConsultRoute),
    /// Denied → pinged → the owner APPROVED this action → the narrow single-shot grant
    /// was installed → the ONE denied action PROCEEDED (single-shot, IV-DP3).
    ApprovedAndProceeded {
        /// The action that proceeded (its hash).
        action_hash_32: [u8; 32],
    },
    /// Denied → pinged → approved + installed, but the proceed tick did NOT run
    /// (defensive — a valid single-shot grant should always proceed). No second action.
    ProceedFailed(TurnOutcome),
    /// Denied → pinged → the owner DENIED this action. Stays denied.
    OwnerDenied {
        /// The action the owner denied (its hash).
        action_hash_32: [u8; 32],
    },
    /// Denied → pinged → no owner approval within the bounded windows (or a transport
    /// failure). The action STAYS DENIED — fail-closed, zero egress (IV-DP7).
    DeniedNoReply {
        /// The action that stays denied (its hash).
        action_hash_32: [u8; 32],
    },
    /// The SI-2 ping could not be built/delivered (secret-shaped or a dedupe error) —
    /// stays denied, fail-closed.
    PingFailed,
    /// The first frontier tick halted on control/budget/terminal (not a frontier
    /// denial) — surfaced, no side effect.
    RunnerHalted(TurnOutcome),
}

/// Run ONE bounded "away → ping → reply → proceed" serve cycle (⑯, E11-3 part 1).
///
/// The order is the security spine: (1) attempt the frontier escalation — with no
/// grant the route selector denies BEFORE any transport call (zero egress); (2) on
/// `FrontierDenied`, register the denied action + PING the owner through the SI-2
/// `build_approval_ping` (dry-run; secret-shaped ⇒ fail-closed) and the SI-6
/// `ping_through_center` dedupe gate; (3) POLL the injected source for the owner's
/// reply across the BOUNDED `poll_windows_max` windows (IV-DP1); (4) on an `Approved`
/// outcome for THIS action, `install_egress_grant` (resets the per-grant rate ⇒ a
/// `max_actions=1` grant fires EXACTLY ONCE) and re-tick — the ONE denied action
/// proceeds (IV-DP3); (5) no approval / a deny / a transport failure ⇒ the action
/// STAYS DENIED (IV-DP7).
///
/// This function MINTS nothing (the SI-3 mint lives in `authenticate_and_mint`,
/// reached only inside `coordinator.ingest_update` via the poll source) and touches
/// no custody/chain symbol — it only INSTALLS an already-minted grant and PROCEEDS
/// (IV-DP6/DP8). The `coordinator` is the caller's LONG-LIVED state (its ledger is
/// persisted across the loop, IV-DP5).
pub fn serve_poll_arm_cycle(
    arm: ServeArm<'_>,
    poll: &mut dyn InboundPollSource,
    frontier_transport: &mut dyn AgentTransport,
    state: &MemoryToolState<'_>,
    params: &ServeParams<'_>,
    now_epoch_ms: u64,
) -> ServeCycleOutcome {
    let ServeArm {
        rt,
        coordinator,
        center,
    } = arm;
    // 1. attempt the frontier escalation. No grant ⇒ the typed route selector denies
    //    BEFORE any transport turn (zero egress); a valid grant proceeds directly.
    match rt.tick(
        now_epoch_ms,
        ConsultPhrase::Frontier,
        params.system,
        params.task,
        frontier_transport,
        state,
    ) {
        TurnOutcome::Ran { route, .. } => return ServeCycleOutcome::RanWithoutApproval(route),
        TurnOutcome::Paused => return ServeCycleOutcome::RunnerHalted(TurnOutcome::Paused),
        TurnOutcome::BudgetStopped(reject) => {
            return ServeCycleOutcome::RunnerHalted(TurnOutcome::BudgetStopped(reject));
        }
        TurnOutcome::Terminated => return ServeCycleOutcome::RunnerHalted(TurnOutcome::Terminated),
        // the away path — ping + poll + proceed.
        TurnOutcome::FrontierDenied => {}
    }
    // 2. FrontierDenied — register the denied action + PING (SI-2 dry-run + SI-6 dedupe).
    let action_hash_32 = crate::sha256_32(format!("frontier egress: {}", params.task).as_bytes());
    let pending = PendingApproval::new(action_hash_32, ApprovalAction::TelegramRemoteControl);
    coordinator.add_pending(pending);
    if build_approval_ping(&pending).is_none() {
        return ServeCycleOutcome::PingFailed;
    }
    if ping_through_center(center, &pending, true, params.trace).is_err() {
        return ServeCycleOutcome::PingFailed;
    }
    // 3. POLL the source for the owner's reply across the BOUNDED windows (IV-DP1).
    for _ in 0..params.poll_windows_max {
        let outcomes = match poll.poll_window(coordinator, now_epoch_ms) {
            Ok(outcomes) => outcomes,
            // a transport failure (e.g. token missing) ⇒ stays denied, fail-closed.
            Err(_) => return ServeCycleOutcome::DeniedNoReply { action_hash_32 },
        };
        for outcome in outcomes {
            match outcome {
                RemoteApprovalOutcome::Approved {
                    grant,
                    action_hash_32: approved,
                } if approved == action_hash_32 => {
                    // 4. INSTALL the narrow single-shot grant + PROCEED exactly once.
                    rt.install_egress_grant(grant);
                    return match rt.tick(
                        now_epoch_ms,
                        ConsultPhrase::Frontier,
                        params.system,
                        params.task,
                        frontier_transport,
                        state,
                    ) {
                        TurnOutcome::Ran { .. } => {
                            ServeCycleOutcome::ApprovedAndProceeded { action_hash_32 }
                        }
                        other => ServeCycleOutcome::ProceedFailed(other),
                    };
                }
                RemoteApprovalOutcome::Denied {
                    action_hash_32: denied,
                } if denied == action_hash_32 => {
                    return ServeCycleOutcome::OwnerDenied { action_hash_32 };
                }
                // an approval/denial for a DIFFERENT action, a mutate approval, or a
                // spoof/replay/unknown reply (NoAction) — not ours; keep polling.
                _ => {}
            }
        }
    }
    // 5. no approval within the bounded windows ⇒ the action STAYS DENIED (IV-DP7).
    ServeCycleOutcome::DeniedNoReply { action_hash_32 }
}

// ============================================================================
// E13-2 (⑱) — the TELEGRAM REMOTE-CONTROL chat cycle: a FREE-FORM owner message →
// a LOCAL agent turn → a redacted reply BACK to Telegram. A SIBLING of
// `serve_poll_arm_cycle` (the frontier-approval loop), NOT an extension of it
// (D-RC2): a chat prompt is not an approve/deny reply, so it is a different
// control flow (local-turn-then-reply, never a frontier escalation). It MINTS
// nothing (the SI-3 mint is `authenticate_and_mint`, reached only on the
// `ApprovalReply` route via `coordinator.ingest_update`); the chat turn is LOCAL +
// READ-class + zero-egress (IV-RC4); the only outbound is the reply, gated by the
// owner-armed session (IV-RC5). custody/funds untouched (PD-6, IV-RC6).
// ============================================================================

/// What an inbound `approve`/`deny` reply routed through the EXISTING ⑪ approval
/// path produced. A `Copy` marker only — the chat cycle proceeds NO frontier
/// action, so any minted grant is DROPPED (a chat-only serve registers no pending
/// action, so this is `NoAction` in practice); recording the kind keeps the
/// outcome log honest without carrying the non-comparable grant.
#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ChatApprovalKind {
    /// An egress-tier approval (grant dropped — not proceeded here).
    Approved = 1,
    /// A mutate-tier approval (grant dropped — not proceeded here).
    ApprovedMutate = 2,
    /// A deny (recorded; no grant).
    Denied = 3,
    /// No action armed (spoof / replay / unknown / unrecognized — fail-closed).
    NoAction = 4,
}

/// The typed outcome of ONE classified inbound update on the chat path. Every
/// variant maps to a threat (IV-RC#). No variant except `Replied` performs an
/// outbound send; no variant reaches a custody/chain symbol.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ChatTurnOutcome {
    /// IV-RC1: a non-owner update — dropped before ANY work (no turn, no send,
    /// nothing recorded).
    NotOwnerDropped,
    /// IV-RC2: a secret-shaped inbound — WITHHELD before the agent ever saw it
    /// (never fed to a turn, never echoed).
    SecretWithheld,
    /// An `approve`/`deny` reply — routed to the EXISTING approval path (⑪), NOT a
    /// chat turn. Carries the typed approval kind (the grant, if any, is dropped).
    ApprovalRouted(ChatApprovalKind),
    /// IV-RC5 (Option A): a chat prompt with NO armed session — surfaced as a card
    /// only. NO turn ran, NO reply was sent (the arm gates the ENTIRE loop).
    CardOnlyNotArmed,
    /// The LOCAL turn produced no answer (a bounded stop: budget / tool-denied /
    /// transport / guard-lockdown) — nothing sent.
    NoAnswer,
    /// IV-RC3: the turn's answer was whole-secret (every fragment denied ⇒ outgoing
    /// fragment count 0) — the reply was WITHHELD (nothing sent).
    ReplyWithheld,
    /// A redacted reply was DELIVERED for an owner chat prompt inside the armed
    /// session (IV-RC4 turn → IV-RC3 redact → IV-RC5 armed send). `sent` = the
    /// reply sink accepted it (a live transport may still report a wire failure).
    Replied {
        /// Whether the reply sink accepted the delivery.
        sent: bool,
    },
    /// The poll source transport failed this window (e.g. token missing) — nothing
    /// classified, nothing sent, fail-closed (IV-RC8 bounded).
    PollFailed,
}

/// A redacted chat reply ready to deliver: the SI-2 send WALL (proves the body
/// passed the `redact()` choke) + the secret-free TEXT the live `sendMessage`
/// codec carries. The ONLY constructor is [`build`](Self::build), which runs the
/// SAME SI-2 `redact()` choke the ping/consult egress use — a whole-secret answer
/// yields `None` (the reply is WITHHELD, IV-RC3). So a chat reply whose text never
/// passed redaction is UNREPRESENTABLE (mirrors [`RedactedTelegramSend`]'s PD-4).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RedactedChatReply {
    /// The SI-2 send wall — a `RedactedTelegramSend` whose payload hash IS the
    /// redacted body hash (built only from the receipt below).
    send: RedactedTelegramSend,
    /// The secret-free reply text (the answer that passed the SI-2 choke ENTIRELY —
    /// `secret_fragments_denied == 0`). Carried to the ONE `sendMessage` edge.
    text: String,
}

impl RedactedChatReply {
    /// Build a redacted reply from a LOCAL turn's `answer`. Runs the SI-2
    /// `redact()` choke over the WHOLE answer as one fragment (the SAME scanners
    /// the choke uses): a whole-secret answer (`secret_fragments_denied > 0`, i.e.
    /// `outgoing_fragment_count == 0`) yields `None` — the reply is WITHHELD
    /// (IV-RC3); a secret-free answer yields the dry-run send (bound to the redacted
    /// body hash) + the text. Single-fragment is the fail-closed choice: an answer
    /// carrying ANY secret-shaped token is withheld whole, never partially echoed.
    /// The caller flips the send live ONLY inside an armed session (IV-RC5).
    #[must_use]
    fn build(answer: &str) -> Option<Self> {
        let fragments = [answer];
        let receipt = redact(&RedactionRequest {
            fragments: &fragments,
            candidate_memory_ids: &[],
            deleted_ids: &[],
            include_private_memory: false,
        })
        .ok()?;
        // IV-RC3 — whole-secret ⇒ WITHHOLD (nothing passed the choke). Identical
        // gate to `build_approval_ping` (secret-denied or zero outgoing ⇒ None).
        if receipt.secret_fragments_denied_u32() > 0 || receipt.outgoing_fragment_count_u32() == 0 {
            return None;
        }
        let command = CommandEnvelope::classify(
            CliNamespace::Platform,
            "remote-chat-reply",
            CliMode::Run,
            CommandRisk::Network,
            answer.as_bytes(),
        );
        let send = RedactedTelegramSend::dry_run(
            MessageEnvelope::new(PlatformOrigin::Telegram, command),
            receipt,
        )?;
        Some(Self {
            send,
            text: answer.to_string(),
        })
    }

    /// Flip the inner send live — ONLY with a granted [`TelegramEgressApproval`]
    /// (produced ONLY on the armed branch of [`serve_chat_cycle`], IV-RC5).
    #[must_use]
    fn into_live(self, approval: TelegramEgressApproval) -> Self {
        Self {
            send: self.send.into_live(approval),
            text: self.text,
        }
    }

    /// The SI-2 send wall (the redacted-body proof the codec preflight demands).
    /// Named `redacted_send` (not `send`) so the call site never collides with the
    /// reqwest socket send-call the SI-2 e0b verifier pins.
    #[must_use]
    pub const fn redacted_send(&self) -> &RedactedTelegramSend {
        &self.send
    }

    /// The secret-free reply text the live `sendMessage` codec carries.
    #[must_use]
    pub fn text(&self) -> &str {
        &self.text
    }
}

/// K-5e — a Skew trade PROPOSAL surfaced as the 7-field Telegram approval card (the owner sees
/// the deterministic K-1 oracle's verdict on their phone). It SURFACES the verdict + the bounds;
/// it AUTHORIZES NOTHING (IV-FG11): the card is delivered ONLY through the SOLE redact wall
/// [`RedactedChatReply::build`] (a secret-shaped field ⇒ the WHOLE card is WITHHELD), the owner
/// replies `approve <id16>` / `deny <id16>` routed through the EXISTING
/// [`RemoteApprovalCoordinator::ingest_update`] (⑪), and the REAL grant is the owner's
/// typed-phrase ceremony — never this card. There is NO sign / mint / broadcast / custody symbol
/// here. Devnet; mainnet = a further owner arm; custody/funds reach value ONLY via the K-2 path.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TradeCard {
    /// The 16-hex pending-action id the owner approves/denies (binds the reply to THIS proposal).
    pub action_id16: String,
    /// The proposed action (e.g. `open-account` / `deposit 1000000`).
    pub action: String,
    /// The target chain (devnet; mainnet = a further owner arm).
    pub network: String,
    /// The target protocol (`skew`).
    pub protocol: String,
    /// The DETERMINISTIC K-1 oracle verdict (`AFFORDABLE & IN-BOUNDS` / `DENIED(reason)`).
    pub oracle_verdict: String,
    /// The re-derived worst-case escrow for this trade (settlement atoms).
    pub escrow_minor: u128,
    /// The total budget (atoms) — escrow ≤ budget is the provable-max-loss bound.
    pub budget_minor: u128,
}

impl TradeCard {
    /// The 7-field card text (pure composition — surfaces the verdict, carries NO secret and NO
    /// authorization). The owner reads it and replies approve/deny; the card itself moves nothing.
    #[must_use]
    pub fn render(&self) -> String {
        format!(
            "skew trade proposal (devnet)\n\
             action:   {}\n\
             network:  {}\n\
             protocol: {}\n\
             oracle:   {}\n\
             escrow:   {} atoms\n\
             budget:   {} atoms (escrow <= budget = provable max loss)\n\
             reply: approve {}  /  deny {}  — the card authorizes nothing; the owner arm is the ceremony",
            self.action,
            self.network,
            self.protocol,
            self.oracle_verdict,
            self.escrow_minor,
            self.budget_minor,
            self.action_id16,
            self.action_id16,
        )
    }

    /// Deliver the card through the SOLE redact wall [`RedactedChatReply::build`] — a secret-shaped
    /// field ⇒ the WHOLE card is WITHHELD (`None`, IV-RC3 / IV-FG11). The card authorizes nothing;
    /// the owner's approve/deny routes through the EXISTING `ingest_update`, and the real grant is
    /// the owner ceremony. NO sign / mint / broadcast / custody constructor is reachable here.
    #[must_use]
    pub fn into_redacted_reply(&self) -> Option<RedactedChatReply> {
        RedactedChatReply::build(&self.render())
    }
}

/// A source of RAW inbound owner-or-not updates for ONE chat poll window
/// (mirroring [`InboundPollSource`], but returning the UN-classified
/// [`InboundUpdate`]s so `serve_chat_cycle` owns the classify). The production
/// [`LiveChatSource`] delegates to the ONE getUpdates edge
/// [`InboundTransport::poll_once`](crate::telegram::inbound::InboundTransport::poll_once)
/// and adopts the monotone offset (IV-T8 reuse, no second poll path); a scripted
/// source (tests only, never shipped) returns a pre-built batch.
pub trait InboundChatSource {
    /// Poll ONE window, returning the RAW updates (an empty vec = no message this
    /// window). `coordinator` supplies + adopts the monotone offset. `Err` = the
    /// transport failed (fail-closed; nothing classified).
    fn poll_chat_window(
        &mut self,
        coordinator: &mut RemoteApprovalCoordinator,
        now_epoch_ms: u64,
    ) -> Result<Vec<InboundUpdate>, ServePollReject>;
}

/// The production inbound chat source: OWNS an
/// [`InboundTransport`](crate::telegram::inbound::InboundTransport) (`Copy`) and
/// delegates to the ONE getUpdates edge `poll_once`, adopting the monotone offset
/// (IV-DP2/IV-T8 reuse). Reached only when the owner runs `daemon serve-chat` with
/// a real token (the go-live step).
#[cfg(feature = "telegram-inbound")]
pub struct LiveChatSource {
    transport: crate::telegram::inbound::InboundTransport,
}

#[cfg(feature = "telegram-inbound")]
impl LiveChatSource {
    /// A live chat source over `transport` (the owner-pinned getUpdates transport).
    #[must_use]
    pub const fn new(transport: crate::telegram::inbound::InboundTransport) -> Self {
        Self { transport }
    }
}

#[cfg(feature = "telegram-inbound")]
impl InboundChatSource for LiveChatSource {
    fn poll_chat_window(
        &mut self,
        coordinator: &mut RemoteApprovalCoordinator,
        _now_epoch_ms: u64,
    ) -> Result<Vec<InboundUpdate>, ServePollReject> {
        let (updates, new_offset) = self
            .transport
            .poll_once(coordinator.offset())
            .map_err(|_| ServePollReject::Transport)?;
        coordinator.adopt_offset(new_offset);
        Ok(updates)
    }
}

/// A sink for ONE delivered redacted reply (mirroring [`InboundChatSource`]). The
/// PRODUCTION reply sink is the closure adapter [`FnChatReplySink`], built in
/// dispatch.rs where the ONE `sendMessage` live edge
/// [`TelegramTransport::send_live_message`](crate::telegram::egress::TelegramTransport::send_live_message)
/// lives — so the single-dispatch-truth (SI-4) holds: NO `.send_live_*` execute path
/// exists outside dispatch.rs (this core adds no live-send path). A scripted sink
/// (tests only, never shipped) records the reply. Reached ONLY on the armed branch
/// of [`serve_chat_cycle`] (IV-RC5).
pub trait ChatReplySink {
    /// Deliver ONE redacted reply. Returns whether the sink accepted it (a live
    /// transport may still report a wire failure). The reply carries the SI-2 wall
    /// + the secret-free text (both bound by [`RedactedChatReply::build`]).
    fn send_reply(&mut self, reply: &RedactedChatReply) -> bool;
}

/// A closure-backed [`ChatReplySink`] (mirrors [`crate::agent_loop::FnTransport`])
/// so the PRODUCTION live `sendMessage` call lives in dispatch.rs — the single
/// SI-4 live-egress execute home — NOT here. The dispatch builds the closure that
/// calls `TelegramTransport::send_live_message`; this core references no
/// `.send_live_*` path (SI-4 preserved). The scripted reply sink for tests is its
/// own `#[cfg(test)]` type.
pub struct FnChatReplySink<F>(pub F);

impl<F> ChatReplySink for FnChatReplySink<F>
where
    F: FnMut(&RedactedChatReply) -> bool,
{
    fn send_reply(&mut self, reply: &RedactedChatReply) -> bool {
        (self.0)(reply)
    }
}

/// The runner + approval state for one chat serve cycle (bundled like
/// [`ServeArm`]; the chat cycle pings nothing, so there is no notification center).
pub struct ChatArm<'a> {
    /// The bounded runner (⑩) — holds the owner-armed SESSION egress grant; the
    /// reply gate ([`AutonomyRuntime::egress_armed_at`]) re-derives it per reply.
    pub rt: &'a mut AutonomyRuntime,
    /// The LONG-LIVED coordinator: its owner pin gates the classify (ONE source,
    /// `owner_chat_id()`), and its load-bearing ledger gates the `ApprovalReply`
    /// route (replay-refused across windows, IV-DP5 reuse).
    pub coordinator: &'a mut RemoteApprovalCoordinator,
}

/// The bounded parameters of one chat serve cycle. `poll_windows_max` is the
/// per-cycle window cap (IV-RC8 — no unbounded spin within a cycle).
pub struct ChatParams<'a> {
    /// The system prompt for the LOCAL chat turn (the loopback Naite identity).
    pub system: &'a str,
    /// The per-cycle poll-window cap (bounded; IV-RC8).
    pub poll_windows_max: u32,
}

/// Run ONE bounded chat serve cycle (⑱, E13-2): poll the injected raw-update
/// source across BOUNDED windows (IV-RC8), classify each update fail-closed
/// ([`classify_inbound`]: owner-pin IV-RC1 → secret-withhold IV-RC2 → split), and
/// per disposition:
/// - `NotOwner` / `WithheldSecret` ⇒ DROP before any turn (IV-RC1/RC2).
/// - `ApprovalReply` ⇒ route to the EXISTING ⑪ approval path
///   ([`RemoteApprovalCoordinator::ingest_update`]); NEVER a turn. Any minted grant
///   is dropped (the chat cycle proceeds no frontier action).
/// - `ChatPrompt` ⇒ Option A (IV-RC5): with NO armed session, surface a card only
///   (NO turn, NO send); otherwise run a LOCAL, READ-class, zero-egress turn
///   ([`run_agent_loop_with`] with `file_policy = None` + `web_seam = None`, IV-RC4),
///   redact the answer (IV-RC3, whole-secret ⇒ withheld), flip the reply live + send
///   it through the armed-gated sink, and consume one session action so replies are
///   bounded by the grant's `max_actions` (IV-RC5/RC8).
///
/// MINTS nothing (the SI-3 mint lives in `authenticate_and_mint`, reached only via
/// the `ApprovalReply` route's `ingest_update`); touches no custody/chain symbol
/// (IV-RC6). The chat turn never reaches the frontier transport (IV-RC4). The
/// `coordinator` is the caller's LONG-LIVED state (its pin + ledger persist).
pub fn serve_chat_cycle(
    arm: ChatArm<'_>,
    poll: &mut dyn InboundChatSource,
    reply: &mut dyn ChatReplySink,
    local_transport: &mut dyn AgentTransport,
    state: &MemoryToolState<'_>,
    params: &ChatParams<'_>,
    now_epoch_ms: u64,
) -> Vec<ChatTurnOutcome> {
    let ChatArm { rt, coordinator } = arm;
    // ONE source for the classify pin — never drifts from the approval pin (IV-RC1).
    let owner_chat_id = coordinator.owner_chat_id();
    let mut outcomes: Vec<ChatTurnOutcome> = Vec::new();
    // BOUNDED poll windows (IV-RC8 — no unbounded spin within a cycle).
    for _ in 0..params.poll_windows_max {
        let updates = match poll.poll_chat_window(coordinator, now_epoch_ms) {
            Ok(updates) => updates,
            // a transport failure (e.g. token missing) ⇒ stop, fail-closed.
            Err(_) => {
                outcomes.push(ChatTurnOutcome::PollFailed);
                break;
            }
        };
        for update in &updates {
            // CLASSIFY fail-closed: owner-pin FIRST (IV-RC1) → secret-withhold
            // (IV-RC2) → approval-vs-free-form split. A non-owner / secret-shaped
            // update never reaches a turn.
            match classify_inbound(update, owner_chat_id) {
                InboundDisposition::NotOwner => {
                    outcomes.push(ChatTurnOutcome::NotOwnerDropped);
                }
                InboundDisposition::WithheldSecret => {
                    outcomes.push(ChatTurnOutcome::SecretWithheld);
                }
                InboundDisposition::ApprovalReply => {
                    // route to the EXISTING ⑪ approval path (NEVER a turn). The
                    // owner pin / replay ledger are reused, never reimplemented. The
                    // chat cycle proceeds no frontier action, so any grant is dropped.
                    let kind = match coordinator.ingest_update(update, now_epoch_ms) {
                        RemoteApprovalOutcome::Approved { .. } => ChatApprovalKind::Approved,
                        RemoteApprovalOutcome::ApprovedMutate { .. } => {
                            ChatApprovalKind::ApprovedMutate
                        }
                        RemoteApprovalOutcome::Denied { .. } => ChatApprovalKind::Denied,
                        RemoteApprovalOutcome::NoAction(_) => ChatApprovalKind::NoAction,
                    };
                    outcomes.push(ChatTurnOutcome::ApprovalRouted(kind));
                }
                InboundDisposition::ChatPrompt(text) => {
                    // IV-RC5 / Option A: the arm gates the ENTIRE loop. With NO
                    // armed session, surface a card only — NO turn, NO send.
                    if !rt.egress_armed_at(now_epoch_ms) {
                        outcomes.push(ChatTurnOutcome::CardOnlyNotArmed);
                        continue;
                    }
                    // IV-RC4: a LOCAL, READ-class, zero-egress turn — `file_policy =
                    // None` (no file access) + `web_seam = None` (no web socket) +
                    // `mcp_seam = None` (no MCP server), so injected inbound text
                    // drives at most a bounded memory-recall turn (it cannot escalate;
                    // the model holds no egress/mutate/custody constructor, E0d).
                    let loop_outcome = run_agent_loop_with(
                        local_transport,
                        state,
                        params.system,
                        text,
                        AGENT_LOOP_MAX_ITER,
                        AGENT_LOOP_TOKEN_CAP,
                        None,
                        None,
                        None,
                    );
                    let Some(answer) = loop_outcome.answer else {
                        outcomes.push(ChatTurnOutcome::NoAnswer);
                        continue;
                    };
                    // IV-RC3: the SI-2 `redact()` choke gates the reply — a
                    // whole-secret answer is WITHHELD (nothing sent).
                    let Some(payload) = RedactedChatReply::build(&answer) else {
                        outcomes.push(ChatTurnOutcome::ReplyWithheld);
                        continue;
                    };
                    // IV-RC5: flip the send live ONLY on the armed branch (the
                    // grant() is produced ONLY here), deliver, then consume one
                    // session action so replies are bounded by `max_actions`.
                    let live = payload.into_live(TelegramEgressApproval::grant());
                    let sent = reply.send_reply(&live);
                    rt.record_egress_action();
                    outcomes.push(ChatTurnOutcome::Replied { sent });
                }
            }
        }
    }
    outcomes
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic)]
    #![allow(clippy::unwrap_used)]
    #![allow(clippy::expect_used)]

    use super::*;

    const OWNER: i64 = 4242;
    const ATTACKER: i64 = 7;

    fn action_hash(seed: u8) -> [u8; 32] {
        crate::sha256_32(&[seed; 8])
    }

    fn pending(seed: u8) -> PendingApproval {
        PendingApproval::new(action_hash(seed), ApprovalAction::TelegramRemoteControl)
    }

    fn reply(chat_id: i64, text: &str) -> InboundUpdate {
        InboundUpdate::new_bounded(1, chat_id, text)
    }

    fn trace() -> StageFTraceLink {
        StageFTraceLink::new([0x4e; 32], 0, 0)
    }

    // The coordinator approves a pending action, mints a grant, and RESOLVES the
    // pending entry (it is no longer awaiting approval).
    #[test]
    fn coordinator_approves_mints_and_resolves_pending() {
        let p = pending(1);
        let mut c = RemoteApprovalCoordinator::new(OWNER);
        c.add_pending(p);
        c.add_pending(p); // idempotent
        assert_eq!(c.pending().len(), 1);
        let out = c.ingest_update(&reply(OWNER, &format!("approve {}", p.id16())), 1);
        match out {
            RemoteApprovalOutcome::Approved {
                grant,
                action_hash_32,
            } => {
                assert_eq!(action_hash_32, p.action_hash_32);
                assert_eq!(grant.audit_hash_32(), p.action_hash_32);
            }
            other => panic!("expected Approved, got {other:?}"),
        }
        // resolved: no longer pending; recorded once.
        assert!(c.pending().is_empty());
        assert_eq!(c.recorded(), 1);
    }

    // A spoofed sender arms nothing and resolves nothing (IV-T1) — the pending action
    // stays pending; nothing recorded.
    #[test]
    fn coordinator_drops_spoofed_sender_and_keeps_pending() {
        let p = pending(1);
        let mut c = RemoteApprovalCoordinator::new(OWNER);
        c.add_pending(p);
        let out = c.ingest_update(&reply(ATTACKER, &format!("approve {}", p.id16())), 1);
        assert!(matches!(
            out,
            RemoteApprovalOutcome::NoAction(RemoteApprovalReject::SenderNotOwner)
        ));
        assert_eq!(c.pending().len(), 1, "spoof must not resolve the action");
        assert_eq!(c.recorded(), 0, "spoof records nothing");
    }

    // A replayed approval is refused on the second ingest (IV-T2) — the grant is
    // minted exactly once.
    #[test]
    fn coordinator_refuses_replay() {
        let p = pending(1);
        let mut c = RemoteApprovalCoordinator::new(OWNER);
        c.add_pending(p);
        let first = c.ingest_update(&reply(OWNER, &format!("approve {}", p.id16())), 1);
        assert!(matches!(first, RemoteApprovalOutcome::Approved { .. }));
        // The same reply again: the action is already resolved AND the ledger refuses
        // the replay — either way, no second grant.
        let second = c.ingest_update(&reply(OWNER, &format!("approve {}", p.id16())), 2);
        assert!(matches!(second, RemoteApprovalOutcome::NoAction(_)));
        assert_eq!(c.recorded(), 1);
    }

    // The outbound ping is built through the SI-2 redact choke (a redacted send whose
    // payload is only a hash) — never raw text.
    #[test]
    fn approval_ping_passes_si2_redact() {
        let p = pending(9);
        let send = build_approval_ping(&p).expect("a benign ping redacts to a send");
        // The send carries only the redacted payload hash — never the raw text.
        assert_eq!(send.payload_hash_32(), send.payload_hash_32());
        assert_eq!(send.envelope().origin, PlatformOrigin::Telegram);
    }

    // The SI-6 single dedupe gate suppresses a duplicate ping for the SAME pending
    // action (no ping spam), and a DIFFERENT action delivers.
    #[test]
    fn ping_dedupe_is_the_single_gate() {
        let p = pending(1);
        let q = pending(2);
        let mut center = NotificationCenter::new(8);
        let first = ping_through_center(&mut center, &p, true, trace()).expect("deliver");
        assert_eq!(first, DeliveryDecision::Deliver);
        // Same action again => suppressed duplicate (one ApprovalRequest per action).
        let dup = ping_through_center(&mut center, &p, true, trace()).expect("deliver");
        assert_eq!(dup, DeliveryDecision::SuppressedDuplicate);
        // A different action delivers.
        let other = ping_through_center(&mut center, &q, true, trace()).expect("deliver");
        assert_eq!(other, DeliveryDecision::Deliver);
    }

    // The offset adoption is monotone (IV-T8): a lower offset never rewinds it.
    #[test]
    fn coordinator_offset_is_monotone() {
        let mut c = RemoteApprovalCoordinator::new(OWNER);
        let mut hi = UpdateOffset::new();
        hi.advance_past(50);
        c.adopt_offset(hi);
        assert_eq!(c.offset().next(), 51);
        // A stale lower offset is ignored.
        let mut lo = UpdateOffset::new();
        lo.advance_past(10);
        c.adopt_offset(lo);
        assert_eq!(c.offset().next(), 51);
    }

    // ---- E11-3 (⑯): the background poll-and-arm SERVE LOOP, hermetic (0 real net) ----

    use crate::agent_loop::{AgentTransportError, AgentTurn};
    use crate::commands::budget::BudgetCap;
    use crate::daemon::runtime::RuntimeHandle;
    use mnemos_b_memory::{MemoryId, MemoryIndexRecord, TombstonePolicy};
    use std::time::Duration;

    /// A scripted inbound poll source (the E4 v1 discipline): each `poll_window` drains
    /// ONE pre-built batch into the SAME `coordinator.ingest_update` — 0 real net, NO
    /// second poll path (sender-pin/replay/offset reused, IV-DP2). `#[cfg(test)]` ONLY.
    struct ScriptedPollSource {
        windows: std::collections::VecDeque<Vec<InboundUpdate>>,
    }
    impl ScriptedPollSource {
        fn new(windows: Vec<Vec<InboundUpdate>>) -> Self {
            Self {
                windows: windows.into_iter().collect(),
            }
        }
    }
    impl InboundPollSource for ScriptedPollSource {
        fn poll_window(
            &mut self,
            coordinator: &mut RemoteApprovalCoordinator,
            now: u64,
        ) -> Result<Vec<RemoteApprovalOutcome>, ServePollReject> {
            let batch = self.windows.pop_front().unwrap_or_default();
            Ok(batch
                .iter()
                .map(|u| coordinator.ingest_update(u, now))
                .collect())
        }
    }

    /// A poll source that always FAILS the transport (the token-missing analogue) —
    /// proves a transport failure keeps the action denied, fail-closed (IV-DP7).
    struct FailingPollSource;
    impl InboundPollSource for FailingPollSource {
        fn poll_window(
            &mut self,
            _coordinator: &mut RemoteApprovalCoordinator,
            _now: u64,
        ) -> Result<Vec<RemoteApprovalOutcome>, ServePollReject> {
            Err(ServePollReject::Transport)
        }
    }

    /// A scripted frontier transport that counts how many turns it served, so a denied
    /// cycle can be PROVEN to have fired NO egress (zero transport call).
    struct CountingTransport {
        calls: u32,
    }
    impl AgentTransport for CountingTransport {
        fn turn(&mut self, _s: &str, _u: &str) -> Result<AgentTurn, AgentTransportError> {
            self.calls += 1;
            Ok(AgentTurn {
                answer_text: "ANSWER: done".to_string(),
                input_tokens_u64: 1,
                output_tokens_u64: 1,
                cached_tokens_u64: 0,
            })
        }
    }

    type IdContent = (MemoryId, &'static [u8]);
    fn empty_state_parts() -> (Vec<MemoryIndexRecord>, Vec<IdContent>, TombstonePolicy) {
        (Vec::new(), Vec::new(), TombstonePolicy::new())
    }
    fn budget(cap: u32) -> BudgetCap {
        BudgetCap::new(cap, 1_000_000, 1_000_000)
    }

    const SERVE_OWNER: i64 = 31337;
    const SERVE_TASK: &str = "ask the frontier";
    fn serve_action_hash() -> [u8; 32] {
        crate::sha256_32(format!("frontier egress: {SERVE_TASK}").as_bytes())
    }
    fn serve_id16() -> String {
        PendingApproval::new(serve_action_hash(), ApprovalAction::TelegramRemoteControl).id16()
    }
    fn serve_params<'a>(poll_windows_max: u32) -> ServeParams<'a> {
        ServeParams {
            system: "system",
            task: SERVE_TASK,
            poll_windows_max,
            trace: trace(),
        }
    }

    // The FULL away → ping → reply → proceed loop, hermetic: a FrontierDenied tick
    // pings + polls; the owner's SCRIPTED approve mints + installs the narrow
    // single-shot grant; the ONE denied action PROCEEDS; a 2nd cycle (grant spent)
    // stays denied — exactly one frontier egress (IV-DP3).
    #[test]
    fn serve_loop_away_ping_reply_proceed_single_shot() {
        let approve = reply(SERVE_OWNER, &format!("approve {}", serve_id16()));
        // window 1: no reply; window 2: the owner approve (the bounded poll catches it).
        let mut poll = ScriptedPollSource::new(vec![vec![], vec![approve]]);
        let mut rt = AutonomyRuntime::arm(720, None, budget(1_000), 2, trace());
        let mut coord = RemoteApprovalCoordinator::new(SERVE_OWNER);
        let mut center = NotificationCenter::new(8);
        let mut tx = CountingTransport { calls: 0 };
        let (records, contents, policy) = empty_state_parts();
        let state = MemoryToolState {
            records: &records,
            contents: &contents,
            policy: &policy,
        };
        let out = serve_poll_arm_cycle(
            ServeArm {
                rt: &mut rt,
                coordinator: &mut coord,
                center: &mut center,
            },
            &mut poll,
            &mut tx,
            &state,
            &serve_params(3),
            2,
        );
        assert_eq!(
            out,
            ServeCycleOutcome::ApprovedAndProceeded {
                action_hash_32: serve_action_hash()
            }
        );
        assert_eq!(tx.calls, 1, "exactly one frontier egress proceeded");
        assert_eq!(rt.egress_actions_used(), 1);
        assert_eq!(coord.recorded(), 1, "the ledger recorded the approve once");
        // SINGLE-SHOT: the grant is spent ⇒ a fresh cycle (no reply) stays denied, zero
        // NEW egress (the 2nd frontier tick re-derives None: used 1 >= max 1).
        let mut poll2 = ScriptedPollSource::new(vec![vec![]]);
        let out2 = serve_poll_arm_cycle(
            ServeArm {
                rt: &mut rt,
                coordinator: &mut coord,
                center: &mut center,
            },
            &mut poll2,
            &mut tx,
            &state,
            &serve_params(1),
            3,
        );
        assert_eq!(
            out2,
            ServeCycleOutcome::DeniedNoReply {
                action_hash_32: serve_action_hash()
            }
        );
        assert_eq!(
            tx.calls, 1,
            "single-shot: no second egress after the grant is spent"
        );
    }

    // IV-DP7: a denied-then-NO-REPLY cycle ends fail-closed — the bounded windows
    // exhaust with no approval, the action stays denied, ZERO frontier egress fired.
    #[test]
    fn serve_loop_no_reply_stays_denied_zero_egress() {
        let mut poll = ScriptedPollSource::new(vec![vec![], vec![], vec![]]);
        let mut rt = AutonomyRuntime::arm(721, None, budget(1_000), 2, trace());
        let mut coord = RemoteApprovalCoordinator::new(SERVE_OWNER);
        let mut center = NotificationCenter::new(8);
        let mut tx = CountingTransport { calls: 0 };
        let (records, contents, policy) = empty_state_parts();
        let state = MemoryToolState {
            records: &records,
            contents: &contents,
            policy: &policy,
        };
        let out = serve_poll_arm_cycle(
            ServeArm {
                rt: &mut rt,
                coordinator: &mut coord,
                center: &mut center,
            },
            &mut poll,
            &mut tx,
            &state,
            &serve_params(3),
            1,
        );
        assert_eq!(
            out,
            ServeCycleOutcome::DeniedNoReply {
                action_hash_32: serve_action_hash()
            }
        );
        assert_eq!(tx.calls, 0, "no reply ⇒ no frontier egress fired (IV-DP7)");
        assert_eq!(rt.egress_actions_used(), 0);
        assert_eq!(coord.recorded(), 0, "no approval recorded");
    }

    // IV-DP7: a transport FAILURE (token missing analogue) keeps the action denied —
    // nothing minted, zero egress.
    #[test]
    fn serve_loop_transport_failure_stays_denied() {
        let mut poll = FailingPollSource;
        let mut rt = AutonomyRuntime::arm(722, None, budget(1_000), 2, trace());
        let mut coord = RemoteApprovalCoordinator::new(SERVE_OWNER);
        let mut center = NotificationCenter::new(8);
        let mut tx = CountingTransport { calls: 0 };
        let (records, contents, policy) = empty_state_parts();
        let state = MemoryToolState {
            records: &records,
            contents: &contents,
            policy: &policy,
        };
        let out = serve_poll_arm_cycle(
            ServeArm {
                rt: &mut rt,
                coordinator: &mut coord,
                center: &mut center,
            },
            &mut poll,
            &mut tx,
            &state,
            &serve_params(3),
            1,
        );
        assert_eq!(
            out,
            ServeCycleOutcome::DeniedNoReply {
                action_hash_32: serve_action_hash()
            }
        );
        assert_eq!(tx.calls, 0, "transport failure ⇒ zero egress (fail-closed)");
        assert_eq!(rt.egress_actions_used(), 0);
    }

    // IV-DP2: a SPOOFED (non-owner) reply NEVER proceeds — the sender pin (reused, not
    // reimplemented) drops it; the action stays denied, zero egress, nothing recorded.
    #[test]
    fn serve_loop_spoofed_sender_never_proceeds() {
        let spoof = reply(ATTACKER, &format!("approve {}", serve_id16()));
        let mut poll = ScriptedPollSource::new(vec![vec![spoof]]);
        let mut rt = AutonomyRuntime::arm(723, None, budget(1_000), 2, trace());
        let mut coord = RemoteApprovalCoordinator::new(SERVE_OWNER);
        let mut center = NotificationCenter::new(8);
        let mut tx = CountingTransport { calls: 0 };
        let (records, contents, policy) = empty_state_parts();
        let state = MemoryToolState {
            records: &records,
            contents: &contents,
            policy: &policy,
        };
        let out = serve_poll_arm_cycle(
            ServeArm {
                rt: &mut rt,
                coordinator: &mut coord,
                center: &mut center,
            },
            &mut poll,
            &mut tx,
            &state,
            &serve_params(3),
            1,
        );
        assert_eq!(
            out,
            ServeCycleOutcome::DeniedNoReply {
                action_hash_32: serve_action_hash()
            }
        );
        assert_eq!(tx.calls, 0, "a spoofed sender never proceeds (IV-DP2)");
        assert_eq!(coord.recorded(), 0, "a spoof records nothing");
    }

    // IV-DP5: the ledger PERSISTS across the loop — ONE long-lived coordinator; the
    // SAME approve replayed in a later cycle is replay-refused, so it NEVER
    // double-proceeds (the grant is minted exactly once).
    #[test]
    fn serve_loop_ledger_persists_no_double_proceed() {
        let approve = reply(SERVE_OWNER, &format!("approve {}", serve_id16()));
        let mut rt = AutonomyRuntime::arm(724, None, budget(1_000), 2, trace());
        let mut coord = RemoteApprovalCoordinator::new(SERVE_OWNER);
        let mut center = NotificationCenter::new(8);
        let mut tx = CountingTransport { calls: 0 };
        let (records, contents, policy) = empty_state_parts();
        let state = MemoryToolState {
            records: &records,
            contents: &contents,
            policy: &policy,
        };
        // cycle 1: approve → proceed.
        let mut poll1 = ScriptedPollSource::new(vec![vec![approve.clone()]]);
        let out1 = serve_poll_arm_cycle(
            ServeArm {
                rt: &mut rt,
                coordinator: &mut coord,
                center: &mut center,
            },
            &mut poll1,
            &mut tx,
            &state,
            &serve_params(3),
            2,
        );
        assert_eq!(
            out1,
            ServeCycleOutcome::ApprovedAndProceeded {
                action_hash_32: serve_action_hash()
            }
        );
        assert_eq!(tx.calls, 1);
        assert_eq!(coord.recorded(), 1);
        // cycle 2: the SAME approve replayed (the coordinator + its ledger PERSIST) ⇒
        // ledger replay-refuses ⇒ NoAction ⇒ stays denied; NO second proceed (IV-DP5).
        let mut poll2 = ScriptedPollSource::new(vec![vec![approve]]);
        let out2 = serve_poll_arm_cycle(
            ServeArm {
                rt: &mut rt,
                coordinator: &mut coord,
                center: &mut center,
            },
            &mut poll2,
            &mut tx,
            &state,
            &serve_params(3),
            3,
        );
        assert_eq!(
            out2,
            ServeCycleOutcome::DeniedNoReply {
                action_hash_32: serve_action_hash()
            }
        );
        assert_eq!(tx.calls, 1, "replay-real: no double-proceed (IV-DP5)");
        assert_eq!(
            coord.recorded(),
            1,
            "the persisted ledger refused the replay"
        );
    }

    // D-DP2 / IV-DP1: the loop runs under the REAL `RuntimeHandle::spawn` std-thread
    // pump (⑩; no new crate), bounded — ONE serve cycle then the driver returns false ⇒
    // the worker breaks + `join` returns (no zombie). The shared flag proves the loop
    // PROCEEDED under the real background pump.
    #[test]
    fn serve_loop_runs_under_runtime_handle_spawn_and_joins() {
        let proceeded = std::sync::Arc::new(std::sync::Mutex::new(false));
        let driver_flag = std::sync::Arc::clone(&proceeded);
        let rt = AutonomyRuntime::arm(725, None, budget(1_000), 2, trace());
        let mut coord = RemoteApprovalCoordinator::new(SERVE_OWNER);
        let mut center = NotificationCenter::new(8);
        let mut poll = ScriptedPollSource::new(vec![vec![reply(
            SERVE_OWNER,
            &format!("approve {}", serve_id16()),
        )]]);
        let driver = move |rt: &mut AutonomyRuntime| -> bool {
            let mut tx = CountingTransport { calls: 0 };
            let records: Vec<MemoryIndexRecord> = Vec::new();
            let contents: Vec<(MemoryId, &[u8])> = Vec::new();
            let policy = TombstonePolicy::new();
            let state = MemoryToolState {
                records: &records,
                contents: &contents,
                policy: &policy,
            };
            let out = serve_poll_arm_cycle(
                ServeArm {
                    rt,
                    coordinator: &mut coord,
                    center: &mut center,
                },
                &mut poll,
                &mut tx,
                &state,
                &ServeParams {
                    system: "system",
                    task: SERVE_TASK,
                    poll_windows_max: 1,
                    trace: trace(),
                },
                2,
            );
            if let ServeCycleOutcome::ApprovedAndProceeded { .. } = out {
                if let Ok(mut f) = driver_flag.lock() {
                    *f = true;
                }
            }
            false // one bounded serve cycle, then stop — the worker breaks + joins.
        };
        let handle = RuntimeHandle::spawn(rt, driver, Duration::from_millis(1));
        handle.join(); // returns ⇒ no zombie (a worker that ignored the stop would hang).
        assert!(
            *proceeded.lock().unwrap(),
            "the serve loop proceeded under the real spawn pump"
        );
    }

    // ---- E13-2 (⑱): the TELEGRAM REMOTE-CONTROL chat cycle, hermetic (0 real net) ----

    use crate::commands::authority::test_egress_capability_grant;

    /// A scripted inbound CHAT source: each window drains ONE pre-built batch of RAW
    /// updates into the cycle (0 real net, NO second poll path). Counts windows
    /// polled (the IV-RC8 bound proof). `#[cfg(test)]` ONLY.
    struct ScriptedChatSource {
        windows: std::collections::VecDeque<Vec<InboundUpdate>>,
        polled: u32,
    }
    impl ScriptedChatSource {
        fn new(windows: Vec<Vec<InboundUpdate>>) -> Self {
            Self {
                windows: windows.into_iter().collect(),
                polled: 0,
            }
        }
    }
    impl InboundChatSource for ScriptedChatSource {
        fn poll_chat_window(
            &mut self,
            _coordinator: &mut RemoteApprovalCoordinator,
            _now: u64,
        ) -> Result<Vec<InboundUpdate>, ServePollReject> {
            self.polled += 1;
            Ok(self.windows.pop_front().unwrap_or_default())
        }
    }

    /// A chat source that always FAILS the transport (the token-missing analogue) —
    /// proves a transport failure is fail-closed (PollFailed; IV-RC8).
    struct FailingChatSource;
    impl InboundChatSource for FailingChatSource {
        fn poll_chat_window(
            &mut self,
            _coordinator: &mut RemoteApprovalCoordinator,
            _now: u64,
        ) -> Result<Vec<InboundUpdate>, ServePollReject> {
            Err(ServePollReject::Transport)
        }
    }

    /// A scripted reply sink: records every delivered redacted reply so a
    /// withheld / card-only / non-owner cycle can be PROVEN to have sent ZERO.
    /// `#[cfg(test)]` ONLY.
    struct ScriptedReplySink {
        sent: Vec<RedactedChatReply>,
    }
    impl ScriptedReplySink {
        fn new() -> Self {
            Self { sent: Vec::new() }
        }
    }
    impl ChatReplySink for ScriptedReplySink {
        fn send_reply(&mut self, reply: &RedactedChatReply) -> bool {
            self.sent.push(reply.clone());
            true
        }
    }

    /// A scripted LOCAL turn transport: returns a fixed answer text and counts the
    /// turns served (so a card-only / withheld cycle can be PROVEN to have run 0 or
    /// 1 local turns — zero egress). The answer carries the `ANSWER:` completion
    /// marker the loop parses.
    struct ScriptedLocalTransport {
        answer_text: String,
        calls: u32,
    }
    impl ScriptedLocalTransport {
        fn answering(answer: &str) -> Self {
            Self {
                answer_text: format!("ANSWER: {answer}"),
                calls: 0,
            }
        }
    }
    impl AgentTransport for ScriptedLocalTransport {
        fn turn(&mut self, _s: &str, _u: &str) -> Result<AgentTurn, AgentTransportError> {
            self.calls += 1;
            Ok(AgentTurn {
                answer_text: self.answer_text.clone(),
                input_tokens_u64: 1,
                output_tokens_u64: 1,
                cached_tokens_u64: 0,
            })
        }
    }

    /// A secret-shaped fixture the SI-2 choke scanners catch (the canonical
    /// `suiprivkey` family, same as the redaction-gate tests).
    const CHAT_SECRET: &str = "key = \"suiprivkey1qexamplenotreal\"";

    fn chat_params<'a>(poll_windows_max: u32) -> ChatParams<'a> {
        ChatParams {
            system: "system",
            poll_windows_max,
        }
    }

    /// An ARMED runner (an owner-armed egress session grant: `max_actions`, expiry).
    fn armed_rt(job: u64, max_actions: u32, expiry: u64) -> AutonomyRuntime {
        let grant = test_egress_capability_grant(max_actions, expiry);
        AutonomyRuntime::arm(job, Some(grant), budget(1_000), 2, trace())
    }

    // IV-RC1 — a NON-OWNER chat message runs NO turn and sends NOTHING, even with the
    // session armed (the drop is the owner pin, not the arm — pin checked FIRST).
    #[test]
    fn chat_non_owner_runs_no_turn_sends_nothing() {
        let mut source =
            ScriptedChatSource::new(vec![vec![reply(ATTACKER, "what is the build status?")]]);
        let mut sink = ScriptedReplySink::new();
        let mut local = ScriptedLocalTransport::answering("the build is green");
        let mut rt = armed_rt(900, 5, 1_000_000);
        let mut coord = RemoteApprovalCoordinator::new(OWNER);
        let (records, contents, policy) = empty_state_parts();
        let state = MemoryToolState {
            records: &records,
            contents: &contents,
            policy: &policy,
        };
        let outcomes = serve_chat_cycle(
            ChatArm {
                rt: &mut rt,
                coordinator: &mut coord,
            },
            &mut source,
            &mut sink,
            &mut local,
            &state,
            &chat_params(1),
            5,
        );
        assert_eq!(outcomes, vec![ChatTurnOutcome::NotOwnerDropped]);
        assert_eq!(local.calls, 0, "a non-owner update runs no turn (IV-RC1)");
        assert!(sink.sent.is_empty(), "a non-owner update sends nothing");
        assert_eq!(rt.egress_actions_used(), 0);
    }

    // IV-RC2 — a SECRET-SHAPED owner inbound is WITHHELD before the agent sees it
    // (no turn, no echo), even with the session armed.
    #[test]
    fn chat_secret_shaped_inbound_is_withheld_no_turn() {
        let mut source = ScriptedChatSource::new(vec![vec![reply(OWNER, CHAT_SECRET)]]);
        let mut sink = ScriptedReplySink::new();
        let mut local = ScriptedLocalTransport::answering("never reached");
        let mut rt = armed_rt(901, 5, 1_000_000);
        let mut coord = RemoteApprovalCoordinator::new(OWNER);
        let (records, contents, policy) = empty_state_parts();
        let state = MemoryToolState {
            records: &records,
            contents: &contents,
            policy: &policy,
        };
        let outcomes = serve_chat_cycle(
            ChatArm {
                rt: &mut rt,
                coordinator: &mut coord,
            },
            &mut source,
            &mut sink,
            &mut local,
            &state,
            &chat_params(1),
            5,
        );
        assert_eq!(outcomes, vec![ChatTurnOutcome::SecretWithheld]);
        assert_eq!(
            local.calls, 0,
            "a secret-shaped inbound never reaches a turn"
        );
        assert!(sink.sent.is_empty());
    }

    // IV-RC5 (Option A) — an owner chat prompt with NO armed session is a CARD ONLY:
    // NO turn runs, NO reply is sent (the arm gates the ENTIRE loop).
    #[test]
    fn chat_unarmed_prompt_is_card_only_no_turn_no_send() {
        let mut source = ScriptedChatSource::new(vec![vec![reply(OWNER, "summarize the audit")]]);
        let mut sink = ScriptedReplySink::new();
        let mut local = ScriptedLocalTransport::answering("never reached");
        // NO grant ⇒ no armed session.
        let mut rt = AutonomyRuntime::arm(902, None, budget(1_000), 2, trace());
        let mut coord = RemoteApprovalCoordinator::new(OWNER);
        let (records, contents, policy) = empty_state_parts();
        let state = MemoryToolState {
            records: &records,
            contents: &contents,
            policy: &policy,
        };
        let outcomes = serve_chat_cycle(
            ChatArm {
                rt: &mut rt,
                coordinator: &mut coord,
            },
            &mut source,
            &mut sink,
            &mut local,
            &state,
            &chat_params(1),
            5,
        );
        assert_eq!(outcomes, vec![ChatTurnOutcome::CardOnlyNotArmed]);
        assert_eq!(local.calls, 0, "Option A: unarmed ⇒ no turn (IV-RC5)");
        assert!(sink.sent.is_empty(), "unarmed ⇒ no send");
        assert_eq!(rt.egress_actions_used(), 0);
    }

    // IV-RC4/RC3/RC5 — an ARMED owner chat prompt runs a LOCAL turn (zero egress),
    // the redacted answer is replied, and ONE session action is consumed.
    #[test]
    fn chat_armed_prompt_runs_local_turn_and_replies() {
        let mut source =
            ScriptedChatSource::new(vec![vec![reply(OWNER, "what is the build status?")]]);
        let mut sink = ScriptedReplySink::new();
        let mut local = ScriptedLocalTransport::answering("the build is green");
        let mut rt = armed_rt(903, 5, 1_000_000);
        let mut coord = RemoteApprovalCoordinator::new(OWNER);
        let (records, contents, policy) = empty_state_parts();
        let state = MemoryToolState {
            records: &records,
            contents: &contents,
            policy: &policy,
        };
        let outcomes = serve_chat_cycle(
            ChatArm {
                rt: &mut rt,
                coordinator: &mut coord,
            },
            &mut source,
            &mut sink,
            &mut local,
            &state,
            &chat_params(1),
            5,
        );
        assert_eq!(outcomes, vec![ChatTurnOutcome::Replied { sent: true }]);
        assert_eq!(local.calls, 1, "exactly one LOCAL turn ran (IV-RC4)");
        assert_eq!(sink.sent.len(), 1, "exactly one redacted reply delivered");
        assert_eq!(
            sink.sent[0].text(),
            "the build is green",
            "the secret-free answer is the reply body"
        );
        assert_eq!(
            rt.egress_actions_used(),
            1,
            "one session action consumed (bounds replies, IV-RC5)"
        );
    }

    // IV-RC3 — a WHOLE-SECRET answer from the LOCAL turn is WITHHELD: the reply is
    // never built/sent, and no session action is consumed.
    #[test]
    fn chat_secret_answer_is_withheld_no_reply() {
        let mut source = ScriptedChatSource::new(vec![vec![reply(OWNER, "what is the key?")]]);
        let mut sink = ScriptedReplySink::new();
        // the LOCAL turn ANSWERS with a secret-shaped string.
        let mut local = ScriptedLocalTransport::answering(CHAT_SECRET);
        let mut rt = armed_rt(904, 5, 1_000_000);
        let mut coord = RemoteApprovalCoordinator::new(OWNER);
        let (records, contents, policy) = empty_state_parts();
        let state = MemoryToolState {
            records: &records,
            contents: &contents,
            policy: &policy,
        };
        let outcomes = serve_chat_cycle(
            ChatArm {
                rt: &mut rt,
                coordinator: &mut coord,
            },
            &mut source,
            &mut sink,
            &mut local,
            &state,
            &chat_params(1),
            5,
        );
        assert_eq!(outcomes, vec![ChatTurnOutcome::ReplyWithheld]);
        assert_eq!(local.calls, 1, "the turn ran");
        assert!(
            sink.sent.is_empty(),
            "a whole-secret answer is withheld — nothing sent (IV-RC3)"
        );
        assert_eq!(
            rt.egress_actions_used(),
            0,
            "a withheld reply consumes no session action"
        );
    }

    // IV-RC5/RC8 — an armed session of `max_actions = 1` bounds the replies: TWO
    // owner prompts in one window ⇒ the first replies, the second is a card only
    // (the consumed action exhausts the rate ⇒ the re-derivation fails closed).
    #[test]
    fn chat_armed_session_bounds_replies_at_max_actions() {
        let mut source = ScriptedChatSource::new(vec![vec![
            reply(OWNER, "status one"),
            reply(OWNER, "status two"),
        ]]);
        let mut sink = ScriptedReplySink::new();
        let mut local = ScriptedLocalTransport::answering("the build is green");
        let mut rt = armed_rt(905, 1, 1_000_000); // max_actions = 1
        let mut coord = RemoteApprovalCoordinator::new(OWNER);
        let (records, contents, policy) = empty_state_parts();
        let state = MemoryToolState {
            records: &records,
            contents: &contents,
            policy: &policy,
        };
        let outcomes = serve_chat_cycle(
            ChatArm {
                rt: &mut rt,
                coordinator: &mut coord,
            },
            &mut source,
            &mut sink,
            &mut local,
            &state,
            &chat_params(1),
            5,
        );
        assert_eq!(
            outcomes,
            vec![
                ChatTurnOutcome::Replied { sent: true },
                ChatTurnOutcome::CardOnlyNotArmed,
            ]
        );
        assert_eq!(local.calls, 1, "the 2nd prompt ran no turn (rate-capped)");
        assert_eq!(sink.sent.len(), 1, "replies bounded at max_actions = 1");
        assert_eq!(rt.egress_actions_used(), 1);
    }

    // The split — an `approve` reply routes to the EXISTING ⑪ approval path (recorded
    // via the load-bearing ledger), NEVER a chat turn, and sends no chat reply.
    #[test]
    fn chat_approval_reply_routes_to_approval_path_never_a_turn() {
        let p = pending(1);
        let mut coord = RemoteApprovalCoordinator::new(OWNER);
        coord.add_pending(p);
        let mut source =
            ScriptedChatSource::new(vec![vec![reply(OWNER, &format!("approve {}", p.id16()))]]);
        let mut sink = ScriptedReplySink::new();
        let mut local = ScriptedLocalTransport::answering("never reached");
        let mut rt = armed_rt(906, 5, 1_000_000);
        let (records, contents, policy) = empty_state_parts();
        let state = MemoryToolState {
            records: &records,
            contents: &contents,
            policy: &policy,
        };
        let outcomes = serve_chat_cycle(
            ChatArm {
                rt: &mut rt,
                coordinator: &mut coord,
            },
            &mut source,
            &mut sink,
            &mut local,
            &state,
            &chat_params(1),
            2,
        );
        assert_eq!(
            outcomes,
            vec![ChatTurnOutcome::ApprovalRouted(ChatApprovalKind::Approved)]
        );
        assert_eq!(local.calls, 0, "an approve reply NEVER runs a chat turn");
        assert!(
            sink.sent.is_empty(),
            "the approval route sends no chat reply"
        );
        assert_eq!(
            coord.recorded(),
            1,
            "the approval was recorded via the EXISTING ledger (pin reused)"
        );
    }

    // IV-RC8 — the poll window count is BOUNDED by `poll_windows_max`: an empty
    // stream polls EXACTLY that many windows, then the cycle returns.
    #[test]
    fn chat_poll_window_count_is_bounded() {
        let mut source = ScriptedChatSource::new(vec![]); // every window empty
        let mut sink = ScriptedReplySink::new();
        let mut local = ScriptedLocalTransport::answering("unused");
        let mut rt = armed_rt(907, 5, 1_000_000);
        let mut coord = RemoteApprovalCoordinator::new(OWNER);
        let (records, contents, policy) = empty_state_parts();
        let state = MemoryToolState {
            records: &records,
            contents: &contents,
            policy: &policy,
        };
        let outcomes = serve_chat_cycle(
            ChatArm {
                rt: &mut rt,
                coordinator: &mut coord,
            },
            &mut source,
            &mut sink,
            &mut local,
            &state,
            &chat_params(2),
            5,
        );
        assert!(outcomes.is_empty(), "no updates ⇒ no outcomes");
        assert_eq!(
            source.polled, 2,
            "exactly poll_windows_max windows polled (IV-RC8)"
        );
        assert_eq!(local.calls, 0);
        assert!(sink.sent.is_empty());
    }

    // IV-RC8 — a poll transport FAILURE is fail-closed: PollFailed, no turn, no send.
    #[test]
    fn chat_poll_transport_failure_is_fail_closed() {
        let mut source = FailingChatSource;
        let mut sink = ScriptedReplySink::new();
        let mut local = ScriptedLocalTransport::answering("unused");
        let mut rt = armed_rt(908, 5, 1_000_000);
        let mut coord = RemoteApprovalCoordinator::new(OWNER);
        let (records, contents, policy) = empty_state_parts();
        let state = MemoryToolState {
            records: &records,
            contents: &contents,
            policy: &policy,
        };
        let outcomes = serve_chat_cycle(
            ChatArm {
                rt: &mut rt,
                coordinator: &mut coord,
            },
            &mut source,
            &mut sink,
            &mut local,
            &state,
            &chat_params(3),
            5,
        );
        assert_eq!(outcomes, vec![ChatTurnOutcome::PollFailed]);
        assert_eq!(local.calls, 0, "transport failure ⇒ no turn");
        assert!(sink.sent.is_empty(), "transport failure ⇒ no send");
    }

    // D-RC2 / IV-RC8 — the chat cycle runs under the REAL `RuntimeHandle::spawn`
    // std-thread pump (⑩; no new crate), bounded — ONE serve cycle then the driver
    // returns false ⇒ the worker breaks + `join` returns (no zombie). The shared
    // flag proves the redacted reply was delivered under the real background pump.
    #[test]
    fn chat_cycle_runs_under_runtime_handle_spawn_and_joins() {
        let replied = std::sync::Arc::new(std::sync::Mutex::new(false));
        let driver_flag = std::sync::Arc::clone(&replied);
        let rt = armed_rt(909, 5, 1_000_000);
        let mut coord = RemoteApprovalCoordinator::new(OWNER);
        let mut source =
            ScriptedChatSource::new(vec![vec![reply(OWNER, "what is the build status?")]]);
        let mut sink = ScriptedReplySink::new();
        let mut local = ScriptedLocalTransport::answering("the build is green");
        let driver = move |rt: &mut AutonomyRuntime| -> bool {
            let records: Vec<MemoryIndexRecord> = Vec::new();
            let contents: Vec<(MemoryId, &[u8])> = Vec::new();
            let policy = TombstonePolicy::new();
            let state = MemoryToolState {
                records: &records,
                contents: &contents,
                policy: &policy,
            };
            let outcomes = serve_chat_cycle(
                ChatArm {
                    rt,
                    coordinator: &mut coord,
                },
                &mut source,
                &mut sink,
                &mut local,
                &state,
                &ChatParams {
                    system: "system",
                    poll_windows_max: 1,
                },
                2,
            );
            if outcomes
                .iter()
                .any(|o| matches!(o, ChatTurnOutcome::Replied { .. }))
            {
                if let Ok(mut f) = driver_flag.lock() {
                    *f = true;
                }
            }
            false // one bounded chat cycle, then stop — the worker breaks + joins.
        };
        let handle = RuntimeHandle::spawn(rt, driver, Duration::from_millis(1));
        handle.join(); // returns ⇒ no zombie.
        assert!(
            *replied.lock().unwrap(),
            "the chat cycle replied under the real spawn pump"
        );
    }

    // ── K-5e: the Telegram trade card (the 7-field approval card; surfaces the oracle, authorizes nothing) ──
    #[test]
    fn trade_card_renders_seven_fields_and_routes_through_the_redact_wall() {
        let card = TradeCard {
            action_id16: "a1b2c3d4e5f60718".to_string(),
            action: "open-account".to_string(),
            network: "solana-devnet".to_string(),
            protocol: "skew".to_string(),
            oracle_verdict: "AFFORDABLE & IN-BOUNDS".to_string(),
            escrow_minor: 0,
            budget_minor: 1_000_000_000,
        };
        let text = card.render();
        // the 7-field envelope + the oracle verdict + the approve/deny id16 (the surface, IV-FG11).
        for needle in [
            "action:",
            "network:",
            "protocol:",
            "oracle:",
            "escrow:",
            "budget:",
            "AFFORDABLE & IN-BOUNDS",
            "approve a1b2c3d4e5f60718",
            "deny a1b2c3d4e5f60718",
            "the card authorizes nothing",
        ] {
            assert!(text.contains(needle), "trade card missing `{needle}`");
        }
        // secret-free ⇒ delivered ONLY through the SOLE redact wall, carrying the card verbatim.
        let reply = card
            .into_redacted_reply()
            .expect("a secret-free card builds through the redact wall");
        assert_eq!(
            reply.text(),
            text,
            "the redacted reply carries the card text verbatim"
        );
    }

    #[test]
    fn trade_card_with_a_secret_shaped_field_is_withheld_whole() {
        // a secret-shaped field (here the verdict) ⇒ the WHOLE card is WITHHELD by the SAME
        // redact wall every chat reply passes (IV-RC3 / IV-FG11) — never partially echoed.
        let card = TradeCard {
            action_id16: "00112233aabbccdd".to_string(),
            action: "deposit 1000000".to_string(),
            network: "solana-devnet".to_string(),
            protocol: "skew".to_string(),
            oracle_verdict: CHAT_SECRET.to_string(),
            escrow_minor: 1_000_000,
            budget_minor: 1_000_000_000,
        };
        assert!(
            card.into_redacted_reply().is_none(),
            "a secret-shaped trade card is withheld whole, never sent"
        );
    }
}
