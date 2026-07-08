//! `sinabro platform telegram` — Telegram platform controls + notification /
//! approval-queue rules.
//!
//! The CLI and the Telegram bridge share a platform-neutral [`MessageEnvelope`]:
//! a command carries the *same* [`CommandEnvelope`] regardless of which
//! transport it entered through, so `/kill` from the CLI and `/kill` from
//! Telegram are byte-identical commands and the pause/sync state can never
//! diverge by origin. Platform pause rides the *same*
//! express control rail as `/kill` and `/budget cap` ([`ExpressControl`]), so a
//! pause acknowledgement stays on the hot path even when the outbound
//! notification queue is full. Approval requests, job-done,
//! job-failed, gas-warning and stale-job notifications are user-configurable and
//! deduped, every delivery attempt is recorded (a failed delivery is surfaced,
//! never silently lost), and every delivered approval is tracked so
//! none is orphaned.
//!
//! Reuse: the bind / authorize / test primitive is the canonical
//! [`mnemos_j_ux::telegram`] gateway ([`TelegramGateway`] / [`TelegramUserId`] /
//! [`Allowlist`] / [`GatewayError`]) — an authorization-only spine that performs
//! zero live transport; the classified command is the crate's
//! [`crate::command::CommandEnvelope`]; the red/yellow/green verdict is the
//! cockpit [`crate::tui::RenderTruth`]; the trace link is
//! [`crate::StageFTraceLink`].
//!
//! `MessageEnvelope` is defined here, next to the [`CommandEnvelope`] it wraps.
//! This module performs no live action.

use crate::StageFTraceLink;
use crate::command::CommandEnvelope;
use crate::hex32;
use crate::tui::RenderTruth;
use mnemos_j_ux::telegram::{Allowlist, GatewayError, TelegramGateway, TelegramUserId};
use std::collections::BTreeSet;

/// First 16 hex characters of a 32-byte key — a redacted, display-only prefix.
#[must_use]
fn redact16(bytes: &[u8; 32]) -> String {
    hex32(bytes).chars().take(16).collect()
}

/// Where a command physically entered Sinabro. The origin is *transport*
/// metadata only: it never changes how a command is classified, so the same verb
/// yields the same [`CommandEnvelope`] regardless of origin (the
/// envelope-equality invariant).
#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum PlatformOrigin {
    /// The local CLI / REPL.
    Cli = 1,
    /// The local TUI cockpit.
    Tui = 2,
    /// The Telegram bridge.
    Telegram = 3,
}

impl PlatformOrigin {
    /// The stable `u8` discriminant.
    #[must_use]
    pub const fn as_u8(self) -> u8 {
        self as u8
    }
}

/// The platform-neutral envelope shared by the CLI, the TUI and the Telegram
/// bridge. It pairs a transport [`PlatformOrigin`] with
/// the *same* classified [`CommandEnvelope`], so a command's semantics cannot
/// diverge by transport.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MessageEnvelope {
    /// The transport the command entered through.
    pub origin: PlatformOrigin,
    /// The origin-independent classified command.
    pub command: CommandEnvelope,
}

impl MessageEnvelope {
    /// Wrap a classified command with its transport origin.
    #[must_use]
    pub const fn new(origin: PlatformOrigin, command: CommandEnvelope) -> Self {
        Self { origin, command }
    }

    /// The classified command (origin-independent).
    #[must_use]
    pub const fn command(&self) -> CommandEnvelope {
        self.command
    }

    /// Envelope equality: two envelopes carry the *same command* iff their
    /// [`CommandEnvelope`]s are equal, regardless of origin. This is the
    /// CLI ⇔ Telegram parity invariant.
    #[must_use]
    pub fn same_command(&self, other: &Self) -> bool {
        self.command == other.command
    }
}

/// The shared platform-channel lifecycle. There is exactly one channel state per
/// platform; the CLI and Telegram both *observe the same value* (it cannot
/// diverge by origin).
#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PlatformChannelState {
    /// Bound and forwarding.
    Active = 1,
    /// Paused via the express control rail; no outbound delivery.
    Paused = 2,
    /// Not yet bound.
    Unbound = 3,
}

impl PlatformChannelState {
    /// The stable `u8` discriminant.
    #[must_use]
    pub const fn as_u8(self) -> u8 {
        self as u8
    }
}

/// The express control rail: a small, pre-allocated set of controls that preempt
/// the normal and background queues. Platform pause rides
/// the *same* rail as `/kill` and `/budget cap`, so a pause acknowledgement stays
/// on the hot path even under a full notification queue.
#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ExpressControl {
    /// `/kill` — hard stop the active turn.
    Kill = 1,
    /// `/budget cap` — pre-dispatch budget gate.
    BudgetCap = 2,
    /// Platform pause — stop outbound platform delivery.
    PlatformPause = 3,
    /// `/lockdown` — freeze all side effects.
    Lockdown = 4,
}

impl ExpressControl {
    /// The stable `u8` discriminant.
    #[must_use]
    pub const fn as_u8(self) -> u8 {
        self as u8
    }

    /// Every express control bypasses the normal / background queues. This is a
    /// total property of the rail — there is no non-express member.
    #[must_use]
    pub const fn bypasses_queue(self) -> bool {
        true
    }
}

/// The shared platform sync state: the single source of truth for the channel
/// lifecycle plus a monotonic version that increments on every express
/// transition, so two observers can confirm they are looking at the same state.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PlatformSyncState {
    /// The shared channel lifecycle.
    pub state: PlatformChannelState,
    /// Monotonic version, bumped on every express transition.
    pub version_u32: u32,
}

impl PlatformSyncState {
    /// A freshly bound channel in [`PlatformChannelState::Active`].
    #[must_use]
    pub const fn active() -> Self {
        Self {
            state: PlatformChannelState::Active,
            version_u32: 0,
        }
    }

    /// An unbound channel.
    #[must_use]
    pub const fn unbound() -> Self {
        Self {
            state: PlatformChannelState::Unbound,
            version_u32: 0,
        }
    }

    /// Apply an express control transition, bumping the version. Pause-class
    /// controls ([`ExpressControl::PlatformPause`] / [`ExpressControl::Lockdown`])
    /// move the channel to [`PlatformChannelState::Paused`]; the others
    /// acknowledge on the rail without changing the channel state. Either way the
    /// version increments, proving the control was processed on the hot path.
    pub fn apply_express(&mut self, control: ExpressControl) {
        self.state = match control {
            ExpressControl::PlatformPause | ExpressControl::Lockdown => {
                PlatformChannelState::Paused
            }
            ExpressControl::Kill | ExpressControl::BudgetCap => self.state,
        };
        self.version_u32 = self.version_u32.saturating_add(1);
    }

    /// Resume a paused channel back to active (express rail).
    pub fn resume(&mut self) {
        if matches!(self.state, PlatformChannelState::Paused) {
            self.state = PlatformChannelState::Active;
            self.version_u32 = self.version_u32.saturating_add(1);
        }
    }
}

/// The result of a `platform telegram test` dry run.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TestMessageReport {
    /// The origin a real message would carry.
    pub origin: PlatformOrigin,
    /// Whether the target user is allowlisted.
    pub authorized: bool,
    /// Whether a real binding *would* send (authorized) — a dry-run intent only.
    pub would_send: bool,
    /// Whether live transport ran. Always `false`.
    pub transport_live: bool,
}

/// A bind view over the canonical [`TelegramGateway`] (authorization-only; the
/// gateway holds no bot token and performs no transport). The
/// transport is never live: [`Self::transport_live`] is structurally `false`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TelegramBindingView {
    gateway: TelegramGateway,
    bound: bool,
}

impl TelegramBindingView {
    /// Bind a gateway from a compile-time allowlist. Binding records the
    /// authorization spine only; no live transport is opened.
    #[must_use]
    pub const fn bind(allow: Allowlist) -> Self {
        Self {
            gateway: TelegramGateway::new(allow),
            bound: true,
        }
    }

    /// Whether a binding exists.
    #[must_use]
    pub const fn bound(&self) -> bool {
        self.bound
    }

    /// Whether live Telegram transport is open. Always `false` — the
    /// Bot API transport is a later wiring step.
    #[must_use]
    pub const fn transport_live(&self) -> bool {
        false
    }

    /// The number of allowlisted operators (the only observable allowlist size).
    #[must_use]
    pub const fn operator_count(&self) -> usize {
        self.gateway.allowlist().len()
    }

    /// Authorize a user against the canonical allowlist (reuses
    /// [`TelegramGateway::authorize`]; the reject is payload-less).
    pub fn authorize(&self, user: TelegramUserId) -> Result<(), GatewayError> {
        self.gateway.authorize(user)
    }

    /// Build a `platform telegram test` report. The test message is a *dry run*:
    /// an authorized user yields `would_send = true` but
    /// `transport_live` stays `false` (nothing is actually sent).
    #[must_use]
    pub fn test_message(&self, user: TelegramUserId) -> TestMessageReport {
        let authorized = self.authorize(user).is_ok();
        TestMessageReport {
            origin: PlatformOrigin::Telegram,
            authorized,
            would_send: authorized,
            transport_live: false,
        }
    }
}

/// The user-configurable notification classes.
#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum NotificationKind {
    /// An approval request is waiting.
    ApprovalRequest = 1,
    /// A job finished successfully.
    JobDone = 2,
    /// A job failed.
    JobFailed = 3,
    /// A gas-budget warning.
    GasWarning = 4,
    /// A background job has gone stale.
    StaleJob = 5,
}

impl NotificationKind {
    /// All five notification classes, in discriminant order.
    pub const ALL: [NotificationKind; 5] = [
        NotificationKind::ApprovalRequest,
        NotificationKind::JobDone,
        NotificationKind::JobFailed,
        NotificationKind::GasWarning,
        NotificationKind::StaleJob,
    ];

    /// The stable `u8` discriminant.
    #[must_use]
    pub const fn as_u8(self) -> u8 {
        self as u8
    }

    /// Zero-based index into the per-kind rule table.
    const fn index(self) -> usize {
        (self as usize) - 1
    }
}

/// A per-kind notification rule. Both knobs are user-configurable; the default is
/// enabled + unmuted (no silent failure, but the user may mute or disable).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NotificationRule {
    /// The class this rule governs.
    pub kind: NotificationKind,
    /// Whether this class is enabled at all.
    pub enabled: bool,
    /// Whether this class is currently muted.
    pub muted: bool,
}

impl NotificationRule {
    /// The default rule for a class: enabled and unmuted.
    #[must_use]
    pub const fn default_for(kind: NotificationKind) -> Self {
        Self {
            kind,
            enabled: true,
            muted: false,
        }
    }
}

/// A single outbound notification: its class plus a 32-byte dedupe key (a hash of
/// the notification's salient fields). Two notifications with the same key are
/// duplicates.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Notification {
    /// The notification class.
    pub kind: NotificationKind,
    /// The dedupe key (hash of the salient fields).
    pub dedupe_key_32: [u8; 32],
}

impl Notification {
    /// Build a notification.
    #[must_use]
    pub const fn new(kind: NotificationKind, dedupe_key_32: [u8; 32]) -> Self {
        Self {
            kind,
            dedupe_key_32,
        }
    }
}

/// The decision for a single notification delivery attempt.
#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DeliveryDecision {
    /// Delivered (rule enabled, unmuted, not a duplicate).
    Deliver = 1,
    /// Suppressed: the class is disabled.
    SuppressedDisabled = 2,
    /// Suppressed: the class is muted.
    SuppressedMuted = 3,
    /// Suppressed: a duplicate of an already-delivered key.
    SuppressedDuplicate = 4,
}

impl DeliveryDecision {
    /// The stable `u8` discriminant.
    #[must_use]
    pub const fn as_u8(self) -> u8 {
        self as u8
    }
}

/// A delivery receipt — recorded for *every* decided attempt (including a failed
/// transport), so a delivery failure is surfaced and never silently lost.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DeliveryReceipt {
    /// The notification class.
    pub kind: NotificationKind,
    /// The delivery decision.
    pub decision: DeliveryDecision,
    /// Whether the message actually left (decision == `Deliver` AND transport ok).
    pub delivered: bool,
    /// The dedupe key the receipt is for (rendered redacted).
    pub dedupe_key_32: [u8; 32],
    /// The trace link the receipt is bound to.
    pub trace: StageFTraceLink,
}

impl DeliveryReceipt {
    /// Redacted, colorless receipt lines bounded by `rows`. The dedupe key is
    /// shown as a 16-hex prefix only — never the full key.
    #[must_use]
    pub fn render(&self, rows: u16) -> Vec<String> {
        let lines = vec![
            format!("kind_u8={}", self.kind.as_u8()),
            format!("decision_u8={}", self.decision.as_u8()),
            format!("delivered={}", self.delivered),
            format!("dedupe_key={}", redact16(&self.dedupe_key_32)),
            format!("atom={}", self.trace.stage_f_atom_u16),
        ];
        lines.into_iter().take(rows as usize).collect()
    }
}

/// Why a platform-telegram command was refused (fail-closed).
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum PlatformTelegramReject {
    /// The outbound notification queue is full; the channel was express-paused.
    #[error("notification queue full; platform express-paused")]
    QueueFull,
    /// The channel is paused; outbound delivery is refused until resume.
    #[error("platform channel paused")]
    ChannelPaused,
    /// The channel is not bound.
    #[error("platform channel unbound")]
    ChannelUnbound,
}

/// The Telegram platform controller: notification rules + dedupe + a bounded
/// outbound queue + the approval queue + the shared sync state. Every surface is
/// a pure in-memory projection (no network, no scan), so a local status render
/// stays within the p95 ≤ 50ms budget.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NotificationCenter {
    rules: [NotificationRule; 5],
    seen: BTreeSet<[u8; 32]>,
    approvals: BTreeSet<[u8; 32]>,
    pending: usize,
    capacity: usize,
    sync: PlatformSyncState,
}

impl NotificationCenter {
    /// A new controller with default rules (all enabled, unmuted), an active
    /// bound channel, and a bounded outbound `capacity`.
    #[must_use]
    pub fn new(capacity: usize) -> Self {
        Self {
            rules: [
                NotificationRule::default_for(NotificationKind::ApprovalRequest),
                NotificationRule::default_for(NotificationKind::JobDone),
                NotificationRule::default_for(NotificationKind::JobFailed),
                NotificationRule::default_for(NotificationKind::GasWarning),
                NotificationRule::default_for(NotificationKind::StaleJob),
            ],
            seen: BTreeSet::new(),
            approvals: BTreeSet::new(),
            pending: 0,
            capacity,
            sync: PlatformSyncState::active(),
        }
    }

    /// The shared sync state (observed identically by every origin).
    #[must_use]
    pub const fn sync_state(&self) -> PlatformSyncState {
        self.sync
    }

    /// The current rule for a class.
    #[must_use]
    pub fn rule(&self, kind: NotificationKind) -> NotificationRule {
        self.rules[kind.index()]
    }

    /// Mute (or unmute) a class — user-configurable.
    pub fn set_muted(&mut self, kind: NotificationKind, muted: bool) {
        self.rules[kind.index()].muted = muted;
    }

    /// Enable (or disable) a class — user-configurable.
    pub fn set_enabled(&mut self, kind: NotificationKind, enabled: bool) {
        self.rules[kind.index()].enabled = enabled;
    }

    /// The pure delivery decision for `n` given the current rules and dedupe set
    /// (does not mutate).
    #[must_use]
    pub fn decide(&self, n: &Notification) -> DeliveryDecision {
        let rule = self.rules[n.kind.index()];
        if !rule.enabled {
            DeliveryDecision::SuppressedDisabled
        } else if rule.muted {
            DeliveryDecision::SuppressedMuted
        } else if self.seen.contains(&n.dedupe_key_32) {
            DeliveryDecision::SuppressedDuplicate
        } else {
            DeliveryDecision::Deliver
        }
    }

    /// Express-pause the channel via the same rail as `/kill` and `/budget cap`.
    /// Acknowledged on the hot path, bypassing the outbound queue.
    pub fn express_pause(&mut self) {
        self.sync.apply_express(ExpressControl::PlatformPause);
    }

    /// Resume a paused channel (express rail).
    pub fn resume(&mut self) {
        self.sync.resume();
    }

    /// Attempt to deliver `n`. `transport_ok` models the (simulated)
    /// transport outcome. A paused / unbound channel refuses up front (the
    /// control state is re-checked before any side effect). A suppressed
    /// notification returns a surfaced receipt. A full queue express-pauses the
    /// channel and refuses with [`PlatformTelegramReject::QueueFull`] — the
    /// notification is surfaced, never silently dropped.
    pub fn deliver(
        &mut self,
        n: Notification,
        transport_ok: bool,
        trace: StageFTraceLink,
    ) -> Result<DeliveryReceipt, PlatformTelegramReject> {
        match self.sync.state {
            PlatformChannelState::Paused => return Err(PlatformTelegramReject::ChannelPaused),
            PlatformChannelState::Unbound => return Err(PlatformTelegramReject::ChannelUnbound),
            PlatformChannelState::Active => {}
        }
        let decision = self.decide(&n);
        if !matches!(decision, DeliveryDecision::Deliver) {
            return Ok(DeliveryReceipt {
                kind: n.kind,
                decision,
                delivered: false,
                dedupe_key_32: n.dedupe_key_32,
                trace,
            });
        }
        if self.pending >= self.capacity {
            // Backpressure: ride the express rail to pause, then surface QueueFull.
            self.express_pause();
            return Err(PlatformTelegramReject::QueueFull);
        }
        let delivered = transport_ok;
        if delivered {
            self.seen.insert(n.dedupe_key_32);
            self.pending = self.pending.saturating_add(1);
            if matches!(n.kind, NotificationKind::ApprovalRequest) {
                self.approvals.insert(n.dedupe_key_32);
            }
        }
        Ok(DeliveryReceipt {
            kind: n.kind,
            decision: DeliveryDecision::Deliver,
            delivered,
            dedupe_key_32: n.dedupe_key_32,
            trace,
        })
    }

    /// The number of outstanding (delivered-but-unresolved) approval requests. No
    /// approval is orphaned: every delivered [`NotificationKind::ApprovalRequest`]
    /// is tracked here until [`Self::resolve_approval`].
    #[must_use]
    pub fn pending_approvals(&self) -> usize {
        self.approvals.len()
    }

    /// Resolve (acknowledge) a tracked approval request.
    pub fn resolve_approval(&mut self, dedupe_key_32: [u8; 32]) {
        self.approvals.remove(&dedupe_key_32);
    }

    /// Drain one delivered item from the outbound queue (transport confirmed).
    pub fn mark_drained(&mut self) {
        self.pending = self.pending.saturating_sub(1);
    }

    /// The render truth: a bound, active channel is `Green`; a paused channel is
    /// `Yellow` (degraded, not healthy); an unbound channel is `Red`. No
    /// false-green.
    #[must_use]
    pub fn render_truth(&self) -> RenderTruth {
        match self.sync.state {
            PlatformChannelState::Active => RenderTruth::Green,
            PlatformChannelState::Paused => RenderTruth::Yellow,
            PlatformChannelState::Unbound => RenderTruth::Red,
        }
    }

    /// Redacted, colorless local-status lines bounded by `rows` (hot path).
    #[must_use]
    pub fn render(&self, rows: u16) -> Vec<String> {
        let lines = vec![
            format!("channel_state_u8={}", self.sync.state.as_u8()),
            format!("sync_version={}", self.sync.version_u32),
            format!("pending={}", self.pending),
            format!("capacity={}", self.capacity),
            format!("pending_approvals={}", self.approvals.len()),
            format!(
                "approval_enabled={}",
                self.rule(NotificationKind::ApprovalRequest).enabled
            ),
            format!("truth_u8={}", self.render_truth() as u8),
        ];
        lines.into_iter().take(rows as usize).collect()
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    #![allow(clippy::expect_used)]
    #![allow(clippy::panic)]

    use super::*;
    use crate::command::{CliMode, CommandRisk};
    use crate::grammar::CliNamespace;
    use crate::repl::latency::p95_ms;

    const OPERATORS: &[TelegramUserId] = &[TelegramUserId(1001), TelegramUserId(2002)];

    fn trace() -> StageFTraceLink {
        StageFTraceLink::new([0x5a; 32], 459, 0)
    }

    fn env(verb: &str) -> CommandEnvelope {
        CommandEnvelope::classify(
            CliNamespace::Agent,
            verb,
            CliMode::Run,
            CommandRisk::ReadOnly,
            verb.as_bytes(),
        )
    }

    fn key(seed: u8) -> [u8; 32] {
        [seed; 32]
    }

    #[test]
    fn bind_fixture_authorizes_allowlisted_only() {
        let b = TelegramBindingView::bind(Allowlist::from_static(OPERATORS));
        assert!(b.bound());
        assert!(!b.transport_live());
        assert_eq!(b.operator_count(), 2);
        assert!(b.authorize(TelegramUserId(1001)).is_ok());
        assert_eq!(
            b.authorize(TelegramUserId(9)),
            Err(GatewayError::NotAllowlisted)
        );
    }

    #[test]
    fn test_message_is_dry_run_never_live() {
        let b = TelegramBindingView::bind(Allowlist::from_static(OPERATORS));
        let ok = b.test_message(TelegramUserId(2002));
        assert!(ok.authorized);
        assert!(ok.would_send);
        assert!(!ok.transport_live); // dry run only
        assert_eq!(ok.origin, PlatformOrigin::Telegram);
        let no = b.test_message(TelegramUserId(7));
        assert!(!no.authorized);
        assert!(!no.would_send);
        assert!(!no.transport_live);
    }

    #[test]
    fn pause_via_express_rail_sets_paused() {
        let mut s = PlatformSyncState::active();
        assert_eq!(s.state, PlatformChannelState::Active);
        assert!(ExpressControl::PlatformPause.bypasses_queue());
        s.apply_express(ExpressControl::PlatformPause);
        assert_eq!(s.state, PlatformChannelState::Paused);
        assert_eq!(s.version_u32, 1);
        s.resume();
        assert_eq!(s.state, PlatformChannelState::Active);
        assert_eq!(s.version_u32, 2);
    }

    #[test]
    fn sync_state_cannot_diverge_across_origins() {
        // One shared state; two origins observe the SAME value.
        let mut center = NotificationCenter::new(8);
        center.express_pause();
        let from_cli = center.sync_state();
        let from_telegram = center.sync_state();
        assert_eq!(from_cli, from_telegram);
        assert_eq!(from_cli.state, PlatformChannelState::Paused);
    }

    #[test]
    fn envelope_equality_cli_and_telegram_same_command() {
        let e = env("kill");
        let cli = MessageEnvelope::new(PlatformOrigin::Cli, e);
        let tg = MessageEnvelope::new(PlatformOrigin::Telegram, e);
        assert_ne!(cli.origin, tg.origin);
        assert_eq!(cli.command(), tg.command()); // identical semantics across transports
        assert!(cli.same_command(&tg));
        // A different verb is NOT the same command.
        let other = MessageEnvelope::new(PlatformOrigin::Telegram, env("approve"));
        assert!(!cli.same_command(&other));
    }

    /// Single dispatch truth (the behavioral half; the structural "exactly one
    /// executor" half is enforced by a separate structural verifier).
    /// A command's semantics AND its gate are a pure function of its
    /// CLASSIFICATION, never of its transport: the SAME [`CommandEnvelope`]
    /// wrapped for the CLI and for Telegram is `same_command`, carries an
    /// IDENTICAL risk + approval requirement, and a side-effecting verb's gate can
    /// NEVER be downgraded by arriving over a different origin. This FAILS if any
    /// transport could mint a second semantics or a weaker gate.
    #[test]
    fn si4_single_dispatch_truth_no_transport_can_diverge_or_downgrade_the_gate() {
        use crate::command::ApprovalRequirement;
        // (verb, risk, the one gate that risk maps to — the closed risk->approval law)
        let cases = [
            ("status", CommandRisk::ReadOnly, ApprovalRequirement::None),
            (
                "apply",
                CommandRisk::LocalWrite,
                ApprovalRequirement::Confirm,
            ),
            (
                "consult",
                CommandRisk::Network,
                ApprovalRequirement::Confirm,
            ),
            (
                "sign",
                CommandRisk::WalletSign,
                ApprovalRequirement::TypedPhrase,
            ),
            (
                "execute",
                CommandRisk::ChainWrite,
                ApprovalRequirement::Multisig,
            ),
        ];
        for (verb, risk, gate) in cases {
            let classified = CommandEnvelope::classify(
                CliNamespace::Agent,
                verb,
                CliMode::Run,
                risk,
                verb.as_bytes(),
            );
            let via_cli = MessageEnvelope::new(PlatformOrigin::Cli, classified);
            let via_telegram = MessageEnvelope::new(PlatformOrigin::Telegram, classified);
            // Origins differ...
            assert_ne!(via_cli.origin, via_telegram.origin);
            // ...but the command is byte-identical across transports (one semantics).
            assert!(
                via_cli.same_command(&via_telegram),
                "{verb}: command diverged by transport"
            );
            assert_eq!(via_cli.command(), via_telegram.command());
            // The gate is fixed by the classification, not the transport.
            assert_eq!(via_cli.command().risk, risk);
            assert_eq!(via_cli.command().approval, gate);
            assert_eq!(via_telegram.command().approval, gate);
            // A side effect is NEVER ungated on ANY origin (no transport downgrade).
            if !matches!(risk, CommandRisk::ReadOnly) {
                assert_ne!(
                    via_telegram.command().approval,
                    ApprovalRequirement::None,
                    "{verb}: a side effect must stay gated regardless of origin"
                );
            }
        }
    }

    #[test]
    fn approval_request_delivers_into_queue_no_orphan() {
        let mut c = NotificationCenter::new(8);
        let k = key(1);
        let r = c
            .deliver(
                Notification::new(NotificationKind::ApprovalRequest, k),
                true,
                trace(),
            )
            .unwrap();
        assert_eq!(r.decision, DeliveryDecision::Deliver);
        assert!(r.delivered);
        assert_eq!(c.pending_approvals(), 1); // tracked, not orphaned
        c.resolve_approval(k);
        assert_eq!(c.pending_approvals(), 0);
    }

    #[test]
    fn mute_rule_suppresses_kind() {
        let mut c = NotificationCenter::new(8);
        c.set_muted(NotificationKind::JobDone, true);
        let r = c
            .deliver(
                Notification::new(NotificationKind::JobDone, key(2)),
                true,
                trace(),
            )
            .unwrap();
        assert_eq!(r.decision, DeliveryDecision::SuppressedMuted);
        assert!(!r.delivered);
    }

    #[test]
    fn dedupe_suppresses_duplicate_key() {
        let mut c = NotificationCenter::new(8);
        let k = key(3);
        let first = c
            .deliver(
                Notification::new(NotificationKind::GasWarning, k),
                true,
                trace(),
            )
            .unwrap();
        assert_eq!(first.decision, DeliveryDecision::Deliver);
        let second = c
            .deliver(
                Notification::new(NotificationKind::GasWarning, k),
                true,
                trace(),
            )
            .unwrap();
        assert_eq!(second.decision, DeliveryDecision::SuppressedDuplicate);
        assert!(!second.delivered);
    }

    #[test]
    fn failed_delivery_is_surfaced_not_lost() {
        let mut c = NotificationCenter::new(8);
        // Transport fails: decision is Deliver but delivered=false (surfaced).
        let r = c
            .deliver(
                Notification::new(NotificationKind::JobFailed, key(4)),
                false,
                trace(),
            )
            .unwrap();
        assert_eq!(r.decision, DeliveryDecision::Deliver);
        assert!(!r.delivered); // failed delivery is visible in the receipt
        // A failed delivery is retryable (not deduped away).
        let retry = c
            .deliver(
                Notification::new(NotificationKind::JobFailed, key(4)),
                true,
                trace(),
            )
            .unwrap();
        assert!(retry.delivered);
    }

    #[test]
    fn queue_full_triggers_express_platform_pause() {
        let mut c = NotificationCenter::new(2);
        c.deliver(
            Notification::new(NotificationKind::JobDone, key(10)),
            true,
            trace(),
        )
        .unwrap();
        c.deliver(
            Notification::new(NotificationKind::JobDone, key(11)),
            true,
            trace(),
        )
        .unwrap();
        // Queue is now full (capacity 2). The next distinct delivery => QueueFull
        // + an express pause (the control ack stays hot-path under backpressure).
        let full = c.deliver(
            Notification::new(NotificationKind::JobDone, key(12)),
            true,
            trace(),
        );
        assert_eq!(full, Err(PlatformTelegramReject::QueueFull));
        assert_eq!(c.sync_state().state, PlatformChannelState::Paused);
        // A paused channel re-checks control state and refuses further delivery.
        let paused = c.deliver(
            Notification::new(NotificationKind::JobDone, key(13)),
            true,
            trace(),
        );
        assert_eq!(paused, Err(PlatformTelegramReject::ChannelPaused));
        c.resume();
        assert_eq!(c.sync_state().state, PlatformChannelState::Active);
    }

    #[test]
    fn notification_rules_user_configurable_default_on() {
        let mut c = NotificationCenter::new(8);
        for kind in NotificationKind::ALL {
            assert!(c.rule(kind).enabled);
            assert!(!c.rule(kind).muted);
        }
        c.set_enabled(NotificationKind::StaleJob, false);
        let r = c
            .deliver(
                Notification::new(NotificationKind::StaleJob, key(5)),
                true,
                trace(),
            )
            .unwrap();
        assert_eq!(r.decision, DeliveryDecision::SuppressedDisabled);
    }

    #[test]
    fn render_bounded_no_commerce_and_p95_within_50ms() {
        let mut c = NotificationCenter::new(16);
        c.deliver(
            Notification::new(NotificationKind::ApprovalRequest, key(20)),
            true,
            trace(),
        )
        .unwrap();
        // Bounded.
        assert!(c.render(3).len() <= 3);
        assert!(c.render(64).len() <= 7);
        // No commerce tokens anywhere in the status render (no-commerce law).
        const COMMERCE: &[&str] = &[
            "price", "pay", "buy", "sell", "checkout", "refund", "fee", "$",
        ];
        for line in c.render(64) {
            for t in COMMERCE {
                assert!(!line.contains(*t), "commerce token {t} leaked: {line}");
            }
        }
        // The receipt renders the dedupe key redacted (16 hex, never the full 64).
        let r = c
            .deliver(
                Notification::new(NotificationKind::JobDone, key(0xab)),
                true,
                trace(),
            )
            .unwrap();
        assert!(
            r.render(8)
                .iter()
                .any(|l| l == "dedupe_key=abababababababab")
        );
        // Local status p95 <= 50ms.
        let mut samples = Vec::with_capacity(256);
        for _ in 0..256 {
            let t = std::time::Instant::now();
            let lines = c.render(32);
            std::hint::black_box(&lines);
            samples.push(t.elapsed().as_nanos() as u64);
        }
        let p95 = p95_ms(&samples) / 1_000_000;
        assert!(
            p95 <= 50,
            "platform telegram status p95 {p95}ms exceeds 50ms budget"
        );
    }
}
