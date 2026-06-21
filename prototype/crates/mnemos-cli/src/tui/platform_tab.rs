//! `sinabro tui` shared platform status tab (atom #461 · F.7.2 shared platform
//! status in TUI).
//!
//! A read-only cockpit projection over the *canonical* notification / platform
//! sync truth that the F-WP-06C [`crate::commands::platform_telegram`]
//! controller already owns. The tab makes the user-facing platform state visible
//! in one place: the shared CLI⇔Telegram sync state (and whether the local
//! observer is *stale* relative to it), the outbound delivery counts (enqueued /
//! failed / suppressed), the paused-channel state, the muted / disabled
//! notification rules, the pending approval-queue depth, and the trace of the
//! last command envelope that crossed a platform boundary.
//!
//! Reuse (no reinvention): every value is read through the *public* API of the
//! canonical [`NotificationCenter`] ([`NotificationCenter::sync_state`],
//! [`NotificationCenter::rule`], [`NotificationCenter::pending_approvals`]) plus
//! the observed [`DeliveryReceipt`] log; this module mints no platform truth and
//! reaches into no private field. The red/yellow/green verdict is the cockpit
//! [`crate::tui::RenderTruth`]. The envelope shown is the canonical
//! [`MessageEnvelope`] (origin + the origin-independent
//! [`crate::command::CommandEnvelope`]).
//!
//! Latency: the projection is a single `O(rules + receipts)` pass and the render
//! is bounded by `rows`; nothing here scans the repo, replays memory, renders a
//! full trace, or touches the network (atom #461 criterion: refresh p95 ≤ 100ms
//! cached). No false green (G-F-UI-TRUTH): an unbound channel is `Red`, a paused
//! channel is `Yellow`, and a stale observer or a failed delivery degrades an
//! otherwise-active channel to `Yellow` — never a false `Green`.

use crate::commands::platform_telegram::{
    DeliveryDecision, DeliveryReceipt, MessageEnvelope, NotificationCenter, NotificationKind,
    PlatformChannelState,
};
use crate::hex32;
use crate::tui::RenderTruth;

/// First 16 hex characters of a 32-byte hash — a redacted, display-only prefix
/// (never the full 64-char value).
#[must_use]
fn redact16(bytes: &[u8; 32]) -> String {
    hex32(bytes).chars().take(16).collect()
}

/// A read-only projection of the shared platform status for the TUI platform
/// tab. Built from the canonical [`NotificationCenter`] plus the observed
/// delivery-receipt log; holds no platform truth of its own.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PlatformStatusTab {
    /// The shared channel lifecycle (observed identically by every origin).
    channel: PlatformChannelState,
    /// The authoritative shared sync version.
    sync_version: u32,
    /// The version this local observer last saw. If it lags `sync_version` the
    /// observer is stale.
    observed_version: u32,
    /// Receipts whose transport succeeded (entered the outbound bridge queue).
    outbound_enqueued: usize,
    /// Receipts the rules chose to deliver but whose transport failed — surfaced,
    /// never silently lost.
    failed_deliveries: usize,
    /// Receipts a rule suppressed (disabled / muted / duplicate).
    suppressed: usize,
    /// Outstanding delivered-but-unresolved approval requests.
    pending_approvals: usize,
    /// How many of the five notification classes are currently muted.
    muted_count: u8,
    /// How many of the five notification classes are currently disabled.
    disabled_count: u8,
    /// The last command envelope that crossed a platform boundary (for the
    /// envelope trace row). `None` if no command has been observed yet.
    last_envelope: Option<MessageEnvelope>,
}

impl PlatformStatusTab {
    /// Project the platform tab from the canonical controller, the local
    /// observed sync version, the recent delivery-receipt log, and the last
    /// platform-boundary command envelope.
    ///
    /// Only the controller's *public* API is read; no private field is touched
    /// and no platform truth is re-minted.
    #[must_use]
    pub fn project(
        center: &NotificationCenter,
        observed_version: u32,
        recent: &[DeliveryReceipt],
        last_envelope: Option<MessageEnvelope>,
    ) -> Self {
        let sync = center.sync_state();

        let mut outbound_enqueued = 0usize;
        let mut failed_deliveries = 0usize;
        let mut suppressed = 0usize;
        for r in recent {
            if r.delivered {
                outbound_enqueued += 1;
            } else if matches!(r.decision, DeliveryDecision::Deliver) {
                // Decided to deliver, but transport did not confirm: a surfaced
                // failure (G-F-NOTIFY), not a silent drop.
                failed_deliveries += 1;
            } else {
                suppressed += 1;
            }
        }

        let mut muted_count = 0u8;
        let mut disabled_count = 0u8;
        for kind in NotificationKind::ALL {
            let rule = center.rule(kind);
            if rule.muted {
                muted_count += 1;
            }
            if !rule.enabled {
                disabled_count += 1;
            }
        }

        Self {
            channel: sync.state,
            sync_version: sync.version_u32,
            observed_version,
            outbound_enqueued,
            failed_deliveries,
            suppressed,
            pending_approvals: center.pending_approvals(),
            muted_count,
            disabled_count,
            last_envelope,
        }
    }

    /// Whether the local observer is stale relative to the shared sync state
    /// (its observed version lags the authoritative version).
    #[must_use]
    pub const fn is_stale(&self) -> bool {
        self.observed_version < self.sync_version
    }

    /// The shared channel lifecycle.
    #[must_use]
    pub const fn channel(&self) -> PlatformChannelState {
        self.channel
    }

    /// The count of failed (decided-but-not-delivered) deliveries.
    #[must_use]
    pub const fn failed_deliveries(&self) -> usize {
        self.failed_deliveries
    }

    /// The outstanding approval-queue depth.
    #[must_use]
    pub const fn pending_approvals(&self) -> usize {
        self.pending_approvals
    }

    /// The number of muted notification classes.
    #[must_use]
    pub const fn muted_count(&self) -> u8 {
        self.muted_count
    }

    /// The render truth (no false green). An unbound channel is `Red`; a paused
    /// channel is `Yellow`; an active channel that is stale or has a failed
    /// delivery is `Yellow`; otherwise `Green`.
    #[must_use]
    pub const fn render_truth(&self) -> RenderTruth {
        match self.channel {
            PlatformChannelState::Unbound => RenderTruth::Red,
            PlatformChannelState::Paused => RenderTruth::Yellow,
            PlatformChannelState::Active => {
                if self.is_stale() || self.failed_deliveries > 0 {
                    RenderTruth::Yellow
                } else {
                    RenderTruth::Green
                }
            }
        }
    }

    /// Redacted, colorless status lines bounded by `rows` (hot-path render). The
    /// last command's argument hash is shown as a 16-hex prefix only.
    #[must_use]
    pub fn render(&self, rows: u16) -> Vec<String> {
        let mut lines = vec![
            format!("channel_state_u8={}", self.channel.as_u8()),
            format!("sync_version={}", self.sync_version),
            format!("observed_version={}", self.observed_version),
            format!("stale={}", self.is_stale()),
            format!("outbound_enqueued={}", self.outbound_enqueued),
            format!("failed_deliveries={}", self.failed_deliveries),
            format!("suppressed={}", self.suppressed),
            format!("pending_approvals={}", self.pending_approvals),
            format!("muted_rules={}", self.muted_count),
            format!("disabled_rules={}", self.disabled_count),
            format!("truth_u8={}", self.render_truth() as u8),
        ];
        match self.last_envelope {
            Some(env) => {
                let cmd = env.command();
                lines.push(format!("last_origin_u8={}", env.origin.as_u8()));
                lines.push(format!("last_cmd_risk_u8={}", cmd.risk as u8));
                lines.push(format!("last_cmd_args={}", redact16(&cmd.args_hash_32)));
            }
            None => lines.push("last_envelope=none".to_string()),
        }
        lines.into_iter().take(rows as usize).collect()
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    #![allow(clippy::expect_used)]
    #![allow(clippy::panic)]

    use super::*;
    use crate::StageFTraceLink;
    use crate::command::{CliMode, CommandEnvelope, CommandRisk};
    use crate::commands::platform_telegram::{Notification, PlatformOrigin};
    use crate::grammar::CliNamespace;
    use crate::repl::latency::p95_ms;

    fn trace() -> StageFTraceLink {
        StageFTraceLink::new([0x5a; 32], 461, 0)
    }

    fn env(verb: &str) -> CommandEnvelope {
        CommandEnvelope::classify(
            CliNamespace::Platform,
            verb,
            CliMode::Tui,
            CommandRisk::ReadOnly,
            verb.as_bytes(),
        )
    }

    fn key(seed: u8) -> [u8; 32] {
        [seed; 32]
    }

    #[test]
    fn active_clean_channel_is_green() {
        let center = NotificationCenter::new(8);
        let v = center.sync_state().version_u32;
        let tab = PlatformStatusTab::project(&center, v, &[], None);
        assert_eq!(tab.channel(), PlatformChannelState::Active);
        assert!(!tab.is_stale());
        assert_eq!(tab.render_truth(), RenderTruth::Green);
    }

    #[test]
    fn paused_channel_renders_yellow() {
        let mut center = NotificationCenter::new(8);
        center.express_pause();
        let v = center.sync_state().version_u32;
        let tab = PlatformStatusTab::project(&center, v, &[], None);
        assert_eq!(tab.channel(), PlatformChannelState::Paused);
        assert_eq!(tab.render_truth(), RenderTruth::Yellow);
    }

    #[test]
    fn failed_delivery_is_surfaced_and_degrades_to_yellow() {
        let mut center = NotificationCenter::new(8);
        // Transport fails: decision Deliver but delivered=false.
        let r = center
            .deliver(
                Notification::new(NotificationKind::JobFailed, key(4)),
                false,
                trace(),
            )
            .unwrap();
        assert!(!r.delivered);
        let v = center.sync_state().version_u32;
        let tab = PlatformStatusTab::project(&center, v, &[r], None);
        assert_eq!(tab.failed_deliveries(), 1);
        assert_eq!(tab.render_truth(), RenderTruth::Yellow); // surfaced, not green
    }

    #[test]
    fn stale_sync_is_detected() {
        let mut center = NotificationCenter::new(8);
        center.express_pause(); // bumps version to 1
        center.resume(); // bumps version to 2
        let current = center.sync_state().version_u32;
        assert!(current >= 2);
        // Observer last saw version 0 -> stale.
        let tab = PlatformStatusTab::project(&center, 0, &[], None);
        assert!(tab.is_stale());
        // The channel is active again, but a stale observer is Yellow not Green.
        assert_eq!(tab.channel(), PlatformChannelState::Active);
        assert_eq!(tab.render_truth(), RenderTruth::Yellow);
        // A current observer is not stale.
        let fresh = PlatformStatusTab::project(&center, current, &[], None);
        assert!(!fresh.is_stale());
        assert_eq!(fresh.render_truth(), RenderTruth::Green);
    }

    #[test]
    fn envelope_trace_row_is_rendered_redacted() {
        let center = NotificationCenter::new(8);
        let v = center.sync_state().version_u32;
        let msg = MessageEnvelope::new(PlatformOrigin::Telegram, env("kill"));
        let tab = PlatformStatusTab::project(&center, v, &[], Some(msg));
        let lines = tab.render(64);
        assert!(
            lines
                .iter()
                .any(|l| l == &format!("last_origin_u8={}", PlatformOrigin::Telegram.as_u8()))
        );
        // The args hash is shown as a 16-hex prefix only, never the full 64.
        assert!(lines.iter().any(|l| {
            l.strip_prefix("last_cmd_args=")
                .is_some_and(|h| h.len() == 16)
        }));
    }

    #[test]
    fn muted_rule_is_visible() {
        let mut center = NotificationCenter::new(8);
        center.set_muted(NotificationKind::JobDone, true);
        let v = center.sync_state().version_u32;
        let tab = PlatformStatusTab::project(&center, v, &[], None);
        assert_eq!(tab.muted_count(), 1);
        assert!(tab.render(64).iter().any(|l| l == "muted_rules=1"));
    }

    #[test]
    fn pending_approval_is_visible() {
        let mut center = NotificationCenter::new(8);
        center
            .deliver(
                Notification::new(NotificationKind::ApprovalRequest, key(1)),
                true,
                trace(),
            )
            .unwrap();
        let v = center.sync_state().version_u32;
        let tab = PlatformStatusTab::project(&center, v, &[], None);
        assert_eq!(tab.pending_approvals(), 1);
        assert!(tab.render(64).iter().any(|l| l == "pending_approvals=1"));
    }

    #[test]
    fn render_is_bounded_no_commerce_and_p95_within_100ms() {
        let mut center = NotificationCenter::new(16);
        let r = center
            .deliver(
                Notification::new(NotificationKind::JobDone, key(0xab)),
                true,
                trace(),
            )
            .unwrap();
        let v = center.sync_state().version_u32;
        let msg = MessageEnvelope::new(PlatformOrigin::Cli, env("status"));
        let tab = PlatformStatusTab::project(&center, v, &[r], Some(msg));

        // Bounded by rows.
        assert!(tab.render(3).len() <= 3);
        assert!(tab.render(64).len() <= 14);

        // No commerce tokens leak into the status render (no-commerce law).
        const COMMERCE: &[&str] = &[
            "price", "pay", "buy", "sell", "checkout", "refund", "fee", "$",
        ];
        for line in tab.render(64) {
            for t in COMMERCE {
                assert!(!line.contains(*t), "commerce token {t} leaked: {line}");
            }
        }

        // Refresh p95 <= 100ms cached (atom #461 criterion).
        let mut samples = Vec::with_capacity(256);
        for _ in 0..256 {
            let t = std::time::Instant::now();
            let lines = PlatformStatusTab::project(&center, v, &[r], Some(msg));
            std::hint::black_box(&lines);
            samples.push(t.elapsed().as_nanos() as u64);
        }
        let p95 = p95_ms(&samples) / 1_000_000;
        assert!(p95 <= 100, "platform tab refresh p95 {p95}ms exceeds 100ms");
    }
}
