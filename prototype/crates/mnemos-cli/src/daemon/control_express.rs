//! Operational control-express bypass (atom #511 · G.2.5).
//!
//! The express rail carries STOP/freeze/pause controls only — `/kill`,
//! `/budget cap lower`, `/pause`, `/lockdown`, provider freeze, and wallet/gas
//! hard stop. Every one of these **halts** side effects; none initiates an
//! egress, a wallet signature, or a spend, so the rail performs no live action
//! (`live_action()` is a structural `false`) and owns no secret. These controls
//! preempt the saturated provider / audit / memory / evidence background queues
//! and are acknowledged synchronously even under backpressure
//! (`G-G-CONTROL-EXPRESS`). The global prompt law still blocks any *live* dispatch
//! until a same-message approval is present — this module never requests one
//! because it only stops work.
//!
//! Reuse (no reinvention): the express-rail bypass property is the canonical
//! [`crate::commands::platform_telegram::ExpressControl`] (every member bypasses
//! the queue). The Stage-G additions (provider freeze, wallet/gas hard stop) ride
//! the strongest STOP rail (`Lockdown`). This module performs no live action.

use crate::commands::platform_telegram::ExpressControl;

/// The express control classes that preempt the background queues. All are
/// STOP/freeze/pause-class: they halt side effects, never initiate them.
#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ExpressClass {
    /// `/kill` — hard stop the active turn.
    Kill = 1,
    /// `/budget cap lower` — tighten the cap, stopping the next over-cap dispatch.
    BudgetCapLower = 2,
    /// `/pause` — pause outbound platform delivery.
    Pause = 3,
    /// `/lockdown` — freeze all side effects.
    Lockdown = 4,
    /// Provider freeze — stop further provider dispatch.
    ProviderFreeze = 5,
    /// Wallet/gas hard stop — halt any wallet/gas side effect.
    WalletGasHardStop = 6,
}

impl ExpressClass {
    /// Every express class, in discriminant order.
    pub const ALL: [ExpressClass; 6] = [
        ExpressClass::Kill,
        ExpressClass::BudgetCapLower,
        ExpressClass::Pause,
        ExpressClass::Lockdown,
        ExpressClass::ProviderFreeze,
        ExpressClass::WalletGasHardStop,
    ];

    /// The stable `u8` discriminant.
    #[must_use]
    pub const fn as_u8(self) -> u8 {
        self as u8
    }

    /// Map onto the canonical F [`ExpressControl`] rail. The Stage-G additions
    /// (provider freeze, wallet/gas hard stop) ride the `Lockdown` rail — the
    /// strongest STOP.
    #[must_use]
    pub const fn express_control(self) -> ExpressControl {
        match self {
            Self::Kill => ExpressControl::Kill,
            Self::BudgetCapLower => ExpressControl::BudgetCap,
            Self::Pause => ExpressControl::PlatformPause,
            Self::Lockdown | Self::ProviderFreeze | Self::WalletGasHardStop => {
                ExpressControl::Lockdown
            }
        }
    }

    /// Every express class bypasses the normal / background queues (reuses the F
    /// rail's total bypass property).
    #[must_use]
    pub const fn bypasses_queue(self) -> bool {
        self.express_control().bypasses_queue()
    }

    /// Whether this control stops the next side effect. Always `true` — every
    /// member is a halt-class control.
    #[must_use]
    pub const fn stops_next_side_effect(self) -> bool {
        true
    }
}

/// The background-queue depths the control rail must bypass (a fixture model of
/// saturation; no real queue or I/O).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct BackgroundQueueDepths {
    /// Provider consult queue depth.
    pub provider: u32,
    /// Audit scan queue depth.
    pub audit: u32,
    /// Memory replay queue depth.
    pub memory: u32,
    /// Evidence pack queue depth.
    pub evidence: u32,
}

impl BackgroundQueueDepths {
    /// All four queues saturated to `depth`.
    #[must_use]
    pub const fn saturated(depth: u32) -> Self {
        Self {
            provider: depth,
            audit: depth,
            memory: depth,
            evidence: depth,
        }
    }

    /// Total pending background work across the four queues.
    #[must_use]
    pub const fn total(&self) -> u64 {
        self.provider as u64 + self.audit as u64 + self.memory as u64 + self.evidence as u64
    }
}

/// The acknowledgement of an express control: produced synchronously on the rail
/// regardless of background-queue saturation, and never performing a live action.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ExpressAck {
    /// The control that was acknowledged.
    pub class: ExpressClass,
    /// Always `true`: the control bypassed the background queues.
    pub bypassed_queue: bool,
    /// Always `true`: the control stops the next side effect.
    pub stops_next_side_effect: bool,
    /// Always `false`: no live action is ever performed here.
    pub live_action: bool,
    /// The total background-queue depth that was bypassed (for the audit trail).
    pub bypassed_depth_total: u64,
}

/// The control-express router: a pure in-memory control-plane projection. It
/// acknowledges a STOP/freeze/pause control immediately even under a saturated
/// background queue, gates the next side effect, and never performs a live action.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ControlExpressRouter {
    side_effects_stopped: bool,
}

impl ControlExpressRouter {
    /// A new router with side effects allowed.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            side_effects_stopped: false,
        }
    }

    /// Acknowledge an express control, bypassing the (possibly saturated)
    /// background queues. Sets the stop flag so the next provider/tool/memory/
    /// evidence side effect is gated. Never performs a live action.
    pub const fn ack(&mut self, class: ExpressClass, queues: BackgroundQueueDepths) -> ExpressAck {
        self.side_effects_stopped = true;
        ExpressAck {
            class,
            bypassed_queue: class.bypasses_queue(),
            stops_next_side_effect: class.stops_next_side_effect(),
            live_action: false,
            bypassed_depth_total: queues.total(),
        }
    }

    /// Whether the NEXT provider/tool/memory/evidence side effect is allowed. After
    /// any express control (cap lower / freeze / stop) this is `false` until an
    /// explicit [`Self::resume`].
    #[must_use]
    pub const fn next_side_effect_allowed(&self) -> bool {
        !self.side_effects_stopped
    }

    /// Structural invariant: this router performs no live action. Always `false`.
    #[must_use]
    pub const fn live_action(&self) -> bool {
        false
    }

    /// Resume normal side-effect flow (after the operator clears the stop).
    pub const fn resume(&mut self) {
        self.side_effects_stopped = false;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::repl::latency::p95_ms;

    #[test]
    fn saturated_provider_queue_is_bypassed() {
        let mut r = ControlExpressRouter::new();
        let q = BackgroundQueueDepths {
            provider: 100_000,
            ..BackgroundQueueDepths::default()
        };
        let ack = r.ack(ExpressClass::Kill, q);
        assert!(ack.bypassed_queue);
        assert!(!ack.live_action);
        assert_eq!(ack.bypassed_depth_total, 100_000);
    }

    #[test]
    fn saturated_audit_queue_is_bypassed() {
        let mut r = ControlExpressRouter::new();
        let q = BackgroundQueueDepths {
            audit: 50_000,
            ..BackgroundQueueDepths::default()
        };
        let ack = r.ack(ExpressClass::Lockdown, q);
        assert!(ack.bypassed_queue);
        assert!(!ack.live_action);
    }

    #[test]
    fn saturated_evidence_queue_is_bypassed() {
        let mut r = ControlExpressRouter::new();
        let q = BackgroundQueueDepths {
            evidence: 75_000,
            ..BackgroundQueueDepths::default()
        };
        let ack = r.ack(ExpressClass::ProviderFreeze, q);
        assert!(ack.bypassed_queue);
        assert!(!ack.live_action);
    }

    #[test]
    fn kill_bypasses_queue() {
        assert!(ExpressClass::Kill.bypasses_queue());
        let mut r = ControlExpressRouter::new();
        let ack = r.ack(ExpressClass::Kill, BackgroundQueueDepths::saturated(9_999));
        assert!(ack.bypassed_queue);
        assert_eq!(ack.class, ExpressClass::Kill);
    }

    #[test]
    fn cap_lower_stops_next_side_effect() {
        let mut r = ControlExpressRouter::new();
        assert!(r.next_side_effect_allowed());
        let ack = r.ack(
            ExpressClass::BudgetCapLower,
            BackgroundQueueDepths::saturated(1_000),
        );
        assert!(ack.stops_next_side_effect);
        assert!(!r.next_side_effect_allowed());
        // An explicit resume re-enables side effects.
        r.resume();
        assert!(r.next_side_effect_allowed());
    }

    #[test]
    fn every_class_bypasses_and_performs_no_live_action() {
        for class in ExpressClass::ALL {
            assert!(class.bypasses_queue(), "{class:?} must bypass the queue");
            let mut r = ControlExpressRouter::new();
            let ack = r.ack(class, BackgroundQueueDepths::saturated(1));
            assert!(!ack.live_action, "{class:?} must perform no live action");
            assert!(!r.live_action());
        }
    }

    #[test]
    fn control_path_p95_within_10ms() {
        let mut r = ControlExpressRouter::new();
        let q = BackgroundQueueDepths::saturated(100_000);
        let mut samples = Vec::with_capacity(256);
        for _ in 0..256 {
            let t = std::time::Instant::now();
            let ack = r.ack(ExpressClass::Kill, q);
            std::hint::black_box(&ack);
            samples.push(t.elapsed().as_nanos() as u64);
        }
        let p95 = p95_ms(&samples) / 1_000_000;
        assert!(p95 <= 10, "control express path p95 {p95}ms exceeds 10ms");
    }
}
