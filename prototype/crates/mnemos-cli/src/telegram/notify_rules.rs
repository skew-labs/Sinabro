//! Operational notify-rule compiler (atom #508 · G.2.2).
//!
//! Stage-G alerts fire only on *verified* status changes — a gate going red, a
//! budget cap lowered, a local audit candidate, a task done, a provider spend, a
//! memory export/delete, a Stage H handoff ready — and each compiles onto the
//! canonical F notification classes with dedupe, mute, and severity ordering, so
//! there is no noisy spam loop (`G-G-CONTROL-EXPRESS`). Stage G mints no new
//! notification truth: delivery is decided by the canonical
//! [`crate::commands::platform_telegram::NotificationCenter`].
//!
//! Reuse (no reinvention): [`NotificationKind`] / [`Notification`] /
//! [`NotificationCenter`] / [`DeliveryDecision`] from
//! [`crate::commands::platform_telegram`]; the dedupe key uses [`crate::sha256_32`].
//! This module performs no live action.

use crate::commands::platform_telegram::{
    DeliveryDecision, Notification, NotificationCenter, NotificationKind,
};
use crate::sha256_32;

/// The severity of an operational alert (drives ordering; higher = more urgent).
#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum AlertSeverity {
    /// Informational (a task finished, a handoff is ready).
    Info = 1,
    /// Warning (budget cap lowered, provider spend, audit candidate, memory op).
    Warn = 2,
    /// Critical (a gate went red).
    Critical = 3,
}

impl AlertSeverity {
    /// The stable `u8` discriminant.
    #[must_use]
    pub const fn as_u8(self) -> u8 {
        self as u8
    }
}

/// The Stage-G operational status changes that may fire an alert.
#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OperationalAlert {
    /// A gate went red.
    GateRed = 1,
    /// A budget cap was lowered.
    BudgetCapLower = 2,
    /// A local audit candidate surfaced (a candidate, never a finding).
    AuditCandidate = 3,
    /// A task finished.
    TaskDone = 4,
    /// A provider spend occurred.
    ProviderSpend = 5,
    /// A memory export or delete happened.
    MemoryExportDelete = 6,
    /// A Stage H training handoff became ready (handoff, not a trained model).
    StageHHandoffReady = 7,
}

impl OperationalAlert {
    /// Every operational alert, in discriminant order.
    pub const ALL: [OperationalAlert; 7] = [
        OperationalAlert::GateRed,
        OperationalAlert::BudgetCapLower,
        OperationalAlert::AuditCandidate,
        OperationalAlert::TaskDone,
        OperationalAlert::ProviderSpend,
        OperationalAlert::MemoryExportDelete,
        OperationalAlert::StageHHandoffReady,
    ];

    /// The stable `u8` discriminant.
    #[must_use]
    pub const fn as_u8(self) -> u8 {
        self as u8
    }

    /// The canonical notification class this alert maps onto. Stage G reuses the
    /// closed F [`NotificationKind`] set and adds no new class.
    #[must_use]
    pub const fn notification_kind(self) -> NotificationKind {
        match self {
            Self::GateRed => NotificationKind::JobFailed,
            Self::TaskDone | Self::StageHHandoffReady => NotificationKind::JobDone,
            Self::BudgetCapLower | Self::ProviderSpend => NotificationKind::GasWarning,
            Self::AuditCandidate | Self::MemoryExportDelete => NotificationKind::ApprovalRequest,
        }
    }

    /// The severity of this alert.
    #[must_use]
    pub const fn severity(self) -> AlertSeverity {
        match self {
            Self::GateRed => AlertSeverity::Critical,
            Self::BudgetCapLower
            | Self::ProviderSpend
            | Self::AuditCandidate
            | Self::MemoryExportDelete => AlertSeverity::Warn,
            Self::TaskDone | Self::StageHHandoffReady => AlertSeverity::Info,
        }
    }
}

/// A compiled alert: the source alert class, its severity, and the canonical
/// notification it maps to (with its dedupe key).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CompiledAlert {
    /// The source operational alert.
    pub alert: OperationalAlert,
    /// The alert severity.
    pub severity: AlertSeverity,
    /// The canonical notification (kind + dedupe key).
    pub notification: Notification,
}

/// The operational notify-rule compiler. Compiles a Stage-G alert + its salient
/// fields into a canonical [`Notification`] and decides delivery via the
/// canonical [`NotificationCenter`] (rules / mute / dedupe), so there is no new
/// notification truth and no noisy spam loop.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NotifyRuleCompiler {
    center: NotificationCenter,
}

impl NotifyRuleCompiler {
    /// A new compiler with default rules and a bounded outbound capacity.
    #[must_use]
    pub fn new(capacity: usize) -> Self {
        Self {
            center: NotificationCenter::new(capacity),
        }
    }

    /// The underlying notification center (read-only).
    #[must_use]
    pub const fn center(&self) -> &NotificationCenter {
        &self.center
    }

    /// Mutable access to the underlying center (mute / enable / deliver) — reuses
    /// the canonical F controls.
    pub fn center_mut(&mut self) -> &mut NotificationCenter {
        &mut self.center
    }

    /// Compile an alert with a salient-fields byte string into a [`CompiledAlert`].
    /// The dedupe key is `SHA-256(alert_class || salient)`, so two alerts with the
    /// same salient content dedupe.
    #[must_use]
    pub fn compile(&self, alert: OperationalAlert, salient: &[u8]) -> CompiledAlert {
        let mut buf = Vec::with_capacity(salient.len() + 1);
        buf.push(alert.as_u8());
        buf.extend_from_slice(salient);
        CompiledAlert {
            alert,
            severity: alert.severity(),
            notification: Notification::new(alert.notification_kind(), sha256_32(&buf)),
        }
    }

    /// The delivery decision for a compiled alert under the current rules + dedupe
    /// set (pure; does not mutate). Reuses [`NotificationCenter::decide`].
    #[must_use]
    pub fn decide(&self, c: &CompiledAlert) -> DeliveryDecision {
        self.center.decide(&c.notification)
    }
}

/// Order compiled alerts by descending severity (`Critical` first), stable within
/// a severity. Returns a new ordering; does not mutate the input.
#[must_use]
pub fn severity_order(alerts: &[CompiledAlert]) -> Vec<CompiledAlert> {
    let mut v = alerts.to_vec();
    v.sort_by(|a, b| b.severity.cmp(&a.severity));
    v
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    #![allow(clippy::expect_used)]
    #![allow(clippy::panic)]

    use super::*;
    use crate::StageFTraceLink;
    use crate::repl::latency::p95_ms;

    fn trace() -> StageFTraceLink {
        StageFTraceLink::new([0x50; 32], 508, 0)
    }

    #[test]
    fn gate_red_is_critical_job_failed() {
        let c = NotifyRuleCompiler::new(8);
        let a = c.compile(OperationalAlert::GateRed, b"gate=G-FMT");
        assert_eq!(a.severity, AlertSeverity::Critical);
        assert_eq!(a.notification.kind, NotificationKind::JobFailed);
    }

    #[test]
    fn budget_cap_lower_is_warn_gas_warning() {
        let c = NotifyRuleCompiler::new(8);
        let a = c.compile(OperationalAlert::BudgetCapLower, b"cap=1000");
        assert_eq!(a.severity, AlertSeverity::Warn);
        assert_eq!(a.notification.kind, NotificationKind::GasWarning);
    }

    #[test]
    fn audit_candidate_is_warn_approval_request() {
        let c = NotifyRuleCompiler::new(8);
        let a = c.compile(OperationalAlert::AuditCandidate, b"candidate=pda-seed");
        assert_eq!(a.severity, AlertSeverity::Warn);
        // A candidate needs user attention but is never auto-promoted to a finding.
        assert_eq!(a.notification.kind, NotificationKind::ApprovalRequest);
    }

    #[test]
    fn task_done_is_info_job_done() {
        let c = NotifyRuleCompiler::new(8);
        let a = c.compile(OperationalAlert::TaskDone, b"task=42");
        assert_eq!(a.severity, AlertSeverity::Info);
        assert_eq!(a.notification.kind, NotificationKind::JobDone);
    }

    #[test]
    fn dedupe_suppresses_repeat_alert() {
        let mut c = NotifyRuleCompiler::new(8);
        let a = c.compile(OperationalAlert::TaskDone, b"task=1");
        // First delivery records the dedupe key.
        let first = c
            .center_mut()
            .deliver(a.notification, true, trace())
            .unwrap();
        assert_eq!(first.decision, DeliveryDecision::Deliver);
        // The same salient content compiles to the same key -> duplicate.
        let again = c.compile(OperationalAlert::TaskDone, b"task=1");
        assert_eq!(c.decide(&again), DeliveryDecision::SuppressedDuplicate);
    }

    /// E0e-3 — SI-6 zero-drift telegram: the idempotency key is ONE pure function
    /// of `(alert class || salient)` and the delivery gate is the SINGLE source of
    /// dedupe. A std-only seeded property loop (NO new crate; `--locked --offline`
    /// honoring [[raw-byte-level-optimization-over-clean-code]]) asserts, over many
    /// generated `(class, salient)` inputs:
    ///   (1) DETERMINISM — recompiling the same input yields the SAME 32-byte key;
    ///   (2) INJECTIVITY over the corpus — distinct inputs yield distinct keys, so
    ///       no idempotency-key collision ever merges two different alerts;
    ///   (3) SINGLE GATE — the first delivery of a key records it and any later
    ///       delivery of the SAME key is `SuppressedDuplicate`, while a fresh key
    ///       delivers.
    /// FAILS if a second key source or a bypassable dedupe gate is ever introduced.
    #[test]
    fn si6_idempotency_key_is_one_pure_source_and_the_gate_is_single() {
        use std::collections::HashMap;
        // A small deterministic LCG (seeded, reproducible — no rng dep, no
        // `Math.random`/`Date::now`); varies the corpus without nondeterminism.
        let mut state: u64 = 0x9E37_79B9_7F4A_7C15;
        let mut next = || {
            state = state
                .wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(1_442_695_040_888_963_407);
            (state >> 33) as u32
        };
        let alerts = [
            OperationalAlert::GateRed,
            OperationalAlert::BudgetCapLower,
            OperationalAlert::AuditCandidate,
            OperationalAlert::TaskDone,
            OperationalAlert::StageHHandoffReady,
        ];
        let compiler = NotifyRuleCompiler::new(8);
        // key -> the exact (class, salient) that produced it; a clash on DIFFERENT
        // inputs is an injectivity break (two distinct alerts sharing one key).
        let mut seen: HashMap<[u8; 32], (OperationalAlert, Vec<u8>)> = HashMap::new();
        for _ in 0..4096 {
            let alert = alerts[(next() as usize) % alerts.len()];
            let salient_len = (next() % 24) as usize;
            let mut salient = Vec::with_capacity(salient_len);
            for _ in 0..salient_len {
                salient.push((next() & 0xff) as u8);
            }
            let k1 = compiler.compile(alert, &salient).notification.dedupe_key_32;
            let k2 = compiler.compile(alert, &salient).notification.dedupe_key_32;
            // (1) determinism: one input -> one key, every time.
            assert_eq!(
                k1, k2,
                "idempotency key not deterministic for the same input"
            );
            // (2) injectivity over the corpus: a key never maps to two inputs.
            let id = (alert, salient.clone());
            match seen.get(&k1) {
                Some(prev) => assert_eq!(
                    *prev, id,
                    "idempotency-key collision would merge two distinct alerts"
                ),
                None => {
                    seen.insert(k1, id);
                }
            }
        }
        // (3) single gate: deliver records the key; a re-compile of the same input
        // is a duplicate; a different input is fresh. The gate is the sole dedupe.
        let mut center = NotifyRuleCompiler::new(8);
        let a = center.compile(OperationalAlert::TaskDone, b"job=42");
        assert_eq!(
            center
                .center_mut()
                .deliver(a.notification, true, trace())
                .unwrap()
                .decision,
            DeliveryDecision::Deliver
        );
        let same = center.compile(OperationalAlert::TaskDone, b"job=42");
        assert_eq!(center.decide(&same), DeliveryDecision::SuppressedDuplicate);
        let different = center.compile(OperationalAlert::TaskDone, b"job=43");
        assert_eq!(center.decide(&different), DeliveryDecision::Deliver);
    }

    #[test]
    fn mute_suppresses_kind() {
        let mut c = NotifyRuleCompiler::new(8);
        c.center_mut().set_muted(NotificationKind::JobDone, true);
        let a = c.compile(OperationalAlert::TaskDone, b"task=7");
        assert_eq!(c.decide(&a), DeliveryDecision::SuppressedMuted);
    }

    #[test]
    fn severity_order_critical_first() {
        let c = NotifyRuleCompiler::new(8);
        let alerts = [
            c.compile(OperationalAlert::TaskDone, b"a"),       // Info
            c.compile(OperationalAlert::GateRed, b"b"),        // Critical
            c.compile(OperationalAlert::BudgetCapLower, b"c"), // Warn
        ];
        let ordered = severity_order(&alerts);
        assert_eq!(ordered[0].severity, AlertSeverity::Critical);
        assert_eq!(ordered[1].severity, AlertSeverity::Warn);
        assert_eq!(ordered[2].severity, AlertSeverity::Info);
    }

    #[test]
    fn all_alerts_map_to_a_canonical_kind() {
        let c = NotifyRuleCompiler::new(8);
        for alert in OperationalAlert::ALL {
            let compiled = c.compile(alert, b"x");
            // Maps onto one of the five canonical kinds (no new truth).
            assert!(NotificationKind::ALL.contains(&compiled.notification.kind));
        }
    }

    #[test]
    fn compile_p95_within_20ms() {
        let c = NotifyRuleCompiler::new(8);
        let mut samples = Vec::with_capacity(256);
        for _ in 0..256 {
            let t = std::time::Instant::now();
            let a = c.compile(OperationalAlert::ProviderSpend, b"spend=120");
            std::hint::black_box(&a);
            samples.push(t.elapsed().as_nanos() as u64);
        }
        let p95 = p95_ms(&samples) / 1_000_000;
        assert!(p95 <= 20, "notify rule compile p95 {p95}ms exceeds 20ms");
    }
}
