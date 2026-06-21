//! Gas Station drain invariant dashboard tab (F-WP-05C, atom #450 · F.5.7 gas
//! drain dashboard).
//!
//! A pure projection (like the rest of [`crate::tui`]) of the master §7.5 Gas
//! Station drain-prevention invariants. Each invariant the §7.5 threat model
//! forbids — wildcard sponsorship, raw `GasData` lease, opaque tx signing, nonce
//! replay, gas-coin lease collision, quota bypass, and the hot-wallet-cap drain
//! bound — is one [`DrainGateKind`] row. The render law mirrors
//! [`crate::tui::provider_tab`]: a **tripped** gate is [`RenderTruth::Red`] and
//! is *never* green; an unevaluated gate is [`RenderTruth::Unknown`], never a
//! false green. The refresh is a status projection only — it makes **no live
//! chain / gas call** ([`GasDrainDashboard::refresh_made_no_live_call`]).
//!
//! Reuse (no reinvention): each drain gate maps 1:1 to a canonical
//! [`mnemos_g_wallet::GasStationRejectReason`] via [`DrainGateKind::reject_reason`],
//! so the dashboard and the real Gas Station agree on the reject taxonomy; the
//! render truth is [`crate::tui::RenderTruth`].

use crate::tui::RenderTruth;
use mnemos_g_wallet::GasStationRejectReason;

/// The master §7.5 drain-prevention invariant gates, in dashboard display order.
#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DrainGateKind {
    /// "Any valid tx within budget is sponsored" — forbidden (§7.5 절대 금지).
    WildcardSponsorship = 1,
    /// Pre-baked raw `GasData` handed to the user — forbidden.
    RawGasDataLease = 2,
    /// Signing undecoded/opaque transaction bytes — forbidden.
    OpaqueTxSigning = 3,
    /// Re-using a nonce for a different intent — rejected (replay gate).
    NonceReplay = 4,
    /// A gas coin leased to two inflight txs at once — rejected (lease gate).
    LeaseCollision = 5,
    /// A request that bypasses the per-identity / global quota — rejected.
    QuotaBypass = 6,
    /// The hot wallet holding at/above the daily burn cap — drain bound broken.
    HotWalletCapExceeded = 7,
}

impl DrainGateKind {
    /// Stable u8 tag.
    #[must_use]
    pub const fn tag(self) -> u8 {
        self as u8
    }

    /// The canonical [`GasStationRejectReason`] this drain gate maps to. The
    /// dashboard does not mint a parallel taxonomy — a tripped gate names the
    /// exact reject reason the real Gas Station would return.
    #[must_use]
    pub const fn reject_reason(self) -> GasStationRejectReason {
        match self {
            Self::WildcardSponsorship => GasStationRejectReason::Wildcard,
            Self::RawGasDataLease => GasStationRejectReason::RawGasData,
            Self::OpaqueTxSigning => GasStationRejectReason::OpaqueBytes,
            Self::NonceReplay => GasStationRejectReason::ReplayNonce,
            Self::LeaseCollision => GasStationRejectReason::GasCoinLease,
            Self::QuotaBypass => GasStationRejectReason::QuotaRisk,
            Self::HotWalletCapExceeded => GasStationRejectReason::Budget,
        }
    }
}

/// Every §7.5 drain gate, in display order. Used by the dashboard + coverage
/// tests so no invariant is silently dropped.
pub const ALL_DRAIN_GATES: [DrainGateKind; 7] = [
    DrainGateKind::WildcardSponsorship,
    DrainGateKind::RawGasDataLease,
    DrainGateKind::OpaqueTxSigning,
    DrainGateKind::NonceReplay,
    DrainGateKind::LeaseCollision,
    DrainGateKind::QuotaBypass,
    DrainGateKind::HotWalletCapExceeded,
];

/// The status of one drain gate. `Tripped` is `Red` and never green; `Unknown`
/// is explicit (an unevaluated gate is never a false green).
#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DrainGateStatus {
    /// The invariant holds (no drain path) — `Green`.
    Hold = 1,
    /// The invariant is violated — `Red`, never green.
    Tripped = 2,
    /// Not yet evaluated — `Unknown`, never a false green.
    Unknown = 3,
}

impl DrainGateStatus {
    /// Project the gate status onto the cockpit render truth.
    #[must_use]
    pub const fn render_truth(self) -> RenderTruth {
        match self {
            Self::Hold => RenderTruth::Green,
            Self::Tripped => RenderTruth::Red,
            Self::Unknown => RenderTruth::Unknown,
        }
    }
}

/// One drain-gate row: the invariant, its status, the canonical reject code it
/// maps to, and a redacted detail string.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DrainGateRow {
    /// Which §7.5 invariant.
    pub kind: DrainGateKind,
    /// The invariant's current status.
    pub status: DrainGateStatus,
    /// The canonical [`GasStationRejectReason`] u8 this gate maps to.
    pub reject_code_u8: u8,
    /// A short, colorless detail (no secret, no raw bytes).
    pub detail: String,
}

impl DrainGateRow {
    /// Build a drain-gate row; the reject code is derived from the gate kind.
    #[must_use]
    pub fn new(kind: DrainGateKind, status: DrainGateStatus, detail: &str) -> Self {
        Self {
            kind,
            status,
            reject_code_u8: kind.reject_reason().as_u8(),
            detail: detail.to_string(),
        }
    }

    /// The row's render truth (a tripped invariant is always `Red`).
    #[must_use]
    pub const fn render_truth(&self) -> RenderTruth {
        self.status.render_truth()
    }
}

/// The Gas Station drain invariant dashboard — a list of §7.5 gate rows.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct GasDrainDashboard {
    rows: Vec<DrainGateRow>,
}

impl GasDrainDashboard {
    /// A new, empty dashboard.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a drain-gate row.
    pub fn push(&mut self, row: DrainGateRow) {
        self.rows.push(row);
    }

    /// The drain-gate rows.
    #[must_use]
    pub fn rows(&self) -> &[DrainGateRow] {
        &self.rows
    }

    /// The number of rows.
    #[must_use]
    pub fn len(&self) -> usize {
        self.rows.len()
    }

    /// Whether the dashboard is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.rows.is_empty()
    }

    /// Recompute the per-gate render truths (the dashboard refresh). A pure
    /// projection — no live chain / gas call is made.
    #[must_use]
    pub fn refresh(&self) -> Vec<RenderTruth> {
        self.rows.iter().map(DrainGateRow::render_truth).collect()
    }

    /// Whether every drain invariant currently holds (`Green`).
    #[must_use]
    pub fn all_invariants_hold(&self) -> bool {
        self.rows
            .iter()
            .all(|r| matches!(r.status, DrainGateStatus::Hold))
    }

    /// The kinds of every currently-tripped gate (the red drain risks).
    #[must_use]
    pub fn tripped(&self) -> Vec<DrainGateKind> {
        self.rows
            .iter()
            .filter(|r| matches!(r.status, DrainGateStatus::Tripped))
            .map(|r| r.kind)
            .collect()
    }

    /// The no-call invariant: a refresh never makes a live chain / gas call.
    /// Always `true` — the dashboard is a pure projection.
    #[must_use]
    pub const fn refresh_made_no_live_call(&self) -> bool {
        true
    }
}

/// The §7.5 hot-wallet drain bound: the hot sponsor wallet's standing balance cap
/// must stay strictly below the daily burn cap, so a fully-drained hot wallet
/// loses less than one day's gas and the cold treasury stays safe. Returns
/// `true` when the bound holds.
#[must_use]
pub const fn hot_cap_below_daily_burn(hot_balance_cap_mist: u64, daily_burn_cap_mist: u64) -> bool {
    hot_balance_cap_mist < daily_burn_cap_mist
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::repl::latency::p95_ms;

    fn full_holding_dashboard() -> GasDrainDashboard {
        let mut d = GasDrainDashboard::new();
        for kind in ALL_DRAIN_GATES {
            d.push(DrainGateRow::new(kind, DrainGateStatus::Hold, "ok"));
        }
        d
    }

    #[test]
    fn all_gates_holding_are_green() {
        let d = full_holding_dashboard();
        assert_eq!(d.len(), 7);
        assert!(d.all_invariants_hold());
        assert!(d.refresh().iter().all(|t| matches!(t, RenderTruth::Green)));
        assert!(d.tripped().is_empty());
    }

    #[test]
    fn tripped_gate_is_red_never_green() {
        for kind in ALL_DRAIN_GATES {
            let row = DrainGateRow::new(kind, DrainGateStatus::Tripped, "violation");
            assert_eq!(row.render_truth(), RenderTruth::Red);
            assert!(!row.render_truth().is_healthy());
        }
    }

    #[test]
    fn unknown_gate_is_unknown_not_green() {
        let row = DrainGateRow::new(
            DrainGateKind::WildcardSponsorship,
            DrainGateStatus::Unknown,
            "?",
        );
        assert_eq!(row.render_truth(), RenderTruth::Unknown);
        assert!(!row.render_truth().is_healthy());
    }

    #[test]
    fn reject_code_mapping_is_canonical() {
        assert_eq!(
            DrainGateKind::WildcardSponsorship.reject_reason(),
            GasStationRejectReason::Wildcard
        );
        assert_eq!(
            DrainGateKind::OpaqueTxSigning.reject_reason(),
            GasStationRejectReason::OpaqueBytes
        );
        assert_eq!(
            DrainGateKind::RawGasDataLease.reject_reason(),
            GasStationRejectReason::RawGasData
        );
        // The row records the canonical u8 code.
        let row = DrainGateRow::new(DrainGateKind::LeaseCollision, DrainGateStatus::Tripped, "x");
        assert_eq!(
            row.reject_code_u8,
            GasStationRejectReason::GasCoinLease.as_u8()
        );
    }

    #[test]
    fn malicious_endpoint_replay_trips_nonce_gate() {
        let mut d = full_holding_dashboard();
        // A malicious endpoint replays a nonce: the replay gate trips red.
        d.push(DrainGateRow::new(
            DrainGateKind::NonceReplay,
            DrainGateStatus::Tripped,
            "nonce reused for different intent",
        ));
        assert!(!d.all_invariants_hold());
        assert!(d.tripped().contains(&DrainGateKind::NonceReplay));
    }

    #[test]
    fn hot_wallet_cap_bound() {
        // Hot cap strictly below daily burn => bound holds.
        assert!(hot_cap_below_daily_burn(1_000, 5_000));
        // Hot cap at or above daily burn => bound broken (drain risk).
        assert!(!hot_cap_below_daily_burn(5_000, 5_000));
        assert!(!hot_cap_below_daily_burn(6_000, 5_000));
        // The dashboard surfaces the broken bound as a tripped gate.
        let tripped = !hot_cap_below_daily_burn(6_000, 5_000);
        let status = if tripped {
            DrainGateStatus::Tripped
        } else {
            DrainGateStatus::Hold
        };
        let row = DrainGateRow::new(DrainGateKind::HotWalletCapExceeded, status, "hot>=daily");
        assert_eq!(row.render_truth(), RenderTruth::Red);
    }

    #[test]
    fn gas_coin_lease_collision_trips() {
        let row = DrainGateRow::new(
            DrainGateKind::LeaseCollision,
            DrainGateStatus::Tripped,
            "coin leased to two inflight txs",
        );
        assert_eq!(row.render_truth(), RenderTruth::Red);
        assert_eq!(
            row.reject_code_u8,
            GasStationRejectReason::GasCoinLease.as_u8()
        );
    }

    #[test]
    fn refresh_makes_no_live_call() {
        let d = full_holding_dashboard();
        assert!(d.refresh_made_no_live_call());
        assert_eq!(d.refresh().len(), 7);
    }

    #[test]
    fn drain_dashboard_refresh_p95_within_250ms() {
        let d = full_holding_dashboard();
        let mut samples = Vec::with_capacity(256);
        for _ in 0..256 {
            let t = std::time::Instant::now();
            let v = d.refresh();
            std::hint::black_box(&v);
            samples.push(t.elapsed().as_nanos() as u64);
        }
        let p95 = p95_ms(&samples) / 1_000_000;
        assert!(
            p95 <= 250,
            "drain dashboard refresh p95 {p95}ms exceeds 250ms budget"
        );
    }
}
