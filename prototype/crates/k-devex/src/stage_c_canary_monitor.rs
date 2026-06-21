//! Stage C read-only canary monitor (C-WP-07 · atom #236 · C.2.17).
//!
//! Canonical OUT: a read-only monitor for package / blob / gas / sponsor status.
//!
//! # Madness invariants (atom #236)
//!
//! * **No signer, no submitter, no write authority.** [`CanaryMonitor`] is a
//!   zero-sized handle. It holds no key, implements no signing method, and has
//!   no transaction-submit path. The only thing it can do is fold read-only
//!   status booleans into a [`CanaryStatus`] and surface anomalies — it can
//!   never mutate chain state.
//! * **Read-only RPC only.** [`poll`](CanaryMonitor::poll) consumes a
//!   [`CanaryInputs`] (the booleans a read-only status RPC would return) and
//!   produces a status plus anomaly set. There is no input by which a write
//!   could be requested.
//! * **Anomaly events are redacted by construction.** A [`CanaryAnomaly`] is a
//!   data-free `#[repr(u8)]` class — it carries no address, no value, no secret.
//!   Surfacing an anomaly therefore cannot leak the thing it observed.
//!
//! # Reuse map (atom contract)
//!
//! * **reuse: A metrics** — anomalies are counted into the existing
//!   [`MetricsExporter`](crate::metrics::MetricsExporter) (atom #49) as
//!   tool-denial-class events ([`Metric::ToolDenials`](crate::metrics::Metric::ToolDenials)):
//!   a health/policy refusal is a denial-class signal, and the exporter emits no
//!   label dimension so no secret can ride along.
//! * **reuse: #235** — observed anomalies drive a
//!   [`BurnInWindow`](crate::stage_c_burn_in::BurnInWindow), keeping its gate
//!   closed.
//!
//! No live action: monitoring only. `MainnetExecutionState` stays `Locked`.

use crate::metrics::{Metric, MetricsExporter};
use crate::stage_c_burn_in::BurnInWindow;

/// The read-only status booleans a canary poll observes (as a status RPC would
/// return them).
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub struct CanaryInputs {
    /// Whether the published package digest still matches the locked one.
    pub package_ok: bool,
    /// Whether the canary blob is still retrievable.
    pub blob_ok: bool,
    /// Whether gas spend is within the expected envelope.
    pub gas_ok: bool,
    /// Whether the sponsor wallet / mode is healthy.
    pub sponsor_ok: bool,
}

/// A single, redacted anomaly class. Data-free: carries no value or secret.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
#[repr(u8)]
pub enum CanaryAnomaly {
    /// The published package digest drifted from the locked one.
    PackageDrift = 1,
    /// The canary blob became unavailable.
    BlobUnavailable = 2,
    /// Gas spend left the expected envelope.
    GasSpike = 3,
    /// The sponsor wallet / mode became unhealthy.
    SponsorUnhealthy = 4,
}

impl CanaryAnomaly {
    /// A short, secret-free label for this anomaly class.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::PackageDrift => "package_drift",
            Self::BlobUnavailable => "blob_unavailable",
            Self::GasSpike => "gas_spike",
            Self::SponsorUnhealthy => "sponsor_unhealthy",
        }
    }
}

/// The result of a read-only poll: the observed status plus the anomalies found.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub struct CanaryStatus {
    /// The four observed status booleans.
    pub inputs: CanaryInputs,
    /// Bit `i` set when the `i`-th [`CanaryAnomaly`] (1-based) is present.
    anomaly_mask_u8: u8,
}

impl CanaryStatus {
    /// Whether every observed status is healthy (no anomaly).
    #[inline]
    #[must_use]
    pub const fn all_healthy(&self) -> bool {
        self.anomaly_mask_u8 == 0
    }

    /// The number of anomalies observed.
    #[inline]
    #[must_use]
    pub const fn anomaly_count(&self) -> u32 {
        self.anomaly_mask_u8.count_ones()
    }

    /// Whether a specific anomaly class is present.
    #[inline]
    #[must_use]
    pub const fn has_anomaly(&self, a: CanaryAnomaly) -> bool {
        self.anomaly_mask_u8 & (1u8 << (a as u8 - 1)) != 0
    }
}

/// A zero-sized, read-only canary monitor. No key, no signer, no submitter.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash, Default)]
pub struct CanaryMonitor;

impl CanaryMonitor {
    /// Construct the monitor. Carries no state and no key material.
    #[inline]
    #[must_use]
    pub const fn new() -> Self {
        Self
    }

    /// Fold read-only status booleans into a [`CanaryStatus`]. Pure: no I/O, no
    /// mutation.
    #[must_use]
    pub const fn evaluate(&self, inputs: CanaryInputs) -> CanaryStatus {
        let mut mask = 0u8;
        if !inputs.package_ok {
            mask |= 1u8 << (CanaryAnomaly::PackageDrift as u8 - 1);
        }
        if !inputs.blob_ok {
            mask |= 1u8 << (CanaryAnomaly::BlobUnavailable as u8 - 1);
        }
        if !inputs.gas_ok {
            mask |= 1u8 << (CanaryAnomaly::GasSpike as u8 - 1);
        }
        if !inputs.sponsor_ok {
            mask |= 1u8 << (CanaryAnomaly::SponsorUnhealthy as u8 - 1);
        }
        CanaryStatus {
            inputs,
            anomaly_mask_u8: mask,
        }
    }

    /// Poll: evaluate the inputs, count any anomalies into the metrics exporter
    /// (as tool-denial-class events) and into the burn-in window, and return the
    /// status. Read-only with respect to chain state; the only mutations are to
    /// the caller-owned monitoring counters.
    pub fn poll(
        &self,
        inputs: CanaryInputs,
        exporter: &MetricsExporter,
        window: &mut BurnInWindow,
    ) -> CanaryStatus {
        let status = self.evaluate(inputs);
        let anomalies = status.anomaly_count();
        if anomalies > 0 {
            exporter.incr(Metric::ToolDenials, u64::from(anomalies));
            for _ in 0..anomalies {
                window.record_anomaly();
            }
        }
        status
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]
    use super::*;

    const HEALTHY: CanaryInputs = CanaryInputs {
        package_ok: true,
        blob_ok: true,
        gas_ok: true,
        sponsor_ok: true,
    };

    #[test]
    fn signer_trait_absent() {
        // The monitor is zero-sized: it cannot physically carry a key or a
        // signer, and exposes no signing/submitting method.
        assert_eq!(core::mem::size_of::<CanaryMonitor>(), 0);
        let m = CanaryMonitor::new();
        // The only outputs are read-only status values.
        assert!(m.evaluate(HEALTHY).all_healthy());
    }

    #[test]
    fn read_only_rpc_only() {
        let m = CanaryMonitor::new();
        let exporter = MetricsExporter::new();
        let mut window = BurnInWindow::new(100, 100);
        // A clean poll records no denial and keeps the gate openable.
        let ok = m.poll(HEALTHY, &exporter, &mut window);
        assert!(ok.all_healthy());
        assert_eq!(window.anomaly_count_u32, 0);
        assert!(window.gate_open(300));
        // An unhealthy poll surfaces anomalies, counts denials, and closes gate.
        let bad = CanaryInputs {
            package_ok: false,
            blob_ok: true,
            gas_ok: false,
            sponsor_ok: true,
        };
        let st = m.poll(bad, &exporter, &mut window);
        assert_eq!(st.anomaly_count(), 2);
        assert!(st.has_anomaly(CanaryAnomaly::PackageDrift));
        assert!(st.has_anomaly(CanaryAnomaly::GasSpike));
        assert!(!st.has_anomaly(CanaryAnomaly::BlobUnavailable));
        assert_eq!(window.anomaly_count_u32, 2);
        assert!(!window.gate_open(300));
        assert!(exporter.render().contains("mnemos_tool_denials_total 2"));
    }

    #[test]
    fn anomaly_event_redacted() {
        // Anomaly classes carry only a secret-free label — no address, value,
        // or secret can ride along.
        for a in [
            CanaryAnomaly::PackageDrift,
            CanaryAnomaly::BlobUnavailable,
            CanaryAnomaly::GasSpike,
            CanaryAnomaly::SponsorUnhealthy,
        ] {
            let label = a.label();
            assert!(!label.is_empty());
            let upper = label.to_ascii_uppercase();
            assert!(!upper.contains("KEY"));
            assert!(!upper.contains("SECRET"));
            assert!(!upper.contains("PRIVATE"));
        }
    }
}
