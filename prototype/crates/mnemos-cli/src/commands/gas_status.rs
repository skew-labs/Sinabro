//! `sinabro gas status` — gas sponsor mode / policy / quota status (F-WP-05C,
//! atom #448 · F.5.5 gas mode/status/policy).
//!
//! The §4.4 `GasStatusView`: a read-only projection of the gas posture. It shows
//! the hosted/self/none sponsor mode, the official-trust verdict, the policy
//! hash, a redacted hot-wallet balance digest, the daily burn vs cap, the
//! remaining quota, the per-tx gas cap, and a suspicious-pattern count —
//! **secrets absent** (only redacted digests + public MIST counts, never a key
//! or raw balance).
//!
//! A Stage F distinction made structural here: **gas/measure telemetry is
//! opt-in and off by default** ([`GasStatusView::telemetry_opt_in`] defaults
//! `false`), while the **gas safety gates are always-on protective checks**
//! ([`GasStatusView::safety_gates_always_on`] is the invariant `true`) — turning
//! telemetry off never turns the drain-protection gates off.
//!
//! Reuse (no reinvention): the sponsor mode is the canonical
//! [`mnemos_g_wallet::GasSponsorMode`] and the trust verdict is
//! [`mnemos_g_wallet::OfficialTrustDecision`]; the policy hash and balance are
//! taken as already-extracted 32-byte digests and redacted on the way in.

use crate::hex32;
use mnemos_g_wallet::{GasSponsorMode, OfficialTrustDecision};

/// First 16 hex characters of a 32-byte digest — a redacted, display-only prefix.
#[must_use]
fn redact16(bytes: &[u8; 32]) -> String {
    hex32(bytes).chars().take(16).collect()
}

/// §4.4 — the read-only gas status view. Holds no secret: balances and policy are
/// redacted digests, the rest are public MIST counts.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GasStatusView {
    /// The sponsor mode (hosted / self-hosted / none).
    pub mode: GasSponsorMode,
    /// The official-trust verdict for the sponsor.
    pub trust: OfficialTrustDecision,
    /// Redacted 16-hex prefix of the gas policy hash.
    pub policy_hash_redacted: String,
    /// Redacted 16-hex prefix of the hot-wallet balance digest (never the raw
    /// balance, never a key).
    pub hot_wallet_balance_redacted: String,
    /// Gas burned so far today, in MIST.
    pub daily_burn_mist: u64,
    /// The daily burn cap, in MIST. The hot wallet stays below this (§7.5).
    pub daily_burn_cap_mist: u64,
    /// Remaining per-identity quota.
    pub quota_remaining_u32: u32,
    /// The per-tx gas cap, in MIST.
    pub max_gas_per_tx_mist: u64,
    /// Count of suspicious patterns observed (anomaly signal, not a reward).
    pub suspicious_pattern_count_u32: u32,
    /// Whether gas/measure telemetry collection is opted in. Default `false`.
    pub telemetry_opt_in: bool,
    /// Invariant `true`: the safety gates are always-on protective checks,
    /// independent of telemetry.
    pub safety_gates_always_on: bool,
}

impl GasStatusView {
    /// Build a gas status view. Telemetry defaults to off (opt-in); the safety
    /// gates are always on. The policy hash and balance are redacted here.
    #[must_use]
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        mode: GasSponsorMode,
        trust: OfficialTrustDecision,
        policy_hash_32: &[u8; 32],
        hot_wallet_balance_hash_32: &[u8; 32],
        daily_burn_mist: u64,
        daily_burn_cap_mist: u64,
        quota_remaining_u32: u32,
        max_gas_per_tx_mist: u64,
        suspicious_pattern_count_u32: u32,
    ) -> Self {
        Self {
            mode,
            trust,
            policy_hash_redacted: redact16(policy_hash_32),
            hot_wallet_balance_redacted: redact16(hot_wallet_balance_hash_32),
            daily_burn_mist,
            daily_burn_cap_mist,
            quota_remaining_u32,
            max_gas_per_tx_mist,
            suspicious_pattern_count_u32,
            telemetry_opt_in: false,
            safety_gates_always_on: true,
        }
    }

    /// Opt in to gas/measure telemetry (returns the updated view). The safety
    /// gates are unaffected — they were and remain on.
    #[must_use]
    pub fn opt_in_telemetry(mut self) -> Self {
        self.telemetry_opt_in = true;
        self
    }

    /// Whether the daily burn has exceeded its cap (a drain warning).
    #[must_use]
    pub const fn over_daily_burn_cap(&self) -> bool {
        self.daily_burn_mist > self.daily_burn_cap_mist
    }

    /// The structural distinction: the safety gates are on regardless of whether
    /// telemetry is opted in. Always `true`.
    #[must_use]
    pub const fn gates_independent_of_telemetry(&self) -> bool {
        self.safety_gates_always_on
    }

    /// Whether the view holds any secret. Always `false` — every field is a
    /// redacted digest or a public count.
    #[must_use]
    pub const fn secrets_absent(&self) -> bool {
        true
    }

    /// Redacted, colorless status lines bounded by `rows`.
    #[must_use]
    pub fn render(&self, rows: u16) -> Vec<String> {
        let lines = vec![
            format!("mode_u8={}", self.mode.as_u8()),
            format!("trust_u8={}", self.trust.as_u8()),
            format!("policy_hash={}", self.policy_hash_redacted),
            format!("hot_wallet_balance={}", self.hot_wallet_balance_redacted),
            format!("daily_burn_mist={}", self.daily_burn_mist),
            format!("daily_burn_cap_mist={}", self.daily_burn_cap_mist),
            format!("over_daily_burn_cap={}", self.over_daily_burn_cap()),
            format!("quota_remaining={}", self.quota_remaining_u32),
            format!("max_gas_per_tx_mist={}", self.max_gas_per_tx_mist),
            format!(
                "suspicious_pattern_count={}",
                self.suspicious_pattern_count_u32
            ),
            format!("telemetry_opt_in={}", self.telemetry_opt_in),
            format!("safety_gates_always_on={}", self.safety_gates_always_on),
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
    use crate::repl::latency::p95_ms;

    fn view(mode: GasSponsorMode, trust: OfficialTrustDecision) -> GasStatusView {
        GasStatusView::new(
            mode,
            trust,
            &[0xAB; 32],
            &[0xCD; 32],
            1_000,
            5_000,
            900,
            800_000,
            0,
        )
    }

    #[test]
    fn hosted_self_none_modes() {
        let h = view(
            GasSponsorMode::Hosted,
            OfficialTrustDecision::OfficialTrusted,
        );
        assert_eq!(h.mode, GasSponsorMode::Hosted);
        assert_eq!(h.trust, OfficialTrustDecision::OfficialTrusted);
        let s = view(
            GasSponsorMode::SelfHosted,
            OfficialTrustDecision::SelfHostedOnly,
        );
        assert_eq!(s.mode, GasSponsorMode::SelfHosted);
        let n = view(GasSponsorMode::None, OfficialTrustDecision::LocalOnly);
        assert_eq!(n.mode, GasSponsorMode::None);
    }

    #[test]
    fn policy_hash_is_redacted() {
        let v = view(
            GasSponsorMode::Hosted,
            OfficialTrustDecision::OfficialTrusted,
        );
        assert_eq!(v.policy_hash_redacted.len(), 16);
        // The full 64-hex digest never appears in the render.
        assert!(!v.render(32).iter().any(|l| l.contains(&hex32(&[0xAB; 32]))));
    }

    #[test]
    fn balance_is_redacted_secrets_absent() {
        let v = view(
            GasSponsorMode::Hosted,
            OfficialTrustDecision::OfficialTrusted,
        );
        assert_eq!(v.hot_wallet_balance_redacted.len(), 16);
        assert!(v.secrets_absent());
    }

    #[test]
    fn suspicious_pattern_count_visible() {
        let mut v = view(
            GasSponsorMode::Hosted,
            OfficialTrustDecision::OfficialTrusted,
        );
        v.suspicious_pattern_count_u32 = 3;
        assert!(
            v.render(32)
                .iter()
                .any(|l| l.contains("suspicious_pattern_count=3"))
        );
    }

    #[test]
    fn telemetry_off_by_default_gates_always_on() {
        let v = view(
            GasSponsorMode::Hosted,
            OfficialTrustDecision::OfficialTrusted,
        );
        assert!(!v.telemetry_opt_in, "telemetry is opt-in, off by default");
        assert!(v.safety_gates_always_on, "safety gates are always-on");
        // Opting in to telemetry does not change the gates.
        let opted = v.opt_in_telemetry();
        assert!(opted.telemetry_opt_in);
        assert!(opted.gates_independent_of_telemetry());
    }

    #[test]
    fn over_daily_burn_cap_flag() {
        let mut v = view(
            GasSponsorMode::Hosted,
            OfficialTrustDecision::OfficialTrusted,
        );
        assert!(!v.over_daily_burn_cap());
        v.daily_burn_mist = 6_000; // > 5_000 cap
        assert!(v.over_daily_burn_cap());
    }

    #[test]
    fn gas_status_p95_within_100ms() {
        let v = view(
            GasSponsorMode::Hosted,
            OfficialTrustDecision::OfficialTrusted,
        );
        let mut samples = Vec::with_capacity(256);
        for _ in 0..256 {
            let t = std::time::Instant::now();
            let lines = v.render(32);
            std::hint::black_box(&lines);
            samples.push(t.elapsed().as_nanos() as u64);
        }
        let p95 = p95_ms(&samples) / 1_000_000;
        assert!(p95 <= 100, "gas status p95 {p95}ms exceeds 100ms budget");
    }
}
