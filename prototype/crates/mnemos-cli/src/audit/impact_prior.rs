//! Audit impact prior.
//!
//! Suspected paths are ranked by plausible impact, not by how scary a diff looks.
//! [`ImpactPrior`] is the record of the per-axis impact estimate (funds at
//! risk, auth bypass, accounting drift, liveness/DoS, exploitability) minus the
//! false-positive risk. A path with no impact axis set scores zero (deny — it is
//! not worth a search slot); a high false-positive risk pulls the score down so a
//! "looks scary" pattern never outranks a real-impact path. Ranking is
//! deterministic — sorted by score, ties broken by ascending index. This
//! module performs no live action.
//!
//! Reuse (no reinvention): the reward-firewall philosophy of the reward
//! pipeline — impact is evidence-weighted, never self-asserted.

/// The per-axis impact prior for a suspected audit path. Each field is in
/// basis points (0..=10000).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ImpactPrior {
    /// Plausible funds-at-risk impact.
    pub funds_at_risk_bps: u16,
    /// Authorization-bypass impact.
    pub auth_bypass_bps: u16,
    /// Accounting-drift impact.
    pub accounting_drift_bps: u16,
    /// Liveness / DoS impact.
    pub liveness_dos_bps: u16,
    /// Exploitability.
    pub exploitability_bps: u16,
    /// False-positive risk (subtracts from the score).
    pub false_positive_risk_bps: u16,
}

/// The score at or above which a path is treated as high impact.
pub const HIGH_IMPACT_THRESHOLD: u32 = 20_000;

impl ImpactPrior {
    /// The composite priority score. Real-impact axes are weighted up (funds ×4,
    /// auth ×3, accounting ×2, exploitability ×2, liveness ×1) and the
    /// false-positive risk is weighted down (×2), clamped to `0`. A "looks scary"
    /// path (high false-positive risk, low real impact) scores low.
    #[must_use]
    pub const fn score(&self) -> u32 {
        let positive = (self.funds_at_risk_bps as u32)
            .saturating_mul(4)
            .saturating_add((self.auth_bypass_bps as u32).saturating_mul(3))
            .saturating_add((self.accounting_drift_bps as u32).saturating_mul(2))
            .saturating_add(self.liveness_dos_bps as u32)
            .saturating_add((self.exploitability_bps as u32).saturating_mul(2));
        let penalty = (self.false_positive_risk_bps as u32).saturating_mul(2);
        positive.saturating_sub(penalty)
    }

    /// Whether any real-impact axis is non-zero (ignoring false-positive risk).
    #[must_use]
    pub const fn has_impact(&self) -> bool {
        self.funds_at_risk_bps != 0
            || self.auth_bypass_bps != 0
            || self.accounting_drift_bps != 0
            || self.liveness_dos_bps != 0
            || self.exploitability_bps != 0
    }

    /// Whether this path clears the high-impact threshold (a non-trivial real
    /// impact that survives its false-positive penalty).
    #[must_use]
    pub const fn is_high_impact(&self) -> bool {
        self.has_impact() && self.score() >= HIGH_IMPACT_THRESHOLD
    }
}

/// Deterministically rank `priors` by score (descending), tie-broken by ascending
/// index. Zero-impact paths are dropped — a no-impact path is never ranked.
#[must_use]
pub fn rank_top_k(priors: &[ImpactPrior], k: usize) -> Vec<usize> {
    let mut scored: Vec<(usize, u32)> = priors
        .iter()
        .enumerate()
        .filter(|(_, p)| p.has_impact())
        .map(|(i, p)| (i, p.score()))
        .collect();
    scored.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(&b.0)));
    scored.into_iter().take(k).map(|(i, _)| i).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn p(funds: u16, auth: u16, acct: u16, live: u16, exploit: u16, fp: u16) -> ImpactPrior {
        ImpactPrior {
            funds_at_risk_bps: funds,
            auth_bypass_bps: auth,
            accounting_drift_bps: acct,
            liveness_dos_bps: live,
            exploitability_bps: exploit,
            false_positive_risk_bps: fp,
        }
    }

    #[test]
    fn high_impact() {
        // funds 9000*4 + exploit 5000*2 = 46000 >= 20000
        assert!(p(9000, 0, 0, 0, 5000, 0).is_high_impact());
    }

    #[test]
    fn low_impact() {
        assert!(!p(100, 0, 0, 0, 0, 0).is_high_impact());
    }

    #[test]
    fn false_positive_risk_lowers_score() {
        let clean = p(5000, 0, 0, 0, 0, 0);
        let scary = p(5000, 0, 0, 0, 0, 9000);
        assert!(
            scary.score() < clean.score(),
            "high FP risk must lower the score"
        );
    }

    #[test]
    fn liveness_only_not_high() {
        let l = p(0, 0, 0, 8000, 0, 0);
        assert!(l.has_impact());
        // liveness weight is 1 => 8000 < 20000
        assert!(!l.is_high_impact());
    }

    #[test]
    fn no_impact_deny() {
        let n = p(0, 0, 0, 0, 0, 5000);
        assert!(!n.has_impact());
        assert_eq!(n.score(), 0);
        assert!(rank_top_k(&[n], 5).is_empty());
    }

    #[test]
    fn top_k_deterministic() {
        let a = p(9000, 0, 0, 0, 0, 0); // 36000
        let b = p(0, 9000, 0, 0, 0, 0); // 27000
        let c = p(0, 0, 0, 0, 0, 0); // no impact -> dropped
        let ranked = rank_top_k(&[a, b, c], 2);
        assert_eq!(ranked, vec![0, 1]);
        // same input always yields the same ranking
        assert_eq!(rank_top_k(&[a, b, c], 2), ranked);
    }
}
