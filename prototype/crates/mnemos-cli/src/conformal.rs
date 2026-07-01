//! `conformal` — O-3c: the EXACT, float-free Clopper-Pearson false-accept-budget certification
//! (master plan §6.5 "certify the false-accept budget" [THM: conformal — Vovk; Angelopoulos-Bates
//! 2021; RCPS/LTT]). The quantitative refinement of O-3b's qualitative zero-false-accept gate:
//! given `k` held-out false-accepts in `n` trials, decide whether the false-accept RATE is
//! bounded `FAR ≤ α_target` at confidence `1−δ`, distribution-free + finite-sample.
//!
//! ## The one identity that makes it float-free + EXACT (the ultrathink crux)
//! The Clopper-Pearson upper bound `p_u(k,n,δ)` is generally IRRATIONAL (e.g. `1−δ^{1/n}`), so a
//! naive computation needs floats. But the DECISION `p_u ≤ α_target` does NOT need `p_u`: because
//! the binomial lower tail `F(k;n,p) = Σ_{i=0}^{k} C(n,i) p^i (1−p)^{n−i}` is monotone DECREASING
//! in `p`, and `p_u` is the `p` where `F = δ`,
//!
//!   `CERTIFY (FAR ≤ α_target @ 1−δ)  ⟺  p_u ≤ α_target  ⟺  F(k;n,α_target) ≤ δ`.
//!
//! With `α_target = a/A` and `δ = d/D` RATIONAL, `F = N / A^n` where
//! `N = Σ_{i=0}^{k} C(n,i) a^i (A−a)^{n−i}` is an INTEGER, so the whole decision is the EXACT
//! big-integer inequality **`N·D ≤ d·A^n`** — no float, no irrational `p_u`, zero drift. (Sanity:
//! `k=0,n=10,α=27/100,δ=5/100` ⇒ `F = 0.73^10 = 0.043 ≤ 0.05` ⇒ certify; `n=9 ⇒ 0.0589 > 0.05`
//! ⇒ no — the §6.5 "n≈10" boundary, reproduced exactly.)
//!
//! ## META-LAW (zero drift, zero LLM tokens, no new crate)
//! A minimal hand-rolled [`BigUint`] (u64 limbs; add / mul / cmp / pow — **no `num-bigint` dep, no
//! `Cargo.lock` relock**) computes `N`, `A^n`, and the comparison EXACTLY. Pure, deterministic, no
//! float / clock / RNG. Cross-checked against `u128` for small values + the §6.5 table, so the
//! carry logic is proven (a wrong certification would be a false-accept-budget breach — the very
//! property this protects). custody/funds HARD-LOCKED.
//!
//! ## ★ HONEST LOCK (the §3-LOCK boundary — never market past it)
//! The bound is EXACT (no float rounding) but it is a bound on the held-out false-accept RATE of
//! the synthesized checker over the **anchor distribution** — distribution-free + finite-sample
//! (Clopper-Pearson is exact for the binomial), NOT a guarantee on arbitrary out-of-distribution
//! inputs (those are handled by the checker's `Escalate`, not this bound). It certifies that, on
//! the recognition distribution, `P(FAR ≤ α*_safe) ≥ 1−δ`; it never claims the checker is correct
//! everywhere. The residual (OOD, the tacit standard) stays the fenced Bucket-B residue (§6.7).

use std::cmp::Ordering;

/// The §6.5 phase-transition threshold `α*_safe ≈ 0.27`: a hard domain is globally stable below
/// it. The certification bounds the false-accept rate at or below this. (Owner-tunable here.)
pub const ALPHA_SAFE_NUM: u64 = 27;
/// Denominator of [`ALPHA_SAFE_NUM`] (`α*_safe = 27/100`).
pub const ALPHA_SAFE_DEN: u64 = 100;
/// The certification confidence error `δ = 0.05` (a 95% upper confidence bound).
pub const DELTA_NUM: u64 = 5;
/// Denominator of [`DELTA_NUM`] (`δ = 5/100`).
pub const DELTA_DEN: u64 = 100;
/// The maximum number of held-out trials the exact computation accepts (a defensive bound; a
/// larger `n` than any realistic recognition set fail-closes to NOT-certified, the safe side).
pub const N_BOUND: u64 = 1024;

/// A minimal arbitrary-precision unsigned integer: little-endian base-`2^64` `u64` limbs,
/// NORMALIZED (no trailing zero limbs; zero = empty). Just enough for the exact binomial-tail
/// inequality — pure, deterministic, float-free. No `num-bigint` dependency.
#[derive(Clone, Debug, PartialEq, Eq)]
struct BigUint {
    limbs: Vec<u64>,
}

impl BigUint {
    fn zero() -> Self {
        Self { limbs: Vec::new() }
    }

    fn from_u64(v: u64) -> Self {
        if v == 0 {
            Self::zero()
        } else {
            Self { limbs: vec![v] }
        }
    }

    fn is_zero(&self) -> bool {
        self.limbs.is_empty()
    }

    fn normalize(&mut self) {
        while self.limbs.last() == Some(&0) {
            self.limbs.pop();
        }
    }

    /// Schoolbook addition (carry in `u128`, cannot overflow).
    fn add(&self, other: &Self) -> Self {
        let n = self.limbs.len().max(other.limbs.len());
        let mut out = Vec::with_capacity(n + 1);
        let mut carry: u128 = 0;
        for i in 0..n {
            let a = u128::from(self.limbs.get(i).copied().unwrap_or(0));
            let b = u128::from(other.limbs.get(i).copied().unwrap_or(0));
            let sum = a + b + carry;
            out.push(sum as u64);
            carry = sum >> 64;
        }
        if carry > 0 {
            out.push(carry as u64);
        }
        let mut r = Self { limbs: out };
        r.normalize();
        r
    }

    /// Schoolbook multiplication. Each partial `a*b + acc + carry` fits in `u128`
    /// (`(2^64−1)^2 + 2·(2^64−1) = 2^128 − 1`), so there is no overflow; the `+1` slack limb +
    /// the `idx < out.len()` guard make the carry walk panic-free.
    fn mul(&self, other: &Self) -> Self {
        if self.is_zero() || other.is_zero() {
            return Self::zero();
        }
        let mut out = vec![0u64; self.limbs.len() + other.limbs.len() + 1];
        for (i, &a) in self.limbs.iter().enumerate() {
            let mut carry: u128 = 0;
            for (j, &b) in other.limbs.iter().enumerate() {
                let cur = u128::from(out[i + j]) + u128::from(a) * u128::from(b) + carry;
                out[i + j] = cur as u64;
                carry = cur >> 64;
            }
            let mut idx = i + other.limbs.len();
            while carry > 0 && idx < out.len() {
                let cur = u128::from(out[idx]) + carry;
                out[idx] = cur as u64;
                carry = cur >> 64;
                idx += 1;
            }
        }
        let mut r = Self { limbs: out };
        r.normalize();
        r
    }

    fn mul_u64(&self, v: u64) -> Self {
        self.mul(&Self::from_u64(v))
    }

    /// Magnitude comparison (normalized ⇒ longer-vector wins; else MSB-first lexicographic).
    fn cmp(&self, other: &Self) -> Ordering {
        match self.limbs.len().cmp(&other.limbs.len()) {
            Ordering::Equal => {
                for i in (0..self.limbs.len()).rev() {
                    match self.limbs[i].cmp(&other.limbs[i]) {
                        Ordering::Equal => {}
                        non_eq => return non_eq,
                    }
                }
                Ordering::Equal
            }
            non_eq => non_eq,
        }
    }

    /// `self^exp` by square-and-multiply.
    fn pow_u64(&self, exp: u64) -> Self {
        let mut result = Self::from_u64(1);
        let mut base = self.clone();
        let mut e = exp;
        while e > 0 {
            if e & 1 == 1 {
                result = result.mul(&base);
            }
            e >>= 1;
            if e > 0 {
                base = base.mul(&base);
            }
        }
        result
    }
}

/// `C(n, 0..=min(k,n))` via DIVISION-FREE Pascal's triangle (additions only — no big-integer
/// division), keeping at most `k+1` entries per row (so it is `O(n·k)`, not `O(n^2)`).
fn binom_upto(n: u64, k: u64) -> Vec<BigUint> {
    let kk = k.min(n);
    let mut prev = vec![BigUint::from_u64(1)]; // row r=0: [C(0,0)=1]
    for r in 1..=n {
        let width = ((kk + 1).min(r + 1)) as usize;
        let mut cur = Vec::with_capacity(width);
        for j in 0..width {
            if j == 0 {
                cur.push(BigUint::from_u64(1)); // C(r,0) = 1
            } else {
                // C(r,j) = C(r-1,j-1) + C(r-1,j); C(r-1,j) = 0 when j > r-1 (absent in `prev`).
                let left = prev[j - 1].clone();
                let right = prev.get(j).cloned().unwrap_or_else(BigUint::zero);
                cur.push(left.add(&right));
            }
        }
        prev = cur;
    }
    prev
}

/// EXACT Clopper-Pearson certification: does observing `k` false-accepts in `n` held-out trials
/// certify `FAR ≤ α_target` (`= alpha_num/alpha_den`) at confidence `1 − δ` (`δ = delta_num/
/// delta_den`)? Returns `true` iff the exact integer inequality `N·D ≤ d·A^n` holds, where
/// `N = Σ_{i=0}^{k} C(n,i) a^i (A−a)^{n−i}` (the binomial lower tail `F(k;n,α)` scaled by `A^n`).
/// Fail-closed (NOT certified) on a malformed input: `α ∉ (0,1)`, `δ ∉ (0,1)`, `k > n`, or
/// `n > N_BOUND`. No float, no irrational upper bound — the decision is an exact big-integer
/// comparison (zero drift).
#[must_use]
pub fn certify_far_bound(
    k: u64,
    n: u64,
    alpha_num: u64,
    alpha_den: u64,
    delta_num: u64,
    delta_den: u64,
) -> bool {
    // 0 < α < 1, 0 < δ < 1, k ≤ n, n bounded — else fail-closed.
    if alpha_num == 0
        || alpha_num >= alpha_den
        || delta_num == 0
        || delta_num >= delta_den
        || k > n
        || n > N_BOUND
    {
        return false;
    }
    let a = BigUint::from_u64(alpha_num);
    let b = BigUint::from_u64(alpha_den - alpha_num); // A − a
    let big_a = BigUint::from_u64(alpha_den);
    let binom = binom_upto(n, k);
    // N = Σ_{i=0}^{k} C(n,i) · a^i · b^{n−i}
    let mut nsum = BigUint::zero();
    for (i, c) in binom.iter().enumerate() {
        let iu = i as u64;
        if iu > k {
            break;
        }
        let term = c.mul(&a.pow_u64(iu)).mul(&b.pow_u64(n - iu));
        nsum = nsum.add(&term);
    }
    let an = big_a.pow_u64(n); // A^n
    // CERTIFY ⟺ F(k;n,α) ≤ δ ⟺ N/A^n ≤ d/D ⟺ N·D ≤ d·A^n.
    let lhs = nsum.mul_u64(delta_den);
    let rhs = an.mul_u64(delta_num);
    lhs.cmp(&rhs) != Ordering::Greater
}

/// The default certification at the §6.5 budget (`FAR ≤ α*_safe = 27/100` @ 95%).
#[must_use]
pub fn certify_far_default(k: u64, n: u64) -> bool {
    certify_far_bound(k, n, ALPHA_SAFE_NUM, ALPHA_SAFE_DEN, DELTA_NUM, DELTA_DEN)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use super::*;

    fn from_u128(mut v: u128) -> BigUint {
        let mut limbs = Vec::new();
        while v > 0 {
            limbs.push(v as u64);
            v >>= 64;
        }
        BigUint { limbs }
    }

    /// BigUint add / mul / cmp / pow are EXACT — cross-checked against u128 over a grid of values
    /// (the carry logic is the safety-critical part: a wrong product ⇒ a wrong certification).
    #[test]
    fn biguint_matches_u128_on_small_values() {
        let samples: [u128; 7] = [
            0,
            1,
            2,
            1_000_000_007,
            u64::MAX as u128,
            (1u128 << 64) - 1,
            3,
        ];
        for &x in &samples {
            for &y in &samples {
                assert_eq!(
                    BigUint::from_u64((x & u128::from(u64::MAX)) as u64).add(&from_u128(y)),
                    from_u128((x & u128::from(u64::MAX)) + y),
                    "add {x}+{y}"
                );
                // mul: keep operands small enough that the product fits u128 for the check.
                let xs = x % 4_000_000_000;
                let ys = y % 4_000_000_000;
                assert_eq!(
                    from_u128(xs).mul(&from_u128(ys)),
                    from_u128(xs * ys),
                    "mul {xs}*{ys}"
                );
                assert_eq!(
                    from_u128(xs).cmp(&from_u128(ys)),
                    xs.cmp(&ys),
                    "cmp {xs} {ys}"
                );
            }
        }
        // a multi-limb product: (2^64-1)^2 = 2^128 - 2^65 + 1.
        let big = BigUint::from_u64(u64::MAX).mul(&BigUint::from_u64(u64::MAX));
        assert_eq!(
            big,
            from_u128((u128::from(u64::MAX)) * (u128::from(u64::MAX)))
        );
        // pow: 7^10 fits u128.
        assert_eq!(BigUint::from_u64(7).pow_u64(10), from_u128(7u128.pow(10)));
        assert_eq!(BigUint::from_u64(2).pow_u64(0), BigUint::from_u64(1));
    }

    /// Pascal row is exact (C(n,i) cross-checked).
    #[test]
    fn binom_is_exact() {
        let row = binom_upto(10, 10);
        let expect = [1u64, 10, 45, 120, 210, 252, 210, 120, 45, 10, 1];
        for (i, e) in expect.iter().enumerate() {
            assert_eq!(row[i], BigUint::from_u64(*e), "C(10,{i})");
        }
        // k-truncation keeps only the first k+1 entries.
        let trunc = binom_upto(100, 2);
        assert_eq!(trunc.len(), 3);
        assert_eq!(trunc[0], BigUint::from_u64(1));
        assert_eq!(trunc[1], BigUint::from_u64(100));
        assert_eq!(trunc[2], BigUint::from_u64(100 * 99 / 2)); // 4950
    }

    /// THE §6.5 TABLE, reproduced EXACTLY (α*_safe = 27/100 @ 95%): 0 false-accepts in 10 held-out
    /// negatives certifies (`0.73^10 = 0.043 ≤ 0.05`); 9 does not (`0.0589 > 0.05`) — the "n≈10"
    /// boundary. A single false-accept needs far more evidence.
    #[test]
    fn clopper_pearson_reproduces_the_6_5_table() {
        assert!(
            certify_far_default(0, 10),
            "0/10 ⇒ FAR≤0.27 @95% (0.73^10=0.043≤0.05)"
        );
        assert!(
            !certify_far_default(0, 9),
            "0/9 ⇒ not yet (0.73^9=0.0589>0.05)"
        );
        assert!(!certify_far_default(0, 5), "0/5 ⇒ far from it (0.207)");
        assert!(certify_far_default(0, 20), "0/20 ⇒ comfortably certified");
        assert!(
            !certify_far_default(1, 10),
            "1/10 ⇒ not certified (F=0.202)"
        );
        assert!(
            certify_far_default(1, 30),
            "1 false-accept needs ~30 trials to certify"
        );
    }

    /// Monotone: more clean trials only help (fixed k); more false-accepts only hurt (fixed n).
    #[test]
    fn certification_is_monotone() {
        // fixed k=0: once certified at n, certified for all larger n.
        let mut first = None;
        for n in 1..=40 {
            if certify_far_default(0, n) {
                first = Some(n);
                break;
            }
        }
        let n0 = first.expect("k=0 certifies eventually");
        assert_eq!(n0, 10, "the k=0 boundary is exactly n=10");
        for n in n0..=60 {
            assert!(certify_far_default(0, n), "monotone in n at k=0 (n={n})");
        }
        // fixed n: a false-accept can only un-certify (never the reverse).
        for n in 1..=40 {
            if !certify_far_default(0, n) {
                assert!(
                    !certify_far_default(1, n),
                    "k=1 is never easier than k=0 (n={n})"
                );
            }
        }
    }

    /// Fail-closed: malformed inputs never certify.
    #[test]
    fn malformed_inputs_fail_closed() {
        assert!(!certify_far_bound(0, 10, 0, 100, 5, 100), "α=0 invalid");
        assert!(!certify_far_bound(0, 10, 100, 100, 5, 100), "α=1 invalid");
        assert!(!certify_far_bound(0, 10, 27, 100, 0, 100), "δ=0 invalid");
        assert!(!certify_far_bound(0, 10, 27, 100, 100, 100), "δ=1 invalid");
        assert!(!certify_far_bound(11, 10, 27, 100, 5, 100), "k>n invalid");
        assert!(
            !certify_far_bound(0, N_BOUND + 1, 27, 100, 5, 100),
            "n>bound fail-closed"
        );
    }

    /// A tighter α_target needs more evidence (the budget is real): FAR≤0.10 @95% with 0
    /// false-accepts needs many more trials than FAR≤0.27.
    #[test]
    fn a_tighter_budget_demands_more_evidence() {
        // 0.90^n ≤ 0.05 ⇒ n ≥ 29 (0.90^28=0.0523, 0.90^29=0.0471).
        assert!(
            !certify_far_bound(0, 10, 10, 100, 5, 100),
            "FAR≤0.10 not met by 0/10"
        );
        assert!(
            certify_far_bound(0, 29, 10, 100, 5, 100),
            "FAR≤0.10 met by 0/29"
        );
    }
}
