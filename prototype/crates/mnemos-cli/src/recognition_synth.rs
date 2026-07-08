//! `recognition_synth` — SYNTHESIZE a deterministic checker from the recognition
//! anchors, then FALSIFY + CERTIFY it (the back-end to
//! [`crate::recognition_elicit`]'s front-end). This closes the Oracle-Bootstrap loop in a
//! TACIT domain: ~10 recognitions → an executable predicate → a 3-way verdict → the
//! ladder. **The customer never writes a rule** — the rule is INDUCED from their labels.
//!
//! ## The synthesis: an axis-aligned bounding-box conjunctive classifier (exact)
//! The classic float-free deterministic concept learner: build the per-dimension `[min,max]`
//! BOX over the POSITIVE anchors (`E⁺`), then check it EXCLUDES every NEGATIVE anchor (`E⁻`).
//! This is precisely the "entails the positives, EXCLUDES the negatives; generalizes from
//! a handful" criterion. The hypothesis class is restrictive (axis-aligned boxes), so when the
//! anchors are NOT box-separable (a negative falls inside the positive box) the checker is
//! UNSOUND and HONESTLY REFUSES (every verdict ⇒ `Escalate`) rather than guessing — the fenced
//! Bucket-B residue made concrete, never faked.
//!
//! ## The runtime verdict: 3-way ACCEPT / REJECT / ESCALATE (fail-closed)
//! For a new example `x` (float-free, L1 integer — the SAME metric as the active-query):
//! * `Accept`   — `x` is INSIDE the positive box (consistent with every good anchor).
//! * `Reject`   — `x` is closer to a known NEGATIVE than to the good box (evidence it is bad);
//!   a sound trustworthy negative (fail-closed).
//! * `Escalate` — otherwise (outside the box, no clear negative evidence = uncertain / OOD), or
//!   the checker is unsound. A provisional ACCEPT is "not-yet-falsified", an ESCALATE defers to
//!   a human — exactly "fail-closed-reject / provisional-accept = no-reward-hacking".
//!
//! ## The certification: the EXACT conformal false-accept-budget gate
//! Leave-one-out over the labeled anchors: synthesize on the rest, classify the held-out one,
//! and COUNT how many held-out NEGATIVES are wrongly `Accept`ed (`k` of `n` negatives).
//! `certified` ⟺ a box exists AND the EXACT Clopper-Pearson bound ([`crate::conformal`])
//! certifies `FAR ≤ α*_safe` at 95% confidence from `(k, n)` — so the "n≈10" labor is
//! enforced (n=2 negatives no longer certifies). The runtime stays float-free; the bound is
//! exact (no rounding), distribution-free + finite-sample.
//!
//! ## META-LAW (zero drift, zero LLM tokens, fast)
//! Everything is INTEGER (i64 features, i128 L1 via [`crate::recognition_elicit::l1_distance`])
//! with **no float, no clock, no RNG**; `synthesize`/`classify`/`certify_leave_one_out` are
//! TOTAL pure functions ⇒ byte-identical re-runs. The selection/verdict is pure geometry — an
//! LLM is never the judge (0 tokens). Per call O(A·D); microseconds. custody/funds HARD-LOCKED.
//!
//! ## ★ HONEST LOCK (never market past it)
//! The induced checker classifies over the customer's **GIVEN features** — it does NOT discover
//! the tacit essence. A certified `Accept` is admitted only when the EXACT Clopper-Pearson bound
//! ([`crate::conformal`]) certifies the held-out false-accept rate `FAR ≤ α*_safe` at 95% —
//! a bound on the anchor DISTRIBUTION, not arbitrary OOD inputs (those `Escalate`). When the
//! anchors are not box-separable the checker REFUSES (Escalate), never guesses. The residual tacit
//! quality stays the fenced Bucket-B residue.

use crate::recognition_elicit::{ElicitPool, Recognition, l1_distance};

/// The induced checker's 3-way verdict on a new example (the deterministic L0 judgment).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum InducedVerdict {
    /// Inside the positive box — consistent with every good anchor (a provisional accept).
    Accept,
    /// Closer to a known negative than to the good box — a sound trustworthy reject.
    Reject,
    /// Outside the box with no clear negative evidence (uncertain / OOD), or the checker is
    /// unsound — defer to a human (the R6-quarantine verdict; never auto-accumulates).
    Escalate,
}

/// An axis-aligned bounding box: per-dimension inclusive `[lo, hi]` bounds.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BoundingBox {
    lo: Vec<i64>,
    hi: Vec<i64>,
}

impl BoundingBox {
    /// The tightest box containing every positive feature vector; `None` if there are no
    /// positives or a ragged vector (fail-closed).
    #[must_use]
    fn from_positives(positives: &[Vec<i64>], dim: usize) -> Option<Self> {
        let first = positives.first()?;
        if first.len() != dim {
            return None;
        }
        let mut lo = first.clone();
        let mut hi = first.clone();
        for p in &positives[1..] {
            if p.len() != dim {
                return None;
            }
            for d in 0..dim {
                if p[d] < lo[d] {
                    lo[d] = p[d];
                }
                if p[d] > hi[d] {
                    hi[d] = p[d];
                }
            }
        }
        Some(Self { lo, hi })
    }

    /// Whether `x` lies inside the (closed) box.
    #[must_use]
    pub fn contains(&self, x: &[i64]) -> bool {
        x.len() == self.lo.len()
            && (0..self.lo.len()).all(|d| self.lo[d] <= x[d] && x[d] <= self.hi[d])
    }

    /// The L1 distance from `x` to the box (0 inside; the per-dimension overflow summed),
    /// i128-checked. `None` on a length mismatch or the (impossible) overflow.
    #[must_use]
    fn l1_to(&self, x: &[i64]) -> Option<i128> {
        if x.len() != self.lo.len() {
            return None;
        }
        let mut acc: i128 = 0;
        for ((xv, lov), hiv) in x.iter().zip(self.lo.iter()).zip(self.hi.iter()) {
            let xi = i128::from(*xv);
            let lo = i128::from(*lov);
            let hi = i128::from(*hiv);
            let over = if xi < lo {
                lo - xi
            } else if xi > hi {
                xi - hi
            } else {
                0
            };
            acc = acc.checked_add(over)?;
        }
        Some(acc)
    }

    /// The per-dimension lower bounds (for a legible render of the induced rule).
    #[must_use]
    pub fn lo(&self) -> &[i64] {
        &self.lo
    }

    /// The per-dimension upper bounds (for a legible render of the induced rule).
    #[must_use]
    pub fn hi(&self) -> &[i64] {
        &self.hi
    }
}

/// The synthesized checker: the positive box, the negative anchors (the reject evidence), and
/// whether it is SOUND (a box exists AND no negative falls inside it). An unsound checker
/// refuses (every verdict ⇒ `Escalate`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InducedChecker {
    bbox: Option<BoundingBox>,
    negatives: Vec<Vec<i64>>,
    sound: bool,
    dim: usize,
    n_positives: usize,
    n_negatives: usize,
}

impl InducedChecker {
    /// Whether the synthesis is SOUND (a positive box that excludes every negative). An unsound
    /// checker (no positives, or a negative inside the box) honestly refuses — `classify`
    /// returns `Escalate` for everything.
    #[must_use]
    pub fn is_sound(&self) -> bool {
        self.sound
    }

    /// The induced positive box (for a legible render), if one was formed.
    #[must_use]
    pub fn bbox(&self) -> Option<&BoundingBox> {
        self.bbox.as_ref()
    }

    /// The number of positive / negative anchors the checker was synthesized from.
    #[must_use]
    pub fn anchor_counts(&self) -> (usize, usize) {
        (self.n_positives, self.n_negatives)
    }

    /// The deterministic 3-way verdict for a new example `x` (float-free L1). An unsound
    /// checker, or a wrong-dimension `x`, fail-closes to `Escalate`.
    #[must_use]
    pub fn classify(&self, x: &[i64]) -> InducedVerdict {
        let Some(bbox) = self.bbox.as_ref() else {
            return InducedVerdict::Escalate;
        };
        if !self.sound || x.len() != self.dim {
            return InducedVerdict::Escalate;
        }
        if bbox.contains(x) {
            return InducedVerdict::Accept;
        }
        // outside the good box: REJECT only with negative evidence (nearer a known bad), else
        // ESCALATE (uncertain / out-of-distribution) — never guess.
        let Some(d_box) = bbox.l1_to(x) else {
            return InducedVerdict::Escalate;
        };
        let mut d_neg: Option<i128> = None;
        for neg in &self.negatives {
            if let Some(d) = l1_distance(x, neg) {
                d_neg = Some(match d_neg {
                    Some(m) if m <= d => m,
                    _ => d,
                });
            }
        }
        match d_neg {
            Some(dn) if dn < d_box => InducedVerdict::Reject,
            _ => InducedVerdict::Escalate,
        }
    }
}

/// Resolve the LABELED anchors to `(features, good)` pairs (the synthesis input). Compare/Triad
/// recognitions are NOT absolute labels, so they do not feed the box (honest: the box is induced
/// from the absolute good/bad judgments).
fn labeled(pool: &ElicitPool, recognitions: &[Recognition]) -> Vec<(Vec<i64>, bool)> {
    let mut out = Vec::new();
    for r in recognitions {
        if let Recognition::Label { example, good } = r {
            if let Some(e) = pool.examples().iter().find(|e| e.id == *example) {
                out.push((e.features.clone(), *good));
            }
        }
    }
    out
}

/// Build the [`InducedChecker`] from a `(features, good)` list + the dimension (the synthesis
/// core; LOO certification calls this on subsets).
#[must_use]
fn synthesize_from_labeled(labeled: &[(Vec<i64>, bool)], dim: usize) -> InducedChecker {
    let positives: Vec<Vec<i64>> = labeled
        .iter()
        .filter(|(_, g)| *g)
        .map(|(f, _)| f.clone())
        .collect();
    let negatives: Vec<Vec<i64>> = labeled
        .iter()
        .filter(|(_, g)| !*g)
        .map(|(f, _)| f.clone())
        .collect();
    let n_positives = positives.len();
    let n_negatives = negatives.len();
    let bbox = BoundingBox::from_positives(&positives, dim);
    // SOUND ⟺ a box exists AND no negative falls inside it (box-separable).
    let sound = bbox
        .as_ref()
        .is_some_and(|b| !negatives.iter().any(|n| b.contains(n)));
    InducedChecker {
        bbox,
        negatives,
        sound,
        dim,
        n_positives,
        n_negatives,
    }
}

/// SYNTHESIZE the deterministic checker from a recognition pool + its recognitions.
#[must_use]
pub fn synthesize(pool: &ElicitPool, recognitions: &[Recognition]) -> InducedChecker {
    synthesize_from_labeled(&labeled(pool, recognitions), pool.dim())
}

/// The held-out certification report: the leave-one-out tallies + the `certified` gate.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CertifyReport {
    /// Held-out NEGATIVES wrongly `Accept`ed (the dangerous error — must be 0 to certify).
    pub false_accepts: usize,
    /// Held-out POSITIVES correctly `Accept`ed (benign coverage; higher is better).
    pub coverage_hits: usize,
    /// Number of positive anchors (held out one at a time).
    pub n_positives: usize,
    /// Number of negative anchors (held out one at a time).
    pub n_negatives: usize,
    /// `true` ⟺ ZERO held-out false-accepts AND ≥1 negative seen AND ≥1 positive (a box exists).
    pub certified: bool,
}

impl CertifyReport {
    /// Whether the checker is CERTIFIED for accumulation. Only a certified
    /// checker's `Accept` may admit a permanent write.
    #[must_use]
    pub const fn is_certified(&self) -> bool {
        self.certified
    }
}

/// CERTIFY the checker by LEAVE-ONE-OUT over the labeled anchors (the held-out
/// zero-false-accept gate). Deterministic: synthesize on every anchor-except-one, classify the
/// held-out one, tally. `certified` ⟺ no held-out negative was `Accept`ed AND the anchor set
/// has both a positive (a box) and a negative (something to exclude).
#[must_use]
pub fn certify_leave_one_out(pool: &ElicitPool, recognitions: &[Recognition]) -> CertifyReport {
    let all = labeled(pool, recognitions);
    let dim = pool.dim();
    let n_positives = all.iter().filter(|(_, g)| *g).count();
    let n_negatives = all.iter().filter(|(_, g)| !*g).count();
    let mut false_accepts = 0usize;
    let mut coverage_hits = 0usize;
    for i in 0..all.len() {
        let mut rest: Vec<(Vec<i64>, bool)> = Vec::with_capacity(all.len().saturating_sub(1));
        for (j, item) in all.iter().enumerate() {
            if j != i {
                rest.push(item.clone());
            }
        }
        let checker = synthesize_from_labeled(&rest, dim);
        let (features, good) = &all[i];
        if checker.classify(features) == InducedVerdict::Accept {
            if *good {
                coverage_hits += 1;
            } else {
                false_accepts += 1;
            }
        }
    }
    // The QUANTITATIVE conformal gate REPLACES the qualitative zero-false-accept stand-in —
    // `certified` ⟺ a box exists (≥1 positive) AND the EXACT Clopper-Pearson bound certifies the
    // held-out false-accept rate `FAR ≤ α*_safe` at 95% (so n=2 negatives no longer certifies; the
    // "n≈10" labor is now enforced, float-free).
    let certified = n_positives >= 1
        && n_negatives >= 1
        && crate::conformal::certify_far_default(false_accepts as u64, n_negatives as u64);
    CertifyReport {
        false_accepts,
        coverage_hits,
        n_positives,
        n_negatives,
        certified,
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use super::*;
    use crate::recognition_elicit::Example;

    fn pool(examples: &[(u32, &[i64])]) -> ElicitPool {
        ElicitPool::new(
            examples
                .iter()
                .map(|(id, f)| Example {
                    id: *id,
                    features: f.to_vec(),
                })
                .collect(),
        )
        .expect("valid pool")
    }

    fn label(example: u32, good: bool) -> Recognition {
        Recognition::Label { example, good }
    }

    /// THE SYNTHESIS: the box is the tight bound over positives; a separable negative makes it
    /// SOUND; a new example inside the box is ACCEPTed, a far-from-good near-a-negative one is
    /// REJECTed, an out-of-distribution one ESCALATEs.
    #[test]
    fn box_classifier_accepts_rejects_escalates() {
        // positives cluster near the origin; one negative far away (separable).
        let p = pool(&[
            (0, &[0, 0]),
            (1, &[2, 1]),
            (2, &[1, 2]),
            (3, &[100, 100]), // the negative
        ]);
        let recs = vec![
            label(0, true),
            label(1, true),
            label(2, true),
            label(3, false),
        ];
        let checker = synthesize(&p, &recs);
        assert!(
            checker.is_sound(),
            "positives + a separable negative ⇒ sound"
        );
        // box = [0..2] x [0..2]
        assert_eq!(
            checker.classify(&[1, 1]),
            InducedVerdict::Accept,
            "inside the box"
        );
        assert_eq!(
            checker.classify(&[99, 99]),
            InducedVerdict::Reject,
            "next to the known negative ⇒ reject"
        );
        assert_eq!(
            checker.classify(&[0, 50]),
            InducedVerdict::Escalate,
            "outside the box, not near the negative ⇒ uncertain ⇒ escalate"
        );
    }

    /// HONEST REFUSAL: when the anchors are NOT box-separable (a negative inside the positive
    /// box), the checker is UNSOUND and refuses everything (Escalate) — never a false guess.
    #[test]
    fn non_separable_anchors_refuse_honestly() {
        // a negative sits INSIDE the convex span of the positives ⇒ the box engulfs it.
        let p = pool(&[(0, &[0, 0]), (1, &[10, 10]), (2, &[5, 5])]);
        let recs = vec![label(0, true), label(1, true), label(2, false)]; // (5,5) inside [0..10]^2
        let checker = synthesize(&p, &recs);
        assert!(!checker.is_sound(), "a negative inside the box ⇒ unsound");
        assert_eq!(
            checker.classify(&[1, 1]),
            InducedVerdict::Escalate,
            "an unsound checker refuses (escalates) everything"
        );
    }

    /// NO NEGATIVES: a box from positives only can ACCEPT inside + ESCALATE outside, but can
    /// never REJECT (no evidence of bad) — honest.
    #[test]
    fn positives_only_never_rejects() {
        let p = pool(&[(0, &[0, 0]), (1, &[4, 4])]);
        let recs = vec![label(0, true), label(1, true)];
        let checker = synthesize(&p, &recs);
        assert!(
            checker.is_sound(),
            "positives with no negative inside ⇒ sound box"
        );
        assert_eq!(checker.classify(&[2, 2]), InducedVerdict::Accept);
        assert_eq!(
            checker.classify(&[100, 100]),
            InducedVerdict::Escalate,
            "no negative evidence ⇒ escalate, never reject"
        );
    }

    /// THE CERTIFY GATE (conformal): a cleanly separable set with ENOUGH negatives certifies
    /// (0 held-out false-accepts over n=10 negatives ⇒ the exact Clopper-Pearson bound `FAR ≤
    /// α*_safe` @95% holds — the "n≈10" labor). Two negatives would NOT suffice (see below).
    #[test]
    fn leave_one_out_certifies_a_separable_set() {
        // 3 positives near the origin; 10 negatives far away (separable + enough to certify).
        let mut examples = vec![
            Example {
                id: 0,
                features: vec![0, 0],
            },
            Example {
                id: 1,
                features: vec![1, 1],
            },
            Example {
                id: 2,
                features: vec![2, 2],
            },
        ];
        let mut recs = vec![label(0, true), label(1, true), label(2, true)];
        for j in 0..10u32 {
            let id = 10 + j;
            examples.push(Example {
                id,
                features: vec![100 + i64::from(j), 100],
            });
            recs.push(label(id, false));
        }
        let p = ElicitPool::new(examples).expect("valid pool");
        let report = certify_leave_one_out(&p, &recs);
        assert_eq!(
            report.false_accepts, 0,
            "separable ⇒ no held-out false-accept"
        );
        assert_eq!(report.n_positives, 3);
        assert_eq!(report.n_negatives, 10);
        assert!(
            report.is_certified(),
            "0 false-accepts over n=10 negatives ⇒ conformally certified (FAR≤α*_safe @95%)"
        );
    }

    /// TIGHTENING: the SAME separable shape with only TWO negatives is NOT conformally
    /// certified — the held-out evidence is too thin to bound `FAR ≤ α*_safe` (the "n≈10").
    #[test]
    fn two_negatives_are_not_enough_to_certify() {
        let p = pool(&[
            (0, &[0, 0]),
            (1, &[1, 1]),
            (2, &[100, 100]),
            (3, &[101, 101]),
        ]);
        let recs = vec![
            label(0, true),
            label(1, true),
            label(2, false),
            label(3, false),
        ];
        let report = certify_leave_one_out(&p, &recs);
        assert_eq!(report.false_accepts, 0, "still separable (0 false-accepts)");
        assert_eq!(report.n_negatives, 2);
        assert!(
            !report.is_certified(),
            "n=2 negatives cannot conformally certify FAR≤α*_safe @95% (need ~10)"
        );
    }

    /// A checker with NO negatives is NOT certified (it has never seen a bad example — you
    /// cannot certify "zero false-accepts" vacuously).
    #[test]
    fn positives_only_is_not_certified() {
        let p = pool(&[(0, &[0, 0]), (1, &[1, 1])]);
        let recs = vec![label(0, true), label(1, true)];
        let report = certify_leave_one_out(&p, &recs);
        assert!(
            !report.is_certified(),
            "no negative ⇒ cannot certify (vacuous zero-false-accept)"
        );
    }

    /// A held-out false-accept BLOCKS certification: if a negative is near the positive box such
    /// that leaving out a positive lets the box (or distance) accept it, certification fails.
    #[test]
    fn a_held_out_false_accept_blocks_certification() {
        // a negative sandwiched so that LOO synthesis mis-accepts it.
        let p = pool(&[(0, &[0]), (1, &[10]), (2, &[5])]);
        // 0,10 positive; 5 negative — but [0..10] box contains 5 ⇒ unsound ⇒ but LOO:
        // leaving out the negative, box=[0..10] over {0,10}; classify 5 ⇒ inside ⇒ Accept ⇒ FA.
        let recs = vec![label(0, true), label(1, true), label(2, false)];
        let report = certify_leave_one_out(&p, &recs);
        assert!(
            report.false_accepts >= 1,
            "the engulfed negative is a held-out false-accept"
        );
        assert!(
            !report.is_certified(),
            "any false-accept blocks certification"
        );
    }

    /// DETERMINISM: synthesize + classify + certify are byte-stable across repeated calls.
    #[test]
    fn synthesis_is_deterministic() {
        let p = pool(&[(0, &[0, 0]), (1, &[3, 3]), (2, &[50, 50])]);
        let recs = vec![label(0, true), label(1, true), label(2, false)];
        let c1 = synthesize(&p, &recs);
        let c2 = synthesize(&p, &recs);
        assert_eq!(c1, c2, "same input ⇒ identical checker");
        assert_eq!(c1.classify(&[1, 1]), c2.classify(&[1, 1]));
        assert_eq!(
            certify_leave_one_out(&p, &recs),
            certify_leave_one_out(&p, &recs),
            "certification is deterministic"
        );
    }

    /// `l1_to` the box: 0 inside, the per-dimension overflow outside.
    #[test]
    fn bounding_box_distance_is_exact() {
        let b = BoundingBox::from_positives(&[vec![0, 0], vec![10, 10]], 2).expect("box");
        assert_eq!(b.l1_to(&[5, 5]), Some(0), "inside ⇒ 0");
        assert_eq!(b.l1_to(&[15, 10]), Some(5), "5 over on dim 0");
        assert_eq!(b.l1_to(&[-3, 13]), Some(6), "3 under + 3 over");
        assert!(b.contains(&[0, 10]));
        assert!(!b.contains(&[11, 5]));
    }
}
