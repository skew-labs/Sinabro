//! `recognition_elicit` — O-3: the recognition-ELICITATION engine (the Oracle Bootstrap
//! customer-anchor front-end; master plan §6.2 Pillar 2 steps 1-2 + §6.9 "recognition-
//! elicitation UX (label/compare/triad) + active-query"). The DETERMINISTIC, ZERO-LLM-TOKEN,
//! zero-drift surface that elicits a customer's TACIT standard as ~10 typed RECOGNITION
//! anchors, choosing each question by an ACTIVE-QUERY criterion — so a downstream synthesis
//! step (Pillar 2 step 3+, deferred) can induce a deterministic checker from a handful of
//! recognitions instead of a hand-written rule. **The customer never writes a rule** (§6.2):
//! they only RECOGNIZE (label / compare / pick-the-odd-of-three), because humans can recognize
//! quality they cannot articulate [Polanyi; Christiano 2017].
//!
//! ## Why this is the right shape (the META-LAW, made physical)
//! * **ZERO external LLM tokens.** The question-SELECTION is pure geometry — an LLM never
//!   decides "what to ask next". The only intelligence input is the customer's recognition;
//!   the system's selection is a deterministic function. The token cost is *exactly zero*.
//! * **Zero drift, by mathematics.** Everything is INTEGER (i64 features, i128 distance),
//!   `checked_*` (fail-closed on the impossible overflow), with **no float, no clock, no RNG**.
//!   `next_label_query` is a TOTAL pure function with a total tie-break (lowest id) ⇒ the same
//!   `(pool, recognitions)` always yields the byte-identical next question + anchor-set hash.
//! * **Active-query = a THEOREM, not a heuristic.** The next question is the unseen example
//!   FARTHEST from the already-seen set (greedy farthest-first / k-center), a **2-approximation
//!   to optimal coverage** [THM: Gonzalez 1985]. The metric is **L1 (Manhattan)** — a true
//!   metric (so the 2-approx holds) that is OVERFLOW-PROOF in i128 for any realistic dimension
//!   (unlike squared-L2, which is not a metric and can overflow). The k-center RADIUS (the
//!   chosen query's min-distance) shrinks monotonically as anchors accumulate ⇒ a deterministic
//!   "coverage achieved / when have we asked enough" signal (the §6.5 "O(10) anchors").
//! * **Fast, because it is the visible surface.** Per call O(N·L·D) integer ops over the pool
//!   (microseconds for any human-scale pool); no allocation in the hot loop; no network round
//!   trip (zero LLM). The UX is instant.
//!
//! ## ★ HONEST LOCK (the §3-LOCK boundary — never market past it)
//! This engine elicits the customer's recognition over **EXPLICIT, GIVEN features** and selects
//! questions to MAXIMIZE feature-space coverage. It does **NOT** discover the tacit essence,
//! and it does **NOT** yet render a verdict: it produces an OWNED, content-addressed ANCHOR
//! SET (+ the customer's named axes) that is INPUT CAPITAL for synthesis (Pillar 2 step 3+,
//! deferred to O-3b). Discovering features / synthesizing the checker / certifying the
//! false-accept budget are the fenced follow-ons; the residual tacit quality stays the fenced
//! Bucket-B residue (§6.7), never sold as a deterministic guarantee. custody/funds HARD-LOCKED.

/// One example in the pool: a stable `id` + an EXPLICIT integer feature vector (NO floats —
/// determinism, like the reconcile oracle's minor units). Every example in a pool must share
/// the same feature dimension (validated at [`ElicitPool::new`]); the features are GIVEN (the
/// honest boundary — the engine elicits judgments OVER them, it does not discover them).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Example {
    /// The stable example id (unique within a pool).
    pub id: u32,
    /// The integer feature vector (fixed dimension across the pool).
    pub features: Vec<i64>,
}

/// One RECOGNITION the customer supplies — never a rule, only a judgment (§6.2 step 1-2).
/// The three modalities are the §6.9 "label / compare / triad".
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Recognition {
    /// label: this example is good (positive) or bad (negative) — an absolute judgment.
    Label {
        /// The judged example id.
        example: u32,
        /// `true` = good (a positive anchor), `false` = bad (a negative anchor / `E⁻`).
        good: bool,
    },
    /// compare: `better` is preferred over `worse` — a pairwise judgment (easier than an
    /// absolute label, and often more reliable; [Christiano 2017]).
    Compare {
        /// The preferred example id.
        better: u32,
        /// The dispreferred example id.
        worse: u32,
    },
    /// triad: of three examples, `odd` is the one that DIFFERS, and the customer NAMES the
    /// axis on which it differs — the Kelly repertory-grid construct that surfaces the
    /// customer's implicit dimension [Kelly 1955; Gaines-Shaw 1988].
    Triad {
        /// First example id.
        a: u32,
        /// Second example id.
        b: u32,
        /// Third example id.
        c: u32,
        /// Which of `a`/`b`/`c` differs (must be one of them).
        odd: u32,
        /// The customer's NAME for the distinguishing axis (bounded, single-line).
        axis: String,
    },
}

impl Recognition {
    /// Every example id this recognition references (so the engine knows which examples the
    /// customer has already SEEN — those are excluded from the next-question candidates, to
    /// spread questions across the feature space rather than re-asking).
    fn referenced_ids(&self) -> Vec<u32> {
        match self {
            Recognition::Label { example, .. } => vec![*example],
            Recognition::Compare { better, worse } => vec![*better, *worse],
            Recognition::Triad { a, b, c, .. } => vec![*a, *b, *c],
        }
    }
}

/// A validated pool of examples (the search space the active-query selects from). Construction
/// is fail-closed: an empty pool, a zero-dimension, a ragged dimension, or duplicate ids all
/// yield `None` (no malformed pool ever reaches the deterministic selector).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ElicitPool {
    examples: Vec<Example>,
    dim: usize,
}

impl ElicitPool {
    /// Validate + construct. Fail-closed: empty pool / zero-dim / ragged feature lengths /
    /// duplicate ids ⇒ `None`.
    #[must_use]
    pub fn new(examples: Vec<Example>) -> Option<Self> {
        let dim = examples.first()?.features.len();
        if dim == 0 {
            return None;
        }
        let mut seen_ids = std::collections::BTreeSet::new();
        for e in &examples {
            if e.features.len() != dim {
                return None; // ragged — a drift hazard, fail-closed
            }
            if !seen_ids.insert(e.id) {
                return None; // duplicate id — ambiguous, fail-closed
            }
        }
        Some(Self { examples, dim })
    }

    /// The number of examples in the pool.
    #[must_use]
    pub fn len(&self) -> usize {
        self.examples.len()
    }

    /// Whether the pool is empty (never true for a constructed pool — `new` rejects empty).
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.examples.is_empty()
    }

    /// The (uniform) feature dimension.
    #[must_use]
    pub fn dim(&self) -> usize {
        self.dim
    }

    /// The examples (in their construction order).
    #[must_use]
    pub fn examples(&self) -> &[Example] {
        &self.examples
    }

    fn get(&self, id: u32) -> Option<&Example> {
        self.examples.iter().find(|e| e.id == id)
    }
}

/// The active-query result: either the next question to ASK, or `Saturated` (every example has
/// been seen — elicitation is complete).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NextQuery {
    /// Ask the customer to LABEL this example next — it is the most-informative unseen example
    /// (the farthest-first / k-center pick), carrying its `marginal_gain` (the min-distance to
    /// the seen set, i.e. the k-center radius / coverage gain this question closes).
    Ask {
        /// The example id to ask about next.
        example: u32,
        /// The marginal coverage gain (min L1 distance to the already-seen set; for the very
        /// first question it is the distance to the pool centroid — the extremity).
        marginal_gain: i128,
    },
    /// Every example has already been referenced by a recognition (or the pool was exhausted)
    /// — there is nothing informative left to ask.
    Saturated,
}

/// The L1 (Manhattan) distance between two equal-length integer feature vectors, accumulated in
/// i128 and CHECKED (fail-closed `None` on the — practically impossible — overflow, or on a
/// length mismatch). L1 is a true metric (so the farthest-first 2-approx holds) and is
/// overflow-proof in i128 for any realistic dimension. `pub(crate)` so the O-3b synthesis
/// ([`crate::recognition_synth`]) reuses the SAME metric the active-query uses (no second metric).
#[must_use]
pub(crate) fn l1_distance(a: &[i64], b: &[i64]) -> Option<i128> {
    if a.len() != b.len() {
        return None;
    }
    let mut acc: i128 = 0;
    for (x, y) in a.iter().zip(b.iter()) {
        // i64 - i64 widened to i128 cannot overflow; |.| is non-negative.
        let d = (i128::from(*x) - i128::from(*y)).abs();
        acc = acc.checked_add(d)?;
    }
    Some(acc)
}

/// The componentwise INTEGER centroid of the pool (each dimension = Σ / N, integer division —
/// deterministic). Used only to seed the very first question (the most EXTREME example, i.e.
/// the one farthest from the center, is the informative cold-start pick). Returns `None` on the
/// impossible overflow.
fn centroid(pool: &ElicitPool) -> Option<Vec<i128>> {
    let n = pool.examples.len() as i128;
    let mut sums = vec![0i128; pool.dim];
    for e in &pool.examples {
        for (s, f) in sums.iter_mut().zip(e.features.iter()) {
            *s = s.checked_add(i128::from(*f))?;
        }
    }
    Some(sums.into_iter().map(|s| s / n).collect())
}

/// L1 distance from an integer example to an i128 centroid (the seed metric).
fn l1_to_centroid(features: &[i64], centroid: &[i128]) -> Option<i128> {
    if features.len() != centroid.len() {
        return None;
    }
    let mut acc: i128 = 0;
    for (x, c) in features.iter().zip(centroid.iter()) {
        let d = (i128::from(*x) - *c).abs();
        acc = acc.checked_add(d)?;
    }
    Some(acc)
}

/// The set of example ids the customer has already SEEN (referenced by any recognition).
fn seen_ids(recognitions: &[Recognition]) -> std::collections::BTreeSet<u32> {
    let mut set = std::collections::BTreeSet::new();
    for r in recognitions {
        for id in r.referenced_ids() {
            set.insert(id);
        }
    }
    set
}

/// The DETERMINISTIC active-query: the next example the customer should LABEL. Greedy
/// farthest-first (k-center): among the UNSEEN examples, pick the one whose minimum L1 distance
/// to the SEEN set is MAXIMAL — a 2-approximation to optimal coverage [THM: Gonzalez 1985]. The
/// first question (no recognitions yet) seeds on the example farthest from the pool centroid
/// (the most extreme / informative cold-start). Ties break to the LOWEST id (a total order ⇒ a
/// unique, drift-free result). `Saturated` when every example has been seen. The model's text
/// is never an input — selection is pure geometry, ZERO LLM tokens.
#[must_use]
pub fn next_label_query(pool: &ElicitPool, recognitions: &[Recognition]) -> NextQuery {
    let seen = seen_ids(recognitions);
    // candidates = the UNSEEN examples (spread questions across the space, never re-ask).
    let candidates: Vec<&Example> = pool
        .examples
        .iter()
        .filter(|e| !seen.contains(&e.id))
        .collect();
    if candidates.is_empty() {
        return NextQuery::Saturated;
    }
    // The reference points the candidates are measured against: the seen examples that EXIST in
    // the pool. (A recognition can only reference pool ids — the parser enforces this — but we
    // resolve defensively and skip any that do not resolve.)
    let reference: Vec<&Example> = seen.iter().filter_map(|id| pool.get(*id)).collect();

    // best = (marginal_gain, id); we maximize marginal_gain, tie-break LOWEST id.
    let mut best: Option<(i128, u32)> = None;
    if reference.is_empty() {
        // cold start: seed on the example FARTHEST from the centroid (the extremity).
        let Some(c) = centroid(pool) else {
            return NextQuery::Saturated; // overflow — fail-closed (impossible in practice)
        };
        for cand in &candidates {
            let Some(gain) = l1_to_centroid(&cand.features, &c) else {
                continue;
            };
            best = Some(pick_better(best, gain, cand.id));
        }
    } else {
        // farthest-first: maximize the min-distance to the seen reference set.
        for cand in &candidates {
            let mut min_d: Option<i128> = None;
            for r in &reference {
                if let Some(d) = l1_distance(&cand.features, &r.features) {
                    min_d = Some(match min_d {
                        Some(m) if m <= d => m,
                        _ => d,
                    });
                }
            }
            if let Some(gain) = min_d {
                best = Some(pick_better(best, gain, cand.id));
            }
        }
    }
    match best {
        Some((marginal_gain, example)) => NextQuery::Ask {
            example,
            marginal_gain,
        },
        None => NextQuery::Saturated,
    }
}

/// Update the running best `(gain, id)` for an argmax-gain / min-id tie-break (a total order ⇒
/// deterministic). A strictly larger gain wins; an equal gain keeps the LOWER id.
fn pick_better(best: Option<(i128, u32)>, gain: i128, id: u32) -> (i128, u32) {
    match best {
        Some((bg, bid)) if bg > gain || (bg == gain && bid <= id) => (bg, bid),
        _ => (gain, id),
    }
}

/// The k-center COVERAGE RADIUS at the current state: the marginal gain of the next question
/// (= the max over unseen examples of the min-distance to the seen set). It shrinks
/// monotonically as anchors accumulate ⇒ a deterministic "how well-covered is the standard"
/// signal; `0` (or `Saturated`) means every region is anchored. `None` once saturated.
#[must_use]
pub fn coverage_radius(pool: &ElicitPool, recognitions: &[Recognition]) -> Option<i128> {
    match next_label_query(pool, recognitions) {
        NextQuery::Ask { marginal_gain, .. } => Some(marginal_gain),
        NextQuery::Saturated => None,
    }
}

/// The elicited ANCHOR SET — the owned, content-addressed capital the engine produces (§6.6):
/// the pool, the recognitions, and the derived summary (counts + the customer's named axes).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AnchorSet {
    /// The number of examples in the pool.
    pub pool_size: usize,
    /// The feature dimension.
    pub dim: usize,
    /// Positive (good) label count.
    pub positives: usize,
    /// Negative (bad) label count.
    pub negatives: usize,
    /// Pairwise comparison count.
    pub comparisons: usize,
    /// Triad count.
    pub triads: usize,
    /// The customer's NAMED axes (from triads), de-duplicated, in sorted order (deterministic).
    pub named_axes: Vec<String>,
    /// `true` once every example has been seen (elicitation saturated).
    pub saturated: bool,
}

/// Build the [`AnchorSet`] summary from a pool + recognitions (pure; counts + de-duplicated,
/// sorted named axes — deterministic).
#[must_use]
pub fn build_anchor_set(pool: &ElicitPool, recognitions: &[Recognition]) -> AnchorSet {
    let mut positives = 0;
    let mut negatives = 0;
    let mut comparisons = 0;
    let mut triads = 0;
    let mut axes = std::collections::BTreeSet::new();
    for r in recognitions {
        match r {
            Recognition::Label { good: true, .. } => positives += 1,
            Recognition::Label { good: false, .. } => negatives += 1,
            Recognition::Compare { .. } => comparisons += 1,
            Recognition::Triad { axis, .. } => {
                triads += 1;
                axes.insert(axis.clone());
            }
        }
    }
    AnchorSet {
        pool_size: pool.len(),
        dim: pool.dim(),
        positives,
        negatives,
        comparisons,
        triads,
        named_axes: axes.into_iter().collect(),
        saturated: matches!(next_label_query(pool, recognitions), NextQuery::Saturated),
    }
}

/// The CANONICAL byte serialization of an anchor set (pool + recognitions), in a fixed,
/// order-independent format: the dimension, then examples SORTED by id, then recognitions
/// SORTED by a canonical key. Hashing this content-addresses the anchor SET (reordering the
/// input file does not change the hash — it is the set, not the sequence, that is the capital).
fn canonical_bytes(pool: &ElicitPool, recognitions: &[Recognition]) -> Vec<u8> {
    use std::fmt::Write as _;
    let mut s = String::new();
    let _ = writeln!(s, "dim {}", pool.dim());
    let mut examples: Vec<&Example> = pool.examples.iter().collect();
    examples.sort_by_key(|e| e.id);
    for e in examples {
        let _ = write!(s, "example {}", e.id);
        for f in &e.features {
            let _ = write!(s, " {f}");
        }
        let _ = writeln!(s);
    }
    // a canonical line per recognition, then sort the lines (order-independent set hashing).
    let mut lines: Vec<String> = recognitions
        .iter()
        .map(|r| match r {
            Recognition::Label { example, good } => {
                format!("label {example} {}", if *good { "good" } else { "bad" })
            }
            Recognition::Compare { better, worse } => format!("compare {better} {worse}"),
            Recognition::Triad { a, b, c, odd, axis } => {
                format!("triad {a} {b} {c} odd={odd} axis={axis}")
            }
        })
        .collect();
    lines.sort();
    for l in lines {
        let _ = writeln!(s, "{l}");
    }
    s.into_bytes()
}

/// The content hash of an anchor set: `hex(sha256(canonical_bytes))[..16]` — a stable,
/// order-independent identity for the owned anchor capital (drift-detectable).
#[must_use]
pub fn anchor_set_hash(pool: &ElicitPool, recognitions: &[Recognition]) -> String {
    let hex = crate::hex32(&crate::sha256_32(&canonical_bytes(pool, recognitions)));
    hex[..16].to_string()
}

/// Parse a pool + recognitions from a deterministic line-based text format:
/// ```text
/// dim <D>
/// example <id> <f0> <f1> ... <f(D-1)>
/// label <id> good|bad
/// compare <better_id> <worse_id>
/// triad <a> <b> <c> odd=<id> axis=<text...>
/// ```
/// `#` comments + blank lines are skipped. Fail-closed (`None`) on ANY malformed line, a wrong
/// feature arity, an unknown referenced id, an `odd` not in the triad, or an empty axis — the
/// customer's prose cannot smuggle past the parser into the selector.
#[must_use]
pub fn parse_pool(text: &str) -> Option<(ElicitPool, Vec<Recognition>)> {
    let mut lines = text
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'));
    // header: `dim <D>`
    let header = lines.next()?;
    let mut hp = header.split_whitespace();
    if hp.next()? != "dim" {
        return None;
    }
    let dim: usize = hp.next()?.parse().ok()?;
    if dim == 0 || hp.next().is_some() {
        return None;
    }
    let mut examples = Vec::new();
    let mut recognitions = Vec::new();
    for l in lines {
        let mut p = l.split_whitespace();
        match p.next()? {
            "example" => {
                let id: u32 = p.next()?.parse().ok()?;
                let mut features = Vec::with_capacity(dim);
                for _ in 0..dim {
                    features.push(p.next()?.parse::<i64>().ok()?);
                }
                if p.next().is_some() {
                    return None; // too many features
                }
                examples.push(Example { id, features });
            }
            "label" => {
                let example: u32 = p.next()?.parse().ok()?;
                let good = match p.next()? {
                    "good" => true,
                    "bad" => false,
                    _ => return None,
                };
                if p.next().is_some() {
                    return None;
                }
                recognitions.push(Recognition::Label { example, good });
            }
            "compare" => {
                let better: u32 = p.next()?.parse().ok()?;
                let worse: u32 = p.next()?.parse().ok()?;
                if p.next().is_some() || better == worse {
                    return None;
                }
                recognitions.push(Recognition::Compare { better, worse });
            }
            "triad" => {
                let a: u32 = p.next()?.parse().ok()?;
                let b: u32 = p.next()?.parse().ok()?;
                let c: u32 = p.next()?.parse().ok()?;
                let odd_tok = p.next()?.strip_prefix("odd=")?;
                let odd: u32 = odd_tok.parse().ok()?;
                let axis_tok = p.next()?.strip_prefix("axis=")?;
                let axis_rest: Vec<&str> = p.collect();
                let axis_raw = if axis_rest.is_empty() {
                    axis_tok.to_string()
                } else {
                    format!("{axis_tok} {}", axis_rest.join(" "))
                };
                // the customer MUST name the construct: an empty RAW axis is fail-closed
                // (`summarize_topic` would otherwise substitute a non-empty placeholder).
                if axis_raw.trim().is_empty() {
                    return None;
                }
                if (odd != a && odd != b && odd != c) || a == b || b == c || a == c {
                    return None;
                }
                let axis = crate::memory_walrus::summarize_topic(axis_raw.as_bytes());
                recognitions.push(Recognition::Triad { a, b, c, odd, axis });
            }
            _ => return None,
        }
    }
    let pool = ElicitPool::new(examples)?;
    // every referenced id must exist in the pool (fail-closed — no dangling recognition).
    for r in &recognitions {
        for id in r.referenced_ids() {
            pool.get(id)?;
        }
    }
    Some((pool, recognitions))
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use super::*;

    fn ex(id: u32, features: &[i64]) -> Example {
        Example {
            id,
            features: features.to_vec(),
        }
    }

    fn pool(examples: &[Example]) -> ElicitPool {
        ElicitPool::new(examples.to_vec()).expect("valid pool")
    }

    /// THE ZERO-DRIFT PROOF: `next_label_query` + the anchor-set hash are byte-identical across
    /// repeated calls on the same input (a pure deterministic function — no float/clock/RNG).
    #[test]
    fn selection_and_hash_are_deterministic() {
        let p = pool(&[
            ex(0, &[0, 0]),
            ex(1, &[10, 0]),
            ex(2, &[0, 10]),
            ex(3, &[100, 100]),
        ]);
        let recs = vec![Recognition::Label {
            example: 0,
            good: true,
        }];
        let q1 = next_label_query(&p, &recs);
        let q2 = next_label_query(&p, &recs);
        assert_eq!(q1, q2, "same input ⇒ identical next question (zero drift)");
        let h1 = anchor_set_hash(&p, &recs);
        let h2 = anchor_set_hash(&p, &recs);
        assert_eq!(h1, h2, "same input ⇒ identical anchor-set hash");
        assert_eq!(h1.len(), 16);
    }

    /// THE k-CENTER ACTIVE-QUERY: after labeling the origin, the FARTHEST example (the corner
    /// at [100,100]) is the most-informative next question (max min-distance to the seen set).
    #[test]
    fn farthest_first_picks_the_max_min_distance_example() {
        let p = pool(&[
            ex(0, &[0, 0]),
            ex(1, &[10, 0]),
            ex(2, &[0, 10]),
            ex(3, &[100, 100]),
        ]);
        let recs = vec![Recognition::Label {
            example: 0,
            good: true,
        }];
        match next_label_query(&p, &recs) {
            NextQuery::Ask {
                example,
                marginal_gain,
            } => {
                assert_eq!(
                    example, 3,
                    "the farthest unseen example is the k-center pick"
                );
                assert_eq!(marginal_gain, 200, "L1([0,0],[100,100]) = 200");
            }
            NextQuery::Saturated => panic!("not saturated"),
        }
    }

    /// THE COLD-START SEED: with no recognitions, the first question seeds on the example
    /// FARTHEST from the centroid (the extremity), not an arbitrary id.
    #[test]
    fn cold_start_seeds_on_the_extreme_example() {
        let p = pool(&[
            ex(0, &[0, 0]),
            ex(1, &[1, 1]),
            ex(2, &[2, 2]),
            ex(3, &[100, 100]),
        ]);
        match next_label_query(&p, &[]) {
            NextQuery::Ask { example, .. } => {
                assert_eq!(example, 3, "the most extreme example seeds the elicitation");
            }
            NextQuery::Saturated => {
                panic!("a non-empty pool with no recognitions is not saturated")
            }
        }
    }

    /// THE COVERAGE SIGNAL SHRINKS: among the POST-SEED farthest-first steps, the k-center
    /// radius is monotone non-increasing (adding a seen example can only decrease or hold the
    /// max-min-distance — the standard k-center property). The cold-start seed radius is a
    /// SEPARATE centroid-extremity quantity (a different metric), so it is not compared here.
    #[test]
    fn coverage_radius_is_monotone_non_increasing_post_seed() {
        let p = pool(&[
            ex(0, &[0, 0]),
            ex(1, &[10, 0]),
            ex(2, &[0, 10]),
            ex(3, &[100, 100]),
        ]);
        let _seed = coverage_radius(&p, &[]).expect("cold-start seed radius exists");
        let r1 = coverage_radius(
            &p,
            &[Recognition::Label {
                example: 3,
                good: true,
            }],
        )
        .expect("k-center radius after 1 seen");
        let r2 = coverage_radius(
            &p,
            &[
                Recognition::Label {
                    example: 3,
                    good: true,
                },
                Recognition::Label {
                    example: 0,
                    good: false,
                },
            ],
        )
        .expect("k-center radius after 2 seen");
        assert_eq!(
            r1, 200,
            "max-min to {{3}} over {{0,1,2}} = L1([0,0],[100,100]) = 200"
        );
        assert!(
            r2 <= r1,
            "adding a seen example shrinks (or holds) the k-center radius"
        );
    }

    /// Ties break to the LOWEST id (a total order ⇒ a unique, drift-free pick).
    #[test]
    fn ties_break_to_lowest_id() {
        // 1 and 2 are equidistant from the seen example 0; the lower id (1) wins.
        let p = pool(&[ex(0, &[0, 0]), ex(1, &[5, 0]), ex(2, &[0, 5])]);
        let recs = vec![Recognition::Label {
            example: 0,
            good: true,
        }];
        match next_label_query(&p, &recs) {
            NextQuery::Ask { example, .. } => assert_eq!(example, 1, "tie ⇒ lowest id"),
            NextQuery::Saturated => panic!("not saturated"),
        }
    }

    /// Saturation: once every example has been seen (referenced by a recognition), there is
    /// nothing informative left to ask.
    #[test]
    fn saturates_when_every_example_is_seen() {
        let p = pool(&[ex(0, &[0, 0]), ex(1, &[10, 10])]);
        let recs = vec![
            Recognition::Label {
                example: 0,
                good: true,
            },
            Recognition::Compare {
                better: 1,
                worse: 0,
            },
        ];
        assert_eq!(next_label_query(&p, &recs), NextQuery::Saturated);
        assert_eq!(coverage_radius(&p, &recs), None);
        assert!(build_anchor_set(&p, &recs).saturated);
    }

    /// The anchor-set hash is ORDER-INDEPENDENT (content-addresses the SET) but CONTENT-
    /// SENSITIVE (a different recognition changes it).
    #[test]
    fn anchor_hash_is_order_independent_but_content_sensitive() {
        let p = pool(&[ex(0, &[0, 0]), ex(1, &[10, 10])]);
        let a = vec![
            Recognition::Label {
                example: 0,
                good: true,
            },
            Recognition::Compare {
                better: 1,
                worse: 0,
            },
        ];
        let b = vec![
            Recognition::Compare {
                better: 1,
                worse: 0,
            },
            Recognition::Label {
                example: 0,
                good: true,
            },
        ];
        assert_eq!(
            anchor_set_hash(&p, &a),
            anchor_set_hash(&p, &b),
            "reordering recognitions does not change the set hash"
        );
        let c = vec![Recognition::Label {
            example: 0,
            good: false, // different judgment
        }];
        assert_ne!(
            anchor_set_hash(&p, &a),
            anchor_set_hash(&p, &c),
            "a different recognition changes the hash"
        );
    }

    /// `build_anchor_set` counts the modalities + collects de-duplicated, sorted named axes.
    #[test]
    fn anchor_set_summarizes_modalities_and_axes() {
        let p = pool(&[
            ex(0, &[0, 0]),
            ex(1, &[5, 5]),
            ex(2, &[9, 9]),
            ex(3, &[1, 1]),
        ]);
        let recs = vec![
            Recognition::Label {
                example: 0,
                good: true,
            },
            Recognition::Label {
                example: 1,
                good: false,
            },
            Recognition::Compare {
                better: 2,
                worse: 3,
            },
            Recognition::Triad {
                a: 0,
                b: 1,
                c: 2,
                odd: 2,
                axis: "brightness".to_string(),
            },
        ];
        let set = build_anchor_set(&p, &recs);
        assert_eq!(set.positives, 1);
        assert_eq!(set.negatives, 1);
        assert_eq!(set.comparisons, 1);
        assert_eq!(set.triads, 1);
        assert_eq!(set.named_axes, vec!["brightness".to_string()]);
    }

    /// L1 distance is exact integer + symmetric; the metric the 2-approx relies on.
    #[test]
    fn l1_distance_is_exact_and_symmetric() {
        assert_eq!(l1_distance(&[0, 0], &[3, 4]), Some(7));
        assert_eq!(l1_distance(&[3, 4], &[0, 0]), Some(7));
        assert_eq!(l1_distance(&[1, 2, 3], &[1, 2, 3]), Some(0));
        assert_eq!(
            l1_distance(&[0], &[0, 0]),
            None,
            "length mismatch fail-closed"
        );
        // extreme integer values do not overflow in i128.
        assert_eq!(
            l1_distance(&[i64::MIN], &[i64::MAX]),
            Some(i128::from(i64::MAX) - i128::from(i64::MIN))
        );
    }

    /// The parser round-trips a pool + the three modalities and FAILS CLOSED on malformed input
    /// (wrong arity, unknown id, odd-not-in-triad, empty axis, unknown line, bad header).
    #[test]
    fn parser_round_trips_and_fails_closed() {
        let text = "# a pool\ndim 2\nexample 0 0 0\nexample 1 10 10\nexample 2 100 100\nlabel 0 good\ncompare 1 2\ntriad 0 1 2 odd=2 axis=brightness here";
        let (p, recs) = parse_pool(text).expect("parses");
        assert_eq!(p.len(), 3);
        assert_eq!(p.dim(), 2);
        assert_eq!(recs.len(), 3);
        // the cold-ish next query is deterministic + valid.
        assert!(matches!(
            next_label_query(&p, &recs),
            NextQuery::Ask { .. } | NextQuery::Saturated
        ));
        // fail-closed cases:
        assert!(parse_pool("").is_none(), "empty input");
        assert!(parse_pool("dim 0\n").is_none(), "zero dim");
        assert!(
            parse_pool("dim 2\nexample 0 1\n").is_none(),
            "too few features"
        );
        assert!(
            parse_pool("dim 2\nexample 0 1 2 3\n").is_none(),
            "too many features"
        );
        assert!(
            parse_pool("dim 2\nexample 0 1 2\nlabel 9 good\n").is_none(),
            "unknown labeled id"
        );
        assert!(
            parse_pool(
                "dim 2\nexample 0 1 2\nexample 1 3 4\nexample 2 5 6\ntriad 0 1 2 odd=9 axis=x"
            )
            .is_none(),
            "odd not in the triad"
        );
        assert!(
            parse_pool(
                "dim 2\nexample 0 1 2\nexample 1 3 4\nexample 2 5 6\ntriad 0 1 2 odd=2 axis="
            )
            .is_none(),
            "empty axis"
        );
        assert!(parse_pool("dim 2\nbogus 0 1 2\n").is_none(), "unknown line");
        assert!(
            parse_pool("dim 2\nexample 0 1 2\nexample 0 3 4\n").is_none(),
            "duplicate id (ElicitPool rejects)"
        );
    }

    /// Pool construction is fail-closed on empty / ragged / duplicate.
    #[test]
    fn pool_construction_is_fail_closed() {
        assert!(ElicitPool::new(vec![]).is_none(), "empty");
        assert!(
            ElicitPool::new(vec![ex(0, &[])]).is_none(),
            "zero dimension"
        );
        assert!(
            ElicitPool::new(vec![ex(0, &[1, 2]), ex(1, &[1])]).is_none(),
            "ragged"
        );
        assert!(
            ElicitPool::new(vec![ex(0, &[1, 2]), ex(0, &[3, 4])]).is_none(),
            "duplicate id"
        );
        assert!(ElicitPool::new(vec![ex(0, &[1, 2])]).is_some(), "valid");
    }
}
