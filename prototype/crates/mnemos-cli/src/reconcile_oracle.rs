//! `reconcile_oracle` — O-1: the finance reconciliation DETERMINISTIC oracle (the Oracle
//! Bootstrap crown jewel; master plan §6.2 Pillar 1 + §6.9). The NON-coding analog of
//! [`crate::code_oracle`]: a financial CLAIM + line items keyed to sources form a
//! CERTIFICATE; this module RE-SUMS / RE-PRICES them and asserts the accounting
//! INVARIANT (Σreserve ≥ Σliability for a solvency claim; claimed == Σ(qty×price) for a
//! NAV claim), FAIL-CLOSED. The model PROPOSES the certificate; this deterministic
//! checker validates it — **the LLM is never the judge** (no reward-hacking). It is the
//! SAME physics as the Skew Groth16 SVP (a cheap deterministic check of a powerful
//! untrusted prover; P/NP → PCP → SNARK). 0 LLM tokens, 0 IO, no clock — pure arithmetic.
//!
//! ## ★ HONEST LOCK (§6.2, the §3-LOCK boundary — never market past it)
//! This is ✅-SOUND on the ARITHMETIC + the COMMITMENT (the claim reconciles with the
//! STATED line items, and every item names a source), NOT that the positions are REAL.
//! **Aggregate-checkable ≠ per-item-trustworthy** — exactly the Skew SVP boundary: a
//! certificate whose numbers are internally consistent `Reconciled`s even if its sources
//! are fictitious. It makes finance a Bucket-A (deterministic-forever) domain *for the
//! reconciliation invariant*; it NEVER asserts the inputs are true. Use it as a
//! `Violated` SOUND REJECTOR (a real arithmetic break) + a provisional `Reconciled`
//! ("not-yet-falsified"), never as proof the books are honest. custody/funds HARD-LOCKED.
//!
//! Integer minor units only (e.g. cents) — NO floats (determinism); checked arithmetic
//! fail-closes to `NotApplicable` on overflow / a negative amount / an empty certificate.

/// Whether a line item is a RESERVE (an asset backing the claim) or a LIABILITY (an
/// obligation it must cover). The solvency invariant is `Σreserve ≥ Σliability`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LineKind {
    /// An asset / reserve backing the claim.
    Reserve,
    /// An obligation the reserves must cover.
    Liability,
}

/// One reconciliation line item: an amount in integer MINOR units, keyed to a `source_ref`
/// (the provenance COMMITMENT — required, but NOT verified-real, per the honest LOCK).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LineItem {
    /// Reserve or liability.
    pub kind: LineKind,
    /// The amount in integer minor units (e.g. cents). Negative ⇒ malformed ⇒ NotApplicable.
    pub amount_minor: i128,
    /// The source this item is keyed to (a commitment; non-empty required).
    pub source_ref: String,
}

/// One NAV holding: `qty` units at `price_minor` each (both integer; the contribution is
/// `qty × price_minor`). Keyed to a `source_ref` (the same commitment discipline).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Holding {
    /// The quantity held (integer; negative ⇒ malformed ⇒ NotApplicable).
    pub qty: i128,
    /// The unit price in integer minor units (negative ⇒ malformed ⇒ NotApplicable).
    pub price_minor: i128,
    /// The source this holding is keyed to (non-empty required).
    pub source_ref: String,
}

/// The financial CLAIM a certificate asserts, with its line items / holdings.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ReconcileClaim {
    /// "Solvent": the invariant is `Σ(reserves) ≥ Σ(liabilities)`.
    Solvent {
        /// The reserve + liability line items.
        items: Vec<LineItem>,
    },
    /// "NAV == `claimed_minor`": the invariant is `claimed == Σ(qty × price)`.
    Nav {
        /// The asserted net asset value (integer minor units).
        claimed_minor: i128,
        /// The holdings whose priced sum must equal the claim.
        holdings: Vec<Holding>,
    },
}

/// The reconciliation verdict (mirrors the [`crate::verification`] verdict shape).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReconcileVerdict {
    /// The accounting invariant HOLDS — the certificate reconciles (a PROVISIONAL accept:
    /// "not-yet-falsified", sound on the arithmetic, NOT proof the sources are real).
    Reconciled,
    /// The invariant FAILS (insolvent / NAV mismatch) — a SOUND reject (a real break).
    Violated,
    /// The certificate is malformed / overflowed / empty — an honest absence, never a
    /// false `Reconciled`.
    NotApplicable,
}

/// The typed reconciliation receipt: the verdict + the deterministically RE-DERIVED total
/// and its comparison target (so a render can SHOW the arithmetic — `computed` vs `target`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ReconcileReceipt {
    /// The verdict.
    pub verdict: ReconcileVerdict,
    /// The re-derived total: Σreserve (solvency) / Σ(qty×price) (NAV).
    pub computed_minor: i128,
    /// The comparison target: Σliability (solvency) / the claimed NAV (NAV).
    pub target_minor: i128,
    /// A secret-zero static reason.
    pub detail: &'static str,
}

impl ReconcileReceipt {
    /// Whether the certificate RECONCILED (the only verdict an autonomous WRITE would
    /// treat as a provisional accept; `Violated`/`NotApplicable` never do).
    #[must_use]
    pub const fn is_reconciled(&self) -> bool {
        matches!(self.verdict, ReconcileVerdict::Reconciled)
    }

    const fn not_applicable(detail: &'static str) -> Self {
        Self {
            verdict: ReconcileVerdict::NotApplicable,
            computed_minor: 0,
            target_minor: 0,
            detail,
        }
    }
}

/// The DETERMINISTIC reconciliation oracle: re-sum / re-price the certificate and assert
/// the accounting invariant, FAIL-CLOSED. The model's prose is NEVER an input — only the
/// typed numbers are (the hidden-oracle β boundary). Sound on the arithmetic; see the
/// module's HONEST LOCK for what it does NOT prove.
#[must_use]
pub fn check_reconciliation(claim: &ReconcileClaim) -> ReconcileReceipt {
    match claim {
        ReconcileClaim::Solvent { items } => {
            if items.is_empty() {
                return ReconcileReceipt::not_applicable("empty certificate (no line items)");
            }
            let mut reserves: i128 = 0;
            let mut liabilities: i128 = 0;
            for it in items {
                if it.amount_minor < 0 || it.source_ref.is_empty() {
                    return ReconcileReceipt::not_applicable(
                        "malformed line item (negative amount or missing source)",
                    );
                }
                let acc = match it.kind {
                    LineKind::Reserve => &mut reserves,
                    LineKind::Liability => &mut liabilities,
                };
                *acc = match acc.checked_add(it.amount_minor) {
                    Some(v) => v,
                    None => return ReconcileReceipt::not_applicable("sum overflow (fail-closed)"),
                };
            }
            let verdict = if reserves >= liabilities {
                ReconcileVerdict::Reconciled
            } else {
                ReconcileVerdict::Violated
            };
            ReconcileReceipt {
                verdict,
                computed_minor: reserves,
                target_minor: liabilities,
                detail: if reserves >= liabilities {
                    "solvent: Σreserve >= Σliability (arithmetic-sound; sources NOT verified real)"
                } else {
                    "INSOLVENT: Σreserve < Σliability (a sound reject)"
                },
            }
        }
        ReconcileClaim::Nav {
            claimed_minor,
            holdings,
        } => {
            if holdings.is_empty() {
                return ReconcileReceipt::not_applicable("empty certificate (no holdings)");
            }
            let mut total: i128 = 0;
            for h in holdings {
                if h.qty < 0 || h.price_minor < 0 || h.source_ref.is_empty() {
                    return ReconcileReceipt::not_applicable(
                        "malformed holding (negative qty/price or missing source)",
                    );
                }
                let line = match h.qty.checked_mul(h.price_minor) {
                    Some(v) => v,
                    None => {
                        return ReconcileReceipt::not_applicable("price overflow (fail-closed)");
                    }
                };
                total = match total.checked_add(line) {
                    Some(v) => v,
                    None => return ReconcileReceipt::not_applicable("sum overflow (fail-closed)"),
                };
            }
            let verdict = if total == *claimed_minor {
                ReconcileVerdict::Reconciled
            } else {
                ReconcileVerdict::Violated
            };
            ReconcileReceipt {
                verdict,
                computed_minor: total,
                target_minor: *claimed_minor,
                detail: if total == *claimed_minor {
                    "NAV reconciles: claimed == Σ(qty×price) (arithmetic-sound; not position-real)"
                } else {
                    "NAV MISMATCH: claimed != Σ(qty×price) (a sound reject)"
                },
            }
        }
    }
}

/// Parse a reconciliation CERTIFICATE from a deterministic line-based text format:
/// ```text
/// solvent
/// reserve <amount_minor> <source_ref...>
/// liability <amount_minor> <source_ref...>
/// ```
/// or
/// ```text
/// nav <claimed_minor>
/// holding <qty> <price_minor> <source_ref...>
/// ```
/// `#` comment lines + blank lines are skipped. `None` (fail-closed) on any malformed
/// line — the model cannot smuggle prose past the parser into the checker.
#[must_use]
pub fn parse_certificate(text: &str) -> Option<ReconcileClaim> {
    let mut lines = text
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'));
    let header = lines.next()?;
    let mut hp = header.split_whitespace();
    match hp.next()? {
        "solvent" => {
            let mut items = Vec::new();
            for l in lines {
                let mut p = l.split_whitespace();
                let kind = match p.next()? {
                    "reserve" => LineKind::Reserve,
                    "liability" => LineKind::Liability,
                    _ => return None,
                };
                let amount_minor: i128 = p.next()?.parse().ok()?;
                let source_ref = p.collect::<Vec<_>>().join(" ");
                if source_ref.is_empty() {
                    return None;
                }
                items.push(LineItem {
                    kind,
                    amount_minor,
                    source_ref,
                });
            }
            Some(ReconcileClaim::Solvent { items })
        }
        "nav" => {
            let claimed_minor: i128 = hp.next()?.parse().ok()?;
            let mut holdings = Vec::new();
            for l in lines {
                let mut p = l.split_whitespace();
                if p.next()? != "holding" {
                    return None;
                }
                let qty: i128 = p.next()?.parse().ok()?;
                let price_minor: i128 = p.next()?.parse().ok()?;
                let source_ref = p.collect::<Vec<_>>().join(" ");
                if source_ref.is_empty() {
                    return None;
                }
                holdings.push(Holding {
                    qty,
                    price_minor,
                    source_ref,
                });
            }
            Some(ReconcileClaim::Nav {
                claimed_minor,
                holdings,
            })
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn item(kind: LineKind, amount_minor: i128) -> LineItem {
        LineItem {
            kind,
            amount_minor,
            source_ref: "src".to_string(),
        }
    }

    #[test]
    fn solvent_reconciles_when_reserves_meet_liabilities() {
        let claim = ReconcileClaim::Solvent {
            items: vec![
                item(LineKind::Reserve, 100_000),
                item(LineKind::Reserve, 50_000),
                item(LineKind::Liability, 120_000),
            ],
        };
        let r = check_reconciliation(&claim);
        assert!(r.is_reconciled());
        assert_eq!(r.computed_minor, 150_000); // Σreserve
        assert_eq!(r.target_minor, 120_000); // Σliability
    }

    #[test]
    fn insolvent_is_a_sound_violation() {
        let claim = ReconcileClaim::Solvent {
            items: vec![
                item(LineKind::Reserve, 80_000),
                item(LineKind::Liability, 100_000),
            ],
        };
        let r = check_reconciliation(&claim);
        assert_eq!(r.verdict, ReconcileVerdict::Violated);
        assert!(!r.is_reconciled(), "insolvent never reconciles");
    }

    #[test]
    fn nav_reconciles_only_on_exact_match() {
        let holdings = vec![
            Holding {
                qty: 10,
                price_minor: 30_000,
                source_ref: "a".to_string(),
            },
            Holding {
                qty: 20,
                price_minor: 10_000,
                source_ref: "b".to_string(),
            },
        ];
        // 10*30000 + 20*10000 = 500000
        let ok = check_reconciliation(&ReconcileClaim::Nav {
            claimed_minor: 500_000,
            holdings: holdings.clone(),
        });
        assert!(ok.is_reconciled());
        let bad = check_reconciliation(&ReconcileClaim::Nav {
            claimed_minor: 500_001,
            holdings,
        });
        assert_eq!(
            bad.verdict,
            ReconcileVerdict::Violated,
            "a 1-unit NAV mismatch is a sound reject"
        );
    }

    #[test]
    fn malformed_and_empty_are_not_applicable_never_false_reconciled() {
        // empty
        assert_eq!(
            check_reconciliation(&ReconcileClaim::Solvent { items: vec![] }).verdict,
            ReconcileVerdict::NotApplicable
        );
        // negative amount
        assert_eq!(
            check_reconciliation(&ReconcileClaim::Solvent {
                items: vec![item(LineKind::Reserve, -5)]
            })
            .verdict,
            ReconcileVerdict::NotApplicable
        );
        // missing source
        assert_eq!(
            check_reconciliation(&ReconcileClaim::Solvent {
                items: vec![LineItem {
                    kind: LineKind::Reserve,
                    amount_minor: 10,
                    source_ref: String::new()
                }]
            })
            .verdict,
            ReconcileVerdict::NotApplicable
        );
        // overflow fail-closed (i128::MAX + 1 via two maxes)
        assert_eq!(
            check_reconciliation(&ReconcileClaim::Solvent {
                items: vec![
                    item(LineKind::Reserve, i128::MAX),
                    item(LineKind::Reserve, 1),
                ]
            })
            .verdict,
            ReconcileVerdict::NotApplicable
        );
    }

    /// THE HONEST LOCK, made a test: a certificate whose numbers reconcile `Reconciled`s
    /// even though the sources are obviously fictitious — the oracle is sound on the
    /// ARITHMETIC, NOT on whether the positions are real (aggregate ≠ per-item-true).
    #[test]
    fn reconciled_does_not_assert_the_sources_are_real() {
        let claim = ReconcileClaim::Solvent {
            items: vec![
                LineItem {
                    kind: LineKind::Reserve,
                    amount_minor: 999_999_999,
                    source_ref: "totally_made_up_account".to_string(),
                },
                LineItem {
                    kind: LineKind::Liability,
                    amount_minor: 1,
                    source_ref: "fictitious".to_string(),
                },
            ],
        };
        // it RECONCILES (the arithmetic holds) — proving the oracle never claims the
        // sources are real; that is the fenced honest residue, not a checker failure.
        assert!(check_reconciliation(&claim).is_reconciled());
    }

    #[test]
    fn parser_round_trips_solvency_and_nav_and_fails_closed() {
        let solv = parse_certificate("solvent\nreserve 150000 bank_q2\nliability 120000 ledger_ap")
            .expect("parses");
        assert!(check_reconciliation(&solv).is_reconciled());
        let nav = parse_certificate("nav 500000\nholding 10 30000 t_a\nholding 20 10000 t_b")
            .expect("parses");
        assert!(check_reconciliation(&nav).is_reconciled());
        // comments + blanks skipped
        assert!(parse_certificate("# a cert\n\nsolvent\nreserve 5 s").is_some());
        // malformed: unknown line kind / missing source / bad number / unknown claim
        assert!(parse_certificate("solvent\nfoo 5 s").is_none());
        assert!(
            parse_certificate("solvent\nreserve 5").is_none(),
            "missing source"
        );
        assert!(
            parse_certificate("solvent\nreserve abc s").is_none(),
            "non-numeric"
        );
        assert!(
            parse_certificate("franchise\n").is_none(),
            "unknown claim type"
        );
        assert!(parse_certificate("").is_none(), "empty input");
    }
}
