//! `mnemos-e-skill::package_policy` — the no-commerce
//! package-metadata policy.
//!
//! ## Policy
//!
//! Active Stage D has **no** price, checkout, paid-license, or revenue
//! field. Useful package metadata is capability, tests, eval, provenance,
//! compatibility, author, and docs. Any money-shaped or
//! commerce-shaped key in the package TOML is rejected **before** the
//! package becomes catalog-visible (G-D-NO-COMMERCE).
//!
//! - [`scan_no_commerce`] — parse a package TOML and reject if any key name
//!   (at any nesting depth) is commerce-shaped. The scan is deterministic
//!   and stable across TOML key order: the verdict is a
//!   pure function of the set of key names, and the reported token is the
//!   lexicographically-smallest matched forbidden token.
//! - [`no_commerce_policy_hash`] — a constant 32-byte hash of this policy
//!   version, bound into the package content digest so a signature proves
//!   the package was checked against this exact forbidden-field set.
//!
//! The base manifest fields (`token_cost_estimate`, …) are deliberately
//! NOT commerce-shaped: `token_cost` is a budgeting estimate, not money.
//! The forbidden tokens below are curated to never alias a legitimate
//! manifest/package field.

#![deny(missing_docs)]

extern crate alloc;

use alloc::string::String;
use alloc::vec::Vec;

use crate::package::blake2b_256;

/// Domain tag for the no-commerce policy hash.
pub(crate) const DOMAIN_NO_COMMERCE: &[u8] = b"mnemos.d.no_commerce.v1";

/// Forbidden commerce substrings — a key whose lowercased name *contains*
/// any of these is rejected. Curated so none aliases a legitimate field:
/// `token_cost_estimate` / `license_hash` do NOT contain any of these.
///
/// Note on `cost`: the bare token `cost` is deliberately ABSENT — it would
/// false-positive on the legitimate `token_cost_estimate` budgeting field
/// (which is an estimate, not money). The money-shaped variant is caught by
/// the exact token `cost_usd`. Likewise `license_key` (paid license) is a
/// substring while `license_hash` (a supply-chain artifact) is allowed —
/// the two do not alias.
pub const FORBIDDEN_COMMERCE_SUBSTRINGS: &[&str] = &[
    "price",
    "checkout",
    "payment",
    "revenue",
    "royalt", // royalty / royalties
    "refund",
    "invoice",
    "billing",
    "subscription",
    "license_fee",
    "license_key",
    "paywall",
    "unlock", // unlock_fee / unlock_price / paid-unlock (fail-closed)
    "fee",
    "usd",
    "donat", // donate / donation
    "stripe",
    "paypal",
    "venmo",
    "cashapp",
    "premium",
    "wallet_pay",
];

/// Forbidden commerce exact key names — a key whose lowercased name
/// *equals* any of these is rejected (short tokens that would over-match as
/// substrings — e.g. `tip` would match `multiple` — are matched exactly).
pub const FORBIDDEN_COMMERCE_EXACT: &[&str] =
    &["buy", "sell", "paid", "cost_usd", "pay", "tip", "tips"];

// ===========================================================================
// 1. NoCommerceViolation — stable rejection reason
// ===========================================================================

/// A commerce-shaped key was found in the package TOML. Carries the matched
/// forbidden token (a `&'static str` from the policy lists) — never the raw
/// operator key — so the rejection reason is stable and leak-free.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub struct NoCommerceViolation {
    /// The forbidden token that matched (from the policy lists).
    pub matched_token: &'static str,
}

impl NoCommerceViolation {
    /// Stable class label namespaced under `no_commerce.*`.
    #[inline]
    #[must_use]
    pub const fn class_label(&self) -> &'static str {
        "no_commerce.forbidden_field"
    }
}

// ===========================================================================
// 2. scan_no_commerce — deterministic, order-stable forbidden-field scan
// ===========================================================================

/// Recursively collect every key name in a TOML value into `out`.
fn collect_keys(value: &toml::Value, out: &mut Vec<String>) {
    match value {
        toml::Value::Table(table) => {
            for (key, child) in table {
                out.push(key.clone());
                collect_keys(child, out);
            }
        }
        toml::Value::Array(items) => {
            for item in items {
                collect_keys(item, out);
            }
        }
        _ => {}
    }
}

/// Return the forbidden token a single key matches, if any.
fn forbidden_token_for_key(key: &str) -> Option<&'static str> {
    let lower = key.to_ascii_lowercase();
    if let Some(&exact) = FORBIDDEN_COMMERCE_EXACT.iter().find(|&&e| lower == e) {
        return Some(exact);
    }
    FORBIDDEN_COMMERCE_SUBSTRINGS
        .iter()
        .find(|&&sub| lower.contains(sub))
        .copied()
}

/// Parse `package_toml` and reject if any key (at any depth) is
/// commerce-shaped. A TOML parse failure is treated as a (non-commerce)
/// pass here — schema validity is the verifier's concern, not this policy's
/// — so this function only ever fails with a [`NoCommerceViolation`].
///
/// Ordering invariant: [`crate::verify::verify_skill_package`] runs
/// `parse_package` (schema reject) BEFORE this scan, so malformed TOML is
/// already rejected by the time the no-commerce gate runs — the "parse
/// failure ⇒ pass" branch here can only be reached by a standalone caller,
/// never by the verifier's commerce gate.
///
/// Deterministic + order-stable: all matched tokens are collected and
/// sorted; the smallest is reported, independent of TOML key order.
pub fn scan_no_commerce(package_toml: &str) -> Result<(), NoCommerceViolation> {
    let value: toml::Value = match toml::from_str(package_toml) {
        Ok(v) => v,
        Err(_) => return Ok(()),
    };
    let mut keys: Vec<String> = Vec::new();
    collect_keys(&value, &mut keys);

    let mut matched: Vec<&'static str> = Vec::new();
    for key in &keys {
        if let Some(token) = forbidden_token_for_key(key) {
            matched.push(token);
        }
    }
    if matched.is_empty() {
        return Ok(());
    }
    matched.sort_unstable();
    Err(NoCommerceViolation {
        matched_token: matched[0],
    })
}

/// `true` iff the TOML contains no commerce-shaped key.
#[must_use]
pub fn is_no_commerce(package_toml: &str) -> bool {
    scan_no_commerce(package_toml).is_ok()
}

// ===========================================================================
// 3. no_commerce_policy_hash — constant policy version hash
// ===========================================================================

/// 32-byte hash of this policy version (the forbidden token sets). Bound
/// into the package content digest so an author signature proves the
/// package was checked against this exact policy. Constant for a given
/// policy version; changes only when the forbidden sets change.
#[must_use]
pub fn no_commerce_policy_hash() -> [u8; 32] {
    let mut buf: Vec<u8> = Vec::new();
    buf.extend_from_slice(&(FORBIDDEN_COMMERCE_EXACT.len() as u32).to_le_bytes());
    for token in FORBIDDEN_COMMERCE_EXACT {
        buf.extend_from_slice(&(token.len() as u32).to_le_bytes());
        buf.extend_from_slice(token.as_bytes());
    }
    buf.extend_from_slice(&(FORBIDDEN_COMMERCE_SUBSTRINGS.len() as u32).to_le_bytes());
    for token in FORBIDDEN_COMMERCE_SUBSTRINGS {
        buf.extend_from_slice(&(token.len() as u32).to_le_bytes());
        buf.extend_from_slice(token.as_bytes());
    }
    blake2b_256(&[DOMAIN_NO_COMMERCE, &buf])
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn free_open_package_accepted() {
        // A package with only capability/eval/provenance/author/docs keys.
        let toml_text = r#"
            name_hash = "abc"
            author = "0x11"
            token_cost_estimate = 250
            [eval]
            rust = 9800
            [docs]
            readme_hash = "def"
        "#;
        assert!(is_no_commerce(toml_text), "free/open package must pass");
    }

    #[test]
    fn package_with_price_rejected() {
        let toml_text = r#"
            name_hash = "abc"
            price = 100
        "#;
        let err = scan_no_commerce(toml_text).expect_err("price must reject");
        assert_eq!(err.matched_token, "price");
        assert_eq!(err.class_label(), "no_commerce.forbidden_field");
    }

    #[test]
    fn package_with_checkout_url_rejected() {
        let toml_text = r#"
            name_hash = "abc"
            checkout_url = "https://pay.example/x"
        "#;
        assert_eq!(
            scan_no_commerce(toml_text)
                .expect_err("checkout must reject")
                .matched_token,
            "checkout"
        );
    }

    #[test]
    fn package_with_revenue_or_royalty_rejected() {
        let revenue = "name_hash = \"a\"\nrevenue_split = 30\n";
        assert_eq!(
            scan_no_commerce(revenue)
                .expect_err("revenue must reject")
                .matched_token,
            "revenue"
        );
        let royalty = "name_hash = \"a\"\n[royalties]\nbps = 250\n";
        assert_eq!(
            scan_no_commerce(royalty)
                .expect_err("royalty must reject")
                .matched_token,
            "royalt"
        );
    }

    #[test]
    fn token_cost_estimate_is_not_commerce() {
        // The legit budgeting field must NOT trip the scan.
        assert!(forbidden_token_for_key("token_cost_estimate").is_none());
        assert!(is_no_commerce("token_cost_estimate = 1000\n"));
        // The legit supply-chain `license_hash` must NOT alias `license_key`.
        assert!(forbidden_token_for_key("license_hash").is_none());
    }

    #[test]
    fn expanded_forbidden_tokens_reject() {
        // The tokens added after the adversarial review must all reject.
        for key in [
            "fee_bps",
            "amount_usd",
            "donate_to",
            "stripe_id",
            "paypal_email",
            "premium_tier",
            "unlock_at",
            "wallet_pay_addr",
            "license_key",
        ] {
            assert!(
                !is_no_commerce(&format!("{key} = 1\n")),
                "`{key}` must reject as commerce-shaped"
            );
        }
        // Exact-list tokens reject only as a whole key.
        for key in ["buy", "sell", "paid", "pay", "tip", "tips", "cost_usd"] {
            assert!(!is_no_commerce(&format!("{key} = 1\n")), "`{key}` exact");
        }
        // `tip` as a substring of a legit word must NOT reject (exact-only).
        assert!(is_no_commerce("multiple = 1\n"));
    }

    #[test]
    fn scan_is_order_stable() {
        // Two TOMLs with the same commerce keys in different order report
        // the same (smallest) matched token.
        let a = "price = 1\nrefund = 2\n";
        let b = "refund = 2\nprice = 1\n";
        let ea = scan_no_commerce(a).expect_err("a");
        let eb = scan_no_commerce(b).expect_err("b");
        assert_eq!(ea.matched_token, eb.matched_token);
        // "price" < "refund" lexicographically.
        assert_eq!(ea.matched_token, "price");
    }

    #[test]
    fn policy_hash_is_constant_and_nonzero() {
        let h1 = no_commerce_policy_hash();
        let h2 = no_commerce_policy_hash();
        assert_eq!(h1, h2);
        assert_ne!(h1, [0u8; 32]);
    }
}
