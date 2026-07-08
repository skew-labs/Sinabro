//! `skew_catalog` — the SINGLE SOURCE OF TRUTH for the Skew Solana
//! derivatives-factory capability surface that Sinabro must be AWARE of.
//!
//! ## PURE knowledge — money 0, no key, no network, no cross-repo build dependency
//! This module is **static data**: Sinabro's *knowledge* of Skew, hand-encoded from a
//! four-repo recon (program `skew_otc` = [`SKEW_PROGRAM_ID_DEVNET`], DEVNET). It dials
//! no RPC, holds no key, moves no funds. Other components wire this catalog into the autonomous loop
//! / consult awareness and a `skew capabilities` readout — they all READ this registry, so there is
//! one truth and no prose drift.
//!
//! ## Honest grounding
//! Skew is PRE-LAUNCH, DEVNET-only; deploy is owner-run; mainnet is a further owner arm. A catalog
//! entry describes what the program EXPOSES, not what has been executed. Every TRADE is built +
//! simulated + signed ONLY within a bounded `CustodyGrant` (devnet/testnet-first); READS are
//! autonomous (money 0); financial finality is read from the chain, never an indexer.

/// Skew program id on Solana DEVNET (the only built/deployed cluster; mainnet = a further owner arm).
pub const SKEW_PROGRAM_ID_DEVNET: &str = "BD4DSsEDfv8zcs1HdgqEDoQCPAEgMi3AWWW9r7DVka81";
/// The cluster Skew is built for today (PRE-LAUNCH).
pub const SKEW_CLUSTER: &str = "devnet";
/// The settlement mint (6 decimals) on devnet.
pub const SKEW_SETTLEMENT_MINT_DEVNET: &str = "CKxSFfRFqeW1mBGMUA3uVxxjwKDHWKsosS3RiMMmhhDC";

/// The payoff families Skew's universal adapter admits (permissionless, UDSI-gated).
pub const SKEW_PAYOFF_KINDS: &[&str] = &[
    "forward", "swap", "collar", "option", "spread", "digital", "straddle", "custom", "perp",
];

/// Capability grouping.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SkewCategory {
    /// Read-only market/portfolio data (OnchainReader / SDK; finality from the chain).
    MarketData,
    /// Per-(owner,mint) margin account + deposit/withdraw.
    AccountMargin,
    /// Perp batch-auction trading (isolated margin; cross-margin permanently inert).
    Perp,
    /// Fully-collateralized OTC / forward lifecycle (the clean provable-max-loss path).
    OtcForward,
    /// Permissionless derivative listing (the factory; math-gated, no admin, no stake/burn).
    PermissionlessListing,
    /// Piecewise / non-affine + batch-auction OTC + structured books.
    PiecewiseStructured,
    /// Secondary market — transfer an existing position to another party.
    SecondaryMarket,
    /// Permissionless deterministic liveness/keeper operations.
    Keeper,
    /// Insurance fund + governance (owner-only).
    InsuranceGovernance,
}

impl SkewCategory {
    /// Stable display label.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::MarketData => "market-data (read)",
            Self::AccountMargin => "account / margin",
            Self::Perp => "perp (batch-auction, isolated)",
            Self::OtcForward => "OTC / forward (collateralized)",
            Self::PermissionlessListing => "permissionless listing",
            Self::PiecewiseStructured => "piecewise / structured",
            Self::SecondaryMarket => "secondary market",
            Self::Keeper => "keeper / liveness",
            Self::InsuranceGovernance => "insurance / governance",
        }
    }

    /// All categories, in display order (for completeness checks + the rendered listing).
    #[must_use]
    pub const fn all() -> [SkewCategory; 9] {
        [
            Self::MarketData,
            Self::AccountMargin,
            Self::Perp,
            Self::OtcForward,
            Self::PermissionlessListing,
            Self::PiecewiseStructured,
            Self::SecondaryMarket,
            Self::Keeper,
            Self::InsuranceGovernance,
        ]
    }
}

/// Sinabro's posture toward a Skew capability — the SAFETY classification that decides how (and
/// whether) the agent may invoke it. A trade is NEVER autonomous outside a bounded `CustodyGrant`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SkewAccess {
    /// Autonomous READ-class: no custody, no key, no money.
    Read,
    /// A user trade Sinabro builds + simulates + signs ONLY within an owner-armed, within-bounds
    /// `CustodyGrant` (devnet/testnet-first; mainnet a further owner arm).
    BoundedTrade,
    /// A permissionless, deterministic keeper op Sinabro MAY run as a bounded autonomous job
    /// (improves protocol liveness; byte-identical regardless of who settles).
    Keeper,
    /// Owner / governance-only — Sinabro never originates it.
    OwnerOnly,
}

impl SkewAccess {
    /// Stable display label.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Read => "READ (autonomous, money 0)",
            Self::BoundedTrade => "TRADE (only within a bounded CustodyGrant)",
            Self::Keeper => "KEEPER (deterministic liveness, bounded)",
            Self::OwnerOnly => "OWNER-ONLY (agent never originates)",
        }
    }
}

/// One Skew capability Sinabro is aware of.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SkewCapability {
    /// The instruction / surface name (as in the `skew_otc` program or the SDK/runtime).
    pub name: &'static str,
    /// The 1-byte program dispatch opcode when known from the recon (`None` if not disambiguated
    /// or not a single program instruction). The FE's `0x00NN` form normalizes to this byte.
    pub opcode: Option<u8>,
    /// Capability grouping.
    pub category: SkewCategory,
    /// Sinabro's safety posture toward it.
    pub access: SkewAccess,
    /// One-line awareness summary.
    pub summary: &'static str,
}

/// A `const fn` constructor so the catalog below reads as a clean, reviewable table.
const fn cap(
    name: &'static str,
    opcode: Option<u8>,
    category: SkewCategory,
    access: SkewAccess,
    summary: &'static str,
) -> SkewCapability {
    SkewCapability {
        name,
        opcode,
        category,
        access,
        summary,
    }
}

/// The Skew capability surface Sinabro knows (the single source of truth; extend HERE).
const SKEW_CATALOG: &[SkewCapability] = &[
    // --- market data (READ; OnchainReader / SDK; finality from the chain, never an indexer) ---
    cap(
        "previewCollateral",
        None,
        SkewCategory::MarketData,
        SkewAccess::Read,
        "keyless closed-form worst-case margin readout {required_initial, maintenance} — read it, then deposit EXACTLY that",
    ),
    cap(
        "onchain_markets",
        None,
        SkewCategory::MarketData,
        SkewAccess::Read,
        "list all product templates (the markets catalog)",
    ),
    cap(
        "onchain_perp_markets",
        None,
        SkewCategory::MarketData,
        SkewAccess::Read,
        "list all perp markets with real open interest",
    ),
    cap(
        "onchain_reference",
        None,
        SkewCategory::MarketData,
        SkewAccess::Read,
        "current validated price snapshot for a market",
    ),
    cap(
        "onchain_portfolio",
        None,
        SkewCategory::MarketData,
        SkewAccess::Read,
        "an owner's balances / positions / piecewise contracts",
    ),
    // --- account / margin ---
    cap(
        "open_risk_account",
        Some(0x60),
        SkewCategory::AccountMargin,
        SkewAccess::BoundedTrade,
        "open the per-(owner,mint) UnifiedRiskAccount (holds free_collateral)",
    ),
    cap(
        "deposit_margin",
        Some(0x61),
        SkewCategory::AccountMargin,
        SkewAccess::BoundedTrade,
        "SPL transfer IN -> raise free collateral (deposit the previewed worst-case exactly)",
    ),
    cap(
        "withdraw_margin",
        Some(0x62),
        SkewCategory::AccountMargin,
        SkewAccess::BoundedTrade,
        "withdraw free collateral OUT",
    ),
    // --- perp (batch-auction, isolated margin) ---
    cap(
        "submit_perp_order",
        Some(0x71),
        SkewCategory::Perp,
        SkewAccess::BoundedTrade,
        "place a perp order into a uniform-clearing batch auction (side long/short, optional reduce_only)",
    ),
    cap(
        "open_perp_market",
        Some(0x6A),
        SkewCategory::Perp,
        SkewAccess::BoundedTrade,
        "permissionlessly open a perp market (tick_size>=1 and contract_size>=1) — wired: daemon trade open-perp-market (escrow=0)",
    ),
    cap(
        "factory_list_perp_market",
        Some(0x81),
        SkewCategory::Perp,
        SkewAccess::BoundedTrade,
        "permissionless perp listing under the UDSI gate + reference-envelope clamp + builder bond — wired: daemon trade factory-list-perp-market (escrow=0)",
    ),
    // --- OTC / forward (fully collateralized; the clean provable-max-loss path) ---
    cap(
        "form_fixed_forward_contract",
        Some(0x03),
        SkewCategory::OtcForward,
        SkewAccess::BoundedTrade,
        "open a fixed-price forward (program-authored from escrowed orders, no co-sign)",
    ),
    cap(
        "lock_fixed_forward_initial_collateral",
        None,
        SkewCategory::OtcForward,
        SkewAccess::BoundedTrade,
        "lock the exact previewed worst-case margin for a forward leg",
    ),
    cap(
        "mark_fixed_forward_vm",
        None,
        SkewCategory::OtcForward,
        SkewAccess::BoundedTrade,
        "variation-margin mark",
    ),
    cap(
        "pay_fixed_forward_vm",
        None,
        SkewCategory::OtcForward,
        SkewAccess::BoundedTrade,
        "variation-margin pay",
    ),
    cap(
        "settle_fixed_forward",
        None,
        SkewCategory::OtcForward,
        SkewAccess::BoundedTrade,
        "settle a forward at maturity into a receipt",
    ),
    // --- permissionless listing (the derivative factory; math-gated, no admin, no stake/burn) ---
    cap(
        "list_wcc_template",
        Some(0x50),
        SkewCategory::PermissionlessListing,
        SkewAccess::BoundedTrade,
        "permissionless OTC template creation, gated by an on-chain UDSI worst-case certificate (no admin, no stake/burn) — list a derivative on any external token",
    ),
    cap(
        "list_piecewise_template",
        Some(0x86),
        SkewCategory::PermissionlessListing,
        SkewAccess::BoundedTrade,
        "permissionless non-affine / piecewise template",
    ),
    // --- piecewise / structured ---
    cap(
        "form_piecewise_contract",
        Some(0x87),
        SkewCategory::PiecewiseStructured,
        SkewAccess::BoundedTrade,
        "form a piecewise / non-affine contract (option / spread / digital / straddle / custom)",
    ),
    cap(
        "submit_order",
        None,
        SkewCategory::PiecewiseStructured,
        SkewAccess::BoundedTrade,
        "submit an order into a batch-auction OTC market",
    ),
    cap(
        "form_dated_book",
        None,
        SkewCategory::PiecewiseStructured,
        SkewAccess::BoundedTrade,
        "form a dated structured book",
    ),
    cap(
        "form_corner_book",
        None,
        SkewCategory::PiecewiseStructured,
        SkewAccess::BoundedTrade,
        "form a corner structured book",
    ),
    cap(
        "form_funding_swap",
        Some(0x8E),
        SkewCategory::PiecewiseStructured,
        SkewAccess::BoundedTrade,
        "form a funding-swap (CEIL worst-case escrow per side) — wired: daemon trade form-funding-swap (2-signer ⇒ assemble+sim only)",
    ),
    // --- secondary market (transfer an existing position to another party) ---
    cap(
        "list_secondary",
        None,
        SkewCategory::SecondaryMarket,
        SkewAccess::BoundedTrade,
        "list an existing OTC position for sale on the secondary market",
    ),
    cap(
        "quote_secondary",
        None,
        SkewCategory::SecondaryMarket,
        SkewAccess::BoundedTrade,
        "quote on a secondary listing",
    ),
    cap(
        "accept_secondary",
        None,
        SkewCategory::SecondaryMarket,
        SkewAccess::BoundedTrade,
        "accept a secondary listing",
    ),
    cap(
        "atomic_position_transfer",
        None,
        SkewCategory::SecondaryMarket,
        SkewAccess::BoundedTrade,
        "atomically transfer a position to another party",
    ),
    cap(
        "cancel_secondary",
        None,
        SkewCategory::SecondaryMarket,
        SkewAccess::BoundedTrade,
        "cancel a secondary listing",
    ),
    // --- keeper / liveness (permissionless, deterministic; bounded autonomous job) ---
    cap(
        "validate_reference_snapshot",
        Some(0x64),
        SkewCategory::Keeper,
        SkewAccess::Keeper,
        "post a firewalled price reference snapshot",
    ),
    cap(
        "advance_funding_epoch",
        Some(0x6D),
        SkewCategory::Keeper,
        SkewAccess::Keeper,
        "advance the funding-index epoch",
    ),
    cap(
        "settle_account_funding",
        Some(0x72),
        SkewCategory::Keeper,
        SkewAccess::Keeper,
        "settle one account's funding",
    ),
    cap(
        "settle_batch_contract",
        Some(0x5A),
        SkewCategory::Keeper,
        SkewAccess::Keeper,
        "settle a forward / affine batch shard",
    ),
    cap(
        "settle_piecewise_contract",
        Some(0x88),
        SkewCategory::Keeper,
        SkewAccess::Keeper,
        "crankless piecewise settle",
    ),
    cap(
        "force_reduce_position",
        Some(0x78),
        SkewCategory::Keeper,
        SkewAccess::Keeper,
        "keeper de-risk of a position (heaviest fund path, ~104k CU)",
    ),
    cap(
        "open_fixed_forward_liquidation",
        Some(0x08),
        SkewCategory::Keeper,
        SkewAccess::Keeper,
        "open liquidation of breached collateral (gated tier) — wired: daemon trade open-liquidation (escrow=0)",
    ),
    cap(
        // 8-byte Anchor sighash (NO 1-byte opcode) ⇒ opcode stays None; the wire prelude is sha256("global:complete_liquidation")[..8].
        "complete_liquidation",
        None,
        SkewCategory::Keeper,
        SkewAccess::Keeper,
        "complete a liquidation into a receipt — wired: daemon trade complete-liquidation (escrow=0; 8-byte sighash)",
    ),
    // --- insurance / governance (owner-only; the agent never originates these) ---
    cap(
        "insurance_fund_draw",
        None,
        SkewCategory::InsuranceGovernance,
        SkewAccess::OwnerOnly,
        "draw from the insurance fund (waterfall)",
    ),
    cap(
        "submit_recovery_bid",
        None,
        SkewCategory::InsuranceGovernance,
        SkewAccess::OwnerOnly,
        "submit a recovery bid",
    ),
    cap(
        "init_governance_config",
        None,
        SkewCategory::InsuranceGovernance,
        SkewAccess::OwnerOnly,
        "initialize governance config (constitutionally fixed ranges)",
    ),
    cap(
        "governance_halt_market",
        None,
        SkewCategory::InsuranceGovernance,
        SkewAccess::OwnerOnly,
        "halt a market to close-only (restrict-only; never seizes funds)",
    ),
];

/// The full Skew capability catalog Sinabro is aware of (the single source of truth).
#[must_use]
pub fn skew_capability_catalog() -> &'static [SkewCapability] {
    SKEW_CATALOG
}

/// The payoff families the permissionless adapter admits.
#[must_use]
pub fn skew_payoff_kinds() -> &'static [&'static str] {
    SKEW_PAYOFF_KINDS
}

/// Render the catalog as a human/agent-readable, HONEST listing — grouped by category, with the
/// devnet grounding + the bounded-custody safety posture stated up front. This is the text the
/// future `skew capabilities` readout + the loop/consult awareness reference (one truth, no drift).
#[must_use]
pub fn render_catalog() -> String {
    let mut out = String::new();
    out.push_str("SKEW capability catalog (Sinabro is aware of the full Skew surface)\n");
    out.push_str("  program: skew_otc ");
    out.push_str(SKEW_PROGRAM_ID_DEVNET);
    out.push_str(" — cluster=");
    out.push_str(SKEW_CLUSTER);
    out.push_str(" (PRE-LAUNCH; mainnet is a further owner arm)\n");
    out.push_str(
        "  safety: every TRADE is built+simulated+signed ONLY within a bounded CustodyGrant; \
         READS are autonomous (money 0); finality from the chain, never an indexer.\n",
    );
    // The agent KNOWS the now-EXECUTABLE surface (the full-surface wiring). PROSE-only;
    // the agent reads this catalog mid-reasoning via `TOOL: skew capabilities`. The agent PROPOSES; the
    // OWNER arms execution (`daemon trade <ARM_PHRASE> <mode> <action>`); the model holds no phrase and
    // selects no speed mode.
    out.push_str(
        "  EXECUTABLE on devnet NOW (28 ix), owner-armed via `daemon trade <ARM_PHRASE> \
         <sim|live|fast|turbo> <action>` — the agent PROPOSES, the owner arms:\n    \
         perp: open-account, deposit, withdraw, submit-perp\n    \
         OTC/forward: submit-order, pay-vm, lock-collateral, mark-vm, settle, form-contract \
         (assemble+sim only, 3 signers)\n    \
         batch books: open-batch, close-batch, settle-batch, claim-fill, settle-batch-contract\n    \
         secondary market: list-secondary, quote-secondary, accept-secondary, cancel-secondary, \
         atomic-transfer\n    \
         keeper (aligned, escrow-0 liveness): validate-reference, advance-funding, \
         settle-account-funding, force-reduce\n    \
         listing/piecewise (permissionless): list-wcc-template (affine forward), \
         list-piecewise-template (option/spread/straddle), form-piecewise (2-signer assemble+sim only), \
         settle-piecewise (keeper)\n  \
         modes: sim=money 0 (dry run), live=sim-gated broadcast (safest), fast=skip pre-sim, \
         turbo=fast+Jito/TPU. EVERY leg is K-1-oracle-gated (deterministic worst-case escrow, no LLM \
         judge); keeper=aligned permissionless liveness; governance/insurance=OWNER-ONLY (the agent \
         NEVER originates). The model selects no mode and holds no arm phrase; mainnet is a further \
         owner arm.\n",
    );
    out.push_str("  payoff kinds: ");
    out.push_str(&SKEW_PAYOFF_KINDS.join(", "));
    out.push('\n');
    for category in SkewCategory::all() {
        out.push_str("\n[");
        out.push_str(category.as_str());
        out.push_str("]\n");
        for c in SKEW_CATALOG.iter().filter(|c| c.category == category) {
            out.push_str("  - ");
            out.push_str(c.name);
            if let Some(op) = c.opcode {
                out.push_str(&format!(" (0x{op:02x})"));
            }
            out.push_str(" — ");
            out.push_str(c.access.as_str());
            out.push_str(" — ");
            out.push_str(c.summary);
            out.push('\n');
        }
    }
    out
}

/// Find one capability by exact name (single-source-of-truth lookup).
#[must_use]
pub fn find_capability(name: &str) -> Option<&'static SkewCapability> {
    SKEW_CATALOG.iter().find(|c| c.name == name)
}

/// Render one capability's detail (for a `skew capability <name>` readout).
#[must_use]
pub fn render_capability(c: &SkewCapability) -> String {
    let op = match c.opcode {
        Some(b) => format!("0x{b:02x}"),
        None => "none".to_string(),
    };
    format!(
        "skew capability: {name}\n  category: {cat}\n  access:   {acc}\n  opcode:   {op}\n  summary:  {sum}\n",
        name = c.name,
        cat = c.category.as_str(),
        acc = c.access.as_str(),
        sum = c.summary,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn catalog_is_nonempty_and_covers_every_category() {
        let cat = skew_capability_catalog();
        assert!(
            cat.len() >= 30,
            "catalog should enumerate the full surface, got {}",
            cat.len()
        );
        for category in SkewCategory::all() {
            assert!(
                cat.iter().any(|c| c.category == category),
                "missing category {category:?}"
            );
        }
    }

    #[test]
    fn secondary_market_is_present() {
        let names: Vec<&str> = skew_capability_catalog().iter().map(|c| c.name).collect();
        for v in [
            "list_secondary",
            "quote_secondary",
            "accept_secondary",
            "atomic_position_transfer",
            "cancel_secondary",
        ] {
            assert!(
                names.contains(&v),
                "secondary-market capability {v} missing"
            );
        }
    }

    #[test]
    fn every_access_class_is_represented() {
        let cat = skew_capability_catalog();
        assert!(cat.iter().any(|c| c.access == SkewAccess::Read));
        assert!(cat.iter().any(|c| c.access == SkewAccess::BoundedTrade));
        assert!(cat.iter().any(|c| c.access == SkewAccess::Keeper));
        assert!(cat.iter().any(|c| c.access == SkewAccess::OwnerOnly));
    }

    #[test]
    fn grounding_constants_are_devnet_truth() {
        assert_eq!(
            SKEW_PROGRAM_ID_DEVNET,
            "BD4DSsEDfv8zcs1HdgqEDoQCPAEgMi3AWWW9r7DVka81"
        );
        assert_eq!(SKEW_CLUSTER, "devnet");
        assert_eq!(SKEW_PAYOFF_KINDS.len(), 9);
    }

    #[test]
    fn render_is_honest_and_complete() {
        let r = render_catalog();
        assert!(r.contains(SKEW_PROGRAM_ID_DEVNET));
        assert!(r.contains("PRE-LAUNCH"));
        assert!(r.contains("bounded CustodyGrant"));
        assert!(r.contains("finality from the chain, never an indexer"));
        for category in SkewCategory::all() {
            assert!(
                r.contains(category.as_str()),
                "render missing category {}",
                category.as_str()
            );
        }
        assert!(r.contains("list_secondary"));
    }

    #[test]
    fn submit_perp_opcode_is_single_byte_0x71() {
        // FE 0x0071 == keeper-space single byte 0x71 (consistent across the two recon digests).
        let perp = skew_capability_catalog()
            .iter()
            .find(|c| c.name == "submit_perp_order")
            .expect("perp present");
        assert_eq!(perp.opcode, Some(0x71));
    }

    #[test]
    fn find_capability_hit_and_miss() {
        assert!(find_capability("submit_perp_order").is_some());
        assert!(find_capability("list_secondary").is_some());
        assert!(find_capability("nonexistent_ix").is_none());
    }

    #[test]
    fn render_capability_shows_detail() {
        let c = find_capability("submit_perp_order").expect("present");
        let r = render_capability(c);
        assert!(r.contains("submit_perp_order"));
        assert!(r.contains("0x71"));
        assert!(r.contains("perp"));
    }
}
