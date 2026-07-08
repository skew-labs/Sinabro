//! `skew_read` — the PURE, byte-locked decode layer for reading the Skew
//! `skew_otc` program's on-chain accounts (DEVNET). Pairs with the `web3_rpc` `getProgramAccounts`
//! READ method: the dispatch glue fetches the raw JSON-RPC result over the EXISTING
//! reqwest path (no Solana client crate pulled), and this module turns the base64 account bytes
//! into a typed, honest render.
//!
//! ## PURE + byte-locked (money 0, no key, no network, no Solana-crate dependency)
//! Every discriminator + the `UnifiedRiskAccount` field offsets are copied **byte-exact** from the
//! verified single-source skew-kernel codec (`skew-kernel/src/state/unified_risk_account.rs`,
//! `offset_of!`- and Z3-verified; discriminators Python-derived AND live-confirmed on devnet — see
//! `skew_chain_m1/skew-runtime/src/onchain.rs:92-138`). Nothing here is hand-guessed; the live
//! `4nANvajB…` $1,000 account is a regression test vector.
//!
//! ## Honest scope
//! v1 decodes **balances** (`UnifiedRiskAccount` → free / locked / equity, faithful) and
//! **classifies** every Skew account by its verified 8-byte discriminator (so the agent reads the
//! real on-chain inventory: how many URAs / perp positions / templates / markets …). Per-type FIELD
//! decode for positions / markets / piecewise (qty / OI / payoff) is the next deepening — each a
//! faithful skew-kernel codec copy, NEVER a hand-rolled offset. Reads gate a trade only off the
//! CHAIN, never an indexer.

/// The Skew account types, keyed by their verified 8-byte Anchor discriminator.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SkewAccountKind {
    /// Per-(owner,mint) margin ledger (207 bytes = 8 disc + 199 body). Holds free / locked / equity.
    UnifiedRiskAccount,
    /// A perp position leaf (keyed by `(market_id, owner)`).
    PerpPosition,
    /// A bilateral piecewise/non-affine OTC contract (option / spread / digital / straddle).
    PiecewiseContract,
    /// A permissionlessly-listed product template (228 bytes; the markets catalog).
    ProductTemplate,
    /// A perp market (153 bytes; carries open interest).
    PerpMarket,
    /// A validated price-reference snapshot (153 bytes; the disc disambiguates it from a market).
    ReferenceSnapshot,
    /// An OTC settlement receipt (441 bytes; the volume / realized-price time-series source).
    SettlementReceipt,
    /// A per-market lazy funding accumulator (74 bytes; the funding-rate time-series source).
    FundingState,
    /// Discriminator matched none of the known Skew account types.
    Unknown,
}

impl SkewAccountKind {
    /// Stable display label.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::UnifiedRiskAccount => "balance (UnifiedRiskAccount)",
            Self::PerpPosition => "perp position",
            Self::PiecewiseContract => "piecewise contract",
            Self::ProductTemplate => "market template",
            Self::PerpMarket => "perp market",
            Self::ReferenceSnapshot => "reference snapshot",
            Self::SettlementReceipt => "settlement receipt",
            Self::FundingState => "funding state",
            Self::Unknown => "unknown",
        }
    }
}

// 8-byte Anchor discriminators — copied byte-exact from the verified source
// (`skew_chain_m1/skew-runtime/src/onchain.rs:92-138`, Python-derived + devnet live-confirmed).
/// `UnifiedRiskAccountPda` discriminator (account = this ‖ 199-byte body = 207 bytes).
pub const URA_DISCRIMINATOR: [u8; 8] = [0xbf, 0xd9, 0x45, 0x95, 0xd6, 0xda, 0x21, 0x39];
/// `PerpPositionPda` discriminator.
pub const PERP_POSITION_DISCRIMINATOR: [u8; 8] = [0xfe, 0x5d, 0xf9, 0x3b, 0xab, 0x4a, 0x4b, 0x12];
/// `PiecewiseContractPda` discriminator.
pub const PIECEWISE_CONTRACT_DISCRIMINATOR: [u8; 8] =
    [0x1a, 0x6b, 0xb8, 0xbe, 0x2b, 0x5c, 0x8c, 0xc8];
/// `ProductTemplatePda` discriminator (228-byte account).
pub const PRODUCT_TEMPLATE_DISCRIMINATOR: [u8; 8] =
    [0x2a, 0x68, 0x6d, 0xcd, 0x76, 0xc9, 0xdd, 0xc0];
/// `PerpMarketPda` discriminator (153-byte account — SAME size as a snapshot; disc disambiguates).
pub const PERP_MARKET_DISCRIMINATOR: [u8; 8] = [0x53, 0xde, 0x9e, 0x49, 0x71, 0x59, 0xcc, 0x36];
/// `ReferenceSnapshotPda` discriminator (153-byte account).
pub const REFERENCE_SNAPSHOT_DISCRIMINATOR: [u8; 8] =
    [0x25, 0x75, 0xa1, 0x4d, 0x30, 0x8f, 0x52, 0x1e];
/// `SettlementReceiptPda` discriminator (441-byte account; the OTC settlement receipt — the
/// volume / realized-price time-series source). DERIVED by the documented Anchor account
/// discriminator formula `sha256("account:SettlementReceiptPda")[..8]` — the SAME formula that
/// reproduces all 6 live-confirmed discriminators above byte-exact (golden-test
/// `discriminators_match_anchor_derivation` re-derives all 8). Not a guessed byte.
pub const SETTLEMENT_RECEIPT_DISCRIMINATOR: [u8; 8] =
    [0x6d, 0xcd, 0x60, 0x5a, 0x2a, 0x39, 0x08, 0xb8];
/// `FundingStatePda` discriminator (74-byte account; the per-market lazy funding accumulator — the
/// funding-rate time-series source). DERIVED by `sha256("account:FundingStatePda")[..8]` (same
/// formula, golden-tested).
pub const FUNDING_STATE_DISCRIMINATOR: [u8; 8] = [0x07, 0x01, 0xd5, 0x51, 0x77, 0x48, 0x79, 0xc1];

/// On-chain account sizes (8-byte Anchor discriminator + Pod body), byte-locked to the verified Skew
/// source's `*_PDA_SPACE` consts (each `offset_of!`-tested + Python/Z3 byte-equality-specced).
/// `ReferenceSnapshotPda` = 8 disc + 145 body (`reference_snapshot.rs:117`).
pub const REFERENCE_SNAPSHOT_PDA_SPACE: usize = 153;
/// `SettlementReceiptPda` = 8 disc + 433 body (`settlement_receipt.rs` `SPACE`).
pub const SETTLEMENT_RECEIPT_PDA_SPACE: usize = 441;
/// `FundingStatePda` = 8 disc + 66 body (`funding_state.rs:91` `FUNDING_STATE_PDA_SPACE`).
pub const FUNDING_STATE_PDA_SPACE: usize = 74;
/// `PerpPositionPda` = 8 disc + 146 body (`perp_position.rs:156` `PERP_POSITION_PDA_SPACE`; the body
/// length is pinned by the source's `offset_of!` layout tests + the Z3/Kani byte-equality specs). The
/// 154-byte account the `skew positions` read filters by `dataSize` then decodes byte-exact.
pub const PERP_POSITION_PDA_SPACE: usize = 154;

/// The `UnifiedRiskAccount` discriminator length + body length + on-chain rent size (8 + 199 = 207).
pub const URA_DISCRIMINATOR_LEN: usize = 8;
/// The `UnifiedRiskAccount` Pod body length (Σ field widths; offset-verified in skew-kernel).
pub const URA_BODY_LEN: usize = 199;
/// The full on-chain `UnifiedRiskAccount` account size.
pub const URA_PDA_SPACE: usize = URA_DISCRIMINATOR_LEN + URA_BODY_LEN;

/// Classify raw on-chain account bytes by the leading 8-byte Anchor discriminator (the same
/// load-bearing key the program's `getProgramAccounts` memcmp@0 uses). Fewer than 8 bytes ⇒ Unknown.
#[must_use]
pub fn classify(account_data: &[u8]) -> SkewAccountKind {
    if account_data.len() < 8 {
        return SkewAccountKind::Unknown;
    }
    let disc = &account_data[..8];
    if disc == URA_DISCRIMINATOR {
        SkewAccountKind::UnifiedRiskAccount
    } else if disc == PERP_POSITION_DISCRIMINATOR {
        SkewAccountKind::PerpPosition
    } else if disc == PIECEWISE_CONTRACT_DISCRIMINATOR {
        SkewAccountKind::PiecewiseContract
    } else if disc == PRODUCT_TEMPLATE_DISCRIMINATOR {
        SkewAccountKind::ProductTemplate
    } else if disc == PERP_MARKET_DISCRIMINATOR {
        SkewAccountKind::PerpMarket
    } else if disc == REFERENCE_SNAPSHOT_DISCRIMINATOR {
        SkewAccountKind::ReferenceSnapshot
    } else if disc == SETTLEMENT_RECEIPT_DISCRIMINATOR {
        SkewAccountKind::SettlementReceipt
    } else if disc == FUNDING_STATE_DISCRIMINATOR {
        SkewAccountKind::FundingState
    } else {
        SkewAccountKind::Unknown
    }
}

/// A decoded `UnifiedRiskAccount` balance (the fields a portfolio read needs). Amounts are integer
/// atoms (the settlement mint's smallest unit; devnet "USDC" = 6 decimals).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct UraBalance {
    /// The account owner (32-byte pubkey).
    pub owner: [u8; 32],
    /// The settlement mint (32-byte pubkey).
    pub settlement_mint: [u8; 32],
    /// Free (withdrawable) collateral atoms.
    pub free: u128,
    /// Collateral locked for the current epoch.
    pub locked_epoch: u128,
    /// Collateral locked at worst-case-collateralized escrow.
    pub locked_wcc: u128,
    /// Backed (settled-in) profit atoms.
    pub backed: u128,
    /// Claimed (withdrawn) profit atoms.
    pub claimed: u128,
    /// Lifecycle status byte (1 = Active).
    pub status: u8,
}

impl UraBalance {
    /// Equity = `free + locked_epoch + locked_wcc + (backed − claimed)` — the SAME liability formula
    /// the skew-kernel codec uses (`pending_profit` EXCLUDED). Checked: `None` on overflow
    /// or the `claimed > backed` underflow (fail-closed; never a fabricated number).
    #[must_use]
    pub fn equity(&self) -> Option<u128> {
        let backed_net = self.backed.checked_sub(self.claimed)?;
        self.free
            .checked_add(self.locked_epoch)?
            .checked_add(self.locked_wcc)?
            .checked_add(backed_net)
    }
}

/// Decode a `UnifiedRiskAccount` from RAW account bytes (incl. the 8-byte discriminator). Returns
/// `None` unless the bytes are exactly [`URA_PDA_SPACE`] AND carry the URA discriminator (fail-closed
/// — a read never mis-attributes a wrong-shaped account). Offsets copied byte-exact from the verified
/// skew-kernel codec.
#[must_use]
pub fn decode_ura_account(account_data: &[u8]) -> Option<UraBalance> {
    if account_data.len() != URA_PDA_SPACE || account_data[..8] != URA_DISCRIMINATOR {
        return None;
    }
    let b = &account_data[URA_DISCRIMINATOR_LEN..]; // the 199-byte body
    let rd16 = |o: usize| -> u128 {
        let mut t = [0u8; 16];
        t.copy_from_slice(&b[o..o + 16]);
        u128::from_le_bytes(t)
    };
    let mut owner = [0u8; 32];
    owner.copy_from_slice(&b[0..32]);
    let mut settlement_mint = [0u8; 32];
    settlement_mint.copy_from_slice(&b[32..64]);
    Some(UraBalance {
        owner,
        settlement_mint,
        free: rd16(64),
        locked_epoch: rd16(80),
        locked_wcc: rd16(96),
        backed: rd16(128),
        claimed: rd16(144),
        status: b[197],
    })
}

// Little-endian field readers over a `#[repr(C, packed)]` Pod body slice. Each caller checks the
// body length == the exact account size FIRST, so `b[o..o+N]` is always in-bounds (fail-closed before
// any read). Multi-byte fields are little-endian (the Solana / bytemuck wire format).
#[inline]
fn le_u16(b: &[u8], o: usize) -> u16 {
    let mut t = [0u8; 2];
    t.copy_from_slice(&b[o..o + 2]);
    u16::from_le_bytes(t)
}
#[inline]
fn le_u32(b: &[u8], o: usize) -> u32 {
    let mut t = [0u8; 4];
    t.copy_from_slice(&b[o..o + 4]);
    u32::from_le_bytes(t)
}
#[inline]
fn le_u64(b: &[u8], o: usize) -> u64 {
    let mut t = [0u8; 8];
    t.copy_from_slice(&b[o..o + 8]);
    u64::from_le_bytes(t)
}
#[inline]
fn le_u128(b: &[u8], o: usize) -> u128 {
    let mut t = [0u8; 16];
    t.copy_from_slice(&b[o..o + 16]);
    u128::from_le_bytes(t)
}
#[inline]
fn le_i128(b: &[u8], o: usize) -> i128 {
    let mut t = [0u8; 16];
    t.copy_from_slice(&b[o..o + 16]);
    i128::from_le_bytes(t)
}
#[inline]
fn le_i64(b: &[u8], o: usize) -> i64 {
    let mut t = [0u8; 8];
    t.copy_from_slice(&b[o..o + 8]);
    i64::from_le_bytes(t)
}

/// A decoded `ReferenceSnapshotPda` — the validated per-market price reference (price series).
/// Field offsets are byte-exact from `skew-mainnet/.../state/reference_snapshot.rs:119-180`
/// (`#[repr(C, packed)]` Pod, body 145 B, all multi-byte LE). The chain stores only the LATEST
/// snapshot; accumulating successive `observed_slot`s is the time-series Sinabro builds.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ReferenceSnapshotData {
    /// @0 Policy id this snapshot was validated under.
    pub policy_id: u16,
    /// @2 Monotone epoch sequence (advances each successful validation).
    pub epoch_seq: u64,
    /// @10 On-chain source id that produced the observation.
    pub source_id: u32,
    /// @14 The slot the observation was validated at — the TIME AXIS of the series.
    pub observed_slot: u64,
    /// @22 Validated numerator price in atoms (raw u128).
    pub numerator_atoms: u128,
    /// @38 Validated divisor price in atoms (≥1; the Percolator-kill guard target).
    pub divisor_atoms: u128,
    /// @54 The validated composite price = `floor(numerator·10^exponent / divisor)` — the PRICE the
    /// OHLC series buckets (integer atoms at scale `10^exponent`).
    pub composite_atoms: u128,
    /// @70 Reported confidence width in bps.
    pub confidence_bps: u16,
    /// @72 Reported bid-ask spread in bps.
    pub bid_ask_spread_bps: u16,
    /// @74 Decimal exponent (the composite scale `10^exponent`).
    pub exponent: u8,
    /// @75 The guard-pass bitmask (`ALL_PASS` on a validated snapshot).
    pub validation_flags: u32,
    /// @143 Lifecycle status (0 = Uninit, 1 = Validated).
    pub status: u8,
}

impl ReferenceSnapshotData {
    /// `true` iff the snapshot carries a validated reference (status byte == 1).
    #[must_use]
    pub const fn is_validated(&self) -> bool {
        self.status == 1
    }

    /// Re-derive the composite price `floor(numerator·10^exponent / divisor)` with CHECKED integer
    /// math — mirrors the program's own `reference_firewall::compute_composite_atoms`. `None` on a
    /// zero divisor, an exponent past u128 (>38), or a numerator·scale overflow (fail-closed, never
    /// a fabricated number). A deterministic cross-check; no float, no LLM.
    #[must_use]
    pub fn recompute_composite(&self) -> Option<u128> {
        if self.divisor_atoms == 0 || self.exponent > 38 {
            return None;
        }
        let scale = 10u128.checked_pow(u32::from(self.exponent))?;
        let scaled = self.numerator_atoms.checked_mul(scale)?;
        Some(scaled / self.divisor_atoms)
    }

    /// `true` iff the stored `composite_atoms` equals the re-derived composite — a deterministic
    /// integrity cross-check the agent can assert without trusting the RPC's composite field.
    #[must_use]
    pub fn composite_consistent(&self) -> bool {
        self.recompute_composite() == Some(self.composite_atoms)
    }
}

/// Decode a `ReferenceSnapshotPda` from RAW account bytes (incl. the 8-byte discriminator). `None`
/// unless the bytes are exactly [`REFERENCE_SNAPSHOT_PDA_SPACE`] AND carry the
/// [`REFERENCE_SNAPSHOT_DISCRIMINATOR`] (fail-closed — a 153-byte perp market is rejected by disc).
/// Offsets byte-exact from the verified Skew source; never hand-rolled.
#[must_use]
pub fn decode_reference_snapshot(account_data: &[u8]) -> Option<ReferenceSnapshotData> {
    if account_data.len() != REFERENCE_SNAPSHOT_PDA_SPACE
        || account_data[..8] != REFERENCE_SNAPSHOT_DISCRIMINATOR
    {
        return None;
    }
    let b = &account_data[8..]; // the 145-byte body
    Some(ReferenceSnapshotData {
        policy_id: le_u16(b, 0),
        epoch_seq: le_u64(b, 2),
        source_id: le_u32(b, 10),
        observed_slot: le_u64(b, 14),
        numerator_atoms: le_u128(b, 22),
        divisor_atoms: le_u128(b, 38),
        composite_atoms: le_u128(b, 54),
        confidence_bps: le_u16(b, 70),
        bid_ask_spread_bps: le_u16(b, 72),
        exponent: b[74],
        validation_flags: le_u32(b, 75),
        status: b[143],
    })
}

/// A decoded `SettlementReceiptPda` — an OTC settlement event (volume / realized-price series).
/// Field offsets are byte-exact from `skew-mainnet/.../state/settlement_receipt.rs:467-733` (account
/// offsets minus the 8-byte disc). `paid_amount` (the actual disbursed atoms) is the volume proxy;
/// `settlement_price` is the realized price; `created_slot` is the time axis.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SettlementReceiptData {
    /// @393(body) Solana slot at settlement — the TIME AXIS (indexers join on this).
    pub created_slot: u64,
    /// @161(body) The reference-snapshot price at settlement (atoms).
    pub settlement_price: u128,
    /// @257(body) Actual SPL-token disbursed magnitude (atoms) — the settlement VOLUME proxy.
    pub paid_amount: u128,
    /// @177(body) Signed settlement payoff (atoms; sign = direction).
    pub signed_payoff_amount: i128,
    /// @289(body) Settlement-mint pubkey (the currency).
    pub settlement_mint: [u8; 32],
}

/// Decode a `SettlementReceiptPda` from RAW account bytes. `None` unless exactly
/// [`SETTLEMENT_RECEIPT_PDA_SPACE`] bytes with the [`SETTLEMENT_RECEIPT_DISCRIMINATOR`] (fail-closed).
/// Offsets byte-exact from the verified source's `SPACE` offset table; never hand-rolled.
#[must_use]
pub fn decode_settlement_receipt(account_data: &[u8]) -> Option<SettlementReceiptData> {
    if account_data.len() != SETTLEMENT_RECEIPT_PDA_SPACE
        || account_data[..8] != SETTLEMENT_RECEIPT_DISCRIMINATOR
    {
        return None;
    }
    let b = &account_data[8..]; // the 433-byte body
    let mut settlement_mint = [0u8; 32];
    settlement_mint.copy_from_slice(&b[289..321]);
    Some(SettlementReceiptData {
        settlement_price: le_u128(b, 161),
        signed_payoff_amount: le_i128(b, 177),
        paid_amount: le_u128(b, 257),
        created_slot: le_u64(b, 393),
        settlement_mint,
    })
}

/// A decoded `FundingStatePda` — the per-market lazy funding accumulator (funding-rate series).
/// Field offsets are byte-exact from `skew-mainnet/.../state/funding_state.rs:93-119`
/// (`#[repr(C, packed)]` Pod, body 66 B). The signed `cumulative_funding_index` deltas across
/// successive `last_snapshot_slot`s are the funding-rate series.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FundingStateData {
    /// @0(body) The perp market this accumulator serves.
    pub market_id: [u8; 32],
    /// @32(body) Cumulative funding index (SIGNED i128; funding flows either direction).
    pub cumulative_funding_index: i128,
    /// @48(body) `Fmax` — the per-step funding-rate clamp bound.
    pub max_rate: u64,
    /// @56(body) The slot of the last `advance_funding_epoch` — the TIME AXIS.
    pub last_snapshot_slot: u64,
    /// @64(body) Lifecycle status (0 = Uninit, 1 = Active).
    pub status: u8,
}

/// Decode a `FundingStatePda` from RAW account bytes. `None` unless exactly
/// [`FUNDING_STATE_PDA_SPACE`] bytes with the [`FUNDING_STATE_DISCRIMINATOR`] (fail-closed). Offsets
/// byte-exact from the verified source; never hand-rolled.
#[must_use]
pub fn decode_funding_state(account_data: &[u8]) -> Option<FundingStateData> {
    if account_data.len() != FUNDING_STATE_PDA_SPACE
        || account_data[..8] != FUNDING_STATE_DISCRIMINATOR
    {
        return None;
    }
    let b = &account_data[8..]; // the 66-byte body
    let mut market_id = [0u8; 32];
    market_id.copy_from_slice(&b[0..32]);
    Some(FundingStateData {
        market_id,
        cumulative_funding_index: le_i128(b, 32),
        max_rate: le_u64(b, 48),
        last_snapshot_slot: le_u64(b, 56),
        status: b[64],
    })
}

/// A FULLY-decoded `PerpPositionPda` — the per-(market, owner) ROLLING net perp position (the leaf the
/// unified WCL engine rolls many fills into ONE signed quantity at one net notional). Field offsets are
/// byte-exact from `skew-mainnet/.../state/perp_position.rs:160-224` and its `offset_of!` layout tests
/// (`#[repr(C, packed)]` Pod, body 146 B; the account-relative offset is body offset + 8). The signed
/// fields are two's-complement LE. This is the RICHER sibling of [`crate::skew_oracle::PerpPositionEscrow`]
/// (which decodes only the margin subset the escrow oracle needs); a portfolio read wants every field.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PerpPositionView {
    /// @0(body) The perp market this position belongs to (first PDA seed; == `PerpMarketPda.market_id`).
    pub market_id: [u8; 32],
    /// @32(body) The position owner (second PDA seed; its margin account is the URA for this owner).
    pub owner: [u8; 32],
    /// @64(body) Net SIGNED position quantity (i64): `+` = net long, `−` = net short, `0` = flat.
    pub signed_qty: i64,
    /// @72(body) Net position notional `PN = signed_qty · per_unit_entry` (i128, sign-unrestricted).
    pub entry_notional: i128,
    /// @88(body) Cumulative funding-index snapshot at the last fill (i128; mirrors `FundingState`).
    pub funding_snapshot: i128,
    /// @104(body) The `RiskEpochPda.epoch_seq` of the last fill (u64; the staleness gate target).
    pub last_epoch_seq: u64,
    /// @112(body) Realized-but-unbacked PnL (u128 atoms; NOT withdrawable).
    pub pending_profit: u128,
    /// @128(body) The position's RESERVED margin = its on-chain `E_epoch` worst-case escrow (u128
    /// atoms; the per-position component of the account-level locked-collateral odometer, Option-R).
    pub reserved_collateral: u128,
    /// @144(body) Lifecycle status byte (0 = Uninit, 1 = Open).
    pub status: u8,
    /// @145(body) Cached PDA bump (`[b"perp_position", market_id, owner]`).
    pub bump: u8,
}

impl PerpPositionView {
    /// `true` iff the position account is Open (status byte == 1).
    #[must_use]
    pub const fn is_open(&self) -> bool {
        self.status == 1
    }

    /// `true` iff the net quantity is flat (no directional exposure).
    #[must_use]
    pub const fn is_flat(&self) -> bool {
        self.signed_qty == 0
    }

    /// The human direction of the signed quantity — `"long"` / `"short"` / `"flat"` (never fabricated;
    /// a pure projection of the decoded sign).
    #[must_use]
    pub const fn direction(&self) -> &'static str {
        if self.signed_qty > 0 {
            "long"
        } else if self.signed_qty < 0 {
            "short"
        } else {
            "flat"
        }
    }
}

/// Decode a `PerpPositionPda` from RAW account bytes (incl. the 8-byte discriminator). Returns `None`
/// (fail-closed) unless the bytes are exactly [`PERP_POSITION_PDA_SPACE`] AND carry the verified
/// [`PERP_POSITION_DISCRIMINATOR`] — a read never mis-attributes a wrong-shaped account. Offsets
/// byte-exact from the verified Skew source; never hand-rolled.
#[must_use]
pub fn decode_perp_position(account_data: &[u8]) -> Option<PerpPositionView> {
    if account_data.len() != PERP_POSITION_PDA_SPACE
        || account_data[..8] != PERP_POSITION_DISCRIMINATOR
    {
        return None;
    }
    let b = &account_data[8..]; // the 146-byte body
    let mut market_id = [0u8; 32];
    market_id.copy_from_slice(&b[0..32]);
    let mut owner = [0u8; 32];
    owner.copy_from_slice(&b[32..64]);
    Some(PerpPositionView {
        market_id,
        owner,
        signed_qty: le_i64(b, 64),
        entry_notional: le_i128(b, 72),
        funding_snapshot: le_i128(b, 88),
        last_epoch_seq: le_u64(b, 104),
        pending_profit: le_u128(b, 112),
        reserved_collateral: le_u128(b, 128),
        status: b[144],
        bump: b[145],
    })
}

/// Render the perp-position inventory from decoded accounts (PURE; the dispatch glue supplies the
/// base64-decoded accounts). Only `PerpPosition`-classified accounts are decoded; if `owner_filter` is
/// `Some`, only positions whose decoded owner matches are listed (the rest are still counted in the
/// total). Signed quantities / notionals render with their sign; amounts are integer atoms. Money 0,
/// no fabricated number — a mis-shaped account is silently skipped, never invented.
#[must_use]
pub fn render_positions(accounts: &[SkewAccount<'_>], owner_filter: Option<[u8; 32]>) -> String {
    let mut out = String::new();
    out.push_str("skew perp positions (devnet; PerpPositionPda, byte-exact decode)\n");
    let mut total = 0usize;
    let mut listed: Vec<(String, PerpPositionView)> = Vec::new();
    for a in accounts {
        if classify(a.data) != SkewAccountKind::PerpPosition {
            continue;
        }
        if let Some(p) = decode_perp_position(a.data) {
            total += 1;
            if owner_filter.is_none_or(|o| p.owner == o) {
                listed.push((a.pubkey.to_string(), p));
            }
        }
    }
    out.push_str(&format!(
        "  perp positions: {total} decoded ({} listed{})\n",
        listed.len(),
        if owner_filter.is_some() {
            ", owner-scoped"
        } else {
            ""
        }
    ));
    for (pubkey, p) in &listed {
        out.push_str(&format!(
            "    {pubkey}: dir={} signed_qty={} entry_notional={} reserved_E_epoch={} pending_profit={} last_epoch_seq={} status={}\n",
            p.direction(),
            p.signed_qty,
            p.entry_notional,
            p.reserved_collateral,
            p.pending_profit,
            p.last_epoch_seq,
            p.status
        ));
    }
    if listed.is_empty() {
        out.push_str("  (no matching perp positions on this read)\n");
    }
    out
}

/// `PiecewiseContractPda` = 8 disc + 259 body (`piecewise_contract.rs:148-162` `SPACE`; the const
/// assert pins `size_of == 259`). The 267-byte bilateral piecewise/non-affine OTC contract the
/// `skew contracts` read filters by `dataSize` then decodes byte-exact.
pub const PIECEWISE_CONTRACT_PDA_SPACE: usize = 267;

/// A FULLY-decoded `PiecewiseContractPda` — a bilateral piecewise / non-affine OTC contract (option /
/// spread / digital / straddle) with per-leg escrow. Field offsets are byte-exact from the documented
/// account-offset table in `skew-mainnet/.../state/piecewise_contract.rs:128-145` (`#[repr(C, packed)]`
/// Pod, body 259 B; account-relative offset = body offset + 8). READ-class, money 0 — the agent reads
/// its OWN bilateral contracts (it may be the long OR the short party).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PiecewiseContractView {
    /// @0(body) Canonical 32-byte contract id (PDA seed `[b"piecewise_contract", contract_id]`).
    pub contract_id: [u8; 32],
    /// @32(body) The piecewise `ProductTemplate.template_id` this contract trades against.
    pub template_id: [u8; 32],
    /// @64(body) SHA-256 commitment to the certified leg pair + declared bounds (settle re-verifies).
    pub payoff_descriptor_hash: [u8; 32],
    /// @96(body) Long-party pubkey (escrows `escrow_long = WCL_long`).
    pub long_party: [u8; 32],
    /// @128(body) Short-party pubkey (escrows `escrow_short = WCL_short`; may equal `long_party`).
    pub short_party: [u8; 32],
    /// @160(body) Settlement mint (== the template's settlement mint; the vault's mint).
    pub settlement_mint: [u8; 32],
    /// @192(body) The per-contract escrow vault (holds `escrow_long + escrow_short`).
    pub collateral_vault: [u8; 32],
    /// @224(body) The long leg's escrowed worst-case loss (u64 atoms).
    pub escrow_long: u64,
    /// @232(body) The short leg's escrowed worst-case loss (u64 atoms).
    pub escrow_short: u64,
    /// @240(body) Forward maturity (unix seconds, i64; settle requires `clock >= maturity`).
    pub maturity_timestamp: i64,
    /// @248(body) Formation slot (audit; the TIME AXIS).
    pub created_slot: u64,
    /// @256(body) `ContractStatus` byte — `Active = 1` at form, `Settled = 6` at settle.
    pub status: u8,
    /// @257(body) Party-role marker (`BOTH_SIGNED = 0b11`).
    pub party_roles: u8,
    /// @258(body) Cached PDA bump.
    pub bump: u8,
}

impl PiecewiseContractView {
    /// `true` iff the contract is Active (status byte == 1; the `ContractStatus::Active` VALUE).
    #[must_use]
    pub const fn is_active(&self) -> bool {
        self.status == 1
    }

    /// `true` iff the contract is Settled (status byte == 6; the `ContractStatus::Settled` VALUE).
    #[must_use]
    pub const fn is_settled(&self) -> bool {
        self.status == 6
    }

    /// `true` iff `party` is the long OR the short party — the owner-scoping predicate (the agent may
    /// be either side of a bilateral contract).
    #[must_use]
    pub fn involves(&self, party: [u8; 32]) -> bool {
        self.long_party == party || self.short_party == party
    }

    /// The total vault escrow `escrow_long + escrow_short` with CHECKED math — `None` on overflow
    /// (fail-closed; never a fabricated number).
    #[must_use]
    pub fn total_escrow(&self) -> Option<u64> {
        self.escrow_long.checked_add(self.escrow_short)
    }
}

/// Decode a `PiecewiseContractPda` from RAW account bytes (incl. the 8-byte discriminator). Returns
/// `None` (fail-closed) unless the bytes are exactly [`PIECEWISE_CONTRACT_PDA_SPACE`] AND carry the
/// verified [`PIECEWISE_CONTRACT_DISCRIMINATOR`]. Offsets byte-exact from the verified Skew source;
/// never hand-rolled.
#[must_use]
pub fn decode_piecewise_contract(account_data: &[u8]) -> Option<PiecewiseContractView> {
    if account_data.len() != PIECEWISE_CONTRACT_PDA_SPACE
        || account_data[..8] != PIECEWISE_CONTRACT_DISCRIMINATOR
    {
        return None;
    }
    let b = &account_data[8..]; // the 259-byte body
    let rd32 = |o: usize| -> [u8; 32] {
        let mut a = [0u8; 32];
        a.copy_from_slice(&b[o..o + 32]);
        a
    };
    Some(PiecewiseContractView {
        contract_id: rd32(0),
        template_id: rd32(32),
        payoff_descriptor_hash: rd32(64),
        long_party: rd32(96),
        short_party: rd32(128),
        settlement_mint: rd32(160),
        collateral_vault: rd32(192),
        escrow_long: le_u64(b, 224),
        escrow_short: le_u64(b, 232),
        maturity_timestamp: le_i64(b, 240),
        created_slot: le_u64(b, 248),
        status: b[256],
        party_roles: b[257],
        bump: b[258],
    })
}

/// Render the piecewise-contract inventory from decoded accounts (PURE; the dispatch glue supplies the
/// base64-decoded accounts). Only `PiecewiseContract`-classified accounts are decoded; if `owner_filter`
/// is `Some`, only contracts the party is long OR short in are listed (the rest are still counted).
/// Amounts are integer atoms; money 0, no fabricated number — a mis-shaped account is silently skipped.
#[must_use]
pub fn render_contracts(accounts: &[SkewAccount<'_>], owner_filter: Option<[u8; 32]>) -> String {
    let mut out = String::new();
    out.push_str("skew piecewise contracts (devnet; PiecewiseContractPda, byte-exact decode)\n");
    let mut total = 0usize;
    let mut listed: Vec<(String, PiecewiseContractView)> = Vec::new();
    for a in accounts {
        if classify(a.data) != SkewAccountKind::PiecewiseContract {
            continue;
        }
        if let Some(c) = decode_piecewise_contract(a.data) {
            total += 1;
            if owner_filter.is_none_or(|o| c.involves(o)) {
                listed.push((a.pubkey.to_string(), c));
            }
        }
    }
    out.push_str(&format!(
        "  piecewise contracts: {total} decoded ({} listed{})\n",
        listed.len(),
        if owner_filter.is_some() {
            ", party-scoped"
        } else {
            ""
        }
    ));
    for (pubkey, c) in &listed {
        let total_escrow = c
            .total_escrow()
            .map_or_else(|| "n/a(overflow)".to_string(), |t| t.to_string());
        let lifecycle = if c.is_active() {
            "active"
        } else if c.is_settled() {
            "settled"
        } else {
            "other"
        };
        out.push_str(&format!(
            "    {pubkey}: status={}({lifecycle}) escrow_long={} escrow_short={} total_escrow={total_escrow} maturity_ts={} created_slot={}\n",
            c.status, c.escrow_long, c.escrow_short, c.maturity_timestamp, c.created_slot
        ));
    }
    if listed.is_empty() {
        out.push_str("  (no matching piecewise contracts on this read)\n");
    }
    out
}

/// Build the `getProgramAccounts` JSON-RPC `params` for one account size, requesting base64 data.
/// A `dataSize` filter bounds the result to one account shape; the client classifies by discriminator
/// (load-bearing where two types share a size, e.g. 153-byte market vs snapshot). PURE string — the
/// `web3_rpc` reqwest path sends it verbatim.
#[must_use]
pub fn program_accounts_params(program_id: &str, data_size: usize) -> String {
    format!(
        "[\"{program_id}\",{{\"encoding\":\"base64\",\"filters\":[{{\"dataSize\":{data_size}}}]}}]"
    )
}

/// Minimal, pure base64 decoder (standard alphabet, optional `=` padding). `None` on any
/// non-alphabet byte or a malformed length. Vendored to avoid a base64 crate dependency.
#[must_use]
pub fn base64_decode(s: &str) -> Option<Vec<u8>> {
    fn val(c: u8) -> Option<u8> {
        match c {
            b'A'..=b'Z' => Some(c - b'A'),
            b'a'..=b'z' => Some(c - b'a' + 26),
            b'0'..=b'9' => Some(c - b'0' + 52),
            b'+' => Some(62),
            b'/' => Some(63),
            _ => None,
        }
    }
    let bytes: &[u8] = s.trim().as_bytes();
    let mut out = Vec::with_capacity(bytes.len() / 4 * 3);
    let mut acc: u32 = 0;
    let mut nbits: u32 = 0;
    for &c in bytes {
        if c == b'=' {
            break;
        }
        let v = u32::from(val(c)?);
        acc = (acc << 6) | v;
        nbits += 6;
        if nbits >= 8 {
            nbits -= 8;
            out.push((acc >> nbits) as u8);
        }
    }
    Some(out)
}

/// Minimal, pure base58 (Bitcoin alphabet) decoder — used to turn an owner pubkey STRING into its
/// 32 raw bytes for client-side owner-scoping. `None` on a non-alphabet char. Vendored to avoid a
/// bs58 crate dependency.
#[must_use]
pub fn base58_decode(s: &str) -> Option<Vec<u8>> {
    const ALPHABET: &[u8; 58] = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
    let s = s.trim();
    let mut bytes: Vec<u8> = Vec::with_capacity(s.len());
    for c in s.bytes() {
        let digit = ALPHABET.iter().position(|&a| a == c)? as u32;
        let mut carry = digit;
        for b in &mut bytes {
            carry += u32::from(*b) * 58;
            *b = (carry & 0xff) as u8;
            carry >>= 8;
        }
        while carry > 0 {
            bytes.push((carry & 0xff) as u8);
            carry >>= 8;
        }
    }
    // leading '1's are leading zero bytes
    for c in s.bytes() {
        if c == b'1' {
            bytes.push(0);
        } else {
            break;
        }
    }
    bytes.reverse();
    Some(bytes)
}

/// One decoded account (pubkey base58 string + its raw bytes) for rendering.
pub struct SkewAccount<'a> {
    /// The account address (base58, from the RPC result — not re-encoded here).
    pub pubkey: &'a str,
    /// The raw account bytes (base64-decoded).
    pub data: &'a [u8],
}

/// Render a Skew portfolio / account-inventory from decoded accounts (PURE; the dispatch glue
/// supplies the base64-decoded accounts). If `owner_filter` is `Some`, only `UnifiedRiskAccount`s
/// whose decoded owner matches are counted as balances (others are still classified for the
/// inventory). 6-decimal settlement-mint amounts are shown as atoms (the agent scales for display).
#[must_use]
pub fn render_accounts(accounts: &[SkewAccount<'_>], owner_filter: Option<[u8; 32]>) -> String {
    let mut out = String::new();
    out.push_str("skew on-chain read (devnet; classified by verified discriminator)\n");
    let mut counts = [0usize; 9];
    let mut balances: Vec<(String, UraBalance)> = Vec::new();
    for a in accounts {
        let kind = classify(a.data);
        counts[kind_index(kind)] += 1;
        if kind == SkewAccountKind::UnifiedRiskAccount {
            if let Some(ura) = decode_ura_account(a.data) {
                if owner_filter.is_none_or(|o| ura.owner == o) {
                    balances.push((a.pubkey.to_string(), ura));
                }
            }
        }
    }
    out.push_str(&format!("  accounts: {} total — ", accounts.len()));
    out.push_str(&format!(
        "balances={} perp_positions={} piecewise={} templates={} perp_markets={} snapshots={} settlements={} funding={} unknown={}\n",
        counts[0], counts[1], counts[2], counts[3], counts[4], counts[5], counts[6], counts[7], counts[8]
    ));
    if !balances.is_empty() {
        out.push_str("  balances (UnifiedRiskAccount, atoms @ mint decimals):\n");
        for (pubkey, b) in &balances {
            let equity = b
                .equity()
                .map_or_else(|| "n/a(overflow)".to_string(), |e| e.to_string());
            out.push_str(&format!(
                "    {pubkey}: free={} locked_epoch={} locked_wcc={} equity={equity} status={}\n",
                b.free, b.locked_epoch, b.locked_wcc, b.status
            ));
        }
    }
    out
}

const fn kind_index(k: SkewAccountKind) -> usize {
    match k {
        SkewAccountKind::UnifiedRiskAccount => 0,
        SkewAccountKind::PerpPosition => 1,
        SkewAccountKind::PiecewiseContract => 2,
        SkewAccountKind::ProductTemplate => 3,
        SkewAccountKind::PerpMarket => 4,
        SkewAccountKind::ReferenceSnapshot => 5,
        SkewAccountKind::SettlementReceipt => 6,
        SkewAccountKind::FundingState => 7,
        SkewAccountKind::Unknown => 8,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A 207-byte URA account = disc ‖ body, with the LIVE devnet `4nANvajB…` $1,000 numbers
    /// (free $999.95 + locked_epoch $0.05 @ 6dp ⇒ equity $1,000.00 = 1_000_000_000 atoms).
    fn live_1000_dollar_ura() -> Vec<u8> {
        let mut acct = vec![0u8; URA_PDA_SPACE];
        acct[..8].copy_from_slice(&URA_DISCRIMINATOR);
        let body = &mut acct[8..];
        body[0..32].copy_from_slice(&[0x11u8; 32]); // owner
        body[32..64].copy_from_slice(&[0x22u8; 32]); // mint
        body[64..80].copy_from_slice(&999_950_000u128.to_le_bytes()); // free
        body[80..96].copy_from_slice(&50_000u128.to_le_bytes()); // locked_epoch
        body[197] = 1; // status = Active
        acct
    }

    #[test]
    fn ura_decode_is_byte_exact_and_equity_matches_live_1000() {
        let acct = live_1000_dollar_ura();
        let ura = decode_ura_account(&acct).expect("decodes");
        assert_eq!(ura.owner, [0x11u8; 32]);
        assert_eq!(ura.settlement_mint, [0x22u8; 32]);
        assert_eq!(ura.free, 999_950_000);
        assert_eq!(ura.locked_epoch, 50_000);
        assert_eq!(ura.locked_wcc, 0);
        assert_eq!(ura.status, 1);
        // equity = free + locked_epoch + locked_wcc + (backed - claimed) = $1,000.00 @ 6dp.
        assert_eq!(ura.equity(), Some(1_000_000_000));
    }

    #[test]
    fn decode_fail_closed_on_wrong_shape() {
        // Wrong discriminator ⇒ None (never mis-attribute).
        let mut acct = live_1000_dollar_ura();
        acct[0] ^= 0xff;
        assert!(decode_ura_account(&acct).is_none());
        // Wrong length ⇒ None.
        assert!(decode_ura_account(&[0u8; 10]).is_none());
        // equity underflow (claimed > backed) ⇒ None, never a fabricated number.
        let bad = UraBalance {
            owner: [0; 32],
            settlement_mint: [0; 32],
            free: 0,
            locked_epoch: 0,
            locked_wcc: 0,
            backed: 1,
            claimed: 5,
            status: 1,
        };
        assert!(bad.equity().is_none());
    }

    #[test]
    fn classify_matches_each_verified_discriminator() {
        let mk = |d: [u8; 8]| {
            let mut v = vec![0u8; 16];
            v[..8].copy_from_slice(&d);
            v
        };
        assert_eq!(
            classify(&mk(URA_DISCRIMINATOR)),
            SkewAccountKind::UnifiedRiskAccount
        );
        assert_eq!(
            classify(&mk(PERP_POSITION_DISCRIMINATOR)),
            SkewAccountKind::PerpPosition
        );
        assert_eq!(
            classify(&mk(PIECEWISE_CONTRACT_DISCRIMINATOR)),
            SkewAccountKind::PiecewiseContract
        );
        assert_eq!(
            classify(&mk(PRODUCT_TEMPLATE_DISCRIMINATOR)),
            SkewAccountKind::ProductTemplate
        );
        assert_eq!(
            classify(&mk(PERP_MARKET_DISCRIMINATOR)),
            SkewAccountKind::PerpMarket
        );
        assert_eq!(
            classify(&mk(REFERENCE_SNAPSHOT_DISCRIMINATOR)),
            SkewAccountKind::ReferenceSnapshot
        );
        assert_eq!(classify(&[0xAAu8; 16]), SkewAccountKind::Unknown);
        assert_eq!(classify(&[0u8; 4]), SkewAccountKind::Unknown);
    }

    #[test]
    fn base64_decode_known_vector() {
        assert_eq!(base64_decode("SGVsbG8="), Some(b"Hello".to_vec()));
        assert_eq!(base64_decode("TWFu"), Some(b"Man".to_vec()));
        assert_eq!(base64_decode("bad_char_!"), None);
    }

    #[test]
    fn base58_decode_known_vector() {
        // 32 '1's in base58 = 32 zero bytes (the system-program-style all-zero pubkey).
        assert_eq!(
            base58_decode("11111111111111111111111111111111"),
            Some(vec![0u8; 32])
        );
        // a single '2' = 1.
        assert_eq!(base58_decode("2"), Some(vec![1u8]));
        assert!(base58_decode("0OIl").is_none()); // chars not in the base58 alphabet
    }

    #[test]
    fn params_request_base64_with_datasize() {
        let p = program_accounts_params("BD4DSsED", 228);
        assert!(p.contains("\"dataSize\":228"));
        assert!(p.contains("\"encoding\":\"base64\""));
        assert!(p.contains("BD4DSsED"));
    }

    #[test]
    fn render_counts_inventory_and_balances_with_owner_filter() {
        let ura = live_1000_dollar_ura();
        let mut tmpl = vec![0u8; 228];
        tmpl[..8].copy_from_slice(&PRODUCT_TEMPLATE_DISCRIMINATOR);
        let accts = [
            SkewAccount {
                pubkey: "URA1",
                data: &ura,
            },
            SkewAccount {
                pubkey: "TPL1",
                data: &tmpl,
            },
        ];
        let r = render_accounts(&accts, Some([0x11u8; 32]));
        assert!(r.contains("balances=1"));
        assert!(r.contains("templates=1"));
        assert!(r.contains("equity=1000000000"));
        assert!(r.contains("URA1"));
        // a non-matching owner filter ⇒ the balance is excluded (still classified in counts).
        let r2 = render_accounts(&accts, Some([0x99u8; 32]));
        assert!(r2.contains("balances=1")); // count by kind
        assert!(!r2.contains("equity=")); // but no balance row for the wrong owner
    }

    /// PROVE every discriminator (the 6 live-confirmed + the 2 derived) is reproduced by the
    /// documented Anchor account-discriminator formula `sha256("account:<Name>")[..8]`. This is the
    /// grounding for the 2 NEW discriminators: the SAME formula that reproduces all 6 live-confirmed
    /// ones byte-exact produces the SettlementReceipt + FundingState ones — a documented derivation,
    /// not a guess.
    #[test]
    fn discriminators_match_anchor_derivation() {
        use sha2::{Digest, Sha256};
        let disc = |name: &str| -> [u8; 8] {
            let h = Sha256::digest(format!("account:{name}").as_bytes());
            let mut d = [0u8; 8];
            d.copy_from_slice(&h[..8]);
            d
        };
        assert_eq!(disc("UnifiedRiskAccountPda"), URA_DISCRIMINATOR);
        assert_eq!(disc("PerpPositionPda"), PERP_POSITION_DISCRIMINATOR);
        assert_eq!(
            disc("PiecewiseContractPda"),
            PIECEWISE_CONTRACT_DISCRIMINATOR
        );
        assert_eq!(disc("ProductTemplatePda"), PRODUCT_TEMPLATE_DISCRIMINATOR);
        assert_eq!(disc("PerpMarketPda"), PERP_MARKET_DISCRIMINATOR);
        assert_eq!(
            disc("ReferenceSnapshotPda"),
            REFERENCE_SNAPSHOT_DISCRIMINATOR
        );
        // the 2 NEW discriminators, derived by the SAME proven formula:
        assert_eq!(
            disc("SettlementReceiptPda"),
            SETTLEMENT_RECEIPT_DISCRIMINATOR
        );
        assert_eq!(disc("FundingStatePda"), FUNDING_STATE_DISCRIMINATOR);
    }

    /// A 153-byte ReferenceSnapshot account with the program's own layout-test vector
    /// (`reference_snapshot.rs:250-268`): composite = floor(65e9·10^6 / 150e6) = 433_333_333.
    fn ref_snapshot_account() -> Vec<u8> {
        let mut a = vec![0u8; REFERENCE_SNAPSHOT_PDA_SPACE];
        a[..8].copy_from_slice(&REFERENCE_SNAPSHOT_DISCRIMINATOR);
        let b = &mut a[8..];
        b[0..2].copy_from_slice(&0x00A1u16.to_le_bytes());
        b[2..10].copy_from_slice(&9u64.to_le_bytes());
        b[10..14].copy_from_slice(&11u32.to_le_bytes());
        b[14..22].copy_from_slice(&123_456u64.to_le_bytes());
        b[22..38].copy_from_slice(&65_000_000_000u128.to_le_bytes());
        b[38..54].copy_from_slice(&150_000_000u128.to_le_bytes());
        b[54..70].copy_from_slice(&433_333_333u128.to_le_bytes());
        b[70..72].copy_from_slice(&40u16.to_le_bytes());
        b[72..74].copy_from_slice(&12u16.to_le_bytes());
        b[74] = 6;
        b[75..79].copy_from_slice(&0xFFFF_FFFFu32.to_le_bytes());
        b[143] = 1; // Validated
        a
    }

    #[test]
    fn reference_snapshot_decode_is_byte_exact_and_composite_consistent() {
        let acct = ref_snapshot_account();
        let s = decode_reference_snapshot(&acct).expect("decodes");
        assert_eq!(s.policy_id, 0x00A1);
        assert_eq!(s.epoch_seq, 9);
        assert_eq!(s.source_id, 11);
        assert_eq!(s.observed_slot, 123_456);
        assert_eq!(s.numerator_atoms, 65_000_000_000);
        assert_eq!(s.divisor_atoms, 150_000_000);
        assert_eq!(s.composite_atoms, 433_333_333);
        assert_eq!(s.confidence_bps, 40);
        assert_eq!(s.bid_ask_spread_bps, 12);
        assert_eq!(s.exponent, 6);
        assert_eq!(s.validation_flags, 0xFFFF_FFFF);
        assert_eq!(s.status, 1);
        assert!(s.is_validated());
        // the deterministic composite cross-check re-derives the SAME stored composite:
        assert_eq!(s.recompute_composite(), Some(433_333_333));
        assert!(s.composite_consistent());
    }

    #[test]
    fn settlement_receipt_decode_is_byte_exact() {
        let mut a = vec![0u8; SETTLEMENT_RECEIPT_PDA_SPACE];
        a[..8].copy_from_slice(&SETTLEMENT_RECEIPT_DISCRIMINATOR);
        {
            let b = &mut a[8..];
            b[161..177].copy_from_slice(&110_000u128.to_le_bytes()); // settlement_price
            b[177..193].copy_from_slice(&10_000i128.to_le_bytes()); // signed_payoff
            b[257..273].copy_from_slice(&10_000u128.to_le_bytes()); // paid_amount
            b[289..321].copy_from_slice(&[0x88u8; 32]); // settlement_mint
            b[393..401].copy_from_slice(&1_234_567_890u64.to_le_bytes()); // created_slot
        }
        let r = decode_settlement_receipt(&a).expect("decodes");
        assert_eq!(r.settlement_price, 110_000);
        assert_eq!(r.signed_payoff_amount, 10_000);
        assert_eq!(r.paid_amount, 10_000);
        assert_eq!(r.created_slot, 1_234_567_890);
        assert_eq!(r.settlement_mint, [0x88u8; 32]);
    }

    #[test]
    fn funding_state_decode_is_byte_exact_signed() {
        let mut a = vec![0u8; FUNDING_STATE_PDA_SPACE];
        a[..8].copy_from_slice(&FUNDING_STATE_DISCRIMINATOR);
        {
            let b = &mut a[8..];
            b[0..32].copy_from_slice(&[0x44u8; 32]); // market_id
            b[32..48].copy_from_slice(&(-987_654i128).to_le_bytes()); // signed cumulative index
            b[48..56].copy_from_slice(&12_345u64.to_le_bytes()); // max_rate
            b[56..64].copy_from_slice(&7_777u64.to_le_bytes()); // last_snapshot_slot
            b[64] = 1; // Active
        }
        let f = decode_funding_state(&a).expect("decodes");
        assert_eq!(f.market_id, [0x44u8; 32]);
        assert_eq!(f.cumulative_funding_index, -987_654);
        assert_eq!(f.max_rate, 12_345);
        assert_eq!(f.last_snapshot_slot, 7_777);
        assert_eq!(f.status, 1);
    }

    #[test]
    fn new_decoders_fail_closed_on_wrong_shape() {
        // Wrong discriminator ⇒ None (a 153-byte perp market is NOT a snapshot).
        let mut snap = ref_snapshot_account();
        snap[0] ^= 0xff;
        assert!(decode_reference_snapshot(&snap).is_none());
        // Wrong length ⇒ None for each.
        assert!(decode_reference_snapshot(&[0u8; 10]).is_none());
        assert!(decode_settlement_receipt(&[0u8; 10]).is_none());
        assert!(decode_funding_state(&[0u8; 10]).is_none());
        // A correct-length-but-wrong-disc settlement / funding ⇒ None.
        let bad_settle = vec![0u8; SETTLEMENT_RECEIPT_PDA_SPACE]; // all-zero disc
        assert!(decode_settlement_receipt(&bad_settle).is_none());
        let bad_funding = vec![0u8; FUNDING_STATE_PDA_SPACE];
        assert!(decode_funding_state(&bad_funding).is_none());
        // composite cross-check rejects a tampered composite (divisor=0 ⇒ None).
        let zero_div = ReferenceSnapshotData {
            policy_id: 0,
            epoch_seq: 0,
            source_id: 0,
            observed_slot: 0,
            numerator_atoms: 1,
            divisor_atoms: 0,
            composite_atoms: 7,
            confidence_bps: 0,
            bid_ask_spread_bps: 0,
            exponent: 6,
            validation_flags: 0,
            status: 1,
        };
        assert_eq!(zero_div.recompute_composite(), None);
        assert!(!zero_div.composite_consistent());
    }

    #[test]
    fn classify_covers_settlement_and_funding() {
        let mk = |d: [u8; 8]| {
            let mut v = vec![0u8; 16];
            v[..8].copy_from_slice(&d);
            v
        };
        assert_eq!(
            classify(&mk(SETTLEMENT_RECEIPT_DISCRIMINATOR)),
            SkewAccountKind::SettlementReceipt
        );
        assert_eq!(
            classify(&mk(FUNDING_STATE_DISCRIMINATOR)),
            SkewAccountKind::FundingState
        );
    }

    /// A 154-byte PerpPosition account = disc ‖ 146-byte body carrying the verified source's OWN Pod
    /// round-trip vector (`perp_position.rs:294-343`): a net-SHORT position (signed_qty = −1234) with a
    /// negative net notional, a reserved E_epoch of 123_456_789 atoms, status = Open, bump = 251. Built
    /// at the byte-exact field offsets so the decode is grounded in the on-chain layout test, not a
    /// guess.
    fn golden_perp_position() -> Vec<u8> {
        let mut a = vec![0u8; PERP_POSITION_PDA_SPACE];
        a[..8].copy_from_slice(&PERP_POSITION_DISCRIMINATOR);
        let b = &mut a[8..];
        b[0..32].copy_from_slice(&[0x11u8; 32]); // market_id
        b[32..64].copy_from_slice(&[0x22u8; 32]); // owner
        b[64..72].copy_from_slice(&(-1234i64).to_le_bytes()); // signed_qty
        b[72..88].copy_from_slice(&(-98_765_432_100i128).to_le_bytes()); // entry_notional
        b[88..104].copy_from_slice(&7_000_000i128.to_le_bytes()); // funding_snapshot
        b[104..112].copy_from_slice(&0x0102_0304_0506_0708u64.to_le_bytes()); // last_epoch_seq
        b[112..128].copy_from_slice(&0u128.to_le_bytes()); // pending_profit
        b[128..144].copy_from_slice(&123_456_789u128.to_le_bytes()); // reserved_collateral
        b[144] = 1; // status = Open
        b[145] = 251; // bump
        a
    }

    #[test]
    fn perp_position_decode_is_byte_exact_signed() {
        let acct = golden_perp_position();
        let p = decode_perp_position(&acct).expect("decodes");
        assert_eq!(p.market_id, [0x11u8; 32]);
        assert_eq!(p.owner, [0x22u8; 32]);
        assert_eq!(p.signed_qty, -1234);
        assert_eq!(p.entry_notional, -98_765_432_100);
        assert_eq!(p.funding_snapshot, 7_000_000);
        assert_eq!(p.last_epoch_seq, 0x0102_0304_0506_0708);
        assert_eq!(p.pending_profit, 0);
        assert_eq!(p.reserved_collateral, 123_456_789);
        assert_eq!(p.status, 1);
        assert_eq!(p.bump, 251);
        // pure projections of the decoded sign / status (never fabricated):
        assert!(p.is_open());
        assert!(!p.is_flat());
        assert_eq!(p.direction(), "short");
        // the skew_read full decode AGREES with the skew_oracle escrow-subset decode on the shared
        // fields (one byte layout, two readers) — a cross-decoder consistency pin.
        let esc = crate::skew_oracle::decode_perp_position(&acct).expect("escrow decodes");
        assert_eq!(esc.market_id, p.market_id);
        assert_eq!(esc.signed_qty, p.signed_qty);
        assert_eq!(esc.entry_notional, p.entry_notional);
        assert_eq!(esc.reserved_collateral, p.reserved_collateral);
        assert_eq!(esc.status, p.status);
    }

    #[test]
    fn perp_position_decode_fail_closed_on_wrong_shape() {
        // Wrong discriminator ⇒ None (never mis-attribute a 154-byte non-position).
        let mut acct = golden_perp_position();
        acct[0] ^= 0xff;
        assert!(decode_perp_position(&acct).is_none());
        // Wrong length ⇒ None (one byte short / long).
        assert!(decode_perp_position(&golden_perp_position()[..153]).is_none());
        assert!(decode_perp_position(&[0u8; 10]).is_none());
        // A correct-length all-zero (Uninit) body has the WRONG (all-zero) disc ⇒ None.
        assert!(decode_perp_position(&[0u8; PERP_POSITION_PDA_SPACE]).is_none());
        // A flat (signed_qty == 0) but Open position reads "flat".
        let mut flat = golden_perp_position();
        flat[8 + 64..8 + 72].copy_from_slice(&0i64.to_le_bytes());
        let fp = decode_perp_position(&flat).expect("decodes");
        assert!(fp.is_flat());
        assert_eq!(fp.direction(), "flat");
    }

    #[test]
    fn render_positions_owner_scopes_and_counts() {
        let pos = golden_perp_position(); // owner = [0x22; 32], short
        // a SECOND position owned by a different key (long), so the owner filter is load-bearing.
        let mut pos2 = golden_perp_position();
        pos2[8 + 32..8 + 64].copy_from_slice(&[0x33u8; 32]); // owner
        pos2[8 + 64..8 + 72].copy_from_slice(&500i64.to_le_bytes()); // signed_qty = +500 (long)
        // a non-position account (template) is ignored by render_positions.
        let mut tmpl = vec![0u8; 228];
        tmpl[..8].copy_from_slice(&PRODUCT_TEMPLATE_DISCRIMINATOR);
        let accts = [
            SkewAccount {
                pubkey: "POS1",
                data: &pos,
            },
            SkewAccount {
                pubkey: "POS2",
                data: &pos2,
            },
            SkewAccount {
                pubkey: "TPL1",
                data: &tmpl,
            },
        ];
        // owner-scoped to 0x22 ⇒ both counted (2 decoded), only POS1 listed.
        let r = render_positions(&accts, Some([0x22u8; 32]));
        assert!(r.contains("2 decoded (1 listed, owner-scoped)"));
        assert!(r.contains("POS1: dir=short"));
        assert!(!r.contains("POS2"));
        // no filter ⇒ both listed.
        let all = render_positions(&accts, None);
        assert!(all.contains("2 decoded (2 listed)"));
        assert!(all.contains("POS1: dir=short"));
        assert!(all.contains("POS2: dir=long"));
        // an owner with no positions ⇒ honest empty render (no fabricated row).
        let none = render_positions(&accts, Some([0x99u8; 32]));
        assert!(none.contains("2 decoded (0 listed, owner-scoped)"));
        assert!(none.contains("(no matching perp positions on this read)"));
    }

    /// A 267-byte PiecewiseContract account built at the documented account-offset table
    /// (`piecewise_contract.rs:128-145`): an Active (status 1) self-cross (long == short == 0x22)
    /// straddle with escrow_long = 7000 + escrow_short = 9000 atoms. Grounded in the on-chain offsets,
    /// not a guess.
    fn golden_piecewise_contract() -> Vec<u8> {
        let mut a = vec![0u8; PIECEWISE_CONTRACT_PDA_SPACE];
        a[..8].copy_from_slice(&PIECEWISE_CONTRACT_DISCRIMINATOR);
        let b = &mut a[8..];
        b[0..32].copy_from_slice(&[0x01u8; 32]); // contract_id
        b[32..64].copy_from_slice(&[0x02u8; 32]); // template_id
        b[64..96].copy_from_slice(&[0x03u8; 32]); // payoff_descriptor_hash
        b[96..128].copy_from_slice(&[0x22u8; 32]); // long_party
        b[128..160].copy_from_slice(&[0x22u8; 32]); // short_party (self-cross)
        b[160..192].copy_from_slice(&[0x44u8; 32]); // settlement_mint
        b[192..224].copy_from_slice(&[0x55u8; 32]); // collateral_vault
        b[224..232].copy_from_slice(&7_000u64.to_le_bytes()); // escrow_long
        b[232..240].copy_from_slice(&9_000u64.to_le_bytes()); // escrow_short
        b[240..248].copy_from_slice(&1_700_000_000i64.to_le_bytes()); // maturity_timestamp
        b[248..256].copy_from_slice(&987_654u64.to_le_bytes()); // created_slot
        b[256] = 1; // status = Active
        b[257] = 0b11; // party_roles = BOTH_SIGNED
        b[258] = 250; // bump
        a
    }

    #[test]
    fn piecewise_contract_decode_is_byte_exact_and_scopes() {
        let acct = golden_piecewise_contract();
        let c = decode_piecewise_contract(&acct).expect("decodes");
        assert_eq!(c.contract_id, [0x01u8; 32]);
        assert_eq!(c.template_id, [0x02u8; 32]);
        assert_eq!(c.payoff_descriptor_hash, [0x03u8; 32]);
        assert_eq!(c.long_party, [0x22u8; 32]);
        assert_eq!(c.short_party, [0x22u8; 32]);
        assert_eq!(c.settlement_mint, [0x44u8; 32]);
        assert_eq!(c.collateral_vault, [0x55u8; 32]);
        assert_eq!(c.escrow_long, 7_000);
        assert_eq!(c.escrow_short, 9_000);
        assert_eq!(c.maturity_timestamp, 1_700_000_000);
        assert_eq!(c.created_slot, 987_654);
        assert_eq!(c.status, 1);
        assert_eq!(c.party_roles, 0b11);
        assert_eq!(c.bump, 250);
        assert!(c.is_active());
        assert!(!c.is_settled());
        assert_eq!(c.total_escrow(), Some(16_000));
        assert!(c.involves([0x22u8; 32])); // the party is long==short here
        assert!(!c.involves([0x99u8; 32]));
        // fail-closed: wrong disc / wrong length ⇒ None.
        let mut bad = golden_piecewise_contract();
        bad[0] ^= 0xff;
        assert!(decode_piecewise_contract(&bad).is_none());
        assert!(decode_piecewise_contract(&golden_piecewise_contract()[..266]).is_none());
        assert!(decode_piecewise_contract(&[0u8; PIECEWISE_CONTRACT_PDA_SPACE]).is_none());
    }

    #[test]
    fn render_contracts_party_scopes_and_counts() {
        let c1 = golden_piecewise_contract(); // long == short == 0x22
        // a SECOND contract between 0x33 (long) and 0x44 (short), so the party filter is load-bearing.
        let mut c2 = golden_piecewise_contract();
        c2[8 + 96..8 + 128].copy_from_slice(&[0x33u8; 32]); // long_party
        c2[8 + 128..8 + 160].copy_from_slice(&[0x44u8; 32]); // short_party
        c2[8 + 256] = 6; // status = Settled
        let accts = [
            SkewAccount {
                pubkey: "PC1",
                data: &c1,
            },
            SkewAccount {
                pubkey: "PC2",
                data: &c2,
            },
        ];
        // party-scoped to 0x44 ⇒ both counted, only PC2 listed (0x44 is its short party).
        let r = render_contracts(&accts, Some([0x44u8; 32]));
        assert!(r.contains("2 decoded (1 listed, party-scoped)"));
        assert!(r.contains("PC2: status=6(settled)"));
        assert!(!r.contains("PC1:"));
        // no filter ⇒ both listed, with honest lifecycle + total escrow.
        let all = render_contracts(&accts, None);
        assert!(all.contains("2 decoded (2 listed)"));
        assert!(all.contains("PC1: status=1(active)"));
        assert!(all.contains("total_escrow=16000"));
    }
}
