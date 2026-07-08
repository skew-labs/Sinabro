//! `solana_codec` — the PURE, byte-exact Solana
//! transaction codec. NO `solana-sdk` (no heavy Solana crates): the legacy
//! message / shortvec / `find_program_address` wire format is implemented FAITHFULLY from the
//! public, stable Solana spec using `sha2` + `curve25519-dalek` (both already in the build closure),
//! golden-tested, and validated by the LIVE devnet simulate (the live Skew program is the ultimate
//! byte-correctness oracle — a wrong byte ⇒ the program rejects, -9).
//!
//! ## What this builds (PURE — no network, no key)
//! - [`find_program_address`] — the EXACT Anchor / Solana PDA derivation (`sha256(seeds ‖ bump ‖
//!   program_id ‖ "ProgramDerivedAddress")`, bump `255→0`, off-curve via
//!   `curve25519_dalek::CompressedEdwardsY::decompress().is_none()` — byte-identical to Solana's
//!   `bytes_are_curve_point`).
//! - [`compile_legacy_message`] — the legacy `Message` wire bytes (the thing that is SIGNED and that
//!   D13 compares): 3-byte header + shortvec(account_keys) + recent_blockhash(32) +
//!   shortvec(instructions). Accounts are de-duplicated and bucketed `[writable-signer,
//!   readonly-signer, writable-nonsigner, readonly-nonsigner]` (the runtime reads privileges from
//!   POSITION + the header counts), fee payer first.
//! - the byte-exact Skew `PROTOCOL_PERP` instruction builders:
//!   `open_risk_account` (0x0060) → `deposit_margin` (0x0061) → `submit_perp_order` (0x0071) — the
//!   perp trade lifecycle. Each is a u16-LE discriminator ‖
//!   borsh-LE descriptor + the handler's exact account-meta order + the cited PDA seeds.
//!
//! ## Sources (cited, never guessed)
//! - discriminators u16-LE: `skew-mainnet/programs/skew_otc/src/dispatcher_band.rs:102,105,176`
//!   (`DISC_OPEN_RISK_ACCOUNT=0x0060` / `DISC_DEPOSIT_MARGIN=0x0061` / `DISC_SUBMIT_PERP_ORDER=0x0071`).
//! - account-meta order + PDA seeds: the handler `#[derive(Accounts)]`
//!   (`open_risk_account.rs:41-105`, `deposit_margin.rs:41-85`, `submit_perp_order.rs:117-209`).
//! - descriptor byte layout: `sdk/src/encoder.ts` (`buildOpenRiskAccountInstructionData` 2 B /
//!   `encodeDepositMarginDescriptor` u64 LE / `encodeSubmitPerpOrderDescriptor` 102 B).
//! - the legacy message + the 3-beat (D2/D3/D13/D14): FE `assemble.ts` / `actions.ts`; the Solana
//!   wire format is the public spec.

/// A 32-byte Solana account address (base58 on the wire / for display, raw bytes in a message).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Pubkey(pub [u8; 32]);

impl Pubkey {
    /// Parse a base58 pubkey STRING into its 32 raw bytes (fail-closed: `None` unless exactly 32
    /// bytes decode). Reuses the verified `skew_read` base58 decoder.
    #[must_use]
    pub fn from_base58(s: &str) -> Option<Self> {
        let bytes = crate::skew_read::base58_decode(s)?;
        let arr: [u8; 32] = bytes.try_into().ok()?;
        Some(Self(arr))
    }

    /// The base58 string form (for display / the D14 genesis compare / the explorer URL).
    #[must_use]
    pub fn to_base58(&self) -> String {
        base58_encode(&self.0)
    }
}

// ============================================================================
// Well-known program / sysvar ids (base58 — decoded at build via `from_base58`).
// ============================================================================

/// SPL Token program.
pub const TOKEN_PROGRAM_ID: &str = "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA";
/// Associated-Token-Account program.
pub const ASSOCIATED_TOKEN_PROGRAM_ID: &str = "ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL";
/// Rent sysvar.
pub const RENT_SYSVAR_ID: &str = "SysvarRent111111111111111111111111111111111";
/// Compute-Budget program (the `setComputeUnitLimit` instruction target).
pub const COMPUTE_BUDGET_PROGRAM_ID: &str = "ComputeBudget111111111111111111111111111111";
/// The Solana devnet GENESIS hash — the D14 cluster pin (FE `assemble.ts:101`). A tx assembled for
/// devnet is REFUSED against any other cluster (-7 / -11).
pub const DEVNET_GENESIS_HASH: &str = "EtWTRABZaYq6iMfeYKouRu166VU2xqa1wcaWoxPkrZBG";

/// The System program (32 zero bytes — `11111111111111111111111111111111`).
#[must_use]
pub const fn system_program_id() -> Pubkey {
    Pubkey([0u8; 32])
}

// ============================================================================
// shortvec (compact-u16) + base58 / base64 encode.
// ============================================================================

/// Append a Solana compact-u16 (shortvec) length prefix: 7 bits per byte, MSB = continuation.
fn push_compact_u16(out: &mut Vec<u8>, mut len: usize) {
    loop {
        let mut byte = (len & 0x7f) as u8;
        len >>= 7;
        if len != 0 {
            byte |= 0x80;
        }
        out.push(byte);
        if len == 0 {
            break;
        }
    }
}

/// Base58 (Bitcoin alphabet) ENCODE — the inverse of `skew_read::base58_decode`. Used for pubkey /
/// signature display + the explorer URL. PURE (no dependency).
#[must_use]
pub fn base58_encode(input: &[u8]) -> String {
    const ALPHABET: &[u8; 58] = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
    // count leading zero bytes (each ⇒ a leading '1').
    let zeros = input.iter().take_while(|&&b| b == 0).count();
    let mut digits: Vec<u8> = Vec::new();
    for &byte in input {
        let mut carry = u32::from(byte);
        for d in &mut digits {
            carry += u32::from(*d) << 8;
            *d = (carry % 58) as u8;
            carry /= 58;
        }
        while carry > 0 {
            digits.push((carry % 58) as u8);
            carry /= 58;
        }
    }
    let mut out = String::with_capacity(zeros + digits.len());
    for _ in 0..zeros {
        out.push('1');
    }
    for &d in digits.iter().rev() {
        out.push(ALPHABET[d as usize] as char);
    }
    if out.is_empty() {
        out.push('1');
    }
    out
}

/// Standard base64 ENCODE (with `=` padding) — the inverse of `skew_read::base64_decode`. Used to
/// place the serialized transaction in a `sendTransaction` / `simulateTransaction` JSON-RPC param.
#[must_use]
pub fn base64_encode(input: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(input.len().div_ceil(3) * 4);
    for chunk in input.chunks(3) {
        let b0 = u32::from(chunk[0]);
        let b1 = chunk.get(1).map_or(0, |&b| u32::from(b));
        let b2 = chunk.get(2).map_or(0, |&b| u32::from(b));
        let n = (b0 << 16) | (b1 << 8) | b2;
        out.push(ALPHABET[((n >> 18) & 0x3f) as usize] as char);
        out.push(ALPHABET[((n >> 12) & 0x3f) as usize] as char);
        if chunk.len() > 1 {
            out.push(ALPHABET[((n >> 6) & 0x3f) as usize] as char);
        } else {
            out.push('=');
        }
        if chunk.len() > 2 {
            out.push(ALPHABET[(n & 0x3f) as usize] as char);
        } else {
            out.push('=');
        }
    }
    out
}

// ============================================================================
// PDA derivation — EXACT (sha2 + curve25519 off-curve), Solana `find_program_address`.
// ============================================================================

/// Whether a 32-byte value decompresses to a valid ed25519 curve point — Solana's
/// `bytes_are_curve_point`. A PDA is an address that is NOT on the curve (so no private key exists).
fn is_on_curve(bytes: &[u8; 32]) -> bool {
    curve25519_dalek::edwards::CompressedEdwardsY::from_slice(bytes)
        .ok()
        .and_then(|c| c.decompress())
        .is_some()
}

/// The maximum number of seeds Solana permits.
const MAX_SEEDS: usize = 16;
/// The maximum length of a single seed.
const MAX_SEED_LEN: usize = 32;

/// Derive a Program-Derived Address: the first off-curve `sha256(seeds ‖ [bump] ‖ program_id ‖
/// "ProgramDerivedAddress")` with `bump` descending from 255. Returns `(pda, bump)` or `None`
/// (fail-closed) if a seed is over-long, there are too many seeds, or no bump yields an off-curve
/// address (the last is astronomically improbable). Byte-identical to Anchor's auto-`bump`.
#[must_use]
pub fn find_program_address(seeds: &[&[u8]], program_id: &Pubkey) -> Option<(Pubkey, u8)> {
    use sha2::{Digest, Sha256};
    if seeds.len() >= MAX_SEEDS {
        return None;
    }
    for s in seeds {
        if s.len() > MAX_SEED_LEN {
            return None;
        }
    }
    let mut bump: u8 = 255;
    loop {
        let mut hasher = Sha256::new();
        for s in seeds {
            hasher.update(s);
        }
        hasher.update([bump]);
        hasher.update(program_id.0);
        hasher.update(b"ProgramDerivedAddress");
        let digest: [u8; 32] = hasher.finalize().into();
        if !is_on_curve(&digest) {
            return Some((Pubkey(digest), bump));
        }
        bump = bump.checked_sub(1)?;
    }
}

/// The owner's associated token account for a mint — `find_program_address([owner, TOKEN_PROGRAM,
/// mint], ASSOCIATED_TOKEN_PROGRAM)` (the standard SPL ATA derivation; `deposit_margin`'s
/// `depositor_token_account`).
#[must_use]
pub fn associated_token_address(owner: &Pubkey, mint: &Pubkey) -> Option<Pubkey> {
    let token = Pubkey::from_base58(TOKEN_PROGRAM_ID)?;
    let ata_prog = Pubkey::from_base58(ASSOCIATED_TOKEN_PROGRAM_ID)?;
    let (pda, _bump) = find_program_address(&[&owner.0, &token.0, &mint.0], &ata_prog)?;
    Some(pda)
}

// ============================================================================
// Instruction / AccountMeta + the legacy message compiler.
// ============================================================================

/// One account reference inside an instruction (the handler-facing order is THIS order — the
/// runtime resolves the instruction's account indices in sequence).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AccountMeta {
    /// The account address.
    pub pubkey: Pubkey,
    /// Whether the account must sign.
    pub is_signer: bool,
    /// Whether the account is written.
    pub is_writable: bool,
}

impl AccountMeta {
    /// A writable account (signer or not).
    #[must_use]
    pub fn writable(pubkey: Pubkey, is_signer: bool) -> Self {
        Self {
            pubkey,
            is_signer,
            is_writable: true,
        }
    }
    /// A read-only account (signer or not).
    #[must_use]
    pub fn readonly(pubkey: Pubkey, is_signer: bool) -> Self {
        Self {
            pubkey,
            is_signer,
            is_writable: false,
        }
    }
}

/// One Solana instruction: the target program + the ordered account metas + the raw data bytes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Instruction {
    /// The program this instruction invokes.
    pub program_id: Pubkey,
    /// The account metas IN THE HANDLER'S ORDER.
    pub accounts: Vec<AccountMeta>,
    /// The raw instruction data (discriminator ‖ descriptor).
    pub data: Vec<u8>,
}

/// Compile a legacy `Message` to its wire bytes — the thing that is SIGNED and that D13 compares.
/// Accounts are de-duplicated (privileges OR-ed), the `fee_payer` is forced first (writable
/// signer), and all keys are bucketed `[writable-signer, readonly-signer, writable-nonsigner,
/// readonly-nonsigner]` (the legacy runtime reads each account's privileges from its POSITION + the
/// 3 header counts). Program ids are added as read-only non-signers. Returns the serialized message.
#[must_use]
pub fn compile_legacy_message(
    fee_payer: &Pubkey,
    instructions: &[Instruction],
    recent_blockhash: &[u8; 32],
) -> Vec<u8> {
    // 1. collect unique accounts in first-appearance order, OR-ing privileges. Fee payer first
    //    (writable signer); then each instruction's program id (readonly non-signer) + accounts.
    let mut order: Vec<Pubkey> = Vec::new();
    let mut signer: std::collections::HashMap<Pubkey, bool> = std::collections::HashMap::new();
    let mut writable: std::collections::HashMap<Pubkey, bool> = std::collections::HashMap::new();
    let mut see = |key: Pubkey, is_signer: bool, is_writable: bool, order: &mut Vec<Pubkey>| {
        use std::collections::hash_map::Entry;
        match signer.entry(key) {
            Entry::Vacant(slot) => {
                order.push(key);
                slot.insert(is_signer);
                writable.insert(key, is_writable);
            }
            Entry::Occupied(mut slot) => {
                let merged = *slot.get() || is_signer;
                slot.insert(merged);
                if let Some(w) = writable.get_mut(&key) {
                    *w = *w || is_writable;
                }
            }
        }
    };
    see(*fee_payer, true, true, &mut order);
    for ix in instructions {
        for m in &ix.accounts {
            see(m.pubkey, m.is_signer, m.is_writable, &mut order);
        }
    }
    for ix in instructions {
        see(ix.program_id, false, false, &mut order);
    }

    // 2. bucket into the 4 privilege groups (stable, first-appearance order within each).
    let is_s = |k: &Pubkey| signer.get(k).copied().unwrap_or(false);
    let is_w = |k: &Pubkey| writable.get(k).copied().unwrap_or(false);
    let mut keys: Vec<Pubkey> = Vec::with_capacity(order.len());
    for k in order.iter().filter(|k| is_s(k) && is_w(k)) {
        keys.push(*k);
    }
    let n_ws = keys.len();
    for k in order.iter().filter(|k| is_s(k) && !is_w(k)) {
        keys.push(*k);
    }
    let n_rs = keys.len() - n_ws;
    for k in order.iter().filter(|k| !is_s(k) && is_w(k)) {
        keys.push(*k);
    }
    for k in order.iter().filter(|k| !is_s(k) && !is_w(k)) {
        keys.push(*k);
    }
    let n_rn = keys.iter().filter(|k| !is_s(k) && !is_w(k)).count();

    // 3. header (legacy): num_required_signatures, num_readonly_signed, num_readonly_unsigned.
    let num_required_signatures = (n_ws + n_rs) as u8;
    let num_readonly_signed = n_rs as u8;
    let num_readonly_unsigned = n_rn as u8;

    // index lookup for the instructions.
    let index_of = |k: &Pubkey| keys.iter().position(|x| x == k).unwrap_or(0) as u8;

    // 4. serialize.
    let mut out: Vec<u8> = Vec::new();
    out.push(num_required_signatures);
    out.push(num_readonly_signed);
    out.push(num_readonly_unsigned);
    push_compact_u16(&mut out, keys.len());
    for k in &keys {
        out.extend_from_slice(&k.0);
    }
    out.extend_from_slice(recent_blockhash);
    push_compact_u16(&mut out, instructions.len());
    for ix in instructions {
        out.push(index_of(&ix.program_id));
        push_compact_u16(&mut out, ix.accounts.len());
        for m in &ix.accounts {
            out.push(index_of(&m.pubkey));
        }
        push_compact_u16(&mut out, ix.data.len());
        out.extend_from_slice(&ix.data);
    }
    out
}

/// Serialize a full transaction: `shortvec(signatures) ‖ message`. For a single-signer tx, pass one
/// 64-byte signature (the real one for broadcast, or a zeroed placeholder for a `sigVerify:false`
/// simulate). The signed-transaction wire form for `sendTransaction` / `simulateTransaction`.
#[must_use]
pub fn serialize_transaction(message: &[u8], signatures: &[[u8; 64]]) -> Vec<u8> {
    let mut out: Vec<u8> = Vec::new();
    push_compact_u16(&mut out, signatures.len());
    for sig in signatures {
        out.extend_from_slice(sig);
    }
    out.extend_from_slice(message);
    out
}

// ============================================================================
// Compute-budget + the byte-exact Skew PROTOCOL_PERP instruction builders.
// ============================================================================

/// `ComputeBudgetProgram.setComputeUnitLimit(units)` — instruction tag `0x02` ‖ `u32 LE` units, NO
/// accounts (the FE prepends this; `assemble.ts` `finalizeTx`). Keeps the init-heavy
/// `open_risk_account` from CU-starving.
#[must_use]
pub fn compute_unit_limit_ix(units: u32) -> Option<Instruction> {
    let program_id = Pubkey::from_base58(COMPUTE_BUDGET_PROGRAM_ID)?;
    let mut data = vec![0x02u8];
    data.extend_from_slice(&units.to_le_bytes());
    Some(Instruction {
        program_id,
        accounts: Vec::new(),
        data,
    })
}

/// `ComputeBudgetProgram.setComputeUnitPrice(micro_lamports)` — instruction tag `0x03` ‖ `u64 LE`
/// micro-lamports-PER-CU (the PRIORITY FEE that wins fast inclusion), NO accounts. Byte-cited from the
/// Skew FE's own apparatus (`Skew-frontend/tools/devnet/form_fixed_forward.mjs:200`
/// `ComputeBudgetProgram.setComputeUnitPrice({microLamports:500000})`,
/// `register_token_markets.mjs:160` `{microLamports:50000}`) — the FE prepends it "so the tx lands
/// under devnet congestion." Pairs with [`compute_unit_limit_ix`] (tag 0x02). Fail-closed on a bad id.
#[must_use]
pub fn compute_unit_price_ix(micro_lamports: u64) -> Option<Instruction> {
    let program_id = Pubkey::from_base58(COMPUTE_BUDGET_PROGRAM_ID)?;
    let mut data = vec![0x03u8];
    data.extend_from_slice(&micro_lamports.to_le_bytes());
    Some(Instruction {
        program_id,
        accounts: Vec::new(),
        data,
    })
}

/// The Skew `skew_otc` program id (devnet) as a [`Pubkey`].
#[must_use]
pub fn skew_program_id() -> Option<Pubkey> {
    Pubkey::from_base58(crate::skew_catalog::SKEW_PROGRAM_ID_DEVNET)
}

/// `open_risk_account` (disc 0x0060) — open the per-(owner,mint) `UnifiedRiskAccount` + the margin
/// pool + the perp margin vault (+ authority). Data = `[0x60, 0x00]` (NO descriptor —
/// `encoder.ts:1942`). Accounts byte-exact from `open_risk_account.rs:41-105`; PDA seeds cited.
/// `owner` is the fee-paying signer (the isolated Sinabro key). Fail-closed on any PDA / id failure.
#[must_use]
pub fn ix_open_risk_account(owner: &Pubkey, settlement_mint: &Pubkey) -> Option<Instruction> {
    let program = skew_program_id()?;
    let (ura, _b1) = find_program_address(
        &[b"unified_risk_account", &owner.0, &settlement_mint.0],
        &program,
    )?;
    let (pool, _b2) =
        find_program_address(&[b"unified_margin_pool", &settlement_mint.0], &program)?;
    let (vault, _b3) = find_program_address(&[b"perp_margin_vault", &settlement_mint.0], &program)?;
    let (vault_auth, _b4) = find_program_address(
        &[b"perp_margin_vault_authority", &settlement_mint.0],
        &program,
    )?;
    let token = Pubkey::from_base58(TOKEN_PROGRAM_ID)?;
    let rent = Pubkey::from_base58(RENT_SYSVAR_ID)?;
    let accounts = vec![
        AccountMeta::writable(*owner, true), // owner (signer, mut) — fee payer
        AccountMeta::readonly(*settlement_mint, false), // settlement_mint
        AccountMeta::writable(ura, false),   // unified_risk_account (init)
        AccountMeta::writable(pool, false),  // margin_pool (init_if_needed)
        AccountMeta::writable(vault, false), // perp_margin_vault (init_if_needed)
        AccountMeta::readonly(vault_auth, false), // perp_margin_vault_authority
        AccountMeta::readonly(token, false), // token_program
        AccountMeta::readonly(system_program_id(), false), // system_program
        AccountMeta::readonly(rent, false),  // rent
    ];
    Some(Instruction {
        program_id: program,
        accounts,
        data: vec![0x60, 0x00],
    })
}

/// `deposit_margin` (disc 0x0061) — SPL-transfer `amount` settlement-mint atoms IN, raising free
/// collateral. Data = `[0x61, 0x00] ‖ u64 LE amount` (`encoder.ts:1678`). Accounts byte-exact from
/// `deposit_margin.rs:41-85`; the `depositor_token_account` is the owner's ATA (derived). The
/// `amount` MUST equal the custody-authorized amount (-3, asserted by the caller).
#[must_use]
pub fn ix_deposit_margin(
    owner: &Pubkey,
    settlement_mint: &Pubkey,
    amount: u64,
) -> Option<Instruction> {
    let program = skew_program_id()?;
    let (ura, _b1) = find_program_address(
        &[b"unified_risk_account", &owner.0, &settlement_mint.0],
        &program,
    )?;
    let (pool, _b2) =
        find_program_address(&[b"unified_margin_pool", &settlement_mint.0], &program)?;
    let (vault, _b3) = find_program_address(&[b"perp_margin_vault", &settlement_mint.0], &program)?;
    let depositor_ata = associated_token_address(owner, settlement_mint)?;
    let token = Pubkey::from_base58(TOKEN_PROGRAM_ID)?;
    let mut data = vec![0x61u8, 0x00];
    data.extend_from_slice(&amount.to_le_bytes());
    let accounts = vec![
        AccountMeta::writable(*owner, true), // owner (signer, mut)
        AccountMeta::readonly(*settlement_mint, false), // settlement_mint
        AccountMeta::writable(ura, false),   // unified_risk_account (mut)
        AccountMeta::writable(pool, false),  // margin_pool (mut)
        AccountMeta::writable(vault, false), // perp_margin_vault (mut)
        AccountMeta::writable(depositor_ata, false), // depositor_token_account (owner ATA)
        AccountMeta::readonly(token, false), // token_program
    ];
    Some(Instruction {
        program_id: program,
        accounts,
        data,
    })
}

/// `withdraw_margin` (disc 0x0062) — release `amount` settlement-mint atoms OUT of the per-mint
/// omnibus vault to the owner's receiver ATA (vault-authority-signed on-chain). Data =
/// `[0x62, 0x00] ‖ u64 LE amount` — **byte-IDENTICAL to the deposit descriptor** (`encoder.ts:1707`
/// "Byte-IDENTICAL to deposit_margin … only the disc (0x0062 vs 0x0061) + the on-chain account
/// context differ"). Accounts byte-exact from `withdraw_margin.rs`'s `#[derive(Accounts)]` field
/// order (NOTE: 8 accounts vs deposit's 7 — withdraw adds the `perp_margin_vault_authority` PDA, the
/// `invoke_signed` OUT-transfer CPI signer, and the `receiver_token_account` replaces the depositor
/// ATA). The receiver = the owner's ATA (the handler lets the owner direct it anywhere of the correct
/// mint; the isolated key withdraws back to itself). The handler debits ONLY `free_collateral` under
/// a status-Active + stale-hash gate (a withdraw can never reach `locked_*` — it structurally
/// reduces, never increases, protocol-held exposure). Fail-closed on any PDA / id failure.
#[must_use]
pub fn ix_withdraw_margin(
    owner: &Pubkey,
    settlement_mint: &Pubkey,
    amount: u64,
) -> Option<Instruction> {
    let program = skew_program_id()?;
    let (ura, _b1) = find_program_address(
        &[b"unified_risk_account", &owner.0, &settlement_mint.0],
        &program,
    )?;
    let (pool, _b2) =
        find_program_address(&[b"unified_margin_pool", &settlement_mint.0], &program)?;
    let (vault, _b3) = find_program_address(&[b"perp_margin_vault", &settlement_mint.0], &program)?;
    let (vault_auth, _b4) = find_program_address(
        &[b"perp_margin_vault_authority", &settlement_mint.0],
        &program,
    )?;
    let receiver_ata = associated_token_address(owner, settlement_mint)?;
    let token = Pubkey::from_base58(TOKEN_PROGRAM_ID)?;
    let mut data = vec![0x62u8, 0x00];
    data.extend_from_slice(&amount.to_le_bytes());
    let accounts = vec![
        AccountMeta::writable(*owner, true), // owner (signer, mut) — authorizes the release
        AccountMeta::readonly(*settlement_mint, false), // settlement_mint
        AccountMeta::writable(ura, false),   // unified_risk_account (mut) — free_collateral debited
        AccountMeta::writable(pool, false),  // margin_pool (mut) — liabilities decremented
        AccountMeta::writable(vault, false), // perp_margin_vault (mut) — transfer source
        AccountMeta::readonly(vault_auth, false), // perp_margin_vault_authority (ro) — CPI signer
        AccountMeta::writable(receiver_ata, false), // receiver_token_account (owner ATA, mut)
        AccountMeta::readonly(token, false), // token_program
    ];
    Some(Instruction {
        program_id: program,
        accounts,
        data,
    })
}

/// The `submit_perp_order` (disc 0x0071) descriptor — 102 bytes, borsh-LE packed
/// (`submit_perp_order.rs:84-114` / `encoder.ts:1288`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SubmitPerpOrderDescriptor {
    /// The perp market id (32-byte).
    pub market_id: [u8; 32],
    /// The settlement mint (32-byte).
    pub settlement_mint: Pubkey,
    /// The target batch slot.
    pub batch_slot: u64,
    /// The risk epoch sequence.
    pub epoch_seq: u64,
    /// The per-(owner,market,batch) order nonce.
    pub nonce: u64,
    /// The limit tick.
    pub limit_tick: u32,
    /// The order quantity.
    pub qty: u64,
    /// Side: `0` = long, `1` = short.
    pub side: u8,
    /// Intent flags (bit0 = reduce_only).
    pub intent_flags: u8,
}

impl SubmitPerpOrderDescriptor {
    /// Encode the 102-byte descriptor (byte-exact field order).
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut d = Vec::with_capacity(102);
        d.extend_from_slice(&self.market_id);
        d.extend_from_slice(&self.settlement_mint.0);
        d.extend_from_slice(&self.batch_slot.to_le_bytes());
        d.extend_from_slice(&self.epoch_seq.to_le_bytes());
        d.extend_from_slice(&self.nonce.to_le_bytes());
        d.extend_from_slice(&self.limit_tick.to_le_bytes());
        d.extend_from_slice(&self.qty.to_le_bytes());
        d.push(self.side);
        d.push(self.intent_flags);
        d
    }
}

/// `submit_perp_order` (disc 0x0071) — place an order into a uniform-clearing batch. Data =
/// `[0x71, 0x00] ‖ descriptor(102 B)`. Accounts byte-exact from `submit_perp_order.rs:117-209`; PDA
/// seeds cited (perp_market / risk_epoch / unified_risk_account / batch / order / batch_epoch_bind).
#[must_use]
pub fn ix_submit_perp_order(
    owner: &Pubkey,
    descriptor: &SubmitPerpOrderDescriptor,
) -> Option<Instruction> {
    let program = skew_program_id()?;
    let mid = &descriptor.market_id;
    let mint = &descriptor.settlement_mint.0;
    let (perp_market, _b1) = find_program_address(&[b"perp_market", mid], &program)?;
    let (risk_epoch, _b2) = find_program_address(
        &[b"risk_epoch", mid, &descriptor.epoch_seq.to_le_bytes()],
        &program,
    )?;
    let (ura, _b3) = find_program_address(&[b"unified_risk_account", &owner.0, mint], &program)?;
    let (batch, _b4) = find_program_address(
        &[b"batch", mid, &descriptor.batch_slot.to_le_bytes()],
        &program,
    )?;
    let (order, _b5) = find_program_address(
        &[
            b"order",
            mid,
            &descriptor.batch_slot.to_le_bytes(),
            &owner.0,
            &descriptor.nonce.to_le_bytes(),
        ],
        &program,
    )?;
    let (batch_epoch_bind, _b6) = find_program_address(
        &[
            b"batch_epoch_bind",
            mid,
            &descriptor.batch_slot.to_le_bytes(),
        ],
        &program,
    )?;
    let mut data = vec![0x71u8, 0x00];
    data.extend_from_slice(&descriptor.encode());
    let accounts = vec![
        AccountMeta::writable(*owner, true),       // owner (signer, mut)
        AccountMeta::readonly(perp_market, false), // perp_market (ro)
        AccountMeta::readonly(risk_epoch, false),  // risk_epoch (ro)
        AccountMeta::writable(ura, false),         // unified_risk_account (mut)
        AccountMeta::writable(batch, false),       // batch_state (mut)
        AccountMeta::writable(order, false),       // order (init)
        AccountMeta::writable(batch_epoch_bind, false), // batch_epoch_bind (init_if_needed)
        AccountMeta::readonly(system_program_id(), false), // system_program
    ];
    Some(Instruction {
        program_id: program,
        accounts,
        data,
    })
}

/// The `WccParams` worst-case-collateral product terms — the 90-byte borsh body inlined into the
/// `submit_order` descriptor (`collateral/wcc.rs:209` `pub struct WccParams`, declaration-order borsh,
/// LE). Maps 1:1 onto the oracle's `escrow_wcc_affine_corner` inputs (the oracle re-derives the
/// EXACT `WCL = q·cs·max(0,gap)` the program escrows). `MintAmount(pub u128)` = transparent u128.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct WccParamsCodec {
    /// Signed collar low bound (price axis).
    pub collar_lo: i128,
    /// Signed collar high bound.
    pub collar_hi: i128,
    /// Forward / strike price `Pc` (signed).
    pub forward_price_pc: i128,
    /// Lattice step `τ` (unsigned).
    pub tick_tau: u128,
    /// Integer contract count `q`.
    pub quantity_q: u64,
    /// Contract-size multiplier `cs` (mint scale; `MintAmount` transparent u128).
    pub contract_size_cs: u128,
    /// Party direction discriminant (`WccPartyDirection`: Long=0, Short=1).
    pub party_direction: u8,
    /// Sup-provider mode discriminant (`SupProviderMode`: A=0, B=1, C=2).
    pub sup_provider_mode: u8,
}

impl WccParamsCodec {
    /// Append the 90-byte borsh body (declaration order, LE).
    fn encode_into(&self, d: &mut Vec<u8>) {
        d.extend_from_slice(&self.collar_lo.to_le_bytes()); // i128 LE (16)
        d.extend_from_slice(&self.collar_hi.to_le_bytes()); // i128 LE (16)
        d.extend_from_slice(&self.forward_price_pc.to_le_bytes()); // i128 LE (16)
        d.extend_from_slice(&self.tick_tau.to_le_bytes()); // u128 LE (16)
        d.extend_from_slice(&self.quantity_q.to_le_bytes()); // u64 LE (8)
        d.extend_from_slice(&self.contract_size_cs.to_le_bytes()); // u128 LE (16)
        d.push(self.party_direction); // u8 (1)
        d.push(self.sup_provider_mode); // u8 (1)
    }
}

/// The `submit_order` (disc 0x0052) descriptor — 142 bytes borsh (pinned by the on-chain test
/// `submit_order_descriptor_borsh_wire_is_142_bytes`): `template_id[32] ‖ batch_slot(u64) ‖
/// nonce(u64) ‖ limit_tick(u32) ‖ WccParams(90) ‖ WccSnapshot(0)`. The SDK mirrors this byte image
/// (no separate encoder — the handler's `AnchorDeserialize` is the wire authority).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SubmitOrderDescriptor {
    /// Binds the `ProductTemplatePda` + the batch/order/vault PDA seeds.
    pub template_id: [u8; 32],
    /// The `BatchStatePda` slot this order joins.
    pub batch_slot: u64,
    /// Per-owner order nonce (the `OrderPda` seed tail).
    pub nonce: u64,
    /// Limit price in tick space.
    pub limit_tick: u32,
    /// The declared WCC product terms (the program's `evaluate` derives `WCL` from these).
    pub wcc: WccParamsCodec,
    // `wcc_snapshot: WccSnapshot` is an EMPTY struct ⇒ 0 wire bytes (nothing to encode).
}

impl SubmitOrderDescriptor {
    /// Encode the 142-byte descriptor (byte-exact field order; `WccSnapshot` is 0 bytes).
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut d = Vec::with_capacity(142);
        d.extend_from_slice(&self.template_id); // (32)
        d.extend_from_slice(&self.batch_slot.to_le_bytes()); // (8)
        d.extend_from_slice(&self.nonce.to_le_bytes()); // (8)
        d.extend_from_slice(&self.limit_tick.to_le_bytes()); // (4)
        self.wcc.encode_into(&mut d); // (90)
        d
    }
}

/// `submit_order` (disc 0x0052) — the SINGLE-PARTY program-authored escrow-intake: atomically
/// computes `WCL` from the WccParams, CPI-pulls EXACTLY `WCL` settlement-mint atoms from the signer's
/// ATA into the per-batch escrow vault, and inits the `OrderPda`. Data = `[0x52, 0x00] ‖
/// descriptor(142 B)`. Accounts byte-exact from `submit_order.rs`'s `#[derive(Accounts)]` order (9):
/// signer(mut) · product_template(ro) · batch_state(mut) · order(init) · source_token_account(owner
/// ATA, mut) · batch_vault(mut) · token_mint(ro) · token_program · system_program. The `token_mint` is
/// the settlement mint; the `source_token_account` is the signer's settlement-mint ATA. Fail-closed.
#[must_use]
pub fn ix_submit_order(
    signer: &Pubkey,
    settlement_mint: &Pubkey,
    descriptor: &SubmitOrderDescriptor,
) -> Option<Instruction> {
    let program = skew_program_id()?;
    let tid = &descriptor.template_id;
    let slot_le = descriptor.batch_slot.to_le_bytes();
    let (product_template, _b1) = find_program_address(&[b"product_template", tid], &program)?;
    let (batch_state, _b2) = find_program_address(&[b"batch", tid, &slot_le], &program)?;
    let (order, _b3) = find_program_address(
        &[
            b"order",
            tid,
            &slot_le,
            &signer.0,
            &descriptor.nonce.to_le_bytes(),
        ],
        &program,
    )?;
    let (batch_vault, _b4) = find_program_address(&[b"batch_vault", tid, &slot_le], &program)?;
    let source_ata = associated_token_address(signer, settlement_mint)?;
    let token = Pubkey::from_base58(TOKEN_PROGRAM_ID)?;
    let mut data = vec![0x52u8, 0x00];
    data.extend_from_slice(&descriptor.encode());
    let accounts = vec![
        AccountMeta::writable(*signer, true), // signer (mut) — escrow source + fee payer
        AccountMeta::readonly(product_template, false), // product_template (ro)
        AccountMeta::writable(batch_state, false), // batch_state (mut) — order_count++
        AccountMeta::writable(order, false),  // order (init)
        AccountMeta::writable(source_ata, false), // source_token_account (signer ATA, mut)
        AccountMeta::writable(batch_vault, false), // batch_vault (mut) — escrow destination
        AccountMeta::readonly(*settlement_mint, false), // token_mint (ro)
        AccountMeta::readonly(token, false),  // token_program
        AccountMeta::readonly(system_program_id(), false), // system_program
    ];
    Some(Instruction {
        program_id: program,
        accounts,
        data,
    })
}

/// The 8-byte Anchor instruction sighash `sha256("global:<fn_name>")[..8]` — the data prelude for Skew
/// handlers WITHOUT a `#[instruction(discriminator = [..])]` attribute (the DEFAULT Anchor dispatch:
/// `lock_fixed_forward_initial_collateral` `24b0aa032932b98c` · `pay_fixed_forward_vm`
/// `64bc0ddeafb74041` · `settle_fixed_forward` `7998223f354222a0` — Python-verified). Handlers WITH the
/// attribute (open/deposit/withdraw/perp/submit_order/form/mark) use a 2-byte u16-LE disc instead. A
/// WRONG sighash is undispatchable ⇒ the real devnet simulator is the final authority. Same `sha256`
/// family as the account-disc derivation (`skew_read::SkewAccountKind`, `account:<Name>`).
#[must_use]
pub fn anchor_ix_sighash(fn_name: &str) -> [u8; 8] {
    use sha2::{Digest, Sha256};
    let h = Sha256::digest(format!("global:{fn_name}").as_bytes());
    let mut out = [0u8; 8];
    out.copy_from_slice(&h[..8]);
    out
}

/// The `pay_fixed_forward_vm` descriptor — FIXED 48 bytes borsh (`pay_vm.rs:188-203`): `contract_id[32]
/// ‖ payment_amount(u128, 16)`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PayVmDescriptor {
    /// The `OtcContractPda` this VM payment settles against.
    pub contract_id: [u8; 32],
    /// Atoms paid in to satisfy the open variation-margin call (`>= vm_state.open_call_amount`).
    pub payment_amount: u128,
}

impl PayVmDescriptor {
    /// Encode the 48-byte descriptor (byte-exact: contract_id ‖ payment_amount u128 LE).
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut d = Vec::with_capacity(48);
        d.extend_from_slice(&self.contract_id);
        d.extend_from_slice(&self.payment_amount.to_le_bytes());
        d
    }
}

/// `pay_fixed_forward_vm` (8-byte sighash `64bc0ddeafb74041`) — the open-call party pays in
/// `payment_amount` settlement-mint atoms to satisfy its variation-margin call. SINGLE-PARTY (1 signer
/// = the `open_call_party`). Data = `sighash(8) ‖ descriptor(48)` = 56 B. Accounts byte-exact from
/// `pay_vm.rs`'s `#[derive(Accounts)]` order (10): signer(mut) · otc_contract(mut) · vm_state(mut) ·
/// product_template(ro) · source_token_account(signer ATA, mut) · vm_vault(mut) · vm_vault_authority(ro)
/// · token_mint(ro) · token_program · system_program. `template_id` is a SEPARATE caller input (the
/// descriptor omits it, but the `product_template` PDA address needs it). Fail-closed.
#[must_use]
pub fn ix_pay_vm(
    signer: &Pubkey,
    settlement_mint: &Pubkey,
    template_id: &[u8; 32],
    descriptor: &PayVmDescriptor,
) -> Option<Instruction> {
    let program = skew_program_id()?;
    let cid = &descriptor.contract_id;
    let (otc_contract, _b1) = find_program_address(&[b"otc_contract", cid], &program)?;
    let (vm_state, _b2) = find_program_address(&[b"vm_state", cid], &program)?;
    let (product_template, _b3) =
        find_program_address(&[b"product_template", template_id], &program)?;
    let (vm_vault, _b4) = find_program_address(&[b"vm_vault", cid], &program)?;
    let (vm_vault_auth, _b5) = find_program_address(&[b"vm_vault_authority", cid], &program)?;
    let source_ata = associated_token_address(signer, settlement_mint)?;
    let token = Pubkey::from_base58(TOKEN_PROGRAM_ID)?;
    let mut data = anchor_ix_sighash("pay_fixed_forward_vm").to_vec();
    data.extend_from_slice(&descriptor.encode());
    let accounts = vec![
        AccountMeta::writable(*signer, true), // signer (mut) — the open_call_party
        AccountMeta::writable(otc_contract, false), // otc_contract (mut)
        AccountMeta::writable(vm_state, false), // vm_state (mut)
        AccountMeta::readonly(product_template, false), // product_template (ro, re-derived)
        AccountMeta::writable(source_ata, false), // source_token_account (signer ATA, mut)
        AccountMeta::writable(vm_vault, false), // vm_vault (init_if_needed)
        AccountMeta::readonly(vm_vault_auth, false), // vm_vault_authority (ro, CPI signer)
        AccountMeta::readonly(*settlement_mint, false), // token_mint (ro)
        AccountMeta::readonly(token, false),  // token_program
        AccountMeta::readonly(system_program_id(), false), // system_program
    ];
    Some(Instruction {
        program_id: program,
        accounts,
        data,
    })
}

// ============================================================================
// The fixed-forward OTC lifecycle (lock · mark · settle · form).
// ★ THE PRELUDE IS MIXED (the silent-bug trap, byte-confirmed from lib.rs's #[program]):
//   form_fixed_forward_contract → 2-byte u16-LE [0x03,0x00] (lib.rs:424 #[instruction(discriminator)]);
//   mark_fixed_forward_vm       → 2-byte u16-LE [0x05,0x00] (lib.rs:495);
//   lock/pay/settle             → DEFAULT 8-byte Anchor sighash (lib.rs:441/512/594 NO attribute) via
//                                 `anchor_ix_sighash` (lock 24b0aa032932b98c · pay 64bc0ddeafb74041 [LIVE] ·
//                                 settle 7998223f354222a0 — Python-verified, sha256("global:<fn>")[..8]).
// Sources: lib.rs:424/441/495/594; the handler `#[derive(Accounts)]`; pda.rs SEED_LABEL_*.
// Byte-locked + golden-tested; the live devnet simulate is the ultimate byte-correctness oracle (-9).
// ============================================================================

/// Append a borsh `Vec<u8>` — `u32 LE length` ‖ raw bytes. The OTC lifecycle descriptors carry
/// policy/snapshot structs as opaque `Vec<u8>` (the caller supplies the borsh-encoded bytes the template
/// fixed at listing; in FixedLock mode the snapshot is the zero-byte unit struct ⇒ `[]`). This encodes
/// the length-prefixed wire faithfully.
fn push_borsh_bytes(out: &mut Vec<u8>, bytes: &[u8]) {
    let len = u32::try_from(bytes.len()).unwrap_or(u32::MAX);
    out.extend_from_slice(&len.to_le_bytes());
    out.extend_from_slice(bytes);
}

/// The `settle_fixed_forward` descriptor — FIXED 128 bytes borsh (`settle.rs:253-258` "6 fields / 128
/// bytes"). ⚠ FIELD-ORDER TRAP: `reference_snapshot_hash` comes BEFORE `settlement_price`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SettleFixedForwardDescriptor {
    /// The `OtcContractPda` this settles (PDA seed binding).
    pub contract_id: [u8; 32],
    /// SHA-256 of the reference snapshot consumed by the payoff computation (must be non-zero).
    pub reference_snapshot_hash: [u8; 32],
    /// The settlement price in atoms (u128 — matches `OtcContractPda.forward_price` width).
    pub settlement_price: u128,
    /// The caller's clock anchor (i64).
    pub current_unix_timestamp: i64,
    /// 32-byte archive pointer to the off-chain reference bundle.
    pub archive_pointer: [u8; 32],
    /// The reference snapshot publish timestamp (i64) — the freshness anchor.
    pub reference_publish_timestamp: i64,
}
impl SettleFixedForwardDescriptor {
    /// Encode the 128-byte descriptor (byte-exact field order; hash BEFORE price).
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut d = Vec::with_capacity(128);
        d.extend_from_slice(&self.contract_id);
        d.extend_from_slice(&self.reference_snapshot_hash);
        d.extend_from_slice(&self.settlement_price.to_le_bytes());
        d.extend_from_slice(&self.current_unix_timestamp.to_le_bytes());
        d.extend_from_slice(&self.archive_pointer);
        d.extend_from_slice(&self.reference_publish_timestamp.to_le_bytes());
        d
    }
}

/// `settle_fixed_forward` (8-byte sighash `7998223f354222a0`) — resolve a fixed-forward at maturity:
/// compute the signed payoff + disburse from the program-owned `collateral_vault` to the winner.
/// PERMISSIONLESS keeper (the signer is NOT a party); the agent-as-keeper commits NO escrow (escrow=0) —
/// the disbursement is bounded by the posted collateral, never the keeper's wallet. Data = sighash(8) ‖
/// descriptor(128) = 136 B. 12 accounts byte-exact from `settle.rs`'s `#[derive(Accounts)]` order.
/// `template_id` (the product_template PDA) + `receiver_token_account` (the winner's ATA) are SEPARATE
/// caller inputs (the descriptor omits them). Fail-closed.
#[must_use]
pub fn ix_settle_fixed_forward(
    signer: &Pubkey,
    settlement_mint: &Pubkey,
    template_id: &[u8; 32],
    receiver_token_account: &Pubkey,
    descriptor: &SettleFixedForwardDescriptor,
) -> Option<Instruction> {
    let program = skew_program_id()?;
    let cid = &descriptor.contract_id;
    let (otc_contract, _b1) = find_program_address(&[b"otc_contract", cid], &program)?;
    let (vm_state, _b2) = find_program_address(&[b"vm_state", cid], &program)?;
    let (liquidation_state, _b3) = find_program_address(&[b"liquidation_state", cid], &program)?;
    let (product_template, _b4) =
        find_program_address(&[b"product_template", template_id], &program)?;
    let (settlement_receipt, _b5) = find_program_address(&[b"settlement_receipt", cid], &program)?;
    let (collateral_vault, _b6) = find_program_address(&[b"collateral_vault", cid], &program)?;
    let (collateral_vault_auth, _b7) =
        find_program_address(&[b"collateral_vault_authority", cid], &program)?;
    let token = Pubkey::from_base58(TOKEN_PROGRAM_ID)?;
    let mut data = anchor_ix_sighash("settle_fixed_forward").to_vec();
    data.extend_from_slice(&descriptor.encode());
    let accounts = vec![
        AccountMeta::writable(*signer, true), // signer (mut) — permissionless worker
        AccountMeta::writable(otc_contract, false), // otc_contract (mut)
        AccountMeta::readonly(vm_state, false), // vm_state (ro)
        AccountMeta::readonly(liquidation_state, false), // liquidation_state (ro, may be uninit)
        AccountMeta::readonly(product_template, false), // product_template (ro, rederived)
        AccountMeta::writable(settlement_receipt, false), // settlement_receipt (init)
        AccountMeta::writable(collateral_vault, false), // collateral_vault (mut) — disburse source
        AccountMeta::readonly(collateral_vault_auth, false), // collateral_vault_authority (ro, CPI signer)
        AccountMeta::writable(*receiver_token_account, false), // receiver_token_account (winner ATA, mut)
        AccountMeta::readonly(*settlement_mint, false),        // token_mint (ro)
        AccountMeta::readonly(token, false),                   // token_program
        AccountMeta::readonly(system_program_id(), false),     // system_program
    ];
    Some(Instruction {
        program_id: program,
        accounts,
        data,
    })
}

/// The `lock_fixed_forward_initial_collateral` descriptor — VARIABLE (`lock_collateral.rs`): the 3
/// `Vec<u8>` carry borsh policy/snapshot structs (caller-supplied; in FixedLock mode
/// `collateral_snapshot_bytes = []`). Fields in declaration order.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LockCollateralDescriptor {
    /// The `OtcContractPda` this locks against.
    pub contract_id: [u8; 32],
    /// Which party (`0` = long, `1` = short) the signer locks for.
    pub party_role: u8,
    /// The collateral the signer locks (settlement-mint atoms; the program enforces `>= required`).
    pub lock_amount: u128,
    /// The collateral policy version selector (u32).
    pub collateral_policy_version: u32,
    /// The borsh-encoded collateral params struct (caller-supplied).
    pub collateral_params_bytes: Vec<u8>,
    /// The borsh-encoded collateral snapshot (`[]` for FixedLock — a zero-byte unit struct).
    pub collateral_snapshot_bytes: Vec<u8>,
    /// SHA-256 of the reference snapshot (freshness gate input).
    pub reference_snapshot_hash: [u8; 32],
    /// The snapshot age in seconds (u32).
    pub reference_snapshot_age_seconds: u32,
    /// The max acceptable snapshot age in seconds (u32).
    pub reference_max_age_seconds: u32,
    /// The borsh-encoded VmPolicy struct (caller-supplied).
    pub vm_policy_bytes: Vec<u8>,
    /// The VM mark source selector (u16).
    pub vm_mark_source: u16,
}
impl LockCollateralDescriptor {
    /// Encode the VARIABLE descriptor (byte-exact declaration order; the 3 Vec<u8> are length-prefixed).
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut d = Vec::new();
        d.extend_from_slice(&self.contract_id);
        d.push(self.party_role);
        d.extend_from_slice(&self.lock_amount.to_le_bytes());
        d.extend_from_slice(&self.collateral_policy_version.to_le_bytes());
        push_borsh_bytes(&mut d, &self.collateral_params_bytes);
        push_borsh_bytes(&mut d, &self.collateral_snapshot_bytes);
        d.extend_from_slice(&self.reference_snapshot_hash);
        d.extend_from_slice(&self.reference_snapshot_age_seconds.to_le_bytes());
        d.extend_from_slice(&self.reference_max_age_seconds.to_le_bytes());
        push_borsh_bytes(&mut d, &self.vm_policy_bytes);
        d.extend_from_slice(&self.vm_mark_source.to_le_bytes());
        d
    }
}

/// `lock_fixed_forward_initial_collateral` (8-byte sighash `24b0aa032932b98c`) — the agent (a contract
/// PARTY) locks ITS side's initial collateral: CPI-pulls `lock_amount` settlement-mint atoms from its
/// ATA into the `collateral_vault`. SINGLE-SIGNER (the agent signs for its own party; the counterparty's
/// `collateral_state` is referenced but does not sign). escrow == `lock_amount` (a real bounded trade).
/// Data = sighash(8) ‖ descriptor(VARIABLE). 12 accounts byte-exact from `lock_collateral.rs`.
/// `template_id` (product_template) + `other_party` (collateral_state_other) are caller inputs.
#[must_use]
pub fn ix_lock_collateral(
    signer: &Pubkey,
    settlement_mint: &Pubkey,
    template_id: &[u8; 32],
    other_party: &Pubkey,
    descriptor: &LockCollateralDescriptor,
) -> Option<Instruction> {
    let program = skew_program_id()?;
    let cid = &descriptor.contract_id;
    let (product_template, _b1) =
        find_program_address(&[b"product_template", template_id], &program)?;
    let (otc_contract, _b2) = find_program_address(&[b"otc_contract", cid], &program)?;
    let (cs_self, _b3) = find_program_address(&[b"collateral_state", cid, &signer.0], &program)?;
    let (cs_other, _b4) =
        find_program_address(&[b"collateral_state", cid, &other_party.0], &program)?;
    let (vm_state, _b5) = find_program_address(&[b"vm_state", cid], &program)?;
    let source_ata = associated_token_address(signer, settlement_mint)?;
    let (collateral_vault, _b6) = find_program_address(&[b"collateral_vault", cid], &program)?;
    let (collateral_vault_auth, _b7) =
        find_program_address(&[b"collateral_vault_authority", cid], &program)?;
    let token = Pubkey::from_base58(TOKEN_PROGRAM_ID)?;
    let mut data = anchor_ix_sighash("lock_fixed_forward_initial_collateral").to_vec();
    data.extend_from_slice(&descriptor.encode());
    let accounts = vec![
        AccountMeta::writable(*signer, true), // signer (mut) — escrow source + fee payer
        AccountMeta::readonly(product_template, false), // product_template (ro)
        AccountMeta::writable(otc_contract, false), // otc_contract (mut)
        AccountMeta::writable(cs_self, false), // collateral_state_self (init)
        AccountMeta::writable(cs_other, false), // collateral_state_other (mut, other party)
        AccountMeta::writable(vm_state, false), // vm_state (init_if_needed)
        AccountMeta::writable(source_ata, false), // source_token_account (signer ATA)
        AccountMeta::writable(collateral_vault, false), // collateral_vault (init_if_needed)
        AccountMeta::readonly(collateral_vault_auth, false), // collateral_vault_authority (ro)
        AccountMeta::readonly(*settlement_mint, false), // token_mint (ro)
        AccountMeta::readonly(token, false),  // token_program
        AccountMeta::readonly(system_program_id(), false), // system_program
    ];
    Some(Instruction {
        program_id: program,
        accounts,
        data,
    })
}

/// The `mark_fixed_forward_vm` descriptor — VARIABLE (`mark_vm.rs`): the single `vm_policy_bytes`
/// Vec<u8> is the VmPolicy struct (caller-supplied). Fields in declaration order.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MarkVmDescriptor {
    /// The `OtcContractPda` this marks.
    pub contract_id: [u8; 32],
    /// The borsh-encoded VmPolicy struct (caller-supplied).
    pub vm_policy_bytes: Vec<u8>,
    /// The mark-to-market price in atoms (u128).
    pub mark_price_atoms: u128,
    /// The mark publish timestamp (i64).
    pub mark_publish_timestamp: i64,
    /// Mark confidence in basis points (u32).
    pub mark_confidence_bps: u32,
    /// SHA-256 of the mark snapshot.
    pub mark_snapshot_hash: [u8; 32],
    /// 32-byte archive pointer for the mark.
    pub mark_archive_pointer: [u8; 32],
    /// The reference policy id (u16).
    pub reference_policy_id: u16,
    /// The mark price decimals (u8).
    pub mark_price_decimals: u8,
    /// The caller's clock anchor (i64).
    pub current_unix_timestamp: i64,
}
impl MarkVmDescriptor {
    /// Encode the VARIABLE descriptor (byte-exact declaration order; vm_policy_bytes length-prefixed).
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut d = Vec::new();
        d.extend_from_slice(&self.contract_id);
        push_borsh_bytes(&mut d, &self.vm_policy_bytes);
        d.extend_from_slice(&self.mark_price_atoms.to_le_bytes());
        d.extend_from_slice(&self.mark_publish_timestamp.to_le_bytes());
        d.extend_from_slice(&self.mark_confidence_bps.to_le_bytes());
        d.extend_from_slice(&self.mark_snapshot_hash);
        d.extend_from_slice(&self.mark_archive_pointer);
        d.extend_from_slice(&self.reference_policy_id.to_le_bytes());
        d.push(self.mark_price_decimals);
        d.extend_from_slice(&self.current_unix_timestamp.to_le_bytes());
        d
    }
}

/// `mark_fixed_forward_vm` (2-byte u16-LE disc `[0x05, 0x00]`) — mark-to-market the variation margin +
/// open a VM call if the mark exceeds the threshold. PERMISSIONLESS keeper (escrow=0; mark-to-market
/// only, no token CPI). Data = `[0x05, 0x00]` ‖ descriptor(VARIABLE). 4 accounts byte-exact from
/// `mark_vm.rs`. `template_id` (product_template) is a caller input.
#[must_use]
pub fn ix_mark_vm(
    signer: &Pubkey,
    template_id: &[u8; 32],
    descriptor: &MarkVmDescriptor,
) -> Option<Instruction> {
    let program = skew_program_id()?;
    let cid = &descriptor.contract_id;
    let (otc_contract, _b1) = find_program_address(&[b"otc_contract", cid], &program)?;
    let (vm_state, _b2) = find_program_address(&[b"vm_state", cid], &program)?;
    let (product_template, _b3) =
        find_program_address(&[b"product_template", template_id], &program)?;
    let mut data = vec![0x05u8, 0x00];
    data.extend_from_slice(&descriptor.encode());
    let accounts = vec![
        // the handler marks the signer non-mut, but it is the tx fee payer ⇒ writable (auto-promoted).
        AccountMeta::writable(*signer, true), // signer (fee payer)
        AccountMeta::writable(otc_contract, false), // otc_contract (mut)
        AccountMeta::writable(vm_state, false), // vm_state (mut)
        AccountMeta::readonly(product_template, false), // product_template (ro, rederived)
    ];
    Some(Instruction {
        program_id: program,
        accounts,
        data,
    })
}

/// The `form_fixed_forward_contract` descriptor — VARIABLE (`form_contract.rs`): a 342-byte fixed prefix
/// then 2 trailing Vecs (`approved_reference_ids: Vec<[u8;32]>`, `approved_settlement_mints:
/// Vec<Pubkey>`). NOTE `version: u32` sits BETWEEN `template_id` and `terms_hash` (offset 64). Fields in
/// declaration order.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FormContractDescriptor {
    /// The new `OtcContractPda` id (init seed).
    pub contract_id: [u8; 32],
    /// The `ProductTemplatePda` id this contract instantiates.
    pub template_id: [u8; 32],
    /// The template version (TRAP — between template_id and terms_hash).
    pub version: u32,
    /// SHA-256 of the contract terms.
    pub terms_hash: [u8; 32],
    /// The accept-record id (init seed).
    pub accept_id: [u8; 32],
    /// The quote expiry (i64).
    pub quote_expiry: i64,
    /// The long party pubkey.
    pub long_party: Pubkey,
    /// The short party pubkey.
    pub short_party: Pubkey,
    /// The party-roles byte.
    pub party_roles: u8,
    /// Whether a self-cross (long == short) is allowed.
    pub allow_self_cross: bool,
    /// The underlying reference id.
    pub underlying_reference_id: [u8; 32],
    /// The settlement mint.
    pub settlement_mint: Pubkey,
    /// The contract quantity (u64).
    pub quantity: u64,
    /// The contract-size multiplier (u128).
    pub contract_size: u128,
    /// The forward / strike price (u128).
    pub forward_price: u128,
    /// The maturity timestamp (i64).
    pub maturity_timestamp: i64,
    /// The notional (u128).
    pub notional: u128,
    /// The reference-data policy id (u16).
    pub reference_data_policy_id: u16,
    /// The collateral policy id (u16).
    pub collateral_policy_id: u16,
    /// The VM policy id (u16).
    pub vm_policy_id: u16,
    /// The settlement adapter id (u16).
    pub settlement_adapter_id: u16,
    /// The approved reference ids (`Vec<[u8;32]>`).
    pub approved_reference_ids: Vec<[u8; 32]>,
    /// The approved settlement mints (`Vec<Pubkey>`).
    pub approved_settlement_mints: Vec<Pubkey>,
}
impl FormContractDescriptor {
    /// Encode the VARIABLE descriptor (byte-exact declaration order; version @64; 2 trailing Vecs).
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut d = Vec::new();
        d.extend_from_slice(&self.contract_id);
        d.extend_from_slice(&self.template_id);
        d.extend_from_slice(&self.version.to_le_bytes());
        d.extend_from_slice(&self.terms_hash);
        d.extend_from_slice(&self.accept_id);
        d.extend_from_slice(&self.quote_expiry.to_le_bytes());
        d.extend_from_slice(&self.long_party.0);
        d.extend_from_slice(&self.short_party.0);
        d.push(self.party_roles);
        d.push(u8::from(self.allow_self_cross));
        d.extend_from_slice(&self.underlying_reference_id);
        d.extend_from_slice(&self.settlement_mint.0);
        d.extend_from_slice(&self.quantity.to_le_bytes());
        d.extend_from_slice(&self.contract_size.to_le_bytes());
        d.extend_from_slice(&self.forward_price.to_le_bytes());
        d.extend_from_slice(&self.maturity_timestamp.to_le_bytes());
        d.extend_from_slice(&self.notional.to_le_bytes());
        d.extend_from_slice(&self.reference_data_policy_id.to_le_bytes());
        d.extend_from_slice(&self.collateral_policy_id.to_le_bytes());
        d.extend_from_slice(&self.vm_policy_id.to_le_bytes());
        d.extend_from_slice(&self.settlement_adapter_id.to_le_bytes());
        let n_ref = u32::try_from(self.approved_reference_ids.len()).unwrap_or(u32::MAX);
        d.extend_from_slice(&n_ref.to_le_bytes());
        for r in &self.approved_reference_ids {
            d.extend_from_slice(r);
        }
        let n_mint = u32::try_from(self.approved_settlement_mints.len()).unwrap_or(u32::MAX);
        d.extend_from_slice(&n_mint.to_le_bytes());
        for m in &self.approved_settlement_mints {
            d.extend_from_slice(&m.0);
        }
        d
    }
}

/// `form_fixed_forward_contract` (2-byte u16-LE disc `[0x03, 0x00]`) — form a bilateral fixed-forward.
/// ★ 3 SIGNERS (long_party + short_party + fee_payer) ⇒ a single bounded agent CANNOT broadcast alone
/// (it can't forge the counterparty signature). HONEST SCOPE: the codec + plan ASSEMBLE + SIMULATE (the
/// devnet sim uses `sigVerify:false`, validating the bytes without real sigs); a REAL broadcast = a
/// multi-sig / 2-agent / quote-authority owner go-live. escrow=0 (creates PDAs only). Data =
/// `[0x03, 0x00]` ‖ descriptor(VARIABLE). 8 accounts byte-exact from `form_contract.rs`. The agent's
/// isolated key is the `fee_payer`; long/short come from the descriptor.
#[must_use]
pub fn ix_form_contract(
    fee_payer: &Pubkey,
    descriptor: &FormContractDescriptor,
) -> Option<Instruction> {
    let program = skew_program_id()?;
    let cid = &descriptor.contract_id;
    let (product_template, _b1) =
        find_program_address(&[b"product_template", &descriptor.template_id], &program)?;
    let (otc_contract, _b2) = find_program_address(&[b"otc_contract", cid], &program)?;
    let (accept_record, _b3) =
        find_program_address(&[b"accept_record", &descriptor.accept_id], &program)?;
    let (lifecycle_event, _b4) =
        find_program_address(&[b"lifecycle_event", cid, &0u64.to_le_bytes()], &program)?;
    let mut data = vec![0x03u8, 0x00];
    data.extend_from_slice(&descriptor.encode());
    let accounts = vec![
        AccountMeta::writable(descriptor.long_party, true), // long_party (signer, mut)
        AccountMeta::writable(descriptor.short_party, true), // short_party (signer, mut)
        AccountMeta::writable(*fee_payer, true),            // fee_payer (signer, mut)
        AccountMeta::readonly(product_template, false),     // product_template (ro)
        AccountMeta::writable(otc_contract, false),         // otc_contract (init)
        AccountMeta::writable(accept_record, false),        // accept_record (init)
        AccountMeta::writable(lifecycle_event, false),      // lifecycle_event (init)
        AccountMeta::readonly(system_program_id(), false),  // system_program
    ];
    Some(Instruction {
        program_id: program,
        accounts,
        data,
    })
}

// ============================================================================
// The SECONDARY market (list / quote / accept / atomic-transfer / cancel an existing OTC
// position). All 2-byte u16-LE discs (lib.rs:1138/1148/1159/1171/1182). All SINGLE-PARTY (1 signer ⇒
// agent-executable). list/quote/accept/cancel move NO tokens (escrow=0, pure coordination); the
// atomic position transfer is the value-moving leg (buyer posts WCL + pays the price). Descriptors +
// account orders byte-exact from `secondary_market.rs`; seeds from pda.rs.
// ============================================================================

/// `list_secondary` (disc `[0x65,0x00]`) descriptor — FIXED 66 B (`secondary_market.rs:82`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ListSecondaryDescriptor {
    /// The OTC contract id (PDA seed).
    pub contract_id: [u8; 32],
    /// Which side (`0`/`1`) is being listed.
    pub side: u8,
    /// The quantity offered.
    pub listing_qty: u64,
    /// The ask price (atoms).
    pub ask_price: u128,
    /// The listing expiry slot.
    pub expiry_slot: u64,
    /// The execution mode selector.
    pub execution_mode: u8,
}
impl ListSecondaryDescriptor {
    /// Encode the 66-byte descriptor.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut d = Vec::with_capacity(66);
        d.extend_from_slice(&self.contract_id);
        d.push(self.side);
        d.extend_from_slice(&self.listing_qty.to_le_bytes());
        d.extend_from_slice(&self.ask_price.to_le_bytes());
        d.extend_from_slice(&self.expiry_slot.to_le_bytes());
        d.push(self.execution_mode);
        d
    }
}

/// `list_secondary` (disc `[0x65,0x00]`) — list an existing OTC position for secondary sale (escrow=0;
/// inits the `SecondaryListingPda`). 1 signer = the seller. 4 accounts byte-exact (`secondary_market.rs`).
#[must_use]
pub fn ix_list_secondary(
    seller: &Pubkey,
    descriptor: &ListSecondaryDescriptor,
) -> Option<Instruction> {
    let program = skew_program_id()?;
    let cid = &descriptor.contract_id;
    let (otc_contract, _b1) = find_program_address(&[b"otc_contract", cid], &program)?;
    let (listing, _b2) = find_program_address(&[b"secondary_listing", cid, &seller.0], &program)?;
    let mut data = vec![0x65u8, 0x00];
    data.extend_from_slice(&descriptor.encode());
    let accounts = vec![
        AccountMeta::writable(*seller, true), // seller (signer, mut)
        AccountMeta::readonly(otc_contract, false), // otc_contract (ro)
        AccountMeta::writable(listing, false), // secondary_listing (init)
        AccountMeta::readonly(system_program_id(), false), // system_program
    ];
    Some(Instruction {
        program_id: program,
        accounts,
        data,
    })
}

/// `quote_secondary` (disc `[0x66,0x00]`) descriptor — FIXED 80 B (`secondary_market.rs:100`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct QuoteSecondaryDescriptor {
    /// The OTC contract id.
    pub contract_id: [u8; 32],
    /// The seller whose listing this quotes (the listing PDA seed).
    pub seller: Pubkey,
    /// The bid price (atoms).
    pub quote_price: u128,
}
impl QuoteSecondaryDescriptor {
    /// Encode the 80-byte descriptor.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut d = Vec::with_capacity(80);
        d.extend_from_slice(&self.contract_id);
        d.extend_from_slice(&self.seller.0);
        d.extend_from_slice(&self.quote_price.to_le_bytes());
        d
    }
}

/// `quote_secondary` (disc `[0x66,0x00]`) — post a bid on a secondary listing (escrow=0). 1 signer = the
/// buyer. 2 accounts byte-exact. The `secondary_listing` PDA seed uses `descriptor.seller`.
#[must_use]
pub fn ix_quote_secondary(
    buyer: &Pubkey,
    descriptor: &QuoteSecondaryDescriptor,
) -> Option<Instruction> {
    let program = skew_program_id()?;
    let (listing, _b1) = find_program_address(
        &[
            b"secondary_listing",
            &descriptor.contract_id,
            &descriptor.seller.0,
        ],
        &program,
    )?;
    let mut data = vec![0x66u8, 0x00];
    data.extend_from_slice(&descriptor.encode());
    let accounts = vec![
        AccountMeta::writable(*buyer, true),   // buyer (signer, mut)
        AccountMeta::writable(listing, false), // secondary_listing (mut)
    ];
    Some(Instruction {
        program_id: program,
        accounts,
        data,
    })
}

/// `accept_secondary` (disc `[0x67,0x00]`) descriptor — FIXED 88 B (`secondary_market.rs:112`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AcceptSecondaryDescriptor {
    /// The OTC contract id.
    pub contract_id: [u8; 32],
    /// The buyer being accepted.
    pub accepted_buyer: Pubkey,
    /// The accepted price (atoms).
    pub accept_price: u128,
    /// The transfer deadline (i64).
    pub transfer_deadline: i64,
}
impl AcceptSecondaryDescriptor {
    /// Encode the 88-byte descriptor.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut d = Vec::with_capacity(88);
        d.extend_from_slice(&self.contract_id);
        d.extend_from_slice(&self.accepted_buyer.0);
        d.extend_from_slice(&self.accept_price.to_le_bytes());
        d.extend_from_slice(&self.transfer_deadline.to_le_bytes());
        d
    }
}

/// `accept_secondary` (disc `[0x67,0x00]`) — the seller accepts a buyer's quote (escrow=0; sets the
/// pending-transfer flag). 1 signer = the seller. 3 accounts byte-exact. The listing PDA seed uses the
/// signer (seller).
#[must_use]
pub fn ix_accept_secondary(
    seller: &Pubkey,
    descriptor: &AcceptSecondaryDescriptor,
) -> Option<Instruction> {
    let program = skew_program_id()?;
    let cid = &descriptor.contract_id;
    let (otc_contract, _b1) = find_program_address(&[b"otc_contract", cid], &program)?;
    let (listing, _b2) = find_program_address(&[b"secondary_listing", cid, &seller.0], &program)?;
    let mut data = vec![0x67u8, 0x00];
    data.extend_from_slice(&descriptor.encode());
    let accounts = vec![
        AccountMeta::writable(*seller, true), // seller (signer, mut)
        AccountMeta::writable(otc_contract, false), // otc_contract (mut)
        AccountMeta::writable(listing, false), // secondary_listing (mut)
    ];
    Some(Instruction {
        program_id: program,
        accounts,
        data,
    })
}

/// `cancel_secondary` (disc `[0x69,0x00]`) descriptor — FIXED 64 B (`secondary_market.rs:147`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CancelSecondaryDescriptor {
    /// The OTC contract id.
    pub contract_id: [u8; 32],
    /// The seller whose listing is cancelled (the listing PDA seed).
    pub seller: Pubkey,
}
impl CancelSecondaryDescriptor {
    /// Encode the 64-byte descriptor.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut d = Vec::with_capacity(64);
        d.extend_from_slice(&self.contract_id);
        d.extend_from_slice(&self.seller.0);
        d
    }
}

/// `cancel_secondary` (disc `[0x69,0x00]`) — cancel a secondary listing (escrow=0; seller before the
/// deadline, anyone after). 1 signer. 3 accounts byte-exact. The listing PDA seed uses `descriptor.seller`.
#[must_use]
pub fn ix_cancel_secondary(
    caller: &Pubkey,
    descriptor: &CancelSecondaryDescriptor,
) -> Option<Instruction> {
    let program = skew_program_id()?;
    let cid = &descriptor.contract_id;
    let (otc_contract, _b1) = find_program_address(&[b"otc_contract", cid], &program)?;
    let (listing, _b2) =
        find_program_address(&[b"secondary_listing", cid, &descriptor.seller.0], &program)?;
    let mut data = vec![0x69u8, 0x00];
    data.extend_from_slice(&descriptor.encode());
    let accounts = vec![
        AccountMeta::writable(*caller, true), // caller (signer, mut)
        AccountMeta::writable(otc_contract, false), // otc_contract (mut)
        AccountMeta::writable(listing, false), // secondary_listing (mut)
    ];
    Some(Instruction {
        program_id: program,
        accounts,
        data,
    })
}

/// `atomic_position_transfer` (disc `[0x68,0x00]`) descriptor — FIXED 88 B (`secondary_market.rs:134`):
/// the collar terms are re-supplied (terms_hash-bound) so the handler can re-derive the WCL.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AtomicPositionTransferDescriptor {
    /// The OTC contract id.
    pub contract_id: [u8; 32],
    /// The double-transfer guard nonce (receipt PDA seed).
    pub transfer_nonce: u64,
    /// Collar low bound (re-supplied, i128).
    pub collar_lo: i128,
    /// Collar high bound (re-supplied, i128).
    pub collar_hi: i128,
    /// Lattice step τ (re-supplied, u128).
    pub tick_tau: u128,
}
impl AtomicPositionTransferDescriptor {
    /// Encode the 88-byte descriptor.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut d = Vec::with_capacity(88);
        d.extend_from_slice(&self.contract_id);
        d.extend_from_slice(&self.transfer_nonce.to_le_bytes());
        d.extend_from_slice(&self.collar_lo.to_le_bytes());
        d.extend_from_slice(&self.collar_hi.to_le_bytes());
        d.extend_from_slice(&self.tick_tau.to_le_bytes());
        d
    }
}

/// `atomic_position_transfer` (disc `[0x68,0x00]`) — the buyer ATOMICALLY takes over an existing OTC
/// position: posts the WCL into the collateral vault, pays the agreed price to the seller, and the vault
/// releases the departing seller's WCL. 1 signer = the buyer (the agent). The buyer's wallet outflow =
/// WCL + price (the oracle bounds it). Data = `[0x68,0x00]` ‖ descriptor(88) = 90 B. 14 accounts
/// byte-exact (`secondary_market.rs`). `seller` is a caller input (the departing holder address).
#[must_use]
pub fn ix_atomic_position_transfer(
    buyer: &Pubkey,
    settlement_mint: &Pubkey,
    seller: &Pubkey,
    descriptor: &AtomicPositionTransferDescriptor,
) -> Option<Instruction> {
    let program = skew_program_id()?;
    let cid = &descriptor.contract_id;
    let (otc_contract, _b1) = find_program_address(&[b"otc_contract", cid], &program)?;
    let (listing, _b2) = find_program_address(&[b"secondary_listing", cid, &seller.0], &program)?;
    let (collateral_vault, _b3) = find_program_address(&[b"collateral_vault", cid], &program)?;
    let (collateral_vault_auth, _b4) =
        find_program_address(&[b"collateral_vault_authority", cid], &program)?;
    let buyer_ata = associated_token_address(buyer, settlement_mint)?;
    let seller_ata = associated_token_address(seller, settlement_mint)?;
    let (old_cs, _b5) = find_program_address(&[b"collateral_state", cid, &seller.0], &program)?;
    let (new_cs, _b6) = find_program_address(&[b"collateral_state", cid, &buyer.0], &program)?;
    let (receipt, _b7) = find_program_address(
        &[
            b"secondary_transfer_receipt",
            cid,
            &descriptor.transfer_nonce.to_le_bytes(),
        ],
        &program,
    )?;
    let token = Pubkey::from_base58(TOKEN_PROGRAM_ID)?;
    let mut data = vec![0x68u8, 0x00];
    data.extend_from_slice(&descriptor.encode());
    let accounts = vec![
        AccountMeta::writable(*buyer, true),        // buyer (signer, mut)
        AccountMeta::writable(*seller, false), // seller (UncheckedAccount, mut — receives payment)
        AccountMeta::writable(otc_contract, false), // otc_contract (mut)
        AccountMeta::writable(listing, false), // secondary_listing (mut)
        AccountMeta::writable(collateral_vault, false), // collateral_vault (mut)
        AccountMeta::readonly(collateral_vault_auth, false), // collateral_vault_authority (ro, CPI signer)
        AccountMeta::writable(buyer_ata, false),             // buyer_escrow_source (buyer ATA, mut)
        AccountMeta::writable(seller_ata, false), // seller_payment_dest (seller ATA, mut)
        AccountMeta::writable(old_cs, false),     // old_collateral_state (mut, close=buyer)
        AccountMeta::writable(new_cs, false),     // new_collateral_state (init)
        AccountMeta::writable(receipt, false),    // secondary_transfer_receipt (init)
        AccountMeta::readonly(*settlement_mint, false), // settlement_mint (ro)
        AccountMeta::readonly(token, false),      // token_program
        AccountMeta::readonly(system_program_id(), false), // system_program
    ];
    Some(Instruction {
        program_id: program,
        accounts,
        data,
    })
}

// ============================================================================
// The batch-auction books (open / close / settle / claim_fill / settle_batch_contract). All
// 2-byte u16-LE discs (lib.rs:820/841/853/875/956). All SINGLE-PARTY + PERMISSIONLESS crank/settle ⇒
// the agent commits NO escrow of its own (escrow=0; refunds/disbursements go to the order owner / the
// winner, bounded by the posted batch escrow). Descriptors + accounts byte-exact (`open_batch.rs` /
// `close_batch.rs` / `settle_batch.rs` / `batch_completion.rs` / `settle_batch_contract.rs`); the
// `histogram` PDA carries a 1-byte side seed (`SIDE_BID = 0`, `SIDE_ASK = 1`, `matching/dfba.rs`).
// ============================================================================

/// The DFBA side seed bytes (`matching/dfba.rs:326-327`): demand/bid = 0, supply/ask = 1.
const SIDE_BID: u8 = 0;
const SIDE_ASK: u8 = 1;

/// `open_batch` (disc `[0x51,0x00]`) descriptor — FIXED 40 B (`open_batch.rs`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct OpenBatchDescriptor {
    /// The product template id (PDA seed).
    pub template_id: [u8; 32],
    /// The batch slot this opens.
    pub batch_slot: u64,
}
impl OpenBatchDescriptor {
    /// Encode the 40-byte descriptor.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut d = Vec::with_capacity(40);
        d.extend_from_slice(&self.template_id);
        d.extend_from_slice(&self.batch_slot.to_le_bytes());
        d
    }
}

/// `open_batch` (disc `[0x51,0x00]`) — open a batch-auction desk (escrow=0; inits the batch state +
/// vault). 1 signer = the permissionless opener. 8 accounts byte-exact.
#[must_use]
pub fn ix_open_batch(
    opener: &Pubkey,
    settlement_mint: &Pubkey,
    descriptor: &OpenBatchDescriptor,
) -> Option<Instruction> {
    let program = skew_program_id()?;
    let tid = &descriptor.template_id;
    let slot = descriptor.batch_slot.to_le_bytes();
    let (product_template, _b1) = find_program_address(&[b"product_template", tid], &program)?;
    let (batch_state, _b2) = find_program_address(&[b"batch", tid, &slot], &program)?;
    let (batch_vault, _b3) = find_program_address(&[b"batch_vault", tid, &slot], &program)?;
    let (batch_vault_auth, _b4) =
        find_program_address(&[b"batch_vault_authority", tid, &slot], &program)?;
    let token = Pubkey::from_base58(TOKEN_PROGRAM_ID)?;
    let mut data = vec![0x51u8, 0x00];
    data.extend_from_slice(&descriptor.encode());
    let accounts = vec![
        AccountMeta::writable(*opener, true), // opener (signer, mut)
        AccountMeta::readonly(product_template, false), // product_template (ro)
        AccountMeta::writable(batch_state, false), // batch_state (init)
        AccountMeta::writable(batch_vault, false), // batch_vault (init)
        AccountMeta::readonly(batch_vault_auth, false), // batch_vault_authority (ro)
        AccountMeta::readonly(*settlement_mint, false), // settlement_mint (ro)
        AccountMeta::readonly(token, false),  // token_program
        AccountMeta::readonly(system_program_id(), false), // system_program
    ];
    Some(Instruction {
        program_id: program,
        accounts,
        data,
    })
}

/// `close_batch` (disc `[0x53,0x00]`) descriptor — FIXED 40 B (same shape as open).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CloseBatchDescriptor {
    /// The product template id.
    pub template_id: [u8; 32],
    /// The batch slot to close.
    pub batch_slot: u64,
}
impl CloseBatchDescriptor {
    /// Encode the 40-byte descriptor.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut d = Vec::with_capacity(40);
        d.extend_from_slice(&self.template_id);
        d.extend_from_slice(&self.batch_slot.to_le_bytes());
        d
    }
}

/// `close_batch` (disc `[0x53,0x00]`) — close a batch + create the settle scaffolding (escrow=0). 1
/// signer = the permissionless cranker. 6 accounts byte-exact; the 2 histogram PDAs carry the side seed.
#[must_use]
pub fn ix_close_batch(cranker: &Pubkey, descriptor: &CloseBatchDescriptor) -> Option<Instruction> {
    let program = skew_program_id()?;
    let tid = &descriptor.template_id;
    let slot = descriptor.batch_slot.to_le_bytes();
    let (batch_state, _b1) = find_program_address(&[b"batch", tid, &slot], &program)?;
    let (batch_result, _b2) = find_program_address(&[b"batch_result", tid, &slot], &program)?;
    let (histogram_supply, _b3) =
        find_program_address(&[b"histogram", tid, &slot, &[SIDE_ASK]], &program)?;
    let (histogram_demand, _b4) =
        find_program_address(&[b"histogram", tid, &slot, &[SIDE_BID]], &program)?;
    let mut data = vec![0x53u8, 0x00];
    data.extend_from_slice(&descriptor.encode());
    let accounts = vec![
        AccountMeta::writable(*cranker, true), // cranker (signer, mut)
        AccountMeta::writable(batch_state, false), // batch_state (mut)
        AccountMeta::writable(batch_result, false), // batch_result (init)
        AccountMeta::writable(histogram_supply, false), // histogram_supply (init, SIDE_ASK)
        AccountMeta::writable(histogram_demand, false), // histogram_demand (init, SIDE_BID)
        AccountMeta::readonly(system_program_id(), false), // system_program
    ];
    Some(Instruction {
        program_id: program,
        accounts,
        data,
    })
}

/// `settle_batch` (disc `[0x54,0x00]`) descriptor — FIXED 49 B (`settle_batch.rs`): adds the multishard
/// phase + shard index/count after the 40-byte prefix.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SettleBatchDescriptor {
    /// The product template id.
    pub template_id: [u8; 32],
    /// The batch slot to settle.
    pub batch_slot: u64,
    /// The multishard phase (0=Ingest, 1=Clear, 2=Fill, 3=SinglePass).
    pub phase: u8,
    /// The 0-based shard index within the phase.
    pub shard_index: u32,
    /// The shard count.
    pub shard_count: u32,
}
impl SettleBatchDescriptor {
    /// Encode the 49-byte descriptor.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut d = Vec::with_capacity(49);
        d.extend_from_slice(&self.template_id);
        d.extend_from_slice(&self.batch_slot.to_le_bytes());
        d.push(self.phase);
        d.extend_from_slice(&self.shard_index.to_le_bytes());
        d.extend_from_slice(&self.shard_count.to_le_bytes());
        d
    }
}

/// `settle_batch` (disc `[0x54,0x00]`) — deterministic batch clearing (escrow=0; conservation-exact). 1
/// signer = the permissionless cranker. 7 accounts byte-exact (histogram side seeds).
#[must_use]
pub fn ix_settle_batch(
    cranker: &Pubkey,
    descriptor: &SettleBatchDescriptor,
) -> Option<Instruction> {
    let program = skew_program_id()?;
    let tid = &descriptor.template_id;
    let slot = descriptor.batch_slot.to_le_bytes();
    let (product_template, _b1) = find_program_address(&[b"product_template", tid], &program)?;
    let (batch_state, _b2) = find_program_address(&[b"batch", tid, &slot], &program)?;
    let (batch_result, _b3) = find_program_address(&[b"batch_result", tid, &slot], &program)?;
    let (histogram_supply, _b4) =
        find_program_address(&[b"histogram", tid, &slot, &[SIDE_ASK]], &program)?;
    let (histogram_demand, _b5) =
        find_program_address(&[b"histogram", tid, &slot, &[SIDE_BID]], &program)?;
    let mut data = vec![0x54u8, 0x00];
    data.extend_from_slice(&descriptor.encode());
    let accounts = vec![
        AccountMeta::writable(*cranker, true), // cranker (signer, mut)
        AccountMeta::readonly(product_template, false), // product_template (ro)
        AccountMeta::writable(batch_state, false), // batch_state (mut)
        AccountMeta::writable(batch_result, false), // batch_result (mut)
        AccountMeta::writable(histogram_supply, false), // histogram_supply (mut, SIDE_ASK)
        AccountMeta::writable(histogram_demand, false), // histogram_demand (mut, SIDE_BID)
        AccountMeta::readonly(system_program_id(), false), // system_program
    ];
    Some(Instruction {
        program_id: program,
        accounts,
        data,
    })
}

/// `claim_fill` (disc `[0x55,0x00]`) descriptor (`BatchCompletionDescriptor`) — FIXED 48 B.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ClaimFillDescriptor {
    /// The product template id.
    pub template_id: [u8; 32],
    /// The batch slot.
    pub batch_slot: u64,
    /// The order owner's nonce (the OrderPda seed tail).
    pub nonce: u64,
}
impl ClaimFillDescriptor {
    /// Encode the 48-byte descriptor.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut d = Vec::with_capacity(48);
        d.extend_from_slice(&self.template_id);
        d.extend_from_slice(&self.batch_slot.to_le_bytes());
        d.extend_from_slice(&self.nonce.to_le_bytes());
        d
    }
}

/// `claim_fill` (disc `[0x55,0x00]`) — reconcile a matched order's escrow: the unmatched proportion is
/// refunded to the ORDER OWNER (NOT the caller); escrow=0 from the caller. 1 signer = the permissionless
/// caller. 11 accounts byte-exact. `order_owner` is a caller input (the refund recipient + the order PDA
/// seed); the recipient ATA is the order owner's ATA.
#[must_use]
pub fn ix_claim_fill(
    caller: &Pubkey,
    settlement_mint: &Pubkey,
    order_owner: &Pubkey,
    descriptor: &ClaimFillDescriptor,
) -> Option<Instruction> {
    let program = skew_program_id()?;
    let tid = &descriptor.template_id;
    let slot = descriptor.batch_slot.to_le_bytes();
    let nonce = descriptor.nonce.to_le_bytes();
    let (product_template, _b1) = find_program_address(&[b"product_template", tid], &program)?;
    let (batch_result, _b2) = find_program_address(&[b"batch_result", tid, &slot], &program)?;
    let (order, _b3) =
        find_program_address(&[b"order", tid, &slot, &order_owner.0, &nonce], &program)?;
    let recipient_ata = associated_token_address(order_owner, settlement_mint)?;
    let (batch_vault, _b4) = find_program_address(&[b"batch_vault", tid, &slot], &program)?;
    let (batch_vault_auth, _b5) =
        find_program_address(&[b"batch_vault_authority", tid, &slot], &program)?;
    let (claim_receipt, _b6) = find_program_address(
        &[b"claim_receipt", tid, &slot, &order_owner.0, &nonce],
        &program,
    )?;
    let token = Pubkey::from_base58(TOKEN_PROGRAM_ID)?;
    let mut data = vec![0x55u8, 0x00];
    data.extend_from_slice(&descriptor.encode());
    let accounts = vec![
        AccountMeta::writable(*caller, true), // caller (signer, mut)
        AccountMeta::readonly(*order_owner, false), // order_owner (address-only)
        AccountMeta::readonly(product_template, false), // product_template (ro)
        AccountMeta::readonly(batch_result, false), // batch_result (ro)
        AccountMeta::writable(order, false),  // order (mut)
        AccountMeta::writable(recipient_ata, false), // recipient_token_account (order owner ATA)
        AccountMeta::writable(batch_vault, false), // batch_vault (mut)
        AccountMeta::readonly(batch_vault_auth, false), // batch_vault_authority (ro, CPI signer)
        AccountMeta::writable(claim_receipt, false), // claim_receipt (init)
        AccountMeta::readonly(token, false),  // token_program
        AccountMeta::readonly(system_program_id(), false), // system_program
    ];
    Some(Instruction {
        program_id: program,
        accounts,
        data,
    })
}

/// `settle_batch_contract` (disc `[0x5A,0x00]`) descriptor — FIXED 96 B (`settle_batch_contract.rs`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SettleBatchContractDescriptor {
    /// The program-authored OTC contract id.
    pub contract_id: [u8; 32],
    /// The settlement price (untrusted; clamped+snapped on-chain).
    pub settlement_price: u128,
    /// Collar low bound (re-supplied, terms-bound).
    pub collar_lo: i128,
    /// Collar high bound (re-supplied).
    pub collar_hi: i128,
    /// Lattice step τ (re-supplied).
    pub tick_tau: u128,
}
impl SettleBatchContractDescriptor {
    /// Encode the 96-byte descriptor.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut d = Vec::with_capacity(96);
        d.extend_from_slice(&self.contract_id);
        d.extend_from_slice(&self.settlement_price.to_le_bytes());
        d.extend_from_slice(&self.collar_lo.to_le_bytes());
        d.extend_from_slice(&self.collar_hi.to_le_bytes());
        d.extend_from_slice(&self.tick_tau.to_le_bytes());
        d
    }
}

/// `settle_batch_contract` (disc `[0x5A,0x00]`) — settle a program-authored batch-formed contract
/// (escrow=0; disburses the net payoff to the winner from the posted collateral). 1 signer =
/// permissionless caller. 10 accounts byte-exact. `template_id` (product_template, rederived) +
/// `receiver_token_account` (the winner's ATA) are caller inputs.
#[must_use]
pub fn ix_settle_batch_contract(
    signer: &Pubkey,
    settlement_mint: &Pubkey,
    template_id: &[u8; 32],
    receiver_token_account: &Pubkey,
    descriptor: &SettleBatchContractDescriptor,
) -> Option<Instruction> {
    let program = skew_program_id()?;
    let cid = &descriptor.contract_id;
    let (otc_contract, _b1) = find_program_address(&[b"otc_contract", cid], &program)?;
    let (product_template, _b2) =
        find_program_address(&[b"product_template", template_id], &program)?;
    let (settlement_receipt, _b3) = find_program_address(&[b"settlement_receipt", cid], &program)?;
    let (collateral_vault, _b4) = find_program_address(&[b"collateral_vault", cid], &program)?;
    let (collateral_vault_auth, _b5) =
        find_program_address(&[b"collateral_vault_authority", cid], &program)?;
    let token = Pubkey::from_base58(TOKEN_PROGRAM_ID)?;
    let mut data = vec![0x5Au8, 0x00];
    data.extend_from_slice(&descriptor.encode());
    let accounts = vec![
        AccountMeta::writable(*signer, true), // signer (mut) — permissionless settler
        AccountMeta::writable(otc_contract, false), // otc_contract (mut)
        AccountMeta::readonly(product_template, false), // product_template (ro, rederived)
        AccountMeta::writable(settlement_receipt, false), // settlement_receipt (init)
        AccountMeta::writable(collateral_vault, false), // collateral_vault (mut)
        AccountMeta::readonly(collateral_vault_auth, false), // collateral_vault_authority (ro, CPI signer)
        AccountMeta::writable(*receiver_token_account, false), // receiver_token_account (winner ATA)
        AccountMeta::readonly(*settlement_mint, false),        // token_mint (ro)
        AccountMeta::readonly(token, false),                   // token_program
        AccountMeta::readonly(system_program_id(), false),     // system_program
    ];
    Some(Instruction {
        program_id: program,
        accounts,
        data,
    })
}

// ============================================================================
// The KEEPER band (permissionless deterministic-liveness ops). All 2-byte u16-LE discs
// (lib.rs:1123/1233/1291/1383). The keeper signer is NOT a trading party + commits NO per-caller escrow
// (escrow=0; disbursements come from the protocol's posted collateral / funding pool, never the keeper's
// wallet — the "aligned permissionless liveness" model). Descriptors + accounts byte-exact (the handler
// `#[derive(Accounts)]`); seeds from pda.rs. `settle_batch_contract` (0x5A) is in Wave C (shared).
// ============================================================================

/// `validate_reference_snapshot` (disc `[0x64,0x00]`) descriptor — FIXED 113 B.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ValidateReferenceSnapshotDescriptor {
    /// The perp market id.
    pub market_id: [u8; 32],
    /// The oracle source id.
    pub source_id: u32,
    /// The slot the price was observed at.
    pub observed_slot: u64,
    /// The price numerator (atoms).
    pub numerator_atoms: u128,
    /// The price divisor (atoms).
    pub divisor_atoms: u128,
    /// Confidence in basis points.
    pub confidence_bps: u16,
    /// Bid/ask spread in basis points.
    pub bid_ask_spread_bps: u16,
    /// The price exponent.
    pub exponent: u8,
    /// SHA-256 of the source payload.
    pub source_payload_hash: [u8; 32],
}
impl ValidateReferenceSnapshotDescriptor {
    /// Encode the 113-byte descriptor.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut d = Vec::with_capacity(113);
        d.extend_from_slice(&self.market_id);
        d.extend_from_slice(&self.source_id.to_le_bytes());
        d.extend_from_slice(&self.observed_slot.to_le_bytes());
        d.extend_from_slice(&self.numerator_atoms.to_le_bytes());
        d.extend_from_slice(&self.divisor_atoms.to_le_bytes());
        d.extend_from_slice(&self.confidence_bps.to_le_bytes());
        d.extend_from_slice(&self.bid_ask_spread_bps.to_le_bytes());
        d.push(self.exponent);
        d.extend_from_slice(&self.source_payload_hash);
        d
    }
}

/// `validate_reference_snapshot` (disc `[0x64,0x00]`) — the permissionless reference firewall validator
/// (escrow=0; writes the snapshot singleton). 1 signer = the keeper. 4 accounts byte-exact.
#[must_use]
pub fn ix_validate_reference_snapshot(
    caller: &Pubkey,
    descriptor: &ValidateReferenceSnapshotDescriptor,
) -> Option<Instruction> {
    let program = skew_program_id()?;
    let m = &descriptor.market_id;
    let (reference_policy, _b1) = find_program_address(&[b"reference_policy", m], &program)?;
    let (reference_snapshot, _b2) = find_program_address(&[b"reference_snapshot", m], &program)?;
    let mut data = vec![0x64u8, 0x00];
    data.extend_from_slice(&descriptor.encode());
    let accounts = vec![
        AccountMeta::writable(*caller, true), // caller (signer, mut) — permissionless keeper
        AccountMeta::readonly(reference_policy, false), // reference_policy (ro)
        AccountMeta::writable(reference_snapshot, false), // reference_snapshot (init_if_needed)
        AccountMeta::readonly(system_program_id(), false), // system_program
    ];
    Some(Instruction {
        program_id: program,
        accounts,
        data,
    })
}

/// `advance_funding_epoch` (disc `[0x6D,0x00]`) descriptor — FIXED 40 B.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AdvanceFundingEpochDescriptor {
    /// The perp market id.
    pub market_id: [u8; 32],
    /// The risk epoch sequence.
    pub epoch_seq: u64,
}
impl AdvanceFundingEpochDescriptor {
    /// Encode the 40-byte descriptor.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut d = Vec::with_capacity(40);
        d.extend_from_slice(&self.market_id);
        d.extend_from_slice(&self.epoch_seq.to_le_bytes());
        d
    }
}

/// `advance_funding_epoch` (disc `[0x6D,0x00]`) — the permissionless funding crank (escrow=0). 1 signer
/// = the keeper. 5 accounts byte-exact.
#[must_use]
pub fn ix_advance_funding_epoch(
    caller: &Pubkey,
    descriptor: &AdvanceFundingEpochDescriptor,
) -> Option<Instruction> {
    let program = skew_program_id()?;
    let m = &descriptor.market_id;
    let epoch = descriptor.epoch_seq.to_le_bytes();
    let (perp_market, _b1) = find_program_address(&[b"perp_market", m], &program)?;
    let (reference_snapshot, _b2) = find_program_address(&[b"reference_snapshot", m], &program)?;
    let (risk_epoch, _b3) = find_program_address(&[b"risk_epoch", m, &epoch], &program)?;
    let (funding_state, _b4) = find_program_address(&[b"funding_state", m], &program)?;
    let mut data = vec![0x6Du8, 0x00];
    data.extend_from_slice(&descriptor.encode());
    let accounts = vec![
        AccountMeta::writable(*caller, true), // caller (signer, fee payer)
        AccountMeta::readonly(perp_market, false), // perp_market (ro)
        AccountMeta::readonly(reference_snapshot, false), // reference_snapshot (ro)
        AccountMeta::readonly(risk_epoch, false), // risk_epoch (ro)
        AccountMeta::writable(funding_state, false), // funding_state (mut)
    ];
    Some(Instruction {
        program_id: program,
        accounts,
        data,
    })
}

/// `settle_account_funding` (disc `[0x72,0x00]`) descriptor — FIXED 104 B.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SettleAccountFundingDescriptor {
    /// The perp market id.
    pub market_id: [u8; 32],
    /// The settlement mint.
    pub settlement_mint: Pubkey,
    /// The position owner.
    pub owner: Pubkey,
    /// The epoch sequence.
    pub epoch_seq: u64,
}
impl SettleAccountFundingDescriptor {
    /// Encode the 104-byte descriptor.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut d = Vec::with_capacity(104);
        d.extend_from_slice(&self.market_id);
        d.extend_from_slice(&self.settlement_mint.0);
        d.extend_from_slice(&self.owner.0);
        d.extend_from_slice(&self.epoch_seq.to_le_bytes());
        d
    }
}

/// `settle_account_funding` (disc `[0x72,0x00]`) — the permissionless per-position funding settler
/// (escrow=0; moves internal ledger buckets, no per-caller token CPI). 1 signer = the keeper. 8 accounts.
#[must_use]
pub fn ix_settle_account_funding(
    caller: &Pubkey,
    descriptor: &SettleAccountFundingDescriptor,
) -> Option<Instruction> {
    let program = skew_program_id()?;
    let m = &descriptor.market_id;
    let owner = &descriptor.owner.0;
    let mint = &descriptor.settlement_mint.0;
    let epoch = descriptor.epoch_seq.to_le_bytes();
    let (perp_market, _b1) = find_program_address(&[b"perp_market", m], &program)?;
    let (risk_epoch, _b2) = find_program_address(&[b"risk_epoch", m, &epoch], &program)?;
    let (funding_state, _b3) = find_program_address(&[b"funding_state", m], &program)?;
    let (perp_position, _b4) = find_program_address(&[b"perp_position", m, owner], &program)?;
    let (ura, _b5) = find_program_address(&[b"unified_risk_account", owner, mint], &program)?;
    let (funding_pool, _b6) = find_program_address(&[b"perp_funding_pool", m], &program)?;
    let mut data = vec![0x72u8, 0x00];
    data.extend_from_slice(&descriptor.encode());
    let accounts = vec![
        AccountMeta::writable(*caller, true), // caller (signer, mut) — keeper
        AccountMeta::readonly(perp_market, false), // perp_market (ro)
        AccountMeta::readonly(risk_epoch, false), // risk_epoch (ro)
        AccountMeta::readonly(funding_state, false), // funding_state (ro)
        AccountMeta::writable(perp_position, false), // perp_position (mut)
        AccountMeta::writable(ura, false),    // unified_risk_account (mut)
        AccountMeta::writable(funding_pool, false), // perp_funding_pool (init_if_needed)
        AccountMeta::readonly(system_program_id(), false), // system_program
    ];
    Some(Instruction {
        program_id: program,
        accounts,
        data,
    })
}

/// `force_reduce_position` (disc `[0x78,0x00]`) descriptor — FIXED 104 B.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ForceReducePositionDescriptor {
    /// The perp market id.
    pub market_id: [u8; 32],
    /// The settlement mint.
    pub settlement_mint: Pubkey,
    /// The position owner.
    pub owner: Pubkey,
    /// The admitted epoch sequence (the pinned band).
    pub admitted_epoch_seq: u64,
}
impl ForceReducePositionDescriptor {
    /// Encode the 104-byte descriptor.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut d = Vec::with_capacity(104);
        d.extend_from_slice(&self.market_id);
        d.extend_from_slice(&self.settlement_mint.0);
        d.extend_from_slice(&self.owner.0);
        d.extend_from_slice(&self.admitted_epoch_seq.to_le_bytes());
        d
    }
}

/// `force_reduce_position` (disc `[0x78,0x00]`) — the permissionless CloseOnly position-reducer (the
/// whale-cap DoS-closure liveness handler; escrow=0; realized P&L moves internal ledgers + an optional
/// backstop draw, never the keeper's wallet). 1 signer = the keeper. 16 accounts byte-exact.
#[must_use]
pub fn ix_force_reduce_position(
    caller: &Pubkey,
    descriptor: &ForceReducePositionDescriptor,
) -> Option<Instruction> {
    let program = skew_program_id()?;
    let m = &descriptor.market_id;
    let owner = &descriptor.owner.0;
    let mint = &descriptor.settlement_mint.0;
    let epoch = descriptor.admitted_epoch_seq.to_le_bytes();
    let (perp_market, _b1) = find_program_address(&[b"perp_market", m], &program)?;
    let (admitted_epoch, _b2) = find_program_address(&[b"risk_epoch", m, &epoch], &program)?;
    let (reference_snapshot, _b3) = find_program_address(&[b"reference_snapshot", m], &program)?;
    let (funding_state, _b4) = find_program_address(&[b"funding_state", m], &program)?;
    let (perp_position, _b5) = find_program_address(&[b"perp_position", m, owner], &program)?;
    let (ura, _b6) = find_program_address(&[b"unified_risk_account", owner, mint], &program)?;
    let (funding_pool, _b7) = find_program_address(&[b"perp_funding_pool", m], &program)?;
    let (backstop_vault, _b8) = find_program_address(&[b"backstop_vault", m], &program)?;
    let (backstop_reserve, _b9) = find_program_address(&[b"backstop_reserve_vault", m], &program)?;
    let (backstop_auth, _b10) = find_program_address(&[b"backstop_vault_authority", m], &program)?;
    let (perp_margin_vault, _b11) = find_program_address(&[b"perp_margin_vault", mint], &program)?;
    let (margin_pool, _b12) = find_program_address(&[b"unified_margin_pool", mint], &program)?;
    let (reference_policy, _b13) = find_program_address(&[b"reference_policy", m], &program)?;
    let token = Pubkey::from_base58(TOKEN_PROGRAM_ID)?;
    let mut data = vec![0x78u8, 0x00];
    data.extend_from_slice(&descriptor.encode());
    let accounts = vec![
        AccountMeta::writable(*caller, true), // caller (signer, mut) — keeper
        AccountMeta::writable(perp_market, false), // perp_market (mut, OI decrement)
        AccountMeta::readonly(admitted_epoch, false), // admitted_epoch (ro)
        AccountMeta::readonly(reference_snapshot, false), // reference_snapshot (ro)
        AccountMeta::readonly(funding_state, false), // funding_state (ro)
        AccountMeta::writable(perp_position, false), // perp_position (mut)
        AccountMeta::writable(ura, false),    // unified_risk_account (mut)
        AccountMeta::writable(funding_pool, false), // perp_funding_pool (init_if_needed)
        AccountMeta::writable(backstop_vault, false), // backstop_vault (mut)
        AccountMeta::writable(backstop_reserve, false), // backstop_reserve_vault (mut)
        AccountMeta::readonly(backstop_auth, false), // backstop_vault_authority (ro, CPI signer)
        AccountMeta::writable(perp_margin_vault, false), // perp_margin_vault (mut)
        AccountMeta::writable(margin_pool, false), // margin_pool (mut)
        AccountMeta::readonly(reference_policy, false), // reference_policy (ro)
        AccountMeta::readonly(token, false),  // token_program
        AccountMeta::readonly(system_program_id(), false), // system_program
    ];
    Some(Instruction {
        program_id: program,
        accounts,
        data,
    })
}

// ============================================================================
// The VARIABLE-leg permissionless listing /
// piecewise instructions. All 2-byte u16-LE discs (lib.rs:645/663/684/702
// `#[instruction(discriminator=[lo,hi])]` — the disc authority).
// The NESTED Vec legs (`ModeCDescriptor` = `Vec<AffineCoord>`, `PiecewiseAffine1D`
// = `Vec<PieceSegment>`) are byte-exact from `collateral/mode_c.rs` (the hard part
// resolved from source, NOT guessed — earlier reads conflicted on the
// `PiecewiseAffine1D` field widths; source says i128/i128/u128 + `Vec<PieceSegment>`).
// borsh canonical: i128/u128 = 16 LE · Vec<T> = u32-LE count ‖ count×T · enum =
// 1-byte variant index ‖ payload. Seeds from pda.rs (b"piecewise_contract" /
// b"piecewise_vault" / b"piecewise_vault_authority" / b"product_template").
// ============================================================================

/// One affine coordinate of a [`ModeCDescriptor`] — byte-exact from `mode_c.rs:124`
/// (`AffineCoord`, borsh body == 64 bytes). The affine form is `f(S) = konst +
/// Σ_j coeff_j·S_j`; each coordinate ranges over the lattice `{lo, lo+tau, ..=hi}`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AffineCoord {
    /// Per-coordinate slope `coeff_j` (signed `i128`).
    pub coeff: i128,
    /// Lattice low bound (signed `i128`; `lo < hi`).
    pub lo: i128,
    /// Lattice high bound (signed `i128`).
    pub hi: i128,
    /// Lattice step `tau` (unsigned `u128`; `>= 1`).
    pub tau: u128,
}
impl AffineCoord {
    /// Append the 64-byte borsh body (declaration order, LE).
    fn encode_into(&self, d: &mut Vec<u8>) {
        d.extend_from_slice(&self.coeff.to_le_bytes()); // i128 LE (16)
        d.extend_from_slice(&self.lo.to_le_bytes()); // i128 LE (16)
        d.extend_from_slice(&self.hi.to_le_bytes()); // i128 LE (16)
        d.extend_from_slice(&self.tau.to_le_bytes()); // u128 LE (16)
    }
}

/// A Mode-C affine payoff descriptor — byte-exact from `mode_c.rs:153`
/// (`ModeCDescriptor`, borsh body == `20 + 64·d`): `konst:i128 ‖ coords:Vec<AffineCoord>`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ModeCDescriptor {
    /// Affine constant term `konst` (signed `i128`).
    pub konst: i128,
    /// The `d` affine coordinates (`1 <= d <= 8`).
    pub coords: Vec<AffineCoord>,
}
impl ModeCDescriptor {
    /// Append the borsh body (`konst(16) ‖ u32-LE len ‖ d×AffineCoord(64)`).
    fn encode_into(&self, d: &mut Vec<u8>) {
        d.extend_from_slice(&self.konst.to_le_bytes()); // i128 LE (16)
        let n = u32::try_from(self.coords.len()).unwrap_or(u32::MAX);
        d.extend_from_slice(&n.to_le_bytes()); // u32 LE count (4)
        for c in &self.coords {
            c.encode_into(d); // 64·d
        }
    }
}

/// The sup-provider certificate kind accompanying a declared bound — byte-exact from
/// `mode_c.rs:183` (`ModeCCertKind`, `#[borsh(use_discriminant = true)] #[repr(u8)]`).
/// borsh enum = 1-byte variant index ‖ payload (`MachineProofII` carries 32 bytes).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ModeCCertKind {
    /// C-i full Mode-B grid-max enumeration (sound; on-chain self-verifying). idx 0.
    GridMaxI,
    /// C-ii machine-checked-proof hash (fail-closed-deferred on-chain). idx 1 ‖ 32 B.
    MachineProofII([u8; 32]),
    /// C-iii affine interval / sign-corner (sound; EXACT for affine). idx 2.
    IntervalAffineIII,
    /// FORBIDDEN — corner probe (UDSI P3). idx 3.
    CornerProbe,
    /// FORBIDDEN — finite sample. idx 4.
    Sample,
    /// FORBIDDEN — Monte-Carlo estimate. idx 5.
    MonteCarlo,
    /// FORBIDDEN — self-attested flag. idx 6.
    SelfDeclaredFlag,
}
impl ModeCCertKind {
    /// Append the borsh variant index byte (+ the 32-byte hash for `MachineProofII`).
    fn encode_into(&self, d: &mut Vec<u8>) {
        match self {
            Self::GridMaxI => d.push(0),
            Self::MachineProofII(h) => {
                d.push(1);
                d.extend_from_slice(h);
            }
            Self::IntervalAffineIII => d.push(2),
            Self::CornerProbe => d.push(3),
            Self::Sample => d.push(4),
            Self::MonteCarlo => d.push(5),
            Self::SelfDeclaredFlag => d.push(6),
        }
    }
}

/// One affine piece of a [`PiecewiseAffine1D`] payoff — byte-exact from `mode_c.rs:733`
/// (`PieceSegment`, borsh body == 48 bytes): `x_hi:i128 ‖ coeff:i128 ‖ konst:i128`.
/// ⚠ Earlier reads conflicted (u32×3 vs i128×3); SOURCE says all `i128`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PieceSegment {
    /// Inclusive upper breakpoint (on-lattice; the last segment's `x_hi == hi`).
    pub x_hi: i128,
    /// Slope `coeff` on this segment (signed `i128`).
    pub coeff: i128,
    /// Intercept `konst`; `f(S) = konst + coeff·S` on this segment (signed `i128`).
    pub konst: i128,
}
impl PieceSegment {
    /// Append the 48-byte borsh body (declaration order, LE).
    fn encode_into(&self, d: &mut Vec<u8>) {
        d.extend_from_slice(&self.x_hi.to_le_bytes()); // i128 LE (16)
        d.extend_from_slice(&self.coeff.to_le_bytes()); // i128 LE (16)
        d.extend_from_slice(&self.konst.to_le_bytes()); // i128 LE (16)
    }
}

/// A 1-D piecewise-affine payoff descriptor — byte-exact from `mode_c.rs:759`
/// (`PiecewiseAffine1D`, borsh body == `52 + 48·m`): `lo:i128 ‖ hi:i128 ‖ tau:u128
/// ‖ segments:Vec<PieceSegment>`. Supports EVERY bounded payoff (option / spread /
/// digital / straddle) as a single 1-D piecewise `f` over the collar lattice.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PiecewiseAffine1D {
    /// Collar low bound (signed `i128`; `lo < hi`).
    pub lo: i128,
    /// Collar high bound (signed `i128`; `== the last segment's x_hi`).
    pub hi: i128,
    /// Lattice step (unsigned `u128`; `>= 1`).
    pub tau: u128,
    /// The `m` affine segments (`1 <= m <= 16`), strictly-ascending `x_hi`.
    pub segments: Vec<PieceSegment>,
}
impl PiecewiseAffine1D {
    /// Append the borsh body (`lo(16) ‖ hi(16) ‖ tau(16) ‖ u32-LE len ‖ m×PieceSegment(48)`).
    fn encode_into(&self, d: &mut Vec<u8>) {
        d.extend_from_slice(&self.lo.to_le_bytes()); // i128 LE (16)
        d.extend_from_slice(&self.hi.to_le_bytes()); // i128 LE (16)
        d.extend_from_slice(&self.tau.to_le_bytes()); // u128 LE (16)
        let n = u32::try_from(self.segments.len()).unwrap_or(u32::MAX);
        d.extend_from_slice(&n.to_le_bytes()); // u32 LE count (4)
        for s in &self.segments {
            s.encode_into(d); // 48·m
        }
    }
}

/// The `list_wcc_template` (disc `[0x50,0x00]`) descriptor — byte-exact from
/// `list_wcc_template.rs:85` (`ListWccTemplateDescriptor`). Borsh wire = 314 bytes for
/// a d=1 forward with `IntervalAffineIII` certs (pinned by the on-chain test
/// `descriptor_borsh_wire_width_is_314`). PERMISSIONLESS affine forward/swap/collar
/// listing (escrow=0). `collateral_policy_id` MUST be `0x1B1B` (SKEW_COLLATERAL_WCC_V1).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ListWccTemplateDescriptor {
    /// 32-byte template id (the `product_template` PDA seed).
    pub template_id: [u8; 32],
    /// Template version (u32).
    pub version: u32,
    /// SHA-256 of the terms schema.
    pub terms_schema_hash: [u8; 32],
    /// The payoff adapter id (u16).
    pub payoff_adapter_id: u16,
    /// The settlement adapter id (u16).
    pub settlement_adapter_id: u16,
    /// The reference-data policy id (u16).
    pub reference_data_policy_id: u16,
    /// MUST equal `0x1B1B` (SKEW_COLLATERAL_WCC_V1) — the soundness binding (G-FAMILY).
    pub collateral_policy_id: u16,
    /// The VM policy id (u16).
    pub vm_policy_id: u16,
    /// SHA-256 of the receipt schema.
    pub receipt_schema_hash: [u8; 32],
    /// The long leg's affine payoff descriptor over its declared lattice.
    pub leg_long: ModeCDescriptor,
    /// The short leg's affine payoff (the antisymmetric partner; G-CONSERVATION).
    pub leg_short: ModeCDescriptor,
    /// Declared WCL bound for the long leg (`>=` the certified grid-max).
    pub declared_b_long: u128,
    /// Declared WCL bound for the short leg.
    pub declared_b_short: u128,
    /// Sup-provider certificate for the long leg.
    pub cert_long: ModeCCertKind,
    /// Sup-provider certificate for the short leg.
    pub cert_short: ModeCCertKind,
    /// FEE-2 fee-policy selector (must be a FORWARD-active id `6..=9`; appended at the tail).
    pub fee_policy_id: u16,
}
impl ListWccTemplateDescriptor {
    /// Encode the VARIABLE descriptor (byte-exact declaration order; the 2 legs +
    /// 2 certs are nested borsh; FEE-2 `fee_policy_id` at the tail).
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut d = Vec::new();
        d.extend_from_slice(&self.template_id);
        d.extend_from_slice(&self.version.to_le_bytes());
        d.extend_from_slice(&self.terms_schema_hash);
        d.extend_from_slice(&self.payoff_adapter_id.to_le_bytes());
        d.extend_from_slice(&self.settlement_adapter_id.to_le_bytes());
        d.extend_from_slice(&self.reference_data_policy_id.to_le_bytes());
        d.extend_from_slice(&self.collateral_policy_id.to_le_bytes());
        d.extend_from_slice(&self.vm_policy_id.to_le_bytes());
        d.extend_from_slice(&self.receipt_schema_hash);
        self.leg_long.encode_into(&mut d);
        self.leg_short.encode_into(&mut d);
        d.extend_from_slice(&self.declared_b_long.to_le_bytes());
        d.extend_from_slice(&self.declared_b_short.to_le_bytes());
        self.cert_long.encode_into(&mut d);
        self.cert_short.encode_into(&mut d);
        d.extend_from_slice(&self.fee_policy_id.to_le_bytes());
        d
    }
}

/// `list_wcc_template` (disc `[0x50,0x00]`) — the PERMISSIONLESS affine-template
/// registration (the on-chain UDSI math gate replaces an admin authority). SINGLE-PARTY
/// (1 signer = the lister/rent-payer); escrow=0 (a listing moves no settlement value).
/// Data = `[0x50,0x00] ‖ descriptor(VARIABLE)`. 5 accounts byte-exact from
/// `list_wcc_template.rs`'s `#[derive(Accounts)]` order: lister(signer,mut) ·
/// product_template(init,[b"product_template",template_id]) · settlement_mint(ro) ·
/// token_program · system_program. Fail-closed on any PDA / id failure.
#[must_use]
pub fn ix_list_wcc_template(
    lister: &Pubkey,
    settlement_mint: &Pubkey,
    descriptor: &ListWccTemplateDescriptor,
) -> Option<Instruction> {
    let program = skew_program_id()?;
    let (product_template, _b1) =
        find_program_address(&[b"product_template", &descriptor.template_id], &program)?;
    let token = Pubkey::from_base58(TOKEN_PROGRAM_ID)?;
    let mut data = vec![0x50u8, 0x00];
    data.extend_from_slice(&descriptor.encode());
    let accounts = vec![
        AccountMeta::writable(*lister, true), // lister (signer, mut) — rent payer
        AccountMeta::writable(product_template, false), // product_template (init)
        AccountMeta::readonly(*settlement_mint, false), // settlement_mint (ro, GOV-15)
        AccountMeta::readonly(token, false),  // token_program
        AccountMeta::readonly(system_program_id(), false), // system_program
    ];
    Some(Instruction {
        program_id: program,
        accounts,
        data,
    })
}

/// The `list_piecewise_template` (disc `[0x86,0x00]`) descriptor — byte-exact from
/// `list_piecewise_template.rs:96` (`ListPiecewiseTemplateDescriptor`). Borsh wire = 438
/// bytes for the m=2 straddle (pinned by the on-chain test `straddle_descriptor_borsh_width_is_438`).
/// The non-affine (option/spread/digital/straddle) twin of `list_wcc_template`: the legs are
/// [`PiecewiseAffine1D`] (vs `ModeCDescriptor`), there is NO `cert_*` field (the piecewise
/// certifier is ALWAYS the exact O(m) breakpoint enumeration), and NO `fee_policy_id` (a
/// piecewise template is not tradeable until the escrow path ships). `collateral_policy_id`
/// MUST be `0x8394` (SKEW_COLLATERAL_WCC_PIECEWISE_V1) so `submit_order`'s G9 fail-closes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ListPiecewiseTemplateDescriptor {
    /// 32-byte template id (the `product_template` PDA seed).
    pub template_id: [u8; 32],
    /// Template version (u32).
    pub version: u32,
    /// SHA-256 of the terms schema.
    pub terms_schema_hash: [u8; 32],
    /// The payoff adapter id (u16).
    pub payoff_adapter_id: u16,
    /// The settlement adapter id (u16).
    pub settlement_adapter_id: u16,
    /// The reference-data policy id (u16).
    pub reference_data_policy_id: u16,
    /// MUST equal `0x8394` (SKEW_COLLATERAL_WCC_PIECEWISE_V1) — the G-FAMILY binding.
    pub collateral_policy_id: u16,
    /// The VM policy id (u16).
    pub vm_policy_id: u16,
    /// SHA-256 of the receipt schema.
    pub receipt_schema_hash: [u8; 32],
    /// The long leg's piecewise-affine payoff over its declared collar lattice.
    pub leg_long: PiecewiseAffine1D,
    /// The short leg (the antisymmetric partner; G-CONSERVATION).
    pub leg_short: PiecewiseAffine1D,
    /// Declared WCL bound for the long leg (`>=` the certified breakpoint-min loss).
    pub declared_b_long: u128,
    /// Declared WCL bound for the short leg.
    pub declared_b_short: u128,
}
impl ListPiecewiseTemplateDescriptor {
    /// Encode the VARIABLE descriptor (byte-exact declaration order; 2 nested
    /// piecewise legs; NO cert / fee fields).
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut d = Vec::new();
        d.extend_from_slice(&self.template_id);
        d.extend_from_slice(&self.version.to_le_bytes());
        d.extend_from_slice(&self.terms_schema_hash);
        d.extend_from_slice(&self.payoff_adapter_id.to_le_bytes());
        d.extend_from_slice(&self.settlement_adapter_id.to_le_bytes());
        d.extend_from_slice(&self.reference_data_policy_id.to_le_bytes());
        d.extend_from_slice(&self.collateral_policy_id.to_le_bytes());
        d.extend_from_slice(&self.vm_policy_id.to_le_bytes());
        d.extend_from_slice(&self.receipt_schema_hash);
        self.leg_long.encode_into(&mut d);
        self.leg_short.encode_into(&mut d);
        d.extend_from_slice(&self.declared_b_long.to_le_bytes());
        d.extend_from_slice(&self.declared_b_short.to_le_bytes());
        d
    }
}

/// `list_piecewise_template` (disc `[0x86,0x00]`) — the PERMISSIONLESS piecewise-template
/// registration (options/spreads/digitals/straddles). SINGLE-PARTY (1 signer = the lister);
/// escrow=0. Data = `[0x86,0x00] ‖ descriptor(VARIABLE)`. 5 accounts byte-exact from
/// `list_piecewise_template.rs`'s `#[derive(Accounts)]` (same shape as `list_wcc_template`):
/// lister(signer,mut) · product_template(init,[b"product_template",template_id]) ·
/// settlement_mint(ro) · token_program · system_program. Fail-closed.
#[must_use]
pub fn ix_list_piecewise_template(
    lister: &Pubkey,
    settlement_mint: &Pubkey,
    descriptor: &ListPiecewiseTemplateDescriptor,
) -> Option<Instruction> {
    let program = skew_program_id()?;
    let (product_template, _b1) =
        find_program_address(&[b"product_template", &descriptor.template_id], &program)?;
    let token = Pubkey::from_base58(TOKEN_PROGRAM_ID)?;
    let mut data = vec![0x86u8, 0x00];
    data.extend_from_slice(&descriptor.encode());
    let accounts = vec![
        AccountMeta::writable(*lister, true), // lister (signer, mut) — rent payer
        AccountMeta::writable(product_template, false), // product_template (init)
        AccountMeta::readonly(*settlement_mint, false), // settlement_mint (ro, GOV-15)
        AccountMeta::readonly(token, false),  // token_program
        AccountMeta::readonly(system_program_id(), false), // system_program
    ];
    Some(Instruction {
        program_id: program,
        accounts,
        data,
    })
}

/// The `form_piecewise_contract` (disc `[0x87,0x00]`) descriptor — byte-exact from
/// `form_piecewise_contract.rs:74` (`FormPiecewiseContractDescriptor`). Bilateral
/// (2-signer) piecewise contract formation: each party escrows its OWN leg's certified
/// WCL (`piecewise_grid_bound(leg).bound`) into ONE shared vault. ★ 2 SIGNERS ⇒ a single
/// bounded agent CANNOT broadcast alone (it can't forge the counterparty signature) — the
/// codec + plan ASSEMBLE + SIMULATE only (the chokepoint's multi-sig guard returns
/// `Simulated`, never broadcasts); a real broadcast is a 2-agent / counterparty owner go-live.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FormPiecewiseContractDescriptor {
    /// 32-byte contract id (the `piecewise_contract` / vault PDA seed; `init`-once dedup).
    pub contract_id: [u8; 32],
    /// The parent piecewise `ProductTemplatePda.template_id` (collateral `0x8394`).
    pub template_id: [u8; 32],
    /// The long leg's piecewise-affine payoff (re-supplied; hash-bound to the template).
    pub leg_long: PiecewiseAffine1D,
    /// The short leg (the antisymmetric partner; G-CONSERVATION).
    pub leg_short: PiecewiseAffine1D,
    /// Declared WCL bound for the long leg (part of the hash preimage).
    pub declared_b_long: u128,
    /// Declared WCL bound for the short leg.
    pub declared_b_short: u128,
    /// Forward maturity (unix seconds); the program verifies `> clock.unix_timestamp`.
    pub maturity_timestamp: i64,
}
impl FormPiecewiseContractDescriptor {
    /// Encode the VARIABLE descriptor (byte-exact declaration order; 2 nested piecewise legs).
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut d = Vec::new();
        d.extend_from_slice(&self.contract_id);
        d.extend_from_slice(&self.template_id);
        self.leg_long.encode_into(&mut d);
        self.leg_short.encode_into(&mut d);
        d.extend_from_slice(&self.declared_b_long.to_le_bytes());
        d.extend_from_slice(&self.declared_b_short.to_le_bytes());
        d.extend_from_slice(&self.maturity_timestamp.to_le_bytes());
        d
    }
}

/// `form_piecewise_contract` (disc `[0x87,0x00]`) — bilateral piecewise formation + per-leg
/// escrow, ATOMIC. ★ 2 SIGNERS (long_party + short_party); the agent's isolated key plays
/// `long_party` (also the rent payer + fee payer) and `short_party` is a counterparty pubkey
/// (a self-cross sets both to the same key). escrow = escrow_long + escrow_short (the two
/// certified WCLs). Data = `[0x87,0x00] ‖ descriptor(VARIABLE)`. 11 accounts byte-exact from
/// `form_piecewise_contract.rs`'s `#[derive(Accounts)]` order. The source token accounts +
/// settlement mint are caller inputs (the descriptor omits the party/account pubkeys).
#[must_use]
pub fn ix_form_piecewise_contract(
    long_party: &Pubkey,
    short_party: &Pubkey,
    long_source_token: &Pubkey,
    short_source_token: &Pubkey,
    settlement_mint: &Pubkey,
    descriptor: &FormPiecewiseContractDescriptor,
) -> Option<Instruction> {
    let program = skew_program_id()?;
    let cid = &descriptor.contract_id;
    let (product_template, _b1) =
        find_program_address(&[b"product_template", &descriptor.template_id], &program)?;
    let (piecewise_contract, _b2) = find_program_address(&[b"piecewise_contract", cid], &program)?;
    let (collateral_vault, _b3) = find_program_address(&[b"piecewise_vault", cid], &program)?;
    let (collateral_vault_auth, _b4) =
        find_program_address(&[b"piecewise_vault_authority", cid], &program)?;
    let token = Pubkey::from_base58(TOKEN_PROGRAM_ID)?;
    let mut data = vec![0x87u8, 0x00];
    data.extend_from_slice(&descriptor.encode());
    let accounts = vec![
        AccountMeta::writable(*long_party, true), // long_party (signer, mut) — rent payer
        AccountMeta::writable(*short_party, true), // short_party (signer, mut)
        AccountMeta::readonly(product_template, false), // product_template (ro)
        AccountMeta::writable(piecewise_contract, false), // piecewise_contract (init)
        AccountMeta::writable(collateral_vault, false), // collateral_vault (init)
        AccountMeta::readonly(collateral_vault_auth, false), // collateral_vault_authority (ro)
        AccountMeta::writable(*long_source_token, false), // long_source_token (mut)
        AccountMeta::writable(*short_source_token, false), // short_source_token (mut)
        AccountMeta::readonly(*settlement_mint, false), // settlement_mint (ro)
        AccountMeta::readonly(token, false),      // token_program
        AccountMeta::readonly(system_program_id(), false), // system_program
    ];
    Some(Instruction {
        program_id: program,
        accounts,
        data,
    })
}

/// The `settle_piecewise_contract` (disc `[0x88,0x00]`) descriptor — byte-exact from
/// `settle_piecewise_contract.rs:61` (`SettlePiecewiseContractDescriptor`). The maturity-time
/// keeper settlement: re-supplies the hash-bound legs, clamp-snaps the reference, evaluates the
/// PWA, and disburses the shared vault. PERMISSIONLESS keeper (escrow=0; the disburse is bounded
/// by the posted vault, never the keeper's wallet).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SettlePiecewiseContractDescriptor {
    /// 32-byte contract id (the `piecewise_contract` / vault PDA seed).
    pub contract_id: [u8; 32],
    /// The long leg (re-supplied; hash-bound to the contract).
    pub leg_long: PiecewiseAffine1D,
    /// The short leg (re-supplied; antisymmetric partner).
    pub leg_short: PiecewiseAffine1D,
    /// Declared long bound (part of the hash preimage).
    pub declared_b_long: u128,
    /// Declared short bound (part of the hash preimage).
    pub declared_b_short: u128,
    /// The raw settlement reference price `r` (signed `i128`; clamp-snapped before any payoff eval).
    pub settlement_reference: i128,
}
impl SettlePiecewiseContractDescriptor {
    /// Encode the VARIABLE descriptor (byte-exact declaration order; 2 nested piecewise legs).
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut d = Vec::new();
        d.extend_from_slice(&self.contract_id);
        self.leg_long.encode_into(&mut d);
        self.leg_short.encode_into(&mut d);
        d.extend_from_slice(&self.declared_b_long.to_le_bytes());
        d.extend_from_slice(&self.declared_b_short.to_le_bytes());
        d.extend_from_slice(&self.settlement_reference.to_le_bytes());
        d
    }
}

/// `settle_piecewise_contract` (disc `[0x88,0x00]`) — the PERMISSIONLESS piecewise settle crank
/// (escrow=0; the keeper commits nothing). SINGLE-SIGNER (the caller, a settle crank — non-mut in
/// the handler but the tx fee payer ⇒ writable). Data = `[0x88,0x00] ‖ descriptor(VARIABLE)`. 7
/// accounts byte-exact from `settle_piecewise_contract.rs`'s `#[derive(Accounts)]` order. The
/// long/short destination token accounts are caller inputs.
#[must_use]
pub fn ix_settle_piecewise_contract(
    caller: &Pubkey,
    long_token_account: &Pubkey,
    short_token_account: &Pubkey,
    descriptor: &SettlePiecewiseContractDescriptor,
) -> Option<Instruction> {
    let program = skew_program_id()?;
    let cid = &descriptor.contract_id;
    let (piecewise_contract, _b1) = find_program_address(&[b"piecewise_contract", cid], &program)?;
    let (collateral_vault, _b2) = find_program_address(&[b"piecewise_vault", cid], &program)?;
    let (collateral_vault_auth, _b3) =
        find_program_address(&[b"piecewise_vault_authority", cid], &program)?;
    let token = Pubkey::from_base58(TOKEN_PROGRAM_ID)?;
    let mut data = vec![0x88u8, 0x00];
    data.extend_from_slice(&descriptor.encode());
    let accounts = vec![
        // the handler marks the caller non-mut, but it is the tx fee payer ⇒ writable (auto-promoted).
        AccountMeta::writable(*caller, true), // caller (signer) — permissionless keeper
        AccountMeta::writable(piecewise_contract, false), // piecewise_contract (mut → Settled)
        AccountMeta::writable(collateral_vault, false), // collateral_vault (mut — disburse source)
        AccountMeta::readonly(collateral_vault_auth, false), // collateral_vault_authority (ro, CPI signer)
        AccountMeta::writable(*long_token_account, false),   // long_token_account (mut)
        AccountMeta::writable(*short_token_account, false),  // short_token_account (mut)
        AccountMeta::readonly(token, false),                 // token_program
    ];
    Some(Instruction {
        program_id: program,
        accounts,
        data,
    })
}

// ---------------------------------------------------------------------------
// The 5 catalog-only-on-chain ix Sinabro now ASSEMBLES byte-exact.
// (1) open_perp_market (0x6A) + factory_list_perp_market (0x81): PERMISSIONLESS perp-market
//     listing, NO token CPI ⇒ escrow=0. (2) form_funding_swap (0x8E): bilateral fixed-for-floating
//     swap, escrow = CEIL worst-case per side (the `/10_000` FLOOR slope the PWA engine can't
//     express), 2-signer ⇒ assemble+sim. (3) open_fixed_forward_liquidation (0x08) +
//     complete_liquidation (8-byte sighash): keeper liquidation lifecycle, NO token CPI ⇒ escrow=0.
//     Each byte-exact from the on-chain `instructions::<name>.rs` `#[derive(Accounts)]` order.
// ---------------------------------------------------------------------------

/// The `open_perp_market` (disc `[0x6A,0x00]`) descriptor — byte-exact from `open_perp_market.rs:33`
/// (`OpenPerpMarketDescriptor`, borsh wire == 126 bytes, pinned by the on-chain test
/// `descriptor_borsh_wire_is_126_bytes`). PERMISSIONLESS per-market init (NO token CPI ⇒ escrow=0);
/// the param-sanity floors (`tick_size >= 1`, `contract_size >= 1`) are the on-chain gate.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct OpenPerpMarketDescriptor {
    /// Market identifier (the `perp_market` / `funding_state` PDA seed; 32 raw bytes).
    pub market_id: [u8; 32],
    /// Settlement mint (the asset-conservation scope; a STORED field, not a seed).
    pub settlement_mint: Pubkey,
    /// Contract size multiplier `cs` (`>= 1`).
    pub contract_size: u128,
    /// Epoch-0 bounded previous-reference seed (atoms).
    pub genesis_reference_atoms: u128,
    /// Open-interest cap.
    pub open_interest_cap: u64,
    /// Market `Fmax` — the per-step funding-rate clamp.
    pub max_funding_rate: u64,
    /// Lattice tick size (price-atoms per tick; `>= 1`).
    pub tick_size: u64,
    /// Reference policy id (the `derive_epoch_band` HARD gate binds).
    pub reference_policy_id: u16,
    /// Active risk-bracket id.
    pub active_risk_bracket_id: u16,
    /// Fee policy id.
    pub fee_policy_id: u16,
}
impl OpenPerpMarketDescriptor {
    /// Encode the 126-byte descriptor (byte-exact field order, LE).
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut d = Vec::with_capacity(126);
        d.extend_from_slice(&self.market_id); // (32)
        d.extend_from_slice(&self.settlement_mint.0); // (32)
        d.extend_from_slice(&self.contract_size.to_le_bytes()); // u128 (16)
        d.extend_from_slice(&self.genesis_reference_atoms.to_le_bytes()); // u128 (16)
        d.extend_from_slice(&self.open_interest_cap.to_le_bytes()); // u64 (8)
        d.extend_from_slice(&self.max_funding_rate.to_le_bytes()); // u64 (8)
        d.extend_from_slice(&self.tick_size.to_le_bytes()); // u64 (8)
        d.extend_from_slice(&self.reference_policy_id.to_le_bytes()); // u16 (2)
        d.extend_from_slice(&self.active_risk_bracket_id.to_le_bytes()); // u16 (2)
        d.extend_from_slice(&self.fee_policy_id.to_le_bytes()); // u16 (2)
        d
    }
}

/// `open_perp_market` (disc `[0x6A,0x00]`) — PERMISSIONLESS per-market init (`PerpMarketPda` +
/// `FundingStatePda`); NO token CPI ⇒ escrow=0. SINGLE-PARTY (1 signer = the opener / rent payer).
/// Data = `[0x6A,0x00] ‖ descriptor(126)`. 4 accounts byte-exact from `open_perp_market.rs`'s
/// `#[derive(Accounts)]` order: opener(signer,mut) · perp_market(init,[b"perp_market",market_id]) ·
/// funding_state(init,[b"funding_state",market_id]) · system_program. Fail-closed.
#[must_use]
pub fn ix_open_perp_market(
    opener: &Pubkey,
    descriptor: &OpenPerpMarketDescriptor,
) -> Option<Instruction> {
    let program = skew_program_id()?;
    let mid = &descriptor.market_id;
    let (perp_market, _b1) = find_program_address(&[b"perp_market", mid], &program)?;
    let (funding_state, _b2) = find_program_address(&[b"funding_state", mid], &program)?;
    let mut data = vec![0x6Au8, 0x00];
    data.extend_from_slice(&descriptor.encode());
    let accounts = vec![
        AccountMeta::writable(*opener, true), // opener (signer, mut) — rent payer
        AccountMeta::writable(perp_market, false), // perp_market (init)
        AccountMeta::writable(funding_state, false), // funding_state (init)
        AccountMeta::readonly(system_program_id(), false), // system_program
    ];
    Some(Instruction {
        program_id: program,
        accounts,
        data,
    })
}

/// The `factory_list_perp_market` (disc `[0x81,0x00]`) descriptor — byte-exact from
/// `factory_list_perp_market.rs:249` (`FactoryListPerpMarketDescriptor`). Carries the
/// `OpenPerpMarketDescriptor` market-config fields + the WCC certification legs the reused INC-A1
/// 6-condition UDSI gate consumes (mirror `ListWccTemplateDescriptor`'s `ModeC` legs + certs) + the
/// raw reference-envelope params (the factory clamps these 3) + the bond commitment. PERMISSIONLESS
/// (the math gate replaces an admin authority) — `open_perp_market` is ALREADY permissionless, so
/// the factory ADDS proof+clamp+bond; NO token CPI (the bond escrow is deferred) ⇒ escrow=0.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FactoryListPerpMarketDescriptor {
    /// Market identifier (the 4-init PDA seed tail; same as `open_perp_market`).
    pub market_id: [u8; 32],
    /// Settlement mint (the GOV-15 conservative mint; also a passed account).
    pub settlement_mint: Pubkey,
    /// Contract size multiplier `cs` (`>= 1`).
    pub contract_size: u128,
    /// Epoch-0 bounded previous-reference seed (atoms).
    pub genesis_reference_atoms: u128,
    /// Open-interest cap.
    pub open_interest_cap: u64,
    /// Market `Fmax` — the per-step funding-rate clamp.
    pub max_funding_rate: u64,
    /// Lattice tick size (price-atoms per tick; `>= 1`).
    pub tick_size: u64,
    /// Reference policy id.
    pub reference_policy_id: u16,
    /// Active risk-bracket id.
    pub active_risk_bracket_id: u16,
    /// Fee policy id.
    pub fee_policy_id: u16,
    /// MUST equal `SKEW_COLLATERAL_WCC_V1` (`0x1B1B`) — the G-FAMILY binding (reused gate checks it).
    pub collateral_policy_id: u16,
    /// The long leg's affine payoff descriptor (the UDSI gate input).
    pub leg_long: ModeCDescriptor,
    /// The short leg's affine payoff (the antisymmetric partner; G-CONSERVATION).
    pub leg_short: ModeCDescriptor,
    /// Declared WCL bound for the long leg.
    pub declared_b_long: u128,
    /// Declared WCL bound for the short leg.
    pub declared_b_short: u128,
    /// Sup-provider certificate for the long leg.
    pub cert_long: ModeCCertKind,
    /// Sup-provider certificate for the short leg.
    pub cert_short: ModeCCertKind,
    /// BUG-19 raw min-divisor price-atoms (the factory CLAMPS to the protocol envelope).
    pub ref_min_divisor_price_atoms: u128,
    /// BUG-19 raw max jump bps/epoch (clamped).
    pub ref_max_jump_bps_per_epoch: u16,
    /// BUG-19 raw max staleness slots (clamped).
    pub ref_max_staleness_slots: u64,
    /// The bond amount RECORDED at listing (RECORD-only in INC-B; no CPI).
    pub bond_committed_atoms: u128,
}
impl FactoryListPerpMarketDescriptor {
    /// Encode the VARIABLE descriptor (byte-exact declaration order; the 2 `ModeC` legs + 2 certs
    /// are nested borsh; the field order is the on-chain `list_wcc` 312 precedent + the factory tail).
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut d = Vec::new();
        d.extend_from_slice(&self.market_id);
        d.extend_from_slice(&self.settlement_mint.0);
        d.extend_from_slice(&self.contract_size.to_le_bytes());
        d.extend_from_slice(&self.genesis_reference_atoms.to_le_bytes());
        d.extend_from_slice(&self.open_interest_cap.to_le_bytes());
        d.extend_from_slice(&self.max_funding_rate.to_le_bytes());
        d.extend_from_slice(&self.tick_size.to_le_bytes());
        d.extend_from_slice(&self.reference_policy_id.to_le_bytes());
        d.extend_from_slice(&self.active_risk_bracket_id.to_le_bytes());
        d.extend_from_slice(&self.fee_policy_id.to_le_bytes());
        d.extend_from_slice(&self.collateral_policy_id.to_le_bytes());
        self.leg_long.encode_into(&mut d);
        self.leg_short.encode_into(&mut d);
        d.extend_from_slice(&self.declared_b_long.to_le_bytes());
        d.extend_from_slice(&self.declared_b_short.to_le_bytes());
        self.cert_long.encode_into(&mut d);
        self.cert_short.encode_into(&mut d);
        d.extend_from_slice(&self.ref_min_divisor_price_atoms.to_le_bytes());
        d.extend_from_slice(&self.ref_max_jump_bps_per_epoch.to_le_bytes());
        d.extend_from_slice(&self.ref_max_staleness_slots.to_le_bytes());
        d.extend_from_slice(&self.bond_committed_atoms.to_le_bytes());
        d
    }
}

/// `factory_list_perp_market` (disc `[0x81,0x00]`) — PERMISSIONLESS perp-market factory; NO token
/// CPI (the bond is RECORD-only) ⇒ escrow=0. SINGLE-PARTY (1 signer = the builder / rent payer; NOT
/// gated against any authority). Data = `[0x81,0x00] ‖ descriptor(VARIABLE)`. 8 accounts byte-exact
/// from `factory_list_perp_market.rs`'s `#[derive(Accounts)]` order: builder(signer,mut) ·
/// perp_market_factory(init,[b"perp_market_factory",market_id]) ·
/// market_builder_bond(init,[b"builder_bond",market_id]) · perp_market(init,[b"perp_market",
/// market_id]) · funding_state(init,[b"funding_state",market_id]) · settlement_mint(ro) ·
/// token_program · system_program. The settlement mint account == `descriptor.settlement_mint`.
#[must_use]
pub fn ix_factory_list_perp_market(
    builder: &Pubkey,
    descriptor: &FactoryListPerpMarketDescriptor,
) -> Option<Instruction> {
    let program = skew_program_id()?;
    let mid = &descriptor.market_id;
    let (perp_market_factory, _b1) =
        find_program_address(&[b"perp_market_factory", mid], &program)?;
    let (market_builder_bond, _b2) = find_program_address(&[b"builder_bond", mid], &program)?;
    let (perp_market, _b3) = find_program_address(&[b"perp_market", mid], &program)?;
    let (funding_state, _b4) = find_program_address(&[b"funding_state", mid], &program)?;
    let token = Pubkey::from_base58(TOKEN_PROGRAM_ID)?;
    let mut data = vec![0x81u8, 0x00];
    data.extend_from_slice(&descriptor.encode());
    let accounts = vec![
        AccountMeta::writable(*builder, true), // builder (signer, mut) — rent payer + bond owner
        AccountMeta::writable(perp_market_factory, false), // perp_market_factory (init)
        AccountMeta::writable(market_builder_bond, false), // market_builder_bond (init)
        AccountMeta::writable(perp_market, false), // perp_market (init)
        AccountMeta::writable(funding_state, false), // funding_state (init)
        AccountMeta::readonly(descriptor.settlement_mint, false), // settlement_mint (ro, GOV-15)
        AccountMeta::readonly(token, false),   // token_program
        AccountMeta::readonly(system_program_id(), false), // system_program
    ];
    Some(Instruction {
        program_id: program,
        accounts,
        data,
    })
}

/// The `form_funding_swap` (disc `[0x8E,0x00]`) descriptor — byte-exact from
/// `form_funding_swap.rs:56` (`FormFundingSwapDescriptor`, all fixed-width ⇒ borsh wire == 88 bytes,
/// Python-verified): `contract_id[32] ‖ quantity u64 ‖ contract_size u128 ‖ fixed_rate_bps i64 ‖
/// rate_lo i64 ‖ rate_hi i64 ‖ maturity_timestamp i64`. Bilateral fixed-for-floating funding swap:
/// each side escrows its `CEIL(q·cs·max_diff/10_000)` worst-case over the floating-rate collar into
/// ONE shared vault (the `/10_000` FLOOR slope the piecewise-affine engine cannot express).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FormFundingSwapDescriptor {
    /// 32-byte contract id (the `funding_swap_contract` / vault PDA seed; `init`-once dedup).
    pub contract_id: [u8; 32],
    /// Number of contracts `q` (`> 0` enforced on-chain). Unsigned.
    pub quantity: u64,
    /// Notional units per contract `cs`. Unsigned.
    pub contract_size: u128,
    /// The contract's fixed funding rate `F` (SIGNED bps).
    pub fixed_rate_bps: i64,
    /// Floating-rate collar LOWER bound (SIGNED bps).
    pub rate_lo: i64,
    /// Floating-rate collar UPPER bound (SIGNED bps); `rate_lo < rate_hi` enforced.
    pub rate_hi: i64,
    /// Forward maturity (unix seconds); verified `> clock.unix_timestamp`.
    pub maturity_timestamp: i64,
}
impl FormFundingSwapDescriptor {
    /// Encode the 88-byte descriptor (byte-exact field order, LE).
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut d = Vec::with_capacity(88);
        d.extend_from_slice(&self.contract_id); // (32)
        d.extend_from_slice(&self.quantity.to_le_bytes()); // u64 (8)
        d.extend_from_slice(&self.contract_size.to_le_bytes()); // u128 (16)
        d.extend_from_slice(&self.fixed_rate_bps.to_le_bytes()); // i64 (8)
        d.extend_from_slice(&self.rate_lo.to_le_bytes()); // i64 (8)
        d.extend_from_slice(&self.rate_hi.to_le_bytes()); // i64 (8)
        d.extend_from_slice(&self.maturity_timestamp.to_le_bytes()); // i64 (8)
        d
    }
}

/// `form_funding_swap` (disc `[0x8E,0x00]`) — bilateral funding-swap formation + per-side escrow,
/// ATOMIC. ★ 2 SIGNERS (long_party = fixed_payer + rent payer; short_party = floating_payer) ⇒ a
/// single bounded agent CANNOT broadcast alone (it can't forge the counterparty sig) — the codec +
/// plan ASSEMBLE + SIMULATE only (the chokepoint's multi-sig guard returns `Simulated`). Data =
/// `[0x8E,0x00] ‖ descriptor(88)`. 10 accounts byte-exact from `form_funding_swap.rs`'s
/// `#[derive(Accounts)]` order (IDENTICAL topology to `form_dated_book`; NO product_template).
#[must_use]
pub fn ix_form_funding_swap(
    long_party: &Pubkey,
    short_party: &Pubkey,
    long_source_token: &Pubkey,
    short_source_token: &Pubkey,
    settlement_mint: &Pubkey,
    descriptor: &FormFundingSwapDescriptor,
) -> Option<Instruction> {
    let program = skew_program_id()?;
    let cid = &descriptor.contract_id;
    let (funding_swap_contract, _b1) =
        find_program_address(&[b"funding_swap_contract", cid], &program)?;
    let (collateral_vault, _b2) = find_program_address(&[b"funding_swap_vault", cid], &program)?;
    let (collateral_vault_auth, _b3) =
        find_program_address(&[b"funding_swap_vault_authority", cid], &program)?;
    let token = Pubkey::from_base58(TOKEN_PROGRAM_ID)?;
    let mut data = vec![0x8Eu8, 0x00];
    data.extend_from_slice(&descriptor.encode());
    let accounts = vec![
        AccountMeta::writable(*long_party, true), // long_party (signer, mut) — fixed_payer + rent
        AccountMeta::writable(*short_party, true), // short_party (signer, mut) — floating_payer
        AccountMeta::writable(funding_swap_contract, false), // funding_swap_contract (init)
        AccountMeta::writable(collateral_vault, false), // collateral_vault (init)
        AccountMeta::readonly(collateral_vault_auth, false), // collateral_vault_authority (ro)
        AccountMeta::writable(*long_source_token, false), // long_source_token (mut)
        AccountMeta::writable(*short_source_token, false), // short_source_token (mut)
        AccountMeta::readonly(*settlement_mint, false), // settlement_mint (ro)
        AccountMeta::readonly(token, false),      // token_program
        AccountMeta::readonly(system_program_id(), false), // system_program
    ];
    Some(Instruction {
        program_id: program,
        accounts,
        data,
    })
}

/// The `open_fixed_forward_liquidation` (disc `[0x08,0x00]`) descriptor — byte-exact from
/// `open_liquidation.rs:216` (`OpenLiquidationDescriptor`, borsh wire == 134 bytes): `liquidation_id
/// [32] ‖ contract_id[32] ‖ trigger_kind u8 ‖ trigger_snapshot_hash[32] ‖ maintenance_requirement
/// u128 ‖ collateral_value u128 ‖ defaulter_role u8 ‖ auction_grace_seconds u32`. The keeper/
/// permissionless liquidation TRIGGER (`init`s `LiquidationStatePda`; NO vault disbursement ⇒ NO
/// token CPI ⇒ escrow=0). `open_fixed_forward_liquidation` reuses the `OpenLiquidation` Accounts ctx.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct OpenLiquidationDescriptor {
    /// 32-byte canonical liquidation identifier.
    pub liquidation_id: [u8; 32],
    /// 32-byte contract identifier (the otc/vm/liquidation PDA seed).
    pub contract_id: [u8; 32],
    /// Trigger-kind discriminant (one of `{0,1,2}`).
    pub trigger_kind: u8,
    /// SHA-256 of the trigger snapshot (MUST be non-zero on-chain; gate 2).
    pub trigger_snapshot_hash: [u8; 32],
    /// Maintenance-margin requirement (atoms) at the trigger snapshot.
    pub maintenance_requirement: u128,
    /// Collateral-value reading (atoms) at the trigger snapshot.
    pub collateral_value: u128,
    /// Role of the defaulting party (`0` = long, `1` = short).
    pub defaulter_role: u8,
    /// Auction grace period (seconds); `auction_deadline = now + this`.
    pub auction_grace_seconds: u32,
}
impl OpenLiquidationDescriptor {
    /// Encode the 134-byte descriptor (byte-exact field order, LE).
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut d = Vec::with_capacity(134);
        d.extend_from_slice(&self.liquidation_id); // (32)
        d.extend_from_slice(&self.contract_id); // (32)
        d.push(self.trigger_kind); // u8 (1)
        d.extend_from_slice(&self.trigger_snapshot_hash); // (32)
        d.extend_from_slice(&self.maintenance_requirement.to_le_bytes()); // u128 (16)
        d.extend_from_slice(&self.collateral_value.to_le_bytes()); // u128 (16)
        d.push(self.defaulter_role); // u8 (1)
        d.extend_from_slice(&self.auction_grace_seconds.to_le_bytes()); // u32 (4)
        d
    }
}

/// `open_fixed_forward_liquidation` (disc `[0x08,0x00]`) — the keeper/permissionless liquidation
/// trigger; NO vault disbursement ⇒ NO token CPI ⇒ escrow=0. SINGLE-PARTY (1 signer = the keeper /
/// rent payer; NOT a contract party). Data = `[0x08,0x00] ‖ descriptor(134)`. 8 accounts byte-exact
/// from `open_liquidation.rs`'s `#[derive(Accounts)] OpenLiquidation` order: signer(signer,mut) ·
/// otc_contract(mut,[b"otc_contract",cid]) · vm_state(ro,[b"vm_state",cid]) · collateral_state_long
/// (mut,[b"collateral_state",cid,long_party]) · collateral_state_short(mut,[b"collateral_state",cid,
/// short_party]) · product_template(ro,[b"product_template",template_id]) · liquidation_state(init,
/// [b"liquidation_state",cid]) · system_program. The 2 collateral_state PDAs use the canonical
/// `[b"collateral_state",cid,party]` seed (the `lock_collateral` precedent); the handler then
/// cross-pins both against the parent `OtcContractPda`.
#[must_use]
pub fn ix_open_fixed_forward_liquidation(
    signer: &Pubkey,
    long_party: &Pubkey,
    short_party: &Pubkey,
    template_id: &[u8; 32],
    descriptor: &OpenLiquidationDescriptor,
) -> Option<Instruction> {
    let program = skew_program_id()?;
    let cid = &descriptor.contract_id;
    let (otc_contract, _b1) = find_program_address(&[b"otc_contract", cid], &program)?;
    let (vm_state, _b2) = find_program_address(&[b"vm_state", cid], &program)?;
    let (collateral_state_long, _b3) =
        find_program_address(&[b"collateral_state", cid, &long_party.0], &program)?;
    let (collateral_state_short, _b4) =
        find_program_address(&[b"collateral_state", cid, &short_party.0], &program)?;
    let (product_template, _b5) =
        find_program_address(&[b"product_template", template_id], &program)?;
    let (liquidation_state, _b6) = find_program_address(&[b"liquidation_state", cid], &program)?;
    let mut data = vec![0x08u8, 0x00];
    data.extend_from_slice(&descriptor.encode());
    let accounts = vec![
        AccountMeta::writable(*signer, true), // signer (keeper, mut) — rent payer
        AccountMeta::writable(otc_contract, false), // otc_contract (mut → Liquidating)
        AccountMeta::readonly(vm_state, false), // vm_state (ro)
        AccountMeta::writable(collateral_state_long, false), // collateral_state_long (mut)
        AccountMeta::writable(collateral_state_short, false), // collateral_state_short (mut)
        AccountMeta::readonly(product_template, false), // product_template (ro)
        AccountMeta::writable(liquidation_state, false), // liquidation_state (init)
        AccountMeta::readonly(system_program_id(), false), // system_program
    ];
    Some(Instruction {
        program_id: program,
        accounts,
        data,
    })
}

/// The `complete_liquidation` (8-byte Anchor sighash `ff00142801090f27`) descriptor — byte-exact
/// from `complete_liquidation.rs:226` (`CompleteLiquidationDescriptor`, borsh wire == 105 bytes):
/// `contract_id[32] ‖ liquidation_id[32] ‖ valuation_amount i128 ‖ close_factor u128 ‖
/// dispute_resolved bool(1) ‖ current_unix_timestamp i64`. Closes the liquidation lifecycle (`init`s
/// `LiquidationReceiptPda`; NO vault disbursement ⇒ NO token CPI ⇒ escrow=0). The handler WITHOUT a
/// `#[instruction(discriminator = ..)]` ⇒ the DEFAULT 8-byte sighash `sha256("global:..")[..8]`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CompleteLiquidationDescriptor {
    /// 32-byte contract identifier (the otc/liquidation/vm/receipt PDA seed).
    pub contract_id: [u8; 32],
    /// 32-byte liquidation identifier (cross-pinned vs `LiquidationStatePda.liquidation_id`).
    pub liquidation_id: [u8; 32],
    /// SIGNED caller-claimed valuation (atoms; cross-pinned on-chain → `ValuationMismatch`).
    pub valuation_amount: i128,
    /// Caller-claimed close_factor (bps; cross-pinned per trigger kind).
    pub close_factor: u128,
    /// `true` ⇒ ClosedNoBreach (dispute-resolution) path; `false` ⇒ Settled (closeout) path.
    pub dispute_resolved: bool,
    /// Caller-claimed wall-clock (preview-parity ONLY; the handler uses `Clock::get()`).
    pub current_unix_timestamp: i64,
}
impl CompleteLiquidationDescriptor {
    /// Encode the 105-byte descriptor (byte-exact field order, LE; `bool` ⇒ 1 byte `0|1`).
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut d = Vec::with_capacity(105);
        d.extend_from_slice(&self.contract_id); // (32)
        d.extend_from_slice(&self.liquidation_id); // (32)
        d.extend_from_slice(&self.valuation_amount.to_le_bytes()); // i128 (16)
        d.extend_from_slice(&self.close_factor.to_le_bytes()); // u128 (16)
        d.push(u8::from(self.dispute_resolved)); // bool (1)
        d.extend_from_slice(&self.current_unix_timestamp.to_le_bytes()); // i64 (8)
        d
    }
}

/// `complete_liquidation` (8-byte sighash `ff00142801090f27`) — closes the liquidation lifecycle
/// (`init`s `LiquidationReceiptPda`; NO vault disbursement ⇒ NO token CPI ⇒ escrow=0). SINGLE-PARTY
/// (1 signer = the keeper / rent payer). Data = `sighash(8) ‖ descriptor(105)` = 113 B. 9 accounts
/// byte-exact from `complete_liquidation.rs`'s `#[derive(Accounts)] CompleteLiquidation` order:
/// signer(signer,mut) · otc_contract(mut,[b"otc_contract",cid]) · liquidation_state(mut,
/// [b"liquidation_state",cid]) · collateral_state_long(mut,[b"collateral_state",cid,long_party]) ·
/// collateral_state_short(mut,[b"collateral_state",cid,short_party]) · vm_state(mut,[b"vm_state",
/// cid]) · liquidation_receipt(init,[b"liquidation_receipt",cid]) · product_template(ro,
/// [b"product_template",template_id]) · system_program.
#[must_use]
pub fn ix_complete_liquidation(
    signer: &Pubkey,
    long_party: &Pubkey,
    short_party: &Pubkey,
    template_id: &[u8; 32],
    descriptor: &CompleteLiquidationDescriptor,
) -> Option<Instruction> {
    let program = skew_program_id()?;
    let cid = &descriptor.contract_id;
    let (otc_contract, _b1) = find_program_address(&[b"otc_contract", cid], &program)?;
    let (liquidation_state, _b2) = find_program_address(&[b"liquidation_state", cid], &program)?;
    let (collateral_state_long, _b3) =
        find_program_address(&[b"collateral_state", cid, &long_party.0], &program)?;
    let (collateral_state_short, _b4) =
        find_program_address(&[b"collateral_state", cid, &short_party.0], &program)?;
    let (vm_state, _b5) = find_program_address(&[b"vm_state", cid], &program)?;
    let (liquidation_receipt, _b6) =
        find_program_address(&[b"liquidation_receipt", cid], &program)?;
    let (product_template, _b7) =
        find_program_address(&[b"product_template", template_id], &program)?;
    let mut data = anchor_ix_sighash("complete_liquidation").to_vec();
    data.extend_from_slice(&descriptor.encode());
    let accounts = vec![
        AccountMeta::writable(*signer, true), // signer (keeper, mut) — rent payer
        AccountMeta::writable(otc_contract, false), // otc_contract (mut)
        AccountMeta::writable(liquidation_state, false), // liquidation_state (mut)
        AccountMeta::writable(collateral_state_long, false), // collateral_state_long (mut)
        AccountMeta::writable(collateral_state_short, false), // collateral_state_short (mut)
        AccountMeta::writable(vm_state, false), // vm_state (mut)
        AccountMeta::writable(liquidation_receipt, false), // liquidation_receipt (init)
        AccountMeta::readonly(product_template, false), // product_template (ro)
        AccountMeta::readonly(system_program_id(), false), // system_program
    ];
    Some(Instruction {
        program_id: program,
        accounts,
        data,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base58_round_trips_known_vectors() {
        // 32 zero bytes ⇒ the system-program "111…1" (32 ones).
        assert_eq!(base58_encode(&[0u8; 32]), "1".repeat(32));
        // round-trip every well-known id through decode∘encode.
        for id in [
            TOKEN_PROGRAM_ID,
            ASSOCIATED_TOKEN_PROGRAM_ID,
            RENT_SYSVAR_ID,
            COMPUTE_BUDGET_PROGRAM_ID,
            DEVNET_GENESIS_HASH,
            crate::skew_catalog::SKEW_PROGRAM_ID_DEVNET,
            crate::skew_catalog::SKEW_SETTLEMENT_MINT_DEVNET,
        ] {
            let pk = Pubkey::from_base58(id).expect("valid base58 id");
            assert_eq!(pk.to_base58(), id, "round-trip {id}");
        }
        // a single byte 0x00 ⇒ "1"; 0x01 ⇒ "2".
        assert_eq!(base58_encode(&[0]), "1");
        assert_eq!(base58_encode(&[1]), "2");
    }

    #[test]
    fn base64_round_trips_via_skew_read_decoder() {
        for v in [
            &b"Hello"[..],
            &b"Man"[..],
            &b""[..],
            &[0u8; 64][..],
            &[0xABu8; 100][..],
        ] {
            let enc = base64_encode(v);
            let dec = crate::skew_read::base64_decode(&enc).expect("decodes");
            assert_eq!(dec, v, "base64 round-trip");
        }
    }

    #[test]
    fn compact_u16_encodes_per_spec() {
        let mut o = Vec::new();
        push_compact_u16(&mut o, 0);
        assert_eq!(o, [0]);
        o.clear();
        push_compact_u16(&mut o, 127);
        assert_eq!(o, [0x7f]);
        o.clear();
        push_compact_u16(&mut o, 128);
        assert_eq!(o, [0x80, 0x01]);
        o.clear();
        push_compact_u16(&mut o, 256);
        assert_eq!(o, [0x80, 0x02]);
    }

    #[test]
    fn system_program_is_all_zero_and_off_curve_pdas() {
        assert_eq!(system_program_id().0, [0u8; 32]);
        // a derived PDA must be OFF the curve (Solana invariant); the bump must be ≤ 255.
        let prog = skew_program_id().expect("skew id");
        let mint =
            Pubkey::from_base58(crate::skew_catalog::SKEW_SETTLEMENT_MINT_DEVNET).expect("m");
        let owner = Pubkey([7u8; 32]);
        let (pda, bump) =
            find_program_address(&[b"unified_risk_account", &owner.0, &mint.0], &prog)
                .expect("pda");
        assert!(!is_on_curve(&pda.0), "a PDA is off-curve by construction");
        // determinism: same seeds ⇒ same PDA + bump.
        let (pda2, bump2) =
            find_program_address(&[b"unified_risk_account", &owner.0, &mint.0], &prog)
                .expect("pda");
        assert_eq!((pda, bump), (pda2, bump2));
    }

    #[test]
    fn open_risk_account_is_byte_exact() {
        let mint =
            Pubkey::from_base58(crate::skew_catalog::SKEW_SETTLEMENT_MINT_DEVNET).expect("m");
        let owner = Pubkey([0x11u8; 32]);
        let ix = ix_open_risk_account(&owner, &mint).expect("ix");
        // data = the 2-byte u16-LE discriminator, NO descriptor.
        assert_eq!(ix.data, vec![0x60, 0x00]);
        // 9 accounts in the handler's exact order; owner is the only signer + writable.
        assert_eq!(ix.accounts.len(), 9);
        assert_eq!(ix.accounts[0].pubkey, owner);
        assert!(ix.accounts[0].is_signer && ix.accounts[0].is_writable);
        assert_eq!(ix.accounts[1].pubkey, mint);
        assert!(!ix.accounts[1].is_signer && !ix.accounts[1].is_writable);
        // accounts[2..5] are the writable init PDAs; [5..9] read-only.
        assert!(ix.accounts[2].is_writable && !ix.accounts[2].is_signer);
        assert!(ix.accounts[8].pubkey == Pubkey::from_base58(RENT_SYSVAR_ID).unwrap());
        assert_eq!(ix.program_id, skew_program_id().unwrap());
    }

    #[test]
    fn deposit_margin_is_byte_exact_and_amount_bound() {
        let mint =
            Pubkey::from_base58(crate::skew_catalog::SKEW_SETTLEMENT_MINT_DEVNET).expect("m");
        let owner = Pubkey([0x22u8; 32]);
        let ix = ix_deposit_margin(&owner, &mint, 1_000_000).expect("ix");
        // data = [0x61,0x00] ‖ u64 LE amount.
        assert_eq!(&ix.data[..2], &[0x61, 0x00]);
        assert_eq!(&ix.data[2..], &1_000_000u64.to_le_bytes());
        assert_eq!(ix.data.len(), 10);
        // 7 accounts; the depositor ATA is the derived owner ATA.
        assert_eq!(ix.accounts.len(), 7);
        let ata = associated_token_address(&owner, &mint).unwrap();
        assert_eq!(ix.accounts[5].pubkey, ata);
        assert!(ix.accounts[5].is_writable);
    }

    #[test]
    fn withdraw_margin_is_byte_exact_and_amount_bound() {
        let mint =
            Pubkey::from_base58(crate::skew_catalog::SKEW_SETTLEMENT_MINT_DEVNET).expect("m");
        let owner = Pubkey([0x66u8; 32]);
        let ix = ix_withdraw_margin(&owner, &mint, 250_000).expect("ix");
        // data = [0x62,0x00] ‖ u64 LE amount (byte-identical width to deposit, distinct disc).
        assert_eq!(&ix.data[..2], &[0x62, 0x00]);
        assert_eq!(&ix.data[2..], &250_000u64.to_le_bytes());
        assert_eq!(ix.data.len(), 10);
        // 8 accounts in the handler's exact #[derive(Accounts)] order (one MORE than deposit's 7).
        assert_eq!(ix.accounts.len(), 8);
        // [0] owner: the only signer + writable.
        assert_eq!(ix.accounts[0].pubkey, owner);
        assert!(ix.accounts[0].is_signer && ix.accounts[0].is_writable);
        assert_eq!(ix.accounts.iter().filter(|a| a.is_signer).count(), 1);
        // [5] perp_margin_vault_authority: read-only (the CPI signer is a PDA, not a tx signer).
        let (vault_auth, _b) = find_program_address(
            &[b"perp_margin_vault_authority", &mint.0],
            &skew_program_id().unwrap(),
        )
        .unwrap();
        assert_eq!(ix.accounts[5].pubkey, vault_auth);
        assert!(!ix.accounts[5].is_writable && !ix.accounts[5].is_signer);
        // [6] receiver_token_account: the owner's derived ATA, writable.
        let ata = associated_token_address(&owner, &mint).unwrap();
        assert_eq!(ix.accounts[6].pubkey, ata);
        assert!(ix.accounts[6].is_writable);
        assert_eq!(ix.program_id, skew_program_id().unwrap());
    }

    #[test]
    fn compute_unit_price_ix_is_byte_exact_priority_fee() {
        // The priority-fee ix (FAST PATH inclusion lever): tag 0x03 ‖ u64 LE micro-lamports, NO
        // accounts, the ComputeBudget program (mirrors the Skew FE's setComputeUnitPrice).
        let ix = compute_unit_price_ix(50_000).expect("ix");
        assert_eq!(ix.data[0], 0x03);
        assert_eq!(&ix.data[1..], &50_000u64.to_le_bytes());
        assert_eq!(ix.data.len(), 9); // 1 tag + 8 (u64)
        assert!(ix.accounts.is_empty());
        assert_eq!(
            ix.program_id,
            Pubkey::from_base58(COMPUTE_BUDGET_PROGRAM_ID).unwrap()
        );
        // distinct from the CU-LIMIT ix (tag 0x02 ‖ u32).
        assert_ne!(ix.data[0], compute_unit_limit_ix(400_000).unwrap().data[0]);
    }

    #[test]
    fn submit_perp_order_descriptor_is_102_bytes() {
        let mint =
            Pubkey::from_base58(crate::skew_catalog::SKEW_SETTLEMENT_MINT_DEVNET).expect("m");
        let owner = Pubkey([0x33u8; 32]);
        let desc = SubmitPerpOrderDescriptor {
            market_id: [0x44u8; 32],
            settlement_mint: mint,
            batch_slot: 7,
            epoch_seq: 3,
            nonce: 99,
            limit_tick: 5,
            qty: 10,
            side: 0,
            intent_flags: 0,
        };
        assert_eq!(desc.encode().len(), 102);
        let ix = ix_submit_perp_order(&owner, &desc).expect("ix");
        // data = [0x71,0x00] ‖ 102B = 104B.
        assert_eq!(&ix.data[..2], &[0x71, 0x00]);
        assert_eq!(ix.data.len(), 104);
        // 8 accounts; owner is the only signer.
        assert_eq!(ix.accounts.len(), 8);
        assert!(ix.accounts[0].is_signer);
        assert_eq!(ix.accounts.iter().filter(|a| a.is_signer).count(), 1);
    }

    #[test]
    fn submit_order_descriptor_is_142_bytes_and_9_accounts() {
        let mint =
            Pubkey::from_base58(crate::skew_catalog::SKEW_SETTLEMENT_MINT_DEVNET).expect("m");
        let signer = Pubkey([0x77u8; 32]);
        let desc = SubmitOrderDescriptor {
            template_id: [0x88u8; 32],
            batch_slot: 5,
            nonce: 42,
            limit_tick: 3,
            wcc: WccParamsCodec {
                collar_lo: -100,
                collar_hi: 100,
                forward_price_pc: 0,
                tick_tau: 1,
                quantity_q: 10,
                contract_size_cs: 1_000_000,
                party_direction: 0,   // Long
                sup_provider_mode: 0, // A
            },
        };
        // descriptor borsh wire = 142 bytes (pinned by the Skew on-chain test).
        let enc = desc.encode();
        assert_eq!(enc.len(), 142);
        assert_eq!(&enc[..32], &[0x88u8; 32]); // template_id
        assert_eq!(&enc[32..40], &5u64.to_le_bytes()); // batch_slot
        assert_eq!(&enc[40..48], &42u64.to_le_bytes()); // nonce
        assert_eq!(&enc[48..52], &3u32.to_le_bytes()); // limit_tick
        assert_eq!(&enc[52..68], &(-100i128).to_le_bytes()); // wcc.collar_lo @ 52
        assert_eq!(enc[140], 0); // party_direction (Long) @ 52+88
        assert_eq!(enc[141], 0); // sup_provider_mode (A) @ 141
        let ix = ix_submit_order(&signer, &mint, &desc).expect("ix");
        // data = [0x52,0x00] ‖ 142 = 144.
        assert_eq!(&ix.data[..2], &[0x52, 0x00]);
        assert_eq!(ix.data.len(), 144);
        // 9 accounts; signer the only signer; source ATA @4; token_mint @6 = settlement mint.
        assert_eq!(ix.accounts.len(), 9);
        assert!(ix.accounts[0].is_signer && ix.accounts[0].is_writable);
        assert_eq!(ix.accounts.iter().filter(|a| a.is_signer).count(), 1);
        let ata = associated_token_address(&signer, &mint).unwrap();
        assert_eq!(ix.accounts[4].pubkey, ata);
        assert!(ix.accounts[4].is_writable);
        assert_eq!(ix.accounts[6].pubkey, mint);
    }

    #[test]
    fn pay_vm_descriptor_is_48_bytes_with_8byte_sighash() {
        let mint =
            Pubkey::from_base58(crate::skew_catalog::SKEW_SETTLEMENT_MINT_DEVNET).expect("m");
        let signer = Pubkey([0x99u8; 32]);
        let tid = [0xABu8; 32];
        let desc = PayVmDescriptor {
            contract_id: [0xCDu8; 32],
            payment_amount: 500_000,
        };
        // descriptor borsh = 48 bytes (contract_id 32 + payment_amount u128 16).
        let enc = desc.encode();
        assert_eq!(enc.len(), 48);
        assert_eq!(&enc[..32], &[0xCDu8; 32]);
        assert_eq!(&enc[32..], &500_000u128.to_le_bytes());
        // the prelude is the 8-byte sighash sha256("global:pay_fixed_forward_vm")[..8] — NOT a 2-byte disc.
        let sig = [0x64, 0xbc, 0x0d, 0xde, 0xaf, 0xb7, 0x40, 0x41];
        assert_eq!(anchor_ix_sighash("pay_fixed_forward_vm"), sig);
        let ix = ix_pay_vm(&signer, &mint, &tid, &desc).expect("ix");
        // data = sighash(8) ‖ descriptor(48) = 56.
        assert_eq!(&ix.data[..8], &sig);
        assert_eq!(ix.data.len(), 56);
        // 10 accounts; signer the only signer; source ATA @4; token_mint @7 = settlement mint.
        assert_eq!(ix.accounts.len(), 10);
        assert!(ix.accounts[0].is_signer && ix.accounts[0].is_writable);
        assert_eq!(ix.accounts.iter().filter(|a| a.is_signer).count(), 1);
        let ata = associated_token_address(&signer, &mint).unwrap();
        assert_eq!(ix.accounts[4].pubkey, ata);
        assert_eq!(ix.accounts[7].pubkey, mint);
    }

    #[test]
    fn settle_descriptor_is_128_bytes_with_8byte_sighash() {
        let mint =
            Pubkey::from_base58(crate::skew_catalog::SKEW_SETTLEMENT_MINT_DEVNET).expect("m");
        let signer = Pubkey([0xA1u8; 32]);
        let tid = [0xB2u8; 32];
        let receiver = Pubkey([0xC3u8; 32]);
        let desc = SettleFixedForwardDescriptor {
            contract_id: [0xD4u8; 32],
            reference_snapshot_hash: [0xE5u8; 32],
            settlement_price: 1_000_000,
            current_unix_timestamp: 1700,
            archive_pointer: [0xF6u8; 32],
            reference_publish_timestamp: 1699,
        };
        let enc = desc.encode();
        assert_eq!(enc.len(), 128);
        // FIELD-ORDER TRAP: reference_snapshot_hash @32 is BEFORE settlement_price @64.
        assert_eq!(&enc[32..64], &[0xE5u8; 32]);
        assert_eq!(&enc[64..80], &1_000_000u128.to_le_bytes());
        // the prelude is the 8-byte sighash sha256("global:settle_fixed_forward")[..8].
        let sig = [0x79, 0x98, 0x22, 0x3f, 0x35, 0x42, 0x22, 0xa0];
        assert_eq!(anchor_ix_sighash("settle_fixed_forward"), sig);
        let ix = ix_settle_fixed_forward(&signer, &mint, &tid, &receiver, &desc).expect("ix");
        assert_eq!(&ix.data[..8], &sig);
        assert_eq!(ix.data.len(), 136); // 8 + 128
        assert_eq!(ix.accounts.len(), 12);
        assert!(ix.accounts[0].is_signer && ix.accounts[0].is_writable);
        assert_eq!(ix.accounts.iter().filter(|a| a.is_signer).count(), 1);
        assert_eq!(ix.accounts[8].pubkey, receiver); // receiver_token_account @8
        assert!(ix.accounts[8].is_writable);
        assert_eq!(ix.accounts[9].pubkey, mint); // token_mint @9 = settlement mint
    }

    #[test]
    fn lock_collateral_variable_descriptor_and_sighash() {
        let mint =
            Pubkey::from_base58(crate::skew_catalog::SKEW_SETTLEMENT_MINT_DEVNET).expect("m");
        let signer = Pubkey([0x1Au8; 32]);
        let tid = [0x2Bu8; 32];
        let other = Pubkey([0x3Cu8; 32]);
        // FixedLock mode: collateral_snapshot_bytes = [] (zero-byte unit struct).
        let desc = LockCollateralDescriptor {
            contract_id: [0x4Du8; 32],
            party_role: 0,
            lock_amount: 500_000,
            collateral_policy_version: 1,
            collateral_params_bytes: vec![0xAA, 0xBB],
            collateral_snapshot_bytes: vec![],
            reference_snapshot_hash: [0x5Eu8; 32],
            reference_snapshot_age_seconds: 10,
            reference_max_age_seconds: 60,
            vm_policy_bytes: vec![0xCC],
            vm_mark_source: 1,
        };
        let enc = desc.encode();
        // 32 + 1 + 16 + 4 + (4+2) + (4+0) + 32 + 4 + 4 + (4+1) + 2 = 110.
        assert_eq!(enc.len(), 110);
        assert_eq!(enc[32], 0); // party_role @32
        assert_eq!(&enc[33..49], &500_000u128.to_le_bytes()); // lock_amount @33
        let sig = [0x24, 0xb0, 0xaa, 0x03, 0x29, 0x32, 0xb9, 0x8c];
        assert_eq!(
            anchor_ix_sighash("lock_fixed_forward_initial_collateral"),
            sig
        );
        let ix = ix_lock_collateral(&signer, &mint, &tid, &other, &desc).expect("ix");
        assert_eq!(&ix.data[..8], &sig);
        assert_eq!(ix.accounts.len(), 12);
        assert!(ix.accounts[0].is_signer && ix.accounts[0].is_writable);
        assert_eq!(ix.accounts.iter().filter(|a| a.is_signer).count(), 1);
        let ata = associated_token_address(&signer, &mint).unwrap();
        assert_eq!(ix.accounts[6].pubkey, ata); // source_token_account @6
    }

    #[test]
    fn mark_vm_2byte_disc_and_variable() {
        let signer = Pubkey([0x11u8; 32]);
        let tid = [0x22u8; 32];
        let desc = MarkVmDescriptor {
            contract_id: [0x33u8; 32],
            vm_policy_bytes: vec![0xDD, 0xEE],
            mark_price_atoms: 2_000_000,
            mark_publish_timestamp: 1700,
            mark_confidence_bps: 50,
            mark_snapshot_hash: [0x44u8; 32],
            mark_archive_pointer: [0x55u8; 32],
            reference_policy_id: 7,
            mark_price_decimals: 6,
            current_unix_timestamp: 1701,
        };
        let enc = desc.encode();
        // 32 + (4+2) + 16 + 8 + 4 + 32 + 32 + 2 + 1 + 8 = 141.
        assert_eq!(enc.len(), 141);
        assert_eq!(&enc[..32], &[0x33u8; 32]);
        assert_eq!(&enc[32..36], &2u32.to_le_bytes()); // vm_policy_bytes len = 2
        let ix = ix_mark_vm(&signer, &tid, &desc).expect("ix");
        // mark_vm uses the 2-byte u16-LE disc [0x05,0x00] (NOT a sighash).
        assert_eq!(&ix.data[..2], &[0x05, 0x00]);
        assert_eq!(ix.accounts.len(), 4);
        assert!(ix.accounts[0].is_signer);
        assert_eq!(ix.accounts.iter().filter(|a| a.is_signer).count(), 1);
    }

    #[test]
    fn form_contract_2byte_disc_and_double_vec() {
        let mint =
            Pubkey::from_base58(crate::skew_catalog::SKEW_SETTLEMENT_MINT_DEVNET).expect("m");
        let fee_payer = Pubkey([0x99u8; 32]);
        let long = Pubkey([0x77u8; 32]);
        let short = Pubkey([0x88u8; 32]);
        let desc = FormContractDescriptor {
            contract_id: [0x01u8; 32],
            template_id: [0x02u8; 32],
            version: 1,
            terms_hash: [0x03u8; 32],
            accept_id: [0x04u8; 32],
            quote_expiry: 1700,
            long_party: long,
            short_party: short,
            party_roles: 0,
            allow_self_cross: false,
            underlying_reference_id: [0x05u8; 32],
            settlement_mint: mint,
            quantity: 10,
            contract_size: 1,
            forward_price: 100,
            maturity_timestamp: 2000,
            notional: 1000,
            reference_data_policy_id: 1,
            collateral_policy_id: 0x1B1B,
            vm_policy_id: 1,
            settlement_adapter_id: 1,
            approved_reference_ids: vec![[0x06u8; 32]],
            approved_settlement_mints: vec![mint],
        };
        let enc = desc.encode();
        // version @64 (TRAP — between template_id and terms_hash).
        assert_eq!(&enc[64..68], &1u32.to_le_bytes());
        // 342-byte fixed prefix + (4 + 32) ref-vec + (4 + 32) mint-vec = 414.
        assert_eq!(enc.len(), 414);
        let ix = ix_form_contract(&fee_payer, &desc).expect("ix");
        // form_contract uses the 2-byte u16-LE disc [0x03,0x00].
        assert_eq!(&ix.data[..2], &[0x03, 0x00]);
        // 3 signers (long, short, fee_payer); 8 accounts in the handler order.
        assert_eq!(ix.accounts.len(), 8);
        assert_eq!(ix.accounts.iter().filter(|a| a.is_signer).count(), 3);
        assert!(ix.accounts[0].pubkey == long && ix.accounts[0].is_signer);
    }

    #[test]
    fn wave_e_keeper_codecs_are_byte_exact() {
        let mint =
            Pubkey::from_base58(crate::skew_catalog::SKEW_SETTLEMENT_MINT_DEVNET).expect("m");
        let caller = Pubkey([0x71u8; 32]);
        let owner = Pubkey([0x72u8; 32]);
        let market = [0x73u8; 32];
        // validate_reference_snapshot 0x64, 113 B, 4 accounts.
        let vrs = ValidateReferenceSnapshotDescriptor {
            market_id: market,
            source_id: 1,
            observed_slot: 100,
            numerator_atoms: 1000,
            divisor_atoms: 1,
            confidence_bps: 50,
            bid_ask_spread_bps: 10,
            exponent: 6,
            source_payload_hash: [0xAB; 32],
        };
        assert_eq!(vrs.encode().len(), 113);
        let ix = ix_validate_reference_snapshot(&caller, &vrs).expect("ix");
        assert_eq!(&ix.data[..2], &[0x64, 0x00]);
        assert_eq!(ix.accounts.len(), 4);
        // advance_funding_epoch 0x6D, 40 B, 5 accounts.
        let afe = AdvanceFundingEpochDescriptor {
            market_id: market,
            epoch_seq: 3,
        };
        assert_eq!(afe.encode().len(), 40);
        let ix = ix_advance_funding_epoch(&caller, &afe).expect("ix");
        assert_eq!(&ix.data[..2], &[0x6D, 0x00]);
        assert_eq!(ix.accounts.len(), 5);
        // settle_account_funding 0x72, 104 B, 8 accounts.
        let saf = SettleAccountFundingDescriptor {
            market_id: market,
            settlement_mint: mint,
            owner,
            epoch_seq: 3,
        };
        assert_eq!(saf.encode().len(), 104);
        let ix = ix_settle_account_funding(&caller, &saf).expect("ix");
        assert_eq!(&ix.data[..2], &[0x72, 0x00]);
        assert_eq!(ix.accounts.len(), 8);
        // force_reduce_position 0x78, 104 B, 16 accounts; 1 signer.
        let frp = ForceReducePositionDescriptor {
            market_id: market,
            settlement_mint: mint,
            owner,
            admitted_epoch_seq: 3,
        };
        assert_eq!(frp.encode().len(), 104);
        let ix = ix_force_reduce_position(&caller, &frp).expect("ix");
        assert_eq!(&ix.data[..2], &[0x78, 0x00]);
        assert_eq!(ix.accounts.len(), 16);
        assert_eq!(ix.accounts.iter().filter(|a| a.is_signer).count(), 1);
    }

    #[test]
    fn wave_c_batch_book_codecs_are_byte_exact() {
        let mint =
            Pubkey::from_base58(crate::skew_catalog::SKEW_SETTLEMENT_MINT_DEVNET).expect("m");
        let signer = Pubkey([0x61u8; 32]);
        let owner = Pubkey([0x62u8; 32]);
        let tid = [0x63u8; 32];
        let cid = [0x64u8; 32];
        // open_batch 0x51, 40 B, 8 accounts.
        let ob = OpenBatchDescriptor {
            template_id: tid,
            batch_slot: 7,
        };
        assert_eq!(ob.encode().len(), 40);
        let ix = ix_open_batch(&signer, &mint, &ob).expect("ix");
        assert_eq!(&ix.data[..2], &[0x51, 0x00]);
        assert_eq!(ix.accounts.len(), 8);
        // close_batch 0x53, 40 B, 6 accounts; the 2 histogram PDAs differ by the side seed.
        let cb = CloseBatchDescriptor {
            template_id: tid,
            batch_slot: 7,
        };
        assert_eq!(cb.encode().len(), 40);
        let ix = ix_close_batch(&signer, &cb).expect("ix");
        assert_eq!(&ix.data[..2], &[0x53, 0x00]);
        assert_eq!(ix.accounts.len(), 6);
        assert_ne!(ix.accounts[3].pubkey, ix.accounts[4].pubkey); // SIDE_ASK != SIDE_BID
        // settle_batch 0x54, 49 B, 7 accounts.
        let sb = SettleBatchDescriptor {
            template_id: tid,
            batch_slot: 7,
            phase: 3,
            shard_index: 0,
            shard_count: 1,
        };
        assert_eq!(sb.encode().len(), 49);
        let ix = ix_settle_batch(&signer, &sb).expect("ix");
        assert_eq!(&ix.data[..2], &[0x54, 0x00]);
        assert_eq!(ix.accounts.len(), 7);
        // claim_fill 0x55, 48 B, 11 accounts; recipient = the order-owner ATA @5.
        let cf = ClaimFillDescriptor {
            template_id: tid,
            batch_slot: 7,
            nonce: 42,
        };
        assert_eq!(cf.encode().len(), 48);
        let ix = ix_claim_fill(&signer, &mint, &owner, &cf).expect("ix");
        assert_eq!(&ix.data[..2], &[0x55, 0x00]);
        assert_eq!(ix.accounts.len(), 11);
        assert_eq!(
            ix.accounts[5].pubkey,
            associated_token_address(&owner, &mint).unwrap()
        );
        // settle_batch_contract 0x5A, 96 B, 10 accounts.
        let sbc = SettleBatchContractDescriptor {
            contract_id: cid,
            settlement_price: 1000,
            collar_lo: -100,
            collar_hi: 100,
            tick_tau: 1,
        };
        assert_eq!(sbc.encode().len(), 96);
        let ix = ix_settle_batch_contract(&signer, &mint, &tid, &owner, &sbc).expect("ix");
        assert_eq!(&ix.data[..2], &[0x5A, 0x00]);
        assert_eq!(ix.accounts.len(), 10);
    }

    #[test]
    fn wave_d_secondary_market_codecs_are_byte_exact() {
        let mint =
            Pubkey::from_base58(crate::skew_catalog::SKEW_SETTLEMENT_MINT_DEVNET).expect("m");
        let seller = Pubkey([0x51u8; 32]);
        let buyer = Pubkey([0x52u8; 32]);
        let cid = [0x53u8; 32];
        // list_secondary: 66 B, disc 0x65, 4 accounts, 1 signer.
        let list = ListSecondaryDescriptor {
            contract_id: cid,
            side: 0,
            listing_qty: 5,
            ask_price: 1000,
            expiry_slot: 999,
            execution_mode: 0,
        };
        assert_eq!(list.encode().len(), 66);
        let ix = ix_list_secondary(&seller, &list).expect("ix");
        assert_eq!(&ix.data[..2], &[0x65, 0x00]);
        assert_eq!(ix.data.len(), 68);
        assert_eq!(ix.accounts.len(), 4);
        assert_eq!(ix.accounts.iter().filter(|a| a.is_signer).count(), 1);
        // quote_secondary: 80 B, disc 0x66, 2 accounts.
        let quote = QuoteSecondaryDescriptor {
            contract_id: cid,
            seller,
            quote_price: 900,
        };
        assert_eq!(quote.encode().len(), 80);
        let ix = ix_quote_secondary(&buyer, &quote).expect("ix");
        assert_eq!(&ix.data[..2], &[0x66, 0x00]);
        assert_eq!(ix.accounts.len(), 2);
        // accept_secondary: 88 B, disc 0x67, 3 accounts.
        let accept = AcceptSecondaryDescriptor {
            contract_id: cid,
            accepted_buyer: buyer,
            accept_price: 900,
            transfer_deadline: 5000,
        };
        assert_eq!(accept.encode().len(), 88);
        let ix = ix_accept_secondary(&seller, &accept).expect("ix");
        assert_eq!(&ix.data[..2], &[0x67, 0x00]);
        assert_eq!(ix.accounts.len(), 3);
        // cancel_secondary: 64 B, disc 0x69, 3 accounts.
        let cancel = CancelSecondaryDescriptor {
            contract_id: cid,
            seller,
        };
        assert_eq!(cancel.encode().len(), 64);
        let ix = ix_cancel_secondary(&seller, &cancel).expect("ix");
        assert_eq!(&ix.data[..2], &[0x69, 0x00]);
        assert_eq!(ix.accounts.len(), 3);
        // atomic_position_transfer: 88 B, disc 0x68, 14 accounts; buyer ATA @6, seller ATA @7.
        let atomic = AtomicPositionTransferDescriptor {
            contract_id: cid,
            transfer_nonce: 1,
            collar_lo: -100,
            collar_hi: 100,
            tick_tau: 1,
        };
        assert_eq!(atomic.encode().len(), 88);
        let ix = ix_atomic_position_transfer(&buyer, &mint, &seller, &atomic).expect("ix");
        assert_eq!(&ix.data[..2], &[0x68, 0x00]);
        assert_eq!(ix.data.len(), 90);
        assert_eq!(ix.accounts.len(), 14);
        assert_eq!(ix.accounts.iter().filter(|a| a.is_signer).count(), 1);
        assert_eq!(
            ix.accounts[6].pubkey,
            associated_token_address(&buyer, &mint).unwrap()
        );
        assert_eq!(
            ix.accounts[7].pubkey,
            associated_token_address(&seller, &mint).unwrap()
        );
    }

    #[test]
    fn legacy_message_compiles_with_correct_header_and_indices() {
        let mint =
            Pubkey::from_base58(crate::skew_catalog::SKEW_SETTLEMENT_MINT_DEVNET).expect("m");
        let owner = Pubkey([0x55u8; 32]);
        let ix = ix_open_risk_account(&owner, &mint).expect("ix");
        let blockhash = [0x99u8; 32];
        let msg = compile_legacy_message(&owner, std::slice::from_ref(&ix), &blockhash);
        // header: exactly 1 required signature (owner), 0 readonly-signed.
        assert_eq!(msg[0], 1, "num_required_signatures");
        assert_eq!(msg[1], 0, "num_readonly_signed");
        // the fee payer (owner) is account[0] in the key list (after the 3 header bytes + the
        // 1-byte account-count shortvec).
        assert_eq!(&msg[4..36], &owner.0);
        // the blockhash sits right after the account keys.
        let num_keys = msg[3] as usize;
        let bh_off = 4 + num_keys * 32;
        assert_eq!(&msg[bh_off..bh_off + 32], &blockhash);
        // a signed tx wraps shortvec(1 sig) ‖ 64-byte sig ‖ message.
        let tx = serialize_transaction(&msg, &[[0u8; 64]]);
        assert_eq!(tx[0], 1); // one signature
        assert_eq!(&tx[1 + 64..], &msg[..]); // D13 spine: the message follows the signatures
    }

    // ---- The VARIABLE-leg permissionless listing codecs. ----

    /// `list_wcc_template` (0x50): the golden affine forward pair from
    /// `list_wcc_template.rs:387` (long `f = S − 40` WCL 40 / short `−(S−40)` WCL 60,
    /// IntervalAffineIII certs) encodes to the on-chain-pinned 314-byte wire (the source
    /// test `descriptor_borsh_wire_width_is_314`), with the 2-byte disc + 5 accounts.
    #[test]
    fn list_wcc_template_is_byte_exact_314() {
        let leg_long = ModeCDescriptor {
            konst: -40,
            coords: vec![AffineCoord {
                coeff: 1,
                lo: 0,
                hi: 100,
                tau: 1,
            }],
        };
        let leg_short = ModeCDescriptor {
            konst: 40,
            coords: vec![AffineCoord {
                coeff: -1,
                lo: 0,
                hi: 100,
                tau: 1,
            }],
        };
        let d = ListWccTemplateDescriptor {
            template_id: [0xF0; 32],
            version: 1,
            terms_schema_hash: [0xF1; 32],
            payoff_adapter_id: 0x42,
            settlement_adapter_id: 0xD4,
            reference_data_policy_id: 0x10,
            collateral_policy_id: 0x1B1B, // SKEW_COLLATERAL_WCC_V1
            vm_policy_id: 0x30,
            receipt_schema_hash: [0xF2; 32],
            leg_long,
            leg_short,
            declared_b_long: 40,
            declared_b_short: 60,
            cert_long: ModeCCertKind::IntervalAffineIII,
            cert_short: ModeCCertKind::IntervalAffineIII,
            fee_policy_id: 6,
        };
        let body = d.encode();
        // The on-chain pinned wire width (d=1 forward + IntervalAffineIII certs + FEE-2).
        assert_eq!(body.len(), 314, "ListWccTemplateDescriptor wire width");
        // collateral_policy_id 0x1B1B LE at descriptor offset 74.
        assert_eq!(&body[74..76], &0x1B1Bu16.to_le_bytes());
        // leg_long.konst (−40 i128 LE) at offset 110 (after the 110-byte fixed prefix).
        assert_eq!(&body[110..126], &(-40i128).to_le_bytes());
        // leg_long.coords count (u32 LE = 1) at offset 126.
        assert_eq!(&body[126..130], &1u32.to_le_bytes());
        // the two 1-byte IntervalAffineIII certs (index 2) at offsets 310/311; fee_policy_id @312.
        assert_eq!(body[310], 2);
        assert_eq!(body[311], 2);
        assert_eq!(&body[312..314], &6u16.to_le_bytes());

        let mint =
            Pubkey::from_base58(crate::skew_catalog::SKEW_SETTLEMENT_MINT_DEVNET).expect("m");
        let lister = Pubkey([0x50u8; 32]);
        let ix = ix_list_wcc_template(&lister, &mint, &d).expect("ix");
        assert_eq!(&ix.data[..2], &[0x50, 0x00]);
        assert_eq!(ix.data.len(), 2 + 314);
        assert_eq!(ix.accounts.len(), 5);
        assert!(ix.accounts[0].is_signer && ix.accounts[0].is_writable); // lister
        assert!(ix.accounts[1].is_writable && !ix.accounts[1].is_signer); // product_template (init)
        assert_eq!(ix.accounts[2].pubkey, mint); // settlement_mint (ro)
        assert!(!ix.accounts[2].is_writable);
        assert_eq!(ix.program_id, skew_program_id().unwrap());
    }

    /// `list_piecewise_template` (0x86): the golden straddle pair from
    /// `list_piecewise_template.rs:386` (`f = |S−50|−8`, WCL 8 / 42) encodes to the
    /// on-chain-pinned 438-byte wire (the source test `straddle_descriptor_borsh_width_is_438`),
    /// with the 2-byte disc + 5 accounts. The m=2 nested `Vec<PieceSegment>` legs are the
    /// hard part — pinned here.
    #[test]
    fn list_piecewise_template_is_byte_exact_438() {
        let leg_long = PiecewiseAffine1D {
            lo: 0,
            hi: 100,
            tau: 10,
            segments: vec![
                PieceSegment {
                    x_hi: 50,
                    coeff: -1,
                    konst: 42,
                },
                PieceSegment {
                    x_hi: 100,
                    coeff: 1,
                    konst: -58,
                },
            ],
        };
        let leg_short = PiecewiseAffine1D {
            lo: 0,
            hi: 100,
            tau: 10,
            segments: vec![
                PieceSegment {
                    x_hi: 50,
                    coeff: 1,
                    konst: -42,
                },
                PieceSegment {
                    x_hi: 100,
                    coeff: -1,
                    konst: 58,
                },
            ],
        };
        let d = ListPiecewiseTemplateDescriptor {
            template_id: [0xE0; 32],
            version: 1,
            terms_schema_hash: [0xE1; 32],
            payoff_adapter_id: 0x243C,
            settlement_adapter_id: 0xC696,
            reference_data_policy_id: 0xA1,
            collateral_policy_id: 0x8394, // SKEW_COLLATERAL_WCC_PIECEWISE_V1
            vm_policy_id: 0x7A,
            receipt_schema_hash: [0xE2; 32],
            leg_long,
            leg_short,
            declared_b_long: 8,
            declared_b_short: 42,
        };
        let body = d.encode();
        assert_eq!(
            body.len(),
            438,
            "ListPiecewiseTemplateDescriptor wire width"
        );
        // collateral_policy_id 0x8394 LE at descriptor offset 74.
        assert_eq!(&body[74..76], &0x8394u16.to_le_bytes());
        // leg_long.lo/hi/tau (i128/i128/u128 LE) at offset 110.
        assert_eq!(&body[110..126], &0i128.to_le_bytes());
        assert_eq!(&body[126..142], &100i128.to_le_bytes());
        assert_eq!(&body[142..158], &10u128.to_le_bytes());
        // leg_long.segments count (u32 LE = 2) at offset 158; seg0.x_hi (50) at 162.
        assert_eq!(&body[158..162], &2u32.to_le_bytes());
        assert_eq!(&body[162..178], &50i128.to_le_bytes());
        assert_eq!(&body[178..194], &(-1i128).to_le_bytes()); // seg0.coeff
        assert_eq!(&body[194..210], &42i128.to_le_bytes()); // seg0.konst
        // declared_b_long (8) at offset 406 (after both 148-byte legs).
        assert_eq!(&body[406..422], &8u128.to_le_bytes());
        assert_eq!(&body[422..438], &42u128.to_le_bytes());

        let mint =
            Pubkey::from_base58(crate::skew_catalog::SKEW_SETTLEMENT_MINT_DEVNET).expect("m");
        let lister = Pubkey([0x86u8; 32]);
        let ix = ix_list_piecewise_template(&lister, &mint, &d).expect("ix");
        assert_eq!(&ix.data[..2], &[0x86, 0x00]);
        assert_eq!(ix.data.len(), 2 + 438);
        assert_eq!(ix.accounts.len(), 5);
        assert!(ix.accounts[0].is_signer && ix.accounts[0].is_writable);
        assert!(ix.accounts[1].is_writable && !ix.accounts[1].is_signer);
        assert_eq!(ix.accounts[2].pubkey, mint);
    }

    // ---- The bilateral piecewise contract lifecycle codecs. ----

    /// The deployed golden straddle leg pair (`f = |S−50| − 8`, WCL 8 / 42) — the
    /// `form_piecewise_contract.rs:406` test fixture, reused by the form/settle goldens.
    fn golden_straddle_legs() -> (PiecewiseAffine1D, PiecewiseAffine1D) {
        let leg_long = PiecewiseAffine1D {
            lo: 0,
            hi: 100,
            tau: 10,
            segments: vec![
                PieceSegment {
                    x_hi: 50,
                    coeff: -1,
                    konst: 42,
                },
                PieceSegment {
                    x_hi: 100,
                    coeff: 1,
                    konst: -58,
                },
            ],
        };
        let leg_short = PiecewiseAffine1D {
            lo: 0,
            hi: 100,
            tau: 10,
            segments: vec![
                PieceSegment {
                    x_hi: 50,
                    coeff: 1,
                    konst: -42,
                },
                PieceSegment {
                    x_hi: 100,
                    coeff: -1,
                    konst: 58,
                },
            ],
        };
        (leg_long, leg_short)
    }

    /// `form_piecewise_contract` (0x87): the straddle descriptor encodes to a 400-byte wire
    /// (contract_id 32 + template_id 32 + 2×148 legs + 2×16 bounds + maturity 8); the ix carries
    /// the 2-byte disc + 11 accounts with the FIRST TWO as signers (long_party + short_party) —
    /// the 2-signer ASSEMBLE+SIM property the chokepoint's multi-sig guard enforces.
    #[test]
    fn form_piecewise_is_byte_exact_2signer() {
        let (leg_long, leg_short) = golden_straddle_legs();
        let d = FormPiecewiseContractDescriptor {
            contract_id: [0xC0; 32],
            template_id: [0xE0; 32],
            leg_long,
            leg_short,
            declared_b_long: 8,
            declared_b_short: 42,
            maturity_timestamp: 1_900_000_000,
        };
        let body = d.encode();
        assert_eq!(
            body.len(),
            400,
            "FormPiecewiseContractDescriptor wire width"
        );
        // leg_long starts at offset 64 (after contract_id + template_id); lo i128 LE.
        assert_eq!(&body[64..80], &0i128.to_le_bytes());
        // maturity_timestamp (i64 LE) is the 8-byte tail.
        assert_eq!(&body[392..400], &1_900_000_000i64.to_le_bytes());

        let long_party = Pubkey([0x87u8; 32]);
        let short_party = Pubkey([0x88u8; 32]);
        let long_src = Pubkey([0x01u8; 32]);
        let short_src = Pubkey([0x02u8; 32]);
        let mint =
            Pubkey::from_base58(crate::skew_catalog::SKEW_SETTLEMENT_MINT_DEVNET).expect("m");
        let ix =
            ix_form_piecewise_contract(&long_party, &short_party, &long_src, &short_src, &mint, &d)
                .expect("ix");
        assert_eq!(&ix.data[..2], &[0x87, 0x00]);
        assert_eq!(ix.data.len(), 2 + 400);
        assert_eq!(ix.accounts.len(), 11);
        // ★ 2 signers: long_party + short_party (the assemble+sim multi-sig property).
        assert!(ix.accounts[0].is_signer && ix.accounts[0].is_writable);
        assert!(ix.accounts[1].is_signer && ix.accounts[1].is_writable);
        assert_eq!(ix.accounts[0].pubkey, long_party);
        assert_eq!(ix.accounts[1].pubkey, short_party);
        // account[2] = product_template (ro); the rest are NOT signers.
        assert!(!ix.accounts[2].is_signer && !ix.accounts[2].is_writable);
        assert!(ix.accounts[3..].iter().all(|a| !a.is_signer));
    }

    /// `settle_piecewise_contract` (0x88): the straddle descriptor encodes to a 376-byte wire
    /// (contract_id 32 + 2×148 legs + 2×16 bounds + settlement_reference 16); the ix carries the
    /// 2-byte disc + 7 accounts with ONLY the caller (a permissionless keeper) as signer.
    #[test]
    fn settle_piecewise_is_byte_exact() {
        let (leg_long, leg_short) = golden_straddle_legs();
        let d = SettlePiecewiseContractDescriptor {
            contract_id: [0xC0; 32],
            leg_long,
            leg_short,
            declared_b_long: 8,
            declared_b_short: 42,
            settlement_reference: 73,
        };
        let body = d.encode();
        assert_eq!(
            body.len(),
            376,
            "SettlePiecewiseContractDescriptor wire width"
        );
        // settlement_reference (i128 LE = 73) is the 16-byte tail.
        assert_eq!(&body[360..376], &73i128.to_le_bytes());

        let caller = Pubkey([0x88u8; 32]);
        let long_tok = Pubkey([0x0Au8; 32]);
        let short_tok = Pubkey([0x0Bu8; 32]);
        let ix = ix_settle_piecewise_contract(&caller, &long_tok, &short_tok, &d).expect("ix");
        assert_eq!(&ix.data[..2], &[0x88, 0x00]);
        assert_eq!(ix.data.len(), 2 + 376);
        assert_eq!(ix.accounts.len(), 7);
        // ONLY the caller signs (1 signer = single-party keeper); it is the writable fee payer.
        assert!(ix.accounts[0].is_signer && ix.accounts[0].is_writable);
        assert_eq!(ix.accounts[0].pubkey, caller);
        assert!(ix.accounts[1..].iter().all(|a| !a.is_signer));
    }

    // ---- The 5 newly-assembled ix golden byte layouts ------------------

    #[test]
    fn open_perp_market_is_byte_exact_126_and_4_accounts() {
        let mint =
            Pubkey::from_base58(crate::skew_catalog::SKEW_SETTLEMENT_MINT_DEVNET).expect("m");
        let opener = Pubkey([0x21u8; 32]);
        let desc = OpenPerpMarketDescriptor {
            market_id: [0x33u8; 32],
            settlement_mint: mint,
            contract_size: 1,
            genesis_reference_atoms: 1_000_000,
            open_interest_cap: 9,
            max_funding_rate: 50,
            tick_size: 20,
            reference_policy_id: 0x00A1,
            active_risk_bracket_id: 3,
            fee_policy_id: 0x0042,
        };
        let enc = desc.encode();
        assert_eq!(
            enc.len(),
            126,
            "OpenPerpMarketDescriptor wire (Python-verified)"
        );
        assert_eq!(&enc[..32], &[0x33u8; 32]); // market_id
        assert_eq!(&enc[32..64], &mint.0); // settlement_mint
        assert_eq!(&enc[64..80], &1u128.to_le_bytes()); // contract_size
        assert_eq!(&enc[112..120], &20u64.to_le_bytes()); // tick_size
        assert_eq!(&enc[120..122], &0x00A1u16.to_le_bytes()); // reference_policy_id
        assert_eq!(&enc[124..126], &0x0042u16.to_le_bytes()); // fee_policy_id
        let ix = ix_open_perp_market(&opener, &desc).expect("ix");
        assert_eq!(&ix.data[..2], &[0x6A, 0x00]);
        assert_eq!(ix.data.len(), 2 + 126);
        assert_eq!(ix.accounts.len(), 4);
        assert!(ix.accounts[0].is_signer && ix.accounts[0].is_writable);
        assert_eq!(ix.accounts.iter().filter(|a| a.is_signer).count(), 1);
        assert!(ix.accounts[1].is_writable && ix.accounts[2].is_writable); // perp_market + funding_state init
    }

    #[test]
    fn factory_list_perp_market_is_byte_exact_8_accounts() {
        let mint =
            Pubkey::from_base58(crate::skew_catalog::SKEW_SETTLEMENT_MINT_DEVNET).expect("m");
        let builder = Pubkey([0x44u8; 32]);
        let leg = ModeCDescriptor {
            konst: 0,
            coords: vec![AffineCoord {
                coeff: 1,
                lo: -100,
                hi: 100,
                tau: 1,
            }],
        };
        let desc = FactoryListPerpMarketDescriptor {
            market_id: [0x55u8; 32],
            settlement_mint: mint,
            contract_size: 1,
            genesis_reference_atoms: 1_000_000,
            open_interest_cap: 9,
            max_funding_rate: 50,
            tick_size: 20,
            reference_policy_id: 0x00A1,
            active_risk_bracket_id: 3,
            fee_policy_id: 0x0042,
            collateral_policy_id: 0x1B1B,
            leg_long: leg.clone(),
            leg_short: leg,
            declared_b_long: 100,
            declared_b_short: 100,
            cert_long: ModeCCertKind::IntervalAffineIII,
            cert_short: ModeCCertKind::IntervalAffineIII,
            ref_min_divisor_price_atoms: 1,
            ref_max_jump_bps_per_epoch: 500,
            ref_max_staleness_slots: 150,
            bond_committed_atoms: 0,
        };
        let enc = desc.encode();
        // head 128 + 2×ModeC(d=1)=84 + b_long/short(32) + 2 certs(2) + envelope(26) + bond(16) = 372.
        assert_eq!(enc.len(), 372, "FactoryListPerpMarketDescriptor d=1 wire");
        assert_eq!(&enc[..32], &[0x55u8; 32]); // market_id
        assert_eq!(&enc[32..64], &mint.0); // settlement_mint
        assert_eq!(&enc[126..128], &0x1B1Bu16.to_le_bytes()); // collateral_policy_id @ head tail
        let ix = ix_factory_list_perp_market(&builder, &desc).expect("ix");
        assert_eq!(&ix.data[..2], &[0x81, 0x00]);
        assert_eq!(ix.data.len(), 2 + 372);
        assert_eq!(ix.accounts.len(), 8);
        assert!(ix.accounts[0].is_signer && ix.accounts[0].is_writable);
        assert_eq!(ix.accounts.iter().filter(|a| a.is_signer).count(), 1);
        assert_eq!(ix.accounts[5].pubkey, mint); // settlement_mint account == descriptor mint
        assert!(!ix.accounts[5].is_writable);
    }

    #[test]
    fn form_funding_swap_is_byte_exact_88_and_2signer() {
        let mint =
            Pubkey::from_base58(crate::skew_catalog::SKEW_SETTLEMENT_MINT_DEVNET).expect("m");
        let long_party = Pubkey([0x61u8; 32]);
        let short_party = Pubkey([0x62u8; 32]);
        let desc = FormFundingSwapDescriptor {
            contract_id: [0x70u8; 32],
            quantity: 10,
            contract_size: 1_000_000,
            fixed_rate_bps: 100,
            rate_lo: -50,
            rate_hi: 300,
            maturity_timestamp: 1_900_000_000,
        };
        let enc = desc.encode();
        assert_eq!(
            enc.len(),
            88,
            "FormFundingSwapDescriptor wire (Python-verified)"
        );
        assert_eq!(&enc[..32], &[0x70u8; 32]); // contract_id
        assert_eq!(&enc[32..40], &10u64.to_le_bytes()); // quantity
        assert_eq!(&enc[40..56], &1_000_000u128.to_le_bytes()); // contract_size
        assert_eq!(&enc[56..64], &100i64.to_le_bytes()); // fixed_rate_bps
        assert_eq!(&enc[64..72], &(-50i64).to_le_bytes()); // rate_lo
        assert_eq!(&enc[72..80], &300i64.to_le_bytes()); // rate_hi
        assert_eq!(&enc[80..88], &1_900_000_000i64.to_le_bytes()); // maturity
        let long_src = associated_token_address(&long_party, &mint).unwrap();
        let short_src = associated_token_address(&short_party, &mint).unwrap();
        let ix = ix_form_funding_swap(
            &long_party,
            &short_party,
            &long_src,
            &short_src,
            &mint,
            &desc,
        )
        .expect("ix");
        assert_eq!(&ix.data[..2], &[0x8E, 0x00]);
        assert_eq!(ix.data.len(), 2 + 88);
        assert_eq!(ix.accounts.len(), 10);
        // ★ 2 SIGNERS ⇒ the chokepoint multi-sig guard returns Simulated (never broadcasts solo).
        assert_eq!(ix.accounts.iter().filter(|a| a.is_signer).count(), 2);
        assert!(ix.accounts[0].is_signer && ix.accounts[0].is_writable);
        assert!(ix.accounts[1].is_signer && ix.accounts[1].is_writable);
        assert_eq!(ix.accounts[5].pubkey, long_src);
        assert_eq!(ix.accounts[6].pubkey, short_src);
        assert_eq!(ix.accounts[7].pubkey, mint);
    }

    #[test]
    fn open_fixed_forward_liquidation_is_byte_exact_134_and_8_accounts() {
        let program = skew_program_id().expect("program");
        let signer = Pubkey([0x81u8; 32]);
        let long_party = Pubkey([0x0Cu8; 32]);
        let short_party = Pubkey([0x0Du8; 32]);
        let template_id = [0x0Eu8; 32];
        let desc = OpenLiquidationDescriptor {
            liquidation_id: [0x90u8; 32],
            contract_id: [0x91u8; 32],
            trigger_kind: 0,
            trigger_snapshot_hash: [0x92u8; 32],
            maintenance_requirement: 500,
            collateral_value: 100,
            defaulter_role: 1,
            auction_grace_seconds: 3600,
        };
        let enc = desc.encode();
        assert_eq!(enc.len(), 134, "OpenLiquidationDescriptor wire");
        assert_eq!(&enc[..32], &[0x90u8; 32]); // liquidation_id
        assert_eq!(&enc[32..64], &[0x91u8; 32]); // contract_id
        assert_eq!(enc[64], 0); // trigger_kind
        assert_eq!(&enc[65..97], &[0x92u8; 32]); // trigger_snapshot_hash
        assert_eq!(&enc[97..113], &500u128.to_le_bytes()); // maintenance_requirement
        assert_eq!(&enc[113..129], &100u128.to_le_bytes()); // collateral_value
        assert_eq!(enc[129], 1); // defaulter_role
        assert_eq!(&enc[130..134], &3600u32.to_le_bytes()); // auction_grace_seconds
        let ix = ix_open_fixed_forward_liquidation(
            &signer,
            &long_party,
            &short_party,
            &template_id,
            &desc,
        )
        .expect("ix");
        assert_eq!(&ix.data[..2], &[0x08, 0x00]);
        assert_eq!(ix.data.len(), 2 + 134);
        assert_eq!(ix.accounts.len(), 8);
        assert!(ix.accounts[0].is_signer && ix.accounts[0].is_writable);
        assert_eq!(ix.accounts.iter().filter(|a| a.is_signer).count(), 1);
        // the collateral_state PDAs use the canonical [b"collateral_state", cid, party] seed.
        let cid = &desc.contract_id;
        let (cs_long, _) =
            find_program_address(&[b"collateral_state", cid, &long_party.0], &program).unwrap();
        let (cs_short, _) =
            find_program_address(&[b"collateral_state", cid, &short_party.0], &program).unwrap();
        let (tmpl, _) =
            find_program_address(&[b"product_template", &template_id], &program).unwrap();
        assert_eq!(ix.accounts[3].pubkey, cs_long);
        assert_eq!(ix.accounts[4].pubkey, cs_short);
        assert_eq!(ix.accounts[5].pubkey, tmpl);
        assert!(!ix.accounts[5].is_writable); // product_template (ro)
    }

    #[test]
    fn complete_liquidation_is_byte_exact_105_with_8byte_sighash() {
        let program = skew_program_id().expect("program");
        let signer = Pubkey([0x82u8; 32]);
        let long_party = Pubkey([0x1Cu8; 32]);
        let short_party = Pubkey([0x1Du8; 32]);
        let template_id = [0x1Eu8; 32];
        let desc = CompleteLiquidationDescriptor {
            contract_id: [0xA1u8; 32],
            liquidation_id: [0xA2u8; 32],
            valuation_amount: -7,
            close_factor: 10_000,
            dispute_resolved: true,
            current_unix_timestamp: 1_900_000_000,
        };
        let enc = desc.encode();
        assert_eq!(enc.len(), 105, "CompleteLiquidationDescriptor wire");
        assert_eq!(&enc[..32], &[0xA1u8; 32]); // contract_id
        assert_eq!(&enc[32..64], &[0xA2u8; 32]); // liquidation_id
        assert_eq!(&enc[64..80], &(-7i128).to_le_bytes()); // valuation_amount
        assert_eq!(&enc[80..96], &10_000u128.to_le_bytes()); // close_factor
        assert_eq!(enc[96], 1); // dispute_resolved (bool ⇒ 1)
        assert_eq!(&enc[97..105], &1_900_000_000i64.to_le_bytes()); // current_unix_timestamp
        // the prelude is the 8-byte sighash sha256("global:complete_liquidation")[..8].
        let sig = [0xff, 0x00, 0x14, 0x28, 0x01, 0x09, 0x0f, 0x27];
        assert_eq!(anchor_ix_sighash("complete_liquidation"), sig);
        let ix = ix_complete_liquidation(&signer, &long_party, &short_party, &template_id, &desc)
            .expect("ix");
        assert_eq!(&ix.data[..8], &sig);
        assert_eq!(ix.data.len(), 8 + 105);
        assert_eq!(ix.accounts.len(), 9);
        assert!(ix.accounts[0].is_signer && ix.accounts[0].is_writable);
        assert_eq!(ix.accounts.iter().filter(|a| a.is_signer).count(), 1);
        let cid = &desc.contract_id;
        let (cs_long, _) =
            find_program_address(&[b"collateral_state", cid, &long_party.0], &program).unwrap();
        let (cs_short, _) =
            find_program_address(&[b"collateral_state", cid, &short_party.0], &program).unwrap();
        let (tmpl, _) =
            find_program_address(&[b"product_template", &template_id], &program).unwrap();
        assert_eq!(ix.accounts[3].pubkey, cs_long);
        assert_eq!(ix.accounts[4].pubkey, cs_short);
        assert_eq!(ix.accounts[7].pubkey, tmpl);
        assert!(!ix.accounts[7].is_writable); // product_template (ro)
    }
}
