//! `skew_execute` — the SIGNING + chain-WRITE chokepoint.
//!
//! This is the deepest gate in the roadmap. Given a [`SkewTxPlan`] (an assembled, byte-exact Skew
//! instruction + the bound the oracle/custody affirmed) and the owner-armed
//! [`ChainTxCapability`](crate::commands::authority::ChainTxCapability) witness, it runs the FULL
//! fail-closed gate chain and — only if EVERY gate passes — signs (isolated ed25519 key) and
//! broadcasts a REAL devnet transaction:
//!
//! 1. **oracle gate** (-1) — the plan's verdict is `AffordableInBounds`, escrow == the request.
//! 2. **custody gate** (-2) — the `ChainTxCapability` witness is required BY VALUE (mintable
//!    ONLY from a within-bounds owner-armed `CustodyGrant`); UNREACHABLE without it.
//! 3. **amount-binding** (-3) — the on-chain value the tx commits == the authorized amount ==
//!    the oracle escrow == the request amount (three-way bind; the signed tx can never move more).
//! 4. **assemble + simulate** (-8, D2/D3) — fetch a recent blockhash, compile the legacy
//!    message, simulate the UNSIGNED tx on devnet; a sim error ⇒ fail-closed (the live program is
//!    the authority).
//! 5. **D14 genesis pin** (-7) — before broadcast, assert the RPC genesis == the devnet hash.
//! 6. **sign + D13** (-6) — sign the message with the isolated key; assert the broadcast tx
//!    carries byte-identically the simulated message.
//! 7. **broadcast** — `sendTransaction`; return the signature.
//!
//! Devnet-FIRST; mainnet = a further, narrower owner arm. The model holds no witness + no signer +
//! no loop tool (-12). The chain WRITE socket is compiled ONLY under `chain-write`; the gate
//! chain is always-compiled + hermetically testable via a scripted [`ChainWritePort`].

use crate::chain_signer::IsolatedSigner;
use crate::commands::authority::ChainTxCapability;
use crate::commands::grant::ChainTxRequest;
#[cfg(feature = "chain-write")]
use crate::provider::redaction::{RedactionRequest, redact};
use crate::provider::web3_rpc::{SafeRpcUrl, classify_rpc_endpoint};
use crate::skew_oracle::{OracleBounds, TradeVerdict, evaluate_trade};
use crate::solana_codec::{
    DEVNET_GENESIS_HASH, Instruction, Pubkey, base64_encode, compile_legacy_message,
    compute_unit_limit_ix, compute_unit_price_ix, ix_accept_secondary, ix_advance_funding_epoch,
    ix_atomic_position_transfer, ix_cancel_secondary, ix_claim_fill, ix_close_batch,
    ix_complete_liquidation, ix_deposit_margin, ix_factory_list_perp_market,
    ix_force_reduce_position, ix_form_contract, ix_form_funding_swap, ix_form_piecewise_contract,
    ix_list_piecewise_template, ix_list_secondary, ix_list_wcc_template, ix_lock_collateral,
    ix_mark_vm, ix_open_batch, ix_open_fixed_forward_liquidation, ix_open_perp_market,
    ix_open_risk_account, ix_pay_vm, ix_quote_secondary, ix_settle_account_funding,
    ix_settle_batch, ix_settle_batch_contract, ix_settle_fixed_forward,
    ix_settle_piecewise_contract, ix_submit_order, ix_submit_perp_order,
    ix_validate_reference_snapshot, ix_withdraw_margin, serialize_transaction,
};

/// The CU limit prepended to every K-2 tx (the init-heavy `open_risk_account` needs headroom; the
/// FE prepends a `setComputeUnitLimit`). 400k is comfortably under the 1.4M tx cap.
pub const K2_COMPUTE_UNIT_LIMIT: u32 = 400_000;

/// The FAST-PATH priority fee (micro-lamports per CU) prepended to every K-2 tx for fast inclusion
/// (the `setComputeUnitPrice` lever). Cited from the Skew FE's own apparatus (50_000 in
/// `register_token_markets.mjs`, 500_000 in the forward lifecycle tools). A modest, always-on default
/// that prioritizes inclusion without overpaying on a quiet devnet; the dynamic congestion-aware
/// priority fee is a documented follow-on. Tunable.
pub const K2_PRIORITY_FEE_MICROLAMPORTS: u64 = 50_000;

/// The bounded chain-RPC methods the WRITE transport may issue (an explicit, closed set — there is
/// no arbitrary-method path; a chain WRITE is exactly `sendTransaction`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ChainRpcMethod {
    /// Fetch a recent blockhash (the message's `recent_blockhash`).
    GetLatestBlockhash,
    /// Fetch the cluster genesis hash (the D14 devnet pin).
    GetGenesisHash,
    /// Simulate a transaction (D2/D3 — the live program is the authority). No state change.
    SimulateTransaction,
    /// Broadcast a signed transaction (the ONE chain WRITE; gated by the full gate chain).
    SendTransaction,
}

impl ChainRpcMethod {
    /// The JSON-RPC wire method name.
    #[must_use]
    pub const fn wire_str(self) -> &'static str {
        match self {
            Self::GetLatestBlockhash => "getLatestBlockhash",
            Self::GetGenesisHash => "getGenesisHash",
            Self::SimulateTransaction => "simulateTransaction",
            Self::SendTransaction => "sendTransaction",
        }
    }
}

/// A devnet simulation result (D2/D3): whether it executed cleanly + the (redacted) program logs.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SimResult {
    /// `true` iff the program executed with NO error (`result.value.err == null`).
    pub ok: bool,
    /// A short, redacted summary of the program logs / error (UNTRUSTED — already redacted).
    pub summary: String,
}

/// Why the WRITE transport could not complete a call (fail-closed; typed).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ChainWriteDenied {
    /// The `chain-write` transport is not compiled (default build) — honest-degrade.
    TransportNotCompiled,
    /// The endpoint failed SSRF hygiene (`classify_rpc_endpoint`).
    EndpointRejected,
    /// The socket / HTTP layer failed (unreachable / non-2xx / over-cap).
    Transport,
    /// The RPC response was malformed / missing the expected field.
    MalformedResponse,
    /// The RPC returned a JSON-RPC `error` object.
    RpcError,
}

/// The WRITE transport seam — ALWAYS compiled so the gate chain has ONE shape across feature combos.
/// The ONLY implementor is the `chain-write` [`ChainWriteTransport`]; the default build has none ⇒
/// every call is the honest [`ChainWriteDenied::TransportNotCompiled`]. The methods return STRUCTURED
/// values (the live impl does the reqwest + JSON parse internally) so the gate chain is hermetically
/// testable via a scripted port.
pub trait ChainWritePort {
    /// Fetch a recent blockhash (32 raw bytes) for the message.
    fn latest_blockhash(&self, safe: &SafeRpcUrl) -> Result<[u8; 32], ChainWriteDenied>;
    /// Fetch the cluster genesis hash (base58 string) for the D14 pin.
    fn genesis_hash(&self, safe: &SafeRpcUrl) -> Result<String, ChainWriteDenied>;
    /// Simulate a base64 transaction on devnet (D2/D3).
    fn simulate(&self, safe: &SafeRpcUrl, tx_b64: &str) -> Result<SimResult, ChainWriteDenied>;
    /// Broadcast a signed base64 transaction; return the signature (base58).
    fn send(&self, safe: &SafeRpcUrl, tx_b64: &str) -> Result<String, ChainWriteDenied>;
    /// FAST PATH (`turbo`): broadcast via the Jito/TPU inclusion path. DEFAULT = honest-degrade to the
    /// standard [`Self::send`] — a port without a Jito route simply uses `sendTransaction` (so `turbo`
    /// is never LESS reliable than `fast`, only — when a Jito endpoint is configured — faster).
    fn send_jito(&self, safe: &SafeRpcUrl, tx_b64: &str) -> Result<String, ChainWriteDenied> {
        self.send(safe, tx_b64)
    }
}

// ---------------------------------------------------------------------------
// The live `chain-write` transport (reqwest; the ONLY chain-WRITE socket).
// ---------------------------------------------------------------------------

/// Default per-call timeout (ms) + response byte cap for the WRITE transport.
pub const CHAIN_WRITE_TIMEOUT_MS: u64 = 20_000;
/// Response byte cap (a sim result / a signature — never a dump).
pub const CHAIN_WRITE_BODY_CAP_BYTES: usize = 256 * 1024;

/// The live chain-WRITE transport (compiled ONLY under `chain-write`). Secret-ZERO: a POST with a
/// `content-type` header and the JSON-RPC body ONLY — NO Authorization / cookie / key / owner secret
/// (the only outbound is the signed-tx base64, which carries the SIGNATURE, never the secret key —
/// -13). `redirect(none)` + `no_proxy` + timeout + byte cap.
#[cfg(feature = "chain-write")]
#[derive(Debug)]
pub struct ChainWriteTransport {
    client: reqwest::blocking::Client,
    body_cap_bytes: usize,
}

#[cfg(feature = "chain-write")]
impl ChainWriteTransport {
    /// Build the transport with the default timeout + body cap. `None` if the client builder fails.
    #[must_use]
    pub fn with_defaults() -> Option<Self> {
        let client = reqwest::blocking::Client::builder()
            .timeout(std::time::Duration::from_millis(CHAIN_WRITE_TIMEOUT_MS))
            .redirect(reqwest::redirect::Policy::none())
            .no_proxy()
            .user_agent("sinabro-chain-write/1.0")
            .build()
            .ok()?;
        Some(Self {
            client,
            body_cap_bytes: CHAIN_WRITE_BODY_CAP_BYTES,
        })
    }

    /// POST a JSON-RPC call (secret-zero) and return the parsed `serde_json::Value` body.
    fn rpc(
        &self,
        safe: &SafeRpcUrl,
        method: ChainRpcMethod,
        params_json: &str,
    ) -> Result<serde_json::Value, ChainWriteDenied> {
        let body = format!(
            "{{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"{}\",\"params\":{params_json}}}",
            method.wire_str()
        );
        let response = self
            .client
            .post(safe.url())
            .header(reqwest::header::CONTENT_TYPE, "application/json")
            .body(body)
            .send()
            .map_err(|_| ChainWriteDenied::Transport)?;
        if !(200..300).contains(&response.status().as_u16()) {
            return Err(ChainWriteDenied::Transport);
        }
        let bytes = response.bytes().map_err(|_| ChainWriteDenied::Transport)?;
        if bytes.len() > self.body_cap_bytes {
            return Err(ChainWriteDenied::Transport);
        }
        serde_json::from_slice(&bytes).map_err(|_| ChainWriteDenied::MalformedResponse)
    }
}

/// FAST PATH: the per-endpoint genesis cache. The genesis hash is a CLUSTER CONSTANT, so once an
/// endpoint is verified it never changes — caching it removes the pre-broadcast `getGenesisHash`
/// round-trip on every tx after the first (the long-running daemon's win). Keyed by the exact endpoint
/// URL ⇒ a different endpoint re-fetches + re-verifies. No TTL/clock (a constant never expires).
#[cfg(feature = "chain-write")]
fn genesis_cache() -> &'static std::sync::Mutex<std::collections::HashMap<String, String>> {
    static C: std::sync::OnceLock<std::sync::Mutex<std::collections::HashMap<String, String>>> =
        std::sync::OnceLock::new();
    C.get_or_init(|| std::sync::Mutex::new(std::collections::HashMap::new()))
}

#[cfg(feature = "chain-write")]
impl ChainWritePort for ChainWriteTransport {
    fn latest_blockhash(&self, safe: &SafeRpcUrl) -> Result<[u8; 32], ChainWriteDenied> {
        let v = self.rpc(
            safe,
            ChainRpcMethod::GetLatestBlockhash,
            "[{\"commitment\":\"confirmed\"}]",
        )?;
        let bh = v
            .get("result")
            .and_then(|r| r.get("value"))
            .and_then(|val| val.get("blockhash"))
            .and_then(serde_json::Value::as_str)
            .ok_or(ChainWriteDenied::MalformedResponse)?;
        let bytes =
            crate::skew_read::base58_decode(bh).ok_or(ChainWriteDenied::MalformedResponse)?;
        bytes
            .try_into()
            .map_err(|_| ChainWriteDenied::MalformedResponse)
    }

    fn genesis_hash(&self, safe: &SafeRpcUrl) -> Result<String, ChainWriteDenied> {
        // FAST PATH: serve the genesis (a cluster constant) from the per-endpoint cache when present.
        let key = safe.url();
        if let Ok(cache) = genesis_cache().lock() {
            if let Some(g) = cache.get(key) {
                return Ok(g.clone());
            }
        }
        let v = self.rpc(safe, ChainRpcMethod::GetGenesisHash, "[]")?;
        let g = v
            .get("result")
            .and_then(serde_json::Value::as_str)
            .map(str::to_string)
            .ok_or(ChainWriteDenied::MalformedResponse)?;
        if let Ok(mut cache) = genesis_cache().lock() {
            cache.insert(key.to_string(), g.clone());
        }
        Ok(g)
    }

    fn simulate(&self, safe: &SafeRpcUrl, tx_b64: &str) -> Result<SimResult, ChainWriteDenied> {
        let params = format!(
            "[\"{tx_b64}\",{{\"encoding\":\"base64\",\"sigVerify\":false,\"replaceRecentBlockhash\":false,\"commitment\":\"confirmed\"}}]"
        );
        let v = self.rpc(safe, ChainRpcMethod::SimulateTransaction, &params)?;
        if v.get("error").is_some() {
            return Err(ChainWriteDenied::RpcError);
        }
        let value = v
            .get("result")
            .and_then(|r| r.get("value"))
            .ok_or(ChainWriteDenied::MalformedResponse)?;
        let err = value.get("err");
        let ok = err.is_none() || err == Some(&serde_json::Value::Null);
        // a compact, redacted summary of err + the last log lines (UNTRUSTED program output).
        let mut raw = String::new();
        if let Some(e) = err {
            if !e.is_null() {
                raw.push_str(&format!("err={e} "));
            }
        }
        if let Some(logs) = value.get("logs").and_then(serde_json::Value::as_array) {
            for line in logs.iter().rev().take(4).rev() {
                if let Some(s) = line.as_str() {
                    raw.push_str(s);
                    raw.push_str(" | ");
                }
            }
        }
        Ok(SimResult {
            ok,
            summary: redact_summary(&raw),
        })
    }

    fn send(&self, safe: &SafeRpcUrl, tx_b64: &str) -> Result<String, ChainWriteDenied> {
        let params = format!("[\"{tx_b64}\",{{\"encoding\":\"base64\",\"skipPreflight\":true}}]");
        let v = self.rpc(safe, ChainRpcMethod::SendTransaction, &params)?;
        if v.get("error").is_some() {
            return Err(ChainWriteDenied::RpcError);
        }
        v.get("result")
            .and_then(serde_json::Value::as_str)
            .map(str::to_string)
            .ok_or(ChainWriteDenied::MalformedResponse)
    }

    fn send_jito(&self, safe: &SafeRpcUrl, tx_b64: &str) -> Result<String, ChainWriteDenied> {
        // FAST PATH `turbo`: route to the owner-configured Jito/TPU endpoint (`SKEW_JITO_ENDPOINT`)
        // for prioritized inclusion; honest-degrade to the standard `send` when none is set, it fails
        // SSRF hygiene, or the Jito call errors — the tx is NEVER silently dropped (re-sending a
        // signed tx is idempotent, deduped by signature). The full Jito bundle (tip ix + `sendBundle`)
        // is a documented owner go-live; v1 routes a `sendTransaction` to the Jito RPC.
        let Some(ep) = std::env::var_os("SKEW_JITO_ENDPOINT") else {
            return self.send(safe, tx_b64);
        };
        let ep = ep.to_string_lossy();
        let Ok(jito_safe) = classify_rpc_endpoint(&ep) else {
            return self.send(safe, tx_b64);
        };
        let params = format!("[\"{tx_b64}\",{{\"encoding\":\"base64\",\"skipPreflight\":true}}]");
        if let Ok(v) = self.rpc(&jito_safe, ChainRpcMethod::SendTransaction, &params) {
            if v.get("error").is_none() {
                if let Some(sig) = v.get("result").and_then(serde_json::Value::as_str) {
                    return Ok(sig.to_string());
                }
            }
        }
        // jito failed / malformed ⇒ degrade to standard send (idempotent; never drop the tx).
        self.send(safe, tx_b64)
    }
}

/// Redact an UNTRUSTED RPC text fragment (program logs / error) before it surfaces — secret-shaped
/// content is withheld wholesale (-13). Bounded to 240 chars. Used by the live `chain-write`
/// transport (the only producer of untrusted RPC text).
#[cfg(feature = "chain-write")]
fn redact_summary(raw: &str) -> String {
    let truncated: String = raw.chars().take(240).collect();
    let fragments = [truncated.as_str()];
    match redact(&RedactionRequest {
        fragments: &fragments,
        candidate_memory_ids: &[],
        deleted_ids: &[],
        include_private_memory: false,
    }) {
        Ok(receipt) if receipt.secret_fragments_denied_u32() == 0 => truncated,
        _ => "<redacted: secret-shaped program output withheld>".to_string(),
    }
}

/// The always-compiled WRITE seam — owns ONE live [`ChainWriteTransport`] under `chain-write`,
/// nothing otherwise (every call ⇒ the honest not-compiled deny).
#[derive(Debug, Default)]
pub struct ChainWriteSeam {
    #[cfg(feature = "chain-write")]
    transport: Option<ChainWriteTransport>,
}

impl ChainWriteSeam {
    /// The LIVE seam (a live transport under `chain-write`, inert otherwise).
    #[must_use]
    pub fn new() -> Self {
        Self {
            #[cfg(feature = "chain-write")]
            transport: ChainWriteTransport::with_defaults(),
        }
    }

    /// An INERT seam — no transport in ANY build (hermetic tests; never a live socket).
    #[must_use]
    pub fn inert() -> Self {
        Self {
            #[cfg(feature = "chain-write")]
            transport: None,
        }
    }

    /// The threaded port — `None` in the default build (no chain-write socket).
    #[must_use]
    pub fn port(&self) -> Option<&dyn ChainWritePort> {
        #[cfg(feature = "chain-write")]
        {
            self.transport.as_ref().map(|t| t as &dyn ChainWritePort)
        }
        #[cfg(not(feature = "chain-write"))]
        {
            None
        }
    }
}

// ---------------------------------------------------------------------------
// The plan: an assembled, oracle-gated, amount-bound Skew tx.
// ---------------------------------------------------------------------------

/// A fully-assembled Skew transaction PLAN — the byte-exact instruction(s) + the oracle verdict +
/// the custody-bound request + the on-chain amount. Built ONLY via the `plan_*` builders (which run
/// the K-1 oracle FIRST), so a `SkewTxPlan` cannot exist without an `AffordableInBounds` verdict.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SkewTxPlan {
    /// The custody request (chain / protocol / amount) — what the `ChainTxCapability` authorizes.
    pub request: ChainTxRequest,
    /// The oracle's verdict (an `AffordableInBounds` is a construction precondition).
    pub verdict: TradeVerdict,
    /// The assembled instructions (compute budget + the byte-exact Skew ix).
    pub instructions: Vec<Instruction>,
    /// The on-chain value (settlement-mint atoms) the tx commits — MUST equal `request.amount_minor`
    /// and the oracle escrow (-3). `0` for `open_risk_account` (moves no settlement value).
    pub authorized_amount_atoms: u64,
    /// A short, secret-free action label (e.g. `open_risk_account`) for the receipt.
    pub action_label: &'static str,
}

/// The fixed chain/protocol the custody bound is matched against. The owner arms a `CustodyGrant`
/// whose allowlist must contain these.
pub const K2_CHAIN: &str = "solana-devnet";
/// The protocol allowlist label for Skew.
pub const K2_PROTOCOL: &str = "skew";

/// Build a request for the oracle/custody bound.
fn request_for(amount_minor: u128) -> ChainTxRequest {
    ChainTxRequest {
        chain: K2_CHAIN.to_string(),
        protocol: K2_PROTOCOL.to_string(),
        amount_minor,
    }
}

/// Build the instruction list for an assembled Skew ix (compute-budget prefix + the ix).
fn with_compute_budget(ix: Instruction) -> Option<Vec<Instruction>> {
    // FAST PATH: prepend BOTH the CU-LIMIT (tight budget) and the CU-PRICE priority fee (fast
    // inclusion). The priority fee is a pure inclusion-speed lever with no safety cost; the sim-skip
    // + Jito speed levers are the owner-selected `ExecMode` (Fast/Turbo).
    Some(vec![
        compute_unit_limit_ix(K2_COMPUTE_UNIT_LIMIT)?,
        compute_unit_price_ix(K2_PRIORITY_FEE_MICROLAMPORTS)?,
        ix,
    ])
}

/// Plan `open_risk_account` — opens the URA/pool/vault PDAs. Moves NO settlement-mint value
/// (`amount = 0`); the oracle trivially affirms a 0-escrow account-open within ANY bound. The SOL
/// rent/fee is the isolated key's operational float (distinct from the settlement-mint bound).
pub fn plan_open_risk_account(
    owner: &Pubkey,
    settlement_mint: &Pubkey,
    bounds: &OracleBounds,
    spent_minor: u128,
    portfolio_locked_minor: u128,
) -> Result<SkewTxPlan, crate::skew_oracle::OracleDenied> {
    let escrow: u128 = 0;
    match evaluate_trade(escrow, spent_minor, portfolio_locked_minor, bounds) {
        v @ TradeVerdict::AffordableInBounds { .. } => {
            let ix = ix_open_risk_account(owner, settlement_mint)
                .ok_or(crate::skew_oracle::OracleDenied::InvalidParams)?;
            let instructions =
                with_compute_budget(ix).ok_or(crate::skew_oracle::OracleDenied::InvalidParams)?;
            Ok(SkewTxPlan {
                request: request_for(escrow),
                verdict: v,
                instructions,
                authorized_amount_atoms: 0,
                action_label: "open_risk_account",
            })
        }
        TradeVerdict::Denied(d) => Err(d),
    }
}

/// Plan `deposit_margin` — deposit EXACTLY `amount_atoms` settlement-mint atoms (the previewed
/// margin). The oracle treats the committed deposit as the escrow (`amount`); the deposit `amount`
/// is bound to the authorized amount (-3). The depositor ATA must be funded (broadcast = a
/// follow-on once the isolated key's ATA holds the settlement mint).
pub fn plan_deposit_margin(
    owner: &Pubkey,
    settlement_mint: &Pubkey,
    amount_atoms: u64,
    bounds: &OracleBounds,
    spent_minor: u128,
    portfolio_locked_minor: u128,
) -> Result<SkewTxPlan, crate::skew_oracle::OracleDenied> {
    let escrow = u128::from(amount_atoms);
    match evaluate_trade(escrow, spent_minor, portfolio_locked_minor, bounds) {
        v @ TradeVerdict::AffordableInBounds { .. } => {
            let ix = ix_deposit_margin(owner, settlement_mint, amount_atoms)
                .ok_or(crate::skew_oracle::OracleDenied::InvalidParams)?;
            let instructions =
                with_compute_budget(ix).ok_or(crate::skew_oracle::OracleDenied::InvalidParams)?;
            Ok(SkewTxPlan {
                request: request_for(escrow),
                verdict: v,
                instructions,
                authorized_amount_atoms: amount_atoms,
                action_label: "deposit_margin",
            })
        }
        TradeVerdict::Denied(d) => Err(d),
    }
}

/// Plan `withdraw_margin` — release EXACTLY `amount_atoms` settlement-mint atoms (free collateral)
/// back to the owner. **HONEST SEMANTICS:** a withdraw structurally REDUCES protocol-held exposure
/// (the handler debits only `free_collateral`, never `locked_*`), so it can never increase max-loss.
/// We nonetheless model it EXACTLY like a deposit on the oracle/binding side — `escrow = amount`, the
/// three-way amount-binding `escrow == request == on-chain` (-3) holds trivially — rather than
/// special-casing the chokepoint's GATE 3 with an escrow≠amount carve-out. The effect is a
/// CONSERVATIVE symmetric bound: a single withdraw is capped at `per_tx_max` (the same uniform
/// amount-binding as a deposit), which never under-protects (it can only be stricter than necessary).
/// The chokepoint, the oracle, and the amount-binding gate are byte-unchanged.
pub fn plan_withdraw_margin(
    owner: &Pubkey,
    settlement_mint: &Pubkey,
    amount_atoms: u64,
    bounds: &OracleBounds,
    spent_minor: u128,
    portfolio_locked_minor: u128,
) -> Result<SkewTxPlan, crate::skew_oracle::OracleDenied> {
    let escrow = u128::from(amount_atoms);
    match evaluate_trade(escrow, spent_minor, portfolio_locked_minor, bounds) {
        v @ TradeVerdict::AffordableInBounds { .. } => {
            let ix = ix_withdraw_margin(owner, settlement_mint, amount_atoms)
                .ok_or(crate::skew_oracle::OracleDenied::InvalidParams)?;
            let instructions =
                with_compute_budget(ix).ok_or(crate::skew_oracle::OracleDenied::InvalidParams)?;
            Ok(SkewTxPlan {
                request: request_for(escrow),
                verdict: v,
                instructions,
                authorized_amount_atoms: amount_atoms,
                action_label: "withdraw_margin",
            })
        }
        TradeVerdict::Denied(d) => Err(d),
    }
}

/// Plan `submit_perp_order` — the escrow is the K-1 oracle's worst-case for the proposed perp trade
/// (`escrow_minor`); the on-chain reservation == that escrow (-3). The model PROPOSES the
/// descriptor; the oracle DECIDES the escrow + affordability.
pub fn plan_submit_perp_order(
    owner: &Pubkey,
    descriptor: &crate::solana_codec::SubmitPerpOrderDescriptor,
    trade: &crate::skew_oracle::SkewTrade,
    bounds: &OracleBounds,
    spent_minor: u128,
    portfolio_locked_minor: u128,
) -> Result<SkewTxPlan, crate::skew_oracle::OracleDenied> {
    match crate::skew_oracle::oracle_verdict(trade, spent_minor, portfolio_locked_minor, bounds) {
        TradeVerdict::AffordableInBounds { escrow_minor } => {
            let amount_atoms = u64::try_from(escrow_minor)
                .map_err(|_| crate::skew_oracle::OracleDenied::InvalidParams)?;
            let ix = ix_submit_perp_order(owner, descriptor)
                .ok_or(crate::skew_oracle::OracleDenied::InvalidParams)?;
            let instructions =
                with_compute_budget(ix).ok_or(crate::skew_oracle::OracleDenied::InvalidParams)?;
            Ok(SkewTxPlan {
                request: request_for(escrow_minor),
                verdict: TradeVerdict::AffordableInBounds { escrow_minor },
                instructions,
                authorized_amount_atoms: amount_atoms,
                action_label: "submit_perp_order",
            })
        }
        TradeVerdict::Denied(d) => Err(d),
    }
}

/// Plan `submit_order` — the SINGLE-PARTY OTC entry (the agent's clean max-loss primitive, the UDSI
/// thesis). The K-1 oracle re-derives the EXACT `WCL = q·cs·max(0,gap)` the program escrows
/// (`escrow_wcc_affine_corner`) from the SAME WccParams carried in the descriptor; the on-chain escrow
/// == that WCL (amount-binding, -3 — the descriptor's WccParams MUST match the `trade`'s WCC
/// inputs, which the caller guarantees by building both from one parse). The model PROPOSES the
/// WccParams; the oracle DECIDES the escrow + affordability.
pub fn plan_submit_order(
    signer: &Pubkey,
    settlement_mint: &Pubkey,
    descriptor: &crate::solana_codec::SubmitOrderDescriptor,
    trade: &crate::skew_oracle::SkewTrade,
    bounds: &OracleBounds,
    spent_minor: u128,
    portfolio_locked_minor: u128,
) -> Result<SkewTxPlan, crate::skew_oracle::OracleDenied> {
    match crate::skew_oracle::oracle_verdict(trade, spent_minor, portfolio_locked_minor, bounds) {
        TradeVerdict::AffordableInBounds { escrow_minor } => {
            let amount_atoms = u64::try_from(escrow_minor)
                .map_err(|_| crate::skew_oracle::OracleDenied::InvalidParams)?;
            let ix = ix_submit_order(signer, settlement_mint, descriptor)
                .ok_or(crate::skew_oracle::OracleDenied::InvalidParams)?;
            let instructions =
                with_compute_budget(ix).ok_or(crate::skew_oracle::OracleDenied::InvalidParams)?;
            Ok(SkewTxPlan {
                request: request_for(escrow_minor),
                verdict: TradeVerdict::AffordableInBounds { escrow_minor },
                instructions,
                authorized_amount_atoms: amount_atoms,
                action_label: "submit_order",
            })
        }
        TradeVerdict::Denied(d) => Err(d),
    }
}

/// Plan `pay_fixed_forward_vm` — pay in EXACTLY `payment_amount` settlement-mint atoms to satisfy the
/// open VM call. The agent's payment IS the escrow (value committed from its wallet into the vm_vault);
/// the oracle bounds it by per-tx/budget (the deposit treatment); amount-binding escrow == request ==
/// payment_amount (-3). `template_id` is the product_template seed (the descriptor omits it).
pub fn plan_pay_vm(
    signer: &Pubkey,
    settlement_mint: &Pubkey,
    template_id: &[u8; 32],
    descriptor: &crate::solana_codec::PayVmDescriptor,
    bounds: &OracleBounds,
    spent_minor: u128,
    portfolio_locked_minor: u128,
) -> Result<SkewTxPlan, crate::skew_oracle::OracleDenied> {
    let escrow = descriptor.payment_amount;
    match evaluate_trade(escrow, spent_minor, portfolio_locked_minor, bounds) {
        v @ TradeVerdict::AffordableInBounds { .. } => {
            let amount_atoms = u64::try_from(escrow)
                .map_err(|_| crate::skew_oracle::OracleDenied::InvalidParams)?;
            let ix = ix_pay_vm(signer, settlement_mint, template_id, descriptor)
                .ok_or(crate::skew_oracle::OracleDenied::InvalidParams)?;
            let instructions =
                with_compute_budget(ix).ok_or(crate::skew_oracle::OracleDenied::InvalidParams)?;
            Ok(SkewTxPlan {
                request: request_for(escrow),
                verdict: v,
                instructions,
                authorized_amount_atoms: amount_atoms,
                action_label: "pay_vm",
            })
        }
        TradeVerdict::Denied(d) => Err(d),
    }
}

/// Plan `settle_fixed_forward` — the agent acts as a PERMISSIONLESS keeper resolving a contract at
/// maturity. The keeper commits NO escrow of its OWN (escrow=0); the disbursement is bounded by the
/// posted collateral, not the keeper's wallet — so the custody bound trivially affirms a 0-escrow keeper
/// op (the keeper=aligned-liveness model). The amount-binding `escrow == request == 0` holds trivially.
/// `template_id` (product_template) + `receiver_token_account` (the winner's ATA) are caller inputs.
#[allow(clippy::too_many_arguments)]
pub fn plan_settle_fixed_forward(
    signer: &Pubkey,
    settlement_mint: &Pubkey,
    template_id: &[u8; 32],
    receiver_token_account: &Pubkey,
    descriptor: &crate::solana_codec::SettleFixedForwardDescriptor,
    bounds: &OracleBounds,
    spent_minor: u128,
    portfolio_locked_minor: u128,
) -> Result<SkewTxPlan, crate::skew_oracle::OracleDenied> {
    let escrow: u128 = 0; // keeper commits nothing from its own wallet
    match evaluate_trade(escrow, spent_minor, portfolio_locked_minor, bounds) {
        v @ TradeVerdict::AffordableInBounds { .. } => {
            let ix = ix_settle_fixed_forward(
                signer,
                settlement_mint,
                template_id,
                receiver_token_account,
                descriptor,
            )
            .ok_or(crate::skew_oracle::OracleDenied::InvalidParams)?;
            let instructions =
                with_compute_budget(ix).ok_or(crate::skew_oracle::OracleDenied::InvalidParams)?;
            Ok(SkewTxPlan {
                request: request_for(escrow),
                verdict: v,
                instructions,
                authorized_amount_atoms: 0,
                action_label: "settle_fixed_forward",
            })
        }
        TradeVerdict::Denied(d) => Err(d),
    }
}

/// Plan `lock_fixed_forward_initial_collateral` — the agent (a contract PARTY) locks ITS side's initial
/// collateral. The lock IS the escrow (value committed from the agent's wallet into the collateral
/// vault); the oracle bounds it by per-tx/budget (the deposit treatment). Amount-binding `escrow ==
/// request == lock_amount` (-3). The on-chain program enforces `lock_amount >= required_initial`,
/// so over-locking (capping at `per_tx_max`) is the SAFE direction. `template_id` + `other_party` are
/// caller inputs. `lock_amount` is narrowed to `u64` for the amount-binding (token width).
#[allow(clippy::too_many_arguments)]
pub fn plan_lock_collateral(
    signer: &Pubkey,
    settlement_mint: &Pubkey,
    template_id: &[u8; 32],
    other_party: &Pubkey,
    descriptor: &crate::solana_codec::LockCollateralDescriptor,
    bounds: &OracleBounds,
    spent_minor: u128,
    portfolio_locked_minor: u128,
) -> Result<SkewTxPlan, crate::skew_oracle::OracleDenied> {
    let escrow = descriptor.lock_amount;
    match evaluate_trade(escrow, spent_minor, portfolio_locked_minor, bounds) {
        v @ TradeVerdict::AffordableInBounds { .. } => {
            let amount_atoms = u64::try_from(escrow)
                .map_err(|_| crate::skew_oracle::OracleDenied::InvalidParams)?;
            let ix = ix_lock_collateral(
                signer,
                settlement_mint,
                template_id,
                other_party,
                descriptor,
            )
            .ok_or(crate::skew_oracle::OracleDenied::InvalidParams)?;
            let instructions =
                with_compute_budget(ix).ok_or(crate::skew_oracle::OracleDenied::InvalidParams)?;
            Ok(SkewTxPlan {
                request: request_for(escrow),
                verdict: v,
                instructions,
                authorized_amount_atoms: amount_atoms,
                action_label: "lock_collateral",
            })
        }
        TradeVerdict::Denied(d) => Err(d),
    }
}

/// Plan `mark_fixed_forward_vm` — a PERMISSIONLESS keeper mark-to-market (escrow=0; no token CPI). The
/// agent-as-keeper commits nothing; the amount-binding `escrow == request == 0` holds trivially.
/// `template_id` (product_template) is a caller input.
pub fn plan_mark_vm(
    signer: &Pubkey,
    template_id: &[u8; 32],
    descriptor: &crate::solana_codec::MarkVmDescriptor,
    bounds: &OracleBounds,
    spent_minor: u128,
    portfolio_locked_minor: u128,
) -> Result<SkewTxPlan, crate::skew_oracle::OracleDenied> {
    let escrow: u128 = 0;
    match evaluate_trade(escrow, spent_minor, portfolio_locked_minor, bounds) {
        v @ TradeVerdict::AffordableInBounds { .. } => {
            let ix = ix_mark_vm(signer, template_id, descriptor)
                .ok_or(crate::skew_oracle::OracleDenied::InvalidParams)?;
            let instructions =
                with_compute_budget(ix).ok_or(crate::skew_oracle::OracleDenied::InvalidParams)?;
            Ok(SkewTxPlan {
                request: request_for(escrow),
                verdict: v,
                instructions,
                authorized_amount_atoms: 0,
                action_label: "mark_vm",
            })
        }
        TradeVerdict::Denied(d) => Err(d),
    }
}

/// Plan `form_fixed_forward_contract` — form a bilateral fixed-forward (creates PDAs; escrow=0). ★ 3
/// SIGNERS ⇒ a single bounded agent CANNOT broadcast alone. HONEST SCOPE: this plan ASSEMBLES the tx so
/// the chokepoint can SIMULATE it (`sigVerify:false` validates the bytes without real sigs); a real
/// broadcast needs both party sigs = a multi-sig / 2-agent / quote-authority owner go-live. The
/// amount-binding `escrow == request == 0` holds trivially. The agent's key is the `fee_payer`.
pub fn plan_form_contract(
    fee_payer: &Pubkey,
    descriptor: &crate::solana_codec::FormContractDescriptor,
    bounds: &OracleBounds,
    spent_minor: u128,
    portfolio_locked_minor: u128,
) -> Result<SkewTxPlan, crate::skew_oracle::OracleDenied> {
    let escrow: u128 = 0;
    match evaluate_trade(escrow, spent_minor, portfolio_locked_minor, bounds) {
        v @ TradeVerdict::AffordableInBounds { .. } => {
            let ix = ix_form_contract(fee_payer, descriptor)
                .ok_or(crate::skew_oracle::OracleDenied::InvalidParams)?;
            let instructions =
                with_compute_budget(ix).ok_or(crate::skew_oracle::OracleDenied::InvalidParams)?;
            Ok(SkewTxPlan {
                request: request_for(escrow),
                verdict: v,
                instructions,
                authorized_amount_atoms: 0,
                action_label: "form_contract",
            })
        }
        TradeVerdict::Denied(d) => Err(d),
    }
}

/// Plan `list_secondary` — list an existing OTC position for secondary sale (escrow=0; the agent moves
/// no tokens, only inits a coordination PDA). The amount-binding `escrow == request == 0` holds trivially.
pub fn plan_list_secondary(
    seller: &Pubkey,
    descriptor: &crate::solana_codec::ListSecondaryDescriptor,
    bounds: &OracleBounds,
    spent_minor: u128,
    portfolio_locked_minor: u128,
) -> Result<SkewTxPlan, crate::skew_oracle::OracleDenied> {
    plan_zero_escrow_op(
        ix_list_secondary(seller, descriptor),
        "list_secondary",
        bounds,
        spent_minor,
        portfolio_locked_minor,
    )
}

/// Plan `quote_secondary` — post a bid on a secondary listing (escrow=0).
pub fn plan_quote_secondary(
    buyer: &Pubkey,
    descriptor: &crate::solana_codec::QuoteSecondaryDescriptor,
    bounds: &OracleBounds,
    spent_minor: u128,
    portfolio_locked_minor: u128,
) -> Result<SkewTxPlan, crate::skew_oracle::OracleDenied> {
    plan_zero_escrow_op(
        ix_quote_secondary(buyer, descriptor),
        "quote_secondary",
        bounds,
        spent_minor,
        portfolio_locked_minor,
    )
}

/// Plan `accept_secondary` — the seller accepts a buyer's quote (escrow=0; sets the pending flag).
pub fn plan_accept_secondary(
    seller: &Pubkey,
    descriptor: &crate::solana_codec::AcceptSecondaryDescriptor,
    bounds: &OracleBounds,
    spent_minor: u128,
    portfolio_locked_minor: u128,
) -> Result<SkewTxPlan, crate::skew_oracle::OracleDenied> {
    plan_zero_escrow_op(
        ix_accept_secondary(seller, descriptor),
        "accept_secondary",
        bounds,
        spent_minor,
        portfolio_locked_minor,
    )
}

/// Plan `cancel_secondary` — cancel a secondary listing (escrow=0).
pub fn plan_cancel_secondary(
    caller: &Pubkey,
    descriptor: &crate::solana_codec::CancelSecondaryDescriptor,
    bounds: &OracleBounds,
    spent_minor: u128,
    portfolio_locked_minor: u128,
) -> Result<SkewTxPlan, crate::skew_oracle::OracleDenied> {
    plan_zero_escrow_op(
        ix_cancel_secondary(caller, descriptor),
        "cancel_secondary",
        bounds,
        spent_minor,
        portfolio_locked_minor,
    )
}

/// Shared helper for the escrow=0 secondary-market coordination ops: oracle-affirm a 0-escrow op, wrap
/// the assembled ix with the compute budget, label it. The amount-binding holds trivially (0==0==0).
fn plan_zero_escrow_op(
    ix: Option<Instruction>,
    action_label: &'static str,
    bounds: &OracleBounds,
    spent_minor: u128,
    portfolio_locked_minor: u128,
) -> Result<SkewTxPlan, crate::skew_oracle::OracleDenied> {
    let escrow: u128 = 0;
    match evaluate_trade(escrow, spent_minor, portfolio_locked_minor, bounds) {
        v @ TradeVerdict::AffordableInBounds { .. } => {
            let ix = ix.ok_or(crate::skew_oracle::OracleDenied::InvalidParams)?;
            let instructions =
                with_compute_budget(ix).ok_or(crate::skew_oracle::OracleDenied::InvalidParams)?;
            Ok(SkewTxPlan {
                request: request_for(escrow),
                verdict: v,
                instructions,
                authorized_amount_atoms: 0,
                action_label,
            })
        }
        TradeVerdict::Denied(d) => Err(d),
    }
}

/// Plan `open_batch` — open a batch-auction desk (escrow=0; permissionless).
pub fn plan_open_batch(
    opener: &Pubkey,
    settlement_mint: &Pubkey,
    descriptor: &crate::solana_codec::OpenBatchDescriptor,
    bounds: &OracleBounds,
    spent_minor: u128,
    portfolio_locked_minor: u128,
) -> Result<SkewTxPlan, crate::skew_oracle::OracleDenied> {
    plan_zero_escrow_op(
        ix_open_batch(opener, settlement_mint, descriptor),
        "open_batch",
        bounds,
        spent_minor,
        portfolio_locked_minor,
    )
}

/// Plan `close_batch` — close a batch + create the settle scaffolding (escrow=0; permissionless crank).
pub fn plan_close_batch(
    cranker: &Pubkey,
    descriptor: &crate::solana_codec::CloseBatchDescriptor,
    bounds: &OracleBounds,
    spent_minor: u128,
    portfolio_locked_minor: u128,
) -> Result<SkewTxPlan, crate::skew_oracle::OracleDenied> {
    plan_zero_escrow_op(
        ix_close_batch(cranker, descriptor),
        "close_batch",
        bounds,
        spent_minor,
        portfolio_locked_minor,
    )
}

/// Plan `settle_batch` — deterministic batch clearing (escrow=0; permissionless crank).
pub fn plan_settle_batch(
    cranker: &Pubkey,
    descriptor: &crate::solana_codec::SettleBatchDescriptor,
    bounds: &OracleBounds,
    spent_minor: u128,
    portfolio_locked_minor: u128,
) -> Result<SkewTxPlan, crate::skew_oracle::OracleDenied> {
    plan_zero_escrow_op(
        ix_settle_batch(cranker, descriptor),
        "settle_batch",
        bounds,
        spent_minor,
        portfolio_locked_minor,
    )
}

/// Plan `claim_fill` — reconcile a matched order's escrow; the refund goes to the order owner (escrow=0
/// from the caller). `order_owner` is a caller input (the refund recipient + the order PDA seed).
pub fn plan_claim_fill(
    caller: &Pubkey,
    settlement_mint: &Pubkey,
    order_owner: &Pubkey,
    descriptor: &crate::solana_codec::ClaimFillDescriptor,
    bounds: &OracleBounds,
    spent_minor: u128,
    portfolio_locked_minor: u128,
) -> Result<SkewTxPlan, crate::skew_oracle::OracleDenied> {
    plan_zero_escrow_op(
        ix_claim_fill(caller, settlement_mint, order_owner, descriptor),
        "claim_fill",
        bounds,
        spent_minor,
        portfolio_locked_minor,
    )
}

/// Plan `settle_batch_contract` — settle a program-authored batch-formed contract (escrow=0; the
/// disburse to the winner is bounded by the posted collateral). `template_id` + `receiver_token_account`
/// are caller inputs.
#[allow(clippy::too_many_arguments)]
pub fn plan_settle_batch_contract(
    signer: &Pubkey,
    settlement_mint: &Pubkey,
    template_id: &[u8; 32],
    receiver_token_account: &Pubkey,
    descriptor: &crate::solana_codec::SettleBatchContractDescriptor,
    bounds: &OracleBounds,
    spent_minor: u128,
    portfolio_locked_minor: u128,
) -> Result<SkewTxPlan, crate::skew_oracle::OracleDenied> {
    plan_zero_escrow_op(
        ix_settle_batch_contract(
            signer,
            settlement_mint,
            template_id,
            receiver_token_account,
            descriptor,
        ),
        "settle_batch_contract",
        bounds,
        spent_minor,
        portfolio_locked_minor,
    )
}

/// Plan `atomic_position_transfer` — the buyer takes over an existing OTC position. The buyer's wallet
/// outflow = the position WCL (re-derived by the K-1 oracle from the SAME collar params the descriptor
/// carries) + the agreed `price`; the oracle bounds that TOTAL by per-tx/budget. Amount-binding `escrow
/// == request == WCL + price` (-3). The model PROPOSES the WCC params + price; the oracle DECIDES.
#[allow(clippy::too_many_arguments)]
pub fn plan_atomic_position_transfer(
    buyer: &Pubkey,
    settlement_mint: &Pubkey,
    seller: &Pubkey,
    descriptor: &crate::solana_codec::AtomicPositionTransferDescriptor,
    wcc_trade: &crate::skew_oracle::SkewTrade,
    price: u128,
    bounds: &OracleBounds,
    spent_minor: u128,
    portfolio_locked_minor: u128,
) -> Result<SkewTxPlan, crate::skew_oracle::OracleDenied> {
    let wcl = wcc_trade
        .worst_case_escrow()
        .ok_or(crate::skew_oracle::OracleDenied::InvalidParams)?;
    let escrow = wcl
        .checked_add(price)
        .ok_or(crate::skew_oracle::OracleDenied::InvalidParams)?;
    match evaluate_trade(escrow, spent_minor, portfolio_locked_minor, bounds) {
        v @ TradeVerdict::AffordableInBounds { .. } => {
            let amount_atoms = u64::try_from(escrow)
                .map_err(|_| crate::skew_oracle::OracleDenied::InvalidParams)?;
            let ix = ix_atomic_position_transfer(buyer, settlement_mint, seller, descriptor)
                .ok_or(crate::skew_oracle::OracleDenied::InvalidParams)?;
            let instructions =
                with_compute_budget(ix).ok_or(crate::skew_oracle::OracleDenied::InvalidParams)?;
            Ok(SkewTxPlan {
                request: request_for(escrow),
                verdict: v,
                instructions,
                authorized_amount_atoms: amount_atoms,
                action_label: "atomic_position_transfer",
            })
        }
        TradeVerdict::Denied(d) => Err(d),
    }
}

/// Plan `validate_reference_snapshot` — the permissionless reference firewall validator (escrow=0).
pub fn plan_validate_reference_snapshot(
    caller: &Pubkey,
    descriptor: &crate::solana_codec::ValidateReferenceSnapshotDescriptor,
    bounds: &OracleBounds,
    spent_minor: u128,
    portfolio_locked_minor: u128,
) -> Result<SkewTxPlan, crate::skew_oracle::OracleDenied> {
    plan_zero_escrow_op(
        ix_validate_reference_snapshot(caller, descriptor),
        "validate_reference_snapshot",
        bounds,
        spent_minor,
        portfolio_locked_minor,
    )
}

/// Plan `advance_funding_epoch` — the permissionless funding crank (escrow=0).
pub fn plan_advance_funding_epoch(
    caller: &Pubkey,
    descriptor: &crate::solana_codec::AdvanceFundingEpochDescriptor,
    bounds: &OracleBounds,
    spent_minor: u128,
    portfolio_locked_minor: u128,
) -> Result<SkewTxPlan, crate::skew_oracle::OracleDenied> {
    plan_zero_escrow_op(
        ix_advance_funding_epoch(caller, descriptor),
        "advance_funding_epoch",
        bounds,
        spent_minor,
        portfolio_locked_minor,
    )
}

/// Plan `settle_account_funding` — the permissionless per-position funding settler (escrow=0).
pub fn plan_settle_account_funding(
    caller: &Pubkey,
    descriptor: &crate::solana_codec::SettleAccountFundingDescriptor,
    bounds: &OracleBounds,
    spent_minor: u128,
    portfolio_locked_minor: u128,
) -> Result<SkewTxPlan, crate::skew_oracle::OracleDenied> {
    plan_zero_escrow_op(
        ix_settle_account_funding(caller, descriptor),
        "settle_account_funding",
        bounds,
        spent_minor,
        portfolio_locked_minor,
    )
}

/// Plan `force_reduce_position` — the permissionless CloseOnly position-reducer (escrow=0; the realized
/// P&L + optional backstop draw move internal ledgers, never the keeper's wallet).
pub fn plan_force_reduce_position(
    caller: &Pubkey,
    descriptor: &crate::solana_codec::ForceReducePositionDescriptor,
    bounds: &OracleBounds,
    spent_minor: u128,
    portfolio_locked_minor: u128,
) -> Result<SkewTxPlan, crate::skew_oracle::OracleDenied> {
    plan_zero_escrow_op(
        ix_force_reduce_position(caller, descriptor),
        "force_reduce_position",
        bounds,
        spent_minor,
        portfolio_locked_minor,
    )
}

// ---------------------------------------------------------------------------
// The VARIABLE-leg PERMISSIONLESS template registrations. A
// listing certifies a payoff family on-chain (the UDSI math gate) but moves NO
// settlement value: the lister pays only rent. escrow=0 ⇒ `plan_zero_escrow_op`
// (the amount-binding 0==0==0 holds trivially). The legs are the model-PROPOSED
// payoff; the on-chain gate (re-run at form/submit) is the real solvency authority.
// ---------------------------------------------------------------------------

/// Plan `list_wcc_template` (0x50) — register a PERMISSIONLESS affine forward/swap/collar
/// template (escrow=0). The on-chain UDSI gate certifies the declared leg bounds + the
/// antisymmetric conservation; this plan only assembles the byte-exact registration tx.
pub fn plan_list_wcc_template(
    lister: &Pubkey,
    settlement_mint: &Pubkey,
    descriptor: &crate::solana_codec::ListWccTemplateDescriptor,
    bounds: &OracleBounds,
    spent_minor: u128,
    portfolio_locked_minor: u128,
) -> Result<SkewTxPlan, crate::skew_oracle::OracleDenied> {
    plan_zero_escrow_op(
        ix_list_wcc_template(lister, settlement_mint, descriptor),
        "list_wcc_template",
        bounds,
        spent_minor,
        portfolio_locked_minor,
    )
}

/// Plan `list_piecewise_template` (0x86) — register a PERMISSIONLESS piecewise (option /
/// spread / digital / straddle) template (escrow=0). The on-chain O(m) breakpoint-enum
/// gate certifies each leg's WCL + the conservation pair; this plan only assembles the tx.
pub fn plan_list_piecewise_template(
    lister: &Pubkey,
    settlement_mint: &Pubkey,
    descriptor: &crate::solana_codec::ListPiecewiseTemplateDescriptor,
    bounds: &OracleBounds,
    spent_minor: u128,
    portfolio_locked_minor: u128,
) -> Result<SkewTxPlan, crate::skew_oracle::OracleDenied> {
    plan_zero_escrow_op(
        ix_list_piecewise_template(lister, settlement_mint, descriptor),
        "list_piecewise_template",
        bounds,
        spent_minor,
        portfolio_locked_minor,
    )
}

// ---------------------------------------------------------------------------
// The bilateral piecewise contract lifecycle (form / settle).
// `form_piecewise_contract` is the ONLY ix here that commits the agent's value: each
// party escrows its OWN leg's certified WCL (`escrow_wcc_piecewise(leg)` == the on-chain
// `piecewise_grid_bound(leg).bound`), so the oracle re-derives the EXACT escrow the
// program pulls (amount-binding, -3). 2-signer ⇒ ASSEMBLE+SIM only (the chokepoint
// multi-sig guard). `settle_piecewise_contract` is a permissionless keeper (escrow=0).
// ---------------------------------------------------------------------------

/// Re-derive a piecewise leg's certified WCL (the on-chain `piecewise_grid_bound(leg).bound`)
/// from the codec descriptor — bridges `solana_codec::PieceSegment` → `skew_oracle::PiecewiseSeg`.
fn piecewise_leg_escrow(leg: &crate::solana_codec::PiecewiseAffine1D) -> Option<u128> {
    let segs: Vec<crate::skew_oracle::PiecewiseSeg> = leg
        .segments
        .iter()
        .map(|s| crate::skew_oracle::PiecewiseSeg {
            x_hi: s.x_hi,
            coeff: s.coeff,
            konst: s.konst,
        })
        .collect();
    crate::skew_oracle::escrow_wcc_piecewise(leg.lo, leg.hi, leg.tau, &segs)
}

/// Plan `form_piecewise_contract` (0x87) — bilateral piecewise formation. ★ 2 SIGNERS ⇒
/// ASSEMBLE+SIM only (the chokepoint's multi-sig guard returns `Simulated`, never broadcasts;
/// a real broadcast = a 2-agent / counterparty owner go-live). The escrow the oracle bounds is
/// `escrow_long + escrow_short` = the two certified WCLs the program pulls into the shared vault
/// (amount-binding, -3). The model PROPOSES the legs; the oracle re-derives + DECIDES.
#[allow(clippy::too_many_arguments)]
pub fn plan_form_piecewise_contract(
    long_party: &Pubkey,
    short_party: &Pubkey,
    long_source_token: &Pubkey,
    short_source_token: &Pubkey,
    settlement_mint: &Pubkey,
    descriptor: &crate::solana_codec::FormPiecewiseContractDescriptor,
    bounds: &OracleBounds,
    spent_minor: u128,
    portfolio_locked_minor: u128,
) -> Result<SkewTxPlan, crate::skew_oracle::OracleDenied> {
    // Re-derive each leg's EXACT certified WCL (the escrow the program pulls per leg) — fail-closed.
    let escrow_long = piecewise_leg_escrow(&descriptor.leg_long)
        .ok_or(crate::skew_oracle::OracleDenied::InvalidParams)?;
    let escrow_short = piecewise_leg_escrow(&descriptor.leg_short)
        .ok_or(crate::skew_oracle::OracleDenied::InvalidParams)?;
    let escrow = escrow_long
        .checked_add(escrow_short)
        .ok_or(crate::skew_oracle::OracleDenied::InvalidParams)?;
    match evaluate_trade(escrow, spent_minor, portfolio_locked_minor, bounds) {
        v @ TradeVerdict::AffordableInBounds { .. } => {
            let amount_atoms = u64::try_from(escrow)
                .map_err(|_| crate::skew_oracle::OracleDenied::InvalidParams)?;
            let ix = ix_form_piecewise_contract(
                long_party,
                short_party,
                long_source_token,
                short_source_token,
                settlement_mint,
                descriptor,
            )
            .ok_or(crate::skew_oracle::OracleDenied::InvalidParams)?;
            let instructions =
                with_compute_budget(ix).ok_or(crate::skew_oracle::OracleDenied::InvalidParams)?;
            Ok(SkewTxPlan {
                request: request_for(escrow),
                verdict: v,
                instructions,
                authorized_amount_atoms: amount_atoms,
                action_label: "form_piecewise_contract",
            })
        }
        TradeVerdict::Denied(d) => Err(d),
    }
}

/// Plan `settle_piecewise_contract` (0x88) — the PERMISSIONLESS piecewise settle crank (escrow=0;
/// the keeper commits nothing, the disburse is bounded by the posted vault). The amount-binding
/// `escrow == request == 0` holds trivially.
pub fn plan_settle_piecewise_contract(
    caller: &Pubkey,
    long_token_account: &Pubkey,
    short_token_account: &Pubkey,
    descriptor: &crate::solana_codec::SettlePiecewiseContractDescriptor,
    bounds: &OracleBounds,
    spent_minor: u128,
    portfolio_locked_minor: u128,
) -> Result<SkewTxPlan, crate::skew_oracle::OracleDenied> {
    plan_zero_escrow_op(
        ix_settle_piecewise_contract(caller, long_token_account, short_token_account, descriptor),
        "settle_piecewise_contract",
        bounds,
        spent_minor,
        portfolio_locked_minor,
    )
}

// ---------------------------------------------------------------------------
// The 5 newly-assembled ix planners (all escrow=0 EXCEPT form_funding_swap,
// whose escrow = the byte-exact CEIL worst-case sum the program pulls). The perp-market listings
// + the keeper-liquidation pair move NO settlement value (NO token CPI) ⇒ the amount-binding
// `escrow == request == 0` holds trivially. `form_funding_swap` is 2-signer ⇒ assemble+sim only.
// ---------------------------------------------------------------------------

/// Plan `open_perp_market` (0x6A) — PERMISSIONLESS per-market init (NO token CPI ⇒ escrow=0). The
/// on-chain param-sanity floors (`tick_size>=1`, `contract_size>=1`) are the gate; this plan only
/// assembles the tx.
pub fn plan_open_perp_market(
    opener: &Pubkey,
    descriptor: &crate::solana_codec::OpenPerpMarketDescriptor,
    bounds: &OracleBounds,
    spent_minor: u128,
    portfolio_locked_minor: u128,
) -> Result<SkewTxPlan, crate::skew_oracle::OracleDenied> {
    plan_zero_escrow_op(
        ix_open_perp_market(opener, descriptor),
        "open_perp_market",
        bounds,
        spent_minor,
        portfolio_locked_minor,
    )
}

/// Plan `factory_list_perp_market` (0x81) — PERMISSIONLESS perp listing under the UDSI gate +
/// reference-envelope clamp + RECORD-only builder bond (NO token CPI ⇒ escrow=0). The on-chain math
/// gate certifies the declared WCC legs; this plan only assembles the tx.
pub fn plan_factory_list_perp_market(
    builder: &Pubkey,
    descriptor: &crate::solana_codec::FactoryListPerpMarketDescriptor,
    bounds: &OracleBounds,
    spent_minor: u128,
    portfolio_locked_minor: u128,
) -> Result<SkewTxPlan, crate::skew_oracle::OracleDenied> {
    plan_zero_escrow_op(
        ix_factory_list_perp_market(builder, descriptor),
        "factory_list_perp_market",
        bounds,
        spent_minor,
        portfolio_locked_minor,
    )
}

/// Plan `form_funding_swap` (0x8E) — bilateral fixed-for-floating funding swap. ★ 2 SIGNERS ⇒
/// ASSEMBLE+SIM only (the chokepoint's multi-sig guard returns `Simulated`, never broadcasts; a
/// real broadcast = a 2-agent / counterparty owner go-live). The escrow the oracle bounds is
/// `escrow_long + escrow_short` = the two CEIL worst-case margins the program pulls into the shared
/// vault (amount-binding, -3); the `/10_000` FLOOR-slope payoff has its own dedicated path. The
/// model PROPOSES the terms; the oracle re-derives the EXACT escrow + DECIDES.
#[allow(clippy::too_many_arguments)]
pub fn plan_form_funding_swap(
    long_party: &Pubkey,
    short_party: &Pubkey,
    long_source_token: &Pubkey,
    short_source_token: &Pubkey,
    settlement_mint: &Pubkey,
    descriptor: &crate::solana_codec::FormFundingSwapDescriptor,
    bounds: &OracleBounds,
    spent_minor: u128,
    portfolio_locked_minor: u128,
) -> Result<SkewTxPlan, crate::skew_oracle::OracleDenied> {
    // Re-derive the EXACT bilateral CEIL worst-case sum the program pulls — fail-closed.
    let escrow = crate::skew_oracle::escrow_funding_swap(
        descriptor.quantity,
        descriptor.contract_size,
        descriptor.fixed_rate_bps,
        descriptor.rate_lo,
        descriptor.rate_hi,
    )
    .ok_or(crate::skew_oracle::OracleDenied::InvalidParams)?;
    match evaluate_trade(escrow, spent_minor, portfolio_locked_minor, bounds) {
        v @ TradeVerdict::AffordableInBounds { .. } => {
            let amount_atoms = u64::try_from(escrow)
                .map_err(|_| crate::skew_oracle::OracleDenied::InvalidParams)?;
            let ix = ix_form_funding_swap(
                long_party,
                short_party,
                long_source_token,
                short_source_token,
                settlement_mint,
                descriptor,
            )
            .ok_or(crate::skew_oracle::OracleDenied::InvalidParams)?;
            let instructions =
                with_compute_budget(ix).ok_or(crate::skew_oracle::OracleDenied::InvalidParams)?;
            Ok(SkewTxPlan {
                request: request_for(escrow),
                verdict: v,
                instructions,
                authorized_amount_atoms: amount_atoms,
                action_label: "form_funding_swap",
            })
        }
        TradeVerdict::Denied(d) => Err(d),
    }
}

/// Plan `open_fixed_forward_liquidation` (0x08) — the keeper/permissionless liquidation TRIGGER (NO
/// vault disbursement ⇒ NO token CPI ⇒ escrow=0; the keeper commits nothing). The collateral_state +
/// product_template PDAs are derived inside the ix from the party pubkeys + `template_id`; the
/// handler then cross-pins them to the parent `OtcContractPda`.
#[allow(clippy::too_many_arguments)]
pub fn plan_open_fixed_forward_liquidation(
    signer: &Pubkey,
    long_party: &Pubkey,
    short_party: &Pubkey,
    template_id: &[u8; 32],
    descriptor: &crate::solana_codec::OpenLiquidationDescriptor,
    bounds: &OracleBounds,
    spent_minor: u128,
    portfolio_locked_minor: u128,
) -> Result<SkewTxPlan, crate::skew_oracle::OracleDenied> {
    plan_zero_escrow_op(
        ix_open_fixed_forward_liquidation(signer, long_party, short_party, template_id, descriptor),
        "open_fixed_forward_liquidation",
        bounds,
        spent_minor,
        portfolio_locked_minor,
    )
}

/// Plan `complete_liquidation` (8-byte sighash) — close the liquidation lifecycle (NO vault
/// disbursement ⇒ NO token CPI ⇒ escrow=0). The collateral_state + product_template PDAs are derived
/// inside the ix from the party pubkeys + `template_id`; the handler then cross-pins them.
#[allow(clippy::too_many_arguments)]
pub fn plan_complete_liquidation(
    signer: &Pubkey,
    long_party: &Pubkey,
    short_party: &Pubkey,
    template_id: &[u8; 32],
    descriptor: &crate::solana_codec::CompleteLiquidationDescriptor,
    bounds: &OracleBounds,
    spent_minor: u128,
    portfolio_locked_minor: u128,
) -> Result<SkewTxPlan, crate::skew_oracle::OracleDenied> {
    plan_zero_escrow_op(
        ix_complete_liquidation(signer, long_party, short_party, template_id, descriptor),
        "complete_liquidation",
        bounds,
        spent_minor,
        portfolio_locked_minor,
    )
}

// ---------------------------------------------------------------------------
// The chokepoint: the full fail-closed gate chain → sign + broadcast.
// ---------------------------------------------------------------------------

/// The execution SPEED MODE (FAST PATH). **Owner-selected ONLY** — the mode comes from the owner-typed
/// CLI verb and the model has no CLI, so the model can NEVER select a faster/less-safe mode (the
/// autonomous path defaults to the safest `SimulateThenBroadcast`). `Fast`/`Turbo` skip the
/// pre-broadcast devnet simulation — the owner's informed speed-for-safety tradeoff: the K-1 oracle
/// still proves affordability LOCALLY (microseconds), and the amount-binding + custody witness + D13 +
/// D14 gates ALL still run; only the D2/D3 "would this succeed on devnet" pre-check is traded for one
/// fewer round-trip (a failed tx costs only a fee, never the trade value).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ExecMode {
    /// `sim` — Assemble → REAL simulate → sign → assert D13 → STOP (no broadcast; money 0). The dry run.
    SimulateOnly,
    /// `live` (Standard, safest) — Assemble → REAL simulate → D14 → sign → D13 → REAL broadcast.
    SimulateThenBroadcast,
    /// `fast` (owner-armed) — Assemble → SKIP pre-sim → sign → D13 → D14 → REAL broadcast (one fewer
    /// round-trip; the oracle / amount-binding / custody / D13 / D14 gates are unchanged).
    FastBroadcast,
    /// `turbo` (owner-armed) — `Fast` + Jito/TPU inclusion: the transport routes to a configured Jito
    /// endpoint for next-slot inclusion, and honest-degrades to a standard `send` when none is set.
    TurboBroadcast,
}

impl ExecMode {
    /// Whether this mode runs the pre-broadcast devnet simulation (D2/D3). `Fast`/`Turbo` skip it.
    #[must_use]
    pub const fn runs_pre_sim(self) -> bool {
        matches!(self, Self::SimulateOnly | Self::SimulateThenBroadcast)
    }
    /// Whether this mode broadcasts a real tx (everything except the `SimulateOnly` dry run).
    #[must_use]
    pub const fn broadcasts(self) -> bool {
        matches!(
            self,
            Self::SimulateThenBroadcast | Self::FastBroadcast | Self::TurboBroadcast
        )
    }
    /// Whether this mode requests Jito/TPU inclusion (`Turbo` only).
    #[must_use]
    pub const fn uses_jito(self) -> bool {
        matches!(self, Self::TurboBroadcast)
    }
    /// A stable, secret-free label for the receipt.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::SimulateOnly => "sim",
            Self::SimulateThenBroadcast => "live",
            Self::FastBroadcast => "fast",
            Self::TurboBroadcast => "turbo",
        }
    }
}

/// Why the chokepoint refused to sign/broadcast (fail-closed; typed; EVERY gate is here).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SkewExecDenied {
    /// The oracle verdict is not `AffordableInBounds` (-1).
    OracleNotAffordable,
    /// The oracle escrow / request amount / on-chain amount do not all agree (-3).
    AmountBindingMismatch,
    /// The owner-configured endpoint failed SSRF hygiene (-13).
    EndpointRejected,
    /// The chain-write transport is not compiled (default build) — honest-degrade.
    TransportNotCompiled,
    /// A recent blockhash could not be fetched.
    BlockhashUnavailable,
    /// The devnet simulation reported a program error (D2/D3-8). Carries a redacted summary.
    SimulateFailed(String),
    /// The RPC genesis hash != the devnet pin (-7).
    GenesisMismatch,
    /// The signed tx message != the assembled/simulated message (-6).
    D13Mismatch,
    /// The broadcast RPC failed / returned an error.
    BroadcastFailed,
    /// A transport-layer error (unreachable / malformed) on a non-broadcast step.
    Transport,
}

impl SkewExecDenied {
    /// A stable, secret-free label.
    #[must_use]
    pub const fn label(&self) -> &'static str {
        match self {
            Self::OracleNotAffordable => "oracle_not_affordable",
            Self::AmountBindingMismatch => "amount_binding_mismatch",
            Self::EndpointRejected => "endpoint_rejected_ssrf",
            Self::TransportNotCompiled => "transport_not_compiled",
            Self::BlockhashUnavailable => "blockhash_unavailable",
            Self::SimulateFailed(_) => "simulate_failed",
            Self::GenesisMismatch => "genesis_mismatch_not_devnet",
            Self::D13Mismatch => "d13_signed_ne_assembled",
            Self::BroadcastFailed => "broadcast_failed",
            Self::Transport => "transport_error",
        }
    }
}

/// The outcome of the K-2 chokepoint.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SkewExecOutcome {
    /// A gate refused — fail-closed, NOTHING signed/broadcast.
    Denied(SkewExecDenied),
    /// Simulate-only: the real devnet sim ran + the sign path proved D13; NO broadcast (money 0).
    Simulated {
        /// Whether the devnet simulation executed cleanly (D2/D3).
        sim_ok: bool,
        /// The redacted sim summary.
        sim_summary: String,
        /// Whether D13 (signed message == assembled message) held.
        d13_ok: bool,
    },
    /// A REAL devnet broadcast: the tx was signed (D13), genesis-pinned (D14), and submitted.
    Broadcast {
        /// The transaction signature (base58) — observable on the explorer.
        signature_b58: String,
        /// Whether the pre-broadcast devnet simulation executed cleanly (`false` when skipped — see
        /// `sim_skipped`).
        sim_ok: bool,
        /// FAST PATH: whether the pre-broadcast devnet simulation was SKIPPED (`fast`/`turbo`).
        sim_skipped: bool,
        /// FAST PATH: whether the tx was submitted via the Jito/TPU inclusion path (`turbo` + a
        /// configured endpoint); `false` = standard `sendTransaction`.
        jito: bool,
        /// Whether D14 (devnet genesis pin) held.
        d14_ok: bool,
        /// Whether D13 (signed message == assembled message) held.
        d13_ok: bool,
    },
}

/// THE single K-2 chokepoint. Requires the [`ChainTxCapability`] witness BY VALUE (-2:
/// UNREACHABLE without an owner-armed within-bounds custody grant). Runs the full fail-closed gate
/// chain and — only if EVERY gate passes — signs (isolated key) + (optionally) broadcasts a REAL
/// devnet tx. Money moves ONLY on `SimulateThenBroadcast` after D14 + D13 + a clean sim.
#[must_use]
pub fn execute_skew_chain_tx(
    _capability: ChainTxCapability,
    plan: &SkewTxPlan,
    signer: &IsolatedSigner,
    port: Option<&dyn ChainWritePort>,
    endpoint: &str,
    mode: ExecMode,
) -> SkewExecOutcome {
    // GATE 1 — oracle: the plan must be AffordableInBounds, escrow == request amount (-1).
    let escrow = match plan.verdict {
        TradeVerdict::AffordableInBounds { escrow_minor } => escrow_minor,
        TradeVerdict::Denied(_) => {
            return SkewExecOutcome::Denied(SkewExecDenied::OracleNotAffordable);
        }
    };
    // GATE 3 — amount-binding: oracle escrow == request amount == on-chain amount (-3).
    if escrow != plan.request.amount_minor
        || plan.request.amount_minor != u128::from(plan.authorized_amount_atoms)
    {
        return SkewExecOutcome::Denied(SkewExecDenied::AmountBindingMismatch);
    }
    // SSRF wall on the owner-configured endpoint BEFORE any dial (-13).
    let Ok(safe) = classify_rpc_endpoint(endpoint) else {
        return SkewExecOutcome::Denied(SkewExecDenied::EndpointRejected);
    };
    // The transport must be compiled (chain-write) — else honest-degrade.
    let Some(port) = port else {
        return SkewExecOutcome::Denied(SkewExecDenied::TransportNotCompiled);
    };

    // GATE 4 — assemble: fetch a recent blockhash + compile the legacy message.
    let blockhash = match port.latest_blockhash(&safe) {
        Ok(bh) => bh,
        Err(_) => return SkewExecOutcome::Denied(SkewExecDenied::BlockhashUnavailable),
    };
    let fee_payer = signer.pubkey();
    let message = compile_legacy_message(&fee_payer, &plan.instructions, &blockhash);
    // The required-signature count (`message[0]`); the isolated key signs slot 0 (the fee payer, forced
    // first by `compile_legacy_message`). A MULTI-PARTY tx (`form_contract` = 3 signers) cannot be
    // broadcast by the isolated key alone — it can't forge the counterparty signatures — so it is
    // ASSEMBLE + SIMULATE only (`sigVerify:false`); a real multi-sig broadcast is a documented owner
    // go-live. Single-signer txs (open/deposit/withdraw/perp/submit_order/pay/lock/settle/mark)
    // are byte-unchanged (num_sigs == 1).
    let num_sigs = usize::from(message.first().copied().unwrap_or(1)).max(1);
    let is_multiparty = num_sigs > 1;

    // GATE 4 — simulate the UNSIGNED tx on devnet (D2/D3; the live program is the authority).
    // FAST PATH: `fast`/`turbo` SKIP this pre-sim (one fewer round-trip) — the OWNER-ARMED
    // speed-for-safety tradeoff. The K-1 oracle already proved affordability LOCALLY; D13/D14 still
    // run; a tx that would have failed sim merely fails on-chain for a fee, never the trade value. A
    // multi-party tx ALWAYS simulates (it never broadcasts, so the sim is its only on-chain check).
    let (sim_ok, sim_summary, sim_skipped) = if mode.runs_pre_sim() || is_multiparty {
        let unsigned_tx = serialize_transaction(&message, &vec![[0u8; 64]; num_sigs]);
        let unsigned_b64 = base64_encode(&unsigned_tx);
        let sim = match port.simulate(&safe, &unsigned_b64) {
            Ok(sim) => sim,
            Err(_) => return SkewExecOutcome::Denied(SkewExecDenied::Transport),
        };
        if !sim.ok {
            return SkewExecOutcome::Denied(SkewExecDenied::SimulateFailed(sim.summary));
        }
        (sim.ok, sim.summary, false)
    } else {
        (false, String::new(), true)
    };

    // SIGN (isolated key) + D13 (the broadcast tx carries byte-identically the assembled message) —
    // ALWAYS, in EVERY mode (the sim-skip never relaxes the signature/consistency gate). The isolated
    // key fills sig slot 0 (the fee payer); the remaining slots (multi-party only) are zero placeholders
    // (valid for a `sigVerify:false` simulate; never broadcast).
    let signature = signer.sign_message(&message);
    let mut sigs = vec![[0u8; 64]; num_sigs];
    if let Some(slot0) = sigs.first_mut() {
        *slot0 = signature;
    }
    let signed_tx = serialize_transaction(&message, &sigs);
    // D13: the assembled message is the exact tail of the signed tx (signatures are prepended) —
    // shortvec-size-independent (skips shortvec(num_sigs) + num_sigs·64 sig bytes).
    let d13_ok = signed_tx.len() >= message.len()
        && signed_tx[signed_tx.len() - message.len()..] == message[..];
    if !d13_ok {
        return SkewExecOutcome::Denied(SkewExecDenied::D13Mismatch);
    }

    // A multi-party tx NEVER broadcasts (the isolated key can't forge the counterparty sigs) ⇒ the
    // assemble+sim+sign+D13 result is returned as `Simulated` regardless of the requested mode.
    if !mode.broadcasts() || is_multiparty {
        // `sim` (or a multi-party assemble) — money 0, no broadcast.
        return SkewExecOutcome::Simulated {
            sim_ok,
            sim_summary,
            d13_ok,
        };
    }

    // GATE 5 — D14 devnet genesis pin BEFORE broadcast (-7), in EVERY broadcast mode. (The live
    // transport may serve the genesis from a per-endpoint cache — it is a cluster constant — removing
    // this round-trip on every tx after the first; the D14 == DEVNET_GENESIS_HASH assertion is
    // byte-unchanged.)
    let genesis = match port.genesis_hash(&safe) {
        Ok(g) => g,
        Err(_) => return SkewExecOutcome::Denied(SkewExecDenied::Transport),
    };
    let d14_ok = genesis == DEVNET_GENESIS_HASH;
    if !d14_ok {
        return SkewExecOutcome::Denied(SkewExecDenied::GenesisMismatch);
    }
    // BROADCAST the SIGNED tx — `turbo` requests Jito/TPU inclusion (honest-degrades to a standard
    // `send` when no Jito endpoint is configured); every other broadcast mode uses standard `send`.
    let signed_b64 = base64_encode(&signed_tx);
    let use_jito = mode.uses_jito();
    let send_result = if use_jito {
        port.send_jito(&safe, &signed_b64)
    } else {
        port.send(&safe, &signed_b64)
    };
    match send_result {
        Ok(sig_b58) => SkewExecOutcome::Broadcast {
            signature_b58: sig_b58,
            sim_ok,
            sim_skipped,
            jito: use_jito,
            d14_ok,
            d13_ok,
        },
        Err(_) => SkewExecOutcome::Denied(SkewExecDenied::BroadcastFailed),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::commands::grant::{
        CUSTODY_ARM_PHRASE, CustodyBounds, CustodyGrant, GrantBounds, GrantTier, OwnerArmCeremony,
    };

    fn bounds(per_tx: u128, budget: u128) -> OracleBounds {
        OracleBounds {
            per_tx_max_minor: per_tx,
            total_budget_minor: budget,
            drawdown_max_minor: budget,
        }
    }

    fn settlement_mint() -> Pubkey {
        Pubkey::from_base58(crate::skew_catalog::SKEW_SETTLEMENT_MINT_DEVNET).expect("mint")
    }

    /// Mint a real owner-armed ChainTxCapability for the K-2 chain/protocol + a within-bounds tx.
    fn witness_for(plan: &SkewTxPlan) -> ChainTxCapability {
        use crate::command::ApprovalRequirement;
        use crate::commands::authority::local_chain_tx_capability;
        use crate::repl::approval::ApprovalPrompt;
        let mut p = ApprovalPrompt::new(ApprovalRequirement::TypedPhrase, CUSTODY_ARM_PHRASE);
        let c =
            OwnerArmCeremony::complete(&mut p, CUSTODY_ARM_PHRASE, GrantTier::Custody, [9u8; 32])
                .expect("ceremony");
        let g = CustodyGrant::arm(
            c,
            CustodyBounds {
                base: GrantBounds {
                    max_actions_u32: 4,
                    expires_at_epoch_ms: 10_000,
                },
                per_tx_max_minor: 1_000_000,
                total_budget_minor: 1_000_000,
                chain_allowlist: vec![K2_CHAIN.to_string()],
                protocol_allowlist: vec![K2_PROTOCOL.to_string()],
            },
        )
        .expect("arm");
        local_chain_tx_capability(&g, 1, 0, 0, &plan.request).expect("within bounds")
    }

    /// A scripted port: canned blockhash/genesis/sim/send — NO network (hermetic).
    struct ScriptedPort {
        sim_ok: bool,
        genesis: String,
        send_ok: bool,
    }
    impl ChainWritePort for ScriptedPort {
        fn latest_blockhash(&self, _s: &SafeRpcUrl) -> Result<[u8; 32], ChainWriteDenied> {
            Ok([0xABu8; 32])
        }
        fn genesis_hash(&self, _s: &SafeRpcUrl) -> Result<String, ChainWriteDenied> {
            Ok(self.genesis.clone())
        }
        fn simulate(&self, _s: &SafeRpcUrl, _tx: &str) -> Result<SimResult, ChainWriteDenied> {
            Ok(SimResult {
                ok: self.sim_ok,
                summary: "Program log: ok".to_string(),
            })
        }
        fn send(&self, _s: &SafeRpcUrl, _tx: &str) -> Result<String, ChainWriteDenied> {
            if self.send_ok {
                Ok("5xTestSignatureBase58".to_string())
            } else {
                Err(ChainWriteDenied::RpcError)
            }
        }
    }

    const EP: &str = "https://api.devnet.solana.com";

    #[test]
    fn full_gate_chain_broadcasts_on_all_green() {
        let mint = settlement_mint();
        let owner = IsolatedSigner::from_seed([0x01u8; 32]);
        let plan = plan_open_risk_account(&owner.pubkey(), &mint, &bounds(1000, 1000), 0, 0)
            .expect("plan");
        let cap = witness_for(&plan);
        let port = ScriptedPort {
            sim_ok: true,
            genesis: DEVNET_GENESIS_HASH.to_string(),
            send_ok: true,
        };
        let out = execute_skew_chain_tx(
            cap,
            &plan,
            &owner,
            Some(&port),
            EP,
            ExecMode::SimulateThenBroadcast,
        );
        match out {
            SkewExecOutcome::Broadcast {
                signature_b58,
                sim_ok,
                sim_skipped,
                jito,
                d14_ok,
                d13_ok,
            } => {
                assert!(sim_ok && d14_ok && d13_ok);
                assert!(!sim_skipped && !jito); // `live` = pre-sim ran, standard inclusion
                assert_eq!(signature_b58, "5xTestSignatureBase58");
            }
            other => panic!("expected Broadcast, got {other:?}"),
        }
    }

    #[test]
    fn fast_mode_skips_pre_sim_but_still_broadcasts_and_keeps_d13_d14() {
        // FAST PATH: `FastBroadcast` SKIPS the pre-sim round-trip yet still signs (D13), pins the
        // genesis (D14), and broadcasts. The scripted port FAILS simulate — proving the fast path
        // never calls it (a `live` run with this port would be Denied(SimulateFailed)).
        let mint = settlement_mint();
        let owner = IsolatedSigner::from_seed([0x09u8; 32]);
        let plan = plan_open_risk_account(&owner.pubkey(), &mint, &bounds(1000, 1000), 0, 0)
            .expect("plan");
        let cap = witness_for(&plan);
        // a port whose simulate would FAIL — fast mode must never reach it.
        let port = ScriptedPort {
            sim_ok: false,
            genesis: DEVNET_GENESIS_HASH.to_string(),
            send_ok: true,
        };
        let out =
            execute_skew_chain_tx(cap, &plan, &owner, Some(&port), EP, ExecMode::FastBroadcast);
        match out {
            SkewExecOutcome::Broadcast {
                sim_ok,
                sim_skipped,
                jito,
                d14_ok,
                d13_ok,
                ..
            } => {
                assert!(sim_skipped, "fast mode must report the pre-sim skipped");
                assert!(!sim_ok, "no sim ran ⇒ sim_ok is false in fast mode");
                assert!(!jito, "fast (not turbo) ⇒ standard inclusion");
                assert!(
                    d13_ok && d14_ok,
                    "D13 + D14 still gate every broadcast mode"
                );
            }
            other => panic!("expected fast Broadcast, got {other:?}"),
        }
    }

    #[test]
    fn simulate_only_signs_and_proves_d13_without_broadcast() {
        let mint = settlement_mint();
        let owner = IsolatedSigner::from_seed([0x02u8; 32]);
        let plan = plan_open_risk_account(&owner.pubkey(), &mint, &bounds(1000, 1000), 0, 0)
            .expect("plan");
        let cap = witness_for(&plan);
        let port = ScriptedPort {
            sim_ok: true,
            genesis: DEVNET_GENESIS_HASH.to_string(),
            send_ok: true,
        };
        let out =
            execute_skew_chain_tx(cap, &plan, &owner, Some(&port), EP, ExecMode::SimulateOnly);
        assert!(matches!(
            out,
            SkewExecOutcome::Simulated {
                sim_ok: true,
                d13_ok: true,
                ..
            }
        ));
    }

    #[test]
    fn fail_closed_on_genesis_mismatch_never_broadcasts() {
        let mint = settlement_mint();
        let owner = IsolatedSigner::from_seed([0x03u8; 32]);
        let plan = plan_open_risk_account(&owner.pubkey(), &mint, &bounds(1000, 1000), 0, 0)
            .expect("plan");
        let cap = witness_for(&plan);
        // a NON-devnet genesis ⇒ D14 fails ⇒ Denied, nothing broadcast (mainnet unreachable).
        let port = ScriptedPort {
            sim_ok: true,
            genesis: "MainnetBeware1111111111111111111111111111111".to_string(),
            send_ok: true,
        };
        let out = execute_skew_chain_tx(
            cap,
            &plan,
            &owner,
            Some(&port),
            EP,
            ExecMode::SimulateThenBroadcast,
        );
        assert_eq!(
            out,
            SkewExecOutcome::Denied(SkewExecDenied::GenesisMismatch)
        );
    }

    #[test]
    fn fail_closed_on_sim_error_never_signs() {
        let mint = settlement_mint();
        let owner = IsolatedSigner::from_seed([0x04u8; 32]);
        let plan = plan_open_risk_account(&owner.pubkey(), &mint, &bounds(1000, 1000), 0, 0)
            .expect("plan");
        let cap = witness_for(&plan);
        let port = ScriptedPort {
            sim_ok: false,
            genesis: DEVNET_GENESIS_HASH.to_string(),
            send_ok: true,
        };
        let out = execute_skew_chain_tx(
            cap,
            &plan,
            &owner,
            Some(&port),
            EP,
            ExecMode::SimulateThenBroadcast,
        );
        assert!(matches!(
            out,
            SkewExecOutcome::Denied(SkewExecDenied::SimulateFailed(_))
        ));
    }

    #[test]
    fn oracle_denies_over_budget_before_any_assembly() {
        let mint = settlement_mint();
        let owner = IsolatedSigner::from_seed([0x05u8; 32]);
        // a deposit of 2000 with a per-tx ceiling of 1000 ⇒ the oracle DENIES at plan time.
        let denied = plan_deposit_margin(&owner.pubkey(), &mint, 2000, &bounds(1000, 1000), 0, 0);
        assert_eq!(
            denied.err(),
            Some(crate::skew_oracle::OracleDenied::PerTxExceeded)
        );
    }

    #[test]
    fn form_contract_is_assemble_and_simulate_only_never_broadcasts() {
        // form_contract = 3 signers ⇒ the isolated key can't forge the counterparty sigs ⇒ even a
        // `live` request returns Simulated (never Broadcast). The sim runs; D13 holds over the multi-sig
        // message (zero-padded sig slots, sigVerify:false).
        let mint = settlement_mint();
        let agent = IsolatedSigner::from_seed([0x0Au8; 32]);
        let desc = crate::solana_codec::FormContractDescriptor {
            contract_id: [0x01u8; 32],
            template_id: [0x02u8; 32],
            version: 1,
            terms_hash: [0x03u8; 32],
            accept_id: [0x04u8; 32],
            quote_expiry: 0,
            long_party: Pubkey([0x77u8; 32]),
            short_party: Pubkey([0x88u8; 32]),
            party_roles: 0,
            allow_self_cross: false,
            underlying_reference_id: [0u8; 32],
            settlement_mint: mint,
            quantity: 1,
            contract_size: 1,
            forward_price: 100,
            maturity_timestamp: 2000,
            notional: 100,
            reference_data_policy_id: 0,
            collateral_policy_id: 0,
            vm_policy_id: 0,
            settlement_adapter_id: 0,
            approved_reference_ids: vec![],
            approved_settlement_mints: vec![],
        };
        let plan =
            plan_form_contract(&agent.pubkey(), &desc, &bounds(1000, 1000), 0, 0).expect("plan");
        let cap = witness_for(&plan);
        let port = ScriptedPort {
            sim_ok: true,
            genesis: DEVNET_GENESIS_HASH.to_string(),
            send_ok: true,
        };
        // even `SimulateThenBroadcast` (live) returns Simulated for a multi-party tx.
        let out = execute_skew_chain_tx(
            cap,
            &plan,
            &agent,
            Some(&port),
            EP,
            ExecMode::SimulateThenBroadcast,
        );
        assert!(
            matches!(
                out,
                SkewExecOutcome::Simulated {
                    sim_ok: true,
                    d13_ok: true,
                    ..
                }
            ),
            "multi-party form is assemble+sim only, got {out:?}"
        );
    }

    #[test]
    fn lock_collateral_escrow_is_lock_amount_and_oracle_gated() {
        let mint = settlement_mint();
        let signer = IsolatedSigner::from_seed([0x0Bu8; 32]);
        let tid = [0x22u8; 32];
        let other = Pubkey([0x33u8; 32]);
        let desc = crate::solana_codec::LockCollateralDescriptor {
            contract_id: [0x44u8; 32],
            party_role: 0,
            lock_amount: 2000, // > per-tx 1000 ⇒ the oracle DENIES (escrow == lock_amount)
            collateral_policy_version: 1,
            collateral_params_bytes: vec![],
            collateral_snapshot_bytes: vec![],
            reference_snapshot_hash: [1u8; 32],
            reference_snapshot_age_seconds: 0,
            reference_max_age_seconds: 0,
            vm_policy_bytes: vec![],
            vm_mark_source: 0,
        };
        let denied = plan_lock_collateral(
            &signer.pubkey(),
            &mint,
            &tid,
            &other,
            &desc,
            &bounds(1000, 1000),
            0,
            0,
        );
        assert_eq!(
            denied.err(),
            Some(crate::skew_oracle::OracleDenied::PerTxExceeded)
        );
        // a within-bounds lock plans cleanly, escrow == lock_amount.
        let mut ok_desc = desc.clone();
        ok_desc.lock_amount = 500;
        let plan = plan_lock_collateral(
            &signer.pubkey(),
            &mint,
            &tid,
            &other,
            &ok_desc,
            &bounds(1000, 1000),
            0,
            0,
        )
        .expect("plan");
        assert_eq!(plan.authorized_amount_atoms, 500);
        assert_eq!(plan.action_label, "lock_collateral");
    }

    #[test]
    fn amount_binding_mismatch_is_fail_closed() {
        let mint = settlement_mint();
        let owner = IsolatedSigner::from_seed([0x06u8; 32]);
        let mut plan =
            plan_deposit_margin(&owner.pubkey(), &mint, 500, &bounds(1000, 1000), 0, 0).expect("p");
        let cap = witness_for(&plan);
        // tamper: the authorized on-chain amount no longer matches the request/escrow.
        plan.authorized_amount_atoms = 999;
        let port = ScriptedPort {
            sim_ok: true,
            genesis: DEVNET_GENESIS_HASH.to_string(),
            send_ok: true,
        };
        let out = execute_skew_chain_tx(
            cap,
            &plan,
            &owner,
            Some(&port),
            EP,
            ExecMode::SimulateThenBroadcast,
        );
        assert_eq!(
            out,
            SkewExecOutcome::Denied(SkewExecDenied::AmountBindingMismatch)
        );
    }

    #[test]
    fn transport_not_compiled_is_honest_degrade() {
        let mint = settlement_mint();
        let owner = IsolatedSigner::from_seed([0x08u8; 32]);
        let plan = plan_open_risk_account(&owner.pubkey(), &mint, &bounds(1000, 1000), 0, 0)
            .expect("plan");
        let cap = witness_for(&plan);
        // no port (default build) ⇒ honest not-compiled deny, nothing signed.
        let out = execute_skew_chain_tx(cap, &plan, &owner, None, EP, ExecMode::SimulateOnly);
        assert_eq!(
            out,
            SkewExecOutcome::Denied(SkewExecDenied::TransportNotCompiled)
        );
    }

    #[test]
    fn ssrf_endpoint_is_rejected_before_dial() {
        let mint = settlement_mint();
        let owner = IsolatedSigner::from_seed([0x09u8; 32]);
        let plan = plan_open_risk_account(&owner.pubkey(), &mint, &bounds(1000, 1000), 0, 0)
            .expect("plan");
        let cap = witness_for(&plan);
        let port = ScriptedPort {
            sim_ok: true,
            genesis: DEVNET_GENESIS_HASH.to_string(),
            send_ok: true,
        };
        // an IP-literal endpoint ⇒ SSRF reject before any dial.
        let out = execute_skew_chain_tx(
            cap,
            &plan,
            &owner,
            Some(&port),
            "https://127.0.0.1:8899",
            ExecMode::SimulateOnly,
        );
        assert_eq!(
            out,
            SkewExecOutcome::Denied(SkewExecDenied::EndpointRejected)
        );
    }
}
