//! `zerog_inft` — 0G ERC-7857 iNFT mint PREPARE for a sinabro expert (W3).
//!
//! This is the agent's side of minting an **ERC-7857 iNFT** on 0G Galileo testnet
//! (chain 16602) that binds the W2-D oracle-verified pattern (`dataHash` = the anchored
//! `patternHash`) to a transferable on-chain agent identity — "own the intelligence".
//! It PREPARES the on-chain action; it never performs it.
//!
//! ## the contract this targets (pinned to what COMPILES, not the docs)
//! `0gfoundation/0g-agent-nft` @ main `b86e108a` — an **upgradeable** `AgentNFT` (OZ
//! 5.0.2; deployed behind an `ERC1967Proxy` + `initialize`). The real mint is:
//! `mint(IntelligentData[] iDatas, address to) payable`  where
//! `struct IntelligentData { string dataDescription; bytes32 dataHash; }`. STEP-0
//! grounding FALSIFIED the older `mint(bytes[],string[],address)` signature — it does
//! not exist on this branch. mint does NOT call the verifier (that is the transfer-only
//! `iTransferFrom` path); a deployed non-zero stub verifier just satisfies `initialize`.
//! The full contract + a hermetic deploy→mint→read forge test live in `chain-inft/`.
//!
//! ## funds-safe posture (PD-6 — the agent NEVER holds a signing key)
//! A proxy deploy + a payable `mint` are gas-costing EVM transactions that need a signing
//! key = FUNDS. So this module is **100% PURE**: it only builds the ABI calldata + a
//! keyless read-only gas-estimate request + the exact OWNER-run deploy/mint commands.
//! No transaction, no signature, no wallet, no `reqwest`, no network, no feature gate —
//! nothing here can spend. The funds-bearing deploy/mint runs OUTSIDE the binary (the
//! owner's `forge script`), and the keyless dry-run runs as a bounded `curl`/`cast` —
//! the W2-C/W2-D split. `CustodyCapability` stays uninhabited (PD-6); names no custody.
//!
//! ## the byte surface (cross-language LOCKED — `chain-inft/golden/mint_calldata.hex`)
//! `mint((string,bytes32)[],address)`
//! * selector = `keccak256("mint((string,bytes32)[],address)")[..4]` = `0xa3acac17`
//!   — derived independently by Python `pycryptodome` (the golden) + the `solc` compiler
//!   (`chain-inft/test/SinabroExpertMint.t.sol`); the Rust encoder below reproduces the
//!   full 324-byte calldata byte-for-byte (the third leg; asserted in the tests against
//!   the machine-written golden file — no hand-transcription of the value anywhere).
//! * `dataHash` reuses [`crate::zerog_chain::W2D_PATTERN_HASH`] (ONE source for the
//!   oracle-verified patternHash, already anchored on-chain at `PatternRegistry`).
//!
//! Honest scope: minting proves OWNED PROVENANCE (this identity points at an oracle-
//! verified pattern), NOT per-user correctness — the same aggregate boundary as W2-D.

use crate::provider::web3_rpc::{SafeRpcUrl, Web3Denied};
use crate::zerog_chain::{ZEROG_TESTNET_EVM_RPC, galileo_rpc_safe, hex_encode, jsonrpc_body};

/// The `mint((string,bytes32)[],address)` selector — `keccak256(sig)[..4]`. LOCKED and
/// cross-checked three ways (Python golden, `solc`, and the encoder tests below).
pub const MINT_SELECTOR: [u8; 4] = [0xa3, 0xac, 0xac, 0x17];

/// The canonical mint signature whose `keccak256` prefix is [`MINT_SELECTOR`]. The
/// `IntelligentData` struct encodes as the tuple `(string,bytes32)`.
pub const MINT_SIGNATURE: &str = "mint((string,bytes32)[],address)";

/// The `intelligentDatasOf(uint256)` read selector — the single combined getter that
/// returns the `IntelligentData[]` for a token (NOT split `dataHashesOf`/`...`).
pub const INTELLIGENT_DATAS_OF_SELECTOR: [u8; 4] = [0x40, 0xfb, 0xd7, 0x2f];

/// The seam-locked provenance descriptor (owner 2026-06-24) — names the expert + the
/// oracle/verdict. Exactly 65 bytes (Python-verified; asserted below). Rides in the
/// iNFT's `dataDescription` and is read back by `intelligentDatasOf` on chainscan.
pub const W3_DESCRIPTOR: &str = "sinabro-expert:generalist; oracle=code_oracle:sui_move_build:pass";

/// The golden recipient — a documented PLACEHOLDER test vector (`0xdEaD`). The real mint
/// substitutes the owner's fresh testnet address at fire time; the encoder is correct
/// for ANY `to`, and this vector locks the encoding shape (matches the Python golden).
pub const GOLDEN_RECIPIENT: [u8; 20] = [
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xde, 0xad,
];

/// A big-endian uint256 from a `u64` (high 24 bytes zero). For offsets + byte lengths.
#[must_use]
fn u256_from_u64(x: u64) -> [u8; 32] {
    let mut word = [0u8; 32];
    word[24..].copy_from_slice(&x.to_be_bytes());
    word
}

/// A left-padded uint256 word for a 20-byte address (12 zero bytes ‖ address).
#[must_use]
fn u256_from_addr(to: &[u8; 20]) -> [u8; 32] {
    let mut word = [0u8; 32];
    word[12..].copy_from_slice(to);
    word
}

/// ABI-encode the calldata for `mint(IntelligentData[] iDatas, address to)` with a SINGLE
/// `IntelligentData { dataDescription, dataHash }` entry — PURE Solidity head/tail layout:
/// `selector(4) ‖ head[offset->iDatas=0x40, to] ‖ iDatas[len=1, offset->elem0=0x20] ‖
/// elem0[offset->string=0x40, dataHash, string.len, string right-padded to 32]`.
/// Byte-identical to the Python + `solc` goldens (`chain-inft/golden`, `chain-inft/test`).
#[must_use]
pub fn encode_mint_calldata(descriptor: &str, data_hash: &[u8; 32], to: &[u8; 20]) -> Vec<u8> {
    let desc = descriptor.as_bytes();
    let pad = (32 - (desc.len() % 32)) % 32;
    let mut out = Vec::with_capacity(4 + 32 * 7 + desc.len() + pad);
    out.extend_from_slice(&MINT_SELECTOR);
    // head: offset to the dynamic iDatas array (2 head words = 0x40), then `to`.
    out.extend_from_slice(&u256_from_u64(0x40));
    out.extend_from_slice(&u256_from_addr(to));
    // iDatas (dynamic array of a dynamic tuple): length=1, then one element offset (0x20).
    out.extend_from_slice(&u256_from_u64(1));
    out.extend_from_slice(&u256_from_u64(0x20));
    // elem0 (dynamic tuple `(string,bytes32)`): offset-to-string (2 tuple words = 0x40),
    // the bytes32 dataHash, then the string tail (length + right-padded data).
    out.extend_from_slice(&u256_from_u64(0x40));
    out.extend_from_slice(data_hash);
    out.extend_from_slice(&u256_from_u64(desc.len() as u64));
    out.extend_from_slice(desc);
    out.resize(out.len() + pad, 0u8);
    out
}

/// The locked W3 mint calldata for a given recipient (the encoder applied to the
/// seam-locked descriptor + the reused W2-D patternHash).
#[must_use]
pub fn w3_mint_calldata(to: &[u8; 20]) -> Vec<u8> {
    encode_mint_calldata(W3_DESCRIPTOR, &crate::zerog_chain::W2D_PATTERN_HASH, to)
}

// ===========================================================================
// W3-B capstone — mint a FINE-TUNED EXPERT as an iNFT ("the adapter IS the intelligence")
// ===========================================================================

/// Parse a 0G Storage rootHash (`0x` + 64 hex = a `bytes32`) to bytes. Fail-closed
/// (`None`) on a malformed root — never a guessed dataHash.
#[must_use]
pub fn parse_root_hash(hex: &str) -> Option<[u8; 32]> {
    let body = hex.strip_prefix("0x")?;
    if body.len() != 64 || !body.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    let mut out = [0u8; 32];
    for (i, b) in out.iter_mut().enumerate() {
        *b = u8::from_str_radix(&body[i * 2..i * 2 + 2], 16).ok()?;
    }
    Some(out)
}

/// The descriptor for a fine-tuned EXPERT iNFT — names the expert domain `kind`, the fixed
/// base it was tuned from (reused from [`crate::zerog_finetune`], one source), the verified-
/// pattern provenance, and that the adapter weights live on 0G Storage (the `dataHash` is
/// that adapter's Storage rootHash). Honest: this names the OWNED weights, not correctness.
#[must_use]
pub fn expert_descriptor(kind: &str) -> String {
    format!(
        "sinabro-expert:{kind}; base={}; trained-on=oracle-verified-patterns; weights=0g-storage",
        crate::zerog_finetune::FINETUNE_BASE_MODEL
    )
}

/// ABI-encode the mint calldata for a fine-tuned EXPERT iNFT: the SAME
/// `mint(IntelligentData[],address)` surface (selector `0xa3acac17`), with `dataHash` = the
/// LoRA adapter's 0G Storage rootHash (the weights ARE the intelligence) and the descriptor
/// naming the expert. Byte-compatible with the W3 encoder (same head/tail layout).
#[must_use]
pub fn expert_mint_calldata(adapter_root_hash: &[u8; 32], kind: &str, to: &[u8; 20]) -> Vec<u8> {
    encode_mint_calldata(&expert_descriptor(kind), adapter_root_hash, to)
}

/// OWNER-runbook lines to mint a fine-tuned expert as an iNFT on the EXISTING AgentNFT (the
/// W3 proxy). `dataHash` = the adapter's 0G Storage rootHash; the descriptor names the
/// expert. PURE — only strings; the owner fires the gas-bearing mint with their own key.
#[must_use]
pub fn expert_mint_bundle_lines(
    adapter_root_hash_hex: &str,
    kind: &str,
    proxy_addr: Option<&str>,
    recipient: Option<&str>,
) -> Vec<String> {
    let proxy = proxy_addr.unwrap_or("<AgentNFT proxy — the W3 deploy, e.g. 0x1b8a7f0a…b153>");
    let to = recipient.unwrap_or("<RECIPIENT — owner's address>");
    let descriptor = expert_descriptor(kind);
    vec![
        "0G expert-iNFT mint PREPARE (W3-B capstone) — agent PREPARES, owner FIRES (PD-6)"
            .to_string(),
        "  the LoRA adapter weights ARE the intelligence; the iNFT OWNS them (ERC-7857)"
            .to_string(),
        format!("  expert kind : {kind}"),
        format!("  descriptor  : {descriptor} ({}B)", descriptor.len()),
        format!("  dataHash    : {adapter_root_hash_hex}  (the adapter's 0G Storage rootHash)"),
        format!(
            "  mint sel    : 0x{} ({MINT_SIGNATURE})",
            hex_encode(&MINT_SELECTOR)
        ),
        String::new(),
        "  prerequisite (owner, FUNDS): upload the decrypted LoRA adapter to 0G Storage"
            .to_string(),
        "  (W2-C `memory backup-0g`) → its rootHash is the dataHash above.".to_string(),
        String::new(),
        "  owner mint on the EXISTING AgentNFT (FUNDS — owner key; mint is payable):".to_string(),
        format!("    cast send {proxy} \"mint((string,bytes32)[],address)\" \\"),
        format!("      \"[(\\\"{descriptor}\\\",{adapter_root_hash_hex})]\" {to} \\"),
        format!("      --rpc-url {ZEROG_TESTNET_EVM_RPC} --legacy --gas-price 6000000000 \\"),
        "      --private-key $OG_TESTNET_PRIVATE_KEY".to_string(),
        String::new(),
        "  verify after mint (keyless read):".to_string(),
        format!(
            "    cast call {proxy} \"intelligentDatasOf(uint256)((string,bytes32)[])\" <TOKEN_ID> --rpc-url {ZEROG_TESTNET_EVM_RPC}"
        ),
        String::new(),
        "  the agent holds NO key; mainnet/funds HARD-LOCKED (the binary signs nothing)."
            .to_string(),
    ]
}

/// ABI-encode the keyless read `intelligentDatasOf(uint256 tokenId)` — `selector ‖
/// tokenId:uint256`. PURE; for the post-mint verification read.
#[must_use]
pub fn encode_intelligent_datas_of(token_id: u64) -> Vec<u8> {
    let mut out = Vec::with_capacity(4 + 32);
    out.extend_from_slice(&INTELLIGENT_DATAS_OF_SELECTOR);
    out.extend_from_slice(&u256_from_u64(token_id));
    out
}

/// SSRF-wall the 0G Galileo RPC const through the SAME classifier the web3 reader uses.
/// Reuses [`crate::zerog_chain::galileo_rpc_safe`] — one wall for the whole 0G lane.
///
/// # Errors
/// Returns [`Web3Denied`] if the const ever fails the SSRF wall (it does not today).
pub fn galileo_rpc_safe_inft() -> Result<SafeRpcUrl, Web3Denied> {
    galileo_rpc_safe()
}

/// Is `s` a `0x`-prefixed 20-byte (40 hex) EVM address? Fail-closed validation for the
/// keyless `eth_estimateGas` builder (never a guessed body).
#[must_use]
fn is_evm_address(s: &str) -> bool {
    match s.strip_prefix("0x") {
        Some(body) => body.len() == 40 && body.bytes().all(|b| b.is_ascii_hexdigit()),
        None => false,
    }
}

/// The keyless read-only `eth_estimateGas` request for the MINT call against a deployed
/// proxy — `[{"to":proxy,"from":from,"data":"0x<mint calldata>"}]`. NO key, NO signature:
/// a pure gas SIMULATION (no state change). Returns `None` (fail-closed) unless both
/// `proxy` and `from` are valid `0x`-addresses. The owner/agent POSTs it with a bounded
/// keyless `curl` to [`ZEROG_TESTNET_EVM_RPC`].
#[must_use]
pub fn estimate_mint_gas_request(proxy: &str, from: &str, to: &[u8; 20]) -> Option<String> {
    if !is_evm_address(proxy) || !is_evm_address(from) {
        return None;
    }
    let data = hex_encode(&w3_mint_calldata(to));
    Some(jsonrpc_body(
        "eth_estimateGas",
        &format!("[{{\"to\":\"{proxy}\",\"from\":\"{from}\",\"data\":\"0x{data}\"}}]"),
    ))
}

/// Build the OWNER-runbook lines for the W3 iNFT mint (PURE — only strings). The agent
/// emits these; the OWNER runs the funds-bearing deploy/mint with their own testnet key.
/// `proxy_addr` fills the post-deploy read; `recipient` the mint target — `None` ⇒
/// `<PROXY_ADDR>` / `<RECIPIENT>` placeholders the owner substitutes.
#[must_use]
pub fn mint_bundle_lines(proxy_addr: Option<&str>, recipient: Option<&str>) -> Vec<String> {
    let golden_calldata = hex_encode(&w3_mint_calldata(&GOLDEN_RECIPIENT));
    let pattern_hex = hex_encode(&crate::zerog_chain::W2D_PATTERN_HASH);
    let endpoint_ok = galileo_rpc_safe_inft().is_ok();
    let proxy = proxy_addr.unwrap_or("<PROXY_ADDR>");
    let to = recipient.unwrap_or("<RECIPIENT — owner's fresh testnet address>");
    let mut lines = vec![
        "0G ERC-7857 iNFT mint PREPARE (W3) — agent PREPARES, owner FIRES (PD-6 funds-lock)"
            .to_string(),
        "  contract    : 0gfoundation/0g-agent-nft AgentNFT (upgradeable, OZ 5.0.2; via ERC1967Proxy)"
            .to_string(),
        format!("  mint        : {MINT_SIGNATURE}  (selector 0x{})", hex_encode(&MINT_SELECTOR)),
        format!("  dataHash    : 0x{pattern_hex}  (W2-D oracle-verified patternHash, reused)"),
        format!("  descriptor  : {W3_DESCRIPTOR}  ({}B)", W3_DESCRIPTOR.len()),
        format!(
            "  calldata    : 0x{golden_calldata} ({} bytes; recipient=0x..dEaD placeholder — real `to` substituted at fire)",
            w3_mint_calldata(&GOLDEN_RECIPIENT).len()
        ),
        format!(
            "  endpoint    : {ZEROG_TESTNET_EVM_RPC} (SSRF wall: {})",
            if endpoint_ok { "ok" } else { "DENIED" }
        ),
        String::new(),
        "  owner deploy + mint (FUNDS — the owner runs this, never the agent):".to_string(),
        "    cd chain-inft".to_string(),
        format!("    MINT_RECIPIENT={to} forge script script/DeployAndMint.s.sol:DeployAndMint \\"),
        format!("      --rpc-url {ZEROG_TESTNET_EVM_RPC} --broadcast \\"),
        "      --private-key $OG_TESTNET_PRIVATE_KEY \\".to_string(),
        "      --priority-gas-price 2000000000   # 0G min tip = 2 gwei (W2-D gas gotcha)".to_string(),
        String::new(),
        "  keyless read-only dry-run (NO key — agent or owner; bounded):".to_string(),
        format!("    curl --max-time 12 -s -X POST {ZEROG_TESTNET_EVM_RPC} \\"),
        format!(
            "      -H 'Content-Type: application/json' -d '{}'",
            jsonrpc_body("eth_chainId", "[]")
        ),
        String::new(),
        "  verify after mint (keyless read — the iNFT's bound pattern):".to_string(),
        format!(
            "    cast call {proxy} \"intelligentDatasOf(uint256)((string,bytes32)[])\" <TOKEN_ID> --rpc-url {ZEROG_TESTNET_EVM_RPC}"
        ),
    ];
    // when the proxy is known, add the keyless mint gas-estimate (a real eth_estimateGas).
    if let (Some(p), Some(r)) = (proxy_addr, recipient) {
        if let Some(body) = estimate_mint_gas_request(p, r, &GOLDEN_RECIPIENT) {
            lines.push(String::new());
            lines.push(
                "  keyless mint gas-estimate (NO key — eth_estimateGas simulation):".to_string(),
            );
            lines.push(format!(
                "    curl --max-time 12 -s -X POST {ZEROG_TESTNET_EVM_RPC} \\"
            ));
            lines.push(format!(
                "      -H 'Content-Type: application/json' -d '{body}'"
            ));
        }
    }
    lines
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The machine-written cross-language golden (Python `mint_golden.py` wrote it; solc
    /// re-reads + asserts it; this is the Rust leg). `include_str!` binds the build to
    /// the on-disk artifact — no hand-transcription of the 324-byte value.
    const GOLDEN_CALLDATA_HEX: &str = include_str!("../../../chain-inft/golden/mint_calldata.hex");

    fn golden_bytes() -> Vec<u8> {
        let h = GOLDEN_CALLDATA_HEX
            .trim()
            .strip_prefix("0x")
            .expect("golden is 0x-prefixed");
        (0..h.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&h[i..i + 2], 16).expect("golden is hex"))
            .collect()
    }

    #[test]
    fn selectors_match_golden() {
        assert_eq!(hex_encode(&MINT_SELECTOR), "a3acac17");
        assert_eq!(hex_encode(&INTELLIGENT_DATAS_OF_SELECTOR), "40fbd72f");
        assert!(GOLDEN_CALLDATA_HEX.trim().contains("a3acac17"));
    }

    #[test]
    fn descriptor_is_exactly_65_bytes() {
        assert_eq!(W3_DESCRIPTOR.len(), 65, "descriptor length drifted");
    }

    #[test]
    fn datahash_is_the_single_source_w2d_patternhash() {
        // ONE source for the oracle-verified patternHash (reused from zerog_chain).
        assert_eq!(
            &crate::zerog_chain::W2D_PATTERN_HASH,
            &[
                0x33, 0x2a, 0x98, 0xdb, 0x38, 0x83, 0xf9, 0x41, 0x61, 0xe2, 0xf8, 0x8a, 0x71, 0x4f,
                0x9a, 0xbf, 0xcd, 0x30, 0x68, 0x88, 0xad, 0xeb, 0x73, 0x03, 0x0b, 0x62, 0xd8, 0xc6,
                0x88, 0x84, 0x97, 0x1a,
            ]
        );
    }

    #[test]
    fn encoder_reproduces_the_cross_language_golden() {
        // Rust encoder ⟂ Python ⟂ solc: the locked W3 mint calldata is byte-identical.
        let cd = w3_mint_calldata(&GOLDEN_RECIPIENT);
        assert_eq!(cd.len(), 324, "calldata length");
        assert_eq!(cd, golden_bytes(), "Rust encoder != python/solc golden");
    }

    #[test]
    fn encoder_layout_for_arbitrary_inputs() {
        // empty descriptor ⇒ 4 + 32*7 = 228 bytes (7 head/array words, no string data).
        let cd = encode_mint_calldata("", &[0xAB; 32], &[0x11; 20]);
        assert_eq!(cd.len(), 228);
        assert_eq!(&cd[0..4], &MINT_SELECTOR);
        assert_eq!(cd[4 + 31], 0x40); // head: offset-to-iDatas low byte
        assert_eq!(&cd[4 + 32 + 12..4 + 64], &[0x11; 20]); // `to` (last 20 of word 1)
        assert_eq!(cd[4 + 64 + 31], 1); // iDatas length = 1
        assert_eq!(cd[4 + 96 + 31], 0x20); // elem0 offset
        assert_eq!(cd[4 + 128 + 31], 0x40); // string offset within tuple
        assert_eq!(&cd[4 + 160..4 + 192], &[0xAB; 32]); // dataHash
        assert_eq!(cd[4 + 192 + 31], 0); // string length = 0 (empty)
        // a 33-byte descriptor pads to 64 ⇒ 228 + 64 = 292 bytes.
        let cd2 = encode_mint_calldata(&"x".repeat(33), &[0; 32], &GOLDEN_RECIPIENT);
        assert_eq!(cd2.len(), 292);
        assert_eq!(cd2[4 + 192 + 31], 33); // string length low byte
    }

    #[test]
    fn read_calldata_is_selector_plus_tokenid() {
        let cd = encode_intelligent_datas_of(7);
        assert_eq!(cd.len(), 36);
        assert_eq!(&cd[0..4], &INTELLIGENT_DATAS_OF_SELECTOR);
        assert_eq!(cd[35], 7);
    }

    #[test]
    fn galileo_endpoint_passes_the_ssrf_wall() {
        let safe = galileo_rpc_safe_inft().expect("0G testnet RPC must pass the SSRF wall");
        assert_eq!(safe.host(), "evmrpc-testnet.0g.ai");
        assert!(safe.url().starts_with("https://"));
    }

    #[test]
    fn estimate_mint_gas_is_fail_closed_and_keyless() {
        // valid addresses ⇒ an eth_estimateGas {to,from,data} params, no key/signature.
        let body = estimate_mint_gas_request(
            "0x000000000000000000000000000000000000dEaD",
            "0x00000000000000000000000000000000000000A1",
            &GOLDEN_RECIPIENT,
        )
        .expect("valid addrs");
        assert!(body.contains("\"method\":\"eth_estimateGas\""));
        assert!(body.contains("\"to\":\"0x000000000000000000000000000000000000dEaD\""));
        assert!(!body.contains("PRIVATE_KEY") && !body.contains("\"sign"));
        // fail-closed on a non-address.
        assert!(estimate_mint_gas_request("0xdead", "0xbeef", &GOLDEN_RECIPIENT).is_none());
        assert!(
            estimate_mint_gas_request(
                "notanaddr",
                "0x00000000000000000000000000000000000000A1",
                &GOLDEN_RECIPIENT
            )
            .is_none()
        );
    }

    #[test]
    fn mint_bundle_is_owner_run_and_funds_safe() {
        let lines = mint_bundle_lines(None, None);
        let blob = lines.join("\n");
        assert!(blob.contains("0xa3acac17")); // the locked selector
        assert!(blob.contains(&format!(
            "0x{}",
            hex_encode(&crate::zerog_chain::W2D_PATTERN_HASH)
        )));
        assert!(blob.contains("324 bytes"));
        assert!(blob.contains(W3_DESCRIPTOR));
        assert!(blob.contains("<PROXY_ADDR>") || blob.contains("<RECIPIENT"));
        // honestly OWNER-run + funds-safe: no key VALUE, only an env reference.
        assert!(blob.contains("agent PREPARES, owner FIRES"));
        assert!(blob.contains("$OG_TESTNET_PRIVATE_KEY"));
        assert!(blob.contains("keyless read-only dry-run"));
        assert!(blob.contains("2 gwei")); // the 0G gas gotcha note
        // a known proxy + recipient fills the post-deploy read + adds the keyless estimate.
        let filled = mint_bundle_lines(
            Some("0xabc0000000000000000000000000000000000def"),
            Some("0x00000000000000000000000000000000000000A1"),
        )
        .join("\n");
        assert!(filled.contains("0xabc0000000000000000000000000000000000def"));
        assert!(filled.contains("eth_estimateGas")); // keyless mint simulation present
        assert!(!filled.contains("<PROXY_ADDR>"));
    }

    #[test]
    fn parse_root_hash_is_fail_closed() {
        assert!(
            parse_root_hash("0x332a98db3883f94161e2f88a714f9abfcd306888adeb73030b62d8c68884971a")
                .is_some()
        );
        assert!(
            parse_root_hash("332a98db3883f94161e2f88a714f9abfcd306888adeb73030b62d8c68884971a")
                .is_none()
        ); // no 0x
        assert!(parse_root_hash("0xabc").is_none()); // wrong length
        assert!(
            parse_root_hash("0xZZ2a98db3883f94161e2f88a714f9abfcd306888adeb73030b62d8c68884971a")
                .is_none()
        ); // non-hex
    }

    #[test]
    fn expert_descriptor_names_kind_base_provenance() {
        let d = expert_descriptor("sui_move");
        assert!(d.contains("sinabro-expert:sui_move"));
        assert!(d.contains("base=Qwen2.5-0.5B-Instruct")); // reused from zerog_finetune (one source)
        assert!(d.contains("trained-on=oracle-verified-patterns"));
        assert!(d.contains("weights=0g-storage"));
    }

    #[test]
    fn expert_mint_calldata_uses_the_w3_surface() {
        let root = [0x11u8; 32];
        let cd = expert_mint_calldata(&root, "sui_move", &GOLDEN_RECIPIENT);
        assert_eq!(&cd[0..4], &MINT_SELECTOR); // same mint selector as W3
        assert_eq!(&cd[164..196], &root); // dataHash slot = the adapter rootHash
        // byte-identical to the W3 encoder applied to the expert descriptor.
        assert_eq!(
            cd,
            encode_mint_calldata(&expert_descriptor("sui_move"), &root, &GOLDEN_RECIPIENT)
        );
    }

    #[test]
    fn expert_mint_bundle_is_owner_run_and_funds_safe() {
        let lines = expert_mint_bundle_lines(
            "0xabc0000000000000000000000000000000000000000000000000000000000def",
            "sui_move",
            None,
            None,
        );
        let blob = lines.join("\n");
        assert!(blob.contains(MINT_SIGNATURE));
        assert!(blob.contains("the adapter's 0G Storage rootHash"));
        assert!(blob.contains("sinabro-expert:sui_move"));
        assert!(blob.contains("$OG_TESTNET_PRIVATE_KEY")); // env-ref, never a value
        assert!(blob.contains("HARD-LOCKED"));
        assert!(blob.contains("--legacy --gas-price 6000000000")); // the W3 gas-gotcha fix
    }
}
