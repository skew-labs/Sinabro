//! `zerog_chain` — 0G Chain (EVM) anchor PREPARE for an oracle-verified pattern (W2-D).
//!
//! This is the agent's side of anchoring a verified-pattern hash on 0G Galileo testnet
//! (chain 16602). It PREPARES the on-chain action; it never performs it.
//!
//! ## funds-safe posture (PD-6 — the agent NEVER holds a signing key)
//! A deploy + an `anchorPattern` send are gas-costing EVM transactions that need a
//! signing key = FUNDS. So this module is **100% PURE**: it only builds the ABI
//! calldata + a read-only gas-estimate request + the exact OWNER-run commands. There is
//! no transaction, no signature, no wallet, no `reqwest`, no network, no feature gate —
//! nothing here can spend. The funds-bearing deploy/anchor run OUTSIDE the binary
//! (the owner's `forge`/`cast`), and the keyless read-only dry-run runs as a bounded
//! `curl`/`cast` — exactly the W2-C split (the network legs live outside the binary).
//! `CustodyCapability` stays uninhabited (PD-6); this module names no custody symbol.
//!
//! ## the byte surface (cross-language LOCKED — `chain/golden/anchor_golden.py`)
//! `anchorPattern(bytes32 patternHash, uint256 expertId, bytes attestation)`
//! * selector = `keccak256("anchorPattern(bytes32,uint256,bytes)")[..4]` = `0x92e3e599`
//!   — derived independently by Python `pycryptodome` (golden) + the `solc` compiler
//!   (`chain/test/PatternRegistry.t.sol`); the Rust encoder below reproduces the full
//!   calldata byte-for-byte (the third leg of the lock; asserted in tests).
//! * the patternHash is the sha256 of a frozen, `sui move build`-verified Move artifact
//!   (`chain/fixtures/verified_pattern`); passing the compiler oracle is what makes it
//!   "oracle-verified" (master plan §6). Reproducibility is `include_bytes!`-checked.
//!
//! Honest scope: anchoring proves PROVENANCE (the owner anchored this hash at an L1
//! slot), NOT that the pattern is per-user-correct — the aggregate/provenance boundary.

use crate::provider::web3_rpc::{SafeRpcUrl, Web3Denied, classify_rpc_endpoint};

/// The `anchorPattern(bytes32,uint256,bytes)` selector — `keccak256(sig)[..4]`. LOCKED
/// and cross-checked three ways (Python golden, `solc`, and the encoder tests below).
pub const ANCHOR_SELECTOR: [u8; 4] = [0x92, 0xe3, 0xe5, 0x99];

/// The canonical type signature whose `keccak256` prefix is [`ANCHOR_SELECTOR`].
pub const ANCHOR_SIGNATURE: &str = "anchorPattern(bytes32,uint256,bytes)";

/// The LOCKED W2-D pattern hash: sha256 of the frozen, `sui move build`-verified Move
/// artifact `chain/fixtures/verified_pattern/sources/verified_pattern.move`. The
/// compiler-oracle PASS is the verdict that makes it an "oracle-verified pattern".
/// Reproducibility from the on-disk source is `include_bytes!`-asserted in the tests.
pub const W2D_PATTERN_HASH: [u8; 32] = [
    0x33, 0x2a, 0x98, 0xdb, 0x38, 0x83, 0xf9, 0x41, 0x61, 0xe2, 0xf8, 0x8a, 0x71, 0x4f, 0x9a, 0xbf,
    0xcd, 0x30, 0x68, 0x88, 0xad, 0xeb, 0x73, 0x03, 0x0b, 0x62, 0xd8, 0xc6, 0x88, 0x84, 0x97, 0x1a,
];

/// The seam-locked expert id for the first anchor: `0` = generalist / unassigned (no
/// per-expert routing until W3).
pub const W2D_EXPERT_ID: u64 = 0;

/// The seam-locked provenance attestation bytes (an honest on-chain tag naming the
/// oracle + verdict). 31 bytes.
pub const W2D_ATTESTATION: &[u8] = b"code_oracle:sui_move_build:pass";

/// The 0G Galileo testnet EVM RPC (chain 16602). Reuses the single source already in
/// [`crate::zerog_storage`] — one const for the whole 0G integration.
pub const ZEROG_TESTNET_EVM_RPC: &str = crate::zerog_storage::ZEROG_TESTNET_EVM_RPC;

/// A big-endian uint256 from a `u64` (the high 24 bytes are zero). Expert ids + byte
/// lengths are small; the EVM word is 32 bytes.
#[must_use]
fn u256_from_u64(x: u64) -> [u8; 32] {
    let mut word = [0u8; 32];
    word[24..].copy_from_slice(&x.to_be_bytes());
    word
}

/// Lowercase hex of `bytes` (no `0x` prefix). Pure; for renders + request bodies.
#[must_use]
pub fn hex_encode(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

/// ABI-encode the calldata for `anchorPattern(bytes32,uint256,bytes)` — PURE Solidity
/// head/tail layout: `selector(4) ‖ patternHash(32) ‖ expertId:uint256(32) ‖
/// offset=0x60(32) ‖ attestation.len:uint256(32) ‖ attestation right-padded to 32`.
/// Byte-identical to the Python + `solc` goldens (`chain/golden`, `chain/test`).
#[must_use]
pub fn encode_anchor_calldata(
    pattern_hash: &[u8; 32],
    expert_id: u64,
    attestation: &[u8],
) -> Vec<u8> {
    let pad = (32 - (attestation.len() % 32)) % 32;
    let mut out = Vec::with_capacity(4 + 32 * 4 + attestation.len() + pad);
    out.extend_from_slice(&ANCHOR_SELECTOR);
    out.extend_from_slice(pattern_hash); // bytes32 head slot
    out.extend_from_slice(&u256_from_u64(expert_id)); // uint256 head slot
    out.extend_from_slice(&u256_from_u64(0x60)); // offset to the bytes tail (3 * 32)
    out.extend_from_slice(&u256_from_u64(attestation.len() as u64)); // bytes length slot
    out.extend_from_slice(attestation);
    out.resize(out.len() + pad, 0u8); // right-pad the dynamic bytes to a 32-byte multiple
    out
}

/// The locked W2-D anchor calldata (the encoder applied to the seam-locked inputs).
#[must_use]
pub fn w2d_anchor_calldata() -> Vec<u8> {
    encode_anchor_calldata(&W2D_PATTERN_HASH, W2D_EXPERT_ID, W2D_ATTESTATION)
}

/// SSRF-wall the 0G Galileo RPC const through the SAME classifier the web3 reader uses
/// (https-only · no IP literal · no localhost · no userinfo). Construction proves the
/// endpoint passed the wall. This module never *dials* — the wall just guards the
/// endpoint we hand to the owner's `curl`/`cast`.
///
/// # Errors
/// Returns [`Web3Denied`] if the const ever fails the SSRF wall (it does not today).
pub fn galileo_rpc_safe() -> Result<SafeRpcUrl, Web3Denied> {
    classify_rpc_endpoint(ZEROG_TESTNET_EVM_RPC)
}

/// A minimal JSON-RPC 2.0 request body (id=1). PURE — the owner/agent POSTs it with a
/// bounded keyless `curl`; this builder never sends. `params_json` must be a JSON array.
#[must_use]
pub fn jsonrpc_body(method: &str, params_json: &str) -> String {
    let params = if params_json.trim().is_empty() {
        "[]"
    } else {
        params_json
    };
    format!("{{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"{method}\",\"params\":{params}}}")
}

/// The read-only `eth_estimateGas` params for a contract CREATION (deploy) — `[{"data":
/// "0x<creation_bytecode>"}]`. NO `to`, NO `from`, NO key: a pure gas SIMULATION (no
/// state change, no tx). Returns `None` if `creation_bytecode` is not `0x`-prefixed hex
/// (fail-closed — never a guessed body).
#[must_use]
pub fn estimate_deploy_gas_params(creation_bytecode: &str) -> Option<String> {
    let body = creation_bytecode.strip_prefix("0x")?;
    if body.is_empty() || body.len() % 2 != 0 || !body.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    Some(format!("[{{\"data\":\"0x{body}\"}}]"))
}

/// The full keyless read-only dry-run body for the deploy gas estimate (None if the
/// bytecode is not hex). The owner/agent POSTs this to [`ZEROG_TESTNET_EVM_RPC`].
#[must_use]
pub fn estimate_deploy_gas_request(creation_bytecode: &str) -> Option<String> {
    Some(jsonrpc_body(
        "eth_estimateGas",
        &estimate_deploy_gas_params(creation_bytecode)?,
    ))
}

/// Build the OWNER-runbook lines for the W2-D anchor (PURE — only strings). The agent
/// emits these; the OWNER runs the funds-bearing deploy/anchor with their own testnet
/// key. `registry_addr` fills the post-deploy commands; `None` ⇒ a `<REGISTRY_ADDR>`
/// placeholder the owner substitutes after deploying.
#[must_use]
pub fn anchor_bundle_lines(registry_addr: Option<&str>) -> Vec<String> {
    let calldata = hex_encode(&w2d_anchor_calldata());
    let pattern_hex = hex_encode(&W2D_PATTERN_HASH);
    let attest_hex = hex_encode(W2D_ATTESTATION);
    let endpoint_ok = galileo_rpc_safe().is_ok();
    let addr = registry_addr.unwrap_or("<REGISTRY_ADDR>");
    vec![
        "0G chain anchor PREPARE (W2-D) — agent PREPARES, owner FIRES (PD-6 funds-lock)"
            .to_string(),
        format!("  patternHash : 0x{pattern_hex}"),
        "                (sha256 of code_oracle-verified verified_pattern.move)".to_string(),
        format!("  expertId    : {W2D_EXPERT_ID} (generalist)"),
        format!(
            "  attestation : {} (0x{attest_hex}, {}B)",
            String::from_utf8_lossy(W2D_ATTESTATION),
            W2D_ATTESTATION.len()
        ),
        format!(
            "  selector    : 0x{} ({ANCHOR_SIGNATURE})",
            hex_encode(&ANCHOR_SELECTOR)
        ),
        format!(
            "  calldata    : 0x{calldata} ({} bytes)",
            w2d_anchor_calldata().len()
        ),
        format!(
            "  endpoint    : {ZEROG_TESTNET_EVM_RPC} (SSRF wall: {})",
            if endpoint_ok { "ok" } else { "DENIED" }
        ),
        String::new(),
        "  owner deploy (FUNDS — the owner runs this, never the agent):".to_string(),
        "    cd chain && forge install foundry-rs/forge-std   # once".to_string(),
        format!("    forge script script/Deploy.s.sol:Deploy --rpc-url {ZEROG_TESTNET_EVM_RPC} \\"),
        "      --private-key $OG_TESTNET_PRIVATE_KEY --broadcast".to_string(),
        String::new(),
        "  owner anchor (FUNDS — typed form):".to_string(),
        format!("    cast send {addr} \"anchorPattern(bytes32,uint256,bytes)\" \\"),
        format!("      0x{pattern_hex} {W2D_EXPERT_ID} 0x{attest_hex} \\"),
        format!("      --rpc-url {ZEROG_TESTNET_EVM_RPC} --private-key $OG_TESTNET_PRIVATE_KEY"),
        String::new(),
        "  keyless read-only dry-run (NO key — agent or owner; bounded):".to_string(),
        format!("    curl --max-time 12 -s -X POST {ZEROG_TESTNET_EVM_RPC} \\"),
        format!(
            "      -H 'Content-Type: application/json' -d '{}'",
            jsonrpc_body("eth_chainId", "[]")
        ),
        String::new(),
        "  verify after anchor (keyless read):".to_string(),
        format!(
            "    cast call {addr} \"anchored(bytes32)(bool)\" 0x{pattern_hex} --rpc-url {ZEROG_TESTNET_EVM_RPC}"
        ),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;
    use sha2::{Digest, Sha256};

    /// The 164-byte golden calldata — the independent Python (`chain/golden`) + `solc`
    /// (`chain/test`) derivation. The Rust encoder must reproduce it byte-for-byte.
    const GOLDEN_CALLDATA_HEX: &str = concat!(
        "92e3e599",
        "332a98db3883f94161e2f88a714f9abfcd306888adeb73030b62d8c68884971a",
        "0000000000000000000000000000000000000000000000000000000000000000",
        "0000000000000000000000000000000000000000000000000000000000000060",
        "000000000000000000000000000000000000000000000000000000000000001f",
        "636f64655f6f7261636c653a7375695f6d6f76655f6275696c643a7061737300",
    );

    #[test]
    fn selector_matches_golden_prefix() {
        // the locked selector == the first 4 bytes of the cross-language golden.
        assert_eq!(hex_encode(&ANCHOR_SELECTOR), "92e3e599");
        assert!(GOLDEN_CALLDATA_HEX.starts_with(&hex_encode(&ANCHOR_SELECTOR)));
    }

    #[test]
    fn pattern_hash_reproducible_from_verified_artifact() {
        // the Rust encoder's patternHash == sha256 of the on-disk, sui-move-build-
        // verified Move source (include_bytes binds the const to the real artifact).
        let artifact = include_bytes!(
            "../../../chain/fixtures/verified_pattern/sources/verified_pattern.move"
        );
        let digest: [u8; 32] = Sha256::digest(artifact).into();
        assert_eq!(
            digest, W2D_PATTERN_HASH,
            "patternHash drifted from the artifact"
        );
    }

    #[test]
    fn encoder_reproduces_the_cross_language_golden() {
        // Rust encoder ⟂ Python ⟂ solc: the locked W2-D calldata is byte-identical.
        assert_eq!(hex_encode(&w2d_anchor_calldata()), GOLDEN_CALLDATA_HEX);
    }

    #[test]
    fn encoder_layout_is_correct_for_arbitrary_inputs() {
        // empty attestation ⇒ 4 + 32*4 = 132 bytes (one zero length slot, no data).
        let cd = encode_anchor_calldata(&[0xAB; 32], 1, b"");
        assert_eq!(cd.len(), 132);
        assert_eq!(&cd[0..4], &ANCHOR_SELECTOR);
        assert_eq!(&cd[4..36], &[0xAB; 32]); // patternHash
        assert_eq!(cd[67], 1); // expertId low byte (slot 1 = bytes 36..68)
        assert_eq!(cd[99], 0x60); // offset low byte (slot 2 = bytes 68..100)
        assert_eq!(cd[131], 0); // length slot (bytes 100..132) low byte = 0 (empty bytes)
        // a 33-byte attestation pads to 64 ⇒ 132 + 64 = 196 bytes.
        let cd2 = encode_anchor_calldata(&[0; 32], 0, &[0x11; 33]);
        assert_eq!(cd2.len(), 196);
        assert_eq!(cd2[100 + 31], 33); // length slot low byte = 33
    }

    #[test]
    fn galileo_endpoint_passes_the_ssrf_wall() {
        let safe = galileo_rpc_safe().expect("0G testnet RPC must pass the SSRF wall");
        assert_eq!(safe.host(), "evmrpc-testnet.0g.ai");
        assert!(safe.url().starts_with("https://"));
    }

    #[test]
    fn deploy_gas_params_are_fail_closed() {
        // valid 0x-hex bytecode ⇒ an eth_estimateGas {data:...} params, no `to`/key.
        let p = estimate_deploy_gas_params("0xdeadbeef").expect("hex");
        assert_eq!(p, "[{\"data\":\"0xdeadbeef\"}]");
        let body = estimate_deploy_gas_request("0xdeadbeef").expect("hex");
        assert!(body.contains("\"method\":\"eth_estimateGas\""));
        assert!(!body.contains("\"to\"")); // a CREATION estimate has no `to`
        // fail-closed on non-hex / odd-length / missing 0x / empty.
        assert!(estimate_deploy_gas_params("deadbeef").is_none());
        assert!(estimate_deploy_gas_params("0xxyz").is_none());
        assert!(estimate_deploy_gas_params("0xabc").is_none());
        assert!(estimate_deploy_gas_params("0x").is_none());
    }

    #[test]
    fn jsonrpc_body_is_read_only_shape() {
        let b = jsonrpc_body("eth_chainId", "[]");
        assert_eq!(
            b,
            "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"eth_chainId\",\"params\":[]}"
        );
        // empty params normalizes to [].
        assert!(jsonrpc_body("eth_gasPrice", "").contains("\"params\":[]"));
    }

    #[test]
    fn anchor_bundle_is_owner_run_and_funds_safe() {
        let lines = anchor_bundle_lines(None);
        let blob = lines.join("\n");
        // the locked surface is present.
        assert!(blob.contains("0x92e3e599"));
        assert!(blob.contains(&format!("0x{}", hex_encode(&W2D_PATTERN_HASH))));
        assert!(blob.contains("164 bytes"));
        assert!(blob.contains("<REGISTRY_ADDR>")); // no addr yet ⇒ placeholder
        // it is honestly OWNER-run + funds-safe: no private key VALUE, only an env ref.
        assert!(blob.contains("agent PREPARES, owner FIRES"));
        assert!(blob.contains("$OG_TESTNET_PRIVATE_KEY")); // an env REFERENCE, never a value
        assert!(blob.contains("keyless read-only dry-run"));
        // a deployed addr fills the post-deploy commands.
        let filled =
            anchor_bundle_lines(Some("0xabc0000000000000000000000000000000000def")).join("\n");
        assert!(filled.contains("0xabc0000000000000000000000000000000000def"));
        assert!(!filled.contains("<REGISTRY_ADDR>"));
    }
}
