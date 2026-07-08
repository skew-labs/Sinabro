#!/usr/bin/env bash
# OWNER-RUN one-shot: deploy PatternRegistry to 0G Galileo testnet, anchor the W2-D
# pattern, and verify — in a single command.
#
# The agent PREPARES this script; the OWNER runs it with a FUNDED testnet key in the
# env (PD-6: the agent holds no key, signs nothing). The deployer becomes the
# contract's IMMUTABLE owner — so this MUST run from YOUR key, or you can't anchor
# (anchorPattern is onlyOwner).
#
#   # 1. a deployer key (keep it yourself — never paste it in chat):
#   cast wallet new                       # prints an Address + Private key
#   # 2. fund that Address at https://faucet.0g.ai  (0.1 0G/day, a web step)
#   # 3. run this (key via env, never on the command line history):
#   export OG_TESTNET_PRIVATE_KEY=0x...   # the funded key from step 1
#   bash deploy_and_anchor.sh
set -euo pipefail
export PATH="$HOME/.foundry/bin:$PATH"
cd "$(dirname "$0")"

RPC="https://evmrpc-testnet.0g.ai"
# the locked W2-D anchor inputs (see golden/anchor_golden.py + README.md):
PATTERN="0x332a98db3883f94161e2f88a714f9abfcd306888adeb73030b62d8c68884971a"
EXPERT_ID=0
ATTEST="0x636f64655f6f7261636c653a7375695f6d6f76655f6275696c643a70617373"

: "${OG_TESTNET_PRIVATE_KEY:?set OG_TESTNET_PRIVATE_KEY (a FUNDED testnet key) first — see the header}"
[ -d lib/forge-std ] || forge install foundry-rs/forge-std

DEPLOYER=$(cast wallet address --private-key "$OG_TESTNET_PRIVATE_KEY")
BAL=$(cast balance --rpc-url "$RPC" "$DEPLOYER")
echo "deployer : $DEPLOYER"
echo "balance  : $BAL wei"
if [ "$BAL" = "0" ]; then
  echo "  -> 0 balance. Fund $DEPLOYER at https://faucet.0g.ai then re-run." >&2
  exit 1
fi

echo "=== 1/3 deploy PatternRegistry ==="
OUT=$(forge create src/PatternRegistry.sol:PatternRegistry \
  --rpc-url "$RPC" --private-key "$OG_TESTNET_PRIVATE_KEY" --broadcast --json)
ADDR=$(printf '%s' "$OUT" | python3 -c 'import sys,json;print(json.load(sys.stdin)["deployedTo"])')
echo "REGISTRY_ADDR=$ADDR"

echo "=== 2/3 anchor the W2-D pattern (anchorPattern) ==="
cast send "$ADDR" "anchorPattern(bytes32,uint256,bytes)" "$PATTERN" "$EXPERT_ID" "$ATTEST" \
  --rpc-url "$RPC" --private-key "$OG_TESTNET_PRIVATE_KEY"

echo "=== 3/3 verify (keyless reads) ==="
echo "anchored($PATTERN) = $(cast call "$ADDR" "anchored(bytes32)(bool)" "$PATTERN" --rpc-url "$RPC")"

echo ""
echo "DONE — W2-D closed on-chain."
echo "  contract : $ADDR"
echo "  explorer : https://chainscan-galileo.0g.ai/address/$ADDR"
echo "Paste REGISTRY_ADDR back to the agent for keyless on-chain verification."
