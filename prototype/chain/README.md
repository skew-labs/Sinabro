# 0G Chain anchor — `PatternRegistry` (W2-D)

sinabro × 0G Buildathon, Wave-2 deliverable **W2-D**: anchor the provenance of one
**oracle-verified pattern** on **0G Galileo testnet** (chain `16602`).

> **Honest scope.** Anchoring proves **PROVENANCE** — the owner committed this exact
> hash on-chain at an L1 slot — **not** that the pattern is per-user-correct. Same
> aggregate/provenance boundary the master plan §6 draws.

> **Funds posture (PD-6).** The agent **PREPARES** (builds the calldata + a keyless
> read-only dry-run + these commands). The **OWNER FIRES** the deploy + anchor with their
> own testnet key. The agent never signs, deploys, or holds a key.

---

## What gets anchored

| field | value |
|---|---|
| **patternHash** (`bytes32`) | `0x332a98db3883f94161e2f88a714f9abfcd306888adeb73030b62d8c68884971a` |
| source | sha256 of `fixtures/verified_pattern/sources/verified_pattern.move`, which **passes `sui move build`** (sinabro's `code_oracle`, the deterministic compiler oracle) |
| **expertId** (`uint256`) | `0` (generalist / unassigned — per-expert routing is W3) |
| **attestation** (`bytes`) | `code_oracle:sui_move_build:pass` (`0x636f64655f6f7261636c653a7375695f6d6f76655f6275696c643a70617373`) |
| **selector** | `0x92e3e599` = `keccak256("anchorPattern(bytes32,uint256,bytes)")[:4]` |

The selector + the full 164-byte calldata are **cross-language locked** — derived
independently by Python (`golden/anchor_golden.py`, pycryptodome), the `solc` compiler
(`test/PatternRegistry.t.sol`), and the Rust encoder
(`../crates/mnemos-cli/src/zerog_chain.rs`); all three agree byte-for-byte.

**Full calldata (164 bytes):**
```
0x92e3e599332a98db3883f94161e2f88a714f9abfcd306888adeb73030b62d8c68884971a00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000060000000000000000000000000000000000000000000000000000000000000001f636f64655f6f7261636c653a7375695f6d6f76655f6275696c643a7061737300
```

---

## 0. Prereqs (one-time)

```bash
# Foundry (forge + cast)
curl -L https://foundry.paradigm.xyz | bash && foundryup
# forge-std (this repo gitignores lib/)
cd chain && forge install foundry-rs/forge-std
# a funded testnet signer: get 0G from the faucet, export the key OUT OF SHELL HISTORY
#   faucet:   https://faucet.0g.ai      (0.1 0G / day)
#   explorer: https://chainscan-galileo.0g.ai
export OG_TESTNET_PRIVATE_KEY=0x...        # your testnet key (never commit / paste in chat)
```

## 1. Build + test locally (no funds)

```bash
cd chain
forge test -vv        # 7/7 pass: deploy · anchor emits event · re-anchor reverts · selector/calldata == golden
python3 golden/anchor_golden.py   # prints + self-asserts the golden (selector + calldata)
```

## 2. Keyless read-only dry-run (no key — agent or owner)

```bash
# confirm the chain (Galileo = 0x40da = 16602)
curl --max-time 12 -s -X POST https://evmrpc-testnet.0g.ai \
  -H 'Content-Type: application/json' \
  -d '{"jsonrpc":"2.0","id":1,"method":"eth_chainId","params":[]}'
# => {"result":"0x40da"}

# estimate the deploy gas (no `to`, no key — a pure simulation)
BYTECODE=$(forge inspect PatternRegistry bytecode)
curl --max-time 15 -s -X POST https://evmrpc-testnet.0g.ai \
  -H 'Content-Type: application/json' \
  -d "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"eth_estimateGas\",\"params\":[{\"data\":\"$BYTECODE\"}]}"
# => {"result":"0x321ed"}   (~205,293 gas, observed 2026-06-24)
```

## 3. Deploy (FUNDS — owner runs)

```bash
cd chain
forge script script/Deploy.s.sol:Deploy \
  --rpc-url https://evmrpc-testnet.0g.ai \
  --private-key $OG_TESTNET_PRIVATE_KEY \
  --broadcast
# note the deployed address → REGISTRY_ADDR (the deployer is the immutable owner).
```

## 4. Anchor the pattern (FUNDS — owner runs)

```bash
REGISTRY_ADDR=0x...   # from step 3

# typed form (cast ABI-encodes — equals the locked calldata):
cast send $REGISTRY_ADDR "anchorPattern(bytes32,uint256,bytes)" \
  0x332a98db3883f94161e2f88a714f9abfcd306888adeb73030b62d8c68884971a \
  0 \
  0x636f64655f6f7261636c653a7375695f6d6f76655f6275696c643a70617373 \
  --rpc-url https://evmrpc-testnet.0g.ai \
  --private-key $OG_TESTNET_PRIVATE_KEY

# or raw calldata (byte-identical to the typed form above):
cast send $REGISTRY_ADDR \
  0x92e3e599332a98db3883f94161e2f88a714f9abfcd306888adeb73030b62d8c68884971a00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000060000000000000000000000000000000000000000000000000000000000000001f636f64655f6f7261636c653a7375695f6d6f76655f6275696c643a7061737300 \
  --rpc-url https://evmrpc-testnet.0g.ai \
  --private-key $OG_TESTNET_PRIVATE_KEY
```

## 5. Verify the anchor (keyless reads)

```bash
# the mapping flipped:
cast call $REGISTRY_ADDR "anchored(bytes32)(bool)" \
  0x332a98db3883f94161e2f88a714f9abfcd306888adeb73030b62d8c68884971a \
  --rpc-url https://evmrpc-testnet.0g.ai
# => true

# the PatternAnchored event: open the tx on https://chainscan-galileo.0g.ai
# topic0 = keccak256("PatternAnchored(bytes32,uint256,address,bytes)")
# topic1 = patternHash, topic2 = expertId (0), topic3 = anchorer (you)
```

A second `anchorPattern` of the same hash **reverts** `AlreadyAnchored` (one anchor / hash).

---

## Layout

```
chain/
  src/PatternRegistry.sol            the registry (immutable owner, mapping=>bool, event)
  test/PatternRegistry.t.sol         forge tests (lifecycle + selector/calldata == golden)
  script/Deploy.s.sol                owner deploy script
  golden/anchor_golden.py            Python golden (selector + calldata, self-asserting)
  fixtures/verified_pattern/         the sui-move-build-verified artifact (its sha256 = patternHash)
  foundry.toml                       solc 0.8.19, evm_version=cancun
```

The agent side (calldata encoder + keyless dry-run builder, all pure) lives in
`../crates/mnemos-cli/src/zerog_chain.rs`, surfaced as `sinabro memory anchor-0g`.
The proof that none of this can spend is `ops/evidence/stage_g/zerog_chain_w2d_grep.sh`.
