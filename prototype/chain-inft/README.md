# chain-inft — sinabro × 0G Buildathon W3 (ERC-7857 iNFT mint)

Mints **one ERC-7857 iNFT** on **0G Galileo testnet (16602)** that IS the "own the
intelligence" identity for the W2-D oracle-verified pattern: the iNFT's `dataHash` = the
anchored W2-D `patternHash` (`0x332a98db…971a`), its descriptor names the oracle. This is
the W3 differentiator — a 0G-native primitive (ERC-7857) no other chain has.

**Honest scope:** minting proves OWNED PROVENANCE (this identity points at an oracle-
verified pattern), NOT per-user correctness — the same aggregate boundary as W2-D.

## What this is (pinned to what COMPILES, not the docs)
The contract is the **real** `0gfoundation/0g-agent-nft` `AgentNFT` (`main` @ `b86e108a`) —
an **upgradeable** (OZ 5.0.2) contract deployed behind an `ERC1967Proxy`. STEP-0 grounding
falsified the stale `mint(bytes[],string[],address)` signature; the real surface is:

```solidity
struct IntelligentData { string dataDescription; bytes32 dataHash; }
function mint(IntelligentData[] iDatas, address to) payable returns (uint256 tokenId);   // 0xa3acac17
function intelligentDatasOf(uint256 tokenId) view returns (IntelligentData[]);            // 0x40fbd72f
```

`mint` does **NOT** call the verifier (that is the transfer-only `iTransferFrom` path,
deferred). `StubVerifier` exists only to satisfy `initialize`'s non-zero-verifier
requirement; it is never executed by mint. `iTransfer`/`iClone` secure transfer + the real
encrypted-adapter-on-0G-Storage binding are **deferred** (need a real TEE/ZKP oracle).

## Layout
- `src/0g/` — the vendored AgentNFT closure (AgentNFT, ERC7857Upgradeable, 3 extensions,
  Utils, interfaces; AgentMarket excluded). `src/StubVerifier.sol` — the minimal verifier.
- `test/SinabroExpertMint.t.sol` — hermetic: deploy → mint → `intelligentDatasOf` reads the
  patternHash back, + the cross-language byte lock (solc abi-encode == the golden).
- `golden/mint_golden.py` — the Python golden; writes + self-checks `golden/mint_calldata.hex`.
- `script/DeployAndMint.s.sol` — the OWNER-FIRED deploy + mint (slice D).
- `lib/` — vendored deps (forge-std 1.16.1, openzeppelin-contracts + -upgradeable v5.0.2),
  copied (mnemos is not a git repo), the same way `chain/lib/forge-std` is.

## The cross-language byte lock (3 independent encoders ⟂ one golden)
`golden/mint_calldata.hex` is the machine-written shared reference (324 bytes, no hand-
transcription). All three re-derive their own bytes and assert equality:
- **Python** (`golden/mint_golden.py`) writes + self-checks it (`keccak` self-test → selector
  `0xa3acac17` → ABI encode → round-trip).
- **solc** (`test/SinabroExpertMint.t.sol::test_CalldataMatchesGolden`) `vm.readFile`s it and
  asserts solc's own `abi.encode` equals it.
- **Rust** (`crates/mnemos-cli/src/zerog_inft.rs`) `include_str!`s it and asserts the encoder
  reproduces it.

## Run the hermetic tests (LOCAL, no network, no funds)
```bash
cd prototype/chain-inft
python3 golden/mint_golden.py      # regenerate + self-check the golden
forge test -vv                     # 4/4: lifecycle + byte lock
```

## Owner runbook — deploy + mint (FUNDS · testnet · agent never signs, PD-6)
The agent PREPARES (above); the **OWNER FIRES** with their own fresh testnet key. (The W2-D
key `0xa7dA3C56…` is BURNED — chat-exposed — generate a fresh one.)

```bash
# 0. fresh testnet key + fund it (faucet 0.1 0G/day; ~4.87M gas needed for deploy+mint)
cast wallet new                                    # → save the private key + address
#   fund the address at https://faucet.0g.ai

# 1. deploy (StubVerifier + AgentNFT impl + ERC1967Proxy+initialize) + mint, one shot
cd prototype/chain-inft
MINT_RECIPIENT=<your fresh address> \
forge script script/DeployAndMint.s.sol:DeployAndMint \
  --rpc-url https://evmrpc-testnet.0g.ai --broadcast \
  --private-key $OG_TESTNET_PRIVATE_KEY \
  --priority-gas-price 2000000000        # 0G min tip = 2 gwei (W2-D gas gotcha;
                                         # forge auto-estimate gives tip=1 = fail)
#   → logs: StubVerifier / AgentNFT impl / iNFT proxy addresses + minted tokenId

# 2. verify the bound pattern (KEYLESS read — anyone can run this)
cast call <iNFT proxy addr> "intelligentDatasOf(uint256)((string,bytes32)[])" <tokenId> \
  --rpc-url https://evmrpc-testnet.0g.ai
#   → [( "sinabro-expert:generalist; oracle=code_oracle:sui_move_build:pass",
#        0x332a98db…971a )]   ← the W2-D patternHash, bound to a transferable iNFT
```

Then view the iNFT proxy + the mint tx on `https://chainscan-galileo.0g.ai`.

**0G gas gotchas (from W2-D):** min priority fee = **2 gwei** + an explicit `--priority-gas-
price`; forge may false-negative "not deployed" on a slow confirm (verify via the tx hash /
`cast code <addr>`). **mainnet/real-funds are HARD-LOCKED** — this is testnet-only; the
`sinabro` binary holds no key (`CustodyCapability` uninhabited).
