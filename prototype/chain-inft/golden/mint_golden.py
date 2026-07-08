#!/usr/bin/env python3
"""W3 0G iNFT mint — cross-language GOLDEN (the independent reference).

Independent derivation of the on-wire calldata for the 0G AgentNFT mint that the
Rust encoder (`crates/mnemos-cli/src/zerog_inft.rs`) and the Solidity test
(`chain-inft/test/SinabroExpertMint.t.sol`) must both reproduce — a three-way
cross-language lock (Python `pycryptodome` keccak  ⟂  Rust  ⟂  the `solc` compiler),
per the project's cross-language-schema-lock law.

Pins the REAL, compiled mint surface of `0gfoundation/0g-agent-nft` @ main b86e108a:

    mint(IntelligentData[] iDatas, address to)   where
    struct IntelligentData { string dataDescription; bytes32 dataHash; }

NOT the stale `mint(bytes[] proofs, string[] dataDescriptions, address)` (that
signature does not exist on this branch — STEP-0 grounding falsified it).

SELF-CHECKING: re-derives every locked constant and asserts; writes the golden
calldata to `golden/mint_calldata.hex` (machine-written, so no hand-transcription of
the 324-byte value anywhere) and re-reads it to confirm the round-trip. A mismatch
exits non-zero, never a silent pass.

Run:  python3 chain-inft/golden/mint_golden.py
Pass: prints the golden + "GOLDEN OK", writes golden/mint_calldata.hex, exits 0.
"""

import sys
from pathlib import Path

try:
    from Crypto.Hash import keccak  # pycryptodome — true Ethereum Keccak-256
except ImportError:  # pragma: no cover - environment guard
    sys.stderr.write(
        "FATAL: pycryptodome not available (need `from Crypto.Hash import keccak`).\n"
    )
    sys.exit(2)


def keccak256(data: bytes) -> bytes:
    h = keccak.new(digest_bits=256)
    h.update(data)
    return h.digest()


# ---------------------------------------------------------------------------
# 0. keccak self-test — proves this keccak IS Ethereum Keccak-256 (not NIST
#    SHA3-256). Known vector: keccak256("").
# ---------------------------------------------------------------------------
KECCAK_EMPTY = "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470"
assert keccak256(b"").hex() == KECCAK_EMPTY, "keccak256 is not Ethereum Keccak-256"

# ---------------------------------------------------------------------------
# 1. selectors — keccak256(canonical_sig)[:4]. The struct encodes as the tuple
#    (string,bytes32); an array of it is (string,bytes32)[]. LOCKED.
# ---------------------------------------------------------------------------
MINT_SIG = b"mint((string,bytes32)[],address)"
MINT_SELECTOR = keccak256(MINT_SIG)[:4]
assert MINT_SELECTOR.hex() == "a3acac17", f"mint selector drift: {MINT_SELECTOR.hex()}"

READ_SIG = b"intelligentDatasOf(uint256)"
READ_SELECTOR = keccak256(READ_SIG)[:4]
assert READ_SELECTOR.hex() == "40fbd72f", f"read selector drift: {READ_SELECTOR.hex()}"

# ---------------------------------------------------------------------------
# 2. the seam-locked IntelligentData (owner 2026-06-24).
#    dataHash = the W2-D oracle-verified patternHash (anchored on Galileo testnet,
#    PatternRegistry 0xDe662d…0C73). dataDescription = the provenance descriptor.
# ---------------------------------------------------------------------------
PATTERN_HASH = bytes.fromhex(
    "332a98db3883f94161e2f88a714f9abfcd306888adeb73030b62d8c68884971a"
)
DESCRIPTOR = b"sinabro-expert:generalist; oracle=code_oracle:sui_move_build:pass"
assert len(PATTERN_HASH) == 32, "patternHash must be bytes32"
assert len(DESCRIPTOR) == 65, f"descriptor length drift: {len(DESCRIPTOR)}"

# the golden recipient — a documented PLACEHOLDER test vector (0xdEaD). The real mint
# substitutes the owner's fresh testnet address at fire time; the encoder is correct
# for ANY `to`, and this vector locks the encoding shape.
RECIPIENT = 0x000000000000000000000000000000000000DEAD

# ---------------------------------------------------------------------------
# 3. the ABI encoder for mint((string,bytes32)[],address). Solidity head/tail:
#    head   = [ offset->iDatas (=0x40), to ]
#    iDatas = [ len (=1), offset->elem0 (=0x20), elem0 ]              (dynamic array)
#    elem0  = [ offset->string (=0x40), dataHash, string.len, string.data padded ]
#             (a dynamic tuple, because it contains a dynamic string)
# ---------------------------------------------------------------------------
def u256(x: int) -> bytes:
    if x < 0 or x >= (1 << 256):
        raise ValueError("uint256 out of range")
    return x.to_bytes(32, "big")


def pad32(b: bytes) -> bytes:
    return b + b"\x00" * ((-len(b)) % 32)


def encode_mint(descriptor: bytes, data_hash: bytes, to: int) -> bytes:
    assert len(data_hash) == 32
    head = u256(0x40) + u256(to)
    elem0 = u256(0x40) + data_hash + u256(len(descriptor)) + pad32(descriptor)
    arr = u256(1) + u256(0x20) + elem0
    return MINT_SELECTOR + head + arr


CALLDATA = encode_mint(DESCRIPTOR, PATTERN_HASH, RECIPIENT)
assert len(CALLDATA) == 324, f"calldata length drift: {len(CALLDATA)}"

# ---------------------------------------------------------------------------
# 4. write the machine-generated golden file (the shared cross-language reference;
#    each language RE-DERIVES its own bytes and asserts equality to this file — no
#    hand-transcription of the 324-byte value). No trailing newline (so the Foundry
#    `vm.parseBytes(vm.readFile(...))` parses cleanly).
# ---------------------------------------------------------------------------
GOLDEN_PATH = Path(__file__).resolve().parent / "mint_calldata.hex"
GOLDEN_TEXT = "0x" + CALLDATA.hex()
GOLDEN_PATH.write_text(GOLDEN_TEXT)
_reread = GOLDEN_PATH.read_text()
assert _reread == GOLDEN_TEXT and bytes.fromhex(_reread[2:]) == CALLDATA, (
    "golden file round-trip mismatch"
)


def main() -> int:
    print("== W3 0G iNFT mint — GOLDEN ==")
    print(f'keccak self-test (keccak256 "")   : PASS ({KECCAK_EMPTY[:16]}...)')
    print(f"mint signature                    : {MINT_SIG.decode()}")
    print(f"mint selector                     : 0x{MINT_SELECTOR.hex()}")
    print(f"intelligentDatasOf selector       : 0x{READ_SELECTOR.hex()}")
    print(f"dataHash (W2-D patternHash)       : 0x{PATTERN_HASH.hex()}")
    print(f"descriptor ({len(DESCRIPTOR)}B)                  : {DESCRIPTOR.decode()}")
    print(f"recipient (placeholder vector)    : 0x{RECIPIENT:040x}")
    print(f"calldata ({len(CALLDATA)} bytes)              :")
    print(f"  0x{CALLDATA.hex()}")
    print(f"golden written                    : {GOLDEN_PATH.name}")
    print("GOLDEN OK")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
