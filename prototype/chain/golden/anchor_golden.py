#!/usr/bin/env python3
"""W2-D 0G chain anchor — cross-language GOLDEN (the independent reference).

This is the *independent* derivation of the on-wire byte surface that the Rust
encoder (`crates/mnemos-cli/src/zerog_chain.rs`) and the Solidity contract
(`chain/src/PatternRegistry.sol`) must both match — a three-way cross-language
lock (Python `pycryptodome` keccak  ⟂  Rust `sha3::Keccak256`  ⟂  the `solc`
compiler's own selector), per the project's cross-language-schema-lock law.

It is SELF-CHECKING: every locked constant is re-derived and asserted here, so
running this file is a falsifiable gate (a mismatch exits non-zero, never a
silent pass). It also re-hashes the frozen, compiler-oracle-verified Move
artifact to prove the patternHash is reproducible from the source on disk.

Run:  python3 chain/golden/anchor_golden.py
Pass: prints the golden calldata + "GOLDEN OK" and exits 0.
"""

import hashlib
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
#    SHA3-256, which has different padding). Known vector: keccak256("").
# ---------------------------------------------------------------------------
KECCAK_EMPTY = "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470"
assert keccak256(b"").hex() == KECCAK_EMPTY, "keccak256 is not Ethereum Keccak-256"

# ---------------------------------------------------------------------------
# 1. function selector — keccak256(canonical_sig)[:4]. LOCKED.
# ---------------------------------------------------------------------------
CANONICAL_SIG = b"anchorPattern(bytes32,uint256,bytes)"
SELECTOR = keccak256(CANONICAL_SIG)[:4]
SELECTOR_LOCKED = bytes.fromhex("92e3e599")
assert SELECTOR == SELECTOR_LOCKED, f"selector drift: {SELECTOR.hex()} != 92e3e599"

# ---------------------------------------------------------------------------
# 2. patternHash — sha256 of the frozen, `sui move build`-verified Move
#    artifact. LOCKED + reproduced from the source file on disk.
# ---------------------------------------------------------------------------
PATTERN_HASH_LOCKED = bytes.fromhex(
    "332a98db3883f94161e2f88a714f9abfcd306888adeb73030b62d8c68884971a"
)
_ARTIFACT = (
    Path(__file__).resolve().parent.parent
    / "fixtures"
    / "verified_pattern"
    / "sources"
    / "verified_pattern.move"
)
if _ARTIFACT.is_file():
    reproduced = hashlib.sha256(_ARTIFACT.read_bytes()).digest()
    assert reproduced == PATTERN_HASH_LOCKED, (
        f"patternHash not reproducible from {_ARTIFACT}: "
        f"{reproduced.hex()} != {PATTERN_HASH_LOCKED.hex()}"
    )
    ARTIFACT_NOTE = f"re-hashed from {_ARTIFACT.name} (reproducible)"
else:  # pragma: no cover - fixture should be present in-tree
    ARTIFACT_NOTE = "fixture not found at runtime; using LOCKED constant"

# ---------------------------------------------------------------------------
# 3. the locked anchor inputs (seam-locked with the owner 2026-06-24).
# ---------------------------------------------------------------------------
EXPERT_ID = 0  # generalist / unassigned — no per-expert routing until W3
ATTESTATION = b"code_oracle:sui_move_build:pass"  # honest on-chain provenance tag


# ---------------------------------------------------------------------------
# 4. the ABI encoder for `anchorPattern(bytes32,uint256,bytes)`. Solidity ABI
#    head/tail: 3 head slots (bytes32 value, uint256 value, offset-to-bytes=96),
#    then the dynamic `bytes` tail (length slot + right-padded data).
# ---------------------------------------------------------------------------
def u256(x: int) -> bytes:
    if x < 0 or x >= (1 << 256):
        raise ValueError("uint256 out of range")
    return x.to_bytes(32, "big")


def pad32(b: bytes) -> bytes:
    return b + b"\x00" * ((-len(b)) % 32)


def encode_anchor(pattern_hash: bytes, expert_id: int, attestation: bytes) -> bytes:
    assert len(pattern_hash) == 32, "patternHash must be 32 bytes (bytes32)"
    head = pattern_hash + u256(expert_id) + u256(0x60)  # bytes offset = 3*32 = 96
    tail = u256(len(attestation)) + pad32(attestation)
    return SELECTOR + head + tail


CALLDATA = encode_anchor(PATTERN_HASH_LOCKED, EXPERT_ID, ATTESTATION)

# the LOCKED golden calldata (the Rust encoder must reproduce this byte-for-byte).
CALLDATA_LOCKED_HEX = (
    "92e3e599"
    "332a98db3883f94161e2f88a714f9abfcd306888adeb73030b62d8c68884971a"
    "0000000000000000000000000000000000000000000000000000000000000000"
    "0000000000000000000000000000000000000000000000000000000000000060"
    "000000000000000000000000000000000000000000000000000000000000001f"
    "636f64655f6f7261636c653a7375695f6d6f76655f6275696c643a7061737300"
)
assert CALLDATA.hex() == CALLDATA_LOCKED_HEX, (
    f"calldata drift:\n  got  {CALLDATA.hex()}\n  want {CALLDATA_LOCKED_HEX}"
)


def main() -> int:
    print("== W2-D 0G chain anchor — GOLDEN ==")
    print(f"keccak self-test (keccak256 \"\")  : PASS ({KECCAK_EMPTY[:16]}...)")
    print(f"canonical sig                     : {CANONICAL_SIG.decode()}")
    print(f"selector                          : 0x{SELECTOR.hex()}")
    print(f"patternHash (bytes32)             : 0x{PATTERN_HASH_LOCKED.hex()}")
    print(f"  source                          : {ARTIFACT_NOTE}")
    print(f"expertId (uint256)                : {EXPERT_ID}")
    print(f"attestation ({len(ATTESTATION)}B)               : {ATTESTATION!r}")
    print(f"calldata ({len(CALLDATA)} bytes)              :")
    print(f"  0x{CALLDATA.hex()}")
    print("GOLDEN OK")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
