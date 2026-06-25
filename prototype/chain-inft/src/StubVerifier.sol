// SPDX-License-Identifier: MIT
pragma solidity 0.8.20;

import {
    IERC7857DataVerifier,
    TransferValidityProof,
    TransferValidityProofOutput
} from "./0g/interfaces/IERC7857DataVerifier.sol";

/// @title  StubVerifier — minimal IERC7857DataVerifier for the mint-only W3 slice.
/// @notice `AgentNFT.initialize()` requires a non-zero verifier address, but the MINT
///         path never calls it. Grounded against the compiled contract (main @
///         b86e108a): `mint(IntelligentData[],address)` → `_safeMint` + `_updateData`
///         (store + emit `Updated`); the verifier (`verifyTransferValidity`) is invoked
///         ONLY by `iTransferFrom` (ERC7857Upgradeable.sol:95), the secure-transfer path
///         this W3 slice deliberately does NOT exercise (deferred — it needs a real
///         TEE/ZKP re-encryption oracle). So this is the smallest conforming verifier
///         that lets AgentNFT be initialized + minted on.
/// @dev    ★ HONEST SCOPE: this verifier verifies NOTHING. It exists solely to satisfy
///         the constructor invariant for a mint-only deployment. A real transfer would
///         need a genuine TEE/ZKP verifier swapped in via `AgentNFT.updateVerifier()`.
///         Never represent a StubVerifier-backed iNFT as transfer-secure.
contract StubVerifier is IERC7857DataVerifier {
    function verifyTransferValidity(
        TransferValidityProof[] calldata proofs
    ) external pure override returns (TransferValidityProofOutput[] memory) {
        // Unreachable from mint(); only an (out-of-scope) iTransferFrom would reach this.
        // Returns a default-shaped output of matching cardinality.
        return new TransferValidityProofOutput[](proofs.length);
    }
}
