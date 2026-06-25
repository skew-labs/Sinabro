// SPDX-License-Identifier: MIT
pragma solidity 0.8.19;

/// @title  PatternRegistry — sinabro × 0G Buildathon (W2-D)
/// @notice Anchors the provenance of an oracle-verified pattern on 0G Galileo
///         testnet (chain 16602). `anchorPattern` records that the contract owner
///         anchored a specific `patternHash` (the sha256 of a compiler-oracle-
///         verified artifact) at a given L1 slot, and emits an indexed event.
/// @dev    Honest scope: anchoring proves PROVENANCE (the owner committed this hash
///         on-chain), NOT that the underlying pattern is per-user-correct. That
///         aggregate/provenance boundary is the same one the master plan §6 draws.
///
///         Minimal + self-contained: an immutable owner set in the constructor (no
///         OpenZeppelin dependency to vendor), a `mapping(bytes32 => bool)`
///         duplicate-guard, custom errors (cheap reverts), and one indexed event.
///         solc 0.8.19 + evm_version=cancun (per 0G docs; 0.8.26 is flagged risky).
contract PatternRegistry {
    /// @notice The deployer — the only address allowed to anchor. Immutable: set
    ///         once in the constructor, never re-assignable (no transfer in v1).
    address public immutable owner;

    /// @notice Whether a given pattern hash has already been anchored (dup-guard).
    mapping(bytes32 => bool) public anchored;

    /// @notice Emitted once per newly anchored pattern. Three indexed topics (the
    ///         max) make patternHash / expertId / anchorer all filterable; the
    ///         attestation rides in data.
    /// @param patternHash sha256 of the oracle-verified artifact (bytes32 commitment).
    /// @param expertId    the expert this pattern belongs to (0 = generalist in v1).
    /// @param anchorer    msg.sender (== owner).
    /// @param attestation free-form provenance bytes (e.g. the oracle id + verdict).
    event PatternAnchored(
        bytes32 indexed patternHash,
        uint256 indexed expertId,
        address indexed anchorer,
        bytes attestation
    );

    /// @notice Caller is not the registry owner.
    error NotOwner();
    /// @notice This patternHash has already been anchored (re-anchor refused).
    error AlreadyAnchored();

    constructor() {
        owner = msg.sender;
    }

    /// @notice Anchor one oracle-verified pattern hash. Owner-only; reverts on a
    ///         duplicate so each hash is anchored at most once. Selector 0x92e3e599.
    /// @param patternHash the bytes32 commitment to anchor.
    /// @param expertId    the owning expert id (0 = generalist).
    /// @param attestation provenance bytes recorded in the event.
    function anchorPattern(
        bytes32 patternHash,
        uint256 expertId,
        bytes calldata attestation
    ) external {
        if (msg.sender != owner) revert NotOwner();
        if (anchored[patternHash]) revert AlreadyAnchored();
        anchored[patternHash] = true;
        emit PatternAnchored(patternHash, expertId, msg.sender, attestation);
    }
}
