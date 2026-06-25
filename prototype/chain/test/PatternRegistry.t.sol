// SPDX-License-Identifier: MIT
pragma solidity 0.8.19;

import {Test} from "forge-std/Test.sol";
import {PatternRegistry} from "../src/PatternRegistry.sol";

/// @title PatternRegistry unit tests (LOCAL — no network, no funds).
/// @notice Proves the W2-D lifecycle hermetically: deploy → anchor emits the event +
///         sets the mapping → re-anchor reverts → non-owner reverts. Also pins the
///         cross-language byte lock: solc's own selector + abi-encoding MUST equal the
///         Python/Rust golden (the third independent derivation).
contract PatternRegistryTest is Test {
    PatternRegistry internal reg;
    address internal owner;
    address internal stranger = address(0xBEEF);

    // the locked W2-D anchor inputs (seam-locked 2026-06-24; see chain/golden/).
    bytes32 internal constant PATTERN =
        0x332a98db3883f94161e2f88a714f9abfcd306888adeb73030b62d8c68884971a;
    uint256 internal constant EXPERT_ID = 0;
    bytes internal constant ATTESTATION = "code_oracle:sui_move_build:pass";

    // mirror of the contract event for vm.expectEmit matching.
    event PatternAnchored(
        bytes32 indexed patternHash,
        uint256 indexed expertId,
        address indexed anchorer,
        bytes attestation
    );

    function setUp() public {
        owner = address(this); // the test contract deploys ⇒ it is the owner
        reg = new PatternRegistry();
    }

    function test_OwnerIsDeployer() public view {
        assertEq(reg.owner(), owner);
    }

    /// The cross-language lock: solc's own selector == the Python/Rust golden 0x92e3e599.
    function test_SelectorMatchesGolden() public pure {
        assertEq(PatternRegistry.anchorPattern.selector, bytes4(0x92e3e599));
    }

    /// The full calldata, encoded by solc's abi.encodeWithSelector, MUST equal the
    /// 164-byte golden produced independently by the Python encoder (chain/golden/) and
    /// the Rust encoder (zerog_chain.rs). Byte-for-byte cross-language schema lock.
    function test_CalldataMatchesGolden() public pure {
        bytes memory cd = abi.encodeWithSelector(
            PatternRegistry.anchorPattern.selector,
            PATTERN,
            EXPERT_ID,
            ATTESTATION
        );
        bytes
            memory golden = hex"92e3e599332a98db3883f94161e2f88a714f9abfcd306888adeb73030b62d8c68884971a00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000060000000000000000000000000000000000000000000000000000000000000001f636f64655f6f7261636c653a7375695f6d6f76655f6275696c643a7061737300";
        assertEq(cd, golden);
    }

    function test_AnchorEmitsEventAndSetsMapping() public {
        assertFalse(reg.anchored(PATTERN));
        vm.expectEmit(true, true, true, true);
        emit PatternAnchored(PATTERN, EXPERT_ID, owner, ATTESTATION);
        reg.anchorPattern(PATTERN, EXPERT_ID, ATTESTATION);
        assertTrue(reg.anchored(PATTERN));
    }

    function test_ReAnchorReverts() public {
        reg.anchorPattern(PATTERN, EXPERT_ID, ATTESTATION);
        vm.expectRevert(PatternRegistry.AlreadyAnchored.selector);
        reg.anchorPattern(PATTERN, EXPERT_ID, ATTESTATION);
    }

    function test_NonOwnerReverts() public {
        vm.prank(stranger);
        vm.expectRevert(PatternRegistry.NotOwner.selector);
        reg.anchorPattern(PATTERN, EXPERT_ID, ATTESTATION);
    }

    /// A different hash still anchors (the guard is per-hash, not a global latch).
    function test_SecondDistinctHashAnchors() public {
        reg.anchorPattern(PATTERN, EXPERT_ID, ATTESTATION);
        bytes32 other = keccak256("another-verified-pattern");
        reg.anchorPattern(other, 1, "");
        assertTrue(reg.anchored(other));
    }
}
