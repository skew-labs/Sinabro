// SPDX-License-Identifier: MIT
pragma solidity 0.8.19;

import {Script} from "forge-std/Script.sol";
import {PatternRegistry} from "../src/PatternRegistry.sol";

/// @title Deploy — OWNER-RUN deployment of PatternRegistry to 0G Galileo testnet.
/// @notice The agent NEVER runs this (it broadcasts a funds-bearing tx needing a
///         signing key). The OWNER runs it with their own testnet key, e.g.:
///
///   forge script script/Deploy.s.sol:Deploy \
///     --rpc-url https://evmrpc-testnet.0g.ai \
///     --private-key $OG_TESTNET_PRIVATE_KEY \
///     --broadcast
///
///   The deployer becomes the immutable `owner` (the only address that can anchor).
contract Deploy is Script {
    function run() external returns (PatternRegistry reg) {
        vm.startBroadcast();
        reg = new PatternRegistry();
        vm.stopBroadcast();
    }
}
