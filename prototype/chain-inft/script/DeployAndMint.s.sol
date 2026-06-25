// SPDX-License-Identifier: MIT
pragma solidity 0.8.20;

import {Script, console2} from "forge-std/Script.sol";
import {AgentNFT} from "../src/0g/AgentNFT.sol";
import {IntelligentData} from "../src/0g/interfaces/IERC7857Metadata.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import {StubVerifier} from "../src/StubVerifier.sol";

/// @title  DeployAndMint — OWNER-FIRED W3 deploy + mint (slice D).
/// @notice FUNDS: this needs a testnet signing key (deploy + a payable mint) ⇒ the
///         agent NEVER runs it autonomously (PD-6; the `sinabro` binary holds no key).
///         The OWNER runs it with their own fresh testnet key, exactly like the W2-D
///         `cast`/`forge` deploy. It: deploys StubVerifier → AgentNFT impl →
///         ERC1967Proxy(initialize) → mints the W2-D pattern as a sinabro-expert iNFT.
/// @dev    Run (owner, testnet):
///           forge script script/DeployAndMint.s.sol:DeployAndMint \
///             --rpc-url https://evmrpc-testnet.0g.ai \
///             --private-key $OG_TESTNET_PRIVATE_KEY --broadcast \
///             --priority-gas-price 2000000000   # 0G min tip = 2 gwei (W2-D gotcha)
///         Optional: MINT_RECIPIENT=0x... (defaults to the broadcaster).
contract DeployAndMint is Script {
    bytes32 internal constant PATTERN =
        0x332a98db3883f94161e2f88a714f9abfcd306888adeb73030b62d8c68884971a;
    string internal constant DESC =
        "sinabro-expert:generalist; oracle=code_oracle:sui_move_build:pass";

    function run() external {
        vm.startBroadcast();
        address deployer = msg.sender; // == the broadcaster (owner's testnet key)
        address recipient = vm.envOr("MINT_RECIPIENT", deployer);

        StubVerifier verifier = new StubVerifier();
        AgentNFT impl = new AgentNFT();
        bytes memory initData = abi.encodeWithSelector(
            AgentNFT.initialize.selector,
            "Sinabro Experts",
            "SNBX",
            "0g-storage://sinabro/experts",
            address(verifier),
            deployer
        );
        ERC1967Proxy proxy = new ERC1967Proxy(address(impl), initData);
        AgentNFT nft = AgentNFT(address(proxy));

        IntelligentData[] memory datas = new IntelligentData[](1);
        datas[0] = IntelligentData({dataDescription: DESC, dataHash: PATTERN});
        uint256 tokenId = nft.mint(datas, recipient);

        vm.stopBroadcast();

        console2.log("StubVerifier      :", address(verifier));
        console2.log("AgentNFT impl     :", address(impl));
        console2.log("AgentNFT iNFT proxy:", address(proxy));
        console2.log("minted tokenId    :", tokenId);
        console2.log("recipient         :", recipient);
    }
}
