// SPDX-License-Identifier: MIT
pragma solidity 0.8.20;

import {Test} from "forge-std/Test.sol";
import {AgentNFT} from "../src/0g/AgentNFT.sol";
import {IntelligentData} from "../src/0g/interfaces/IERC7857Metadata.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import {StubVerifier} from "../src/StubVerifier.sol";

/// @title  SinabroExpertMint — W3 ERC-7857 iNFT mint lifecycle (LOCAL, hermetic).
/// @notice Proves the W3 vertical against the REAL 0gfoundation/0g-agent-nft AgentNFT
///         (main @ b86e108a, upgradeable): deploy stub verifier → deploy AgentNFT impl
///         → deploy ERC1967Proxy(initialize) → `mint([{descriptor, patternHash}], to)`
///         → `intelligentDatasOf(tokenId)` reads the W2-D patternHash back. Also pins
///         the cross-language byte lock: solc's own selector + abi-encoding MUST equal
///         the machine-written Python golden (chain-inft/golden/mint_calldata.hex),
///         which the Rust encoder (zerog_inft.rs) independently re-derives too.
contract SinabroExpertMintTest is Test {
    AgentNFT internal nft; // the ERC1967 proxy, typed as AgentNFT
    StubVerifier internal verifier;
    address internal admin;

    // The W2-D oracle-verified patternHash — sha256 of a `sui move build`-verified Move
    // artifact, ANCHORED on Galileo testnet (PatternRegistry 0xDe662d…0C73, anchor tx
    // 0x7e05d6f5…). dataHash binds this iNFT to that oracle-verified pattern.
    bytes32 internal constant PATTERN =
        0x332a98db3883f94161e2f88a714f9abfcd306888adeb73030b62d8c68884971a;
    // The seam-locked provenance descriptor (65 bytes; chain-inft/golden/mint_golden.py).
    string internal constant DESC =
        "sinabro-expert:generalist; oracle=code_oracle:sui_move_build:pass";
    // The golden recipient — a documented PLACEHOLDER test vector (0xdEaD). The real
    // mint substitutes the owner's fresh testnet address at fire time; the encoder is
    // correct for ANY `to`, and this vector locks the encoding shape.
    address internal constant RECIPIENT = address(0xdEaD);

    function setUp() public {
        admin = address(this);
        verifier = new StubVerifier();
        AgentNFT impl = new AgentNFT();
        bytes memory initData = abi.encodeWithSelector(
            AgentNFT.initialize.selector,
            "Sinabro Experts",
            "SNBX",
            "0g-storage://sinabro/experts",
            address(verifier),
            admin
        );
        ERC1967Proxy proxy = new ERC1967Proxy(address(impl), initData);
        nft = AgentNFT(address(proxy));
    }

    /// Lifecycle: mint binds the patternHash + descriptor; intelligentDatasOf reads them
    /// back (the W2-D pattern round-trips into a real ERC-7857 iNFT). This is the W3 e2e.
    function test_MintBindsPatternHashAndReadsBack() public {
        IntelligentData[] memory datas = new IntelligentData[](1);
        datas[0] = IntelligentData({dataDescription: DESC, dataHash: PATTERN});

        uint256 tokenId = nft.mint(datas, RECIPIENT);

        assertEq(nft.ownerOf(tokenId), RECIPIENT, "recipient owns the iNFT");
        IntelligentData[] memory read = nft.intelligentDatasOf(tokenId);
        assertEq(read.length, 1, "one intelligent-data entry");
        assertEq(read[0].dataHash, PATTERN, "dataHash == W2-D patternHash");
        assertEq(read[0].dataDescription, DESC, "descriptor round-trips");
    }

    /// A second mint gets a distinct tokenId (the data store is per-token).
    function test_SecondMintDistinctToken() public {
        IntelligentData[] memory datas = new IntelligentData[](1);
        datas[0] = IntelligentData({dataDescription: DESC, dataHash: PATTERN});
        uint256 t1 = nft.mint(datas, RECIPIENT);
        uint256 t2 = nft.mint(datas, RECIPIENT);
        assertTrue(t1 != t2, "distinct token ids");
    }

    /// Cross-language lock leg 1 — solc's own keccak of the canonical signatures equals
    /// the golden selectors (the Python + Rust encoders pin the same values).
    function test_SelectorsMatchGolden() public pure {
        assertEq(bytes4(keccak256("mint((string,bytes32)[],address)")), bytes4(0xa3acac17));
        assertEq(bytes4(keccak256("intelligentDatasOf(uint256)")), bytes4(0x40fbd72f));
    }

    /// Cross-language lock leg 2 — solc's own ABI encoding of the mint calldata MUST
    /// equal the 324-byte machine-written Python golden (which the Rust encoder also
    /// reproduces). solc is ground truth for ABI; a mismatch fails this test.
    function test_CalldataMatchesGolden() public view {
        IntelligentData[] memory datas = new IntelligentData[](1);
        datas[0] = IntelligentData({dataDescription: DESC, dataHash: PATTERN});
        bytes memory cd = abi.encodePacked(bytes4(0xa3acac17), abi.encode(datas, RECIPIENT));

        bytes memory golden = vm.parseBytes(vm.readFile("golden/mint_calldata.hex"));
        assertEq(cd, golden, "solc abi-encoding != python golden");
        assertEq(cd.length, 324, "calldata length");
    }
}
